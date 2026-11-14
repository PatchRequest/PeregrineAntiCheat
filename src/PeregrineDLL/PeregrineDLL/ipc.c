#include <stdio.h>
#include "ipc.h"
#include <string.h>
#include <stdarg.h>
#include <windows.h>

#define IPC_PIPE_NAMEA "\\\\.\\pipe\\peregrine_ipc"

static HANDLE g_pipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_lock;
static volatile LONG g_lock_init = 0;

static void EnsureLock(void) {
    if (InterlockedCompareExchange(&g_lock_init, 1, 0) == 0)
        InitializeCriticalSection(&g_lock);
}

static HANDLE GetPipe(void) {
    if (g_pipe != INVALID_HANDLE_VALUE)
        return g_pipe;

    if (!WaitNamedPipeA(IPC_PIPE_NAMEA, 1000))
        return INVALID_HANDLE_VALUE;

    /* FILE_WRITE_DATA, not GENERIC_WRITE: the generic right includes
       FILE_CREATE_PIPE_INSTANCE, which the server deliberately does not grant
       to ordinary users (it would let any process serve this pipe name).
       SECURITY_IDENTIFICATION: whoever answers on the pipe may learn who we
       are but can never impersonate the host process. */
    g_pipe = CreateFileA(
        IPC_PIPE_NAMEA,
        FILE_WRITE_DATA | SYNCHRONIZE,
        0, NULL,
        OPEN_EXISTING,
        SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
        NULL);

    return g_pipe;
}

static void ClosePipe(void) {
    if (g_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
}

void ipc_write_json(const char* json) {
    if (!json) return;
    EnsureLock();

    EnterCriticalSection(&g_lock);

    HANDLE h = GetPipe();
    if (h == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_lock);
        return;
    }

    DWORD len = (DWORD)strlen(json);
    DWORD written = 0;
    if (!WriteFile(h, json, len, &written, NULL)) {
        ClosePipe();
    }

    LeaveCriticalSection(&g_lock);
}

#define IPC_PARAMS_MAX  768
#define IPC_MESSAGE_MAX 1024

void ipc_log_event(const char* event, const char* fmt, ...) {
    char params[IPC_PARAMS_MAX];
    va_list args;
    va_start(args, fmt);
    vsnprintf(params, sizeof(params), fmt, args);
    va_end(args);

    char buf[IPC_MESSAGE_MAX];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"event\":\"%s\",%s}", event, params);

    ipc_write_json(buf);
}

/* ------------------------------------------------------------ */
/* Message rate limit (see ipc.h)                               */
/* ------------------------------------------------------------ */

#define RL_SLOTS      32
#define RL_WINDOW_MS  2000
#define RL_BURST      2      /* messages per key per window */

typedef struct {
    int          in_use;
    const char*  event;
    const char*  subkey;        /* may be NULL */
    DWORD        target_pid;
    ULONGLONG    window_start;
    unsigned     emitted;       /* in the current window */
    unsigned     suppressed;    /* since the last emitted message */
} RateSlot;

typedef struct {
    int          emit;
    unsigned     suppressed;

    int          flush;         /* an evicted key still held a count */
    const char*  flush_event;
    const char*  flush_subkey;
    DWORD        flush_target_pid;
    unsigned     flush_suppressed;
} RateDecision;

static RateSlot g_rate_slots[RL_SLOTS];
static SRWLOCK  g_rate_lock = SRWLOCK_INIT;

static int same_text(const char* a, const char* b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    return strcmp(a, b) == 0;
}

static void rate_limit_decide(const char* event, const char* subkey, DWORD target_pid,
                              RateDecision* out) {
    memset(out, 0, sizeof(*out));
    ULONGLONG now = GetTickCount64();

    AcquireSRWLockExclusive(&g_rate_lock);

    RateSlot* slot = NULL;
    RateSlot* reclaim = &g_rate_slots[0];
    for (int i = 0; i < RL_SLOTS; i++) {
        RateSlot* s = &g_rate_slots[i];
        if (s->in_use && s->target_pid == target_pid &&
            same_text(s->event, event) && same_text(s->subkey, subkey)) {
            slot = s;
            break;
        }
        /* Reclaim candidate: any free slot, else the oldest window. */
        if (reclaim->in_use && (!s->in_use || s->window_start < reclaim->window_start))
            reclaim = s;
    }

    if (!slot) {
        if (reclaim->in_use && reclaim->suppressed != 0) {
            out->flush = 1;
            out->flush_event = reclaim->event;
            out->flush_subkey = reclaim->subkey;
            out->flush_target_pid = reclaim->target_pid;
            out->flush_suppressed = reclaim->suppressed;
        }
        slot = reclaim;
        slot->in_use = 1;
        slot->event = event;
        slot->subkey = subkey;
        slot->target_pid = target_pid;
        slot->window_start = now;
        slot->emitted = 0;
        slot->suppressed = 0;
    } else if (now - slot->window_start >= RL_WINDOW_MS) {
        /* Fixed window: a swallowed message never extends it. */
        slot->window_start = now;
        slot->emitted = 0;
    }

    if (slot->emitted < RL_BURST) {
        slot->emitted++;
        out->emit = 1;
        out->suppressed = slot->suppressed;
        slot->suppressed = 0;
    } else if (slot->suppressed != 0xFFFFFFFFu) {
        slot->suppressed++;
    }

    ReleaseSRWLockExclusive(&g_rate_lock);
}

void ipc_log_event_limited(const char* event, const char* subkey, DWORD target_pid,
                           const char* fmt, ...) {
    RateDecision decision;
    rate_limit_decide(event, subkey, target_pid, &decision);

    char buf[IPC_MESSAGE_MAX];

    if (decision.flush) {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "{\"event\":\"RateLimitFlush\",\"of\":\"%s\",\"subkey\":\"%s\","
            "\"targetPID\":%lu,\"suppressed\":%u}",
            decision.flush_event,
            decision.flush_subkey ? decision.flush_subkey : "",
            (unsigned long)decision.flush_target_pid,
            decision.flush_suppressed);
        ipc_write_json(buf);
    }

    if (!decision.emit)
        return;

    char params[IPC_PARAMS_MAX];
    va_list args;
    va_start(args, fmt);
    vsnprintf(params, sizeof(params), fmt, args);
    va_end(args);

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"event\":\"%s\",%s,\"suppressed\":%u}", event, params, decision.suppressed);

    ipc_write_json(buf);
}
