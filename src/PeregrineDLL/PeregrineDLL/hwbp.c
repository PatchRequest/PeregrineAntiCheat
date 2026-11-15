#include "hwbp.h"
#include "ipc.h"
#include <tlhelp32.h>

/*
 * VEH-handler and hardware-breakpoint detection (Game DLL only).
 *
 * What a FakeVEH / HWBP-hook cheat does inside the game:
 *   1. registers a vectored exception handler that lives in memory it
 *      injected (not backed by any image), and
 *   2. sets hardware breakpoints (DR0-DR3 + DR7) on game threads so the
 *      handler gets control at the "hooked" addresses.
 *
 * Detection, none of which changes the game's own state:
 *   - a hook on RtlAddVectoredExceptionHandler reports a handler that is not
 *     inside a loaded image at the moment it is registered;
 *   - a watchdog thread walks the VEH list itself, which also finds handlers
 *     that were linked in without the API or before this DLL was loaded;
 *   - the same watchdog reports every thread with an enabled hardware
 *     breakpoint, and a hook on NtSetContextThread (dllmain.cpp) reports the
 *     in-process call that sets one.
 *
 * Deliberately NOT done: putting our own data breakpoint on the VEH list.
 * ntdll modifies the list while holding the list's SRW lock; the resulting
 * single-step exception is dispatched on the same thread, and vectored
 * dispatch takes that same lock again — the thread deadlocks, and with it
 * every later exception in the process. An earlier version did this and froze
 * any armed thread that registered a first-chance handler.
 */

static DWORD g_my_pid = 0;

#define WATCHDOG_INTERVAL_MS 2000

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/* TRUE if addr lies in committed memory that maps an image (exe / dll). */
static int is_image_backed(const void* addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!addr || !VirtualQuery(addr, &mbi, sizeof(mbi)))
        return 0;
    return mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE;
}

/* ------------------------------------------------------------------ */
/* Hook: RtlAddVectoredExceptionHandler                               */
/* ------------------------------------------------------------------ */

hwbp_add_veh_t hwbp_orig_add_veh = NULL;

PVOID NTAPI hwbp_hook_add_veh(ULONG first, PVECTORED_EXCEPTION_HANDLER handler)
{
    /* The original takes and releases the list lock; report afterwards. */
    PVOID cookie = hwbp_orig_add_veh(first, handler);
    DWORD last_error = GetLastError();

    if (cookie && !is_image_backed((const void*)handler)) {
        ipc_log_event_limited("VehTableTamper", "registration", 0,
            "\"callerPID\":%lu,\"threadId\":%lu,\"handler\":\"0x%llX\","
            "\"first\":%lu,\"source\":\"registration\"",
            g_my_pid, (unsigned long)GetCurrentThreadId(),
            (unsigned long long)(ULONG_PTR)handler, (unsigned long)(first != 0));
    }

    SetLastError(last_error);
    return cookie;
}

/* ------------------------------------------------------------------ */
/* VEH list walk                                                      */
/* ------------------------------------------------------------------ */
/*
 * The list head and the entry layout are private to ntdll and differ between
 * Windows versions, so both are measured instead of assumed: register a
 * handler of our own as first entry, take the head from its back link, and
 * find the slot that holds the encoded pointer we just registered.
 */

static LIST_ENTRY* g_veh_head = NULL;
static SIZE_T      g_handler_offset = 0;   /* 0 = layout not recognised */

static LONG NTAPI CalibrationVeh(PEXCEPTION_POINTERS ep)
{
    (void)ep;
    return EXCEPTION_CONTINUE_SEARCH;
}

static void calibrate_veh_list(void)
{
    PVOID cookie = AddVectoredExceptionHandler(1, CalibrationVeh);
    if (!cookie) return;

    __try {
        LIST_ENTRY* entry = (LIST_ENTRY*)cookie;
        LIST_ENTRY* head = entry->Blink;        /* we are first */
        PVOID encoded = EncodePointer((PVOID)CalibrationVeh);

        /* Entry: LIST_ENTRY, then at most three pointer-sized fields. */
        for (SIZE_T off = sizeof(LIST_ENTRY);
             off <= sizeof(LIST_ENTRY) + 2 * sizeof(PVOID);
             off += sizeof(PVOID)) {
            if (*(PVOID*)((BYTE*)entry + off) == encoded) {
                g_veh_head = head;
                g_handler_offset = off;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_veh_head = NULL;
        g_handler_offset = 0;
    }

    RemoveVectoredExceptionHandler(cookie);
}

#define MAX_VEH_ENTRIES 64

/* Unbacked handlers seen by the previous walk; only the watchdog touches it. */
static ULONG_PTR g_known_unbacked[MAX_VEH_ENTRIES];
static int       g_known_unbacked_count = 0;

static void scan_veh_list(void)
{
    if (!g_veh_head || !g_handler_offset) return;

    ULONG_PTR found[MAX_VEH_ENTRIES];
    int found_first[MAX_VEH_ENTRIES];     /* handler is the first in the list */
    int found_count = 0;

    /* Walked without ntdll's list lock (not reachable from here): entries can
       be unlinked and freed underneath us, hence the guard and the bound. */
    __try {
        int guard = 0;
        for (LIST_ENTRY* e = g_veh_head->Flink;
             e != g_veh_head && guard < MAX_VEH_ENTRIES;
             e = e->Flink, guard++) {
            PVOID handler = DecodePointer(*(PVOID*)((BYTE*)e + g_handler_offset));
            if (!is_image_backed(handler)) {
                found[found_count] = (ULONG_PTR)handler;
                found_first[found_count] = (guard == 0);
                found_count++;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return; /* list changed mid-walk; the next pass sees the result */
    }

    for (int i = 0; i < found_count; i++) {
        int known = 0;
        for (int k = 0; k < g_known_unbacked_count; k++)
            if (g_known_unbacked[k] == found[i]) { known = 1; break; }
        if (!known) {
            ipc_log_event("VehTableTamper",
                "\"callerPID\":%lu,\"threadId\":0,\"handler\":\"0x%llX\","
                "\"first\":%d,\"source\":\"list\"",
                g_my_pid, (unsigned long long)found[i], found_first[i]);
        }
    }

    memcpy(g_known_unbacked, found, (size_t)found_count * sizeof(found[0]));
    g_known_unbacked_count = found_count;
}

/* ------------------------------------------------------------------ */
/* Hardware breakpoints on our threads                                */
/* ------------------------------------------------------------------ */

#define MAX_TRACKED_THREADS 256

typedef struct {
    DWORD     tid;
    ULONG_PTR dr[4];
    ULONG_PTR dr7;
} ThreadBreakpoints;

/* Breakpoints reported by the previous pass; only the watchdog touches it. */
static ThreadBreakpoints g_known_bp[MAX_TRACKED_THREADS];
static int               g_known_bp_count = 0;

/* DR7 bits 0-7 are the local/global enables of DR0-DR3. */
#define DR7_ENABLE_MASK 0xFF

static void scan_debug_registers(void)
{
    static ThreadBreakpoints now_bp[MAX_TRACKED_THREADS];
    int now_count = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != g_my_pid) continue;

            /* Read-only and without suspending the thread: debug registers
               are kept per thread by the kernel, a running thread is fine. */
            HANDLE th = OpenThread(THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
            if (!th) continue;

            CONTEXT ctx;
            memset(&ctx, 0, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            BOOL ok = GetThreadContext(th, &ctx);
            CloseHandle(th);
            if (!ok || (ctx.Dr7 & DR7_ENABLE_MASK) == 0) continue;

            ThreadBreakpoints cur;
            cur.tid = te.th32ThreadID;
            cur.dr[0] = (ULONG_PTR)ctx.Dr0;
            cur.dr[1] = (ULONG_PTR)ctx.Dr1;
            cur.dr[2] = (ULONG_PTR)ctx.Dr2;
            cur.dr[3] = (ULONG_PTR)ctx.Dr3;
            cur.dr7 = (ULONG_PTR)ctx.Dr7;

            int known = 0;
            for (int k = 0; k < g_known_bp_count; k++) {
                if (memcmp(&g_known_bp[k], &cur, sizeof(cur)) == 0) { known = 1; break; }
            }
            if (!known) {
                ipc_log_event("HardwareBreakpoint",
                    "\"callerPID\":%lu,\"threadId\":%lu,"
                    "\"dr0\":\"0x%llX\",\"dr1\":\"0x%llX\",\"dr2\":\"0x%llX\",\"dr3\":\"0x%llX\","
                    "\"dr7\":\"0x%llX\"",
                    g_my_pid, (unsigned long)cur.tid,
                    (unsigned long long)cur.dr[0], (unsigned long long)cur.dr[1],
                    (unsigned long long)cur.dr[2], (unsigned long long)cur.dr[3],
                    (unsigned long long)cur.dr7);
            }
            if (now_count < MAX_TRACKED_THREADS)
                now_bp[now_count++] = cur;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    memcpy(g_known_bp, now_bp, (size_t)now_count * sizeof(now_bp[0]));
    g_known_bp_count = now_count;
}

/* ------------------------------------------------------------------ */
/* Watchdog                                                           */
/* ------------------------------------------------------------------ */

static DWORD WINAPI WatchdogThread(LPVOID param)
{
    (void)param;

    for (;;) {
        scan_veh_list();
        scan_debug_registers();
        Sleep(WATCHDOG_INTERVAL_MS);
    }
}

/* ------------------------------------------------------------------ */
/* Public init                                                        */
/* ------------------------------------------------------------------ */

void hwbp_init(void)
{
    g_my_pid = GetCurrentProcessId();

    calibrate_veh_list();

    ipc_log_event("VehGuardInit",
        "\"callerPID\":%lu,\"status\":\"ok\",\"listScan\":%s,\"vehListAddr\":\"0x%llX\"",
        g_my_pid, g_handler_offset ? "true" : "false",
        (unsigned long long)(ULONG_PTR)g_veh_head);

    HANDLE wt = CreateThread(NULL, 0, WatchdogThread, NULL, 0, NULL);
    if (wt) CloseHandle(wt);
}
