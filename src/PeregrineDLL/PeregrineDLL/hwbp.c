#include "hwbp.h"
#include "ipc.h"
#include <tlhelp32.h>

volatile LONG g_hwbp_arming = 0;

static DWORD  g_my_pid        = 0;
static DWORD  g_watchdog_tid  = 0;
static ULONG_PTR g_veh_list_addr = 0;

/* DR7: local-enable DR0 (bit 0), write-only condition (bits 16-17 = 01),
   8-byte length (bits 18-19 = 10 on x64).  Result: 0x00090001 */
#define DR7_WATCH_DR0  0x00090001ULL

#define CONTEXT_AMD64_FLAG  0x00100000UL
#define CONTEXT_DBG_REGS    (CONTEXT_AMD64_FLAG | 0x10)

/* ------------------------------------------------------------------ */
/* Resolve LdrpVectorHandlerList                                      */
/* ------------------------------------------------------------------ */

typedef struct _VEH_LIST_ENTRY {
    LIST_ENTRY List;
} VEH_LIST_ENTRY;

static LONG NTAPI DummyVeh(PEXCEPTION_POINTERS ep) {
    (void)ep;
    return EXCEPTION_CONTINUE_SEARCH;
}

static ULONG_PTR find_veh_list_head(void)
{
    /* Register ourselves as FIRST handler so entry->List.Blink == list head */
    PVOID h = AddVectoredExceptionHandler(1, DummyVeh);
    if (!h) return 0;

    VEH_LIST_ENTRY* entry = (VEH_LIST_ENTRY*)h;
    ULONG_PTR head = (ULONG_PTR)entry->List.Blink;

    RemoveVectoredExceptionHandler(h);
    return head;
}

/* ------------------------------------------------------------------ */
/* Set / verify DR0 on a single thread                                */
/* ------------------------------------------------------------------ */

static int set_dr0_on_thread(DWORD tid)
{
    if (tid == GetCurrentThreadId() || tid == g_watchdog_tid)
        return 0;

    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                           THREAD_SET_CONTEXT, FALSE, tid);
    if (!th) return 0;

    SuspendThread(th);

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DBG_REGS;

    int armed = 0;
    if (GetThreadContext(th, &ctx)) {
        ctx.Dr0 = (DWORD64)g_veh_list_addr;
        ctx.Dr7 = (ctx.Dr7 & ~0x000F0003ULL) | DR7_WATCH_DR0;
        ctx.Dr6 = 0;
        ctx.ContextFlags = CONTEXT_DBG_REGS;

        InterlockedExchange(&g_hwbp_arming, 1);
        armed = SetThreadContext(th, &ctx);
        InterlockedExchange(&g_hwbp_arming, 0);
    }

    ResumeThread(th);
    CloseHandle(th);
    return armed;
}

static int check_dr0_on_thread(DWORD tid, int* out_cleared)
{
    *out_cleared = 0;
    if (tid == GetCurrentThreadId() || tid == g_watchdog_tid)
        return 0;

    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                           THREAD_SET_CONTEXT, FALSE, tid);
    if (!th) return 0;

    SuspendThread(th);

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DBG_REGS;

    int ok = 0;
    if (GetThreadContext(th, &ctx)) {
        ok = 1;
        if ((ULONG_PTR)ctx.Dr0 != g_veh_list_addr) {
            *out_cleared = 1;
            /* Re-arm */
            ctx.Dr0 = (DWORD64)g_veh_list_addr;
            ctx.Dr7 = (ctx.Dr7 & ~0x000F0003ULL) | DR7_WATCH_DR0;
            ctx.Dr6 = 0;
            ctx.ContextFlags = CONTEXT_DBG_REGS;

            InterlockedExchange(&g_hwbp_arming, 1);
            SetThreadContext(th, &ctx);
            InterlockedExchange(&g_hwbp_arming, 0);
        }
    }

    ResumeThread(th);
    CloseHandle(th);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Arm DR0 on every thread in this process                            */
/* ------------------------------------------------------------------ */

static int arm_all_threads(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    int count = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == g_my_pid) {
                count += set_dr0_on_thread(te.th32ThreadID);
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return count;
}

/* ------------------------------------------------------------------ */
/* VEH handler: catch EXCEPTION_SINGLE_STEP from our DR0 breakpoint   */
/* ------------------------------------------------------------------ */

static PVOID g_veh_handle = NULL;

static LONG NTAPI HwbpVehHandler(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    /* Check DR6 bit 0 (B0) — our DR0 triggered */
    DWORD64 dr6 = ep->ContextRecord->Dr6;
    if (!(dr6 & 1))
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD tid = GetCurrentThreadId();
    ipc_log_event("VehTableTamper",
        "\"callerPID\":%lu,\"threadId\":%lu,\"dr6\":\"0x%llX\"",
        g_my_pid, (unsigned long)tid, (unsigned long long)dr6);

    /* Clear B0 and re-arm DR0 */
    ep->ContextRecord->Dr6 &= ~(DWORD64)1;
    ep->ContextRecord->Dr0 = (DWORD64)g_veh_list_addr;
    ep->ContextRecord->Dr7 = (ep->ContextRecord->Dr7 & ~0x000F0003ULL) | DR7_WATCH_DR0;

    return EXCEPTION_CONTINUE_EXECUTION;
}

/* ------------------------------------------------------------------ */
/* Watchdog thread: periodic DR0 validation + re-arm                  */
/* ------------------------------------------------------------------ */

#define WATCHDOG_INTERVAL_MS 5000

static DWORD WINAPI WatchdogThread(LPVOID param)
{
    (void)param;
    g_watchdog_tid = GetCurrentThreadId();

    for (;;) {
        Sleep(WATCHDOG_INTERVAL_MS);

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;

        THREADENTRY32 te;
        te.dwSize = sizeof(te);

        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != g_my_pid) continue;

                int cleared = 0;
                if (check_dr0_on_thread(te.th32ThreadID, &cleared) && cleared) {
                    ipc_log_event("DebugRegisterTamper",
                        "\"callerPID\":%lu,\"threadId\":%lu,\"action\":\"re-armed\"",
                        g_my_pid, (unsigned long)te.th32ThreadID);
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public init                                                        */
/* ------------------------------------------------------------------ */

void hwbp_init(void)
{
    g_my_pid = GetCurrentProcessId();

    g_veh_list_addr = find_veh_list_head();
    if (!g_veh_list_addr) {
        ipc_log_event("HwbpInit", "\"status\":\"failed\",\"reason\":\"cannot resolve LdrpVectorHandlerList\"");
        return;
    }

    /* Register our VEH handler FIRST so we see single-step before anyone else */
    g_veh_handle = AddVectoredExceptionHandler(1, HwbpVehHandler);

    int armed = arm_all_threads();

    ipc_log_event("HwbpInit",
        "\"status\":\"ok\",\"vehListAddr\":\"0x%llX\",\"threadsArmed\":%d",
        (unsigned long long)g_veh_list_addr, armed);

    /* Start watchdog */
    HANDLE wt = CreateThread(NULL, 0, WatchdogThread, NULL, 0, NULL);
    if (wt) CloseHandle(wt);
}
