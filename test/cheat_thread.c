/*
 * Thread-handle test: OpenThread on a game thread WITHOUT any process handle.
 *
 * THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT is all a
 * cheat needs to freeze a thread, read/modify its registers and hijack it.
 * No OpenProcess is involved, so process-handle monitoring alone never sees it.
 *
 * Expected (game PID protected):
 *   [Handle Access] PID=<this> -> thread <tid> of PID=<game> op=create
 *                   [SUSPEND_RESUME|GET_CONTEXT|SET_CONTEXT]
 * Expected against a non-protected PID: no Peregrine line at all.
 *
 * The handle is only opened and closed; the target thread is never touched.
 *
 * Usage: cheat_thread.exe <PID> [repeat]
 *   repeat > 1 re-opens in a loop to exercise the kernel report rate limit
 *   (one line, then "(+N identical suppressed)" on the next report).
 */
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>

static DWORD first_thread_of(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD tid = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tid;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: cheat_thread.exe <PID> [repeat]\n");
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    int repeat = (argc >= 3) ? atoi(argv[2]) : 1;
    if (repeat < 1) repeat = 1;

    DWORD tid = first_thread_of(pid);
    if (!tid) {
        printf("[THREAD] no thread found for PID %lu\n", pid);
        return 1;
    }
    printf("[THREAD] target PID=%lu TID=%lu, opening %d time(s)\n", pid, tid, repeat);

    int opened = 0;
    for (int i = 0; i < repeat; i++) {
        HANDLE th = OpenThread(
            THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
            FALSE, tid);
        if (th) {
            opened++;
            CloseHandle(th);
        } else if (i == 0) {
            printf("[THREAD] OpenThread failed: %lu\n", GetLastError());
        }
    }

    printf("[THREAD] %d/%d opens succeeded (handles closed again, thread untouched)\n",
        opened, repeat);
    return opened ? 0 : 1;
}
