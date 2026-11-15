#include <stdio.h>
#include <string.h>
#include <windows.h>

/*
 * game.exe              plain target: prints PID + the address of `health`, then loops.
 * game.exe --veh        additionally, every 10 s, registers and removes a vectored
 *                       exception handler from a fresh thread *inside* the game —
 *                       the INTERNAL case the Game DLL's VEH-list breakpoint must
 *                       report as VehTableTamper (new threads included).
 *                       Registered as FIRST handler (what a FakeVEH cheat does).
 * game.exe --veh-last   same, registered as LAST handler.
 * game.exe --veh-main   the main thread itself registers a first handler every 10 s.
 * The --veh modes print the thread's debug registers first, so the log shows
 * whether the thread was armed.
 */

static LONG NTAPI DummyHandler(PEXCEPTION_POINTERS ep)
{
    (void)ep;
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Debug registers of the calling thread, as the Game DLL left them. */
static void PrintOwnDebugRegisters(const char* who)
{
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx))
        printf("[GAME] %s TID %lu: DR0=0x%p DR1=0x%p DR7=0x%p\n", who, GetCurrentThreadId(),
            (void*)(ULONG_PTR)ctx.Dr0, (void*)(ULONG_PTR)ctx.Dr1, (void*)(ULONG_PTR)ctx.Dr7);
}

/* param != NULL: register as first handler. */
static DWORD WINAPI VehOnce(LPVOID param)
{
    PrintOwnDebugRegisters("veh thread");
    PVOID h = AddVectoredExceptionHandler(param ? 1 : 0, DummyHandler);
    if (h) RemoveVectoredExceptionHandler(h);
    return 0;
}

static DWORD WINAPI VehLoop(LPVOID param)
{
    for (;;) {
        Sleep(10000);
        HANDLE th = CreateThread(NULL, 0, VehOnce, param, 0, NULL);
        if (th) {
            WaitForSingleObject(th, INFINITE);
            CloseHandle(th);
        }
    }
}

int main(int argc, char* argv[])
{
    volatile int health = 100;

    /* Unbuffered: the address must be readable when stdout is a file. */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[GAME] PID = %lu\n", GetCurrentProcessId());
    printf("[GAME] health address = 0x%p\n", (void*)&health);
    printf("[GAME] health = %d\n\n", health);

    if (argc >= 2 && (strcmp(argv[1], "--veh") == 0 || strcmp(argv[1], "--veh-last") == 0)) {
        const int first = strcmp(argv[1], "--veh-last") != 0;
        printf("[GAME] %s: registering a VEH (%s handler) from a new thread every 10 s\n",
            argv[1], first ? "first" : "last");
        HANDLE th = CreateThread(NULL, 0, VehLoop, (LPVOID)(ULONG_PTR)first, 0, NULL);
        if (th) CloseHandle(th);
    }

    const int vehMain = argc >= 2 && strcmp(argv[1], "--veh-main") == 0;

    for (unsigned tick = 1;; tick++) {
        printf("[GAME] health = %d  (addr 0x%p)\n", health, (void*)&health);
        Sleep(100);

        /* --veh-main: the long-lived main thread registers a first handler. */
        if (vehMain && tick % 100 == 0) {
            PrintOwnDebugRegisters("main thread");
            PVOID h = AddVectoredExceptionHandler(1, DummyHandler);
            if (h) RemoveVectoredExceptionHandler(h);
        }
    }

    return 0;
}
