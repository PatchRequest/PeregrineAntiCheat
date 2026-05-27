#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

/*
 * Hardware-breakpoint / FakeVEH / debug-register smoke test.
 *
 * Two attack phases:
 *   Phase A — FakeVEH simulation: injects shellcode into game.exe that
 *             calls AddVectoredExceptionHandler, modifying the VEH list
 *             from inside the process.  Triggers DR0 hardware breakpoint
 *             → VehTableTamper event.
 *
 *   Phase B — DR clearing: zeroes DR0-DR7 on game threads via remote
 *             SetThreadContext.  Triggers DebugRegisterClearing (hook)
 *             and DebugRegisterTamper (watchdog re-arm).
 *
 * Usage:
 *   cheat_hwbp.exe <PID>           full test (VEH inject + DR clear)
 *   cheat_hwbp.exe <PID> --veh     VEH injection only, don't clear DRs
 *   cheat_hwbp.exe <PID> --read    just dump DR registers, no attacks
 */

#ifndef CONTEXT_AMD64
#define CONTEXT_AMD64  0x00100000
#endif
#define CONTEXT_DBG_REGS  (CONTEXT_AMD64 | 0x10)

typedef struct { DWORD tid; HANDLE handle; } ThreadSlot;
#define MAX_THREADS 64

/* ------------------------------------------------------------------ */
/* Thread helpers                                                      */
/* ------------------------------------------------------------------ */

static int collect_threads(DWORD pid, ThreadSlot* slots)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te;  te.dwSize = sizeof(te);
    int count = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid && count < MAX_THREADS) {
                HANDLE th = OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                    FALSE, te.th32ThreadID);
                if (th) { slots[count].tid = te.th32ThreadID; slots[count].handle = th; count++; }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return count;
}

static void print_dr_regs(DWORD tid, HANDLE th)
{
    SuspendThread(th);
    CONTEXT ctx;  memset(&ctx, 0, sizeof(ctx));  ctx.ContextFlags = CONTEXT_DBG_REGS;
    if (GetThreadContext(th, &ctx))
        printf("  TID %5lu: DR0=0x%016llX  DR7=0x%016llX\n",
            (unsigned long)tid, (unsigned long long)ctx.Dr0, (unsigned long long)ctx.Dr7);
    else
        printf("  TID %5lu: GetThreadContext failed (%lu)\n", (unsigned long)tid, GetLastError());
    ResumeThread(th);
}

static void clear_dr_regs(DWORD tid, HANDLE th)
{
    SuspendThread(th);
    CONTEXT ctx;  memset(&ctx, 0, sizeof(ctx));  ctx.ContextFlags = CONTEXT_DBG_REGS;
    if (GetThreadContext(th, &ctx)) {
        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = ctx.Dr6 = ctx.Dr7 = 0;
        ctx.ContextFlags = CONTEXT_DBG_REGS;
        if (SetThreadContext(th, &ctx))
            printf("  TID %5lu: DR registers cleared\n", (unsigned long)tid);
        else
            printf("  TID %5lu: SetThreadContext failed (%lu)\n", (unsigned long)tid, GetLastError());
    } else {
        printf("  TID %5lu: GetThreadContext failed (%lu)\n", (unsigned long)tid, GetLastError());
    }
    ResumeThread(th);
}

/* ------------------------------------------------------------------ */
/* FakeVEH simulation — shellcode that calls AddVectoredExceptionHandler */
/* inside the target process, modifying LdrpVectorHandlerList.          */
/* This triggers the DR0 hardware breakpoint (VehTableTamper event).    */
/* ------------------------------------------------------------------ */

/*
 * x64 shellcode layout:
 *   0x00  dummy VEH handler:  xor eax,eax; ret  (EXCEPTION_CONTINUE_SEARCH)
 *   0x08  main:
 *         sub rsp, 0x28
 *         xor ecx, ecx                          ; First = 0
 *         mov rdx, <handler_addr>                ; Handler = dummy at 0x00
 *         mov rax, <AddVectoredExceptionHandler>
 *         call rax                               ; rax = handle
 *         mov rbx, rax
 *         mov ecx, 3000                          ; Sleep 3s
 *         mov rax, <Sleep>
 *         call rax
 *         mov rcx, rbx                           ; handle
 *         mov rax, <RemoveVectoredExceptionHandler>
 *         call rax
 *         add rsp, 0x28
 *         xor eax, eax
 *         ret
 *
 * Patch offsets (absolute 8-byte addresses):
 *   0x10  handler_addr  (= alloc base + 0x00)
 *   0x1A  AddVectoredExceptionHandler
 *   0x27  Sleep
 *   0x36  RemoveVectoredExceptionHandler
 */
static unsigned char sc_fakeveh[] = {
    /* 0x00: dummy handler */
    0x31, 0xC0,                                     /* xor eax, eax */
    0xC3,                                           /* ret          */
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC,                  /* padding      */

    /* 0x08: main */
    0x48, 0x83, 0xEC, 0x28,                         /* sub rsp, 0x28 */
    0x33, 0xC9,                                     /* xor ecx, ecx  */
    0x48, 0xBA,                                     /* mov rdx, imm64 → handler addr */
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,     /* [patch @ 0x10] */
    0x48, 0xB8,                                     /* mov rax, imm64 → AddVEH */
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,     /* [patch @ 0x1A] */
    0xFF, 0xD0,                                     /* call rax       */
    0x48, 0x89, 0xC3,                               /* mov rbx, rax   */

    0xB9, 0xB8, 0x0B, 0x00, 0x00,                  /* mov ecx, 3000  */
    0x48, 0xB8,                                     /* mov rax, imm64 → Sleep */
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,     /* [patch @ 0x2F] */
    0xFF, 0xD0,                                     /* call rax       */

    0x48, 0x89, 0xD9,                               /* mov rcx, rbx   */
    0x48, 0xB8,                                     /* mov rax, imm64 → RemoveVEH */
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,     /* [patch @ 0x3C] */
    0xFF, 0xD0,                                     /* call rax       */

    0x48, 0x83, 0xC4, 0x28,                         /* add rsp, 0x28  */
    0x33, 0xC0,                                     /* xor eax, eax   */
    0xC3,                                           /* ret            */
};

#define SC_PATCH_HANDLER  0x10
#define SC_PATCH_ADDVEH   0x1A
#define SC_PATCH_SLEEP    0x2F
#define SC_PATCH_REMVEH   0x3C

static int do_fakeveh_inject(HANDLE hProc)
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) { printf("  GetModuleHandle(kernel32) failed\n"); return 0; }

    FARPROC pAddVeh    = GetProcAddress(k32, "AddVectoredExceptionHandler");
    FARPROC pRemoveVeh = GetProcAddress(k32, "RemoveVectoredExceptionHandler");
    FARPROC pSleep     = GetProcAddress(k32, "Sleep");
    if (!pAddVeh || !pRemoveVeh || !pSleep) {
        printf("  Failed to resolve VEH/Sleep functions\n");
        return 0;
    }

    LPVOID alloc = VirtualAllocEx(hProc, NULL, sizeof(sc_fakeveh),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc) { printf("  VirtualAllocEx failed (%lu)\n", GetLastError()); return 0; }

    unsigned long long handlerAddr = (unsigned long long)(ULONG_PTR)alloc;
    memcpy(sc_fakeveh + SC_PATCH_HANDLER, &handlerAddr, 8);
    unsigned long long addr;
    addr = (unsigned long long)(ULONG_PTR)pAddVeh;    memcpy(sc_fakeveh + SC_PATCH_ADDVEH,  &addr, 8);
    addr = (unsigned long long)(ULONG_PTR)pSleep;     memcpy(sc_fakeveh + SC_PATCH_SLEEP,   &addr, 8);
    addr = (unsigned long long)(ULONG_PTR)pRemoveVeh; memcpy(sc_fakeveh + SC_PATCH_REMVEH,  &addr, 8);

    SIZE_T written = 0;
    WriteProcessMemory(hProc, alloc, sc_fakeveh, sizeof(sc_fakeveh), &written);

    DWORD oldProt;
    VirtualProtectEx(hProc, alloc, sizeof(sc_fakeveh), PAGE_EXECUTE_READ, &oldProt);

    /* Entry point = offset 0x08 (past the dummy handler) */
    LPVOID entry = (LPVOID)((ULONG_PTR)alloc + 0x08);
    printf("  Shellcode at 0x%p, entry at 0x%p\n", alloc, entry);
    printf("  AddVEH=0x%p  RemoveVEH=0x%p  Sleep=0x%p\n",
        (void*)pAddVeh, (void*)pRemoveVeh, (void*)pSleep);

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)entry, NULL, 0, NULL);
    if (!hThread) {
        printf("  CreateRemoteThread failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        return 0;
    }

    printf("  Remote thread created — VEH handler will be added then removed after 3s\n");
    printf("  Waiting for shellcode to finish...\n");
    WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: cheat_hwbp.exe <target_PID> [--veh | --read]\n\n");
        printf("  (no flag)  Full test: FakeVEH injection + DR register clearing\n");
        printf("  --veh      VEH injection only (triggers VehTableTamper)\n");
        printf("  --read     Just dump DR registers, no attacks\n");
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    int mode_veh  = (argc >= 3 && strcmp(argv[2], "--veh") == 0);
    int mode_read = (argc >= 3 && strcmp(argv[2], "--read") == 0);

    const char* modeStr = mode_read ? "READ ONLY" : mode_veh ? "VEH INJECTION ONLY" : "FULL (VEH + DR CLEAR)";
    printf("[HWBP] PID %lu (self %lu) — mode: %s\n\n", pid, GetCurrentProcessId(), modeStr);

    /* Collect threads for DR operations */
    ThreadSlot threads[MAX_THREADS];
    int tcount = collect_threads(pid, threads);
    printf("[HWBP] Found %d threads\n\n", tcount);

    /* Always show current DR state */
    printf("[HWBP] === Current DR registers ===\n");
    for (int i = 0; i < tcount; i++)
        print_dr_regs(threads[i].tid, threads[i].handle);
    printf("\n");

    if (mode_read) goto done;

    /* Phase A: FakeVEH — inject shellcode that modifies VEH list */
    printf("[HWBP] === Phase A: FakeVEH injection (AddVectoredExceptionHandler in target) ===\n");
    {
        HANDLE hProc = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
            FALSE, pid);
        if (!hProc) {
            printf("  OpenProcess failed (%lu)\n", GetLastError());
        } else {
            if (do_fakeveh_inject(hProc))
                printf("  [OK] VEH list was modified and restored inside target\n");
            else
                printf("  [FAIL] FakeVEH injection failed\n");
            CloseHandle(hProc);
        }
    }
    printf("\n");

    if (mode_veh) goto done;

    /* Phase B: Clear DR registers */
    Sleep(1000);
    printf("[HWBP] === Phase B: Clear DR registers (SetThreadContext) ===\n");
    for (int i = 0; i < tcount; i++)
        clear_dr_regs(threads[i].tid, threads[i].handle);
    printf("\n");
    Sleep(1000);

    printf("[HWBP] === Verify cleared ===\n");
    for (int i = 0; i < tcount; i++)
        print_dr_regs(threads[i].tid, threads[i].handle);
    printf("\n");

    printf("[HWBP] === Waiting 10s for Peregrine watchdog to re-arm... ===\n");
    Sleep(10000);

    printf("[HWBP] === Re-read (should be re-armed) ===\n");
    for (int i = 0; i < tcount; i++)
        print_dr_regs(threads[i].tid, threads[i].handle);
    printf("\n");

done:
    for (int i = 0; i < tcount; i++)
        CloseHandle(threads[i].handle);

    printf("[HWBP] Done. Expected Peregrine events:\n");
    if (!mode_read) printf("  - VehTableTamper       (DR0 breakpoint on VEH list write)\n");
    if (!mode_read && !mode_veh) {
        printf("  - DebugRegisterClearing (NtSetContextThread hook)\n");
        printf("  - DebugRegisterTamper   (watchdog re-arm)\n");
    }
    if (mode_read) printf("  - (none — read-only mode)\n");
    printf("\nPress Enter to exit.\n");
    getchar();
    return 0;
}
