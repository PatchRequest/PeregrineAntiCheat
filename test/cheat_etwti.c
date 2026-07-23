#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>

/*
 * ETW-TI smoketest: exercises every remote operation that the
 * Microsoft-Windows-Threat-Intelligence provider reports.
 *
 * Triggers (all remote, targeting game.exe):
 *   - ALLOCVM_REMOTE      (VirtualAllocEx)
 *   - PROTECTVM_REMOTE    (VirtualProtectEx)
 *   - WRITEVM_REMOTE      (WriteProcessMemory)
 *   - READVM_REMOTE       (ReadProcessMemory)
 *   - SUSPEND_THREAD      (SuspendThread on remote thread)
 *   - RESUME_THREAD       (ResumeThread on remote thread)
 *
 * Triggers (local, in this process):
 *   - ALLOCVM_LOCAL        (VirtualAlloc RWX)
 *   - PROTECTVM_LOCAL      (VirtualProtect to RWX)
 *
 * Usage:
 *   1. Start game.exe, note its PID
 *   2. Add the PID in Peregrine, click ETW-TI
 *   3. cheat_etwti.exe <PID>
 *   4. Watch for all event types in the Peregrine GUI
 */

static DWORD find_thread_in_process(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD tid = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tid;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: cheat_etwti.exe <target_PID>\n");
        printf("\nExercises all ETW-TI event types against the target process.\n");
        printf("Start ETW-TI in Peregrine first, then run this.\n");
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    printf("[ETW-TI] This process PID = %lu\n", GetCurrentProcessId());
    printf("[ETW-TI] Target PID = %lu\n\n", pid);

    /* --- Remote operations --- */
    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_QUERY_INFORMATION,
        FALSE, pid);

    if (!hProc) {
        printf("[ETW-TI] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[ETW-TI] Handle acquired\n\n");

    /* 1. ALLOCVM_REMOTE */
    printf("[ETW-TI] 1/8  VirtualAllocEx (ALLOCVM_REMOTE)...\n");
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        printf("  FAILED: %lu\n", GetLastError());
    } else {
        printf("  OK: 0x%p\n", remoteMem);
    }
    Sleep(500);

    /* 2. WRITEVM_REMOTE */
    printf("[ETW-TI] 2/8  WriteProcessMemory (WRITEVM_REMOTE)...\n");
    const char marker[] = "PEREGRINE_ETW_TEST";
    SIZE_T written = 0;
    if (remoteMem) {
        WriteProcessMemory(hProc, remoteMem, marker, sizeof(marker), &written);
        printf("  OK: %zu bytes\n", written);
    } else {
        printf("  SKIP (no allocation)\n");
    }
    Sleep(500);

    /* 3. READVM_REMOTE */
    printf("[ETW-TI] 3/8  ReadProcessMemory (READVM_REMOTE)...\n");
    char readBuf[64] = {0};
    SIZE_T bytesRead = 0;
    if (remoteMem) {
        ReadProcessMemory(hProc, remoteMem, readBuf, sizeof(marker), &bytesRead);
        printf("  OK: %zu bytes, data='%s'\n", bytesRead, readBuf);
    } else {
        printf("  SKIP (no allocation)\n");
    }
    Sleep(500);

    /* 4. PROTECTVM_REMOTE */
    printf("[ETW-TI] 4/8  VirtualProtectEx (PROTECTVM_REMOTE)...\n");
    if (remoteMem) {
        DWORD oldProt = 0;
        VirtualProtectEx(hProc, remoteMem, 4096, PAGE_EXECUTE_READWRITE, &oldProt);
        printf("  OK: changed to RWX\n");
    } else {
        printf("  SKIP (no allocation)\n");
    }
    Sleep(500);

    /* 5. SUSPEND_THREAD */
    printf("[ETW-TI] 5/8  SuspendThread (SUSPEND_THREAD)...\n");
    DWORD tid = find_thread_in_process(pid);
    HANDLE hThread = NULL;
    if (tid) {
        hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (hThread) {
            DWORD sc = SuspendThread(hThread);
            printf("  OK: suspended TID %lu (count=%lu)\n", tid, sc);
        } else {
            printf("  OpenThread failed: %lu\n", GetLastError());
        }
    } else {
        printf("  SKIP (no thread found)\n");
    }
    Sleep(500);

    /* 6. RESUME_THREAD */
    printf("[ETW-TI] 6/8  ResumeThread (RESUME_THREAD)...\n");
    if (hThread) {
        DWORD sc = ResumeThread(hThread);
        printf("  OK: resumed TID %lu (count=%lu)\n", tid, sc);
        CloseHandle(hThread);
    } else {
        printf("  SKIP (no suspended thread)\n");
    }
    Sleep(500);

    /* Cleanup remote alloc */
    if (remoteMem) {
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    }
    CloseHandle(hProc);

    /* --- Local operations --- */

    /* 7. ALLOCVM_LOCAL (RWX) */
    printf("[ETW-TI] 7/8  VirtualAlloc RWX (ALLOCVM_LOCAL)...\n");
    LPVOID localMem = VirtualAlloc(NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (localMem) {
        printf("  OK: 0x%p\n", localMem);
    } else {
        printf("  FAILED: %lu\n", GetLastError());
    }
    Sleep(500);

    /* 8. PROTECTVM_LOCAL */
    printf("[ETW-TI] 8/8  VirtualProtect to RWX (PROTECTVM_LOCAL)...\n");
    LPVOID localMem2 = VirtualAlloc(NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (localMem2) {
        DWORD oldProt = 0;
        VirtualProtect(localMem2, 4096, PAGE_EXECUTE_READWRITE, &oldProt);
        printf("  OK: changed to RWX\n");
        VirtualFree(localMem2, 0, MEM_RELEASE);
    } else {
        printf("  FAILED: %lu\n", GetLastError());
    }
    Sleep(500);

    if (localMem) VirtualFree(localMem, 0, MEM_RELEASE);

    printf("\n[ETW-TI] All 8 operations complete.\n");
    printf("[ETW-TI] Check Peregrine for: ALLOCVM_REMOTE, WRITEVM_REMOTE, READVM_REMOTE,\n");
    printf("         PROTECTVM_REMOTE, SUSPEND_THREAD, RESUME_THREAD,\n");
    printf("         ALLOCVM_LOCAL, PROTECTVM_LOCAL\n");
    printf("\nPress Enter to exit.\n");
    getchar();
    return 0;
}
