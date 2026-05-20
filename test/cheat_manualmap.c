#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/* Manual-map simulation: allocates executable private memory in a target process,
   writes a fake PE + shellcode, and optionally erases the PE header.
   Triggers: VAD scan (executable private memory, no image backing).
   Run with --no-header to erase MZ signature after writing. */

static const unsigned char shellcode[] = {
    0x48, 0x83, 0xEC, 0x28,                /* sub rsp, 0x28         */
    0xB9, 0xE8, 0x03, 0x00, 0x00,          /* mov ecx, 1000         */
    0xFF, 0x15, 0x02, 0x00, 0x00, 0x00,    /* call [rip+2]          */
    0xEB, 0xF3,                             /* jmp back to mov ecx   */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* Sleep addr (patched) */
};

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: cheat_manualmap.exe <PID> [--no-header]\n");
        printf("  Simulates manual-mapped DLL injection.\n");
        printf("  --no-header  Erase PE header after writing (advanced evasion)\n");
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    int erase_header = 0;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--no-header") == 0) erase_header = 1;
    }

    printf("[MANUALMAP] Target PID = %lu%s\n", pid,
        erase_header ? " (will erase PE header)" : "");

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_READ | PROCESS_VM_WRITE,
        FALSE, pid);
    if (!hProc) {
        printf("[MANUALMAP] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    /* Allocate 64 KB to simulate a realistic DLL size */
    SIZE_T allocSize = 64 * 1024;
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, allocSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        printf("[MANUALMAP] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }
    printf("[MANUALMAP] Allocated %zu KB RW at 0x%p\n", allocSize / 1024, remoteMem);

    /* Build a fake PE image in local buffer */
    unsigned char* localBuf = (unsigned char*)calloc(1, allocSize);

    /* Minimal MZ + PE header so the VAD scanner can detect PE signature */
    localBuf[0] = 'M';
    localBuf[1] = 'Z';
    *(DWORD*)(localBuf + 0x3C) = 0x80;         /* e_lfanew */
    *(DWORD*)(localBuf + 0x80) = 0x00004550;    /* PE\0\0 signature */
    *(WORD*)(localBuf + 0x84)  = 0x8664;        /* Machine: AMD64 */

    /* Write shellcode at offset 0x1000 (simulated .text section) */
    SIZE_T codeOff = 0x1000;
    memcpy(localBuf + codeOff, shellcode, sizeof(shellcode));

    /* Patch Sleep address */
    FARPROC pSleep = GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep");
    *(ULONGLONG*)(localBuf + codeOff + 17) = (ULONGLONG)pSleep;

    /* Write the whole buffer into the target */
    SIZE_T written = 0;
    WriteProcessMemory(hProc, remoteMem, localBuf, allocSize, &written);
    printf("[MANUALMAP] Wrote %zu bytes (fake PE + shellcode)\n", written);

    /* Change to executable */
    DWORD oldProt = 0;
    VirtualProtectEx(hProc, remoteMem, allocSize, PAGE_EXECUTE_READ, &oldProt);
    printf("[MANUALMAP] Changed protection to EXECUTE_READ\n");

    /* Optionally erase PE header to simulate advanced manual mapper */
    if (erase_header) {
        unsigned char zeros[0x200] = { 0 };
        WriteProcessMemory(hProc, remoteMem, zeros, sizeof(zeros), &written);
        printf("[MANUALMAP] Erased PE header (%zu bytes zeroed)\n", written);
    }

    /* Create remote thread at the shellcode offset */
    LPVOID entryPoint = (LPBYTE)remoteMem + codeOff;
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);
    if (!hThread) {
        printf("[MANUALMAP] CreateRemoteThread failed: %lu\n", GetLastError());
    } else {
        printf("[MANUALMAP] Thread running at 0x%p\n", entryPoint);
    }

    printf("\n[MANUALMAP] Manual-mapped region at 0x%p (%zu KB)\n", remoteMem, allocSize / 1024);
    printf("[MANUALMAP] Click 'VAD' in Peregrine to detect this region.\n");
    printf("[MANUALMAP] Press Enter to cleanup and exit.\n");
    getchar();

    if (hThread) {
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
    }
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProc);
    free(localBuf);
    return 0;
}
