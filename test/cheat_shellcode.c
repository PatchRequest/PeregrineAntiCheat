#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/* Shellcode injection: alloc RWX, write shellcode, create remote thread.
   Triggers: VirtualAllocEx hook, VirtualProtectEx hook, WriteProcessMemory hook,
   CreateRemoteThread hook, Thread RIP scan (suspicious - outside modules),
   ETW-TI (ALLOCVM_REMOTE, PROTECTVM_REMOTE, WRITEVM_REMOTE) */

/* x64 shellcode: infinite sleep loop (simulates a persistent cheat thread).
   Thread RIP will always be inside this shellcode = outside any known module. */
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
        printf("Usage: cheat_shellcode.exe <PID>\n");
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    printf("[SHELLCODE] Target PID = %lu\n", pid);

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_READ | PROCESS_VM_WRITE,
        FALSE, pid);

    if (!hProc) {
        printf("[SHELLCODE] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[SHELLCODE] Handle acquired\n");

    /* Step 1: Allocate RW memory */
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteMem) {
        printf("[SHELLCODE] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }
    printf("[SHELLCODE] Allocated RW page at 0x%p\n", remoteMem);

    /* Step 2: Write shellcode with patched Sleep address */
    unsigned char sc[sizeof(shellcode)];
    memcpy(sc, shellcode, sizeof(sc));

    /* Patch Sleep() address at offset 17 (the qword after jmp) */
    FARPROC pSleep = GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep");
    *(ULONGLONG*)(sc + 17) = (ULONGLONG)pSleep;

    SIZE_T written = 0;
    WriteProcessMemory(hProc, remoteMem, sc, sizeof(sc), &written);
    printf("[SHELLCODE] Wrote %zu bytes of shellcode (Sleep=0x%llX)\n",
        written, (unsigned long long)pSleep);

    /* Step 3: Change to RWX (triggers VirtualProtectEx hook) */
    DWORD oldProtect = 0;
    VirtualProtectEx(hProc, remoteMem, 4096, PAGE_EXECUTE_READWRITE, &oldProtect);
    printf("[SHELLCODE] Changed protection to RWX\n");

    /* Step 4: Create remote thread pointing to shellcode */
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);

    if (!hThread) {
        printf("[SHELLCODE] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }
    printf("[SHELLCODE] Remote thread created at 0x%p\n", remoteMem);

    printf("[SHELLCODE] Remote thread running at 0x%p (sleeping loop)\n", remoteMem);
    printf("[SHELLCODE] Run 'Check Threads' in Peregrine to detect suspicious RIP.\n");
    printf("[SHELLCODE] Press Enter to cleanup and exit.\n");
    getchar();

    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
