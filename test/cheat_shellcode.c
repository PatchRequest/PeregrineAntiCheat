#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/* Shellcode injection: alloc RWX, write shellcode, create remote thread.
   Triggers: VirtualAllocEx hook, VirtualProtectEx hook, WriteProcessMemory hook,
   CreateRemoteThread hook, Thread RIP scan (suspicious - outside modules),
   ETW-TI (ALLOCVM_REMOTE, PROTECTVM_REMOTE, WRITEVM_REMOTE) */

/* Minimal x64 shellcode: just returns 0 (ExitThread(0) equivalent).
   In a real cheat this would be an aimbot/ESP payload. */
static const unsigned char shellcode[] = {
    0x48, 0x31, 0xC9,       /* xor rcx, rcx     */
    0x48, 0x31, 0xC0,       /* xor rax, rax     */
    0xC3                    /* ret              */
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

    /* Step 2: Write shellcode */
    SIZE_T written = 0;
    WriteProcessMemory(hProc, remoteMem, shellcode, sizeof(shellcode), &written);
    printf("[SHELLCODE] Wrote %zu bytes of shellcode\n", written);

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

    WaitForSingleObject(hThread, 5000);
    printf("[SHELLCODE] Thread completed\n");

    /* Leave memory allocated so thread scan can find it */
    printf("[SHELLCODE] Shellcode memory left at 0x%p for detection.\n", remoteMem);
    printf("[SHELLCODE] Press Enter to cleanup and exit.\n");
    getchar();

    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
