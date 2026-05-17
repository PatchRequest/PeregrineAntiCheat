#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/* Classic DLL injection via CreateRemoteThread + LoadLibraryA.
   Triggers: ObCallback, CreateRemoteThread hook, VirtualAllocEx hook,
   WriteProcessMemory hook, ETW-TI (ALLOCVM_REMOTE, WRITEVM_REMOTE) */

int main(int argc, char* argv[])
{
    if (argc < 3) {
        printf("Usage: cheat_inject.exe <PID> <DLL_PATH>\n");
        printf("Example: cheat_inject.exe 1234 C:\\path\\to\\payload.dll\n");
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    const char* dllPath = argv[2];

    printf("[INJECT] Target PID = %lu\n", pid);
    printf("[INJECT] DLL = %s\n", dllPath);

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_READ | PROCESS_VM_WRITE,
        FALSE, pid);

    if (!hProc) {
        printf("[INJECT] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[INJECT] Handle acquired\n");

    size_t pathLen = strlen(dllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, pathLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteMem) {
        printf("[INJECT] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }
    printf("[INJECT] Allocated %zu bytes at 0x%p\n", pathLen, remoteMem);

    SIZE_T written = 0;
    WriteProcessMemory(hProc, remoteMem, dllPath, pathLen, &written);
    printf("[INJECT] Wrote DLL path (%zu bytes)\n", written);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibA = GetProcAddress(hKernel32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibA, remoteMem, 0, NULL);

    if (!hThread) {
        printf("[INJECT] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }
    printf("[INJECT] Remote thread created, waiting...\n");

    WaitForSingleObject(hThread, 5000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    printf("[INJECT] Thread exited, HMODULE = 0x%lX\n", exitCode);

    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);

    printf("[INJECT] Done. Press Enter to exit.\n");
    getchar();
    return 0;
}
