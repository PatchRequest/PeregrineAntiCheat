#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/* Code patching: writes NOPs into the .text section of a module.
   Triggers: Module Integrity Check (hash mismatch / tamper detection),
   WriteProcessMemory hook, ETW-TI (WRITEVM_REMOTE, PROTECTVM_REMOTE) */

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: cheat_patch.exe <PID>\n");
        printf("Patches the first 4 bytes of kernel32.dll's .text in the target.\n");
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    printf("[PATCH] Target PID = %lu\n", pid);

    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_QUERY_INFORMATION,
        FALSE, pid);

    if (!hProc) {
        printf("[PATCH] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    /* Find kernel32.dll base in target via snapshot */
    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    if (!EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        printf("[PATCH] EnumProcessModules failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    ULONG_PTR patchAddr = 0;
    int modCount = cbNeeded / sizeof(HMODULE);
    for (int i = 0; i < modCount; i++) {
        char name[MAX_PATH];
        if (GetModuleFileNameExA(hProc, hMods[i], name, MAX_PATH)) {
            if (strstr(name, "kernel32.dll") || strstr(name, "KERNEL32.DLL")) {
                /* Read the PE headers to find .text section */
                IMAGE_DOS_HEADER dos;
                ReadProcessMemory(hProc, hMods[i], &dos, sizeof(dos), NULL);
                if (dos.e_magic != IMAGE_DOS_SIGNATURE) continue;

                IMAGE_NT_HEADERS64 nt;
                ReadProcessMemory(hProc, (BYTE*)hMods[i] + dos.e_lfanew, &nt, sizeof(nt), NULL);

                /* Find .text section */
                DWORD secOff = dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
                for (int s = 0; s < nt.FileHeader.NumberOfSections; s++) {
                    IMAGE_SECTION_HEADER sec;
                    ReadProcessMemory(hProc, (BYTE*)hMods[i] + secOff + s * sizeof(sec), &sec, sizeof(sec), NULL);
                    if (memcmp(sec.Name, ".text", 5) == 0) {
                        patchAddr = (ULONG_PTR)hMods[i] + sec.VirtualAddress + 0x100;
                        break;
                    }
                }
                break;
            }
        }
    }

    if (!patchAddr) {
        printf("[PATCH] Could not find .text section\n");
        CloseHandle(hProc);
        return 1;
    }

    /* Read original bytes */
    unsigned char orig[4];
    ReadProcessMemory(hProc, (LPCVOID)patchAddr, orig, 4, NULL);
    printf("[PATCH] Original bytes at 0x%llX: %02X %02X %02X %02X\n",
        (unsigned long long)patchAddr, orig[0], orig[1], orig[2], orig[3]);

    /* Make writable */
    DWORD oldProtect;
    VirtualProtectEx(hProc, (LPVOID)patchAddr, 4, PAGE_EXECUTE_READWRITE, &oldProtect);

    /* Write NOPs */
    unsigned char nops[4] = { 0x90, 0x90, 0x90, 0x90 };
    SIZE_T written = 0;
    WriteProcessMemory(hProc, (LPVOID)patchAddr, nops, 4, &written);
    printf("[PATCH] Wrote %zu NOP bytes at 0x%llX\n", written, (unsigned long long)patchAddr);

    /* Restore protection */
    VirtualProtectEx(hProc, (LPVOID)patchAddr, 4, oldProtect, &oldProtect);

    printf("[PATCH] Code patched! Run 'Check Modules' in Peregrine to detect.\n");
    printf("[PATCH] Restoring in 30 seconds...\n");
    Sleep(30000);

    /* Restore original bytes */
    VirtualProtectEx(hProc, (LPVOID)patchAddr, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(hProc, (LPVOID)patchAddr, orig, 4, NULL);
    VirtualProtectEx(hProc, (LPVOID)patchAddr, 4, oldProtect, &oldProtect);
    printf("[PATCH] Original bytes restored.\n");

    CloseHandle(hProc);
    return 0;
}
