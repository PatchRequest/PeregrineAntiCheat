#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* Simulates a cheat that injects a config + code block into a target process.
   The injected memory contains unique marker strings that the YARA rule matches.
   Triggers: YARA scan (PeregrineTestCheat rule) */

static const char cheat_payload[] =
    "PEREGRINE_CHEAT_MARKER_v1\0"
    "[cheat_config]\n"
    "aimbot_fov=2.5\n"
    "aimbot_smooth=0.8\n"
    "esp_enabled=1\n"
    "esp_box=1\n"
    "esp_health=1\n"
    "triggerbot_delay=45\n";

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: cheat_yara.exe <PID>\n");
        printf("  Injects cheat config into target. Detected by YARA rule.\n");
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    printf("[YARA-TEST] Target PID = %lu\n", pid);

    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProc) {
        printf("[YARA-TEST] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    LPVOID remote = VirtualAllocEx(hProc, NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        printf("[YARA-TEST] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    SIZE_T written = 0;
    WriteProcessMemory(hProc, remote, cheat_payload, sizeof(cheat_payload), &written);
    printf("[YARA-TEST] Wrote %zu bytes at 0x%p\n", written, remote);

    printf("[YARA-TEST] Click YARA in Peregrine to detect.\n");
    printf("[YARA-TEST] Press Enter to cleanup.\n");
    getchar();

    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return 0;
}
