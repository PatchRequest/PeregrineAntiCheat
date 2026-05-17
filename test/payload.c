#include <windows.h>

/* Payload DLL injected by cheat_inject.exe.
   Once loaded, it's detected by IAT scan (if it hooks anything)
   and by image load monitoring. */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)hModule; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        OutputDebugStringA("[PAYLOAD] DLL loaded into target process!\n");
    }
    return TRUE;
}
