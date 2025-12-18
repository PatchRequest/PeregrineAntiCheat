// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "MinHook.h"
#include "ipc.h"
#include <stdio.h>
#include <stdarg.h>
#pragma comment(lib, "user32.lib")

// Helper to log to OutputDebugString (viewable in DebugView)
static void DebugLog(const char* format, ...) {
    char buf[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    OutputDebugStringA(buf);
}

static volatile LONG g_console_ready = 0;
static void EnsureConsole() {
    // Only run once even if multiple threads race through InitThread.
    if (InterlockedCompareExchange(&g_console_ready, 1, 0) != 0) return;

    // Try to attach to the parent console; fall back to allocating a new one.
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        AllocConsole();
    }

    // Redirect stdout and stderr to the console for quick diagnostics.
    FILE* dummy = nullptr;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONOUT$", "w", stderr);
    freopen_s(&dummy, "CONIN$", "r", stdin);
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    // Make console visible and bring to front
    HWND consoleWnd = GetConsoleWindow();
    if (consoleWnd) {
        SetWindowPos(consoleWnd, HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        SetConsoleTitle(L"PeregrineDLL Debug Console");
        ShowWindow(consoleWnd, SW_SHOW);
        SetForegroundWindow(consoleWnd);
    }
}

static int PID = GetCurrentProcessId();
static volatile LONG g_inited = 0;


typedef HANDLE(WINAPI* CreateRemoteThreadEx_t)(
    HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
    LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);

static CreateRemoteThreadEx_t oCreateRemoteThreadEx = nullptr;
static HANDLE WINAPI HookCreateRemoteThreadEx(
    HANDLE hProcess, LPSECURITY_ATTRIBUTES sa, SIZE_T stackSize,
    LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags,
    LPPROC_THREAD_ATTRIBUTE_LIST attrList, LPDWORD tid)
{
    DebugLog("[PeregrineDLL] CreateRemoteThreadEx hook called!\n");

    HANDLE h = oCreateRemoteThreadEx
        ? oCreateRemoteThreadEx(hProcess, sa, stackSize, start, param, flags, attrList, tid)
        : NULL;

    DWORD gle = GetLastError();
    DebugLog("[PeregrineDLL] Logging CreateRemoteThreadEx to IPC...\n");

    ipc_log_createremotethreadex(
        hProcess,
        sa,
        stackSize,
        start,
        param,
        flags,
        attrList,
        tid,
        h,
        gle,
        PID);

    return h;
}





static void HookExport(HMODULE mod, LPCSTR name, void** pReal, void* hook) {
    if (!mod) return;
    if (void* p = (void*)GetProcAddress(mod, name)) {
        if (MH_CreateHook(p, hook, pReal) == MH_OK) MH_EnableHook(p);
    }
}

static DWORD WINAPI InitThread(LPVOID) {
    if (InterlockedCompareExchange(&g_inited, 1, 0) != 0) return 0;
    // EnsureConsole();  // Disabled to prevent console window from opening
    DebugLog("[PeregrineDLL] InitThread started (PID=%d)\n", PID);

    if (MH_Initialize() != MH_OK) {
        DebugLog("[PeregrineDLL] MH_Initialize failed; aborting hooks.\n");
        return 0;
    }
    DebugLog("[PeregrineDLL] MinHook initialized successfully\n");

    // write a hello world to the ipc pipe
    DebugLog("[PeregrineDLL] Attempting to send dll_loaded event via IPC...\n");
    ipc_write_json("{\"event\":\"dll_loaded\",\"message\":\"PeregrineDLL loaded successfully.\"}");
    DebugLog("[PeregrineDLL] IPC message sent (or failed silently if pipe not available)\n");

    HMODULE kb = GetModuleHandleW(L"KernelBase.dll");
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!kb && !k32) {
        DebugLog("[PeregrineDLL] Failed to locate KernelBase/kernel32 modules.\n");
    }

    HookExport(kb, "CreateRemoteThreadEx", (void**)&oCreateRemoteThreadEx, (void*)HookCreateRemoteThreadEx);
    if (!oCreateRemoteThreadEx)
        HookExport(k32, "CreateRemoteThreadEx", (void**)&oCreateRemoteThreadEx, (void*)HookCreateRemoteThreadEx);
    if (oCreateRemoteThreadEx) {
        DebugLog("[PeregrineDLL] Successfully hooked CreateRemoteThreadEx\n");
    } else {
        DebugLog("[PeregrineDLL] Failed to hook CreateRemoteThreadEx.\n");
    }

    DebugLog("[PeregrineDLL] Initialization complete\n");
    return 0;
}

// Debug entry for rundll32 to force console visibility and keep process alive.
extern "C" __declspec(dllexport) void CALLBACK DebugEntry(HWND, HINSTANCE, LPSTR, int) {
    EnsureConsole();
    DebugLog("[PeregrineDLL] DebugEntry running; press Ctrl+C or kill process to exit.\n");
    Sleep(INFINITE);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        HANDLE th = CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
        if (th) CloseHandle(th);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

