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


typedef BOOL(WINAPI* ReadProcessMemory_t)(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead);

typedef BOOL(WINAPI* WriteProcessMemory_t)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten);

// Native API typedefs (NTSTATUS return value)
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten);

static ReadProcessMemory_t oReadProcessMemory = nullptr;
static WriteProcessMemory_t oWriteProcessMemory = nullptr;
static NtReadVirtualMemory_t oNtReadVirtualMemory = nullptr;
static NtWriteVirtualMemory_t oNtWriteVirtualMemory = nullptr;

static BOOL WINAPI HookReadProcessMemory(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead)
{
    // Call original function first
    BOOL result = oReadProcessMemory
        ? oReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)
        : FALSE;

    DWORD targetPID = GetProcessId(hProcess);
    DWORD gle = GetLastError();

    // Log to IPC
    ipc_log_readprocessmemory(
        hProcess,
        targetPID,
        lpBaseAddress,
        nSize,
        lpNumberOfBytesRead ? *lpNumberOfBytesRead : 0,
        result,
        gle,
        PID);

    return result;
}

static BOOL WINAPI HookWriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten)
{
    // Call original function first
    BOOL result = oWriteProcessMemory
        ? oWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
        : FALSE;

    DWORD targetPID = GetProcessId(hProcess);
    DWORD gle = GetLastError();

    // Log to IPC
    ipc_log_writeprocessmemory(
        hProcess,
        targetPID,
        lpBaseAddress,
        nSize,
        lpNumberOfBytesWritten ? *lpNumberOfBytesWritten : 0,
        result,
        gle,
        PID);

    return result;
}

static NTSTATUS NTAPI HookNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead)
{
    // Call original function first
    NTSTATUS status = oNtReadVirtualMemory
        ? oNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead)
        : -1;

    DWORD targetPID = GetProcessId(ProcessHandle);

    // Log to IPC
    ipc_log_readprocessmemory(
        ProcessHandle,
        targetPID,
        BaseAddress,
        NumberOfBytesToRead,
        NumberOfBytesRead ? *NumberOfBytesRead : 0,
        NT_SUCCESS(status),
        status,
        PID);

    return status;
}

static NTSTATUS NTAPI HookNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
    // Call original function first
    NTSTATUS status = oNtWriteVirtualMemory
        ? oNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten)
        : -1;

    DWORD targetPID = GetProcessId(ProcessHandle);

    // Log to IPC
    ipc_log_writeprocessmemory(
        ProcessHandle,
        targetPID,
        BaseAddress,
        NumberOfBytesToWrite,
        NumberOfBytesWritten ? *NumberOfBytesWritten : 0,
        NT_SUCCESS(status),
        status,
        PID);

    return status;
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
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    if (!kb && !k32) {
        DebugLog("[PeregrineDLL] Failed to locate KernelBase/kernel32 modules.\n");
    }

    // Hook ReadProcessMemory (kernel32/kernelbase)
    HookExport(kb, "ReadProcessMemory", (void**)&oReadProcessMemory, (void*)HookReadProcessMemory);
    if (!oReadProcessMemory)
        HookExport(k32, "ReadProcessMemory", (void**)&oReadProcessMemory, (void*)HookReadProcessMemory);
    if (oReadProcessMemory) {
        DebugLog("[PeregrineDLL] Successfully hooked ReadProcessMemory\n");
    } else {
        DebugLog("[PeregrineDLL] Failed to hook ReadProcessMemory.\n");
    }

    // Hook WriteProcessMemory (kernel32/kernelbase)
    HookExport(kb, "WriteProcessMemory", (void**)&oWriteProcessMemory, (void*)HookWriteProcessMemory);
    if (!oWriteProcessMemory)
        HookExport(k32, "WriteProcessMemory", (void**)&oWriteProcessMemory, (void*)HookWriteProcessMemory);
    if (oWriteProcessMemory) {
        DebugLog("[PeregrineDLL] Successfully hooked WriteProcessMemory\n");
    } else {
        DebugLog("[PeregrineDLL] Failed to hook WriteProcessMemory.\n");
    }

    // Hook NtReadVirtualMemory (ntdll - used by sophisticated cheats)
    HookExport(ntdll, "NtReadVirtualMemory", (void**)&oNtReadVirtualMemory, (void*)HookNtReadVirtualMemory);
    if (oNtReadVirtualMemory) {
        DebugLog("[PeregrineDLL] Successfully hooked NtReadVirtualMemory\n");
    } else {
        DebugLog("[PeregrineDLL] Failed to hook NtReadVirtualMemory.\n");
    }

    // Hook NtWriteVirtualMemory (ntdll - used by sophisticated cheats)
    HookExport(ntdll, "NtWriteVirtualMemory", (void**)&oNtWriteVirtualMemory, (void*)HookNtWriteVirtualMemory);
    if (oNtWriteVirtualMemory) {
        DebugLog("[PeregrineDLL] Successfully hooked NtWriteVirtualMemory\n");
    } else {
        DebugLog("[PeregrineDLL] Failed to hook NtWriteVirtualMemory.\n");
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

