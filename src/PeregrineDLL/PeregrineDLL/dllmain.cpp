// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "MinHook.h"
#include "ipc.h"
#include <stdio.h>
#include <stdarg.h>
#pragma comment(lib, "user32.lib")

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
    if (InterlockedCompareExchange(&g_console_ready, 1, 0) != 0) return;
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) AllocConsole();
    FILE* dummy = nullptr;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONOUT$", "w", stderr);
    freopen_s(&dummy, "CONIN$", "r", stdin);
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    HWND consoleWnd = GetConsoleWindow();
    if (consoleWnd) {
        SetWindowPos(consoleWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        SetConsoleTitle(L"PeregrineDLL Debug Console");
        ShowWindow(consoleWnd, SW_SHOW);
        SetForegroundWindow(consoleWnd);
    }
}

static DWORD PID = GetCurrentProcessId();
static volatile LONG g_inited = 0;

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// ============================================================
// Original function pointers
// ============================================================
typedef BOOL(WINAPI* ReadProcessMemory_t)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef LPVOID(WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* VirtualProtectEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE(WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);

static ReadProcessMemory_t      oReadProcessMemory = nullptr;
static WriteProcessMemory_t     oWriteProcessMemory = nullptr;
static NtReadVirtualMemory_t    oNtReadVirtualMemory = nullptr;
static NtWriteVirtualMemory_t   oNtWriteVirtualMemory = nullptr;
static VirtualAllocEx_t         oVirtualAllocEx = nullptr;
static VirtualProtectEx_t       oVirtualProtectEx = nullptr;
static CreateRemoteThread_t     oCreateRemoteThread = nullptr;
static OpenProcess_t            oOpenProcess = nullptr;

// ============================================================
// Hook implementations
// ============================================================

static BOOL WINAPI HookReadProcessMemory(HANDLE hProcess, LPCVOID lpBase, LPVOID lpBuf, SIZE_T nSize, SIZE_T* pRead) {
    BOOL result = oReadProcessMemory(hProcess, lpBase, lpBuf, nSize, pRead);
    DWORD targetPID = GetProcessId(hProcess);
    ipc_log_event("ReadProcessMemory",
        "\"callerPID\":%lu,\"targetPID\":%lu,\"address\":%llu,\"size\":%llu",
        PID, targetPID, (unsigned long long)(ULONG_PTR)lpBase, (unsigned long long)nSize);
    return result;
}

static BOOL WINAPI HookWriteProcessMemory(HANDLE hProcess, LPVOID lpBase, LPCVOID lpBuf, SIZE_T nSize, SIZE_T* pWritten) {
    BOOL result = oWriteProcessMemory(hProcess, lpBase, lpBuf, nSize, pWritten);
    DWORD targetPID = GetProcessId(hProcess);
    ipc_log_event("WriteProcessMemory",
        "\"callerPID\":%lu,\"targetPID\":%lu,\"address\":%llu,\"size\":%llu",
        PID, targetPID, (unsigned long long)(ULONG_PTR)lpBase, (unsigned long long)nSize);
    return result;
}

static NTSTATUS NTAPI HookNtReadVirtualMemory(HANDLE hProcess, PVOID base, PVOID buf, SIZE_T size, PSIZE_T pRead) {
    NTSTATUS status = oNtReadVirtualMemory(hProcess, base, buf, size, pRead);
    DWORD targetPID = GetProcessId(hProcess);
    ipc_log_event("ReadProcessMemory",
        "\"callerPID\":%lu,\"targetPID\":%lu,\"address\":%llu,\"size\":%llu",
        PID, targetPID, (unsigned long long)(ULONG_PTR)base, (unsigned long long)size);
    return status;
}

static NTSTATUS NTAPI HookNtWriteVirtualMemory(HANDLE hProcess, PVOID base, PVOID buf, SIZE_T size, PSIZE_T pWritten) {
    NTSTATUS status = oNtWriteVirtualMemory(hProcess, base, buf, size, pWritten);
    DWORD targetPID = GetProcessId(hProcess);
    ipc_log_event("WriteProcessMemory",
        "\"callerPID\":%lu,\"targetPID\":%lu,\"address\":%llu,\"size\":%llu",
        PID, targetPID, (unsigned long long)(ULONG_PTR)base, (unsigned long long)size);
    return status;
}

static LPVOID WINAPI HookVirtualAllocEx(HANDLE hProcess, LPVOID lpAddr, SIZE_T dwSize, DWORD flType, DWORD flProtect) {
    LPVOID result = oVirtualAllocEx(hProcess, lpAddr, dwSize, flType, flProtect);
    DWORD targetPID = GetProcessId(hProcess);
    if (targetPID != PID) {
        ipc_log_event("VirtualAllocEx",
            "\"callerPID\":%lu,\"targetPID\":%lu,\"address\":%llu,\"size\":%llu,\"protect\":\"0x%08X\"",
            PID, targetPID, (unsigned long long)(ULONG_PTR)result, (unsigned long long)dwSize, flProtect);
    }
    return result;
}

static BOOL WINAPI HookVirtualProtectEx(HANDLE hProcess, LPVOID lpAddr, SIZE_T dwSize, DWORD flNew, PDWORD lpflOld) {
    BOOL result = oVirtualProtectEx(hProcess, lpAddr, dwSize, flNew, lpflOld);
    DWORD targetPID = GetProcessId(hProcess);
    if (targetPID != PID) {
        ipc_log_event("VirtualProtectEx",
            "\"callerPID\":%lu,\"targetPID\":%lu,\"address\":%llu,\"size\":%llu,\"newProtect\":\"0x%08X\"",
            PID, targetPID, (unsigned long long)(ULONG_PTR)lpAddr, (unsigned long long)dwSize, flNew);
    }
    return result;
}

static HANDLE WINAPI HookCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpAttr, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStart, LPVOID lpParam, DWORD dwFlags, LPDWORD lpTid) {
    HANDLE result = oCreateRemoteThread(hProcess, lpAttr, dwStackSize, lpStart, lpParam, dwFlags, lpTid);
    DWORD targetPID = GetProcessId(hProcess);
    if (targetPID != PID) {
        ipc_log_event("CreateRemoteThread",
            "\"callerPID\":%lu,\"targetPID\":%lu,\"startAddress\":%llu",
            PID, targetPID, (unsigned long long)(ULONG_PTR)lpStart);
    }
    return result;
}

static HANDLE WINAPI HookOpenProcess(DWORD dwAccess, BOOL bInherit, DWORD dwPID) {
    HANDLE result = oOpenProcess(dwAccess, bInherit, dwPID);
    // Only log dangerous access flags, skip query-only
    const DWORD DANGEROUS = 0x0001 | 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0800;
    if (dwPID != PID && (dwAccess & DANGEROUS)) {
        ipc_log_event("OpenProcess",
            "\"callerPID\":%lu,\"targetPID\":%lu,\"access\":\"0x%08X\"",
            PID, dwPID, dwAccess);
    }
    return result;
}

// ============================================================
// Hook setup helpers
// ============================================================

static void HookExport(HMODULE mod, LPCSTR name, void** pReal, void* hook) {
    if (!mod) return;
    if (void* p = (void*)GetProcAddress(mod, name)) {
        if (MH_CreateHook(p, hook, pReal) == MH_OK) MH_EnableHook(p);
    }
}

// Try hooking in primary module first, fall back to secondary
static bool InstallHook(HMODULE primary, HMODULE fallback, LPCSTR name, void** pReal, void* hook) {
    HookExport(primary, name, pReal, hook);
    if (!*pReal && fallback)
        HookExport(fallback, name, pReal, hook);
    if (*pReal) {
        DebugLog("[PeregrineDLL] Hooked %s\n", name);
        return true;
    }
    DebugLog("[PeregrineDLL] Failed to hook %s\n", name);
    return false;
}

// ============================================================
// Init
// ============================================================

static DWORD WINAPI InitThread(LPVOID) {
    if (InterlockedCompareExchange(&g_inited, 1, 0) != 0) return 0;
    DebugLog("[PeregrineDLL] InitThread started (PID=%lu)\n", PID);

    if (MH_Initialize() != MH_OK) {
        DebugLog("[PeregrineDLL] MH_Initialize failed\n");
        return 0;
    }

    ipc_write_json("{\"event\":\"dll_loaded\",\"message\":\"PeregrineDLL loaded successfully.\"}");

    HMODULE kb    = GetModuleHandleW(L"KernelBase.dll");
    HMODULE k32   = GetModuleHandleW(L"kernel32.dll");
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    // Memory access hooks
    InstallHook(kb, k32, "ReadProcessMemory",  (void**)&oReadProcessMemory,  (void*)HookReadProcessMemory);
    InstallHook(kb, k32, "WriteProcessMemory", (void**)&oWriteProcessMemory, (void*)HookWriteProcessMemory);
    InstallHook(ntdll, NULL, "NtReadVirtualMemory",  (void**)&oNtReadVirtualMemory,  (void*)HookNtReadVirtualMemory);
    InstallHook(ntdll, NULL, "NtWriteVirtualMemory", (void**)&oNtWriteVirtualMemory, (void*)HookNtWriteVirtualMemory);

    // Memory manipulation hooks
    InstallHook(kb, k32, "VirtualAllocEx",   (void**)&oVirtualAllocEx,   (void*)HookVirtualAllocEx);
    InstallHook(kb, k32, "VirtualProtectEx", (void**)&oVirtualProtectEx, (void*)HookVirtualProtectEx);

    // Thread/process hooks
    InstallHook(kb, k32, "CreateRemoteThread", (void**)&oCreateRemoteThread, (void*)HookCreateRemoteThread);
    InstallHook(kb, k32, "OpenProcess",        (void**)&oOpenProcess,        (void*)HookOpenProcess);

    DebugLog("[PeregrineDLL] Initialization complete\n");
    return 0;
}

extern "C" __declspec(dllexport) void CALLBACK DebugEntry(HWND, HINSTANCE, LPSTR, int) {
    EnsureConsole();
    DebugLog("[PeregrineDLL] DebugEntry running; press Ctrl+C or kill process to exit.\n");
    Sleep(INFINITE);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
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
