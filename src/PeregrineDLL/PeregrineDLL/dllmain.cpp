// dllmain.cpp : Defines the entry point for the DLL application.
//
// Build roles (PEREGRINE_DLL_ROLE):
//   0 = Game   — full hooks + HWBP/VEH (inject into protected game)
//   1 = Sensor — external API hooks + callstack, no HWBP (inject into cheats)
//
#include "pch.h"
#include "MinHook.h"
#include "ipc.h"
#include "callstack.h"
#include "hwbp.h"
#include <stdio.h>
#include <stdarg.h>
// user32 loaded dynamically only when needed (DebugEntry)

#ifndef PEREGRINE_DLL_ROLE
#define PEREGRINE_DLL_ROLE 0
#endif
#define PEREGRINE_ROLE_GAME   0
#define PEREGRINE_ROLE_SENSOR 1
#if PEREGRINE_DLL_ROLE == PEREGRINE_ROLE_SENSOR
#define PEREGRINE_IS_SENSOR 1
#else
#define PEREGRINE_IS_SENSOR 0
#endif

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
}

static DWORD PID = GetCurrentProcessId();
static volatile LONG g_inited = 0;

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// ============================================================
// Original function pointers
// ============================================================
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef LPVOID(WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* VirtualProtectEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE(WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);
#if !PEREGRINE_IS_SENSOR
typedef LONG(NTAPI* NtSetContextThread_t)(HANDLE, PCONTEXT);
#endif

static NtReadVirtualMemory_t    oNtReadVirtualMemory = nullptr;
static NtWriteVirtualMemory_t   oNtWriteVirtualMemory = nullptr;
static VirtualAllocEx_t         oVirtualAllocEx = nullptr;
static VirtualProtectEx_t       oVirtualProtectEx = nullptr;
static CreateRemoteThread_t     oCreateRemoteThread = nullptr;
static OpenProcess_t            oOpenProcess = nullptr;
#if !PEREGRINE_IS_SENSOR
static NtSetContextThread_t     oNtSetContextThread = nullptr;
#endif

// ============================================================
// Hook implementations
// ============================================================
//
// Every hook: call through, run the call-stack check unconditionally, then
// report the operation if it targets another process. Reports go through
// ipc_log_event_limited (per event + target PID), so an API called in a loop
// yields a few lines plus a suppressed count instead of a flood.

// PID behind a process handle. GetProcessId needs QUERY_(LIMITED_)INFORMATION,
// which a handle opened with e.g. only PROCESS_VM_READ lacks — exactly the
// handle an external reader uses — so fall back to a re-opened duplicate.
// Returns 0 only if the target cannot be identified at all.
static DWORD TargetPidOf(HANDLE hProcess) {
    if (hProcess == GetCurrentProcess())
        return PID;

    DWORD pid = GetProcessId(hProcess);
    if (pid != 0)
        return pid;

    HANDLE dup = NULL;
    if (DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &dup,
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)) {
        pid = GetProcessId(dup);
        CloseHandle(dup);
    }
    return pid;
}

// ReadProcessMemory / WriteProcessMemory are not hooked separately: both are
// thin wrappers over these two ntdll exports, so hooking here reports each
// operation exactly once and also covers callers that skip KernelBase.
static NTSTATUS NTAPI HookNtReadVirtualMemory(HANDLE hProcess, PVOID base, PVOID buf, SIZE_T size, PSIZE_T pRead) {
    NTSTATUS status = oNtReadVirtualMemory(hProcess, base, buf, size, pRead);
    DWORD targetPID = TargetPidOf(hProcess);
    callstack_check("NtReadVirtualMemory", targetPID);
    if (targetPID != PID) {
        ipc_log_event_limited("ReadProcessMemory", NULL, targetPID,
            "\"callerPID\":%lu,\"targetPID\":%lu,\"address\":%llu,\"size\":%llu",
            PID, targetPID, (unsigned long long)(ULONG_PTR)base, (unsigned long long)size);
    }
    return status;
}

static NTSTATUS NTAPI HookNtWriteVirtualMemory(HANDLE hProcess, PVOID base, PVOID buf, SIZE_T size, PSIZE_T pWritten) {
    NTSTATUS status = oNtWriteVirtualMemory(hProcess, base, buf, size, pWritten);
    DWORD targetPID = TargetPidOf(hProcess);
    callstack_check("NtWriteVirtualMemory", targetPID);
    if (targetPID != PID) {
        ipc_log_event_limited("WriteProcessMemory", NULL, targetPID,
            "\"callerPID\":%lu,\"targetPID\":%lu,\"address\":%llu,\"size\":%llu",
            PID, targetPID, (unsigned long long)(ULONG_PTR)base, (unsigned long long)size);
    }
    return status;
}

static LPVOID WINAPI HookVirtualAllocEx(HANDLE hProcess, LPVOID lpAddr, SIZE_T dwSize, DWORD flType, DWORD flProtect) {
    LPVOID result = oVirtualAllocEx(hProcess, lpAddr, dwSize, flType, flProtect);
    DWORD targetPID = TargetPidOf(hProcess);
    callstack_check("VirtualAllocEx", targetPID);
    if (targetPID != PID) {
        ipc_log_event_limited("VirtualAllocEx", NULL, targetPID,
            "\"callerPID\":%lu,\"targetPID\":%lu,\"address\":%llu,\"size\":%llu,\"protect\":\"0x%08X\"",
            PID, targetPID, (unsigned long long)(ULONG_PTR)result, (unsigned long long)dwSize, flProtect);
    }
    return result;
}

static BOOL WINAPI HookVirtualProtectEx(HANDLE hProcess, LPVOID lpAddr, SIZE_T dwSize, DWORD flNew, PDWORD lpflOld) {
    BOOL result = oVirtualProtectEx(hProcess, lpAddr, dwSize, flNew, lpflOld);
    DWORD targetPID = TargetPidOf(hProcess);
    callstack_check("VirtualProtectEx", targetPID);
    if (targetPID != PID) {
        ipc_log_event_limited("VirtualProtectEx", NULL, targetPID,
            "\"callerPID\":%lu,\"targetPID\":%lu,\"address\":%llu,\"size\":%llu,\"newProtect\":\"0x%08X\"",
            PID, targetPID, (unsigned long long)(ULONG_PTR)lpAddr, (unsigned long long)dwSize, flNew);
    }
    return result;
}

static HANDLE WINAPI HookCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpAttr, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStart, LPVOID lpParam, DWORD dwFlags, LPDWORD lpTid) {
    HANDLE result = oCreateRemoteThread(hProcess, lpAttr, dwStackSize, lpStart, lpParam, dwFlags, lpTid);
    DWORD targetPID = TargetPidOf(hProcess);
    callstack_check("CreateRemoteThread", targetPID);
    if (targetPID != PID) {
        ipc_log_event_limited("CreateRemoteThread", NULL, targetPID,
            "\"callerPID\":%lu,\"targetPID\":%lu,\"startAddress\":%llu",
            PID, targetPID, (unsigned long long)(ULONG_PTR)lpStart);
    }
    return result;
}

static HANDLE WINAPI HookOpenProcess(DWORD dwAccess, BOOL bInherit, DWORD dwPID) {
    HANDLE result = oOpenProcess(dwAccess, bInherit, dwPID);
    callstack_check("OpenProcess", dwPID);
    // Same access the kernel ObCallback reports (obCallback.c DANGEROUS_PROCESS_ACCESS),
    // including not-yet-resolved generic / MAXIMUM_ALLOWED requests.
    const DWORD DANGEROUS = 0x0001 | 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0200 | 0x0800 |
                            MAXIMUM_ALLOWED | GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ;
    if (dwPID != PID && (dwAccess & DANGEROUS)) {
        ipc_log_event_limited("OpenProcess", NULL, dwPID,
            "\"callerPID\":%lu,\"targetPID\":%lu,\"access\":\"0x%08X\"",
            PID, dwPID, dwAccess);
    }
    return result;
}

#if !PEREGRINE_IS_SENSOR
#define CONTEXT_DBG_REGS_FLAG 0x00100010

static LONG NTAPI HookNtSetContextThread(HANDLE hThread, PCONTEXT ctx) {
    if (!g_hwbp_arming && ctx && (ctx->ContextFlags & CONTEXT_DBG_REGS_FLAG) == CONTEXT_DBG_REGS_FLAG) {
        if (ctx->Dr0 == 0 && ctx->Dr1 == 0 && ctx->Dr2 == 0 && ctx->Dr3 == 0 && ctx->Dr7 == 0) {
            callstack_check("NtSetContextThread", GetProcessIdOfThread(hThread));
            DWORD tid = GetThreadId(hThread);
            ipc_log_event("DebugRegisterClearing",
                "\"callerPID\":%lu,\"threadId\":%lu",
                PID, (unsigned long)tid);
        }
    }
    return oNtSetContextThread(hThread, ctx);
}
#endif

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
#if PEREGRINE_IS_SENSOR
    DebugLog("[PeregrineDLL] InitThread SENSOR started (PID=%lu)\n", PID);
#else
    DebugLog("[PeregrineDLL] InitThread GAME started (PID=%lu)\n", PID);
#endif

    if (MH_Initialize() != MH_OK) {
        DebugLog("[PeregrineDLL] MH_Initialize failed\n");
        return 0;
    }

    HMODULE kb    = GetModuleHandleW(L"KernelBase.dll");
    HMODULE k32   = GetModuleHandleW(L"kernel32.dll");
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    // Keep this list in sync with SELF_HOOKED_EXPORTS in
    // peregrine-tauri/src-tauri/src/detections/patch.rs (module integrity
    // excuses exactly these prologues as our own hooks).

    // Memory access hooks (both roles) — ntdll only, see HookNtReadVirtualMemory.
    InstallHook(ntdll, NULL, "NtReadVirtualMemory",  (void**)&oNtReadVirtualMemory,  (void*)HookNtReadVirtualMemory);
    InstallHook(ntdll, NULL, "NtWriteVirtualMemory", (void**)&oNtWriteVirtualMemory, (void*)HookNtWriteVirtualMemory);

    // Memory manipulation hooks
    InstallHook(kb, k32, "VirtualAllocEx",   (void**)&oVirtualAllocEx,   (void*)HookVirtualAllocEx);
    InstallHook(kb, k32, "VirtualProtectEx", (void**)&oVirtualProtectEx, (void*)HookVirtualProtectEx);

    // Thread/process hooks
    InstallHook(kb, k32, "CreateRemoteThread", (void**)&oCreateRemoteThread, (void*)HookCreateRemoteThread);
    InstallHook(kb, k32, "OpenProcess",        (void**)&oOpenProcess,        (void*)HookOpenProcess);

#if !PEREGRINE_IS_SENSOR
    // Game only: debug register / VEH protection
    InstallHook(ntdll, NULL, "NtSetContextThread", (void**)&oNtSetContextThread, (void*)HookNtSetContextThread);
#endif

    callstack_init();
#if !PEREGRINE_IS_SENSOR
    hwbp_init();
#endif
    DebugLog("[PeregrineDLL] Initialization complete\n");

    char exeName[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, exeName, MAX_PATH);
    const char* baseName = exeName;
    for (const char* p = exeName; *p; p++)
        if (*p == '\\' || *p == '/') baseName = p + 1;

#if PEREGRINE_IS_SENSOR
    ipc_log_event("hello",
        "\"callerPID\":%lu,\"image\":\"%s\",\"role\":\"sensor\"", PID, baseName);
#else
    ipc_log_event("hello",
        "\"callerPID\":%lu,\"image\":\"%s\",\"role\":\"game\"", PID, baseName);
#endif

    return 0;
}

extern "C" __declspec(dllexport) void CALLBACK DebugEntry(HWND, HINSTANCE, LPSTR, int) {
    EnsureConsole();
    DebugLog("[PeregrineDLL] DebugEntry running; press Ctrl+C or kill process to exit.\n");
    Sleep(INFINITE);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
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
