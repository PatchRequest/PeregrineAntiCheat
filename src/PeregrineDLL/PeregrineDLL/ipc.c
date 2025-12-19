// Simple IPC helper for sending JSON events to the named pipe listener.
#include <stdio.h>
#include "ipc.h"
#include <string.h>
#include <stdarg.h>
#include <windows.h>

#define IPC_PIPE_NAMEA "\\\\.\\pipe\\peregrine_ipc"

// Helper to log to OutputDebugString (viewable in DebugView)
static void DebugLog(const char* format, ...) {
    char buf[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    OutputDebugStringA(buf);
}

static ULONGLONG ptr_to_ull(const void* p) {
    return (ULONGLONG)(ULONG_PTR)p;
}

// Best-effort write; failures are logged to console.
void ipc_write_json(const char* json) {
    if (!json) return;

    // Avoid blocking indefinitely if nobody is listening.
    if (!WaitNamedPipeA(IPC_PIPE_NAMEA, 500)) {
        DWORD err = GetLastError();
        // Silently fail - pipe not being available is normal
        DebugLog("[IPC] Pipe not available (err=%lu)\n", err);
        return;
    }

    HANDLE h = CreateFileA(
        IPC_PIPE_NAMEA,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (h == INVALID_HANDLE_VALUE) {
        DebugLog("[IPC] CreateFile failed: %lu\n", GetLastError());
        return;
    }

    DWORD len = (DWORD)strlen(json);
    DWORD written = 0;
    if (!WriteFile(h, json, len, &written, NULL)) {
        DebugLog("[IPC] WriteFile failed: %lu\n", GetLastError());
    } else if (written != len) {
        DebugLog("[IPC] Partial write: %lu/%lu bytes\n", written, len);
    } else {
        DebugLog("[IPC] Sent %lu bytes successfully\n", written);
    }
    CloseHandle(h);
}

void ipc_log_readprocessmemory(
    HANDLE hProcess,
    DWORD targetPID,
    LPCVOID lpBaseAddress,
    SIZE_T nSize,
    SIZE_T bytesRead,
    BOOL result,
    DWORD lastError,
    DWORD callerPid)
{
    char buf[512] = {0};

    _snprintf_s(
        buf,
        sizeof(buf),
        _TRUNCATE,
        "{\"event\":\"ReadProcessMemory\",\"callerPID\":%lu,\"targetPID\":%lu,"
        "\"hProcess\":%llu,\"address\":%llu,\"size\":%llu,\"bytesRead\":%llu,"
        "\"success\":%d,\"lastError\":%lu}",
        (unsigned long)callerPid,
        (unsigned long)targetPID,
        (unsigned long long)ptr_to_ull(hProcess),
        (unsigned long long)ptr_to_ull(lpBaseAddress),
        (unsigned long long)nSize,
        (unsigned long long)bytesRead,
        result ? 1 : 0,
        (unsigned long)lastError);

    ipc_write_json(buf);
}

void ipc_log_writeprocessmemory(
    HANDLE hProcess,
    DWORD targetPID,
    LPVOID lpBaseAddress,
    SIZE_T nSize,
    SIZE_T bytesWritten,
    BOOL result,
    DWORD lastError,
    DWORD callerPid)
{
    char buf[512] = {0};

    _snprintf_s(
        buf,
        sizeof(buf),
        _TRUNCATE,
        "{\"event\":\"WriteProcessMemory\",\"callerPID\":%lu,\"targetPID\":%lu,"
        "\"hProcess\":%llu,\"address\":%llu,\"size\":%llu,\"bytesWritten\":%llu,"
        "\"success\":%d,\"lastError\":%lu}",
        (unsigned long)callerPid,
        (unsigned long)targetPID,
        (unsigned long long)ptr_to_ull(hProcess),
        (unsigned long long)ptr_to_ull(lpBaseAddress),
        (unsigned long long)nSize,
        (unsigned long long)bytesWritten,
        result ? 1 : 0,
        (unsigned long)lastError);

    ipc_write_json(buf);
}
