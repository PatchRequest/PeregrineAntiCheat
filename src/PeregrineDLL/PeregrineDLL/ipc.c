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

void ipc_log_createremotethreadex(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES sa,
    SIZE_T stackSize,
    LPTHREAD_START_ROUTINE start,
    LPVOID param,
    DWORD flags,
    LPPROC_THREAD_ATTRIBUTE_LIST attrList,
    LPDWORD tid,
    HANDLE threadHandle,
    DWORD lastError,
    DWORD callerPid)
{
    char buf[512] = {0};
    DWORD tid_val = 0;
    if (tid) {
        __try { tid_val = *tid; }
        __except (EXCEPTION_EXECUTE_HANDLER) { tid_val = 0; }
    }

    _snprintf_s(
        buf,
        sizeof(buf),
        _TRUNCATE,
        "{\"event\":\"CreateRemoteThreadEx\",\"callerPID\":%lu,\"hProcess\":%llu,"
        "\"stackSize\":%llu,\"start\":%llu,\"param\":%llu,\"flags\":%lu,"
        "\"attrList\":%llu,\"threadId\":%lu,\"resultHandle\":%llu,\"lastError\":%lu}",
        (unsigned long)callerPid,
        (unsigned long long)ptr_to_ull(hProcess),
        (unsigned long long)stackSize,
        (unsigned long long)ptr_to_ull(start),
        (unsigned long long)ptr_to_ull(param),
        (unsigned long)flags,
        (unsigned long long)ptr_to_ull(attrList),
        (unsigned long)tid_val,
        (unsigned long long)ptr_to_ull(threadHandle),
        (unsigned long)lastError);

    ipc_write_json(buf);
}
