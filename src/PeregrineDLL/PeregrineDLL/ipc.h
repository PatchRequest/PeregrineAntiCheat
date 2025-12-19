#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif
    
// Writes a raw JSON string to the named pipe; best-effort and may silently fail.
void ipc_write_json(const char* json);

// Sends a ReadProcessMemory event to the userland IPC pipe as JSON.
void ipc_log_readprocessmemory(
    HANDLE hProcess,
    DWORD targetPID,
    LPCVOID lpBaseAddress,
    SIZE_T nSize,
    SIZE_T bytesRead,
    BOOL result,
    DWORD lastError,
    DWORD callerPid);

// Sends a WriteProcessMemory event to the userland IPC pipe as JSON.
void ipc_log_writeprocessmemory(
    HANDLE hProcess,
    DWORD targetPID,
    LPVOID lpBaseAddress,
    SIZE_T nSize,
    SIZE_T bytesWritten,
    BOOL result,
    DWORD lastError,
    DWORD callerPid);

#ifdef __cplusplus
}
#endif




