#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif
    
// Writes a raw JSON string to the named pipe; best-effort and may silently fail.
void ipc_write_json(const char* json);

// Sends a CreateRemoteThreadEx event to the userland IPC pipe as JSON.
// All pointer-sized values are emitted as unsigned 64-bit integers.
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
    DWORD callerPid);

#ifdef __cplusplus
}
#endif




