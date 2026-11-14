#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void callstack_init(void);

/* Walks the current stack and reports a "CallstackAnomaly" if a frame returns
   into executable private (unbacked) memory. Always runs — only the resulting
   message is rate-limited. `hook_name` must be a string literal; `target_pid`
   is the process the hooked operation acts on (the host PID for local ops).
   Returns 1 if an anomalous frame was found. */
int callstack_check(const char* hook_name, DWORD target_pid);

#ifdef __cplusplus
}
#endif
