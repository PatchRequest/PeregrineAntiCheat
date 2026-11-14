#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Writes a raw JSON string to the named pipe; best-effort and may silently fail.
void ipc_write_json(const char* json);

// Sends {"event":"<event>",<fmt...>}. `fmt` produces the remaining JSON members,
// e.g. ipc_log_event("HwbpInit", "\"status\":\"ok\",\"threadsArmed\":%d", n).
// Unlimited: use only for lifecycle and inherently rare events.
void ipc_log_event(const char* event, const char* fmt, ...);

// Same, but rate-limited per (event, subkey, target_pid) so a hooked API called
// in a loop cannot flood the pipe. The limit applies to the *message only* —
// callers run their detection first and unconditionally. Nothing is dropped
// silently: every emitted message carries "suppressed":<n>, the number of
// identical-key messages swallowed since the previous one, and a key that is
// evicted while still holding a count is flushed as a "RateLimitFlush" event.
//
// `event` and `subkey` (may be NULL) must be string literals / static storage.
void ipc_log_event_limited(const char* event, const char* subkey, DWORD target_pid,
                           const char* fmt, ...);

#ifdef __cplusplus
}
#endif
