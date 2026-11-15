#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* VEH-handler and hardware-breakpoint detection, see hwbp.c. Game DLL only. */
void hwbp_init(void);

/* Detour for ntdll!RtlAddVectoredExceptionHandler; dllmain.cpp installs it and
   stores the trampoline in hwbp_orig_add_veh before hwbp_init() runs. */
typedef PVOID (NTAPI* hwbp_add_veh_t)(ULONG first, PVECTORED_EXCEPTION_HANDLER handler);
extern hwbp_add_veh_t hwbp_orig_add_veh;
PVOID NTAPI hwbp_hook_add_veh(ULONG first, PVECTORED_EXCEPTION_HANDLER handler);

#ifdef __cplusplus
}
#endif
