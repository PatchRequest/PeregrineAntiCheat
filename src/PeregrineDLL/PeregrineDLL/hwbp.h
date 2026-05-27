#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void hwbp_init(void);

/* Set by hwbp.c while it manipulates debug registers itself,
   so the NtSetContextThread hook can skip our own calls. */
extern volatile LONG g_hwbp_arming;

#ifdef __cplusplus
}
#endif
