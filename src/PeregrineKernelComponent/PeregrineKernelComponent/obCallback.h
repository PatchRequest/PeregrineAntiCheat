#pragma once
#include <fltKernel.h>

/* ObCallback registration for process and thread handles (see obCallback.c). */
NTSTATUS createRegistration(void);
VOID unregisterRegistration(void);

/* Emits rate-limit counts whose burst has ended. PASSIVE_LEVEL, cheap to call often. */
VOID ObFlushSuppressedReports(VOID);
