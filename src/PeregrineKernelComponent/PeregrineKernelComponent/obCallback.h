#pragma once
#include <fltKernel.h>

/* ObCallback registration for process and thread handles (see obCallback.c). */
NTSTATUS createRegistration(void);
VOID unregisterRegistration(void);
