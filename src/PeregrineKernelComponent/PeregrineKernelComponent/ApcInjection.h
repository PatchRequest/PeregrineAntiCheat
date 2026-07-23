#pragma once
#include <fltKernel.h>

/*
 * OpenEDR-style kernel APC DLL injection (LoadLibraryExW + RW path only).
 * Implementation: ApcInjection.c — no shellcode / no LdrLoadDll stub.
 */

#define INJ_POOL_TAG    'jnIp'
#define INJ_MAX_TARGETS 16
#define INJ_MAX_PENDING 32
#define INJ_MAX_NAME    260
#define INJ_MAX_PATH    260

VOID InjInit(VOID);
VOID InjCleanup(VOID);

NTSTATUS InjSetDllPath(_In_ BOOLEAN IsX86,
    _In_reads_bytes_(PathLenBytes) const WCHAR* Path,
    _In_ USHORT PathLenBytes);
NTSTATUS InjAddTarget(_In_reads_(NameLen) const CHAR* Name, _In_ ULONG NameLen);
NTSTATUS InjClearTargets(VOID);
VOID     InjSetEnabled(_In_ BOOLEAN Enabled);

VOID    InjOnProcessCreate(_In_ HANDLE ProcessId, _In_ PPS_CREATE_NOTIFY_INFO CreateInfo);
VOID    InjOnProcessExit(_In_ HANDLE ProcessId);
BOOLEAN InjOnThreadCreate(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId);
VOID    InjOnImageLoad(_In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ PIMAGE_INFO ImageInfo);
