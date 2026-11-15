#pragma once
#include <fltKernel.h>

/*
 * OpenEDR-style kernel APC DLL injection (LoadLibraryExW + RW path only).
 * Implementation: ApcInjection.c — no shellcode / no LdrLoadDll stub.
 */

#define INJ_POOL_TAG     'jnIp'
#define INJ_MAX_TARGETS  16
#define INJ_MAX_PENDING  32
#define INJ_MAX_INJECTED 64
#define INJ_MAX_PATH     260

/* Inject roles: different DLL paths + target lists */
#define INJ_ROLE_GAME   ((UCHAR)0)
#define INJ_ROLE_SENSOR ((UCHAR)1)
#define INJ_ROLE_COUNT  2

/* InjQueryRole results (IOCTL_PEREGRINE_QUERY_INJECTED output). */
#define INJ_QUERY_NONE   ((ULONG)0)
#define INJ_QUERY_GAME   ((ULONG)1)
#define INJ_QUERY_SENSOR ((ULONG)2)

VOID InjInit(VOID);
/* DriverUnload, after the notify routines are gone: waits until no APC that
   runs code of this image is pending any more. */
VOID InjWaitForApcs(VOID);

/* Path: UTF-16LE DOS path of the DLL, no terminator, possibly unaligned. */
NTSTATUS InjSetDllPath(_In_ UCHAR Role, _In_ BOOLEAN IsX86,
    _In_reads_bytes_(PathBytes) const VOID* Path,
    _In_ ULONG PathBytes);

/*
 * Path: UTF-16LE normalized NT path of the target image
 * (\Device\HarddiskVolumeN\dir\game.exe), no terminator, possibly unaligned.
 * Targets are identified by this full path only — never by basename — so a
 * binary that is merely *named* like the game is neither injected nor protected.
 */
NTSTATUS InjAddTarget(_In_ UCHAR Role,
    _In_reads_bytes_(PathBytes) const VOID* Path,
    _In_ ULONG PathBytes);
NTSTATUS InjClearTargets(VOID);
VOID     InjSetEnabled(_In_ BOOLEAN Enabled);

/* State readback for the GUI (IOCTL_PEREGRINE_QUERY_STATE). */
BOOLEAN  InjIsEnabled(VOID);
/* Copies target number Index of Role (upper-cased NT path, NUL-terminated)
   into Dest. FALSE once Index is past the end of the list. */
BOOLEAN  InjGetTarget(_In_ UCHAR Role, _In_ ULONG Index,
    _Out_writes_(INJ_MAX_PATH) WCHAR* Dest);

/* INJ_QUERY_*: which of our DLLs (if any) the kernel injected into Pid. */
ULONG    InjQueryRole(_In_ HANDLE Pid);

VOID    InjOnProcessCreate(_In_ HANDLE ProcessId, _In_ PPS_CREATE_NOTIFY_INFO CreateInfo);
VOID    InjOnProcessExit(_In_ HANDLE ProcessId);
VOID    InjOnImageLoad(_In_ HANDLE ProcessId,
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ PIMAGE_INFO ImageInfo);
