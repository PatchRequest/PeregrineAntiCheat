#pragma once
#include <fltKernel.h>
#include "AppState.h"

#define PEREGRINE_DEVICE_NAME      L"\\Device\\Peregrine"
#define PEREGRINE_SYMLINK_NAME     L"\\DosDevices\\Peregrine"

/* user -> kernel command; first byte is a COMS_COMMAND. The IOCTL status is the command's status. */
#define IOCTL_PEREGRINE_SEND_FROM_USER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* kernel -> user event queue; STATUS_NO_MORE_ENTRIES when empty (doubles as the liveness probe). */
#define IOCTL_PEREGRINE_RECV_TO_USER   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
/* in: ULONG pid; out: ULONG INJ_QUERY_* — did the kernel inject one of our DLLs into this PID? */
#define IOCTL_PEREGRINE_QUERY_INJECTED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*
 * Command bytes for IOCTL_PEREGRINE_SEND_FROM_USER.
 * Mirrored in src/peregrine-tauri/src-tauri/src/driver_comm.rs (mod cmd) — keep in sync.
 */
typedef enum _COMS_COMMAND {
    ComsCmdProtectPid          = 1,  /* HANDLE pid            -> PROTECTED set */
    ComsCmdUnprotectPid        = 2,  /* HANDLE pid */
    ComsCmdClearProtected      = 3,
    ComsCmdSetPpl              = 4,  /* HANDLE pid */
    ComsCmdScanDrivers         = 5,
    ComsCmdScanObCallbacks     = 6,
    ComsCmdSystemCheck         = 7,
    ComsCmdSetGameDllX64       = 8,  /* UTF-16LE DOS path, no NUL */
    ComsCmdSetGameDllX86       = 9,
    ComsCmdAddGameTarget       = 10, /* UTF-16LE normalized NT path of the target image, no NUL */
    ComsCmdSetInjectionEnabled = 11, /* UCHAR 0/1 */
    ComsCmdCollectHwid         = 12,
    ComsCmdScanVad             = 13, /* HANDLE pid */
    ComsCmdClearTargets        = 14,
    ComsCmdSetSensorDllX64     = 15,
    ComsCmdSetSensorDllX86     = 16,
    ComsCmdAddSensorTarget     = 17, /* same payload as ComsCmdAddGameTarget */
    ComsCmdTrustCaller         = 18, /* no payload: adds the *calling* process to the TRUSTED set */
} COMS_COMMAND;

// Maximum bytes per queued message and queue depth for kernel->user notifications.
#define COMS_MAX_MESSAGE_SIZE   1024
#define COMS_MAX_QUEUE_DEPTH    1024

NTSTATUS ComsInitialize(_In_ PDRIVER_OBJECT DriverObject);
VOID ComsCleanup(void);
NTSTATUS ComsCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS ComsDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

/*
 * Queue an event for the GUI. Never blocks. When the ring is full the oldest
 * entry is discarded and counted; the count is delivered as a "coms_overflow"
 * event ahead of the next message, so drops are never silent.
 */
NTSTATUS ComsSendToUser(_In_reads_bytes_(DataSize) const void* Data, _In_ ULONG DataSize);

/* Escape src for a JSON string value into dest (NUL-terminated). Returns FALSE on overflow. */
BOOLEAN JsonEscapeString(
    _Out_writes_bytes_(DestSize) PCHAR Dest,
    _In_ SIZE_T DestSize,
    _In_opt_ PCSTR Src);
