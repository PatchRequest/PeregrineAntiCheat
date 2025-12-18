#pragma once
#include <ntddk.h>
#include "AppState.h"

#define PEREGRINE_DEVICE_NAME      L"\\Device\\Peregrine"
#define PEREGRINE_SYMLINK_NAME     L"\\DosDevices\\Peregrine"

#define IOCTL_PEREGRINE_SEND_FROM_USER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PEREGRINE_RECV_TO_USER   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Maximum bytes per queued message and queue depth for kernel->user notifications.
#define COMS_MAX_MESSAGE_SIZE   1024
#define COMS_MAX_QUEUE_DEPTH    1024

NTSTATUS ComsInitialize(_In_ PDRIVER_OBJECT DriverObject);
VOID ComsCleanup(void);
NTSTATUS ComsCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS ComsDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS ComsSendToUser(_In_reads_bytes_(DataSize) const void* Data, _In_ ULONG DataSize);
