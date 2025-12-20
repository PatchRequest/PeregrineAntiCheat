#include "Coms.h"
#include "Protection.h"

static PDEVICE_OBJECT g_ComsDevice = NULL;
static KSPIN_LOCK g_ComsLock;
static BOOLEAN g_SymbolicLinkCreated = FALSE;

typedef struct _COMS_MESSAGE {
    UCHAR Data[COMS_MAX_MESSAGE_SIZE];
    ULONG Length;
} COMS_MESSAGE, *PCOMS_MESSAGE;

static COMS_MESSAGE g_MessageQueue[COMS_MAX_QUEUE_DEPTH];
static ULONG g_Head = 0; // Next insertion point
static ULONG g_Tail = 0; // Next removal point
static ULONG g_Count = 0;

static VOID ComsHandleUserCommand(_In_reads_bytes_(DataSize) const UCHAR* Data,
    _In_ ULONG DataSize)
{
    if (!Data || DataSize == 0) {
        KdPrint(("Peregrine: empty/NULL user command\n"));
        return;
    }
    KdPrint(("Peregrine: Received command 0x%02X, DataSize=%lu\n", Data[0], DataSize));
    HANDLE pid = 0;
    switch (Data[0]) {
    case 1: { // set PID
        if (DataSize < 1 + sizeof(HANDLE)) {
            KdPrint(("Peregrine: cmd=1 too small (%lu)\n", DataSize));
            return;
        }
        
        RtlCopyMemory(&pid, Data + 1, sizeof(pid)); // avoid unaligned deref
		StateAddPid(pid);
        KdPrint(("Peregrine: user set target PID to %ld\n", pid));
        break;
    }
    case 2:
        if (DataSize < 1 + sizeof(HANDLE)) {
            KdPrint(("Peregrine: cmd=1 too small (%lu)\n", DataSize));
            return;
        }
        
        RtlCopyMemory(&pid, Data + 1, sizeof(pid)); // avoid unaligned deref
        StateRemovePid(pid);
        KdPrint(("Peregrine: user set target PID to %ld\n", pid));
        break;

    case 3:
	{ // clear all PIDs
        StateClearPids();
		KdPrint(("Peregrine: user cleared all target PIDs\n"));
		break;
	}

    case 4: { // set process to PPL
        if (DataSize < 1 + sizeof(HANDLE)) {
            KdPrint(("Peregrine: cmd=4 too small (%lu)\n", DataSize));
            return;
        }
        
        RtlCopyMemory(&pid, Data + 1, sizeof(pid));

        NTSTATUS status = ProtectionSetProcessPPL(pid);
        if (NT_SUCCESS(status)) {
            KdPrint(("Peregrine: Set PID %lu to PPL successfully\n", (ULONG)(ULONG_PTR)pid));
        } else {
            KdPrint(("Peregrine: Failed to set PID %lu to PPL: 0x%X\n", (ULONG)(ULONG_PTR)pid, status));
        }
        break;
    }

    default:
        KdPrint(("Peregrine: unknown command 0x%02X\n", Data[0]));
        break;
    }
}

NTSTATUS ComsSendToUser(_In_reads_bytes_(DataSize) const void* Data, _In_ ULONG DataSize) {
    if (Data == NULL || DataSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (DataSize > COMS_MAX_MESSAGE_SIZE) {
        DataSize = COMS_MAX_MESSAGE_SIZE;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ComsLock, &oldIrql);

    // If full, overwrite the oldest (advance tail) to avoid blocking producers.
    if (g_Count == COMS_MAX_QUEUE_DEPTH) {
        g_Tail = (g_Tail + 1) % COMS_MAX_QUEUE_DEPTH;
        g_Count--;
    }

    RtlCopyMemory(g_MessageQueue[g_Head].Data, Data, DataSize);
    g_MessageQueue[g_Head].Length = DataSize;
    g_Head = (g_Head + 1) % COMS_MAX_QUEUE_DEPTH;
    g_Count++;

    KeReleaseSpinLock(&g_ComsLock, oldIrql);

    //KdPrint(("Peregrine: queued %lu bytes for user retrieval (depth %lu/%u)\n", DataSize, g_Count, COMS_MAX_QUEUE_DEPTH));
    return STATUS_SUCCESS;
}

NTSTATUS ComsCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS ComsDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG_PTR information = 0;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_PEREGRINE_SEND_FROM_USER: {
        const ULONG inLength = stack->Parameters.DeviceIoControl.InputBufferLength;
        if (Irp->AssociatedIrp.SystemBuffer == NULL || inLength == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        const ULONG bytesToProcess = (inLength > COMS_MAX_MESSAGE_SIZE) ? COMS_MAX_MESSAGE_SIZE : inLength;
        ComsHandleUserCommand((const UCHAR*)Irp->AssociatedIrp.SystemBuffer, bytesToProcess);
        status = STATUS_SUCCESS;
        information = 0;
        break;
    }
    case IOCTL_PEREGRINE_RECV_TO_USER: {
        const ULONG outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_ComsLock, &oldIrql);

        if (g_Count == 0) {
            status = STATUS_NO_MORE_ENTRIES;
            KeReleaseSpinLock(&g_ComsLock, oldIrql);
            break;
        }

        const ULONG available = g_MessageQueue[g_Tail].Length;

        if (outLength < available) {
            status = STATUS_BUFFER_TOO_SMALL;
            KeReleaseSpinLock(&g_ComsLock, oldIrql);
            break;
        }

        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, g_MessageQueue[g_Tail].Data, available);
        information = available;
        status = STATUS_SUCCESS;

        // Pop the entry.
        g_Tail = (g_Tail + 1) % COMS_MAX_QUEUE_DEPTH;
        g_Count--;

        KeReleaseSpinLock(&g_ComsLock, oldIrql);
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS ComsInitialize(_In_ PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(PEREGRINE_DEVICE_NAME);
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(PEREGRINE_SYMLINK_NAME);

    KeInitializeSpinLock(&g_ComsLock);

    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_ComsDevice);

    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: IoCreateDevice failed 0x%X\n", status));
        return status;
    }

    g_ComsDevice->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: IoCreateSymbolicLink failed 0x%X\n", status));
        IoDeleteDevice(g_ComsDevice);
        g_ComsDevice = NULL;
        return status;
    }

    g_SymbolicLinkCreated = TRUE;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = ComsCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = ComsCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ComsDeviceControl;

    g_ComsDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

VOID ComsCleanup(void) {
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(PEREGRINE_SYMLINK_NAME);

    if (g_SymbolicLinkCreated) {
        IoDeleteSymbolicLink(&symLink);
        g_SymbolicLinkCreated = FALSE;
    }

    if (g_ComsDevice != NULL) {
        IoDeleteDevice(g_ComsDevice);
        g_ComsDevice = NULL;
    }

    KdPrint(("Peregrine: communications cleanup complete\n"));
}
