#include "Coms.h"
#include "Protection.h"
#include "DriverScan.h"
#include "ObCallbackScan.h"
#include "SystemCheck.h"
#include "ApcInjection.h"
#include "Hwid.h"
#include "VadScan.h"
#include "obCallback.h"
#include <wdmsec.h>
#include <ntstrsafe.h>

#pragma comment(lib, "wdmsec.lib")

/* Administrators + SYSTEM only — not world-open. */
#define PEREGRINE_DEVICE_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

BOOLEAN JsonEscapeString(
    _Out_writes_bytes_(DestSize) PCHAR Dest,
    _In_ SIZE_T DestSize,
    _In_opt_ PCSTR Src)
{
    if (!Dest || DestSize == 0)
        return FALSE;

    Dest[0] = '\0';
    if (!Src)
        return TRUE;

    SIZE_T out = 0;
    for (const unsigned char* p = (const unsigned char*)Src; *p; p++) {
        CHAR esc[8];
        SIZE_T elen = 0;

        switch (*p) {
        case '\\':  esc[0] = '\\'; esc[1] = '\\'; elen = 2; break;
        case '"':   esc[0] = '\\'; esc[1] = '"';  elen = 2; break;
        case '\b':  esc[0] = '\\'; esc[1] = 'b';  elen = 2; break;
        case '\f':  esc[0] = '\\'; esc[1] = 'f';  elen = 2; break;
        case '\n':  esc[0] = '\\'; esc[1] = 'n';  elen = 2; break;
        case '\r':  esc[0] = '\\'; esc[1] = 'r';  elen = 2; break;
        case '\t':  esc[0] = '\\'; esc[1] = 't';  elen = 2; break;
        default:
            if (*p < 0x20) {
                /* \u00XX */
                static const CHAR hex[] = "0123456789abcdef";
                esc[0] = '\\'; esc[1] = 'u'; esc[2] = '0'; esc[3] = '0';
                esc[4] = hex[(*p >> 4) & 0xF];
                esc[5] = hex[*p & 0xF];
                elen = 6;
            } else {
                esc[0] = (CHAR)*p;
                elen = 1;
            }
            break;
        }

        if (out + elen + 1 > DestSize)
            return FALSE;
        for (SIZE_T i = 0; i < elen; i++)
            Dest[out++] = esc[i];
    }
    Dest[out] = '\0';
    return TRUE;
}

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

/* Events discarded because the ring was full; reported by the next RECV. */
static ULONG g_Dropped = 0;

/* Upper bound for the synthesized overflow notice (see ComsDeviceControl). */
#define COMS_OVERFLOW_NOTICE_MAX 96

static NTSTATUS ReadPidArg(
    _In_reads_bytes_(DataSize) const UCHAR* Data,
    _In_ ULONG DataSize,
    _Out_ HANDLE* Pid)
{
    *Pid = NULL;
    if (DataSize < 1 + sizeof(HANDLE))
        return STATUS_BUFFER_TOO_SMALL;
    RtlCopyMemory(Pid, Data + 1, sizeof(HANDLE)); /* payload is unaligned */
    return STATUS_SUCCESS;
}

/*
 * PASSIVE_LEVEL. RequestorPid is the process that issued the IOCTL.
 * The returned status becomes the IOCTL status, so the GUI sees real failures.
 */
static NTSTATUS ComsHandleUserCommand(
    _In_reads_bytes_(DataSize) const UCHAR* Data,
    _In_ ULONG DataSize,
    _In_ HANDLE RequestorPid)
{
    if (!Data || DataSize == 0)
        return STATUS_INVALID_PARAMETER;

    const UCHAR* payload = Data + 1;
    const ULONG payloadSize = DataSize - 1;
    HANDLE pid = NULL;
    NTSTATUS status;

    switch (Data[0]) {
    case ComsCmdProtectPid:
        status = ReadPidArg(Data, DataSize, &pid);
        if (NT_SUCCESS(status))
            status = StateProtectPid(pid);
        return status;

    case ComsCmdUnprotectPid:
        status = ReadPidArg(Data, DataSize, &pid);
        if (NT_SUCCESS(status))
            status = StateUnprotectPid(pid);
        return status;

    case ComsCmdClearProtected:
        StateClearProtected();
        return STATUS_SUCCESS;

    case ComsCmdSetPpl:
        status = ReadPidArg(Data, DataSize, &pid);
        if (NT_SUCCESS(status))
            status = ProtectionSetProcessPPL(pid);
        return status;

    case ComsCmdScanDrivers:
        return DriverScanEnumerate();

    case ComsCmdScanObCallbacks:
        return ObCallbackScanEnumerate();

    case ComsCmdSystemCheck:
        return SystemCheckRunAll();

    case ComsCmdSetGameDllX64:
        return InjSetDllPath(INJ_ROLE_GAME, FALSE, payload, payloadSize);

    case ComsCmdSetGameDllX86:
        return InjSetDllPath(INJ_ROLE_GAME, TRUE, payload, payloadSize);

    case ComsCmdAddGameTarget:
        return InjAddTarget(INJ_ROLE_GAME, payload, payloadSize);

    case ComsCmdSetInjectionEnabled:
        if (payloadSize < 1)
            return STATUS_BUFFER_TOO_SMALL;
        InjSetEnabled(payload[0] != 0);
        return STATUS_SUCCESS;

    case ComsCmdCollectHwid:
        return HwidCollectAll();

    case ComsCmdScanVad:
        status = ReadPidArg(Data, DataSize, &pid);
        if (NT_SUCCESS(status))
            status = VadScanProcess(pid);
        return status;

    case ComsCmdClearTargets:
        InjClearTargets();
        InjSetEnabled(FALSE);
        return STATUS_SUCCESS;

    case ComsCmdSetSensorDllX64:
        return InjSetDllPath(INJ_ROLE_SENSOR, FALSE, payload, payloadSize);

    case ComsCmdSetSensorDllX86:
        return InjSetDllPath(INJ_ROLE_SENSOR, TRUE, payload, payloadSize);

    case ComsCmdAddSensorTarget:
        return InjAddTarget(INJ_ROLE_SENSOR, payload, payloadSize);

    case ComsCmdTrustCaller:
        /* Deliberately takes no PID: a process can only ever vouch for itself. */
        return StateTrustPid(RequestorPid);

    default:
        KdPrint(("Peregrine: unknown command 0x%02X\n", Data[0]));
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

/* printf-append into a shrinking buffer; any failure means "does not fit". */
static NTSTATUS StateAppend(
    _Inout_ PCHAR* Cursor,
    _Inout_ size_t* Remaining,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...)
{
    va_list args;
    va_start(args, Format);
    NTSTATUS status = RtlStringCbVPrintfExA(*Cursor, *Remaining, Cursor, Remaining, 0, Format, args);
    va_end(args);
    return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
}

/* PASSIVE_LEVEL. Writes the IOCTL_PEREGRINE_QUERY_STATE reply (see Coms.h). */
static NTSTATUS ComsBuildStateJson(
    _Out_writes_bytes_(OutSize) PCHAR Out,
    _In_ size_t OutSize,
    _Out_ ULONG_PTR* Written)
{
    static const PCSTR roleNames[INJ_ROLE_COUNT] = { "game", "sensor" };

    PCHAR cur = Out;
    size_t remaining = OutSize;
    *Written = 0;

    NTSTATUS status = StateAppend(&cur, &remaining,
        "{ \"injection_enabled\": %s, \"protected\": [",
        InjIsEnabled() ? "true" : "false");
    if (!NT_SUCCESS(status)) return status;

    HANDLE pids[STATE_MAX_PROTECTED];
    const ULONG pidCount = StateSnapshotProtected(pids, ARRAYSIZE(pids));
    for (ULONG i = 0; i < pidCount; i++) {
        status = StateAppend(&cur, &remaining, "%s%lu",
            i ? ", " : "", (ULONG)(ULONG_PTR)pids[i]);
        if (!NT_SUCCESS(status)) return status;
    }

    status = StateAppend(&cur, &remaining, "], \"targets\": [");
    if (!NT_SUCCESS(status)) return status;

    BOOLEAN first = TRUE;
    for (UCHAR role = 0; role < INJ_ROLE_COUNT; role++) {
        WCHAR path[INJ_MAX_PATH];
        for (ULONG i = 0; InjGetTarget(role, i, path); i++) {
            UNICODE_STRING wide;
            ANSI_STRING ansi = { 0 };
            RtlInitUnicodeString(&wide, path);
            status = RtlUnicodeStringToAnsiString(&ansi, &wide, TRUE);
            if (!NT_SUCCESS(status)) return status;

            /* Worst case every character is escaped to two. */
            CHAR escaped[INJ_MAX_PATH * 2 + 1];
            const BOOLEAN ok = JsonEscapeString(escaped, sizeof(escaped), ansi.Buffer);
            RtlFreeAnsiString(&ansi);
            if (!ok) return STATUS_BUFFER_TOO_SMALL;

            status = StateAppend(&cur, &remaining,
                "%s{ \"role\": \"%s\", \"path\": \"%s\" }",
                first ? "" : ", ", roleNames[role], escaped);
            if (!NT_SUCCESS(status)) return status;
            first = FALSE;
        }
    }

    status = StateAppend(&cur, &remaining, "] }");
    if (!NT_SUCCESS(status)) return status;

    *Written = (ULONG_PTR)(cur - Out);
    return STATUS_SUCCESS;
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

    // If full, discard the oldest entry (never block producers) and count it.
    if (g_Count == COMS_MAX_QUEUE_DEPTH) {
        g_Tail = (g_Tail + 1) % COMS_MAX_QUEUE_DEPTH;
        g_Count--;
        if (g_Dropped != MAXULONG)
            g_Dropped++;
    }

    RtlCopyMemory(g_MessageQueue[g_Head].Data, Data, DataSize);
    g_MessageQueue[g_Head].Length = DataSize;
    g_Head = (g_Head + 1) % COMS_MAX_QUEUE_DEPTH;
    g_Count++;

    KeReleaseSpinLock(&g_ComsLock, oldIrql);
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

    /*
     * The device ACL admits every administrator, and a cheat may well run
     * elevated. Being able to open the device is therefore not enough: only
     * the one process that holds TRUSTED may configure the driver or read its
     * events. The single exception is the request that asks for that trust
     * (ComsCmdTrustCaller), which StateTrustPid grants to one process only.
     */
    const HANDLE requestor = (HANDLE)(ULONG_PTR)IoGetRequestorProcessId(Irp);
    const ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    BOOLEAN allowed = StateIsPidTrusted(requestor);
    if (!allowed && ioctl == IOCTL_PEREGRINE_SEND_FROM_USER &&
        Irp->AssociatedIrp.SystemBuffer != NULL &&
        stack->Parameters.DeviceIoControl.InputBufferLength >= 1 &&
        *(const UCHAR*)Irp->AssociatedIrp.SystemBuffer == ComsCmdTrustCaller) {
        allowed = TRUE;
    }
    if (!allowed) {
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }

    switch (ioctl) {
    case IOCTL_PEREGRINE_SEND_FROM_USER: {
        const ULONG inLength = stack->Parameters.DeviceIoControl.InputBufferLength;
        if (Irp->AssociatedIrp.SystemBuffer == NULL || inLength == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (inLength > COMS_MAX_MESSAGE_SIZE) {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        status = ComsHandleUserCommand(
            (const UCHAR*)Irp->AssociatedIrp.SystemBuffer, inLength, requestor);
        information = 0;
        break;
    }
    case IOCTL_PEREGRINE_QUERY_INJECTED: {
        if (Irp->AssociatedIrp.SystemBuffer == NULL ||
            stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG) ||
            stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        ULONG pid = 0;
        RtlCopyMemory(&pid, Irp->AssociatedIrp.SystemBuffer, sizeof(pid));
        ULONG role = InjQueryRole((HANDLE)(ULONG_PTR)pid);
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &role, sizeof(role));
        information = sizeof(role);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_PEREGRINE_QUERY_STATE: {
        const ULONG outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
        if (Irp->AssociatedIrp.SystemBuffer == NULL || outLength == 0) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = ComsBuildStateJson((PCHAR)Irp->AssociatedIrp.SystemBuffer, outLength, &information);
        if (!NT_SUCCESS(status))
            information = 0;
        break;
    }
    case IOCTL_PEREGRINE_RECV_TO_USER: {
        const ULONG outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG dropped = 0;

        /* The poll is the driver's only periodic PASSIVE_LEVEL tick. */
        ObFlushSuppressedReports();

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_ComsLock, &oldIrql);

        /* Pending overflow notice goes out first; the queue itself is left
           untouched and is drained by the following calls. */
        if (g_Dropped != 0) {
            if (outLength < COMS_OVERFLOW_NOTICE_MAX) {
                status = STATUS_BUFFER_TOO_SMALL;
                KeReleaseSpinLock(&g_ComsLock, oldIrql);
                break;
            }
            dropped = g_Dropped;
            g_Dropped = 0;
            KeReleaseSpinLock(&g_ComsLock, oldIrql);

            /* Formatted outside the spinlock (PASSIVE_LEVEL). */
            PCHAR out = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
            status = RtlStringCchPrintfA(out, COMS_OVERFLOW_NOTICE_MAX,
                "{ \"event\": \"coms_overflow\", \"dropped\": %lu }", dropped);
            if (NT_SUCCESS(status))
                information = strlen(out);
            break;
        }

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
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(PEREGRINE_DEVICE_SDDL);

    KeInitializeSpinLock(&g_ComsLock);

    /* Restrict device open to SYSTEM + Administrators (not world-writable). */
    NTSTATUS status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        NULL,
        &g_ComsDevice);

    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: IoCreateDeviceSecure failed 0x%X\n", status));
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
