#include "Hwid.h"
#include "Coms.h"
#include <ntstrsafe.h>

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

// IOCTL_STORAGE_QUERY_PROPERTY = CTL_CODE(0x2d, 0x500, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HWID_IOCTL_STORAGE_QUERY_PROPERTY 0x002D1400

typedef struct {
    ULONG PropertyId;   // 0 = StorageDeviceProperty
    ULONG QueryType;    // 0 = PropertyStandardQuery
    UCHAR AdditionalParameters[1];
} HWID_STORAGE_QUERY;

typedef struct {
    ULONG Version;
    ULONG Size;
    UCHAR DeviceType;
    UCHAR DeviceTypeModifier;
    BOOLEAN RemovableMedia;
    BOOLEAN CommandQueueing;
    ULONG VendorIdOffset;
    ULONG ProductIdOffset;
    ULONG ProductRevisionOffset;
    ULONG SerialNumberOffset;
    ULONG BusType;
    ULONG RawPropertiesLength;
    UCHAR RawDeviceProperties[1];
} HWID_STORAGE_DESCRIPTOR;

#define SystemBootEnvironmentInformation 0x5A

// ============================================================
// Disk Serial via IOCTL_STORAGE_QUERY_PROPERTY
// ============================================================

static void TrimSpaces(char* s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len > 0 && s[len - 1] == ' ') s[--len] = '\0';
    // trim leading spaces
    char* start = s;
    while (*start == ' ') start++;
    if (start != s) RtlMoveMemory(s, start, strlen(start) + 1);
}

static void CollectDiskSerial(ULONG idx) {
    WCHAR path[64];
    RtlStringCchPrintfW(path, ARRAYSIZE(path), L"\\Device\\Harddisk%lu\\DR0", idx);

    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &devName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDisk = NULL;
    IO_STATUS_BLOCK iosb = { 0 };
    NTSTATUS status = ZwCreateFile(&hDisk, GENERIC_READ | SYNCHRONIZE, &oa, &iosb,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(status)) return;

    HWID_STORAGE_QUERY query = { 0 };
    UCHAR buf[1024] = { 0 };

    status = ZwDeviceIoControlFile(hDisk, NULL, NULL, NULL, &iosb,
        HWID_IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), buf, sizeof(buf));
    ZwClose(hDisk);
    if (!NT_SUCCESS(status)) return;

    HWID_STORAGE_DESCRIPTOR* desc = (HWID_STORAGE_DESCRIPTOR*)buf;

    char serial[128] = { 0 };
    char vendor[128] = { 0 };
    char product[128] = { 0 };

    if (desc->SerialNumberOffset && desc->SerialNumberOffset < sizeof(buf))
        { RtlStringCchCopyA(serial, sizeof(serial), (char*)(buf + desc->SerialNumberOffset)); TrimSpaces(serial); }
    if (desc->VendorIdOffset && desc->VendorIdOffset < sizeof(buf))
        { RtlStringCchCopyA(vendor, sizeof(vendor), (char*)(buf + desc->VendorIdOffset)); TrimSpaces(vendor); }
    if (desc->ProductIdOffset && desc->ProductIdOffset < sizeof(buf))
        { RtlStringCchCopyA(product, sizeof(product), (char*)(buf + desc->ProductIdOffset)); TrimSpaces(product); }

    if (serial[0] == '\0') return;

    CHAR json[COMS_MAX_MESSAGE_SIZE];
    RtlStringCchPrintfA(json, ARRAYSIZE(json),
        "{ \"event\": \"hwid_data\", \"source\": \"kernel\", "
        "\"name\": \"disk_serial_%lu\", \"value\": \"%s\", "
        "\"detail\": \"%s %s\" }", idx, serial, vendor, product);
    ComsSendToUser(json, (ULONG)strlen(json));
}

// ============================================================
// Boot GUID via ZwQuerySystemInformation
// ============================================================

static void CollectBootGuid(void) {
    UCHAR buf[64] = { 0 };
    NTSTATUS status = ZwQuerySystemInformation(SystemBootEnvironmentInformation, buf, sizeof(buf), NULL);
    if (!NT_SUCCESS(status)) return;

    GUID* g = (GUID*)buf;
    CHAR json[COMS_MAX_MESSAGE_SIZE];
    RtlStringCchPrintfA(json, ARRAYSIZE(json),
        "{ \"event\": \"hwid_data\", \"source\": \"kernel\", "
        "\"name\": \"boot_guid\", \"value\": \"%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\" }",
        g->Data1, g->Data2, g->Data3,
        g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3],
        g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
    ComsSendToUser(json, (ULONG)strlen(json));
}

// ============================================================
// Entry point
// ============================================================

NTSTATUS HwidCollectAll(void) {
    KdPrint(("Peregrine: HWID collection starting\n"));

    for (ULONG i = 0; i < 4; i++)
        CollectDiskSerial(i);

    CollectBootGuid();

    CHAR json[COMS_MAX_MESSAGE_SIZE];
    RtlStringCchPrintfA(json, ARRAYSIZE(json), "{ \"event\": \"hwid_kernel_complete\" }");
    ComsSendToUser(json, (ULONG)strlen(json));

    KdPrint(("Peregrine: HWID collection complete\n"));
    return STATUS_SUCCESS;
}
