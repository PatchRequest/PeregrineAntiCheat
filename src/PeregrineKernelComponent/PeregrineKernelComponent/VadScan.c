#include "VadScan.h"
#include "Coms.h"
#include <ntstrsafe.h>

// ZwQueryVirtualMemory is declared in ntifs.h (included via fltKernel.h)
// but uses MEMORY_INFORMATION_CLASS enum. We pass 0 = MemoryBasicInformation.

NTSTATUS NTAPI MmCopyVirtualMemory(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _Out_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T ReturnSize
);

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif

typedef struct _MEMORY_BASIC_INFORMATION_KM {
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    USHORT PartitionId;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} MEMORY_BASIC_INFORMATION_KM;

#define MBI_MEM_COMMIT  0x1000
#define MBI_MEM_IMAGE   0x1000000
#define MBI_MEM_PRIVATE 0x20000
#define MBI_MEM_MAPPED  0x40000

#define MBI_PAGE_EXECUTE           0x10
#define MBI_PAGE_EXECUTE_READ      0x20
#define MBI_PAGE_EXECUTE_READWRITE 0x40
#define MBI_PAGE_EXECUTE_WRITECOPY 0x80
#define MBI_EXECUTE_FLAGS (MBI_PAGE_EXECUTE | MBI_PAGE_EXECUTE_READ | MBI_PAGE_EXECUTE_READWRITE | MBI_PAGE_EXECUTE_WRITECOPY)

#define MBI_PAGE_GUARD 0x100

// Usermode address limit on x64
#define USER_ADDR_MAX 0x00007FFFFFFFFFFFULL

static const char* ProtString(ULONG prot) {
    switch (prot & 0xFF) {
    case MBI_PAGE_EXECUTE:           return "EXECUTE";
    case MBI_PAGE_EXECUTE_READ:      return "EXECUTE_READ";
    case MBI_PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
    case MBI_PAGE_EXECUTE_WRITECOPY: return "EXECUTE_WRITECOPY";
    default:                         return "EXECUTE_?";
    }
}

static const char* TypeString(ULONG type) {
    switch (type) {
    case MBI_MEM_IMAGE:   return "IMAGE";
    case MBI_MEM_MAPPED:  return "MAPPED";
    case MBI_MEM_PRIVATE: return "PRIVATE";
    default:              return "?";
    }
}

NTSTATUS VadScanProcess(_In_ HANDLE ProcessId) {
    NTSTATUS status;
    PEPROCESS process = NULL;
    PEPROCESS selfProcess = PsGetCurrentProcess();
    HANDLE hProc = NULL;

    KdPrint(("Peregrine: VAD scan for PID %lu\n", (ULONG)(ULONG_PTR)ProcessId));

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: PsLookupProcessByProcessId failed 0x%X\n", status));
        return status;
    }

    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, *PsProcessType, KernelMode, &hProc);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        KdPrint(("Peregrine: ObOpenObjectByPointer failed 0x%X\n", status));
        return status;
    }

    ULONG_PTR addr = 0;
    ULONG hits = 0;
    ULONG totalRegions = 0;

    while (addr < USER_ADDR_MAX) {
        MEMORY_BASIC_INFORMATION_KM mbi = { 0 };
        SIZE_T retLen = 0;

        status = ZwQueryVirtualMemory(hProc, (PVOID)addr, 0 /* MemoryBasicInformation */,
            &mbi, sizeof(mbi), &retLen);
        if (!NT_SUCCESS(status)) break;

        ULONG_PTR base = (ULONG_PTR)mbi.BaseAddress;
        SIZE_T size = mbi.RegionSize;

        totalRegions++;

        BOOLEAN isCommitted = (mbi.State == MBI_MEM_COMMIT);
        BOOLEAN isExec = (mbi.Protect & MBI_EXECUTE_FLAGS) != 0;
        BOOLEAN isGuard = (mbi.Protect & MBI_PAGE_GUARD) != 0;
        BOOLEAN isImage = (mbi.Type == MBI_MEM_IMAGE);

        if (isCommitted && isExec && !isGuard && !isImage && size >= 0x1000) {
            BOOLEAN hasPe = FALSE;
            UCHAR header[2] = { 0 };
            SIZE_T bytesRead = 0;

            __try {
                status = MmCopyVirtualMemory(process, (PVOID)base,
                    selfProcess, header, sizeof(header), KernelMode, &bytesRead);
                if (NT_SUCCESS(status) && bytesRead >= 2 && header[0] == 'M' && header[1] == 'Z') {
                    hasPe = TRUE;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { }

            BOOLEAN isRwx = (mbi.Protect & 0xFF) == MBI_PAGE_EXECUTE_READWRITE;

            CHAR json[COMS_MAX_MESSAGE_SIZE];
            RtlStringCchPrintfA(json, ARRAYSIZE(json),
                "{ \"event\": \"vad_suspicious\", \"pid\": %lu, "
                "\"base\": \"0x%llX\", \"size\": %llu, "
                "\"protection\": \"%s\", \"type\": \"%s\", "
                "\"has_pe_header\": %s, \"rwx\": %s }",
                (ULONG)(ULONG_PTR)ProcessId,
                (unsigned long long)base,
                (unsigned long long)size,
                ProtString(mbi.Protect),
                TypeString(mbi.Type),
                hasPe ? "true" : "false",
                isRwx ? "true" : "false");
            ComsSendToUser(json, (ULONG)strlen(json));
            hits++;
        }

        ULONG_PTR next = base + size;
        if (next <= addr) break;
        addr = next;
    }

    ZwClose(hProc);
    ObDereferenceObject(process);

    CHAR json[COMS_MAX_MESSAGE_SIZE];
    RtlStringCchPrintfA(json, ARRAYSIZE(json),
        "{ \"event\": \"vad_scan_complete\", \"pid\": %lu, "
        "\"suspicious_count\": %lu, \"regions_scanned\": %lu }",
        (ULONG)(ULONG_PTR)ProcessId, hits, totalRegions);
    ComsSendToUser(json, (ULONG)strlen(json));

    KdPrint(("Peregrine: VAD scan done — %lu suspicious of %lu regions\n", hits, totalRegions));
    return STATUS_SUCCESS;
}
