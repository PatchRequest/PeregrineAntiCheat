#include "NotifyRoutine.h"
#include "Coms.h"
#include <ntstrsafe.h>

// Forward declarations for thread functions
NTKERNELAPI NTSTATUS ZwOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
);

NTKERNELAPI NTSTATUS ZwQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_ PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
);

// Thread access rights
#define THREAD_QUERY_INFORMATION 0x0040

// ThreadQuerySetWin32StartAddress = 9
#define ThreadQuerySetWin32StartAddress 9

static VOID UnicodeToAnsiLimited(_In_opt_ PCUNICODE_STRING Src, _Out_writes_(DestChars) PCHAR Dest, _In_ SIZE_T DestChars) {
    if (DestChars == 0) {
        return;
    }
    Dest[0] = '\0';
    if (Src == NULL) {
        return;
    }

    ANSI_STRING ansi = { 0 };
    NTSTATUS status = RtlUnicodeStringToAnsiString(&ansi, Src, TRUE);
    if (!NT_SUCCESS(status)) {
        return;
    }

    SIZE_T copyLen = (ansi.Length < DestChars - 1) ? ansi.Length : DestChars - 1;
    RtlCopyMemory(Dest, ansi.Buffer, copyLen);
    Dest[copyLen] = '\0';
    RtlFreeAnsiString(&ansi);
}

static VOID SendJsonString(_In_ const CHAR* Json) {
    if (Json == NULL) {
        return;
    }
    ComsSendToUser(Json, (ULONG)strlen(Json));
}

VOID CreateProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);

    CHAR imageName[260];
    UnicodeToAnsiLimited(CreateInfo ? CreateInfo->ImageFileName : NULL, imageName, ARRAYSIZE(imageName));



    CHAR json[COMS_MAX_MESSAGE_SIZE];
    if (CreateInfo != NULL) {
        // Process creation event
        RtlStringCchPrintfA(
            json,
            ARRAYSIZE(json),
            "{ \"event\": \"process_create\", \"pid\": %lu, \"ppid\": %lu, \"image\": \"%s\" }",
            (ULONG)(ULONG_PTR)ProcessId,
            (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId,
            imageName);
    } else {
        // Process exit event
        RtlStringCchPrintfA(
            json,
            ARRAYSIZE(json),
            "{ \"event\": \"process_exit\", \"pid\": %lu }",
            (ULONG)(ULONG_PTR)ProcessId);
    }

    SendJsonString(json);
}

VOID CreateThreadNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
) {
    const CHAR* ev = Create ? "thread_create" : "thread_exit";


	if (!StateIsPidProtected(ProcessId)) {
		return;
	}

    CHAR json[COMS_MAX_MESSAGE_SIZE];
    PVOID startAddress = NULL;

    // Query thread start address if this is a thread creation event
    if (Create) {
        HANDLE hThread = NULL;
        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

        CLIENT_ID clientId;
        clientId.UniqueProcess = ProcessId;
        clientId.UniqueThread = ThreadId;

        NTSTATUS status = ZwOpenThread(&hThread, THREAD_QUERY_INFORMATION, &objAttr, &clientId);
        if (NT_SUCCESS(status)) {
            // Query the Win32 start address
            status = ZwQueryInformationThread(
                hThread,
                (THREADINFOCLASS)ThreadQuerySetWin32StartAddress,
                &startAddress,
                sizeof(PVOID),
                NULL
            );

            ZwClose(hThread);
        }
    }

    // Include start address in JSON if available
    if (startAddress != NULL) {
        RtlStringCchPrintfA(
            json,
            ARRAYSIZE(json),
            "{ \"event\": \"%s\", \"pid\": %lu, \"tid\": %lu, \"callerpid\": %lu, \"start_address\": \"0x%p\" }",
            ev,
            (ULONG)(ULONG_PTR)ProcessId,
            (ULONG)(ULONG_PTR)ThreadId,
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
            startAddress);
    } else {
        RtlStringCchPrintfA(
            json,
            ARRAYSIZE(json),
            "{ \"event\": \"%s\", \"pid\": %lu, \"tid\": %lu, \"callerpid\": %lu }",
            ev,
            (ULONG)(ULONG_PTR)ProcessId,
            (ULONG)(ULONG_PTR)ThreadId,
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    }

    SendJsonString(json);
}

VOID LoadImageNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId, // pid of process loading the image
    _In_ PIMAGE_INFO ImageInfo
) {

	if (!StateIsPidProtected(ProcessId)) {
		return;
	}

    CHAR imageName[260];
    UnicodeToAnsiLimited(FullImageName, imageName, ARRAYSIZE(imageName));

    CHAR json[COMS_MAX_MESSAGE_SIZE];
    RtlStringCchPrintfA(
        json,
        ARRAYSIZE(json),
        "{ \"event\": \"image_load\", \"pid\": %lu, \"base\": \"%p\", \"size\": %lu, \"image\": \"%s\" }",
        (ULONG)(ULONG_PTR)ProcessId,
        ImageInfo ? ImageInfo->ImageBase : NULL,
        ImageInfo ? (ULONG)ImageInfo->ImageSize : 0,
        imageName);

    SendJsonString(json);
}

NTSTATUS registerNotifyRoutine() {
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "PsSetCreateProcessNotifyRoutineEx failed with status 0x%08X\n", status);
    }

    status = PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "PsSetCreateThreadNotifyRoutine failed with status 0x%08X\n", status);
    }

    status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "PsSetLoadImageNotifyRoutine failed with status 0x%08X\n", status);
    }

    return status;
}

void unregisterNotifyRoutine() {
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx, TRUE);
    PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
    PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
}
