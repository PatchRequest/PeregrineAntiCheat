#include "MiniFilter.h"
#include "Coms.h"
#include "AppState.h"
#include <ntstrsafe.h>

static PFLT_FILTER g_FilterHandle = NULL;

static LARGE_INTEGER g_LastBlockReport = { 0 };
static HANDLE        g_LastBlockPid = NULL;
#define BLOCK_REPORT_INTERVAL_MS 2000

static BOOLEAN ShouldReport(HANDLE Pid)
{
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    LONGLONG diffMs = (now.QuadPart - g_LastBlockReport.QuadPart) / 10000;
    if (g_LastBlockPid == Pid && diffMs < BLOCK_REPORT_INTERVAL_MS)
        return FALSE;
    g_LastBlockReport = now;
    g_LastBlockPid = Pid;
    return TRUE;
}

static WCHAR LowerAscii(WCHAR c)
{
    return (c >= L'A' && c <= L'Z') ? (WCHAR)(c + 32) : c;
}

/* Suffix/Sub are compile-time constants (RTL_CONSTANT_STRING): their length
   comes from sizeof, never from a hand-counted number. */
static BOOLEAN EndsWithI(_In_ PCUNICODE_STRING Path, _In_ PCUNICODE_STRING Suffix)
{
    if (!Path->Buffer || Path->Length < Suffix->Length) return FALSE;
    const USHORT pathChars = Path->Length / sizeof(WCHAR);
    const USHORT sufChars = Suffix->Length / sizeof(WCHAR);
    for (USHORT i = 0; i < sufChars; i++) {
        if (LowerAscii(Path->Buffer[pathChars - sufChars + i]) != LowerAscii(Suffix->Buffer[i]))
            return FALSE;
    }
    return TRUE;
}

static BOOLEAN ContainsI(_In_ PCUNICODE_STRING Path, _In_ PCUNICODE_STRING Sub)
{
    if (!Path->Buffer || Path->Length < Sub->Length) return FALSE;
    const USHORT pathChars = Path->Length / sizeof(WCHAR);
    const USHORT subChars = Sub->Length / sizeof(WCHAR);
    for (USHORT i = 0; i <= pathChars - subChars; i++) {
        BOOLEAN ok = TRUE;
        for (USHORT j = 0; j < subChars; j++) {
            if (LowerAscii(Path->Buffer[i + j]) != LowerAscii(Sub->Buffer[j])) { ok = FALSE; break; }
        }
        if (ok) return TRUE;
    }
    return FALSE;
}

/* AC artifacts live in a directory named "Peregrine" (deploy: C:\Peregrine\). */
static const UNICODE_STRING g_AcDirectory = RTL_CONSTANT_STRING(L"\\peregrine\\");

/* Leading backslash: these are whole file names, not name suffixes
   ("xrules.yar" is not ours). */
static const UNICODE_STRING g_AcFileNames[] = {
    RTL_CONSTANT_STRING(L"\\peregrinekernelcomponent.sys"),
    RTL_CONSTANT_STRING(L"\\peregrinekernelcomponent.inf"),
    RTL_CONSTANT_STRING(L"\\peregrinegame_x64.dll"),
    RTL_CONSTANT_STRING(L"\\peregrinegame_x86.dll"),
    RTL_CONSTANT_STRING(L"\\peregrinesensor_x64.dll"),
    RTL_CONSTANT_STRING(L"\\peregrinesensor_x86.dll"),
    RTL_CONSTANT_STRING(L"\\peregrine-tauri.exe"),
    RTL_CONSTANT_STRING(L"\\rules.yar"),
};

static BOOLEAN IsProtectedFile(_In_ PCUNICODE_STRING Path)
{
    if (!ContainsI(Path, &g_AcDirectory)) return FALSE;

    for (ULONG i = 0; i < ARRAYSIZE(g_AcFileNames); i++) {
        if (EndsWithI(Path, &g_AcFileNames[i])) return TRUE;
    }
    return FALSE;
}

/* The AC directory itself, as the last path component (rename / delete of it). */
static const UNICODE_STRING g_AcDirectoryLeaf = RTL_CONSTANT_STRING(L"\\peregrine");

/*
 * TRUE if the object named by Info is an AC file (or, with IncludeDirectory,
 * the AC directory itself). The stream part is ignored: "rules.yar::$DATA"
 * and "rules.yar:anything" are still rules.yar.
 */
static BOOLEAN IsProtectedName(
    _Inout_ PFLT_FILE_NAME_INFORMATION Info,
    _In_ BOOLEAN IncludeDirectory)
{
    UNICODE_STRING name = Info->Name;
    if (NT_SUCCESS(FltParseFileNameInformation(Info)) &&
        Info->Stream.Length != 0 && Info->Stream.Length <= name.Length) {
        name.Length -= Info->Stream.Length;
    }

    if (IsProtectedFile(&name))
        return TRUE;
    return IncludeDirectory && EndsWithI(&name, &g_AcDirectoryLeaf);
}

/*
 * Who is exempt from the file self-defense:
 *   - the TRUSTED process (the AC GUI itself). Not PROTECTED: the game being
 *     defended, or anything that managed to get protected, may not touch AC
 *     files;
 *   - kernel-mode requestors. A user-mode attacker cannot issue those, and
 *     denying them would interfere with the system (and other drivers) for no
 *     gain.
 */
static BOOLEAN IsExemptRequest(_In_ PFLT_CALLBACK_DATA Data)
{
    if (Data->RequestorMode == KernelMode)
        return TRUE;
    return StateIsPidTrusted(PsGetCurrentProcessId());
}

/* Report a blocked operation (rate-limited per PID). PASSIVE_LEVEL. */
static VOID ReportBlocked(_In_ PCUNICODE_STRING Path, _In_z_ const CHAR* OpName)
{
    HANDLE callerPid = PsGetCurrentProcessId();
    if (!ShouldReport(callerPid))
        return;

    ANSI_STRING ansi = { 0 };
    if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, Path, TRUE))) {
        CHAR json[COMS_MAX_MESSAGE_SIZE];
        CHAR escaped[520];
        if (!JsonEscapeString(escaped, sizeof(escaped), ansi.Buffer))
            escaped[0] = '\0';
        RtlStringCchPrintfA(json, ARRAYSIZE(json),
            "{ \"event\": \"file_access\", \"pid\": %lu, \"path\": \"%s\", \"op\": \"%s\" }",
            (ULONG)(ULONG_PTR)callerPid, escaped, OpName);
        ComsSendToUser(json, (ULONG)strlen(json));
        RtlFreeAnsiString(&ansi);
    }
}

/* Report and fail the operation with ACCESS_DENIED (pre-operation). */
static FLT_PREOP_CALLBACK_STATUS DenyAndReport(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCUNICODE_STRING Path,
    _In_z_ const CHAR* OpName)
{
    ReportBlocked(Path, OpName);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

/* ------------------------------------------------------------------ */
/*  Create: deny write/delete access to protected AC files            */
/*  Only resolves the file name for write-like opens.                 */
/* ------------------------------------------------------------------ */

#define WRITE_ACCESS_FLAGS (FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | \
    FILE_WRITE_EA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER)

static FLT_PREOP_CALLBACK_STATUS FLTAPI
PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (Data == NULL || Data->Iopb == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IsExemptRequest(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    ACCESS_MASK desired = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    const ULONG options = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
    const ULONG disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

    const BOOLEAN isWrite = (desired & WRITE_ACCESS_FLAGS) != 0 ||
                            FlagOn(options, FILE_DELETE_ON_CLOSE);
    const BOOLEAN isDestructive = (disposition == FILE_OVERWRITE ||
                                   disposition == FILE_OVERWRITE_IF ||
                                   disposition == FILE_SUPERSEDE);
    const BOOLEAN isCreateNew = (disposition == FILE_CREATE) || isDestructive;

    if (!isWrite && !isCreateNew) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS st = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(st) || nameInfo == NULL) {
        /* An open by file ID has no path yet, so "which file is this" cannot
           be answered before the file system has opened it. */
        if (FlagOn(options, FILE_OPEN_BY_FILE_ID)) {
            if (isDestructive) {
                /* Would truncate before we could look. Nothing legitimate
                   overwrites by ID. */
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
            return FLT_PREOP_SUCCESS_WITH_CALLBACK; /* decided in PostCreate */
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FLT_PREOP_CALLBACK_STATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IsProtectedName(nameInfo, FALSE))
        result = DenyAndReport(Data, &nameInfo->Name, "write");

    FltReleaseFileNameInformation(nameInfo);
    return result;
}

/* Only reached for write-like opens by file ID (see PreCreate). The file is
   open now and has a name: if it is an AC file, undo the open. */
static FLT_POSTOP_CALLBACK_STATUS FLTAPI
PostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE)
        return FLT_POSTOP_FINISHED_PROCESSING;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS st = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(st) || nameInfo == NULL)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (IsProtectedName(nameInfo, FALSE)) {
        ReportBlocked(&nameInfo->Name, "write_by_id");
        FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ------------------------------------------------------------------ */
/*  Pre-SetInformation: deny delete/rename/link touching AC files     */
/* ------------------------------------------------------------------ */

/*
 * Rename and hard-link requests name a *destination*. Checking only the file
 * being renamed misses the overwrite direction: renaming evil.dll onto
 * C:\Peregrine\PeregrineGame_x64.dll (ReplaceIfExists) replaces an AC file
 * without ever opening it for write. FILE_RENAME_INFORMATION and
 * FILE_LINK_INFORMATION share the layout used here.
 */
static BOOLEAN IsDestinationProtected(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PFLT_FILE_NAME_INFORMATION* DestInfo)
{
    *DestInfo = NULL;

    PFILE_RENAME_INFORMATION info =
        (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;

    if (info == NULL || length < (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
        info->FileNameLength > length - (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName))
        return FALSE; /* malformed — the file system rejects it */

    NTSTATUS st = FltGetDestinationFileNameInformation(
        FltObjects->Instance, FltObjects->FileObject,
        info->RootDirectory, info->FileName, info->FileNameLength,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, DestInfo);
    if (!NT_SUCCESS(st) || *DestInfo == NULL) {
        *DestInfo = NULL;
        return FALSE;
    }

    if (IsProtectedName(*DestInfo, TRUE))
        return TRUE;

    FltReleaseFileNameInformation(*DestInfo);
    *DestInfo = NULL;
    return FALSE;
}

static FLT_PREOP_CALLBACK_STATUS FLTAPI
PreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    *CompletionContext = NULL;

    if (Data == NULL || Data->Iopb == NULL || FltObjects == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IsExemptRequest(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    ULONG infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    BOOLEAN isDelete = (infoClass == FileDispositionInformation ||
                        infoClass == FileDispositionInformationEx);
    BOOLEAN isRename = (infoClass == FileRenameInformation ||
                        infoClass == FileRenameInformationEx);
    BOOLEAN isLink   = (infoClass == FileLinkInformation ||
                        infoClass == FileLinkInformationEx);
    if (!isDelete && !isRename && !isLink) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Destination of a rename / hard link is (or replaces) an AC file. */
    if (isRename || isLink) {
        PFLT_FILE_NAME_INFORMATION destInfo = NULL;
        if (IsDestinationProtected(Data, FltObjects, &destInfo)) {
            FLT_PREOP_CALLBACK_STATUS result = DenyAndReport(Data, &destInfo->Name,
                isRename ? "rename_onto" : "link_onto");
            FltReleaseFileNameInformation(destInfo);
            return result;
        }
    }

    /* The object itself is an AC file — or the AC directory — being deleted,
       renamed away or given a second name. The hard link is denied as well:
       the new name would be an unprotected path to the same file, writable
       by anyone. */
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS st = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(st) || nameInfo == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FLT_PREOP_CALLBACK_STATUS result = FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IsProtectedName(nameInfo, TRUE))
        result = DenyAndReport(Data, &nameInfo->Name,
            isRename ? "rename" : isLink ? "link" : "delete");

    FltReleaseFileNameInformation(nameInfo);
    return result;
}

/* ------------------------------------------------------------------ */
/*  Registration — Create (pre, post for opens by ID) + SetInformation */
/* ------------------------------------------------------------------ */

static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE,          0, PreCreate,  PostCreate },
    { IRP_MJ_SET_INFORMATION, 0, PreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};
NTSTATUS MfInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

NTSTATUS MfUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    MfCleanup();
    return STATUS_SUCCESS;
}

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    g_Callbacks,
    (PFLT_FILTER_UNLOAD_CALLBACK)MfUnload,
    MfInstanceSetup,
    NULL, NULL, NULL,
    NULL, NULL, NULL
};

NTSTATUS MfInit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: FltRegisterFilter failed 0x%X\n", status));
        return status;
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: FltStartFiltering failed 0x%X\n", status));
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        return status;
    }

    KdPrint(("Peregrine: Minifilter started\n"));
    return STATUS_SUCCESS;
}

VOID MfCleanup(VOID)
{
    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }
}
