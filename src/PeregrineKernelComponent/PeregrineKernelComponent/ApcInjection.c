#include "ApcInjection.h"
#include "Coms.h"
#include <ntstrsafe.h>

/* ------------------------------------------------------------------ */
/*  Undocumented kernel API forward declarations                      */
/* ------------------------------------------------------------------ */

NTKERNELAPI PPEB  PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI PVOID PsGetProcessWow64Process(PEPROCESS Process);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId, _Out_ PEPROCESS* Process);
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(
    _In_ HANDLE ThreadId,  _Out_ PETHREAD* Thread);

typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
    PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
typedef VOID (NTAPI *PKKERNEL_ROUTINE)(
    PRKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);
typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(PRKAPC Apc);

typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

NTKERNELAPI VOID KeInitializeApc(
    _Out_ PRKAPC Apc, _In_ PRKTHREAD Thread,
    _In_  KAPC_ENVIRONMENT Environment,
    _In_  PKKERNEL_ROUTINE  KernelRoutine,
    _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ PKNORMAL_ROUTINE  NormalRoutine,
    _In_  KPROCESSOR_MODE ApcMode,
    _In_opt_ PVOID NormalContext);

NTKERNELAPI BOOLEAN KeInsertQueueApc(
    _Inout_ PRKAPC Apc, _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2, _In_ KPRIORITY Increment);

NTKERNELAPI BOOLEAN  KeTestAlertThread(_In_ KPROCESSOR_MODE AlertMode);
NTKERNELAPI NTSTATUS PsWrapApcWow64Thread(
    _Inout_ PVOID* ApcContext, _Inout_ PVOID* ApcRoutine);

typedef struct _INJ_APC_STATE {
    UCHAR Opaque[48];
} INJ_APC_STATE;

NTKERNELAPI VOID KeStackAttachProcess(
    _Inout_ PEPROCESS Process, _Out_ PVOID ApcState);
NTKERNELAPI VOID KeUnstackDetachProcess(
    _In_ PVOID ApcState);

NTSYSAPI NTSTATUS NTAPI ZwAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType, _In_ ULONG Protect);

/* ------------------------------------------------------------------ */
/*  Shellcode: calls LdrLoadDll(NULL, NULL, &UnicodeString, &hMod)    */
/*  NormalContext  = pointer to UNICODE_STRING in target process       */
/*  LdrLoadDll address is patched into the shellcode at load time     */
/* ------------------------------------------------------------------ */

static const UCHAR g_ShellcodeX64[] = {
    0x48, 0xB8,                                     /* mov rax, imm64       */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* <LdrLoadDll addr>   */
    0x48, 0x83, 0xEC, 0x28,                         /* sub rsp, 0x28        */
    0x49, 0x89, 0xC8,                               /* mov r8,  rcx         */
    0x4C, 0x8D, 0x4C, 0x24, 0x20,                   /* lea r9,  [rsp+0x20]  */
    0x48, 0x31, 0xC9,                               /* xor rcx, rcx         */
    0x48, 0x31, 0xD2,                               /* xor rdx, rdx         */
    0xFF, 0xD0,                                     /* call rax             */
    0x48, 0x83, 0xC4, 0x28,                         /* add rsp, 0x28        */
    0xC3                                            /* ret                  */
};
#define SC64_SIZE  sizeof(g_ShellcodeX64)
#define SC64_PATCH 2

static const UCHAR g_ShellcodeX86[] = {
    0xB8,                                           /* mov eax, imm32       */
    0x00, 0x00, 0x00, 0x00,                         /* <LdrLoadDll addr>   */
    0x8B, 0x4C, 0x24, 0x04,                         /* mov ecx, [esp+4]    */
    0x6A, 0x00,                                     /* push 0   (hMod out) */
    0x54,                                           /* push esp (&hMod)    */
    0x51,                                           /* push ecx (UStr*)    */
    0x6A, 0x00,                                     /* push 0   (Chars)    */
    0x6A, 0x00,                                     /* push 0   (Path)     */
    0xFF, 0xD0,                                     /* call eax            */
    0x83, 0xC4, 0x04,                               /* add esp, 4          */
    0xC3                                            /* ret                 */
};
#define SC86_SIZE  sizeof(g_ShellcodeX86)
#define SC86_PATCH 1

/* UNICODE_STRING sizes in the target process */
#define USTR64_SIZE 16   /* Length(2)+Max(2)+pad(4)+Buffer(8) */
#define USTR32_SIZE  8   /* Length(2)+Max(2)+Buffer(4)        */

/* ------------------------------------------------------------------ */
/*  Global injection state                                            */
/* ------------------------------------------------------------------ */

typedef struct _INJ_STATE {
    KSPIN_LOCK Lock;
    BOOLEAN    Enabled;

    WCHAR  DllPathX64[INJ_MAX_PATH];
    USHORT DllPathX64Bytes;
    WCHAR  DllPathX86[INJ_MAX_PATH];
    USHORT DllPathX86Bytes;

    CHAR   Targets[INJ_MAX_TARGETS][INJ_MAX_NAME];
    ULONG  TargetCount;

    HANDLE Pending[INJ_MAX_PENDING];
    ULONG  PendingCount;
} INJ_STATE;

static INJ_STATE g_Inj = { 0 };

/* Cached ntdll bases & LdrLoadDll addresses (set once per boot) */
static volatile LONG_PTR g_NtdllBaseX64   = 0;
static volatile LONG     g_NtdllBaseX86   = 0;
static volatile LONG_PTR g_LdrLoadDllX64  = 0;
static volatile LONG     g_LdrLoadDllX86  = 0;

/* ------------------------------------------------------------------ */
/*  Unicode helpers                                                   */
/* ------------------------------------------------------------------ */

static BOOLEAN UStrEndsWith(_In_ PCUNICODE_STRING Str, _In_ PCWSTR Suffix)
{
    if (!Str || !Str->Buffer || !Suffix) return FALSE;
    SIZE_T sLen = wcslen(Suffix);
    SIZE_T uLen = Str->Length / sizeof(WCHAR);
    if (uLen < sLen) return FALSE;
    for (SIZE_T i = 0; i < sLen; i++) {
        WCHAR a = Str->Buffer[uLen - sLen + i];
        WCHAR b = Suffix[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return FALSE;
    }
    return TRUE;
}

static BOOLEAN UStrContainsI(_In_ PCUNICODE_STRING Str, _In_ PCWSTR Sub)
{
    if (!Str || !Str->Buffer || !Sub) return FALSE;
    SIZE_T sLen = wcslen(Sub);
    SIZE_T uLen = Str->Length / sizeof(WCHAR);
    if (uLen < sLen) return FALSE;
    for (SIZE_T i = 0; i <= uLen - sLen; i++) {
        BOOLEAN ok = TRUE;
        for (SIZE_T j = 0; j < sLen; j++) {
            WCHAR a = Str->Buffer[i + j];
            WCHAR b = Sub[j];
            if (a >= L'A' && a <= L'Z') a += 32;
            if (b >= L'A' && b <= L'Z') b += 32;
            if (a != b) { ok = FALSE; break; }
        }
        if (ok) return TRUE;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/*  Pending-PID helpers (spinlock-protected)                          */
/* ------------------------------------------------------------------ */

static VOID PendingAdd(HANDLE Pid)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    if (g_Inj.PendingCount < INJ_MAX_PENDING) {
        for (ULONG i = 0; i < g_Inj.PendingCount; i++)
            if (g_Inj.Pending[i] == Pid) { KeReleaseSpinLock(&g_Inj.Lock, irql); return; }
        g_Inj.Pending[g_Inj.PendingCount++] = Pid;
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);
}

static BOOLEAN PendingRemove(HANDLE Pid)
{
    BOOLEAN found = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    for (ULONG i = 0; i < g_Inj.PendingCount; i++) {
        if (g_Inj.Pending[i] == Pid) {
            g_Inj.Pending[i] = g_Inj.Pending[--g_Inj.PendingCount];
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return found;
}

/* ------------------------------------------------------------------ */
/*  Target-name matching                                              */
/* ------------------------------------------------------------------ */

static BOOLEAN MatchesAnyTarget(_In_ const CHAR* ImageName)
{
    if (!ImageName || !*ImageName) return FALSE;
    const CHAR* fn = ImageName;
    for (const CHAR* p = ImageName; *p; p++)
        if (*p == '\\' || *p == '/') fn = p + 1;

    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    BOOLEAN hit = FALSE;
    for (ULONG i = 0; i < g_Inj.TargetCount; i++) {
        if (_stricmp(fn, g_Inj.Targets[i]) == 0) { hit = TRUE; break; }
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return hit;
}

/* ------------------------------------------------------------------ */
/*  PE export-table parser (reads from user-space while attached)     */
/* ------------------------------------------------------------------ */

static ULONG_PTR ParseExports(_In_ PVOID ImageBase, _In_ BOOLEAN Is32)
{
    ULONG_PTR result = 0;
    __try {
        PUCHAR base = (PUCHAR)ImageBase;
        if (*(PUSHORT)base != 0x5A4D) return 0;            /* MZ */

        LONG lfanew = *(PLONG)(base + 0x3C);
        if (*(PULONG)(base + lfanew) != 0x00004550) return 0; /* PE\0\0 */

        PUCHAR opt = base + lfanew + 24;
        ULONG  expRva;
        if (Is32)
            expRva = *(PULONG)(opt + 96);                   /* DataDir[0].VA */
        else
            expRva = *(PULONG)(opt + 112);

        if (expRva == 0) return 0;

        PUCHAR ed  = base + expRva;
        ULONG  nNames    = *(PULONG)(ed + 24);
        ULONG  fnRva     = *(PULONG)(ed + 28);
        ULONG  nameRva   = *(PULONG)(ed + 32);
        ULONG  ordRva    = *(PULONG)(ed + 36);

        PULONG  names    = (PULONG)(base + nameRva);
        PUSHORT ords     = (PUSHORT)(base + ordRva);
        PULONG  funcs    = (PULONG)(base + fnRva);

        for (ULONG i = 0; i < nNames; i++) {
            if (strcmp((const CHAR*)(base + names[i]), "LdrLoadDll") == 0) {
                result = (ULONG_PTR)base + funcs[ords[i]];
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = 0;
    }
    return result;
}

/* ------------------------------------------------------------------ */
/*  APC callbacks                                                     */
/* ------------------------------------------------------------------ */

static VOID NTAPI KernelRoutineCb(
    PRKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext, PVOID* Sys1, PVOID* Sys2)
{
    UNREFERENCED_PARAMETER(Sys1); UNREFERENCED_PARAMETER(Sys2);
    if (PsGetProcessWow64Process(PsGetCurrentProcess()) != NULL)
        PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);
    ExFreePoolWithTag(Apc, INJ_POOL_TAG);
}

static VOID NTAPI AlertRoutineCb(
    PRKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext, PVOID* Sys1, PVOID* Sys2)
{
    UNREFERENCED_PARAMETER(NormalRoutine); UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(Sys1); UNREFERENCED_PARAMETER(Sys2);
    KeTestAlertThread(UserMode);
    ExFreePoolWithTag(Apc, INJ_POOL_TAG);
}

static VOID NTAPI RundownCb(PRKAPC Apc)
{
    ExFreePoolWithTag(Apc, INJ_POOL_TAG);
}

/* ------------------------------------------------------------------ */
/*  Core injection logic — runs in the target process context         */
/*  (called from image load callback when kernel32.dll loads)         */
/* ------------------------------------------------------------------ */

static NTSTATUS DoInjectInContext(_In_ BOOLEAN IsWow64)
{
    NTSTATUS status;
    PVOID    alloc = NULL;
    SIZE_T   allocSz = 0;

    /* Pick DLL path */
    KIRQL irql;
    WCHAR  dllPath[INJ_MAX_PATH];
    USHORT dllBytes;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    if (IsWow64) {
        RtlCopyMemory(dllPath, g_Inj.DllPathX86, sizeof(g_Inj.DllPathX86));
        dllBytes = g_Inj.DllPathX86Bytes;
    } else {
        RtlCopyMemory(dllPath, g_Inj.DllPathX64, sizeof(g_Inj.DllPathX64));
        dllBytes = g_Inj.DllPathX64Bytes;
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);

    if (dllBytes == 0) return STATUS_NOT_FOUND;

    /* Resolve LdrLoadDll — we're already in the target address space,
       ntdll is mapped and its exports are readable. */
    ULONG_PTR ldrAddr;
    if (IsWow64) {
        ldrAddr = (ULONG_PTR)InterlockedCompareExchange(&g_LdrLoadDllX86, 0, 0);
        if (ldrAddr == 0 && g_NtdllBaseX86 != 0) {
            ldrAddr = ParseExports((PVOID)(ULONG_PTR)g_NtdllBaseX86, TRUE);
            if (ldrAddr) InterlockedExchange(&g_LdrLoadDllX86, (LONG)ldrAddr);
        }
    } else {
        ldrAddr = (ULONG_PTR)InterlockedCompareExchangePointer(
            (PVOID*)&g_LdrLoadDllX64, NULL, NULL);
        if (ldrAddr == 0 && g_NtdllBaseX64 != 0) {
            ldrAddr = ParseExports((PVOID)g_NtdllBaseX64, FALSE);
            if (ldrAddr) InterlockedExchangePointer(
                (PVOID*)&g_LdrLoadDllX64, (PVOID)ldrAddr);
        }
    }
    if (ldrAddr == 0) return STATUS_PROCEDURE_NOT_FOUND;

    /* Compute sizes */
    const UCHAR* sc;
    ULONG scSz, patch, ustrSz;
    if (IsWow64) {
        sc = g_ShellcodeX86; scSz = SC86_SIZE;
        patch = SC86_PATCH; ustrSz = USTR32_SIZE;
    } else {
        sc = g_ShellcodeX64; scSz = SC64_SIZE;
        patch = SC64_PATCH; ustrSz = USTR64_SIZE;
    }

    ULONG total = scSz + ustrSz + dllBytes + sizeof(WCHAR);
    allocSz = total;

    /* Allocate in current (target) process — no attach needed */
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &alloc, 0,
        &allocSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) return status;

    PUCHAR dst = (PUCHAR)alloc;

    /* Write shellcode with patched LdrLoadDll address */
    RtlCopyMemory(dst, sc, scSz);
    if (IsWow64)
        *(PULONG)(dst + patch)     = (ULONG)ldrAddr;
    else
        *(PULONG_PTR)(dst + patch) = ldrAddr;

    /* Build UNICODE_STRING after shellcode */
    PUCHAR ustrA = dst + scSz;
    PUCHAR pathA = ustrA + ustrSz;

    RtlCopyMemory(pathA, dllPath, dllBytes);
    *(PWCHAR)(pathA + dllBytes) = L'\0';

    if (IsWow64) {
        *(PUSHORT)(ustrA + 0) = dllBytes;
        *(PUSHORT)(ustrA + 2) = dllBytes + (USHORT)sizeof(WCHAR);
        *(PULONG) (ustrA + 4) = (ULONG)(ULONG_PTR)pathA;
    } else {
        *(PUSHORT)  (ustrA + 0) = dllBytes;
        *(PUSHORT)  (ustrA + 2) = dllBytes + (USHORT)sizeof(WCHAR);
        *(PULONG)   (ustrA + 4) = 0;
        *(PULONG_PTR)(ustrA + 8) = (ULONG_PTR)pathA;
    }

    /* Queue user-mode APC to current thread (the loader thread) */
    PRKTHREAD curThread = (PRKTHREAD)PsGetCurrentThread();

    PRKAPC execApc = (PRKAPC)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(KAPC), INJ_POOL_TAG);
    if (!execApc) return STATUS_INSUFFICIENT_RESOURCES;

    KeInitializeApc(execApc, curThread, OriginalApcEnvironment,
        (PKKERNEL_ROUTINE)KernelRoutineCb, (PKRUNDOWN_ROUTINE)RundownCb,
        (PKNORMAL_ROUTINE)alloc, UserMode, ustrA);

    if (!KeInsertQueueApc(execApc, NULL, NULL, 0)) {
        ExFreePoolWithTag(execApc, INJ_POOL_TAG);
        return STATUS_UNSUCCESSFUL;
    }

    /* Force APC delivery on next kernel-to-user transition.
       We're in the loader thread context so this is safe. */
    KeTestAlertThread(UserMode);

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

VOID InjInit(VOID)
{
    RtlZeroMemory(&g_Inj, sizeof(g_Inj));
    KeInitializeSpinLock(&g_Inj.Lock);
}

VOID InjCleanup(VOID) { /* static state, nothing to free */ }

NTSTATUS InjSetDllPath(BOOLEAN IsX86, const WCHAR* Path, USHORT PathLenBytes)
{
    if (!Path || PathLenBytes == 0 ||
        PathLenBytes > (INJ_MAX_PATH - 1) * sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    if (IsX86) {
        RtlZeroMemory(g_Inj.DllPathX86, sizeof(g_Inj.DllPathX86));
        RtlCopyMemory(g_Inj.DllPathX86, Path, PathLenBytes);
        g_Inj.DllPathX86Bytes = PathLenBytes;
    } else {
        RtlZeroMemory(g_Inj.DllPathX64, sizeof(g_Inj.DllPathX64));
        RtlCopyMemory(g_Inj.DllPathX64, Path, PathLenBytes);
        g_Inj.DllPathX64Bytes = PathLenBytes;
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS InjAddTarget(const CHAR* Name, ULONG NameLen)
{
    if (!Name || NameLen == 0 || NameLen >= INJ_MAX_NAME)
        return STATUS_INVALID_PARAMETER;

    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    if (g_Inj.TargetCount >= INJ_MAX_TARGETS) {
        KeReleaseSpinLock(&g_Inj.Lock, irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (ULONG i = 0; i < g_Inj.TargetCount; i++) {
        if (_stricmp(g_Inj.Targets[i], Name) == 0) {
            KeReleaseSpinLock(&g_Inj.Lock, irql);
            return STATUS_ALREADY_COMMITTED;
        }
    }
    RtlCopyMemory(g_Inj.Targets[g_Inj.TargetCount], Name, NameLen);
    g_Inj.Targets[g_Inj.TargetCount][NameLen] = '\0';
    g_Inj.TargetCount++;
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS InjClearTargets(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    g_Inj.TargetCount  = 0;
    g_Inj.PendingCount = 0;
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return STATUS_SUCCESS;
}

VOID InjSetEnabled(BOOLEAN Enabled)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    g_Inj.Enabled = Enabled;
    KeReleaseSpinLock(&g_Inj.Lock, irql);
}

/* ------------------------------------------------------------------ */
/*  Callback hooks (called from NotifyRoutine.c)                      */
/* ------------------------------------------------------------------ */

VOID InjOnImageLoad(HANDLE ProcessId, PUNICODE_STRING FullImageName,
    PIMAGE_INFO ImageInfo)
{
    if (!FullImageName || !ImageInfo || !ImageInfo->ImageBase) return;
    if ((ULONG_PTR)ProcessId == 0) return;

    /* Always capture ntdll bases (needed for LdrLoadDll resolution) */
    if (UStrEndsWith(FullImageName, L"ntdll.dll")) {
        if (UStrContainsI(FullImageName, L"syswow64")) {
            if (g_NtdllBaseX86 == 0)
                InterlockedExchange(&g_NtdllBaseX86,
                    (LONG)(ULONG)(ULONG_PTR)ImageInfo->ImageBase);
        } else {
            if (g_NtdllBaseX64 == 0)
                InterlockedExchangePointer(
                    (PVOID*)&g_NtdllBaseX64, ImageInfo->ImageBase);
        }
        return;
    }

    /* Trigger injection when kernel32.dll loads in a pending process.
       At this point the loader is initialized and LdrLoadDll works.
       The callback runs in the target process's loader thread context. */
    if (!UStrEndsWith(FullImageName, L"kernel32.dll")) return;

    BOOLEAN isPending = PendingRemove(ProcessId);
    if (!isPending) return;

    BOOLEAN isWow64 = UStrContainsI(FullImageName, L"syswow64");

    NTSTATUS st = DoInjectInContext(isWow64);

    CHAR json[COMS_MAX_MESSAGE_SIZE];
    ULONG tid = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    if (NT_SUCCESS(st)) {
        RtlStringCchPrintfA(json, ARRAYSIZE(json),
            "{ \"event\": \"apc_inject\", \"pid\": %lu, \"tid\": %lu, "
            "\"status\": \"success\" }",
            (ULONG)(ULONG_PTR)ProcessId, tid);
    } else {
        RtlStringCchPrintfA(json, ARRAYSIZE(json),
            "{ \"event\": \"apc_inject\", \"pid\": %lu, \"tid\": %lu, "
            "\"status\": \"failed\", \"error\": \"0x%08X\" }",
            (ULONG)(ULONG_PTR)ProcessId, tid, st);
    }
    ComsSendToUser(json, (ULONG)strlen(json));
    KdPrint(("Peregrine: APC inject (kernel32 load) PID=%lu => 0x%08X\n",
        (ULONG)(ULONG_PTR)ProcessId, st));
}

VOID InjOnProcessCreate(HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (!CreateInfo || !CreateInfo->ImageFileName) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    BOOLEAN go = g_Inj.Enabled && g_Inj.TargetCount > 0;
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    if (!go) return;

    ANSI_STRING ansi = { 0 };
    if (!NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, CreateInfo->ImageFileName, TRUE)))
        return;

    CHAR buf[260];
    SIZE_T n = min(ansi.Length, sizeof(buf) - 1);
    RtlCopyMemory(buf, ansi.Buffer, n);
    buf[n] = '\0';
    RtlFreeAnsiString(&ansi);

    if (MatchesAnyTarget(buf)) {
        PendingAdd(ProcessId);
        KdPrint(("Peregrine: injection pending PID %lu (%s)\n",
            (ULONG)(ULONG_PTR)ProcessId, buf));
    }
}

VOID InjOnProcessExit(HANDLE ProcessId) { PendingRemove(ProcessId); }

BOOLEAN InjOnThreadCreate(HANDLE ProcessId, HANDLE ThreadId)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ThreadId);
    return FALSE;
}
