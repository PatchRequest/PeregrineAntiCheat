/*
 * Kernel APC DLL injection — OpenEDR-style LoadLibraryExW path
 *
 * Design (adapted from OpenEDR / ComodoSecurity/openedr injectengine):
 *   edrav2/iprj/edrdrv/src/kernelinjectlib/injectengine/apcinjector.cpp
 *   edrav2/iprj/edrdrv/src/kernelinjectlib/injectengine/apcqueue.cpp
 *
 * User-mode APC shape:
 *   NormalRoutine  = KernelBase!LoadLibraryExW  (real code; see crash note below)
 *   NormalContext  = LPWSTR full DLL path in target process (PAGE_READWRITE only)
 *   SystemArgument1 = NULL  (hFile, reserved)
 *   SystemArgument2 = dwFlags for LoadLibraryExW
 *
 * No private executable shellcode, no ntdll!LdrLoadDll stub, no ZwProtectVirtualMemory.
 * Path buffer is freed on process exit (LoadLibraryExW may still hold the pointer
 * during LoadImageNotify for our DLL — never free while load is in flight).
 *
 * Crash note (early kernel32 LoadImage + KeTestAlertThread):
 *   kernel32!LoadLibraryExW is typically an IAT thunk (ff 25 …) whose slot is
 *   unbound while kernel32 is still mapping. Forcing the APC with KeTestAlertThread
 *   in LoadImageNotify jumps through a bad IAT → process death. OpenEDR does NOT
 *   TestAlert; delivery happens at the loader's later NtTestAlert after static
 *   imports are initialized. We also resolve the real export from KernelBase
 *   (already initialized by the time kernel32 maps) instead of the kernel32 stub.
 *
 * LoadLibraryExW flags: 0. Peregrine uses absolute paths under C:\Peregrine\.
 * OpenEDR often passes LOAD_IGNORE_CODE_AUTHZ_LEVEL | LOAD_LIBRARY_SEARCH_SYSTEM32
 * for System32-relative names; SEARCH_SYSTEM32 would break non-System32 full paths.
 *
 * Product semantics kept: named targets, IOCTL path config, auto StateAddPid,
 * x64 + WoW64 (PsWrapApcWow64Thread in KernelRoutine).
 */

#include "ApcInjection.h"
#include "Coms.h"
#include "AppState.h"
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

NTKERNELAPI NTSTATUS PsWrapApcWow64Thread(
    _Inout_ PVOID* ApcContext, _Inout_ PVOID* ApcRoutine);

/*
 * LoadLibraryExW dwFlags — absolute path under C:\Peregrine\.
 * See file header for why this is not OpenEDR's SEARCH_SYSTEM32 combo.
 */
#define INJ_LOADLIBRARY_FLAGS  ((ULONG)0)

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

    /* Path-only user allocations to free on process exit */
    struct {
        HANDLE Pid;
        PVOID  Base;
        SIZE_T Size;
    } PendingFree[INJ_MAX_PENDING];
    ULONG PendingFreeCount;
} INJ_STATE;

static INJ_STATE g_Inj = { 0 };

static VOID PendingFreeAdd(HANDLE Pid, PVOID Base, SIZE_T Size)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    if (g_Inj.PendingFreeCount < INJ_MAX_PENDING && Base != NULL) {
        ULONG i = g_Inj.PendingFreeCount++;
        g_Inj.PendingFree[i].Pid  = Pid;
        g_Inj.PendingFree[i].Base = Base;
        g_Inj.PendingFree[i].Size = Size;
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);
}

/* Free inject path buffer on process exit. */
static VOID PendingFreeRelease(_In_ HANDLE Pid, _In_ BOOLEAN AttachIfNeeded)
{
    PVOID bases[INJ_MAX_PENDING];
    SIZE_T sizes[INJ_MAX_PENDING];
    ULONG n = 0;
    KIRQL irql;

    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    for (ULONG i = 0; i < g_Inj.PendingFreeCount; ) {
        if (g_Inj.PendingFree[i].Pid == Pid) {
            if (n < INJ_MAX_PENDING) {
                bases[n] = g_Inj.PendingFree[i].Base;
                sizes[n] = g_Inj.PendingFree[i].Size;
                n++;
            }
            g_Inj.PendingFree[i] = g_Inj.PendingFree[--g_Inj.PendingFreeCount];
        } else {
            i++;
        }
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);

    if (n == 0) return;

    PEPROCESS process = NULL;
    KAPC_STATE apc;
    BOOLEAN attached = FALSE;

    if (AttachIfNeeded && PsGetCurrentProcessId() != Pid) {
        if (NT_SUCCESS(PsLookupProcessByProcessId(Pid, &process))) {
            KeStackAttachProcess(process, &apc);
            attached = TRUE;
        } else {
            return; /* process gone — memory already reclaimed */
        }
    }

    for (ULONG i = 0; i < n; i++) {
        PVOID base = bases[i];
        SIZE_T region = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &region, MEM_RELEASE);
    }

    if (attached) {
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(process);
    }
}

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

static ULONG_PTR ParseExport(
    _In_ PVOID ImageBase,
    _In_ BOOLEAN Is32,
    _In_z_ const CHAR* ExportName)
{
    ULONG_PTR result = 0;
    if (!ImageBase || !ExportName) return 0;

    __try {
        PUCHAR base = (PUCHAR)ImageBase;
        if (*(PUSHORT)base != 0x5A4D) return 0;            /* MZ */

        LONG lfanew = *(PLONG)(base + 0x3C);
        if (*(PULONG)(base + lfanew) != 0x00004550) return 0; /* PE\0\0 */

        PUCHAR opt = base + lfanew + 24;
        ULONG  expRva, expSize;
        if (Is32) {
            expRva  = *(PULONG)(opt + 96);                  /* DataDir[0] */
            expSize = *(PULONG)(opt + 100);
        } else {
            expRva  = *(PULONG)(opt + 112);
            expSize = *(PULONG)(opt + 116);
        }

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
            if (strcmp((const CHAR*)(base + names[i]), ExportName) == 0) {
                ULONG rva = funcs[ords[i]];
                /* Forwarded export (RVA inside export directory) — not callable. */
                if (rva >= expRva && rva < expRva + expSize)
                    return 0;
                result = (ULONG_PTR)base + rva;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = 0;
    }
    return result;
}

/* ------------------------------------------------------------------ */
/*  PEB LDR walk — find a loaded module base in the current process   */
/* ------------------------------------------------------------------ */

static BOOLEAN UStrEqISuffix(_In_ PCUNICODE_STRING Name, _In_ PCWSTR Want)
{
    if (!Name || !Name->Buffer || !Want) return FALSE;
    SIZE_T wLen = wcslen(Want);
    SIZE_T nLen = Name->Length / sizeof(WCHAR);
    if (nLen != wLen) return FALSE;
    for (SIZE_T i = 0; i < wLen; i++) {
        WCHAR a = Name->Buffer[i];
        WCHAR b = Want[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return FALSE;
    }
    return TRUE;
}

/* x64 LDR_DATA_TABLE_ENTRY layout (stable for our fields). */
#define LDR64_DLLBASE_OFF     0x30
#define LDR64_BASENAME_OFF    0x58
/* PEB.Ldr */
#define PEB64_LDR_OFF         0x18
#define LDR_INLOADORDER_OFF   0x10

/* Wow64 PEB32 / LDR_DATA_TABLE_ENTRY32 */
#define PEB32_LDR_OFF         0x0C
#define LDR32_INLOADORDER_OFF 0x0C
#define LDR32_DLLBASE_OFF     0x18
#define LDR32_BASENAME_OFF    0x2C

static PVOID FindModuleBaseByName(_In_ BOOLEAN IsWow64, _In_ PCWSTR BaseName)
{
    PVOID found = NULL;

    __try {
        if (!IsWow64) {
            PPEB peb = PsGetProcessPeb(PsGetCurrentProcess());
            if (!peb) return NULL;
            PUCHAR pebB = (PUCHAR)peb;
            PVOID ldr = *(PVOID*)(pebB + PEB64_LDR_OFF);
            if (!ldr) return NULL;
            PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)ldr + LDR_INLOADORDER_OFF);
            for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
                PUCHAR ent = (PUCHAR)e;
                UNICODE_STRING name = *(PUNICODE_STRING)(ent + LDR64_BASENAME_OFF);
                if (UStrEqISuffix(&name, BaseName)) {
                    found = *(PVOID*)(ent + LDR64_DLLBASE_OFF);
                    break;
                }
            }
        } else {
            /* PEB32 in Wow64 process */
            PUCHAR peb32 = (PUCHAR)PsGetProcessWow64Process(PsGetCurrentProcess());
            if (!peb32) return NULL;
            ULONG ldr32 = *(PULONG)(peb32 + PEB32_LDR_OFF);
            if (!ldr32) return NULL;
            ULONG head = ldr32 + LDR32_INLOADORDER_OFF;
            ULONG flink = *(PULONG)(ULONG_PTR)head;
            ULONG start = flink;
            ULONG guard = 0;
            while (flink && flink != head && guard++ < 512) {
                PUCHAR ent = (PUCHAR)(ULONG_PTR)flink;
                USHORT len = *(PUSHORT)(ent + LDR32_BASENAME_OFF);
                USHORT max = *(PUSHORT)(ent + LDR32_BASENAME_OFF + 2);
                ULONG buf32 = *(PULONG)(ent + LDR32_BASENAME_OFF + 4);
                UNREFERENCED_PARAMETER(max);
                if (buf32 && len) {
                    UNICODE_STRING name;
                    name.Length = len;
                    name.MaximumLength = len;
                    name.Buffer = (PWCH)(ULONG_PTR)buf32;
                    if (UStrEqISuffix(&name, BaseName)) {
                        found = (PVOID)(ULONG_PTR)*(PULONG)(ent + LDR32_DLLBASE_OFF);
                        break;
                    }
                }
                flink = *(PULONG)(ULONG_PTR)flink; /* InLoadOrderLinks.Flink */
                if (flink == start) break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        found = NULL;
    }
    return found;
}

/*
 * Prefer KernelBase!LoadLibraryExW (real body, initialized before kernel32).
 * Fall back to kernel32 export only if KernelBase is missing (legacy).
 */
static ULONG_PTR ResolveLoadLibraryExW(
    _In_ BOOLEAN IsWow64,
    _In_opt_ PVOID Kernel32Base)
{
    PVOID kbase = FindModuleBaseByName(IsWow64, L"kernelbase.dll");
    if (kbase) {
        ULONG_PTR p = ParseExport(kbase, IsWow64, "LoadLibraryExW");
        if (p) return p;
    }

    if (Kernel32Base) {
        ULONG_PTR p = ParseExport(Kernel32Base, IsWow64, "LoadLibraryExW");
        if (p) return p;
    }

    PVOID k32 = FindModuleBaseByName(IsWow64, L"kernel32.dll");
    if (k32)
        return ParseExport(k32, IsWow64, "LoadLibraryExW");

    return 0;
}

/* ------------------------------------------------------------------ */
/*  APC callbacks (OpenEDR apcqueue pattern, C / pool-tag style)      */
/* ------------------------------------------------------------------ */

static VOID NTAPI KernelRoutineCb(
    PRKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext, PVOID* Sys1, PVOID* Sys2)
{
    UNREFERENCED_PARAMETER(Sys1); UNREFERENCED_PARAMETER(Sys2);
    /* WoW64: convert routine + context for the 32-bit APC dispatcher.
       Mirrors OpenEDR wrapApcWow64Thread before delivery. */
    if (PsGetProcessWow64Process(PsGetCurrentProcess()) != NULL)
        PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);
    ExFreePoolWithTag(Apc, INJ_POOL_TAG);
}

static VOID NTAPI RundownCb(PRKAPC Apc)
{
    ExFreePoolWithTag(Apc, INJ_POOL_TAG);
}

/* ------------------------------------------------------------------ */
/*  Core injection — runs in target process context (loader thread)   */
/* ------------------------------------------------------------------ */

static NTSTATUS DoInjectInContext(
    _In_ BOOLEAN IsWow64,
    _In_ PVOID Kernel32Base)
{
    NTSTATUS status;
    PVOID    alloc = NULL;
    SIZE_T   allocSz = 0;

    if (!Kernel32Base)
        return STATUS_INVALID_PARAMETER;

    /* Pick DLL path for this architecture */
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

    /* KernelBase real export — not the unbound kernel32 IAT stub. */
    ULONG_PTR loadLib = ResolveLoadLibraryExW(IsWow64, Kernel32Base);
    if (loadLib == 0)
        return STATUS_PROCEDURE_NOT_FOUND;

    /* Path + NUL only — PAGE_READWRITE, never executable. */
    allocSz = (SIZE_T)dllBytes + sizeof(WCHAR);
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &alloc, 0,
        &allocSz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) return status;

    __try {
        RtlCopyMemory(alloc, dllPath, dllBytes);
        *(PWCHAR)((PUCHAR)alloc + dllBytes) = L'\0';
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        SIZE_T freeSz = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc, &freeSz, MEM_RELEASE);
        return GetExceptionCode();
    }

    /* Queue user-mode APC: NormalRoutine = LoadLibraryExW, Context = path.
       Do NOT KeTestAlertThread here — that forces delivery while kernel32 is
       still mid-map (IAT unbound). OpenEDR also only queues; the loader's
       NtTestAlert after static init delivers the APC safely. */
    PRKTHREAD curThread = (PRKTHREAD)PsGetCurrentThread();

    PRKAPC execApc = (PRKAPC)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(KAPC), INJ_POOL_TAG);
    if (!execApc) {
        SIZE_T freeSz = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc, &freeSz, MEM_RELEASE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeApc(execApc, curThread, OriginalApcEnvironment,
        (PKKERNEL_ROUTINE)KernelRoutineCb, (PKRUNDOWN_ROUTINE)RundownCb,
        (PKNORMAL_ROUTINE)loadLib, UserMode, alloc);

    if (!KeInsertQueueApc(execApc, NULL,
            (PVOID)(ULONG_PTR)INJ_LOADLIBRARY_FLAGS, 0)) {
        ExFreePoolWithTag(execApc, INJ_POOL_TAG);
        {
            SIZE_T freeSz = 0;
            ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc, &freeSz, MEM_RELEASE);
        }
        return STATUS_UNSUCCESSFUL;
    }

    PendingFreeAdd(PsGetCurrentProcessId(), alloc, allocSz);

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
    /* Leave PendingFree entries — still need to free if inject already ran. */
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

    /* Trigger when kernel32 maps in a pending target. KernelBase is already
       initialized by then; APC is delivered later (no KeTestAlertThread). */
    if (!UStrEndsWith(FullImageName, L"kernel32.dll")) return;

    BOOLEAN isPending = PendingRemove(ProcessId);
    if (!isPending) return;

    BOOLEAN isWow64 = UStrContainsI(FullImageName, L"syswow64");

    NTSTATUS st = DoInjectInContext(isWow64, ImageInfo->ImageBase);

    CHAR json[COMS_MAX_MESSAGE_SIZE];
    ULONG tid = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    if (NT_SUCCESS(st)) {
        /* Kernel is source of truth for ObCallback / notify filtering. */
        StateAddPid(ProcessId);
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
    KdPrint(("Peregrine: APC inject (LoadLibraryExW) PID=%lu => 0x%08X\n",
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

VOID InjOnProcessExit(HANDLE ProcessId)
{
    PendingRemove(ProcessId);
    PendingFreeRelease(ProcessId, TRUE);
    StateRemovePid(ProcessId);
}

BOOLEAN InjOnThreadCreate(HANDLE ProcessId, HANDLE ThreadId)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ThreadId);
    return FALSE;
}
