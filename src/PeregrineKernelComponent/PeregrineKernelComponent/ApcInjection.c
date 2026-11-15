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
 * The path buffer is never freed by us: LoadLibraryExW reads it whenever the APC
 * is finally delivered, and the allocation lives in the target's address space,
 * which the memory manager reclaims in full at process teardown.
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
 * Target identity: the normalized NT path of the process image, compared in
 * full (case-insensitive). A basename is not an identity — a cheat renamed to
 * game.exe must not receive the Game DLL and the PROTECTED status that follows.
 *
 * Product semantics kept: IOCTL path config, auto-protect on Game inject
 * (PROTECTED only, never TRUSTED), x64 + WoW64 (PsWrapApcWow64Thread).
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
/*  Global injection state (per-role paths + targets)                 */
/* ------------------------------------------------------------------ */

/* Upper-cased normalized NT path; compared byte-for-byte under the spinlock. */
typedef struct _INJ_TARGET {
    WCHAR  Path[INJ_MAX_PATH];
    USHORT Bytes;
} INJ_TARGET;

typedef struct _INJ_PROFILE {
    WCHAR  DllPathX64[INJ_MAX_PATH];
    USHORT DllPathX64Bytes;
    WCHAR  DllPathX86[INJ_MAX_PATH];
    USHORT DllPathX86Bytes;
    INJ_TARGET Targets[INJ_MAX_TARGETS];
    ULONG  TargetCount;
} INJ_PROFILE;

typedef struct _INJ_PID_ROLE {
    HANDLE Pid;
    UCHAR  Role;
} INJ_PID_ROLE;

typedef struct _INJ_STATE {
    KSPIN_LOCK Lock;
    BOOLEAN    Enabled;

    INJ_PROFILE Profile[INJ_ROLE_COUNT];

    /* Matched at process create, waiting for kernel32 to map. */
    INJ_PID_ROLE Pending[INJ_MAX_PENDING];
    ULONG        PendingCount;

    /* Live processes we queued the inject APC into (source of truth for
       IOCTL_PEREGRINE_QUERY_INJECTED). Entries leave on process exit. */
    INJ_PID_ROLE Injected[INJ_MAX_INJECTED];
    ULONG        InjectedCount;
} INJ_STATE;

static INJ_STATE g_Inj = { 0 };

static __forceinline BOOLEAN InjRoleValid(UCHAR Role)
{
    return Role < INJ_ROLE_COUNT;
}

static __forceinline const CHAR* InjRoleName(UCHAR Role)
{
    return Role == INJ_ROLE_SENSOR ? "sensor" : "game";
}

/* ------------------------------------------------------------------ */
/*  PID/role tables (spinlock-protected)                              */
/* ------------------------------------------------------------------ */

/* Caller holds g_Inj.Lock. FALSE when the table is full. Idempotent per PID. */
static BOOLEAN PidRoleAddLocked(
    _Inout_updates_(Capacity) INJ_PID_ROLE* Table,
    _Inout_ ULONG* Count,
    _In_ ULONG Capacity,
    _In_ HANDLE Pid,
    _In_ UCHAR Role)
{
    for (ULONG i = 0; i < *Count; i++) {
        if (Table[i].Pid == Pid)
            return TRUE;
    }
    if (*Count >= Capacity)
        return FALSE;
    Table[*Count].Pid  = Pid;
    Table[*Count].Role = Role;
    (*Count)++;
    return TRUE;
}

/* Caller holds g_Inj.Lock. Removes the entry; TRUE and OutRole if it existed. */
static BOOLEAN PidRoleTakeLocked(
    _Inout_updates_(*Count) INJ_PID_ROLE* Table,
    _Inout_ ULONG* Count,
    _In_ HANDLE Pid,
    _Out_opt_ UCHAR* OutRole)
{
    for (ULONG i = 0; i < *Count; i++) {
        if (Table[i].Pid == Pid) {
            if (OutRole)
                *OutRole = Table[i].Role;
            Table[i] = Table[--(*Count)];
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN PendingAdd(HANDLE Pid, UCHAR Role)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    BOOLEAN ok = PidRoleAddLocked(g_Inj.Pending, &g_Inj.PendingCount,
        INJ_MAX_PENDING, Pid, Role);
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return ok;
}

static BOOLEAN PendingTake(HANDLE Pid, _Out_opt_ UCHAR* OutRole)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    BOOLEAN found = PidRoleTakeLocked(g_Inj.Pending, &g_Inj.PendingCount, Pid, OutRole);
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return found;
}

static BOOLEAN InjectedAdd(HANDLE Pid, UCHAR Role)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    BOOLEAN ok = PidRoleAddLocked(g_Inj.Injected, &g_Inj.InjectedCount,
        INJ_MAX_INJECTED, Pid, Role);
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return ok;
}

static VOID InjectedRemove(HANDLE Pid)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    PidRoleTakeLocked(g_Inj.Injected, &g_Inj.InjectedCount, Pid, NULL);
    KeReleaseSpinLock(&g_Inj.Lock, irql);
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

/* ------------------------------------------------------------------ */
/*  Target matching by full image path (Game first, then Sensor)      */
/* ------------------------------------------------------------------ */

/*
 * Copies a counted UTF-16 path into Dest upper-cased, so later comparisons
 * are a plain memory compare that is legal under a spinlock.
 * PASSIVE_LEVEL (RtlUpcaseUnicodeString touches pageable NLS tables).
 */
static NTSTATUS UpcasePath(
    _In_ PCUNICODE_STRING Src,
    _Out_writes_(INJ_MAX_PATH) WCHAR* Dest,
    _Out_ USHORT* DestBytes)
{
    *DestBytes = 0;
    if (Src->Length == 0 || (Src->Length % sizeof(WCHAR)) != 0 ||
        Src->Length > (INJ_MAX_PATH - 1) * sizeof(WCHAR))
        return STATUS_NAME_TOO_LONG;

    UNICODE_STRING dst;
    dst.Buffer = Dest;
    dst.Length = 0;
    dst.MaximumLength = (USHORT)(INJ_MAX_PATH * sizeof(WCHAR));

    NTSTATUS status = RtlUpcaseUnicodeString(&dst, Src, FALSE);
    if (NT_SUCCESS(status))
        *DestBytes = dst.Length;
    return status;
}

/* Returns TRUE and OutRole if the upper-cased image path is a configured target. */
static BOOLEAN MatchTargetRole(
    _In_reads_bytes_(PathBytes) const WCHAR* UpperPath,
    _In_ USHORT PathBytes,
    _Out_ UCHAR* OutRole)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    BOOLEAN hit = FALSE;
    /* Prefer Game over Sensor if the same path is listed twice. */
    for (UCHAR role = 0; role < INJ_ROLE_COUNT && !hit; role++) {
        INJ_PROFILE* prof = &g_Inj.Profile[role];
        for (ULONG i = 0; i < prof->TargetCount; i++) {
            if (prof->Targets[i].Bytes == PathBytes &&
                RtlCompareMemory(prof->Targets[i].Path, UpperPath, PathBytes) == PathBytes) {
                *OutRole = role;
                hit = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return hit;
}

/* ------------------------------------------------------------------ */
/*  Reading the target's user-mode memory                             */
/* ------------------------------------------------------------------ */
/*
 * Everything below reads structures that live in the target process and are
 * therefore under that process' control: PEB, loader lists, the PE headers
 * of mapped images. __try alone is not enough — it catches a fault on a bad
 * *user* address, but dereferencing a pointer that an attacker aimed at
 * kernel space bugchecks (or leaks kernel memory). Every pointer taken from
 * user memory is range-checked against the user address space first, and
 * every list walk is bounded.
 */

static __forceinline BOOLEAN UserRange(_In_opt_ const VOID* Address, _In_ SIZE_T Length)
{
    const ULONG_PTR start = (ULONG_PTR)Address;
    const ULONG_PTR end = start + Length;
    return start != 0 && end >= start && end <= (ULONG_PTR)MmUserProbeAddress;
}

#define INJ_MAX_MODULES      512
#define INJ_MAX_EXPORT_NAMES 0x10000

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

    const SIZE_T wantLen = strlen(ExportName) + 1; /* compare includes the NUL */

    __try {
        PUCHAR base = (PUCHAR)ImageBase;
        if (!UserRange(base, 0x40)) return 0;
        if (*(PUSHORT)base != 0x5A4D) return 0;            /* MZ */

        LONG lfanew = *(PLONG)(base + 0x3C);
        if (lfanew < 0x40 || lfanew > 0x1000) return 0;
        if (!UserRange(base + lfanew, 24 + 120)) return 0;
        if (*(PULONG)(base + lfanew) != 0x00004550) return 0; /* PE\0\0 */

        PUCHAR opt = base + lfanew + 24;
        const ULONG imageSize = *(PULONG)(opt + 56);       /* SizeOfImage, PE32 and PE32+ */
        if (imageSize == 0 || !UserRange(base, imageSize)) return 0;

        ULONG  expRva, expSize;
        if (Is32) {
            expRva  = *(PULONG)(opt + 96);                  /* DataDir[0] */
            expSize = *(PULONG)(opt + 100);
        } else {
            expRva  = *(PULONG)(opt + 112);
            expSize = *(PULONG)(opt + 116);
        }

        /* Every RVA below is checked against SizeOfImage before it is used:
           (rva, len) lies inside the image <=> rva <= size && len <= size - rva. */
#define IN_IMAGE(rva, len) ((ULONG)(rva) <= imageSize && (SIZE_T)(len) <= (SIZE_T)(imageSize - (ULONG)(rva)))

        if (expRva == 0 || !IN_IMAGE(expRva, 40)) return 0;

        PUCHAR ed  = base + expRva;
        ULONG  nFuncs    = *(PULONG)(ed + 20);
        ULONG  nNames    = *(PULONG)(ed + 24);
        ULONG  fnRva     = *(PULONG)(ed + 28);
        ULONG  nameRva   = *(PULONG)(ed + 32);
        ULONG  ordRva    = *(PULONG)(ed + 36);

        if (nNames > INJ_MAX_EXPORT_NAMES || nFuncs > INJ_MAX_EXPORT_NAMES) return 0;
        if (!IN_IMAGE(nameRva, (SIZE_T)nNames * sizeof(ULONG)) ||
            !IN_IMAGE(ordRva,  (SIZE_T)nNames * sizeof(USHORT)) ||
            !IN_IMAGE(fnRva,   (SIZE_T)nFuncs * sizeof(ULONG)))
            return 0;

        PULONG  names    = (PULONG)(base + nameRva);
        PUSHORT ords     = (PUSHORT)(base + ordRva);
        PULONG  funcs    = (PULONG)(base + fnRva);

        for (ULONG i = 0; i < nNames; i++) {
            const ULONG strRva = names[i];
            if (!IN_IMAGE(strRva, wantLen)) continue;
            if (RtlCompareMemory(base + strRva, ExportName, wantLen) != wantLen) continue;

            const USHORT ord = ords[i];
            if (ord >= nFuncs) return 0;
            const ULONG rva = funcs[ord];
            /* Forwarded export (RVA inside export directory) — not callable. */
            if (rva >= expRva && rva - expRva < expSize)
                return 0;
            if (!IN_IMAGE(rva, 1)) return 0;
            result = (ULONG_PTR)base + rva;
            break;
        }
#undef IN_IMAGE
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = 0;
    }
    return result;
}

/* ------------------------------------------------------------------ */
/*  PEB LDR walk — find a loaded module base in the current process   */
/* ------------------------------------------------------------------ */

/* Name->Buffer has already been range-checked by the caller. */
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
#define LDR64_ENTRY_MIN       (LDR64_BASENAME_OFF + sizeof(UNICODE_STRING))
/* PEB.Ldr */
#define PEB64_LDR_OFF         0x18
#define LDR_INLOADORDER_OFF   0x10

/* Wow64 PEB32 / LDR_DATA_TABLE_ENTRY32 */
#define PEB32_LDR_OFF         0x0C
#define LDR32_INLOADORDER_OFF 0x0C
#define LDR32_DLLBASE_OFF     0x18
#define LDR32_BASENAME_OFF    0x2C
#define LDR32_ENTRY_MIN       (LDR32_BASENAME_OFF + 8)

static PVOID FindModuleBaseByName(_In_ BOOLEAN IsWow64, _In_ PCWSTR BaseName)
{
    PVOID found = NULL;

    __try {
        if (!IsWow64) {
            PUCHAR pebB = (PUCHAR)PsGetProcessPeb(PsGetCurrentProcess());
            if (!UserRange(pebB + PEB64_LDR_OFF, sizeof(PVOID))) return NULL;
            PUCHAR ldr = *(PUCHAR*)(pebB + PEB64_LDR_OFF);
            if (!UserRange(ldr + LDR_INLOADORDER_OFF, sizeof(LIST_ENTRY))) return NULL;

            PLIST_ENTRY head = (PLIST_ENTRY)(ldr + LDR_INLOADORDER_OFF);
            ULONG guard = 0;
            for (PLIST_ENTRY e = head->Flink;
                 e != head && guard < INJ_MAX_MODULES;
                 e = e->Flink, guard++) {
                PUCHAR ent = (PUCHAR)e;
                if (!UserRange(ent, LDR64_ENTRY_MIN)) break;

                UNICODE_STRING name = *(PUNICODE_STRING)(ent + LDR64_BASENAME_OFF);
                if (name.Buffer && name.Length && UserRange(name.Buffer, name.Length) &&
                    UStrEqISuffix(&name, BaseName)) {
                    PVOID dllBase = *(PVOID*)(ent + LDR64_DLLBASE_OFF);
                    if (UserRange(dllBase, PAGE_SIZE))
                        found = dllBase;
                    break;
                }
            }
        } else {
            /* PEB32 in Wow64 process. 32-bit pointers cannot reach kernel
               space, but they are still range-checked for NULL / wrap. */
            PUCHAR peb32 = (PUCHAR)PsGetProcessWow64Process(PsGetCurrentProcess());
            if (!UserRange(peb32 + PEB32_LDR_OFF, sizeof(ULONG))) return NULL;
            ULONG ldr32 = *(PULONG)(peb32 + PEB32_LDR_OFF);
            ULONG head = ldr32 + LDR32_INLOADORDER_OFF;
            if (!ldr32 || !UserRange((PVOID)(ULONG_PTR)head, sizeof(ULONG))) return NULL;

            ULONG flink = *(PULONG)(ULONG_PTR)head;
            ULONG guard = 0;
            while (flink && flink != head && guard++ < INJ_MAX_MODULES) {
                PUCHAR ent = (PUCHAR)(ULONG_PTR)flink;
                if (!UserRange(ent, LDR32_ENTRY_MIN)) break;

                USHORT len = *(PUSHORT)(ent + LDR32_BASENAME_OFF);
                ULONG buf32 = *(PULONG)(ent + LDR32_BASENAME_OFF + 4);
                if (buf32 && len && UserRange((PVOID)(ULONG_PTR)buf32, len)) {
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

/*
 * Every queued APC (the deferred kernel work item and the user-mode
 * LoadLibraryExW APC) has routines inside this driver image. Each one holds a
 * rundown reference from the moment it is queued until its last routine has
 * run; DriverUnload waits for all of them (InjWaitForApcs) so the image is
 * never unmapped underneath a pending APC.
 */
static EX_RUNDOWN_REF g_InjRundown;

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
    ExReleaseRundownProtection(&g_InjRundown);
}

static VOID NTAPI RundownCb(PRKAPC Apc)
{
    ExFreePoolWithTag(Apc, INJ_POOL_TAG);
    ExReleaseRundownProtection(&g_InjRundown);
}

/* ------------------------------------------------------------------ */
/*  Core injection — runs in target process context (loader thread)   */
/* ------------------------------------------------------------------ */

static NTSTATUS DoInjectInContext(
    _In_ BOOLEAN IsWow64,
    _In_ PVOID Kernel32Base,
    _In_ UCHAR Role)
{
    NTSTATUS status;
    PVOID    alloc = NULL;
    SIZE_T   allocSz = 0;

    if (!Kernel32Base || !InjRoleValid(Role))
        return STATUS_INVALID_PARAMETER;

    /* Pick DLL path for this role + architecture */
    KIRQL irql;
    WCHAR  dllPath[INJ_MAX_PATH];
    USHORT dllBytes;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    {
        INJ_PROFILE* prof = &g_Inj.Profile[Role];
        if (IsWow64) {
            RtlCopyMemory(dllPath, prof->DllPathX86, sizeof(prof->DllPathX86));
            dllBytes = prof->DllPathX86Bytes;
        } else {
            RtlCopyMemory(dllPath, prof->DllPathX64, sizeof(prof->DllPathX64));
            dllBytes = prof->DllPathX64Bytes;
        }
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);

    if (dllBytes == 0) return STATUS_NOT_FOUND;

    /* KernelBase real export — not the unbound kernel32 IAT stub. */
    ULONG_PTR loadLib = ResolveLoadLibraryExW(IsWow64, Kernel32Base);
    if (loadLib == 0)
        return STATUS_PROCEDURE_NOT_FOUND;

    /* Path + NUL only — PAGE_READWRITE, never executable. Not freed by us:
       see the file header (owned by the target address space). */
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

    /* Held until KernelRoutineCb / RundownCb has run. Fails once the driver
       is unloading. */
    if (!ExAcquireRundownProtection(&g_InjRundown)) {
        ExFreePoolWithTag(execApc, INJ_POOL_TAG);
        SIZE_T freeSz = 0;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc, &freeSz, MEM_RELEASE);
        return STATUS_DELETE_PENDING;
    }

    KeInitializeApc(execApc, curThread, OriginalApcEnvironment,
        (PKKERNEL_ROUTINE)KernelRoutineCb, (PKRUNDOWN_ROUTINE)RundownCb,
        (PKNORMAL_ROUTINE)loadLib, UserMode, alloc);

    if (!KeInsertQueueApc(execApc, NULL,
            (PVOID)(ULONG_PTR)INJ_LOADLIBRARY_FLAGS, 0)) {
        ExReleaseRundownProtection(&g_InjRundown);
        ExFreePoolWithTag(execApc, INJ_POOL_TAG);
        {
            SIZE_T freeSz = 0;
            ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc, &freeSz, MEM_RELEASE);
        }
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

VOID InjInit(VOID)
{
    RtlZeroMemory(&g_Inj, sizeof(g_Inj));
    KeInitializeSpinLock(&g_Inj.Lock);
    ExInitializeRundownProtection(&g_InjRundown);
}

VOID InjWaitForApcs(VOID)
{
    /* PASSIVE_LEVEL. Blocks until every queued APC has been delivered or run
       down; afterwards no new one can be queued. */
    ExWaitForRundownProtectionRelease(&g_InjRundown);
}

NTSTATUS InjSetDllPath(UCHAR Role, BOOLEAN IsX86, const VOID* Path, ULONG PathBytes)
{
    if (!InjRoleValid(Role) || !Path || PathBytes == 0 ||
        (PathBytes % sizeof(WCHAR)) != 0 ||
        PathBytes > (INJ_MAX_PATH - 1) * sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    {
        INJ_PROFILE* prof = &g_Inj.Profile[Role];
        if (IsX86) {
            RtlZeroMemory(prof->DllPathX86, sizeof(prof->DllPathX86));
            RtlCopyMemory(prof->DllPathX86, Path, PathBytes);
            prof->DllPathX86Bytes = (USHORT)PathBytes;
        } else {
            RtlZeroMemory(prof->DllPathX64, sizeof(prof->DllPathX64));
            RtlCopyMemory(prof->DllPathX64, Path, PathBytes);
            prof->DllPathX64Bytes = (USHORT)PathBytes;
        }
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS InjAddTarget(UCHAR Role, const VOID* Path, ULONG PathBytes)
{
    if (!InjRoleValid(Role) || !Path || PathBytes == 0 ||
        (PathBytes % sizeof(WCHAR)) != 0 ||
        PathBytes > (INJ_MAX_PATH - 1) * sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    /* The IOCTL payload is unaligned: copy before treating it as WCHARs. */
    WCHAR raw[INJ_MAX_PATH];
    RtlCopyMemory(raw, Path, PathBytes);

    /* Only an absolute NT path can equal a normalized image name. */
    if (raw[0] != L'\\')
        return STATUS_OBJECT_PATH_SYNTAX_BAD;

    UNICODE_STRING src;
    src.Buffer = raw;
    src.Length = (USHORT)PathBytes;
    src.MaximumLength = (USHORT)PathBytes;

    INJ_TARGET target;
    NTSTATUS status = UpcasePath(&src, target.Path, &target.Bytes);
    if (!NT_SUCCESS(status))
        return status;

    status = STATUS_SUCCESS;
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    {
        INJ_PROFILE* prof = &g_Inj.Profile[Role];
        BOOLEAN present = FALSE;
        for (ULONG i = 0; i < prof->TargetCount; i++) {
            if (prof->Targets[i].Bytes == target.Bytes &&
                RtlCompareMemory(prof->Targets[i].Path, target.Path, target.Bytes) == target.Bytes) {
                present = TRUE;
                break;
            }
        }
        if (!present) {
            if (prof->TargetCount >= INJ_MAX_TARGETS) {
                status = STATUS_INSUFFICIENT_RESOURCES;
            } else {
                INJ_TARGET* slot = &prof->Targets[prof->TargetCount++];
                RtlCopyMemory(slot->Path, target.Path, target.Bytes);
                slot->Bytes = target.Bytes;
            }
        }
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return status;
}

NTSTATUS InjClearTargets(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    for (UCHAR r = 0; r < INJ_ROLE_COUNT; r++)
        g_Inj.Profile[r].TargetCount = 0;
    g_Inj.PendingCount = 0;
    /* Injected entries stay: those processes still host our DLL. */
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

BOOLEAN InjIsEnabled(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    BOOLEAN enabled = g_Inj.Enabled;
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return enabled;
}

BOOLEAN InjGetTarget(UCHAR Role, ULONG Index, WCHAR* Dest)
{
    BOOLEAN found = FALSE;
    Dest[0] = L'\0';
    if (!InjRoleValid(Role))
        return FALSE;

    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    const INJ_PROFILE* prof = &g_Inj.Profile[Role];
    if (Index < prof->TargetCount) {
        const INJ_TARGET* t = &prof->Targets[Index];
        /* Bytes <= (INJ_MAX_PATH - 1) * sizeof(WCHAR), enforced by InjAddTarget. */
        const ULONG chars = min((ULONG)t->Bytes / sizeof(WCHAR), INJ_MAX_PATH - 1);
        RtlCopyMemory(Dest, t->Path, chars * sizeof(WCHAR));
        Dest[chars] = L'\0';
        found = TRUE;
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return found;
}

ULONG InjQueryRole(HANDLE Pid)
{
    ULONG result = INJ_QUERY_NONE;
    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    for (ULONG i = 0; i < g_Inj.InjectedCount; i++) {
        if (g_Inj.Injected[i].Pid == Pid) {
            result = (g_Inj.Injected[i].Role == INJ_ROLE_SENSOR)
                ? INJ_QUERY_SENSOR : INJ_QUERY_GAME;
            break;
        }
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    return result;
}

/* ------------------------------------------------------------------ */
/*  Callback hooks (called from NotifyRoutine.c)                      */
/* ------------------------------------------------------------------ */

static VOID InjReport(_In_ HANDLE ProcessId, _In_ UCHAR Role, _In_ NTSTATUS Status,
    _In_ BOOLEAN IsProtected)
{
    CHAR json[384];
    const ULONG tid = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    const CHAR* roleStr = InjRoleName(Role);

    if (NT_SUCCESS(Status)) {
        RtlStringCchPrintfA(json, ARRAYSIZE(json),
            "{ \"event\": \"apc_inject\", \"pid\": %lu, \"tid\": %lu, "
            "\"status\": \"success\", \"role\": \"%s\", \"protected\": %s }",
            (ULONG)(ULONG_PTR)ProcessId, tid, roleStr,
            IsProtected ? "true" : "false");
    } else {
        RtlStringCchPrintfA(json, ARRAYSIZE(json),
            "{ \"event\": \"apc_inject\", \"pid\": %lu, \"tid\": %lu, "
            "\"status\": \"failed\", \"error\": \"0x%08X\", \"role\": \"%s\" }",
            (ULONG)(ULONG_PTR)ProcessId, tid, Status, roleStr);
    }
    ComsSendToUser(json, (ULONG)strlen(json));
    KdPrint(("Peregrine: APC inject role=%s PID=%lu => 0x%08X\n",
        roleStr, (ULONG)(ULONG_PTR)ProcessId, Status));
}

/*
 * The actual injection is not done in the load-image notify routine: such a
 * routine must not allocate, map or otherwise operate on user-space virtual
 * memory (documented deadlock). The notify routine only queues a kernel-mode
 * APC to the loading thread; its normal routine runs at PASSIVE_LEVEL in the
 * same thread and process once the image mapping has completed, and does the
 * work there (the OpenEDR apcqueue pattern).
 */
typedef struct _INJ_WORK {
    KAPC    Apc;
    HANDLE  ProcessId;
    PVOID   Kernel32Base;
    UCHAR   Role;
    BOOLEAN IsWow64;
} INJ_WORK;

static VOID NTAPI InjWorkKernelRoutine(
    PRKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext, PVOID* Sys1, PVOID* Sys2)
{
    /* Nothing to do at APC_LEVEL; InjWorkNormalRoutine follows and owns the item. */
    UNREFERENCED_PARAMETER(Apc);
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(Sys1);
    UNREFERENCED_PARAMETER(Sys2);
}

static VOID NTAPI InjWorkRundown(PRKAPC Apc)
{
    /* The thread went away before the APC was delivered. */
    INJ_WORK* work = CONTAINING_RECORD(Apc, INJ_WORK, Apc);
    ExFreePoolWithTag(work, INJ_POOL_TAG);
    ExReleaseRundownProtection(&g_InjRundown);
}

/* PASSIVE_LEVEL, in the target process, on the thread that mapped kernel32. */
static VOID NTAPI InjWorkNormalRoutine(PVOID NormalContext, PVOID Sys1, PVOID Sys2)
{
    UNREFERENCED_PARAMETER(Sys1);
    UNREFERENCED_PARAMETER(Sys2);

    INJ_WORK* work = (INJ_WORK*)NormalContext;
    const HANDLE processId = work->ProcessId;
    const UCHAR role = work->Role;

    /* Reserve the bookkeeping slot first: an inject we cannot account for
       (IPC authentication relies on it) must not happen at all. */
    NTSTATUS st;
    if (!InjectedAdd(processId, role)) {
        st = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        st = DoInjectInContext(work->IsWow64, work->Kernel32Base, role);
        if (!NT_SUCCESS(st))
            InjectedRemove(processId);
    }

    /* Only Game inject auto-protects the PID (Sensor = cheat host).
       This grants PROTECTED only — never TRUSTED. */
    BOOLEAN isProtected = FALSE;
    if (NT_SUCCESS(st) && role == INJ_ROLE_GAME)
        isProtected = NT_SUCCESS(StateProtectPid(processId));

    InjReport(processId, role, st, isProtected);

    ExFreePoolWithTag(work, INJ_POOL_TAG);
    ExReleaseRundownProtection(&g_InjRundown);
}

VOID InjOnImageLoad(HANDLE ProcessId, PUNICODE_STRING FullImageName,
    PIMAGE_INFO ImageInfo)
{
    if (!FullImageName || !ImageInfo || !ImageInfo->ImageBase) return;
    if ((ULONG_PTR)ProcessId == 0 || ImageInfo->SystemModeImage) return;

    /* The image must be mapped by the process itself (its loader). When
       another process maps a section into the target, this routine runs on
       the *mapper's* thread: an APC queued here would never run in the game,
       and reporting success would vouch for a game without our DLL. */
    if (PsGetCurrentProcessId() != ProcessId) return;

    /* Trigger: the system's own kernel32 for this process' bitness. */
    const BOOLEAN isWow64 = PsGetProcessWow64Process(PsGetCurrentProcess()) != NULL;
    if (!UStrEndsWith(FullImageName,
            isWow64 ? L"\\windows\\syswow64\\kernel32.dll"
                    : L"\\windows\\system32\\kernel32.dll"))
        return;

    UCHAR role = INJ_ROLE_GAME;
    if (!PendingTake(ProcessId, &role)) return;

    NTSTATUS st = STATUS_SUCCESS;
    INJ_WORK* work = NULL;

    if (!ExAcquireRundownProtection(&g_InjRundown)) {
        st = STATUS_DELETE_PENDING;
    } else {
        work = (INJ_WORK*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(INJ_WORK), INJ_POOL_TAG);
        if (!work) {
            ExReleaseRundownProtection(&g_InjRundown);
            st = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (work) {
        work->ProcessId = ProcessId;
        work->Kernel32Base = ImageInfo->ImageBase;
        work->Role = role;
        work->IsWow64 = isWow64;

        KeInitializeApc(&work->Apc, (PRKTHREAD)PsGetCurrentThread(), OriginalApcEnvironment,
            (PKKERNEL_ROUTINE)InjWorkKernelRoutine, (PKRUNDOWN_ROUTINE)InjWorkRundown,
            (PKNORMAL_ROUTINE)InjWorkNormalRoutine, KernelMode, work);

        if (!KeInsertQueueApc(&work->Apc, NULL, NULL, 0)) {
            ExFreePoolWithTag(work, INJ_POOL_TAG);
            ExReleaseRundownProtection(&g_InjRundown);
            st = STATUS_UNSUCCESSFUL;
        }
    }

    if (!NT_SUCCESS(st))
        InjReport(ProcessId, role, st, FALSE);
}
VOID InjOnProcessCreate(HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (!CreateInfo || !CreateInfo->FileObject) return;

    KIRQL irql;
    KeAcquireSpinLock(&g_Inj.Lock, &irql);
    BOOLEAN go = g_Inj.Enabled;
    ULONG totalTargets = 0;
    if (go) {
        for (UCHAR r = 0; r < INJ_ROLE_COUNT; r++)
            totalTargets += g_Inj.Profile[r].TargetCount;
    }
    KeReleaseSpinLock(&g_Inj.Lock, irql);
    if (!go || totalTargets == 0) return;

    /* Normalized NT path of the image actually being executed. Unlike
       CreateInfo->ImageFileName this is independent of how the caller spelled
       the path (short names, relative paths, links resolved by the FS). */
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS st = FltGetFileNameInformationUnsafe(CreateInfo->FileObject, NULL,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(st) || nameInfo == NULL) return;

    WCHAR upper[INJ_MAX_PATH];
    USHORT upperBytes = 0;
    st = UpcasePath(&nameInfo->Name, upper, &upperBytes);
    FltReleaseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(st)) return; /* longer than any configurable target */

    UCHAR role = INJ_ROLE_GAME;
    if (!MatchTargetRole(upper, upperBytes, &role)) return;

    if (!PendingAdd(ProcessId, role)) {
        CHAR json[COMS_MAX_MESSAGE_SIZE];
        RtlStringCchPrintfA(json, ARRAYSIZE(json),
            "{ \"event\": \"apc_inject\", \"pid\": %lu, \"tid\": 0, "
            "\"status\": \"failed\", \"error\": \"0x%08X\", \"role\": \"%s\" }",
            (ULONG)(ULONG_PTR)ProcessId, (ULONG)STATUS_INSUFFICIENT_RESOURCES,
            InjRoleName(role));
        ComsSendToUser(json, (ULONG)strlen(json));
        return;
    }

    KdPrint(("Peregrine: injection pending PID %lu role=%s\n",
        (ULONG)(ULONG_PTR)ProcessId, InjRoleName(role)));
}

VOID InjOnProcessExit(HANDLE ProcessId)
{
    PendingTake(ProcessId, NULL);
    InjectedRemove(ProcessId);
}
