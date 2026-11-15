/*
 * Handle monitoring for PROTECTED processes — process handles AND thread handles.
 *
 * OpenThread needs no process handle: THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME
 * on a game thread is enough to hijack execution. Watching PsProcessType alone
 * leaves that half of the handle surface invisible, so both types are registered.
 *
 * Report-only: access masks are not stripped.
 *
 * Reporting policy
 *   - target (or the thread's owning process) must be PROTECTED
 *   - kernel handles, self-access and TRUSTED callers are skipped
 *   - only access that lets the holder read, modify or control the target is
 *     reported (masks below — this is the single definition; the GUI only
 *     decodes bits, it does not filter again)
 *   - rate limit is on the *report*, never on the detection: see ObRateLimit
 */

#include "obCallback.h"
#include "Coms.h"
#include <ntstrsafe.h>

static PVOID g_ObRegistration = NULL;

/* Exported by ntoskrnl, not declared in the WDK headers. */
NTKERNELAPI PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

/* Access that has not been resolved to specific rights yet. MAXIMUM_ALLOWED in
   particular would otherwise grant everything while matching no specific bit. */
#define UNRESOLVED_ACCESS ( \
    0x02000000 /* MAXIMUM_ALLOWED */ | \
    0x10000000 /* GENERIC_ALL */     | \
    0x20000000 /* GENERIC_EXECUTE */ | \
    0x40000000 /* GENERIC_WRITE */   | \
    0x80000000 /* GENERIC_READ */ )

/* PROCESS_VM_READ is included on purpose: external ESP / aimbots are exactly
   OpenProcess(VM_READ) + a read loop. Its volume is handled by the rate limit. */
#define DANGEROUS_PROCESS_ACCESS ( \
    0x0001 /* PROCESS_TERMINATE */       | \
    0x0002 /* PROCESS_CREATE_THREAD */   | \
    0x0008 /* PROCESS_VM_OPERATION */    | \
    0x0010 /* PROCESS_VM_READ */         | \
    0x0020 /* PROCESS_VM_WRITE */        | \
    0x0040 /* PROCESS_DUP_HANDLE */      | \
    0x0200 /* PROCESS_SET_INFORMATION */ | \
    0x0800 /* PROCESS_SUSPEND_RESUME */  | \
    UNRESOLVED_ACCESS )

#define DANGEROUS_THREAD_ACCESS ( \
    0x0001 /* THREAD_TERMINATE */        | \
    0x0002 /* THREAD_SUSPEND_RESUME */   | \
    0x0008 /* THREAD_GET_CONTEXT */      | \
    0x0010 /* THREAD_SET_CONTEXT */      | \
    0x0020 /* THREAD_SET_INFORMATION */  | \
    UNRESOLVED_ACCESS )

typedef enum _OB_KIND {
    ObKindProcess = 0,
    ObKindThread  = 1,
} OB_KIND;

static __forceinline const CHAR* ObKindName(OB_KIND Kind)
{
    return Kind == ObKindThread ? "thread" : "process";
}

/* ------------------------------------------------------------------ */
/*  Report rate limit per (caller, target, kind)                       */
/* ------------------------------------------------------------------ */
/*
 * A handle-open loop must neither flood the event ring (which would push real
 * findings out) nor go silent. Per pair:
 *   - the first event is reported immediately
 *   - an event that requests dangerous bits not yet reported in the current
 *     window is reported immediately (an escalation is new information)
 *   - everything else inside the window is counted, and the count rides on the
 *     next report for that pair as "suppressed"
 * Suppressed events therefore never carry access bits the GUI has not already
 * seen for that pair. If a slot is reclaimed while it still holds a count, the
 * count is flushed as its own "ob_callback_suppressed" event.
 */

#define OB_RL_SLOTS        64
#define OB_RL_WINDOW_100NS (2ULL * 10 * 1000 * 1000) /* 2 s in 100 ns units */

typedef struct _OB_RL_ENTRY {
    BOOLEAN     InUse;
    UCHAR       Kind;
    HANDLE      CallerPid;
    HANDLE      TargetPid;
    ULONGLONG   WindowStart;
    ACCESS_MASK Reported;
    ULONG       Suppressed;
} OB_RL_ENTRY;

typedef struct _OB_RL_DECISION {
    BOOLEAN Report;
    ULONG   Suppressed;        /* repeats swallowed since the last report */

    BOOLEAN FlushEvicted;      /* a reclaimed slot still held a count */
    UCHAR   EvictedKind;
    HANDLE  EvictedCallerPid;
    HANDLE  EvictedTargetPid;
    ULONG   EvictedSuppressed;
} OB_RL_DECISION;

static OB_RL_ENTRY g_ObRl[OB_RL_SLOTS];
static KSPIN_LOCK  g_ObRlLock;

static VOID ObRateLimit(
    _In_ OB_KIND Kind,
    _In_ HANDLE CallerPid,
    _In_ HANDLE TargetPid,
    _In_ ACCESS_MASK Dangerous,
    _Out_ OB_RL_DECISION* Decision)
{
    RtlZeroMemory(Decision, sizeof(*Decision));

    const ULONGLONG now = KeQueryInterruptTime();
    KIRQL irql;
    KeAcquireSpinLock(&g_ObRlLock, &irql);

    OB_RL_ENTRY* entry = NULL;
    OB_RL_ENTRY* reclaim = &g_ObRl[0];

    for (ULONG i = 0; i < OB_RL_SLOTS; i++) {
        OB_RL_ENTRY* e = &g_ObRl[i];
        if (e->InUse && e->Kind == (UCHAR)Kind &&
            e->CallerPid == CallerPid && e->TargetPid == TargetPid) {
            entry = e;
            break;
        }
        /* Reclaim candidate: any free slot, else the oldest window. */
        if (reclaim->InUse && (!e->InUse || e->WindowStart < reclaim->WindowStart))
            reclaim = e;
    }

    if (entry != NULL) {
        const BOOLEAN expired = (now - entry->WindowStart) >= OB_RL_WINDOW_100NS;
        const ACCESS_MASK newBits = Dangerous & ~entry->Reported;

        if (expired) {
            entry->WindowStart = now;
            entry->Reported = Dangerous;
        } else if (newBits != 0) {
            entry->Reported |= Dangerous;
        }

        if (expired || newBits != 0) {
            Decision->Report = TRUE;
            Decision->Suppressed = entry->Suppressed;
            entry->Suppressed = 0;
        } else if (entry->Suppressed != MAXULONG) {
            entry->Suppressed++;
        }
    } else {
        if (reclaim->InUse && reclaim->Suppressed != 0) {
            Decision->FlushEvicted = TRUE;
            Decision->EvictedKind = reclaim->Kind;
            Decision->EvictedCallerPid = reclaim->CallerPid;
            Decision->EvictedTargetPid = reclaim->TargetPid;
            Decision->EvictedSuppressed = reclaim->Suppressed;
        }

        reclaim->InUse = TRUE;
        reclaim->Kind = (UCHAR)Kind;
        reclaim->CallerPid = CallerPid;
        reclaim->TargetPid = TargetPid;
        reclaim->WindowStart = now;
        reclaim->Reported = Dangerous;
        reclaim->Suppressed = 0;

        Decision->Report = TRUE;
    }

    KeReleaseSpinLock(&g_ObRlLock, irql);
}

/*
 * A burst that simply stops (the tool exits) never produces the "next report"
 * its count would ride on. Called from the GUI's event poll (PASSIVE_LEVEL):
 * emits the count of every pair whose window has run out as its own
 * "ob_callback_suppressed" event, at most a few times per second.
 */
#define OB_RL_FLUSH_INTERVAL_100NS (5ULL * 1000 * 1000) /* 500 ms */
#define OB_RL_FLUSH_BATCH          8

static ULONGLONG g_ObRlLastFlush = 0;

VOID ObFlushSuppressedReports(VOID)
{
    struct {
        UCHAR  Kind;
        HANDLE CallerPid;
        HANDLE TargetPid;
        ULONG  Suppressed;
    } pending[OB_RL_FLUSH_BATCH];
    ULONG count = 0;

    /* Table and lock are set up by createRegistration. */
    if (g_ObRegistration == NULL)
        return;

    const ULONGLONG now = KeQueryInterruptTime();
    KIRQL irql;
    KeAcquireSpinLock(&g_ObRlLock, &irql);

    if ((now - g_ObRlLastFlush) >= OB_RL_FLUSH_INTERVAL_100NS) {
        g_ObRlLastFlush = now;
        for (ULONG i = 0; i < OB_RL_SLOTS && count < OB_RL_FLUSH_BATCH; i++) {
            OB_RL_ENTRY* e = &g_ObRl[i];
            if (e->InUse && e->Suppressed != 0 &&
                (now - e->WindowStart) >= OB_RL_WINDOW_100NS) {
                pending[count].Kind = e->Kind;
                pending[count].CallerPid = e->CallerPid;
                pending[count].TargetPid = e->TargetPid;
                pending[count].Suppressed = e->Suppressed;
                count++;
                e->Suppressed = 0;
            }
        }
    }

    KeReleaseSpinLock(&g_ObRlLock, irql);

    for (ULONG i = 0; i < count; i++) {
        CHAR json[192];
        RtlStringCchPrintfA(
            json, ARRAYSIZE(json),
            "{ \"event\": \"ob_callback_suppressed\", \"type\": \"%s\", "
            "\"target_pid\": %lu, \"caller_pid\": %lu, \"suppressed\": %lu }",
            ObKindName((OB_KIND)pending[i].Kind),
            (ULONG)(ULONG_PTR)pending[i].TargetPid,
            (ULONG)(ULONG_PTR)pending[i].CallerPid,
            pending[i].Suppressed);
        ComsSendToUser(json, (ULONG)strlen(json));
    }
}

/* ------------------------------------------------------------------ */
/*  Pre-operation callback (process + thread handles)                  */
/* ------------------------------------------------------------------ */

static OB_PREOP_CALLBACK_STATUS ObPreOperation(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    /* 1. Kernel handles — always skip. */
    if (OperationInformation->KernelHandle)
        return OB_PREOP_SUCCESS;

    if (OperationInformation->Object == NULL)
        return OB_PREOP_SUCCESS;

    /* 2. Resolve the process the handle would give access to. */
    OB_KIND kind;
    HANDLE targetPid;
    HANDLE targetTid = NULL;
    ACCESS_MASK dangerousMask;

    if (OperationInformation->ObjectType == *PsProcessType) {
        kind = ObKindProcess;
        targetPid = PsGetProcessId((PEPROCESS)OperationInformation->Object);
        dangerousMask = DANGEROUS_PROCESS_ACCESS;
    } else if (OperationInformation->ObjectType == *PsThreadType) {
        kind = ObKindThread;
        targetPid = PsGetThreadProcessId((PETHREAD)OperationInformation->Object);
        targetTid = PsGetThreadId((PETHREAD)OperationInformation->Object);
        dangerousMask = DANGEROUS_THREAD_ACCESS;
    } else {
        return OB_PREOP_SUCCESS;
    }

    /* 3. Only PROTECTED targets are in scope. */
    if (!StateIsPidProtected(targetPid))
        return OB_PREOP_SUCCESS;

    /* 4. Desired access, and for duplicates the process receiving the handle. */
    ACCESS_MASK desiredAccess;
    const CHAR* opName;
    HANDLE recipientPid = NULL;

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        opName = "create";
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        opName = "duplicate";
        PVOID recipient = OperationInformation->Parameters->DuplicateHandleInformation.TargetProcess;
        if (recipient != NULL)
            recipientPid = PsGetProcessId((PEPROCESS)recipient);
    } else {
        return OB_PREOP_SUCCESS;
    }

    const HANDLE callerPid = PsGetCurrentProcessId();

    /* 5. Self-access: the game opening itself. A duplicate only counts as
          self-access if the handle also stays inside the game — the game
          handing a handle to another process is exactly what we want to see. */
    if (callerPid == targetPid &&
        (recipientPid == NULL || recipientPid == targetPid))
        return OB_PREOP_SUCCESS;

    /* 6. TRUSTED caller (the AC GUI itself). PROTECTED is deliberately not an
          exemption: being defended does not make a process one of us. */
    if (StateIsPidTrusted(callerPid))
        return OB_PREOP_SUCCESS;

    /* 7. Only access that can read, modify or control the target. */
    const ACCESS_MASK dangerous = desiredAccess & dangerousMask;
    if (dangerous == 0)
        return OB_PREOP_SUCCESS;

    /* 8. Rate-limit the report (never the decision above). */
    OB_RL_DECISION decision;
    ObRateLimit(kind, callerPid, targetPid, dangerous, &decision);

    CHAR json[448];

    if (decision.FlushEvicted) {
        RtlStringCchPrintfA(
            json, ARRAYSIZE(json),
            "{ \"event\": \"ob_callback_suppressed\", \"type\": \"%s\", "
            "\"target_pid\": %lu, \"caller_pid\": %lu, \"suppressed\": %lu }",
            ObKindName((OB_KIND)decision.EvictedKind),
            (ULONG)(ULONG_PTR)decision.EvictedTargetPid,
            (ULONG)(ULONG_PTR)decision.EvictedCallerPid,
            decision.EvictedSuppressed);
        ComsSendToUser(json, (ULONG)strlen(json));
    }

    if (decision.Report) {
        /* Image name of the caller (EPROCESS.ImageFileName, at most 15 chars).
           Informational only: the name is caller-controlled and never used
           for a decision. Captured here because the process may be gone by
           the time the GUI could look the PID up. */
        CHAR callerName[40];
        if (!JsonEscapeString(callerName, sizeof(callerName),
                PsGetProcessImageFileName(PsGetCurrentProcess())))
            callerName[0] = '\0';

        RtlStringCchPrintfA(
            json, ARRAYSIZE(json),
            "{ \"event\": \"ob_callback\", \"type\": \"%s\", \"op\": \"%s\", "
            "\"target_pid\": %lu, \"target_tid\": %lu, \"caller_pid\": %lu, "
            "\"caller_name\": \"%s\", "
            "\"recipient_pid\": %lu, \"desired_access\": \"0x%08X\", "
            "\"suppressed\": %lu }",
            ObKindName(kind),
            opName,
            (ULONG)(ULONG_PTR)targetPid,
            (ULONG)(ULONG_PTR)targetTid,
            (ULONG)(ULONG_PTR)callerPid,
            callerName,
            (ULONG)(ULONG_PTR)recipientPid,
            desiredAccess,
            decision.Suppressed);
        ComsSendToUser(json, (ULONG)strlen(json));
    }

    return OB_PREOP_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Registration                                                       */
/* ------------------------------------------------------------------ */

VOID unregisterRegistration(void) {
    if (g_ObRegistration != NULL) {
        ObUnRegisterCallbacks(g_ObRegistration);
        g_ObRegistration = NULL;
    }
}

NTSTATUS createRegistration(void) {
    OB_CALLBACK_REGISTRATION registrationInfo;
    OB_OPERATION_REGISTRATION operations[2];

    RtlZeroMemory(&registrationInfo, sizeof(registrationInfo));
    RtlZeroMemory(operations, sizeof(operations));
    RtlZeroMemory(g_ObRl, sizeof(g_ObRl));
    KeInitializeSpinLock(&g_ObRlLock);

    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = ObPreOperation;

    operations[1].ObjectType = PsThreadType;
    operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = ObPreOperation;

    registrationInfo.Version = OB_FLT_REGISTRATION_VERSION;
    registrationInfo.OperationRegistrationCount = ARRAYSIZE(operations);
    registrationInfo.RegistrationContext = NULL;
    registrationInfo.OperationRegistration = operations;
    RtlInitUnicodeString(&registrationInfo.Altitude, L"362249.1234");

    NTSTATUS status = ObRegisterCallbacks(&registrationInfo, &g_ObRegistration);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "ObRegisterCallbacks failed 0x%08X\n", status);
    }
    return status;
}
