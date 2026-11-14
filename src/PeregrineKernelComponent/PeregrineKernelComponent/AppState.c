#include "AppState.h"

#define STATE_SET_CAPACITY STATE_MAX_PROTECTED

C_ASSERT(STATE_MAX_TRUSTED <= STATE_SET_CAPACITY);

typedef struct _PID_SET {
    HANDLE     Pids[STATE_SET_CAPACITY];
    ULONG      Count;
    ULONG      Limit;
    KSPIN_LOCK Lock;
} PID_SET;

static PID_SET g_Protected;
static PID_SET g_Trusted;

static VOID PidSetInit(_Out_ PID_SET* Set, _In_ ULONG Limit)
{
    RtlZeroMemory(Set, sizeof(*Set));
    Set->Limit = Limit;
    KeInitializeSpinLock(&Set->Lock);
}

static NTSTATUS PidSetAdd(_Inout_ PID_SET* Set, _In_ HANDLE Pid)
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;
    KeAcquireSpinLock(&Set->Lock, &irql);

    BOOLEAN present = FALSE;
    for (ULONG i = 0; i < Set->Count; i++) {
        if (Set->Pids[i] == Pid) { present = TRUE; break; }
    }

    if (!present) {
        if (Set->Count >= Set->Limit)
            status = STATUS_INSUFFICIENT_RESOURCES;
        else
            Set->Pids[Set->Count++] = Pid;
    }

    KeReleaseSpinLock(&Set->Lock, irql);
    return status;
}

static NTSTATUS PidSetRemove(_Inout_ PID_SET* Set, _In_ HANDLE Pid)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL irql;
    KeAcquireSpinLock(&Set->Lock, &irql);

    for (ULONG i = 0; i < Set->Count; i++) {
        if (Set->Pids[i] == Pid) {
            /* Order is irrelevant: move the last entry into the gap. */
            Set->Pids[i] = Set->Pids[--Set->Count];
            status = STATUS_SUCCESS;
            break;
        }
    }

    KeReleaseSpinLock(&Set->Lock, irql);
    return status;
}

static BOOLEAN PidSetContains(_Inout_ PID_SET* Set, _In_ HANDLE Pid)
{
    BOOLEAN found = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&Set->Lock, &irql);
    for (ULONG i = 0; i < Set->Count; i++) {
        if (Set->Pids[i] == Pid) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&Set->Lock, irql);
    return found;
}

static VOID PidSetClear(_Inout_ PID_SET* Set)
{
    KIRQL irql;
    KeAcquireSpinLock(&Set->Lock, &irql);
    Set->Count = 0;
    KeReleaseSpinLock(&Set->Lock, irql);
}

VOID StateInit(VOID)
{
    PidSetInit(&g_Protected, STATE_MAX_PROTECTED);
    PidSetInit(&g_Trusted, STATE_MAX_TRUSTED);
}

NTSTATUS StateProtectPid(HANDLE Pid)   { return PidSetAdd(&g_Protected, Pid); }
NTSTATUS StateUnprotectPid(HANDLE Pid) { return PidSetRemove(&g_Protected, Pid); }
VOID     StateClearProtected(VOID)     { PidSetClear(&g_Protected); }
BOOLEAN  StateIsPidProtected(HANDLE Pid) { return PidSetContains(&g_Protected, Pid); }

NTSTATUS StateTrustPid(HANDLE Pid)     { return PidSetAdd(&g_Trusted, Pid); }
BOOLEAN  StateIsPidTrusted(HANDLE Pid) { return PidSetContains(&g_Trusted, Pid); }

VOID StateOnProcessExit(HANDLE Pid)
{
    PidSetRemove(&g_Protected, Pid);
    PidSetRemove(&g_Trusted, Pid);
}
