#include "AppState.h"

#define MAX_PIDS 32  // anpassen bei Bedarf

typedef struct _APP_STATE {
    HANDLE    Pids[MAX_PIDS];
    ULONG   Count;
    KSPIN_LOCK Lock;
} APP_STATE;

static APP_STATE g_State = { 0 };

VOID StateInit(VOID)
{
    KeInitializeSpinLock(&g_State.Lock);
    g_State.Count = 0;
    RtlZeroMemory(g_State.Pids, sizeof(g_State.Pids));
}

NTSTATUS StateAddPid(HANDLE pid)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_State.Lock, &irql);

    // bereits drin?
    for (ULONG i = 0; i < g_State.Count; i++) {
        if (g_State.Pids[i] == pid) {
            KeReleaseSpinLock(&g_State.Lock, irql);
            return STATUS_ALREADY_COMMITTED;
        }
    }

    if (g_State.Count >= MAX_PIDS) {
        KeReleaseSpinLock(&g_State.Lock, irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_State.Pids[g_State.Count++] = pid;
    KeReleaseSpinLock(&g_State.Lock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS StateClearPids()
{
	KIRQL irql;
	KeAcquireSpinLock(&g_State.Lock, &irql);
	g_State.Count = 0;
	RtlZeroMemory(g_State.Pids, sizeof(g_State.Pids));
	KeReleaseSpinLock(&g_State.Lock, irql);
	return STATUS_SUCCESS;
}

NTSTATUS StateRemovePid(HANDLE pid)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_State.Lock, &irql);

    for (ULONG i = 0; i < g_State.Count; i++) {
        if (g_State.Pids[i] == pid) {
            // kompaktes Entfernen: letztes Element nach vorn ziehen
            g_State.Pids[i] = g_State.Pids[g_State.Count - 1];
            g_State.Count--;
            KeReleaseSpinLock(&g_State.Lock, irql);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&g_State.Lock, irql);
    return STATUS_NOT_FOUND;
}

BOOLEAN StateIsPidProtected(HANDLE pid)
{
    BOOLEAN found = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_State.Lock, &irql);
    for (ULONG i = 0; i < g_State.Count; i++) {
        if (g_State.Pids[i] == pid) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&g_State.Lock, irql);
    return found;
}

VOID StateClearAll(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_State.Lock, &irql);
    g_State.Count = 0;
    RtlZeroMemory(g_State.Pids, sizeof(g_State.Pids));
    KeReleaseSpinLock(&g_State.Lock, irql);
}