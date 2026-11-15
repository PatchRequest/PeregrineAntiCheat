#include <fltKernel.h>
#include "Coms.h"
#include "obCallback.h"
#include "NotifyRoutine.h"
#include "AppState.h"
#include "ApcInjection.h"
#include "MiniFilter.h"
#include "DriverScan.h"
#include "ObCallbackScan.h"
#include "SystemCheck.h"

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    MfCleanup();
    unregisterNotifyRoutine();
    /* No new inject APC can be queued now; wait for the ones in flight. */
    InjWaitForApcs();
    unregisterRegistration();
    ComsCleanup();
    KdPrint(("Peregrine: Unload called\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    KdPrint(("Peregrine: DriverEntry called\n"));

    /* State first: every callback registered below may fire immediately and
       reads these tables. */
    StateInit();
    InjInit();

    NTSTATUS status = ComsInitialize(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: ComsInitialize failed 0x%X\n", status));
        return status;
    }

    status = createRegistration();
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: createRegistration failed 0x%X\n", status));
        ComsCleanup();
        return status;
    }

    status = registerNotifyRoutine();
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: registerNotifyRoutine failed 0x%X\n", status));
        unregisterRegistration();
        ComsCleanup();
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;

    status = MfInit(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: MfInit failed 0x%X (minifilter disabled, rest OK)\n", status));
    }

    return STATUS_SUCCESS;
}
