#include <ntddk.h>
#include "Coms.h"
#include "obCallback.h"
#include "NotifyRoutine.h"
#include "AppState.h"

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    unregisterNotifyRoutine();
    unregisterRegistration();
    ComsCleanup();
    KdPrint(("Peregrine: Unload called\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    KdPrint(("Peregrine: DriverEntry called\n"));
    
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

	StateInit();

   

    return STATUS_SUCCESS;
}
