#include "obCallback.h"
#include "Coms.h"
#include <ntstrsafe.h>

PVOID callbackRegistrationHandle = NULL;



VOID unregisterRegistration(void) {
    if (callbackRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(callbackRegistrationHandle);
        callbackRegistrationHandle = NULL;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Unregistered callback\n");
    }
}


OB_PREOP_CALLBACK_STATUS CreateCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    PEPROCESS Process = (PEPROCESS)OperationInformation->Object;
    if (OperationInformation->KernelHandle || OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    // get pid
    HANDLE pid = PsGetProcessId(Process);
	// check if the pid matches the target pid
    if (!StateIsPidProtected(pid)) { return  OB_PREOP_SUCCESS; }

    HANDLE callerPID = PsGetCurrentProcessId();

    ACCESS_MASK desiredAccess = 0;
    const char* opName = "unknown";
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        opName = "create";
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        opName = "duplicate";
    }

    CHAR json[256];
    RtlStringCchPrintfA(
        json,
        ARRAYSIZE(json),
        "{ \"event\": \"ob_callback\", \"op\": \"%s\", \"target_pid\": %lu, \"caller_pid\": %lu, \"desired_access\": \"0x%08X\" }",
        opName,
        (ULONG)(ULONG_PTR)pid,
        (ULONG)(ULONG_PTR)callerPID,
        desiredAccess);

    // Fire-and-forget; best-effort notification to userland
    ComsSendToUser(json, (ULONG)strlen(json));

	// remove desired access rights
    //OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
    return OB_PREOP_SUCCESS;
}

NTSTATUS createRegistration() {
    OB_CALLBACK_REGISTRATION registrationInfo;
    OB_OPERATION_REGISTRATION operationInfo;
    NTSTATUS status;

    RtlZeroMemory(&registrationInfo, sizeof(registrationInfo));
    RtlZeroMemory(&operationInfo, sizeof(operationInfo));

    operationInfo.ObjectType = PsProcessType;
    operationInfo.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationInfo.PreOperation = CreateCallback;

    registrationInfo.Version = OB_FLT_REGISTRATION_VERSION;
    registrationInfo.OperationRegistrationCount = 1;
    registrationInfo.RegistrationContext = NULL;
    registrationInfo.OperationRegistration = &operationInfo;

    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"362249.1234");
    registrationInfo.Altitude = altitude;

    status = ObRegisterCallbacks(&registrationInfo, &callbackRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObRegisterCallbacks failed with status 0x%08X\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Registered callback successfully\n");
    return STATUS_SUCCESS;
}
