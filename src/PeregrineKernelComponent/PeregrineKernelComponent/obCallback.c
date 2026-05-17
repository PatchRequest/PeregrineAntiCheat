#include "obCallback.h"
#include "Coms.h"
#include <ntstrsafe.h>

PVOID callbackRegistrationHandle = NULL;

/* Dangerous access flags worth reporting (OpenEDR-inspired).
   VM_READ is excluded — too noisy, most tools need it for queries. */
#define DANGEROUS_PROCESS_ACCESS ( \
    0x0001 /* PROCESS_TERMINATE */       | \
    0x0002 /* PROCESS_CREATE_THREAD */   | \
    0x0008 /* PROCESS_VM_OPERATION */    | \
    0x0020 /* PROCESS_VM_WRITE */        | \
    0x0040 /* PROCESS_DUP_HANDLE */      | \
    0x0200 /* PROCESS_SET_INFORMATION */ | \
    0x0800 /* PROCESS_SUSPEND_RESUME */ )

VOID unregisterRegistration(void) {
    if (callbackRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(callbackRegistrationHandle);
        callbackRegistrationHandle = NULL;
    }
}

OB_PREOP_CALLBACK_STATUS CreateCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    /* 1. Kernel handles — always skip (OpenEDR, HazardShield, all do this) */
    if (OperationInformation->KernelHandle)
        return OB_PREOP_SUCCESS;

    if (OperationInformation->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;

    PEPROCESS targetProc = (PEPROCESS)OperationInformation->Object;
    if (targetProc == NULL)
        return OB_PREOP_SUCCESS;

    HANDLE targetPid = PsGetProcessId(targetProc);

    /* 2. Only care about protected targets */
    if (!StateIsPidProtected(targetPid))
        return OB_PREOP_SUCCESS;

    HANDLE callerPid = PsGetCurrentProcessId();

    /* 3. Self-access — always skip */
    if (callerPid == targetPid)
        return OB_PREOP_SUCCESS;

    /* 4. Caller is also protected (our own AC components) — skip */
    if (StateIsPidProtected(callerPid))
        return OB_PREOP_SUCCESS;

    /* 5. Extract desired access */
    ACCESS_MASK desiredAccess = 0;
    const char* opName = "unknown";
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        opName = "create";
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        opName = "duplicate";
    } else {
        return OB_PREOP_SUCCESS;
    }

    /* 6. Only report dangerous access — skip harmless queries
       (SYNCHRONIZE, QUERY_LIMITED_INFORMATION, QUERY_INFORMATION) */
    if (!(desiredAccess & DANGEROUS_PROCESS_ACCESS))
        return OB_PREOP_SUCCESS;

    /* 7. Report to userland */
    CHAR json[256];
    RtlStringCchPrintfA(
        json, ARRAYSIZE(json),
        "{ \"event\": \"ob_callback\", \"op\": \"%s\", \"target_pid\": %lu, "
        "\"caller_pid\": %lu, \"desired_access\": \"0x%08X\" }",
        opName,
        (ULONG)(ULONG_PTR)targetPid,
        (ULONG)(ULONG_PTR)callerPid,
        desiredAccess);

    ComsSendToUser(json, (ULONG)strlen(json));
    return OB_PREOP_SUCCESS;
}

NTSTATUS createRegistration() {
    OB_CALLBACK_REGISTRATION registrationInfo;
    OB_OPERATION_REGISTRATION operationInfo;

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

    NTSTATUS status = ObRegisterCallbacks(&registrationInfo, &callbackRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "ObRegisterCallbacks failed 0x%08X\n", status);
    }
    return status;
}
