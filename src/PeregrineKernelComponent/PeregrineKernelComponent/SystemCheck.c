#include "SystemCheck.h"
#include "Coms.h"
#include <ntstrsafe.h>
#include <intrin.h>

// ============================================================
// ZwQuerySystemInformation for code integrity
// ============================================================

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

#define SystemCodeIntegrityInformationClass  103

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

// CodeIntegrityOptions flags
#define CODEINTEGRITY_OPTION_ENABLED                0x0001
#define CODEINTEGRITY_OPTION_TESTSIGN               0x0002
#define CODEINTEGRITY_OPTION_UMCI_ENABLED           0x0004
#define CODEINTEGRITY_OPTION_UMCI_AUDITMODE         0x0008
#define CODEINTEGRITY_OPTION_FLIGHTING_ENABLED      0x0010
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED      0x0400
#define CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE    0x0800
#define CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED       0x1000

// ============================================================
// Test-Sign Detection
// ============================================================

static void CheckTestSigning(void) {
    SYSTEM_CODEINTEGRITY_INFORMATION ci = { 0 };
    ci.Length = sizeof(ci);

    NTSTATUS status = ZwQuerySystemInformation(
        SystemCodeIntegrityInformationClass,
        &ci,
        sizeof(ci),
        NULL);

    CHAR json[COMS_MAX_MESSAGE_SIZE];

    if (!NT_SUCCESS(status)) {
        RtlStringCchPrintfA(json, ARRAYSIZE(json),
            "{ \"event\": \"system_check\", \"check\": \"test_sign\", \"error\": \"query failed 0x%08X\" }",
            status);
        ComsSendToUser(json, (ULONG)strlen(json));
        return;
    }

    BOOLEAN testSigning = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN) != 0;
    BOOLEAN ciEnabled = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) != 0;

    RtlStringCchPrintfA(json, ARRAYSIZE(json),
        "{ \"event\": \"system_check\", \"check\": \"test_sign\", "
        "\"test_signing\": %s, \"code_integrity_enabled\": %s, "
        "\"raw_flags\": \"0x%08X\" }",
        testSigning ? "true" : "false",
        ciEnabled ? "true" : "false",
        ci.CodeIntegrityOptions);

    ComsSendToUser(json, (ULONG)strlen(json));
    KdPrint(("Peregrine: TestSign=%d CI=%d flags=0x%X\n", testSigning, ciEnabled, ci.CodeIntegrityOptions));
}

// ============================================================
// HVCI Disabled Detection
// ============================================================

static void CheckHVCI(void) {
    SYSTEM_CODEINTEGRITY_INFORMATION ci = { 0 };
    ci.Length = sizeof(ci);

    NTSTATUS status = ZwQuerySystemInformation(
        SystemCodeIntegrityInformationClass,
        &ci,
        sizeof(ci),
        NULL);

    CHAR json[COMS_MAX_MESSAGE_SIZE];

    if (!NT_SUCCESS(status)) {
        RtlStringCchPrintfA(json, ARRAYSIZE(json),
            "{ \"event\": \"system_check\", \"check\": \"hvci\", \"error\": \"query failed 0x%08X\" }",
            status);
        ComsSendToUser(json, (ULONG)strlen(json));
        return;
    }

    BOOLEAN hvciEnabled = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0;
    BOOLEAN hvciAudit = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE) != 0;
    BOOLEAN hvciIum = (ci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED) != 0;

    RtlStringCchPrintfA(json, ARRAYSIZE(json),
        "{ \"event\": \"system_check\", \"check\": \"hvci\", "
        "\"hvci_enabled\": %s, \"hvci_audit_mode\": %s, \"hvci_ium\": %s }",
        hvciEnabled ? "true" : "false",
        hvciAudit ? "true" : "false",
        hvciIum ? "true" : "false");

    ComsSendToUser(json, (ULONG)strlen(json));
    KdPrint(("Peregrine: HVCI=%d Audit=%d IUM=%d\n", hvciEnabled, hvciAudit, hvciIum));
}

// ============================================================
// CPU Vendor / Hypervisor Detection
// ============================================================

static void CheckCPUVendor(void) {
    int regs[4] = { 0 };
    char vendor[13] = { 0 };

    // CPUID leaf 0: vendor string
    __cpuid(regs, 0);
    *(int*)(vendor + 0) = regs[1]; // EBX
    *(int*)(vendor + 4) = regs[3]; // EDX
    *(int*)(vendor + 8) = regs[2]; // ECX
    vendor[12] = '\0';

    // CPUID leaf 1: feature flags, ECX bit 31 = hypervisor present
    __cpuid(regs, 1);
    BOOLEAN hypervisorPresent = (regs[2] & (1 << 31)) != 0;

    char hvVendor[13] = { 0 };
    if (hypervisorPresent) {
        // CPUID leaf 0x40000000: hypervisor vendor
        __cpuid(regs, 0x40000000);
        *(int*)(hvVendor + 0) = regs[1]; // EBX
        *(int*)(hvVendor + 4) = regs[2]; // ECX
        *(int*)(hvVendor + 8) = regs[3]; // EDX
        hvVendor[12] = '\0';
    }

    CHAR json[COMS_MAX_MESSAGE_SIZE];
    RtlStringCchPrintfA(json, ARRAYSIZE(json),
        "{ \"event\": \"system_check\", \"check\": \"cpu_vendor\", "
        "\"cpu_vendor\": \"%s\", \"hypervisor_present\": %s, "
        "\"hypervisor_vendor\": \"%s\" }",
        vendor,
        hypervisorPresent ? "true" : "false",
        hypervisorPresent ? hvVendor : "none");

    ComsSendToUser(json, (ULONG)strlen(json));
    KdPrint(("Peregrine: CPU=%s HV=%d HVVendor=%s\n", vendor, hypervisorPresent, hvVendor));
}

// ============================================================
// Run all checks
// ============================================================

NTSTATUS SystemCheckRunAll(void) {
    KdPrint(("Peregrine: SystemCheck starting\n"));

    CheckTestSigning();
    CheckHVCI();
    CheckCPUVendor();

    CHAR json[COMS_MAX_MESSAGE_SIZE];
    RtlStringCchPrintfA(json, ARRAYSIZE(json),
        "{ \"event\": \"system_check_complete\" }");
    ComsSendToUser(json, (ULONG)strlen(json));

    KdPrint(("Peregrine: SystemCheck complete\n"));
    return STATUS_SUCCESS;
}
