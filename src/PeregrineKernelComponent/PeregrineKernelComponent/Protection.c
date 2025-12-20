#include "Protection.h"

// Declare PsLookupProcessByProcessId (documented kernel function)
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS *Process
);

// PS_PROTECTION structure (undocumented)
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        } Flags;
    } u;
} PS_PROTECTION, *PPS_PROTECTION;

// Protection levels
#define PsProtectedTypeProtectedLight   1
#define PsProtectedSignerAntimalware    6

// Offset to PS_PROTECTION in EPROCESS (varies by Windows version)
// For Windows 10/11 x64, typically around 0x87A
// This will need adjustment based on your Windows version
static ULONG g_ProtectionOffset = 0;

// Function to find the protection offset dynamically
static NTSTATUS FindProtectionOffset(void) {
    // Common offsets for different Windows versions (x64)
    // Windows 10 1809-1903: 0x6CA
    // Windows 10 1909-2004: 0x87A
    // Windows 10 21H1+: 0x87A
    // Windows 11: 0x87A

    // For now, use a common offset (Windows 10 2004+)
    // In production, you'd scan for this or use version detection
    g_ProtectionOffset = 0x87A;

    KdPrint(("Peregrine: Using PS_PROTECTION offset 0x%X\n", g_ProtectionOffset));
    return STATUS_SUCCESS;
}

NTSTATUS ProtectionSetProcessPPL(_In_ HANDLE ProcessId) {
    NTSTATUS status;
    PEPROCESS process = NULL;

    KdPrint(("Peregrine: ProtectionSetProcessPPL called for PID %lu\n", (ULONG)(ULONG_PTR)ProcessId));

    // Find offset if not initialized
    if (g_ProtectionOffset == 0) {
        status = FindProtectionOffset();
        if (!NT_SUCCESS(status)) {
            KdPrint(("Peregrine: Failed to find protection offset\n"));
            return status;
        }
    }

    // Get EPROCESS structure for the target process
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: PsLookupProcessByProcessId failed for PID %lu: 0x%X\n",
                 (ULONG)(ULONG_PTR)ProcessId, status));
        return status;
    }

    // Calculate pointer to PS_PROTECTION field
    PPS_PROTECTION protection = (PPS_PROTECTION)((PUCHAR)process + g_ProtectionOffset);

    // Set protection level to PPL with Antimalware signer
    PS_PROTECTION newProtection = { 0 };
    newProtection.u.Flags.Type = PsProtectedTypeProtectedLight;
    newProtection.u.Flags.Signer = PsProtectedSignerAntimalware;
    newProtection.u.Flags.Audit = 0;

    // Apply protection
    __try {
        protection->u.Level = newProtection.u.Level;
        KdPrint(("Peregrine: Set PID %lu to PPL (Type=%d, Signer=%d)\n",
                 (ULONG)(ULONG_PTR)ProcessId,
                 (int)newProtection.u.Flags.Type,
                 (int)newProtection.u.Flags.Signer));
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("Peregrine: Exception while setting PPL for PID %lu\n",
                 (ULONG)(ULONG_PTR)ProcessId));
        status = STATUS_ACCESS_VIOLATION;
    }

    // Dereference the process object
    ObDereferenceObject(process);

    return status;
}
