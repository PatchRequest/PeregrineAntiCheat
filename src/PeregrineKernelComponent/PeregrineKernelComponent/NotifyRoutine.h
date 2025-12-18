#pragma once
#include <ntddk.h>

VOID CreateProcessNotifyRoutineEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

NTSTATUS registerNotifyRoutine(void);
void unregisterNotifyRoutine(void);
