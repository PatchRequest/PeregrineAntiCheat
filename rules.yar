// Peregrine YARA Rules
// Place next to peregrine-tauri.exe or in C:\Peregrine\

rule CheatEngine {
    meta:
        description = "Cheat Engine process strings"
        severity = "high"
    strings:
        $ce1 = "CheatEngine" ascii
        $ce2 = "cheatengine" ascii nocase
        $ce3 = "DBVM Driver" ascii
        $ce4 = "Cheat Engine" wide
    condition:
        any of them
}

rule ManualMapShellcode {
    meta:
        description = "Sleep-loop shellcode from cheat_manualmap test"
        severity = "critical"
    strings:
        $shell = { 48 83 EC 28 B9 E8 03 00 00 FF 15 02 00 00 00 EB F3 }
    condition:
        $shell
}

rule GenericSleepLoopShellcode {
    meta:
        description = "Generic sleep-loop shellcode pattern"
        severity = "high"
    strings:
        $loop = { 48 83 EC 28 B9 ?? ?? 00 00 FF 15 ?? 00 00 00 EB }
    condition:
        $loop
}

rule SuspiciousAPIHashing {
    meta:
        description = "Common API hashing routines used by shellcode"
        severity = "high"
    strings:
        // ROR13 hash loop (classic shellcode API resolution)
        $ror13 = { C1 C? 0D 03 C? }
        // CRC32-based API resolution
        $crc32 = { F2 0F 38 F1 }
    condition:
        any of them
}

rule InjectionStrings {
    meta:
        description = "Common injection-related API strings in suspicious memory"
        severity = "medium"
    strings:
        $s1 = "VirtualAllocEx" ascii
        $s2 = "WriteProcessMemory" ascii
        $s3 = "CreateRemoteThread" ascii
        $s4 = "NtMapViewOfSection" ascii
        $s5 = "RtlCreateUserThread" ascii
        $s6 = "LdrLoadDll" ascii
    condition:
        3 of them
}

rule AntiDebugStrings {
    meta:
        description = "Anti-debug evasion strings"
        severity = "medium"
    strings:
        $s1 = "IsDebuggerPresent" ascii
        $s2 = "NtQueryInformationProcess" ascii
        $s3 = "CheckRemoteDebuggerPresent" ascii
        $s4 = "OutputDebugString" ascii
    condition:
        3 of them
}

rule SuspiciousDriverNames {
    meta:
        description = "Known exploit/cheat driver name strings"
        severity = "critical"
    strings:
        $d1 = "dbk64.sys" ascii nocase
        $d2 = "kdmapper" ascii nocase
        $d3 = "capcom.sys" ascii nocase
        $d4 = "iqvw64e.sys" ascii nocase
        $d5 = "gdrv.sys" ascii nocase
        $d6 = "winring0" ascii nocase
    condition:
        any of them
}

rule PEHeaderInPrivateMemory {
    meta:
        description = "PE header found (potential manual-mapped DLL)"
        severity = "critical"
    strings:
        $mz = "MZ"
        $pe = "PE\x00\x00"
    condition:
        $mz at 0 and $pe
}
