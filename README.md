
# Peregrine Anti-Cheat

An educational anti-cheat system demonstrating Windows kernel programming, process monitoring, and cheat detection.

<p align="center">
  <img src="logo.png" alt="Peregrine Logo" width="400">
</p>

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Tauri GUI (Rust + Svelte)                                  │
│  peregrine-tauri.exe                                        │
│  ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌──────────────┐   │
│  │ Driver   │ │ IPC Pipe │ │ Detection │ │ ETW-TI       │   │
│  │ Polling  │ │ Server   │ │ Scans     │ │ Consumer     │   │
│  └────┬─────┘ └────┬─────┘ └───────────┘ └──────────────┘   │
│       │IOCTL       │Named Pipe                PPL+ETW       │
├───────┼────────────┼────────────────────────────────────────┤
│       ▼            ▼                                        │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Kernel Driver (Minifilter)                         │    │
│  │  PeregrineKernelComponent.sys                       │    │
│  │  • ObCallback (handle monitoring)                   │    │
│  │  • Process/Thread/Image notify routines             │    │
│  │  • APC DLL injection (shellcode + LdrLoadDll)       │    │
│  │  • PPL elevation (EPROCESS patch)                   │    │
│  │  • Minifilter (file access monitoring)              │    │
│  │  • Driver/ObCallback scanning                       │    │
│  │  • HWID collection (disk serial, boot GUID)         │    │
│  └─────────┬───────────────────────────────────────────┘    │
│            │ APC Injection                                  │
│            ▼                                                │
│  ┌──────────────────────┐      ┌─────────────────────┐      │
│  │  PeregrineDLL        │      │  Target Process     │      │
│  │  (injected into      │─────▶│  (game / cheat)     │      │
│  │   target processes)  │ IPC  │                     │      │
│  │  • MinHook API hooks │pipe  │  APIs hooked:       │      │
│  │  • RPM/WPM/NtR/NtW   │      │  ReadProcessMemory  │      │
│  │  • VirtualAlloc/Prot │      │  WriteProcessMemory │      │
│  │  • CreateRemoteThread│      │  VirtualAllocEx ... │      │
│  │  • OpenProcess       │      │                     │      │
│  └──────────────────────┘      └─────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

| Component | Language | Role |
|-----------|----------|------|
| **Kernel Driver** | C (Minifilter) | Ring-0: ObCallbacks, APC injection, PPL, notify routines, file access monitoring, driver scanning, HWID collection |
| **Injection DLL** | C++ (MinHook) | Injected into targets: hooks WinAPI calls, reports via named pipe IPC |
| **Tauri GUI** | Rust + Svelte | Userland: IOCTL commands, IPC receiver, detection scans, ETW-TI consumer, HWID fingerprinting, dark-themed UI |

**Communication flows:**
- **GUI ↔ Driver**: IOCTL commands (add PIDs, configure injection, trigger scans) + event polling
- **DLL → GUI**: Named pipe `\\.\pipe\peregrine_ipc` (hook events, hello message)
- **Driver → DLL**: APC injection at kernel32.dll load time (autonomous, no userland roundtrip)
- **GUI → ETW**: PPL-protected trace session consuming kernel Threat Intelligence events

## Detection Capabilities

| # | Detection | Technique |
|---|-----------|-----------|
| 1 | **Module Integrity** | `.text` section SHA-256: disk vs memory, relocation-aware |
| 2 | **IAT/EAT Hook Detection** | PE import/export table scanning for entries outside known modules |
| 3 | **External Memory Access** | DLL hooks on RPM/WPM/NtRead/NtWrite/VirtualAllocEx/VirtualProtectEx/CreateRemoteThread/OpenProcess |
| 4 | **Thread & Shellcode Detection** | RIP + Win32 start address checked against loaded module ranges |
| 5 | **Handle Access Monitoring** | Kernel ObCallback on handle create/duplicate with dangerous access flags |
| 6 | **Process Blacklist** | Keyword scan against running process paths |
| 7 | **Driver Blacklist** | Ring-0 enumeration of loaded kernel drivers |
| 8 | **ObCallback Enumeration** | Ring-0 scan of registered object callbacks |
| 9 | **Manual-Map Detection** | VAD walking for executable regions without backing modules |
| 10 | **Overlay Detection** | EnumWindows for layered/transparent/topmost fullscreen windows |
| 11 | **System Integrity** | Test-signing, HVCI, CPU vendor/hypervisor detection |
| 12 | **ETW Threat Intelligence** | PPL-protected consumer for ALLOCVM/PROTECTVM/MAPVIEW/QUEUEAPC/SETTHREADCONTEXT/READVM/WRITEVM remote events |
| 13 | **File Access Monitoring** | Minifilter reports write/delete/rename on protected AC files |
| 14 | **HWID Collection** | Hybrid kernel+userland hardware fingerprinting (disk serials, boot GUID, MAC, SMBIOS UUID, volume serials, registry IDs) |

## Kernel APC DLL Injection

The driver autonomously injects DLLs via kernel APC queuing:
1. Userland configures target process names + DLL paths via IOCTL
2. Driver matches image names on process creation
3. At `kernel32.dll` load time, resolves `LdrLoadDll` from ntdll exports
4. Writes shellcode + UNICODE_STRING into target, queues user-mode APC
5. Supports x64 native + x86 WoW64 (`PsWrapApcWow64Thread`)

## Building

```batch
build_dll.bat                     # builds DLLs + driver, copies to C:\Peregrine\
cd src\peregrine-tauri && npx tauri build   # builds Tauri GUI (~9 MB)
```

**Requirements:** Windows 10/11 x64, VS2022 + WDK, Rust 1.70+, Node.js 18+, test signing enabled

## Usage

```
sc.exe create Peregrine type= kernel binPath= "C:\Peregrine\PeregrineKernelComponent.sys"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Peregrine\Instances" /v "DefaultInstance" /d "Peregrine Instance" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Peregrine\Instances\Peregrine Instance" /v "Altitude" /d "370030" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Peregrine\Instances\Peregrine Instance" /v "Flags" /t REG_DWORD /d 0 /f
sc.exe start Peregrine
C:\Peregrine\peregrine-tauri.exe
```

## Test Suite

Purpose-built cheats in `test/` that showcase every detection layer:

| Cheat | Technique | Detected by |
|-------|-----------|-------------|
| `cheat.exe <PID> <addr>` | RPM/WPM every 5s | DLL Hooks, ETW-TI (`WRITEVM_REMOTE`), ObCallback |
| `cheat_inject.exe <PID> payload.dll` | CreateRemoteThread + LoadLibrary | ObCallback, DLL Hooks, ETW-TI (`ALLOCVM_REMOTE`) |
| `cheat_shellcode.exe <PID>` | VirtualAllocEx RWX + remote thread | ObCallback, ETW-TI (`PROTECTVM_REMOTE`), Thread Scan (start addr outside modules) |
| `cheat_patch.exe <PID>` | NOP bytes in kernel32 .text | Module Integrity (`[tamper]`), ETW-TI (`WRITEVM_REMOTE`) |
| `CheatEngine.exe` | Just existing | Blacklist Scan |

Start `game.exe` first — it prints its PID and a health variable address for the cheats to target.

## Components

```
src/
├── PeregrineKernelComponent/    # Kernel minifilter driver (ring-0)
├── PeregrineDLL/                # Injected API hook DLL (x86 + x64)
└── peregrine-tauri/             # Rust/Tauri desktop GUI
test/                            # Cheat test tools (game.exe, cheat_*.exe)
```

## Blog Posts

This project has an accompanying blog series on [patchi.fyi](https://patchi.fyi):

- [Anatomy of an Anti-Cheat](https://patchi.fyi/blog/peregrine-anatomy-of-an-anticheat/)
- [ObCallbacks](https://patchi.fyi/blog/peregrine-obcallbacks/)
- [Kernel APC Injection](https://patchi.fyi/blog/peregrine-kernel-apc-injection/)
- [MinHook API Interception](https://patchi.fyi/blog/peregrine-minhook-api-interception/)
- [Relocation-Aware Hashing](https://patchi.fyi/blog/peregrine-relocation-aware-hashing/)
- [IAT/EAT Scanning](https://patchi.fyi/blog/peregrine-iat-eat-scanning/)
- [Shellcode Thread Analysis](https://patchi.fyi/blog/peregrine-shellcode-thread-analysis/)
- [PPL ETW Threat Intelligence](https://patchi.fyi/blog/peregrine-ppl-etw-threat-intelligence/)
- [Minifilter Self-Defense](https://patchi.fyi/blog/peregrine-minifilter-self-defense/)
- [Kernel Scanning](https://patchi.fyi/blog/peregrine-kernel-scanning/)

## Disclaimer

**Strictly for educational purposes.** Use only in controlled environments with proper authorization.
