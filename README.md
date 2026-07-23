
# Peregrine Anti-Cheat

An educational anti-cheat system demonstrating Windows kernel programming, process monitoring, and cheat detection.

<p align="center">
  <img src="logo.png" alt="Peregrine Logo" width="400">
</p>

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Tauri GUI (Rust + Svelte)                                  │
│  peregrine-tauri.exe  (run elevated)                        │
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
│  │  • Thread/Image notify (protected PIDs)             │    │
│  │  • APC DLL injection + auto StateAddPid             │    │
│  │  • PPL elevation (EPROCESS patch)                   │    │
│  │  • Minifilter (report + deny AC file tamper)        │    │
│  │  • Driver/ObCallback scanning                       │    │
│  │  • HWID collection (disk serial, boot GUID)         │    │
│  │  • VAD scan (executable private memory)             │    │
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
│  │  • HWBP / VEH watch  │      │                     │      │
│  └──────────────────────┘      └─────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

| Component | Language | Role |
|-----------|----------|------|
| **Kernel Driver** | C (Minifilter) | Ring-0: ObCallbacks, APC injection, PPL, notify routines, file defense, driver scanning, HWID, VAD |
| **Injection DLL** | C++ (MinHook) | Injected into targets: hooks WinAPI, HWBP/VEH, reports via named pipe IPC |
| **Tauri GUI** | Rust + Svelte | Userland: IOCTL commands, IPC receiver, detection scans, ETW-TI consumer, HWID, dark UI |

**Communication flows:**
- **GUI ↔ Driver**: IOCTL commands (PIDs, injection config, scans) + event polling
- **DLL → GUI**: Named pipe `\\.\pipe\peregrine_ipc` (hook events, `hello`, HWBP)
- **Driver → target**: APC injection at `kernel32.dll` load (no userland roundtrip); on success the kernel auto-protects the PID
- **GUI → ETW**: PPL-protected trace session for Threat Intelligence events

## Detection Capabilities

| # | Detection | Technique |
|---|-----------|-----------|
| 1 | **Module Integrity** | `.text` section SHA-256: disk vs memory, relocation-aware |
| 2 | **IAT/EAT Hook Detection** | PE import/export table scanning for entries outside known modules |
| 3 | **External Memory Access** | DLL hooks on RPM/WPM/NtRead/NtWrite/VirtualAllocEx/VirtualProtectEx/CreateRemoteThread/OpenProcess |
| 3b | **Call Stack Validation** | `RtlCaptureStackBackTrace` on hooked APIs — flags callers in `MEM_PRIVATE` executable memory |
| 4 | **Thread & Shellcode Detection** | Kernel `thread_create` (start address) + userland scan: suspend → `GetThreadContext` → RIP/start vs modules |
| 5 | **Handle Access Monitoring** | Kernel ObCallback on handle create/duplicate with dangerous access flags |
| 6 | **Process Blacklist** | Keyword scan against running process paths |
| 7 | **Driver Blacklist** | Ring-0 enumeration of loaded kernel drivers |
| 8 | **ObCallback Enumeration** | Ring-0 scan of registered object callbacks |
| 9 | **Manual-Map / VAD** | Kernel `ZwQueryVirtualMemory` walk — executable private regions |
| 10 | **Overlay Detection** | `EnumWindows` for layered / transparent / topmost+near-fullscreen windows |
| 11 | **System Integrity** | Test-signing, HVCI, CPU vendor/hypervisor detection |
| 12 | **ETW Threat Intelligence** | PPL consumer for remote ALLOCVM/PROTECTVM/MAPVIEW/QUEUEAPC/SETTHREADCONTEXT/READVM/WRITEVM |
| 13 | **File Self-Defense** | Minifilter reports **and denies** write/delete/rename on AC artifacts under `\peregrine\` |
| 14 | **HWID Collection** | Hybrid kernel+userland fingerprinting |
| 15 | **YARA Memory Scanning** | yara-x over process address space (`rules.yar`) |
| 16 | **HWBP / VEH Protection** | DLL arms DR0 on VEH list; watchdog re-arms cleared DRs |

## Kernel APC DLL Injection

OpenEDR-style user-mode APC (no private shellcode):

1. GUI sets DLL paths (`PeregrineDLL_x64.dll` / `PeregrineDLL_x86.dll`) and target names via IOCTL  
2. Driver matches on process create; when `kernel32.dll` maps, queues a user APC with:
   - `NormalRoutine` = `KernelBase!LoadLibraryExW` (real export — not the `kernel32` IAT thunk, which is unbound mid-map)
   - `NormalContext` = full wide path in target VA (`PAGE_READWRITE` only)
   - `SystemArgument1` = `NULL`, `SystemArgument2` = load flags (`0` for absolute paths under `C:\Peregrine\`)
3. **No `KeTestAlertThread`** — APC is delivered by the loader’s later `NtTestAlert` after static imports are initialized (forcing delivery in `LoadImageNotify` crashes the process)
4. Path buffer is freed on process exit (never freed mid-load)  
5. On inject **success**, kernel calls `StateAddPid` so ObCallback / thread / image notifies apply immediately  
6. x64 + x86 WoW64 (`PsWrapApcWow64Thread` in the APC kernel routine)

Approach adapted from [OpenEDR](https://github.com/ComodoSecurity/openedr) injectengine (`apcinjector` / `apcqueue`). No RX inject staging (path buffer is RW only).

**VAD after inject:** A VAD scan on an injected game may still report a small private `EXECUTE_READWRITE` region. That is expected **MinHook trampoline** noise from `PeregrineDLL` (hooks need a short writable-exec stub), not the old inject shellcode page. The inject path itself no longer allocates executable staging.

**IOCTL notes:** command `14` clears injection targets and disables injection (not just disable).

## Security model (educational)

| Surface | Policy |
|---------|--------|
| Device `\\.\Peregrine` | `IoCreateDeviceSecure` — **SYSTEM + Administrators** only |
| IPC pipe | SYSTEM + Administrators full; **Authenticated Users** write (injected medium-IL games can still send events). Not world-writable. |
| GUI | Must run **elevated** |
| Kernel JSON | Paths escaped in-kernel (`JsonEscapeString`); no userland `\` massaging |

## Building

```batch
build_dll.bat                     # DLLs + driver → src\Userland\ and C:\Peregrine\
cd src\peregrine-tauri && npx tauri build
```

**Requirements:** Windows 10/11 x64, VS2022 + WDK, Rust 1.70+, Node.js 18+, test signing enabled

**Deploy layout (typical VM):**
```
C:\Peregrine\
  PeregrineKernelComponent.sys
  PeregrineDLL_x64.dll
  PeregrineDLL_x86.dll
  peregrine-tauri.exe
  rules.yar
```

## Usage

```
sc.exe create Peregrine type= kernel binPath= "C:\Peregrine\PeregrineKernelComponent.sys"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Peregrine\Instances" /v "DefaultInstance" /d "Peregrine Instance" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Peregrine\Instances\Peregrine Instance" /v "Altitude" /d "370030" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Peregrine\Instances\Peregrine Instance" /v "Flags" /t REG_DWORD /d 0 /f
sc.exe start Peregrine
C:\Peregrine\peregrine-tauri.exe
```

1. Connect (auto-finds DLLs under `C:\Peregrine` or next to the EXE)  
2. Add injection target e.g. `game.exe` → start the game → expect `apc_inject` + `[ok] DLL injected…`  
3. Game PID is protected without a manual Add PID  
4. Run cheats / scans (Threads, VAD, Overlay, ETW-TI, …)

## Test Suite

Purpose-built tools in `test/`:

| Cheat | Technique | Detected by |
|-------|-----------|-------------|
| `cheat.exe <PID> <addr>` | RPM/WPM | DLL hooks, ETW-TI, ObCallback |
| `cheat_inject.exe <PID> payload.dll` | Remote LoadLibrary | ObCallback, hooks, ETW-TI |
| `cheat_shellcode.exe <PID>` | RWX private + remote thread (CFG-safe spin loop) | Thread scan, VAD, ETW-TI, ObCallback |
| `cheat_patch.exe <PID>` | NOP in kernel32 `.text` | Module integrity, ETW-TI |
| `cheat_manualmap.exe <PID>` | Private exec ± PE header | VAD |
| `cheat_yara.exe <PID>` | Marker strings / blob | YARA |
| `cheat_callstack.exe <PID>` | OpenProcess from private RWX | Callstack anomaly |
| `CheatEngine.exe` | Exists | Blacklist |

Start `game.exe` first — it prints PID and a health address.

**Note:** Older shellcode demos that `call Sleep` from private memory can **CFG FastFail** the whole target process. The current `cheat_shellcode` uses a no-API spin loop so the game stays alive for Thread/VAD checks.

## Components

```
src/
├── PeregrineKernelComponent/    # Kernel minifilter driver (ring-0)
├── PeregrineDLL/                # Injected API hook DLL (x86 + x64)
└── peregrine-tauri/             # Rust/Tauri desktop GUI
test/                            # Cheat test tools
```

## Blog Posts

Accompanying series on [patchi.fyi](https://patchi.fyi):

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
