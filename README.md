

# Peregrine Anti-Cheat

An educational anti-cheat system for learning Windows kernel programming, process monitoring, and cheat detection techniques.

<p align="center">
  <img src="logo.png" alt="Peregrine Logo" width="400">
</p>

## Overview

Peregrine is a learning-focused anti-cheat project that demonstrates core concepts in game security and Windows internals. This project implements both kernel-mode and user-mode components to detect common cheating techniques used in games.

## Architecture

### Kernel Component
The kernel driver (`PeregrineKernelComponent`) operates at ring-0 and provides:
- **ObCallback Registration**: Process and thread handle operation monitoring
- **Notify Routines**: Process, thread, and image load notifications
- **IOCTL Communications**: Bidirectional kernel-user communication channel
- **Process Protection**: Protected Process Light (PPL) enforcement
- **Driver Scanning**: Enumerates loaded kernel drivers and checks against a blacklist
- **ObCallback Scanning**: Enumerates registered object callbacks to detect tampering
- **System Integrity Checks**: Test-signing, HVCI, and CPU/hypervisor detection
- **APC DLL Injection**: Kernel-mode APC-based DLL injection into target processes at kernel32.dll load time — no user-mode CreateRemoteThread needed

### User-Mode Components
- **DLL Component** (`PeregrineDLL`): Injected into protected processes for in-process API hook monitoring (x86 + x64)
- **Rust/Tauri GUI** (`peregrine-tauri`): Native desktop app with dark-themed real-time monitoring, detection scans, and injection control
- **Legacy Python GUI** (`src/Userland/`): Original Python/Tkinter interface (still functional)

## Detection Capabilities

### Current Detections
1. **Module Integrity Checking**
   - Compares `.text` section hashes of in-memory modules against on-disk originals
   - Handles PE base relocations to avoid false positives from ASLR
   - Handles WoW64 path redirection for 32-bit processes on 64-bit Windows
   - Detects runtime code patches, inline hooks, and trampolines

2. **IAT & EAT Hook Detection**
   - Scans Import Address Tables for entries pointing outside known modules
   - Scans Export Address Tables for tampered function RVAs
   - Full PE parsing from process memory with forwarder handling

3. **External Memory Access Detection**
   - Hooks `ReadProcessMemory` and `WriteProcessMemory` (kernel32/kernelbase)
   - Hooks `NtReadVirtualMemory` and `NtWriteVirtualMemory` (ntdll)
   - Hooks `VirtualAllocEx` and `VirtualProtectEx` (remote memory manipulation)
   - Hooks `CreateRemoteThread` (remote code execution)
   - Hooks `OpenProcess` (handle acquisition with dangerous access flags)
   - Filters out harmless query-only access to reduce noise

4. **Thread & Shellcode Detection**
   - Detects thread execution originating outside trusted modules
   - Enumerates all threads and checks instruction pointers (RIP) against module ranges
   - Identifies shellcode execution in non-module memory regions

5. **Handle Access Monitoring**
   - Kernel ObCallback intercepts handle creation/duplication to protected processes
   - Logs dangerous access flags (VM_READ, VM_WRITE, CREATE_THREAD, TERMINATE, etc.)

6. **Process Blacklist Scanning**
   - Enumerates all running processes and checks against a keyword blacklist
   - Detects known cheat tools: CheatEngine, x64dbg, IDA, ProcessHacker, etc.

7. **Driver Blacklist Scanning**
   - Enumerates all loaded kernel drivers from ring-0
   - Checks against a blacklist of known cheat/bypass drivers

8. **ObCallback Enumeration**
   - Scans registered object callbacks from ring-0
   - Identifies which drivers have registered process/thread handle callbacks

## Kernel APC DLL Injection

The driver performs autonomous DLL injection via kernel APC queuing:
- Userland configures target process names and DLL paths via IOCTL
- On process creation, the driver matches the image name against targets
- When `kernel32.dll` loads in the target (loader is initialized), the driver:
  - Resolves `LdrLoadDll` by parsing ntdll's export table from kernel mode
  - Allocates RWX memory and writes position-independent shellcode + DLL path
  - Queues a user-mode APC with `KeInitializeApc` / `KeInsertQueueApc`
  - Forces delivery via `KeTestAlertThread(UserMode)`
- Supports both x64 native and x86 WoW64 processes (`PsWrapApcWow64Thread`)
- Injected DLL sends a "hello" IPC message back to confirm successful load

9. **Manual-Map / Shellcode Detection**
   - Walks process virtual address space with `VirtualQueryEx`
   - Flags committed, executable memory regions not backed by any loaded module
   - Detects manually mapped DLLs, shellcode, and injected executable code

10. **Overlay Window Detection**
    - Enumerates all top-level windows via `EnumWindows`
    - Flags large/fullscreen windows with overlay traits (layered, transparent, topmost)
    - Detects ESP/wallhack overlays commonly used in game cheats

11. **System Integrity Checks**
    - **Test-Sign Detection**: Queries CodeIntegrityOptions to detect test-signing mode
    - **HVCI Detection**: Checks if Hypervisor Code Integrity is enabled or disabled
    - **CPU Vendor / Hypervisor Detection**: CPUID-based check for VM/hypervisor presence

## Protection Features

### Protected Process Light (PPL)
Peregrine can elevate processes to Protected Process Light status:
- **Kernel-Enforced Protection**: PPL processes are protected from unauthorized memory access
- **Anti-Malware Signer**: Uses PPL-Antimalware protection level
- **GUI Control**: Set processes to PPL status with one click

## Technical Stack

- **Kernel Driver**: C (WDM)
- **DLL Component**: C/C++ with MinHook for API hooking
- **Tauri GUI**: Rust backend + Svelte/TypeScript frontend
- **Legacy GUI**: Python 3 with Tkinter
- **IPC**: Named pipes (`\\.\pipe\peregrine_ipc`)
- **Kernel Communication**: IOCTL codes (commands 1-11)

## Components

```
src/
├── PeregrineKernelComponent/    # Kernel driver (ring-0)
│   ├── ApcInjection.c           # Kernel APC injection (shellcode, PE export parsing)
│   ├── obCallback.c             # Object callback routines
│   ├── NotifyRoutine.c          # Process/thread/image notifications
│   ├── Coms.c                   # IOCTL communication handler (commands 1-11)
│   ├── Protection.c             # PPL implementation
│   ├── AppState.c               # Driver state management
│   ├── DriverScan.c             # Loaded driver enumeration & blacklist
│   ├── ObCallbackScan.c         # ObCallback enumeration
│   └── SystemCheck.c            # Test-sign, HVCI, CPU/hypervisor checks
│
├── PeregrineDLL/                # User-mode DLL (x86 + x64)
│   ├── dllmain.cpp              # Hook setup, detour functions, IPC hello
│   └── ipc.c                    # Named pipe IPC event logging
│
├── peregrine-tauri/             # Rust/Tauri desktop GUI
│   ├── src-tauri/src/
│   │   ├── lib.rs               # Tauri commands, driver polling, IPC polling
│   │   ├── driver_comm.rs       # IOCTL driver communication
│   │   ├── ipc.rs               # Named pipe server for DLL messages
│   │   └── detections/          # Detection modules (Rust ports)
│   │       ├── pe.rs            # PE parsing, process memory reading
│   │       ├── hooks.rs         # IAT & EAT hook detection
│   │       ├── patch.rs         # .text section integrity checking
│   │       ├── threads.rs       # Thread RIP analysis
│   │       └── blacklist.rs     # Process blacklist scanning
│   └── src/routes/+page.svelte  # Dark-themed Svelte frontend
│
└── Userland/                    # Legacy Python service layer
    ├── peregrine_gui.py         # Original Tkinter GUI
    ├── IPC.py                   # Named pipe IPC server
    ├── DLL.py                   # DLL injection (LoadLibraryA)
    ├── PatchDetection.py        # Module integrity checking
    ├── HookDetection.py         # IAT/EAT hook detection
    ├── threadWork.py            # Thread analysis
    ├── ProcessBlacklist.py      # Process blacklist scanning
    ├── HookDetection.py         # IAT and EAT hook detection
    ├── ManualMapDetection.py    # Manual-map and shellcode detection
    ├── OverlayDetection.py      # Overlay window detection
    └── self_tamper.py           # Self-integrity checks
```

## Building

### Full Build (DLLs + Driver)

Run `build_dll.bat` from the project root:

```batch
build_dll.bat
```

This builds and copies everything to `C:\Peregrine\`:
- `Peregrine64.dll` (x64 Release)
- `Peregrine32.dll` (x86 Release)
- `PeregrineKernelComponent.sys` (x64 Release)
- `peregrine-tauri.exe` (if previously built)

### Tauri GUI

```batch
cd src\peregrine-tauri
npm install
npx tauri build
```

Produces `peregrine-tauri.exe` (~9 MB standalone).

### Requirements
- Windows 10/11 (x64)
- Visual Studio 2022 with C++ workload
- Windows Driver Kit (WDK)
- Rust 1.70+ with cargo
- Node.js 18+ with npm
- Test signing enabled (`bcdedit /set testsigning on`)

## Usage

### Starting the Driver
```
sc.exe create Peregrine type= kernel binPath= "C:\Peregrine\PeregrineKernelComponent.sys"
sc.exe start Peregrine
```

### Running the GUI
```
C:\Peregrine\peregrine-tauri.exe
```

On connect, the app auto-detects DLLs in `C:\Peregrine\` and configures the driver.

### GUI Controls
- **PID Management**: Add/Remove/Clear protected PIDs
- **Set PPL**: Elevate processes to Protected Process Light
- **Inject**: Add target process names for kernel APC injection
- **Check Modules**: Scan a process for module tampering
- **Check IAT/EAT**: Scan for Import/Export Address Table hooks
- **Check Threads**: Analyze thread execution locations
- **Scan Blacklist**: Scan all running processes for known cheat tools
- **Scan Memory**: Detect manually mapped code and shellcode
- **Scan Overlays**: Detect suspicious overlay windows
- **Scan Drivers**: Enumerate loaded kernel drivers and check blacklist
- **Scan ObCallbacks**: Enumerate registered object callbacks
- **System Check**: Test-signing, HVCI, and hypervisor detection

### IOCTL Protocol

| Cmd | Description |
|-----|-------------|
| 1 | Add PID to protected list |
| 2 | Remove PID |
| 3 | Clear all PIDs |
| 4 | Set process to PPL |
| 5 | Scan loaded drivers |
| 6 | Scan ObCallbacks |
| 7 | System integrity checks |
| 8 | Set x64 DLL injection path |
| 9 | Set x86 DLL injection path |
| 10 | Add injection target process name |
| 11 | Enable/disable auto-injection |

## Disclaimer

This project is **strictly for educational purposes**. It demonstrates security concepts and Windows internals for learning and research. Use only in controlled environments with proper authorization.

## License

This is an educational project. Use responsibly and ethically.
