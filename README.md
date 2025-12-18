# Peregrine Anti-Cheat

An educational anti-cheat system for learning Windows kernel programming, process monitoring, and cheat detection techniques.

## Overview

Peregrine is a learning-focused anti-cheat project that demonstrates core concepts in game security and Windows internals. This project implements both kernel-mode and user-mode components to detect common cheating techniques used in games.

## Architecture

### Kernel Component
The kernel driver (`PeregrineKernelComponent`) operates at ring-0 and provides:
- **ObCallback Registration**: Process and thread handle operation monitoring
- **Notify Routines**: Process, thread, and image load notifications
- **IOCTL Communications**: Bidirectional kernel-user communication channel

### User-Mode Components
- **DLL Component** (`PeregrineDLL`): Injected into protected processes for in-process monitoring
- **Userland Service**: Python-based service that manages communication and analysis
- **GUI Interface**: Real-time monitoring and control interface

## Detection Capabilities

### Current Detections
1. **Module Patching Detection**
   - Monitors for unauthorized modifications to loaded modules
   - Detects runtime code patches in protected memory regions

2. **Remote Thread Creation**
   - Identifies threads created remotely in the protected process
   - Flags suspicious cross-process thread injection attempts

3. **Thread & Shellcode Execution**
   - Detects thread execution originating outside trusted modules
   - Identifies shellcode execution patterns in non-module memory

4. **Thread Analysis & Module Mapping**
   - Enumerates all threads in a process and checks their current instruction pointers (RIP)
   - Maps each thread's execution location to its corresponding module (DLL)
   - Identifies which code (from which modules) is actively running in the process
   - Flags suspicious threads executing from unknown or unmapped memory regions

5. **DLL Injection Detection**
   - Monitors unauthorized library loading
   - Tracks suspicious image load notifications

## Technical Stack

- **Kernel Driver**: C (WDM/WDF)
- **DLL Component**: C/C++ with MinHook for hooking
- **Userland Service**: Python 3
- **IPC Mechanism**: Named pipes and shared memory
- **Kernel Communication**: IOCTL (I/O Control) codes

## Components

```
src/
├── PeregrineKernelComponent/    # Kernel driver (ring-0)
│   ├── obCallback.c             # Object callback routines
│   ├── NotifyRoutine.c          # Process/thread/image notifications
│   ├── Coms.c                   # IOCTL communication handler
│   └── AppState.c               # Driver state management
│
├── PeregrineDLL/                # User-mode DLL
│   ├── dllmain.cpp              # DLL entry point and initialization
│   └── ipc.c                    # Inter-process communication
│
└── Userland/                    # Python service layer
    ├── peregrine_gui.py         # GUI interface
    ├── IPC.py                   # IPC client implementation
    ├── PatchDetection.py        # Patch detection logic
    ├── threadWork.py            # Thread analysis
    └── self_tamper.py           # Self-integrity checks
```

## How It Works

1. **Driver Loading**: The kernel component registers callbacks and notify routines
2. **Process Protection**: When a protected process starts, the driver monitors its activity
3. **DLL Injection**: The user-mode DLL is injected for in-process monitoring
4. **Communication**: Kernel and user-mode components exchange data via IOCTL and IPC
5. **Detection**: Multiple layers analyze behavior for suspicious patterns
6. **Response**: Detected threats are logged and can trigger protective actions

## Educational Purpose

This project is designed for learning:
- Windows kernel driver development
- Callback and notify routine mechanisms
- User-kernel communication patterns
- Process and memory analysis techniques
- Anti-tampering and self-protection methods
- Cheat detection methodologies

## Requirements

- Windows 10/11 (x64)
- Visual Studio 2019 or later
- Windows Driver Kit (WDK)
- Python 3.8+
- Test signing enabled (for driver development)

## Disclaimer

This project is **strictly for educational purposes**. It demonstrates security concepts and Windows internals for learning and research. Use only in controlled environments with proper authorization.

## License

This is an educational project. Use responsibly and ethically.
