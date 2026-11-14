# Handoff — branch `hardening/self-defense-and-coverage`

Written on macOS. **Nothing on this branch has been built with MSVC/WDK or run.**
First job on the Windows machine: build, fix what the real compiler finds, then verify on the VM.
Delete this file once the branch is verified.

## What was checked, and how weakly

| Component | Check done | Not done |
|-----------|-----------|----------|
| Driver | `clang -fsyntax-only` against mingw DDK headers with a hand-written `fltKernel.h` shim | Real WDK build (`/W4 /WX`), load, any runtime test |
| DLL | `mingw-w64 gcc/g++ -fsyntax-only`, both roles | MSVC build, inject, runtime |
| GUI (Rust) | `cargo check --target x86_64-pc-windows-gnu --tests` clean | Running; the unit tests in `ipc.rs` were only type-checked, never executed |
| UI | `svelte-check` 0 errors | Running |
| `test/cheat_thread.c`, `test/cheat_pipe.c` | Built with mingw | Run |

An independent code review of the diff was started and **aborted before it produced results** — the diff is unreviewed apart from my own pass.

## Build order on Windows

```batch
build_dll.bat
cd src\peregrine-tauri && npm install && npx tauri build
test\build.bat
```

`cargo test` in `src-tauri` should now be runnable (4 tests in `ipc.rs`).

## Behaviour changes you will notice immediately

- **Inject targets are full paths.** The target box takes `C:\test\game.exe`, not `game.exe`. The file must exist when you add it (it is opened to resolve the NT path).
- **The GUI is TRUSTED, not PROTECTED.** It no longer appears in thread/image-load events and is not in the protected list.
- **The game is no longer treated as "ours" by the minifilter.** Only the GUI may write under `C:\Peregrine\`.
- **IOCTL commands return their real status.** Things that used to fail silently now show an error in the log.
- **Wire protocol changed** (commands 10/17 payload, new command 18, new IOCTL 0x803). Driver, DLLs and GUI must all come from this branch — do not mix with old binaries. The committed binaries in `src/Userland/` and `test/*.exe` are still the **old** ones.
- Legacy file names (`peregrinedll_x64.dll`, `peregrine64.dll`, …) were dropped from the minifilter list.

## Verify in this order (each maps to todo.xml)

1. **Driver loads, GUI connects**, log shows `connected (GUI PID … trusted)`, no offline banner.
2. **Path identity (task 1):** add `C:\test\game.exe` as Game target → inject + auto-protect still work. Copy any exe to `C:\other\game.exe` and run it → no inject, no protect.
   - Riskiest piece: `InjOnProcessCreate` uses `FltGetFileNameInformationUnsafe` on `CreateInfo->FileObject` and compares against what `GetFinalPathNameByHandleW(VOLUME_NAME_NT)` gave the GUI. If inject never fires, DbgPrint both strings first.
3. **Minifilter:** from an admin cmd, `del`, overwrite, and `move /y x.dll C:\Peregrine\PeregrineGame_x64.dll` must all be denied and logged. Specifically confirm `PeregrineKernelComponent.sys` is now protected (it was not before — length bug).
4. **Thread handles (task 10):** `test\cheat_thread.exe <game_pid>` → one `[Handle Access] … thread …` line. Against a non-protected PID → nothing.
5. **VM_READ + rate limit (task 11):** `test\cheat_thread.exe <game_pid> 500` and `test\cheat.exe` → a line plus `(+N identical suppressed)`, not a flood, not silence.
   - Expect new legitimate lines from system processes (csrss, Task Manager) now that VM_READ is reported. Decide whether that is acceptable noise.
6. **IPC auth (task 6):** real DLL `hello` still arrives. `test\cheat_pipe.exe <game_pid>` → tool prints PASS, GUI shows nothing.
   - Riskiest piece: pipe DACL for Authenticated Users is `0x00120192` and the DLL opens with `FILE_WRITE_DATA | SYNCHRONIZE`. If the DLL can no longer connect from a medium-IL game, this is where to look (`ipc.rs` `PIPE_SDDL`, DLL `ipc.c` `GetPipe`).
7. **Heartbeat (task 3):** stop the driver while the GUI runs → red banner. Start it again → banner clears and targets/PIDs are re-pushed.
   - Note: with the GUI's poll handle open, `sc stop` may stay pending until the GUI closes. Observe what actually happens.
8. **IPC filtering (task 41):** `cheat.exe` (as Sensor target) against the game → external lines. Same cheat against notepad → no line.
9. **Callstack (task 45/93):** `cheat_callstack.exe` still yields `[Callstack Anomaly]`; it now needs the *target* to be the protected game (event carries `targetPID`).
10. **Module check:** after Game inject, Modules scan still reports `ok self-hooks`. The DLL no longer hooks `ReadProcessMemory`/`WriteProcessMemory` in KernelBase and `patch.rs` no longer excuses them.
11. **Overflow (task 48):** hard to trigger on purpose; at least confirm normal polling is unaffected.

## todo.xml mapping

`todo.xml` was left untouched (it has your uncommitted rewrite). Status after VM verification would be:

- Implemented, unverified: **1, 3, 6 (PID auth only — no per-session token), 10, 11, 41, 44, 45, 48, 83**, 43 (partly: README scope + known limits)
- Found and fixed outside the list: minifilter suffix-length bug, rename/hard-link-onto bypass, `FILE_CREATE_PIPE_INSTANCE` granted to all users, pipe-name squatting, `MAXIMUM_ALLOWED` not counted as dangerous, `GetProcessId` failing on VM_READ-only handles, DriverEntry registering callbacks before state init
- Deliberately not done: **2** (see below), 4, 5, 20–22, 30, 40, 46, 47, 50+

### Why task 2 (refuse unload) is not in here

`sc stop` is a mandatory unload — `FilterUnloadCallback` cannot refuse it. The documented way is `FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP`, but I could not confirm from memory how that interacts with the `DriverUnload` set in `main.c` and FltMgr's saved `OldDriverUnload`. Getting it wrong means a driver that cannot be unloaded or a bugcheck, so it needs to be done with a debugger attached, not blind.

## Things I am not confident about

- Everything kernel-side until a WDK build passes. Likely first failures: `/W4 /WX` conversion warnings in new code.
- `FltGetFileNameInformationUnsafe` from the process-create callback (documented use, never exercised here).
- `FltGetDestinationFileNameInformation` in `PreSetInfo` for the `…Ex` info classes.
- The pipe access-mask change (step 6).
- UI resync after driver restart re-protects PIDs the UI remembers; if the game exited while the driver was down, a stale PID gets protected until the UI is told otherwise.
- GUI restart with the driver still loaded: kernel keeps protected PIDs/targets the fresh UI does not know about. Pre-existing, not fixed.
