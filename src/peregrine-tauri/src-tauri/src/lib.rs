mod driver_comm;
mod ipc;
mod detections;
mod etw_ti;
mod hwid;

use driver_comm::{DllArch, DriverHandle, InjectRole};
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager};

// Every command opens its own driver handle. No shared state, no mutex, no deadlocks.

/// Liveness of one backend channel, as shown in the UI banner.
#[derive(Debug, Clone, Serialize, PartialEq)]
struct ChannelStatus {
    online: bool,
    detail: String,
}

impl ChannelStatus {
    fn starting() -> Self {
        Self { online: false, detail: "starting".into() }
    }
}

/// Last known state of the two channels the GUI depends on. The UI reads this
/// on mount (events emitted before the page listens would otherwise be lost)
/// and then follows `driver-status` / `ipc-status` events.
#[derive(Debug, Clone, Serialize)]
struct BackendStatus {
    driver: ChannelStatus,
    ipc: ChannelStatus,
}

type SharedBackendStatus = Arc<Mutex<BackendStatus>>;

#[derive(Clone, Copy)]
enum Channel {
    Driver,
    Ipc,
}

/// Records the new state and notifies the UI only when it actually changed.
fn set_channel_status(
    app: &AppHandle,
    shared: &SharedBackendStatus,
    channel: Channel,
    online: bool,
    detail: String,
) {
    let new = ChannelStatus { online, detail };
    {
        let mut guard = shared.lock().unwrap_or_else(|e| e.into_inner());
        let slot = match channel {
            Channel::Driver => &mut guard.driver,
            Channel::Ipc => &mut guard.ipc,
        };
        if *slot == new {
            return;
        }
        *slot = new.clone();
    }
    let event = match channel {
        Channel::Driver => "driver-status",
        Channel::Ipc => "ipc-status",
    };
    let _ = app.emit(event, &new);
}

#[tauri::command]
fn backend_status(state: tauri::State<'_, SharedBackendStatus>) -> BackendStatus {
    state.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Starts the driver poll and the DLL pipe, once, after the page has registered
/// its event listeners.
///
/// Both channels forward what they receive as Tauri events, and an event
/// emitted before anybody listens is gone. The kernel queue in particular can
/// hold a backlog from before this GUI started (including the overflow
/// notice); draining it into the void would silently discard findings.
#[tauri::command]
fn ui_ready(app: AppHandle, state: tauri::State<'_, SharedBackendStatus>) {
    static STARTED: std::sync::Once = std::sync::Once::new();
    let status = state.inner().clone();
    STARTED.call_once(move || {
        start_driver_polling(app.clone(), status.clone());
        start_ipc_polling(app, status);
    });
}

/// (Re)establishes this GUI's standing with the driver. Driver state does not
/// survive a driver restart, so the UI calls this on every offline→online edge.
#[tauri::command]
fn connect_driver() -> Result<String, String> {
    let h = DriverHandle::open()?;

    // TRUSTED (not PROTECTED): this process is the AC. Without it the minifilter
    // would deny our own file access and ObCallback would report our scans.
    h.trust_self()
        .map_err(|e| format!("driver refused to trust the GUI: {e}"))?;

    let mut msg = format!("connected (GUI PID {} trusted)", std::process::id());

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    let search_dirs: Vec<std::path::PathBuf> = [
        exe_dir,
        Some(std::path::PathBuf::from(r"C:\Peregrine")),
        Some(std::path::PathBuf::from(r"E:\Peregrine\src\Userland")),
    ]
    .into_iter()
    .flatten()
    .collect();

    let find_dll = |name: &str| -> Option<String> {
        search_dirs
            .iter()
            .map(|dir| dir.join(name))
            .find(|p| p.exists())
            .map(|p| p.to_string_lossy().into_owned())
    };

    let dlls = [
        ("game-x64", "PeregrineGame_x64.dll", InjectRole::Game, DllArch::X64),
        ("game-x86", "PeregrineGame_x86.dll", InjectRole::Game, DllArch::X86),
        ("sensor-x64", "PeregrineSensor_x64.dll", InjectRole::Sensor, DllArch::X64),
        ("sensor-x86", "PeregrineSensor_x86.dll", InjectRole::Sensor, DllArch::X86),
    ];
    for (label, file, role, arch) in dlls {
        match find_dll(file) {
            Some(path) => match h.set_dll_path(role, arch, &path) {
                Ok(()) => msg.push_str(&format!(" | {label}: {path}")),
                Err(e) => msg.push_str(&format!(" | {label}: REJECTED ({e})")),
            },
            None => msg.push_str(&format!(" | {label}: NOT FOUND")),
        }
    }

    Ok(msg)
}

#[tauri::command]
fn add_pid(pid: u32) -> Result<(), String> {
    DriverHandle::open()?.protect_pid(pid)
}

#[tauri::command]
fn remove_pid(pid: u32) -> Result<(), String> {
    DriverHandle::open()?.unprotect_pid(pid)
}

#[tauri::command]
fn clear_pids() -> Result<(), String> {
    DriverHandle::open()?.clear_protected()
}

#[tauri::command]
fn set_ppl(pid: u32) -> Result<(), String> {
    DriverHandle::open()?.set_ppl(pid)
}

#[tauri::command]
fn scan_drivers() -> Result<(), String> {
    DriverHandle::open()?.scan_drivers()
}

#[tauri::command]
fn scan_ob_callbacks() -> Result<(), String> {
    DriverHandle::open()?.scan_ob_callbacks()
}

#[tauri::command]
fn system_check() -> Result<(), String> {
    DriverHandle::open()?.system_check()
}

/// Registers `path` (an existing executable) as an inject target and returns
/// the normalized NT path the kernel will match — the target's identity.
fn add_target(role: InjectRole, path: &str) -> Result<String, String> {
    let nt_path = driver_comm::image_nt_path(path)?;
    let h = DriverHandle::open()?;
    h.add_injection_target(role, &nt_path)?;
    h.set_injection_enabled(true)?;
    Ok(nt_path)
}

#[tauri::command]
fn add_injection_target(path: String) -> Result<String, String> {
    add_target(InjectRole::Game, &path)
}

#[tauri::command]
fn add_sensor_injection_target(path: String) -> Result<String, String> {
    add_target(InjectRole::Sensor, &path)
}

#[tauri::command]
fn clear_injection_targets() -> Result<String, String> {
    DriverHandle::open()?.clear_injection_targets()?;
    Ok("injection targets cleared and disabled".into())
}

#[tauri::command]
fn start_etw_ti(app: tauri::AppHandle) -> Result<String, String> {
    if etw_ti::is_running() {
        return Ok("ETW-TI already running".into());
    }
    let my_pid = std::process::id();
    DriverHandle::open()?.set_ppl(my_pid)?;

    let rx = etw_ti::start_etw_session().map_err(|e| format!("ETW-TI: {e}"))?;

    std::thread::spawn(move || {
        while let Ok(ev) = rx.recv() {
            let _ = app.emit("etw-ti-event", &ev);
        }
    });

    Ok(format!("ETW-TI started (PID {} set to PPL)", my_pid))
}

#[tauri::command]
fn stop_etw_ti() -> Result<String, String> {
    etw_ti::stop_etw_session().map_err(|e| format!("ETW-TI: {e}"))?;
    Ok("ETW-TI stopped".into())
}

#[tauri::command]
fn check_modules(pid: u32) -> Result<Vec<detections::patch::ModuleCheck>, String> {
    detections::patch::check_process_modules(pid)
}

#[tauri::command]
fn check_iat(pid: u32) -> Result<Vec<detections::hooks::IatHook>, String> {
    detections::hooks::check_iat_hooks(pid)
}

#[tauri::command]
fn check_eat(pid: u32) -> Result<Vec<detections::hooks::EatHook>, String> {
    detections::hooks::check_eat_hooks(pid)
}

#[tauri::command]
fn check_threads(pid: u32) -> Result<Vec<detections::threads::ThreadInfo>, String> {
    detections::threads::check_all_threads(pid)
}

#[tauri::command]
fn scan_blacklist() -> Vec<detections::blacklist::BlacklistMatch> {
    detections::blacklist::scan_processes(None)
}

#[tauri::command]
fn scan_signatures(pid: u32) -> Result<Vec<detections::sigscan::SigMatch>, String> {
    let (matches, bytes) = detections::sigscan::scan_process(pid)?;
    eprintln!("[DBG] SigScan: {} matches in {} MB", matches.len(), bytes / (1024 * 1024));
    Ok(matches)
}

#[tauri::command]
fn scan_vad(pid: u32) -> Result<(), String> {
    DriverHandle::open()?.scan_vad(pid)
}

#[tauri::command]
fn collect_hwid() -> Result<Vec<hwid::HwidEntry>, String> {
    if let Ok(h) = DriverHandle::open() {
        let _ = h.collect_hwid();
    }
    Ok(hwid::collect_userland_hwids())
}

#[tauri::command]
fn scan_overlays() -> Vec<detections::overlay::OverlayWindow> {
    detections::overlay::detect_overlays()
}

fn start_ipc_polling(app: AppHandle, status: SharedBackendStatus) {
    let rx = ipc::start_ipc_server();
    std::thread::spawn(move || {
        while let Ok(event) = rx.recv() {
            match event {
                ipc::IpcEvent::Message(msg) => {
                    let _ = app.emit("ipc-event", &msg);
                }
                ipc::IpcEvent::ServerStatus { online, detail } => {
                    set_channel_status(&app, &status, Channel::Ipc, online, detail);
                }
            }
        }
        // Sender dropped: the server thread is gone and nothing will arrive anymore.
        set_channel_status(
            &app,
            &status,
            Channel::Ipc,
            false,
            "IPC server thread exited".into(),
        );
    });
}

/// Pause between polls while the kernel queue is empty.
const DRIVER_IDLE_POLL: std::time::Duration = std::time::Duration::from_millis(5);
/// Pause before retrying after the driver could not be reached.
const DRIVER_RETRY: std::time::Duration = std::time::Duration::from_secs(1);
/// How often the SCM is asked whether a stop of the driver is pending.
const DRIVER_SCM_CHECK: std::time::Duration = std::time::Duration::from_secs(1);

/// Drains kernel events and doubles as the driver heartbeat: every poll is a
/// full IOCTL round-trip, so the first failed one flips the UI to
/// "kernel component offline" and it stays there until a poll succeeds again.
fn start_driver_polling(app: AppHandle, status: SharedBackendStatus) {
    std::thread::spawn(move || {
        let mut poll_handle: Option<DriverHandle> = None;
        let mut stop_pending = false;
        let mut last_scm_check = std::time::Instant::now();

        loop {
            // A requested stop stays pending behind our open handle and is
            // invisible to the poll below; ask the SCM about it once a second.
            if last_scm_check.elapsed() >= DRIVER_SCM_CHECK {
                last_scm_check = std::time::Instant::now();
                let pending = poll_handle.is_some() && driver_comm::driver_stop_pending();
                if pending != stop_pending {
                    stop_pending = pending;
                    let _ = app.emit(
                        "driver-event",
                        serde_json::json!({ "event": "driver_stop_pending", "pending": pending }),
                    );
                }
            }

            let handle = match poll_handle.as_ref() {
                Some(h) => h,
                None => match DriverHandle::open() {
                    Ok(h) => poll_handle.insert(h),
                    Err(e) => {
                        set_channel_status(&app, &status, Channel::Driver, false, e);
                        std::thread::sleep(DRIVER_RETRY);
                        continue;
                    }
                },
            };

            match handle.recv_event() {
                Ok(Some(raw)) => {
                    set_channel_status(&app, &status, Channel::Driver, true, "online".into());
                    forward_driver_event(&app, &raw);
                    // Keep draining without a pause while events are queued.
                }
                Ok(None) => {
                    set_channel_status(&app, &status, Channel::Driver, true, "online".into());
                    std::thread::sleep(DRIVER_IDLE_POLL);
                }
                Err(e) => {
                    eprintln!("[DBG] DRV poll error: {}", e);
                    set_channel_status(&app, &status, Channel::Driver, false, e);
                    poll_handle = None;
                    std::thread::sleep(DRIVER_RETRY);
                }
            }
        }
    });
}

fn forward_driver_event(app: &AppHandle, raw: &[u8]) {
    let s = String::from_utf8_lossy(raw);
    // Kernel emits valid JSON (JsonEscapeString); no massaging.
    match serde_json::from_str::<serde_json::Value>(&s) {
        Ok(obj) => {
            let ev = obj.get("event").and_then(|v| v.as_str()).unwrap_or("");
            // High-volume / uninteresting: drop before UI.
            // process_exit for protected PIDs is still forwarded
            // so the UI can prune protectedPids (no log line).
            if !matches!(ev, "thread_exit" | "process_create") {
                let _ = app.emit("driver-event", &obj);
            }
        }
        Err(e) => {
            eprintln!("[DBG] DRV JSON parse fail: {} | raw={}", e, s);
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            backend_status,
            ui_ready,
            connect_driver,
            add_pid,
            remove_pid,
            clear_pids,
            set_ppl,
            scan_drivers,
            scan_ob_callbacks,
            system_check,
            add_injection_target,
            add_sensor_injection_target,
            clear_injection_targets,
            start_etw_ti,
            stop_etw_ti,
            check_modules,
            check_iat,
            check_eat,
            check_threads,
            scan_blacklist,
            scan_signatures,
            scan_vad,
            collect_hwid,
            scan_overlays,
        ])
        .setup(|app| {
            detections::threads::enable_debug_privilege();
            let status: SharedBackendStatus = Arc::new(Mutex::new(BackendStatus {
                driver: ChannelStatus::starting(),
                ipc: ChannelStatus::starting(),
            }));
            app.manage(status.clone());

            // The channels are started by `ui_ready`, not here: see there.
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
