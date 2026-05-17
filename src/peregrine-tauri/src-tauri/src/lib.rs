mod driver_comm;
mod ipc;
mod detections;
mod etw_ti;

use driver_comm::DriverHandle;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};

// Every command opens its own driver handle. No shared state, no mutex, no deadlocks.

#[tauri::command]
fn connect_driver() -> Result<String, String> {
    let h = DriverHandle::open()?;
    let my_pid = std::process::id();
    let _ = h.add_pid(my_pid);

    let mut msg = format!("connected (self PID {} protected)", my_pid);

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

    let find_dll = |names: &[&str]| -> Option<String> {
        for dir in &search_dirs {
            for name in names {
                let p = dir.join(name);
                if p.exists() {
                    return Some(p.to_string_lossy().into_owned());
                }
            }
        }
        None
    };

    if let Some(x64) = find_dll(&["PeregrineDLL_x64.dll", "Peregrine64.dll", "64.dll"]) {
        let _ = h.set_dll_path_x64(&x64);
        msg.push_str(&format!(" | x64: {x64}"));
    } else {
        msg.push_str(" | x64 DLL: NOT FOUND");
    }
    if let Some(x86) = find_dll(&["PeregrineDLL_x86.dll", "Peregrine32.dll", "32.dll"]) {
        let _ = h.set_dll_path_x86(&x86);
        msg.push_str(&format!(" | x86: {x86}"));
    } else {
        msg.push_str(" | x86 DLL: NOT FOUND");
    }

    Ok(msg)
}

#[tauri::command]
fn add_pid(pid: u32) -> Result<(), String> {
    DriverHandle::open()?.add_pid(pid)
}

#[tauri::command]
fn remove_pid(pid: u32) -> Result<(), String> {
    DriverHandle::open()?.remove_pid(pid)
}

#[tauri::command]
fn clear_pids() -> Result<(), String> {
    DriverHandle::open()?.clear_pids()
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

#[tauri::command]
fn add_injection_target(name: String) -> Result<String, String> {
    let h = DriverHandle::open()?;
    h.add_injection_target(&name)?;
    h.set_injection_enabled(true)?;
    Ok(format!("target '{}' added, injection enabled", name))
}

#[tauri::command]
fn clear_injection_targets() -> Result<String, String> {
    DriverHandle::open()?.set_injection_enabled(false)?;
    Ok("injection disabled".into())
}

#[tauri::command]
fn start_etw_ti(app: tauri::AppHandle) -> Result<String, String> {
    let my_pid = std::process::id();
    DriverHandle::open()?.set_ppl(my_pid)?;

    let stop = Arc::new(AtomicBool::new(false));
    let rx = etw_ti::start_etw_session(stop).map_err(|e| format!("ETW-TI: {e}"))?;

    std::thread::spawn(move || {
        while let Ok(ev) = rx.recv() {
            let _ = app.emit("etw-ti-event", &ev);
        }
    });

    Ok(format!("ETW-TI started (PID {} set to PPL)", my_pid))
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

fn start_ipc_polling(app: AppHandle) {
    let stop = Arc::new(AtomicBool::new(false));
    let rx = ipc::start_ipc_server(stop);
    std::thread::spawn(move || {
        let mut count = 0u64;
        while let Ok(msg) = rx.recv() {
            count += 1;
            let ev = msg.get("event").and_then(|v| v.as_str()).unwrap_or("?");
            eprintln!("[DBG] IPC msg #{}: event={}", count, ev);
            let _ = app.emit("ipc-event", &msg);
            eprintln!("[DBG] IPC msg #{} emitted", count);
        }
        eprintln!("[DBG] IPC polling channel closed!");
    });
}

fn start_driver_polling(app: AppHandle) {
    std::thread::spawn(move || {
        let mut poll_handle: Option<DriverHandle> = None;

        loop {
            std::thread::sleep(std::time::Duration::from_millis(5));

            if poll_handle.is_none() {
                poll_handle = DriverHandle::open().ok();
                if poll_handle.is_none() {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    continue;
                }
            }

            match poll_handle.as_ref().unwrap().recv_event() {
                Ok(Some(raw)) => {
                    let s = String::from_utf8_lossy(&raw);
                    let fixed = s.replace('\\', "\\\\");
                    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&fixed) {
                        let ev = obj.get("event").and_then(|v| v.as_str()).unwrap_or("");
                        match ev {
                            "process_create" | "process_exit" |
                            "thread_create" | "thread_exit" |
                            "image_load" => {}
                            _ => {
                                eprintln!("[DBG] DRV event: {}", ev);
                                let _ = app.emit("driver-event", &obj);
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("[DBG] DRV poll error: {}", e);
                    poll_handle = None;
                }
            }
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            connect_driver,
            add_pid,
            remove_pid,
            clear_pids,
            set_ppl,
            scan_drivers,
            scan_ob_callbacks,
            system_check,
            add_injection_target,
            clear_injection_targets,
            start_etw_ti,
            check_modules,
            check_iat,
            check_eat,
            check_threads,
            scan_blacklist,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            start_driver_polling(handle.clone());
            start_ipc_polling(handle);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
