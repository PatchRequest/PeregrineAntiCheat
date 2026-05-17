mod driver_comm;
mod ipc;
mod detections;

use driver_comm::{DriverHandle, SharedDriver};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager};

#[tauri::command]
fn connect_driver(state: tauri::State<'_, SharedDriver>) -> Result<String, String> {
    let handle = DriverHandle::open()?;

    let mut msg = String::from("connected");

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    let search_dirs: Vec<std::path::PathBuf> = [
        exe_dir.clone(),
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
        let _ = handle.set_dll_path_x64(&x64);
        msg.push_str(&format!(" | x64: {x64}"));
    } else {
        msg.push_str(" | x64 DLL: NOT FOUND");
    }
    if let Some(x86) = find_dll(&["PeregrineDLL_x86.dll", "Peregrine32.dll", "32.dll"]) {
        let _ = handle.set_dll_path_x86(&x86);
        msg.push_str(&format!(" | x86: {x86}"));
    } else {
        msg.push_str(" | x86 DLL: NOT FOUND");
    }

    let mut guard = state.lock().map_err(|e| e.to_string())?;
    *guard = Some(handle);
    Ok(msg)
}

#[tauri::command]
fn add_injection_target(name: String, state: tauri::State<'_, SharedDriver>) -> Result<String, String> {
    let guard = state.lock().map_err(|e| e.to_string())?;
    let drv = guard.as_ref().ok_or("not connected")?;
    drv.add_injection_target(&name)?;
    drv.set_injection_enabled(true)?;
    Ok(format!("target '{}' added, injection enabled", name))
}

#[tauri::command]
fn clear_injection_targets(state: tauri::State<'_, SharedDriver>) -> Result<String, String> {
    let guard = state.lock().map_err(|e| e.to_string())?;
    let drv = guard.as_ref().ok_or("not connected")?;
    drv.set_injection_enabled(false)?;
    // Send clear command (command 10 with empty = not valid, but we can disable + the driver clears on disable)
    // Actually we need a proper clear IOCTL. For now just disable.
    Ok("injection disabled".into())
}

#[tauri::command]
fn add_pid(pid: u32, state: tauri::State<'_, SharedDriver>) -> Result<(), String> {
    let guard = state.lock().map_err(|e| e.to_string())?;
    guard.as_ref().ok_or("not connected")?.add_pid(pid)
}

#[tauri::command]
fn remove_pid(pid: u32, state: tauri::State<'_, SharedDriver>) -> Result<(), String> {
    let guard = state.lock().map_err(|e| e.to_string())?;
    guard.as_ref().ok_or("not connected")?.remove_pid(pid)
}

#[tauri::command]
fn clear_pids(state: tauri::State<'_, SharedDriver>) -> Result<(), String> {
    let guard = state.lock().map_err(|e| e.to_string())?;
    guard.as_ref().ok_or("not connected")?.clear_pids()
}

#[tauri::command]
fn set_ppl(pid: u32, state: tauri::State<'_, SharedDriver>) -> Result<(), String> {
    let guard = state.lock().map_err(|e| e.to_string())?;
    guard.as_ref().ok_or("not connected")?.set_ppl(pid)
}

#[tauri::command]
fn scan_drivers(state: tauri::State<'_, SharedDriver>) -> Result<(), String> {
    let guard = state.lock().map_err(|e| e.to_string())?;
    guard.as_ref().ok_or("not connected")?.scan_drivers()
}

#[tauri::command]
fn scan_ob_callbacks(state: tauri::State<'_, SharedDriver>) -> Result<(), String> {
    let guard = state.lock().map_err(|e| e.to_string())?;
    guard.as_ref().ok_or("not connected")?.scan_ob_callbacks()
}

#[tauri::command]
fn system_check(state: tauri::State<'_, SharedDriver>) -> Result<(), String> {
    let guard = state.lock().map_err(|e| e.to_string())?;
    guard.as_ref().ok_or("not connected")?.system_check()
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
fn configure_injection(
    dll_x64: String,
    dll_x86: String,
    targets: Vec<String>,
    state: tauri::State<'_, SharedDriver>,
) -> Result<(), String> {
    let guard = state.lock().map_err(|e| e.to_string())?;
    let drv = guard.as_ref().ok_or("not connected")?;

    if !dll_x64.is_empty() {
        drv.set_dll_path_x64(&dll_x64)?;
    }
    if !dll_x86.is_empty() {
        drv.set_dll_path_x86(&dll_x86)?;
    }
    for t in &targets {
        drv.add_injection_target(t)?;
    }
    drv.set_injection_enabled(true)?;
    Ok(())
}

fn start_ipc_polling(app: AppHandle) {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rx = ipc::start_ipc_server(stop);
    std::thread::spawn(move || {
        while let Ok(msg) = rx.recv() {
            let _ = app.emit("ipc-event", &msg);
        }
    });
}

fn start_driver_polling(app: AppHandle, driver: SharedDriver) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(2));

        let data = {
            let guard = match driver.lock() {
                Ok(g) => g,
                Err(_) => continue,
            };
            match guard.as_ref() {
                Some(d) => d.recv_event(),
                None => Ok(None),
            }
        };

        if let Ok(Some(raw)) = data {
            let s = String::from_utf8_lossy(&raw);
            let fixed = s.replace('\\', "\\\\");
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&fixed) {
                let _ = app.emit("driver-event", &obj);
            }
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Arc::new(Mutex::new(None::<DriverHandle>)) as SharedDriver)
        .invoke_handler(tauri::generate_handler![
            connect_driver,
            add_injection_target,
            clear_injection_targets,
            add_pid,
            remove_pid,
            clear_pids,
            set_ppl,
            scan_drivers,
            scan_ob_callbacks,
            system_check,
            configure_injection,
            check_modules,
            check_iat,
            check_eat,
            check_threads,
            scan_blacklist,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            let driver = app.state::<SharedDriver>().inner().clone();
            start_driver_polling(handle.clone(), driver);
            start_ipc_polling(handle);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
