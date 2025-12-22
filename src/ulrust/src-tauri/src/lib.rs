mod kernel_ioctl;
mod ipc;
mod dll_injection;
mod process_blacklist;

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tauri::State;

// Application state
struct AppState {
    kernel_device: Arc<Mutex<Option<kernel_ioctl::KernelDevice>>>,
    protected_pids: Arc<Mutex<Vec<u32>>>,
    ipc_server: Arc<Mutex<Option<ipc::IpcServer>>>,
}

// Tauri Commands

#[tauri::command]
fn connect_to_kernel() -> Result<String, String> {
    match kernel_ioctl::KernelDevice::open() {
        Ok(_) => Ok("Connected to kernel driver".to_string()),
        Err(e) => Err(format!("Failed to connect: {:?}", e)),
    }
}

#[tauri::command]
fn add_protected_pid(pid: u32, state: State<AppState>) -> Result<String, String> {
    let app_state = state.inner();
    let device = app_state.kernel_device.lock().unwrap();
    if let Some(ref dev) = *device {
        dev.add_pid(pid as usize)
            .map_err(|e| format!("Failed to add PID: {:?}", e))?;
        drop(device);

        let mut pids = app_state.protected_pids.lock().unwrap();
        if !pids.contains(&pid) {
            pids.push(pid);
        }
        Ok(format!("Added PID {} to protection list", pid))
    } else {
        Err("Not connected to kernel driver".to_string())
    }
}

#[tauri::command]
fn remove_protected_pid(pid: u32, state: State<AppState>) -> Result<String, String> {
    let app_state = state.inner();
    let device = app_state.kernel_device.lock().unwrap();
    if let Some(ref dev) = *device {
        dev.remove_pid(pid as usize)
            .map_err(|e| format!("Failed to remove PID: {:?}", e))?;
        drop(device);

        let mut pids = app_state.protected_pids.lock().unwrap();
        pids.retain(|&p| p != pid);
        Ok(format!("Removed PID {} from protection list", pid))
    } else {
        Err("Not connected to kernel driver".to_string())
    }
}

#[tauri::command]
fn clear_all_pids(state: State<AppState>) -> Result<String, String> {
    let app_state = state.inner();
    let device = app_state.kernel_device.lock().unwrap();
    if let Some(ref dev) = *device {
        dev.clear_all_pids()
            .map_err(|e| format!("Failed to clear PIDs: {:?}", e))?;
        drop(device);

        let mut pids = app_state.protected_pids.lock().unwrap();
        pids.clear();
        Ok("Cleared all PIDs from protection list".to_string())
    } else {
        Err("Not connected to kernel driver".to_string())
    }
}

#[tauri::command]
fn set_ppl(pid: u32, state: State<AppState>) -> Result<String, String> {
    let app_state = state.inner();
    let device = app_state.kernel_device.lock().unwrap();
    if let Some(ref dev) = *device {
        dev.set_ppl(pid as usize)
            .map_err(|e| format!("Failed to set PPL: {:?}", e))?;
        Ok(format!("Set PID {} to Protected Process Light status", pid))
    } else {
        Err("Not connected to kernel driver".to_string())
    }
}

#[tauri::command]
fn get_protected_pids(state: State<AppState>) -> Vec<u32> {
    let app_state = state.inner();
    let pids = app_state.protected_pids.lock().unwrap();
    pids.clone()
}

#[tauri::command]
fn scan_blacklist(keywords: Option<Vec<String>>) -> Result<Vec<process_blacklist::BlacklistMatch>, String> {
    let keyword_refs: Option<Vec<&str>> = keywords.as_ref().map(|v| v.iter().map(|s| s.as_str()).collect());
    let keyword_slice = keyword_refs.as_ref().map(|v| v.as_slice());

    Ok(process_blacklist::scan_processes_for_blacklist(keyword_slice))
}

#[tauri::command]
fn inject_dll(pid: u32, dll_x86: String, dll_x64: String) -> Result<String, String> {
    let mut dll_paths = HashMap::new();
    dll_paths.insert("x86".to_string(), dll_x86);
    dll_paths.insert("x64".to_string(), dll_x64);

    match dll_injection::inject_dll(pid, &dll_paths) {
        Ok(Some(hmodule)) => Ok(format!("Successfully injected DLL into PID {} (HMODULE: 0x{:X})", pid, hmodule)),
        Ok(None) => Err(format!("DLL injection failed for PID {} - LoadLibraryA returned NULL", pid)),
        Err(e) => Err(format!("DLL injection error: {}", e)),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Try to connect to kernel driver on startup
    let kernel_device = match kernel_ioctl::KernelDevice::open() {
        Ok(dev) => Some(dev),
        Err(_) => None,
    };

    let app_state = AppState {
        kernel_device: Arc::new(Mutex::new(kernel_device)),
        protected_pids: Arc::new(Mutex::new(Vec::new())),
        ipc_server: Arc::new(Mutex::new(None)),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            connect_to_kernel,
            add_protected_pid,
            remove_protected_pid,
            clear_all_pids,
            set_ppl,
            get_protected_pids,
            scan_blacklist,
            inject_dll,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
