use std::collections::HashMap;
use std::ffi::CString;
use windows::core::PCSTR;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::LibraryLoader::*;

const PROCESS_CREATE_THREAD: u32 = 0x0002;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_VM_WRITE: u32 = 0x0020;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

/// Check if a process is 32-bit (WOW64)
fn is_process_32bit(pid: u32) -> Result<bool, windows::core::Error> {
    unsafe {
        let h_process = OpenProcess(
            PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_INFORMATION),
            false,
            pid,
        )?;

        let mut is_wow64 = BOOL::default();
        let result = IsWow64Process(h_process, &mut is_wow64);

        let _ = CloseHandle(h_process);

        if result.is_ok() {
            Ok(is_wow64.as_bool())
        } else {
            Err(windows::core::Error::from_win32())
        }
    }
}

/// Inject a DLL into a target process using LoadLibraryA
///
/// # Arguments
/// * `target_pid` - Process ID to inject into
/// * `dll_paths` - Map with "x86" and/or "x64" keys containing DLL paths
///
/// # Returns
/// The HMODULE handle from LoadLibraryA, or None if injection failed
pub fn inject_dll(
    target_pid: u32,
    dll_paths: &HashMap<String, String>,
) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    // Determine which DLL to use based on architecture
    let is_32bit = is_process_32bit(target_pid)?;

    let dll_path = if is_32bit {
        dll_paths.get("x86").ok_or("No x86 DLL available")?
    } else {
        dll_paths.get("x64").ok_or("No x64 DLL available")?
    };

    // Convert path to null-terminated bytes
    let dll_path_bytes = CString::new(dll_path.as_str())?;
    let dll_path_len = dll_path_bytes.as_bytes_with_nul().len();

    unsafe {
        // Open target process
        let access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;
        let h_process = OpenProcess(
            PROCESS_ACCESS_RIGHTS(access),
            false,
            target_pid,
        )?;

        // Ensure cleanup on error
        let _guard = ProcessHandleGuard(h_process);

        // Allocate memory in remote process
        let remote_mem = VirtualAllocEx(
            h_process,
            None,
            dll_path_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            return Err("VirtualAllocEx failed".into());
        }

        // Write DLL path to remote memory
        let mut bytes_written: usize = 0;
        WriteProcessMemory(
            h_process,
            remote_mem,
            dll_path_bytes.as_ptr() as *const _,
            dll_path_len,
            Some(&mut bytes_written),
        )?;

        // Get address of LoadLibraryA in kernel32.dll
        let kernel32_name = CString::new("kernel32.dll")?;
        let h_kernel32 = GetModuleHandleA(PCSTR(kernel32_name.as_ptr() as *const u8))?;

        let load_library_name = CString::new("LoadLibraryA")?;
        let load_library_addr = GetProcAddress(
            h_kernel32,
            PCSTR(load_library_name.as_ptr() as *const u8),
        ).ok_or("GetProcAddress failed")?;

        // Create remote thread
        let h_thread = CreateRemoteThread(
            h_process,
            None,
            0,
            Some(std::mem::transmute(load_library_addr)),
            Some(remote_mem),
            0,
            None,
        )?;

        // Wait for thread to complete
        WaitForSingleObject(h_thread, INFINITE);

        // Get exit code (HMODULE from LoadLibraryA)
        let mut exit_code: u32 = 0;
        GetExitCodeThread(h_thread, &mut exit_code)?;

        // Cleanup
        let _ = CloseHandle(h_thread);
        let _ = VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);

        if exit_code == 0 {
            Ok(None) // LoadLibraryA failed
        } else {
            Ok(Some(exit_code as usize))
        }
    }
}

/// RAII guard for process handle cleanup
struct ProcessHandleGuard(HANDLE);

impl Drop for ProcessHandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
