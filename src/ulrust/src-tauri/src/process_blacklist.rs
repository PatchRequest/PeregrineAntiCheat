use serde::{Deserialize, Serialize};
use windows::core::PWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::*;

const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

/// Default blacklist keywords for suspicious processes
pub const DEFAULT_BLACKLIST: &[&str] = &[
    "GuidedHacking",
    "CheatEngine",
    "x64dbg",
    "x32dbg",
    "IDA",
    "dnSpy",
    "ProcessHacker",
    "ReClass",
    "Cheat",
    "Trainer",
    "Injector",
    "DLLInjector",
];

/// Result of a blacklist scan match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistMatch {
    pub pid: u32,
    pub path: String,
    pub keyword: String,
}

/// Scan all running processes for blacklisted keywords
pub fn scan_processes_for_blacklist(blacklist_keywords: Option<&[&str]>) -> Vec<BlacklistMatch> {
    let keywords = blacklist_keywords.unwrap_or(DEFAULT_BLACKLIST);
    let mut matches = Vec::new();

    unsafe {
        // Create snapshot of all processes
        let snapshot_result = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot_result.is_err() {
            return matches;
        }

        let snapshot = snapshot_result.unwrap();
        if snapshot.is_invalid() {
            return matches;
        }

        let mut pe32 = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        // Get first process
        if Process32FirstW(snapshot, &mut pe32).is_err() {
            let _ = CloseHandle(snapshot);
            return matches;
        }

        loop {
            let pid = pe32.th32ProcessID;

            // Skip System processes (PID 0 and 4)
            if pid != 0 && pid != 4 {
                // Try to open process and get full path
                if let Ok(h_process) = OpenProcess(
                    PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_LIMITED_INFORMATION),
                    false,
                    pid,
                ) {
                    let mut path_buffer = vec![0u16; 1024];
                    let mut path_size = path_buffer.len() as u32;

                    if QueryFullProcessImageNameW(
                        h_process,
                        PROCESS_NAME_WIN32,
                        PWSTR(path_buffer.as_mut_ptr()),
                        &mut path_size,
                    ).is_ok() {
                        // Convert to String
                        let full_path = String::from_utf16_lossy(&path_buffer[..path_size as usize]);
                        let full_path_lower = full_path.to_lowercase();

                        // Check against blacklist (case-insensitive)
                        for &keyword in keywords {
                            if full_path_lower.contains(&keyword.to_lowercase()) {
                                matches.push(BlacklistMatch {
                                    pid,
                                    path: full_path.clone(),
                                    keyword: keyword.to_string(),
                                });
                                break;
                            }
                        }
                    }

                    let _ = CloseHandle(h_process);
                }
            }

            // Move to next process
            if Process32NextW(snapshot, &mut pe32).is_err() {
                break;
            }
        }

        let _ = CloseHandle(snapshot);
    }

    matches
}
