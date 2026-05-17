use serde::Serialize;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

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

#[derive(Debug, Clone, Serialize)]
pub struct BlacklistMatch {
    pub pid: u32,
    pub path: String,
    pub keyword: String,
}

pub fn scan_processes(keywords: Option<&[&str]>) -> Vec<BlacklistMatch> {
    let kw = keywords.unwrap_or(DEFAULT_BLACKLIST);
    let mut matches = Vec::new();

    let snap = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(h) if h != INVALID_HANDLE_VALUE => h,
        _ => return matches,
    };

    let mut pe = PROCESSENTRY32W::default();
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snap, &mut pe) }.is_err() {
        let _ = unsafe { CloseHandle(snap) };
        return matches;
    }

    loop {
        let pid = pe.th32ProcessID;
        if pid > 4 {
            if let Ok(h) = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
                if h != INVALID_HANDLE_VALUE {
                    let mut buf = [0u16; 1024];
                    let mut sz = buf.len() as u32;
                    let ok = unsafe {
                        QueryFullProcessImageNameW(
                            h,
                            PROCESS_NAME_FORMAT(0),
                            PWSTR(buf.as_mut_ptr()),
                            &mut sz,
                        )
                    };
                    if ok.is_ok() {
                        let path = String::from_utf16_lossy(&buf[..sz as usize]);
                        let lower = path.to_lowercase();
                        for &k in kw {
                            if lower.contains(&k.to_lowercase()) {
                                matches.push(BlacklistMatch {
                                    pid,
                                    path: path.clone(),
                                    keyword: k.to_string(),
                                });
                                break;
                            }
                        }
                    }
                    let _ = unsafe { CloseHandle(h) };
                }
            }
        }

        if unsafe { Process32NextW(snap, &mut pe) }.is_err() {
            break;
        }
    }

    let _ = unsafe { CloseHandle(snap) };
    matches
}
