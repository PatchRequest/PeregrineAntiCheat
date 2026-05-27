use super::pe::*;
use serde::Serialize;
use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION};

#[derive(Debug, Clone, Serialize)]
pub struct ThreadInfo {
    pub tid: u32,
    pub rip: u64,
    pub start_address: u64,
    pub rip_module: Option<String>,
    pub start_module: Option<String>,
    pub suspicious: bool,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
}

#[repr(C)]
#[allow(non_snake_case)]
struct M128A {
    Low: u64,
    High: i64,
}

#[repr(C, align(16))]
#[allow(non_snake_case)]
struct CONTEXT64 {
    P1Home: u64,
    P2Home: u64,
    P3Home: u64,
    P4Home: u64,
    P5Home: u64,
    P6Home: u64,
    ContextFlags: u32,
    MxCsr: u32,
    SegCs: u16,
    SegDs: u16,
    SegEs: u16,
    SegFs: u16,
    SegGs: u16,
    SegSs: u16,
    EFlags: u32,
    Dr0: u64,
    Dr1: u64,
    Dr2: u64,
    Dr3: u64,
    Dr6: u64,
    Dr7: u64,
    Rax: u64,
    Rcx: u64,
    Rdx: u64,
    Rbx: u64,
    Rsp: u64,
    Rbp: u64,
    Rsi: u64,
    Rdi: u64,
    R8: u64,
    R9: u64,
    R10: u64,
    R11: u64,
    R12: u64,
    R13: u64,
    R14: u64,
    R15: u64,
    Rip: u64,
    FltSave: [u8; 512],
    VectorRegister: [M128A; 26],
    VectorControl: u64,
    DebugControl: u64,
    LastBranchToRip: u64,
    LastBranchFromRip: u64,
    LastExceptionToRip: u64,
    LastExceptionFromRip: u64,
}

const CONTEXT_AMD64: u32 = 0x00100000;
const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x10;
const CONTEXT_FULL: u32 = CONTEXT_AMD64 | 0x07 | 0x10;

extern "system" {
    fn GetThreadContext(hThread: windows::Win32::Foundation::HANDLE, lpContext: *mut CONTEXT64)
        -> i32;
    fn NtQueryInformationThread(
        ThreadHandle: windows::Win32::Foundation::HANDLE,
        ThreadInformationClass: u32,
        ThreadInformation: *mut u64,
        ThreadInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
}

const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;

pub fn check_all_threads(pid: u32) -> Result<Vec<ThreadInfo>, String> {
    let proc = ProcessHandle::open(pid).ok_or("OpenProcess failed")?;
    let modules = proc.modules();

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }
        .map_err(|e| format!("snapshot: {e}"))?;
    if snap == INVALID_HANDLE_VALUE {
        return Err("CreateToolhelp32Snapshot failed".into());
    }

    let mut results = Vec::new();
    let mut te = THREADENTRY32::default();
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    if unsafe { Thread32First(snap, &mut te) }.is_err() {
        let _ = unsafe { CloseHandle(snap) };
        return Ok(results);
    }

    loop {
        if te.th32OwnerProcessID == pid {
            let tid = te.th32ThreadID;
            let th = unsafe {
                OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, false, tid)
            };
            if let Ok(th) = th {
                if th != INVALID_HANDLE_VALUE {
                    let mut ctx: CONTEXT64 = unsafe { std::mem::zeroed() };
                    ctx.ContextFlags = CONTEXT_FULL;

                    let ok = unsafe { GetThreadContext(th, &mut ctx) };
                    if ok != 0 {
                        let rip = ctx.Rip;

                        let mut start_addr: u64 = 0;
                        unsafe {
                            NtQueryInformationThread(
                                th,
                                THREAD_QUERY_SET_WIN32_START_ADDRESS,
                                &mut start_addr,
                                8,
                                std::ptr::null_mut(),
                            );
                        }

                        let rip_mod = modules
                            .iter()
                            .find(|m| rip >= m.base as u64 && rip < (m.base + m.size) as u64)
                            .map(|m| m.name().to_string());

                        let start_mod = if start_addr != 0 {
                            modules
                                .iter()
                                .find(|m| start_addr >= m.base as u64 && start_addr < (m.base + m.size) as u64)
                                .map(|m| m.name().to_string())
                        } else {
                            None
                        };

                        let suspicious = rip_mod.is_none() || (start_addr != 0 && start_mod.is_none());

                        results.push(ThreadInfo {
                            tid,
                            rip,
                            start_address: start_addr,
                            rip_module: rip_mod,
                            start_module: start_mod,
                            suspicious,
                            dr0: ctx.Dr0,
                            dr1: ctx.Dr1,
                            dr2: ctx.Dr2,
                            dr3: ctx.Dr3,
                            dr6: ctx.Dr6,
                            dr7: ctx.Dr7,
                        });
                    }
                    let _ = unsafe { CloseHandle(th) };
                }
            }
        }

        if unsafe { Thread32Next(snap, &mut te) }.is_err() {
            break;
        }
    }

    let _ = unsafe { CloseHandle(snap) };
    Ok(results)
}
