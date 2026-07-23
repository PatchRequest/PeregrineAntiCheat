//! Microsoft-Windows-Threat-Intelligence consumer (ETW-TI).
//!
//! Parsing follows the supported path (Pavel Yosifovich / MSDN):
//!   EVENT_RECORD → TdhGetProperty / TdhGetPropertySize by **property name**
//! Hardcoded UserData offsets are intentionally avoided — layouts change with
//! EventDescriptor.Version, FILL_VAD keywords, and Windows builds.
//!
//! Requires elevated GUI + PPL (kernel set_ppl) for EnableTraceEx2 on this provider.

use std::collections::HashMap;
use std::mem::size_of;
use std::ptr::copy_nonoverlapping;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::*;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

const ETW_TI_GUID: GUID = GUID::from_u128(0xf4e1897c_bb5d_5668_f1d8_040f4d8dd344);
const SESSION_NAME: &str = "PeregrineETWThreatIntel";

// Modern granular TI keywords (wevtutil gp / Sanctum).
const KW_ALLOCVM_LOCAL: u64 = 0x1;
const KW_ALLOCVM_LOCAL_KERNEL: u64 = 0x2;
const KW_ALLOCVM_REMOTE: u64 = 0x4;
const KW_ALLOCVM_REMOTE_KERNEL: u64 = 0x8;
const KW_PROTECTVM_LOCAL: u64 = 0x10;
const KW_PROTECTVM_LOCAL_KERNEL: u64 = 0x20;
const KW_PROTECTVM_REMOTE: u64 = 0x40;
const KW_PROTECTVM_REMOTE_KERNEL: u64 = 0x80;
const KW_MAPVIEW_LOCAL: u64 = 0x100;
const KW_MAPVIEW_LOCAL_KERNEL: u64 = 0x200;
const KW_MAPVIEW_REMOTE: u64 = 0x400;
const KW_MAPVIEW_REMOTE_KERNEL: u64 = 0x800;
const KW_QUEUEAPC_REMOTE: u64 = 0x1000;
const KW_QUEUEAPC_REMOTE_KERNEL: u64 = 0x2000;
const KW_SETCTX_REMOTE: u64 = 0x4000;
const KW_SETCTX_REMOTE_KERNEL: u64 = 0x8000;
const KW_READVM_LOCAL: u64 = 0x10000;
const KW_READVM_REMOTE: u64 = 0x20000;
const KW_WRITEVM_LOCAL: u64 = 0x40000;
const KW_WRITEVM_REMOTE: u64 = 0x80000;
const KW_SUSPEND_THREAD: u64 = 0x100000;
const KW_RESUME_THREAD: u64 = 0x200000;
const KW_SUSPEND_PROCESS: u64 = 0x400000;
const KW_RESUME_PROCESS: u64 = 0x800000;

const TASK_ALLOCVM: u16 = 1;
const TASK_PROTECTVM: u16 = 2;
const TASK_MAPVIEW: u16 = 3;
const TASK_QUEUEUSERAPC: u16 = 4;
const TASK_SETTHREADCONTEXT: u16 = 5;
const TASK_READVM: u16 = 6;
const TASK_WRITEVM: u16 = 7;
const TASK_SUSPENDRESUME_THREAD: u16 = 8;
const TASK_SUSPENDRESUME_PROCESS: u16 = 9;

const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

const ERROR_SUCCESS: u32 = 0;
const ERROR_NOT_FOUND: u32 = 1168;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TiEvent {
    pub event_type: String,
    /// remote | local
    pub scope: String,
    /// critical | high | medium | low | info
    pub severity: String,
    pub caller_pid: u32,
    pub caller_tid: u32,
    pub caller_name: String,
    pub target_pid: u32,
    pub target_name: String,
    pub base_address: u64,
    pub region_size: u64,
    pub protection: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_protection: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocation_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_status: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_tid: Option<u32>,
    pub executable: bool,
    pub event_id: u16,
    /// true when BaseAddress/Protection came from TDH property names
    pub tdh_ok: bool,
}

pub type TiReceiver = mpsc::Receiver<TiEvent>;

struct SessionState {
    stop: Arc<AtomicBool>,
}

static TX: Mutex<Option<mpsc::Sender<TiEvent>>> = Mutex::new(None);
static SESSION: Mutex<Option<SessionState>> = Mutex::new(None);
static RATE: OnceLock<Mutex<HashMap<(u32, u32, u8), Instant>>> = OnceLock::new();

fn rate_allow(caller: u32, target: u32, kind: u8, min_interval: Duration) -> bool {
    let map = RATE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = map.lock().unwrap_or_else(|e| e.into_inner());
    let key = (caller, target, kind);
    let now = Instant::now();
    if let Some(prev) = g.get(&key) {
        if now.duration_since(*prev) < min_interval {
            return false;
        }
    }
    g.insert(key, now);
    if g.len() > 512 {
        g.retain(|_, t| now.duration_since(*t) < Duration::from_secs(30));
    }
    true
}

pub fn is_executable_protect(p: u32) -> bool {
    let low = p & 0xFF;
    (low & PAGE_EXECUTE) != 0
        || (low & PAGE_EXECUTE_READ) != 0
        || (low & PAGE_EXECUTE_READWRITE) != 0
        || (low & PAGE_EXECUTE_WRITECOPY) != 0
        || matches!(low, 0x10 | 0x20 | 0x40 | 0x80)
}

fn severity_for(event_type: &str, executable: bool) -> &'static str {
    match event_type {
        "QUEUEAPC_REMOTE" | "SETTHREADCONTEXT_REMOTE" | "WRITEVM_REMOTE" => "critical",
        "ALLOCVM_REMOTE" | "PROTECTVM_REMOTE" | "MAPVIEW_REMOTE" if executable => "critical",
        "SUSPEND_THREAD" | "RESUME_THREAD" | "SUSPEND_PROCESS" | "RESUME_PROCESS" => "high",
        "ALLOCVM_LOCAL" | "PROTECTVM_LOCAL" | "MAPVIEW_LOCAL" if executable => "high",
        "WRITEVM_LOCAL" => "high",
        "ALLOCVM_REMOTE" | "PROTECTVM_REMOTE" | "MAPVIEW_REMOTE" | "READVM_REMOTE" => "medium",
        _ if executable => "medium",
        _ => "info",
    }
}

fn is_remote_kw(kw: u64, remote: u64, remote_k: u64) -> bool {
    kw & (remote | remote_k) != 0
}
fn is_local_kw(kw: u64, local: u64, local_k: u64) -> bool {
    kw & (local | local_k) != 0
}

fn classify(kw: u64, task: u16) -> Option<(&'static str, &'static str)> {
    if kw & KW_SUSPEND_THREAD != 0 {
        return Some(("SUSPEND_THREAD", "remote"));
    }
    if kw & KW_RESUME_THREAD != 0 {
        return Some(("RESUME_THREAD", "remote"));
    }
    if kw & KW_SUSPEND_PROCESS != 0 {
        return Some(("SUSPEND_PROCESS", "remote"));
    }
    if kw & KW_RESUME_PROCESS != 0 {
        return Some(("RESUME_PROCESS", "remote"));
    }
    if is_remote_kw(kw, KW_QUEUEAPC_REMOTE, KW_QUEUEAPC_REMOTE_KERNEL) {
        return Some(("QUEUEAPC_REMOTE", "remote"));
    }
    if is_remote_kw(kw, KW_SETCTX_REMOTE, KW_SETCTX_REMOTE_KERNEL) {
        return Some(("SETTHREADCONTEXT_REMOTE", "remote"));
    }
    if kw & KW_WRITEVM_REMOTE != 0 {
        return Some(("WRITEVM_REMOTE", "remote"));
    }
    if kw & KW_READVM_REMOTE != 0 {
        return Some(("READVM_REMOTE", "remote"));
    }
    if kw & KW_WRITEVM_LOCAL != 0 {
        return Some(("WRITEVM_LOCAL", "local"));
    }
    if kw & KW_READVM_LOCAL != 0 {
        return Some(("READVM_LOCAL", "local"));
    }
    if is_remote_kw(kw, KW_ALLOCVM_REMOTE, KW_ALLOCVM_REMOTE_KERNEL) {
        return Some(("ALLOCVM_REMOTE", "remote"));
    }
    if is_local_kw(kw, KW_ALLOCVM_LOCAL, KW_ALLOCVM_LOCAL_KERNEL) {
        return Some(("ALLOCVM_LOCAL", "local"));
    }
    if is_remote_kw(kw, KW_PROTECTVM_REMOTE, KW_PROTECTVM_REMOTE_KERNEL) {
        return Some(("PROTECTVM_REMOTE", "remote"));
    }
    if is_local_kw(kw, KW_PROTECTVM_LOCAL, KW_PROTECTVM_LOCAL_KERNEL) {
        return Some(("PROTECTVM_LOCAL", "local"));
    }
    if is_remote_kw(kw, KW_MAPVIEW_REMOTE, KW_MAPVIEW_REMOTE_KERNEL) {
        return Some(("MAPVIEW_REMOTE", "remote"));
    }
    if is_local_kw(kw, KW_MAPVIEW_LOCAL, KW_MAPVIEW_LOCAL_KERNEL) {
        return Some(("MAPVIEW_LOCAL", "local"));
    }

    // Task fallback when keyword bits alone are insufficient.
    match task {
        TASK_ALLOCVM => {
            if is_local_kw(kw, KW_ALLOCVM_LOCAL, KW_ALLOCVM_LOCAL_KERNEL) {
                Some(("ALLOCVM_LOCAL", "local"))
            } else {
                Some(("ALLOCVM_REMOTE", "remote"))
            }
        }
        TASK_PROTECTVM => {
            if is_local_kw(kw, KW_PROTECTVM_LOCAL, KW_PROTECTVM_LOCAL_KERNEL)
                && !is_remote_kw(kw, KW_PROTECTVM_REMOTE, KW_PROTECTVM_REMOTE_KERNEL)
            {
                Some(("PROTECTVM_LOCAL", "local"))
            } else {
                Some(("PROTECTVM_REMOTE", "remote"))
            }
        }
        TASK_MAPVIEW => {
            if is_local_kw(kw, KW_MAPVIEW_LOCAL, KW_MAPVIEW_LOCAL_KERNEL)
                && !is_remote_kw(kw, KW_MAPVIEW_REMOTE, KW_MAPVIEW_REMOTE_KERNEL)
            {
                Some(("MAPVIEW_LOCAL", "local"))
            } else {
                Some(("MAPVIEW_REMOTE", "remote"))
            }
        }
        TASK_QUEUEUSERAPC => Some(("QUEUEAPC_REMOTE", "remote")),
        TASK_SETTHREADCONTEXT => Some(("SETTHREADCONTEXT_REMOTE", "remote")),
        TASK_READVM => {
            if kw & KW_READVM_LOCAL != 0 && kw & KW_READVM_REMOTE == 0 {
                Some(("READVM_LOCAL", "local"))
            } else {
                Some(("READVM_REMOTE", "remote"))
            }
        }
        TASK_WRITEVM => {
            if kw & KW_WRITEVM_LOCAL != 0 && kw & KW_WRITEVM_REMOTE == 0 {
                Some(("WRITEVM_LOCAL", "local"))
            } else {
                Some(("WRITEVM_REMOTE", "remote"))
            }
        }
        TASK_SUSPENDRESUME_THREAD => {
            if kw & KW_RESUME_THREAD != 0 {
                Some(("RESUME_THREAD", "remote"))
            } else {
                Some(("SUSPEND_THREAD", "remote"))
            }
        }
        TASK_SUSPENDRESUME_PROCESS => {
            if kw & KW_RESUME_PROCESS != 0 {
                Some(("RESUME_PROCESS", "remote"))
            } else {
                Some(("SUSPEND_PROCESS", "remote"))
            }
        }
        _ => None,
    }
}

fn pid_to_name(pid: u32) -> String {
    if pid == 0 || pid == 4 {
        return if pid == 0 {
            "System Idle".into()
        } else {
            "System".into()
        };
    }
    unsafe {
        let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) if h != INVALID_HANDLE_VALUE => h,
            _ => return String::new(),
        };
        let mut buf = [0u16; 260];
        let mut sz = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut sz,
        );
        let _ = CloseHandle(h);
        if ok.is_ok() && sz > 0 {
            let path = String::from_utf16_lossy(&buf[..sz as usize]);
            path.rsplit('\\').next().unwrap_or(&path).to_string()
        } else {
            String::new()
        }
    }
}

// ---------------------------------------------------------------------------
// TDH property helpers (schema-driven, version-safe)
// ---------------------------------------------------------------------------

/// Fetch a property buffer by UTF-16 name via TdhGetProperty.
fn tdh_property_bytes(event: *const EVENT_RECORD, name: &str) -> Option<Vec<u8>> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // PropertyName is a ULONGLONG that holds a pointer to the wide name.
    // ArrayIndex = ULONG_MAX → scalar (not array element).
    let desc = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: wide.as_ptr() as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let descs = [desc];

    let mut size: u32 = 0;
    let st = unsafe { TdhGetPropertySize(event, None, &descs, &mut size) };
    if st == ERROR_NOT_FOUND || size == 0 {
        return None;
    }
    if st != ERROR_SUCCESS {
        // Some builds return success only after size query with ERROR_INSUFFICIENT_BUFFER pattern;
        // if size was filled, continue.
        if size == 0 {
            return None;
        }
    }

    let mut buf = vec![0u8; size as usize];
    let st = unsafe { TdhGetProperty(event, None, &descs, &mut buf) };
    if st != ERROR_SUCCESS {
        return None;
    }
    Some(buf)
}

fn tdh_u32(event: *const EVENT_RECORD, name: &str) -> Option<u32> {
    let buf = tdh_property_bytes(event, name)?;
    match buf.len() {
        1 => Some(buf[0] as u32),
        2 => Some(u16::from_le_bytes([buf[0], buf[1]]) as u32),
        4 => Some(u32::from_le_bytes(buf[0..4].try_into().ok()?)),
        8 => Some(u64::from_le_bytes(buf[0..8].try_into().ok()?) as u32),
        _ => None,
    }
}

fn tdh_u64(event: *const EVENT_RECORD, name: &str) -> Option<u64> {
    let buf = tdh_property_bytes(event, name)?;
    match buf.len() {
        4 => Some(u32::from_le_bytes(buf[0..4].try_into().ok()?) as u64),
        8 => Some(u64::from_le_bytes(buf[0..8].try_into().ok()?)),
        // POINTER on x64 is 8; some schemas report as hex string via Format — we only take raw.
        _ => None,
    }
}

/// First matching property among alternate names (manifest renames across versions).
fn tdh_u32_any(event: *const EVENT_RECORD, names: &[&str]) -> Option<u32> {
    for n in names {
        if let Some(v) = tdh_u32(event, n) {
            return Some(v);
        }
    }
    None
}

fn tdh_u64_any(event: *const EVENT_RECORD, names: &[&str]) -> Option<u64> {
    for n in names {
        if let Some(v) = tdh_u64(event, n) {
            return Some(v);
        }
    }
    None
}

/// Pull the fields we care about via TDH property names from the live schema.
fn tdh_extract(event: *const EVENT_RECORD) -> TdhFields {
    let caller_pid = tdh_u32_any(event, &["CallingProcessId"]).unwrap_or(0);
    let caller_tid = tdh_u32_any(event, &["CallingThreadId"]).unwrap_or(0);
    let target_pid = tdh_u32_any(event, &["TargetProcessId"]).unwrap_or(0);
    let base_address = tdh_u64_any(event, &["BaseAddress", "Pc", "ApcRoutine"]).unwrap_or(0);
    let region_size =
        tdh_u64_any(event, &["RegionSize", "ViewSize", "BytesCopied"]).unwrap_or(0);
    let protection = tdh_u32_any(event, &["ProtectionMask"]).unwrap_or(0);
    let last_protection = tdh_u32_any(event, &["LastProtectionMask"]);
    let allocation_type = tdh_u32_any(event, &["AllocationType"]);
    let operation_status = tdh_u32_any(event, &["OperationStatus"]);
    let target_tid = tdh_u32_any(event, &["TargetThreadId", "ThreadId"]);

    // Consider TDH successful if we got at least caller or target or a base address.
    let tdh_ok = caller_pid != 0 || target_pid != 0 || base_address != 0 || protection != 0;

    TdhFields {
        caller_pid,
        caller_tid,
        target_pid,
        base_address,
        region_size,
        protection,
        last_protection,
        allocation_type,
        operation_status,
        target_tid,
        tdh_ok,
    }
}

struct TdhFields {
    caller_pid: u32,
    caller_tid: u32,
    target_pid: u32,
    base_address: u64,
    region_size: u64,
    protection: u32,
    last_protection: Option<u32>,
    allocation_type: Option<u32>,
    operation_status: Option<u32>,
    target_tid: Option<u32>,
    tdh_ok: bool,
}

fn emit(ti: TiEvent) {
    if ti.event_type.contains("READVM") {
        let kind = if ti.event_type.contains("REMOTE") { 1 } else { 2 };
        if !rate_allow(ti.caller_pid, ti.target_pid, kind, Duration::from_millis(2000)) {
            return;
        }
    }
    if let Ok(g) = TX.lock() {
        if let Some(tx) = g.as_ref() {
            let _ = tx.send(ti);
        }
    }
}

unsafe extern "system" fn trace_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let ev = unsafe { &*record };
    let kw = ev.EventHeader.EventDescriptor.Keyword;
    let event_id = ev.EventHeader.EventDescriptor.Id;
    let task = ev.EventHeader.EventDescriptor.Task;
    let hdr_pid = ev.EventHeader.ProcessId;
    let hdr_tid = ev.EventHeader.ThreadId;

    let Some((event_type, scope)) = classify(kw, task) else {
        return;
    };

    // Schema-driven field extract (correct path).
    let mut f = tdh_extract(record);

    // Header fallbacks — EventHeader.ProcessId is the emitting process (caller).
    if f.caller_pid == 0 && hdr_pid != 0 {
        f.caller_pid = hdr_pid;
    }
    if f.caller_tid == 0 && hdr_tid != 0 {
        f.caller_tid = hdr_tid;
    }

    // Suspend events often expose ThreadId as the suspended TID.
    let is_suspend = matches!(
        event_type,
        "SUSPEND_THREAD" | "RESUME_THREAD" | "SUSPEND_PROCESS" | "RESUME_PROCESS"
    );
    if is_suspend {
        if f.target_tid.is_none() && f.base_address != 0 && f.base_address <= u32::MAX as u64 {
            f.target_tid = Some(f.base_address as u32);
        }
        // Put suspended TID into base_address for UI continuity when only ThreadId exists.
        if let Some(tid) = f.target_tid {
            if f.base_address == 0 {
                f.base_address = tid as u64;
            }
        }
    }

    let exec = is_executable_protect(f.protection)
        || f.last_protection.map(is_executable_protect).unwrap_or(false);

    let ti = TiEvent {
        event_type: event_type.to_string(),
        scope: scope.to_string(),
        severity: severity_for(event_type, exec).into(),
        caller_pid: f.caller_pid,
        caller_tid: f.caller_tid,
        caller_name: pid_to_name(f.caller_pid),
        target_pid: f.target_pid,
        target_name: pid_to_name(f.target_pid),
        base_address: f.base_address,
        region_size: f.region_size,
        protection: f.protection,
        last_protection: f.last_protection,
        allocation_type: f.allocation_type,
        operation_status: f.operation_status,
        target_tid: f.target_tid,
        executable: exec,
        event_id,
        tdh_ok: f.tdh_ok,
    };
    emit(ti);
}

fn enable_keyword_mask() -> u64 {
    // Subscribe to everything TI can emit; TDH names fields regardless of keyword combo.
    // Explicit bits alone can miss build-specific high bits (FILL_VAD etc.).
    u64::MAX
}

pub fn start_etw_session() -> Result<TiReceiver, String> {
    let mut sess = SESSION.lock().map_err(|e| e.to_string())?;
    if sess.is_some() {
        return Err("ETW-TI session already running".into());
    }

    let (tx, rx) = mpsc::channel();
    {
        let mut g = TX.lock().map_err(|e| e.to_string())?;
        *g = Some(tx);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let wide: Vec<u16> = SESSION_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    let props_size = size_of::<EVENT_TRACE_PROPERTIES>();
    let total = props_size + wide.len() * 2;
    let mut buf = vec![0u8; total];
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

    unsafe {
        (*props).Wnode.BufferSize = total as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).LoggerNameOffset = props_size as u32;
        copy_nonoverlapping(
            wide.as_ptr(),
            buf.as_mut_ptr().add(props_size) as *mut u16,
            wide.len(),
        );
    }

    let mut stop_buf = buf.clone();
    unsafe {
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(wide.as_ptr()),
            stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }

    let mut handle = CONTROLTRACE_HANDLE::default();
    let err = unsafe { StartTraceW(&mut handle, PCWSTR(wide.as_ptr()), props) };
    if err != WIN32_ERROR(0) {
        let mut g = TX.lock().map_err(|e| e.to_string())?;
        *g = None;
        return Err(format!("StartTraceW failed: {:?}", err));
    }

    let enable_kw = enable_keyword_mask();
    let err = unsafe {
        EnableTraceEx2(
            handle,
            &ETW_TI_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            5, // TRACE_LEVEL_VERBOSE
            enable_kw,
            0,
            0,
            None,
        )
    };
    if err != WIN32_ERROR(0) {
        let mut sb = buf.clone();
        unsafe {
            let _ = ControlTraceW(
                handle,
                PCWSTR::null(),
                sb.as_mut_ptr() as *mut _,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
        let mut g = TX.lock().map_err(|e| e.to_string())?;
        *g = None;
        return Err(format!("EnableTraceEx2 failed (need PPL?): {:?}", err));
    }

    let mut wide_mut = wide.clone();
    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
    logfile.LoggerName = PWSTR(wide_mut.as_mut_ptr());
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(trace_callback);

    let trace_handle = unsafe { OpenTraceW(&mut logfile) };
    if trace_handle.Value == u64::MAX {
        let mut sb = buf.clone();
        unsafe {
            let _ = ControlTraceW(
                handle,
                PCWSTR::null(),
                sb.as_mut_ptr() as *mut _,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
        let mut g = TX.lock().map_err(|e| e.to_string())?;
        *g = None;
        return Err("OpenTraceW failed".into());
    }

    std::thread::spawn(move || {
        unsafe {
            let _ = ProcessTrace(&[trace_handle], None, None);
        }
    });

    let buf2 = buf;
    let wide2 = wide;
    let stop_watcher = stop.clone();
    std::thread::spawn(move || {
        while !stop_watcher.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(200));
        }
        unsafe {
            let _ = CloseTrace(trace_handle);
            let _ = ControlTraceW(
                handle,
                PCWSTR(wide2.as_ptr()),
                buf2.as_ptr() as *mut _,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
    });

    *sess = Some(SessionState { stop });
    Ok(rx)
}

pub fn stop_etw_session() -> Result<(), String> {
    let mut sess = SESSION.lock().map_err(|e| e.to_string())?;
    let Some(state) = sess.take() else {
        return Err("ETW-TI session not running".into());
    };
    state.stop.store(true, Ordering::Relaxed);
    if let Ok(mut g) = TX.lock() {
        *g = None;
    }
    Ok(())
}

pub fn is_running() -> bool {
    SESSION.lock().map(|s| s.is_some()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_by_keyword() {
        assert_eq!(
            classify(KW_WRITEVM_REMOTE, 0).map(|x| x.0),
            Some("WRITEVM_REMOTE")
        );
        assert_eq!(
            classify(KW_ALLOCVM_LOCAL, 0).map(|x| x.0),
            Some("ALLOCVM_LOCAL")
        );
        assert_eq!(
            classify(KW_PROTECTVM_REMOTE, 0).map(|x| x.0),
            Some("PROTECTVM_REMOTE")
        );
        assert_eq!(
            classify(KW_SUSPEND_THREAD, 0).map(|x| x.0),
            Some("SUSPEND_THREAD")
        );
    }

    #[test]
    fn classify_task_fallback() {
        assert_eq!(
            classify(0, TASK_WRITEVM).map(|x| x.0),
            Some("WRITEVM_REMOTE")
        );
        assert_eq!(
            classify(KW_ALLOCVM_REMOTE, TASK_ALLOCVM).map(|x| x.0),
            Some("ALLOCVM_REMOTE")
        );
    }

    #[test]
    fn executable_protect_detects_rwx() {
        assert!(is_executable_protect(0x40));
        assert!(is_executable_protect(0x20));
        assert!(!is_executable_protect(0x04));
    }

    #[test]
    fn severity_critical_for_remote_write() {
        assert_eq!(severity_for("WRITEVM_REMOTE", false), "critical");
        assert_eq!(severity_for("ALLOCVM_REMOTE", true), "critical");
        assert_eq!(severity_for("PROTECTVM_REMOTE", true), "critical");
    }

    #[test]
    fn ti_event_serialization() {
        let ev = TiEvent {
            event_type: "PROTECTVM_REMOTE".into(),
            scope: "remote".into(),
            severity: "critical".into(),
            caller_pid: 100,
            caller_tid: 200,
            caller_name: "cheat.exe".into(),
            target_pid: 300,
            target_name: "game.exe".into(),
            base_address: 0x164088A0000,
            region_size: 4096,
            protection: 0x40,
            last_protection: Some(0x04),
            allocation_type: None,
            operation_status: Some(0),
            target_tid: None,
            executable: true,
            event_id: 2,
            tdh_ok: true,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"tdh_ok\":true"));
        assert!(json.contains("\"protection\":64"));
        assert!(json.contains("\"last_protection\":4"));
    }

    #[test]
    fn etw_ti_guid_value() {
        assert_eq!(
            ETW_TI_GUID,
            GUID::from_u128(0xf4e1897c_bb5d_5668_f1d8_040f4d8dd344),
        );
    }

    #[test]
    fn pid_to_name_system_pids() {
        assert_eq!(pid_to_name(0), "System Idle");
        assert_eq!(pid_to_name(4), "System");
    }
}
