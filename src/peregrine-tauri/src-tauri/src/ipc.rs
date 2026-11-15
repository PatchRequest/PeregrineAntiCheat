//! Named-pipe server for telemetry from the injected Game / Sensor DLLs.
//!
//! Trust model
//!   * The pipe is writable by any authenticated local user, because the DLL
//!     runs inside medium-IL game processes. Being able to connect therefore
//!     proves nothing.
//!   * Every connection is authenticated by the client PID the pipe driver
//!     reports (`GetNamedPipeClientProcessId` — not something the client can
//!     choose) against the kernel's own inject bookkeeping
//!     (`IOCTL_PEREGRINE_QUERY_INJECTED`). A process the kernel did not inject
//!     is disconnected before a single byte is read.
//!   * `callerPID` and `role` in every forwarded message are overwritten with
//!     those verified values. Message *content* is still only a claim made by
//!     code running inside that process, and must never promote a PID to
//!     protected/trusted — only the kernel does that.
//!
//!   * An authenticated client is still hostile: a Sensor target *is* the
//!     cheat. Each connection is therefore rate-limited, the queue to the UI
//!     is bounded, and the number of connections is capped. Whatever is
//!     dropped is counted and reported (`IpcFlood`), never dropped silently.
//!   * The identity is re-checked for the lifetime of the connection: the
//!     server holds a handle to the authenticated process and stops reading
//!     the moment that process is gone, so a pipe handle passed on to another
//!     process cannot keep speaking under the old PID.
//!
//! Clients get write access only, and explicitly not FILE_CREATE_PIPE_INSTANCE:
//! with it, any local process could create its own instance of this pipe name
//! and swallow the DLL's connections.

use crate::driver_comm::{DriverHandle, InjectRole};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::time::Instant;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    ReadFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_INBOUND,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};

const PIPE_NAME: &str = r"\\.\pipe\peregrine_ipc";
const READ_BUF_SIZE: usize = 64 * 1024;

/// The DLL formats every message into a 1 KiB buffer. Anything that has not
/// produced a complete JSON object within this many bytes is not our DLL.
const MAX_PENDING_BYTES: usize = 16 * 1024;

/// Messages waiting for the UI. A full queue drops (and counts) instead of
/// growing without bound inside this elevated process.
const QUEUE_DEPTH: usize = 8192;

/// Per-connection budget. The DLL limits itself to a few messages per key and
/// second; a client far above that is not our DLL behaving normally.
const CLIENT_BURST: f64 = 200.0;
const CLIENT_MSGS_PER_SEC: f64 = 100.0;

/// Concurrent connections (each costs a thread and a read buffer).
const MAX_CLIENTS: usize = 64;
static ACTIVE_CLIENTS: AtomicUsize = AtomicUsize::new(0);

/// SYSTEM + Administrators: full control.
/// Authenticated Users: 0x00120192 =
///   FILE_GENERIC_WRITE & ~FILE_CREATE_PIPE_INSTANCE | FILE_READ_ATTRIBUTES
/// i.e. connect and write, but never create a server instance.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00120192;;;AU)";

pub enum IpcEvent {
    /// A message from a kernel-verified injected process, `callerPID` / `role` stamped.
    Message(serde_json::Value),
    /// The server came up, or is unable to serve (pipe name taken, API failure).
    ServerStatus { online: bool, detail: String },
}

pub fn start_ipc_server() -> Receiver<IpcEvent> {
    let (tx, rx) = std::sync::mpsc::sync_channel(QUEUE_DEPTH);
    std::thread::spawn(move || run_server(tx));
    rx
}

fn status(tx: &SyncSender<IpcEvent>, online: bool, detail: impl Into<String>) {
    // Never block the accept loop on a full queue; the next status change
    // (or the UI reading `backend_status`) corrects a lost one.
    let _ = tx.try_send(IpcEvent::ServerStatus { online, detail: detail.into() });
}

/// Security descriptor for the pipe. Allocated once and intentionally kept for
/// the lifetime of the server thread, which is the lifetime of the process.
fn pipe_security_descriptor() -> Result<PSECURITY_DESCRIPTOR, String> {
    let sddl: Vec<u16> = PIPE_SDDL.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .map_err(|e| format!("building pipe security descriptor failed: {e}"))?;
    Ok(sd)
}

fn create_instance(
    name: &[u16],
    sa: &SECURITY_ATTRIBUTES,
    first_instance: bool,
) -> Result<HANDLE, String> {
    // FIRST_PIPE_INSTANCE: if another process already owns this pipe name, fail
    // instead of silently becoming one more instance of *their* pipe.
    let mut open_mode = PIPE_ACCESS_INBOUND;
    if first_instance {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }

    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR(name.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(open_mode.0),
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            0,
            READ_BUF_SIZE as u32,
            0,
            Some(sa),
        )
    };

    if pipe == INVALID_HANDLE_VALUE {
        return Err(format!(
            "CreateNamedPipeW failed: {}",
            windows::core::Error::from_win32()
        ));
    }
    Ok(pipe)
}

fn run_server(tx: SyncSender<IpcEvent>) {
    let name: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    let sd = match pipe_security_descriptor() {
        Ok(sd) => sd,
        Err(e) => {
            // Without the descriptor the pipe would get a default DACL; refuse
            // to serve rather than run with an access policy nobody chose.
            status(&tx, false, e);
            return;
        }
    };
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };

    // The very first instance must be the first instance system-wide.
    let mut listening = loop {
        match create_instance(&name, &sa, true) {
            Ok(pipe) => break pipe,
            Err(e) => {
                status(&tx, false, format!("{e} (is another process squatting the pipe name?)"));
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        }
    };
    status(&tx, true, "listening");

    loop {
        // ERROR_PIPE_CONNECTED (client raced in before the call) is reported
        // as an error by the binding but means "connected".
        if let Err(e) = unsafe { ConnectNamedPipe(listening, None) } {
            const ERROR_PIPE_CONNECTED: u32 = 535;
            if e.code() != windows::core::HRESULT::from_win32(ERROR_PIPE_CONNECTED) {
                eprintln!("[DBG] IPC ConnectNamedPipe failed: {e}");
                let _ = unsafe { DisconnectNamedPipe(listening) };
                continue;
            }
        }

        // Create the next listening instance *before* releasing the connected
        // one, so there is never a moment in which no instance of ours exists
        // and the name could be taken over.
        let next = loop {
            match create_instance(&name, &sa, false) {
                Ok(pipe) => break pipe,
                Err(e) => {
                    status(&tx, false, e);
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        };
        status(&tx, true, "listening");

        let connected = std::mem::replace(&mut listening, next);
        let close = |pipe: HANDLE| unsafe {
            let _ = DisconnectNamedPipe(pipe);
            let _ = CloseHandle(pipe);
        };

        if ACTIVE_CLIENTS.load(Ordering::Relaxed) >= MAX_CLIENTS {
            eprintln!("[DBG] IPC connection refused: {MAX_CLIENTS} clients already connected");
            close(connected);
            continue;
        }

        ACTIVE_CLIENTS.fetch_add(1, Ordering::Relaxed);
        let client_tx = tx.clone();
        let raw = connected.0 as usize;
        let spawned = std::thread::Builder::new()
            .name("ipc-client".into())
            .spawn(move || {
                let pipe = HANDLE(raw as *mut _);
                serve_client(pipe, &client_tx);
                unsafe {
                    let _ = DisconnectNamedPipe(pipe);
                    let _ = CloseHandle(pipe);
                }
                ACTIVE_CLIENTS.fetch_sub(1, Ordering::Relaxed);
            });
        if let Err(e) = spawned {
            // Out of threads: drop this client, keep accepting.
            eprintln!("[DBG] IPC client thread could not be started: {e}");
            ACTIVE_CLIENTS.fetch_sub(1, Ordering::Relaxed);
            close(connected);
        }
    }
}

/// Handle to the authenticated client process, closed on drop.
struct ClientProcess(HANDLE);

impl ClientProcess {
    fn alive(&self) -> bool {
        unsafe { WaitForSingleObject(self.0, 0) != WAIT_OBJECT_0 }
    }
}

impl Drop for ClientProcess {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Identifies the client through the kernel. `Err` means "not ours" or
/// "cannot be verified" — both are treated as a rejection (fail closed).
fn authenticate(pipe: HANDLE) -> Result<(u32, InjectRole, ClientProcess), String> {
    let mut pid = 0u32;
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }
        .map_err(|e| format!("GetNamedPipeClientProcessId failed: {e}"))?;

    // Pin the process *before* asking the kernel about the PID: the kernel
    // forgets an injected PID when its process exits, so a positive answer
    // while we hold this handle is about exactly this process, not about a
    // later one that got the same PID.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }
        .map(ClientProcess)
        .map_err(|e| format!("cannot open client PID {pid}: {e}"))?;

    match DriverHandle::open()?.query_injected(pid)? {
        Some(role) if process.alive() => Ok((pid, role, process)),
        Some(_) => Err(format!("PID {pid} exited during authentication")),
        None => Err(format!("PID {pid} is not a process the kernel injected")),
    }
}

/// Token bucket for one connection.
struct Budget {
    tokens: f64,
    last: Instant,
}

impl Budget {
    fn new() -> Self {
        Self { tokens: CLIENT_BURST, last: Instant::now() }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let refill = now.duration_since(self.last).as_secs_f64() * CLIENT_MSGS_PER_SEC;
        self.tokens = (self.tokens + refill).min(CLIENT_BURST);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Forwards one message unless the client is over budget or the UI queue is
/// full; `dropped` accumulates what was not forwarded and is announced ahead
/// of the next message that does get through. `false`: the receiver is gone.
fn forward(
    tx: &SyncSender<IpcEvent>,
    budget: &mut Budget,
    dropped: &mut u64,
    pid: u32,
    role: InjectRole,
    msg: serde_json::Value,
) -> bool {
    if !budget.take() {
        *dropped += 1;
        return true;
    }

    if *dropped > 0 {
        let notice = serde_json::json!({
            "event": "IpcFlood",
            "callerPID": pid,
            "role": role.as_str(),
            "dropped": *dropped,
        });
        match tx.try_send(IpcEvent::Message(notice)) {
            Ok(()) => *dropped = 0,
            Err(TrySendError::Full(_)) => {
                *dropped += 1;
                return true;
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }

    match tx.try_send(IpcEvent::Message(msg)) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            *dropped += 1;
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

fn serve_client(pipe: HANDLE, tx: &SyncSender<IpcEvent>) {
    let (pid, role, process) = match authenticate(pipe) {
        Ok(identity) => identity,
        Err(reason) => {
            // Deliberately not forwarded to the UI log: any local process can
            // connect, so a UI line per rejection would itself be a flood vector.
            eprintln!("[DBG] IPC client rejected: {reason}");
            return;
        }
    };
    eprintln!("[DBG] IPC client connected: PID {pid} role={}", role.as_str());

    let mut buf = vec![0u8; READ_BUF_SIZE];
    let mut pending: Vec<u8> = Vec::new();
    let mut budget = Budget::new();
    let mut dropped = 0u64;

    loop {
        let mut read = 0u32;
        let ok = unsafe { ReadFile(pipe, Some(&mut buf), Some(&mut read), None) };
        if ok.is_err() || read == 0 {
            break;
        }
        // Whoever wrote these bytes must still be the process we verified.
        if !process.alive() {
            eprintln!("[DBG] IPC PID {pid}: data after the authenticated process exited, dropping");
            break;
        }
        pending.extend_from_slice(&buf[..read as usize]);

        // Each message is one {...} object, written back to back. Scan with a
        // cursor and remove the consumed prefix once per read.
        let mut start = 0usize;
        while let Some(len) = find_json_end(&pending[start..]) {
            let end = start + len;
            if let Some(msg) = parse_message(&pending[start..=end], pid, role) {
                if !forward(tx, &mut budget, &mut dropped, pid, role, msg) {
                    return;
                }
            }
            start = end + 1;
        }
        pending.drain(..start);

        if pending.len() > MAX_PENDING_BYTES {
            eprintln!("[DBG] IPC PID {pid}: no JSON boundary in {} bytes, dropping client", pending.len());
            break;
        }
    }

    eprintln!("[DBG] IPC client disconnected: PID {pid}");
}

/// Parses one object and stamps the kernel-verified identity over whatever
/// the client claimed about itself.
fn parse_message(chunk: &[u8], pid: u32, role: InjectRole) -> Option<serde_json::Value> {
    let text = std::str::from_utf8(chunk).ok()?;
    let mut value: serde_json::Value = serde_json::from_str(text).ok()?;
    let obj = value.as_object_mut()?;
    obj.insert("callerPID".into(), serde_json::Value::from(pid));
    obj.insert("role".into(), serde_json::Value::from(role.as_str()));
    Some(value)
}

/// Index of the `}` closing the first top-level JSON object in `data`.
fn find_json_end(data: &[u8]) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;

    for (i, &b) in data.iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        if b == b'\\' && in_string {
            escape = true;
            continue;
        }
        if b == b'"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
            if depth <= 0 {
                return Some(i);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_end_handles_nesting_and_strings() {
        assert_eq!(find_json_end(br#"{"a":1}{"b":2}"#), Some(6));
        assert_eq!(find_json_end(br#"{"a":{"b":"}"}}"#), Some(14));
        assert_eq!(find_json_end(br#"{"a":"\"}"}"#), Some(10));
        assert_eq!(find_json_end(br#"{"a":1"#), None);
    }

    #[test]
    fn stray_closing_brace_is_consumed_not_stuck() {
        // Garbage before a message must not wedge the splitter forever.
        assert_eq!(find_json_end(b"}{\"a\":1}"), Some(0));
    }

    #[test]
    fn verified_identity_overrides_client_claims() {
        let msg = parse_message(
            br#"{"event":"hello","callerPID":4,"role":"game"}"#,
            1234,
            InjectRole::Sensor,
        )
        .unwrap();
        assert_eq!(msg["callerPID"], 1234);
        assert_eq!(msg["role"], "sensor");
        assert_eq!(msg["event"], "hello");
    }

    #[test]
    fn budget_allows_a_burst_then_throttles() {
        let mut budget = Budget::new();
        let allowed = (0..1000).filter(|_| budget.take()).count();
        // The whole burst, plus at most the little that refills while looping.
        assert!(allowed >= CLIENT_BURST as usize);
        assert!(allowed < CLIENT_BURST as usize + 50, "allowed {allowed}");
    }

    #[test]
    fn over_budget_messages_are_counted_and_announced() {
        let (tx, rx) = std::sync::mpsc::sync_channel(QUEUE_DEPTH);
        let mut budget = Budget { tokens: 1.0, last: Instant::now() };
        let mut dropped = 0u64;
        let msg = || serde_json::json!({ "event": "x" });

        assert!(forward(&tx, &mut budget, &mut dropped, 7, InjectRole::Sensor, msg()));
        // Out of tokens: swallowed, but counted.
        budget.tokens = 0.0;
        budget.last = Instant::now();
        assert!(forward(&tx, &mut budget, &mut dropped, 7, InjectRole::Sensor, msg()));
        assert_eq!(dropped, 1);
        // Budget back: the notice goes out ahead of the message.
        budget.tokens = 5.0;
        assert!(forward(&tx, &mut budget, &mut dropped, 7, InjectRole::Sensor, msg()));
        assert_eq!(dropped, 0);

        let events: Vec<serde_json::Value> = rx
            .try_iter()
            .filter_map(|e| match e {
                IpcEvent::Message(m) => Some(m),
                _ => None,
            })
            .collect();
        assert_eq!(events.len(), 3);
        assert_eq!(events[1]["event"], "IpcFlood");
        assert_eq!(events[1]["dropped"], 1);
        assert_eq!(events[1]["callerPID"], 7);
    }

    #[test]
    fn non_object_messages_are_dropped() {
        assert!(parse_message(b"[1,2]", 1, InjectRole::Game).is_none());
        assert!(parse_message(b"{not json}", 1, InjectRole::Game).is_none());
    }
}
