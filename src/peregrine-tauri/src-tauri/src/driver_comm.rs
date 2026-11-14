use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_ITEMS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFinalPathNameByHandleW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_NONE, FILE_SHARE_READ, FILE_SHARE_WRITE, GETFINALPATHNAMEBYHANDLE_FLAGS,
    OPEN_EXISTING, VOLUME_NAME_NT,
};
use windows::Win32::System::IO::DeviceIoControl;

const DEVICE_PATH: &str = r"\\.\Peregrine";

const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

const fn ctl_code(dev: u32, func: u32, method: u32, access: u32) -> u32 {
    (dev << 16) | (access << 14) | (func << 2) | method
}

const IOCTL_SEND: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_RECV: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_QUERY_INJECTED: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// Kernel event messages are at most COMS_MAX_MESSAGE_SIZE bytes.
const MAX_EVENT_SIZE: usize = 1024;

/// Command bytes for IOCTL_SEND. Mirrors `COMS_COMMAND` in the driver's Coms.h — keep in sync.
mod cmd {
    pub const PROTECT_PID: u8 = 1;
    pub const UNPROTECT_PID: u8 = 2;
    pub const CLEAR_PROTECTED: u8 = 3;
    pub const SET_PPL: u8 = 4;
    pub const SCAN_DRIVERS: u8 = 5;
    pub const SCAN_OB_CALLBACKS: u8 = 6;
    pub const SYSTEM_CHECK: u8 = 7;
    pub const SET_GAME_DLL_X64: u8 = 8;
    pub const SET_GAME_DLL_X86: u8 = 9;
    pub const ADD_GAME_TARGET: u8 = 10;
    pub const SET_INJECTION_ENABLED: u8 = 11;
    pub const COLLECT_HWID: u8 = 12;
    pub const SCAN_VAD: u8 = 13;
    pub const CLEAR_TARGETS: u8 = 14;
    pub const SET_SENSOR_DLL_X64: u8 = 15;
    pub const SET_SENSOR_DLL_X86: u8 = 16;
    pub const ADD_SENSOR_TARGET: u8 = 17;
    pub const TRUST_CALLER: u8 = 18;
}

/// Which inject profile a DLL path or target belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectRole {
    /// Protected game: full hooks + HWBP, auto-protect on inject.
    Game,
    /// Cheat / tool host: external hooks only, never protected.
    Sensor,
}

impl InjectRole {
    pub fn as_str(self) -> &'static str {
        match self {
            InjectRole::Game => "game",
            InjectRole::Sensor => "sensor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DllArch {
    X64,
    X86,
}

pub struct DriverHandle {
    handle: HANDLE,
}

unsafe impl Send for DriverHandle {}
unsafe impl Sync for DriverHandle {}

fn utf16le_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

impl DriverHandle {
    pub fn open() -> Result<Self, String> {
        let wide: Vec<u16> = DEVICE_PATH.encode_utf16().chain(std::iter::once(0)).collect();
        let h = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(|e| format!("CreateFileW failed: {e}"))?;

        if h == INVALID_HANDLE_VALUE {
            return Err("Got INVALID_HANDLE_VALUE".into());
        }
        Ok(Self { handle: h })
    }

    /// Sends one command. The driver's NTSTATUS for the command is the IOCTL
    /// result, so a rejected command (bad path, table full, ...) is an `Err`.
    fn send_command(&self, data: &[u8]) -> Result<(), String> {
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_SEND,
                Some(data.as_ptr() as *const _),
                data.len() as u32,
                None,
                0,
                Some(&mut returned),
                None,
            )
        }
        .map_err(|e| format!("driver command {} failed: {e}", data.first().copied().unwrap_or(0)))
    }

    fn send_pid_command(&self, command: u8, pid: u32) -> Result<(), String> {
        // The driver reads a HANDLE-sized PID (this GUI and the driver are both x64).
        let mut buf = vec![command];
        buf.extend_from_slice(&(pid as usize).to_le_bytes());
        self.send_command(&buf)
    }

    /// Pops one kernel event.
    ///
    /// `Ok(None)` means the queue is empty *and the driver answered* — callers
    /// use that as the liveness signal. Any other failure (device gone, handle
    /// invalid) is an `Err` and must not be mistaken for "no events".
    pub fn recv_event(&self) -> Result<Option<Vec<u8>>, String> {
        let mut buf = [0u8; MAX_EVENT_SIZE];
        let mut returned = 0u32;
        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_RECV,
                None,
                0,
                Some(buf.as_mut_ptr() as *mut _),
                buf.len() as u32,
                Some(&mut returned),
                None,
            )
        };

        match result {
            Ok(()) => Ok(Some(buf[..returned as usize].to_vec())),
            // STATUS_NO_MORE_ENTRIES: queue empty.
            Err(e) if e.code() == ERROR_NO_MORE_ITEMS.to_hresult() => Ok(None),
            Err(e) => Err(format!("DeviceIoControl(RECV) failed: {e}")),
        }
    }

    /// Asks the kernel whether it injected one of our DLLs into `pid`.
    /// The kernel's inject bookkeeping is the only source of truth for this.
    pub fn query_injected(&self, pid: u32) -> Result<Option<InjectRole>, String> {
        let input = pid.to_le_bytes();
        let mut output = [0u8; 4];
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_QUERY_INJECTED,
                Some(input.as_ptr() as *const _),
                input.len() as u32,
                Some(output.as_mut_ptr() as *mut _),
                output.len() as u32,
                Some(&mut returned),
                None,
            )
        }
        .map_err(|e| format!("DeviceIoControl(QUERY_INJECTED) failed: {e}"))?;

        if returned as usize != output.len() {
            return Err(format!("QUERY_INJECTED returned {returned} bytes"));
        }
        // INJ_QUERY_* in ApcInjection.h
        match u32::from_le_bytes(output) {
            0 => Ok(None),
            1 => Ok(Some(InjectRole::Game)),
            2 => Ok(Some(InjectRole::Sensor)),
            other => Err(format!("QUERY_INJECTED returned unknown role {other}")),
        }
    }

    // ---- High-level commands ----

    /// Adds the *calling* process (this GUI) to the kernel's TRUSTED set.
    /// There is deliberately no PID argument: a process can only vouch for itself.
    pub fn trust_self(&self) -> Result<(), String> {
        self.send_command(&[cmd::TRUST_CALLER])
    }

    /// Adds `pid` to the PROTECTED set (the game we defend).
    pub fn protect_pid(&self, pid: u32) -> Result<(), String> {
        self.send_pid_command(cmd::PROTECT_PID, pid)
    }

    pub fn unprotect_pid(&self, pid: u32) -> Result<(), String> {
        self.send_pid_command(cmd::UNPROTECT_PID, pid)
    }

    pub fn clear_protected(&self) -> Result<(), String> {
        self.send_command(&[cmd::CLEAR_PROTECTED])
    }

    pub fn set_ppl(&self, pid: u32) -> Result<(), String> {
        self.send_pid_command(cmd::SET_PPL, pid)
    }

    pub fn scan_drivers(&self) -> Result<(), String> {
        self.send_command(&[cmd::SCAN_DRIVERS])
    }

    pub fn scan_ob_callbacks(&self) -> Result<(), String> {
        self.send_command(&[cmd::SCAN_OB_CALLBACKS])
    }

    pub fn system_check(&self) -> Result<(), String> {
        self.send_command(&[cmd::SYSTEM_CHECK])
    }

    /// DOS path of the DLL the kernel hands to LoadLibraryExW for this role/arch.
    pub fn set_dll_path(&self, role: InjectRole, arch: DllArch, path: &str) -> Result<(), String> {
        let command = match (role, arch) {
            (InjectRole::Game, DllArch::X64) => cmd::SET_GAME_DLL_X64,
            (InjectRole::Game, DllArch::X86) => cmd::SET_GAME_DLL_X86,
            (InjectRole::Sensor, DllArch::X64) => cmd::SET_SENSOR_DLL_X64,
            (InjectRole::Sensor, DllArch::X86) => cmd::SET_SENSOR_DLL_X86,
        };
        let mut buf = vec![command];
        buf.extend_from_slice(&utf16le_bytes(path));
        self.send_command(&buf)
    }

    /// Registers an inject target by the normalized NT path of its image
    /// (see [`image_nt_path`]). The kernel matches the full path only.
    pub fn add_injection_target(&self, role: InjectRole, nt_path: &str) -> Result<(), String> {
        let command = match role {
            InjectRole::Game => cmd::ADD_GAME_TARGET,
            InjectRole::Sensor => cmd::ADD_SENSOR_TARGET,
        };
        let mut buf = vec![command];
        buf.extend_from_slice(&utf16le_bytes(nt_path));
        self.send_command(&buf)
    }

    pub fn set_injection_enabled(&self, enabled: bool) -> Result<(), String> {
        self.send_command(&[cmd::SET_INJECTION_ENABLED, u8::from(enabled)])
    }

    pub fn collect_hwid(&self) -> Result<(), String> {
        self.send_command(&[cmd::COLLECT_HWID])
    }

    pub fn scan_vad(&self, pid: u32) -> Result<(), String> {
        self.send_pid_command(cmd::SCAN_VAD, pid)
    }

    /// Clears both target lists and disables injection.
    pub fn clear_injection_targets(&self) -> Result<(), String> {
        self.send_command(&[cmd::CLEAR_TARGETS])
    }
}

impl Drop for DriverHandle {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

/// Resolves an existing executable to its normalized NT path
/// (`\Device\HarddiskVolume3\Games\game.exe`).
///
/// This is the identity the kernel compares against at process creation
/// (FltMgr-normalized image name): long names, real volume, links resolved.
/// Resolving through an open handle — rather than string manipulation —
/// means subst drives, 8.3 names and relative paths all end up as the same
/// canonical name the kernel will see.
pub fn image_nt_path(path: &str) -> Result<String, String> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|e| format!("cannot open '{path}': {e}"))?;

    let mut buf = vec![0u16; 1024];
    let flags = GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_NT.0);
    let len = unsafe { GetFinalPathNameByHandleW(handle, &mut buf, flags) } as usize;
    let last_error = windows::core::Error::from_win32();
    let _ = unsafe { CloseHandle(handle) };

    if len == 0 {
        return Err(format!("cannot resolve NT path of '{path}': {last_error}"));
    }
    if len >= buf.len() {
        return Err(format!("NT path of '{path}' is too long ({len} chars)"));
    }

    let nt_path = String::from_utf16(&buf[..len])
        .map_err(|_| format!("NT path of '{path}' is not valid UTF-16"))?;
    if !nt_path.starts_with('\\') {
        return Err(format!("unexpected NT path '{nt_path}' for '{path}'"));
    }
    Ok(nt_path)
}
