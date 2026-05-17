use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum DriverEvent {
    #[serde(rename = "process_create")]
    ProcessCreate { pid: u32, ppid: u32, image: String },
    #[serde(rename = "process_exit")]
    ProcessExit { pid: u32 },
    #[serde(rename = "thread_create")]
    ThreadCreate {
        pid: u32,
        tid: u32,
        callerpid: u32,
        #[serde(default)]
        start_address: Option<String>,
    },
    #[serde(rename = "thread_exit")]
    ThreadExit { pid: u32, tid: u32, callerpid: u32 },
    #[serde(rename = "image_load")]
    ImageLoad {
        pid: u32,
        base: String,
        size: u32,
        image: String,
    },
    #[serde(rename = "ob_callback")]
    ObCallback {
        op: String,
        target_pid: u32,
        caller_pid: u32,
        desired_access: String,
    },
    #[serde(rename = "apc_inject")]
    ApcInject {
        pid: u32,
        tid: u32,
        status: String,
        #[serde(default)]
        error: Option<String>,
    },
    #[serde(rename = "driver_scan")]
    DriverScan {
        driver: String,
        path: String,
        size: u32,
    },
    #[serde(rename = "driver_scan_complete")]
    DriverScanComplete {
        total_drivers: u32,
        blacklisted_count: u32,
    },
    #[serde(rename = "system_check")]
    SystemCheck(serde_json::Value),
    #[serde(other)]
    Unknown,
}

pub struct DriverHandle {
    handle: HANDLE,
}

unsafe impl Send for DriverHandle {}
unsafe impl Sync for DriverHandle {}

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

    pub fn send_command(&self, data: &[u8]) -> Result<(), String> {
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
        .map_err(|e| format!("DeviceIoControl(SEND) failed: {e}"))
    }

    pub fn recv_event(&self) -> Result<Option<Vec<u8>>, String> {
        let mut buf = [0u8; 1024];
        let mut returned = 0u32;
        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_RECV,
                Some(b"".as_ptr() as *const _),
                0,
                Some(buf.as_mut_ptr() as *mut _),
                buf.len() as u32,
                Some(&mut returned),
                None,
            )
        };

        match result {
            Ok(()) => Ok(Some(buf[..returned as usize].to_vec())),
            Err(_) => Ok(None),
        }
    }

    // ---- High-level commands ----

    pub fn add_pid(&self, pid: u32) -> Result<(), String> {
        let handle_size = std::mem::size_of::<usize>();
        let mut buf = vec![1u8];
        if handle_size == 8 {
            buf.extend_from_slice(&(pid as u64).to_le_bytes());
        } else {
            buf.extend_from_slice(&pid.to_le_bytes());
        }
        self.send_command(&buf)
    }

    pub fn remove_pid(&self, pid: u32) -> Result<(), String> {
        let handle_size = std::mem::size_of::<usize>();
        let mut buf = vec![2u8];
        if handle_size == 8 {
            buf.extend_from_slice(&(pid as u64).to_le_bytes());
        } else {
            buf.extend_from_slice(&pid.to_le_bytes());
        }
        self.send_command(&buf)
    }

    pub fn clear_pids(&self) -> Result<(), String> {
        self.send_command(&[3])
    }

    pub fn set_ppl(&self, pid: u32) -> Result<(), String> {
        let handle_size = std::mem::size_of::<usize>();
        let mut buf = vec![4u8];
        if handle_size == 8 {
            buf.extend_from_slice(&(pid as u64).to_le_bytes());
        } else {
            buf.extend_from_slice(&pid.to_le_bytes());
        }
        self.send_command(&buf)
    }

    pub fn scan_drivers(&self) -> Result<(), String> {
        self.send_command(&[5])
    }

    pub fn scan_ob_callbacks(&self) -> Result<(), String> {
        self.send_command(&[6])
    }

    pub fn system_check(&self) -> Result<(), String> {
        self.send_command(&[7])
    }

    pub fn set_dll_path_x64(&self, path: &str) -> Result<(), String> {
        let wide: Vec<u8> = path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut buf = vec![8u8];
        buf.extend_from_slice(&wide);
        self.send_command(&buf)
    }

    pub fn set_dll_path_x86(&self, path: &str) -> Result<(), String> {
        let wide: Vec<u8> = path
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut buf = vec![9u8];
        buf.extend_from_slice(&wide);
        self.send_command(&buf)
    }

    pub fn add_injection_target(&self, name: &str) -> Result<(), String> {
        let mut buf = vec![10u8];
        buf.extend_from_slice(name.as_bytes());
        self.send_command(&buf)
    }

    pub fn set_injection_enabled(&self, enabled: bool) -> Result<(), String> {
        self.send_command(&[11, if enabled { 1 } else { 0 }])
    }
}

impl Drop for DriverHandle {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

pub type SharedDriver = Arc<Mutex<Option<DriverHandle>>>;

pub fn parse_driver_event(raw: &[u8]) -> Option<DriverEvent> {
    let s = String::from_utf8_lossy(raw);
    let fixed = s.replace('\\', "\\\\");
    serde_json::from_str(&fixed).ok()
}
