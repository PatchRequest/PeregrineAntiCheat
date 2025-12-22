use std::ptr;
use windows::core::Error as WindowsError;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
use windows::Win32::System::IO::DeviceIoControl;

const FILE_DEVICE_UNKNOWN: u32 = 0x00000022;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

/// Generate IOCTL code similar to Windows CTL_CODE macro
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const IOCTL_PEREGRINE_SEND_FROM_USER: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_PEREGRINE_RECV_TO_USER: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum KernelCommand {
    AddPid = 1,
    RemovePid = 2,
    ClearAll = 3,
    SetPpl = 4,
}

pub struct KernelDevice {
    handle: HANDLE,
}

// SAFETY: Windows HANDLE can be safely sent between threads
unsafe impl Send for KernelDevice {}
unsafe impl Sync for KernelDevice {}

impl KernelDevice {
    /// Open the Peregrine kernel device
    pub fn open() -> Result<Self, WindowsError> {
        Self::open_with_path(r"\\.\Peregrine")
    }

    /// Open the kernel device with a custom path
    pub fn open_with_path(path: &str) -> Result<Self, WindowsError> {
        unsafe {
            let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

            let handle = CreateFileW(
                windows::core::PCWSTR(wide_path.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                Default::default(),
                None,
                OPEN_EXISTING,
                Default::default(),
                None,
            )?;

            Ok(Self { handle })
        }
    }

    /// Send IOCTL command to kernel
    pub fn send_command(&self, cmd: KernelCommand, pid: Option<usize>) -> Result<Vec<u8>, WindowsError> {
        let mut payload = vec![cmd as u8];

        if let Some(pid_val) = pid {
            // Pack PID as pointer-sized little-endian
            if std::mem::size_of::<usize>() == 8 {
                payload.extend_from_slice(&(pid_val as u64).to_le_bytes());
            } else {
                payload.extend_from_slice(&(pid_val as u32).to_le_bytes());
            }
        }

        self.device_io_control(IOCTL_PEREGRINE_SEND_FROM_USER, &payload)
    }

    /// Receive events from kernel
    pub fn receive_events(&self) -> Result<Vec<u8>, WindowsError> {
        self.device_io_control(IOCTL_PEREGRINE_RECV_TO_USER, &[])
    }

    /// Low-level DeviceIoControl wrapper
    fn device_io_control(&self, ioctl_code: u32, input_buffer: &[u8]) -> Result<Vec<u8>, WindowsError> {
        unsafe {
            let mut output_buffer = vec![0u8; 1024];
            let mut bytes_returned: u32 = 0;

            let input_ptr = if input_buffer.is_empty() {
                ptr::null()
            } else {
                input_buffer.as_ptr() as *const _
            };

            let success = DeviceIoControl(
                self.handle,
                ioctl_code,
                Some(input_ptr as *const _),
                input_buffer.len() as u32,
                Some(output_buffer.as_mut_ptr() as *mut _),
                output_buffer.len() as u32,
                Some(&mut bytes_returned),
                None,
            );

            if success.is_ok() {
                output_buffer.truncate(bytes_returned as usize);
                Ok(output_buffer)
            } else {
                Err(WindowsError::from_win32())
            }
        }
    }

    /// Add PID to protection list
    pub fn add_pid(&self, pid: usize) -> Result<(), WindowsError> {
        self.send_command(KernelCommand::AddPid, Some(pid))?;
        Ok(())
    }

    /// Remove PID from protection list
    pub fn remove_pid(&self, pid: usize) -> Result<(), WindowsError> {
        self.send_command(KernelCommand::RemovePid, Some(pid))?;
        Ok(())
    }

    /// Clear all PIDs from protection list
    pub fn clear_all_pids(&self) -> Result<(), WindowsError> {
        self.send_command(KernelCommand::ClearAll, None)?;
        Ok(())
    }

    /// Set process to Protected Process Light (PPL) status
    pub fn set_ppl(&self, pid: usize) -> Result<(), WindowsError> {
        self.send_command(KernelCommand::SetPpl, Some(pid))?;
        Ok(())
    }
}

impl Drop for KernelDevice {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
