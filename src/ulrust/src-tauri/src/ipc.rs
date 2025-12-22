use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use windows::Win32::Foundation::*;
use windows::Win32::Security::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Pipes::*;
use windows::Win32::System::IO::*;
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use serde_json::Value as JsonValue;

const PIPE_NAME: &str = r"\\.\pipe\peregrine_ipc";
const BUFFER_SIZE: u32 = 65536;

pub type MessageCallback = Arc<dyn Fn(JsonValue) + Send + Sync>;
pub type ErrorCallback = Arc<dyn Fn(String) + Send + Sync>;

/// Named pipe server for IPC communication
pub struct IpcServer {
    stop_flag: Arc<AtomicBool>,
}

impl IpcServer {
    /// Start the IPC server with message and error callbacks
    pub fn start(
        on_message: MessageCallback,
        on_error: ErrorCallback,
    ) -> Self {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        thread::spawn(move || {
            run_server(stop_flag_clone, on_message, on_error);
        });

        Self { stop_flag }
    }

    /// Stop the IPC server
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Create a security descriptor that allows Everyone to access the pipe
fn create_permissive_security_attributes() -> SECURITY_ATTRIBUTES {
    unsafe {
        // For simplicity, we'll use a NULL security descriptor which allows default permissions
        // In production, you'd want proper security here
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: FALSE,
        }
    }
}

/// Create a named pipe instance
fn create_pipe_instance() -> Result<HANDLE, windows::core::Error> {
    unsafe {
        let pipe_name: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let sa = create_permissive_security_attributes();

        let handle = CreateNamedPipeW(
            windows::core::PCWSTR(pipe_name.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE,
            BUFFER_SIZE,
            0,
            Some(&sa as *const _),
        );

        if handle.is_invalid() {
            Err(windows::core::Error::from_win32())
        } else {
            Ok(handle)
        }
    }
}

/// Handle a single pipe connection (synchronous)
fn handle_pipe_connection(
    pipe_handle: HANDLE,
    on_message: &MessageCallback,
    on_error: &ErrorCallback,
) {
    unsafe {
        // Wait for client connection
        if ConnectNamedPipe(pipe_handle, None).is_err() {
            let error = GetLastError();
            // ERROR_PIPE_CONNECTED means client connected before we called ConnectNamedPipe
            if error != ERROR_PIPE_CONNECTED {
                on_error(format!("ConnectNamedPipe failed: {:?}", error));
                let _ = CloseHandle(pipe_handle);
                return;
            }
        }

        // Read message
        let mut buffer = vec![0u8; BUFFER_SIZE as usize];
        let mut bytes_read: u32 = 0;

        if ReadFile(
            pipe_handle,
            Some(&mut buffer),
            Some(&mut bytes_read),
            None,
        ).is_ok() && bytes_read > 0 {
            buffer.truncate(bytes_read as usize);
            match String::from_utf8(buffer) {
                Ok(text) => match serde_json::from_str::<JsonValue>(&text) {
                    Ok(json) => on_message(json),
                    Err(e) => on_error(format!("JSON decode error: {}", e)),
                },
                Err(e) => on_error(format!("UTF-8 decode error: {}", e)),
            }
        }

        // Cleanup
        let _ = DisconnectNamedPipe(pipe_handle);
        let _ = CloseHandle(pipe_handle);
    }
}

/// Run the pipe server
fn run_server(
    stop_flag: Arc<AtomicBool>,
    on_message: MessageCallback,
    on_error: ErrorCallback,
) {
    while !stop_flag.load(Ordering::Relaxed) {
        match create_pipe_instance() {
            Ok(pipe_handle) => {
                let on_message = on_message.clone();
                let on_error = on_error.clone();
                // Convert HANDLE to isize which is Send
                let handle_value = pipe_handle.0 as isize;

                // Spawn a thread for each connection
                thread::spawn(move || {
                    let handle = HANDLE(handle_value as *mut _);
                    handle_pipe_connection(handle, &on_message, &on_error);
                });
            }
            Err(e) => {
                on_error(format!("Failed to create pipe instance: {:?}", e));
                // Small delay before retrying
                thread::sleep(std::time::Duration::from_millis(100));
            }
        }

        // Small delay to prevent tight loop
        thread::sleep(std::time::Duration::from_millis(10));
    }
}
