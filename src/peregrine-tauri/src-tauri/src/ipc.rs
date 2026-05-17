use serde::Deserialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const PIPE_NAME: &str = r"\\.\pipe\peregrine_ipc";
const BUF_SIZE: u32 = 65536;
const PIPE_INSTANCES: u32 = 10;
const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;

pub type IpcMessage = serde_json::Value;
pub type IpcReceiver = std::sync::mpsc::Receiver<IpcMessage>;

pub fn start_ipc_server(stop: Arc<AtomicBool>) -> IpcReceiver {
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows::Win32::Storage::FileSystem::ReadFile;
        use windows::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
            PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
        };

        let wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

        while !stop.load(Ordering::Relaxed) {
            let pipe = unsafe {
                CreateNamedPipeW(
                    PCWSTR(wide.as_ptr()),
                    windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX),
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                    PIPE_INSTANCES,
                    BUF_SIZE,
                    BUF_SIZE,
                    0,
                    None,
                )
            };

            if pipe == INVALID_HANDLE_VALUE {
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }

            if unsafe { ConnectNamedPipe(pipe, None) }.is_err() {
                let _ = unsafe { CloseHandle(pipe) };
                continue;
            }

            let tx2 = tx.clone();
            let stop2 = stop.clone();
            let raw = pipe.0 as usize;

            std::thread::spawn(move || {
                use windows::Win32::Foundation::HANDLE;
                let pipe = HANDLE(raw as *mut _);
                let mut buf = vec![0u8; BUF_SIZE as usize];
                while !stop2.load(Ordering::Relaxed) {
                    let mut read = 0u32;
                    let ok = unsafe {
                        ReadFile(pipe, Some(&mut buf), Some(&mut read), None)
                    };
                    if ok.is_err() || read == 0 {
                        break;
                    }
                    if let Ok(s) = std::str::from_utf8(&buf[..read as usize]) {
                        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(s) {
                            let _ = tx2.send(msg);
                        }
                    }
                }
                let _ = unsafe { DisconnectNamedPipe(pipe) };
                let _ = unsafe { CloseHandle(pipe) };
            });
        }
    });

    rx
}
