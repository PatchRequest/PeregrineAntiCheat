use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct OverlayWindow {
    pub hwnd: u64,
    pub class_name: String,
    pub title: String,
    pub pid: u32,
}

pub fn detect_overlays() -> Vec<OverlayWindow> {
    // TODO: port from Python OverlayDetection.py
    Vec::new()
}
