use super::pe::ProcessHandle;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SigMatch {
    pub rule_name: String,
    pub address: String,
    pub region_protection: String,
    pub region_type: String,
    pub match_length: usize,
}

// ============================================================
// YARA rules loading
// ============================================================

fn load_rules() -> Result<yara_x::Rules, String> {
    let paths = [
        std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("rules.yar"))),
        Some(std::path::PathBuf::from("rules.yar")),
        Some(std::path::PathBuf::from(r"C:\Peregrine\rules.yar")),
        Some(std::path::PathBuf::from(r"E:\Peregrine\rules.yar")),
    ];
    for p in paths.iter().flatten() {
        if let Ok(src) = std::fs::read_to_string(p) {
            return yara_x::compile(src.as_str()).map_err(|e| format!("YARA compile error: {e}"));
        }
    }
    Err("rules.yar not found".into())
}

// ============================================================
// Memory walking via raw FFI
// ============================================================

#[repr(C)]
struct MemBasicInfo {
    base_address: usize,
    allocation_base: usize,
    allocation_protect: u32,
    _partition_pad: u32,
    region_size: usize,
    state: u32,
    protect: u32,
    mem_type: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn VirtualQueryEx(process: *mut std::ffi::c_void, address: usize, buffer: *mut MemBasicInfo, length: usize) -> usize;
}

const MEM_COMMIT: u32 = 0x1000;
const MEM_IMAGE: u32 = 0x1000000;
const MEM_PRIVATE: u32 = 0x20000;
const PAGE_GUARD: u32 = 0x100;
const PAGE_NOACCESS: u32 = 0x01;
const MAX_REGION_READ: usize = 16 * 1024 * 1024;

fn is_readable(protect: u32) -> bool {
    let base = protect & 0xFF;
    base != 0 && base != PAGE_NOACCESS && (protect & PAGE_GUARD) == 0
}

fn prot_str(p: u32) -> &'static str {
    match p & 0xFF {
        0x02 => "READONLY",
        0x04 => "READWRITE",
        0x08 => "WRITECOPY",
        0x10 => "EXECUTE",
        0x20 => "EXECUTE_READ",
        0x40 => "EXECUTE_READWRITE",
        0x80 => "EXECUTE_WRITECOPY",
        _ => "?",
    }
}

fn type_str(t: u32) -> &'static str {
    match t {
        MEM_IMAGE => "IMAGE",
        MEM_PRIVATE => "PRIVATE",
        0x40000 => "MAPPED",
        _ => "?",
    }
}

// ============================================================
// Public scan function
// ============================================================

pub fn scan_process(pid: u32) -> Result<(Vec<SigMatch>, usize), String> {
    let rules = load_rules()?;
    let proc = ProcessHandle::open(pid).ok_or("OpenProcess failed")?;
    let handle_raw = proc.0.0;

    let mut scanner = yara_x::Scanner::new(&rules);
    let mut results = Vec::new();
    let mut addr: usize = 0;
    let mut bytes_scanned: usize = 0;

    loop {
        let mut mbi: MemBasicInfo = unsafe { std::mem::zeroed() };
        let ret = unsafe { VirtualQueryEx(handle_raw, addr, &mut mbi, std::mem::size_of::<MemBasicInfo>()) };
        if ret == 0 { break; }

        let base = mbi.base_address;
        let size = mbi.region_size;

        if mbi.state == MEM_COMMIT && is_readable(mbi.protect) && size > 0 && size <= MAX_REGION_READ {
            if let Some(data) = proc.read_memory(base, size) {
                bytes_scanned += data.len();

                let scan_results = scanner.scan(&data);
                if let Ok(scan_results) = scan_results {
                    for rule in scan_results.matching_rules() {
                        for pattern in rule.patterns() {
                            for m in pattern.matches() {
                                results.push(SigMatch {
                                    rule_name: rule.identifier().to_string(),
                                    address: format!("0x{:X}", base + m.range().start),
                                    region_protection: prot_str(mbi.protect).into(),
                                    region_type: type_str(mbi.mem_type).into(),
                                    match_length: m.range().len(),
                                });
                            }
                        }
                    }
                }
            }
        }

        let next = base.wrapping_add(size);
        if next <= addr { break; }
        addr = next;
    }

    Ok((results, bytes_scanned))
}
