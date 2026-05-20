use super::pe::ProcessHandle;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SigMatch {
    pub pattern_name: String,
    pub address: String,
    pub region_protection: String,
    pub region_type: String,
}

struct Pattern {
    name: String,
    bytes: Vec<Option<u8>>,
}

// ============================================================
// Config parsing
// ============================================================

fn parse_config(text: &str) -> Vec<Pattern> {
    let mut patterns = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if let Some((name, hex_part)) = line.split_once(':') {
            let name = name.trim().to_string();
            let bytes: Vec<Option<u8>> = hex_part
                .split_whitespace()
                .filter_map(|tok| {
                    if tok == "??" { Some(None) }
                    else { u8::from_str_radix(tok, 16).ok().map(Some) }
                })
                .collect();
            if !bytes.is_empty() {
                patterns.push(Pattern { name, bytes });
            }
        }
    }
    patterns
}

fn load_signatures() -> Result<Vec<Pattern>, String> {
    let paths = [
        std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("signatures.conf"))),
        Some(std::path::PathBuf::from("signatures.conf")),
        Some(std::path::PathBuf::from(r"C:\Peregrine\signatures.conf")),
        Some(std::path::PathBuf::from(r"E:\Peregrine\signatures.conf")),
    ];
    for p in paths.iter().flatten() {
        if let Ok(text) = std::fs::read_to_string(p) {
            let pats = parse_config(&text);
            if !pats.is_empty() {
                return Ok(pats);
            }
        }
    }
    Err("signatures.conf not found or empty".into())
}

// ============================================================
// Pattern matching
// ============================================================

fn matches_at(data: &[u8], offset: usize, pattern: &[Option<u8>]) -> bool {
    if offset + pattern.len() > data.len() { return false; }
    for (i, p) in pattern.iter().enumerate() {
        if let Some(b) = p {
            if data[offset + i] != *b { return false; }
        }
    }
    true
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
const CHUNK_SIZE: usize = 256 * 1024;

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

const MAX_MATCHES_PER_PATTERN: usize = 50;

pub fn scan_process(pid: u32) -> Result<(Vec<SigMatch>, usize), String> {
    let patterns = load_signatures()?;
    let proc = ProcessHandle::open(pid).ok_or("OpenProcess failed")?;
    let handle_raw = proc.0.0;

    let max_pat = patterns.iter().map(|p| p.bytes.len()).max().unwrap_or(0);
    let overlap = if max_pat > 1 { max_pat - 1 } else { 0 };

    let mut results = Vec::new();
    let mut hit_count: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut addr: usize = 0;
    let mut bytes_scanned: usize = 0;

    loop {
        let mut mbi: MemBasicInfo = unsafe { std::mem::zeroed() };
        let ret = unsafe { VirtualQueryEx(handle_raw, addr, &mut mbi, std::mem::size_of::<MemBasicInfo>()) };
        if ret == 0 { break; }

        let base = mbi.base_address;
        let size = mbi.region_size;

        if mbi.state == MEM_COMMIT && is_readable(mbi.protect) && size > 0 && size <= MAX_REGION_READ {
            let mut read_off = 0usize;
            while read_off < size {
                let want = std::cmp::min(CHUNK_SIZE + overlap, size - read_off);
                if let Some(data) = proc.read_memory(base + read_off, want) {
                    let scan_end = if read_off + want < size {
                        data.len().saturating_sub(overlap)
                    } else {
                        data.len()
                    };

                    for i in 0..scan_end {
                        for pat in &patterns {
                            let count = hit_count.get(&pat.name).copied().unwrap_or(0);
                            if count >= MAX_MATCHES_PER_PATTERN { continue; }
                            if matches_at(&data, i, &pat.bytes) {
                                *hit_count.entry(pat.name.clone()).or_insert(0) += 1;
                                results.push(SigMatch {
                                    pattern_name: pat.name.clone(),
                                    address: format!("0x{:X}", base + read_off + i),
                                    region_protection: prot_str(mbi.protect).into(),
                                    region_type: type_str(mbi.mem_type).into(),
                                });
                            }
                        }
                    }
                    bytes_scanned += data.len();
                }
                read_off += CHUNK_SIZE;
            }
        }

        let next = base.wrapping_add(size);
        if next <= addr { break; }
        addr = next;
    }

    // Append truncation notices
    for (name, count) in &hit_count {
        if *count >= MAX_MATCHES_PER_PATTERN {
            results.push(SigMatch {
                pattern_name: format!("{} (truncated, {}+ matches)", name, count),
                address: "—".into(),
                region_protection: "—".into(),
                region_type: "—".into(),
            });
        }
    }

    Ok((results, bytes_scanned))
}
