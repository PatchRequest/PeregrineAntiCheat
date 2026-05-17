use super::pe::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct ModuleCheck {
    pub path: String,
    pub base: u64,
    pub size: u32,
    pub section: Option<String>,
    pub section_size: Option<usize>,
    pub mem_sha256: Option<String>,
    pub disk_sha256: Option<String>,
    pub matched: Option<bool>,
    pub error: Option<String>,
}

struct TextInfo {
    text_rva: u32,
    text_raw: u32,
    text_raw_size: u32,
    text_virt_size: u32,
    reloc_offsets: Vec<(usize, usize)>,
}

fn rva_to_raw(file: &[u8], sec_off: usize, num_sec: u16, rva: u32) -> Option<usize> {
    for i in 0..num_sec as usize {
        let off = sec_off + i * 40;
        if off + 40 > file.len() {
            break;
        }
        let va = u32::from_le_bytes(file[off + 12..off + 16].try_into().ok()?);
        let raw_sz = u32::from_le_bytes(file[off + 16..off + 20].try_into().ok()?);
        let raw_ptr = u32::from_le_bytes(file[off + 20..off + 24].try_into().ok()?);
        if rva >= va && rva < va + raw_sz {
            return Some((raw_ptr + (rva - va)) as usize);
        }
    }
    None
}

fn parse_pe_from_disk(file: &[u8]) -> Option<TextInfo> {
    if file.len() < 0x40 {
        return None;
    }
    let magic = u16::from_le_bytes([file[0], file[1]]);
    if magic != IMAGE_DOS_SIGNATURE {
        return None;
    }
    let lfanew = u32::from_le_bytes(file[0x3C..0x40].try_into().ok()?) as usize;
    if lfanew + 4 > file.len() {
        return None;
    }
    let sig = u32::from_le_bytes(file[lfanew..lfanew + 4].try_into().ok()?);
    if sig != IMAGE_NT_SIGNATURE {
        return None;
    }

    let machine = u16::from_le_bytes(file[lfanew + 4..lfanew + 6].try_into().ok()?);
    let is64 = machine == IMAGE_FILE_MACHINE_AMD64;
    let reloc_patch_size = if is64 { 8 } else { 4 };

    let num_sec = u16::from_le_bytes(file[lfanew + 6..lfanew + 8].try_into().ok()?);
    let opt_hdr_size =
        u16::from_le_bytes(file[lfanew + 20..lfanew + 22].try_into().ok()?) as usize;
    let opt_off = lfanew + 24;
    let sec_off = opt_off + opt_hdr_size;

    let mut text_rva = 0u32;
    let mut text_raw = 0u32;
    let mut text_raw_size = 0u32;
    let mut text_virt_size = 0u32;
    let mut found = false;

    for i in 0..num_sec as usize {
        let so = sec_off + i * 40;
        if so + 40 > file.len() {
            break;
        }
        let name = &file[so..so + 8];
        let end = name.iter().position(|&b| b == 0).unwrap_or(8);
        if &name[..end] == b".text" {
            text_virt_size = u32::from_le_bytes(file[so + 8..so + 12].try_into().ok()?);
            text_rva = u32::from_le_bytes(file[so + 12..so + 16].try_into().ok()?);
            text_raw_size = u32::from_le_bytes(file[so + 16..so + 20].try_into().ok()?);
            text_raw = u32::from_le_bytes(file[so + 20..so + 24].try_into().ok()?);
            text_virt_size = text_virt_size.max(text_raw_size);
            found = true;
            break;
        }
    }
    if !found {
        return None;
    }

    let mut reloc_offsets = Vec::new();
    let reloc_dir_idx = 5usize;
    let num_rva_off = if is64 { opt_off + 108 } else { opt_off + 92 };
    let dd_off = if is64 { opt_off + 112 } else { opt_off + 96 };

    if num_rva_off + 4 <= file.len() {
        let num_rva = u32::from_le_bytes(file[num_rva_off..num_rva_off + 4].try_into().ok()?) as usize;
        if num_rva > reloc_dir_idx {
            let rd = dd_off + reloc_dir_idx * 8;
            if rd + 8 <= file.len() {
                let reloc_rva = u32::from_le_bytes(file[rd..rd + 4].try_into().ok()?);
                let reloc_size = u32::from_le_bytes(file[rd + 4..rd + 8].try_into().ok()?);
                if reloc_rva != 0 && reloc_size != 0 {
                    if let Some(reloc_raw) = rva_to_raw(file, sec_off, num_sec, reloc_rva) {
                        let mut pos = reloc_raw;
                        let end = reloc_raw + reloc_size as usize;
                        let text_end = text_rva + text_virt_size;
                        while pos + 8 <= end && pos + 8 <= file.len() {
                            let brva =
                                u32::from_le_bytes(file[pos..pos + 4].try_into().ok()?);
                            let bsz =
                                u32::from_le_bytes(file[pos + 4..pos + 8].try_into().ok()?);
                            if bsz < 8 {
                                break;
                            }
                            let n = (bsz as usize - 8) / 2;
                            for j in 0..n {
                                let eoff = pos + 8 + j * 2;
                                if eoff + 2 > file.len() {
                                    break;
                                }
                                let entry =
                                    u16::from_le_bytes(file[eoff..eoff + 2].try_into().ok()?);
                                let rtype = entry >> 12;
                                let offset = (entry & 0xFFF) as u32;
                                if rtype == 3 || rtype == 10 {
                                    let rrva = brva + offset;
                                    if rrva >= text_rva && rrva < text_end {
                                        reloc_offsets
                                            .push(((rrva - text_rva) as usize, reloc_patch_size));
                                    }
                                }
                            }
                            pos += bsz as usize;
                        }
                    }
                }
            }
        }
    }

    Some(TextInfo {
        text_rva,
        text_raw,
        text_raw_size,
        text_virt_size,
        reloc_offsets,
    })
}

fn zero_relocs(data: &mut [u8], offsets: &[(usize, usize)]) {
    for &(off, sz) in offsets {
        for k in 0..sz {
            if off + k < data.len() {
                data[off + k] = 0;
            }
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

fn wow64_fixup(disk_path: &str, base: usize) -> String {
    if base >= 0x1_0000_0000 {
        return disk_path.to_string();
    }
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let sys32 = format!(r"{}\System32", sys_root);
    if disk_path.to_lowercase().starts_with(&sys32.to_lowercase()) {
        let rest = &disk_path[sys32.len()..];
        let wow = format!(r"{}\SysWOW64{}", sys_root, rest);
        if Path::new(&wow).exists() {
            return wow;
        }
    }
    disk_path.to_string()
}

pub fn check_process_modules(pid: u32) -> Result<Vec<ModuleCheck>, String> {
    let proc = ProcessHandle::open(pid).ok_or("OpenProcess failed")?;
    let modules = proc.modules();
    let mut results = Vec::new();
    let max_bytes = 8 * 1024 * 1024;

    for m in &modules {
        let mut entry = ModuleCheck {
            path: m.path.clone(),
            base: m.base as u64,
            size: m.size as u32,
            section: None,
            section_size: None,
            mem_sha256: None,
            disk_sha256: None,
            matched: None,
            error: None,
        };

        let disk_path = wow64_fixup(&m.path, m.base);

        if !Path::new(&disk_path).exists() {
            entry.error = Some("module path missing".into());
            results.push(entry);
            continue;
        }

        let file_bytes = match std::fs::read(&disk_path) {
            Ok(b) => b,
            Err(e) => {
                entry.error = Some(format!("disk read failed: {e}"));
                results.push(entry);
                continue;
            }
        };

        let ti = match parse_pe_from_disk(&file_bytes) {
            Some(t) => t,
            None => {
                entry.error = Some("no .text section found".into());
                results.push(entry);
                continue;
            }
        };

        let read_sz = (ti.text_virt_size as usize)
            .min(ti.text_raw_size as usize)
            .min(max_bytes);

        let raw = ti.text_raw as usize;
        if raw + read_sz > file_bytes.len() {
            entry.error = Some("disk .text truncated".into());
            results.push(entry);
            continue;
        }
        let mut disk_data = file_bytes[raw..raw + read_sz].to_vec();

        let mem_addr = m.base + ti.text_rva as usize;
        let mut mem_data = match proc.read_memory(mem_addr, read_sz) {
            Some(d) => d,
            None => {
                entry.error = Some("ReadProcessMemory failed".into());
                results.push(entry);
                continue;
            }
        };

        zero_relocs(&mut disk_data, &ti.reloc_offsets);
        zero_relocs(&mut mem_data, &ti.reloc_offsets);

        let dh = sha256_hex(&disk_data);
        let mh = sha256_hex(&mem_data);
        entry.matched = Some(dh == mh);
        entry.disk_sha256 = Some(dh);
        entry.mem_sha256 = Some(mh);
        entry.section = Some(".text".into());
        entry.section_size = Some(read_sz);

        results.push(entry);
    }

    Ok(results)
}
