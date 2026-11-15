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
    /// Full .text match after reloc zeroing (and optional self-hook mask).
    pub matched: Option<bool>,
    /// true = only differed at PeregrineDLL MinHook sites (not real tamper).
    pub self_hooks: Option<bool>,
    pub error: Option<String>,
}

/// Exports that PeregrineDLL hooks via MinHook (dllmain.cpp InstallHook list).
/// Module basename is compared case-insensitively.
///
/// Must list exactly what dllmain.cpp hooks: every extra name here is a
/// prologue a cheat could patch while being excused as "our own hook".
/// (ReadProcessMemory / WriteProcessMemory are intentionally absent — memory
/// access is hooked once, at ntdll's NtRead/NtWriteVirtualMemory.)
const SELF_HOOKED_EXPORTS: &[(&str, &[&str])] = &[
    (
        "ntdll.dll",
        &[
            "NtReadVirtualMemory",
            "NtWriteVirtualMemory",
            "NtSetContextThread",
            "RtlAddVectoredExceptionHandler",
        ],
    ),
    (
        "kernelbase.dll",
        &[
            "VirtualAllocEx",
            "VirtualProtectEx",
            "CreateRemoteThread",
            "OpenProcess",
        ],
    ),
    (
        "kernel32.dll",
        &[
            "VirtualAllocEx",
            "VirtualProtectEx",
            "CreateRemoteThread",
            "OpenProcess",
        ],
    ),
];

/// Bytes of prologue MinHook may overwrite (x64 absolute jump is ≤14).
const HOOK_MASK_BYTES: usize = 16;

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

fn zero_range(data: &mut [u8], off: usize, len: usize) {
    for k in 0..len {
        if off + k < data.len() {
            data[off + k] = 0;
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

fn module_basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_ascii_lowercase()
}

fn self_hook_names_for(path: &str) -> Option<&'static [&'static str]> {
    let base = module_basename(path);
    SELF_HOOKED_EXPORTS
        .iter()
        .find(|(name, _)| base.eq_ignore_ascii_case(name))
        .map(|(_, exports)| *exports)
}

/// Resolve named export RVAs from an on-disk PE image.
fn export_rvas(file: &[u8], names: &[&str]) -> Vec<u32> {
    if names.is_empty() || file.len() < 0x40 {
        return Vec::new();
    }
    let magic = u16::from_le_bytes([file[0], file[1]]);
    if magic != IMAGE_DOS_SIGNATURE {
        return Vec::new();
    }
    let lfanew = u32::from_le_bytes(file[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
    if lfanew + 24 > file.len() {
        return Vec::new();
    }
    let sig = u32::from_le_bytes(file[lfanew..lfanew + 4].try_into().unwrap_or([0; 4]));
    if sig != IMAGE_NT_SIGNATURE {
        return Vec::new();
    }
    let machine = u16::from_le_bytes(file[lfanew + 4..lfanew + 6].try_into().unwrap_or([0; 2]));
    let is64 = machine == IMAGE_FILE_MACHINE_AMD64;
    let num_sec = u16::from_le_bytes(file[lfanew + 6..lfanew + 8].try_into().unwrap_or([0; 2]));
    let opt_hdr_size =
        u16::from_le_bytes(file[lfanew + 20..lfanew + 22].try_into().unwrap_or([0; 2])) as usize;
    let opt_off = lfanew + 24;
    let sec_off = opt_off + opt_hdr_size;

    let dd0 = if is64 { opt_off + 112 } else { opt_off + 96 };
    if dd0 + 8 > file.len() {
        return Vec::new();
    }
    let exp_rva = u32::from_le_bytes(file[dd0..dd0 + 4].try_into().unwrap_or([0; 4]));
    if exp_rva == 0 {
        return Vec::new();
    }
    let Some(exp_raw) = rva_to_raw(file, sec_off, num_sec, exp_rva) else {
        return Vec::new();
    };
    if exp_raw + 40 > file.len() {
        return Vec::new();
    }
    let n_names =
        u32::from_le_bytes(file[exp_raw + 24..exp_raw + 28].try_into().unwrap_or([0; 4])) as usize;
    let fn_rva = u32::from_le_bytes(file[exp_raw + 28..exp_raw + 32].try_into().unwrap_or([0; 4]));
    let name_rva =
        u32::from_le_bytes(file[exp_raw + 32..exp_raw + 36].try_into().unwrap_or([0; 4]));
    let ord_rva =
        u32::from_le_bytes(file[exp_raw + 36..exp_raw + 40].try_into().unwrap_or([0; 4]));

    let Some(names_raw) = rva_to_raw(file, sec_off, num_sec, name_rva) else {
        return Vec::new();
    };
    let Some(ords_raw) = rva_to_raw(file, sec_off, num_sec, ord_rva) else {
        return Vec::new();
    };
    let Some(funcs_raw) = rva_to_raw(file, sec_off, num_sec, fn_rva) else {
        return Vec::new();
    };

    let want: Vec<&str> = names.to_vec();
    let mut found = Vec::new();

    for i in 0..n_names {
        let no = names_raw + i * 4;
        if no + 4 > file.len() {
            break;
        }
        let nrva = u32::from_le_bytes(file[no..no + 4].try_into().unwrap_or([0; 4]));
        let Some(nraw) = rva_to_raw(file, sec_off, num_sec, nrva) else {
            continue;
        };
        let end = file[nraw..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(0)
            .min(128);
        let ename = std::str::from_utf8(&file[nraw..nraw + end]).unwrap_or("");
        if !want.iter().any(|w| *w == ename) {
            continue;
        }
        let oo = ords_raw + i * 2;
        if oo + 2 > file.len() {
            continue;
        }
        let ord = u16::from_le_bytes(file[oo..oo + 2].try_into().unwrap_or([0; 2])) as usize;
        let fo = funcs_raw + ord * 4;
        if fo + 4 > file.len() {
            continue;
        }
        let rva = u32::from_le_bytes(file[fo..fo + 4].try_into().unwrap_or([0; 4]));
        if rva != 0 {
            found.push(rva);
        }
    }
    found
}

/// Base names of the DLLs this anti-cheat injects.
const OWN_DLL_NAMES: &[&str] = &[
    "peregrinegame_x64.dll",
    "peregrinegame_x86.dll",
    "peregrinesensor_x64.dll",
    "peregrinesensor_x86.dll",
];

/// Address ranges of our injected DLL inside the target: right base name
/// *and* loaded from the directory this GUI runs from (the directory the
/// driver's file self-defense covers) — a DLL that merely carries the name
/// somewhere else is not ours.
fn own_dll_ranges(modules: &[ModuleEntry]) -> Vec<(usize, usize)> {
    let own_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_string_lossy().to_ascii_lowercase()));
    let Some(own_dir) = own_dir else {
        return Vec::new();
    };

    modules
        .iter()
        .filter(|m| {
            let base = module_basename(&m.path);
            let dir = Path::new(&m.path)
                .parent()
                .map(|d| d.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            OWN_DLL_NAMES.contains(&base.as_str()) && dir == own_dir
        })
        .map(|m| (m.base, m.base + m.size))
        .collect()
}

fn in_ranges(addr: usize, ranges: &[(usize, usize)]) -> bool {
    ranges.iter().any(|&(lo, hi)| addr >= lo && addr < hi)
}

/// Follows the detour MinHook writes at `site`:
///   x86:  E9 rel32                      -> detour
///   x64:  E9 rel32 -> relay: FF 25 00000000 <abs64> -> detour
/// Returns (relay address if there is one, final destination).
fn hook_destination(proc: &ProcessHandle, site: usize, is64: bool) -> Option<(Option<usize>, usize)> {
    let head = proc.read_memory(site, 5)?;
    if head[0] != 0xE9 {
        return None;
    }
    let rel = i32::from_le_bytes(head[1..5].try_into().ok()?) as isize;
    let mut target = (site as isize).wrapping_add(5).wrapping_add(rel) as usize;
    if !is64 {
        target &= 0xFFFF_FFFF;
        return Some((None, target));
    }

    let relay = proc.read_memory(target, 14)?;
    if relay[..6] == [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00] {
        let dest = u64::from_le_bytes(relay[6..14].try_into().ok()?) as usize;
        Some((Some(target), dest))
    } else {
        Some((None, target))
    }
}

fn file_is_64bit(file: &[u8]) -> bool {
    if file.len() < 0x40 {
        return false;
    }
    let lfanew = u32::from_le_bytes(file[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
    if lfanew + 6 > file.len() {
        return false;
    }
    u16::from_le_bytes([file[lfanew + 4], file[lfanew + 5]]) == IMAGE_FILE_MACHINE_AMD64
}

/// One export we hook, as found in a target process.
struct HookSite {
    address: usize,
    is64: bool,
    /// Relay stub inside MinHook's buffer (x64 only).
    relay: Option<usize>,
}

/// Hook sites in `m` whose detour really ends inside our injected DLL. A
/// patched prologue that leads anywhere else is somebody else's hook.
fn verified_hook_sites(
    proc: &ProcessHandle,
    m: &ModuleEntry,
    file: &[u8],
    own: &[(usize, usize)],
) -> Vec<(u32, HookSite)> {
    let Some(names) = self_hook_names_for(&m.path) else {
        return Vec::new();
    };
    let is64 = file_is_64bit(file);
    export_rvas(file, names)
        .into_iter()
        .filter_map(|rva| {
            let address = m.base + rva as usize;
            let (relay, dest) = hook_destination(proc, address, is64)?;
            in_ranges(dest, own).then_some((rva, HookSite { address, is64, relay }))
        })
        .collect()
}

/// Zero the prologues of *verified* self-hooks so they do not count as tamper.
fn mask_self_hooks(
    disk_data: &mut [u8],
    mem_data: &mut [u8],
    text_rva: u32,
    sites: &[(u32, HookSite)],
) -> usize {
    let mut masked = 0usize;
    for (rva, _) in sites {
        if *rva < text_rva {
            continue;
        }
        let off = (*rva - text_rva) as usize;
        if off >= disk_data.len() {
            continue;
        }
        zero_range(disk_data, off, HOOK_MASK_BYTES);
        zero_range(mem_data, off, HOOK_MASK_BYTES);
        masked += 1;
    }
    masked
}

/// Private executable regions in `pid` that hold MinHook's trampolines for our
/// own hooks. Such a region looks exactly like injected code to a VAD scan, so
/// it is not exempted by address or by anything the game process says about
/// itself, but only if it is tied to a verified hook site:
///   x64: the relay stub the hooked export jumps to lies in the region;
///   x86: the region contains the trampoline's jump back into the hooked
///        export (there is no relay on x86).
pub fn own_hook_regions(pid: u32) -> Result<Vec<u64>, String> {
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE,
    };

    let proc = ProcessHandle::open(pid).ok_or("OpenProcess failed")?;
    let modules = proc.modules();
    let own = own_dll_ranges(&modules);
    if own.is_empty() {
        return Ok(Vec::new());
    }

    let mut sites: Vec<HookSite> = Vec::new();
    for m in &modules {
        if self_hook_names_for(&m.path).is_none() {
            continue;
        }
        let disk_path = wow64_fixup(&m.path, m.base);
        let Ok(file) = std::fs::read(&disk_path) else {
            continue;
        };
        sites.extend(verified_hook_sites(&proc, m, &file, &own).into_iter().map(|(_, s)| s));
    }
    if sites.is_empty() {
        return Ok(Vec::new());
    }

    let region_of = |addr: usize| -> Option<(usize, usize)> {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let got = unsafe {
            VirtualQueryEx(
                proc.0,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        (got != 0 && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
            .then_some((mbi.BaseAddress as usize, mbi.RegionSize))
    };

    let mut regions: Vec<u64> = Vec::new();
    let mut add = |base: usize| {
        if !regions.contains(&(base as u64)) {
            regions.push(base as u64);
        }
    };

    // x64: the relay is in the buffer.
    for s in sites.iter().filter(|s| s.is64) {
        if let Some((base, _)) = s.relay.and_then(|r| region_of(r)) {
            add(base);
        }
    }

    // x86: look for the trampoline's jump back into a hooked export. MinHook
    // allocates its buffer in 4 KiB blocks; only small regions are candidates.
    let x86_sites: Vec<&HookSite> = sites.iter().filter(|s| !s.is64).collect();
    if !x86_sites.is_empty() {
        const MAX_REGION: usize = 0x10000;
        let mut addr = 0x10000usize;
        while addr < 0x8000_0000 {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let got = unsafe {
                VirtualQueryEx(
                    proc.0,
                    Some(addr as *const _),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if got == 0 || mbi.RegionSize == 0 {
                break;
            }
            let base = mbi.BaseAddress as usize;
            let executable = (mbi.Protect.0 & 0xF0) != 0;
            if mbi.State == MEM_COMMIT
                && mbi.Type == MEM_PRIVATE
                && executable
                && mbi.RegionSize <= MAX_REGION
            {
                if let Some(bytes) = proc.read_memory(base, mbi.RegionSize) {
                    let jumps_back = bytes.windows(5).enumerate().any(|(i, w)| {
                        if w[0] != 0xE9 {
                            return false;
                        }
                        let rel = i32::from_le_bytes([w[1], w[2], w[3], w[4]]) as isize;
                        let dest = ((base + i) as isize).wrapping_add(5).wrapping_add(rel) as usize
                            & 0xFFFF_FFFF;
                        x86_sites
                            .iter()
                            .any(|s| dest > s.address && dest <= s.address + HOOK_MASK_BYTES)
                    });
                    if jumps_back {
                        add(base);
                    }
                }
            }
            addr = base + mbi.RegionSize;
        }
    }

    Ok(regions)
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
    let own = own_dll_ranges(&modules);
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
            self_hooks: None,
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

        if dh == mh {
            entry.matched = Some(true);
            entry.self_hooks = Some(false);
            entry.disk_sha256 = Some(dh);
            entry.mem_sha256 = Some(mh);
        } else {
            // PeregrineDLL MinHook patches ntdll/KernelBase prologues — exclude
            // those sites, but only the ones whose detour verifiably ends in
            // our own DLL. Anything else at these exports is a foreign hook
            // and stays in the comparison.
            let mut disk2 = disk_data.clone();
            let mut mem2 = mem_data.clone();
            let sites = verified_hook_sites(&proc, m, &file_bytes, &own);
            let n = mask_self_hooks(&mut disk2, &mut mem2, ti.text_rva, &sites);
            let dh2 = sha256_hex(&disk2);
            let mh2 = sha256_hex(&mem2);
            if n > 0 && dh2 == mh2 {
                entry.matched = Some(true);
                entry.self_hooks = Some(true);
                entry.disk_sha256 = Some(dh2);
                entry.mem_sha256 = Some(mh2);
            } else {
                entry.matched = Some(false);
                entry.self_hooks = Some(false);
                entry.disk_sha256 = Some(dh);
                entry.mem_sha256 = Some(mh);
            }
        }
        entry.section = Some(".text".into());
        entry.section_size = Some(read_sz);

        results.push(entry);
    }

    Ok(results)
}
