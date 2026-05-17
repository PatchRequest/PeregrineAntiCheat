use super::pe::*;
use serde::Serialize;

const IMAGE_DIRECTORY_ENTRY_EXPORT: u32 = 0;
const IMAGE_DIRECTORY_ENTRY_IMPORT: u32 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct IatHook {
    pub module: String,
    pub imported_dll: String,
    pub function: String,
    pub iat_value: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EatHook {
    pub module: String,
    pub function: String,
    pub rva: u32,
    pub target_addr: u64,
}

pub fn check_iat_hooks(pid: u32) -> Result<Vec<IatHook>, String> {
    let proc = ProcessHandle::open(pid).ok_or("OpenProcess failed")?;
    let modules = proc.modules();
    let mut results = Vec::new();

    for m in &modules {
        let pe = match parse_pe_header(&proc, m.base) {
            Some(p) => p,
            None => continue,
        };

        let (import_rva, _) = match get_data_directory(&proc, &pe, IMAGE_DIRECTORY_ENTRY_IMPORT) {
            Some(d) => d,
            None => continue,
        };
        if import_rva == 0 {
            continue;
        }

        let ptr_size = if pe.is64 { 8usize } else { 4 };
        let ordinal_flag: u64 = if pe.is64 { 1 << 63 } else { 1 << 31 };

        let mut desc = m.base + import_rva as usize;
        loop {
            let ilt_rva = match proc.read_u32(desc) {
                Some(v) => v,
                None => break,
            };
            let name_rva = match proc.read_u32(desc + 12) {
                Some(v) => v,
                None => break,
            };
            let iat_rva = match proc.read_u32(desc + 16) {
                Some(v) => v,
                None => break,
            };

            if iat_rva == 0 && name_rva == 0 {
                break;
            }

            let dll_name = if name_rva != 0 {
                proc.read_cstring(m.base + name_rva as usize, 256)
                    .unwrap_or_else(|| "?".into())
            } else {
                "?".into()
            };

            let name_tbl = if ilt_rva != 0 { ilt_rva } else { iat_rva };
            let mut iat_addr = m.base + iat_rva as usize;
            let mut name_addr = m.base + name_tbl as usize;
            let mut idx = 0u32;

            loop {
                let iat_val = match proc.read_ptr(iat_addr, pe.is64) {
                    Some(v) => v,
                    None => break,
                };
                let name_val = match proc.read_ptr(name_addr, pe.is64) {
                    Some(v) => v,
                    None => break,
                };

                if iat_val == 0 {
                    break;
                }

                let func_name = if name_val != 0 && (name_val & ordinal_flag) == 0 {
                    let hint_addr = m.base + (name_val & 0x7FFF_FFFF) as usize + 2;
                    proc.read_cstring(hint_addr, 256)
                        .unwrap_or_else(|| format!("ordinal_{idx}"))
                } else {
                    format!("ordinal_{idx}")
                };

                if !addr_in_modules(iat_val, &modules) {
                    results.push(IatHook {
                        module: m.name().to_string(),
                        imported_dll: dll_name.clone(),
                        function: func_name,
                        iat_value: iat_val,
                    });
                }

                iat_addr += ptr_size;
                name_addr += ptr_size;
                idx += 1;
            }

            desc += 20;
        }
    }

    Ok(results)
}

pub fn check_eat_hooks(pid: u32) -> Result<Vec<EatHook>, String> {
    let proc = ProcessHandle::open(pid).ok_or("OpenProcess failed")?;
    let modules = proc.modules();
    let mut results = Vec::new();

    for m in &modules {
        let pe = match parse_pe_header(&proc, m.base) {
            Some(p) => p,
            None => continue,
        };

        let (export_rva, export_size) =
            match get_data_directory(&proc, &pe, IMAGE_DIRECTORY_ENTRY_EXPORT) {
                Some(d) => d,
                None => continue,
            };
        if export_rva == 0 || export_size == 0 {
            continue;
        }

        let ea = m.base + export_rva as usize;
        let num_funcs = match proc.read_u32(ea + 20) {
            Some(v) => v,
            None => continue,
        };
        let num_names = match proc.read_u32(ea + 24) {
            Some(v) => v,
            None => continue,
        };
        let fn_rva = match proc.read_u32(ea + 28) {
            Some(v) => v as usize,
            None => continue,
        };
        let name_rva = match proc.read_u32(ea + 32) {
            Some(v) => v as usize,
            None => continue,
        };
        let ord_rva = match proc.read_u32(ea + 36) {
            Some(v) => v as usize,
            None => continue,
        };

        let mut ord_to_name = std::collections::HashMap::new();
        for i in 0..num_names as usize {
            if let (Some(nrva), Some(ord)) = (
                proc.read_u32(m.base + name_rva + i * 4),
                proc.read_u16(m.base + ord_rva + i * 2),
            ) {
                if let Some(name) = proc.read_cstring(m.base + nrva as usize, 128) {
                    ord_to_name.insert(ord as u32, name);
                }
            }
        }

        for i in 0..num_funcs {
            let frva = match proc.read_u32(m.base + fn_rva + i as usize * 4) {
                Some(v) => v,
                None => continue,
            };
            if frva == 0 {
                continue;
            }

            let fname = ord_to_name
                .get(&i)
                .cloned()
                .unwrap_or_else(|| format!("ordinal_{i}"));

            if frva >= export_rva && frva < export_rva + export_size {
                continue;
            }

            let target = m.base as u64 + frva as u64;
            if target < m.base as u64 || target >= (m.base + m.size) as u64 {
                results.push(EatHook {
                    module: m.name().to_string(),
                    function: fname,
                    rva: frva,
                    target_addr: target,
                });
            }
        }
    }

    Ok(results)
}
