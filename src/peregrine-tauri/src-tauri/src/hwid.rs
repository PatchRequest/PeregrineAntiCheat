use serde::Serialize;
use std::ffi::CStr;

#[derive(Debug, Clone, Serialize)]
pub struct HwidEntry {
    pub source: String,
    pub name: String,
    pub value: String,
}

pub fn collect_userland_hwids() -> Vec<HwidEntry> {
    let mut entries = Vec::new();
    collect_mac_addresses(&mut entries);
    collect_volume_serials(&mut entries);
    collect_smbios(&mut entries);
    collect_registry_ids(&mut entries);
    entries
}

// ============================================================
// Raw FFI declarations
// ============================================================

const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as i32 as isize;
const KEY_READ: u32 = 0x20019;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const REG_QWORD: u32 = 11;
const ERROR_SUCCESS: u32 = 0;
const RSMB: u32 = 0x52534D42;

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(key: isize, subkey: *const u16, opts: u32, sam: u32, result: *mut isize) -> u32;
    fn RegQueryValueExW(key: isize, value: *const u16, reserved: *const u32, reg_type: *mut u32, data: *mut u8, size: *mut u32) -> u32;
    fn RegCloseKey(key: isize) -> u32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetVolumeInformationW(root: *const u16, vol_name: *mut u16, vol_size: u32, serial: *mut u32, max_comp: *mut u32, flags: *mut u32, fs_name: *mut u16, fs_size: u32) -> i32;
    fn GetSystemFirmwareTable(provider: u32, table_id: u32, buf: *mut u8, size: u32) -> u32;
}

#[repr(C)]
struct AdapterInfo {
    next: *mut AdapterInfo,
    combo_index: u32,
    adapter_name: [u8; 260],
    description: [u8; 132],
    address_length: u32,
    address: [u8; 8],
}

#[link(name = "iphlpapi")]
extern "system" {
    fn GetAdaptersInfo(info: *mut AdapterInfo, size: *mut u32) -> u32;
}

// ============================================================
// Registry helper
// ============================================================

fn read_reg(subkey: &str, value_name: &str) -> Option<String> {
    unsafe {
        let sk: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let vn: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();

        let mut hkey: isize = 0;
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, sk.as_ptr(), 0, KEY_READ, &mut hkey) != ERROR_SUCCESS {
            return None;
        }

        let mut rtype: u32 = 0;
        let mut size: u32 = 0;
        if RegQueryValueExW(hkey, vn.as_ptr(), std::ptr::null(), &mut rtype, std::ptr::null_mut(), &mut size) != ERROR_SUCCESS || size == 0 {
            RegCloseKey(hkey);
            return None;
        }

        let mut data = vec![0u8; size as usize];
        let ret = RegQueryValueExW(hkey, vn.as_ptr(), std::ptr::null(), &mut rtype, data.as_mut_ptr(), &mut size);
        RegCloseKey(hkey);
        if ret != ERROR_SUCCESS { return None; }

        match rtype {
            REG_SZ | REG_EXPAND_SZ => {
                let wide = std::slice::from_raw_parts(data.as_ptr() as *const u16, size as usize / 2);
                Some(String::from_utf16_lossy(wide).trim_end_matches('\0').to_string())
            }
            REG_DWORD if data.len() >= 4 => {
                Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string())
            }
            REG_QWORD if data.len() >= 8 => {
                Some(u64::from_le_bytes(data[..8].try_into().unwrap()).to_string())
            }
            _ => None,
        }
    }
}

// ============================================================
// MAC Addresses via GetAdaptersInfo
// ============================================================

fn collect_mac_addresses(out: &mut Vec<HwidEntry>) {
    unsafe {
        let mut size: u32 = 0;
        GetAdaptersInfo(std::ptr::null_mut(), &mut size);
        if size == 0 { return; }

        let layout = std::alloc::Layout::from_size_align(size as usize, 8).unwrap();
        let buf = std::alloc::alloc_zeroed(layout);
        if buf.is_null() { return; }

        if GetAdaptersInfo(buf as *mut AdapterInfo, &mut size) == ERROR_SUCCESS {
            let mut ptr = buf as *const AdapterInfo;
            let mut idx = 0u32;
            while !ptr.is_null() {
                let a = &*ptr;
                let len = a.address_length as usize;
                if len > 0 && len <= 8 {
                    let mac = a.address[..len].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":");
                    let desc = CStr::from_ptr(a.description.as_ptr() as *const i8)
                        .to_string_lossy().into_owned();
                    out.push(HwidEntry {
                        source: "userland".into(),
                        name: format!("mac_{} ({})", idx, desc),
                        value: mac,
                    });
                    idx += 1;
                }
                ptr = a.next;
            }
        }
        std::alloc::dealloc(buf, layout);
    }
}

// ============================================================
// Volume Serial Numbers
// ============================================================

fn collect_volume_serials(out: &mut Vec<HwidEntry>) {
    for letter in ['C', 'D', 'E', 'F'] {
        let root: Vec<u16> = format!("{}:\\", letter).encode_utf16().chain(std::iter::once(0)).collect();
        let mut serial: u32 = 0;
        let ok = unsafe {
            GetVolumeInformationW(
                root.as_ptr(), std::ptr::null_mut(), 0,
                &mut serial, std::ptr::null_mut(), std::ptr::null_mut(),
                std::ptr::null_mut(), 0,
            )
        };
        if ok != 0 && serial != 0 {
            out.push(HwidEntry {
                source: "userland".into(),
                name: format!("volume_serial_{}", letter),
                value: format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF),
            });
        }
    }
}

// ============================================================
// SMBIOS UUID + Serial via GetSystemFirmwareTable
// ============================================================

fn collect_smbios(out: &mut Vec<HwidEntry>) {
    unsafe {
        let size = GetSystemFirmwareTable(RSMB, 0, std::ptr::null_mut(), 0);
        if size < 8 { return; }

        let mut buf = vec![0u8; size as usize];
        let written = GetSystemFirmwareTable(RSMB, 0, buf.as_mut_ptr(), size);
        if written < 8 { return; }

        let table = &buf[8..written as usize];
        let mut off = 0usize;

        while off + 4 <= table.len() {
            let etype = table[off];
            let elen = table[off + 1] as usize;
            if elen < 4 { break; }

            if etype == 1 && elen >= 24 && off + 24 <= table.len() {
                // UUID at offset 8 within the Type 1 entry
                let u = &table[off + 8..off + 24];
                let uuid = format!(
                    "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                    u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6],
                    u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15],
                );
                out.push(HwidEntry { source: "userland".into(), name: "smbios_uuid".into(), value: uuid });

                // Serial number string (index at offset 7)
                let serial_idx = table[off + 7] as usize;
                if serial_idx > 0 {
                    if let Some(s) = smbios_string(table, off, elen, serial_idx) {
                        if !s.is_empty() {
                            out.push(HwidEntry { source: "userland".into(), name: "smbios_serial".into(), value: s });
                        }
                    }
                }
                // Product name (index at offset 5)
                let product_idx = table[off + 5] as usize;
                if product_idx > 0 {
                    if let Some(s) = smbios_string(table, off, elen, product_idx) {
                        if !s.is_empty() {
                            out.push(HwidEntry { source: "userland".into(), name: "smbios_product".into(), value: s });
                        }
                    }
                }
                break;
            }

            // Skip to next entry: past formatted area, then past double-null-terminated strings
            let mut p = off + elen;
            while p + 1 < table.len() {
                if table[p] == 0 && table[p + 1] == 0 { p += 2; break; }
                p += 1;
            }
            off = p;
        }
    }
}

fn smbios_string(table: &[u8], entry_off: usize, entry_len: usize, idx: usize) -> Option<String> {
    let mut p = entry_off + entry_len;
    let mut cur = 1usize;
    while p < table.len() {
        let end = table[p..].iter().position(|&b| b == 0).map(|i| p + i)?;
        if cur == idx {
            return Some(String::from_utf8_lossy(&table[p..end]).into_owned());
        }
        p = end + 1;
        if p < table.len() && table[p] == 0 { break; } // double null = end of strings
        cur += 1;
    }
    None
}

// ============================================================
// Registry identifiers
// ============================================================

fn collect_registry_ids(out: &mut Vec<HwidEntry>) {
    let keys: &[(&str, &str, &str)] = &[
        ("machine_guid",        r"SOFTWARE\Microsoft\Cryptography", "MachineGuid"),
        ("hw_profile_guid",     r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001", "HwProfileGuid"),
        ("computer_hw_id",      r"SYSTEM\CurrentControlSet\Control\SystemInformation", "ComputerHardwareId"),
        ("product_id",          r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductId"),
        ("install_date",        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "InstallDate"),
        ("install_time",        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "InstallTime"),
        ("sus_client_id",       r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "SusClientId"),
        ("sqm_machine_id",      r"SOFTWARE\Microsoft\SQMClient", "MachineId"),
        ("activation_machine",  r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows Activation Technologies\AdminObject\Store", "MachineId"),
    ];

    for &(name, subkey, value) in keys {
        if let Some(v) = read_reg(subkey, value) {
            if !v.is_empty() {
                out.push(HwidEntry { source: "userland".into(), name: name.into(), value: v });
            }
        }
    }
}
