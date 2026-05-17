use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL,
    MODULEINFO,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::Foundation::HMODULE;

pub struct ProcessHandle(pub HANDLE);

impl ProcessHandle {
    pub fn open(pid: u32) -> Option<Self> {
        let h = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
        }
        .ok()?;
        if h == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self(h))
        }
    }

    pub fn read_memory(&self, addr: usize, size: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; size];
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.0,
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                size,
                Some(&mut read),
            )
        };
        if ok.is_err() || read == 0 {
            return None;
        }
        buf.truncate(read);
        Some(buf)
    }

    pub fn read_u16(&self, addr: usize) -> Option<u16> {
        let d = self.read_memory(addr, 2)?;
        Some(u16::from_le_bytes([d[0], d[1]]))
    }

    pub fn read_u32(&self, addr: usize) -> Option<u32> {
        let d = self.read_memory(addr, 4)?;
        Some(u32::from_le_bytes([d[0], d[1], d[2], d[3]]))
    }

    pub fn read_u64(&self, addr: usize) -> Option<u64> {
        let d = self.read_memory(addr, 8)?;
        Some(u64::from_le_bytes(d.try_into().ok()?))
    }

    pub fn read_ptr(&self, addr: usize, is64: bool) -> Option<u64> {
        if is64 {
            self.read_u64(addr)
        } else {
            self.read_u32(addr).map(|v| v as u64)
        }
    }

    pub fn read_cstring(&self, addr: usize, max: usize) -> Option<String> {
        let data = self.read_memory(addr, max)?;
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        String::from_utf8_lossy(&data[..end]).into_owned().into()
    }

    pub fn modules(&self) -> Vec<ModuleEntry> {
        let mut needed = 0u32;
        unsafe {
            let _ = EnumProcessModulesEx(
                self.0,
                std::ptr::null_mut(),
                0,
                &mut needed,
                LIST_MODULES_ALL,
            );
        }
        if needed == 0 {
            return Vec::new();
        }
        let count = needed as usize / std::mem::size_of::<HMODULE>();
        let mut arr = vec![HMODULE::default(); count];
        let ok = unsafe {
            EnumProcessModulesEx(
                self.0,
                arr.as_mut_ptr(),
                needed,
                &mut needed,
                LIST_MODULES_ALL,
            )
        };
        if ok.is_err() {
            return Vec::new();
        }
        arr.truncate(needed as usize / std::mem::size_of::<HMODULE>());

        let mut result = Vec::new();
        for hmod in &arr {
            let mut info = MODULEINFO::default();
            let ok = unsafe {
                GetModuleInformation(
                    self.0,
                    *hmod,
                    &mut info,
                    std::mem::size_of::<MODULEINFO>() as u32,
                )
            };
            if ok.is_err() {
                continue;
            }
            let base = info.lpBaseOfDll as usize;
            let size = info.SizeOfImage as usize;

            let mut buf = [0u16; 1024];
            let len = unsafe { GetModuleFileNameExW(Some(self.0), Some(*hmod), &mut buf) } as usize;
            let path = if len > 0 {
                String::from_utf16_lossy(&buf[..len])
            } else {
                String::new()
            };

            result.push(ModuleEntry { base, size, path });
        }
        result
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModuleEntry {
    pub base: usize,
    pub size: usize,
    pub path: String,
}

impl ModuleEntry {
    pub fn name(&self) -> &str {
        self.path.rsplit('\\').next().unwrap_or(&self.path)
    }
}

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

pub struct PeInfo {
    pub base: usize,
    pub is64: bool,
    pub data_dir_off: usize,
    pub num_rva: u32,
}

pub fn parse_pe_header(proc: &ProcessHandle, base: usize) -> Option<PeInfo> {
    let dos = proc.read_memory(base, 0x40)?;
    if u16::from_le_bytes([dos[0], dos[1]]) != IMAGE_DOS_SIGNATURE {
        return None;
    }
    let lfanew = u32::from_le_bytes([dos[0x3C], dos[0x3D], dos[0x3E], dos[0x3F]]) as usize;
    let sig = proc.read_u32(base + lfanew)?;
    if sig != IMAGE_NT_SIGNATURE {
        return None;
    }

    let machine = proc.read_u16(base + lfanew + 4)?;
    let is64 = machine == IMAGE_FILE_MACHINE_AMD64;
    let opt_off = base + lfanew + 24;

    let (num_rva_off, data_dir_off) = if is64 {
        (opt_off + 108, opt_off + 112)
    } else {
        (opt_off + 92, opt_off + 96)
    };

    let num_rva = proc.read_u32(num_rva_off)?;
    Some(PeInfo {
        base,
        is64,
        data_dir_off,
        num_rva,
    })
}

pub fn get_data_directory(proc: &ProcessHandle, pe: &PeInfo, idx: u32) -> Option<(u32, u32)> {
    if idx >= pe.num_rva {
        return Some((0, 0));
    }
    let off = pe.data_dir_off + idx as usize * 8;
    let rva = proc.read_u32(off)?;
    let size = proc.read_u32(off + 4)?;
    Some((rva, size))
}

pub fn addr_in_modules(addr: u64, modules: &[ModuleEntry]) -> bool {
    modules
        .iter()
        .any(|m| addr >= m.base as u64 && addr < (m.base + m.size) as u64)
}
