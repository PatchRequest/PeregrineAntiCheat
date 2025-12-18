import ctypes
import os
import struct
import time
import sys
from ctypes import wintypes

PAGE_EXECUTE_READWRITE = 0x40

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.GetModuleHandleW.restype = wintypes.HMODULE
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]

kernel32.VirtualProtect.restype = wintypes.BOOL
kernel32.VirtualProtect.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

kernel32.GetSystemInfo.restype = None
class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD),
        ("lpMinimumApplicationAddress", wintypes.LPVOID),
        ("lpMaximumApplicationAddress", wintypes.LPVOID),
        ("dwActiveProcessorMask", ctypes.c_void_p),
        ("dwNumberOfProcessors", wintypes.DWORD),
        ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]

def get_page_size():
    info = SYSTEM_INFO()
    kernel32.GetSystemInfo(ctypes.byref(info))
    return info.dwPageSize or 0x1000

def parse_text_section(base_addr: int):
    header = ctypes.string_at(base_addr, 0x1000)
    e_magic = struct.unpack_from("<H", header, 0)[0]
    if e_magic != 0x5A4D:  # 'MZ'
        raise RuntimeError("not an MZ header at base")
    e_lfanew = struct.unpack_from("<I", header, 0x3C)[0]
    pe_sig = struct.unpack_from("<I", header, e_lfanew)[0]
    if pe_sig != 0x00004550:  # 'PE\0\0'
        raise RuntimeError("invalid PE signature")

    file_header_off = e_lfanew + 4
    num_sections = struct.unpack_from("<H", header, file_header_off + 2)[0]
    opt_size = struct.unpack_from("<H", header, file_header_off + 16)[0]
    section_off = file_header_off + 20 + opt_size

    SECTION_SIZE = 40
    for i in range(num_sections):
        off = section_off + i * SECTION_SIZE
        name = header[off : off + 8].split(b"\x00", 1)[0].decode(errors="ignore")
        virtual_size = struct.unpack_from("<I", header, off + 8)[0]
        virtual_address = struct.unpack_from("<I", header, off + 12)[0]
        size_of_raw = struct.unpack_from("<I", header, off + 16)[0]
        pointer_to_raw = struct.unpack_from("<I", header, off + 20)[0]
        if name == ".text":
            text_size = max(virtual_size, size_of_raw)
            return {
                "rva": virtual_address,
                "raw_offset": pointer_to_raw,
                "raw_size": size_of_raw,
                "virt_size": virtual_size,
                "text_size": text_size,
            }
    raise RuntimeError(".text section not found")

def patch_last_byte_of_text():
    base = kernel32.GetModuleHandleW(None)
    if not base:
        raise OSError(ctypes.get_last_error(), "GetModuleHandleW failed")
    base_int = ctypes.cast(base, ctypes.c_void_p).value
    text_info = parse_text_section(base_int)

    text_offset = text_info["rva"] + max(0, text_info["raw_size"] - 1)
    target_addr = base_int + text_offset

    orig = ctypes.string_at(target_addr, 1)
    new_byte = bytes([orig[0] ^ 0xFF])

    old_protect = wintypes.DWORD(0)
    if not kernel32.VirtualProtect(ctypes.c_void_p(target_addr), 1, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)):
        raise OSError(ctypes.get_last_error(), "VirtualProtect RW failed")

    ctypes.memmove(ctypes.c_void_p(target_addr), new_byte, 1)

    kernel32.VirtualProtect(ctypes.c_void_p(target_addr), 1, old_protect.value, ctypes.byref(old_protect))

    return {
        "base": base_int,
        "text_rva": text_info["rva"],
        "text_size": text_info["text_size"],
        "patched_offset": text_offset,
        "orig_byte": orig[0],
        "new_byte": new_byte[0],
    }

def main():
    print(f"Self-tamper helper. PID={os.getpid()}")
    try:
        info = patch_last_byte_of_text()
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Failed to patch: {exc}")
        sys.exit(1)

    print(f"[+] Patched last byte of .text")
    print(f"    base=0x{info['base']:X}")
    print(f"    text_rva=0x{info['text_rva']:X} size={info['text_size']}")
    print(f"    patched offset=0x{info['patched_offset']:X}")
    print(f"    orig=0x{info['orig_byte']:02X} -> new=0x{info['new_byte']:02X}")
    print("Now point your detector at this PID to confirm it flags the tamper.")
    print("Sleeping; press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("Exiting.")


if __name__ == "__main__":
    main()
