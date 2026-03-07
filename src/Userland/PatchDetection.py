import ctypes
import hashlib
import os
import struct
from ctypes import wintypes

# Minimal module integrity checker: compares .text section in memory vs on-disk.
# Avoids false positives from relocations/IAT/.data differences.

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03  # EnumProcessModulesEx flag

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", wintypes.LPVOID),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", wintypes.LPVOID),
    ]


kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

psapi.EnumProcessModulesEx.restype = wintypes.BOOL
psapi.EnumProcessModulesEx.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.HMODULE),
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.DWORD,
]
psapi.GetModuleFileNameExW.restype = wintypes.DWORD
psapi.GetModuleFileNameExW.argtypes = [
    wintypes.HANDLE,
    wintypes.HMODULE,
    wintypes.LPWSTR,
    wintypes.DWORD,
]
psapi.GetModuleInformation.restype = wintypes.BOOL
psapi.GetModuleInformation.argtypes = [
    wintypes.HANDLE,
    wintypes.HMODULE,
    ctypes.POINTER(MODULEINFO),
    wintypes.DWORD,
]


def _hash_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _read_process_memory(proc, base, size):
    buf = (ctypes.c_ubyte * size)()
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(proc, base, buf, size, ctypes.byref(read))
    if not ok or read.value == 0:
        raise OSError(ctypes.get_last_error(), "ReadProcessMemory failed")
    return bytes(buf[: read.value])


def _get_modules(proc):
    needed = wintypes.DWORD(0)
    psapi.EnumProcessModulesEx(proc, None, 0, ctypes.byref(needed), LIST_MODULES_ALL)
    if needed.value == 0:
        return []
    count = needed.value // ctypes.sizeof(wintypes.HMODULE)
    mod_array = (wintypes.HMODULE * count)()
    if not psapi.EnumProcessModulesEx(proc, mod_array, needed, ctypes.byref(needed), LIST_MODULES_ALL):
        raise OSError(ctypes.get_last_error(), "EnumProcessModulesEx failed")
    return list(mod_array)[: count]


def _module_path(proc, hmod):
    buf = ctypes.create_unicode_buffer(1024)
    length = psapi.GetModuleFileNameExW(proc, hmod, buf, len(buf))
    if length == 0:
        return None
    return buf.value


# PE parsing helpers (minimal)
IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664


class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ("e_magic", wintypes.WORD),
        ("e_cblp", wintypes.WORD),
        ("e_cp", wintypes.WORD),
        ("e_crlc", wintypes.WORD),
        ("e_cparhdr", wintypes.WORD),
        ("e_minalloc", wintypes.WORD),
        ("e_maxalloc", wintypes.WORD),
        ("e_ss", wintypes.WORD),
        ("e_sp", wintypes.WORD),
        ("e_csum", wintypes.WORD),
        ("e_ip", wintypes.WORD),
        ("e_cs", wintypes.WORD),
        ("e_lfarlc", wintypes.WORD),
        ("e_ovno", wintypes.WORD),
        ("e_res", wintypes.WORD * 4),
        ("e_oemid", wintypes.WORD),
        ("e_oeminfo", wintypes.WORD),
        ("e_res2", wintypes.WORD * 10),
        ("e_lfanew", wintypes.LONG),
    ]


class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ("Machine", wintypes.WORD),
        ("NumberOfSections", wintypes.WORD),
        ("TimeDateStamp", wintypes.DWORD),
        ("PointerToSymbolTable", wintypes.DWORD),
        ("NumberOfSymbols", wintypes.DWORD),
        ("SizeOfOptionalHeader", wintypes.WORD),
        ("Characteristics", wintypes.WORD),
    ]


class IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [("VirtualAddress", wintypes.DWORD), ("Size", wintypes.DWORD)]


class IMAGE_OPTIONAL_HEADER32(ctypes.Structure):
    _fields_ = [
        ("Magic", wintypes.WORD),
        ("MajorLinkerVersion", ctypes.c_byte),
        ("MinorLinkerVersion", ctypes.c_byte),
        ("SizeOfCode", wintypes.DWORD),
        ("SizeOfInitializedData", wintypes.DWORD),
        ("SizeOfUninitializedData", wintypes.DWORD),
        ("AddressOfEntryPoint", wintypes.DWORD),
        ("BaseOfCode", wintypes.DWORD),
        ("BaseOfData", wintypes.DWORD),
        ("ImageBase", wintypes.DWORD),
        ("SectionAlignment", wintypes.DWORD),
        ("FileAlignment", wintypes.DWORD),
        ("MajorOperatingSystemVersion", wintypes.WORD),
        ("MinorOperatingSystemVersion", wintypes.WORD),
        ("MajorImageVersion", wintypes.WORD),
        ("MinorImageVersion", wintypes.WORD),
        ("MajorSubsystemVersion", wintypes.WORD),
        ("MinorSubsystemVersion", wintypes.WORD),
        ("Win32VersionValue", wintypes.DWORD),
        ("SizeOfImage", wintypes.DWORD),
        ("SizeOfHeaders", wintypes.DWORD),
        ("CheckSum", wintypes.DWORD),
        ("Subsystem", wintypes.WORD),
        ("DllCharacteristics", wintypes.WORD),
        ("SizeOfStackReserve", wintypes.DWORD),
        ("SizeOfStackCommit", wintypes.DWORD),
        ("SizeOfHeapReserve", wintypes.DWORD),
        ("SizeOfHeapCommit", wintypes.DWORD),
        ("LoaderFlags", wintypes.DWORD),
        ("NumberOfRvaAndSizes", wintypes.DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * 16),
    ]


class IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
    _fields_ = [
        ("Magic", wintypes.WORD),
        ("MajorLinkerVersion", ctypes.c_byte),
        ("MinorLinkerVersion", ctypes.c_byte),
        ("SizeOfCode", wintypes.DWORD),
        ("SizeOfInitializedData", wintypes.DWORD),
        ("SizeOfUninitializedData", wintypes.DWORD),
        ("AddressOfEntryPoint", wintypes.DWORD),
        ("BaseOfCode", wintypes.DWORD),
        ("ImageBase", ctypes.c_ulonglong),
        ("SectionAlignment", wintypes.DWORD),
        ("FileAlignment", wintypes.DWORD),
        ("MajorOperatingSystemVersion", wintypes.WORD),
        ("MinorOperatingSystemVersion", wintypes.WORD),
        ("MajorImageVersion", wintypes.WORD),
        ("MinorImageVersion", wintypes.WORD),
        ("MajorSubsystemVersion", wintypes.WORD),
        ("MinorSubsystemVersion", wintypes.WORD),
        ("Win32VersionValue", wintypes.DWORD),
        ("SizeOfImage", wintypes.DWORD),
        ("SizeOfHeaders", wintypes.DWORD),
        ("CheckSum", wintypes.DWORD),
        ("Subsystem", wintypes.WORD),
        ("DllCharacteristics", wintypes.WORD),
        ("SizeOfStackReserve", ctypes.c_ulonglong),
        ("SizeOfStackCommit", ctypes.c_ulonglong),
        ("SizeOfHeapReserve", ctypes.c_ulonglong),
        ("SizeOfHeapCommit", ctypes.c_ulonglong),
        ("LoaderFlags", wintypes.DWORD),
        ("NumberOfRvaAndSizes", wintypes.DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * 16),
    ]


class IMAGE_NT_HEADERS32(ctypes.Structure):
    _fields_ = [
        ("Signature", wintypes.DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER32),
    ]


class IMAGE_NT_HEADERS64(ctypes.Structure):
    _fields_ = [
        ("Signature", wintypes.DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER64),
    ]


class IMAGE_SECTION_HEADER(ctypes.Structure):
    _fields_ = [
        ("Name", ctypes.c_char * 8),
        ("Misc", wintypes.DWORD * 1),
        ("VirtualAddress", wintypes.DWORD),
        ("SizeOfRawData", wintypes.DWORD),
        ("PointerToRawData", wintypes.DWORD),
        ("PointerToRelocations", wintypes.DWORD),
        ("PointerToLinenumbers", wintypes.DWORD),
        ("NumberOfRelocations", wintypes.WORD),
        ("NumberOfLinenumbers", wintypes.WORD),
        ("Characteristics", wintypes.DWORD),
    ]


def _parse_pe_info(file_bytes):
    """Parse PE and return dict with text section info, image base, and reloc offsets within .text."""
    dos = IMAGE_DOS_HEADER.from_buffer_copy(file_bytes)
    if dos.e_magic != IMAGE_DOS_SIGNATURE:
        return None
    nt_off = dos.e_lfanew
    sig = struct.unpack_from("<I", file_bytes, nt_off)[0]
    if sig != IMAGE_NT_SIGNATURE:
        return None
    machine = struct.unpack_from("<H", file_bytes, nt_off + 4)[0]
    if machine == IMAGE_FILE_MACHINE_I386:
        nt = IMAGE_NT_HEADERS32.from_buffer_copy(file_bytes, nt_off)
        reloc_size = 4  # 32-bit relocations patch 4 bytes
    elif machine == IMAGE_FILE_MACHINE_AMD64:
        nt = IMAGE_NT_HEADERS64.from_buffer_copy(file_bytes, nt_off)
        reloc_size = 8  # 64-bit relocations patch 8 bytes
    else:
        return None

    image_base = nt.OptionalHeader.ImageBase
    num_sections = nt.FileHeader.NumberOfSections
    sec_off = nt_off + 4 + ctypes.sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader

    # Find .text section
    text_info = None
    for i in range(num_sections):
        off = sec_off + i * ctypes.sizeof(IMAGE_SECTION_HEADER)
        sec = IMAGE_SECTION_HEADER.from_buffer_copy(file_bytes, off)
        name = sec.Name.split(b"\x00", 1)[0].decode(errors="ignore")
        if name == ".text":
            virt_size = max(sec.SizeOfRawData, sec.Misc[0])
            text_info = (sec.VirtualAddress, sec.PointerToRawData, sec.SizeOfRawData, virt_size)
            break

    if text_info is None:
        return None

    text_rva, text_raw, text_raw_size, text_virt_size = text_info

    # Parse base relocation table to find offsets within .text that get patched
    reloc_offsets = []
    IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
    if nt.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC:
        reloc_dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
        if reloc_dir.VirtualAddress and reloc_dir.Size:
            # Find raw offset of reloc data by mapping RVA to file offset
            reloc_raw = _rva_to_raw(file_bytes, sec_off, num_sections, reloc_dir.VirtualAddress)
            if reloc_raw is not None:
                pos = reloc_raw
                end = reloc_raw + reloc_dir.Size
                text_end_rva = text_rva + text_virt_size
                while pos + 8 <= end:
                    block_rva, block_size = struct.unpack_from("<II", file_bytes, pos)
                    if block_size < 8:
                        break
                    num_entries = (block_size - 8) // 2
                    for j in range(num_entries):
                        entry = struct.unpack_from("<H", file_bytes, pos + 8 + j * 2)[0]
                        rtype = entry >> 12
                        offset = entry & 0xFFF
                        # Type 3 = HIGHLOW (32-bit), Type 10 = DIR64 (64-bit)
                        if rtype in (3, 10):
                            reloc_rva = block_rva + offset
                            if text_rva <= reloc_rva < text_end_rva:
                                reloc_offsets.append((reloc_rva - text_rva, reloc_size))
                    pos += block_size

    return {
        "text_rva": text_rva,
        "text_raw": text_raw,
        "text_raw_size": text_raw_size,
        "text_virt_size": text_virt_size,
        "image_base": image_base,
        "reloc_offsets": reloc_offsets,
    }


def _rva_to_raw(file_bytes, sec_off, num_sections, rva):
    """Convert an RVA to a raw file offset using section headers."""
    for i in range(num_sections):
        off = sec_off + i * ctypes.sizeof(IMAGE_SECTION_HEADER)
        sec = IMAGE_SECTION_HEADER.from_buffer_copy(file_bytes, off)
        if sec.VirtualAddress <= rva < sec.VirtualAddress + sec.SizeOfRawData:
            return sec.PointerToRawData + (rva - sec.VirtualAddress)
    return None


def _zero_reloc_offsets(data, reloc_offsets):
    """Zero out bytes at relocation offsets to ignore loader fixups."""
    buf = bytearray(data)
    for offset, size in reloc_offsets:
        for k in range(size):
            if offset + k < len(buf):
                buf[offset + k] = 0
    return bytes(buf)


def check_process_modules(pid, max_bytes=8 * 1024 * 1024):
    """
    Returns a list of dicts per module:
    {path, base, size, mem_sha256, disk_sha256, matched, error}
    """
    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    proc = kernel32.OpenProcess(access, False, pid)
    if not proc:
        raise OSError(ctypes.get_last_error(), f"OpenProcess failed for pid {pid}")

    results = []
    try:
        modules = _get_modules(proc)
        for hmod in modules:
            info = MODULEINFO()
            if not psapi.GetModuleInformation(proc, hmod, ctypes.byref(info), ctypes.sizeof(info)):
                results.append(
                    {"path": None, "base": None, "size": None, "matched": None, "error": "GetModuleInformation failed"}
                )
                continue

            size = info.SizeOfImage
            path = _module_path(proc, hmod)
            entry = {"path": path, "base": ctypes.cast(info.lpBaseOfDll, ctypes.c_void_p).value, "size": size}

            # Prefer comparing .text section to avoid expected runtime differences elsewhere.
            if path and os.path.exists(path):
                try:
                    with open(path, "rb") as f:
                        file_bytes = f.read()
                except Exception as exc:  # noqa: BLE001
                    entry["error"] = f"disk read failed: {exc}"
                    entry["matched"] = None
                    results.append(entry)
                    continue
                pe_info = _parse_pe_info(file_bytes)
                if pe_info:
                    rva = pe_info["text_rva"]
                    raw_off = pe_info["text_raw"]
                    raw_size = pe_info["text_raw_size"]
                    virt_size = pe_info["text_virt_size"]
                    size_to_read = min(virt_size, raw_size, max_bytes)
                    disk_data = file_bytes[raw_off : raw_off + size_to_read]
                    try:
                        mem_data = _read_process_memory(
                            proc,
                            ctypes.c_void_p(ctypes.cast(info.lpBaseOfDll, ctypes.c_void_p).value + rva),
                            size_to_read,
                        )
                        # Zero out relocation offsets to ignore loader fixups
                        reloc_offsets = pe_info["reloc_offsets"]
                        if reloc_offsets:
                            disk_data = _zero_reloc_offsets(disk_data, reloc_offsets)
                            mem_data = _zero_reloc_offsets(mem_data, reloc_offsets)
                        entry["mem_sha256"] = _hash_bytes(mem_data)
                        entry["disk_sha256"] = _hash_bytes(disk_data)
                        entry["matched"] = entry["disk_sha256"] == entry["mem_sha256"]
                        entry["section"] = ".text"
                        entry["section_size"] = size_to_read
                    except Exception as exc:  # noqa: BLE001
                        entry["error"] = f"ReadProcessMemory failed: {exc}"
                        entry["matched"] = None
                else:
                    entry["error"] = "no .text section found"
                    entry["matched"] = None
            else:
                entry["disk_sha256"] = None
                entry["matched"] = None
                entry["error"] = "module path missing"

            results.append(entry)
    finally:
        kernel32.CloseHandle(proc)

    return results


__all__ = ["check_process_modules"]
