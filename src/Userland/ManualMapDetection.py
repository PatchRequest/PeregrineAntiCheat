"""
Manual-Map / Shellcode Detection

Walks a process's virtual address space with VirtualQueryEx looking for
executable memory regions that don't belong to any known loaded module.
This catches:
- Manually mapped DLLs (not in module list)
- Shellcode allocated with VirtualAlloc + PAGE_EXECUTE_*
- Executable regions from any injected code
"""

import ctypes
from ctypes import wintypes
from PatchDetection import (
    kernel32, psapi, _get_modules, _module_path,
    MODULEINFO, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
)


# Memory protection constants with execute permission
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

EXECUTABLE_PROTECTIONS = (
    PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
)

# Memory state
MEM_COMMIT = 0x1000

# Memory type
MEM_IMAGE = 0x1000000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000

# Protection flag names for reporting
PROTECT_NAMES = {
    PAGE_EXECUTE: "X",
    PAGE_EXECUTE_READ: "RX",
    PAGE_EXECUTE_READWRITE: "RWX",
    PAGE_EXECUTE_WRITECOPY: "WCX",
}


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t


def _build_module_ranges(proc):
    """Get list of (base, end) for all loaded modules."""
    ranges = []
    modules = _get_modules(proc)
    for hmod in modules:
        info = MODULEINFO()
        if not psapi.GetModuleInformation(proc, hmod, ctypes.byref(info), ctypes.sizeof(info)):
            continue
        base = ctypes.cast(info.lpBaseOfDll, ctypes.c_void_p).value
        ranges.append((base, base + info.SizeOfImage))
    return ranges


def _is_in_module(addr, size, module_ranges):
    """Check if a memory region overlaps with any known module."""
    region_end = addr + size
    for mod_base, mod_end in module_ranges:
        if addr < mod_end and region_end > mod_base:
            return True
    return False


def scan_manual_map(pid):
    """
    Scan a process for executable memory regions not backed by any loaded module.
    Returns list of dicts: {address, size, protection, type}
    """
    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    proc = kernel32.OpenProcess(access, False, pid)
    if not proc:
        raise OSError(ctypes.get_last_error(), f"OpenProcess failed for pid {pid}")

    results = []
    try:
        module_ranges = _build_module_ranges(proc)

        # Walk virtual address space
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        mbi_size = ctypes.sizeof(mbi)

        while True:
            ret = kernel32.VirtualQueryEx(
                proc, ctypes.c_void_p(address),
                ctypes.byref(mbi), mbi_size)
            if ret == 0:
                break

            base = mbi.BaseAddress or 0
            region_size = mbi.RegionSize

            # Check: committed, executable, not an image (loaded DLL/EXE)
            if (mbi.State == MEM_COMMIT
                    and mbi.Protect in EXECUTABLE_PROTECTIONS
                    and mbi.Type != MEM_IMAGE
                    and not _is_in_module(base, region_size, module_ranges)):

                prot_name = PROTECT_NAMES.get(mbi.Protect, f"0x{mbi.Protect:X}")
                type_name = "private" if mbi.Type == MEM_PRIVATE else "mapped"

                results.append({
                    "address": base,
                    "size": region_size,
                    "protection": prot_name,
                    "type": type_name,
                    "alloc_base": mbi.AllocationBase or 0,
                })

            # Advance to next region
            address = base + region_size
            if address <= base:
                break

    finally:
        kernel32.CloseHandle(proc)

    return results
