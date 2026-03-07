import ctypes
import struct
from ctypes import wintypes
from PatchDetection import (
    kernel32, psapi, _get_modules, _module_path, _read_process_memory,
    MODULEINFO, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
    IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64,
)

# PE data directory indices
IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1


def _read_u8(proc, addr):
    return struct.unpack("<B", _read_process_memory(proc, addr, 1))[0]


def _read_u16(proc, addr):
    return struct.unpack("<H", _read_process_memory(proc, addr, 2))[0]


def _read_u32(proc, addr):
    return struct.unpack("<I", _read_process_memory(proc, addr, 4))[0]


def _read_u64(proc, addr):
    return struct.unpack("<Q", _read_process_memory(proc, addr, 8))[0]


def _read_cstring(proc, addr, max_len=256):
    """Read a null-terminated ASCII string from process memory."""
    try:
        data = _read_process_memory(proc, ctypes.c_void_p(addr), max_len)
    except OSError:
        return None
    nul = data.find(b'\x00')
    if nul >= 0:
        data = data[:nul]
    return data.decode('ascii', errors='ignore')


def _parse_pe_header(proc, base):
    """Parse PE header from process memory. Returns dict with key info or None."""
    try:
        dos_header = _read_process_memory(proc, ctypes.c_void_p(base), 0x40)
    except OSError:
        return None

    e_magic = struct.unpack_from("<H", dos_header, 0)[0]
    if e_magic != IMAGE_DOS_SIGNATURE:
        return None

    e_lfanew = struct.unpack_from("<I", dos_header, 0x3C)[0]

    try:
        pe_sig = _read_u32(proc, ctypes.c_void_p(base + e_lfanew))
    except OSError:
        return None
    if pe_sig != IMAGE_NT_SIGNATURE:
        return None

    file_header_off = base + e_lfanew + 4
    machine = _read_u16(proc, ctypes.c_void_p(file_header_off))
    is64 = (machine == IMAGE_FILE_MACHINE_AMD64)

    opt_header_off = file_header_off + 20  # sizeof(IMAGE_FILE_HEADER)

    # Read NumberOfRvaAndSizes and DataDirectory
    if is64:
        num_rva_off = opt_header_off + 108  # offset within optional header
        data_dir_off = opt_header_off + 112
    else:
        num_rva_off = opt_header_off + 92
        data_dir_off = opt_header_off + 96

    try:
        num_rva = _read_u32(proc, ctypes.c_void_p(num_rva_off))
    except OSError:
        return None

    return {
        "base": base,
        "is64": is64,
        "data_dir_off": data_dir_off,
        "num_rva": num_rva,
    }


def _get_data_directory(proc, pe_info, index):
    """Get (RVA, Size) of a data directory entry."""
    if index >= pe_info["num_rva"]:
        return (0, 0)
    entry_off = pe_info["data_dir_off"] + index * 8
    rva = _read_u32(proc, ctypes.c_void_p(entry_off))
    size = _read_u32(proc, ctypes.c_void_p(entry_off + 4))
    return (rva, size)


def _build_module_map(proc):
    """Build a dict mapping lowercase DLL name -> (base, size)."""
    mod_map = {}
    modules = _get_modules(proc)
    for hmod in modules:
        info = MODULEINFO()
        if not psapi.GetModuleInformation(proc, hmod, ctypes.byref(info), ctypes.sizeof(info)):
            continue
        path = _module_path(proc, hmod)
        if not path:
            continue
        base = ctypes.cast(info.lpBaseOfDll, ctypes.c_void_p).value
        size = info.SizeOfImage
        name = path.rsplit("\\", 1)[-1].lower()
        mod_map[name] = (base, size)
        # Also store without extension for matching flexibility
        if name.endswith(".dll"):
            mod_map[name[:-4]] = (base, size)
    return mod_map


def check_iat_hooks(pid):
    """
    Scan all modules in a process for IAT hooks.
    Returns list of dicts: {module, imported_dll, function, expected_module, actual_addr, hooked}
    """
    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    proc = kernel32.OpenProcess(access, False, pid)
    if not proc:
        raise OSError(ctypes.get_last_error(), f"OpenProcess failed for pid {pid}")

    results = []
    try:
        mod_map = _build_module_map(proc)
        modules = _get_modules(proc)

        for hmod in modules:
            info = MODULEINFO()
            if not psapi.GetModuleInformation(proc, hmod, ctypes.byref(info), ctypes.sizeof(info)):
                continue
            path = _module_path(proc, hmod)
            if not path:
                continue
            base = ctypes.cast(info.lpBaseOfDll, ctypes.c_void_p).value

            pe_info = _parse_pe_header(proc, base)
            if not pe_info:
                continue

            import_rva, import_size = _get_data_directory(proc, pe_info, IMAGE_DIRECTORY_ENTRY_IMPORT)
            if import_rva == 0:
                continue

            is64 = pe_info["is64"]
            ptr_size = 8 if is64 else 4
            read_ptr = _read_u64 if is64 else _read_u32
            ordinal_flag = (1 << 63) if is64 else (1 << 31)

            # Walk IMAGE_IMPORT_DESCRIPTORs (20 bytes each, null-terminated)
            desc_addr = base + import_rva
            while True:
                try:
                    ilt_rva = _read_u32(proc, ctypes.c_void_p(desc_addr + 0))   # OriginalFirstThunk
                    name_rva = _read_u32(proc, ctypes.c_void_p(desc_addr + 12))
                    iat_rva = _read_u32(proc, ctypes.c_void_p(desc_addr + 16))  # FirstThunk
                except OSError:
                    break

                # Null descriptor = end
                if iat_rva == 0 and name_rva == 0:
                    break

                dll_name = _read_cstring(proc, base + name_rva) if name_rva else "?"
                dll_name_lower = dll_name.lower() if dll_name else "?"

                # Resolve expected DLL base/size
                dll_key = dll_name_lower.replace(".dll", "") if dll_name_lower.endswith(".dll") else dll_name_lower
                expected_base, expected_size = mod_map.get(dll_key, (None, None))
                if expected_base is None:
                    expected_base, expected_size = mod_map.get(dll_name_lower, (None, None))

                # Use OriginalFirstThunk (ILT) for names if available, else use IAT
                name_table_rva = ilt_rva if ilt_rva else iat_rva
                iat_entry_addr = base + iat_rva
                name_entry_addr = base + name_table_rva

                idx = 0
                while True:
                    try:
                        iat_value = read_ptr(proc, ctypes.c_void_p(iat_entry_addr))
                        name_value = read_ptr(proc, ctypes.c_void_p(name_entry_addr))
                    except OSError:
                        break

                    if iat_value == 0:
                        break

                    # Get function name from ILT
                    func_name = None
                    if name_value and not (name_value & ordinal_flag):
                        # Points to IMAGE_IMPORT_BY_NAME: 2-byte hint + name
                        func_name = _read_cstring(proc, base + (name_value & 0x7FFFFFFF) + 2)
                    if not func_name:
                        func_name = f"ordinal_{idx}"

                    # Check if IAT pointer falls within expected DLL
                    hooked = False
                    if expected_base is not None:
                        if not (expected_base <= iat_value < expected_base + expected_size):
                            hooked = True

                    if hooked:
                        mod_name = path.rsplit("\\", 1)[-1]
                        results.append({
                            "module": mod_name,
                            "imported_dll": dll_name,
                            "function": func_name,
                            "iat_value": iat_value,
                            "expected_range": (expected_base, expected_base + expected_size) if expected_base else None,
                            "hooked": True,
                        })

                    iat_entry_addr += ptr_size
                    name_entry_addr += ptr_size
                    idx += 1

                desc_addr += 20  # next IMAGE_IMPORT_DESCRIPTOR

    finally:
        kernel32.CloseHandle(proc)

    return results


def check_eat_hooks(pid):
    """
    Scan all modules in a process for EAT hooks.
    Returns list of dicts: {module, function, rva, target_addr, hooked, forwarder}
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
                continue
            path = _module_path(proc, hmod)
            if not path:
                continue
            base = ctypes.cast(info.lpBaseOfDll, ctypes.c_void_p).value
            mod_size = info.SizeOfImage

            pe_info = _parse_pe_header(proc, base)
            if not pe_info:
                continue

            export_rva, export_size = _get_data_directory(proc, pe_info, IMAGE_DIRECTORY_ENTRY_EXPORT)
            if export_rva == 0 or export_size == 0:
                continue

            export_dir_start = export_rva
            export_dir_end = export_rva + export_size

            # Read IMAGE_EXPORT_DIRECTORY fields
            export_addr = base + export_rva
            try:
                num_functions = _read_u32(proc, ctypes.c_void_p(export_addr + 20))
                num_names = _read_u32(proc, ctypes.c_void_p(export_addr + 24))
                addr_of_functions_rva = _read_u32(proc, ctypes.c_void_p(export_addr + 28))
                addr_of_names_rva = _read_u32(proc, ctypes.c_void_p(export_addr + 32))
                addr_of_ordinals_rva = _read_u32(proc, ctypes.c_void_p(export_addr + 36))
            except OSError:
                continue

            # Build ordinal-to-name map
            ordinal_to_name = {}
            for i in range(num_names):
                try:
                    name_rva = _read_u32(proc, ctypes.c_void_p(base + addr_of_names_rva + i * 4))
                    ordinal = _read_u16(proc, ctypes.c_void_p(base + addr_of_ordinals_rva + i * 2))
                    name = _read_cstring(proc, base + name_rva, 128)
                    if name:
                        ordinal_to_name[ordinal] = name
                except OSError:
                    continue

            # Walk AddressOfFunctions
            for i in range(num_functions):
                try:
                    func_rva = _read_u32(proc, ctypes.c_void_p(base + addr_of_functions_rva + i * 4))
                except OSError:
                    continue

                if func_rva == 0:
                    continue

                func_name = ordinal_to_name.get(i, f"ordinal_{i}")

                # Check if RVA points within export directory = forwarder (legitimate)
                if export_dir_start <= func_rva < export_dir_end:
                    continue  # forwarder, skip

                # Check if base + func_rva falls within the module
                target_addr = base + func_rva
                if not (base <= target_addr < base + mod_size):
                    mod_name = path.rsplit("\\", 1)[-1]
                    results.append({
                        "module": mod_name,
                        "function": func_name,
                        "rva": func_rva,
                        "target_addr": target_addr,
                        "module_range": (base, base + mod_size),
                        "hooked": True,
                    })

    finally:
        kernel32.CloseHandle(proc)

    return results
