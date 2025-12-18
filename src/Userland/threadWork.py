import ctypes
from ctypes import wintypes
from PatchDetection import _get_modules, MODULEINFO, _module_path, kernel32, psapi, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ


def checkThread(obj, ui):
    try:
        callerPID = obj.get("callerpid", "N/A")
        targetPID = obj.get("pid", "N/A")

        # Check for remote thread creation
        if callerPID != "N/A" and targetPID != "N/A" and callerPID != targetPID:
            ui.append_log(f"[Remote Thread] callerPID={callerPID} -> targetPID={targetPID}")

        # Get start address from kernel
        start_addr_str = obj.get("start_address")
        if not start_addr_str:
            ui.append_log(f"[Thread Check] No start_address in event: {obj}")
            return

        # Parse the start address (format: "0x...")
        try:
            if isinstance(start_addr_str, str):
                start_addr = int(start_addr_str, 16)
            else:
                start_addr = int(start_addr_str)
        except (ValueError, TypeError):
            ui.append_log(f"[Thread Check] Failed to parse start_address: {start_addr_str}")
            return

        pid = obj.get("pid", "N/A")
        if pid == "N/A":
            ui.append_log("[Thread Check] No pid in thread event")
            return

        # Open process and enumerate modules (same as PatchDetection.py)
        access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        proc = kernel32.OpenProcess(access, False, pid)
        if not proc:
            raise OSError(ctypes.get_last_error(), f"OpenProcess failed for pid {pid}")

        try:
            modules = _get_modules(proc)
            found_module = None

            for hmod in modules:
                info = MODULEINFO()
                if not psapi.GetModuleInformation(proc, hmod, ctypes.byref(info), ctypes.sizeof(info)):
                    continue

                base = ctypes.cast(info.lpBaseOfDll, ctypes.c_void_p).value
                size = info.SizeOfImage

                # Check if start address is within this module's range
                if base <= start_addr < base + size:
                    path = _module_path(proc, hmod)
                    found_module = True
                    ui.append_log(f"[Thread OK] Start=0x{start_addr:X} Module={path}")
                    break

            if not found_module:
                ui.append_log(f"[SUSPICIOUS!] Thread start 0x{start_addr:X} NOT in any known module! PID={pid}")
        finally:
            kernel32.CloseHandle(proc)

    except Exception as e:
        ui.append_log(f"[Thread Check Error] {e}")
    
