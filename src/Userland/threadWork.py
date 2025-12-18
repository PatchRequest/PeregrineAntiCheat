import ctypes
from ctypes import wintypes
from PatchDetection import _get_modules, MODULEINFO, _module_path, kernel32, psapi, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ

# Thread enumeration constants
TH32CS_SNAPTHREAD = 0x00000004
THREAD_GET_CONTEXT = 0x0008
THREAD_QUERY_INFORMATION = 0x0040
CONTEXT_FULL = 0x10007

# Thread snapshot structures
class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]

# CONTEXT structure for x64
class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("DUMMYUNIONNAME", M128A * 26),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong),
    ]

# Thread API functions
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32First.restype = wintypes.BOOL

kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32Next.restype = wintypes.BOOL

kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE

kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONTEXT)]
kernel32.GetThreadContext.restype = wintypes.BOOL


def get_module_for_address(proc, address, pid):
    """
    Find which module contains the given address.
    Returns tuple (module_path, base_address) or (None, None) if not found.
    """
    try:
        modules = _get_modules(proc)

        for hmod in modules:
            info = MODULEINFO()
            if not psapi.GetModuleInformation(proc, hmod, ctypes.byref(info), ctypes.sizeof(info)):
                continue

            base = ctypes.cast(info.lpBaseOfDll, ctypes.c_void_p).value
            size = info.SizeOfImage

            # Check if address is within this module's range
            if base <= address < base + size:
                path = _module_path(proc, hmod)
                return (path, base)

        return (None, None)
    except Exception as e:
        return (None, None)


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

        # Open process and check which module contains the start address
        access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        proc = kernel32.OpenProcess(access, False, pid)
        if not proc:
            raise OSError(ctypes.get_last_error(), f"OpenProcess failed for pid {pid}")

        try:
            module_path, base_addr = get_module_for_address(proc, start_addr, pid)

            if module_path:
                ui.append_log(f"[Thread OK] Start=0x{start_addr:X} Module={module_path}")
            else:
                ui.append_log(f"[SUSPICIOUS!] Thread start 0x{start_addr:X} NOT in any known module! PID={pid}")
        finally:
            kernel32.CloseHandle(proc)

    except Exception as e:
        ui.append_log(f"[Thread Check Error] {e}")
    


def checkAllThreads(pid, ui):
    """
    Enumerate all threads in a process and check which module each thread's RIP is pointing to.
    """
    try:
        ui.append_log(f"[Thread Scan] Checking all threads for PID {pid}...")

        # Open the process
        access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        proc = kernel32.OpenProcess(access, False, pid)
        if not proc:
            error_code = ctypes.get_last_error()
            ui.append_log(f"[Thread Scan Error] OpenProcess failed for PID {pid}: Error {error_code}")
            return

        try:
            # Create snapshot of all threads in the system
            snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            if snapshot == -1:
                ui.append_log(f"[Thread Scan Error] CreateToolhelp32Snapshot failed")
                return

            try:
                thread_entry = THREADENTRY32()
                thread_entry.dwSize = ctypes.sizeof(THREADENTRY32)

                # Get first thread
                if not kernel32.Thread32First(snapshot, ctypes.byref(thread_entry)):
                    ui.append_log(f"[Thread Scan Error] Thread32First failed")
                    return

                thread_count = 0
                suspicious_count = 0

                # Iterate through all threads
                while True:
                    # Check if this thread belongs to our target process
                    if thread_entry.th32OwnerProcessID == pid:
                        thread_count += 1
                        tid = thread_entry.th32ThreadID

                        # Open the thread to get its context
                        thread_handle = kernel32.OpenThread(
                            THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                            False,
                            tid
                        )

                        if thread_handle:
                            try:
                                # Get thread context to read RIP
                                context = CONTEXT()
                                context.ContextFlags = CONTEXT_FULL

                                if kernel32.GetThreadContext(thread_handle, ctypes.byref(context)):
                                    rip = context.Rip

                                    # Find which module this RIP belongs to
                                    module_path, base_addr = get_module_for_address(proc, rip, pid)

                                    if module_path:
                                        ui.append_log(f"[Thread {tid}] RIP=0x{rip:X} -> {module_path}")
                                    else:
                                        suspicious_count += 1
                                        ui.append_log(f"[SUSPICIOUS! Thread {tid}] RIP=0x{rip:X} NOT in any known module!")
                                else:
                                    ui.append_log(f"[Thread {tid}] GetThreadContext failed (Error: {ctypes.get_last_error()})")

                            finally:
                                kernel32.CloseHandle(thread_handle)
                        else:
                            ui.append_log(f"[Thread {tid}] OpenThread failed (Error: {ctypes.get_last_error()})")

                    # Get next thread
                    if not kernel32.Thread32Next(snapshot, ctypes.byref(thread_entry)):
                        break

                ui.append_log(f"[Thread Scan] Completed. Checked {thread_count} threads, {suspicious_count} suspicious")

            finally:
                kernel32.CloseHandle(snapshot)

        finally:
            kernel32.CloseHandle(proc)

    except Exception as e:
        ui.append_log(f"[Thread Scan Error] {e}")