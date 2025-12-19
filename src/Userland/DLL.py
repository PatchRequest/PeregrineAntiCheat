
import ctypes
from ctypes import wintypes
import platform

# Minimal LoadLibraryA-based DLL injection helper (Windows).
# NOTE: caller must pass an ASCII/ANSI DLL path.

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Access flags
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020

# Allocation / protection
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
MEM_RELEASE = 0x8000

# Waiting
INFINITE = 0xFFFFFFFF

# Types
LPTHREAD_START_ROUTINE = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.LPVOID)

# Prototypes
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

kernel32.VirtualAllocEx.restype = wintypes.LPVOID
kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]

kernel32.VirtualFreeEx.restype = wintypes.BOOL
kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]

kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPCVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

kernel32.GetModuleHandleA.restype = wintypes.HMODULE
kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]

kernel32.GetProcAddress.restype = wintypes.LPVOID
kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]

kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.c_size_t,
    LPTHREAD_START_ROUTINE,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPVOID,
]

kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]

kernel32.GetExitCodeThread.restype = wintypes.BOOL
kernel32.GetExitCodeThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]

kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

kernel32.IsWow64Process.restype = wintypes.BOOL
kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]

kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]


def _raise_last_error(msg):
    err = ctypes.get_last_error()
    raise OSError(err, f"{msg} (err={err})")


def _is_process_32bit(pid):
    """Check if a process is 32-bit. Returns None if unable to determine."""
    # If we're on 32-bit Windows, all processes are 32-bit
    if platform.machine().lower() not in ['amd64', 'x86_64']:
        return True

    PROCESS_QUERY_INFORMATION = 0x0400
    h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not h_process:
        return None

    try:
        is_wow64 = wintypes.BOOL()
        if kernel32.IsWow64Process(h_process, ctypes.byref(is_wow64)):
            # If IsWow64Process returns TRUE, the process is 32-bit running on 64-bit Windows
            return bool(is_wow64.value)
        return None
    finally:
        kernel32.CloseHandle(h_process)


def InjectDLL(target_pid: int, dll_paths, log_callback=None):
    """
    Inject DLL into target process using LoadLibraryA.
    dll_paths: either a dict with 'x86' and 'x64' keys containing DLL paths as bytes,
               or a bytes object for backward compatibility.
    log_callback: optional function(msg) to log messages (success/failure).
    """
    try:
        # Determine which DLL to use based on architecture
        if isinstance(dll_paths, dict):
            is_32bit = _is_process_32bit(target_pid)
            if is_32bit is None:
                # if log_callback:
                #     log_callback(f"[DLL Inject] Cannot determine architecture for PID={target_pid}, skipping")
                return None

            if is_32bit:
                filename_dll = dll_paths.get('x86')
                if not filename_dll:
                    # if log_callback:
                    #     log_callback(f"[DLL Inject] No x86 DLL available for 32-bit PID={target_pid}")
                    return None
            else:
                filename_dll = dll_paths.get('x64')
                if not filename_dll:
                    # if log_callback:
                    #     log_callback(f"[DLL Inject] No x64 DLL available for 64-bit PID={target_pid}")
                    return None
        else:
            # Backward compatibility: dll_paths is actually a bytes object
            filename_dll = dll_paths

        if not isinstance(filename_dll, (bytes, bytearray)):
            raise TypeError("filename_dll must be bytes")
        if not filename_dll.endswith(b"\x00"):
            filename_dll = filename_dll + b"\x00"

        access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
        h_proc = kernel32.OpenProcess(access, False, wintypes.DWORD(target_pid))
        if not h_proc:
            _raise_last_error("OpenProcess failed")

        try:
            alloc_size = len(filename_dll)
            remote_mem = kernel32.VirtualAllocEx(h_proc, None, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            if not remote_mem:
                _raise_last_error("VirtualAllocEx failed")

            written = ctypes.c_size_t(0)
            if not kernel32.WriteProcessMemory(h_proc, remote_mem, filename_dll, alloc_size, ctypes.byref(written)):
                _raise_last_error("WriteProcessMemory failed")

            h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
            if not h_kernel32:
                _raise_last_error("GetModuleHandleA failed")
            load_lib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
            if not load_lib:
                _raise_last_error("GetProcAddress(LoadLibraryA) failed")

            h_thread = kernel32.CreateRemoteThread(
                h_proc, None, 0, LPTHREAD_START_ROUTINE(load_lib), remote_mem, 0, None
            )
            if not h_thread:
                _raise_last_error("CreateRemoteThread failed")

            kernel32.WaitForSingleObject(h_thread, INFINITE)
            exit_code = wintypes.DWORD(0)
            kernel32.GetExitCodeThread(h_thread, ctypes.byref(exit_code))

            kernel32.CloseHandle(h_thread)
            kernel32.VirtualFreeEx(h_proc, remote_mem, 0, MEM_RELEASE)

            # Check if LoadLibraryA succeeded (non-zero HMODULE)
            dll_name = filename_dll.rstrip(b"\x00").decode('utf-8', errors='ignore')
            # if exit_code.value == 0:
            #     if log_callback:
            #         log_callback(f"[DLL Inject] LoadLibraryA returned NULL for {dll_name} in PID={target_pid} - DLL not found or failed to load!")
            # else:
            #     if log_callback:
            #         log_callback(f"[DLL Inject] Successfully injected {dll_name} into PID={target_pid} (HMODULE=0x{exit_code.value:X})")

            return exit_code.value
        finally:
            kernel32.CloseHandle(h_proc)
    except Exception as e:
        # if log_callback:
        #     dll_name = filename_dll.rstrip(b"\x00").decode('utf-8', errors='ignore') if isinstance(filename_dll, bytes) else str(filename_dll)
        #     log_callback(f"[DLL Inject] Failed to inject {dll_name} into PID={target_pid}: {e}")
        # else:
        #     # Re-raise if no callback provided (backward compatibility)
        #     raise
        pass
