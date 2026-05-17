import ctypes
import json
import os
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import scrolledtext
from ctypes import wintypes
from pathlib import Path
from DLL import InjectDLL

from PatchDetection import check_process_modules
from threadWork import checkThread, checkAllThreads
from IPC import start_server as start_ipc_server
from ProcessBlacklist import scan_processes_for_blacklist, DEFAULT_BLACKLIST
from HookDetection import check_iat_hooks, check_eat_hooks
from ManualMapDetection import scan_manual_map
from OverlayDetection import scan_overlays

# Constants/IOCTLs mirror the working Python sample
FILE_DEVICE_UNKNOWN = 0x00000022
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0






def CTL_CODE(dev, func, method, access):
    return (dev << 16) | (access << 14) | (func << 2) | method


IOCTL_PEREGRINE_SEND_FROM_USER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_PEREGRINE_RECV_TO_USER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.DeviceIoControl.restype = wintypes.BOOL
kernel32.DeviceIoControl.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


def find_dll_paths():
    """Get the absolute paths to both x86 and x64 DLLs next to this script."""
    script_dir = Path(__file__).parent.absolute()
    dll_x64 = script_dir / "PeregrineDLL_x64.dll"
    dll_x86 = script_dir / "PeregrineDLL_x86.dll"

    # Also check for generic name (assume x64)
    dll_generic = script_dir / "PeregrineDLL.dll"

    paths = {}

    if dll_x64.exists():
        paths['x64'] = str(dll_x64).encode('ascii')
    elif dll_generic.exists():
        paths['x64'] = str(dll_generic).encode('ascii')
    else:
        paths['x64'] = None

    if dll_x86.exists():
        paths['x86'] = str(dll_x86).encode('ascii')
    else:
        paths['x86'] = None

    return paths


def _send_injection_config(handle, dll_paths, targets, log_fn):
    """Send DLL paths and target process names to the driver for kernel APC injection."""
    # Command 8: x64 DLL path (wide string)
    if dll_paths.get('x64'):
        path_str = dll_paths['x64'].decode('ascii') if isinstance(dll_paths['x64'], bytes) else dll_paths['x64']
        path_wide = path_str.encode('utf-16-le')
        payload = bytes([8]) + path_wide
        device_io_control(handle, IOCTL_PEREGRINE_SEND_FROM_USER, payload)
        log_fn(f"[APC] Set x64 DLL: {path_str}")

    # Command 9: x86 DLL path (wide string)
    if dll_paths.get('x86'):
        path_str = dll_paths['x86'].decode('ascii') if isinstance(dll_paths['x86'], bytes) else dll_paths['x86']
        path_wide = path_str.encode('utf-16-le')
        payload = bytes([9]) + path_wide
        device_io_control(handle, IOCTL_PEREGRINE_SEND_FROM_USER, payload)
        log_fn(f"[APC] Set x86 DLL: {path_str}")

    # Command 10: add target process names
    for target in targets:
        name_bytes = target.encode('ascii') if isinstance(target, str) else target
        payload = bytes([10]) + name_bytes
        device_io_control(handle, IOCTL_PEREGRINE_SEND_FROM_USER, payload)
        log_fn(f"[APC] Added target: {target}")

    # Command 11: enable injection
    payload = bytes([11, 1])
    device_io_control(handle, IOCTL_PEREGRINE_SEND_FROM_USER, payload)
    log_fn("[APC] Kernel injection enabled")

def raise_last_error(msg):
    err = ctypes.get_last_error()
    raise OSError(err, f"{msg} (err={err})")


def open_device(path=r"\\.\\Peregrine"):
    h = kernel32.CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
    if h == wintypes.HANDLE(-1).value:
        raise_last_error(f"CreateFile({path}) failed")
    return h


def device_io_control(handle, code, in_buf):
    in_size = len(in_buf) if in_buf else 0
    in_ptr = ctypes.c_char_p(in_buf) if in_buf else None
    out_size = 1024
    out_buf = (ctypes.c_ubyte * out_size)()
    returned = wintypes.DWORD(0)

    ok = kernel32.DeviceIoControl(
        handle,
        code,
        in_ptr,
        in_size,
        ctypes.byref(out_buf),
        out_size,
        ctypes.byref(returned),
        None,
    )
    if not ok:
        return None
    return bytes(out_buf[: returned.value])


class PeregrineGUI:
    # Color tags: (prefix_match, tag_name, foreground_color)
    LOG_COLORS = [
        ("[ok]",                    "ok",         "#4ec94e"),
        ("[tamper]",                "tamper",      "#ff4444"),
        ("[SUSPICIOUS",             "suspicious",  "#ff3333"),
        ("[Remote Thread]",         "remote_thr",  "#ff6644"),
        ("[External WriteProcessMemory]", "ext_wpm", "#e8a838"),
        ("[External ReadProcessMemory]",  "ext_rpm", "#c8a848"),
        ("[External VirtualAllocEx]",     "ext_va",  "#e8a838"),
        ("[External VirtualProtectEx]",   "ext_vp",  "#e8a838"),
        ("[External CreateRemoteThread]", "ext_crt", "#ff6644"),
        ("[External OpenProcess]",        "ext_op",  "#c8a848"),
        ("[Handle Access]",         "handle",      "#e8a838"),
        ("[Image Load]",            "imgload",     "#6ab0f3"),
        ("[Thread OK]",             "thr_ok",      "#4ec94e"),
        ("[Thread Scan]",           "thr_scan",    "#6ab0f3"),
        ("[Blacklist]",             "blacklist",   "#e67e22"),
        ("[Driver Blacklist]",      "drv_bl",      "#ff4444"),
        ("[Driver Scan]",           "drv_scan",    "#6ab0f3"),
        ("[ObCallback]",            "obcb",        "#e8a838"),
        ("[System Check]",          "syschk",      "#a78bfa"),
        ("[Test-Sign]",             "testsign",    "#ff4444"),
        ("[HVCI]",                  "hvci",        "#ff4444"),
        ("[CPU]",                   "cpu",         "#6ab0f3"),
        ("[IAT Hook]",              "iat_hook",    "#ff4444"),
        ("[IAT Scan]",              "iat_scan",    "#6ab0f3"),
        ("[EAT Hook]",              "eat_hook",    "#ff4444"),
        ("[EAT Scan]",              "eat_scan",    "#6ab0f3"),
        ("[Manual-Map]",            "mmap",        "#ff4444"),
        ("[Memory Scan]",           "memscan",     "#6ab0f3"),
        ("[Overlay]",               "overlay",     "#ff4444"),
        ("[Overlay Scan]",          "ovlscan",     "#6ab0f3"),
        ("[PPL]",                   "ppl",         "#4a90e2"),
        ("[DLL Inject FAIL]",       "inj_fail",    "#ff4444"),
        ("[Kernel Parse Error]",    "kerr",        "#ff4444"),
        ("connected",               "connected",   "#4ec94e"),
        ("connect failed",          "conn_fail",   "#c83c3c"),
        ("[unknown]",               "unknown",     "#888888"),
    ]

    def __init__(self, root):
        self.root = root
        self.root.title("Peregrine Monitor")
        self.root.configure(bg="#1e1e2e")
        self.root.geometry("1000x600")

        # Hardcoded DLL paths (built by build_dll.bat into this directory)
        script_dir = Path(__file__).parent.absolute()
        self.dll_paths = {
            'x64': str(script_dir / "PeregrineDLL_x64.dll").encode('ascii'),
            'x86': str(script_dir / "PeregrineDLL_x86.dll").encode('ascii'),
        }

        # Style constants
        BG = "#1e1e2e"
        FG = "#cdd6f4"
        BG_ENTRY = "#313244"
        BG_BTN = "#45475a"
        FG_BTN = "#cdd6f4"
        FONT = ("Consolas", 10)
        FONT_BOLD = ("Consolas", 11, "bold")

        # Status bar
        status_row = tk.Frame(root, bg=BG)
        tk.Label(status_row, text="STATUS:", font=FONT_BOLD, bg=BG, fg="#888888").pack(side=tk.LEFT, padx=(0, 6))
        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = tk.Label(status_row, textvariable=self.status_var, fg="#c83c3c", bg=BG, font=FONT_BOLD)
        self.status_label.pack(side=tk.LEFT)
        status_row.pack(anchor="w", padx=10, pady=(10, 2))

        # Protected PIDs display
        self.protected_pids_var = tk.StringVar(value="Protected PIDs: None")
        protected_row = tk.Frame(root, bg=BG)
        self.protected_label = tk.Label(protected_row, textvariable=self.protected_pids_var, font=FONT, bg=BG, fg="#888888")
        self.protected_label.pack(side=tk.LEFT)
        protected_row.pack(anchor="w", padx=10, pady=(0, 4))

        # Controls
        controls = tk.Frame(root, bg=BG)
        tk.Label(controls, text="PID:", font=FONT, bg=BG, fg=FG).pack(side=tk.LEFT, padx=(0, 6))
        self.pid_var = tk.StringVar()
        self.pid_entry = tk.Entry(controls, textvariable=self.pid_var, width=12, font=FONT,
                                  bg=BG_ENTRY, fg=FG, insertbackground=FG, relief=tk.FLAT, bd=4)
        self.pid_entry.pack(side=tk.LEFT, padx=(0, 8))

        btn_cfg = dict(font=FONT, bg=BG_BTN, fg=FG_BTN, relief=tk.FLAT, bd=0, padx=10, pady=4, cursor="hand2")
        tk.Button(controls, text="Add", command=self.on_add_pid, **btn_cfg).pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="Remove", command=self.on_remove_pid, **btn_cfg).pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="Clear All", command=self.on_clear_all_pids, **btn_cfg).pack(side=tk.LEFT, padx=(0, 8))
        tk.Button(controls, text="Set PPL", command=self.on_set_ppl, bg="#4a90e2", fg="white", font=FONT,
                  relief=tk.FLAT, bd=0, padx=10, pady=4, cursor="hand2").pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="Check Modules", command=self.on_check_modules, **btn_cfg).pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="Check Threads", command=self.on_check_threads, **btn_cfg).pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="Check IAT", command=self.on_check_iat, **btn_cfg).pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="Check EAT", command=self.on_check_eat, **btn_cfg).pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="Scan Memory", command=self.on_scan_memory, **btn_cfg).pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="Scan Overlays", command=self.on_scan_overlays, bg="#ff6644", fg="white", font=FONT,
                  relief=tk.FLAT, bd=0, padx=10, pady=4, cursor="hand2").pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="Scan Blacklist", command=self.on_scan_blacklist, bg="#e67e22", fg="white", font=FONT,
                  relief=tk.FLAT, bd=0, padx=10, pady=4, cursor="hand2").pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="Scan Drivers", command=self.on_scan_drivers, bg="#e67e22", fg="white", font=FONT,
                  relief=tk.FLAT, bd=0, padx=10, pady=4, cursor="hand2").pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="Scan ObCallbacks", command=self.on_scan_ob_callbacks, bg="#e8a838", fg="white", font=FONT,
                  relief=tk.FLAT, bd=0, padx=10, pady=4, cursor="hand2").pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="System Check", command=self.on_system_check, bg="#a78bfa", fg="white", font=FONT,
                  relief=tk.FLAT, bd=0, padx=10, pady=4, cursor="hand2").pack(side=tk.LEFT, padx=(0, 4))
        controls.pack(anchor="w", padx=10, pady=(0, 8))

        # Log view
        self.log_view = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20, state="disabled",
                                                   bg="#11111b", fg="#cdd6f4", font=("Consolas", 10),
                                                   insertbackground="#cdd6f4", relief=tk.FLAT, bd=8,
                                                   selectbackground="#45475a", selectforeground="#cdd6f4")
        self.log_view.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # Configure color tags
        for _, tag_name, color in self.LOG_COLORS:
            self.log_view.tag_configure(tag_name, foreground=color)

        self.stop_event = threading.Event()
        self.handle = None
        self.log_lock = threading.Lock()
        self.log_lines = []
        self.max_log_lines = 2000
        self.protected_pids = set()  # Track PIDs we've added to the kernel
        self.protected_pids_lock = threading.Lock()
        self.injection_targets = []  # Process names for kernel APC injection
        self.kernel_injection = True  # Use kernel APC injection instead of user-mode
        self.ipc_stop = start_ipc_server(on_message=self.on_ipc_message, on_error=self.on_ipc_error)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        threading.Thread(target=self.connection_loop, daemon=True).start()

    def _pack_handle(self, pid_val: int) -> bytes:
        # HANDLE is pointer-sized; pack little-endian
        handle_size = ctypes.sizeof(ctypes.c_void_p)
        if handle_size == 8:
            return struct.pack("<Q", pid_val & 0xFFFFFFFFFFFFFFFF)
        return struct.pack("<L", pid_val & 0xFFFFFFFF)

    def _parse_pid_input(self, require_connection=True):
        text = self.pid_var.get().strip()
        if not text:
            self.append_log("PID input is empty")
            return None
        try:
            pid = int(text, 0)
        except ValueError:
            self.append_log(f"invalid PID: {text}")
            return None
        if require_connection and not self.handle:
            self.append_log("cannot set PID: not connected")
            return None
        return pid

    def on_add_pid(self):
        pid = self._parse_pid_input()
        if pid is None:
            return
        payload = bytes([1]) + self._pack_handle(pid)
        res = device_io_control(self.handle, IOCTL_PEREGRINE_SEND_FROM_USER, payload)
        if res is None:
            self.append_log("add PID failed")
        else:
            with self.protected_pids_lock:
                self.protected_pids.add(pid)
            self.append_log(f"added PID {pid}")
            self.update_protected_pids_display()

    def on_remove_pid(self):
        pid = self._parse_pid_input()
        if pid is None:
            return
        payload = bytes([2]) + self._pack_handle(pid)
        res = device_io_control(self.handle, IOCTL_PEREGRINE_SEND_FROM_USER, payload)
        if res is None:
            self.append_log("remove PID failed")
        else:
            with self.protected_pids_lock:
                self.protected_pids.discard(pid)
            self.append_log(f"removed PID {pid}")
            self.update_protected_pids_display()

    def on_clear_all_pids(self):
        if not self.handle:
            self.append_log("cannot clear PIDs: not connected")
            return
        payload = bytes([3])
        res = device_io_control(self.handle, IOCTL_PEREGRINE_SEND_FROM_USER, payload)
        if res is None:
            self.append_log("clear all PIDs failed")
        else:
            with self.protected_pids_lock:
                self.protected_pids.clear()
            self.append_log("cleared all PIDs")
            self.update_protected_pids_display()

    def on_set_ppl(self):
        """Set a process to Protected Process Light (PPL) status."""
        pid = self._parse_pid_input()
        if pid is None:
            return
        payload = bytes([4]) + self._pack_handle(pid)
        res = device_io_control(self.handle, IOCTL_PEREGRINE_SEND_FROM_USER, payload)
        if res is None:
            self.append_log(f"[PPL] Failed to set PPL for PID {pid}")
        else:
            self.append_log(f"[PPL] Set PID {pid} to PPL")

    def on_check_modules(self):
        pid = self._parse_pid_input(require_connection=False)
        if pid is None:
            return
        try:
            results = check_process_modules(pid)
        except Exception as exc:  # noqa: BLE001
            self.append_log(f"module check failed: {exc}")
            return

        if not results:
            self.append_log(f"module check: no modules enumerated for pid {pid}")
            return

        for r in results:
            path = r.get("path") or "<unknown>"
            err = r.get("error")
            base = r.get("base")
            base_str = f"0x{base:X}" if isinstance(base, int) else "<n/a>"
            matched_val = r.get("matched")
            matched = bool(matched_val) if matched_val is not None else None
            mem_hash = r.get("mem_sha256")
            disk_hash = r.get("disk_sha256")
            section = r.get("section") or ""
            sec_size = r.get("section_size")
            if matched is True:
                status = "[ok]"
            elif matched is False:
                status = "[tamper]"
            else:
                status = "[unknown]"
            msg = f"{status} {path} base={base_str} size={r.get('size')} matched={matched_val}"
            if section:
                msg += f" section={section}"
            if sec_size:
                msg += f" sec_size={sec_size}"
            if mem_hash:
                msg += f" mem={mem_hash[:8]}"
            if disk_hash:
                msg += f" disk={disk_hash[:8]}"
            if err:
                msg += f" err={err}"
            self.append_log(msg)

    def on_check_threads(self):
        pid = self._parse_pid_input(require_connection=False)
        if pid is None:
            return
        # Run checkAllThreads in a background thread to avoid blocking UI
        threading.Thread(target=checkAllThreads, args=(pid, self), daemon=True).start()

    def _run_iat_check(self, pid):
        """Background worker for IAT hook scan."""
        try:
            hooks = check_iat_hooks(pid)
            if hooks:
                self.append_log(f"[IAT Hook] Found {len(hooks)} IAT hook(s) in PID {pid}:")
                for h in hooks:
                    self.append_log(
                        f"[IAT Hook] {h['module']} -> {h['imported_dll']}!{h['function']} "
                        f"IAT=0x{h['iat_value']:X}")
            else:
                self.append_log(f"[IAT Scan] PID {pid}: No IAT hooks detected")
        except Exception as exc:
            self.append_log(f"[IAT Scan] Error: {exc}")

    def on_check_iat(self):
        pid = self._parse_pid_input(require_connection=False)
        if pid is None:
            return
        self.append_log(f"[IAT Scan] Scanning PID {pid}...")
        threading.Thread(target=self._run_iat_check, args=(pid,), daemon=True).start()

    def _run_eat_check(self, pid):
        """Background worker for EAT hook scan."""
        try:
            hooks = check_eat_hooks(pid)
            if hooks:
                self.append_log(f"[EAT Hook] Found {len(hooks)} EAT hook(s) in PID {pid}:")
                for h in hooks:
                    self.append_log(
                        f"[EAT Hook] {h['module']}!{h['function']} "
                        f"RVA=0x{h['rva']:X} -> 0x{h['target_addr']:X}")
            else:
                self.append_log(f"[EAT Scan] PID {pid}: No EAT hooks detected")
        except Exception as exc:
            self.append_log(f"[EAT Scan] Error: {exc}")

    def on_check_eat(self):
        pid = self._parse_pid_input(require_connection=False)
        if pid is None:
            return
        self.append_log(f"[EAT Scan] Scanning PID {pid}...")
        threading.Thread(target=self._run_eat_check, args=(pid,), daemon=True).start()

    def _run_memory_scan(self, pid):
        """Background worker for manual-map / shellcode scan."""
        try:
            regions = scan_manual_map(pid)
            if regions:
                self.append_log(f"[Manual-Map] Found {len(regions)} suspicious executable region(s) in PID {pid}:")
                for r in regions:
                    self.append_log(
                        f"[Manual-Map] 0x{r['address']:X} size={r['size']:#x} "
                        f"prot={r['protection']} type={r['type']} alloc=0x{r['alloc_base']:X}")
            else:
                self.append_log(f"[Memory Scan] PID {pid}: No suspicious executable regions found")
        except Exception as exc:
            self.append_log(f"[Memory Scan] Error: {exc}")

    def on_scan_memory(self):
        pid = self._parse_pid_input(require_connection=False)
        if pid is None:
            return
        self.append_log(f"[Memory Scan] Scanning PID {pid} for manual-mapped code...")
        threading.Thread(target=self._run_memory_scan, args=(pid,), daemon=True).start()

    def _run_overlay_scan(self):
        """Background worker for overlay window scan."""
        try:
            overlays = scan_overlays()
            if overlays:
                self.append_log(f"[Overlay] Found {len(overlays)} suspicious overlay window(s):")
                for o in overlays:
                    self.append_log(
                        f"[Overlay] PID={o['pid']} \"{o['title']}\" "
                        f"{o['width']}x{o['height']} alpha={o['alpha']} [{o['flags']}]")
            else:
                self.append_log("[Overlay Scan] No suspicious overlay windows found")
        except Exception as exc:
            self.append_log(f"[Overlay Scan] Error: {exc}")

    def on_scan_overlays(self):
        self.append_log("[Overlay Scan] Scanning for overlay windows...")
        threading.Thread(target=self._run_overlay_scan, daemon=True).start()

    def on_scan_blacklist(self):
        """Scan all processes for blacklisted keywords."""
        self.append_log("[Blacklist] Starting scan...")
        try:
            matches = scan_processes_for_blacklist()

            if matches:
                self.append_log(f"[Blacklist] Found {len(matches)} suspicious process(es):")
                for match in matches:
                    pid = match['pid']
                    path = match['path']
                    keyword = match['keyword']
                    self.append_log(f"[Blacklist] PID {pid}: {path} (matched: {keyword})")
            else:
                self.append_log("[Blacklist] No blacklisted processes found")

        except Exception as exc:
            self.append_log(f"[Blacklist] Error during scan: {exc}")

    def on_scan_drivers(self):
        """Send command 5 to kernel to enumerate loaded drivers."""
        if not self.handle:
            self.append_log("cannot scan drivers: not connected")
            return
        payload = bytes([5])
        res = device_io_control(self.handle, IOCTL_PEREGRINE_SEND_FROM_USER, payload)
        if res is None:
            self.append_log("[Driver Scan] command failed")
        else:
            self.append_log("[Driver Scan] Scanning loaded kernel drivers...")

    def on_scan_ob_callbacks(self):
        """Send command 6 to kernel to enumerate ObRegisterCallbacks."""
        if not self.handle:
            self.append_log("cannot scan ObCallbacks: not connected")
            return
        payload = bytes([6])
        res = device_io_control(self.handle, IOCTL_PEREGRINE_SEND_FROM_USER, payload)
        if res is None:
            self.append_log("[ObCallback] command failed")
        else:
            self.append_log("[ObCallback] Scanning registered callbacks...")

    def on_system_check(self):
        """Send command 7 to kernel to run system integrity checks."""
        if not self.handle:
            self.append_log("cannot run system check: not connected")
            return
        payload = bytes([7])
        res = device_io_control(self.handle, IOCTL_PEREGRINE_SEND_FROM_USER, payload)
        if res is None:
            self.append_log("[System Check] command failed")
        else:
            self.append_log("[System Check] Running integrity checks...")

    def handle_process_create(self, obj):
        """Handle process_create event.

        With kernel APC injection enabled, the driver injects autonomously
        for matching target processes.  This handler only does user-mode
        fallback injection when kernel injection is disabled.
        """
        if self.kernel_injection:
            return

        pid = obj.get("pid", "N/A")
        if pid == "N/A" or pid == os.getpid():
            return

        time.sleep(2)

        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_INFORMATION = 0x0400
        SYNCHRONIZE = 0x00100000
        h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, False, pid)

        if not h_process:
            return

        exit_code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(h_process, ctypes.byref(exit_code))
        kernel32.CloseHandle(h_process)

        STILL_ACTIVE = 259
        if exit_code.value != STILL_ACTIVE:
            return

        InjectDLL(pid, self.dll_paths, self.append_log)

    def on_ipc_message(self, msg):
        event = msg.get("event", "")

        # Handle Read/WriteProcessMemory with filtering
        if event in ("ReadProcessMemory", "WriteProcessMemory"):
            caller = msg.get("callerPID", "?")
            target = msg.get("targetPID", "?")
            addr = msg.get("address", 0)
            size = msg.get("size", 0)
            success = msg.get("success", 0)

            # Only log if:
            # - Target is protected (the victim is one we care about)
            # - Caller is NOT protected (it's an external process, not our own)
            # - It's not self-access
            # - Operation succeeded
            with self.protected_pids_lock:
                target_protected = target in self.protected_pids
                caller_protected = caller in self.protected_pids

            if success and caller != target and target_protected and not caller_protected:
                self.append_log(f"[External {event}] PID {caller} → PID {target} | {size} bytes at 0x{addr:X}")
            return

        if event == "VirtualAllocEx":
            caller = msg.get("callerPID", "?")
            target = msg.get("targetPID", "?")
            addr = msg.get("address", 0)
            size = msg.get("size", 0)
            protect = msg.get("protect", "?")
            with self.protected_pids_lock:
                target_protected = target in self.protected_pids
                caller_protected = caller in self.protected_pids
            if caller != target and target_protected and not caller_protected:
                self.append_log(f"[External VirtualAllocEx] PID {caller} -> PID {target} | {size} bytes at 0x{addr:X} protect={protect}")
            return

        if event == "VirtualProtectEx":
            caller = msg.get("callerPID", "?")
            target = msg.get("targetPID", "?")
            addr = msg.get("address", 0)
            size = msg.get("size", 0)
            protect = msg.get("newProtect", "?")
            with self.protected_pids_lock:
                target_protected = target in self.protected_pids
                caller_protected = caller in self.protected_pids
            if caller != target and target_protected and not caller_protected:
                self.append_log(f"[External VirtualProtectEx] PID {caller} -> PID {target} | {size} bytes at 0x{addr:X} protect={protect}")
            return

        if event == "CreateRemoteThread":
            caller = msg.get("callerPID", "?")
            target = msg.get("targetPID", "?")
            start = msg.get("startAddress", 0)
            with self.protected_pids_lock:
                target_protected = target in self.protected_pids
                caller_protected = caller in self.protected_pids
            if caller != target and target_protected and not caller_protected:
                self.append_log(f"[External CreateRemoteThread] PID {caller} -> PID {target} | start=0x{start:X}")
            return

        if event == "OpenProcess":
            caller = msg.get("callerPID", "?")
            target = msg.get("targetPID", "?")
            access = msg.get("access", "?")
            with self.protected_pids_lock:
                target_protected = target in self.protected_pids
                caller_protected = caller in self.protected_pids
            if caller != target and target_protected and not caller_protected:
                self.append_log(f"[External OpenProcess] PID {caller} -> PID {target} | access={access}")
            return

    def on_ipc_error(self, err):
        self.append_log(f"[ipc-error] {err}")

    def set_status(self, text, color):
        self.root.after(0, lambda: (self.status_var.set(text), self.status_label.configure(fg=color, bg="#1e1e2e")))

    def update_protected_pids_display(self):
        """Update the protected PIDs display label."""
        with self.protected_pids_lock:
            if self.protected_pids:
                pids_str = ", ".join(str(pid) for pid in sorted(self.protected_pids))
                display_text = f"Protected PIDs: {pids_str}"
            else:
                display_text = "Protected PIDs: None"

        self.root.after(0, lambda: self.protected_pids_var.set(display_text))

    def append_log(self, msg):
        with self.log_lock:
            self.log_lines.append(msg)
            if len(self.log_lines) > self.max_log_lines:
                self.log_lines = self.log_lines[-self.max_log_lines :]
            snapshot = list(self.log_lines)
        self.root.after(0, lambda: self._render_log(snapshot))

    def _render_log(self, lines):
        self.log_view.configure(state="normal")
        self.log_view.delete("1.0", tk.END)
        for i, line in enumerate(lines):
            if i > 0:
                self.log_view.insert(tk.END, "\n")
            tag = None
            for prefix, tag_name, _ in self.LOG_COLORS:
                if line.startswith(prefix):
                    tag = tag_name
                    break
            if tag:
                self.log_view.insert(tk.END, line, tag)
            else:
                self.log_view.insert(tk.END, line)
        self.log_view.see(tk.END)
        self.log_view.configure(state="disabled")

    def _configure_kernel_injection(self):
        """Send hardcoded DLL paths and injection targets to the driver."""
        if not self.handle or not self.kernel_injection:
            return
        _send_injection_config(
            self.handle,
            self.dll_paths,
            self.injection_targets,
            self.append_log,
        )

    def connection_loop(self):
        backoff = 0.5
        max_backoff = 5.0
        while not self.stop_event.is_set():
            try:
                h = open_device()
                self.handle = h
                self.set_status("Connected", "#3cb45a")
                self.append_log("connected")
                self._configure_kernel_injection()
                backoff = 0.5
                self.receiver_loop()
            except Exception as exc:
                self.handle = None
                self.set_status("Disconnected", "#c83c3c")
                self.append_log(f"connect failed: {exc} (retry in {backoff:.1f}s)")
                time.sleep(backoff)
                backoff = min(max_backoff, backoff * 2)

    def receiver_loop(self):
        while not self.stop_event.is_set() and self.handle:
            data = device_io_control(self.handle, IOCTL_PEREGRINE_RECV_TO_USER, b"")
            if data:
                s = data.decode("utf-8", errors="ignore")
                s_fixed = s.replace("\\", "\\\\")
                try:
                    obj = json.loads(s_fixed)
                    event = obj.get("event")
                    if event == "thread_create":
                        threading.Thread(target=checkThread, args=(obj, self), daemon=True).start()
                    elif event == "process_create":
                        threading.Thread(target=self.handle_process_create, args=(obj,), daemon=True).start()
                    elif event == "image_load":
                        name = obj.get("image") or obj.get("image_name") or "?"
                        pid = obj.get("pid", "?")
                        self.append_log(f"[Image Load] PID={pid} {name}")
                    elif event == "ob_callback":
                        access_str = obj.get("desired_access", "0x0")
                        access = int(access_str, 16) if isinstance(access_str, str) else access_str
                        DANGEROUS = 0x0001 | 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0800  # TERMINATE|CREATE_THREAD|VM_OP|VM_R|VM_W|DUP_HANDLE|SUSPEND_RESUME
                        if access & DANGEROUS:
                            op = obj.get("op", "?")
                            target = obj.get("target_pid", "?")
                            caller = obj.get("caller_pid", "?")
                            flags = []
                            ACCESS_FLAGS = {
                                0x0001: "TERMINATE", 0x0002: "CREATE_THREAD",
                                0x0008: "VM_OPERATION", 0x0010: "VM_READ",
                                0x0020: "VM_WRITE", 0x0040: "DUP_HANDLE",
                                0x0800: "SUSPEND_RESUME",
                            }
                            for bit, name in ACCESS_FLAGS.items():
                                if access & bit:
                                    flags.append(name)
                            flag_str = "|".join(flags)
                            self.append_log(f"[Handle Access] PID={caller} -> PID={target} op={op} [{flag_str}]")
                    elif event == "driver_scan":
                        driver = obj.get("driver", "?")
                        path = obj.get("path", "?")
                        size = obj.get("size", 0)
                        self.append_log(f"[Driver Blacklist] DETECTED: {driver} ({path}) size={size}")

                    elif event == "driver_scan_complete":
                        total = obj.get("total_drivers", 0)
                        bl = obj.get("blacklisted_count", 0)
                        if bl > 0:
                            self.append_log(f"[Driver Scan] Complete: {total} drivers loaded, {bl} BLACKLISTED")
                        else:
                            self.append_log(f"[Driver Scan] Complete: {total} drivers loaded, none blacklisted")

                    elif event == "ob_callback_found":
                        cb_type = obj.get("type", "?")
                        pre_drv = obj.get("pre_driver", "none")
                        post_drv = obj.get("post_driver", "none")
                        pre_op = obj.get("pre_op", "0x0")
                        post_op = obj.get("post_op", "0x0")
                        ops = obj.get("operations", "?")
                        enabled = obj.get("enabled", False)
                        driver = pre_drv if pre_drv != "none" else post_drv
                        self.append_log(
                            f"[ObCallback] type={cb_type} driver={driver} "
                            f"pre={pre_op}({pre_drv}) post={post_op}({post_drv}) "
                            f"ops={ops} enabled={enabled}")

                    elif event == "ob_callback_scan_complete":
                        self.append_log("[ObCallback] Scan complete")

                    elif event == "ob_callback_error":
                        cb_type = obj.get("type", "?")
                        error = obj.get("error", "unknown")
                        self.append_log(f"[ObCallback] Error scanning {cb_type}: {error}")

                    elif event == "system_check":
                        check = obj.get("check", "?")
                        error = obj.get("error")
                        if error:
                            self.append_log(f"[System Check] {check}: ERROR - {error}")
                        elif check == "test_sign":
                            ts = obj.get("test_signing", False)
                            ci = obj.get("code_integrity_enabled", False)
                            if ts:
                                self.append_log(f"[Test-Sign] DETECTED - Test signing is ENABLED (CI={ci})")
                            else:
                                self.append_log(f"[System Check] Test signing disabled, Code Integrity={ci}")
                        elif check == "hvci":
                            enabled = obj.get("hvci_enabled", False)
                            audit = obj.get("hvci_audit_mode", False)
                            if not enabled:
                                self.append_log(f"[HVCI] WARNING - HVCI is DISABLED (audit={audit})")
                            else:
                                self.append_log(f"[System Check] HVCI enabled (audit={audit})")
                        elif check == "cpu_vendor":
                            vendor = obj.get("cpu_vendor", "?")
                            hv = obj.get("hypervisor_present", False)
                            hv_vendor = obj.get("hypervisor_vendor", "none")
                            if hv:
                                self.append_log(f"[CPU] {vendor} - Hypervisor DETECTED: {hv_vendor}")
                            else:
                                self.append_log(f"[CPU] {vendor} - No hypervisor detected")

                    elif event == "system_check_complete":
                        self.append_log("[System Check] All checks complete")

                    elif event == "apc_inject":
                        pid = obj.get("pid", "?")
                        tid = obj.get("tid", "?")
                        status = obj.get("status", "?")
                        if status == "success":
                            self.append_log(f"[ok] APC injection PID={pid} TID={tid}")
                            payload = bytes([1]) + self._pack_handle(pid)
                            device_io_control(self.handle, IOCTL_PEREGRINE_SEND_FROM_USER, payload)
                            with self.protected_pids_lock:
                                self.protected_pids.add(pid)
                            self.update_protected_pids_display()

                            threading.Thread(target=checkAllThreads, args=(pid, self), daemon=True).start()
                            threading.Thread(target=lambda p=pid: check_process_modules(p), daemon=True).start()
                        else:
                            err = obj.get("error", "?")
                            self.append_log(f"[DLL Inject FAIL] APC injection PID={pid} error={err}")

                except Exception as exc:
                    self.append_log(f"[Kernel Parse Error] {exc}")

    def on_close(self):
        self.stop_event.set()
        if self.handle:
            kernel32.CloseHandle(self.handle)
        if self.ipc_stop:
            self.ipc_stop.set()
        self.root.destroy()

    def _add_own_pid(self):
        """Send our own process ID as protected right after connect."""
        my_pid = os.getpid()
        payload = bytes([1]) + self._pack_handle(my_pid)
        res = device_io_control(self.handle, IOCTL_PEREGRINE_SEND_FROM_USER, payload)
        if res is None:
            self.append_log(f"auto-add self PID {my_pid} failed")
        else:
            self.append_log(f"auto-added self PID {my_pid}")

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def elevate():
    """Re-launch the script with administrator privileges."""
    try:
        if sys.argv[0].endswith('.py'):
            # Running as a Python script
            params = ' '.join([f'"{arg}"' for arg in sys.argv])
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                params,
                None,
                1  # SW_SHOWNORMAL
            )
        else:
            # Running as a compiled executable
            params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.argv[0],
                params,
                None,
                1  # SW_SHOWNORMAL
            )
    except Exception as e:
        print(f"Failed to elevate: {e}")
        sys.exit(1)

def main():
    if not is_admin():
        print("Not running as administrator. Requesting elevation...")
        elevate()
        sys.exit(0)

    print("Running with administrator privileges")
    root = tk.Tk()
    PeregrineGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
