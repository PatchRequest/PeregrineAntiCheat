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
        print(f"Found x64 DLL at: {dll_x64}")
    elif dll_generic.exists():
        paths['x64'] = str(dll_generic).encode('ascii')
        print(f"Found DLL (assuming x64) at: {dll_generic}")
    else:
        print(f"WARNING: x64 DLL not found")
        paths['x64'] = None

    if dll_x86.exists():
        paths['x86'] = str(dll_x86).encode('ascii')
        print(f"Found x86 DLL at: {dll_x86}")
    else:
        print(f"WARNING: x86 DLL not found")
        paths['x86'] = None

    return paths

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
    def __init__(self, root):
        self.root = root
        self.root.title("Peregrine Monitor")

        # Find DLL paths once at startup
        self.dll_paths = find_dll_paths()

        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = tk.Label(root, textvariable=self.status_var, fg="#c83c3c", font=("Segoe UI", 12, "bold"))
        status_row = tk.Frame(root)
        tk.Label(status_row, text="Status:").pack(side=tk.LEFT, padx=(0, 6))
        self.status_label.pack(in_=status_row, side=tk.LEFT)
        status_row.pack(anchor="w", padx=8, pady=(8, 4))

        # Protected PIDs display
        self.protected_pids_var = tk.StringVar(value="Protected PIDs: None")
        protected_row = tk.Frame(root)
        self.protected_label = tk.Label(protected_row, textvariable=self.protected_pids_var, font=("Segoe UI", 10))
        self.protected_label.pack(side=tk.LEFT)
        protected_row.pack(anchor="w", padx=8, pady=(0, 4))

        controls = tk.Frame(root)
        tk.Label(controls, text="PID:").pack(side=tk.LEFT, padx=(0, 6))
        self.pid_var = tk.StringVar()
        self.pid_entry = tk.Entry(controls, textvariable=self.pid_var, width=12)
        self.pid_entry.pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(controls, text="Add", command=self.on_add_pid).pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="Remove", command=self.on_remove_pid).pack(side=tk.LEFT, padx=(0, 4))
        tk.Button(controls, text="Clear All", command=self.on_clear_all_pids).pack(side=tk.LEFT)
        tk.Button(controls, text="Check Modules", command=self.on_check_modules).pack(side=tk.LEFT, padx=(6, 0))
        tk.Button(controls, text="Check Threads", command=self.on_check_threads).pack(side=tk.LEFT, padx=(4, 0))
        controls.pack(anchor="w", padx=8, pady=(0, 8))

        self.log_view = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20, state="disabled")
        self.log_view.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.stop_event = threading.Event()
        self.handle = None
        self.log_lock = threading.Lock()
        self.log_lines = []
        self.max_log_lines = 2000
        self.protected_pids = set()  # Track PIDs we've added to the kernel
        self.protected_pids_lock = threading.Lock()
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

    def handle_process_create(self, obj):
        """Handle process_create event - injects DLL into new process."""
        pid = obj.get("pid", "N/A")
        if pid == "N/A" or pid == os.getpid():
            return

        # Inject DLL into the new process
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

        # Log other IPC messages (dll_loaded, etc.)
        try:
            pretty = json.dumps(msg)
        except Exception:
            pretty = str(msg)
        #self.append_log(f"[ipc] {pretty}")

    def on_ipc_error(self, err):
        self.append_log(f"[ipc-error] {err}")

    def set_status(self, text, color):
        self.root.after(0, lambda: (self.status_var.set(text), self.status_label.configure(fg=color)))

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
            text = "\n".join(self.log_lines)
        self.root.after(0, lambda: self._render_log(text))

    def _render_log(self, text):
        self.log_view.configure(state="normal")
        self.log_view.delete("1.0", tk.END)
        self.log_view.insert(tk.END, text)
        self.log_view.see(tk.END)
        self.log_view.configure(state="disabled")

    def connection_loop(self):
        backoff = 0.5
        max_backoff = 5.0
        while not self.stop_event.is_set():
            try:
                h = open_device()
                self.handle = h
                self.set_status("Connected", "#3cb45a")
                self.append_log("connected")
                #self._add_own_pid()
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
                    if obj.get("event"):
                        #self.append_log(f"[from kernel] event={obj['event']} raw={data!r}")
                        if obj['event'] == "thread_create":
                            threading.Thread(target=checkThread, args=(obj, self), daemon=True).start()

                        elif obj['event'] == "process_create":
                            threading.Thread(target=self.handle_process_create, args=(obj,), daemon=True).start()

                        elif obj["event"] == "image_load":
                            self.append_log(f"[from kernel] event={obj['event']} raw={data!r}")

                    else:
                        self.append_log(f"[from kernel] {data!r}")
                except Exception as exc:
                    self.append_log(f"decode error: {exc} raw={data!r}")

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
