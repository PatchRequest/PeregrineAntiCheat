import json
import threading
from typing import Callable, Optional

import pywintypes
import win32file
import win32pipe
import winerror
import win32security
import ntsecuritycon

PIPE_NAME = r"\\.\pipe\peregrine_ipc"
BUFSZ = 65536


def read_message(h) -> bytes:
    """Read a whole message (pipe in message mode); tolerates ERROR_MORE_DATA."""
    chunks = []
    while True:
        try:
            _, chunk = win32file.ReadFile(h, BUFSZ)
            chunks.append(chunk)
            break
        except pywintypes.error as e:
            if e.winerror == winerror.ERROR_MORE_DATA:
                chunks.append(e.args[2])
                continue
            raise
    return b"".join(chunks)


def client_worker(
    h,
    on_message: Optional[Callable[[dict], None]] = None,
    on_error: Optional[Callable[[str], None]] = None,
    stop_event: Optional[threading.Event] = None,
):
    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            payload = read_message(h)
            msg = json.loads(payload.decode("utf-8"))

            if on_message:
                try:
                    on_message(msg)
                except Exception as cb_exc:  # noqa: BLE001
                    if on_error:
                        on_error(f"on_message error: {cb_exc}")

    except pywintypes.error as e:
        # ERROR_BROKEN_PIPE (109) means client disconnected - this is normal
        if e.winerror != 109 and on_error:
            on_error(f"ipc client error: {e}")
    except (ValueError, json.JSONDecodeError) as e:
        if on_error:
            on_error(f"ipc client error: {e}")
    finally:
        try:
            win32file.CloseHandle(h)
        except Exception:
            pass

def create_permissive_security_attributes():
    """Create security attributes that allow Everyone to access the pipe."""
    # Create a security descriptor
    sd = win32security.SECURITY_DESCRIPTOR()
    sd.Initialize()

    # Create a DACL (Discretionary Access Control List)
    dacl = win32security.ACL()
    dacl.Initialize()

    # Add an ACE (Access Control Entry) that grants GENERIC_ALL to Everyone
    everyone_sid = win32security.CreateWellKnownSid(win32security.WinWorldSid)
    dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        ntsecuritycon.GENERIC_ALL,
        everyone_sid
    )

    # Set the DACL in the security descriptor
    sd.SetSecurityDescriptorDacl(1, dacl, 0)

    # Create SECURITY_ATTRIBUTES
    sa = win32security.SECURITY_ATTRIBUTES()
    sa.SECURITY_DESCRIPTOR = sd
    sa.bInheritHandle = 0

    return sa

def start_server(
    on_message: Optional[Callable[[dict], None]] = None,
    on_error: Optional[Callable[[str], None]] = None,
):
    """
    Starts the named-pipe server in background threads.
    Returns a stop_event you can set() to request shutdown.
    """
    stop_event = threading.Event()

    def accept_loop():
        sa = create_permissive_security_attributes()
        while not stop_event.is_set():
            h = win32pipe.CreateNamedPipe(
                PIPE_NAME,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_MESSAGE
                | win32pipe.PIPE_READMODE_MESSAGE
                | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES,
                BUFSZ,
                BUFSZ,
                0,
                sa,
            )

            try:
                win32pipe.ConnectNamedPipe(h, None)
            except pywintypes.error as e:
                if on_error:
                    on_error(f"ipc connect error: {e}")
                try:
                    win32file.CloseHandle(h)
                except Exception:
                    pass
                continue

            threading.Thread(
                target=client_worker,
                args=(h, on_message, on_error, stop_event),
                daemon=True,
            ).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return stop_event


__all__ = ["start_server"]
