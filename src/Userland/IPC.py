import json
import threading
from typing import Callable, Optional

import pywintypes
import win32file
import win32pipe
import winerror
import win32security
import ntsecuritycon
import win32event

PIPE_NAME = r"\\.\pipe\peregrine_ipc"
BUFSZ = 65536
INITIAL_PIPE_INSTANCES = 10  # Create this many pipe instances upfront


class PipeInstance:
    """Represents a single pipe instance with overlapped I/O."""
    def __init__(self, sa):
        self.handle = win32pipe.CreateNamedPipe(
            PIPE_NAME,
            win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            BUFSZ,
            BUFSZ,
            0,
            sa,
        )
        self.overlapped = pywintypes.OVERLAPPED()
        self.overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
        self.state = "CONNECTING"  # CONNECTING, READING, DISCONNECTING
        self.buffer = win32file.AllocateReadBuffer(BUFSZ)

    def start_connect(self):
        """Initiate an overlapped ConnectNamedPipe operation."""
        self.state = "CONNECTING"
        try:
            win32pipe.ConnectNamedPipe(self.handle, self.overlapped)
        except pywintypes.error as e:
            # ERROR_IO_PENDING (997) is expected for overlapped operations
            if e.winerror != winerror.ERROR_IO_PENDING:
                # ERROR_PIPE_CONNECTED (535) means client connected before we called ConnectNamedPipe
                if e.winerror != winerror.ERROR_PIPE_CONNECTED:
                    raise

    def start_read(self):
        """Initiate an overlapped ReadFile operation."""
        self.state = "READING"
        win32event.ResetEvent(self.overlapped.hEvent)
        try:
            hr, self.buffer = win32file.ReadFile(self.handle, BUFSZ, self.overlapped)
        except pywintypes.error as e:
            if e.winerror != winerror.ERROR_IO_PENDING:
                raise

    def disconnect(self):
        """Disconnect the client and prepare for reuse."""
        self.state = "DISCONNECTING"
        try:
            win32pipe.DisconnectNamedPipe(self.handle)
        except Exception:
            pass

    def close(self):
        """Close the pipe handle and event."""
        try:
            win32file.CloseHandle(self.handle)
            win32event.CloseHandle(self.overlapped.hEvent)
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
    Starts an overlapped I/O named-pipe server with multiple pipe instances.
    Returns a stop_event you can set() to request shutdown.
    """
    stop_event = threading.Event()
    stop_event_handle = win32event.CreateEvent(None, True, False, None)

    def server_loop():
        sa = create_permissive_security_attributes()
        pipes = []

        try:
            # Create initial pool of pipe instances
            for _ in range(INITIAL_PIPE_INSTANCES):
                try:
                    pipe = PipeInstance(sa)
                    pipe.start_connect()
                    pipes.append(pipe)
                except Exception as e:
                    if on_error:
                        on_error(f"Failed to create pipe instance: {e}")

            while not stop_event.is_set():
                # Build list of events to wait on
                events = [stop_event_handle] + [p.overlapped.hEvent for p in pipes]

                try:
                    # Wait for any event to signal (timeout every second to check stop_event)
                    result = win32event.WaitForMultipleObjects(events, False, 1000)

                    # Check if stop event was signaled
                    if result == win32event.WAIT_OBJECT_0:
                        break

                    # Timeout - just loop back to check stop_event
                    if result == win32event.WAIT_TIMEOUT:
                        continue

                    # Calculate which pipe signaled
                    pipe_idx = result - win32event.WAIT_OBJECT_0 - 1
                    if pipe_idx < 0 or pipe_idx >= len(pipes):
                        continue

                    pipe = pipes[pipe_idx]

                    # Get the number of bytes transferred
                    try:
                        bytes_transferred = win32file.GetOverlappedResult(
                            pipe.handle, pipe.overlapped, False
                        )
                    except pywintypes.error as e:
                        # Client disconnected or error - recycle this pipe
                        if on_error and e.winerror not in (109, 232):  # Not BROKEN_PIPE or PIPE_CLOSING
                            on_error(f"GetOverlappedResult error: {e}")
                        pipe.disconnect()
                        pipe.start_connect()
                        continue

                    # Handle based on current state
                    if pipe.state == "CONNECTING":
                        # Client connected, start reading
                        try:
                            pipe.start_read()
                        except Exception as e:
                            if on_error:
                                on_error(f"Failed to start read: {e}")
                            pipe.disconnect()
                            pipe.start_connect()

                    elif pipe.state == "READING":
                        # Read completed, process message
                        try:
                            data = bytes(pipe.buffer[:bytes_transferred])
                            msg = json.loads(data.decode("utf-8"))

                            if on_message:
                                try:
                                    on_message(msg)
                                except Exception as cb_exc:
                                    if on_error:
                                        on_error(f"on_message error: {cb_exc}")

                        except (ValueError, json.JSONDecodeError) as e:
                            if on_error:
                                on_error(f"json decode error: {e}")
                        except Exception as e:
                            if on_error:
                                on_error(f"message processing error: {e}")

                        # Disconnect and wait for next client
                        pipe.disconnect()
                        pipe.start_connect()

                except Exception as e:
                    if not stop_event.is_set() and on_error:
                        on_error(f"server loop error: {e}")

        finally:
            # Cleanup
            for pipe in pipes:
                pipe.close()
            win32event.CloseHandle(stop_event_handle)

    def stop_callback():
        """Called when stop_event is set to signal the server thread."""
        win32event.SetEvent(stop_event_handle)

    # Override the stop_event.set to also signal our Windows event
    original_set = stop_event.set
    def new_set():
        original_set()
        stop_callback()
    stop_event.set = new_set

    threading.Thread(target=server_loop, daemon=True).start()
    return stop_event


__all__ = ["start_server"]
