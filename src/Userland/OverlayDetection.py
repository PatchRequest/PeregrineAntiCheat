"""
Overlay Window Detection

Enumerates all top-level windows and flags ones that look like cheat overlays:
- Transparent + click-through (WS_EX_TRANSPARENT | WS_EX_LAYERED)
- Always on top (WS_EX_TOPMOST)
- Large or fullscreen size
- Common with ESP/wallhack overlays

Reports the window title, owning process, size, and style flags.
"""

import ctypes
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Extended window styles
WS_EX_TOPMOST = 0x00000008
WS_EX_TRANSPARENT = 0x00000020
WS_EX_LAYERED = 0x00080000
WS_EX_NOACTIVATE = 0x08000000
WS_EX_TOOLWINDOW = 0x00000080

# Window styles
WS_VISIBLE = 0x10000000
WS_POPUP = 0x80000000

# EnumWindows callback type
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL

user32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetWindowLongW.restype = ctypes.c_long

user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.GetWindowRect.restype = wintypes.BOOL

user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int

user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int

user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL

user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD

user32.GetLayeredWindowAttributes.argtypes = [
    wintypes.HWND, ctypes.POINTER(wintypes.COLORREF),
    ctypes.POINTER(wintypes.BYTE), ctypes.POINTER(wintypes.DWORD)]
user32.GetLayeredWindowAttributes.restype = wintypes.BOOL

GWL_STYLE = -16
GWL_EXSTYLE = -20

LWA_ALPHA = 0x2
LWA_COLORKEY = 0x1

# Screen size for "large window" heuristic
user32.GetSystemMetrics.argtypes = [ctypes.c_int]
user32.GetSystemMetrics.restype = ctypes.c_int
SM_CXSCREEN = 0
SM_CYSCREEN = 1


def _get_window_title(hwnd):
    length = user32.GetWindowTextLengthW(hwnd)
    if length == 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buf, length + 1)
    return buf.value


def _get_window_pid(hwnd):
    pid = wintypes.DWORD(0)
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def scan_overlays():
    """
    Scan for suspicious overlay windows.
    Returns list of dicts: {hwnd, title, pid, width, height, flags, alpha}
    """
    screen_w = user32.GetSystemMetrics(SM_CXSCREEN)
    screen_h = user32.GetSystemMetrics(SM_CYSCREEN)
    # Consider "large" as covering at least 50% of screen area
    min_area = (screen_w * screen_h) * 0.5

    results = []

    def enum_callback(hwnd, lparam):
        if not user32.IsWindowVisible(hwnd):
            return True

        ex_style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE) & 0xFFFFFFFF
        style = user32.GetWindowLongW(hwnd, GWL_STYLE) & 0xFFFFFFFF

        is_layered = bool(ex_style & WS_EX_LAYERED)
        is_transparent = bool(ex_style & WS_EX_TRANSPARENT)
        is_topmost = bool(ex_style & WS_EX_TOPMOST)

        # Must be layered (transparency capable) to be an overlay
        if not is_layered:
            return True

        # Get window size
        rect = wintypes.RECT()
        if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
            return True
        width = rect.right - rect.left
        height = rect.bottom - rect.top
        area = width * height

        # Skip small windows — overlays are typically large/fullscreen
        if area < min_area:
            return True

        # Get alpha if available
        alpha_val = wintypes.BYTE(255)
        flags = wintypes.DWORD(0)
        color_key = wintypes.COLORREF(0)
        user32.GetLayeredWindowAttributes(
            hwnd, ctypes.byref(color_key),
            ctypes.byref(alpha_val), ctypes.byref(flags))

        # Build flags string
        flag_parts = ["LAYERED"]
        if is_transparent:
            flag_parts.append("TRANSPARENT")
        if is_topmost:
            flag_parts.append("TOPMOST")
        if style & WS_POPUP:
            flag_parts.append("POPUP")
        if ex_style & WS_EX_NOACTIVATE:
            flag_parts.append("NOACTIVATE")
        if ex_style & WS_EX_TOOLWINDOW:
            flag_parts.append("TOOLWINDOW")

        # Scoring: more overlay-like traits = higher suspicion
        # Require at least transparent+topmost or transparent+large
        suspicious = False
        if is_transparent and is_topmost:
            suspicious = True
        elif is_transparent and area >= screen_w * screen_h * 0.8:
            suspicious = True
        elif is_topmost and (style & WS_POPUP) and alpha_val.value < 255:
            suspicious = True

        if suspicious:
            title = _get_window_title(hwnd)
            pid = _get_window_pid(hwnd)
            results.append({
                "hwnd": hwnd,
                "title": title or "<no title>",
                "pid": pid,
                "width": width,
                "height": height,
                "flags": "|".join(flag_parts),
                "alpha": alpha_val.value,
            })

        return True

    cb = WNDENUMPROC(enum_callback)
    user32.EnumWindows(cb, 0)

    return results
