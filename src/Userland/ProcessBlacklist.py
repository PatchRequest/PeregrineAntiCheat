import ctypes
from ctypes import wintypes

# Process enumeration APIs
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD)
]

kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

kernel32.Process32First.restype = wintypes.BOOL
kernel32.Process32Next.restype = wintypes.BOOL


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.CHAR * 260)
    ]


kernel32.Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]


# Default blacklist keywords
DEFAULT_BLACKLIST = [
    "GuidedHacking",
    "CheatEngine",
    "x64dbg",
    "x32dbg",
    "IDA",
    "dnSpy",
    "ProcessHacker",
    "ReClass",
    "Cheat",
    "Trainer",
    "Injector",
    "DLLInjector",
]


def scan_processes_for_blacklist(blacklist_keywords=None):
    """
    Enumerate all running processes and check their image paths against a blacklist.

    Args:
        blacklist_keywords: List of keywords to search for (default: DEFAULT_BLACKLIST)

    Returns:
        List of dictionaries containing PID, path, and matched keyword for suspicious processes
    """
    if blacklist_keywords is None:
        blacklist_keywords = DEFAULT_BLACKLIST

    matches = []
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    if snapshot == wintypes.HANDLE(-1).value:
        return matches

    try:
        pe32 = PROCESSENTRY32()
        pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

        if not kernel32.Process32First(snapshot, ctypes.byref(pe32)):
            return matches

        while True:
            pid = pe32.th32ProcessID

            # Skip System process (PID 0 and 4)
            if pid in (0, 4):
                if not kernel32.Process32Next(snapshot, ctypes.byref(pe32)):
                    break
                continue

            # Try to get full image path
            h_process = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if h_process:
                try:
                    path_buffer = ctypes.create_unicode_buffer(1024)
                    path_size = wintypes.DWORD(1024)

                    if kernel32.QueryFullProcessImageNameW(h_process, 0, path_buffer, ctypes.byref(path_size)):
                        full_path = path_buffer.value

                        # Check against blacklist (case-insensitive)
                        full_path_lower = full_path.lower()
                        for keyword in blacklist_keywords:
                            if keyword.lower() in full_path_lower:
                                matches.append({
                                    "pid": pid,
                                    "path": full_path,
                                    "keyword": keyword
                                })
                                break
                finally:
                    kernel32.CloseHandle(h_process)

            # Move to next process
            if not kernel32.Process32Next(snapshot, ctypes.byref(pe32)):
                break

    finally:
        kernel32.CloseHandle(snapshot)

    return matches


if __name__ == "__main__":
    # Test the scanner
    print("Scanning for blacklisted processes...")
    results = scan_processes_for_blacklist()

    if results:
        print(f"\nFound {len(results)} suspicious process(es):")
        for r in results:
            print(f"  [PID {r['pid']}] {r['path']} (matched: {r['keyword']})")
    else:
        print("\nNo blacklisted processes found.")
