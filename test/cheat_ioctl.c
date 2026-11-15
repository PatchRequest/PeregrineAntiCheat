#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winioctl.h>

/*
 * An elevated cheat talking to the anti-cheat driver directly.
 *
 * The control device is open to every administrator, so opening it works.
 * What must NOT work while the real GUI is running: becoming "trusted"
 * (which would exempt this process from all reporting and from the file
 * self-defense), reconfiguring the driver, or stealing its events.
 *
 * Usage: cheat_ioctl.exe      (run elevated, with the Peregrine GUI running)
 */

#define IOCTL_SEND  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RECV  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QINJ  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define CMD_CLEAR_PROTECTED 3
#define CMD_CLEAR_TARGETS   14
#define CMD_TRUST_CALLER    18

static int g_failures = 0;

static void attempt(HANDLE dev, const char* what, DWORD code, const void* in, DWORD inLen)
{
    char out[4096];
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(dev, code, (LPVOID)in, inLen, out, sizeof(out), &returned, NULL);
    DWORD err = GetLastError();

    /* RECV on an empty queue fails with ERROR_NO_MORE_ITEMS — that still means
       the driver answered us, i.e. the attack got through. */
    if (ok || (code == IOCTL_RECV && err == ERROR_NO_MORE_ITEMS)) {
        printf("  [FAIL] %s — the driver accepted the request\n", what);
        g_failures++;
    } else {
        printf("  [ok]   %s — refused (error %lu)\n", what, err);
    }
}

int main(void)
{
    HANDLE dev = CreateFileA("\\\\.\\Peregrine", GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (dev == INVALID_HANDLE_VALUE) {
        printf("[IOCTL] cannot open \\\\.\\Peregrine (error %lu) — driver not loaded or not elevated\n",
            GetLastError());
        return 2;
    }
    printf("[IOCTL] device opened as PID %lu\n", GetCurrentProcessId());

    unsigned char cmd;
    DWORD pid = GetCurrentProcessId();

    cmd = CMD_TRUST_CALLER;
    attempt(dev, "become trusted (TrustCaller)", IOCTL_SEND, &cmd, 1);
    cmd = CMD_CLEAR_PROTECTED;
    attempt(dev, "unprotect every game (ClearProtected)", IOCTL_SEND, &cmd, 1);
    cmd = CMD_CLEAR_TARGETS;
    attempt(dev, "disable injection (ClearTargets)", IOCTL_SEND, &cmd, 1);
    attempt(dev, "steal kernel events (RECV)", IOCTL_RECV, NULL, 0);
    attempt(dev, "query inject bookkeeping (QUERY_INJECTED)", IOCTL_QINJ, &pid, sizeof(pid));
    attempt(dev, "read driver configuration (QUERY_STATE)", IOCTL_STATE, NULL, 0);

    CloseHandle(dev);

    printf("\n[IOCTL] %s\n", g_failures == 0
        ? "PASS: the driver answers nobody but its trusted GUI."
        : "FAIL: the driver accepted a request from an untrusted process.");
    return g_failures == 0 ? 0 : 1;
}
