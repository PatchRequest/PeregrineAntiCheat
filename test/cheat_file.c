#include <stdio.h>
#include <string.h>
#include <windows.h>

/*
 * Tamper attempts against the anti-cheat's own files (minifilter self-defense).
 * Every attempt must FAIL with access denied while the driver is loaded; the
 * tool only reports, it restores whatever an unexpected success changed.
 *
 * Usage: cheat_file.exe [ac_directory]      (default C:\Peregrine)
 * Run elevated — the point is that even an administrator is refused.
 */

static int g_failures = 0;

static void verdict(const char* what, BOOL attackSucceeded, DWORD err)
{
    if (attackSucceeded) {
        printf("  [FAIL] %s — the operation SUCCEEDED\n", what);
        g_failures++;
    } else {
        printf("  [ok]   %s — refused (error %lu)\n", what, err);
    }
}

int main(int argc, char* argv[])
{
    const char* dir = argc >= 2 ? argv[1] : "C:\\Peregrine";
    char target[MAX_PATH], path[MAX_PATH], tmp[MAX_PATH];
    snprintf(target, sizeof(target), "%s\\rules.yar", dir);

    printf("[FILE] target: %s\n", target);
    if (GetFileAttributesA(target) == INVALID_FILE_ATTRIBUTES) {
        printf("[FILE] target does not exist (error %lu)\n", GetLastError());
        return 2;
    }

    /* 1. Plain write open. */
    HANDLE h = CreateFileA(target, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD err = GetLastError();
    verdict("open for write", h != INVALID_HANDLE_VALUE, err);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    /* 2. The default data stream by its explicit name. */
    snprintf(path, sizeof(path), "%s::$DATA", target);
    h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    err = GetLastError();
    verdict("open ::$DATA for write", h != INVALID_HANDLE_VALUE, err);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    /* 3. A new alternate data stream on the file. */
    snprintf(path, sizeof(path), "%s:evil", target);
    h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    err = GetLastError();
    verdict("create alternate data stream", h != INVALID_HANDLE_VALUE, err);
    if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); DeleteFileA(path); }

    /* 4. Open by file ID: no path for a name-based filter to look at. */
    h = CreateFileA(target, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("  [skip] open by file ID — cannot open target for attributes (%lu)\n", GetLastError());
    } else {
        BY_HANDLE_FILE_INFORMATION info;
        if (GetFileInformationByHandle(h, &info)) {
            FILE_ID_DESCRIPTOR id;
            memset(&id, 0, sizeof(id));
            id.dwSize = sizeof(id);
            id.Type = FileIdType;
            id.FileId.HighPart = (LONG)info.nFileIndexHigh;
            id.FileId.LowPart = info.nFileIndexLow;
            HANDLE byId = OpenFileById(h, &id, GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, 0);
            err = GetLastError();
            verdict("open by file ID for write", byId != INVALID_HANDLE_VALUE, err);
            if (byId != INVALID_HANDLE_VALUE) CloseHandle(byId);
        }
        CloseHandle(h);
    }

    /* 5. Hard link: a second, unprotected name for the same file. */
    GetTempPathA(sizeof(tmp), tmp);
    snprintf(path, sizeof(path), "%speregrine_link_test.yar", tmp);
    DeleteFileA(path);
    BOOL ok = CreateHardLinkA(path, target, NULL);
    err = GetLastError();
    verdict("hard link to an unprotected name", ok, err);
    if (ok) DeleteFileA(path);

    /* 6. Delete. */
    ok = DeleteFileA(target);
    err = GetLastError();
    verdict("delete", ok, err);

    /* 7. Rename away. */
    snprintf(path, sizeof(path), "%s\\rules.yar.bak", dir);
    ok = MoveFileA(target, path);
    err = GetLastError();
    verdict("rename away", ok, err);
    if (ok) MoveFileA(path, target);

    /* 8. Replace by renaming another file onto it. */
    snprintf(path, sizeof(path), "%speregrine_replace_test.yar", tmp);
    h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        ok = MoveFileExA(path, target, MOVEFILE_REPLACE_EXISTING);
        err = GetLastError();
        verdict("replace by rename", ok, err);
        DeleteFileA(path);
    }

    /* 9. Rename the whole directory out from under the driver. */
    snprintf(path, sizeof(path), "%s_moved", dir);
    ok = MoveFileA(dir, path);
    err = GetLastError();
    verdict("rename the AC directory", ok, err);
    if (ok) MoveFileA(path, dir);

    printf("\n[FILE] %s\n", g_failures == 0
        ? "PASS: every tamper attempt was refused."
        : "FAIL: at least one tamper attempt succeeded.");
    return g_failures == 0 ? 0 : 1;
}
