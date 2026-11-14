/*
 * IPC forgery test: a process the kernel never injected connects to the
 * Peregrine telemetry pipe and sends hand-crafted "DLL" events — a fake hello,
 * a fake tamper alarm and an external-op event naming an arbitrary PID.
 *
 * Expected: the GUI authenticates every pipe client by its real PID against
 * the kernel's inject bookkeeping, disconnects this process without reading
 * its data, and shows NO log line for any of the forged events.
 * This tool reports whether the pipe was closed on it.
 *
 * Usage: cheat_pipe.exe [claimed_PID]
 *   claimed_PID is put into the forged messages as callerPID / targetPID
 *   (e.g. the game's PID) to show that claimed identity is ignored.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define PIPE_NAME "\\\\.\\pipe\\peregrine_ipc"

int main(int argc, char* argv[])
{
    DWORD claimed = (argc >= 2) ? (DWORD)atoi(argv[1]) : 4;

    /* Same access the real DLL requests (write only, no pipe-instance right). */
    HANDLE pipe = CreateFileA(PIPE_NAME, FILE_WRITE_DATA | SYNCHRONIZE, 0, NULL,
        OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        printf("[PIPE] cannot open %s: %lu (is the Peregrine GUI running?)\n",
            PIPE_NAME, GetLastError());
        return 1;
    }
    printf("[PIPE] connected as PID %lu, claiming to be PID %lu\n",
        GetCurrentProcessId(), claimed);

    char forged[3][256];
    _snprintf_s(forged[0], sizeof(forged[0]), _TRUNCATE,
        "{\"event\":\"hello\",\"callerPID\":%lu,\"image\":\"game.exe\",\"role\":\"game\"}", claimed);
    _snprintf_s(forged[1], sizeof(forged[1]), _TRUNCATE,
        "{\"event\":\"VehTableTamper\",\"callerPID\":%lu,\"threadId\":1,\"dr6\":\"0x1\"}", claimed);
    _snprintf_s(forged[2], sizeof(forged[2]), _TRUNCATE,
        "{\"event\":\"WriteProcessMemory\",\"callerPID\":4,\"targetPID\":%lu,\"address\":4096,\"size\":8}", claimed);

    /* The server drops unauthenticated clients right after accepting them, so
       writes start failing as soon as the disconnect has been processed. */
    int rejected = 0;
    for (int round = 0; round < 20 && !rejected; round++) {
        for (int i = 0; i < 3; i++) {
            DWORD written = 0;
            if (!WriteFile(pipe, forged[i], (DWORD)strlen(forged[i]), &written, NULL)) {
                printf("[PIPE] write failed with %lu — server closed the connection\n",
                    GetLastError());
                rejected = 1;
                break;
            }
        }
        Sleep(100);
    }
    CloseHandle(pipe);

    if (rejected) {
        printf("[PIPE] PASS: forged client was disconnected. The GUI log must show none of the forged events.\n");
        return 0;
    }
    printf("[PIPE] FAIL: the pipe accepted forged traffic for 2 seconds.\n");
    return 2;
}
