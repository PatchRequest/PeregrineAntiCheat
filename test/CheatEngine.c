#include <stdio.h>
#include <windows.h>

/* Fake "CheatEngine" process — just existing triggers blacklist scan.
   Triggers: Process Blacklist Detection */

int main(void)
{
    printf("[CheatEngine] Fake cheat engine running (PID %lu)\n", GetCurrentProcessId());
    printf("[CheatEngine] Run 'Scan Blacklist' in Peregrine to detect me.\n");
    printf("[CheatEngine] Press Enter to exit.\n");
    getchar();
    return 0;
}
