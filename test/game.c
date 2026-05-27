#include <stdio.h>
#include <windows.h>

int main(void)
{
    volatile int health = 100;

    printf("[GAME] PID = %lu\n", GetCurrentProcessId());
    printf("[GAME] health address = 0x%p\n", (void*)&health);
    printf("[GAME] health = %d\n\n", health);

    while (1) {
        printf("[GAME] health = %d  (addr 0x%p)\n", health, (void*)&health);
        Sleep(100);
    }

    return 0;
}
