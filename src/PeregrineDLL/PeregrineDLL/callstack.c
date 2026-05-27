#include "callstack.h"
#include "ipc.h"
#include <string.h>

/* ------------------------------------------------------------ */
/* Module range cache                                           */
/* ------------------------------------------------------------ */

typedef struct {
    ULONG_PTR base;
    ULONG_PTR end;
} ModuleRange;

#define MAX_MODULE_RANGES 512
#define CACHE_REFRESH_MS  5000

static ModuleRange g_modules[MAX_MODULE_RANGES];
static volatile LONG g_module_count = 0;
static volatile LONG g_cache_lock = 0;
static volatile ULONGLONG g_cache_last_refresh = 0;

static int range_cmp(const void* a, const void* b) {
    const ModuleRange* ra = (const ModuleRange*)a;
    const ModuleRange* rb = (const ModuleRange*)b;
    if (ra->base < rb->base) return -1;
    if (ra->base > rb->base) return  1;
    return 0;
}

static void refresh_module_cache(void) {
    if (InterlockedCompareExchange(&g_cache_lock, 1, 0) != 0)
        return;

    ModuleRange tmp[MAX_MODULE_RANGES];
    int count = 0;

    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0;

    while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.Type == MEM_IMAGE && count < MAX_MODULE_RANGES) {
            ULONG_PTR rBase = (ULONG_PTR)mbi.BaseAddress;
            ULONG_PTR rEnd  = rBase + mbi.RegionSize;

            if (count > 0 && tmp[count - 1].end == rBase) {
                tmp[count - 1].end = rEnd;
            } else {
                tmp[count].base = rBase;
                tmp[count].end  = rEnd;
                count++;
            }
        }
        ULONG_PTR next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    qsort(tmp, count, sizeof(ModuleRange), range_cmp);

    memcpy(g_modules, tmp, count * sizeof(ModuleRange));
    InterlockedExchange(&g_module_count, count);
    g_cache_last_refresh = GetTickCount64();

    InterlockedExchange(&g_cache_lock, 0);
}

static int is_in_module(ULONG_PTR addr) {
    LONG count = g_module_count;
    int lo = 0, hi = count - 1;

    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (addr < g_modules[mid].base)
            hi = mid - 1;
        else if (addr >= g_modules[mid].end)
            lo = mid + 1;
        else
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------ */
/* Per-hook rate limiter                                        */
/* ------------------------------------------------------------ */

typedef struct {
    const char*     hook_name;
    LONG            max_per_minute;
    volatile LONG   count;
    volatile ULONGLONG window_start;
} RateLimit;

#define NUM_HOOKS 9

static RateLimit g_limits[NUM_HOOKS] = {
    { "OpenProcess",          50, 0, 0 },
    { "CreateRemoteThread",   50, 0, 0 },
    { "NtSetContextThread",   50, 0, 0 },
    { "VirtualAllocEx",       20, 0, 0 },
    { "VirtualProtectEx",     20, 0, 0 },
    { "ReadProcessMemory",     2, 0, 0 },
    { "WriteProcessMemory",    2, 0, 0 },
    { "NtReadVirtualMemory",   2, 0, 0 },
    { "NtWriteVirtualMemory",  2, 0, 0 },
};

static int rate_limit_allow(const char* hook_name) {
    RateLimit* rl = NULL;
    for (int i = 0; i < NUM_HOOKS; i++) {
        if (strcmp(g_limits[i].hook_name, hook_name) == 0) {
            rl = &g_limits[i];
            break;
        }
    }
    if (!rl) return 1;

    ULONGLONG now = GetTickCount64();
    if (now - rl->window_start >= 60000) {
        rl->window_start = now;
        InterlockedExchange(&rl->count, 0);
    }

    LONG c = InterlockedIncrement(&rl->count);
    return c <= rl->max_per_minute;
}

/* ------------------------------------------------------------ */
/* Stack walk + detection                                       */
/* ------------------------------------------------------------ */

#define MAX_FRAMES  32
#define SKIP_FRAMES  2

int callstack_check(const char* hook_name) {
    if (!rate_limit_allow(hook_name))
        return 0;

    ULONGLONG now = GetTickCount64();
    if (now - g_cache_last_refresh > CACHE_REFRESH_MS)
        refresh_module_cache();

    void* frames[MAX_FRAMES];
    USHORT count = RtlCaptureStackBackTrace(SKIP_FRAMES, MAX_FRAMES, frames, NULL);

    for (USHORT i = 0; i < count; i++) {
        ULONG_PTR addr = (ULONG_PTR)frames[i];
        if (addr == 0) continue;

        if (!is_in_module(addr)) {
            refresh_module_cache();
            if (!is_in_module(addr)) {
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    DWORD prot = mbi.Protect & 0xFF;
                    int executable = (prot == PAGE_EXECUTE ||
                                     prot == PAGE_EXECUTE_READ ||
                                     prot == PAGE_EXECUTE_READWRITE ||
                                     prot == PAGE_EXECUTE_WRITECOPY);
                    if (mbi.Type == MEM_PRIVATE && executable) {
                        ipc_log_event("CallstackAnomaly",
                            "\"hook\":\"%s\",\"address\":\"0x%llX\","
                            "\"frameIndex\":%u,\"regionBase\":\"0x%llX\","
                            "\"regionSize\":%llu,\"protect\":\"0x%lX\"",
                            hook_name,
                            (unsigned long long)addr,
                            (unsigned int)i,
                            (unsigned long long)(ULONG_PTR)mbi.BaseAddress,
                            (unsigned long long)mbi.RegionSize,
                            (unsigned long)mbi.Protect);
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

void callstack_init(void) {
    refresh_module_cache();
    ULONGLONG now = GetTickCount64();
    for (int i = 0; i < NUM_HOOKS; i++) {
        g_limits[i].window_start = now;
        g_limits[i].count = 0;
    }
}
