#!/bin/bash
# Build LACUNA Chain PoC for Windows x64
# Cross-compile from Linux using mingw-w64
#
# Techniques implemented:
#   BYOUD-Gap, BYOUD-MF, BYOUD-RT, ETW-Ti APC window,
#   parameter encryption (HW breakpoint VEH), indirect syscalls,
#   ghost gadget scanning, win32u NOP gap chain,
#   section-based APC injection

set -e

CC=x86_64-w64-mingw32-gcc
SRC=lacuna_chain.c
OUT=lacuna.exe

echo "[*] Building LACUNA Chain PoC..."

$CC \
    -O0 \
    -masm=intel \
    -fno-omit-frame-pointer \
    -Wall -Wno-unused-function -Wno-frame-address \
    -o "$OUT" "$SRC" \
    -lkernel32 -lntdll

echo "[+] Built: $OUT ($(stat -c%s "$OUT") bytes)"
echo ""
echo "usage:"
echo "  lacuna.exe scan              enumerate ghost regions + gadgets across all DLLs"
echo "  lacuna.exe verify            build chain and walk L0(MF)→L1→L2→L3→L4→L5"
echo "  lacuna.exe inject <pid> <sc.bin>   section-based APC injection with full chain"
