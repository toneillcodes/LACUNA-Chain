# Stop execution if any command fails (equivalent to set -e)
$ErrorActionPreference = "Stop"

# Define compiler and flags
$CC = "x86_64-w64-mingw32-gcc"
$CFLAGS = @("-O2", "-s", "-masm=intel", "-fno-omit-frame-pointer", "-Wall", "-Wno-unused-function", "-Wno-frame-address")
$LIBS = @("-lkernel32", "-lntdll")

Write-Host "[*] Building LACUNA Chain PoC..."
# Run compiler for the main executable
& $CC $CFLAGS -o lacuna.exe lacuna_chain.c $LIBS
$Size1 = (Get-Item .\lacuna.exe).Length
Write-Host "[+] Built: lacuna.exe ($Size1 bytes)"

Write-Host "[*] Building LACUNA Sleep..."
# Run compiler for the sleep executable
& $CC $CFLAGS -o lacuna_sleep.exe lacuna_sleep.c $LIBS
$Size2 = (Get-Item .\lacuna_sleep.exe).Length
Write-Host "[+] Built: lacuna_sleep.exe ($Size2 bytes)"

Write-Host ""
Write-Host "usage:"
Write-Host "  lacuna.exe scan                 enumerate ghost regions + gadgets"
Write-Host "  lacuna.exe verify               build chain and walk L0->L1->L2->L3->L4->L5"
Write-Host "  lacuna.exe inject <pid> <sc.bin>   section-based APC injection with full chain"
Write-Host "  lacuna_sleep.exe                    demo mode (3 cycles, test payload)"
Write-Host "  lacuna_sleep.exe <sc.bin> [ms]      sleep-loop with real shellcode"
