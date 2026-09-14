; fpu.asm — enable the x87 FPU + SSE so userspace can use floating point, and
; provide FXSAVE/FXRSTOR so the scheduler can preserve FP/SSE state per task.
;
; The kernel itself is built -mgeneral-regs-only (it never touches the FPU/SSE
; registers), but userspace programs compiled with floating point — DOOM and
; Quake — need SSE. fpu_init enables it globally at boot:
;
;   CR0.EM (bit 2) = 0  use the real FPU, don't trap FP ops to an emulator
;   CR0.MP (bit 1) = 1  monitor coprocessor
;   CR4.OSFXSR     = 1  enable SSE + the FXSAVE/FXRSTOR area layout
;   CR4.OSXMMEXCPT = 1  deliver unmasked SSE exceptions as #XM (not #UD)
;   fninit + MXCSR = 0x1F80  reset x87 and mask all SSE exceptions
;
; It then snapshots this clean state into fpu_template, which task.c copies into
; each new task's save area so a first FXRSTOR loads a sane state. The scheduler
; calls fpu_save/fpu_restore (FXSAVE/FXRSTOR) around every context switch, so two
; FP-using programs (e.g. DOOM and Quake) can run at once without corrupting each
; other's XMM/x87 registers.

section .text
global fpu_init
fpu_init:
    mov rax, cr0
    btr rax, 2          ; clear CR0.EM
    bts rax, 1          ; set   CR0.MP
    mov cr0, rax
    mov rax, cr4
    bts rax, 9          ; set CR4.OSFXSR
    bts rax, 10         ; set CR4.OSXMMEXCPT
    mov cr4, rax
    fninit              ; reset the x87 FPU
    push 0x1F80         ; default MXCSR: all SSE exceptions masked
    ldmxcsr [rsp]
    add rsp, 8
    fxsave [fpu_template]   ; capture the clean state as the per-task template
    ret

; void fpu_init_ap(void) — CR0/CR4 are PER-CORE control registers (M1531): the
; BSP's fpu_init() above only ever enabled FXSAVE/FXRSTOR on the BSP itself.
; Once a task (with its own fxbuf) can be scheduled onto an AP (M1531's cross-
; core scheduler), that AP's FIRST fpu_save/fpu_restore call would execute
; FXSAVE/FXRSTOR with CR4.OSFXSR still 0 -- #UD (Invalid Opcode), hit exactly
; that as a real in-guest crash. Same CR0/CR4 bits, but skips capturing
; fpu_template again: it's a static "clean FPU state" snapshot, identical on
; every core, already captured once by the BSP -- every task's fxbuf is
; seeded from that same shared copy (task.c's fx_alloc), so there is nothing
; core-specific left to (re-)do here.
global fpu_init_ap
fpu_init_ap:
    mov rax, cr0
    btr rax, 2
    bts rax, 1
    mov cr0, rax
    mov rax, cr4
    bts rax, 9
    bts rax, 10
    mov cr4, rax
    fninit
    push 0x1F80
    ldmxcsr [rsp]
    add rsp, 8
    ret

; void fpu_save(void *area16)    — area must be 16-byte aligned
global fpu_save
fpu_save:
    fxsave [rdi]
    ret

; void fpu_restore(const void *area16)
global fpu_restore
fpu_restore:
    fxrstor [rdi]
    ret

section .bss
align 16
global fpu_template
fpu_template:
    resb 512

section .note.GNU-stack noalloc noexec nowrite progbits

section .text                   ; MUST re-declare: everything below was appended
                                ; after the .note.GNU-stack directive at the end
                                ; of this file, and ld DISCARDS that section --
                                ; so these functions silently vanished from the
                                ; link while `make` looked like it succeeded.
; --- XSAVE / AVX (M1942) ----------------------------------------------------
;
; Real Linux binaries contain AVX. glibc's own _dl_aux_init opens with
; `vpxor %xmm0,%xmm0,%xmm0`, and a VEX-encoded instruction raises #UD unless
; CR4.OSXSAVE is set AND XCR0 enables the SSE and AVX state components. Neither
; was ever done here -- fpu_init above enables only CR4.OSFXSR/OSXMMEXCPT --
; because OS-DEV's own apps are SSE2 at most.
;
; Enabling AVX is NOT just a control-register poke. FXSAVE/FXRSTOR preserve x87
; and the low 128 bits (XMM) but NOT the upper halves of YMM, so two AVX-using
; tasks would silently corrupt each other's registers across a context switch.
; That is why this comes with XSAVE/XRSTOR, and why the switch only moves to
; XSAVE when the CPU actually reports both features.

; int fpu_enable_xsave(void) -- arm XSAVE+AVX on the CALLING core. Returns 1 on
; success, 0 if the CPU lacks XSAVE or AVX (leaving FXSAVE/FXRSTOR in use).
; CR4 and XCR0 are PER-CORE, so every AP must call this too.
global fpu_enable_xsave
fpu_enable_xsave:
    push rbx
    mov eax, 1
    cpuid                       ; ECX[26] = XSAVE, ECX[28] = AVX
    test ecx, 1 << 26
    jz .unsupported
    test ecx, 1 << 28
    jz .unsupported
    mov rax, cr4
    bts rax, 18                 ; CR4.OSXSAVE -- must precede XGETBV/XSETBV,
    mov cr4, rax                ; which themselves #UD without it
    ; WHICH STATE COMPONENTS DOES THIS CPU ACTUALLY HAVE? (M2007)
    ;
    ; We used to enable exactly x87|SSE|AVX and stop there -- while CPUID went
    ; on advertising AVX-512 to userspace, because nothing here masks CPUID and
    ; `-cpu max` reports what the emulator can do. A library that dispatches on
    ; CPUID then issues an AVX-512 instruction, the CPU finds its state disabled
    ; in XCR0, and the instruction is simply not there:
    ;
    ;   [fault] Invalid Opcode (vector 6) at libxul.so + 788f4eb
    ;
    ; CPUID says yes and XCR0 says no, and userspace believes CPUID. So enable
    ; every component the CPU reports, masked to the ones whose state XSAVE can
    ; carry for us with no extra bookkeeping. fpu_xsave_size then sizes the area
    ; from XCR0, so the save/restore path follows automatically.
    mov eax, 0x0D
    xor ecx, ecx
    cpuid                       ; EAX = bitmap of XCR0 bits this CPU supports
    mov ebx, eax                ; keep the supported mask
    mov eax, 0x7                ; x87 | SSE | AVX -- the baseline, always
    ; AVX-512 is bits 5 (opmask), 6 (ZMM_Hi256) and 7 (Hi16_ZMM), and it is ALL
    ; OR NOTHING: XSETBV #GPs on a subset.
    mov edx, ebx
    and edx, 0xE0
    cmp edx, 0xE0
    jne .no_avx512
    or eax, 0xE0
.no_avx512:
    and eax, ebx                ; never set a bit the CPU does not have
    xor ecx, ecx
    xor edx, edx
    xsetbv
    mov eax, 1
    pop rbx
    ret
.unsupported:
    xor eax, eax
    pop rbx
    ret

; uint64_t fpu_xcr0(void) -- the state components actually enabled, so the boot
; log can say which ones rather than claiming a fixed set. (M2007)
global fpu_xcr0
fpu_xcr0:
    ; XGETBV ITSELF #UDs WHEN CR4.OSXSAVE IS CLEAR. That is not a
    ; theoretical guard: vexemu_try calls this from the #UD handler to decide
    ; whether it can emulate, so on a CPU with no XSAVE at all (QEMU's default
    ; qemu64, which is what several suites boot) the FIRST ring-3 invalid
    ; opcode took a SECOND #UD inside the handler, in ring 0 -- a kernel panic
    ; where the correct outcome was "kill that one process".
    ; Report XCR0 = 0, which every caller already reads as "no such state".
    push rbx
    mov rax, cr4
    test rax, 0x40000           ; CR4.OSXSAVE
    jz .none
    xor ecx, ecx
    xgetbv                      ; EDX:EAX = XCR0
    shl rdx, 32
    or rax, rdx
    pop rbx
    ret
.none:
    xor eax, eax
    pop rbx
    ret

; uint32_t fpu_avx_offset(void) -- byte offset of the YMM_Hi128 state component
; inside an XSAVE area: CPUID.(EAX=0Dh,ECX=2):EBX. Queried, not hardcoded --
; the layout is the CPU's to choose, and the GFNI emulator has to find YMM's
; upper halves there. 0 if the CPU has no such component. (M2007)
global fpu_avx_offset
fpu_avx_offset:
    push rbx
    mov eax, 0x0D
    mov ecx, 2
    cpuid
    mov eax, ebx
    pop rbx
    ret

; uint32_t fpu_xsave_size(void) -- bytes the XSAVE area needs for the features
; currently enabled in XCR0 (CPUID.(EAX=0Dh,ECX=0):EBX). Queried rather than
; hardcoded: it depends on which components XCR0 actually enabled.
global fpu_xsave_size
fpu_xsave_size:
    push rbx
    mov eax, 0x0D
    xor ecx, ecx
    cpuid
    mov eax, ebx
    pop rbx
    ret

; void fpu_xsave_to(void *area) / void fpu_xrstor_from(const void *area)
; EDX:EAX is the requested-feature bitmap; all-ones means "everything XCR0
; permits". The area must be 64-BYTE aligned -- XSAVE #GPs otherwise, and
; kmalloc only guarantees 16, which is why the caller aligns inside a slack
; buffer rather than trusting the allocator.
global fpu_xsave_to
fpu_xsave_to:
    mov eax, 0xFFFFFFFF
    mov edx, 0xFFFFFFFF
    xsave [rdi]
    ret

global fpu_xrstor_from
fpu_xrstor_from:
    mov eax, 0xFFFFFFFF
    mov edx, 0xFFFFFFFF
    xrstor [rdi]
    ret

; void fpu_xsave_template(void *area) -- capture a CLEAN state for new tasks.
; Not a zeroed buffer: with XSTATE_BV=0 an XRSTOR would load MXCSR straight from
; the area, and a zero MXCSR unmasks every SSE exception, so the first FP
; instruction in a fresh task could take a #XM. fninit + MXCSR=0x1F80 then
; XSAVE captures the same sane state fpu_init already relies on.
global fpu_xsave_template
fpu_xsave_template:
    fninit
    push 0x1F80
    ldmxcsr [rsp]
    add rsp, 8
    mov eax, 0xFFFFFFFF
    mov edx, 0xFFFFFFFF
    xsave [rdi]
    ret

section .bss
align 64
global fpu_xtemplate
fpu_xtemplate:
    ; Generously sized and 64-BYTE aligned (XSAVE #GPs otherwise). 4 KiB covers
    ; x87+SSE+AVX (832 B) with room to spare if AVX-512 is ever enabled, and
    ; fpu_xsave_size() is what actually bounds the per-task copies -- this is
    ; only the clean template captured once at boot.
    resb 4096
