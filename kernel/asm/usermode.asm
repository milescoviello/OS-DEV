; usermode.asm — cross the ring 0 <-> ring 3 boundary.
;
; enter_user(entry, user_stack): drop into ring 3. There's no "jump to ring 3"
; instruction — you *return* into it. We fake an interrupt-return frame
; (SS, RSP, RFLAGS, CS, RIP) with user selectors and execute `iretq`, which
; pops it and lands in ring 3 with the user's stack and instruction pointer.
;
; Before doing that we stash the kernel's callee-saved state + stack pointer so
; that SYS_exit can come back here (return_to_kernel) and resume the kernel
; right after the enter_user() call — a one-way longjmp out of userspace.

section .bss
global kernel_resume_rsp
kernel_resume_rsp: resq 1
global user_exit_code
user_exit_code: resq 1

section .text

; void enter_user(uint64_t entry /* rdi */, uint64_t user_stack /* rsi */)
global enter_user
enter_user:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov [kernel_resume_rsp], rsp     ; remember how to get back

    mov ax, 0x23                     ; USER_DS (ring 3 data) into the data segs
    mov ds, ax
    mov es, ax
    ; FS is deliberately NOT reloaded (M1949): loading any FS selector ZEROES
    ; FS_BASE, which is the thread's TLS pointer. The context switch has just
    ; restored it (load_fs_base), so reloading the selector here wiped it
    ; microseconds later -- a forked child inherited its parent's TLS base and
    ; then entered ring 3 with FS_BASE = 0, so its first %fs access read a
    ; small absolute address. glibc's _Fork does exactly that (`mov %fs:0x10`)
    ; and page faulted with err=0x5: a ring-3 read of address 0x10, present in
    ; the low identity map but with no PTE_USER.
    ;
    ; Worse, loaded_fs_base[core] still believed the MSR held the right value,
    ; so a later load_fs_base() would SKIP the write and leave it zeroed.
    ; In long mode the DS/ES/FS/GS selectors are not used for access checks --
    ; only FS/GS BASE matters -- so leaving FS alone is correct, and
    ; load_fs_base() on every context switch is the single authority.
    ; GS is deliberately NOT reloaded (M1949): loading any GS selector ZEROES
    ; GS_BASE, and GS_BASE permanently holds this core's Linux-ABI per-CPU
    ; pointer. In long mode the DS/ES/FS/GS selectors are not used for access
    ; checks anyway -- only FS/GS BASE matters -- so leaving it is harmless,
    ; and ring 3 cannot read through it (the block has no PTE_USER).

    pushfq                           ; take current RFLAGS...
    pop rax
    or rax, 0x200                    ; ...and make sure IF is set in user mode

    push 0x23                        ; SS  = USER_DS
    push rsi                         ; RSP = user stack top
    push rax                         ; RFLAGS
    push 0x1B                        ; CS  = USER_CS
    push rdi                         ; RIP = entry point

    ; Zero every general-purpose register before crossing into ring 3 (M1945).
    ; The iret frame is already on the stack, so the argument registers have
    ; been consumed and this is safe. Two independent reasons, both real:
    ;
    ; 1) THE ABI REQUIRES IT. The x86-64 System V ABI says %rdx holds a
    ;    function pointer for the program to register with atexit (rtld_fini)
    ;    and must be ZERO when there is none. glibc's _start passes %rdx
    ;    straight to __libc_start_main, which registers it via __cxa_atexit --
    ;    so a leftover kernel value there is CALLED when the program exits.
    ;    Measured: a glibc binary faulted on an instruction fetch at
    ;    0xffff8000fee00000 (the kernel's LAPIC mapping) with the exit status
    ;    still in %rsi. It was calling our stale register as an exit handler.
    ;
    ; 2) IT IS AN INFORMATION LEAK REGARDLESS. Ring 3 previously started with
    ;    whatever the kernel happened to leave in every register, kernel
    ;    pointers included -- and that applied to OS-DEV's own apps, not just
    ;    Linux ones. Nothing in ring 3 has any business reading them.
    ;
    ; Only this path zeroes: iret_to_user() restores a FULL saved frame on
    ; purpose (a fork child must resume with its parent's registers).
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    xor edi, edi
    xor ebp, ebp
    xor r8d,  r8d
    xor r9d,  r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d
    iretq                            ; -> ring 3

; void return_to_kernel(long code /* rdi */)  — does not return to its caller;
; resumes execution right after enter_user() in the kernel.
global return_to_kernel
return_to_kernel:
    mov [user_exit_code], rdi

    mov ax, 0x10                     ; back to KERNEL_DS
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    mov rsp, [kernel_resume_rsp]     ; restore the saved kernel stack
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret                              ; return out of enter_user()

section .note.GNU-stack noalloc noexec nowrite progbits
