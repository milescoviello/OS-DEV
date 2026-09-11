; --- Linux ABI entry: the `syscall` instruction (M1938) ----------------------
;
; OS-DEV's own 345 syscalls arrive via `int 0x80`. This is a SECOND, fully
; independent entry path implementing the Linux x86-64 ABI, so the two can
; never collide -- a Linux binary's `syscall` and our own `int 0x80` land in
; different handlers with different number tables, in the same process if need
; be. Nothing about the native ABI changes.
;
; SYSCALL does NOT switch stacks. It loads CS/SS from STAR, puts the return RIP
; in RCX and RFLAGS in R11, masks the bits named by SFMASK, and jumps to LSTAR
; -- leaving RSP pointing at the USER stack. So we must find a kernel stack
; before touching anything, which is what the per-CPU block reached through
; KERNEL_GS_BASE is for: `swapgs` makes it addressable without first needing a
; free register to spill into.
;
; We return with `iretq`, NOT `sysret`. SYSRET derives SS from STAR[63:48]+8 and
; CS from +16, but this GDT has user code at 0x18 and user data at 0x20 -- the
; opposite order -- so sysret would load the wrong selectors. Reordering the GDT
; would touch USER_CS/USER_DS everywhere; iretq just names both explicitly and
; costs a few tens of cycles more per call.
extern linux_syscall_dispatch
global linux_syscall_entry
linux_syscall_entry:
    swapgs                          ; GS base -> this core's per-CPU block
    mov [gs:8], rsp                 ; stash the user RSP in the scratch slot
    mov rsp, [gs:0]                 ; ... and take this core's kernel stack

    ; Build a frame byte-identical to isr_common's `struct registers`, so every
    ; existing helper that takes one keeps working unchanged -- signal delivery
    ; (app_deliver_pending), /proc/<pid>/regs, and fork's frame cloning all
    ; mutate this struct in place and must not know which entry path built it.
    push qword 0x23                 ; ss     = USER_DS
    push qword [gs:8]               ; rsp    = the user's, from the scratch slot
    push r11                        ; rflags = saved by SYSCALL
    push qword 0x1B                 ; cs     = USER_CS
    push rcx                        ; rip    = saved by SYSCALL
    push qword 0                    ; err_code (none)
    push qword 0x80                 ; int_no: reuse SYSCALL_VECTOR so anything
                                    ; keying on "this is a syscall frame" agrees

    push rax                        ; GP block, in isr_common's exact order
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    cld                             ; SysV ABI: DF clear on entry to C
    mov rdi, rsp                    ; arg0 = struct registers *
    call linux_syscall_dispatch

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16                     ; discard int_no + err_code
    swapgs                          ; user GS base back
    iretq                           ; rip/cs/rflags/rsp/ss -- honours any frame
                                    ; edit the dispatcher made (signals, exec)
