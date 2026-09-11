# A hand-written Linux x86-64 assembly program, ASSEMBLED AND LINKED INSIDE
# OS-DEV by the borrowed host binutils (M1955). Freestanding: no libc, so the
# only thing between this source and a running program is `as` and `ld`.
#
# -pie / ET_DYN on purpose: boot/boot.asm maps the low 1 GiB as supervisor
# pages, so no user page can exist below 1 GiB and a classic non-PIE link at
# 0x400000 cannot be loaded. Position-independent code with no relocations
# loads anywhere.
        .text
        .globl _start
_start:
        mov     $1, %eax                # write
        mov     $1, %edi                # fd 1
        lea     msg(%rip), %rsi
        mov     $len, %edx
        syscall
        mov     $231, %eax              # exit_group
        mov     $23, %edi
        syscall

        .section .rodata
msg:    .ascii  "SELFBUILT: assembled and linked by binutils running inside OS-DEV\n"
        len = . - msg
