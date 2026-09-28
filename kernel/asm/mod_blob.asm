; mod_blob.asm — embed the compiled loadable kernel module (build/testmod.ko)
; into the kernel image, so insmod can load + relocate + run it with no disk.
; (M1261) Mirrors user_blob.asm's incbin idiom for the userspace app ELFs.
; The Makefile builds build/testmod.ko (an ET_REL object) before assembling
; this file (an explicit prerequisite on build/kernel/asm/mod_blob.o).

section .rodata
global testmod_ko_start, testmod_ko_end
testmod_ko_start:
        incbin "build/testmod.ko"
testmod_ko_end:

; No executable stack (the linker otherwise assumes one for this object).
section .note.GNU-stack noalloc noexec nowrite progbits
