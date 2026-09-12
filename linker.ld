/*
 * linker.ld — lay out the kernel ELF for the multiboot loader.
 *
 * The kernel is loaded at physical 1 MiB (0x100000), the conventional spot
 * for a multiboot kernel (below that is BIOS/legacy junk). The .multiboot
 * section is placed first so the magic header lands within the first 8 KiB
 * of the file, which the loader requires.
 *
 * HIGHER-HALF (M1968). The kernel is still LOADED at physical 1 MiB -- that is
 * where a multiboot loader puts it and it needs RAM to exist there -- but it is
 * now LINKED at 0xFFFFFFFF80100000 and runs there once paging is on. Every
 * section therefore carries an explicit AT() giving its physical load address.
 *
 * Why: the low 1 GiB was identity-mapped as SUPERVISOR pages shared into every
 * address space, so no user page could exist below 1 GiB. That is fine for
 * position-independent binaries (we relocate them to 0x40000000) and fatal for
 * everything else: a non-PIE Linux ET_EXEC binary is linked at a fixed low
 * address and cannot be moved. Claude Code is one -- a single 214 MB image
 * linked at 0x200000, running to 0xD78F000 -- and the kernel's own code sat
 * inside exactly that range. Kernel code must stay mapped in every address
 * space to service a syscall, so the only fix is to put it somewhere a user
 * program will never ask for. The top 2 GiB is that place.
 *
 * -mcmodel=kernel goes with this: it tells the compiler every symbol lives in
 * the top 2 GiB, so it keeps using cheap sign-extended 32-bit displacements
 * instead of full 64-bit addresses.
 */

OUTPUT_FORMAT(elf64-x86-64)

KERNEL_PHYS_ADDR = 1M;
KERNEL_VMA       = 0xFFFFFFFF80000000;
KERNEL_LOAD_ADDR = KERNEL_VMA + KERNEL_PHYS_ADDR;

/* The ENTRY POINT must be PHYSICAL (M1968).
 *
 * The multiboot loader jumps to e_entry in 32-bit protected mode with paging
 * off, so it has to be a physical address -- but `_start` is now a higher-half
 * symbol, and build/kernel32.elf is the whole image repackaged as elf32 (QEMU's
 * multiboot loader refuses ELF64), which TRUNCATES every address to 32 bits.
 * 0xFFFFFFFF80100000 truncates to 0x80100000: the load addresses survive
 * (p_paddr is already physical) but the entry would have pointed at nothing.
 * Name the physical alias explicitly instead of relying on truncation. */
_start_phys = _start - KERNEL_VMA;
ENTRY(_start_phys)

SECTIONS
{
    . = KERNEL_LOAD_ADDR;

    .boot : AT(ADDR(.boot) - KERNEL_VMA) {
        *(.multiboot)
    }

    .text : AT(ADDR(.text) - KERNEL_VMA) ALIGN(4K) {
        _kimage_start = .;          /* start of the read-only code+rodata image (measured-boot, M1096) */
        *(.text*)
    }

    .rodata : AT(ADDR(.rodata) - KERNEL_VMA) ALIGN(4K) {
        _srodata = .;               /* W^X: page-aligned start of read-only data (vmm_harden_kernel) */
        *(.rodata*)
        _kimage_end = .;            /* end of .text+.rodata: a deterministic span covering kernel code + the embedded app ELFs */
    }

    .data : AT(ADDR(.data) - KERNEL_VMA) ALIGN(4K) {
        _sdata = .;                 /* W^X: page-aligned start of writable data */
        *(.data*)
    }

    /* Executable scratch for the eBPF JIT (kernel/bpf.c) and the loadable-module
     * loader (kernel/module.c): both emit/relocate machine code into these buffers
     * and then jump to it, so this region must stay executable. W^X
     * (vmm_harden_kernel) marks the REST of .data/.bss no-execute but re-marks
     * [_jitexec_start, _jitexec_end) RWX. Page-aligned both ends so it is a whole
     * number of pages. NOLOAD (like .bss): the buffers are written before use. */
    .jitexec (NOLOAD) : AT(ADDR(.jitexec) - KERNEL_VMA) ALIGN(4K) {
        _jitexec_start = .;
        *(.jitexec*)
        . = ALIGN(4K);
        _jitexec_end = .;
    }

    /* Low-physical, page-aligned BSS placed BEFORE the big .bss arenas, so any
     * buffer here is guaranteed to sit within the low 16 MiB of physical RAM.
     * This is for ISA DMA (the 8237 / floppy), whose DMA controller can only
     * address 24 bits (16 MiB): the kernel image's huge static arenas (the JS
     * arena alone is 44 MiB) push kernel_end past 16 MiB, so NO free PMM frame
     * is low enough — a reserved low buffer in the image is the way to get one.
     * Kept tiny (a couple of pages) so it stays comfortably under 16 MiB even as
     * .text/.rodata/.data grow. NOLOAD: zero-initialised at runtime like .bss. */
    .lowbss (NOLOAD) : AT(ADDR(.lowbss) - KERNEL_VMA) ALIGN(4K) {
        *(.lowbss*)
    }

    .bss : AT(ADDR(.bss) - KERNEL_VMA) ALIGN(4K) {
        *(COMMON)
        *(.bss*)
    }

    kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.note*)
        *(.comment)
    }
}
