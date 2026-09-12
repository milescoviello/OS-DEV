/* elf.h — minimal ELF64 loader. */
#pragma once
#include <stdint.h>

/* A page-aligned, whole-BSS (no file-backed bytes) sub-range of a PT_LOAD
 * segment that elf_load left unmapped instead of eagerly zeroing — see
 * elf_load's out_lazy parameter below. */
typedef struct { uint64_t start, len; } elf_lazy_range_t;

/* Load the PT_LOAD segments of an ELF64 image (already in memory) into the
 * current address space as user pages, and return the entry point address.
 * `maxsz` bounds the readable image (file offsets/sizes are validated against
 * it; pass ~0ull for a fully trusted in-kernel image). Returns 0 on a bad or
 * out-of-bounds image.
 *
 * out_lazy/max_lazy/out_nlazy (all optional — pass 0/0/0 to disable): a large
 * static BSS (e.g. a multi-MB interpreter arena) costs real time to eagerly
 * map+zero page by page at every spawn, almost all of which a typical run
 * never touches. For each writable, non-executable PT_LOAD segment, elf_load
 * eagerly maps+copies+zeroes only through the page containing the last
 * file-backed byte (as before — a partial page there mixes real data and
 * zero padding, so it can't be deferred); any further pages are PURE zero
 * and are reported as a range in `out_lazy` (up to `max_lazy` of them, count
 * in `*out_nlazy`) instead of being mapped at all. The caller is expected to
 * register each range as a demand-zero region (this file has no notion of a
 * process's VMA list); its own page-fault handler must map with the same
 * effective permissions elf_load would have applied (writable, non-exec) —
 * true of this codebase's app_fault_handle anon-mmap path. Passing NULL for
 * out_lazy (or max_lazy 0) reverts to fully-eager loading of every page,
 * which is what a caller with no lazy-fault machinery of its own must do. */
uint64_t elf_load(const void *image, uint64_t maxsz,
                   elf_lazy_range_t *out_lazy, int max_lazy, int *out_nlazy);

/* The on-disk byte extent of an ELF image (max p_offset+p_filesz over PT_LOAD,
 * capped at maxsz; 0 on a bad header). Lets measured-boot hash the exact image
 * bytes of an app even when it was spawned with maxsz = ~0 (trusted embedded). */
uint64_t elf_image_size(const void *image, uint64_t maxsz);

/* Load base for a position-independent executable (ET_DYN). Lives in the header
 * because the Linux ABI layer must report exactly this value as auxv AT_BASE --
 * a mismatch would make a libc self-relocate against the wrong bias. Just above
 * boot's low 1 GiB identity map, which is supervisor-only and so cannot hold
 * user pages at all. (M1465; hoisted M1940) */
#define ELF_DYN_BASE 0x40000000ull

/* Dynamic-linking support (M1954). A dynamically-linked image names its
 * interpreter in PT_INTERP; elf_interp_path reports that path (it does NOT
 * read the file -- elf.c has no VFS and stays host-testable), and elf_load_at
 * maps a PIE at a base the caller chooses, so the interpreter can be placed
 * clear of the executable it will load. */
int      elf_interp_path(const void *image, uint64_t maxsz, char *out, int max);
uint64_t elf_load_at(const void *image, uint64_t maxsz, uint64_t base);

/* Where the dynamic linker is mapped: clear of ELF_DYN_BASE (the executable)
 * and of the mmap window, so the three cannot collide. */
#define ELF_INTERP_BASE 0xB0000000ull   /* was 0x48000000, which is INSIDE the heap -- see the map in app.c (M1961) */

/* A loadable segment, reported to a caller that wants to MAP the image from
 * disk instead of having elf.c copy it out of a buffer (M1956). */
typedef struct { unsigned long vaddr, memsz, file_off, filesz; unsigned flags; } elf_pt_load_t;

/* List an image's PT_LOAD segments from its HEADER ALONE -- the ELF header plus
 * the program-header table, which live in the first page or two. Nothing else
 * of the file is read.
 *
 * This is what lets a 42 MB binary be loaded without a 42 MB kernel buffer:
 * app.c maps each segment file-backed and demand-pages it, instead of
 * elf_load() memcpy'ing from an image the caller had to slurp whole.
 *
 * Pure and fully bounds-checked, like the rest of elf.c, so it stays
 * host-testable. `hdrsz` bounds the buffer; `imgsz` is the FILE's real size and
 * is what segment offsets are validated against -- the two differ precisely
 * because the file is not in memory. Returns the number of segments written (<= max), or -1
 * if the header is malformed or the phdr table is not inside hdrsz.
 * *out_entry is the raw e_entry field and *out_bias the load bias to add to
 * it (and to every vaddr): ELF_DYN_BASE for an ET_DYN image, 0 for ET_EXEC.
 * The bias is decided here so validation and placement cannot disagree. */
int elf_pt_loads(const void *hdr, unsigned long hdrsz, unsigned long imgsz,
                 elf_pt_load_t *out, int max,
                 unsigned long *out_entry, unsigned long *out_bias,
                 unsigned long *out_phoff, unsigned *out_phent, unsigned *out_phnum);
