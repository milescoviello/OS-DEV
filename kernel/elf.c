/*
 * elf.c — load an ELF64 executable into the current address space.
 *
 * An ELF file starts with a header that, among other things, gives the entry
 * point and the location of the "program headers." Each program header of type
 * PT_LOAD describes a chunk that must be copied into memory at a given virtual
 * address: `filesz` bytes come from the file, and any extra up to `memsz` is
 * zero (that's the .bss). We allocate frames, map them as user pages, and copy.
 *
 * This is the bridge between "a blob of bytes" and "a running program."
 *
 * Inputs may be untrusted (an ELF loaded from disk), so every header field is
 * validated against the image size and the user address range before use.
 */
#include "elf.h"
#include "vmm.h"
#include "pmm.h"
#include "string.h"

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed)) Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed)) Elf64_Phdr;

#define PT_LOAD 1
#define PF_X 0x1   /* segment is executable */
#define PF_W 0x2   /* segment is writable   */
#define PF_R 0x4   /* segment is readable    */

/* Dynamic-executable (ET_DYN / PIE) support (M1465): a position-independent
 * executable is loaded at a non-zero base, so its absolute pointers need
 * R_X86_64_RELATIVE fix-ups from PT_DYNAMIC. A self-contained PIE (no external
 * symbols) has ONLY RELATIVE relocs — no GLOB_DAT/JUMP_SLOT — so that's all we
 * handle here. Kept in a separate path so the ET_EXEC loader (and the host
 * elf_test that #includes this file) stay byte-for-byte unchanged. */
#define ET_DYN            3
#define PT_DYNAMIC        2
#define DT_NULL           0
#define DT_RELA           7
#define DT_RELASZ         8
#define R_X86_64_RELATIVE 8

typedef struct { int64_t  d_tag; uint64_t d_val;            } Elf64_Dyn;
typedef struct { uint64_t r_offset, r_info; int64_t r_addend; } Elf64_Rela;

static inline uint64_t page_down(uint64_t x) { return x & ~(uint64_t)(PAGE_SIZE - 1); }
static inline uint64_t page_up(uint64_t x)   { return (x + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1); }

/* User segments must sit in the low range, below the user stack — this also
 * rejects any p_vaddr aimed at kernel/higher-half memory. */
#define ELF_VADDR_MAX 0x50000000ull

/* A validated PT_LOAD segment: file bytes [file_off, file_off+filesz) of the
 * image map to [vaddr, vaddr+memsz), the tail beyond filesz being zero (.bss). */
typedef struct { uint64_t vaddr, memsz, file_off, filesz; uint32_t flags; } elf_seg_t;

/* Validate the ELF header and locate the program-header table. On success,
 * fills the phoff/phnum/phentsize/entry out-params and returns 1; else 0. Reads only
 * the fixed header, fully bounds-checked against maxsz — and guarantees the
 * whole program-header table lies within the image, so a later per-header read
 * of sizeof(Elf64_Phdr) bytes at any index can't run past the buffer. Pure: no
 * memory is mapped or written, which is what lets it be fuzzed on the host. */
static int elf_check_header(const void *image, uint64_t maxsz,
                            uint64_t *phoff, uint16_t *phnum,
                            uint16_t *phentsize, uint64_t *entry) {
    const Elf64_Ehdr *eh = image;
    if (maxsz < sizeof(Elf64_Ehdr)) return 0;
    if (eh->e_ident[0] != 0x7F || eh->e_ident[1] != 'E' ||
        eh->e_ident[2] != 'L'  || eh->e_ident[3] != 'F')
        return 0;
    /* stride must hold a full header, and the table must lie within the image */
    if (eh->e_phentsize < sizeof(Elf64_Phdr)) return 0;
    if (eh->e_phoff > maxsz ||
        (uint64_t)eh->e_phnum * eh->e_phentsize > maxsz - eh->e_phoff)
        return 0;
    *phoff = eh->e_phoff; *phnum = eh->e_phnum;
    *phentsize = eh->e_phentsize; *entry = eh->e_entry;
    return 1;
}

/* Validate program header #i (the header table must already be validated by
 * elf_check_header). Returns 1 = loadable, *seg filled; 0 = skip (not PT_LOAD);
 * -1 = malformed, reject the whole image. Checks the segment against the image
 * bounds and the user address range. Pure: reads only header bytes. */
static int elf_check_phdr(const void *image, uint64_t maxsz, uint64_t phoff,
                          uint16_t phentsize, uint16_t i, elf_seg_t *seg) {
    const Elf64_Phdr *ph = (const Elf64_Phdr *)
        ((const uint8_t *)image + phoff + (uint64_t)i * phentsize);
    if (ph->p_type != PT_LOAD) return 0;
    if (ph->p_offset > maxsz || ph->p_filesz > maxsz - ph->p_offset) return -1;
    if (ph->p_memsz < ph->p_filesz) return -1;
    if (ph->p_vaddr < PAGE_SIZE) return -1;                         /* no null page */
    if (ph->p_memsz > ELF_VADDR_MAX || ph->p_vaddr > ELF_VADDR_MAX - ph->p_memsz)
        return -1;                                                  /* fits below the stack, no overflow */
    seg->vaddr = ph->p_vaddr; seg->memsz = ph->p_memsz;
    seg->file_off = ph->p_offset; seg->filesz = ph->p_filesz;
    seg->flags = ph->p_flags;
    return 1;
}

/* The on-disk byte extent of the ELF image: max(p_offset + p_filesz) over its
 * PT_LOAD segments (and at least through the program-header table), capped at
 * maxsz. A deterministic identity for the file's loadable content — used by
 * measured-boot (M1096) to hash an app's image even when the caller passed
 * maxsz = ~0 (a trusted embedded ELF). Returns 0 on an invalid header. */
uint64_t elf_image_size(const void *image, uint64_t maxsz) {
    uint64_t phoff, entry; uint16_t phnum, phentsize;
    if (!elf_check_header(image, maxsz, &phoff, &phnum, &phentsize, &entry)) return 0;
    uint64_t hi = phoff + (uint64_t)phnum * phentsize;   /* through the phdr table at minimum */
    for (uint16_t i = 0; i < phnum; i++) {
        elf_seg_t s;
        if (elf_check_phdr(image, maxsz, phoff, phentsize, i, &s) != 1) continue;
        uint64_t end = s.file_off + s.filesz;
        if (end > hi) hi = end;
    }
    return hi > maxsz ? maxsz : hi;
}

/* Load a position-independent executable (ET_DYN): map every PT_LOAD at
 * ELF_DYN_BASE + p_vaddr, apply R_X86_64_RELATIVE relocations from PT_DYNAMIC,
 * then return the based entry. Separate from elf_load so the ET_EXEC path stays
 * unchanged. Every field is bounds-checked against the loaded span so a corrupt
 * dynamic section can never write outside the image's mapped pages (M1465). */
static uint64_t elf_load_dyn(const void *image, uint64_t maxsz) {
    uint64_t phoff, entry; uint16_t phnum, phentsize;
    if (!elf_check_header(image, maxsz, &phoff, &phnum, &phentsize, &entry)) return 0;
    const uint64_t base = ELF_DYN_BASE;
    uint64_t max_eff = 0;                                 /* highest mapped address (base + vaddr + memsz) */

    for (uint16_t i = 0; i < phnum; i++) {                /* map + copy each PT_LOAD, writable for now */
        const Elf64_Phdr *ph = (const Elf64_Phdr *)((const uint8_t *)image + phoff + (uint64_t)i * phentsize);
        if (ph->p_type != PT_LOAD) continue;
        if (ph->p_offset > maxsz || ph->p_filesz > maxsz - ph->p_offset) return 0;
        if (ph->p_memsz < ph->p_filesz) return 0;
        uint64_t va = base + ph->p_vaddr;                 /* effective load address */
        if (va < PAGE_SIZE || ph->p_memsz > ELF_VADDR_MAX || va > ELF_VADDR_MAX - ph->p_memsz) return 0;
        uint64_t start = page_down(va), end = page_up(va + ph->p_memsz);
        for (uint64_t v = start; v < end; v += PAGE_SIZE) {
            if (!vmm_translate(v)) {
                uint64_t frame = pmm_alloc_frame();
                if (!frame) return 0;
                if (vmm_map(v, frame, PTE_WRITABLE | PTE_USER) != 0) { pmm_free_frame(frame); return 0; }
                memset((void *)v, 0, PAGE_SIZE);
            }
        }
        memcpy((void *)va, (const uint8_t *)image + ph->p_offset, ph->p_filesz);
        if (va + ph->p_memsz > max_eff) max_eff = va + ph->p_memsz;
    }
    if (max_eff <= base) return 0;                        /* no loadable segments */
    uint64_t span = max_eff - base;                       /* valid un-based offset range [0, span) */

    for (uint16_t i = 0; i < phnum; i++) {                /* R_X86_64_RELATIVE fix-ups from PT_DYNAMIC */
        const Elf64_Phdr *ph = (const Elf64_Phdr *)((const uint8_t *)image + phoff + (uint64_t)i * phentsize);
        if (ph->p_type != PT_DYNAMIC) continue;
        if (ph->p_vaddr >= span) break;                   /* .dynamic must lie within the loaded image */
        const Elf64_Dyn *dyn = (const Elf64_Dyn *)(base + ph->p_vaddr);
        uint64_t rela = 0, relasz = 0, dsz = ph->p_memsz;
        if (dsz > span - ph->p_vaddr) dsz = span - ph->p_vaddr;
        for (uint64_t o = 0; o + sizeof(Elf64_Dyn) <= dsz; o += sizeof(Elf64_Dyn)) {
            const Elf64_Dyn *d = (const Elf64_Dyn *)((const uint8_t *)dyn + o);
            if (d->d_tag == DT_NULL) break;
            else if (d->d_tag == DT_RELA)   rela   = d->d_val;
            else if (d->d_tag == DT_RELASZ) relasz = d->d_val;
        }
        if (rela && rela < span) {
            for (uint64_t o = 0; o + sizeof(Elf64_Rela) <= relasz; o += sizeof(Elf64_Rela)) {
                const Elf64_Rela *r = (const Elf64_Rela *)(base + rela + o);
                if ((uint32_t)r->r_info == R_X86_64_RELATIVE &&
                    r->r_offset <= span - sizeof(uint64_t))               /* in-image, no overflow write */
                    *(uint64_t *)(base + r->r_offset) = base + (uint64_t)r->r_addend;
            }
        }
        break;
    }

    for (uint16_t i = 0; i < phnum; i++) {                /* re-protect W^X now copy + relocs are done */
        const Elf64_Phdr *ph = (const Elf64_Phdr *)((const uint8_t *)image + phoff + (uint64_t)i * phentsize);
        if (ph->p_type != PT_LOAD) continue;
        uint64_t va = base + ph->p_vaddr;
        uint64_t start = page_down(va), end = page_up(va + ph->p_memsz);
        uint64_t prot = PTE_USER;
        if (ph->p_flags & PF_W)    prot |= PTE_WRITABLE;
        if (!(ph->p_flags & PF_X)) prot |= PTE_NX;
        for (uint64_t v = start; v < end; v += PAGE_SIZE) {
            uint64_t phys = vmm_translate(v);
            if (phys) vmm_map(v, phys & ~(uint64_t)(PAGE_SIZE - 1), prot);
        }
    }
    return base + entry;
}

uint64_t elf_load(const void *image, uint64_t maxsz,
                   elf_lazy_range_t *out_lazy, int max_lazy, int *out_nlazy) {
    uint64_t phoff, entry; uint16_t phnum, phentsize;
    if (out_nlazy) *out_nlazy = 0;
    if (!elf_check_header(image, maxsz, &phoff, &phnum, &phentsize, &entry))
        return 0;
    if (((const Elf64_Ehdr *)image)->e_type == ET_DYN)    /* a PIE: separate base-relative + relocating path (M1465) */
        return elf_load_dyn(image, maxsz);

    for (uint16_t i = 0; i < phnum; i++) {
        elf_seg_t s;
        int r = elf_check_phdr(image, maxsz, phoff, phentsize, i, &s);
        if (r == 0) continue;      /* not a loadable segment */
        if (r < 0)  return 0;      /* malformed segment: reject the image */

        /* Map every page this segment touches as a user page (once), writable
         * for now so we can copy/zero into it. Pages entirely past the last
         * file-backed byte are pure zero (.bss) and, for a writable/non-exec
         * segment when the caller wants it, get deferred to out_lazy instead
         * of being mapped here — see elf_load's own doc comment in elf.h. The
         * boundary page containing s.vaddr+s.filesz (if not page-aligned)
         * mixes real data and zero padding, so it always stays eager. */
        uint64_t start = page_down(s.vaddr);
        uint64_t end   = page_up(s.vaddr + s.memsz);
        uint64_t map_end = end;
        if (out_lazy && out_nlazy && max_lazy > 0 && !(s.flags & PF_X)) {
            uint64_t lazy_start = page_up(s.vaddr + s.filesz);
            if (lazy_start < end && *out_nlazy < max_lazy) {
                out_lazy[*out_nlazy].start = lazy_start;
                out_lazy[*out_nlazy].len   = end - lazy_start;
                (*out_nlazy)++;
                map_end = lazy_start;
            }
        }
        for (uint64_t v = start; v < map_end; v += PAGE_SIZE) {
            if (!vmm_translate(v)) {
                uint64_t frame = pmm_alloc_frame();
                if (!frame) return 0;              /* out of memory: fail cleanly */
                if (vmm_map(v, frame, PTE_WRITABLE | PTE_USER) != 0) {
                    pmm_free_frame(frame);         /* OOM building a page table: don't memset an unmapped page */
                    return 0;
                }
                memset((void *)v, 0, PAGE_SIZE);   /* zero -> covers .bss */
            }
        }

        /* Copy the file-backed part of the segment into place. */
        memcpy((void *)s.vaddr, (const uint8_t *)image + s.file_off, s.filesz);

        /* Re-protect with the segment's real permissions now the copy is done
         * (W^X): code becomes read-only + executable, data writable + NX. The
         * linker emits .text/.rodata page-aligned away from .data/.bss, so each
         * page belongs to exactly one segment and these flags never conflict.
         * Bounded to map_end, not end: a deferred page was never mapped, so
         * vmm_translate would report it not-present anyway (the `if (phys)`
         * below already skips it) — stopping the loop early just avoids
         * walking the page tables of however many pages were deferred. */
        uint64_t prot = PTE_USER;
        if (s.flags & PF_W)    prot |= PTE_WRITABLE;
        if (!(s.flags & PF_X)) prot |= PTE_NX;
        for (uint64_t v = start; v < map_end; v += PAGE_SIZE) {
            uint64_t phys = vmm_translate(v);
            if (phys) vmm_map(v, phys & ~(uint64_t)(PAGE_SIZE - 1), prot);
        }
    }

    return entry;
}
