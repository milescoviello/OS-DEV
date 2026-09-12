/*
 * pmm.c — physical memory manager (a frame allocator).
 *
 * The job: track which 4 KiB physical "frames" of RAM are free vs used, and
 * hand them out one at a time. Everything above this (paging, the heap,
 * user processes) ultimately gets its memory from here.
 *
 * Design: a bitmap, one bit per frame (1 = used). Simple and compact —
 * 128 MiB of RAM needs a 4 KiB bitmap. We discover RAM from the Multiboot
 * memory map, mark all of it used, then free the regions the firmware says
 * are available, and finally re-reserve the frames our kernel and the bitmap
 * itself occupy.
 *
 * Everything here works in physical addresses, which are currently identical
 * to virtual addresses (the low 1 GiB is identity-mapped). M5 changes that.
 */
#include "pmm.h"
#include "multiboot.h"
#include "string.h"

/* End of the kernel image in memory, provided by the linker script. */
extern char kernel_end[];

static uint8_t  *bitmap;          /* one bit per frame */
static uint64_t  total_frames;
static uint64_t  used_frames;
static uint64_t  bitmap_bytes;
static uint64_t  next_hint;       /* where to start the next allocation scan */

/* Per-frame EXTRA-reference count for shared frames (M1089): 0 = the common
 * case (one mapping, free on the first pmm_free_frame); N>0 = the frame is
 * mapped N+1 times (a magic ring buffer's double-mapping, or a future COW page),
 * so the first N frees just decrement and only the last actually releases it.
 * 0-initialized, so untouched frames keep the exact prior behaviour — the guard
 * in pmm_free_frame is a no-op for them. */
/* 1<<18 -> 1<<22: covers 16 GiB of RAM instead of 1 GiB, for a 4 MiB array.
 *
 * Above the ceiling pmm_addref() SILENTLY DOES NOTHING and pmm_refcount()
 * reports 0, so a COW frame shared by a fork was freed the first time either
 * side unmapped it -- while the other was still using it. A real
 * use-after-free, and invisible until something both forks a lot and runs on
 * a machine with more than 1 GiB: `make` driving gcc driving cc1 on a 3 GiB
 * guest corrupted cc1's hash tables and faulted it on a garbage slot pointer,
 * naming nothing. (M1961) */
#define PMM_MAXREFS (1u << 22)    /* covers up to 16 GiB of RAM (4 MiB array) */
static uint8_t  pmm_refs[PMM_MAXREFS];

/* The bitmap is shared mutable state, and the allocator runs from more than one
 * thread: kmalloc/sbrk on whatever task needs memory, and pmm_free_frame from
 * the desktop task's app-reaper (vmm_destroy_address_space, interrupts ON). The
 * bit twiddle below is a non-atomic read-modify-write of a whole byte, so a
 * timer preempt mid-update could lose a concurrent alloc/free in the same byte
 * and double-hand-out a frame. Guard the mutators the same way kheap.c does:
 * save IF + cli on entry, restore on exit (nests correctly, cheap, short).
 * M1531: cli alone only ever stopped a LOCAL interrupt from reentering —
 * every core now allocates/frees frames (any core's task can kmalloc, which
 * can grow the heap, which calls here), so a real cross-core spinlock is
 * nested inside it too, same treatment as kheap.c's own irq_save/restore. */
static volatile int pmm_lock;
static inline uint64_t irq_save(void) {
    uint64_t fl;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
    while (__atomic_exchange_n(&pmm_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return fl;
}
static inline void irq_restore(uint64_t fl) {
    __atomic_store_n(&pmm_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(fl) : "memory", "cc");
}

static inline void bm_set(uint64_t f)   { bitmap[f >> 3] |=  (1u << (f & 7)); }
static inline void bm_clear(uint64_t f) { bitmap[f >> 3] &= ~(1u << (f & 7)); }
static inline int  bm_test(uint64_t f)  { return bitmap[f >> 3] & (1u << (f & 7)); }

static inline uint64_t align_up(uint64_t x, uint64_t a) {
    return (x + a - 1) & ~(a - 1);
}

static void mark_used(uint64_t frame) {
    if (frame < total_frames && !bm_test(frame)) {
        bm_set(frame);
        used_frames++;
    }
}

static void mark_free(uint64_t frame) {
    if (frame < total_frames && bm_test(frame)) {
        bm_clear(frame);
        used_frames--;
    }
}

void pmm_init(uint64_t mb_info_phys) {
    struct multiboot_info *mbi = (struct multiboot_info *)(uintptr_t)mb_info_phys;

    /* Pass 1: find the highest physical address present, to size the bitmap. */
    uint64_t highest = 0;
    if (mbi->flags & MULTIBOOT_FLAG_MMAP) {
        uint32_t cur = mbi->mmap_addr;
        uint32_t stop = mbi->mmap_addr + mbi->mmap_length;
        while (cur < stop) {
            struct multiboot_mmap_entry *e =
                (struct multiboot_mmap_entry *)(uintptr_t)cur;
            uint64_t top = e->addr + e->len;
            if (e->type == MULTIBOOT_MEM_AVAILABLE && top > highest)
                highest = top;
            cur += e->size + 4;
        }
    } else {
        /* Fallback: mem_upper is KiB above 1 MiB. */
        highest = 0x100000 + (uint64_t)mbi->mem_upper * 1024;
    }

    total_frames = highest / PAGE_SIZE;
    bitmap_bytes = align_up(total_frames / 8, PAGE_SIZE);

    /* Park the bitmap right after the kernel image. */
    bitmap = (uint8_t *)align_up((uintptr_t)kernel_end, PAGE_SIZE);

    /* Start with everything marked used... */
    memset(bitmap, 0xFF, bitmap_bytes);
    used_frames = total_frames;

    /* ...then free exactly the frames the firmware reports as available. */
    if (mbi->flags & MULTIBOOT_FLAG_MMAP) {
        uint32_t cur = mbi->mmap_addr;
        uint32_t stop = mbi->mmap_addr + mbi->mmap_length;
        while (cur < stop) {
            struct multiboot_mmap_entry *e =
                (struct multiboot_mmap_entry *)(uintptr_t)cur;
            if (e->type == MULTIBOOT_MEM_AVAILABLE) {
                uint64_t start = align_up(e->addr, PAGE_SIZE);
                uint64_t end   = e->addr + e->len;
                for (uint64_t a = start; a + PAGE_SIZE <= end; a += PAGE_SIZE)
                    mark_free(a / PAGE_SIZE);
            }
            cur += e->size + 4;
        }
    } else {
        for (uint64_t a = 0x100000; a + PAGE_SIZE <= highest; a += PAGE_SIZE)
            mark_free(a / PAGE_SIZE);
    }

    /* Re-reserve everything from address 0 through the end of our bitmap:
     * the low BIOS area, the kernel image, and the bitmap storage itself. */
    uint64_t reserved_top = (uint64_t)(uintptr_t)bitmap + bitmap_bytes;
    for (uint64_t a = 0; a < reserved_top; a += PAGE_SIZE)
        mark_used(a / PAGE_SIZE);

    next_hint = 0;
}

uint64_t pmm_alloc_frame(void) {
    uint64_t fl = irq_save();
    for (uint64_t i = next_hint; i < total_frames; i++) {
        if (!bm_test(i)) {
            bm_set(i);
            used_frames++;
            next_hint = i + 1;
            irq_restore(fl);
            return i * PAGE_SIZE;
        }
    }
    /* wrap around once */
    for (uint64_t i = 0; i < next_hint; i++) {
        if (!bm_test(i)) {
            bm_set(i);
            used_frames++;
            next_hint = i + 1;
            irq_restore(fl);
            return i * PAGE_SIZE;
        }
    }
    irq_restore(fl);
    return 0;   /* out of memory */
}

void pmm_free_frame(uint64_t phys) {
    uint64_t frame = phys / PAGE_SIZE;
    uint64_t fl = irq_save();
    if (frame < PMM_MAXREFS && pmm_refs[frame]) {   /* a shared frame: drop one reference, keep it allocated */
        pmm_refs[frame]--;
        irq_restore(fl);
        return;
    }
    mark_free(frame);
    if (frame < next_hint)
        next_hint = frame;
    irq_restore(fl);
}

/* Allocate `n` CONTIGUOUS free frames whose base frame is a multiple of `align`
 * frames (so the returned physical address is align*4096-aligned). Returns the
 * base physical address, or 0 if no such run is free. Backs 2 MiB hugepages
 * (n=512, align=512). Marks the whole run used in one shot. (M1155) */
uint64_t pmm_alloc_contiguous(uint64_t n, uint64_t align) {
    if (n == 0) return 0;
    if (align == 0) align = 1;
    uint64_t fl = irq_save();
    for (uint64_t base = align; base + n <= total_frames; base += align) {  /* base, a multiple of align (skip frame 0) */
        uint64_t k = 0;
        while (k < n && !bm_test(base + k)) k++;
        if (k == n) {                                  /* a fully-clear aligned run */
            for (k = 0; k < n; k++) bm_set(base + k);
            used_frames += n;
            irq_restore(fl);
            return base * PAGE_SIZE;
        }
    }
    irq_restore(fl);
    return 0;                                          /* no contiguous run available */
}

/* Free `n` contiguous frames from pmm_alloc_contiguous. These are single-owner
 * anon frames (hugepages are never COW-shared), so release them directly. */
void pmm_free_contiguous(uint64_t phys, uint64_t n) {
    uint64_t base = phys / PAGE_SIZE;
    uint64_t fl = irq_save();
    for (uint64_t k = 0; k < n; k++) mark_free(base + k);
    if (base < next_hint) next_hint = base;
    irq_restore(fl);
}

/* Add an extra reference to an already-allocated frame (so it survives the next
 * pmm_free_frame). For frames mapped more than once. M1089. */
void pmm_addref(uint64_t phys) {
    uint64_t frame = phys / PAGE_SIZE;
    if (frame >= PMM_MAXREFS) return;               /* >1 GiB: unref-counted (won't be double-mapped) */
    uint64_t fl = irq_save();
    pmm_refs[frame]++;
    irq_restore(fl);
}

/* The extra-reference count of a frame: 0 means single-owner (a normal
 * allocation), >0 means it is mapped more than once (a shared/ring-mirror
 * frame). Lets callers (e.g. madvise) avoid reclaiming a frame another mapping
 * still needs. */
int pmm_refcount(uint64_t phys) {
    uint64_t frame = phys / PAGE_SIZE;
    return frame < PMM_MAXREFS ? pmm_refs[frame] : 0;
}

/* Is this frame within the refcount array's coverage? COW sharing (fork) must
 * only share frames whose references can be counted — a frame beyond the array
 * (>1 GiB) would be double-freed at teardown. At the 256 MiB guest size every
 * allocatable frame qualifies; this is defensive insurance if -m ever grows. */
int pmm_refcountable(uint64_t phys) {
    return (phys / PAGE_SIZE) < PMM_MAXREFS;
}

uint64_t pmm_total_bytes(void) { return total_frames * PAGE_SIZE; }
uint64_t pmm_free_bytes(void)  { return (total_frames - used_frames) * PAGE_SIZE; }
