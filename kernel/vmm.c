/*
 * vmm.c — walk and edit the x86_64 page tables.
 *
 * A 48-bit virtual address is sliced into four 9-bit indices plus a 12-bit
 * offset:
 *
 *   [ 47 .. 39 | 38 .. 30 | 29 .. 21 | 20 .. 12 | 11 .. 0 ]
 *       PML4       PDPT        PD         PT       offset
 *
 * To map a page we follow those indices from the PML4 (in CR3) down, creating
 * any missing intermediate table along the way, and write the final entry.
 *
 * We reach the tables themselves through the low 1 GiB identity map: every
 * table frame comes from the PMM, which only returns low physical RAM, so its
 * physical address doubles as a usable virtual address. (Once we have the
 * HHDM we could use that instead; identity is simplest while it covers RAM.)
 */
#include "smp.h"    /* TLB shootdown IPI (M1963) */
#include "vmm.h"
#include "pmm.h"
#include "string.h"
#include "console.h"   /* kprintf — for the W^X self-check report */

/* app.c's demand-pager: resolves a not-present address that falls inside the
 * CURRENT app's registered VMA list (mmap, or elf_load's deferred .bss —
 * see vmm_user_ok below) by allocating+zeroing+mapping it, exactly as a real
 * ring-3 #PF would. A forward declaration (not "app.h") keeps vmm.c from
 * gaining a real dependency on app.c's types for one narrow call. */
extern int app_fault_handle(uint64_t cr2, uint64_t err);

#define PML4_IDX(v) (((v) >> 39) & 0x1FF)
#define PDPT_IDX(v) (((v) >> 30) & 0x1FF)
#define PD_IDX(v)   (((v) >> 21) & 0x1FF)
#define PT_IDX(v)   (((v) >> 12) & 0x1FF)

#define ADDR_MASK   0x000FFFFFFFFFF000ull   /* frame address bits of an entry */

static uint64_t kernel_pml4;   /* the kernel's own PML4 — empty user region */

/* M1531: every page-table mutator below used to run with NO locking at all —
 * safe only because a single core ever executed kernel code. `next_table`'s
 * "if not present, allocate + write" is a classic check-then-act: two
 * concurrent callers that both see an intermediate table as not-present (e.g.
 * two cores' kstack_alloc calls landing in the same not-yet-built PD/PT range
 * of the shared KSTACK_WIN region) would both allocate a frame and race to
 * write the SAME slot — the loser's frame is silently orphaned AND, worse,
 * any leaf mapping already placed under the loser's now-discarded table
 * becomes unreachable, a real corruption, not just a leak. A plain `cli`
 * alone (this file never even had that) only ever stopped a LOCAL interrupt
 * from reentering; it says nothing about a second core. One spinlock, nested
 * inside a local cli exactly like kheap.c/pmm.c's own irq_save/restore,
 * brackets every function that walks-and-writes the shared hierarchy. */
static volatile int vmm_lock;
static inline uint64_t vmm_lock_take(void) {
    uint64_t fl;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
    while (__atomic_exchange_n(&vmm_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return fl;
}
static inline void vmm_lock_give(uint64_t fl) {
    __atomic_store_n(&vmm_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(fl) : "memory", "cc");
}

/* Reach a page-table frame by physical address. The boot trampoline only
 * identity-maps the low 1 GiB, so on real hardware with >1 GiB RAM a page-table
 * frame (or a walk into a high region) can sit above that and fault. The HHDM
 * direct-maps ALL physical RAM, so once it's built we reach any frame through it.
 * During the HHDM's OWN construction (early vmm_init) the HHDM isn't up yet, so we
 * fall back to the low identity map — pmm hands out low frames first, so the
 * handful of tables the build itself allocates stay under 1 GiB. (M1875) */
static int g_hhdm_ready;
static uint64_t *phys_to_table(uint64_t phys) {
    return (uint64_t *)(uintptr_t)(g_hhdm_ready ? HHDM_BASE + phys : phys);
}

static uint64_t read_cr3(void) {
    uint64_t v;
    __asm__ volatile("mov %%cr3, %0" : "=r"(v));
    return v;
}

/* Drop this core's cached translation for one page. Exposed because the page
 * fault handler needs it for a SPURIOUS fault -- an access the PTE already
 * permits, faulting because a stale TLB entry has not caught up with a PTE that
 * was made more permissive. x86 allows exactly that, and the only correct
 * response is to invalidate and retry. (M2005) */
void vmm_invlpg_one(uint64_t virt) {
    __asm__ volatile("invlpg (%0)" : : "r"(virt) : "memory");
}
static void invlpg(uint64_t virt) {
    __asm__ volatile("invlpg (%0)" : : "r"(virt) : "memory");
}

/* Return the next-level table, allocating + zeroing it if not present.
 * Returns NULL if the PMM is out of frames: the alternative — mapping the
 * frame-0 sentinel as a PRESENT page table — would silently alias whatever
 * lives at physical 0 (the IVT / boot stubs) as live page tables. Callers must
 * propagate the failure rather than walk into a half-built mapping. */
static uint64_t *next_table(uint64_t *table, uint64_t idx, uint64_t flags) {
    if (!(table[idx] & PTE_PRESENT)) {
        uint64_t frame = pmm_alloc_frame();
        if (!frame) return 0;            /* OOM — do not map frame 0 */
        memset(phys_to_table(frame), 0, PAGE_SIZE);
        /* Intermediate entries must allow the most permissive access any leaf
         * under them needs — so propagate USER, always allow WRITABLE. */
        table[idx] = frame | PTE_PRESENT | PTE_WRITABLE | (flags & PTE_USER);
    } else if (flags & PTE_USER) {
        /* The table already exists (e.g. boot's supervisor-only pml4[0]). A
         * user mapping underneath it is only reachable if USER is set at EVERY
         * level, so upgrade this entry. This never weakens kernel pages: their
         * leaf/huge entries still lack USER, and the effective permission is
         * the AND across all levels. */
        table[idx] |= PTE_USER;
    }
    return phys_to_table(table[idx] & ADDR_MASK);
}

/* Lock-free core of do_map: the caller ALREADY holds vmm_lock. Split out so a
 * caller that must hold the lock across MANY mappings -- vmm_fork_cow's chunked
 * walk -- can map without self-deadlocking. vmm_lock is a plain, NON-RECURSIVE
 * test-and-set spinlock, so a second acquisition on the same core spins against
 * itself for ever. (M2045) */
static int do_map_nl(uint64_t pml4_phys, uint64_t virt, uint64_t phys, uint64_t flags) {
    uint64_t *pml4 = phys_to_table(pml4_phys);
    uint64_t *pdpt = next_table(pml4, PML4_IDX(virt), flags);
    uint64_t *pd   = pdpt ? next_table(pdpt, PDPT_IDX(virt), flags) : 0;
    /* If a 2 MiB huge page already covers this VA, split it into 512 x 4 KiB
     * first, so we can set one fine-grained PTE (e.g. a UC MMIO page for HPET /
     * LAPIC) without clobbering the rest of the region. This is why MMIO mapping
     * faulted on >1 GiB machines: the HHDM huge-maps [0,total) including the MMIO
     * hole, and do_map used to walk INTO that huge page as if it were a PT. (M1875) */
    if (pd && (pd[PD_IDX(virt)] & (PTE_PRESENT | PTE_HUGE)) == (PTE_PRESENT | PTE_HUGE)) {
        uint64_t e    = pd[PD_IDX(virt)];
        uint64_t base = e & ~0x1FFFFFull;
        uint64_t lf   = e & (PTE_WRITABLE | PTE_USER | PTE_NX | PTE_PCD | PTE_PWT);   /* carry leaf perms + cache attrs, drop HUGE (M1884) */
        uint64_t ptphys = pmm_alloc_frame();
        if (!ptphys) return -1;
        uint64_t *npt = phys_to_table(ptphys);
        for (int i = 0; i < 512; i++)
            npt[i] = (base + (uint64_t)i * PAGE_SIZE) | PTE_PRESENT | lf;
        pd[PD_IDX(virt)] = ptphys | PTE_PRESENT | PTE_WRITABLE | (e & PTE_USER);
        uint64_t hbase = virt & ~0x1FFFFFull;
        for (uint64_t off = 0; off < 0x200000; off += PAGE_SIZE) invlpg(hbase + off);
    }
    uint64_t *pt   = pd   ? next_table(pd,   PD_IDX(virt),   flags) : 0;
    if (!pt) return -1;

    /* x86 TLBs never cache a not-present translation, so populating a fresh
     * (previously not-present) PTE can never leave a stale entry behind — only
     * overwriting an ALREADY-present PTE (a permission change or a remap onto a
     * live translation) can, and still gets flushed below. This matters: a new
     * address space's whole user region starts not-present, so every page an
     * app's spawn maps (ELF segments, the user stack, a task's kernel stack)
     * hits the skip path. vmm_unmap already invlpg's on the transition to
     * not-present, so a later remap of the same VA correctly sees "wasn't
     * present" with no staleness risk. */
    int was_present = (pt[PT_IDX(virt)] & PTE_PRESENT) != 0;
    pt[PT_IDX(virt)] = (phys & ADDR_MASK) | PTE_PRESENT | flags;
    if (was_present) invlpg(virt);
    return 0;
}

static int do_map(uint64_t pml4_phys, uint64_t virt, uint64_t phys, uint64_t flags) {
    uint64_t f = vmm_lock_take();
    int rc = do_map_nl(pml4_phys, virt, phys, flags);
    vmm_lock_give(f);
    return rc;
}

/* vmm_map_to for a caller that already holds vmm_lock. Never call it without:
 * do_map_nl assumes the exclusive access every other caller gets from do_map's
 * wrapper. Static -- vmm_fork_cow is the only walker of more than one mapping
 * at a time. (M2045) */
static int vmm_map_to_nl(uint64_t pml4_phys, uint64_t virt, uint64_t phys, uint64_t flags) {
    return do_map_nl(pml4_phys & ADDR_MASK, virt, phys, flags);
}

int vmm_map(uint64_t virt, uint64_t phys, uint64_t flags) {
    return do_map(read_cr3() & ADDR_MASK, virt, phys, flags);
}

int vmm_map_to(uint64_t pml4_phys, uint64_t virt, uint64_t phys, uint64_t flags) {
    return do_map(pml4_phys & ADDR_MASK, virt, phys, flags);
}

/*
 * Build a new address space. The new PML4 shares everything the kernel needs:
 *  - the entire higher half (PML4[256..511]): HHDM, kernel heap, etc.
 *  - the kernel's low mappings (identity RAM + device MMIO) by copying the
 *    boot PML4[0]'s PDPT entries into a *new* PDPT.
 * The new PDPT is private, so per-process user mappings added under PML4[0]
 * (e.g. at 0x40000000) don't leak between address spaces.
 */
uint64_t vmm_create_address_space(void) {
    /* Always derive from the kernel PML4, NOT the current one: a caller running
     * in some process's address space has user mappings in its low region that
     * must NOT leak into the new space. The kernel PML4's user region is empty,
     * while its kernel/heap/MMIO mappings (shared, by pointer) stay live. */
    uint64_t *bpml4 = phys_to_table(kernel_pml4);

    uint64_t newp = pmm_alloc_frame();
    if (!newp) return 0;                   /* OOM */
    uint64_t *npml4 = phys_to_table(newp);
    memset(npml4, 0, PAGE_SIZE);

    for (int i = 256; i < 512; i++)        /* share the higher half */
        npml4[i] = bpml4[i];

    uint64_t *bpdpt = phys_to_table(bpml4[0] & ADDR_MASK);
    uint64_t newpdpt = pmm_alloc_frame();
    if (!newpdpt) { pmm_free_frame(newp); return 0; }   /* OOM — undo the PML4 */
    uint64_t *npdpt = phys_to_table(newpdpt);
    for (int i = 0; i < 512; i++)          /* share the kernel's MMIO/device PDs */
        npdpt[i] = bpdpt[i];
    /* ...but NOT the low 1 GiB (M1969).
     *
     * PDPT[0] is the boot identity map: 512 supervisor 2 MiB pages covering
     * physical 0..1 GiB. Inheriting it into every address space is what made
     * the first gigabyte permanently unavailable to user programs -- the
     * entries are present and supervisor-only, so no user page could be mapped
     * underneath them. That was survivable while everything we ran was
     * position-independent and could be relocated to 0x40000000. A non-PIE
     * ET_EXEC binary is linked at a fixed low address and cannot move: Claude
     * Code is a 214 MB image at 0x200000.
     *
     * Dropping it is only safe because the kernel no longer LIVES there: since
     * M1968 it is linked at 0xFFFFFFFF80100000, reached through PML4[511],
     * which IS shared. Physical memory is reached through the HHDM
     * (PML4[256..511], also shared). The kernel address space keeps its own
     * identity map, so boot-time code that still uses low physical addresses
     * directly is unaffected -- it runs before any process exists. */
    npdpt[0] = 0;

    npml4[0] = newpdpt | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
    return newp;
}

/*
 * Tear down an address space built by vmm_create_address_space: free the app's
 * private user mappings (frames + their page tables) and the private PML4/PDPT
 * pages, leaving the shared kernel identity map and the higher half intact.
 *
 * Safety rests on a property of vmm_create_address_space + next_table:
 * vmm_create copies boot's PDPT entries verbatim, and next_table only ever
 * *writes* a PDPT/PD slot when it was not-present (allocating a fresh table).
 * So a PDPT entry that DIFFERS from boot's is provably a private, app-allocated
 * PD — the shared kernel PDs are byte-identical copies and are skipped. User
 * mappings all live above boot's low identity map (user.ld bases apps at 1 GiB,
 * stack at 0x50000000), i.e. under PDPT slots boot leaves empty, so the whole
 * user footprint is reclaimed. Only call on a NON-ACTIVE space (asserted via the
 * CR3 guard below); the desktop reaper that calls this runs in the kernel PML4.
 */
void vmm_destroy_address_space(uint64_t cr3) {
    cr3 &= ADDR_MASK;
    if (!cr3 || cr3 == kernel_pml4) return;          /* never the kernel's own */
    if (cr3 == (read_cr3() & ADDR_MASK)) return;     /* never the active space  */

    uint64_t *pml4  = phys_to_table(cr3);
    uint64_t *bpml4 = phys_to_table(kernel_pml4);

    /* The user/private region lives only under PML4[0]; [1..255] are zero and
     * [256..511] are the shared higher half — never touched. */
    uint64_t pml4e = pml4[0];
    if ((pml4e & PTE_PRESENT) && (pml4e & ADDR_MASK) != (bpml4[0] & ADDR_MASK)) {
        uint64_t pdpt_phys = pml4e & ADDR_MASK;
        uint64_t *pdpt  = phys_to_table(pdpt_phys);
        uint64_t *bpdpt = phys_to_table(bpml4[0] & ADDR_MASK);
        for (int i = 0; i < 512; i++) {
            if (!(pdpt[i] & PTE_PRESENT)) continue;
            if ((pdpt[i] & ADDR_MASK) == (bpdpt[i] & ADDR_MASK)) continue;  /* shared boot PD */
            if (pdpt[i] & PTE_HUGE) continue;                              /* 1 GiB page (n/a for user) */
            uint64_t *pd = phys_to_table(pdpt[i] & ADDR_MASK);
            for (int j = 0; j < 512; j++) {
                if (!(pd[j] & PTE_PRESENT)) continue;
                if (pd[j] & PTE_HUGE) { pmm_free_contiguous(pd[j] & ~0x1FFFFFull, 512); continue; }  /* user 2 MiB hugepage (M1155) */
                uint64_t *pt = phys_to_table(pd[j] & ADDR_MASK);
                for (int k = 0; k < 512; k++)
                    if (pt[k] & PTE_PRESENT) pmm_free_frame(pt[k] & ADDR_MASK);  /* user frame */
                pmm_free_frame(pd[j] & ADDR_MASK);                         /* the PT page */
            }
            pmm_free_frame(pdpt[i] & ADDR_MASK);                          /* the PD page */
        }
        pmm_free_frame(pdpt_phys);                                       /* the private PDPT page */
    }
    pmm_free_frame(cr3);                                                 /* the PML4 page */
}

/*
 * Copy-on-write clone the CURRENT (parent) address space into child_cr3, for
 * fork() (M1116). Walks the same private PML4[0] subtree as the teardown/wss
 * walks (a PDPT slot differing from boot's is app-private). For each present
 * user 4 KiB leaf:
 *   - a WRITABLE page becomes read-only + PTE_COW in BOTH parent and child, and
 *     the shared frame gets one extra reference (pmm_addref) — a later write in
 *     either process faults and copies (app_fault_handle).
 *   - a read-only page is shared as-is (one extra ref), still RO.
 * Page-TABLE pages are never shared: vmm_map_to builds fresh tables in the child
 * (so each address space frees its own hierarchy at teardown, no double-free).
 * Frames outside the refcount array (>1 GiB; impossible at 256 MiB) are eagerly
 * copied instead, so they're never double-freed. The parent's TLB is flushed
 * (CR3 reload) because we write-protected its live pages. Returns 0, or -1.
 */
/* FORK COPIED ONLY THE FIRST 512 GiB (M2031).
 *
 * This walked pml4[0] and nothing else, so a fork() duplicated only the bottom
 * 512 GiB of the address space. MMAP_TOP is 32 TiB -- PML4 entries 0 through 63
 * -- and mmap hands out addresses across that whole range, so any mapping above
 * half a terabyte was simply absent from the child.
 *
 * It is not absent in a way that faults, which is what made it so hard to see:
 * the child still has the VMA (app_fork_common copies the table), so the
 * address is valid and readable -- it just faults in a FRESH ZERO PAGE. The
 * child reads zeros where the parent wrote data, and every check passes.
 *
 * Claude Code died of this on every subprocess it spawned. Bun's heap sits
 * around 5 TiB, so the child's argv and path pointers were readable, correctly
 * aligned, in a real VMA, and pointed at zeros -- which is an empty string. It
 * called execve("") , got ENOENT, and exited 127, nine times in a row, with no
 * error anywhere naming a pointer or a page.
 *
 * Walk every user PML4 slot (the low half; the kernel's own entries are shared
 * and identified by matching the master table), and carry the slot index into
 * the virtual address. */
int vmm_fork_cow(uint64_t child_cr3) {
    /* REMEMBER THE CALLER'S INTERRUPT STATE (M2045). The chunked walk below
     * re-enables interrupts between page tables -- that is the whole point, so
     * this core can ACK a TLB shootdown during an RSS-proportional fork -- but
     * fork is entered from the syscall gate with IF=0 and everything after this
     * call in app_fork_common (publishing the child, handing it its task) is
     * written for IF=0. Returning with interrupts on would silently hand the
     * rest of fork a different set of rules. Saved here, restored before every
     * return. */
    uint64_t entry_fl;
    __asm__ volatile("pushfq; pop %0" : "=r"(entry_fl));
    uint64_t cr3 = read_cr3() & ADDR_MASK;
    uint64_t *pml4  = phys_to_table(cr3);
    uint64_t *bpml4 = phys_to_table(kernel_pml4);
    int rc = 0;
    for (int top = 0; top < 256 && rc == 0; top++) {          /* user half only */
    uint64_t pml4e = pml4[top];
    if (!(pml4e & PTE_PRESENT)) continue;
    if ((bpml4[top] & PTE_PRESENT) && (pml4e & ADDR_MASK) == (bpml4[top] & ADDR_MASK)) continue;  /* shared with the kernel */
    uint64_t *pdpt  = phys_to_table(pml4e & ADDR_MASK);
    uint64_t *bpdpt = (bpml4[top] & PTE_PRESENT) ? phys_to_table(bpml4[top] & ADDR_MASK) : 0;
    for (int i = 0; i < 512 && rc == 0; i++) {
        if (!(pdpt[i] & PTE_PRESENT)) continue;
        if (bpdpt && (bpdpt[i] & PTE_PRESENT) &&
            (pdpt[i] & ADDR_MASK) == (bpdpt[i] & ADDR_MASK)) continue;   /* shared boot PD */
        if (pdpt[i] & PTE_HUGE) continue;
        uint64_t *pd = phys_to_table(pdpt[i] & ADDR_MASK);
        for (int j = 0; j < 512 && rc == 0; j++) {
                /* Cheap UNLOCKED peek. An intermediate table, once created, is
                 * never torn down while its address space is ACTIVE: munmap and
                 * vmm_unmap free only leaf DATA frames, and only
                 * vmm_destroy_address_space frees a PD/PT, for a space nobody
                 * is running. So `pd` cannot dangle under this walk. What CAN
                 * change is the CONTENT of pd[j] -- a huge-page split -- which
                 * is why the real work below re-reads it under the lock. (M2045) */
                if (!(pd[j] & PTE_PRESENT) || (pd[j] & PTE_HUGE)) continue;

                /* HOLD vmm_lock FOR ONE PAGE TABLE AT A TIME (M2045).
                 *
                 * This walk read and rewrote pt[k] with NO LOCK, while every
                 * other mutator of the same hierarchy -- vmm_map_to,
                 * vmm_protect, vmm_unmap, vmm_set_raw -- takes vmm_lock, which
                 * exists (per its own comment) precisely to stop two cores
                 * walking-and-writing it at once. A sibling thread calling
                 * mmap/mprotect/munmap raced this, and fork's write, built from
                 * the stale snapshot `e`, could silently clobber it.
                 *
                 * CHUNKED rather than held for the whole walk, because vmm_lock
                 * is GLOBAL: holding it across an RSS-proportional fork would
                 * freeze memory management for every process on every core.
                 * One PT bounds any waiter to <=512 leaves.
                 *
                 * The sti is not incidental either. Nothing upstream of fork
                 * re-enables interrupts, so this walk ran with IF=0 for its
                 * whole length -- during which this core cannot ACK another
                 * core's TLB shootdown. That is what made the bounded ack wait
                 * time out in practice, observed once per run, leaking a frame
                 * rather than freeing it. Safe only because it happens strictly
                 * AFTER vmm_lock_give: nothing is held across the window. */
                uint64_t lf = vmm_lock_take();
                uint64_t pde = pd[j];                      /* re-validate under the lock */
                if (!(pde & PTE_PRESENT) || (pde & PTE_HUGE)) { vmm_lock_give(lf); continue; }
                uint64_t *pt = phys_to_table(pde & ADDR_MASK);
            for (int k = 0; k < 512; k++) {
                uint64_t e = pt[k];
                if (!(e & PTE_PRESENT) || !(e & PTE_USER)) continue;
                uint64_t phys = e & ADDR_MASK;
                uint64_t va = ((uint64_t)top << 39) | ((uint64_t)i << 30) |
                              ((uint64_t)j << 21) | ((uint64_t)k << 12);   /* incl. the PML4 slot (M2031) */
                if (!pmm_refcountable(phys)) {            /* can't refcount -> eager private copy */
                    uint64_t nf = pmm_alloc_frame();
                    if (!nf) { rc = -1; break; }
                    uint8_t *s = hhdm(phys), *d = hhdm(nf);
                    for (int b = 0; b < PAGE_SIZE; b++) d[b] = s[b];
                    if (vmm_map_to_nl(child_cr3, va, nf, e & (PTE_WRITABLE | PTE_USER | PTE_NX)) != 0) { pmm_free_frame(nf); rc = -1; break; }
                    continue;
                }
                uint64_t flags = e & (PTE_USER | PTE_NX);
                /* ADDREF BEFORE WRITE-PROTECTING, NOT AFTER (M2036).
                 *
                 * The reference for the child's mapping used to be taken at the
                 * END of this block -- after the parent's PTE was made RO|COW
                 * and after the child was mapped. That leaves a window in which
                 * the page is shared but its refcount still says nobody else
                 * holds it, and a sibling thread of the parent, on another core,
                 * can COW-fault inside it:
                 *
                 *   this core:  parent PTE := RO|COW                  (shared now)
                 *   other core: COW fault -> pmm_refcount(phys) == 0
                 *               -> "I am the sole owner" -> make it WRITABLE
                 *                  in place and clear PTE_COW
                 *   this core:  map it into the child, pmm_addref
                 *
                 * The parent now has a writable, non-COW mapping of a frame the
                 * child shares, so every later write by the parent silently
                 * appears in the child. Nothing faults and no count is wrong
                 * afterwards -- the damage is already done.
                 *
                 * Taking the reference first makes the refcount an OVER-estimate
                 * for a moment, which is the safe direction: the worst a racing
                 * fault can then do is copy a page it did not strictly need to. */
                pmm_addref(phys);                         /* one extra ref for the child's mapping */
                if (e & PTE_WRITABLE) pt[k] = (e & ~PTE_WRITABLE) | PTE_COW;  /* first share: write-protect both sides, mark COW */
                /* Either this page just became RO+COW above, OR it already was
                 * (a second-or-later fork of a page an EARLIER child already
                 * shares) -- both cases need the new child's own mapping to
                 * carry PTE_COW too. Missing the latter used to silently map a
                 * later child's copy read-only with NO COW bit: a write to it
                 * would fail every one of app_fault_handle's checks (not the
                 * COW branch -- no COW bit; not swap; and the VMA-lazy branch
                 * sees the page already present and just says "retry" without
                 * ever making it writable) -- an infinite refault loop, latent
                 * since COW existed (M1116) and only surfaced now because
                 * nothing before this had a 3rd-generation-or-later child
                 * write to a page any earlier sibling had already touched. */
                if (e & (PTE_WRITABLE | PTE_COW)) flags |= PTE_COW;
                if (vmm_map_to_nl(child_cr3, va, phys, flags) != 0) {
                    pmm_free_frame(phys);                 /* undo the reference taken above */
                    rc = -1; break;
                }
                vmm_lock_give(lf);
                /* Interrupts ON from here to the end of the walk (M2045).
                 *
                 * I tried throttling this -- a window every 32 tables with a
                 * cli in between -- to cut the number of preemption points.
                 * The guest HUNG: 716 seconds of wall clock for 16 seconds of
                 * CPU, every core halted. I could not explain it, and shipping
                 * an unexplained hang to save some throughput is not a trade
                 * worth making, so it is reverted to the form that
                 * demonstrably makes progress: once the lock is released the
                 * first time, this walk stays preemptible.
                 *
                 * Safe because it happens strictly AFTER vmm_lock_give --
                 * nothing is held across it -- and because the caller's
                 * interrupt state is restored before this function returns. */
                __asm__ volatile("sti");
            }
        }
    }
    }   /* end of the PML4 loop (M2031) */
    /* AND EVERY OTHER CORE HAS TO LOSE THE WRITABLE ENTRY TOO (M2036).
     *
     * This reloaded CR3 to flush the parent's TLB on THIS core, which is right
     * and not enough. Write-protecting a page for copy-on-write is only
     * effective if every core that could write it takes the fault -- and a
     * sibling thread of the parent, running on another core, keeps a cached
     * WRITABLE translation for pages this loop has already marked COW. It
     * writes straight into a frame that is now shared with the child, without
     * faulting, and the child sees the write.
     *
     * That is silent cross-process corruption, and it explains why Claude Code
     * died only on -smp 4 and never once on -smp 1, with identical progress on
     * both: it forks constantly and every fork left the other three cores able
     * to scribble on shared pages.
     *
     * Barely reachable before M2031, which widened this walk from the bottom
     * 512 GiB to the whole user half -- a threaded runtime keeps its heap far
     * above 512 GiB, so before that there was almost nothing here to race on. */
    __asm__ volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");   /* flush parent TLB (we write-protected it) */
    /* The CALLER does the shootdown now (M2047), because only it knows whether
     * this address space is live on another core at all. An unconditional IPI
     * plus its bounded ack wait on EVERY fork is very expensive for the common
     * case -- a single-threaded parent has no sibling using its address space,
     * so there is nothing to shoot down -- and gcc forks once per compilation
     * stage. app_fork_common calls app_tlb_sync(parent), which fires only when
     * a live thread exists. */
    __asm__ volatile("push %0; popfq" : : "r"(entry_fl) : "memory", "cc");   /* as we found it (M2045) */
    return rc;
}

/*
 * Walk every present ring-3 (PTE_USER) 4 KiB leaf in address space `cr3`. This
 * is the read-only twin of vmm_destroy_address_space and rests on the same
 * invariant: the app's private user region lives only under PML4[0], and a PDPT
 * slot that DIFFERS from boot's is a private, app-allocated PD (the shared
 * kernel PDs are byte-identical copies, skipped). For `clear`==0 it tallies
 * into *w; for `clear`==1 it clears the Accessed bit on each leaf. Returns the
 * resident-leaf count. Caller flushes the TLB if needed (see vmm_clear_accessed).
 */
static uint64_t walk_user_leaves(uint64_t cr3, vmm_wss_t *w, int clear) {
    cr3 &= ADDR_MASK;
    if (!cr3) return 0;
    uint64_t *pml4  = phys_to_table(cr3);
    uint64_t *bpml4 = phys_to_table(kernel_pml4);
    uint64_t pml4e = pml4[0];
    if (!(pml4e & PTE_PRESENT) || (pml4e & ADDR_MASK) == (bpml4[0] & ADDR_MASK)) return 0;
    uint64_t *pdpt  = phys_to_table(pml4e & ADDR_MASK);
    uint64_t *bpdpt = phys_to_table(bpml4[0] & ADDR_MASK);
    uint64_t n = 0;
    for (int i = 0; i < 512; i++) {
        if (!(pdpt[i] & PTE_PRESENT)) continue;
        if ((pdpt[i] & ADDR_MASK) == (bpdpt[i] & ADDR_MASK)) continue;  /* shared boot PD */
        if (pdpt[i] & PTE_HUGE) continue;
        uint64_t *pd = phys_to_table(pdpt[i] & ADDR_MASK);
        for (int j = 0; j < 512; j++) {
            if (!(pd[j] & PTE_PRESENT) || (pd[j] & PTE_HUGE)) continue;
            uint64_t *pt = phys_to_table(pd[j] & ADDR_MASK);
            for (int k = 0; k < 512; k++) {
                uint64_t e = pt[k];
                if (!(e & PTE_PRESENT) || !(e & PTE_USER)) continue;
                n++;
                if (clear) {
                    if (e & PTE_ACCESSED) pt[k] = e & ~PTE_ACCESSED;
                } else if (w) {
                    w->resident++;
                    if (e & PTE_ACCESSED) w->referenced++;
                    if (e & PTE_DIRTY)    w->dirty++;
                    if (e & PTE_WRITABLE) w->writable++;
                }
            }
        }
    }
    return n;
}

void vmm_wss(uint64_t cr3, vmm_wss_t *out) {
    if (!out) return;
    out->resident = out->referenced = out->dirty = out->writable = 0;
    walk_user_leaves(cr3, out, 0);
}

int vmm_clear_accessed(uint64_t cr3) {
    uint64_t n = walk_user_leaves(cr3, 0, 1);
    /* The CPU caches A=1 in the TLB; clearing the PTE alone won't make the next
     * access re-set it unless we flush. A CR3 reload flushes the whole
     * non-global TLB — needed only when clearing the ACTIVE space (self). For a
     * non-active target, the scheduler's CR3 reload on the next switch flushes it. */
    if ((cr3 & ADDR_MASK) == (read_cr3() & ADDR_MASK))
        __asm__ volatile("mov %%cr3, %%rax; mov %%rax, %%cr3" ::: "rax", "memory");
    return (int)n;
}

/* Read the raw leaf PTE for `virt` in the active space (0 if no page table walks
 * there). Lets swap distinguish a not-present-but-swapped page (a software marker
 * + slot packed into the entry) from a genuinely unmapped one. M1105. */
uint64_t vmm_pte_raw(uint64_t virt) {
    uint64_t *pml4 = phys_to_table(read_cr3() & ADDR_MASK);
    if (!(pml4[PML4_IDX(virt)] & PTE_PRESENT)) return 0;
    uint64_t *pdpt = phys_to_table(pml4[PML4_IDX(virt)] & ADDR_MASK);
    if (!(pdpt[PDPT_IDX(virt)] & PTE_PRESENT)) return 0;
    uint64_t *pd = phys_to_table(pdpt[PDPT_IDX(virt)] & ADDR_MASK);
    if (!(pd[PD_IDX(virt)] & PTE_PRESENT) || (pd[PD_IDX(virt)] & PTE_HUGE)) return 0;
    uint64_t *pt = phys_to_table(pd[PD_IDX(virt)] & ADDR_MASK);
    return pt[PT_IDX(virt)];
}
/* Set the raw leaf PTE for `virt` (the page table must already exist — true for
 * a page being evicted, which was present). Used to write the swapped encoding. */
/* Take/release the page-table lock from ANOTHER file (M2046).
 *
 * The copy-on-write fault handler in app.c has to decide "am I the sole owner
 * of this frame?" and act on the answer atomically with respect to
 * vmm_fork_cow, which takes its child's reference and write-protects the parent
 * under this same lock (M2045). Without sharing the lock the decision is made
 * on a value that can change before it is committed -- which is the race M2044
 * removed the fast path entirely to avoid. With it, the fast path is safe
 * again, and a fork-heavy workload does not pay a page copy per fault.
 *
 * Order is unchanged and unchanged everywhere: vma_alloc_lock (per-process) ->
 * vmm_lock (page tables) -> pmm_lock (frame allocator). */
uint64_t vmm_lock_acquire(void) { return vmm_lock_take(); }
void     vmm_lock_release(uint64_t fl) { vmm_lock_give(fl); }

void vmm_set_raw(uint64_t virt, uint64_t pte) {
    uint64_t *pml4 = phys_to_table(read_cr3() & ADDR_MASK);
    if (!(pml4[PML4_IDX(virt)] & PTE_PRESENT)) return;
    uint64_t *pdpt = phys_to_table(pml4[PML4_IDX(virt)] & ADDR_MASK);
    if (!(pdpt[PDPT_IDX(virt)] & PTE_PRESENT)) return;
    uint64_t *pd = phys_to_table(pdpt[PDPT_IDX(virt)] & ADDR_MASK);
    if (!(pd[PD_IDX(virt)] & PTE_PRESENT)) return;
    uint64_t *pt = phys_to_table(pd[PD_IDX(virt)] & ADDR_MASK);
    pt[PT_IDX(virt)] = pte;
    invlpg(virt);
}

int vmm_map_huge(uint64_t virt, uint64_t phys, uint64_t flags) {
    uint64_t f = vmm_lock_take();
    uint64_t *pml4 = phys_to_table(read_cr3() & ADDR_MASK);
    uint64_t *pdpt = next_table(pml4, PML4_IDX(virt), flags);
    uint64_t *pd   = pdpt ? next_table(pdpt, PDPT_IDX(virt), flags) : 0;
    if (!pd) { vmm_lock_give(f); return -1; }

    pd[PD_IDX(virt)] = (phys & ~0x1FFFFFull) | PTE_PRESENT | PTE_HUGE | flags;
    invlpg(virt);
    vmm_lock_give(f);
    return 0;
}

void vmm_unmap(uint64_t virt) {
    uint64_t f = vmm_lock_take();
    uint64_t *pml4 = phys_to_table(read_cr3() & ADDR_MASK);
    if (!(pml4[PML4_IDX(virt)] & PTE_PRESENT)) { vmm_lock_give(f); return; }
    uint64_t *pdpt = phys_to_table(pml4[PML4_IDX(virt)] & ADDR_MASK);
    if (!(pdpt[PDPT_IDX(virt)] & PTE_PRESENT)) { vmm_lock_give(f); return; }
    uint64_t *pd = phys_to_table(pdpt[PDPT_IDX(virt)] & ADDR_MASK);
    if (!(pd[PD_IDX(virt)] & PTE_PRESENT)) { vmm_lock_give(f); return; }
    uint64_t *pt = phys_to_table(pd[PD_IDX(virt)] & ADDR_MASK);

    pt[PT_IDX(virt)] = 0;
    invlpg(virt);
    vmm_lock_give(f);
}

/* Tear down a 2 MiB huge mapping: clear the PD entry directly (a huge PD entry
 * points at the 2 MiB data frame, NOT a page table — so vmm_unmap must not be
 * used on it). The caller frees the underlying contiguous run. (M1155) */
void vmm_unmap_huge(uint64_t virt) {
    uint64_t f = vmm_lock_take();
    uint64_t *pml4 = phys_to_table(read_cr3() & ADDR_MASK);
    if (!(pml4[PML4_IDX(virt)] & PTE_PRESENT)) { vmm_lock_give(f); return; }
    uint64_t *pdpt = phys_to_table(pml4[PML4_IDX(virt)] & ADDR_MASK);
    if (!(pdpt[PDPT_IDX(virt)] & PTE_PRESENT)) { vmm_lock_give(f); return; }
    uint64_t *pd = phys_to_table(pdpt[PDPT_IDX(virt)] & ADDR_MASK);
    pd[PD_IDX(virt)] = 0;
    invlpg(virt);
    vmm_lock_give(f);
}

/* Physical address of the 4 KiB page table (PT) that maps `virt` in space
 * `cr3`, or 0 if there's no 4 KiB-level PT (absent, or a 2 MiB huge PD entry).
 * MADV_COLLAPSE uses it to free the page table it orphans when it overwrites
 * the PD entry with a hugepage (M1168). */
uint64_t vmm_pt_phys_in(uint64_t cr3, uint64_t virt) {
    uint64_t *pml4 = phys_to_table(cr3 & ADDR_MASK);
    if (!(pml4[PML4_IDX(virt)] & PTE_PRESENT)) return 0;
    uint64_t *pdpt = phys_to_table(pml4[PML4_IDX(virt)] & ADDR_MASK);
    if (!(pdpt[PDPT_IDX(virt)] & PTE_PRESENT) || (pdpt[PDPT_IDX(virt)] & PTE_HUGE)) return 0;
    uint64_t *pd = phys_to_table(pdpt[PDPT_IDX(virt)] & ADDR_MASK);
    uint64_t e = pd[PD_IDX(virt)];
    if (!(e & PTE_PRESENT) || (e & PTE_HUGE)) return 0;
    return e & ADDR_MASK;
}

/* Rewrite the access flags of an already-mapped 4 KiB page, keeping its frame
 * (for mprotect / W^X). `flags` are the new low bits (e.g. PTE_USER, plus maybe
 * PTE_WRITABLE / PTE_NX); PTE_PRESENT is always set. Returns 0/-1. M1090. */
/* --- TLB shootdown (M1963) -------------------------------------------------
 *
 * invlpg only invalidates the TLB of the core that runs it. Once an address
 * space can be live on more than one core at a time -- which is exactly what
 * real threads brought (M1959) -- unmapping or write-protecting a page leaves
 * every OTHER core free to keep using its cached translation: writing through
 * a mapping that was just removed, or into a page that was just handed to
 * someone else. It is a silent memory-corruption bug, and it is why the plan
 * listed this as "a live correctness bug once real threads run on -smp 4".
 *
 * Implementation notes, both deliberate:
 *
 *  - A FULL local flush (CR3 reload) on the target, not a per-page invlpg.
 *    Coarser and slower, but it needs no argument marshalling and cannot be
 *    wrong about which page; shootdowns are rare next to ordinary faults.
 *
 *  - The wait for acknowledgement is BOUNDED, and gives up rather than
 *    spinning forever. An unbounded wait here is a deadlock waiting to
 *    happen: a core that is spinning on a lock with interrupts off can never
 *    ack, and this kernel takes locks with IF=0 in many places. Giving up is
 *    survivable -- the target flushes anyway the next time it enters this
 *    address space -- and it is reported, once, rather than hidden. */
static volatile int g_tlb_pending;
static volatile int g_tlb_gaveup;
static volatile unsigned long g_tlb_shootdowns;   /* how many we have actually performed */

unsigned long vmm_tlb_shootdown_count(void) { return g_tlb_shootdowns; }

/* WHO STILL OWES A FLUSH, per core (M1993).
 *
 * The pending COUNT alone cannot answer "do I owe one?", and that is what
 * deadlocked this. A core spinning to take the shootdown lock below has
 * interrupts off, so it never takes the IPI and never acks -- while the core
 * that holds the lock waits for exactly that ack. With four cores all
 * unmapping memory (which is what a threaded program does constantly) every
 * shootdown ran to its 200000-spin timeout, and the guest stopped making
 * progress: all four cores sampled at the same two instructions, one on the
 * xchg and the rest on the wait.
 *
 * A per-core flag lets a spinner discharge its own obligation by hand while it
 * waits, which is the standard answer and the only one that composes. */
static volatile unsigned char g_tlb_owed[32];

static inline int tlb_me(void) { return (int)(smp_current_cpu() & 31); }

/* Flush and clear this core's obligation, if it has one. Safe to call from
 * anywhere: it is a no-op when nothing is owed. */
static void tlb_discharge(void) {
    int me = tlb_me();
    if (!g_tlb_owed[me]) return;
    g_tlb_owed[me] = 0;
    uint64_t c = read_cr3();
    __asm__ volatile("mov %0, %%cr3" : : "r"(c) : "memory");   /* full local flush */
    __atomic_sub_fetch(&g_tlb_pending, 1, __ATOMIC_RELEASE);
}

void vmm_tlb_shootdown_ack(void) { tlb_discharge(); }

/* Returns 1 if EVERY other core acknowledged, 0 if we gave up waiting.
 *
 * It used to return void, and that was the dangerous part (M2043). Callers
 * proceed straight from here to something irreversible -- the COW fault path
 * does `app_tlb_sync(a); pmm_free_frame(old);` -- so a shootdown that timed out
 * silently handed a frame back to the allocator while another core still had a
 * cached translation for it. The comment below is right that the target flushes
 * on its next entry to the address space, and that is no comfort at all if the
 * frame has been reallocated to somebody else in the meantime. A caller that is
 * about to free has to be able to ASK. */
int vmm_tlb_shootdown(void) {
    if (smp_cpu_count <= 1) return 1;           /* uniprocessor: invlpg was enough */
    int others = smp_cpu_count - 1;
    /* One shootdown at a time: the pending counter is global. A second caller
     * simply waits its turn, which is fine -- these are rare. */
    static volatile int lock;
    /* Discharge our own obligation WHILE waiting for the lock, or the holder
     * can never finish and we can never start. This is the deadlock. */
    while (__atomic_exchange_n(&lock, 1, __ATOMIC_ACQUIRE)) {
        tlb_discharge();
        __asm__ volatile("pause");
    }
    tlb_discharge();                            /* and once more before we own it */
    for (int c = 0; c < 32; c++) g_tlb_owed[c] = 0;
    {   /* Mark every OTHER present core as owing a flush. */
        int me = tlb_me(), n = smp_cpu_count;
        if (n > 32) n = 32;
        for (int c = 0; c < n; c++) if (c != me) g_tlb_owed[c] = 1;
    }
    __atomic_store_n(&g_tlb_pending, others, __ATOMIC_RELEASE);
    __atomic_add_fetch(&g_tlb_shootdowns, 1, __ATOMIC_RELAXED);
    smp_send_tlb_shootdown_ipi();
    /* A few milliseconds, not seconds. The first version spun 20 million times
     * and a boot-time self-test measured the giving-up path at 15.9 SECONDS --
     * which would have stalled every mprotect on a threaded process for that
     * long the first time a core was slow to ack. An ack is an interrupt on an
     * already-running core: if it has not arrived in this many spins it is not
     * coming, and waiting longer buys nothing. (M1963) */
    for (int spin = 0; spin < 200000 && __atomic_load_n(&g_tlb_pending, __ATOMIC_ACQUIRE) > 0; spin++)
        __asm__ volatile("pause");
    if (__atomic_load_n(&g_tlb_pending, __ATOMIC_ACQUIRE) > 0 && !g_tlb_gaveup) {
        g_tlb_gaveup = 1;
        kprintf("[vmm] TLB shootdown timed out waiting for %d core(s) -- they will flush on next entry\n",
                __atomic_load_n(&g_tlb_pending, __ATOMIC_ACQUIRE));
    }
    int acked = (__atomic_load_n(&g_tlb_pending, __ATOMIC_ACQUIRE) == 0);
    for (int c = 0; c < 32; c++) g_tlb_owed[c] = 0;   /* give up cleanly: owe nothing */
    __atomic_store_n(&g_tlb_pending, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&lock, 0, __ATOMIC_RELEASE);
    return acked;
}

int vmm_protect(uint64_t virt, uint64_t flags) {
    uint64_t f = vmm_lock_take();
    uint64_t *pml4 = phys_to_table(read_cr3() & ADDR_MASK);
    if (!(pml4[PML4_IDX(virt)] & PTE_PRESENT)) { vmm_lock_give(f); return -1; }
    uint64_t *pdpt = phys_to_table(pml4[PML4_IDX(virt)] & ADDR_MASK);
    if (!(pdpt[PDPT_IDX(virt)] & PTE_PRESENT)) { vmm_lock_give(f); return -1; }
    uint64_t *pd = phys_to_table(pdpt[PDPT_IDX(virt)] & ADDR_MASK);
    if (!(pd[PD_IDX(virt)] & PTE_PRESENT) || (pd[PD_IDX(virt)] & PTE_HUGE)) { vmm_lock_give(f); return -1; }
    uint64_t *pt = phys_to_table(pd[PD_IDX(virt)] & ADDR_MASK);
    uint64_t e = pt[PT_IDX(virt)];
    if (!(e & PTE_PRESENT)) { vmm_lock_give(f); return -1; }
    pt[PT_IDX(virt)] = (e & ADDR_MASK) | PTE_PRESENT | flags;   /* keep the frame, replace the flags */
    invlpg(virt);
    vmm_lock_give(f);
    return 0;
}

/* Split the 2 MiB huge page that maps `virt` (active space) into 512 individual
 * 4 KiB pages over the same physical 2 MiB, preserving the leaf flags. This is the
 * prerequisite for per-page permissions (W^X) on a region the boot trampoline
 * mapped with one huge page. Returns 0 if already 4 KiB-mapped (no-op) or after a
 * successful split; -1 on OOM or if there is no present PD entry. */
static int vmm_split_huge(uint64_t virt) {
    uint64_t *pml4 = phys_to_table(read_cr3() & ADDR_MASK);
    if (!(pml4[PML4_IDX(virt)] & PTE_PRESENT)) return -1;
    uint64_t *pdpt = phys_to_table(pml4[PML4_IDX(virt)] & ADDR_MASK);
    if (!(pdpt[PDPT_IDX(virt)] & PTE_PRESENT) || (pdpt[PDPT_IDX(virt)] & PTE_HUGE)) return -1;
    uint64_t *pd = phys_to_table(pdpt[PDPT_IDX(virt)] & ADDR_MASK);
    uint64_t e = pd[PD_IDX(virt)];
    if (!(e & PTE_PRESENT)) return -1;
    if (!(e & PTE_HUGE))    return 0;                  /* already a 4 KiB PT — nothing to split */

    uint64_t base   = e & ~0x1FFFFFull;                /* 2 MiB-aligned physical base */
    uint64_t lflags = e & (PTE_WRITABLE | PTE_USER | PTE_NX | PTE_PCD | PTE_PWT);   /* carry leaf perms + cache attrs, drop HUGE (M1884) */
    uint64_t ptphys = pmm_alloc_frame();
    if (!ptphys) return -1;
    uint64_t *pt = phys_to_table(ptphys);
    for (int i = 0; i < 512; i++)
        pt[i] = (base + (uint64_t)i * PAGE_SIZE) | PTE_PRESENT | lflags;
    pd[PD_IDX(virt)] = ptphys | PTE_PRESENT | PTE_WRITABLE;     /* PD entry now points at the PT */
    uint64_t hbase = virt & ~0x1FFFFFull;
    for (uint64_t off = 0; off < 0x200000; off += PAGE_SIZE) invlpg(hbase + off);
    return 0;
}

/* ---- guarded kernel task stacks (M1495) ---------------------------------------
 * Kernel task stacks were kmalloc'd from the heap, so an overflow silently
 * corrupted the adjacent allocation (the bug class M1491/M1492 dealt with). These
 * map each stack in a dedicated VA window with an UNMAPPED guard page on each side,
 * so an overflow faults IMMEDIATELY (a clean #PF in the guard) — caught at the
 * exact offending instruction, before any corruption — instead of being detected
 * only later by the M1492 canary. The window sits in the upper half of the kheap's
 * PML4 entry (288), which kheap_init establishes before any address space is
 * created; vmm_create_address_space shares [256..512) by pointer, so every task's
 * CR3 sees these mappings (a clone'd thread runs ring-0 on its kernel stack while
 * the app's CR3 is active, so the stack VA must be globally mapped). VA is never
 * recycled — the 256 GiB window dwarfs any realistic task churn, so leaking it on
 * free is simpler and safe; the frames (the actual RAM) are freed. */
#define KSTACK_WIN_BASE 0xFFFF904000000000ull   /* upper half of PML4[288]; kheap grows from 0xFFFF9000.. far below */
#define KSTACK_WIN_END  0xFFFF908000000000ull   /* = end of PML4[288] (289 << 39) */
static volatile uint64_t kstack_next = KSTACK_WIN_BASE;

void *kstack_alloc(uint64_t size) {
    uint64_t pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    if (!pages) return 0;
    uint64_t total = (pages + 2) * PAGE_SIZE;                         /* + a low and a high guard page */
    uint64_t guard_lo = __atomic_fetch_add(&kstack_next, total, __ATOMIC_SEQ_CST);  /* lock-free bump */
    if (guard_lo + total > KSTACK_WIN_END) return 0;                 /* window exhausted (the bump leak is harmless) */
    uint64_t base = guard_lo + PAGE_SIZE;                            /* lowest usable address (guard page below) */
    uint64_t end  = base + pages * PAGE_SIZE;                        /* exclusive; a guard page sits at `end` */
    for (uint64_t v = base; v < end; v += PAGE_SIZE) {
        uint64_t frame = pmm_alloc_frame();
        if (!frame || vmm_map(v, frame, PTE_WRITABLE | PTE_NX) != 0) {
            if (frame) pmm_free_frame(frame);
            for (uint64_t u = base; u < v; u += PAGE_SIZE) {         /* unwind the pages mapped so far */
                uint64_t p = vmm_translate(u);
                vmm_unmap(u);
                if (p) pmm_free_frame(p);
            }
            return 0;
        }
    }
    return (void *)base;
}

void kstack_free(void *stackbase, uint64_t size) {
    if (!stackbase) return;
    uint64_t pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    uint64_t base  = (uint64_t)stackbase;
    /* NO CROSS-CORE SHOOTDOWN, AND THE REASON MATTERS (M1994).
     *
     * The comment here used to say "only the BSP runs tasks", which stopped
     * being true at M1531 when the scheduler went multi-core -- so this looked
     * exactly like a stale-TLB bug: unmap locally, hand the frames back, and
     * let another core write through a cached translation into memory that now
     * belongs to something else.
     *
     * It is not one, and the real invariant is worth stating: kernel-stack
     * VIRTUAL addresses are bump-allocated out of kstack_next and NEVER REUSED
     * (the allocator returns 0 when the window is exhausted rather than
     * wrapping). A stale translation for a freed stack therefore names an
     * address nothing will ever reference again, so it can never be
     * dereferenced -- the physical frame is recycled, the virtual address is
     * not.
     *
     * Adding the shootdown that the wrong comment implied made things WORSE,
     * and that is instructive: vmm_tlb_shootdown spins for up to 200000
     * iterations, and this runs from task_free with the run-queue lock held and
     * interrupts off. smpthreadtest went from passing to a kernel stack
     * overflow inside the IPI handler. A lock-free path that only needed its
     * comment corrected does not want a synchronous broadcast in it. */
    for (uint64_t v = base; v < base + pages * PAGE_SIZE; v += PAGE_SIZE) {
        uint64_t p = vmm_translate(v);
        vmm_unmap(v);                            /* invlpg, local: see above */
        if (p) pmm_free_frame(p);
    }
}

/* A #PF whose CR2 lands in the stack window is necessarily a guard-page (or unused
 * slack) hit — mapped stack pages don't fault — i.e. a kernel stack overflow. */
int kstack_is_guard(uint64_t addr) {
    return addr >= KSTACK_WIN_BASE && addr < KSTACK_WIN_END;
}

/* Boot self-test (M1495), in the kernel's self-test idiom (cf. SMEP/SMP/IDE-DMA/
 * RAID): allocate a guarded stack and prove via the page tables that the usable
 * region is mapped while BOTH guard pages are genuinely unmapped — so a real
 * overflow will fault rather than corrupt. Run once at boot, single-threaded. */
void kstack_selftest(void) {
    uint64_t sz = 16384;
    void *s = kstack_alloc(sz);
    if (!s) { kprintf("[ !! ] guarded kernel stacks: self-test alloc failed\n"); return; }
    uint64_t base = (uint64_t)s;
    int lo_guard = (vmm_translate(base - PAGE_SIZE) == 0);                 /* page below = guard, must be unmapped */
    int hi_guard = (vmm_translate(base + sz) == 0);                       /* page at end = guard, must be unmapped */
    int mapped   = (vmm_translate(base) != 0) && (vmm_translate(base + sz - PAGE_SIZE) != 0);
    kstack_free(s, sz);
    int ok = lo_guard && hi_guard && mapped;
    kprintf("[ %s ] guarded kernel task stacks: usable mapped=%d, guard pages unmapped lo=%d hi=%d\n",
            ok ? "ok" : "!!", mapped, lo_guard, hi_guard);
}

/*
 * Enforce W^X on the kernel image. The boot trampoline (boot.asm) identity-maps the
 * low 1 GiB with 2 MiB huge pages, so the kernel's own code and data share huge,
 * writable, EXECUTABLE mappings — a kernel bug can overwrite kernel code, and any
 * writable page (stack, heap, data) is also executable. Here we split the huge pages
 * covering the kernel image into 4 KiB pages and tighten each section:
 *   .text            -> read-only + executable  (kernel code can no longer be patched)
 *   .rodata          -> read-only + no-execute   (constants + embedded app ELFs immutable)
 *   .data/.bss/stack -> writable  + no-execute   (defeats executing injected data/stack bytes)
 * The eBPF JIT + module loader emit code into the .jitexec section, which is re-marked
 * RWX after the blanket NX pass. EFER.NXE is enabled in boot.asm. Run once at boot,
 * single-threaded, in the kernel address space (before sched_init / any user CR3).
 */
void vmm_harden_kernel(void) {
    extern char _kimage_start[], _srodata[], _sdata[], kernel_end[];
    extern char _jitexec_start[], _jitexec_end[];
    uint64_t text_s = (uint64_t)_kimage_start;
    uint64_t ro_s   = (uint64_t)_srodata;
    uint64_t data_s = (uint64_t)_sdata;
    uint64_t end    = ((uint64_t)kernel_end + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t jit_s  = (uint64_t)_jitexec_start;
    uint64_t jit_e  = (uint64_t)_jitexec_end;

    /* 1. Split every 2 MiB huge page overlapping the kernel image into 4 KiB pages. */
    for (uint64_t v = text_s & ~0x1FFFFFull; v < end; v += 0x200000)
        vmm_split_huge(v);

    /* 2. Tighten per section (vmm_protect always re-sets PRESENT). */
    for (uint64_t v = text_s; v < ro_s;   v += PAGE_SIZE) vmm_protect(v, 0);                      /* RX, read-only */
    for (uint64_t v = ro_s;   v < data_s; v += PAGE_SIZE) vmm_protect(v, PTE_NX);                 /* R,  NX        */
    for (uint64_t v = data_s; v < end;    v += PAGE_SIZE) vmm_protect(v, PTE_WRITABLE | PTE_NX);  /* RW, NX        */

    /* 3. The JIT / module scratch must execute: re-mark it RWX (override the NX above). */
    for (uint64_t v = jit_s;  v < jit_e;  v += PAGE_SIZE) vmm_protect(v, PTE_WRITABLE);           /* RWX           */

    /* 4. Unmap the boot stack's guard page (boot.asm reserves it just below the
     *    stack): a boot-stack overflow now faults here instead of silently
     *    corrupting the page tables / multiboot info that sit beneath the stack. */
    extern char stack_guard[];
    vmm_unmap((uint64_t)stack_guard);

    /* Verify the protection actually took (read representative leaf PTEs straight from
     * the page tables) and report — turns "it booted" into a checked invariant. */
    uint64_t te = vmm_pte_raw(text_s), re = vmm_pte_raw(ro_s), de = vmm_pte_raw(data_s);
    kprintf("[ ok ] W^X: .text=%s .rodata=%s .data/.bss=%s (kernel image %lu KiB)\n",
            ((te & PTE_PRESENT) && !(te & PTE_WRITABLE) && !(te & PTE_NX)) ? "RO+X"  : "BAD",
            ((re & PTE_PRESENT) && !(re & PTE_WRITABLE) &&  (re & PTE_NX)) ? "RO+NX" : "BAD",
            ((de & PTE_PRESENT) &&  (de & PTE_WRITABLE) &&  (de & PTE_NX)) ? "RW+NX" : "BAD",
            (unsigned long)((end - text_s) / 1024));
    kprintf("[ ok ] stack guard: boot-stack guard page %s\n",
            (vmm_pte_raw((uint64_t)stack_guard) & PTE_PRESENT) ? "MAPPED (BAD)" : "unmapped");

    /* Flush the whole TLB (we downgraded huge->4 KiB and changed many leaf flags). */
    __asm__ volatile("mov %%cr3, %%rax; mov %%rax, %%cr3" ::: "rax", "memory");
}

/* Translate a virtual address in an ARBITRARY address space (walk `cr3`'s tables
 * via the HHDM, never loading CR3) — for inspecting another process's memory
 * (/proc/<pid>/mem, M1114). Returns the physical address, or 0 if unmapped. */
uint64_t vmm_translate_in(uint64_t cr3, uint64_t virt) {
    uint64_t *pml4 = phys_to_table(cr3 & ADDR_MASK);
    if (!(pml4[PML4_IDX(virt)] & PTE_PRESENT)) return 0;
    uint64_t *pdpt = phys_to_table(pml4[PML4_IDX(virt)] & ADDR_MASK);
    if (!(pdpt[PDPT_IDX(virt)] & PTE_PRESENT)) return 0;
    uint64_t *pd = phys_to_table(pdpt[PDPT_IDX(virt)] & ADDR_MASK);
    if (!(pd[PD_IDX(virt)] & PTE_PRESENT)) return 0;
    if (pd[PD_IDX(virt)] & PTE_HUGE)
        return (pd[PD_IDX(virt)] & ~0x1FFFFFull) | (virt & 0x1FFFFF);
    uint64_t *pt = phys_to_table(pd[PD_IDX(virt)] & ADDR_MASK);
    if (!(pt[PT_IDX(virt)] & PTE_PRESENT)) return 0;
    return (pt[PT_IDX(virt)] & ADDR_MASK) | (virt & 0xFFF);
}

/* The raw leaf PTE for `virt` in an arbitrary address space `cr3` (0 if the walk
 * can't reach a leaf). Unlike vmm_translate_in this returns the entry even when
 * PRESENT=0, so a caller can see the software PTE_SWAP marker + the A/D bits —
 * exactly what /proc/<pid>/smaps needs to classify a page (M1151). */
uint64_t vmm_pte_in(uint64_t cr3, uint64_t virt) {
    uint64_t *pml4 = phys_to_table(cr3 & ADDR_MASK);
    if (!(pml4[PML4_IDX(virt)] & PTE_PRESENT)) return 0;
    uint64_t *pdpt = phys_to_table(pml4[PML4_IDX(virt)] & ADDR_MASK);
    if (!(pdpt[PDPT_IDX(virt)] & PTE_PRESENT)) return 0;
    uint64_t *pd = phys_to_table(pdpt[PDPT_IDX(virt)] & ADDR_MASK);
    if (!(pd[PD_IDX(virt)] & PTE_PRESENT)) return 0;
    if (pd[PD_IDX(virt)] & PTE_HUGE) return pd[PD_IDX(virt)];
    uint64_t *pt = phys_to_table(pd[PD_IDX(virt)] & ADDR_MASK);
    return pt[PT_IDX(virt)];   /* raw leaf: PRESENT/DIRTY/ACCESSED/SWAP bits all intact */
}

/* Set the 4 KiB leaf PTE for `virt` in an arbitrary address space `cr3`, ONLY if
 * the page tables down to the leaf already exist (the page is present) — it never
 * creates tables. Returns 0 on success, -1 if no leaf. Used by process_vm_write
 * to break COW in the target before poking it (M1165). On single-CPU the target
 * isn't running, and its next schedule reloads CR3 (flushing the TLB), so no
 * cross-AS invlpg is needed. */
int vmm_set_pte_in(uint64_t cr3, uint64_t virt, uint64_t pte) {
    uint64_t *pml4 = phys_to_table(cr3 & ADDR_MASK);
    if (!(pml4[PML4_IDX(virt)] & PTE_PRESENT)) return -1;
    uint64_t *pdpt = phys_to_table(pml4[PML4_IDX(virt)] & ADDR_MASK);
    if (!(pdpt[PDPT_IDX(virt)] & PTE_PRESENT)) return -1;
    uint64_t *pd = phys_to_table(pdpt[PDPT_IDX(virt)] & ADDR_MASK);
    if (!(pd[PD_IDX(virt)] & PTE_PRESENT) || (pd[PD_IDX(virt)] & PTE_HUGE)) return -1;
    uint64_t *pt = phys_to_table(pd[PD_IDX(virt)] & ADDR_MASK);
    pt[PT_IDX(virt)] = pte;
    return 0;
}

uint64_t vmm_translate(uint64_t virt) {
    uint64_t *pml4 = phys_to_table(read_cr3() & ADDR_MASK);
    if (!(pml4[PML4_IDX(virt)] & PTE_PRESENT)) return 0;
    uint64_t *pdpt = phys_to_table(pml4[PML4_IDX(virt)] & ADDR_MASK);
    if (!(pdpt[PDPT_IDX(virt)] & PTE_PRESENT)) return 0;
    uint64_t *pd = phys_to_table(pdpt[PDPT_IDX(virt)] & ADDR_MASK);
    if (!(pd[PD_IDX(virt)] & PTE_PRESENT)) return 0;
    if (pd[PD_IDX(virt)] & PTE_HUGE)
        return (pd[PD_IDX(virt)] & ~0x1FFFFFull) | (virt & 0x1FFFFF);
    uint64_t *pt = phys_to_table(pd[PD_IDX(virt)] & ADDR_MASK);
    if (!(pt[PT_IDX(virt)] & PTE_PRESENT)) return 0;
    return (pt[PT_IDX(virt)] & ADDR_MASK) | (virt & 0xFFF);
}

/*
 * Does a leaf, USER, PRESENT page cover `v` in the current CR3? If a level
 * comes back not-present, that's either a genuine hole OR a demand-paged
 * region (mmap, or elf_load's deferred whole-.bss range) nobody has touched
 * yet — indistinguishable from the page tables alone. Try exactly once to
 * resolve it the same way a real ring-3 #PF would (app_fault_handle, which
 * only succeeds for an address inside the CURRENT app's own registered VMA
 * list) and re-walk from the top, since that call may have just built the
 * intermediate tables too. A present-but-!USER entry at any level is a real
 * violation (kernel memory) and is never retried.
 */
static int user_page_present(uint64_t v) {
    for (int attempt = 0; attempt < 2; attempt++) {
        uint64_t *pml4 = phys_to_table(read_cr3() & ADDR_MASK);
        uint64_t e = pml4[PML4_IDX(v)];
        if (!(e & PTE_PRESENT)) { if (attempt == 0 && app_fault_handle(v, 0)) continue; return 0; }
        if (!(e & PTE_USER)) return 0;
        uint64_t *pdpt = phys_to_table(e & ADDR_MASK);
        e = pdpt[PDPT_IDX(v)];
        if (!(e & PTE_PRESENT)) { if (attempt == 0 && app_fault_handle(v, 0)) continue; return 0; }
        if (!(e & PTE_USER)) return 0;
        if (e & PTE_HUGE) return 1;                /* 1 GiB user page covers v */
        uint64_t *pd = phys_to_table(e & ADDR_MASK);
        e = pd[PD_IDX(v)];
        if (!(e & PTE_PRESENT)) { if (attempt == 0 && app_fault_handle(v, 0)) continue; return 0; }
        if (!(e & PTE_USER)) return 0;
        if (e & PTE_HUGE) return 1;                /* 2 MiB user page covers v */
        uint64_t *pt = phys_to_table(e & ADDR_MASK);
        e = pt[PT_IDX(v)];
        if (!(e & PTE_PRESENT)) { if (attempt == 0 && app_fault_handle(v, 0)) continue; return 0; }
        if (!(e & PTE_USER)) return 0;
        return 1;
    }
    return 0;
}

/*
 * Is the whole range [ptr, ptr+len) accessible to the CURRENT (user) address
 * space — i.e. mapped (or lazily resolvable — see user_page_present) and
 * PTE_USER at every paging level? A ring-0 syscall handler runs with the
 * calling app's CR3 active, where the kernel's higher half and low identity
 * map are mapped (and writable in ring 0) but NOT marked USER. So validating
 * PTE_USER on every page an app hands to a syscall stops it from steering the
 * kernel into reading/writing kernel memory through a forged pointer. Returns
 * 1 if every page is user-accessible, 0 otherwise (unmapped and not a known
 * VMA, supervisor-only, or a length that wraps the address space).
 */
int vmm_user_ok(uint64_t ptr, uint64_t len) {
    if (len == 0) return 1;                       /* empty range touches nothing */
    uint64_t end = ptr + len;
    if (end < ptr) return 0;                      /* address wrap */
    for (uint64_t v = ptr & ~(uint64_t)(PAGE_SIZE - 1); v < end; v += PAGE_SIZE)
        if (!user_page_present(v)) return 0;
    return 1;
}

/*
 * Is the NUL-terminated string at `ptr` entirely within the current space's
 * user pages, up to and including its terminator? Validates each page (via
 * vmm_user_ok) before reading any byte of it, so the scan itself can't fault
 * or run into kernel memory. Scans at most `max` bytes — a string with no NUL
 * in range, or one that crosses into a non-user page, is rejected (returns 0).
 * For syscall string arguments (filenames, hostnames) whose length isn't known
 * up front.
 */
int vmm_user_str_ok(uint64_t ptr, uint64_t max) {
    uint64_t scanned = 0;
    while (scanned < max) {
        uint64_t page = (ptr + scanned) & ~(uint64_t)(PAGE_SIZE - 1);
        if (!vmm_user_ok(page, PAGE_SIZE)) return 0;       /* page not user-accessible */
        for (uint64_t a = ptr + scanned; a < page + PAGE_SIZE && scanned < max; a++, scanned++)
            if (*(const char *)a == 0) return 1;           /* terminator reached, every byte was user */
    }
    return 0;   /* no terminator within `max`: reject rather than read unbounded */
}

/* Build the higher-half direct map: map all physical RAM at HHDM_BASE using
 * cheap 2 MiB pages, so the kernel can touch any frame via hhdm(phys). */
void vmm_init(void) {
    kernel_pml4 = read_cr3() & ADDR_MASK;   /* boot PML4: kernel-only mappings */
    uint64_t total = pmm_total_bytes();
    for (uint64_t phys = 0; phys < total; phys += 0x200000)
        vmm_map_huge(HHDM_BASE + phys, phys, PTE_WRITABLE);
    g_hhdm_ready = 1;   /* HHDM now covers all RAM: reach page tables through it, not the 1 GiB boot identity map (M1875) */
}
