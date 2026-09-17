/*
 * swap.c — back anonymous pages, with a COMPRESSED-RAM tier (zram, M1156) in
 * front of optional disk swap. swap_out(phys) reclaims a frame: an all-zero
 * page costs 1 bit, an otherwise-compressible page is DEFLATE-compressed into a
 * kheap blob (raw_deflate, kernel/deflate.c), and only an incompressible page
 * spills to a writable non-boot disk (or, if none, is held raw in RAM). swap_in
 * restores it (memset-zero / inflate / copy / disk read). The slot index lives
 * in the swapped page's not-present PTE (kernel/app.c does the encoding + the
 * fault-in), so the zram tier is invisible to that ABI. Because the primary
 * tier is RAM, swap is ALWAYS active — no disk required (M1156).
 */
#include "string.h"   /* memcpy/memset: a page moves word-at-a-time (M2094) */
#include "swap.h"
#include "blockdev.h"
#include "vmm.h"        /* hhdm() */
#include "pmm.h"        /* PAGE_SIZE */
#include "kheap.h"      /* kmalloc / kfree */
#include "inflate.h"    /* raw_deflate (compress) + inflate (decompress) */
#include "console.h"    /* kprintf */
#include <stdint.h>

#define SWAP_SLOTS    8192            /* 8192 pages of swap slots */
#define SECT_PER_PAGE (PAGE_SIZE / 512)

/* per-slot kind: 0 = free, 1 = RAM blob (zbuf/zsz), 2 = all-zero, 3 = on disk */
static uint8_t  zk[SWAP_SLOTS];
static uint8_t *zbuf[SWAP_SLOTS];     /* kheap blob for kind 1 (compressed if zsz<PAGE, else raw) */
static uint16_t zsz[SWAP_SLOTS];      /* stored bytes for kind 1 */
static int      swap_dev = -1;        /* disk-tier blockdev index, -1 = none yet */
static uint64_t swap_base;            /* first swap sector on that device */
static uint64_t g_out, g_in, g_cur;   /* cumulative out / in, current resident slots (all kinds: RAM/zero/disk) */
static uint64_t g_zbytes;             /* bytes currently held in the RAM (zram) tier */
static uint64_t g_ramcur;             /* current resident slots in the RAM tier ONLY (kind==1) -- g_zbytes's own page-count sibling, for the ratio stat below (g_cur counts disk/zero slots too, which g_zbytes never does) */

/* zram is RAM-backed, so swap is always available — no disk needed (M1156). */
int swap_active(void) { return 1; }

/* Lazily find a writable non-boot disk for the incompressible-page spill tier;
 * returns its blockdev index, or -1 if none. (Was the old swap_active body.) */
static int swap_disk(void) {
    if (swap_dev >= 0) return swap_dev;
    int n = blockdev_count();
    for (int i = 0; i < n; i++) {
        blockdev_t *d = blockdev_get(i);
        if (!d || !d->name || !d->write) continue;             /* writable devices only */
        const char *nm = d->name;
        if (nm[0]=='a' && nm[1]=='t' && nm[2]=='a' && nm[3]=='0') continue;  /* never the boot disk */
        uint64_t need = (uint64_t)SWAP_SLOTS * SECT_PER_PAGE;
        if (d->sectors && d->sectors < need + 4096) continue;  /* too small */
        swap_base = d->sectors ? d->sectors - need : 200000;   /* high end (or a fixed high LBA) */
        swap_dev = i;
        kprintf("[swap] disk spill tier on %s at lba %lu\n", nm, (unsigned long)swap_base);
        return swap_dev;
    }
    return -1;
}

static int free_slot(void) { for (int i = 0; i < SWAP_SLOTS; i++) if (!zk[i]) return i; return -1; }

/* M1605: unlike pmm.c/vmm.c/kheap.c (all retrofitted under M1531 with a real
 * cross-core spinlock, since "cli alone only ever stopped a LOCAL interrupt"),
 * this table had NO lock at all -- reachable from more than one core via the
 * same page-fault swap-in path pmm.c is, plus a direct syscall (MADV_PAGEOUT,
 * app_swap_out). Two cores racing free_slot() could both claim the same index
 * before either marks it used, then the second swap_out() to finish clobbers
 * the first's zbuf[s] pointer (a permanent kheap leak) while the first's PTE
 * still encodes slot s -- a later fault-in of THAT page would read back the
 * SECOND process's data. Same idiom as pmm.c: spinlock nested in cli. Held
 * across the whole of each function below, including the disk tier's
 * blockdev_read/write -- not free, but safe (those are busy-polled, never
 * task_block, so no deadlock risk) and swap ops are rare enough that a coarse
 * lock costs far less here than the same choice would in pmm.c/kheap.c. */
static volatile int swap_lock;
static inline uint64_t irq_save(void) {
    uint64_t fl;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
    while (__atomic_exchange_n(&swap_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return fl;
}
static inline void irq_restore(uint64_t fl) {
    __atomic_store_n(&swap_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(fl) : "memory", "cc");
}

/* Reclaim frame `phys`: store its contents in the zram RAM tier (or disk) and
 * return the slot index, or -1 on failure (table full / OOM). */
int swap_out(uint64_t phys) {
    uint64_t fl = irq_save();
    int s = free_slot();
    if (s < 0) { irq_restore(fl); return -1; }                 /* swap table full */
    const uint8_t *src = (const uint8_t *)hhdm(phys);

    int allzero = 1;
    for (int i = 0; i < PAGE_SIZE; i++) if (src[i]) { allzero = 0; break; }
    if (allzero) { zk[s] = 2; g_out++; g_cur++; irq_restore(fl); return s; }    /* all-zero page: store nothing */

    uint8_t *tmp = kmalloc(PAGE_SIZE);
    int clen = tmp ? raw_deflate(src, PAGE_SIZE, tmp, PAGE_SIZE - 1) : -1;
    if (clen > 0 && clen < PAGE_SIZE) {                        /* it compressed: keep a right-sized blob */
        uint8_t *b = kmalloc((unsigned long)clen);
        if (b) {
            for (int i = 0; i < clen; i++) b[i] = tmp[i];
            kfree(tmp);
            zbuf[s] = b; zsz[s] = (uint16_t)clen; zk[s] = 1;
            g_out++; g_cur++; g_ramcur++; g_zbytes += (uint64_t)clen;
            irq_restore(fl);
            return s;
        }
    }
    if (tmp) kfree(tmp);

    int dev = swap_disk();                                    /* incompressible: spill to disk if we have one */
    if (dev >= 0 && blockdev_write(dev, swap_base + (uint64_t)s * SECT_PER_PAGE, SECT_PER_PAGE, hhdm(phys)) == 0) {
        zk[s] = 3; g_out++; g_cur++;
        irq_restore(fl);
        return s;
    }
    uint8_t *b = kmalloc(PAGE_SIZE);                          /* no disk: hold it raw in RAM */
    if (!b) { irq_restore(fl); return -1; }
    memcpy(b, src, PAGE_SIZE);   /* word-at-a-time (M2094) */
    zbuf[s] = b; zsz[s] = (uint16_t)PAGE_SIZE; zk[s] = 1;
    g_out++; g_cur++; g_ramcur++; g_zbytes += PAGE_SIZE;
    irq_restore(fl);
    return s;
}

/* Restore the slot's page into frame `phys`. */
int swap_in(int slot, uint64_t phys) {
    uint64_t fl = irq_save();
    if (slot < 0 || slot >= SWAP_SLOTS || !zk[slot]) { irq_restore(fl); return -1; }
    uint8_t *dst = (uint8_t *)hhdm(phys);
    if (zk[slot] == 2) { memset(dst, 0, PAGE_SIZE); g_in++; irq_restore(fl); return 0; }   /* zero page */
    if (zk[slot] == 1) {
        if (zsz[slot] < PAGE_SIZE) {                          /* compressed */
            if (inflate(zbuf[slot], zsz[slot], dst, PAGE_SIZE) != PAGE_SIZE) { irq_restore(fl); return -1; }   /* corrupt */
        } else {
            memcpy(dst, zbuf[slot], PAGE_SIZE);   /* raw, word-at-a-time (M2094) */
        }
        g_in++; irq_restore(fl); return 0;
    }
    /* kind 3: disk */
    if (swap_dev < 0 || blockdev_read(swap_dev, swap_base + (uint64_t)slot * SECT_PER_PAGE, SECT_PER_PAGE, hhdm(phys)) < 0) {
        irq_restore(fl); return -1;
    }
    g_in++; irq_restore(fl); return 0;
}

void swap_release(int slot) {
    uint64_t fl = irq_save();
    if (slot < 0 || slot >= SWAP_SLOTS || !zk[slot]) { irq_restore(fl); return; }
    if (zk[slot] == 1 && zbuf[slot]) { if (zsz[slot]) g_zbytes -= zsz[slot]; kfree(zbuf[slot]); zbuf[slot] = 0; g_ramcur--; }
    zk[slot] = 0; zsz[slot] = 0; g_cur--;
    irq_restore(fl);
}

static int sp_put(char *b, int p, int max, const char *s) { while (*s && p + 1 < max) b[p++] = *s++; return p; }
static int sp_num(char *b, int p, int max, uint64_t v) {
    char t[24]; int n = 0;
    if (!v) t[n++] = '0';
    while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
    while (n && p + 1 < max) b[p++] = t[--n];
    return p;
}

int swap_format(char *out, int max) {
    int p = 0;
    p = sp_put(out, p, max, "Backing:\tzram (compressed RAM)");
    if (swap_dev >= 0) { blockdev_t *d = blockdev_get(swap_dev); p = sp_put(out, p, max, " + disk spill on "); p = sp_put(out, p, max, d && d->name ? d->name : "?"); }
    p = sp_put(out, p, max, "\n");
    p = sp_put(out, p, max, "Slots:\t");     p = sp_num(out, p, max, SWAP_SLOTS);  p = sp_put(out, p, max, "\n");
    p = sp_put(out, p, max, "Resident:\t");  p = sp_num(out, p, max, g_cur);       p = sp_put(out, p, max, " pages\n");
    p = sp_put(out, p, max, "PagesOut:\t");  p = sp_num(out, p, max, g_out);       p = sp_put(out, p, max, "\n");
    p = sp_put(out, p, max, "PagesIn:\t");   p = sp_num(out, p, max, g_in);        p = sp_put(out, p, max, "\n");
    /* zram compression: original (resident RAM pages * 4 KiB) vs bytes actually held */
    p = sp_put(out, p, max, "RAM held:\t");  p = sp_num(out, p, max, g_zbytes);    p = sp_put(out, p, max, " bytes\n");
    p = sp_put(out, p, max, "Ratio x100:\t");
    p = sp_num(out, p, max, g_zbytes ? (g_ramcur * (uint64_t)PAGE_SIZE * 100) / g_zbytes : 0);   /* orig/held * 100 -- was g_cur, which also counts disk/zero-page slots g_zbytes never touches */
    p = sp_put(out, p, max, "  (orig/held; higher = better, inf for all-zero)\n");
    if (p < max) out[p] = 0;
    return p;
}
