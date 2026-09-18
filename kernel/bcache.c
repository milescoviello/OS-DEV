/*
 * bcache.c — the unified block cache (M1869; hashed, resized and made
 * scan-resistant in M2154). See bcache.h.
 *
 * One shared pool replaces ata.c's ACACHE and blockdev.c's per-layer buffer
 * cache. Keyed by (owner, lba). The internal spinlock-in-cli guards only the
 * in-memory bookkeeping — NEVER disk I/O (callers read/write the disk outside
 * these calls and then install), and every lookup copies the block into the
 * caller's buffer, so an eviction can never leave a dangling pointer.
 * Write-through, so a crash can't lose a cached write.
 *
 * WHY THIS WAS REWRITTEN (M2154). The pool was 128 entries — 64 KiB, which is
 * EXACTLY one readahead window, so a single prefetch evicted the entire cache.
 * Measured on Claude Code's steady state: one page fault issued 588 ATA
 * commands to deliver 68 KiB, and 450 of those 588 sectors were re-reads of
 * metadata that the same prefetch had just thrown out. A cache that cannot hold
 * one window plus its metadata is not a cache; it is an echo.
 *
 * Three changes, in order of how much they matter:
 *
 *  1. SIZE. Sized from physical memory (1/32, capped at 32 MiB) instead of a
 *     compile-time 128 entries. At the 8 GiB Firefox runs that is 65536 sectors
 *     against 128 — 512x — and at the 256 MiB the test suites boot with it is
 *     still 16384. Allocated once from the heap; if that fails, the old static
 *     128-entry pool remains and everything keeps working, slowly.
 *
 *  2. A HASH INDEX. Lookup was a linear scan of every entry, so growing the
 *     pool would have made each miss 512x more expensive and eaten the win.
 *     Chained buckets, one per entry, power-of-two masked.
 *
 *  3. SCAN RESISTANCE. Demand-paging 2 GiB of Firefox libraries is one enormous
 *     sequential scan, and plain LRU lets it evict the filesystem metadata that
 *     every one of those reads must walk THROUGH. So: CLOCK with a reference
 *     bit, and a block that is hit a second time becomes `prot`, which buys it
 *     one full extra pass of the hand. Metadata is read repeatedly by
 *     definition; a scanned data block is not.
 */
#include "bcache.h"
#include "string.h"
#include "kheap.h"
#include "pmm.h"
#include "console.h"

#define BCACHE_STATIC_N 128          /* the pre-init fallback pool: 64 KiB, as before */
/* THE CAP, AND WHY IT IS THIS BIG (M2155). The binding constraint at the 8 GiB
 * Firefox runs is this number, not the 1/32-of-memory rule -- and the workload
 * it exists for is demand-paging a two-gigabyte library closure, where a cache
 * an order of magnitude smaller than the working set still thrashes. 128 MiB of
 * budget lands ~64 MiB of sectors plus its metadata, which is under 1% of that
 * machine. Small configurations are protected by the fraction, not by this:
 * at the 256 MiB the test suites boot with, 1/32 gives 8 MiB and this never
 * applies. */
#define BCACHE_MAX_BYTES (128u << 20)

struct bcmeta {
    uint32_t owner;
    uint64_t lba;
    uint32_t next;                   /* hash chain: entry index + 1, 0 = end */
    uint8_t  valid, ref, prot;
};

/* The pre-init pool. Static so that the very first sector read — which happens
 * during blockdev/mount bring-up, before the heap is worth trusting with 32 MiB
 * — is still cached. */
static struct bcmeta g_smeta[BCACHE_STATIC_N];
static uint8_t       g_sdata[BCACHE_STATIC_N][BCACHE_SECSZ];
static uint32_t      g_sbucket[BCACHE_STATIC_N];

static struct bcmeta *g_meta   = g_smeta;
static uint8_t       *g_data   = (uint8_t *)g_sdata;
static uint32_t      *g_bucket = g_sbucket;
static uint32_t       g_ncap   = BCACHE_STATIC_N;
static uint32_t       g_nbucket = BCACHE_STATIC_N;   /* power of two */
static uint32_t       g_hand;
static uint64_t       g_hits, g_miss, g_evict, g_promote;
static unsigned long  g_chain_broken;   /* corrupted-chain walks refused (M2176) */

static volatile int g_lock;
/* BCACHE_HOST_TEST: `cli` is privileged, so the host test would take a SIGSEGV
 * on the first lock. Same accommodation kheap.c already makes for the same
 * reason -- the atomic exchange is kept, so what the test exercises is still
 * the real bookkeeping, just without the interrupt masking that a
 * single-threaded userspace process has no use for. (M2176) */
static inline uint64_t bc_lock(void) {
    uint64_t f = 0;
#ifndef BCACHE_HOST_TEST
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory");
#endif
    while (__atomic_exchange_n(&g_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return f;
}
static inline void bc_unlock(uint64_t f) {
    __atomic_store_n(&g_lock, 0, __ATOMIC_RELEASE);
#ifndef BCACHE_HOST_TEST
    __asm__ volatile("push %0; popfq" : : "r"(f) : "memory", "cc");
#else
    (void)f;
#endif
}

static inline uint32_t bc_hash(uint32_t owner, uint64_t lba) {
    /* Sector numbers are dense and owners are tiny, so mix rather than mask:
     * the low bits of an lba alone put a whole readahead window in one bucket. */
    uint64_t h = lba * 0x9E3779B97F4A7C15ull + (uint64_t)owner * 0x100000001B3ull;
    return (uint32_t)((h >> 29) ^ (h >> 13)) & (g_nbucket - 1);
}

/* Both called with the lock held. */
static void bc_unlink(uint32_t idx) {
    uint32_t b = bc_hash(g_meta[idx].owner, g_meta[idx].lba);
    uint32_t *pp = &g_bucket[b];
    while (*pp) {
        uint32_t i = *pp - 1;
        if (i == idx) { *pp = g_meta[i].next; g_meta[i].next = 0; return; }
        pp = &g_meta[i].next;
    }
}
static void bc_link(uint32_t idx) {
    uint32_t b = bc_hash(g_meta[idx].owner, g_meta[idx].lba);
    g_meta[idx].next = g_bucket[b];
    g_bucket[b] = idx + 1;
}
/* A CORRUPTED CHAIN MUST NOT HANG THE KERNEL (M2176).
 *
 * This walked the chain with no bound. A chain can only ever be as long as the
 * pool, so a walk that exceeds that has found a cycle -- and the walk runs
 * inside cli plus a spinlock, so the machine stops with no diagnostic and no
 * way back. Not hypothetical: mutating `bcache_install` to skip unlinking an
 * evicted victim -- exactly the kind of thing a later refactor gets wrong --
 * HUNG the new host test instead of failing it, which is how this was found.
 *
 * Bounded, it degrades to a miss, which is always a legal answer for a cache,
 * and says so once. A wrong answer would be worse, and a hang worse still. */
static int bc_find(uint32_t owner, uint64_t lba) {
    uint32_t steps = 0;
    for (uint32_t e = g_bucket[bc_hash(owner, lba)]; e; e = g_meta[e - 1].next) {
        if (e > g_ncap || ++steps > g_ncap) {       /* a cycle, or an index off the end */
            if (!g_chain_broken++)
                kprintf("[bcache] CHAIN CORRUPT in the bucket for owner %u lba %lu after %u "
                        "step(s) -- answering MISS. This bucket is degraded, not wrong.\n",
                        owner, (unsigned long)lba, steps);
            return -1;
        }
        struct bcmeta *m = &g_meta[e - 1];
        if (m->valid && m->owner == owner && m->lba == lba) return (int)(e - 1);
    }
    return -1;
}

/* CLOCK, with a second chance for anything that has been hit twice. Bounded by
 * 3 * ncap so a pathological all-protected pool still terminates — a cache that
 * can spin is worse than a cache that misses. */
static uint32_t bc_victim(void) {
    for (uint32_t guard = 0; guard < g_ncap * 3u; guard++) {
        uint32_t i = g_hand;
        g_hand = (g_hand + 1 >= g_ncap) ? 0 : g_hand + 1;
        if (!g_meta[i].valid) return i;
        if (g_meta[i].ref) { g_meta[i].ref = 0; continue; }
        if (g_meta[i].prot) { g_meta[i].prot = 0; continue; }   /* demote, don't evict */
        return i;
    }
    return g_hand;
}

/* THE RESIZE (M2154). kmalloc is called OUTSIDE the lock: allocating inside
 * cli + a spinlock is how M1531 deadlocked the kheap, and it is the same shape
 * here. Nothing is carried over from the old pool — this is a pure read cache,
 * so dropping it costs one re-read per live block and cannot be incorrect. */
int g_bcache_small;                  /* -append bcachesmall: A/B back to the 64 KiB pool */

void bcache_init(void) {
    if (g_bcache_small) {
        kprintf("[bcache] -append bcachesmall: staying at %u entries (64 KiB)\n", g_ncap);
        return;
    }
    uint64_t budget = pmm_free_bytes() / 32;
    if (budget > BCACHE_MAX_BYTES) budget = BCACHE_MAX_BYTES;
    uint32_t n = 1;
    while ((uint64_t)n * 2u * (BCACHE_SECSZ + sizeof(struct bcmeta) + 4) <= budget) n *= 2;
    if (n <= g_ncap) {
        kprintf("[bcache] %u entries (%u KiB), not grown: %lu MiB free\n",
                g_ncap, (g_ncap * BCACHE_SECSZ) >> 10, (unsigned long)(pmm_free_bytes() >> 20));
        return;
    }
    struct bcmeta *meta = (struct bcmeta *)kmalloc((size_t)n * sizeof(struct bcmeta));
    uint8_t *data = (uint8_t *)kmalloc((size_t)n * BCACHE_SECSZ);
    uint32_t *bucket = (uint32_t *)kmalloc((size_t)n * 4);
    if (!meta || !data || !bucket) {
        if (meta) kfree(meta);
        if (data) kfree(data);
        if (bucket) kfree(bucket);
        kprintf("[bcache] wanted %u entries (%lu MiB) and the heap refused -- staying at %u\n",
                n, (unsigned long)(((uint64_t)n * BCACHE_SECSZ) >> 20), g_ncap);
        return;
    }
    memset(meta, 0, (size_t)n * sizeof(struct bcmeta));
    memset(bucket, 0, (size_t)n * 4);
    uint64_t f = bc_lock();
    g_meta = meta; g_data = data; g_bucket = bucket;
    g_ncap = n; g_nbucket = n; g_hand = 0;
    bc_unlock(f);
    kprintf("[bcache] %u entries (%lu MiB of sectors), hashed, CLOCK with a second "
            "chance for twice-read blocks -- was %u entries (64 KiB), one readahead window\n",
            n, (unsigned long)(((uint64_t)n * BCACHE_SECSZ) >> 20), BCACHE_STATIC_N);
}

int bcache_lookup(uint32_t owner, uint64_t lba, void *buf) {
    uint64_t f = bc_lock();
    int i = bc_find(owner, lba);
    if (i >= 0) {
        memcpy(buf, g_data + (size_t)i * BCACHE_SECSZ, BCACHE_SECSZ);
        /* Second touch = keep it: this is what stops a 2 GiB sequential scan
         * from evicting the metadata the scan itself has to walk through. */
        if (g_meta[i].ref) { if (!g_meta[i].prot) g_promote++; g_meta[i].prot = 1; }
        g_meta[i].ref = 1;
        g_hits++;
        bc_unlock(f); return 1;
    }
    g_miss++;
    bc_unlock(f);
    return 0;
}

void bcache_install(uint32_t owner, uint64_t lba, const void *buf) {
    uint64_t f = bc_lock();
    int i = bc_find(owner, lba);
    if (i < 0) {
        uint32_t v = bc_victim();
        if (g_meta[v].valid) { bc_unlink(v); g_evict++; }
        g_meta[v].owner = owner; g_meta[v].lba = lba;
        g_meta[v].valid = 1; g_meta[v].ref = 0; g_meta[v].prot = 0;
        bc_link(v);
        i = (int)v;
    }
    memcpy(g_data + (size_t)i * BCACHE_SECSZ, buf, BCACHE_SECSZ);
    bc_unlock(f);
}

void bcache_inval(uint32_t owner, uint64_t lba) {
    uint64_t f = bc_lock();
    int i = bc_find(owner, lba);
    if (i >= 0) { bc_unlink((uint32_t)i); g_meta[i].valid = 0; }
    bc_unlock(f);
}

void bcache_inval_range(uint32_t owner, uint64_t lba, uint32_t count) {
    uint64_t f = bc_lock();
    /* Per-sector through the hash while that is the cheaper of the two, and a
     * full sweep once it is not. The crossover is the pool size: a range wider
     * than the cache cannot have more hits than the cache has entries. */
    if (count <= g_ncap) {
        for (uint32_t k = 0; k < count; k++) {
            int i = bc_find(owner, lba + k);
            if (i >= 0) { bc_unlink((uint32_t)i); g_meta[i].valid = 0; }
        }
    } else {
        for (uint32_t k = 0; k < g_ncap; k++)
            if (g_meta[k].valid && g_meta[k].owner == owner &&
                g_meta[k].lba >= lba && g_meta[k].lba < lba + count) {
                bc_unlink(k); g_meta[k].valid = 0;
            }
    }
    bc_unlock(f);
}

void bcache_inval_owner(uint32_t owner) {
    uint64_t f = bc_lock();
    for (uint32_t k = 0; k < g_ncap; k++)
        if (g_meta[k].valid && g_meta[k].owner == owner) { bc_unlink(k); g_meta[k].valid = 0; }
    bc_unlock(f);
}

void bcache_flush(void) {
    uint64_t f = bc_lock();
    for (uint32_t k = 0; k < g_ncap; k++) g_meta[k].valid = 0;
    for (uint32_t k = 0; k < g_nbucket; k++) g_bucket[k] = 0;
    bc_unlock(f);
}

/* HOW MANY WALKS FOUND A CORRUPT CHAIN (M2176). Exposed because the bound in
 * bc_find turns a corrupt chain into a MISS -- which is a legal answer, and so
 * invisible to a test whose invariant is "a hit must be correct". Hardening
 * that hides the bug it guards against is the same defect as no hardening;
 * this is what makes it observable. Must be zero. */
unsigned long bcache_chain_breaks(void) { return g_chain_broken; }

void bcache_counts(uint64_t *hits, uint64_t *miss) {
    uint64_t f = bc_lock();
    if (hits) *hits = g_hits; if (miss) *miss = g_miss;
    bc_unlock(f);
}

int bcache_stats(char *out, int max) {
    uint64_t f = bc_lock();
    uint32_t used = 0, prot = 0;
    for (uint32_t k = 0; k < g_ncap; k++) {
        if (g_meta[k].valid) used++;
        if (g_meta[k].valid && g_meta[k].prot) prot++;
    }
    uint64_t hits = g_hits, miss = g_miss, ev = g_evict, pr = g_promote;
    uint32_t cap = g_ncap;
    bc_unlock(f);
    /* tiny manual formatter (no snprintf in the freestanding kernel) */
    int n = 0;
    const char *labels[6] = { "entries ", " used ", " protected ", " hits ", " miss ", " evicted " };
    uint64_t vals[6] = { (uint64_t)cap, (uint64_t)used, (uint64_t)prot, hits, miss, ev };
    (void)pr;
    for (int i = 0; i < 6 && n < max - 24; i++) {
        for (const char *s = labels[i]; *s && n < max - 24; s++) out[n++] = *s;
        char tmp[24]; int t = 0; uint64_t v = vals[i];
        if (!v) tmp[t++] = '0'; else while (v) { tmp[t++] = (char)('0' + v % 10); v /= 10; }
        while (t) out[n++] = tmp[--t];
    }
    if (n < max) out[n++] = '\n';
    if (n < max) out[n] = 0;
    return n;
}

/* THE TEST THAT FAILS WITHOUT THE SIZE (M2154).
 *
 * Read a 1 MiB span of a disk, then read it again. The second pass can only hit
 * on blocks the cache still holds, so the hit rate IS the usable cache size,
 * measured rather than asserted from a constant: at 128 entries it is ~6%
 * (64 KiB of a 1 MiB span), and at 16384+ it is ~100%.
 *
 * Deliberately NOT a check against BCACHE_STATIC_N or any internal number --
 * a test that reads the same constant the code reads proves only that the
 * constant is itself. This one does I/O and counts what came back.
 *
 * `-append bcachesmall` restores the old pool and this must fail; that is the
 * revert proof, and it is a runtime flag so it needs no code edit to run.
 */
#define BCSELF_SECTORS 2048          /* 1 MiB, 16x the old whole-cache size */
void bcache_selftest(void) {
    extern int ata_read_drive(int drive, uint32_t lba, uint32_t count, void *buf);
    uint8_t *buf = (uint8_t *)kmalloc(BCACHE_SECSZ);
    if (!buf) { kprintf("BCACHESELF: SKIP (no heap)\n"); return; }
    bcache_flush();
    uint64_t h0 = 0, m0 = 0;
    bcache_counts(&h0, &m0);
    int bad = 0;
    for (uint32_t k = 0; k < BCSELF_SECTORS; k++)
        if (ata_read_drive(0, k, 1, buf) != 0) { bad = 1; break; }
    if (bad) { kfree(buf); kprintf("BCACHESELF: SKIP (no readable ata0)\n"); return; }
    uint64_t h1 = 0, m1 = 0;
    bcache_counts(&h1, &m1);
    for (uint32_t k = 0; k < BCSELF_SECTORS; k++)
        if (ata_read_drive(0, k, 1, buf) != 0) { bad = 1; break; }
    uint64_t h2 = 0, m2 = 0;
    bcache_counts(&h2, &m2);
    kfree(buf);
    uint64_t pass2_hits = h2 - h1, pass2_miss = m2 - m1;
    uint64_t tot = pass2_hits + pass2_miss;
    unsigned pct = tot ? (unsigned)((pass2_hits * 100) / tot) : 0;
    kprintf("BCACHESELF: %u entries; re-reading a %u KiB span hit %lu of %lu (%u%%) "
            "-- %s\n", g_ncap, (BCSELF_SECTORS * BCACHE_SECSZ) >> 10,
            (unsigned long)pass2_hits, (unsigned long)tot, pct,
            pct >= 90 ? "PASSED" : "FAILED: the cache cannot hold 1 MiB");
}
