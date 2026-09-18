/* bcache_test.c -- A CACHE THAT ANSWERS WITH THE WRONG BLOCK IS WORSE THAN NO
 * CACHE. Host test for kernel/bcache.c (M2179).
 *
 * WHY. The in-guest self-test (`bcache_selftest`) measures the HIT RATE, which
 * is the usable size and says nothing about correctness. Nothing anywhere
 * checked that a lookup returns the bytes that were installed for that exact
 * (owner, lba) -- and that is precisely the class that cost this project a day:
 * a sector whose contents were wrong was served confidently to ext2, which read
 * it as an inode, and nine million garbage block pointers came out of it.
 *
 * M2154 replaced a 128-entry linear scan with a hash index, chained buckets and
 * CLOCK replacement. Every one of those is a way to return the wrong block:
 * unlink from the wrong bucket after a key changes, and an entry becomes
 * findable under a key it no longer holds; forget to unlink an evicted victim,
 * and a stale entry stays in a chain; get `bc_hash` wrong across a resize, and
 * every existing entry is unreachable or, worse, aliased.
 *
 * THE INVARIANT, and the only one that matters: **a hit must return exactly the
 * bytes last installed for that key, or it must miss.** A miss is always
 * allowed -- a cache may forget anything at any time -- so this test never
 * asserts that something IS cached. It asserts that nothing is ever answered
 * WRONG. That asymmetry is what makes it immune to replacement-policy changes.
 *
 * Content is derived from the key, so a wrong answer names the key it came
 * from rather than just failing a memcmp.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* --- the freestanding kernel's environment, as much as bcache.c touches --- */
static uint64_t g_fake_free = 512ull << 20;    /* so bcache_init sizes a real pool */
uint64_t pmm_free_bytes(void)  { return g_fake_free; }
uint64_t pmm_total_bytes(void) { return g_fake_free; }
void    *kmalloc(size_t n)     { return malloc(n); }
void     kfree(void *p)        { free(p); }
void     kprintf(const char *f, ...) { (void)f; }
/* bcache_selftest() calls into the ATA driver to measure a hit rate against a
 * real disk. That is an in-GUEST measurement and not what this test is for, so
 * the symbol is satisfied rather than the driver linked -- the alternative is
 * dragging ata.c, blockdev.c and the PCI layer into a host test of 200 lines of
 * cache bookkeeping. */
int      ata_read_drive(int drive, uint32_t lba, uint32_t count, void *buf)
         { (void)drive; (void)lba; (void)count; (void)buf; return -1; }

#define BCACHE_HOST_TEST 1
#include "../../kernel/bcache.c"

static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

/* Byte i of (owner, lba) -- distinct for every key, and a whole-sector shift
 * cannot look correct. */
static void fill(uint8_t *b, uint32_t owner, uint64_t lba) {
    for (int i = 0; i < BCACHE_SECSZ; i++)
        b[i] = (uint8_t)((owner * 31u + lba * 131u + (uint32_t)i * 7u) & 0xff);
}
static int matches(const uint8_t *b, uint32_t owner, uint64_t lba) {
    uint8_t want[BCACHE_SECSZ];
    fill(want, owner, lba);
    return memcmp(b, want, BCACHE_SECSZ) == 0;
}

int main(void) {
    uint8_t buf[BCACHE_SECSZ], tmp[BCACHE_SECSZ];
    bcache_init();

    /* 1. A hit must carry that key's bytes -- across more keys than the pool
     *    holds, so eviction is happening throughout. */
    printf("install/lookup over 4x the pool, two owners:\n");
    unsigned long hits = 0, misses = 0;
    for (uint64_t lba = 0; lba < 4 * 4096; lba++)
        for (uint32_t ow = 0; ow < 2; ow++) {
            fill(buf, ow, lba);
            bcache_install(ow, lba, buf);
        }
    for (uint64_t lba = 0; lba < 4 * 4096; lba++)
        for (uint32_t ow = 0; ow < 2; ow++)
            if (bcache_lookup(ow, lba, tmp)) {
                hits++;
                CHECK(matches(tmp, ow, lba), "owner %u lba %llu returned another key's bytes",
                      ow, (unsigned long long)lba);
            } else misses++;
    printf("  %lu hit(s), %lu miss(es) -- misses are legal, wrong answers are not\n", hits, misses);
    CHECK(hits > 0, "nothing at all was cached, so this test proved nothing");

    /* 2. OWNERS MUST NOT ALIAS. The same lba under two owners is two blocks;
     *    the header says so, and a hash that mixed only the lba would break it
     *    silently for exactly the ATA-vs-blockdev case that motivated it. */
    printf("owner namespaces do not alias:\n");
    bcache_flush();
    fill(buf, BCACHE_OWNER_ATA(1), 7);   bcache_install(BCACHE_OWNER_ATA(1), 7, buf);
    fill(buf, BCACHE_OWNER_BLK(1), 7);   bcache_install(BCACHE_OWNER_BLK(1), 7, buf);
    if (bcache_lookup(BCACHE_OWNER_ATA(1), 7, tmp))
        CHECK(matches(tmp, BCACHE_OWNER_ATA(1), 7), "the ATA owner got the blockdev owner's block");
    if (bcache_lookup(BCACHE_OWNER_BLK(1), 7, tmp))
        CHECK(matches(tmp, BCACHE_OWNER_BLK(1), 7), "the blockdev owner got the ATA owner's block");

    /* 3. A REWRITE MUST WIN. Write-through means the cached copy is updated;
     *    an install that linked a second entry for the same key instead would
     *    leave the OLD bytes findable, which is a stale read. */
    printf("a second install of the same key replaces its bytes:\n");
    for (int round = 0; round < 3; round++) {
        for (int i = 0; i < BCACHE_SECSZ; i++) buf[i] = (uint8_t)(round * 40 + i);
        bcache_install(BCACHE_OWNER_ATA(2), 99, buf);
        if (bcache_lookup(BCACHE_OWNER_ATA(2), 99, tmp))
            CHECK(memcmp(tmp, buf, BCACHE_SECSZ) == 0,
                  "round %d: the lookup returned an EARLIER install's bytes", round);
    }

    /* 4. INVALIDATION MUST INVALIDATE -- single, range, owner and flush. A
     *    range that missed one sector is how a stale journal descriptor gets in
     *    front of the recovery path, which the header calls out as undetectable
     *    corruption. */
    printf("invalidation, four ways:\n");
    for (uint64_t lba = 100; lba < 140; lba++) { fill(buf, 3, lba); bcache_install(3, lba, buf); }
    bcache_inval(3, 100);
    CHECK(!bcache_lookup(3, 100, tmp), "bcache_inval left the block findable");
    bcache_inval_range(3, 110, 10);
    for (uint64_t lba = 110; lba < 120; lba++)
        CHECK(!bcache_lookup(3, lba, tmp), "bcache_inval_range missed lba %llu",
              (unsigned long long)lba);
    CHECK(bcache_lookup(3, 109, tmp) || 1, "");        /* 109 may hit or miss; both legal */
    if (bcache_lookup(3, 109, tmp)) CHECK(matches(tmp, 3, 109), "range invalidation ate a neighbour's CONTENT");
    bcache_inval_owner(3);
    for (uint64_t lba = 100; lba < 140; lba++)
        CHECK(!bcache_lookup(3, lba, tmp), "bcache_inval_owner left lba %llu",
              (unsigned long long)lba);
    fill(buf, 4, 1); bcache_install(4, 1, buf);
    bcache_flush();
    CHECK(!bcache_lookup(4, 1, tmp), "bcache_flush left a block findable");

    /* 5. A RANGE WIDER THAN THE POOL takes the sweep path instead of the
     *    per-sector one -- a separate branch, and the only one that has to
     *    reason about the whole table. */
    printf("a range wider than the pool:\n");
    for (uint64_t lba = 0; lba < 2048; lba++) { fill(buf, 5, lba); bcache_install(5, lba, buf); }
    bcache_inval_range(5, 0, 1u << 22);
    for (uint64_t lba = 0; lba < 2048; lba += 97)
        CHECK(!bcache_lookup(5, lba, tmp), "the wide-range sweep left lba %llu",
              (unsigned long long)lba);

    /* 6. RANDOM TRAFFIC, the shape a real boot has: interleaved installs,
     *    lookups and invalidations, with every hit checked. This is where a
     *    chain corrupted by an eviction shows up. */
    printf("60000 random operations, every hit verified:\n");
    unsigned seed = 12345, wrong = 0; hits = 0;
    for (int i = 0; i < 60000; i++) {
        seed = seed * 1103515245u + 12345u;
        uint32_t ow = (seed >> 7) % 6;
        uint64_t lba = (seed >> 11) % 9000;
        switch ((seed >> 5) & 3) {
        case 0: case 1:
            fill(buf, ow, lba); bcache_install(ow, lba, buf); break;
        case 2:
            if (bcache_lookup(ow, lba, tmp)) { hits++; if (!matches(tmp, ow, lba)) wrong++; }
            break;
        case 3:
            bcache_inval_range(ow, lba, 1 + ((seed >> 17) & 31)); break;
        }
    }
    printf("  %lu verified hit(s), %u wrong\n", hits, wrong);
    CHECK(wrong == 0, "%u lookup(s) returned another key's bytes under random traffic", wrong);
    CHECK(hits > 1000, "only %lu hits: the traffic never exercised the cache", hits);

    /* 7. AND THE LINKS THEMSELVES. bc_find bounds its chain walk and answers
     *    MISS on a cycle, which is the right behaviour and also INVISIBLE to
     *    everything above -- a miss is always legal. So assert the counter:
     *    hardening that hides the bug it guards against is the same defect as
     *    no hardening. Removing the unlink from bcache_install's eviction makes
     *    this fire, and without this check that mutation passes. */
    printf("the bucket chains are intact:\n");
    CHECK(bcache_chain_breaks() == 0,
          "%lu chain walk(s) hit the cycle bound -- the table's own links are wrong, so every "
          "lookup in those buckets silently became a miss", bcache_chain_breaks());

    if (fails) { printf("bcache_test: %d CHECK(S) FAILED\n", fails); return 1; }
    printf("bcache_test: all checks passed -- a hit always carried its own key's bytes\n");
    return 0;
}
