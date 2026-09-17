/*
 * e2race.c — prove the ext2 path cache answers correctly when eight cores use
 * it at once (M2155).
 *
 * WHY THIS TEST EXISTS. `walk_cached()` in ext2.c (M2104) is a 256-entry
 * path->inode cache with no lock. On eight cores two inserts scan the same LRU
 * array, choose the same victim slot, and interleave their field writes, so the
 * slot ends up holding one path's NAME with the other's INODE or `negative`
 * flag. A later lookup of a good library path then answers "absent",
 * ext2_pread returns -1, and — before M2155's second fix — the page-fault
 * handler mapped the still-zero frame over executable code and reported the
 * fault resolved. Firefox died in a function half a megabyte from the cause,
 * two runs in three, on eight cores only.
 *
 * WHAT IT ASSERTS, and why it is not circular. Not "the slots look right" —
 * that reads the same state the bug corrupts. It does the thing the corruption
 * breaks: read the first bytes of several hundred REAL files on the ext2
 * volume, concurrently, from one thread per core, and require every read to
 * return bytes. A torn cache entry produces a -1 or a short read from the wrong
 * inode, and both are counted as failures. There is no path through this test
 * that a correct cache fails and no path through it that the racy cache passes
 * reliably.
 *
 * MORE PATHS THAN SLOTS, ON PURPOSE. 256 entries means the pressure — and so
 * the victim collisions — only happen when the working set exceeds the table.
 * The old cache passed every single-threaded test in the tree precisely because
 * nothing ever contended a slot.
 */
#include "vfs.h"
#include "kheap.h"
#include "smpthread.h"
#include "console.h"
#include "smp.h"
#include <stdint.h>

#define E2R_PATHS   800            /* > E2PC_N (256), so victim slots collide */
#define E2R_THREADS 8
#define E2R_ITERS   4000           /* per thread */

static char  (*g_e2r_path)[VFS_PATH_MAX];
static unsigned *g_e2r_sig;                 /* a hash of each path's first 512 bytes */
static int     g_e2r_npath;
static volatile unsigned long g_e2r_reads, g_e2r_fail, g_e2r_short, g_e2r_wrong;
static volatile int g_e2r_done;
static volatile int g_e2r_told;

/* Collect real files from a few populated directories of the ext2 volume. */
static void e2r_collect(const char *dir) {
    if (g_e2r_npath >= E2R_PATHS) return;
    vfs_dirent *d = (vfs_dirent *)kmalloc(sizeof(vfs_dirent) * 128);
    if (!d) return;
    int n = vfs_list_path(dir, d, 128);
    for (int i = 0; i < n && g_e2r_npath < E2R_PATHS; i++) {
        if (!d[i].size) continue;                   /* skip directories / empty files */
        char *p = g_e2r_path[g_e2r_npath];
        int k = 0;
        for (const char *s = dir; *s && k < VFS_PATH_MAX - 2; s++) p[k++] = *s;
        if (k && p[k - 1] != '/') p[k++] = '/';
        for (const char *s = d[i].name; *s && k < VFS_PATH_MAX - 1; s++) p[k++] = *s;
        p[k] = 0;
        g_e2r_npath++;
    }
    kfree(d);
}

/* COMPARE THE BYTES, NOT THE RETURN CODE (M2155).
 *
 * The first version of this worker required only that the read SUCCEED, and it
 * passed with the racy cache deliberately restored -- because the dominant
 * symptom of a torn slot is not a failure. It is a slot holding one path's NAME
 * with another path's INODE, and a read through that entry succeeds and returns
 * the WRONG FILE'S BYTES. A test that checks the return code cannot see the bug
 * it was written for: the same "instrument measuring the wrong quantity" that
 * this whole hunt has been made of.
 *
 * So the validation pass records every path's first 16 bytes, and the
 * concurrent pass requires exactly those bytes back. */
/* A HASH OF 512 BYTES, NOT 16 (M2155). Sixteen bytes is not a signature on
 * this volume: every ELF shares its first 16, and the 600 mime files share an
 * XML declaration -- so a 16-byte check left 13 distinguishable paths out of
 * 547, far under the 256-entry table, and the working set that makes the bug
 * possible vanished. Length is folded in, so a short file cannot collide with
 * a longer one that starts the same way. */
#define E2R_SIGBYTES 512
static unsigned e2r_hash(const unsigned char *p, long n) {
    unsigned h = 2166136261u ^ (unsigned)n;
    for (long i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h ? h : 1u;                        /* 0 means "no signature" */
}

static void e2r_worker(void *arg) {
    unsigned seed = (unsigned)(uintptr_t)arg * 2654435761u + 12345u;
    unsigned char *buf = (unsigned char *)kmalloc(E2R_SIGBYTES);
    if (!buf) { __atomic_add_fetch(&g_e2r_done, 1, __ATOMIC_RELAXED); return; }
    for (int it = 0; it < E2R_ITERS; it++) {
        seed = seed * 1103515245u + 12345u;
        int idx = (int)((seed >> 8) % (unsigned)g_e2r_npath);
        long got = vfs_pread(g_e2r_path[idx], buf, E2R_SIGBYTES, 0);
        __atomic_add_fetch(&g_e2r_reads, 1, __ATOMIC_RELAXED);
        if (got < 0) __atomic_add_fetch(&g_e2r_fail, 1, __ATOMIC_RELAXED);
        else {
            unsigned h = e2r_hash(buf, got);
            if (h != g_e2r_sig[idx]) {
                __atomic_add_fetch(&g_e2r_wrong, 1, __ATOMIC_RELAXED);
                if (!__atomic_exchange_n(&g_e2r_told, 1, __ATOMIC_ACQ_REL))
                    kprintf("E2PCRACE: %s hashed to %x, not %x (%ld bytes) -- this path "
                            "resolved to ANOTHER FILE'S inode\n",
                            g_e2r_path[idx], h, g_e2r_sig[idx], got);
            }
        }
        if ((it & 63) == 0) smp_thread_yield();
    }
    kfree(buf);
    __atomic_add_fetch(&g_e2r_done, 1, __ATOMIC_RELAXED);
}

void ext2_path_cache_race_test(void) {
    g_e2r_path = (char (*)[VFS_PATH_MAX])kmalloc(E2R_PATHS * VFS_PATH_MAX);
    g_e2r_sig  = (unsigned *)kmalloc(E2R_PATHS * sizeof(unsigned));
    if (!g_e2r_path || !g_e2r_sig) { kprintf("E2PCRACE: SKIP (no heap)\n"); return; }
    g_e2r_npath = 0;
    /* MORE PATHS THAN THE CACHE HAS SLOTS IS THE WHOLE POINT. The first cut of
     * this test found 221 files -- under the 256-entry table -- so no entry was
     * ever a victim and the collision the bug lives in never happened. It
     * passed, and it would have passed on the broken code. /usr/share/mime
     * alone holds 610 small files, which is what this needs. */
    e2r_collect("/disk2/usr/share/mime/application");
    e2r_collect("/disk2/usr/share/mime/text");
    e2r_collect("/disk2/usr/lib64/firefox");
    e2r_collect("/disk2/usr/lib64");
    e2r_collect("/disk2/usr/bin");
    e2r_collect("/disk2/etc/fonts/conf.avail");
    e2r_collect("/disk2/usr/share/fonts/dejavu");
    /* VALIDATE THE PATHS SINGLE-THREADED FIRST (and drop the directories:
     * vfs_dirent carries no is_dir, and an ext2 directory has a non-zero size,
     * so the listing alone cannot tell them apart -- and reading a directory
     * legitimately returns -1, which would have been counted as the very
     * failure this test is looking for).
     *
     * This pass is also the baseline: after it, every path in the array is
     * KNOWN to read successfully with one core using the cache. Any failure in
     * the concurrent phase is therefore concurrency, and nothing else. */
    {
        unsigned char *probe = (unsigned char *)kmalloc(E2R_SIGBYTES);
        if (!probe) { kprintf("E2PCRACE: SKIP (no heap)\n"); kfree(g_e2r_path); kfree(g_e2r_sig); return; }
        int keep = 0;
        for (int i = 0; i < g_e2r_npath; i++) {
            long got = vfs_pread(g_e2r_path[i], probe, E2R_SIGBYTES, 0);
            if (got <= 0) continue;                       /* a directory, or absent */
            if (keep != i) for (int k = 0; k < VFS_PATH_MAX; k++)
                g_e2r_path[keep][k] = g_e2r_path[i][k];
            g_e2r_sig[keep] = e2r_hash(probe, got);
            keep++;
        }
        kfree(probe);
        kprintf("E2PCRACE: %d of %d listed entries read cleanly single-threaded\n",
                keep, g_e2r_npath);
        g_e2r_npath = keep;
    }
    /* DROP PATHS THAT SHARE A SIGNATURE: two files indistinguishable in their
     * first 512 bytes cannot witness a swap between them, so keeping both would
     * dilute the test with reads that pass whichever inode answered. */
    {
        int keep = 0;
        for (int i = 0; i < g_e2r_npath; i++) {
            int dup = 0;
            for (int j = 0; j < keep; j++) if (g_e2r_sig[i] == g_e2r_sig[j]) { dup = 1; break; }
            if (dup) continue;
            if (keep != i) {
                for (int k = 0; k < VFS_PATH_MAX; k++) g_e2r_path[keep][k] = g_e2r_path[i][k];
                g_e2r_sig[keep] = g_e2r_sig[i];
            }
            keep++;
        }
        kprintf("E2PCRACE: %d of those have a DISTINCT 512-byte signature, so a swapped "
                "inode is observable\n", keep);
        g_e2r_npath = keep;
    }
    if (g_e2r_npath < 64) {
        kprintf("E2PCRACE: SKIP (only %d readable files found on /disk2 -- is the ext2 image "
                "attached?)\n", g_e2r_npath);
        kfree(g_e2r_path); return;
    }
    kprintf("E2PCRACE: hammering %d real ext2 paths (cache holds 256) from %d threads, "
            "%d reads each...\n", g_e2r_npath, E2R_THREADS, E2R_ITERS);
    smp_thread_t *t[E2R_THREADS];
    int spawned = 0;
    for (int i = 0; i < E2R_THREADS; i++) {
        t[i] = smp_thread_spawn(e2r_worker, (void *)(uintptr_t)(i + 1));
        if (t[i]) spawned++;
    }
    for (int i = 0; i < E2R_THREADS; i++) if (t[i]) smp_thread_join(t[i]);
    unsigned long reads = g_e2r_reads, fail = g_e2r_fail, shrt = g_e2r_short, wrong = g_e2r_wrong;
    kprintf("E2PCRACE: %lu reads across %d spawned thread(s): %lu FAILED (-1), %lu short, "
            "%lu WRONG BYTES -- %s\n", reads, spawned, fail, shrt, wrong,
            (fail == 0 && shrt == 0 && wrong == 0)
                ? "PASSED"
                : "FAILED: a concurrent lookup answered wrong, which is how an executable "
                  "page became zeros");
    kfree(g_e2r_path); kfree(g_e2r_sig);
}
