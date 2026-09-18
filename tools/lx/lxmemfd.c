#define _GNU_SOURCE
/*
 * lxmemfd.c -- who OWNS the pages behind a memfd mapping? (M1985)
 *
 * A memfd's buffer lives in the KERNEL HEAP, and mmap()ing it aliases those
 * pages into the process. That makes two ordinary, documented things dangerous
 * if the kernel gets ownership wrong, and this binary does both:
 *
 *   1. mmap(), then munmap(). Unmapping walks the region and frees every page
 *      it finds. If those pages are not reference-counted, the first munmap
 *      hands live kernel-heap memory back to the physical allocator -- and the
 *      next allocation anywhere in the kernel gets memory the heap is still
 *      using. The symptom is never here: it is a corrupted buffer somewhere
 *      else entirely. So after unmapping we ALLOCATE AND DIRTY several
 *      megabytes to make the kernel hand those frames out again, then check
 *      the memfd's contents are still what we wrote.
 *
 *   2. mmap(), then close() while still mapped. That is the DOCUMENTED way to
 *      use a memfd -- every toolkit does it -- and if the mapping does not
 *      hold a reference to the object, the last close frees the buffer under a
 *      live mapping.
 *
 * A pass means the pattern survives both. A failure prints what it found.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define SZ  (64 * 1024)
#define PAT 0xA5
#define CHURN (4 * 1024 * 1024)

static int fails;
static void ok(int cond, const char *what) {
    printf("LXMEMFD-%s: %s\n", cond ? "OK" : "FAIL", what);
    fflush(stdout);
    if (!cond) fails++;
}

static int done(void) {
    printf("LXMEMFD-RESULT: %d failure(s)\n", fails);
    fflush(stdout);
    return fails ? 1 : 0;
}

static int count_pattern(const unsigned char *p, int n) {
    int bad = 0;
    for (int i = 0; i < n; i++) if (p[i] != PAT) bad++;
    return bad;
}

int main(void) {
    int fd = (int)syscall(SYS_memfd_create, "ownership", 0);
    if (fd < 0) { ok(0, "memfd_create"); return done(); }
    if (ftruncate(fd, SZ) != 0) { ok(0, "ftruncate"); return done(); }

    unsigned char *p = mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { ok(0, "first mmap"); return done(); }
    memset(p, PAT, SZ);
    ok(count_pattern(p, SZ) == 0, "wrote a pattern through a MAP_SHARED memfd mapping");

    /* (1) unmap, then make the kernel reuse whatever it just reclaimed. */
    munmap(p, SZ);
    unsigned char *churn = mmap(NULL, CHURN, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (churn == MAP_FAILED) { ok(0, "churn mmap"); return done(); }
    memset(churn, 0x5A, CHURN);            /* every page touched: they are really ours now */

    unsigned char *q = mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (q == MAP_FAILED) { ok(0, "re-mmap after munmap"); return done(); }
    int bad = count_pattern(q, SZ);
    if (bad) printf("LXMEMFD: %d of %d bytes were overwritten after munmap + 4 MiB of churn\n", bad, SZ);
    ok(bad == 0, "the memfd's contents SURVIVED munmap + 4 MiB of other allocations");

    /* (2) close while still mapped -- the documented pattern. */
    close(fd);
    memset(churn, 0x3C, CHURN);            /* churn again, now that the fd is gone */
    int bad2 = count_pattern(q, SZ);
    if (bad2) printf("LXMEMFD: %d of %d bytes changed after close() with the mapping live\n", bad2, SZ);
    ok(bad2 == 0, "the mapping OUTLIVED the last close() of the memfd");

    /* (3) A MAPPED memfd THAT GROWS MUST STILL BE ONE OBJECT (M2200).
     *
     * This kernel serves a memfd out of a kmalloc'd buffer, so growing one can
     * mean moving it -- and a buffer that some process has mapped cannot simply
     * be freed. M2082's answer was to RETIRE the old buffer and keep it alive,
     * which stops a use-after-free and silently unshares the object: from then
     * on the file's bytes are in the new buffer and the live mapping is looking
     * at the old one. Safe, and wrong -- and invisible, because both sides keep
     * working and merely stop agreeing.
     *
     * One process is enough to prove it. Write through the MAPPING and read the
     * same offset through the DESCRIPTOR: on Linux a file and its MAP_SHARED
     * mapping are the same bytes by definition, and if a grow has unshared them
     * here, these two reads disagree.
     *
     * The grow must be big enough to force a move. MEMFD headroom means a
     * resize usually fits in the capacity already allocated, so ask for
     * something far past it. */
    int g = (int)syscall(SYS_memfd_create, "grown-while-mapped", 0);
    if (g >= 0 && ftruncate(g, SZ) == 0) {
        unsigned char *m1 = mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED, g, 0);
        if (m1 != MAP_FAILED) {
            memset(m1, 0x11, SZ);
            /* Grow it by 64x while that mapping is live. */
            int grew = ftruncate(g, (off_t)SZ * 64);
            ok(grew == 0, "a memfd can be grown 64x while a mapping of it is live");
            /* Now write a distinct byte through the mapping... */
            m1[0] = 0x77; m1[SZ - 1] = 0x77;
            /* ...and read the same offsets through the descriptor. */
            unsigned char v0 = 0, vn = 0;
            ssize_t r0 = pread(g, &v0, 1, 0);
            ssize_t rn = pread(g, &vn, 1, SZ - 1);
            if (r0 == 1 && rn == 1 && (v0 != 0x77 || vn != 0x77))
                printf("LXMEMFD: after the grow the mapping and the descriptor DISAGREE: "
                       "wrote 77 through the mapping, the file says %02x at 0 and %02x at %d "
                       "-- the object was silently unshared\n", v0, vn, SZ - 1);
            ok(r0 == 1 && rn == 1 && v0 == 0x77 && vn == 0x77,
               "after growing a MAPPED memfd, the mapping and the file are still ONE object");
            munmap(m1, (size_t)SZ);
        } else ok(0, "mmap of the memfd that is about to grow");
    } else ok(0, "a second memfd for the grow-while-mapped case");
    if (g >= 0) close(g);

    /* (4) A MAPPING MADE AT AN OFFSET KNOWS WHICH BYTES IT COVERS (M2205).
     *
     * mmap's `offset` argument was accepted and honoured when the pages were
     * mapped, and then discarded -- `vma[].foff` was never set for a memfd
     * mapping -- so nothing afterwards could say which part of the object a
     * mapping was of. /proc/self/maps printed a hardcoded 00000000 for every
     * mapping in the process, which is why that was invisible: a field that
     * cannot disagree with the kernel proves nothing about it.
     *
     * Three separate defects lived behind it, all of the same shape (comparing
     * two different offsets): the remap in memfd_grow, the sharing audit, and
     * the wl_surface.commit check. This is the assertion that would have caught
     * all three from outside the kernel. */
    {   int o = (int)syscall(SYS_memfd_create, "offset-mapping", 0);
        if (o >= 0 && ftruncate(o, (off_t)SZ * 4) == 0) {
            const unsigned long OFF = 4096 * 3;
            unsigned char *mo = mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED, o, (off_t)OFF);
            if (mo != MAP_FAILED) {
                /* The mapping covers [OFF, OFF+SZ) of the object. Write a byte
                 * through it and require the DESCRIPTOR to see it at OFF --
                 * this is the part a wrong foff corrupts once the object moves. */
                mo[0] = 0x5E;
                unsigned char at_off = 0, at_zero = 0xFF;
                if (pread(o, &at_off, 1, (off_t)OFF) != 1) at_off = 0;
                if (pread(o, &at_zero, 1, 0) != 1) at_zero = 0xFF;
                ok(at_off == 0x5E, "a write through a mapping made at offset 12288 lands at 12288 in the file");
                ok(at_zero == 0, "...and NOT at offset 0");

                /* Now grow it enough to force the buffer to move, with that
                 * offset mapping live, and require the mapping to still be the
                 * same bytes. Pre-M2205 the remap re-pointed it at the wrong
                 * part of the new buffer. */
                if (ftruncate(o, (off_t)SZ * 64) == 0) {
                    mo[0] = 0x6F;
                    unsigned char after = 0;
                    if (pread(o, &after, 1, (off_t)OFF) != 1) after = 0;
                    if (after != 0x6F)
                        printf("LXMEMFD: after growing the object the offset mapping points "
                               "somewhere else: wrote 6f at object offset %lu, the file says "
                               "%02x there\n", OFF, after);
                    ok(after == 0x6F,
                       "after a grow, a mapping made at an offset still covers the same bytes");
                }

                /* And /proc/self/maps has to SAY which bytes, or none of the
                 * above is checkable without kernel access. */
                {   FILE *f = fopen("/proc/self/maps", "r");
                    char line[512]; int found = 0;
                    if (f) {
                        while (fgets(line, sizeof line, f)) {
                            unsigned long lo = 0, hi = 0, off2 = 0;
                            char perms[8];
                            if (sscanf(line, "%lx-%lx %7s %lx", &lo, &hi, perms, &off2) != 4) continue;
                            if (lo != (unsigned long)mo) continue;
                            found = 1;
                            if (off2 != OFF)
                                printf("LXMEMFD: /proc/self/maps says this mapping starts at "
                                       "object offset %lu; it was mmap'd at %lu\n", off2, OFF);
                            ok(off2 == OFF, "/proc/self/maps reports the mapping's real object offset");
                            break;
                        }
                        fclose(f);
                    }
                    if (!found) ok(0, "the offset mapping appears in /proc/self/maps");
                }
                munmap(mo, SZ);
            } else ok(0, "mmap of a memfd at a non-zero offset");
            close(o);
        } else ok(0, "a memfd for the offset-mapping case");
    }

    munmap(churn, CHURN);
    munmap(q, SZ);
    return done();
}
