/*
 * lxvmagap.c -- a big anonymous mmap must never land on top of an existing
 * mapping (M1965).
 *
 * app_mmap found a free gap and THEN rounded the result up to 2 MiB, so that
 * mappings >= 2 MiB could be folded into hugepages by MADV_COLLAPSE. The
 * rounding walked the mapping up to 2 MiB - 4 KiB past the gap that had just
 * been verified, onto whatever VMA followed it, and nothing re-checked. Two
 * VMAs then owned the same pages and the first munmap of either freed the
 * frames out from under the other.
 *
 * It surfaced as Node dying AFTER a successful socket round-trip, reading a
 * pointer out of a region it still owned. Only mappings >= 2 MiB were
 * affected, and only when a VMA sat right after the chosen gap, which is why
 * it came and went -- roughly one Node run in three.
 *
 * The construction here makes it deterministic rather than probable:
 *
 *   1. Fill the low mmap window with A so nothing can be placed below B.
 *   2. Map B and stamp every page with a value derived from its own address.
 *   3. Punch a hole in B at a deliberately NON-2 MiB-aligned offset, slightly
 *      larger than the request to come. That is now the first gap big enough.
 *   4. Ask for a 2 MiB mapping. The gap fits it, so the buggy search returns
 *      the hole's start -- and then rounds up past the hole's end into B's
 *      surviving tail.
 *   5. Write over the new mapping and check B's stamps are still there.
 *
 * A mapping that aliases another is not "a bit wrong": the second write
 * silently destroys the first region's data. So the assertion is on the DATA,
 * not on the addresses -- an overlap that somehow did no damage is not what
 * this is guarding against.
 */
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>

#define MB (1024UL * 1024UL)
#define PG 4096UL

static uint64_t stamp(unsigned char *page) { return (uint64_t)(uintptr_t)page ^ 0x5DEADBEEF1234567ULL; }

int main(void) {
    const size_t alen = 64 * MB, blen = 16 * MB, want = 2 * MB;

    unsigned char *a = mmap(NULL, alen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *b = mmap(NULL, blen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (a == MAP_FAILED || b == MAP_FAILED) { printf("LXVMAGAP: setup mmap failed\n"); fflush(stdout); return 1; }

    for (size_t o = 0; o < blen; o += PG) *(uint64_t *)(b + o) = stamp(b + o);

    /* The hole: starts 4 KiB off a 2 MiB boundary, and is 8 KiB larger than
     * the request, so the request fits in it but its 2 MiB-aligned rounding
     * does not. */
    unsigned char *hole = b + 4 * MB + PG;
    size_t hlen = want + 2 * PG;
    if (munmap(hole, hlen) != 0) { printf("LXVMAGAP: hole munmap failed\n"); fflush(stdout); return 2; }

    unsigned char *c = mmap(NULL, want, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (c == MAP_FAILED) { printf("LXVMAGAP: 2MiB mmap failed\n"); fflush(stdout); return 3; }
    for (size_t o = 0; o < want; o += PG) c[o] = 0xAA;          /* scribble over every page of it */

    /* Now re-read B. Everything outside the hole must be exactly as stamped. */
    size_t hoff = (size_t)(hole - b);
    for (size_t o = 0; o < blen; o += PG) {
        if (o >= hoff && o < hoff + hlen) continue;             /* the hole: legitimately gone */
        uint64_t got = *(uint64_t *)(b + o), wantv = stamp(b + o);
        if (got != wantv) {
            printf("LXVMAGAP: OVERLAP -- B+0x%zx was overwritten (got %016llx want %016llx); "
                   "b=%p hole=%p new=%p\n", o, (unsigned long long)got, (unsigned long long)wantv,
                   (void *)b, (void *)hole, (void *)c);
            fflush(stdout);
            return 4;
        }
    }
    printf("LXVMAGAP: a 2MiB mmap next to an unaligned gap did not alias the mapping after it "
           "(b=%p new=%p, %zu pages verified)\n", (void *)b, (void *)c, blen / PG);
    fflush(stdout);
    (void)a;
    return 0;
}
