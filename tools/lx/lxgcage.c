/* lxgcage -- the "reserve huge, trim to alignment, commit pieces" pattern
 * (M2035).
 *
 * JavaScriptCore builds its pointer cage exactly this way, and Claude Code
 * died inside it:
 *
 *   [vma] carve 107200000-200000000 cuts into vma[43] 107200000-307200000 (8192 MiB)
 *   [vma] carve 300000000-307200000 cuts into vma[43] 200000000-307200000 (4210 MiB)
 *   [fault] page fault at rip=...  CR2=0x300000005  in NO VMA of this process
 *
 * -- reserve 8 GiB, trim below the aligned 4 GiB base, trim above the limit,
 * then use it. Nothing in the existing mmap probes covers a reservation that
 * large being trimmed at BOTH ends and then partially committed, which is the
 * combination that loses the remainder.
 *
 * Every check below is about the RESERVATION still being there after the
 * operation, because that is what silently stopped being true.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>

static int fails;
static void ck(int cond, const char *what) {
    if (cond) printf("LXGCAGE: ok  %s\n", what);
    else { printf("LXGCAGE: FAIL %s\n", what); fails++; }
}

/* Is `p` usable? mprotect() on a page we believe is reserved must succeed; it
 * fails with ENOMEM if the range is not mapped at all, which is precisely the
 * "the reservation vanished" symptom. */
static int reserved(void *p) {
    return mprotect(p, 4096, PROT_READ | PROT_WRITE) == 0;
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    const size_t GiB = 1024ull * 1024 * 1024;
    const size_t want = 4 * GiB;          /* the cage */
    const size_t total = 8 * GiB;         /* reserve double, to guarantee alignment */

    char *res = mmap(0, total, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (res == MAP_FAILED) { printf("LXGCAGE: FAIL could not reserve 8 GiB\n"); return 1; }
    printf("LXGCAGE: reserved %p..%p\n", res, res + total);

    /* Align up to a 4 GiB boundary, exactly as the cage does. */
    uintptr_t base = ((uintptr_t)res + (want - 1)) & ~(uintptr_t)(want - 1);
    char *cage = (char *)base;
    size_t below = (size_t)(cage - res);
    size_t above = total - below - want;

    if (below) ck(munmap(res, below) == 0, "trimming below the aligned base succeeds");
    if (above) ck(munmap(cage + want, above) == 0, "trimming above the cage limit succeeds");
    printf("LXGCAGE: cage %p..%p\n", cage, cage + want);

    /* THE POINT. After trimming both ends, every page of the cage must still
     * be reserved -- especially the far end, which is what got lost. */
    ck(reserved(cage), "the cage's FIRST page is still reserved after both trims");
    ck(reserved(cage + want / 2), "...the MIDDLE page too");
    ck(reserved(cage + want - 4096), "...and the LAST page, 4 GiB in");

    /* Commit a slab near the start, the way a heap grows into its cage. */
    void *slab = mmap(cage, 16 * 1024 * 1024, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    ck(slab == cage, "committing 16 MiB at the cage base with MAP_FIXED lands there");
    if (slab == cage) { memset(slab, 0xA5, 4096); ck(((unsigned char *)slab)[0] == 0xA5, "...and it is writable"); }

    /* AND THE REST OF THE CAGE MUST SURVIVE THAT COMMIT. This is the assertion
     * that matters: a MAP_FIXED inside a reservation carves the reservation,
     * and the remainder has to stay mapped. */
    ck(reserved(cage + 64 * 1024 * 1024), "the cage 64 MiB in survives a commit at its base");
    ck(reserved(cage + want / 2), "...the middle survives it");
    ck(reserved(cage + want - 4096), "...and so does the last page");

    /* Commit a second slab far away, then re-check the first is untouched. */
    void *far = mmap(cage + 2 * GiB, 1024 * 1024, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    ck(far == cage + 2 * GiB, "a second commit 2 GiB into the cage lands where asked");
    if (far == cage + 2 * GiB) { memset(far, 0x5A, 4096); ck(((unsigned char *)far)[0] == 0x5A, "...and is writable"); }
    if (slab == cage) ck(((unsigned char *)slab)[0] == 0xA5, "the first slab's contents survived the second commit");

    /* MANY SMALL COMMITS, the way a heap actually grows into its cage. This is
     * the case the single-commit checks above miss: each MAP_FIXED carves the
     * reservation and re-inserts the remainder, so the remainder is rebuilt
     * dozens of times and only has to be dropped once. Claude Code's cage came
     * out of this as three fragments totalling 10 MiB out of 4 GiB. */
    {
        int committed = 0;
        for (int k = 0; k < 64; k++) {
            char *at = cage + (size_t)(k + 4) * 16 * 1024 * 1024;   /* every 16 MiB */
            void *g = mmap(at, 64 * 1024, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (g == at) { *(volatile unsigned char *)g = (unsigned char)k; committed++; }
        }
        ck(committed == 64, "64 small MAP_FIXED commits scattered through the cage all land");
        ck(reserved(cage + want - 4096), "the cage's LAST page is STILL reserved after 64 commits");
        ck(reserved(cage + want / 2 + 4096), "...and so is a page in the middle");
        /* and the earlier writes must not have been disturbed */
        int intact = 1;
        for (int k = 0; k < 64; k++) {
            char *at = cage + (size_t)(k + 4) * 16 * 1024 * 1024;
            if (*(volatile unsigned char *)at != (unsigned char)k) { intact = 0; break; }
        }
        ck(intact, "every one of the 64 slabs still holds what was written to it");
    }

    /* One page PAST the cage must NOT be mapped -- the trim has to be exact,
     * or the cage is bigger than it claims and the bug hides. */
    ck(!reserved(cage + want), "one page past the cage limit is NOT mapped (the trim was exact)");

    if (fails) { printf("LXGCAGE: %d FAILED\n", fails); return 1; }
    printf("LXGCAGE: all checks passed\n");
    return 0;
}
