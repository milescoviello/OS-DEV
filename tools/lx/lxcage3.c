/* lxcage3 -- JSC's pointer cage, reproduced argument-for-argument (M2035).
 *
 * The trace from Claude Code says exactly what it asks for:
 *
 *   [lxmmap] BIG anon request: addr=0 len=200000000 (8192 MiB) prot=3 flags=4022 -> 107200000
 *   [vma] carve 107200000-200000000 cuts into vma[43] 107200000-307200000 (8192 MiB)
 *   [vma] carve 300000000-307200000 cuts into vma[43] 200000000-307200000 (4210 MiB)
 *
 * prot=3 is READ|WRITE and flags=0x4022 is PRIVATE|ANONYMOUS|NORESERVE -- the
 * whole cage is demand-paged RW from the start, so nothing needs to be
 * "committed" into it. After the two trims the cage should be ONE 4 GiB VMA.
 *
 * It was not. The crash dump showed it as three contiguous fragments totalling
 * ten megabytes, with everything above 0x200a20000 simply gone -- which is why
 * a read at 0x300000000 landed in no VMA at all.
 *
 * /proc/self/maps is the ground truth for a VMA's extent, so this reports the
 * cage's real size after every step rather than inferring it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>

static int fails;
static void ck(int c, const char *w) {
    if (c) printf("LXCAGE3: ok  %s\n", w);
    else { printf("LXCAGE3: FAIL %s\n", w); fails++; }
}

/* Total bytes of mapping that lie within [lo,hi), summed from /proc/self/maps. */
static unsigned long long mapped_in(uintptr_t lo, uintptr_t hi) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;
    static char buf[1 << 16];
    long n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    unsigned long long tot = 0;
    char *p = buf;
    while (*p) {
        unsigned long long a = 0, b = 0;
        int got = 0;
        while (*p == '\n') p++;
        char *q = p;
        while (*q && *q != '-' && *q != '\n') q++;
        if (*q == '-') {
            *q = 0; a = strtoull(p, 0, 16); got = 1; p = q + 1;
            char *r = p; while (*r && *r != ' ' && *r != '\n') r++;
            char save = *r; *r = 0; b = strtoull(p, 0, 16); *r = save; p = r;
        }
        while (*p && *p != '\n') p++;
        if (got && b > a) {
            unsigned long long s = a > lo ? a : lo, e = b < hi ? b : hi;
            if (e > s) tot += e - s;
        }
    }
    return tot;
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);
    const size_t GiB = 1024ull * 1024 * 1024;
    const size_t want = 4 * GiB, total = 8 * GiB;

    /* EXACTLY what the trace shows: prot=3, PRIVATE|ANONYMOUS|NORESERVE. */
    char *res = mmap(0, total, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (res == MAP_FAILED) { printf("LXCAGE3: FAIL 8 GiB reservation refused\n"); return 1; }
    uintptr_t base = ((uintptr_t)res + (want - 1)) & ~(uintptr_t)(want - 1);
    char *cage = (char *)base;
    printf("LXCAGE3: reservation %p, cage %p..%p\n", res, cage, cage + want);

    ck(mapped_in((uintptr_t)res, (uintptr_t)res + total) == total,
       "the 8 GiB reservation is fully mapped to begin with");

    size_t below = (size_t)(cage - res), above = total - below - want;
    if (below) ck(munmap(res, below) == 0, "trim below the aligned base");
    unsigned long long after1 = mapped_in(base, base + want);
    printf("LXCAGE3: cage mapped after trim 1: %llu MiB\n", after1 >> 20);
    ck(after1 == want, "the cage is STILL 4 GiB after trimming below it");

    if (above) ck(munmap(cage + want, above) == 0, "trim above the cage limit");
    unsigned long long after2 = mapped_in(base, base + want);
    printf("LXCAGE3: cage mapped after trim 2: %llu MiB\n", after2 >> 20);
    ck(after2 == want, "the cage is STILL 4 GiB after trimming above it");

    /* Touch the far end -- the access that killed Claude Code was near here. */
    volatile unsigned char *last = (volatile unsigned char *)(cage + want - 4096);
    *last = 0x5A;
    ck(*last == 0x5A, "the cage's LAST page is readable and writable");
    volatile unsigned char *mid = (volatile unsigned char *)(cage + want / 2);
    *mid = 0xA5;
    ck(*mid == 0xA5, "...and so is the middle");

    /* JSC mprotects sub-ranges of the cage as it hands memory out. Each one
     * splits the VMA; the remainder has to survive every split. */
    for (int k = 0; k < 32; k++) {
        char *at = cage + (size_t)k * 32 * 1024 * 1024;
        if (mprotect(at, 64 * 1024, PROT_READ | PROT_WRITE) != 0) { ck(0, "mprotect inside the cage"); break; }
    }
    unsigned long long after3 = mapped_in(base, base + want);
    printf("LXCAGE3: cage mapped after 32 mprotects: %llu MiB\n", after3 >> 20);
    ck(after3 == want, "the cage is STILL 4 GiB after 32 sub-range mprotects");
    ck(*last == 0x5A, "the far end still holds its byte after the mprotects");

    if (fails) { printf("LXCAGE3: %d FAILED\n", fails); return 1; }
    printf("LXCAGE3: all checks passed\n");
    return 0;
}
