/* lxcage -- reserve, align, TRIM, and then actually use the range.
 *
 * This is the shape JavaScriptCore (and therefore Bun, and therefore Claude
 * Code) uses for its pointer cage, taken verbatim from the kernel's own trace
 * of it:
 *
 *   [lxmmap] BIG anon request: addr=0 len=200000000 (8192 MiB) -> 146c00000
 *   [lxmmap] BIG munmap: addr=146c00000 len=b9400000   <- trim the head
 *   [lxmmap] BIG munmap: addr=300000000 len=46c00000   <- trim the tail
 *
 * Reserve TWICE the size you want, round the result up to the alignment you
 * want, and give back the two pieces you did not want. What is left is a
 * correctly aligned region -- and the engine then builds every pointer it owns
 * as `base + 32-bit offset` into it. If the trim takes the wrong range, or
 * takes everything, nothing fails at the time: mmap and munmap both report
 * success, and the program dies much later reading through a base address that
 * is no longer mapped, with no syscall anywhere near the crash.
 *
 * So the check is not "did munmap return 0". It is: write a recognisable
 * pattern across the whole kept region -- first page, last page, and a stride
 * through the middle -- and read it back. (M1999)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

static int fails;

#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0x4000
#endif

/* One reserve/align/trim/use cycle at a given size and alignment. */
static void cage(const char *what, size_t size, size_t align)
{
    size_t total = size + align;
    char *raw = mmap(0, total, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (raw == MAP_FAILED) {
        printf("LXCAGE: %s reserve of %zu MiB FAILED errno=%d\n", what, total >> 20, errno);
        fails++; return;
    }
    uintptr_t base = ((uintptr_t)raw + align - 1) & ~(uintptr_t)(align - 1);
    size_t head = base - (uintptr_t)raw;
    size_t tail = total - head - size;
    printf("LXCAGE: %s reserved %zu MiB at %p, aligned base %p (head %zu MiB, tail %zu MiB)\n",
           what, total >> 20, (void *)raw, (void *)base, head >> 20, tail >> 20);

    if (head && munmap(raw, head) != 0) {
        printf("LXCAGE: %s head trim FAILED errno=%d\n", what, errno); fails++; return;
    }
    if (tail && munmap((void *)(base + size), tail) != 0) {
        printf("LXCAGE: %s tail trim FAILED errno=%d\n", what, errno); fails++; return;
    }

    /* THE ACTUAL TEST. Both trims said 0; that is not the claim being checked.
     * Touch the first page, the last page, and a stride across the middle. */
    volatile unsigned char *p = (volatile unsigned char *)base;
    size_t stride = 64u << 20;                       /* every 64 MiB */
    size_t n = 0;
    for (size_t off = 0; off < size; off += stride) { p[off] = (unsigned char)(off / stride + 1); n++; }
    p[size - 1] = 0xAB;
    int bad = 0;
    n = 0;
    for (size_t off = 0; off < size; off += stride) {
        if (p[off] != (unsigned char)(off / stride + 1)) { bad++; }
        n++;
    }
    if (p[size - 1] != 0xAB) bad++;
    if (bad) { printf("LXCAGE: %s %d of %zu probe points did not read back\n", what, bad, n + 1); fails++; }
    else printf("LXCAGE: %s wrote and read back %zu points across the whole %zu MiB region\n",
                what, n + 1, size >> 20);
    munmap((void *)base, size);
}

int main(void)
{
    /* JSC's own numbers first: a 4 GiB region, 4 GiB-aligned. */
    cage("4GiB/4GiB", 4ull << 30, 4ull << 30);
    /* Then the small end, where an arithmetic mistake in the split shows up
     * without needing gigabytes of address space to be available. */
    cage("64MiB/64MiB", 64ull << 20, 64ull << 20);
    cage("1GiB/2MiB", 1ull << 30, 2ull << 20);

    /* And the case with NO head trim at all -- an already-aligned reservation.
     * A split that mishandles a zero-length head is a different bug from one
     * that mishandles a real one. */
    size_t sz = 32ull << 20;
    char *raw = mmap(0, sz * 2, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (raw == MAP_FAILED) { printf("LXCAGE: plain reserve FAILED errno=%d\n", errno); fails++; }
    else {
        if (munmap(raw + sz, sz) != 0) { printf("LXCAGE: tail-only trim FAILED errno=%d\n", errno); fails++; }
        else {
            volatile unsigned char *q = (volatile unsigned char *)raw;
            q[0] = 7; q[sz - 1] = 9;
            if (q[0] == 7 && q[sz - 1] == 9) printf("LXCAGE: a tail-only trim left the head usable\n");
            else { printf("LXCAGE: a tail-only trim damaged the head\n"); fails++; }
        }
        munmap(raw, sz);
    }

    printf("LXCAGE: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}
