/* Exercise MAP_FIXED (M1952): reserve at an address WE choose, then prove the
 * kernel honoured it -- i.e. returned that exact address and the memory is
 * usable. This is the primitive ld.so needs to place shared objects and V8
 * needs to reserve its heap cage, so "did it come back at the address I asked
 * for" is the whole question. */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

int main(void) {
    /* First take a normal (kernel-chosen) mapping so we know a good region,
     * then unmap it and re-request that EXACT address with MAP_FIXED. Picking
     * an address blind would be a test of luck, not of MAP_FIXED. */
    size_t len = 64 * 1024;
    void *probe = mmap(NULL, len, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe == MAP_FAILED) { printf("LXMMAP: probe mmap failed\n"); fflush(stdout); return 1; }
    munmap(probe, len);

    void *want = probe;
    void *got = mmap(want, len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (got == MAP_FAILED) { printf("LXMMAP: MAP_FIXED refused\n"); fflush(stdout); return 2; }
    if (got != want) { printf("LXMMAP: MAP_FIXED gave a DIFFERENT address\n"); fflush(stdout); return 3; }

    /* And it must actually be usable memory, not just a bookkeeping entry. */
    memset(got, 0xA5, len);
    unsigned char *p = got;
    for (size_t i = 0; i < len; i++)
        if (p[i] != 0xA5) { printf("LXMMAP: byte %zu did not stick\n", i); fflush(stdout); return 4; }

    printf("LXMMAP: MAP_FIXED honoured at the requested address, %zu bytes readable/writable\n", len);
    fflush(stdout);
    return 0;
}
