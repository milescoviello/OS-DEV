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
    munmap(got, len);

    /* DOES AN ANONYMOUS MAPPING REMEMBER ITS OWN PROTECTION? (M1987)
     *
     * mprotect()ing the FIRST page of a mapping splits it, and the tail
     * inherits whatever protection the original mapping recorded. If it
     * recorded none -- which an anonymous mmap did, because nothing set the
     * field and zero means PROT_NONE -- then the first touch of a page in the
     * tail demand-faults, gets mapped with no write permission, and the write
     * faults again immediately: the kernel kills the process for writing to
     * memory it just granted read-write.
     *
     * The whole sequence is single-threaded and deterministic, which is the
     * point: the same defect only showed up under a browser otherwise. */
    size_t big = 2u << 20;
    unsigned char *q = mmap(NULL, big, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (q == MAP_FAILED) { printf("LXMMAP: split-prot mmap failed\n"); fflush(stdout); return 5; }
    q[0] = 0x11;                          /* page 0 is now present and writable */
    if (mprotect(q, 4096, PROT_READ) != 0) {
        printf("LXMMAP: mprotect(PROT_READ) failed\n"); fflush(stdout); return 6;
    }
    /* The first touch of a page in the TAIL. Reached only if the tail kept
     * read-write; otherwise the process is killed here and never prints. */
    q[4096] = 0x22;
    q[big - 1] = 0x33;
    if (q[4096] != 0x22 || q[big - 1] != 0x33) {
        printf("LXMMAP: tail writes did not stick\n"); fflush(stdout); return 7;
    }
    munmap(q, big);
    printf("LXMMAP-PROT: the tail of an mprotect-split anonymous mapping is still writable\n");
    fflush(stdout);
    return 0;
}
