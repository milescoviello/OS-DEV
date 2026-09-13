/*
 * lxnopiedyn.c -- a NON-PIE, DYNAMICALLY LINKED binary (M1970).
 *
 * This is Claude Code's exact shape, and the one combination nothing else here
 * covers:
 *
 *   lxdyn     ET_DYN + PT_INTERP   (ld.so, relocations, libc.so)
 *   lxnopie   ET_EXEC, static      (fixed low addresses, no interpreter)
 *   THIS      ET_EXEC + PT_INTERP  (both at once)
 *
 * The two halves interact: ld.so has to be told where the program headers are,
 * and for an ET_EXEC image AT_PHDR is NOT base + e_phoff -- it has to be
 * resolved through the PT_LOAD that contains them. Getting that wrong sends
 * ld.so to read an ELF header at 0x40 and the program dies before main with no
 * message. A C++-style static initialiser and a large malloc run before main
 * too, so they are exercised here on purpose.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static long ctor_ran;
__attribute__((constructor))
static void before_main(void) { ctor_ran = 0x5AFE; }

int main(void) {
    if (ctor_ran != 0x5AFE) { printf("LXNOPIEDYN: constructor did not run\n"); fflush(stdout); return 1; }

    /* Larger than glibc's 128 KiB mmap threshold, so this goes to mmap rather
     * than the brk heap -- the path a big runtime's allocator uses. */
    size_t n = 192 * 1024;
    unsigned char *p = malloc(n);
    if (!p) { printf("LXNOPIEDYN: malloc(%zu) failed\n", n); fflush(stdout); return 2; }
    memset(p, 0x5A, n);
    for (size_t i = 0; i < n; i++)
        if (p[i] != 0x5A) { printf("LXNOPIEDYN: heap byte %zu wrong\n", i); fflush(stdout); return 3; }
    free(p);

    unsigned long code = (unsigned long)(uintptr_t)&main;
    if (code >= 0x40000000UL) {
        printf("LXNOPIEDYN: not actually low -- main at %lx\n", code); fflush(stdout); return 4;
    }
    printf("LXNOPIEDYN: ET_EXEC + PT_INTERP ran -- main=%lx, ctor ok, %zu KiB mmap-heap verified\n",
           code, n / 1024);
    fflush(stdout);
    return 0;
}
