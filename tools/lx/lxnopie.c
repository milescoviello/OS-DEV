/*
 * lxnopie.c -- a NON-PIE (ET_EXEC) Linux binary (M1970).
 *
 * Everything this OS ran before was position-independent, so it could be
 * relocated to ELF_DYN_BASE (0x40000000) and the low 1 GiB could stay a
 * supervisor-only identity map shared into every address space. An ET_EXEC
 * binary is linked at fixed low addresses and cannot be moved: it needs the
 * first gigabyte to belong to the process. That is what M1968 (kernel to the
 * higher half) and M1969 (stop inheriting the identity map) are for, and this
 * is the smallest thing that proves it.
 *
 * It checks three separate properties, because "it printed something" would
 * not distinguish them:
 *
 *   1. It RUNS at all -- code executing below 1 GiB in user mode.
 *   2. Its own address is actually low, so the loader did not quietly relocate
 *      it somewhere safe and make the test meaningless.
 *   3. A LARGE INITIALISED ARRAY reads back correctly. The interesting part of
 *      a big ET_EXEC image is a multi-megabyte data segment demand-paged from a
 *      non-page-aligned file offset; if the loader got that offset wrong, the
 *      program still starts and then reads plausible garbage. Claude Code's
 *      data segment is 137 MB at file offset 0x51f6ce0, so this is the shape
 *      that matters.
 */
#include <stdio.h>
#include <stdint.h>

/* ~2 MB of initialised data with a position-dependent pattern, so a page read
 * from the wrong file offset cannot accidentally match. */
#define N (256 * 1024)
static uint64_t table[N] = { 1 };          /* forces .data, not .bss */

int main(void) {
    for (long i = 0; i < N; i++) table[i] = (uint64_t)i * 0x9E3779B97F4A7C15ULL;

    long bad = -1;
    for (long i = 0; i < N; i++)
        if (table[i] != (uint64_t)i * 0x9E3779B97F4A7C15ULL) { bad = i; break; }

    unsigned long code = (unsigned long)(uintptr_t)&main;
    unsigned long data = (unsigned long)(uintptr_t)&table[0];

    if (bad >= 0) { printf("LXNOPIE: data CORRUPT at index %ld\n", bad); fflush(stdout); return 1; }
    if (code >= 0x40000000UL) {
        printf("LXNOPIE: not actually low -- main at %lx (relocated?)\n", code);
        fflush(stdout); return 2;
    }
    printf("LXNOPIE: ET_EXEC ran below 1 GiB -- main=%lx data=%lx, %d KiB of .data verified\n",
           code, data, (int)(N * sizeof(uint64_t) / 1024));
    fflush(stdout);
    return 0;
}
