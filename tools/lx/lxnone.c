/* lxnone.c -- PROT_NONE MUST FAULT, AND MUST NOT DISCARD WHAT IT PROTECTS.
 *
 * WHY THIS EXISTS. `app_mprotect` recorded the requested protection as
 * `(prot & 0x7) ? (prot & 0x7) : VMA_PROT_READ`, so a requested PROT_NONE was
 * written down as READ-ONLY. The fallback dated from when zero meant "not
 * recorded"; M1987 gave every mapping a real protection so that zero could
 * mean what it says, and M2060 then made the fault handler honour it. That one
 * line kept a requested PROT_NONE from ever reaching either of them, so a
 * reservation a program made PRECISELY so that touching it would fail answered
 * every read with a demand-zeroed page instead.
 *
 * It is not a theoretical case. glibc mprotects the gaps between a shared
 * object's segments PROT_NONE, so that a stray pointer into the padding traps
 * instead of reading a neighbouring segment. JavaScriptCore reserves its 4 GiB
 * structure heap PROT_NONE on purpose, so that StructureID 0 is an invalid id
 * -- if that reservation reads as zeroes, id 0 resolves to a zeroed Structure
 * and the failure surfaces as a garbage JSValue somewhere unrelated.
 *
 * A counter would not have caught it. What is needed is the guarantee itself:
 * a read of a PROT_NONE page must raise SIGSEGV. So take the signal, with
 * sigsetjmp/siglongjmp, and require it.
 *
 * Four assertions, and each checks something a different way of getting it
 * wrong would break:
 *   1. A read of a PROT_NONE'd region must SIGSEGV.  (recorded as READ-ONLY
 *      => it returns zeroes instead)
 *   2. A write to it must SIGSEGV.                   (recorded as READ-WRITE)
 *   3. Restoring PROT_READ must reveal the ORIGINAL bytes -- PROT_NONE must
 *      protect the page, not drop it.                (an implementation that
 *      unmapped the range would pass 1 and 2 and fail this)
 *   4. A region mmap'd PROT_NONE from the start must SIGSEGV on read, not
 *      demand-zero.                                  (this is the JSC case:
 *      the reservation is never anything else first)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>

#define LEN (64 * 1024)

static sigjmp_buf g_jb;
static volatile int g_caught;

static void segv(int sig) { (void)sig; g_caught = 1; siglongjmp(g_jb, 1); }

/* Returns 1 if the access raised SIGSEGV, 0 if it completed. `sink` keeps the
 * compiler from eliding a read whose value is unused. */
static volatile unsigned char g_sink;
static int faults_on_read(const volatile unsigned char *p) {
    g_caught = 0;
    if (sigsetjmp(g_jb, 1) == 0) { g_sink = *p; return 0; }
    return g_caught;
}
static int faults_on_write(volatile unsigned char *p) {
    g_caught = 0;
    if (sigsetjmp(g_jb, 1) == 0) { *p = 0x5a; return 0; }
    return g_caught;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = segv;
    sa.sa_flags = SA_NODEFER;          /* the handler longjmps out; do not leave SIGSEGV blocked */
    if (sigaction(SIGSEGV, &sa, 0) != 0) { printf("LXNONE: FAIL sigaction\n"); return 1; }
    /* SIGBUS too: a kernel that reports a refused access as a bus error rather
     * than a segmentation fault is still faulting, which is what is under
     * test; failing the run over the signal NUMBER would be testing the wrong
     * thing. */
    sigaction(SIGBUS, &sa, 0);

    int fails = 0;

    unsigned char *p = mmap(0, LEN, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { printf("LXNONE: FAIL mmap\n"); return 1; }
    for (int i = 0; i < LEN; i++) p[i] = (unsigned char)(i * 7 + 3);

    if (mprotect(p, LEN, PROT_NONE) != 0) { printf("LXNONE: FAIL mprotect PROT_NONE\n"); return 1; }

    if (!faults_on_read(p + 1234)) {
        printf("LXNONE: FAIL a READ of a PROT_NONE page did not fault -- it returned %u. "
               "A reservation made so that touching it fails is answering with data.\n", g_sink);
        fails++;
    }
    if (!faults_on_write(p + 4321)) {
        printf("LXNONE: FAIL a WRITE to a PROT_NONE page did not fault\n");
        fails++;
    }

    /* PROT_NONE protects; it does not discard. */
    if (mprotect(p, LEN, PROT_READ) != 0) { printf("LXNONE: FAIL mprotect back to READ\n"); return 1; }
    int bad = -1;
    for (int i = 0; i < LEN; i++)
        if (p[i] != (unsigned char)(i * 7 + 3)) { bad = i; break; }
    if (bad >= 0) {
        printf("LXNONE: FAIL byte %d changed across PROT_NONE (%u, expected %u) -- the range "
               "was dropped rather than protected\n", bad, p[bad], (unsigned char)(bad * 7 + 3));
        fails++;
    }

    /* The JavaScriptCore case: PROT_NONE from the start, never anything else. */
    unsigned char *q = mmap(0, LEN, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (q == MAP_FAILED) { printf("LXNONE: FAIL mmap PROT_NONE\n"); return 1; }
    if (!faults_on_read(q + 99)) {
        printf("LXNONE: FAIL a READ of a mapping created PROT_NONE did not fault -- it "
               "returned %u. This is the shape JavaScriptCore reserves its structure heap "
               "with, so that StructureID 0 is an invalid id.\n", g_sink);
        fails++;
    }

    /* AN UNALIGNED mprotect MUST BE REFUSED, NOT ROUNDED DOWN (M2197).
     *
     * `app_mprotect_nl` rounded `addr` down to a page boundary, so an
     * unaligned request changed the protection of the page holding the bytes
     * BEFORE it -- and returned 0. mprotect(2) requires a page-aligned
     * address and returns EINVAL; it does not round.
     *
     * Three assertions, and the SECOND is the one that matters. The return
     * value is cheap; the question is whether the neighbouring page is still
     * usable, because a kernel that returns EINVAL and revokes access anyway
     * would pass the first check. With the rounding restored, the write below
     * lands on a page that has just been made PROT_NONE and takes SIGSEGV --
     * a fault in code that never asked for anything to change, which is what
     * this bug looks like from the outside. */
    {
        long pg = 4096;
        unsigned char *r = mmap(0, pg * 3, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (r == MAP_FAILED) {
            printf("LXNONE: SKIP unaligned-mprotect (mmap failed)\n");
        } else {
            memset(r, 0x3c, (size_t)(pg * 3));
            errno = 0;
            int urc = mprotect(r + pg + 64, (size_t)pg, PROT_NONE);
            if (urc == 0) {
                printf("LXNONE: FAIL an unaligned mprotect(PROT_NONE) SUCCEEDED -- the "
                       "start was rounded DOWN, so the page before the address lost its "
                       "access rights and the caller was told the call worked\n");
                fails++;
            }
            if (urc != 0 && errno != EINVAL) {
                printf("LXNONE: FAIL an unaligned mprotect returned errno %d, not EINVAL\n", errno);
                fails++;
            }
            /* The page the rounding would have taken: still writable? */
            if (faults_on_write(r + pg)) {
                printf("LXNONE: FAIL the page BEFORE an unaligned mprotect lost its write "
                       "access -- the refusal did not protect the neighbour\n");
                fails++;
            }
            munmap(r, (size_t)(pg * 3));
        }
    }

    munmap(p, LEN); munmap(q, LEN);
    printf(fails ? "LXNONE: %d FAILURE(S)\n" : "LXNONE: ALL PASSED\n", fails);
    return fails ? 1 : 0;
}
