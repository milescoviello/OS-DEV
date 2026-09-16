/* lxzero.c -- ANONYMOUS MEMORY MUST BE ZERO, EVERY TIME IT IS HANDED OVER.
 *
 * JavaScriptCore's heap crashes inside the parallel marker on a JSValue that
 * passes isCell() and is not a pointer -- 0x9000900090, a repeating 16-bit
 * pattern, which is what recycled memory looks like and what zeroed memory
 * does not. A garbage collector reads every word it ever allocated, so it is
 * the most sensitive consumer of this invariant in the system, and the least
 * able to say which page was wrong.
 *
 * Every case below is a distinct way for a page to arrive dirty: a first
 * fault, a re-fault after MADV_DONTNEED, a MAP_FIXED replacement, an address
 * reused after munmap, and a COW break. They are checked with a pattern
 * written BEFORE each discard, so a page that merely kept its old contents
 * fails rather than passing by luck on a fresh frame.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdint.h>

#define MB (1024UL * 1024UL)
static int fails;

/* Report the FIRST non-zero word and its offset: "not zero" is not actionable,
 * "offset 0x3000 holds 0x9000900090" says which page and which recycled use. */
static int all_zero(const char *what, volatile uint64_t *p, size_t bytes) {
    size_t n = bytes / 8;
    for (size_t i = 0; i < n; i++)
        if (p[i] != 0) {
            printf("LXZERO: FAIL %s -- offset 0x%lx holds 0x%lx, not zero\n",
                   what, (unsigned long)(i * 8), (unsigned long)p[i]);
            fails++;
            return 0;
        }
    printf("LXZERO: %s is zero across %lu MiB\n", what, (unsigned long)(bytes / MB));
    return 1;
}

static void fill(volatile uint64_t *p, size_t bytes, uint64_t v) {
    for (size_t i = 0; i < bytes / 8; i++) p[i] = v;
}

int main(void) {
    const size_t SZ = 64 * MB;

    /* 1. A FIRST FAULT. */
    volatile uint64_t *m = mmap(NULL, SZ, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) { printf("LXZERO: FAIL mmap (%s)\n", strerror(errno)); return 1; }
    all_zero("a fresh anonymous mapping", m, SZ);

    /* 2. A RE-FAULT AFTER MADV_DONTNEED. This is how JSC decommits: it writes
     *    objects, hands the pages back, and expects zeros when it touches them
     *    again. Fill first, so keeping the old contents cannot pass. */
    fill(m, SZ, 0x9000900090UL);
    if (madvise((void *)m, SZ, MADV_DONTNEED) != 0)
        printf("LXZERO: FAIL madvise(MADV_DONTNEED) (%s)\n", strerror(errno)), fails++;
    else
        all_zero("re-faulted memory after MADV_DONTNEED", m, SZ);

    /* 3. MAP_FIXED OVER A LIVE MAPPING replaces it, so the new pages are new. */
    fill(m, SZ, 0xDEADBEEFDEADBEEFUL);
    volatile uint64_t *f = mmap((void *)m, SZ, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (f != m) { printf("LXZERO: FAIL MAP_FIXED moved (%p != %p)\n", (void *)f, (void *)m); fails++; }
    else all_zero("a MAP_FIXED replacement", m, SZ);

    /* 4. AN ADDRESS REUSED AFTER munmap. The allocator reuses VA ranges
     *    (M1962), so a new mapping at an old address must not see the old
     *    contents -- the case a bump allocator could never hit. */
    fill(m, SZ, 0x5A5A5A5A5A5A5A5AUL);
    munmap((void *)m, SZ);
    volatile uint64_t *m2 = mmap(NULL, SZ, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m2 == MAP_FAILED) { printf("LXZERO: FAIL second mmap\n"); return 1; }
    all_zero("a mapping at a REUSED address", m2, SZ);

    /* 5. A COW BREAK. The parent's pages go read-only at fork; the first write
     *    afterwards copies. The copy must carry the PARENT's bytes -- not the
     *    child's, not zeros, not another page. */
    const size_t CB = 4 * MB;
    volatile uint64_t *c = mmap(NULL, CB, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    fill(c, CB, 0xA5A5A5A5A5A5A5A5UL);
    pid_t pid = fork();
    if (pid == 0) {
        fill(c, CB, 0x1111111111111111UL);          /* the child's own copies */
        for (size_t i = 0; i < CB / 8; i++)
            if (c[i] != 0x1111111111111111UL) _exit(2);
        _exit(0);
    }
    fill(c, CB, 0xA5A5A5A5A5A5A5A5UL);              /* forces the parent's copies */
    int st = 0; waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("LXZERO: FAIL the child did not see its own COW copies (status %d)\n", st); fails++;
    }
    { size_t bad = 0;
      for (size_t i = 0; i < CB / 8; i++) if (c[i] != 0xA5A5A5A5A5A5A5A5UL) bad++;
      if (bad) { printf("LXZERO: FAIL %lu of %lu words lost their value across a COW break\n",
                        (unsigned long)bad, (unsigned long)(CB / 8)); fails++; }
      else printf("LXZERO: a COW break kept every one of %lu words\n", (unsigned long)(CB / 8));
    }

    /* 6. AND ZERO AFTER A FORK, because fork is where the page tables change
     *    most and a wrongly shared frame would show as somebody else's bytes. */
    volatile uint64_t *z = mmap(NULL, 16 * MB, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    pid = fork();
    if (pid == 0) {
        for (size_t i = 0; i < (16 * MB) / 8; i++) if (z[i] != 0) _exit(3);
        _exit(0);
    }
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("LXZERO: FAIL a mapping made before fork was not zero in the child (status %d)\n", st); fails++;
    } else printf("LXZERO: a mapping made before fork reads zero in the child too\n");
    all_zero("...and still zero in the parent", z, 16 * MB);

    printf(fails ? "LXZERO: FAILED\n" : "LXZERO: OK\n");
    return fails ? 1 : 0;
}
