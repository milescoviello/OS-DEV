/* lxmadv.c -- MADV_DONTNEED ON A FORK-SHARED PAGE DID NOTHING AND RETURNED 0.
 *
 * The kernel's MADV_DONTNEED reclaimed a page only when
 * `pmm_refcount(ph) == 0` -- "single-owner anon page: safe to reclaim". Every
 * page that a fork had left copy-on-write shared was therefore SKIPPED, and
 * madvise still returned success.
 *
 * But MADV_DONTNEED does not promise to free memory if that happens to be
 * convenient. It promises that THE NEXT READ OF THE RANGE SEES ZEROES. A page
 * left in place keeps whatever was written to it, and the caller has been told
 * it is gone -- so this is the campaign's dominant bug class exactly: a
 * mechanism answering with a plausible wrong value instead of failing.
 *
 * What it cost: mozjemalloc purges a free run with MADV_DONTNEED, records the
 * run as already-zeroed, and later hands it out for an allocation it therefore
 * does not clear. It also fills freed memory with 0xe5. Firefox forks, so much
 * of its heap is COW-shared -- and it read back a pointer field as
 * 0xe5e5e5e5e5e5e5e5, which is non-canonical, so:
 *
 *   [fault] General Protection Fault at rip=libc.so.6+971c4  rdi=e5e5e5e5e5e5e5e5
 *           == pthread_mutex_lock+4, `mov 0x10(%rdi),%edx`
 *
 * THE FORK IS THE WHOLE TEST. Without it every page is single-owner, the old
 * refcount test passes them, and the bug is invisible -- which is why an
 * madvise test that did not fork would have stayed green through all of this.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/wait.h>

static int fails;
#define CK(c, msg) do { if (c) printf("LXMADV: ok   %s\n", msg); \
                        else { printf("LXMADV: FAIL %s (errno %d %s)\n", msg, errno, strerror(errno)); fails++; } } while (0)

#define NPG   64
#define POISON 0xe5                     /* mozjemalloc's own free-fill byte */

static int all_bytes_are(const unsigned char *p, unsigned long n, int want) {
    for (unsigned long i = 0; i < n; i++) if (p[i] != (unsigned char)want) return 0;
    return 1;
}
static unsigned long first_bad(const unsigned char *p, unsigned long n, int want) {
    for (unsigned long i = 0; i < n; i++) if (p[i] != (unsigned char)want) return i;
    return n;
}

int main(void) {
    long ps = sysconf(_SC_PAGESIZE);
    unsigned long len = (unsigned long)ps * NPG;

    /* 1. THE UNSHARED CASE, which already worked -- included so that a
     *    regression in the common path cannot hide behind the new one. */
    unsigned char *a = mmap(0, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CK(a != MAP_FAILED, "mmap 64 anonymous pages");
    if (a == MAP_FAILED) return 1;
    memset(a, POISON, len);
    CK(all_bytes_are(a, len, POISON), "the region holds the poison we wrote");
    CK(madvise(a, len, MADV_DONTNEED) == 0, "madvise(MADV_DONTNEED) on unshared pages returns 0");
    CK(all_bytes_are(a, len, 0), "...and every byte of an UNSHARED region reads back zero");

    /* 2. THE CASE THAT WAS BROKEN: make the pages COW-shared with a fork
     *    FIRST, and only then purge them. The child must still be alive when
     *    madvise runs, or the pages are single-owner again by the time it
     *    matters and the test proves nothing. */
    memset(a, POISON, len);
    CK(all_bytes_are(a, len, POISON), "re-poisoned, ready to share");

    int pfd[2], cfd[2];
    if (pipe(pfd) || pipe(cfd)) { printf("LXMADV: FAIL pipe\n"); return 1; }
    pid_t kid = fork();
    if (kid != 0) CK(kid >= 0, "fork, so every page of the region becomes COW-shared");  /* the CHILD must not print it too */
    if (kid == 0) {
        char c;
        close(pfd[1]); close(cfd[0]);
        /* Touch nothing: the point is to hold a second reference to the
         * parent's pages, not to break them. */
        if (write(cfd[1], "r", 1) != 1) _exit(1);      /* "I exist" */
        if (read(pfd[0], &c, 1) != 1) _exit(1);        /* wait to be released */
        _exit(0);
    }
    close(pfd[0]); close(cfd[1]);
    { char c; CK(read(cfd[0], &c, 1) == 1, "the child is alive and holding a reference"); }

    int rc = madvise(a, len, MADV_DONTNEED);
    CK(rc == 0, "madvise(MADV_DONTNEED) on COW-SHARED pages returns 0");
    /* THE ASSERTION THE WHOLE FILE EXISTS FOR. */
    unsigned long bad = first_bad(a, len, 0);
    if (bad == len)
        printf("LXMADV: ok   every byte of a COW-SHARED region reads back ZERO after DONTNEED\n");
    else {
        printf("LXMADV: FAIL byte %lu of a COW-shared region reads 0x%02x, not 0 -- madvise "
               "returned success and kept the page (this is the Firefox 0xe5 crash)\n",
               bad, a[bad]);
        fails++;
    }

    /* 3. THE CHILD MUST BE UNAFFECTED. Dropping our view of a shared page may
     *    not drop the child's: pmm_free_frame decrements a refcounted frame
     *    rather than freeing it. If this ever fails, the fix traded one
     *    corruption for a worse one. */
    if (write(pfd[1], "g", 1) != 1) { printf("LXMADV: FAIL release the child\n"); fails++; }
    int st = 0;
    CK(waitpid(kid, &st, 0) == kid, "reaped the child");
    CK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
       "the child survived its parent purging pages they shared");

    /* 4. Writing after the purge must work, and must not resurrect old data. */
    memset(a, 0x42, ps);
    CK(all_bytes_are(a, (unsigned long)ps, 0x42), "the purged region is writable again");
    CK(all_bytes_are(a + ps, len - ps, 0), "...and the pages past it are still zero");

    munmap(a, len);
    if (!fails) printf("LXMADV: OK\n");
    else        printf("LXMADV: %d failure(s)\n", fails);
    printf("LXMADV: done\n");
    return fails ? 1 : 0;
}
