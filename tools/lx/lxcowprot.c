/* lxcowprot.c -- mprotect MUST NOT BREAK COPY-ON-WRITE, OR FORGET A DIRTY PAGE.
 *
 * lxcow proves that two threads faulting on the same copy-on-write page do not
 * lose each other's writes. This proves something mprotect does to a COW page,
 * which no existing probe touches.
 *
 * `vmm_protect` kept the frame and replaced the PTE flags wholesale. PTE_COW is
 * a software bit marking a PRESENT page as write-protected ON PURPOSE, so that
 * the next write traps and privatises it. An mprotect that grants PTE_WRITABLE
 * while dropping COW hands the writer a frame STILL SHARED with whatever it was
 * forked from -- so two processes write one physical page and neither is told.
 *
 * That is not an exotic path. Firefox forks its content processes, and a JIT
 * mprotecting a region it has just forked over is ordinary. It is also the
 * shape this project has chased under the name "memory quietly changing under
 * them".
 *
 * ASSERTION 1 -- the one that fails when COW is dropped. The parent fills a
 * private mapping with its own marker and forks. The child mprotects the range
 * read-only and back to read-write -- which is what drives vmm_protect over
 * pages that are present and COW -- and then writes ITS marker over all of it.
 * The parent must still see its own. If the COW bit was dropped, the child's
 * write went into the page the parent is still reading.
 *
 * ASSERTION 2 -- the same thing without the round trip, since granting write on
 * an already-writable COW page is the single combination that shares silently:
 * the child mprotects straight to READ|WRITE and writes.
 *
 * ASSERTION 3 -- PTE_DIRTY. msync decides what to flush to a MAP_SHARED file by
 * looking for dirty PTEs, so an mprotect that clears DIRTY makes it skip a page
 * the program HAS written and the write is lost with nothing reported. Write
 * through a shared mapping, mprotect it read-only, msync, and require the FILE
 * to contain the bytes.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdint.h>

#define LEN   (256 * 1024)
#define PMARK 0xAA
#define CMARK 0xBB

static int child_rewrites(unsigned char *p, int via_readonly) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (via_readonly && mprotect(p, LEN, PROT_READ) != 0) _exit(11);
        if (mprotect(p, LEN, PROT_READ | PROT_WRITE) != 0) _exit(12);
        memset(p, CMARK, LEN);
        /* Touch it back afterwards so the write cannot be optimised away and so
         * the child definitely observes its own value. */
        if (p[LEN / 2] != CMARK) _exit(13);
        _exit(0);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) return -1;
    return (WIFEXITED(st) ? WEXITSTATUS(st) : 99);
}

static int check_parent_untouched(const unsigned char *p, const char *what) {
    for (int i = 0; i < LEN; i++)
        if (p[i] != PMARK) {
            printf("LXCOWPROT: FAIL %s -- byte %d of the PARENT's private mapping is %u, not "
                   "%u. The child's write landed in the parent's page: the copy-on-write bit "
                   "was dropped by mprotect and the frame is still shared.\n",
                   what, i, p[i], PMARK);
            return 1;
        }
    return 0;
}

int main(void) {
    int fails = 0;

    /* 1. mprotect READ then READ|WRITE, then write. */
    unsigned char *a = mmap(0, LEN, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (a == MAP_FAILED) { printf("LXCOWPROT: FAIL mmap\n"); return 1; }
    memset(a, PMARK, LEN);
    int rc = child_rewrites(a, 1);
    if (rc != 0) { printf("LXCOWPROT: FAIL child exited %d (round trip)\n", rc); fails++; }
    else fails += check_parent_untouched(a, "after a child's RO->RW mprotect");

    /* 2. mprotect straight to READ|WRITE, then write. */
    unsigned char *b = mmap(0, LEN, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (b == MAP_FAILED) { printf("LXCOWPROT: FAIL mmap 2\n"); return 1; }
    memset(b, PMARK, LEN);
    rc = child_rewrites(b, 0);
    if (rc != 0) { printf("LXCOWPROT: FAIL child exited %d (direct)\n", rc); fails++; }
    else fails += check_parent_untouched(b, "after a child's direct RW mprotect");

    /* 3. PTE_DIRTY must survive an mprotect, or msync forgets the page. */
    const char *path = "/tmp/lxcowprot.dat";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { printf("LXCOWPROT: SKIP dirty check (no %s)\n", path); }
    else {
        if (ftruncate(fd, LEN) != 0) { printf("LXCOWPROT: FAIL ftruncate\n"); fails++; }
        unsigned char *m = mmap(0, LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (m == MAP_FAILED) { printf("LXCOWPROT: FAIL mmap shared\n"); fails++; }
        else {
            memset(m, 0x5C, LEN);                 /* dirties every page */
            if (mprotect(m, LEN, PROT_READ) != 0) { printf("LXCOWPROT: FAIL mprotect RO\n"); fails++; }
            msync(m, LEN, MS_SYNC);
            munmap(m, LEN);
            unsigned char *buf = malloc(LEN);
            lseek(fd, 0, SEEK_SET);
            long got = buf ? read(fd, buf, LEN) : -1;
            int bad = -1;
            for (long i = 0; i < got; i++) if (buf[i] != 0x5C) { bad = (int)i; break; }
            if (got != LEN || bad >= 0) {
                printf("LXCOWPROT: FAIL the file has %ld bytes and byte %d is %u, not 92 -- an "
                       "mprotect cleared PTE_DIRTY and msync skipped a page the program had "
                       "written\n", got, bad, bad >= 0 ? buf[bad] : 0);
                fails++;
            }
            free(buf);
        }
        close(fd);
        unlink(path);
    }

    munmap(a, LEN); munmap(b, LEN);
    printf(fails ? "LXCOWPROT: %d FAILURE(S)\n" : "LXCOWPROT: ALL PASSED\n", fails);
    return fails ? 1 : 0;
}
