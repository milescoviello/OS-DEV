/* lxshcow -- does a fork() quietly unshare a MAP_SHARED mapping?
 *
 * THE BUG THIS EXISTS FOR (M2209). vmm_fork_cow write-protects EVERY page of
 * the parent, because it walks the page tables and the page tables do not
 * record which mappings are shared. Nothing afterwards undid that for the
 * shared ones -- so the first write to a MAP_SHARED page, by the parent or the
 * child, took the copy-on-write path and was given a PRIVATE COPY. From that
 * moment the mapping is no longer the object: both sides keep working and
 * quietly stop agreeing.
 *
 * It was found by a kernel-side audit, in a boot that rendered the page:
 *
 *   ** memfd 44 ('org.mozilla.ipc.166.45') is NOT SHARED with pid 166: object
 *   offset 0 is phys 2be76000, but the process's mapping at 1bed00000 resolves
 *   to 27030000 **
 *
 * pid 166 is the Firefox parent and that is its own mapping of its own IPC
 * buffer. Firefox forks per content process, so every shared buffer it held
 * across a fork was one write away from being unshared.
 *
 * Linux never copy-on-writes a shared mapping -- the page IS the object -- so
 * every expectation here is checkable against the host, which runs this binary.
 *
 * Four directions, because the bug is symmetric and fixing one side is this
 * codebase's favourite mistake:
 *   parent writes  -> child must see it
 *   child writes   -> parent must see it
 *   parent writes  -> the FILE must see it (memfd read, not the mapping)
 *   child writes   -> the FILE must see it
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>

static int fails;
static void ck(int ok, const char *what)
{
    if (!ok) { fails++; printf("LXSHCOW: FAIL -- %s\n", what); }
    else       printf("LXSHCOW: ok   -- %s\n", what);
    fflush(stdout);
}

#define SZ 65536

int main(void)
{
    int fd = (int)syscall(SYS_memfd_create, "forked-share", 0);
    if (fd < 0 || ftruncate(fd, SZ) != 0) {
        printf("LXSHCOW: could not make a memfd: %s\n", strerror(errno));
        return 1;
    }
    volatile unsigned char *p = mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { printf("LXSHCOW: mmap failed: %s\n", strerror(errno)); return 1; }

    /* Touch every page BEFORE the fork, so they are all resident and all get
     * write-protected by the fork -- which is the state the bug needs. */
    for (int i = 0; i < SZ; i += 4096) p[i] = 0x11;

    /* A second shared mapping, used to prove the two mappings in ONE process
     * still agree after the fork as well. */
    volatile unsigned char *q = mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (q == MAP_FAILED) { printf("LXSHCOW: second mmap failed\n"); return 1; }

    /* A pipe each way, so the two processes can take turns rather than racing. */
    int down[2], up[2];
    if (pipe(down) || pipe(up)) { printf("LXSHCOW: pipe failed\n"); return 1; }

    pid_t kid = fork();
    if (kid < 0) { printf("LXSHCOW: fork failed: %s\n", strerror(errno)); return 1; }

    if (kid == 0) {
        char c;
        /* 1. Wait for the parent's write, then check we can see it. */
        if (read(down[0], &c, 1) != 1) _exit(20);
        int saw_parent = (p[0] == 0xAA && p[SZ - 4096] == 0xAA);
        /* 2. Write our own bytes and tell the parent. */
        p[4096] = 0xBB;
        p[SZ - 8192] = 0xBB;
        c = saw_parent ? 'y' : 'n';
        if (write(up[1], &c, 1) != 1) _exit(21);
        /* 3. And confirm the FILE has our bytes, read through the descriptor
         *    rather than through any mapping. */
        unsigned char v = 0;
        if (pread(fd, &v, 1, 4096) != 1) v = 0;
        c = (v == 0xBB) ? 'y' : 'n';
        if (write(up[1], &c, 1) != 1) _exit(22);
        _exit(0);
    }

    /* PARENT. Write first -- this is the write that used to be given a private
     * copy, because the fork had just write-protected the page. */
    p[0] = 0xAA;
    p[SZ - 4096] = 0xAA;
    {   char c = 'g';
        if (write(down[1], &c, 1) != 1) { printf("LXSHCOW: handshake write failed\n"); return 1; } }

    char ans = 0;
    ck(read(up[0], &ans, 1) == 1 && ans == 'y',
       "the CHILD sees what the parent wrote through a MAP_SHARED mapping after fork");
    char ans2 = 0;
    ck(read(up[0], &ans2, 1) == 1 && ans2 == 'y',
       "the child's write reached the FILE, not a private copy of it");

    int st = 0;
    waitpid(kid, &st, 0);

    ck(p[4096] == 0xBB && p[SZ - 8192] == 0xBB,
       "the PARENT sees what the child wrote through the same mapping");
    ck(q[0] == 0xAA && q[4096] == 0xBB,
       "a SECOND mapping in the parent sees both processes' writes");

    unsigned char v0 = 0, v1 = 0;
    if (pread(fd, &v0, 1, 0) != 1) v0 = 0;
    if (pread(fd, &v1, 1, 4096) != 1) v1 = 0;
    if (v0 != 0xAA || v1 != 0xBB)
        printf("LXSHCOW: the file holds %02x at 0 and %02x at 4096; the mappings wrote "
               "aa and bb -- a fork gave somebody a private copy\n", v0, v1);
    ck(v0 == 0xAA && v1 == 0xBB,
       "the FILE holds both processes' writes (the mapping never stopped being the object)");

    munmap((void *)p, SZ);
    munmap((void *)q, SZ);
    close(fd);
    printf("LXSHCOW: %d failure(s)\n", fails);
    fflush(stdout);
    return fails ? 1 : 0;
}
