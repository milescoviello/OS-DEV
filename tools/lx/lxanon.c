/* lxanon -- the anonymous shared file every Wayland client creates.
 *
 * libwayland-cursor loads a cursor theme by first making a wl_shm pool, and it
 * makes the pool's backing file with os_create_anonymous_file(), which is:
 *
 *     fd = memfd_create("wayland-shm", MFD_CLOEXEC | MFD_ALLOW_SEALING);
 *     fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK);
 *     do { ret = posix_fallocate(fd, 0, size); } while (ret == EINTR);
 *
 * If ANY of that fails it returns -1, shm_pool_create returns NULL, and
 * wl_cursor_theme_load returns NULL -- at which point GDK prints
 *
 *     Gdk-WARNING: Failed to load cursor theme Adwaita
 *
 * and carries on without a cursor theme. One warning, four candidate causes,
 * and the warning names none of them. posix_fallocate in particular is not one
 * syscall: glibc tries fallocate(2), and on EOPNOTSUPP -- which is what this
 * kernel answers -- falls back to reading and writing the range by hand, which
 * only works if a memfd supports pread and pwrite.
 *
 * So do exactly what libwayland does, step by step, and say which step failed.
 * Then mmap it, because a pool you cannot map is no better than one you could
 * not create. (M2000)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#define F_SEAL_SHRINK 0x0002   /* Linux: SEAL=1, SHRINK=2, GROW=4, WRITE=8 */
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#define MFD_ALLOW_SEALING 0x0002U
#endif

static int fails;

int main(void)
{
    /* 32x32 ARGB is what a cursor theme asks for; libwayland uses size*size*4. */
    off_t size = 32 * 32 * 4;

    int fd = (int)syscall(SYS_memfd_create, "wayland-shm", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) { printf("LXANON: memfd_create FAILED errno=%d\n", errno); fails++; return 1; }
    printf("LXANON: memfd_create -> fd %d\n", fd);

    /* libwayland ignores the result, but a kernel that cannot be ASKED is a
     * different thing from one that declines, and only one of those is fine. */
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK) != 0) {
        printf("LXANON: F_ADD_SEALS FAILED errno=%d\n", errno); fails++;
    } else {
        /* F_ADD_SEALS returns 0; F_GET_SEALS returns the set. A kernel that
         * returned the set from both would look successful to a caller that
         * only checks for -1 and broken to one that checks for 0. */
        int got = fcntl(fd, 1034 /* F_GET_SEALS */, 0);
        if (got == F_SEAL_SHRINK) printf("LXANON: F_ADD_SEALS ok and F_GET_SEALS reads it back (0x%x)\n", got);
        else { printf("LXANON: F_GET_SEALS returned 0x%x, wanted 0x%x\n", got, F_SEAL_SHRINK); fails++; }
    }

    int ret;
    do { ret = posix_fallocate(fd, 0, size); } while (ret == EINTR);
    if (ret != 0) { printf("LXANON: posix_fallocate(%ld) FAILED ret=%d\n", (long)size, ret); fails++; }
    else printf("LXANON: posix_fallocate(%ld) ok\n", (long)size);

    /* ...and the thing the pool is FOR. */
    void *p = mmap(0, (size_t)size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { printf("LXANON: mmap(MAP_SHARED) FAILED errno=%d\n", errno); fails++; }
    else {
        memset(p, 0xA5, (size_t)size);
        unsigned char *b = p;
        if (b[0] == 0xA5 && b[size - 1] == 0xA5) printf("LXANON: mapped and wrote %ld bytes of pool\n", (long)size);
        else { printf("LXANON: the pool did not hold what was written\n"); fails++; }
        munmap(p, (size_t)size);
    }

    /* The other route libwayland takes when memfd_create is unavailable, and
     * the one an older libwayland uses unconditionally: ftruncate. */
    int fd2 = (int)syscall(SYS_memfd_create, "wayland-shm2", MFD_CLOEXEC);
    if (fd2 < 0) { printf("LXANON: second memfd_create FAILED errno=%d\n", errno); fails++; }
    else {
        if (ftruncate(fd2, size) == 0) printf("LXANON: ftruncate on a memfd ok\n");
        else { printf("LXANON: ftruncate on a memfd FAILED errno=%d\n", errno); fails++; }
        close(fd2);
    }
    close(fd);

    /* ---- POSIX SHARED MEMORY, between two real processes (M2008) -----------
     *
     * This is the part Firefox does not treat as optional: its parent and
     * content processes address each other through a segment they both open by
     * NAME, and when the open fails it dereferences a null pointer on purpose.
     * shm_open(3) is literally open("/dev/shm/NAME"), so what is being tested
     * here is that the name resolves and that two separate address spaces end
     * up looking at the SAME bytes -- which is the only claim that matters and
     * the only one a single-process test cannot make.
     *
     * The handshake goes both ways on purpose: a one-way check passes if the
     * child merely inherited the parent's mapping through fork. */
    shm_unlink("/osdev-shm-probe");                    /* from a previous run */
    int sfd = shm_open("/osdev-shm-probe", O_RDWR | O_CREAT | O_EXCL, 0600);
    if (sfd < 0) {
        printf("LXANON: shm_open(O_CREAT|O_EXCL) FAILED errno=%d\n", errno); fails++;
    } else {
        printf("LXANON: shm_open -> fd %d\n", sfd);
        /* A second O_EXCL create of a name that exists must be refused -- that
         * is how two processes decide which of them owns the segment. */
        int dup_fd = shm_open("/osdev-shm-probe", O_RDWR | O_CREAT | O_EXCL, 0600);
        if (dup_fd >= 0) { printf("LXANON: O_EXCL did not refuse an existing name\n"); fails++; close(dup_fd); }
        else if (errno != EEXIST) { printf("LXANON: O_EXCL refused with errno=%d, wanted EEXIST\n", errno); fails++; }
        else printf("LXANON: a second O_EXCL create is refused with EEXIST\n");

        if (ftruncate(sfd, 4096) != 0) { printf("LXANON: ftruncate on shm FAILED errno=%d\n", errno); fails++; }
        volatile unsigned *sp = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, sfd, 0);
        if (sp == MAP_FAILED) { printf("LXANON: mmap of shm FAILED errno=%d\n", errno); fails++; }
        else {
            sp[0] = 0; sp[1] = 0;
            sp[2] = 0xC0FFEE01u;                       /* what the parent says */
            pid_t kid = fork();
            if (kid == 0) {
                /* A FRESH open by name in the child -- not the inherited fd,
                 * which would prove nothing about the name at all. */
                int cfd = shm_open("/osdev-shm-probe", O_RDWR, 0600);
                if (cfd < 0) _exit(11);
                volatile unsigned *cp = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, cfd, 0);
                if (cp == MAP_FAILED) _exit(12);
                if (cp[2] != 0xC0FFEE01u) _exit(13);   /* the parent's write is not visible */
                cp[3] = 0xD15EA5E2u;                   /* answer in the same pages */
                cp[0] = 1;
                _exit(0);
            }
            if (kid < 0) { printf("LXANON: fork FAILED errno=%d\n", errno); fails++; }
            else {
                int st = 0; waitpid(kid, &st, 0);
                int cst = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
                if (cst != 0) { printf("LXANON: the child failed at step %d\n", cst); fails++; }
                else if (sp[0] != 1 || sp[3] != 0xD15EA5E2u) {
                    printf("LXANON: the child's write is not visible to the parent (%u, 0x%x)\n", sp[0], sp[3]); fails++;
                } else {
                    printf("LXANON: TWO PROCESSES SHARE ONE /dev/shm SEGMENT BY NAME (0x%x both ways)\n", sp[3]);
                }
            }
            munmap((void *)sp, 4096);
        }
        close(sfd);
        /* The name goes away; the segment itself is still mappable by anyone
         * holding a descriptor, which is what POSIX promises. */
        if (shm_unlink("/osdev-shm-probe") != 0) { printf("LXANON: shm_unlink FAILED errno=%d\n", errno); fails++; }
        else {
            int gone = shm_open("/osdev-shm-probe", O_RDWR, 0600);
            if (gone >= 0) { printf("LXANON: the name survived shm_unlink\n"); fails++; close(gone); }
            else printf("LXANON: shm_unlink removed the name\n");
        }
    }

    printf("LXANON: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}
