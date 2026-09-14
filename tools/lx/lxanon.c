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

    printf("LXANON: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}
