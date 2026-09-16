/* lxlock.c -- fcntl RECORD LOCKS AND flock(2), WHICH ANSWERED EBADF ON A VALID FD.
 *
 * Both capabilities already existed -- kernel/flock.c's rlock_get/rlock_set
 * have backed the NATIVE fcntl since M1597 and flock_op since M1177 -- and
 * neither was wired to the Linux syscall. F_GETLK/F_SETLK/F_SETLKW fell through
 * to a stub that returns -1, which the ABI layer turned into EBADF: the one
 * errno whose meaning is "that descriptor is not open", answered for a
 * descriptor that is. flock(2) had no case at all.
 *
 * Firefox asked four times in one startup and its IPC channel setup aborts on a
 * failed CHECK; its profile lock takes the fcntl path first and only falls back
 * to a symlink when the errno says the filesystem cannot do locks.
 *
 * Every check here fails with EBADF on the unwired kernel.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/wait.h>

static int fails;
#define CK(c, msg) do { if (c) printf("LXLOCK: ok   %s\n", msg); \
                        else { printf("LXLOCK: FAIL %s (errno %d %s)\n", msg, errno, strerror(errno)); fails++; } } while (0)

int main(void) {
    const char *path = "/root/lxlock.dat";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { printf("LXLOCK: FAIL open (%s)\n", strerror(errno)); return 1; }
    if (write(fd, "0123456789abcdef", 16) != 16) { printf("LXLOCK: FAIL write\n"); return 1; }

    /* 1. A WRITE LOCK IS GRANTED. The EBADF this used to return is what makes a
     *    caller conclude the filesystem has no locks at all. */
    struct flock l = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 8 };
    CK(fcntl(fd, F_SETLK, &l) == 0, "F_SETLK took a write lock on a valid fd");

    /* 2. F_GETLK ON OUR OWN LOCK reports no conflict -- a lock does not
     *    conflict with its own owner. */
    struct flock q = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 8 };
    CK(fcntl(fd, F_GETLK, &q) == 0, "F_GETLK answered");
    CK(q.l_type == F_UNLCK, "...and reports no conflict with our own lock");

    /* 3. l_whence IS HONOURED. Ignoring it locks the wrong range, silently,
     *    which is the worst possible shape for a lock. SEEK_END with a 16-byte
     *    file must land at 16, so it cannot conflict with [0,8). */
    struct flock e = { .l_type = F_WRLCK, .l_whence = SEEK_END, .l_start = 0, .l_len = 4 };
    CK(fcntl(fd, F_SETLK, &e) == 0, "F_SETLK with l_whence=SEEK_END took a lock past the first");

    /* 4. ANOTHER PROCESS CONFLICTS, and is told EAGAIN rather than EBADF. */
    pid_t c = fork();
    if (c == 0) {
        int f2 = open(path, O_RDWR);
        if (f2 < 0) _exit(20);
        struct flock w = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 8 };
        if (fcntl(f2, F_SETLK, &w) == 0) _exit(21);          /* should have conflicted */
        if (errno != EAGAIN && errno != EACCES) _exit(22);   /* and with the right errno */
        struct flock g = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 8 };
        if (fcntl(f2, F_GETLK, &g) != 0) _exit(23);
        if (g.l_type == F_UNLCK) _exit(24);                  /* must SEE the holder */
        _exit(0);
    }
    int st = 0; waitpid(c, &st, 0);
    CK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
       "another process was refused with EAGAIN and F_GETLK named the holder");
    if (WIFEXITED(st) && WEXITSTATUS(st) != 0)
        printf("LXLOCK:      (child exit code %d)\n", WEXITSTATUS(st));

    /* 5. UNLOCKING RELEASES IT. */
    struct flock u = { .l_type = F_UNLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 8 };
    CK(fcntl(fd, F_SETLK, &u) == 0, "F_UNLCK released the range");
    c = fork();
    if (c == 0) {
        int f3 = open(path, O_RDWR);
        struct flock w = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 8 };
        _exit(f3 >= 0 && fcntl(f3, F_SETLK, &w) == 0 ? 0 : 30);
    }
    waitpid(c, &st, 0);
    CK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "...and another process could then take it");

    /* 6. AN UNIMPLEMENTED COMMAND IS EINVAL, NOT EBADF. The descriptor is
     *    open; saying otherwise is a lie about the wrong noun. */
    errno = 0;
    long rc = fcntl(fd, 1024 /* no such command */, 0);
    CK(rc < 0 && errno == EINVAL, "an unknown fcntl command on an OPEN fd is EINVAL, not EBADF");

    /* 7. flock(2), which had no case at all. */
    CK(flock(fd, LOCK_EX | LOCK_NB) == 0, "flock(LOCK_EX|LOCK_NB) was granted");
    c = fork();
    if (c == 0) {
        int f4 = open(path, O_RDWR);
        _exit(f4 >= 0 && flock(f4, LOCK_EX | LOCK_NB) < 0 ? 0 : 40);
    }
    waitpid(c, &st, 0);
    CK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "...and another process was refused it");
    CK(flock(fd, LOCK_UN) == 0, "flock(LOCK_UN) released it");

    close(fd);
    unlink(path);
    printf(fails ? "LXLOCK: FAILED\n" : "LXLOCK: OK\n");
    return fails ? 1 : 0;
}
