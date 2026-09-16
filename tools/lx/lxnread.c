/* lxnread.c -- FIONREAD ANSWERED "THAT DESCRIPTOR IS NOT A TERMINAL".
 *
 * The Linux ioctl handler decided one thing -- is this fd a console? -- and
 * answered ENOTTY to every request on every fd for which the answer was no.
 * That is right for TCGETS and TIOCGWINSZ. It is wrong for the FIO* family,
 * which is defined on *any* descriptor: FIONREAD on a socket, a pipe, a pty or
 * a file is an ordinary, portable question, and it was being refused as though
 * the caller had asked about baud rates.
 *
 * What it cost: Firefox's IPC channel asked FIONREAD on a healthy socketpair,
 * was told ENOTTY, and aborted -- and the very next syscall on that same
 * descriptor read 142 bytes off it.
 *
 *     t293 16(2f, 541b, 1257c47ac) = ffffffffffffffe7   ioctl(FIONREAD) -25
 *     t293 45(2f, 12ae81000, 10000) = 8e                recvfrom(same fd) 142
 *
 * Every FIONREAD check here returns -1/ENOTTY on the unfixed kernel, and the
 * counting ones fail again if a count is ever wired up that reports mere
 * readiness (1) instead of a byte total.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

static int fails;
#define CK(c, msg) do { if (c) printf("LXNREAD: ok   %s\n", msg); \
                        else { printf("LXNREAD: FAIL %s (errno %d %s)\n", msg, errno, strerror(errno)); fails++; } } while (0)

int main(void) {
    /* 1. THE EXACT CASE FIREFOX DIED ON: a socketpair with a known number of
     *    bytes waiting. 142 is the byte count from the trace above. */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { printf("LXNREAD: FAIL socketpair\n"); return 1; }
    char blob[142];
    for (int i = 0; i < 142; i++) blob[i] = (char)i;
    CK(write(sv[1], blob, 142) == 142, "142 bytes written into a socketpair");

    int n = -1; errno = 0;
    int rc = ioctl(sv[0], FIONREAD, &n);
    CK(rc == 0, "FIONREAD on a socket is answered at all (was ENOTTY)");
    CK(errno != ENOTTY, "...and specifically NOT with 'not a terminal'");
    CK(n == 142, "...and reports 142, the real byte count, not 1 for 'readable'");

    /* 2. A COUNT IS A COUNT: draining half must halve it. A readiness flag
     *    dressed up as a count passes check 1 and fails this one. */
    char half[100];
    CK(read(sv[0], half, 100) == 100, "100 of those bytes read back");
    n = -1;
    CK(ioctl(sv[0], FIONREAD, &n) == 0 && n == 42, "FIONREAD now reports the remaining 42");

    /* 3. DRAINED IS ZERO, NOT AN ERROR. An empty socket is still a socket. */
    CK(read(sv[0], half, 42) == 42, "the rest read back");
    n = -1;
    CK(ioctl(sv[0], FIONREAD, &n) == 0 && n == 0, "a drained socket reports 0 and does not fail");

    /* 4. A PENDING EOF IS NOT A BYTE. Closing the peer makes the socket
     *    readable (read returns 0) -- but there is nothing to read, and a
     *    caller that mallocs this number and then reads it would hang. */
    close(sv[1]);
    n = -1;
    CK(ioctl(sv[0], FIONREAD, &n) == 0 && n == 0, "a hung-up socket reports 0 bytes, not 1 for the EOF");
    close(sv[0]);

    /* 5. PIPES. Same family, same ioctl, same ENOTTY before the fix. */
    int pf[2];
    if (pipe(pf) != 0) { printf("LXNREAD: FAIL pipe\n"); return 1; }
    CK(write(pf[1], "hello pipe", 10) == 10, "10 bytes written into a pipe");
    n = -1;
    CK(ioctl(pf[0], FIONREAD, &n) == 0 && n == 10, "FIONREAD on a pipe read end reports 10");
    /* FIONREAD ON A PIPE IS A PROPERTY OF THE PIPE, NOT OF THE END YOU HOLD.
     * I guessed 0 here and a real Linux kernel said 10 -- this file's numbers
     * are all checked against one, because a tidy-looking wrong answer is
     * exactly the failure mode being fixed. */
    n = -1;
    CK(ioctl(pf[1], FIONREAD, &n) == 0 && n == 10, "FIONREAD on the pipe's WRITE end reports 10 too, as Linux does");
    close(pf[0]); close(pf[1]);

    /* 6. A REGULAR FILE: bytes from here to the end, and it moves with the
     *    file offset. Getting this from the size alone passes the first half
     *    and fails the second. */
    const char *path = "/root/lxnread.dat";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { printf("LXNREAD: FAIL open (%s)\n", strerror(errno)); return 1; }
    CK(write(fd, "0123456789abcdefghij", 20) == 20, "20 bytes written to a file");
    CK(lseek(fd, 0, SEEK_SET) == 0, "rewound");
    n = -1;
    CK(ioctl(fd, FIONREAD, &n) == 0 && n == 20, "FIONREAD on a file at offset 0 reports 20");
    CK(lseek(fd, 12, SEEK_SET) == 12, "seeked to 12");
    n = -1;
    CK(ioctl(fd, FIONREAD, &n) == 0 && n == 8, "...and at offset 12 reports 8 -- size MINUS offset");
    CK(lseek(fd, 20, SEEK_SET) == 20, "seeked to EOF");
    n = -1;
    CK(ioctl(fd, FIONREAD, &n) == 0 && n == 0, "...and at EOF reports 0, not a negative");

    /* 7. AN EVENTFD AND A TIMERFD MUST *REFUSE*. Linux answers ENOTTY for
     *    both -- they are not byte streams -- and "8, one u64 is waiting"
     *    would be a fabrication that looks more helpful than the truth. This
     *    is the check that fails if someone later decides every fd should
     *    return something. */
    int ef = eventfd(0, 0);
    if (ef >= 0) {
        unsigned long long one = 1;
        CK(write(ef, &one, 8) == 8, "an eventfd counter raised");
        errno = 0; n = -1;
        CK(ioctl(ef, FIONREAD, &n) < 0 && errno == ENOTTY, "FIONREAD on an eventfd REFUSES with ENOTTY, as Linux does");
        close(ef);
    }
    int tf = timerfd_create(CLOCK_MONOTONIC, 0);
    if (tf >= 0) {
        errno = 0; n = -1;
        CK(ioctl(tf, FIONREAD, &n) < 0 && errno == ENOTTY, "FIONREAD on a timerfd REFUSES with ENOTTY");
        close(tf);
    }

    /* 7b. A LISTENING SOCKET IS EINVAL, NOT 0. There is no stream yet, and 0
     *     would read as "the stream is drained". Linux distinguishes these two
     *     refusals and so must we -- one errno for two causes is the same
     *     defect wearing different clothes. */
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls >= 0) {
        struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
        sa.sun_family = AF_UNIX;
        snprintf(sa.sun_path, sizeof sa.sun_path, "/tmp/lxnread.sock");
        unlink(sa.sun_path);
        if (bind(ls, (struct sockaddr *)&sa, sizeof sa) == 0 && listen(ls, 4) == 0) {
            errno = 0; n = -1;
            CK(ioctl(ls, FIONREAD, &n) < 0 && errno == EINVAL, "FIONREAD on a LISTENING socket is EINVAL, not 0");
        }
        close(ls); unlink(sa.sun_path);
    }

    /* 7c. A DIRECTORY fd is ENOTTY -- reporting its on-disk size as "bytes you
     *     may read" is meaningless and getdents does not read bytes. */
    int dfd = open("/", O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) {
        errno = 0; n = -1;
        CK(ioctl(dfd, FIONREAD, &n) < 0 && errno == ENOTTY, "FIONREAD on a DIRECTORY fd is ENOTTY, not its size");
        close(dfd);
    }

    /* 8. THE OTHER FIO* IOCTLS, refused by the same gate. Both are the ioctl
     *    spelling of an fcntl that already worked -- the capability existed
     *    and this door was shut. Checked through fcntl, so the assertion is
     *    that the state really changed and not merely that a call returned 0. */
    CK(ioctl(fd, FIOCLEX) == 0, "FIOCLEX answered");
    CK((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0, "...and FD_CLOEXEC is really set");
    CK(ioctl(fd, FIONCLEX) == 0, "FIONCLEX answered");
    CK((fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0, "...and FD_CLOEXEC is really clear");
    int on = 1;
    CK(ioctl(fd, FIONBIO, &on) == 0, "FIONBIO answered");
    CK((fcntl(fd, F_GETFL) & O_NONBLOCK) != 0, "...and O_NONBLOCK is really set");
    on = 0;
    CK(ioctl(fd, FIONBIO, &on) == 0 && (fcntl(fd, F_GETFL) & O_NONBLOCK) == 0, "...and clears again");

    /* 9. A CLOSED DESCRIPTOR IS EBADF. "Not a terminal" was the wrong errno in
     *    both directions: refused on a valid fd, and it would also have hidden
     *    a genuinely bad one. */
    close(fd);
    errno = 0;
    n = -1;
    rc = ioctl(fd, FIONREAD, &n);
    CK(rc < 0 && errno == EBADF, "FIONREAD on a CLOSED fd is EBADF");

    unlink(path);
    printf(fails ? "LXNREAD: FAILED\n" : "LXNREAD: OK\n");
    return fails ? 1 : 0;
}
