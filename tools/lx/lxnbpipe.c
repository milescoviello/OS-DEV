/* lxnbpipe -- O_NONBLOCK on a pipe, which is how every event loop wakes up.
 *
 * A program of this shape owns a SELF-PIPE: any thread that wants the main
 * loop to notice something writes one byte into it, and the loop -- which is
 * sitting in poll() on the read end -- wakes, then DRAINS the pipe by reading
 * until it gets EAGAIN. The last read of that drain is *expected* to find the
 * pipe empty. That is the terminating condition.
 *
 * Firefox's main thread hung there forever (M2009). Every other descriptor
 * type in this kernel honoured O_NONBLOCK; the pipe, which was the original fd
 * type, did not, so the drain's final read blocked inside the kernel. The
 * symptom was not "a read hung" -- it was 33 threads futex-waiting on work
 * that only the wedged thread could ever post, and a process making zero
 * syscalls for five minutes.
 *
 * Every call here that WOULD have blocked before the fix is made in a forked
 * child with the parent timing it out, so this probe reports a verdict instead
 * of becoming the hang it is testing for.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>

static int fails;

/* Run `fn` in a child and give it `ms` to finish. Returns the child's exit
 * status, or -1 if it had to be killed -- which is what "the kernel blocked"
 * looks like from out here. */
static int timed(int (*fn)(int *), int *fds, int ms)
{
    pid_t k = fork();
    if (k == 0) _exit(fn(fds));
    if (k < 0) return -2;
    for (int i = 0; i < ms / 20; i++) {
        int st = 0;
        pid_t r = waitpid(k, &st, WNOHANG);
        if (r == k) return WIFEXITED(st) ? WEXITSTATUS(st) : -3;
        usleep(20000);
    }
    kill(k, SIGKILL);
    waitpid(k, 0, 0);
    return -1;                       /* still running: it blocked */
}

/* The drain: read an empty non-blocking pipe. 0 = EAGAIN as it should be. */
static int kid_empty_read(int *fds)
{
    char c;
    ssize_t n = read(fds[0], &c, 1);
    if (n < 0 && errno == EAGAIN) return 0;
    if (n < 0) return 4 + (errno & 15);
    return 3;                        /* returned data from an empty pipe */
}

/* The post: write to a pipe whose ring is already full. */
static int kid_full_write(int *fds)
{
    char buf[4096];
    memset(buf, 'x', sizeof buf);
    for (int i = 0; i < 4096; i++) {                 /* bounded: 16 MB of tries */
        ssize_t n = write(fds[1], buf, sizeof buf);
        if (n < 0 && errno == EAGAIN) return 0;      /* full, and it said so */
        if (n < 0) return 4 + (errno & 15);
    }
    return 3;                                        /* never filled: no back-pressure at all */
}

int main(void)
{
    int fds[2];
    if (pipe2(fds, O_NONBLOCK) != 0) { printf("LXNB: pipe2(O_NONBLOCK) FAILED errno=%d\n", errno); return 1; }
    printf("LXNB: pipe2(O_NONBLOCK) -> %d %d\n", fds[0], fds[1]);

    int rc = timed(kid_empty_read, fds, 3000);
    if (rc == 0) printf("LXNB: reading an EMPTY non-blocking pipe returns EAGAIN\n");
    else { printf("LXNB: an empty non-blocking read did not return EAGAIN (rc=%d%s)\n", rc, rc == -1 ? ": IT BLOCKED" : ""); fails++; }

    /* O_NONBLOCK must not cost a read its DATA -- the drain has to actually
     * drain, or the loop spins forever on a byte it can never consume. */
    if (write(fds[1], "A", 1) != 1) { printf("LXNB: write of one byte FAILED errno=%d\n", errno); fails++; }
    else {
        char c = 0;
        ssize_t n = read(fds[0], &c, 1);
        if (n == 1 && c == 'A') printf("LXNB: a non-blocking read still delivers data that IS there\n");
        else { printf("LXNB: non-blocking read lost the byte (n=%ld c=%d)\n", (long)n, c); fails++; }
    }

    /* Three wakeups posted, then the full drain loop, exactly as an event loop
     * runs it: read until EAGAIN and count what came out. */
    if (write(fds[1], "123", 3) != 3) { printf("LXNB: posting three wakeups FAILED errno=%d\n", errno); fails++; }
    else {
        int got = 0; char c;
        for (;;) {
            ssize_t n = read(fds[0], &c, 1);
            if (n == 1) { got++; continue; }
            if (n < 0 && errno == EAGAIN) break;
            printf("LXNB: the drain loop ended on n=%ld errno=%d\n", (long)n, errno); fails++; break;
        }
        if (got == 3) printf("LXNB: THE SELF-PIPE DRAIN LOOP TERMINATES (3 bytes, then EAGAIN)\n");
        else { printf("LXNB: the drain loop read %d bytes, wanted 3\n", got); fails++; }
    }

    rc = timed(kid_full_write, fds, 5000);
    if (rc == 0) printf("LXNB: writing a FULL non-blocking pipe returns EAGAIN\n");
    else { printf("LXNB: a full non-blocking write did not return EAGAIN (rc=%d%s)\n", rc, rc == -1 ? ": IT BLOCKED" : ""); fails++; }

    /* Drain whatever the child managed to leave behind, then prove that EOF is
     * still EOF: a closed writer must read as 0, NOT as EAGAIN. Conflating the
     * two makes a reader loop forever on a pipe nobody will ever write again. */
    { char buf[4096]; while (read(fds[0], buf, sizeof buf) > 0) ; }
    close(fds[1]);
    { char c; ssize_t n = read(fds[0], &c, 1);
      if (n == 0) printf("LXNB: a closed writer still reads as EOF, not EAGAIN\n");
      else { printf("LXNB: EOF on a non-blocking pipe read as n=%ld errno=%d\n", (long)n, errno); fails++; } }
    close(fds[0]);

    /* THE OTHER ROUTE to the same property: a plain pipe() plus the
     * F_GETFL/F_SETFL read-modify-write that libuv and glibc's stdio both do.
     * pipe2's flags and fcntl's flags are separate code paths here, and only
     * one of them was dropping the bit. */
    int p2[2];
    if (pipe(p2) != 0) { printf("LXNB: pipe() FAILED errno=%d\n", errno); fails++; }
    else {
        int fl = fcntl(p2[0], F_GETFL, 0);
        if (fl < 0 || fcntl(p2[0], F_SETFL, fl | O_NONBLOCK) != 0) {
            printf("LXNB: fcntl(F_SETFL, O_NONBLOCK) FAILED errno=%d\n", errno); fails++;
        } else if (!(fcntl(p2[0], F_GETFL, 0) & O_NONBLOCK)) {
            printf("LXNB: F_GETFL does not read O_NONBLOCK back\n"); fails++;
        } else {
            int rc2 = timed(kid_empty_read, p2, 3000);
            if (rc2 == 0) printf("LXNB: fcntl(F_SETFL, O_NONBLOCK) makes an empty read EAGAIN too\n");
            else { printf("LXNB: the fcntl route did not take (rc=%d%s)\n", rc2, rc2 == -1 ? ": IT BLOCKED" : ""); fails++; }
        }
        close(p2[0]); close(p2[1]);
    }

    printf("LXNB: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}
