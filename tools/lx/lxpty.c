/* lxpty -- can a Linux binary get a pty here, and does a full one say so?
 *
 * TWO THINGS AT ONCE (M2206).
 *
 * 1. /dev/ptmx and /dev/pts/<n> have been openable since M1274 and the pty
 *    itself is complete -- line discipline, canonical editing, INTR->signal,
 *    window size. But glibc's openpty() asks the master for its slave NUMBER
 *    (TIOCGPTN) and unlocks it (TIOCSPTLCK), and both answered ENOTTY. So no
 *    Linux program could get a pty at all, and from outside there was no way
 *    to tell that the reason was two missing ioctl numbers rather than a
 *    missing pty.
 *
 * 2. pty_write's MASTER path returned the full length unconditionally while
 *    the line discipline dropped whatever did not fit -- the dominant bug
 *    class in this tree, a mechanism answering with a plausible wrong value
 *    instead of failing. And app_fd_ready answered POLLOUT for a pty
 *    unconditionally, which is the same omission M2202 fixed for AF_UNIX.
 *
 * The host runs this too (it is -static-pie), so the expectations are real
 * pty(7) semantics rather than a reading of them.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <termios.h>

static int fails;
static void ck(int ok, const char *what)
{
    if (!ok) { fails++; printf("LXPTY: FAIL -- %s\n", what); }
    else       printf("LXPTY: ok   -- %s\n", what);
    fflush(stdout);
}

static int writable(int fd)
{
    struct pollfd p = { .fd = fd, .events = POLLOUT, .revents = 0 };
    int r = poll(&p, 1, 0);
    return r > 0 && (p.revents & POLLOUT);
}

int main(void)
{
    int m = -1, s = -1;
    if (openpty(&m, &s, NULL, NULL, NULL) != 0) {
        printf("LXPTY: openpty failed: %s\n", strerror(errno));
        ck(0, "openpty() gives a master/slave pair");
        printf("LXPTY: %d failure(s)\n", fails);
        fflush(stdout);
        return 1;
    }
    ck(1, "openpty() gives a master/slave pair");
    printf("LXPTY: master fd %d, slave fd %d, slave is %s\n", m, s, ttyname(s) ? ttyname(s) : "?");
    fflush(stdout);

    /* Raw mode on the slave, so a byte written to the master is deliverable
     * immediately and the test is about the ring rather than about line
     * editing. */
    struct termios t;
    if (tcgetattr(s, &t) == 0) {
        cfmakeraw(&t);
        tcsetattr(s, TCSANOW, &t);
    }

    /* 1. A byte written to the master arrives at the slave. */
    fcntl(m, F_SETFL, O_NONBLOCK);
    fcntl(s, F_SETFL, O_NONBLOCK);
    ssize_t w = write(m, "hi", 2);
    char got[8];
    ssize_t rd = -1;
    for (int i = 0; i < 100 && rd <= 0; i++) rd = read(s, got, sizeof got);
    ck(w == 2 && rd == 2 && got[0] == 'h' && got[1] == 'i',
       "a byte written to the master is read by the slave");

    /* 2. Fill it. What matters is that the kernel's count matches what it took:
     *    a write that reports N must have delivered N. Sum the reported
     *    writes, drain the slave, and require the totals to agree. */
    static char blob[1024];
    memset(blob, 'x', sizeof blob);
    long claimed = 0;
    int refused = 0;
    for (int i = 0; i < 4096; i++) {
        ssize_t n = write(m, blob, sizeof blob);
        if (n > 0) { claimed += n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { refused = 1; break; }
        if (n == 0) { refused = 1; break; }        /* a short write of zero is also a refusal */
        printf("LXPTY: write failed: %s after %ld bytes\n", strerror(errno), claimed);
        break;
    }
    printf("LXPTY: the master accepted %ld byte(s) before refusing (refused=%d)\n", claimed, refused);
    fflush(stdout);
    ck(refused, "a master write to a FULL pty is refused instead of reporting success");

    /* 3. THE ASSERTION. Everything the kernel said it took must be readable.
     *    Pre-M2206 the master path returned the full length for bytes the line
     *    discipline had dropped, so this comes up short by exactly the lie. */
    long drained = 0;
    for (;;) {
        char sink[4096];
        ssize_t n = read(s, sink, sizeof sink);
        if (n <= 0) break;
        drained += n;
    }
    if (drained != claimed)
        printf("LXPTY: the master was told it wrote %ld byte(s) and the slave could only read "
               "%ld -- %ld byte(s) were dropped by a write that reported success\n",
               claimed, drained, claimed - drained);
    ck(drained == claimed, "every byte the master was told it wrote is readable by the slave");

    /* 4. And poll must agree with the write. Fill it again and ask. */
    for (int i = 0; i < 4096; i++) {
        ssize_t n = write(m, blob, sizeof blob);
        if (n <= 0) break;
    }
    ck(!writable(m), "a FULL pty master does NOT poll writable");
    for (;;) {
        char sink[4096];
        ssize_t n = read(s, sink, sizeof sink);
        if (n <= 0) break;
    }
    ck(writable(m), "after the slave drained it, the master polls writable again");

    close(m); close(s);
    printf("LXPTY: %d failure(s)\n", fails);
    fflush(stdout);
    return fails ? 1 : 0;
}
