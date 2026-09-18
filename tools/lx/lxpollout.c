/* lxpollout -- does poll() tell the truth about whether a send will block?
 *
 * THE BUG THIS EXISTS FOR (M2202). app_fd_ready answered POLLOUT
 * unconditionally for every AF_UNIX endpoint, with the comment "the ring
 * drains quickly; a blocked send is brief". The measurement disagrees: every
 * Firefox boot in this tree logs
 *
 *   SPINNING: pid 165 tid 87 has had EAGAIN from sendmsg(fd 58) 1000 times in
 *   a row -- ... TX_queued=16383 tx_room=0 peer_reader_waiting=0 nonblock=1
 *
 * A thread asks poll whether it can write, is told yes, writes, is refused
 * with EAGAIN, and goes straight back to poll. A thousand times in a row. On
 * one core that spinner starves the peer whose read is the only thing that can
 * drain the ring it is waiting on, so the lie is not merely wasteful -- it
 * removes the mechanism that would have made it untrue.
 *
 * Every assertion here is about the CONTRACT, not about a size: fill the
 * socket until the kernel itself says EAGAIN, and then ask poll. A kernel that
 * answers POLLOUT there has promised something it just refused.
 *
 * Nothing in here can hang: the socket is non-blocking throughout, and every
 * poll has a timeout.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>

static int fails;
static void ck(int ok, const char *what)
{
    if (!ok) { fails++; printf("LXPOLLOUT: FAIL -- %s\n", what); }
    else       printf("LXPOLLOUT: ok   -- %s\n", what);
    fflush(stdout);
}

/* POLLOUT on `fd`, right now. */
static int writable(int fd)
{
    struct pollfd p = { .fd = fd, .events = POLLOUT, .revents = 0 };
    int r = poll(&p, 1, 0);
    return r > 0 && (p.revents & POLLOUT);
}

int main(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("LXPOLLOUT: socketpair failed: %s\n", strerror(errno));
        return 1;
    }
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    fcntl(sv[1], F_SETFL, O_NONBLOCK);

    /* 1. An empty socket is writable, and poll had better say so -- an
     *    unconditional NO would be just as wrong as an unconditional YES, and
     *    it is the failure this fix could plausibly introduce. */
    ck(writable(sv[0]), "an empty socket polls writable");

    /* 2. Fill it until the kernel refuses. The buffer size is deliberately not
     *    asserted: what matters is that the refusal and poll's answer agree. */
    static char blob[4096];
    memset(blob, 'x', sizeof blob);
    long total = 0;
    int refused = 0;
    for (int i = 0; i < 100000; i++) {
        ssize_t n = write(sv[0], blob, sizeof blob);
        if (n > 0) { total += n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { refused = 1; break; }
        printf("LXPOLLOUT: write failed with %s after %ld bytes\n", strerror(errno), total);
        return 1;
    }
    printf("LXPOLLOUT: the socket took %ld byte(s) before it said EAGAIN\n", total);
    fflush(stdout);
    ck(refused, "a non-blocking write on a full socket returns EAGAIN");

    /* 3. THE ASSERTION. The kernel has just refused a write. If poll now says
     *    POLLOUT, it is promising exactly what was refused, and a caller that
     *    believes it spins. */
    ck(!writable(sv[0]), "a FULL socket does NOT poll writable");

    /* 4. And it has to come back. A predicate that is merely always-false
     *    would pass assertion 3 and break every event loop in the system, so
     *    drain the peer and require poll to notice.
     *
     *    DRAIN IT COMPLETELY, and the reason is the host. The first cut read
     *    64 KiB of the 176 KiB Linux had accepted and asserted writability --
     *    and LINUX SAID NO, because its test is a WATERMARK (free space
     *    against a fraction of the send buffer, counted with skb overhead, not
     *    payload), not "is there a free byte". An assertion that fails on the
     *    kernel whose behaviour it is copying is an assertion about nothing.
     *    Empty is the one state every implementation agrees about. */
    char sink[8192];
    long drained = 0;
    for (;;) {
        ssize_t n = read(sv[1], sink, sizeof sink);
        if (n <= 0) break;
        drained += n;
    }
    printf("LXPOLLOUT: drained %ld byte(s) from the peer\n", drained);
    fflush(stdout);
    ck(drained > 0, "the peer could read what was queued");
    ck(writable(sv[0]), "after the peer drained it, the socket polls writable again");

    /* 5. A DEAD PEER IS WRITABLE, because the write does not block -- it fails
     *    with EPIPE. A poller waiting for room on a socket whose peer has gone
     *    must be woken, or it waits for ever. */
    int sv2[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0) {
        fcntl(sv2[0], F_SETFL, O_NONBLOCK);
        /* Fill it first, so "writable" cannot come from having room. */
        for (int i = 0; i < 100000; i++) {
            ssize_t n = write(sv2[0], blob, sizeof blob);
            if (n < 0) break;
        }
        close(sv2[1]);
        ck(writable(sv2[0]), "a full socket whose peer is CLOSED polls writable (the send errors, it does not block)");
        close(sv2[0]);
    }

    close(sv[0]); close(sv[1]);
    printf("LXPOLLOUT: %d failure(s)\n", fails);
    fflush(stdout);
    return fails ? 1 : 0;
}
