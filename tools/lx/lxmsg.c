/* lxmsg.c -- sendmsg/recvmsg REPORTED ONE ERRNO FOR SIX DIFFERENT FAILURES,
 * AND THE ONE IT CHOSE WAS IMPOSSIBLE.
 *
 * Every path out of the send handler that sent nothing fell through to
 *   if (done == 0) r->rax = -ENETUNREACH;
 * and ENETUNREACH on an AF_UNIX socket cannot happen: there is no network
 * between two ends of a socketpair. The six causes were "too many iovecs",
 * "an unreadable iovec array", "an unreadable iovec", "the underlying write
 * failed", "out of memory", and a datagram silently shortened to 2048 bytes.
 *
 * What it cost: Firefox's FORK SERVER, which is how every content process is
 * created. Its last five calls before aborting were
 *
 *   47(3, 50fff388, 0) = 40    recvmsg -- a 64-byte request
 *   14(0, ...)         = 0     rt_sigprocmask(SIG_BLOCK)
 *   56(1200011, 0, 0)  = ec    clone   -- it forked child pid 236
 *   14(2, ...)         = 0     rt_sigprocmask(SIG_SETMASK)
 *   46(3, 50fff200, 0) = -101  sendmsg -- ENETUNREACH
 *
 * It had done the work and could not report it. A caller told ENETUNREACH
 * tears the channel down; one told EAGAIN polls and retries, which is exactly
 * what a non-blocking socket with a briefly full ring is asking for.
 *
 * Checked against a real Linux kernel first, as always.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int fails;
#define CK(c, msg) do { if (c) printf("LXMSG: ok   %s\n", msg); \
                        else { printf("LXMSG: FAIL %s (errno %d %s)\n", msg, errno, strerror(errno)); fails++; } } while (0)

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { printf("LXMSG: FAIL socketpair\n"); return 1; }

    /* 1. THE ORDINARY CASE STILL WORKS, with several iovecs gathered into one
     *    stream -- the baseline every later assertion is measured against. */
    {
        struct iovec iov[3];
        iov[0].iov_base = (void *)"AAA"; iov[0].iov_len = 3;
        iov[1].iov_base = (void *)"BBBB"; iov[1].iov_len = 4;
        iov[2].iov_base = (void *)"CC"; iov[2].iov_len = 2;
        struct msghdr mh; memset(&mh, 0, sizeof mh);
        mh.msg_iov = iov; mh.msg_iovlen = 3;
        CK(sendmsg(sv[0], &mh, 0) == 9, "sendmsg gathered 3 iovecs into 9 bytes");
        char b[16]; struct iovec riov = { b, sizeof b };
        struct msghdr rh; memset(&rh, 0, sizeof rh);
        rh.msg_iov = &riov; rh.msg_iovlen = 1;
        ssize_t got = recvmsg(sv[1], &rh, 0);
        CK(got == 9 && memcmp(b, "AAABBBBCC", 9) == 0, "...and recvmsg scattered the same 9 bytes back");
        CK(rh.msg_flags == 0, "...with msg_flags reporting no truncation");
    }

    /* 2. AN UNREADABLE IOVEC IS EFAULT, NOT "the network is unreachable". */
    {
        struct iovec iov = { (void *)0x10, 8 };     /* never mapped */
        struct msghdr mh; memset(&mh, 0, sizeof mh);
        mh.msg_iov = &iov; mh.msg_iovlen = 1;
        errno = 0;
        ssize_t rc = sendmsg(sv[0], &mh, 0);
        CK(rc < 0 && errno == EFAULT, "sendmsg with an unreadable iovec is EFAULT");
        CK(errno != ENETUNREACH, "...and specifically NOT ENETUNREACH on a Unix socket");
    }

    /* 3. AN UNREADABLE IOVEC ARRAY, likewise. */
    {
        struct msghdr mh; memset(&mh, 0, sizeof mh);
        mh.msg_iov = (struct iovec *)0x10; mh.msg_iovlen = 2;
        errno = 0;
        CK(sendmsg(sv[0], &mh, 0) < 0 && errno == EFAULT, "sendmsg with an unreadable iovec ARRAY is EFAULT");
    }

    /* 4. A FULL NON-BLOCKING SOCKET IS EAGAIN. This is the one that killed
     *    Firefox's fork server: told ENETUNREACH it destroys the channel,
     *    told EAGAIN it polls and retries. Fill the ring until a write
     *    refuses, then check what sendmsg calls it. */
    {
        int fl = fcntl(sv[0], F_GETFL);
        fcntl(sv[0], F_SETFL, fl | O_NONBLOCK);
        char chunk[4096]; memset(chunk, 'x', sizeof chunk);
        struct iovec iov = { chunk, sizeof chunk };
        struct msghdr mh; memset(&mh, 0, sizeof mh);
        mh.msg_iov = &iov; mh.msg_iovlen = 1;
        int hit = 0;
        for (int i = 0; i < 4096; i++) {
            errno = 0;
            ssize_t rc = sendmsg(sv[0], &mh, 0);
            if (rc < 0) { hit = errno; break; }
        }
        CK(hit == EAGAIN, "a FULL non-blocking socket answers sendmsg with EAGAIN");
        /* Drain so the rest of the test has a working socket. */
        char d[8192];
        int fl1 = fcntl(sv[1], F_GETFL);
        fcntl(sv[1], F_SETFL, fl1 | O_NONBLOCK);
        while (read(sv[1], d, sizeof d) > 0) { }
        fcntl(sv[1], F_SETFL, fl1);
        fcntl(sv[0], F_SETFL, fl);
    }

    /* 5. A CLOSED PEER IS EPIPE, and a bad descriptor is EBADF. Two more
     *    causes that shared the one impossible errno -- and both mean "stop",
     *    where EAGAIN means "try again", so getting them wrong turns a dead
     *    socket into an infinite retry loop. */
    {
        int p[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) == 0) {
            close(p[1]);
            signal(SIGPIPE, SIG_IGN);
            struct iovec iov = { (void *)"z", 1 };
            struct msghdr mh; memset(&mh, 0, sizeof mh);
            mh.msg_iov = &iov; mh.msg_iovlen = 1;
            errno = 0;
            CK(sendmsg(p[0], &mh, 0) < 0 && errno == EPIPE, "sendmsg to a CLOSED peer is EPIPE");
            close(p[0]);
            errno = 0;
            CK(sendmsg(p[0], &mh, 0) < 0 && errno == EBADF, "sendmsg on a CLOSED fd is EBADF");
        }
    }

    /* 6. MSG_CMSG_CLOEXEC, WHICH LIBWAYLAND ALWAYS PASSES. Ignored, so every
     *    received descriptor leaked across execve -- and Firefox execve's a
     *    content process per tab, each inheriting a memfd it can never close.
     *    Asserted through fcntl, so what is checked is that the STATE changed
     *    and not merely that a call returned. */
    {
        int payload = memfd_create("lxmsg-pass", 0);
        if (payload >= 0) {
            char cbuf[CMSG_SPACE(sizeof(int))];
            struct iovec iov = { (void *)"f", 1 };
            struct msghdr mh; memset(&mh, 0, sizeof mh);
            mh.msg_iov = &iov; mh.msg_iovlen = 1;
            mh.msg_control = cbuf; mh.msg_controllen = sizeof cbuf;
            struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
            cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS;
            cm->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(cm), &payload, sizeof(int));
            CK(sendmsg(sv[0], &mh, 0) == 1, "a descriptor was passed with SCM_RIGHTS");

            char rb[8], rcbuf[CMSG_SPACE(sizeof(int))];
            struct iovec riov = { rb, sizeof rb };
            struct msghdr rh; memset(&rh, 0, sizeof rh);
            rh.msg_iov = &riov; rh.msg_iovlen = 1;
            rh.msg_control = rcbuf; rh.msg_controllen = sizeof rcbuf;
            ssize_t got = recvmsg(sv[1], &rh, MSG_CMSG_CLOEXEC);
            CK(got == 1, "...and received with MSG_CMSG_CLOEXEC");
            struct cmsghdr *rcm = CMSG_FIRSTHDR(&rh);
            if (rcm && rcm->cmsg_type == SCM_RIGHTS) {
                int nf; memcpy(&nf, CMSG_DATA(rcm), sizeof nf);
                CK(nf >= 0, "...the descriptor arrived");
                CK((fcntl(nf, F_GETFD) & FD_CLOEXEC) != 0,
                   "...and MSG_CMSG_CLOEXEC really set FD_CLOEXEC on it");
                close(nf);
            } else { printf("LXMSG: FAIL no SCM_RIGHTS cmsg came back\n"); fails++; }
            close(payload);
        }
    }

    /* 7. A DATAGRAM TOO BIG IS EMSGSIZE, NOT A SHORTENED DATAGRAM. A stream
     *    may be short-written -- the caller sends the rest -- but a datagram
     *    is one packet and there is no rest, so shortening it silently hands
     *    the peer a message nobody knows was cut.
     *
     *    ON AN AF_INET SOCKET, deliberately. My first version used
     *    socketpair(AF_UNIX, SOCK_DGRAM) and it passed on the host and failed
     *    in the guest -- because our AF_UNIX socketpair serves SOCK_DGRAM out
     *    of the same byte ring a stream uses, so it is not a datagram socket
     *    at all and a short write there is legal. Asserting EMSGSIZE against
     *    it would have been asserting a behaviour we do not have, on a socket
     *    that is not the kind the assertion is about. That gap is real and is
     *    now named out loud by the kernel; this checks the datagram socket we
     *    genuinely model. */
    {
        int dg = socket(AF_INET, SOCK_DGRAM, 0);
        if (dg >= 0) {
            struct sockaddr_in to;
            memset(&to, 0, sizeof to);
            to.sin_family = AF_INET; to.sin_port = htons(9);
            to.sin_addr.s_addr = htonl(0x7f000001);
            size_t big = 1u << 20;
            char *buf = malloc(big);
            if (buf) {
                memset(buf, 'q', big);
                struct iovec iov = { buf, big };
                struct msghdr mh; memset(&mh, 0, sizeof mh);
                mh.msg_iov = &iov; mh.msg_iovlen = 1;
                mh.msg_name = &to; mh.msg_namelen = sizeof to;
                errno = 0;
                ssize_t rc = sendmsg(dg, &mh, 0);
                CK(rc < 0 && errno == EMSGSIZE, "an oversized DATAGRAM is EMSGSIZE, not silently shortened");
                free(buf);
            }
            close(dg);
        }
    }

    close(sv[0]); close(sv[1]);
    printf(fails ? "LXMSG: FAILED\n" : "LXMSG: OK\n");
    return fails ? 1 : 0;
}
