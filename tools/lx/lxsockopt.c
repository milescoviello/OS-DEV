/* lxsockopt.c -- getsockopt ANSWERED ZERO TO EVERY OPTION EVER ASKED.
 *
 * The handler wrote a 4-byte zero into the caller's buffer and returned
 * success, without reading optname at all. It was written for SO_ERROR, where
 * zero means "this connection is fine" and the answer is right. Every other
 * option inherited it.
 *
 * So a socket's send buffer was nought bytes, its type was neither STREAM nor
 * DGRAM, its domain was neither AF_UNIX nor AF_INET, and an option nobody had
 * implemented reported a clean, confident zero. Firefox's IPC I/O thread built
 * its channel, asked how much it could send, and aborted:
 *
 *   t219 53(1, 80801, 0) = 0   socketpair(AF_UNIX, STREAM|CLOEXEC|NONBLOCK)
 *   t219 55(3d, 1, 7)    = 0   getsockopt(fd 61, SOL_SOCKET, SO_SNDBUF)
 *   t219 1(2, ..., 78)   = 78  "###!!! ABORT: ... ipc_channel_posix.cc:128"
 *
 * Every expectation below was checked against a real Linux kernel first, and
 * three of them are not what I would have written: setting SO_SNDBUF makes a
 * later get report DOUBLE the request, an unknown option is ENOPROTOOPT and
 * not EINVAL, and any of this on a non-socket is ENOTSOCK and not ENOTTY.
 *
 * The SIZES are deliberately not asserted against Linux's numbers -- ours are
 * ours. What is asserted is that they are real: positive, big enough to send
 * a message through, and the same number a write can actually use.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <fcntl.h>

static int fails;
#define CK(c, msg) do { if (c) printf("LXSOCKOPT: ok   %s\n", msg); \
                        else { printf("LXSOCKOPT: FAIL %s (errno %d %s)\n", msg, errno, strerror(errno)); fails++; } } while (0)

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { printf("LXSOCKOPT: FAIL socketpair\n"); return 1; }

    /* 1. THE ONE FIREFOX ASKED. A send buffer of zero bytes is not a socket. */
    int v = -1; socklen_t l = sizeof v;
    CK(getsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &v, &l) == 0, "getsockopt(SO_SNDBUF) is answered");
    CK(v > 0, "...and the send buffer is NOT zero bytes");
    CK(v >= 4096, "...and is big enough to put a message through (>= 4 KiB)");
    CK(l == 4, "...and reports 4 bytes written, not a guess");
    int snd = v;

    v = -1; l = sizeof v;
    CK(getsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &v, &l) == 0 && v > 0, "SO_RCVBUF is a real number too");

    /* 2. THE BUFFER SIZE IS THE SIZE THAT IS REALLY THERE. Not an assertion
     *    about a constant -- an assertion that the number means something: a
     *    write of a quarter of it must fit without blocking. */
    {
        char *big = malloc(snd / 4);
        memset(big, 0x5a, snd / 4);
        int flags = fcntl(sv[1], F_GETFL);
        fcntl(sv[1], F_SETFL, flags | O_NONBLOCK);
        ssize_t w = write(sv[1], big, snd / 4);
        CK(w == snd / 4, "a write of a QUARTER of the reported send buffer fits in one go");
        char *rb = malloc(snd / 4);
        ssize_t rd = read(sv[0], rb, snd / 4);
        CK(rd == w, "...and reads back the same length");
        fcntl(sv[1], F_SETFL, flags);
        free(big); free(rb);
    }

    /* 3. SO_TYPE AND SO_DOMAIN. Zero is neither a socket type nor an address
     *    family -- a program switching on either was switching on nothing. */
    v = -1; l = sizeof v;
    CK(getsockopt(sv[0], SOL_SOCKET, SO_TYPE, &v, &l) == 0 && v == SOCK_STREAM, "SO_TYPE reports SOCK_STREAM");
    v = -1; l = sizeof v;
    CK(getsockopt(sv[0], SOL_SOCKET, SO_DOMAIN, &v, &l) == 0 && v == AF_UNIX, "SO_DOMAIN reports AF_UNIX");
    v = -1; l = sizeof v;
    CK(getsockopt(sv[0], SOL_SOCKET, SO_ERROR, &v, &l) == 0 && v == 0, "SO_ERROR still reports no error (the one zero that was right)");
    v = -1; l = sizeof v;
    CK(getsockopt(sv[0], SOL_SOCKET, SO_ACCEPTCONN, &v, &l) == 0 && v == 0, "SO_ACCEPTCONN is 0 on a connected socket");

    /* 4. A BOOLEAN OPTION ROUND-TRIPS. Accepting a set and then reporting 0
     *    is the same defect from the other side: the program believes it
     *    changed something it did not. */
    v = 1;
    CK(setsockopt(sv[0], SOL_SOCKET, SO_REUSEADDR, &v, sizeof v) == 0, "setsockopt(SO_REUSEADDR, 1) accepted");
    v = -1; l = sizeof v;
    CK(getsockopt(sv[0], SOL_SOCKET, SO_REUSEADDR, &v, &l) == 0 && v != 0, "...and it reads back as SET");
    v = 0;
    setsockopt(sv[0], SOL_SOCKET, SO_REUSEADDR, &v, sizeof v);
    v = -1; l = sizeof v;
    CK(getsockopt(sv[0], SOL_SOCKET, SO_REUSEADDR, &v, &l) == 0 && v == 0, "...and clears again");

    /* 5. SO_SNDBUF SET THEN READ. Linux reports DOUBLE the request (clamped to
     *    the system maximum), so a get that echoes the request verbatim is as
     *    wrong as one that reports zero. Asserted as "at least what a clamp
     *    could give", which is what a portable program can rely on. */
    v = 2048;
    if (setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &v, sizeof v) == 0) {
        int got = -1; l = sizeof got;
        CK(getsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &got, &l) == 0 && got >= 2048,
           "SO_SNDBUF set to 2048 reads back at least 2048 (Linux doubles it; a clamp may cap it)");
    }

    /* 6. SO_PEERCRED: the pid on the far end, and TWELVE bytes not four. A
     *    struct ucred whose length is reported as 4 leaves uid and gid as
     *    whatever was on the caller's stack. */
    {
        struct ucred uc; memset(&uc, 0xAA, sizeof uc);
        socklen_t ul = sizeof uc;
        if (getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, &uc, &ul) == 0) {
            CK(ul == sizeof uc, "SO_PEERCRED reports the full struct ucred length");
            CK(uc.pid == getpid(), "...and names our own pid for a socketpair");
        } else {
            printf("LXSOCKOPT: FAIL SO_PEERCRED was refused (errno %d %s)\n", errno, strerror(errno)); fails++;
        }
    }

    /* 7. AN OPTION NOBODY IMPLEMENTED MUST SAY SO. This is the assertion that
     *    dies if anyone reinstates the confident zero. */
    v = -12345; l = sizeof v;
    errno = 0;
    CK(getsockopt(sv[0], SOL_SOCKET, 9999, &v, &l) < 0 && errno == ENOPROTOOPT,
       "an unimplemented option is ENOPROTOOPT, not a confident zero");
    CK(v == -12345, "...and the caller's buffer is left ALONE when the call fails");

    /* 8. AND ON A NON-SOCKET, ENOTSOCK. */
    {
        int p[2];
        if (pipe(p) == 0) {
            v = -1; l = sizeof v; errno = 0;
            CK(getsockopt(p[0], SOL_SOCKET, SO_TYPE, &v, &l) < 0 && errno == ENOTSOCK,
               "getsockopt on a PIPE is ENOTSOCK");
            close(p[0]); close(p[1]);
        }
    }

    /* 9. A DATAGRAM SOCKET IS A DIFFERENT TYPE, and a listener accepts. Both
     *    were zero before, which is to say indistinguishable from everything. */
    {
        int d = socket(AF_INET, SOCK_DGRAM, 0);
        if (d >= 0) {
            v = -1; l = sizeof v;
            CK(getsockopt(d, SOL_SOCKET, SO_TYPE, &v, &l) == 0 && v == SOCK_DGRAM, "SO_TYPE on a UDP socket reports SOCK_DGRAM");
            v = -1; l = sizeof v;
            CK(getsockopt(d, SOL_SOCKET, SO_DOMAIN, &v, &l) == 0 && v == AF_INET, "SO_DOMAIN on it reports AF_INET");
            close(d);
        }
        int ls = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
        sa.sun_family = AF_UNIX;
        snprintf(sa.sun_path, sizeof sa.sun_path, "/tmp/lxsockopt.sock");
        unlink(sa.sun_path);
        if (ls >= 0 && bind(ls, (struct sockaddr *)&sa, sizeof sa) == 0 && listen(ls, 4) == 0) {
            v = -1; l = sizeof v;
            CK(getsockopt(ls, SOL_SOCKET, SO_ACCEPTCONN, &v, &l) == 0 && v == 1, "SO_ACCEPTCONN is 1 on a LISTENING socket");
        }
        if (ls >= 0) { close(ls); unlink(sa.sun_path); }
    }

    /* 10. TCP_NODELAY, at a different LEVEL. A handler that ignores optname
     *     also ignores level, so every level answered the same zero. */
    {
        int t = socket(AF_INET, SOCK_STREAM, 0);
        if (t >= 0) {
            v = 1;
            if (setsockopt(t, IPPROTO_TCP, TCP_NODELAY, &v, sizeof v) == 0) {
                v = -1; l = sizeof v;
                CK(getsockopt(t, IPPROTO_TCP, TCP_NODELAY, &v, &l) == 0 && v != 0, "TCP_NODELAY round-trips at SOL_TCP");
            } else { printf("LXSOCKOPT: FAIL setsockopt(TCP_NODELAY) refused (errno %d)\n", errno); fails++; }
            close(t);
        }
    }

    close(sv[0]); close(sv[1]);
    printf(fails ? "LXSOCKOPT: FAILED\n" : "LXSOCKOPT: OK\n");
    return fails ? 1 : 0;
}
