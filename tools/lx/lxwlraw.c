/*
 * lxwlraw.c -- the Wayland handshake by hand, with a hexdump (M1978).
 *
 * libwayland stalls in the guest after receiving bytes that are byte-identical
 * to ones it accepts happily on the host. That leaves two possibilities and no
 * way to tell them apart from outside the process: either the bytes are not
 * actually landing where recvmsg says they are, or libwayland's own logic is
 * unhappy about something unrelated to their content.
 *
 * This client does the same handshake with raw syscalls and PRINTS WHAT IT
 * GOT. If the dump is correct, the socket path is exonerated and the problem
 * is inside libwayland.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

static void put32(unsigned char *p, unsigned v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static unsigned get32(const unsigned char *p) { return p[0]|(p[1]<<8)|(p[2]<<16)|((unsigned)p[3]<<24); }

int main(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { printf("LXWLRAW: socket failed\n"); fflush(stdout); return 1; }
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, "/run/wayland-0");
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        printf("LXWLRAW: connect failed\n"); fflush(stdout); return 2;
    }

    /* get_registry(new_id=2) then sync(new_id=3), in one write -- exactly what
     * libwayland sends. */
    unsigned char req[24];
    put32(req + 0, 1); put32(req + 4, (12u << 16) | 1); put32(req + 8, 2);      /* get_registry */
    put32(req + 12, 1); put32(req + 16, (12u << 16) | 0); put32(req + 20, 3);   /* sync */
    if (write(fd, req, sizeof req) != (ssize_t)sizeof req) {
        printf("LXWLRAW: write failed\n"); fflush(stdout); return 3;
    }

    unsigned char buf[1024];
    ssize_t n = read(fd, buf, sizeof buf);
    printf("LXWLRAW: read %zd bytes\n", n);
    if (n <= 0) { fflush(stdout); return 4; }

    /* Walk the messages and describe each, so a malformed size or opcode is
     * visible rather than inferred. */
    int off = 0, count = 0;
    while (off + 8 <= n) {
        unsigned obj = get32(buf + off);
        unsigned szop = get32(buf + off + 4);
        unsigned size = szop >> 16, op = szop & 0xFFFF;
        if (size < 8 || off + (int)size > n) { printf("LXWLRAW: bad size %u at %d\n", size, off); break; }
        printf("LXWLRAW-MSG: obj=%u op=%u size=%u", obj, op, size);
        if (op == 0 && size > 16 && obj != 1 && obj != 3) {   /* a registry global: name, string, version */
            unsigned name = get32(buf + off + 8);
            unsigned slen = get32(buf + off + 12);
            printf("  name=%u iface=\"%.*s\"", name, (int)(slen ? slen - 1 : 0), buf + off + 16);
        }
        printf("\n");
        off += (int)size; count++;
    }
    printf("LXWLRAW: %d complete message(s) in %zd bytes\n", count, n);
    fflush(stdout);
    close(fd);

    /* Round two, through RECVMSG with TWO iovecs -- the shape libwayland uses
     * (its connection buffer is a ring, so the free space is usually split in
     * two). read() above proved the bytes reach the socket; this proves the
     * scatter puts them in the right places. */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { printf("LXWLRAW2: socket failed\n"); fflush(stdout); return 5; }
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        printf("LXWLRAW2: connect failed\n"); fflush(stdout); return 6;
    }
    if (write(fd, req, sizeof req) != (ssize_t)sizeof req) {
        printf("LXWLRAW2: write failed\n"); fflush(stdout); return 7;
    }
    unsigned char a[64], b[512];
    memset(a, 0xEE, sizeof a); memset(b, 0xEE, sizeof b);
    struct iovec iov[2] = { { a, sizeof a }, { b, sizeof b } };
    struct msghdr mh; memset(&mh, 0, sizeof mh);
    mh.msg_iov = iov; mh.msg_iovlen = 2;
    ssize_t r2 = recvmsg(fd, &mh, 0);
    printf("LXWLRAW2: recvmsg -> %zd (iov0=%zu iov1=%zu)\n", r2, sizeof a, sizeof b);
    if (r2 > 0) {
        /* The first message must be intact ACROSS the iovec boundary. */
        unsigned o0 = get32(a), s0 = get32(a + 4) >> 16;
        printf("LXWLRAW2: first msg obj=%u size=%u; iov0 tail %02x %02x, iov1 head %02x %02x\n",
               o0, s0, a[62], a[63], b[0], b[1]);
        /* Reassemble and re-walk, so a scatter that dropped or duplicated a
         * byte shows up as a bad message rather than as plausible garbage. */
        unsigned char all[1024]; int m = 0;
        for (int i = 0; i < (int)sizeof a && m < r2; i++) all[m++] = a[i];
        for (int i = 0; m < r2; i++) all[m++] = b[i];
        int off2 = 0, c2 = 0;
        while (off2 + 8 <= m) {
            unsigned sz = get32(all + off2 + 4) >> 16;
            if (sz < 8 || off2 + (int)sz > m) { printf("LXWLRAW2: bad size %u at %d\n", sz, off2); break; }
            off2 += (int)sz; c2++;
        }
        printf("LXWLRAW2: %d complete message(s) reassembled from %zd bytes\n", c2, r2);
    }
    fflush(stdout);
    close(fd);
    return 0;
}
