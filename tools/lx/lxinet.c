/*
 * lxinet.c -- AF_INET sockets through the Linux ABI (M1967).
 *
 * Phase 6's gate is "a script that touches the network", and the blocker was
 * that AF_INET sockets were not POLLABLE: tcp_read pulled frames straight off
 * the NIC, so nothing could answer "is there data?" without consuming it --
 * and an event loop asks exactly that about every socket it owns before
 * reading any of them. poll() reported POLLNVAL for socket fds, which is why
 * libuv could not drive them at all.
 *
 * This is the same path Node uses, exercised directly so a failure is a
 * kernel failure rather than a five-minute V8 run:
 *
 *   1. DNS over a UDP socket -- sendto/recvfrom with poll() in between.
 *   2. TCP connect + an HTTP request, driven by poll() rather than a
 *      blocking read.
 *
 * poll() is the assertion, not a convenience: if it returned POLLNVAL or lied
 * about readiness, the reads below would spin or block forever.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

/* Build a minimal DNS A query for `host`. Returns the length. */
static int dns_query(unsigned char *q, const char *host, unsigned short id) {
    int n = 0;
    q[n++] = (unsigned char)(id >> 8); q[n++] = (unsigned char)id;
    q[n++] = 0x01; q[n++] = 0x00;         /* recursion desired */
    q[n++] = 0; q[n++] = 1;               /* QDCOUNT = 1 */
    q[n++] = 0; q[n++] = 0;               /* ANCOUNT */
    q[n++] = 0; q[n++] = 0;               /* NSCOUNT */
    q[n++] = 0; q[n++] = 0;               /* ARCOUNT */
    const char *p = host;
    while (*p) {                           /* QNAME: length-prefixed labels */
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);
        q[n++] = (unsigned char)l;
        memcpy(q + n, p, (size_t)l); n += l;
        if (!dot) break;
        p = dot + 1;
    }
    q[n++] = 0;
    q[n++] = 0; q[n++] = 1;               /* QTYPE = A */
    q[n++] = 0; q[n++] = 1;               /* QCLASS = IN */
    return n;
}

/* Pull the first A record out of a DNS response. 0 on success. */
static int dns_answer(const unsigned char *r, int len, unsigned char ip[4]) {
    if (len < 12) return -1;
    int qd = (r[4] << 8) | r[5], an = (r[6] << 8) | r[7];
    if (an < 1) return -1;
    int off = 12;
    for (int i = 0; i < qd && off < len; i++) {         /* skip the questions */
        while (off < len && r[off]) off += r[off] + 1;
        off += 1 + 4;
    }
    for (int i = 0; i < an && off + 12 <= len; i++) {
        if ((r[off] & 0xC0) == 0xC0) off += 2;          /* compressed name */
        else { while (off < len && r[off]) off += r[off] + 1; off += 1; }
        if (off + 10 > len) return -1;
        int type = (r[off] << 8) | r[off + 1];
        int rdl  = (r[off + 8] << 8) | r[off + 9];
        off += 10;
        if (type == 1 && rdl == 4 && off + 4 <= len) { memcpy(ip, r + off, 4); return 0; }
        off += rdl;
    }
    return -1;
}

/* Wait up to `ms` for `ev` on `fd`. Returns the revents, or 0 on timeout. */
static int waitfd(int fd, short ev, int ms) {
    struct pollfd p; p.fd = fd; p.events = ev; p.revents = 0;
    int r = poll(&p, 1, ms);
    if (r <= 0) return 0;
    if (p.revents & POLLNVAL) { printf("LXINET: poll says POLLNVAL on fd %d -- socket not pollable\n", fd); fflush(stdout); return -1; }
    return p.revents;
}

int main(void) {
    unsigned char ip[4];

    /* ---- 1. DNS over UDP, driven by poll ---- */
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u < 0) { printf("LXINET: UDP socket failed\n"); fflush(stdout); return 1; }
    struct sockaddr_in ns; memset(&ns, 0, sizeof ns);
    ns.sin_family = AF_INET; ns.sin_port = htons(53);
    ns.sin_addr.s_addr = inet_addr("10.0.2.3");        /* QEMU user-mode's DNS */
    unsigned char q[512]; int qn = dns_query(q, "example.com", 0x1234);
    if (sendto(u, q, (size_t)qn, 0, (struct sockaddr *)&ns, sizeof ns) != qn) {
        printf("LXINET: DNS sendto failed\n"); fflush(stdout); return 2;
    }
    int rv = waitfd(u, POLLIN, 5000);
    if (rv <= 0) { printf("LXINET: no DNS reply (poll revents=%d)\n", rv); fflush(stdout); return 3; }
    unsigned char resp[512];
    ssize_t rn = recvfrom(u, resp, sizeof resp, 0, NULL, NULL);
    if (rn <= 0 || dns_answer(resp, (int)rn, ip) != 0) {
        printf("LXINET: DNS reply unusable (%zd bytes)\n", rn); fflush(stdout); return 4;
    }
    close(u);
    printf("LXINET-DNS: example.com -> %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
    fflush(stdout);

    /* ---- 2. TCP connect + HTTP, driven by poll ---- */
    int t = socket(AF_INET, SOCK_STREAM, 0);
    if (t < 0) { printf("LXINET: TCP socket failed\n"); fflush(stdout); return 5; }
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(80);
    memcpy(&sa.sin_addr, ip, 4);
    if (connect(t, (struct sockaddr *)&sa, sizeof sa) != 0) {
        printf("LXINET: TCP connect failed\n"); fflush(stdout); return 6;
    }
    if (waitfd(t, POLLOUT, 5000) <= 0) { printf("LXINET: never became writable\n"); fflush(stdout); return 7; }
    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    if (write(t, req, strlen(req)) != (ssize_t)strlen(req)) {
        printf("LXINET: request write failed\n"); fflush(stdout); return 8;
    }

    /* Read the reply the way an event loop does: poll, then read what is
     * ready, never blocking on the socket itself. */
    char buf[2048]; int total = 0;
    for (int turns = 0; turns < 200 && total < (int)sizeof buf - 1; turns++) {
        int ev = waitfd(t, POLLIN, 200);
        if (ev < 0) return 9;
        if (ev == 0) continue;
        ssize_t n = read(t, buf + total, sizeof buf - 1 - (size_t)total);
        if (n <= 0) break;                              /* EOF */
        total += (int)n;
        if (strstr(buf, "\r\n\r\n")) break;             /* headers complete: enough */
    }
    buf[total > 0 ? total : 0] = 0;
    close(t);
    if (total <= 0 || strncmp(buf, "HTTP/1.", 7) != 0) {
        printf("LXINET: no HTTP response (%d bytes)\n", total);
        fflush(stdout); return 10;
    }
    int sp = 0; while (sp < total && buf[sp] != ' ') sp++;
    int code = (sp + 3 < total) ? (buf[sp+1]-'0')*100 + (buf[sp+2]-'0')*10 + (buf[sp+3]-'0') : 0;
    printf("LXINET-HTTP: status %d, %d bytes, poll-driven\n", code, total);
    fflush(stdout);
    return 0;
}
