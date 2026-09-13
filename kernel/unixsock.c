/*
 * unixsock.c — path-keyed AF_UNIX stream sockets (M1169). See unixsock.h.
 *
 * A fixed table of connections, each a pair of byte rings (a2b, b2a) so the two
 * endpoints stream in both directions, plus a fixed table of listeners keyed by
 * pathname. An ENDPOINT id packs the connection index and which side (A=client,
 * B=server): ep = (conn<<1)|side. send writes the side's TX ring (= the peer's
 * RX ring) and wakes the peer; recv reads the side's RX ring and blocks once
 * when empty, returning 0 at EOF (peer closed and the ring is drained). No fd
 * table is needed: the small integer ep handle is the socket reference, and
 * because it indexes this global table it stays valid across fork().
 *
 * M1609: the old comment claimed the IF=0 int-0x80 gate alone made "empty?
 * then block" atomic against a sender -- true only on a single CPU. Since
 * M1531 a sender and a blocking receiver can run on two different cores at
 * once: receiver checks its ring (empty), sender enqueues + checks the
 * waiter field (still unset, so no wake), THEN receiver sets the waiter and
 * blocks forever. unix_listen/unix_connect/unix_socketpair's table
 * scan-and-claim has the same-shaped hazard one level up. One lock now
 * covers every lookup/create/check-set-block/produce-check-wake sequence in
 * this file, so none of them can interleave into a lost wakeup or a
 * double-claimed slot. Same idiom as pmm.c/swap.c/tls.c/pty.c/mbox.c. */
#include "unixsock.h"
#include "task.h"
#include "console.h"   /* kprintf for the close/EOF trace (M1978) */

static volatile int usock_lock;
static inline uint64_t usock_irq_save(void) {
    uint64_t fl;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
    while (__atomic_exchange_n(&usock_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return fl;
}
static inline void usock_irq_restore(uint64_t fl) {
    __atomic_store_n(&usock_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(fl) : "memory", "cc");
}

/* M1965 raised all four. The old numbers were sized for one in-tree demo
 * talking to itself; a real event-loop program (Node, and later a Wayland
 * compositor) opens a listener per service and a connection per client, and
 * 64 bytes of path could not even hold a name under /run. A 4 KiB ring also
 * makes every sizeable message a short write, which is legal but forces the
 * sender back through poll for each 4 KiB. */
#define U_LISTEN  32              /* concurrent listeners */
#define U_CONN    128             /* concurrent connections (each = 2 endpoints) */
#define U_RING    16384           /* bytes buffered per direction */
#define U_PATH    128             /* Linux sun_path is 108 (M1965) */

struct uring { unsigned char buf[U_RING]; int head, tail; };   /* empty when head==tail */
static int rcount(struct uring *r) { return (r->head - r->tail + U_RING) % U_RING; }
static int rfree(struct uring *r)  { return U_RING - 1 - rcount(r); }   /* keep one slot empty to tell full from empty */
static int rput(struct uring *r, const unsigned char *d, int n) {
    int f = rfree(r); if (n > f) n = f;
    for (int i = 0; i < n; i++) { r->buf[r->head] = d[i]; r->head = (r->head + 1) % U_RING; }
    return n;
}
static int rget(struct uring *r, unsigned char *d, int n) {
    int c = rcount(r); if (n > c) n = c;
    for (int i = 0; i < n; i++) { d[i] = r->buf[r->tail]; r->tail = (r->tail + 1) % U_RING; }
    return n;
}

struct uconn {
    int used;
    struct uring a2b, b2a;        /* A(client)->B(server) stream, and B->A stream */
    int a_closed, b_closed;
    /* HALF-CLOSE (M1965). shutdown(fd, SHUT_WR) ends one DIRECTION: the peer
     * must read EOF while this side can still read the peer's reply. Without
     * it, Node's socket.end() was accepted and did nothing, the server never
     * saw EOF, its connection handle stayed open, and the event loop had
     * nothing left to do but could not exit -- a hang with no error. */
    int a_wr_closed, b_wr_closed;
    task_t *a_waiter, *b_waiter;  /* side A blocked reading b2a; side B blocked reading a2b */
};
static struct uconn conns[U_CONN];

struct ulisten {
    int used;
    char path[U_PATH];
    int  pend[U_CONN];            /* connection indices awaiting accept (FIFO) */
    int  np;
    task_t *waiter;               /* a server blocked in accept */
};
static struct ulisten lis[U_LISTEN];

static int peq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }

int unix_listen(const char *path) {
    if (!path || !path[0]) return -1;
    uint64_t fl = usock_irq_save();
    for (int i = 0; i < U_LISTEN; i++) if (lis[i].used && peq(lis[i].path, path)) { usock_irq_restore(fl); return i; }   /* already bound: idempotent re-listen (single-user OS) */
    for (int i = 0; i < U_LISTEN; i++) if (!lis[i].used) {
        int j = 0; while (path[j] && j < U_PATH - 1) { lis[i].path[j] = path[j]; j++; } lis[i].path[j] = 0;
        /* Refuse an over-long name instead of listening on a PREFIX of it --
         * a truncated bind succeeds and then no connect ever matches, which
         * looks like "the server is not running". Same rule as the VMA path
         * table (M1955). */
        if (path[j]) { usock_irq_restore(fl); return -1; }
        lis[i].used = 1; lis[i].np = 0; lis[i].waiter = 0;
        usock_irq_restore(fl);
        return i;
    }
    usock_irq_restore(fl);
    return -1;                                    /* listener table full */
}

/* Release a listener's name (M1965). close(listen_fd) must free the path, or
 * a server that restarts finds its own socket still bound -- and with a table
 * of 32, a few restarts exhaust it. Pending-but-unaccepted connections are
 * closed on the server side so a client blocked in connect() sees EOF rather
 * than waiting on a server that is gone. */
int unix_unlisten(int lid) {
    if (lid < 0 || lid >= U_LISTEN) return -1;
    uint64_t fl = usock_irq_save();
    if (!lis[lid].used) { usock_irq_restore(fl); return -1; }
    for (int i = 0; i < lis[lid].np; i++) {
        struct uconn *c = &conns[lis[lid].pend[i]];
        c->b_closed = 1;
        if (c->a_waiter) { task_wake(c->a_waiter); c->a_waiter = 0; }
    }
    lis[lid].np = 0; lis[lid].used = 0; lis[lid].path[0] = 0;
    if (lis[lid].waiter) { task_wake(lis[lid].waiter); lis[lid].waiter = 0; }
    usock_irq_restore(fl);
    return 0;
}

int unix_connect(const char *path) {
    if (!path) return -1;
    uint64_t fl = usock_irq_save();
    int li = -1; for (int i = 0; i < U_LISTEN; i++) if (lis[i].used && peq(lis[i].path, path)) { li = i; break; }
    if (li < 0) { usock_irq_restore(fl); return -1; }   /* nobody listening on this path */
    if (lis[li].np >= U_CONN) { usock_irq_restore(fl); return -1; }   /* accept backlog full */
    int ci = -1; for (int i = 0; i < U_CONN; i++) if (!conns[i].used) { ci = i; break; }
    if (ci < 0) { usock_irq_restore(fl); return -1; }   /* connection table full */
    struct uconn *c = &conns[ci];
    c->used = 1; c->a2b.head = c->a2b.tail = 0; c->b2a.head = c->b2a.tail = 0;
    c->a_closed = c->b_closed = 0; c->a_wr_closed = c->b_wr_closed = 0; c->a_waiter = c->b_waiter = 0;
    lis[li].pend[lis[li].np++] = ci;               /* enqueue for the server to accept */
    if (lis[li].waiter) { task_wake(lis[li].waiter); lis[li].waiter = 0; }
    usock_irq_restore(fl);
    return (ci << 1) | 0;                          /* client gets side A */
}

int unix_accept(int lid) {
    if (lid < 0 || lid >= U_LISTEN) return -1;
    uint64_t fl = usock_irq_save();
    if (!lis[lid].used) { usock_irq_restore(fl); return -1; }
    struct ulisten *l = &lis[lid];
    if (l->np == 0) {                              /* no pending connection -> block for one */
        l->waiter = task_self();
        usock_irq_restore(fl);
        task_block();                              /* woken by a connector (or a kill) */
        fl = usock_irq_save();
        l->waiter = 0;
        if (l->np == 0) { usock_irq_restore(fl); return -1; }   /* spurious wake -> nothing to accept */
    }
    int ci = l->pend[0];                           /* FIFO dequeue */
    for (int i = 1; i < l->np; i++) l->pend[i - 1] = l->pend[i];
    l->np--;
    usock_irq_restore(fl);
    return (ci << 1) | 1;                          /* server gets side B */
}

/* Resolve an endpoint id to its connection + side (0=A, 1=B); 0 if invalid. */
static struct uconn *ep_conn(int ep, int *side) {
    if (ep < 0) return 0;
    int ci = ep >> 1;
    if (ci >= U_CONN || !conns[ci].used) return 0;
    *side = ep & 1;
    return &conns[ci];
}

long unix_send(int ep, const void *buf, unsigned long len) {
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s); if (!c) { usock_irq_restore(fl); return -1; }
    int peer_closed = s ? c->a_closed : c->b_closed;
    int self_wr = s ? c->b_wr_closed : c->a_wr_closed;
    if (peer_closed || self_wr) { usock_irq_restore(fl); return -1; }   /* peer is gone, or we shut our write side */
    struct uring *tx = s ? &c->b2a : &c->a2b;                    /* B writes b2a, A writes a2b */
    int n = rput(tx, (const unsigned char *)buf, (int)len);
    task_t **pw = s ? &c->a_waiter : &c->b_waiter;               /* wake the peer's blocked reader */
    if (n > 0 && *pw) { task_wake(*pw); *pw = 0; }
    usock_irq_restore(fl);
    return n;
}

long unix_recv(int ep, void *buf, unsigned long max) {
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s); if (!c) { usock_irq_restore(fl); return -1; }
    struct uring *rx = s ? &c->a2b : &c->b2a;                    /* B reads a2b, A reads b2a */
    int self_closed = s ? c->b_closed : c->a_closed;
    if (self_closed) { usock_irq_restore(fl); return -1; }       /* we closed our own end */
    /* WAIT IN A LOOP, and never report EOF for an empty ring (M1978).
     *
     * This used to block once and, if the ring was still empty on waking,
     * return 0 -- which to every caller means END OF FILE. A spurious wake is
     * not EOF, and spurious wakes are routine here: task_wake on a task that
     * has not blocked yet sets `wake_pending`, so a burst of sends while the
     * reader is running leaves a wake banked that fires the instant it finally
     * blocks. A Wayland client hit this exactly: it read 94 bytes of our
     * registry events, came back for the rest, and got 0 -- libwayland reads
     * that as the compositor hanging up, and wl_display_roundtrip never
     * returns. EOF is a property of the PEER, not of the ring being empty. */
    while (rcount(rx) == 0) {
        int peer_closed = (s ? c->a_closed : c->b_closed) || (s ? c->a_wr_closed : c->b_wr_closed);
        if (peer_closed) {
            if (g_unix_verbose)
                kprintf("[usock] recv(ep %d side %d) EOF: a_closed=%d b_closed=%d a_wr=%d b_wr=%d\n",
                        ep, s, c->a_closed, c->b_closed, c->a_wr_closed, c->b_wr_closed);
            usock_irq_restore(fl); return 0;                     /* EOF: peer closed (or shut down writing) and ring drained */
        }
        task_t **mw = s ? &c->b_waiter : &c->a_waiter;
        *mw = task_self();
        usock_irq_restore(fl);
        task_block();                                            /* woken by the peer's send/close (or a kill) */
        fl = usock_irq_save();
        *mw = 0;
    }
    int got = rget(rx, (unsigned char *)buf, (int)max);
    usock_irq_restore(fl);
    return got;
}

/* shutdown(2). how: 0 = SHUT_RD, 1 = SHUT_WR, 2 = SHUT_RDWR. Only the write
 * direction is modelled -- SHUT_RD has no observable effect on a local ring
 * beyond discarding what is already buffered, and no caller depends on it. */
int unix_shutdown(int ep, int how) {
    if (how != 1 && how != 2) return 0;                          /* SHUT_RD: accepted, nothing to do */
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s); if (!c) { usock_irq_restore(fl); return -1; }
    if (s) c->b_wr_closed = 1; else c->a_wr_closed = 1;
    task_t **pw = s ? &c->a_waiter : &c->b_waiter;               /* wake the peer so its recv returns EOF */
    if (*pw) { task_wake(*pw); *pw = 0; }
    usock_irq_restore(fl);
    return 0;
}

int g_unix_verbose;     /* -append unixverbose: trace closes and EOF decisions */
int unix_close(int ep) {
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s); if (!c) { usock_irq_restore(fl); return -1; }
    if (g_unix_verbose) kprintf("[usock] close(ep %d side %d)\n", ep, s);
    if (s) c->b_closed = 1; else c->a_closed = 1;
    task_t **pw = s ? &c->a_waiter : &c->b_waiter;               /* wake the peer so its recv returns EOF */
    if (*pw) { task_wake(*pw); *pw = 0; }
    if (c->a_closed && c->b_closed) c->used = 0;                 /* both ends gone -> free the slot */
    usock_irq_restore(fl);
    return 0;
}

/* Is endpoint `ep` readable — i.e. would unix_recv NOT block? True when its RX
 * ring has bytes OR the peer has closed (recv would return data or EOF). */
static int ep_readable(int ep) {
    int s; struct uconn *c = ep_conn(ep, &s); if (!c) return 0;
    struct uring *rx = s ? &c->a2b : &c->b2a;
    int peer_closed = (s ? c->a_closed : c->b_closed) || (s ? c->a_wr_closed : c->b_wr_closed);
    return rcount(rx) > 0 || peer_closed;      /* pending EOF counts as readable -- that is how a poller learns of it */
}

/* Non-blocking readiness predicates, for the fd table's poll/epoll ladder
 * (M1965). `ep_readable` already existed as exactly the right test -- it was
 * simply static, usable only by unix_wait_any's own blocking multiplexer.
 * app_fd_ready is called in a loop over many fds and must never block, so it
 * needs these instead. */
int unix_readable(int ep) {
    uint64_t fl = usock_irq_save();
    int r = ep_readable(ep);
    usock_irq_restore(fl);
    return r;
}
/* Does this listener have a connection waiting? POLLIN on a listening socket
 * means "accept would not block", which is what a server's event loop polls. */
int unix_pending(int lid) {
    if (lid < 0 || lid >= U_LISTEN) return 0;
    uint64_t fl = usock_irq_save();
    int n = lis[lid].used ? lis[lid].np : 0;
    usock_irq_restore(fl);
    return n > 0;
}
/* accept without blocking: -1 when nothing is pending. unix_accept blocks, and
 * a non-blocking accept(2) after a readable poll must not. */
int unix_accept_nb(int lid) {
    if (!unix_pending(lid)) return -1;
    return unix_accept(lid);
}

/* wait_any: the poll/epoll-style readiness multiplexer. Given up to 16 endpoint
 * ids, return the index of the first one that is readable, blocking once if none
 * are. Registers the caller on every endpoint's RX waiter slot, blocks, then
 * unregisters and re-scans; a spurious/kill wake returns -1 (the caller re-polls)
 * rather than spinning. NB one waiter slot per endpoint, so a process shouldn't
 * both wait_any and recv-block on the same endpoint concurrently. (M1170) */
int unix_wait_any(const int *eps, int n) {
    if (n <= 0 || n > 16) return -1;
    uint64_t fl = usock_irq_save();
    for (int i = 0; i < n; i++) if (ep_readable(eps[i])) { usock_irq_restore(fl); return i; }   /* fast path: already ready */
    for (int i = 0; i < n; i++) {                                    /* park on each endpoint's reader slot */
        int s; struct uconn *c = ep_conn(eps[i], &s); if (!c) continue;
        *(s ? &c->b_waiter : &c->a_waiter) = task_self();
    }
    usock_irq_restore(fl);
    task_block();                                                    /* woken by a sender/close on any of them (or a kill) */
    fl = usock_irq_save();
    for (int i = 0; i < n; i++) {                                    /* unregister ourselves everywhere */
        int s; struct uconn *c = ep_conn(eps[i], &s); if (!c) continue;
        task_t **mw = s ? &c->b_waiter : &c->a_waiter;
        if (*mw == task_self()) *mw = 0;
    }
    for (int i = 0; i < n; i++) if (ep_readable(eps[i])) { usock_irq_restore(fl); return i; }   /* re-scan after the wake */
    usock_irq_restore(fl);
    return -1;                                                       /* spurious/kill -> caller re-polls */
}

/* socketpair(2): hand back two already-connected endpoints with no path /
 * listen / accept dance — just claim a free connection slot (the same struct a
 * connect/accept pair would use) and return both of its sides. The two ends
 * then stream bidirectionally exactly like an accepted connection, and the ids
 * survive fork() since they index this global table. (M1254) */
/* The connection index behind an endpoint — the per-connection key SCM_RIGHTS
 * fd-passing uses so a sendfd on one end is received on the other. -1 if the
 * endpoint is invalid. (M1265) */
int unix_ep_conn(int ep) {
    int s; struct uconn *c = ep_conn(ep, &s);
    return c ? (ep >> 1) : -1;
}

int unix_socketpair(int *a, int *b) {
    if (!a || !b) return -1;
    uint64_t fl = usock_irq_save();
    int ci = -1; for (int i = 0; i < U_CONN; i++) if (!conns[i].used) { ci = i; break; }
    if (ci < 0) { usock_irq_restore(fl); return -1; }   /* connection table full */
    struct uconn *c = &conns[ci];
    c->used = 1; c->a2b.head = c->a2b.tail = 0; c->b2a.head = c->b2a.tail = 0;
    c->a_closed = c->b_closed = 0; c->a_wr_closed = c->b_wr_closed = 0; c->a_waiter = c->b_waiter = 0;
    *a = (ci << 1) | 0;                             /* side A */
    *b = (ci << 1) | 1;                             /* side B */
    usock_irq_restore(fl);
    return 0;
}

static int sapp(char *b, int p, int max, const char *s) { while (*s && p < max - 1) b[p++] = *s++; return p; }
static int sdec(char *b, int p, int max, int v) {
    char t[12]; int n = 0; if (!v) t[n++] = '0';
    while (v > 0) { t[n++] = (char)('0' + v % 10); v /= 10; }
    while (n && p < max - 1) b[p++] = t[--n];
    return p;
}
int unix_format(char *b, int max) {
    int p = sapp(b, 0, max, "LISTENERS\n"), any = 0;
    for (int i = 0; i < U_LISTEN; i++) if (lis[i].used) {
        p = sapp(b, p, max, "  "); p = sapp(b, p, max, lis[i].path);
        p = sapp(b, p, max, "  backlog="); p = sdec(b, p, max, lis[i].np); p = sapp(b, p, max, "\n"); any = 1;
    }
    if (!any) p = sapp(b, p, max, "  (none)\n");
    p = sapp(b, p, max, "CONNECTIONS\n"); any = 0;
    for (int i = 0; i < U_CONN; i++) if (conns[i].used) {
        p = sapp(b, p, max, "  conn"); p = sdec(b, p, max, i);
        p = sapp(b, p, max, ": a2b="); p = sdec(b, p, max, rcount(&conns[i].a2b));
        p = sapp(b, p, max, "B b2a="); p = sdec(b, p, max, rcount(&conns[i].b2a)); p = sapp(b, p, max, "B");
        if (conns[i].a_closed) p = sapp(b, p, max, " A-closed");
        if (conns[i].b_closed) p = sapp(b, p, max, " B-closed");
        p = sapp(b, p, max, "\n"); any = 1;
    }
    if (!any) p = sapp(b, p, max, "  (none)\n");
    if (p < max) b[p] = 0;
    return p;
}
