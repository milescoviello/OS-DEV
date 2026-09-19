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
#include "app.h"       /* app_current_pid, for SO_PEERCRED (M2088) */

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
/* 64 KiB, not 16 (M2202). Linux's default AF_UNIX send buffer is ~208 KiB and
 * ours was 16, which is not a tuning difference when the program on top is
 * Firefox: its IPC channel filled the ring to 16383 of 16383 bytes in every
 * boot this tree has produced, and the sender then spun on EAGAIN because poll
 * had told it the socket was writable (fixed alongside this -- see
 * unix_writable). A full ring is legitimate backpressure; a ring that fills on
 * an ordinary burst turns every message into a round trip through the peer's
 * scheduler. 128 connections x 2 directions x 64 KiB = 16 MiB of BSS, against
 * the 4 MiB it was.
 *
 * Still static, and still a fixed per-connection cost -- Linux allocates per
 * socket and autotunes. If this ever needs to be 208 KiB the rings have to come
 * off the BSS and out of kmalloc first. */
#define U_RING    65536           /* bytes buffered per direction */
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
    /* HOW MANY FILE DESCRIPTORS NAME EACH END (M2002).
     *
     * An endpoint used to be closed by the first close() that reached it, and
     * fork COPIES the whole fd table -- so a child that inherited a socket and
     * then closed it (which every child does after exec, and which posix_spawn
     * does explicitly) hung up the PARENT'S live connection. Firefox forks its
     * content processes, so its display connection died moments after it had
     * bound every global and taken its keymap, and the compositor saw a clean
     * EOF from a client that had not gone anywhere:
     *
     *     [wl] client disconnected (ep 3, recv -> 0, 0 byte(s) still queued)
     *
     * A descriptor is a reference. Only the last one closes the end. This is
     * the same refcount pipes, memfds, epoll instances, inotify instances and
     * TCP sockets already had in app_fd_fork -- AF_UNIX was the one type never
     * added to that list. */
    int a_refs, b_refs;
    /* WHO IS ON EACH END (M2088). SO_PEERCRED is the only way a program can
     * learn the pid on the far side of a Unix socket, and it is not a nicety:
     * GDBus uses it to authenticate, and Firefox's IPC channel reads it to
     * confirm it is talking to the process it launched. Recorded at the moment
     * the end is created, because that is the only moment it is known -- a
     * later lookup cannot tell which of several descriptors is asking. */
    int a_pid, b_pid;
    task_t *a_waiter, *b_waiter;  /* side A blocked reading b2a; side B blocked reading a2b */
    /* A WRITER HAS TO BE ABLE TO WAIT TOO (M2090).
     *
     * unix_send did `rput()` and returned whatever fitted -- including ZERO
     * when the ring was full -- and nothing ever waited. A write that returns
     * 0 is the worst of the three possible answers: a blocking socket must
     * wait for space, a non-blocking one must say EAGAIN, and 0 makes every
     * caller loop for ever making no progress while believing it is working.
     * That is the same shape as the EAGAIN spin M2087's detector found.
     *
     * Woken by unix_recv, which is the only thing that creates space. */
    task_t *a_wwaiter, *b_wwaiter;
    /* WHICH THREADS READ THIS CONNECTION (M2292).
     *
     * libwayland lets any number of threads share one wl_display: one of them
     * wins wl_display_read_events(), drains the socket, and DISTRIBUTES the
     * messages into each proxy's event queue, after which every other thread
     * dispatches its own queue. If that distribution does not reach the queue
     * GDK's seat proxies live on, the bytes are gone from the socket -- so
     * the compositor sees them consumed -- and no handler ever runs. That
     * failure is invisible from outside and it is exactly what Firefox looks
     * like here: every byte taken, nothing done.
     *
     * A single-threaded client reads with one tid. Recording the distinct
     * readers per connection is the cheapest way to tell those two worlds
     * apart, and it costs one comparison on a path that already holds the
     * lock. */
    int rd_tid[2][4], rd_ntid[2], rd_lasttid[2];
    unsigned long rd_calls[2];
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

/* FORGET A DYING TASK (M2053).
 *
 * This table parks a task_t* so it can be woken later. Nothing told it when
 * that task was freed, so a stale pointer survived here and a later wake
 * called task_wake() on reclaimed memory -- which sets a state field and puts
 * it back on the run queue. A freed task_t then gets SCHEDULED, and its
 * trampoline runs with whatever the allocator has since put in those bytes.
 * That is exactly the symptom the kernel reported during a Claude Code run:
 *
 *   [task] thread 66 reached its trampoline with no start frame
 *          -- it was made runnable before its context was complete
 *
 * Only the futex table had a forget hook (app_futex_forget). Every other
 * subsystem that stores a waiter needed the same one. */
void unix_forget_task(void *t) {
    for (int i = 0; i < U_LISTEN; i++) if ((void *)lis[i].waiter == t) lis[i].waiter = 0;
    /* AND THE PER-CONNECTION SLOTS, which this never cleared (M2090).
     * M2053 added this function for exactly the hazard it left half-open: a
     * freed task_t parked in a waiter slot gets task_wake()'d later, which
     * sets a state field on reclaimed memory and puts it back on the run
     * queue -- and then a freed task is SCHEDULED. The listener slots were
     * cleared; the reader and (new) writer slots on every connection were
     * not, and those are the ones a busy socket actually uses. */
    for (int i = 0; i < U_CONN; i++) {
        if (!conns[i].used) continue;
        if ((void *)conns[i].a_waiter  == t) conns[i].a_waiter  = 0;
        if ((void *)conns[i].b_waiter  == t) conns[i].b_waiter  = 0;
        if ((void *)conns[i].a_wwaiter == t) conns[i].a_wwaiter = 0;
        if ((void *)conns[i].b_wwaiter == t) conns[i].b_wwaiter = 0;
    }
}


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
    c->a_wwaiter = c->b_wwaiter = 0;            /* a reused slot must not inherit a stale writer (M2090) */
    c->a_refs = c->b_refs = 1;                     /* one descriptor per end to begin with (M2002) */
    c->a_pid = app_current_pid();                  /* the connector (M2088) */
    c->b_pid = 0;                                  /* ...the server's pid is set by accept */
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
    conns[ci].b_pid = app_current_pid();           /* the server, for SO_PEERCRED (M2088) */
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

/* THE DIRECTION THAT IS FAILING (M2131).
 *
 * unix_nread reports this endpoint's RX ring -- what WE can read. A send that
 * returns EAGAIN is about the TX ring, which is the PEER's RX ring, and nothing
 * could report it. So the spin detector printed
 *
 *   EAGAIN from sendmsg(fd 59) 1000 times in a row -- ... queued=0 readable=0
 *
 * about a socket whose send ring was completely full: two different rings, one
 * of them empty, and the empty one is the one that got printed. "The peer is
 * not draining" and "we wrongly believe we are full" are the two explanations
 * for that message and it could not tell them apart. */
long unix_txqueued(int ep) {
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s);
    if (!c) { usock_irq_restore(fl); return -1; }
    struct uring *tx = s ? &c->b2a : &c->a2b;
    long n = rcount(tx);
    usock_irq_restore(fl);
    return n;
}
int unix_txroom(int ep) {
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s);
    if (!c) { usock_irq_restore(fl); return -1; }
    struct uring *tx = s ? &c->b2a : &c->a2b;
    int n = rfree(tx);
    usock_irq_restore(fl);
    return n;
}
/* Has the peer registered a BLOCKING reader on the ring we write into?
 *
 * READ THE LIMIT OF THIS BEFORE USING IT: only unix_recv's blocking path sets
 * that waiter. A peer sitting in poll()/epoll() does NOT register one, because
 * this kernel's poll is a re-checking nap loop rather than a wait queue. So 0
 * means "nobody is parked in a blocking read", NOT "the peer is not reading" --
 * a poll-driven peer, which is what every event loop is, always reports 0 here.
 * Written down because a field that looks like it answers "is the peer stuck"
 * and does not is the failure mode this campaign keeps paying for. */
int unix_peer_reader_waiting(int ep) {
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s);
    if (!c) { usock_irq_restore(fl); return -1; }
    int w = (s ? c->a_waiter : c->b_waiter) ? 1 : 0;
    usock_irq_restore(fl);
    return w;
}

long unix_send(int ep, const void *buf, unsigned long len) { return unix_send_ex(ep, buf, len, 0); }

/* `nb` = the caller's O_NONBLOCK. Returns bytes written (a SHORT count is
 * legal and real), UNIX_EAGAIN when nothing at all fitted on a non-blocking
 * socket, or -1 for a dead peer. Never 0 for a non-empty write. (M2090) */
long unix_send_ex(int ep, const void *buf, unsigned long len, int nb) {
    if (!len) return 0;
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s); if (!c) { usock_irq_restore(fl); return -1; }
    for (;;) {
        int peer_closed = s ? c->a_closed : c->b_closed;
        int self_wr = s ? c->b_wr_closed : c->a_wr_closed;
        if (peer_closed || self_wr) { usock_irq_restore(fl); return -1; }   /* peer gone, or we shut our write side */
        struct uring *tx = s ? &c->b2a : &c->a2b;                /* B writes b2a, A writes a2b */
        int n = rput(tx, (const unsigned char *)buf, (int)len);
        if (n > 0) {
            task_t **pw = s ? &c->a_waiter : &c->b_waiter;       /* wake the peer's blocked reader */
            if (*pw) { task_wake(*pw); *pw = 0; }
            usock_irq_restore(fl);
            return n;
        }
        /* The ring is full and not one byte moved. */
        if (nb) { usock_irq_restore(fl); return UNIX_EAGAIN; }
        /* Block once, registered so the draining reader can wake us. Same
         * check-set-block sequence under the same lock as unix_recv, which is
         * what makes it lost-wakeup-free across cores (M1609). */
        task_t **ww = s ? &c->b_wwaiter : &c->a_wwaiter;
        *ww = task_self();
        usock_irq_restore(fl);
        task_block();
        fl = usock_irq_save();
        c = ep_conn(ep, &s);
        if (!c) { usock_irq_restore(fl); return -1; }            /* the connection went away while we slept */
        ww = s ? &c->b_wwaiter : &c->a_wwaiter;
        *ww = 0;
    }
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
    {   int tid = task_current_id();
        c->rd_lasttid[s] = tid; c->rd_calls[s]++;
        int seen = 0;
        for (int i = 0; i < c->rd_ntid[s]; i++) if (c->rd_tid[s][i] == tid) { seen = 1; break; }
        if (!seen && c->rd_ntid[s] < 4) c->rd_tid[s][c->rd_ntid[s]++] = tid;
    }
    int got = rget(rx, (unsigned char *)buf, (int)max);
    /* DRAINING IS WHAT CREATES SPACE, so this is where a blocked writer gets
     * woken (M2090). Without it unix_send_ex's wait never ends and a full ring
     * is a permanent hang rather than momentary backpressure. The writer on
     * OUR rx ring is the peer: side B reads a2b, which side A writes. */
    if (got > 0) {
        task_t **pw = s ? &c->a_wwaiter : &c->b_wwaiter;
        if (*pw) { task_wake(*pw); *pw = 0; }
    }
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
    /* ...AND ANY WRITER WAITING FOR SPACE (M2090). It is waiting for a reader
     * that is never coming back; leaving it parked is a hang, and its retry
     * will now see the closed flag and return -1 (EPIPE) as it must. Both
     * sides, because either could be blocked on this connection. */
    if (c->a_wwaiter) { task_wake(c->a_wwaiter); c->a_wwaiter = 0; }
    if (c->b_wwaiter) { task_wake(c->b_wwaiter); c->b_wwaiter = 0; }
    usock_irq_restore(fl);
    return 0;
}

int g_unix_verbose;     /* -append unixverbose: trace closes and EOF decisions */
/* Another descriptor now names this endpoint (fork, dup, SCM_RIGHTS). */
int unix_ref(int ep) {
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s); if (!c) { usock_irq_restore(fl); return -1; }
    if (s) c->b_refs++; else c->a_refs++;
    usock_irq_restore(fl);
    return 0;
}

int unix_close(int ep) {
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s); if (!c) { usock_irq_restore(fl); return -1; }
    if (g_unix_verbose) kprintf("[usock] close(ep %d side %d) refs=%d\n", ep, s, s ? c->b_refs : c->a_refs);
    /* Drop ONE reference; the end stays open while any descriptor names it. */
    int *rp = s ? &c->b_refs : &c->a_refs;
    if (*rp > 1) { (*rp)--; usock_irq_restore(fl); return 0; }
    *rp = 0;
    if (s) c->b_closed = 1; else c->a_closed = 1;
    task_t **pw = s ? &c->a_waiter : &c->b_waiter;               /* wake the peer so its recv returns EOF */
    if (*pw) { task_wake(*pw); *pw = 0; }
    /* ...and any writer blocked for space, which will now see the close and
     * return EPIPE instead of waiting for a reader that has gone (M2090). */
    if (c->a_wwaiter) { task_wake(c->a_wwaiter); c->a_wwaiter = 0; }
    if (c->b_wwaiter) { task_wake(c->b_wwaiter); c->b_wwaiter = 0; }
    int freed_ci = -1;
    if (c->a_closed && c->b_closed) { c->used = 0; freed_ci = ep >> 1; }   /* both ends gone -> free the slot */
    usock_irq_restore(fl);
    /* ANY DESCRIPTOR STILL IN FLIGHT ON THIS CONNECTION IS NOW UNRECEIVABLE
     * (M2104), and it holds a reference nobody will ever hand on. Released
     * OUTSIDE this lock, because those teardowns take their own. */
    if (freed_ci >= 0) app_scm_drop_conn(freed_ci);
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
/* WOULD A SEND BLOCK? (M2202)
 *
 * The other half of the pair, and it was missing -- app_fd_ready answered
 * POLLOUT unconditionally for every AF_UNIX endpoint, with the comment "the
 * ring drains quickly; a blocked send is brief". That is an assumption standing
 * where a measurement belongs, and the measurement disagrees: EVERY Firefox
 * boot in this tree logs
 *
 *   SPINNING: pid 165 tid 87 has had EAGAIN from sendmsg(fd 58) 1000 times in a
 *   row -- ... TX_queued=16383 tx_room=0 peer_reader_waiting=0 nonblock=1
 *
 * which is a thread that poll TOLD it could write, writing, being refused, and
 * going straight back to poll. A thousand times in a row, on a uniprocessor,
 * against a ring only the peer can drain -- so the spinner is starving the one
 * thread that could make it progress.
 *
 * "Would not block" is the whole meaning of POLLOUT, and a dead peer satisfies
 * it: the send fails at once with EPIPE, which is not blocking. So room, or no
 * connection at all, or a peer that has gone away. */
int unix_writable(int ep) {
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s);
    int w;
    if (!c) w = 1;                    /* no connection: the send errors, it does not block */
    else {
        struct uring *tx = s ? &c->b2a : &c->a2b;
        int peer_closed = (s ? c->a_closed : c->b_closed) || (s ? c->b_wr_closed : c->a_wr_closed);
        w = rfree(tx) > 0 || peer_closed;
    }
    usock_irq_restore(fl);
    return w;
}
/* THE PID ON THE OTHER END, for SO_PEERCRED (M2088). 0 when nothing has
 * accepted yet -- a pending connection has no server. */
int unix_peer_pid(int ep) {
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s);
    int pid = c ? (s ? c->a_pid : c->b_pid) : -1;
    usock_irq_restore(fl);
    return pid;
}
/* THE REAL SIZE OF ONE DIRECTION'S RING, for SO_SNDBUF/SO_RCVBUF (M2088).
 * One slot is always kept empty to tell full from empty, so the usable
 * capacity is one less than the array -- and reporting the array size would be
 * a number no write can ever reach. */
int unix_ring_bytes(void) { return U_RING - 1; }

/* HOW MANY BYTES ARE WAITING, not merely "are there any" (M2086).
 *
 * ep_readable answers a yes/no question, and FIONREAD asks a numeric one --
 * so there was nothing here that could answer it, and the ioctl handler
 * answered ENOTTY instead. A socket is not a terminal, but "not a terminal"
 * is not the same statement as "that question is meaningless": the caller
 * asked how much it may read, 142 bytes were sitting in the ring, and it was
 * told the descriptor does not support the concept.
 *
 * Note this deliberately does NOT count a pending EOF as a byte. ep_readable
 * must (a poller has to learn of the hangup), but a count is a count: a
 * caller that sizes a buffer from it and then reads that many bytes would
 * block for ever on the phantom one. */
long unix_nread(int ep) {
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s);
    long n = -1;
    if (c) { struct uring *rx = s ? &c->a2b : &c->b2a; n = rcount(rx); }
    usock_irq_restore(fl);
    return n;
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
/* Per-connection reader census, for the side that is NOT ours: given the
 * compositor's endpoint, report who on the client side has been reading. */
void unix_peer_readers(int ep, int *ntid, int *lasttid, unsigned long *calls) {
    uint64_t fl = usock_irq_save();
    int s; struct uconn *c = ep_conn(ep, &s);
    if (!c) { usock_irq_restore(fl); if (ntid) *ntid = -1; return; }
    int o = s ? 0 : 1;                       /* the OTHER side: the client's */
    if (ntid)    *ntid    = c->rd_ntid[o];
    if (lasttid) *lasttid = c->rd_lasttid[o];
    if (calls)   *calls   = c->rd_calls[o];
    usock_irq_restore(fl);
}

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
    c->a_wwaiter = c->b_wwaiter = 0;            /* a reused slot must not inherit a stale writer (M2090) */
    c->a_refs = c->b_refs = 1;                     /* one descriptor per end to begin with (M2002) */
    c->a_pid = c->b_pid = app_current_pid();       /* both ends are this process's (M2088) */
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
