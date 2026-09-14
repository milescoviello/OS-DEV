/*
 * pipe.c — anonymous pipe objects (M1187). See pipe.h.
 *
 * Each pipe is one ring buffer (writer -> reader) plus r_open/w_open reference
 * counts (how many fds, across all processes, hold the read / write end). A read
 * blocks while the ring is empty and a writer still exists, and returns 0 (EOF)
 * once all writers have closed and the ring is drained. A write blocks while the
 * ring is full and a reader still exists, and returns -1 (EPIPE) once all readers
 * have closed. The slot is freed when both ends reach zero.
 *
 * M1610: this used to claim lost-wakeup-freedom from the single-CPU int-0x80
 * gate alone -- the same assumption M1531 invalidated in mbox.c/unixsock.c/
 * pty.c (and, one level down, in pmm.c/vmm.c/kheap.c). A writer and a
 * blocking reader can now run on two different cores at once: reader checks
 * the ring (empty), writer fills it + checks the waiter field (still unset,
 * so no wake), THEN reader records itself and blocks forever. pipe_new's
 * table scan-and-claim has the same-shaped hazard one level up. One lock
 * now covers every check-set-block / produce-check-wake sequence in this
 * file (including splice/tee, which touch two pipes' state at once), same
 * idiom as the other three files above.
 */
#include "pipe.h"
#include "task.h"

static volatile int pipe_lock;
static inline uint64_t pipe_irq_save(void) {
    uint64_t fl;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
    while (__atomic_exchange_n(&pipe_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return fl;
}
static inline void pipe_irq_restore(uint64_t fl) {
    __atomic_store_n(&pipe_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(fl) : "memory", "cc");
}

#define NPIPE 32
#define PBUF  4096

struct kpipe {
    int used;
    unsigned char b[PBUF];
    int head, tail;                  /* ring; empty when head==tail, one slot kept free */
    int r_open, w_open;              /* reference counts on the read / write ends */
    int pinned;                      /* a FIFO's backing pipe: persists at 0/0 (M1188) */
    int had_writer;                  /* a writer has connected at least once (FIFO EOF gating, M1188) */
    task_t *rw, *ww;                 /* a blocked reader / writer */
};
static struct kpipe pipes[NPIPE];

static int p_cnt(struct kpipe *p) { return (p->head - p->tail + PBUF) % PBUF; }
static int p_spc(struct kpipe *p) { return PBUF - 1 - p_cnt(p); }
static struct kpipe *pp(int idx) { return (idx < 0 || idx >= NPIPE || !pipes[idx].used) ? 0 : &pipes[idx]; }

/* Non-destructive readiness (poll/select, M1210). A read won't block iff there
 * is buffered data, OR EOF has been reached (no writers left, and -- for a FIFO
 * -- a writer has connected at least once: matches pipe_read's EOF gating). */
int pipe_readable(int idx) {
    struct kpipe *p = pp(idx); if (!p) return 0;
    return p_cnt(p) > 0 || (p->w_open == 0 && p->had_writer);
}
/* A write won't block iff the ring has room, or no reader remains (a write to a
 * reader-less pipe raises EPIPE and returns at once rather than blocking). */
/* How many descriptors hold each end, and how many bytes are queued (M2004).
 *
 * "A reader is polling a pipe and never sees EOF" has exactly one cause -- a
 * write end is still open somewhere -- and exactly one way to tell whether that
 * is the application's doing or ours: count the references. A parent that forks
 * a helper and forgets to close its own copy of the write end hangs on Linux
 * too; a kernel that loses a close does not. */
void pipe_state(int idx, int *r_open, int *w_open, int *queued, int *had_writer) {
    struct kpipe *p = pp(idx);
    if (r_open) *r_open = p ? p->r_open : -1;
    if (w_open) *w_open = p ? p->w_open : -1;
    if (queued) *queued = p ? p_cnt(p) : -1;
    if (had_writer) *had_writer = p ? p->had_writer : -1;
}

int pipe_writable(int idx) {
    struct kpipe *p = pp(idx); if (!p) return 0;
    return p->r_open == 0 || p_spc(p) > 0;
}

int pipe_new(void) {
    uint64_t fl = pipe_irq_save();
    for (int i = 0; i < NPIPE; i++) if (!pipes[i].used) {
        struct kpipe *p = &pipes[i];
        for (unsigned k = 0; k < sizeof *p; k++) ((unsigned char *)p)[k] = 0;
        p->used = 1; p->r_open = 1; p->w_open = 1; p->had_writer = 1;   /* anon: the creator holds both ends */
        pipe_irq_restore(fl);
        return i;
    }
    pipe_irq_restore(fl);
    return -1;
}

/* A FIFO's backing pipe (M1188): unopened (0/0 — opens are per-process) and
 * `pinned` so it survives at 0/0 (the named pipe outlives any single open). A
 * reader can't EOF until a writer has connected at least once (had_writer). */
int pipe_new_fifo(void) {
    int idx = pipe_new(); if (idx < 0) return -1;
    struct kpipe *p = &pipes[idx];
    /* pipe_new() just set the anon-pipe defaults (1/1/1) under pipe_lock; flip
     * them to the FIFO defaults under the SAME lock too -- every other mutator
     * of these fields (pipe_open_end/pipe_close_end) already does, and this was
     * the one unlocked window where another path scanning pipes[] could observe
     * a slot that's used=1 but transiently has anon-pipe r_open/w_open/had_writer
     * instead of the FIFO values it's about to get. */
    uint64_t fl = pipe_irq_save();
    p->r_open = 0; p->w_open = 0; p->pinned = 1; p->had_writer = 0;
    pipe_irq_restore(fl);
    return idx;
}

long pipe_read(int idx, void *buf, unsigned long max) {
    struct kpipe *p = pp(idx); if (!p) return -1;
    for (;;) {
        uint64_t fl = pipe_irq_save();
        if (p_cnt(p) > 0) {
            unsigned char *d = (unsigned char *)buf; long g = 0;
            while ((unsigned long)g < max && p_cnt(p) > 0) { d[g++] = p->b[p->tail]; p->tail = (p->tail + 1) % PBUF; }
            if (p->ww) { task_wake(p->ww); p->ww = 0; }          /* a blocked writer now has room */
            pipe_irq_restore(fl);
            return g;
        }
        if (p->w_open == 0 && p->had_writer) { pipe_irq_restore(fl); return 0; }   /* EOF: drained + no writers (FIFO: only after one connected) */
        p->rw = task_self();
        pipe_irq_restore(fl);
        task_block();                                            /* woken by a writer/close (or a kill) */
        p = pp(idx); if (!p) return -1;                          /* freed under us */
    }
}

long pipe_write(int idx, const void *buf, unsigned long len) {
    struct kpipe *p = pp(idx); if (!p) return -1;
    const unsigned char *d = (const unsigned char *)buf;
    unsigned long done = 0;
    while (done < len) {
        uint64_t fl = pipe_irq_save();
        if (p->r_open == 0) { pipe_irq_restore(fl); return done ? (long)done : -1; }   /* EPIPE: no readers left */
        if (p_spc(p) > 0) {
            while (done < len && p_spc(p) > 0) { p->b[p->head] = d[done++]; p->head = (p->head + 1) % PBUF; }
            if (p->rw) { task_wake(p->rw); p->rw = 0; }          /* a blocked reader now has data */
            pipe_irq_restore(fl);
            continue;
        }
        p->ww = task_self();
        pipe_irq_restore(fl);
        task_block();                                            /* ring full: wait for a reader to drain */
        p = pp(idx); if (!p) return done ? (long)done : -1;
    }
    return (long)done;
}

/* Move up to `max` bytes from pipe `in` to pipe `out`, ring-to-ring, with no
 * userspace bounce (splice, M1211). Non-blocking: transfers only what's buffered
 * in `in` and fits in `out` right now. Consumes from `in`. Returns bytes moved
 * (0 = in empty / out full / EOF); -1 on a bad/identical index. */
long pipe_splice(int in, int out, unsigned long max) {
    struct kpipe *pi = pp(in), *po = pp(out); if (!pi || !po || in == out) return -1;
    uint64_t fl = pipe_irq_save();
    long n = 0;
    while ((unsigned long)n < max && p_cnt(pi) > 0 && p_spc(po) > 0) {
        po->b[po->head] = pi->b[pi->tail];
        po->head = (po->head + 1) % PBUF;
        pi->tail = (pi->tail + 1) % PBUF;
        n++;
    }
    if (n) {
        if (po->rw) { task_wake(po->rw); po->rw = 0; }           /* dest now has data */
        if (pi->ww) { task_wake(pi->ww); pi->ww = 0; }           /* source now has room */
    }
    pipe_irq_restore(fl);
    return n;
}
/* Copy up to `max` bytes from pipe `in` to pipe `out` WITHOUT consuming `in`
 * (tee, M1211): the source stays fully readable. Non-blocking. Returns bytes
 * copied (0 = nothing buffered / out full); -1 on a bad/identical index. */
long pipe_tee(int in, int out, unsigned long max) {
    struct kpipe *pi = pp(in), *po = pp(out); if (!pi || !po || in == out) return -1;
    uint64_t fl = pipe_irq_save();
    long n = 0; int t = pi->tail;
    while ((unsigned long)n < max && t != pi->head && p_spc(po) > 0) {
        po->b[po->head] = pi->b[t];
        po->head = (po->head + 1) % PBUF;
        t = (t + 1) % PBUF;
        n++;
    }
    if (n && po->rw) { task_wake(po->rw); po->rw = 0; }          /* dest now has data */
    pipe_irq_restore(fl);
    return n;
}

void pipe_open_end(int idx, int write_end) {
    struct kpipe *p = pp(idx); if (!p) return;
    uint64_t fl = pipe_irq_save();
    if (write_end) { p->w_open++; p->had_writer = 1; } else p->r_open++;
    pipe_irq_restore(fl);
}

void pipe_close_end(int idx, int write_end) {
    struct kpipe *p = pp(idx); if (!p) return;
    uint64_t fl = pipe_irq_save();
    if (write_end) { if (p->w_open > 0) p->w_open--; if (p->w_open == 0 && p->rw) { task_wake(p->rw); p->rw = 0; } }  /* readers see EOF */
    else           { if (p->r_open > 0) p->r_open--; if (p->r_open == 0 && p->ww) { task_wake(p->ww); p->ww = 0; } }  /* writers get EPIPE */
    if (p->r_open == 0 && p->w_open == 0 && !p->pinned) p->used = 0;   /* both ends gone -> free (a FIFO's pinned pipe persists) */
    pipe_irq_restore(fl);
}
