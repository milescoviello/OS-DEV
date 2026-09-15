/*
 * mqueue.c — POSIX-style priority message queues (M1154).
 *
 * Named, bounded queues where every message carries a PRIORITY: a receive
 * returns the HIGHEST-priority message (FIFO within a priority), unlike the
 * plain FIFO /ipc mailboxes (mbox.c). Senders block when the queue is full,
 * receivers block when it is empty — the same IRQ-safe task_block/task_wake
 * rendezvous mbox.c uses (task_block itself brackets interrupts). Queues are
 * shared by NAME, so two processes that mq_open the same name share one queue
 * (e.g. a fork parent/child) — no per-process fd table needed. Bounded; never
 * allocates.
 */
#include "mqueue.h"
#include "task.h"
#include <stdint.h>

/* M1618: same fix as sysvipc.c/sem.c/shm.c this same pass -- this file
 * claimed the same "IRQ-safe task_block/task_wake rendezvous mbox.c uses"
 * but, unlike mbox.c (fixed as M1608), never got the cross-core lock that
 * claim actually needs since M1531. One lock for the whole file. */
static volatile int mq_lock;
static inline uint64_t mq_irq_save(void) {
    uint64_t f;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory");
    while (__atomic_exchange_n(&mq_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return f;
}
static inline void mq_irq_restore(uint64_t f) {
    __atomic_store_n(&mq_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(f) : "memory", "cc");
}

#define MQ_N       16     /* max simultaneous named queues */
#define MQ_MAXMSG  16     /* max messages held per queue    */
#define MQ_MSGSZ   128    /* max message payload (bytes)     */

struct mqmsg { uint8_t used; uint32_t prio; uint32_t seq; int len; char data[MQ_MSGSZ]; };  /* prio widened from uint8_t (M1623): mqueue_send's own param is a full unsigned int, and nothing documents an 8-bit cap */
struct mqueue {
    char   name[32];
    int    used, maxmsg, msgsize, count;
    int    nonblock;                    /* O_NONBLOCK (M1571): mq_send/receive return -1 immediately
                                          * instead of blocking when full/empty, respectively */
    uint32_t seq;                       /* ever-increasing, for FIFO-within-priority ties */
    struct mqmsg msg[MQ_MAXMSG];
    task_t *send_waiter, *recv_waiter;  /* one blocked sender / receiver (mbox-style) */
};
static struct mqueue mq[MQ_N];

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
void mqueue_forget_task(void *t) {
    for (int i = 0; i < MQ_N; i++) {
        if ((void *)mq[i].send_waiter == t) mq[i].send_waiter = 0;
        if ((void *)mq[i].recv_waiter == t) mq[i].recv_waiter = 0;
    }
}


static int meq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }

/* Open (find-or-create) the named queue; returns its index, or -1 if the table
 * is full / the name is empty. maxmsg/msgsize are clamped to the static caps. */
int mqueue_open(const char *name, int maxmsg, int msgsize) {
    if (!name || !name[0]) return -1;
    uint64_t f = mq_irq_save();
    for (int i = 0; i < MQ_N; i++) if (mq[i].used && meq(mq[i].name, name)) { mq_irq_restore(f); return i; }
    for (int i = 0; i < MQ_N; i++) if (!mq[i].used) {
        int j = 0; while (name[j] && j < 31) { mq[i].name[j] = name[j]; j++; } mq[i].name[j] = 0;
        mq[i].used = 1; mq[i].count = 0; mq[i].seq = 0; mq[i].nonblock = 0;
        mq[i].maxmsg  = (maxmsg  > 0 && maxmsg  <= MQ_MAXMSG) ? maxmsg  : MQ_MAXMSG;
        mq[i].msgsize = (msgsize > 0 && msgsize <= MQ_MSGSZ)  ? msgsize : MQ_MSGSZ;
        mq[i].send_waiter = mq[i].recv_waiter = 0;
        for (int k = 0; k < MQ_MAXMSG; k++) mq[i].msg[k].used = 0;
        mq_irq_restore(f);
        return i;
    }
    mq_irq_restore(f);
    return -1;
}

/* Enqueue a message with priority `prio`; blocks while the queue is full. The
 * payload is truncated to msgsize. Returns the bytes stored, or -1. */
long mqueue_send(int idx, const void *buf, unsigned long len, unsigned int prio) {
    if (idx < 0 || idx >= MQ_N || !mq[idx].used) return -1;
    struct mqueue *q = &mq[idx];
    if ((int)len > q->msgsize) len = (unsigned long)q->msgsize;
    for (;;) {
        uint64_t f = mq_irq_save();
        if (q->count < q->maxmsg) {
            int placed = 0;
            for (int i = 0; i < MQ_MAXMSG; i++) if (!q->msg[i].used) {
                q->msg[i].used = 1; q->msg[i].prio = prio; q->msg[i].seq = q->seq++;
                q->msg[i].len = (int)len;
                for (unsigned long k = 0; k < len; k++) q->msg[i].data[k] = ((const char *)buf)[k];
                q->count++;
                if (q->recv_waiter) { task_wake(q->recv_waiter); q->recv_waiter = 0; }
                placed = 1;
                break;
            }
            mq_irq_restore(f);
            return placed ? (long)len : -1;   /* !placed shouldn't happen (count said there was room) */
        }
        /* full -> block for room (or fail fast, O_NONBLOCK) */
        if (q->nonblock) { mq_irq_restore(f); return -1; }
        q->send_waiter = task_self();
        mq_irq_restore(f);              /* released BEFORE blocking (M1618) */
        task_block();
        q->send_waiter = 0;
        if (!q->used) return -1;
    }
}

/* Dequeue the HIGHEST-priority message (oldest seq among equal priorities);
 * blocks while the queue is empty. Writes the message priority to *prio_out (if
 * non-NULL) and the payload (truncated to `max`) to buf. Returns the byte
 * length, or -1. */
long mqueue_receive(int idx, void *buf, unsigned long max, unsigned int *prio_out) {
    if (idx < 0 || idx >= MQ_N || !mq[idx].used) return -1;
    struct mqueue *q = &mq[idx];
    for (;;) {
        uint64_t f = mq_irq_save();
        if (q->count == 0) {                          /* empty -> block for a message (or fail fast, O_NONBLOCK) */
            if (q->nonblock) { mq_irq_restore(f); return -1; }
            q->recv_waiter = task_self();
            mq_irq_restore(f);          /* released BEFORE blocking (M1618) */
            task_block();
            q->recv_waiter = 0;
            if (!q->used || q->count == 0) return -1;    /* woken but still empty (e.g. killed) */
            continue;
        }
        int best = -1;
        for (int i = 0; i < MQ_MAXMSG; i++) if (q->msg[i].used) {
            if (best < 0 || q->msg[i].prio > q->msg[best].prio ||
                (q->msg[i].prio == q->msg[best].prio && q->msg[i].seq < q->msg[best].seq))
                best = i;
        }
        if (best < 0) { mq_irq_restore(f); return -1; }
        int n = q->msg[best].len; if ((unsigned long)n > max) n = (int)max;
        for (int k = 0; k < n; k++) ((char *)buf)[k] = q->msg[best].data[k];
        if (prio_out) *prio_out = q->msg[best].prio;
        q->msg[best].used = 0; q->count--;
        if (q->send_waiter) { task_wake(q->send_waiter); q->send_waiter = 0; }
        mq_irq_restore(f);
        return (long)n;
    }
}

/* mq_getattr/mq_setattr (M1571): maxmsg/msgsize/count were already tracked
 * (mqueue_format's own /proc/mqueue line already reports two of them) --
 * this just exposes all four POSIX mq_attr fields together. Only mq_flags
 * (O_NONBLOCK) is settable: real mq_setattr leaves mq_maxmsg/mq_msgsize
 * fixed at creation time and ignores those fields in *newattr entirely. */
int mqueue_getattr(int idx, long *flags, long *maxmsg, long *msgsize, long *curmsgs) {
    if (idx < 0 || idx >= MQ_N) return -1;
    struct mqueue *q = &mq[idx];
    uint64_t f = mq_irq_save();
    int ok = q->used;
    if (ok) {
        if (flags)   *flags   = q->nonblock ? 1 : 0;
        if (maxmsg)  *maxmsg  = q->maxmsg;
        if (msgsize) *msgsize = q->msgsize;
        if (curmsgs) *curmsgs = q->count;
    }
    mq_irq_restore(f);
    return ok ? 0 : -1;
}
int mqueue_setattr(int idx, long new_flags, long *old_flags_out) {
    if (idx < 0 || idx >= MQ_N) return -1;
    struct mqueue *q = &mq[idx];
    uint64_t f = mq_irq_save();
    int ok = q->used;
    if (ok) {
        if (old_flags_out) *old_flags_out = q->nonblock ? 1 : 0;
        q->nonblock = new_flags ? 1 : 0;
    }
    mq_irq_restore(f);
    return ok ? 0 : -1;
}

/* mq_unlink (M1593): mqueue_open's create path has set `used = 1` since
 * M1154 with no removal path anywhere in this file -- 16 distinct mq_open
 * names in one boot permanently exhausted the table forever. No refcount/
 * open-descriptor-count exists here (unlike sem.c's named semaphores), so
 * this is an immediate, unconditional free, not a mirrors-sem_named_unlink
 * defer-until-last-close; any sender/receiver already blocked on this exact
 * queue is woken rather than left parked on removed state forever, and
 * their own task_block loops already check `q->used` on wake and bail with
 * -1 (the same "woken but still gone" path they already use for a kill). */
int mqueue_unlink(const char *name) {
    if (!name || !name[0]) return -1;
    uint64_t f = mq_irq_save();
    for (int i = 0; i < MQ_N; i++) if (mq[i].used && meq(mq[i].name, name)) {
        mq[i].used = 0;
        if (mq[i].send_waiter) { task_wake(mq[i].send_waiter); mq[i].send_waiter = 0; }
        if (mq[i].recv_waiter) { task_wake(mq[i].recv_waiter); mq[i].recv_waiter = 0; }
        mq_irq_restore(f);
        return 0;
    }
    mq_irq_restore(f);
    return -1;
}

/* Backs /proc/mqueue: one line per open queue — "name  cur/max  msgsize". */
int mqueue_format(char *out, int max) {
    int p = 0;
    for (int i = 0; i < MQ_N; i++) if (mq[i].used && p < max - 80) {
        for (const char *s = mq[i].name; *s && p < max - 40; s++) out[p++] = *s;
        out[p++] = ' '; out[p++] = ' ';
        char t[12]; int n = 0, v = mq[i].count; if (!v) t[n++] = '0'; while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
        while (n) out[p++] = t[--n];
        out[p++] = '/';
        n = 0; v = mq[i].maxmsg; if (!v) t[n++] = '0'; while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
        while (n) out[p++] = t[--n];
        out[p++] = '\n';
    }
    out[p] = 0; return p;
}
