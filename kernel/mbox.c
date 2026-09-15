/*
 * mbox.c — named message-queue IPC (M1087). See mbox.h.
 *
 * A fixed table of named queues, each a small ring of bounded messages, created
 * on first use. The VFS routes /ipc/<name> here (kernel/vfs.c): write enqueues,
 * read dequeues FIFO and blocks the caller (task_block) when empty until a
 * writer task_wake()s it.
 *
 * M1608: the old comment claimed the interrupt gate's IF=0 alone made "queue
 * empty? then block" atomic against a writer -- true only on a single CPU.
 * Since M1531 a writer and a blocking reader can run on two different cores
 * at once: reader checks the ring (empty), writer enqueues + checks q->waiter
 * (still unset, so no wake), THEN reader sets the waiter and blocks forever.
 * mbox_get()'s table scan-and-create had the same-shaped hazard one level up
 * (two cores racing to create the SAME new name could both find an empty
 * slot). One lock now covers the lookup/create AND the check-set-block /
 * enqueue-check-wake sequences in both mbox_write and mbox_read, so the two
 * can't interleave into a lost wakeup. Same idiom as pmm.c/swap.c/tls.c/pty.c.
 * A read woken with the queue still empty (a stray keypress wake, or a kill)
 * returns 0 rather than re-blocking, so a `cat /ipc/<empty>` is never stuck.
 */
#include "mbox.h"
#include "task.h"

static volatile int mbox_lock;
static inline uint64_t mbox_irq_save(void) {
    uint64_t fl;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
    while (__atomic_exchange_n(&mbox_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return fl;
}
static inline void mbox_irq_restore(uint64_t fl) {
    __atomic_store_n(&mbox_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(fl) : "memory", "cc");
}

#define MBOX_N      8           /* up to 8 named queues */
#define MBOX_MSGS   16          /* ring depth per queue */
#define MBOX_MSGSZ  128         /* max message size */

struct mbox {
    char    name[32];
    int     used;
    int     head, tail;         /* ring: empty when head==tail, full when (head+1)%N==tail */
    struct { char data[MBOX_MSGSZ]; int len; } msg[MBOX_MSGS];
    task_t *waiter;             /* a reader blocked on this queue (one consumer) */
};
static struct mbox mb[MBOX_N];

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
void mbox_forget_task(void *t) {
    for (int i = 0; i < MBOX_N; i++) if ((void *)mb[i].waiter == t) mb[i].waiter = 0;
}


static int meq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }

/* Non-blocking readiness peek for fswait (M1125): is a message queued? (ring not
 * empty.) Does NOT create the queue. */
int mbox_ready(const char *name) {
    for (int i = 0; i < MBOX_N; i++) if (mb[i].used && meq(mb[i].name, name)) return mb[i].head != mb[i].tail;
    return 0;
}

/* Find queue `name`, creating it on first use; NULL if the table is full. */
static struct mbox *mbox_get(const char *name) {
    if (!name || !name[0]) return 0;
    for (int i = 0; i < MBOX_N; i++) if (mb[i].used && meq(mb[i].name, name)) return &mb[i];
    for (int i = 0; i < MBOX_N; i++) if (!mb[i].used) {
        int j = 0; while (name[j] && j < 31) { mb[i].name[j] = name[j]; j++; } mb[i].name[j] = 0;
        mb[i].used = 1; mb[i].head = mb[i].tail = 0; mb[i].waiter = 0;
        return &mb[i];
    }
    return 0;
}

long mbox_write(const char *name, const void *data, unsigned long len) {
    uint64_t fl = mbox_irq_save();
    struct mbox *q = mbox_get(name);
    if (!q) { mbox_irq_restore(fl); return -1; }
    int next = (q->head + 1) % MBOX_MSGS;
    if (next == q->tail) { mbox_irq_restore(fl); return -1; }   /* full */
    if (len > MBOX_MSGSZ) len = MBOX_MSGSZ;
    for (unsigned long i = 0; i < len; i++) q->msg[q->head].data[i] = ((const char *)data)[i];
    q->msg[q->head].len = (int)len;
    q->head = next;
    if (q->waiter) { task_wake(q->waiter); q->waiter = 0; }   /* wake a blocked consumer */
    mbox_irq_restore(fl);
    return (long)len;
}

long mbox_read(const char *name, void *buf, unsigned long max) {
    uint64_t fl = mbox_irq_save();
    struct mbox *q = mbox_get(name);
    if (!q) { mbox_irq_restore(fl); return -1; }
    if (q->tail == q->head) {                       /* empty -> block once for a producer */
        q->waiter = task_self();
        mbox_irq_restore(fl);
        task_block();                               /* woken by a writer, a keypress, or a kill */
        fl = mbox_irq_save();
        q->waiter = 0;
        if (q->tail == q->head) { mbox_irq_restore(fl); return 0; }   /* still empty -> don't re-block */
    }
    int n = q->msg[q->tail].len;
    if ((unsigned long)n > max) n = (int)max;
    for (int i = 0; i < n; i++) ((char *)buf)[i] = q->msg[q->tail].data[i];
    q->tail = (q->tail + 1) % MBOX_MSGS;
    mbox_irq_restore(fl);
    return n;
}

static int sapp(char *b, int p, int max, const char *s) { while (*s && p < max - 1) b[p++] = *s++; return p; }
static int sdec(char *b, int p, int max, int v) {
    char t[12]; int n = 0; if (!v) t[n++] = '0';
    while (v > 0) { t[n++] = (char)('0' + v % 10); v /= 10; }
    while (n && p < max - 1) b[p++] = t[--n]; return p;
}

int mbox_format(char *b, int max) {
    int p = sapp(b, 0, max, "  QUEUE                 PENDING\n");
    int any = 0;
    for (int i = 0; i < MBOX_N; i++) if (mb[i].used) {
        int depth = (mb[i].head - mb[i].tail + MBOX_MSGS) % MBOX_MSGS;
        p = sapp(b, p, max, "  "); p = sapp(b, p, max, mb[i].name);
        int pad = 20; const char *nm = mb[i].name; int nl = 0; while (nm[nl]) nl++;
        for (int k = nl; k < pad && p < max - 1; k++) b[p++] = ' ';
        p = sdec(b, p, max, depth); p = sapp(b, p, max, "\n");
        any = 1;
    }
    if (!any) p = sapp(b, p, max, "  (no mailboxes — write to /ipc/<name> to create one)\n");
    if (p < max) b[p] = 0;
    return p;
}
