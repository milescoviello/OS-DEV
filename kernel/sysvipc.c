/*
 * sysvipc.c — System V semaphores (M1159): keyed counting-semaphore SETS with
 * the classic atomic all-or-nothing semop. semget(key,nsems,flags) opens/creates
 * a set (IPC_PRIVATE always creates; else found by key or created with IPC_CREAT);
 * semop applies an ARRAY of {sem_num, sem_op, sem_flg} ops — but only if EVERY op
 * can proceed without a semaphore going negative (or, for op==0, without a
 * non-zero value); otherwise it blocks the whole call (no partial apply) until
 * woken, unless IPC_NOWAIT. semctl does SETVAL/GETVAL/IPC_RMID. Built on the same
 * IRQ-safe task_block/task_wake rendezvous mqueue.c/mbox.c use. Distinct from the
 * POSIX shm/mqueue/futex the OS already has — this is the keyed SysV API.
 */
#include "sysvipc.h"
#include "task.h"
#include "app.h"        /* app_shm_open (SysV shm reuses the M1108 named-shm backing) */
#include "shm.h"        /* shm_unlink/shm_max_bytes -- the real removal path + size cap (M1592) */
#include <stdint.h>

/* M1618: this file claimed "built on the same IRQ-safe task_block/task_wake
 * rendezvous mqueue.c/mbox.c use" -- true of the rendezvous shape, but not of
 * the IRQ-safety itself: unlike mbox.c (fixed as M1608) and app.c's futex
 * (M1612), this file had NO lock of any kind, not even a bare cli. Since
 * M1531 a writer and a blocking reader/waiter can run on two different
 * cores at once, and every table here (sem sets, message queues, shm
 * segments) also has the scan-then-create race one level up (two cores
 * racing semget/msgget/shmget on the same brand-new key could both find the
 * same free slot, or worse for shmget, corrupt the shared struct while
 * writing it). One lock for the whole file -- these sub-tables never touch
 * each other's state and IPC setup/wait is rare, so one coarse lock costs
 * nothing measurable. Same idiom as the eleven files already fixed this
 * session. */
static volatile int sysvipc_lock;
static inline uint64_t sv_irq_save(void) {
    uint64_t f;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory");
    while (__atomic_exchange_n(&sysvipc_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return f;
}
static inline void sv_irq_restore(uint64_t f) {
    __atomic_store_n(&sysvipc_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(f) : "memory", "cc");
}

#define SEM_N        16   /* max semaphore sets */
#define SEM_PER      16   /* max semaphores per set */
#define SEM_WAITERS  8    /* max tasks blocked on one set */

struct sem_set {
    int     used, key, nsems;
    int     val[SEM_PER];
    task_t *waiters[SEM_WAITERS];
    int     nwait;
};
static struct sem_set sets[SEM_N];

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
void sysvsem_forget_task(void *t) {
    for (int i = 0; i < SEM_N; i++)
        for (int w = 0; w < SEM_WAITERS; w++)
            if ((void *)sets[i].waiters[w] == t) sets[i].waiters[w] = 0;
}


/* Open or create a semaphore set. IPC_PRIVATE (key 0) always makes a fresh set;
 * a positive key reuses an existing set or (with IPC_CREAT) makes one. Returns
 * the set id, or -1. */
int sysv_semget(int key, int nsems, int flags) {
    if (nsems <= 0 || nsems > SEM_PER) return -1;
    uint64_t f = sv_irq_save();
    if (key != IPC_PRIVATE)
        for (int i = 0; i < SEM_N; i++) if (sets[i].used && sets[i].key == key) { sv_irq_restore(f); return i; }
    if (key != IPC_PRIVATE && !(flags & IPC_CREAT)) { sv_irq_restore(f); return -1; }   /* not found, not asked to create */
    for (int i = 0; i < SEM_N; i++) if (!sets[i].used) {
        sets[i].used = 1; sets[i].key = key; sets[i].nsems = nsems; sets[i].nwait = 0;
        for (int j = 0; j < nsems; j++) sets[i].val[j] = 0;
        sv_irq_restore(f);
        return i;
    }
    sv_irq_restore(f);
    return -1;   /* table full */
}

static void wake_all(struct sem_set *s) {      /* a value changed: let every blocked op recheck */
    int n = s->nwait; s->nwait = 0;
    for (int i = 0; i < n; i++) if (s->waiters[i]) task_wake(s->waiters[i]);
}

/* Atomic all-or-nothing semop over an array of ops. Returns 0, or -1 on a bad
 * id/arg or (with IPC_NOWAIT) when it would block. */
int sysv_semop(int id, struct sembuf *sops, unsigned nsops) {
    if (id < 0 || id >= SEM_N || !sets[id].used) return -1;
    if (nsops == 0 || nsops > SEM_PER) return -1;
    struct sem_set *s = &sets[id];
    for (unsigned k = 0; k < nsops; k++)        /* validate sem_num up front */
        if (sops[k].sem_num < 0 || sops[k].sem_num >= s->nsems) return -1;
    for (;;) {
        uint64_t f = sv_irq_save();
        int would_block = 0, nowait = 0;
        for (unsigned k = 0; k < nsops; k++) {
            int v = s->val[sops[k].sem_num], op = sops[k].sem_op;
            if ((op < 0 && v + op < 0) || (op == 0 && v != 0)) {
                would_block = 1;
                if (sops[k].sem_flg & IPC_NOWAIT) nowait = 1;
            }
        }
        if (!would_block) {                     /* every op can proceed: commit + wake under the same lock */
            for (unsigned k = 0; k < nsops; k++) s->val[sops[k].sem_num] += sops[k].sem_op;
            wake_all(s);                        /* increments may unblock other waiters */
            sv_irq_restore(f);
            return 0;
        }
        if (nowait) { sv_irq_restore(f); return -1; }   /* EAGAIN: do not apply anything */
        if (s->nwait >= SEM_WAITERS) { sv_irq_restore(f); return -1; }   /* M1618: refuse rather than silently
                                                                            * drop the registration and block
                                                                            * anyway -- a permanent, deterministic
                                                                            * hang once 8 tasks already wait here */
        s->waiters[s->nwait++] = task_self();
        sv_irq_restore(f);                      /* released BEFORE blocking (M1618) */
        task_block();                           /* woken by semop/semctl changing the set */
        if (!s->used) return -1;                /* removed (IPC_RMID) while we blocked */
    }
}

/* SETVAL (set a semaphore's value), GETVAL (read one), IPC_RMID (remove the set). */
int sysv_semctl(int id, int semnum, int cmd, int arg) {
    if (id < 0 || id >= SEM_N || !sets[id].used) return -1;
    struct sem_set *s = &sets[id];
    uint64_t f = sv_irq_save();
    if (cmd == IPC_RMID) { s->used = 0; wake_all(s); sv_irq_restore(f); return 0; }
    if (semnum < 0 || semnum >= s->nsems) { sv_irq_restore(f); return -1; }
    if (cmd == GETVAL) { int v = s->val[semnum]; sv_irq_restore(f); return v; }
    if (cmd == SETVAL) { s->val[semnum] = arg; wake_all(s); sv_irq_restore(f); return 0; }
    sv_irq_restore(f);
    return -1;
}

/* ---- System V message queues (M1160) ---------------------------------------
 * Keyed queues of TYPED messages. msgsnd appends a message tagged with a
 * positive mtype; msgrcv selects by `mtyp`: 0 = the oldest message, >0 = the
 * oldest with mtype == mtyp, <0 = the oldest among messages with mtype <= |mtyp|
 * (picking the LOWEST such mtype first). Blocks (task_block) when full/empty.
 * Distinct from the M1154 POSIX mqueue (priority-ordered, named): this is the
 * keyed, type-selected SysV API. */
#define MSG_N    8
#define MSG_MAX  32
#define MSG_SZ   192
struct sysv_msg { int used; long mtype; uint32_t seq; int len; char data[MSG_SZ]; };
struct msg_q {
    int used, key, count; uint32_t seq;
    struct sysv_msg m[MSG_MAX];
    task_t *swait[4], *rwait[4]; int nsw, nrw;
};
static struct msg_q mqs[MSG_N];

static void mq_wake(task_t **w, int *n) { int k = *n; *n = 0; for (int i = 0; i < k; i++) if (w[i]) task_wake(w[i]); }

int sysv_msgget(int key, int flags) {
    uint64_t f = sv_irq_save();
    if (key != IPC_PRIVATE) for (int i = 0; i < MSG_N; i++) if (mqs[i].used && mqs[i].key == key) { sv_irq_restore(f); return i; }
    if (key != IPC_PRIVATE && !(flags & IPC_CREAT)) { sv_irq_restore(f); return -1; }
    for (int i = 0; i < MSG_N; i++) if (!mqs[i].used) {
        mqs[i].used = 1; mqs[i].key = key; mqs[i].count = 0; mqs[i].seq = 0; mqs[i].nsw = mqs[i].nrw = 0;
        for (int j = 0; j < MSG_MAX; j++) mqs[i].m[j].used = 0;
        sv_irq_restore(f);
        return i;
    }
    sv_irq_restore(f);
    return -1;
}

int sysv_msgsnd(int id, long mtype, const void *data, int len, int flags) {
    if (id < 0 || id >= MSG_N || !mqs[id].used || mtype <= 0) return -1;
    if (len < 0 || len > MSG_SZ) return -1;
    struct msg_q *q = &mqs[id];
    for (;;) {
        uint64_t f = sv_irq_save();
        if (q->count >= MSG_MAX) {                       /* full -> block (unless IPC_NOWAIT) */
            if (flags & IPC_NOWAIT) { sv_irq_restore(f); return -1; }
            if (q->nsw >= 4) { sv_irq_restore(f); return -1; }   /* M1618: refuse rather than block with no
                                                                    * way to ever be woken (a permanent hang) */
            q->swait[q->nsw++] = task_self();
            sv_irq_restore(f);                            /* released BEFORE blocking (M1618) */
            task_block();
            if (!q->used) return -1;
            continue;                                     /* re-check count under the lock */
        }
        int placed = 0;
        for (int i = 0; i < MSG_MAX; i++) if (!q->m[i].used) {
            q->m[i].used = 1; q->m[i].mtype = mtype; q->m[i].seq = q->seq++; q->m[i].len = len;
            for (int b = 0; b < len; b++) q->m[i].data[b] = ((const char *)data)[b];
            q->count++;
            mq_wake(q->rwait, &q->nrw);
            placed = 1;
            break;
        }
        sv_irq_restore(f);
        return placed ? 0 : -1;      /* !placed shouldn't happen (count said there was room) */
    }
}

int sysv_msgrcv(int id, long mtyp, void *out, int max, long *mtype_out, int flags) {
    if (id < 0 || id >= MSG_N || !mqs[id].used) return -1;
    struct msg_q *q = &mqs[id];
    for (;;) {
        uint64_t f = sv_irq_save();
        int best = -1;
        for (int i = 0; i < MSG_MAX; i++) if (q->m[i].used) {
            long t = q->m[i].mtype;
            int match = (mtyp == 0) || (mtyp > 0 && t == mtyp) || (mtyp < 0 && t <= -mtyp);
            if (!match) continue;
            if (best < 0) { best = i; continue; }
            if (mtyp < 0) {            /* lowest mtype, then oldest */
                if (t < q->m[best].mtype || (t == q->m[best].mtype && q->m[i].seq < q->m[best].seq)) best = i;
            } else if (q->m[i].seq < q->m[best].seq) best = i;   /* oldest match */
        }
        if (best >= 0) {
            int n = q->m[best].len; if (n > max) n = max;
            for (int b = 0; b < n; b++) ((char *)out)[b] = q->m[best].data[b];
            if (mtype_out) *mtype_out = q->m[best].mtype;
            q->m[best].used = 0; q->count--;
            mq_wake(q->swait, &q->nsw);
            sv_irq_restore(f);
            return n;
        }
        if (flags & IPC_NOWAIT) { sv_irq_restore(f); return -1; }   /* no match -> block (unless IPC_NOWAIT) */
        if (q->nrw >= 4) { sv_irq_restore(f); return -1; }   /* M1618: same overflow fix as msgsnd */
        q->rwait[q->nrw++] = task_self();
        sv_irq_restore(f);                                  /* released BEFORE blocking (M1618) */
        task_block();
        if (!q->used) return -1;
    }
}

/* IPC_RMID (M1576): the removal path this table never had. Before this,
 * MSG_N=8 message queues, ever created, permanently exhausted the table for
 * the machine's uptime -- mirrors sysv_semctl's own IPC_RMID exactly, waking
 * every blocked sender/receiver so nobody is left parked on a removed queue. */
int sysv_msgctl(int id, int cmd) {
    if (id < 0 || id >= MSG_N || !mqs[id].used) return -1;
    if (cmd != IPC_RMID) return -1;
    uint64_t f = sv_irq_save();
    mqs[id].used = 0;
    mq_wake(mqs[id].swait, &mqs[id].nsw);
    mq_wake(mqs[id].rwait, &mqs[id].nrw);
    sv_irq_restore(f);
    return 0;
}

/* ---- System V shared memory (M1161) ----------------------------------------
 * Keyed shared-memory segments. shmget(key,size,flags) opens/creates a segment;
 * shmat maps it into the caller's address space; shmdt unmaps. A segment is just
 * a named object backed by the existing M1108 shm machinery (app_shm_open) —
 * each segment gets a stable synthetic name, so two shmat()s of the same id (in
 * the same or different processes) map the SAME physical frames. */
#define SHM_N      16
struct shm_seg { int used, key; uint64_t size; char name[16]; };
static struct shm_seg shms[SHM_N];

int sysv_shmget(int key, uint64_t size, int flags) {
    /* the real cap is shm.c's own (M1592) -- a separately-maintained constant
     * here previously let shmget accept sizes shmat would then silently fail
     * on (shmget's own 4 MiB vs shm_get's real 256 KiB, a live gap the same
     * research pass that found the IPC_RMID wiring bug below also caught). */
    if (size == 0 || size > shm_max_bytes()) return -1;
    uint64_t f = sv_irq_save();
    /* M1618: two cores racing shmget on the same brand-new key was the worst
     * case this file's own scan-then-create race could hit -- both could
     * find the same free slot and each write HALF of shms[i] (used/key/size
     * fields interleaved with the other's), or hand out the same id with
     * two different sizes. Now serialized like every other table here. */
    if (key != IPC_PRIVATE) for (int i = 0; i < SHM_N; i++) if (shms[i].used && shms[i].key == key) { sv_irq_restore(f); return i; }
    if (key != IPC_PRIVATE && !(flags & IPC_CREAT)) { sv_irq_restore(f); return -1; }
    for (int i = 0; i < SHM_N; i++) if (!shms[i].used) {
        shms[i].used = 1; shms[i].key = key; shms[i].size = size;
        char *n = shms[i].name; int p = 0;                 /* stable synthetic name "sysvshmNN" */
        const char *pre = "sysvshm"; while (*pre) n[p++] = *pre++;
        n[p++] = (char)('0' + i / 10); n[p++] = (char)('0' + i % 10); n[p] = 0;
        sv_irq_restore(f);
        return i;
    }
    sv_irq_restore(f);
    return -1;
}

/* Attach: map the segment into the caller's address space, return the base VA
 * (or 0). Two attaches of the same id share the backing (same synthetic name). */
uint64_t sysv_shmat(int id) {
    if (id < 0 || id >= SHM_N) return 0;
    uint64_t f = sv_irq_save();
    int ok = shms[id].used;
    char name[16] = {0}; uint64_t size = 0;
    if (ok) { for (int i = 0; i < 16; i++) name[i] = shms[id].name[i]; size = shms[id].size; }
    sv_irq_restore(f);
    if (!ok) return 0;
    return app_shm_open(name, size);   /* outside the lock: a separate subsystem call, avoid nesting locks */
}

/* IPC_RMID (M1576, fully wired M1592): frees THIS id slot (SHM_N=16,
 * permanently exhausted without this before now) so a future sysv_shmget can
 * reuse the number -- matching real shmctl(IPC_RMID)'s effect on the id
 * namespace. M1576 deliberately scoped itself no further, since the
 * underlying named object in shm.c (its own separate, smaller SHM_N=8 table,
 * keyed by THIS segment's synthetic "sysvshmNN" name, derived deterministically
 * from `id`) had no removal path of its own at the time. shm_unlink() (M1590)
 * is exactly that removal path, just never wired back to this caller until
 * now -- calling it here means a freed id's frames are actually released
 * (matching the M1089 per-frame refcount: still-live shmat mappings keep
 * their own separate references, same as shm_unlink's own POSIX contract),
 * and a later shmget reusing this id's synthetic name gets a genuinely fresh,
 * zeroed segment rather than the same stale frames a pure id-slot free would
 * have handed back. */
int sysv_shmctl(int id, int cmd) {
    if (id < 0 || id >= SHM_N) return -1;
    if (cmd != IPC_RMID) return -1;
    uint64_t f = sv_irq_save();
    int ok = shms[id].used;
    char name[16] = {0};
    if (ok) { for (int i = 0; i < 16; i++) name[i] = shms[id].name[i]; shms[id].used = 0; }
    sv_irq_restore(f);
    if (!ok) return -1;
    shm_unlink(name);   /* outside the lock: a separate subsystem call */
    return 0;
}

/* /proc/sysvipc: one line per live set — "id key nsems val0,val1,...". */
int sysv_sem_format(char *out, int max) {
    int p = 0;
    for (int i = 0; i < SEM_N && p < max - 96; i++) if (sets[i].used) {
        char t[16]; int n;
        for (int pass = 0; pass < 2; pass++) {    /* id, key */
            int v = pass ? sets[i].key : i; n = 0;
            if (!v) t[n++] = '0'; while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
            while (n) out[p++] = t[--n];
            out[p++] = ' ';
        }
        for (int j = 0; j < sets[i].nsems && p < max - 16; j++) {
            int v = sets[i].val[j]; n = 0;
            if (!v) t[n++] = '0'; while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
            while (n) out[p++] = t[--n];
            out[p++] = (j + 1 < sets[i].nsems) ? ',' : '\n';
        }
        if (sets[i].nsems == 0) out[p++] = '\n';
    }
    out[p] = 0; return p;
}

/* M1619: /proc/sysvipc only ever reported semaphore sets -- message queues
 * and shm segments (both fully implemented, both with a working IPC_RMID
 * path) had no formatter anywhere, unlike every other resource table in
 * procfs.c. Same "id key ..." shape as sysv_sem_format above. */
int sysv_msg_format(char *out, int max) {         /* one line per live queue: "id key count" */
    int p = 0;
    for (int i = 0; i < MSG_N && p < max - 48; i++) if (mqs[i].used) {
        char t[16]; int n;
        for (int pass = 0; pass < 3; pass++) {    /* id, key, count */
            int v = pass == 0 ? i : (pass == 1 ? mqs[i].key : mqs[i].count); n = 0;
            if (!v) t[n++] = '0'; while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
            while (n) out[p++] = t[--n];
            out[p++] = (pass < 2) ? ' ' : '\n';
        }
    }
    out[p] = 0; return p;
}
int sysv_shm_format(char *out, int max) {         /* one line per live segment: "id key size" */
    int p = 0;
    for (int i = 0; i < SHM_N && p < max - 48; i++) if (shms[i].used) {
        char t[24]; int n;
        for (int pass = 0; pass < 2; pass++) {    /* id, key */
            int v = pass ? shms[i].key : i; n = 0;
            if (!v) t[n++] = '0'; while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
            while (n) out[p++] = t[--n];
            out[p++] = ' ';
        }
        uint64_t sz = shms[i].size; n = 0;
        if (!sz) t[n++] = '0'; while (sz) { t[n++] = (char)('0' + sz % 10); sz /= 10; }
        while (n) out[p++] = t[--n];
        out[p++] = '\n';
    }
    out[p] = 0; return p;
}
