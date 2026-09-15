/*
 * sem.c — POSIX named semaphores (M1575): sem_open/wait/trywait/post/close/
 * unlink/getvalue. Distinct from the keyed SysV semaphore SETS in sysvipc.c
 * (multi-semaphore, atomic multi-op semop) -- this is a single counting
 * semaphore per NAME, shared by any process that sem_opens the same name,
 * with independent per-process handles: sem_close only drops one handle
 * (refcounted), the semaphore itself persists until sem_unlink AND every
 * handle has closed, matching real POSIX exactly. Built on the same
 * IRQ-safe task_block/task_wake rendezvous mqueue.c/sysvipc.c use, and the
 * same wake-everyone-let-them-recheck idiom sysvipc.c's own wake_all uses
 * (safe under this codebase's plain task_block/task_wake model, rather than
 * trying to wake exactly one waiter by queue position).
 */
#include "sem.h"
#include "task.h"
#include <stdint.h>

/* M1618: same fix as sysvipc.c/mqueue.c/shm.c this same pass -- this file had
 * no lock of any kind, despite the header comment's own claim of being
 * "built on the same IRQ-safe task_block/task_wake rendezvous" other,
 * already-fixed files use. One lock for the whole file (open/close/unlink's
 * scan-then-create-or-mutate, wait/trywait/post/getvalue's check-then-act). */
static volatile int sem_lock;
static inline uint64_t sm_irq_save(void) {
    uint64_t f;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory");
    while (__atomic_exchange_n(&sem_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return f;
}
static inline void sm_irq_restore(uint64_t f) {
    __atomic_store_n(&sem_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(f) : "memory", "cc");
}

#define SEM_N       16   /* max named semaphores */
#define SEM_WAITERS 8    /* max tasks blocked on one semaphore */

struct psem {
    char    name[32];
    int     used, unlinked, value, refcount;
    task_t *waiters[SEM_WAITERS];
    int     nwait;
};
static struct psem tab[SEM_N];

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
void psem_forget_task(void *t) {
    for (int i = 0; i < SEM_N; i++)
        for (int w = 0; w < SEM_WAITERS; w++)
            if ((void *)tab[i].waiters[w] == t) tab[i].waiters[w] = 0;
}


static int seq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }

/* Open (find-or-create) a named semaphore. O_CREAT|O_EXCL fails (EEXIST) if
 * it already exists; a plain O_CREAT reuses an existing one silently
 * (value/mode ignored on reuse, matching real POSIX). Each successful open
 * -- even a second one from the SAME process -- gets its own refcounted
 * handle that must be independently closed. */
int sem_named_open(const char *name, int oflag, unsigned int value) {
    if (!name || !name[0]) return -1;
    uint64_t f = sm_irq_save();
    for (int i = 0; i < SEM_N; i++)
        if (tab[i].used && !tab[i].unlinked && seq(tab[i].name, name)) {
            if ((oflag & O_CREAT) && (oflag & O_EXCL)) { sm_irq_restore(f); return -1; }   /* EEXIST */
            tab[i].refcount++;
            sm_irq_restore(f);
            return i;
        }
    if (!(oflag & O_CREAT)) { sm_irq_restore(f); return -1; }   /* ENOENT */
    for (int i = 0; i < SEM_N; i++) if (!tab[i].used) {
        int j = 0; while (name[j] && j < 31) { tab[i].name[j] = name[j]; j++; } tab[i].name[j] = 0;
        tab[i].used = 1; tab[i].unlinked = 0; tab[i].value = (int)value; tab[i].refcount = 1; tab[i].nwait = 0;
        sm_irq_restore(f);
        return i;
    }
    sm_irq_restore(f);
    return -1;   /* table full */
}

int sem_named_close(int idx) {
    if (idx < 0 || idx >= SEM_N) return -1;
    uint64_t f = sm_irq_save();
    if (!tab[idx].used) { sm_irq_restore(f); return -1; }
    if (tab[idx].refcount > 0) tab[idx].refcount--;
    if (tab[idx].refcount == 0 && tab[idx].unlinked) tab[idx].used = 0;
    sm_irq_restore(f);
    return 0;
}

/* Removes the NAME so no new sem_open can find it; existing handles (and
 * anyone still blocked in sem_wait on this index) stay valid until closed. */
int sem_named_unlink(const char *name) {
    if (!name || !name[0]) return -1;
    uint64_t f = sm_irq_save();
    for (int i = 0; i < SEM_N; i++) if (tab[i].used && !tab[i].unlinked && seq(tab[i].name, name)) {
        tab[i].unlinked = 1;
        if (tab[i].refcount == 0) tab[i].used = 0;   /* nobody holds it open -- free now */
        sm_irq_restore(f);
        return 0;
    }
    sm_irq_restore(f);
    return -1;   /* ENOENT */
}

static void wake_all(struct psem *s) {   /* a post changed the value: let every blocked waiter recheck */
    int n = s->nwait; s->nwait = 0;
    for (int i = 0; i < n; i++) if (s->waiters[i]) task_wake(s->waiters[i]);
}

int sem_named_wait(int idx) {
    if (idx < 0 || idx >= SEM_N) return -1;
    struct psem *s = &tab[idx];
    for (;;) {
        uint64_t f = sm_irq_save();
        if (!s->used) { sm_irq_restore(f); return -1; }
        if (s->value > 0) { s->value--; sm_irq_restore(f); return 0; }
        if (s->nwait >= SEM_WAITERS) { sm_irq_restore(f); return -1; }   /* M1618: refuse rather than block
                                                                            * with no way to ever be woken */
        s->waiters[s->nwait++] = task_self();
        sm_irq_restore(f);                  /* released BEFORE blocking (M1618) */
        task_block();
        if (!s->used) return -1;            /* removed (fully closed + unlinked) while blocked */
    }
}

int sem_named_trywait(int idx) {
    if (idx < 0 || idx >= SEM_N) return -1;
    struct psem *s = &tab[idx];
    uint64_t f = sm_irq_save();
    if (!s->used || s->value == 0) { sm_irq_restore(f); return -1; }   /* EAGAIN */
    s->value--;
    sm_irq_restore(f);
    return 0;
}

int sem_named_post(int idx) {
    if (idx < 0 || idx >= SEM_N) return -1;
    struct psem *s = &tab[idx];
    uint64_t f = sm_irq_save();
    if (!s->used) { sm_irq_restore(f); return -1; }
    s->value++;
    wake_all(s);
    sm_irq_restore(f);
    return 0;
}

int sem_named_getvalue(int idx, int *out) {
    if (idx < 0 || idx >= SEM_N || !out) return -1;
    uint64_t f = sm_irq_save();
    int ok = tab[idx].used;
    if (ok) *out = tab[idx].value;
    sm_irq_restore(f);
    return ok ? 0 : -1;
}
