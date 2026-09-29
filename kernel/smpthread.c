/* smpthread.c — see smpthread.h for the model and why it's shaped this way.
 *
 * Reuses context_switch (kernel/asm/context_switch.asm) directly: it's a
 * generic "save callee-saved regs + rsp, load a new rsp, ret" primitive with
 * no dependency on task.c's data structures, so a completely separate ring
 * per core can use it safely without touching the existing scheduler.
 */
#include "smpthread.h"
#include "smp.h"
#include "vmm.h"       /* kstack_alloc/kstack_free — guarded stacks (M1495) */
#include "kheap.h"
#include "interrupts.h"
#include <stdint.h>
#include <stddef.h>

extern void context_switch(uint64_t *old_rsp, uint64_t new_rsp);

#define ST_MAXCPUS  16
#define ST_STACK    (64 * 1024)

typedef enum { ST_READY, ST_RUNNING, ST_DONE } st_state;

struct smp_thread {
    uint64_t rsp;
    void *stack_base;
    smp_thread_fn fn;
    void *arg;
    volatile st_state state;
    volatile int gone;          /* off its stack for good: join may free it */
    struct smp_thread *next;    /* ring, scoped to ONE core */
};

/* Indexed by APIC id & (ST_MAXCPUS-1), the same masking convention smp.c's own
 * cpu_jobs[] and ecdsa.c's per-core slots already use. Assumes APIC ids are
 * small/dense (0..cpu_count-1) -- true for every QEMU -smp config this project
 * targets; a real multi-socket machine with sparse APIC ids would need a real
 * id->index table instead. */
static struct smp_thread *core_ring[ST_MAXCPUS];      /* one thread's "next" pointer per ring */
static struct smp_thread *core_current[ST_MAXCPUS];   /* who's running on that core right now */
static uint64_t core_base_rsp[ST_MAXCPUS];            /* that core's ap_main call site, to return to */
/* A finished thread is still ON ITS STACK after it marks itself ST_DONE: its
 * final context_switch pushes registers there. So "done" cannot mean "free
 * it" -- join used to free the stack at ST_DONE, under a thread still
 * switching off it. Whatever runs next on the core is proof it has left, and
 * publishes `gone`, the same shape as task.c's core_dying. */
static struct smp_thread *core_dead[ST_MAXCPUS];
static void st_reap_prev(int core) {
    struct smp_thread *d = core_dead[core];
    if (d) { core_dead[core] = 0; __atomic_store_n(&d->gone, 1, __ATOMIC_RELEASE); }
}
static volatile int st_lock;
static int rr_next = 1;                               /* round-robin spawn target, skip 0 (the BSP) */

static void stlock(void)   { while (__atomic_exchange_n(&st_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause"); }
static void stunlock(void) { __atomic_store_n(&st_lock, 0, __ATOMIC_RELEASE); }

static int this_core(void) { return smp_current_cpu() & (ST_MAXCPUS - 1); }

/* Where a freshly spawned thread begins; `core_current[this_core()]` is
 * already this thread (set under the lock before the first switch-in). */
static void st_trampoline(void) {
    st_reap_prev(this_core());           /* before interrupts: we are the next context here */
    interrupts_enable();
    int core = this_core();
    struct smp_thread *me = core_current[core];
    me->fn(me->arg);

    stlock();
    me->state = ST_DONE;
    /* unlink from this core's ring */
    if (me->next == me) {
        core_ring[core] = 0;
    } else {
        struct smp_thread *p = me->next;
        while (p->next != me) p = p->next;
        p->next = me->next;
        if (core_ring[core] == me) core_ring[core] = me->next;
    }
    struct smp_thread *next = 0;
    if (core_ring[core]) {
        struct smp_thread *p = core_ring[core];
        do { if (p->state == ST_READY) { next = p; break; } p = p->next; } while (p != core_ring[core]);
    }
    core_current[core] = next;
    if (next) next->state = ST_RUNNING;
    core_dead[core] = me;                /* the next context on this core marks us gone */
    stunlock();

    uint64_t discard;
    if (next) context_switch(&discard, next->rsp);              /* never returns */
    else      context_switch(&discard, core_base_rsp[core]);    /* back to ap_main's loop */
    for (;;) __asm__ volatile("cli; hlt");                       /* unreachable */
}

smp_thread_t *smp_thread_spawn(smp_thread_fn fn, void *arg) {
    int nc = __atomic_load_n(&smp_cpu_count, __ATOMIC_SEQ_CST);
    if (nc <= 1) { fn(arg); return 0; }         /* uniprocessor: nowhere to send it, just run it now */

    int core = (__atomic_fetch_add(&rr_next, 1, __ATOMIC_SEQ_CST) % (nc - 1)) + 1;   /* 1..nc-1, skip the BSP */

    struct smp_thread *t = kzalloc(sizeof *t);
    if (!t) return 0;
    t->stack_base = kstack_alloc(ST_STACK);
    if (!t->stack_base) { kfree(t); return 0; }
    t->fn = fn; t->arg = arg; t->state = ST_READY;

    /* Same stack pre-build as task.c's task_create_stack: a fake frame so
     * context_switch's `ret` lands in the trampoline on first switch-in. */
    uint64_t top = ((uint64_t)t->stack_base + ST_STACK) & ~15ull;
    uint64_t *sp = (uint64_t *)top;
    *--sp = (uint64_t)st_trampoline;
    *--sp = 0; *--sp = 0; *--sp = 0; *--sp = 0; *--sp = 0; *--sp = 0;
    t->rsp = (uint64_t)sp;

    stlock();
    if (!core_ring[core]) { t->next = t; core_ring[core] = t; }
    else { t->next = core_ring[core]->next; core_ring[core]->next = t; }
    stunlock();

    smp_wake_aps();     /* nudge every AP to check in (reuses the existing job-pool wake IPI) */
    return t;
}

void smp_thread_yield(void) {
    int core = this_core();
    stlock();
    struct smp_thread *me = core_current[core];
    if (!me) { stunlock(); return; }
    struct smp_thread *next = 0;
    for (struct smp_thread *p = me->next; p != me; p = p->next)
        if (p->state == ST_READY) { next = p; break; }
    if (!next) { stunlock(); return; }         /* no sibling waiting -- keep running */
    me->state = ST_READY;
    next->state = ST_RUNNING;
    core_current[core] = next;
    stunlock();
    context_switch(&me->rsp, next->rsp);       /* resumes here once picked again */
    st_reap_prev(core);
}

void smp_thread_join(smp_thread_t *t) {
    if (!t) return;
    while (!__atomic_load_n(&t->gone, __ATOMIC_ACQUIRE))   /* not ST_DONE: see core_dead */
        __asm__ volatile("pause");
    kstack_free(t->stack_base, ST_STACK);
    kfree(t);
}

void smpthread_ap_tick(void) {
    int core = this_core();
    stlock();
    struct smp_thread *ring = core_ring[core];
    struct smp_thread *first = 0;
    if (ring) {
        struct smp_thread *p = ring;
        do { if (p->state == ST_READY) { first = p; break; } p = p->next; } while (p != ring);
    }
    if (!first) { stunlock(); return; }
    first->state = ST_RUNNING;
    core_current[core] = first;
    stunlock();
    context_switch(&core_base_rsp[core], first->rsp);   /* returns once this core's ring drains */
    st_reap_prev(core);
}
