/*
 * task.c — kernel threads and a round-robin scheduler.
 *
 * Tasks live in a circular linked list (the "ready ring"). `current` points at
 * the running one; scheduling just walks to `current->next`. A context switch
 * (context_switch.asm) swaps the saved stack pointer, which swaps everything a
 * thread is doing.
 *
 * This is *preemptive* round-robin: the timer IRQ calls sched_tick() (see
 * timer.c), which switches to current->next, so a thread can be suspended
 * between any two instructions — threads also yield voluntarily via task_yield()
 * or block via task_block(). Because switches can happen anywhere, code that
 * shares state between tasks must guard it (e.g. irq_save/irq_restore below).
 * See docs/07 (threads) and docs/11 (preemption) for the history.
 */
#include "task.h"
#include "syscall.h"   /* SCHED_OTHER/FIFO/RR (M1172) */
#include "kheap.h"
#include "interrupts.h"
#include "gdt.h"
#include "string.h"
#include "timer.h"
#include "console.h"   /* kprintf — for the stack-overflow panic */
#include "vmm.h"       /* kstack_alloc/free — guarded task stacks (M1495) */
#include "smp.h"       /* smp_current_cpu — per-core scheduler state (M1531) */

#define STACK_SIZE 16384
#define FXSZ       512                 /* FXSAVE area size */
/* A magic value written at the LOWEST address of every kmalloc'd kernel task stack
 * (task_create_stack) and checked on each context switch (switch_to_next): if a
 * deep call chain overran the stack down to its base, this is clobbered and we
 * panic cleanly instead of silently corrupting the adjacent heap — which is how an
 * undersized stack manifested before (the ring-3 browser fetch worker, M1491:
 * a 64K stack overflowed during the in-kernel TLS bignum handshake and trashed the
 * task ring, GPF'ing in task_wake_sleepers with no hint of the real cause). */
#define STACK_CANARY 0x9e3b8a7c5d6f1024ull

/* --- multi-core scheduler state (M1531) ---------------------------------
 * Before this, `current`/`active_cr3` were single globals: only the BSP ever
 * ran the scheduler, every other core sat in kernel/smp.c's job-pool-only
 * idle loop. Now every core (BSP + each AP) has its OWN slot, indexed by its
 * APIC id masked the same way kernel/smp.c's own cpu_jobs[]/ecdsa.c's per-core
 * arrays already do — and the shared ready ring itself needs a REAL cross-
 * core lock (a plain `cli` only ever protected against a LOCAL interrupt
 * reentering, never against another core concurrently walking/mutating the
 * same ring). `current`/`active_cr3` are kept as macros so the large existing
 * body of this file (every `current->x`, `current = t`, etc.) keeps working
 * unchanged — each reference now transparently resolves to THIS core's own
 * slot instead of silently being a single-core assumption. */
#define MAX_SCHED_CPUS 16
static task_t   *cur[MAX_SCHED_CPUS];
static uint64_t  active_cr3_arr[MAX_SCHED_CPUS];
static inline int mycore(void) { return smp_current_cpu() & (MAX_SCHED_CPUS - 1); }
#define current    (cur[mycore()])
#define active_cr3 (active_cr3_arr[mycore()])

/* The cross-core ready-ring lock. Local interrupt disabling (irq_save/
 * irq_restore, unchanged below) still matters — it stops a task on THIS core
 * from being reentered mid-update — but by itself says nothing about another
 * core running concurrently. rq_lock_take/give bracket the actual ring reads/
 * writes; switch_to_next/task_exit release it BEFORE their context_switch
 * tail (a switch can leave a task off-CPU for an arbitrary time, so holding a
 * global lock across it would freeze every other core's scheduling for that
 * whole time) while leaving interrupts disabled around that tail exactly as
 * the single-core version already did. */
static volatile int rq_lock;
static inline void rq_lock_take(void) { while (__atomic_exchange_n(&rq_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause"); }
static inline void rq_lock_give(void) { __atomic_store_n(&rq_lock, 0, __ATOMIC_RELEASE); }

static int     next_id;
static uint64_t g_nr_switches;   /* total context switches since boot — /proc/stat "ctxt" (M1253) */

/* Set once sched_init() has built task 0 (M1531). smp_init() runs BEFORE
 * sched_init() (kmain.c relies on being genuinely single-threaded across the
 * AP bring-up + vmm_harden_kernel span in between — see kmain.c's own
 * comment), so an AP that reaches ap_main() early would otherwise call
 * task_register_ap_core() while `cur[0]` (task 0) doesn't exist yet and
 * dereference it — hit exactly that crash once, in-guest, before adding this
 * gate. task_register_ap_core() spins on this instead. */
static volatile int g_sched_ready;

extern void context_switch(uint64_t *old_rsp, uint64_t new_rsp);
extern void fpu_save(void *area16);            /* FXSAVE  (kernel/asm/fpu.asm) */
extern void fpu_restore(const void *area16);   /* FXRSTOR */
extern uint8_t fpu_template[];                 /* a clean FP state, captured at boot */
/* XSAVE/AVX (M1942) — see kernel/asm/fpu.asm for why enabling AVX REQUIRES
 * moving the context switch off FXSAVE: FXSAVE preserves XMM but not the upper
 * halves of YMM, so two AVX-using tasks would silently corrupt each other. */
extern void     fpu_xsave_to(void *area64);
extern void     fpu_xrstor_from(const void *area64);
extern void     fpu_xsave_template(void *area64);
extern uint32_t fpu_xsave_size(void);
extern uint8_t  fpu_xtemplate[];

/* 0 until fpu_xsave_arm() finds XSAVE+AVX. While 0 everything below behaves
 * exactly as it did before, which is what QEMU's default CPU (no AVX) gets. */
static int      g_use_xsave;
static uint32_t g_fpu_area = FXSZ;             /* bytes a task's FP area needs */
static uint32_t g_fpu_align = 16;              /* FXSAVE wants 16, XSAVE wants 64 */

/* Called once per core at boot, BEFORE any task exists (the area size decides
 * every later allocation). CR4.OSXSAVE and XCR0 are per-core, so every AP must
 * call it too, but only the first caller sizes the area. */
void fpu_xsave_arm(void) {
    extern int fpu_enable_xsave(void);
    if (!fpu_enable_xsave()) {                 /* no XSAVE/AVX: stay on FXSAVE */
        static int once; if (!once) { once = 1; kprintf("[ .. ] fpu: no XSAVE/AVX on this CPU -- staying on FXSAVE (AVX binaries will #UD)\n"); }
        return;
    }
    if (!g_use_xsave) {
        uint32_t sz = fpu_xsave_size();
        if (sz < FXSZ) sz = FXSZ;              /* paranoia: never shrink */
        g_fpu_area = sz; g_fpu_align = 64; g_use_xsave = 1;
        fpu_xsave_template(fpu_xtemplate);     /* a CLEAN state, not a zeroed buffer */
        kprintf("[ ok ] fpu: XSAVE+AVX enabled (XCR0 state area %u bytes)\n", sz);
    }
}

/* Aligned FP-save pointer inside a task's over-allocated fxbuf. XSAVE #GPs on a
 * misaligned area and kmalloc only guarantees 16, hence the slack + mask. */
static inline void *fxptr(task_t *t) {
    uintptr_t a = g_fpu_align - 1;
    return (void *)(((uintptr_t)t->fxbuf + a) & ~a);
}
static void fx_alloc(task_t *t) {              /* give a task its own FP save area */
    t->fxbuf = kmalloc(g_fpu_area + g_fpu_align);
    if (t->fxbuf)
        memcpy(fxptr(t), g_use_xsave ? fpu_xtemplate : fpu_template, g_fpu_area);
}
static inline void fpu_store(task_t *t) {
    if (g_use_xsave) fpu_xsave_to(fxptr(t)); else fpu_save(fxptr(t));
}
static inline void fpu_load(task_t *t) {
    if (g_use_xsave) fpu_xrstor_from(fxptr(t)); else fpu_restore(fxptr(t));
}

/* Copy the FP/SSE state of `src` (which must be the running task) into `dst` —
 * for fork(), so a child of a process mid-float-computation inherits its state.
 * fpu_save captures the live CPU FP state into src's area first. */
void task_copy_fpu(task_t *dst, task_t *src) {
    if (!dst || !src || !dst->fxbuf || !src->fxbuf) return;
    fpu_store(src);                            /* src is current: capture its live FP state */
    memcpy(fxptr(dst), fxptr(src), g_fpu_area);
}

struct registers *task_uframe(task_t *t) { return t ? t->uframe : 0; }

/* The scheduling floor, ONE PER CORE (M1531): never blocks/exits, run ONLY
 * when nothing else runnable exists FOR THAT CORE. Each is pin_core-tagged so
 * it can never be picked up by a DIFFERENT core (two cores can't share one
 * task_t's saved rsp/stack). NULL until sched_init/task_register_ap_core runs
 * for that slot -> switch_to_next falls back to its prior (keep prev) behavior. */
static task_t *floor_task[MAX_SCHED_CPUS];

/* --- CFS weighted-fair scheduling (M1171) -------------------------------------
 * Each task carries a vruntime (weighted CPU consumed) and a weight derived from
 * its nice level; switch_to_next runs the runnable task with the SMALLEST
 * vruntime, and charges the running task slice*NICE0_WEIGHT/weight of vruntime,
 * so a low-nice (high-weight) task accrues vruntime slowly and thus gets more
 * CPU. With every task at nice 0 (weight 1024) vruntime advances by real time
 * for all, so the pick reduces to "least-recently-run" — fair round-robin,
 * preserving the prior behavior. The Linux nice->weight table (nice -20..+19). */
#define NICE0_WEIGHT 1024u
static const uint32_t sched_weight[40] = {  /* index = nice + 20 */
    88761, 71755, 56483, 46273, 36291,      /* -20..-16 */
    29154, 23254, 18705, 14949, 11916,      /* -15..-11 */
     9548,  7620,  6100,  4904,  3906,      /* -10..-6  */
     3121,  2501,  1991,  1586,  1277,      /* -5..-1   */
     1024,   820,   655,   526,   423,      /*  0..+4   */
      335,   272,   215,   172,   137,      /* +5..+9   */
      110,    87,    70,    56,    45,      /* +10..+14 */
       36,    29,    23,    18,    15 };     /* +15..+19 */
static uint32_t nice_to_weight(int nice) {
    if (nice < -20) nice = -20; if (nice > 19) nice = 19;
    return sched_weight[nice + 20];
}
static uint64_t g_min_vruntime;   /* floor: the smallest vruntime among runnable tasks (monotonic non-decreasing) */
#define RR_QUANTUM 5              /* SCHED_RR timeslice in timer ticks before rotating among equal-priority RR tasks (M1172) */
static void sched_place_wake(task_t *t) {   /* a waking task can't be below the floor (no unfair head start; no starvation) */
    if (t && t->vruntime < g_min_vruntime) t->vruntime = g_min_vruntime;
}

static inline uint64_t read_cr3(void) {
    uint64_t v; __asm__ volatile("mov %%cr3, %0" : "=r"(v)); return v;
}
static inline void load_cr3(uint64_t v) {
    __asm__ volatile("mov %0, %%cr3" : : "r"(v) : "memory");
}

/* Per-thread %fs base for TLS (M1140). The kernel never uses FS_BASE itself, so
 * we only touch the MSR on behalf of threads that set one; `loaded_fs_base`
 * tracks the live value so a system with no TLS pays nothing (stays 0 == 0).
 * M1531: FS_BASE is a PER-CORE MSR — a single shared `loaded_fs_base` let one
 * core's write make the cache claim a value that was only ever actually
 * loaded on THAT core, so a DIFFERENT core would then wrongly skip its own
 * wrmsr for the same value (or, worse, for 0 vs non-zero, actually diverge).
 * Hit this as a real in-guest crash (wrmsr faulting -- a stale/never-loaded
 * FS_BASE on an AP). Now one slot per core, same masking convention as every
 * other per-core array in this codebase. */
#define MSR_FS_BASE 0xC0000100u
#define FSBASE_MAXCPUS 16
static uint64_t loaded_fs_base[FSBASE_MAXCPUS];
static void load_fs_base(uint64_t b) {
    int c = mycore();
    if (b == loaded_fs_base[c]) return;
    __asm__ volatile("wrmsr" : : "c"(MSR_FS_BASE), "a"((uint32_t)b), "d"((uint32_t)(b >> 32)));
    loaded_fs_base[c] = b;
}
/* Set the CURRENT thread's TLS base (live + saved for restore). M1140. */
void task_set_fs_base(uint64_t b) { current->fs_base = b; load_fs_base(b); }

/* Register the CURRENT thread's userspace robust-futex list (M1141). */
void task_set_robust(uint64_t r) { current->robust = r; }
uint64_t task_robust(void) { return current->robust; }

/* Save RFLAGS and disable interrupts (returns old flags); and restore them.
 * Scheduling edits the shared ready ring, so it must be uninterruptible. */
static inline uint64_t irq_save(void) {
    uint64_t f;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory");
    return f;
}
static inline void irq_restore(uint64_t f) {
    __asm__ volatile("push %0; popfq" : : "r"(f) : "memory", "cc");
}

/* Deferred post-switch cleanup (M1531 — the pattern real kernels call
 * finish_task_switch): the task a core just switched AWAY from must not
 * become pickable by ANOTHER core (state -> READY) until this core has
 * TRULY finished touching its stack/registers — which, thanks to the CR3/
 * TSS/FPU/FS_BASE hardware tail AFTER the scheduling decision commits, is
 * NOT the same moment as the decision itself. Marking it READY too early
 * left a real window where a second core could pick the same task and
 * context_switch onto its stack while the first core was still physically
 * running on it — hit this as a cluster of intermittent, differently-
 * shaped crashes (stack overflows, #UD, #GP/#DF) all landing somewhere in
 * switch_to_next's hardware tail, before adding this. `core_prev[c]` is
 * consumed exactly once per switch, by whichever code path resumes AFTER
 * it: thread_trampoline for a brand-new task, or switch_to_next's own line
 * right after context_switch returns for a task resuming a previous switch. */
static task_t *core_prev[MAX_SCHED_CPUS];
void task_finish_switch(void) {
    int c = mycore();
    task_t *p = core_prev[c];
    if (!p) return;
    core_prev[c] = 0;
    uint64_t f = irq_save();
    rq_lock_take();
    p->state = TASK_READY;
    p->ready_since = timer_ms();
    p->nivcsw++;
    rq_lock_give();
    irq_restore(f);
}

/* Where a freshly created thread begins. `current` is already this thread. */
static void thread_trampoline(void) {
    task_finish_switch();             /* complete whoever we just preempted (M1531) */
    interrupts_enable();        /* new threads start with interrupts on */
    current->entry();
    task_exit();                /* if the entry function returns, end cleanly */
}

/* The idle task: a guaranteed-runnable floor. Halts with interrupts on so the
 * timer can preempt it the instant any real task becomes runnable. */
static void idle_loop(void) { for (;;) __asm__ volatile("sti; hlt"); }

void sched_init(void) {
    task_t *t = kzalloc(sizeof(task_t));
    t->id = next_id++;
    t->state = TASK_RUNNING;
    t->next = t;                /* a ring of one */
    t->weight = NICE0_WEIGHT;   /* CFS: task 0 at nice 0 (M1171) — never leave weight 0 (div-by-zero in the charge) */
    t->cr3 = read_cr3();        /* task 0 runs in the kernel's address space */
    active_cr3 = t->cr3;
    fx_alloc(t);
    t->last_in = timer_ms();    /* start CPU-time accounting for task 0 */
    /* task 0 becomes the WM/desktop main loop (kmain -> desktop_run(), never
     * returns) — pinned to the BSP (M1531): its is_floor stays 0 so it competes
     * normally via CFS, but pin_core keeps it from ever migrating to an AP,
     * where the graphics/driver code it calls has never run and has not been
     * audited for it. Hit exactly that as a real in-guest crash (intermittent
     * page faults/GPFs right as the desktop launched) before adding this. */
    t->pin_core = mycore();
    t->affinity = ~0u;           /* pin_core already governs task 0; affinity is just the default (M1557) */
    current = t;
    task_t *idle = task_create(idle_loop, read_cr3(), 0);   /* the BSP's always-runnable floor (heap is up: kheap_init precedes sched_init); task_create already defaults its affinity to ~0u */
    idle->pin_core = mycore();                              /* never let another core pick this up (M1531) */
    idle->is_floor = 1;
    floor_task[mycore()] = idle;
    __atomic_store_n(&g_sched_ready, 1, __ATOMIC_RELEASE);   /* APs may now call task_register_ap_core (M1531) */
}

/* Called once by each AP (kernel/smp.c's ap_main, after gdt/idt are up) to
 * register ITS running context as a real scheduler participant, with its own
 * floor/idle task — the multi-core half of sched_init's BSP setup (M1531).
 * Until this runs for a given core, that core never appears in the ready
 * ring at all (matches the pre-M1531 world exactly: only the BSP scheduled). */
void task_register_ap_core(void) {
    while (!__atomic_load_n(&g_sched_ready, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    int c = mycore();
    task_t *self = kzalloc(sizeof(task_t));
    self->id = next_id++;
    self->state = TASK_RUNNING;
    self->weight = NICE0_WEIGHT;
    self->vruntime = g_min_vruntime;
    self->cr3 = read_cr3();          /* this AP is already running in the kernel's address space */
    self->pin_core = c;              /* this core's OWN native context (its ap_main loop / job-pool /
                                       * smp_thread draining) — pinned, not migratable: it's tied to THIS
                                       * core's own hardware execution, not portable work (M1531). Competes
                                       * normally (is_floor stays 0) against whatever else lands on this core. */
    self->affinity = ~0u;             /* pin_core already governs it; affinity is just the default (M1557) */
    fx_alloc(self);
    self->last_in = timer_ms();

    task_t *idle = kzalloc(sizeof(task_t));
    idle->id = next_id++;
    idle->state = TASK_READY;
    idle->entry = idle_loop;
    idle->weight = NICE0_WEIGHT;
    idle->vruntime = g_min_vruntime;
    idle->cr3 = read_cr3();
    idle->pin_core = c;               /* this core's OWN floor -- never picked by anyone else */
    idle->affinity = ~0u;
    idle->is_floor = 1;
    fx_alloc(idle);
    uint8_t *stack = kstack_alloc(STACK_SIZE);
    idle->stack_base = (uint64_t)stack;
    if (stack) {
        *(volatile uint64_t *)stack = STACK_CANARY;
        uint64_t top = ((uint64_t)stack + STACK_SIZE) & ~15ull;
        idle->kstack_top = top;
        uint64_t *sp = (uint64_t *)top;
        *--sp = (uint64_t)thread_trampoline;
        *--sp = 0; *--sp = 0; *--sp = 0; *--sp = 0; *--sp = 0; *--sp = 0;
        idle->rsp = (uint64_t)sp;
    }

    rq_lock_take();
    self->next = cur[0]->next;   /* insert both into the ring right after task 0 (any live anchor works) */
    cur[0]->next = self;
    idle->next = self->next;
    self->next = idle;
    rq_lock_give();

    cur[c] = self;
    active_cr3_arr[c] = self->cr3;
    floor_task[c] = idle;
}

task_t *task_create(void (*entry)(void), uint64_t cr3, void *proc) {
    return task_create_stack(entry, cr3, proc, STACK_SIZE);
}

/* Like task_create but with an explicit kernel-stack size — for tasks that run
 * deep/heavy code (e.g. the browser fetch worker, which does bignum/RSA crypto
 * that would overflow the default 16 KB stack). */
task_t *task_create_stack(void (*entry)(void), uint64_t cr3, void *proc, int stack_size) {
    task_t *t = kzalloc(sizeof(task_t));
    if (!t) return 0;                        /* OOM: fail cleanly rather than deref NULL */
    t->id = next_id++;
    t->entry = entry;
    t->state = TASK_READY;
    t->weight = NICE0_WEIGHT;   /* CFS: born at nice 0 (M1171) — must be non-zero before any vruntime charge */
    t->vruntime = g_min_vruntime;  /* start at the floor: don't dominate (vruntime 0) or starve */
    t->cr3 = cr3;             /* set BEFORE the ring insert: no startup race */
    t->proc = proc;

    fx_alloc(t);

    uint8_t *stack = kstack_alloc(stack_size);   /* guarded VA stack: an overflow faults in a guard page, not the heap (M1495) */
    if (!stack || !t->fxbuf) {               /* OOM on the stack or FP save area: don't build a bogus stack frame
                                              * (a NULL stack -> top at a wild low address -> triple-fault on first
                                              * switch-in) or run with no FP save (XMM/x87 corruption between tasks). */
        if (stack) kstack_free(stack, stack_size);
        if (t->fxbuf) kfree(t->fxbuf);
        kfree(t);
        return 0;
    }
    t->stack_base = (uint64_t)stack;
    *(volatile uint64_t *)stack = STACK_CANARY;   /* overflow tripwire at the stack's lowest address */

    /* Build the initial stack so the first switch-in "returns" into the
     * trampoline. The layout must mirror context_switch's pops:
     * (top) [trampoline][rbx][rbp][r12][r13][r14][r15] (rsp) */
    uint64_t top = ((uint64_t)stack + stack_size) & ~15ull;
    t->kstack_top = top;                   /* used as TSS rsp0 if this runs ring 3 */
    uint64_t *sp = (uint64_t *)top;
    *--sp = (uint64_t)thread_trampoline;   /* return address for `ret` */
    *--sp = 0;  /* rbx */
    *--sp = 0;  /* rbp */
    *--sp = 0;  /* r12 */
    *--sp = 0;  /* r13 */
    *--sp = 0;  /* r14 */
    *--sp = 0;  /* r15 */
    t->rsp = (uint64_t)sp;

    t->pin_core = -1;   /* an ordinary task: any core may run it (M1531) */
    t->affinity = ~0u;  /* and no self-imposed core restriction yet either (M1557) */

    /* Insert into the ring right after the current task. */
    uint64_t f = irq_save();
    rq_lock_take();
    t->next = current->next;
    current->next = t;
    rq_lock_give();
    irq_restore(f);
    return t;
}

/* Is `t` a valid competitive-pick candidate ON THIS CORE (M1531)? A floor/
 * idle task never competes (it's the last resort, checked separately); a
 * pinned task (pin_core>=0 — a core's own floor OR a genuinely core-affine
 * task like task 0/the desktop) may only be picked by its OWN core. Below
 * that, an ordinary task (pin_core<0) is further filtered by its own
 * user-facing affinity mask (M1557, sched_setaffinity) — defaults to
 * "any core" so this is a no-op for every task that never calls it. */
static inline int sched_eligible(task_t *t) {
    if (t->is_floor) return 0;
    if (t->pin_core >= 0) return t->pin_core == mycore();
    return (t->affinity >> mycore()) & 1;
}

/* Core switch — assumes interrupts already disabled (unchanged contract).
 * M1531: takes the cross-core rq_lock itself for the decision + commit
 * (ring walk, state changes, `current` reassignment), releasing it BEFORE the
 * cr3/TSS/FPU/context_switch tail below — a switch can leave this call not
 * returning for an arbitrary time, so holding a lock every OTHER core needs
 * across that would freeze their scheduling for the same span. Interrupts
 * stay disabled the whole time regardless (the caller's job, unchanged). */
static void switch_to_next(void) {
    rq_lock_take();
    task_t *prev = current;
    /* Stack-overflow tripwire: if prev overran its kernel stack to the base during
     * its slice, the canary there is clobbered — halt cleanly rather than run on
     * with a corrupted heap/task-ring (a silent, near-undebuggable failure). */
    if (prev->stack_base && *(volatile uint64_t *)prev->stack_base != STACK_CANARY) {
        interrupts_disable();
        kprintf("\n*** KERNEL STACK OVERFLOW (task %lu): canary at %p clobbered ***\n"
                "    a deep call chain overran the task's kernel stack; system halted.\n",
                (unsigned long)prev->id, (void *)prev->stack_base);
        for (;;) __asm__ volatile("cli; hlt");
    }
    uint64_t now = timer_ms();

    /* Charge prev for the slice it just ran BEFORE deciding (M1171): real time to
     * run_ms, and weighted time to vruntime, so the comparison below sees prev's
     * up-to-date cost (otherwise a still-running task's stale vruntime would let
     * it win forever). Done every call — including the keep-prev early return. */
    uint64_t slice = now - prev->last_in;
    prev->last_in = now;
    prev->run_ms += slice;
    if (!prev->is_floor) {
        uint64_t charge = slice * NICE0_WEIGHT / (prev->weight ? prev->weight : NICE0_WEIGHT);
        /* A sub-millisecond slice must STILL advance vruntime (M1912). timer_ms()
         * has millisecond granularity, so a task that yields faster than that --
         * exactly what every spin-then-yield lock in this kernel does
         * (ata_lock_take, blk_lock_take, ...) -- was charged ZERO and stayed
         * pinned at g_min_vruntime forever. CFS then always picked it over any
         * task even one unit ahead, so a lock HOLDER could be starved
         * indefinitely by its own waiters. Measured mid-deadlock:
         *   min_vr=1420 | id7 vr=1420 (spinning) id6 vr=1420 (spinning)
         *                | id0 vr=1430 READY, holding ata_lock, never picked
         * Charging a floor of 1 makes vruntime strictly increase per switch, so a
         * yield-spinner overtakes the holder within a few yields and the holder
         * runs. This is a fairness toll on voluntary yielding, which is correct:
         * a switch has real cost, and "yielded 10000 times" must not read as "used
         * no CPU". */
        if (charge == 0) charge = 1;
        prev->vruntime += charge;
    }
    if (prev->policy == SCHED_RR && prev->rt_ticks > 0) prev->rt_ticks--;   /* RR timeslice tick (M1172) */

    task_t *best = 0;
    /* --- Real-time classes first (M1172): the highest-priority runnable FIFO/RR
       task preempts the ENTIRE normal (CFS) class. Only if none are runnable do
       we fall through to the CFS pick — so with no RT task this is byte-for-byte
       the M1171 behavior. Any floor/idle task (M1531) is excluded exactly like
       the old single `idle_task` pointer check was, and a pinned task (task 0/
       the desktop, or a core's own floor) is only eligible on ITS OWN core —
       see sched_eligible().
       CRITICAL (M1531): TASK_RUNNING no longer means "the one task on the one
       core" — now up to N tasks are RUNNING at once, one per core. `u==prev`
       is allowed to match ONLY while it's STILL ACTUALLY RUNNING (this core's
       own incumbent, not yet switched out); every other candidate — including
       prev ITSELF if its caller already flipped it to BLOCKED/DEAD before
       this exact call (task_block/task_exit-style self-transitions) — must be
       TASK_READY. Getting this wrong two different ways, both hit as real
       in-guest bugs: (1) matching ANY `u==prev` unconditionally let a task
       that just blocked itself keep "winning" its own pick forever (it never
       actually switches away, so a real wake racing against it gets lost —
       surfaced as keystrokes silently dropped); (2) matching `u`'s state
       alone (RUNNING) let a DIFFERENT core's ACTIVELY EXECUTING task be
       stolen (loading a stale/zero rsp out from under it — a crash). Needs
       BOTH conditions together. --- */
    int top_rt = -1;
    for (task_t *u = prev->next; ; u = u->next) {
        if (sched_eligible(u) && ((u == prev && u->state == TASK_RUNNING) || u->state == TASK_READY)
            && u->policy != SCHED_OTHER && u->rt_priority > top_rt)
            top_rt = u->rt_priority;
        if (u == prev) break;
    }
    if (top_rt >= 0) {                          /* an RT task wants the CPU */
        int prev_top = (sched_eligible(prev) && (prev->state == TASK_RUNNING || prev->state == TASK_READY)
                        && prev->policy != SCHED_OTHER && prev->rt_priority == top_rt);
        if (prev_top && !(prev->policy == SCHED_RR && prev->rt_ticks <= 0)) {
            best = prev;                        /* incumbent keeps the CPU: FIFO always; RR within its quantum */
        } else {
            for (task_t *u = prev->next; ; u = u->next) {   /* next runnable RT task at top_rt (ring order => RR rotation) */
                if (sched_eligible(u) && ((u == prev && u->state == TASK_RUNNING) || u->state == TASK_READY)
                    && u->policy != SCHED_OTHER && u->rt_priority == top_rt) { best = u; break; }
                if (u == prev) break;
            }
            if (!best) best = prev;
            if (prev_top) prev->rt_ticks = RR_QUANTUM;                          /* rotated out: refill */
            if (best && best != prev && best->policy == SCHED_RR) best->rt_ticks = RR_QUANTUM;  /* fresh quantum on switch-in */
        }
    } else {
        /* CFS pick: the runnable, non-idle task with the smallest vruntime,
         * from the WHOLE shared ring — any eligible READY task may be picked
         * here regardless of which core it last ran on (M1531: this is the
         * actual cross-core migration point) — but never a task that's
         * RUNNING on a different core, and never prev itself unless it's
         * STILL running (see the CRITICAL note above). */
        task_t *t = prev;
        do {
            if (sched_eligible(t) && ((t == prev && t->state == TASK_RUNNING) || t->state == TASK_READY))
                if (!best || t->vruntime < best->vruntime) best = t;
            t = t->next;
        } while (t != prev);
        /* Advance the floor every call (even when we keep prev): it's the smallest
         * runnable vruntime, so a task that wakes mid-way clamps to HERE and can't
         * monopolize the CPU catching up to a long-running solo task (M1171). */
        if (best) g_min_vruntime = best->vruntime;
    }

    task_t *next;
    if (best == prev) { rq_lock_give(); return; }   /* prev is the most-deserving runnable -> keep it (no switch) */
    if (best) { next = best; }                  /* a different task has a smaller vruntime -> run it (maybe cross-core) */
    else {                                       /* nothing non-idle is runnable */
        if (prev->state == TASK_RUNNING || prev->state == TASK_READY)
            { rq_lock_give(); return; }         /* prev still runnable (e.g. the desktop) -> keep it */
        task_t *floor = floor_task[mycore()];
        if (!floor || prev == floor)
            { rq_lock_give(); return; }         /* no floor / already on it */
        next = floor;                           /* prev blocked/exited, nothing ready -> THIS core's floor */
    }

    /* CRITICAL (M1531): do NOT flip prev to TASK_READY here. That would make
     * it pickable by ANOTHER core immediately — but this core hasn't finished
     * with its stack/registers yet (the hardware tail below, then
     * context_switch itself, both still run ON prev's stack). Doing this too
     * early is exactly what let two cores end up running the same task's
     * stack at once — a real, repeatedly-hit, intermittently-shaped crash
     * (stack overflows/#UD/#GP landing somewhere in this tail) before this
     * fix. finish_switch() (called from the far side of context_switch, once
     * this core has genuinely moved on) does the READY transition instead. */
    int prev_was_running = (prev->state == TASK_RUNNING);
    if (!prev_was_running) prev->nvcsw++;   /* blocked/exited itself (its own caller already set state) => voluntary (M1150) */
    core_prev[mycore()] = prev_was_running ? prev : 0;   /* what finish_switch() must complete, if anything */

    next->state = TASK_RUNNING;
    if (next->ready_since) {                      /* leaving the run queue: charge the time it waited (M1148) */
        next->rq_wait_ms += now - next->ready_since;
        next->ready_since = 0;
    }
    current = next;
    g_nr_switches++;                              /* a real switch happened (next != prev guaranteed above) — /proc/stat ctxt (M1253) */

    next->last_in = now;                          /* stamp switch-in (prev was already charged above) */
    next->nswitch++;

    rq_lock_give();   /* decision + commit done; the hardware tail below is per-core-local (M1531) */

    /* switch address space if the next task lives in a different one. Safe to
     * do here: kernel code, this stack (heap), and the GDT/IDT/TSS are mapped
     * in every address space, so execution continues seamlessly. */
    if (next->cr3 && next->cr3 != active_cr3) {
        active_cr3 = next->cr3;
        load_cr3(next->cr3);
    }
    if (next->kstack_top)
        tss_set_rsp0(next->kstack_top);     /* traps from ring 3 land here */
    if (prev->fxbuf) fpu_store(prev);           /* preserve FP/SSE/AVX across the switch */
    if (next->fxbuf) fpu_load(next);
    load_fs_base(next->fs_base);                 /* restore the thread's TLS base (M1140) */
    context_switch(&prev->rsp, next->rsp);
    task_finish_switch();   /* runs once THIS exact call site is resumed later (M1531) */
}

/* Voluntarily give another ready task a turn (M1531: now also used by an AP's
 * own idle loop, kernel/smp.c's ap_main, to let a real — possibly ring-3 —
 * task run on that core). Self-contained: disables interrupts itself rather
 * than assuming the caller already did (unlike switch_to_next's internal
 * callers, which manage that explicitly around a state change). */
void schedule(void) {
    uint64_t f = irq_save();
    switch_to_next();
    irq_restore(f);
}

/* Preemption entry point, called from the timer IRQ. We're already in
 * interrupt context (IF clear), so we can switch directly. switch_to_next is a
 * no-op until sched_init runs (current == NULL) or when only one task exists. */
void sched_tick(void) {
    if (current)
        switch_to_next();
}

void task_yield(void) {
    uint64_t f = irq_save();
    switch_to_next();
    irq_restore(f);
}

/* Block the current task: it leaves the run rotation until task_wake() marks it
 * runnable. Interrupts are off across the state change + switch so a wakeup
 * can't be lost. */
void task_block(void) {
    uint64_t f = irq_save();
    rq_lock_take();
    current->wchan = (uint64_t)__builtin_return_address(0);   /* who we're blocking in, for /proc/sched WCHAN (M1166) */
    current->wake_at = 0;          /* not a timed sleep -> the timer scan must ignore it */
    current->state = TASK_BLOCKED;
    rq_lock_give();
    switch_to_next();               /* takes rq_lock itself */
    irq_restore(f);
}

/* Like task_block, but also wakeable by task_wake_sleepers() once timer_ms()
 * reaches `deadline_ms` (M1578) -- the two wake paths compose for free: a
 * real task_wake() call still works exactly as it does on a plain
 * task_block()'d task (it clears wake_at and marks READY, same either way),
 * and if the deadline passes first, task_wake_sleepers()'s own existing
 * "BLOCKED + nonzero wake_at + past due" check does the same. Deliberately
 * NOT implemented as task_block()'s new body (with task_block becoming a
 * thin `task_block_timeout(0)` wrapper): that would shift WCHAN's captured
 * return address to this function instead of task_block's own caller for
 * every ORDINARY (non-timed) blocker, an existing, tested /proc/sched
 * diagnostic this milestone has no reason to touch. A few duplicated lines
 * here is the safer trade. First caller: app_futex's FUTEX_WAIT timeout. */
void task_block_timeout(uint64_t deadline_ms) {
    uint64_t f = irq_save();
    rq_lock_take();
    current->wchan = (uint64_t)__builtin_return_address(0);
    current->wake_at = deadline_ms;
    current->state = TASK_BLOCKED;
    rq_lock_give();
    switch_to_next();
    irq_restore(f);
}

void task_wake(task_t *t) {
    uint64_t f = irq_save();
    rq_lock_take();
    if (t && t->state == TASK_BLOCKED) {
        t->wake_at = 0;            /* cancel any pending timed wake */
        t->state = TASK_READY;
        t->ready_since = timer_ms();   /* re-entered the run queue (M1148) */
        sched_place_wake(t);           /* clamp vruntime up to the floor: no head-start, no starvation (M1171) */
    }
    rq_lock_give();
    irq_restore(f);
}

/* Sleep the current task for `ms`, off-CPU, until the timer wakes it (M1079) —
 * the real, non-busy version of timer_wait(). Falls back to a HLT loop before
 * the scheduler is up. The deadline is recorded in wake_at; task_wake_sleepers()
 * (driven by the timer IRQ) flips us back to READY when it passes. */
void task_sleep_ms(uint64_t ms) {
    if (!current || current->pin_core >= 0) {       /* no scheduler / this core's own floor: busy-wait */
        uint64_t target = timer_ms() + ms;
        while (timer_ms() < target) __asm__ volatile("sti; hlt");
        return;
    }
    uint64_t f = irq_save();
    current->wchan = (uint64_t)__builtin_return_address(0);   /* the sleep's caller, for WCHAN (M1166) */
    current->wake_at = timer_ms() + ms;           /* 0 ms still parks until the next tick */
    current->state = TASK_BLOCKED;
    switch_to_next();                             /* yields; woken by the timer scan */
    irq_restore(f);
}

/* Called from the timer IRQ (interrupts already off): wake every task whose
 * timed-sleep deadline has passed. The ring is tiny, so a full scan per tick is
 * cheap; only BLOCKED tasks with a non-zero wake_at are sleepers. */
void task_wake_sleepers(void) {
    if (!current) return;
    rq_lock_take();
    uint64_t now = timer_ms();
    task_t *t = current;
    do {
        if (t->state == TASK_BLOCKED && t->wake_at && t->wake_at <= now) {
            t->wake_at = 0;
            t->state = TASK_READY;
            t->ready_since = now;       /* re-entered the run queue (M1148) */
            sched_place_wake(t);        /* clamp vruntime up to the floor (M1171) */
        }
        t = t->next;
    } while (t != current);
    rq_lock_give();
}

/* ---- load average (M1148) -------------------------------------------------
 * An EWMA of the RUN-QUEUE DEPTH, using the classic Linux fixed-point scheme
 * (FSHIFT=11, FIXED_1=2048), sampled every 5 s from the timer IRQ. The sample
 * is the number of RUNNABLE tasks right now — RUNNING or READY, with the idle
 * floor excluded — i.e. how many tasks want the CPU. This replaces the old
 * hardcoded /proc/loadavg stub ("0.00 0.00 0.00") with a figure that genuinely
 * climbs under contention (spawn N spinners -> the 1-min average approaches N)
 * and decays back toward the desktop's baseline when they exit. */
#define LOAD_FSHIFT  11
#define LOAD_FIXED_1 (1u << LOAD_FSHIFT)
#define LOAD_EXP_1   1884     /* 1/exp(5s/1min)  as a FIXED_1-scaled fraction */
#define LOAD_EXP_5   2014     /* 1/exp(5s/5min)  */
#define LOAD_EXP_15  2037     /* 1/exp(5s/15min) */
static uint64_t load_avg[3];      /* fixed-point 1/5/15-min averages */
static uint64_t load_next_ms;     /* next 5 s sample boundary */

/* Tasks that want the CPU right now: RUNNING or READY, idle floor excluded.
 * Walks the (tiny) ready ring; safe from the IRQ as task_wake_sleepers does. */
int task_runnable_count(void) {
    if (!current) return 0;
    rq_lock_take();
    int n = 0; task_t *t = current;
    do {
        if (!t->is_floor && (t->state == TASK_RUNNING || t->state == TASK_READY)) n++;
        t = t->next;
    } while (t != current);
    rq_lock_give();
    return n;
}

/* Update the EWMAs at most once per 5 s. Called every timer tick. */
void loadavg_sample(void) {
    uint64_t now = timer_ms();
    if (now < load_next_ms) return;
    load_next_ms = now + 5000;
    uint64_t active = (uint64_t)task_runnable_count() << LOAD_FSHIFT;
    static const uint64_t exp_[3] = { LOAD_EXP_1, LOAD_EXP_5, LOAD_EXP_15 };
    for (int i = 0; i < 3; i++)
        load_avg[i] = (load_avg[i] * exp_[i] + active * (LOAD_FIXED_1 - exp_[i])) >> LOAD_FSHIFT;
}

void task_loadavg(uint64_t out[3]) {
    out[0] = load_avg[0]; out[1] = load_avg[1]; out[2] = load_avg[2];
}

/* Set while the compositor's main thread is halted in idle_hlt(): the timer tick
 * that wakes it is then credited to idle rather than pinning that task at "busy". */
static volatile int g_in_hlt;
static volatile uint64_t g_hlt_idle_ms;

/* Per-core user/system ms (M1538): unlike task_cpu_times' per-TASK totals
 * (which can't say which core a migrated task's time was spent on), these
 * are tagged with mycore() at the exact instant of each timer tick -- a
 * property of the CORE right now, not something that needs to survive a
 * migration, so this is safe by construction (no per-core-state-outlives-
 * this-call hazard the way ecdsa.c's g_P/g_N/g_Pbar had, M1536). Exposed via
 * /proc/stat's per-core cpuN lines for real multi-core visibility. */
static uint64_t core_user_ms[MAX_SCHED_CPUS], core_sys_ms[MAX_SCHED_CPUS];

/* Charge the current task `ms` of CPU time to user or kernel mode, called from
 * the timer IRQ with user = (the interrupted frame was ring 3). Tick-sampled,
 * so coarse (one-tick granularity) — the standard getrusage utime/stime model
 * (M1150). The precise total CPU time stays in run_ms (switch_to_next). */
void task_cpu_tick(uint64_t ms, int user) {
    /* g_in_hlt is specifically the BSP-pinned compositor's own idle_hlt() flag
     * (see its own comment above) -- checking it unqualified used to be safe
     * only because this function was itself BSP-exclusive (called solely from
     * timer.c's PIT handler). Now that each AP's own LAPIC tick calls this too
     * (M1548, fixing utime_ms/stime_ms staying 0 forever for a task that
     * simply wasn't BSP-resident), an AP's tick landing while the BSP happens
     * to be idle-halted would otherwise get swallowed into g_hlt_idle_ms
     * instead of crediting that AP's actually-running task -- so this check
     * must stay scoped to the one core it actually describes. */
    if (mycore() == 0 && g_in_hlt) { g_hlt_idle_ms += ms; return; }
    if (!current) return;
    if (user) { current->utime_ms += ms; core_user_ms[mycore()] += ms; }
    else      { current->stime_ms += ms; core_sys_ms[mycore()]  += ms; }
}

/* Set the current task's nice level (-20..+19) and its CFS weight (M1171). A
 * higher nice => smaller weight => vruntime accrues faster => less CPU. */
int task_set_nice(int nice) {
    if (!current) return 0;
    if (nice < -20) nice = -20; if (nice > 19) nice = 19;
    current->nice = nice;
    current->weight = nice_to_weight(nice);
    return nice;
}
int task_get_nice(void) { return current ? current->nice : 0; }

/* Set the current task's scheduling class (M1172). SCHED_FIFO/RR are real-time
 * (rt_priority 1..99, clamped) and preempt the SCHED_OTHER/CFS class; switching
 * back to OTHER re-places it at the CFS floor so its frozen vruntime can't make
 * it dominate or starve. Returns 0, or -1 on a bad policy. */
int task_set_sched(int policy, int rt_priority) {
    if (!current) return -1;
    if (policy != SCHED_OTHER && policy != SCHED_FIFO && policy != SCHED_RR) return -1;
    if (policy == SCHED_OTHER) {
        current->policy = SCHED_OTHER;
        current->rt_priority = 0;
        if (current->vruntime < g_min_vruntime) current->vruntime = g_min_vruntime;
    } else {
        if (rt_priority < 1) rt_priority = 1; if (rt_priority > 99) rt_priority = 99;
        current->policy = policy;
        current->rt_priority = rt_priority;
        current->rt_ticks = RR_QUANTUM;
    }
    return 0;
}
/* sched_get_priority_max/min (M1589): the valid rt_priority range per policy --
 * the same 1..99 clamp task_set_sched already enforces above, just handed back
 * rather than silently applied. SCHED_OTHER has no rt_priority concept (always
 * 0 here, per task_set_sched's own SCHED_OTHER branch), matching real Linux's
 * own answer for it. */
int task_sched_get_priority_max(int policy) {
    if (policy == SCHED_FIFO || policy == SCHED_RR) return 99;
    if (policy == SCHED_OTHER) return 0;
    return -1;
}
int task_sched_get_priority_min(int policy) {
    if (policy == SCHED_FIFO || policy == SCHED_RR) return 1;
    if (policy == SCHED_OTHER) return 0;
    return -1;
}
/* sched_getscheduler/sched_getparam (M1591): the read side of task_set_sched,
 * never added when the setter shipped in M1172. Self-only, no target pid --
 * matching task_set_nice/task_set_sched/sched_setaffinity's own established
 * no-pid convention in this family (see sched_setaffinity's own comment
 * above). Both flatten their POSIX pointer-out-param to a plain scalar
 * return, the same simplification getpgid/getsid already use for a
 * single-int payload. */
int task_get_sched(void) { return current ? current->policy : -1; }
int task_get_sched_priority(void) { return current ? current->rt_priority : -1; }
/* sched_rr_get_interval (M1591): the SCHED_RR timeslice, as a real duration
 * rather than the internal tick count -- RR_QUANTUM is a fixed constant, not
 * per-task state, so this doesn't depend on (or need) a caller's own policy. */
void task_sched_rr_get_interval(long *sec, long *nsec) {
    uint64_t ms = (uint64_t)RR_QUANTUM * timer_tick_ms();
    *sec = (long)(ms / 1000);
    *nsec = (long)((ms % 1000) * 1000000);
}

/* Clamp a requested/reported affinity mask to bits that name an actually-
 * online core — MAX_SCHED_CPUS is the scheduler's own hard ceiling (mycore()
 * wraps modulo it), so this also protects the `1u << nc` below from a
 * shift-by->=32 UB if smp_cpu_count were ever (incorrectly) larger (M1557). */
static inline uint32_t online_mask(void) {
    int nc = smp_cpu_count;
    if (nc < 1) nc = 1;
    if (nc > MAX_SCHED_CPUS) nc = MAX_SCHED_CPUS;
    return (uint32_t)((1u << nc) - 1);
}

/* Restrict the current task to a subset of online cores (M1557, POSIX
 * sched_setaffinity — self-only, matching task_set_nice/task_set_sched's own
 * no-target-pid convention above). Rejects a mask that names no online core
 * at all (would make the task permanently unschedulable). If the caller's
 * OWN core just became disallowed, force it off NOW: sched_eligible() only
 * re-filters a task against its mask when picking a candidate to switch TO,
 * so without an explicit yield here the now-ineligible task would simply
 * keep running on the forbidden core for as long as it keeps winning CFS
 * picks (i.e. indefinitely) — the mask would be set but never actually take
 * effect on this core. */
int task_set_affinity(uint32_t mask) {
    if (!current) return -1;
    mask &= online_mask();
    if (!mask) return -1;
    current->affinity = mask;
    if (!((mask >> mycore()) & 1)) task_yield();
    return 0;
}
uint32_t task_get_affinity(void) {
    if (!current) return 0;
    return current->affinity & online_mask();
}

/* Suspend a task (it leaves the run rotation until task_cont). Only a runnable,
 * non-current task — never stop ourselves (that needs a yield) or a blocked task
 * (it's already off-CPU; STOPPING it would lose the BLOCKED->READY wake path). */
void task_stop(task_t *t) {
    uint64_t f = irq_save();
    rq_lock_take();
    if (t && t != current && (t->state == TASK_READY || t->state == TASK_RUNNING))
        t->state = TASK_STOPPED;
    rq_lock_give();
    irq_restore(f);
}

/* Resume a STOPPED task. */
void task_cont(task_t *t) {
    uint64_t f = irq_save();
    rq_lock_take();
    if (t && t->state == TASK_STOPPED) {
        t->state = TASK_READY;
        sched_place_wake(t);            /* a long-stopped task rejoins at the floor, not dominating (M1171) */
    }
    rq_lock_give();
    irq_restore(f);
}

void task_exit(void) {
    irq_save();                 /* disable; this task is ending, never restore */
    rq_lock_take();
    task_t *dead = current;
    dead->state = TASK_DEAD;

    /* Unlink from the ring. */
    task_t *prev = dead->next;
    while (prev->next != dead)
        prev = prev->next;
    prev->next = dead->next;

    /* Pick a replacement (M1531): NOT just "whatever's next in the ring" —
     * that could be a DIFFERENT core's pinned floor task, which only that
     * core may ever run. Prefer any unpinned READY task (smallest vruntime,
     * same CFS shape as switch_to_next) — NEVER a RUNNING one: unlike
     * switch_to_next, `dead` has no "stay put" exception (it's exiting), so
     * TASK_RUNNING here can only mean "executing on a different core right
     * now," which must never be picked (see switch_to_next's CRITICAL note).
     * Fall back to THIS core's own floor if nothing else is ready. */
    task_t *next = 0;
    task_t *t = dead->next;
    do {
        if (sched_eligible(t) && t->state == TASK_READY)
            if (!next || t->vruntime < next->vruntime) next = t;
        t = t->next;
    } while (t != dead->next);
    if (!next) next = floor_task[mycore()];

    next->state = TASK_RUNNING;
    current = next;
    next->last_in = timer_ms();   /* stamp switch-in so its CPU time isn't over-counted from a stale last_in */
    next->nswitch++;
    rq_lock_give();

    /* Load next's address space + kernel stack BEFORE switching, mirroring
     * switch_to_next. Otherwise the dead task's CR3 stays loaded under `next`,
     * which is unsafe the moment that CR3 is reclaimed (vmm_destroy on an app
     * exit) — `next` would be running on freed page tables. With this, an app's
     * CR3 is never the active one by the time the WM reaps it. */
    if (next->cr3 && next->cr3 != active_cr3) {
        active_cr3 = next->cr3;
        load_cr3(next->cr3);
    }
    if (next->kstack_top)
        tss_set_rsp0(next->kstack_top);
    if (next->fxbuf) fpu_load(next);             /* the dead task's FP state is discarded */
    load_fs_base(next->fs_base);                 /* restore the thread's TLS base (M1140) */
    context_switch(&dead->rsp, next->rsp);   /* dead->rsp save is discarded */
    /* unreachable */
}

/* Free a dead task's kernel stack and its task_t. ONLY safe on a task that has
 * exited (state==TASK_DEAD), been unlinked from the ready ring (task_exit does
 * that), and is no longer executing on its stack — i.e. reaped from a DIFFERENT
 * task's context. A task can't free its own stack (it's running on it), so a
 * separate reaper calls this once the task is off-CPU. Observing TASK_DEAD from
 * another task is sufficient proof of off-CPU: task_exit sets DEAD with
 * interrupts disabled and only leaves that region via its final context_switch,
 * so no other task can run (and observe DEAD) while this task still executes. */
void task_free(task_t *t) {
    if (!t) return;
    if (t->stack_base) kstack_free((void *)t->stack_base, t->kstack_top - t->stack_base);
    if (t->fxbuf) kfree(t->fxbuf);
    kfree(t);
}

int task_current_id(void) {
    return current ? current->id : 0;        /* NULL before sched_init (matches task_snapshot/sched_tick's guard) */
}

task_t *task_self(void) {
    return current;
}

/* Temporarily pin the CALLING task to the core it's running on RIGHT NOW, for
 * code that keeps per-core global state across a call long enough to risk a
 * preemption (M1536): task_pin_here()'s caller can be migrated to a different
 * core mid-call by the ordinary preemptive scheduler (M1531/M1532) exactly
 * like any other task, UNLIKE an smp_parallel_for job (which runs start-to-
 * finish on one core by that primitive's own contract) -- ecdsa.c's per-core
 * field-prime/Barrett-context slots (curP/curN/curPbar) assumed the latter
 * but are reachable from an ordinary ring-3 syscall (sys_https), where only
 * this explicit pin actually guarantees it. Returns the task's PREVIOUS
 * pin_core (restore it with task_unpin when done); nests correctly with an
 * already-pinned caller (e.g. task 0) since it just saves/restores the value. */
int task_pin_here(void) {
    uint64_t f = irq_save();
    rq_lock_take();
    int saved = current->pin_core;
    current->pin_core = mycore();
    rq_lock_give();
    irq_restore(f);
    return saved;
}
void task_unpin(int saved_pin_core) {
    uint64_t f = irq_save();
    rq_lock_take();
    current->pin_core = saved_pin_core;
    rq_lock_give();
    irq_restore(f);
}


/* The calling task's current vruntime — exposed so the boot self-test below can
 * assert the M1912 fix directly instead of inferring it from a flaky hang. */
uint64_t task_vruntime_self(void) { return current ? current->vruntime : 0; }

/* Boot self-test (M1912): a task that yields FASTER than the millisecond clock
 * must still accrue vruntime. If it does not, CFS pins it at g_min_vruntime and
 * it can starve any task even one unit ahead — which is exactly how a spin-then-
 * yield lock waiter (ata_lock_take) starved the task HOLDING the lock, wedging
 * every disk user in the system. Deterministic: no timing, no hang required. */
void sched_selftest(void) {
    uint64_t a = task_vruntime_self();
    for (int i = 0; i < 64; i++) task_yield();
    uint64_t b = task_vruntime_self();
    uint64_t d = b - a;
    if (d >= 64)
        kprintf("[ ok ] sched: 64 sub-millisecond yields advanced vruntime by %lu "
                "(>=64: a yield-spinner cannot starve a lock holder)\n", (unsigned long)d);
    else
        kprintf("[FAIL] sched: 64 fast yields advanced vruntime by only %lu (need >=64) "
                "— yield-spinners accrue nothing and WILL starve other runnable tasks\n",
                (unsigned long)d);
}

int task_count(void) {
    if (!current) return 0;                  /* ring not built yet */
    rq_lock_take();
    int n = 0;
    task_t *t = current;
    do { if (t->state != TASK_DEAD) n++; t = t->next; } while (t != current);
    rq_lock_give();
    return n;
}

/* Walk the ready ring (uninterruptibly — it's shared with the scheduler) and
 * record each task for `ps`. */
int task_snapshot(task_info_t *out, int max) {
    uint64_t f = irq_save();
    rq_lock_take();
    int n = 0;
    if (current) {
        task_t *t = current;
        uint64_t now = timer_ms();
        do {
            if (n >= max) break;
            out[n].id = t->id; out[n].state = (int)t->state; out[n].proc = t->proc;
            uint64_t rm = t->run_ms;
            if (t->state == TASK_RUNNING) rm += now - t->last_in;   /* include the in-progress slice */
            out[n].run_ms = rm; out[n].nswitch = t->nswitch; out[n].rq_wait_ms = t->rq_wait_ms;
            out[n].wchan = (t->state == TASK_BLOCKED) ? t->wchan : 0;   /* only meaningful while blocked (M1166) */
            out[n].nice = t->nice;                                       /* CFS nice level (M1171) */
            out[n].policy = t->policy; out[n].rt_priority = t->rt_priority;   /* scheduling class (M1172) */
            n++; t = t->next;
        } while (t != current);
    }
    rq_lock_give();
    irq_restore(f);
    return n;
}

/* Total ms all cores' floor/idle tasks have run, SUMMED (M1531: there's now
 * one per core, not a single global) — the system's idle time, for
 * `/proc/sched`/`/proc/stat`. */
uint64_t task_idle_ms(void) {
    uint64_t rm = 0;
    uint64_t now = timer_ms();
    for (int i = 0; i < MAX_SCHED_CPUS; i++) {
        task_t *ft = floor_task[i];
        if (!ft) continue;
        rm += ft->run_ms;
        if (ft->state == TASK_RUNNING) rm += now - ft->last_in;
    }
    return rm;
}

/* Halt until the next interrupt, crediting the slept time to idle. The compositor's
 * main loop calls this on each idle pass; without it the waking timer tick is charged
 * to that (always-running) task and /proc/stat's CPU would stick at 100%. (M1361) */
void idle_hlt(void) {
    g_in_hlt = 1;
    __asm__ volatile("sti; hlt");
    g_in_hlt = 0;
}
uint64_t task_idle_hlt_ms(void) { return g_hlt_idle_ms; }

/* --- /proc/stat aggregates (M1253) --- */
uint64_t task_ctxt_count(void)    { return g_nr_switches; }      /* total context switches since boot */
uint64_t task_total_spawned(void) { return (uint64_t)next_id; }  /* cumulative tasks ever created = "processes" */

/* One core's user/system/idle ms (M1538) — /proc/stat's per-core `cpuN` lines
 * (gen_stat sums these across cores for the aggregate `cpu` line too, replacing
 * the old task_cpu_times' "sum only currently-live tasks" approximation with a
 * real one). `core` is a masked index (0..MAX_SCHED_CPUS-1), matching mycore()'s
 * range. Idle mirrors task_idle_ms()'s per-core term (that core's OWN floor
 * task's run_ms, live-updated if it's RUNNING right now) plus, for core 0
 * only, the BSP-pinned compositor's own idle_hlt() time (g_hlt_idle_ms is
 * BSP-specific by construction — see idle_hlt's caller, desktop.c's task 0). */
void task_percore_times(int core, uint64_t *user_ms, uint64_t *sys_ms, uint64_t *idle_ms) {
    if (core < 0 || core >= MAX_SCHED_CPUS) { if (user_ms) *user_ms = 0; if (sys_ms) *sys_ms = 0; if (idle_ms) *idle_ms = 0; return; }
    if (user_ms) *user_ms = core_user_ms[core];
    if (sys_ms)  *sys_ms  = core_sys_ms[core];
    if (idle_ms) {
        uint64_t rm = 0;
        task_t *ft = floor_task[core];
        if (ft) {
            rm = ft->run_ms;
            if (ft->state == TASK_RUNNING) rm += timer_ms() - ft->last_in;
        }
        if (core == 0) rm += g_hlt_idle_ms;
        *idle_ms = rm;
    }
}

/* Count of blocked tasks (excl. any core's idle floor) — /proc/stat procs_blocked.
 * The runnable count is the existing task_runnable_count() (M1148). */
int task_blocked_count(void) {
    int b = 0;
    if (current) {
        rq_lock_take();
        task_t *t = current;
        do { if (!t->is_floor && t->state == TASK_BLOCKED) b++;
             t = t->next; } while (t != current);
        rq_lock_give();
    }
    return b;
}
