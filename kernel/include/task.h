/* task.h — kernel threads + round-robin scheduler. */
#pragma once
#include <stdint.h>

typedef enum { TASK_READY, TASK_RUNNING, TASK_BLOCKED, TASK_DEAD, TASK_STOPPED } task_state_t;

struct registers;   /* (interrupts.h) — the trap frame, captured for /proc/<pid>/regs */

typedef struct task {
    uint64_t      rsp;        /* saved stack pointer — MUST be the first field */
    struct task  *next;       /* circular ready-ring link */
    void        (*entry)(void);
    uint64_t      stack_base;
    uint64_t      kstack_top;  /* TSS rsp0 for this task (ring3->ring0 traps)  */
    uint64_t      cr3;         /* address space (0 = use the kernel's)         */
    void         *proc;        /* opaque per-task data (userspace app, if any) */
    int           id;
    task_state_t  state;
    uint8_t      *fxbuf;       /* FXSAVE area (512B + slack, aligned to 16 at use) */
    char         name[16];     /* prctl(PR_SET_NAME): what the THREAD calls itself (M2014) */
    uint64_t      run_ms;      /* total ms this task has been RUNNING (CPU time)   */
    uint64_t      last_in;     /* timer_ms() when it last became `current`         */
    uint64_t      nswitch;     /* times it has been scheduled in (context switches) */
    uint64_t      utime_ms;    /* CPU time charged in user mode (ring 3), tick-sampled (getrusage, M1150) */
    uint64_t      stime_ms;    /* CPU time charged in kernel mode (ring 0), tick-sampled (M1150) */
    uint64_t      nvcsw;       /* voluntary context switches: it blocked/yielded (M1150) */
    uint64_t      nivcsw;      /* involuntary context switches: it was preempted (M1150) */
    uint64_t      rq_wait_ms;  /* total ms spent READY-but-not-running (run-queue wait, /proc/sched) (M1148) */
    uint64_t      ready_since; /* timer_ms() when it last entered the run queue; 0 = not waiting (M1148) */
    uint64_t      wchan;       /* kernel PC where it last blocked (task_block/sleep), for /proc/sched WCHAN (M1166) */
    uint64_t      vruntime;    /* CFS virtual runtime: weighted CPU consumed; the scheduler runs the smallest (M1171) */
    uint32_t      weight;      /* CFS weight from nice (NICE0_WEIGHT=1024); vruntime += slice*1024/weight (M1171) */
    int           nice;        /* -20..+19; lower = more CPU (M1171) */
    int           policy;      /* SCHED_OTHER (CFS) / SCHED_FIFO / SCHED_RR; RT classes preempt OTHER (M1172) */
    int           rt_priority; /* 1..99 for FIFO/RR; higher preempts lower (0 for OTHER) (M1172) */
    int           rt_ticks;    /* SCHED_RR: timeslice ticks left before rotating among equal-priority RR tasks (M1172) */
    uint64_t      wake_at;     /* if BLOCKED via task_sleep_ms: timer_ms() deadline (0 = not a timed sleep) */
    int           off_cpu;     /* a DEAD task has finished its final context_switch and is no longer
                                 * executing on its own kernel stack. task_exit sets TASK_DEAD and then
                                 * RELEASES THE RUN-QUEUE LOCK before switching away -- so between those
                                 * two points the task is "dead" and still running, and its final
                                 * context_switch still WRITES to its own task_t (saving rsp). A reaper on
                                 * another core that freed it on state alone corrupted whatever memory the
                                 * stack and task_t were handed to next: intermittent, and it looked like
                                 * wild-pointer faults inside whichever ring-3 program got the pages.
                                 * Set by the task that runs NEXT on that core. (M1961) */
    /* How deep this TASK is inside app_fault_handle. Per-task, not per-core:
     * the fault path enables interrupts to read from disk, so a core can be
     * running several tasks' faults at once and a per-core counter reads their
     * sum as one recursion. (M1992) */
    int           fault_depth;
    int           wake_pending; /* a task_wake() arrived while this task was still RUNNING, i.e. in the
                                 * window between deciding to block and actually blocking. The next
                                 * task_block() consumes it instead of sleeping. Without this the wake is
                                 * silently DROPPED (task_wake only acts on an already-BLOCKED task) and
                                 * the task sleeps forever -- the classic lost wakeup. Rare with one
                                 * blocking caller per process; constant once real threads park several
                                 * of them on a futex at once (M1959). */
    struct registers *uframe;  /* most recent ring-3 trap frame (for /proc/<pid>/regs); valid while stopped (M1119) */
    struct registers *start_frame;  /* a thread's initial ring-3 frame: iret'd to once at startup, then freed (M1138) */
    uint64_t      fs_base;     /* per-thread %fs base for TLS; 0 = unused (restored on switch, M1140) */
    uint64_t      robust;      /* userspace robust_t* (held robust locks); walked on exit (M1141) */
    uint64_t      clear_child_tid;  /* set_tid_address: zeroed + FUTEX_WAKE'd on exit (pthread_join) (M1226) */
    /* PER-THREAD SIGNAL STATE (M2075).
     *
     * All of this used to live in struct app, i.e. once per PROCESS, and every
     * field of it is per-thread by definition:
     *
     *   - pthread_sigmask is a THREAD's mask. One shared mask means a thread
     *     blocking a signal blocks it for its siblings too.
     *   - sigaltstack is a THREAD's alternate stack.
     *   - `in` and `saved` are the interrupted context. ONE slot, shared by
     *     every thread: two threads taking signals at once overwrite each
     *     other's saved registers, and the second sigreturn restores the
     *     first thread's rip into the second thread. That is a jump to an
     *     address nothing computed -- we saw rip=0x1e, an instruction fetch
     *     at offset 30 of the first page.
     *   - tkill(tid) could not be honoured at all: the pending bit had nowhere
     *     thread-shaped to go, so it was raised on the process and delivered
     *     to whichever thread next returned to ring 3.
     *
     * The last one is why JavaScriptCore's heap was corrupt. It suspends
     * threads for a collection by pthread_kill-ing each one and having the
     * handler record ITS OWN registers; the collector then scans from that
     * thread's stack pointer. Deliver the signal to the wrong thread and the
     * wrong thread's registers are recorded as the target's, so the scan
     * starts from an unrelated stack pointer, misses live roots, and the
     * collector frees objects that are still referenced.
     *
     * `sig_pending` here is the THREAD-DIRECTED set (tkill/tgkill/pthread_kill).
     * Process-directed signals still land in struct app's shared set and are
     * taken by whichever thread does not block them, exactly as on Linux.
     *
     * `sig_saved` is a `struct registers *`, allocated on first delivery --
     * most threads never take a signal, and 200 bytes times every thread of
     * every process is not worth reserving for that. */
    uint64_t      sig_pending;      /* thread-directed, not yet delivered */
    uint64_t      sig_blocked;      /* pthread_sigmask */
    void         *sig_saved;        /* struct registers *: the pre-handler context */
    uint64_t      sig_uctx;         /* SA_SIGINFO: user address of the delivered mcontext */
    uint64_t      sig_alt_base, sig_alt_size;
    uint64_t      sig_q_value;      /* si_value for the signal being delivered */
    int           sig_q_code;       /* si_code  for the signal being delivered */
    int           sig_in;           /* 1 while this thread runs a handler */
    int           pin_core;    /* CPU AFFINITY (M1531): -1 = may run on any core; >=0 = the ONE core
                                 * (APIC id & 15) allowed to run this task. Used for each core's own
                                 * floor/idle task (must never migrate) AND for task 0 (the kernel's own
                                 * boot-context task, which becomes the WM/desktop main loop via
                                 * desktop_run() — pinned to the BSP because the graphics/driver code it
                                 * calls has never been audited for running anywhere else). */
    int           is_floor;    /* 1 = this is a core's fallback/idle task: excluded from normal CFS/RT
                                 * competition, run ONLY when nothing else on its core is ready. A pinned
                                 * (pin_core>=0) task that is NOT a floor task (e.g. task 0) still competes
                                 * normally via CFS on its one allowed core (M1531). */
    uint32_t      affinity;    /* USER-FACING CPU affinity mask (M1557, sched_setaffinity): bit i = may
                                 * run on core i. Independent of pin_core (that's an internal hard single-
                                 * core pin for floor tasks/task 0; this is the general POSIX-style subset
                                 * a task can restrict ITSELF to). Only consulted when pin_core<0 — every
                                 * ordinary task_create_stack task starts with all bits set (any core). */
} task_t;

void    sched_init(void);                  /* adopt the current context as task 0 */
void    task_register_ap_core(void);       /* each AP: join the shared scheduler with its own floor task (M1531) */
/* Complete the deferred post-switch cleanup (M1531 — marks whoever this core
 * just switched AWAY from as READY, now that this core is truly off its
 * stack). MUST be the first thing ANY brand-new task's entry trampoline
 * calls — task.c's own thread_trampoline does; kernel/app.c has three more
 * (app_trampoline/fork_child_trampoline/thread_trampoline) that must too, or
 * whichever task got preempted to start this one is never marked READY
 * again — permanently stuck, not crashed. Hit exactly that as a real
 * in-guest hang (boot never got past a fault-and-terminate) before adding
 * the missing calls. */
void    task_finish_switch(void);
/* Spawn a task. cr3 = address space (0 for the kernel's); proc = opaque data.
 * Both are set before the task can be scheduled (no startup race). */
task_t *task_create(void (*entry)(void), uint64_t cr3, void *proc);
task_t *task_create_stack(void (*entry)(void), uint64_t cr3, void *proc, int stack_size);
task_t *task_create_stack_suspended(void (*entry)(void), uint64_t cr3, void *proc, int stack_size);   /* born TASK_STOPPED: task_cont it once FPU/TLS are copied (M2006) */
void    schedule(void);                    /* switch to the next ready task */
void    task_yield(void);                  /* voluntarily give up the CPU */
void    task_exit(void);                   /* end the current thread (no return) */
void    task_free(task_t *t);              /* free a DEAD, unlinked, off-CPU task (reaper only) */
int     task_current_id(void);
task_t *task_self(void);                   /* the currently running task */
/* Pin the calling task to its CURRENT core until task_unpin (M1536): for code
 * that keeps per-core global state across a call long enough to risk a
 * preemption-then-migration (the ordinary scheduler, unlike smp_parallel_for,
 * offers no "runs start-to-finish on one core" guarantee). Returns the prior
 * pin_core to restore; nests correctly with an already-pinned caller. */
int     task_pin_here(void);
void    task_unpin(int saved_pin_core);
void    task_set_fs_base(uint64_t b);
void    task_copy_tls(task_t *dst, task_t *src);
uint64_t task_fs_base(void);   /* fork: the child inherits the parent's %fs (TLS) base + robust list (M1949) */      /* set the current thread's %fs (TLS) base (M1140) */
void    task_set_robust(uint64_t r);       /* register the current thread's robust-futex list (M1141) */
uint64_t task_robust(void);                /* the current thread's robust-list ptr (0 = none) (M1141) */
void    task_block(void);                  /* block current task until woken */
void    task_block_timeout(uint64_t deadline_ms);  /* like task_block, but also woken by the timer at deadline_ms (M1578) */
void    task_wake(task_t *t);              /* mark a blocked task runnable again */
static inline task_state_t task_state_of(task_t *t) { return t->state; }   /* never wake a DEAD task (M1990) */
void    task_sleep_ms(uint64_t ms);        /* sleep the current task off-CPU until the timer wakes it */
void    task_wake_sleepers(void);          /* timer IRQ: wake tasks whose sleep deadline passed */
void    task_set_name(const char *n);      /* record prctl(PR_SET_NAME) for the current thread (M2014) */
const char *task_name_of(task_t *t);       /* ...and read it back; "" if the thread never named itself */
uint64_t task_fs_base_live_value(void);                                  /* the CPU's real FS base, read straight from the MSR (M2013) */
void    task_fs_base_live(uint64_t *live, uint64_t *cached, int *core);  /* the CPU's real FS base vs what we think we loaded (M2013) */
void    task_fs_base_last(int *tid, uint64_t *seq, uint64_t *now);       /* WHO last wrote this core's FS_BASE, and when (M2089) */
uint64_t task_nswitch_of(task_t *t);                                     /* has this task ever been switched in? (M2089) */
void    task_copy_fpu(task_t *dst, task_t *src);   /* clone src's live FP/SSE state into dst (fork) */
struct registers *task_uframe(task_t *t);  /* the task's most recent ring-3 trap frame, or 0 (M1119) */
void    task_stop(task_t *t);              /* suspend another task (READY/RUNNING -> STOPPED); not self */
void    task_report_why_idle(task_t *t);   /* state+ring+affinity, for a stall dump (M2039) */
int     task_off_stack(task_t *t);         /* has it left its kernel stack, so a reaper may free it? (M2025) */
int     task_retire_stopped(task_t *t);    /* unlink a STOPPED task from the ring so it can be freed (M2025) */
void    task_cont(task_t *t);              /* resume a STOPPED task */
int     task_count(void);
uint64_t task_vruntime_self(void);   /* current task's CFS vruntime (M1912 self-test) */
void     sched_selftest(void);       /* boot-time: fast yields must advance vruntime (M1912) */                  /* number of live tasks */

/* A snapshot of one task, for `ps` and `/proc/sched`. */
typedef struct { int id; int state; void *proc; uint64_t run_ms; uint64_t nswitch; uint64_t rq_wait_ms; uint64_t wchan; int nice; int policy; int rt_priority; } task_info_t;
int     task_snapshot(task_info_t *out, int max);   /* fill out[]; returns count */
uint64_t task_idle_ms(void);                         /* ms the idle task has run (system idle time) */
uint64_t task_idle_hlt_ms(void);                     /* ms the main thread spent halted = idle (M1361) */
void     idle_hlt(void);                             /* halt until an IRQ, crediting the slept time to idle (M1361) */
int     task_runnable_count(void);   /* tasks wanting the CPU now (RUNNING|READY, idle excluded) (M1148) */
uint64_t task_ctxt_count(void);                      /* total context switches since boot — /proc/stat ctxt (M1253) */
uint64_t task_total_spawned(void);                   /* cumulative tasks ever created — /proc/stat processes (M1253) */
void     task_percore_times(int core, uint64_t *user_ms, uint64_t *sys_ms, uint64_t *idle_ms);  /* one core's own ms; sum across cores for /proc/stat's aggregate (M1538) */
int     task_blocked_count(void);                    /* blocked tasks (idle excluded) — /proc/stat procs_blocked (M1253) */
void    loadavg_sample(void);        /* called each timer tick; updates the EWMA once per 5 s (M1148) */
void    task_loadavg(uint64_t out[3]); /* fixed-point (FSHIFT=11) 1/5/15-min load averages (M1148) */
void    task_cpu_tick(uint64_t ms, int user);  /* timer: charge current task ms of user/kernel CPU time (M1150) */
int     task_set_nice(int nice);     /* set the current task's nice (-20..19) -> CFS weight; returns the clamped nice (M1171) */
int     task_get_nice(void);         /* the current task's nice (M1171) */
int     task_set_sched(int policy, int rt_priority);   /* set the current task's scheduling class (SCHED_*); 0/-1 (M1172) */
int     task_sched_get_priority_max(int policy);       /* the valid rt_priority ceiling for a policy; -1 on a bad policy (M1589) */
int     task_sched_get_priority_min(int policy);       /* the valid rt_priority floor for a policy; -1 on a bad policy (M1589) */
int     task_get_sched(void);                          /* the caller's own scheduling policy; -1 if unset (M1591) */
int     task_get_sched_priority(void);                 /* the caller's own rt_priority (0 for SCHED_OTHER); -1 if unset (M1591) */
void    task_sched_rr_get_interval(long *sec, long *nsec);  /* the SCHED_RR timeslice as a real duration (M1591) */
int      task_set_affinity(uint32_t mask);   /* restrict the current task to a subset of online cores; 0/-1 (M1557) */
uint32_t task_get_affinity(void);            /* the current task's affinity mask, clamped to online cores (M1557) */

/* Called from the timer IRQ to preempt the running thread (no-op until the
 * scheduler is initialized and there's more than one task). */
void    sched_tick(void);
