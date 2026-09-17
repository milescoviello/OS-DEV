/*
 * timer.c — the Programmable Interval Timer (PIT), our system heartbeat.
 *
 * The PIT has a fixed input clock of 1193182 Hz. We program channel 0 with a
 * 16-bit "divisor": it counts the input clock down and raises IRQ0 each time it
 * hits zero. So output frequency = 1193182 / divisor. Pick the divisor for the
 * Hz you want.
 *
 * Why we care: a steady, periodic interrupt is the basis of timekeeping,
 * sleeping, and — crucially — *preemptive* multitasking (M7), where the timer
 * interrupt is what yanks the CPU away from a running task.
 */
#include "timer.h"
#include "vmm.h"   /* vmm_tlb_discharge: pay any deferred shootdown debt on the tick (M2065) */
#include "watchdog.h"
#include "interrupts.h"
#include "io.h"
#include "task.h"
#include "audio.h"
#include "profile.h"
#include "app.h"
#include "vdso.h"
#include "console.h"   /* kprintf, for the one calibration line (M2114) */

#define PIT_CH0_DATA 0x40
#define PIT_COMMAND  0x43
#define PIT_FREQUENCY 1193182u

static volatile uint64_t ticks;
static uint32_t          tick_hz = 100;   /* IRQ0 frequency, set by timer_init */
static uint32_t          tick_ms = 10;    /* ms per tick (1000/hz), for CPU-time accounting (M1150) */

/* A MONOTONIC CLOCK THAT MOVES IN 10 ms STEPS IS NOT A CLOCK A BROWSER CAN USE
 * (M2114).
 *
 * The PIT runs at 100 Hz, so timer_ms() -- which is what clock_gettime(2)
 * answers from -- advanced in TEN MILLISECOND JUMPS, while clock_getres(2)
 * claimed one millisecond. Ten milliseconds is coarser than a 60 Hz frame
 * interval (16.7 ms), so every duration Gecko measures quantises to 0 or 10,
 * and a refresh driver that asks "has enough time passed to draw" gets an
 * answer with no information in it.
 *
 * The TSC has the resolution; what it lacks is a known frequency and a
 * guarantee of not drifting. So do not build a clock out of it -- ANCHOR it.
 * The PIT tick count stays the authority for whole ticks and the TSC only
 * fills in the fraction SINCE the last tick, clamped so it can never reach the
 * next one. That is monotonic by construction, cannot drift however wrong the
 * calibration is, and degrades to exactly the old behaviour if the TSC is
 * unusable. */
static uint64_t g_tsc_per_tick;           /* 0 = not calibrated: fall back to whole ticks */
static uint64_t g_ns_per_cycle_q16;       /* nanoseconds per TSC cycle, 16.16 fixed point */
static volatile uint64_t g_tick_tsc;      /* TSC at the last PIT tick */

static inline uint64_t rdtsc_now(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static void timer_handler(struct registers *r) {
    /* PAY ANY TLB DEBT FIRST (M2065). A shootdown whose IPI this core missed
     * leaves a per-core flag set rather than cancelling it, and this tick --
     * 100 times a second, on every core -- is the backstop that guarantees the
     * flush actually happens. Before anything else in the handler, because the
     * handler itself can touch a task's memory. */
    vmm_tlb_discharge();
    ticks++;
    g_tick_tsc = rdtsc_now();   /* the anchor for sub-tick time (M2114) */
    watchdog_pet();        /* pet the HW watchdog (no-op unless armed) — a wedge that stops this IRQ lets it reset (M1881) */
    vdso_tick(ticks);      /* refresh the userspace vDSO time page (syscall-free clock_gettime, M1111) */
    prof_tick(r->rip, r->cs);  /* sampling profiler: record the interrupted kernel RIP (M1086) */
    task_cpu_tick(tick_ms, (r->cs & 3) == 3);  /* charge this tick to current's user/sys time (getrusage, M1150) */
    audio_pump();          /* keep the audio DMA fed (no-op unless streaming) */
    task_wake_sleepers();  /* wake any timed-sleep task whose deadline has passed (M1079) */
    app_alarm_tick();      /* raise SIGALRM if the current app's periodic alarm is due (M1102) */
    app_timer_tick();      /* fire any due POSIX timer_create() timers, on every app (M1272) */
    app_cpulimit_tick();   /* raise SIGXCPU if the current task exceeds its RLIMIT_CPU (M1548) */
    loadavg_sample();      /* update the 1/5/15-min run-queue load average every 5 s (M1148) */
    sched_tick();          /* preempt the running thread on THIS (BSP) core */
    /* Every other core has its OWN local LAPIC timer now (M1532), armed by
     * lapic_timer_start_this_cpu() in kernel/smp.c's ap_main -- no need to
     * broadcast an IPI from here anymore (M1531's original, workaround-era
     * mechanism, removed once the real per-core source existed and was
     * verified: make check + repeated in-guest boots + the interactive
     * keyboard/httpd test, since that's the specific class of bug this
     * scheduler code has produced before). */
}

uint32_t timer_tick_ms(void) { return tick_ms; }
/* THE TICK RATE, so nothing has to assume it (M2117).
 *
 * Six places divided timer_ticks() by a literal 100 to get seconds, and
 * kernel/net.c builds about ninety deadlines as `timer_ticks() + 200` with the
 * constant meaning "two seconds at 100 Hz". That makes the PIT frequency
 * un-raisable: 1000 Hz would give millisecond sleep granularity -- every
 * task_sleep_ms(1) currently waits for the NEXT TICK, so a one-millisecond
 * sleep really takes up to ten -- and it would also silently shorten every ARP,
 * DNS and TCP timeout by a factor of ten. The literals are the blocker, not the
 * rate, and this is the accessor that removes them. */
uint32_t timer_hz(void) { return tick_hz ? tick_hz : 100; }

void timer_init(uint32_t hz) {
    uint32_t divisor = PIT_FREQUENCY / hz;
    tick_hz = hz;
    tick_ms = hz ? 1000 / hz : 10;   /* CPU-time tick granularity (M1150) */

    /* command 0x36: channel 0, access lobyte+hibyte, mode 3 (square wave). */
    outb(PIT_COMMAND, 0x36);
    outb(PIT_CH0_DATA, (uint8_t)(divisor & 0xFF));
    outb(PIT_CH0_DATA, (uint8_t)((divisor >> 8) & 0xFF));

    irq_install_handler(0, timer_handler);   /* IRQ0, also unmasks it */
}

uint64_t timer_ticks(void) {
    return ticks;
}

/* Milliseconds since boot, derived from the tick count and the PIT frequency.
 * Monotonic; resolution is one tick (10 ms at the default 100 Hz) — coarse but
 * ample for frame pacing (e.g. DOOM's DG_GetTicksMs). */
uint64_t timer_ms(void) {
    return ticks * 1000ull / tick_hz;
}

/* NANOSECONDS since boot. Whole ticks from the PIT, the remainder from the TSC.
 * (M2114) */
static volatile uint64_t g_ns_floor;      /* the highest value ever returned (M2119) */
uint64_t timer_ns(void) {
    /* THREE WAYS THIS WENT BACKWARDS, and the test caught it: "the monotonic
     * clock went BACKWARDS by 4872123ns" (M2119).
     *
     * 1. `ticks` and `g_tick_tsc` were read as separate loads. A tick landing
     *    between them pairs the OLD tick count with the NEW tick's anchor, so
     *    the TSC delta is ~0 against a base one tick too low -- a jump back of
     *    very nearly one tick, which is exactly the 4.87 ms observed. Read the
     *    tick count on both sides and retry if it moved.
     * 2. `rdtsc_now() - anchor` is unsigned. On more than one core the anchor
     *    may have been taken on a CPU whose TSC runs ahead of this one -- under
     *    TCG they are barely related -- and the subtraction underflows to an
     *    enormous number, which the clamp then turns into a full tick forward,
     *    and the next call comes back down. Guard the underflow.
     * 3. Even with both fixed, two cores with skewed TSCs disagree about the
     *    sub-tick fraction. So monotonicity is not argued, it is ENFORCED: the
     *    highest value ever returned is remembered and never gone below. That
     *    is the property callers actually depend on, and a clock that
     *    guarantees it by construction cannot be wrong about it. */
    uint64_t per = g_tsc_per_tick;
    uint64_t ns_per_tick = 1000000000ull / (tick_hz ? tick_hz : 100);
    uint64_t val = 0;
    for (int attempt = 0; attempt < 4; attempt++) {
        uint64_t t1 = ticks;
        uint64_t anchor = g_tick_tsc;
        uint64_t now = rdtsc_now();
        if (ticks != t1) continue;        /* a tick landed mid-read: the pair is inconsistent */
        uint64_t base = t1 * ns_per_tick;
        if (!per) { val = base; break; }
        uint64_t d = (now > anchor) ? (now - anchor) : 0;
        if (d >= per) d = per - 1;        /* never reach the next tick */
        val = base + ((d * g_ns_per_cycle_q16) >> 16);
        break;
    }
    if (!val) val = ticks * ns_per_tick;  /* four retries lost: whole ticks is still correct */
    /* The floor, published with a compare-exchange so a racing core cannot
     * lower it. */
    for (;;) {
        uint64_t f = g_ns_floor;
        if (val <= f) return f;
        if (__atomic_compare_exchange_n((uint64_t *)&g_ns_floor, &f, val, 0,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
            return val;
    }
}


/* The real resolution, so clock_getres can stop claiming one it does not have.
 * Nanoseconds per TSC cycle, rounded up, or a whole tick if uncalibrated. */
uint64_t timer_res_ns(void) {
    if (!g_tsc_per_tick) return 1000000000ull / (tick_hz ? tick_hz : 100);
    /* One TSC cycle, in nanoseconds, rounded UP -- and never below 1, because a
     * timespec cannot express a fraction of a nanosecond however fast the
     * counter is. Rounding up rather than down so the figure is never better
     * than the truth. */
    uint64_t r = (g_ns_per_cycle_q16 + 0xffffu) >> 16;
    return r ? r : 1;
}

/* TSC cycles in one millisecond, or 0 if the clock is not calibrated yet.
 * Exported so a caller that has measured something in cycles can report it in
 * a unit a human can compare against a wall-clock interval. (M2139) */
uint64_t timer_cycles_per_ms(void) {
    if (!g_tsc_per_tick) return 0;
    uint32_t hz = tick_hz ? tick_hz : 100;
    return (g_tsc_per_tick * hz) / 1000;          /* per-tick * ticks/s / 1000 */
}

/* CALIBRATE AGAINST THE CLOCK WE ALREADY TRUST. Called once, after the PIT is
 * running and before anything measures anything: sit on two tick edges and
 * count cycles between them. Four ticks (40 ms) rather than one, because a
 * single interval is dominated by whatever the interrupt itself cost. */
void timer_calibrate_tsc(void) {
    uint64_t t0 = ticks;
    while (ticks == t0) { }                       /* wait for an edge */
    uint64_t c0 = rdtsc_now(), t1 = ticks;
    while (ticks < t1 + 4) { }
    uint64_t c1 = rdtsc_now();
    uint64_t per = (c1 - c0) / 4;
    /* Sanity: anything outside 1 MHz..100 GHz is not a TSC we can use, and a
     * wrong calibration must not be allowed to produce a wrong clock. */
    uint64_t lo = 1000000ull / (tick_hz ? tick_hz : 100);
    uint64_t hi = 100000000000ull / (tick_hz ? tick_hz : 100);
    if (per > lo && per < hi) {
        g_tsc_per_tick = per;
        g_ns_per_cycle_q16 = ((1000000000ull / (tick_hz ? tick_hz : 100)) << 16) / per;
        g_tick_tsc = rdtsc_now();
        kprintf("[timer] TSC calibrated: %lu cycles/tick (~%lu MHz), clock resolution now ~%luns "
                "instead of %ums (M2114)\n",
                (unsigned long)per,
                (unsigned long)(per * (tick_hz ? tick_hz : 100) / 1000000u),
                (unsigned long)timer_res_ns(), tick_ms);
    } else {
        kprintf("[timer] TSC calibration REJECTED (%lu cycles/tick is outside 1MHz..100GHz): "
                "the monotonic clock stays at %ums granularity\n",
                (unsigned long)per, tick_ms);
    }
}

void timer_wait(uint64_t n) {
    /* Real off-CPU sleep once the scheduler is up: the task blocks and the timer
     * IRQ wakes it at the deadline, instead of spinning READY and re-HLTing every
     * slice (which burned a slot and looked like CPU use in /proc/sched). M1079.
     * task_sleep_ms falls back to a HLT loop before the scheduler exists. */
    task_sleep_ms(n * 1000ull / tick_hz);
}
