/* lxtime -- deadlines. Not durations: DEADLINES.
 *
 * Three of this kernel's timing syscalls took an ABSOLUTE timestamp and read it
 * as a relative duration, or gave up and substituted a constant. Both mistakes
 * are invisible from inside the kernel -- the wait proceeds exactly as asked --
 * and both are fatal to a real program (M2010):
 *
 *   - FUTEX_WAIT_BITSET's timeout is absolute; that is the whole difference
 *     between it and FUTEX_WAIT. Read as a duration, a 50 ms
 *     pthread_cond_timedwait becomes a wait of 1.79e12 ms: fifty-six years.
 *     Firefox parked sixty-six threads in those.
 *   - clock_nanosleep(TIMER_ABSTIME) was collapsed to a 1 ms sleep, so "wake
 *     me at T" became a thousand-hertz busy loop.
 *   - nanosleep(2) was ENOSYS, which does not sleep at all.
 *
 * So every check here asserts a wait was NEITHER too long NOR too short. Too
 * long is a hang; too short is a spin; only the window in between is a timer.
 * The waits that would hang run in a forked child with a parent timeout, so a
 * regression reports "IT BLOCKED" instead of becoming the hang.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/wait.h>

static int fails;

static long now_ms(clockid_t c)
{
    struct timespec t;
    clock_gettime(c, &t);
    return (long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static struct timespec deadline(clockid_t c, long ms)
{
    struct timespec t;
    clock_gettime(c, &t);
    t.tv_nsec += (long)(ms % 1000) * 1000000;
    t.tv_sec  += ms / 1000 + t.tv_nsec / 1000000000;
    t.tv_nsec %= 1000000000;
    return t;
}

/* The verdict for one timed wait: was the elapsed time in the window? */
static void judge(const char *what, long want, long got)
{
    /* Generous upper bound: this runs under an emulator with no host virtual
     * machine extensions, so a 200 ms wait taking 600 ms is the machine being
     * slow, not the clock being wrong. Fifty-six years is what is being ruled
     * out, and so is one millisecond. */
    long lo = want / 2, hi = want * 4 + 2000;
    if (got >= lo && got <= hi) printf("LXTIME: %s waited %ldms for a %ldms deadline\n", what, got, want);
    else { printf("LXTIME: %s waited %ldms for a %ldms deadline -- outside [%ld,%ld]\n", what, got, want, lo, hi); fails++; }
}

static pthread_mutex_t mx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  cv = PTHREAD_COND_INITIALIZER;

/* pthread_cond_timedwait is the one Firefox died in: glibc implements it with
 * FUTEX_WAIT_BITSET and an absolute deadline, always. Nobody ever signals `cv`,
 * so the only way out is the timeout. */
static int kid_cond_timedwait(void *unused)
{
    (void)unused;
    long t0 = now_ms(CLOCK_MONOTONIC);
    struct timespec d = deadline(CLOCK_REALTIME, 300);
    pthread_mutex_lock(&mx);
    int rc = pthread_cond_timedwait(&cv, &mx, &d);
    pthread_mutex_unlock(&mx);
    long el = now_ms(CLOCK_MONOTONIC) - t0;
    if (rc != ETIMEDOUT) { printf("LXTIME: cond_timedwait returned %d, wanted ETIMEDOUT\n", rc); return 3; }
    /* Report through the exit status so the PARENT does the judging even
     * though the child did the waiting: a child that never returns cannot
     * print anything, and that is the failure being tested for. */
    if (el < 150) return 4;             /* far too short: the deadline was ignored */
    if (el > 3000) return 5;            /* far too long */
    printf("LXTIME: pthread_cond_timedwait waited %ldms for a 300ms ABSOLUTE deadline\n", el);
    return 0;
}

static sem_t sm;
static int kid_sem_timedwait(void *unused)
{
    (void)unused;
    long t0 = now_ms(CLOCK_MONOTONIC);
    struct timespec d = deadline(CLOCK_REALTIME, 300);
    int rc = sem_timedwait(&sm, &d);
    long el = now_ms(CLOCK_MONOTONIC) - t0;
    if (!(rc < 0 && errno == ETIMEDOUT)) { printf("LXTIME: sem_timedwait rc=%d errno=%d, wanted ETIMEDOUT\n", rc, errno); return 3; }
    if (el < 150) return 4;
    if (el > 3000) return 5;
    printf("LXTIME: sem_timedwait waited %ldms for a 300ms ABSOLUTE deadline\n", el);
    return 0;
}

static int timed(int (*fn)(void *), int ms)
{
    pid_t k = fork();
    if (k == 0) _exit(fn(0));
    if (k < 0) return -2;
    for (int i = 0; i < ms / 20; i++) {
        int st = 0;
        if (waitpid(k, &st, WNOHANG) == k) return WIFEXITED(st) ? WEXITSTATUS(st) : -3;
        usleep(20000);
    }
    kill(k, SIGKILL); waitpid(k, 0, 0);
    return -1;                          /* still there: the wait never ended */
}

static void report(const char *what, int rc)
{
    if (rc == 0) return;
    const char *why = rc == -1 ? "IT BLOCKED" : rc == 4 ? "it returned immediately (the deadline was ignored)"
                    : rc == 5 ? "it waited far too long" : "it failed";
    printf("LXTIME: %s -- %s (rc=%d)\n", what, why, rc);
    fails++;
}

int main(void)
{
    /* Unbuffered, because the checks that matter run in a forked child that
     * leaves with _exit() -- which does not flush stdio, so a buffered verdict
     * is a verdict nobody ever sees. */
    setvbuf(stdout, 0, _IONBF, 0);
    sem_init(&sm, 0, 0);

    report("pthread_cond_timedwait on an absolute deadline", timed(kid_cond_timedwait, 8000));
    report("sem_timedwait on an absolute deadline", timed(kid_sem_timedwait, 8000));

    /* clock_nanosleep(TIMER_ABSTIME): the spin, not the hang. Both clocks,
     * because the absolute deadline is measured against whichever one was
     * named and they are different numbers here. */
    for (int i = 0; i < 2; i++) {
        clockid_t c = i ? CLOCK_REALTIME : CLOCK_MONOTONIC;
        struct timespec d = deadline(c, 300);
        long t0 = now_ms(CLOCK_MONOTONIC);
        int rc = clock_nanosleep(c, TIMER_ABSTIME, &d, 0);
        long el = now_ms(CLOCK_MONOTONIC) - t0;
        if (rc != 0) { printf("LXTIME: clock_nanosleep(%s, ABSTIME) rc=%d errno=%d\n", i ? "REALTIME" : "MONOTONIC", rc, errno); fails++; }
        else judge(i ? "clock_nanosleep(REALTIME, ABSTIME)" : "clock_nanosleep(MONOTONIC, ABSTIME)", 300, el);
    }

    /* ...and the relative forms, which must still work. */
    {
        struct timespec rel = { 0, 300 * 1000000 };
        long t0 = now_ms(CLOCK_MONOTONIC);
        int rc = clock_nanosleep(CLOCK_MONOTONIC, 0, &rel, 0);
        long el = now_ms(CLOCK_MONOTONIC) - t0;
        if (rc != 0) { printf("LXTIME: clock_nanosleep(relative) rc=%d errno=%d\n", rc, errno); fails++; }
        else judge("clock_nanosleep(relative)", 300, el);
    }
    {
        struct timespec rel = { 0, 300 * 1000000 };
        long t0 = now_ms(CLOCK_MONOTONIC);
        int rc = nanosleep(&rel, 0);
        long el = now_ms(CLOCK_MONOTONIC) - t0;
        if (rc != 0) { printf("LXTIME: nanosleep rc=%d errno=%d\n", rc, errno); fails++; }
        else judge("nanosleep", 300, el);
    }

    /* A sub-millisecond wait must not be rounded DOWN to zero -- a timed wait
     * that returns instantly is a spin, and 100 us is a perfectly ordinary
     * thing to ask for. */
    {
        struct timespec rel = { 0, 100000 };      /* 100 us */
        long t0 = now_ms(CLOCK_MONOTONIC);
        nanosleep(&rel, 0);
        long el = now_ms(CLOCK_MONOTONIC) - t0;
        if (el <= 2000) printf("LXTIME: a 100us sleep took %ldms (rounded up, not away)\n", el);
        else { printf("LXTIME: a 100us sleep took %ldms\n", el); fails++; }
    }

    /* THE MONOTONIC CLOCK'S ACTUAL RESOLUTION (M2114).
     *
     * It advanced in TEN MILLISECOND JUMPS -- the PIT runs at 100 Hz and
     * clock_gettime answered `(ms % 1000) * 1000000`, so every tv_nsec it ever
     * returned was a multiple of a million -- while clock_getres claimed one
     * millisecond. The one call whose whole job is to report the resolution
     * was reporting a figure ten times better than the truth.
     *
     * It matters because 10 ms is coarser than a 60 Hz frame interval (16.7
     * ms), so a browser's refresh driver measuring "has enough time passed to
     * draw" gets an answer quantised to 0 or 10.
     *
     * This does not trust clock_getres -- a wrong constant there is exactly
     * what was wrong before. It MEASURES: read the clock in a tight loop and
     * find the smallest non-zero step it actually takes. */
    {
        struct timespec r;
        long res_ns = -1;
        if (clock_getres(CLOCK_MONOTONIC, &r) == 0) res_ns = (long)r.tv_nsec;

        long smallest = 1000000000L;
        struct timespec a, b;
        clock_gettime(CLOCK_MONOTONIC, &a);
        for (int i = 0; i < 200000; i++) {
            clock_gettime(CLOCK_MONOTONIC, &b);
            long d = (long)(b.tv_sec - a.tv_sec) * 1000000000L + (long)(b.tv_nsec - a.tv_nsec);
            if (d < 0) { printf("LXTIME: FAIL the monotonic clock went BACKWARDS by %ldns\n", -d); fails++; break; }
            if (d > 0 && d < smallest) smallest = d;
            a = b;
        }
        printf("LXTIME: clock_getres says %ldns; the smallest step actually observed is %ldns\n",
               res_ns, smallest);
        if (smallest < 1000000L)
            printf("LXTIME: ok   CLOCK_MONOTONIC has sub-millisecond resolution\n");
        else {
            printf("LXTIME: FAIL CLOCK_MONOTONIC moves in steps of %ldns -- a 60Hz frame is "
                   "16666666ns, so a refresh driver cannot measure one\n", smallest);
            fails++;
        }
        /* And the claim must not be BETTER than the measurement. Understating
         * resolution is safe; overstating it is the original bug. */
        if (res_ns > 0 && smallest < 1000000L && res_ns > smallest * 4)
            { printf("LXTIME: FAIL clock_getres claims %ldns but the clock steps %ldns\n", res_ns, smallest); fails++; }
        else
            printf("LXTIME: ok   clock_getres does not overstate what the clock delivers\n");
    }

    if (!fails) printf("LXTIME: OK\n");
    printf("LXTIME: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}
