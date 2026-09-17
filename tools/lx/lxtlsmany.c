/* lxtlsmany.c -- THE TLS BASE MUST SURVIVE A HUNDRED THREADS MIGRATING.
 *
 * lxtls (M2083) asserts the three PROPERTIES of per-thread TLS with 8 threads.
 * This asserts the same invariant at Firefox's scale, because the failure it
 * exists to catch is a scale failure: a thread found running with FS_BASE = 0
 * while its own saved base was a perfectly good 0x1210846c0 --
 *
 *   [fault] CR2=0x28 is the `mov %fs:0x28` stack canary: FS BASE is
 *           saved=0x1210846c0 live=0x0 cached=0x0 core=1
 *
 * -- i.e. the restore did not happen, not that the thread never had a block.
 * Eight threads on four cores never reproduced it; Firefox runs a hundred and
 * forty and dies every time.
 *
 * Every loop body below is chosen to make the bug fire rather than to look
 * busy:
 *   - snprintf into a stack buffer, because that is a libc function with a
 *     local array, so it reads %fs:0x28 on entry. A zero FS base faults there
 *     and nowhere else.
 *   - a __thread value only this thread can produce, checked every round, so a
 *     base that is merely WRONG (another thread's block) is caught as well as
 *     one that is zero.
 *   - sched_yield and a sub-millisecond sleep, to force descheduling and
 *     cross-core migration, which is the only way a per-core MSR shadow can go
 *     stale.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <stdint.h>

#define NT     120              /* APP_MAXTHREAD is 192; Firefox reaches ~140 */
/* 40, NOT 150 (M2095). The property under test is THREAD COUNT and migration
 * -- does a thread's own TLS survive being descheduled among 119 others -- and
 * the round count is not what establishes it. At 150 the probe took longer
 * than its 300-second budget under -cpu max, where TCG is emulating AVX-512,
 * and timed out with every one of its checks passing. A test that is killed
 * for being slow reports a failure it did not find. 40 rounds is still 9600
 * checks across 120 threads, with two deschedules each. */
#define ROUNDS 100000   /* an upper bound only: BUDGET_MS is what actually stops it (M2100) */

static __thread uint64_t mine;
static __thread char     scratch[192];   /* guarantees a canary read in this frame */
static volatile long checks, wrong;
static volatile int  started;
/* SELF-PACING, SO IT CAN NEVER BE KILLED FOR BEING SLOW (M2100).
 *
 * The property under test is thread COUNT and migration: does a thread's own
 * TLS survive being descheduled among 119 others. The ROUND count does not
 * establish it -- and twice now a fixed round count has had this probe killed
 * by a timeout with every one of its checks passing, once at 150 rounds and
 * again at 40 under `make check`'s six-way parallel TCG at -cpu max. A test
 * killed for being slow reports a failure it did not find.
 *
 * So: run rounds until the budget is spent, and report how many checks that
 * bought. The assertion is "N checks, 0 wrong, at least 64 threads" with N
 * measured rather than assumed -- which is a stronger claim than a fixed N
 * that only holds on an idle host. */
#define BUDGET_MS 20000
static volatile int g_stop;
static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void *body(void *arg) {
    long id = (long)arg;
    uint64_t tag = 0xA5A5000000000000ull | (uint64_t)id;
    mine = tag;
    __atomic_add_fetch(&started, 1, __ATOMIC_RELAXED);
    for (int r = 0; r < ROUNDS && !g_stop; r++) {
        /* A libc call with a local buffer: the canary read that faults. */
        int n = snprintf(scratch, sizeof scratch, "thread %ld round %d tag %llx",
                         id, r, (unsigned long long)mine);
        if (n <= 0) __atomic_add_fetch(&wrong, 1, __ATOMIC_RELAXED);
        if (mine != tag) __atomic_add_fetch(&wrong, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&checks, 1, __ATOMIC_RELAXED);
        if ((r & 7) == 0) {
            struct timespec ts = { 0, 200000 };     /* 0.2 ms: a real deschedule */
            nanosleep(&ts, 0);
        } else {
            sched_yield();
        }
        if (mine != tag) __atomic_add_fetch(&wrong, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&checks, 1, __ATOMIC_RELAXED);
    }
    return 0;
}

int main(void) {
    pthread_t th[NT];
    int made = 0;
    for (int i = 0; i < NT; i++) {
        if (pthread_create(&th[i], 0, body, (void *)(long)i) != 0) break;
        made++;
    }
    printf("LXTLSMANY: %d of %d threads created\n", made, NT);
    fflush(stdout);
    /* Stop the workers once the budget is spent; they check g_stop each round,
     * so they wind down at a round boundary with their invariant intact. */
    {   long t0 = now_ms();
        while (now_ms() - t0 < BUDGET_MS) {
            if (__atomic_load_n(&started, __ATOMIC_RELAXED) < made) { usleep(2000); continue; }
            /* Every thread is up; give them the rest of the budget. */
            long spent = now_ms() - t0;
            if (BUDGET_MS > spent) usleep((unsigned)((BUDGET_MS - spent) * 1000));
            break;
        }
        g_stop = 1;
    }
    for (int i = 0; i < made; i++) pthread_join(th[i], 0);

    /* The main thread's own TLS must still be its own after all that. */
    mine = 0xDEADBEEFCAFEull;
    char b[128];
    snprintf(b, sizeof b, "main %llx", (unsigned long long)mine);
    int mainok = (mine == 0xDEADBEEFCAFEull);

    printf("LXTLSMANY: %ld checks across %d threads, %ld wrong (%d ms budget)\n",
           checks, made, wrong, BUDGET_MS);
    if (checks < 2000)
        printf("LXTLSMANY: FAIL only %ld checks fitted in the budget -- too few to mean anything\n", checks);
    if (made < 64)
        printf("LXTLSMANY: FAIL only %d threads could be created -- the scale this tests is the point\n", made);
    if (!mainok)
        printf("LXTLSMANY: FAIL the MAIN thread's own TLS was corrupted\n");
    if (wrong)
        printf("LXTLSMANY: FAIL %ld reads saw a TLS value that was not this thread's\n", wrong);
    int bad = (wrong || !mainok || made < 64 || checks < 2000);
    printf(bad ? "LXTLSMANY: FAILED\n" : "LXTLSMANY: OK\n");
    return bad ? 1 : 0;
}
