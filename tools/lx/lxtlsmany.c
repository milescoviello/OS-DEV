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
#define ROUNDS 40

static __thread uint64_t mine;
static __thread char     scratch[192];   /* guarantees a canary read in this frame */
static volatile long checks, wrong;
static volatile int  started;

static void *body(void *arg) {
    long id = (long)arg;
    uint64_t tag = 0xA5A5000000000000ull | (uint64_t)id;
    mine = tag;
    __atomic_add_fetch(&started, 1, __ATOMIC_RELAXED);
    for (int r = 0; r < ROUNDS; r++) {
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
    for (int i = 0; i < made; i++) pthread_join(th[i], 0);

    /* The main thread's own TLS must still be its own after all that. */
    mine = 0xDEADBEEFCAFEull;
    char b[128];
    snprintf(b, sizeof b, "main %llx", (unsigned long long)mine);
    int mainok = (mine == 0xDEADBEEFCAFEull);

    printf("LXTLSMANY: %ld checks across %d threads, %ld wrong\n", checks, made, wrong);
    if (made < 64)
        printf("LXTLSMANY: FAIL only %d threads could be created -- the scale this tests is the point\n", made);
    if (!mainok)
        printf("LXTLSMANY: FAIL the MAIN thread's own TLS was corrupted\n");
    if (wrong)
        printf("LXTLSMANY: FAIL %ld reads saw a TLS value that was not this thread's\n", wrong);
    printf((wrong || !mainok || made < 64) ? "LXTLSMANY: FAILED\n" : "LXTLSMANY: OK\n");
    return (wrong || !mainok || made < 64) ? 1 : 0;
}
