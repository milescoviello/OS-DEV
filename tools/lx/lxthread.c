/* Real POSIX threads under OS-DEV's Linux ABI (M1959).
 *
 * Deliberately uses glibc's actual NPTL -- pthread_create, a mutex, a
 * condition variable and pthread_join -- rather than raw clone(). That is the
 * point: those are what a real program uses, and they exercise clone with the
 * full pthread flag set, CLONE_SETTLS, set_tid_address, and futex WAIT/WAKE in
 * both the lock and the join.
 *
 * The counter is the assertion. Four threads each increment a shared counter
 * 2000 times under a mutex; a total of exactly 8000 proves the threads really
 * shared one address space (a fork would give each its own copy and the total
 * would be 2000) AND that the mutex actually serialised them.
 *
 * __thread proves CLONE_SETTLS separately: each thread stores its own index in
 * thread-local storage and reads it back after the barrier. Without a
 * per-thread %fs base they would all alias one slot.
 */
#include <stdio.h>
#include <pthread.h>

#define NTHREAD 4
#define NITER   2000

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  ready = PTHREAD_COND_INITIALIZER;
static long counter;
static int  arrived;
static __thread int my_index = -1;
static int tls_seen[NTHREAD];

static void *worker(void *arg) {
    long idx = (long)arg;
    my_index = (int)idx;                 /* thread-local: needs a per-thread %fs */

    for (int i = 0; i < NITER; i++) {
        pthread_mutex_lock(&lock);
        counter++;
        pthread_mutex_unlock(&lock);
    }

    /* A condvar as well as a mutex: it blocks in futex WAIT and is released by
     * a broadcast, which is a different path from the mutex's fast case. */
    pthread_mutex_lock(&lock);
    arrived++;
    if (arrived == NTHREAD) pthread_cond_broadcast(&ready);
    else while (arrived < NTHREAD) pthread_cond_wait(&ready, &lock);
    pthread_mutex_unlock(&lock);

    /* Read TLS back AFTER the barrier: if %fs were shared, the last writer
     * would have clobbered everyone and these would not be distinct. */
    tls_seen[idx] = my_index;
    return (void *)(idx + 100);
}

int main(void) {
    pthread_t th[NTHREAD];
    for (long i = 0; i < NTHREAD; i++)
        if (pthread_create(&th[i], 0, worker, (void *)i) != 0) {
            printf("LXTHREAD: pthread_create failed at %ld\n", i);
            return 1;
        }

    long joined = 0;
    for (int i = 0; i < NTHREAD; i++) {
        void *ret = 0;
        if (pthread_join(th[i], &ret) != 0) { printf("LXTHREAD: join failed\n"); return 2; }
        joined += (long)ret;             /* 100+101+102+103 = 406 */
    }

    int tls_ok = 1;
    for (int i = 0; i < NTHREAD; i++) if (tls_seen[i] != i) tls_ok = 0;

    printf("LXTHREAD: %d threads, counter=%ld (want %d), joined=%ld (want 406), tls=%s\n",
           NTHREAD, counter, NTHREAD * NITER, joined, tls_ok ? "per-thread" : "SHARED-WRONG");

    if (counter != NTHREAD * NITER || joined != 406 || !tls_ok) return 3;
    return 17;                           /* its own status, so a stale binary cannot fake it */
}
