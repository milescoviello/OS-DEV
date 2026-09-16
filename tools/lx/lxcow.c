/* lxcow.c -- CONCURRENT COW BREAKS MUST NOT LOSE WRITES.
 *
 * lxzero proves a copy-on-write break keeps its page's contents. It proves it
 * with ONE thread, which is the case that cannot race. fork() in a threaded
 * process marks every page read-only in an address space that dozens of
 * threads are still writing to, so the interesting event is two threads
 * faulting on the SAME page at the same moment: if each allocates a copy and
 * installs it, one thread's writes land in a page the other has already
 * discarded, and nothing anywhere reports an error.
 *
 * Claude Code is the shape that provokes it -- sixty threads, and a fork for
 * every `git` it runs during startup. Its crashes were a write through a null
 * field in a JIT worker, a non-canonical pointer returned from a call, and a
 * garbage JSValue in the marker: three threads, three addresses, one cause if
 * memory is quietly changing under them.
 *
 * Each thread owns a disjoint slice and writes a value derived from its own
 * index, so a lost write is attributable: the reported value says which
 * thread's copy won.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>

#define NT      8
#define SLICE   (2UL * 1024 * 1024)      /* per thread */
#define FORKS   40

static volatile uint64_t *mem;
static volatile int stop, started[NT];
static volatile unsigned long long bad[NT], passes[NT];

static void nap_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static uint64_t want_of(int t, unsigned long i) {
    return ((uint64_t)(t + 1) << 40) | (i * 2654435761ULL & 0xFFFFFFFFFFULL);
}

static void *churn(void *p) {
    long t = (long)p;
    volatile uint64_t *slice = mem + (t * SLICE) / 8;
    unsigned long n = SLICE / 8;
    for (unsigned long i = 0; i < n; i++) slice[i] = want_of((int)t, i);
    started[t] = 1;
    while (!stop) {
        /* Verify, then rewrite: the rewrite is what breaks COW after a fork,
         * and the verify is what catches the break losing the previous one. */
        for (unsigned long i = 0; i < n; i++) {
            uint64_t got = slice[i], w = want_of((int)t, i);
            if (got != w) {
                if (bad[t]++ < 3)
                    printf("LXCOW: BAD thread %ld word %lu: got %llx want %llx\n",
                           t, i, (unsigned long long)got, (unsigned long long)w);
            }
        }
        for (unsigned long i = 0; i < n; i++) slice[i] = want_of((int)t, i);
        passes[t]++;
    }
    return NULL;
}

int main(void) {
    mem = mmap(NULL, NT * SLICE, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { printf("LXCOW: FAIL mmap (%s)\n", strerror(errno)); return 1; }

    pthread_t th[NT];
    for (long t = 0; t < NT; t++)
        if (pthread_create(&th[t], NULL, churn, (void *)t) != 0) { printf("LXCOW: FAIL pthread_create %ld\n", t); return 1; }
    for (int t = 0; t < NT; t++) { int w = 0; while (!started[t] && w++ < 2000) nap_ms(10); }

    int forked = 0, childbad = 0;
    for (int f = 0; f < FORKS; f++) {
        pid_t c = fork();
        if (c == 0) {
            /* The child gets a snapshot. It only has the forking thread, so
             * its slices are whatever the others had mid-write -- not checked.
             * What IS checked is that the child can write its own copies
             * without faulting, which is the other half of the break. */
            for (unsigned long i = 0; i < (NT * SLICE) / 8; i += 512) mem[i] = 0xC0FFEE;
            _exit(0);
        }
        if (c < 0) { printf("LXCOW: FAIL fork %d (%s)\n", f, strerror(errno)); break; }
        forked++;
        int st = 0; waitpid(c, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) childbad++;
        nap_ms(20);
    }
    stop = 1;
    for (int t = 0; t < NT; t++) pthread_join(th[t], NULL);

    unsigned long long tb = 0, tp = 0;
    for (int t = 0; t < NT; t++) { tb += bad[t]; tp += passes[t]; }
    printf("LXCOW: %d forks, %d threads, %llu verify passes over %lu MiB\n",
           forked, NT, tp, (unsigned long)(NT * SLICE / (1024 * 1024)));
    if (childbad) printf("LXCOW: FAIL %d child(ren) did not exit cleanly\n", childbad);
    if (tb) printf("LXCOW: FAIL %llu word(s) lost their value across a concurrent COW break\n", tb);

    /* And a final full sweep, in case a lost write happened after the last
     * verify pass of the thread that owned it. */
    unsigned long long late = 0;
    for (int t = 0; t < NT; t++) {
        volatile uint64_t *slice = mem + ((unsigned long)t * SLICE) / 8;
        for (unsigned long i = 0; i < SLICE / 8; i++)
            if (slice[i] != want_of(t, i)) {
                if (late++ < 3)
                    printf("LXCOW: BAD final thread %d word %lu: got %llx want %llx\n",
                           t, i, (unsigned long long)slice[i], (unsigned long long)want_of(t, i));
            }
    }
    if (late) printf("LXCOW: FAIL %llu word(s) wrong in the final sweep\n", late);
    int fails = (tb || late || childbad || forked != FORKS);
    printf(fails ? "LXCOW: FAILED\n" : "LXCOW: OK\n");
    return fails ? 1 : 0;
}
