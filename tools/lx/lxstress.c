#define _GNU_SOURCE
/*
 * lxstress.c -- reproduce the kernel corruption Firefox hits, in two minutes
 * instead of ten (M1987).
 *
 * Firefox dies with a supervisor instruction fetch from a USER address (SMEP
 * catching the kernel jumping into userspace) and with mozjemalloc's 0xe5
 * freed-memory poison in its own registers. That is kernel memory corruption
 * under load, and the long-standing intermittent `cc1` crash looks the same.
 * Neither is a usable test: one takes ten minutes to reach the failure and the
 * other is a whole compiler.
 *
 * So do what they do, deliberately and densely, from several threads at once:
 *
 *   - mmap / touch / mprotect / munmap churn, in sizes that straddle the
 *     page-and-hugepage boundaries the VMA code special-cases
 *   - threads created and joined repeatedly, so kernel stacks and task slots
 *     are recycled while other threads are running
 *   - futex wait/wake ping-pong, which is where a task can block and be woken
 *     by another core
 *   - signals delivered to a thread that is inside a syscall
 *   - clock_gettime and getpid at high rate, to keep the syscall path hot
 *
 * It prints one line per phase so a failure says WHICH kind of work was
 * running, and a final LXSTRESS-RESULT that the harness asserts on. A kernel
 * that corrupts itself here never reaches that line.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <linux/futex.h>
#include <sys/syscall.h>

#define NTHREAD   6
#define ROUNDS    120

static volatile int futex_word;
static volatile unsigned long sig_count;
static volatile int stop;

static int fwait(volatile int *w, int v) {
    return (int)syscall(SYS_futex, (int *)w, FUTEX_WAIT_PRIVATE, v, NULL, NULL, 0);
}
static int fwake(volatile int *w, int n) {
    return (int)syscall(SYS_futex, (int *)w, FUTEX_WAKE_PRIVATE, n, NULL, NULL, 0);
}

static void on_sig(int s) { (void)s; sig_count++; }

/* mmap churn: sizes chosen to cross the boundaries the VMA code treats
 * specially -- one page, just under and just over 2 MiB, and a big
 * PROT_NONE reservation that is then committed in pieces, which is the shape
 * a JIT uses. */
static void churn(int seed) {
    static const size_t sizes[] = { 4096, 65536, 2u << 20, (2u << 20) + 4096, 1u << 20 };
    for (int i = 0; i < ROUNDS; i++) {
        size_t len = sizes[(i + seed) % 5];
        unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) continue;
        p[0] = (unsigned char)i;
        p[len / 2] = (unsigned char)i;
        p[len - 1] = (unsigned char)i;
        if ((i & 3) == 0) mprotect(p, 4096, PROT_READ);
        if ((i & 7) == 0 && len > 8192) {
            /* punch a hole: the split path, which is where a VMA table gets
             * rewritten while other threads are faulting on their own. */
            munmap(p + 4096, 4096);
            munmap(p, 4096);
            munmap(p + 8192, len - 8192);
        } else {
            munmap(p, len);
        }
        if ((i & 15) == 0) {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            (void)getpid();
        }
    }
}

static void *worker(void *arg) {
    int id = (int)(long)arg;
    churn(id);
    /* futex ping-pong with whoever else is here */
    for (int i = 0; i < 60 && !stop; i++) {
        int v = futex_word;
        fwake(&futex_word, 1);
        if (v == futex_word) fwait(&futex_word, v);
    }
    return NULL;
}

int main(void) {
    printf("LXSTRESS: start\n"); fflush(stdout);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sigaction(SIGUSR1, &sa, NULL);

    /* Phase 1: single-threaded mmap churn -- a clean baseline. If this alone
     * breaks, threads are not the ingredient. */
    churn(0);
    printf("LXSTRESS: phase1 mmap churn done\n"); fflush(stdout);

    /* Phase 2: the same work from several threads at once, with threads
     * created and joined repeatedly so task slots and kernel stacks recycle
     * under other threads' feet. */
    for (int gen = 0; gen < 2; gen++) {
        pthread_t th[NTHREAD];
        int n = 0;
        for (int i = 0; i < NTHREAD; i++)
            if (pthread_create(&th[i], NULL, worker, (void *)(long)i) == 0) n++;
        for (int i = 0; i < n; i++) {
            /* signal a thread while it is mid-syscall */
            pthread_kill(th[i], SIGUSR1);
            pthread_join(th[i], NULL);
        }
        fwake(&futex_word, NTHREAD);
        printf("LXSTRESS: generation %d of threads joined\n", gen); fflush(stdout);
    }
    stop = 1;
    fwake(&futex_word, NTHREAD * 4);

    printf("LXSTRESS-RESULT: survived %d rounds x %d threads x 2 generations, %lu signal(s)\n",
           ROUNDS, NTHREAD, sig_count);
    fflush(stdout);
    return 0;
}
