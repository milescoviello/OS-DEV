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
#include <fcntl.h>
#include <linux/futex.h>
#include <sys/syscall.h>

#define NTHREAD   8
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

/* FILE-BACKED mappings, held MANY AT A TIME (M1993).
 *
 * The anonymous churn above is what a program's allocator does. What a dynamic
 * runtime does is different and exercises different code: it maps real files at
 * page offsets, keeps hundreds of those mappings alive at once, reads through
 * them, and unmaps them out of order. That is the shape Claude Code and Firefox
 * die in and the shape `churn` never produced -- every mapping it made was
 * anonymous, and it never held more than one.
 *
 * The files are whatever the image happens to carry; missing ones are skipped,
 * so this degrades to a no-op rather than a false failure. */
#define NLIVE 48
static void filemaps(int seed) {
    static const char *files[] = {
        "/usr/lib64/libc.so.6", "/usr/lib64/libm.so.6", "/usr/lib64/libz.so.1",
        "/lib64/ld-linux-x86-64.so.2", "/hellofree", "/lxbox", 0
    };
    void  *live[NLIVE] = {0};
    size_t lens[NLIVE] = {0};
    for (int i = 0; i < 40; i++) {
        int k = (i + seed) % NLIVE;
        if (live[k]) { munmap(live[k], lens[k]); live[k] = 0; }
        const char *fn = files[(i + seed) % 6];
        if (!fn) continue;
        int fd = open(fn, O_RDONLY);
        if (fd < 0) continue;
        size_t len = (size_t)(1 + ((i + seed) % 12)) * 4096;
        off_t off = (off_t)((i % 4) * 4096);
        unsigned char *m = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, off);
        close(fd);                       /* the documented pattern: close, keep the mapping */
        if (m == MAP_FAILED) continue;
        volatile unsigned char sink = 0;
        for (size_t o = 0; o < len; o += 4096) sink ^= m[o];
        (void)sink;
        /* Make part of it writable, the way a loader does for its relocations. */
        if ((i & 3) == 0) mprotect(m, 4096, PROT_READ | PROT_WRITE);
        live[k] = m; lens[k] = len;
    }
    for (int k = 0; k < NLIVE; k++) if (live[k]) munmap(live[k], lens[k]);
}

static void *worker(void *arg) {
    int id = (int)(long)arg;
    churn(id);
    filemaps(id);
    /* Futex ping-pong with whoever else is here. The wait is TIMED on purpose:
     * an untimed wait on a word nobody advances is a deadlock in the TEST, and
     * a test that hangs teaches nothing about the kernel. Every iteration also
     * advances the word, so a waiter that missed its wake sees a changed value
     * and returns immediately. */
    for (int i = 0; i < 60 && !stop; i++) {
        __atomic_fetch_add(&futex_word, 1, __ATOMIC_SEQ_CST);
        fwake(&futex_word, 2);
        struct timespec ts = { 0, 20 * 1000 * 1000 };   /* 20 ms */
        syscall(SYS_futex, (int *)&futex_word, FUTEX_WAIT_PRIVATE, futex_word, &ts, NULL, 0);
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
    filemaps(0);
    printf("LXSTRESS: phase1b file-backed mmap done\n"); fflush(stdout);

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

    printf("LXSTRESS-RESULT: survived %d rounds x %d threads x 2 generations (+ file-backed maps), %lu signal(s)\n",
           ROUNDS, NTHREAD, sig_count);
    fflush(stdout);
    return 0;
}
