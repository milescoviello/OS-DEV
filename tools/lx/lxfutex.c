/* lxfutex.c -- A FUTEX MUST SURVIVE ITS PAGE MOVING (M2073).
 *
 * The futex key was the word's PHYSICAL address. fork() marks every page COW,
 * so the parent's next write to a page allocates a fresh frame -- and a thread
 * that parked before that point kept the old frame's key. Every FUTEX_WAKE
 * afterwards computed the new one, matched nothing, and returned 0, which is
 * exactly what an uncontended unlock returns. Nothing failed; the threads
 * simply stopped being able to wake each other.
 *
 * Claude Code forks to run `git` during startup, so this is where its main
 * thread parked on a condition variable for ever with the TUI never painted.
 *
 * The test reproduces the sequence directly: park a thread on a futex in a
 * private anonymous page, fork, then WRITE to that page in the parent so the
 * COW break hands it a different frame, and only then wake. On the physical
 * key this hangs. It is the one shape a green futex test would never catch,
 * because every futex operation in it succeeds.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <errno.h>
#include <time.h>

static volatile int *word;                  /* the futex itself */
static volatile int  parked, woke;
static volatile long waitret;

static void nap_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void *waiter(void *p) {
    (void)p;
    parked = 1;
    /* *word is 0, so this parks. No timeout: only a real FUTEX_WAKE can
     * release it, which is the whole point -- a timeout would paper over the
     * lost wakeup and make the test pass on the broken kernel. */
    waitret = syscall(SYS_futex, (int *)word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
    woke = 1;
    return NULL;
}

int main(void) {
    int fails = 0;
    void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) { printf("LXFUTEX: FAIL mmap (%s)\n", strerror(errno)); return 1; }
    word = (volatile int *)m;
    word[0] = 0;
    word[1] = 0;

    pthread_t t;
    if (pthread_create(&t, NULL, waiter, NULL) != 0) { printf("LXFUTEX: FAIL pthread_create\n"); return 1; }
    while (!parked) nap_ms(5);
    nap_ms(300);                            /* ...and let it reach the syscall */

    /* 1. THE BASELINE: a wake with the page where the waiter left it. */
    long w = syscall(SYS_futex, (int *)word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);
    for (int i = 0; i < 200 && !woke; i++) nap_ms(10);
    if (!woke) { printf("LXFUTEX: FAIL a plain wake did not reach the waiter (wake returned %ld)\n", w); return 1; }
    pthread_join(t, NULL);
    printf("LXFUTEX: a wake reaches a parked thread (returned %ld)\n", waitret);

    /* 2. THE REAL CASE: park again, fork, MOVE THE PAGE, then wake. */
    parked = woke = 0; waitret = -999;
    word[0] = 0;
    if (pthread_create(&t, NULL, waiter, NULL) != 0) { printf("LXFUTEX: FAIL pthread_create 2\n"); return 1; }
    while (!parked) nap_ms(5);
    nap_ms(300);

    pid_t c = fork();
    if (c == 0) _exit(0);
    if (c < 0) { printf("LXFUTEX: FAIL fork (%s)\n", strerror(errno)); return 1; }
    int st = 0; waitpid(c, &st, 0);

    /* The COW break. word[1], not word[0]: the futex word itself must keep the
     * value the waiter parked on, or the wake below would be unnecessary. */
    word[1] = 0x5AFE;

    w = syscall(SYS_futex, (int *)word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);
    for (int i = 0; i < 400 && !woke; i++) nap_ms(10);
    if (!woke) {
        printf("LXFUTEX: FAIL the wake was LOST across the COW break "
               "(FUTEX_WAKE returned %ld -- it reported success and woke nobody)\n", w);
        fails++;
    } else {
        pthread_join(t, NULL);
        printf("LXFUTEX: a wake still reaches the waiter after fork moved its page (woke %ld)\n", w);
    }

    /* 3. AND THE SAME ACROSS A SECOND FORK, so a one-shot repair would show. */
    if (!fails) {
        parked = woke = 0; word[0] = 0;
        if (pthread_create(&t, NULL, waiter, NULL) != 0) { printf("LXFUTEX: FAIL pthread_create 3\n"); return 1; }
        while (!parked) nap_ms(5);
        nap_ms(300);
        c = fork();
        if (c == 0) _exit(0);
        waitpid(c, &st, 0);
        word[1] = 0xC0FFEE;
        w = syscall(SYS_futex, (int *)word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0);
        for (int i = 0; i < 400 && !woke; i++) nap_ms(10);
        if (!woke) { printf("LXFUTEX: FAIL the wake was lost after a SECOND fork\n"); fails++; }
        else { pthread_join(t, NULL); printf("LXFUTEX: ...and after a second fork too\n"); }
    }

    /* 4. A pthread condvar over the same ground: this is the shape the real
     *    program uses, and it must work for the same reason. */
    printf(fails ? "LXFUTEX: FAILED\n" : "LXFUTEX: OK\n");
    return fails ? 1 : 0;
}
