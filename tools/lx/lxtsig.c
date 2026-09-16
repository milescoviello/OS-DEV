/* lxtsig.c -- A SIGNAL SENT TO A THREAD MUST ARRIVE AT THAT THREAD.
 *
 * tkill/tgkill/pthread_kill name a thread. Until M2075 the name was discarded:
 * the pending bit went into a process-wide set and was delivered to whichever
 * thread next returned to ring 3. For kill(2) that is indistinguishable; for
 * the use that matters it is the whole bug.
 *
 * JavaScriptCore suspends a thread for a collection by pthread_kill-ing it and
 * having the handler record ITS OWN registers, then scans that thread's stack
 * from the recorded stack pointer. Delivered to the wrong thread, the target
 * never suspends and the collector scans from an unrelated stack pointer: live
 * roots are invisible and objects still in use are freed. The crash lands much
 * later, inside the marker, on a pointer like 0x9000900090.
 *
 * Every check here passes trivially on a single-threaded program and fails on
 * a process-wide signal implementation.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/syscall.h>

#define NT 4

static pthread_t     th[NT];
static volatile pid_t tids[NT];
static volatile int   ready[NT];
static volatile int   stop;
static volatile pid_t handler_tid;     /* who actually ran the handler */
static volatile int   handler_runs;
static volatile int   usr2_tid;
static int fails;

static pid_t mytid(void) { return (pid_t)syscall(SYS_gettid); }

static void nap_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void h_usr1(int s) { (void)s; handler_tid = mytid(); handler_runs++; }
static void h_usr2(int s) { (void)s; usr2_tid = mytid(); }

static void *worker(void *p) {
    long i = (long)p;
    tids[i] = mytid();
    ready[i] = 1;
    /* Short sleeps, so the thread returns to user mode often -- a signal is
     * delivered on the way back out, and a thread parked for ever in one
     * syscall would make this a test of the wake path instead. */
    while (!stop) nap_ms(10);
    return NULL;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h_usr1; sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) { printf("LXTSIG: FAIL sigaction SIGUSR1\n"); return 1; }
    sa.sa_handler = h_usr2;
    if (sigaction(SIGUSR2, &sa, NULL) != 0) { printf("LXTSIG: FAIL sigaction SIGUSR2\n"); return 1; }

    pid_t main_tid = mytid();
    for (long i = 0; i < NT; i++)
        if (pthread_create(&th[i], NULL, worker, (void *)i) != 0) { printf("LXTSIG: FAIL pthread_create %ld\n", i); return 1; }
    for (int i = 0; i < NT; i++) { int w = 0; while (!ready[i] && w++ < 500) nap_ms(10); }
    for (int i = 0; i < NT; i++)
        if (!ready[i]) { printf("LXTSIG: FAIL worker %d never started\n", i); return 1; }
    printf("LXTSIG: main tid %d, workers %d %d %d %d\n",
           (int)main_tid, (int)tids[0], (int)tids[1], (int)tids[2], (int)tids[3]);

    /* 1. EACH THREAD IN TURN. The handler records the tid it ran on; that must
     *    be the thread the signal named, not "whoever got there first". */
    int right = 0, wrong = 0;
    for (int i = 0; i < NT; i++) {
        handler_tid = 0; handler_runs = 0;
        if (pthread_kill(th[i], SIGUSR1) != 0) { printf("LXTSIG: FAIL pthread_kill worker %d\n", i); fails++; continue; }
        int w = 0; while (!handler_tid && w++ < 300) nap_ms(10);
        if (!handler_tid) { printf("LXTSIG: FAIL worker %d: the signal was never delivered at all\n", i); fails++; continue; }
        if (handler_tid == tids[i]) right++;
        else {
            wrong++;
            if (wrong <= 2)
                printf("LXTSIG: FAIL pthread_kill(worker %d, tid %d) ran the handler on tid %d instead\n",
                       i, (int)tids[i], (int)handler_tid);
        }
    }
    if (!wrong) printf("LXTSIG: each of %d pthread_kills ran its handler on the thread it named\n", right);
    else fails++;

    /* 2. AND AT OURSELVES, which is what raise() does -- the case a
     *    process-wide implementation gets right by accident. */
    handler_tid = 0;
    if (pthread_kill(pthread_self(), SIGUSR1) != 0) { printf("LXTSIG: FAIL pthread_kill(self)\n"); fails++; }
    else if (handler_tid != main_tid) {
        printf("LXTSIG: FAIL pthread_kill(self) ran on tid %d, not %d\n", (int)handler_tid, (int)main_tid);
        fails++;
    } else printf("LXTSIG: pthread_kill(self) ran the handler on the calling thread\n");

    /* 3. THE MASK IS THE THREAD'S. The main thread blocks SIGUSR2 and signals
     *    a worker: a shared mask would swallow it, because the deliverer would
     *    consult the blocker's mask. */
    sigset_t only2; sigemptyset(&only2); sigaddset(&only2, SIGUSR2);
    if (pthread_sigmask(SIG_BLOCK, &only2, NULL) != 0) { printf("LXTSIG: FAIL pthread_sigmask\n"); fails++; }
    usr2_tid = 0;
    if (pthread_kill(th[0], SIGUSR2) != 0) { printf("LXTSIG: FAIL pthread_kill SIGUSR2\n"); fails++; }
    { int w = 0; while (!usr2_tid && w++ < 300) nap_ms(10); }
    if (!usr2_tid) {
        printf("LXTSIG: FAIL SIGUSR2 to a worker was swallowed by the MAIN thread's mask"
               " -- the blocked set is shared\n");
        fails++;
    } else if (usr2_tid != tids[0]) {
        printf("LXTSIG: FAIL SIGUSR2 ran on tid %d, not worker 0 (tid %d)\n", (int)usr2_tid, (int)tids[0]);
        fails++;
    } else printf("LXTSIG: a worker received SIGUSR2 while the main thread had it blocked\n");
    pthread_sigmask(SIG_UNBLOCK, &only2, NULL);

    /* 4. ALL OF THEM AT ONCE, which is how a collector actually does it: every
     *    thread signalled before any of them is waited for. The shared
     *    save slot shows up here -- two handlers in flight overwrite each
     *    other's interrupted context, and the second sigreturn resumes the
     *    wrong thread at the wrong address. */
    handler_runs = 0;
    for (int i = 0; i < NT; i++) pthread_kill(th[i], SIGUSR1);
    { int w = 0; while (handler_runs < NT && w++ < 600) nap_ms(10); }
    if (handler_runs < NT) {
        printf("LXTSIG: FAIL %d of %d concurrent signals were delivered\n", handler_runs, NT);
        fails++;
    } else printf("LXTSIG: %d threads signalled at once all ran their handlers\n", NT);

    /* ...and every thread must still be alive and looping afterwards, which is
     *    the part a clobbered saved context breaks: the thread returns from the
     *    handler to an address nothing computed. */
    stop = 1;
    int joined = 0;
    for (int i = 0; i < NT; i++) if (pthread_join(th[i], NULL) == 0) joined++;
    if (joined != NT) { printf("LXTSIG: FAIL only %d of %d threads survived their handler\n", joined, NT); fails++; }
    else printf("LXTSIG: every thread resumed correctly after its handler and joined\n");

    printf(fails ? "LXTSIG: FAILED\n" : "LXTSIG: OK\n");
    return fails ? 1 : 0;
}
