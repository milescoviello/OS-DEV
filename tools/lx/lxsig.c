/* lxsig.c -- rt_sigaction AND rt_sigprocmask, HONOURED (M2063).
 *
 * Both syscalls used to `return 0` and do nothing. That is the worst-behaved
 * shape of "granted in name only", because rt_sigaction is a QUERY as well as
 * a setter: answering 0 without writing `oldact` leaves the caller reading its
 * own uninitialised stack as a function pointer, and a runtime that saves the
 * old handler to restore it later then installs garbage. SIG_IGN was not
 * recorded either, so a program that asked for a signal to be ignored kept
 * being interrupted by it.
 *
 * Every check here fails on the accept-and-discard implementation. */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

static volatile sig_atomic_t got_usr1, got_usr2, got_winch;
static void h_usr1(int s)  { (void)s; got_usr1++; }
static void h_usr2(int s)  { (void)s; got_usr2++; }
static void h_winch(int s) { (void)s; got_winch++; }

int main(void) {
    struct sigaction sa, old;
    int fails = 0;

    /* 1. A HANDLER ACTUALLY RUNS. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h_usr1;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) { printf("LXSIG: FAIL sigaction SIGUSR1 (%s)\n", strerror(errno)); return 1; }
    raise(SIGUSR1);
    if (got_usr1 != 1) { printf("LXSIG: FAIL the SIGUSR1 handler did not run (got %d)\n", (int)got_usr1); fails++; }
    else printf("LXSIG: a handler installed with sigaction RAN\n");

    /* 2. THE QUERY. oldact must report the handler that is installed -- this is
     *    what a runtime reads back before it overwrites or restores one. */
    memset(&old, 0xAA, sizeof old);
    if (sigaction(SIGUSR1, NULL, &old) != 0) { printf("LXSIG: FAIL query sigaction\n"); return 1; }
    if (old.sa_handler != h_usr1) {
        printf("LXSIG: FAIL oldact reported %p, not the installed handler %p\n",
               (void *)(unsigned long)(unsigned long)old.sa_handler, (void *)h_usr1);
        fails++;
    } else printf("LXSIG: a query reported the handler that is actually installed\n");

    /* 3. SIG_IGN MEANS IGNORED -- and must not sit pending for ever either. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR2, &sa, NULL) != 0) { printf("LXSIG: FAIL sigaction SIG_IGN\n"); return 1; }
    raise(SIGUSR2);
    if (got_usr2 != 0) { printf("LXSIG: FAIL an ignored signal still ran something\n"); fails++; }
    sigset_t pend;
    sigemptyset(&pend);
    if (sigpending(&pend) == 0 && sigismember(&pend, SIGUSR2)) {
        printf("LXSIG: FAIL an IGNORED signal is sitting PENDING -- it was never discarded\n");
        fails++;
    } else printf("LXSIG: SIG_IGN discarded the signal instead of queueing it\n");
    /* ...and the query must say SIG_IGN, not 0 (SIG_DFL). */
    memset(&old, 0xAA, sizeof old);
    sigaction(SIGUSR2, NULL, &old);
    if (old.sa_handler != SIG_IGN) { printf("LXSIG: FAIL a query on an ignored signal did not report SIG_IGN\n"); fails++; }
    else printf("LXSIG: ...and a query reports SIG_IGN, not SIG_DFL\n");

    /* 4. BLOCKING. A blocked signal stays pending, then runs on unblock -- the
     *    order matters, so check both halves. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h_winch;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGWINCH, &sa, NULL);
    sigset_t blk, oldset;
    sigemptyset(&blk); sigaddset(&blk, SIGWINCH);
    sigemptyset(&oldset);
    if (sigprocmask(SIG_BLOCK, &blk, &oldset) != 0) { printf("LXSIG: FAIL sigprocmask BLOCK\n"); return 1; }
    raise(SIGWINCH);
    if (got_winch != 0) { printf("LXSIG: FAIL a BLOCKED signal was delivered anyway\n"); fails++; }
    else printf("LXSIG: a blocked signal was not delivered\n");
    sigemptyset(&pend);
    if (sigpending(&pend) != 0 || !sigismember(&pend, SIGWINCH)) {
        printf("LXSIG: FAIL a blocked signal is not reported as pending\n"); fails++;
    } else printf("LXSIG: ...and IS reported pending while blocked\n");
    if (sigprocmask(SIG_UNBLOCK, &blk, NULL) != 0) { printf("LXSIG: FAIL sigprocmask UNBLOCK\n"); return 1; }
    /* glibc's sigprocmask returns before the pending signal is taken; a
     * syscall gives the kernel its chance to deliver on the way back. */
    (void)getpid();
    if (got_winch != 1) { printf("LXSIG: FAIL the signal did not arrive after UNBLOCK (got %d)\n", (int)got_winch); fails++; }
    else printf("LXSIG: ...and arrived once unblocked\n");

    /* 5. THE MASK QUERY. oldset must be the mask that was in force. */
    sigset_t cur;
    sigemptyset(&cur);
    if (sigprocmask(SIG_BLOCK, NULL, &cur) != 0) { printf("LXSIG: FAIL sigprocmask query\n"); return 1; }
    if (sigismember(&cur, SIGWINCH)) { printf("LXSIG: FAIL the mask query still shows SIGWINCH blocked\n"); fails++; }
    else printf("LXSIG: a mask query reports the live mask\n");

    /* 6. SIGKILL AND SIGSTOP CANNOT BE CAUGHT. Accepting that is an error a
     *    program relies on: it probes with sigaction and expects EINVAL. */
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h_usr1;
    if (sigaction(SIGKILL, &sa, NULL) == 0) { printf("LXSIG: FAIL installing a SIGKILL handler was ACCEPTED\n"); fails++; }
    else printf("LXSIG: a SIGKILL handler is refused (%s)\n", strerror(errno));

    if (fails) { printf("LXSIG: %d FAILED\n", fails); return 2; }
    printf("LXSIG: ALL PASSED\n");
    return 0;
}
