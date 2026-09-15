/* lxwait -- the subprocess lifecycle every Linux runtime depends on (M2025).
 *
 * Claude Code hung inside OS-DEV with every core halted and no syscall for 45
 * seconds. Its main thread was parked in wait4() for children that had ALREADY
 * exited. Two independent defects put it there, and this probe covers both:
 *
 *   1. A child could exit and never become a collectable zombie, so a blocking
 *      wait4() never returned.
 *   2. wait4() discarded its options argument, so WNOHANG -- "look, do not
 *      block" -- blocked for ever on the first call.
 *
 * Each check prints a line the test harness greps for. The spawn loop runs well
 * past the window manager's MAX_WINDOWS so a child that only gets reaped by
 * virtue of owning a window cannot carry the test.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <pthread.h>

#define NKIDS 40

static void *thread_exits(void *arg) {
    (void)arg;
    _exit(23);                 /* exit_group from a NON-main thread */
}

int main(void) {
    setvbuf(stdout, 0, _IONBF, 0);   /* unbuffered: a crash must not eat the progress lines */

    /* 1. Many short-lived children, each collected by a blocking wait4. */
    int ok = 0;
    for (int i = 0; i < NKIDS; i++) {
        pid_t p = fork();
        if (p == 0) _exit(7);
        if (p < 0) { printf("LXWAIT: fork failed at %d\n", i); return 1; }
        int st = 0;
        pid_t got = waitpid(p, &st, 0);
        if (got == p && WIFEXITED(st) && WEXITSTATUS(st) == 7) ok++;
    }
    printf("LXWAIT: reaped %d/%d children\n", ok, NKIDS);

    /* 2. A child whose exit_group comes from a non-main thread. That is what
     *    every threaded runtime does, and it left the process's MAIN task
     *    merely STOPPED -- a state the reaper's gate could never satisfy. */
    pid_t p = fork();
    if (p == 0) {
        pthread_t t;
        pthread_create(&t, 0, thread_exits, 0);
        for (;;) pause();      /* the main thread never exits; the helper does */
    }
    int st = 0;
    pid_t got = waitpid(p, &st, 0);
    printf("LXWAIT: threaded child reaped pid=%d status=%d\n",
           got == p, WIFEXITED(st) ? WEXITSTATUS(st) : -1);

    /* 3. WNOHANG must return 0 immediately while a child is still alive. */
    p = fork();
    if (p == 0) { sleep(3); _exit(11); }
    int polls = 0;
    for (;;) {
        st = 0;
        pid_t g = waitpid(p, &st, WNOHANG);
        if (g == 0) { polls++; if (polls > 200000) { printf("LXWAIT: WNOHANG spun too long\n"); return 1; } usleep(1000); continue; }
        if (g == p) break;
        printf("LXWAIT: WNOHANG returned %d\n", (int)g);
        return 1;
    }
    printf("LXWAIT: WNOHANG polled %s and collected status=%d\n",
           polls > 0 ? "without blocking" : "(child already gone)",
           WIFEXITED(st) ? WEXITSTATUS(st) : -1);

    /* 4. No children left -> ECHILD, not a hang. */
    st = 0;
    pid_t none = waitpid(-1, &st, 0);
    printf("LXWAIT: no children -> %s\n", none < 0 ? "ECHILD" : "WRONG");
    printf("LXWAIT: done\n");
    return 0;
}
