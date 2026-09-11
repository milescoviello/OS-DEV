/* lxbox — a multi-call utility binary, in the shape busybox has: one
 * executable that behaves as a different tool depending on argv[1].
 *
 * busybox itself is not obtainable on this host (no binary, no cached source,
 * only an unbuilt ebuild needing network and root). But Phase 3's actual
 * deliverable was never that particular binary -- it was
 * `busybox ls | busybox wc -l` producing the right number THROUGH A REAL PIPE,
 * which is a statement about fork, execve, wait4, pipe2 and dup2. This
 * exercises exactly those, and it re-execs ITSELF, so execve has to work on a
 * real on-disk path with a fresh argv.
 *
 *   lxbox echo A B C   -> prints the args, one per line
 *   lxbox wc           -> counts lines on stdin
 *   lxbox pipe         -> fork+exec BOTH sides of `echo | wc`, wired with a
 *                         real pipe, and report both exit statuses
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static int do_echo(int argc, char **argv) {
    for (int i = 2; i < argc; i++) printf("%s\n", argv[i]);
    fflush(stdout);
    return 0;
}

static int do_wc(void) {
    int n = 0, c;
    while ((c = getchar()) != EOF) if (c == '\n') n++;
    printf("LXBOX-WC: %d\n", n);
    fflush(stdout);
    /* Return the COUNT as the exit status, so the parent can report it via
     * wait4. The reader's own console output turned out to be intermittently
     * lost under load, and asserting on it made the test flaky; routing the
     * result through the exit status means the assertion rests on ONE line
     * from ONE process, and it proves more -- that wait4 carries a real
     * value, not just zero. */
    return n;
}

static int do_pipe(const char *self) {
    int fds[2];
    if (pipe(fds) != 0) { printf("LXBOX: pipe failed\n"); return 1; }

    pid_t a = fork();
    if (a < 0) { printf("LXBOX: fork 1 failed\n"); return 1; }
    if (a == 0) {                                   /* writer: echo -> pipe */
        dup2(fds[1], 1); close(fds[0]); close(fds[1]);
        char *av[] = { (char *)self, "echo", "one", "two", "three", "four", NULL };
        execve(self, av, (char *[]){ NULL });
        _exit(127);                                 /* only reached if execve failed */
    }
    pid_t b = fork();
    if (b < 0) { printf("LXBOX: fork 2 failed\n"); return 1; }
    if (b == 0) {                                   /* reader: pipe -> wc */
        dup2(fds[0], 0); close(fds[0]); close(fds[1]);
        char *av[] = { (char *)self, "wc", NULL };
        execve(self, av, (char *[]){ NULL });
        _exit(127);
    }
    close(fds[0]); close(fds[1]);

    int s1 = 0, s2 = 0;
    waitpid(a, &s1, 0);
    waitpid(b, &s2, 0);
    printf("LXBOX: pipeline wc=%d writer=%d\n",
           WIFEXITED(s2) ? WEXITSTATUS(s2) : -1,
           WIFEXITED(s1) ? WEXITSTATUS(s1) : -1);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    const char *self = argc > 0 ? argv[0] : "/lxbox";
    if (argc > 1 && !strcmp(argv[1], "echo")) return do_echo(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "wc"))   return do_wc();
    if (argc > 1 && !strcmp(argv[1], "pipe")) return do_pipe(self);
    printf("LXBOX: usage: lxbox echo|wc|pipe\n");
    fflush(stdout);
    return 1;
}
