#define _GNU_SOURCE
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
#include <fcntl.h>
#include <errno.h>

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

/* dup3 HAD NO LINUX SYSCALL NUMBER AT ALL (M2107).
 *
 * It answered ENOSYS while app_dup3 had existed since M1218 -- and glibc
 * reaches for dup3 whenever a caller wants the duplicate to be close-on-exec,
 * which is precisely what a process launcher remapping descriptors before an
 * exec wants. The second trap is that the FLAG IS A DIFFERENT NUMBER on the two
 * sides (Linux O_CLOEXEC is 02000000, this kernel's is 0x10), so passing the
 * bits through unchanged sets nothing and still returns success.
 *
 * So both halves are asserted here: the descriptor must be duplicated, it must
 * come back with FD_CLOEXEC actually SET, plain dup2 must leave it CLEAR (that
 * is M2037's fix and the reason the pipeline below works at all), and equal
 * descriptors must be EINVAL rather than dup2's silent success. */
static void do_dup3(int *fails) {
    int a = dup(1);                                  /* something harmless to copy */
    if (a < 0) { printf("LXBOX: FAIL dup(1)\n"); (*fails)++; return; }

    int got = dup3(a, 30, O_CLOEXEC);
    if (got != 30) { printf("LXBOX: FAIL dup3 -> %d errno %d\n", got, errno); (*fails)++; }
    else {
        int fl = fcntl(30, F_GETFD);
        if (fl >= 0 && (fl & FD_CLOEXEC))
            printf("LXBOX: ok   dup3(O_CLOEXEC) duplicated the fd AND set FD_CLOEXEC\n");
        else {
            printf("LXBOX: FAIL dup3 succeeded but FD_CLOEXEC is not set (F_GETFD -> %d) -- "
                   "the flag was passed through untranslated\n", fl);
            (*fails)++;
        }
        close(30);
    }
    if (dup2(a, 31) == 31) {
        int fl = fcntl(31, F_GETFD);
        if (fl >= 0 && !(fl & FD_CLOEXEC))
            printf("LXBOX: ok   dup2 leaves FD_CLOEXEC CLEAR, as POSIX requires\n");
        else { printf("LXBOX: FAIL dup2 set FD_CLOEXEC (F_GETFD -> %d)\n", fl); (*fails)++; }
        close(31);
    } else { printf("LXBOX: FAIL dup2(a,31)\n"); (*fails)++; }

    if (dup3(a, a, 0) < 0 && errno == EINVAL)
        printf("LXBOX: ok   dup3(fd, fd) is EINVAL, unlike dup2\n");
    else { printf("LXBOX: FAIL dup3(fd,fd) should be EINVAL, errno %d\n", errno); (*fails)++; }
    close(a);
}

static int do_pipe(const char *self) {
    int fds[2];
    if (pipe(fds) != 0) { printf("LXBOX: pipe failed\n"); return 1; }
    { int f = 0; do_dup3(&f);
      if (f) printf("LXBOX: %d dup3 failure(s)\n", f);
      else   printf("LXBOX: DUP3 OK\n"); }

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
