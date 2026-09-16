/* lxtls.c -- EVERY THREAD MUST SEE ITS OWN TLS, AND A FORKED CHILD MUST KEEP IT.
 *
 * Firefox died at t=120s with CR2=0x28 in libc: the `mov %fs:0x28` stack-
 * protector canary, which every glibc function with a local buffer reads on
 * entry. A fault there means the FS base was ZERO -- a thread running user code
 * with no TLS at all. The reported address is always in libc and always
 * innocent; the cause is clone/CLONE_SETTLS or the context switch's FS_BASE
 * restore.
 *
 * Three properties, none of which anything in the tree asserted:
 *
 *   1. A thread's __thread variable is ITS OWN. If two tasks share an FS base,
 *      one thread's value appears in another -- attributable here, because each
 *      thread writes a value only it can produce.
 *   2. It survives being descheduled, repeatedly. The FS base lives in a
 *      per-core MSR shadow, so a thread that migrates cores must have it
 *      rewritten; a stale per-core cache shows up only after a migration.
 *   3. A child forked from a NON-MAIN thread inherits the FORKING thread's TLS.
 *      task_copy_tls copies from the process's MAIN task, so a fork off any
 *      other thread hands the child the wrong thread-control block.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <time.h>
#include <stdint.h>

#define NT     8
#define ROUNDS 200

static __thread uint64_t mine;          /* the variable under test */
static __thread char     pad[256];      /* so every call here reads a canary */
static volatile int fails, checks;
static volatile int forkfail = -1;

static pid_t mytid(void) { return (pid_t)syscall(SYS_gettid); }
static void nap_ms(long ms) { struct timespec t = { ms/1000, (ms%1000)*1000000L }; nanosleep(&t, NULL); }

static void *worker(void *p) {
    long id = (long)p;
    mine = 0xA5A50000ULL | (uint64_t)id;
    memset(pad, (int)id, sizeof pad);
    for (int r = 0; r < ROUNDS; r++) {
        /* Yield so the scheduler can move us between cores -- property 2. */
        nap_ms(1);
        __sync_fetch_and_add((int *)&checks, 1);
        if (mine != (0xA5A50000ULL | (uint64_t)id)) {
            if (__sync_fetch_and_add((int *)&fails, 1) < 4)
                printf("LXTLS: BAD thread %ld round %d: __thread is %llx, not %llx\n",
                       id, r, (unsigned long long)mine,
                       (unsigned long long)(0xA5A50000ULL | (uint64_t)id));
            continue;
        }
        for (unsigned i = 0; i < sizeof pad; i++)
            if ((unsigned char)pad[i] != (unsigned char)id) {
                if (__sync_fetch_and_add((int *)&fails, 1) < 4)
                    printf("LXTLS: BAD thread %ld round %d: pad[%u]=%02x, not %02lx\n",
                           id, r, i, (unsigned char)pad[i], (unsigned long)(id & 0xff));
                break;
            }
    }
    return NULL;
}

/* Property 3: fork from a thread that is NOT the main thread. */
static void *forker(void *p) {
    (void)p;
    mine = 0xDEADBEEFULL;
    pid_t c = fork();
    if (c == 0) {
        /* Any TLS read here uses the base the kernel gave the child. A canary
         * read happens on entry to printf anyway; check the value too. */
        volatile char local[512];
        memset((void *)local, 0x5A, sizeof local);
        _exit(mine == 0xDEADBEEFULL && local[0] == 0x5A ? 0 : 3);
    }
    if (c < 0) { forkfail = 1; return NULL; }
    int st = 0; waitpid(c, &st, 0);
    forkfail = (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : 2;
    return NULL;
}

int main(void) {
    pthread_t th[NT];
    printf("LXTLS: main tid %d, %d threads x %d rounds\n", (int)mytid(), NT, ROUNDS);
    for (long i = 0; i < NT; i++)
        if (pthread_create(&th[i], NULL, worker, (void *)i) != 0) { printf("LXTLS: FAIL pthread_create %ld\n", i); return 1; }
    for (int i = 0; i < NT; i++) pthread_join(th[i], NULL);
    if (fails) printf("LXTLS: FAIL %d TLS mismatch(es) across %d checks\n", fails, checks);
    else printf("LXTLS: %d checks, every thread saw its own __thread storage\n", checks);

    pthread_t f;
    if (pthread_create(&f, NULL, forker, NULL) != 0) { printf("LXTLS: FAIL pthread_create forker\n"); return 1; }
    pthread_join(f, NULL);
    if (forkfail != 0) {
        printf("LXTLS: FAIL a child forked from a NON-MAIN thread did not keep that thread's TLS (code %d)\n", forkfail);
        fails++;
    } else
        printf("LXTLS: a child forked from a non-main thread kept the forking thread's TLS\n");

    printf(fails ? "LXTLS: FAILED\n" : "LXTLS: OK\n");
    return fails ? 1 : 0;
}
