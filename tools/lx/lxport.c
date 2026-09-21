/* lxport — can two datagram sockets be handed the SAME local port? (M2324)
 *
 * They could, and that was the whole DNS bug. kernel/net.c matches an inbound
 * datagram to a waiter by local port and nothing else -- it cannot tell two
 * sockets on one port apart -- so a collision means one lookup silently eats
 * the other's reply. glibc sees a transaction ID it never sent, discards the
 * answer as spoofed, and waits out all five attempts: EAI_AGAIN.
 *
 * The point of asking it THIS way, rather than by counting failed lookups, is
 * that a duplicate port is a fact the kernel states out loud through
 * getsockname. No network, no resolver, no timing window to wait out, and no
 * ambiguity about whose fault a failure is. A DNS-level test of the same bug
 * needs load, luck and ten minutes; this needs a second.
 *
 * connect() rather than bind(): an unbound datagram socket has no port until
 * something forces the kernel to pick one, and connect() on AF_INET is the
 * path glibc's resolver actually takes.
 *
 * TWO ARMS, AND THE SECOND ONE IS THE TEST. Opening 480 sockets as fast as
 * twelve threads can is not enough: with the fix reverted it still reported
 * 480 distinct ports, because the window between reading the counter and
 * writing it back is a few instructions wide and free-running threads drift
 * straight past it. Widening that window artificially produced duplicates
 * instantly, which proved the race reachable and the TEST inadequate -- a test
 * that passes against the bug it was written for is worse than no test.
 *
 * So arm 2 puts a barrier immediately before connect(), which is the call that
 * allocates, and repeats: every thread arrives at the racing instruction at
 * the same instant, hundreds of times. That is what makes a few-instruction
 * window reproducible without altering the code under test. (M2324)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define NTHREAD 12
#define PER     40
#define NSOCK   (NTHREAD * PER)

static int      g_fd[NSOCK];
static uint16_t g_port[NSOCK];

static void *grab(void *arg) {
    long id = (long)arg;
    for (int i = 0; i < PER; i++) {
        int k = (int)id * PER + i;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { g_fd[k] = -1; continue; }
        struct sockaddr_in to;
        memset(&to, 0, sizeof to);
        to.sin_family = AF_INET;
        to.sin_port   = htons(53);
        to.sin_addr.s_addr = inet_addr("1.1.1.1");
        if (connect(fd, (struct sockaddr *)&to, sizeof to) != 0) { close(fd); g_fd[k] = -1; continue; }
        struct sockaddr_in me;
        socklen_t ml = sizeof me;
        if (getsockname(fd, (struct sockaddr *)&me, &ml) != 0) { close(fd); g_fd[k] = -1; continue; }
        g_fd[k]   = fd;
        g_port[k] = ntohs(me.sin_port);
    }
    return NULL;
}

/* ---- arm 2: everyone allocates at once, over and over -------------------- */
#define ROUNDS 400
static pthread_barrier_t g_bar;
static uint16_t g_rport[NTHREAD];
static int      g_rfd[NTHREAD];
static int      g_round_dups;

static void *rounds(void *arg) {
    long id = (long)arg;
    for (int r = 0; r < ROUNDS; r++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in to;
        memset(&to, 0, sizeof to);
        to.sin_family = AF_INET;
        to.sin_port   = htons(53);
        to.sin_addr.s_addr = inet_addr("1.1.1.1");

        g_rfd[id] = fd; g_rport[id] = 0;
        pthread_barrier_wait(&g_bar);          /* <-- all twelve, same instant */
        if (fd >= 0 && connect(fd, (struct sockaddr *)&to, sizeof to) == 0) {
            struct sockaddr_in me; socklen_t ml = sizeof me;
            if (getsockname(fd, (struct sockaddr *)&me, &ml) == 0)
                g_rport[id] = ntohs(me.sin_port);
        }
        pthread_barrier_wait(&g_bar);

        if (id == 0) {
            for (int i = 0; i < NTHREAD; i++)
                for (int j = 0; j < i; j++)
                    if (g_rport[i] && g_rport[i] == g_rport[j]) {
                        g_round_dups++;
                        if (g_round_dups <= 10)
                            printf("LXPORT-DUP: round %d: thread %d (fd %d) and thread %d (fd %d) "
                                   "were BOTH given local port %u%s\n", r, j, g_rfd[j], i, g_rfd[i],
                                   g_rport[i],
                                   g_rfd[i] == g_rfd[j] ? "  -- AND THE SAME DESCRIPTOR" : "");
                    }
        }
        pthread_barrier_wait(&g_bar);
        if (fd >= 0) close(fd);
    }
    return NULL;
}

int main(void) {
    pthread_t th[NTHREAD];
    int live = 0, dups = 0, noport = 0;

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("LXPORT: %d threads x %d datagram sockets, all held open at once\n", NTHREAD, PER);

    for (long i = 0; i < NTHREAD; i++)
        if (pthread_create(&th[i], NULL, grab, (void *)i) != 0) { printf("LXPORT: pthread_create failed\n"); return 2; }
    for (int i = 0; i < NTHREAD; i++) pthread_join(th[i], NULL);

    /* Every socket is still open, so every port here is simultaneously live:
     * any repeat is two sockets sharing one port RIGHT NOW, not reuse after a
     * close, which would be legitimate. */
    for (int i = 0; i < NSOCK; i++) {
        if (g_fd[i] < 0) continue;
        live++;
        if (g_port[i] == 0) { noport++; continue; }
        for (int j = 0; j < i; j++) {
            if (g_fd[j] < 0 || g_port[j] != g_port[i]) continue;
            dups++;
            if (dups <= 10)
                printf("LXPORT-DUP: fd %d and fd %d are BOTH bound to local port %u -- "
                       "a reply to either will be delivered to whichever polls first\n",
                       g_fd[j], g_fd[i], g_port[i]);
            break;
        }
    }

    printf("LXPORT: %d socket(s) open, %d with no port, %d DUPLICATE port(s)\n",
           live, noport, dups);
    for (int i = 0; i < NSOCK; i++) if (g_fd[i] >= 0) close(g_fd[i]);

    printf("LXPORT: arm 2: %d threads allocating in lockstep, %d rounds\n", NTHREAD, ROUNDS);
    pthread_barrier_init(&g_bar, NULL, NTHREAD);
    for (long i = 0; i < NTHREAD; i++)
        if (pthread_create(&th[i], NULL, rounds, (void *)i) != 0) { printf("LXPORT: pthread_create failed\n"); return 2; }
    for (int i = 0; i < NTHREAD; i++) pthread_join(th[i], NULL);
    printf("LXPORT: arm 2: %d duplicate(s) across %d simultaneous allocations\n",
           g_round_dups, NTHREAD * ROUNDS);
    dups += g_round_dups;
    if (live < NSOCK / 2) { printf("LXPORT-FAIL: only %d of %d sockets opened -- this run proves nothing\n", live, NSOCK); return 2; }
    if (dups)  { printf("LXPORT-FAIL: the ephemeral port allocator hands the same port to two live sockets\n"); return 1; }
    printf("LXPORT-OK: %d live sockets and %d lockstep allocations, no local port repeated\n",
           live, NTHREAD * ROUNDS);
    return 0;
}
