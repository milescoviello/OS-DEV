/* lxepoll.c -- AN EDGE-TRIGGERED EPOLL MUST NOT LOSE AN EDGE (M2059).
 *
 * OS-DEV's epoll is a POLLING loop: each wait asks every registered fd whether
 * it is ready and, for an EPOLLET item, reports it only if the previous answer
 * was "not ready". Nothing else ever cleared that memory -- so the only way an
 * item could become eligible again was for a wait to personally OBSERVE it
 * not-ready.
 *
 * A wake-up eventfd is never observed in that state. Write, wait (edge
 * reported), read it to zero, write again: the dip to zero happened between
 * two waits, so the second write looks like "still ready" and is suppressed.
 * The waiter sleeps forever with the fd sitting ready in front of it.
 *
 * That is the shape of Claude Code's hang: every core idle, no page fault in
 * minutes, an HTTP/2 request to the API returning 401 in nine seconds from
 * Node on the same kernel -- and one line in the dump saying
 *
 *     [poll] epfd 3: fd 4 type 5 want 80000001 -> 1 (edge reported)
 *
 * A thread parked in epoll_pwait2 on that instance, and the eventfd it was
 * waiting for READY and suppressed.
 *
 * Every check here fails on the pre-M2059 kernel. The last one fails if the
 * fix over-corrects into level-triggered behaviour, which is the opposite
 * defect and makes an event loop spin at full speed. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

int main(void) {
    int ep = epoll_create1(0);
    int efd = eventfd(0, 0);
    if (ep < 0 || efd < 0) { printf("LXEPOLL: FAIL epoll_create1/eventfd (%s)\n", strerror(errno)); return 1; }

    struct epoll_event ev; memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN | EPOLLET; ev.data.fd = efd;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev) != 0) { printf("LXEPOLL: FAIL epoll_ctl ADD\n"); return 1; }

    uint64_t one = 1, got = 0;
    struct epoll_event out[4];
    int n;

    /* 1. The rising edge itself -- this always worked. */
    if (write(efd, &one, 8) != 8) { printf("LXEPOLL: FAIL write eventfd\n"); return 1; }
    n = epoll_wait(ep, out, 4, 2000);
    if (n != 1) { printf("LXEPOLL: FAIL the first edge was not reported (n=%d)\n", n); return 1; }
    printf("LXEPOLL: first edge reported\n");

    /* 2. DRAIN IT WITH NO WAIT IN BETWEEN, then re-arm. The whole test. */
    if (read(efd, &got, 8) != 8 || got != 1) { printf("LXEPOLL: FAIL drain read (got %llu)\n", (unsigned long long)got); return 1; }
    if (write(efd, &one, 8) != 8) { printf("LXEPOLL: FAIL re-arm write\n"); return 1; }
    n = epoll_wait(ep, out, 4, 2000);
    if (n != 1) { printf("LXEPOLL: FAIL the edge after an unobserved drain was LOST (n=%d)\n", n); return 2; }
    printf("LXEPOLL: an edge after an unobserved drain is still reported\n");

    /* 3. ...and an fd that STAYS ready must NOT fire again. Edge-triggered
     *    silently becoming level-triggered is the opposite bug: the loop
     *    spins at full speed on a readiness it already handled. */
    n = epoll_wait(ep, out, 4, 60);
    if (n != 0) { printf("LXEPOLL: FAIL a still-ready fd fired again (n=%d) -- this is a spin\n", n); return 3; }
    printf("LXEPOLL: a still-ready fd does not fire twice\n");

    /* 4. A hundred cycles. One lost edge in a hundred is still a hang. */
    for (int i = 0; i < 100; i++) {
        if (read(efd, &got, 8) != 8) { printf("LXEPOLL: FAIL cycle %d read\n", i); return 4; }
        if (write(efd, &one, 8) != 8) { printf("LXEPOLL: FAIL cycle %d write\n", i); return 4; }
        n = epoll_wait(ep, out, 4, 2000);
        if (n != 1) { printf("LXEPOLL: FAIL lost the edge on cycle %d (n=%d)\n", i, n); return 4; }
    }
    printf("LXEPOLL: 100 drain/re-arm cycles, no lost edge\n");

    /* 5. The same for a PIPE, whose readiness is bytes rather than a counter
     *    -- a different app_fd_ready path, the same missed transition. */
    int p[2];
    if (pipe(p) != 0) { printf("LXEPOLL: FAIL pipe()\n"); return 5; }
    struct epoll_event pev; memset(&pev, 0, sizeof pev);
    pev.events = EPOLLIN | EPOLLET; pev.data.fd = p[0];
    if (epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &pev) != 0) { printf("LXEPOLL: FAIL epoll_ctl ADD pipe\n"); return 5; }
    char c = 'x', rc = 0;
    if (write(p[1], &c, 1) != 1) { printf("LXEPOLL: FAIL pipe write\n"); return 5; }
    n = epoll_wait(ep, out, 4, 2000);
    if (n < 1) { printf("LXEPOLL: FAIL the pipe's first edge (n=%d)\n", n); return 5; }
    if (read(p[0], &rc, 1) != 1) { printf("LXEPOLL: FAIL pipe drain\n"); return 6; }
    if (write(p[1], &c, 1) != 1) { printf("LXEPOLL: FAIL pipe re-arm write\n"); return 6; }
    n = epoll_wait(ep, out, 4, 2000);
    if (n < 1) { printf("LXEPOLL: FAIL the pipe's edge after a drain was LOST (n=%d)\n", n); return 6; }
    printf("LXEPOLL: a pipe's edge survives an unobserved drain too\n");

    printf("LXEPOLL: ALL PASSED\n");
    return 0;
}
