/*
 * lxscm.c -- passing a descriptor over a socket, and sharing memory through it
 * (M1977).
 *
 * This is the whole foundation of wl_shm, and therefore of any Wayland client
 * including Firefox: a client puts its pixels in a memfd, passes the DESCRIPTOR
 * to the compositor over the AF_UNIX connection they already have, and both
 * processes mmap it. No pixel is ever copied through the socket.
 *
 * Three things are checked separately, because they fail independently:
 *
 *   1. memfd_create gives a real, writable, mmap-able anonymous file.
 *   2. SCM_RIGHTS actually transfers the descriptor -- the receiver gets a
 *      NEW fd number that refers to the SAME object, not a copy of the number.
 *   3. The mapping is genuinely SHARED: a write through the receiver's mapping
 *      is visible through the sender's. That is the part that makes it useful
 *      and the part that a stub would get wrong while passing 1 and 2.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define SHM_SIZE 65536

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { printf("LXSCM: socketpair failed\n"); fflush(stdout); return 1; }

    int mfd = memfd_create("lxscm", 0);
    if (mfd < 0) { printf("LXSCM: memfd_create failed\n"); fflush(stdout); return 2; }
    if (ftruncate(mfd, SHM_SIZE) != 0) { printf("LXSCM: ftruncate failed\n"); fflush(stdout); return 3; }

    unsigned char *mine = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    if (mine == MAP_FAILED) { printf("LXSCM: sender mmap failed\n"); fflush(stdout); return 4; }
    memset(mine, 0xC3, SHM_SIZE);          /* a pattern the receiver must see */

    /* Pass the descriptor with one byte of payload, exactly as a protocol
     * message would carry it. */
    char iobuf[1] = { 'F' };
    struct iovec iov = { iobuf, 1 };
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int))]; } cm;
    memset(&cm, 0, sizeof cm);
    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = cm.b; msg.msg_controllen = sizeof cm.b;
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &mfd, sizeof(int));
    if (sendmsg(sv[0], &msg, 0) != 1) { printf("LXSCM: sendmsg failed\n"); fflush(stdout); return 5; }

    /* Receive it on the other end. */
    char rbuf[1] = { 0 };
    struct iovec riov = { rbuf, 1 };
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(int))]; } rcm;
    memset(&rcm, 0, sizeof rcm);
    struct msghdr rmsg;
    memset(&rmsg, 0, sizeof rmsg);
    rmsg.msg_iov = &riov; rmsg.msg_iovlen = 1;
    rmsg.msg_control = rcm.b; rmsg.msg_controllen = sizeof rcm.b;
    if (recvmsg(sv[1], &rmsg, 0) != 1 || rbuf[0] != 'F') {
        printf("LXSCM: recvmsg did not deliver the payload\n"); fflush(stdout); return 6;
    }
    struct cmsghdr *rc = CMSG_FIRSTHDR(&rmsg);
    if (!rc || rc->cmsg_level != SOL_SOCKET || rc->cmsg_type != SCM_RIGHTS) {
        printf("LXSCM: no SCM_RIGHTS control message came back\n"); fflush(stdout); return 7;
    }
    int got;
    memcpy(&got, CMSG_DATA(rc), sizeof(int));
    if (got < 0) { printf("LXSCM: received an invalid fd\n"); fflush(stdout); return 8; }
    if (got == mfd) { printf("LXSCM: receiver got the SAME fd number -- not a real transfer\n"); fflush(stdout); return 9; }

    /* The received descriptor must name the same object. */
    unsigned char *theirs = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, got, 0);
    if (theirs == MAP_FAILED) { printf("LXSCM: receiver mmap failed\n"); fflush(stdout); return 10; }
    for (int i = 0; i < SHM_SIZE; i += 4096)
        if (theirs[i] != 0xC3) { printf("LXSCM: page %d not visible through the passed fd\n", i / 4096); fflush(stdout); return 11; }

    /* ...and the sharing has to go BOTH ways: write through the receiver's
     * mapping, see it through the sender's. A private copy would pass every
     * check above and fail this one. */
    theirs[4096] = 0x5A; theirs[SHM_SIZE - 1] = 0x7E;
    if (mine[4096] != 0x5A || mine[SHM_SIZE - 1] != 0x7E) {
        printf("LXSCM: writes are NOT shared -- the mapping is a private copy\n"); fflush(stdout); return 12;
    }

    printf("LXSCM: memfd + SCM_RIGHTS + MAP_SHARED -- fd %d passed as %d, %d KiB shared both ways\n",
           mfd, got, SHM_SIZE / 1024);
    fflush(stdout);
    close(got);

    /* ---- AND NOW ACROSS TWO PROCESSES, WHICH IS THE CASE THAT MATTERS -----
     *
     * Everything above happens inside ONE process: socketpair(), sendmsg on
     * sv[0], recvmsg on sv[1], both ends owned by the same address space. So
     * the "received" descriptor referred to the same memfd object by
     * construction, and the mapping came out of the same page tables -- which
     * means this file has never once tested the thing it is named for.
     *
     * Firefox's case is the other one: the parent creates a memfd, forks and
     * execs a content process, hands the descriptor over a socket, and the
     * CHILD maps it in a different address space. Its rendered frames travel
     * that way, and the content area on screen is blank while the content
     * process is demonstrably alive -- so whether two address spaces really
     * see one set of physical pages is precisely the open question.
     *
     * Both directions are checked, because a receiver that gets a private
     * copy passes every read and fails only when the parent looks for the
     * child's write. (M2107) */
    int xv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, xv) != 0) {
        printf("LXSCM: cross-process socketpair failed\n"); fflush(stdout); return 13; }
    int xfd = memfd_create("lxscm-cross", 0);
    if (xfd < 0 || ftruncate(xfd, SHM_SIZE) != 0) {
        printf("LXSCM: cross-process memfd failed\n"); fflush(stdout); return 14; }
    unsigned char *pm = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, xfd, 0);
    if (pm == MAP_FAILED) { printf("LXSCM: cross-process parent mmap failed\n"); fflush(stdout); return 15; }
    memset(pm, 0xA7, SHM_SIZE);                      /* what the child must SEE */

    pid_t kid = fork();
    if (kid < 0) { printf("LXSCM: cross-process fork failed\n"); fflush(stdout); return 16; }
    if (kid == 0) {
        close(xv[0]); close(xfd);                    /* the child must rely on the PASSED fd only */
        char cb[CMSG_SPACE(sizeof(int))]; char one = 0;
        struct iovec iv = { &one, 1 };
        struct msghdr m = { 0 };
        m.msg_iov = &iv; m.msg_iovlen = 1; m.msg_control = cb; m.msg_controllen = sizeof cb;
        if (recvmsg(xv[1], &m, 0) != 1) _exit(21);
        struct cmsghdr *c = CMSG_FIRSTHDR(&m);
        if (!c || c->cmsg_type != SCM_RIGHTS) _exit(22);
        int rfd; memcpy(&rfd, CMSG_DATA(c), sizeof rfd);
        if (rfd < 0) _exit(23);
        unsigned char *cm = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, rfd, 0);
        if (cm == MAP_FAILED) _exit(24);
        for (int i = 0; i < SHM_SIZE; i += 4096) if (cm[i] != 0xA7) _exit(25);
        if (cm[SHM_SIZE - 1] != 0xA7) _exit(26);
        cm[0] = 0x11; cm[8192] = 0x22; cm[SHM_SIZE - 1] = 0x33;   /* what the PARENT must see */
        if (write(xv[1], "d", 1) != 1) _exit(27);
        _exit(0);
    }
    close(xv[1]);
    {   char one = 'x';
        struct iovec iv = { &one, 1 };
        char cb[CMSG_SPACE(sizeof(int))]; memset(cb, 0, sizeof cb);
        struct msghdr m = { 0 };
        m.msg_iov = &iv; m.msg_iovlen = 1; m.msg_control = cb; m.msg_controllen = sizeof cb;
        struct cmsghdr *c = CMSG_FIRSTHDR(&m);
        c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &xfd, sizeof xfd);
        if (sendmsg(xv[0], &m, 0) != 1) { printf("LXSCM: cross-process sendmsg failed\n"); fflush(stdout); return 17; }
    }
    { char d; if (read(xv[0], &d, 1) != 1) printf("LXSCM: the child never reported back\n"); }
    int xs = 0; waitpid(kid, &xs, 0);
    if (!WIFEXITED(xs) || WEXITSTATUS(xs) != 0) {
        printf("LXSCM: FAIL a FORKED child could not use the passed memfd (exit %d: "
               "21=recvmsg 22=no SCM_RIGHTS 23=bad fd 24=mmap 25/26=parent's bytes NOT visible)\n",
               WIFEXITED(xs) ? WEXITSTATUS(xs) : -1);
        fflush(stdout); return 18;
    }
    printf("LXSCM: ok   a FORKED child mapped the passed memfd and saw the parent's bytes\n");
    if (pm[0] != 0x11 || pm[8192] != 0x22 || pm[SHM_SIZE - 1] != 0x33) {
        printf("LXSCM: FAIL the child's writes are NOT visible to the parent (%02x %02x %02x) -- "
               "two address spaces, two different sets of physical pages\n",
               pm[0], pm[8192], pm[SHM_SIZE - 1]);
        fflush(stdout); return 19;
    }
    printf("LXSCM: ok   and the parent sees the CHILD's writes -- one memfd, one set of pages\n");

    /* ---- AND A SOCKET, WHICH IS A DIFFERENT FD TYPE ENTIRELY --------------
     *
     * Everything above passes a MEMFD. Gecko's content process does not get
     * its compositor connection from a memfd: the parent creates a socketpair,
     * forks and execs the child, and sends one END OF THE SOCKET over the
     * existing channel with SCM_RIGHTS. The child then opens PCompositorBridge
     * and PWebRenderBridge on it and sends its display lists through -- which
     * is how page content reaches the compositor and appears on screen.
     *
     * In this kernel a socket is fd type 12 and a memfd is type 3, and they
     * take different branches on both the send and the receive side of
     * app_scm_send (the per-type reference in M2104 has a case for each). So a
     * passing memfd test says nothing at all about this, and Firefox paints its
     * chrome while the content area stays blank -- which is exactly the open
     * symptom.
     *
     * The test is end to end on purpose: the child must WRITE through the
     * passed endpoint and the parent must read it out of the other end. An
     * endpoint that arrives as a descriptor but is not connected to anything
     * passes every check short of that one. (M2111) */
    int pv[2], cv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pv) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, cv) != 0) {
        printf("LXSCM: socket-passing socketpair failed\n"); fflush(stdout); return 20; }
    pid_t k2 = fork();
    if (k2 < 0) { printf("LXSCM: socket-passing fork failed\n"); fflush(stdout); return 21; }
    if (k2 == 0) {
        close(pv[0]); close(cv[0]); close(cv[1]);
        char cb[CMSG_SPACE(sizeof(int))]; char one = 0;
        struct iovec iv = { &one, 1 };
        struct msghdr m = { 0 };
        m.msg_iov = &iv; m.msg_iovlen = 1; m.msg_control = cb; m.msg_controllen = sizeof cb;
        if (recvmsg(pv[1], &m, 0) != 1) _exit(31);
        struct cmsghdr *c = CMSG_FIRSTHDR(&m);
        if (!c || c->cmsg_type != SCM_RIGHTS) _exit(32);
        int ep; memcpy(&ep, CMSG_DATA(c), sizeof ep);
        if (ep < 0) _exit(33);
        /* Use it as a socket: talk through the endpoint we were handed. */
        if (write(ep, "HELLO-FROM-CHILD", 16) != 16) _exit(34);
        char back[8];
        if (read(ep, back, 5) != 5) _exit(35);
        if (memcmp(back, "REPLY", 5) != 0) _exit(36);
        _exit(0);
    }
    close(pv[1]);
    {   char one = 'e';
        struct iovec iv = { &one, 1 };
        char cb[CMSG_SPACE(sizeof(int))]; memset(cb, 0, sizeof cb);
        struct msghdr m = { 0 };
        m.msg_iov = &iv; m.msg_iovlen = 1; m.msg_control = cb; m.msg_controllen = sizeof cb;
        struct cmsghdr *c = CMSG_FIRSTHDR(&m);
        c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &cv[1], sizeof cv[1]);
        if (sendmsg(pv[0], &m, 0) != 1) {
            printf("LXSCM: FAIL sendmsg of a SOCKET endpoint failed (errno %d)\n", errno);
            fflush(stdout); return 22;
        }
    }
    close(cv[1]);                                 /* the child owns it now */
    {   char buf[17]; memset(buf, 0, sizeof buf);
        long n = read(cv[0], buf, 16);
        if (n != 16 || memcmp(buf, "HELLO-FROM-CHILD", 16) != 0) {
            printf("LXSCM: FAIL the child wrote through the passed SOCKET and the parent read "
                   "%ld byte(s) '%s' -- the endpoint arrived as a descriptor but is not "
                   "connected\n", n, buf);
            fflush(stdout); return 23;
        }
        printf("LXSCM: ok   a FORKED child wrote through a SOCKET endpoint passed over SCM_RIGHTS\n");
        if (write(cv[0], "REPLY", 5) != 5) { printf("LXSCM: FAIL reply write\n"); fflush(stdout); return 24; }
    }
    { int s2 = 0; waitpid(k2, &s2, 0);
      if (!WIFEXITED(s2) || WEXITSTATUS(s2) != 0) {
          printf("LXSCM: FAIL the child could not use the passed socket (exit %d: 31=recvmsg "
                 "32=no SCM_RIGHTS 33=bad fd 34=write 35/36=no reply back)\n",
                 WIFEXITED(s2) ? WEXITSTATUS(s2) : -1);
          fflush(stdout); return 25;
      } }
    printf("LXSCM: ok   and the reply travelled back the other way -- a passed socket is bidirectional\n");
    close(pv[0]); close(cv[0]);
    printf("LXSCM: CROSS OK\n");
    fflush(stdout);
    close(xfd); close(xv[0]); close(mfd); close(sv[0]); close(sv[1]);
    return 0;
}
