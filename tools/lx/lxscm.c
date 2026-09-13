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
    close(got); close(mfd); close(sv[0]); close(sv[1]);
    return 0;
}
