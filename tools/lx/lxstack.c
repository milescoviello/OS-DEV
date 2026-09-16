/* lxstack.c -- A THREAD MUST BE ABLE TO FIND ITS OWN STACK.
 *
 * A garbage collector scans thread stacks CONSERVATIVELY: every machine word
 * between the stack pointer and the stack base is treated as a possible
 * pointer and keeps its object alive. So the bounds are not diagnostic
 * information, they are a correctness input -- report them wrong and live
 * objects are collected, the heap fills with stale pointers, and the crash
 * arrives seconds later inside the marker on a value like 0x9000900090 with
 * nothing to connect it to the cause.
 *
 * JavaScriptCore gets those bounds from pthread_getattr_np, which for the
 * MAIN thread means /proc/self/maps and RLIMIT_STACK, and for any other
 * thread means the attributes the kernel let pthread_create record. Both are
 * the kernel's answers, and neither is checked by anything else here.
 *
 * The assertion is the one a collector needs: the reported range must contain
 * an address that is demonstrably on the stack.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/resource.h>
#include <errno.h>
#include <stdint.h>

static int fails;

static void check(const char *who, uintptr_t local) {
    pthread_attr_t at;
    void *base = NULL; size_t size = 0;
    int rc = pthread_getattr_np(pthread_self(), &at);
    if (rc != 0) {
        printf("LXSTACK: FAIL %s: pthread_getattr_np failed (%s) -- a collector then scans"
               " whatever pthread_attr_init left behind\n", who, strerror(rc));
        fails++;
        return;
    }
    if (pthread_attr_getstack(&at, &base, &size) != 0) {
        printf("LXSTACK: FAIL %s: pthread_attr_getstack failed\n", who); fails++;
        pthread_attr_destroy(&at); return;
    }
    pthread_attr_destroy(&at);
    uintptr_t lo = (uintptr_t)base, hi = lo + size;
    printf("LXSTACK: %s reports stack %p-%p (%lu KiB); a local is at %p\n",
           who, (void *)lo, (void *)hi, (unsigned long)(size / 1024), (void *)local);
    if (!size)              { printf("LXSTACK: FAIL %s: a zero-sized stack\n", who); fails++; return; }
    if (local < lo || local >= hi) {
        printf("LXSTACK: FAIL %s: the reported range does NOT contain its own local variable"
               " -- every conservative root on this stack is invisible\n", who);
        fails++;
        return;
    }
    /* ...and the stack pointer itself, which is what the scan starts from. */
    uintptr_t sp = (uintptr_t)__builtin_frame_address(0);
    if (sp < lo || sp >= hi) {
        printf("LXSTACK: FAIL %s: the reported range does not contain the frame pointer %p\n",
               who, (void *)sp);
        fails++;
    }
}

static void *thread_main(void *p) {
    volatile int onstack = 0x5A;
    (void)p; (void)onstack;
    check("a pthread", (uintptr_t)&onstack);
    return NULL;
}

int main(void) {
    volatile int onstack = 0x5A;
    (void)onstack;

    struct rlimit rl;
    if (getrlimit(RLIMIT_STACK, &rl) == 0)
        printf("LXSTACK: RLIMIT_STACK = %lu KiB\n", (unsigned long)(rl.rlim_cur / 1024));
    else
        printf("LXSTACK: FAIL getrlimit(RLIMIT_STACK) failed\n"), fails++;

    check("the main thread", (uintptr_t)&onstack);

    pthread_t t;
    if (pthread_create(&t, NULL, thread_main, NULL) != 0) {
        printf("LXSTACK: FAIL pthread_create\n"); fails++;
    } else pthread_join(t, NULL);

    /* A deep frame, because the interesting half of the range is the far end:
     * a base that is right and a size that is too small looks fine at main(). */
    {
        volatile char pad[512 * 1024];
        memset((void *)pad, 0, sizeof pad);
        check("a frame 512 KiB deep", (uintptr_t)&pad[0]);
    }

    printf(fails ? "LXSTACK: FAILED\n" : "LXSTACK: OK\n");
    return fails ? 1 : 0;
}
