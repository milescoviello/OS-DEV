/*
 * ulib.c — the userspace runtime + a minimal libc.
 *
 * This is the beginning of a real libc: program startup (`_start` → `main`),
 * system-call wrappers, and a few string/IO helpers. It links into every user
 * program. Everything ultimately goes through `int 0x80`.
 */
#include "ulib.h"
#include "syscall.h"

static long do_syscall(long n, long a1, long a2, long a3) {
    long ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3)
                     : "memory");
    return ret;
}

/* 4-argument variant: the 4th arg goes in r10 (Linux-style), which the kernel
 * reads as r->r10. Used by syscalls like fallocate(path, mode, offset, len). */
static long do_syscall4(long n, long a1, long a2, long a3, long a4) {
    long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10)
                     : "memory");
    return ret;
}

/* 5-argument variant: the 5th arg goes in r8 too (Linux-style), which the
 * kernel reads as r->r8. Used by setsockopt/getsockopt (M1554). */
static long do_syscall5(long n, long a1, long a2, long a3, long a4, long a5) {
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8)
                     : "memory");
    return ret;
}

long sys_write(int fd, const void *buf, unsigned long len) {
    return do_syscall(SYS_write, fd, (long)buf, (long)len);
}
long sys_read(int fd, void *buf, unsigned long len) {
    return do_syscall(SYS_read, fd, (long)buf, (long)len);
}
void sys_exit(int code) { do_syscall(SYS_exit, code, 0, 0); }
int  sys_getpid(void)   { return (int)do_syscall(SYS_getpid, 0, 0, 0); }
long sys_fork(void)     { return do_syscall(SYS_fork, 0, 0, 0); }
long sys_waitpid(int pid, int *status) { return do_syscall(SYS_waitpid, pid, (long)status, 0); }
long sys_exec(const char *name, const char *arg) { return do_syscall(SYS_exec, (long)name, (long)arg, 0); }
long sys_unshare(void) { return do_syscall(SYS_unshare, 0, 0, 0); }
long sys_singlestep(int n) { return do_syscall(SYS_singlestep, n, 0, 0); }
long sys_seccomp(int nr) { return do_syscall(SYS_seccomp, nr, 0, 0); }
long sys_seccomp_wait(int childpid, unsigned long *ev4) { return do_syscall(SYS_seccomp_wait, childpid, (long)ev4, 0); }
long sys_seccomp_reply(int childpid, int run_real, long retval) { return do_syscall(SYS_seccomp_reply, childpid, run_real, retval); }

/* fswait: block until one of `n` paths is readable (or timeout_ms; -1 = forever).
 * Packs the path array into a NUL-separated buffer for the kernel. M1125. */
long sys_signalfd(unsigned mask) { return do_syscall(SYS_signalfd, (long)mask, 0, 0); }
long sys_fanotify_serve(void) { return do_syscall(SYS_fanotify_serve, 0, 0, 0); }
long sys_fanotify_wait(char *namebuf, int max) { return do_syscall(SYS_fanotify_wait, 0, (long)namebuf, max); }
long sys_fanotify_provide(const void *content, unsigned long len) { return do_syscall(SYS_fanotify_provide, (long)content, (long)len, 0); }
long sys_io_uring_enter(void *ring) { return do_syscall(SYS_io_uring_enter, (long)ring, 0, 0); }
long sys_mseal(void *addr, unsigned long len) { return do_syscall(SYS_mseal, (long)addr, (long)len, 0); }
void *sys_mmap_file(const char *path, unsigned long len, int shared) { return (void *)do_syscall(SYS_mmap_file, (long)path, (long)len, shared); }
int   sys_msync(void *addr, unsigned long len) { return (int)do_syscall(SYS_msync, (long)addr, (long)len, 0); }
long sys_clone(void *fn, void *stack, void *arg) { return do_syscall(SYS_clone, (long)fn, (long)stack, (long)arg); }
int  sys_gettid(void) { return (int)do_syscall(SYS_gettid, 0, 0, 0); }
void sys_thread_exit(void) { do_syscall(SYS_thread_exit, 0, 0, 0); for (;;) {} }
int  sys_join(int tid) { return (int)do_syscall(SYS_join, tid, 0, 0); }
void sys_set_tls(void *base) { do_syscall(SYS_set_tls, (long)base, 0, 0); }   /* set %fs base for thread-local storage */
long sys_set_robust_list(void *r) { return do_syscall(SYS_set_robust_list, (long)r, 0, 0); }
long sys_overlay(const char *lower, const char *upper) { return do_syscall(SYS_overlay, (long)lower, (long)upper, 0); }

/* robust-mutex helpers (M1141). The lock word holds the owner's tid (0 = free),
 * with FUTEX_OWNER_DIED set if the previous owner died holding it. A thread
 * records its held locks in its robust_t (registered via sys_set_robust_list) so
 * the kernel can release them on the thread's behalf if it dies. */
static void robust_add(robust_t *r, void *m) { if (r && r->n < ROBUST_MAX) r->held[r->n++] = m; }
static void robust_rm(robust_t *r, void *m) {
    if (!r) return;
    for (int i = 0; i < r->n; i++) if (r->held[i] == m) { r->held[i] = r->held[--r->n]; return; }
}
/* Lock a robust mutex. Returns 0, or 1 (EOWNERDEAD) if the previous owner died
 * holding it — the caller now owns the lock and should treat the protected data
 * as needing recovery. `r` is this thread's robust list (0 to skip robustness). */
int rmutex_lock(volatile int *m, robust_t *r) {
    int tid = sys_gettid();
    for (;;) {
        int old = *m;
        if (old == 0) {
            if (__sync_val_compare_and_swap(m, 0, tid) == 0) { robust_add(r, (void *)m); return 0; }
            continue;
        }
        if (old & FUTEX_OWNER_DIED) {                       /* previous owner died -> recover */
            if (__sync_val_compare_and_swap(m, old, tid) == old) { robust_add(r, (void *)m); return 1; }
            continue;
        }
        sys_futex((void *)m, FUTEX_WAIT, old, -1);          /* held by a live owner -> wait */
    }
}
void rmutex_unlock(volatile int *m, robust_t *r) {
    robust_rm(r, (void *)m);
    __sync_lock_release(m);                                 /* word = 0 */
    sys_futex((void *)m, FUTEX_WAKE, 1, -1);
}

/* A futex-backed mutex (M1139): the lock word is 0 = free, 1 = held. Uncontended
 * lock/unlock is a single atomic with no syscall; only a waiter sleeps. */
void mutex_lock(volatile int *m) {
    while (__sync_lock_test_and_set(m, 1) != 0)      /* atomic xchg; old != 0 => was held */
        sys_futex((void *)m, FUTEX_WAIT, 1, -1);         /* sleep while it stays held */
}
void mutex_unlock(volatile int *m) {
    __sync_lock_release(m);                          /* store 0 + barrier */
    sys_futex((void *)m, FUTEX_WAKE, 1, -1);             /* wake one waiter */
}

/* If a thread function returns, land here and end the thread cleanly. */
static void thread_exit_stub(void) { sys_thread_exit(); }

/* thread_spawn: run fn(arg) in a NEW thread that shares this address space.
 * Allocates a stack, lays a return-to-thread_exit_stub at the top (so a thread
 * that simply returns ends cleanly) with the SysV alignment a fresh frame wants,
 * and clones. Returns the new thread id, or -1. M1138. */
int thread_spawn(void (*fn)(void *), void *arg) {
    unsigned long sz = 64 * 1024;
    char *stk = (char *)sys_mmap(sz);
    if (!stk) return -1;
    unsigned long top = ((unsigned long)stk + sz) & ~15UL;   /* 16-align the stack top */
    top -= 8;                                                /* callee entry wants rsp%16==8 */
    *(void **)top = (void *)thread_exit_stub;                /* fn's `ret` lands here */
    return (int)sys_clone((void *)fn, (void *)top, arg);
}
long sys_uffd_register(void *addr, unsigned long len) { return do_syscall(SYS_uffd_register, (long)addr, (long)len, 0); }
long sys_uffd_read(void) { return do_syscall(SYS_uffd_read, 0, 0, 0); }
long sys_uffd_copy(void *addr, const void *data, unsigned long len) { return do_syscall(SYS_uffd_copy, (long)addr, (long)data, (long)len); }
long sys_tcp_serve(int port, const void *resp, unsigned long resp_len, void *reqbuf, unsigned long reqmax) {
    long ret;
    register long r10 __asm__("r10") = (long)reqbuf;     /* 4th + 5th args via r10/r8 (like sys_http) */
    register long r8  __asm__("r8")  = (long)reqmax;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"((long)SYS_tcp_serve), "D"((long)port), "S"((long)resp),
                       "d"((long)resp_len), "r"(r10), "r"(r8)
                     : "memory");
    return ret;
}
long sys_tcp_accept(int port, void *reqbuf, unsigned long reqmax) { return do_syscall(SYS_tcp_accept, (long)port, (long)reqbuf, (long)reqmax); }
long sys_tcp_respond(const void *resp, unsigned long resp_len) { return do_syscall(SYS_tcp_respond, (long)resp, (long)resp_len, 0); }
long sys_ws_open(const char *url, int *status) { return do_syscall(SYS_ws_open, (long)url, (long)status, 0); }
long sys_ws_serve(int port, char *lastmsg, int lastmax, int *nframes) { return do_syscall4(SYS_ws_serve, port, (long)lastmsg, lastmax, (long)nframes); }
long sys_ws_exchange(int id, const char *sendbuf, int sendtot, char *out, int outmax, int *nrecv) {
    long ret;                                            /* 6 args: id,sendbuf,sendtot in rdi/rsi/rdx; out,outmax,nrecv via r10/r8/r9 */
    register long r10 __asm__("r10") = (long)out;
    register long r8  __asm__("r8")  = (long)outmax;
    register long r9  __asm__("r9")  = (long)nrecv;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"((long)SYS_ws_exchange), "D"((long)id), "S"((long)sendbuf),
                       "d"((long)sendtot), "r"(r10), "r"(r8), "r"(r9)
                     : "memory");
    return ret;
}
long sys_fswait(const char *const *paths, int n, long timeout_ms) {
    char buf[512]; int p = 0;
    if (n < 1 || n > 8) return -1;
    for (int i = 0; i < n; i++) {
        const char *s = paths[i];
        while (*s && p < (int)sizeof buf - 2) buf[p++] = *s++;
        buf[p++] = 0;
    }
    return do_syscall(SYS_fswait, (long)buf, n, timeout_ms);
}
long sys_poll(struct pollfd *fds, int nfds, long timeout_ms) {
    return do_syscall(SYS_poll, (long)fds, nfds, timeout_ms);
}
long sys_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    return do_syscall5(SYS_select, nfds, (long)readfds, (long)writefds, (long)exceptfds, (long)timeout);
}
long sys_ppoll(struct pollfd *fds, int nfds, long timeout_ms, unsigned sigmask) {
    return do_syscall4(SYS_ppoll, (long)fds, nfds, timeout_ms, sigmask);
}
long sys_splice(int in_fd, int out_fd, unsigned long len) {
    return do_syscall(SYS_splice, in_fd, out_fd, (long)len);
}
long sys_tee(int in_fd, int out_fd, unsigned long len) {
    return do_syscall(SYS_tee, in_fd, out_fd, (long)len);
}
int sys_memfd_create(const char *name, int flags) {
    return (int)do_syscall(SYS_memfd_create, (long)name, flags, 0);
}
long sys_memfd_seal(int fd, unsigned seals) {
    return do_syscall(SYS_memfd_seal, fd, (long)seals, 0);
}
long sys_ftruncate(int fd, long len) {
    return do_syscall(SYS_ftruncate, fd, len, 0);
}
long sys_fsync(int fd) { return do_syscall(SYS_fsync, fd, 0, 0); }
long sys_fdatasync(int fd) { return do_syscall(SYS_fdatasync, fd, 0, 0); }
void sys_sync(void) { do_syscall(SYS_sync, 0, 0, 0); }
long sys_sync_file_range(int fd, unsigned long offset, unsigned long nbytes, unsigned flags) {
    return do_syscall4(SYS_sync_file_range, fd, (long)offset, (long)nbytes, flags);
}
long sys_list(void *buf, unsigned long len) {
    /* leading 0 so buf/len land in the same registers (rsi/rdx) the kernel
     * reads them from — matching the write/readfile arg layout. */
    return do_syscall(SYS_list, 0, (long)buf, (long)len);
}
long sys_readfile(const char *name, void *buf, unsigned long len) {
    return do_syscall(SYS_readfile, (long)name, (long)buf, (long)len);
}
long sys_writefile(const char *name, const void *buf, unsigned long len) {
    return do_syscall(SYS_writefile, (long)name, (long)buf, (long)len);
}
long sys_delete(const char *name) { return do_syscall(SYS_delete, (long)name, 0, 0); }
long sys_time(void *buf, unsigned long len) {
    return do_syscall(SYS_time, 0, (long)buf, (long)len);
}
void sys_beep(int hz, int ms) { do_syscall(SYS_beep, hz, ms, 0); }
long sys_sysinfo(void *buf, unsigned long len) { return do_syscall(SYS_sysinfo, 0, (long)buf, (long)len); }
void sys_clear(void)  { do_syscall(SYS_clear, 0, 0, 0); }
void sys_setcolor(int color) { do_syscall(SYS_setcolor, color, 0, 0); }
void sys_reboot(void) { do_syscall(SYS_reboot, 0, 0, 0); }
void sys_poweroff(void) { do_syscall(SYS_poweroff, 0, 0, 0); }
long sys_kill(int pid) { return do_syscall(SYS_kill, pid, 0, 0); }
long sys_ping(void) { return do_syscall(SYS_ping, 0, 0, 0); }
long sys_ping_host(const char *host) { return do_syscall(SYS_pinghost, (long)host, 0, 0); }
long sys_netinfo(void *buf, unsigned long len) { return do_syscall(SYS_netinfo, (long)buf, (long)len, 0); }
long sys_dhcp(void) { return do_syscall(SYS_dhcp, 0, 0, 0); }
long sys_cas_store(const void *buf, unsigned long len, void *hash32) { return do_syscall(SYS_cas_store, (long)buf, (long)len, (long)hash32); }
long sys_cas_fetch(const void *hash32, void *buf, unsigned long max) { return do_syscall(SYS_cas_fetch, (long)hash32, (long)buf, (long)max); }
long sys_tftp(const char *filename, void *buf, unsigned long max) { return do_syscall(SYS_tftp, (long)filename, (long)buf, (long)max); }
long sys_madvise(void *addr, unsigned long len, int advice) { return do_syscall(SYS_madvise, (long)addr, (long)len, advice); }
long sys_process_madvise(int pidfd, void *addr, unsigned long len, int advice) { return do_syscall4(SYS_process_madvise, pidfd, (long)addr, (long)len, advice); }
long sys_mincore(void *addr, unsigned long len, unsigned char *vec) { return do_syscall(SYS_mincore, (long)addr, (long)len, (long)vec); }
long sys_mlock(void *addr, unsigned long len) { return do_syscall(SYS_mlock, (long)addr, (long)len, 0); }
long sys_munlock(void *addr, unsigned long len) { return do_syscall(SYS_munlock, (long)addr, (long)len, 0); }
long sys_mlockall(int flags) { return do_syscall(SYS_mlockall, flags, 0, 0); }       /* pin all current/future pages; 0/-1 (M1283) */
long sys_munlockall(void) { return do_syscall(SYS_munlockall, 0, 0, 0); }            /* unpin all pages; 0/-1 (M1283) */
long sys_acpi(int what) { return do_syscall(SYS_acpi, what, 0, 0); }                  /* ACPI AML namespace query (M1284) */
unsigned long sys_aslr(int pid) { return (unsigned long)do_syscall(SYS_aslr, pid, 0, 0); }  /* ASLR mmap base of pid (0=self) (M1287) */
long sys_getrusage(int who, struct rusage *ru) { return do_syscall(SYS_getrusage, who, (long)ru, 0); }
long sys_fiemap(const char *path, struct fiemap_extent *out, int max) { return do_syscall(SYS_fiemap, (long)path, (long)out, max); }
long sys_fallocate(const char *path, int mode, unsigned long offset, unsigned long len) { return do_syscall4(SYS_fallocate, (long)path, mode, (long)offset, (long)len); }
long sys_mq_open(const char *name, int maxmsg, int msgsize) { return do_syscall(SYS_mq_open, (long)name, maxmsg, msgsize); }
long sys_mq_unlink(const char *name) { return do_syscall(SYS_mq_unlink, (long)name, 0, 0); }
long sys_mq_send(int idx, const void *buf, unsigned long len, unsigned int prio) { return do_syscall4(SYS_mq_send, idx, (long)buf, (long)len, (long)prio); }
long sys_mq_receive(int idx, void *buf, unsigned long max, unsigned int *prio) { return do_syscall4(SYS_mq_receive, idx, (long)buf, (long)max, (long)prio); }
long sys_mq_getattr(int idx, struct mq_attr *out) { return do_syscall(SYS_mq_getattr, idx, (long)out, 0); }
long sys_mq_setattr(int idx, const struct mq_attr *newattr, struct mq_attr *oldattr) { return do_syscall(SYS_mq_setattr, idx, (long)newattr, (long)oldattr); }
long sys_semget(int key, int nsems, int flags) { return do_syscall(SYS_semget, key, nsems, flags); }
int  sys_sem_open(const char *name, int oflag, unsigned int value) { return (int)do_syscall(SYS_sem_open, (long)name, oflag, value); }
int  sys_sem_close(int idx) { return (int)do_syscall(SYS_sem_close, idx, 0, 0); }
int  sys_sem_unlink(const char *name) { return (int)do_syscall(SYS_sem_unlink, (long)name, 0, 0); }
int  sys_sem_wait(int idx) { return (int)do_syscall(SYS_sem_wait, idx, 0, 0); }
int  sys_sem_trywait(int idx) { return (int)do_syscall(SYS_sem_trywait, idx, 0, 0); }
int  sys_sem_post(int idx) { return (int)do_syscall(SYS_sem_post, idx, 0, 0); }
int  sys_sem_getvalue(int idx, int *out) { return (int)do_syscall(SYS_sem_getvalue, idx, (long)out, 0); }
long sys_semop(int semid, struct sembuf *sops, unsigned nsops) { return do_syscall(SYS_semop, semid, (long)sops, (long)nsops); }
long sys_semctl(int semid, int semnum, int cmd, int arg) { return do_syscall4(SYS_semctl, semid, semnum, cmd, arg); }
long sys_msgget(int key, int flags) { return do_syscall(SYS_msgget, key, flags, 0); }
long sys_msgsnd(int id, const void *msgp, unsigned long sz, int flags) { return do_syscall4(SYS_msgsnd, id, (long)msgp, (long)sz, flags); }
long sys_msgrcv(int id, void *msgp, unsigned long sz, long mtyp) { return do_syscall4(SYS_msgrcv, id, (long)msgp, (long)sz, (long)mtyp); }
long sys_shmget(int key, unsigned long size, int flags) { return do_syscall(SYS_shmget, key, (long)size, flags); }
int  sys_msgctl(int id, int cmd) { return (int)do_syscall(SYS_msgctl, id, cmd, 0); }
int  sys_shmctl(int id, int cmd) { return (int)do_syscall(SYS_shmctl, id, cmd, 0); }
void *sys_shmat(int shmid) { long r = do_syscall(SYS_shmat, shmid, 0, 0); return r ? (void *)r : 0; }
long sys_shmdt(void *addr) { return do_syscall(SYS_shmdt, (long)addr, 0, 0); }
long sys_process_vm_read(int pid, unsigned long raddr, void *buf, unsigned long len) { return do_syscall4(SYS_process_vm_read, pid, (long)raddr, (long)buf, (long)len); }
long sys_ptrace(long req, int pid, unsigned long addr, unsigned long data) { return do_syscall4(SYS_ptrace, req, pid, (long)addr, (long)data); }
long sys_bpf_trace(const void *prog, unsigned long bytes) { return do_syscall(SYS_bpf_trace, (long)prog, (long)bytes, 0); }
unsigned long sys_bpf_map_get(unsigned idx) { return (unsigned long)do_syscall(SYS_bpf_map_get, (long)idx, 0, 0); }
long sys_process_vm_write(int pid, unsigned long raddr, const void *buf, unsigned long len) { return do_syscall4(SYS_process_vm_write, pid, (long)raddr, (long)buf, (long)len); }
int  sys_unix_listen(const char *path) { return (int)do_syscall(SYS_unix_listen, (long)path, 0, 0); }
int  sys_unix_connect(const char *path) { return (int)do_syscall(SYS_unix_connect, (long)path, 0, 0); }
int  sys_unix_accept(int lid) { return (int)do_syscall(SYS_unix_accept, lid, 0, 0); }
long sys_unix_send(int ep, const void *buf, unsigned long len) { return do_syscall(SYS_unix_send, ep, (long)buf, (long)len); }
long sys_unix_recv(int ep, void *buf, unsigned long max) { return do_syscall(SYS_unix_recv, ep, (long)buf, (long)max); }
int  sys_unix_close(int ep) { return (int)do_syscall(SYS_unix_close, ep, 0, 0); }
int  sys_unix_wait_any(const int *eps, int n) { return (int)do_syscall(SYS_unix_wait_any, (long)eps, n, 0); }
int  sys_unix_shutdown(int ep, int how)      { return (int)do_syscall(SYS_unix_shutdown, ep, how, 0); }
int  sys_unix_unlisten(int lid)              { return (int)do_syscall(SYS_unix_unlisten, lid, 0, 0); }
int  sys_socketpair(int *sv) { return (int)do_syscall(SYS_socketpair, (long)sv, 0, 0); }
int  sys_nice(int nice) { return (int)do_syscall(SYS_nice, nice, 0, 0); }
int  sys_sched_setscheduler(int policy, int rt_priority) { return (int)do_syscall(SYS_sched_setscheduler, policy, rt_priority, 0); }
int  sys_sched_get_priority_max(int policy) { return (int)do_syscall(SYS_sched_get_priority_max, policy, 0, 0); }
int  sys_sched_get_priority_min(int policy) { return (int)do_syscall(SYS_sched_get_priority_min, policy, 0, 0); }
int  sys_sched_getscheduler(void) { return (int)do_syscall(SYS_sched_getscheduler, 0, 0, 0); }
int  sys_sched_getparam(void) { return (int)do_syscall(SYS_sched_getparam, 0, 0, 0); }
long sys_sched_rr_get_interval(long *sec, long *nsec) { return do_syscall(SYS_sched_rr_get_interval, (long)sec, (long)nsec, 0); }
long sys_statx(const char *path, struct statx *st) { return do_syscall(SYS_statx, (long)path, (long)st, 0); }
int  sys_tcgetattr(struct termios *t) { return (int)do_syscall(SYS_tcgetattr, (long)t, 0, 0); }
int  sys_tcsetattr(const struct termios *t) { return (int)do_syscall(SYS_tcsetattr, (long)t, 0, 0); }
int  sys_tcflush(int queue_selector) { return (int)do_syscall(SYS_tcflush, queue_selector, 0, 0); }
int  sys_tcdrain(void) { return (int)do_syscall(SYS_tcdrain, 0, 0, 0); }
int  sys_setpgid(int pid, int pgid) { return (int)do_syscall(SYS_setpgid, pid, pgid, 0); }
int  sys_getpgid(int pid) { return (int)do_syscall(SYS_getpgid, pid, 0, 0); }
int  sys_getsid(int pid)  { return (int)do_syscall(SYS_getsid, pid, 0, 0); }
int  sys_setsid(void) { return (int)do_syscall(SYS_setsid, 0, 0, 0); }
int  sys_tcsetpgrp(int pgid) { return (int)do_syscall(SYS_tcsetpgrp, pgid, 0, 0); }
int  sys_tcgetpgrp(void) { return (int)do_syscall(SYS_tcgetpgrp, 0, 0, 0); }
int  sys_killpg(int pgid, int signo) { return (int)do_syscall(SYS_killpg, pgid, signo, 0); }
int  sys_flock(const char *path, int op) { return (int)do_syscall(SYS_flock, (long)path, op, 0); }
long sys_getrlimit(int resource, struct rlimit *rl) { return do_syscall(SYS_getrlimit, resource, (long)rl, 0); }
long sys_setrlimit(int resource, struct rlimit *rl) { return do_syscall(SYS_setrlimit, resource, (long)rl, 0); }
long sys_alarm(unsigned long ticks) { return do_syscall(SYS_alarm, (long)ticks, 0, 0); }
long sys_setitimer(unsigned long delay_ticks, unsigned long interval_ticks) { return do_syscall(SYS_setitimer, (long)delay_ticks, (long)interval_ticks, 0); }
long sys_getitimer(unsigned long *remain_ticks, unsigned long *interval_ticks) { return do_syscall(SYS_getitimer, (long)remain_ticks, (long)interval_ticks, 0); }
long sys_sntp(void) { return do_syscall(SYS_sntp, 0, 0, 0); }
long sys_swapout(void *addr, unsigned long len) { return do_syscall(SYS_swapout, (long)addr, (long)len, 0); }
long sys_losetup(const char *path) { return do_syscall(SYS_losetup, (long)path, 0, 0); }
void *sys_shm_open(const char *name, unsigned long size) { return (void *)do_syscall(SYS_shm_open, (long)name, (long)size, 0); }
long  sys_shm_unlink(const char *name) { return do_syscall(SYS_shm_unlink, (long)name, 0, 0); }
long sys_futex(void *uaddr, int op, int val, long timeout_ms) { return do_syscall4(SYS_futex, (long)uaddr, op, val, timeout_ms); }
long sys_apps(void *buf, unsigned long len) { return do_syscall(SYS_apps, (long)buf, (long)len, 0); }
long sys_spawn(const char *name) { return do_syscall(SYS_spawn, (long)name, 0, 0); }
long sys_spawn_arg(const char *name, const char *arg) { return do_syscall(SYS_spawn, (long)name, (long)arg, 0); }
long sys_browse(const char *url) { return do_syscall(SYS_browse, (long)url, 0, 0); }
long sys_mkdir(const char *path) { return do_syscall(SYS_mkdir, (long)path, 0, 0); }
long sys_chdir(const char *path) { return do_syscall(SYS_chdir, (long)path, 0, 0); }
long sys_fchdir(int fd) { return do_syscall(SYS_fchdir, fd, 0, 0); }
long sys_tree(void *buf, unsigned long len) { return do_syscall(SYS_tree, 0, (long)buf, (long)len); }
long sys_ps(void *buf, unsigned long len) { return do_syscall(SYS_ps, 0, (long)buf, (long)len); }
long sys_font(void *buf, unsigned long len) { return do_syscall(SYS_font, 0, (long)buf, (long)len); }
long sys_loadimg(const char *name, void *buf, int cw, int ch, int *outwh) {
    return do_syscall4(SYS_loadimg, (long)name, (long)buf, ((long)cw << 16) | ((long)ch & 0xFFFF), (long)outwh);
}
long sys_history(void *buf, unsigned long len) { return do_syscall(SYS_history, 0, (long)buf, (long)len); }
int  sys_pollkey(void) { return (int)do_syscall(SYS_pollkey, 0, 0, 0); }
long sys_df(void *buf, unsigned long len) { return do_syscall(SYS_df, 0, (long)buf, (long)len); }
long sys_lspci(void *buf, unsigned long len) { return do_syscall(SYS_lspci, (long)buf, (long)len, 0); }
long sys_lsblk(void *buf, unsigned long len) { return do_syscall(SYS_lsblk, (long)buf, (long)len, 0); }
long sys_mounts(void *buf, unsigned long len) { return do_syscall(SYS_mounts, (long)buf, (long)len, 0); }
long sys_getrandom(void *buf, unsigned long len) { return do_syscall(SYS_getrandom, (long)buf, (long)len, 0); }
int  sys_pledge(const char *promises) { return (int)do_syscall(SYS_pledge, (long)promises, 0, 0); }
int  sys_unveil(const char *path, const char *perms) { return (int)do_syscall(SYS_unveil, (long)path, (long)perms, 0); }
int  sys_symlink(const char *linkpath, const char *target) { return (int)do_syscall(SYS_symlink, (long)linkpath, (long)target, 0); }
int  sys_link(const char *oldpath, const char *newpath) { return (int)do_syscall(SYS_link, (long)oldpath, (long)newpath, 0); }
int  sys_rename(const char *oldpath, const char *newpath) { return (int)do_syscall(SYS_rename, (long)oldpath, (long)newpath, 0); }
int  sys_renameat2(const char *oldpath, const char *newpath, int flags) { return (int)do_syscall(SYS_renameat2, (long)oldpath, (long)newpath, flags); }
long sys_readlink(const char *path, void *buf, unsigned long size) { return do_syscall(SYS_readlink, (long)path, (long)buf, (long)size); }
int  sys_sched_yield(void) { return (int)do_syscall(SYS_sched_yield, 0, 0, 0); }
int  sys_nanosleep(long sec, long nsec) { return (int)do_syscall(SYS_nanosleep, sec, nsec, 0); }
int  sys_clock_nanosleep(int clockid, int flags, long sec, long nsec) { return (int)do_syscall4(SYS_clock_nanosleep, clockid, flags, sec, nsec); }
long sys_clock_settime(int clockid, long sec, long nsec) { return do_syscall(SYS_clock_settime, clockid, sec, nsec); }  /* set the wall clock (CLOCK_REALTIME); 0/-1 (M1280) */
long sys_clock_getres(int clockid) { return do_syscall(SYS_clock_getres, clockid, 0, 0); }
int  sys_udp_send(const unsigned char *ip4, unsigned short dport, unsigned short sport, const void *buf, unsigned len) {
    return (int)do_syscall4(SYS_udp_send, (long)ip4, ((unsigned long)dport << 16) | sport, (long)buf, (long)len);
}
long sys_udp_recv(unsigned short sport, void *buf, unsigned max, void *from) {
    return do_syscall4(SYS_udp_recv, sport, (long)buf, (long)max, (long)from);
}
int  sys_raw_send(const void *frame, unsigned len) { return (int)do_syscall(SYS_raw_send, (long)frame, (long)len, 0); }
long sys_raw_recv(void *buf, unsigned max) { return do_syscall(SYS_raw_recv, (long)buf, (long)max, 0); }
long sys_insmod(void) { return do_syscall(SYS_insmod, 0, 0, 0); }
long sys_insmod_path(const char *path) { return do_syscall(SYS_insmod_path, (long)path, 0, 0); }
/* Run a LINUX binary from OS-DEV's own shell (M1988). `args` is a plain string,
 * split on spaces by the kernel; returns the new pid, or -1. */
long sys_linux_run(const char *path, const char *args) { return do_syscall(SYS_linux_run, (long)path, (long)args, 0); }
int  sys_rmmod(const char *name) { return (int)do_syscall(SYS_rmmod, (long)name, 0, 0); }
int  sys_sendfd(int ep, int fd) { return (int)do_syscall(SYS_sendfd, ep, fd, 0); }
int  sys_recvfd(int ep) { return (int)do_syscall(SYS_recvfd, ep, 0, 0); }
int  sys_inotify_init(void) { return (int)do_syscall(SYS_inotify_init, 0, 0, 0); }
int  sys_inotify_add_watch(int fd, const char *path, unsigned int mask) { return (int)do_syscall(SYS_inotify_add_watch, fd, (long)path, (long)mask); }
int  sys_inotify_rm_watch(int fd, int wd) { return (int)do_syscall(SYS_inotify_rm_watch, fd, wd, 0); }
int  sys_socket(int domain, int type) { return (int)do_syscall(SYS_socket, domain, type, 0); }
int  sys_sock_bind(int fd, int port) { return (int)do_syscall(SYS_sock_bind, fd, port, 0); }
long sys_sendto(int fd, const unsigned char *ip4, int port, const void *buf, unsigned len) {
    unsigned char ad[6] = { ip4[0], ip4[1], ip4[2], ip4[3], (unsigned char)(port & 0xFF), (unsigned char)((port >> 8) & 0xFF) };
    return do_syscall4(SYS_sendto, fd, (long)ad, (long)buf, (long)len);
}
long sys_recvfrom(int fd, void *buf, unsigned max, void *from) { return do_syscall4(SYS_recvfrom, fd, (long)buf, (long)max, (long)from); }
int  sys_connect(int fd, const unsigned char *ip4, int port) {
    unsigned char ad[6] = { ip4[0], ip4[1], ip4[2], ip4[3], (unsigned char)(port & 0xFF), (unsigned char)((port >> 8) & 0xFF) };
    return (int)do_syscall(SYS_connect, fd, (long)ad, 0);
}
int  sys_setsockopt(int fd, int level, int optname, const void *optval, unsigned optlen) {
    return (int)do_syscall5(SYS_setsockopt, fd, level, optname, (long)optval, optlen);
}
int  sys_getsockopt(int fd, int level, int optname, void *optval, unsigned *optlen) {
    return (int)do_syscall5(SYS_getsockopt, fd, level, optname, (long)optval, (long)optlen);
}
/* getsockname/getpeername (M1560): unpack the same 6-byte {ip[4],port} wire
 * format sys_connect() packs, so callers get plain (ip4[4], *port) instead
 * of a raw buffer -- symmetric with how sys_connect() takes them. */
int  sys_getsockname(int fd, unsigned char ip4_out[4], int *port_out) {
    unsigned char ad[6];
    int rc = (int)do_syscall(SYS_getsockname, fd, (long)ad, 0);
    if (rc == 0) {
        if (ip4_out) for (int i = 0; i < 4; i++) ip4_out[i] = ad[i];
        if (port_out) *port_out = ad[4] | (ad[5] << 8);
    }
    return rc;
}
int  sys_getpeername(int fd, unsigned char ip4_out[4], int *port_out) {
    unsigned char ad[6];
    int rc = (int)do_syscall(SYS_getpeername, fd, (long)ad, 0);
    if (rc == 0) {
        if (ip4_out) for (int i = 0; i < 4; i++) ip4_out[i] = ad[i];
        if (port_out) *port_out = ad[4] | (ad[5] << 8);
    }
    return rc;
}

/* ===================================================================== *
 *  Userspace dynamic linker (M1263): dlopen()/dlsym() over an ELF .so.
 *  A real ring-3 ld.so — reads a shared object from the filesystem, maps its
 *  PT_LOAD segments into a fresh mmap region at a runtime base, applies the
 *  ELF relocations (RELATIVE / GLOB_DAT / JUMP_SLOT / 64) so the GOT points at
 *  the loaded code, mprotects the image executable, and resolves exported
 *  symbols from .dynsym. Eager binding (no lazy PLT resolver needed).
 * ===================================================================== */
typedef struct { unsigned char e_ident[16]; unsigned short e_type, e_machine; unsigned e_version;
    unsigned long e_entry, e_phoff, e_shoff; unsigned e_flags;
    unsigned short e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx; } dl_ehdr;
typedef struct { unsigned p_type, p_flags; unsigned long p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align; } dl_phdr;
typedef struct { unsigned sh_name, sh_type; unsigned long sh_flags, sh_addr, sh_offset, sh_size;
    unsigned sh_link, sh_info; unsigned long sh_addralign, sh_entsize; } dl_shdr;
typedef struct { unsigned st_name; unsigned char st_info, st_other; unsigned short st_shndx; unsigned long st_value, st_size; } dl_sym;
typedef struct { unsigned long r_offset, r_info; long r_addend; } dl_rela;

struct dlobj { unsigned char *base; const dl_sym *dynsym; const char *dynstr; int nsym; int ok; };

/* M1539: cross-object symbol resolution. Every object dlopen() has EVER
 * loaded lives here (not just the one currently being loaded), so a later
 * .so's undefined (SHN_UNDEF) imports can be resolved against an earlier
 * .so's exports -- real multi-library linking, not just each .so's own
 * self-contained relocations (which is all M1263's original dlopen did:
 * every S was computed straight from the CURRENT object's own dynsym, so an
 * import from a different object silently resolved to that object's OWN
 * base+0 instead of ever being looked up elsewhere). Load order matters, the
 * same as classic Unix dynamic linking: a dependency must be dlopen()'d
 * before the library that imports from it. */
static struct dlobj g_dlobjs[4];
static int g_dlnobj;

static unsigned long dl_resolve_import(const char *name) {
    for (int oi = 0; oi < g_dlnobj; oi++) {
        struct dlobj *o = &g_dlobjs[oi];
        if (!o->ok || !o->dynsym) continue;
        for (int i = 0; i < o->nsym; i++) {
            if (o->dynsym[i].st_shndx == 0 || !o->dynsym[i].st_value) continue;  /* not a real export */
            const char *n = o->dynstr + o->dynsym[i].st_name;
            const char *a = n, *b = name;
            while (*a && *a == *b) { a++; b++; }
            if (*a == 0 && *b == 0) return (unsigned long)(o->base + o->dynsym[i].st_value);
        }
    }
    return 0;
}

void *dlopen(const char *path) {
    if (g_dlnobj >= 4) return 0;
    /* File buffer must be MALLOC'd (pre-faulted heap), not mmap'd: sys_readfile
     * validates the user buffer's PTEs, and a fresh demand-paged mmap region has
     * no present pages yet -> validation would reject it. */
    unsigned char *file = (unsigned char *)malloc(256 * 1024);
    if (!file) return 0;
    long flen = sys_readfile(path, file, 256 * 1024);
    if (flen < (long)sizeof(dl_ehdr)) return 0;
    unsigned long ulen = (unsigned long)flen;   /* everything below is bounds-checked against this, not trusted from the ELF header alone */
    dl_ehdr *eh = (dl_ehdr *)file;
    if (!(eh->e_ident[0] == 0x7f && eh->e_ident[1] == 'E' && eh->e_ident[2] == 'L' && eh->e_ident[3] == 'F')) return 0;
    if (eh->e_type != 3 /*ET_DYN*/ || eh->e_machine != 62 /*x86-64*/) return 0;
    /* A short/truncated read (e.g. a transient disk hiccup mid-transfer) can
     * still pass the checks above -- the ELF magic + a plausible-looking
     * header live in the first few bytes, well within even a partial read --
     * but every OFFSET the rest of this function dereferences (phdrs, PT_LOAD
     * segment bytes, shdrs, .dynsym/.dynstr) must actually be covered by what
     * was really read, or this ends up copying/relocating garbage from the
     * tail of an uninitialized malloc buffer instead of failing cleanly. */
    if (eh->e_phoff + (unsigned long)eh->e_phnum * sizeof(dl_phdr) > ulen) return 0;

    /* image span = max(p_vaddr + p_memsz) over PT_LOAD */
    dl_phdr *ph = (dl_phdr *)(file + eh->e_phoff);
    unsigned long span = 0;
    for (int i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == 1) {
            if (ph[i].p_offset + ph[i].p_filesz > ulen) return 0;
            unsigned long e = ph[i].p_vaddr + ph[i].p_memsz; if (e > span) span = e;
        }
    if (!span || span > 16 * 1024 * 1024) return 0;
    unsigned char *base = (unsigned char *)sys_mmap(span);         /* the runtime image (RW; mprotect'd X below) */
    if (!base) return 0;
    for (int i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == 1)
            for (unsigned long b = 0; b < ph[i].p_filesz; b++) base[ph[i].p_vaddr + b] = file[ph[i].p_offset + b];

    /* find .dynsym + .dynstr via section headers (the .so isn't stripped) */
    if (eh->e_shoff + (unsigned long)eh->e_shnum * sizeof(dl_shdr) > ulen) return 0;
    dl_shdr *sh = (dl_shdr *)(file + eh->e_shoff);
    const dl_sym *dynsym = 0; const char *dynstr = 0; int nsym = 0;
    for (int i = 0; i < eh->e_shnum; i++)
        if (sh[i].sh_type == 11 /*SHT_DYNSYM*/) {
            if (sh[i].sh_offset + sh[i].sh_size > ulen) return 0;
            if (sh[i].sh_link >= (unsigned)eh->e_shnum || sh[sh[i].sh_link].sh_offset + sh[sh[i].sh_link].sh_size > ulen) return 0;
            dynsym = (const dl_sym *)(file + sh[i].sh_offset);
            nsym = (int)(sh[i].sh_size / sizeof(dl_sym));
            dynstr = (const char *)(file + sh[sh[i].sh_link].sh_offset);
            break;
        }

    /* apply relocations (every SHT_RELA section): point the GOT at loaded code.
     * M1539: a symbol UNDEFINED in this object's own dynsym (st_shndx==0) is an
     * IMPORT -- resolve it against every object dlopen()'d so far, instead of
     * the old (silently wrong for real imports) "always use this object's own
     * dynsym[sidx].st_value" -- which for an undefined symbol is always 0, so
     * it used to resolve straight to this object's own base with no warning. */
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != 4 /*SHT_RELA*/) continue;
        if (sh[i].sh_offset + sh[i].sh_size > ulen) return 0;
        const dl_rela *rel = (const dl_rela *)(file + sh[i].sh_offset);
        int nr = (int)(sh[i].sh_size / sizeof(dl_rela));
        for (int r = 0; r < nr; r++) {
            unsigned sidx = (unsigned)(rel[r].r_info >> 32);
            unsigned typ  = (unsigned)(rel[r].r_info & 0xffffffffu);
            unsigned long S = 0;
            if (dynsym && sidx < (unsigned)nsym) {
                if (dynsym[sidx].st_shndx != 0 && dynsym[sidx].st_value)
                    S = (unsigned long)base + dynsym[sidx].st_value;          /* defined in THIS object */
                else
                    S = dl_resolve_import(dynstr + dynsym[sidx].st_name);    /* import: search earlier objects */
            }
            unsigned long *slot = (unsigned long *)(base + rel[r].r_offset);
            if (typ == 8 /*RELATIVE*/)                    *slot = (unsigned long)base + (unsigned long)rel[r].r_addend;
            else if (typ == 6 /*GLOB_DAT*/ || typ == 7 /*JUMP_SLOT*/) *slot = S;
            else if (typ == 1 /*64*/)                     *slot = S + (unsigned long)rel[r].r_addend;
        }
    }

    /* W^X hardening: mprotect each PT_LOAD segment to its OWN p_flags (like
     * elf_load_dyn does for the app's own executable in kernel/elf.c), not a
     * single blanket R|W|X for the whole image -- a .so's read-only/code
     * segments have no business being writable, or its data segment being
     * executable. ELF's PF_R/PF_W/PF_X (4/2/1) don't share sys_mprotect's own
     * prot encoding (1/2/4), so this translates rather than passing p_flags
     * through directly. Page-align each segment's own range so adjoining
     * segments' differing permissions on a shared page can't clobber one
     * another (the same segment-boundary care a page-granular real ld.so
     * takes). */
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != 1) continue;
        int prot = 1;                                       /* PF_R is implicit for any real segment, as elf_load_dyn also assumes */
        if (ph[i].p_flags & 2) prot |= 2;                    /* PF_W -> W */
        if (ph[i].p_flags & 1) prot |= 4;                    /* PF_X -> X */
        unsigned long start = ph[i].p_vaddr & ~4095ul;
        unsigned long end   = (ph[i].p_vaddr + ph[i].p_memsz + 4095ul) & ~4095ul;
        sys_mprotect(base + start, end - start, prot);
    }
    g_dlobjs[g_dlnobj].base = base; g_dlobjs[g_dlnobj].dynsym = dynsym; g_dlobjs[g_dlnobj].dynstr = dynstr;
    g_dlobjs[g_dlnobj].nsym = nsym; g_dlobjs[g_dlnobj].ok = 1;
    return &g_dlobjs[g_dlnobj++];
}

void *dlsym(void *handle, const char *name) {
    struct dlobj *o = (struct dlobj *)handle;
    if (!o || !o->ok || !o->dynsym) return 0;
    for (int i = 0; i < o->nsym; i++) {
        const char *n = o->dynstr + o->dynsym[i].st_name;
        const char *a = n, *b = name;
        while (*a && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0 && o->dynsym[i].st_value) return (void *)(o->base + o->dynsym[i].st_value);
    }
    return 0;
}
long sys_times(struct tms *t) { return do_syscall(SYS_times, (long)t, 0, 0); }
int  sys_uname(struct utsname *u) { return (int)do_syscall(SYS_uname, (long)u, 0, 0); }
int  sys_getppid(void) { return (int)do_syscall(SYS_getppid, 0, 0, 0); }
int  sys_getuid(void) { return (int)do_syscall(SYS_getuid, 0, 0, 0); }
int  sys_getgid(void) { return (int)do_syscall(SYS_getgid, 0, 0, 0); }
int  sys_geteuid(void) { return (int)do_syscall(SYS_geteuid, 0, 0, 0); }
int  sys_getegid(void) { return (int)do_syscall(SYS_getegid, 0, 0, 0); }
int  sys_sethostname(const char *buf, unsigned long len) { return (int)do_syscall(SYS_sethostname, (long)buf, (long)len, 0); }
int  sys_gethostname(char *buf, unsigned long len) { return (int)do_syscall(SYS_gethostname, (long)buf, (long)len, 0); }
int  sys_getentropy(void *buf, unsigned long len) { return (int)do_syscall(SYS_getentropy, (long)buf, (long)len, 0); }
int  sys_getpriority(int which, int who) { return (int)do_syscall(SYS_getpriority, which, who, 0); }
int  sys_setpriority(int which, int who, int prio) { return (int)do_syscall(SYS_setpriority, which, who, prio); }
int  sys_pipe2(int *fds, int flags) { return (int)do_syscall(SYS_pipe2, (long)fds, flags, 0); }
int  sys_statfs(const char *path, struct statvfs *sv) { return (int)do_syscall(SYS_statfs, (long)path, (long)sv, 0); }
int  sys_chmod(const char *path, unsigned mode) { return (int)do_syscall(SYS_chmod, (long)path, (long)mode, 0); }
int  sys_fchmod(int fd, unsigned mode) { return (int)do_syscall(SYS_fchmod, fd, (long)mode, 0); }
int  sys_eventfd(unsigned initval, int flags) { return (int)do_syscall(SYS_eventfd, (long)initval, flags, 0); }
int  sys_chown(const char *path, int uid, int gid) { return (int)do_syscall(SYS_chown, (long)path, uid, gid); }
int  sys_fchown(int fd, int uid, int gid) { return (int)do_syscall(SYS_fchown, fd, uid, gid); }
int  sys_sched_getcpu(void) { return (int)do_syscall(SYS_sched_getcpu, 0, 0, 0); }
int  sys_sched_setaffinity(unsigned int mask) { return (int)do_syscall(SYS_sched_setaffinity, mask, 0, 0); }
unsigned int sys_sched_getaffinity(void) { return (unsigned int)do_syscall(SYS_sched_getaffinity, 0, 0, 0); }
long sys_getcwd(char *buf, unsigned long size) { return do_syscall(SYS_getcwd, (long)buf, (long)size, 0); }
int  sys_openat(int dirfd, const char *path, int flags) { return (int)do_syscall(SYS_openat, dirfd, (long)path, flags); }
int  sys_unlinkat(int dirfd, const char *path, int flags) { return (int)do_syscall(SYS_unlinkat, dirfd, (long)path, flags); }
int  sys_mkdirat(int dirfd, const char *path, int mode) { return (int)do_syscall(SYS_mkdirat, dirfd, (long)path, mode); }
int  sys_fstatat(int dirfd, const char *path, struct statx *st, int flags) { return (int)do_syscall4(SYS_fstatat, dirfd, (long)path, (long)st, flags); }
int  sys_fchmodat(int dirfd, const char *path, unsigned mode) { return (int)do_syscall(SYS_fchmodat, dirfd, (long)path, mode); }
int  sys_fchownat(int dirfd, const char *path, int uid, int gid) { return (int)do_syscall4(SYS_fchownat, dirfd, (long)path, uid, gid); }
int  sys_symlinkat(const char *target, int newdirfd, const char *linkpath) { return (int)do_syscall(SYS_symlinkat, (long)target, newdirfd, (long)linkpath); }
int  sys_linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) { return (int)do_syscall4(SYS_linkat, olddirfd, (long)oldpath, newdirfd, (long)newpath); }
long sys_readlinkat(int dirfd, const char *path, void *buf, unsigned long size) { return do_syscall4(SYS_readlinkat, dirfd, (long)path, (long)buf, (long)size); }
long sys_prlimit(int pid, int resource, unsigned long newval, int do_set) { return do_syscall4(SYS_prlimit, pid, resource, (long)newval, do_set); }
int  sys_timerfd_create(void) { return (int)do_syscall(SYS_timerfd_create, 0, 0, 0); }
long sys_timerfd_settime(int fd, long delay_ms, long interval_ms) { return do_syscall(SYS_timerfd_settime, fd, delay_ms, interval_ms); }
long sys_fcntl(int fd, int cmd, long arg) { return do_syscall(SYS_fcntl, fd, cmd, arg); }
int  sys_dup3(int oldfd, int newfd, int flags) { return (int)do_syscall(SYS_dup3, oldfd, newfd, flags); }
long sys_close_range(unsigned lo, unsigned hi, int flags) { return do_syscall(SYS_close_range, (long)lo, (long)hi, flags); }
long sys_sendfile(int out_fd, int in_fd, long *off, unsigned long count) { return do_syscall4(SYS_sendfile, out_fd, in_fd, (long)off, (long)count); }
int  sys_epoll_create1(int flags) { return (int)do_syscall(SYS_epoll_create1, flags, 0, 0); }
int  sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev) { return (int)do_syscall4(SYS_epoll_ctl, epfd, op, fd, (long)ev); }
int  sys_epoll_wait(int epfd, struct epoll_event *evs, int maxevents, long timeout) { return (int)do_syscall4(SYS_epoll_wait, epfd, (long)evs, maxevents, timeout); }
int  sys_epoll_pwait(int epfd, struct epoll_event *evs, int maxevents, long timeout, unsigned sigmask) { return (int)do_syscall5(SYS_epoll_pwait, epfd, (long)evs, maxevents, timeout, sigmask); }
int  sys_pidfd_open(int pid, int flags) { return (int)do_syscall(SYS_pidfd_open, pid, flags, 0); }
int  sys_pidfd_send_signal(int pidfd, int sig) { return (int)do_syscall(SYS_pidfd_send_signal, pidfd, sig, 0); }
int  sys_pidfd_getfd(int pidfd, int targetfd, int flags) { return (int)do_syscall(SYS_pidfd_getfd, pidfd, targetfd, flags); }  /* dup another process's fd; new fd/-1 (M1281) */
long sys_getdents64(void *buf, unsigned long max, int start) { return do_syscall(SYS_getdents64, (long)buf, (long)max, start); }
int  sys_access(const char *path, int amode) { return (int)do_syscall(SYS_access, (long)path, amode, 0); }
int  sys_faccessat2(int dirfd, const char *path, int amode, int flags) { return (int)do_syscall4(SYS_faccessat2, dirfd, (long)path, amode, flags); }
long sys_prctl(int option, unsigned long arg2) { return do_syscall(SYS_prctl, option, (long)arg2, 0); }
long sys_set_tid_address(void *tidptr) { return do_syscall(SYS_set_tid_address, (long)tidptr, 0, 0); }
int  sys_waitid(int idtype, int id, struct siginfo *si, int options) { return (int)do_syscall4(SYS_waitid, idtype, id, (long)si, options); }
int  sys_truncate(const char *path, long len) { return (int)do_syscall(SYS_truncate, (long)path, len, 0); }
int  sys_utimens(const char *path, long atime, long mtime) { return (int)do_syscall(SYS_utimens, (long)path, atime, mtime); }
int  sys_futimens(int fd, long atime, long mtime) { return (int)do_syscall(SYS_futimens, fd, atime, mtime); }
int  sys_utimensat(int dirfd, const char *path, long atime, long mtime) { return (int)do_syscall4(SYS_utimensat, dirfd, (long)path, atime, mtime); }
int  sys_jail(const char *prog, const char *promises, const char *path) { return (int)do_syscall(SYS_jail, (long)prog, (long)promises, (long)path); }
long sys_find(const char *want, void *buf, unsigned long len) { return do_syscall(SYS_find, (long)want, (long)buf, (long)len); }
long sys_sha1(const char *name, void *hexbuf, unsigned long max) { return do_syscall(SYS_sha1, (long)name, (long)hexbuf, (long)max); }
long sys_sha256(const char *name, void *hexbuf, unsigned long max) { return do_syscall(SYS_sha256, (long)name, (long)hexbuf, (long)max); }
long sys_sha512(const char *name, void *hexbuf, unsigned long max) { return do_syscall(SYS_sha512, (long)name, (long)hexbuf, (long)max); }
long sys_crypt(const char *name, const char *pass) { return do_syscall(SYS_crypt, (long)name, (long)pass, 0); }
long sys_js(const char *src, void *out, unsigned long max) { return do_syscall(SYS_js, (long)src, (long)out, (long)max); }
long sys_screenshot(const char *name) { return do_syscall(SYS_screenshot, (long)name, 0, 0); }
long sys_setwall(const char *name) { return do_syscall(SYS_setwall, (long)name, 0, 0); }
long sys_savebmp(const char *name, const void *pixels, int w, int h) {
    long ret;
    register long r10 __asm__("r10") = (long)h;         /* 4th arg via r10 */
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"((long)SYS_savebmp), "D"((long)name), "S"((long)pixels),
                       "d"((long)w), "r"(r10)
                     : "memory");
    return ret;
}
long sys_gunzip(const char *insrc, const char *outname) { return do_syscall(SYS_gunzip, (long)insrc, (long)outname, 0); }
long sys_gzip(const char *insrc, const char *outname) { return do_syscall(SYS_gzip, (long)insrc, (long)outname, 0); }
long sys_unzip(const char *zipname) { return do_syscall(SYS_unzip, (long)zipname, 0, 0); }
long sys_untar(const char *tarname) { return do_syscall(SYS_untar, (long)tarname, 0, 0); }
void sys_sleep(int ms) { do_syscall(SYS_sleep, ms, 0, 0); }
void *sbrk(long inc) { return (void *)do_syscall(SYS_sbrk, inc, 0, 0); }
void *sys_mmap(unsigned long len) { long r = do_syscall(SYS_mmap, (long)len, 0, 0); return r ? (void *)r : 0; }
void *sys_mmap_huge(unsigned long len) { long r = do_syscall(SYS_mmap_huge, (long)len, 0, 0); return r ? (void *)r : 0; }
void *sys_ringbuf(unsigned long len) { long r = do_syscall(SYS_ringbuf, (long)len, 0, 0); return r ? (void *)r : 0; }
int   sys_mprotect(void *addr, unsigned long len, int prot) { return (int)do_syscall(SYS_mprotect, (long)addr, (long)len, prot); }
int   sys_bind(const char *from, const char *to) { return (int)do_syscall(SYS_bind, (long)from, (long)to, 0); }
long  sys_munmap(void *addr, unsigned long len) { return do_syscall(SYS_munmap, (long)addr, (long)len, 0); }
void *sys_mremap(void *old_addr, unsigned long old_len, unsigned long new_len, int flags) {
    long r = do_syscall4(SYS_mremap, (long)old_addr, (long)old_len, (long)new_len, flags);
    return (r == -1) ? (void *)0 : (void *)r;   /* -1 -> NULL for easy checking */
}
long sys_copy_file_range(const char *src, const char *dst, unsigned long len) { return do_syscall(SYS_copy_file_range, (long)src, (long)dst, (long)len); }
long sys_setxattr(const char *path, const char *name, const void *val, unsigned long vlen) { return do_syscall4(SYS_setxattr, (long)path, (long)name, (long)val, (long)vlen); }
long sys_getxattr(const char *path, const char *name, void *out, unsigned long max) { return do_syscall4(SYS_getxattr, (long)path, (long)name, (long)out, (long)max); }
long sys_listxattr(const char *path, char *out, unsigned long max) { return do_syscall(SYS_listxattr, (long)path, (long)out, (long)max); }
long sys_removexattr(const char *path, const char *name) { return do_syscall(SYS_removexattr, (long)path, (long)name, 0); }
long sys_fsetxattr(int fd, const char *name, const void *val, unsigned long vlen) { return do_syscall4(SYS_fsetxattr, fd, (long)name, (long)val, (long)vlen); }
long sys_fgetxattr(int fd, const char *name, void *out, unsigned long max) { return do_syscall4(SYS_fgetxattr, fd, (long)name, (long)out, (long)max); }
long sys_flistxattr(int fd, char *out, unsigned long max) { return do_syscall(SYS_flistxattr, fd, (long)out, (long)max); }
long sys_fremovexattr(int fd, const char *name) { return do_syscall(SYS_fremovexattr, fd, (long)name, 0); }
int  sys_pty_open(void) { return (int)do_syscall(SYS_pty_open, 0, 0, 0); }
long sys_pty_read(int id, void *buf, unsigned long max) { return do_syscall(SYS_pty_read, id, (long)buf, (long)max); }
long sys_pty_write(int id, const void *buf, unsigned long len) { return do_syscall(SYS_pty_write, id, (long)buf, (long)len); }
int  sys_pty_close(int id) { return (int)do_syscall(SYS_pty_close, id, 0, 0); }
int  sys_pty_ctl(int id, int cmd, int arg) { return (int)do_syscall(SYS_pty_ctl, id, cmd, arg); }
int  sys_pipe(int fds[2]) { return (int)do_syscall(SYS_pipe, (long)fds, 0, 0); }
long sys_fdread(int fd, void *buf, unsigned long max) { return do_syscall(SYS_fdread, fd, (long)buf, (long)max); }
long sys_fdwrite(int fd, const void *buf, unsigned long len) { return do_syscall(SYS_fdwrite, fd, (long)buf, (long)len); }
int  sys_fdclose(int fd) { return (int)do_syscall(SYS_fdclose, fd, 0, 0); }
int  sys_dup2(int oldfd, int newfd) { return (int)do_syscall(SYS_dup2, oldfd, newfd, 0); }
int  sys_dup(int fd) { return (int)do_syscall(SYS_dup, fd, 0, 0); }
int  sys_mkfifo(const char *path) { return (int)do_syscall(SYS_mkfifo, (long)path, 0, 0); }
int  sys_fifo_open(const char *path, int write) { return (int)do_syscall(SYS_fifo_open, (long)path, write, 0); }
int  sys_open(const char *path) { return (int)do_syscall(SYS_open, (long)path, O_RDONLY, 0); }
int  sys_open_mode(const char *path, int flags) { return (int)do_syscall(SYS_open, (long)path, flags, 0); }
long sys_lseek(int fd, long off, int whence) { return do_syscall(SYS_lseek, fd, off, whence); }
long sys_pread(int fd, void *buf, unsigned long max, long off) { return do_syscall4(SYS_pread, fd, (long)buf, (long)max, off); }
long sys_pwrite(int fd, const void *buf, unsigned long len, long off) { return do_syscall4(SYS_pwrite, fd, (long)buf, (long)len, off); }
long sys_readv(int fd, struct iovec *iov, int iovcnt) { return do_syscall(SYS_readv, fd, (long)iov, iovcnt); }
long sys_writev(int fd, const struct iovec *iov, int iovcnt) { return do_syscall(SYS_writev, fd, (long)iov, iovcnt); }
long sys_preadv(int fd, struct iovec *iov, int iovcnt, long off) { return do_syscall4(SYS_preadv, fd, (long)iov, iovcnt, off); }
long sys_pwritev(int fd, const struct iovec *iov, int iovcnt, long off) { return do_syscall4(SYS_pwritev, fd, (long)iov, iovcnt, off); }
long sys_seccomp_filter(const void *prog, unsigned long bytes) { return do_syscall(SYS_seccomp_filter, (long)prog, (long)bytes, 0); }
/* Restorer trampoline: a signal handler returns HERE; we ask the kernel to
 * restore the pre-signal context (which iretq's elsewhere, so this never
 * returns). The kernel is told this address via sys_signal's 3rd arg. */
void sig_trampoline(void) { do_syscall(SYS_sigreturn, 0, 0, 0); for (;;) { } }
long sys_signal(int signo, void (*handler)(int)) { return do_syscall(SYS_signal, signo, (long)handler, (long)sig_trampoline); }
long sys_sigaction(int signo, void (*h)(int, struct ksiginfo *, struct kmcontext *), int flags) {
    return do_syscall4(SYS_sigaction, signo, (long)h, (long)sig_trampoline, flags);
}
void sys_raise(int signo) { do_syscall(SYS_raise, signo, 0, 0); }
long sys_sigqueue(int pid, int signo, unsigned long value) { return do_syscall(SYS_sigqueue, pid, signo, (long)value); }
long sys_timer_create(int clockid, int signo, unsigned long value) { return do_syscall(SYS_timer_create, clockid, signo, (long)value); }
long sys_timer_settime(int id, int flags, unsigned long value_ms, unsigned long interval_ms) { return do_syscall4(SYS_timer_settime, id, flags, (long)value_ms, (long)interval_ms); }
long sys_timer_gettime(int id) { return do_syscall(SYS_timer_gettime, id, 0, 0); }
long sys_timer_delete(int id) { return do_syscall(SYS_timer_delete, id, 0, 0); }
unsigned long sys_hpet(int what) { return (unsigned long)do_syscall(SYS_hpet, what, 0, 0); }  /* 0=ns 1=hz 2=counter 3=present (M1273) */
long sys_ptsname(int fd) { return do_syscall(SYS_ptsname, fd, 0, 0); }  /* /dev/pts/<n> index for a /dev/ptmx master fd, or -1 (M1274) */
long sys_oom(int cmd, int arg) { return do_syscall(SYS_oom, cmd, arg, 0); }  /* 0=set self oom_adj 1=trigger kill(->pid) 2=score of pid (M1275) */
long sys_sigaltstack(void *ss_sp, unsigned long ss_size) { return do_syscall(SYS_sigaltstack, (long)ss_sp, (long)ss_size, 0); }  /* alternate signal stack for SA_ONSTACK; 0/-1 (M1276) */
unsigned sys_sigprocmask(int how, unsigned set) { return (unsigned)do_syscall(SYS_sigprocmask, how, (long)set, 0); }
unsigned sys_sigpending(void) { return (unsigned)do_syscall(SYS_sigpending, 0, 0, 0); }
int      sys_sigsuspend(unsigned mask) { return (int)do_syscall(SYS_sigsuspend, (long)mask, 0, 0); }
int      sys_pause(void) { return (int)do_syscall(SYS_pause, 0, 0, 0); }
unsigned long sys_uptime_ms(void) { return (unsigned long)do_syscall(SYS_uptime_ms, 0, 0, 0); }
int  sys_gfx_init(int w, int h) { return (int)do_syscall(SYS_gfx_init, w, h, 0); }
int  sys_gfx_blit(const void *pixels) { return (int)do_syscall(SYS_gfx_blit, (long)pixels, 0, 0); }
void sys_setkbmode(int raw) { do_syscall(SYS_setkbmode, raw, 0, 0); }
void sys_caret(int on) { do_syscall(SYS_caret, on, 0, 0); }
int  sys_clip_get(char *buf, int max) { return (int)do_syscall(SYS_clip_get, (long)buf, max, 0); }
void sys_clip_set(const char *buf, int len) { do_syscall(SYS_clip_set, (long)buf, len, 0); }
int  sys_getarg(char *buf, int max) { return (int)do_syscall(SYS_getarg, (long)buf, max, 0); }
int  sys_getkbevent(void) { return (int)do_syscall(SYS_getkbevent, 0, 0, 0); }
void sys_pcm(const void *frames, int nframes) { do_syscall(SYS_pcm, (long)frames, nframes, 0); }
long sys_playwav(const char *name) { return do_syscall(SYS_playwav, (long)name, 0, 0); }
int  sys_pcm_stream(const void *frames, int nframes) { return (int)do_syscall(SYS_pcm_stream, (long)frames, nframes, 0); }
int  sys_pcm_avail(void) { return (int)do_syscall(SYS_pcm_avail, 0, 0, 0); }
int  sys_mouse(int *x, int *y) {
    long v = do_syscall(SYS_mouse, 0, 0, 0);
    if (x) *x = (int)(short)(v & 0xFFFF);          /* sign-extend 16-bit (-1 = outside) */
    if (y) *y = (int)(short)((v >> 16) & 0xFFFF);
    return (int)((v >> 32) & 0x7);
}
void sys_mouse_rel(int *dx, int *dy) {
    long v = do_syscall(SYS_mouse_rel, 0, 0, 0);
    if (dx) *dx = (int)(v & 0xFFFFFFFF);
    if (dy) *dy = (int)((v >> 32) & 0xFFFFFFFF);
}
long sys_playbg(const char *name) { return do_syscall(SYS_playbg, (long)name, 0, 0); }
void sys_audiostop(void) { do_syscall(SYS_audiostop, 0, 0, 0); }
long sys_resolve(const char *host, void *buf, unsigned long len) {
    return do_syscall(SYS_resolve, (long)host, (long)buf, (long)len);
}
long sys_http(const char *host, const char *path, void *buf, unsigned long max) {
    long ret;
    register long r10 __asm__("r10") = (long)max;       /* 4th arg via r10 */
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"((long)SYS_http), "D"((long)host), "S"((long)path),
                       "d"((long)buf), "r"(r10)
                     : "memory");
    return ret;
}
long sys_https(const char *host, const char *path, void *buf, unsigned long max) {
    long ret;
    register long r10 __asm__("r10") = (long)max;       /* 4th arg via r10 */
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"((long)SYS_https), "D"((long)host), "S"((long)path),
                       "d"((long)buf), "r"(r10)
                     : "memory");
    return ret;
}

unsigned long ustrlen(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

/* Output capture: when a capture buffer is installed (via cap_begin), print()
 * appends to it instead of writing to fd 1. Used by the shell to grab one
 * command's output and feed it to the next stage of a pipe. Off by default —
 * g_capbuf is NULL for every other program and the whole boot, so print() is
 * byte-for-byte the plain sys_write path until a caller opts in. */
static char         *g_capbuf = 0;     /* destination buffer, or NULL = not capturing */
static unsigned long  g_caplen = 0;    /* bytes written so far */
static unsigned long  g_capmax = 0;    /* buffer capacity (incl. room for the NUL) */

/* Capture nests: cap_begin/cap_end save+restore the enclosing capture on a small
 * stack, so a $(...) command substitution that runs another $(...) (e.g.
 * `$(echo $(echo x))`) keeps the outer capture intact. 16 levels is far beyond
 * the shell's cmdsub recursion cap, so the stack never fills in practice. */
#define CAP_STACK 16
static char         *g_capstk_buf[CAP_STACK];
static unsigned long  g_capstk_len[CAP_STACK], g_capstk_max[CAP_STACK];
static int            g_capsp = 0;

void cap_begin(void) {                 /* capture print() into a growable heap buffer */
    if (g_capsp < CAP_STACK) {         /* push the enclosing capture (if any) so it survives this one */
        g_capstk_buf[g_capsp] = g_capbuf;
        g_capstk_len[g_capsp] = g_caplen;
        g_capstk_max[g_capsp] = g_capmax;
        g_capsp++;
    }
    g_capmax = 65536;
    g_capbuf = malloc(g_capmax);
    g_caplen = 0;
    if (g_capbuf) g_capbuf[0] = '\0';
    else g_capmax = 0;                 /* malloc failed: capture off, print() falls through to the screen */
}
char *cap_end(unsigned long *outlen) { /* stop; hand the malloc'd buffer to the caller (which frees it) */
    char *b = g_capbuf;
    if (outlen) *outlen = g_caplen;
    if (g_capsp > 0) {                 /* pop: restore the enclosing capture */
        g_capsp--;
        g_capbuf = g_capstk_buf[g_capsp];
        g_caplen = g_capstk_len[g_capsp];
        g_capmax = g_capstk_max[g_capsp];
    } else { g_capbuf = 0; g_caplen = 0; g_capmax = 0; }
    return b;
}
int cap_active(void) { return g_capbuf != 0; }   /* is print() being captured (a pipe stage or $())? — so commands can suppress decorative output that would pollute the data */

void print(const char *s) {
    if (g_capbuf) {                    /* capture mode: append, growing the buffer as output accumulates */
        unsigned long i = 0;
        while (s[i]) {
            if (g_caplen + 1 >= g_capmax) {            /* full: double the buffer (cap at 32MB) */
                if (g_capmax >= (32u << 20)) break;    /* refuse to grow past 32MB (truncate gracefully) */
                unsigned long nc = g_capmax << 1;
                char *nb = realloc(g_capbuf, nc);
                if (!nb) break;                        /* OOM: keep what we captured so far */
                g_capbuf = nb; g_capmax = nc;
            }
            g_capbuf[g_caplen++] = s[i++];
        }
        g_capbuf[g_caplen] = '\0';
        return;
    }
    sys_write(1, s, ustrlen(s));
}

int readline(char *buf, int max) {
    if (max <= 0) return 0;            /* no room even for a terminator (and max-1 would underflow) */
    long n = sys_read(0, buf, (unsigned long)(max - 1));
    if (n < 0) n = 0;                  /* read rejected (e.g. the kernel refused the buffer): empty line, never buf[-1] */
    if (n > 0 && buf[n - 1] == '\n')
        n--;                       /* drop the trailing newline */
    buf[n] = '\0';
    return (int)n;
}

int streq(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
}

int startswith(const char *s, const char *prefix) {
    while (*prefix) {
        if (*s != *prefix) return 0;
        s++; prefix++;
    }
    return 1;
}

/* clock_gettime — read the vDSO time page directly, no syscall (M1111). The page
 * is mapped read-only at VDSO_ADDR in every process; the kernel timer IRQ writes
 * it under a seqlock, so we retake the snapshot until `seq` is even and unchanged
 * across the read (the standard seqlock reader). Layout mirrors kernel vdso.h. */
#define VDSO_ADDR 0x80000000ull   /* keep in sync with kernel vdso.h */
struct ul_vdso_time {
    volatile unsigned seq;
    unsigned          hz;
    unsigned long     ticks;
    unsigned long     mono_ns;
    unsigned long     real_sec;
    unsigned          real_nsec;
    unsigned          _pad;
};
int clock_gettime(int clk, struct timespec *ts) {
    volatile struct ul_vdso_time *vt = (volatile struct ul_vdso_time *)VDSO_ADDR;
    unsigned long sec = 0, ns = 0;
    for (int tries = 0; tries < 256; tries++) {
        unsigned s1 = vt->seq;
        __asm__ volatile("" ::: "memory");
        if (clk == CLOCK_MONOTONIC) { sec = vt->mono_ns / 1000000000ull; ns = vt->mono_ns % 1000000000ull; }
        else                        { sec = vt->real_sec;                ns = vt->real_nsec; }
        __asm__ volatile("" ::: "memory");
        unsigned s2 = vt->seq;
        if (!(s1 & 1u) && s1 == s2) break;   /* stable, complete snapshot */
    }
    if (ts) { ts->tv_sec = (long)sec; ts->tv_nsec = (long)ns; }
    return 0;
}

/* ---- freestanding mem primitives -------------------------------------- *
 * Word-at-a-time so GCC's loop-pattern pass doesn't rewrite a naive byte loop
 * into a call to memcpy/memset (which would be infinite recursion), mirroring
 * the kernel's kernel/lib/string.c. GCC may emit calls to these from struct
 * copies / array inits even under -ffreestanding, so they must exist. */
typedef unsigned long uword_t;

void *memset(void *dst, int c, unsigned long n) {
    unsigned char *p = dst;
    unsigned char b = (unsigned char)c;
    if (n >= 8) {
        uword_t w = (uword_t)b;
        w |= w << 8; w |= w << 16; w |= w << 32;
        while (n && ((unsigned long)p & 7u)) { *p++ = b; n--; }
        while (n >= 8) { *(uword_t *)p = w; p += 8; n -= 8; }
    }
    while (n--) *p++ = b;
    return dst;
}
void *memcpy(void *dst, const void *src, unsigned long n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    if ((((unsigned long)d ^ (unsigned long)s) & 7u) == 0) {
        while (n && ((unsigned long)d & 7u)) { *d++ = *s++; n--; }
        while (n >= 8) { *(uword_t *)d = *(const uword_t *)s; d += 8; s += 8; n -= 8; }
    }
    while (n--) *d++ = *s++;
    return dst;
}
void *memmove(void *dst, const void *src, unsigned long n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    if (d < s) { while (n--) *d++ = *s++; }
    else { d += n; s += n; while (n--) *--d = *--s; }
    return dst;
}

/* malloc/free/calloc/realloc live in umalloc.c (host-testable in isolation). */

/* Program entry: the ELF entry point. Calls main() and exits with its result.
 * force_align_arg_pointer: the kernel enters _start with a 16-byte-aligned RSP
 * (the ELF entry-point convention), but GCC compiles _start as an ordinary
 * function assuming the post-CALL alignment (RSP ≡ 8 mod 16). That 8-byte skew
 * is invisible to integer code but makes SSE programs (DOOM, built with -msse2)
 * fault on the first aligned `movaps (%rsp)` in main. The attribute emits a
 * stack-realigning prologue so main and everything it calls get correct
 * 16-byte alignment regardless. Harmless for the non-SSE apps. */
extern int main(void);
__attribute__((force_align_arg_pointer))
void _start(void) {
    sys_exit(main());
    for (;;) { }
}
