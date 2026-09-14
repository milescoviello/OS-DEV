/*
 * ipcselftest.c — boot-time self-tests for the POSIX IPC surface (M1906).
 *
 * --- Why this exists ---------------------------------------------------------
 * A coverage survey found ~2,700 lines of IPC/filesystem code with NO automated
 * assertions at all: POSIX message queues, named semaphores, shared memory, ptys,
 * advisory file locks, inotify and eventfd. Every one of them is reachable from
 * userspace (each has syscalls that apps use), so they were being exercised
 * incidentally — but nothing checked that they behaved correctly, which is
 * exactly the situation that let three box-model bugs coexist in a green tree
 * until M1902 added rendering assertions.
 *
 * These subsystems cannot be covered the way the userspace test apps do it:
 * ring-3 `print()` goes to an app's window text grid and is NOT mirrored to the
 * serial port, so a headless test cannot read it. Kernel `kprintf` DOES reach
 * COM1, so this follows the pattern every driver already uses — a boot-time
 * self-test that prints "[ ok ]" markers a test script greps for
 * (tests/run-ipc-tests.sh), the same shape as ahci_selftest / nvme_selftest.
 *
 * --- Scope -------------------------------------------------------------------
 * Deliberately only NON-BLOCKING operations. Every one of these subsystems has
 * blocking paths (mqueue_send on a full queue, sem_named_wait at zero,
 * pty_read on an empty buffer), and calling one from the boot path with no other
 * runnable task would wedge the boot. So each test drives the queue/semaphore/pty
 * to a state where the operation is known to complete, and uses the trywait /
 * ready / getattr variants to probe the rest. That is a real limit on what this
 * proves, and it is stated here rather than implied.
 *
 * Everything is cleaned up (unlink/close) so the running system is left exactly
 * as it was found.
 */
#include "mqueue.h"
#include "sem.h"
#include "shm.h"
#include "pty.h"
#include "flock.h"
#include "inotify.h"
#include "eventfd.h"
#include "syscall.h"   /* O_CREAT/O_EXCL, struct sembuf, IPC_* / GET-SETVAL */
#include "tmpfs.h"
#include "task.h"   /* task_set_fs_base / task_fs_base_live_value (M2013) */
#include "unixsock.h"
#include "sysvipc.h"
#include "procfs.h"
#include "vfs.h"       /* vfs_dirent, for the tmpfs/procfs listings */
#include "console.h"
#include "string.h"
#include <stdint.h>

/* One assertion. Prints a pass/fail line and tallies, so the test script can both
 * grep individual markers AND assert the summary count. */
static int ipc_pass, ipc_fail;
static void ck(int cond, const char *what) {
    if (cond) { ipc_pass++; kprintf("[ ok ] ipc: %s\n", what); }
    else      { ipc_fail++; kprintf("[FAIL] ipc: %s\n", what); }
}

/* --- the FS_BASE restore invariant (M2013) ---------------------------------
 *
 * FS_BASE is the thread pointer. Every TLS access in every glibc program goes
 * through it, and the stack-protector canary is read from %fs:0x28 on entry to
 * most functions -- so a thread running with the wrong FS_BASE does not
 * misbehave subtly, it dies on its first function call.
 *
 * load_fs_base() used to SKIP the wrmsr when this core's recorded value
 * already matched the one being loaded. The flaw is not the idea, it is that
 * the record has to stay true about a register three assembly stubs zero as a
 * side effect (loading any FS selector clears FS_BASE on x86-64), across a
 * scheduler that migrates tasks between cores. It did not stay true: Firefox
 * died reading %fs:0x28 with CR2 = 0x28 in a thread whose SAVED base was a
 * perfectly good pointer, and the live MSR was zero while the per-core record
 * claimed zero as well -- the skip decision, not the value, was wrong.
 *
 * This reproduces exactly that, deterministically and in three lines: load a
 * base, zero the register the way those stubs do, ask for the SAME base again,
 * and read the hardware back. With the cache the second request is skipped and
 * the register stays zero. The test therefore FAILS if the cache is restored,
 * which is the whole point of it existing. */
static void test_fsbase(void) {
    uint64_t saved = task_fs_base_live_value();
    const uint64_t probe = 0x0000700011223000ull;   /* canonical, page-aligned, ours */

    task_set_fs_base(probe);
    ck(task_fs_base_live_value() == probe, "FS_BASE: setting a thread pointer reaches the hardware");

    /* What gdt_flush, ap_trampoline and return_to_kernel each do, and what the
     * cache could not know about: writing the FS SELECTOR clears FS_BASE. */
    __asm__ volatile("mov $0x10, %%ax; mov %%ax, %%fs" ::: "ax");
    ck(task_fs_base_live_value() == 0, "FS_BASE: loading an FS selector really does zero it");

    /* The same value again. A cache keyed on "what we last loaded" says there
     * is nothing to do here; the hardware disagrees. */
    task_set_fs_base(probe);
    ck(task_fs_base_live_value() == probe,
       "FS_BASE: reloading the SAME base after the register was zeroed behind us still writes it");

    task_set_fs_base(saved);
    ck(task_fs_base_live_value() == saved, "FS_BASE: and the caller's own base is put back");
}

/* --- POSIX message queues -------------------------------------------------- */
static void test_mqueue(void) {
    int q = mqueue_open("/ipcselftest", 4, 64);
    ck(q >= 0, "mq_open created a queue");
    if (q < 0) return;

    long maxmsg = 0, msgsize = 0, curmsgs = 0, flags = 0;
    ck(mqueue_getattr(q, &flags, &maxmsg, &msgsize, &curmsgs) == 0 && curmsgs == 0,
       "mq_getattr reports an empty queue");

    /* Priority ordering is the interesting property: receive must return the
     * HIGHEST priority first, not FIFO. Send low, then high, then read back. */
    ck(mqueue_send(q, "lo", 2, 1) == 2, "mq_send accepted a low-priority message");
    ck(mqueue_send(q, "hi", 2, 9) == 2, "mq_send accepted a high-priority message");
    ck(mqueue_getattr(q, &flags, &maxmsg, &msgsize, &curmsgs) == 0 && curmsgs == 2,
       "mq_getattr counts both queued messages");

    char buf[64]; unsigned int prio = 0;
    memset(buf, 0, sizeof buf);
    long n = mqueue_receive(q, buf, sizeof buf, &prio);
    ck(n == 2 && buf[0] == 'h' && buf[1] == 'i' && prio == 9,
       "mq_receive returned the HIGHEST priority message first");

    memset(buf, 0, sizeof buf); prio = 0;
    n = mqueue_receive(q, buf, sizeof buf, &prio);
    ck(n == 2 && buf[0] == 'l' && buf[1] == 'o' && prio == 1,
       "mq_receive then returned the lower-priority message");

    ck(mqueue_unlink("/ipcselftest") == 0, "mq_unlink removed the queue");
}

/* --- POSIX named semaphores ------------------------------------------------ */
static void test_sem(void) {
    /* O_CREAT is REQUIRED to create: without it sem_named_open correctly returns
     * ENOENT for a name that does not exist. The first cut of this test passed
     * oflag=0 and "failed" — the kernel was right and the test was wrong, which is
     * worth asserting explicitly now that it is understood. */
    ck(sem_named_open("/ipcselftest_absent", 0, 1) < 0,
       "sem_open without O_CREAT fails for a missing name (ENOENT)");

    int s = sem_named_open("/ipcselftest", O_CREAT, 1);   /* initial value 1 */
    ck(s >= 0, "sem_open with O_CREAT created a semaphore with value 1");
    if (s < 0) return;

    /* O_CREAT|O_EXCL on an existing name must fail (EEXIST). */
    ck(sem_named_open("/ipcselftest", O_CREAT | O_EXCL, 1) < 0,
       "sem_open O_CREAT|O_EXCL fails on an existing name (EEXIST)");

    int v = -1;
    ck(sem_named_getvalue(s, &v) == 0 && v == 1, "sem_getvalue reports 1");
    ck(sem_named_trywait(s) == 0, "sem_trywait succeeded while the count was 1");
    ck(sem_named_getvalue(s, &v) == 0 && v == 0, "sem_trywait decremented it to 0");
    /* At zero, trywait must FAIL rather than block — the property worth asserting. */
    ck(sem_named_trywait(s) != 0, "sem_trywait fails at 0 instead of blocking");
    ck(sem_named_post(s) == 0, "sem_post incremented it");
    ck(sem_named_getvalue(s, &v) == 0 && v == 1, "sem_getvalue back to 1 after post");
    ck(sem_named_close(s) == 0, "sem_close released the handle");
    ck(sem_named_unlink("/ipcselftest") == 0, "sem_unlink removed the name");
}

/* --- POSIX shared memory --------------------------------------------------- */
static void test_shm(void) {
    uint64_t *frames = 0; int npages = 0;
    int r = shm_get("/ipcselftest", 8192, &frames, &npages);
    ck(r == 0 && frames && npages == 2, "shm_open/ftruncate gave 2 pages for 8 KiB");

    /* Re-opening the SAME name must return the SAME frames: that identity is the
     * whole point of shared memory, and a bug there would silently un-share it. */
    uint64_t *frames2 = 0; int npages2 = 0;
    int r2 = shm_get("/ipcselftest", 8192, &frames2, &npages2);
    ck(r2 == 0 && npages2 == npages && frames2 && frames2[0] == frames[0],
       "shm_open of the same name returned the SAME backing frames");

    /* The size cap must be enforced, not silently truncated. */
    uint64_t cap = shm_max_bytes();
    uint64_t *f3 = 0; int n3 = 0;
    ck(shm_get("/ipcselftest_toobig", cap + 4096, &f3, &n3) != 0,
       "shm_open past the size cap is rejected");

    ck(shm_unlink("/ipcselftest") == 0, "shm_unlink removed the object");
}

/* --- pseudo-terminals ------------------------------------------------------ */
static void test_pty(void) {
    int m = pty_open();
    ck(m >= 0, "pty_open allocated a master/slave pair");
    if (m < 0) return;
    int slave = m | 1;

    /* Write on the master, read on the slave: proves the pair is actually wired
     * together and in the right direction. Raw mode first, so line discipline
     * doesn't hold the bytes back and turn the read below into a block. */
    pty_ctl(m, 0, 0);                      /* lflag = 0: no ICANON/ECHO */
    pty_ctl(slave, 0, 0);
    ck(pty_write(m, "AB", 2) == 2, "pty_write accepted 2 bytes on the master");
    ck(pty_ready(slave) == 1, "pty_ready says the slave has data (so read won't block)");

    char buf[8]; memset(buf, 0, sizeof buf);
    long n = pty_ready(slave) ? pty_read(slave, buf, sizeof buf) : -1;
    ck(n == 2 && buf[0] == 'A' && buf[1] == 'B', "pty_read on the slave got those bytes");

    ck(pty_ready(slave) == 0, "pty_ready is clear once the slave is drained");
    ck(pty_close(m) == 0, "pty_close closed the master");
    ck(pty_close(slave) == 0, "pty_close closed the slave");
}

/* --- advisory file locks (flock) ------------------------------------------- */
#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_UN 8
#define LOCK_NB 4
static void test_flock(void) {
    /* Two different pids contending. An exclusive lock must exclude, and a shared
     * lock must not — the core semantics, and the part a bug would silently break. */
    ck(flock_op("/ipcselftest.lock", 101, LOCK_EX | LOCK_NB) == 0,
       "flock LOCK_EX granted to pid 101");
    ck(flock_op("/ipcselftest.lock", 102, LOCK_EX | LOCK_NB) != 0,
       "flock LOCK_EX refused to pid 102 while 101 holds it");
    ck(flock_op("/ipcselftest.lock", 101, LOCK_UN) == 0, "flock unlocked by pid 101");
    ck(flock_op("/ipcselftest.lock", 101, LOCK_SH | LOCK_NB) == 0,
       "flock LOCK_SH granted to pid 101");
    ck(flock_op("/ipcselftest.lock", 102, LOCK_SH | LOCK_NB) == 0,
       "flock LOCK_SH ALSO granted to pid 102 (shared locks coexist)");
    ck(flock_op("/ipcselftest.lock", 103, LOCK_EX | LOCK_NB) != 0,
       "flock LOCK_EX refused while shared locks are held");
    flock_release_pid(101);
    flock_release_pid(102);
    ck(flock_op("/ipcselftest.lock", 103, LOCK_EX | LOCK_NB) == 0,
       "flock LOCK_EX granted after the holders' pids were released");
    flock_op("/ipcselftest.lock", 103, LOCK_UN);
}

/* --- inotify --------------------------------------------------------------- */
static void test_inotify(void) {
    int i = inotify_new();
    ck(i >= 0, "inotify_init allocated an instance");
    if (i < 0) return;
    int wd = inotify_add(i, "/ipcselftest.watch", 0xFFFFFFFFu);
    ck(wd >= 0, "inotify_add_watch registered a watch");
    ck(inotify_ready(i) == 0, "inotify queue starts empty");

    /* Feed the same hook the VFS uses, so this exercises the real event path
     * rather than a private one. */
    inotify_feed('c', "/ipcselftest.watch");
    ck(inotify_ready(i) == 1, "inotify saw an event after a matching VFS mutation");

    char buf[256]; memset(buf, 0, sizeof buf);
    long n = inotify_read(i, buf, sizeof buf);
    ck(n > 0, "inotify_read drained the queued event");
    ck(inotify_ready(i) == 0, "inotify queue empty again after the read");

    /* A path that is NOT watched must not generate events. */
    inotify_feed('c', "/some.other.path");
    ck(inotify_ready(i) == 0, "inotify ignores mutations outside its watch");

    ck(inotify_rm(i, wd) == 0, "inotify_rm_watch removed the watch");
    inotify_free(i);
}

/* --- eventfd --------------------------------------------------------------- */
static void test_eventfd(void) {
    ck(eventfd_ready("ipcself") == 0, "eventfd counter starts at 0");
    /* eventfd semantics: writes ACCUMULATE, and a read drains the whole counter. */
    ck(eventfd_write("ipcself", "1", 1) > 0, "eventfd_write bumped the counter");
    ck(eventfd_ready("ipcself") == 1, "eventfd is readable once non-zero");
    ck(eventfd_write("ipcself", "1", 1) > 0, "eventfd_write bumped it again");

    char buf[64]; memset(buf, 0, sizeof buf);
    long n = eventfd_ready("ipcself") ? eventfd_read("ipcself", buf, sizeof buf) : -1;
    ck(n > 0, "eventfd_read returned the accumulated count");
    ck(eventfd_ready("ipcself") == 0, "eventfd drained to 0 by the read");
}

/* --- tmpfs (in-memory files) ----------------------------------------------- */
static void test_tmpfs(void) {
    const char *f = "/tmp/ipcself.txt";
    ck(tmpfs_write(f, "HelloTmpfs", 10) == 10, "tmpfs_write wrote 10 bytes");

    char buf[32]; memset(buf, 0, sizeof buf);
    ck(tmpfs_read(f, buf, sizeof buf) == 10 && buf[0] == 'H' && buf[9] == 's',
       "tmpfs_read round-tripped the content");

    /* Positioned read: the offset must actually skip bytes, not restart. */
    memset(buf, 0, sizeof buf);
    ck(tmpfs_pread(f, buf, sizeof buf, 5) == 5 && buf[0] == 'T' && buf[4] == 's',
       "tmpfs_pread honoured the offset");

    ck(tmpfs_truncate(f, 5) == 0, "tmpfs_truncate shrank the file");
    memset(buf, 0, sizeof buf);
    ck(tmpfs_read(f, buf, sizeof buf) == 5 && buf[0] == 'H' && buf[4] == 'o',
       "tmpfs_read sees the truncated length");

    /* A symlink must NOT be followed by readlink — it returns the target text. */
    ck(tmpfs_symlink("/tmp/ipcself.lnk", f) == 0, "tmpfs_symlink created a link");
    memset(buf, 0, sizeof buf);
    long rl = tmpfs_readlink("/tmp/ipcself.lnk", buf, sizeof buf);
    ck(rl > 0 && buf[0] == '/', "tmpfs_readlink returned the target, unfollowed");

    ck(tmpfs_remove(f) == 0, "tmpfs_remove deleted the file");
    ck(tmpfs_read(f, buf, sizeof buf) < 0, "tmpfs_read fails after remove");
    tmpfs_remove("/tmp/ipcself.lnk");
}

/* --- unix-domain sockets --------------------------------------------------- */
static void test_unixsock(void) {
    /* socketpair, not listen/accept: unix_accept BLOCKS, and blocking from the
     * boot path with no other runnable task would wedge the boot. A pre-connected
     * pair exercises the same send/recv machinery without that risk. */
    int a = -1, b = -1;
    ck(unix_socketpair(&a, &b) == 0 && a >= 0 && b >= 0,
       "unix socketpair created a connected endpoint pair");
    if (a < 0 || b < 0) return;

    char buf[32];
    ck(unix_send(a, "ping", 4) == 4, "unix_send wrote 4 bytes on endpoint A");
    memset(buf, 0, sizeof buf);
    ck(unix_recv(b, buf, sizeof buf) == 4 && buf[0] == 'p' && buf[3] == 'g',
       "unix_recv read them on endpoint B");

    /* And the other direction, so this isn't a one-way fluke. */
    ck(unix_send(b, "pong", 4) == 4, "unix_send wrote back on endpoint B");
    memset(buf, 0, sizeof buf);
    ck(unix_recv(a, buf, sizeof buf) == 4 && buf[0] == 'p' && buf[3] == 'g',
       "unix_recv read it on endpoint A");

    /* After the peer closes and the buffer is drained, recv must report EOF (0),
     * not block and not error — the property a bug here would break. */
    ck(unix_close(b) == 0, "unix_close closed endpoint B");
    ck(unix_recv(a, buf, sizeof buf) == 0, "unix_recv reports EOF once the peer closed");
    unix_close(a);

    /* --- M1965: the behaviours the Linux ABI layer depends on ---------------
     * Each of these was found by running real Node.js, and each presented as
     * something other than what it was. They are asserted here so a regression
     * costs a `make check`, not a twenty-minute guest run. */

    /* HALF-CLOSE. shutdown(SHUT_WR) ends ONE direction: the peer reads EOF
     * while this side can still receive. Accepting it and doing nothing (what
     * we did until M1965) makes a finished connection look permanently open,
     * so an event loop with no work left still cannot exit -- a hang with no
     * error message anywhere. */
    int c = -1, d = -1;
    ck(unix_socketpair(&c, &d) == 0, "unix socketpair for the half-close test");
    ck(unix_send(c, "hi", 2) == 2, "unix_send queued 2 bytes before the shutdown");
    ck(unix_shutdown(c, 1 /*SHUT_WR*/) == 0, "unix_shutdown(SHUT_WR) accepted");
    memset(buf, 0, sizeof buf);
    ck(unix_recv(d, buf, sizeof buf) == 2 && buf[0] == 'h',
       "bytes already queued survive the shutdown");
    /* Gate every recv on unix_readable first. This file's rule is that a
     * boot-path self-test must never call a blocking operation, and a
     * half-close regression is exactly the case that would block: with
     * unix_shutdown reverted to the no-op it used to be, this recv waits
     * forever for an EOF that never comes, and the boot WEDGES instead of
     * reporting a failure. Proven by reverting it. (M1965) */
    int d_eof = unix_readable(d);
    ck(d_eof, "the peer sees the connection as readable after SHUT_WR (a pending EOF)");
    ck(d_eof && unix_recv(d, buf, sizeof buf) == 0, "the peer then reads EOF after SHUT_WR");
    ck(unix_send(c, "x", 1) == -1, "sending on a shut-down write side fails");
    ck(unix_send(d, "yo", 2) == 2, "the peer may still write back (HALF-close)");
    memset(buf, 0, sizeof buf);
    int c_rd = unix_readable(c);
    ck(c_rd && unix_recv(c, buf, sizeof buf) == 2 && buf[0] == 'y',
       "and the shut-down side may still read: the reverse direction stays open");
    unix_close(c); unix_close(d);

    /* A LISTENER'S NAME IS RELEASED when its socket closes. Without this a
     * server that restarts finds its own path still bound, and a table of 32
     * names is exhausted by a handful of restarts. */
    int l1 = unix_listen("/run/ipcself");
    ck(l1 >= 0, "unix_listen bound a name");
    ck(unix_unlisten(l1) == 0, "unix_unlisten released it");
    ck(unix_connect("/run/ipcself") == -1, "connecting to the released name fails");
    int l2 = unix_listen("/run/ipcself");
    ck(l2 >= 0, "the released name can be bound again");
    if (l2 >= 0) unix_unlisten(l2);

    /* An over-long name is REFUSED, not silently truncated. A truncated bind
     * succeeds and then no connect ever matches it, which presents as "the
     * server isn't running". */
    char big[200]; big[0] = '/';
    for (int i = 1; i < 199; i++) big[i] = 'n';
    big[199] = 0;
    ck(unix_listen(big) == -1, "unix_listen refuses a name too long to store");
}

/* --- System V IPC (semaphores + message queues) ---------------------------- */
static void test_sysvipc(void) {
    int sid = sysv_semget(0x1C5E1F, 1, IPC_CREAT | 0666);
    ck(sid >= 0, "sysv semget created a 1-semaphore set");
    if (sid >= 0) {
        ck(sysv_semctl(sid, 0, SETVAL, 3) == 0, "sysv semctl SETVAL set it to 3");
        ck(sysv_semctl(sid, 0, GETVAL, 0) == 3, "sysv semctl GETVAL reads back 3");

        /* semop is all-or-nothing: -1 succeeds against a value of 3. */
        struct sembuf op = { 0, -1, 0 };
        ck(sysv_semop(sid, &op, 1) == 0, "sysv semop -1 succeeded");
        ck(sysv_semctl(sid, 0, GETVAL, 0) == 2, "sysv semop decremented it to 2");

        /* A decrement that would block must fail immediately under IPC_NOWAIT
         * rather than wait -- and must NOT partially apply. */
        struct sembuf too = { 0, -9, IPC_NOWAIT };
        ck(sysv_semop(sid, &too, 1) != 0, "sysv semop -9 with IPC_NOWAIT fails, not blocks");
        ck(sysv_semctl(sid, 0, GETVAL, 0) == 2, "the failed semop left the value UNCHANGED");

        ck(sysv_semctl(sid, 0, IPC_RMID, 0) == 0, "sysv semctl IPC_RMID removed the set");
    }

    int qid = sysv_msgget(0x1C5E1F, IPC_CREAT | 0666);
    ck(qid >= 0, "sysv msgget created a message queue");
    if (qid >= 0) {
        ck(sysv_msgsnd(qid, 7, "seven", 5, 0) == 0, "sysv msgsnd enqueued mtype 7");
        ck(sysv_msgsnd(qid, 9, "nine", 4, 0) == 0, "sysv msgsnd enqueued mtype 9");

        /* Receiving by TYPE must skip the earlier message of a different type --
         * that selectivity is the whole point of SysV mtype. */
        char m[32]; long got = 0; memset(m, 0, sizeof m);
        int n = sysv_msgrcv(qid, 9, m, sizeof m, &got, 0);
        ck(n == 4 && got == 9 && m[0] == 'n', "sysv msgrcv selected mtype 9, skipping 7");

        memset(m, 0, sizeof m); got = 0;
        n = sysv_msgrcv(qid, 7, m, sizeof m, &got, 0);
        ck(n == 5 && got == 7 && m[0] == 's', "sysv msgrcv then got mtype 7");

        ck(sysv_msgctl(qid, IPC_RMID) == 0, "sysv msgctl IPC_RMID removed the queue");
    }
}

/* --- procfs ---------------------------------------------------------------- */
static void test_procfs(void) {
    ck(procfs_owns("/proc/meminfo") == 1, "procfs claims /proc/meminfo");
    ck(procfs_owns("/README.TXT") == 0, "procfs does NOT claim a real disk path");
    ck(procfs_is_dir("/proc") == 1, "procfs reports /proc as a directory");

    char buf[512]; memset(buf, 0, sizeof buf);
    long n = procfs_read("/proc/meminfo", buf, sizeof buf - 1);
    ck(n > 0, "procfs_read returned /proc/meminfo content");
    ck(n > 0 && buf[0] != 0, "the meminfo content is non-empty text");

    memset(buf, 0, sizeof buf);
    ck(procfs_read("/proc/uptime", buf, sizeof buf - 1) > 0, "procfs_read served /proc/uptime");

    /* A nonexistent node under /proc must fail rather than return stale bytes. */
    memset(buf, 0, sizeof buf);
    ck(procfs_read("/proc/definitely_not_here", buf, sizeof buf - 1) <= 0,
       "procfs_read fails for a nonexistent node");

    static vfs_dirent ents[64];
    int cnt = procfs_list("/proc", ents, 64);
    ck(cnt > 0, "procfs_list enumerated /proc");

    /* --- M1965: synthetic FILES are stat-able and read-able through the VFS --
     * procfs_read has generated these since M1216, but vfs_stat only ever knew
     * about the /proc and /dev DIRECTORIES -- so stat said "no such file" for
     * every node inside them and open() refused all of them. Node's probes of
     * /proc/meminfo, /proc/stat and /dev/null therefore all failed against
     * files that were right there. */
    int chardev = -1;
    ck(procfs_exists("/proc/meminfo", &chardev) == 1 && chardev == 0,
       "procfs_exists finds /proc/meminfo and calls it a regular file");
    ck(procfs_exists("/dev/null", &chardev) == 1 && chardev == 1,
       "procfs_exists finds /dev/null and calls it a character device");
    ck(procfs_exists("/dev/definitely_not_here", &chardev) == 0,
       "procfs_exists rejects a /dev node that does not exist");

    struct statx st;
    ck(vfs_stat("/proc/meminfo", &st) == 0 && (st.stx_mode & S_IFMT) == S_IFREG,
       "vfs_stat resolves /proc/meminfo as a regular file");
    ck(vfs_stat("/dev/null", &st) == 0 && (st.stx_mode & S_IFMT) == S_IFCHR,
       "vfs_stat resolves /dev/null as a character device");
    ck(vfs_stat("/dev/definitely_not_here", &st) != 0,
       "vfs_stat still reports a missing /dev node as absent");

    memset(buf, 0, sizeof buf);
    ck(vfs_pread("/proc/meminfo", buf, sizeof buf - 1, 0) > 0,
       "vfs_pread served /proc/meminfo -- this is what open()+read() goes through");
    ck(vfs_pread("/dev/null", buf, sizeof buf - 1, 0) == 0, "/dev/null reads as immediate EOF");
    /* A character device is a STREAM. Applying a file's offset logic to it
     * would report EOF on the second read of /dev/urandom. */
    ck(vfs_pread("/dev/urandom", buf, 16, 0) == 16, "/dev/urandom yielded 16 bytes");
    ck(vfs_pread("/dev/urandom", buf, 16, 4096) == 16,
       "/dev/urandom yields more at a large offset: a char device is a stream, not a file");
}

void ipc_selftest(void) {
    ipc_pass = ipc_fail = 0;
    kprintf("[ipc] POSIX IPC self-test (mqueue / sem / shm / pty / flock / inotify / eventfd\n");
    kprintf("[ipc]                        / tmpfs / unixsock / sysvipc / procfs)\n");
    test_fsbase();
    test_mqueue();
    test_sem();
    test_shm();
    test_pty();
    test_flock();
    test_inotify();
    test_eventfd();
    test_tmpfs();
    test_unixsock();
    test_sysvipc();
    test_procfs();
    kprintf("[ %s ] ipc self-test: %d passed, %d failed\n\n",
            ipc_fail ? "!!" : "ok", ipc_pass, ipc_fail);
}
