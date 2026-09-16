/*
 * linuxabi.c — a Linux x86-64 ABI compatibility layer (M1938).
 *
 * WHAT THIS IS, AND IS NOT. OS-DEV's own userspace uses its own 345-call ABI
 * over `int 0x80`, and none of that changes. This is a SECOND, independent
 * entry path on the `syscall` instruction that speaks Linux's ABI instead, so
 * that unmodified static Linux binaries — busybox, a real GCC, eventually Node
 * — can run. It is a bolt-on for running OTHER PEOPLE'S binaries; every
 * subsystem it calls into (the VFS, the scheduler, the memory managers) is
 * still the from-scratch one.
 *
 * The two ABIs cannot collide: different entry instructions, different handlers,
 * different number tables. A process can legitimately use both.
 *
 * THREE THINGS MAKE THIS UNUSUALLY CHEAP HERE:
 *   1. `syscall`/`sysret` were entirely unused — LSTAR/STAR/SFMASK were never
 *      programmed and EFER.SCE was never set, so the instruction was a free slot.
 *   2. The register convention is ALREADY identical: rax = number, args in
 *      rdi, rsi, rdx, r10, r8, r9. Linux uses r10 (not rcx) for arg4 precisely
 *      because `syscall` clobbers rcx, and ulib.c had independently done the same.
 *   3. The hard primitives already exist — fork with real COW, execve-shaped
 *      image replacement, futex, clone, epoll, mmap with demand paging, and
 *      RW->RX mprotect.
 *
 * WHAT IS GENUINELY NEW is shape, not capability: Linux's syscall numbers,
 * Linux's struct layouts, and — the one that silently poisons everything if you
 * skip it — the NEGATIVE-ERRNO return convention. Our native calls return a
 * bare -1 on failure. musl tests `ret < 0 && ret > -4096` and treats the
 * negation as errno, so a bare -1 reads as EPERM for EVERY failure: a missing
 * file reports "Operation not permitted" and nothing behaves sanely.
 */
#include "interrupts.h"
#include "gdt.h"
#include "console.h"
#include "smp.h"
#include "task.h"
#include "lxerrno.h"
#include "wayland.h"   /* g_wl_verbose (M1978) */
#include "vmm.h"
#include "app.h"
#include "rtc.h"
#include "random.h"
#include "vfs.h"
#include "pipe.h"      /* app_sbrk/app_mmap/app_mprotect/app_munmap -- the native primitives these translate onto */
#include "timer.h"
#include "pmm.h"    /* sysinfo reports real memory totals (M1958) */
#include "kheap.h"  /* execve copies argv/envp into heap buffers, not onto the kernel stack (M1962) */
#include "syscall.h"   /* AT_PAGESZ/AT_ENTRY/AT_UID/... -- the auxv types we share with /proc/<pid>/auxv */
#include <stdint.h>

/* ---- MSRs ---------------------------------------------------------------- */
#define MSR_EFER            0xC0000080u
#define   EFER_SCE          (1u << 0)      /* System Call Extensions: enables `syscall` */
#define MSR_STAR            0xC0000081u
#define MSR_LSTAR           0xC0000082u
#define MSR_SFMASK          0xC0000084u
#define MSR_GS_BASE         0xC0000101u
#define MSR_KERNEL_GS_BASE  0xC0000102u

static inline uint64_t rdmsr(uint32_t m) {
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(m));
    return ((uint64_t)hi << 32) | lo;
}
static inline void wrmsr(uint32_t m, uint64_t v) {
    __asm__ volatile("wrmsr" : : "c"(m), "a"((uint32_t)v), "d"((uint32_t)(v >> 32)));
}

/* ---- the per-CPU block the entry stub reaches through GS ------------------
 * SYSCALL hands us no stack, so offset 0 MUST hold this core's current kernel
 * stack top and offset 8 is scratch for the user's RSP. The offsets are
 * hard-coded in linux_syscall_entry (kernel/asm/linux_entry.asm) — keep them
 * in sync. One block per core, indexed by APIC id like gdt.c's TSS array,
 * because RSP0 is a per-core resource: two cores trapping in at once must not
 * share a kernel stack. */
#define LX_MAXCPUS 16
struct lx_percpu {
    uint64_t kernel_rsp;        /* offset 0  — must match the asm */
    uint64_t user_rsp_scratch;  /* offset 8  — must match the asm */
} __attribute__((aligned(64)));
static struct lx_percpu lx_pc[LX_MAXCPUS];

/* Called by tss_set_rsp0() on every context switch, so the syscall path always
 * finds the CURRENT task's kernel stack — exactly the value the CPU would have
 * loaded from the TSS had this been an interrupt gate. */
void linux_abi_set_kernel_rsp(int cpu, uint64_t rsp) {
    int i = cpu & (LX_MAXCPUS - 1);
    lx_pc[i].kernel_rsp = rsp;

    /* Re-assert KERNEL_GS_BASE too (M1943).
     *
     * (M1943, superseded by M1949's no-swapgs design but kept armed here
     * because a context switch is still the cheapest place to re-assert it.)
     * `swapgs` was only self-restoring when every entry was PAIRED with an exit,
     * and a syscall that never returns breaks the pair: exit_group calls
     * task_exit(), so the closing swapgs in the entry stub never executes.
     * KERNEL_GS_BASE is then left holding the USER's base (0, since
     * iret_to_user's `mov gs, ax` zeroes it), and the NEXT Linux syscall on
     * this core swaps that 0 into GS -- so `mov %gs:0, %rsp` reads absolute
     * address 0 and loads garbage.
     *
     * Measured, not hypothesised: that produced a DOUBLE FAULT at
     * linux_syscall_entry+0x15 with rsp=0xf000ff53f000ff53 -- the real-mode
     * IVT, read from address 0 -- on glibc's first syscall (brk), immediately
     * after the freestanding binary had exited. It was ORDER-DEPENDENT, which
     * is exactly why it showed up as a flaky test rather than a hard failure.
     *
     * Re-asserting here makes the invariant self-healing: a task can only reach
     * a syscall after being switched to, and this runs on every switch. The
     * rdmsr guard keeps the common case to a read rather than a write. */
    if (rdmsr(MSR_GS_BASE) != (uint64_t)&lx_pc[i])
        wrmsr(MSR_GS_BASE, (uint64_t)&lx_pc[i]);
}

extern void linux_syscall_entry(void);

/* Arm the `syscall` instruction on the CALLING core. Must run on every core
 * (BSP and each AP): EFER, LSTAR, STAR, SFMASK and KERNEL_GS_BASE are all
 * per-core MSRs, and a core that skipped this would #UD on a Linux binary's
 * very first instruction. */
void linux_abi_init_this_cpu(void) {
    int cpu = smp_current_cpu() & (LX_MAXCPUS - 1);

    /* The ACTIVE GS_BASE, and NO swapgs anywhere (M1949).
     *
     * The swapgs design was wrong in a way two fixes did not reach. swapgs is
     * only correct if every entry is paired with an exit AND nothing disturbs
     * GS_BASE in between -- but GS_BASE is a per-CORE MSR that NOTHING SAVES
     * ACROSS A CONTEXT SWITCH. So if a Linux syscall blocks mid-call, another
     * task's exit swapgs changes GS_BASE underneath it; the blocked syscall's
     * own exit swapgs then writes garbage into KERNEL_GS_BASE, and the next
     * entry loads that garbage. Symptom: `mov %gs:0, %rsp` reading absolute
     * address 0 and a DOUBLE FAULT with rsp=0xf000ff53f000ff53 (the real-mode
     * IVT). M1943 fixed one instance of the pairing problem; this removes the
     * requirement altogether.
     *
     * Keeping the percpu pointer in the live GS_BASE at all times means the
     * stub needs no swapgs and there is nothing to get out of sync. Ring 3
     * cannot read through it: the percpu block is kernel .bss with no
     * PTE_USER, so a ring-3 `mov %gs:0,%rax` faults rather than leaking. */
    wrmsr(MSR_GS_BASE, (uint64_t)&lx_pc[cpu]);

    /* STAR[47:32] = the CS the CPU loads on SYSCALL; SS becomes that + 8.
     * KERNEL_CS is 0x08 and KERNEL_DS is 0x10, so this GDT already satisfies
     * the requirement with no reshuffling.
     *
     * STAR[63:48] is the SYSRET base and is DON'T-CARE here: we return via
     * iretq (see the asm) because sysret would want user data at base+8 and
     * user code at base+16, while this GDT has them the other way round. It is
     * set to KERNEL_CS purely for determinism. */
    wrmsr(MSR_STAR, ((uint64_t)KERNEL_CS << 32) | ((uint64_t)KERNEL_CS << 48));

    wrmsr(MSR_LSTAR, (uint64_t)linux_syscall_entry);

    /* Bits CLEARED in RFLAGS on entry. IF is the important one: it makes the
     * syscall path start with interrupts off, matching the int 0x80 gate
     * (0xEE, an interrupt gate), so blocking calls opt back in with `sti`
     * exactly as the native path does. TF/DF/NT/AC are masked so a hostile or
     * careless ring-3 RFLAGS cannot single-step or misdirect kernel code. */
    wrmsr(MSR_SFMASK, 0x200 /*IF*/ | 0x100 /*TF*/ | 0x400 /*DF*/ | 0x4000 /*NT*/ | 0x40000 /*AC*/);

    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_SCE);
}

/* ---- Linux syscall numbers (x86-64) -------------------------------------- */
#define LXS_read           0
#define LXS_write          1
#define LXS_close          3
#define LXS_brk           12
#define APP_NSIG_LX 65          /* signals 1..64, matching app.c's table (M2063) */
/* LINUX NUMBERS ITS SIGSET BITS FROM ZERO, WE NUMBER OURS FROM ONE (M2063).
 *
 * Linux's `sigmask(sig)` is `1UL << (sig - 1)`, and glibc's `sigaddset` agrees,
 * so SIGWINCH (28) is bit 27 in every sigset that crosses this boundary. Our
 * own masks are indexed by the signal number itself, because that is what
 * `pending_sigs`, `sig_blocked` and `sig_handler[]` have always used and those
 * are shared with the native ABI.
 *
 * One shift either way. Getting it wrong is silent and total: a program blocks
 * SIGWINCH, we record SIGPROF as blocked, and the signal it asked us to hold
 * back is delivered immediately -- which is exactly what lxsig caught. Same
 * class as M1967's struct statx offsets: only an exact-value assertion finds
 * it, which is why lxsig checks the DELIVERY and the PENDING SET rather than
 * the return code. */
static inline uint64_t lx_sigset_in(uint64_t user)  { return user << 1; }
static inline uint64_t lx_sigset_out(uint64_t mine) { return mine >> 1; }
#define LXS_rt_sigaction  13
#define LXS_rt_sigprocmask 14
#define LXS_rt_sigreturn_  15
#define LXS_pause_         34
#define LXS_rt_sigpending_ 127
#define LXS_rt_sigsuspend_ 130
#define LXS_ioctl         16
#define LXS_readv         19
#define LXS_preadv       295
#define LXS_pwritev      296
#define LXS_preadv2      327
#define LXS_pwritev2     328
#define LXS_writev        20
#define LXS_getpid        39
#define LXS_exit          60
#define LXS_arch_prctl   158
#define LXS_set_tid_address 218
#define LXS_exit_group   231
#define LXS_getrandom    318

/* --- the batch glibc asks for next (M1943) -------------------------------
 * Each of these is a TRANSLATION onto a native primitive that already exists,
 * not new mechanism. The shapes differ, and the differences are where the bugs
 * live, so each is noted where it is not a straight pass-through. */
#define LXS_mmap           9
#define LXS_mprotect      10
#define LXS_munmap        11
#define LXS_uname         63
#define LXS_readlink      89
#define LXS_sysinfo       99
#define LXS_getuid       102
#define LXS_getpeername_  52
#define LXS_statfs_      137
#define LXS_fstatfs_     138
#define LXS_getresuid_   118
#define LXS_getresgid_   120
#define LXS_fallocate_   285
#define LXS_inotify_init1_ 294
#define LXS_getgid       104
#define LXS_geteuid      107
#define LXS_getegid      108
#define LXS_clock_gettime 228
#define LXS_readlinkat   267
#define LXS_set_robust_list 273
#define LXS_prlimit64    302
#define LXS_rseq         334
#define LXS_fstat          5
#define LXS_getrandom_    318
#define LXS_openat_      257
#define LXS_open_          2      /* the pre-openat form; still emitted by plenty of real code (M1970) */
#define LXS_sigaltstack_ 131
#define LXS_close_range_ 436
#define LXS_read_          0
#define LXS_close_         3
#define LXS_lseek_         8
#define LXS_getdents64   217
#define LXS_newfstatat   262
#define LXS_stat_          4   /* the OLD by-path spelling; Claude Code uses it constantly (M1992) */
#define LXS_lstat_         6
#define LXS_fsync_        74
#define LXS_fdatasync_    75
#define LXS_rename_       82
#define LXS_link_         86
#define LXS_symlink_      88
#define LXS_linkat_      265
#define LXS_symlinkat_   266
#define LXS_utimensat_   280
#define LXS_pidfd_open_  434
#define LXS_unlink_       87
#define LXS_unlinkat_    263
#define LXS_pread64_      17
#define LXS_access_       21
#define LXS_faccessat_   269
#define LXS_clone_        56
#define LXS_fork_         57
#define LX_CLONE_VM   0x00000100
#define LX_CLONE_THREAD 0x00010000
#define LX_CLONE_VFORK  0x00004000
#define LXS_vfork_        58
#define LXS_execve_       59
#define LX_WNOHANG        1      /* wait4/waitid: do not block (M2025) */
#define LXS_wait4_        61
#define LXS_pipe_         22
#define LXS_pipe2_       293
#define LXS_dup2_         33
#define LXS_dup_          32
#define LXS_getppid_     110
#define LXS_fcntl_        72
#define LXS_getrusage_    98
#define LXS_time_        201
#define LXS_getcwd_       79
#define LXS_chmod_        90
#define LXS_fchmod_       91   /* same answer as chmod, by fd (M1992) */
#define LXS_fchmodat_    268
#define LXS_umask_        95
#define LXS_clone3_      435
#define LXS_sysinfo_      99
#define LXS_gettimeofday_ 96
#define LXS_futex_       202
#define LXS_gettid_      186
#define LXS_madvise_      28
#define LXS_mremap_       25
#define LXS_prctl_       157
#define LXS_capget_      125
#define LXS_socket_       41
#define LXS_connect_      42
#define LXS_accept_       43
#define LXS_accept4_     288
#define LXS_bind_         49
#define LXS_listen_       50
#define LXS_socketpair_   53
#define LXS_getsockname_  51
#define LXS_setsockopt_   54
#define LXS_getsockopt_   55
#define LXS_shutdown_     48
#define LXS_sendto_       44
#define LXS_recvfrom_     45
#define LXS_sendmsg_      46
#define LXS_recvmsg_      47
#define LXS_recvmmsg_    299
#define LXS_sendmmsg_    307
#define LXS_memfd_create_ 319
#define LXS_ftruncate_    77
#define LXS_readahead_   187
#define LXS_sendfile_     40
#define LXS_fadvise64_   221
#define LXS_nanosleep_    35
#define LXS_clock_nanosleep_ 230
#define LXS_statx_       332
#define LXS_sched_getaffinity_ 204
#define LXS_sched_setparam_    142
#define LXS_getpriority_ 140
#define LXS_setpriority_ 141
#define LXS_sched_getparam_    143
#define LXS_sched_setscheduler_ 144
#define LXS_sched_getscheduler_ 145
#define LXS_clock_getres_ 229
#define LXS_epoll_create1_ 291
#define LXS_epoll_ctl_   233
#define LXS_epoll_wait_  232
#define LXS_sched_yield_  24   /* Claude Code calls it in a tight loop; ENOSYS turned that into a busy-wait (M1992) */
#define LXS_epoll_pwait2_ 441
#define LXS_inotify_add_watch_ 254   /* Firefox retries this forever on ENOSYS (M1996) */
#define LXS_inotify_rm_watch_  255  /* epoll_pwait with a timespec instead of a millisecond count (M1992) */
#define LXS_epoll_pwait_ 281
#define LXS_eventfd_     284   /* the flagless original; glibc still emits it (M2017) */
#define LXS_eventfd2_    290
#define LXS_timerfd_create_  283
#define LXS_timerfd_settime_ 286
#define LXS_timerfd_gettime_ 287
#define LXS_msync_            26
#define LXS_poll_          7
#define LXS_ppoll_       271
#define LXS_chdir_        80
#define LXS_tgkill_      234
#define LXS_tkill_       200
#define LXS_mkdir_        83
#define LXS_mkdirat_     258
#define LXS_rmdir_        84
#define LXS_fchdir_       81
#define LXS_kill_         62

/* Linux's O_* are OCTAL and do NOT match ours -- O_CREAT is 0100 (64) there and
 * 8 here, O_TRUNC 01000 (512) vs 4. Passing them through unmapped would silently
 * mean something else entirely (Linux's O_CREAT=64 would land on nothing we
 * define, so a create would quietly become an open-existing and fail). */
#define LXO_WRONLY   01
#define LXO_RDWR     02
#define LXO_CREAT   0100
#define LXO_TRUNC  01000
#define LXO_APPEND 02000
#define LXO_NONBLOCK 04000        /* Linux O_NONBLOCK (M2009) */
#define LXO_CLOEXEC 02000000      /* Linux O_CLOEXEC */

/* Linux's x86-64 `struct stat` -- 144 bytes, and the field OFFSETS are the ABI.
 * Writing our own struct layout here would compile fine and hand glibc
 * garbage, so the offsets are spelled out rather than mirrored in a C struct. */
#define LXST_SIZE     144
#define LXST_O_DEV      0
#define LX_FAKE_DEV 0x0801ull      /* one device for everything; st_ino is what distinguishes files (M1955) */
#define LXST_O_INO      8
#define LXST_O_NLINK   16
#define LXST_O_MODE    24
#define LXST_O_UID     28
#define LXST_O_GID     32
#define LXST_O_RDEV    40
#define LXST_O_SIZE    48
#define LXST_O_BLKSIZE 56
#define LXST_O_BLOCKS  64
/* THE TIMESTAMPS, which this struct never carried (M1999). Every file a Linux
 * program stat'd here reported 1 January 1970, because these three fields were
 * simply left as the zeroes the caller's buffer was cleared to.
 *
 * That is not cosmetic. `make` decides what to rebuild by comparing an output's
 * mtime with its inputs' -- with every file equally ancient it cannot order
 * anything, which is the self-hosting path. git uses mtime to decide whether a
 * working-tree file needs re-hashing. And utimensat appeared to do nothing at
 * all: it set the time correctly and stat could not read it back. */
#define LXST_O_ATIME   72
#define LXST_O_MTIME   88
#define LXST_O_CTIME  104
#define LX_S_IFCHR  0020000
#define LX_S_IFREG  0100000

/* Linux mmap flags we care about */
#define LX_MAP_SHARED    0x01
#define LX_MAP_PRIVATE   0x02
#define LX_MAP_FIXED     0x10
#define LX_MAP_ANONYMOUS 0x20

#define ARCH_SET_FS 0x1002

/* ---- the Linux process root (M1954) ------------------------------------
 * A Linux binary's absolute paths are absolute in ITS world: it asks for
 * /lib64/ld-linux-x86-64.so.2, not /disk2/lib64/... But the ext2 volume that
 * holds the Linux userland is mounted at /disk2, and re-rooting the whole OS
 * onto it would break every OS-DEV app, fixture and test that expects the
 * FAT32 boot volume at /.
 *
 * So Linux processes get their OWN root instead -- effectively a chroot into
 * the ext2 volume. It is the right abstraction rather than a workaround: a
 * toolchain installed later needs /usr/lib and /usr/include to mean something,
 * and this is how they come to. Relative paths pass through untouched. */
int g_lx_systrace;
static void lx_trace_on_error(const char *b, unsigned long n);
static int g_lx_statfail;     /* rate-limit the failed-path report (M1992) */                        /* -append lxsystrace: log EVERY Linux syscall (very noisy; for finding where a program blocks) */

/* Translate a negative app_fd_* return into a Linux errno (M1965).
 *
 * Collapsing every failure to EBADF cost real debugging time: Node reported
 * "write EBADF" on a socket whose fd was perfectly valid, because the byte
 * path for that fd type did not exist. EBADF sends you looking at descriptor
 * bookkeeping; EPIPE/EAGAIN name what actually happened. */
static long lx_fd_err(long rc) {
    if (rc == APP_FD_EAGAIN) return -(long)LX_EAGAIN;
    if (rc == APP_FD_EPIPE)  return -(long)LX_EPIPE;
    if (rc == APP_FD_EISDIR) return -(long)LX_EISDIR;   /* M2071 */
    return -(long)LX_EBADF;
}
static long g_epoll_lastk = -1;   /* what the last epoll_wait answered, for the spin detector (M2016) */
int g_lx_mmap_trace;                      /* -append lxmmaptrace: log every Linux mmap/mprotect (M1955) */
#define LX_ROOT     "/disk2"
#define LX_ROOT_LEN 6

/* Translate a Linux path into one the VFS understands. Returns `out`. */
/* Paths the kernel serves itself. /sys is included because procfs_owns() does
 * not claim it -- the probes that go there (cpu/online, cgroup limits) are
 * better answered with a clean ENOENT than with a lookup in a disk root that
 * has no /sys either, and keeping them here documents the boundary. */
static int lx_is_synth(const char *p) {
    const char *pre[] = { "/proc/", "/dev/", "/sys/", 0 };
    for (int i = 0; pre[i]; i++) {
        int j = 0; while (pre[i][j] && p[j] == pre[i][j]) j++;
        if (!pre[i][j]) return 1;
    }
    return 0;
}

static const char *lx_xlate(const char *p, char *out, int max) {
    if (!p) return p;
    int n = 0;
    if (p[0] == '/') {
        /* /proc and /dev are the KERNEL'S OWN synthetic filesystems and must
         * not be rewritten into the ext2 root -- there is nothing there. This
         * layer had been prefixing them like any other path, so Node's probes
         * of /proc/meminfo, /proc/stat, /sys/devices/system/cpu/online and
         * /dev/null all resolved to /disk2/... and came back ENOENT, even
         * though procfs.c has generated every one of those files since M1216.
         * A missing /dev/null in particular is not cosmetic: it is where a
         * runtime sends output it means to discard. (M1965) */
        if (lx_is_synth(p)) return p;
        for (const char *r = LX_ROOT; *r && n < max - 1; r++) out[n++] = *r;
        int pi = 0;
        for (; p[pi] && n < max - 1; pi++) out[n++] = p[pi];
        out[n] = 0;
        /* A TRUNCATED PATH IS A DIFFERENT FILE (M2062).
         *
         * This loop stopped at max-1 and said nothing, so a path longer than
         * VFS_PATH_MAX quietly named something else -- create it and you get a
         * file under the wrong name; open it and you get ENOENT for a file you
         * just wrote. It is the eleventh instance in this campaign of a request
         * accepted and then not honoured, and the only one that had no
         * diagnostic at all.
         *
         * The real repair is a longer path budget: VFS_PATH_MAX is 256 against
         * Linux's 4096, and the /disk2 prefix eats six more, so the usable
         * limit is 249. Raising it is not a constant change -- seventy stack
         * buffers are declared [VFS_PATH_MAX] and several nest in one call
         * chain against a 16 KB kernel stack -- so it is its own milestone.
         * Until then, say so: a wrong answer that announces itself can be
         * found, and this one could not. */
        if (p[pi]) {
            int want = 0; while (p[want]) want++;
            static int told;
            if (++told <= 4)
                kprintf("[linuxabi] path TRUNCATED: %d chars requested, %d is the limit "
                        "(+%d for the mount prefix) -- this names a DIFFERENT file: \"%s\"\n",
                        want, max - 1, LX_ROOT_LEN, out);
        }
        /* A TRAILING SLASH IS NOT A CHARACTER THE PATH WALKER FORGIVES, and
         * "/" is the path a program is most likely to hand us: the root itself
         * became "/disk2/", which resolved to nothing. Claude Code checks its
         * own working directory before it does anything else and stopped with
         *
         *     Error: Can't access working directory /: Path "/" does not exist
         *
         * which is true of the translated path and false of the real one. Any
         * directory named with a trailing slash -- "/tmp/", "foo/bar/" -- hit
         * the same wall. (M1992) */
        while (n > 1 && out[n - 1] == '/') out[--n] = 0;
        return out;
    }
    /* RELATIVE. Leaving these alone was wrong: the kernel resolves them against
     * its own current directory, which for a Linux process is not where the
     * process thinks it is. gcc writes its intermediate assembly as
     * "./ccXXXXXX.s" and died with
     *
     *     Cannot create temporary file in ./: No such file or directory
     *
     * Resolve against the process's OWN cwd, which app_spawn starts at
     * LX_ROOT. A leading "./" is stripped because it is pure noise that the
     * VFS's path walker does not recognise. (M1960) */
    while (p[0] == '.' && p[1] == '/') p += 2;
    const char *cwd = app_cwd_str(app_current());
    if (!cwd || !cwd[0]) cwd = LX_ROOT;
    for (int i = 0; cwd[i] && n < max - 1; i++) out[n++] = cwd[i];
    if (n && out[n - 1] != '/' && n < max - 1) out[n++] = '/';
    for (int i = 0; p[i] && n < max - 1; i++) out[n++] = p[i];
    out[n] = 0;
    while (n > 1 && out[n - 1] == '/') out[--n] = 0;      /* same rule for a relative path */
    return out;
}

/* THE dirfd WAS BEING DISCARDED (M2032).
 *
 * openat's own comment admitted it: "the leading dirfd, which we ignore anyway
 * (everything resolves against the process cwd)". So openat(dirfd, "name")
 * looked for "name" in the CWD instead of in the directory that fd refers to.
 *
 * That is not an edge case -- it is how every real directory walker reads a
 * tree. ripgrep's walkdir, Go's filepath.WalkDir, glibc's fts, find(1): all of
 * them open a directory once and then reference its children by a bare name
 * against that descriptor, because it is both faster and immune to renames.
 * Every one of those lookups landed in the wrong directory.
 *
 * The symptom was ripgrep reporting a hundred files as "No such file or
 * directory" that a shell in the same boot could list and read perfectly --
 * the file existed, the name was right, and the directory it was looked up in
 * was not the one asked for.
 *
 * Seventh instance of the session's recurring shape: an argument accepted and
 * then not honoured. (pipe2 M2009, socketpair M2012, eventfd2 M2017, bind
 * M2020, wait4's options M2025, a timeout as EOF M2026.)
 *
 * An absolute path ignores dirfd, exactly as Linux does. AT_FDCWD keeps the
 * old cwd-relative behaviour. The stored fd path is ALREADY kernel-side
 * (/disk2/...), so it must not be translated a second time. */
#define LX_AT_FDCWD (-100)
static const char *lx_xlate_at(long dirfd, const char *up, char *out, int max) {
    if (!up) return lx_xlate(up, out, max);
    if (up[0] == '/' || dirfd == LX_AT_FDCWD) return lx_xlate(up, out, max);
    const char *base = app_fd_path_of((int)dirfd);
    if (!base) return lx_xlate(up, out, max);      /* not a path-bearing fd: old behaviour */
    int p = 0;
    while (base[p] && p < max - 2) { out[p] = base[p]; p++; }
    if (p && out[p - 1] != '/') out[p++] = '/';
    /* skip a leading "./" so "./x" does not become "dir/./x" */
    const char *u = up;
    while (u[0] == '.' && u[1] == '/') u += 2;
    for (int k = 0; u[k] && p < max - 1; k++) out[p++] = u[k];
    out[p] = 0;
    return out;
}

/* struct iovec, exactly Linux's layout. */
struct lx_iovec { void *iov_base; unsigned long iov_len; };

/* Counters so the boot self-test can prove the path was actually taken rather
 * than inferring it from a value that could have come from anywhere. */
volatile unsigned long lx_syscall_count, lx_unknown_count;
static int64_t g_lx_boot_unix;   /* wall-clock second the machine booted; see clock_gettime (M1972) */

/* The wall clock, anchored to uptime so it cannot run backwards. Every
 * time-returning syscall uses this: reporting a different answer from time(),
 * gettimeofday() and clock_gettime() is its own bug, and a caller that mixes
 * them gets a negative interval. */
static int64_t lx_realtime_sec(void) {
    uint64_t ms = timer_ms();
    if (!g_lx_boot_unix) g_lx_boot_unix = (int64_t)rtc_unix() - (int64_t)(ms / 1000);
    return g_lx_boot_unix + (int64_t)(ms / 1000);
}

/* The last LXRING_N Linux syscalls, for post-mortem on a process that dies
 * without saying anything. (M1970) */
#define LXRING_N 256
/* WHICH THREAD MADE THE CALL (M2003). The ring is global -- it has to be, a
 * process's threads interleave and the interleaving is often the point -- but
 * that makes the history of the thread that actually FAULTED unreadable when
 * five others are busy. Firefox crashes with two threads in the same
 * instruction and ~470 mappings; without a tid the sixteen calls before it come
 * from six different places and mean nothing. */
#define LX_INFLIGHT 0xB10CEDB10CEDB10Cull   /* `ret` of a call that has not come back yet (M2004) */
/* `seq` is the global ticket this entry was claimed with (M2013). The ring is
 * 256 entries and a hundred threads share it, so a call that BLOCKS has its
 * slot recycled out from under it long before it returns -- and the return
 * patch below then lands on whatever call owns the slot now. That is how
 * FUTEX_WAKE appeared to return -110 (ETIMEDOUT), which it cannot: a slow
 * futex WAIT elsewhere finished and wrote its timeout into a stranger's entry.
 * Checking the ticket makes a late return drop its patch instead of lying. */
/* `pid` as well as `tid` (M2069). The ring is GLOBAL and shared by every Linux
 * process, so a short-lived child overwrites its parent's history completely:
 * every dump I took of a stalled Claude Code showed the same `git` exit, and
 * the parent's last 256 syscalls -- the only record of what it was doing -- had
 * been gone since before the stall began. One extra int makes the dump
 * filterable, which is the difference between an instrument and a decoration. */
struct lxring_ent { uint32_t nr; int tid; int pid; unsigned long seq; uint64_t a1, a2, a3, ret; char path[56]; };
static struct lxring_ent g_lxring[LXRING_N];
static unsigned long g_lxring_i;

/* Which argument of a syscall is a pathname, if any: 1 = rdi, 2 = rsi, 0 = none.
 * Captured AT RECORD TIME, not at dump time -- by the time a process aborts,
 * a string it opened forty calls ago may well have been freed, and a dump that
 * prints whatever is at that address now is worse than printing nothing. */
static int lx_path_arg(uint32_t nr) {
    switch (nr) {
        case 2: case 4: case 6: case 21: case 59: case 83: case 84: case 87:
        case 89: case 90: case 133: case 161:
            return 1;                       /* open/stat/unlink/access/execve/mkdir/rmdir/readlink/chmod/chroot */
        case 257: case 258: case 262: case 263: case 269: case 267: case 332:
            return 2;                       /* the *at forms: dirfd first, path second */
        default: return 0;
    }
}

/* Walk the user frame chain and print return addresses (M1970).
 *
 * A process that calls abort() leaves no fault address and, if it never got as
 * far as writing to stderr, no message either -- the syscall ring says WHAT it
 * did and still not WHERE it was. These addresses do: the image is ET_EXEC, so
 * they are its link-time addresses, and `addr2line -e <binary>` on the host
 * resolves them directly.
 *
 * -fno-omit-frame-pointer is not something we can impose on a foreign binary,
 * so this is best-effort: it stops at the first RBP that is not a plausible,
 * increasing user address rather than chasing garbage. */
/* Read user memory WITHOUT materialising it (M1991).
 *
 * vmm_user_ok resolves a lazily-mappable page as a side effect -- which is the
 * right thing for a syscall argument and exactly wrong on the fault path: the
 * backtrace walks a user stack that may be half-mapped, so checking it with
 * vmm_user_ok re-enters app_fault_handle from inside app_fault_handle. Four
 * levels deep the recursion guard refuses and the process dies of the
 * diagnostic rather than of its own bug. vmm_translate answers the same
 * question and changes nothing. */
static int lx_user_mapped(uint64_t p, uint64_t n) {
    for (uint64_t a = p & ~(uint64_t)0xFFF; a < p + n; a += 0x1000)
        if (!vmm_translate(a)) return 0;
    return 1;
}

void lx_user_backtrace(struct registers *r) {
    kprintf("[linuxabi] user backtrace: rip=%lx rsp=%lx rbp=%lx\n", r->rip, r->rsp, r->rbp);
    uint64_t rbp = r->rbp, prev = 0;
    for (int f = 0; f < 16; f++) {
        if (rbp <= prev || (rbp & 7) || !lx_user_mapped(rbp, 16)) break;
        uint64_t ret = ((const uint64_t *)rbp)[1];
        if (!ret) break;
        kprintf("    [%d] %lx\n", f, ret);
        prev = rbp;
        rbp = ((const uint64_t *)rbp)[0];
    }
    /* The chain above needs frame pointers, and optimised code does not keep
     * them -- it stops early or follows garbage. Scanning the stack for values
     * that fall inside a mapped EXECUTABLE region finds the return addresses
     * regardless, at the cost of some false positives. Both are printed
     * because they fail in different ways. (M1970) */
    kprintf("[linuxabi] stack scan (executable-looking words):\n");
    struct app *a = app_current();
    int shown = 0;
    for (uint64_t sp = r->rsp; sp < r->rsp + 1024 && shown < 24; sp += 8) {
        if (!lx_user_mapped(sp, 8)) break;
        uint64_t w = *(const uint64_t *)sp;
        if (w < 0x1000) continue;
        int exec = 0;
        for (int i = 0; a && i < app_vma_count(a); i++) {
            uint64_t st, ln; int prot;
            if (app_vma_info(a, i, &st, &ln, &prot) != 0) continue;
            if (w >= st && w < st + ln && (prot & 0x4)) { exec = 1; break; }   /* PROT_EXEC */
        }
        if (exec) { kprintf("    +%lu: %lx\n", sp - r->rsp, w); shown++; }
    }
}

unsigned long lx_syscalls_made(void) { return lx_syscall_count; }

void lx_trace_dump_pid(const char *why, unsigned long want, int only_pid);
void lx_trace_dump_last(const char *why, unsigned long want) { lx_trace_dump_pid(why, want, 0); }

/* `only_pid` != 0 restricts the dump to one process and SCANS THE WHOLE RING
 * for its entries, rather than taking the last `want` slots -- otherwise a
 * chatty child still crowds the parent out of the window. (M2069) */
void lx_trace_dump_pid(const char *why, unsigned long want, int only_pid) {
    unsigned long have = g_lxring_i < LXRING_N ? g_lxring_i : LXRING_N;
    unsigned long n = have;
    if (!only_pid && want && n > want) n = want;
    if (only_pid) {
        unsigned long shown = 0;
        kprintf("[linuxabi] last syscalls by pid %d before %s (oldest first):\n", only_pid, why);
        /* Count backwards to find where the last `want` of THIS pid's entries
         * start, then print forwards so the order reads chronologically. */
        unsigned long start = have, found = 0;
        for (unsigned long k = 0; k < have && found < (want ? want : have); k++) {
            struct lxring_ent *e = &g_lxring[(g_lxring_i - 1 - k) & (LXRING_N - 1)];
            if (e->pid == only_pid) { found++; start = have - 1 - k; }
        }
        for (unsigned long k = start; k < have; k++) {
            struct lxring_ent *e = &g_lxring[(g_lxring_i - have + k) & (LXRING_N - 1)];
            if (e->pid != only_pid) continue;
            if (e->ret == LX_INFLIGHT) {
                if (e->path[0]) kprintf("   t%d %u(%lx, %lx, %lx) = <still blocked in this call>  \"%s\"\n", e->tid, e->nr, e->a1, e->a2, e->a3, e->path);
                else            kprintf("   t%d %u(%lx, %lx, %lx) = <still blocked in this call>\n", e->tid, e->nr, e->a1, e->a2, e->a3);
            } else if (e->path[0]) kprintf("   t%d %u(%lx, %lx, %lx) = %lx  \"%s\"\n", e->tid, e->nr, e->a1, e->a2, e->a3, e->ret, e->path);
            else            kprintf("   t%d %u(%lx, %lx, %lx) = %lx\n", e->tid, e->nr, e->a1, e->a2, e->a3, e->ret);
            shown++;
        }
        if (!shown) kprintf("   (no entries for pid %d are left in the ring -- another process filled it)\n", only_pid);
        return;
    }
    kprintf("[linuxabi] last %lu syscalls before %s (oldest first):\n", n, why);
    for (unsigned long k = 0; k < n; k++) {
        struct lxring_ent *e = &g_lxring[(g_lxring_i - n + k) & (LXRING_N - 1)];
        /* The RETURN VALUE is the point. Arguments alone show what a program
         * asked for; only the result shows which answer it could not live
         * with, and a negative return here is a Linux errno. */
        if (e->ret == LX_INFLIGHT) {
            if (e->path[0]) kprintf("   t%d %u(%lx, %lx, %lx) = <still blocked in this call>  \"%s\"\n", e->tid, e->nr, e->a1, e->a2, e->a3, e->path);
            else            kprintf("   t%d %u(%lx, %lx, %lx) = <still blocked in this call>\n", e->tid, e->nr, e->a1, e->a2, e->a3);
        } else if (e->path[0]) kprintf("   t%d %u(%lx, %lx, %lx) = %lx  \"%s\"\n", e->tid, e->nr, e->a1, e->a2, e->a3, e->ret, e->path);
        else            kprintf("   t%d %u(%lx, %lx, %lx) = %lx\n", e->tid, e->nr, e->a1, e->a2, e->a3, e->ret);
    }
}

void lx_trace_dump(const char *why) { lx_trace_dump_last(why, 0); }

/* The depth a RING-3 FAULT dumps at. 64 entries with a tid on each is what made
 * Firefox's faulting thread readable among five busy ones -- and it is ~120
 * extra lines of byte-at-a-time serial output per fault, which pushed the
 * console-lock regression boot past its budget. Deep on demand, modest by
 * default: the flag that asks for syscall tracing is asking for exactly this.
 * (M2003) */
void lx_trace_dump_fault(void) {
    lx_trace_dump_last("a ring-3 fault", g_lx_systrace ? 64 : 20);
}

/* DUMP THE HISTORY WHEN A PROGRAM SAYS IT IS GIVING UP (M1992).
 *
 * Hooking "the first write to fd 2" did not work, and finding that out was
 * the useful part: a runtime with its own IO layer does not necessarily use
 * stderr, or write(), or even the fd the message appears on. What is reliable
 * is the TEXT -- a program announcing an error says so in words, and the ring
 * holds what it did to get there. One shot per boot, and it costs a substring
 * scan of output that is already being copied. */
static int g_err_traced;
static void lx_trace_on_error(const char *b, unsigned long n) {
    if (g_err_traced || !b || n < 6 || n > 4096) return;
    static const char *needles[] = { "Error", "error:", "cannot", "Cannot", "does not exist", 0 };
    for (int k = 0; needles[k]; k++) {
        const char *nd = needles[k];
        for (unsigned long i = 0; i + 5 < n; i++) {
            unsigned long j = 0;
            while (nd[j] && i + j < n && b[i + j] == nd[j]) j++;
            if (!nd[j]) {
                g_err_traced = 1;
                kprintf("[linuxabi] the program is reporting an error; the last 20 syscalls were:\n");
                lx_trace_dump_last("that error", 0);   /* the WHOLE ring: the failing call is further back than 20 */
                return;
            }
        }
    }
}   /* 0 = the whole ring */

/*
 * The Linux dispatcher. Mirrors syscall_dispatch's shape (it mutates the same
 * struct registers in place, and the return value goes in r->rax) but reads
 * LINUX numbers and returns NEGATIVE ERRNO -- see lxerrno.h for why that
 * matters more than it looks.
 *
 * Deliberately small for now: enough for a static binary to start up, say
 * something and exit. Everything else returns -ENOSYS, which is the honest
 * answer and exactly what musl expects for a call the kernel lacks.
 */
/* -append polltrace: when a poll/epoll_wait sits for seconds without a single
 * ready fd, print the WHOLE fd set with each fd's type and readiness. A stalled
 * event loop looks exactly like a hung process from outside, and the fd set is
 * the only thing that names which descriptor the program waits on and which
 * layer owes it an event. (M1998) */
/* "/proc/self/<tail>" or "/proc/<our own pid>/<tail>" -> <tail>, else 0. A
 * process asking about another process's descriptors is not something anything
 * we run does, and answering it wrongly is worse than saying no. (M1998) */
static int str_eq_lx(const char *a, const char *b) {
    int i = 0; while (a[i] && a[i] == b[i]) i++;
    return a[i] == b[i];
}
static const char *lx_proc_self_tail(const char *p) {
    const char *pre = "/proc/";
    int i = 0; while (pre[i]) { if (p[i] != pre[i]) return 0; i++; }
    const char *q = p + i;
    if (q[0] == 's' && q[1] == 'e' && q[2] == 'l' && q[3] == 'f' && q[4] == '/') return q + 5;
    int v = 0, k = 0;
    while (q[k] >= '0' && q[k] <= '9') { v = v * 10 + (q[k] - '0'); k++; }
    if (k && q[k] == '/' && v == app_current_pid()) return q + k + 1;
    return 0;
}

int g_poll_trace;
static int g_poll_reports;

/* HOW MANY SYSCALLS THIS THREAD HAS MADE (M2066). Per-task, so a thread that
 * dies young can say how far it got -- "exited after 6 syscalls" is a failed
 * startup, "after 40000" is a worker that finished its work. 16 slots keyed on
 * the task id, which is enough to be informative and cannot grow unboundedly;
 * a collision only mixes two counters in a diagnostic. */
static unsigned long g_thr_calls[16];
static void lx_thread_calls_bump(void) { g_thr_calls[task_current_id() & 15]++; }
static unsigned long lx_thread_calls(void) { return g_thr_calls[task_current_id() & 15]; }

/* Output from a Linux process goes to the window that launched it, or to the
 * kernel console when there is none. Which of the two it took is the whole
 * question when a program "produces no output" -- so say, once per process,
 * when it takes the console. (M2004) */
/* -append lxout: mirror a Linux process's output to the kernel log as well as
 * to its window (M2023).
 *
 * Everything a guest program prints has only ever existed as PIXELS -- it goes
 * to a window text grid, and nothing else. That means the only way to read what
 * a program said is to screenshot it and transcribe, which I did to get Claude
 * Code's OAuth URL out and promptly misread one character of a scope string.
 * The program was not wrong and the terminal was not wrong; the output simply
 * was not text anywhere.
 *
 * It costs nothing on screen: since M2011 the console writes to the serial port
 * and /proc/kmsg only once the window manager owns the framebuffer. So this is
 * the same bytes, in a form you can grep. */
int g_lx_out_log;
static void lx_emit(const char *b, unsigned long n) {
    app_t *dst = app_out_to();
    /* The lxout mirror moved into app_write_to (M2056) -- it has to cover the
     * fd-table path too, and doing it in both places printed the no-window
     * case twice. */
    if (dst) { app_write_to(dst, b, (unsigned)n); return; }
    static int told_pid = -1;
    int me = app_current_pid();
    if (me != told_pid) {
        told_pid = me;
        kprintf("[app] pid %d has NO window for its output -- going to the console\n", me);
    }
    console_write_n(b, n);
}

/* HOW LONG TO WAIT BEFORE LOOKING AGAIN (M2004).
 *
 * Every poll and epoll_wait here is a sleep-spin, and it slept 10 ms between
 * checks. That is a hard ceiling of a hundred wake-ups a second on every
 * socket in the system, and a TLS handshake is a dozen round trips of a few
 * kilobytes each -- so a connection that takes a fraction of a second on Linux
 * took many seconds here, and Claude Code's ten-second connectivity check
 * simply expired:
 *
 *     Connection to platform.claude.com timed out after 10 seconds
 *
 * Busy work is cheap for the first moment and expensive forever, so back off:
 * 1 ms while something is plainly in flight, widening to 10 ms once the wait
 * is clearly idle. An event loop servicing I/O gets a hundredfold more
 * chances to see it; a loop parked on nothing costs what it did before. */
static int lx_poll_nap(int spins) { return spins < 200 ? 1 : 10; }

/* A syscall NUMBER is not a name, and a histogram of numbers is unreadable
 * (M2066). Generated from the LXS_* table in this file, so it cannot drift
 * from what is actually dispatched. "?" means we have never handled it. */
const char *lx_syscall_name(unsigned long nr) {
    switch (nr) {
    case 0: return "read";
    case 1: return "write";
    case 2: return "open";
    case 3: return "close";
    case 4: return "stat";
    case 5: return "fstat";
    case 6: return "lstat";
    case 7: return "poll";
    case 8: return "lseek";
    case 9: return "mmap";
    case 10: return "mprotect";
    case 11: return "munmap";
    case 12: return "brk";
    case 13: return "rt_sigaction";
    case 14: return "rt_sigprocmask";
    case 15: return "rt_sigreturn";
    case 16: return "ioctl";
    case 17: return "pread64";
    case 19: return "readv";
    case 20: return "writev";
    case 21: return "access";
    case 22: return "pipe";
    case 24: return "sched_yield";
    case 25: return "mremap";
    case 28: return "madvise";
    case 32: return "dup";
    case 33: return "dup2";
    case 34: return "pause";
    case 35: return "nanosleep";
    case 39: return "getpid";
    case 40: return "sendfile";
    case 41: return "socket";
    case 42: return "connect";
    case 43: return "accept";
    case 44: return "sendto";
    case 45: return "recvfrom";
    case 46: return "sendmsg";
    case 47: return "recvmsg";
    case 48: return "shutdown";
    case 49: return "bind";
    case 50: return "listen";
    case 51: return "getsockname";
    case 52: return "getpeername";
    case 53: return "socketpair";
    case 54: return "setsockopt";
    case 55: return "getsockopt";
    case 56: return "clone";
    case 57: return "fork";
    case 58: return "vfork";
    case 59: return "execve";
    case 60: return "exit";
    case 61: return "wait4";
    case 62: return "kill";
    case 63: return "uname";
    case 72: return "fcntl";
    case 74: return "fsync";
    case 75: return "fdatasync";
    case 77: return "ftruncate";
    case 79: return "getcwd";
    case 80: return "chdir";
    case 81: return "fchdir";
    case 82: return "rename";
    case 83: return "mkdir";
    case 84: return "rmdir";
    case 86: return "link";
    case 87: return "unlink";
    case 88: return "symlink";
    case 89: return "readlink";
    case 90: return "chmod";
    case 91: return "fchmod";
    case 95: return "umask";
    case 96: return "gettimeofday";
    case 98: return "getrusage";
    case 99: return "sysinfo";
    case 102: return "getuid";
    case 104: return "getgid";
    case 107: return "geteuid";
    case 108: return "getegid";
    case 110: return "getppid";
    case 118: return "getresuid";
    case 120: return "getresgid";
    case 125: return "capget";
    case 127: return "rt_sigpending";
    case 130: return "rt_sigsuspend";
    case 131: return "sigaltstack";
    case 137: return "statfs";
    case 138: return "fstatfs";
    case 140: return "getpriority";
    case 141: return "setpriority";
    case 142: return "sched_setparam";
    case 143: return "sched_getparam";
    case 144: return "sched_setscheduler";
    case 145: return "sched_getscheduler";
    case 157: return "prctl";
    case 158: return "arch_prctl";
    case 186: return "gettid";
    case 187: return "readahead";
    case 200: return "tkill";
    case 201: return "time";
    case 202: return "futex";
    case 204: return "sched_getaffinity";
    case 217: return "getdents64";
    case 218: return "set_tid_address";
    case 221: return "fadvise64";
    case 228: return "clock_gettime";
    case 229: return "clock_getres";
    case 230: return "clock_nanosleep";
    case 231: return "exit_group";
    case 232: return "epoll_wait";
    case 233: return "epoll_ctl";
    case 234: return "tgkill";
    case 254: return "inotify_add_watch";
    case 255: return "inotify_rm_watch";
    case 257: return "openat";
    case 258: return "mkdirat";
    case 262: return "newfstatat";
    case 263: return "unlinkat";
    case 265: return "linkat";
    case 266: return "symlinkat";
    case 267: return "readlinkat";
    case 268: return "fchmodat";
    case 269: return "faccessat";
    case 271: return "ppoll";
    case 273: return "set_robust_list";
    case 280: return "utimensat";
    case 281: return "epoll_pwait";
    case 284: return "eventfd";
    case 285: return "fallocate";
    case 288: return "accept4";
    case 290: return "eventfd2";
    case 283: return "timerfd_create";
    case 286: return "timerfd_settime";
    case 287: return "timerfd_gettime";
    case 26: return "msync";
    case 291: return "epoll_create1";
    case 293: return "pipe2";
    case 294: return "inotify_init1";
    case 295: return "preadv";
    case 296: return "pwritev";
    case 299: return "recvmmsg";
    case 302: return "prlimit64";
    case 307: return "sendmmsg";
    case 318: return "getrandom";
    case 319: return "memfd_create";
    case 327: return "preadv2";
    case 328: return "pwritev2";
    case 332: return "statx";
    case 334: return "rseq";
    case 434: return "pidfd_open";
    case 435: return "clone3";
    case 436: return "close_range";
    case 441: return "epoll_pwait2";
    default: return "?";
    }
}

void linux_syscall_dispatch(struct registers *r) {
    /* WHICH RING SLOT THIS CALL OWNS -- a LOCAL, not a shared cursor (M2003).
     *
     * g_lxring_cur was a single global pointer set on entry and patched with
     * the result on exit. With two threads in the syscall path at once -- which
     * is the normal state of any threaded program -- the second overwrites it,
     * and the first patches the SECOND's slot with its own return value. The
     * ring then attributes one thread's answer to another thread's call, and
     * the dump reads as a syscall returning something it cannot possibly
     * return: a futex wait reporting ENOENT, which sent me looking for a bug in
     * the futex code that was never there.
     *
     * A diagnostic that lies is worse than no diagnostic. This is the same
     * shared-mutable-global class as the recvmsg staging buffer in M2001 --
     * worth grepping the whole file for. */
    unsigned long ring_slot;
    lx_thread_calls_bump();
    /* PAY ANY TLB DEBT BEFORE TOUCHING USER MEMORY (M2065). Almost every
     * handler below dereferences a user pointer directly after vmm_user_ok,
     * so a stale translation here reads the WRONG PAGE -- silently, with the
     * right permissions. A shootdown that timed out leaves this core's flag
     * set precisely so that this line settles it. */
    vmm_tlb_discharge();
    lx_syscall_count++;
    app_count_lx_syscall(r->rax);    /* per-process, BY NUMBER, for the stall watchdog + histogram (M2004/M2066) */
    /* Always record; print only on demand. The rate-limited trace below is for
     * finding a SPIN (the same call repeating), and deliberately samples one in
     * 4096 so a compiler does not drown the log -- but that makes it useless for
     * the opposite question, "what were the last things this process did before
     * it died?". A program that calls abort() on itself prints nothing and
     * leaves no fault address; without a history there is simply no evidence.
     * The ring costs one store per syscall and is dumped by lx_trace_dump on an
     * abnormal exit. (M1970) */
    {
        /* Claim the slot ATOMICALLY: a plain post-increment shared by every
         * thread hands two of them the same entry, and one overwrites the
         * other's call. (M2003) */
        ring_slot = __atomic_fetch_add(&g_lxring_i, 1, __ATOMIC_RELAXED);
        struct lxring_ent *re = &g_lxring[ring_slot & (LXRING_N - 1)];
        re->nr = (uint32_t)r->rax; re->tid = task_current_id(); re->pid = app_current_pid(); re->seq = ring_slot;
        re->a1 = r->rdi; re->a2 = r->rsi; re->a3 = r->rdx;
        /* MARK IT IN FLIGHT (M2004). `ret` is only written when the dispatch
         * RETURNS, so an entry for a call that is still blocked -- which is
         * exactly the entry you most want to read when a program has stalled --
         * displayed whatever the previous occupant of the slot returned. That
         * is how a futex wait appeared to return ENOENT, which it cannot, and
         * it cost me a search for a bug that was not there. A blocked call has
         * no return value yet; say so. */
        re->ret = LX_INFLIGHT;
        re->path[0] = 0;
        int pa = lx_path_arg(re->nr);
        if (pa) {
            uint64_t up = (pa == 1) ? r->rdi : r->rsi;
            if (up && vmm_user_ok(up, 1)) {
                const char *sp = (const char *)up;
                int ci = 0;
                while (ci < (int)sizeof re->path - 1 && sp[ci]) { re->path[ci] = sp[ci]; ci++; }
                re->path[ci] = 0;
            }
        }

    }
    if (g_lx_systrace && (lx_syscall_count & 0xFFF) == 0)
        kprintf("[sys] %ld(%lx,%lx,%lx)\n", (long)r->rax, r->rdi, r->rsi, r->rdx);
    long a1 = (long)r->rdi, a3 = (long)r->rdx;
    const char *p2 = (const char *)r->rsi;

    switch (r->rax) {
    case LXS_write: {                       /* (fd, buf, count) */
        /* BEFORE the fd branching: the message a program prints when it gives
         * up does not necessarily go to fd 1 or 2. Claude Code writes its
         * startup error to fd SEVEN -- a dup -- which took the fd-table path
         * and never reached the console hook this used to live in. (M1992) */
        if (a3 > 0 && a3 < 4096 && vmm_user_ok(r->rsi, (uint64_t)a3))
            lx_trace_on_error((const char *)r->rsi, (unsigned long)a3);
        /* fd 1/2 are the console ONLY while untouched. After dup2() onto a
         * pipe they are real fd-table entries and must go there -- routing
         * them to the console regardless is why the first pipeline attempt
         * produced "LXBOX-WC: 0": the writer's output went to the screen
         * instead of down the pipe, so the reader saw EOF immediately. */
        if ((a1 != 1 && a1 != 2) || app_fd_is_open((int)a1)) {
            if (a3 < 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
            if (a3 && !vmm_user_ok(r->rsi, (uint64_t)a3)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            long w = app_fd_write((int)a1, (const void *)r->rsi, (unsigned long)a3);
            /* A write that reports ZERO bytes for a non-empty buffer is not a
             * short write, it is NO PROGRESS -- and every caller loops on a
             * short write, so it spins forever. `as` did exactly that for
             * twenty minutes on a large object file, burning a core with flat
             * memory and no diagnostic anywhere. Say so. (M1961) */
            if (w == 0 && a3 > 0 && app_fd_type((int)a1) != 12)
                kprintf("[linuxabi] write(fd %ld, %ld bytes) made NO PROGRESS\n", a1, a3);
            /* A socket whose ring is full wrote zero bytes and that is EAGAIN,
             * not an error and not progress -- returning 0 would make the
             * caller loop forever on a buffer that only drains when it goes
             * back to poll. (M1965) */
            if (w == 0 && a3 > 0 && app_fd_type((int)a1) == 12) w = APP_FD_EAGAIN;
            r->rax = (w < 0) ? (uint64_t)lx_fd_err(w) : (uint64_t)w;
            break;
        }
        /* Validate before dereferencing -- the native path routes every ring-3
         * pointer through vmm_user_ok (a PTE_USER page-table walk) and this
         * path must not be the hole in that. An unvalidated buf here would let
         * ring 3 make the kernel read arbitrary memory and print it. */
        if (a3 < 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (a3 && !vmm_user_ok(r->rsi, (uint64_t)a3)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        {   /* THE FIRST WRITE TO STDERR is where a program says why it is
             * about to give up, and the ring holds what it did to get there.
             * Printing the history at that exact moment is the difference
             * between "it printed an error" and knowing which call returned
             * the answer it could not live with. Once per boot. (M1992) */
            /* Launched from a shell? Then its window is where the output
             * belongs -- see app_write_to. Otherwise the console, as before. */
            lx_emit(p2, (unsigned long)a3);
        }
        r->rax = (uint64_t)a3;
        break;
    }
    case LXS_readv:                         /* (fd, iov, iovcnt) */
    case LXS_preadv:                        /* (fd, iov, iovcnt, off) */
    case LXS_preadv2: {                     /* (fd, iov, iovcnt, off_lo, off_hi, flags) */
        /* READV DID NOT EXIST (M2004), which went unnoticed because glibc's
         * stdio reads with read(2). Bun does not use glibc's stdio: it reads
         * stdin with preadv2, and an ENOSYS there means an interactive program
         * can never see a keystroke. It sat waiting for input it had no way to
         * receive, which looks exactly like a program that has hung.
         *
         * An offset of -1 means "use the file position", i.e. plain readv --
         * which is what a terminal always is, since a tty has no position. */
        long noff = (r->rax == LXS_readv) ? -1 : (long)r->r10;
        const struct lx_iovec *v = (const struct lx_iovec *)r->rsi;
        if (a3 < 0 || a3 > 1024) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (!vmm_user_ok(r->rsi, (uint64_t)a3 * sizeof *v)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        if (!app_fd_is_open((int)a1) && a1 != 0) { r->rax = (uint64_t)-(long)LX_EBADF; break; }
        long total = 0;
        for (long i = 0; i < a3; i++) {
            char *b = (char *)v[i].iov_base;
            unsigned long n = v[i].iov_len;
            if (!n) continue;
            if (!vmm_user_ok((uint64_t)v[i].iov_base, n)) { if (!total) total = -(long)LX_EFAULT; break; }
            long got;
            if (noff >= 0) {
                /* Positional: read the file directly so the fd's cursor is not
                 * disturbed, exactly as pread64 does for ld.so. */
                const char *fp = app_fd_path((int)a1);
                got = fp ? vfs_pread(fp, b, n, (uint64_t)noff + (uint64_t)total) : -1;
            } else {
                got = app_fd_read((int)a1, b, n);
            }
            if (got == APP_FD_EAGAIN) { if (!total) total = -(long)LX_EAGAIN; break; }
            if (got < 0) { if (!total) total = (long)lx_fd_err(got); break; }
            total += got;
            if ((unsigned long)got < n) break;   /* short read: stop, as readv does */
        }
        r->rax = (uint64_t)total;
        break;
    }
    case LXS_pwritev:
    case LXS_pwritev2:
    case LXS_writev: {                      /* (fd, iov, iovcnt) -- glibc's stdio flush path */
        /* Same rule as write(): fd 1/2 are the console ONLY while untouched.
         * This handler previously hard-coded them to the console and returned
         * EBADF for everything else, so a dup2'd stdout still went to the
         * SCREEN -- which is why the pipeline's writer produced console output
         * and the reader saw an empty pipe, even after write() was fixed.
         * glibc's buffered stdio flushes through writev, not write, so fixing
         * only write() fixed only the unbuffered cases. */
        int fd_tab = app_fd_is_open((int)a1);
        if (a1 != 1 && a1 != 2 && !fd_tab) { r->rax = (uint64_t)-(long)LX_EBADF; break; }
        const struct lx_iovec *v = (const struct lx_iovec *)r->rsi;
        if (a3 < 0 || a3 > 1024) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        /* The iovec ARRAY is a user pointer, and so is every iov_base inside
         * it -- both need validating, and the array first, or we would be
         * reading the lengths we validate against out of unchecked memory. */
        if (!vmm_user_ok(r->rsi, (uint64_t)a3 * sizeof *v)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        long total = 0;
        for (long i = 0; i < a3; i++) {
            const char *b = (const char *)v[i].iov_base;
            unsigned long n = v[i].iov_len;
            if (!n) continue;
            if (!b || !vmm_user_ok((uint64_t)b, n)) { r->rax = (uint64_t)-(long)LX_EFAULT; goto done; }
            if (fd_tab) {
                long w = app_fd_write((int)a1, b, n);
                if (w == 0 && app_fd_type((int)a1) == 12) w = APP_FD_EAGAIN;
                /* A partial writev is a SUCCESS with a short count. Only
                 * report the error when nothing at all got through, or a
                 * caller that already sent 8 KiB is told it sent none. */
                if (w < 0) {
                    if (total > 0) { r->rax = (uint64_t)total; goto done; }
                    r->rax = (uint64_t)lx_fd_err(w); goto done;
                }
                total += w;
                if ((unsigned long)w < n) { r->rax = (uint64_t)total; goto done; }   /* short: stop, don't skip a gap */
            } else {
                /* Same reason the routing lives here: buffered output goes out
                 * through writev, so a hook on write() alone never sees the
                 * error message a program prints before giving up. (M1992) */
                /* glibc's buffered stdio flushes through writev, not write, so
                 * the shell-window routing has to be here too -- fixing only
                 * write() would leave every printf-heavy program invisible. */
                lx_emit(b, (unsigned long)n);
                total += (long)n;
            }
        }
        r->rax = (uint64_t)total;
        break;
    }
    done: break;
    case LXS_getpid:
        /* THE PROCESS's id, NOT THE CALLING THREAD's (M2003).
         *
         * On Linux every thread of a process reports the same getpid() -- that
         * is the difference between getpid and gettid, and it is load-bearing.
         * This returned task_current_id(), so each thread got its own answer.
         * It went unnoticed for as long as nothing threaded got far enough to
         * care: a program that records getpid() at startup and re-checks it
         * later to find out whether it has been forked concludes that it HAS
         * been, on every thread, and takes its post-fork teardown path.
         *
         * It was also inconsistent with its own neighbours: fork() hands the
         * parent the child's APP pid, getppid() returns an app pid, and
         * /proc/<pid> is keyed on app pids. getpid() was the one that answered
         * in a different namespace. */
        r->rax = (uint64_t)app_current_pid();
        break;
    case LXS_arch_prctl:
        /* musl sets up its thread pointer here before main; refusing it is
         * fatal, because every later TLS access reads through %fs. */
        if (a1 == ARCH_SET_FS) { task_set_fs_base(r->rsi); r->rax = 0; }
        else                    r->rax = (uint64_t)-(long)LX_EINVAL;
        break;
    case LXS_set_tid_address:
        /* Was: return the tid and THROW THE POINTER AWAY. That pointer is what
         * the kernel zeroes and FUTEX_WAKEs on thread exit, so discarding it
         * makes a blocking pthread_join wait forever. (M1959) */
        r->rax = (uint64_t)app_set_tid_address(r->rdi);
        break;
    case LXS_unlink_:                       /* (path) */
        /* shm_unlink(3) is unlink("/dev/shm/NAME"). Firefox creates its segment
         * with O_EXCL and unlinks it immediately, so without this the next
         * process to want that name collides with a ghost. (M2008) */
        if (r->rdi && vmm_user_ok(r->rdi, 1)) {
            const char *up_ = (const char *)r->rdi;
            const char *t_ = "/dev/shm/";
            int k_ = 0; while (t_[k_] && up_[k_] == t_[k_]) k_++;
            if (!t_[k_] && up_[k_]) {
                int urc = app_shm_unlink(up_ + k_);
                r->rax = (urc < 0) ? (uint64_t)(long)urc : 0;
                break;
            }
        }
    case LXS_unlinkat_: {                   /* (dirfd, path, flags) */
        /* unlinkat shifts its arguments one right, exactly like faccessat. */
        uint64_t up = (r->rax == LXS_unlink_) ? r->rdi : r->rsi;
        const char *upath = (const char *)up;
        if (!upath || !vmm_user_ok(up, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate_at((long)r->rdi, upath, xp, sizeof xp);   /* dirfd (M2032) */
        /* gcc writes its intermediate .s to a mkstemp'd name and unlinks it
         * when done; without this the driver reported
         * "gcc: error: ./ccXXXXXX.s: Function not implemented" and stopped
         * before it ever ran the assembler. (M1960) */
        r->rax = (uint64_t)(vfs_remove(path) == 0 ? 0 : -(long)LX_ENOENT);
        break;
    }
    case LXS_mkdir_:                        /* (path, mode) */
    case LXS_mkdirat_: {                    /* (dirfd, path, mode) */
        uint64_t up = (r->rax == LXS_mkdir_) ? r->rdi : r->rsi;   /* mkdirat shifts right */
        const char *upath = (const char *)up;
        if (!upath || !vmm_user_ok(up, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate_at((long)r->rdi, upath, xp, sizeof xp);   /* dirfd (M2032) */
        /* A TRAILING SLASH is legal in mkdir(2) -- `mkdir -p o/kernel/` passes
         * one straight through -- and our VFS path walker treats it as an
         * extra empty component and fails. Strip it here rather than in
         * lx_xlate, where a trailing slash still carries meaning for stat. */
        { int e = 0; while (xp[e]) e++;
          while (e > 1 && xp[e - 1] == '/') xp[--e] = 0;
          if (path == xp) path = xp; }
        /* A build creates its output tree before compiling anything, so
         * without this `mkdir -p o/kernel` failed with "Function not
         * implemented" and the very first object file stopped the build. */
        if (vfs_mkdir(path) != 0) {
            /* Already there is SUCCESS for mkdir -p, which retries per
             * component; reporting EEXIST is what lets it continue. */
            struct statx ex;
            if (vfs_stat(path, &ex) == 0) { r->rax = (uint64_t)-(long)LX_EEXIST; break; }
            kprintf("[linuxabi] mkdir(%s) failed\n", path);
            r->rax = (uint64_t)-(long)LX_ENOENT;
            break;
        }
        r->rax = 0;
        break;
    }
    case LXS_link_:                         /* (oldpath, newpath) */
    case LXS_linkat_: {                     /* (olddirfd, old, newdirfd, new, flags) */
        /* HARD LINKS. ext2_link_path has existed since M1207 and vfs_link
         * since then; this entry point simply never existed, so every attempt
         * came back ENOSYS. Firefox makes them -- a profile writes its files
         * by linking a temporary into place, which is how an update is made
         * atomic. An allocator of atomicity that cannot link falls back to
         * copy-and-rename or gives up. (M1999) */
        uint64_t uo = (r->rax == LXS_link_) ? r->rdi : r->rsi;
        uint64_t un = (r->rax == LXS_link_) ? r->rsi : r->r10;
        if (!uo || !un || !vmm_user_ok(uo, 1) || !vmm_user_ok(un, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xo[VFS_PATH_MAX], xn[VFS_PATH_MAX];
        const char *op = lx_xlate((const char *)uo, xo, sizeof xo);
        const char *np = lx_xlate((const char *)un, xn, sizeof xn);
        r->rax = (uint64_t)(vfs_link(op, np) == 0 ? 0 : -(long)LX_EPERM);
        break;
    }
    case LXS_symlink_:                      /* (target, linkpath) */
    case LXS_symlinkat_: {                  /* (target, newdirfd, linkpath) */
        /* SYMLINKS, same story: vfs_symlink creates real on-disk ext2 symlinks
         * (M1146) and readlink has read them since M1998. Note the argument
         * ORDER -- symlink(2) is (target, linkpath), the opposite way round
         * from link(2)'s (old, new) in the sense that the FIRST argument is
         * the contents of the link, not an existing path that must resolve.
         * Getting it backwards produces links that point at themselves. */
        uint64_t ut = r->rdi;
        uint64_t ul = (r->rax == LXS_symlink_) ? r->rsi : r->rdx;
        if (!ut || !ul || !vmm_user_ok(ut, 1) || !vmm_user_ok(ul, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xl[VFS_PATH_MAX];
        const char *lp = lx_xlate((const char *)ul, xl, sizeof xl);
        /* The TARGET is not translated: it is the link's contents, a string
         * interpreted later in the process's own view of the filesystem, and
         * rewriting it into /disk2/... would bake our mount point into a file
         * on disk. */
        r->rax = (uint64_t)(vfs_symlink(lp, (const char *)ut) == 0 ? 0 : -(long)LX_EPERM);
        break;
    }
    case LXS_utimensat_: {                  /* (dirfd, path, struct timespec[2], flags) */
        /* Set a file's times. app_utimens has existed since M1230 and was
         * reachable only through the native entry point. Claude Code calls
         * this on every file it writes; a build system calls it to make an
         * output look older or newer than its input, so this is the
         * self-hosting path too. NULL times means "now" for both.
         *
         * UTIME_NOW is 0x3fffffff and UTIME_OMIT is 0x3ffffffe, in the
         * NANOSECONDS field -- a value that is not a time at all, which is why
         * they have to be recognised before the seconds are used. */
        if (!r->rsi || !vmm_user_ok(r->rsi, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xu[VFS_PATH_MAX];
        const char *up2 = lx_xlate((const char *)r->rsi, xu, sizeof xu);
        long at = -1, mt = -1;                       /* -1 = leave alone */
        if (!r->rdx) { at = (long)(rtc_unix()); mt = at; }
        else if (vmm_user_ok(r->rdx, 32)) {
            const int64_t *ts = (const int64_t *)r->rdx;
            long now = (long)rtc_unix();
            at = (ts[1] == 0x3fffffff) ? now : (ts[1] == 0x3ffffffe ? -1 : (long)ts[0]);
            mt = (ts[3] == 0x3fffffff) ? now : (ts[3] == 0x3ffffffe ? -1 : (long)ts[2]);
        } else { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        r->rax = (uint64_t)(vfs_utimes(up2, at, mt) == 0 ? 0 : -(long)LX_ENOENT);
        break;
    }
    case LXS_pidfd_open_: {                 /* (pid, flags) */
        /* A pollable handle to a process's exit. app_pidfd_open has backed
         * fd type 7 since M1222; a runtime that manages child processes uses
         * this instead of SIGCHLD because it composes with an event loop. */
        int pfd = app_pidfd_open((int)a1);
        r->rax = (pfd < 0) ? (uint64_t)-(long)LX_ESRCH : (uint64_t)pfd;
        break;
    }
    case LXS_rmdir_: {                      /* (path) */
        const char *upath = (const char *)r->rdi;
        if (!upath || !vmm_user_ok(r->rdi, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate(upath, xp, sizeof xp);
        r->rax = (uint64_t)(vfs_remove(path) == 0 ? 0 : -(long)LX_ENOENT);
        break;
    }
    case LXS_fchdir_: {                     /* (fd) */
        /* coreutils' `mkdir -p` walks the path with openat+fchdir rather than
         * building the string itself, so without this the very first
         * `mkdir -p o/kernel` of a build failed with "Function not
         * implemented" -- and mkdir's own error message says nothing about
         * which call it was. The fd table already remembers each FILE fd's
         * path, which is exactly what chdir needs. (M1961) */
        const char *fp = app_fd_path((int)a1);
        if (!fp) { r->rax = (uint64_t)-(long)LX_EBADF; break; }
        if (vfs_chdir(fp) != 0) { r->rax = (uint64_t)-(long)LX_ENOTDIR; break; }
        app_chdir_track(fp);
        r->rax = 0;
        break;
    }
    case LXS_chdir_: {                      /* (path) */
        const char *up = (const char *)r->rdi;
        if (!up || !vmm_user_ok(r->rdi, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate(up, xp, sizeof xp);
        if (vfs_chdir(path) != 0) { r->rax = (uint64_t)-(long)LX_ENOENT; break; }
        app_chdir_track(path);              /* keep getcwd's answer in step */
        r->rax = 0;
        break;
    }
    case LXS_kill_:
    case LXS_tkill_:
    case LXS_tgkill_: {                     /* kill(pid,sig) / tkill(tid,sig) / tgkill(tgid,tid,sig) */
        /* The signal number is the LAST argument, and the three calls have
         * different arities -- reading the wrong register here turns an abort
         * into a silent no-op. */
        int sig = (r->rax == LXS_tgkill_) ? (int)r->rdx : (int)r->rsi;
        /* glibc's abort() lands here: it raises SIGABRT at itself and, when
         * nothing handles it, EXPECTS TO DIE. With no delivery at all the
         * raise returned, abort() fell through to its "kill myself harder"
         * path and the process took a General Protection Fault instead -- a
         * confusing crash in place of a clean, reportable abort. Terminating
         * with 128+signal is the shell's convention and makes the abort
         * visible for what it is. (M1960) */
        if (sig < 0 || sig >= APP_NSIG_LX) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (sig == 0) { r->rax = 0; break; }         /* signal 0 is an existence probe */
        /* WHICH THREAD (M2075). M2063's note here said signals were
         * per-PROCESS, "stated rather than pretended" -- and that statement
         * was the defect: tkill(tid) and tgkill(tgid, tid) NAME a thread, and
         * discarding the name is what broke JavaScriptCore's collector, which
         * suspends each thread in turn by signalling it and reading back the
         * registers the handler saved. Delivered to the wrong thread, the
         * target never stops and the collector scans from someone else's stack
         * pointer. tkill's first argument is the tid; tgkill's second is. */
        long tpid = (r->rax == LXS_tkill_) ? 0 : a1;
        int ttid  = (r->rax == LXS_tkill_) ? (int)a1 : (int)r->rsi;
        int rc = app_raise_signal_to_thread((int)tpid, ttid, sig);
        /* A tid we do not know is not automatically an error: glibc's raise()
         * uses tgkill with its own tid, and a runtime may signal a thread that
         * has just exited. Fall back to the process so a self-raise can never
         * be lost, which is the case abort() depends on. */
        if (rc < 0) rc = app_raise_signal_to((int)tpid, sig);
        if (rc == 1) {                               /* SIG_DFL and fatal, at ourselves */
            kprintf("[linuxabi] process raised signal %d at itself with no handler -- terminating\n", sig);
            /* abort() prints nothing of its own and leaves no fault address, so
             * without this the only evidence is the exit status. (M1970) */
            if (sig == 6) { lx_trace_dump("abort()"); lx_user_backtrace(r); }
            app_sys_exit(128 + sig);
            break;
        }
        r->rax = (rc < 0) ? (uint64_t)-(long)LX_ESRCH : 0;
        break;
    }
    case LXS_uname: {                       /* (struct utsname *) */
        /* Six fixed 65-byte fields: sysname, nodename, release, version,
         * machine, domainname. The LAYOUT is the ABI -- libuv reads `release`
         * and parses a version out of it, and a program that cannot parse it
         * may refuse to start.
         *
         * We report "Linux" and a plausible release on purpose: that is what
         * the compatibility layer is FOR, and a binary asking this question
         * wants to know which ABI it is talking to, not which project built
         * the kernel. `version` says OS-DEV, so anyone actually reading the
         * output learns the truth. (M1964) */
        if (!vmm_user_ok(r->rdi, 6 * 65)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char *u = (char *)r->rdi;
        for (int i = 0; i < 6 * 65; i++) u[i] = 0;
        static const char *f[6] = { "Linux", "osdev", "6.1.0",
                                    "OS-DEV (from-scratch kernel, Linux ABI layer)",
                                    "x86_64", "(none)" };
        for (int k = 0; k < 6; k++)
            for (int i = 0; f[k][i] && i < 64; i++) u[k * 65 + i] = f[k][i];
        r->rax = 0;
        break;
    }
    /* --- sockets (M1965) ---------------------------------------------------
     * AF_UNIX came first (M1965) because unixsock.c was a complete local-socket
     * implementation that needed nothing but an fd. AF_INET took a per-socket
     * receive ring and a non-blocking pump before anything could answer "is
     * there data?" without pulling frames off the NIC and stealing them from
     * other sockets -- that is M1967, and both families are here now. */
    case LXS_statx_: {                      /* (dirfd, path, flags, mask, struct statx *) */
        /* Linux's statx buffer is 256 bytes with its own field offsets, quite
         * unlike struct stat. Node stats constantly, and an ENOSYS here makes
         * libuv fall back -- but reporting the size correctly is cheap. */
        const char *up = (const char *)r->rsi;
        if (!up || !vmm_user_ok(r->rsi, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        if (!vmm_user_ok(r->r8, 256)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate_at((long)r->rdi, up, xp, sizeof xp);   /* dirfd (M2032) */
        struct statx sx;
        if (vfs_stat(path, &sx) != 0) {
            /* Name BOTH spellings. A stat that fails on a path the program
             * believes in is nearly always a TRANSLATION problem, and the
             * translated form is the only place that shows. (M1992) */
            if (g_lx_statfail < 400) {
                g_lx_statfail++;
                kprintf("[linuxabi] statx(\"%s\") -> \"%s\": no such path\n", up, path);
            }
            r->rax = (uint64_t)-(long)LX_ENOENT; break;
        }
        uint8_t *o = (uint8_t *)r->r8;
        for (int i = 0; i < 256; i++) o[i] = 0;
        /* FIELD OFFSETS, and they are not negotiable (fixed M1967).
         *
         * The first version of this had every field EIGHT BYTES TOO FAR --
         * nlink at 24 instead of 16, mode at 32 instead of 28, ino at 40
         * instead of 32, size at 48 instead of 40. Nothing failed loudly: the
         * call returned 0 and the buffer was full of plausible numbers. Node's
         * statSync read stx_size out of offset 40, where we had written
         * stx_ino, and reported a 26-byte file as 2675 bytes -- a size that
         * changed run to run because it was the real ext2 inode number. The
         * content read back correctly the whole time, which is what made it
         * look like anything other than a stat bug.
         *
         *   0  stx_mask(u32)   4  stx_blksize(u32)   8  stx_attributes(u64)
         *  16  stx_nlink(u32) 20  stx_uid(u32)      24  stx_gid(u32)
         *  28  stx_mode(u16)  30  spare(u16)        32  stx_ino(u64)
         *  40  stx_size(u64)  48  stx_blocks(u64)   56  attributes_mask(u64)
         *  64  atime          80  btime             96  ctime      112  mtime
         *      (each timestamp: s64 sec, u32 nsec, u32 pad)
         */
        int isdir = (sx.stx_mode & 0170000u) == 0040000u;
        *(uint32_t *)(o + 0)  = 0x7ff;                     /* stx_mask: what we filled in */
        *(uint32_t *)(o + 4)  = 4096;                      /* stx_blksize */
        *(uint32_t *)(o + 16) = sx.stx_nlink ? sx.stx_nlink : (isdir ? 2u : 1u);  /* stx_nlink -- the real count (M1998) */
        *(uint16_t *)(o + 28) = (uint16_t)((sx.stx_mode & 07777u) ? sx.stx_mode
                                           : (isdir ? (0040000u | 0755u) : (0100000u | 0644u)));  /* stx_mode, real when we have it (M1999) */
        *(uint64_t *)(o + 32) = sx.stx_ino;                /* stx_ino */
        *(uint64_t *)(o + 40) = sx.stx_size;               /* stx_size */
        *(uint64_t *)(o + 48) = (sx.stx_size + 511) / 512; /* stx_blocks */
        for (int t = 64; t <= 112; t += 16)                /* atime/btime/ctime/mtime */
            *(uint64_t *)(o + t) = sx.stx_mtime;
        r->rax = 0;
        break;
    }
    case LXS_socket_: {                     /* (domain, type, protocol) */
        /* Pass `type` THROUGH with its flag bits: app_socket records
         * SOCK_NONBLOCK/SOCK_CLOEXEC and masks them itself. Masking here threw
         * the caller's non-blocking request away silently (M1965). */
        int dom = (int)a1;
        int sfd = app_socket(dom, (int)r->rsi);
        if (g_lx_systrace) kprintf("[sock] socket(dom %d, type %lx) -> %d\n", dom, r->rsi, sfd);
        r->rax = (sfd < 0) ? (uint64_t)-(long)LX_EAFNOSUPPORT : (uint64_t)sfd;
        break;
    }
    case LXS_bind_:
    case LXS_connect_: {                    /* (fd, struct sockaddr *, addrlen) */
        /* struct sockaddr_un { uint16_t sun_family; char sun_path[108]; } --
         * the family is the first two bytes on both sides. */
        if (!vmm_user_ok(r->rsi, 2)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        uint16_t fam = *(const uint16_t *)r->rsi;
        if (fam == 2 /*AF_INET*/) {
            /* struct sockaddr_in { u16 family; u16 port (BIG-endian); u32 addr
             * (network order); u8 zero[8] }. The port is the field that bites:
             * it is big-endian ON THE WIRE AND IN THE STRUCT, so a caller's
             * htons() must not be undone twice. (M1967) */
            if (!vmm_user_ok(r->rsi, 8)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            const uint8_t *sa = (const uint8_t *)r->rsi;
            uint16_t port = (uint16_t)((sa[2] << 8) | sa[3]);
            uint8_t ip[4] = { sa[4], sa[5], sa[6], sa[7] };
            if (r->rax == LXS_bind_) {
                /* A REAL BIND (M2020). This used to be accepted and ignored on
                 * the reasoning that nothing depended on a specific local port.
                 * Something does: Claude Code's OAuth login binds port 0, asks
                 * getsockname which port it got, and puts that port in the URL
                 * it shows you. Ignoring the bind and then failing the listen
                 * produced "Failed to start OAuth callback server. Is port 0 in
                 * use?" -- a question the kernel had made unanswerable. */
                int bp = app_inet_bind((int)a1, port);
                if (bp == -2) { r->rax = (uint64_t)-(long)LX_EADDRINUSE; break; }
                r->rax = (bp < 0) ? (uint64_t)-(long)LX_EINVAL : 0;
                break;
            }
            /* PORT 0 IS NOT CONNECTABLE (M2055). A connect() to port 0 was
             * accepted and reported success:
             *
             *   [net] connect -> 160.79.104.10:0 = 0
             *
             * Nothing can answer on port 0 -- Linux returns ECONNREFUSED (or
             * EADDRNOTAVAIL) and every client handles that by moving on. Saying
             * "connected" instead hands back a socket that will never deliver a
             * byte, and a client that trusts us then waits for a reply for
             * ever, with no error anywhere to explain it. Refusing is both
             * correct and the kinder failure: the same shape as pipe2's flags,
             * wait4's options and openat's dirfd -- a request accepted and not
             * actually honourable. */
            if (port == 0) { r->rax = (uint64_t)-(long)LX_ECONNREFUSED; break; }
            int crc = app_connect((int)a1, ip, port);
            /* ALWAYS, not only under a trace flag (M2004). An outbound
             * connection is a rare, structural event, and "which address did it
             * actually try, and did it get there" is the first question when a
             * program reports it cannot reach a service. Claude Code says
             * "Connection to platform.claude.com timed out" without telling you
             * whether that name resolved at all. */
            kprintf("[net] t=%lums connect -> %d.%d.%d.%d:%d = %d\n",
                    (unsigned long)timer_ms(), ip[0], ip[1], ip[2], ip[3], port, crc);
            if (g_lx_systrace || crc != 0)
                kprintf("[sock] connect(fd %ld, %u.%u.%u.%u:%u) -> %d\n",
                        a1, ip[0], ip[1], ip[2], ip[3], port, crc);
            r->rax = (crc == 0) ? 0 : (uint64_t)-(long)LX_ECONNREFUSED;
            break;
        }
        if (fam != 1 /*AF_UNIX*/) { r->rax = (uint64_t)-(long)LX_EAFNOSUPPORT; break; }
        if (!vmm_user_ok(r->rsi, 3)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        const char *sun = (const char *)(r->rsi + 2);
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate(sun, xp, sizeof xp);
        int is_bind = (r->rax == LXS_bind_);
        int rc2 = is_bind ? app_unix_bind((int)a1, path) : app_unix_connect((int)a1, path);
        if (g_lx_systrace || rc2 != 0)
            kprintf("[sock] %s(fd %ld, %s) -> %d\n", is_bind ? "bind" : "connect", a1, path, rc2);
        r->rax = (rc2 == 0) ? 0 : (uint64_t)-(long)(is_bind ? LX_EADDRINUSE : LX_ECONNREFUSED);
        break;
    }
    case LXS_listen_: {
        /* AF_INET listens here too now (M2020) -- it used to be AF_UNIX only,
         * so an IP server socket got EADDRINUSE for a port nobody held. */
        if (app_fd_type((int)a1) == 10) {
            int lrc = app_inet_listen((int)a1, (int)r->rsi);
            kprintf("[net] listen(fd %ld) on AF_INET -> %d\n", a1, lrc);
            r->rax = (uint64_t)(lrc == 0 ? 0 : -(long)LX_EADDRINUSE);
            break;
        }
        int lrc = app_unix_listen((int)a1);
        if (g_lx_systrace) kprintf("[sock] listen(fd %ld) -> %d\n", a1, lrc);
        if (lrc != 0) kprintf("[linuxabi] listen(fd %ld) FAILED\n", a1);
        r->rax = (uint64_t)(lrc == 0 ? 0 : -(long)LX_EADDRINUSE);
        break;
    }
    case LXS_accept_:
    case LXS_accept4_: {                    /* (fd, sockaddr *, addrlen *[, flags]) */
        int is4 = (r->rax == LXS_accept4_);          /* rax still holds the syscall number here */
        if (app_fd_type((int)a1) == 15) {            /* AF_INET listener (M2020) */
            int af = app_inet_accept((int)a1);
            if (af < 0) { r->rax = (uint64_t)lx_fd_err(af); break; }
            if (is4) app_fd_set_nonblock(af, (r->r10 & 0x800) ? 1 : 0);
            if (r->rsi && vmm_user_ok(r->rsi, 16)) {   /* fill in a plausible peer address */
                uint8_t *o = (uint8_t *)r->rsi;
                for (int i = 0; i < 16; i++) o[i] = 0;
                *(uint16_t *)o = 2;                    /* AF_INET */
                o[4] = 127; o[7] = 1;                  /* the callback comes from loopback */
            }
            if (r->rdx && vmm_user_ok(r->rdx, 4)) *(uint32_t *)r->rdx = 16;
            r->rax = (uint64_t)af;
            break;
        }
        int nf = app_unix_accept((int)a1);
        if (g_lx_systrace) kprintf("[sock] accept(fd %ld) -> %d\n", a1, nf);
        /* Non-blocking by construction: a server polls POLLIN first. Reporting
         * EAGAIN rather than blocking is what a non-blocking socket does, and
         * every event loop handles it. "Out of descriptors" is NOT EAGAIN --
         * a loop that retries on EAGAIN would spin on it forever. */
        if (nf < 0) { r->rax = (uint64_t)lx_fd_err(nf); break; }
        /* accept4's SOCK_NONBLOCK applies to the ACCEPTED fd, not the listener. */
        if (is4) app_fd_set_nonblock(nf, (r->r10 & 0x800) ? 1 : 0);
        if (r->rdx && vmm_user_ok(r->rdx, 4)) *(uint32_t *)r->rdx = 2;   /* addrlen: just the family */
        r->rax = (uint64_t)nf;
        break;
    }
    case LXS_socketpair_: {                 /* (domain, type, protocol, int sv[2]) */
        if ((int)a1 != 1 /*AF_UNIX*/) { r->rax = (uint64_t)-(long)LX_EAFNOSUPPORT; break; }
        if (!vmm_user_ok(r->r10, 8)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        int sv[2];
        if (app_unix_socketpair(sv) != 0) { r->rax = (uint64_t)-(long)LX_EMFILE; break; }
        /* THE TYPE'S FLAG BITS ARE PART OF THE REQUEST (M2012). socket() has
         * passed SOCK_NONBLOCK/SOCK_CLOEXEC through since M1965 and accept4
         * honours its own flags; socketpair masked them off, so a caller that
         * asked for a non-blocking pair got a blocking one and was never told.
         *
         * Firefox's IPC channel is built exactly this way --
         *   socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0)
         * -- and then relies on the property it just asked for. It aborted at
         * ipc/chromium/src/chrome/common/ipc_channel_posix.cc:128, which is
         * the channel refusing to run on descriptors that are not what it
         * created. Same defect class as pipe2's discarded flags (M2009): the
         * dangerous failure is not refusing the request, it is granting it
         * silently in name only. */
        int sp_ty = (int)r->rsi;
        if (sp_ty & 0x800)   { app_fd_set_nonblock(sv[0], 1); app_fd_set_nonblock(sv[1], 1); }   /* SOCK_NONBLOCK */
        if (sp_ty & 0x80000) { app_fd_set_cloexec(sv[0], 1);  app_fd_set_cloexec(sv[1], 1);  }   /* SOCK_CLOEXEC */
        ((int *)r->r10)[0] = sv[0]; ((int *)r->r10)[1] = sv[1];
        r->rax = 0;
        break;
    }
    case LXS_getsockname_: {                /* (fd, sockaddr *, addrlen *) */
        /* Report the REAL family and address. Hardcoding AF_UNIX was fine
         * while AF_UNIX was the only family in the fd table (M1965) and is a
         * correctness bug the moment AF_INET joins it: glibc's getaddrinfo
         * learns which local address would be used for each candidate
         * destination by connect()ing a UDP socket and calling getsockname on
         * it, and an AF_UNIX answer made it abort outright --
         *   Fatal glibc error: rfc3484_sort: assertion failed:
         *     a1->source_addr.sin6_family == PF_INET
         * after the DNS lookup had already succeeded. (M1967) */
        int ty = app_fd_type((int)a1);
        if (ty == 15 || ty == 16) {                  /* a listening / accepted AF_INET socket (M2020) */
            /* THE PORT IS THE WHOLE ANSWER. A program that binds port 0 asks
             * this to find out what it actually got, and then tells the world
             * -- Claude Code puts it straight into the OAuth callback URL. */
            if (!r->rsi || !vmm_user_ok(r->rsi, 16)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            uint8_t *o = (uint8_t *)r->rsi;
            for (int i = 0; i < 16; i++) o[i] = 0;
            long lp = app_fd_port((int)a1);
            *(uint16_t *)o = 2;                                   /* AF_INET */
            o[2] = (uint8_t)((lp >> 8) & 0xFF); o[3] = (uint8_t)(lp & 0xFF);
            o[4] = 127; o[7] = 1;                                 /* 127.0.0.1 */
            if (r->rdx && vmm_user_ok(r->rdx, 4)) *(uint32_t *)r->rdx = 16;
            r->rax = 0; break;
        }
        if (ty == 9 || ty == 10) {
            if (!r->rsi || !vmm_user_ok(r->rsi, 16)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            uint8_t lip[4] = {0,0,0,0}; uint16_t lport = 0;
            app_sock_localaddr((int)a1, lip, &lport);
            uint8_t *o = (uint8_t *)r->rsi;
            for (int i = 0; i < 16; i++) o[i] = 0;
            *(uint16_t *)o = 2;                                  /* AF_INET */
            o[2] = (uint8_t)(lport >> 8); o[3] = (uint8_t)(lport & 0xFF);   /* big-endian in the struct */
            for (int i = 0; i < 4; i++) o[4 + i] = lip[i];
            if (r->rdx && vmm_user_ok(r->rdx, 4)) *(uint32_t *)r->rdx = 16;
            r->rax = 0;
            break;
        }
        if (r->rsi && vmm_user_ok(r->rsi, 2)) *(uint16_t *)r->rsi = 1 /*AF_UNIX*/;
        if (r->rdx && vmm_user_ok(r->rdx, 4)) *(uint32_t *)r->rdx = 2;
        r->rax = 0;
        break;
    }
    case LXS_setsockopt_:
        r->rax = 0;                          /* accepted; no option changes local-socket behaviour */
        break;
    case LXS_getsockopt_:
        /* SO_ERROR (4) in particular: an event loop reads it after connect to
         * decide whether the connection succeeded, and a nonzero answer would
         * make it give up on a socket that is fine. */
        /* ARGUMENT ORDER: getsockopt(fd, level, optname, optval, optlen) --
         * optval is r10 and optlen is r8. Having them the other way round
         * wrote the LENGTH (4) into the value buffer, so libuv read
         * SO_ERROR == 4 and reported "connect EINTR" on a connection that had
         * succeeded: socket, bind, listen, connect and accept had all
         * returned cleanly. Nothing in the error named the real call. */
        if (r->r10 && vmm_user_ok(r->r10, 4)) *(uint32_t *)r->r10 = 0;   /* optval: no error */
        if (r->r8  && vmm_user_ok(r->r8, 4))  *(uint32_t *)r->r8  = 4;   /* optlen: bytes written */
        r->rax = 0;
        break;
    case LXS_sendto_: {                     /* (fd, buf, len, flags, dest_addr, addrlen) */
        long slen = (long)r->rdx;
        if (slen < 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (slen && !vmm_user_ok(r->rsi, (uint64_t)slen)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        /* A NULL dest_addr means "already connected" -- for a stream socket
         * that is just write(). */
        if (!r->r8) {
            long w = app_fd_write((int)a1, (const void *)r->rsi, (unsigned long)slen);
            r->rax = (w < 0) ? (uint64_t)lx_fd_err(w) : (uint64_t)w;
            break;
        }
        if (!vmm_user_ok(r->r8, 8)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        const uint8_t *sa = (const uint8_t *)r->r8;
        if (*(const uint16_t *)sa != 2 /*AF_INET*/) { r->rax = (uint64_t)-(long)LX_EAFNOSUPPORT; break; }
        uint16_t dport = (uint16_t)((sa[2] << 8) | sa[3]);       /* big-endian in the struct */
        uint8_t dip[4] = { sa[4], sa[5], sa[6], sa[7] };
        long sn = app_sendto((int)a1, dip, dport, (const void *)r->rsi, (int)slen);
        if (g_lx_systrace)
            kprintf("[sock] sendto(fd %ld, %u.%u.%u.%u:%u, %ld) -> %ld\n",
                    a1, dip[0], dip[1], dip[2], dip[3], dport, slen, sn);
        r->rax = (sn < 0) ? (uint64_t)-(long)LX_ENETUNREACH : (uint64_t)sn;
        break;
    }
    case LXS_recvfrom_: {                   /* (fd, buf, len, flags, src_addr, addrlen *) */
        long rlen = (long)r->rdx;
        if (rlen < 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (rlen && !vmm_user_ok(r->rsi, (uint64_t)rlen)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        if (app_fd_type((int)a1) != 9) {                          /* stream socket: plain read */
            long got = app_fd_read((int)a1, (void *)r->rsi, (unsigned long)rlen);
            r->rax = (got < 0) ? (uint64_t)lx_fd_err(got) : (uint64_t)got;
            break;
        }
        uint8_t sip[4] = {0,0,0,0}; uint16_t sp = 0;
        long gn = app_recvfrom((int)a1, (void *)r->rsi, (int)rlen, sip, &sp);
        if (gn == APP_FD_EAGAIN) { r->rax = (uint64_t)-(long)LX_EAGAIN; break; }
        if (gn < 0) { r->rax = (uint64_t)-(long)LX_EAGAIN; break; }
        /* Fill in src_addr only if the caller asked for it AND told us how much
         * room there is -- writing 16 bytes into a smaller buffer is exactly
         * the kind of silent overrun this layer exists to prevent. */
        if (r->r8 && r->r9 && vmm_user_ok(r->r9, 4)) {
            uint32_t cap = *(const uint32_t *)r->r9;
            if (cap >= 16 && vmm_user_ok(r->r8, 16)) {
                uint8_t *o = (uint8_t *)r->r8;
                for (int i = 0; i < 16; i++) o[i] = 0;
                *(uint16_t *)o = 2;                               /* AF_INET */
                o[2] = (uint8_t)(sp >> 8); o[3] = (uint8_t)(sp & 0xFF);
                for (int i = 0; i < 4; i++) o[4 + i] = sip[i];
                *(uint32_t *)r->r9 = 16;
            }
        }
        r->rax = (uint64_t)gn;
        break;
    }
    /* --- the message-vector calls (M1967) ------------------------------------
     *
     * glibc's RESOLVER needs these. It sends the A and AAAA queries for a name
     * in ONE sendmmsg, and with that call returning ENOSYS it gave up on the
     * lookup entirely: every hostname failed with EAI_AGAIN -- "try again
     * later" -- with a correct /etc/resolv.conf in place and a working
     * resolver underneath. Nothing in the error mentioned sendmmsg.
     *
     *   struct msghdr  { void *name; u32 namelen; iovec *iov; u64 iovlen;
     *                    void *control; u64 controllen; int flags; }   56 bytes
     *   struct mmsghdr { struct msghdr hdr; u32 len; }                 64 bytes
     */
    case LXS_fadvise64_:
        /* (fd, offset, len, advice). A HINT, exactly like readahead_ below:
         * "I will read this sequentially / at random / not again." A kernel
         * with no page-cache policy to steer has nothing to do with it, and
         * the caller's correctness never depends on the answer. Claude Code
         * issues one every time it checks for an IDE, so ENOSYS made a
         * successful no-op look like a repeated failure. (M2026) */
        r->rax = 0;
        break;
    case LXS_sendfile_: {                   /* (out_fd, in_fd, off_t *off, count) */
        /* Copy between two descriptors without a round trip through user
         * memory. We have no page-cache splice, so do the obvious thing: read
         * a chunk from in_fd and write it to out_fd, honouring the optional
         * *off (which, when given, is updated and the file cursor is NOT
         * moved -- pread semantics, the same distinction app_pread exists to
         * make). Returning ENOSYS instead made every caller believe the copy
         * had FAILED, rather than that it had to do the loop itself. (M2026) */
        int ofd = (int)a1, ifd = (int)r->rsi;
        uint64_t upoff = r->rdx;
        unsigned long count = (unsigned long)r->r10;
        long off = -1;
        if (upoff) {
            if (!vmm_user_ok(upoff, 8)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            off = *(long *)upoff;
        }
        static char sfbuf[4096];            /* the syscall path is serialized; see lx_emit */
        long total = 0;
        while ((unsigned long)total < count) {
            unsigned long want = count - (unsigned long)total;
            if (want > sizeof sfbuf) want = sizeof sfbuf;
            long got = (off >= 0) ? app_pread(ifd, sfbuf, want, off + total)
                                  : app_fd_read(ifd, sfbuf, want);
            if (got <= 0) { if (total == 0 && got < 0) total = got; break; }
            long put = app_fd_write(ofd, sfbuf, (unsigned long)got);
            if (put <= 0) { if (total == 0) total = put < 0 ? put : 0; break; }
            total += put;
            if (put < got) break;           /* short write: stop, report what landed */
        }
        if (total >= 0 && off >= 0) *(long *)upoff = off + total;
        r->rax = (uint64_t)total;
        break;
    }
    case LXS_readahead_:
        /* (fd, offset, count). A HINT: "I will read this soon." Linux may
         * start the I/O early or ignore it entirely, and the caller's
         * correctness never depends on it -- Firefox issues a burst of these
         * while loading libxul. Returning 0 is the honest answer for a kernel
         * with no readahead machinery; ENOSYS made it look like a failure. */
        r->rax = 0;
        break;
    case LXS_ftruncate_: {                  /* (fd, length) */
        /* A memfd is created EMPTY; it has to be sized before it can be
         * mapped, so wl_shm's very first move is memfd_create + ftruncate.
         * app_ftruncate has existed since M1212 with no Linux number. (M1977) */
        long tr = app_ftruncate((int)a1, (long)r->rsi);
        if (g_lx_systrace) kprintf("[sock] ftruncate(fd %ld, %ld) -> %ld\n", a1, (long)r->rsi, tr);
        r->rax = (uint64_t)(tr == 0 ? 0 : -(long)LX_EINVAL);
        break;
    }
    case LXS_memfd_create_: {               /* (name, flags) -> an anonymous in-RAM file */
        /* The foundation of wl_shm: a client puts its pixels in a memfd, passes
         * the descriptor to the compositor over the socket, and both mmap it.
         * app_memfd_create has existed since M1212; it simply had no Linux
         * number. (M1977) */
        const char *nm = (const char *)r->rdi;
        if (nm && !vmm_user_ok(r->rdi, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        int mf = app_memfd_create(nm ? nm : "memfd", 0);
        if (mf < 0) { r->rax = (uint64_t)-(long)LX_EMFILE; break; }
        if (r->rsi & 1) app_fd_set_cloexec(mf, 1);      /* MFD_CLOEXEC */
        if (g_lx_systrace) kprintf("[sock] memfd_create(%s) -> %d\n", nm ? nm : "?", mf);
        r->rax = (uint64_t)mf;
        break;
    }
    case LXS_sendmsg_:
    case LXS_sendmmsg_: {                   /* (fd, msg[vec], vlen, flags) */
        int is_mm = (r->rax == LXS_sendmmsg_);
        unsigned long vlen = is_mm ? (unsigned long)r->rdx : 1;
        if (vlen > 64) vlen = 64;
        unsigned long stride = is_mm ? 64 : 56;
        if (!vlen || !vmm_user_ok(r->rsi, vlen * stride)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        long done = 0, first = -1;
        for (unsigned long m = 0; m < vlen; m++) {
            const uint8_t *h = (const uint8_t *)(r->rsi + m * stride);
            uint64_t nameptr = *(const uint64_t *)(h + 0);
            uint32_t namelen = *(const uint32_t *)(h + 8);
            uint64_t iovptr  = *(const uint64_t *)(h + 16);
            uint64_t iovlen  = *(const uint64_t *)(h + 24);
            if (iovlen > 16) break;
            if (iovlen && !vmm_user_ok(iovptr, iovlen * sizeof(struct lx_iovec))) break;
            /* Gather the iovecs. A datagram is ONE packet, so they have to be
             * concatenated before it goes out -- sending them separately would
             * turn one query into several. */
            /* PER CALL, NOT static -- see the note on recvmsg's sbuf below.
             * Two tasks gathering into one shared buffer splice one client's
             * outgoing message into another's. (M2000) */
            uint8_t *gbuf = kmalloc(2048);
            if (!gbuf) { r->rax = (uint64_t)-(long)LX_ENOMEM; break; }
            unsigned long tot = 0;
            const struct lx_iovec *v = (const struct lx_iovec *)iovptr;
            int bad = 0;
            for (uint64_t i = 0; i < iovlen; i++) {
                unsigned long n = v[i].iov_len;
                if (!n) continue;
                if (!v[i].iov_base || !vmm_user_ok((uint64_t)v[i].iov_base, n)) { bad = 1; break; }
                if (tot + n > 2048) n = 2048 - tot;
                for (unsigned long k = 0; k < n; k++) gbuf[tot + k] = ((const uint8_t *)v[i].iov_base)[k];
                tot += n;
                if (tot >= 2048) break;
            }
            if (bad) { kfree(gbuf); break; }
            /* SCM_RIGHTS: hand any descriptors in msg_control to the peer
             * BEFORE the bytes, so they are already queued when it reads.
             *
             *   struct cmsghdr { u64 cmsg_len; int cmsg_level; int cmsg_type; }
             *   then the payload -- for SCM_RIGHTS, an array of ints.
             *
             * This is how a Wayland client gives the compositor its pixels: it
             * puts them in a memfd and passes the descriptor down the same
             * socket as the protocol messages. (M1977) */
            uint64_t ctl = *(const uint64_t *)(h + 32);
            uint64_t ctllen = *(const uint64_t *)(h + 40);
            if (ctl && ctllen >= 16 && vmm_user_ok(ctl, ctllen)) {
                const uint8_t *cm = (const uint8_t *)ctl;
                uint64_t clen = *(const uint64_t *)(cm + 0);
                int level = *(const int *)(cm + 8), ctype = *(const int *)(cm + 12);
                if (level == 1 /*SOL_SOCKET*/ && ctype == 1 /*SCM_RIGHTS*/ &&
                    clen >= 16 && clen <= ctllen) {
                    int nfd = (int)((clen - 16) / sizeof(int));
                    const int *fds = (const int *)(cm + 16);
                    for (int q = 0; q < nfd; q++) {
                        if (app_unix_send_fd((int)a1, fds[q]) != 0)
                            kprintf("[sock] SCM_RIGHTS: could not pass fd %d\n", fds[q]);
                        else if (g_lx_systrace)
                            kprintf("[sock] SCM_RIGHTS: passed fd %d\n", fds[q]);
                    }
                }
            }
            long sn;
            if (nameptr && namelen >= 8 && vmm_user_ok(nameptr, 8)) {
                const uint8_t *sa = (const uint8_t *)nameptr;
                uint16_t dport = (uint16_t)((sa[2] << 8) | sa[3]);
                uint8_t dip[4] = { sa[4], sa[5], sa[6], sa[7] };
                sn = app_sendto((int)a1, dip, dport, gbuf, (int)tot);
            } else {
                sn = app_fd_write((int)a1, gbuf, tot);   /* connected socket */
            }
            kfree(gbuf);
            if (sn < 0) break;
            if (first < 0) first = sn;
            if (is_mm) *(uint32_t *)(h + 56) = (uint32_t)sn;   /* msg_len, per message */
            done++;
        }
        if (done == 0) { r->rax = (uint64_t)-(long)LX_ENETUNREACH; break; }
        r->rax = is_mm ? (uint64_t)done : (uint64_t)first;
        break;
    }
    case LXS_recvmsg_:
    case LXS_recvmmsg_: {                   /* (fd, msg[vec], vlen, flags[, timeout]) */
        int is_mm = (r->rax == LXS_recvmmsg_);
        long rflags = is_mm ? (long)r->r10 : (long)r->rdx;   /* recvmsg(fd,msg,flags); recvmmsg(fd,vec,vlen,flags,ts) */
        unsigned long vlen = is_mm ? (unsigned long)r->rdx : 1;
        if (vlen > 64) vlen = 64;
        unsigned long stride = is_mm ? 64 : 56;
        if (!vlen || !vmm_user_ok(r->rsi, vlen * stride)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        long done = 0, first = -1;
        for (unsigned long m = 0; m < vlen; m++) {
            uint8_t *h = (uint8_t *)(r->rsi + m * stride);
            uint64_t nameptr = *(const uint64_t *)(h + 0);
            uint64_t iovptr  = *(const uint64_t *)(h + 16);
            uint64_t iovlen  = *(const uint64_t *)(h + 24);
            if (!iovlen || iovlen > 16) break;
            if (!vmm_user_ok(iovptr, iovlen * sizeof(struct lx_iovec))) break;
            const struct lx_iovec *v = (const struct lx_iovec *)iovptr;
            /* Receive into a staging buffer and SCATTER: a datagram arrives
             * whole and then fills the iovecs in order.
             *
             * PER CALL, NOT static (M2000). This buffer was one 2 KiB array
             * shared by every task on every core, with no lock, in the middle
             * of a syscall two of them can be executing at once. Two concurrent
             * recvmsg calls overwrite each other's bytes, and for a STREAM
             * socket those bytes are already consumed from the ring -- so a
             * client gets someone else's data spliced into its own and its
             * message framing is permanently offset. libwayland reports the
             * wreckage as
             *
             *   Wayland protocol error: message too short, object (2),
             *   message global(usu)
             *
             * -- a `global` event 24 bytes long, which is shorter than any
             * global this compositor can produce. Intermittent, because it
             * needs two readers to overlap. Firefox has several threads and
             * several processes on the socket; the demo client has one, which
             * is why the test suite never saw it.
             *
             * The send side had the identical bug with gbuf. */
            uint8_t *sbuf = kmalloc(2048);
            if (!sbuf) { r->rax = (uint64_t)-(long)LX_ENOMEM; goto msgdone; }
            #define sbuf_free() kfree(sbuf)
            /* NEVER read more than the caller can take. Reading into a staging
             * buffer and scattering means anything past the end of the iovecs
             * is DROPPED -- and for a stream socket those bytes are gone from
             * the ring, so the caller is silently short. A Wayland client read
             * 94 bytes of a 148-byte burst of registry events and waited
             * forever for the other 54, which had been thrown away here.
             * (M1978) */
            unsigned long want = 0;
            for (uint64_t i = 0; i < iovlen; i++) want += v[i].iov_len;
            if (want > 2048) want = 2048;
            if (!want) { sbuf_free(); break; }
            uint8_t sip[4] = {0,0,0,0}; uint16_t sp = 0;
            long gn;
            /* MSG_DONTWAIT (0x40) makes THIS CALL non-blocking regardless of
             * the descriptor's own O_NONBLOCK. Ignoring it is not a shortcut,
             * it is a hang: libwayland reads with MSG_DONTWAIT on a BLOCKING
             * socket and loops until it gets EAGAIN, so a read that waits
             * instead never comes back -- wl_display_read_events stopped dead
             * there with every byte already delivered. (M1978) */
            int nb_save = app_fd_nonblock((int)a1);
            if (rflags & 0x40) app_fd_set_nonblock((int)a1, 1);
            if (app_fd_type((int)a1) == 9) gn = app_recvfrom((int)a1, sbuf, (int)want, sip, &sp);
            else                            gn = app_fd_read((int)a1, sbuf, want);
            if (rflags & 0x40) app_fd_set_nonblock((int)a1, nb_save);
            if (g_wl_verbose) kprintf("[sock] recvmsg(fd %ld) want=%lu -> %ld\n", a1, want, gn);
            if (gn == APP_FD_EAGAIN) { sbuf_free(); if (done == 0) { r->rax = (uint64_t)-(long)LX_EAGAIN; goto msgdone; } break; }
            if (gn < 0) { sbuf_free(); break; }
            unsigned long off = 0;
            for (uint64_t i = 0; i < iovlen && off < (unsigned long)gn; i++) {
                unsigned long n = v[i].iov_len;
                if (!n) continue;
                if (!v[i].iov_base || !vmm_user_ok((uint64_t)v[i].iov_base, n)) break;
                if (n > (unsigned long)gn - off) n = (unsigned long)gn - off;
                for (unsigned long k = 0; k < n; k++) ((uint8_t *)v[i].iov_base)[k] = sbuf[off + k];
                off += n;
            }
            if (nameptr && vmm_user_ok(nameptr, 16)) {
                uint8_t *o = (uint8_t *)nameptr;
                for (int i = 0; i < 16; i++) o[i] = 0;
                *(uint16_t *)o = 2;                       /* AF_INET */
                o[2] = (uint8_t)(sp >> 8); o[3] = (uint8_t)(sp & 0xFF);
                for (int i = 0; i < 4; i++) o[4 + i] = sip[i];
                *(uint32_t *)(h + 8) = 16;                /* msg_namelen */
            }
            /* SCM_RIGHTS the other way: install any descriptors the peer passed
             * and describe them in msg_control. A receiver that asked for no
             * control space gets none, which is what Linux does. (M1977) */
            {
                uint64_t ctl = *(const uint64_t *)(h + 32);
                uint64_t ctllen = *(const uint64_t *)(h + 40);
                uint64_t wrote = 0;
                if (ctl && ctllen >= 16 + sizeof(int) && vmm_user_ok(ctl, ctllen)) {
                    int cap = (int)((ctllen - 16) / sizeof(int));
                    uint8_t *cm = (uint8_t *)ctl;
                    int *outfds = (int *)(cm + 16);
                    int nfd = 0;
                    while (nfd < cap) {
                        int nf2 = app_unix_recv_fd((int)a1);
                        if (nf2 < 0) break;
                        outfds[nfd++] = nf2;
                        if (g_lx_systrace) kprintf("[sock] SCM_RIGHTS: received fd %d\n", nf2);
                    }
                    if (nfd > 0) {
                        wrote = 16 + (uint64_t)nfd * sizeof(int);
                        *(uint64_t *)(cm + 0) = wrote;
                        *(int *)(cm + 8)  = 1;            /* SOL_SOCKET */
                        *(int *)(cm + 12) = 1;            /* SCM_RIGHTS  */
                    }
                }
                *(uint64_t *)(h + 40) = wrote;            /* msg_controllen: what we actually filled */
            }
            *(uint32_t *)(h + 48) = 0;                    /* msg_flags: nothing truncated */
            sbuf_free();
            if (first < 0) first = (long)off;
            if (is_mm) *(uint32_t *)(h + 56) = (uint32_t)off;
            done++;
        }
        #undef sbuf_free
        if (done == 0) { r->rax = (uint64_t)-(long)LX_EAGAIN; break; }
        r->rax = is_mm ? (uint64_t)done : (uint64_t)first;
        msgdone: break;
    }
    case LXS_nanosleep_:                    /* (req, rem) -- clock_nanosleep's arguments shifted two LEFT */
        /* Plain nanosleep(2) was ENOSYS. glibc's sleep()/usleep() prefer
         * clock_nanosleep, but plenty of code calls the syscall directly and
         * an ENOSYS sleep does not sleep at all -- it returns instantly and
         * whatever loop was pacing itself with it becomes a spin. Normalise
         * into the handler below: CLOCK_REALTIME, relative. (M2010) */
        r->rdx = r->rdi; r->r10 = r->rsi; a1 = 0; r->rsi = 0;
        /* fall through */
    case LXS_clock_nanosleep_: {            /* (clockid, flags, req, rem) */
        /* Node polls with this. ENOSYS made it a busy-wait. */
        if (!r->rdx || !vmm_user_ok(r->rdx, 16)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        const uint64_t *ts = (const uint64_t *)r->rdx;
        uint64_t ms = ts[0] * 1000ull + (ts[1] + 999999ull) / 1000000ull;
        /* TIMER_ABSTIME (M2010). This used to collapse to a 1 ms sleep on the
         * claim that there was no absolute clock to compare against -- but
         * clock_gettime above serves both CLOCK_REALTIME and CLOCK_MONOTONIC,
         * so there is, and it is the very clock the caller derived this
         * deadline from. Sleeping 1 ms instead turns "wake me at T" into a
         * thousand-hertz busy loop: Firefox burned 1.2 million syscalls in
         * fifteen seconds doing exactly that. */
        if (r->rsi & 1) {                   /* TIMER_ABSTIME: `ms` is a DEADLINE */
            int64_t now = (a1 == 0 /*CLOCK_REALTIME*/)
                ? (int64_t)lx_realtime_sec() * 1000 + (int64_t)(timer_ms() % 1000)
                : (int64_t)timer_ms();
            int64_t rel = (int64_t)ms - now;
            ms = (rel > 0) ? (uint64_t)rel : 0;
        }
        if (ms > 60000) ms = 60000;
        __asm__ volatile("sti");
        task_sleep_ms((int)ms);
        __asm__ volatile("cli");
        if (r->r10 && vmm_user_ok(r->r10, 16)) { ((uint64_t *)r->r10)[0] = 0; ((uint64_t *)r->r10)[1] = 0; }
        r->rax = 0;
        break;
    }
    case LXS_shutdown_: {                   /* (fd, how) */
        /* Was: accepted and ignored, on the reasoning that a local socket has
         * no half-close. It does, and it is load-bearing -- Node's
         * socket.end() is a shutdown(SHUT_WR), and the peer's "the other side
         * is finished" event never fired, so a finished connection kept the
         * event loop alive forever. See unix_shutdown. (M1965) */
        int sr = (app_fd_type((int)a1) == 12) ? app_unix_shutdown((int)a1, (int)r->rsi) : 0;
        if (g_lx_systrace) kprintf("[sock] shutdown(fd %ld, how %ld) -> %d\n", a1, (long)r->rsi, sr);
        r->rax = (sr == 0) ? 0 : (uint64_t)-(long)LX_ENOTCONN;
        break;
    }
    case LXS_capget_:
        /* (hdrp, datap). Single-user, everything runs as root, so there are no
         * capability sets to report -- but ENOSYS made Node ask hundreds of
         * times. Zeroed data means "no capabilities", which is a coherent
         * answer rather than an error. */
        if (r->rsi && vmm_user_ok(r->rsi, 12)) {
            uint8_t *d = (uint8_t *)r->rsi;
            for (int i = 0; i < 12; i++) d[i] = 0;
        }
        r->rax = 0;
        break;
    case LXS_sched_getaffinity_: {          /* (pid, cpusetsize, mask) */
        long sz = (long)r->rsi;
        if (sz < 8) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (!vmm_user_ok(r->rdx, (uint64_t)sz)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        uint8_t *m = (uint8_t *)r->rdx;
        for (long i = 0; i < sz; i++) m[i] = 0;
        /* One bit per online core. Node sizes its libuv thread pool and
         * reports os.cpus() from this, so a wrong answer here is a wrong
         * answer in the program. */
        for (int c = 0; c < smp_cpu_count && c < sz * 8; c++) m[c / 8] |= (uint8_t)(1u << (c % 8));
        r->rax = (uint64_t)sz;              /* Linux returns the size written */
        break;
    }
    case LXS_getpriority_:                  /* (which, who) */
        /* THE ONLY UNIMPLEMENTED SYSCALL LEFT IN A FIREFOX RUN (M2003), and it
         * is on the startup path of every thread it creates -- the trace of the
         * thread that faulted is set_robust_list, rt_sigprocmask, gettid,
         * getpriority, prctl(PR_SET_NAME), and then it dies.
         *
         * NOTE THE ENCODING. The raw syscall returns 20 - nice, not the nice
         * value, precisely so that a legitimate nice of -1 is not confused with
         * an error; glibc's wrapper subtracts it back. Returning 0 here would
         * therefore claim a nice of 20 -- the lowest priority there is --
         * rather than "normal". Everything runs at one priority here, so 20 is
         * the honest answer and 0 is a silently wrong one. */
        r->rax = 20;                        /* 20 - nice, with nice == 0 */
        break;
    case LXS_setpriority_:                  /* (which, who, prio) */
        /* Accepted and ignored: there is one scheduling priority here, and a
         * failure makes a runtime think the system is broken rather than
         * uniform. */
        r->rax = 0;
        break;
    case LXS_sched_getparam_:                /* (pid, struct sched_param *) */
        /* struct sched_param is a single int, the priority. SCHED_OTHER
         * threads have priority 0, which is what we run everything at.
         * Returning ENOSYS instead made V8's own mutex code log
         *   [mutex.cc : 956] RAW: pthread_getschedparam failed: 1
         * on every thread it created -- glibc's pthread_getschedparam is
         * exactly sched_getparam + sched_getscheduler. (M1965) */
        if (r->rsi) {
            if (!vmm_user_ok(r->rsi, 4)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            *(int32_t *)r->rsi = 0;
        }
        r->rax = 0;
        break;
    case LXS_sched_getscheduler_:            /* (pid) -> policy */
        r->rax = 0;                          /* SCHED_OTHER: the CFS class everything runs in */
        break;
    case LXS_sched_setparam_:
    case LXS_sched_setscheduler_:
        /* Accepted. A single-user desktop OS has no privilege boundary to
         * enforce here, and a runtime that cannot set a policy it did not
         * need is a runtime that refuses to start. */
        r->rax = 0;
        break;
    case LXS_prctl_:
        /* Node calls PR_SET_NAME(15) for its threads and PR_SET_VMA
         * (0x53564d41, "AMVS") to label V8's heap regions for /proc/maps.
         *
         * PR_SET_NAME is NOT cosmetic here, and calling it that cost real time
         * (M2014): when eighty Gecko threads are parked on condition variables,
         * "which thread" is the whole question, and every one of them announces
         * its own answer -- "IPC I/O Parent", "Compositor", "JS Helper". Keep
         * it and print it in the thread dump. PR_SET_VMA really is advisory. */
        if (a1 == 15 /*PR_SET_NAME*/ && r->rsi && vmm_user_ok(r->rsi, 1))
            task_set_name((const char *)r->rsi);
        r->rax = 0;
        break;
    case LXS_clock_getres_: {               /* (clk_id, struct timespec *) */
        if (!r->rsi) { r->rax = 0; break; }
        if (!vmm_user_ok(r->rsi, 16)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        int64_t *ts = (int64_t *)r->rsi;
        /* Our clocks tick in milliseconds, and saying so is more useful than
         * claiming nanoseconds we cannot deliver. */
        ts[0] = 0; ts[1] = 1000000;
        r->rax = 0;
        break;
    }
    case LXS_eventfd_:                      /* (initval) -- no flags at all */
    case LXS_eventfd2_: {                   /* (initval, flags) */
        /* THE FLAGS WERE PASSED AS LITERAL ZERO (M2017), and they are not
         * decoration. EFD_NONBLOCK on an eventfd is what makes an event loop's
         * cross-thread wakeup safe to drain: the loop reads until EAGAIN. A
         * blocking one stops the loop dead on an empty counter -- and it is
         * the MAIN loop, so everything else the program was going to do,
         * including handling the HTTP response already sitting in a socket,
         * simply never happens.
         *
         * They also need TRANSLATING rather than passing through: our native
         * EFD_* are 1/2/4 and Linux's are 1/0x80000/0x800, so handing the raw
         * Linux value to app_eventfd_create would have set SEMAPHORE on
         * anything asking for CLOEXEC. Third time this class has bitten in one
         * session -- see pipe2 (M2009) and socketpair (M2012). */
        long lf = (r->rax == LXS_eventfd2_) ? (long)r->rsi : 0;
        int nf = 0;
        if (lf & 1)       nf |= EFD_SEMAPHORE;   /* EFD_SEMAPHORE: same value on both sides */
        if (lf & 0x800)   nf |= EFD_NONBLOCK;    /* Linux EFD_NONBLOCK  */
        if (lf & 0x80000) nf |= EFD_CLOEXEC;     /* Linux EFD_CLOEXEC   */
        int efd = app_eventfd_create((unsigned)r->rdi, nf);
        r->rax = (efd < 0) ? (uint64_t)-(long)LX_EMFILE : (uint64_t)efd;
        break;
    }
    /* TIMERFD, WHICH AN EVENT LOOP CANNOT DO WITHOUT (M2073).
     *
     * ENOSYS here is not a missing convenience. uSockets says so and stops:
     * "panic(main thread): us_create_timer: returned null: 38" -- errno 38,
     * ENOSYS, surfaced as a null pointer three layers up. Everything else
     * that reaches for a timer and gets nothing falls back to POLLING, which
     * is how a program ends up making nine hundred clock_gettime calls every
     * fifteen seconds and looking busy while waiting.
     *
     * The native timerfd has existed since M1217 and is already pollable; all
     * that was missing is the translation. Linux's interface is absolute-or-
     * relative itimerspec in NANOSECONDS, ours is a relative millisecond
     * delay plus an interval, so the conversion is the work -- and TFD_ABSTIME
     * matters: reading an absolute deadline as a relative one is the same
     * mistake M2010 fixed in FUTEX_WAIT_BITSET. */
    case LXS_timerfd_create_: {             /* (clockid, flags) */
        int tfd = app_timerfd_create();
        if (tfd < 0) { r->rax = (uint64_t)-(long)LX_EMFILE; break; }
        if (r->rsi & 0x800)   app_fd_set_nonblock(tfd, 1);   /* TFD_NONBLOCK */
        if (r->rsi & 0x80000) app_fd_set_cloexec(tfd, 1);    /* TFD_CLOEXEC  */
        r->rax = (uint64_t)tfd;
        break;
    }
    case LXS_timerfd_settime_: {            /* (fd, flags, new*, old*) */
        if (!r->rdx) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        if (!vmm_user_ok(r->rdx, 32)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        const int64_t *it = (const int64_t *)r->rdx;      /* {interval.sec,nsec, value.sec,nsec} */
        /* Round the nanoseconds UP, for the same reason the futex path does:
         * a sub-millisecond timer must not become a zero-millisecond one,
         * which reads as "disarm" and stops the loop it was driving. */
        int64_t ival = it[0] * 1000 + (it[1] + 999999) / 1000000;
        int64_t want = it[2] * 1000 + (it[3] + 999999) / 1000000;
        int64_t delay = want;
        if ((it[2] || it[3]) && (r->rsi & 1)) {           /* TFD_TIMER_ABSTIME */
            int64_t now = (int64_t)timer_ms();
            delay = want - now;
            if (delay <= 0) delay = 1;                    /* already due: fire at once, not never */
        }
        if (!it[2] && !it[3]) delay = 0;                  /* value 0 = disarm, exactly as Linux */
        if (r->r10) {                                     /* old_value, if asked for */
            if (!vmm_user_ok(r->r10, 32)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            int64_t *ov = (int64_t *)r->r10;
            long rem = app_timerfd_remaining_ms((int)a1), iv = app_timerfd_interval_ms((int)a1);
            ov[0] = iv / 1000; ov[1] = (iv % 1000) * 1000000;
            ov[2] = rem / 1000; ov[3] = (rem % 1000) * 1000000;
        }
        long rc3 = app_timerfd_settime((int)a1, (long)delay, (long)ival);
        r->rax = (rc3 < 0) ? (uint64_t)-(long)LX_EINVAL : 0;
        break;
    }
    case LXS_timerfd_gettime_: {            /* (fd, old*) */
        if (!vmm_user_ok(r->rsi, 32)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        long rem = app_timerfd_remaining_ms((int)a1), iv = app_timerfd_interval_ms((int)a1);
        if (rem < 0) { r->rax = (uint64_t)-(long)LX_EBADF; break; }
        int64_t *ov = (int64_t *)r->rsi;
        ov[0] = iv / 1000; ov[1] = (iv % 1000) * 1000000;
        ov[2] = rem / 1000; ov[3] = (rem % 1000) * 1000000;
        r->rax = 0;
        break;
    }
    case LXS_msync_:                        /* (addr, len, flags) */
        /* A MAP_SHARED writer that cannot flush has no way to make its writes
         * durable, and the honest failure is not ENOSYS -- app_msync exists
         * and does exactly this. MS_INVALIDATE has nothing to drop here (our
         * page cache IS the mapping), so it is a successful no-op. */
        r->rax = (uint64_t)(app_msync(r->rdi, r->rsi) < 0 ? -(long)LX_EINVAL : 0);
        break;
    case LXS_epoll_create1_: {              /* (flags) */
        int efd = app_epoll_create();
        r->rax = (efd < 0) ? (uint64_t)-(long)LX_EMFILE : (uint64_t)efd;
        break;
    }
    case LXS_epoll_ctl_: {                  /* (epfd, op, fd, struct epoll_event *) */
        /* LAYOUT: Linux's struct epoll_event is PACKED -- 4-byte events then
         * an 8-byte data field at offset 4, twelve bytes total. Ours is a
         * plain struct and therefore 16 with padding. Reading it as our own
         * type would take `data` from the wrong offset, which is the same
         * class of bug as struct stat's field offsets. Unpack by hand. */
        unsigned ev = 0; unsigned long data = 0;
        if (r->r10) {
            if (!vmm_user_ok(r->r10, 12)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            const uint8_t *p = (const uint8_t *)r->r10;
            ev   = *(const uint32_t *)(p + 0);
            data = *(const uint64_t *)(p + 4);
        }
        /* app_epoll_ctl returns a negative Linux errno directly -- EEXIST is
         * load-bearing for libuv, see the note on its definition. */
        int rc2 = app_epoll_ctl((int)a1, (int)r->rsi, (int)r->rdx, ev, data);
        r->rax = (uint64_t)(long)rc2;
        break;
    }
    case LXS_sched_yield_:
        /* Not decorative. Claude Code called this thirty-nine times in one
         * startup and every one returned ENOSYS -- so a cooperative yield
         * became a spin, on a machine with no spare cores under TCG. A yield
         * that does nothing is the difference between a scheduler point and a
         * busy-wait. */
        task_yield();
        r->rax = 0;
        break;
    case LXS_epoll_pwait2_:
    case LXS_epoll_wait_:
    case LXS_epoll_pwait_: {                /* (epfd, events, maxevents, timeout[, sigmask]) */
        long maxev = (long)r->rdx, timeout = (long)r->r10;
        /* epoll_pwait2 takes a `struct timespec *`, not a millisecond count --
         * and NULL means block forever, which is -1 in the millisecond
         * convention. Reading the pointer as an integer timeout would give a
         * caller either an instant return or a nonsense deadline. */
        if (r->rax == LXS_epoll_pwait2_) {
            if (!r->r10) timeout = -1;
            else if (vmm_user_ok(r->r10, 16)) {
                const uint64_t *ts2 = (const uint64_t *)r->r10;
                timeout = (long)(ts2[0] * 1000ull + ts2[1] / 1000000ull);
            } else { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        }
        if (maxev <= 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (maxev > 64) maxev = 64;         /* app_epoll_check's own clamp */
        if (!vmm_user_ok(r->rsi, (uint64_t)maxev * 12)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        struct epoll_event tmp[64];
        uint64_t start = timer_ms();
        /* AN EPOLL THAT KEEPS SAYING YES IS A BUSY LOOP (M2016). A level-
         * triggered fd whose readiness is never consumed makes an event loop
         * spin at full speed doing nothing -- Claude Code's main thread did
         * exactly that, returning 2 every time, while the socket it was
         * waiting on sat untouched. The report is worth one line: which fds,
         * what they asked for, what we answered. */
        if (g_net_trace) {
            static unsigned long same; static long lastk = -1; static int told;
            if (lastk > 0 && lastk == g_epoll_lastk) same++; else same = 0;   /* 0 is a legitimate timeout, not a spin */
            lastk = g_epoll_lastk;
            if (same == 400 && !told) {
                told = 1;
                kprintf("[nettrace] epoll fd %ld has answered %ld the same way 400 times "
                        "-- this loop is spinning. Its fds:\n", a1, lastk);
                app_epoll_dump((int)a1);
            }
        }
        long k = 0;
        __asm__ volatile("sti");            /* this loop sleeps on the timer */
        int etold = 0, espins = 0;
        for (;;) {
            k = app_epoll_check((int)a1, tmp, (int)maxev);
            if (k != 0) break;
            if (timeout >= 0 && (long)(timer_ms() - start) >= timeout) break;
            espins++;
            if (g_poll_trace && !etold && (long)(timer_ms() - start) > 3000 &&
                g_poll_reports < 24) {
                etold = 1; g_poll_reports++;
                kprintf("[poll] pid %d tid %d STALLED in epoll_wait(%d), timeout %ld:\n",
                        app_current_pid(), task_current_id(), (int)a1, timeout);
                app_epoll_dump((int)a1);
            }
            task_sleep_ms(lx_poll_nap(espins));
        }
        __asm__ volatile("cli");
        if (k < 0) { r->rax = (uint64_t)-(long)LX_EBADF; break; }
        uint8_t *out = (uint8_t *)r->rsi;   /* pack back into Linux's 12-byte layout */
        for (long i = 0; i < k; i++) {
            *(uint32_t *)(out + i * 12 + 0) = tmp[i].events;
            *(uint64_t *)(out + i * 12 + 4) = tmp[i].data;
        }
        g_epoll_lastk = k;
        r->rax = (uint64_t)k;
        break;
    }
    case LXS_poll_:
    case LXS_ppoll_: {                      /* (fds, nfds, timeout | timespec) */
        /* struct pollfd { int fd; short events; short revents; } -- 8 bytes,
         * same on both sides. */
        long nfds = (long)r->rsi;
        if (nfds < 0 || nfds > 256) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (nfds && !vmm_user_ok(r->rdi, (uint64_t)nfds * 8)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        long timeout;
        if (r->rax == LXS_poll_) timeout = (long)r->rdx;
        else if (!r->rdx) timeout = -1;     /* ppoll: NULL timespec = forever */
        else {
            if (!vmm_user_ok(r->rdx, 16)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            const int64_t *ts = (const int64_t *)r->rdx;
            timeout = (long)(ts[0] * 1000 + ts[1] / 1000000);
        }
        uint8_t *fds = (uint8_t *)r->rdi;
        uint64_t start = timer_ms();
        long ready = 0;
        int told = 0, spins = 0;
        __asm__ volatile("sti");
        for (;;) {
            ready = 0;
            for (long i = 0; i < nfds; i++) {
                int fd = *(const int32_t *)(fds + i * 8);
                short want = *(const int16_t *)(fds + i * 8 + 4);
                int re = (fd < 0) ? 0 : app_fd_ready(app_current(), fd, want);
                *(int16_t *)(fds + i * 8 + 6) = (short)re;
                if (re) ready++;
            }
            if (ready) break;
            if (timeout >= 0 && (long)(timer_ms() - start) >= timeout) break;
            spins++;
            if (g_poll_trace && !told && (long)(timer_ms() - start) > 3000 &&
                g_poll_reports < 24) {
                told = 1; g_poll_reports++;
                kprintf("[poll] pid %d tid %d STALLED on %ld fd(s), timeout %ld:\n",
                        app_current_pid(), task_current_id(), nfds, timeout);
                for (long i = 0; i < nfds; i++) {
                    int fd = *(const int32_t *)(fds + i * 8);
                    short want = *(const int16_t *)(fds + i * 8 + 4);
                    int fty = fd < 0 ? -1 : app_fd_type(fd);
                    kprintf("[poll]   fd %d type %d want %x -> %x\n", fd, fty,
                            (unsigned)(want & 0xffff),
                            fd < 0 ? 0 : app_fd_ready(app_current(), fd, want));
                    /* A PIPE that never reports EOF still has a writer. Say how
                     * many descriptors hold each end: that distinguishes a
                     * program that forgot to close its own copy (which hangs on
                     * Linux too) from a kernel that lost a close. (M2004) */
                    if (fty == 1) {
                        int ro = 0, wo = 0, q = 0, hw = 0;
                        pipe_state(app_fd_obj(fd), &ro, &wo, &q, &hw);
                        kprintf("[poll]     pipe #%d: %d reader(s), %d writer(s), %d byte(s) queued, had_writer=%d\n",
                                app_fd_obj(fd), ro, wo, q, hw);
                    }
                }
            }
            task_sleep_ms(lx_poll_nap(spins));
        }
        __asm__ volatile("cli");
        r->rax = (uint64_t)ready;
        break;
    }
    case LXS_mremap_: {                     /* (old, old_len, new_len, flags, new_addr) */
        /* app_mremap has existed since M1179; it was simply never wired up
         * here. GCC's allocator grows its heap with mremap, and an ENOSYS
         * sends glibc down a malloc/copy/free fallback that behaves
         * differently under memory pressure -- the compiler died on the
         * largest source file in the tree and nothing named this. (M1961) */
        uint64_t nb = app_mremap(r->rdi, r->rsi, r->rdx, (int)r->r10);
        r->rax = (nb == (uint64_t)-1) ? (uint64_t)-(long)LX_ENOMEM : nb;
        break;
    }
    case LXS_madvise_:                      /* (addr, len, advice) */
        /* app_madvise already existed (swap/zram work): it handles
         * DONTNEED/COLD/PAGEOUT/COLLAPSE and treats the rest as an accepted
         * no-op. It returns a PAGE COUNT, not 0 -- madvise(2) returns 0 on
         * success, so only the negative case is an error. glibc's thread-stack
         * cache calls this on every stack it retires, so it is on the
         * pthread_create path. (M1959) */
        r->rax = (uint64_t)(app_madvise(r->rdi, r->rsi, (int)r->rdx) < 0 ? -(long)LX_EINVAL : 0);
        break;
    case LXS_gettid_:
        r->rax = (uint64_t)app_gettid();        /* a thread's id, NOT the process's */
        break;
    case LXS_futex_: {                          /* (uaddr, op, val, timeout, uaddr2, val3) */
        /* FUTEX_PRIVATE_FLAG(128) is genuinely a scope hint and is masked off.
         *
         * FUTEX_CLOCK_REALTIME(256) IS NOT (M2010). It was masked off too, with
         * a comment claiming it did not change what we do, and it changes
         * everything: it names the clock an ABSOLUTE deadline is measured
         * against. FUTEX_WAIT_BITSET's timeout is absolute -- that is the
         * difference between it and FUTEX_WAIT -- so reading its timespec as a
         * relative duration turned a 50 ms pthread_cond_timedwait into a wait
         * of 1.79e12 milliseconds: fifty-six years.
         *
         * That is what Firefox looked like: sixty-six threads parked in futex
         * waits they believed were milliseconds long, the process making zero
         * syscalls, and nothing in the trace saying "timeout" because from the
         * kernel's side the wait was proceeding exactly as asked. Every
         * condition variable with a deadline in glibc goes through this path. */
        int op = (int)r->rsi & 0x7F;
        int val = (int)r->rdx;
        if (!vmm_user_ok(r->rdi, 4)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        if (op == 0 /*FUTEX_WAIT*/ || op == 9 /*FUTEX_WAIT_BITSET*/) {
            /* The value check happens HERE, not inside app_futex, because
             * app_futex returns -1 for both "value changed" and "timed out"
             * and glibc treats them completely differently: EAGAIN means retry
             * the fast path, ETIMEDOUT means give up. Checking first makes the
             * common case unambiguous. */
            if (*(volatile int *)r->rdi != val) { r->rax = (uint64_t)-(long)LX_EAGAIN; break; }
            long ms = -1;
            if (r->r10) {                       /* struct timespec { sec; nsec; } */
                if (!vmm_user_ok(r->r10, 16)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
                const int64_t *ts = (const int64_t *)r->r10;
                /* Round the nanoseconds UP: a 500 us wait must not become a
                 * zero-millisecond one that returns ETIMEDOUT without ever
                 * yielding, which turns a timed wait into a spin. */
                int64_t want = ts[0] * 1000 + (ts[1] + 999999) / 1000000;
                if (op == 9) {                  /* FUTEX_WAIT_BITSET: `want` is a DEADLINE */
                    /* Measured against the same clock clock_gettime reports,
                     * because that is the clock the caller computed it from. */
                    int64_t now = ((int)r->rsi & 256)        /* FUTEX_CLOCK_REALTIME */
                        ? (int64_t)lx_realtime_sec() * 1000 + (int64_t)(timer_ms() % 1000)
                        : (int64_t)timer_ms();
                    want -= now;
                }
                ms = (long)want;
                if (ms < 0) ms = 0;             /* already expired */
            }
            long fr = app_futex(r->rdi, FUTEX_WAIT, val, ms);
            /* We got past the value check, so a -1 now is the timeout (or the
             * waiter table being full, which is indistinguishable here and
             * equally a "could not wait"). */
            r->rax = (fr == 0) ? 0 : (uint64_t)-(long)(ms >= 0 ? LX_ETIMEDOUT : LX_EAGAIN);
            break;
        }
        if (op == 1 /*FUTEX_WAKE*/ || op == 10 /*FUTEX_WAKE_BITSET*/) {
            long woke = app_futex(r->rdi, FUTEX_WAKE, val, -1);
            r->rax = (woke < 0) ? 0 : (uint64_t)woke;   /* waking nothing is success, not an error */
            break;
        }
        /* REQUEUE/CMP_REQUEUE/WAKE_OP/PI are optimisations glibc has fallbacks
         * for. ENOSYS is the honest answer and makes it use them. */
        r->rax = (uint64_t)-(long)LX_ENOSYS;
        break;
    }
    /* SIGNALS, HONOURED RATHER THAN ACKNOWLEDGED (M2063).
     *
     * Both of these returned 0 and did nothing. That is the twelfth "granted
     * in name only" defect in this campaign, and the worst-behaved shape of
     * it: `rt_sigaction(sig, NULL, &old)` is a QUERY, and answering 0 without
     * writing `old` leaves the caller reading its own uninitialised stack as
     * a function pointer. A runtime that saves the old handler and restores it
     * later then installs garbage. Meanwhile SIG_IGN was not recorded at all,
     * so a program that asked for a signal to be ignored kept getting it.
     *
     * Everything needed already existed -- app_sigaction, app_sigprocmask, a
     * pending bitset, sigaltstack, an RT sigqueue. The numbers just did not
     * line up: our SIGWINCH was 24 where Linux says 28, and SIGRTMIN was 28.
     * M2063 renumbered both and widened every mask to 64 bits, so a Linux
     * signal number now passes straight through. */
    case LXS_rt_sigaction: {                /* (sig, act, oldact, sigsetsize) */
        int sig = (int)a1;
        if (sig <= 0 || sig >= APP_NSIG_LX) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (sig == 9 || sig == 19) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }   /* SIGKILL/SIGSTOP */
        /* Linux's KERNEL sigaction, which is not glibc's:
         *   { void *handler; unsigned long flags; void *restorer; u64 mask; } */
        if (r->rdx) {                       /* oldact first: `act` may alias it */
            if (!vmm_user_ok(r->rdx, 32)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            uint64_t *o = (uint64_t *)r->rdx;
            o[0] = app_sig_handler_of(sig);
            o[1] = (uint64_t)app_sig_flags_of(sig);
            o[2] = app_sig_restorer_of();
            o[3] = lx_sigset_out(app_sig_mask_of(sig));
        }
        if (r->rsi) {
            if (!vmm_user_ok(r->rsi, 32)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            const uint64_t *na = (const uint64_t *)r->rsi;
            app_sigaction_full(sig, na[0], na[2], (uint32_t)na[1], lx_sigset_in(na[3]));
        }
        r->rax = 0;
        break;
    }
    case LXS_rt_sigpending_:                /* (set, sigsetsize) */
        /* ENOSYS until M2063, so a program could not tell a blocked signal
         * from one that was never raised -- and sigwait/sigtimedwait loops are
         * built on exactly that question. */
        if (!r->rdi || !vmm_user_ok(r->rdi, 8)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        *(uint64_t *)r->rdi = lx_sigset_out(app_sigpending());
        r->rax = 0;
        break;
    case LXS_pause_:
        /* WAIT FOR A SIGNAL (M2063). ENOSYS until now, which was harmless only
         * while nothing could deliver a signal anyway -- and Firefox called it
         * forty times in one startup. A thread told "that syscall does not
         * exist" where it expected to sleep until a signal arrives either
         * spins or gives up; neither is what it asked for.
         *
         * app_pause blocks on the CURRENT mask and always returns -1/EINTR,
         * which is pause()'s only defined success. */
        __asm__ volatile("sti");            /* it sleeps: the timer has to run */
        app_pause(r);
        __asm__ volatile("cli");
        r->rax = (uint64_t)-(long)LX_EINTR;
        break;
    case LXS_rt_sigsuspend_: {              /* (mask, sigsetsize) */
        /* Same shape, with a temporary mask -- glibc's sigwait and
         * pthread_cond_wait cancellation path both land here. */
        if (!r->rdi || !vmm_user_ok(r->rdi, 8)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        uint64_t m = lx_sigset_in(*(const uint64_t *)r->rdi);
        __asm__ volatile("sti");
        app_sigsuspend(r, m);
        __asm__ volatile("cli");
        r->rax = (uint64_t)-(long)LX_EINTR;
        break;
    }
    case LXS_rt_sigreturn_:
        /* THE HANDLER'S WAY BACK. glibc's __restore_rt is `syscall(15)`, so
         * without this a Linux signal handler could be entered and never
         * return: the trampoline would fall through to an ENOSYS and then off
         * the end of the world. Nothing had noticed because nothing could
         * raise a signal in the first place (see kill, above). (M2063) */
        app_sigreturn(r);
        break;
    case LXS_rt_sigprocmask: {              /* (how, set, oldset, sigsetsize) */
        long how = a1;
        if (r->rdx) {
            if (!vmm_user_ok(r->rdx, 8)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            *(uint64_t *)r->rdx = lx_sigset_out(app_sigprocmask(3 /* query only */, 0));
        }
        if (r->rsi) {
            if (!vmm_user_ok(r->rsi, 8)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            if (how != 0 && how != 1 && how != 2) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
            app_sigprocmask((int)how, lx_sigset_in(*(const uint64_t *)r->rsi));
        }
        r->rax = 0;
        break;
    }
    case LXS_ioctl: {                       /* (fd, request, arg) */
        /* A TERMINAL PROGRAM HAS TO BE ABLE TO FIND OUT IT IS ON A TERMINAL
         * (M2004).
         *
         * This answered ENOTTY to everything, which was the right answer while
         * the only caller was musl deciding how to buffer stdio. It is the
         * wrong answer for an interactive program: Claude Code, like anything
         * built on a TUI, asks TCGETS to learn whether it may take over the
         * screen and TIOCGWINSZ to learn how big the screen is. Told "not a
         * terminal" it falls back to non-interactive mode, which is exactly the
         * mode in which you cannot log in.
         *
         * Only fd 0/1/2, and only when there is really a window behind them --
         * a process with no console must still be told the truth, or it will
         * draw a UI nobody can see. */
        long req = (long)r->rsi;
        int cols = 0, rows = 0;
        {   /* Which ioctls does this program actually ask, and on which fd?
             * Each distinct pair once -- guessing which one decides "am I a
             * terminal" is how two rebuilds got spent on the wrong fd. */
            static struct { long fd, rq; } seen[24]; static int nseen;
            int known = 0;
            for (int i = 0; i < nseen; i++) if (seen[i].fd == a1 && seen[i].rq == req) { known = 1; break; }
            if (!known && nseen < 24) {
                seen[nseen].fd = a1; seen[nseen].rq = req; nseen++;
                if (g_lx_systrace)
                    kprintf("[linuxabi] ioctl(fd %ld, 0x%lx) type=%d\n", a1, req, app_fd_type((int)a1));
            }
        }
        /* A DESCRIPTOR IS A TERMINAL BECAUSE OF WHAT IT REFERS TO, not because
         * of its number (M2004). Checking `fd <= 2` looks right and is wrong
         * the moment a program dups its stdio -- which Claude Code does, and
         * then asks the DUP whether it is a tty. Type 14 is the console alias,
         * so any copy of it answers yes, exactly as a dup of a tty does on
         * Linux. */
        int is_console = (app_fd_type((int)a1) == 14 ||
                          ((a1 >= 0 && a1 <= 2) && !app_fd_is_open((int)a1)))
                         && app_console_size(&cols, &rows);
        if (!is_console) { r->rax = (uint64_t)-(long)LX_ENOTTY; break; }
        /* TCGETS2, NOT TCGETS (M2004). glibc's tcgetattr has used the '2'
         * variants since it grew arbitrary baud rates, so a modern program
         * asks _IOR('T', 0x2A, struct termios2) -- 0x802c542a -- and never
         * touches 0x5401 at all. Implementing only the old one looks correct
         * and answers a question nobody asks; the trace is what settled it:
         *
         *     [linuxabi] ioctl(fd 0, 0x802c542a) type=14
         *
         * termios2 is termios plus c_ispeed/c_ospeed, so 44 bytes not 36. */
        /* TCGETS/TCGETS2 must report what TCSETS LAST SET, not a constant
         * (M2014). glibc's cfmakeraw is a read-modify-write: tcgetattr,
         * clear the flags, tcsetattr. If the read always answers "canonical,
         * echo on, ICRNL" then a program that just turned raw mode ON is told
         * it is still off, and any code that trusts the round trip -- or
         * restores the "previous" settings on exit -- is working from
         * fiction. */
        if (req == 0x802c542a /*TCGETS2*/ || req == 0x5401 /*TCGETS*/) {
            int sz = (req == 0x5401) ? 36 : 44;
            if (!vmm_user_ok(r->rdx, (uint64_t)sz)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            uint8_t *t = (uint8_t *)r->rdx;
            for (int i = 0; i < sz; i++) t[i] = 0;
            uint32_t ifl = 0, ofl = 0, cfl = 0, lfl = 0; uint8_t cc[19];
            if (app_termios_get(&ifl, &ofl, &cfl, &lfl, cc) != 0) { r->rax = (uint64_t)-(long)LX_ENOTTY; break; }
            *(uint32_t *)(t + 0) = ifl; *(uint32_t *)(t + 4) = ofl;
            *(uint32_t *)(t + 8) = cfl; *(uint32_t *)(t + 12) = lfl;
            for (int i = 0; i < 19; i++) t[17 + i] = cc[i];
            if (sz == 44) { *(uint32_t *)(t + 36) = 38400; *(uint32_t *)(t + 40) = 38400; }
            r->rax = 0; break;
        }
        if (req == 0x402c542b || req == 0x402c542c || req == 0x402c542d ||   /* TCSETS2/W2/F2 */
            req == 0x5402 || req == 0x5403 || req == 0x5404) {               /* TCSETS/W/F */
            /* STORED, NOT DISCARDED (M2014). This was "accepted and ignored"
             * because our console already delivers keys one at a time -- which
             * is true and is not the point. The flags say how those keys should
             * be ENCODED, and the one that matters is ICRNL: cleared, it means
             * the program wants the Return key as CR. Ink (which is what Claude
             * Code draws with) maps \r to `key.return` and NOTHING else does,
             * so discarding the flag left a TUI whose selection list could be
             * moved but never chosen. */
            if (!vmm_user_ok(r->rdx, 36)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            const uint8_t *t = (const uint8_t *)r->rdx;
            app_termios_set(*(const uint32_t *)(t + 0), *(const uint32_t *)(t + 4),
                            *(const uint32_t *)(t + 8), *(const uint32_t *)(t + 12), t + 17);
            r->rax = 0; break;
        }
        if (req == 0x5413 /*TIOCGWINSZ*/) {
            if (!vmm_user_ok(r->rdx, 8)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            uint16_t *w = (uint16_t *)r->rdx;
            { static int told; if (!told) { told = 1;
                kprintf("[tty] reporting a %dx%d terminal (cols x rows)\n", cols, rows); } }
            w[0] = (uint16_t)rows; w[1] = (uint16_t)cols;
            w[2] = (uint16_t)(cols * 8); w[3] = (uint16_t)(rows * 16);   /* pixels, at our font cell */
            r->rax = 0; break;
        }
        if (req == 0x540F /*TIOCGPGRP*/) {
            if (r->rdx && vmm_user_ok(r->rdx, 4)) *(int32_t *)r->rdx = app_current_pid();
            r->rax = 0; break;
        }
        if (req == 0x5410 /*TIOCSPGRP*/) { r->rax = 0; break; }
        r->rax = (uint64_t)-(long)LX_ENOTTY;
        break;
    }
    case LXS_brk: {
        /* Linux brk(0) returns the CURRENT break; brk(addr) sets it and returns
         * the resulting break -- crucially it does NOT return an errno on
         * failure, it returns the UNCHANGED break and lets the caller notice.
         * Returning -ENOMEM here would make glibc's malloc think it had grown.
         *
         * app_sbrk is grow-only and takes a DELTA, so shrink requests are
         * accepted and ignored, which brk permits (the memory stays mapped). */
        uint64_t cur = app_sbrk(0);
        if (a1 == 0) { r->rax = cur; break; }
        if ((uint64_t)a1 > cur) {
            uint64_t want = (uint64_t)a1 - cur;
            if (app_sbrk((long)want) == (uint64_t)-1) { r->rax = cur; break; }  /* failed: unchanged break */
            r->rax = app_sbrk(0);
            break;
        }
        /* A SHRINK MUST SUCCEED AND REPORT THE ADDRESS IT WAS GIVEN (M2049).
         *
         * This used to "accept and ignore" a shrink and then return the
         * UNCHANGED, higher break. On Linux, brk(addr) below the current break
         * succeeds and returns addr, and glibc compares the value it gets back
         * against the one it asked for -- so returning a higher number is a
         * FAILURE report. malloc's heap-trimming path then asks again, gets the
         * same answer, and asks again:
         *
         *   t70 12(48572000, ...) = 48592000      (x thousands)
         *
         * -- a brk loop that hung the in-guest GCC compile with the guest at
         * 12% CPU, which reads as a wedged machine rather than a disagreement
         * about a return value.
         *
         * The bookkeeping moves down; the pages stay mapped. Linux does not
         * guarantee the memory is returned either, only that the break is
         * where you asked, and not unmapping keeps this a two-line change
         * instead of a teardown path. Never below the heap base. */
        {
            uint64_t lo = (uint64_t)a1;
            uint64_t base = app_heap_base();
            if (lo < base) lo = base;
            app_set_break(lo);
            r->rax = lo;
        }
        break;
    }
    case LXS_mmap: {
        /* Linux: mmap(addr, len, prot, flags, fd, off). Ours reserves an
         * anonymous demand-paged region and CHOOSES the address, so only the
         * anonymous case is expressible. MAP_FIXED cannot be honoured at all
         * and must fail rather than silently land elsewhere -- a caller that
         * asked for a specific address and got another one corrupts itself. */
        long len = (long)r->rsi, prot = (long)r->rdx, flags = (long)r->r10;
        /* (int), NOT (long). `fd` is an int in Linux's prototype, so a caller
         * passing -1 leaves 0xFFFFFFFF in the low half of r8 with a ZERO upper
         * half -- read as a long that is 4294967295, which sails past a
         * `fd >= 0` check and made every anonymous mmap fail. Any int-typed
         * syscall argument whose negative values are meaningful has to be
         * narrowed like this: AT_FDCWD (-100) and wait4's pid (-1) are the
         * other cases in this file. */
        int fd = (int)r->r8;
        if (len <= 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (!(flags & LX_MAP_ANONYMOUS)) {
            /* A memfd has no PATH, so the file-backed route below cannot serve
             * it -- and mapping one is the entire point of memfd. Both
             * processes that map the same object get the same physical pages,
             * which is what makes wl_shm a zero-copy pixel handoff. (M1977) */
            if (fd >= 0 && app_fd_type(fd) == 3) {
                uint64_t mb = app_mmap_memfd(fd, (uint64_t)len, (uint64_t)r->r9);
                if (g_lx_systrace)
                    kprintf("[lxmmap] memfd fd=%d len=%lx off=%lx -> %lx\n",
                            fd, (unsigned long)len, (unsigned long)r->r9, (unsigned long)mb);
                if (!mb) { r->rax = (uint64_t)-(long)LX_ENOMEM; break; }
                r->rax = mb; break;
            }
            /* File-backed: resolve the fd to its path and map at the given
             * offset. This is the shape a dynamic linker uses for every
             * PT_LOAD of a shared object. (M1953) */
            const char *fpath = (fd >= 0) ? app_fd_path(fd) : 0;
            if (!fpath) { r->rax = (uint64_t)-(long)LX_ENODEV; break; }
            uint64_t fbase = app_mmap_file_at(fpath, (flags & LX_MAP_FIXED) ? r->rdi : 0,
                                              (uint64_t)len, (uint64_t)r->r9,
                                              (flags & LX_MAP_SHARED) ? 1 : 0);
            if (g_lx_mmap_trace)
                kprintf("[lxmmap] file addr=%lx len=%lx off=%lx prot=%ld fixed=%d -> %lx\n",
                        (unsigned long)r->rdi, (unsigned long)len, (unsigned long)r->r9,
                        prot, (flags & LX_MAP_FIXED) ? 1 : 0, (unsigned long)fbase);
            if (!fbase) {
                kprintf("[linuxabi] mmap(%s, len=%ld, off=%ld, fixed=%d) FAILED\n",
                        fpath, len, (long)r->r9, (flags & LX_MAP_FIXED) ? 1 : 0);
                r->rax = (uint64_t)-(long)LX_ENOMEM; break;
            }
            if (prot != (1 | 2)) app_mprotect(fbase, (uint64_t)len, (int)prot);
            r->rax = fbase;
            break;
        }
        if (fd >= 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }   /* MAP_ANONYMOUS with an fd */
        /* MAP_FIXED is honoured now (M1952) -- it used to be refused outright,
         * which is correct-but-useless: a caller that asks for a specific
         * address needs that address. Still refused if the range is
         * unaligned, outside the window, or overlaps an existing VMA, because
         * Linux's silent-replace needs VMA splitting we do not have yet. */
        uint64_t base;
        if (flags & LX_MAP_FIXED) base = app_mmap_fixed(r->rdi, (uint64_t)len);
        else {
            /* HONOUR THE ADDRESS HINT (M2000). Without MAP_FIXED the `addr`
             * argument is advice, and Linux takes it whenever the range is
             * free. Allocators rely on that: mimalloc -- Bun's allocator --
             * picks an address in the terabytes and expects its arenas there,
             * and packing them low instead puts them on top of the region
             * JavaScriptCore reserved for its pointer cage.
             *
             * Advice, not a demand: if the hint is unaligned, outside the mmap
             * window, or already occupied, fall back to choosing an address
             * ourselves, which is exactly what Linux does. */
            base = 0;
            if (r->rdi && !(r->rdi & (PAGE_SIZE - 1)))
                base = app_mmap_hint(r->rdi, (uint64_t)len);   /* NEVER app_mmap_fixed: that REPLACES */
            if (!base) base = app_mmap((uint64_t)len);
        }
        /* A HUGE reservation is always structural, never incidental, and it is
         * worth a line in the log whether or not tracing is on. JSC reserves
         * `size + alignment` of PROT_NONE address space for its pointer cage
         * and then aligns the result up by hand -- 32 GiB of cage means a 64
         * GiB request, and the base it computes is the first 32 GiB-aligned
         * address inside whatever it got back. If the reservation is short, or
         * it is trimmed wrong afterwards, the program does not fail here: it
         * fails much later, reading through a pointer built from a base that
         * was never mapped. (M1999) */
        if (len >= (1L << 30))
            kprintf("[lxmmap] BIG anon request: addr=%lx len=%lx (%ld MiB) prot=%ld flags=%lx -> %lx\n",
                    (unsigned long)r->rdi, (unsigned long)len, len >> 20, prot,
                    (unsigned long)flags, (unsigned long)base);
        if (g_lx_mmap_trace)
            kprintf("[lxmmap] anon addr=%lx len=%lx prot=%ld fixed=%d -> %lx\n",
                    (unsigned long)r->rdi, (unsigned long)len, prot,
                    (flags & LX_MAP_FIXED) ? 1 : 0, (unsigned long)base);
        /* A refused anonymous mapping is worth saying out loud even without the
         * trace flag: an allocator that cannot get memory usually aborts, and
         * an abort says nothing about why. (M1970) */
        if (!base) {
            kprintf("[linuxabi] mmap(anon, addr=%lx, len=%lx, fixed=%d) REFUSED\n",
                    (unsigned long)r->rdi, (unsigned long)len,
                    (flags & LX_MAP_FIXED) ? 1 : 0);
            r->rax = (uint64_t)-(long)LX_ENOMEM; break;
        }
        /* our regions come back writable+NX; tighten to what was asked for */
        if (prot != (1 | 2)) app_mprotect(base, (uint64_t)len, (int)prot);
        r->rax = base;
        break;
    }
    case LXS_mprotect: {
        int mrc = app_mprotect(r->rdi, r->rsi, (int)r->rdx);
        if (g_lx_mmap_trace)
            kprintf("[lxmmap] mprotect addr=%lx len=%lx prot=%ld -> %d\n",
                    (unsigned long)r->rdi, (unsigned long)r->rsi, (long)r->rdx, mrc);
        r->rax = (uint64_t)(mrc == 0 ? 0 : -(long)LX_EINVAL);
        break;
    }
    case LXS_munmap: {
        long urc = app_munmap(r->rdi, r->rsi);
        /* The other half of the huge-reservation story (M1999): JSC trims its
         * over-sized reservation down to the aligned window it wants by
         * munmapping the head and the tail. A trim that removes the wrong
         * range, or that FAILS and leaves the caller believing it succeeded,
         * is indistinguishable from the reservation never having happened --
         * and it only shows up much later, as a read through a cage base that
         * is not mapped. */
        if ((long)r->rsi >= (1L << 30))
            kprintf("[lxmmap] BIG munmap: addr=%lx len=%lx (%ld MiB) -> %ld\n",
                    (unsigned long)r->rdi, (unsigned long)r->rsi,
                    (long)r->rsi >> 20, urc);
        r->rax = (uint64_t)(urc == 0 ? 0 : -(long)LX_EINVAL);
        break;
    }
    case LXS_set_robust_list:
    case LXS_rseq:
        /* Both are pure optimisations: the robust-futex list only matters if a
         * thread dies holding a lock, and rseq is a fast-path hint. Linux
         * itself returns -ENOSYS for rseq when unsupported and glibc copes, so
         * accepting-and-ignoring is safe for set_robust_list and ENOSYS is the
         * honest answer for rseq. */
        r->rax = (r->rax == LXS_rseq) ? (uint64_t)-(long)LX_ENOSYS : 0;
        break;
    case LXS_getuid: case LXS_geteuid:
    case LXS_getgid: case LXS_getegid:
        r->rax = 0;                          /* single-user: always root */
        break;
    case LXS_getresuid_: case LXS_getresgid_: {
        /* (real*, effective*, saved*). Single-user, so all three are root --
         * but they must be WRITTEN. glib calls this to decide whether it is
         * running setuid, and an ENOSYS left it reading its own uninitialised
         * stack. (M1986) */
        for (int q = 0; q < 3; q++) {
            uint64_t up = q == 0 ? r->rdi : (q == 1 ? r->rsi : r->rdx);
            if (up && vmm_user_ok(up, 4)) *(uint32_t *)up = 0;
        }
        r->rax = 0;
        break;
    }
    case LXS_getpeername_: {                /* (fd, sockaddr *, addrlen *) */
        /* The mirror of getsockname above, and the same trap: an AF_UNIX
         * answer for an AF_INET socket makes glibc abort rather than fail. */
        int ty2 = app_fd_type((int)a1);
        if (!r->rsi || !vmm_user_ok(r->rsi, 16)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        uint8_t *o2 = (uint8_t *)r->rsi;
        for (int i = 0; i < 16; i++) o2[i] = 0;
        if (ty2 == 9 || ty2 == 10) {
            uint8_t pip[4] = {0,0,0,0}; uint16_t pport = 0;
            app_sock_peeraddr((int)a1, pip, &pport);
            *(uint16_t *)o2 = 2;                                 /* AF_INET */
            o2[2] = (uint8_t)(pport >> 8); o2[3] = (uint8_t)(pport & 0xFF);
            for (int i = 0; i < 4; i++) o2[4 + i] = pip[i];
            if (r->rdx && vmm_user_ok(r->rdx, 4)) *(uint32_t *)r->rdx = 16;
        } else if (ty2 == 12 || ty2 == 13) {
            *(uint16_t *)o2 = 1;                                 /* AF_UNIX */
            if (r->rdx && vmm_user_ok(r->rdx, 4)) *(uint32_t *)r->rdx = 2;
        } else { r->rax = (uint64_t)-(long)LX_ENOTSOCK; break; }
        r->rax = 0;
        break;
    }
    case LXS_statfs_: case LXS_fstatfs_: {
        /* struct statfs is 120 bytes: f_type, f_bsize, f_blocks, f_bfree,
         * f_bavail, f_files, f_ffree, f_fsid[2], f_namelen, f_frsize, f_flags,
         * f_spare[4] -- all 8-byte except the fsid pair. glib uses it to decide
         * whether a directory is on a remote filesystem before it will watch
         * it; ENOSYS made every path look unwatchable. The numbers are the
         * ext2 volume's shape, rounded: honest enough for that decision and
         * not pretending to a precision we do not have. */
        uint64_t up2 = (r->rax == LXS_statfs_) ? r->rsi : r->rsi;
        if (!up2 || !vmm_user_ok(up2, 120)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        uint64_t *f = (uint64_t *)up2;
        for (int i = 0; i < 15; i++) f[i] = 0;
        f[0] = 0xEF53;                       /* f_type: EXT2_SUPER_MAGIC */
        f[1] = 4096;                         /* f_bsize */
        f[2] = 563200;                       /* f_blocks (2200 MiB / 4 KiB) */
        f[3] = 280000;                       /* f_bfree */
        f[4] = 280000;                       /* f_bavail */
        f[5] = 65536;                        /* f_files */
        f[6] = 60000;                        /* f_ffree */
        f[9] = 255;                          /* f_namelen */
        f[10] = 4096;                        /* f_frsize */
        r->rax = 0;
        break;
    }
    case LXS_fallocate_: {                  /* (fd, mode, offset, len) */
        /* ALLOCATE FOR REAL WHEN WE CAN (M2000).
         *
         * Answering EOPNOTSUPP is legal -- Linux filesystems do, and glibc's
         * posix_fallocate falls back to writing the range by hand. But that
         * fallback needs pread/pwrite on the fd, and for a MEMFD it got ENOSYS
         * and gave up. Every Wayland client sizes its shared-memory pool with
         * exactly this call, so the pool stayed zero-length and the mmap after
         * it failed -- reported by GDK as one warning about a cursor theme.
         *
         * A memfd is an in-RAM file that ftruncate can already grow, which is
         * precisely what mode-0 fallocate means: make sure the bytes exist.
         * Do that, and keep EOPNOTSUPP for everything else, where the caller's
         * fallback is the right answer. */
        long foff = (long)r->rdx, flen = (long)r->r10;
        if ((int)r->rsi == 0 && foff >= 0 && flen > 0 && app_memfd_size((int)a1) >= 0) {
            long want = foff + flen;
            long have = app_memfd_size((int)a1);
            long tr = (have >= want) ? 0 : app_ftruncate((int)a1, want);
            r->rax = (uint64_t)(tr == 0 ? 0 : -(long)LX_ENOSPC);
            break;
        }
        r->rax = (uint64_t)-(long)LX_EOPNOTSUPP;
        break;
    }
    case LXS_inotify_add_watch_: {          /* (fd, path, mask) -> a watch descriptor */
        /* inotify_init1 landed in M1986 and these did not, which is the worst
         * half to implement: a program gets a working inotify fd, cannot put a
         * single watch on it, and -- because a file watcher has nothing else to
         * do -- retries forever. Firefox sat in a three-syscall loop
         * (add_watch, add_watch, ppoll) burning a core with its window never
         * opening, and the ring is what showed it. The native watch mechanism
         * has existed since M1266; only the ABI spelling was missing. */
        if (!r->rsi || !vmm_user_ok(r->rsi, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate((const char *)r->rsi, xp, sizeof xp);
        int wd = app_inotify_add((int)a1, path, (unsigned)r->rdx);
        r->rax = (wd < 0) ? (uint64_t)-(long)LX_ENOENT : (uint64_t)wd;
        break;
    }
    case LXS_inotify_rm_watch_:             /* (fd, wd) */
        r->rax = (app_inotify_rm((int)a1, (int)r->rsi) == 0) ? 0 : (uint64_t)-(long)LX_EINVAL;
        break;
    case LXS_inotify_init1_:
        /* inotify EXISTS here (M1266) -- only the flags-taking entry point was
         * missing, which is the only one glib uses. */
        { int ifd = app_inotify_init(); r->rax = ifd < 0 ? (uint64_t)-(long)LX_EMFILE : (uint64_t)ifd; }
        break;
    case LXS_prlimit64:
        /* (pid, resource, new, old). Report "unlimited" for a get and accept a
         * set: glibc reads RLIMIT_STACK here to size its thread stacks, and a
         * failure makes it fall back to a default rather than break. */
        if (r->r10) {
            uint64_t *old = (uint64_t *)r->r10;
            if (!vmm_user_ok(r->r10, 16)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            /* Tell the TRUTH for the limits we actually enforce. Reporting
             * RLIM_INFINITY for everything is fine for RLIMIT_STACK (glibc
             * just picks a default) and actively harmful for RLIMIT_NOFILE:
             * a program told its descriptor limit is unlimited asks for
             * fd 1023 -- Linux's conventional top -- and gets EBADF from a
             * 512-entry table. Claude Code does exactly that with
             * fcntl(0, F_DUPFD_CLOEXEC, 1023). (M1972) */
            uint64_t cur = ~0ull, mx = ~0ull;
            switch ((int)r->rsi) {
                case 7: cur = mx = (uint64_t)app_nfd_max();  break;   /* RLIMIT_NOFILE */
                case 6: cur = mx = (uint64_t)app_proc_max(); break;   /* RLIMIT_NPROC  */
                /* RLIMIT_STACK: glibc reports the main thread's stack size from
                 * this, and a runtime that checks its own stack bounds before
                 * recursing believes it. Claiming RLIM_INFINITY made glibc use
                 * its 8 MiB default while we actually supplied 512 KiB. (M1975) */
                case 3: cur = mx = (uint64_t)app_stack_bytes(); break;   /* RLIMIT_STACK */
                default: break;                                       /* the rest really are unbounded here */
            }
            old[0] = cur; old[1] = mx;
        }
        r->rax = 0;
        break;
    case LXS_getrandom_: {                  /* (buf, len, flags) */
        long len = (long)r->rsi;
        if (len < 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (len && !vmm_user_ok(r->rdi, (uint64_t)len)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        /* glibc uses this for malloc's canary and pointer mangling, so failing
         * it is not cosmetic -- it changes how glibc protects itself. */
        random_bytes((void *)r->rdi, (unsigned long)len);
        r->rax = (uint64_t)len;
        break;
    }
    case LXS_clock_gettime: {               /* (clk_id, struct timespec*) */
        if (!vmm_user_ok(r->rsi, 16)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        uint64_t ms = timer_ms();
        int64_t *ts = (int64_t *)r->rsi;
        /* CLOCK_REALTIME(0) wants wall time; everything else (MONOTONIC and
         * the CPU-time clocks) is satisfied from uptime, which is what our
         * millisecond timer actually measures. */
        /* CLOCK_REALTIME has to be COHERENT with itself (M1972).
         *
         * It used to take seconds from the RTC and nanoseconds from uptime --
         * two clocks that are not related. The RTC ticks over at some arbitrary
         * point inside the uptime second, so consecutive reads could go
         * BACKWARDS by up to a second, and code that measures a duration by
         * subtracting two of them gets a negative interval. Anchor the wall
         * clock to uptime once, then derive it: still the right absolute time,
         * and monotonic like the real thing. */
        if (a1 == 0) {
            ts[0] = lx_realtime_sec();
            ts[1] = (int64_t)((ms % 1000) * 1000000);
        }
        else         { ts[0] = (int64_t)(ms / 1000); ts[1] = (int64_t)((ms % 1000) * 1000000); }
        r->rax = 0;
        break;
    }
    case LXS_fstat: {                       /* (fd, struct stat*) */
        if (!vmm_user_ok(r->rsi, LXST_SIZE)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        uint8_t *st = (uint8_t *)r->rsi;
        for (int i = 0; i < LXST_SIZE; i++) st[i] = 0;
        /* stdio calls this on its own fds to decide buffering. Reporting a
         * CHARACTER DEVICE is both true (they are the console) and what makes
         * glibc pick line buffering instead of a full 4 KiB buffer -- with a
         * regular-file answer, output would not appear until an explicit
         * fflush or exit. */
        if (a1 >= 0 && a1 <= 2) {
            *(uint32_t *)(st + LXST_O_MODE) = LX_S_IFCHR | 0620;
            *(uint64_t *)(st + LXST_O_RDEV) = 0x0501;          /* a tty-ish rdev */
            *(uint64_t *)(st + LXST_O_NLINK) = 1;
            *(int64_t  *)(st + LXST_O_BLKSIZE) = 1024;
            r->rax = 0;
        } else {
            /* A REAL fd. opendir() fstat()s the fd it just opened to confirm it
             * is a directory before it will call getdents64 -- so returning
             * EBADF here made every opendir() fail silently, with the directory
             * fd already successfully created. The fd table remembers each
             * FILE fd's path, so stat that. */
            const char *fp = app_fd_path((int)a1);
            struct statx sx;
            if (!fp) {
                /* A non-FILE fd -- a pipe, socket, eventfd and so on. Report a
                 * FIFO rather than EBADF: stdio calls fstat() on its own fds to
                 * pick a buffering mode, and an error there leaves it guessing.
                 * S_IFIFO is also the truthful answer for the pipe case, which
                 * is the one a shell pipeline depends on. */
                if (!app_fd_is_open((int)a1)) { r->rax = (uint64_t)-(long)LX_EBADF; break; }
                /* EXCEPT A MEMFD, which is a REGULAR FILE -- an unlinked tmpfs
                 * one -- and every Wayland client depends on that being said.
                 * glibc's posix_fallocate fstat()s first and returns ESPIPE for
                 * a FIFO without attempting anything, so the shared-memory pool
                 * libwayland-cursor sizes that way was never sized at all, the
                 * mmap after it failed, and GDK reported the entire chain as
                 * one warning: "Failed to load cursor theme Adwaita". (M2000) */
                long mfsz = app_memfd_size((int)a1);
                if (mfsz >= 0) {
                    *(uint32_t *)(st + LXST_O_MODE)    = LX_S_IFREG | 0600u;
                    *(uint64_t *)(st + LXST_O_NLINK)   = 1;
                    *(int64_t  *)(st + LXST_O_SIZE)    = (int64_t)mfsz;
                    *(int64_t  *)(st + LXST_O_BLKSIZE) = 4096;
                    *(int64_t  *)(st + LXST_O_BLOCKS)  = (mfsz + 511) / 512;
                    *(uint64_t *)(st + LXST_O_INO)     = 0x2000ull + (uint64_t)a1;
                    *(uint64_t *)(st + LXST_O_DEV)     = LX_FAKE_DEV;
                    r->rax = 0;
                    break;
                }
                *(uint32_t *)(st + LXST_O_MODE)    = 0010000u | 0600u;   /* S_IFIFO */
                *(uint64_t *)(st + LXST_O_NLINK)   = 1;
                *(int64_t  *)(st + LXST_O_BLKSIZE) = 4096;
                /* Per-fd, so two different pipes are not reported as the
                 * same file. The 0x1000 bias keeps these clear of the
                 * path-hash inodes vfs_stat hands out for real files. */
                *(uint64_t *)(st + LXST_O_INO)     = 0x1000ull + (uint64_t)a1;
                *(uint64_t *)(st + LXST_O_DEV)     = LX_FAKE_DEV;
                r->rax = 0;
                break;
            }
            if (vfs_stat(fp, &sx) != 0) { r->rax = (uint64_t)-(long)LX_EBADF; break; }
            int isdir = (sx.stx_mode & 0170000u) == 0040000u;
            /* The REAL mode when the filesystem reported one -- ext2 does. An
             * executable bit that is not reported is an executable that cannot be
             * run, and a mode of 0644 on every file makes chmod look broken.
             * (M1999) */
            *(uint32_t *)(st + LXST_O_MODE)    = (sx.stx_mode & 07777u)
                                                 ? sx.stx_mode
                                                 : (isdir ? (0040000u | 0755u) : (LX_S_IFREG | 0644u));
            /* The REAL link count, not a constant 1 (M1998). A directory
             * always has at least two links ("." and its entry in its parent);
             * find(1) subtracts 2 from st_nlink to decide how many
             * subdirectories are left to visit and walks a negative number of
             * them. A hardlinked file reported 1 too, so nothing could tell
             * that two names were the same file. */
            *(uint64_t *)(st + LXST_O_NLINK)   = sx.stx_nlink ? sx.stx_nlink : (isdir ? 2u : 1u);
            *(int64_t  *)(st + LXST_O_ATIME)   = (int64_t)sx.stx_mtime;
            *(int64_t  *)(st + LXST_O_MTIME)   = (int64_t)sx.stx_mtime;
            *(int64_t  *)(st + LXST_O_CTIME)   = (int64_t)sx.stx_mtime;
            *(int64_t  *)(st + LXST_O_SIZE)    = (int64_t)sx.stx_size;
            *(int64_t  *)(st + LXST_O_BLKSIZE) = 4096;
            *(int64_t  *)(st + LXST_O_BLOCKS)  = (int64_t)((sx.stx_size + 511) / 512);
            /* A REAL inode, not a constant. ld.so decides "is this object
             * already loaded?" by comparing (st_dev, st_ino) -- reporting 1
             * for everything made it map libbfd and then skip libz, libzstd
             * and libc as duplicates of it, and the only symptom was
             * `undefined symbol: free, version GLIBC_2.2.5`. (M1955) */
            *(uint64_t *)(st + LXST_O_INO)     = sx.stx_ino;
            *(uint64_t *)(st + LXST_O_DEV)     = LX_FAKE_DEV;
            r->rax = 0;
        }
        break;
    }
    case LXS_readlinkat:
    case LXS_readlink: {
        /* readlink answers three different questions and we used to answer one.
         *
         * 1. /proc/self/exe (M1970). A Node/Bun single-executable application
         *    is runtime and JS in one image and finds its own embedded payload
         *    by reading this. With no answer Claude Code called abort() during
         *    startup, printing nothing.
         *
         * 2. /proc/self/cwd and /proc/self/fd/<n> (M1998). THIS IS HOW ZIG --
         *    and therefore Bun, and therefore Claude Code -- resolves a path.
         *    It does not call realpath(3): it opens the path O_PATH and reads
         *    back the magic link for the descriptor. Both returned ENOENT, so
         *    Claude Code decided its own working directory did not exist:
         *
         *        Error: Can't access working directory /: Path "/" does not exist
         *
         *    Every glibc route to the same question worked, which is why a
         *    glibc probe passed while the real program failed -- see
         *    tools/lx/lxcwd.c, which now asks BOTH ways.
         *
         * 3. A REAL SYMLINK on the filesystem. ext2 has had symlinks since
         *    M1233 and vfs_readlink since then, and this entry point never
         *    called it -- so every symlink in the compat root read as ENOENT.
         *
         * Paths are translated back OUT of the compat root before they are
         * returned: the process believes it is /usr/bin/claude, not
         * /disk2/usr/bin/claude. */
        uint64_t up  = (r->rax == LXS_readlinkat) ? r->rsi : r->rdi;
        uint64_t ub  = (r->rax == LXS_readlinkat) ? r->rdx : r->rsi;
        uint64_t usz = (r->rax == LXS_readlinkat) ? r->r10 : r->rdx;
        const char *upath = (const char *)up;
        if (!upath || !vmm_user_ok(up, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }

        const char *vis = 0;                 /* the answer, in the process's own view */
        char lbuf[VFS_PATH_MAX];             /* ...when it has to be read off disk */

        /* /proc/<self|pid>/... -- only "self" and the caller's own pid are
         * interesting here, and both name the calling process. */
        const char *pp = lx_proc_self_tail(upath);
        if (pp) {
            if (str_eq_lx(pp, "exe"))      vis = app_exe_str(app_current());
            else if (str_eq_lx(pp, "cwd")) vis = app_cwd_str(app_current());
            else if (str_eq_lx(pp, "root")) vis = "/";
            else if (pp[0] == 'f' && pp[1] == 'd' && pp[2] == '/') {
                int fd = 0, k = 3, any = 0;
                while (pp[k] >= '0' && pp[k] <= '9') { fd = fd * 10 + (pp[k] - '0'); k++; any = 1; }
                if (any && !pp[k]) vis = app_fd_path(fd);
            }
            if (!vis) { r->rax = (uint64_t)-(long)LX_ENOENT; break; }
        } else {
            /* A real symlink. */
            const char *xp = lx_xlate(upath, lbuf, (int)sizeof lbuf);
            char tgt[VFS_PATH_MAX];
            long tn = vfs_readlink(xp, tgt, sizeof tgt - 1);
            if (tn < 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
            if (tn > (long)sizeof tgt - 1) tn = (long)sizeof tgt - 1;
            tgt[tn] = 0;
            for (long k = 0; k <= tn; k++) lbuf[k] = tgt[k];
            vis = lbuf;
        }
        if (!vis || !vis[0]) { r->rax = (uint64_t)-(long)LX_ENOENT; break; }
        /* Strip LX_ROOT if it is there. "/disk2" alone becomes "/". */
        int rl = 0; while (LX_ROOT[rl]) rl++;
        int match = 1; for (int k = 0; k < rl; k++) if (vis[k] != LX_ROOT[k]) { match = 0; break; }
        if (match && vis[rl] == '/')     vis = vis + rl;
        else if (match && vis[rl] == 0)  vis = "/";
        long vn = 0; while (vis[vn]) vn++;
        if ((long)usz < vn) vn = (long)usz;          /* readlink TRUNCATES, it does not NUL-terminate */
        if (vn < 0 || !vmm_user_ok(ub, (uint64_t)vn)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        for (long k = 0; k < vn; k++) ((char *)ub)[k] = vis[k];
        r->rax = (uint64_t)vn;
        break;
    }
    case LXS_sigaltstack_:
        /* (ss, old_ss). An alternate signal stack only matters for delivering a
         * signal ON it -- most often SIGSEGV for stack-overflow recovery. We
         * deliver signals on the normal stack, so there is nothing to install;
         * refusing, though, is fatal to a runtime that treats the failure as
         * "this kernel is broken". Report "no alternate stack installed"
         * (ss_flags = SS_DISABLE) if asked for the old one. */
        if (r->rsi && vmm_user_ok(r->rsi, 24)) {
            uint8_t *o = (uint8_t *)r->rsi;
            for (int i = 0; i < 24; i++) o[i] = 0;
            *(int32_t *)(o + 8) = 2;        /* SS_DISABLE */
        }
        r->rax = 0;
        break;
    case LXS_close_range_: {                /* (first, last, flags) */
        long crc = app_close_range((unsigned)a1, (unsigned)r->rsi, (int)r->rdx);
        r->rax = (uint64_t)(crc == 0 ? 0 : -(long)LX_EINVAL);
        break;
    }
    case LXS_open_:                         /* (path, flags, mode) -- openat's arguments shifted one LEFT */
    case LXS_openat_: {                     /* (dirfd, path, flags, mode) */
        /* open() predates openat() and is still emitted by plenty of real code;
         * ENOSYS here made Claude Code abort during startup. Normalise it into
         * the openat path by shifting the register reads rather than
         * duplicating the body -- the two differ only in the leading dirfd,
         * which we ignore anyway (everything resolves against the process cwd). */
        if (r->rax == LXS_open_) {
            uint64_t p_ = r->rdi, f_ = r->rsi;   /* read BOTH before overwriting either */
            r->rsi = p_; r->rdx = f_;
        }
        const char *upath = (const char *)r->rsi;
        if (!upath || !vmm_user_ok(r->rsi, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate_at((long)r->rdi, upath, xp, sizeof xp);   /* honour dirfd (M2032) */
        /* /dev/tty IS THE CONTROLLING TERMINAL (M2004), and we had no such
         * file at all. A TUI does not settle for stdin: Ink -- which is what
         * Claude Code draws with -- opens /dev/tty so it can read keys even
         * when stdin has been redirected, and a program that cannot open it
         * waits for input on a descriptor it never got. Hand back the same
         * console alias fd 0/1/2 are, which is exactly what /dev/tty means:
         * whatever terminal this process is attached to. */
        {
            const char *t = "/dev/tty";
            int k = 0; while (t[k] && upath[k] == t[k]) k++;
            if (!t[k] && !upath[k]) {
                int tfd = app_open_console_alias();
                r->rax = (tfd < 0) ? (uint64_t)-(long)LX_ENODEV : (uint64_t)tfd;
                break;
            }
        }
        /* /dev/shm/NAME is POSIX shared memory, and shm_open(3) IS this open.
         * Firefox's parent and content processes talk through one, and it
         * crashes on purpose when the open fails. (M2008) */
        {
            const char *t = "/dev/shm/";
            int k = 0; while (t[k] && upath[k] == t[k]) k++;
            if (!t[k] && upath[k]) {
                long sflags = (long)r->rdx;
                int sfd = app_shm_fd(upath + k, (sflags & LXO_CREAT) ? 1 : 0,
                                     (sflags & 0200 /*O_EXCL*/) ? 1 : 0);
                r->rax = (sfd < 0) ? (uint64_t)(long)sfd : (uint64_t)sfd;
                break;
            }
        }
        long lf = (long)r->rdx, nf = 0;
        if (lf & (LXO_WRONLY | LXO_RDWR)) nf |= O_WRONLY;   /* we have no separate RDWR */
        if (lf & LXO_CREAT)  nf |= O_CREAT;
        if (lf & LXO_TRUNC)  nf |= O_TRUNC;
        if (lf & LXO_APPEND) nf |= O_APPEND;
        int fd = app_open(path, (int)nf);
        if (fd >= 0) { r->rax = (uint64_t)fd; break; }
        /* WHY it failed matters. Reporting ENOENT for everything told `ld`
         * that an object file it had just been handed did not exist, when in
         * fact we were out of descriptors -- and EMFILE is a condition BFD
         * knows how to handle, by closing a cached file and retrying. The
         * result was a link that silently dropped the tail of its input and
         * blamed the source. A stat distinguishes the two without changing
         * app_open's contract. (M1962) */
        struct statx exs;
        int exists = (vfs_stat(path, &exs) == 0);
        if (exists) { r->rax = (uint64_t)-(long)LX_EMFILE; break; }
        /* Report the miss. A dynamic linker probes many paths that are MEANT
         * to be absent, but when something it actually needs is missing the
         * failure surfaces much later as a NULL deref inside ld.so -- this
         * line is the difference between "page fault at 0x8" and "libbfd is
         * not where you put it". (M1955) */
        kprintf("[linuxabi] openat(%s) -> ENOENT\n", path);
        r->rax = (uint64_t)-(long)LX_ENOENT;
        break;
    }
    case LXS_read_: {                       /* (fd, buf, count) */
        long n = (long)r->rdx;
        if (n < 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (n && !vmm_user_ok(r->rsi, (uint64_t)n)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        /* STDIN ON A PROCESS NOBODY IS TYPING AT IS AT END OF FILE (M1992).
         *
         * fd 0 untouched means the console keyboard. For a process the kernel
         * launched -- no terminal, no window -- nobody will ever type into it,
         * so a read there blocks forever. It is not a hypothetical: `claude -p`
         * checks whether its prompt was piped in before it uses the one on the
         * command line, and hung there for the full fifteen-minute budget with
         * zero page faults and no error. A process that DOES have a window
         * (launched with `linux` from a shell) still gets the keyboard. */
        if (a1 == 0 && !app_fd_is_open(0) && !app_out_to()) { r->rax = 0; break; }
        long got = app_fd_read((int)a1, (void *)r->rsi, (unsigned long)n);
        r->rax = (got < 0) ? (uint64_t)lx_fd_err(got) : (uint64_t)got;
        break;
    }
    case LXS_close_:
        /* CLOSING A SOCKET IS THE END OF A STORY (M2016). When an HTTPS client
         * gives up, the close is the only event it produces -- the ten seconds
         * before it are silent, which is exactly the interval you need to see.
         * Dump the ring here, under lxnettrace, so "timed out" comes with the
         * syscalls the program made while waiting instead of nothing at all. */
        if (g_net_trace && app_fd_type((int)a1) == 10) {
            kprintf("[nettrace] t=%lums pid %d CLOSES socket fd %ld -- what it did while waiting:\n",
                    (unsigned long)timer_ms(), app_current_pid(), a1);
            lx_trace_dump_last("that socket's last seconds", 48);
        }
        /* CLOSE CAN BLOCK, SO IT NEEDS THE TIMER (M2060). Closing a live TCP
         * socket flushes unacked data with a deadline measured in timer ticks,
         * and this dispatch runs with IF=0 -- so the deadline was unreachable
         * and close() never returned. The poll/epoll/nanosleep handlers above
         * already do exactly this for the same reason. */
        {
            int cl_sock = (app_fd_type((int)a1) == 10 || app_fd_type((int)a1) == 16 ||
                           app_fd_type((int)a1) == 12 || app_fd_type((int)a1) == 15);
            int cl_rc;
            if (cl_sock) { __asm__ volatile("sti"); cl_rc = app_fd_close((int)a1); __asm__ volatile("cli"); }
            else cl_rc = app_fd_close((int)a1);
            if (cl_rc == 0) { r->rax = 0; break; }
        }
        /* fd 0/1/2 are the console when they are not fd-table entries -- they
         * ARE open, so closing them succeeds; there is simply nothing to free.
         * Returning EBADF made coreutils' close_stdout report
         * "echo: write error: Bad file descriptor" AFTER printing correctly,
         * which then failed the make recipe that ran it. */
        r->rax = (a1 >= 0 && a1 <= 2) ? 0 : (uint64_t)-(long)LX_EBADF;
        break;
    case LXS_lseek_: {                      /* (fd, offset, whence) -- SET/CUR/END match */
        long off = app_lseek((int)a1, (long)r->rsi, (int)r->rdx);
        if (off >= 0) { r->rax = (uint64_t)off; break; }
        /* ESPIPE, not EINVAL, when the fd is simply not seekable. stdio probes
         * seekability with an lseek before its first read, and ESPIPE is the
         * documented "this is a pipe" answer it expects and shrugs off --
         * EINVAL reads as a real error and leaves the stream unusable, so
         * glibc never issued a single read() on a dup2'd pipe stdin and a
         * pipeline's reader silently saw nothing at all. */
        r->rax = (uint64_t)-(long)(app_fd_is_open((int)a1) ? LX_ESPIPE : LX_EBADF);
        break;
    }
    case LXS_stat_:
    case LXS_lstat_:
    case LXS_newfstatat: {                  /* (dirfd, path, statbuf, flags) */
        /* stat(2) and lstat(2) are the same call one argument to the left:
         * (path, statbuf) rather than (dirfd, path, statbuf, flags). glibc on
         * x86-64 still emits them, and a program that gets ENOSYS for stat
         * cannot look at a file at all -- Claude Code issued twelve in a row
         * before giving up. We have no symlinks to follow differently, so
         * lstat is the same answer. (M1992) */
        int by_path = (r->rax == LXS_stat_ || r->rax == LXS_lstat_);
        uint64_t upath_u = by_path ? r->rdi : r->rsi;
        uint64_t ubuf_u  = by_path ? r->rsi : r->rdx;
        const char *upath = (const char *)upath_u;
        if (!upath || !vmm_user_ok(upath_u, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate_at((long)r->rdi, upath, xp, sizeof xp);   /* dirfd (M2032) */
        if (!vmm_user_ok(ubuf_u, LXST_SIZE)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        r->rdx = ubuf_u;                    /* the writes below all go through rdx */
        struct statx sx;
        if (vfs_stat(path, &sx) != 0) {
            /* Name BOTH spellings. A stat that fails on a path the program
             * believes in is nearly always a TRANSLATION problem, and the
             * translated form is the only place it shows. (M1992) */
            if (g_lx_statfail < 400) {
                g_lx_statfail++;
                kprintf("[linuxabi] stat(\"%s\") -> \"%s\": no such path\n", upath, path);
            }
            r->rax = (uint64_t)-(long)LX_ENOENT; break;
        }
        uint8_t *st = (uint8_t *)r->rdx;
        for (int i = 0; i < LXST_SIZE; i++) st[i] = 0;
        int isdir = (sx.stx_mode & 0170000u) == 0040000u;
        /* The REAL mode when the filesystem reported one -- ext2 does. An
         * executable bit that is not reported is an executable that cannot be
         * run, and a mode of 0644 on every file makes chmod look broken.
         * (M1999) */
        *(uint32_t *)(st + LXST_O_MODE)    = (sx.stx_mode & 07777u)
                                             ? sx.stx_mode
                                             : (isdir ? (0040000u | 0755u) : (LX_S_IFREG | 0644u));
        *(uint64_t *)(st + LXST_O_NLINK)   = sx.stx_nlink ? sx.stx_nlink : (isdir ? 2u : 1u);   /* the real count -- see LXS_fstat (M1998) */
        *(int64_t  *)(st + LXST_O_ATIME)   = (int64_t)sx.stx_mtime;   /* real times -- see LXST_O_MTIME (M1999) */
        *(int64_t  *)(st + LXST_O_MTIME)   = (int64_t)sx.stx_mtime;
        *(int64_t  *)(st + LXST_O_CTIME)   = (int64_t)sx.stx_mtime;
        *(int64_t  *)(st + LXST_O_SIZE)    = (int64_t)sx.stx_size;
        *(int64_t  *)(st + LXST_O_BLKSIZE) = 4096;
        *(int64_t  *)(st + LXST_O_BLOCKS)  = (int64_t)((sx.stx_size + 511) / 512);  /* 512-byte units, as Linux defines it */
        *(uint64_t *)(st + LXST_O_INO)     = sx.stx_ino;   /* a real inode -- see LXS_fstat (M1955) */
        *(uint64_t *)(st + LXST_O_DEV)     = LX_FAKE_DEV;
        r->rax = 0;
        break;
    }
    case LXS_fsync_:
    case LXS_fdatasync_:
        /* Every write here is already through to the block layer, so there is
         * nothing queued to force out. Returning 0 is the truth; ENOSYS made a
         * program that checkpoints its own state file treat a completed write
         * as a failed one. (M1992) */
        r->rax = app_fd_is_open((int)a1) ? 0 : (uint64_t)-(long)LX_EBADF;
        break;
    case LXS_rename_: {                     /* (oldpath, newpath) */
        if (!vmm_user_ok(r->rdi, 1) || !vmm_user_ok(r->rsi, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char op[VFS_PATH_MAX], np[VFS_PATH_MAX];
        char ox[VFS_PATH_MAX], nx[VFS_PATH_MAX];
        const char *o = lx_xlate((const char *)r->rdi, ox, sizeof ox);
        const char *n = lx_xlate((const char *)r->rsi, nx, sizeof nx);
        int k = 0; while (o[k] && k < VFS_PATH_MAX - 1) { op[k] = o[k]; k++; } op[k] = 0;
        k = 0; while (n[k] && k < VFS_PATH_MAX - 1) { np[k] = n[k]; k++; } np[k] = 0;
        r->rax = (vfs_rename_path(op, np) == 0) ? 0 : (uint64_t)-(long)LX_ENOENT;
        break;
    }
    case LXS_getdents64: {                  /* (fd, dirp, count) */
        long cap = (long)r->rdx;
        if (cap <= 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (!vmm_user_ok(r->rsi, (uint64_t)cap)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        /* Our native app_getdents64 walks the CWD, not an fd, so it cannot
         * serve this. The fd table already remembers each FILE fd's path
         * (app_fd_path), so list THAT directory instead -- which is what the
         * caller actually opened. */
        const char *dp = app_fd_path((int)a1);
        if (!dp) { r->rax = (uint64_t)-(long)LX_EBADF; break; }
        /* 64 -> 1024, and from the HEAP rather than a shared static (M1962).
         *
         * A directory listing that stops at 64 entries is a silent wrong
         * answer, not an error: GNU make's $(wildcard kernel/*.c) saw only the
         * first 64 of OS-DEV's 136 kernel sources, so the build linked a
         * PARTIAL object list and came back as pages of "undefined reference
         * to kmalloc / pci_find / wav_parse" -- every one of them a file
         * alphabetically after the cut. Nothing in that error mentions
         * directories.
         *
         * Static was also wrong once two processes can list at once; a build
         * runs several. Per-call from the heap costs a kmalloc on a syscall
         * that already walks a filesystem. */
        /* A dirent is 264 bytes since M2062 (a 256-byte name, because every
         * listing used to truncate at 31 characters), so 1024 of them is a
         * 270 KB allocation on a syscall a directory walker makes in a loop.
         * The full count is still needed -- this re-lists on every call and
         * indexes by position, so a short buffer would drop entries the next
         * call has to find. Fall back to 256 rather than fail the readdir
         * outright when the heap cannot spare it; a truncated listing is
         * reported below, which is more than a lost directory would be. */
        int ecap = 1024;                    /* NB: `cap` is already the user buffer size */
        vfs_dirent *ents = kmalloc((unsigned long)ecap * sizeof *ents);
        if (!ents) { ecap = 256; ents = kmalloc((unsigned long)ecap * sizeof *ents); }
        if (!ents) { r->rax = (uint64_t)-(long)LX_ENOMEM; break; }
        int n = vfs_list_path(dp, ents, ecap);
        if (n < 0) { kfree(ents); r->rax = (uint64_t)-(long)LX_ENOTDIR; break; }
        if (n == ecap)
            kprintf("[linuxabi] getdents64(%s): at least %d entries -- listing TRUNCATED\n", dp, ecap);
        /* The offset is carried in the fd's own cursor, so a second call
         * returns 0 and readdir() terminates instead of looping forever. */
        long start = app_lseek((int)a1, 0, 1 /*SEEK_CUR*/);
        if (start < 0) start = 0;
        uint8_t *out = (uint8_t *)r->rsi;
        long used = 0; int emitted = 0;
        for (int i = (int)start; i < n; i++) {
            int nl = 0; while (ents[i].name[nl]) nl++;
            long rec = (19 + nl + 1 + 7) & ~7L;        /* dirent64 header is 19 bytes, 8-byte aligned */
            if (used + rec > cap) break;
            uint8_t *e = out + used;
            *(uint64_t *)(e + 0)  = (uint64_t)(i + 2);            /* d_ino (nonzero) */
            *(int64_t  *)(e + 8)  = (int64_t)(i + 1);             /* d_off = next index */
            *(uint16_t *)(e + 16) = (uint16_t)rec;                /* d_reclen */
            /* DT_UNKNOWN: vfs_dirent carries no type field, and guessing wrong
             * is worse than admitting it -- DT_UNKNOWN is explicitly legal and
             * makes readdir() fall back to stat() when the caller needs a type. */
            e[18] = 0 /*DT_UNKNOWN*/;
            for (int k = 0; k < nl; k++) e[19 + k] = (uint8_t)ents[i].name[k];
            e[19 + nl] = 0;
            used += rec; emitted++;
        }
        app_lseek((int)a1, start + emitted, 0 /*SEEK_SET*/);
        kfree(ents);
        r->rax = (uint64_t)used;            /* 0 = end of directory */
        break;
    }
    case LXS_clone_:
        /* glibc's fork() does NOT call fork(57) -- it calls clone(56). Linux
         * clone is (flags, stack, ptid, ctid, tls); a NULL child stack plus no
         * CLONE_VM is exactly fork semantics, which is the only shape served
         * here. A thread clone (CLONE_VM with a real stack) needs the flags
         * plumbing our native app_clone lacks, so it is refused rather than
         * quietly turned into a process -- silently forking where a caller
         * expected a shared address space would corrupt it. */
        if (!(r->rdi & LX_CLONE_VM) && r->rsi == 0) { r->rax = (uint64_t)app_fork(r); break; }
        /* A REAL THREAD: CLONE_THREAD means share the address space, and the
         * caller genuinely wants that -- this is pthread_create. (M1959) */
        if ((r->rdi & LX_CLONE_THREAD) && r->rsi) {
            long tid = app_clone_linux(r, (unsigned long)r->rdi, r->rsi, r->rdx, r->r10, r->r8);
            r->rax = (tid < 0) ? (uint64_t)-(long)LX_EAGAIN : (uint64_t)tid;
            break;
        }
        /* CLONE_VM|CLONE_VFORK WITHOUT CLONE_THREAD is posix_spawn, which is a
         * process, not a thread -- it execs immediately. Served by a COW fork
         * with the child's rsp overridden; see app_fork_at for why sharing the
         * address space for real would be worse here. (M1958) */
        if (r->rsi) {
            /* CLONE_VM|CLONE_VFORK is posix_spawn, and it means what it says:
             * share the address space and suspend me until the child execs.
             * Serving it with a copy-on-write fork made the child's exec-failure
             * report land in memory nobody read. (M2006) */
            if (r->rdi & LX_CLONE_VM) { r->rax = (uint64_t)app_vfork_at(r, r->rsi); break; }
            r->rax = (uint64_t)app_fork_at(r, r->rsi); break;
        }
        r->rax = (uint64_t)-(long)LX_ENOSYS;
        break;
    case LXS_clone3_: {                     /* (struct clone_args *, size) */
        /* glibc tries clone3 first and falls back to clone(2) on ENOSYS, so
         * this is optional -- but the fallback then hits the CLONE_VM case
         * above anyway, and serving clone3 directly keeps the flags in one
         * place. Layout: flags, pidfd, child_tid, parent_tid, exit_signal,
         * stack, stack_size, tls -- all __aligned_u64.
         * NOTE stack is the LOW end here and the stack pointer is
         * stack+stack_size; clone(2) passes the top directly. Getting that
         * backwards puts the child's rsp below its own stack. */
        if ((long)r->rsi < 64 || !vmm_user_ok(r->rdi, 64)) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        const uint64_t *ca = (const uint64_t *)r->rdi;
        uint64_t cflags = ca[0], cstack = ca[5], cssize = ca[6];
        if (!(cflags & LX_CLONE_VM) && !cstack) { r->rax = (uint64_t)app_fork(r); break; }
        if ((cflags & LX_CLONE_THREAD) && cstack) {
            long tid = app_clone_linux(r, (unsigned long)cflags, cstack + cssize,
                                       ca[3] /*parent_tid*/, ca[2] /*child_tid*/, ca[7] /*tls*/);
            r->rax = (tid < 0) ? (uint64_t)-(long)LX_EAGAIN : (uint64_t)tid;
            break;
        }
        if (cstack) {
            if (cflags & LX_CLONE_VM) { r->rax = (uint64_t)app_vfork_at(r, cstack + cssize); break; }
            r->rax = (uint64_t)app_fork_at(r, cstack + cssize); break;
        }
        r->rax = (uint64_t)-(long)LX_ENOSYS;
        break;
    }
    case LXS_getcwd_: {                     /* (buf, size) -> the LENGTH incl. NUL, and fills buf */
        long cap = (long)r->rsi;
        if (cap <= 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (!vmm_user_ok(r->rdi, (uint64_t)cap)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char cw[VFS_PATH_MAX];
        long n = app_getcwd(cw, sizeof cw);
        if (n < 0) { cw[0] = '/'; cw[1] = 0; n = 1; }
        /* Strip the /disk2 mount prefix: inside a Linux process that volume IS
         * the root, exactly as lx_xlate adds it on the way in. A cwd of
         * "/disk2/x" would make every relative path resolve to /disk2/disk2/x. */
        const char *cp = cw;
        { const char *pre = LX_ROOT; int k = 0;
          while (pre[k] && cw[k] == pre[k]) k++;
          if (!pre[k]) { cp = (cw[k] == '/') ? cw + k : "/"; } }
        long len = 0; while (cp[len]) len++;
        if (len + 1 > cap) { r->rax = (uint64_t)-(long)LX_ERANGE; break; }
        char *out = (char *)r->rdi;
        for (long i = 0; i <= len; i++) out[i] = cp[i];
        r->rax = (uint64_t)(len + 1);       /* Linux returns the length INCLUDING the NUL */
        break;
    }
    case LXS_sysinfo_: {                    /* (struct sysinfo *) */
        /* 112 bytes of longs. cc1 reads it to size its garbage-collector
         * heuristics; zeros would make it think there is no memory at all, so
         * report the real totals from the physical allocator. */
        if (!vmm_user_ok(r->rdi, 112)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        uint8_t *si = (uint8_t *)r->rdi;
        for (int i = 0; i < 112; i++) si[i] = 0;
        /* FIELD OFFSETS (fixed M1971). These were wrong by one slot and the
         * call still returned 0 with a buffer full of plausible numbers --
         * exactly the failure mode of the statx layout (M1967).
         *
         *    0 uptime(s64)   8 loads[3](u64)  32 totalram   40 freeram
         *   48 sharedram    56 bufferram      64 totalswap  72 freeswap
         *   80 procs(u16)   82 pad(u16)       88 totalhigh  96 freehigh
         *  104 mem_unit(u32)                                size 112
         *
         * totalram had been written into loads[2], freeram into totalram, and
         * procs into totalhigh -- so a caller read the FREE figure as the
         * total, saw freeram as 0 and procs as 0. A runtime sizes its heap
         * from these. */
        *(int64_t  *)(si + 0)   = (int64_t)(timer_ms() / 1000);   /* uptime   */
        *(uint64_t *)(si + 32)  = pmm_total_bytes();              /* totalram */
        *(uint64_t *)(si + 40)  = pmm_free_bytes();               /* freeram  */
        *(uint16_t *)(si + 80)  = 1;                               /* procs: we have no cheap live count, and 0 is worse than an understatement */
        *(uint32_t *)(si + 104) = 1;                              /* mem_unit */
        r->rax = 0;
        break;
    }
    case LXS_gettimeofday_: {               /* (struct timeval *, struct timezone *) */
        if (r->rdi) {
            if (!vmm_user_ok(r->rdi, 16)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            int64_t *tv = (int64_t *)r->rdi;
            uint64_t ms = timer_ms();
            tv[0] = lx_realtime_sec();
            tv[1] = (int64_t)((ms % 1000) * 1000);   /* microseconds */
        }
        r->rax = 0;                          /* the timezone arg is obsolete; Linux ignores it too */
        break;
    }
    case LXS_umask_:
        /* We have no mode bits to mask. Report the conventional 022 as the
         * PREVIOUS mask and accept the new one: umask's return value is the
         * old mask, and an error here makes a shell think it cannot set one. */
        r->rax = 022;
        break;
    case LXS_chmod_:
    case LXS_fchmod_:
    case LXS_fchmodat_:
        /* Accepted and ignored. Everything runs as root on a volume with no
         * enforced permission bits, so refusing would fail `as`'s attempt to
         * chmod the object file it just wrote for no gain. The by-fd and
         * at-relative spellings get the same answer for the same reason --
         * Claude Code calls fchmod on its own state files and treated ENOSYS
         * as fatal. (M1992) */
        r->rax = 0;
        break;
    case LXS_fork_:
    case LXS_vfork_:
        /* vfork is served by a real fork. The difference (sharing the parent's
         * memory and suspending it) is an optimisation; a plain fork is always
         * a CORRECT implementation of it, and ours is already COW. */
        r->rax = (uint64_t)app_fork(r);
        break;
    case LXS_execve_: {                     /* (path, argv[], envp[]) */
        const char *path = (const char *)r->rdi;
        if (!path || !vmm_user_ok(r->rdi, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        /* Copy argv/envp into KERNEL memory before exec'ing. The vectors live
         * in the OLD address space, which app_execve_linux tears down partway
         * through -- reading them afterwards would be a use-after-free of an
         * entire address space. */
        /* NOT static. These were shared across every process, so two execves
         * in flight RACED on them: both children of a pipeline ended up with
         * the SAME argv, so both ran the writer applet -- one writing to the
         * pipe and one to the console -- and the reader never ran at all.
         * Stack-allocated is correct and safe: the syscall frame stays live
         * through app_exec (which switches CR3 but not the kernel stack), and
         * lx_spawn_stack copies the strings into the new user stack before it
         * returns. ~8 KiB against an app task's 256 KiB kernel stack. */
        /* 16 -> 64. The gcc DRIVER execs cc1 with about 25 arguments, so a
         * 16-entry cap silently dropped everything from -mtune onward --
         * including -ffreestanding. The only symptom was cc1 taking the HOSTED
         * branch of GCC's own stdint.h and failing on an #include_next, which
         * looks like a missing header and is nothing of the sort. Silent
         * truncation of an argument vector is not survivable; it is reported
         * now as well as being far larger. 64*256*2 = 32 KiB against an app
         * task's 256 KiB kernel stack. (M1960) */
/* 16 -> 64 -> 512, and off the kernel stack (M1962). A real link line names
 * every object file: OS-DEV's own kernel is ~75, and a 64-entry cap silently
 * handed `ld` a short command line, which came back as pages of "undefined
 * reference" -- an error about the CODE, not about the exec that mangled it.
 * At 512 entries these no longer fit on a 256 KiB kernel stack, so they come
 * from the heap; per-call, so still free of the cross-process race that made
 * them stack-allocated in the first place (M1952). */
#define LX_EXEC_ARGS 512
        char (*abuf)[256] = kmalloc(LX_EXEC_ARGS * 256);
        char (*ebuf)[256] = kmalloc(LX_EXEC_ARGS * 256);
        const char **av = kmalloc((LX_EXEC_ARGS + 1) * sizeof *av);
        const char **ev = kmalloc((LX_EXEC_ARGS + 1) * sizeof *ev);
        if (!abuf || !ebuf || !av || !ev) {
            if (abuf) kfree(abuf); if (ebuf) kfree(ebuf);
            if (av) kfree(av); if (ev) kfree(ev);
            r->rax = (uint64_t)-(long)LX_ENOMEM; break;
        }
        int na = 0, ne = 0;
        const char *const *uav = (const char *const *)r->rsi;
        const char *const *uev = (const char *const *)r->rdx;
        if (uav && vmm_user_ok(r->rsi, sizeof(char *))) {
            for (; na < LX_EXEC_ARGS && uav[na]; na++) {
                const char *sp = uav[na]; int k = 0;
                if (!vmm_user_ok((uint64_t)sp, 1)) break;
                while (sp[k] && k < 255) { abuf[na][k] = sp[k]; k++; }
                abuf[na][k] = 0; av[na] = abuf[na];
            }
            if (na == LX_EXEC_ARGS && uav[na])
                kprintf("[linuxabi] execve(%s): argv TRUNCATED at %d -- the program will see a short command line\n",
                        path, LX_EXEC_ARGS);
        }
        av[na] = 0;
        if (uev && vmm_user_ok(r->rdx, sizeof(char *))) {
            for (; ne < LX_EXEC_ARGS && uev[ne]; ne++) {
                const char *sp = uev[ne]; int k = 0;
                if (!vmm_user_ok((uint64_t)sp, 1)) break;
                while (sp[k] && k < 255) { ebuf[ne][k] = sp[k]; k++; }
                ebuf[ne][k] = 0; ev[ne] = ebuf[ne];
            }
            if (ne == LX_EXEC_ARGS && uev[ne])
                kprintf("[linuxabi] execve(%s): envp TRUNCATED at %d\n", path, LX_EXEC_ARGS);
        }
        ev[ne] = 0;
        char pbuf[VFS_PATH_MAX];
        { char t[VFS_PATH_MAX]; const char *xp = lx_xlate(path, t, sizeof t);
          int k = 0; while (xp[k] && k < (int)sizeof pbuf - 1) { pbuf[k] = xp[k]; k++; } pbuf[k] = 0; }
        /* COPY argv[0] BEFORE THE FREES (M2061).
         *
         * The failure diagnostic below printed `av[0]` with %s -- and `av` and
         * the `abuf` its entries point into are kfree'd two lines above it. So
         * the one line added to EXPLAIN a failed execve dereferenced freed
         * kernel heap, read the allocator's 0xde poison, and took a General
         * Protection Fault inside kprintf:
         *
         *   *** KERNEL PANIC: CPU EXCEPTION ***
         *     General Protection Fault ... r15=dededededededede
         *     [0] kvprintf+0x2b9  [1] kprintf+0x40
         *     [2] linux_syscall_dispatch+0x3547
         *
         * That is `make check`'s only red: gcc cannot find cc1 (a real and
         * separate problem -- exec'd as /usr/bin/gcc, its relative prefix
         * resolves to /libexec/gcc/... where nothing is staged), falls back to
         * /bin/cc1, and the ENOENT report then kills the machine. A recoverable
         * "command not found" became a dead kernel, and the log stopped
         * mid-format at `argv0="` -- which is exactly where the bad pointer was
         * dereferenced, and the only clue that the message itself was the bug.
         *
         * A diagnostic that CRASHES is worse than none, for the same reason
         * M2003's ring-slot race made a diagnostic that LIES worse than none. */
        char a0buf[128];
        { const char *a0 = (na > 0 && av[0]) ? av[0] : "<none>";
          int k = 0; while (a0[k] && k < (int)sizeof a0buf - 1) { a0buf[k] = a0[k]; k++; } a0buf[k] = 0; }
        long xrc = app_execve_linux(r, pbuf, av, ev);
        /* Safe on both paths: lx_spawn_stack has already copied the strings
         * into the NEW user stack by the time app_exec returns. */
        kfree(abuf); kfree(ebuf); kfree(av); kfree(ev);
        if (xrc < 0) {
            /* SAY WHAT IT COULD NOT EXEC (M2030). A failed execve is reported
             * to the parent as a child that exited 127, and 127 is the shell's
             * "command not found" -- so the one fact that would explain it,
             * the path, was the one thing never written down. Six children in a
             * row died this way and the log named none of them. */
            kprintf("[linuxabi] execve(\"%s\") -> ENOENT (raw=\"%s\" ptr=%lx readable=%d argv0=\"%s\" na=%d) (child exits 127)\n",
                    pbuf, (path && vmm_user_ok(r->rdi, 1)) ? path : "<unreadable>",
                    (unsigned long)r->rdi, (path && vmm_user_ok(r->rdi, 1)) ? 1 : 0,
                    a0buf, na);
            r->rax = (uint64_t)-(long)LX_ENOENT;   /* only reached on failure */
        }
        break;
    }
    case LXS_wait4_: {                      /* (pid, status*, options, rusage*) */
        int st = 0;
        /* The OPTIONS argument was being discarded (M2025) -- the same
         * granted-in-name-only shape as pipe2's flags (M2009), socketpair's
         * (M2012) and eventfd2's (M2017). WNOHANG means "look, do not block",
         * and an event loop that polls its children with it was instead parked
         * forever on the first call. */
        long got = app_wait4((int)a1, &st, ((int)a3 & LX_WNOHANG) != 0);
        if (got < 0) { r->rax = (uint64_t)-(long)LX_ECHILD; break; }
        if (got == 0) { r->rax = 0; break; }   /* WNOHANG: children exist, none ready */
        if (r->rsi) {
            if (!vmm_user_ok(r->rsi, 4)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            /* Linux packs the exit code into bits 8-15 and leaves the low byte
             * for the terminating signal, which is what WEXITSTATUS/WIFEXITED
             * decode. Handing back the raw code would make WIFEXITED false and
             * WEXITSTATUS read as 0 -- a silently wrong status, not an error. */
            *(int *)r->rsi = (st & 0xFF) << 8;
        }
        r->rax = (uint64_t)got;
        break;
    }
    case LXS_pipe_:
    case LXS_pipe2_: {                      /* (int fds[2] [, flags]) */
        if (!vmm_user_ok(r->rdi, 8)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        int fds[2];
        /* pipe2's FLAGS were being discarded (M2009). O_CLOEXEC and
         * O_NONBLOCK both arrive here and both were dropped, so
         * pipe2(fds, O_NONBLOCK) handed back a pipe that blocks -- which is
         * the worst possible answer, because the caller now believes it can
         * read the pipe dry. That is exactly how Firefox's main thread
         * stopped: its self-pipe drain loop asked for a non-blocking pipe,
         * got a blocking one, and never came back out of the last read. */
        long pf = (r->rax == LXS_pipe2_) ? (long)r->rsi : 0;
        if (app_pipe2(fds, (pf & LXO_CLOEXEC) ? O_CLOEXEC : 0) < 0) { r->rax = (uint64_t)-(long)LX_EMFILE; break; }
        if (pf & LXO_NONBLOCK) { app_fd_set_nonblock(fds[0], 1); app_fd_set_nonblock(fds[1], 1); }
        ((int *)r->rdi)[0] = fds[0]; ((int *)r->rdi)[1] = fds[1];
        r->rax = 0;
        break;
    }
    case LXS_dup_: {                        /* (fd) -> lowest free fd (M1962) */
        long nf = app_fcntl((int)a1, 0 /*F_DUPFD*/, 0);
        r->rax = (nf < 0) ? (uint64_t)-(long)LX_EBADF : (uint64_t)nf;
        break;
    }
    case LXS_dup2_: {
        int nf = app_dup2((int)a1, (int)r->rsi);
        r->rax = (nf < 0) ? (uint64_t)-(long)LX_EBADF : (uint64_t)nf;
        break;
    }
    case LXS_fcntl_: {                      /* (fd, cmd, arg) */
        /* F_DUPFD/F_GETFD/F_SETFD/F_DUPFD_CLOEXEC happen to be numbered
         * identically in our native fcntl, so they pass straight through.
         * F_GETFL/F_SETFL do not exist there: `as` calls F_GETFD on the object
         * file it just opened, and glibc's stdio calls F_GETFL to learn a
         * stream's access mode. */
        long cmd = (long)r->rsi, arg = (long)r->rdx;
        /* F_ADD_SEALS(1033) / F_GET_SEALS(1034). app_memfd_seal has existed
         * since M1212 and enforced F_SEAL_WRITE and F_SEAL_GROW; only the
         * Linux spelling was missing, so it answered EBADF. Every Wayland
         * client that passes a buffer to a compositor seals it first --
         * F_SEAL_SHRINK is how a compositor knows the pool it mapped cannot be
         * truncated out from under it, which is a real protection and not a
         * formality. libwayland ignores the return, but a kernel that cannot
         * be ASKED is a different thing from one that declines. (M2000) */
        if (cmd == 1033 || cmd == 1034) {
            long sl = app_memfd_seal((int)a1, cmd == 1033 ? (unsigned)arg : 0u);
            /* F_ADD_SEALS returns 0 on success; only F_GET_SEALS returns the
             * set. Returning the set from both would make a caller that checks
             * `!= 0` treat a successful seal as a failure. */
            r->rax = (sl < 0) ? (uint64_t)-(long)LX_EINVAL
                              : (cmd == 1034 ? (uint64_t)sl : 0ull);
            break;
        }
        if (cmd == 3) {                     /* F_GETFL */
            /* O_RDWR, plus O_NONBLOCK if it is actually set. We do not record
             * per-fd access modes, and claiming read-write is the permissive
             * answer -- an fd we handed out is usable, and stdio only uses this
             * to reject an impossible operation it was never going to attempt.
             * The O_NONBLOCK bit, though, must be TRUE: libuv does the
             * read-modify-write F_GETFL/F_SETFL dance and then trusts the
             * result. (M1965) */
            r->rax = 2 | (app_fd_nonblock((int)a1) ? 04000u : 0u);
            break;
        }
        if (cmd == 4) {                     /* F_SETFL */
            /* Was: accepted and DISCARDED. That is a lie the caller cannot
             * detect until its event loop blocks in a read it was promised
             * would return EAGAIN. Record it for real; on fd types that have
             * no notion of blocking it is simply unused. (M1965) */
            if (app_fd_set_nonblock((int)a1, (arg & 04000) ? 1 : 0) != 0) { r->rax = 0; break; }
            r->rax = 0;
            break;
        }
        long fr = app_fcntl((int)a1, (int)cmd, arg);
        r->rax = (fr < 0) ? (uint64_t)-(long)LX_EBADF : (uint64_t)fr;
        break;
    }
    case LXS_getrusage_: {                  /* (who, struct rusage*) */
        /* 144 bytes: ru_utime + ru_stime (two 16-byte timevals) then 14 longs.
         * `as` reads this to report assembly time with --statistics; zeros are
         * a truthful "we do not account this" rather than a failure, and an
         * error here makes it print nothing at all. */
        if (!vmm_user_ok(r->rsi, 144)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        uint8_t *ru = (uint8_t *)r->rsi;
        for (int i = 0; i < 144; i++) ru[i] = 0;
        uint64_t ms = timer_ms();
        *(int64_t *)(ru + 0) = (int64_t)(ms / 1000);            /* ru_utime.tv_sec  */
        *(int64_t *)(ru + 8) = (int64_t)((ms % 1000) * 1000);   /* ru_utime.tv_usec */
        r->rax = 0;
        break;
    }
    case LXS_time_:                         /* (time_t *tloc) */
        /* Returns the value AND stores it when tloc is non-NULL -- both, not
         * either. `as` stamps the object file's timestamp from this. */
        if (r->rdi) {
            if (!vmm_user_ok(r->rdi, 8)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
            *(int64_t *)r->rdi = lx_realtime_sec();
        }
        r->rax = (uint64_t)lx_realtime_sec();
        break;
    case LXS_getppid_:
        r->rax = (uint64_t)app_sys_getppid();
        break;
    case LXS_pread64_: {                    /* (fd, buf, count, offset) */
        long n = (long)r->rdx; uint64_t off = r->r10;
        if (n < 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (n && !vmm_user_ok(r->rsi, (uint64_t)n)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        /* ld.so reads a shared object's headers with pread rather than
         * seek+read, precisely so it does not disturb the fd's cursor -- so
         * this must NOT go through app_fd_read. */
        const char *fp = app_fd_path((int)a1);
        if (!fp) { r->rax = (uint64_t)-(long)LX_EBADF; break; }
        long got = vfs_pread(fp, (void *)r->rsi, (unsigned long)n, off);
        r->rax = (got < 0) ? (uint64_t)-(long)LX_EIO : (uint64_t)got;
        break;
    }
    case LXS_access_:
    case LXS_faccessat_: {                  /* (path, mode) / (dirfd, path, mode, flags) */
        uint64_t pa = (r->rax == LXS_access_) ? r->rdi : r->rsi;
        const char *up = (const char *)pa;
        if (!up || !vmm_user_ok(pa, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate(up, xp, sizeof xp);
        struct statx sx;
        /* Existence only. Everything runs as root here and there are no mode
         * bits on the boot volume, so reporting a permission failure would be
         * inventing one -- ld.so uses this to probe for library paths. */
        if (vfs_stat(path, &sx) == 0) r->rax = 0;
        else {
            if (g_lx_statfail < 400) {
                g_lx_statfail++;
                kprintf("[linuxabi] access(\"%s\") -> \"%s\": no such path\n", up, path);
            }
            r->rax = (uint64_t)-(long)LX_ENOENT;
        }
        break;
    }
    case LXS_exit:
        /* exit(2) ends ONE THREAD. Routing it to process exit killed every
         * sibling the moment a pthread returned -- but the MAIN thread calling
         * exit(2) really does end the process, or a program returning from
         * main would leave a husk nothing ever reaps. (M1959) */
        if (!app_is_main_thread()) {
            /* NAME THE THREAD THAT DIED (M2066). A per-process syscall
             * histogram showed Claude Code spawning three threads and losing
             * three, over and over: prctl(PR_SET_NAME), gettid,
             * sched_getaffinity, set_robust_list, getrandom -- and then
             * exit(2). Which POOL that is decides everything, and prctl has
             * already told us its name by this point. M2003 chased the same
             * signature to a missing getpriority; the name is what makes the
             * next one a lookup instead of a hunt. */
            extern int g_lx_syshist;
            if (g_lx_syshist)
                kprintf("[syshist] thread %d '%s' exited with %ld after %lu syscall(s)\n",
                        task_current_id(), task_name_of(task_self()), a1,
                        (unsigned long)lx_thread_calls());
            app_thread_exit(); break;
        }
        /* fall through */
    case LXS_exit_group:
        kprintf("[linuxabi] guest exited with status %ld\n", a1);
        /* A NON-ZERO EXIT IS A FAILURE WITH NO FAULT ADDRESS (M1992). The ring
         * already holds the history; a program that gives up cleanly is
         * exactly the case where there is otherwise nothing to look at, and
         * "it printed an error and exited 1" is not a place to start. */
        if (a1 != 0) lx_trace_dump_last("a non-zero exit", 20);
        /* app_sys_exit, NOT a bare task_exit(). It records the status, marks
         * the app dead AND RELEASES ITS FDS -- and that last part is what makes
         * a pipe signal EOF to the other end. Calling task_exit() directly left
         * the process's pipe write end open forever, so a reader blocked in
         * read() never saw EOF: the pipeline deadlocked with the writer already
         * finished, the reader stuck, and the parent stuck in wait4. Deferring
         * the close to app_reap is not enough either -- that runs on the window
         * manager's schedule, while POSIX requires the fds to close at EXIT. */
        app_sys_exit((int)a1);
        break;
    default:
        /* Log it. Implementing a Linux ABI by GUESSING which calls a libc makes
         * is hopeless; making the binary say so turns the whole thing into a
         * mechanical loop -- run it, read the numbers, implement, repeat.
         * Rate-limited so a libc that retries in a loop cannot bury the log. */
        lx_unknown_count++;
        if (lx_unknown_count <= 40)
            kprintf("[linuxabi] ENOSYS: unimplemented Linux syscall %lu "
                    "(args %lx %lx %lx)\n", (unsigned long)r->rax,
                    (unsigned long)r->rdi, (unsigned long)r->rsi, (unsigned long)r->rdx);
        r->rax = (uint64_t)-(long)LX_ENOSYS;
        break;
    }
    /* Patch the ring entry with what we actually answered. Recorded here rather
     * than at entry because the whole value of the record is the RESULT. */
    { struct lxring_ent *re = &g_lxring[ring_slot & (LXRING_N - 1)];
      if (re->seq == ring_slot) re->ret = r->rax;   /* still ours: see `seq` */ }
    /* EVERY SYSCALL THAT FAILED, EXCEPT THE ONES THAT FAIL BY DESIGN (M2070).
     *
     * A histogram says what a program is doing a lot of; it cannot show the
     * call it made ONCE and could not recover from. That is usually where a
     * startup stops -- and this whole campaign's dominant bug class is a
     * syscall that returns a plausible wrong answer, which by definition does
     * not appear as an error at all until something downstream gives up.
     *
     * ENOENT and EAGAIN are excluded because they are the normal vocabulary of
     * a runtime probing for config files and polling a non-blocking fd; they
     * would drown everything else by three orders of magnitude. EINTR likewise.
     * What is left -- EINVAL, ENOSYS, EBADF, EFAULT, EPERM, ENOTTY... -- is
     * short enough to read and is exactly the set worth reading. */
    { extern int g_lx_syshist;
      if (g_lx_syshist) {
        long rv = (long)r->rax;
        /* `r->rax` is the RETURN VALUE by now -- the number lives in the ring
         * entry we just patched. Reading rax for the name printed "?" for
         * every line, which is the instrument making the same mistake the code
         * it watches keeps making. (M2070) */
        unsigned long nr_ = g_lxring[ring_slot & (LXRING_N - 1)].seq == ring_slot
                          ? g_lxring[ring_slot & (LXRING_N - 1)].nr : 0;
        if (rv < 0 && rv > -4096) {
            int e = (int)-rv;
            if (e != LX_ENOENT && e != LX_EAGAIN && e != LX_EINTR) {
                static int shown;
                if (++shown <= 200)
                    kprintf("[syserr] pid %d t%d %s(%lx, %lx, %lx) = -%d\n",
                            app_current_pid(), task_current_id(),
                            lx_syscall_name(nr_), r->rdi, r->rsi, r->rdx, e);
                /* EBADF is the one errno where the ANSWER is about a
                 * descriptor, so say what that descriptor actually is: "not
                 * open" and "open, but this call does not handle its type"
                 * are completely different bugs and read identically as -9. */
                if (e == LX_EBADF && (long)r->rdi >= 0 && (long)r->rdi < 4096)
                    kprintf("[syserr]   ...fd %ld is type %d (open=%d)\n",
                            (long)r->rdi, app_fd_type((int)r->rdi), app_fd_is_open((int)r->rdi));
            }
        }
      }
    }
    /* AND DELIVER ANY SIGNAL THAT CAME DUE (M2063).
     *
     * The native syscall return (syscall.c) and the interrupt return
     * (interrupts.c) both do this; the LINUX entry never did. So a Linux
     * process could install a handler, raise the signal, and return from the
     * raising syscall straight past its own handler -- `raise(SIGUSR1)`
     * reported success and the handler did not run until some later timer
     * interrupt happened to catch the process in ring 3, which for a program
     * that checks immediately is never.
     *
     * AFTER the ring patch and after r->rax is final, because
     * app_deliver_pending snapshots the whole frame for sigreturn to restore --
     * both existing call sites carry the same note, and for the same reason. */
    app_deliver_pending(r);
}

/* ---- the System V initial process stack (M1939) --------------------------
 *
 * A Linux binary does not get its arguments in registers. It expects, at the
 * exact address RSP holds on entry:
 *
 *     [rsp]      argc
 *     [rsp+8]    argv[0..argc-1], then a NULL
 *                envp[0..], then a NULL
 *                auxv: (a_type, a_val) pairs, terminated by AT_NULL
 *                ...the string bytes those pointers refer to...
 *
 * Our own loader never built any of this -- app.c:1162 says so outright, and
 * passes a single 128-byte argument out of band via SYS_getarg instead. That
 * is fine for our apps and fatal for a real libc: musl reads the auxiliary
 * vector in __init_libc BEFORE main, and **AT_RANDOM is not optional** -- it
 * is where the stack-protector canary and malloc's pointer-mangling secret
 * come from. A missing AT_RANDOM is a NULL dereference before the program's
 * first instruction, which looks like "the binary just dies instantly".
 *
 * RSP must also be 16-byte aligned with argc AT [rsp]. Getting this wrong does
 * not fault immediately; it corrupts the first SSE spill, so the failure shows
 * up somewhere unrelated and much later.
 */
#define LX_AT_PHDR    3
#define LX_AT_PHENT   4
#define LX_AT_PHNUM   5
#define LX_AT_BASE    7
#define LX_AT_FLAGS   8
#define LX_AT_HWCAP  16
#define LX_AT_RANDOM 25
#define LX_AT_EXECFN 31

struct lx_stack_info {
    uint64_t phdr, entry, base;      /* runtime addresses */
    uint16_t phent, phnum;
};

/* Push `n` bytes to the stack, keeping it descending. Returns the new top. */
static uint64_t sp_push(uint64_t sp, const void *src, uint64_t n) {
    sp -= n;
    for (uint64_t i = 0; i < n; i++) ((uint8_t *)sp)[i] = ((const uint8_t *)src)[i];
    return sp;
}
static uint64_t sp_str(uint64_t sp, const char *s, uint64_t *out_addr) {
    uint64_t n = 0; while (s[n]) n++;
    sp = sp_push(sp, s, n + 1);
    *out_addr = sp;
    return sp;
}

/* Build the frame at the top of an already-mapped user stack. Must run with
 * the TARGET address space active. Returns the entry RSP, or 0 on overflow. */
uint64_t lx_build_stack(uint64_t stack_top, uint64_t stack_bottom,
                        const char *const *argv, const char *const *envp,
                        const struct lx_stack_info *si) {
    uint64_t sp = stack_top & ~(uint64_t)15;
    /* 64 -> 512 (M1962). "More than any real invocation" was wrong: a LINK
     * names every object file, and OS-DEV's own kernel is 146 of them. The
     * execve handler had already been raised to copy that many, but the stack
     * builder still stopped at 64 -- so `ld` was handed 57 objects plus its
     * own flags and reported "undefined reference to kmalloc" about the
     * sources it never saw. Three separate caps in one path, each silently
     * truncating; this was the last. 512 * 8 = 4 KiB per array on a 256 KiB
     * kernel stack. */
#define LX_STACK_ARGS 512
    uint64_t argp[LX_STACK_ARGS], envpp[LX_STACK_ARGS];
    int argc = 0, envc = 0;

    /* 1. strings first, at the very top, so the pointer arrays below can name
     *    them. A cap is required since these are fixed arrays -- but hitting
     *    it is REPORTED, because a short argv is a wrong answer that the
     *    program then blames on its own inputs. */
    for (; argv && argv[argc] && argc < LX_STACK_ARGS; argc++) { }
    for (; envp && envp[envc] && envc < LX_STACK_ARGS; envc++) { }
    if (argc == LX_STACK_ARGS && argv[argc])
        kprintf("[linuxabi] initial stack: argv TRUNCATED at %d\n", LX_STACK_ARGS);
    for (int i = argc - 1; i >= 0; i--) sp = sp_str(sp, argv[i], &argp[i]);
    for (int i = envc - 1; i >= 0; i--) sp = sp_str(sp, envp[i], &envpp[i]);

    uint64_t execfn = argc > 0 ? argp[0] : 0;      /* AT_EXECFN: argv[0] will do */

    /* 2. 16 bytes of AT_RANDOM seed. Not decorative: musl's canary and
     *    malloc secret are read straight out of here. */
    uint8_t rnd[16];
    for (int i = 0; i < 16; i++) rnd[i] = (uint8_t)(timer_ms() * 31u + i * 131u + 7u);
    uint64_t rnd_addr;
    sp = sp_push(sp, rnd, sizeof rnd);
    rnd_addr = sp;

    /* 3. Build the auxv into a local array FIRST, then size the reservation
     *    from what it actually contains. An earlier version hand-counted the
     *    pairs into an `n_aux` constant and got it wrong twice -- which writes
     *    past the reserved block and corrupts the strings just above it. This
     *    shape makes that class of mistake impossible rather than fixing one
     *    instance of it. */
    uint64_t aux[2 * 24]; int na = 0;
#define AUX(t, v) do { aux[na++] = (uint64_t)(t); aux[na++] = (uint64_t)(v); } while (0)
    /* AT_PHDR/PHENT/PHNUM let a static-PIE binary find its own program headers,
     * which it needs to locate PT_DYNAMIC (self-relocation) and PT_TLS (its
     * thread pointer). AT_BASE is the load bias. */
    AUX(LX_AT_PHDR,   si->phdr);
    AUX(LX_AT_PHENT,  si->phent);
    AUX(LX_AT_PHNUM,  si->phnum);
    AUX(LX_AT_BASE,   si->base);
    AUX(AT_ENTRY,     si->entry);
    AUX(AT_PAGESZ,    4096);
    AUX(LX_AT_RANDOM, rnd_addr);        /* NOT optional -- see the header comment */
    AUX(LX_AT_HWCAP,  0);
    AUX(AT_CLKTCK,    100);
    AUX(AT_UID,       0);
    AUX(AT_EUID,      0);
    AUX(AT_GID,       0);
    AUX(AT_EGID,      0);
    AUX(AT_SECURE,    0);
    AUX(LX_AT_FLAGS,  0);
    AUX(LX_AT_EXECFN, execfn);
    AUX(AT_NULL,      0);               /* terminator -- must be last */
#undef AUX

    /* Reserve the pointer block and align its BASE to 16, because that base is
     * the RSP the program starts with and argc must sit exactly there.
     * Aligning `sp` first and then subtracting would undo itself.
     *
     * A misaligned RSP does not fault: it corrupts the first SSE spill, so the
     * damage surfaces somewhere unrelated and much later. */
    uint64_t words = 1                             /* argc */
                   + (uint64_t)argc + 1            /* argv + NULL */
                   + (uint64_t)envc + 1            /* envp + NULL */
                   + (uint64_t)na;                 /* auxv, already counted in words */
    uint64_t need = words * 8;
    if (sp < stack_bottom + need + 16) return 0;   /* would run off the stack */
    uint64_t p = (sp - need) & ~(uint64_t)15;

    uint64_t *w = (uint64_t *)p;
    uint64_t k = 0;
    w[k++] = (uint64_t)argc;
    for (int i = 0; i < argc; i++) w[k++] = argp[i];
    w[k++] = 0;
    for (int i = 0; i < envc; i++) w[k++] = envpp[i];
    w[k++] = 0;
    for (int i = 0; i < na; i++) w[k++] = aux[i];
    if (k != words) {                              /* belt and braces: the two
                                                    * must agree by construction */
        kprintf("[linuxabi] BUG: stack words %lu != written %lu\n", words, k);
        return 0;
    }
    return p;
}

/* Parse the just-loaded image's program-header location and build the initial
 * stack for it. Keeps ELF field decoding out of app.c, which only knows it is
 * spawning "a Linux binary". Returns the entry RSP, or 0.
 *
 * AT_PHDR used to be computed as base + e_phoff, which is correct only when
 * the program headers fall inside a PT_LOAD that maps file offset 0 at vaddr 0.
 * That holds for every normal PIE -- and not for an ET_EXEC image, whose first
 * PT_LOAD is at a fixed vaddr (0x200000 for Claude Code) while e_phoff is still
 * 0x40. ld.so then went looking for an ELF header at address 0x40 and faulted,
 * with the segments correctly mapped the whole time. Resolve the headers
 * through the PT_LOAD that actually contains them, exactly as Linux's
 * fs/binfmt_elf.c does. (M1970) */
uint64_t lx_spawn_stack_dyn(const void *image, uint64_t base, uint64_t entry,
                            uint64_t interp_base,
                            uint64_t stack_top, uint64_t stack_bottom,
                            const char *const *argv, const char *const *envp) {
    const uint8_t *e = (const uint8_t *)image;
    uint64_t phoff   = *(const uint64_t *)(e + 32);   /* e_phoff */
    uint16_t phent   = *(const uint16_t *)(e + 54);   /* e_phentsize */
    uint16_t phnum   = *(const uint16_t *)(e + 56);   /* e_phnum */

    /* Find the PT_LOAD whose FILE range covers e_phoff; the headers' virtual
     * address is then p_vaddr + (e_phoff - p_offset). Falls back to phoff (the
     * old behaviour) if no segment claims them, which is what a PIE mapping
     * file offset 0 at vaddr 0 yields anyway. */
    uint64_t phdr_va = phoff;
    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *ph = e + phoff + (uint64_t)i * phent;
        if (*(const uint32_t *)(ph + 0) != 1) continue;            /* PT_LOAD */
        uint64_t p_off = *(const uint64_t *)(ph + 8);
        uint64_t p_va  = *(const uint64_t *)(ph + 16);
        uint64_t p_fsz = *(const uint64_t *)(ph + 32);
        if (phoff >= p_off && phoff < p_off + p_fsz) { phdr_va = p_va + (phoff - p_off); break; }
    }
    /* AT_BASE names the INTERPRETER's load bias when there is one -- that is
     * how ld.so finds itself to self-relocate. AT_PHDR and AT_ENTRY must still
     * describe the EXECUTABLE, because that is the program ld.so is being
     * asked to start. Getting these crossed makes the linker relocate itself
     * against the wrong bias. (M1954) */
    struct lx_stack_info si = {
        .phdr = base + phdr_va, .entry = entry,
        .base = interp_base ? interp_base : base,
        .phent = phent, .phnum = phnum,
    };
    return lx_build_stack(stack_top, stack_bottom, argv, envp, &si);
}

uint64_t lx_spawn_stack(const void *image, uint64_t base, uint64_t entry,
                        uint64_t stack_top, uint64_t stack_bottom,
                        const char *const *argv, const char *const *envp) {
    return lx_spawn_stack_dyn(image, base, entry, 0, stack_top, stack_bottom, argv, envp);
}
