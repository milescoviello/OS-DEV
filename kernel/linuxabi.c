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
#include "vfs.h"      /* app_sbrk/app_mmap/app_mprotect/app_munmap -- the native primitives these translate onto */
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
#define LXS_rt_sigaction  13
#define LXS_rt_sigprocmask 14
#define LXS_ioctl         16
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
#define LXS_clock_nanosleep_ 230
#define LXS_statx_       332
#define LXS_sched_getaffinity_ 204
#define LXS_sched_setparam_    142
#define LXS_sched_getparam_    143
#define LXS_sched_setscheduler_ 144
#define LXS_sched_getscheduler_ 145
#define LXS_clock_getres_ 229
#define LXS_epoll_create1_ 291
#define LXS_epoll_ctl_   233
#define LXS_epoll_wait_  232
#define LXS_epoll_pwait_ 281
#define LXS_eventfd2_    290
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
int g_lx_systrace;                        /* -append lxsystrace: log EVERY Linux syscall (very noisy; for finding where a program blocks) */

/* Translate a negative app_fd_* return into a Linux errno (M1965).
 *
 * Collapsing every failure to EBADF cost real debugging time: Node reported
 * "write EBADF" on a socket whose fd was perfectly valid, because the byte
 * path for that fd type did not exist. EBADF sends you looking at descriptor
 * bookkeeping; EPIPE/EAGAIN name what actually happened. */
static long lx_fd_err(long rc) {
    if (rc == APP_FD_EAGAIN) return -(long)LX_EAGAIN;
    if (rc == APP_FD_EPIPE)  return -(long)LX_EPIPE;
    return -(long)LX_EBADF;
}
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
        for (int i = 0; p[i] && n < max - 1; i++) out[n++] = p[i];
        out[n] = 0;
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
struct lxring_ent { uint32_t nr; uint64_t a1, a2, a3, ret; char path[56]; };
static struct lxring_ent g_lxring[LXRING_N];
static unsigned long g_lxring_i;
static struct lxring_ent *g_lxring_cur;

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
void lx_user_backtrace(struct registers *r) {
    kprintf("[linuxabi] user backtrace: rip=%lx rsp=%lx rbp=%lx\n", r->rip, r->rsp, r->rbp);
    uint64_t rbp = r->rbp, prev = 0;
    for (int f = 0; f < 16; f++) {
        if (rbp <= prev || (rbp & 7) || !vmm_user_ok(rbp, 16)) break;
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
        if (!vmm_user_ok(sp, 8)) break;
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

void lx_trace_dump_last(const char *why, unsigned long want) {
    unsigned long n = g_lxring_i < LXRING_N ? g_lxring_i : LXRING_N;
    if (want && n > want) n = want;
    kprintf("[linuxabi] last %lu syscalls before %s (oldest first):\n", n, why);
    for (unsigned long k = 0; k < n; k++) {
        struct lxring_ent *e = &g_lxring[(g_lxring_i - n + k) & (LXRING_N - 1)];
        /* The RETURN VALUE is the point. Arguments alone show what a program
         * asked for; only the result shows which answer it could not live
         * with, and a negative return here is a Linux errno. */
        if (e->path[0]) kprintf("    %3u(%lx, %lx, %lx) = %lx  \"%s\"\n", e->nr, e->a1, e->a2, e->a3, e->ret, e->path);
        else            kprintf("    %3u(%lx, %lx, %lx) = %lx\n", e->nr, e->a1, e->a2, e->a3, e->ret);
    }
}

void lx_trace_dump(const char *why) { lx_trace_dump_last(why, 0); }   /* 0 = the whole ring */

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
void linux_syscall_dispatch(struct registers *r) {
    lx_syscall_count++;
    /* Always record; print only on demand. The rate-limited trace below is for
     * finding a SPIN (the same call repeating), and deliberately samples one in
     * 4096 so a compiler does not drown the log -- but that makes it useless for
     * the opposite question, "what were the last things this process did before
     * it died?". A program that calls abort() on itself prints nothing and
     * leaves no fault address; without a history there is simply no evidence.
     * The ring costs one store per syscall and is dumped by lx_trace_dump on an
     * abnormal exit. (M1970) */
    {
        struct lxring_ent *re = &g_lxring[g_lxring_i & (LXRING_N - 1)];
        re->nr = (uint32_t)r->rax; re->a1 = r->rdi; re->a2 = r->rsi; re->a3 = r->rdx;
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
        g_lxring_cur = re;          /* patched with the result once the dispatch returns */
        g_lxring_i++;
    }
    if (g_lx_systrace && (lx_syscall_count & 0xFFF) == 0)
        kprintf("[sys] %ld(%lx,%lx,%lx)\n", (long)r->rax, r->rdi, r->rsi, r->rdx);
    long a1 = (long)r->rdi, a3 = (long)r->rdx;
    const char *p2 = (const char *)r->rsi;

    switch (r->rax) {
    case LXS_write: {                       /* (fd, buf, count) */
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
        console_write_n(p2, (unsigned long)a3);   /* lock once: no splicing (M1952) */
        r->rax = (uint64_t)a3;
        break;
    }
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
                console_write_n(b, n);                /* lock once: no splicing (M1952) */
                total += (long)n;
            }
        }
        r->rax = (uint64_t)total;
        break;
    }
    done: break;
    case LXS_getpid:
        r->rax = (uint64_t)task_current_id();
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
    case LXS_unlinkat_: {                   /* (dirfd, path, flags) */
        /* unlinkat shifts its arguments one right, exactly like faccessat. */
        uint64_t up = (r->rax == LXS_unlink_) ? r->rdi : r->rsi;
        const char *upath = (const char *)up;
        if (!upath || !vmm_user_ok(up, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate(upath, xp, sizeof xp);
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
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate(upath, xp, sizeof xp);
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
        if (sig == 6 /*SIGABRT*/ || sig == 9 /*SIGKILL*/ || sig == 4 /*SIGILL*/ ||
            sig == 8 /*SIGFPE*/ || sig == 11 /*SIGSEGV*/) {
            kprintf("[linuxabi] process raised signal %d at itself -- terminating\n", sig);
            /* abort() prints nothing of its own and leaves no fault address, so
             * without this the only evidence is the exit status. (M1970) */
            if (sig == 6) { lx_trace_dump("abort()"); lx_user_backtrace(r); }
            app_sys_exit(128 + sig);
            break;
        }
        r->rax = 0;                          /* other signals: accepted, undelivered */
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
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate(up, xp, sizeof xp);
        struct statx sx;
        if (vfs_stat(path, &sx) != 0) { r->rax = (uint64_t)-(long)LX_ENOENT; break; }
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
        *(uint32_t *)(o + 16) = 1;                         /* stx_nlink */
        *(uint16_t *)(o + 28) = (uint16_t)(isdir ? (0040000u | 0755u) : (0100000u | 0644u));  /* stx_mode */
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
                /* bind() on a client socket names a local port. We are
                 * single-homed with ephemeral source ports, and no caller here
                 * depends on a specific one, so accept it rather than fail a
                 * program that binds out of habit. */
                r->rax = 0; break;
            }
            int crc = app_connect((int)a1, ip, port);
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
        int lrc = app_unix_listen((int)a1);
        if (g_lx_systrace) kprintf("[sock] listen(fd %ld) -> %d\n", a1, lrc);
        if (lrc != 0) kprintf("[linuxabi] listen(fd %ld) FAILED\n", a1);
        r->rax = (uint64_t)(lrc == 0 ? 0 : -(long)LX_EADDRINUSE);
        break;
    }
    case LXS_accept_:
    case LXS_accept4_: {                    /* (fd, sockaddr *, addrlen *[, flags]) */
        int is4 = (r->rax == LXS_accept4_);          /* rax still holds the syscall number here */
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
            static uint8_t gbuf[2048];
            unsigned long tot = 0;
            const struct lx_iovec *v = (const struct lx_iovec *)iovptr;
            int bad = 0;
            for (uint64_t i = 0; i < iovlen; i++) {
                unsigned long n = v[i].iov_len;
                if (!n) continue;
                if (!v[i].iov_base || !vmm_user_ok((uint64_t)v[i].iov_base, n)) { bad = 1; break; }
                if (tot + n > sizeof gbuf) n = sizeof gbuf - tot;
                for (unsigned long k = 0; k < n; k++) gbuf[tot + k] = ((const uint8_t *)v[i].iov_base)[k];
                tot += n;
                if (tot >= sizeof gbuf) break;
            }
            if (bad) break;
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
             * whole and then fills the iovecs in order. */
            static uint8_t sbuf[2048];
            /* NEVER read more than the caller can take. Reading into a staging
             * buffer and scattering means anything past the end of the iovecs
             * is DROPPED -- and for a stream socket those bytes are gone from
             * the ring, so the caller is silently short. A Wayland client read
             * 94 bytes of a 148-byte burst of registry events and waited
             * forever for the other 54, which had been thrown away here.
             * (M1978) */
            unsigned long want = 0;
            for (uint64_t i = 0; i < iovlen; i++) want += v[i].iov_len;
            if (want > sizeof sbuf) want = sizeof sbuf;
            if (!want) break;
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
            if (gn == APP_FD_EAGAIN) { if (done == 0) { r->rax = (uint64_t)-(long)LX_EAGAIN; goto msgdone; } break; }
            if (gn < 0) break;
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
            if (first < 0) first = (long)off;
            if (is_mm) *(uint32_t *)(h + 56) = (uint32_t)off;
            done++;
        }
        if (done == 0) { r->rax = (uint64_t)-(long)LX_EAGAIN; break; }
        r->rax = is_mm ? (uint64_t)done : (uint64_t)first;
        msgdone: break;
    }
    case LXS_clock_nanosleep_: {            /* (clockid, flags, req, rem) */
        /* Node polls with this. ENOSYS made it a busy-wait. */
        if (!r->rdx || !vmm_user_ok(r->rdx, 16)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        const uint64_t *ts = (const uint64_t *)r->rdx;
        uint64_t ms = ts[0] * 1000ull + ts[1] / 1000000ull;
        if (r->rsi & 1) ms = 1;             /* TIMER_ABSTIME: we have no absolute clock to compare against */
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
         * Both are purely cosmetic to us -- there is nothing to name -- and
         * accepting them is what Linux does when the option is understood. */
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
    case LXS_eventfd2_: {                   /* (initval, flags) */
        int efd = app_eventfd_create((unsigned)r->rdi, 0);
        r->rax = (efd < 0) ? (uint64_t)-(long)LX_EMFILE : (uint64_t)efd;
        break;
    }
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
    case LXS_epoll_wait_:
    case LXS_epoll_pwait_: {                /* (epfd, events, maxevents, timeout[, sigmask]) */
        long maxev = (long)r->rdx, timeout = (long)r->r10;
        if (maxev <= 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (maxev > 64) maxev = 64;         /* app_epoll_check's own clamp */
        if (!vmm_user_ok(r->rsi, (uint64_t)maxev * 12)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        struct epoll_event tmp[64];
        uint64_t start = timer_ms();
        long k = 0;
        __asm__ volatile("sti");            /* this loop sleeps on the timer */
        for (;;) {
            k = app_epoll_check((int)a1, tmp, (int)maxev);
            if (k != 0) break;
            if (timeout >= 0 && (long)(timer_ms() - start) >= timeout) break;
            task_sleep_ms(10);
        }
        __asm__ volatile("cli");
        if (k < 0) { r->rax = (uint64_t)-(long)LX_EBADF; break; }
        uint8_t *out = (uint8_t *)r->rsi;   /* pack back into Linux's 12-byte layout */
        for (long i = 0; i < k; i++) {
            *(uint32_t *)(out + i * 12 + 0) = tmp[i].events;
            *(uint64_t *)(out + i * 12 + 4) = tmp[i].data;
        }
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
            task_sleep_ms(10);
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
        /* FUTEX_PRIVATE_FLAG(128) and FUTEX_CLOCK_REALTIME(256) are hints about
         * scope and clock source; neither changes what we do, so mask them off
         * rather than failing an op we do support. */
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
                ms = (long)(ts[0] * 1000 + ts[1] / 1000000);
                if (ms < 0) ms = 0;
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
    case LXS_rt_sigaction:
    case LXS_rt_sigprocmask:
        r->rax = 0;                         /* accepted-and-ignored for now */
        break;
    case LXS_ioctl:
        /* musl asks TCGETS on stdout to decide whether it is a tty and thus
         * whether to line-buffer. ENOTTY is a legitimate answer and makes it
         * pick full buffering, which is correct for a non-tty. */
        r->rax = (uint64_t)-(long)LX_ENOTTY;
        break;
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
        }
        r->rax = app_sbrk(0);
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
        uint64_t base = (flags & LX_MAP_FIXED) ? app_mmap_fixed(r->rdi, (uint64_t)len)
                                              : app_mmap((uint64_t)len);
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
    case LXS_munmap:
        r->rax = (uint64_t)(app_munmap(r->rdi, r->rsi) == 0 ? 0 : -(long)LX_EINVAL);
        break;
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
            *(uint32_t *)(st + LXST_O_MODE)    = isdir ? (0040000u | 0755u) : (LX_S_IFREG | 0644u);
            *(uint64_t *)(st + LXST_O_NLINK)   = 1;
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
        /* /proc/self/exe is REAL now (M1970).
         *
         * Returning ENOENT was defensible while the only caller was glibc
         * probing it and falling back on argv[0]. It is not defensible for a
         * Node single-executable application: the runtime and the JS are one
         * image, and it finds its own embedded payload by reading
         * /proc/self/exe and opening the result. With no answer, Claude Code
         * called abort() during startup -- printing nothing, leaving no fault
         * address, and naming nothing. The syscall ring is what showed
         * gettid/getpid/tgkill(SIGABRT) right after the probe.
         *
         * The path has to be translated back OUT of the compat root: the
         * process believes it is /usr/bin/claude, not /disk2/usr/bin/claude. */
        uint64_t up  = (r->rax == LXS_readlinkat) ? r->rsi : r->rdi;
        uint64_t ub  = (r->rax == LXS_readlinkat) ? r->rdx : r->rsi;
        uint64_t usz = (r->rax == LXS_readlinkat) ? r->r10 : r->rdx;
        const char *upath = (const char *)up;
        if (!upath || !vmm_user_ok(up, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        int is_exe = 0;
        { const char *a_ = "/proc/self/exe"; int k = 0;
          while (a_[k] && upath[k] == a_[k]) k++;
          is_exe = (!a_[k] && !upath[k]); }
        if (!is_exe) { r->rax = (uint64_t)-(long)LX_ENOENT; break; }
        const char *ep = app_exe_str(app_current());
        if (!ep || ep[0] != '/') { r->rax = (uint64_t)-(long)LX_ENOENT; break; }
        /* Strip LX_ROOT if it is there, so the answer is in the process's own
         * view of the filesystem. */
        int rl = 0; while (LX_ROOT[rl]) rl++;
        int match = 1; for (int k = 0; k < rl; k++) if (ep[k] != LX_ROOT[k]) { match = 0; break; }
        const char *vis = (match && ep[rl] == '/') ? ep + rl : ep;
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
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate(upath, xp, sizeof xp);
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
        long got = app_fd_read((int)a1, (void *)r->rsi, (unsigned long)n);
        r->rax = (got < 0) ? (uint64_t)lx_fd_err(got) : (uint64_t)got;
        break;
    }
    case LXS_close_:
        if (app_fd_close((int)a1) == 0) { r->rax = 0; break; }
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
    case LXS_newfstatat: {                  /* (dirfd, path, statbuf, flags) */
        const char *upath = (const char *)r->rsi;
        if (!upath || !vmm_user_ok(r->rsi, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate(upath, xp, sizeof xp);
        if (!vmm_user_ok(r->rdx, LXST_SIZE)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        struct statx sx;
        if (vfs_stat(path, &sx) != 0) { r->rax = (uint64_t)-(long)LX_ENOENT; break; }
        uint8_t *st = (uint8_t *)r->rdx;
        for (int i = 0; i < LXST_SIZE; i++) st[i] = 0;
        int isdir = (sx.stx_mode & 0170000u) == 0040000u;
        *(uint32_t *)(st + LXST_O_MODE)    = isdir ? (0040000u | 0755u) : (LX_S_IFREG | 0644u);
        *(uint64_t *)(st + LXST_O_NLINK)   = 1;
        *(int64_t  *)(st + LXST_O_SIZE)    = (int64_t)sx.stx_size;
        *(int64_t  *)(st + LXST_O_BLKSIZE) = 4096;
        *(int64_t  *)(st + LXST_O_BLOCKS)  = (int64_t)((sx.stx_size + 511) / 512);  /* 512-byte units, as Linux defines it */
        *(uint64_t *)(st + LXST_O_INO)     = sx.stx_ino;   /* a real inode -- see LXS_fstat (M1955) */
        *(uint64_t *)(st + LXST_O_DEV)     = LX_FAKE_DEV;
        r->rax = 0;
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
        int ecap = 1024;                    /* NB: `cap` is already the user buffer size */
        vfs_dirent *ents = kmalloc((unsigned long)ecap * sizeof *ents);
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
        if (r->rsi) { r->rax = (uint64_t)app_fork_at(r, r->rsi); break; }
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
        if (cstack) { r->rax = (uint64_t)app_fork_at(r, cstack + cssize); break; }
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
        /* Accepted and ignored. Everything runs as root on a volume with no
         * enforced permission bits, so refusing would fail `as`'s attempt to
         * chmod the object file it just wrote for no gain. */
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
        long xrc = app_execve_linux(r, pbuf, av, ev);
        /* Safe on both paths: lx_spawn_stack has already copied the strings
         * into the NEW user stack by the time app_exec returns. */
        kfree(abuf); kfree(ebuf); kfree(av); kfree(ev);
        if (xrc < 0) r->rax = (uint64_t)-(long)LX_ENOENT;   /* only reached on failure */
        break;
    }
    case LXS_wait4_: {                      /* (pid, status*, options, rusage*) */
        int st = 0;
        long got = app_waitpid((int)a1, &st);
        if (got < 0) { r->rax = (uint64_t)-(long)LX_ECHILD; break; }
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
        if (app_pipe2(fds, 0) < 0) { r->rax = (uint64_t)-(long)LX_EMFILE; break; }
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
        r->rax = (vfs_stat(path, &sx) == 0) ? 0 : (uint64_t)-(long)LX_ENOENT;
        break;
    }
    case LXS_exit:
        /* exit(2) ends ONE THREAD. Routing it to process exit killed every
         * sibling the moment a pthread returned -- but the MAIN thread calling
         * exit(2) really does end the process, or a program returning from
         * main would leave a husk nothing ever reaps. (M1959) */
        if (!app_is_main_thread()) { app_thread_exit(); break; }
        /* fall through */
    case LXS_exit_group:
        kprintf("[linuxabi] guest exited with status %ld\n", a1);
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
    if (g_lxring_cur) { g_lxring_cur->ret = r->rax; g_lxring_cur = 0; }
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
