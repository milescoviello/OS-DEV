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
#include "vmm.h"
#include "app.h"
#include "rtc.h"
#include "random.h"
#include "vfs.h"      /* app_sbrk/app_mmap/app_mprotect/app_munmap -- the native primitives these translate onto */
#include "timer.h"
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
int g_lx_mmap_trace;                      /* -append lxmmaptrace: log every Linux mmap/mprotect (M1955) */
#define LX_ROOT     "/disk2"
#define LX_ROOT_LEN 6

/* Translate a Linux path into one the VFS understands. Returns `out`. */
static const char *lx_xlate(const char *p, char *out, int max) {
    if (!p || p[0] != '/') return p;                  /* relative: leave alone */
    int n = 0;
    for (const char *r = LX_ROOT; *r && n < max - 1; r++) out[n++] = *r;
    for (int i = 0; p[i] && n < max - 1; i++) out[n++] = p[i];
    out[n] = 0;
    return out;
}

/* struct iovec, exactly Linux's layout. */
struct lx_iovec { void *iov_base; unsigned long iov_len; };

/* Counters so the boot self-test can prove the path was actually taken rather
 * than inferring it from a value that could have come from anywhere. */
volatile unsigned long lx_syscall_count, lx_unknown_count;

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
            r->rax = (w < 0) ? (uint64_t)-(long)LX_EBADF : (uint64_t)w;
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
                if (w < 0) { r->rax = (uint64_t)-(long)LX_EPIPE; goto done; }
                total += w;
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
        r->rax = (uint64_t)task_current_id();   /* Linux returns the caller's tid */
        break;
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
        if (!base) { r->rax = (uint64_t)-(long)LX_ENOMEM; break; }
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
            old[0] = old[1] = ~0ull;         /* RLIM_INFINITY, both cur and max */
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
        if (a1 == 0) { ts[0] = (int64_t)rtc_unix(); ts[1] = (int64_t)((ms % 1000) * 1000000); }
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
    case LXS_readlink:
        /* glibc probes /proc/self/exe here. ENOENT is the honest answer while
         * that node does not exist, and glibc falls back on argv[0] -- which
         * the M1940 stack supplies. */
        r->rax = (uint64_t)-(long)LX_ENOENT;
        break;
    case LXS_openat_: {                     /* (dirfd, path, flags, mode) */
        const char *upath = (const char *)r->rsi;
        if (!upath || !vmm_user_ok(r->rsi, 1)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        char xp[VFS_PATH_MAX]; const char *path = lx_xlate(upath, xp, sizeof xp);
        long lf = (long)r->rdx, nf = 0;
        if (lf & (LXO_WRONLY | LXO_RDWR)) nf |= O_WRONLY;   /* we have no separate RDWR */
        if (lf & LXO_CREAT)  nf |= O_CREAT;
        if (lf & LXO_TRUNC)  nf |= O_TRUNC;
        if (lf & LXO_APPEND) nf |= O_APPEND;
        int fd = app_open(path, (int)nf);
        /* Report the miss. A dynamic linker probes many paths that are MEANT
         * to be absent, but when something it actually needs is missing the
         * failure surfaces much later as a NULL deref inside ld.so -- this
         * line is the difference between "page fault at 0x8" and "libbfd is
         * not where you put it". (M1955) */
        if (fd < 0) kprintf("[linuxabi] openat(%s) -> ENOENT\n", path);
        r->rax = (fd < 0) ? (uint64_t)-(long)LX_ENOENT : (uint64_t)fd;
        break;
    }
    case LXS_read_: {                       /* (fd, buf, count) */
        long n = (long)r->rdx;
        if (n < 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (n && !vmm_user_ok(r->rsi, (uint64_t)n)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        long got = app_fd_read((int)a1, (void *)r->rsi, (unsigned long)n);
        r->rax = (got < 0) ? (uint64_t)-(long)LX_EBADF : (uint64_t)got;
        break;
    }
    case LXS_close_:
        r->rax = (uint64_t)(app_fd_close((int)a1) == 0 ? 0 : -(long)LX_EBADF);
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
        static vfs_dirent ents[64];         /* static: 64 * sizeof(vfs_dirent) is far too much stack */
        int n = vfs_list_path(dp, ents, 64);
        if (n < 0) { r->rax = (uint64_t)-(long)LX_ENOTDIR; break; }
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
        r->rax = (uint64_t)-(long)LX_ENOSYS;
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
        char abuf[16][256]; const char *av[17];
        char ebuf[16][256]; const char *ev[17];
        int na = 0, ne = 0;
        const char *const *uav = (const char *const *)r->rsi;
        const char *const *uev = (const char *const *)r->rdx;
        if (uav && vmm_user_ok(r->rsi, sizeof(char *))) {
            for (; na < 16 && uav[na]; na++) {
                const char *sp = uav[na]; int k = 0;
                if (!vmm_user_ok((uint64_t)sp, 1)) break;
                while (sp[k] && k < 255) { abuf[na][k] = sp[k]; k++; }
                abuf[na][k] = 0; av[na] = abuf[na];
            }
        }
        av[na] = 0;
        if (uev && vmm_user_ok(r->rdx, sizeof(char *))) {
            for (; ne < 16 && uev[ne]; ne++) {
                const char *sp = uev[ne]; int k = 0;
                if (!vmm_user_ok((uint64_t)sp, 1)) break;
                while (sp[k] && k < 255) { ebuf[ne][k] = sp[k]; k++; }
                ebuf[ne][k] = 0; ev[ne] = ebuf[ne];
            }
        }
        ev[ne] = 0;
        char pbuf[VFS_PATH_MAX];
        { char t[VFS_PATH_MAX]; const char *xp = lx_xlate(path, t, sizeof t);
          int k = 0; while (xp[k] && k < (int)sizeof pbuf - 1) { pbuf[k] = xp[k]; k++; } pbuf[k] = 0; }
        if (app_execve_linux(r, pbuf, av, ev) < 0)
            r->rax = (uint64_t)-(long)LX_ENOENT;   /* only reached on failure */
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
            /* O_RDWR. We do not record per-fd access modes, and claiming
             * read-write is the permissive answer -- an fd we handed out is
             * usable, and stdio only uses this to reject an impossible
             * operation it was never going to attempt. */
            r->rax = 2;
            break;
        }
        if (cmd == 4) { r->rax = 0; break; } /* F_SETFL: accepted; we have no O_NONBLOCK on files */
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
            *(int64_t *)r->rdi = (int64_t)rtc_unix();
        }
        r->rax = (uint64_t)rtc_unix();
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
    uint64_t argp[64], envpp[64];
    int argc = 0, envc = 0;

    /* 1. strings first, at the very top, so the pointer arrays below can name
     *    them. Bounded at 64 each: more than any real invocation, and a cap is
     *    required since these are fixed arrays. */
    for (; argv && argv[argc] && argc < 64; argc++) { }
    for (; envp && envp[envc] && envc < 64; envc++) { }
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
 * AT_PHDR is computed as base + e_phoff, which is correct when the program
 * headers fall inside a PT_LOAD that maps file offset 0 at vaddr 0 -- true for
 * every normal static-PIE image, and the only shape we load. */
uint64_t lx_spawn_stack_dyn(const void *image, uint64_t base, uint64_t entry,
                            uint64_t interp_base,
                            uint64_t stack_top, uint64_t stack_bottom,
                            const char *const *argv, const char *const *envp) {
    const uint8_t *e = (const uint8_t *)image;
    uint64_t phoff   = *(const uint64_t *)(e + 32);   /* e_phoff */
    uint16_t phent   = *(const uint16_t *)(e + 54);   /* e_phentsize */
    uint16_t phnum   = *(const uint16_t *)(e + 56);   /* e_phnum */
    /* AT_BASE names the INTERPRETER's load bias when there is one -- that is
     * how ld.so finds itself to self-relocate. AT_PHDR and AT_ENTRY must still
     * describe the EXECUTABLE, because that is the program ld.so is being
     * asked to start. Getting these crossed makes the linker relocate itself
     * against the wrong bias. (M1954) */
    struct lx_stack_info si = {
        .phdr = base + phoff, .entry = entry,
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
