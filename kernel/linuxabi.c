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
#include <stdint.h>

/* ---- MSRs ---------------------------------------------------------------- */
#define MSR_EFER            0xC0000080u
#define   EFER_SCE          (1u << 0)      /* System Call Extensions: enables `syscall` */
#define MSR_STAR            0xC0000081u
#define MSR_LSTAR           0xC0000082u
#define MSR_SFMASK          0xC0000084u
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
    lx_pc[cpu & (LX_MAXCPUS - 1)].kernel_rsp = rsp;
}

extern void linux_syscall_entry(void);

/* Arm the `syscall` instruction on the CALLING core. Must run on every core
 * (BSP and each AP): EFER, LSTAR, STAR, SFMASK and KERNEL_GS_BASE are all
 * per-core MSRs, and a core that skipped this would #UD on a Linux binary's
 * very first instruction. */
void linux_abi_init_this_cpu(void) {
    int cpu = smp_current_cpu() & (LX_MAXCPUS - 1);

    /* KERNEL_GS_BASE, not GS_BASE: ring 3 owns GS_BASE (and `mov gs, ax` in
     * iret_to_user zeroes it on every fork-child/thread entry), so the entry
     * stub's `swapgs` brings ours in and the matching one on return puts the
     * user's back. */
    wrmsr(MSR_KERNEL_GS_BASE, (uint64_t)&lx_pc[cpu]);

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

#define ARCH_SET_FS 0x1002

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
        if (a1 != 1 && a1 != 2) { r->rax = (uint64_t)-(long)LX_EBADF; break; }
        /* Validate before dereferencing -- the native path routes every ring-3
         * pointer through vmm_user_ok (a PTE_USER page-table walk) and this
         * path must not be the hole in that. An unvalidated buf here would let
         * ring 3 make the kernel read arbitrary memory and print it. */
        if (a3 < 0) { r->rax = (uint64_t)-(long)LX_EINVAL; break; }
        if (a3 && !vmm_user_ok(r->rsi, (uint64_t)a3)) { r->rax = (uint64_t)-(long)LX_EFAULT; break; }
        for (long i = 0; i < a3; i++) console_putc(p2[i]);
        r->rax = (uint64_t)a3;
        break;
    }
    case LXS_writev: {                      /* (fd, iov, iovcnt) -- musl's printf path */
        if (a1 != 1 && a1 != 2) { r->rax = (uint64_t)-(long)LX_EBADF; break; }
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
            for (unsigned long k = 0; k < n; k++) console_putc(b[k]);
            total += (long)n;
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
    case LXS_exit:
    case LXS_exit_group:
        kprintf("[linuxabi] guest exited with status %ld\n", a1);
        task_exit();
        break;
    default:
        lx_unknown_count++;
        r->rax = (uint64_t)-(long)LX_ENOSYS;
        break;
    }
}
