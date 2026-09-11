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
#include "timer.h"
#include "syscall.h"   /* AT_PAGESZ/AT_ENTRY/AT_UID/... -- the auxv types we share with /proc/<pid>/auxv */
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
uint64_t lx_spawn_stack(const void *image, uint64_t base, uint64_t entry,
                        uint64_t stack_top, uint64_t stack_bottom,
                        const char *const *argv, const char *const *envp) {
    const uint8_t *e = (const uint8_t *)image;
    uint64_t phoff   = *(const uint64_t *)(e + 32);   /* e_phoff */
    uint16_t phent   = *(const uint16_t *)(e + 54);   /* e_phentsize */
    uint16_t phnum   = *(const uint16_t *)(e + 56);   /* e_phnum */
    struct lx_stack_info si = {
        .phdr = base + phoff, .entry = entry, .base = base,
        .phent = phent, .phnum = phnum,
    };
    return lx_build_stack(stack_top, stack_bottom, argv, envp, &si);
}
