/* lxsigctx.c -- THE SIGNAL CONTEXT A JVM DEPENDS ON (M2392).
 *
 * HotSpot does not test for null, for division by zero, or for a pending
 * safepoint. It lets the hardware fault, and its SIGSEGV/SIGFPE handler reads
 * the fault out of siginfo_t and ucontext_t, decides the fault is one of its
 * own, WRITES a new program counter into the ucontext, and returns. The kernel
 * has to resume at that new program counter. At startup it also faults on
 * purpose with known values in YMM, to learn whether the kernel keeps vector
 * state across a signal.
 *
 * The frame this kernel delivered could do none of that: OS-DEV's interrupt
 * frame where the ucontext belongs, si_code and si_addr eight bytes early,
 * and a sigreturn that restored a kernel-side copy and discarded the edit. So
 * every check below asks for the Linux behaviour itself, by doing what a JVM
 * does -- and each one fails on the old frame:
 *
 *   1. siginfo_t: si_signo, si_code and the EXACT fault address for a read of
 *      a PROT_NONE page, a write to a read-only page, and a null page
 *   2. ucontext_t: gregs[REG_RIP] is the faulting instruction, REG_TRAPNO /
 *      REG_ERR / REG_CR2 describe the fault, callee-saved registers hold the
 *      values the interrupted code put there
 *   3. the handler MOVES THE PC and edits registers; the thread resumes there
 *   4. FP state: fpregs points at an XSAVE image holding the interrupted
 *      XMM0 (and YMM0's upper half); a handler that clobbers them does not
 *      change what the interrupted code sees afterwards
 *   5. integer divide by zero is SIGFPE / FPE_INTDIV; ud2 is SIGILL / ILL_ILLOPN
 *   6. the handled signal is blocked inside its handler, uc_sigmask is the
 *      mask to go back to, and an edit to uc_sigmask is what sigreturn installs
 *   7. a fault INSIDE another signal's handler is delivered (nesting)
 *   8. four threads faulting at once each get their OWN si_addr
 *   9. sigaltstack + SA_ONSTACK runs the handler on the alternate stack
 *  10. a forked child's SA_SIGINFO handler still gets siginfo and ucontext
 *  11. sigsuspend returns EINTR and puts the ORIGINAL mask back
 *  12. getcpu(2) answers (HotSpot exits the VM when it does not)
 *  13. a loop of 100000 caught faults, timed -- the cost of a null check that
 *      misses, and proof the path does not leak per delivery
 *
 * On the old kernel a discarded PC edit re-executes the faulting instruction
 * for ever, so every handler counts entries per site and siglongjmps out
 * after three: a FAIL, never a hang. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>
#include <cpuid.h>

/* ---- fault sites, in assembly so the addresses are exact ------------------ */
uint64_t lxs_after_r12;
__asm__(
    ".text\n"
    /* uint64_t lxs_load(const void *p): sentinels in rbx and r12-r15, then a
     * load at a known address. A handler that resumes at lxs_load_cont with
     * rax edited makes this return the edit. */
    ".globl lxs_load\n.type lxs_load,@function\nlxs_load:\n"
    "  push %rbx\n  push %r12\n  push %r13\n  push %r14\n  push %r15\n"
    "  movabs $0x1111111111111111, %rbx\n"
    "  movabs $0x2222222222222222, %r12\n"
    "  movabs $0x3333333333333333, %r13\n"
    "  movabs $0x4444444444444444, %r14\n"
    "  movabs $0x5555555555555555, %r15\n"
    "  xor %eax, %eax\n"
    ".globl lxs_load_site\nlxs_load_site:\n"
    "  movq (%rdi), %rax\n"
    ".globl lxs_load_cont\nlxs_load_cont:\n"
    "  mov %r12, lxs_after_r12(%rip)\n"
    "  pop %r15\n  pop %r14\n  pop %r13\n  pop %r12\n  pop %rbx\n"
    "  ret\n"
    /* void lxs_store(void *p): a write at a known address. */
    ".globl lxs_store\n.type lxs_store,@function\nlxs_store:\n"
    ".globl lxs_store_site\nlxs_store_site:\n"
    "  movq $0x5a, (%rdi)\n"
    ".globl lxs_store_cont\nlxs_store_cont:\n"
    "  ret\n"
    /* void lxs_fp(const void *fault, const void *in32, void *out32, int avx):
     * put a pattern in XMM0 (YMM0 with AVX), fault, and store what XMM0/YMM0
     * holds after the handler returns. rcx carries the AVX flag ACROSS the
     * fault, so a kernel that does not restore rcx fails here too. */
    ".globl lxs_fp\n.type lxs_fp,@function\nlxs_fp:\n"
    "  test %ecx, %ecx\n  jz 1f\n"
    "  vmovdqu (%rsi), %ymm0\n  jmp 2f\n"
    "1: movdqu (%rsi), %xmm0\n"
    "2:\n"
    ".globl lxs_fp_site\nlxs_fp_site:\n"
    "  movq (%rdi), %rax\n"
    ".globl lxs_fp_cont\nlxs_fp_cont:\n"
    "  test %ecx, %ecx\n  jz 3f\n"
    "  vmovdqu %ymm0, (%rdx)\n  vzeroupper\n  ret\n"
    "3: movdqu %xmm0, (%rdx)\n  ret\n"
    /* int lxs_div(int d): 100 / d */
    ".globl lxs_div\n.type lxs_div,@function\nlxs_div:\n"
    "  mov $100, %eax\n  cltd\n"
    ".globl lxs_div_site\nlxs_div_site:\n"
    "  idiv %edi\n"
    ".globl lxs_div_cont\nlxs_div_cont:\n"
    "  ret\n"
    /* int lxs_ud(void): ud2 */
    ".globl lxs_ud\n.type lxs_ud,@function\nlxs_ud:\n"
    "  xor %eax, %eax\n"
    ".globl lxs_ud_site\nlxs_ud_site:\n"
    "  ud2\n"
    ".globl lxs_ud_cont\nlxs_ud_cont:\n"
    "  ret\n"
);
uint64_t lxs_load(const volatile void *p);
void lxs_store(volatile void *p);
void lxs_fp(const volatile void *fault, const void *in32, void *out32, int avx);
int lxs_div(int d);
int lxs_ud(void);
extern char lxs_load_site[], lxs_load_cont[], lxs_store_site[], lxs_store_cont[];
extern char lxs_fp_site[], lxs_fp_cont[], lxs_div_site[], lxs_div_cont[];
extern char lxs_ud_site[], lxs_ud_cont[];

static int fails;
#define CHECK(cond, ...) do { if (cond) { printf("LXSIGCTX: ok   "); printf(__VA_ARGS__); printf("\n"); } \
                              else { printf("LXSIGCTX: FAIL "); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

/* ---- what the handler saw -------------------------------------------------- */
struct seen {
    int signo, code, entries;
    uint64_t addr, rip, trapno, err, cr2, rbx, r12, r13, r15;
    int have_fp;
    uint8_t xmm0[16], ymm0hi[16];
    uint32_t magic1, xstate_size;
    uint64_t xstate_bv;
    int sig_blocked_inside, usr2_in_ucmask;
};
static __thread struct seen S;
static __thread sigjmp_buf bail;
static __thread int bail_armed;
static __thread int edit_mask, clobber_fp;
static int g_avx;
static unsigned g_ymm_off = 576;          /* CPUID.(0xD,2).EBX: YMM_Hi128's offset in the XSAVE image */

static void handler(int sig, siginfo_t *si, void *ucv) {
    ucontext_t *uc = ucv;
    greg_t *g = uc->uc_mcontext.gregs;
    S.entries++;
    S.signo = si->si_signo; S.code = si->si_code; S.addr = (uint64_t)si->si_addr;
    S.rip = g[REG_RIP]; S.trapno = g[REG_TRAPNO]; S.err = g[REG_ERR]; S.cr2 = g[REG_CR2];
    S.rbx = g[REG_RBX]; S.r12 = g[REG_R12]; S.r13 = g[REG_R13]; S.r15 = g[REG_R15];
    sigset_t now; sigprocmask(SIG_BLOCK, NULL, &now);
    S.sig_blocked_inside = sigismember(&now, sig);
    S.usr2_in_ucmask = sigismember(&uc->uc_sigmask, SIGUSR2);
    const uint8_t *fp = (const uint8_t *)uc->uc_mcontext.fpregs;
    S.have_fp = fp != NULL;
    if (fp) {
        memcpy(S.xmm0, fp + 160, 16);                         /* FXSAVE: XMM0 at byte 160 */
        memcpy(&S.magic1, fp + 464, 4);
        memcpy(&S.xstate_size, fp + 464 + 16, 4);
        if (S.magic1 == 0x46505853u) {
            memcpy(&S.xstate_bv, fp + 512, 8);
            memcpy(S.ymm0hi, fp + g_ymm_off, 16);
        }
    }
    if (S.entries > 3) { if (bail_armed) siglongjmp(bail, 1); _exit(99); }   /* the edit was discarded */

    char *pc = (char *)g[REG_RIP];
    if (pc == lxs_load_site) {
        g[REG_RIP] = (greg_t)lxs_load_cont;
        g[REG_RAX] = 0xC0FFEE;
        g[REG_R12] = 0xBEEF;
    } else if (pc == lxs_store_site) {
        g[REG_RIP] = (greg_t)lxs_store_cont;
    } else if (pc == lxs_fp_site) {
        g[REG_RIP] = (greg_t)lxs_fp_cont;
    } else if (pc == lxs_div_site) {
        g[REG_RIP] = (greg_t)lxs_div_cont;
        g[REG_RAX] = 42;
    } else if (pc == lxs_ud_site) {
        g[REG_RIP] = (greg_t)lxs_ud_cont;
        g[REG_RAX] = 7;
    } else {
        if (bail_armed) siglongjmp(bail, 2);                  /* not one of ours */
        _exit(98);
    }
    if (edit_mask) sigaddset(&uc->uc_sigmask, SIGUSR1);
    if (clobber_fp) {                                          /* what a memcpy in a handler does */
        if (g_avx) __asm__ volatile("vpxor %%xmm0, %%xmm0, %%xmm0\n vzeroall" ::: "xmm0", "xmm1", "xmm2", "xmm3",
                                    "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12",
                                    "xmm13", "xmm14", "xmm15", "memory");
        else       __asm__ volatile("pxor %%xmm0, %%xmm0" ::: "xmm0");
    }
}

static void install(int sig, int extra_flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART | extra_flags;     /* HotSpot's flags */
    sigemptyset(&sa.sa_mask);
    if (sigaction(sig, &sa, NULL) != 0) { printf("LXSIGCTX: FAIL sigaction(%d): %s\n", sig, strerror(errno)); exit(1); }
}

/* Run one faulting call under the bail-out guard. Returns 1 if it returned
 * normally (the handler's edit was honoured), 0 if the guard fired. */
#define GUARDED(expr) ({ volatile int _ok = 0; memset(&S, 0, sizeof S); bail_armed = 1;     \
                         if (sigsetjmp(bail, 1) == 0) { expr; _ok = 1; }         \
                         bail_armed = 0; _ok; })

/* ---- 7: a fault inside another handler ------------------------------------ */
static volatile uint64_t nested_result;
static volatile const void *nested_ptr;
static void usr1_nested(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)si; (void)uc;
    nested_result = lxs_load(nested_ptr);
}

/* ---- 8: threads ------------------------------------------------------------ */
#define NTHR 4
#define PER_THREAD 20000
static uint8_t *g_none;                   /* a PROT_NONE region, one page per thread */
static int thr_bad[NTHR];
static void *thr_main(void *arg) {
    int id = (int)(intptr_t)arg;
    for (volatile int k = 0; k < PER_THREAD; k++) {
        const uint8_t *p = g_none + (size_t)id * 4096 + (size_t)(k % 512) * 8;
        uint64_t v = 0;
        if (!GUARDED(v = lxs_load(p)) || v != 0xC0FFEE || S.addr != (uint64_t)p) { thr_bad[id]++; if (thr_bad[id] > 3) break; }
    }
    return NULL;
}

/* ---- 9, 10, 11 ------------------------------------------------------------- */
static volatile int got_usr2, usr2_on_alt, usr2_ss_onstack, usr2_had_ctx;
static uint8_t *g_alt; static size_t g_alt_sz = 64 * 1024;
static void usr2_handler(int sig, siginfo_t *si, void *uc) {
    got_usr2 = sig;
    usr2_had_ctx = si && uc && si->si_signo == sig;
    volatile int here;
    usr2_on_alt = (uint8_t *)&here >= g_alt && (uint8_t *)&here < g_alt + g_alt_sz;
    stack_t cur; if (sigaltstack(NULL, &cur) == 0) usr2_ss_onstack = (cur.ss_flags & SS_ONSTACK) != 0;
}
static volatile int usr1_count;
static void usr1_count_handler(int sig) { (void)sig; usr1_count++; }

static double now_s(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    {   unsigned a, b, c, d;
        if (__get_cpuid(1, &a, &b, &c, &d) && (c & (1u << 28)) && (c & (1u << 27))) {
            unsigned lo, hi; __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
            g_avx = (lo & 6) == 6;
        }
        if (g_avx && __get_cpuid_count(0xD, 2, &a, &b, &c, &d) && b) g_ymm_off = b;
    }
    printf("LXSIGCTX: AVX %s (YMM_Hi128 at XSAVE offset %u)\n", g_avx ? "enabled" : "absent", g_ymm_off);
    install(SIGSEGV, 0);
    install(SIGBUS, 0);
    install(SIGFPE, 0);
    install(SIGILL, 0);

    long pg = sysconf(_SC_PAGESIZE);
    uint8_t *none = mmap(NULL, pg, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint8_t *ro = mmap(NULL, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (none == MAP_FAILED || ro == MAP_FAILED) { printf("LXSIGCTX: FAIL mmap\n"); return 1; }
    ro[0] = 1; mprotect(ro, pg, PROT_READ);

    /* 1-3: a read of PROT_NONE, with SIGUSR2 blocked so the mask can be read back */
    sigset_t m; sigemptyset(&m); sigaddset(&m, SIGUSR2); sigprocmask(SIG_BLOCK, &m, NULL);
    uint64_t v = 0;
    const uint8_t *target = none + 0x123;
    int ok = GUARDED(v = lxs_load(target));
    CHECK(ok, "the handler moved the PC and the thread resumed THERE (%d entr%s)", S.entries, S.entries == 1 ? "y" : "ies");
    CHECK(S.signo == SIGSEGV, "si_signo = %d (want SIGSEGV)", S.signo);
    CHECK(S.code == SEGV_ACCERR, "si_code = %d for a PROT_NONE read (want SEGV_ACCERR=2)", S.code);
    CHECK(S.addr == (uint64_t)target, "si_addr = %#lx (want the exact address %#lx)", (unsigned long)S.addr, (unsigned long)target);
    CHECK(S.rip == (uint64_t)lxs_load_site, "gregs[REG_RIP] = %#lx is the faulting instruction (%#lx)", (unsigned long)S.rip, (unsigned long)lxs_load_site);
    CHECK(S.trapno == 14 && S.cr2 == (uint64_t)target && (S.err & 4), "REG_TRAPNO %lu, REG_CR2 %#lx, REG_ERR %#lx (want 14, the address, user bit)",
          (unsigned long)S.trapno, (unsigned long)S.cr2, (unsigned long)S.err);
    CHECK(S.rbx == 0x1111111111111111ull && S.r12 == 0x2222222222222222ull && S.r13 == 0x3333333333333333ull && S.r15 == 0x5555555555555555ull,
          "callee-saved registers in the ucontext are the interrupted code's (rbx %#lx r12 %#lx)", (unsigned long)S.rbx, (unsigned long)S.r12);
    CHECK(v == 0xC0FFEE && lxs_after_r12 == 0xBEEF, "register EDITS came back: rax %#lx (want 0xc0ffee), r12 %#lx (want 0xbeef)",
          (unsigned long)v, (unsigned long)lxs_after_r12);
    CHECK(S.sig_blocked_inside == 1, "SIGSEGV is blocked while its handler runs");
    CHECK(S.usr2_in_ucmask == 1, "uc_sigmask is the interrupted mask (SIGUSR2 blocked)");
    sigprocmask(SIG_UNBLOCK, &m, NULL);

    ok = GUARDED(lxs_store(ro + 8));
    CHECK(ok && S.code == SEGV_ACCERR && S.addr == (uint64_t)(ro + 8) && (S.err & 2),
          "a write to a read-only page: resumed %d, si_code %d, si_addr ok %d, REG_ERR write bit %d",
          ok, S.code, S.addr == (uint64_t)(ro + 8), (int)((S.err >> 1) & 1));
    ok = GUARDED(v = lxs_load((const void *)0x10));
    CHECK(ok && S.addr == 0x10 && S.code == SEGV_MAPERR, "a null-page read: resumed %d, si_addr %#lx (want 0x10), si_code %d (want SEGV_MAPERR=1)",
          ok, (unsigned long)S.addr, S.code);

    /* 4: FP state */
    {   uint8_t in[32], out[32];
        for (int i = 0; i < 32; i++) in[i] = (uint8_t)(0xA0 + i);
        memset(out, 0, sizeof out);
        clobber_fp = 1;
        ok = GUARDED(lxs_fp(none, in, out, g_avx));
        clobber_fp = 0;
        CHECK(ok && S.have_fp, "fpregs is set (resumed %d)", ok);
        CHECK(memcmp(S.xmm0, in, 16) == 0, "the frame's XSAVE image holds the interrupted XMM0");
        if (g_avx) {
            CHECK(S.magic1 == 0x46505853u && S.xstate_size >= 576, "FP_XSTATE_MAGIC1 present, xstate_size %u", S.xstate_size);
            CHECK((S.xstate_bv & 4) && memcmp(S.ymm0hi, in + 16, 16) == 0, "...and YMM0's upper half (XSTATE_BV %#lx)", (unsigned long)S.xstate_bv);
        }
        CHECK(memcmp(out, in, g_avx ? 32 : 16) == 0, "%s survived a handler that zeroed it", g_avx ? "YMM0" : "XMM0");
    }

    /* 5: SIGFPE and SIGILL */
    volatile int q = 0;
    ok = GUARDED(q = lxs_div(0));
    CHECK(ok && S.signo == SIGFPE && S.code == FPE_INTDIV && S.addr == (uint64_t)lxs_div_site && q == 42,
          "divide by zero -> signo %d (want SIGFPE=8), si_code %d (want FPE_INTDIV=1), si_addr is the idiv %d, resumed with %d",
          S.signo, S.code, S.addr == (uint64_t)lxs_div_site, q);
    ok = GUARDED(q = lxs_ud());
    CHECK(ok && S.signo == SIGILL && S.code == ILL_ILLOPN && q == 7,
          "ud2 -> signo %d (want SIGILL=4), si_code %d (want ILL_ILLOPN=2), resumed with %d", S.signo, S.code, q);

    /* 6: sigreturn installs uc_sigmask */
    edit_mask = 1;
    ok = GUARDED(lxs_load(none));
    edit_mask = 0;
    {   sigset_t cur; sigprocmask(SIG_BLOCK, NULL, &cur);
        CHECK(ok && sigismember(&cur, SIGUSR1) && !sigismember(&cur, SIGSEGV),
              "an edit to uc_sigmask is what sigreturn installs (SIGUSR1 now blocked %d, SIGSEGV %d)",
              sigismember(&cur, SIGUSR1), sigismember(&cur, SIGSEGV));
        sigset_t u; sigemptyset(&u); sigaddset(&u, SIGUSR1); sigprocmask(SIG_UNBLOCK, &u, NULL);
    }

    /* 12: getcpu */
    {   unsigned cpu = 999, node = 999;
        long r = syscall(SYS_getcpu, &cpu, &node, NULL);
        int s = sched_getcpu();
        CHECK(r == 0 && (int)cpu >= 0 && (int)cpu < get_nprocs() && s >= 0,
              "getcpu -> %ld (cpu %u of %d, node %u), sched_getcpu -> %d", r, cpu, get_nprocs(), node, s);
    }

    /* 13: many faults */
    {   double t0 = now_s(); int bad = 0;
        for (int i = 0; i < 100000; i++) {
            uint64_t w = lxs_load(none + (i & 511) * 8);
            if (w != 0xC0FFEE) { bad++; break; }
            S.entries = 0;
        }
        double dt = now_s() - t0;
        CHECK(!bad, "100000 caught-and-resumed faults in %.3f s (%.2f us each)", dt, dt * 10.0);
    }

    /* 8: threads */
    {   g_none = mmap(NULL, NTHR * 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        pthread_t t[NTHR];
        for (int i = 0; i < NTHR; i++) pthread_create(&t[i], NULL, thr_main, (void *)(intptr_t)i);
        for (int i = 0; i < NTHR; i++) pthread_join(t[i], NULL);
        int bad = 0; for (int i = 0; i < NTHR; i++) bad += thr_bad[i];
        CHECK(bad == 0, "%d threads x %d faults at once: every one got its OWN si_addr (%d wrong)", NTHR, PER_THREAD, bad);
    }

    /* 9: sigaltstack */
    {   g_alt = mmap(NULL, g_alt_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        stack_t ss = { .ss_sp = g_alt, .ss_size = g_alt_sz, .ss_flags = 0 }, old;
        int r = sigaltstack(&ss, NULL);
        struct sigaction sa; memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = usr2_handler; sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
        sigaction(SIGUSR2, &sa, NULL);
        raise(SIGUSR2);
        sigaltstack(NULL, &old);
        CHECK(r == 0 && got_usr2 == SIGUSR2 && usr2_on_alt && usr2_ss_onstack && old.ss_sp == g_alt && old.ss_size == g_alt_sz,
              "SA_ONSTACK ran on the alternate stack (install %d, ran %d, on it %d, SS_ONSTACK inside %d, query back %d)",
              r, got_usr2 == SIGUSR2, usr2_on_alt, usr2_ss_onstack, old.ss_sp == g_alt);
        ss.ss_flags = SS_DISABLE; sigaltstack(&ss, NULL);
    }

    /* 10: fork keeps SA_SIGINFO */
    {   got_usr2 = 0; usr2_had_ctx = 0;
        pid_t p = fork();
        if (p == 0) { raise(SIGUSR2); _exit(got_usr2 == SIGUSR2 && usr2_had_ctx ? 0 : 1); }
        int st = -1; waitpid(p, &st, 0);
        CHECK(p > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0,
              "a forked child's SA_SIGINFO handler got siginfo + ucontext (status %#x)", st);
    }

    /* 11: sigsuspend */
    {   signal(SIGUSR1, usr1_count_handler);
        sigset_t b; sigemptyset(&b); sigaddset(&b, SIGUSR1);
        sigprocmask(SIG_BLOCK, &b, NULL);
        raise(SIGUSR1);                                   /* pending: blocked */
        sigset_t none_set; sigemptyset(&none_set);
        errno = 0;
        int r = sigsuspend(&none_set);
        int e = errno;
        sigset_t cur; sigprocmask(SIG_BLOCK, NULL, &cur);
        CHECK(r == -1 && e == EINTR && usr1_count == 1 && sigismember(&cur, SIGUSR1),
              "sigsuspend: -1/%s, handler ran %d time(s), original mask back (SIGUSR1 blocked %d)",
              e == EINTR ? "EINTR" : strerror(e), usr1_count, sigismember(&cur, SIGUSR1));
        sigprocmask(SIG_UNBLOCK, &b, NULL);
    }

    /* 7: nesting -- last, because the old kernel KILLS the process here */
    {   struct sigaction sa; memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = usr1_nested; sa.sa_flags = SA_SIGINFO;
        sigaction(SIGUSR1, &sa, NULL);
        nested_ptr = none + 64; nested_result = 0;
        memset(&S, 0, sizeof S);
        raise(SIGUSR1);
        CHECK(nested_result == 0xC0FFEE, "a fault INSIDE a SIGUSR1 handler was delivered and resumed (rax %#lx)",
              (unsigned long)nested_result);
    }

    printf("LXSIGCTX: RESULT %s (%d check(s) failed)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
