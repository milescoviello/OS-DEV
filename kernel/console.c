/*
 * console.c — console_putc + a small freestanding printf (kprintf).
 *
 * There is no libc here, so we write our own formatter. It supports the
 * conversions the kernel actually needs:
 *
 *   %s   string            %c   character        %%   literal percent
 *   %d/%i signed decimal    %u   unsigned decimal
 *   %x/%X hex (lower/upper)  %p   pointer (0x + 64-bit hex)
 *
 * with an optional field width and '0' padding flag (e.g. %08x), and the
 * length modifiers 'l' (long) and 'z' (size_t) — important because addresses
 * and sizes in a 64-bit kernel don't fit in an int.
 */
#include "console.h"
#include "smp.h"      /* smp_current_cpu — console lock re-entry guard (M1915) */
#include "task.h"     /* console_selftest spawns a concurrent logger (M1915) */
#include "vga.h"
#include "serial.h"
#include "fbcon.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

static bool gfx_console;
/* THE DESKTOP AND THE FRAMEBUFFER CONSOLE ARE THE SAME PIXELS (M2011).
 *
 * fbcon draws into the linear framebuffer and SCROLLS it when it reaches the
 * bottom -- which means every kernel log line printed after the window manager
 * takes over shifts the whole desktop up by one text row, until the WM's next
 * full redraw puts it back. Reported as "the desktop jumped around a lot, like
 * the whole thing moving", and it is exactly that: a 43-line stall dump moved
 * the desktop up 690 pixels in one go.
 *
 * Nothing is lost by stopping: every byte still goes to the serial port (which
 * is what every headless test greps) and into the /proc/kmsg ring (which is
 * what `dmesg` reads). Only the drawing stops. A panic takes the screen back,
 * because a panic nobody can see is worse than a scrolled desktop. */
static bool gfx_owned;

/* ---- kernel log ring buffer (M1071) -----------------------------------------
 * Every byte that goes to the console is also captured into a fixed circular
 * buffer, so userspace can read the kernel log back as /proc/kmsg (a `dmesg`)
 * even after it has scrolled off-screen. Lock-free by design: a single
 * monotonically-increasing head index + plain byte writes, so it is safe to
 * call from IRQ / kprintf / panic context with no risk of deadlock. A reader
 * may see a torn tail byte under a concurrent write; that is acceptable for a
 * log. */
#define KLOG_SIZE 65536
static char klog[KLOG_SIZE];
static volatile uint32_t klog_head;          /* total bytes ever written (wraps the buffer) */

static void klog_putc(char c) {
    klog[klog_head % KLOG_SIZE] = c;
    klog_head++;
}

/* Copy the most recent log bytes (oldest-first) into out[max], NUL-terminated.
 * Returns the number of bytes written (excluding the NUL). */
int klog_copy(char *out, int max) {
    if (!out || max <= 1) return 0;
    uint32_t head  = klog_head;               /* snapshot the head once */
    uint32_t avail = head < KLOG_SIZE ? head : KLOG_SIZE;
    if (avail > (uint32_t)(max - 1)) avail = (uint32_t)(max - 1);
    uint32_t start = head - avail;            /* oldest byte we will return */
    int n = 0;
    for (uint32_t i = 0; i < avail; i++)
        out[n++] = klog[(start + i) % KLOG_SIZE];
    out[n] = 0;
    return n;
}

/* Append userspace bytes to the kernel log ring (the /dev/kmsg writer, M1216),
 * so init scripts / apps can log into `dmesg`. A trailing newline is ensured so
 * each write is its own log line. */
void klog_write(const char *buf, int n) {
    for (int i = 0; i < n; i++) klog_putc(buf[i]);
    if (n == 0 || buf[n - 1] != '\n') klog_putc('\n');
}

/* ---- console capture (M1870) ------------------------------------------------
 * A single-consumer sink so the network debug console (netcon.c) can capture the
 * output of a kprintf-based dumper (e.g. pci_enumerate) into a buffer and ship it
 * over the socket, instead of only to the screen/serial. Best-effort: another
 * core's kprintf during a capture window interleaves into the buffer, which is
 * fine for diagnostics. Bracket the buffer's lifetime with begin()/end(). */
static char *g_cap; static int g_cap_max, g_cap_n;
void console_capture_begin(char *buf, int max) { g_cap_n = 0; g_cap_max = max; g_cap = buf; }
int  console_capture_end(void)   { int n = g_cap_n; g_cap = 0; return n; }

void console_init(void) {
    serial_init();
    vga_init();
}

void console_enable_gfx(void) {
    gfx_console = true;
}
void console_gfx_release(void) { gfx_owned = true; }    /* the WM owns the screen: log to serial only */
void console_gfx_reclaim(void) { gfx_owned = false; }   /* a panic/exception must be visible on screen */

/* PANIC MODE (M2080): the console must not be able to swallow a panic.
 *
 * The panic path disables interrupts on its own core FOR LIFE and then calls
 * kprintf a dozen times. Everything about that is hostile to the normal
 * locking discipline:
 *
 *   - con_lock's owner is a TASK, not a core, and M1926 deliberately takes it
 *     with interrupts ON so serial_putc's ~87us/byte does not eat a tick. So a
 *     holder can be preempted -- and a panicking core can neither be scheduled
 *     to wait for it nor answer an IPI to get it released.
 *   - console_gfx_reclaim() routes output to fbcon, whose newline scrolls the
 *     whole framebuffer: 4.9 MB of memmove per line, inside the lock.
 *   - CON_SPIN_LIMIT is 40,000,000 and does NOT accumulate, so each of the
 *     dozen panic kprintf calls pays it again. Twelve times forty million
 *     `pause` iterations under TCG is minutes of silence, which is
 *     indistinguishable from a wedge.
 *
 * Measured: three runs in four on -smp 4 produced no panic text at all.
 *
 * In panic mode nothing takes the lock and fbcon stops scrolling. Output can
 * interleave with another core's final bytes for a moment before the NMI stops
 * them, which is strictly the better outcome -- the same trade M1941 already
 * made, and the same one this file's own comment demands: a lock must never be
 * able to silence the panic path. */
static volatile int panic_mode;
static volatile unsigned panic_lock_attempts;
void console_panic_mode(void) { panic_mode = 1; }
int  console_in_panic(void) { return panic_mode; }
unsigned console_panic_lock_attempts(void) { return panic_lock_attempts; }

void console_putc(char c) {
    if (gfx_console) {
        if (!gfx_owned) fbcon_putc(c);   /* framebuffer console (silent while the WM owns it) */
    } else
        vga_putc(c);         /* legacy VGA text mode */
    klog_putc(c);            /* capture into the kernel log ring (M1071) */
    if (g_cap && g_cap_n < g_cap_max - 1) g_cap[g_cap_n++] = c;   /* netcon capture (M1870) */
    if (c == '\n')
        serial_putc('\r');   /* terminals want CRLF; the screen doesn't care */
    serial_putc(c);
}

/* ---- console serialization (M1915) -------------------------------------------
 * kprintf had NO lock, so two tasks logging at once interleaved CHARACTER BY
 * CHARACTER. Real captured output from this kernel:
 *     MARGIN.HTM  (1477 bytes)[hb] ticks=164 n=4 | id6 st=1; ...
 * That is two tasks' lines spliced together. It is not cosmetic: it corrupts the
 * serial log that every headless test greps, and this project previously
 * attributed exactly this shape ("foreign lines bleeding into a suite's block")
 * to harness timing rather than to the kernel.
 *
 * A whole formatted line is emitted under one lock. Interrupts are disabled for
 * the duration, which is what makes it deadlock-free: a same-core IRQ handler
 * cannot arrive mid-line and try to take a lock we are holding, and another
 * core's handler simply spins until we release. The honest cost is that
 * interrupts stay off for one line of output, and serial_putc busy-waits on the
 * UART (~87 us/byte at 115200 on real hardware) — acceptable because the kernel
 * logs at boot and during tests, not in steady-state hot paths, and garbled logs
 * have already cost real debugging time.
 *
 * con_owner makes re-entry on the SAME core (a fault or NMI raised while we are
 * inside a log call) print rather than deadlock — the panic path must never be
 * silenced by this lock. */
static volatile int con_lock;
static volatile int con_owner = -1;      /* TASK currently emitting, -1 = none */

/* Owner is the TASK, not the core, and interrupts are NOT disabled (M1926).
 *
 * M1915 held `cli` for the whole line to stop a preemption splitting it. That
 * worked, but `serial_putc` busy-waits on the UART (~87 us/byte at 115200), so an
 * 80-char line meant ~7 ms with interrupts off -- most of a 100 Hz tick, every
 * line, on the bare-metal target this project boots on. Dropped ticks and
 * serial-RX overruns on netcon (the primary bare-metal debug channel) are a real
 * price to pay for a log.
 *
 * Keying the owner on the task instead makes `cli` unnecessary:
 *   - a task preempted INTO while another holds the lock sees a different owner
 *     and spins, so lines still never interleave (and M1912 guarantees the holder
 *     cannot be starved by that spinning);
 *   - an interrupt handler on the same core runs in the interrupted task's
 *     context, so it sees ITSELF as owner and proceeds instead of deadlocking.
 *     Its output may interleave in that rare case, which is the right trade: a
 *     lock must never be able to silence a fault or the panic path. */
/* The spin is BOUNDED (M1941), and on timeout we print ANYWAY.
 *
 * Every exception gate is 0x8E -- an interrupt gate, which CLEARS IF -- so a
 * fault handler runs with interrupts disabled. If the task holding this lock
 * happens to be on the SAME core, it can never be scheduled to release it, and
 * an unbounded spin here is a hard deadlock that also SWALLOWS the fault
 * report. That is the exact failure this file's own comment above says must
 * never happen: a lock must not be able to silence a fault or the panic path.
 *
 * Measured, not theorised: a ring-3 fault raised while the boot task was
 * mid-way through printing a directory listing wedged the machine with all
 * four cores stuck and no `[fault]` line ever appearing -- RIP sampling through
 * the QEMU monitor showed a constant address inside this very loop.
 *
 * Giving up and writing unlocked risks interleaved output, which is strictly
 * the better outcome and is the same trade already made for the same-core
 * interrupt case. The bound is large enough that real contention (another core
 * finishing a line) always wins the lock normally. */
#define CON_SPIN_LIMIT 40000000u
static inline int con_take(uint64_t *fl) {
    int me = task_current_id();
    *fl = 0;
    /* THE INSTRUMENT ASSERTS ITS OWN INVARIANT (M2080). Nothing may take this
     * lock once a panic is printing. Counted rather than printed, because
     * printing from inside the lock's own acquire path would recurse through
     * kvprintf; the panic path reports the tally on its way out, so a future
     * code path that violates this says so instead of hanging. */
    if (panic_mode) { panic_lock_attempts++; return 0; }
    if (con_owner == me && con_lock) return 0;           /* re-entered: don't block */
    for (uint32_t i = 0; i < CON_SPIN_LIMIT; i++) {
        if (!__atomic_exchange_n(&con_lock, 1, __ATOMIC_ACQUIRE)) {
            con_owner = me;
            return 1;
        }
        __asm__ volatile("pause");
    }
    return 0;   /* never acquired -> con_give must NOT release someone else's lock */
}
static inline void con_give(int held, uint64_t f) {
    (void)f;
    if (held) { con_owner = -1; __atomic_store_n(&con_lock, 0, __ATOMIC_RELEASE); }
}

/* Write exactly `n` bytes, taking the console lock ONCE for the whole run
 * (M1952). console_putc is the unlocked primitive, so a caller looping over it
 * per character can be spliced mid-string by any other task's output -- the
 * same failure M1913 fixed for kprintf. The Linux ABI's write()/writev() hit
 * this: a program's line came out with kernel log text inserted into the
 * middle of it, which is both unreadable and invisible to a log assertion. */
void console_write_n(const char *s, unsigned long n) {
    uint64_t f; int held = con_take(&f);
    for (unsigned long i = 0; i < n; i++) console_putc(s[i]);
    con_give(held, f);
}

void console_write(const char *s) {
    uint64_t f; int held = con_take(&f);
    for (; *s; s++)
        console_putc(*s);
    con_give(held, f);
}

/* ---- number formatting ------------------------------------------------- */

/* Print `value` in the given base, right-justified in `width` using `pad`. */
static void print_uint(uint64_t value, unsigned base, bool upper,
                       int width, char pad) {
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char buf[32];
    int n = 0;

    if (value == 0)
        buf[n++] = '0';
    while (value) {
        buf[n++] = digits[value % base];
        value /= base;
    }

    for (int i = n; i < width; i++)   /* leading padding */
        console_putc(pad);
    while (n > 0)                     /* digits come out reversed */
        console_putc(buf[--n]);
}

/* ---- the formatter ----------------------------------------------------- */

void kvprintf(const char *fmt, va_list ap) {
    uint64_t f_; int held_ = con_take(&f_);
    for (; *fmt; fmt++) {
        if (*fmt != '%') {
            console_putc(*fmt);
            continue;
        }

        fmt++;                                  /* skip '%' */

        char pad = ' ';
        if (*fmt == '0') { pad = '0'; fmt++; }

        int width = 0;
        while (*fmt >= '0' && *fmt <= '9')
            width = width * 10 + (*fmt++ - '0');

        int lng = 0;                            /* 0=int, 1=long, 2=size_t */
        if (*fmt == 'l') { lng = 1; fmt++; if (*fmt == 'l') fmt++; }
        else if (*fmt == 'z') { lng = 2; fmt++; }

        switch (*fmt) {
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s) s = "(null)";
            while (*s) console_putc(*s++);
            break;
        }
        case 'c':
            console_putc((char)va_arg(ap, int));
            break;
        case 'd':
        case 'i': {
            long v = (lng == 0) ? va_arg(ap, int) : va_arg(ap, long);
            if (v < 0) { console_putc('-'); v = -v; }
            print_uint((uint64_t)v, 10, false, width, pad);
            break;
        }
        case 'u': {
            uint64_t v = (lng == 0) ? va_arg(ap, unsigned)
                                    : va_arg(ap, unsigned long);
            print_uint(v, 10, false, width, pad);
            break;
        }
        case 'x':
        case 'X': {
            uint64_t v = (lng == 0) ? va_arg(ap, unsigned)
                                    : va_arg(ap, unsigned long);
            print_uint(v, 16, *fmt == 'X', width, pad);
            break;
        }
        case 'p':
            console_putc('0'); console_putc('x');
            print_uint((uint64_t)(uintptr_t)va_arg(ap, void *),
                       16, false, 16, '0');
            break;
        case '%':
            console_putc('%');
            break;
        default:                                /* unknown: print verbatim */
            console_putc('%');
            console_putc(*fmt);
            break;
        }
    }
    con_give(held_, f_);
}

void kprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    kvprintf(fmt, ap);
    va_end(ap);
}

/* ---- boot self-test: a log line must never be spliced (M1915) ----------------
 * Two tasks emit distinctive fixed lines as fast as they can. With the console
 * lock working, every "[cs]" line in the serial log is all-A or all-B. Without
 * it, lines come out spliced, which the host-side check in run-boot-tests.sh
 * detects — the assertion has to live on the host because the corruption is in
 * the log stream itself, which the guest cannot see.
 *
 * Every line is the same length and printed with ONE kprintf, so any mixture of
 * A and B on one line is proof the emission was not atomic. */
static volatile int cs_stop, cs_done;
/* Long lines on purpose: a splice can only happen if a preemption lands INSIDE
 * one emission, so the detection rate scales with how long the critical section
 * is. 48-char lines gave only ~1 splice per boot when the lock was removed,
 * which is too thin a margin for a regression gate; ~360 chars gives many. */
static const char cs_ayes[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static const char cs_bees[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

static void console_selftest_peer(void) {
    for (int i = 0; i < 24 && !cs_stop; i++) {
        kprintf("[cs] %s\n", cs_bees);
        task_yield();
    }
    __atomic_store_n(&cs_done, 1, __ATOMIC_SEQ_CST);
    task_exit();
}

/* -append selftest: THE PANIC PATH MUST NOT WAIT FOR A LOCK IT CANNOT WIN (M2080).
 *
 * The `kstackover` symptom test does NOT discriminate this fix, and saying so
 * is the point: a deliberate kernel-stack overflow panics on a QUIET console,
 * where no other core happens to be holding con_lock, so it prints fine either
 * way. Four runs passed with the bypass and four passed without it. The wedge
 * that cost three runs in four needed the other half of the picture -- a core
 * holding the lock inside fb_scroll's 4.9 MB memmove while the panicking core
 * spins with interrupts off, which a test cannot reliably schedule.
 *
 * So assert the INVARIANT instead of waiting for the symptom: with a FOREIGN
 * owner holding the lock, a print in panic mode must refuse the lock rather
 * than spin for it, and must leave the foreigner's lock exactly as it found it.
 *
 * `con_lock`/`con_owner` are poked directly because that is the only way to
 * stage a foreign holder deterministically from one core. Everything is put
 * back before returning. */
void console_panic_selftest(void) {
    int fails = 0, checks = 0;
    unsigned before = panic_lock_attempts;
    int save_lock = con_lock, save_owner = con_owner;

    /* Stage a holder that is definitely not us. */
    con_owner = 0x7FFFFFFF;
    __atomic_store_n(&con_lock, 1, __ATOMIC_RELEASE);
    panic_mode = 1;

    /* This print must come straight back. On the reverted code con_take spins
     * CON_SPIN_LIMIT times first -- bounded, but forty million `pause`
     * iterations per line, which under TCG is the difference between a report
     * and a wedge. */
    kprintf("[conlock] a report-mode print issued with a FOREIGN lock holder\n");

    checks++;
    if (panic_lock_attempts <= before) {
        panic_mode = 0;
        kprintf("[conlock] FAIL report mode did not REFUSE the console lock -- "
                "the fault reporter is waiting for a lock a stopped core still holds\n");
        fails++;
    } else {
        panic_mode = 0;
        kprintf("[conlock] ok   a report-mode print refuses the lock instead of spinning for it\n");
    }

    checks++;
    if (!con_lock || con_owner != 0x7FFFFFFF) {
        kprintf("[conlock] FAIL the bypass DISTURBED the foreign holder's lock "
                "(lock=%d owner=%d)\n", con_lock, con_owner);
        fails++;
    } else
        kprintf("[conlock] ok   ...and left the foreign holder's lock untouched\n");

    /* Put it back exactly as it was. */
    con_owner = save_owner;
    __atomic_store_n(&con_lock, save_lock, __ATOMIC_RELEASE);
    panic_lock_attempts = before;
    panic_mode = 0;

    /* The tag deliberately avoids the word the boot suite forbids: a crash
     * guard that greps the log for it must not be weakened so a test can name
     * itself conveniently. */
    kprintf("[conlock] %s (%d checks)\n",
            fails ? "CONLOCKSELFTEST FAILED" : "CONLOCKSELFTEST PASSED", checks);
}

void console_selftest(void) {
    cs_stop = cs_done = 0;
    if (!task_create_stack(console_selftest_peer, 0, 0, 16 * 1024)) {
        kprintf("[ ok ] console: log-splicing self-test skipped (no task slot)\n");
        return;
    }
    for (int i = 0; i < 24; i++) {
        kprintf("[cs] %s\n", cs_ayes);
        task_yield();
    }
    __atomic_store_n(&cs_stop, 1, __ATOMIC_SEQ_CST);
    for (int i = 0; i < 100000 && !__atomic_load_n(&cs_done, __ATOMIC_SEQ_CST); i++)
        task_yield();
    kprintf("[ ok ] console: emitted 48 long interleaved log lines from 2 tasks "
            "(host checks none were spliced)\n");
}
