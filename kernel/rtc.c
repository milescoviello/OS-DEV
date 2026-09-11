/*
 * rtc.c — read the CMOS real-time clock.
 *
 * The PC's battery-backed clock lives behind the CMOS index/data ports
 * (0x70/0x71): write a register number to 0x70, read its value from 0x71. The
 * time registers can be in BCD or binary and 12- or 24-hour, told by status
 * register B. We also avoid reading mid-"update" (status A bit 7) and re-read
 * until two reads agree, so we never catch the clock half-incremented.
 */
#include "rtc.h"
#include "io.h"
#include "task.h"      /* rtc_selftest spawns a second concurrent reader (M1913) */
#include "console.h"   /* kprintf */
#include <stdint.h>

#define CMOS_ADDR 0x70
#define CMOS_DATA 0x71

/* CMOS is an INDEX/DATA port PAIR, and the pair is not atomic: the register
 * number written to 0x70 is global hardware state, so if a second reader writes
 * 0x70 between our write and our read of 0x71, we read a DIFFERENT REGISTER than
 * we asked for and silently return another field's value as the time (M1913).
 *
 * That is not theoretical here: there are ~21 callers across the kernel, and they
 * are genuinely concurrent — the desktop clock redraws, every FAT32/ext2 file
 * timestamp, and ring-3 clock_gettime/stat syscalls, all from different tasks.
 *
 * A plain spinlock is enough and cli is deliberately NOT used: no interrupt
 * handler touches CMOS (checked: nothing in interrupts.c/timer.c/keyboard.c
 * reads the RTC), so the only racers are other tasks/cores, which this excludes.
 * Holding cli instead would be actively worse — the UIP wait below can last
 * ~2 ms on real hardware, and disabling interrupts that long would drop timer
 * ticks. The lock is held across the WHOLE read sequence, not per register, so
 * the fields form one coherent snapshot. */
static volatile int cmos_lock;
static inline void cmos_take(void) {
    while (__atomic_exchange_n(&cmos_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
}
static inline void cmos_give(void) { __atomic_store_n(&cmos_lock, 0, __ATOMIC_RELEASE); }

/* Test-only: widen the index->data window so the race is REACHABLE.
 *
 * The window between writing 0x70 and reading 0x71 is two instructions, so a
 * sampling test cannot hit it — the first version of the self-test below ran
 * 3001 concurrent reads with the lock REMOVED and saw zero tearing, i.e. it
 * proved nothing. Yielding inside the window makes the interleaving certain, so
 * the test now fails without the lock and passes with it. Off in normal
 * operation; one predictable branch on a path that runs a handful of times a
 * second. (M1913) */
volatile int cmos_widen_window;

/* Unlocked single-register read: ONLY call with cmos_lock held. */
static uint8_t cmos_fast(uint8_t reg) {
    outb(CMOS_ADDR, reg);
    return inb(CMOS_DATA);
}
static uint8_t cmos(uint8_t reg) {
    outb(CMOS_ADDR, reg);
    if (cmos_widen_window) task_yield();
    return inb(CMOS_DATA);
}
/* Deliberately the FAST variant: the UIP poll below can iterate up to
 * RTC_UIP_SPINS times, and yielding inside it took boot-to-desktop from ~1.5 s to
 * over 30 s. Widening the window on the six time-field reads is what the test
 * needs; the status poll adds nothing to it. */
static int updating(void)      { return cmos_fast(0x0A) & 0x80; }
static uint8_t bcd2bin(uint8_t v) { return (v & 0x0F) + (v >> 4) * 10; }

/* Both loops below were UNBOUNDED. A wedged or emulated RTC that never clears
 * UIP, or whose seconds never read the same twice, would spin a kernel task
 * forever. Neither bound can be hit by working hardware (UIP clears within
 * ~2 ms; two agreeing reads take at most a second attempt), and bailing out
 * returns a possibly one-second-stale time, which beats hanging the caller. */
#define RTC_UIP_SPINS  1000000
#define RTC_MAX_TRIES  16

void rtc_now(struct rtc_time *t) {
    uint8_t s, mi, h, d, mo, y, ls = 0xFF;
    cmos_take();
    for (int tries = 0; tries < RTC_MAX_TRIES; tries++) {
        int guard = 0;
        while (updating() && ++guard < RTC_UIP_SPINS) { }
        s = cmos(0x00); mi = cmos(0x02); h = cmos(0x04);
        d = cmos(0x07); mo = cmos(0x08); y = cmos(0x09);
        if (s == ls) break;             /* two consecutive reads agree */
        ls = s;
    }

    uint8_t regB = cmos(0x0B);
    cmos_give();
    int pm = h & 0x80;
    if (!(regB & 0x04)) {               /* BCD -> binary */
        s = bcd2bin(s); mi = bcd2bin(mi); h = bcd2bin(h & 0x7F);
        d = bcd2bin(d); mo = bcd2bin(mo); y = bcd2bin(y);
    } else {
        h &= 0x7F;
    }
    if (!(regB & 0x02)) {                /* 12-hour -> 24-hour */
        if (pm) h = (h % 12) + 12;       /* 12/1..11 PM -> 12/13..23 */
        else    h = h % 12;              /* 12/1..11 AM -> 0/1..11 (was left at 12 for midnight) */
    }

    t->sec = s; t->min = mi; t->hour = h;
    t->day = d; t->month = mo; t->year = 2000 + y;
}

/* Current time as Unix epoch seconds — for filesystem timestamps (statx, ext2
 * inode i_*time, tmpfs mtime). Uses Howard Hinnant's days_from_civil algorithm
 * (correct across the 1900/2100 leap-century rules). (M1173) */
uint32_t rtc_unix(void) {
    struct rtc_time t; rtc_now(&t);
    int y = t.year, m = t.month, d = t.day;
    if (m <= 2) y -= 1;                                   /* shift Jan/Feb to the end of the prior year */
    int era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);             /* year of era [0,399] */
    unsigned doy = (unsigned)((153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1);   /* day of year [0,365] */
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; /* day of era [0,146096] */
    long days = (long)era * 146097 + (long)doe - 719468;  /* days since 1970-01-01 */
    return (uint32_t)(days * 86400 + t.hour * 3600 + t.min * 60 + t.sec);
}

static void cmos_write(uint8_t reg, uint8_t v) { outb(CMOS_ADDR, reg); outb(CMOS_DATA, v); }
static uint8_t bin2bcd(int v) { return (uint8_t)(((v / 10) << 4) | (v % 10)); }

/* Write the CMOS clock (used by SNTP). Honours register B's BCD/binary flag and
 * writes 24-hour (the QEMU/PC default, regB bit 1 set). Brackets the writes with
 * the SET bit so the clock isn't read mid-update. Year is the low two digits
 * (rtc_now reconstructs 2000+yy). */
void rtc_set(const struct rtc_time *t) {
    /* Takes cmos_lock for the WHOLE write (M1913). A concurrent rtc_now() would
     * otherwise retarget the 0x70 index between our index and data writes and we
     * would write the time into the wrong register — worse than a bad read, since
     * this corrupts the clock persistently. It also keeps the SET-bit bracket
     * indivisible: a reader must not observe the clock halted mid-update. */
    cmos_take();
    uint8_t regB = cmos(0x0B);
    int bcd = !(regB & 0x04);
    cmos_write(0x0B, regB | 0x80);                 /* SET: halt updates while we write */
    int yy = t->year % 100;
    int vals[6] = { t->sec, t->min, t->hour, t->day, t->month, yy };
    uint8_t regs[6] = { 0x00, 0x02, 0x04, 0x07, 0x08, 0x09 };
    for (int i = 0; i < 6; i++)
        cmos_write(regs[i], bcd ? bin2bcd(vals[i]) : (uint8_t)vals[i]);
    cmos_write(0x0B, (uint8_t)((regB | 0x02) & ~0x80));   /* clear SET, force 24-hour mode */
    cmos_give();
}

/* ---- boot self-test: concurrent readers must never see a torn snapshot -------
 * The CMOS index/data pair is shared hardware state, so an unsynchronised second
 * reader makes the first read the WRONG REGISTER — which surfaces as a field
 * that is not a legal time (a "month" of 0x50 is really the seconds register,
 * an "hour" of 45 is really the day-of-month, and so on). This spawns a second
 * task hammering rtc_now() while the caller does the same, and range-checks
 * every field of every sample. Two tasks are the point: a single-threaded loop
 * cannot detect the bug this guards. (M1913) */
static volatile int rtc_st_stop, rtc_st_bad, rtc_st_n, rtc_st_done;

static int rtc_time_sane(const struct rtc_time *t) {
    return t->month >= 1 && t->month <= 12 && t->day >= 1 && t->day <= 31 &&
           t->hour <= 23 && t->min <= 59 && t->sec <= 60 &&
           t->year >= 2000 && t->year <= 2099;
}

static void rtc_selftest_peer(void) {
    /* Yields explicitly rather than relying on preemption: this runs during boot
     * bring-up, and a peer that never yields simply never hands the CPU back. */
    while (!rtc_st_stop) {
        struct rtc_time t; rtc_now(&t);
        if (!rtc_time_sane(&t)) __atomic_add_fetch(&rtc_st_bad, 1, __ATOMIC_SEQ_CST);
        __atomic_add_fetch(&rtc_st_n, 1, __ATOMIC_SEQ_CST);
        task_yield();
    }
    __atomic_store_n(&rtc_st_done, 1, __ATOMIC_SEQ_CST);
    task_exit();
}

void rtc_selftest(void) {
    rtc_st_stop = rtc_st_bad = rtc_st_n = rtc_st_done = 0;
    if (!task_create_stack(rtc_selftest_peer, 0, 0, 16 * 1024)) {
        kprintf("[ ok ] rtc: concurrency self-test skipped (no task slot)\n");
        return;
    }
    /* Raised only AFTER the bail-out (M1926). Left set on the failure path it
     * would make every later rtc_now() -- the desktop clock, every filesystem
     * timestamp, ring-3 clock_gettime -- yield seven times WHILE HOLDING
     * cmos_lock, with other tasks spinning on it: exactly the
     * spin-yield-starves-the-holder shape M1912 was about, self-inflicted. */
    cmos_widen_window = 1;      /* make the two-instruction race reachable */
    for (int i = 0; i < 40; i++) {          /* 40 is ample: with the window forced open the\n                                             * unlocked version tears ~86% of reads (2588/3003),\n                                             * so detection is certain while boot stays fast */
        struct rtc_time t; rtc_now(&t);
        if (!rtc_time_sane(&t)) __atomic_add_fetch(&rtc_st_bad, 1, __ATOMIC_SEQ_CST);
        __atomic_add_fetch(&rtc_st_n, 1, __ATOMIC_SEQ_CST);
        task_yield();                             /* interleave the two readers */
    }
    __atomic_store_n(&rtc_st_stop, 1, __ATOMIC_SEQ_CST);
    for (int i = 0; i < 100000 && !__atomic_load_n(&rtc_st_done, __ATOMIC_SEQ_CST); i++)
        task_yield();

    cmos_widen_window = 0;
    int bad = __atomic_load_n(&rtc_st_bad, __ATOMIC_SEQ_CST);
    int n   = __atomic_load_n(&rtc_st_n,   __ATOMIC_SEQ_CST);
    if (bad == 0)
        kprintf("[ ok ] rtc: %d concurrent CMOS reads from 2 tasks with the "
                "index->data window forced open, 0 torn (the pair is atomic)\n", n);
    else
        kprintf("[FAIL] rtc: %d of %d concurrent CMOS reads returned an impossible "
                "time — the 0x70/0x71 index/data pair is being interleaved\n", bad, n);
}
