/*
 * procfs.c — synthetic /proc and /dev, generated from live kernel state.
 *
 * A recognized hobby-OS / r/osdev milestone: the Unix "everything is a file"
 * idiom. Because our VFS dispatches by NAME (not fd), the vfs layer just routes
 * paths under /proc and /dev to the generators here — no per-process fd table
 * needed. Reads format live data (RAM from the PMM, uptime from the timer, the
 * CPU via CPUID, the process count) into the caller buffer; the /dev nodes are
 * the classic null / zero / random / full. Bounded string builders; read-only
 * for /proc, and /dev writes either discard (null) or fail (full).
 */
#include "procfs.h"
#include "virtio_gpu.h"   /* is there a GPU behind /dev/dri/renderD128? (M2351) */
#include "pmm.h"
#include "vmm.h"
#include "timer.h"
#include "task.h"
#include "app.h"
#include "smp.h"
#include "kheap.h"
#include "blockdev.h"
#include "interrupts.h"
#include "console.h"
#include "random.h"
#include "ksyms.h"
#include "net.h"
#include "fsevents.h"
#include "acpi.h"   /* aml_count/aml_obj for /proc/acpi (M1285) */
#include "profile.h"
#include "mbox.h"
#include "measure.h"
#include "cas.h"
#include "fw.h"
#include "notify.h"
#include "eventfd.h"
#include "strace.h"
#include "bpf.h"
#include "swap.h"
#include "shm.h"
#include "mqueue.h"
#include "sysvipc.h"
#include "unixsock.h"
#include "flock.h"
#include <stdint.h>

extern int task_count(void);   /* kernel/task.c */
extern uint64_t task_ctxt_count(void);                          /* /proc/stat aggregates (M1253) */
extern uint64_t task_total_spawned(void);
extern void task_percore_times(int core, uint64_t *user_ms, uint64_t *sys_ms, uint64_t *idle_ms);   /* M1538 */
extern int task_runnable_count(void);
extern int task_blocked_count(void);
extern uint64_t rtc_unix(void);            /* current epoch seconds — for btime (M1253) */
extern int smp_cpu_count;                  /* CPUs online (kernel/smp.c) */

/* ---- tiny bounded string/number appenders -------------------------------- */
static int sapp(char *b, int p, int max, const char *s) {
    while (*s && p < max - 1) b[p++] = *s++;
    return p;
}
static int sdec(char *b, int p, int max, uint64_t v) {
    char t[24]; int n = 0;
    if (v == 0) t[n++] = '0';
    while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
    while (n > 0 && p < max - 1) b[p++] = t[--n];
    return p;
}
/* two-digit fractional centiseconds for uptime "S.cc" */
static int sdec2(char *b, int p, int max, uint64_t v) {
    if (p < max - 1) b[p++] = (char)('0' + (v / 10) % 10);
    if (p < max - 1) b[p++] = (char)('0' + v % 10);
    return p;
}

static int peq(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == *b;
}
static int startswith(const char *s, const char *pre) {
    while (*pre) { if (*s++ != *pre++) return 0; }
    return 1;
}

static void cpuid(uint32_t leaf, uint32_t sub, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    __asm__ volatile("cpuid" : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d) : "a"(leaf), "c"(sub));
}

/* ---- /proc generators ----------------------------------------------------- */
/* /proc/acpi (M1285): the ACPI AML namespace decoded from the DSDT (M1284) —
 * a browsable object list (TYPE<TAB>NAME), like acpidump's namespace view. */
static long gen_acpi(char *b, int max) {
    static const char *tn[] = { "?", "Scope", "Device", "Method", "Name", "OpRegion",
                                "Field", "Processor", "PowerRes", "ThermalZone", "Mutex", "Event" };
    int total = aml_count(0), dev = aml_count(AML_DEVICE), mth = aml_count(AML_METHOD);
    int p = 0;
    p = sapp(b, p, max, "DSDT AML namespace: "); p = sdec(b, p, max, (uint64_t)total);
    p = sapp(b, p, max, " objects ("); p = sdec(b, p, max, (uint64_t)dev); p = sapp(b, p, max, " devices, ");
    p = sdec(b, p, max, (uint64_t)mth); p = sapp(b, p, max, " methods)\n");
    char nm[5];
    for (int i = 0; i < total && p < max - 24; i++) {
        int t = aml_obj(i, nm); if (t < 0) break;
        p = sapp(b, p, max, (t >= 1 && t <= 11) ? tn[t] : "?");
        p = sapp(b, p, max, "\t"); p = sapp(b, p, max, nm); p = sapp(b, p, max, "\n");
    }
    b[p] = 0; return p;
}
/* MEMAVAILABLE WAS MISSING, AND THAT MEANT "NO MEMORY" (M2066).
 *
 * This reported three lines: MemTotal, MemFree, and a MemUsed that Linux does
 * not have. Every Linux memory-pressure estimator written in the last decade
 * reads **MemAvailable** -- it is the field that exists precisely so a program
 * does not have to guess how much of Cached is reclaimable. A reader that
 * scans for it and does not find it gets zero, and zero available memory is
 * not "unknown", it is CRITICAL PRESSURE.
 *
 * JavaScriptCore's MemoryPressureHandler does exactly that. Told the machine
 * has nothing left, it collects continuously and never returns to running the
 * program -- which is what Claude Code was doing: alive, its event loop
 * ticking about four times a second, no network, no output, and a fresh batch
 * of three `HeapHelper` GC marker threads spawning and dying every few
 * seconds, for ever. Nothing faulted and nothing was logged, because from the
 * kernel's side every answer was a success.
 *
 * So report what Linux reports. Buffers and Cached are honestly 0 here -- this
 * kernel has a block cache but does not account it as reclaimable page cache --
 * and MemAvailable is therefore MemFree, which is the truth rather than a
 * flattering estimate. MemUsed stays at the end: it is not a Linux field, but
 * three of our own programs (httpd, shell's `mem`, sysgraph) parse it
 * positionally and there is no reason to break them. */
static long gen_meminfo(char *b, int max) {
    uint64_t total = pmm_total_bytes() / 1024, freeb = pmm_free_bytes() / 1024;
    int p = 0;
    p = sapp(b, p, max, "MemTotal:     "); p = sdec(b, p, max, total); p = sapp(b, p, max, " kB\n");
    p = sapp(b, p, max, "MemFree:      "); p = sdec(b, p, max, freeb); p = sapp(b, p, max, " kB\n");
    p = sapp(b, p, max, "MemUsed:      "); p = sdec(b, p, max, total - freeb); p = sapp(b, p, max, " kB\n");
    p = sapp(b, p, max, "MemAvailable: "); p = sdec(b, p, max, freeb); p = sapp(b, p, max, " kB\n");
    p = sapp(b, p, max, "Buffers:      "); p = sdec(b, p, max, 0);     p = sapp(b, p, max, " kB\n");
    p = sapp(b, p, max, "Cached:       "); p = sdec(b, p, max, 0);     p = sapp(b, p, max, " kB\n");
    p = sapp(b, p, max, "SwapCached:   "); p = sdec(b, p, max, 0);     p = sapp(b, p, max, " kB\n");
    p = sapp(b, p, max, "Active:       "); p = sdec(b, p, max, total - freeb); p = sapp(b, p, max, " kB\n");
    p = sapp(b, p, max, "Inactive:     "); p = sdec(b, p, max, 0);     p = sapp(b, p, max, " kB\n");
    p = sapp(b, p, max, "SwapTotal:    "); p = sdec(b, p, max, 0);     p = sapp(b, p, max, " kB\n");
    p = sapp(b, p, max, "SwapFree:     "); p = sdec(b, p, max, 0);     p = sapp(b, p, max, " kB\n");
    p = sapp(b, p, max, "Shmem:        "); p = sdec(b, p, max, 0);     p = sapp(b, p, max, " kB\n");
    b[p] = 0; return p;
}
static long gen_uptime(char *b, int max) {
    uint64_t ms = timer_ms();
    int p = 0;
    p = sdec(b, p, max, ms / 1000); b[p < max-1 ? p++ : p] = '.'; p = sdec2(b, p, max, (ms % 1000) / 10);
    p = sapp(b, p, max, " ");
    p = sdec(b, p, max, ms / 1000); b[p < max-1 ? p++ : p] = '.'; p = sdec2(b, p, max, (ms % 1000) / 10);
    p = sapp(b, p, max, "\n");
    b[p] = 0; return p;
}
static long gen_cpuinfo(char *b, int max) {
    uint32_t a, x, c, d;
    int p = 0;
    /* number of CPUs the kernel brought online at boot (BSP + APs, M1197) */
    p = sapp(b, p, max, "processors\t: "); p = sdec(b, p, max, (uint64_t)smp_cpu_count); p = sapp(b, p, max, "\n");
    /* the boot parallel self-test: how many cores ran a chunk + whether it matched (M1198) */
    if (smp_cpu_count > 1) {
        p = sapp(b, p, max, "smp parallel\t: "); p = sdec(b, p, max, (uint64_t)smp_selftest_cores);
        p = sapp(b, p, max, " cores, sum self-test "); p = sapp(b, p, max, smp_selftest_ok ? "OK\n" : "FAIL\n");
    }
    /* vendor string (leaf 0: EBX, EDX, ECX) */
    char vendor[13];
    cpuid(0, 0, &a, &x, &c, &d);
    *(uint32_t *)&vendor[0] = x; *(uint32_t *)&vendor[4] = d; *(uint32_t *)&vendor[8] = c;
    vendor[12] = 0;
    p = sapp(b, p, max, "vendor_id\t: "); p = sapp(b, p, max, vendor); p = sapp(b, p, max, "\n");
    /* brand string (leaves 0x80000002..4) */
    char brand[49]; int bi = 0;
    for (uint32_t leaf = 0x80000002u; leaf <= 0x80000004u; leaf++) {
        cpuid(leaf, 0, &a, &x, &c, &d);
        *(uint32_t *)&brand[bi] = a; *(uint32_t *)&brand[bi+4] = x;
        *(uint32_t *)&brand[bi+8] = c; *(uint32_t *)&brand[bi+12] = d; bi += 16;
    }
    brand[48] = 0;
    const char *bp = brand; while (*bp == ' ') bp++;     /* trim leading spaces */
    p = sapp(b, p, max, "model name\t: "); p = sapp(b, p, max, bp); p = sapp(b, p, max, "\n");
    /* a few feature flags from leaf 1 */
    cpuid(1, 0, &a, &x, &c, &d);
    p = sapp(b, p, max, "flags\t\t:");
    if (d & (1u<<0))  p = sapp(b, p, max, " fpu");
    if (d & (1u<<4))  p = sapp(b, p, max, " tsc");
    if (d & (1u<<5))  p = sapp(b, p, max, " msr");
    if (d & (1u<<6))  p = sapp(b, p, max, " pae");
    if (d & (1u<<9))  p = sapp(b, p, max, " apic");
    if (d & (1u<<23)) p = sapp(b, p, max, " mmx");
    if (d & (1u<<25)) p = sapp(b, p, max, " sse");
    if (d & (1u<<26)) p = sapp(b, p, max, " sse2");
    if (c & (1u<<0))  p = sapp(b, p, max, " sse3");
    if (c & (1u<<19)) p = sapp(b, p, max, " sse4_1");
    if (c & (1u<<28)) p = sapp(b, p, max, " avx");
    if (c & (1u<<30)) p = sapp(b, p, max, " rdrand");
    p = sapp(b, p, max, "\n");
    b[p] = 0; return p;
}
static long gen_version(char *b, int max) {
    int p = sapp(b, 0, max, "OS-DEV version 1.0 (x86_64) - a from-scratch kernel, built " __DATE__ " " __TIME__ "\n");
    b[p] = 0; return p;
}
static long gen_mqueue(char *b, int max) { return mqueue_format(b, max); }   /* open priority msg queues (M1154) */
/* SysV IPC (M1159/1160/1161): semaphore sets, message queues, shm segments --
 * the latter two had no formatter anywhere until M1619, so 2/3 of a fully-
 * implemented IPC family was invisible to introspection. */
static long gen_sysvipc(char *b, int max) {
    long p = sysv_sem_format(b, max);
    if (p < max) p += sysv_msg_format(b + p, max - (int)p);
    if (p < max) p += sysv_shm_format(b + p, max - (int)p);
    return p;
}
static long gen_unix(char *b, int max) { return unix_format(b, max); }       /* AF_UNIX listeners + connections (M1169) */
static long gen_locks(char *b, int max) { return flock_format(b, max); }     /* advisory file locks (M1177) */
static long gen_loadavg(char *b, int max) {     /* real 1/5/15-min run-queue load average (M1148) */
    uint64_t la[3]; task_loadavg(la);           /* fixed-point, FSHIFT=11 (FIXED_1 = 2048) */
    int p = 0;
    for (int i = 0; i < 3; i++) {
        p = sdec(b, p, max, la[i] >> 11);                    /* integer part */
        if (p < max - 1) b[p++] = '.';
        p = sdec2(b, p, max, ((la[i] & 2047) * 100) >> 11);  /* two fractional digits */
        if (p < max - 1) b[p++] = ' ';
    }
    p = sdec(b, p, max, (uint64_t)task_runnable_count());    /* runnable now / total tasks */
    if (p < max - 1) b[p++] = '/';
    p = sdec(b, p, max, (uint64_t)task_count());
    p = sapp(b, p, max, " 0\n");                             /* last-pid field (stub) */
    b[p] = 0; return p;
}
static long gen_processes(char *b, int max) {
    task_info_t ti[24];
    int cnt = task_snapshot(ti, 24);
    static const char *st[5] = { "ready", "run  ", "block", "dead ", "stop " };
    int p = sapp(b, 0, max, "  PID  STATE  NAME\n");
    for (int i = 0; i < cnt; i++) {
        if (ti[i].state == 3) continue;                 /* skip dead */
        p = sapp(b, p, max, "  ");
        p = sdec(b, p, max, (uint64_t)ti[i].id);
        p = sapp(b, p, max, "    ");
        p = sapp(b, p, max, st[(unsigned)ti[i].state < 5 ? ti[i].state : 0]);
        p = sapp(b, p, max, "  ");
        p = sapp(b, p, max, ti[i].proc ? app_title((app_t *)ti[i].proc) : "(kernel)");
        p = sapp(b, p, max, "\n");
    }
    b[p] = 0; return p;
}
static long gen_partitions(char *b, int max) {   /* the block-device + FAT32-volume map (same data as `lsblk`) */
    return blockdev_format(b, max);
}
static long gen_bcache(char *b, int max) {       /* the disk buffer-cache stats (M1095) */
    return blockdev_cache_format(b, max);
}
static long gen_measure(char *b, int max) {      /* measured-boot PCRs + event log (M1096) */
    return measure_format(b, max);
}
static long gen_cas(char *b, int max) {          /* content-addressed store stats (M1097) */
    return cas_format(b, max);
}
static long gen_fw(char *b, int max) {           /* packet-filter rules + hit counts (M1100) */
    return fw_format(b, max);
}
static long gen_notify(char *b, int max) {       /* notification objects + pending masks (M1101) */
    return notify_format(b, max);
}
static long gen_events(char *b, int max) {       /* eventfd counters (M1113) */
    return eventfd_format(b, max);
}
static long gen_swaps(char *b, int max) {        /* swap device + page-out/in stats (M1105) */
    return swap_format(b, max);
}
static long gen_shm(char *b, int max) {          /* named shared-memory objects (M1108) */
    return shm_format(b, max);
}
static long gen_bpf(char *b, int max) {          /* eBPF-lite program + run/drop counters (M1127) */
    return bpf_format(b, max);
}
static long gen_syscalls(char *b, int max) {     /* syscount: the eBPF tracepoint histogram, named (M1203) */
    return syscall_histogram_format(b, max);
}
static long gen_filesystems(char *b, int max) {
    int p = sapp(b, 0, max, "nodev\tprocfs\nnodev\tdevfs\n      \tfat32\n");
    b[p] = 0; return p;
}
static long gen_mounts(char *b, int max) {
    /* This used to say fat32 was mounted on /, which is true for the NATIVE
     * side and false for every Linux process -- they see the ext2 volume as
     * their root. Two different answers to the same question in the same
     * kernel is the kind of thing a program resolves by believing the wrong
     * one, so this now matches /proc/self/mounts exactly. (M2013) */
    int p = sapp(b, 0, max,
        "/dev/sda2 / ext2 rw,relatime 0 0\n"
        "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
        "devtmpfs /dev devtmpfs rw,nosuid,mode=755 0 0\n"
        "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
        "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n");
    b[p] = 0; return p;
}
static long gen_interrupts(char *b, int max) {
    static const char *names[16] = {
        "timer", "keyboard", "cascade", "COM2", "COM1", "LPT2", "floppy", "LPT1",
        "RTC", "irq9", "irq10", "irq11", "mouse", "FPU", "ATA0", "ATA1"
    };
    int p = sapp(b, 0, max, "  IRQ  COUNT       NAME\n");
    for (int i = 0; i < 16; i++) {
        uint64_t c = irq_count(i);
        if (c == 0) continue;                          /* only IRQs that have fired */
        p = sapp(b, p, max, "  "); p = sdec(b, p, max, (uint64_t)i);
        p = sapp(b, p, max, "    "); p = sdec(b, p, max, c);
        p = sapp(b, p, max, "    "); p = sapp(b, p, max, names[i]);
        p = sapp(b, p, max, "\n");
    }
    b[p] = 0; return p;
}
/* /proc/stat in the real Linux layout that top/vmstat/uptime parse (M1253):
 * upgraded from a 3-line custom blob. CPU time is in USER_HZ=100 ticks (ms/10,
 * matching gen_pid_stat). Columns we don't account for (nice/iowait/irq/
 * softirq/steal/guest) are honest zeros. ctxt + processes are real new
 * counters; btime is the real boot epoch.
 *
 * Per-core `cpuN` lines (M1538): the aggregate-only comment this replaced
 * was correct when written (M1253, a single-BSP scheduler) but stale once
 * M1531/M1532 shipped a real per-core scheduler + per-core LAPIC timers —
 * task_percore_times() now tracks genuine per-core user/system/idle ms
 * (tagged by mycore() at each timer tick, not reconstructed after the fact),
 * so these are real measurements, not fabricated splits of the aggregate. */
static long gen_stat(char *b, int max) {
    uint64_t up = timer_ms();
    uint64_t now = rtc_unix();
    uint64_t btime = (now > up / 1000) ? now - up / 1000 : 0;   /* boot epoch = now - uptime */

    /* Compute every core's numbers FIRST and sum them for the aggregate `cpu`
     * line, rather than deriving it separately (the old task_cpu_times() sums
     * only CURRENTLY LIVE tasks, silently dropping exited ones -- wrong for
     * this line's real semantic, which is monotonic-since-boot like Linux's.
     * Summing the per-core counters instead is both more correct AND keeps
     * `cpu` == the sum of every `cpuN`, an invariant real tools may check). */
    uint64_t tot_u = 0, tot_s = 0, tot_i = 0;
    uint64_t cu[16], cs[16], ci[16];
    int ncore = smp_cpu_count; if (ncore > 16) ncore = 16; if (ncore < 1) ncore = 1;
    for (int c = 0; c < ncore; c++) {
        task_percore_times(c, &cu[c], &cs[c], &ci[c]);
        if (ci[c] > up) ci[c] = up;
        tot_u += cu[c]; tot_s += cs[c]; tot_i += ci[c];
    }
    /* cpu  user nice system idle iowait irq softirq steal guest guest_nice */
    int p = sapp(b, 0, max, "cpu  ");
    p = sdec(b, p, max, tot_u / 10);  p = sapp(b, p, max, " 0 ");      /* user, nice */
    p = sdec(b, p, max, tot_s / 10);  p = sapp(b, p, max, " ");        /* system */
    p = sdec(b, p, max, tot_i / 10);
    p = sapp(b, p, max, " 0 0 0 0 0 0\n");                             /* iowait irq softirq steal guest guest_nice */
    for (int c = 0; c < ncore; c++) {
        p = sapp(b, p, max, "cpu"); p = sdec(b, p, max, (uint64_t)c); p = sapp(b, p, max, " ");
        p = sdec(b, p, max, cu[c] / 10);  p = sapp(b, p, max, " 0 ");
        p = sdec(b, p, max, cs[c] / 10);  p = sapp(b, p, max, " ");
        p = sdec(b, p, max, ci[c] / 10);
        p = sapp(b, p, max, " 0 0 0 0 0 0\n");
    }
    p = sapp(b, p, max, "ctxt ");          p = sdec(b, p, max, task_ctxt_count());
    p = sapp(b, p, max, "\nbtime ");       p = sdec(b, p, max, btime);
    p = sapp(b, p, max, "\nprocesses ");   p = sdec(b, p, max, task_total_spawned());
    p = sapp(b, p, max, "\nprocs_running "); p = sdec(b, p, max, (uint64_t)task_runnable_count());
    p = sapp(b, p, max, "\nprocs_blocked "); p = sdec(b, p, max, (uint64_t)task_blocked_count());
    p = sapp(b, p, max, "\nncpu ");        p = sdec(b, p, max, (uint64_t)smp_cpu_count);
    p = sapp(b, p, max, "\nuptime_ms ");   p = sdec(b, p, max, up);   /* kept for back-compat with the old format */
    p = sapp(b, p, max, "\n");
    b[p] = 0; return p;
}
/* /proc/diskstats — per-block-device I/O counters (M1256), the file `iostat`
 * parses. One line per registered block device in the Linux layout:
 *   major minor name  rd_ios rd_merges rd_sectors rd_ticks  wr_ios wr_merges
 *   wr_sectors wr_ticks  in_flight io_ticks time_in_queue
 * We tally rd_ios/rd_sectors/wr_ios/wr_sectors in blockdev_read/write; the fields
 * we don't track (merges, per-op ticks, in-flight, queue time) are honest zeros.
 * There's no real major/minor here, so we emit `0 <registry-index>`. */
static long gen_diskstats(char *b, int max) {
    int p = 0, n = blockdev_count();
    for (int i = 0; i < n && p < max - 128; i++) {
        blockdev_t *d = blockdev_get(i);
        if (!d) continue;
        p = sapp(b, p, max, "   0 "); p = sdec(b, p, max, (uint64_t)i);   /* major minor */
        p = sapp(b, p, max, " ");     p = sapp(b, p, max, d->name ? d->name : "blk");
        p = sapp(b, p, max, " ");     p = sdec(b, p, max, d->rd_ios);     /* rd_ios */
        p = sapp(b, p, max, " 0 ");   p = sdec(b, p, max, d->rd_sectors); /* rd_merges rd_sectors */
        p = sapp(b, p, max, " 0 ");   p = sdec(b, p, max, d->wr_ios);     /* rd_ticks wr_ios */
        p = sapp(b, p, max, " 0 ");   p = sdec(b, p, max, d->wr_sectors); /* wr_merges wr_sectors */
        p = sapp(b, p, max, " 0 0 0 0\n");                                /* wr_ticks in_flight io_ticks time_in_queue */
    }
    b[p] = 0; return p;
}
extern int module_list(char *b, int max);       /* kernel/module.c — loaded modules (M1262) */
static long gen_modules(char *b, int max) {      /* /proc/modules: "name size" per loaded .ko (lsmod-ish) */
    return module_list(b, max);
}
static long gen_kmsg(char *b, int max) {        /* the kernel log ring buffer (dmesg) */
    return klog_copy(b, max);
}
static long gen_net(char *b, int max) {         /* interface + ARP/DNS caches (Linux /proc/net-ish) */
    return net_proc(b, max);
}
static long gen_fsevents(char *b, int max) {    /* recent filesystem mutations (inotify-style, M1085) */
    return fsevents_format(b, max);
}
static long gen_profile(char *b, int max) {     /* sampling profiler histogram (M1086) */
    return prof_format(b, max);
}
static long gen_ipc(char *b, int max) {         /* named message queues + pending depth (M1087) */
    return mbox_format(b, max);
}
static long gen_binds(char *b, int max) {       /* active bind mounts (M1091) */
    return vfs_binds_format(b, max);
}
static long gen_kallsyms(char *b, int max) {    /* the embedded kernel symbol table (addr + name per line) */
    int p = 0;
    for (int i = 0; i < ksyms_count && p < max - 24; i++) {
        unsigned long a = ksyms[i].addr;
        char h[16]; int hn = 0;
        if (a == 0) h[hn++] = '0';
        while (a && hn < 16) { int d = (int)(a & 0xf); h[hn++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); a >>= 4; }
        while (hn && p < max - 1) b[p++] = h[--hn];
        if (p < max - 1) b[p++] = ' ';
        const char *n = ksyms[i].name;
        while (*n && p < max - 1) b[p++] = *n++;
        if (p < max - 1) b[p++] = '\n';
    }
    b[p] = 0; return p;
}
static long gen_sched(char *b, int max) {       /* per-task CPU time + system idle% (backs `top`) */
    task_info_t ti[24];
    int cnt = task_snapshot(ti, 24);
    uint64_t up = timer_ms(); if (up == 0) up = 1;
    uint64_t idle = task_idle_ms() + task_idle_hlt_ms(); if (idle > up) idle = up;
    static const char *st[5] = { "ready", "run  ", "block", "dead ", "stop " };
    uint64_t memt = pmm_total_bytes() / (1024 * 1024), memf = pmm_free_bytes() / (1024 * 1024);
    int p = sapp(b, 0, max, "uptime_ms ");  p = sdec(b, p, max, up);
    p = sapp(b, p, max, "  idle ");         p = sdec(b, p, max, (idle * 100) / up); p = sapp(b, p, max, "%\n");
    p = sapp(b, p, max, "mem ");            p = sdec(b, p, max, memt - memf);
    p = sapp(b, p, max, "/");               p = sdec(b, p, max, memt);
    p = sapp(b, p, max, " MiB used  tasks "); p = sdec(b, p, max, (uint64_t)task_count());
    p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "  PID  STATE  CPU_MS   CPU%  WAIT_MS  SWITCHES  NI  POL   WCHAN              NAME\n");
    for (int i = 0; i < cnt; i++) {
        if (ti[i].state == 3) continue;             /* skip dead */
        p = sapp(b, p, max, "  ");  p = sdec(b, p, max, (uint64_t)ti[i].id);
        p = sapp(b, p, max, "    "); p = sapp(b, p, max, st[(unsigned)ti[i].state < 5 ? ti[i].state : 0]);
        p = sapp(b, p, max, "  ");  p = sdec(b, p, max, ti[i].run_ms);
        p = sapp(b, p, max, "    "); p = sdec(b, p, max, (ti[i].run_ms * 100) / up); p = sapp(b, p, max, "%");
        p = sapp(b, p, max, "    "); p = sdec(b, p, max, ti[i].rq_wait_ms);
        p = sapp(b, p, max, "    "); p = sdec(b, p, max, ti[i].nswitch);
        /* NI: CFS nice level (M1171) */
        p = sapp(b, p, max, "  ");
        if (ti[i].nice < 0) { p = sapp(b, p, max, "-"); p = sdec(b, p, max, (uint64_t)(-ti[i].nice)); }
        else p = sdec(b, p, max, (uint64_t)ti[i].nice);
        /* POL: scheduling class — OT (CFS) / FF<prio> (FIFO) / RR<prio> (M1172) */
        p = sapp(b, p, max, "  ");
        if (ti[i].policy == 1)      { p = sapp(b, p, max, "FF"); p = sdec(b, p, max, (uint64_t)ti[i].rt_priority); }
        else if (ti[i].policy == 2) { p = sapp(b, p, max, "RR"); p = sdec(b, p, max, (uint64_t)ti[i].rt_priority); }
        else                          p = sapp(b, p, max, "OT");
        /* WCHAN: the kernel routine a blocked task is parked in, symbolised (M1166) */
        p = sapp(b, p, max, "  ");
        if (ti[i].wchan) { unsigned long off; const char *nm = ksym_lookup(ti[i].wchan, &off);
                           p = sapp(b, p, max, nm ? nm : "?"); }
        else p = sapp(b, p, max, "-");
        p = sapp(b, p, max, "  ");  p = sapp(b, p, max, ti[i].proc ? app_title((app_t *)ti[i].proc) : "(kernel)");
        p = sapp(b, p, max, "\n");
    }
    b[p] = 0; return p;
}

/* /proc/kasan (M1201): kernel-heap sanitizer counters — allocations redzone-
 * checked at free, and heap buffer-overflows caught. */
static long gen_kasan(char *b, int max) {
    uint64_t ov = 0, chk = 0; kheap_kasan_stats(&ov, &chk);
    int p = 0;
    p = sapp(b, p, max, "redzone_checks:   "); p = sdec(b, p, max, chk); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "overflows_caught: "); p = sdec(b, p, max, ov);  p = sapp(b, p, max, "\n");
    b[p] = 0; return p;
}

/* ---- the directory tables ------------------------------------------------- */
struct pf { const char *name; long (*gen)(char *, int); };
static const struct pf proc_files[] = {
    { "meminfo", gen_meminfo }, { "uptime", gen_uptime }, { "cpuinfo", gen_cpuinfo }, { "acpi", gen_acpi },
    { "version", gen_version }, { "loadavg", gen_loadavg }, { "stat", gen_stat }, { "kasan", gen_kasan },
    { "mqueue", gen_mqueue }, { "sysvipc", gen_sysvipc }, { "unix", gen_unix }, { "locks", gen_locks },
    { "processes", gen_processes }, { "partitions", gen_partitions }, { "diskstats", gen_diskstats }, { "modules", gen_modules },
    { "filesystems", gen_filesystems }, { "mounts", gen_mounts },
    { "interrupts", gen_interrupts }, { "kmsg", gen_kmsg }, { "sched", gen_sched },
    { "kallsyms", gen_kallsyms }, { "net", gen_net }, { "fsevents", gen_fsevents },
    { "profile", gen_profile }, { "ipc", gen_ipc }, { "binds", gen_binds },
    { "bcache", gen_bcache }, { "measure", gen_measure }, { "cas", gen_cas }, { "fw", gen_fw },
    { "notify", gen_notify }, { "swaps", gen_swaps }, { "shm", gen_shm }, { "events", gen_events }, { "bpf", gen_bpf }, { "syscalls", gen_syscalls },
};
static const char *dev_files[] = { "null", "zero", "random", "urandom", "full", "clipboard", "kmsg", "tty" };
/* Listed in /dev separately from dev_files because it is a DIRECTORY, not a
 * character device, and procfs_exists keys chardev off that table. (M2351) */   /* tty: the controlling terminal, opened specially by the Linux ABI (M2004) */

/* --- NESTED /proc/sys and /sys nodes (M1970) --------------------------------
 *
 * The table above is keyed on a flat name directly under /proc, which cannot
 * express /proc/sys/vm/overcommit_memory or /sys/kernel/mm/... -- and those are
 * exactly the paths a large runtime reads on startup to size itself. Claude
 * Code probed six of them and got ENOENT for every one.
 *
 * These are honest answers about THIS kernel, not placeholders: we do not
 * overcommit, we have no transparent hugepage daemon (MADV_COLLAPSE is
 * explicit, M1155/M1168), and the CPU list comes from the live SMP count. */
struct sf { const char *path; const char *text; };
static const struct sf sys_files[] = {
    { "/proc/sys/vm/overcommit_memory",              "0\n" },
    { "/proc/sys/vm/overcommit_ratio",               "50\n" },
    { "/proc/sys/vm/mmap_min_addr",                  "65536\n" },
    { "/proc/sys/vm/max_map_count",                  "65530\n" },
    { "/proc/sys/kernel/pid_max",                    "32768\n" },
    { "/proc/sys/kernel/osrelease",                  "6.1.0-osdev\n" },
    { "/proc/sys/fs/pipe-max-size",                  "1048576\n" },
    /* "[never]" is the SELECTED value in this format, and it is the truth: a
     * hugepage here is something a program asks for, never something the
     * kernel folds in behind its back. */
    { "/sys/kernel/mm/transparent_hugepage/enabled", "always madvise [never]\n" },
    { "/sys/kernel/mm/transparent_hugepage/defrag",  "always defer madvise [never]\n" },
};
#define NSYSF (int)(sizeof(sys_files)/sizeof(sys_files[0]))

/* WHAT libdrm READS BEFORE MESA WILL LOAD ANY DRIVER (M2353).
 *
 * Mesa's EGL calls `_eglAddDevice(fd)` -> `_eglAddDRMDevice` ->
 * `drmGetDevice2(fd, 0, &dev)`, and returns NULL -- no device, therefore
 * EGL_NOT_INITIALIZED -- if that fails. drmGetDevice2 is a sysfs reader:
 *
 *   1. fstat(fd): S_ISCHR and a DRM major/minor. (done in M2351)
 *   2. drmNodeIsDRM: stat("/sys/dev/char/226:128/device/drm")
 *   3. drmParseSubsystemType: realpath("/sys/dev/char/226:128/device/subsystem")
 *      and compare the BASENAME against pci/usb/platform/virtio. realpath, not
 *      readlink -- so `subsystem` has to be a real symlink and its target has
 *      to exist, or glibc's realpath fails on the component.
 *   4. drmParsePciBusInfo: "PCI_SLOT_NAME=" out of .../device/uevent
 *   5. drmParsePciDeviceInfo: the five hex files below, falling back to
 *      .../device/config if they are absent.
 *
 * None of this is invented: the device really is PCI 0000:00:1c.0, really is
 * 1af4:1050, and the kernel already printed exactly that from its own PCI
 * enumeration. This is the same information, in the place a library looks.
 *
 * Gated on virtio_gpu_has_3d() throughout, so a boot with no GPU has no
 * /sys/dev/char entries to mislead anything. */
#define DRM_SYS "/sys/dev/char/226:128/device"
/* AND THE SUBSYSTEM IS pci -- RETRACTING A "CORRECTION" (M2354).
 *
 * This table said `pci` with the device's real 1af4:1050 ids. I changed it to
 * `virtio` on the reasoning that Linux reports virtio (true: the DRM device's
 * parent is the virtio device) and that Mesa's PCI-id table has no 1af4 entry,
 * so succeeding at the PCI probe would return NULL. THE SECOND HALF WAS WRONG,
 * read off an older Mesa. Mesa 26 does:
 *
 *     driver = loader_get_pci_driver(fd);
 *     if (!driver) driver = loader_get_kernel_driver_name(fd);
 *
 * -- it FALLS BACK. An unknown PCI id costs nothing.
 *
 * And libdrm requires PCI outright. `drmGetDevice2` is `drmGetDeviceFromDevId`,
 * which contains:
 *
 *     subsystem_type = drmParseSubsystemType(maj, min);
 *     if (subsystem_type != DRM_BUS_PCI)
 *             return -ENODEV;
 *
 * Which is exactly what the probe then measured: `drmGetDevice2(fd) -> -19
 * (No such device)`, `drmGetDevices2 -> 0 device(s)`, and therefore an empty
 * EGL device list and "DRI2: failed to load driver" three layers up.
 *
 * Real Linux survives reporting virtio because drmParseSubsystemType, on
 * seeing DRM_BUS_VIRTIO, re-reads the subsystem of the PARENT (`.../device/..`)
 * and gets pci from the virtio device's PCI parent. Modelling that would mean
 * a second synthetic level; reporting pci directly is the same answer with
 * less machinery, and it is what `get_pci_path` -- which reads the ids below --
 * expects to find anyway.
 *
 * Two lessons, both about reading rather than reasoning: libdrm's source was
 * on this machine the whole time (/var/cache/distfiles), and one grep for
 * ENODEV answered what four VM round trips could not. And a change justified
 * by "this is more truthful" is still a regression if it is untested --
 * this one replaced a working table with a broken one on a chain of
 * plausible-sounding inference. */
static const struct sf drm_sys_files[] = {
    /* PCI_SLOT_NAME is what drmParsePciBusInfo sscanf's out of uevent; the four
     * hex files are what parse_separate_sysfs_files reads (it skips `revision`
     * unless DRM_DEVICE_GET_PCI_REVISION is asked for, but it costs nothing).
     * Every value is what the kernel's own PCI enumeration printed:
     * `00:1c.0  1af4:1050  class 03:80`. */
    { DRM_SYS "/uevent",
      "DRIVER=virtio_gpu\n"
      "PCI_CLASS=38000\n"
      "PCI_ID=1AF4:1050\n"
      "PCI_SUBSYS_ID=1AF4:1100\n"
      "PCI_SLOT_NAME=0000:00:1c.0\n"
      "MODALIAS=pci:v00001AF4d00001050sv00001AF4sd00001100bc03sc80i00\n" },
    { DRM_SYS "/vendor",            "0x1af4\n" },
    { DRM_SYS "/device",            "0x1050\n" },
    { DRM_SYS "/revision",          "0x00\n" },
    { DRM_SYS "/subsystem_vendor",  "0x1af4\n" },
    { DRM_SYS "/subsystem_device",  "0x1100\n" },
};
#define NDRMSYSF (int)(sizeof(drm_sys_files)/sizeof(drm_sys_files[0]))

/* The directories those files live in, plus the symlink target. `drm` is a
 * directory purely so step 2's stat() succeeds -- that is all libdrm does with
 * it. */
static const char *drm_sys_dirs[] = {
    "/sys/dev", "/sys/dev/char", "/sys/dev/char/226:128",
    DRM_SYS, DRM_SYS "/drm", "/sys/bus", "/sys/bus/pci",
};
#define NDRMSYSD (int)(sizeof(drm_sys_dirs)/sizeof(drm_sys_dirs[0]))

/* THE ONE SYMLINK. Its target must exist, because realpath resolves every
 * component -- pointing it at a path we do not serve would fail in exactly the
 * same silent way as not having it at all. */
#define DRM_SYS_SUBSYSTEM DRM_SYS "/subsystem"
#define DRM_SYS_SUBSYS_TARGET "/sys/bus/pci"

int procfs_is_drm_symlink(const char *abs) {
    return virtio_gpu_has_3d() && peq(abs, DRM_SYS_SUBSYSTEM);
}
const char *procfs_drm_symlink_target(const char *abs) {
    return procfs_is_drm_symlink(abs) ? DRM_SYS_SUBSYS_TARGET : 0;
}

/* /sys/devices/system/cpu/online is generated, not constant: it reports the
 * cores that are actually up, which is what a runtime sizes its thread pool
 * from. Format is a range list, "0" for one core and "0-3" for four. */
static long gen_cpu_online(char *b, int max) {
    int n = smp_cpu_count > 0 ? smp_cpu_count : 1;
    int p = 0;
    p = sapp(b, p, max, "0");
    if (n > 1) { p = sapp(b, p, max, "-"); p = sdec(b, p, max, (uint64_t)(n - 1)); }
    p = sapp(b, p, max, "\n");
    b[p] = 0; return p;
}

/* Serve a nested node. Returns bytes, or -1 if this path is not one of ours. */
static long sysfs_read(const char *abs, char *b, int max) {
    if (peq(abs, "/sys/devices/system/cpu/online") ||
        peq(abs, "/sys/devices/system/cpu/possible") ||
        peq(abs, "/sys/devices/system/cpu/present"))
        return gen_cpu_online(b, max);
    for (int i = 0; i < NSYSF; i++)
        if (peq(abs, sys_files[i].path)) {
            int p = 0;
            p = sapp(b, p, max, sys_files[i].text);
            b[p] = 0; return p;
        }
    if (virtio_gpu_has_3d())
        for (int i = 0; i < NDRMSYSF; i++)
            if (peq(abs, drm_sys_files[i].path)) {
                int p = 0;
                p = sapp(b, p, max, drm_sys_files[i].text);
                b[p] = 0; return p;
            }
    return -1;
}
static int sysfs_has(const char *abs) {
    if (peq(abs, "/sys/devices/system/cpu/online") ||
        peq(abs, "/sys/devices/system/cpu/possible") ||
        peq(abs, "/sys/devices/system/cpu/present")) return 1;
    for (int i = 0; i < NSYSF; i++) if (peq(abs, sys_files[i].path)) return 1;
    if (virtio_gpu_has_3d()) {
        for (int i = 0; i < NDRMSYSF; i++) if (peq(abs, drm_sys_files[i].path)) return 1;
        if (peq(abs, DRM_SYS_SUBSYSTEM)) return 1;
    }
    return 0;
}
#define NPROC (int)(sizeof(proc_files)/sizeof(proc_files[0]))
#define NDEV  (int)(sizeof(dev_files)/sizeof(dev_files[0]))

static int proc_pid_path(const char *abs, int *pid, const char **file);   /* defined below (M1965) */

/* The synthetic sysfs directories the DRM device needs (M2353). A trailing
 * slash is accepted on each, because callers spell directories both ways and a
 * path that exists only without its slash is a bug waiting for one caller. */
static int procfs_is_drm_sysdir(const char *abs) {
    if (!virtio_gpu_has_3d()) return 0;
    for (int i = 0; i < NDRMSYSD; i++) {
        if (peq(abs, drm_sys_dirs[i])) return 1;
        {   const char *d = drm_sys_dirs[i]; int k = 0;
            while (d[k] && abs[k] == d[k]) k++;
            if (!d[k] && abs[k] == '/' && !abs[k + 1]) return 1;
        }
    }
    return 0;
}
int procfs_is_dir(const char *abs) {
    /* /dev/shm is a DIRECTORY -- POSIX shared memory lives in it as named
     * objects, and a program that means to use shm checks for the directory
     * before trying. The objects themselves are not files on any filesystem;
     * openat() intercepts /dev/shm/NAME into a named memfd (M2008), so this
     * only has to make the directory itself real. */
    /* AND /dev/dri IS A DIRECTORY (M2351), for the same reason: Mesa's
     * surfaceless platform and libdrm both stat it, and a render node in a
     * directory that does not exist is a node nobody looks for. The node
     * itself is intercepted in app_open (fd type 17 over drm.c), so this only
     * has to make the directory and the name real. */
    /* AND /sys ITSELF (M2353). procfs.c has generated nested /sys nodes since
     * M1970 and the directory they live in was never a directory -- stat("/sys")
     * failed. Nothing noticed, because everything reaching /sys until now asked
     * for a leaf by full path. glibc's realpath(3) does not: it lstats every
     * component in turn, so a single missing intermediate makes the whole
     * resolution fail, and libdrm resolves
     * /sys/dev/char/226:128/device/subsystem before Mesa will load a driver. */
    return peq(abs, "/proc") || peq(abs, "/proc/") || peq(abs, "/dev") || peq(abs, "/dev/") ||
           peq(abs, "/dev/shm") || peq(abs, "/dev/shm/") ||
           peq(abs, "/dev/dri") || peq(abs, "/dev/dri/") ||
           peq(abs, "/sys") || peq(abs, "/sys/") ||
           peq(abs, "/sys/kernel") || peq(abs, "/sys/kernel/") ||
           peq(abs, "/sys/devices") || peq(abs, "/sys/devices/") ||
           procfs_is_drm_sysdir(abs);
}
int procfs_owns(const char *abs) {
    return startswith(abs, "/proc/") || startswith(abs, "/dev/") ||
           startswith(abs, "/sys/") ||                      /* nested sysfs nodes (M1970) */
           procfs_is_dir(abs);
}

/* Does this synthetic node actually EXIST, and is it a character device?
 * (M1965)
 *
 * procfs_owns() answers "is this path ours", which is a different question:
 * /dev/wumpus is ours and is not there. Until now nothing could tell the two
 * apart, so vfs_stat reported every /proc and /dev file as absent, open()
 * refused them, and Node's probes of /proc/meminfo, /proc/stat and /dev/null
 * all failed against files procfs.c has generated since M1216.
 *
 * chardev matters separately: a runtime that opens /dev/null checks S_IFCHR
 * before trusting it to swallow output. */
int procfs_exists(const char *abs, int *chardev) {
    if (chardev) *chardev = 0;
    if (procfs_is_dir(abs)) return 1;
    if (sysfs_has(abs)) return 1;                            /* nested /proc/sys and /sys (M1970) */
    if (startswith(abs, "/dev/")) {
        const char *f = abs + 5;
        /* The render node, only when there is really a GPU behind it -- the
         * same rule app_open applies. A node that stats as present and then
         * refuses to open reads as a broken driver; absent reads as a machine
         * without a GPU, and only the second is true. (M2351) */
        if (peq(f, "dri/renderD128") && virtio_gpu_has_3d()) { if (chardev) *chardev = 1; return 1; }
        for (int i = 0; i < NDEV; i++) if (peq(f, dev_files[i])) { if (chardev) *chardev = 1; return 1; }
        return 0;
    }
    if (startswith(abs, "/proc/")) {
        const char *f = abs + 6;
        for (int i = 0; i < NPROC; i++) if (peq(f, proc_files[i].name)) return 1;
        /* A per-pid path must be one we can actually SERVE. Claiming every
         * /proc/<pid>/<anything> made open() succeed and the following read()
         * fail with EBADF -- a file that exists until you touch it. Claude Code
         * opened /proc/self/cgroup, got a descriptor, read EBADF and aborted;
         * the syscall ring's return values are what showed it. (M1970) */
        /* MUST match what procfs_read below actually serves. Claiming a name
         * it does not serve recreates the exact bug this list exists to fix:
         * open() succeeds and read() returns EBADF. "environ" was in here and
         * is not served; "maps" is served and was missing, so it read as
         * absent. (M1971) */
        static const char *pid_files[] = {
            "auxv", "cgroup", "cmdline", "comm", "cwd", "exe", "fd", "io",
            "limits", "maps", "mountinfo", "mounts", "oom_score", "oom_score_adj", "pagemap", "regs",
            "root", "sigfd", "smaps", "sstrace", "stat", "statm", "status",
            "strace", "wchan", "wss", "ctl", 0
        };
        int pid; const char *sub;                 /* /proc/<pid>/... and /proc/self/... */
        if (proc_pid_path(abs, &pid, &sub)) {
            for (int i = 0; pid_files[i]; i++) if (peq(sub, pid_files[i])) return 1;
            if (startswith(sub, "mem/")) return 1;
            return 0;
        }
        return 0;
    }
    return 0;
}

/* --- per-process /proc/<pid>/{status,cmdline,ctl} (Plan 9 / Linux style) --- */
static int proc_pid_path(const char *abs, int *pid, const char **file) {
    if (!startswith(abs, "/proc/")) return 0;
    const char *p = abs + 6;
    if (startswith(p, "self/")) {                 /* /proc/self/... -> the calling task */
        *pid = task_current_id(); *file = p + 5;
        /* /proc/<pid>/task/<tid>/<file> -- the PER-THREAD view. A runtime that
         * manages its own threads reads this (Firefox reads task/<tid>/stat
         * while starting up). We have no separate per-thread accounting, so
         * the thread's file is answered with the process's: the numbers are
         * the ones we actually have rather than zeros, and the alternative was
         * ENOENT for a path Linux always provides. (M1982) */
        if (startswith(*file, "task/")) {
            const char *q = *file + 5;
            while (*q && *q != '/') q++;
            if (*q == '/' && q[1]) *file = q + 1;
        }
        return **file != 0;
    }
    if (*p < '1' || *p > '9') return 0;          /* a pid starts 1-9; flat files start with a letter */
    int n = 0; while (*p >= '0' && *p <= '9') { n = n * 10 + (*p - '0'); p++; }
    if (*p != '/' || p[1] == 0) return 0;        /* must be "/proc/<pid>/<file>" */
    *pid = n; *file = p + 1;
    return 1;
}
static void *proc_find(int pid, int *state_out) {
    task_info_t ti[24]; int cnt = task_snapshot(ti, 24);
    for (int i = 0; i < cnt; i++)
        if (ti[i].id == pid && ti[i].proc) { if (state_out) *state_out = ti[i].state; return ti[i].proc; }
    return 0;
}
static long gen_pid_status(char *b, int max, int pid, int state, void *proc) {
    static const char *st[5] = { "ready", "running", "blocked", "dead", "stopped" };
    int p = 0;
    p = sapp(b, p, max, "Name:\t");        p = sapp(b, p, max, app_title((app_t *)proc)); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "Pid:\t");         p = sdec(b, p, max, (uint64_t)pid);            p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "State:\t");       p = sapp(b, p, max, st[(state >= 0 && state < 5) ? state : 0]); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "HeapKB:\t");      p = sdec(b, p, max, app_heap_bytes((app_t *)proc) / 1024); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "MmapRegions:\t"); p = sdec(b, p, max, (uint64_t)app_vma_count((app_t *)proc)); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "Pledge:\t");
    if (app_is_pledged((app_t *)proc)) {
        char pl[64]; app_pledge_format(app_promises((app_t *)proc), pl, sizeof pl);
        p = sapp(b, p, max, pl[0] ? pl : "(none)");
    } else p = sapp(b, p, max, "(unrestricted)");
    p = sapp(b, p, max, "\n");
    b[p] = 0; return p;
}
/* /proc/<pid>/stat (M1231): the single-line, space-separated record `ps`/`top`/
 * `htop` parse. We emit the classic fields 1-24 — pid, (comm), state, ppid,
 * pgrp, session, then utime/stime (CPU ticks @100Hz from the task), nice,
 * vsize (heap bytes) and rss (resident pages from the PTE walk) — with 0 for
 * the counters we don't track (tty, faults, etc.). */
static long gen_pid_stat(char *b, int max, int pid, int state, void *proc) {
    app_t *a = (app_t *)proc;
    task_t *t = (task_t *)app_task(a);
    char stc = (state == 2) ? 'S' : (state == 3) ? 'Z' : (state == 4) ? 'T' : 'R';
    uint64_t utime = t ? t->utime_ms / 10 : 0;             /* ms -> clock ticks @ 100 Hz */
    uint64_t stime = t ? t->stime_ms / 10 : 0;
    int nice = t ? t->nice : 0;
    vmm_wss_t w; vmm_wss(app_cr3(a), &w);
    int p = 0;
    p = sdec(b, p, max, (uint64_t)pid);          p = sapp(b, p, max, " (");
    p = sapp(b, p, max, app_title(a));           p = sapp(b, p, max, ") ");
    if (p < max - 1) b[p++] = stc;               p = sapp(b, p, max, " ");
    p = sdec(b, p, max, (uint64_t)app_ppid(a));    p = sapp(b, p, max, " ");
    p = sdec(b, p, max, (uint64_t)app_pgid_of(a)); p = sapp(b, p, max, " ");
    p = sdec(b, p, max, (uint64_t)app_sid_of(a));  p = sapp(b, p, max, " ");
    p = sapp(b, p, max, "0 0 0 ");               /* tty_nr tpgid flags */
    uint64_t mnf = 0, mjf = 0; app_faults(a, &mnf, &mjf);   /* real page-fault counts (M1252) */
    p = sdec(b, p, max, mnf); p = sapp(b, p, max, " 0 ");   /* minflt cminflt(0: no child accounting) */
    p = sdec(b, p, max, mjf); p = sapp(b, p, max, " 0 ");   /* majflt cmajflt */
    p = sdec(b, p, max, utime);                  p = sapp(b, p, max, " ");
    p = sdec(b, p, max, stime);                  p = sapp(b, p, max, " ");
    p = sapp(b, p, max, "0 0 20 ");              /* cutime cstime priority */
    if (nice < 0) { if (p < max - 1) b[p++] = '-'; p = sdec(b, p, max, (uint64_t)(-nice)); }
    else p = sdec(b, p, max, (uint64_t)nice);
    p = sapp(b, p, max, " 1 0 0 ");              /* nice<sp> num_threads itrealvalue starttime */
    p = sdec(b, p, max, app_heap_bytes(a));      p = sapp(b, p, max, " ");   /* vsize (bytes) */
    p = sdec(b, p, max, w.resident);             p = sapp(b, p, max, "\n");  /* rss (pages) */
    b[p] = 0; return p;
}
/* /proc/<pid>/io (M1244): per-process I/O byte accounting — the rchar/wchar
 * counters `iotop`/`pidstat -d` read. We tally bytes through the fd read/write
 * path (read_bytes/write_bytes mirror them — no separate cached-vs-disk split). */
static long gen_pid_io(char *b, int max, void *proc) {
    uint64_t rc = 0, wc = 0; app_io_counts((app_t *)proc, &rc, &wc);
    int p = 0;
    p = sapp(b, p, max, "rchar: ");       p = sdec(b, p, max, rc); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "wchar: ");       p = sdec(b, p, max, wc); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "read_bytes: ");  p = sdec(b, p, max, rc); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "write_bytes: "); p = sdec(b, p, max, wc); p = sapp(b, p, max, "\n");
    b[p] = 0; return p;
}
/* /proc/<pid>/statm (M1245): the short memory line `top`/`free`/`ps` parse —
 * seven page counts "size resident shared text lib data dt". We fill size
 * (resident + heap), resident (the PTE-walk count), and data (heap pages);
 * shared/text/lib/dt are 0 (not separately tracked). */
static long gen_pid_statm(char *b, int max, void *proc) {
    app_t *a = (app_t *)proc;
    vmm_wss_t w; vmm_wss(app_cr3(a), &w);
    uint64_t rss = w.resident, data = app_heap_bytes(a) / 4096, size = rss + data;
    int p = 0;
    p = sdec(b, p, max, size); p = sapp(b, p, max, " ");   /* size      */
    p = sdec(b, p, max, rss);  p = sapp(b, p, max, " ");   /* resident  */
    p = sapp(b, p, max, "0 0 0 ");                         /* shared text lib */
    p = sdec(b, p, max, data); p = sapp(b, p, max, " 0\n");/* data, dt  */
    b[p] = 0; return p;
}
/* /proc/<pid>/wchan (M1247): the kernel symbol where a process is blocked —
 * what `ps -o wchan` shows, and the building block for debugging hung tasks.
 * The task's blocked-PC (task_block/sleep stamp it, M1166) is symbolized via
 * the same ksym_lookup `/proc/sched` uses; a running task reports "0". */
static long gen_pid_wchan(char *b, int max, int pid) {
    task_info_t ti[24]; int cnt = task_snapshot(ti, 24);
    uint64_t wchan = 0;
    for (int i = 0; i < cnt; i++) if (ti[i].id == pid) { wchan = ti[i].wchan; break; }
    int p = 0;
    if (wchan) { unsigned long off; const char *nm = ksym_lookup(wchan, &off); p = sapp(b, p, max, nm ? nm : "?"); }
    else p = sapp(b, p, max, "0");                         /* running / not blocked */
    p = sapp(b, p, max, "\n");
    b[p] = 0; return p;
}
/* /proc/<pid>/cwd (M1249): the process's current directory — what `pwdx` and
 * `lsof` read, and `ls -l /proc/<pid>/cwd` resolves. Reuses the M1248 cwd_path
 * string. (/proc/<pid>/root is always "/" — the OS has no per-process chroot.) */
static long gen_pid_cwd(char *b, int max, void *proc) {
    int p = sapp(b, 0, max, app_cwd_str((app_t *)proc));
    p = sapp(b, p, max, "\n"); b[p] = 0; return p;
}
/* /proc/<pid>/exe (M1250): the path of the program image — what ls -l
 * /proc/<pid>/exe and "find my own binary" code read. The spawn/exec path,
 * captured separately from the title so prctl(PR_SET_NAME) can't change it. */
static long gen_pid_exe(char *b, int max, void *proc) {
    int p = sapp(b, 0, max, app_exe_str((app_t *)proc));
    p = sapp(b, p, max, "\n"); b[p] = 0; return p;
}
/* /proc/<pid>/wss: working-set size from the CPU's Accessed/Dirty PTE bits.
 * "Referenced" counts pages touched since the last `clearref` (write it to ctl
 * to reset the window) — the building block for an LRU/swap victim picker. */
static long gen_pid_wss(char *b, int max, int pid, void *proc) {
    vmm_wss_t w; vmm_wss(app_cr3((app_t *)proc), &w);
    int p = 0;
    p = sapp(b, p, max, "Pid:\t");          p = sdec(b, p, max, (uint64_t)pid);       p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "Resident:\t");     p = sdec(b, p, max, w.resident);          p = sapp(b, p, max, " pages\n");
    p = sapp(b, p, max, "ResidentKB:\t");   p = sdec(b, p, max, w.resident * 4);      p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "Referenced:\t");   p = sdec(b, p, max, w.referenced);        p = sapp(b, p, max, " pages (accessed since clearref)\n");
    p = sapp(b, p, max, "Dirty:\t");        p = sdec(b, p, max, w.dirty);             p = sapp(b, p, max, " pages (written)\n");
    p = sapp(b, p, max, "Writable:\t");     p = sdec(b, p, max, w.writable);          p = sapp(b, p, max, " pages\n");
    b[p] = 0; return p;
}

/* /proc/<pid>/oom_score (M1277): the OOM killer's victim score for this process
 * — RSS in pages plus the oom_adj bias. The number the OOM killer ranks by; a
 * single line like Linux's. */
static long gen_pid_oom(char *b, int max, void *proc) {
    long s = app_oom_score_of((app_t *)proc); if (s < 0) s = 0;
    int p = sdec(b, 0, max, (uint64_t)s);
    p = sapp(b, p, max, "\n");
    b[p] = 0; return p;
}
/* /proc/<pid>/oom_score_adj (M1282): the tunable OOM victim bias [-1000,1000], rw. */
static long gen_pid_oom_score_adj(char *b, int max, void *proc) {
    int v = app_oom_adj_get((app_t *)proc);
    int p = 0;
    if (v < 0) { if (p < max - 1) b[p++] = '-'; v = -v; }   /* sdec is unsigned: emit the sign ourselves (was p<max, the one site not reserving the trailing NUL slot every sibling sapp/sdec call does) */
    p = sdec(b, p, max, (uint64_t)v);
    p = sapp(b, p, max, "\n");
    b[p] = 0; return p;
}

/* /proc/<pid>/mem/<hexaddr>[/<len>]: hexdump another process's memory — the live
 * counterpart to the post-mortem core reader (crashinfo, M1112). The name-based
 * VFS has no fd offsets, so the address+length ride in the path. Restricted to
 * the user footprint [0x40000000,0x80001000) so it can never expose the shared
 * kernel higher-half or the low identity map; bytes outside a mapped page print
 * as "..". M1114. */
#define MEM_USER_LO 0x40000000ull
#define MEM_USER_HI 0x80001000ull
static int hx(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int shexw(char *b, int p, int max, uint64_t v, int width) {
    for (int i = width - 1; i >= 0; i--) { int nyb = (int)((v >> (i * 4)) & 0xF); if (p < max - 1) b[p++] = (char)(nyb < 10 ? '0' + nyb : 'a' + nyb - 10); }
    return p;
}
static long gen_pid_mem(char *b, int max, void *proc, const char *spec) {
    uint64_t va = 0; const char *s = spec; int v;
    while ((v = hx(*s)) >= 0) { va = (va << 4) | (uint64_t)v; s++; }
    unsigned long len = 64;
    if (*s == '/') { s++; len = 0; while (*s >= '0' && *s <= '9') { len = len * 10 + (unsigned long)(*s - '0'); s++; } }
    if (len == 0) len = 64;
    if (len > 256) len = 256;                              /* one screenful per read */
    uint64_t cr3 = app_cr3((app_t *)proc);
    int p = 0;
    for (unsigned long i = 0; i < len; i += 16) {
        p = sapp(b, p, max, "  "); p = shexw(b, p, max, va + i, 8); p = sapp(b, p, max, ": ");
        char ascii[17]; int na = 0;
        for (int j = 0; j < 16; j++) {
            if (i + (unsigned long)j >= len) { p = sapp(b, p, max, "   "); continue; }
            uint64_t cur = va + i + (unsigned long)j;
            uint64_t phys = (cur >= MEM_USER_LO && cur < MEM_USER_HI) ? vmm_translate_in(cr3, cur) : 0;
            if (phys) {
                unsigned char by = *((volatile unsigned char *)hhdm(phys));
                p = shexw(b, p, max, by, 2); p = sapp(b, p, max, " ");
                ascii[na++] = (by >= 32 && by < 127) ? (char)by : '.';
            } else {
                p = sapp(b, p, max, ".. "); ascii[na++] = '.';
            }
        }
        ascii[na] = 0;
        p = sapp(b, p, max, " |"); p = sapp(b, p, max, ascii); p = sapp(b, p, max, "|\n");
    }
    b[p] = 0; return p;
}

/* /proc/<pid>/regs: the ring-3 register file captured at the target's most recent
 * trap (M1119). Most meaningful for a STOPPED task (its frame is frozen); for a
 * running task it's the last trap (constantly changing). Pairs with /proc/<pid>/mem
 * + ctl stop/cont to inspect a halted process. */
static int rreg(char *b, int p, int max, const char *nm, uint64_t v) {
    p = sapp(b, p, max, nm); p = sapp(b, p, max, "="); p = shexw(b, p, max, v, 16); return p;
}
static long gen_pid_regs(char *b, int max, void *proc) {
    struct registers *r = task_uframe((task_t *)app_task((app_t *)proc));
    if (!r) { int p = sapp(b, 0, max, "  (no saved trap frame — the task has not entered ring 3)\n"); if (p < max) b[p] = 0; return p; }
    int p = 0;
    p = sapp(b, p, max, "  "); p = rreg(b, p, max, "rip", r->rip); p = sapp(b, p, max, "  "); p = rreg(b, p, max, "rsp", r->rsp);    p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "  "); p = rreg(b, p, max, "rbp", r->rbp); p = sapp(b, p, max, "  "); p = rreg(b, p, max, "rfl", r->rflags); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "  "); p = rreg(b, p, max, "rax", r->rax); p = sapp(b, p, max, "  "); p = rreg(b, p, max, "rbx", r->rbx); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "  "); p = rreg(b, p, max, "rcx", r->rcx); p = sapp(b, p, max, "  "); p = rreg(b, p, max, "rdx", r->rdx); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "  "); p = rreg(b, p, max, "rsi", r->rsi); p = sapp(b, p, max, "  "); p = rreg(b, p, max, "rdi", r->rdi); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "  "); p = rreg(b, p, max, "r8 ", r->r8);  p = sapp(b, p, max, "  "); p = rreg(b, p, max, "r9 ", r->r9);  p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "  "); p = rreg(b, p, max, "r10", r->r10); p = sapp(b, p, max, "  "); p = rreg(b, p, max, "r11", r->r11); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "  "); p = rreg(b, p, max, "r12", r->r12); p = sapp(b, p, max, "  "); p = rreg(b, p, max, "r13", r->r13); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "  "); p = rreg(b, p, max, "r14", r->r14); p = sapp(b, p, max, "  "); p = rreg(b, p, max, "r15", r->r15); p = sapp(b, p, max, "\n");
    p = sapp(b, p, max, "  "); p = rreg(b, p, max, "cs",  r->cs);  p = sapp(b, p, max, "  "); p = rreg(b, p, max, "ss",  r->ss);  p = sapp(b, p, max, "\n");
    if (p < max) b[p] = 0; return p;
}

/* /proc/<pid>/sstrace: the hardware single-step instruction trace (M1123) — the
 * RIPs recorded by the last sys_singlestep(n), oldest-first. */
static long gen_pid_sstrace(char *b, int max, void *proc) {
    uint64_t rips[64]; int n = app_sstep_get((app_t *)proc, rips, 64);
    int p = sapp(b, 0, max, "  #  INSTRUCTION POINTER\n");
    for (int i = 0; i < n; i++) {
        p = sapp(b, p, max, "  "); p = sdec(b, p, max, (uint64_t)i); p = sapp(b, p, max, "  0x");
        p = shexw(b, p, max, rips[i], 8); p = sapp(b, p, max, "\n");
    }
    if (!n) p = sapp(b, p, max, "  (none — sys_singlestep(n) first)\n");
    if (p < max) b[p] = 0; return p;
}

long procfs_read(const char *abs, void *buf, unsigned long max) {
    if (max == 0) return -1;
    /* NESTED NODES FIRST, and the order is the whole point (M1971). This call
     * used to sit after the "/proc/" block, which returns -1 for any name it
     * does not recognise -- so /proc/sys/vm/mmap_min_addr was reported to
     * EXIST by procfs_exists, opened successfully, and then failed its read
     * with EBADF. A file that exists until you touch it is worse than one that
     * is simply absent: the caller has already committed to using it. */
    { long sn = sysfs_read(abs, (char *)buf, (int)max); if (sn >= 0) return sn; }
    if (startswith(abs, "/proc/")) {
        int pid; const char *file;
        if (proc_pid_path(abs, &pid, &file)) {            /* /proc/<pid>/... */
            int st = 0; void *proc = proc_find(pid, &st);
            if (!proc) return -1;
            if (peq(file, "status"))  return gen_pid_status((char *)buf, (int)max, pid, st, proc);
            if (peq(file, "stat"))    return gen_pid_stat((char *)buf, (int)max, pid, st, proc);   /* ps/top line (M1231) */
            if (peq(file, "io"))      return gen_pid_io((char *)buf, (int)max, proc);              /* I/O byte counters (M1244) */
            if (peq(file, "statm"))   return gen_pid_statm((char *)buf, (int)max, proc);           /* short memory line (M1245) */
            if (peq(file, "wchan"))   return gen_pid_wchan((char *)buf, (int)max, pid);            /* per-pid blocked-PC symbol (M1247) */
            if (peq(file, "cwd"))     return gen_pid_cwd((char *)buf, (int)max, proc);             /* current directory (M1249) */
            if (peq(file, "exe"))     return gen_pid_exe((char *)buf, (int)max, proc);             /* program image path (M1250) */
            if (peq(file, "root")) { char *bb = (char *)buf; if (max >= 3) { bb[0] = '/'; bb[1] = '\n'; bb[2] = 0; return 2; } return 0; }  /* no per-proc chroot -> "/" (M1249) */
            /* cgroup v2's one-line format. We have no cgroups, and "0::/" is
             * how Linux says "the root of the unified hierarchy" -- which is
             * the truth here. A runtime reads this to discover a container
             * memory limit; the answer means "not in a container". (M1970) */
            /* /proc/self/mountinfo (M2013). Gecko reads it before it will
             * trust the profile directory: mozilla::GetFilesystemType asks
             * which filesystem a path is on, because that decides whether
             * SQLite may use WAL, whether the cache may memory-map, and
             * whether shared memory is available. ENOENT is the one answer it
             * cannot act on -- it has no fallback for "there are no mounts".
             *
             * The mount-id/parent-id/major:minor fields are made up, and that
             * is fine: nothing reads them for identity. The FSTYPE column is
             * the load-bearing one, and /dev/shm being tmpfs is the specific
             * fact a program checks before using POSIX shared memory. */
            if (peq(file, "mountinfo")) {
                const char *c =
                    "15 1 8:1 / / rw,relatime - ext2 /dev/sda2 rw\n"
                    "16 15 0:15 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n"
                    "17 15 0:16 / /dev rw,nosuid - devtmpfs devtmpfs rw,mode=755\n"
                    "18 17 0:17 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw\n"
                    "19 15 0:18 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw\n";
                int n = 0; while (c[n] && n < max - 1) { ((char *)buf)[n] = c[n]; n++; }
                ((char *)buf)[n] = 0; return n;
            }
            /* ...and the older per-process view of the same thing, which is
             * what code that predates mountinfo reads. Same list, /etc/mtab
             * format, and it must AGREE with the one above. */
            if (peq(file, "mounts")) {
                const char *c =
                    "/dev/sda2 / ext2 rw,relatime 0 0\n"
                    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
                    "devtmpfs /dev devtmpfs rw,nosuid,mode=755 0 0\n"
                    "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
                    "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n";
                int n = 0; while (c[n] && n < max - 1) { ((char *)buf)[n] = c[n]; n++; }
                ((char *)buf)[n] = 0; return n;
            }
            if (peq(file, "cgroup")) { const char *c = "0::/\n"; int n = 0; while (c[n] && n < max - 1) { ((char *)buf)[n] = c[n]; n++; } ((char *)buf)[n] = 0; return n; }
            if (peq(file, "wss"))     return gen_pid_wss((char *)buf, (int)max, pid, proc);
            if (peq(file, "oom_score")) return gen_pid_oom((char *)buf, (int)max, proc);            /* OOM victim score (M1277) */
            if (peq(file, "oom_score_adj")) return gen_pid_oom_score_adj((char *)buf, (int)max, proc);  /* OOM tuning bias rw (M1282) */
            if (startswith(file, "mem/")) return gen_pid_mem((char *)buf, (int)max, proc, file + 4);
            if (peq(file, "strace")) return strace_format(pid, (char *)buf, (int)max);   /* traced syscalls (M1118) */
            if (peq(file, "regs"))   return gen_pid_regs((char *)buf, (int)max, proc);   /* ring-3 register file (M1119) */
            if (peq(file, "sstrace")) return gen_pid_sstrace((char *)buf, (int)max, proc); /* single-step trace (M1123) */
            if (peq(file, "sigfd")) {                                                     /* signalfd: next signo, blocks (M1126) */
                if (proc != (void *)app_current()) return -1;   /* only your OWN signals */
                return app_sigfd_read((app_t *)proc, (char *)buf, (int)max);
            }
            if (peq(file, "maps"))    return app_format_maps((app_t *)proc, (char *)buf, (int)max);
            if (peq(file, "comm")) {                                                                   /* the process's runtime name (M1225) */
                const char *t = app_title((app_t *)proc); int p = 0;
                while (t && t[p] && p < (int)max - 2) { ((char *)buf)[p] = t[p]; p++; }
                if (p < (int)max - 1) ((char *)buf)[p++] = '\n';
                return p;
            }
            if (peq(file, "limits"))  return app_format_limits((app_t *)proc, (char *)buf, (int)max);   /* enforced rlimits (M1214) */
            if (peq(file, "auxv"))    return app_format_auxv((app_t *)proc, (char *)buf, (int)max);     /* ELF auxiliary vector (M1215) */
            if (peq(file, "smaps"))   return app_format_smaps((app_t *)proc, (char *)buf, (int)max);
            if (peq(file, "pagemap")) return app_format_pagemap((app_t *)proc, (char *)buf, (int)max);
            if (peq(file, "fd"))      return app_format_fds((app_t *)proc, (char *)buf, (int)max);   /* M1194 */
            if (peq(file, "cmdline")) {
                char *bb = (char *)buf; int p = sapp(bb, 0, (int)max, app_title((app_t *)proc));
                const char *arg = app_arg((app_t *)proc);
                if (arg && arg[0]) { p = sapp(bb, p, (int)max, " "); p = sapp(bb, p, (int)max, arg); }
                p = sapp(bb, p, (int)max, "\n"); bb[p] = 0; return p;
            }
            return -1;                                    /* ctl is write-only; unknown file */
        }
        const char *f = abs + 6;
        for (int i = 0; i < NPROC; i++)
            if (peq(f, proc_files[i].name)) return proc_files[i].gen((char *)buf, (int)max);
        return -1;
    }
    if (startswith(abs, "/dev/")) {
        const char *f = abs + 5;
        if (peq(f, "null"))   return 0;                         /* EOF */
        if (peq(f, "zero") || peq(f, "full")) {                 /* a bufferful of zeros */
            unsigned long n = max < 4096 ? max : 4096;
            for (unsigned long i = 0; i < n; i++) ((char *)buf)[i] = 0;
            return (long)n;
        }
        if (peq(f, "random") || peq(f, "urandom")) {            /* CSPRNG bytes (hardware-seeded) */
            unsigned long n = max < 4096 ? max : 4096;
            random_bytes(buf, n);
            return (long)n;
        }
        if (peq(f, "clipboard"))                                 /* the system clipboard as a file */
            return (long)clip_get((char *)buf, (int)max);
        if (peq(f, "kmsg"))   return klog_copy((char *)buf, (int)max);   /* the kernel log ring, like /proc/kmsg (M1216) */
    }
    return -1;
}

long procfs_write(const char *abs, const void *buf, unsigned long len) {
    if (startswith(abs, "/dev/")) {
        const char *f = abs + 5;
        if (peq(f, "null") || peq(f, "zero")) return (long)len;  /* discard, "succeed" */
        if (peq(f, "full")) return -1;                           /* always ENOSPC */
        if (peq(f, "clipboard")) { clip_set((const char *)buf, (int)len); return (long)len; }
        if (peq(f, "kmsg")) { klog_write((const char *)buf, (int)len); return (long)len; }   /* userspace -> the kernel log ring (M1216) */
        return -1;                                               /* other /dev nodes: read-only */
    }
    if (startswith(abs, "/proc/")) {
        if (peq(abs + 6, "profile")) {                               /* echo on|off|reset > /proc/profile (M1086) */
            char cmd[16]; int c = 0; const char *s = (const char *)buf;
            for (unsigned long i = 0; i < len && c < 15 && s[i] && s[i] != '\n' && s[i] != ' '; i++) cmd[c++] = s[i];
            cmd[c] = 0; prof_control(cmd); return (long)len;
        }
        if (peq(abs + 6, "fw")) {                                    /* echo "drop in icmp" > /proc/fw (M1100) */
            char cmd[64]; int c = 0; const char *s = (const char *)buf;
            for (unsigned long i = 0; i < len && c < 63 && s[i] && s[i] != '\n'; i++) cmd[c++] = s[i];
            cmd[c] = 0; fw_control(cmd, c); return (long)len;
        }
        if (peq(abs + 6, "sysrq-trigger")) {                         /* magic SysRq (M1278): echo a key > /proc/sysrq-trigger */
            char k = len > 0 ? ((const char *)buf)[0] : 0;
            switch (k) {
                case 'f':                                            /* invoke the OOM killer to reclaim memory */
                    kprintf("[sysrq] manual OOM kill requested\n"); app_oom_kill(); break;
                case 'm':                                            /* dump memory info to the kernel log */
                    kprintf("[sysrq] MemTotal: %lu kB  MemFree: %lu kB\n",
                            pmm_total_bytes() / 1024, pmm_free_bytes() / 1024); break;
                default:                                             /* 'h' / anything else: list the keys */
                    kprintf("[sysrq] HELP: f=oom-kill m=show-memory h=help\n"); break;
            }
            return (long)len;
        }
        int pid; const char *file;
        if (proc_pid_path(abs, &pid, &file) && peq(file, "ctl")) {   /* echo CMD > /proc/<pid>/ctl */
            void *proc = proc_find(pid, 0);
            if (!proc) return -1;
            char cmd[16]; int c = 0; const char *s = (const char *)buf;
            for (unsigned long i = 0; i < len && c < 15 && s[i] && s[i] != '\n' && s[i] != ' '; i++) cmd[c++] = s[i];
            cmd[c] = 0;
            if (peq(cmd, "kill")) { app_request_kill((app_t *)proc); return (long)len; }
            if (peq(cmd, "stop")) { task_stop((task_t *)app_task((app_t *)proc)); return (long)len; }
            if (peq(cmd, "cont")) { task_cont((task_t *)app_task((app_t *)proc)); return (long)len; }
            if (peq(cmd, "trace"))   { app_set_traced((app_t *)proc, 1); return (long)len; }   /* strace -> dmesg (M1084) */
            if (peq(cmd, "untrace")) { app_set_traced((app_t *)proc, 0); return (long)len; }
            if (peq(cmd, "clearref")) { vmm_clear_accessed(app_cr3((app_t *)proc)); return (long)len; }  /* reset the /proc/<pid>/wss window (M1093) */
            return -1;                                            /* unknown command */
        }
        if (proc_pid_path(abs, &pid, &file) && peq(file, "oom_score_adj")) {   /* echo N > /proc/<pid>/oom_score_adj (M1282) */
            void *proc = proc_find(pid, 0); if (!proc) return -1;
            const char *s = (const char *)buf; int i = 0, neg = 0, v = 0;
            if (i < (int)len && s[i] == '-') { neg = 1; i++; }
            for (; i < (int)len && s[i] >= '0' && s[i] <= '9'; i++) v = v * 10 + (s[i] - '0');
            app_oom_adj_set((app_t *)proc, neg ? -v : v);
            return (long)len;
        }
        return -1;                                               /* /proc otherwise read-only */
    }
    return -2;                                                   /* not ours */
}

int procfs_list(const char *dir, vfs_dirent *out, int max) {
    int n = 0;
    if (peq(dir, "/proc") || peq(dir, "/proc/")) {
        for (int i = 0; i < NPROC && n < max; i++) {
            int k = 0; const char *s = proc_files[i].name;
            while (s[k] && k < 62) { out[n].name[k] = s[k]; k++; }
            out[n].name[k] = 0; out[n].size = 0; out[n].date = out[n].time = 0; n++;
        }
    } else if (peq(dir, "/dev/dri") || peq(dir, "/dev/dri/")) {
        if (virtio_gpu_has_3d() && n < max) {
            const char *s2 = "renderD128";
            int k = 0; while (s2[k] && k < 62) { out[n].name[k] = s2[k]; k++; }
            out[n].name[k] = 0; out[n].size = 0; out[n].date = out[n].time = 0; n++;
        }
    } else if (peq(dir, "/dev") || peq(dir, "/dev/")) {
        /* `dri` is in this listing but not in dev_files, because dev_files is
         * the character-device table and this is a directory. A program that
         * scans /dev looking for a GPU needs to SEE it here. (M2351) */
        if (virtio_gpu_has_3d() && n < max) {
            const char *d2 = "dri";
            int k = 0; while (d2[k] && k < 62) { out[n].name[k] = d2[k]; k++; }
            out[n].name[k] = 0; out[n].size = 0; out[n].date = out[n].time = 0; n++;
        }
        for (int i = 0; i < NDEV && n < max; i++) {
            int k = 0; const char *s = dev_files[i];
            while (s[k] && k < 62) { out[n].name[k] = s[k]; k++; }
            out[n].name[k] = 0; out[n].size = 0; out[n].date = out[n].time = 0; n++;
        }
    }
    return n;
}
