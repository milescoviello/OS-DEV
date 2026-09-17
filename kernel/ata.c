/*
 * ata.c — minimal ATA (IDE) disk driver, PIO mode.
 *
 * This is the *block device*: the lowest layer of storage, which reads and
 * writes the disk in fixed 512-byte sectors addressed by a linear number (LBA).
 * The filesystem (FAT32) sits on top and gives those sectors meaning (files and
 * directories).
 *
 * "PIO" (Programmed I/O) means the CPU itself moves every word through the data
 * port — slow, but dead simple and perfect for learning. We talk to the
 * controller through its command-block I/O ports.
 *
 * The legacy PC has up to four ATA disks on two buses:
 *
 *   drive 0  primary master    I/O 0x1F0  ctrl 0x3F6   drive-select 0xE0
 *   drive 1  primary slave     I/O 0x1F0  ctrl 0x3F6   drive-select 0xF0
 *   drive 2  secondary master  I/O 0x170  ctrl 0x376   drive-select 0xE0
 *   drive 3  secondary slave   I/O 0x170  ctrl 0x376   drive-select 0xF0
 *
 * The original driver spoke only to drive 0 (the boot disk). ata_read()/
 * ata_write() still do exactly that — they are now thin wrappers over the
 * drive-parameterised core — so the FAT32 boot mount is untouched. The new
 * ata_read_drive()/ata_identify_all() add the other three drives so the
 * partition layer can enumerate every disk attached to the machine.
 */
#include "ata.h"
#include "bcache.h"   /* unified kernel-wide block cache (M1869) */
#include "io.h"
#include "console.h"
#include "pci.h"
#include "pmm.h"
#include "vmm.h"
#include "string.h"
#include "timer.h"
#include "task.h"

/* Per-bus command-block + control-block base ports. A drive's I/O base depends
 * only on its bus (primary/secondary); master vs slave is the DRV bit in the
 * drive-select register (0xA0 base, |0x10 = slave). */
#define PRIMARY_IO    0x1F0
#define PRIMARY_CTRL  0x3F6
#define SECONDARY_IO  0x170
#define SECONDARY_CTRL 0x376

/* Command-block register offsets from the I/O base. */
#define REG_DATA      0      /* r/w  16-bit data port */
#define REG_ERROR     1      /* r    error */
#define REG_FEATURES  1      /* w    features */
#define REG_SECCOUNT  2      /* r/w  sector count */
#define REG_LBA0      3      /* r/w  LBA bits 0..7   (also sector number) */
#define REG_LBA1      4      /* r/w  LBA bits 8..15  (also cylinder low) */
#define REG_LBA2      5      /* r/w  LBA bits 16..23 (also cylinder high) */
#define REG_DRIVE     6      /* r/w  drive/head select */
#define REG_STATUS    7      /* r    status */
#define REG_COMMAND   7      /* w    command */

#define ST_BSY 0x80          /* busy */
#define ST_DRDY 0x40         /* device ready */
#define ST_DRQ 0x08          /* data request ready */
#define ST_ERR 0x01

#define CMD_READ_SECTORS  0x20
#define CMD_WRITE_SECTORS 0x30
#define CMD_READ_SECTORS_EXT  0x24   /* LBA48 PIO read  */
#define CMD_WRITE_SECTORS_EXT 0x34   /* LBA48 PIO write */
#define CMD_FLUSH         0xE7
#define CMD_FLUSH_EXT     0xEA        /* LBA48 cache flush */
#define CMD_IDENTIFY      0xEC

/* The four legacy drives, in index order. */
static const struct { uint16_t io, ctrl; uint8_t slave; } ATA_DRIVES[ATA_MAX_DRIVES] = {
    { PRIMARY_IO,   PRIMARY_CTRL,   0 },   /* 0: primary master   */
    { PRIMARY_IO,   PRIMARY_CTRL,   1 },   /* 1: primary slave    */
    { SECONDARY_IO, SECONDARY_CTRL, 0 },   /* 2: secondary master */
    { SECONDARY_IO, SECONDARY_CTRL, 1 },   /* 3: secondary slave  */
};

/* Discovered drives, filled lazily on first IDENTIFY (ata_identify_all). */
static struct ata_drive_info g_drives[ATA_MAX_DRIVES];
static int g_probed;          /* have we run the IDENTIFY sweep yet? */

static int drive_ok(int drive) { return drive >= 0 && drive < ATA_MAX_DRIVES; }

/* The legacy ATA command-block registers are ONE shared hardware resource
 * (drive-select/LBA/command/status, all at the same handful of I/O ports) --
 * there is no way for two in-flight transactions to interleave and both come
 * out correct, PIO or DMA, same drive or not (the DMA channels still share
 * the drive's own task-file registers for addressing). This was never
 * enforced: nothing here ever stopped two tasks from both being mid-transfer
 * at once. It went unnoticed for a long time because most disk I/O used to
 * come from one thread of control, but M1531 gave this kernel a REAL
 * preemptive multi-core scheduler -- and the desktop redraws its Files panel
 * (a full directory re-scan, kernel/desktop.c's KIND_FILES case) on almost
 * every frame, so it is very often mid-ata_read at the exact moment some
 * OTHER task (e.g. a ring-3 dlopen()) also wants the disk. That's the real
 * root cause behind the M1539 dlxtest flakiness -- not a slow timeout, an
 * actual unsynchronized race on shared hardware. A plain cross-core spinlock
 * (the same atomic-exchange pattern task.c's rq_lock uses) fixes it: no IRQ
 * handler ever touches ata.c (confirmed -- this driver is polled, not
 * interrupt-driven), so there's no need for task.c's additional local
 * irq_save/restore, just mutual exclusion across cores. */
static volatile int ata_lock;
/* Spin tightly for a short while (the common case: the lock is held only for
 * a quick transfer), then start YIELDING instead of pure-spinning. Found via
 * a real, reproduced hang: task 0 (the desktop main loop, PERMANENTLY pinned
 * to the BSP -- see task_t's pin_core comment) held the lock through a slow
 * multi-sector operation while another task, scheduled on that SAME core,
 * pure-spun waiting for it -- burning the very CPU time that would have let
 * the holder finish and release the lock sooner, extending the wait instead
 * of just riding it out. task_yield() breaks that: it hands the CPU back to
 * the scheduler instead of consuming a whole timeslice on a doomed poll. */
/* Who holds it, for the stuck-waiter report below. -1 = free. Written only
 * inside the critical section, so a torn read is impossible. */
static volatile int ata_lock_owner = -1;

/* A waiter that has yielded this many times has been waiting for minutes, which
 * is never legitimate -- the longest real transfer is orders of magnitude
 * shorter. Report ONCE and keep waiting (reporting is a diagnostic, not a
 * recovery: silently breaking the lock would corrupt an in-flight transfer). */
#define ATA_LOCK_STUCK_YIELDS 20000u

static inline void ata_lock_take(void) {
    uint32_t spins = 0, yields = 0; int reported = 0;
    while (__atomic_exchange_n(&ata_lock, 1, __ATOMIC_ACQUIRE)) {
        if (++spins >= 1000) {
            spins = 0; task_yield();
            /* M1911: make an ATA-lock deadlock SAY SO. This was found the hard
             * way -- a boot hang whose only symptom was the serial log stopping
             * mid-TLS, which cost an entire investigation to localise by
             * sampling RIP through the QEMU monitor. Every task that needs the
             * disk piles up here, so the first thing worth knowing is who is
             * holding it and that nobody is progressing. */
            if (!reported && ++yields >= ATA_LOCK_STUCK_YIELDS) {
                reported = 1;
                kprintf("[ata] LOCK STUCK: task %d has waited ~minutes for ata_lock, "
                        "held by task %d. Nothing that touches the disk can proceed "
                        "(app launch, FS reads) until it is released.\n",
                        task_current_id(), ata_lock_owner);
            }
        }
        else __asm__ volatile("pause");
    }
    ata_lock_owner = task_current_id();
}
static inline void ata_lock_give(void) {
    ata_lock_owner = -1;
    __atomic_store_n(&ata_lock, 0, __ATOMIC_RELEASE);
}

/* --- low-level busy/DRQ polling, scoped to a given I/O base ---------------- */

/* A real wall-clock bound, not a raw iteration count: under host CPU
 * contention (several QEMU instances, a busy build) the wall-clock time
 * behind a fixed spin count varies a lot, so a count-based "timeout" can
 * genuinely expire before an emulated drive finishes — a real, observed
 * source of transient read failures (see the osdev-ata-pio-busywait-flakiness
 * memory), not a sign of a stuck device. 300ms is still generous for any real
 * or emulated ATA command (which normally completes in low single-digit ms)
 * -- kept modest on purpose, since kernel/fat32.c's ata_read_retry() can
 * multiply a single stuck sector into 3 of these in a row, and one caller
 * (a directory scan) can need one per sector: an overly generous bound here
 * compounds into a multi-TEN-second worst case while holding ata_lock, which
 * is what actually caused a real, reproduced httpd-server hang (a slow
 * lock-holder + a busy-spinning waiter competing for the same core -- see
 * ata_lock_take's own comment). ATA_SPIN_HARDCAP is a zero-cost last-resort
 * fallback in case this is ever reached before the timer/interrupts are up
 * (it never is today — timer_init()+interrupts_enable() run at kmain.c's
 * boot, long before any ATA call — but a wall-clock check alone would spin
 * forever if timer_ms() ever stopped advancing). */
#define ATA_TIMEOUT_MS    300u
#define ATA_SPIN_HARDCAP  100000000u

static int wait_busy_clear(uint16_t io) {
    uint64_t deadline = timer_ms() + ATA_TIMEOUT_MS;
    for (uint32_t i = 0; i < ATA_SPIN_HARDCAP; i++) {
        if (!(inb(io + REG_STATUS) & ST_BSY))
            return 0;
        if (timer_ms() >= deadline) return -1;
    }
    return -1;
}

static int wait_drq(uint16_t io) {
    uint64_t deadline = timer_ms() + ATA_TIMEOUT_MS;
    for (uint32_t i = 0; i < ATA_SPIN_HARDCAP; i++) {
        uint8_t s = inb(io + REG_STATUS);
        if (s & ST_ERR) return -1;
        if (!(s & ST_BSY) && (s & ST_DRQ)) return 0;
        if (timer_ms() >= deadline) return -1;
    }
    return -1;
}

/* Read `words` 16-bit words from the data port into `buf`. */
static void read_data(uint16_t io, void *buf, int words) {
    __asm__ volatile("rep insw"
                     : "+D"(buf), "+c"(words)
                     : "d"((uint16_t)(io + REG_DATA))
                     : "memory");
}

static void write_data(uint16_t io, const void *buf, int words) {
    __asm__ volatile("rep outsw"
                     : "+S"(buf), "+c"(words)
                     : "d"((uint16_t)(io + REG_DATA))
                     : "memory");
}

/* Select a drive + program an LBA28 access. `slave` picks master/slave; the top
 * LBA nibble goes in the low 4 bits of the drive register. */
static void select_lba(uint16_t io, uint8_t slave, uint32_t lba, uint8_t count) {
    outb(io + REG_DRIVE, 0xE0 | (slave ? 0x10 : 0) | ((lba >> 24) & 0x0F));
    outb(io + REG_SECCOUNT, count);
    outb(io + REG_LBA0, (uint8_t)(lba & 0xFF));
    outb(io + REG_LBA1, (uint8_t)((lba >> 8) & 0xFF));
    outb(io + REG_LBA2, (uint8_t)((lba >> 16) & 0xFF));
}

/* Program a 48-bit LBA access: LBA mode with no address bits in the drive
 * register, then each of the seccount/LBA0..2 registers written TWICE — the high
 * byte first (latched as the "previous" content) then the low byte. This lets the
 * primary ATA path reach past the LBA28 128 GiB ceiling (up to the 2 TB the
 * 32-bit `lba` argument allows). */
static void select_lba48(uint16_t io, uint8_t slave, uint64_t lba, uint16_t count) {
    outb(io + REG_DRIVE, 0x40 | (slave ? 0x10 : 0));
    outb(io + REG_SECCOUNT, (uint8_t)(count >> 8));
    outb(io + REG_LBA0, (uint8_t)(lba >> 24));
    outb(io + REG_LBA1, (uint8_t)(lba >> 32));
    outb(io + REG_LBA2, (uint8_t)(lba >> 40));
    outb(io + REG_SECCOUNT, (uint8_t)(count & 0xFF));
    outb(io + REG_LBA0, (uint8_t)(lba & 0xFF));
    outb(io + REG_LBA1, (uint8_t)((lba >> 8) & 0xFF));
    outb(io + REG_LBA2, (uint8_t)((lba >> 16) & 0xFF));
}

/* LBA48 PIO read/write — the mirror of the LBA28 impls below, used only for
 * accesses that reach sector >= 2^28 (see the dispatch in those impls). Chunks
 * are still bounded at 256 sectors (count <= 256 fits the 16-bit EXT count). */
static int ata_read_drive_impl_lba48(int drive, uint32_t lba, uint32_t count, void *buf) {
    uint16_t io = ATA_DRIVES[drive].io;
    uint8_t slave = ATA_DRIVES[drive].slave;
    uint8_t *p = buf;
    while (count > 0) {
        uint32_t chunk = count > 256 ? 256 : count;
        if (wait_busy_clear(io) < 0) return -1;
        select_lba48(io, slave, lba, (uint16_t)chunk);
        outb(io + REG_COMMAND, CMD_READ_SECTORS_EXT);
        for (uint32_t s = 0; s < chunk; s++) {
            if (wait_drq(io) < 0) return -1;
            read_data(io, p, SECTOR_SIZE / 2);
            p += SECTOR_SIZE;
        }
        lba += chunk;
        count -= chunk;
    }
    return 0;
}

static int ata_write_drive_impl_lba48(int drive, uint32_t lba, uint32_t count, const void *buf) {
    uint16_t io = ATA_DRIVES[drive].io;
    uint8_t slave = ATA_DRIVES[drive].slave;
    const uint8_t *p = buf;
    while (count > 0) {
        uint32_t chunk = count > 256 ? 256 : count;
        if (wait_busy_clear(io) < 0) return -1;
        select_lba48(io, slave, lba, (uint16_t)chunk);
        outb(io + REG_COMMAND, CMD_WRITE_SECTORS_EXT);
        for (uint32_t s = 0; s < chunk; s++) {
            if (wait_drq(io) < 0) return -1;
            write_data(io, p, SECTOR_SIZE / 2);
            p += SECTOR_SIZE;
        }
        outb(io + REG_COMMAND, CMD_FLUSH_EXT);
        wait_busy_clear(io);
        lba += chunk;
        count -= chunk;
    }
    return 0;
}

/* --- drive-parameterised read/write core ---------------------------------- */

static int ata_read_drive_impl(int drive, uint32_t lba, uint32_t count, void *buf) {
    if (!drive_ok(drive) || count == 0) return -1;
    /* Any access reaching sector 2^28 or beyond needs LBA48; low accesses (all of
     * the boot / FAT path) keep the proven LBA28 code below, byte-for-byte. */
    if ((uint64_t)lba + count > (1u << 28))
        return ata_read_drive_impl_lba48(drive, lba, count, buf);
    uint16_t io = ATA_DRIVES[drive].io;
    uint8_t slave = ATA_DRIVES[drive].slave;

    /* LBA28 sector count is an 8-bit field (0 means 256). Loop in chunks so a
     * caller can request more than 256 sectors in one call. */
    uint8_t *p = buf;
    while (count > 0) {
        uint32_t chunk = count > 256 ? 256 : count;
        if (wait_busy_clear(io) < 0)
            return -1;
        select_lba(io, slave, lba, (uint8_t)(chunk & 0xFF));   /* 256 -> 0 in the register */
        outb(io + REG_COMMAND, CMD_READ_SECTORS);
        for (uint32_t s = 0; s < chunk; s++) {
            if (wait_drq(io) < 0)
                return -1;
            read_data(io, p, SECTOR_SIZE / 2);                 /* 256 words = 512 bytes */
            p += SECTOR_SIZE;
        }
        lba += chunk;
        count -= chunk;
    }
    return 0;
}

/* Public entry point: the whole multi-chunk transfer above is one hardware
 * transaction as far as mutual exclusion is concerned (see ata_lock's
 * comment) -- take the lock for its full duration, not per-chunk, so a large
 * transfer can't be sliced up and interleaved with someone else's. */
/* --- single-sector read cache (M1855) ---------------------------------------
 * fat32 walks the FAT + directory sectors over and over, re-reading the same
 * LBAs; each miss is a full PIO sector transfer off the disk. A small LRU cache
 * of single-sector reads turns those repeats into a memcpy. COHERENT: every
 * write path (ata_write_drive) invalidates the sectors it touches, and all
 * access is inside ata_lock (so it is SMP-safe, same as the transfers). Only
 * count==1 reads are cached (the fat32 hot path); multi-sector reads bypass. */
/* Block caching moved to the unified kernel-wide cache (kernel/bcache.c, M1869):
 * ata reads/writes go through it under the ATA owner namespace, so the boot disk
 * shares one 64 KiB LRU pool + one /proc/bcache stat with every other block
 * device instead of ata keeping a private 32 KiB copy. Behaviour is unchanged —
 * single-sector read cache + write-through invalidation. */
/* Drop everything (e.g. before a DMA write path that bypasses ata_write_drive,
 * and the journal's flush hook). */
void ata_cache_flush(void) { bcache_flush(); }

/* WHAT THE DISK ACTUALLY COSTS (M2091).
 *
 * The question the whole optimisation phase turns on, and nothing could answer
 * it: is a two-and-a-half-minute Firefox startup disk-bound, or is it TCG
 * executing Firefox's own code? Those need completely different work, and
 * guessing which costs a week.
 *
 * So: count the commands, the sectors, and the CYCLES SPENT INSIDE THE DRIVER,
 * separately for cache hits and real transfers. Cycles rather than
 * milliseconds because a single PIO sector is far below the 10 ms PIT tick,
 * and rdtsc is the only clock here with the resolution to see one.
 *
 * The number that makes this unfalsifiable is the ratio printed at the end:
 * driver cycles against the whole boot's cycles. If the disk is 5% of the
 * boot, no amount of block-cache work will make the boot feel different, and
 * that is worth knowing BEFORE writing any of it. */
static uint64_t io_cmds, io_sectors, io_hits, io_cyc_xfer, io_cyc_hit;
static inline uint64_t ata_tsc(void) {
    uint32_t lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
static uint64_t io_dma_cmds;
uint64_t ata_dma_commands(void) { return io_dma_cmds; }
void ata_io_stats(uint64_t *cmds, uint64_t *sectors, uint64_t *hits,
                  uint64_t *cyc_xfer, uint64_t *cyc_hit) {
    if (cmds)     *cmds     = io_cmds;
    if (sectors)  *sectors  = io_sectors;
    if (hits)     *hits     = io_hits;
    if (cyc_xfer) *cyc_xfer = io_cyc_xfer;
    if (cyc_hit)  *cyc_hit  = io_cyc_hit;
}

/* READS GO BY DMA WHEN THEY CAN (M2091).
 *
 * MEASURED, not assumed, and the measurement is the whole reason this exists:
 *
 *   64 sectors as 64 single-sector PIO commands: 4780 Kcycles
 *   the same 64 as 8 eight-sector PIO commands:  4804 Kcycles   (0.99x -- NOTHING)
 *   the same 64 by DMA, 8 eight-sector transfers: 611 Kcycles   (7.81x)
 *
 * The middle line is the surprise and it killed the plan's headline disk fix.
 * "blockdev_read shreds every request into single sectors" is true, and
 * un-shredding it is worth nothing at all -- because PIO's cost is the insw
 * DATA TRANSFER, not the per-command overhead, and eight sectors in one
 * command still moves eight sectors a word at a time through an I/O port. Under
 * TCG every one of those words is a device access.
 *
 * DMA is the only thing that changes the quantity being paid for: the
 * controller moves the bytes and the emulator does it as a memcpy. 7.81x, on a
 * path that already existed and had never been given a reason to be preferred.
 *
 * Reads only. A write going wrong is a corrupted disk; a read going wrong is a
 * wrong byte in RAM, which the self-test below can catch outright. And any DMA
 * failure falls back to PIO rather than failing the read, so a controller that
 * misbehaves costs speed and not correctness. */
int g_ata_dma_reads = 1;        /* -append nodma turns it off, for A/B measurement */
/* A read bigger than this does not populate the block cache -- see the note at
 * the install. One eighth of the cache, so eight such reads could at worst
 * turn it over once rather than a single read wiping it. (M2101) */
#define BCACHE_INSTALL_MAX 16u
/* 16 FRAMES = 64 KiB = 128 SECTORS PER TRANSFER (M2101).
 *
 * Was one frame, so eight sectors, so a Firefox first paint needed 206704
 * commands to move 1607420 sectors -- measured under KVM, where emulation is
 * not in the way and the number is therefore about this kernel rather than
 * about TCG. 64 KiB is also exactly FAULT_READAHEAD_PAGES, so a readahead
 * window becomes ONE command instead of sixteen. */
#define ATA_DMA_FRAMES 16
#define ATA_DMA_BOUNCE_SECTORS (ATA_DMA_FRAMES * (PAGE_SIZE / SECTOR_SIZE))   /* 128 */
static int ata_dma_xfer_impl(int drive, uint32_t lba, uint32_t count, void *buf, int write);
static int ata_dma_setup(void);

int ata_read_drive(int drive, uint32_t lba, uint32_t count, void *buf) {
    ata_lock_take();
    uint64_t t0 = ata_tsc();
    if (count == 1 && bcache_lookup(BCACHE_OWNER_ATA(drive), lba, buf)) {
        io_cyc_hit += ata_tsc() - t0; io_hits++;
        ata_lock_give(); return 0;
    }
    /* A MULTI-SECTOR READ MUST ALSO USE THE CACHE, IN BOTH DIRECTIONS (M2091).
     *
     * The install was `if (count == 1)`, and so was the lookup. That was
     * self-consistent while every caller read one sector at a time -- which is
     * what blockdev_read did, and it is exactly what has to stop. But batching
     * without this would have been a silent regression: multi-sector reads
     * would neither consult the cache nor populate it, so a boot that was
     * getting 2.5 million hits against 917 thousand misses would get none, and
     * the batching win would be paid for with a cache that no longer works.
     * The plan called this out and it was right to.
     *
     * Whole-range hit first -- cheap, and the common case for a re-read -- then
     * one transfer, then install every sector of it. */
    if (count > 1) {
        int all = 1;
        for (uint32_t k = 0; k < count; k++)
            if (!bcache_lookup(BCACHE_OWNER_ATA(drive), lba + k,
                               (uint8_t *)buf + (uint64_t)k * SECTOR_SIZE)) { all = 0; break; }
        if (all) { io_cyc_hit += ata_tsc() - t0; io_hits++; ata_lock_give(); return 0; }
    }
    int r = -1;
    if (g_ata_dma_reads && count <= ATA_DMA_BOUNCE_SECTORS && ata_dma_setup()) {
        r = ata_dma_xfer_impl(drive, lba, count, buf, 0);
        if (r >= 0) io_dma_cmds++;
    }
    if (r < 0) r = ata_read_drive_impl(drive, lba, count, buf);   /* PIO fallback, always */
    /* SCAN-RESISTANT INSERTION (M2101). The block cache is 128 sectors, and
     * M2101 raised the transfer ceiling to 128 -- so ONE streaming read would
     * install 128 entries and evict every other thing in it. A sequential walk
     * through a 500 MB library closure would leave the cache holding only the
     * last 64 KiB it happened to touch, which is the one thing nobody is about
     * to ask for again.
     *
     * So a big read does not populate it. The cache exists for the small,
     * repeated, random reads -- inodes, directory blocks, indirect blocks, the
     * superblock -- which are exactly the ones that fit under this bound and
     * exactly the ones a large read must not be allowed to push out. */
    if (r >= 0 && count <= BCACHE_INSTALL_MAX)
        for (uint32_t k = 0; k < count; k++)
            bcache_install(BCACHE_OWNER_ATA(drive), lba + k,
                           (const uint8_t *)buf + (uint64_t)k * SECTOR_SIZE);
    /* (see ata_read_drive_pio below: the DMA==PIO self-test must NOT come
     * through this function any more, because this function is now DMA.) */
    io_cyc_xfer += ata_tsc() - t0;
    io_cmds++;
    io_sectors += count;
    ata_lock_give();
    return r;
}

/* A READ THAT IS GUARANTEED TO BE PIO (M2091).
 *
 * The DMA==PIO self-test compared ata_read_dma against ata_read_drive, and
 * ata_read_drive is now the DMA path -- so the moment reads were routed
 * through DMA, that test began comparing DMA against DMA and asserting
 * nothing. A test that cannot fail is worse than no test, and this one would
 * have gone on printing "DMA==PIO OK" over a broken transfer.
 *
 * So the comparison needs a second, independent route to the same bytes, and
 * this is it: the PIO implementation, reached deliberately, whatever the DMA
 * policy is. */
int ata_read_drive_pio(int drive, uint32_t lba, uint32_t count, void *buf) {
    ata_lock_take();
    int r = ata_read_drive_impl(drive, lba, count, buf);
    ata_lock_give();
    return r;
}

static int ata_write_drive_impl(int drive, uint32_t lba, uint32_t count, const void *buf) {
    if (!drive_ok(drive) || count == 0) return -1;
    if ((uint64_t)lba + count > (1u << 28))
        return ata_write_drive_impl_lba48(drive, lba, count, buf);
    uint16_t io = ATA_DRIVES[drive].io;
    uint8_t slave = ATA_DRIVES[drive].slave;

    const uint8_t *p = buf;
    while (count > 0) {
        uint32_t chunk = count > 256 ? 256 : count;
        if (wait_busy_clear(io) < 0)
            return -1;
        select_lba(io, slave, lba, (uint8_t)(chunk & 0xFF));
        outb(io + REG_COMMAND, CMD_WRITE_SECTORS);
        for (uint32_t s = 0; s < chunk; s++) {
            if (wait_drq(io) < 0)
                return -1;
            write_data(io, p, SECTOR_SIZE / 2);
            p += SECTOR_SIZE;
        }
        outb(io + REG_COMMAND, CMD_FLUSH);        /* flush the write cache */
        wait_busy_clear(io);
        lba += chunk;
        count -= chunk;
    }
    return 0;
}

int ata_write_drive(int drive, uint32_t lba, uint32_t count, const void *buf) {
    ata_lock_take();
    bcache_inval_range(BCACHE_OWNER_ATA(drive), lba, count);   /* keep the read cache coherent (M1855/M1869) */
    int r = ata_write_drive_impl(drive, lba, count, buf);
    ata_lock_give();
    return r;
}

/* WHAT ONE COMMAND COSTS, MEASURED IN ISOLATION (M2091).
 *
 * The elapsed sums in the boot budget are upper bounds -- a PIO transfer
 * spin-yields, so the TSC across one spans whatever else the core ran. That
 * makes them useless for PREDICTING a win. This measures the thing a
 * prediction needs: the cost of a single command, with nothing else running
 * and the cache bypassed, at one sector and at eight.
 *
 * Why eight: blockdev_read shreds every request into single sectors, so a
 * 4 KiB filesystem block is eight commands. If an eight-sector command costs
 * materially less than eight single-sector ones, the difference IS the win
 * from not shredding, and it can be stated as a number before any of it is
 * written -- and then checked against a re-measurement afterwards.
 *
 * Reads only, and off the END of the disk where nothing structural lives. */
void ata_diskbench(void) {
    const struct ata_drive_info *info = ata_drive(1);
    if (!info || !info->present || info->sectors < 4096) {
        kprintf("[diskbench] drive 1 absent or tiny; skipped\n");
        return;
    }
    static uint8_t buf[8 * SECTOR_SIZE];
    uint32_t base = (uint32_t)(info->sectors - 2048);
    const int N = 64;
    /* Single sectors, N different LBAs so the drive's own cache cannot serve
     * them and our bcache install/lookup is bypassed by going to the impl. */
    ata_lock_take();
    uint64_t t0 = ata_tsc();
    for (int i = 0; i < N; i++) ata_read_drive_impl(1, base + (uint32_t)i, 1, buf);
    uint64_t one = ata_tsc() - t0;
    /* The same 512-byte sectors, eight at a time: N/8 commands for the same
     * bytes. Same LBAs, so the comparison is commands, not data. */
    t0 = ata_tsc();
    for (int i = 0; i < N; i += 8) ata_read_drive_impl(1, base + (uint32_t)i, 8, buf);
    uint64_t eight = ata_tsc() - t0;
    ata_lock_give();       /* ata_read_dma locks for itself: holding it here self-deadlocked,
                            * and "LOCK STUCK: task 0 ... held by task 0" is what said so (M2091) */
    /* AND THE SAME BYTES BY DMA (M2091). The one-vs-eight result above says
     * PIO's cost is the insw DATA TRANSFER and not the per-command overhead --
     * eight sectors in one command still moves eight sectors a word at a time
     * through a port, and under TCG every one of those is a device access. DMA
     * is the only thing that changes that: the controller moves the bytes and
     * QEMU does it as a memcpy into guest RAM.
     *
     * So this is the measurement that decides whether the disk path is worth
     * any work at all. ata_read_dma already exists and is byte-identical; what
     * has never existed is a reason to prefer it, stated as a number. */
    uint64_t dma = 0, dma1 = 0; int dma_ok = 0;
    if (ata_dma_available() && ata_dma_max_sectors() >= 8) {
        t0 = ata_tsc();
        for (int i = 0; i < N; i += 8)
            if (ata_read_dma(1, base + (uint32_t)i, 8, buf) < 0) { dma_ok = -1; break; }
        dma = ata_tsc() - t0;
        /* AND SINGLE-SECTOR DMA, which is the arm that was missing and the one
         * that actually matters (M2091). The first measurement compared
         * EIGHT-sector DMA against SINGLE-sector PIO and reported 8.48x -- two
         * changes at once, and then the read path adopted only one of them:
         * blockdev_read still shreds every request, so 917021 of 917022 reads
         * went by DMA and every one of them moved a single sector.
         *
         * A DMA command has fixed setup: program the PRD, start the bus
         * master, poll for completion, copy out of the bounce buffer. Eight of
         * those for 4 KiB is not the same as one. This arm is what says how
         * much of the 8.48x was DMA and how much was batching -- and therefore
         * whether un-shredding, which the PIO comparison said was worth
         * nothing, is worth everything once the transfer is DMA. */
        t0 = ata_tsc();
        for (int i = 0; i < N; i++)
            if (ata_read_dma(1, base + (uint32_t)i, 1, buf) < 0) { dma_ok = -1; break; }
        dma1 = ata_tsc() - t0;
        if (dma_ok == 0) dma_ok = 1;
    }
    kprintf("[diskbench] %d sectors as %d single-sector commands: %lu Kcycles (%lu Kcycles each)\n",
            N, N, one / 1000, (one / N) / 1000);
    kprintf("[diskbench] the same %d sectors as %d eight-sector commands: %lu Kcycles (%lu Kcycles each)\n",
            N, N / 8, eight / 1000, (eight / (N / 8)) / 1000);
    if (eight)
        kprintf("[diskbench] so NOT shredding a 4 KiB block would be %lu.%02lux cheaper per block\n",
                one / eight, ((one * 100) / eight) % 100);
    if (dma_ok == 1) {
        kprintf("[diskbench] the same %d sectors by DMA, %d eight-sector transfers: %lu Kcycles (%lu Kcycles each)\n",
                N, N / 8, dma / 1000, (dma / (N / 8)) / 1000);
        kprintf("[diskbench] the same %d sectors by DMA, %d SINGLE-sector transfers: %lu Kcycles (%lu Kcycles each)\n",
                N, N, dma1 / 1000, (dma1 / N) / 1000);
        /* FOUR NUMBERS, SO EVERY PAIR CAN BE COMPARED. Reporting only
         * "8-sector DMA vs 1-sector PIO" measured two changes at once and led
         * straight to adopting the wrong half. */
        if (dma)  kprintf("[diskbench]   8-sector DMA vs 1-sector PIO: %lu.%02lux  (both changes)\n",
                          one / dma, ((one * 100) / dma) % 100);
        if (dma1) kprintf("[diskbench]   1-sector DMA vs 1-sector PIO: %lu.%02lux  (DMA alone -- what the read path gets today)\n",
                          one / dma1, ((one * 100) / dma1) % 100);
        if (dma)  kprintf("[diskbench]   8-sector DMA vs 1-sector DMA: %lu.%02lux  (batching alone, ON TOP of DMA)\n",
                          dma1 / dma, ((dma1 * 100) / dma) % 100);
    } else if (dma_ok < 0) {
        kprintf("[diskbench] DMA was available but a transfer FAILED -- not usable as it stands\n");
    } else {
        kprintf("[diskbench] no DMA available on this controller (bounce max %u sectors)\n",
                ata_dma_max_sectors());
    }
}

/* Boot self-test for the read cache (M1855): on drive 0's LAST sector
 * (save+restore, non-destructive — MBR/FAT metadata lives at the start), prove
 * fill→hit and, critically, that a write INVALIDATES the cached copy so a
 * subsequent read sees the new bytes, never a stale hit. No-op if drive 0 is
 * absent. */
void ata_cache_selftest(void) {
    const struct ata_drive_info *info = ata_drive(0);
    if (!info || !info->present || info->sectors == 0) {
        kprintf("[ata-cache] drive 0 absent; read cache present, self-test skipped.\n\n");
        return;
    }
    static uint8_t save[SECTOR_SIZE], pa[SECTOR_SIZE], pb[SECTOR_SIZE], rd[SECTOR_SIZE];
    uint32_t lba = (uint32_t)(info->sectors - 1);
    if (ata_read_drive(0, lba, 1, save) < 0) { kprintf("[ata-cache] save read failed; skipping\n\n"); return; }
    for (int i = 0; i < SECTOR_SIZE; i++) { pa[i] = (uint8_t)(i * 7 + 1); pb[i] = (uint8_t)(i * 13 + 2); }

    uint64_t h0, m0; bcache_counts(&h0, &m0);         /* unified block cache (M1869) */
    ata_write_drive(0, lba, 1, pa);                  /* write A (invalidates) */
    ata_read_drive(0, lba, 1, rd); int okA   = (memcmp(rd, pa, SECTOR_SIZE) == 0);   /* miss -> fresh A */
    ata_read_drive(0, lba, 1, rd); int okHit = (memcmp(rd, pa, SECTOR_SIZE) == 0);   /* hit  -> A */
    uint64_t h1, m1; bcache_counts(&h1, &m1);
    ata_write_drive(0, lba, 1, pb);                  /* write B: must invalidate the cached A */
    ata_read_drive(0, lba, 1, rd); int okInv = (memcmp(rd, pb, SECTOR_SIZE) == 0);   /* NOT stale A */
    ata_write_drive(0, lba, 1, save);                /* restore the original bytes */

    if (okA && okHit && okInv && h1 > h0)
        kprintf("[ ok ] ATA read cache: fill+hit+write-invalidate coherent (%u hits, %u misses).\n\n",
                (unsigned)h1, (unsigned)m1);
    else
        kprintf("[ata-cache] FAIL: freshA=%d hit=%d invalidate=%d hits+%u\n\n",
                okA, okHit, okInv, (unsigned)(h1 - h0));
}

/* --- the original primary-master API, unchanged for every existing caller --- */

int ata_read(uint32_t lba, uint8_t count, void *buf) {
    /* count==0 meant "256 sectors" in the old LBA28 sense; preserve that. */
    return ata_read_drive(0, lba, count ? count : 256, buf);
}

int ata_write(uint32_t lba, uint8_t count, const void *buf) {
    return ata_write_drive(0, lba, count ? count : 256, buf);
}

/* ===========================================================================
 * Bus-master IDE DMA (PIIX3 "BMIDE") — an ADDITIVE capability alongside the PIO
 * path above. The PIO ata_read()/ata_write() stay the DEFAULT that fat32/vfs/
 * boot use; this DMA path is separate and is proven byte-identical to PIO by
 * ata_dma_selftest(), so a subtle DMA bug can never break the boot disk.
 *
 * The legacy IDE controller (PIIX3, PCI 0x8086:0x7010) can move sectors by DMA
 * instead of the CPU-driven PIO loop: we hand it, in RAM, a Physical Region
 * Descriptor table (PRDT) naming the buffer to fill, issue a READ DMA command to
 * the drive exactly as PIO does the addressing, then set the bus master running
 * and poll its status to completion. No IRQ is used (we poll, like ahci.c).
 *
 * BMIDE register file (16 bytes at BAR4): the PRIMARY channel at +0, the
 * SECONDARY at +8. Per channel:
 *   +0 Command  bit0 = start/stop the bus master; bit3 = direction
 *               (1 = device->memory, i.e. a disk READ).
 *   +2 Status   bit0 = active; bit1 = error; bit2 = IRQ. Write 1 to bits 1/2
 *               to clear them.
 *   +4 PRDT ptr u32 physical address of the PRD table (must be 4-byte aligned
 *               and must not cross a 64 KiB boundary).
 *
 * DMA, like the other drivers, goes through a page-aligned BOUNCE buffer from
 * pmm_alloc_frame() (identity-mapped low RAM: phys == virt). That removes any
 * alignment requirement on the caller's buffer AND bounds every transfer to the
 * fixed bounce size, so a single PRD always describes it. We cap a transfer at
 * the bounce size (see ATA_DMA_BOUNCE_SECTORS below). The PRD table itself lives
 * in its own pmm frame (4 KiB, far inside one 64 KiB window — never crosses it).
 * ========================================================================== */

/* PIIX3 IDE controller PCI id; BAR4 is the BMIDE I/O-port base. */
#define PIIX3_IDE_VENDOR 0x8086
#define PIIX3_IDE_DEVICE 0x7010

/* Per-channel BMIDE register offsets from the channel base. */
#define BMIDE_CMD    0       /* command  (bit0 start/stop, bit3 direction) */
#define BMIDE_STATUS 2       /* status   (bit0 active, bit1 err, bit2 IRQ) */
#define BMIDE_PRDT   4       /* PRDT physical pointer (u32) */

#define BM_CMD_START 0x01    /* bit0: start the bus master engine */
#define BM_CMD_READ  0x08    /* bit3: direction = device->memory (disk read) */

#define BM_ST_ACTIVE 0x01    /* bit0: transfer in progress */
#define BM_ST_ERR    0x02    /* bit1: DMA error (write 1 to clear) */
#define BM_ST_IRQ    0x04    /* bit2: device raised its interrupt (write 1 to clear) */

/* LBA48 read/write-DMA opcodes (we only need READ DMA for the proven path;
 * WRITE DMA is the stretch goal). The LBA28 variants are 0xC8/0xCA. */
#define CMD_READ_DMA       0xC8   /* LBA28 READ DMA  */
#define CMD_READ_DMA_EXT   0x25   /* LBA48 READ DMA EXT */
#define CMD_WRITE_DMA      0xCA   /* LBA28 WRITE DMA */
#define CMD_WRITE_DMA_EXT  0x35   /* LBA48 WRITE DMA EXT */

/* One 8-byte PRD entry: a physical region + byte count (0 means 64 KiB) + flags
 * (bit15 of the flags word = EOT, end of table). */
struct ata_prd {
    uint32_t base;     /* physical base of the region */
    uint16_t count;    /* byte count (0 == 64 KiB) */
    uint16_t flags;    /* bit15 = EOT */
} __attribute__((packed));

#define PRD_EOT 0x8000

/* Bounce-buffer cap. One 4 KiB frame = 8 sectors; we use a single page-aligned
 * frame so a transfer is at most 8 KiB... but a 4 KiB frame is exactly 4 KiB, so
 * the cap is 8 sectors. We keep it deliberately small (well under the 64 KiB a
 * single PRD allows) — the selftest only reads a handful of sectors, and a small
 * fixed bound is the safe choice for a capability that must never misbehave. */
/* ATA_DMA_BOUNCE_SECTORS is defined up at the read path, which needs it to
 * decide whether a request fits the bounce buffer (M2091). */

/* BMIDE state, discovered once on first use. */
static struct {
    int      probed;       /* have we looked for the controller yet? */
    int      present;      /* 1 if the PIIX3 BMIDE BAR4 was found + set up */
    uint16_t bmide_base;   /* BAR4 I/O base (low flag bit masked off) */

    struct ata_prd *prdt;  /* PRD table (its own pmm frame) */
    uint64_t prdt_phys;    /* physical address of the PRD table */
    /* The bounce buffer is ATA_DMA_FRAMES separate frames, described by one PRD
     * entry each -- scatter-gather is what a PRD list is FOR, so the buffer
     * need not be contiguous and the allocator is never asked for a run it
     * cannot give. (M2101) */
    uint64_t bounce_phys_n[ATA_DMA_FRAMES];
    int      nbounce;

    uint8_t *bounce;       /* page-aligned DMA bounce buffer (pmm frame) */
    uint64_t bounce_phys;  /* physical address of the bounce buffer */
} g_bm;

/* Channel base for a drive: primary drives (0,1) at BAR4+0, secondary (2,3) at
 * BAR4+8. */
static uint16_t bmide_channel(int drive) {
    return (uint16_t)(g_bm.bmide_base + ((drive >= 2) ? 8 : 0));
}

/* Locate + set up the PIIX3 bus-master IDE controller. Idempotent: probes PCI
 * once, allocates the PRD table + bounce frame, enables PCI bus mastering.
 * Returns 1 if BMIDE is available, 0 if the controller/BAR is absent or setup
 * failed (in which case the DMA path is a clean no-op). */
static int ata_dma_setup(void) {
    if (g_bm.probed)
        return g_bm.present;
    g_bm.probed = 1;
    g_bm.present = 0;

    pci_device_t dev = pci_find(PIIX3_IDE_VENDOR, PIIX3_IDE_DEVICE);
    if (!dev.valid)
        return 0;                       /* no PIIX3 IDE controller present */

    uint32_t bar4 = pci_bar(&dev, 4);   /* pci_bar already masks the I/O flag bit */
    if (bar4 == 0)
        return 0;                       /* BMIDE BAR not assigned */

    /* Bus mastering must be enabled for the controller to drive DMA. (This also
     * sets memory-space enable, which is harmless for an I/O-mapped BMIDE.) */
    pci_enable_bus_master(&dev);

    /* The PRD table + bounce buffer come from the PMM (identity-mapped low RAM:
     * phys == virt). A 4 KiB frame is page-aligned (the PRD table is far inside
     * one 64 KiB window, so it never crosses one) and is the bounce buffer. */
    /* BOTH FRAMES MUST LIVE BELOW 4 GiB (M2091).
     *
     * The PRD's `base` field is 32 bits -- that is the hardware's format, not
     * a choice -- and it was filled with `(uint32_t)g_bm.bounce_phys` from a
     * 64-bit frame. At -m 2G every frame is under 4 GiB and the cast is
     * harmless, which is why this has never fired. At -m 8G, which is what
     * Firefox needs and what every recent measurement here uses, the allocator
     * will hand out a frame above 4 GiB and the cast silently drops the high
     * bits -- so the controller DMAs a disk sector into SOMEBODY ELSE'S
     * PHYSICAL PAGE. Undetectable corruption, in the one subsystem whose whole
     * job is to be byte-exact.
     *
     * DMA setup is once per boot, so the honest fix is the simple one: keep
     * asking until two low frames turn up, hand the high ones back, and if the
     * allocator has nothing low then say so and leave DMA off rather than
     * corrupt memory. A bounded number of attempts, because a machine whose
     * low memory is entirely used is a machine where DMA simply is not
     * available today. */
    /* ONE FRAME OF BOUNCE BUFFER CAPPED EVERY TRANSFER AT 8 SECTORS (M2101).
     *
     * Measured under KVM on pve-ultra -- which is the measurement that matters,
     * because it removes emulation from the question entirely: Firefox's first
     * paint reads 1607420 sectors (803 MB) in 206704 commands. That is 7.8
     * sectors each, and it is 7.8 because the bounce buffer is a single 4 KiB
     * frame and nothing can ask for more than fits in it.
     *
     * A PRD table is a SCATTER-GATHER list -- that is its entire purpose -- so
     * the buffer does not have to be one contiguous region. ATA_DMA_FRAMES
     * separate frames, one PRD entry each, gives a 64 KiB transfer out of
     * frames the allocator can actually produce. 206704 commands becomes
     * roughly 13000.
     *
     * All of them below 4 GiB, because the PRD's `base` field is 32 bits --
     * that is the hardware's format, not a choice. A frame above 4 GiB
     * truncates and the controller DMAs a disk sector into somebody else's
     * physical page, which is undetectable corruption in the one subsystem
     * whose whole job is to be byte-exact. At -m 2G every frame is low and the
     * cast was harmless; at the 8 GiB Firefox needs it is not. */
    uint64_t prdt_f = 0;
    {
        uint64_t held[64]; int nheld = 0;
        int got = 0;
        for (int i = 0; i < 256 && (!prdt_f || got < ATA_DMA_FRAMES); i++) {
            uint64_t f = pmm_alloc_frame();
            if (!f) break;
            if (f + PAGE_SIZE > 0x100000000ull) {        /* above 4 GiB: unusable for a 32-bit PRD */
                if (nheld < 64) held[nheld++] = f; else pmm_free_frame(f);
                continue;
            }
            if (!prdt_f) prdt_f = f;
            else g_bm.bounce_phys_n[got++] = f;
        }
        g_bm.nbounce = got;
        for (int i = 0; i < nheld; i++) pmm_free_frame(held[i]);
    }
    if (!prdt_f || g_bm.nbounce < 1) {
        if (prdt_f) pmm_free_frame(prdt_f);
        for (int i = 0; i < g_bm.nbounce; i++) pmm_free_frame(g_bm.bounce_phys_n[i]);
        g_bm.nbounce = 0;
        kprintf("[ata] DMA disabled: no physical frame below 4 GiB for the PRD table and bounce "
                "buffer, and the PRD's base address field is 32 bits wide. PIO only.\n");
        return 0;
    }
    uint64_t bnc_f = g_bm.bounce_phys_n[0];
    for (int i = 0; i < g_bm.nbounce; i++) memset(hhdm(g_bm.bounce_phys_n[i]), 0, PAGE_SIZE);
    if (g_bm.nbounce < ATA_DMA_FRAMES)
        kprintf("[ata] DMA bounce buffer is %d of %d frames (low memory is tight): transfers "
                "cap at %d sectors\n", g_bm.nbounce, ATA_DMA_FRAMES,
                g_bm.nbounce * (int)(PAGE_SIZE / SECTOR_SIZE));
    memset(hhdm(prdt_f), 0, PAGE_SIZE);
    memset(hhdm(bnc_f),  0, PAGE_SIZE);

    g_bm.prdt       = (struct ata_prd *)hhdm(prdt_f);
    g_bm.prdt_phys  = prdt_f;
    g_bm.bounce     = (uint8_t *)hhdm(bnc_f);
    g_bm.bounce_phys = bnc_f;
    g_bm.bmide_base = (uint16_t)bar4;
    g_bm.present    = 1;
    return 1;
}

/* The shared core of DMA read and write. Bounces one transfer (<= the bounce
 * cap) through the page-aligned bounce frame and runs a READ/WRITE DMA on the
 * given drive's channel. `write` copies the caller's data into the bounce first
 * and uses WRITE DMA; a read copies the bounce back into `buf` after completion.
 * Returns 0 on success, -1 on bad-arg / absent controller / device error /
 * timeout. The PIO addressing sequence (drive-select + LBA28) is reused so the
 * only thing that differs from PIO is the command + the data transfer. */
static int ata_dma_xfer_impl(int drive, uint32_t lba, uint32_t count, void *buf, int write) {
    /* Validate: drive in range + actually present, count in (0, bounce cap],
     * buffer non-NULL, controller available. */
    if (!drive_ok(drive) || count == 0 || !buf)
        return -1;
    if (count > ATA_DMA_BOUNCE_SECTORS)
        return -1;
    if (!ata_dma_setup())
        return -1;                      /* no BMIDE: clean no-op capability */
    const struct ata_drive_info *info = ata_drive(drive);
    if (!info || !info->present)
        return -1;                      /* no disk in this slot */
    /* Refuse access past the end of the disk (the IDENTIFYd capacity). */
    if ((uint64_t)lba + count > info->sectors)
        return -1;
    /* LBA28 addressing only on this path (the selftest reads low sectors); a
     * larger LBA would need the EXT command + the high LBA bytes. */
    if ((uint64_t)lba + count > 0x0FFFFFFFull)
        return -1;

    uint16_t io   = ATA_DRIVES[drive].io;
    uint8_t  slave = ATA_DRIVES[drive].slave;
    uint16_t ch   = bmide_channel(drive);
    uint32_t bytes = count * SECTOR_SIZE;

    /* Scatter the write across the bounce frames, and gather the read back out
     * of them afterwards. Both loops walk the SAME frame order the PRD list
     * below is built in, which is what makes the transfer byte-exact. (M2101) */
    if (write) {
        uint32_t left = bytes, off = 0;
        for (int i = 0; i < g_bm.nbounce && left; i++) {
            uint32_t n = left > PAGE_SIZE ? PAGE_SIZE : left;
            memcpy(hhdm(g_bm.bounce_phys_n[i]), (const uint8_t *)buf + off, n);
            off += n; left -= n;
        }
    }

    /* Build the single PRD: the whole transfer in one region, EOT set.
     * The cast is safe because ata_dma_setup refuses any frame at or above
     * 4 GiB -- but assert it here too, because this is the line where a wrong
     * address becomes a write to a stranger's page and there is no later
     * symptom that would point back at it. */
    {   uint32_t left = bytes;
        int n = 0;
        for (int i = 0; i < g_bm.nbounce && left; i++) {
            uint64_t ph = g_bm.bounce_phys_n[i];
            if (ph + PAGE_SIZE > 0x100000000ull) return -1;   /* 32-bit PRD base: never truncate */
            uint32_t c = left > PAGE_SIZE ? PAGE_SIZE : left;
            g_bm.prdt[n].base  = (uint32_t)ph;
            g_bm.prdt[n].count = (uint16_t)(c & 0xFFFF);      /* 4096 fits; 0 would mean 64 KiB */
            g_bm.prdt[n].flags = 0;
            left -= c; n++;
        }
        if (left || !n) return -1;                            /* asked for more than the buffer holds */
        g_bm.prdt[n - 1].flags = PRD_EOT;                     /* only the LAST entry ends the list */
    }

    /* Make sure the bus master is stopped before we reprogram it, then point it
     * at our PRD table and clear any latched error/IRQ status (write-1-to-clear). */
    outb(ch + BMIDE_CMD, 0);
    outl(ch + BMIDE_PRDT, (uint32_t)g_bm.prdt_phys);
    outb(ch + BMIDE_STATUS, BM_ST_ERR | BM_ST_IRQ);

    /* Set the transfer direction. For a READ the bus master writes memory
     * (device->memory), so the direction bit is SET; for a WRITE it is clear.
     * Set direction but leave the start bit (bit0) clear for now. */
    outb(ch + BMIDE_CMD, write ? 0 : BM_CMD_READ);

    /* Issue the ATA command with the standard PIO addressing sequence (this is
     * the only place the two paths share — drive-select + LBA28 + sector count). */
    if (wait_busy_clear(io) < 0)
        return -1;
    select_lba(io, slave, lba, (uint8_t)(count & 0xFF));   /* count<=8, never wraps to 0 */
    outb(io + REG_COMMAND, write ? CMD_WRITE_DMA : CMD_READ_DMA);

    /* Start the bus master: keep the direction bit, set bit0. The controller now
     * DMAs as the drive streams data. */
    outb(ch + BMIDE_CMD, (uint8_t)((write ? 0 : BM_CMD_READ) | BM_CMD_START));

    /* Poll the BMIDE status to completion with a finite timeout. The transfer is
     * done when the controller drops the active bit (and typically raises IRQ).
     * We watch for the error bit and bail on it; we also bound the spin (by
     * real wall-clock time, not a raw iteration count -- see wait_busy_clear's
     * comment above) so an absent/stuck device can never hang the kernel. */
    int err = 0;
    int done = 0;
    uint64_t dma_deadline = timer_ms() + ATA_TIMEOUT_MS;
    for (uint32_t i = 0; i < ATA_SPIN_HARDCAP; i++) {
        uint8_t st = inb(ch + BMIDE_STATUS);
        if (st & BM_ST_ERR) { err = 1; break; }
        /* Active clears when the data transfer has finished. The IRQ bit being
         * set with active clear is the unambiguous "complete" signal; active
         * clear alone is also complete (some controllers don't latch IRQ here). */
        if (!(st & BM_ST_ACTIVE)) { done = 1; break; }
        if (timer_ms() >= dma_deadline) break;               /* done/err both still 0 -> the !done check below fails it */
    }

    /* Stop the bus master regardless of outcome (clear the start bit). */
    outb(ch + BMIDE_CMD, write ? 0 : BM_CMD_READ);

    /* Re-read + clear the BMIDE status (ack IRQ / latch error). */
    uint8_t fin = inb(ch + BMIDE_STATUS);
    outb(ch + BMIDE_STATUS, BM_ST_ERR | BM_ST_IRQ);
    if (fin & BM_ST_ERR)
        err = 1;

    /* Let the drive settle and check its task-file status/error register. */
    if (wait_busy_clear(io) < 0)
        return -1;
    uint8_t ata_st = inb(io + REG_STATUS);
    if ((ata_st & ST_ERR) || (ata_st & ST_BSY))
        return -1;

    if (err || !done)
        return -1;                      /* DMA error or timed out: clean failure */

    if (!write)
        {   uint32_t left = bytes, off = 0;
            for (int i = 0; i < g_bm.nbounce && left; i++) {
                uint32_t n = left > PAGE_SIZE ? PAGE_SIZE : left;
                memcpy((uint8_t *)buf + off, hhdm(g_bm.bounce_phys_n[i]), n);
                off += n; left -= n;
            }
        }
    return 0;
}

/* Same shared-hardware exclusion as ata_read_drive/ata_write_drive above --
 * DMA still addresses the drive through the same task-file registers PIO
 * uses, so a PIO transfer and a DMA transfer to any drive on the same
 * controller must not interleave either. */
static int ata_dma_xfer(int drive, uint32_t lba, uint32_t count, void *buf, int write) {
    ata_lock_take();
    if (write) bcache_inval_range(BCACHE_OWNER_ATA(drive), lba, count);   /* DMA write bypasses ata_write_drive — invalidate too (M1855/M1869) */
    int r = ata_dma_xfer_impl(drive, lba, count, buf, write);
    ata_lock_give();
    return r;
}

int ata_read_dma(int drive, uint32_t lba, uint32_t count, void *buf) {
    return ata_dma_xfer(drive, lba, count, buf, 0);
}

int ata_write_dma(int drive, uint32_t lba, uint32_t count, const void *buf) {
    return ata_dma_xfer(drive, lba, count, (void *)buf, 1);
}

int ata_dma_available(void) {
    return ata_dma_setup();
}

uint32_t ata_dma_max_sectors(void) {
    /* WHAT THE BUFFER REALLY IS, NOT WHAT IT WAS ASKED TO BE (M2101). The
     * bounce buffer is ATA_DMA_FRAMES frames if the allocator could produce
     * that many below 4 GiB, and fewer if it could not. blockdev_read sizes
     * its batches from this, and a batch larger than the buffer falls back to
     * PIO for the whole request -- so reporting the constant instead of the
     * actual count would silently turn DMA off on a machine with tight low
     * memory. Before setup has run there is nothing yet, so report the
     * intended size: the caller will find out when it tries. */
    if (g_bm.probed && g_bm.present)
        return (uint32_t)g_bm.nbounce * (PAGE_SIZE / SECTOR_SIZE);
    return ATA_DMA_BOUNCE_SECTORS;
}

/* --- IDENTIFY-based enumeration -------------------------------------------- */

/*
 * Probe one drive with IDENTIFY DEVICE. Returns 1 + fills *out if a usable ATA
 * disk answered, 0 if the slot is empty / not an ATA disk.
 *
 * Robustness is the whole point here: an absent drive on a "floating" bus must
 * NOT hang the kernel. We follow the standard sequence with finite spins —
 * select the drive, issue IDENTIFY, and if the status register reads 0 (no
 * device on this bus at all) bail immediately; otherwise wait for BSY to clear
 * within a bounded loop and require DRQ. A device that signals it is ATAPI/SATA
 * (the LBA1/LBA2 signature bytes become non-zero after IDENTIFY) is treated as
 * "no PIO ATA disk here" and skipped — we are an LBA28/48 PIO driver only.
 */
static int identify_drive(int drive, struct ata_drive_info *out) {
    uint16_t io = ATA_DRIVES[drive].io;
    uint8_t slave = ATA_DRIVES[drive].slave;

    /* Select the drive and give it a moment (400ns ~= 4 status reads). */
    outb(io + REG_DRIVE, 0xA0 | (slave ? 0x10 : 0));
    for (int i = 0; i < 4; i++) (void)inb(io + REG_STATUS);

    /* Status 0xFF (or 0x00) => nothing on this bus: a floating bus reads all-ones
     * (open bus) or all-zeros. Bail before issuing any command so we never spin
     * waiting on a device that isn't there. */
    uint8_t st = inb(io + REG_STATUS);
    if (st == 0xFF || st == 0x00)
        return 0;

    /* Zero the addressing registers, then IDENTIFY. */
    outb(io + REG_SECCOUNT, 0);
    outb(io + REG_LBA0, 0);
    outb(io + REG_LBA1, 0);
    outb(io + REG_LBA2, 0);
    outb(io + REG_COMMAND, CMD_IDENTIFY);

    /* IDENTIFY of an absent device leaves status 0 -> no device. */
    st = inb(io + REG_STATUS);
    if (st == 0x00)
        return 0;

    /* Wait (bounded) for BSY to clear. */
    int spun = 0;
    while (inb(io + REG_STATUS) & ST_BSY) {
        if (++spun > 100000)
            return 0;                  /* stuck busy: treat as absent, don't hang */
    }

    /* Non-zero LBA-mid/high after IDENTIFY = an ATAPI/SATA signature, not a plain
     * ATA disk our PIO read path can serve. Skip it. */
    uint8_t lo = inb(io + REG_LBA1);
    uint8_t hi = inb(io + REG_LBA2);
    if (lo != 0 || hi != 0)
        return 0;

    /* Wait (bounded) for DRQ or ERR. */
    spun = 0;
    for (;;) {
        st = inb(io + REG_STATUS);
        if (st & ST_ERR) return 0;
        if (st & ST_DRQ) break;
        if (++spun > 100000) return 0;
    }

    /* Read the 256-word IDENTIFY block. */
    uint16_t id[256];
    read_data(io, id, 256);

    /* Sector count: prefer the LBA48 64-bit field (words 100..103) if the drive
     * supports 48-bit addressing (word 83 bit 10), else the LBA28 32-bit count
     * (words 60..61). */
    uint64_t sectors = 0;
    if (id[83] & (1u << 10)) {
        sectors = (uint64_t)id[100] | ((uint64_t)id[101] << 16) |
                  ((uint64_t)id[102] << 32) | ((uint64_t)id[103] << 48);
    }
    if (sectors == 0)
        sectors = (uint32_t)id[60] | ((uint32_t)id[61] << 16);   /* LBA28 */
    if (sectors == 0)
        return 0;                       /* a present device that reports no capacity: ignore */

    out->present = 1;
    out->drive = drive;
    out->sectors = sectors;
    out->lba48 = (id[83] & (1u << 10)) ? 1 : 0;

    /* Pull the model string (words 27..46, byte-swapped ATA convention) for the
     * log. Trim trailing spaces. */
    int n = 0;
    for (int w = 27; w <= 46 && n < (int)sizeof(out->model) - 1; w++) {
        out->model[n++] = (char)(id[w] >> 8);
        out->model[n++] = (char)(id[w] & 0xFF);
    }
    while (n > 0 && (out->model[n - 1] == ' ' || out->model[n - 1] == '\0')) n--;
    out->model[n] = '\0';
    return 1;
}

int ata_identify_all(void) {
    int found = 0;
    for (int d = 0; d < ATA_MAX_DRIVES; d++) {
        g_drives[d].present = 0;
        g_drives[d].drive = d;
        g_drives[d].sectors = 0;
        g_drives[d].lba48 = 0;
        g_drives[d].model[0] = '\0';
        if (identify_drive(d, &g_drives[d]))
            found++;
    }
    g_probed = 1;
    return found;
}

const struct ata_drive_info *ata_drive(int drive) {
    if (!drive_ok(drive)) return 0;
    if (!g_probed) ata_identify_all();
    return &g_drives[drive];
}

uint64_t ata_drive_sectors(int drive) {
    const struct ata_drive_info *info = ata_drive(drive);
    return (info && info->present) ? info->sectors : 0;
}

/* ---- boot-time verification: DMA read returns identical bytes to PIO ------ */

/* Two static sector buffers (kernel BSS) to land the DMA read and the PIO read
 * for the byte-for-byte comparison. The DMA path uses its own internal bounce
 * frame, so these need no special alignment. */
static uint8_t dma_buf[SECTOR_SIZE];
static uint8_t pio_buf[SECTOR_SIZE];
static uint8_t dma_saved[SECTOR_SIZE];
static uint8_t dma_scratch[SECTOR_SIZE];
static uint8_t dma_readback[SECTOR_SIZE];

/*
 * The proof that the bus-master DMA path returns the SAME data as the trusted
 * PIO path: for a few low sectors of the boot disk (drive 0, which sits on the
 * PIIX3 IDE controller and is therefore bus-master capable), DMA-read the sector
 * and PIO-read the same sector, then memcmp the two. Logs "IDE DMA: sector N
 * DMA==PIO OK" on a match (or a MISMATCH line). Then a DMA write round-trip on a
 * scratch sector near the end of the disk: save it (PIO), DMA-write a marker,
 * DMA-read it back + verify, PIO-read it back + verify, and restore the original
 * (PIO) so the test image is untouched.
 *
 * A clean no-op (logs "DMA unavailable") if no PIIX3 BMIDE controller is present
 * — boot is entirely unaffected (the boot path uses PIO regardless).
 */
void ata_dma_selftest(void) {
    if (!ata_dma_available()) {
        kprintf("[ata-dma] IDE DMA unavailable (no PIIX3 bus-master IDE "
                "controller; PIO boot path intact).\n\n");
        return;
    }

    const struct ata_drive_info *info = ata_drive(0);
    if (!info || !info->present) {
        kprintf("[ata-dma] IDE DMA unavailable (drive 0 absent; PIO boot path "
                "intact).\n\n");
        return;
    }

    kprintf("[ ok ] IDE bus-master DMA up: PIIX3 BMIDE found "
            "(BAR4 I/O base 0x%x, %u-sector bounce) -- READS NOW USE IT (M2091, 7.81x).\n",
            (unsigned)g_bm.bmide_base, (unsigned)ata_dma_max_sectors());

    /* Per-sector DMA==PIO byte comparison on the first few sectors.
     *
     * AGAINST ata_read_drive_pio, NOT ata_read_drive (M2091). This used to
     * compare against ata_read_drive, and routing reads through DMA turned it
     * into DMA-versus-DMA -- a test that agrees with itself and would print
     * "DMA==PIO OK" over a broken transfer. The second route has to be a
     * genuinely different one. */
    int compared = 0, matched = 0;
    uint32_t nsec = 3;
    if (info->sectors < nsec) nsec = (uint32_t)info->sectors;
    for (uint32_t lba = 0; lba < nsec; lba++) {
        int dma_ok = (ata_read_dma(0, lba, 1, dma_buf) == 0);
        int pio_ok = (ata_read_drive_pio(0, lba, 1, pio_buf) == 0);
        if (!dma_ok || !pio_ok) {
            kprintf("[ata-dma] sector %u: %s read FAILED\n", lba,
                    !dma_ok ? "DMA" : "PIO");
            continue;
        }
        compared++;
        if (memcmp(dma_buf, pio_buf, SECTOR_SIZE) == 0) {
            matched++;
            /* Show a checksum + the first 16 bytes so the read can also be eyeballed
             * against known on-disk content (mirrors the other drivers' logs). */
            uint32_t sum = 0;
            for (int i = 0; i < SECTOR_SIZE; i++) sum += dma_buf[i];
            kprintf("[ata-dma] IDE DMA: sector %u DMA==PIO OK (sum=%08x first16=",
                    lba, sum);
            for (int i = 0; i < 16; i++) kprintf("%02x ", dma_buf[i]);
            kprintf(")\n");
        } else {
            kprintf("[ata-dma] IDE DMA: sector %u DMA!=PIO MISMATCH\n", lba);
        }
    }

    /* AND AT THE SIZE THE READ PATH ACTUALLY USES (M2091).
     *
     * The per-sector comparison above is 1 sector at 3 low LBAs. The read path
     * now issues up to EIGHT sectors per transfer, on both drives, at
     * arbitrary LBAs -- and a bounce buffer, a PRD byte count and a 32-bit
     * base address are all things that can be right for one sector and wrong
     * for eight. So compare what is really being done: 8 sectors at a time,
     * across both drives, at LBAs spread over the disk rather than clustered
     * at zero where the bytes are mostly identical anyway.
     *
     * This is the assertion that fires if the PRD count is truncated, if the
     * bounce buffer is copied short, or if a frame above 4 GiB slips through
     * the 32-bit base. Nothing else in the tree would notice any of those. */
    /* AT EVERY TRANSFER SIZE THE READ PATH CAN ASK FOR, NOT JUST ONE (M2101).
     *
     * This tested EIGHT sectors -- and eight sectors is exactly one 4 KiB
     * bounce frame, so it exercised exactly ONE PRD entry. M2101 made the
     * bounce buffer sixteen frames described by sixteen PRD entries, and the
     * second through sixteenth entries, the EOT placement, the scatter of a
     * write and the gather of a read were all completely untested by a check
     * that reported "BYTE-IDENTICAL to PIO" and passed.
     *
     * A test that cannot fail is worse than no test. Every size the read path
     * can issue now: 1 sector, 8 (one frame), 9 (the first size that crosses a
     * PRD boundary), 16, 64, and the full ceiling. And at four LBAs spread
     * over each disk rather than clustered at zero, where the bytes are mostly
     * identical anyway and a misplaced frame would not show. */
    {
        static uint8_t dbig[128 * SECTOR_SIZE], pbig[128 * SECTOR_SIZE];
        uint32_t sizes[6] = { 1, 8, 9, 16, 64, ata_dma_max_sectors() };
        int total = 0, okall = 0;
        for (int drv = 0; drv < 2; drv++) {
            const struct ata_drive_info *di = ata_drive(drv);
            if (!di || !di->present || di->sectors < 8192) continue;
            uint32_t spots[4] = { 64, (uint32_t)(di->sectors / 4),
                                  (uint32_t)(di->sectors / 2),
                                  (uint32_t)(di->sectors - 256) };
            for (int z = 0; z < 6; z++) {
                uint32_t n = sizes[z];
                if (!n || n > 128 || n > ata_dma_max_sectors()) continue;
                for (int k = 0; k < 4; k++) {
                    if ((uint64_t)spots[k] + n > di->sectors) continue;
                    /* Poison the destination so a SHORT transfer is caught as
                     * well as a wrong one: bytes the DMA never wrote would
                     * otherwise compare equal to whatever was there before. */
                    for (uint32_t b = 0; b < n * SECTOR_SIZE; b++) dbig[b] = 0xA5;
                    if (ata_read_dma(drv, spots[k], n, dbig) != 0) {
                        kprintf("[ata-dma] FAIL: %u-sector DMA read at lba %u REFUSED\n", n, spots[k]);
                        total++; continue;
                    }
                    if (ata_read_drive_pio(drv, spots[k], n, pbig) != 0) continue;
                    total++;
                    if (memcmp(dbig, pbig, n * SECTOR_SIZE) == 0) okall++;
                    else {
                        unsigned long first = 0;
                        while (first < n * SECTOR_SIZE && dbig[first] == pbig[first]) first++;
                        kprintf("[ata-dma] MISMATCH: drive %d lba %u, %u sectors, first differing "
                                "byte at offset %lu (that is PRD entry %lu of %u)\n",
                                drv, spots[k], n, first, first / PAGE_SIZE,
                                (n * SECTOR_SIZE + PAGE_SIZE - 1) / PAGE_SIZE);
                    }
                }
            }
        }
        if (total && okall == total)
            kprintf("[ ok ] IDE DMA: %d reads at 1/8/9/16/64/%u sectors across both drives are "
                    "BYTE-IDENTICAL to PIO -- every PRD entry, not just the first\n",
                    total, ata_dma_max_sectors());
        else if (total)
            kprintf("[ata-dma] FAIL: only %d of %d multi-size reads matched PIO\n", okall, total);
        else
            kprintf("[ata-dma] no drive large enough for the multi-size comparison\n");
    }

    /* DMA write round-trip on a scratch sector near the end of the disk (so the
     * boot FAT32 region up front is never touched). Save it via PIO, DMA-write a
     * marker, read it back (DMA and PIO) + verify, restore via PIO. Done only if
     * the disk has room. A failure here is reported but never fatal to boot. */
    if (info->sectors >= 8) {
        uint32_t test_lba = (uint32_t)(info->sectors - 1);
        if (ata_read_drive(0, test_lba, 1, dma_saved) == 0) {
            for (int i = 0; i < SECTOR_SIZE; i++)
                dma_scratch[i] = (uint8_t)(0xA5 ^ (i & 0xFF));
            int ok = (ata_write_dma(0, test_lba, 1, dma_scratch) == 0);
            memset(dma_readback, 0, sizeof(dma_readback));
            ok = ok && (ata_read_dma(0, test_lba, 1, dma_readback) == 0);
            ok = ok && (memcmp(dma_readback, dma_scratch, SECTOR_SIZE) == 0);
            /* Cross-check the DMA write with a PIO read of the same sector. */
            memset(pio_buf, 0, sizeof(pio_buf));
            ok = ok && (ata_read_drive(0, test_lba, 1, pio_buf) == 0);
            ok = ok && (memcmp(pio_buf, dma_scratch, SECTOR_SIZE) == 0);
            ata_write_drive(0, test_lba, 1, dma_saved);   /* restore (PIO) */
            kprintf("[ata-dma] IDE DMA write round-trip on sector %u: %s\n",
                    test_lba,
                    ok ? "DMA==PIO OK (wrote+read back+restored)" : "MISMATCH");
        }
    }

    if (compared > 0 && compared == matched)
        kprintf("[ ok ] IDE DMA self-test complete: %d/%d sectors DMA==PIO "
                "(DMA path proven identical to PIO).\n\n", matched, compared);
    else
        kprintf("[ata-dma] IDE DMA self-test: %d/%d sectors matched "
                "(see above).\n\n", matched, compared);
}

/* LBA48 self-test (M1721): if a NON-boot ATA disk larger than the LBA28 ceiling
 * (2^28 sectors = 128 GiB) is attached, write a known pattern to a sector PAST
 * that boundary, read it back, and confirm the round-trip — proving the primary
 * ATA path can now address beyond 128 GiB. A clean no-op if no such disk is
 * present (the default config), so the LBA28 boot path stays untouched. Never
 * touches drive 0 (the boot disk). */
void ata_lba48_selftest(void) {
    if (!g_probed) ata_identify_all();

    int big = -1;
    for (int d = 1; d < ATA_MAX_DRIVES; d++) {
        const struct ata_drive_info *info = ata_drive(d);
        if (info && info->present && info->sectors > (1ull << 28)) { big = d; break; }
    }
    if (big < 0) {
        kprintf("[ata-lba48] no >128 GiB ATA disk attached "
                "(LBA48 path idle; LBA28 boot path intact).\n\n");
        return;
    }

    const struct ata_drive_info *info = ata_drive(big);
    kprintf("[ ok ] ATA LBA48: drive %d is %lu sectors (> the 2^28 LBA28 limit); "
            "testing a high-LBA round-trip.\n", big, info->sectors);

    uint64_t hi = (1ull << 28) + 100000;             /* ~49 MiB past the 128 GiB boundary -> needs LBA48 */
    if (hi >= info->sectors) hi = info->sectors - 1;
    for (int i = 0; i < SECTOR_SIZE; i++) dma_scratch[i] = (uint8_t)(i * 3 + 0x2D);
    memset(dma_readback, 0, sizeof(dma_readback));
    int ok = (ata_write_drive(big, (uint32_t)hi, 1, dma_scratch) == 0);
    ok = ok && (ata_read_drive(big, (uint32_t)hi, 1, dma_readback) == 0);
    ok = ok && (memcmp(dma_readback, dma_scratch, SECTOR_SIZE) == 0);
    kprintf("[ %s ] ATA LBA48 high-LBA round-trip at sector %lu (past the 128 GiB "
            "boundary): %s\n\n", ok ? "ok" : "!!", hi,
            ok ? "wrote + read back, data matches (LBA48 OK)" : "MISMATCH/FAIL");
}
