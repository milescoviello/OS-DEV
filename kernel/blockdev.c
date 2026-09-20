/*
 * blockdev.c — a generic block-device registry + read-only multi-volume FAT32
 * browsing over EVERY storage driver (see blockdev.h for the why).
 *
 * blockdev_init() registers each present storage device behind one uniform
 * read(ctx,lba,count,buf) vtable; blockdev_enumerate() then reads LBA 0 of each,
 * works out where any FAT32 volumes live (a bare FS at LBA 0, or FAT32 partitions
 * carved out by an MBR/GPT table), and for each one MOUNTS it read-only via the
 * device-agnostic fatvol_list()/fatvol_find() in partition.c and LISTS its root
 * directory. This proves every driver's disk is genuinely browsable.
 *
 * SECURITY — this parses untrusted on-disk MBR/GPT/FAT structures over DMA driver
 * reads, so every field is validated before use:
 *   - Every sector read targets a FIXED 512-byte stack buffer; buffer offsets are
 *     compile-time constants well within 512.
 *   - The MBR/GPT scan only ever COLLECTS candidate start-LBAs; the heavy FAT walk
 *     (fatvol_*) re-validates the whole BPB and is bounded by the cluster count +
 *     a cycle guard, so a corrupt table/FAT can never loop or read unboundedly.
 *   - Candidate start-LBAs are validated against the device capacity where known
 *     and against the 64-bit/addressable range; the GPT entry array is read in
 *     bounded single-sector chunks with the entry count + size capped.
 *   - A device read() returning an error => the volume/device is skipped cleanly.
 *   - The candidate list, the per-volume file listing, and the device registry are
 *     all fixed-size and capped.
 *
 * It is purely READ-ONLY and never touches the boot FAT32 mount (fat32.c/vfs.c).
 */
#include "blockdev.h"
#include "bcache.h"    /* unified kernel-wide block cache (M1869) */
#include "kheap.h"     /* kmalloc/kfree for blockdev_mount_pread's prefix temp (M1196) */
#include "partition.h"
#include "ext2.h"
#include "iso9660.h"
#include "atapi.h"     /* ATAPI CD-ROM registered as a read-only blockdev (M1853) */
#include "ata.h"
#include "ahci.h"
#include "virtio_blk.h"
#include "nvme.h"
#include "usb_storage.h"
#include "ehci.h"      /* USB 2.0 mass storage registered as a blockdev (M1889) */
#include "xhci.h"      /* USB 3.0 mass storage registered as a blockdev (M1889) */
#include "console.h"
#include "string.h"
#include "task.h"      /* task_yield() for the per-device cache lock's backoff */

#define SECSZ 512

/* Little-endian field readers over a byte buffer (on-disk byte order). */
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64(const uint8_t *p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

/* --- the registry ---------------------------------------------------------- */

static blockdev_t g_dev[BLOCKDEV_MAX];
static int        g_ndev;

/* --- per-driver read adapters (each matches blockdev_t.read / blk_read_fn) --- */

/* ATA: the drive index is packed into ctx (drives 0..3 share one read fn). */
static int ata_bd_read(void *ctx, uint64_t lba, uint32_t count, void *buf) {
    int drive = (int)(intptr_t)ctx;
    if (lba > 0xFFFFFFFFull) return -1;            /* ata_read_drive takes a u32 LBA */
    return ata_read_drive(drive, (uint32_t)lba, count, buf);
}
/* AHCI: the SATA-disk index is packed into ctx. */
static int ahci_bd_read(void *ctx, uint64_t lba, uint32_t count, void *buf) {
    return ahci_read((int)(intptr_t)ctx, lba, count, buf);
}
/* virtio-blk: single device, ctx unused. */
static int virtio_bd_read(void *ctx, uint64_t lba, uint32_t count, void *buf) {
    (void)ctx; return virtio_blk_read(lba, count, buf);
}
/* NVMe: namespace 1, ctx unused. */
static int nvme_bd_read(void *ctx, uint64_t lba, uint32_t count, void *buf) {
    (void)ctx; return nvme_read(lba, count, buf);
}
/* USB mass-storage: single device, ctx unused; its read takes a u32 LBA. */
static int usb_bd_read(void *ctx, uint64_t lba, uint32_t count, void *buf) {
    (void)ctx;
    if (lba > 0xFFFFFFFFull) return -1;
    return usb_storage_read((uint32_t)lba, count, buf);
}
/* ATAPI CD-ROM: 2048-byte media exposed as 512-byte sectors (M1853). Read-only
 * (registered with write==NULL). Reads each distinct 2048-byte logical sector at
 * most once per call (iso9660 fetches 4 contiguous 512-sectors per 2 KiB sector). */
static int atapi_bd_read(void *ctx, uint64_t lba, uint32_t count, void *buf) {
    int slot = (int)(intptr_t)ctx;
    uint8_t *out = buf; static uint8_t sec[2048]; uint32_t cached = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t l = lba + i;
        uint32_t asec = (uint32_t)(l >> 2);          /* 512-LBA / 4 -> 2 KiB sector */
        int off = (int)(l & 3) << 9;                 /* (LBA % 4) * 512 */
        if (asec != cached) {
            if (atapi_read10(slot, asec, 1, sec, (int)sizeof sec) < 2048) return -1;
            cached = asec;
        }
        memcpy(out + (uint64_t)i * SECSZ, sec + off, SECSZ);
    }
    return 0;
}
static int usb_bd_write(void *ctx, uint64_t lba, uint32_t count, const void *buf) {
    (void)ctx;
    if (lba > 0xFFFFFFFFull) return -1;
    return usb_storage_write((uint32_t)lba, count, buf);
}
/* USB mass-storage behind EHCI (USB 2.0) and xHCI (USB 3.0) — M1889. Each host
 * controller carries at most one BOT/SCSI disk today, so ctx is unused; both
 * take a u32 LBA like the UHCI path. These are what make a USB disk usable on
 * real hardware, which has no UHCI controller at all. */
static int ehci_bd_read(void *ctx, uint64_t lba, uint32_t count, void *buf) {
    (void)ctx;
    if (lba > 0xFFFFFFFFull) return -1;
    return ehci_storage_read((uint32_t)lba, count, buf);
}
static int ehci_bd_write(void *ctx, uint64_t lba, uint32_t count, const void *buf) {
    (void)ctx;
    if (lba > 0xFFFFFFFFull) return -1;
    return ehci_storage_write((uint32_t)lba, count, buf);
}
static int xhci_bd_read(void *ctx, uint64_t lba, uint32_t count, void *buf) {
    (void)ctx;
    if (lba > 0xFFFFFFFFull) return -1;
    return xhci_storage_read((uint32_t)lba, count, buf);
}
static int xhci_bd_write(void *ctx, uint64_t lba, uint32_t count, const void *buf) {
    (void)ctx;
    if (lba > 0xFFFFFFFFull) return -1;
    return xhci_storage_write((uint32_t)lba, count, buf);
}

/* --- per-driver WRITE adapters (each matches blockdev_t.write) — M1095. The
 * boot FAT32 volume is read by fat32.c directly via ATA, never through this
 * layer, so these writes cannot corrupt it. USB mass-storage's write is static
 * in its driver, so it is registered read-only (write == NULL). --- */
static int ata_bd_write(void *ctx, uint64_t lba, uint32_t count, const void *buf) {
    int drive = (int)(intptr_t)ctx;
    if (lba > 0xFFFFFFFFull) return -1;
    return ata_write_drive(drive, (uint32_t)lba, count, buf);
}
static int ahci_bd_write(void *ctx, uint64_t lba, uint32_t count, const void *buf) {
    return ahci_write((int)(intptr_t)ctx, lba, count, buf);
}
static int virtio_bd_write(void *ctx, uint64_t lba, uint32_t count, const void *buf) {
    (void)ctx; return virtio_blk_write(lba, count, buf);
}
static int nvme_bd_write(void *ctx, uint64_t lba, uint32_t count, const void *buf) {
    (void)ctx; return nvme_write(lba, count, buf);
}

/* Per-device cache serialization (M1885). Like the ATA driver's ata_lock, this
 * is held across the WHOLE read-miss (lookup -> raw_read -> bcache_install) and
 * the whole write (bcache_inval_range -> raw_write), so a concurrent same-LBA
 * write on another core can't slip its invalidation between a read's raw_read
 * and its install and leave a stale cached sector. Per-device (indexed by the
 * registry slot) so different devices still run in parallel; the underlying
 * driver's own lock (e.g. ata_lock) nests inside, always in this order. Yields
 * after a short spin, exactly as ata_lock_take does (same rationale). */
static volatile int blk_lock[BLOCKDEV_MAX];
static inline void blk_lock_take(int i) {
    uint32_t spins = 0;
    while (__atomic_exchange_n(&blk_lock[i], 1, __ATOMIC_ACQUIRE)) {
        if (++spins >= 1000) { spins = 0; task_yield(); }
        else __asm__ volatile("pause");
    }
}
static inline void blk_lock_give(int i) { __atomic_store_n(&blk_lock[i], 0, __ATOMIC_RELEASE); }

unsigned long g_bd_reg_skipped;      /* re-registrations that kept the existing index (M2229) */
unsigned long g_bd_init_calls;       /* how often anything asked for a (re)probe (M2229) */
/* REGISTRATION IS ADDITIVE, AND AN INDEX NEVER MOVES (M2229).
 *
 * It used to be "zero g_ndev and register everything again", which is two
 * separate disasters.
 *
 * THE FIRST, MEASURED: `/proc/partitions` -> gen_partitions ->
 * blockdev_format -> blockdev_init, so ANY program reading that file sets
 * g_ndev to 0 for the duration of a full device probe. Every blockdev_read
 * running on another core during that window fails at the entry guard --
 * silently, because that guard was the one return -1 in the whole path with no
 * reason recorded. The failing 8-core boots show exactly that: 6 to 48
 * SUPERBLOCK read failures at LBA 2, `ata: 0 retr 0 FAIL`, and every one of
 * the seven refusal reasons at zero. Firefox's GIO volume monitor reads
 * /proc/partitions. On ONE core nothing else is mid-read while the probe runs,
 * which is why this was 8-core-only.
 *
 * THE SECOND, latent: `g_mount[].dev` stores an INDEX. Re-registering in a
 * different order silently repoints a mounted filesystem at another disk. The
 * comment at the mount scan already notes indices "came back at a different
 * index" as a known effect, which is a bug being described rather than fixed.
 *
 * So: never zero the table, and skip a device that is already registered under
 * the same name. A later probe (a USB disk that appeared after boot -- which
 * is why kmain calls this a second time) still adds what is new, and every
 * index that already existed keeps meaning what it meant. */
static void reg(const char *name, int (*read)(void *, uint64_t, uint32_t, void *),
                int (*write)(void *, uint64_t, uint32_t, const void *),
                uint64_t sectors, void *ctx) {
    if (g_ndev >= BLOCKDEV_MAX) return;
    for (int k = 0; k < g_ndev; k++) {
        const char *a = g_dev[k].name, *b = name;
        if (!a || !b) continue;
        while (*a && *a == *b) { a++; b++; }
        if (*a == *b) {                       /* same name: already registered */
            g_dev[k].sectors = sectors;       /* size can legitimately be re-reported */
            g_bd_reg_skipped++;
            return;
        }
    }
    g_dev[g_ndev].name    = name;
    g_dev[g_ndev].read    = read;
    g_dev[g_ndev].write   = write;
    g_dev[g_ndev].sectors = sectors;
    g_dev[g_ndev].ctx     = ctx;
    g_dev[g_ndev].rd_ios = g_dev[g_ndev].rd_sectors = 0;   /* fresh I/O counters (M1256) */
    g_dev[g_ndev].wr_ios = g_dev[g_ndev].wr_sectors = 0;
    g_ndev++;
}

/* THE TABLE AS IT STANDS, WITHOUT RE-PROBING ANYTHING (M2231).
 *
 * M2229 stopped blockdev_init() zeroing g_ndev, which removed the window in
 * which every concurrent read failed. It did NOT stop /proc/partitions calling
 * it -- so every read of that file still re-probes ATA, AHCI, NVMe, virtio-blk
 * and USB storage, touching five drivers' hardware while other cores are using
 * them. The superblock failures went to zero and the inode-table rejections
 * came back at 72-111 per boot with one run reaching 1467524 rejected block
 * pointers, which is M2174's cascade: one bad group-descriptor read makes
 * every inode in that group come back as data.
 *
 * A LISTING IS A READ. It has no business probing anything. This returns what
 * is already registered, and probes only if nothing ever has been. */
int blockdev_ready(void) {
    if (g_ndev > 0) return g_ndev;
    return blockdev_init();
}

int blockdev_init(void) {
    /* NO TEARDOWN. See reg() above: zeroing g_ndev here is what made every
     * concurrent read on another core fail while /proc/partitions was being
     * formatted. The probe below is additive and idempotent now, so calling
     * this repeatedly is harmless -- and bcache_flush() is gone with it,
     * because there are no stale indices to drop when indices never move. */
    g_bd_init_calls++;

    /* ATA drives 0..3 — those that answered IDENTIFY. Static names so the
     * registered pointer stays valid for the lifetime of the kernel. */
    static const char *ata_names[ATA_MAX_DRIVES] = {
        "ata0", "ata1", "ata2", "ata3"
    };
    ata_identify_all();                            /* idempotent; ensure probed */
    for (int d = 0; d < ATA_MAX_DRIVES; d++) {
        const struct ata_drive_info *info = ata_drive(d);
        if (info && info->present)
            reg(ata_names[d], ata_bd_read, ata_bd_write, info->sectors, (void *)(intptr_t)d);
    }

    /* AHCI SATA disks — sized by IDENTIFY DEVICE (M1715), so the block layer
     * bounds-checks them like the ATA disks (capacity 0 only if IDENTIFY failed,
     * in which case reads stay unbounded, as before). */
    static const char *ahci_names[4] = { "ahci0", "ahci1", "ahci2", "ahci3" };
    int nahci = ahci_disk_count();
    for (int a = 0; a < nahci && a < 4; a++)
        reg(ahci_names[a], ahci_bd_read, ahci_bd_write, ahci_disk_sectors(a), (void *)(intptr_t)a);

    /* virtio-blk (single paravirtual disk). */
    if (virtio_blk_present())
        reg("virtio-blk", virtio_bd_read, virtio_bd_write, virtio_blk_capacity(), 0);

    /* NVMe namespace 1. */
    if (nvme_present())
        reg("nvme0n1", nvme_bd_read, nvme_bd_write, nvme_capacity(), 0);

    /* USB mass-storage over UHCI — read+write (M1728: usb_storage_write wired in). */
    if (usb_storage_present())
        reg("usb-storage", usb_bd_read, usb_bd_write, usb_storage_capacity(), 0);

    /* USB mass-storage over EHCI (USB 2.0) and xHCI (USB 3.0) — M1889. Until now
     * a disk on either was enumerated and read once at LBA 0 by the driver's own
     * self-test, then dropped on the floor; it is now a first-class blockdev, so
     * blockdev_enumerate() below mounts its FAT32/ext2 volumes like any other
     * disk. This is the path that matters off QEMU: real machines have no UHCI. */
    if (ehci_storage_present())
        reg("usb-ehci", ehci_bd_read, ehci_bd_write, ehci_storage_capacity(), 0);
    if (xhci_storage_present())
        reg("usb-xhci", xhci_bd_read, xhci_bd_write, xhci_storage_capacity(), 0);

    /* ATAPI CD-ROM(s) — read-only (write==NULL); enumerate then auto-mounts the
     * ISO 9660 volume like any other device (M1853). */
    atapi_init();
    for (int s = 0; s < ATAPI_MAX; s++)
        if (atapi_present(s))
            reg("cdrom", atapi_bd_read, 0, atapi_capacity512(s), (void *)(intptr_t)s);

    return g_ndev;
}

int blockdev_count(void) { return g_ndev; }

blockdev_t *blockdev_get(int i) {
    if (i < 0 || i >= g_ndev) return 0;
    return &g_dev[i];
}

/* Uncached driver dispatch + bounds — the read path before the cache. */
/* WHY THE LAST BLOCK READ REFUSED (M2157).
 *
 * `-1` from this function is seven different refusals wearing one number, and
 * by the time it reaches a caller it has been through ext2 (which called it
 * "file not found") and the page-fault fill. M2155 traced a zeroed executable
 * page back to exactly this -1 and could get no further than "a device error",
 * which is not a diagnosis. Name it here, where the branch is taken. */
int g_bd_fail_reason;
/* THE NUMBERS, NOT JUST THE BRANCH (M2158). "at or past the device's reported
 * capacity" names the branch and still leaves the two facts that decide it
 * unstated: WHICH lba, and what the device says its capacity IS. Both runs of
 * the 8-core Firefox failure refused the same file offset, so this is
 * arithmetic, not a race, and arithmetic is only debuggable with the operands
 * in hand. */
static uint64_t g_bd_fail_lba, g_bd_fail_cap;
static uint32_t g_bd_fail_count;
static int      g_bd_fail_dev = -1;
void blockdev_fail_operands(int *dev, uint64_t *lba, uint32_t *count, uint64_t *cap) {
    if (dev)   *dev   = g_bd_fail_dev;
    if (lba)   *lba   = g_bd_fail_lba;
    if (count) *count = g_bd_fail_count;
    if (cap)   *cap   = g_bd_fail_cap;
}
/* ONE COUNTER PER REASON (M2227).
 *
 * `blockdev_fail_why` remembers only the LAST refusal, so a boot that refuses
 * a superblock read six times and a garbage LBA a hundred times reports
 * whichever happened last -- and the one that matters is the one that did not.
 * The measured case: `6 readfail 0 BADMAGIC` on the superblock (LBA 2, which
 * cannot be past any capacity) while the last recorded refusal said exactly
 * that. Two different failures wearing one number, which is the shape this
 * whole hunt keeps turning up.
 *
 * Counted per reason, and the capacity the device CLAIMED at the moment of a
 * reason-4 refusal is kept with them: a capacity of zero on a device that has
 * sectors is a different bug from an LBA that is genuinely too large. */
unsigned long g_bd_fail_n[9];
int g_bd_badidx = -99, g_bd_badndev = -99;   /* the index and the table size at the last reason-8 refusal (M2228) */
uint64_t      g_bd_fail_cap4;     /* d->sectors as seen by the last reason-4 refusal */
uint64_t      g_bd_fail_lba4;
static void bd_fail(int reason, int i, uint64_t lba, uint32_t count, uint64_t cap) {
    g_bd_fail_reason = reason; g_bd_fail_dev = i;
    g_bd_fail_lba = lba; g_bd_fail_count = count; g_bd_fail_cap = cap;
    if (reason >= 0 && reason < 9) g_bd_fail_n[reason]++;
    if (reason == 4) { g_bd_fail_cap4 = cap; g_bd_fail_lba4 = lba; }
}
const char *blockdev_fail_why(void) {
    switch (g_bd_fail_reason) {
    case 1: return "the device index was out of range";
    case 2: return "the device has no read hook";
    case 3: return "the request was for ZERO sectors (a batch size computed as 0)";
    case 4: return "the starting LBA is at or past the device's reported capacity";
    case 5: return "lba + count overflowed 64 bits";
    case 6: return "the request runs past the device's reported capacity";
    case 7: return "the DRIVER returned an error";
    case 8: return "the DEVICE INDEX was out of range at blockdev_read's own entry guard (M2228)";
    default: return "no recorded reason";
    }
}

static int raw_read(int i, uint64_t lba, uint32_t count, void *buf) {
    if (i < 0 || i >= g_ndev || !buf) { bd_fail(1, i, lba, count, 0); return -1; }
    if (count == 0) { bd_fail(3, i, lba, count, 0); return -1; }
    blockdev_t *d = &g_dev[i];
    if (!d->read) { bd_fail(2, i, lba, count, 0); return -1; }
    /* Range-check against the known capacity (0 = unknown -> defer to the driver). */
    if (d->sectors) {
        if (lba >= d->sectors)       { bd_fail(4, i, lba, count, d->sectors); return -1; }
        if (lba + count < lba)       { bd_fail(5, i, lba, count, d->sectors); return -1; }
        if (lba + count > d->sectors){ bd_fail(6, i, lba, count, d->sectors); return -1; }
    }
    if (d->read(d->ctx, lba, count, buf) < 0) { bd_fail(7, i, lba, count, d->sectors); return -1; }
    return 0;
}
static int raw_write(int i, uint64_t lba, uint32_t count, const void *buf) {
    if (i < 0 || i >= g_ndev || !buf || count == 0) return -1;
    blockdev_t *d = &g_dev[i];
    if (!d->write) return -1;                        /* read-only device */
    if (d->sectors) {
        if (lba >= d->sectors) return -1;
        if (lba + count < lba) return -1;
        if (lba + count > d->sectors) return -1;
    }
    return d->write(d->ctx, lba, count, buf) < 0 ? -1 : 0;
}

/* Block caching is the unified kernel-wide cache now (kernel/bcache.c, M1869):
 * blockdev reads/writes go through it under the BLK owner namespace, sharing one
 * 64 KiB LRU pool + one /proc/bcache stat with the ATA driver instead of keeping
 * a private copy. Every lookup copies into the caller's buffer (no dangling on
 * eviction) and writes are write-through, exactly as before. */

/* An ATA-backed device is already cached AND kept coherent under the ATA owner by
 * ata_read_drive / ata_write_drive (which invalidates on every write). Adding a
 * second BLK-owner copy here would double-cache the same physical sector and,
 * worse, miss ata_write_drive's invalidation (a direct FAT32 write would leave
 * the BLK copy stale). So for ATA devices we skip this layer entirely and let the
 * driver's own cache serve — one coherent copy per sector (M1885, closes the
 * double-cache coherence gap the bcache.h note wrongly claimed was already gone). */
static int is_ata_backed(int i) { return g_dev[i].read == ata_bd_read; }

/* DROP A RANGE FROM WHICHEVER CACHE HOLDS IT (M2220).
 *
 * ext2.c is #included and compiled on the host by tests/ext2/ext2_test.c and
 * deliberately calls nothing outside itself, so it cannot reach bcache. It
 * needs to: `ext2_open` reads the superblock on EVERY pread, and on eight
 * cores that read comes back with the wrong MAGIC often enough to kill
 * Firefox two boots in three -- the fault handler's own diagnosis being
 * "the ext2 SUPERBLOCK could not be read". Whether the wrong bytes are in the
 * cache or came off the wire is the question, and dropping the range and
 * re-reading answers it in one step while also being the repair.
 *
 * Which owner key applies depends on the transport, which is exactly the
 * knowledge blockdev has and ext2 does not: an ATA-backed device is cached by
 * the driver under BCACHE_OWNER_ATA and every other one under
 * BCACHE_OWNER_BLK (M1885 -- one coherent copy per sector, never both). */
/* A READ THAT BYPASSES BOTH THE BLOCK CACHE AND DMA (M2240).
 *
 * The question M2237 could not answer: when a group descriptor block reads
 * back invalid, is the DISK wrong or is the PATH TO IT wrong? Dropping the
 * cache and re-reading does not separate them -- it still goes through the
 * same cache install and the same DMA engine, so agreement between the two
 * reads is equally consistent with "the platter holds this" and with "this
 * path returns the same wrong thing twice". Measured: 495 bad reads, 0 fixed
 * by the re-read, which is exactly the ambiguous answer.
 *
 * ata_read_drive_pio exists for precisely this (M2091): it takes ata_lock and
 * calls the PIO transfer directly, consulting no cache and programming no bus
 * master. Two independent mechanisms reading one sector is a discriminator
 * where two runs of one mechanism is not. */
int blockdev_read_raw(int i, uint64_t lba, uint32_t count, void *buf) {
    if (i < 0 || i >= g_ndev || !buf || count == 0) return -1;
    if (g_dev[i].sectors && (lba >= g_dev[i].sectors ||
                             count > g_dev[i].sectors - lba)) return -1;
    if (is_ata_backed(i))
        return ata_read_drive_pio((int)(intptr_t)g_dev[i].ctx, (uint32_t)lba, count, buf);
    return raw_read(i, lba, count, buf);      /* no independent path on this transport */
}

void blockdev_drop_cache(int i, uint64_t lba, uint32_t count) {
    if (i < 0 || i >= g_ndev || !count) return;
    if (is_ata_backed(i)) bcache_inval_range(BCACHE_OWNER_ATA((int)(intptr_t)g_dev[i].ctx), lba, count);
    else                  bcache_inval_range(BCACHE_OWNER_BLK(i), lba, count);
}

/* The largest run handed to the ATA driver in one call. It must match the
 * driver's DMA transfer ceiling exactly: a call bigger than that falls back to
 * PIO for the WHOLE request, which is slower than splitting it. M2091 set this
 * to 8 because the bounce buffer was one 4 KiB frame; M2101 made it sixteen
 * frames of scatter-gather PRD, so 128. Named from the driver's own constant
 * rather than copied, so the two cannot drift apart again. */
#define BLOCKDEV_MAX_BATCH ((uint32_t)ata_dma_max_sectors())

/* Read one sector (dev i, lba) into dst, via the cache. The per-device lock spans
 * lookup->read->install so a concurrent write's invalidation can't race between
 * the raw_read and the install and strand a stale sector in the cache (M1885). */
static int bread(int i, uint64_t lba, uint8_t *dst) {
    if (is_ata_backed(i)) return raw_read(i, lba, 1, dst) < 0 ? -1 : 0;   /* ATA: driver caches coherently */
    blk_lock_take(i);
    if (bcache_lookup(BCACHE_OWNER_BLK(i), lba, dst)) { blk_lock_give(i); return 0; }  /* hit */
    int r = raw_read(i, lba, 1, dst);                               /* miss */
    if (r >= 0) bcache_install(BCACHE_OWNER_BLK(i), lba, dst);
    blk_lock_give(i);
    return r < 0 ? -1 : 0;
}

/* Raised with the cache in M2154-M2155, for the same reason ATA's was: at 128
 * entries one big read had to bypass the cache to avoid flushing it, and
 * against tens of thousands of entries a 128-sector read is a fraction of a
 * percent of the pool and is the first thing CLOCK takes back anyway. Leaving
 * it at 16 meant a batched read populated NOTHING, so the readahead had to be
 * re-read from the device by the fault that followed it. */
#define BLOCKDEV_INSTALL_MAX 256u

int blockdev_read(int i, uint64_t lba, uint32_t count, void *buf) {
    /* THE ONLY RETURN -1 IN THE WHOLE PATH THAT RECORDED NOTHING (M2228).
     *
     * Measured: a failing 8-core boot reports 6 to 48 SUPERBLOCK read failures
     * -- `ext2_open`'s `read(ctx, start + 2, 2, sb) < 0` -- with
     *
     *     ata: 0 retr 0 FAIL 0 dma-short
     *     blockdev refusals by reason: idx 0 nohook 0 zerocount 0 LBA>=cap 0
     *                                  ovf 0 past-cap 0 driver 0
     *
     * The disk never errored and `raw_read` never refused, so the -1 came from
     * HERE, the one guard with no bd_fail behind it. The superblock read has a
     * non-null buffer and a count of 2, which leaves exactly one possibility:
     * `i < 0 || i >= g_ndev`. The device index that reaches this function is
     * wrong, or g_ndev is.
     *
     * Reason 8 records it with the offending index AND the g_ndev it was
     * compared against, because "the index is 3 and g_ndev is 4" and "the
     * index is 3 and g_ndev is 0" are different bugs -- the second means the
     * device table itself was transiently empty, which would refuse every read
     * on the machine at once and is exactly the burst this failure looks like
     * from outside. */
    if (i < 0 || i >= g_ndev || !buf || count == 0) {
        bd_fail(8, i, lba, count, (uint64_t)g_ndev);
        g_bd_badidx = i; g_bd_badndev = g_ndev;
        return -1;
    }
    uint8_t *out = (uint8_t *)buf;
    /* STOP SHREDDING (M2091).
     *
     * This loop turned every request into single-sector reads, so a 4 KiB
     * filesystem block was eight commands and the driver's own multi-sector
     * support was never reached. A Firefox boot issued 917022 commands to move
     * 917022 sectors -- exactly one sector each.
     *
     * MEASURED, and the measurement is the reason the fix looks like this
     * rather than like the plan's version. Per 512-byte sector:
     *
     *     1-sector PIO   94 Kcycles    (what this used to do)
     *     8-sector PIO   70 Kcycles    1.36x  -- nearly nothing
     *     1-sector DMA   41 Kcycles    2.26x
     *     8-sector DMA  8.3 Kcycles   11.39x
     *
     * The second line is why my first conclusion was wrong. I measured
     * batching on PIO, got 0.99x, and wrote off un-shredding as a dead end --
     * because PIO's cost is the insw transfer and batching does not reduce the
     * words moved. On DMA the transfer is a memcpy and what is left is the
     * per-command setup, so batching is worth 5.03x ON TOP of DMA. One
     * measurement of one pair, generalised, pointed at exactly the wrong half.
     *
     * Chunked to the driver's transfer limit rather than handed the whole
     * request: the DMA bounce buffer is one 4 KiB frame, and a request larger
     * than that has to be split somewhere. Non-ATA devices keep the
     * sector-at-a-time path, which is where their own cache lives. */
    if (is_ata_backed(i)) {
        uint32_t left = count, off = 0;
        /* NEVER LET THE BATCH BE ZERO (M2157). BLOCKDEV_MAX_BATCH is a CALL
         * into the driver -- `ata_dma_max_sectors()` -- and it reports the
         * bounce buffer it actually has, which can be none. A zero batch makes
         * `n` zero, `raw_read` refuses a zero-sector request, and every read on
         * the device fails with nothing pointing at the arithmetic. */
        uint32_t batch = BLOCKDEV_MAX_BATCH;
        if (!batch) batch = 1;
        while (left) {
            uint32_t n = left > batch ? batch : left;
            if (raw_read(i, lba + off, n, out + (uint64_t)off * BLOCKDEV_SECSZ) < 0) return -1;
            off += n; left -= n;
        }
    } else {
        /* NOT SHREDDING IS NOT AN ATA PRIVILEGE (M2147).
         *
         * M2091 stopped turning every request into single-sector commands --
         * for ATA-backed devices only. Every other block device in the tree
         * kept the sector-at-a-time loop: virtio-blk, AHCI, NVMe, USB storage.
         * So moving the Linux root onto virtio-blk, a transport with far less
         * per-request overhead than IDE, made it SLOWER: IDE was getting
         * 128-sector DMA batches while virtio got one sector per request. This
         * benchmark's own numbers say what that costs -- 8-sector versus
         * 1-sector DMA is 8.04x, and single-sector DMA is no better than PIO.
         *
         * The ATA branch above can batch freely because that driver caches
         * internally. Here the block cache IS the cache, so batching has to
         * keep it working or it silently turns filesystem caching off: try the
         * whole range first, and on any miss read it in driver-sized chunks
         * and install each sector individually. Sector-granular keys are kept
         * deliberately -- bcache_inval_range invalidates per sector for the
         * single-sector writes fat32 and the journal do, and re-keying to
         * block size would leave a stale journal descriptor in front of the
         * recovery path, which is undetectable corruption. */
        blk_lock_take(i);
        uint32_t hit = 0;
        for (; hit < count; hit++)
            if (!bcache_lookup(BCACHE_OWNER_BLK(i), lba + hit,
                               out + (uint64_t)hit * BLOCKDEV_SECSZ)) break;
        if (hit < count) {
            uint32_t left = count - hit, off = hit;
            uint32_t batch = BLOCKDEV_MAX_BATCH;
            if (!batch) batch = 1;
            while (left) {
                uint32_t n = left > batch ? batch : left;
                if (raw_read(i, lba + off, n, out + (uint64_t)off * BLOCKDEV_SECSZ) < 0) {
                    blk_lock_give(i); return -1;
                }
                /* Install per sector, and only for requests small enough that
                 * one of them cannot turn the whole cache over -- the same
                 * scan-resistance rule ata_read_drive applies. */
                if (n <= BLOCKDEV_INSTALL_MAX)
                    for (uint32_t k = 0; k < n; k++)
                        bcache_install(BCACHE_OWNER_BLK(i), lba + off + k,
                                       out + (uint64_t)(off + k) * BLOCKDEV_SECSZ);
                off += n; left -= n;
            }
        }
        blk_lock_give(i);
    }
    g_dev[i].rd_ios++; g_dev[i].rd_sectors += count;       /* /proc/diskstats (M1256) */
    return 0;
}

/* WHO WRITES OVER THE GROUP DESCRIPTOR TABLE? (M2236)
 *
 * Three facts, each cheap, that together move this from a read bug to a write
 * bug:
 *
 *   1. The rejected descriptor comes from LBA 8 -- the right sector.
 *   2. Dropping the block cache and reading LBA 8 AGAIN, from the disk,
 *      returns the SAME wrong bytes (`re-read 90: 0 DIFFERED`).
 *   3. Those eight bytes -- 78 00 1a 42 22 00 11 1b -- appear NOWHERE in
 *      build/ext2.img. Searched all 3355443200 bytes of it, and all of
 *      fat.img: zero hits.
 *
 * (3) kills "the read returned some other sector's data", which is what every
 * theory so far assumed. Bytes that are on no disk were never read off one.
 * And (2) says the disk now holds them -- the VM runs with `-snapshot`, so a
 * guest write persists for the rest of the boot and a re-read finds it.
 *
 * Put together: something in this kernel WROTE those bytes onto LBA 8. ext2 is
 * mounted read-write and Firefox writes constantly to its profile, so there is
 * no shortage of candidate writers -- but a write landing on the group
 * descriptor table is a wrong ADDRESS, not wrong data, and nothing in the tree
 * records where writes go.
 *
 * So record it. Every filesystem's metadata that matters lives in the first
 * few sectors of its volume, which makes "below LBA 32" a tripwire that costs
 * one comparison per write and fires on exactly the thing being hunted. The
 * legitimate writers show up here too -- ext2 does rewrite the group
 * descriptor's free counts -- and that is the point: a list of who writes here
 * with what is what distinguishes them from the one that should not. */
#define BD_WTRIP_LBA 32
unsigned long g_bd_wtrip_n;        /* writes below BD_WTRIP_LBA, any device */
unsigned long g_bd_wr_total;       /* every write, so "no writes at all" is visible */
unsigned long g_bd_wr_refused;     /* writes refused for an out-of-range LBA (M2237) */
uint64_t      g_bd_wr_ref_lba;     /* ...and the last such LBA */
static int    g_bd_wtrip_shown;

int blockdev_write(int i, uint64_t lba, uint32_t count, const void *buf) {
    if (i < 0 || i >= g_ndev) return -1;                   /* bound i before it indexes blk_lock/bcache */
    int r;
    /* A WRITE HAS NO BOUND AT ALL, AND A READ HAS EIGHT (M2237).
     *
     * blockdev_read refuses an out-of-range LBA for seven distinct reasons and
     * counts each one. blockdev_write checks the device index and nothing
     * else -- so a block number produced by corrupt metadata goes straight to
     * the driver as a write. ext2 reads bg_block_bitmap out of a group
     * descriptor and hands it to wrblk unchecked, which is exactly how a
     * single bad descriptor turns into a write at sector 8879342544.
     *
     * The asymmetry is the whole point: a refused read costs one failed
     * lookup, while an unbounded write is corruption somewhere nobody is
     * looking. The cheaper side was the one that got the checks. */
    if (g_dev[i].sectors && (lba >= g_dev[i].sectors ||
                             count > g_dev[i].sectors - lba)) {
        g_bd_wr_refused++;
        g_bd_wr_ref_lba = lba;
        return -1;
    }
    g_bd_wr_total++;
    if (lba < BD_WTRIP_LBA) {
        const unsigned char *tp = (const unsigned char *)buf;
        g_bd_wtrip_n++;
        if (g_bd_wtrip_shown < 32) {
            g_bd_wtrip_shown++;
            kprintf("[bdwr] dev %d lba %lu x%lu task %d <- %02x %02x %02x %02x %02x %02x %02x %02x\n",
                    i, (unsigned long)lba, (unsigned long)count, task_current_id(),
                    tp[0], tp[1], tp[2], tp[3], tp[4], tp[5], tp[6], tp[7]);
        }
    }
    if (is_ata_backed(i)) {
        /* ATA path: ata_write_drive already invalidates the ATA-owner cache under
         * ata_lock (and we keep no BLK-owner copy for ATA — see bread), so no
         * blockdev-level cache work is needed and it stays coherent (M1885). */
        r = raw_write(i, lba, count, buf);
    } else {
        /* Invalidate any cached copies of the written range BEFORE the write so a
         * concurrent reader can't re-cache stale bytes, then write (M1869). The
         * per-device lock spans inval+write so it is atomic against a concurrent
         * read-miss install on another core (M1885). Coherent + pollution-free (a
         * big swap write won't evict the read cache). */
        blk_lock_take(i);
        bcache_inval_range(BCACHE_OWNER_BLK(i), lba, count);
        r = raw_write(i, lba, count, buf);
        blk_lock_give(i);
    }
    if (r < 0) return -1;
    g_dev[i].wr_ios++; g_dev[i].wr_sectors += count;       /* /proc/diskstats (M1256) */
    return 0;
}

int blockdev_cache_format(char *out, int max) {
    /* the unified kernel-wide block cache now backs every device (M1869) */
    return bcache_stats(out, max);
}

/* Boot self-test (M1095): prove the write vtable + cache coherence + durability
 * on the first WRITABLE NON-boot device. We skip any "ata*" device so the boot
 * FAT32 disk is never written. Saves the target sector, writes a known pattern,
 * reads it back from the cache (coherence), flushes + reads from disk
 * (durability), then restores. Logged to the kernel log (dmesg); a clean no-op
 * if no safe writable device is present. Call after blockdev_enumerate. */
void blockdev_selftest(void) {
    int dev = -1;
    for (int i = 0; i < g_ndev; i++) {
        const char *nm = g_dev[i].name;
        if (!g_dev[i].write) continue;
        if (nm && nm[0] == 'a' && nm[1] == 't' && nm[2] == 'a') continue;  /* never the boot ATA disk */
        dev = i; break;
    }
    if (dev < 0) { kprintf("  blockdev cache: no non-boot writable device; write self-test skipped\n"); return; }

    uint64_t lba = g_dev[dev].sectors ? g_dev[dev].sectors - 1 : 2048;     /* a high, FS-unlikely sector */
    static uint8_t saved[BLOCKDEV_SECSZ], pat[BLOCKDEV_SECSZ], back[BLOCKDEV_SECSZ];
    if (blockdev_read(dev, lba, 1, saved) < 0) {
        kprintf("  blockdev cache: self-test read failed on %s\n", g_dev[dev].name); return;
    }
    for (int b = 0; b < BLOCKDEV_SECSZ; b++) pat[b] = (uint8_t)(b * 7 + 0x5A);

    int ok = blockdev_write(dev, lba, 1, pat) == 0 && blockdev_read(dev, lba, 1, back) == 0;
    for (int b = 0; ok && b < BLOCKDEV_SECSZ; b++) if (back[b] != pat[b]) ok = 0;   /* coherence (cached read-back) */
    bcache_flush();
    ok = ok && blockdev_read(dev, lba, 1, back) == 0;
    for (int b = 0; ok && b < BLOCKDEV_SECSZ; b++) if (back[b] != pat[b]) ok = 0;   /* durability (read from disk) */

    blockdev_write(dev, lba, 1, saved);                                            /* restore the original sector */
    kprintf("  blockdev cache: write+read-back+coherence+durability on %s lba %u: %s\n",
            g_dev[dev].name, (unsigned)lba, ok ? "OK" : "FAILED");
}

/* --- FAT32 volume discovery over a generic block device -------------------- */

/* A blk_read_fn (for fatvol_*) bound to one registered device by index. The
 * device index is packed into ctx. Reads go through blockdev_read so the device's
 * capacity bound (where known) is enforced. */
static int bd_blk_read(void *ctx, uint64_t lba, uint32_t count, void *buf) {
    return blockdev_read((int)(intptr_t)ctx, lba, count, buf);
}
/* The write counterpart (M1132): goes through the write-through buffer cache, so
 * a subsequent bd_blk_read sees the new bytes (read-back coherence). */
static int bd_blk_write(void *ctx, uint64_t lba, uint32_t count, const void *buf) {
    return blockdev_write((int)(intptr_t)ctx, lba, count, buf);
}

/* Collect candidate FAT32-volume start-LBAs on device `i` into `starts` (up to
 * `max`). A device either holds a bare filesystem at LBA 0 (no table) or an
 * MBR/GPT table carving it into partitions; we collect LBA 0 for the bare case
 * and each partition's start-LBA otherwise. fatvol_*() re-validates each as FAT32,
 * so collecting a non-FAT32 candidate is harmless. Returns the candidate count. */
static int collect_fat_starts(int i, uint64_t *starts, int max) {
    if (max <= 0) return 0;
    blockdev_t *d = blockdev_get(i);
    if (!d) return 0;
    uint64_t cap = d->sectors;                       /* 0 = unknown */

    uint8_t lba0[SECSZ];
    if (blockdev_read(i, 0, 1, lba0) < 0) return 0;

    /* No 0x55AA boot signature at LBA 0 => no MBR/GPT and no FAT32 BPB here. */
    if (rd16(lba0 + 510) != 0xAA55) return 0;

    /* Is LBA 0 itself a FAT32 BPB (a bare, unpartitioned volume)? Heuristic only —
     * fatvol_*() does the authoritative validation. The "FAT32" type string sits
     * at offset 82 in a FAT32 BPB; bytes/sector at 11 must be 512. */
    int n = 0;
    if (rd16(lba0 + 11) == SECSZ && memcmp(lba0 + 82, "FAT32", 5) == 0) {
        starts[n++] = 0;
        return n;                                    /* a bare volume has no table */
    }

    /* Otherwise treat LBA 0 as an MBR (or protective MBR for GPT). GPT if any of
     * the four primary entries is the 0xEE protective type. */
    int is_gpt = 0;
    for (int k = 0; k < 4; k++)
        if (lba0[0x1BE + k * 16 + 4] == 0xEE) { is_gpt = 1; break; }

    if (!is_gpt) {
        /* --- classic MBR: four 16-byte primary entries at 0x1BE --- */
        for (int k = 0; k < 4 && n < max; k++) {
            const uint8_t *e = lba0 + 0x1BE + k * 16;
            uint8_t type = e[4];
            if (type == 0x00) continue;              /* empty slot */
            if (type == 0xEE) continue;              /* protective (handled by GPT path) */
            uint64_t start = rd32(e + 8);
            uint64_t count = rd32(e + 12);
            if (count == 0) continue;
            if (start + count < start) continue;     /* overflow */
            if (cap && start >= cap) continue;       /* runs off a known-size disk */
            starts[n++] = start;
        }
        return n;
    }

    /* --- GPT: header at LBA 1, entry array it points at --- */
    uint8_t hdr[SECSZ];
    if (blockdev_read(i, 1, 1, hdr) < 0) return n;
    if (memcmp(hdr, "EFI PART", 8) != 0) return n;   /* protective MBR but no GPT */

    uint64_t arr_lba    = rd64(hdr + 72);
    uint32_t nentries   = rd32(hdr + 80);
    uint32_t entry_size = rd32(hdr + 84);
    if (entry_size < 128 || entry_size > SECSZ) return n;
    if (SECSZ % entry_size != 0) return n;           /* must tile a sector cleanly */
    if (nentries == 0) return n;
    if (nentries > 512) nentries = 512;              /* cap a runaway entry count */
    if (cap && arr_lba >= cap) return n;

    uint32_t per_sec = SECSZ / entry_size;
    uint32_t sectors_needed = (nentries + per_sec - 1) / per_sec;
    for (uint32_t s = 0; s < sectors_needed && n < max; s++) {
        uint64_t lba = arr_lba + s;
        if (cap && lba >= cap) break;
        uint8_t buf[SECSZ];
        if (blockdev_read(i, lba, 1, buf) < 0) break;
        for (uint32_t e = 0; e < per_sec && n < max; e++) {
            uint32_t idx = s * per_sec + e;
            if (idx >= nentries) break;
            const uint8_t *ent = buf + e * entry_size;   /* e*entry_size < SECSZ */
            int used = 0;
            for (int b = 0; b < 16; b++) if (ent[b]) { used = 1; break; }
            if (!used) continue;                     /* all-zero type GUID = unused */
            uint64_t first = rd64(ent + 32);
            uint64_t last  = rd64(ent + 40);
            if (last < first) continue;
            if (cap && first >= cap) continue;
            starts[n++] = first;
        }
    }
    return n;
}

/* --- read-only mount registry: every FAT32 volume across all block devices,
 *     browsable in the VFS as /disk1, /disk2, ... (M1061). Lazily built on the
 *     first query. Each mount is just (device index, volume start-LBA); reads go
 *     through bd_blk_read + the device-agnostic fatvol_list/fatvol_read. --- */
#define FS_FAT  0
#define FS_EXT2 1
#define FS_ISO9660 2
struct bd_mount {
    char name[8]; int dev; uint64_t start; int fstype;
    int is_loop; uint8_t *loopbuf; uint64_t looplen;   /* loop device: a file image held in RAM (M1107) */
};
static struct bd_mount g_mount[8];
static int g_nmount, g_mount_scanned_upto = -1;
static volatile int g_mount_scan_state;   /* 0 = never scanned, 1 = a core is scanning, 2 = done (M2155) */

/* DROP EVERYTHING CACHED FOR THE VOLUME BEHIND A MOUNT (M2223).
 *
 * The blunt version of blockdev_drop_cache, for the one caller that cannot
 * name the sectors it distrusts: a page fault whose file read came back wrong.
 * It knows the PATH and therefore the mount, and nothing more -- the block
 * numbers it would need are the ones the filesystem got wrong.
 *
 * Dropping a whole device's cache is always SAFE (the cache is write-through;
 * every entry can be re-read) and costs a re-read of whatever was live. That
 * is the right price for turning a corrupted read into a slow one instead of
 * into a dead process. */
void blockdev_drop_mount_caches(int midx) {
    if (midx < 0 || midx >= g_nmount) return;
    if (g_mount[midx].is_loop) return;             /* a RAM image: nothing below it is cached */
    int d = g_mount[midx].dev;
    if (d < 0 || d >= g_ndev) return;
    if (is_ata_backed(d)) bcache_inval_owner(BCACHE_OWNER_ATA((int)(intptr_t)g_dev[d].ctx));
    else                  bcache_inval_owner(BCACHE_OWNER_BLK(d));
}


/* A blk_read_fn for a loop mount: serve 512-byte sectors from its in-RAM image.
 * ctx is the mount index (so we can reach g_mount[idx].loopbuf). */
static int loop_blk_read(void *ctx, uint64_t lba, uint32_t count, void *buf) {
    int idx = (int)(intptr_t)ctx;
    /* bound by the array, not g_nmount: during losetup the slot is set up
     * (is_loop + loopbuf) and probed BEFORE g_nmount is incremented. */
    if (idx < 0 || idx >= 8 || !g_mount[idx].is_loop || !g_mount[idx].loopbuf) return -1;
    uint64_t off = lba * SECSZ, n = (uint64_t)count * SECSZ;
    if (off + n > g_mount[idx].looplen) return -1;          /* past the image */
    const uint8_t *src = g_mount[idx].loopbuf + off;
    uint8_t *dst = (uint8_t *)buf;
    for (uint64_t i = 0; i < n; i++) dst[i] = src[i];
    return 0;
}

/* Write counterpart for a loop mount: store sectors into its in-RAM image (M1132). */
static int loop_blk_write(void *ctx, uint64_t lba, uint32_t count, const void *buf) {
    int idx = (int)(intptr_t)ctx;
    if (idx < 0 || idx >= 8 || !g_mount[idx].is_loop || !g_mount[idx].loopbuf) return -1;
    uint64_t off = lba * SECSZ, n = (uint64_t)count * SECSZ;
    if (off + n > g_mount[idx].looplen) return -1;
    uint8_t *dst = g_mount[idx].loopbuf + off;
    const uint8_t *src = (const uint8_t *)buf;
    for (uint64_t i = 0; i < n; i++) dst[i] = src[i];
    return 0;
}

static void blockdev_mount_scan(void) {
    /* SCAN ONCE, AND MAKE SURE EVERY DISK EXISTS BY THEN (M2148).
     *
     * M2144 made this scan incrementally, keyed on the block-device INDEX, so
     * that a device registering after the first mount lookup would still be
     * picked up. That assumed device indices are stable across calls, and they
     * are not -- historically a later blockdev_init() re-registered and ata0 came
     * back at a different index, which M2229 fixed by making registration
     * additive; the note stays because the ORIGINAL reasoning for copying was
     * sound and the copy is still the right shape. Historically: ata0 came
     * back at a
     * different index. The result was the boot volume mounted TWICE under two
     * names --
     *
     *   [mount] disk2 = blockdev 1 (ata1) ... ext2
     *   [mount] disk3 = blockdev 2 (ata0) ... fat     <- ata0, again
     *
     * -- which renumbered the volumes under a running system. Mount names are
     * positional and LX_ROOT hardcodes `disk2`, so that is not a cosmetic bug.
     *
     * The real fix is upstream and simpler: bring every disk up BEFORE anything
     * mounts one (kmain calls virtio_blk_init() early for exactly this), and
     * then one scan is enough. A one-shot that runs at the right time beats an
     * incremental one that has to reason about identity it does not have. */
    /* ONE CORE SCANS, AND THE OTHERS WAIT FOR IT (M2155).
     *
     * `if (flag >= 0) return; ... flag = 1;` is a guard with the two halves the
     * wrong way round: the whole scan sat between the test and the set, so on
     * eight cores two early readers could both run it -- appending to
     * `g_mount[]` and `g_nmount` while the other walked them. Mount names here
     * are POSITIONAL and the Linux root is hardcoded `/disk2`, so a duplicate
     * or a renumbered volume is not cosmetic: it makes a path resolve against
     * the wrong filesystem, which comes back as "no such file", which is the
     * exact wrong answer M2155 is about everywhere else.
     *
     * A waiter that gave up and read the half-built table would be the same
     * bug, so it spins -- bounded, and falling through to the old behaviour if
     * the budget runs out, which is no worse than today and cannot hang. */
    if (__atomic_load_n(&g_mount_scan_state, __ATOMIC_ACQUIRE) == 2) return;
    {
        int expect = 0;
        if (!__atomic_compare_exchange_n(&g_mount_scan_state, &expect, 1, 0,
                                         __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            for (unsigned long w = 0; w < 200000000ul; w++) {
                if (__atomic_load_n(&g_mount_scan_state, __ATOMIC_ACQUIRE) == 2) return;
                __asm__ volatile("pause");
            }
            return;                           /* budget spent: behave as before */
        }
    }
    blockdev_ready();                         /* make sure devices are registered (M2231: without re-probing if they already are) */
    g_mount_scanned_upto = 1;
    for (int i = 0; i < g_ndev && g_nmount < 8; i++) {
        uint64_t starts[17];
        int ns = collect_fat_starts(i, starts, 16);
        /* Also consider LBA 0 for a table-less volume (e.g. a raw `mke2fs` image,
         * which has no 0xAA55 signature so collect_fat_starts skips it). */
        int have0 = 0; for (int v = 0; v < ns; v++) if (starts[v] == 0) have0 = 1;
        if (!have0) starts[ns++] = 0;
        for (int v = 0; v < ns && g_nmount < 8; v++) {
            int fstype;
            fatvol_dirent probe[1];
            /* Probe ext2 FIRST: its superblock-magic check is strict, whereas
             * fatvol_list returns 0 (>=0) even for a non-FAT volume, which would
             * otherwise misclaim an ext2 disk as an empty FAT one. */
            if (ext2_probe(bd_blk_read, (void *)(intptr_t)i, starts[v]) == 0)
                fstype = FS_EXT2;                                 /* an ext2 volume */
            else if (iso9660_probe(bd_blk_read, (void *)(intptr_t)i, starts[v]) == 0)
                fstype = FS_ISO9660;                              /* an ISO 9660 (CD/DVD) volume */
            else if (fatvol_list(bd_blk_read, (void *)(intptr_t)i, starts[v], probe, 1) >= 0)
                fstype = FS_FAT;                                  /* a FAT32 volume */
            else continue;                                        /* neither -> skip */
            struct bd_mount *m = &g_mount[g_nmount];
            m->name[0]='d'; m->name[1]='i'; m->name[2]='s'; m->name[3]='k';
            m->name[4] = (char)('1' + g_nmount); m->name[5] = 0;   /* disk1..disk8 */
            m->dev = i; m->start = starts[v]; m->fstype = fstype;
            /* NAME THE MOUNTS AS THEY ARE MADE (M2145). LX_ROOT hardcodes
             * `/disk2`, so which volume gets that name decides whether the
             * whole Linux side of this OS has a filesystem -- and nothing ever
             * printed it. Moving the root to another transport produced a
             * machine with two mounted volumes and no /disk2, and the table
             * that would have said why in one line did not exist. */
            kprintf("[mount] %s = blockdev %d (%s) at LBA %lu, fstype %s\n",
                    m->name, i, g_dev[i].name, (unsigned long)starts[v],
                    fstype == FS_EXT2 ? "ext2" : (fstype == FS_ISO9660 ? "iso9660" : "fat"));
            /* PROVE THE GROUP DESCRIPTORS ARE READABLE NOW, before any load
             * (M2235). Every reading of this filesystem's corruption so far
             * comes from a Firefox boot on eight cores, which cannot separate
             * "it never read correctly" from "it stops reading correctly under
             * concurrency" -- and those need opposite investigations. One read
             * at mount time settles it, and a clean line on every boot is what
             * will make the dirty one mean something. */
            if (fstype == FS_EXT2)
                ext2_gdt_selftest(bd_blk_read, (void *)(intptr_t)i, starts[v], kprintf);
            g_nmount++;
        }
    }
    __atomic_store_n(&g_mount_scan_state, 2, __ATOMIC_RELEASE);   /* table complete (M2155) */
}

int blockdev_mount_count(void) { blockdev_mount_scan(); return g_nmount; }

const char *blockdev_mount_name(int i) {
    blockdev_mount_scan();
    return (i >= 0 && i < g_nmount) ? g_mount[i].name : 0;
}

int blockdev_mount_index(const char *name) {     /* "disk2" -> index, else -1 */
    blockdev_mount_scan();
    for (int i = 0; i < g_nmount; i++) {
        const char *a = g_mount[i].name, *b = name;
        while (*a && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0) return i;
    }
    return -1;
}

/* List the directory at `subpath` (relative to the volume root, "" = root) of
 * mount `i`. Subdirectory-aware (M1070). */
/* The read fn + ctx for mount `i`: a loop device reads from RAM (ctx = the mount
 * index), a hardware mount via the blockdev layer (ctx = the device index). */
static blk_read_fn  mount_rfn(int i) { return g_mount[i].is_loop ? loop_blk_read  : bd_blk_read;  }
static blk_write_fn mount_wfn(int i) { return g_mount[i].is_loop ? loop_blk_write : bd_blk_write; }
static void        *mount_ctx(int i) { return (void *)(intptr_t)(g_mount[i].is_loop ? i : g_mount[i].dev); }

int blockdev_mount_list(int i, const char *subpath, fatvol_dirent *out, int max) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return 0;
    blk_read_fn r = mount_rfn(i); void *c = mount_ctx(i); uint64_t s = g_mount[i].start;
    return g_mount[i].fstype == FS_EXT2    ? ext2_list_path(r, c, s, subpath ? subpath : "", out, max)
         : g_mount[i].fstype == FS_ISO9660 ? iso9660_list_path(r, c, s, subpath ? subpath : "", out, max)
                                           : fatvol_list_path(r, c, s, subpath ? subpath : "", out, max);
}

/* Read the file at `path` (relative to the volume root) of mount `i`. -1 if it
 * is a directory / not found. Subdirectory-aware (M1070); ext2 or FAT32. */
long blockdev_mount_read(int i, const char *path, void *buf, unsigned long max) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    blk_read_fn r = mount_rfn(i); void *c = mount_ctx(i); uint64_t s = g_mount[i].start;
    return g_mount[i].fstype == FS_EXT2    ? ext2_read_path(r, c, s, path ? path : "", buf, max)
         : g_mount[i].fstype == FS_ISO9660 ? iso9660_read_path(r, c, s, path ? path : "", buf, max)
                                           : fatvol_read_path(r, c, s, path ? path : "", buf, max);
}
/* Positioned read on mount `i` (M1196): ext2 reads natively at the offset; ISO/
 * FAT fall back to a read-prefix-then-slice (read [0, offset+max), return the
 * [offset..] tail) — correct, just not seek-efficient on those. */
long blockdev_mount_pread(int i, const char *path, void *buf, unsigned long max, unsigned long offset) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    /* THE MOUNT'S START SECTOR MUST BE ON THE DEVICE (M2167). Every read this
     * mount performs is `start + block * sectors_per_block`, so a corrupt
     * `start` makes every one of them land off the end of the disk -- which is
     * exactly what a refused read reporting `lba 18962972664 cap 6553600`
     * looks like once you notice the block number itself was in range. The
     * table is built once at boot and never changed after, so this can only
     * fire if something wrote over it. Say so; do not read past the disk. */
    {   blockdev_t *d = blockdev_get(g_mount[i].dev);
        if (d && d->sectors && g_mount[i].start >= d->sectors) {
            static int told;
            if (told < 4) {
                told++;
                kprintf("[mount] CORRUPT: mount %d (%s) claims to start at LBA %lu on a device "
                        "with %lu sectors. Every read through it would land off the end of the "
                        "disk. The table is built once at boot, so this was OVERWRITTEN.\n",
                        i, g_mount[i].name, (unsigned long)g_mount[i].start,
                        (unsigned long)d->sectors);
            }
            return -1;
        }
    }
    if (g_mount[i].fstype == FS_EXT2)
        return ext2_pread(mount_rfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", buf, max, offset);
    /* ISO/FAT: read the prefix into a temp, slice the tail */
    unsigned long want = offset + max; if (want > (16u << 20)) want = 16u << 20;
    char *tmp = kmalloc(want ? want : 1); if (!tmp) return -1;
    long got = blockdev_mount_read(i, path, tmp, want);
    long n = 0;
    if (got > (long)offset) { n = got - (long)offset; if ((unsigned long)n > max) n = (long)max;
                              for (long k = 0; k < n; k++) ((char *)buf)[k] = tmp[offset + k]; }
    kfree(tmp);
    return n;
}

/* Create a new file at `path` (relative to the volume root) on mount `i`. Only
 * ext2 mounts are writable here (FAT32 boot disk is written directly by fat32.c;
 * ISO 9660 is a read-only medium). Bytes written, or -1. M1132. */
/* ---- ONE WRITER AT A TIME IN THE FILESYSTEM (M2308) ---------------------
 *
 * ext2.c, blockdev.c and vfs.c contained NO serialisation of any kind, and
 * every metadata mutation here is a read-modify-write of a SHARED block:
 * write_inode reads a 4096-byte inode-table block, changes one 256-byte
 * inode and writes the whole block back; alloc_block does it to a bitmap;
 * dir_add to a directory block. Two cores doing that for two different
 * inodes that happen to share a block each read, each modify, each write --
 * and the second puts back a copy that never contained the first's change.
 *
 * That is the corruption exactly: an inode table whose bytes are wrong,
 * `0 DIFFERED` on re-read because the bad data really is on the disk, and
 * only ever above one core --
 *
 *     cores    itable errors    SIGSEGVs
 *       1            0              0
 *       4            0              0
 *       8        111-115          8-11
 *
 * M2236-M2240 found this same hazard for the GROUP DESCRIPTOR block and
 * fixed it there alone. M2252 then read "0 / 0 / 0" off a filesystem that
 * was 100% FULL -- where allocation failed instantly and this path barely
 * ran -- and called it cured. It was not; it was unexercised.
 *
 * The ATA driver already serialises individual TRANSFERS and that cannot
 * help: the race is between the read and the write, not inside either.
 *
 * Writers only -- readers do not modify, and serialising path resolution
 * across eight cores would cost far more than it buys. Spin-then-yield, the
 * shape ata.c's lock uses (M1911), because this is held across real disk I/O
 * and a pure spinner on the holder's own core starves the task it waits for. */
static volatile int fsw_lock;
static void fsw_take(void) {
    uint32_t spins = 0;
    while (__atomic_exchange_n(&fsw_lock, 1, __ATOMIC_ACQUIRE))
        if (++spins >= 1000) { spins = 0; task_yield(); }
}
static void fsw_give(void) { __atomic_store_n(&fsw_lock, 0, __ATOMIC_RELEASE); }

static long blockdev_mount_write_locked(int i, const char *path, const void *buf, unsigned long len) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;          /* read-only filesystem */
    return ext2_write_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                           path ? path : "", buf, len);
}
long blockdev_mount_write(int i, const char *path, const void *buf, unsigned long len) {
    fsw_take();
    long r = blockdev_mount_write_locked(i, path, buf, len);
    fsw_give();
    return r;
}


/* Positional WRITE on mount `i` (ext2 only): place len bytes at byte offset
 * `off`, creating/extending the file, without ever materialising the whole
 * file. The streaming counterpart of blockdev_mount_pread — and unlike that
 * one there is no read-prefix fallback for ISO/FAT, because ISO is read-only
 * and a secondary FAT mount has no write path here at all. M1935. */
static long blockdev_mount_pwrite_locked(int i, const char *path, const void *buf, unsigned long len, uint64_t off) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;          /* read-only filesystem */
    return ext2_pwrite_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                            path ? path : "", off, buf, len);
}
long blockdev_mount_pwrite(int i, const char *path, const void *buf, unsigned long len, uint64_t off) {
    fsw_take();
    long r = blockdev_mount_pwrite_locked(i, path, buf, len, off);
    fsw_give();
    return r;
}


/* Delete a file on mount `i` (ext2 only). 0 on success, -1 otherwise. M1135. */
static long blockdev_mount_remove_locked(int i, const char *path) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_unlink_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                            path ? path : "");
}
long blockdev_mount_remove(int i, const char *path) {
    fsw_take();
    long r = blockdev_mount_remove_locked(i, path);
    fsw_give();
    return r;
}


/* Create a directory on mount `i` (ext2 only). 0 on success, -1 otherwise. M1137. */
static long blockdev_mount_mkdir_locked(int i, const char *path) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_mkdir_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                           path ? path : "");
}
long blockdev_mount_mkdir(int i, const char *path) {
    fsw_take();
    long r = blockdev_mount_mkdir_locked(i, path);
    fsw_give();
    return r;
}


/* Create a symlink on mount `i` (ext2 only). 0 on success, -1 otherwise. M1146. */
static long blockdev_mount_symlink_locked(int i, const char *path, const char *target) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_symlink_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                             path ? path : "", target ? target : "");
}
long blockdev_mount_symlink(int i, const char *path, const char *target) {
    fsw_take();
    long r = blockdev_mount_symlink_locked(i, path, target);
    fsw_give();
    return r;
}


/* Read a symlink's target on mount `i` (ext2 only), not followed. bytes/-1. M1594. */
long blockdev_mount_readlink(int i, const char *path, void *buf, unsigned long max) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_readlink_path(mount_rfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", buf, max);
}

static long blockdev_mount_link_locked(int i, const char *oldpath, const char *newpath) {   /* hard link (ext2 only); 0/-1 (M1207) */
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_link_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                          oldpath ? oldpath : "", newpath ? newpath : "");
}
long blockdev_mount_link(int i, const char *oldpath, const char *newpath) {
    fsw_take();
    long r = blockdev_mount_link_locked(i, oldpath, newpath);
    fsw_give();
    return r;
}

static long blockdev_mount_rename_locked(int i, const char *oldpath, const char *newpath) {   /* rename/move (ext2 only); 0/-1 (M1213) */
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_rename_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                            oldpath ? oldpath : "", newpath ? newpath : "");
}
long blockdev_mount_rename(int i, const char *oldpath, const char *newpath) {
    fsw_take();
    long r = blockdev_mount_rename_locked(i, oldpath, newpath);
    fsw_give();
    return r;
}

long blockdev_mount_rename2(int i, const char *oldpath, const char *newpath, int flags) {  /* renameat2 (ext2 only); 0/-1 (M1232) */
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_rename2_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                             oldpath ? oldpath : "", newpath ? newpath : "", flags);
}
static long blockdev_mount_truncate_locked(int i, const char *path, uint64_t newlen) {   /* resize (ext2 only); 0/-1 (M1228) */
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_truncate_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", newlen);
}
long blockdev_mount_truncate(int i, const char *path, uint64_t newlen) {
    fsw_take();
    long r = blockdev_mount_truncate_locked(i, path, newlen);
    fsw_give();
    return r;
}


/* SEEK_HOLE/SEEK_DATA on mount `i`. ext2 walks the block map for real sparse
 * boundaries; -2 means "not an ext2 mount" so vfs falls back to a generic
 * no-holes answer (FAT/ISO are never sparse). M1229. */
long blockdev_mount_seek_data_hole(int i, const char *path, long off, int find_hole) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -2;
    if (g_mount[i].fstype != FS_EXT2) return -2;
    return ext2_seek_data_hole(mount_rfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", off, find_hole);
}

/* utimensat backend on mount `i` (ext2 only; negative time = leave). 0/-1. M1230. */
static long blockdev_mount_utimes_locked(int i, const char *path, long atime, long mtime) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_utimes_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", atime, mtime);
}
long blockdev_mount_utimes(int i, const char *path, long atime, long mtime) {
    fsw_take();
    long r = blockdev_mount_utimes_locked(i, path, atime, mtime);
    fsw_give();
    return r;
}

/* chmod backend on mount `i` (ext2 only). 0/-1. M1241. */
static long blockdev_mount_chmod_locked(int i, const char *path, uint32_t mode) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_chmod_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", mode);
}
long blockdev_mount_chmod(int i, const char *path, uint32_t mode) {
    fsw_take();
    long r = blockdev_mount_chmod_locked(i, path, mode);
    fsw_give();
    return r;
}

/* chown backend on mount `i` (ext2 only; negative id = leave). 0/-1. M1243. */
static long blockdev_mount_chown_locked(int i, const char *path, long uid, long gid) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_chown_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", uid, gid);
}
long blockdev_mount_chown(int i, const char *path, long uid, long gid) {
    fsw_take();
    long r = blockdev_mount_chown_locked(i, path, uid, gid);
    fsw_give();
    return r;
}


int blockdev_mount_fiemap(int i, const char *path, ext2_extent_t *out, int max) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;    /* physical extent map: ext2 only (M1152) */
    return ext2_fiemap(mount_rfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", out, max);
}

static long blockdev_mount_punch_locked(int i, const char *path, uint64_t offset, uint64_t len) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;    /* hole punching: ext2 only (M1153) */
    return ext2_punch_hole(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                           path ? path : "", offset, len);
}
long blockdev_mount_punch(int i, const char *path, uint64_t offset, uint64_t len) {
    fsw_take();
    long r = blockdev_mount_punch_locked(i, path, offset, len);
    fsw_give();
    return r;
}


/* Extended attributes on mount `i` (ext2 only, user.* namespace). M1182. */
static long blockdev_mount_setxattr_locked(int i, const char *path, const char *name, const void *val, unsigned long vlen) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount || g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_setxattr(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                         path ? path : "", name ? name : "", val, vlen);
}
long blockdev_mount_setxattr(int i, const char *path, const char *name, const void *val, unsigned long vlen) {
    fsw_take();
    long r = blockdev_mount_setxattr_locked(i, path, name, val, vlen);
    fsw_give();
    return r;
}

long blockdev_mount_getxattr(int i, const char *path, const char *name, void *out, unsigned long max) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount || g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_getxattr(mount_rfn(i), mount_ctx(i), g_mount[i].start,
                         path ? path : "", name ? name : "", out, max);
}
long blockdev_mount_listxattr(int i, const char *path, char *out, unsigned long max) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount || g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_listxattr(mount_rfn(i), mount_ctx(i), g_mount[i].start,
                          path ? path : "", out, max);
}
static long blockdev_mount_removexattr_locked(int i, const char *path, const char *name) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount || g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_removexattr(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                            path ? path : "", name ? name : "");
}
long blockdev_mount_removexattr(int i, const char *path, const char *name) {
    fsw_take();
    long r = blockdev_mount_removexattr_locked(i, path, name);
    fsw_give();
    return r;
}


/* Is `path` (relative to the volume root) a directory on mount `i`? For `cd`. */
int blockdev_mount_isdir(int i, const char *path) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return 0;
    blk_read_fn r = mount_rfn(i); void *c = mount_ctx(i); uint64_t s = g_mount[i].start;
    return g_mount[i].fstype == FS_EXT2    ? ext2_isdir_path(r, c, s, path ? path : "")
         : g_mount[i].fstype == FS_ISO9660 ? iso9660_isdir_path(r, c, s, path ? path : "")
                                           : fatvol_isdir_path(r, c, s, path ? path : "");
}

/* Size + isdir for `path` (relative to the volume root) on mount `i` (M1624):
 * same 3-way dispatch as blockdev_mount_isdir, feeding vfs_stat so an
 * ABSOLUTE /diskN/... path resolves even when cwd is outside that mount
 * (vfs_stat's own FAT32-only fallback has no notion of a mount name at all). */
int blockdev_mount_stat(int i, const char *path, uint32_t *out_size, int *out_isdir, uint32_t *out_ino,
                        uint32_t *out_mtime, uint32_t *out_nlink, uint32_t *out_mode) {
    blockdev_mount_scan();
    if (out_ino) *out_ino = 0;                  /* 0 = this filesystem has no inode to report */
    if (out_mtime) *out_mtime = 0;
    if (out_nlink) *out_nlink = 0;
    if (out_mode)  *out_mode  = 0;   /* ext2 fills these; FAT32/ISO9660 have no inode (M1999) */
    if (i < 0 || i >= g_nmount) return -1;
    blk_read_fn r = mount_rfn(i); void *c = mount_ctx(i); uint64_t s = g_mount[i].start;
    /* Only ext2 has real inodes. FAT32 and ISO9660 have none, so they leave
     * out_ino at 0 and vfs_stat synthesizes one from the path instead. */
    return g_mount[i].fstype == FS_EXT2    ? ext2_stat_path(r, c, s, path ? path : "", out_size, out_isdir, out_ino, out_mtime, out_nlink, out_mode)
         : g_mount[i].fstype == FS_ISO9660 ? iso9660_stat_path(r, c, s, path ? path : "", out_size, out_isdir)
                                           : fatvol_stat_path(r, c, s, path ? path : "", out_size, out_isdir);
}

/* losetup: register a loop mount backed by the file image `data` (len bytes,
 * ownership transferred — freed never; loops are permanent for the session).
 * Detects FAT32/ext2 in the image and mounts it as the next /diskN. Returns the
 * mount index, or -1 (full, or not a recognised filesystem). M1107. */
int blockdev_losetup(uint8_t *data, uint64_t len) {
    blockdev_mount_scan();
    if (g_nmount >= 8 || !data || len < 1024) return -1;
    int i = g_nmount;
    g_mount[i].is_loop = 1; g_mount[i].loopbuf = data; g_mount[i].looplen = len; g_mount[i].start = 0;
    int fstype;
    fatvol_dirent probe[1];
    if (ext2_probe(loop_blk_read, (void *)(intptr_t)i, 0) == 0) fstype = FS_EXT2;
    else if (iso9660_probe(loop_blk_read, (void *)(intptr_t)i, 0) == 0) fstype = FS_ISO9660;
    else if (fatvol_list(loop_blk_read, (void *)(intptr_t)i, 0, probe, 1) >= 0) fstype = FS_FAT;
    else { g_mount[i].is_loop = 0; return -1; }              /* unrecognised -> don't mount */
    g_mount[i].fstype = fstype;
    g_mount[i].name[0]='d'; g_mount[i].name[1]='i'; g_mount[i].name[2]='s'; g_mount[i].name[3]='k';
    g_mount[i].name[4] = (char)('1' + i); g_mount[i].name[5] = 0;
    g_nmount++;
    return i;
}

/* --- the headless browsing demo -------------------------------------------- */

void blockdev_enumerate(void) {
    int ndev = blockdev_ready();       /* a listing does not re-probe (M2231) */
    kprintf("[ ok ] block devices: %d present (browsable across all storage drivers).\n",
            ndev);

    int total_volumes = 0;
    for (int i = 0; i < ndev; i++) {
        blockdev_t *d = blockdev_get(i);
        if (!d) continue;
        if (d->sectors)
            kprintf("  blockdev %d: %s, %lu sectors (%lu MiB)\n",
                    i, d->name, (unsigned long)d->sectors,
                    (unsigned long)(d->sectors / 2048));
        else
            kprintf("  blockdev %d: %s, capacity unknown\n", i, d->name);

        uint64_t starts[16];
        int nstart = collect_fat_starts(i, starts, 16);
        if (nstart == 0) {
            kprintf("    no FAT32 volume found (not FAT32 / unreadable).\n");
            continue;
        }

        for (int v = 0; v < nstart; v++) {
            uint64_t start = starts[v];
            static fatvol_dirent ents[32];   /* static, not stack: 8 KB of 256-byte names on a 16 KB kernel stack (M2062). Boot probe, one core, one caller. */
            int n = fatvol_list(bd_blk_read, (void *)(intptr_t)i, start, ents, 32);
            if (n <= 0) {
                /* The candidate wasn't actually a readable FAT32 volume — skip
                 * cleanly (e.g. a non-FAT32 partition, or a read error). */
                continue;
            }
            total_volumes++;
            kprintf("    FAT32 volume mounted (read-only) at start-LBA %lu: %d root entr%s\n",
                    (unsigned long)start, n, n == 1 ? "y" : "ies");
            for (int e = 0; e < n; e++) {
                if (ents[e].is_dir)
                    kprintf("        %s/  (dir)\n", ents[e].name);
                else
                    kprintf("        %s  (%lu bytes)\n",
                            ents[e].name, (unsigned long)ents[e].size);
            }
        }
    }

    /* Also list any mounted NON-FAT volumes (ISO 9660 CDs, ext2 disks): the
     * per-device scan above only covers FAT32, so a mounted CD/ext2 disk was
     * invisible in the boot browse until now (M1854). */
    int nmounts = blockdev_mount_count();
    for (int mi = 0; mi < nmounts; mi++) {
        if (g_mount[mi].fstype == FS_FAT) continue;                 /* already shown above */
        const char *fs = g_mount[mi].fstype == FS_ISO9660 ? "ISO 9660" : "ext2";
        const char *ro = g_mount[mi].fstype == FS_ISO9660 ? "read-only" : "read-write";
        static fatvol_dirent ents[32];   /* see above (M2062) */
        int n = blockdev_mount_list(mi, "", ents, 32);
        if (n < 0) n = 0;
        total_volumes++;
        kprintf("    %s volume mounted (%s) as /%s: %d root entr%s\n",
                fs, ro, g_mount[mi].name, n, n == 1 ? "y" : "ies");
        for (int e = 0; e < n; e++) {
            if (ents[e].is_dir) kprintf("        %s/  (dir)\n", ents[e].name);
            else kprintf("        %s  (%lu bytes)\n", ents[e].name, (unsigned long)ents[e].size);
        }
    }

    kprintf("[ ok ] blockdev browse: %d volume(s) listed across %d device(s).\n",
            total_volumes, ndev);
}

/* --- text formatting for the userspace `lsblk` shell command (SYS_lsblk) ----
 * Bounded string/decimal appenders, then the same browse as above but written to
 * a caller buffer instead of the serial log. */
static int sapp(char *b, int p, int max, const char *s) {
    while (*s && p < max - 1) b[p++] = *s++;
    return p;
}
static int sdec(char *b, int p, int max, uint64_t v) {
    char t[24]; int n = 0;
    if (v == 0) t[n++] = '0';
    while (v && n < 24) { t[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n && p < max - 1) b[p++] = t[--n];
    return p;
}

int blockdev_format(char *out, int max) {
    if (!out || max < 2) return 0;
    /* /proc/partitions lands here. It must not re-probe five storage drivers
     * while other cores are reading from them (M2231). */
    int ndev = blockdev_ready();
    int p = 0;
    p = sapp(out, p, max, "block devices: ");
    p = sdec(out, p, max, (uint64_t)ndev);
    p = sapp(out, p, max, " present\n");
    for (int i = 0; i < ndev; i++) {
        blockdev_t *d = blockdev_get(i);
        if (!d) continue;
        p = sapp(out, p, max, "  ");
        p = sapp(out, p, max, d->name);
        if (d->sectors) {
            p = sapp(out, p, max, "  ");
            p = sdec(out, p, max, d->sectors / 2048);
            p = sapp(out, p, max, " MiB");
        } else {
            p = sapp(out, p, max, "  (size unknown)");
        }
        p = sapp(out, p, max, "\n");
        uint64_t starts[16];
        int nstart = collect_fat_starts(i, starts, 16);
        for (int v = 0; v < nstart; v++) {
            static fatvol_dirent ents[32];   /* static, not stack: 8 KB of 256-byte names on a 16 KB kernel stack (M2062). Boot probe, one core, one caller. */
            int n = fatvol_list(bd_blk_read, (void *)(intptr_t)i, starts[v], ents, 32);
            if (n <= 0) continue;
            p = sapp(out, p, max, "    FAT32 @ LBA ");
            p = sdec(out, p, max, starts[v]);
            p = sapp(out, p, max, ":\n");
            for (int e = 0; e < n; e++) {
                p = sapp(out, p, max, "      ");
                p = sapp(out, p, max, ents[e].name);
                if (ents[e].is_dir) {
                    p = sapp(out, p, max, "/");
                } else {
                    p = sapp(out, p, max, "  (");
                    p = sdec(out, p, max, ents[e].size);
                    p = sapp(out, p, max, " bytes)");
                }
                p = sapp(out, p, max, "\n");
            }
        }
    }
    if (p < max) out[p] = 0;
    return p;
}

/* List the read-only disk mounts (/disk1, /disk2, ...) into `out` — backs the
 * `mount` shell command so the secondary volumes are discoverable. */
int blockdev_mounts_format(char *out, int max) {
    blockdev_mount_scan();
    int p = 0;
    if (g_nmount == 0) { p = sapp(out, p, max, "no FAT32 disk volumes found\n"); if (p < max) out[p] = 0; return p; }
    for (int i = 0; i < g_nmount; i++) {
        p = sapp(out, p, max, "  /");
        p = sapp(out, p, max, g_mount[i].name);
        p = sapp(out, p, max, "  on ");
        p = sapp(out, p, max, g_dev[g_mount[i].dev].name ? g_dev[g_mount[i].dev].name : "?");
        p = sapp(out, p, max, " @ LBA ");
        p = sdec(out, p, max, g_mount[i].start);
        p = sapp(out, p, max, "  (read-only)\n");
    }
    if (p < max) out[p] = 0;
    return p;
}
