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

static void reg(const char *name, int (*read)(void *, uint64_t, uint32_t, void *),
                int (*write)(void *, uint64_t, uint32_t, const void *),
                uint64_t sectors, void *ctx) {
    if (g_ndev >= BLOCKDEV_MAX) return;
    g_dev[g_ndev].name    = name;
    g_dev[g_ndev].read    = read;
    g_dev[g_ndev].write   = write;
    g_dev[g_ndev].sectors = sectors;
    g_dev[g_ndev].ctx     = ctx;
    g_dev[g_ndev].rd_ios = g_dev[g_ndev].rd_sectors = 0;   /* fresh I/O counters (M1256) */
    g_dev[g_ndev].wr_ios = g_dev[g_ndev].wr_sectors = 0;
    g_ndev++;
}

int blockdev_init(void) {
    g_ndev = 0;
    bcache_flush();                  /* device indices may change -> drop stale cached blocks */

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
static int raw_read(int i, uint64_t lba, uint32_t count, void *buf) {
    if (i < 0 || i >= g_ndev || !buf || count == 0) return -1;
    blockdev_t *d = &g_dev[i];
    if (!d->read) return -1;
    /* Range-check against the known capacity (0 = unknown -> defer to the driver). */
    if (d->sectors) {
        if (lba >= d->sectors) return -1;
        if (lba + count < lba) return -1;            /* 64-bit overflow */
        if (lba + count > d->sectors) return -1;
    }
    return d->read(d->ctx, lba, count, buf) < 0 ? -1 : 0;
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

int blockdev_read(int i, uint64_t lba, uint32_t count, void *buf) {
    if (i < 0 || i >= g_ndev || !buf || count == 0) return -1;
    uint8_t *out = (uint8_t *)buf;
    for (uint32_t s = 0; s < count; s++)
        if (bread(i, lba + s, out + (uint64_t)s * BLOCKDEV_SECSZ) < 0) return -1;
    g_dev[i].rd_ios++; g_dev[i].rd_sectors += count;       /* /proc/diskstats (M1256) */
    return 0;
}

int blockdev_write(int i, uint64_t lba, uint32_t count, const void *buf) {
    if (i < 0 || i >= g_ndev) return -1;                   /* bound i before it indexes blk_lock/bcache */
    int r;
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
static int g_nmount, g_mount_scanned;

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
    if (g_mount_scanned) return;
    g_mount_scanned = 1;
    blockdev_init();                          /* make sure devices are registered */
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
            g_nmount++;
        }
    }
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
long blockdev_mount_write(int i, const char *path, const void *buf, unsigned long len) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;          /* read-only filesystem */
    return ext2_write_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                           path ? path : "", buf, len);
}

/* Positional WRITE on mount `i` (ext2 only): place len bytes at byte offset
 * `off`, creating/extending the file, without ever materialising the whole
 * file. The streaming counterpart of blockdev_mount_pread — and unlike that
 * one there is no read-prefix fallback for ISO/FAT, because ISO is read-only
 * and a secondary FAT mount has no write path here at all. M1935. */
long blockdev_mount_pwrite(int i, const char *path, const void *buf, unsigned long len, uint64_t off) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;          /* read-only filesystem */
    return ext2_pwrite_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                            path ? path : "", off, buf, len);
}

/* Delete a file on mount `i` (ext2 only). 0 on success, -1 otherwise. M1135. */
long blockdev_mount_remove(int i, const char *path) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_unlink_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                            path ? path : "");
}

/* Create a directory on mount `i` (ext2 only). 0 on success, -1 otherwise. M1137. */
long blockdev_mount_mkdir(int i, const char *path) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_mkdir_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                           path ? path : "");
}

/* Create a symlink on mount `i` (ext2 only). 0 on success, -1 otherwise. M1146. */
long blockdev_mount_symlink(int i, const char *path, const char *target) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_symlink_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                             path ? path : "", target ? target : "");
}

/* Read a symlink's target on mount `i` (ext2 only), not followed. bytes/-1. M1594. */
long blockdev_mount_readlink(int i, const char *path, void *buf, unsigned long max) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_readlink_path(mount_rfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", buf, max);
}

long blockdev_mount_link(int i, const char *oldpath, const char *newpath) {   /* hard link (ext2 only); 0/-1 (M1207) */
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_link_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                          oldpath ? oldpath : "", newpath ? newpath : "");
}
long blockdev_mount_rename(int i, const char *oldpath, const char *newpath) {   /* rename/move (ext2 only); 0/-1 (M1213) */
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_rename_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                            oldpath ? oldpath : "", newpath ? newpath : "");
}
long blockdev_mount_rename2(int i, const char *oldpath, const char *newpath, int flags) {  /* renameat2 (ext2 only); 0/-1 (M1232) */
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_rename2_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                             oldpath ? oldpath : "", newpath ? newpath : "", flags);
}
long blockdev_mount_truncate(int i, const char *path, uint64_t newlen) {   /* resize (ext2 only); 0/-1 (M1228) */
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_truncate_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", newlen);
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
long blockdev_mount_utimes(int i, const char *path, long atime, long mtime) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_utimes_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", atime, mtime);
}
/* chmod backend on mount `i` (ext2 only). 0/-1. M1241. */
long blockdev_mount_chmod(int i, const char *path, uint32_t mode) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_chmod_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", mode);
}
/* chown backend on mount `i` (ext2 only; negative id = leave). 0/-1. M1243. */
long blockdev_mount_chown(int i, const char *path, long uid, long gid) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_chown_path(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", uid, gid);
}

int blockdev_mount_fiemap(int i, const char *path, ext2_extent_t *out, int max) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;    /* physical extent map: ext2 only (M1152) */
    return ext2_fiemap(mount_rfn(i), mount_ctx(i), g_mount[i].start, path ? path : "", out, max);
}

long blockdev_mount_punch(int i, const char *path, uint64_t offset, uint64_t len) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    if (g_mount[i].fstype != FS_EXT2) return -1;    /* hole punching: ext2 only (M1153) */
    return ext2_punch_hole(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                           path ? path : "", offset, len);
}

/* Extended attributes on mount `i` (ext2 only, user.* namespace). M1182. */
long blockdev_mount_setxattr(int i, const char *path, const char *name, const void *val, unsigned long vlen) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount || g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_setxattr(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                         path ? path : "", name ? name : "", val, vlen);
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
long blockdev_mount_removexattr(int i, const char *path, const char *name) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount || g_mount[i].fstype != FS_EXT2) return -1;
    return ext2_removexattr(mount_rfn(i), mount_wfn(i), mount_ctx(i), g_mount[i].start,
                            path ? path : "", name ? name : "");
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
int blockdev_mount_stat(int i, const char *path, uint32_t *out_size, int *out_isdir) {
    blockdev_mount_scan();
    if (i < 0 || i >= g_nmount) return -1;
    blk_read_fn r = mount_rfn(i); void *c = mount_ctx(i); uint64_t s = g_mount[i].start;
    return g_mount[i].fstype == FS_EXT2    ? ext2_stat_path(r, c, s, path ? path : "", out_size, out_isdir)
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
    int ndev = blockdev_init();
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
            fatvol_dirent ents[32];
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
        fatvol_dirent ents[32];
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
    int ndev = blockdev_init();
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
            fatvol_dirent ents[32];
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
