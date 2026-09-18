/*
 * blockdev.h — a generic block-device registry over every storage driver.
 *
 * Each storage driver in this kernel (ATA/IDE, AHCI/SATA, virtio-blk, NVMe, USB
 * mass-storage) self-tests its own raw sectors at boot, but each exposes a
 * different read signature, so kernel/partition.c's read-only FAT32 walk was
 * wired to ATA alone. This layer abstracts them behind ONE uniform read
 * interface so that walk (now fatvol_find/fatvol_list in partition.c) — and any
 * future read-only consumer — works over EVERY disk, not just the ATA boot disk.
 *
 * A block device is a tiny vtable: { name, read(ctx,lba,count,buf), sectors, ctx }.
 * blockdev_init() registers each PRESENT storage device, wrapping that driver's
 * read function; blockdev_enumerate() then reads LBA 0 of each and, if it finds a
 * FAT32 volume (bare, or inside an MBR/GPT partition), MOUNTS it read-only and
 * LISTS its root directory — proving every driver's disk is browsable.
 *
 * This is purely ADDITIVE and READ-ONLY: it never writes a disk, never touches
 * the boot FAT32 mount (kernel/fat32.c / kernel/vfs.c) or its global state, and a
 * device's read() returning an error makes that volume be skipped cleanly. The
 * boot disk's bare-FAT32 mount in kmain (ATA primary master, LBA 0) is unchanged.
 */
#pragma once
#include <stdint.h>
#include "partition.h"   /* fatvol_dirent + ext2_extent_t, for the mount registry below */

#define BLOCKDEV_SECSZ   512   /* every registered device speaks 512-byte sectors */
#define BLOCKDEV_MAX     8     /* cap on registered devices (4 ATA + 4 others)    */

/* One registered block device. `read` reads `count` 512-byte sectors at absolute
 * LBA `lba` into `buf` (>= count*512 bytes), returning 0 on success / <0 on error;
 * `ctx` is the driver-specific handle it was registered with (e.g. an ATA drive
 * index or an AHCI disk index). `sectors` is the device capacity in 512-byte
 * sectors, or 0 if the driver does not report one (then LBAs aren't range-checked
 * here — the read function still bounds them, and the FAT walk stays bounded). */
typedef struct {
    const char *name;
    int       (*read)(void *ctx, uint64_t lba, uint32_t count, void *buf);
    int       (*write)(void *ctx, uint64_t lba, uint32_t count, const void *buf);  /* NULL = read-only */
    uint64_t    sectors;
    void       *ctx;
    /* Cumulative I/O counters since boot, tallied in blockdev_read/blockdev_write,
     * surfaced by /proc/diskstats (M1256). "ios" = read/write calls; "sectors" =
     * 512-byte sectors transferred. */
    uint64_t    rd_ios, rd_sectors, wr_ios, wr_sectors;
} blockdev_t;

/* Register every PRESENT storage device (ATA drives 0..3, the AHCI disk, virtio-
 * blk, NVMe, USB mass-storage) into the registry, wrapping each driver's read.
 * Idempotent: rebuilds the registry from scratch each call. Call AFTER the
 * storage drivers have been brought up (ata_identify_all / ahci_init / etc.).
 * Returns the number of devices registered. */
int blockdev_init(void);

/* Number of registered block devices (0 until blockdev_init() runs). */
int blockdev_count(void);

/* The i-th registered block device (0..blockdev_count()-1), or NULL if `i` is out
 * of range. */
blockdev_t *blockdev_get(int i);

/* Read `count` 512-byte sectors at absolute LBA `lba` from device `i` into `buf`.
 * Returns 0 on success, -1 on a bad index / unregistered device / driver error /
 * (where the capacity is known) an out-of-range request. */
int blockdev_read(int i, uint64_t lba, uint32_t count, void *buf);
void blockdev_drop_cache(int i, uint64_t lba, uint32_t count);   /* drop a range from whichever cache holds it (M2220) */
void blockdev_drop_mount_caches(int midx);   /* drop EVERYTHING cached for that mount's device (M2223) */
int  blockdev_ready(void);      /* the table as it stands; probes only if nothing ever has (M2231) */

/* Write `count` 512-byte sectors at absolute LBA `lba` to device `i` from `buf`.
 * Returns 0 on success, -1 on a bad index / read-only (no write fn) device /
 * driver error / out-of-range request. Write-through: the buffer cache (below)
 * is kept coherent so a subsequent blockdev_read sees the new bytes. The boot
 * FAT32 volume is read by kernel/fat32.c directly via ATA, NOT through this
 * layer, so this write path cannot corrupt it. */
int blockdev_write(int i, uint64_t lba, uint32_t count, const void *buf);

/* Format the buffer-cache statistics (entries, hits, misses, writes, hit rate)
 * into `out` (capacity `max`) as text lines; returns the byte length. Backs the
 * /proc/bcache file. */
int blockdev_cache_format(char *out, int max);

/* Boot self-test of the write path + buffer-cache coherence/durability, on the
 * first writable NON-boot device (skips "ata*" so the boot disk is never
 * written; restores the sector it touches). Logged to dmesg. Call after
 * blockdev_enumerate. A clean no-op if no safe writable device is present. */
void blockdev_selftest(void);

/* The headless browsing demo: bring up the registry (blockdev_init), then for
 * EACH registered device read LBA 0 and — if it is a bare FAT32 volume OR has an
 * MBR/GPT partition table carrying FAT32 partitions — MOUNT each FAT32 volume
 * read-only and LIST its root directory, logging the device name, the volume's
 * start-LBA, and each entry's name + size. Read-only; never touches the boot
 * mount. Call from kmain near partition_enumerate(). */
void blockdev_enumerate(void);

/* Format the block-device + FAT32-volume browse (same content as
 * blockdev_enumerate) into the caller's buffer `out` (capacity `max`), as text
 * lines. Returns the byte length written (NUL-terminated). Backs the userspace
 * `lsblk` shell command (SYS_lsblk). Read-only. */
int blockdev_format(char *out, int max);

/* --- read-only mount registry (M1061): every FAT32 volume found across all
 *     block devices, exposed to the VFS as /disk1, /disk2, ... so any disk's
 *     files are browsable, not just the boot volume. Lazily scanned. --- */
int  blockdev_mount_count(void);                 /* number of mountable FAT32 volumes */
const char *blockdev_mount_name(int i);          /* "disk1".."disk8", or NULL */
int  blockdev_mount_index(const char *name);     /* "disk2" -> index, else -1 */
/* Subdirectory-aware (M1070): `subpath`/`path` is relative to the volume root
 * ("" or NULL = root), so a mounted disk can be browsed in full, not just its
 * root. blockdev_mount_isdir backs `cd` validation. */
int  blockdev_mount_list(int i, const char *subpath, fatvol_dirent *out, int max); /* list dir at subpath */
long blockdev_mount_read(int i, const char *path, void *buf, unsigned long max);   /* read file at path */
long blockdev_mount_pread(int i, const char *path, void *buf, unsigned long max, unsigned long offset);  /* positioned read (M1196) */
long blockdev_mount_write(int i, const char *path, const void *buf, unsigned long len);  /* create/overwrite a file (ext2 only); M1132/M1135 */
long blockdev_mount_pwrite(int i, const char *path, const void *buf, unsigned long len, uint64_t off);  /* positioned/streaming write (ext2 only); M1935 */
long blockdev_mount_remove(int i, const char *path);   /* delete a file (ext2 only); 0/-1 (M1135) */
long blockdev_mount_mkdir(int i, const char *path);    /* create a directory (ext2 only); 0/-1 (M1137) */
long blockdev_mount_symlink(int i, const char *path, const char *target);  /* create a symlink (ext2 only); 0/-1 (M1146) */
long blockdev_mount_readlink(int i, const char *path, void *buf, unsigned long max);  /* read a symlink's target (ext2 only), not followed; bytes/-1 (M1594) */
long blockdev_mount_link(int i, const char *oldpath, const char *newpath); /* hard link (ext2 only); 0/-1 (M1207) */
long blockdev_mount_rename(int i, const char *oldpath, const char *newpath); /* rename/move (ext2 only); 0/-1 (M1213) */
long blockdev_mount_rename2(int i, const char *oldpath, const char *newpath, int flags); /* renameat2 NOREPLACE/EXCHANGE (M1232) */
long blockdev_mount_truncate(int i, const char *path, uint64_t newlen);      /* resize (ext2 only); 0/-1 (M1228) */
long blockdev_mount_seek_data_hole(int i, const char *path, long off, int find_hole); /* SEEK_HOLE/DATA; off/-1/-2 not-ext2 (M1229) */
long blockdev_mount_utimes(int i, const char *path, long atime, long mtime);  /* set mtime/atime (ext2 only); 0/-1 (M1230) */
long blockdev_mount_chmod(int i, const char *path, uint32_t mode);            /* set perm bits (ext2 only); 0/-1 (M1241) */
long blockdev_mount_chown(int i, const char *path, long uid, long gid);       /* set uid/gid (ext2 only); 0/-1 (M1243) */
int  blockdev_mount_fiemap(int i, const char *path, ext2_extent_t *out, int max);  /* file physical extent map (ext2 only); count/-1 (M1152) */
long blockdev_mount_punch(int i, const char *path, uint64_t offset, uint64_t len);  /* fallocate PUNCH_HOLE (ext2 only); blocks/-1 (M1153) */
long blockdev_mount_setxattr(int i, const char *path, const char *name, const void *val, unsigned long vlen);  /* set user.* xattr (ext2 only); vlen/-1 (M1182) */
long blockdev_mount_getxattr(int i, const char *path, const char *name, void *out, unsigned long max);  /* get user.* xattr (ext2 only); size/-1 (M1182) */
long blockdev_mount_listxattr(int i, const char *path, char *out, unsigned long max);  /* NUL-sep xattr names (ext2 only); total/-1 (M1182) */
long blockdev_mount_removexattr(int i, const char *path, const char *name);  /* remove a user.* xattr (ext2 only); 0/-1 (M1182) */
int  blockdev_mount_isdir(int i, const char *path);   /* is path a directory on mount i? */
int  blockdev_mount_stat(int i, const char *path, uint32_t *out_size, int *out_isdir, uint32_t *out_ino, uint32_t *out_mtime, uint32_t *out_nlink, uint32_t *out_mode);  /* size + isdir + inode + mtime/nlink/mode on mount i (0 = this fs has none); 0/-1 (M1624, ino M1955, times M1999) */
int  blockdev_mounts_format(char *out, int max);  /* list the mounts as text (the `mount` command) */
/* losetup (M1107): register a loop mount backed by the RAM image `data` (len
 * bytes; ownership transferred). Detects FAT32/ext2 and mounts it as the next
 * /diskN. Returns the mount index, or -1. */
int  blockdev_losetup(uint8_t *data, uint64_t len);
