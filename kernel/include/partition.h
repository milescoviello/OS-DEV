/*
 * partition.h — parse MBR and GPT partition tables on an ATA drive.
 *
 * A drive's first sector (LBA 0) either holds a bare filesystem (no partition
 * table — our boot disk is like this) or a partition table that carves the
 * drive into volumes. We support both classic schemes:
 *
 *   MBR  — a 0x55AA signature at offset 510 and four 16-byte primary entries at
 *          offset 0x1BE. Each entry has a type byte, a 32-bit start-LBA and a
 *          32-bit sector count.
 *   GPT  — modern, unbounded. The MBR is then "protective" (one type-0xEE entry
 *          covering the disk); the real table is a GPT header at LBA 1 ("EFI
 *          PART") pointing at an array of 128-byte entries, each with a type
 *          GUID and 64-bit first/last LBA.
 *
 * partition_scan() reads the table on a drive and returns each non-empty
 * partition as a (drive, start-LBA, sector-count, type) tuple, every field
 * validated against the drive's reported size. It never writes the disk.
 */
#pragma once
#include <stdint.h>

/* How a partition table was encoded (for logging / callers that care). */
#define PART_SCHEME_NONE 0   /* no recognizable table at LBA 0 */
#define PART_SCHEME_MBR  1
#define PART_SCHEME_GPT  2

/* One discovered partition. `type` is the MBR type byte (e.g. 0x0C = FAT32 LBA)
 * for MBR partitions, or PART_TYPE_GPT for a GPT partition (whose real type is a
 * 16-byte GUID, not a single byte). */
#define PART_TYPE_GPT 0xEE   /* also the protective-MBR type byte that signals GPT */

typedef struct {
    int      drive;          /* ATA drive index 0..3 this partition lives on */
    uint64_t start_lba;      /* first sector of the partition */
    uint64_t sectors;        /* partition length in sectors */
    int      type;           /* MBR type byte, or PART_TYPE_GPT for a GPT entry */
    int      scheme;         /* PART_SCHEME_MBR / PART_SCHEME_GPT */
} partition_t;

/* Cap on partitions returned, so a malformed/huge GPT can never make us read or
 * emit an unbounded array. Callers pass their own `max` too; the smaller wins. */
#define PART_MAX 64

/* Scan drive `drive`'s partition table into `out` (up to `max` entries).
 * Returns the number of partitions found (>=0), or -1 if the drive is absent or
 * unreadable. A drive with no table (bare filesystem) returns 0 — not an error.
 * Every emitted partition is bounds-checked: start_lba + sectors fits within the
 * drive's reported sector count, and we never read past a sector buffer. */
int partition_scan(int drive, partition_t *out, int max);

/* Detect the scheme at LBA 0 without enumerating (PART_SCHEME_*). */
int partition_scheme(int drive);

/* Read-only FAT32 probe at a partition's start-LBA on any drive: validate the
 * BPB is FAT32, then find an 8.3 file (`name83`, 11 bytes, space-padded) in the
 * root directory. Returns 1 + sets *out_size if found; 0 otherwise. This proves
 * a partition's filesystem is readable from its offset, without touching the
 * boot-disk FAT32 mount's global state. (A thin wrapper over fatvol_find() below
 * using an ATA read callback — kept so existing ATA callers are unchanged.) */
int partition_fat32_find(int drive, uint64_t start_lba, const char name83[11],
                         uint32_t *out_size);

/* --- generic, device-agnostic read-only FAT32 walk --------------------------
 *
 * The self-contained FAT32 reader generalized to read through a caller-supplied
 * block-read callback instead of a hardwired ata_read_drive(), so the SAME
 * read-only walk works over ANY storage driver (ATA, AHCI, virtio-blk, NVMe, USB
 * mass-storage) via kernel/blockdev.c. It never touches the boot-disk fat32.c /
 * vfs.c mount state. Every field of the on-disk BPB/FAT is treated as untrusted:
 * validated before use, every sector read targets a fixed 512-byte buffer, and
 * the cluster-chain walk is bounded by the computed cluster count + a cycle guard.
 *
 * The callback reads `count` 512-byte sectors starting at absolute LBA `lba`
 * (NOT relative to the volume) into `buf`; returns 0 on success, <0 on error.
 * `ctx` is the caller's opaque handle (e.g. a block-device index). */
typedef int (*blk_read_fn)(void *ctx, uint64_t lba, uint32_t count, void *buf);
/* The write counterpart (M1132): persist `count` sectors at `lba` from `buf`. */
typedef int (*blk_write_fn)(void *ctx, uint64_t lba, uint32_t count, const void *buf);

/* One directory entry returned by fatvol_list() / ext2_list_path(). FAT fills
 * only an 8.3 "NAME.EXT" (<=12), but ext2 supports long names, so `name` is 32
 * (31 usable + NUL) -- widened from 13 (M1746) to stop ext2 listings truncating
 * to 12. It now carries ext2's full 255-byte limit; see the field comment for
 * why the old stack-size argument for keeping it short was the wrong trade. */
typedef struct {
    /* 32 -> 256 (M2062). Every directory listing in the kernel came through
     * this struct, so every listing TRUNCATED AT 31 CHARACTERS -- and a
     * truncated name is not a cosmetic problem, it is a name that does not
     * exist. `find /root/.claude` inside OS-DEV said it plainly:
     *
     *   find: '/root/.claude/backups/.claude.json.backup.17894368240':
     *         No such file or directory
     *   find: '/root/.claude/sessions/101.e6a4c69b6e4f03ca50222125240':
     *         No such file or directory
     *
     * -- both exactly 31 characters, both real files with longer names. A
     * program that writes a file, lists the directory and then acts on what it
     * read gets ENOENT for its own data. Claude Code names its session keys
     * with a 64-hex-character hash and its config backups with a millisecond
     * timestamp, so nearly everything it owns was invisible to it.
     *
     * The old comment reasoned this was safe because the struct is used in
     * [64] arrays on a 16 KB kernel stack. That reasoning was sound and the
     * conclusion was wrong: the answer is to move the arrays to the heap, not
     * to hand back the wrong filename. Every such array is now allocated. */
    char     name[256];  /* file name + NUL (ext2's own limit is 255; FAT 8.3 <= 12) */
    uint32_t size;       /* file size in bytes (0 for directories) */
    int      is_dir;     /* 1 if a subdirectory, else 0 */
} fatvol_dirent;

/* One physical extent of a file: a maximal run of contiguous on-disk blocks.
 * All three fields are BYTE offsets/lengths. Backs FIEMAP (M1152). Lives here in
 * the base block-layer header so ext2.h + blockdev.h both see it without a cycle. */
typedef struct { uint64_t logical, physical, length; } ext2_extent_t;

/* Validate that the FAT32 volume whose boot sector is at absolute LBA `start_lba`
 * (read via `read`/`ctx`) is FAT32, then find an 8.3 file (`name83`, 11 bytes,
 * space-padded) in its root directory. Returns 1 + sets *out_size if found; 0 if
 * not FAT32, unreadable, or absent. Device-agnostic counterpart of
 * partition_fat32_find(). */
int fatvol_find(blk_read_fn read, void *ctx, uint64_t start_lba,
                const char name83[11], uint32_t *out_size);

/* List the root directory of the FAT32 volume at absolute LBA `start_lba` (read
 * via `read`/`ctx`) into `out` (up to `max` entries). Returns the number of
 * entries written (>=0), or 0 if the volume is not FAT32 / unreadable. Skips LFN,
 * volume-label, deleted and "."/".." entries. The scan is bounded by the volume's
 * cluster count + a cycle guard and the output is capped at `max`. */
int fatvol_list(blk_read_fn read, void *ctx, uint64_t start_lba,
                fatvol_dirent *out, int max);

/* Read the 8.3 file `name83` (11 bytes, space-padded) from the FAT32 volume at
 * `start_lba` into `buf` (<= max bytes). Returns bytes read, or -1. Read-only,
 * device-agnostic, bounded — the counterpart of fatvol_list for file contents. */
long fatvol_read(blk_read_fn read, void *ctx, uint64_t start_lba,
                 const char name83[11], void *buf, unsigned long max);

/* Subdirectory-aware variants (M1070): `path` is a '/'-separated path relative
 * to the volume root (empty = root), descending into subdirectories. */
int  fatvol_list_path(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path,
                      fatvol_dirent *out, int max);
long fatvol_read_path(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path,
                      void *buf, unsigned long max);
int  fatvol_isdir_path(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path);
int  fatvol_stat_path(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path, uint32_t *out_size, int *out_isdir);  /* 0/-1 (M1624) */

/* Probe all four ATA drives and log each present drive + its partition table
 * (scheme, and per-partition drive/type/start/size). The headless self-test. */
void partition_enumerate(void);
