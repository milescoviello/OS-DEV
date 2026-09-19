/*
 * ext2.c — read-only ext2. See ext2.h. Superblock @ byte 1024; block-group
 * descriptors after it; an inode's 15 i_block pointers give direct (0-11),
 * single-indirect (12) and double-indirect (13) data blocks; directories are a
 * chain of {inode, rec_len, name_len, file_type, name} records. Root = inode 2.
 * Standard layouts (inode_size 128/256, block_size 1024-4096) only.
 */
#include "ext2.h"
#include "string.h"
#include <stdint.h>

#define EXT2_MAGIC    0xEF53
#define EXT2_ROOT_INO 2
#define SECSZ         512

static uint16_t e_rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t e_rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void e_wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void e_wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

/* Clock hook for inode timestamps (M1175). A function pointer (NOT a direct
 * rtc_unix call) so ext2.c stays self-contained + host-#include-linkable — the
 * kernel wires ext2_set_clock(rtc_unix) at boot; a host test that doesn't sets
 * nothing, so timestamps are 0 (the historical behaviour). */
static uint32_t (*ext2_clock)(void);
void ext2_set_clock(uint32_t (*fn)(void)) { ext2_clock = fn; }
static void e_stamp(uint8_t *inode) {                  /* set i_atime/i_ctime/i_mtime to "now" */
    uint32_t t = ext2_clock ? ext2_clock() : 0;
    e_wr32(inode + 8, t); e_wr32(inode + 12, t); e_wr32(inode + 16, t);
}

typedef struct {
    blk_read_fn read; blk_write_fn write; void *ctx; uint64_t start;
    uint32_t block_size, inodes_per_group, inode_size, gdt_block;
    uint32_t blocks_per_group, first_data_block, first_ino, blocks_count, groups;   /* for allocation (M1132) */
    uint32_t feat_incompat;          /* s_feature_incompat; bit 0x40 = `extent` (M1189) */
    /* A FAILED BLOCK READ IS NOT A MISSING FILE (M2155).
     *
     * `walk_d` returns 0 both when a path component is genuinely absent and
     * when the READ of the directory or inode block failed, and `walk_cached`
     * then wrote that 0 into the table as a NEGATIVE entry -- so one transient
     * device error made a shared library permanently "not there" for the rest
     * of the boot, and no retry could recover because the retry hit the cache.
     * That is what zeroed an executable page of libxul under eight cores, and
     * it is the dominant bug class in this project wearing yet another hat: a
     * mechanism answering with a plausible WRONG VALUE instead of failing.
     *
     * `ext2_t` is stack-allocated per call, so a flag in it is per-call state
     * and needs no lock. Set by rdblk/rdblks; read by walk_cached (which then
     * refuses to cache anything) and by ext2_pread (which reports it). */
    int ioerr;
} ext2_t;

/* read ext2 block `blk` (block_size bytes) into buf (>= block_size) */
/* THE VOLUME'S START LBA, BECAUSE THE ARITHMETIC POINTS AT IT (M2167).
 *
 * A refused read reported `lba 18962972664 count 8 cap 6553600`. The block
 * pointer had already PASSED the blocks_count check, so blk < 819200, so
 * blk * 8 < 6553600 -- inside the disk. An LBA of 18.9 billion can therefore
 * only come from `v->start`, the volume's start sector, which for /disk2 is
 * supposed to be 0. So record it and make it visible: `start + blk * spb` has
 * two operands and only one of them had ever been printed. */
uint64_t g_e2_vstart;
static uint32_t e2_ptr_ok(ext2_t *v, uint32_t blk, int level);   /* M2176; defined below */
/* Group descriptors that could not be believed (M2174). An inode table pointer
 * off the end of the filesystem means the descriptor block we read was not a
 * descriptor block, and every inode in that group would come back as data. */
unsigned long g_e2_bad_itable, g_e2_bad_groups;
/* THE RE-READ EXPERIMENT (M2219): how often a rejected inode-table pointer
 * reads back DIFFERENTLY, and how often the second read is valid. A difference
 * means the storage path handed back bytes that were not the sector asked for;
 * agreement means the block number itself was wrong. */
unsigned long g_e2_itable_reread, g_e2_itable_differed, g_e2_itable_secondgood;
unsigned int  g_e2_bad_itable_2nd;
/* EVERY REASON THIS VOLUME COULD NOT BE BELIEVED, IN ONE COUNTER (M2213).
 *
 * A caller that has just had -1 out of a read needs to know whether the answer
 * was "that path does not exist" or "the device/metadata failed", and the
 * DIFFERENCE decides whether zero-filling a page is correct or is corruption
 * (see app.c's unlinked-mapping case, M2160). `g_e2_pread_why` almost says it,
 * but it is a per-call code that goes stale the moment the mapping is on tmpfs
 * or /proc instead -- and a stale 4 there would refuse a legitimate
 * zero-fill, which is the regression M2160 exists to undo.
 *
 * A monotonic EVENT COUNT cannot go stale: sample it before the read and after,
 * and a value that moved means something in this transport distrusted itself
 * during THIS read, whatever transport it was. */
unsigned long g_e2_distrust;
/* Blocks served as a sparse HOLE (M2221). Legitimate for a sparse file and
 * indistinguishable, from inside ext2, from an inode whose block pointer was
 * read as zero -- so the count is exported and the caller decides. */
unsigned long g_e2_holes;
unsigned long ext2_hole_events(void) { return g_e2_holes; }
unsigned long ext2_distrust_events(void) { return g_e2_distrust; }
unsigned int  g_e2_bad_itable_val;

static int rdblk(ext2_t *v, uint32_t blk, uint8_t *buf) {
    uint32_t spb = v->block_size / SECSZ;
    int r = v->read(v->ctx, v->start + (uint64_t)blk * spb, spb, buf);
    if (r < 0) { v->ioerr = 1; g_e2_distrust++; g_e2_vstart = v->start; }   /* see ext2_t.ioerr (M2155) */
    return r;
}
/* ONE SECTOR OF A BLOCK, for the two reads that need 32 and 256 bytes (M2212).
 *
 * THE BUG THIS EXISTS FOR. `read_inode` declared TWO 4096-byte buffers -- one
 * for the group-descriptor block and one for the inode-table block -- and
 * -fstack-usage puts the function at 8240 bytes. The kernel stack is 16384.
 * The fault path to a file read is
 *
 *   app_fault_handle 64 + _inner 960 + vfs_pread 592 + ext2_pread 4528
 *   + walk_d 416 + read_inode 8240  =  ~14800 of 16384  (90%)
 *
 * and M2163 deliberately enables interrupts across that read so the ATA
 * deadline can expire -- so an interrupt arriving at the deepest point pushes
 * its own frame and its handler's onto the same stack. What comes out is
 * exactly the 8-core crash: 204 inode-table pointers rejected in one boot, a
 * block pointer off the end of the filesystem, an LBA of 15088200464 against a
 * 6553600-sector device -- garbage in a LOCAL buffer, which is what a stack
 * that has been written past looks like from inside.
 *
 * Neither read needs a block. A group descriptor is 32 bytes and an inode is
 * 128 or 256; both divide 512, so each lies wholly inside one sector. Reading
 * the sector instead of the block takes read_inode from 8240 bytes of stack to
 * about 700, and asks the disk for 512 bytes instead of 4096 while it is at it.
 *
 * `secoff` is the sector index WITHIN the block. */
static int rdsec(ext2_t *v, uint32_t blk, uint32_t secoff, uint8_t *buf) {
    uint32_t spb = v->block_size / SECSZ;
    if (secoff >= spb) return -1;
    int r = v->read(v->ctx, v->start + (uint64_t)blk * spb + secoff, 1, buf);
    if (r < 0) { v->ioerr = 1; g_e2_distrust++; g_e2_vstart = v->start; }   /* see ext2_t.ioerr (M2155) */
    return r;
}
/* `n` PHYSICALLY CONSECUTIVE blocks in one request (M2101).
 *
 * Measured under KVM, so this is about the kernel and not about emulation:
 * Firefox's first paint issued 128750 block-device commands to move 998396
 * sectors -- 7.8 sectors each, which is one 4 KiB ext2 block. The driver can
 * do 128 sectors per DMA transfer since this milestone, and blockdev_read
 * stopped shredding in M2092, so the remaining 4 KiB granularity was entirely
 * ext2_pread asking for one block at a time.
 *
 * Every one of those commands takes the GLOBAL ata_lock, which is why 8 fast
 * KVM cores did not help: the disk work cannot overlap, so the boot serialises
 * on a lock held 128750 times. Coalescing a run is worth a factor on the lock
 * traffic as much as on the transfers. */
static int rdblks(ext2_t *v, uint32_t blk, uint32_t n, uint8_t *buf) {
    uint32_t spb = v->block_size / SECSZ;
    int r = v->read(v->ctx, v->start + (uint64_t)blk * spb, n * spb, buf);
    if (r < 0) { v->ioerr = 1; g_e2_distrust++; g_e2_vstart = v->start; }
    return r;
}
/* How many blocks a single request may cover: the block device's own transfer
 * ceiling, in blocks. Asking for more than it can do in one go makes it split
 * the request anyway -- or, worse, fall back off its fast path. */
#define EXT2_MAX_RUN 16u

/* parse + validate the superblock; 0 on a supported ext2, -1 otherwise */
/* DROP A RANGE FROM THE BLOCK CACHE, if the kernel wired one (M2220).
 *
 * Same shape as ext2_set_clock: a function pointer, so ext2.c stays
 * self-contained and host-#include-linkable. The kernel points it at
 * blockdev_drop_cache, which knows which owner key this transport uses; a host
 * test sets nothing and the retry below simply re-reads. */
static void (*ext2_dropc)(void *ctx, uint64_t lba, uint32_t n);
void ext2_set_cache_drop(void (*fn)(void *, uint64_t, uint32_t)) { ext2_dropc = fn; }

/* WHY THE SUPERBLOCK WAS NOT BELIEVED (M2220). Every one of these used to be a
 * bare `return -1` with no ioerr and no counter, so the fault handler's
 * distrust guard (M2213) could not see them and zero-filled a page of libxul
 * instead -- which is how "the ext2 SUPERBLOCK could not be read" ends up
 * presenting as a SIGSEGV at a rip full of zeros. */
unsigned long g_e2_sb_readfail, g_e2_sb_badmagic, g_e2_sb_badfield;
unsigned long g_e2_sb_retried, g_e2_sb_retry_ok;
unsigned int  g_e2_sb_sawmagic;

static int ext2_open(blk_read_fn read, void *ctx, uint64_t start, ext2_t *v) {
    uint8_t sb[1024];
    v->ioerr = 0;
    if (read(ctx, start + 2, 2, sb) < 0) {                 /* superblock: byte 1024 = LBA+2 */
        v->ioerr = 1; g_e2_sb_readfail++; g_e2_distrust++; return -1;
    }
    if (e_rd16(sb + 56) != EXT2_MAGIC) {
        /* THE BYTES ARE NOT THIS SECTOR'S. Drop the two sectors from whatever
         * cache holds them and read once more: if the second read is good, the
         * cache was serving another sector's bytes and this both proves it and
         * repairs it. If it is still wrong, the bytes came off the wire that
         * way. Either answer is worth far more than the silent `return -1`
         * this replaced -- and on eight cores this fires often enough to kill
         * Firefox two boots in three. */
        g_e2_sb_badmagic++;
        g_e2_sb_sawmagic = e_rd16(sb + 56);
        if (ext2_dropc) {
            ext2_dropc(ctx, start + 2, 2);
            g_e2_sb_retried++;
            if (read(ctx, start + 2, 2, sb) >= 0 && e_rd16(sb + 56) == EXT2_MAGIC) {
                g_e2_sb_retry_ok++;                        /* the CACHE was wrong, and is now right */
                goto magic_ok;
            }
        }
        v->ioerr = 1; g_e2_distrust++;
        return -1;
    }
  magic_ok:;
    uint32_t logbs = e_rd32(sb + 24);
    if (logbs > 2) { v->ioerr = 1; g_e2_sb_badfield++; g_e2_distrust++; return -1; }   /* only 1024/2048/4096 */
    v->read = read; v->write = 0; v->ctx = ctx; v->start = start;
    v->block_size = 1024u << logbs;
    v->inodes_per_group = e_rd32(sb + 40);
    uint32_t rev = e_rd32(sb + 76);
    v->inode_size = (rev >= 1) ? e_rd16(sb + 88) : 128;
    if (!v->inodes_per_group || v->inode_size < 128 || v->inode_size > 256) {
        v->ioerr = 1; g_e2_sb_badfield++; g_e2_distrust++; return -1; }
    v->gdt_block = (v->block_size == 1024) ? 2 : 1;        /* GDT follows the superblock's block */
    v->blocks_per_group = e_rd32(sb + 32);
    v->first_data_block = e_rd32(sb + 20);
    v->blocks_count     = e_rd32(sb + 4);
    v->first_ino        = (rev >= 1) ? e_rd32(sb + 84) : 11;
    v->feat_incompat    = (rev >= 1) ? e_rd32(sb + 96) : 0;   /* `extent`=0x40, for extent writes (M1189) */
    if (!v->blocks_per_group || v->blocks_count <= v->first_data_block) {
        v->ioerr = 1; g_e2_sb_badfield++; g_e2_distrust++; return -1; }
    v->groups = (v->blocks_count - v->first_data_block + v->blocks_per_group - 1) / v->blocks_per_group;
    return 0;
}

/* read inode `ino` (1-based) into out (>= inode_size bytes); 0/-1 */
/* VALIDATE THE INODE TABLE POINTER, ONE LEVEL UP (M2174).
 *
 * M2158 rejected a block pointer past the end of the filesystem and that was
 * right, but it was applied one level too low. The instrument then reported
 * **8999698 rejected pointers at indirect level 0** in a single run, with the
 * last value 1768685824 -- which is ASCII bytes, not a block number. Level 0 is
 * a DIRECT pointer read straight out of an inode, so the inode itself was file
 * data: `read_inode` had taken `inode_table` out of a group descriptor and
 * never checked it, so one bad descriptor read makes every inode in that group
 * come back as whatever data block the arithmetic lands on. Nine million wrong
 * pointers from one wrong read, and each of them merely "rejected" downstream
 * where the cause is invisible.
 *
 * So check it where the value is produced. An inode table that cannot be on
 * the filesystem is corruption, not a hole -- `ioerr`, and the read fails
 * honestly instead of walking data. */
static int read_inode(ext2_t *v, uint32_t ino, uint8_t *out) {
    if (ino == 0) return -1;
    uint32_t group = (ino - 1) / v->inodes_per_group;
    uint32_t index = (ino - 1) % v->inodes_per_group;
    /* ONE SECTOR EACH, NOT ONE BLOCK EACH (M2212) -- see rdsec. Two 4096-byte
     * buffers here put this function at 8240 bytes of a 16384-byte kernel
     * stack, on a path that reaches it at 90% full with interrupts enabled. */
    uint8_t sec[SECSZ];
    uint32_t gd_per_block = v->block_size / 32;
    if (v->groups && group >= v->groups) { v->ioerr = 1; g_e2_bad_groups++; g_e2_distrust++; return -1; }
    /* The descriptor block itself is a produced block number too (M2176). */
    uint32_t gdblk = v->gdt_block + group / gd_per_block;
    if (!e2_ptr_ok(v, gdblk, 5)) { v->ioerr = 1; return -1; }
    {   uint32_t gdbyte = (group % gd_per_block) * 32;      /* byte offset in the block */
        if (rdsec(v, gdblk, gdbyte / SECSZ, sec) < 0) return -1;
        uint32_t inode_table = e_rd32(sec + (gdbyte % SECSZ) + 8);
        if (!inode_table || (v->blocks_count && inode_table >= v->blocks_count)) {
            /* READ IT AGAIN, AND SAY WHETHER THE ANSWER CHANGES (M2219).
             *
             * This fires 88-204 times per boot on EIGHT cores and NEVER on
             * one, so it is a concurrency bug -- but every layer under it is
             * already serialised: ata_lock covers the whole transfer including
             * DMA, and bcache copies in and out under its own lock. "Which
             * layer corrupts it" has run out of suspects and needs an
             * experiment rather than another theory.
             *
             * A second read of the SAME sector separates the two cases.
             * DIFFERENT answer => the first read returned bytes that were not
             * this sector's, and the fault is in the storage path. SAME answer
             * => the bytes really are what we asked for and the block number
             * we computed is wrong, which points at the volume struct or the
             * arithmetic, not at the disk.
             *
             * On the failure path only: one extra sector read per rejection,
             * and a rejection is already a disaster. */
            /* DROP THE CACHE FIRST (M2232). The first cut of this re-read
             * went through the SAME block cache, so a poisoned entry gives
             * the same bytes twice and "0 DIFFERED" proves nothing -- it
             * cannot tell "the disk really holds this" from "the cache
             * remembers something else". Two boots reported exactly that: 168
             * re-reads, 0 differed. Dropping the two sectors first makes the
             * second read go to the disk, which is the comparison the
             * experiment was supposed to be making.
             *
             * (The superblock path has done this since M2220; this one was
             * written first and never caught up.) */
            uint8_t again[SECSZ];
            uint32_t second = 0;
            if (ext2_dropc) ext2_dropc(v->ctx, v->start + (uint64_t)gdblk * (v->block_size / SECSZ)
                                                + gdbyte / SECSZ, 1);
            int rr = rdsec(v, gdblk, gdbyte / SECSZ, again);
            if (rr >= 0) second = e_rd32(again + (gdbyte % SECSZ) + 8);
            g_e2_itable_reread++;
            if (rr >= 0 && second != inode_table) g_e2_itable_differed++;
            if (rr >= 0 && second && (!v->blocks_count || second < v->blocks_count))
                g_e2_itable_secondgood++;
            g_e2_bad_itable_2nd = second;
            v->ioerr = 1;
            g_e2_bad_itable++;
            /* AND IT COUNTS AS DISTRUST (M2219). M2213 added that counter so
             * the fault handler could tell "this path does not exist" from
             * "the filesystem does not believe itself" before zero-filling a
             * page -- and this site, the one that actually fires, was the one
             * it missed: the edit landed on the pre-M2212 text. Every crashing
             * 8-core boot therefore reported `refused=0` while rejecting
             * eighty-eight inode tables. */
            g_e2_distrust++;
            g_e2_bad_itable_val = inode_table;
            return -1;
        }
        uint64_t byte_off = (uint64_t)index * v->inode_size;
        uint32_t off = (uint32_t)(byte_off % v->block_size);
        if (off + v->inode_size > v->block_size) return -1;  /* straddles a block (non-standard) */
        /* An inode is 128 or 256 bytes and both divide 512, so it cannot cross
         * a sector boundary either -- but say so rather than assume it, because
         * a filesystem with a 512-byte inode_size would silently read half. */
        if ((off % SECSZ) + v->inode_size > SECSZ) return -1;
        if (rdsec(v, inode_table + (uint32_t)(byte_off / v->block_size),
                  off / SECSZ, sec) < 0) return -1;
        uint32_t so = off % SECSZ;
        for (uint32_t i = 0; i < v->inode_size; i++) out[i] = sec[so + i];
    }
    return 0;
}

/* map a file-relative block index to its disk block (0 = sparse hole) */
/* ext4 extent tree (M1186): map logical block `fblk` -> physical, walking from a
 * node (the 60-byte i_block, or a block-sized internal/leaf node). Bounded depth
 * + entry count + rdblk range-checks, so a corrupt tree can't OOB or loop. 0 =
 * hole/unmapped (the read path zero-fills). Only the low 32 bits of the physical
 * block are used (no 64bit feature); an uninitialized extent reads as a hole. */
#define EXT4_EXTENTS_FL 0x80000u
#define EXT4_EXT_MAGIC  0xF30Au
/* EVERY BLOCK NUMBER THIS FUNCTION PRODUCES IS ALSO UNCHECKED (M2176).
 *
 * M2174 validated the indirect path and the inode table and left THIS one, on
 * the assumption that a "classic ext2" image has no extent inodes. It does:
 * ext2_write_path creates them (M1189), so every file the guest itself writes
 * -- the whole Firefox profile, every cache -- is extent-mapped and reads back
 * through here.
 *
 * The cost of the omission was visible in the very next measurement: a refused
 * read at `lba 15630828400 cap 6553600`, which is block 1953853550 against a
 * filesystem of 819200, with rejected-pointer and rejected-inode-table counts
 * both at ZERO. A wild block number that passed every check there was, because
 * the one path that produced it had none. */
static uint32_t extent_map(ext2_t *v, const uint8_t *ib, uint32_t fblk) {
    uint8_t buf[4096];
    const uint8_t *node = ib;
    uint32_t node_size = 60;                               /* i_block[] is 60 bytes */
    for (int guard = 0; guard < 8; guard++) {              /* depth cap */
        if (e_rd16(node) != EXT4_EXT_MAGIC) return 0;      /* eh_magic */
        uint32_t entries = e_rd16(node + 2);               /* eh_entries */
        uint16_t depth   = e_rd16(node + 6);               /* eh_depth */
        uint32_t cap = (node_size - 12) / 12;              /* entries that physically fit */
        if (entries > cap) entries = cap;
        if (depth == 0) {                                  /* leaf: ext4_extent[] */
            for (uint32_t i = 0; i < entries; i++) {
                const uint8_t *e = node + 12 + i * 12;
                uint32_t eb = e_rd32(e + 0);               /* ee_block (logical start) */
                uint16_t raw = e_rd16(e + 4);              /* ee_len (>32768 = uninitialized) */
                uint32_t st = e_rd32(e + 8);               /* ee_start_lo (start_hi ignored: 32-bit) */
                uint32_t len = raw > 32768 ? (uint32_t)(raw - 32768) : raw;
                if (len && fblk >= eb && fblk - eb < len)
                    return raw > 32768 ? 0
                                       : e2_ptr_ok(v, st + (fblk - eb), 3);   /* uninit -> hole */
            }
            return 0;                                      /* fblk in no extent -> hole */
        }
        uint32_t child = 0;                                /* internal: ext4_extent_idx[] */
        for (uint32_t i = 0; i < entries; i++) {
            const uint8_t *e = node + 12 + i * 12;
            if (fblk >= e_rd32(e + 0)) child = e_rd32(e + 4);   /* last idx with ei_block <= fblk */
            else break;
        }
        child = e2_ptr_ok(v, child, 4);                    /* an interior node off the fs is corruption */
        if (!child || rdblk(v, child, buf) < 0) return 0;
        node = buf; node_size = v->block_size;             /* descend */
    }
    return 0;
}

/* A BLOCK POINTER PAST THE END OF THE FILESYSTEM IS NOT A BLOCK POINTER (M2158).
 *
 * This is the last link in the chain M2155 traced. `map_block` returned
 * whatever 32-bit word it found in an indirect block and nothing checked it, so
 * a corrupt or misread pointer went straight down to the block layer:
 *
 *     blockdev 1, lba 732105248, count 8, device capacity 6553600 sectors
 *
 * 91513156 as a block number, in a filesystem with 819200 of them -- 112 times
 * the size of the disk. `raw_read` refused it (correctly), which ext2 reported
 * as "file not found" (M2155 fixed that), which the page-fault fill turned into
 * a zero-filled page of executable code (M2155 fixed that too). But the value
 * was already provably wrong HERE, where the superblock's own block count is in
 * hand, and passing it on was the first wrong answer in the sequence.
 *
 * Out of range is a CORRUPTION, so it sets `ioerr` rather than returning 0: a 0
 * means "sparse hole, these bytes are legitimately zero", which is exactly the
 * plausible-wrong-value this whole arc is about. The caller now fails the read.
 *
 * `blocks_count` of 0 means the superblock did not say, in which case there is
 * nothing to check against and the old behaviour stands. */
unsigned long g_e2_bad_ptrs;          /* out-of-range block pointers rejected */
uint32_t      g_e2_bad_ptr_val;       /* the last one, and where it came from */
int           g_e2_bad_ptr_level;     /* 1 = single indirect, 2 = double indirect, 0 = direct */
unsigned int  g_e2_blocks_count;      /* what the superblock says, so a bogus BOUND is visible too */

static uint32_t e2_ptr_ok(ext2_t *v, uint32_t blk, int level) {
    if (!blk) return 0;                                    /* a real hole */
    g_e2_blocks_count = v->blocks_count;
    if (v->blocks_count && blk >= v->blocks_count) {
        g_e2_bad_ptrs++; g_e2_distrust++;
        g_e2_bad_ptr_val = blk;
        g_e2_bad_ptr_level = level;
        v->ioerr = 1;                                      /* corruption, NOT a hole */
        return 0;
    }
    return blk;
}

static uint32_t map_block(ext2_t *v, const uint8_t *inode, uint32_t fblk) {
    if (e_rd32(inode + 32) & EXT4_EXTENTS_FL)              /* i_flags: ext4 extent-mapped (M1186) */
        return extent_map(v, inode + 40, fblk);
    const uint8_t *ib = inode + 40;                        /* i_block[15] */
    uint32_t ppb = v->block_size / 4;
    if (fblk < 12) return e2_ptr_ok(v, e_rd32(ib + fblk * 4), 0);   /* direct */
    fblk -= 12;
    uint8_t buf[4096];
    if (fblk < ppb) {                                      /* single-indirect */
        uint32_t ind = e2_ptr_ok(v, e_rd32(ib + 12 * 4), 0);
        if (!ind || rdblk(v, ind, buf) < 0) return 0;
        return e2_ptr_ok(v, e_rd32(buf + fblk * 4), 1);
    }
    fblk -= ppb;
    if (fblk < ppb * ppb) {                                /* double-indirect */
        uint32_t dind = e2_ptr_ok(v, e_rd32(ib + 13 * 4), 0);
        if (!dind || rdblk(v, dind, buf) < 0) return 0;
        uint32_t ind = e2_ptr_ok(v, e_rd32(buf + (fblk / ppb) * 4), 1);
        if (!ind || rdblk(v, ind, buf) < 0) return 0;
        return e2_ptr_ok(v, e_rd32(buf + (fblk % ppb) * 4), 2);
    }
    return 0;                                              /* triple-indirect unsupported */
}

/* find `name` in directory inode `dino`; returns the child inode #, 0 if absent */
static uint32_t dir_lookup(ext2_t *v, const uint8_t *dino, const char *name, int *is_dir) {
    uint32_t size = e_rd32(dino + 4);
    uint8_t blk[4096];
    for (uint32_t off = 0; off < size; off += v->block_size) {
        uint32_t db = map_block(v, dino, off / v->block_size);
        if (!db || rdblk(v, db, blk) < 0) continue;
        uint32_t bo = 0;
        while (bo + 8 <= v->block_size) {
            uint32_t ino = e_rd32(blk + bo);
            uint16_t rl = e_rd16(blk + bo + 4);
            uint8_t nl = blk[bo + 6];
            if (rl < 8) break;
            if (ino && nl && bo + 8 + nl <= v->block_size) {
                int match = 1;
                for (int k = 0; k < nl; k++) if (name[k] == 0 || (uint8_t)name[k] != blk[bo + 8 + k]) { match = 0; break; }
                if (match && name[nl] == 0) { if (is_dir) *is_dir = (blk[bo + 7] == 2); return ino; }
            }
            bo += rl;
        }
    }
    return 0;
}

/* walk a '/'-path from `startino`, filling inode_out (>=256B) + *is_dir; returns
 * the inode # or 0. Follows symlinks (M1146): a resolved component that is a
 * symlink (mode 0xA000) is replaced by recursively resolving its target — an
 * absolute target ("/x") from the volume root, else relative to the symlink's
 * own directory. `depth` bounds symlink->symlink chains (loop guard). Fast
 * symlinks only (target stored inline in i_block, i.e. i_size <= 60). */
#define EXT2_SYMLINK_MAX 8
static uint32_t walk_d(ext2_t *v, uint32_t startino, const char *path,
                       uint8_t *inode_out, int *is_dir, int depth) {
    if (read_inode(v, startino, inode_out) < 0) return 0;
    if (is_dir) *is_dir = 1;
    uint32_t ino = startino, dirino = startino;
    const char *p = path;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        char comp[256]; int n = 0;
        while (*p && *p != '/' && n < 255) comp[n++] = *p++;
        comp[n] = 0;
        int cd = 0;
        uint32_t child = dir_lookup(v, inode_out, comp, &cd);
        if (!child || read_inode(v, child, inode_out) < 0) return 0;
        dirino = ino; ino = child;
        if (is_dir) *is_dir = cd;
        if ((e_rd16(inode_out + 0) & 0xF000) == 0xA000) {     /* a symlink: follow it */
            if (depth >= EXT2_SYMLINK_MAX) return 0;          /* loop / too deep */
            uint32_t sz = e_rd32(inode_out + 4);
            if (sz > 60) return 0;                            /* slow symlink (target in a block): unsupported */
            char tgt[64]; for (uint32_t i = 0; i < sz; i++) tgt[i] = (char)inode_out[40 + i]; tgt[sz] = 0;
            uint32_t base = (tgt[0] == '/') ? EXT2_ROOT_INO : dirino;
            ino = walk_d(v, base, tgt, inode_out, is_dir, depth + 1);   /* resolve the target */
            if (!ino) return 0;                               /* inode_out now = the target's inode */
        }
    }
    return ino;
}
/* ================= A PATH CACHE, POSITIVE AND NEGATIVE (M2103) ============
 *
 * WHY. Every path resolution walked from the volume root, reading a directory
 * block per component, with no cache of any kind anywhere in the tree. A
 * Firefox startup spends seven of its forty seconds in a stretch that is
 * almost entirely this -- thousands of stat() calls, and the log shows what
 * they are:
 *
 *   stat(".../storage/ls-archive.sqlite-journal") -> no such path
 *   stat(".../storage/ls-archive.sqlite-wal")     -> no such path
 *   stat(".../storage/ls-archive.sqlite-journal") -> no such path
 *   stat(".../storage/ls-archive.sqlite-wal")     -> no such path
 *
 * SQLite probes for a journal and a write-ahead log before every transaction,
 * and neither exists, so every probe was a full walk down eight components to
 * find nothing. A NEGATIVE cache is worth more here than a positive one, which
 * is not the usual way round and is exactly what the workload asked for.
 *
 * FLUSH EVERYTHING ON ANY WRITE, never selectively. That is the plan's own
 * prescription and it is the right one: selective invalidation of a path cache
 * requires knowing every path affected by a rename, an unlink, a directory
 * grow or a symlink change, and being wrong once means serving a stale answer
 * about whether a file exists. A whole-cache flush is one line, cannot be
 * subtly wrong, and costs a rebuild that the reads themselves pay for. Writes
 * are rare here; lookups are not.
 *
 * The inode NUMBER is cached, not the inode BYTES: the bytes carry a size and
 * timestamps that a write changes, and re-reading one inode block is the cheap
 * part -- the walk was the expensive part. A negative entry caches nothing but
 * the absence. */
/* THE CACHE WAS SHARED MUTABLE STATE WITH NO LOCK (M2155).
 *
 * This is the 8-core Firefox corruption, root-caused. Every thread that faults
 * a page of a demand-paged library comes through here, and on eight cores
 * several are inside the insert at once. Two of them scan the same LRU array,
 * pick the SAME victim slot, and interleave their field writes -- so the slot
 * ends up holding one path's name with the other's inode number, or with the
 * other's `negative` flag. A later lookup of a perfectly good library path then
 * gets "absent", ext2_pread returns -1, and the page-fault handler mapped the
 * still-zero frame anyway. Execution fell into the hole and `00 00` decoded as
 * `add %al,(%rax)`, which is a STORE, which faulted as a write to a read-only
 * mapping half a megabyte from the cause. Three sessions of hunting a
 * "corrupted executable page" and the corruption was one unlocked 256-entry
 * table answering with a plausible wrong value.
 *
 * NOT a spinlock, for two reasons that both matter here. ext2.c is #included
 * and compiled by tests/ext2/ext2_test.c on the HOST, where `cli` is a #GP --
 * so the primitive has to be something GCC gives both builds. And the lookup
 * path does DISK I/O (read_inode), which no lock in this file may span.
 *
 * So: claim the slot with an atomic exchange, and if the claim is already
 * taken, DON'T CACHE. A cache is allowed to miss; that is the whole of its
 * contract. The reader is safe against a torn entry because `used` is cleared
 * before the fields are written and set after, with a fence either side -- so
 * `used == 1` means the entry is whole. */
#define E2PC_N 256
/* `gen` is a seqlock: ODD = published and whole, EVEN = free or mid-write. It
 * replaces the old `used` flag because a flag cannot express "being rewritten",
 * and that is the state a reader has to detect. See walk_cached. */
static struct { char path[128]; uint32_t ino; uint8_t isdir, negative;
                volatile unsigned gen; volatile int claim; } g_e2pc[E2PC_N];
static unsigned g_e2pc_clk;
static uint8_t  g_e2pc_lru[E2PC_N];
unsigned long g_e2pc_races;      /* inserts abandoned because another core held the slot */
unsigned long g_e2pc_ioerrs;     /* lookups a device error spoiled, and so were NOT cached */
int g_e2pc_racy;                 /* -append e2pcracy: the pre-M2155 unlocked insert, for the revert proof */
/* WIDEN THE WINDOW, IN BOTH ARMS (M2155).
 *
 * The unlocked insert's bad window is the handful of instructions between
 * writing the path and writing the inode -- perhaps fifty cycles, against
 * millions between inserts. A test that waits for two cores to land inside
 * that window will not see it in any run anyone would sit through, so `0
 * failures` from the racy arm proves nothing about the racy arm.
 *
 * `-append e2pcwiden` puts the same delay in BOTH the fixed and the racy
 * insert, so the arms differ only in whether the entry is ATOMIC, which is the
 * property under test. The fixed path is unaffected by any delay because the
 * entry is unpublished (even generation) for the whole write; the racy path
 * leaves the previous occupant's odd generation in place and is therefore
 * readable, half-rewritten, for the duration.
 *
 * This is the same technique M1913/M1894 used to prove their races, and it is
 * the only honest way to make an intermittent defect testable. */
int g_e2pc_widen;
static void e2pc_widen(void) {
    if (!g_e2pc_widen) return;
    for (volatile int q = 0; q < 20000; q++) { }
}
unsigned long g_e2pc_hits, g_e2pc_misses, g_e2pc_neg_hits, g_e2pc_flushes;

static int e2pc_eq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}
/* Any write to this volume drops the whole cache. Called from every mutating
 * entry point in this file. */
void ext2_path_cache_flush(void) {
    for (int i = 0; i < E2PC_N; i++) {
        unsigned g = __atomic_load_n(&g_e2pc[i].gen, __ATOMIC_ACQUIRE);
        if (g & 1u) __atomic_store_n(&g_e2pc[i].gen, g + 1, __ATOMIC_RELEASE);
    }
    g_e2pc_flushes++;
}
void ext2_path_cache_stats(unsigned long *hits, unsigned long *misses,
                           unsigned long *neg, unsigned long *flushes) {
    if (hits)    *hits    = g_e2pc_hits;
    if (misses)  *misses  = g_e2pc_misses;
    if (neg)     *neg     = g_e2pc_neg_hits;
    if (flushes) *flushes = g_e2pc_flushes;
}

static uint32_t walk(ext2_t *v, const char *path, uint8_t *inode_out, int *is_dir) {
    return walk_d(v, EXT2_ROOT_INO, path, inode_out, is_dir, 0);
}

/* THE CACHE IS FOR READERS ONLY, and that is not a simplification -- it is the
 * fix for a bug the ext2 suite caught immediately (M2103).
 *
 * The first version cached inside walk() itself, and every WRITER calls walk()
 * to find what it is about to change. So ext2_rename_path looked up the old
 * name (caching it as present), renamed it, and left a stale positive entry
 * behind that no amount of flushing at the function's ENTRY could remove. The
 * test said so in six words:
 *
 *     old name still readable after rename
 *
 * Flushing on the way out instead would have worked too, and would have meant
 * touching every return in fourteen functions. Having the readers cache and
 * the writers not is smaller, and it cannot be got wrong by adding a
 * fifteenth writer later. */
/* -append nopathcache / noreadrun: turn each of this milestone's two read-path
 * changes off, so a failure elsewhere can be attributed rather than argued
 * about. A performance change that cannot be switched off is a change you
 * cannot be acquitted of. (M2104) */
int g_e2_path_cache = 1;
int g_e2_read_runs  = 1;

static uint32_t walk_cached(ext2_t *v, const char *path, uint8_t *inode_out, int *is_dir) {
    if (!g_e2_path_cache) return walk(v, path, inode_out, is_dir);
    int plen = 0; while (path[plen]) plen++;
    int cacheable = (plen > 0 && plen < (int)sizeof g_e2pc[0].path);
    int slot = -1;
    if (cacheable) {
        for (int i = 0; i < E2PC_N; i++) {
            /* READ THE ENTRY AS ONE VALUE OR NOT AT ALL (M2155).
             *
             * A flag test is not enough. A reader that passes the test and is
             * then overtaken mid-`e2pc_eq` by a writer recycling the slot can
             * match a HALF-REWRITTEN name -- the new path shares a prefix with
             * the old often enough on a library directory -- and then read the
             * new path's inode for the old path's name. That is the same wrong
             * answer the unlocked version gave, just through a narrower window,
             * and a narrower window is not a fix.
             *
             * So: odd generation = published, and re-read it after copying the
             * fields out. If it moved, the entry we just read never existed as
             * a whole and we fall through to the real walk. */
            unsigned g1 = __atomic_load_n(&g_e2pc[i].gen, __ATOMIC_ACQUIRE);
            if (!(g1 & 1u)) continue;                  /* free, or being written */
            if (!e2pc_eq(g_e2pc[i].path, path)) continue;
            uint32_t cino = g_e2pc[i].ino;
            uint8_t  cdir = g_e2pc[i].isdir, cneg = g_e2pc[i].negative;
            __atomic_thread_fence(__ATOMIC_ACQUIRE);
            if (!g_e2pc_racy && __atomic_load_n(&g_e2pc[i].gen, __ATOMIC_ACQUIRE) != g1) continue;
            g_e2pc_lru[i] = (uint8_t)(++g_e2pc_clk);
            if (cneg) { g_e2pc_neg_hits++; return 0; }   /* known absent: no walk at all */
            /* Positive: we still read the one inode, because its SIZE and
             * timestamps must be current -- but not the directories above it,
             * which is where the cost was. */
            if (read_inode(v, cino, inode_out) >= 0) {
                if (is_dir) *is_dir = cdir;
                g_e2pc_hits++;
                return cino;
            }
            /* The inode is gone: retire the entry, but only if it is still the
             * one we read -- otherwise we would be invalidating a stranger. */
            if (__atomic_load_n(&g_e2pc[i].gen, __ATOMIC_ACQUIRE) == g1)
                __atomic_compare_exchange_n(&g_e2pc[i].gen, &g1, g1 + 1, 0,
                                            __ATOMIC_RELEASE, __ATOMIC_RELAXED);
            break;
        }
        g_e2pc_misses++;
    }
    int isd = 0;
    uint32_t ino = walk_d(v, EXT2_ROOT_INO, path, inode_out, &isd, 0);
    if (is_dir) *is_dir = isd;
    /* NEVER CACHE AN ANSWER A DEVICE ERROR PRODUCED (M2155). A negative entry
     * written from a failed read is the whole bug: it makes a transient error
     * permanent, and it makes it permanent for the one path that was unlucky. */
    if (v->ioerr) { g_e2pc_ioerrs++; return ino; }
    if (cacheable) {
        /* Least-recently-used victim, or the first free slot. A linear scan of
         * 256 entries is nothing against the directory reads it replaces. */
        int v2 = -1; uint8_t oldest = 0xFF;
        for (int i = 0; i < E2PC_N; i++) {
            if (!(__atomic_load_n(&g_e2pc[i].gen, __ATOMIC_ACQUIRE) & 1u)) { v2 = i; break; }
            uint8_t age = (uint8_t)(g_e2pc_clk - g_e2pc_lru[i]);
            if (age >= oldest) { oldest = age; v2 = i; }
        }
        /* Claim the slot, and if another core already has it, DON'T CACHE. A
         * cache is allowed to miss; that is the whole of its contract, and it
         * is much cheaper than any lock that would have to be held across the
         * disk read this function performs. */
        /* THE REVERT PROOF, AS A BOOT FLAG (M2155). `-append e2pcracy` restores
         * the original unlocked insert -- no generation, no claim, fields
         * written straight into the victim slot -- so the test that proves this
         * milestone can be failed on demand without editing a line. The same
         * reasoning as `nodma` and `nopathcache`: a fix that cannot be switched
         * off is a fix you cannot be acquitted of. */
        if (v2 >= 0 && g_e2pc_racy) {
            slot = v2;
            int j = 0; for (; path[j] && j < (int)sizeof g_e2pc[0].path - 1; j++) g_e2pc[slot].path[j] = path[j];
            g_e2pc[slot].path[j] = 0;
            e2pc_widen();
            g_e2pc[slot].ino = ino;
            g_e2pc[slot].isdir = (uint8_t)(isd ? 1 : 0);
            g_e2pc[slot].negative = (uint8_t)(ino ? 0 : 1);
            g_e2pc[slot].gen |= 1u;                  /* "published", with no ordering at all */
            g_e2pc_lru[slot] = (uint8_t)(++g_e2pc_clk);
        } else if (v2 >= 0 && !__atomic_exchange_n(&g_e2pc[v2].claim, 1, __ATOMIC_ACQUIRE)) {
            slot = v2;
            unsigned g0 = __atomic_load_n(&g_e2pc[slot].gen, __ATOMIC_ACQUIRE);
            if (g0 & 1u)                                 /* published -> mark it in-flight */
                __atomic_store_n(&g_e2pc[slot].gen, g0 + 1, __ATOMIC_RELEASE);
            int j = 0; for (; path[j] && j < (int)sizeof g_e2pc[0].path - 1; j++) g_e2pc[slot].path[j] = path[j];
            g_e2pc[slot].path[j] = 0;
            e2pc_widen();                                /* the same delay as the racy arm */
            g_e2pc[slot].ino = ino;
            g_e2pc[slot].isdir = (uint8_t)(isd ? 1 : 0);
            g_e2pc[slot].negative = (uint8_t)(ino ? 0 : 1);
            __atomic_thread_fence(__ATOMIC_RELEASE);
            __atomic_store_n(&g_e2pc[slot].gen,
                             (__atomic_load_n(&g_e2pc[slot].gen, __ATOMIC_RELAXED) | 1u) + 2u,
                             __ATOMIC_RELEASE);          /* publish: odd, and different */
            g_e2pc_lru[slot] = (uint8_t)(++g_e2pc_clk);
            __atomic_store_n(&g_e2pc[v2].claim, 0, __ATOMIC_RELEASE);
        } else if (v2 >= 0) {
            g_e2pc_races++;      /* another core owns that slot: miss rather than corrupt it */
        }
    }
    return ino;
}

int ext2_probe(blk_read_fn read, void *ctx, uint64_t start_lba) {
    /* A PROBE IS A QUESTION, NOT A FAILURE (M2222).
     *
     * ext2_probe is how blockdev asks "is this volume ext2?", and it asks it of
     * every volume on the machine -- including the FAT boot disk, whose
     * superblock magic is of course not 0xEF53. M2220 made every ext2_open
     * rejection count as distrust so the fault handler could stop zero-filling
     * pages over a filesystem that disbelieved itself, and that turned each of
     * those perfectly correct "no, not ext2" answers into evidence of
     * corruption. The fault handler samples the counter as a DELTA across one
     * read, so a probe racing a page fault would make it refuse a legitimate
     * fill -- a false positive that looks exactly like the real bug it was
     * added to catch.
     *
     * Snapshot and restore: whatever the probe learns, it leaves the counters
     * where it found them. */
    unsigned long d0 = g_e2_distrust, rf = g_e2_sb_readfail;
    unsigned long bm = g_e2_sb_badmagic, bf = g_e2_sb_badfield;
    unsigned long rt = g_e2_sb_retried, rk = g_e2_sb_retry_ok;
    ext2_t v;
    int r = ext2_open(read, ctx, start_lba, &v);
    if (r != 0) {
        g_e2_distrust = d0; g_e2_sb_readfail = rf;
        g_e2_sb_badmagic = bm; g_e2_sb_badfield = bf;
        g_e2_sb_retried = rt; g_e2_sb_retry_ok = rk;
    }
    return r;
}

/* Positioned read: up to `max` bytes starting at byte `offset` (M1196). Walks
 * blocks from offset/bs with a partial first/last block, so file fds read at an
 * arbitrary position without the read-the-whole-prefix workaround. */
/* WHY THE LAST ext2_pread RETURNED -1 (M2155).
 *
 * `-1` from here is three different failures wearing one number, and the one
 * that mattered -- "the path cache answered absent for a file that exists" --
 * was indistinguishable from "that file really is not there". A caller can now
 * name it. Not a kprintf: ext2.c is #included and compiled on the host by
 * tests/ext2/ext2_test.c and deliberately calls nothing outside itself. */
int g_e2_pread_why;      /* 0 = ok, 1 = superblock unreadable, 2 = path not found, 3 = is a directory */
const char *ext2_pread_why(void) {
    switch (g_e2_pread_why) {
    case 1:  return "the ext2 SUPERBLOCK could not be read";
    case 2:  return "the PATH was not found (a real walk, or the path cache, said absent)";
    case 3:  return "the path is a DIRECTORY";
    case 4:  return "a BLOCK READ FAILED during the path walk -- a device error, not a missing file";
    case 5:  return "a BLOCK READ FAILED while reading the file's data";
    case 6:  return "a BLOCK POINTER was past the end of the filesystem (corruption, not a hole)";
    default: return "no recorded reason";
    }
}

long ext2_pread(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path,
                void *buf, unsigned long max, unsigned long offset) {
    ext2_t v; if (ext2_open(read, ctx, start_lba, &v) < 0) { g_e2_pread_why = 1; return -1; }
    uint8_t inode[256]; int isdir = 0;
    if (!walk_cached(&v, path, inode, &isdir)) { g_e2_pread_why = v.ioerr ? 4 : 2; return -1; }
    if (isdir) { g_e2_pread_why = 3; return -1; }
    g_e2_pread_why = 0;
    uint32_t size = e_rd32(inode + 4);
    if (offset >= size) return 0;                          /* at/after EOF */
    unsigned long avail = size - offset;
    unsigned long want = max < avail ? max : avail;        /* read min(max, remaining) */
    uint8_t blk[4096]; unsigned long done = 0;
    while (done < want) {
        unsigned long pos = offset + done;
        uint32_t lb = (uint32_t)(pos / v.block_size);
        uint32_t db = map_block(&v, inode, lb);
        uint32_t bo = (uint32_t)(pos % v.block_size);      /* byte offset within the block */
        uint32_t chunk = v.block_size - bo;                /* to the block's end */
        if (chunk > want - done) chunk = (uint32_t)(want - done);
        /* WHOLE, ALIGNED, CONTIGUOUS BLOCKS GO STRAIGHT INTO THE CALLER'S
         * BUFFER, AS MANY AS FOLLOW EACH OTHER (M2101).
         *
         * The old loop did one block per iteration and bounced every one
         * through `blk[]` even when the whole block was wanted -- so a 64 KiB
         * readahead of a contiguous file was sixteen device commands and
         * sixteen redundant 4 KiB memcpys. A run of physically consecutive
         * blocks is one command and no copy at all.
         *
         * The partial-block path below is unchanged and still bounces, because
         * it must: the caller's buffer has no room for the bytes either side
         * of the piece it asked for. */
        if (g_e2_read_runs && db && bo == 0 && want - done >= v.block_size) {
            uint32_t run = 1;
            while (run < EXT2_MAX_RUN && (done + (unsigned long)(run + 1) * v.block_size) <= want) {
                if (map_block(&v, inode, lb + run) != db + run) break;   /* not contiguous: stop the run */
                run++;
            }
            /* The RUN's far end is produced arithmetic as well (M2176): `db` was
             * checked, `db + run` never was. */
            if (v.blocks_count && (uint64_t)db + run > v.blocks_count) { v.ioerr = 1; break; }
            if (rdblks(&v, db, run, (uint8_t *)buf + done) < 0) break;
            done += (unsigned long)run * v.block_size;
            continue;
        }
        if (!db) {
            /* A HOLE, AND SOMEBODY HAS TO BE ABLE TO KNOW (M2221).
             *
             * A zero block pointer means a sparse hole, and zeros are the
             * correct answer for one. They are also what a CORRUPTED inode
             * produces: read the inode wrong, get a zero where a block number
             * belongs, and this returns a page of zeros with no error, no
             * ioerr and nothing in the log. That is the worst form of the bug
             * class this tree keeps paying for -- a plausible wrong value
             * instead of a failure -- and it is how a page of libstdc++'s TEXT
             * came back as zeros and the process jumped into it:
             *
             *   [fault] Page Fault at rip=0x102b59ba0 ... [tid 94]
             *   [fault] code check: memory 00 00 00 ... file 00 00 00 ...
             *           IDENTICAL, so the mapping is intact
             *
             * "Identical to the file" because the verification read came back
             * from the same hole. ext2 cannot tell a real hole from a
             * corrupted pointer on its own -- but the CALLER can: a hole in
             * the middle of an executable mapping is not a hole. Count them so
             * the fault handler can sample the counter across its read, the
             * same way it samples g_e2_distrust (M2213). */
            g_e2_holes++;
            memset((uint8_t *)buf + done, 0, chunk);
        }
        else { if (rdblk(&v, db, blk) < 0) break; memcpy((uint8_t *)buf + done, blk + bo, chunk); }
        done += chunk;
    }
    /* A SHORT COUNT FROM A DEVICE ERROR IS A SILENT HOLE (M2155). Both `break`s
     * above leave `done` short of `want`, and the caller cannot tell that from
     * a file that simply ends there -- so the page-fault fill zero-filled the
     * remainder of an executable page and mapped it. An error is an error: say
     * so, and let the caller retry the whole read. */
    if (v.ioerr) { g_e2_pread_why = 5; return -1; }
    return (long)done;
}
long ext2_read_path(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path,
                    void *buf, unsigned long max) {
    return ext2_pread(read, ctx, start_lba, path, buf, max, 0);   /* whole-file read = pread @0 (M1196) */
}

/* FIEMAP (M1152): the file's physical extent map — each maximal run of
 * contiguous on-disk blocks, in BYTES. Walks logical blocks 0..ceil(size/bs)
 * via map_block (the same direct/indirect resolver ext2_read_path uses),
 * coalescing runs where physical[n+1] == physical[n]+1. Sparse holes (block 0)
 * end the current run and aren't emitted. Fills out[0..max), returns the extent
 * count, or -1 if the path is absent / a directory. Self-contained (no external
 * calls) so the host-test #include of ext2.c stays linkable. */
int ext2_fiemap(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path,
                ext2_extent_t *out, int max) {
    ext2_t v; if (ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    uint8_t inode[256]; int isdir = 0;
    if (!walk_cached(&v, path, inode, &isdir) || isdir) return -1;
    uint64_t size = e_rd32(inode + 4);
    uint32_t bs = v.block_size;
    uint32_t nblk = (uint32_t)((size + bs - 1) / bs);
    int n = 0; uint32_t i = 0;
    while (i < nblk && n < max) {
        uint32_t phys = map_block(&v, inode, i);
        if (!phys) { i++; continue; }                       /* sparse hole: not an extent */
        uint32_t log0 = i, phys0 = phys, runlen = 1; i++;
        while (i < nblk && map_block(&v, inode, i) == phys0 + runlen) { runlen++; i++; }
        out[n].logical  = (uint64_t)log0  * bs;
        out[n].physical = (uint64_t)phys0 * bs;
        out[n].length   = (uint64_t)runlen * bs;
        n++;
    }
    return n;
}

int ext2_isdir_path(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path) {
    ext2_t v; if (ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    uint8_t inode[256]; int isdir = 0;
    if (!walk_cached(&v, path, inode, &isdir)) return -1;
    return isdir;
}

/* Size + isdir for `path` (M1624): same walk() as ext2_isdir_path, just also
 * reading the size field the inode buffer already has. 0 on success, -1 if
 * absent -- feeds vfs_stat's /diskN dispatch via blockdev_mount_stat. */
int ext2_stat_path(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path,
                   uint32_t *out_size, int *out_isdir, uint32_t *out_ino,
                   uint32_t *out_mtime, uint32_t *out_nlink, uint32_t *out_mode) {
    ext2_t v; if (ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    uint8_t inode[256]; int isdir = 0;
    /* walk() already returns the inode NUMBER; it was simply being discarded.
     * st_ino is not decoration: a dynamic linker decides whether a library is
     * already loaded by comparing (st_dev, st_ino), so a constant inode makes
     * every library look like the first one it mapped. (M1955) */
    uint32_t ino = walk_cached(&v, path, inode, &isdir);
    if (!ino) return -1;
    if (out_size)  *out_size  = e_rd32(inode + 4);
    if (out_isdir) *out_isdir = isdir;
    if (out_ino)   *out_ino   = ino;
    /* THE FIELDS THAT WERE ALREADY IN HAND AND WERE THROWN AWAY (M1999). The
     * inode is right here, fully read: i_mode at 0, i_links_count at 26,
     * i_mtime at 16. e_stamp has been WRITING the timestamps since M1175 and
     * nothing could read one back, so every file a Linux program stat'd
     * reported 1 January 1970 -- which is what `make` compares to decide what
     * to rebuild, and what git compares to decide what to re-hash. */
    if (out_mtime) *out_mtime = e_rd32(inode + 16);
    if (out_nlink) *out_nlink = e_rd16(inode + 26);
    if (out_mode)  *out_mode  = e_rd16(inode + 0);
    return 0;
}

int ext2_list_path(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path,
                   fatvol_dirent *out, int max) {
    ext2_t v; if (ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    uint8_t inode[256]; int isdir = 0;
    if (!walk_cached(&v, path, inode, &isdir) || !isdir) return -1;
    uint32_t size = e_rd32(inode + 4);
    uint8_t blk[4096]; int n = 0;
    for (uint32_t off = 0; off < size && n < max; off += v.block_size) {
        uint32_t db = map_block(&v, inode, off / v.block_size);
        if (!db || rdblk(&v, db, blk) < 0) continue;
        uint32_t bo = 0;
        while (bo + 8 <= v.block_size && n < max) {
            uint32_t ino = e_rd32(blk + bo);
            uint16_t rl = e_rd16(blk + bo + 4);
            uint8_t nl = blk[bo + 6];
            if (rl < 8) break;
            if (ino && nl && bo + 8 + nl <= v.block_size) {
                /* skip "." and ".." */
                int dot = (nl == 1 && blk[bo + 8] == '.') || (nl == 2 && blk[bo + 8] == '.' && blk[bo + 9] == '.');
                if (!dot) {
                    int k = 0; for (; k < nl && k < (int)sizeof out[n].name - 1; k++) out[n].name[k] = (char)blk[bo + 8 + k];   /* 12 -> 31 (M1746) -> 255, ext2's own limit (M2062) */
                    out[n].name[k] = 0;
                    out[n].is_dir = (blk[bo + 7] == 2);
                    uint8_t cino[256];                         /* child inode -> size */
                    out[n].size = (read_inode(&v, ino, cino) == 0 && !out[n].is_dir) ? e_rd32(cino + 4) : 0;
                    n++;
                }
            }
            bo += rl;
        }
    }
    return n;
}

/* ===================== write path (M1132) =============================== *
 * Create a new regular file: allocate an inode + data blocks (updating the
 * block/inode bitmaps and the free counts in the group descriptor + superblock),
 * write the data, fill the inode, and splice a directory record into the parent.
 * Direct + single-indirect extents. The superblock is read/written as its raw
 * 1024 bytes at LBA+2 (block-size-independent); bitmaps/GDT/inode-table/data go
 * through wrblk. Writes are cache-coherent (the blockdev write-through cache), so
 * the read paths above immediately see what we commit. */

static int wrblk(ext2_t *v, uint32_t blk, const uint8_t *buf) {
    if (!v->write) return -1;
    uint32_t spb = v->block_size / SECSZ;
    return v->write(v->ctx, v->start + (uint64_t)blk * spb, spb, buf);
}
/* The write counterpart of rdsec (M2212): one sector of a block. */
static int wrsec(ext2_t *v, uint32_t blk, uint32_t secoff, const uint8_t *buf) {
    if (!v->write) return -1;
    uint32_t spb = v->block_size / SECSZ;
    if (secoff >= spb) return -1;
    return v->write(v->ctx, v->start + (uint64_t)blk * spb + secoff, 1, buf);
}
static int rd_sb(ext2_t *v, uint8_t *sb) { return v->read(v->ctx, v->start + 2, 2, sb); }      /* the 1024-byte superblock */
static int wr_sb(ext2_t *v, const uint8_t *sb) { return v->write ? v->write(v->ctx, v->start + 2, 2, sb) : -1; }

/* decrement the superblock's free-block (off=12) or free-inode (off=16) count */
static int sb_dec(ext2_t *v, int off) {
    uint8_t sb[1024];
    if (rd_sb(v, sb) < 0) return -1;
    e_wr32(sb + off, e_rd32(sb + off) - 1);
    return wr_sb(v, sb);
}

/* Allocate a free data block; returns its 1-based-into-fs block number, or 0. */
static uint32_t alloc_block(ext2_t *v) {
    uint8_t gd[4096], bm[4096];
    uint32_t gd_per_block = v->block_size / 32;
    for (uint32_t g = 0; g < v->groups; g++) {
        uint32_t gdblk = v->gdt_block + g / gd_per_block, goff = (g % gd_per_block) * 32;
        if (rdblk(v, gdblk, gd) < 0) return 0;
        if (e_rd16(gd + goff + 12) == 0) continue;             /* no free blocks in this group */
        uint32_t bbm = e_rd32(gd + goff + 0);
        if (rdblk(v, bbm, bm) < 0) return 0;
        uint32_t inthis = v->blocks_per_group, prev = g * v->blocks_per_group;
        if (v->blocks_count - v->first_data_block - prev < inthis)
            inthis = v->blocks_count - v->first_data_block - prev;
        for (uint32_t i = 0; i < inthis; i++) {
            if (!(bm[i >> 3] & (1 << (i & 7)))) {
                bm[i >> 3] |= (uint8_t)(1 << (i & 7));
                if (wrblk(v, bbm, bm) < 0) return 0;
                e_wr16(gd + goff + 12, e_rd16(gd + goff + 12) - 1);
                if (wrblk(v, gdblk, gd) < 0 || sb_dec(v, 12) < 0) return 0;
                return v->first_data_block + g * v->blocks_per_group + i;
            }
        }
    }
    return 0;
}

/* Decrement a 32-bit superblock counter by n (the run-allocation form of sb_dec). */
static int sb_sub(ext2_t *v, int off, uint32_t n) {
    uint8_t sb[1024];
    if (rd_sb(v, sb) < 0) return -1;
    e_wr32(sb + off, e_rd32(sb + off) - n);
    return wr_sb(v, sb);
}

/* Allocate n CONTIGUOUS free blocks within one group (a single-extent write,
 * M1189); returns the first block number, or 0 if no run of n fits. Mirrors
 * alloc_block's bitmap + group/superblock free-count bookkeeping. */
static uint32_t alloc_run(ext2_t *v, uint32_t n) {
    if (n == 0) return 0;
    uint8_t gd[4096], bm[4096];
    uint32_t gd_per_block = v->block_size / 32;
    for (uint32_t g = 0; g < v->groups; g++) {
        uint32_t gdblk = v->gdt_block + g / gd_per_block, goff = (g % gd_per_block) * 32;
        if (rdblk(v, gdblk, gd) < 0) return 0;
        if (e_rd16(gd + goff + 12) < n) continue;              /* group lacks n free blocks */
        uint32_t bbm = e_rd32(gd + goff + 0);
        if (rdblk(v, bbm, bm) < 0) return 0;
        uint32_t inthis = v->blocks_per_group, prev = g * v->blocks_per_group;
        if (v->blocks_count - v->first_data_block - prev < inthis)
            inthis = v->blocks_count - v->first_data_block - prev;
        uint32_t run = 0;
        for (uint32_t i = 0; i < inthis; i++) {
            if (!(bm[i >> 3] & (1 << (i & 7)))) {
                if (++run == n) {                              /* found n consecutive free bits */
                    uint32_t startbit = i + 1 - n;
                    for (uint32_t j = 0; j < n; j++) { uint32_t b = startbit + j; bm[b >> 3] |= (uint8_t)(1 << (b & 7)); }
                    if (wrblk(v, bbm, bm) < 0) return 0;
                    e_wr16(gd + goff + 12, (uint16_t)(e_rd16(gd + goff + 12) - n));
                    if (wrblk(v, gdblk, gd) < 0 || sb_sub(v, 12, n) < 0) return 0;
                    return v->first_data_block + g * v->blocks_per_group + startbit;
                }
            } else run = 0;
        }
    }
    return 0;
}

/* Allocate a free inode; returns its 1-based number, or 0. */
static uint32_t alloc_inode(ext2_t *v) {
    uint8_t gd[4096], bm[4096];
    uint32_t gd_per_block = v->block_size / 32;
    for (uint32_t g = 0; g < v->groups; g++) {
        uint32_t gdblk = v->gdt_block + g / gd_per_block, goff = (g % gd_per_block) * 32;
        if (rdblk(v, gdblk, gd) < 0) return 0;
        if (e_rd16(gd + goff + 14) == 0) continue;             /* no free inodes in this group */
        uint32_t ibm = e_rd32(gd + goff + 4);
        if (rdblk(v, ibm, bm) < 0) return 0;
        uint32_t lo = (g == 0 && v->first_ino > 1) ? v->first_ino - 1 : 0;   /* skip reserved inodes in group 0 */
        for (uint32_t i = lo; i < v->inodes_per_group; i++) {
            if (!(bm[i >> 3] & (1 << (i & 7)))) {
                bm[i >> 3] |= (uint8_t)(1 << (i & 7));
                if (wrblk(v, ibm, bm) < 0) return 0;
                e_wr16(gd + goff + 14, e_rd16(gd + goff + 14) - 1);
                if (wrblk(v, gdblk, gd) < 0 || sb_dec(v, 16) < 0) return 0;
                return g * v->inodes_per_group + i + 1;
            }
        }
    }
    return 0;
}

/* Write inode `ino` back into its inode-table slot (read-modify-write). */
static int write_inode(ext2_t *v, uint32_t ino, const uint8_t *in) {
    if (ino == 0) return -1;
    uint32_t group = (ino - 1) / v->inodes_per_group, index = (ino - 1) % v->inodes_per_group;
    /* ONE SECTOR EACH, as in read_inode (M2212): 8240 bytes of stack for two
     * reads that need 32 and 256 bytes, in a file whose deepest path already
     * runs at 90% of a 16 KiB kernel stack. */
    uint8_t sec[SECSZ];
    uint32_t gd_per_block = v->block_size / 32;
    uint32_t gdblk = v->gdt_block + group / gd_per_block;
    uint32_t gdbyte = (group % gd_per_block) * 32;
    if (!e2_ptr_ok(v, gdblk, 5)) { v->ioerr = 1; return -1; }
    if (rdsec(v, gdblk, gdbyte / SECSZ, sec) < 0) return -1;
    uint32_t itable = e_rd32(sec + (gdbyte % SECSZ) + 8);
    /* CHECK IT HERE TOO. read_inode has rejected an out-of-range inode table
     * since M2174; this one took the same value on trust and would write an
     * inode into whatever data block the arithmetic landed on -- the same
     * defect, in the direction that destroys the filesystem instead of merely
     * misreading it. */
    if (!itable || (v->blocks_count && itable >= v->blocks_count)) {
        v->ioerr = 1; g_e2_bad_itable++; g_e2_bad_itable_val = itable; return -1;
    }
    uint64_t byte_off = (uint64_t)index * v->inode_size;
    uint32_t tblk = itable + (uint32_t)(byte_off / v->block_size);
    uint32_t off = (uint32_t)(byte_off % v->block_size);
    if (off + v->inode_size > v->block_size) return -1;
    if ((off % SECSZ) + v->inode_size > SECSZ) return -1;   /* would straddle a sector */
    if (rdsec(v, tblk, off / SECSZ, sec) < 0) return -1;
    {   uint32_t so = off % SECSZ;
        for (uint32_t i = 0; i < v->inode_size; i++) sec[so + i] = in[i]; }
    return wrsec(v, tblk, off / SECSZ, sec);
}

static int free_block(ext2_t *v, uint32_t blk);        /* defined below; bmap_alloc unwinds with it */

/* ---- bmap_alloc: the ALLOCATING counterpart of map_block (M1933) -----------
 *
 * map_block() is read-only — it returns 0 for a hole. Growing a file needs the
 * inverse: walk the same direct / single / double-indirect tree, but CREATE
 * each missing level on the way down. This is the primitive that turns ext2
 * from "can rewrite a small file" into "can grow a large one", and both
 * dir_add (growing a directory) and streaming writes are built on it.
 *
 * `*charged` accumulates EVERY block allocated — data and indirect metablocks
 * alike — because i_blocks counts both. Forgetting the metablocks is the
 * classic way to leave a filesystem that mounts fine but fails fsck.
 *
 * Triple-indirect is deliberately NOT allocated: double-indirect already
 * reaches 4 GiB at a 4 KiB block size (12 + 1024 + 1024*1024 blocks), which is
 * also FAT32's per-file ceiling, and free_inode_blocks() only frees through
 * double — allocating a level it cannot free would leak blocks on unlink. */

/* These helpers are deliberately written to hold AT MOST ONE 4 KiB block buffer
 * live at a time, and never to nest two of them. ext2_write_path already spends
 * ~9 KiB of frame on blk[]+ind[], dir_add another ~4.3 KiB, and the default
 * KERNEL task stack is 16 KiB (task.c:27) — an allocator that nested two block
 * buffers under that chain would overflow it. Only app tasks get 256 KiB. */

/* Allocate a ZERO-FILLED block, for use as an indirect metablock: a recycled
 * block still holding its previous contents reads back as a page of bogus
 * block pointers, which map_block would follow straight off the rails. */
static uint32_t alloc_zeroed(ext2_t *v, uint32_t *charged) {
    uint32_t b = alloc_block(v);
    if (!b) return 0;
    uint8_t z[4096];
    memset(z, 0, v->block_size);
    if (wrblk(v, b, z) < 0) { free_block(v, b); return 0; }
    if (charged) (*charged)++;
    return b;
}

/* Get-or-create the intermediate indirect level at slot `idx` of block `tbl`.
 * Zeroes the new level BEFORE linking it, reusing the one buffer for both (at
 * the cost of re-reading `tbl`) — link-then-zero would leave a window where a
 * crash publishes a garbage indirect block. */
static uint32_t ind_level(ext2_t *v, uint32_t tbl, uint32_t idx, uint32_t *charged) {
    uint8_t b[4096];
    if (rdblk(v, tbl, b) < 0) return 0;
    uint32_t got = e_rd32(b + idx * 4);
    if (got) return got;
    if (!(got = alloc_block(v))) return 0;
    if (charged) (*charged)++;
    memset(b, 0, v->block_size);                           /* b's contents no longer needed */
    if (wrblk(v, got, b) < 0)      { free_block(v, got); return 0; }
    if (rdblk(v, tbl, b) < 0)      { free_block(v, got); return 0; }
    e_wr32(b + idx * 4, got);
    if (wrblk(v, tbl, b) < 0)      { free_block(v, got); return 0; }
    return got;
}

/* Where a logical block's pointer lives. tblk==0 means "in i_block[idx]". */
typedef struct { uint32_t tblk, idx; } bslot_t;

/* Locate logical block `fblk`'s pointer slot, CREATING any missing indirect
 * levels on the way down. Declares no block buffer of its own, so the helpers
 * it calls never stack. Returns 1, or 0 on failure. */
static int bmap_slot(ext2_t *v, uint8_t *inode, uint32_t fblk, bslot_t *s, uint32_t *charged) {
    if (e_rd32(inode + 32) & EXT4_EXTENTS_FL) return 0;    /* extent-mapped: not ours to grow */
    uint8_t *ib = inode + 40;                              /* i_block[15] */
    uint32_t ppb = v->block_size / 4;

    if (fblk < 12) { s->tblk = 0; s->idx = fblk; return 1; }   /* direct */
    fblk -= 12;

    if (fblk < ppb) {                                      /* single-indirect */
        uint32_t ind = e_rd32(ib + 12 * 4);
        if (!ind) { if (!(ind = alloc_zeroed(v, charged))) return 0; e_wr32(ib + 12 * 4, ind); }
        s->tblk = ind; s->idx = fblk; return 1;
    }
    fblk -= ppb;

    if (fblk < ppb * ppb) {                                /* double-indirect */
        uint32_t dind = e_rd32(ib + 13 * 4);
        if (!dind) { if (!(dind = alloc_zeroed(v, charged))) return 0; e_wr32(ib + 13 * 4, dind); }
        uint32_t ind = ind_level(v, dind, fblk / ppb, charged);
        if (!ind) return 0;
        s->tblk = ind; s->idx = fblk % ppb; return 1;
    }
    return 0;                                              /* triple-indirect: see the note above */
}

static uint32_t bslot_get(ext2_t *v, const uint8_t *inode, bslot_t s) {
    if (!s.tblk) return e_rd32(inode + 40 + s.idx * 4);
    uint8_t b[4096];
    if (rdblk(v, s.tblk, b) < 0) return 0;
    return e_rd32(b + s.idx * 4);
}

static int bslot_set(ext2_t *v, uint8_t *inode, bslot_t s, uint32_t phys) {
    if (!s.tblk) { e_wr32(inode + 40 + s.idx * 4, phys); return 0; }  /* caller write_inode()s */
    uint8_t b[4096];
    if (rdblk(v, s.tblk, b) < 0) return -1;
    e_wr32(b + s.idx * 4, phys);
    return wrblk(v, s.tblk, b);
}

/* Physical block backing logical block `fblk`, allocating it (and any indirect
 * level above it) if absent. Updates i_block[] in the caller's in-memory
 * `inode`, so the caller must write_inode() to commit. 0 on failure. */
static uint32_t bmap_alloc(ext2_t *v, uint8_t *inode, uint32_t fblk, uint32_t *charged) {
    bslot_t s;
    if (!bmap_slot(v, inode, fblk, &s, charged)) return 0;
    uint32_t b = bslot_get(v, inode, s);
    if (b) return b;                                       /* already mapped */
    if (!(b = alloc_block(v))) return 0;
    if (charged) (*charged)++;
    if (bslot_set(v, inode, s, b) < 0) { free_block(v, b); return 0; }
    return b;
}

/* Point logical block `fblk` at an ALREADY-ALLOCATED physical block — used to
 * rebuild an extent-mapped file's mapping as an indirect tree without moving
 * any data. Charges only the indirect metablocks; `phys` is already counted. */
static int bmap_install(ext2_t *v, uint8_t *inode, uint32_t fblk, uint32_t phys, uint32_t *charged) {
    bslot_t s;
    if (!bmap_slot(v, inode, fblk, &s, charged)) return -1;
    return bslot_set(v, inode, s, phys);
}

/* Add a directory record {child_ino, name, ftype} to directory inode `parent_ino`
 * by splitting an existing record's slack, APPENDING A BLOCK if none has room
 * (M1933 — before that a directory was permanently stuck at its first block,
 * i.e. roughly 30-50 entries, which no real source tree fits in). Returns 0. */
static int dir_add(ext2_t *v, uint32_t parent_ino, const char *name, uint32_t child_ino, uint8_t ftype) {
    uint8_t pin[256], blk[4096];
    if (read_inode(v, parent_ino, pin) < 0) return -1;
    uint32_t size = e_rd32(pin + 4);
    int nl = 0; while (name[nl]) nl++;
    if (nl < 1 || nl > 255) return -1;
    uint32_t need = 8 + (((uint32_t)nl + 3) & ~3u);
    for (uint32_t off = 0; off < size; off += v->block_size) {
        uint32_t db = map_block(v, pin, off / v->block_size);
        if (!db || rdblk(v, db, blk) < 0) continue;
        uint32_t bo = 0;
        while (bo + 8 <= v->block_size) {
            uint32_t ino = e_rd32(blk + bo);
            uint16_t rl = e_rd16(blk + bo + 4);
            uint8_t enl = blk[bo + 6];
            if (rl < 8 || bo + rl > v->block_size) break;
            uint32_t used = ino ? (8 + (((uint32_t)enl + 3) & ~3u)) : 0;
            if (rl >= used + need) {                       /* slack here fits the new record */
                uint32_t newoff; uint16_t newrl;
                if (ino) { e_wr16(blk + bo + 4, (uint16_t)used); newoff = bo + used; newrl = (uint16_t)(rl - used); }
                else     { newoff = bo; newrl = rl; }      /* reuse an empty (deleted) slot */
                e_wr32(blk + newoff, child_ino);
                e_wr16(blk + newoff + 4, newrl);
                blk[newoff + 6] = (uint8_t)nl;
                blk[newoff + 7] = ftype;
                for (int k = 0; k < nl; k++) blk[newoff + 8 + k] = (uint8_t)name[k];
                return wrblk(v, db, blk);
            }
            bo += rl;
        }
    }

    /* Every existing block is full -> APPEND one. A directory's i_size is always
     * a whole number of blocks, so the new block's logical index is exactly
     * size/block_size, and the fresh block holds a single record spanning it. */
    if (need > v->block_size) return -1;
    uint32_t charged = 0;
    uint32_t nb = bmap_alloc(v, pin, size / v->block_size, &charged);
    if (!nb) return -1;                                    /* out of space, or an extent-mapped dir */
    memset(blk, 0, v->block_size);
    e_wr32(blk + 0, child_ino);
    e_wr16(blk + 4, (uint16_t)v->block_size);              /* this record owns the whole block */
    blk[6] = (uint8_t)nl;
    blk[7] = ftype;
    for (int k = 0; k < nl; k++) blk[8 + k] = (uint8_t)name[k];
    /* Commit the data block BEFORE the inode: a crash between the two leaves an
     * allocated-but-unreferenced block (which fsck reclaims), whereas the
     * reverse order would publish a directory block full of stale garbage. */
    if (wrblk(v, nb, blk) < 0) { free_block(v, nb); return -1; }
    e_wr32(pin + 4,  size + v->block_size);                               /* i_size  */
    e_wr32(pin + 28, e_rd32(pin + 28) + charged * (v->block_size / 512)); /* i_blocks, 512-byte units */
    return write_inode(v, parent_ino, pin);
}

/* ----- freeing, for overwrite + unlink (M1135) ----- *
 * The inverses of alloc_block/alloc_inode: clear the bitmap bit and bump the free
 * count in the group descriptor + superblock. */
static int free_block(ext2_t *v, uint32_t blk) {
    if (blk < v->first_data_block || blk >= v->blocks_count) return -1;
    uint32_t rel = blk - v->first_data_block;
    uint32_t g = rel / v->blocks_per_group, idx = rel % v->blocks_per_group;
    uint8_t gd[4096], bm[4096];
    uint32_t gd_per_block = v->block_size / 32;
    uint32_t gdblk = v->gdt_block + g / gd_per_block, goff = (g % gd_per_block) * 32;
    if (rdblk(v, gdblk, gd) < 0) return -1;
    uint32_t bbm = e_rd32(gd + goff + 0);
    if (rdblk(v, bbm, bm) < 0) return -1;
    bm[idx >> 3] &= (uint8_t)~(1 << (idx & 7));
    if (wrblk(v, bbm, bm) < 0) return -1;
    e_wr16(gd + goff + 12, e_rd16(gd + goff + 12) + 1);
    if (wrblk(v, gdblk, gd) < 0) return -1;
    uint8_t sb[1024];
    if (rd_sb(v, sb) < 0) return -1;
    e_wr32(sb + 12, e_rd32(sb + 12) + 1);
    return wr_sb(v, sb);
}

/* Free every data block an inode references — direct (0-11), single-indirect
 * (12) and double-indirect (13), plus the indirect metablocks themselves. */
static void free_inode_blocks(ext2_t *v, const uint8_t *inode) {
    const uint8_t *ib = inode + 40;
    uint32_t ppb = v->block_size / 4;
    uint8_t buf[4096], buf2[4096];
    if (e_rd32(inode + 32) & EXT4_EXTENTS_FL) {            /* extent-mapped (M1189) */
        if (e_rd16(ib) == EXT4_EXT_MAGIC && e_rd16(ib + 6) == 0) {   /* depth-0 leaf: free each extent's run */
            uint32_t ents = e_rd16(ib + 2), maxe = (60 - 12) / 12;
            if (ents > maxe) ents = maxe;
            for (uint32_t i = 0; i < ents; i++) {
                const uint8_t *e = ib + 12 + i * 12;
                uint16_t raw = e_rd16(e + 4);
                uint32_t l = raw > 32768 ? (uint32_t)(raw - 32768) : raw, st = e_rd32(e + 8);
                for (uint32_t j = 0; j < l; j++) free_block(v, st + j);
            }
        }   /* depth>0 trees (only from externally-written files) are left intact; a future pass can reclaim them */
        return;
    }
    for (int i = 0; i < 12; i++) { uint32_t b = e_rd32(ib + i * 4); if (b) free_block(v, b); }
    uint32_t ind = e_rd32(ib + 12 * 4);
    if (ind) {
        if (rdblk(v, ind, buf) == 0)
            for (uint32_t i = 0; i < ppb; i++) { uint32_t b = e_rd32(buf + i * 4); if (b) free_block(v, b); }
        free_block(v, ind);
    }
    uint32_t dind = e_rd32(ib + 13 * 4);
    if (dind) {
        if (rdblk(v, dind, buf) == 0)
            for (uint32_t i = 0; i < ppb; i++) {
                uint32_t ind2 = e_rd32(buf + i * 4); if (!ind2) continue;
                if (rdblk(v, ind2, buf2) == 0)
                    for (uint32_t j = 0; j < ppb; j++) { uint32_t b = e_rd32(buf2 + j * 4); if (b) free_block(v, b); }
                free_block(v, ind2);
            }
        free_block(v, dind);
    }
}

/* PUNCH_HOLE helper (M1153): free the data block at file-relative index `fblk`
 * AND zero its pointer — direct in the inode buffer (caller persists), single/
 * double-indirect in the on-disk indirect block (written back here) — so the
 * file gets a sparse hole there. Returns 1 if a block was freed, 0 if it was
 * already a hole. Indirect METABLOCKS are kept (they validly map all-holes),
 * which is e2fsck-clean. */
static int punch_block(ext2_t *v, uint8_t *inode, uint32_t fblk) {
    uint8_t *ib = inode + 40;
    uint32_t ppb = v->block_size / 4;
    if (fblk < 12) {
        uint32_t b = e_rd32(ib + fblk * 4);
        if (!b) return 0;
        free_block(v, b); e_wr32(ib + fblk * 4, 0);
        return 1;
    }
    fblk -= 12;
    uint8_t buf[4096];
    if (fblk < ppb) {                                   /* single-indirect */
        uint32_t ind = e_rd32(ib + 12 * 4);
        if (!ind || rdblk(v, ind, buf) < 0) return 0;
        uint32_t b = e_rd32(buf + fblk * 4);
        if (!b) return 0;
        free_block(v, b); e_wr32(buf + fblk * 4, 0); wrblk(v, ind, buf);
        return 1;
    }
    fblk -= ppb;
    if (fblk < ppb * ppb) {                             /* double-indirect */
        uint32_t dind = e_rd32(ib + 13 * 4);
        if (!dind || rdblk(v, dind, buf) < 0) return 0;
        uint32_t ind = e_rd32(buf + (fblk / ppb) * 4);
        if (!ind) return 0;
        uint8_t buf2[4096];
        if (rdblk(v, ind, buf2) < 0) return 0;
        uint32_t b = e_rd32(buf2 + (fblk % ppb) * 4);
        if (!b) return 0;
        free_block(v, b); e_wr32(buf2 + (fblk % ppb) * 4, 0); wrblk(v, ind, buf2);
        return 1;
    }
    return 0;
}

/* Release an inode number: clear the inode-bitmap bit + bump the free counts. */
static int free_inode_num(ext2_t *v, uint32_t ino) {
    if (ino == 0) return -1;
    uint32_t g = (ino - 1) / v->inodes_per_group, idx = (ino - 1) % v->inodes_per_group;
    uint8_t gd[4096], bm[4096];
    uint32_t gd_per_block = v->block_size / 32;
    uint32_t gdblk = v->gdt_block + g / gd_per_block, goff = (g % gd_per_block) * 32;
    if (rdblk(v, gdblk, gd) < 0) return -1;
    uint32_t ibm = e_rd32(gd + goff + 4);
    if (rdblk(v, ibm, bm) < 0) return -1;
    bm[idx >> 3] &= (uint8_t)~(1 << (idx & 7));
    if (wrblk(v, ibm, bm) < 0) return -1;
    e_wr16(gd + goff + 14, e_rd16(gd + goff + 14) + 1);
    if (wrblk(v, gdblk, gd) < 0) return -1;
    uint8_t sb[1024];
    if (rd_sb(v, sb) < 0) return -1;
    e_wr32(sb + 16, e_rd32(sb + 16) + 1);
    return wr_sb(v, sb);
}

/* Remove `name` from directory inode `parent_ino`: coalesce its record into the
 * preceding one (or, if it's first in its block, just zero the inode field). */
static int dir_remove(ext2_t *v, uint32_t parent_ino, const char *name) {
    uint8_t pin[256], blk[4096];
    if (read_inode(v, parent_ino, pin) < 0) return -1;
    uint32_t size = e_rd32(pin + 4);
    int nl = 0; while (name[nl]) nl++;
    for (uint32_t off = 0; off < size; off += v->block_size) {
        uint32_t db = map_block(v, pin, off / v->block_size);
        if (!db || rdblk(v, db, blk) < 0) continue;
        uint32_t bo = 0, prev = 0; int have_prev = 0;
        while (bo + 8 <= v->block_size) {
            uint32_t ino = e_rd32(blk + bo);
            uint16_t rl = e_rd16(blk + bo + 4);
            uint8_t enl = blk[bo + 6];
            if (rl < 8 || bo + rl > v->block_size) break;
            if (ino && enl == nl) {
                int match = 1;
                for (int k = 0; k < nl; k++) if (blk[bo + 8 + k] != (uint8_t)name[k]) { match = 0; break; }
                if (match) {
                    if (have_prev) e_wr16(blk + prev + 4, (uint16_t)(e_rd16(blk + prev + 4) + rl));  /* absorb */
                    else           e_wr32(blk + bo, 0);                                              /* first: empty it */
                    return wrblk(v, db, blk);
                }
            }
            prev = bo; have_prev = 1; bo += rl;
        }
    }
    return -1;
}

/* Delete a regular file: free its blocks + inode and unlink its directory entry.
 * Removes a regular file, or (M1145) an EMPTY directory (rmdir). 0/-1. */
static void grp_dirs(ext2_t *v, uint32_t ino, int delta);   /* defined below (M1137) */
/* A directory is empty if it holds nothing but "." and "..". */
static int dir_is_empty(ext2_t *v, const uint8_t *dino) {
    uint32_t size = e_rd32(dino + 4);
    uint8_t blk[4096];
    for (uint32_t off = 0; off < size; off += v->block_size) {
        uint32_t db = map_block(v, dino, off / v->block_size);
        if (!db || rdblk(v, db, blk) < 0) continue;
        uint32_t bo = 0;
        while (bo + 8 <= v->block_size) {
            uint32_t ino = e_rd32(blk + bo); uint16_t rl = e_rd16(blk + bo + 4); uint8_t nl = blk[bo + 6];
            if (rl < 8) break;
            if (ino && nl) {
                int dot = (nl == 1 && blk[bo + 8] == '.') ||
                          (nl == 2 && blk[bo + 8] == '.' && blk[bo + 9] == '.');
                if (!dot) return 0;                    /* a real child -> not empty */
            }
            bo += rl;
        }
    }
    return 1;
}
long ext2_unlink_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                      const char *path) {
    /* EVERY write flushes the path cache WHOLESALE (M2103). Selective
     * invalidation of a path cache needs to know every path a rename, an
     * unlink, a directory grow or a symlink change can affect -- and being
     * wrong once means answering "that file does not exist" about a file
     * that does. One line that cannot be subtly wrong beats a clever one
     * that can. */
    ext2_path_cache_flush();
    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;

    char parent[256], base[256];
    int last = -1, n = 0;
    for (int i = 0; path[i]; i++) { if (path[i] == '/') last = i; n = i + 1; }
    if (last < 0) parent[0] = 0;
    else { int j = 0; for (; j < last && j < 255; j++) parent[j] = path[j]; parent[j] = 0; }
    { int j = 0, s = last + 1; for (; s < n && j < 255; s++, j++) base[j] = path[s]; base[j] = 0; }
    if (base[0] == 0) return -1;

    uint8_t pin[256]; int pdir = 0;
    uint32_t parent_ino = walk(&v, parent, pin, &pdir);
    if (!parent_ino || !pdir) return -1;
    int cd = 0;
    uint32_t ino = dir_lookup(&v, pin, base, &cd);
    if (!ino) return -1;                                    /* absent */
    uint8_t inode[256];
    if (read_inode(&v, ino, inode) < 0) return -1;
    if (cd) {                                               /* rmdir: only an EMPTY directory (M1145) */
        if (!dir_is_empty(&v, inode)) return -1;
        free_inode_blocks(&v, inode);
        e_wr16(inode + 26, 0); e_wr32(inode + 20, 1700000000u);
        e_wr32(inode + 28, 0); for (int i = 0; i < 15; i++) e_wr32(inode + 40 + i * 4, 0);
        write_inode(&v, ino, inode);
        free_inode_num(&v, ino);
        dir_remove(&v, parent_ino, base);
        if (read_inode(&v, parent_ino, pin) >= 0) {         /* the removed dir's ".." dropped a parent link */
            e_wr16(pin + 26, (uint16_t)(e_rd16(pin + 26) - 1));
            write_inode(&v, parent_ino, pin);
        }
        grp_dirs(&v, ino, -1);                              /* one fewer directory in its group */
        return 0;
    }
    /* Drop THIS directory entry, then decrement the link count. With hard links
     * (M1207) the inode may have other names — only free it + its blocks when the
     * LAST link is removed; otherwise the remaining names keep reading the data. */
    dir_remove(&v, parent_ino, base);
    uint16_t lc = e_rd16(inode + 26);
    if (lc > 1) {
        e_wr16(inode + 26, (uint16_t)(lc - 1));           /* one fewer hard link */
        e_stamp(inode);                                   /* ctime changed */
        write_inode(&v, ino, inode);
        return 0;
    }
    free_inode_blocks(&v, inode);
    /* Mark the inode DEAD before clearing its bitmap bit, so a consistency check
     * sees a clean deletion rather than a live-but-unattached inode: links_count
     * = 0, a nonzero deletion time, and no block references / i_blocks. */
    e_wr16(inode + 26, 0);                                /* i_links_count = 0   */
    e_wr32(inode + 20, ext2_clock ? ext2_clock() : 1700000000u);  /* i_dtime: the real epoch (M1175), or a
                                                           * large fallback — a tiny dtime is misread as an
                                                           * orphan-list inode pointer by fsck; a timestamp
                                                           * >> inode count is not */
    e_wr32(inode + 28, 0);                                /* i_blocks = 0        */
    for (int i = 0; i < 15; i++) e_wr32(inode + 40 + i * 4, 0);  /* clear i_block[] */
    write_inode(&v, ino, inode);
    free_inode_num(&v, ino);
    return 0;
}

/* Bump (delta=+1) or drop (delta=-1) a group's bg_used_dirs_count for inode `ino`. */
static void grp_dirs(ext2_t *v, uint32_t ino, int delta) {
    uint32_t g = (ino - 1) / v->inodes_per_group;
    uint8_t gd[4096]; uint32_t gd_per_block = v->block_size / 32;
    uint32_t gdblk = v->gdt_block + g / gd_per_block, goff = (g % gd_per_block) * 32;
    if (rdblk(v, gdblk, gd) < 0) return;
    e_wr16(gd + goff + 16, (uint16_t)(e_rd16(gd + goff + 16) + delta));
    wrblk(v, gdblk, gd);
}

/* Create a directory `path`: a fresh dir inode whose single block holds "." (->
 * itself) and ".." (-> parent); link it into the parent (which gains a link from
 * the new dir's ".."), and bump the group's directory count. M1137. */
long ext2_mkdir_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                     const char *path) {
    ext2_path_cache_flush();   /* wholesale: see the note at ext2_unlink_path (M2103) */
    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;

    char parent[256], base[256];
    int last = -1, n = 0;
    for (int i = 0; path[i]; i++) { if (path[i] == '/') last = i; n = i + 1; }
    if (last < 0) parent[0] = 0;
    else { int j = 0; for (; j < last && j < 255; j++) parent[j] = path[j]; parent[j] = 0; }
    { int j = 0, s = last + 1; for (; s < n && j < 255; s++, j++) base[j] = path[s]; base[j] = 0; }
    if (base[0] == 0) return -1;

    uint8_t pin[256]; int pdir = 0;
    uint32_t parent_ino = walk(&v, parent, pin, &pdir);
    if (!parent_ino || !pdir) return -1;
    if (dir_lookup(&v, pin, base, 0)) return -1;           /* name already taken */

    uint32_t ino = alloc_inode(&v); if (!ino) return -1;
    uint32_t blk = alloc_block(&v);
    if (!blk) { free_inode_num(&v, ino); return -1; }   /* M1616: don't leak the inode we just claimed */

    /* the dir's data block: "." (rec_len 12) then ".." (rec_len = rest of block) */
    uint8_t db[4096];
    for (uint32_t i = 0; i < v.block_size; i++) db[i] = 0;
    e_wr32(db + 0, ino);  e_wr16(db + 4, 12); db[6] = 1; db[7] = 2; db[8] = '.';
    e_wr32(db + 12, parent_ino); e_wr16(db + 16, (uint16_t)(v.block_size - 12));
    db[18] = 2; db[19] = 2; db[20] = '.'; db[21] = '.';
    if (wrblk(&v, blk, db) < 0) { free_block(&v, blk); free_inode_num(&v, ino); return -1; }

    uint8_t inode[256];
    for (uint32_t i = 0; i < v.inode_size; i++) inode[i] = 0;
    e_wr16(inode + 0, 0x4000 | 0x1ED);                     /* i_mode: directory, rwxr-xr-x */
    e_wr32(inode + 4, v.block_size);                       /* i_size = one block          */
    e_wr16(inode + 26, 2);                                 /* i_links_count: itself + "."  */
    e_wr32(inode + 28, v.block_size / 512);                /* i_blocks                     */
    e_wr32(inode + 40, blk);                               /* i_block[0]                   */
    e_stamp(inode);                                        /* i_atime/ctime/mtime = now (M1175) */
    if (write_inode(&v, ino, inode) < 0) { free_block(&v, blk); free_inode_num(&v, ino); return -1; }

    /* dir_add's own comment: "Returns 0, or -1 if no block has room (growing
     * the directory is unsupported)" -- a real, reachable failure (any
     * directory whose one allocated block fills up), not a hardware-error
     * edge case. Without this cleanup, every failed mkdir into a full
     * directory leaked one inode + one block permanently (M1616). */
    if (dir_add(&v, parent_ino, base, ino, 2) < 0) { free_block(&v, blk); free_inode_num(&v, ino); return -1; }   /* ftype 2 = directory */
    if (read_inode(&v, parent_ino, pin) < 0) return -1;         /* parent gains a link (the new dir's "..") */
    e_wr16(pin + 26, (uint16_t)(e_rd16(pin + 26) + 1));
    if (write_inode(&v, parent_ino, pin) < 0) return -1;
    grp_dirs(&v, ino, +1);
    return 0;
}

/* Create a fast symlink `path` -> `target` (target stored inline in i_block,
 * resolved by walk(); M1146). Target must be <= 60 bytes. 0/-1. */
long ext2_symlink_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                       const char *path, const char *target) {
    ext2_path_cache_flush();   /* wholesale: see the note at ext2_unlink_path (M2103) */
    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;
    int tlen = 0; while (target[tlen]) tlen++;
    if (tlen == 0 || tlen > 60) return -1;                 /* fast symlinks only */

    char parent[256], base[256];
    int last = -1, n = 0;
    for (int i = 0; path[i]; i++) { if (path[i] == '/') last = i; n = i + 1; }
    if (last < 0) parent[0] = 0;
    else { int j = 0; for (; j < last && j < 255; j++) parent[j] = path[j]; parent[j] = 0; }
    { int j = 0, s = last + 1; for (; s < n && j < 255; s++, j++) base[j] = path[s]; base[j] = 0; }
    if (base[0] == 0) return -1;

    uint8_t pin[256]; int pdir = 0;
    uint32_t parent_ino = walk(&v, parent, pin, &pdir);
    if (!parent_ino || !pdir) return -1;
    if (dir_lookup(&v, pin, base, 0)) return -1;           /* name already taken */

    uint32_t ino = alloc_inode(&v); if (!ino) return -1;
    uint8_t inode[256];
    for (uint32_t i = 0; i < v.inode_size; i++) inode[i] = 0;
    e_wr16(inode + 0, 0xA000 | 0x1FF);                     /* i_mode: symlink, rwxrwxrwx */
    e_wr32(inode + 4, (uint32_t)tlen);                     /* i_size = target length */
    e_wr16(inode + 26, 1);                                 /* i_links_count = 1 */
    for (int i = 0; i < tlen; i++) inode[40 + i] = (uint8_t)target[i];   /* target inline in i_block */
    e_stamp(inode);                                        /* i_atime/ctime/mtime = now (M1175) */
    if (write_inode(&v, ino, inode) < 0) { free_inode_num(&v, ino); return -1; }
    if (dir_add(&v, parent_ino, base, ino, 7) < 0) { free_inode_num(&v, ino); return -1; }   /* ftype 7 = symlink;
                                                    * don't leak the inode on a full-directory failure (M1616) */
    return 0;
}

/* readlink (M1594): the read counterpart ext2_symlink_path never got. Same
 * parent+base split as symlink/link/rename below -- walk() to the PARENT
 * (following any symlinks along the WAY there, correct: only the FINAL
 * component itself must not be auto-followed) then dir_lookup() the base
 * name directly, exactly like walk_d's OWN inline symlink-decode (a few
 * hundred lines up) does right before it recurses into resolving the
 * target -- this just returns that decoded target instead of following it.
 * Slow symlinks (target too long to fit inline) are unsupported, matching
 * walk_d's own existing limit for auto-following. */
long ext2_readlink_path(blk_read_fn read, void *ctx, uint64_t start_lba,
                        const char *path, void *buf, unsigned long max) {
    ext2_t v;
    if (ext2_open(read, ctx, start_lba, &v) < 0) return -1;

    char parent[256], base[256];
    int last = -1, n = 0;
    for (int i = 0; path[i]; i++) { if (path[i] == '/') last = i; n = i + 1; }
    if (last < 0) parent[0] = 0;
    else { int j = 0; for (; j < last && j < 255; j++) parent[j] = path[j]; parent[j] = 0; }
    { int j = 0, s = last + 1; for (; s < n && j < 255; s++, j++) base[j] = path[s]; base[j] = 0; }
    if (base[0] == 0) return -1;

    uint8_t pin[256]; int pdir = 0;
    uint32_t parent_ino = walk(&v, parent, pin, &pdir);
    if (!parent_ino || !pdir) return -1;
    int cd = 0;
    uint32_t ino = dir_lookup(&v, pin, base, &cd);
    if (!ino) return -1;

    uint8_t inode[256];
    if (read_inode(&v, ino, inode) < 0) return -1;
    if ((e_rd16(inode + 0) & 0xF000) != 0xA000) return -1;   /* not a symlink */
    uint32_t sz = e_rd32(inode + 4);
    if (sz > 60) return -1;                                   /* slow symlink: unsupported (matches walk_d) */
    unsigned long got = (sz < max) ? sz : max;
    for (unsigned long i = 0; i < got; i++) ((char *)buf)[i] = (char)inode[40 + i];
    return (long)got;
}

/* Hard link (M1207): add a second directory entry (newpath) pointing at the SAME
 * inode as oldpath, and bump that inode's link count — POSIX link(2). Directories
 * are refused. ext2_unlink_path already decrements i_links_count and frees the
 * inode only when it hits 0, so removing either name leaves the other working. */
long ext2_link_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                    const char *oldpath, const char *newpath) {
    ext2_path_cache_flush();   /* wholesale: see the note at ext2_unlink_path (M2103) */
    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;

    /* the existing target: must exist and not be a directory */
    uint8_t tin[256]; int tdir = 0;
    uint32_t target_ino = walk(&v, oldpath, tin, &tdir);
    if (!target_ino || tdir) return -1;
    uint8_t ftype = ((e_rd16(tin) & 0xF000) == 0xA000) ? 7 : 1;   /* symlink : regular */

    /* split newpath into its parent directory + the new base name */
    char parent[256], base[256];
    int last = -1, n = 0;
    for (int i = 0; newpath[i]; i++) { if (newpath[i] == '/') last = i; n = i + 1; }
    if (last < 0) parent[0] = 0;
    else { int j = 0; for (; j < last && j < 255; j++) parent[j] = newpath[j]; parent[j] = 0; }
    { int j = 0, s = last + 1; for (; s < n && j < 255; s++, j++) base[j] = newpath[s]; base[j] = 0; }
    if (base[0] == 0) return -1;

    uint8_t pin[256]; int pdir = 0;
    uint32_t parent_ino = walk(&v, parent, pin, &pdir);
    if (!parent_ino || !pdir) return -1;
    if (dir_lookup(&v, pin, base, 0)) return -1;       /* the new name is already taken */

    if (dir_add(&v, parent_ino, base, target_ino, ftype) < 0) return -1;
    e_wr16(tin + 26, (uint16_t)(e_rd16(tin + 26) + 1));   /* i_links_count++ */
    e_stamp(tin);                                          /* ctime */
    if (write_inode(&v, target_ino, tin) < 0) return -1;
    return 0;
}

/* Split `path` into its parent directory + base name (the inline used by
 * write/link/mkdir, factored out for rename's two paths). */
static void path_split(const char *path, char *parent, char *base) {
    int last = -1, n = 0;
    for (int i = 0; path[i]; i++) { if (path[i] == '/') last = i; n = i + 1; }
    if (last < 0) parent[0] = 0;
    else { int j = 0; for (; j < last && j < 255; j++) parent[j] = path[j]; parent[j] = 0; }
    { int j = 0, s = last + 1; for (; s < n && j < 255; s++, j++) base[j] = path[s]; base[j] = 0; }
}
/* Repoint a directory's ".." entry at `new_parent` (when a directory moves to a
 * new parent dir). 0/-1. */
static int dir_set_dotdot(ext2_t *v, uint32_t dir_ino, uint32_t new_parent) {
    uint8_t din[256], blk[4096];
    if (read_inode(v, dir_ino, din) < 0) return -1;
    uint32_t db = map_block(v, din, 0);
    if (!db || rdblk(v, db, blk) < 0) return -1;
    uint32_t bo = 0;
    while (bo + 8 <= v->block_size) {
        uint16_t rl = e_rd16(blk + bo + 4); uint8_t nl = blk[bo + 6];
        if (rl < 8) break;
        if (nl == 2 && blk[bo + 8] == '.' && blk[bo + 9] == '.') { e_wr32(blk + bo, new_parent); return wrblk(v, db, blk); }
        bo += rl;
    }
    return -1;
}
/* Rewrite an existing dirent's inode# + file_type in place, found by name (for
 * RENAME_EXCHANGE, M1232). Returns 0 if rewritten, -1 if the name wasn't found. */
static int dir_set_entry(ext2_t *v, uint32_t dir_ino, const char *name, uint32_t new_ino, uint8_t new_ftype) {
    uint8_t dino[256], blk[4096];
    if (read_inode(v, dir_ino, dino) < 0) return -1;
    uint32_t size = e_rd32(dino + 4);
    for (uint32_t off = 0; off < size; off += v->block_size) {
        uint32_t db = map_block(v, dino, off / v->block_size);
        if (!db || rdblk(v, db, blk) < 0) continue;
        uint32_t bo = 0;
        while (bo + 8 <= v->block_size) {
            uint32_t ino = e_rd32(blk + bo);
            uint16_t rl = e_rd16(blk + bo + 4);
            uint8_t nl = blk[bo + 6];
            if (rl < 8) break;
            if (ino && nl && bo + 8 + nl <= v->block_size) {
                int match = 1;
                for (int k = 0; k < nl; k++) if (name[k] == 0 || (uint8_t)name[k] != blk[bo + 8 + k]) { match = 0; break; }
                if (match && name[nl] == 0) { e_wr32(blk + bo, new_ino); blk[bo + 7] = new_ftype; return wrblk(v, db, blk); }
            }
            bo += rl;
        }
    }
    return -1;
}
/* Is `anc` an ancestor of (or equal to) directory `start`? Climbs ".." to the
 * root inode (2). Used to refuse moving a directory into its own subtree. */
static int is_ancestor(ext2_t *v, uint32_t anc, uint32_t start) {
    uint32_t cur = start;
    for (int i = 0; i < 64 && cur; i++) {
        if (cur == anc) return 1;
        if (cur == 2) break;                               /* reached the root */
        uint8_t din[256]; if (read_inode(v, cur, din) < 0) break;
        int d = 0; uint32_t up = dir_lookup(v, din, "..", &d);
        if (!up || up == cur) break;
        cur = up;
    }
    return 0;
}
/* rename(oldpath, newpath) within one ext2 volume (M1213): relocate a directory
 * entry to (possibly) a new parent, preserving the inode. Same inode + a net-zero
 * link count for the moved name (add the new name, remove the old). Replaces an
 * existing regular-file target; refuses to replace a directory or to move a
 * directory into its own subtree. For a directory moved across parents, fixes its
 * ".." entry and adjusts both parents' link counts (so e2fsck stays clean). 0/-1. */
long ext2_rename_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                      const char *oldpath, const char *newpath) {
    ext2_path_cache_flush();   /* wholesale: see the note at ext2_unlink_path (M2103) */
    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;

    uint8_t sin[256]; int sdir = 0;
    uint32_t src_ino = walk(&v, oldpath, sin, &sdir);
    if (!src_ino) return -1;                               /* source must exist */
    uint8_t ftype = sdir ? 2 : (((e_rd16(sin) & 0xF000) == 0xA000) ? 7 : 1);

    char op[256], ob[256], np[256], nb[256];
    path_split(oldpath, op, ob);
    path_split(newpath, np, nb);
    if (ob[0] == 0 || nb[0] == 0) return -1;
    if (nb[0] == '.' && (nb[1] == 0 || (nb[1] == '.' && nb[2] == 0))) return -1;   /* refuse "." / ".." */

    uint8_t opin[256], npin[256]; int od = 0, nd = 0;
    uint32_t oldp = walk(&v, op, opin, &od);
    uint32_t newp = walk(&v, np, npin, &nd);
    if (!oldp || !od || !newp || !nd) return -1;           /* both parents must be dirs */

    if (sdir && is_ancestor(&v, src_ino, newp)) return -1; /* can't move a dir into itself/subtree */

    int td = 0;
    uint32_t tgt = dir_lookup(&v, npin, nb, &td);
    if (tgt) {
        if (tgt == src_ino) return 0;                      /* same inode (incl. rename-to-self): no-op */
        if (td || sdir) return -1;                         /* refuse replacing a dir / moving a dir onto a file */
        uint8_t tin[256];                                  /* replace a regular-file target: unlink it first */
        if (read_inode(&v, tgt, tin) < 0) return -1;
        if (dir_remove(&v, newp, nb) < 0) return -1;
        uint16_t lc = e_rd16(tin + 26);
        if (lc > 1) { e_wr16(tin + 26, (uint16_t)(lc - 1)); e_stamp(tin); write_inode(&v, tgt, tin); }
        else { free_inode_blocks(&v, tin); free_inode_num(&v, tgt); }
    }

    if (dir_add(&v, newp, nb, src_ino, ftype) < 0) return -1;
    if (dir_remove(&v, oldp, ob) < 0) { dir_remove(&v, newp, nb); return -1; }   /* roll back the add */

    if (sdir && oldp != newp) {                            /* directory moved to a new parent */
        dir_set_dotdot(&v, src_ino, newp);
        uint8_t pb[256];
        if (read_inode(&v, oldp, pb) == 0) { uint16_t l = e_rd16(pb + 26); if (l > 0) e_wr16(pb + 26, (uint16_t)(l - 1)); write_inode(&v, oldp, pb); }
        if (read_inode(&v, newp, pb) == 0) { e_wr16(pb + 26, (uint16_t)(e_rd16(pb + 26) + 1)); write_inode(&v, newp, pb); }
    }

    e_stamp(sin);                                          /* ctime on the moved inode */
    write_inode(&v, src_ino, sin);
    return 0;
}

/* renameat2 flag values (mirror syscall.h's RENAME_*; kept local so ext2.c
 * stays self-contained / host-#include-linkable). */
#define EXT2_RN_NOREPLACE 1
#define EXT2_RN_EXCHANGE  2

/* renameat2 (M1232): rename with flags. flags==0 delegates to the plain M1213
 * rename. RENAME_NOREPLACE fails (-1) if the destination already exists.
 * RENAME_EXCHANGE atomically swaps two existing entries by rewriting each
 * dirent's inode#+file_type (no link-count change — both names persist); it
 * refuses a CROSS-directory exchange when either side is a directory (that would
 * need ".."/parent-link fixups), keeping every result e2fsck-clean. */
long ext2_rename2_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                       const char *oldpath, const char *newpath, int flags) {
    /* THE FIFTEENTH WRITER (M2103). I added the flush to fourteen mutating
     * entry points by listing the ones that take a blk_write_fn -- and missed
     * this one, because renameat2 lives apart from rename. The ext2 suite
     * caught it within a second: EXCHANGE atomically swaps two files, and a
     * cached positive entry for either name is then a pointer to the other
     * one's inode.
     *
     * Which is why the audit that found it is now a shell one-liner in the
     * commit message rather than a memory of having been careful: every
     * function here that takes a write callback must flush, and the way to
     * know is to ask the file, not to remember. */
    ext2_path_cache_flush();
    if (flags == 0) return ext2_rename_path(read, write, ctx, start_lba, oldpath, newpath);
    if ((flags & EXT2_RN_NOREPLACE) && (flags & EXT2_RN_EXCHANGE)) return -1;   /* mutually exclusive */

    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;

    uint8_t sin[256]; int sdir = 0;
    uint32_t src_ino = walk(&v, oldpath, sin, &sdir);
    if (!src_ino) return -1;                               /* source must exist */

    char op[256], ob[256], np[256], nb[256];
    path_split(oldpath, op, ob);
    path_split(newpath, np, nb);
    if (ob[0] == 0 || nb[0] == 0) return -1;

    uint8_t opin[256], npin[256]; int od = 0, nd = 0;
    uint32_t oldp = walk(&v, op, opin, &od);
    uint32_t newp = walk(&v, np, npin, &nd);
    if (!oldp || !od || !newp || !nd) return -1;           /* both parents must be dirs */

    int td = 0;
    uint32_t tgt = dir_lookup(&v, npin, nb, &td);

    if (flags & EXT2_RN_NOREPLACE) {
        if (tgt) return -1;                                /* destination exists -> EEXIST */
        return ext2_rename_path(read, write, ctx, start_lba, oldpath, newpath);   /* now a plain move */
    }

    /* RENAME_EXCHANGE: both must exist; swap the two dirents' inode#+file_type. */
    if (!tgt) return -1;
    if (tgt == src_ino) return 0;                          /* same entry: no-op */
    if ((sdir || td) && oldp != newp) return -1;           /* cross-dir dir exchange: refuse */
    uint8_t ftype_s = sdir ? 2 : (((e_rd16(sin) & 0xF000) == 0xA000) ? 7 : 1);
    uint8_t din[256];
    if (read_inode(&v, tgt, din) < 0) return -1;
    uint8_t ftype_d = td ? 2 : (((e_rd16(din) & 0xF000) == 0xA000) ? 7 : 1);
    if (dir_set_entry(&v, oldp, ob, tgt, ftype_d) < 0) return -1;
    if (dir_set_entry(&v, newp, nb, src_ino, ftype_s) < 0) { dir_set_entry(&v, oldp, ob, src_ino, ftype_s); return -1; }  /* roll back */
    e_stamp(sin); write_inode(&v, src_ino, sin);           /* ctime on both swapped inodes */
    e_stamp(din); write_inode(&v, tgt, din);
    return 0;
}

/* fallocate(PUNCH_HOLE) (M1153): deallocate the WHOLE data blocks fully inside
 * [offset, offset+len) of a regular file, turning that range into a sparse hole
 * that reads back as zeros (the file SIZE is unchanged — KEEP_SIZE semantics).
 * Frees each block + zeros its pointer via punch_block, decrements i_blocks, and
 * persists the inode. Partial edge blocks keep their data (whole-block grain).
 * Returns the number of blocks punched, or -1. */
long ext2_punch_hole(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                     const char *path, uint64_t offset, uint64_t len) {
    ext2_path_cache_flush();   /* wholesale: see the note at ext2_unlink_path (M2103) */
    ext2_t v;
    if (!write || len == 0 || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;
    uint8_t inode[256]; int isdir = 0;
    uint32_t ino = walk(&v, path, inode, &isdir);
    if (!ino || isdir) return -1;
    uint32_t bs = v.block_size;
    uint64_t end = offset + len; if (end < offset) return -1;
    uint32_t first = (uint32_t)((offset + bs - 1) / bs);   /* first block fully inside the range */
    uint32_t last  = (uint32_t)(end / bs);                 /* one past the last fully-inside block */
    int freed = 0;
    uint8_t *ib = inode + 40;
    if (e_rd32(inode + 32) & EXT4_EXTENTS_FL) {
        /* M1614: punch_block only understands the direct/indirect scheme -- for
         * an extent-mapped inode (this driver's own writer sets EXTENTS_FL on
         * every new file when the volume has the feature, so this is the COMMON
         * case, not a rare one) it was misreading the extent header/records as
         * raw block pointers, freeing arbitrary live blocks via free_block() and
         * zeroing the extent tree in place -- silent data loss + free-space
         * corruption from an ordinary fallocate(PUNCH_HOLE) call, no concurrency
         * needed. Same narrow scope as ext2_truncate_path's own extent handling
         * (a single depth-0 extent): refuse rather than corrupt for anything
         * wider (multi-extent trees, depth>0), but unlike truncate (which only
         * ever shrinks from the tail) a punched hole can land at the head, the
         * tail, or strictly inside the extent -- the middle case needs splitting
         * into two extent records, handled below if eh_max has room for one. */
        if (!(e_rd16(ib) == EXT4_EXT_MAGIC && e_rd16(ib + 6) == 0)) return -1;   /* not a depth-0 leaf */
        uint32_t maxe = (60 - 12) / 12;
        uint32_t ents = e_rd16(ib + 2); if (ents > maxe) ents = maxe;
        if (ents > 1) return -1;                            /* multi-extent tree: out of scope, refuse */
        if (ents == 1) {
            uint8_t *ee = ib + 12;
            uint32_t eb = e_rd32(ee + 0);                   /* ee_block: logical start */
            uint32_t elen = e_rd16(ee + 4); if (elen > 32768) elen -= 32768;
            uint32_t estart = e_rd32(ee + 8);               /* ee_start_lo: physical start */
            uint32_t ee_end = eb + elen;                    /* one past the extent's logical end */
            uint32_t lo = first > eb ? first : eb;          /* overlap of [first,last) and [eb,ee_end) */
            uint32_t hi = last < ee_end ? last : ee_end;
            if (lo < hi) {
                if (lo == eb && hi == ee_end) {              /* covers the whole extent */
                    for (uint32_t b = 0; b < elen; b++) { free_block(&v, estart + b); freed++; }
                    e_wr16(ib + 2, 0);
                } else if (lo == eb) {                       /* touches the head: shift start+len forward */
                    uint32_t n = hi - lo;
                    for (uint32_t b = 0; b < n; b++) { free_block(&v, estart + b); freed++; }
                    e_wr32(ee + 0, eb + n); e_wr32(ee + 8, estart + n); e_wr16(ee + 4, (uint16_t)(elen - n));
                } else if (hi == ee_end) {                   /* touches the tail: shrink len */
                    for (uint32_t b = lo - eb; b < elen; b++) { free_block(&v, estart + b); freed++; }
                    e_wr16(ee + 4, (uint16_t)(lo - eb));
                } else if (ents < maxe) {                    /* strictly inside: split into two extents */
                    for (uint32_t b = lo - eb; b < hi - eb; b++) { free_block(&v, estart + b); freed++; }
                    uint8_t *ee2 = ib + 12 + ents * 12;      /* new record right after the existing one */
                    e_wr32(ee2 + 0, hi); e_wr16(ee2 + 4, (uint16_t)(ee_end - hi));
                    e_wr16(ee2 + 6, 0);  e_wr32(ee2 + 8, estart + (hi - eb));
                    e_wr16(ee + 4, (uint16_t)(lo - eb));     /* shrink the first record to just the head piece */
                    e_wr16(ib + 2, (uint16_t)(ents + 1));
                }                                            /* else: no room to split -- leave this hole unpunched */
            }
        }
    } else {
        for (uint32_t fb = first; fb < last; fb++) freed += punch_block(&v, inode, fb);
    }
    if (freed) {
        uint32_t iblk = e_rd32(inode + 28);                /* i_blocks counts 512-byte sectors */
        uint32_t dec = (uint32_t)freed * (bs / 512);
        e_wr32(inode + 28, iblk > dec ? iblk - dec : 0);
        if (write_inode(&v, ino, inode) < 0) return -1;    /* persist zeroed direct pointers + i_blocks */
    }
    return freed;
}

/* truncate (M1228): resize a regular file to `newlen`. Shrink frees the blocks
 * fully beyond newlen (via punch_block) and lowers i_size/i_blocks; grow is
 * sparse — just raise i_size, so the new tail reads back as zeros through the
 * hole path (ext2_pread zero-fills unmapped blocks). 0/-1. */
long ext2_truncate_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                        const char *path, uint64_t newlen) {
    ext2_path_cache_flush();   /* wholesale: see the note at ext2_unlink_path (M2103) */
    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;
    uint8_t inode[256]; int isdir = 0;
    uint32_t ino = walk(&v, path, inode, &isdir);
    if (!ino || isdir) return -1;                          /* regular files only */
    uint32_t bs = v.block_size, old = e_rd32(inode + 4);   /* i_size */
    if ((uint32_t)newlen == old) return 0;
    if ((uint32_t)newlen < old) {                          /* shrink: free blocks fully beyond newlen */
        uint32_t first = ((uint32_t)newlen + bs - 1) / bs; /* # of file-blocks to keep */
        uint32_t last  = (old + bs - 1) / bs;              /* one past the last data block */
        uint8_t *ib = inode + 40;
        int freed = 0;
        if ((e_rd32(inode + 32) & EXT4_EXTENTS_FL) &&      /* extent-mapped (M1189 driver writes one */
            e_rd16(ib) == EXT4_EXT_MAGIC && e_rd16(ib + 6) == 0 && e_rd16(ib + 2) == 1) {
            uint8_t *ee = ib + 12;                         /* contiguous depth-0 leaf extent): shrink ee_len, */
            uint32_t elen = e_rd16(ee + 4);               /* free the trailing physical run. punch_block only */
            if (elen > 32768) elen -= 32768;              /* knows the direct/indirect scheme, so handle this */
            uint32_t estart = e_rd32(ee + 8);             /* layout here. (uninit extents: treat length plainly.) */
            uint32_t keep = first < elen ? first : elen;
            for (uint32_t b = keep; b < elen; b++) { free_block(&v, estart + b); freed++; }
            e_wr16(ee + 4, (uint16_t)keep);
            if (keep == 0) e_wr16(ib + 2, 0);             /* no extents left */
        } else if (!(e_rd32(inode + 32) & EXT4_EXTENTS_FL)) {
            for (uint32_t fb = first; fb < last; fb++) freed += punch_block(&v, inode, fb);
        }
        if (freed) {
            uint32_t iblk = e_rd32(inode + 28), dec = (uint32_t)freed * (bs / 512);
            e_wr32(inode + 28, iblk > dec ? iblk - dec : 0);
        }
        uint32_t poff = (uint32_t)newlen % bs;             /* zero the stale tail of the partial EOF block */
        if (poff) {                                        /* (so a later grow reads back zeros, not old data); */
            uint32_t db = map_block(&v, inode, (uint32_t)newlen / bs);   /* map_block resolves both schemes */
            uint8_t blk[4096];
            if (db && rdblk(&v, db, blk) >= 0) { for (uint32_t k = poff; k < bs; k++) blk[k] = 0; wrblk(&v, db, blk); }
        }
    }
    e_wr32(inode + 4, (uint32_t)newlen);                   /* i_size (grow is sparse) */
    e_stamp(inode);
    return write_inode(&v, ino, inode);
}

/* SEEK_HOLE / SEEK_DATA (M1229): given a byte offset, find the next hole (an
 * unallocated/sparse block) or the next data block at/after `off`, at block
 * granularity. `find_hole` selects which. Returns the offset, or -1 (ENXIO):
 * SEEK_DATA past the last data returns -1; SEEK_HOLE always finds the implicit
 * hole at EOF. map_block resolves both the extent and direct/indirect schemes,
 * so this works on either layout (read-only — no write fn needed). */
long ext2_seek_data_hole(blk_read_fn read, void *ctx, uint64_t start_lba,
                         const char *path, long off, int find_hole) {
    ext2_t v;
    if (ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    uint8_t inode[256]; int isdir = 0;
    if (!walk(&v, path, inode, &isdir) || isdir) return -1;
    uint32_t size = e_rd32(inode + 4);
    if (off < 0 || (uint32_t)off >= size) return -1;       /* ENXIO: at/after EOF */
    uint32_t bs = v.block_size;
    uint32_t nblocks = (size + bs - 1) / bs;
    for (uint32_t fb = (uint32_t)off / bs; fb < nblocks; fb++) {
        int hole = (map_block(&v, inode, fb) == 0);
        if (hole == find_hole) {                           /* the block kind we're after */
            uint32_t bstart = fb * bs;
            return bstart > (uint32_t)off ? (long)bstart : off;  /* clamp to off if it's inside this block */
        }
    }
    return find_hole ? (long)size : -1;                    /* SEEK_HOLE: hole at EOF; SEEK_DATA: ENXIO */
}

/* utimensat backend (M1230): set i_atime / i_mtime to the given Unix epochs.
 * A negative value leaves that field unchanged (the caller maps UTIME_OMIT to
 * <0 and resolves UTIME_NOW to a concrete epoch before calling, so ext2.c stays
 * free of syscall.h). i_ctime is bumped to "now" since metadata changed. */
long ext2_utimes_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                      const char *path, long atime, long mtime) {
    /* No flush: mode, owner and times are not in the path cache (M2140). */
    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;
    uint8_t inode[256]; int isdir = 0;
    uint32_t ino = walk(&v, path, inode, &isdir);          /* files and dirs both (touch -d a dir) */
    if (!ino) return -1;
    if (atime >= 0) e_wr32(inode + 8,  (uint32_t)atime);   /* i_atime */
    if (mtime >= 0) e_wr32(inode + 16, (uint32_t)mtime);   /* i_mtime */
    e_wr32(inode + 12, ext2_clock ? ext2_clock() : 0);     /* i_ctime: metadata changed now */
    return write_inode(&v, ino, inode);
}

/* chmod(2) backend (M1241): replace i_mode's permission bits (low 12) while
 * preserving the file-type bits (high nibble: regular/dir/symlink). i_ctime is
 * bumped since metadata changed. Files and directories both. Returns 0/-1. */
long ext2_chmod_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                     const char *path, uint32_t mode) {
    /* No flush: mode, owner and times are not in the path cache (M2140). */
    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;
    uint8_t inode[256]; int isdir = 0;
    uint32_t ino = walk(&v, path, inode, &isdir);
    if (!ino) return -1;
    uint16_t cur = e_rd16(inode + 0);
    e_wr16(inode + 0, (uint16_t)((cur & 0xF000) | (mode & 0x0FFF)));   /* keep type, set perms */
    e_wr32(inode + 12, ext2_clock ? ext2_clock() : 0);                /* i_ctime */
    return write_inode(&v, ino, inode);
}

/* chown(2) backend (M1243): set i_uid (offset 2) / i_gid (offset 24). A negative
 * id leaves that field unchanged (POSIX chown(-1) semantics; keeps ext2.c free of
 * syscall.h). i_ctime is bumped. Files and directories both. Returns 0/-1. */
long ext2_chown_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                     const char *path, long uid, long gid) {
    /* No flush: mode, owner and times are not in the path cache (M2140). */
    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;
    uint8_t inode[256]; int isdir = 0;
    uint32_t ino = walk(&v, path, inode, &isdir);
    if (!ino) return -1;
    if (uid >= 0) e_wr16(inode + 2,  (uint16_t)uid);   /* i_uid (low 16) */
    if (gid >= 0) e_wr16(inode + 24, (uint16_t)gid);   /* i_gid (low 16) */
    e_wr32(inode + 12, ext2_clock ? ext2_clock() : 0); /* i_ctime */
    return write_inode(&v, ino, inode);
}

/* Rebuild an extent-mapped file's mapping as an indirect tree, IN PLACE and
 * without moving a single data block: snapshot the extent root out of
 * i_block[], clear it, then re-point every logical block at the same physical
 * block through bmap_install. Needed because bmap_alloc cannot grow an extent
 * tree, and appending to a file this driver created (which takes the
 * single-extent fast path) is an entirely ordinary thing to do. (M1934)
 *
 * Only depth-0 trees are converted. A deeper tree keeps its index blocks on
 * disk, and those would be orphaned by the rewrite — refusing is honest;
 * leaking them silently is not. */
static int extent_to_indirect(ext2_t *v, uint8_t *inode, uint32_t *charged) {
    uint8_t eh[60];
    memcpy(eh, inode + 40, 60);                            /* snapshot before we clobber i_block[] */
    if (e_rd16(eh + 0) != EXT4_EXT_MAGIC) return -1;
    if (e_rd16(eh + 6) != 0) return -1;                    /* eh_depth > 0: see above */
    uint32_t size = e_rd32(inode + 4);
    uint32_t nb = (uint32_t)((size + v->block_size - 1) / v->block_size);

    for (int i = 0; i < 15; i++) e_wr32(inode + 40 + i * 4, 0);
    e_wr32(inode + 32, e_rd32(inode + 32) & ~EXT4_EXTENTS_FL);
    for (uint32_t fb = 0; fb < nb; fb++) {
        uint32_t phys = extent_map(v, eh, fb);
        if (!phys) continue;                               /* sparse: leave the hole a hole */
        if (bmap_install(v, inode, fb, phys, charged) < 0) return -1;
    }
    return 0;
}

/* Positional write: put `len` bytes at byte offset `off` in `path`, creating
 * the file if absent and extending it as needed. Returns `len`, or -1.
 *
 * This is the STREAMING counterpart of ext2_write_path below, which takes the
 * whole file as one in-memory buffer — fine for a config file, impossible for
 * a 200 MB toolchain binary. Only the blocks the write actually touches are
 * read, modified and written back, so cost is proportional to `len` rather
 * than to the file size, and a caller can build an arbitrarily large file from
 * a small buffer. (M1934)
 *
 * A write starting past EOF leaves a genuine sparse hole: unmapped blocks read
 * back as zeroes via map_block, which is what ext2 semantics call for. */
/* WHY THIS ONE DOES NOT FLUSH THE PATH CACHE (M2140).
 *
 * M2103's rule -- every mutating entry point drops the whole cache -- is right
 * for anything that changes the NAMESPACE, because selective invalidation of a
 * path cache has to know every path a rename or an unlink can affect and being
 * wrong once means answering "no such file" about a file that exists.
 *
 * It is the wrong rule here, and the reason is in what the cache actually
 * stores: `{ path, ino, used, isdir, negative }`. No inode bytes, no size, no
 * timestamps. Writing a file's DATA, or changing its mode, owner or times,
 * cannot falsify any of those fields -- the path still names the same inode
 * and it is still not a directory. Only CREATING a name can, by falsifying a
 * negative entry, and that case still flushes below.
 *
 * The cost of getting this wrong was the whole of Firefox's time-to-page.
 * Firefox writes ~25 times a second during startup; each write dropped 256
 * cached path resolutions, so every subsequent lookup in the system re-walked
 * from the volume root. Measured per-syscall thread time: pwrite64 cost about
 * 13.8 SECONDS in every 15 seconds of wall clock -- one thread inside write()
 * 92% of the time, ~37 ms for a single write -- and none of it was the write. */
long ext2_pwrite_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                      const char *path, uint64_t off, const void *buf, unsigned long len) {
    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;
    if (len == 0) return 0;
    if (off + len > 0xFFFFFFFFull) return -1;              /* i_size is 32-bit here */

    /* split `path` into parent directory + base filename (as ext2_write_path) */
    char parent[256], base[256];
    int last = -1, n = 0;
    for (int i = 0; path[i]; i++) { if (path[i] == '/') last = i; n = i + 1; }
    if (last < 0) { parent[0] = 0; }
    else { int j = 0; for (; j < last && j < 255; j++) parent[j] = path[j]; parent[j] = 0; }
    { int j = 0, s = last + 1; for (; s < n && j < 255; s++, j++) base[j] = path[s]; base[j] = 0; }
    if (base[0] == 0) return -1;

    uint8_t pin[256]; int pdir = 0;
    uint32_t parent_ino = walk(&v, parent, pin, &pdir);
    if (!parent_ino || !pdir) return -1;
    int cd = 0;
    uint32_t existing = dir_lookup(&v, pin, base, &cd);
    if (existing && cd) return -1;                         /* it's a directory */
    /* Creating a name DOES change the namespace: a negative entry for this
     * path would now be a lie. Overwriting an existing one changes nothing the
     * cache holds -- see the note above this function. (M2140) */
    if (!existing) ext2_path_cache_flush();

    uint8_t inode[256]; uint32_t ino; uint32_t charged = 0;
    if (existing) {
        ino = existing;
        if (read_inode(&v, ino, inode) < 0) return -1;
        if ((e_rd32(inode + 32) & EXT4_EXTENTS_FL) &&
            extent_to_indirect(&v, inode, &charged) < 0) return -1;
    } else {
        if (!(ino = alloc_inode(&v))) return -1;
        for (uint32_t i = 0; i < v.inode_size; i++) inode[i] = 0;
        e_wr16(inode + 0, 0x8000 | 0x1A4);                 /* regular file, rw-r--r-- */
        e_wr16(inode + 26, 1);                             /* i_links_count */
    }

    uint32_t size = e_rd32(inode + 4);
    uint32_t first = (uint32_t)(off / v.block_size), last_b = (uint32_t)((off + len - 1) / v.block_size);
    uint8_t blk[4096];

    for (uint32_t fb = first; fb <= last_b; fb++) {
        uint32_t bstart = fb * v.block_size;               /* this block's byte range */
        uint32_t lo = (off > bstart) ? (uint32_t)(off - bstart) : 0;
        uint32_t hi = ((off + len) < (uint64_t)bstart + v.block_size)
                        ? (uint32_t)(off + len - bstart) : v.block_size;
        uint32_t db = bmap_alloc(&v, inode, fb, &charged);
        if (!db) goto fail;

        if (lo == 0 && hi == v.block_size) {               /* full block: no read needed */
            memcpy(blk, (const uint8_t *)buf + (bstart - off), v.block_size);
        } else {                                           /* partial: read-modify-write */
            /* A block inside the old file must be preserved around the edit;
             * one past EOF (or a hole) has no contents to preserve and must
             * read as zeroes, not as whatever the recycled block held. */
            if (bstart < size) { if (rdblk(&v, db, blk) < 0) goto fail; }
            else               { memset(blk, 0, v.block_size); }
            const uint8_t *src = (const uint8_t *)buf + (bstart + lo - off);
            memcpy(blk + lo, src, hi - lo);
        }
        if (wrblk(&v, db, blk) < 0) goto fail;
    }

    if ((uint32_t)(off + len) > size) e_wr32(inode + 4, (uint32_t)(off + len));   /* i_size grows only */
    e_wr32(inode + 28, e_rd32(inode + 28) + charged * (v.block_size / 512));      /* i_blocks */
    e_stamp(inode);
    if (write_inode(&v, ino, inode) < 0) goto fail;
    if (!existing && dir_add(&v, parent_ino, base, ino, 1) < 0) goto fail;
    return (long)len;

fail:
    /* Blocks allocated by THIS call are already recorded in the in-memory inode
     * (and in any indirect block, which bslot_set wrote through). For a CREATE
     * nothing is reachable yet, so freeing the inode number is enough and
     * free_inode_blocks cleans the tree. For an EXTEND of an existing file we
     * deliberately commit what did land: the inode's old contents are still
     * intact and the extra mapped blocks are real, so writing i_blocks back
     * keeps the accounting honest rather than leaving them unaccounted. */
    if (!existing) { free_inode_blocks(&v, inode); free_inode_num(&v, ino); }
    else {
        e_wr32(inode + 28, e_rd32(inode + 28) + charged * (v.block_size / 512));
        write_inode(&v, ino, inode);
    }
    return -1;
}

long ext2_write_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                     const char *path, const void *buf, unsigned long len) {
    ext2_path_cache_flush();   /* wholesale: see the note at ext2_unlink_path (M2103) */
    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;

    /* split `path` into parent directory + base filename */
    char parent[256], base[256];
    int last = -1, n = 0;
    for (int i = 0; path[i]; i++) { if (path[i] == '/') last = i; n = i + 1; }
    if (last < 0) { parent[0] = 0; }
    else { int j = 0; for (; j < last && j < 255; j++) parent[j] = path[j]; parent[j] = 0; }
    { int j = 0, s = last + 1; for (; s < n && j < 255; s++, j++) base[j] = path[s]; base[j] = 0; }
    if (base[0] == 0) return -1;                           /* no filename */

    uint8_t pin[256]; int pdir = 0;
    uint32_t parent_ino = walk(&v, parent, pin, &pdir);
    if (!parent_ino || !pdir) return -1;                   /* parent dir must exist */
    int cd = 0;
    uint32_t existing = dir_lookup(&v, pin, base, &cd);
    if (existing && cd) return -1;                         /* a directory already owns that name */

    uint32_t ppb = v.block_size / 4;
    uint32_t nblocks = (uint32_t)((len + v.block_size - 1) / v.block_size);
    if (nblocks > 12 + ppb) return -1;                     /* beyond direct + single-indirect */

    uint8_t inode[256]; uint32_t ino;
    if (existing) {                                        /* OVERWRITE: reuse the inode, free its old data (M1135) */
        ino = existing;
        if (read_inode(&v, ino, inode) < 0) return -1;
        free_inode_blocks(&v, inode);
        for (int i = 0; i < 15; i++) e_wr32(inode + 40 + i * 4, 0);   /* drop the stale block pointers */
        e_wr32(inode + 32, e_rd32(inode + 32) & ~EXT4_EXTENTS_FL);    /* overwrite rebuilds via indirect (M1189) */
    } else {                                               /* CREATE: a fresh inode + dir entry */
        ino = alloc_inode(&v);
        if (!ino) return -1;
        for (uint32_t i = 0; i < v.inode_size; i++) inode[i] = 0;
        e_wr16(inode + 0, 0x8000 | 0x1A4);                 /* i_mode: regular file, rw-r--r-- */
        e_wr16(inode + 26, 1);                             /* i_links_count = 1 */
    }

    uint8_t blk[4096], ind[4096];

    /* M1189: on an `extent`-feature fs, place a NEW file as a single CONTIGUOUS
     * extent (what ext4 produces; e2fsck-clean). Falls through to the direct/
     * indirect path below if the feature is off or no contiguous run fits. */
    if (!existing && (v.feat_incompat & 0x40) && nblocks > 0 && nblocks <= 32768) {
        uint32_t start = alloc_run(&v, nblocks);
        if (start) {
            for (uint32_t fb = 0; fb < nblocks; fb++) {
                uint32_t boff = fb * v.block_size, chunk = (uint32_t)len - boff;
                if (chunk > v.block_size) chunk = v.block_size;
                memcpy(blk, (const uint8_t *)buf + boff, chunk);
                if (chunk < v.block_size) memset(blk + chunk, 0, v.block_size - chunk);
                if (wrblk(&v, start + fb, blk) < 0) {          /* disk error mid-run: free the whole run + inode (M1745) */
                    for (uint32_t k = 0; k < nblocks; k++) free_block(&v, start + k);
                    free_inode_num(&v, ino);
                    return -1;
                }
            }
            uint8_t *eh = inode + 40;                          /* extent header in i_block[] */
            for (int i = 0; i < 15; i++) e_wr32(inode + 40 + i * 4, 0);
            e_wr16(eh + 0, EXT4_EXT_MAGIC);                    /* eh_magic 0xF30A */
            e_wr16(eh + 2, 1);                                 /* eh_entries = 1 */
            e_wr16(eh + 4, 4);                                 /* eh_max (i_block holds 4) */
            e_wr16(eh + 6, 0);                                 /* eh_depth = 0 (leaf) */
            e_wr32(eh + 8, 0);                                 /* eh_generation */
            uint8_t *ee = eh + 12;                             /* the one extent */
            e_wr32(ee + 0, 0);                                 /* ee_block (logical start) */
            e_wr16(ee + 4, (uint16_t)nblocks);                 /* ee_len */
            e_wr16(ee + 6, 0);                                 /* ee_start_hi (32-bit fs) */
            e_wr32(ee + 8, start);                             /* ee_start_lo */
            e_wr32(inode + 32, e_rd32(inode + 32) | EXT4_EXTENTS_FL);
            e_wr32(inode + 4, (uint32_t)len);                  /* i_size */
            e_wr32(inode + 28, nblocks * (v.block_size / 512)); /* i_blocks */
            e_stamp(inode);
            if (write_inode(&v, ino, inode) < 0) return -1;
            /* dir_add's own comment: growing the directory is unsupported, so a
             * full directory is a real, reachable failure here -- without this,
             * it leaked the new inode AND its whole extent run (M1616). Reuses
             * free_inode_blocks rather than duplicating the extent-vs-direct/
             * indirect freeing logic; `inode` already has the extent fully set. */
            if (dir_add(&v, parent_ino, base, ino, 1) < 0) { free_inode_blocks(&v, inode); free_inode_num(&v, ino); return -1; }
            return (long)len;
        }
        /* no contiguous run -> fall through to direct/indirect below */
    }

    /* Allocate + write the data blocks (+ a single-indirect block if needed). On
     * ANY failure we must undo everything allocated THIS call, else we leak the
     * inode + blocks (CREATE) or -- worse -- leave the on-disk inode pointing at
     * the OLD blocks we already freed at the top (OVERWRITE) => cross-linked
     * blocks + silent corruption. Each data block is RECORDED in inode[]/ind[]
     * BEFORE its wrblk, so `fail_free` frees exactly what was allocated. (M1745;
     * the M1616 fix only covered the two dir_add failures, not these earlier ones,
     * which FAT32 already handles via free_chain -- fat32.c:533.) */
    uint32_t indirect = 0, isectors = 0, fb = 0;
    for (fb = 0; fb < nblocks; fb++) {
        uint32_t db = alloc_block(&v);
        if (!db) goto fail_free;                           /* out of space */
        isectors += v.block_size / 512;
        if (fb < 12) e_wr32(inode + 40 + fb * 4, db);      /* record before writing */
        else {
            if (!indirect) {
                indirect = alloc_block(&v);
                if (!indirect) { free_block(&v, db); goto fail_free; }   /* db not yet in ind[] */
                memset(ind, 0, v.block_size);
                isectors += v.block_size / 512;
                e_wr32(inode + 40 + 12 * 4, indirect);
            }
            e_wr32(ind + (fb - 12) * 4, db);
        }
        uint32_t boff = fb * v.block_size, chunk = (uint32_t)len - boff;
        if (chunk > v.block_size) chunk = v.block_size;
        memcpy(blk, (const uint8_t *)buf + boff, chunk);
        if (chunk < v.block_size) memset(blk + chunk, 0, v.block_size - chunk);
        if (wrblk(&v, db, blk) < 0) goto fail_free;        /* db already recorded => fail_free frees it */
    }
    if (indirect && wrblk(&v, indirect, ind) < 0) goto fail_free;

    e_wr32(inode + 4, (uint32_t)len);                      /* i_size */
    e_wr32(inode + 28, isectors);                          /* i_blocks (in 512-byte sectors) */
    e_stamp(inode);                                        /* i_atime/ctime/mtime = now (M1175) */
    if (write_inode(&v, ino, inode) < 0) goto fail_free;
    if (!existing && dir_add(&v, parent_ino, base, ino, 1) < 0) goto fail_free;   /* ftype 1 = regular file */
    return (long)len;

fail_free:   /* undo THIS call's allocations, leaving the fs consistent (M1745) */
    for (int i = 0; i < 12; i++) { uint32_t b = e_rd32(inode + 40 + i * 4); if (b) free_block(&v, b); }
    if (indirect) {
        uint32_t ppb2 = v.block_size / 4;
        for (uint32_t i = 0; i < ppb2; i++) { uint32_t b = e_rd32(ind + i * 4); if (b) free_block(&v, b); }
        free_block(&v, indirect);
    }
    if (existing) {   /* OVERWRITE: old blocks already freed -> leave a CONSISTENT empty inode, never dangling refs */
        for (int i = 0; i < 15; i++) e_wr32(inode + 40 + i * 4, 0);
        e_wr32(inode + 4, 0); e_wr32(inode + 28, 0); e_stamp(inode);
        write_inode(&v, ino, inode);
    } else {          /* CREATE: release the inode number we reserved */
        free_inode_num(&v, ino);
    }
    return -1;
}

/* ---- extended attributes (in-inode EA, user.* namespace) --------------------
 * M1182. Stores xattrs in the inode's spare space (needs a >=256-byte inode):
 *   inode+128: i_extra_isize = 32 (le16)
 *   inode+160 (=128+extra_isize): magic 0xEA020000 (le32)
 *   inode+164: ext2_xattr_entry[] { name_len:u8, name_index:u8(1=user),
 *              value_offs:le16 (relative to +164), value_block:le32=0,
 *              value_size:le32, e_hash:le32 } + name[name_len], padded to 4;
 *              a zero name_len terminates the list.
 *   values are packed from the inode's end growing down, each slot round_up(len,4).
 * e_hash is 0 for in-inode EAs (e2fsck accepts it) — no hash to compute.
 * Only the user.* namespace; name stored without the "user." prefix. Larger
 * xattrs (needing a separate EA block) are out of scope. */
#define EXT2_XATTR_MAGIC 0xEA020000u
static uint32_t xa_strlen(const char *s) { uint32_t n = 0; while (s[n]) n++; return n; }
/* split "user.NAME" -> NAME (returns the suffix) or 0 if not the user namespace */
static const char *xa_user(const char *name) {
    const char *p = "user.";
    for (int i = 0; i < 5; i++) if (name[i] != p[i]) return 0;
    return name[5] ? name + 5 : 0;
}

/* xattr limits. Small attrs live in the inode's ~92 spare bytes; when they
 * overflow that (or the value is large), the whole set spills to one EA block
 * referenced by i_file_acl (M1184). XA_VAL is bounded so the ents[] working set
 * stays small on the kernel stack. */
#define XA_MAX   6      /* distinct user.* attrs per inode */
#define XA_NAME  40     /* max name length (sans "user.") */
#define XA_VAL   200    /* max value length (block-stored when it won't fit in-inode) */
struct xa_ent { uint8_t idx, nl; uint32_t vsz; uint8_t nm[XA_NAME]; uint8_t vl[XA_VAL]; };

/* ext2 per-entry xattr hash (Linux ext2_xattr_hash_entry). REQUIRED for block
 * EAs (e2fsck rejects a zero entry hash there); in-inode entries use 0. Rolling
 * hash: name bytes (shift 5), then the value as LE32 words zero-padded (shift
 * 16). Verified byte-exact against a debugfs-created reference block. */
static uint32_t xa_hash_entry(const uint8_t *name, uint32_t nlen, const uint8_t *val, uint32_t vsz) {
    uint32_t h = 0;
    for (uint32_t i = 0; i < nlen; i++) h = (h << 5) ^ (h >> 27) ^ name[i];
    if (vsz) {
        uint32_t nwords = (vsz + 3) >> 2;                /* ceil(vsz/4); value zero-padded */
        for (uint32_t w = 0; w < nwords; w++) {
            uint32_t word = 0;
            for (int b = 0; b < 4; b++) { uint32_t k = w * 4 + b; if (k < vsz) word |= (uint32_t)val[k] << (b * 8); }
            h = (h << 16) ^ (h >> 16) ^ word;
        }
    }
    return h;
}

/* Append the in-inode EA set to ents[] (from *ne_io), skipping the user.* entry
 * named `skip` (if non-NULL). Updates *ne_io. Returns 0, or -1 on bad/absent magic. */
static int xa_parse(const uint8_t *inode, uint32_t inode_size, struct xa_ent *ents, int *ne_io,
                    const char *skip, uint32_t skip_nl) {
    uint32_t extra = e_rd16(inode + 128);
    if (extra < 4 || 128 + extra + 4 > inode_size) return -1;
    uint32_t magic_off = 128 + extra, ebase = magic_off + 4;
    if (e_rd32(inode + magic_off) != EXT2_XATTR_MAGIC) return -1;
    int ne = *ne_io;
    for (uint32_t e = ebase; e + 16 <= inode_size; ) {
        uint8_t enl = inode[e]; if (enl == 0) break;        /* terminator */
        if (e + 16 + enl > inode_size) break;
        uint8_t idx = inode[e + 1];
        uint32_t voffs = e_rd16(inode + e + 2), vsz = e_rd32(inode + e + 8), vpos = ebase + voffs;
        int is_skip = (skip && idx == 1 && enl == skip_nl);
        if (is_skip) for (uint32_t i = 0; i < enl; i++) if (inode[e + 16 + i] != (uint8_t)skip[i]) { is_skip = 0; break; }
        if (!is_skip && ne < XA_MAX && enl <= XA_NAME && vsz <= XA_VAL &&
            voffs < inode_size && vpos + vsz <= inode_size && vpos >= ebase) {
            ents[ne].idx = idx; ents[ne].nl = enl; ents[ne].vsz = vsz;
            for (uint32_t i = 0; i < enl; i++) ents[ne].nm[i] = inode[e + 16 + i];
            for (uint32_t i = 0; i < vsz; i++) ents[ne].vl[i] = inode[vpos + i];
            ne++;
        }
        e += (16 + enl + 3) & ~3u;
    }
    *ne_io = ne;
    return 0;
}

/* Append the EA block (i_file_acl) set to ents[] (from *ne_io), skipping `skip`.
 * Block entries' value_offs are relative to the block start. own 4 KiB buffer. */
static int xa_parse_block(ext2_t *v, uint32_t facl, struct xa_ent *ents, int *ne_io,
                          const char *skip, uint32_t skip_nl) {
    if (!facl) return 0;
    uint8_t blk[4096];
    if (rdblk(v, facl, blk) < 0 || e_rd32(blk + 0) != EXT2_XATTR_MAGIC) return -1;
    uint32_t bs = v->block_size; if (bs > sizeof blk) bs = sizeof blk;
    int ne = *ne_io;
    for (uint32_t e = 32; e + 16 <= bs; ) {                  /* entries start after the 32-byte header */
        uint8_t enl = blk[e]; if (enl == 0) break;
        if (e + 16 + enl > bs) break;
        uint8_t idx = blk[e + 1];
        uint32_t voffs = e_rd16(blk + e + 2), vsz = e_rd32(blk + e + 8), vpos = voffs;  /* block-relative */
        int is_skip = (skip && idx == 1 && enl == skip_nl);
        if (is_skip) for (uint32_t i = 0; i < enl; i++) if (blk[e + 16 + i] != (uint8_t)skip[i]) { is_skip = 0; break; }
        if (!is_skip && ne < XA_MAX && enl <= XA_NAME && vsz <= XA_VAL &&
            voffs < bs && vpos + vsz <= bs && vpos >= 32) {
            ents[ne].idx = idx; ents[ne].nl = enl; ents[ne].vsz = vsz;
            for (uint32_t i = 0; i < enl; i++) ents[ne].nm[i] = blk[e + 16 + i];
            for (uint32_t i = 0; i < vsz; i++) ents[ne].vl[i] = blk[vpos + i];
            ne++;
        }
        e += (16 + enl + 3) & ~3u;
    }
    *ne_io = ne;
    return 0;
}

/* Collect the WHOLE xattr set (in-inode then block) into ents[], skipping `skip`.
 * Returns the count. */
static int xa_collect(ext2_t *v, const uint8_t *inode, struct xa_ent *ents,
                      const char *skip, uint32_t skip_nl) {
    int ne = 0;
    xa_parse(inode, v->inode_size, ents, &ne, skip, skip_nl);
    xa_parse_block(v, e_rd32(inode + 104), ents, &ne, skip, skip_nl);
    return ne;
}

/* Rewrite the in-inode EA set from ents[ne]: magic, entries from the region
 * start, values packed from the inode end. ne==0 clears it (no magic). Returns
 * 0, or -1 if it won't fit in-inode (caller should spill to a block). */
static int xa_write(uint8_t *inode, uint32_t inode_size, struct xa_ent *ents, int ne) {
    uint32_t extra = 32, magic_off = 128 + extra, ebase = magic_off + 4;
    uint32_t need = 4;                                       /* terminator */
    for (int i = 0; i < ne; i++) need += ((16u + ents[i].nl + 3) & ~3u) + ((ents[i].vsz + 3) & ~3u);
    if (ne > 0 && ebase + need > inode_size) return -1;      /* won't fit in-inode */
    e_wr16(inode + 128, (uint16_t)extra);                   /* i_extra_isize */
    for (uint32_t i = magic_off; i < inode_size; i++) inode[i] = 0;   /* clear EA region */
    if (ne == 0) return 0;                                   /* no attrs -> no magic, clean */
    e_wr32(inode + magic_off, EXT2_XATTR_MAGIC);
    uint32_t ep = ebase, vp = inode_size;
    for (int i = 0; i < ne; i++) {
        vp -= (ents[i].vsz + 3) & ~3u;                       /* value slot, packed downward */
        inode[ep] = ents[i].nl; inode[ep + 1] = ents[i].idx;
        e_wr16(inode + ep + 2, (uint16_t)(vp - ebase));      /* value_offs (rel to ebase) */
        e_wr32(inode + ep + 4, 0);                           /* value_block */
        e_wr32(inode + ep + 8, ents[i].vsz);                 /* value_size */
        e_wr32(inode + ep + 12, 0);                          /* e_hash = 0 (in-inode) */
        for (uint32_t j = 0; j < ents[i].nl; j++) inode[ep + 16 + j] = ents[i].nm[j];
        for (uint32_t j = 0; j < ents[i].vsz; j++) inode[vp + j] = ents[i].vl[j];
        ep += (16u + ents[i].nl + 3) & ~3u;
    }
    return 0;
}

/* Write ents[ne] as an EA block into the (already-allocated) block `facl`:
 * 32-byte header (magic, refcount=1, blocks=1, h_hash=0), entries from +32 with
 * the REQUIRED per-entry hash, values packed from the block end (value_offs
 * block-relative). own 4 KiB buffer. Returns 0, or -1 (won't fit / I/O). */
static int xa_write_block(ext2_t *v, uint32_t facl, struct xa_ent *ents, int ne) {
    uint8_t blk[4096];
    uint32_t bs = v->block_size; if (bs > sizeof blk) return -1;
    for (uint32_t i = 0; i < bs; i++) blk[i] = 0;
    e_wr32(blk + 0, EXT2_XATTR_MAGIC); e_wr32(blk + 4, 1); e_wr32(blk + 8, 1); e_wr32(blk + 12, 0);
    uint32_t need = 32 + 4;
    for (int i = 0; i < ne; i++) need += ((16u + ents[i].nl + 3) & ~3u) + ((ents[i].vsz + 3) & ~3u);
    if (need > bs) return -1;
    uint32_t ep = 32, vp = bs;
    for (int i = 0; i < ne; i++) {
        vp -= (ents[i].vsz + 3) & ~3u;
        blk[ep] = ents[i].nl; blk[ep + 1] = ents[i].idx;
        e_wr16(blk + ep + 2, (uint16_t)vp);                  /* value_offs (block-relative) */
        e_wr32(blk + ep + 4, 0);                             /* value_block */
        e_wr32(blk + ep + 8, ents[i].vsz);                   /* value_size */
        for (uint32_t j = 0; j < ents[i].nl; j++) blk[ep + 16 + j] = ents[i].nm[j];
        for (uint32_t j = 0; j < ents[i].vsz; j++) blk[vp + j] = ents[i].vl[j];
        e_wr32(blk + ep + 12, xa_hash_entry(ents[i].nm, ents[i].nl, ents[i].vl, ents[i].vsz));  /* e_hash */
        ep += (16u + ents[i].nl + 3) & ~3u;
    }
    return wrblk(v, facl, blk);
}

/* Detach the EA block (free it, clear i_file_acl, decrement i_blocks). */
static void xa_drop_block(ext2_t *v, uint8_t *inode) {
    uint32_t facl = e_rd32(inode + 104);
    if (!facl) return;
    free_block(v, facl);
    e_wr32(inode + 104, 0);
    uint32_t ib = e_rd32(inode + 28), d = v->block_size / 512;
    e_wr32(inode + 28, ib > d ? ib - d : 0);
}

/* Persist ents[ne] for inode `ino`: in-inode if it fits (freeing any old block),
 * else spill the whole set to one EA block. Returns 0, or -1. */
static int xa_save(ext2_t *v, uint32_t ino, uint8_t *inode, struct xa_ent *ents, int ne) {
    if (xa_write(inode, v->inode_size, ents, ne) == 0) {     /* fits in-inode (or empty) */
        xa_drop_block(v, inode);                             /* no longer need a block */
        return write_inode(v, ino, inode);
    }
    uint32_t facl = e_rd32(inode + 104);
    if (!facl) {                                             /* allocate an EA block */
        facl = alloc_block(v); if (!facl) return -1;
        e_wr32(inode + 104, facl);
        e_wr32(inode + 28, e_rd32(inode + 28) + v->block_size / 512);   /* i_blocks += */
    }
    if (xa_write_block(v, facl, ents, ne) < 0) return -1;
    e_wr16(inode + 128, 32);                                 /* clear the in-inode EA (all in the block now) */
    for (uint32_t i = 160; i < v->inode_size; i++) inode[i] = 0;
    return write_inode(v, ino, inode);
}

/* set user.<name> = value (vlen bytes) on `path`; replaces an existing one,
 * preserves the rest (read-modify-write across in-inode + EA block). returns vlen/-1. */
long ext2_setxattr(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                   const char *path, const char *name, const void *value, unsigned long vlen) {
    ext2_path_cache_flush();   /* wholesale: see the note at ext2_unlink_path (M2103) */
    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;
    if (v.inode_size < 256) return -1;                 /* in-inode EA region needs a 256-byte inode */
    const char *xn = xa_user(name); if (!xn) return -1;
    uint32_t nlen = xa_strlen(xn);
    if (nlen == 0 || nlen > XA_NAME || vlen > XA_VAL) return -1;
    uint8_t inode[256]; int isdir = 0;
    uint32_t ino = walk(&v, path, inode, &isdir);
    if (!ino || isdir) return -1;
    struct xa_ent ents[XA_MAX];
    int ne = xa_collect(&v, inode, ents, xn, nlen);           /* whole set, minus our name */
    if (ne >= XA_MAX) return -1;
    ents[ne].idx = 1; ents[ne].nl = (uint8_t)nlen; ents[ne].vsz = (uint32_t)vlen;
    for (uint32_t i = 0; i < nlen; i++) ents[ne].nm[i] = (uint8_t)xn[i];
    for (uint32_t i = 0; i < vlen; i++) ents[ne].vl[i] = ((const uint8_t *)value)[i];
    ne++;
    return xa_save(&v, ino, inode, ents, ne) < 0 ? -1 : (long)vlen;
}

/* remove user.<name> from `path`. returns 0 (removed), or -1 (absent/no EA). */
long ext2_removexattr(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                      const char *path, const char *name) {
    ext2_path_cache_flush();   /* wholesale: see the note at ext2_unlink_path (M2103) */
    ext2_t v;
    if (!write || ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    v.write = write;
    if (v.inode_size < 256) return -1;
    const char *xn = xa_user(name); if (!xn) return -1;
    uint32_t nlen = xa_strlen(xn);
    uint8_t inode[256]; int isdir = 0;
    uint32_t ino = walk(&v, path, inode, &isdir);
    if (!ino || isdir) return -1;
    struct xa_ent ents[XA_MAX];
    int nb = xa_collect(&v, inode, ents, 0, 0);               /* full set */
    int ne = xa_collect(&v, inode, ents, xn, nlen);           /* minus our name */
    if (nb == ne) return -1;                                  /* not present */
    return xa_save(&v, ino, inode, ents, ne) < 0 ? -1 : 0;
}

/* read user.<name> from `path` into out (max bytes). returns the value's full
 * size (may exceed max -> truncated), or -1 if absent. */
long ext2_getxattr(blk_read_fn read, void *ctx, uint64_t start_lba,
                   const char *path, const char *name, void *out, unsigned long max) {
    ext2_t v; if (ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    if (v.inode_size < 256) return -1;
    const char *xn = xa_user(name); if (!xn) return -1;
    uint32_t nlen = xa_strlen(xn);
    uint8_t inode[256]; int isdir = 0;
    if (!walk(&v, path, inode, &isdir)) return -1;
    struct xa_ent ents[XA_MAX];
    int ne = xa_collect(&v, inode, ents, 0, 0);
    for (int i = 0; i < ne; i++) {
        if (ents[i].idx != 1 || ents[i].nl != nlen) continue;
        int match = 1;
        for (uint32_t j = 0; j < nlen; j++) if (ents[i].nm[j] != (uint8_t)xn[j]) { match = 0; break; }
        if (!match) continue;
        uint32_t n = ents[i].vsz < max ? ents[i].vsz : (uint32_t)max;
        for (uint32_t j = 0; j < n; j++) ((uint8_t *)out)[j] = ents[i].vl[j];
        return (long)ents[i].vsz;
    }
    return -1;
}

/* list xattr names as NUL-separated "user.NAME\0" entries into out (max bytes).
 * returns the total bytes (may exceed max -> truncated), or -1 if not ext2. */
long ext2_listxattr(blk_read_fn read, void *ctx, uint64_t start_lba,
                    const char *path, char *out, unsigned long max) {
    ext2_t v; if (ext2_open(read, ctx, start_lba, &v) < 0) return -1;
    if (v.inode_size < 256) return -1;
    uint8_t inode[256]; int isdir = 0;
    if (!walk(&v, path, inode, &isdir)) return -1;
    struct xa_ent ents[XA_MAX];
    int ne = xa_collect(&v, inode, ents, 0, 0);
    uint32_t total = 0;
    for (int i = 0; i < ne; i++) {
        if (ents[i].idx != 1) continue;                       /* user.* only */
        const char *pre = "user.";
        for (int k = 0; k < 5; k++) { if (total < max) out[total] = pre[k]; total++; }
        for (uint32_t j = 0; j < ents[i].nl; j++) { if (total < max) out[total] = (char)ents[i].nm[j]; total++; }
        if (total < max) out[total] = 0;
        total++;                                              /* NUL terminator (counted even if truncated) */
    }
    return (long)total;
}
