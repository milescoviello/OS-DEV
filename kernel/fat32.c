/*
 * fat32.c — a small read/write FAT32 filesystem driver (with subdirectories).
 *
 * FAT32's layout, from the boot sector (BPB) outward:
 *
 *   [ reserved (incl. boot sector) ][ FAT #1 ][ FAT #2 ][ data clusters... ]
 *
 * The "File Allocation Table" is the heart of it: a big array indexed by
 * cluster number. FAT[c] holds the *next* cluster of a file, or an
 * end-of-chain marker. So a file is a linked list of clusters threaded through
 * the FAT. Directories are just files whose contents are 32-byte entries.
 *
 * We read the disk through the ATA driver and expose list/read to the VFS.
 */
#include "fat32.h"
#include "vfs.h"
#include "ata.h"
#include "rtc.h"
#include "string.h"
#include "journal.h"    /* write-ahead journal: crash-consistent metadata writes (M1866) */
#include <stdint.h>

#define SECSZ 512
#define EOC   0x0FFFFFF8      /* >= this in a FAT entry means end-of-chain */

static uint32_t bytes_per_sec;
static uint32_t sec_per_clus;
static uint32_t fat_start;     /* first FAT sector */
static uint32_t data_start;    /* sector of cluster 2 */
static uint32_t root_cluster;
static uint32_t cwd_cluster;   /* current directory (for relative paths) */
static uint32_t num_fats;
static uint32_t fat_sectors;   /* sectors per FAT */
static uint32_t total_clusters; /* count of data clusters on the volume */
static uint32_t alloc_hint = 2; /* where the next free-cluster scan starts (set on free) */

/* --- write-ahead journal for crash-consistent metadata writes (M1866) ---------
 * A filesystem-mutating op (create a file = allocate FAT clusters + write the
 * data + add a directory entry) is many sector writes; a power loss between them
 * tears the volume. So a journaled op opens a transaction (g_fj_txn=1): every
 * single-sector write funnels through fat_wr() -> journal_write() (STAGED, not on
 * disk yet), and every single-sector read (all go through ata_read_retry) first
 * peeks the staged blocks so a read-modify-write inside the op sees its own
 * earlier writes (fat_set touches two entries in one FAT sector; a chain link
 * re-reads it). journal_commit() then atomically logs + checkpoints them. The
 * journal lives in the disk tail mkfatfs reserves OUTSIDE the FS ([tot_sec,
 * tot_sec+JRNL_MINLEN); see M1865). Journal-region I/O + checkpoint go straight to
 * disk via the jf_* backend below. On mount, journal_recover() replays a
 * committed-but-uncheckpointed transaction (a crash mid-checkpoint) or discards an
 * uncommitted one (a crash before commit — the FS was never touched). */
static journal_t g_fj;
static int g_fj_ready;          /* journal formatted/recovered and usable */
static int g_fj_txn;            /* a filesystem-op transaction is open */
/* Claimed atomically so only ONE journaled op runs at a time: on SMP a second
 * concurrent writer just falls back to the direct (non-journaled) path rather
 * than corrupting the shared transaction buffer — no yielding lock (which would
 * deadlock against ata_lock's own yield). */
static volatile int g_fj_busy;
/* The task whose op opened the transaction. Only ITS writes are staged and
 * only its reads peek the staged blocks: anyone else sees the disk. */
struct task;
extern struct task *task_self(void);
extern void task_yield(void);
static struct task *volatile g_fj_owner;
static int fat_in_txn(void) { return g_fj_txn && g_fj_owner == task_self(); }
static int g_fj_overflow;        /* a staged write didn't fit the open txn -> force abort, never tear (M1885) */

static uint16_t rd16(const uint8_t *p) { return p[0] | p[1] << 8; }
static uint32_t rd32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

/* Every read in this file (a directory scan, a file's cluster-chain walk, a
 * FAT-table lookup) is built from many single- or few-sector ata_read calls
 * in sequence, and ata_read failing on ANY one of them used to abort the
 * WHOLE operation -- silently truncating a file read partway through, or
 * giving up a directory scan before it ever reached a late entry (a 137-file
 * root needs 9 sectors; the target could be in the last one). This showed up
 * as two distinct, real symptoms while chasing the M1539 dlxtest flakiness:
 * dlopen() returning "not found" for a file that's really there (walk_dir
 * gave up early), and dlopen() "succeeding" with a corrupted image (a
 * mid-transfer truncation went undetected because dlopen never checks that
 * the bytes it got cover the offsets it dereferences). This wrapper retries
 * a failing sector read a few times -- see the osdev-ata-pio-busywait-flakiness
 * memory -- before the caller gives up on the whole operation. Reads only:
 * ata_write call sites are untouched (a partially-applied retried write has
 * a different correctness story, and nothing here shows write-side flakiness). */
static int ata_read_retry(uint32_t lba, uint8_t count, void *buf) {
    /* Inside a journaled op, a single-sector read must see any block this op has
     * already STAGED (not the stale on-disk copy) — else e.g. a chain-link
     * fat_set would re-read a FAT sector and undo the just-allocated entry. */
    if (fat_in_txn() && count == 1 && journal_peek(&g_fj, lba, buf)) return 0;
    int r = -1;
    for (int attempt = 0; attempt < 3 && r < 0; attempt++) r = ata_read(lba, count, buf);
    return r;
}

/* journal backend: the journal's OWN region I/O + its checkpoint writes go
 * straight to disk (they must not re-enter the transaction). */
static int  jf_bread(void *c, uint64_t lba, void *buf)        { (void)c; return ata_read((uint32_t)lba, 1, buf) < 0 ? -1 : 0; }
static int  jf_bwrite(void *c, uint64_t lba, const void *buf) { (void)c; return ata_write((uint32_t)lba, 1, (void *)buf) < 0 ? -1 : 0; }
static void jf_bflush(void *c)                                { (void)c; ata_cache_flush(); }

/* fat32's single-sector write funnel: STAGE into the open transaction (so the op
 * is atomic), else write straight through. If staging ever fails (txn full — the
 * caller's size guard prevents this), fall back to a direct write. */
static void fat_wr(uint32_t lba, const void *buf) {
    if (fat_in_txn()) {
        /* In a journaled op: stage it. If it somehow doesn't fit the transaction
         * (the cluster-cap guard below should make this impossible), do NOT fall
         * back to a direct write — that tears the op (some blocks staged, this one
         * live on disk). Mark overflow so fat_txn_end aborts the whole txn instead,
         * keeping the op all-or-nothing (M1885, was a torn-write hazard). */
        if (journal_write(&g_fj, lba, buf) == 0) return;
        g_fj_overflow = 1;
        return;
    }
    ata_write(lba, 1, buf);
}

/* Max clusters a single op may stage in one journal transaction. Each cluster
 * touches a FAT sector in EVERY FAT copy (num_fats), plus a handful of directory
 * sectors, and the lot must fit one JRNL_MAXTXN-block transaction — otherwise a
 * staged write would overflow and (pre-M1885) tear via fat_wr's direct fallback.
 * Capped at 24 (the long-standing safe value for the usual 2 FAT copies) and
 * tightened for num_fats>2 so the txn can never overflow (Finding 5). */
static uint32_t jrnl_cluster_cap(void) {
    if (num_fats == 0) return 0;
    uint32_t c = (JRNL_MAXTXN - 6) / num_fats;
    return c < 24 ? c : 24;
}

/* Open a journaled transaction for one FS op. Returns 1 if journaling is active
 * (caller MUST call fat_txn_end() with commit=1 on success / 0 on error), or 0
 * if the op should just run direct (journal off, or another op owns it — the
 * atomic claim serializes journaled ops without a yielding lock). Never nests:
 * if a transaction is already open, returns 0 so the inner op writes through it. */
static int fat_txn_begin_op(void) {
    if (!g_fj_ready || g_fj_txn) return 0;
    if (__atomic_exchange_n(&g_fj_busy, 1, __ATOMIC_ACQUIRE) != 0) return 0;
    if (journal_begin(&g_fj) != 0) { __atomic_store_n(&g_fj_busy, 0, __ATOMIC_RELEASE); return 0; }
    g_fj_owner = task_self();
    g_fj_txn = 1;
    g_fj_overflow = 0;
    return 1;
}
static void fat_txn_end(int commit) {
    if (!g_fj_txn) return;
    g_fj_txn = 0;
    if (g_fj_overflow) commit = 0;      /* a staged write overflowed the txn -> abort, don't tear (M1885) */
    if (commit) journal_commit(&g_fj); else journal_abort(&g_fj);
    g_fj_overflow = 0;
    g_fj_owner = 0;
    __atomic_store_n(&g_fj_busy, 0, __ATOMIC_RELEASE);
}

/* Current wall-clock packed into FAT16 date/time fields (date = y-1980<<9|mon<<5|day,
 * time = hour<<11|min<<5|sec/2), for stamping new directory entries. */
static void fat_now(uint16_t *date, uint16_t *time) {
    struct rtc_time t; rtc_now(&t);
    int y = t.year - 1980; if (y < 0) y = 0; if (y > 127) y = 127;
    *date = (uint16_t)((y << 9) | ((t.month & 15) << 5) | (t.day & 31));
    *time = (uint16_t)(((t.hour & 31) << 11) | ((t.min & 63) << 5) | ((t.sec / 2) & 31));
}

static uint32_t cluster_to_sector(uint32_t cl) {
    return data_start + (cl - 2) * sec_per_clus;
}

/* Look up the next cluster in a chain. */
static uint32_t fat_next(uint32_t cl) {
    uint8_t sec[SECSZ];
    uint32_t fat_offset = cl * 4;
    uint32_t fat_sec = fat_start + fat_offset / SECSZ;
    if (ata_read_retry(fat_sec, 1, sec) < 0)
        return EOC;
    return rd32(sec + (fat_offset % SECSZ)) & 0x0FFFFFFF;
}

/* Follow a chain one step, but bail (return EOC) if we've taken more steps than
 * there are clusters — a corrupt/cyclic FAT can't legitimately chain that long,
 * so this stops an infinite loop from hanging the kernel inside a syscall. */
static uint32_t fat_step(uint32_t cl, uint32_t *steps) {
    if (total_clusters && ++(*steps) > total_clusters + 2) return EOC;
    return fat_next(cl);
}

/* A legitimate data cluster is in [2, total_clusters+2). A corrupt/cyclic FAT can
 * aim a chain at an out-of-range cluster that's still < EOC; treating that as
 * end-of-chain stops a wrong/garbage read (the LBA would wrap to 28 bits or the
 * drive would error). The read path is memory-safe regardless (every read targets
 * the fixed-size sector buffer), so this is robustness/correctness, not a memory
 * fix — and it also rejects cluster 0/1 (so an empty file's first-cluster-0 can't
 * underflow cluster_to_sector). total_clusters==0 (pre-mount) falls back to the
 * old cl<EOC test. */
static int cluster_in_range(uint32_t cl) {
    return cl >= 2 && cl < EOC && (!total_clusters || cl < total_clusters + 2);
}

/* Turn an 8.3 directory name (11 bytes, space-padded) into "NAME.EXT". */
static void format_83(const uint8_t *raw, char *out) {
    int n = 0;
    for (int i = 0; i < 8 && raw[i] != ' '; i++)
        out[n++] = raw[i];
    if (raw[8] != ' ') {
        out[n++] = '.';
        for (int i = 8; i < 11 && raw[i] != ' '; i++)
            out[n++] = raw[i];
    }
    out[n] = '\0';
}

static char up(char c) { return (c >= 'a' && c <= 'z') ? c - 32 : c; }

static int ieq(const char *a, const char *b) {
    while (*a && *b) {
        if (up(*a) != up(*b)) return 0;
        a++; b++;
    }
    return up(*a) == up(*b);
}

/*
 * Walk a directory's cluster chain (starting at cluster `cl`), calling visit()
 * per valid entry. visit returns nonzero to stop early. Returns count visited.
 * A directory is just a file whose data is 32-byte entries, so this works for
 * the root and any subdirectory alike.
 */
typedef int (*dir_visit_fn)(const uint8_t *entry, const char *name, void *ctx);

static int walk_dir(uint32_t cl, dir_visit_fn visit, void *ctx) {
    uint8_t sec[SECSZ];
    int count = 0;
    uint32_t steps = 0;

    while (cluster_in_range(cl)) {
        uint32_t first = cluster_to_sector(cl);
        for (uint32_t s = 0; s < sec_per_clus; s++) {
            /* A directory scan reads MANY sectors in sequence to reach a late
             * entry (a 137-file root needs 9), so a single transient ata_read
             * hiccup here used to abort the ENTIRE remaining scan -- giving up
             * a lookup for a file that would have been found just fine, a few
             * sectors further in (see ata_read_retry's comment above). */
            if (ata_read_retry(first + s, 1, sec) < 0)
                return count;
            for (int off = 0; off < SECSZ; off += 32) {
                uint8_t *e = sec + off;
                if (e[0] == 0x00)            /* end of directory */
                    return count;
                if (e[0] == 0xE5)            /* deleted */
                    continue;
                if (e[11] == 0x0F)           /* long-file-name entry */
                    continue;
                if (e[11] & 0x08)            /* volume label */
                    continue;
                char name[16];
                format_83(e, name);
                count++;
                if (visit(e, name, ctx))
                    return count;
            }
        }
        cl = fat_step(cl, &steps);
    }
    return count;
}

/* Find an entry by name within directory cluster `cl`. Returns 1 + its first
 * cluster / dir-flag / size, or 0 if not present. */
static void to_83(const char *name, uint8_t out[11]);   /* fwd: 8.3-normalize a leaf for matching */
struct dfind { const char *want; const uint8_t *want83; uint32_t fc, size; int isdir, found; };
static int dfind_visit(const uint8_t *e, const char *name, void *ctx) {
    struct dfind *c = ctx;
    int eq = ieq(name, c->want);                 /* normal/case-insensitive name + "." / ".." */
    if (!eq) {                                   /* also match a leaf that 8.3-truncates to this entry */
        eq = 1; for (int i = 0; i < 11; i++) if (e[i] != c->want83[i]) { eq = 0; break; }  /* e.g. "dl.html" -> DL.HTM */
    }
    if (eq) {
        c->fc = (uint32_t)rd16(e + 26) | ((uint32_t)rd16(e + 20) << 16);
        c->size = rd32(e + 28);
        c->isdir = (e[11] & 0x10) ? 1 : 0;
        c->found = 1;
        return 1;
    }
    return 0;
}
static int dir_find(uint32_t cl, const char *name, uint32_t *fc, int *isdir, uint32_t *size) {
    uint8_t want83[11]; to_83(name, want83);     /* match the 8.3-truncated form too, like write/delete do */
    struct dfind c = { name, want83, 0, 0, 0, 0 };
    walk_dir(cl, dfind_visit, &c);
    if (!c.found) return 0;
    if (fc) *fc = c.fc; if (isdir) *isdir = c.isdir; if (size) *size = c.size;
    return 1;
}

/* Split `path` into its containing-directory cluster (*dir) and final
 * component (*leaf), descending subdirectories. Absolute (/foo) starts at the
 * root, relative at the cwd; "." and ".." are honoured. 0 on success. */
static int resolve(const char *path, uint32_t *dir, const char **leaf) {
    uint32_t cur = (path[0] == '/') ? root_cluster : cwd_cluster;
    const char *p = path;
    if (*p == '/') p++;
    for (;;) {
        const char *slash = p; while (*slash && *slash != '/') slash++;
        if (*slash == 0) { *dir = cur; *leaf = p; return 0; }   /* last = leaf */
        char comp[16]; int n = 0;
        for (const char *q = p; q < slash && n < 15; q++) comp[n++] = *q;
        comp[n] = 0;
        if (comp[0] == 0 || ieq(comp, ".")) { p = slash + 1; continue; }
        uint32_t fc; int isdir;
        if (ieq(comp, "..")) {                       /* up one (no-op at root) */
            if (dir_find(cur, "..", &fc, &isdir, 0)) cur = fc ? fc : root_cluster;
        } else {
            if (!dir_find(cur, comp, &fc, &isdir, 0) || !isdir) return -1;
            cur = fc;
        }
        p = slash + 1;
    }
}

/* Full-path stat (M1622): walks the path's OWN directory components via
 * resolve() (absolute from root, relative from cwd) instead of assuming the
 * caller already narrowed it to the current directory -- vfs_stat's old
 * fallback stripped to a bare basename and matched against list()'s listing
 * of the CURRENT cwd, so an absolute path silently failed whenever cwd wasn't
 * "/" (a real /README.TXT reported as not-found while cwd was /tmp). */
static long fat32_stat_path(const char *path, uint32_t *size, int *isdir) {
    uint32_t dir; const char *leaf;
    if (resolve(path, &dir, &leaf) < 0) return -1;
    if (!leaf[0]) {                 /* a trailing slash: resolve() already walked INTO this
                                      * component and required it to be a directory, so an
                                      * empty leaf here means a confirmed-existing dir, not
                                      * "nothing to look up" (M1622 follow-up) */
        if (size) *size = 0;
        if (isdir) *isdir = 1;
        return 0;
    }
    uint32_t fc; int isd; uint32_t sz;
    if (!dir_find(dir, leaf, &fc, &isd, &sz)) return -1;
    if (size) *size = sz;
    if (isdir) *isdir = isd;
    return 0;
}

static uint32_t alloc_cluster(void);              /* fwd: add_entry grows a full dir chain */
static void     fat_set(uint32_t cl, uint32_t val);

/* Append a directory entry (name83/attr/first-cluster/size) into directory
 * cluster `dircl`, reusing the first free or deleted slot, growing the dir's
 * cluster chain if it is completely full. 0 on success. */
static int add_entry(uint32_t dircl, const uint8_t name83[11], uint8_t attr,
                     uint32_t first, uint32_t size) {
    uint8_t sec[SECSZ];
    uint32_t cl = dircl, steps = 0, last = dircl;
    while (cluster_in_range(cl)) {            /* stop on a corrupt out-of-range chain value, not just EOC (mirrors the read path) */
        uint32_t firsts = cluster_to_sector(cl);
        for (uint32_t s = 0; s < sec_per_clus; s++) {
            if (ata_read_retry(firsts + s, 1, sec) < 0) return -1;
            for (int off = 0; off < SECSZ; off += 32) {
                uint8_t *e = sec + off;
                if (e[0] == 0x00 || e[0] == 0xE5) {
                    for (int i = 0; i < 32; i++) e[i] = 0;
                    for (int i = 0; i < 11; i++) e[i] = name83[i];
                    e[11] = attr;
                    e[20] = first >> 16; e[21] = first >> 24;
                    e[26] = first;       e[27] = first >> 8;
                    e[28] = size; e[29] = size >> 8; e[30] = size >> 16; e[31] = size >> 24;
                    { uint16_t fd, ft; fat_now(&fd, &ft);     /* stamp create/write/access time */
                      e[14] = ft; e[15] = ft >> 8; e[16] = fd; e[17] = fd >> 8;   /* create */
                      e[18] = fd; e[19] = fd >> 8;                                /* access */
                      e[22] = ft; e[23] = ft >> 8; e[24] = fd; e[25] = fd >> 8; } /* write  */
                    fat_wr(firsts + s, sec);      /* dir entry: journaled metadata (M1866) */
                    return 0;
                }
            }
        }
        last = cl;
        cl = fat_step(cl, &steps);
    }
    /* The directory is full. A FAT32 directory is an ordinary cluster chain
     * (unlike FAT12/16's fixed-size root), so grow it: allocate a fresh cluster,
     * zero every 32-byte slot (so they read as free) and place this entry in the
     * first slot, THEN link it onto the chain — writing the cluster before
     * linking means a concurrent chain-walk never sees an uninitialised cluster.
     * Mirrors fat32_write's data-chain growth. */
    uint32_t newcl = alloc_cluster();
    if (newcl == 0) return -1;                       /* disk full */
    uint32_t firsts = cluster_to_sector(newcl);
    uint8_t z[SECSZ];
    for (int i = 0; i < SECSZ; i++) z[i] = 0;
    for (uint32_t s = 1; s < sec_per_clus; s++) ata_write(firsts + s, 1, z);   /* zero the rest of the cluster */
    for (int i = 0; i < 11; i++) z[i] = name83[i];   /* the entry, in slot 0 (the rest of z stays zero = free slots) */
    z[11] = attr;
    z[20] = first >> 16; z[21] = first >> 24;
    z[26] = first;       z[27] = first >> 8;
    z[28] = size; z[29] = size >> 8; z[30] = size >> 16; z[31] = size >> 24;
    ata_write(firsts, 1, z);
    fat_set(last, newcl);                            /* link the new cluster onto the dir chain */
    return 0;
}

/* ---- VFS: list ---- */

struct list_ctx { vfs_dirent *out; int max; int n; };

static int list_visit(const uint8_t *e, const char *name, void *ctx) {
    struct list_ctx *c = ctx;
    if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0)))
        return 0;                         /* hide "." and ".." */
    if (c->n >= c->max)
        return 1;
    int i = 0;
    while (name[i] && i < 62) { c->out[c->n].name[i] = name[i]; i++; }
    if (e[11] & 0x10) c->out[c->n].name[i++] = '/';   /* mark directories */
    c->out[c->n].name[i] = '\0';
    c->out[c->n].size = rd32(e + 28);
    c->out[c->n].time = rd16(e + 22);     /* last-write time/date (FAT-packed) */
    c->out[c->n].date = rd16(e + 24);
    c->n++;
    return 0;
}

static int fat32_list(vfs_dirent *out, int max) {
    struct list_ctx ctx = { out, max, 0 };
    walk_dir(cwd_cluster, list_visit, &ctx);          /* list the current dir */
    return ctx.n;
}
/* List an ARBITRARY directory by path (absolute from root, or cwd-relative),
 * without touching cwd_cluster -- so the GUI Files window keeps its own browse
 * directory independent of the shell/app cwd (M1761). */
static int fat32_list_path(const char *path, vfs_dirent *out, int max) {
    uint32_t dir; const char *leaf;
    if (resolve(path, &dir, &leaf) < 0) return -1;
    uint32_t target;
    if (!leaf[0]) target = dir;                       /* "/" or a trailing slash: resolve() already walked into the dir */
    else {                                            /* leaf names the directory to list */
        uint32_t fc; int isdir;
        if (!dir_find(dir, leaf, &fc, &isdir, 0) || !isdir) return -1;  /* not found, or not a directory */
        target = fc ? fc : root_cluster;              /* a ".." that lands on root reports cluster 0 */
    }
    struct list_ctx ctx = { out, max, 0 };
    walk_dir(target, list_visit, &ctx);
    return ctx.n;
}

/* ---- VFS: read ---- */

static long fat32_read(const char *name, void *buf, unsigned long max) {
    uint32_t dir; const char *leaf;
    if (resolve(name, &dir, &leaf) < 0) return -1;
    uint32_t cl0, size; int isdir;
    if (!dir_find(dir, leaf, &cl0, &isdir, &size) || isdir) return -1;

    uint8_t *dst = buf;
    uint32_t remaining = size;
    if (remaining > max) remaining = max;            /* never write past the caller's buffer */
    unsigned long written = 0;
    uint32_t cl = cl0, steps = 0;

    /* A sequential chain walk hits the same FAT sector for 128 consecutive
     * clusters, so cache it (local to this call -> no staleness vs. writes), and
     * read each run of physically-contiguous clusters in one multi-sector
     * transfer straight into the destination instead of a sector at a time.
     * This turns a multi-MB read from tens of thousands of single-sector PIO
     * commands into a few hundred. */
    uint8_t  fatbuf[SECSZ]; uint32_t fatbuf_sec = 0xFFFFFFFFu;
    uint8_t  tail[SECSZ];

    while (cluster_in_range(cl) && remaining > 0) {
        uint32_t run_start = cl, run_len = 1;
        for (;;) {                                   /* coalesce a contiguous, chain-linked run */
            uint32_t off = cl * 4, fsec = fat_start + off / SECSZ;
            if (fsec != fatbuf_sec) {
                if (ata_read_retry(fsec, 1, fatbuf) < 0) { cl = EOC; goto have_run; }
                fatbuf_sec = fsec;
            }
            uint32_t next = rd32(fatbuf + (off % SECSZ)) & 0x0FFFFFFF;
            if (total_clusters && ++steps > total_clusters + 2) next = EOC;   /* cycle guard */
            if (next == cl + 1 && cluster_in_range(next) && run_len < 2048) { cl = next; run_len++; continue; }
            cl = next;                               /* the cluster to continue from after this run */
            break;
        }
    have_run:;
        uint32_t lba = cluster_to_sector(run_start);
        uint32_t run_sectors = run_len * sec_per_clus;
        while (run_sectors > 0 && remaining >= SECSZ) {           /* whole sectors, in bulk */
            uint32_t cnt = run_sectors < 255 ? run_sectors : 255; /* count is a uint8 (0 != 256 here) */
            if ((unsigned long)cnt * SECSZ > remaining) cnt = remaining / SECSZ;
            if (ata_read_retry(lba, (uint8_t)cnt, dst + written) < 0) return (long)written;
            written += (unsigned long)cnt * SECSZ; remaining -= cnt * SECSZ;
            lba += cnt; run_sectors -= cnt;
        }
        if (run_sectors > 0 && remaining > 0) {                   /* final partial sector */
            if (ata_read_retry(lba, 1, tail) < 0) return (long)written;
            for (uint32_t i = 0; i < remaining; i++) dst[written++] = tail[i];
            remaining = 0;
        }
    }
    return (long)written;
}

/* Read up to `max` bytes of `name` starting at byte offset `off` (M1136, for
 * file-backed mmap's per-page demand reads). A simple sector-by-sector chain
 * walk — no coalescing, since callers fetch a page at a time — with a 512-byte
 * stack buffer (so a large cluster never overflows the stack). Bytes read (0 at
 * EOF), or -1. */
static long fat32_pread(const char *name, void *buf, unsigned long max, uint64_t off) {
    uint32_t dir; const char *leaf;
    if (resolve(name, &dir, &leaf) < 0) return -1;
    uint32_t cl0, size; int isdir;
    if (!dir_find(dir, leaf, &cl0, &isdir, &size) || isdir) return -1;
    if (off >= size) return 0;                               /* nothing past EOF */
    uint64_t want = (uint64_t)size - off;
    if (want > max) want = max;

    uint32_t cbytes = sec_per_clus * SECSZ;
    uint32_t cl = cl0;
    uint32_t skip_steps = 0;
    for (uint32_t i = 0, skip = (uint32_t)(off / cbytes); i < skip; i++) {  /* skip to the offset's cluster */
        if (!cluster_in_range(cl)) return 0;
        cl = fat_next(cl);
        if (total_clusters && ++skip_steps > total_clusters + 2) return 0;   /* corrupt/cyclic chain (M1601) --
            * `skip` comes from the on-disk size field (untrusted), with no
            * cross-check against the chain's real length; the coalescing
            * loop 20 lines below already guards its own walk the same way */
    }
    uint32_t pos = (uint32_t)(off % cbytes);                 /* byte position within the current cluster */

    uint8_t *dst = (uint8_t *)buf, sbuf[SECSZ];
    uint64_t done = 0; uint32_t steps = 0;
    while (done < want && cluster_in_range(cl)) {
        uint32_t base = cluster_to_sector(cl);
        uint32_t s = pos / SECSZ, bo = pos % SECSZ;
        for (; s < sec_per_clus && done < want; s++, bo = 0) {
            if (ata_read_retry(base + s, 1, sbuf) < 0) return (long)done;
            uint32_t avail = SECSZ - bo, left = (uint32_t)(want - done);
            uint32_t chunk = left < avail ? left : avail;
            for (uint32_t k = 0; k < chunk; k++) dst[done + k] = sbuf[bo + k];
            done += chunk;
        }
        pos = 0;
        cl = fat_next(cl);
        if (total_clusters && ++steps > total_clusters + 2) break;   /* cycle guard */
    }
    return (long)done;
}

/* ---- write support ---- */

/* Write a FAT entry (in all FAT copies), preserving the reserved top bits. */
static void fat_set(uint32_t cl, uint32_t val) {
    uint8_t sec[SECSZ];
    uint32_t off = cl * 4;
    uint32_t rel = fat_start + off / SECSZ, fo = off % SECSZ;
    for (uint32_t f = 0; f < num_fats; f++) {
        uint32_t s = rel + f * fat_sectors;
        if (ata_read_retry(s, 1, sec) < 0) return;
        uint32_t nv = (rd32(sec + fo) & 0xF0000000u) | (val & 0x0FFFFFFFu);
        sec[fo] = nv; sec[fo+1] = nv>>8; sec[fo+2] = nv>>16; sec[fo+3] = nv>>24;
        fat_wr(s, sec);                       /* FAT entry: journaled metadata (M1866) */
    }
}

/* Find a free cluster, mark it end-of-chain, and return it (0 = disk full). */
static uint32_t alloc_cluster(void) {
    uint8_t sec[SECSZ]; uint32_t cached = 0xFFFFFFFFu;
    uint32_t span = total_clusters ? total_clusters : fat_sectors * (SECSZ / 4);
    if (span == 0) return 0;
    uint32_t start = alloc_hint < 2 ? 2 : alloc_hint;
    /* Scan [start..) then wrap to cluster 2, covering every data cluster exactly
     * once. Starting where the previous allocation ended (and caching the FAT
     * sector across the scan) makes a sequential write O(n) instead of
     * rescanning the whole FAT per cluster — and it allocates contiguously,
     * which the run-coalescing reader then loads fast. Still returns only a
     * genuinely free (entry==0) cluster, so the worst a stale hint can do is a
     * false "disk full", never a clobber. */
    for (uint32_t n = 0; n < span; n++) {
        uint32_t cl = 2 + (((start - 2) + n) % span);
        uint32_t off = cl * 4, fsec = fat_start + off / SECSZ;
        if (fsec != cached) { if (ata_read_retry(fsec, 1, sec) < 0) return 0; cached = fsec; }
        if ((rd32(sec + (off % SECSZ)) & 0x0FFFFFFF) == 0) {
            fat_set(cl, EOC);
            alloc_hint = cl + 1;
            return cl;
        }
    }
    return 0;
}

static void write_cluster(uint32_t cl, const uint8_t *data, uint32_t len) {
    uint32_t first = cluster_to_sector(cl);
    for (uint32_t s = 0; s < sec_per_clus; s++) {
        uint8_t sec[SECSZ];
        uint32_t chunk = len > SECSZ ? SECSZ : len;
        memcpy(sec, data, chunk);                    /* the actual file bytes for this sector */
        if (chunk < SECSZ) memset(sec + chunk, 0, SECSZ - chunk);   /* pad the rest (only the file's last sector needs this) */
        ata_write(first + s, 1, sec);
        data += chunk; len -= chunk;
    }
}

static char up_c(char c) { return (c >= 'a' && c <= 'z') ? c - 32 : c; }

static void to_83(const char *name, uint8_t out[11]) {
    for (int i = 0; i < 11; i++) out[i] = ' ';
    int i = 0, o = 0;
    while (name[i] && name[i] != '.' && o < 8) out[o++] = up_c(name[i++]);
    while (name[i] && name[i] != '.') i++;
    if (name[i] == '.') {
        i++;
        for (int e = 8; name[i] && e < 11; ) out[e++] = up_c(name[i++]);
    }
}

/* Free a whole cluster chain back to the FAT. */
static void free_chain(uint32_t cl) {
    uint32_t steps = 0;
    while (cluster_in_range(cl)) {            /* a corrupt chain can't free FAT entries belonging to other files / a wild sector */
        uint32_t nx = fat_step(cl, &steps);
        fat_set(cl, 0);
        if (cl < alloc_hint) alloc_hint = cl;     /* let the next allocation reuse freed space */
        cl = nx;
    }
}

static long fat32_delete_nl(const char *name);       /* forward decl */

static long fat32_write_nl(const char *name, const void *data, unsigned long len) {
    uint32_t dir; const char *leaf;
    if (resolve(name, &dir, &leaf) < 0 || !leaf[0]) return -1;
    int exists = 0; uint32_t oldsz = 0;
    { uint32_t fc; int isdir = 0; uint32_t sz;            /* refuse to overwrite a DIRECTORY with a file: else the */
      if (dir_find(dir, leaf, &fc, &isdir, &sz)) {        /* fat32_delete below either fails on a non-empty dir (leaving a */
          if (isdir) return -1;                           /* duplicate same-name entry) or silently rmdir's an empty one. */
          exists = 1; oldsz = sz;
      }
    }

    uint32_t csize = sec_per_clus * SECSZ;
    uint32_t nclus = (uint32_t)((len + csize - 1) / csize);
    if (nclus == 0) nclus = 1;

    /* Journal a NEW small file's create atomically (M1866): the transaction holds
     * only this create's metadata (ordered mode — data clusters written direct
     * FIRST, then the FAT entries + directory entry journaled), so a crash leaves
     * the file fully present or fully absent. Deliberately NOT for an OVERWRITE:
     * doing the old-chain free + the new-chain alloc in one transaction would let
     * alloc_cluster reuse a cluster that this same uncommitted txn just staged as
     * free and overwrite the OLD file's data before commit — corrupting it on a
     * crash. Instead an overwrite takes the direct path where the nested
     * fat32_delete SELF-journals the rm (frees committed first), then the create
     * runs direct — no reuse-of-uncommitted-free hazard. jrnl_cluster_cap() caps
     * the txn (num_fats-aware) so even a fragmented chain's FAT sectors + the dir
     * entry fit one transaction. */
    (void)oldsz;
    int owns = (!exists && nclus <= jrnl_cluster_cap()) ? fat_txn_begin_op() : 0;

    fat32_delete_nl(name);         /* no-op for a new file; for an overwrite it self-journals the rm (direct path) */

    /* allocate a cluster chain and write the data into it */
    uint32_t first = 0, prev = 0;
    const uint8_t *p = data;
    unsigned long rem = len;
    int failed = 0;
    for (uint32_t i = 0; i < nclus; i++) {
        uint32_t cl = alloc_cluster();
        if (!cl) { failed = 1; break; }               /* disk full */
        if (i == 0) first = cl; else fat_set(prev, cl);
        uint32_t chunk = rem > csize ? csize : (uint32_t)rem;
        write_cluster(cl, p, chunk);                   /* DATA: direct, ordered-mode */
        p += chunk; rem -= chunk;
        prev = cl;
    }

    if (!failed) {
        uint8_t name83[11];
        to_83(leaf, name83);
        if (add_entry(dir, name83, 0x20, first, (uint32_t)len) < 0) failed = 1;   /* dir full */
    }

    if (failed) {
        free_chain(first);                             /* don't leak the data (staged frees discarded on abort) */
        if (owns) fat_txn_end(0);                      /* abort: nothing checkpointed -> FS untouched */
        return -1;
    }
    if (owns) fat_txn_end(1);                          /* atomically commit + checkpoint the metadata */
    return (long)len;
}

/* Create a new (empty) subdirectory at `path`. */
static long fat32_mkdir_nl(const char *path) {
    uint32_t dir; const char *leaf;
    if (resolve(path, &dir, &leaf) < 0 || !leaf[0]) return -1;
    if (dir_find(dir, leaf, 0, 0, 0)) return -1;          /* already exists */

    int owns = fat_txn_begin_op();                        /* journal the directory create atomically (metadata; M1866) */
    uint32_t newcl = alloc_cluster();
    if (!newcl) { if (owns) fat_txn_end(0); return -1; }

    /* the new directory's first cluster holds just "." and ".." (rest zero) */
    uint8_t buf[64];
    for (int i = 0; i < 64; i++) buf[i] = 0;
    for (int i = 0; i < 11; i++) { buf[i] = ' '; buf[32 + i] = ' '; }
    buf[0] = '.'; buf[11] = 0x10;                          /* "."  -> itself */
    buf[20] = newcl >> 16; buf[21] = newcl >> 24; buf[26] = newcl; buf[27] = newcl >> 8;
    buf[32] = '.'; buf[33] = '.'; buf[43] = 0x10;          /* ".." -> parent  */
    uint32_t par = (dir == root_cluster) ? 0 : dir;        /* root stored as 0 */
    buf[52] = par >> 16; buf[53] = par >> 24; buf[58] = par; buf[59] = par >> 8;
    write_cluster(newcl, buf, 64);

    uint8_t name83[11];
    to_83(leaf, name83);
    if (add_entry(dir, name83, 0x10, newcl, 0) < 0) { fat_set(newcl, 0); if (owns) fat_txn_end(0); return -1; }
    if (owns) fat_txn_end(1);
    return 0;
}

/* ---- recursive tree listing ---- */
struct tctx { char *out; int *p; int max; int depth; };
static void tree_rec(uint32_t cl, char *out, int *p, int max, int depth);

static int tree_visit(const uint8_t *e, const char *name, void *ctx) {
    struct tctx *c = ctx;
    if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0)))
        return 0;                                 /* skip "." and ".." */
    int *p = c->p, isdir = (e[11] & 0x10);
    for (int i = 0; i < c->depth && *p < c->max - 2; i++) { c->out[(*p)++] = ' '; c->out[(*p)++] = ' '; }
    for (int i = 0; name[i] && *p < c->max - 2; i++) c->out[(*p)++] = name[i];
    if (isdir && *p < c->max - 1) c->out[(*p)++] = '/';
    if (*p < c->max - 1) c->out[(*p)++] = '\n';
    if (isdir && c->depth < 5) {                  /* recurse (depth-capped) */
        uint32_t fc = (uint32_t)rd16(e + 26) | ((uint32_t)rd16(e + 20) << 16);
        if (fc >= 2) tree_rec(fc, c->out, c->p, c->max, c->depth + 1);
    }
    return 0;
}
static void tree_rec(uint32_t cl, char *out, int *p, int max, int depth) {
    struct tctx c = { out, p, max, depth };
    walk_dir(cl, tree_visit, &c);
}
static long fat32_tree(char *out, int max) {
    int p = 0;
    tree_rec(cwd_cluster, out, &p, max, 0);
    out[p < max ? p : max - 1] = 0;
    return p;
}

/* ---- recursive name search (`find`) ---- */
static int name_has(const char *hay, const char *needle) {   /* case-insensitive substring */
    if (!needle[0]) return 1;
    for (int i = 0; hay[i]; i++) {
        int j = 0;
        while (hay[i+j] && needle[j] && up(hay[i+j]) == up(needle[j])) j++;
        if (!needle[j]) return 1;
    }
    return 0;
}
struct findctx { const char *want; char *path; int plen; char *out; int *p; int max; int depth; };
static void find_rec(uint32_t cl, struct findctx *c);
static int find_visit(const uint8_t *e, const char *name, void *ctx) {
    struct findctx *c = ctx;
    if (name[0]=='.' && (name[1]==0 || (name[1]=='.' && name[2]==0))) return 0;
    int isdir = (e[11] & 0x10), saved = c->plen;
    if (c->plen < 200) c->path[c->plen++] = '/';
    for (int i = 0; name[i] && c->plen < 200; i++) c->path[c->plen++] = name[i];
    c->path[c->plen] = 0;
    if (name_has(name, c->want)) {                  /* a hit: emit its full path */
        for (int i = 0; i < c->plen && *c->p < c->max - 2; i++) c->out[(*c->p)++] = c->path[i];
        if (isdir && *c->p < c->max - 2) c->out[(*c->p)++] = '/';
        if (*c->p < c->max - 1) c->out[(*c->p)++] = '\n';
    }
    if (isdir && c->depth < 6) {
        uint32_t fc = (uint32_t)rd16(e + 26) | ((uint32_t)rd16(e + 20) << 16);
        if (fc >= 2) { c->depth++; find_rec(fc, c); c->depth--; }
    }
    c->plen = saved; c->path[saved] = 0;
    return 0;
}
static void find_rec(uint32_t cl, struct findctx *c) { walk_dir(cl, find_visit, c); }
static long fat32_find(const char *want, char *out, int max) {
    char path[208]; path[0] = 0;
    int p = 0;
    struct findctx c = { want, path, 0, out, &p, max, 0 };
    find_rec(cwd_cluster, &c);
    out[p < max ? p : max - 1] = 0;
    return p;
}

/* Change the current directory to `path` (so relative names resolve under it). */
static int fat32_chdir(const char *path) {
    uint32_t cur = (path[0] == '/') ? root_cluster : cwd_cluster;
    const char *p = path; if (*p == '/') p++;
    while (*p) {
        const char *slash = p; while (*slash && *slash != '/') slash++;
        char comp[16]; int n = 0;
        for (const char *q = p; q < slash && n < 15; q++) comp[n++] = *q;
        comp[n] = 0;
        if (comp[0] && !ieq(comp, ".")) {
            uint32_t fc; int isdir;
            if (ieq(comp, "..")) {
                if (dir_find(cur, "..", &fc, &isdir, 0)) cur = fc ? fc : root_cluster;
            } else {
                if (!dir_find(cur, comp, &fc, &isdir, 0) || !isdir) return -1;
                cur = fc;
            }
        }
        p = *slash ? slash + 1 : slash;
    }
    cwd_cluster = cur;
    return 0;
}

/* Per-process cwd support (M1144): the VFS saves/restores the boot-FS cwd cluster
 * around app switches. A 0 means "root" (a fresh app's default). */
uint32_t fat32_get_cwd(void) { return cwd_cluster; }
void     fat32_set_cwd(uint32_t c) { cwd_cluster = c ? c : root_cluster; }

/* visit() that flags a directory as non-empty on its first real entry (not . / ..) */
static int dir_nonempty_visit(const uint8_t *e, const char *name, void *ctx) {
    (void)e;
    if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0))) return 0;  /* skip . and .. */
    *(int *)ctx = 1;
    return 1;                                  /* a real entry — stop the walk */
}

static long fat32_delete_nl(const char *name) {
    uint32_t dir; const char *leaf;
    if (resolve(name, &dir, &leaf) < 0 || !leaf[0]) return -1;
    uint8_t want[11];
    to_83(leaf, want);
    uint8_t sec[SECSZ];
    uint32_t cl = dir, steps = 0;
    while (cluster_in_range(cl)) {            /* corrupt-chain-safe (was cl < EOC, which a wild value steers to a bad sector) */
        uint32_t firsts = cluster_to_sector(cl);
        for (uint32_t s = 0; s < sec_per_clus; s++) {
            if (ata_read_retry(firsts + s, 1, sec) < 0) return -1;
            for (int off = 0; off < SECSZ; off += 32) {
                uint8_t *e = sec + off;
                if (e[0] == 0x00 || e[0] == 0xE5 || e[11] == 0x0F || (e[11] & 0x08))
                    continue;
                int eq = 1;
                for (int i = 0; i < 11; i++) if (e[i] != want[i]) { eq = 0; break; }
                if (!eq) continue;
                uint32_t fc = (uint32_t)rd16(e + 26) | ((uint32_t)rd16(e + 20) << 16);
                if (e[11] & 0x10) {          /* a directory: refuse unless empty, else its children's clusters would leak */
                    int nonempty = 0; walk_dir(fc, dir_nonempty_visit, &nonempty);
                    if (nonempty) return -1;
                }
                /* Journal rm atomically (M1868): free the chain + clear the dir
                 * entry in ONE transaction, so a crash never leaves the entry
                 * pointing at freed clusters. Only when standalone (a nested
                 * overwrite's txn is already open -> owns=0, stage into it) and the
                 * chain is short enough to fit one transaction; else direct. */
                int owns = 0;
                { uint32_t c = fc, st = 0, cnt = 0; uint32_t cap = jrnl_cluster_cap();
                  while (cluster_in_range(c) && cnt <= cap) { cnt++; c = fat_step(c, &st); }
                  if (cnt <= cap) owns = fat_txn_begin_op(); }
                free_chain(fc);              /* free the cluster chain (guarded); stages if in a txn */
                e[0] = 0xE5;                 /* mark the dir entry deleted */
                fat_wr(firsts + s, sec);     /* dir entry: journaled metadata */
                if (owns) fat_txn_end(1);
                return 0;
            }
        }
        cl = fat_step(cl, &steps);
    }
    return -1;
}

/* Does `name` fit the FS's 8.3 write format (<=8 base + optional '.' + <=3 ext,
 * non-empty)? to_83() SILENTLY truncates an over-long name, so the rename path
 * must reject it up front rather than rename to a surprising shorter name. */
static int name_fits_83(const char *name) {
    int base = 0, ext = 0, i = 0;
    while (name[i] && name[i] != '.') { base++; i++; }
    if (name[i] == '.') { i++; while (name[i]) { ext++; i++; } }
    if (base == 0 || base > 8 || ext > 3) return 0;   /* "", "TOOLONGNAME", ".x", "a.exten" all rejected */
    return 1;
}

/* Rename an entry IN PLACE: change ONLY the 11-byte 8.3 name field of `path`'s
 * directory entry to `newname`. The FAT, cluster chain, attributes, size and
 * date stamps are all left untouched (rename is purely a name change), so it
 * works identically for a file or a directory. Returns 0 on success, -1 on a
 * bad/over-long name, a name collision (refuse to clobber), or a missing target.
 *
 * Mirrors fat32_delete's read-modify-write: it scans the directory's cluster
 * chain a sector at a time, and on the matching 32-byte entry overwrites bytes
 * [0..10] (the name) in the in-memory sector buffer and writes back ONLY that
 * one sector — every other byte of that entry and every other entry in the
 * sector is preserved exactly. */
static long fat32_rename_nl(const char *path, const char *newname) {
    if (!name_fits_83(newname)) return -1;            /* 8.3-write only: reject empty / over-long */
    uint8_t new83[11];
    to_83(newname, new83);

    uint32_t dir; const char *leaf;
    if (resolve(path, &dir, &leaf) < 0 || !leaf[0]) return -1;
    /* a trailing '/' (the listing marks dirs with one) is not part of the name */
    char baseleaf[16]; int bn = 0;
    for (int i = 0; leaf[i] && bn < 15; i++) baseleaf[bn++] = leaf[i];
    if (bn > 0 && baseleaf[bn-1] == '/') bn--;
    baseleaf[bn] = 0;
    if (bn == 0) return -1;
    uint8_t want[11];
    to_83(baseleaf, want);

    /* Refuse to clobber: if an entry with the target name already exists in this
     * directory, do nothing (a rename onto an existing name would otherwise
     * create a duplicate-named entry — the kind of ambiguity the rest of the FS
     * avoids). dir_find matches case-insensitively + the 8.3-truncated form. */
    if (dir_find(dir, newname, 0, 0, 0)) return -1;

    uint8_t sec[SECSZ];
    uint32_t cl = dir, steps = 0;
    while (cluster_in_range(cl)) {            /* corrupt-chain-safe, exactly like fat32_delete's scan */
        uint32_t firsts = cluster_to_sector(cl);
        for (uint32_t s = 0; s < sec_per_clus; s++) {
            if (ata_read_retry(firsts + s, 1, sec) < 0) return -1;
            for (int off = 0; off < SECSZ; off += 32) {
                uint8_t *e = sec + off;
                if (e[0] == 0x00 || e[0] == 0xE5 || e[11] == 0x0F || (e[11] & 0x08))
                    continue;
                int eq = 1;
                for (int i = 0; i < 11; i++) if (e[i] != want[i]) { eq = 0; break; }
                if (!eq) continue;
                for (int i = 0; i < 11; i++) e[i] = new83[i];   /* the ONLY mutation: bytes [0..10] (name) */
                fat_wr(firsts + s, sec);                        /* dir entry write-back: journaled metadata (M1866) */
                return 0;
            }
        }
        cl = fat_step(cl, &steps);
    }
    return -1;                               /* target not found */
}

/* Report free + total bytes on the volume (counts unallocated FAT entries). */
static void fat32_df(uint64_t *freeb, uint64_t *totalb) {
    uint8_t sec[SECSZ];
    uint32_t per = SECSZ / 4, freecl = 0;
    for (uint32_t cl = 2; cl < total_clusters + 2; cl++) {
        uint32_t s = fat_start + (cl * 4) / SECSZ;
        if ((cl == 2) || ((cl * 4) % SECSZ == 0)) { if (ata_read_retry(s, 1, sec) < 0) break; }
        uint32_t e = (cl * 4) % SECSZ;
        if ((rd32(sec + e) & 0x0FFFFFFF) == 0) freecl++;
        (void)per;
    }
    uint64_t cs = (uint64_t)sec_per_clus * SECSZ;
    *freeb  = (uint64_t)freecl * cs;
    *totalb = (uint64_t)total_clusters * cs;
}

/* ONE WRITER AT A TIME.
 *
 * Every mutation here is a read-modify-write of shared sectors -- a FAT
 * sector holds 128 cluster links, a directory sector 16 entries -- plus a
 * free-cluster search from a shared hint, and nothing serialised them. Two
 * cores creating files could read the same FAT sector, each set its own link,
 * and write back: one chain loses its link, or both claim the same free
 * cluster and two files share their data.
 *
 * The journal made it worse rather than better. Its "one op at a time" claim
 * (g_fj_busy) sent the loser down the direct path -- but the transaction flag
 * is global, so the loser's fat_wr saw it set and STAGED its sectors into the
 * winner's transaction, to be committed, or discarded on abort, with an op
 * that knew nothing about them. The transaction now belongs to the task that
 * opened it (g_fj_owner), and this lock makes the fallback unreachable.
 *
 * Spin-then-yield, like ext2's fsw_take: it is held across disk I/O, and the
 * ATA lock taken inside it yields the same way, so neither can starve the
 * other's holder. */
static volatile int fat_wlk;
static void fat_w_take(void) {
    uint32_t spins = 0;
    while (__atomic_exchange_n(&fat_wlk, 1, __ATOMIC_ACQUIRE))
        if (++spins >= 1000) { spins = 0; task_yield(); }
}
static void fat_w_give(void) { __atomic_store_n(&fat_wlk, 0, __ATOMIC_RELEASE); }
static long fat32_write(const char *name, const void *data, unsigned long len) {
    fat_w_take(); long r = fat32_write_nl(name, data, len); fat_w_give(); return r;
}
static long fat32_mkdir(const char *path) {
    fat_w_take(); long r = fat32_mkdir_nl(path); fat_w_give(); return r;
}
static long fat32_delete(const char *name) {
    fat_w_take(); long r = fat32_delete_nl(name); fat_w_give(); return r;
}
static long fat32_rename(const char *path, const char *newname) {
    fat_w_take(); long r = fat32_rename_nl(path, newname); fat_w_give(); return r;
}

static struct vfs_ops fat32_ops = { fat32_list, fat32_read, fat32_write,
                                    fat32_delete, fat32_mkdir, fat32_chdir,
                                    fat32_tree, fat32_df, fat32_find,
                                    fat32_rename, fat32_pread, fat32_stat_path,
                                    fat32_list_path };

int fat32_mount(void) {
    uint8_t bs[SECSZ];
    if (ata_read_retry(0, 1, bs) < 0)
        return -1;

    if (rd16(bs + 510) != 0xAA55)          /* boot signature */
        return -1;
    bytes_per_sec = rd16(bs + 11);
    sec_per_clus  = bs[13];
    if (bytes_per_sec != SECSZ || sec_per_clus == 0)
        return -1;

    uint32_t reserved = rd16(bs + 14);
    num_fats    = bs[16];
    fat_sectors = rd32(bs + 36);           /* FAT size 32 */
    if (fat_sectors == 0)
        return -1;                          /* not FAT32 */
    root_cluster = rd32(bs + 44);
    cwd_cluster  = root_cluster;           /* start in the root directory */

    fat_start  = reserved;
    data_start = reserved + num_fats * fat_sectors;

    uint32_t tot_sec = rd16(bs + 19) ? rd16(bs + 19) : rd32(bs + 32);  /* 16- or 32-bit count */
    uint32_t meta = reserved + num_fats * fat_sectors;
    total_clusters = (tot_sec > meta) ? (tot_sec - meta) / sec_per_clus : 0;
    uint32_t fatcap = fat_sectors * (SECSZ / 4);                 /* entries the FAT can actually index */
    if (fatcap > 2 && total_clusters > fatcap - 2)
        total_clusters = fatcap - 2;                             /* never claim more clusters than the FAT addresses — else a malformed BPB makes alloc_cluster/df walk FAT entries that fall inside the data region (wrong-sector write) */
    if (root_cluster < 2) return -1;                            /* corrupt BPB: a root cluster of 0/1 would underflow cluster_to_sector */
    alloc_hint = 2;

    /* Set up the write-ahead journal in the disk tail mkfatfs reserves OUTSIDE
     * the FS: [tot_sec, tot_sec+JRNL_MINLEN) (M1865). journal_recover() replays a
     * transaction a prior crash left committed-but-uncheckpointed, or discards an
     * uncommitted one. If the region isn't there (recover's read fails on a disk
     * with no reserved tail) journaling just stays off and writes go direct. A
     * fresh mkfatfs image has the region zeroed, which reads as "clean". */
    g_fj.read = jf_bread; g_fj.write = jf_bwrite; g_fj.flush = jf_bflush; g_fj.ctx = 0;
    g_fj.jstart = tot_sec; g_fj.jlen = JRNL_MINLEN;
    g_fj_txn = 0; g_fj_ready = 0;
    if (tot_sec >= 2 && journal_recover(&g_fj) >= 0) g_fj_ready = 1;

    vfs_register(&fat32_ops);
    return 0;
}

/* In-guest proof that a REAL file create on the live FS is crash-atomic (M1866,
 * `-append fatjournaltest`). Creates a file with a simulated power loss right
 * after the journal commit point (dbg_crash) — so the metadata is committed to
 * the journal but NOT yet checkpointed, and the file is invisible on disk — then
 * runs journal_recover() and asserts the file appears with the exact content
 * (the transaction was replayed), and that recovery is idempotent. */
extern void kprintf(const char *fmt, ...);
int fat32_journal_selftest(void) {
    if (!g_fj_ready) { kprintf("[fatjournal] journal not ready (no reserved tail?): SKIP\n"); return -2; }
    const char *nm = "JRNLTEST.TXT";
    char content[48]; int cl = 0;
    for (const char *s = "journaled-atomic-create-ok-M1866"; *s; s++) content[cl++] = *s;

    fat32_delete(nm);                        /* clean slate */
    /* (0) a NORMAL journaled create: commit + checkpoint -> immediately visible + correct */
    char rb0[64];
    fat32_write(nm, content, (unsigned long)cl);
    long n0 = fat32_read(nm, rb0, sizeof rb0);
    int normal_ok = (n0 == cl);
    for (int i = 0; i < cl && normal_ok; i++) if (rb0[i] != content[i]) normal_ok = 0;
    fat32_delete(nm);

    /* (1) crash right after the commit point: committed to the journal, NOT checkpointed */
    g_fj.dbg_crash = 1;
    fat32_write(nm, content, (unsigned long)cl);
    g_fj.dbg_crash = 0;

    char rb[64];
    long pre = fat32_read(nm, rb, sizeof rb);          /* must be invisible (dir entry never hit disk) */
    int not_visible = (pre <= 0);
    int rep = journal_recover(&g_fj);                  /* replay -> checkpoint the metadata */
    long n = fat32_read(nm, rb, sizeof rb);            /* now the file must be there, exact content */
    int content_ok = (n == cl);
    for (int i = 0; i < cl && content_ok; i++) if (rb[i] != content[i]) content_ok = 0;
    int idem = (journal_recover(&g_fj) == 0);          /* nothing left to replay */
    fat32_delete(nm);                                  /* clean up */

    /* (2) crash-RM: create a file, delete it with a simulated crash right after
     * the commit point (rm committed to the journal but NOT checkpointed -> the
     * file is still visible), then recover -> replay -> the file is gone. */
    fat32_write(nm, content, (unsigned long)cl);
    g_fj.dbg_crash = 1;
    fat32_delete(nm);
    g_fj.dbg_crash = 0;
    long still = fat32_read(nm, rb, sizeof rb);
    int rm_visible_pre = (still == cl);                /* rm not yet applied */
    int rm_rep = journal_recover(&g_fj);
    long gone = fat32_read(nm, rb, sizeof rb);
    int rm_gone = (gone <= 0);                         /* now really deleted */

    int ok = (normal_ok && not_visible && rep == 1 && content_ok && idem &&
              rm_visible_pre && rm_rep == 1 && rm_gone);
    kprintf("[fatjournal] normal_create=%d | crash-create pre_invisible=%d replayed=%d content_ok=%d(n=%ld) idem=%d | crash-rm visible_pre=%d replayed=%d gone=%d: %s\n",
            normal_ok, not_visible, rep, content_ok, n, idem, rm_visible_pre, rm_rep, rm_gone, ok ? "OK" : "FAIL");
    return ok ? 0 : -1;
}
