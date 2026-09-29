/*
 * fs_test.c — host-side fuzz test of the FAT32 READ path (ASan + UBSan).
 *
 * #includes fat32.c to reach the static walk_dir / fat32_read / fat32_list /
 * fat32_find / fat32_tree / cluster_in_range / fat_step, and stubs fat32.c's
 * only external deps — the disk (ata_read/ata_write serve a small in-memory
 * image) and vfs_register. It builds ONE valid minimal FAT32 image, confirms it
 * reads correctly, then FUZZES corrupted copies of the metadata region (BPB +
 * FAT + root directory + the first few clusters) and re-runs list/read/find/tree
 * under ASan/UBSan.
 *
 * Locks the disk-trust-boundary robustness verified in M435 + earlier:
 *   - cluster_in_range (M435): a corrupt cluster (large-but-<EOC, or 0/1) must
 *     end the chain, never wrap/OOB,
 *   - fat_step's step-count cycle guard: a cyclic FAT must not hang,
 *   - find_rec/tree_rec depth caps: a cyclic DIRECTORY tree must not recurse
 *     unbounded,
 *   - the dir-entry / path-buffer bounds.
 * A corrupt/cyclic FAT must never out-of-bounds or hang. Exit 0 = pass.
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* ---- in-memory disk (256 KB) ---- */
#define SS 512
#define DISK_SECTORS 256
static uint8_t g_disk[DISK_SECTORS * SS];

/* ---- stubs for fat32.c's only external symbols ---- */
#include "vfs.h"
#include "ata.h"
static long g_ata_read_count;   /* counts real disk reads -- the M1601 skip-loop guard test needs this */
int ata_read(uint32_t lba, uint8_t count, void *buf) {
    g_ata_read_count++;
    /* mimic a real drive: an out-of-range LBA errors (so the stub never reads
     * past g_disk, and a runaway chain walk terminates at the disk edge). */
    if ((uint64_t)lba + count > DISK_SECTORS) return -1;
    memcpy(buf, g_disk + (uint64_t)lba * SS, (size_t)count * SS);
    return 0;
}
int ata_write(uint32_t lba, uint8_t count, const void *buf) {
    if ((uint64_t)lba + count > DISK_SECTORS) return -1;
    memcpy(g_disk + (uint64_t)lba * SS, buf, (size_t)count * SS);
    return 0;
}
void ata_cache_flush(void) { }                       /* journal flush hook (M1866) — mock disk is write-through */
void kprintf(const char *fmt, ...) { (void)fmt; }    /* fat32_journal_selftest logs via kprintf (unused here) */
void vfs_register(struct vfs_ops *ops) { (void)ops; }
/* fat32.c's writer lock and journal owner ask which task is running: one here. */
struct task; struct task *task_self(void) { return 0; }
void task_yield(void) { }
/* fat32.c now routes metadata writes through the write-ahead journal; pull in the
 * real journal.c so the same code links here (JRNL_HOST -> host <string.h>). If the
 * mock disk has no reserved tail the journal just stays off and the direct path is
 * tested exactly as before. */
#define JRNL_HOST
#include "journal.c"
#include "rtc.h"
void rtc_now(struct rtc_time *t) {   /* fixed clock so timestamps in created entries are deterministic */
    t->year = 2026; t->month = 6; t->day = 20; t->hour = 12; t->min = 0; t->sec = 0;
}

#include "fat32.c"   /* the static walk_dir / fat32_read / cluster_in_range / ... */

/* ---- image geometry (must match fat32.c's BPB-derived layout) ---- */
#define RESERVED   1
#define NUM_FATS   1
#define FATSZ      2                          /* FAT sectors (256 entries) */
#define SPC        1                          /* sectors per cluster */
#define FAT_SEC    RESERVED                   /* FAT #1 starts here (sector 1) */
#define DATA_SEC   (RESERVED + NUM_FATS*FATSZ)/* sector 3 == cluster 2 */
#define META_BYTES (8 * SS)                   /* BPB + FAT + root dir + a few clusters */

static void w16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void w32(uint8_t *p, uint32_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static uint32_t clus_sec(uint32_t cl) { return DATA_SEC + (cl-2)*SPC; }
static void mk_fat_set(uint32_t cl, uint32_t val) { w32(g_disk + FAT_SEC*SS + cl*4, val & 0x0FFFFFFFu); }
static void dir_ent(uint32_t dir_cl, int idx, const char *name83, uint8_t attr, uint32_t first, uint32_t size) {
    uint8_t *e = g_disk + clus_sec(dir_cl)*SS + idx*32;
    memcpy(e, name83, 11);
    e[11] = attr;
    w16(e+20, (uint16_t)(first >> 16));    /* first-cluster high word */
    w16(e+26, (uint16_t)(first & 0xFFFF)); /* first-cluster low word */
    w32(e+28, size);
}

static void build_valid_image(void) {
    memset(g_disk, 0, sizeof(g_disk));
    uint8_t *bs = g_disk;
    w16(bs+11, SS);             /* bytes per sector */
    bs[13] = SPC;              /* sectors per cluster */
    w16(bs+14, RESERVED);      /* reserved sectors */
    bs[16] = NUM_FATS;
    w32(bs+36, FATSZ);         /* FAT size (32) */
    w32(bs+44, 2);             /* root cluster */
    w32(bs+32, DISK_SECTORS);  /* total sectors (32) */
    w16(bs+510, 0xAA55);       /* boot signature */

    /* FAT: [0]/[1] reserved; [2] root (1 cluster); TEST.TXT = 3->4; SUB = 5 */
    mk_fat_set(0, 0x0FFFFFF8); mk_fat_set(1, 0x0FFFFFFF);
    mk_fat_set(2, 0x0FFFFFFF);
    mk_fat_set(3, 4); mk_fat_set(4, 0x0FFFFFFF);
    mk_fat_set(5, 0x0FFFFFFF);

    /* root directory (cluster 2): a file, a subdir, then end-of-dir */
    dir_ent(2, 0, "TEST    TXT", 0x20, 3, 600);
    dir_ent(2, 1, "SUB        ", 0x10, 5, 0);
    /* slot 2 left 0x00 -> end of directory */

    /* subdir (cluster 5): "." ".." then end */
    dir_ent(5, 0, ".          ", 0x10, 5, 0);
    dir_ent(5, 1, "..         ", 0x10, 2, 0);

    /* TEST.TXT data: cluster 3 all 'A', cluster 4 all 'B' (size 600 = 512+88) */
    memset(g_disk + clus_sec(3)*SS, 'A', SS);
    memset(g_disk + clus_sec(4)*SS, 'B', SS);
}

/* xorshift fuzz rng */
static uint32_t rs = 0x9e3779b9u;
static uint32_t xr(void) { rs ^= rs<<13; rs ^= rs>>17; rs ^= rs<<5; return rs; }

int main(void) {
    /* ---- baseline: the valid image reads correctly ---- */
    build_valid_image();
    if (fat32_mount() != 0)            { printf("FAIL: mount of valid image\n"); return 1; }
    vfs_dirent ents[16];
    int n = fat32_list(ents, 16);
    if (n < 2)                         { printf("FAIL: want >=2 root entries, got %d\n", n); return 1; }
    static char rb[1024];
    long got = fat32_read("TEST.TXT", rb, sizeof(rb));
    if (got != 600)                    { printf("FAIL: TEST.TXT read %ld, want 600\n", got); return 1; }
    if (rb[0]!='A'||rb[511]!='A'||rb[512]!='B'||rb[599]!='B') { printf("FAIL: TEST.TXT content\n"); return 1; }
    if (fat32_read("SUB", rb, sizeof(rb)) != -1)              { printf("FAIL: read of a dir should be -1\n"); return 1; }
    printf("baseline OK: %d root entries, TEST.TXT=600B correct, dir-read rejected\n", n);

    /* ---- rename: the in-place 8.3 name-field change (M1007 fat32_rename) ----
     * On the baseline image (TEST.TXT=600B + SUB dir). A rename must change ONLY
     * the name (data + size preserved), clear the old name, refuse to clobber an
     * existing name, reject non-8.3 names, fail on a missing source, and work for
     * a directory. This locks in the data-safety of the FS's only rename path. */
    if (fat32_rename("TEST.TXT", "REN.TXT") != 0)            { printf("FAIL: rename TEST.TXT->REN.TXT\n"); return 1; }
    got = fat32_read("REN.TXT", rb, sizeof(rb));
    if (got != 600)                                          { printf("FAIL: REN.TXT read %ld, want 600 (rename changed size)\n", got); return 1; }
    if (rb[0]!='A'||rb[511]!='A'||rb[512]!='B'||rb[599]!='B'){ printf("FAIL: REN.TXT content (rename corrupted data)\n"); return 1; }
    if (fat32_read("TEST.TXT", rb, sizeof(rb)) != -1)        { printf("FAIL: old name TEST.TXT still present after rename\n"); return 1; }
    if (fat32_rename("REN.TXT", "SUB") != -1)                { printf("FAIL: rename onto existing name SUB should be refused\n"); return 1; }
    if (fat32_read("REN.TXT", rb, sizeof(rb)) != 600)        { printf("FAIL: REN.TXT lost after a refused clobber\n"); return 1; }
    if (fat32_rename("REN.TXT", "ABCDEFGHI") != -1)          { printf("FAIL: rename to a >8-char base should be refused\n"); return 1; }
    if (fat32_rename("REN.TXT", "X.LONGX")   != -1)          { printf("FAIL: rename to a >3-char ext should be refused\n"); return 1; }
    if (fat32_rename("NOPE.TXT", "X.TXT")    != -1)          { printf("FAIL: rename of a missing file should be -1\n"); return 1; }
    if (fat32_rename("SUB", "SUB2") != 0)                    { printf("FAIL: rename dir SUB->SUB2\n"); return 1; }
    if (fat32_read("SUB2", rb, sizeof(rb)) != -1)            { printf("FAIL: SUB2 should still be a (read-rejected) dir after rename\n"); return 1; }
    printf("  rename OK: data-preserving, clobber + bad-name + missing refused, dir rename\n");

    /* ---- pread skip-loop cycle guard (M1601): the offset-skip loop must not
     * follow a corrupt/cyclic chain indefinitely just because the on-disk
     * size field claims a large offset is valid -- it needs the same cycle
     * guard the coalescing loop 20 lines below it in fat32_pread already
     * has. A fresh valid image, then: make cluster 4 loop back to cluster 3
     * (a 2-cluster cycle instead of EOC) and claim a multi-MB size (the real
     * chain is 2 sectors), then pread far past that: the guard must stop the
     * skip loop within a small, bounded number of real disk reads, not walk
     * the cycle ~976 times chasing an untrusted offset. */
    build_valid_image();
    mk_fat_set(4, 3);                                        /* cluster 4 -> 3: a cycle, not EOC */
    dir_ent(2, 0, "TEST    TXT", 0x20, 3, 10000000);          /* claim 10MB (real chain: 2 sectors) */
    if (fat32_mount() != 0)                                  { printf("FAIL: mount for pread cycle test\n"); return 1; }
    g_ata_read_count = 0;
    long pn = fat32_pread("TEST.TXT", rb, sizeof(rb), 500000);   /* skip ~976 clusters into the cycle */
    if (pn != 0)              { printf("FAIL: pread on a cyclic chain should return 0, got %ld\n", pn); return 1; }
    if (g_ata_read_count > 300) { printf("FAIL: pread skip loop took %ld disk reads chasing a cycle (missing cycle guard)\n", g_ata_read_count); return 1; }
    printf("  pread cycle guard: offset far past a corrupt/cyclic chain returns 0 in %ld disk reads, not ~976\n", g_ata_read_count);

    /* ---- fuzz: corrupt the metadata region, re-mount, re-read ---- */
    static uint8_t pristine[sizeof(g_disk)];
    build_valid_image();
    memcpy(pristine, g_disk, sizeof(g_disk));

    const long ITERS = 12000;
    for (long it = 0; it < ITERS; it++) {
        memcpy(g_disk, pristine, META_BYTES);          /* restore just the metadata */
        int K = 1 + (int)(xr() % 10);
        for (int k = 0; k < K; k++) g_disk[xr() % META_BYTES] = (uint8_t)xr();

        if (fat32_mount() != 0) continue;              /* corrupt BPB -> graceful reject */

        vfs_dirent fe[32];
        int m = fat32_list(fe, 32);
        char fb[2048];
        fat32_read("TEST.TXT", fb, sizeof(fb));
        fat32_read("SUB",      fb, sizeof(fb));
        for (int i = 0; i < m && i < 8; i++)           /* read each listed name */
            fat32_read(fe[i].name, fb, sizeof(fb));
        char tb[4096];
        fat32_find("T", tb, sizeof(tb));               /* recursive name search */
        char trb[4096];
        fat32_tree(trb, sizeof(trb));                  /* recursive tree walk */
    }
    printf("  read-path: %ld corrupt-image iters clean\n", ITERS);

    /* ---- Phase 2: write-path stress (the kernel's most-fragile parser) ----
     * From a fresh valid image, hammer create/write/delete/mkdir + read-back on
     * an ACCUMULATING image (the "heavy repeated writes" scenario the kernel is
     * flagged-fragile on), under ASan. Stresses alloc_cluster / add_entry /
     * write_fat / chain-extension / cluster-free on deletion. All on the
     * in-memory image — the real disk is never touched. */
    build_valid_image();
    if (fat32_mount() != 0) { printf("FAIL: remount for write fuzz\n"); return 1; }
    static char wdata[1600];
    for (size_t i = 0; i < sizeof(wdata); i++) wdata[i] = (char)('a' + (i % 26));
    const long WOPS = 8000;
    for (long it = 0; it < WOPS; it++) {
        char nm[4]; nm[0]='F'; nm[1]=(char)('0' + (xr()%8)); nm[2]=0;   /* F0..F7 */
        char dn[4]; dn[0]='D'; dn[1]=(char)('0' + (xr()%4)); dn[2]=0;   /* D0..D3 */
        char rb2[2048];
        switch (xr() % 7) {
            case 0: case 1: fat32_write(nm, wdata, xr() % (sizeof(wdata)+1)); break;  /* create/overwrite 0..1600B */
            case 2: fat32_delete(nm); break;
            case 3: fat32_mkdir(dn); break;
            case 4: fat32_read(nm, rb2, sizeof(rb2)); break;
            case 5: { vfs_dirent fe2[32]; fat32_list(fe2, 32); char tb2[4096]; fat32_tree(tb2, sizeof(tb2)); } break;
            case 6: { char nm2[4]; nm2[0]='F'; nm2[1]=(char)('0'+(xr()%8)); nm2[2]=0; fat32_rename(nm, nm2); } break;  /* rename F?->F? (clobber/missing/valid mix) */
        }
    }
    printf("  write-path: %ld create/write/delete/mkdir/rename ops clean\n", WOPS);

    /* ---- Phase 3: directory growth (full-root-dir extension) ----
     * Create many distinct files so the root directory must grow past its
     * initial single cluster (16 entries here), then read each back and verify
     * its content — proving add_entry now extends a full dir chain (previously
     * creation simply failed once the directory filled). */
    build_valid_image();
    if (fat32_mount() != 0) { printf("FAIL: remount for dir-growth\n"); return 1; }
    const int NF = 100;
    int created = 0, verified = 0;
    for (int i = 0; i < NF; i++) {
        char nm[16], body[24];
        snprintf(nm, sizeof nm, "G%d.TXT", i);
        int bl = snprintf(body, sizeof body, "body-%d", i);
        if (fat32_write(nm, body, (unsigned long)bl) >= 0) created++;
    }
    for (int i = 0; i < NF; i++) {
        char nm[16], body[24], rb[64];
        snprintf(nm, sizeof nm, "G%d.TXT", i);
        int bl = snprintf(body, sizeof body, "body-%d", i);
        long n = fat32_read(nm, rb, sizeof rb);
        if (n == (long)bl) { int ok = 1; for (int k = 0; k < bl; k++) if (rb[k] != body[k]) { ok = 0; break; } if (ok) verified++; }
    }
    printf("  dir-growth: created %d/%d distinct files (forces add_entry chain growth), %d read back & verified\n", created, NF, verified);
    if (created != NF || verified != NF) { printf("FAIL: dir-growth lost files (created %d, verified %d, want %d)\n", created, verified, NF); return 1; }

    /* ---- Phase 4: regression — rm of a NON-EMPTY directory is refused, with
     * NO cluster leak (M624). The old fat32_delete freed only the directory's
     * own cluster chain, orphaning every child file's clusters (silent FAT
     * leak). Now it refuses a non-empty dir, so: df must be unchanged by the
     * refused delete, the child must stay readable, and a proper delete (child
     * then dir) must reclaim every cluster back to the starting free count. */
    build_valid_image();
    if (fat32_mount() != 0) { printf("FAIL: remount for rm-nonempty-dir\n"); return 1; }
    uint64_t f0, tot;
    fat32_df(&f0, &tot);
    if (fat32_mkdir("RMDIR") != 0)            { printf("FAIL: mkdir RMDIR\n"); return 1; }
    static char cdata[1500];                  /* >1 cluster so a leak spans several */
    for (size_t i = 0; i < sizeof(cdata); i++) cdata[i] = (char)('A' + (i % 26));
    if (fat32_write("RMDIR/CHILD.TXT", cdata, sizeof(cdata)) < 0) { printf("FAIL: write RMDIR/CHILD.TXT\n"); return 1; }
    uint64_t f1; fat32_df(&f1, &tot);
    if (f1 >= f0)                             { printf("FAIL: dir+child consumed no space (%llu->%llu)\n", (unsigned long long)f0, (unsigned long long)f1); return 1; }
    if (fat32_delete("RMDIR") != -1)          { printf("FAIL: rm of NON-EMPTY dir must be refused (-1)\n"); return 1; }
    uint64_t f2; fat32_df(&f2, &tot);
    if (f2 != f1)                             { printf("FAIL: refused dir-delete changed free space — leak/early-free (%llu vs %llu)\n", (unsigned long long)f2, (unsigned long long)f1); return 1; }
    char crb[1600];
    long cn = fat32_read("RMDIR/CHILD.TXT", crb, sizeof(crb));
    if (cn != (long)sizeof(cdata) || crb[0] != 'A' || crb[1499] != cdata[1499]) { printf("FAIL: child unreadable after refused dir-delete (got %ld)\n", cn); return 1; }
    if (fat32_delete("RMDIR/CHILD.TXT") != 0) { printf("FAIL: delete child\n"); return 1; }
    if (fat32_delete("RMDIR") != 0)           { printf("FAIL: delete now-empty dir\n"); return 1; }
    uint64_t f3; fat32_df(&f3, &tot);
    if (f3 != f0)                             { printf("FAIL: clusters not fully reclaimed (%llu, want %llu)\n", (unsigned long long)f3, (unsigned long long)f0); return 1; }
    printf("  rm-nonempty-dir (M624): refused (-1), no leak, child survived, full reclaim (free %llu->%llu->%llu)\n",
           (unsigned long long)f0, (unsigned long long)f1, (unsigned long long)f3);

    /* ---- Phase 4b: writefile over a DIRECTORY is refused (M963). Without the
     * guard, fat32_write deleted-then-wrote: over a NON-EMPTY dir the delete
     * failed (-1) but the write proceeded anyway -> a duplicate same-name entry
     * (a directory AND a file); over an EMPTY dir the delete succeeded -> the
     * directory silently vanished. Now it refuses (-1), leaving the dir intact
     * and still usable, while a normal file overwrite/create is unaffected. */
    build_valid_image();
    if (fat32_mount() != 0) { printf("FAIL: remount for write-over-dir\n"); return 1; }
    char wd[4] = { 'h', 'i', 0, 0 };
    if (fat32_mkdir("WDIR") != 0)                       { printf("FAIL: mkdir WDIR\n"); return 1; }
    if (fat32_write("WDIR", wd, 2) != -1)               { printf("FAIL: writefile over a directory must be refused (-1)\n"); return 1; }
    if (fat32_read("WDIR", crb, sizeof(crb)) != -1)     { printf("FAIL: WDIR must still be a directory (read -1)\n"); return 1; }
    if (fat32_write("WDIR/CHILD.TXT", wd, 2) < 0)       { printf("FAIL: WDIR must still be a usable directory after the refused write\n"); return 1; }
    if (fat32_write("WFILE.TXT", wd, 2) < 0)            { printf("FAIL: a normal file write after the refused dir-write must still succeed\n"); return 1; }
    if (fat32_read("WFILE.TXT", crb, sizeof(crb)) != 2) { printf("FAIL: WFILE.TXT readback after refused dir-write\n"); return 1; }
    printf("  write-over-dir (M963): refused (-1), directory intact + usable, normal writes OK\n");

    /* ---- Phase 5: regression — the READ path finds a name that 8.3-TRUNCATES
     * (M630). dir_find used to compare only the formatted display name (ieq), so
     * a file written "dl.html" (stored 8.3 "DL      HTM") was findable by
     * delete/mkdir (which to_83 the leaf) but NOT by read -> "no such file".
     * dir_find now also matches the to_83 form, so a long name whose formatted
     * 8.3 differs from it still reads back. */
    build_valid_image();
    if (fat32_mount() != 0) { printf("FAIL: remount for 8.3 read\n"); return 1; }
    const char *body = "<html>truncated-name body</html>";
    unsigned long blen = strlen(body);
    char eb[64];
    /* (a) extension truncated: "dl.html" -> "DL      HTM" (formatted "DL.HTM" != "dl.html") */
    if (fat32_write("dl.html", body, blen) < 0)               { printf("FAIL: write dl.html\n"); return 1; }
    if (fat32_read("dl.html", eb, sizeof(eb)) != (long)blen)  { printf("FAIL: read 'dl.html' by long name (M630 regression)\n"); return 1; }
    if (fat32_read("DL.HTM", eb, sizeof(eb)) != (long)blen)   { printf("FAIL: read 'DL.HTM' by its 8.3 name\n"); return 1; }
    /* (b) base truncated: "verylongname.txt" -> "VERYLONG TXT" (formatted "VERYLONG.TXT") */
    if (fat32_write("verylongname.txt", body, blen) < 0)              { printf("FAIL: write verylongname.txt\n"); return 1; }
    if (fat32_read("verylongname.txt", eb, sizeof(eb)) != (long)blen) { printf("FAIL: read 'verylongname.txt' by long name (M630)\n"); return 1; }
    printf("  8.3-read (M630): 'dl.html'->DL.HTM and 'verylongname.txt'->VERYLONG.TXT both readable by long name\n");

    printf("PASS: FAT32 read+write paths, ASan/UBSan clean (corrupt-FAT fuzz + write stress + dir growth + rm-nonempty-dir + 8.3-read regressions)\n");
    return 0;
}
