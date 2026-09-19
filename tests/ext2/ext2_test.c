/*
 * ext2_test.c — host-side fuzz test of the ext2 READ path (ASan + UBSan).
 *
 * ext2 is the OS's most-exposed on-disk parser: the kernel auto-mounts ARBITRARY
 * ext2 volumes from any attached disk (/diskN, M1061), ISO/loop images (M1106/
 * M1107) — i.e. untrusted on-disk metadata — yet, unlike fat32 (tests/fs) /
 * x509 / the image decoders, it had no fuzz harness. This is that harness.
 *
 * ext2.c is device-agnostic (blk_read_fn/blk_write_fn callbacks) and uses no
 * kernel heap (stack buffers + local helpers), so it #includes cleanly with only
 * an in-memory disk served by bd_read (out-of-range LBA -> error, so the parser
 * can never read past the image, and a runaway block/inode walk terminates at
 * the disk edge). It builds a real golden image with mke2fs (argv[1]), confirms
 * it probes + lists, then FUZZES corrupted copies of the metadata region
 * (superblock + group descriptors + bitmaps + inode table — which holds the
 * direct/indirect block pointers) and re-runs probe/list/isdir/read.
 *
 * A corrupt superblock/GDT/inode (bad block_size, inode count, block pointers,
 * a cyclic/huge indirect chain, a cyclic directory) must never out-of-bounds or
 * hang. ASan/UBSan catch OOB; ext2.c's bounds/depth caps must catch the rest;
 * the runner's `timeout` catches a hang. Exit 0 = pass.
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SECSZ 512
static uint8_t g_img[2 * 1024 * 1024];      /* the (mutable, fuzzed) working image */
static long    g_img_bytes;

/* blk_read_fn: serve 512-byte sectors from g_img; OOB -> error (the disk edge). */
/* A READ THAT SUCCEEDS AND RETURNS THE WRONG BYTES (M2237).
 *
 * Every fault this harness could previously inject was a read that FAILED, or
 * an image that was corrupt on disk. The failure the kernel actually suffers
 * is neither: the disk is pristine, the read returns 0, and the bytes in the
 * buffer are not the ones on the platter. Nothing downstream can tell.
 *
 * Arm it for one read of one LBA. It scribbles the RETURNED BUFFER and leaves
 * g_img alone, which is the whole point -- the disk stays correct unless the
 * driver writes the garbage back to it. */
static uint64_t g_inject_lba   = ~0ull;
static uint32_t g_inject_count = 0;     /* match the COUNT too: read_inode reads the same
                                         * LBA one SECTOR at a time and already rejects a
                                         * wild descriptor, so without this it eats the
                                         * injection and the write path never sees it */
static int      g_inject_left  = 0;

static int bd_read(void *ctx, uint64_t lba, uint32_t count, void *buf) {
    (void)ctx;
    if ((lba + count) * SECSZ > (uint64_t)g_img_bytes) return -1;
    memcpy(buf, g_img + lba * SECSZ, (size_t)count * SECSZ);
    if (g_inject_left && lba == g_inject_lba && count == g_inject_count) {
        g_inject_left--;
        /* Corrupt ONLY bg_inode_table (+8), leaving both bitmap pointers
         * valid. That is the production shape -- the boot log rejects inode
         * tables, not bitmaps -- and it is the only shape that reaches the
         * write-back: scribbling the bitmap pointers too makes the allocator
         * fail on the bitmap read first and the descriptor is never rewritten,
         * so the test would pass for a reason that has nothing to do with the
         * fix. (It did, on the first cut.) */
        memset((uint8_t *)buf + 8, 0xA5, 4);
    }
    return 0;
}
static int bd_write(void *ctx, uint64_t lba, uint32_t count, const void *buf) {
    (void)ctx;
    if ((lba + count) * SECSZ > (uint64_t)g_img_bytes) return -1;
    memcpy(g_img + lba * SECSZ, buf, (size_t)count * SECSZ);
    return 0;
}

#include "ext2.c"                             /* the read paths: ext2_probe/list/read/isdir + the static walkers */

static uint8_t g_golden[2 * 1024 * 1024];
static long    g_golden_bytes;

/* Hammer every read/walk parser over whatever currently sits in g_img. Return
 * values are ignored — the point is that NONE of these crash or hang on garbage.
 * (void) casts silence -Wunused-result. */
static void exercise(void) {
    fatvol_dirent ents[32];
    uint8_t rb[512];
    (void)ext2_probe(bd_read, 0, 0);
    (void)ext2_list_path(bd_read, 0, 0, "/", ents, 32);
    (void)ext2_list_path(bd_read, 0, 0, "/lost+found", ents, 32);
    (void)ext2_isdir_path(bd_read, 0, 0, "/lost+found");
    (void)ext2_isdir_path(bd_read, 0, 0, "/BIG");
    (void)ext2_read_path(bd_read, 0, 0, "/HELLO", rb, sizeof rb);
    (void)ext2_read_path(bd_read, 0, 0, "/BIG", rb, sizeof rb);   /* walks direct + (double-)indirect blocks */
    (void)ext2_read_path(bd_read, 0, 0, "/nope", rb, sizeof rb);
    /* xattr read parsers (M1182): walk the in-inode EA on possibly-corrupt
     * inodes — a bad i_extra_isize/magic/entry must never read past the inode. */
    char xb[256];
    (void)ext2_getxattr(bd_read, 0, 0, "/HELLO", "user.greeting", xb, sizeof xb);
    (void)ext2_getxattr(bd_read, 0, 0, "/BIG", "user.x", xb, sizeof xb);
    (void)ext2_listxattr(bd_read, 0, 0, "/HELLO", xb, sizeof xb);
    (void)ext2_listxattr(bd_read, 0, 0, "/lost+found", xb, sizeof xb);
}

/* s_free_blocks_count from the ext2 superblock (byte 1024, field offset 12).
 * bd_write is write-through to g_img, so this reflects the live free count --
 * used by the M1745 leak check. */
static uint32_t free_blocks_count(void) {
    const uint8_t *sb = g_img + 1024;
    return (uint32_t)sb[12] | ((uint32_t)sb[13] << 8) | ((uint32_t)sb[14] << 16) | ((uint32_t)sb[15] << 24);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: ext2_test <golden.ext2>\n"); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open golden"); return 2; }
    g_golden_bytes = (long)fread(g_golden, 1, sizeof g_golden, f);
    fclose(f);
    if (g_golden_bytes < 2048) { fprintf(stderr, "golden image too small (%ld)\n", g_golden_bytes); return 2; }

    /* 1) the golden image must probe + list correctly (proves the harness is real) */
    memcpy(g_img, g_golden, (size_t)g_golden_bytes); g_img_bytes = g_golden_bytes;
    if (ext2_probe(bd_read, 0, 0) != 0) { fprintf(stderr, "golden ext2_probe failed\n"); return 1; }
    fatvol_dirent ents[32];
    int n = ext2_list_path(bd_read, 0, 0, "/", ents, 32);
    int found = 0;
    for (int i = 0; i < n; i++) if (!strcmp(ents[i].name, "lost+found")) found = 1;
    if (n < 1 || !found) { fprintf(stderr, "golden root listing wrong (n=%d, lost+found=%d)\n", n, found); return 1; }
    uint8_t rb[512];
    long hn = ext2_read_path(bd_read, 0, 0, "/HELLO", rb, sizeof rb);
    if (hn <= 0) { fprintf(stderr, "golden /HELLO read failed (%ld)\n", hn); return 1; }
    printf("golden ext2: probe OK, root has %d entries (incl lost+found), /HELLO reads %ld bytes\n", n, hn);

    /* ext2_pread positioned read (M1196): a slice read at an offset must match the
     * same bytes from a full read — across block boundaries + a partial first block. */
    {
        static uint8_t full[400000];
        long bn = ext2_read_path(bd_read, 0, 0, "/BIG", full, sizeof full);   /* the 300 KB golden file */
        if (bn < 200000) { fprintf(stderr, "golden /BIG too small (%ld)\n", bn); return 1; }
        unsigned long offs[] = { 0, 1, 1000, 1023, 1024, 4096, 4097, 100000, 250000 };
        for (unsigned t = 0; t < sizeof offs / sizeof offs[0]; t++) {
            unsigned long o = offs[t]; if ((long)o >= bn) continue;
            uint8_t slice[777];
            long sn = ext2_pread(bd_read, 0, 0, "/BIG", slice, sizeof slice, o);
            long want = bn - (long)o; if (want > (long)sizeof slice) want = sizeof slice;
            if (sn != want || memcmp(slice, full + o, (size_t)sn) != 0) {
                fprintf(stderr, "ext2_pread @%lu wrong (got %ld, want %ld)\n", o, sn, want); return 1;
            }
        }
        if (ext2_pread(bd_read, 0, 0, "/BIG", rb, sizeof rb, (unsigned long)bn + 10) != 0) {
            fprintf(stderr, "ext2_pread past EOF should be 0\n"); return 1;
        }
        printf("ext2_pread: positioned reads byte-exact vs a full read (9 offsets + past-EOF)\n");
    }

    /* 2) fuzz the metadata region (superblock + GDT + bitmaps + inode table, which
     *    carries every block pointer), re-running all read parsers each time. */
    unsigned seed = 0x9e3779b9u;
    long meta = g_golden_bytes < 65536 ? g_golden_bytes : 65536;
    const int ITERS = 8000;
    for (int iter = 0; iter < ITERS; iter++) {
        memcpy(g_img, g_golden, (size_t)g_golden_bytes); g_img_bytes = g_golden_bytes;
        int flips = 1 + (int)(seed % 12);
        for (int k = 0; k < flips; k++) {
            seed = seed * 1103515245u + 12345u; long off = (long)(seed % (unsigned)meta);
            seed = seed * 1103515245u + 12345u; g_img[off] ^= (uint8_t)(seed >> 13);
        }
        exercise();
    }
    printf("fuzz: %d corrupt-metadata iterations, no OOB / no hang\n", ITERS);

    /* 3) ext4 extent-mapped reads (M1186): if an extent image is given, its
     *    extent-flag inodes must read byte-exact, and fuzzing its metadata (which
     *    now carries the in-inode extent tree) must stay OOB/hang-safe. */
    if (argc > 2) {
        FILE *xf = fopen(argv[2], "rb");
        if (!xf) { fprintf(stderr, "open extent image failed\n"); return 1; }
        g_golden_bytes = (long)fread(g_golden, 1, sizeof g_golden, xf); fclose(xf);
        memcpy(g_img, g_golden, (size_t)g_golden_bytes); g_img_bytes = g_golden_bytes;
        static uint8_t big[131072];
        long bn = ext2_read_path(bd_read, 0, 0, "/BIG.TXT", big, sizeof big);
        int okb = (bn == 100000);
        for (long i = 0; i < bn && okb; i++) if (big[i] != 'E') okb = 0;
        if (!okb) { fprintf(stderr, "extent /BIG.TXT read wrong (%ld)\n", bn); return 1; }
        long sn = ext2_read_path(bd_read, 0, 0, "/SMALL.TXT", big, sizeof big);
        if (sn != 19 || memcmp(big, "hello extent world\n", 19) != 0) {
            fprintf(stderr, "extent /SMALL.TXT read wrong (%ld)\n", sn); return 1;
        }
        printf("extent: /BIG.TXT %ld bytes + /SMALL.TXT byte-exact via the extent tree\n", bn);
        /* ext4 extent WRITE (M1189): the driver creates a file as a single contiguous
         * extent; read it back byte-exact, and dump the image (argv[3]) for the runner
         * to e2fsck (which validates the extent layout + the alloc_run bitmap/counts). */
        {
            memcpy(g_img, g_golden, (size_t)g_golden_bytes); g_img_bytes = g_golden_bytes;
            static uint8_t wd[50000]; for (int i = 0; i < 50000; i++) wd[i] = (uint8_t)('A' + (i % 26));
            long w = ext2_write_path(bd_read, bd_write, 0, 0, "/EXTW.TXT", wd, 50000);
            static uint8_t wr[50000]; long rr = (w == 50000) ? ext2_read_path(bd_read, 0, 0, "/EXTW.TXT", wr, sizeof wr) : -1;
            if (w != 50000 || rr != 50000 || memcmp(wr, wd, 50000) != 0) {
                fprintf(stderr, "extent WRITE/readback wrong (w=%ld r=%ld)\n", w, rr); return 1;
            }
            printf("extent write: created /EXTW.TXT (50000 bytes) as an extent, read back byte-exact\n");
            /* hard link (M1207): a 2nd name -> the same inode; both read identically,
             * and unlinking one leaves the other working (links_count inc/dec). Uses
             * a dedicated file so /EXTW.TXT (separately checked extent-mapped) is
             * untouched. The final image (dumped below) must stay e2fsck-clean. */
            {
                static uint8_t hd[1000]; for (int i = 0; i < 1000; i++) hd[i] = (uint8_t)(i * 7 + 1);
                if (ext2_write_path(bd_read, bd_write, 0, 0, "/HL1.TXT", hd, 1000) != 1000) { fprintf(stderr, "hard-link setup write failed\n"); return 1; }
                if (ext2_link_path(bd_read, bd_write, 0, 0, "/HL1.TXT", "/HL2.TXT") != 0) { fprintf(stderr, "ext2_link_path failed\n"); return 1; }
                static uint8_t lr[1000];
                long l1 = ext2_read_path(bd_read, 0, 0, "/HL2.TXT", lr, sizeof lr);
                if (l1 != 1000 || memcmp(lr, hd, 1000) != 0) { fprintf(stderr, "hard-link readback wrong (%ld)\n", l1); return 1; }
                ext2_unlink_path(bd_read, bd_write, 0, 0, "/HL1.TXT");            /* drop the original name */
                long l2 = ext2_read_path(bd_read, 0, 0, "/HL2.TXT", lr, sizeof lr);
                if (l2 != 1000 || memcmp(lr, hd, 1000) != 0) { fprintf(stderr, "hard link did not survive unlink (%ld)\n", l2); return 1; }
                if (ext2_read_path(bd_read, 0, 0, "/HL1.TXT", lr, sizeof lr) > 0) { fprintf(stderr, "unlinked original still readable\n"); return 1; }
                printf("hard link: /HL1.TXT -> /HL2.TXT shares the inode; after unlinking the original the link still reads 1000 bytes\n");
            }
            /* symlink + readlink (M1146 create, M1594 read): ext2_symlink_path could
             * create a real on-disk symlink since M1146, but nothing could ever read
             * one back until now -- genuinely the FIRST automated test of ext2
             * symlinks at all, create or read. The dumped image (e2fsck'd below)
             * must stay clean either way. */
            {
                if (ext2_symlink_path(bd_read, bd_write, 0, 0, "/SYM1.LNK", "/SYMTARGET.TXT") != 0) { fprintf(stderr, "ext2_symlink_path failed\n"); return 1; }
                char sb[64];
                long sl = ext2_readlink_path(bd_read, 0, 0, "/SYM1.LNK", sb, sizeof sb);
                if (sl != 14 || memcmp(sb, "/SYMTARGET.TXT", 14) != 0) { fprintf(stderr, "readlink target wrong (n=%ld)\n", sl); return 1; }
                if (ext2_readlink_path(bd_read, 0, 0, "/HL2.TXT", sb, sizeof sb) != -1) { fprintf(stderr, "readlink on a non-symlink should fail\n"); return 1; }
                char tiny[4];
                long sl2 = ext2_readlink_path(bd_read, 0, 0, "/SYM1.LNK", tiny, sizeof tiny);
                if (sl2 != 4 || memcmp(tiny, "/SYM", 4) != 0) { fprintf(stderr, "readlink truncation wrong (n=%ld)\n", sl2); return 1; }
                printf("readlink: real on-disk (ext2) symlink target read back exact, non-symlink refused, small buffer truncates safely\n");
            }
            /* rename (M1213): relocate a directory entry, preserving the inode.
             * (a) same-dir file rename, (b) cross-dir file move, (c) directory move
             * across parents (fixes ".." + both parents' link counts), (d) a move
             * into the directory's own subtree is refused. The final image (dumped
             * below) must stay e2fsck-clean — the gold check of link counts + dirents. */
            {
                static uint8_t rd[1500]; for (int i = 0; i < 1500; i++) rd[i] = (uint8_t)(i * 3 + 5);
                if (ext2_write_path(bd_read, bd_write, 0, 0, "/RN1.TXT", rd, 1500) != 1500) { fprintf(stderr, "rename setup write failed\n"); return 1; }
                static uint8_t rr2[1500];
                /* (a) same-directory rename */
                if (ext2_rename_path(bd_read, bd_write, 0, 0, "/RN1.TXT", "/RN2.TXT") != 0) { fprintf(stderr, "rename same-dir failed\n"); return 1; }
                if (ext2_read_path(bd_read, 0, 0, "/RN2.TXT", rr2, sizeof rr2) != 1500 || memcmp(rr2, rd, 1500) != 0) { fprintf(stderr, "rename same-dir readback wrong\n"); return 1; }
                if (ext2_read_path(bd_read, 0, 0, "/RN1.TXT", rr2, sizeof rr2) > 0) { fprintf(stderr, "old name still readable after rename\n"); return 1; }
                /* (b) cross-directory file move into a fresh subdir */
                if (ext2_mkdir_path(bd_read, bd_write, 0, 0, "/RNDIR") != 0) { fprintf(stderr, "rename mkdir failed\n"); return 1; }
                if (ext2_rename_path(bd_read, bd_write, 0, 0, "/RN2.TXT", "/RNDIR/RN3.TXT") != 0) { fprintf(stderr, "rename cross-dir failed\n"); return 1; }
                if (ext2_read_path(bd_read, 0, 0, "/RNDIR/RN3.TXT", rr2, sizeof rr2) != 1500 || memcmp(rr2, rd, 1500) != 0) { fprintf(stderr, "rename cross-dir readback wrong\n"); return 1; }
                /* (c) directory move across parents (".." repoint + parent link counts) */
                if (ext2_mkdir_path(bd_read, bd_write, 0, 0, "/RNSUB") != 0) { fprintf(stderr, "rename mkdir2 failed\n"); return 1; }
                if (ext2_mkdir_path(bd_read, bd_write, 0, 0, "/RNSUB/INNER") != 0) { fprintf(stderr, "rename mkdir3 failed\n"); return 1; }
                if (ext2_rename_path(bd_read, bd_write, 0, 0, "/RNSUB/INNER", "/RNDIR/INNER") != 0) { fprintf(stderr, "rename dir-move failed\n"); return 1; }
                if (ext2_isdir_path(bd_read, 0, 0, "/RNDIR/INNER") != 1) { fprintf(stderr, "moved dir absent at new path\n"); return 1; }
                if (ext2_isdir_path(bd_read, 0, 0, "/RNSUB/INNER") == 1) { fprintf(stderr, "moved dir still at old path\n"); return 1; }
                /* (d) refuse moving a directory into its own subtree (would orphan it) */
                if (ext2_rename_path(bd_read, bd_write, 0, 0, "/RNDIR", "/RNDIR/INNER/LOOP") == 0) { fprintf(stderr, "rename allowed a dir into its own subtree\n"); return 1; }
                printf("rename: same-dir + cross-dir file move + directory move across parents (\"..\" + link counts), subtree-loop refused\n");
            }
            /* truncate (M1228): shrink frees blocks beyond newlen + lowers i_size;
             * grow is sparse (the new tail reads back as zeros). The dumped image
             * must stay e2fsck-clean. */
            {
                static uint8_t td[3000]; for (int i = 0; i < 3000; i++) td[i] = (uint8_t)(i * 5 + 3);
                if (ext2_write_path(bd_read, bd_write, 0, 0, "/TR.TXT", td, 3000) != 3000) { fprintf(stderr, "truncate setup write failed\n"); return 1; }
                static uint8_t tr[4096];
                if (ext2_truncate_path(bd_read, bd_write, 0, 0, "/TR.TXT", 500) != 0) { fprintf(stderr, "truncate shrink failed\n"); return 1; }
                long r = ext2_read_path(bd_read, 0, 0, "/TR.TXT", tr, sizeof tr);
                if (r != 500 || memcmp(tr, td, 500) != 0) { fprintf(stderr, "truncate shrink readback wrong (%ld)\n", r); return 1; }
                if (ext2_truncate_path(bd_read, bd_write, 0, 0, "/TR.TXT", 1500) != 0) { fprintf(stderr, "truncate grow failed\n"); return 1; }
                long r2 = ext2_read_path(bd_read, 0, 0, "/TR.TXT", tr, sizeof tr);
                int zeros_ok = 1; for (int i = 500; i < 1500; i++) if (tr[i] != 0) { zeros_ok = 0; break; }
                if (r2 != 1500 || memcmp(tr, td, 500) != 0 || !zeros_ok) { fprintf(stderr, "truncate grow readback wrong (%ld z=%d)\n", r2, zeros_ok); return 1; }
                printf("truncate: shrink 3000->500 (frees blocks), grow 500->1500 sparse (zero-filled tail)\n");
            }
            /* SEEK_HOLE / SEEK_DATA (M1229): build a file with a real middle hole
             * ([data][hole][data]) and assert the boundaries. Overwrite converts
             * the extent inode to block-mapped so punch_hole can carve the hole. */
            {
                static uint8_t sd[5000]; for (int i = 0; i < 5000; i++) sd[i] = (uint8_t)(i | 1);
                if (ext2_write_path(bd_read, bd_write, 0, 0, "/SH.TXT", sd, 5000) != 5000) { fprintf(stderr, "seek setup write failed\n"); return 1; }
                if (ext2_write_path(bd_read, bd_write, 0, 0, "/SH.TXT", sd, 5000) != 5000) { fprintf(stderr, "seek overwrite failed\n"); return 1; }
                if (ext2_punch_hole(bd_read, bd_write, 0, 0, "/SH.TXT", 1024, 2048) < 0) { fprintf(stderr, "seek punch_hole failed\n"); return 1; }  /* returns #blocks freed */
                /* now: [0,1024) data, [1024,3072) hole, [3072,5000) data */
                long e = 0;
                if (ext2_seek_data_hole(bd_read, 0, 0, "/SH.TXT", 0,    0) != 0)    e = __LINE__;   /* DATA at 0 -> 0 */
                if (ext2_seek_data_hole(bd_read, 0, 0, "/SH.TXT", 0,    1) != 1024) e = __LINE__;   /* HOLE after 0 -> 1024 */
                if (ext2_seek_data_hole(bd_read, 0, 0, "/SH.TXT", 1024, 0) != 3072) e = __LINE__;   /* DATA after the hole -> 3072 */
                if (ext2_seek_data_hole(bd_read, 0, 0, "/SH.TXT", 1024, 1) != 1024) e = __LINE__;   /* HOLE at 1024 -> 1024 */
                if (ext2_seek_data_hole(bd_read, 0, 0, "/SH.TXT", 3072, 1) != 5000) e = __LINE__;   /* HOLE after last data -> EOF */
                if (ext2_seek_data_hole(bd_read, 0, 0, "/SH.TXT", 5000, 0) != -1)   e = __LINE__;   /* DATA at EOF -> ENXIO */
                if (e) { fprintf(stderr, "seek_data_hole wrong (line %ld)\n", e); return 1; }
                printf("seek: SEEK_DATA/SEEK_HOLE on a [data|hole|data] file -- boundaries at 0/1024/3072/5000 + ENXIO at EOF\n");
            }
            /* punch_hole on a FRESH, still extent-mapped file (M1614): unlike the
             * seek/hole test above, which deliberately overwrites first to
             * de-extent (so the OLD punch_hole wouldn't corrupt it), this writes
             * ONCE and punches a hole strictly inside the extent -- the case that
             * needs splitting one extent record into two, the newest and riskiest
             * part of the fix. A sibling file written right after must also come
             * back exact (the original bug freed essentially-arbitrary "block
             * numbers" misread from the extent header). */
            {
                static uint8_t ph[5000]; for (int i = 0; i < 5000; i++) ph[i] = (uint8_t)(i * 7 + 11);
                if (ext2_write_path(bd_read, bd_write, 0, 0, "/PH.TXT", ph, 5000) != 5000) { fprintf(stderr, "punch setup write failed\n"); return 1; }
                if (ext2_punch_hole(bd_read, bd_write, 0, 0, "/PH.TXT", 2048, 1024) < 0) { fprintf(stderr, "extent punch_hole failed\n"); return 1; }
                static uint8_t sib[64]; for (int i = 0; i < 64; i++) sib[i] = (uint8_t)(i ^ 0x5A);
                if (ext2_write_path(bd_read, bd_write, 0, 0, "/PHSIB.TXT", sib, 64) != 64) { fprintf(stderr, "punch sibling write failed\n"); return 1; }
                static uint8_t pr[5000];
                long pn = ext2_read_path(bd_read, 0, 0, "/PH.TXT", pr, sizeof pr);
                int ok = (pn == 5000);
                for (int i = 0; ok && i < 2048; i++) if (pr[i] != ph[i]) ok = 0;      /* before the hole: untouched */
                for (int i = 2048; ok && i < 3072; i++) if (pr[i] != 0) ok = 0;       /* the hole: reads as zero */
                for (int i = 3072; ok && i < 5000; i++) if (pr[i] != ph[i]) ok = 0;   /* after the hole: untouched */
                static uint8_t sibr[64];
                long sn = ext2_read_path(bd_read, 0, 0, "/PHSIB.TXT", sibr, sizeof sibr);
                if (sn != 64 || memcmp(sibr, sib, 64) != 0) ok = 0;
                if (!ok) { fprintf(stderr, "extent punch_hole readback wrong (pn=%ld sn=%ld)\n", pn, sn); return 1; }
                printf("punch_hole: fresh extent-mapped file, hole strictly mid-extent -- splits cleanly, sibling file intact\n");
            }
            /* utimensat (M1230): set i_atime/i_mtime to fixed epochs + read the raw
             * inode back (white-box via walk); a negative arg must leave a field. */
            {
                static uint8_t ud[64]; for (int i = 0; i < 64; i++) ud[i] = (uint8_t)i;
                if (ext2_write_path(bd_read, bd_write, 0, 0, "/UT.TXT", ud, 64) != 64) { fprintf(stderr, "utimes setup write failed\n"); return 1; }
                if (ext2_utimes_path(bd_read, bd_write, 0, 0, "/UT.TXT", 0x40000000L, 0x50000000L) != 0) { fprintf(stderr, "utimes set failed\n"); return 1; }
                ext2_t uv; uint8_t uin[256]; int uisd = 0;
                if (ext2_open(bd_read, 0, 0, &uv) < 0 || !walk(&uv, "/UT.TXT", uin, &uisd)) { fprintf(stderr, "utimes walk failed\n"); return 1; }
                if (e_rd32(uin + 8) != 0x40000000u || e_rd32(uin + 16) != 0x50000000u) { fprintf(stderr, "utimes readback wrong (a=%u m=%u)\n", e_rd32(uin+8), e_rd32(uin+16)); return 1; }
                if (ext2_utimes_path(bd_read, bd_write, 0, 0, "/UT.TXT", -1L, 0x60000000L) != 0) { fprintf(stderr, "utimes omit set failed\n"); return 1; }
                if (ext2_open(bd_read, 0, 0, &uv) < 0 || !walk(&uv, "/UT.TXT", uin, &uisd)) { fprintf(stderr, "utimes walk2 failed\n"); return 1; }
                if (e_rd32(uin + 8) != 0x40000000u || e_rd32(uin + 16) != 0x60000000u) { fprintf(stderr, "utimes omit wrong (a=%u m=%u)\n", e_rd32(uin+8), e_rd32(uin+16)); return 1; }
                printf("utimes: set atime/mtime to fixed epochs (read back exact); a negative arg leaves the field (OMIT)\n");
            }
            /* renameat2 (M1232): RENAME_NOREPLACE refuses to clobber; RENAME_EXCHANGE
             * atomically swaps two files. (flag values: NOREPLACE=1, EXCHANGE=2.) */
            {
                static uint8_t ra[40], rb[40];
                for (int i = 0; i < 40; i++) { ra[i] = (uint8_t)('A' + (i % 5)); rb[i] = (uint8_t)('a' + (i % 7)); }
                if (ext2_write_path(bd_read, bd_write, 0, 0, "/R2A.TXT", ra, 40) != 40) { fprintf(stderr, "renameat2 setup A failed\n"); return 1; }
                if (ext2_write_path(bd_read, bd_write, 0, 0, "/R2B.TXT", rb, 40) != 40) { fprintf(stderr, "renameat2 setup B failed\n"); return 1; }
                /* NOREPLACE onto an existing name must fail and leave both intact */
                if (ext2_rename2_path(bd_read, bd_write, 0, 0, "/R2A.TXT", "/R2B.TXT", 1) == 0) { fprintf(stderr, "renameat2 NOREPLACE clobbered an existing file\n"); return 1; }
                /* NOREPLACE onto a free name must succeed */
                if (ext2_rename2_path(bd_read, bd_write, 0, 0, "/R2A.TXT", "/R2NEW.TXT", 1) != 0) { fprintf(stderr, "renameat2 NOREPLACE to a free name failed\n"); return 1; }
                static uint8_t chk[64];
                if (ext2_read_path(bd_read, 0, 0, "/R2NEW.TXT", chk, sizeof chk) != 40 || memcmp(chk, ra, 40) != 0) { fprintf(stderr, "renameat2 NOREPLACE moved wrong content\n"); return 1; }
                if (ext2_read_path(bd_read, 0, 0, "/R2A.TXT", chk, sizeof chk) >= 0) { fprintf(stderr, "renameat2 NOREPLACE left the source\n"); return 1; }
                /* EXCHANGE: swap /R2NEW.TXT (ra) and /R2B.TXT (rb); contents must trade places */
                if (ext2_rename2_path(bd_read, bd_write, 0, 0, "/R2NEW.TXT", "/R2B.TXT", 2) != 0) { fprintf(stderr, "renameat2 EXCHANGE failed\n"); return 1; }
                if (ext2_read_path(bd_read, 0, 0, "/R2NEW.TXT", chk, sizeof chk) != 40 || memcmp(chk, rb, 40) != 0) { fprintf(stderr, "renameat2 EXCHANGE: R2NEW wrong\n"); return 1; }
                if (ext2_read_path(bd_read, 0, 0, "/R2B.TXT", chk, sizeof chk) != 40 || memcmp(chk, ra, 40) != 0) { fprintf(stderr, "renameat2 EXCHANGE: R2B wrong\n"); return 1; }
                printf("renameat2: NOREPLACE refuses to clobber (ok onto a free name) + EXCHANGE atomically swaps two files\n");
            }
            /* chmod (M1241): change the permission bits while preserving the file-type
             * nibble (0x8000 = regular file). Read the raw i_mode back (white-box). */
            {
                static uint8_t cd[16]; for (int i = 0; i < 16; i++) cd[i] = (uint8_t)i;
                if (ext2_write_path(bd_read, bd_write, 0, 0, "/CH.TXT", cd, 16) != 16) { fprintf(stderr, "chmod setup write failed\n"); return 1; }
                ext2_t cv; uint8_t cin[256]; int cisd = 0;
                if (ext2_chmod_path(bd_read, bd_write, 0, 0, "/CH.TXT", 0600) != 0) { fprintf(stderr, "chmod 0600 failed\n"); return 1; }
                if (ext2_open(bd_read, 0, 0, &cv) < 0 || !walk(&cv, "/CH.TXT", cin, &cisd)) { fprintf(stderr, "chmod walk failed\n"); return 1; }
                if ((e_rd16(cin) & 0xFFF) != 0600 || (e_rd16(cin) & 0xF000) != 0x8000) { fprintf(stderr, "chmod 0600 wrong (mode=%o)\n", e_rd16(cin)); return 1; }
                if (ext2_chmod_path(bd_read, bd_write, 0, 0, "/CH.TXT", 0755) != 0) { fprintf(stderr, "chmod 0755 failed\n"); return 1; }
                if (ext2_open(bd_read, 0, 0, &cv) < 0 || !walk(&cv, "/CH.TXT", cin, &cisd)) { fprintf(stderr, "chmod walk2 failed\n"); return 1; }
                if ((e_rd16(cin) & 0xFFF) != 0755 || (e_rd16(cin) & 0xF000) != 0x8000) { fprintf(stderr, "chmod 0755 wrong (mode=%o)\n", e_rd16(cin)); return 1; }
                printf("chmod: set perm bits 0600 then 0755 (read raw i_mode back); the regular-file type bit is preserved\n");
            }
            /* chown (M1243): set i_uid (offset 2) / i_gid (offset 24); a negative id
             * leaves that field. Read the raw inode fields back (white-box). */
            {
                static uint8_t od[16]; for (int i = 0; i < 16; i++) od[i] = (uint8_t)(i + 1);
                if (ext2_write_path(bd_read, bd_write, 0, 0, "/OWN.TXT", od, 16) != 16) { fprintf(stderr, "chown setup write failed\n"); return 1; }
                ext2_t ov; uint8_t oin[256]; int oisd = 0;
                if (ext2_chown_path(bd_read, bd_write, 0, 0, "/OWN.TXT", 1000, 1000) != 0) { fprintf(stderr, "chown 1000:1000 failed\n"); return 1; }
                if (ext2_open(bd_read, 0, 0, &ov) < 0 || !walk(&ov, "/OWN.TXT", oin, &oisd)) { fprintf(stderr, "chown walk failed\n"); return 1; }
                if (e_rd16(oin + 2) != 1000 || e_rd16(oin + 24) != 1000) { fprintf(stderr, "chown 1000 wrong (uid=%u gid=%u)\n", e_rd16(oin+2), e_rd16(oin+24)); return 1; }
                if (ext2_chown_path(bd_read, bd_write, 0, 0, "/OWN.TXT", -1, 500) != 0) { fprintf(stderr, "chown -1:500 failed\n"); return 1; }
                if (ext2_open(bd_read, 0, 0, &ov) < 0 || !walk(&ov, "/OWN.TXT", oin, &oisd)) { fprintf(stderr, "chown walk2 failed\n"); return 1; }
                if (e_rd16(oin + 2) != 1000 || e_rd16(oin + 24) != 500) { fprintf(stderr, "chown -1:500 wrong (uid=%u gid=%u)\n", e_rd16(oin+2), e_rd16(oin+24)); return 1; }
                printf("chown: set uid/gid 1000:1000 then gid->500 with uid=-1 (read raw i_uid/i_gid back); -1 leaves the field\n");
            }
            if (argc > 3) { FILE *wf = fopen(argv[3], "wb"); if (wf) { fwrite(g_img, 1, (size_t)g_img_bytes, wf); fclose(wf); } }
        }
        long emeta = g_golden_bytes < 65536 ? g_golden_bytes : 65536;
        for (int iter = 0; iter < 6000; iter++) {
            memcpy(g_img, g_golden, (size_t)g_golden_bytes); g_img_bytes = g_golden_bytes;
            int flips = 1 + (int)(seed % 12);
            for (int k = 0; k < flips; k++) {
                seed = seed * 1103515245u + 12345u; long off = (long)(seed % (unsigned)emeta);
                seed = seed * 1103515245u + 12345u; g_img[off] ^= (uint8_t)(seed >> 13);
            }
            (void)ext2_read_path(bd_read, 0, 0, "/BIG.TXT", big, sizeof big);   /* walks the (corrupt) extent tree */
            exercise();
        }
        printf("extent fuzz: 6000 corrupt-extent-tree iterations, no OOB / no hang\n");
    }
    /* --- M1745: an out-of-space write must not LEAK the inode/blocks, and a
     * doomed OVERWRITE must not leave the inode pointing at blocks it already
     * freed (silent corruption). Reproduces the failure paths the M1616 fix
     * missed (only dir_add failures were cleaned up before). --- */
    memcpy(g_img, g_golden, (size_t)g_golden_bytes); g_img_bytes = g_golden_bytes;   /* fresh, uncorrupted */
    {
        static uint8_t big[262144];                          /* ~256 KB, near the single-indirect max */
        for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i * 7 + 1);
        char nm[24]; int i;
        for (i = 0; i < 64; i++) {                           /* fill the volume until a write fails */
            snprintf(nm, sizeof nm, "/FILL%d.BIN", i);
            if (ext2_write_path(bd_read, bd_write, 0, 0, nm, big, sizeof big) < 0) break;
        }
        if (i >= 64) { fprintf(stderr, "FAIL nearfull: 64x256KB never filled the volume\n"); return 1; }

        /* (a) leak: a doomed out-of-space write leaves the free-block count unchanged */
        uint32_t free_before = free_blocks_count();
        long w = ext2_write_path(bd_read, bd_write, 0, 0, "/NOFIT.BIN", big, sizeof big);
        uint32_t free_after = free_blocks_count();
        if (w >= 0) { fprintf(stderr, "FAIL nearfull: /NOFIT.BIN unexpectedly fit (%ld)\n", w); return 1; }
        if (free_after != free_before) { fprintf(stderr, "FAIL nearfull LEAK: doomed write changed free blocks %u -> %u\n", free_before, free_after); return 1; }

        /* (b) corruption: a doomed OVERWRITE leaves a CONSISTENT (empty) file --
         * never dangling refs to the old blocks it already freed at the top. */
        memcpy(g_img, g_golden, (size_t)g_golden_bytes);     /* fresh */
        uint8_t small[300]; for (int k = 0; k < 300; k++) small[k] = (uint8_t)k;
        if (ext2_write_path(bd_read, bd_write, 0, 0, "/OV.BIN", small, 300) != 300) { fprintf(stderr, "FAIL nearfull: /OV.BIN setup failed\n"); return 1; }
        for (i = 0; i < 64; i++) { snprintf(nm, sizeof nm, "/G%d.BIN", i); if (ext2_write_path(bd_read, bd_write, 0, 0, nm, big, sizeof big) < 0) break; }   /* fill the rest */
        long ow = ext2_write_path(bd_read, bd_write, 0, 0, "/OV.BIN", big, sizeof big);   /* doomed overwrite */
        if (ow >= 0) { fprintf(stderr, "FAIL nearfull: doomed /OV.BIN overwrite fit (%ld)\n", ow); return 1; }
        uint8_t ovb[512];
        long r = ext2_read_path(bd_read, 0, 0, "/OV.BIN", ovb, sizeof ovb);
        if (r != 0) { fprintf(stderr, "FAIL nearfull CORRUPTION: /OV.BIN reads %ld bytes after a failed overwrite (should be 0)\n", r); return 1; }
        printf("nearfull (M1745): out-of-space write leaks no blocks + failed overwrite leaves no dangling refs\n");
    }

    /* --- M1746: an ext2 listing must not truncate a long (>12-char) name --- */
    memcpy(g_img, g_golden, (size_t)g_golden_bytes); g_img_bytes = g_golden_bytes;
    {
        const char *lname = "documentation-notes.md";        /* 22 chars > the old 12-char cap */
        uint8_t d[8]; for (int k = 0; k < 8; k++) d[k] = (uint8_t)k;
        char p[40]; snprintf(p, sizeof p, "/%s", lname);
        if (ext2_write_path(bd_read, bd_write, 0, 0, p, d, 8) != 8) { fprintf(stderr, "FAIL longname: create of %s failed\n", lname); return 1; }
        fatvol_dirent le[64];
        int ln = ext2_list_path(bd_read, 0, 0, "/", le, 64);
        int found = 0;
        for (int i = 0; i < ln; i++) if (!strcmp(le[i].name, lname)) found = 1;
        if (!found) { fprintf(stderr, "FAIL longname: '%s' not listed untruncated (n=%d)\n", lname, ln); return 1; }
        printf("longname (M1746): ext2 listing returns '%s' (22 chars) untruncated\n", lname);
    }

    /* --- M1933: a directory must GROW past its first block ------------------
     * Before this, dir_add could only split slack inside blocks the directory
     * ALREADY had, so a directory was permanently capped at roughly 30-50
     * entries. No real source tree fits in that, let alone a node_modules.
     *
     * The check is deliberately end-to-end rather than a unit test of dir_add:
     * create far more entries than one block can hold, list them ALL back, and
     * confirm i_size actually grew. The runner then runs e2fsck over the
     * result, which is the real proof that the appended blocks are
     * spec-correct and not merely readable by the code that wrote them. */
    if (argc > 4) {
        FILE *df = fopen(argv[4], "rb");
        if (df) {
            g_img_bytes = (long)fread(g_img, 1, sizeof g_img, df);
            fclose(df);
            uint8_t d[8]; for (int k = 0; k < 8; k++) d[k] = (uint8_t)(k + 1);
            char p[40];
            int made = 0;
            for (int i = 0; i < 600; i++) {
                snprintf(p, sizeof p, "/grow%03d.txt", i);
                if (ext2_write_path(bd_read, bd_write, 0, 0, p, d, 8) != 8) break;
                made++;
            }
            /* ~24 bytes/record at a 1 KiB block => ~42 entries per block, so
             * 200 is already several blocks deep. Without the fix this loop
             * stops in the 30s and the assert below fires. */
            if (made < 200) {
                fprintf(stderr, "FAIL dirgrow: only %d files created; a directory still cannot grow past one block\n", made);
                return 1;
            }

            ext2_t vv; uint8_t rin[256];
            if (ext2_open(bd_read, 0, 0, &vv) < 0)  { fprintf(stderr, "FAIL dirgrow: reopen\n"); return 1; }
            if (read_inode(&vv, 2, rin) < 0)        { fprintf(stderr, "FAIL dirgrow: root inode unreadable\n"); return 1; }
            uint32_t dsz = e_rd32(rin + 4);
            if (dsz <= vv.block_size) {
                fprintf(stderr, "FAIL dirgrow: root dir is still %u bytes (one block) after %d creates\n", dsz, made);
                return 1;
            }

            /* every name must come back from a listing... */
            static fatvol_dirent le[1024];
            int ln = ext2_list_path(bd_read, 0, 0, "/", le, 1024), found = 0;
            for (int i = 0; i < made; i++) {
                snprintf(p, sizeof p, "grow%03d.txt", i);
                for (int j = 0; j < ln; j++) if (!strcmp(le[j].name, p)) { found++; break; }
            }
            if (found != made) {
                fprintf(stderr, "FAIL dirgrow: created %d files but only %d listed back (listing returned %d)\n", made, found, ln);
                return 1;
            }
            /* ...and an entry in a LATER block must still resolve by path, which
             * is what actually exercises map_block past the first block. */
            uint8_t rb2[16];
            snprintf(p, sizeof p, "/grow%03d.txt", made - 1);
            if (ext2_read_path(bd_read, 0, 0, p, rb2, sizeof rb2) != 8) {
                fprintf(stderr, "FAIL dirgrow: the last-created file is not readable by path\n");
                return 1;
            }

            if (argc > 5) { FILE *wf = fopen(argv[5], "wb"); if (wf) { fwrite(g_img, 1, (size_t)g_img_bytes, wf); fclose(wf); } }
            printf("dirgrow (M1933): %d files in ONE directory -- i_size grew to %u bytes (%u blocks), all %d listed back\n",
                   made, dsz, dsz / vv.block_size, found);
        }
    }

    /* --- M1934: STREAMING (positional) writes + double-indirect -------------
     * ext2_write_path takes the whole file as one in-memory buffer and refuses
     * anything past direct + single-indirect. Neither is survivable for a
     * toolchain: a 200 MB binary cannot be held in a kernel buffer, and 268 KB
     * (at a 1 KiB block) is not a meaningful file-size ceiling. */
    if (argc > 4) {
        FILE *df = fopen(argv[4], "rb");
        if (df) {
            g_img_bytes = (long)fread(g_img, 1, sizeof g_img, df);
            fclose(df);
#define PW_CHUNK 4096
#define PW_TOTAL (400 * 1024)
            static uint8_t chunk[PW_CHUNK];
            static uint8_t whole[PW_TOTAL];

            /* (a) build 400 KB from a 4 KB buffer, one pwrite per chunk. At a
             * 1 KiB block that is 400 blocks > 12 + 256, so it also proves
             * double-indirect -- which ext2_write_path rejects outright. */
            for (uint64_t o = 0; o < PW_TOTAL; o += PW_CHUNK) {
                for (int k = 0; k < PW_CHUNK; k++) chunk[k] = (uint8_t)((o + (uint64_t)k) * 31 + 7);
                long w = ext2_pwrite_path(bd_read, bd_write, 0, 0, "/stream.bin", o, chunk, PW_CHUNK);
                if (w != PW_CHUNK) { fprintf(stderr, "FAIL pwrite: chunk at %llu wrote %ld\n", (unsigned long long)o, w); return 1; }
            }
            long rr = ext2_read_path(bd_read, 0, 0, "/stream.bin", whole, PW_TOTAL);
            if (rr != PW_TOTAL) { fprintf(stderr, "FAIL pwrite: read back %ld of %d bytes\n", rr, PW_TOTAL); return 1; }
            for (int k = 0; k < PW_TOTAL; k++)
                if (whole[k] != (uint8_t)((uint64_t)k * 31 + 7)) {
                    fprintf(stderr, "FAIL pwrite: byte %d is %02x, expected %02x\n", k, whole[k], (uint8_t)((uint64_t)k * 31 + 7));
                    return 1;
                }
            /* the old whole-buffer API genuinely cannot express this file */
            if (ext2_write_path(bd_read, bd_write, 0, 0, "/toobig.bin", whole, PW_TOTAL) >= 0) {
                fprintf(stderr, "FAIL pwrite: ext2_write_path unexpectedly accepted %d bytes\n", PW_TOTAL); return 1;
            }

            /* (b) a partial-block edit mid-file must preserve both neighbours
             * and must NOT shrink the file */
            uint8_t patch[5] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x42 };
            if (ext2_pwrite_path(bd_read, bd_write, 0, 0, "/stream.bin", 100003, patch, 5) != 5) {
                fprintf(stderr, "FAIL pwrite: mid-file patch failed\n"); return 1;
            }
            rr = ext2_read_path(bd_read, 0, 0, "/stream.bin", whole, PW_TOTAL);
            if (rr != PW_TOTAL) { fprintf(stderr, "FAIL pwrite: mid-file patch changed size to %ld\n", rr); return 1; }
            if (whole[100002] != (uint8_t)(100002ull * 31 + 7) || whole[100008] != (uint8_t)(100008ull * 31 + 7)) {
                fprintf(stderr, "FAIL pwrite: mid-file patch clobbered a neighbouring byte\n"); return 1;
            }
            for (int k = 0; k < 5; k++)
                if (whole[100003 + k] != patch[k]) { fprintf(stderr, "FAIL pwrite: patch byte %d wrong\n", k); return 1; }

            /* (c) a write far past EOF leaves a real sparse hole reading as zeroes.
             *
             * The obvious version of this check is WORTHLESS: mke2fs leaves free
             * blocks zeroed, so a block recycled into the sparse file reads as
             * zeroes whether or not the code zero-fills it, and a mutation that
             * removed the zero-fill passed cleanly. So dirty a swathe of blocks
             * with 0xAA and free them FIRST — alloc_block hands out the lowest
             * free block, so the sparse file lands on one of them and the
             * partial tail block genuinely contains garbage to begin with. */
            memset(chunk, 0xAA, PW_CHUNK);
            for (uint64_t o = 0; o < 200 * 1024; o += PW_CHUNK)
                if (ext2_pwrite_path(bd_read, bd_write, 0, 0, "/dirty.bin", o, chunk, PW_CHUNK) != PW_CHUNK) {
                    fprintf(stderr, "FAIL pwrite: dirty-fill failed at %llu\n", (unsigned long long)o); return 1;
                }
            if (ext2_unlink_path(bd_read, bd_write, 0, 0, "/dirty.bin") != 0) {
                fprintf(stderr, "FAIL pwrite: could not free the dirty blocks\n"); return 1;
            }

            uint8_t tail[4] = { 1, 2, 3, 4 };
            if (ext2_pwrite_path(bd_read, bd_write, 0, 0, "/sparse.bin", 60000, tail, 4) != 4) {
                fprintf(stderr, "FAIL pwrite: sparse create failed\n"); return 1;
            }
            static uint8_t sp[60004];
            long sr = ext2_read_path(bd_read, 0, 0, "/sparse.bin", sp, sizeof sp);
            if (sr != 60004) { fprintf(stderr, "FAIL pwrite: sparse file is %ld bytes, expected 60004\n", sr); return 1; }
            for (int k = 0; k < 60000; k++)
                if (sp[k] != 0) { fprintf(stderr, "FAIL pwrite: sparse hole byte %d is %02x, not zero\n", k, sp[k]); return 1; }
            if (memcmp(sp + 60000, tail, 4)) { fprintf(stderr, "FAIL pwrite: sparse tail wrong\n"); return 1; }

            if (argc > 6) { FILE *wf = fopen(argv[6], "wb"); if (wf) { fwrite(g_img, 1, (size_t)g_img_bytes, wf); fclose(wf); } }
            printf("pwrite (M1934): 400 KB streamed in 4 KB chunks (double-indirect; whole-buffer API refuses it), "
                   "mid-file patch preserves neighbours, 60 KB sparse hole reads as zeroes\n");
        }
    }

    /* --- M1934: appending to an EXTENT file converts it to indirect ---------
     * Files this driver creates take the single-extent fast path, so appending
     * to one is completely ordinary -- and bmap_alloc cannot grow an extent
     * tree. The conversion must preserve every existing byte. */
    if (argc > 2) {
        FILE *xf2 = fopen(argv[2], "rb");
        if (xf2) {
            g_img_bytes = (long)fread(g_img, 1, sizeof g_img, xf2);
            fclose(xf2);
            static uint8_t orig[20000];
            for (int k = 0; k < (int)sizeof orig; k++) orig[k] = (uint8_t)(k * 13 + 5);
            if (ext2_write_path(bd_read, bd_write, 0, 0, "/CONV.BIN", orig, sizeof orig) != (long)sizeof orig) {
                fprintf(stderr, "FAIL convert: extent create failed\n"); return 1;
            }
            {   /* it must really be extent-mapped, or the test proves nothing */
                ext2_t cv; uint8_t cin[256]; int isd = 0;
                if (ext2_open(bd_read, 0, 0, &cv) < 0) { fprintf(stderr, "FAIL convert: reopen\n"); return 1; }
                uint32_t cino = walk(&cv, "/CONV.BIN", cin, &isd);
                if (!cino || !(e_rd32(cin + 32) & EXT4_EXTENTS_FL)) {
                    fprintf(stderr, "FAIL convert: /CONV.BIN is not extent-mapped to begin with\n"); return 1;
                }
            }
            uint8_t add[1000];
            for (int k = 0; k < 1000; k++) add[k] = (uint8_t)(k * 7 + 3);
            if (ext2_pwrite_path(bd_read, bd_write, 0, 0, "/CONV.BIN", sizeof orig, add, sizeof add) != (long)sizeof add) {
                fprintf(stderr, "FAIL convert: append to an extent file failed\n"); return 1;
            }
            static uint8_t back[21000];
            long cr = ext2_read_path(bd_read, 0, 0, "/CONV.BIN", back, sizeof back);
            if (cr != 21000) { fprintf(stderr, "FAIL convert: read back %ld, expected 21000\n", cr); return 1; }
            if (memcmp(back, orig, sizeof orig)) { fprintf(stderr, "FAIL convert: the original 20000 bytes did not survive conversion\n"); return 1; }
            if (memcmp(back + sizeof orig, add, sizeof add)) { fprintf(stderr, "FAIL convert: appended bytes wrong\n"); return 1; }
            printf("pwrite convert (M1934): appended to an extent-mapped file -- rebuilt as indirect, all 20000 original bytes intact\n");
        }
    }

    /* --- M2237: one wrong-bytes read must not become a corrupt disk --------
     *
     * Six places in ext2.c read the whole group descriptor block, change two
     * bytes of a free count, and write all of it back. The `< 0` they check
     * catches a read that failed; it cannot catch a read that succeeded with
     * the wrong bytes -- and that shape commits those bytes to the disk, so
     * ONE transient bad read permanently destroys the group descriptor table
     * and every inode lookup after it.
     *
     * That is what an 8-core Firefox boot shows: a descriptor rejected from
     * LBA 8, the same wrong bytes still there after dropping the cache and
     * re-reading from the disk, and those bytes present nowhere in either
     * disk image. Bytes that are on no disk, and are now on the disk, were
     * written there.
     *
     * Reload the golden image, snapshot the descriptor block, inject exactly
     * one bad read of it during an allocation, and require the disk to be
     * untouched. */
    {   FILE *gf = fopen(argv[1], "rb");
        if (gf) {
            g_img_bytes = (long)fread(g_img, 1, sizeof g_img, gf);
            fclose(gf);

            ext2_t gv;
            if (ext2_open(bd_read, 0, 0, &gv) < 0) { fprintf(stderr, "FAIL gdt: reopen\n"); return 1; }
            uint32_t spb  = gv.block_size / SECSZ;
            uint64_t gdlba = (uint64_t)gv.gdt_block * spb;

            /* (a) the validator is a real discriminator, not a rubber stamp:
             *     it must accept the genuine block and reject a wild one. */
            static uint8_t gdcopy[4096];
            memcpy(gdcopy, g_img + gdlba * SECSZ, gv.block_size);
            if (!gd_block_ok(&gv, gv.gdt_block, gdcopy)) {
                fprintf(stderr, "FAIL gdt: the REAL descriptor block was rejected\n"); return 1;
            }
            memset(gdcopy, 0xA5, 32);
            if (gd_block_ok(&gv, gv.gdt_block, gdcopy)) {
                fprintf(stderr, "FAIL gdt: a descriptor with three wild block pointers was ACCEPTED\n"); return 1;
            }
            printf("gdt (M2237): ok   -- gd_block_ok accepts the real descriptor block and rejects a wild one\n");

            /* (b) the one that matters. */
            static uint8_t before[4096];
            memcpy(before, g_img + gdlba * SECSZ, gv.block_size);
            unsigned long bad0 = g_e2_gd_badread;

            g_inject_lba = gdlba; g_inject_count = spb; g_inject_left = 1;
            uint8_t payload[64];
            for (int k = 0; k < 64; k++) payload[k] = (uint8_t)k;
            (void)ext2_write_path(bd_read, bd_write, 0, 0, "/POISON.BIN", payload, sizeof payload);
            g_inject_left = 0;

            if (memcmp(before, g_img + gdlba * SECSZ, gv.block_size) != 0) {
                fprintf(stderr, "FAIL gdt: ONE wrong-bytes read was written back -- the descriptor "
                                "block on disk is now corrupt (this is the M2237 bug)\n");
                return 1;
            }
            if (g_e2_gd_badread == bad0) {
                fprintf(stderr, "FAIL gdt: the injected bad read was never noticed, so this test "
                                "is not exercising the check it claims to\n");
                return 1;
            }
            printf("gdt (M2237): ok   -- one wrong-bytes read of the descriptor block did NOT reach the disk (%lu caught)\n",
                   g_e2_gd_badread - bad0);

            /* (c) refusing must not wedge the volume: the very next allocation,
             *     with no injection, has to work and read back byte-exact. */
            if (ext2_write_path(bd_read, bd_write, 0, 0, "/AFTER.BIN", payload, sizeof payload) != (long)sizeof payload) {
                fprintf(stderr, "FAIL gdt: the volume was unusable after a refused descriptor write\n"); return 1;
            }
            uint8_t rb2[64];
            if (ext2_read_path(bd_read, 0, 0, "/AFTER.BIN", rb2, sizeof rb2) != (long)sizeof rb2 ||
                memcmp(rb2, payload, sizeof payload)) {
                fprintf(stderr, "FAIL gdt: /AFTER.BIN did not read back\n"); return 1;
            }
            printf("gdt (M2237): ok   -- the next allocation still succeeds and reads back byte-exact\n");
        }
    }

    printf("PASS\n");
    return 0;
}
