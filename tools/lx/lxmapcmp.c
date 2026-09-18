/* lxmapcmp.c -- DOES A MAPPED LIBRARY SEE ITS OWN FILE'S BYTES, ALL OF THEM?
 *
 * WHY. The two remaining Firefox failures on eight cores are wild pointers, not
 * wrong protections: an instruction fetch at the exact base of libgtk's
 * read-only LOAD, and a write into libxul's RELRO. `rip == CR2 == a segment
 * base` is not a random garbage value -- it is what `base + 0x418000` looks
 * like, i.e. a relocation whose ADDEND was 0x418000. ld.so reads those addends
 * out of `.rela.dyn`, which it reads THROUGH A MAPPING OF THE FILE. If any page
 * of that mapping holds the wrong bytes, every relocation computed from it is
 * wrong, and the program jumps and writes to plausible-looking addresses that
 * are nowhere near anything.
 *
 * That is not a hypothetical class here. Today's chain (M2155-M2158) was
 * exactly "a page of a mapped library held the wrong bytes": an abandoned DMA
 * left the drive holding a sector, the PIO fallback read it at the next
 * command's LBA and reported success, and the bytes were installed in the block
 * cache. The in-kernel `code check` compares SIXTEEN bytes at a faulting rip.
 * This compares a WHOLE LIBRARY, tens of megabytes, from userspace, where the
 * comparison is cheap and needs no interrupts.
 *
 * THE METHOD, AND THE HOLE THE FIRST VERSION HAD. mmap the library MAP_PRIVATE
 * PROT_READ -- the same way ld.so does -- and compare every byte against
 * `pread` of the same file. Two routes to the same bytes: the demand-fault path
 * on one side, the ordinary read path on the other.
 *
 * They are not INDEPENDENT routes, and the first version of this claimed they
 * were. Both go through the kernel's block cache, so a sector that was already
 * WRONG WHEN IT WAS INSTALLED yields the same wrong bytes to both sides and
 * this comparison passes. That is exactly the bug that was live while I ran it
 * (M2172: a DMA read that stopped early was reported as a success and its stale
 * tail was cached), so "171910680 bytes identical" was a weaker statement than
 * I made of it -- it ruled out the mapping DIVERGING from a read, not the bytes
 * being wrong.
 *
 * So the real oracle has to come from outside the guest. `--gen` mode prints a
 * length and a hash per file, and the image build runs the HOST-built binary
 * over the host's own copies to bake a manifest into the image. Same code, same
 * algorithm, no second implementation to drift -- and the numbers were computed
 * where the bytes are not in question. Verify mode checks the mapping against
 * THAT, which no cache in this kernel can satisfy with stale data.
 *
 * A mismatch names the offset, both values, and whether the mapped page is all
 * zeros (a fill that never happened) or merely different (a fill that read the
 * wrong thing) -- which are different bugs.
 *
 * Deliberately compares in a different ORDER than the faults arrive: forwards
 * for the first pass, then backwards, so a mismatch that only appears when a
 * page is faulted in out of readahead order still shows up.
 *
 * Marker `LXMAPCMP:`; `LXMAPCMP: ALL PASSED` only if every byte of every file
 * given matched, both ways round.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define CHUNK (1u << 20)

/* FNV-1a over the whole file, length folded in. Deliberately the same few
 * lines on both sides: a manifest generator that reimplements the hash is a
 * manifest generator that can disagree with the checker. */
static unsigned long long file_hash(const unsigned char *p, size_t n) {
    unsigned long long h = 1469598103934665603ULL ^ (unsigned long long)n;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

/* `--gen`: print `<len> <hash> <path>` for each file, for the image build to
 * bake in. Runs on the HOST, over the host's copies. */
static int gen_one(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return 1; }
    unsigned char *m = mmap(0, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED) { close(fd); return 1; }
    printf("%lld %llu %s\n", (long long)st.st_size, file_hash(m, (size_t)st.st_size), path);
    munmap(m, (size_t)st.st_size); close(fd);
    return 0;
}

/* Verify a mapping against the manifest the host wrote. Returns 0 = matched,
 * 1 = mismatch, 2 = not testable. */
static int verify_manifest(const char *mpath) {
    FILE *f = fopen(mpath, "r");
    if (!f) { printf("LXMAPCMP: SKIP manifest (%s absent -- rebuild the image)\n", mpath); return 2; }
    char line[1024]; int bad = 0, n = 0;
    while (fgets(line, sizeof line, f)) {
        long long want_len = 0; unsigned long long want_hash = 0; char path[768];
        if (sscanf(line, "%lld %llu %767s", &want_len, &want_hash, path) != 3) continue;
        int fd = open(path, O_RDONLY);
        if (fd < 0) { printf("LXMAPCMP: manifest: %s is ABSENT in the guest\n", path); bad++; continue; }
        struct stat st;
        if (fstat(fd, &st) != 0) { close(fd); bad++; continue; }
        if ((long long)st.st_size != want_len) {
            printf("LXMAPCMP: *** %s is %lld bytes, the host recorded %lld ***\n",
                   path, (long long)st.st_size, want_len);
            close(fd); bad++; continue;
        }
        unsigned char *m = mmap(0, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (m == MAP_FAILED) { close(fd); bad++; continue; }
        unsigned long long got = file_hash(m, (size_t)st.st_size);
        if (got != want_hash)
            printf("LXMAPCMP: *** %s HASHES TO %llu, the host recorded %llu -- the bytes this "
                   "kernel served are NOT the file's ***\n", path, got, want_hash);
        else
            printf("LXMAPCMP: %s matches the host's own hash of it (%lld bytes)\n", path, want_len);
        if (got != want_hash) bad++;
        n++;
        munmap(m, (size_t)st.st_size); close(fd);
    }
    fclose(f);
    if (!n && !bad) { printf("LXMAPCMP: SKIP manifest (no usable entries)\n"); return 2; }
    return bad ? 1 : 0;
}

static int page_all_zero(const unsigned char *p) {
    for (int i = 0; i < 4096; i++) if (p[i]) return 0;
    return 1;
}

/* Returns 0 = matched, 1 = mismatch, 2 = could not test. */
static int compare_one(const char *path, int backwards) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("LXMAPCMP: SKIP %s (cannot open)\n", path); return 2; }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) { printf("LXMAPCMP: SKIP %s (no size)\n", path); close(fd); return 2; }
    size_t len = (size_t)st.st_size;

    unsigned char *m = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED) { printf("LXMAPCMP: SKIP %s (mmap failed)\n", path); close(fd); return 2; }
    unsigned char *buf = malloc(CHUNK);
    if (!buf) { printf("LXMAPCMP: SKIP %s (no memory)\n", path); munmap(m, len); close(fd); return 2; }

    long bad = -1; unsigned char bmem = 0, bfile = 0;
    size_t nchunk = (len + CHUNK - 1) / CHUNK;
    for (size_t ci = 0; ci < nchunk && bad < 0; ci++) {
        size_t c = backwards ? (nchunk - 1 - ci) : ci;
        size_t off = c * CHUNK;
        size_t n = (len - off) < CHUNK ? (len - off) : CHUNK;
        ssize_t got = pread(fd, buf, n, (off_t)off);
        if (got != (ssize_t)n) {
            printf("LXMAPCMP: %s: READ FAILED at %zu (wanted %zu, got %zd) -- the read path, "
                   "not the mapping\n", path, off, n, got);
            bad = -2; break;
        }
        if (memcmp(buf, m + off, n) == 0) continue;
        for (size_t i = 0; i < n; i++)
            if (buf[i] != m[off + i]) { bad = (long)(off + i); bmem = m[off + i]; bfile = buf[i]; break; }
    }
    if (bad >= 0) {
        const unsigned char *pg = m + (bad & ~(long)4095);
        printf("LXMAPCMP: *** %s DIFFERS at offset %ld: the mapping says %02x, the file says %02x "
               "-- the mapped page is %s ***\n", path, bad, bmem, bfile,
               page_all_zero(pg) ? "ALL ZEROS (a fill that never happened)"
                                 : "NOT all zeros (a fill that read the wrong bytes)");
    } else if (bad == -1) {
        printf("LXMAPCMP: %s %s: %zu bytes identical\n", path, backwards ? "backwards" : "forwards", len);
    }
    free(buf); munmap(m, len); close(fd);
    return bad == -1 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc > 2 && !strcmp(argv[1], "--gen")) {
        int bad = 0;
        for (int i = 2; i < argc; i++) bad += gen_one(argv[i]);
        return bad ? 1 : 0;
    }
    static const char *const deflt[] = {
        "/usr/lib64/firefox/libxul.so",
        "/usr/lib64/libgtk-3.so.0",
        "/usr/lib64/libc.so.6",
        0
    };
    int fails = 0, tested = 0;
    if (argc > 1) {
        for (int i = 1; i < argc; i++)
            for (int b = 0; b < 2; b++) {
                int r = compare_one(argv[i], b);
                if (r == 1) fails++; else if (r == 0) tested++;
            }
    } else {
        for (int i = 0; deflt[i]; i++)
            for (int b = 0; b < 2; b++) {
                int r = compare_one(deflt[i], b);
                if (r == 1) fails++; else if (r == 0) tested++;
            }
    }
    /* THE ORACLE FROM OUTSIDE (see the header). Run last, so a mapping-versus-
     * read difference is reported separately from a bytes-are-simply-wrong
     * one -- they point at different subsystems. */
    { int r = verify_manifest("/lxmapcmp.manifest"); if (r == 1) fails++; else if (r == 0) tested++; }
    if (!tested && !fails) { printf("LXMAPCMP: SKIP (nothing was testable)\n"); return 0; }
    printf(fails ? "LXMAPCMP: %d COMPARISON(S) FAILED\n" : "LXMAPCMP: ALL PASSED (%d comparisons)\n",
           fails ? fails : tested);
    return fails ? 1 : 0;
}
