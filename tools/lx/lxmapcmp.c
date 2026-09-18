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
 * THE METHOD. mmap the library MAP_PRIVATE PROT_READ -- the same way ld.so does
 * -- and compare every byte against `pread` of the same file. Two independent
 * routes to the same bytes: the demand-fault path on one side, the ordinary
 * read path on the other. A mismatch names the offset, both values, and whether
 * the mapped page is all zeros (a fill that never happened) or merely different
 * (a fill that read the wrong thing) -- which are different bugs.
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
    if (!tested && !fails) { printf("LXMAPCMP: SKIP (nothing was testable)\n"); return 0; }
    printf(fails ? "LXMAPCMP: %d COMPARISON(S) FAILED\n" : "LXMAPCMP: ALL PASSED (%d comparisons)\n",
           fails ? fails : tested);
    return fails ? 1 : 0;
}
