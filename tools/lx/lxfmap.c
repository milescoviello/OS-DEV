/* File-backed mmap with a non-zero OFFSET (M1953) -- the shape a dynamic
 * linker uses for every PT_LOAD of a shared object. The assertion is that the
 * RIGHT BYTES appear: mapping at offset N must show the file's byte N, not its
 * byte 0. A test that only checked "the mapping succeeded" would pass with the
 * offset silently ignored, which is exactly the bug worth catching. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#define PGSZ 4096

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "/disk2/lxfmap.bin";
    /* Build a file whose every page is stamped with its own page number, so a
     * wrong offset is immediately visible rather than plausible. */
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { printf("LXFMAP: create failed\n"); fflush(stdout); return 1; }
    static unsigned char page[PGSZ];
    for (int p = 0; p < 4; p++) {
        memset(page, (unsigned char)(0x10 + p), PGSZ);
        if (write(fd, page, PGSZ) != PGSZ) { printf("LXFMAP: write failed\n"); fflush(stdout); return 2; }
    }
    close(fd);

    fd = open(path, O_RDONLY);
    if (fd < 0) { printf("LXFMAP: reopen failed\n"); fflush(stdout); return 3; }
    /* Map ONE page starting at file offset 2*PGSZ -- so it must read 0x12. */
    unsigned char *m = mmap(NULL, PGSZ, PROT_READ, MAP_PRIVATE, fd, 2 * PGSZ);
    if (m == MAP_FAILED) { printf("LXFMAP: mmap at an offset failed\n"); fflush(stdout); return 4; }
    unsigned char got = m[0], want = 0x12;
    int bad = 0;
    for (int i = 0; i < PGSZ; i++) if (m[i] != want) { bad = 1; break; }
    close(fd);

    if (got != want || bad) {
        printf("LXFMAP: offset IGNORED -- saw 0x%02x, wanted 0x%02x\n", got, want);
        fflush(stdout);
        return 5;
    }
    printf("LXFMAP: file-backed mmap at offset 8192 read the right page (0x%02x)\n", got);
    fflush(stdout);
    return 0;
}
