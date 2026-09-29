/* A demanding glibc program: real file I/O and a directory listing -- i.e. the
 * syscall surface a `cat` and an `ls` actually need. busybox is not obtainable
 * on this host (no binary, no source, only an unbuilt ebuild), and the point of
 * Phase 3 is the ABI surface rather than one particular binary, so this drives
 * the same calls: openat, write, read, lseek, close, fstat, getdents64. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>

int main(int argc, char **argv) {
    const char *dir  = argc > 1 ? argv[1] : "/";   /* the Linux root IS the ext2 volume (M1954) */
    char path[256];
    snprintf(path, sizeof path, "%s/lxio.txt", dir);

    /* 1. write a file through glibc stdio */
    FILE *f = fopen(path, "w");
    if (!f) { printf("LXIO: fopen(w) failed\n"); return 1; }
    for (int i = 0; i < 200; i++) fprintf(f, "line %d\n", i);
    fclose(f);

    /* 2. read it back and count */
    f = fopen(path, "r");
    if (!f) { printf("LXIO: fopen(r) failed\n"); return 1; }
    char buf[64]; int lines = 0; long bytes = 0;
    while (fgets(buf, sizeof buf, f)) { lines++; bytes += (long)strlen(buf); }
    fclose(f);

    /* 3. stat it */
    struct stat st;
    if (stat(path, &st) != 0) { printf("LXIO: stat failed\n"); return 1; }

    /* 4. list the directory (getdents64 under the hood) */
    int nents = 0;
    DIR *d = opendir(dir);
    if (d) { while (readdir(d)) nents++; closedir(d); }

    printf("LXIO: wrote+read %d lines / %ld bytes, stat size=%ld, dir entries=%d\n",
           lines, bytes, (long)st.st_size, nents);
    fflush(stdout);
    /* ONE OPENING, SHARED OFFSET. dup'd and forked descriptors share the file
     * position (POSIX's open file description): `cmd >log 2>&1` depends on it.
     * Each descriptor used to keep its own cursor, so the second writer
     * overwrote the first. And O_APPEND writes at end-of-file EVERY time. */
    int shared_ok = 0;
    {
        const char *sp = "/root/lxio-shared.txt";
        unlink(sp);
        int a = open(sp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        int b = (a >= 0) ? dup(a) : -1;
        if (a >= 0 && b >= 0 && write(a, "AAAA", 4) == 4 && write(b, "BBBB", 4) == 4) {
            pid_t pid = fork();
            if (pid == 0) { ssize_t w = write(a, "CCCC", 4); _exit(w == 4 ? 0 : 1); }
            int stt = 0; waitpid(pid, &stt, 0);
            if (write(b, "DDDD", 4) == 4) {
                int x = open(sp, O_WRONLY | O_APPEND), y = open(sp, O_WRONLY | O_APPEND);
                if (x >= 0 && y >= 0 && write(x, "EE", 2) == 2 && write(y, "FF", 2) == 2) {
                    char got[64] = {0};
                    int r = open(sp, O_RDONLY);
                    ssize_t n = (r >= 0) ? read(r, got, sizeof got - 1) : -1;
                    if (n == 20 && memcmp(got, "AAAABBBBCCCCDDDDEEFF", 20) == 0) shared_ok = 1;
                    else printf("LXIO: shared-offset file reads \"%.*s\" (%zd bytes), want AAAABBBBCCCCDDDDEEFF\n",
                                (int)(n > 0 ? n : 0), got, n);
                    if (r >= 0) close(r);
                }
                if (x >= 0) close(x);
                if (y >= 0) close(y);
            }
        }
        if (a >= 0) close(a);
        if (b >= 0) close(b);
        unlink(sp);
    }
    if (shared_ok) printf("LXIO: dup'd and forked descriptors share one offset, O_APPEND appends every write\n");

    /* THE rm -r SHAPE: list a directory in small getdents64 calls, deleting
     * each entry as it is read. The listing used to be rebuilt per call and
     * indexed by the fd's offset, so deletions shifted the rest past it and
     * entries were skipped. A 256-byte buffer forces many calls (glibc's
     * readdir would take all 300 in one and never reach the bug). */
    int rmr_ok = 0;
    {
        const char *d = "/root/lxio-rmr";
        char pth[128];
        mkdir(d, 0755);
        for (int i = 0; i < 300; i++) {
            snprintf(pth, sizeof pth, "%s/f%03d", d, i);
            int f = open(pth, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (f >= 0) close(f);
        }
        int dfd = open(d, O_RDONLY | O_DIRECTORY);
        int removed = 0;
        char db[256];
        for (;;) {
            long nb = (dfd >= 0) ? syscall(SYS_getdents64, dfd, db, sizeof db) : -1;
            if (nb <= 0) break;
            for (long o = 0; o < nb; ) {
                unsigned short reclen = *(unsigned short *)(db + o + 16);
                const char *nm = db + o + 19;
                if (nm[0] != '.') {
                    snprintf(pth, sizeof pth, "%s/%s", d, nm);
                    if (unlink(pth) == 0) removed++;
                }
                if (!reclen) break;
                o += reclen;
            }
        }
        if (dfd >= 0) close(dfd);
        int rmd = rmdir(d);
        if (removed == 300 && rmd == 0) rmr_ok = 1;
        else printf("LXIO: deleting while reading removed %d of 300 entries, rmdir %s\n",
                    removed, rmd == 0 ? "ok" : "FAILED");
    }
    if (rmr_ok) printf("LXIO: reading a directory while deleting it returned every entry\n");
    return (lines == 200 && st.st_size == bytes && nents > 0 && shared_ok && rmr_ok) ? 0 : 2;
}
