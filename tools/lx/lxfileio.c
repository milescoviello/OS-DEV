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
    return (lines == 200 && st.st_size == bytes && nents > 0) ? 0 : 2;
}
