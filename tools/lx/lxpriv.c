/* lxpriv.c -- A MAP_PRIVATE FILE MAPPING MUST BE PRIVATE TO THE PROCESS.
 *
 * WHY THIS EXISTS. Two Firefox failures on eight cores both come down to a bad
 * pointer rather than a bad protection: a WRITE into libxul's RELRO segment
 * (which readelf confirms ld.so is right to have made read-only), and an
 * INSTRUCTION FETCH at the exact base of libgtk's read-only data segment. The
 * shape that produces both is one process seeing ANOTHER process's relocations.
 *
 * ld.so maps every PT_LOAD of a shared object MAP_PRIVATE, writes relocations
 * into `.data.rel.ro`, and then mprotects it read-only. Every process loads the
 * library at its own ASLR base, so those relocated pointers are only valid for
 * the process that wrote them. If a MAP_PRIVATE file page were shared between
 * processes instead of copied, process B would read pointers relocated for
 * process A's base -- and a pointer that is wrong by a whole load bias lands
 * somewhere like "the base of a read-only segment", which is precisely what the
 * crash reports say.
 *
 * lxcow already covers concurrent COW breaks on ANONYMOUS memory after fork,
 * and lxfmap covers mapping at a non-zero offset. Neither asks whether a
 * private file mapping is private ACROSS PROCESSES, which is the ld.so case.
 *
 * FOUR ASSERTIONS, each a different way to get this wrong:
 *   1. a SECOND, INDEPENDENT process mapping the same file sees the FILE's
 *      bytes, not this process's writes  (the ld.so case; uses execve, not
 *      fork, because fork is allowed to share by copy-on-write)
 *   2. the file ON DISK is unchanged -- MAP_PRIVATE writes never write back
 *   3. a fork CHILD sees the parent's pre-fork writes (correct COW inheritance)
 *   4. the child's own writes are NOT visible to the parent
 *
 * Marker `LXPRIV:` lines; `LXPRIV: ALL PASSED` only when all four hold.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define PGSZ  4096
#define NPG   4
#define LEN   (PGSZ * NPG)

/* The file's own content: byte i is (i * 7 + 11) & 0xff, so any byte says
 * which offset it came from and a whole-page shift cannot look correct. */
static unsigned char filebyte(long i) { return (unsigned char)((i * 7 + 11) & 0xff); }
/* What this process writes over it, distinguishable from the file's bytes. */
static unsigned char mybyte(long i, int tag) { return (unsigned char)((i * 13 + tag * 61 + 3) & 0xff); }

static int make_file(const char *path) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    unsigned char *buf = malloc(LEN);
    if (!buf) { close(fd); return -1; }
    for (long i = 0; i < LEN; i++) buf[i] = filebyte(i);
    if (write(fd, buf, LEN) != LEN) { free(buf); close(fd); return -1; }
    free(buf);
    return fd;
}

/* The second, independent process: map the file and require the FILE's bytes. */
static int child_check(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("LXPRIV-CHILD: open failed\n"); return 2; }
    unsigned char *m = mmap(0, LEN, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED) { printf("LXPRIV-CHILD: mmap failed\n"); close(fd); return 2; }
    long bad = -1;
    for (long i = 0; i < LEN; i++)
        if (m[i] != filebyte(i)) { bad = i; break; }
    if (bad >= 0)
        printf("LXPRIV-CHILD: FAILED at offset %ld: saw %02x, the file holds %02x "
               "(another process's private writes are visible here)\n",
               bad, m[bad], filebyte(bad));
    else
        printf("LXPRIV-CHILD: ok -- the file's own bytes, all %d of them\n", LEN);
    munmap(m, LEN); close(fd);
    return bad >= 0 ? 1 : 0;
}

int main(int argc, char **argv) {
    const char *path = "/tmp/lxpriv.bin";
    if (argc > 1 && !strcmp(argv[1], "child")) return child_check(argc > 2 ? argv[2] : path);

    int fails = 0;
    int fd = make_file(path);
    if (fd < 0) { printf("LXPRIV: SKIP (cannot create %s)\n", path); return 0; }

    unsigned char *m = mmap(0, LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED) { printf("LXPRIV: SKIP (mmap failed)\n"); return 0; }
    for (long i = 0; i < LEN; i++) if (m[i] != filebyte(i)) {
        printf("LXPRIV: FAILED -- the mapping did not show the file at offset %ld\n", i);
        fails++; break;
    }
    /* Write over every page, the way ld.so writes relocations. */
    for (long i = 0; i < LEN; i++) m[i] = mybyte(i, 1);

    /* 1. A SECOND, INDEPENDENT PROCESS. execve, not fork: fork may legitimately
     *    share these pages copy-on-write, so it cannot answer this question. */
    pid_t p = fork();
    if (p == 0) {
        execl("/proc/self/exe", argv[0], "child", path, (char *)0);
        execl(argv[0], argv[0], "child", path, (char *)0);
        _exit(3);
    }
    int st = 0;
    if (p > 0) waitpid(p, &st, 0);
    if (!(p > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0)) {
        if (WIFEXITED(st) && WEXITSTATUS(st) == 3) printf("LXPRIV: SKIP (could not re-exec)\n");
        else { printf("LXPRIV: FAILED -- an independent process saw this one's private writes\n"); fails++; }
    } else printf("LXPRIV: an independent process mapping the same file saw the FILE\n");

    /* 2. The file on disk is untouched. */
    {
        unsigned char *disk = malloc(LEN);
        ssize_t got = disk ? pread(fd, disk, LEN, 0) : -1;
        long bad = -1;
        if (got == LEN) for (long i = 0; i < LEN; i++) if (disk[i] != filebyte(i)) { bad = i; break; }
        if (got != LEN)      { printf("LXPRIV: FAILED -- could not read the file back\n"); fails++; }
        else if (bad >= 0)   { printf("LXPRIV: FAILED -- a MAP_PRIVATE write reached the FILE at %ld\n", bad); fails++; }
        else                   printf("LXPRIV: the file on disk is unchanged\n");
        free(disk);
    }

    /* 3 + 4. fork inheritance, and isolation the other way. */
    p = fork();
    if (p == 0) {
        int bad = 0;
        for (long i = 0; i < LEN; i += 512) if (m[i] != mybyte(i, 1)) { bad = 1; break; }
        for (long i = 0; i < LEN; i++) m[i] = mybyte(i, 2);      /* the child's own writes */
        _exit(bad ? 1 : 0);
    }
    st = 0; if (p > 0) waitpid(p, &st, 0);
    if (!(p > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0)) {
        printf("LXPRIV: FAILED -- a fork child did not inherit the parent's pre-fork writes\n"); fails++;
    } else printf("LXPRIV: a fork child inherited the parent's pre-fork writes\n");
    {
        long bad = -1;
        for (long i = 0; i < LEN; i++) if (m[i] != mybyte(i, 1)) { bad = i; break; }
        if (bad >= 0) { printf("LXPRIV: FAILED -- the child's writes are visible in the PARENT at %ld "
                               "(saw %02x, expected %02x)\n", bad, m[bad], mybyte(bad, 1)); fails++; }
        else printf("LXPRIV: the child's writes stayed in the child\n");
    }

    munmap(m, LEN); close(fd); unlink(path);
    printf(fails ? "LXPRIV: %d CHECK(S) FAILED\n" : "LXPRIV: ALL PASSED\n", fails);
    return fails ? 1 : 0;
}
