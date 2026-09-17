/* lxcwd -- what does a Linux program actually learn about the ROOT DIRECTORY?
 *
 * Claude Code stops before it does anything useful with
 *
 *     Error: Can't access working directory /: Path "/" does not exist
 *
 * and the syscall trace does not say which question it asked, because the
 * tracer only prints the calls that FAIL BY PATH. A runtime has half a dozen
 * ways to ask "does this directory exist" and they go through different kernel
 * paths -- stat, lstat, statx, access, openat(O_DIRECTORY), opendir/readdir,
 * realpath, chdir. This asks all of them about "/" (and about the cwd getcwd
 * reports) and prints each answer, so the gap is NAMED instead of inferred.
 *
 * Ten seconds instead of ten minutes of Claude Code. (M1998)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/syscall.h>

static int fails;

static void probe(const char *path) {
    printf("LXCWD: ---- %s ----\n", path);

    struct stat st;
    if (stat(path, &st) == 0)
        printf("LXCWD: stat ok mode=%o dir=%d size=%lld nlink=%lu ino=%llu dev=%llu blksz=%ld blocks=%lld\n",
               st.st_mode & 07777, S_ISDIR(st.st_mode), (long long)st.st_size,
               (unsigned long)st.st_nlink, (unsigned long long)st.st_ino,
               (unsigned long long)st.st_dev, (long)st.st_blksize,
               (long long)st.st_blocks);
    else { printf("LXCWD: stat FAILED errno=%d\n", errno); fails++; }

    if (lstat(path, &st) == 0)
        printf("LXCWD: lstat ok dir=%d\n", S_ISDIR(st.st_mode));
    else { printf("LXCWD: lstat FAILED errno=%d\n", errno); fails++; }

    /* statx is what a modern runtime actually calls. */
    char buf[256];
    long r = syscall(SYS_statx, AT_FDCWD, path, 0, 0x7ff /* STATX_BASIC_STATS */, buf);
    if (r == 0) printf("LXCWD: statx ok mode=%o\n", *(unsigned short *)(buf + 0x1c));
    else { printf("LXCWD: statx FAILED errno=%d\n", errno); fails++; }

    /* DO THE TWO SPELLINGS AGREE? (M2107)
     *
     * This file has stat'd the same path three ways since M1998 and never once
     * COMPARED the answers -- it printed `mode` from statx and nothing else, so
     * st_dev was never read and the divergence it was written to find sat here
     * in plain sight through every green run.
     *
     * The answers matter because a runtime uses them together: Bun's Zig
     * standard library records (st_dev, st_ino) for a directory and re-checks
     * it before running a command, so two handlers that disagree read as "the
     * directory was swapped underneath you". st_dev came back 0x801 from stat
     * and 0 from statx, and Claude Code's Bash tool refused for that reason.
     *
     * A kernel is free to choose any device number it likes. It is not free to
     * report two. */
    if (r == 0 && stat(path, &st) == 0) {
        unsigned maj = *(unsigned *)(buf + 136), min = *(unsigned *)(buf + 140);
        unsigned long long xdev = ((unsigned long long)(min & 0xff))
                                | ((unsigned long long)(maj & 0xfff) << 8)
                                | ((unsigned long long)(min & ~0xffu) << 12)
                                | ((unsigned long long)(maj & ~0xfffu) << 32);
        unsigned long long xino = *(unsigned long long *)(buf + 32);
        if (xdev == (unsigned long long)st.st_dev)
            printf("LXCWD: ok   stat and statx AGREE on st_dev (%llu, from major %u minor %u)\n",
                   xdev, maj, min);
        else {
            printf("LXCWD: FAIL stat says dev=%llu but statx says dev=%llu (major %u minor %u) "
                   "-- one path, two devices, so a (dev,ino) guard sees it move\n",
                   (unsigned long long)st.st_dev, xdev, maj, min);
            fails++;
        }
        if (xino == (unsigned long long)st.st_ino)
            printf("LXCWD: ok   stat and statx AGREE on st_ino (%llu)\n", xino);
        else {
            printf("LXCWD: FAIL stat says ino=%llu but statx says ino=%llu\n",
                   (unsigned long long)st.st_ino, xino);
            fails++;
        }
    }

    if (access(path, F_OK) == 0) printf("LXCWD: access F_OK ok\n");
    else { printf("LXCWD: access F_OK FAILED errno=%d\n", errno); fails++; }
    if (access(path, R_OK | X_OK) == 0) printf("LXCWD: access R_OK|X_OK ok\n");
    else { printf("LXCWD: access R_OK|X_OK FAILED errno=%d\n", errno); fails++; }

    int fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd >= 0) { printf("LXCWD: open O_DIRECTORY ok fd=%d\n", fd); close(fd); }
    else { printf("LXCWD: open O_DIRECTORY FAILED errno=%d\n", errno); fails++; }

    DIR *d = opendir(path);
    if (d) {
        int n = 0; struct dirent *e;
        while ((e = readdir(d))) n++;
        printf("LXCWD: opendir ok, %d entries\n", n);
        closedir(d);
    } else { printf("LXCWD: opendir FAILED errno=%d\n", errno); fails++; }

    char rp[4096];
    if (realpath(path, rp)) printf("LXCWD: realpath -> %s\n", rp);
    else { printf("LXCWD: realpath FAILED errno=%d\n", errno); fails++; }

    /* THE ZIG/BUN IDIOM, and the reason a glibc probe can pass while Claude
     * Code fails: Bun does not call realpath(3). It opens the path O_PATH and
     * reads back /proc/self/fd/<n>, and it asks fstatat(fd, "",
     * AT_EMPTY_PATH) rather than stat(path). Different kernel paths entirely.
     * Claude Code is a Bun binary, so these are the calls that matter. */
    int pf = open(path, O_PATH | O_CLOEXEC);
    if (pf < 0) { printf("LXCWD: open O_PATH FAILED errno=%d\n", errno); fails++; }
    else {
        char lnk[64], tgt[4096];
        snprintf(lnk, sizeof lnk, "/proc/self/fd/%d", pf);
        ssize_t n = readlink(lnk, tgt, sizeof tgt - 1);
        if (n >= 0) { tgt[n] = 0; printf("LXCWD: readlink %s -> %s\n", lnk, tgt); }
        else { printf("LXCWD: readlink %s FAILED errno=%d\n", lnk, errno); fails++; }
        struct stat es;
        if (fstatat(pf, "", &es, AT_EMPTY_PATH) == 0)
            printf("LXCWD: fstatat AT_EMPTY_PATH ok dir=%d\n", S_ISDIR(es.st_mode));
        else { printf("LXCWD: fstatat AT_EMPTY_PATH FAILED errno=%d\n", errno); fails++; }
        if (fstat(pf, &es) == 0) printf("LXCWD: fstat ok dir=%d\n", S_ISDIR(es.st_mode));
        else { printf("LXCWD: fstat FAILED errno=%d\n", errno); fails++; }
        close(pf);
    }
}

/* The exact shape Claude Code failed on:
 *
 *     [linuxabi] mkdir(/disk2/root/.claude/projects/-/memory) failed
 *
 * A nested tree created one component at a time, with a component named "-".
 * `mkdir -p` does this, which means so does every Makefile that builds into an
 * output directory -- so this is the self-hosting path too, not just Claude
 * Code's. Each level is reported separately: "the deepest one failed" and "all
 * of them failed" are different bugs. (M1998) */
static void mkchain(void) {
    static const char *dirs[] = {
        "/root/lxcwd", "/root/lxcwd/projects", "/root/lxcwd/projects/-",
        "/root/lxcwd/projects/-/memory",
    };
    int n = (int)(sizeof dirs / sizeof dirs[0]);
    for (int i = 0; i < n; i++) {
        if (mkdir(dirs[i], 0755) == 0 || errno == EEXIST) {
            struct stat st;
            if (stat(dirs[i], &st) == 0 && S_ISDIR(st.st_mode))
                printf("LXCWD: mkdir %s ok\n", dirs[i]);
            else { printf("LXCWD: mkdir %s claimed success but is not a directory\n", dirs[i]); fails++; }
        } else { printf("LXCWD: mkdir %s FAILED errno=%d\n", dirs[i], errno); fails++; }
    }
    /* ...and a file inside the deepest one, because a directory you cannot
     * write into is not a directory you created. */
    int fd = open("/root/lxcwd/projects/-/memory/f", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) { write(fd, "ok\n", 3); close(fd); printf("LXCWD: wrote a file into the deepest directory\n"); }
    else { printf("LXCWD: open in the deepest directory FAILED errno=%d\n", errno); fails++; }
    unlink("/root/lxcwd/projects/-/memory/f");
    for (int i = n - 1; i >= 0; i--)
        if (rmdir(dirs[i]) != 0) { printf("LXCWD: rmdir %s FAILED errno=%d\n", dirs[i], errno); fails++; }
}

/* SYMLINKS ON THE REAL FILESYSTEM. Firefox says
 *
 *     Gdk-WARNING: Failed to load cursor theme Adwaita
 *
 * and the Adwaita cursor directory is almost entirely symlinks -- left_ptr is
 * a link to "default". readlink() on a real file was ENOENT until M1998, and
 * whether open() FOLLOWS one is a separate question with a separate answer.
 * A cursor theme that will not load is not cosmetic: GDK treats the result as
 * a theme it does not have. (M1999) */
static void symlinks(void) {
    const char *cur = "/usr/share/icons/Adwaita/cursors/left_ptr";
    char tgt[256];
    ssize_t n = readlink(cur, tgt, sizeof tgt - 1);
    if (n > 0) { tgt[n] = 0; printf("LXCWD: readlink %s -> %s\n", cur, tgt); }
    else printf("LXCWD: readlink %s -> errno=%d (not a symlink here?)\n", cur, errno);

    /* Whatever it is, opening it must produce an Xcursor file: "Xcur" magic.
     * That is the whole question -- does a path THROUGH a symlink resolve. */
    int fd = open(cur, O_RDONLY);
    if (fd < 0) { printf("LXCWD: open %s FAILED errno=%d\n", cur, errno); fails++; return; }
    char magic[4] = {0, 0, 0, 0};
    ssize_t r = read(fd, magic, 4);
    close(fd);
    if (r == 4 && magic[0] == 'X' && magic[1] == 'c' && magic[2] == 'u' && magic[3] == 'r')
        printf("LXCWD: opened the cursor through its symlink and read the Xcur magic\n");
    else {
        printf("LXCWD: cursor read %zd bytes, magic %02x%02x%02x%02x (want 'Xcur')\n",
               r, magic[0], magic[1], magic[2], magic[3]);
        fails++;
    }
    /* ...and one we make ourselves, so the test does not depend on staging. */
    unlink("/root/lxcwd-link");
    unlink("/root/lxcwd-hard");
    if (symlink("/etc/machine-id", "/root/lxcwd-link") != 0) {
        printf("LXCWD: symlink() FAILED errno=%d\n", errno); fails++; return;
    }
    char own[256];
    n = readlink("/root/lxcwd-link", own, sizeof own - 1);
    if (n > 0) { own[n] = 0; printf("LXCWD: our own symlink reads back as %s\n", own); }
    else { printf("LXCWD: readlink of our own symlink FAILED errno=%d\n", errno); fails++; }
    fd = open("/root/lxcwd-link", O_RDONLY);
    if (fd >= 0) { char b[8]; ssize_t k = read(fd, b, 8); close(fd);
        if (k > 0) printf("LXCWD: open() FOLLOWED our symlink (%zd bytes)\n", k);
        else { printf("LXCWD: open followed the link but read nothing\n"); fails++; } }
    else { printf("LXCWD: open of our own symlink FAILED errno=%d\n", errno); fails++; }
    unlink("/root/lxcwd-link");

    /* A HARD LINK, and TIMESTAMPS. Firefox links a temporary into place to make
     * a profile write atomic, and Claude Code sets times on the files it
     * writes; both syscalls returned ENOSYS while the VFS had done the work
     * since M1207 and M1230. (M1999) */
    if (link("/etc/machine-id", "/root/lxcwd-hard") == 0) {
        struct stat a1s, b1s;
        if (stat("/etc/machine-id", &a1s) == 0 && stat("/root/lxcwd-hard", &b1s) == 0 &&
            a1s.st_ino == b1s.st_ino && a1s.st_ino != 0)
            printf("LXCWD: hard link shares the inode (%llu)\n", (unsigned long long)a1s.st_ino);
        else { printf("LXCWD: hard link did not share an inode\n"); fails++; }
        unlink("/root/lxcwd-hard");
    } else { printf("LXCWD: link() FAILED errno=%d\n", errno); fails++; }

    int tfd = open("/root/lxcwd-times", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (tfd >= 0) {
        write(tfd, "t\n", 2); close(tfd);
        struct timespec ts[2];
        ts[0].tv_sec = 1000000000; ts[0].tv_nsec = 0;      /* 2001-09-09 */
        ts[1].tv_sec = 1000000000; ts[1].tv_nsec = 0;
        if (utimensat(AT_FDCWD, "/root/lxcwd-times", ts, 0) == 0) {
            struct stat us;
            if (stat("/root/lxcwd-times", &us) == 0 && us.st_mtime == 1000000000)
                printf("LXCWD: utimensat set mtime and stat read it back\n");
            else { printf("LXCWD: utimensat claimed success, mtime is %ld\n",
                          (long)(stat("/root/lxcwd-times", &us) == 0 ? us.st_mtime : -1)); fails++; }
        } else { printf("LXCWD: utimensat FAILED errno=%d\n", errno); fails++; }
        unlink("/root/lxcwd-times");
    } else { printf("LXCWD: could not create a file to time-stamp errno=%d\n", errno); fails++; }
}

int main(void) {
    char cwd[4096];
    if (getcwd(cwd, sizeof cwd)) printf("LXCWD: getcwd -> %s\n", cwd);
    else { printf("LXCWD: getcwd FAILED errno=%d\n", errno); fails++; strcpy(cwd, "?"); }

    char lk[4096];
    ssize_t ln = readlink("/proc/self/cwd", lk, sizeof lk - 1);
    if (ln >= 0) { lk[ln] = 0; printf("LXCWD: readlink /proc/self/cwd -> %s\n", lk); }
    else { printf("LXCWD: readlink /proc/self/cwd FAILED errno=%d\n", errno); fails++; }
    ln = readlink("/proc/self/exe", lk, sizeof lk - 1);
    if (ln >= 0) { lk[ln] = 0; printf("LXCWD: readlink /proc/self/exe -> %s\n", lk); }
    else { printf("LXCWD: readlink /proc/self/exe FAILED errno=%d\n", errno); fails++; }

    probe("/");
    if (strcmp(cwd, "/") != 0 && cwd[0] == '/') probe(cwd);

    /* chdir("/") then ask again: a runtime that starts elsewhere still has to
     * be able to GET to the root. */
    if (chdir("/") == 0) {
        printf("LXCWD: chdir(/) ok\n");
        if (getcwd(cwd, sizeof cwd)) printf("LXCWD: getcwd after chdir -> %s\n", cwd);
        else { printf("LXCWD: getcwd after chdir FAILED errno=%d\n", errno); fails++; }
    } else { printf("LXCWD: chdir(/) FAILED errno=%d\n", errno); fails++; }

    mkchain();
    symlinks();

    printf("LXCWD: %d probe(s) failed\n", fails);
    return fails ? 1 : 0;
}
