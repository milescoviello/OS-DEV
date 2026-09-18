/* lxwrite.c -- THE KERNEL HALF OF CLAUDE CODE'S EDIT TOOL, WITHOUT THE API.
 *
 * WHY. Phase 7's demo is "Claude Code edits a file in the OS-DEV source tree,
 * inside OS-DEV". Today that cannot be run at all: the staged OAuth session's
 * access token expired and the CLI declines to refresh it, so every run stops
 * at `Failed to authenticate` before it reaches a tool call. Renewing the login
 * needs a human.
 *
 * But the API is only half of that demo. The other half is a kernel path, and
 * it is a DIFFERENT path from the Bash tool that M2130 proved: Write and Edit
 * go through openat(O_CREAT|O_TRUNC|O_WRONLY) / write / close / fsync against
 * ext2, where Bash goes through fork, execve and a pipe. Nothing exercises the
 * write path against the real source tree. This does -- so when the login is
 * renewed, the only untested thing left is Claude Code itself.
 *
 * The method this project keeps coming back to: build a probe smaller than the
 * program, and assert what the program would assert.
 *
 * WHAT AN EDIT ACTUALLY DOES, and each step is a way to fail:
 *   1. read the original (Edit refuses to touch a file it has not read)
 *   2. create a new file, write it, close it, read it back
 *   3. OVERWRITE an existing file with O_TRUNC and a SHORTER body -- the case
 *      that leaves a stale tail if truncation is ignored, which would corrupt
 *      the source tree silently rather than failing
 *   4. fsync, then re-open and re-read, because "write returned N" is not
 *      "the bytes are on the disk"
 *   5. rename over the original, the atomic-replace idiom every editor uses
 *   6. and leave the tree exactly as it was found
 *
 * Marker `LXWRITE:`; `LXWRITE: ALL PASSED` only when every step held.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define DIR_DEFAULT "/src"

static int fails;
static void bad(const char *what) { printf("LXWRITE: FAILED -- %s\n", what); fails++; }

static long slurp(const char *path, char *buf, long max) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    long n = 0, r;
    while (n < max && (r = read(fd, buf + n, (size_t)(max - n))) > 0) n += r;
    close(fd);
    return n;
}

static int put(const char *path, const char *body, int do_fsync) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    long len = (long)strlen(body), n = 0, w;
    while (n < len && (w = write(fd, body + n, (size_t)(len - n))) > 0) n += w;
    if (do_fsync && fsync(fd) != 0) { close(fd); return -2; }
    if (close(fd) != 0) return -3;
    return n == len ? 0 : -4;
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : DIR_DEFAULT;
    char path[512], path2[512], buf[4096];
    snprintf(path,  sizeof path,  "%s/OSDEV-LXWRITE.txt", dir);
    snprintf(path2, sizeof path2, "%s/OSDEV-LXWRITE.tmp", dir);

    /* 1. The tree is readable at all -- if this fails the rest says nothing. */
    {   char probe[256];
        char mk[512]; snprintf(mk, sizeof mk, "%s/Makefile", dir);
        if (slurp(mk, probe, sizeof probe) <= 0) {
            printf("LXWRITE: SKIP (%s does not look like the source tree)\n", dir);
            return 0;
        }
        printf("LXWRITE: %s is readable\n", mk);
    }

    /* 2. Create, write, close, read back. */
    static const char *const body1 =
        "OSDEV-WRITE-OK line one\nline two\nline three, longer than what replaces it\n";
    if (put(path, body1, 0) != 0) bad("creating a new file and writing it");
    else {
        long n = slurp(path, buf, sizeof buf);
        if (n != (long)strlen(body1) || memcmp(buf, body1, (size_t)n) != 0)
            bad("the new file did not read back as written");
        else printf("LXWRITE: created a file and read it back (%ld bytes)\n", n);
    }

    /* 3. OVERWRITE with a SHORTER body. O_TRUNC ignored leaves a stale tail,
     *    which in a source tree is silent corruption rather than an error. */
    static const char *const body2 = "OSDEV-WRITE-OK short\n";
    if (put(path, body2, 1) != 0) bad("overwriting with O_TRUNC and fsync");
    else {
        long n = slurp(path, buf, sizeof buf);
        if (n != (long)strlen(body2))
            printf("LXWRITE: FAILED -- O_TRUNC left a stale tail: %ld bytes, expected %ld\n",
                   n, (long)strlen(body2)), fails++;
        else if (memcmp(buf, body2, (size_t)n) != 0)
            bad("the overwritten file has the wrong contents");
        else printf("LXWRITE: overwrote it shorter, fsync'd, and it is exactly %ld bytes\n", n);
    }

    /* 4. fsync then a FRESH open -- "write returned N" is not "it is on disk".
     *    A cached-but-unwritten file reads back correctly from the same
     *    descriptor and wrongly from a new one. */
    {   long n = slurp(path, buf, sizeof buf);
        if (n != (long)strlen(body2) || memcmp(buf, body2, (size_t)n) != 0)
            bad("a fresh open after fsync did not see the written bytes");
        else printf("LXWRITE: a fresh open after fsync sees the same bytes\n");
    }

    /* 5. rename over it -- the atomic-replace every editor uses, and the idiom
     *    Claude Code's Write tool relies on. */
    static const char *const body3 = "OSDEV-WRITE-OK renamed into place\n";
    if (put(path2, body3, 1) != 0) bad("writing the temp file for a rename");
    else if (rename(path2, path) != 0) {
        printf("LXWRITE: FAILED -- rename(%s -> %s): errno %d\n", path2, path, errno);
        fails++;
    } else {
        long n = slurp(path, buf, sizeof buf);
        if (n != (long)strlen(body3) || memcmp(buf, body3, (size_t)n) != 0)
            bad("the renamed file does not have the new contents");
        else printf("LXWRITE: renamed a temp file over it and the contents followed\n");
        if (slurp(path2, buf, sizeof buf) >= 0) bad("the temp file still exists after rename");
    }

    /* 6. Leave the tree as found. A test that litters the source tree is a test
     *    that changes what the next one measures. */
    if (unlink(path) != 0) bad("removing the test file");
    else if (slurp(path, buf, sizeof buf) >= 0) bad("the file is still readable after unlink");
    else printf("LXWRITE: cleaned up\n");
    unlink(path2);

    printf(fails ? "LXWRITE: %d CHECK(S) FAILED\n" : "LXWRITE: ALL PASSED\n", fails);
    return fails ? 1 : 0;
}
