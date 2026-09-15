/* lxlongname.c -- A DIRECTORY LISTING MUST GIVE BACK THE NAME THAT IS THERE (M2062).
 *
 * Every listing in the kernel came through one struct whose name field was 32
 * bytes, so every filename was truncated at 31 characters -- and a truncated
 * name is not a cosmetic problem, it is a name that does not exist. `find`
 * inside OS-DEV said it plainly:
 *
 *   find: '/root/.claude/backups/.claude.json.backup.17894368240':
 *         No such file or directory
 *   find: '/root/.claude/sessions/101.e6a4c69b6e4f03ca50222125240':
 *         No such file or directory
 *
 * Both exactly 31 characters; both real files with longer names. A program
 * that writes a file, lists the directory and then acts on what it read gets
 * ENOENT for its own data. Claude Code names its session keys with a 64-hex
 * hash and its config backups with a millisecond timestamp, so nearly
 * everything it owns was invisible to it.
 *
 * This writes names at the lengths that matter, lists the directory, and
 * demands the bytes back exactly -- then opens each one BY THE NAME THE
 * LISTING GAVE, which is the operation that actually failed. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#define DIR_PATH "/lnt"

static int mk(const char *name) {
    char p[512];
    snprintf(p, sizeof p, "%s/%s", DIR_PATH, name);
    int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { printf("LXLONG: FAIL create %s (%s)\n", name, strerror(errno)); return -1; }
    write(fd, "x", 1);
    close(fd);
    return 0;
}

int main(void) {
    mkdir(DIR_PATH, 0755);
    /* 31 is the old cap, so it always passed. 32 is the first length that
     * could not survive. 40 and 72 are the shapes real programs use: a
     * millisecond-stamped backup and a 64-hex-character session key.
     *
     * 240 rather than ext2's full 255 because a SECOND limit binds after this
     * one: VFS_PATH_MAX is 256 and the kernel prefixes "/disk2", so the whole
     * path -- not the name -- runs out at 249 characters. That truncation now
     * announces itself in the kernel log instead of silently naming another
     * file, and raising the path budget is its own milestone (seventy stack
     * buffers are declared [VFS_PATH_MAX]). "/lnt/" + 240 + "/disk2" = 251. */
    static const int lens[] = { 31, 32, 40, 72, 120, 200, 240 };
    char want[7][300];
    int nw = (int)(sizeof lens / sizeof lens[0]);
    for (int i = 0; i < nw; i++) {
        int L = lens[i];
        for (int k = 0; k < L; k++) want[i][k] = (char)('a' + ((i * 7 + k) % 26));
        want[i][L] = 0;
        if (mk(want[i]) != 0) return 1;
    }

    DIR *d = opendir(DIR_PATH);
    if (!d) { printf("LXLONG: FAIL opendir (%s)\n", strerror(errno)); return 1; }
    int seen[7] = {0};
    int nent = 0, truncated = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        nent++;
        int matched = -1;
        for (int i = 0; i < nw; i++) if (!strcmp(e->d_name, want[i])) { matched = i; break; }
        if (matched < 0) {
            /* a name we did not write: almost certainly a PREFIX of one we did */
            for (int i = 0; i < nw; i++) {
                size_t n = strlen(e->d_name);
                if (n < strlen(want[i]) && !strncmp(e->d_name, want[i], n)) {
                    printf("LXLONG: FAIL the listing TRUNCATED a %zu-char name to %zu: \"%s\"\n",
                           strlen(want[i]), n, e->d_name);
                    truncated = 1;
                    break;
                }
            }
            continue;
        }
        seen[matched] = 1;
        /* THE OPERATION THAT ACTUALLY FAILED: open it by the listed name. */
        char p[512];
        snprintf(p, sizeof p, "%s/%s", DIR_PATH, e->d_name);
        int fd = open(p, O_RDONLY);
        if (fd < 0) {
            printf("LXLONG: FAIL a listed name cannot be opened: %zu chars (%s)\n",
                   strlen(e->d_name), strerror(errno));
            truncated = 1;
        } else close(fd);
    }
    closedir(d);

    if (truncated) return 2;
    for (int i = 0; i < nw; i++)
        if (!seen[i]) { printf("LXLONG: FAIL a %d-char name never came back from the listing\n", lens[i]); return 3; }
    printf("LXLONG: %d names round-tripped exactly (31..240 chars), every one openable\n", nw);
    printf("LXLONG: ALL PASSED\n");
    return 0;
}
