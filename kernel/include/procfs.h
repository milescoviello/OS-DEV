/* procfs.h — synthetic /proc and /dev filesystems.
 *
 * The VFS is name-based, so these need no per-process fd table: the vfs layer
 * routes paths under /proc and /dev here, and we generate their contents on the
 * fly from live kernel state (memory, uptime, CPU, process count) and the
 * classic character devices (null/zero/random/full). "Everything is a file." */
#pragma once
#include <stdint.h>
#include "vfs.h"

/* Does this absolute path live in the synthetic tree (/proc or /dev)? */
int  procfs_owns(const char *abs);
/* "/proc" or "/dev" themselves (the directories)? */
int  procfs_is_dir(const char *abs);
/* Does this synthetic node exist? *chardev is set for /dev char devices (M1965). */
int  procfs_exists(const char *abs, int *chardev);
/* Read a synthetic file. Returns bytes produced (>=0) or -1 if not ours. */
long procfs_read(const char *abs, void *buf, unsigned long max);
/* Write to a synthetic file (e.g. /dev/null discards). len/-1, or -2 if not ours. */
long procfs_write(const char *abs, const void *buf, unsigned long len);
/* List the entries of "/proc" or "/dev" into out[]; returns the count. */
int  procfs_list(const char *dir, vfs_dirent *out, int max);
