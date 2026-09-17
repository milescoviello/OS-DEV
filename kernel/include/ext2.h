/*
 * ext2.h — a read-only ext2 filesystem driver (Linux interop).
 *
 * Device-agnostic, mirroring the FAT32 volume API (partition.h): each call
 * takes a blk_read_fn + ctx + the volume's absolute start LBA. Parses the
 * superblock, block-group descriptors, inodes (direct + single/double-indirect
 * blocks) and linked directory entries, so a real mke2fs image can be mounted
 * and read in-guest. Read-only; bounded; never writes.
 */
#pragma once
#include <stdint.h>
#include "partition.h"   /* blk_read_fn, fatvol_dirent (reused for listings) */

void ext2_set_clock(uint32_t (*fn)(void));   /* wire the inode-timestamp clock (kernel: rtc_unix) (M1175) */
int  ext2_probe(blk_read_fn read, void *ctx, uint64_t start_lba);   /* 0 if a valid ext2 volume, else -1 */
int  ext2_list_path(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path,
                    fatvol_dirent *out, int max);                   /* list a dir; entries written, or -1 */
long ext2_pread(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path,
                void *buf, unsigned long max, unsigned long offset);   /* positioned read; bytes/-1 (M1196) */
long ext2_read_path(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path,
                    void *buf, unsigned long max);                  /* read a file; bytes, or -1 */
int  ext2_isdir_path(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path);  /* 1 dir / 0 file / -1 absent */
int  ext2_stat_path(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path, uint32_t *out_size, int *out_isdir, uint32_t *out_ino, uint32_t *out_mtime, uint32_t *out_nlink, uint32_t *out_mode);  /* 0/-1; out_ino = the real inode number (M1955); mtime/nlink/mode (M1999) */
/* Create a NEW regular file `path` with `buf`/`len` (block + inode allocation,
 * directory insertion). Fails (-1) if the file already exists, the parent dir is
 * missing/full, or there's no space. Direct + single-indirect extents only. M1132. */
long ext2_write_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                     const char *path, const void *buf, unsigned long len);   /* create OR overwrite (M1132/M1135) */
/* STREAMING write: place len bytes at byte offset `off`, creating the file if
 * absent and extending it as needed. Unlike ext2_write_path this never needs
 * the whole file in memory — only the touched blocks are read/modified/written,
 * so an arbitrarily large file can be built from a small buffer. Writing past
 * EOF leaves a real sparse hole (unmapped blocks read as zeroes). Reaches
 * double-indirect = 4 GiB at a 4 KiB block size. Bytes written, or -1. M1934. */
long ext2_pwrite_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                      const char *path, uint64_t off, const void *buf, unsigned long len);
long ext2_unlink_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                      const char *path);                                      /* delete a regular file; 0/-1 (M1135) */
long ext2_mkdir_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                     const char *path);                                       /* create a directory; 0/-1 (M1137) */
long ext2_symlink_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                       const char *path, const char *target);                 /* create a fast symlink; 0/-1 (M1146) */
long ext2_readlink_path(blk_read_fn read, void *ctx, uint64_t start_lba,
                        const char *path, void *buf, unsigned long max);      /* read a symlink's target, not followed; bytes/-1 (M1594) */
long ext2_link_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                    const char *oldpath, const char *newpath);                 /* hard link: 2nd name -> same inode; 0/-1 (M1207) */
long ext2_rename_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                      const char *oldpath, const char *newpath);               /* rename/move (incl. dirs); 0/-1 (M1213) */
long ext2_rename2_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                       const char *oldpath, const char *newpath, int flags);   /* renameat2: NOREPLACE/EXCHANGE; 0/-1 (M1232) */
long ext2_truncate_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                        const char *path, uint64_t newlen);                    /* resize a regular file; 0/-1 (M1228) */
long ext2_seek_data_hole(blk_read_fn read, void *ctx, uint64_t start_lba,
                         const char *path, long off, int find_hole);          /* SEEK_HOLE/DATA: next hole/data >= off; -1 ENXIO (M1229) */
long ext2_utimes_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                      const char *path, long atime, long mtime);             /* set i_atime/i_mtime (neg = leave); 0/-1 (M1230) */
long ext2_chmod_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                     const char *path, uint32_t mode);                       /* set i_mode perm bits (keep type); 0/-1 (M1241) */
long ext2_chown_path(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                     const char *path, long uid, long gid);                  /* set i_uid/i_gid (neg = leave); 0/-1 (M1243) */
/* ext2_extent_t lives in partition.h (the base block-layer header). (M1152) */
int  ext2_fiemap(blk_read_fn read, void *ctx, uint64_t start_lba, const char *path,
                 ext2_extent_t *out, int max);                                /* file's physical extent map; extent count, or -1 (M1152) */
long ext2_punch_hole(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                     const char *path, uint64_t offset, uint64_t len);        /* fallocate PUNCH_HOLE; blocks punched, or -1 (M1153) */
long ext2_setxattr(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                   const char *path, const char *name, const void *value, unsigned long vlen);  /* set user.* xattr; vlen or -1 (M1182) */
long ext2_getxattr(blk_read_fn read, void *ctx, uint64_t start_lba,
                   const char *path, const char *name, void *out, unsigned long max);           /* get user.* xattr; full size or -1 (M1182) */
long ext2_listxattr(blk_read_fn read, void *ctx, uint64_t start_lba,
                    const char *path, char *out, unsigned long max);                            /* NUL-sep names; total or -1 (M1182) */
long ext2_removexattr(blk_read_fn read, blk_write_fn write, void *ctx, uint64_t start_lba,
                      const char *path, const char *name);                                      /* remove a user.* xattr; 0 or -1 (M1182) */
/* A PATH CACHE, POSITIVE AND NEGATIVE (M2103). Every resolution used to walk
 * from the volume root with no cache anywhere; SQLite probes for a journal and
 * a WAL before every transaction and neither exists, so the NEGATIVE half
 * carries most of the win. Flushed wholesale by every write in this file. */
void ext2_path_cache_flush(void);
void ext2_path_cache_stats(unsigned long *hits, unsigned long *misses,
                           unsigned long *neg, unsigned long *flushes);
extern int g_e2_path_cache;   /* 0 = walk every path from the root, as before M2103 */
extern int g_e2_read_runs;    /* 0 = one block per request, as before M2100 */
