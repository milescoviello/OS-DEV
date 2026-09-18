/*
 * bcache.h — one unified block cache for the whole kernel (M1869).
 *
 * Before this, two separate 512-byte block caches existed: ata.c's ACACHE (the
 * boot disk's read cache, keyed by ATA drive) and blockdev.c's LRU buffer cache
 * (keyed by blockdev device index). They duplicated the same logic. This is the
 * single shared pool both now use — one LRU, one set of hit/miss stats
 * (/proc/bcache), one implementation — with each caller passing an `owner` id so
 * the ATA and blockdev key namespaces don't collide.
 *
 * The two owner namespaces still key the SAME physical sector separately when an
 * ATA disk is reached both directly (fat32.c) and via the blockdev layer, and
 * their invalidations are independent — so to avoid double-caching an ATA sector
 * AND leaving one copy stale on a write, blockdev.c does NOT cache ATA-backed
 * devices under the BLK owner at all; it routes them through ata_read_drive/
 * ata_write_drive, which cache + invalidate coherently under the ATA owner
 * (M1885). Non-ATA devices (nvme, virtio-blk, ahci, usb) use the BLK owner.
 *
 * Write-through (a write updates the cached copy AND the disk), so the cache
 * never holds data the disk doesn't — a crash can't lose a cached write. It is a
 * pure LRU read cache + coherence point; correctness never depends on it (every
 * lookup copies into the CALLER's buffer, so an eviction can't dangle).
 */
#ifndef BCACHE_H
#define BCACHE_H
#include <stdint.h>

#define BCACHE_SECSZ 512

/* Owner namespaces so ATA drives and blockdev devices don't alias each other. */
#define BCACHE_OWNER_ATA(drive) ((uint32_t)(drive))          /* 0..15  : ATA drives */
#define BCACHE_OWNER_BLK(dev)   ((uint32_t)(16 + (dev)))     /* 16..   : blockdev devices */

/* SIZE THE POOL FROM PHYSICAL MEMORY (M2154). Until this runs the cache is the
 * old static 128 entries, so the very first boot sector is still cached; after
 * it, up to 32 MiB. Idempotent-by-refusal: it only ever grows. */
void bcache_init(void);

/* Read one 512-byte block from the cache: 1 = hit (copied into buf), 0 = miss. */
int  bcache_lookup(uint32_t owner, uint64_t lba, void *buf);
/* Install / refresh a block in the cache (after a disk read, or a write-through). */
void bcache_install(uint32_t owner, uint64_t lba, const void *buf);
/* Drop one block / a [lba, lba+count) range / all of one owner's / everything. */
void bcache_inval(uint32_t owner, uint64_t lba);
void bcache_inval_range(uint32_t owner, uint64_t lba, uint32_t count);
void bcache_inval_owner(uint32_t owner);
void bcache_flush(void);
/* /proc/bcache: entries, hits, misses. Returns bytes written. */
int  bcache_stats(char *out, int max);
/* Walks that found a corrupt bucket chain and answered MISS rather than spin.
 * Zero on a healthy cache; non-zero means the table's own links are wrong.
 * (M2176) */
unsigned long bcache_chain_breaks(void);
/* Numeric hit/miss counters (for self-tests). */
void bcache_counts(uint64_t *hits, uint64_t *miss);

#endif
