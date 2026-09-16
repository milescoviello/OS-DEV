/* ata.h — read/write sectors from the legacy ATA (IDE) disks (PIO mode). */
#pragma once
#include <stdint.h>

#define SECTOR_SIZE 512

/* The four legacy ATA drives, in index order:
 *   0 = primary master, 1 = primary slave,
 *   2 = secondary master, 3 = secondary slave. */
#define ATA_MAX_DRIVES 4

/* What an IDENTIFY sweep learns about one drive. */
struct ata_drive_info {
    int      present;        /* 1 if a usable PIO ATA disk answered IDENTIFY */
    int      drive;          /* drive index 0..3 */
    uint64_t sectors;        /* reported LBA28/LBA48 sector count */
    int      lba48;          /* 1 if the drive advertised 48-bit addressing */
    char     model[41];      /* model string (trimmed), for logging */
};

/* --- primary-master API (drive 0): unchanged, every existing caller uses it -- */

/* Read `count` 512-byte sectors starting at LBA `lba` into `buf` (drive 0).
 * Returns 0 on success, -1 on error/timeout. (count==0 means 256, the LBA28
 * convention the original driver used.) */
int ata_read(uint32_t lba, uint8_t count, void *buf);

/* Write `count` 512-byte sectors starting at LBA `lba` from `buf` (drive 0). */
int ata_write(uint32_t lba, uint8_t count, const void *buf);

/* --- multi-drive API ------------------------------------------------------- */

/* Read/write `count` sectors at `lba` on drive `drive` (0..3). `count` is a
 * 32-bit count here (chunked internally to the 8-bit LBA28 sector field), so a
 * caller may request more than 256 sectors. Returns 0 on success, -1 on error. */
int ata_read_drive(int drive, uint32_t lba, uint32_t count, void *buf);
int ata_write_drive(int drive, uint32_t lba, uint32_t count, const void *buf);
/* Single-sector read cache (M1855): faster repeated FS reads, coherent w/ writes. */
void ata_cache_flush(void);
void ata_cache_selftest(void);   /* boot self-test: fill+hit+write-invalidate coherence (save/restore) */

/* Probe all four legacy drives with IDENTIFY (finite timeouts; an absent drive
 * is detected via the status register, never hangs). Records which are present
 * and their sector counts. Returns the number of present drives. Idempotent. */
int ata_identify_all(void);

/* Info for drive `drive` (runs ata_identify_all() lazily on first use). NULL for
 * an out-of-range index; check ->present for whether a disk is actually there. */
const struct ata_drive_info *ata_drive(int drive);

/* Convenience: reported sector count of drive `drive`, or 0 if absent. */
uint64_t ata_drive_sectors(int drive);

/* --- bus-master IDE DMA (PIIX3 "BMIDE") ------------------------------------ */

/*
 * An ADDITIVE DMA path alongside the PIO ata_read()/ata_write() above. The PIO
 * functions stay the DEFAULT every existing caller (fat32/vfs/boot) uses; these
 * DMA functions are a separate capability, proven byte-identical to PIO by
 * ata_dma_selftest(). They use the PIIX3 IDE controller's bus-master interface
 * (PCI 0x8086:0x7010, BAR4) + a PRD table to move sectors by DMA through an
 * internal page-aligned bounce buffer (so `buf` needs no alignment).
 *
 * If the PIIX3 BMIDE controller/BAR isn't present, every call is a clean no-op
 * that returns -1 — the boot path (PIO) is entirely unaffected.
 */

/* Read `count` 512-byte sectors at `lba` on drive `drive` (0..3) into `buf` via
 * bus-master DMA. `count` must be in 1..ata_dma_max_sectors(); `buf` must hold
 * count*512 bytes (no alignment constraint — DMA goes through an internal bounce
 * buffer). Returns 0 on success, -1 on bad-arg / absent controller / absent
 * drive / device error / timeout. */
int ata_read_dma(int drive, uint32_t lba, uint32_t count, void *buf);

/* Write `count` sectors from `buf` to `lba` on drive `drive` via bus-master DMA.
 * Same argument rules as ata_read_dma. Returns 0 on success, -1 otherwise. */
int ata_write_dma(int drive, uint32_t lba, uint32_t count, const void *buf);

/* 1 if the PIIX3 bus-master IDE controller is present + set up (so the DMA path
 * is usable), else 0. Idempotent (probes PCI once). */
int ata_dma_available(void);

/* Maximum sectors a single ata_read_dma/ata_write_dma call can move (the
 * internal bounce-buffer cap). */
uint32_t ata_dma_max_sectors(void);

/* Boot-time verification: if the BMIDE controller is present, DMA-read a few low
 * sectors of the boot disk (drive 0) and compare each byte-for-byte against a PIO
 * read of the same sectors, logging "IDE DMA: sector N DMA==PIO OK" per sector
 * (this is the proof the DMA path returns identical data to the trusted PIO
 * path); then a DMA write round-trip on a scratch sector. No-op (logs "DMA
 * unavailable") if no BMIDE controller is attached. */
void ata_dma_selftest(void);

/* LBA48 self-test (M1721): if a non-boot ATA disk larger than the LBA28 128 GiB
 * ceiling is present, write+read-back a sector past the 2^28 boundary to prove
 * the LBA48 path. A clean no-op with no such disk (the default). */
void ata_lba48_selftest(void);

/* WHAT THE DISK ACTUALLY COST (M2091): commands, sectors, cache hits, and the
 * cycles spent inside the driver -- transfers and hits counted apart, because
 * a cache that is working shows up as the second number growing while the
 * first does not. Measured before any block-cache work, so the claim that the
 * disk is or is not the bottleneck is a reading rather than an opinion. */
void ata_io_stats(uint64_t *cmds, uint64_t *sectors, uint64_t *hits,
                  uint64_t *cyc_xfer, uint64_t *cyc_hit);
