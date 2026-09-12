/*
 * ahci.c — AHCI/SATA disk driver: modern storage over a DMA HBA.
 *
 * Where kernel/ata.c drives the legacy IDE controller in PIO mode (the CPU
 * moves every word through an I/O port), a SATA disk hangs off an AHCI "host
 * bus adapter" (HBA) — a PCI device whose registers are memory-mapped (MMIO via
 * BAR5, the "ABAR") and which moves data by DMA. We never touch the disk's
 * bytes through a port: instead we hand the HBA, in RAM, a *command list* of
 * *command headers*; each header points at a *command table* that holds a SATA
 * "Register H2D FIS" (the actual READ/WRITE command + 48-bit LBA + sector count)
 * and a *PRDT* (physical-region descriptor table) naming the buffer to DMA into.
 * We set the slot's bit in PxCI, the HBA executes the command, DMAs the sectors,
 * and clears the bit. A spin-wait poll on PxCI tells us it's done — no IRQ.
 *
 * SAFE SCOPE: this is an *additional* block device. The OS still BOOTS from, and
 * runs FAT32/VFS on, the legacy ATA disk (kernel/ata.c). ahci_init() probes the
 * PCI bus for an AHCI HBA; if there's none (or no SATA disk on it) it is a clean
 * no-op, so a legacy-only machine boots unchanged. Once this is proven, the boot
 * volume could be migrated onto an AHCI disk by pointing fat32/vfs at ahci_read.
 *
 * All DMA structures come from pmm_alloc_frame(): the PMM only returns low
 * physical RAM, which the boot page tables identity-map (phys == virt), so the
 * frame's address is BOTH a CPU-usable pointer AND the physical address the HBA
 * needs — exactly how kernel/e1000.c sets up its descriptor rings. A 4 KiB frame
 * is naturally 4 KiB-aligned, which satisfies AHCI's alignment rules for the
 * command list (1 KiB), received-FIS area (256 B) and command table (128 B).
 */
#include "ahci.h"
#include "pci.h"
#include "pmm.h"
#include "vmm.h"
#include "string.h"
#include "console.h"

/* ---- HBA global (generic host control) registers, ABAR-relative ---------- */
#define HBA_CAP   0x00     /* host capabilities                                */
#define HBA_GHC   0x04     /* global host control                              */
#define HBA_IS    0x08     /* interrupt status (per-port bitmap)               */
#define HBA_PI    0x0C     /* ports implemented (bitmap)                       */
#define HBA_VS    0x10     /* version                                          */

#define GHC_AE    (1u << 31)   /* AHCI enable                                  */
#define GHC_HR    (1u << 0)    /* HBA reset                                    */

/* ---- per-port register block: ABAR + 0x100 + port*0x80 ------------------- */
#define PORT_BASE 0x100
#define PORT_STRIDE 0x80
#define PxCLB     0x00     /* command list base, low 32 (1 KiB aligned)       */
#define PxCLBU    0x04     /* command list base, high 32                       */
#define PxFB      0x08     /* received-FIS base, low 32 (256 B aligned)        */
#define PxFBU     0x0C     /* received-FIS base, high 32                       */
#define PxIS      0x10     /* interrupt status                                 */
#define PxIE      0x14     /* interrupt enable                                 */
#define PxCMD     0x18     /* command and status                              */
#define PxTFD     0x20     /* task file data (status/error of last cmd)        */
#define PxSIG     0x24     /* signature (identifies the attached device type)  */
#define PxSSTS    0x28     /* SATA status (DET/IPM — is a device present?)     */
#define PxSCTL    0x2C     /* SATA control                                     */
#define PxSERR    0x30     /* SATA error (write-1-to-clear)                    */
#define PxSACT    0x34     /* SATA active (for native command queuing)         */
#define PxCI      0x38     /* command issue (one bit per slot)                 */

#define PxCMD_ST  (1u << 0)    /* start (process the command list)             */
#define PxCMD_FRE (1u << 4)    /* FIS receive enable                           */
#define PxCMD_FR  (1u << 14)   /* FIS receive running (read-only status)       */
#define PxCMD_CR  (1u << 15)   /* command list running (read-only status)      */

#define PxTFD_ERR (1u << 0)    /* error bit in the task-file status            */
#define PxTFD_DRQ (1u << 3)    /* data transfer requested                      */
#define PxTFD_BSY (1u << 7)    /* interface busy                               */

#define PxIS_TFES (1u << 30)   /* task file error status                       */

/* PxSSTS.DET (device detection) and the SATA-disk signature in PxSIG. */
#define DET_PRESENT 0x3        /* device present + PHY communication           */
#define SIG_SATA    0x00000101 /* a SATA hard disk (vs ATAPI/SEMB/PM)          */

/* SATA FIS types + ATA commands we use. */
#define FIS_TYPE_REG_H2D 0x27
#define ATA_CMD_READ_DMA_EXT  0x25
#define ATA_CMD_WRITE_DMA_EXT 0x35
#define ATA_CMD_IDENTIFY      0xEC   /* IDENTIFY DEVICE — reports the disk's capacity */

/* A command header (one of 32 in the command list). Bitfields pack the DW0
 * flags: CFL = command-FIS length in DWORDs, W = write, PRDTL = #PRDT entries. */
struct hba_cmd_header {
    uint8_t  cfl : 5;          /* command FIS length, in 32-bit DWORDs         */
    uint8_t  a   : 1;          /* ATAPI                                        */
    uint8_t  w   : 1;          /* write (1) vs read (0), from the HBA's view   */
    uint8_t  p   : 1;          /* prefetchable                                 */
    uint8_t  r   : 1;          /* reset                                        */
    uint8_t  b   : 1;          /* BIST                                         */
    uint8_t  c   : 1;          /* clear busy on R_OK                           */
    uint8_t  rsv0 : 1;
    uint8_t  pmp : 4;          /* port-multiplier port                         */
    uint16_t prdtl;            /* number of PRDT entries                       */
    volatile uint32_t prdbc;   /* PRD byte count transferred (HBA writes this) */
    uint32_t ctba;             /* command table base, low 32 (128 B aligned)   */
    uint32_t ctbau;            /* command table base, high 32                  */
    uint32_t rsv1[4];
} __attribute__((packed));

/* One PRDT entry: a physical buffer region + its byte count (-1) to DMA. */
struct hba_prdt_entry {
    uint32_t dba;              /* data base address, low 32                    */
    uint32_t dbau;             /* data base address, high 32                   */
    uint32_t rsv0;
    uint32_t dbc_i;            /* bits 21..0 = byte count - 1; bit 31 = IRQ    */
} __attribute__((packed));

/* The command table a header points at: the command FIS, then the PRDT. We use
 * a single PRDT entry, which is all a contiguous DMA buffer needs. */
struct hba_cmd_table {
    uint8_t  cfis[64];         /* command FIS (we write a Register H2D here)   */
    uint8_t  acmd[16];         /* ATAPI command (unused)                       */
    uint8_t  rsv[48];
    struct hba_prdt_entry prdt[1];
} __attribute__((packed));

/* A Register Host-to-Device FIS — the SATA-level command packet. */
struct fis_reg_h2d {
    uint8_t  fis_type;         /* FIS_TYPE_REG_H2D (0x27)                      */
    uint8_t  pmp : 4;
    uint8_t  rsv0 : 3;
    uint8_t  c : 1;            /* 1 = this FIS is a command (not a control)    */
    uint8_t  command;          /* ATA command (READ/WRITE DMA EXT)             */
    uint8_t  featurel;
    uint8_t  lba0, lba1, lba2; /* LBA bits 0..23                               */
    uint8_t  device;           /* 0x40 = LBA mode                              */
    uint8_t  lba3, lba4, lba5; /* LBA bits 24..47 (48-bit addressing)          */
    uint8_t  featureh;
    uint8_t  countl, counth;   /* sector count                                 */
    uint8_t  icc;
    uint8_t  control;
    uint8_t  rsv1[4];
} __attribute__((packed));

#define AHCI_MAX_PORTS 32

/* Per-disk state: which port it is, plus that port's DMA structures. The
 * command list / FIS area / command table each get their own physical frame
 * (so each is naturally aligned, and we waste a little RAM for clarity). */
struct ahci_disk {
    volatile uint8_t      *port;       /* this port's MMIO register block      */
    struct hba_cmd_header *cmd_list;   /* 32 command headers (1 KiB used)      */
    void                  *fis;        /* received-FIS area (256 B used)       */
    struct hba_cmd_table  *cmd_table;  /* one command table (we reuse slot 0)  */
    uint64_t               sectors;    /* capacity from IDENTIFY (0 = unknown) */
};

static uint64_t ahci_identify(int disk);   /* fwd: IDENTIFY DEVICE -> sector count */

static volatile uint8_t   *abar;       /* HBA register block (mapped BAR5)     */
static struct ahci_disk    disks[AHCI_MAX_PORTS];
static int                 ndisks;

/* ---- small MMIO + helpers ------------------------------------------------ */
static uint32_t hba_read(uint32_t off)             { return *(volatile uint32_t *)(abar + off); }
static void     hba_write(uint32_t off, uint32_t v){ *(volatile uint32_t *)(abar + off) = v; }
static uint32_t port_read(volatile uint8_t *p, uint32_t off)             { return *(volatile uint32_t *)(p + off); }
static void     port_write(volatile uint8_t *p, uint32_t off, uint32_t v){ *(volatile uint32_t *)(p + off) = v; }

/* Physical address of a kernel pointer, for handing buffers to the HBA's DMA
 * engine. DMA structures and the kernel buffers we read into live in the low
 * 1 GiB identity map (phys == virt), but translating is the correct, general
 * way to get the physical address rather than assuming the identity. */
static uint64_t phys_of(const void *p) {
    uint64_t t = vmm_translate((uint64_t)(uintptr_t)p);
    return t ? t : hhdm_phys(p);   /* no translation: it is an HHDM pointer, so subtract the base (M1970) */
}

/* Stop the port's command engine: clear ST + FRE, then wait for the HBA to
 * report both engines idle (CR + FR clear) so it's safe to repoint CLB/FB. */
static void port_stop(volatile uint8_t *p) {
    uint32_t cmd = port_read(p, PxCMD);
    cmd &= ~PxCMD_ST;
    cmd &= ~PxCMD_FRE;
    port_write(p, PxCMD, cmd);
    for (int i = 0; i < 1000000; i++)
        if (!(port_read(p, PxCMD) & (PxCMD_CR | PxCMD_FR)))
            break;
}

/* Start the port's command engine: FRE first (so received FISes have a home),
 * then ST. Wait for CR to confirm the command list is running. */
static void port_start(volatile uint8_t *p) {
    for (int i = 0; i < 1000000; i++)
        if (!(port_read(p, PxCMD) & PxCMD_CR))
            break;
    uint32_t cmd = port_read(p, PxCMD);
    cmd |= PxCMD_FRE;
    cmd |= PxCMD_ST;
    port_write(p, PxCMD, cmd);
}

/* Bring one implemented, SATA-disk-present port up: stop it, allocate + point
 * its command list and received-FIS area at fresh zeroed frames, clear errors,
 * and start it. Returns 0 on success. */
static int port_init(int pi_index) {
    volatile uint8_t *p = abar + PORT_BASE + (uint32_t)pi_index * PORT_STRIDE;

    /* Only bring up a port with a SATA hard disk actually attached. */
    uint32_t ssts = port_read(p, PxSSTS);
    if ((ssts & 0x0F) != DET_PRESENT)
        return -1;
    if (port_read(p, PxSIG) != SIG_SATA)
        return -1;

    port_stop(p);

    /* Each structure gets its own physically-contiguous frame from the PMM. */
    uint64_t clb = pmm_alloc_frame();
    uint64_t fb  = pmm_alloc_frame();
    uint64_t ct  = pmm_alloc_frame();
    if (!clb || !fb || !ct) {
        if (clb) pmm_free_frame(clb);
        if (fb)  pmm_free_frame(fb);
        if (ct)  pmm_free_frame(ct);
        return -1;
    }
    memset(hhdm(clb), 0, PAGE_SIZE);
    memset(hhdm(fb),  0, PAGE_SIZE);
    memset(hhdm(ct),  0, PAGE_SIZE);

    port_write(p, PxCLB,  (uint32_t)clb);
    port_write(p, PxCLBU, (uint32_t)(clb >> 32));
    port_write(p, PxFB,   (uint32_t)fb);
    port_write(p, PxFBU,  (uint32_t)(fb >> 32));

    port_write(p, PxSERR, 0xFFFFFFFF);   /* write-1-to-clear any latched errors */
    port_write(p, PxIS,   0xFFFFFFFF);   /* clear pending interrupt status       */

    port_start(p);

    int idx = ndisks;
    disks[idx].port      = p;
    disks[idx].cmd_list  = (struct hba_cmd_header *)hhdm(clb);
    disks[idx].fis       = hhdm(fb);
    disks[idx].cmd_table = (struct hba_cmd_table *)hhdm(ct);
    disks[idx].sectors   = 0;
    ndisks++;
    disks[idx].sectors = ahci_identify(idx);   /* now the port runs: ask it its capacity */
    return 0;
}

int ahci_init(void) {
    ndisks = 0;

    /* Locate an AHCI HBA by PCI class (0x01 mass-storage, 0x06 SATA, 0x01 AHCI).
     * QEMU's `-device ahci` is an Intel ICH9 (8086:2922) at this class triple. */
    pci_device_t dev = pci_find_class(0x01, 0x06, 0x01);
    if (!dev.valid)
        return -1;

    /* Enable PCI memory-space decode + bus mastering so the HBA can DMA. */
    pci_enable_bus_master(&dev);

    /* ABAR is BAR5. Map it as cache-disabled MMIO (it sits in the PCI hole,
     * above the boot identity map, so it must be mapped before we touch it).
     * The register window is 0x100 + 32*0x80 = 0x1100 bytes; two pages cover
     * it with room to spare. */
    uint64_t bar5 = pci_bar(&dev, 5);
    for (uint64_t off = 0; off < 0x2000; off += PAGE_SIZE)
        vmm_map(bar5 + off, bar5 + off, PTE_WRITABLE | PTE_PCD);
    abar = (volatile uint8_t *)(uintptr_t)bar5;

    /* Take ownership: put the HBA in AHCI mode. */
    hba_write(HBA_GHC, hba_read(HBA_GHC) | GHC_AE);

    /* Walk the implemented-ports bitmap; bring up each port that has a SATA
     * disk. CAP[4:0]+1 caps the port count, but PI is authoritative. */
    uint32_t pi = hba_read(HBA_PI);
    for (int i = 0; i < AHCI_MAX_PORTS; i++)
        if (pi & (1u << i))
            port_init(i);

    return ndisks;
}

int ahci_disk_count(void) { return ndisks; }

uint64_t ahci_disk_sectors(int disk) {
    return (disk >= 0 && disk < ndisks) ? disks[disk].sectors : 0;
}

/* Find a free command slot: a slot is busy if its bit is set in either PxCI
 * (command issue) or PxSACT (NCQ active). We only ever use slot 0, but checking
 * keeps this correct if that ever changes. Returns -1 if none free. */
static int find_cmd_slot(volatile uint8_t *p) {
    uint32_t busy = port_read(p, PxCI) | port_read(p, PxSACT);
    for (int i = 0; i < 32; i++)
        if (!(busy & (1u << i)))
            return i;
    return -1;
}

/* The shared core of read and write: build the command header + table + FIS +
 * PRDT for one DMA transfer, issue it on a free slot, and poll to completion.
 * `write` picks WRITE DMA EXT and sets the header's W bit; the buffer's physical
 * address is taken from `buf`. Returns 0 on success, -1 on bad arg / error. */
static int ahci_xfer(int disk, uint64_t lba, uint32_t count, void *buf, int write) {
    if (disk < 0 || disk >= ndisks || count == 0 || !buf)
        return -1;
    /* One PRDT entry carries up to 4 MiB (its byte count is 22 bits, value-1),
     * i.e. 8192 sectors. Keep the whole transfer in that single entry. */
    if (count > 8192)
        return -1;

    volatile uint8_t *p = disks[disk].port;

    /* Wait for the port to be idle (not busy / no data-request pending). */
    for (int i = 0; i < 1000000; i++)
        if (!(port_read(p, PxTFD) & (PxTFD_BSY | PxTFD_DRQ)))
            break;

    int slot = find_cmd_slot(p);
    if (slot < 0)
        return -1;

    struct hba_cmd_header *hdr = &disks[disk].cmd_list[slot];
    struct hba_cmd_table  *tbl = disks[disk].cmd_table;
    uint64_t tbl_phys = phys_of(tbl);

    memset(hdr, 0, sizeof(*hdr));
    hdr->cfl   = sizeof(struct fis_reg_h2d) / sizeof(uint32_t);  /* = 5 DWORDs */
    hdr->w     = write ? 1 : 0;
    hdr->prdtl = 1;
    hdr->ctba  = (uint32_t)tbl_phys;
    hdr->ctbau = (uint32_t)(tbl_phys >> 32);

    memset(tbl, 0, sizeof(*tbl));
    uint64_t buf_phys = phys_of(buf);
    tbl->prdt[0].dba   = (uint32_t)buf_phys;
    tbl->prdt[0].dbau  = (uint32_t)(buf_phys >> 32);
    tbl->prdt[0].dbc_i = ((count * AHCI_SECTOR_SIZE) - 1) | (1u << 31);  /* byte count-1 + IOC */

    struct fis_reg_h2d *fis = (struct fis_reg_h2d *)tbl->cfis;
    fis->fis_type = FIS_TYPE_REG_H2D;
    fis->c        = 1;                       /* this is a command FIS */
    fis->command  = write ? ATA_CMD_WRITE_DMA_EXT : ATA_CMD_READ_DMA_EXT;
    fis->device   = 0x40;                    /* LBA mode */
    fis->lba0 = (uint8_t)(lba);
    fis->lba1 = (uint8_t)(lba >> 8);
    fis->lba2 = (uint8_t)(lba >> 16);
    fis->lba3 = (uint8_t)(lba >> 24);
    fis->lba4 = (uint8_t)(lba >> 32);
    fis->lba5 = (uint8_t)(lba >> 40);
    fis->countl = (uint8_t)(count & 0xFF);
    fis->counth = (uint8_t)((count >> 8) & 0xFF);

    port_write(p, PxIS, 0xFFFFFFFF);         /* clear stale status before issue */
    port_write(p, PxCI, 1u << slot);         /* issue: the HBA runs the command */

    /* Poll until the HBA clears our slot bit (command complete), watching for a
     * task-file error along the way. A spin-wait is fine — no IRQ needed. */
    for (int i = 0; i < 5000000; i++) {
        if (!(port_read(p, PxCI) & (1u << slot)))
            break;
        if (port_read(p, PxIS) & PxIS_TFES)
            return -1;                       /* device flagged an error */
        if (i == 4999999)
            return -1;                       /* timeout */
    }

    /* Final error check: task-file ERR bit, or an interrupt-status error. */
    if (port_read(p, PxTFD) & PxTFD_ERR)
        return -1;
    if (port_read(p, PxIS) & PxIS_TFES)
        return -1;
    return 0;
}

int ahci_read(int disk, uint64_t lba, uint32_t count, void *buf) {
    return ahci_xfer(disk, lba, count, buf, 0);
}

int ahci_write(int disk, uint64_t lba, uint32_t count, const void *buf) {
    return ahci_xfer(disk, lba, count, (void *)buf, 1);
}

/* IDENTIFY DEVICE target: a page-aligned 512-byte DMA buffer in identity-mapped
 * low RAM (its physical address is its own). Init is sequential (one port at a
 * time), so a single shared buffer is fine. */
static uint16_t ahci_id_buf[256] __attribute__((aligned(PAGE_SIZE)));

/* Issue IDENTIFY DEVICE (ATA 0xEC) to `disk` and return its total 512-byte
 * sector count — the LBA48 64-bit field (IDENTIFY words 100..103) when 48-bit
 * addressing is supported (word 83 bit 10), else the LBA28 32-bit field (words
 * 60..61); 0 if IDENTIFY errors. Same command mechanism as ahci_xfer, but a
 * data-in command with no LBA/sector-count (it returns one 512-byte block). */
static uint64_t ahci_identify(int disk) {
    if (disk < 0 || disk >= ndisks)
        return 0;
    volatile uint8_t *p = disks[disk].port;

    for (int i = 0; i < 1000000; i++)
        if (!(port_read(p, PxTFD) & (PxTFD_BSY | PxTFD_DRQ)))
            break;

    int slot = find_cmd_slot(p);
    if (slot < 0)
        return 0;

    struct hba_cmd_header *hdr = &disks[disk].cmd_list[slot];
    struct hba_cmd_table  *tbl = disks[disk].cmd_table;
    uint64_t tbl_phys = phys_of(tbl);

    memset(hdr, 0, sizeof(*hdr));
    hdr->cfl   = sizeof(struct fis_reg_h2d) / sizeof(uint32_t);
    hdr->w     = 0;                          /* data-in (device -> host) */
    hdr->prdtl = 1;
    hdr->ctba  = (uint32_t)tbl_phys;
    hdr->ctbau = (uint32_t)(tbl_phys >> 32);

    memset(tbl, 0, sizeof(*tbl));
    memset(ahci_id_buf, 0, sizeof(ahci_id_buf));
    uint64_t buf_phys = phys_of(ahci_id_buf);
    tbl->prdt[0].dba   = (uint32_t)buf_phys;
    tbl->prdt[0].dbau  = (uint32_t)(buf_phys >> 32);
    tbl->prdt[0].dbc_i = (512 - 1) | (1u << 31);   /* one 512-byte block, IOC */

    struct fis_reg_h2d *fis = (struct fis_reg_h2d *)tbl->cfis;
    fis->fis_type = FIS_TYPE_REG_H2D;
    fis->c        = 1;
    fis->command  = ATA_CMD_IDENTIFY;        /* device / LBA / count all 0 for IDENTIFY */

    port_write(p, PxIS, 0xFFFFFFFF);
    port_write(p, PxCI, 1u << slot);
    for (int i = 0; i < 5000000; i++) {
        if (!(port_read(p, PxCI) & (1u << slot)))
            break;
        if (port_read(p, PxIS) & PxIS_TFES)
            return 0;
        if (i == 4999999)
            return 0;
    }
    if (port_read(p, PxTFD) & PxTFD_ERR)
        return 0;

    const uint16_t *id = ahci_id_buf;
    uint64_t sectors = 0;
    if (id[83] & (1u << 10))
        sectors = (uint64_t)id[100] | ((uint64_t)id[101] << 16) |
                  ((uint64_t)id[102] << 32) | ((uint64_t)id[103] << 48);
    if (sectors == 0)
        sectors = (uint32_t)id[60] | ((uint32_t)id[61] << 16);   /* LBA28 fallback */
    return sectors;
}

/* ---- boot-time verification --------------------------------------------- */

/* A static, page-frame-sized DMA buffer for the self-test, in the kernel's BSS
 * (identity-mapped low RAM, so its physical address is its own address). */
static uint8_t selftest_buf[AHCI_SECTOR_SIZE * 4] __attribute__((aligned(PAGE_SIZE)));

/* Read a few sectors off the first AHCI disk and log the first bytes + a simple
 * additive checksum, so the read can be matched against known on-disk content.
 * This is the verification hook called from boot; a no-op if no AHCI disk. */
void ahci_selftest(void) {
    if (ndisks <= 0) {
        kprintf("[ahci] no AHCI SATA disk found (none attached; legacy ATA boot intact).\n\n");
        return;
    }

    kprintf("[ ok ] AHCI HBA up: %d SATA disk(s) via DMA (boot stays on legacy ATA).\n",
            ndisks);
    for (int d = 0; d < ndisks; d++)
        kprintf("[ ok ] ahci%d: %lu sectors (%lu MiB) via IDENTIFY DEVICE.\n",
                d, disks[d].sectors, disks[d].sectors / 2048);

    for (uint64_t lba = 0; lba < 3; lba++) {
        if (ahci_read(0, lba, 1, selftest_buf) != 0) {
            kprintf("[ahci] sector %lu: READ FAILED\n", lba);
            continue;
        }
        /* Additive checksum over the whole sector + the first 16 bytes shown as
         * both hex and (printable) ASCII, so a known pattern is recognizable. */
        uint32_t sum = 0;
        for (int i = 0; i < AHCI_SECTOR_SIZE; i++)
            sum += selftest_buf[i];
        kprintf("[ahci] sector %lu sum=%08x first16=", lba, sum);
        for (int i = 0; i < 16; i++)
            kprintf("%02x ", selftest_buf[i]);
        kprintf(" |");
        for (int i = 0; i < 16; i++) {
            uint8_t c = selftest_buf[i];
            kprintf("%c", (c >= 0x20 && c < 0x7F) ? (char)c : '.');
        }
        kprintf("|\n");
    }
    kprintf("[ ok ] AHCI read self-test complete (bytes above are the real disk content).\n\n");
}
