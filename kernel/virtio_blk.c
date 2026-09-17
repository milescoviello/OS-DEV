/*
 * virtio_blk.c — virtio-blk driver: the paravirtual "fast VM disk" over PCI.
 *
 * A virtio device is not emulated register-by-register like the IDE/AHCI
 * controllers; the hypervisor and guest agree on a shared-memory protocol and
 * exchange requests through a *virtqueue* — a ring of descriptors in RAM that we
 * fill and the device consumes. This is the disk QEMU/KVM offer natively, and
 * it's both the simplest and the fastest.
 *
 * We speak the LEGACY transport (virtio spec 0.9.5) over PCI, which QEMU exposes
 * with `-device virtio-blk-pci,disable-modern=on,disable-legacy=off`:
 *
 *   - The device is found on the PCI bus as vendor 0x1AF4, device 0x1001.
 *   - Its config registers live behind an *I/O-port* BAR (BAR0), poked with
 *     in/out — NOT MMIO. (Modern virtio uses MMIO capability structures; legacy
 *     is just this flat I/O-port window, which is why we use it here.)
 *   - Init is a handshake through the Device Status register: reset, then set
 *     ACKNOWLEDGE, DRIVER, negotiate features (we need none), DRIVER_OK.
 *   - One split virtqueue (queue 0) is a single physically-contiguous region:
 *     the descriptor table, then the available ring, then (page-aligned) the
 *     used ring. We hand the device its page-frame number (phys >> 12) in the
 *     Queue Address register.
 *   - A block request is three chained descriptors: a 16-byte header (type +
 *     LBA, device-readable), the data buffer (writable for a read, readable for
 *     a write), and a 1-byte status the device writes. We put the head in the
 *     available ring, bump its index, write the queue index to Queue Notify, and
 *     poll the used ring until the request is consumed; status == 0 means OK.
 *
 * SAFE SCOPE: this is an *additional* block device. The OS still BOOTS from, and
 * runs FAT32/VFS on, the legacy ATA disk (kernel/ata.c). virtio_blk_init() probes
 * PCI for a virtio block device; with none attached it is a clean no-op, so a
 * machine without one boots unchanged. Mirrors kernel/ahci.c's additive shape.
 *
 * All shared structures come from pmm_alloc_frame(): the PMM returns low physical
 * RAM that the boot page tables identity-map (phys == virt), so a frame address
 * is BOTH a CPU-usable pointer AND the physical address the device needs — the
 * same path kernel/ahci.c and kernel/e1000.c use for their DMA structures. A
 * 4 KiB frame is naturally 4 KiB-aligned, which is exactly the alignment the
 * legacy virtqueue's PFN scheme and the used-ring page boundary require.
 */
#include "virtio_blk.h"
#include "pci.h"
#include "pmm.h"
#include "vmm.h"
#include "string.h"
#include "console.h"
#include "io.h"

/* ---- legacy virtio-over-PCI config registers (I/O-port BAR, byte offsets) ---
 * This is the "legacy common configuration" header that begins at the start of
 * the device's I/O space when MSI-X is not enabled. */
#define VIRTIO_PCI_HOST_FEATURES 0x00   /* 32-bit: features the device offers (RO)   */
#define VIRTIO_PCI_GUEST_FEATURES 0x04  /* 32-bit: features we accept (WO)           */
#define VIRTIO_PCI_QUEUE_PFN     0x08   /* 32-bit: queue page-frame number (phys>>12)*/
#define VIRTIO_PCI_QUEUE_SIZE    0x0C   /* 16-bit: size of the selected queue (RO)   */
#define VIRTIO_PCI_QUEUE_SEL     0x0E   /* 16-bit: which queue subsequent regs act on*/
#define VIRTIO_PCI_QUEUE_NOTIFY  0x10   /* 16-bit: write a queue index to kick it    */
#define VIRTIO_PCI_STATUS        0x12   /* 8-bit: device status handshake            */
#define VIRTIO_PCI_ISR           0x13   /* 8-bit: interrupt status (read to ack)     */
/* Device-specific config begins here (MSI-X disabled). For virtio-blk the first
 * field is the 64-bit capacity, in 512-byte sectors. */
#define VIRTIO_PCI_CONFIG        0x14

/* Device Status bits. */
#define VIRTIO_STATUS_ACKNOWLEDGE 0x01  /* we noticed the device                     */
#define VIRTIO_STATUS_DRIVER      0x02  /* we know how to drive it                   */
#define VIRTIO_STATUS_DRIVER_OK   0x04  /* setup complete, may use the device        */
#define VIRTIO_STATUS_FAILED      0x80  /* we gave up (so the device can react)      */

/* virtqueue descriptor flags. */
#define VRING_DESC_F_NEXT  1            /* this descriptor chains to ->next          */
#define VRING_DESC_F_WRITE 2            /* device-WRITABLE (else device-readable)    */

/* virtio-blk request types + status (the request header's `type` and the trailing
 * status byte). */
#define VIRTIO_BLK_T_IN  0             /* read from device into our buffer          */
#define VIRTIO_BLK_T_OUT 1             /* write from our buffer to device           */
#define VIRTIO_BLK_S_OK  0             /* request completed successfully            */

#define VIRTIO_QUEUE_ALIGN 4096        /* legacy: used ring sits at the next 4K page */

/* One 16-byte split-virtqueue descriptor: a physical buffer + flags + chain. */
struct vring_desc {
    uint64_t addr;     /* guest-physical address of the buffer                      */
    uint32_t len;      /* length in bytes                                           */
    uint16_t flags;    /* VRING_DESC_F_*                                            */
    uint16_t next;     /* index of the next descriptor if F_NEXT                    */
} __attribute__((packed));

/* The available ring: we publish descriptor-chain heads here for the device. */
struct vring_avail {
    uint16_t flags;
    uint16_t idx;      /* total entries ever added (free-running, wraps mod qsz)    */
    uint16_t ring[];   /* ring[idx % qsz] = head descriptor index                   */
} __attribute__((packed));

/* One used-ring entry: the device reports a completed chain here. */
struct vring_used_elem {
    uint32_t id;       /* head descriptor index of the completed chain              */
    uint32_t len;      /* total bytes written into the chain's writable buffers     */
} __attribute__((packed));

/* The used ring: the device publishes completions here for us to poll. */
struct vring_used {
    uint16_t flags;
    uint16_t idx;      /* total completions ever produced (free-running)            */
    struct vring_used_elem ring[];
} __attribute__((packed));

/* The 16-byte virtio-blk request header (always device-readable). */
struct virtio_blk_req_hdr {
    uint32_t type;     /* VIRTIO_BLK_T_IN / _OUT                                     */
    uint32_t reserved;
    uint64_t sector;   /* starting LBA (in 512-byte units)                          */
} __attribute__((packed));

/* Compute the byte size of the three legacy-vring regions given the queue size:
 * the descriptor table + available ring fall in the first block, then the used
 * ring starts at the next VIRTIO_QUEUE_ALIGN boundary. (This is the standard
 * `vring_size` from the virtio spec, specialized to align == 4096.) */
static uint32_t vring_size(uint16_t qsz) {
    uint32_t a = (uint32_t)qsz * sizeof(struct vring_desc)            /* desc table */
               + sizeof(uint16_t) * (2 + qsz);                        /* avail ring */
    uint32_t used = sizeof(uint16_t) * 2                              /* used hdr   */
                  + (uint32_t)qsz * sizeof(struct vring_used_elem);   /* used ring  */
    /* round `a` up to the alignment, then add the used-ring block */
    a = (a + (VIRTIO_QUEUE_ALIGN - 1)) & ~(VIRTIO_QUEUE_ALIGN - 1);
    return a + used;
}

/* Driver state for the one virtio block device we support. */
static struct {
    int                present;
    uint16_t           io_base;    /* I/O-port BAR base for the config registers   */
    uint16_t           qsz;        /* queue 0 size (number of descriptors)         */
    uint64_t           capacity;   /* device capacity in 512-byte sectors          */

    struct vring_desc *desc;       /* descriptor table (qsz entries)               */
    struct vring_avail *avail;     /* available ring                               */
    struct vring_used  *used;      /* used ring (page-aligned after the avail ring)*/
    uint64_t           queue_phys; /* physical base of the contiguous vring region */
    uint16_t           used_seen;  /* used->idx we've already processed            */
} vb;

/* ---- I/O-port config accessors (legacy BAR0 is in I/O space) ------------- */
static uint8_t  vcfg_r8 (uint16_t off)            { return inb(vb.io_base + off); }
static void     vcfg_w8 (uint16_t off, uint8_t v) { outb(vb.io_base + off, v); }
static uint16_t vcfg_r16(uint16_t off)            { return inw(vb.io_base + off); }
static void     vcfg_w16(uint16_t off, uint16_t v){ outw(vb.io_base + off, v); }
static uint32_t vcfg_r32(uint16_t off)            { return inl(vb.io_base + off); }
static void     vcfg_w32(uint16_t off, uint32_t v){ outl(vb.io_base + off, v); }

/* Set a Device Status bit (status is cumulative — read, OR, write back). */
static void vb_add_status(uint8_t bits) {
    vcfg_w8(VIRTIO_PCI_STATUS, (uint8_t)(vcfg_r8(VIRTIO_PCI_STATUS) | bits));
}

/* Physical address of a kernel pointer, for handing buffers to the device. Our
 * structures and the kernel buffers we read into live in the identity-mapped low
 * RAM (phys == virt), but translating is the correct general way to obtain the
 * physical address — exactly as kernel/ahci.c does. */
static uint64_t phys_of(const void *p) {
    uint64_t t = vmm_translate((uint64_t)(uintptr_t)p);
    return t ? t : hhdm_phys(p);   /* no translation: it is an HHDM pointer, so subtract the base (M1970) */
}

int virtio_blk_init(void) {
    memset(&vb, 0, sizeof(vb));

    /* Legacy virtio-blk over PCI: vendor 0x1AF4 (Red Hat / virtio), device
     * 0x1001 (legacy block; the modern device id is 0x1042). */
    pci_device_t dev = pci_find(0x1AF4, 0x1001);
    if (!dev.valid)
        return -1;

    /* Enable bus mastering (the device DMAs our virtqueue) + I/O-space decode so
     * the BAR0 config ports respond. pci_enable_bus_master sets bus-master +
     * memory-space; also set I/O-space (bit 0) since our BAR is in I/O space. */
    pci_enable_bus_master(&dev);
    uint32_t cmd = pci_read32(dev.bus, dev.slot, dev.func, 0x04);
    cmd |= (1u << 0);                       /* I/O space enable */
    pci_write32(dev.bus, dev.slot, dev.func, 0x04, cmd);

    /* BAR0 is the legacy I/O-port window; pci_bar masks off the low flag bits. */
    uint32_t bar0 = pci_bar(&dev, 0);
    vb.io_base = (uint16_t)(bar0 & 0xFFFF);

    /* --- init handshake (virtio 0.9.5 §2.2.1) --------------------------------
     * Reset by writing 0, then announce ourselves step by step. */
    vcfg_w8(VIRTIO_PCI_STATUS, 0);          /* reset the device */
    vb_add_status(VIRTIO_STATUS_ACKNOWLEDGE);
    vb_add_status(VIRTIO_STATUS_DRIVER);

    /* Feature negotiation: read what the device offers and accept the subset we
     * support. A basic blocking driver needs none of the optional features
     * (no SCSI, no FLUSH-dependence, no segment-max constraint we must honor for
     * single-segment data), so we negotiate 0 — simplest and always valid. */
    (void)vcfg_r32(VIRTIO_PCI_HOST_FEATURES);
    vcfg_w32(VIRTIO_PCI_GUEST_FEATURES, 0);

    /* Capacity (device-specific config): 64-bit sector count at offset 0x14.
     * Read as two 32-bit halves (the I/O window is 32-bit at most). */
    uint32_t cap_lo = vcfg_r32(VIRTIO_PCI_CONFIG + 0);
    uint32_t cap_hi = vcfg_r32(VIRTIO_PCI_CONFIG + 4);
    vb.capacity = ((uint64_t)cap_hi << 32) | cap_lo;

    /* --- virtqueue 0 setup ---------------------------------------------------
     * Select queue 0 and read its size; bound it so the whole vring fits in the
     * frames we allocate below (qsz is a power of two, <= 256 for virtio-blk on
     * QEMU, and we cap defensively). */
    vcfg_w16(VIRTIO_PCI_QUEUE_SEL, 0);
    uint16_t qsz = vcfg_r16(VIRTIO_PCI_QUEUE_SIZE);
    if (qsz == 0) {                         /* no such queue: bail cleanly */
        vb_add_status(VIRTIO_STATUS_FAILED);
        return -1;
    }
    if (qsz > 256)
        qsz = 256;                          /* keep the vring within a few frames */
    vb.qsz = qsz;

    /* Allocate one physically-contiguous, page-aligned region for the whole
     * split virtqueue. pmm_alloc_frame() returns page-aligned 4 KiB frames; the
     * region may need more than one, so grab a run of *consecutive* frames. For
     * the sizes here (qsz<=256 -> ~8 KiB) this is one or two frames; we allocate
     * the worst case and verify they came back contiguous (the PMM is a simple
     * bump/bitmap allocator, so a fresh run is contiguous in practice — but we
     * check rather than assume). */
    uint32_t need = vring_size(qsz);
    uint32_t frames = (need + (PAGE_SIZE - 1)) / PAGE_SIZE;

    uint64_t base = pmm_alloc_frame();
    if (!base) { vb_add_status(VIRTIO_STATUS_FAILED); return -1; }
    uint64_t prev = base;
    for (uint32_t i = 1; i < frames; i++) {
        uint64_t f = pmm_alloc_frame();
        if (!f || f != prev + PAGE_SIZE) {
            /* Not contiguous (or out of memory): give up cleanly. We don't try
             * to free the partial run — frame leak on this rare path is harmless
             * and keeps the bail-out simple; the boot continues on ATA. */
            vb_add_status(VIRTIO_STATUS_FAILED);
            return -1;
        }
        prev = f;
    }
    memset(hhdm(base), 0, (size_t)frames * PAGE_SIZE);

    vb.queue_phys = base;
    vb.desc  = (struct vring_desc *)hhdm(base);
    vb.avail = (struct vring_avail *)hhdm(base + qsz * sizeof(struct vring_desc));
    /* The used ring starts at the next VIRTIO_QUEUE_ALIGN boundary after the
     * descriptor table + available ring (legacy layout). */
    uint64_t used_off = (uint64_t)qsz * sizeof(struct vring_desc)
                      + sizeof(uint16_t) * (2 + qsz);
    used_off = (used_off + (VIRTIO_QUEUE_ALIGN - 1)) & ~(uint64_t)(VIRTIO_QUEUE_ALIGN - 1);
    vb.used  = (struct vring_used *)hhdm(base + used_off);
    vb.used_seen = 0;

    /* Hand the device the queue by page-frame number (legacy: PFN = phys >> 12).
     * The region is page-aligned, so this is exact. */
    vcfg_w32(VIRTIO_PCI_QUEUE_PFN, (uint32_t)(base >> 12));

    /* Setup done: the device may now process the queue. */
    vb_add_status(VIRTIO_STATUS_DRIVER_OK);

    vb.present = 1;
    return 0;
}

int      virtio_blk_present(void)  { return vb.present; }
uint64_t virtio_blk_capacity(void) { return vb.present ? vb.capacity : 0; }

/* The shared core of read and write: build the 3-descriptor request chain for one
 * transfer, publish it, notify the device, and poll the used ring to completion.
 * `write` selects VIRTIO_BLK_T_OUT and makes the data descriptor device-readable.
 * Returns 0 on success, -1 on bad-arg / device error / timeout. */
/* Is [p, p+len) one contiguous run in physical memory? Walks page by page and
 * requires each successive page to be physically adjacent to the last. (M2144) */
static int virtio_phys_contiguous(const void *p, uint32_t len) {
    uint64_t a0 = phys_of(p);
    if (!a0) return 0;
    uint64_t va = (uint64_t)p;
    uint64_t end = va + len;
    for (uint64_t v = (va & ~(uint64_t)(PAGE_SIZE - 1)) + PAGE_SIZE; v < end; v += PAGE_SIZE) {
        uint64_t want = a0 + (v - va);
        if (phys_of((const void *)v) != want) return 0;
    }
    return 1;
}

static int virtio_blk_xfer(uint64_t lba, uint32_t count, void *buf, int write) {
    if (!vb.present || count == 0 || !buf)
        return -1;
    /* Need three descriptors (header, data, status). The queue must hold them. */
    if (vb.qsz < 3)
        return -1;
    /* Bound the transfer: a single data descriptor's len is 32-bit, and we don't
     * want a multi-MiB request — cap at 256 sectors (128 KiB) per call, well
     * within range. Also refuse reads/writes past the device. */
    if (count > 256)
        return -1;
    if (vb.capacity && (lba >= vb.capacity || count > vb.capacity - lba))
        return -1;

    /* One in-flight request at a time (this is a simple blocking driver), so we
     * always use descriptors 0,1,2 and avail/used slot 0. A persistent on-stack
     * header+status keeps their physical addresses valid for the device. The
     * header/status sit in identity-mapped kernel stack/BSS; phys_of() resolves
     * them the same way as the data buffer. */
    static struct virtio_blk_req_hdr hdr;   /* device-readable request header   */
    static volatile uint8_t status;         /* device-writable completion byte  */

    hdr.type     = write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    hdr.reserved = 0;
    hdr.sector   = lba;
    status       = 0xFF;                     /* poison; device overwrites with 0 */

    uint32_t bytes = count * VIRTIO_BLK_SECTOR_SIZE;

    /* ONE DESCRIPTOR DESCRIBES ONE PHYSICALLY CONTIGUOUS RUN (M2144).
     *
     * desc[1] below is a single (addr, len) pair, so pointing it at the
     * caller's buffer is only correct while that buffer is contiguous in
     * PHYSICAL memory. It was written against the self-test, whose buffer is a
     * page-aligned array in identity-mapped BSS -- contiguous by construction
     * -- and every caller was that self-test, so the assumption held and was
     * never stated.
     *
     * It stops holding the moment a filesystem uses this device. ext2 with 4
     * KiB blocks reads eight sectors into an arbitrary kernel buffer, which
     * straddles pages that need not be physically adjacent; the device then
     * DMAs the tail of the transfer into whatever happens to live after the
     * first page. The symptom was a machine that could read the ext2
     * superblock in a self-test and had no readable filesystem at all:
     *
     *   [ ok ] blockdev browse: 2 volume(s) listed across 2 device(s).
     *   [lxabi] root /disk2: vfs_stat FAILED
     *
     * Bounce through a buffer that IS contiguous, exactly as ata.c's DMA path
     * does. A scatter-gather chain -- one descriptor per physical run -- would
     * avoid the copy and is the better answer eventually; a memcpy inside RAM
     * is nothing against the transport win, and correctness comes first. */
    static uint8_t bounce[256 * VIRTIO_BLK_SECTOR_SIZE] __attribute__((aligned(PAGE_SIZE)));
    void *dma = buf;
    int bounced = 0;
    if (!virtio_phys_contiguous(buf, bytes)) {
        if (bytes > sizeof bounce) return -1;   /* capped at 256 sectors above */
        dma = bounce;
        bounced = 1;
        if (write) for (uint32_t k = 0; k < bytes; k++) bounce[k] = ((const uint8_t *)buf)[k];
    }

    /* desc[0]: the header, device-readable, chains to the data descriptor. */
    vb.desc[0].addr  = phys_of(&hdr);
    vb.desc[0].len   = sizeof(hdr);
    vb.desc[0].flags = VRING_DESC_F_NEXT;
    vb.desc[0].next  = 1;

    /* desc[1]: the data buffer. For a READ the device writes into it
     * (F_WRITE); for a WRITE the device reads from it (no F_WRITE). Chains to
     * the status descriptor. */
    vb.desc[1].addr  = phys_of(dma);
    vb.desc[1].len   = bytes;
    vb.desc[1].flags = VRING_DESC_F_NEXT | (write ? 0 : VRING_DESC_F_WRITE);
    vb.desc[1].next  = 2;

    /* desc[2]: the 1-byte status, always device-writable, end of the chain. */
    vb.desc[2].addr  = phys_of((const void *)&status);
    vb.desc[2].len   = 1;
    vb.desc[2].flags = VRING_DESC_F_WRITE;
    vb.desc[2].next  = 0;

    /* Publish the chain head (descriptor 0) in the available ring and bump idx.
     * (One outstanding request, so slot index = avail->idx % qsz.) The write to
     * avail->idx must land after the ring entry — a compiler barrier suffices on
     * x86's strong memory model (no store reordering across volatiles). */
    vb.avail->ring[vb.avail->idx % vb.qsz] = 0;
    __asm__ volatile("" ::: "memory");
    vb.avail->idx++;
    __asm__ volatile("" ::: "memory");

    /* Notify the device that queue 0 has work. */
    vcfg_w16(VIRTIO_PCI_QUEUE_NOTIFY, 0);

    /* Poll the used ring until the device reports our chain complete. No IRQ. */
    int done = 0;
    for (int i = 0; i < 100000000; i++) {
        if (vb.used->idx != vb.used_seen) { done = 1; break; }
        __asm__ volatile("pause");
    }
    if (!done)
        return -1;                           /* timeout */

    if (bounced && !write)
        for (uint32_t k = 0; k < bytes; k++) ((uint8_t *)buf)[k] = bounce[k];

    /* Consume exactly one used entry (the one we submitted). */
    vb.used_seen++;
    (void)vcfg_r8(VIRTIO_PCI_ISR);           /* read ISR to ack any pending IRQ  */

    return (status == VIRTIO_BLK_S_OK) ? 0 : -1;
}

int virtio_blk_read(uint64_t lba, uint32_t count, void *buf) {
    return virtio_blk_xfer(lba, count, buf, 0);
}

int virtio_blk_write(uint64_t lba, uint32_t count, const void *buf) {
    return virtio_blk_xfer(lba, count, (void *)buf, 1);
}

/* ---- boot-time verification --------------------------------------------- */

/* A static, page-aligned DMA buffer for the self-test, in the kernel's BSS
 * (identity-mapped low RAM, so its physical address is its own address). */
static uint8_t selftest_buf[VIRTIO_BLK_SECTOR_SIZE * 4] __attribute__((aligned(PAGE_SIZE)));

/* Read a few sectors off the virtio block device and log the first bytes + a
 * simple additive checksum, so the read can be matched against known on-disk
 * content. This is the boot verification hook; a no-op if no virtio block
 * device is attached (mirrors ahci_selftest). */
void virtio_blk_selftest(void) {
    if (!vb.present) {
        kprintf("[virtio-blk] no virtio block device found "
                "(none attached; legacy ATA boot intact).\n\n");
        return;
    }

    kprintf("[ ok ] virtio-blk up: %lu sectors (%lu MiB) via virtqueue "
            "(boot stays on legacy ATA).\n",
            vb.capacity, (vb.capacity * VIRTIO_BLK_SECTOR_SIZE) / (1024 * 1024));

    for (uint64_t lba = 0; lba < 3; lba++) {
        if (virtio_blk_read(lba, 1, selftest_buf) != 0) {
            kprintf("[virtio-blk] sector %lu: READ FAILED\n", lba);
            continue;
        }
        /* Additive checksum over the whole sector + the first 16 bytes shown as
         * hex and (printable) ASCII, so a known pattern is recognizable. */
        uint32_t sum = 0;
        for (int i = 0; i < VIRTIO_BLK_SECTOR_SIZE; i++)
            sum += selftest_buf[i];
        kprintf("[virtio-blk] sector %lu sum=%08x first16=", lba, sum);
        for (int i = 0; i < 16; i++)
            kprintf("%02x ", selftest_buf[i]);
        kprintf(" |");
        for (int i = 0; i < 16; i++) {
            uint8_t c = selftest_buf[i];
            kprintf("%c", (c >= 0x20 && c < 0x7F) ? (char)c : '.');
        }
        kprintf("|\n");
    }

    /* Write round-trip on a high sector: save it, write a marker, read it back,
     * verify, then restore the original so we don't corrupt the test image. Done
     * only if the device has room (>=8 sectors) — the self-test image is tiny but
     * non-trivial. A failure here is reported but not fatal to boot. */
    if (vb.capacity >= 8) {
        uint64_t test_lba = vb.capacity - 1;   /* last sector: least likely to matter */
        static uint8_t saved[VIRTIO_BLK_SECTOR_SIZE] __attribute__((aligned(PAGE_SIZE)));
        static uint8_t scratch[VIRTIO_BLK_SECTOR_SIZE] __attribute__((aligned(PAGE_SIZE)));
        if (virtio_blk_read(test_lba, 1, saved) == 0) {
            for (int i = 0; i < VIRTIO_BLK_SECTOR_SIZE; i++)
                scratch[i] = (uint8_t)(0xA5 ^ (i & 0xFF));
            int ok = (virtio_blk_write(test_lba, 1, scratch) == 0);
            uint8_t readback[VIRTIO_BLK_SECTOR_SIZE] = {0};
            ok = ok && (virtio_blk_read(test_lba, 1, readback) == 0);
            ok = ok && (memcmp(readback, scratch, VIRTIO_BLK_SECTOR_SIZE) == 0);
            virtio_blk_write(test_lba, 1, saved);   /* restore original content */
            kprintf("[virtio-blk] write round-trip on sector %lu: %s\n",
                    test_lba, ok ? "OK (wrote+read back+restored)" : "MISMATCH");
        }
    }

    kprintf("[ ok ] virtio-blk read self-test complete "
            "(bytes above are the real disk content).\n\n");
}
