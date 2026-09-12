/*
 * virtio_rng.c — virtio-rng driver: the paravirtual hardware entropy source.
 *
 * virtio-rng is the simplest virtio device there is: a single virtqueue over
 * which we hand the device an empty, device-WRITABLE buffer and it fills it
 * with random bytes (drawn from the host's entropy pool) and reports how many
 * it wrote. No request header, no status byte, no device-specific config — just
 * "here's a buffer, fill it." It's the canonical way a guest gets real entropy
 * from the hypervisor instead of relying solely on its own PRNG seeding.
 *
 * Like kernel/virtio_blk.c we speak the LEGACY transport (virtio 0.9.5) over
 * PCI, which QEMU exposes with `-device virtio-rng-pci` (legacy by default on
 * the i440fx machine, or force it with disable-modern=on):
 *
 *   - vendor 0x1AF4, device 0x1005 (legacy entropy source; modern id 0x1044).
 *   - Config registers behind the I/O-port BAR0, poked with in/out.
 *   - Init handshake through Device Status: reset, ACKNOWLEDGE, DRIVER,
 *     negotiate features (none needed), set up the one virtqueue, DRIVER_OK.
 *   - To get entropy: publish ONE device-writable descriptor pointing at our
 *     buffer in the available ring, kick Queue Notify, poll the used ring; the
 *     used element's `len` is how many random bytes the device wrote.
 *
 * SAFE SCOPE: purely additive. virtio_rng_init() probes PCI; with no virtio-rng
 * device attached it is a clean no-op (so every existing boot is unchanged), and
 * nothing in the kernel depends on it — it's an extra entropy source the
 * self-test exercises. Mirrors the additive shape of virtio_blk.c / ahci.c.
 *
 * All shared structures come from pmm_alloc_frame(): the PMM returns low
 * physical RAM the boot page tables identity-map (phys == virt), so a frame is
 * both a usable pointer and the physical address the device DMAs — the same
 * path virtio_blk.c uses, and a 4 KiB frame is the alignment the legacy
 * virtqueue PFN scheme requires.
 */
#include "virtio_rng.h"
#include "pci.h"
#include "pmm.h"
#include "vmm.h"
#include "string.h"
#include "console.h"
#include "io.h"
#include "msi.h"          /* MSI-X: route queue 0 to a message-signaled interrupt (M1288) */

/* ---- legacy virtio-over-PCI config registers (I/O-port BAR, byte offsets) --- */
#define VIRTIO_PCI_HOST_FEATURES  0x00
#define VIRTIO_PCI_GUEST_FEATURES 0x04
#define VIRTIO_PCI_QUEUE_PFN      0x08
#define VIRTIO_PCI_QUEUE_SIZE     0x0C
#define VIRTIO_PCI_QUEUE_SEL      0x0E
#define VIRTIO_PCI_QUEUE_NOTIFY   0x10
#define VIRTIO_PCI_STATUS         0x12
#define VIRTIO_PCI_ISR            0x13
/* These two 16-bit registers only EXIST once MSI-X is enabled in the device's
 * PCI capability; they pick which MSI-X table entry the config-change event and
 * the currently-selected queue signal through (M1288). */
#define VIRTIO_MSIX_CONFIG_VEC    0x14
#define VIRTIO_MSIX_QUEUE_VEC     0x16
#define VIRTIO_MSI_NO_VECTOR      0xFFFF

#define VIRTIO_STATUS_ACKNOWLEDGE 0x01
#define VIRTIO_STATUS_DRIVER      0x02
#define VIRTIO_STATUS_DRIVER_OK   0x04
#define VIRTIO_STATUS_FAILED      0x80

#define VRING_DESC_F_NEXT  1
#define VRING_DESC_F_WRITE 2            /* device-WRITABLE (the rng fills it)        */

#define VIRTIO_QUEUE_ALIGN 4096

/* Split-virtqueue structures (identical layout to virtio_blk.c). */
struct vring_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed));

struct vring_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
} __attribute__((packed));

struct vring_used_elem {
    uint32_t id;       /* head descriptor index of the completed chain              */
    uint32_t len;      /* bytes the device wrote into the chain's writable buffers  */
} __attribute__((packed));

struct vring_used {
    uint16_t flags;
    uint16_t idx;
    struct vring_used_elem ring[];
} __attribute__((packed));

static uint32_t vring_size(uint16_t qsz) {
    uint32_t a = (uint32_t)qsz * sizeof(struct vring_desc)
               + sizeof(uint16_t) * (2 + qsz);
    uint32_t used = sizeof(uint16_t) * 2
                  + (uint32_t)qsz * sizeof(struct vring_used_elem);
    a = (a + (VIRTIO_QUEUE_ALIGN - 1)) & ~(VIRTIO_QUEUE_ALIGN - 1);
    return a + used;
}

/* Driver state for the one virtio-rng device we support. */
static struct {
    int                present;
    uint16_t           io_base;
    uint16_t           qsz;
    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used  *used;
    uint64_t           queue_phys;
    uint16_t           used_seen;
    int                msi_vec;            /* MSI-X vector routed to queue 0, 0 if none (M1288) */
} vr;

/* MSI-X (M1288): our queue-0 interrupt handler + the count of times it has run.
 * The self-test checks this to prove our handler actually executed in interrupt
 * context — not merely that the kernel tallied a delivery. */
static volatile uint32_t vr_msi_fires;
static void vr_msi_handler(struct registers *r) { (void)r; vr_msi_fires++; }

static uint8_t  vcfg_r8 (uint16_t off)            { return inb(vr.io_base + off); }
static void     vcfg_w8 (uint16_t off, uint8_t v) { outb(vr.io_base + off, v); }
static uint16_t vcfg_r16(uint16_t off)            { return inw(vr.io_base + off); }
static void     vcfg_w16(uint16_t off, uint16_t v){ outw(vr.io_base + off, v); }
static uint32_t vcfg_r32(uint16_t off)            { return inl(vr.io_base + off); }
static void     vcfg_w32(uint16_t off, uint32_t v){ outl(vr.io_base + off, v); }

static void vr_add_status(uint8_t bits) {
    vcfg_w8(VIRTIO_PCI_STATUS, (uint8_t)(vcfg_r8(VIRTIO_PCI_STATUS) | bits));
}

static uint64_t phys_of(const void *p) {
    uint64_t t = vmm_translate((uint64_t)(uintptr_t)p);
    return t ? t : hhdm_phys(p);   /* no translation: it is an HHDM pointer, so subtract the base (M1970) */
}

int virtio_rng_init(void) {
    memset(&vr, 0, sizeof(vr));

    pci_device_t dev = pci_find(0x1AF4, 0x1005);   /* legacy virtio entropy source */
    if (!dev.valid)
        return -1;

    pci_enable_bus_master(&dev);
    uint32_t cmd = pci_read32(dev.bus, dev.slot, dev.func, 0x04);
    cmd |= (1u << 0);                              /* I/O-space enable */
    pci_write32(dev.bus, dev.slot, dev.func, 0x04, cmd);

    uint32_t bar0 = pci_bar(&dev, 0);
    vr.io_base = (uint16_t)(bar0 & 0xFFFF);

    /* Init handshake: reset, then announce ourselves step by step. */
    vcfg_w8(VIRTIO_PCI_STATUS, 0);
    vr_add_status(VIRTIO_STATUS_ACKNOWLEDGE);
    vr_add_status(VIRTIO_STATUS_DRIVER);

    /* virtio-rng needs no optional features — negotiate 0 (always valid). */
    (void)vcfg_r32(VIRTIO_PCI_HOST_FEATURES);
    vcfg_w32(VIRTIO_PCI_GUEST_FEATURES, 0);

    /* The single request virtqueue (queue 0). */
    vcfg_w16(VIRTIO_PCI_QUEUE_SEL, 0);
    uint16_t qsz = vcfg_r16(VIRTIO_PCI_QUEUE_SIZE);
    if (qsz == 0) { vr_add_status(VIRTIO_STATUS_FAILED); return -1; }
    if (qsz > 256) qsz = 256;
    vr.qsz = qsz;

    uint32_t need = vring_size(qsz);
    uint32_t frames = (need + (PAGE_SIZE - 1)) / PAGE_SIZE;

    uint64_t base = pmm_alloc_frame();
    if (!base) { vr_add_status(VIRTIO_STATUS_FAILED); return -1; }
    uint64_t prev = base;
    for (uint32_t i = 1; i < frames; i++) {
        uint64_t f = pmm_alloc_frame();
        if (!f || f != prev + PAGE_SIZE) { vr_add_status(VIRTIO_STATUS_FAILED); return -1; }
        prev = f;
    }
    memset(hhdm(base), 0, (size_t)frames * PAGE_SIZE);

    vr.queue_phys = base;
    vr.desc  = (struct vring_desc *)hhdm(base);
    vr.avail = (struct vring_avail *)hhdm(base + qsz * sizeof(struct vring_desc));
    uint64_t used_off = (uint64_t)qsz * sizeof(struct vring_desc)
                      + sizeof(uint16_t) * (2 + qsz);
    used_off = (used_off + (VIRTIO_QUEUE_ALIGN - 1)) & ~(uint64_t)(VIRTIO_QUEUE_ALIGN - 1);
    vr.used  = (struct vring_used *)hhdm(base + used_off);
    vr.used_seen = 0;

    vcfg_w32(VIRTIO_PCI_QUEUE_PFN, (uint32_t)(base >> 12));

    /* MSI-X (M1288): route queue 0's used-buffer notification to a real message-
     * signaled interrupt rather than relying solely on the used-ring poll in
     * virtio_rng_read. If the device exposes an MSI-X capability, claim a CPU
     * vector, program table entry 0 to deliver it to the boot CPU, then tell the
     * device — via the legacy virtio MSI-X vector registers, which only appear
     * once MSI-X is enabled in the PCI capability — to use that entry for queue 0.
     * Purely additive: the poll still works regardless of whether this succeeds. */
    vr.msi_vec = 0;
    int nvec = 0;
    if (msi_x_available(&dev, &nvec) && nvec >= 1) {
        int vec = msi_alloc_vector(vr_msi_handler);
        if (vec >= 0 && msi_x_route(&dev, 0, (uint8_t)vec) == 0) {
            vcfg_w16(VIRTIO_MSIX_CONFIG_VEC, VIRTIO_MSI_NO_VECTOR);  /* no config-change vector */
            vcfg_w16(VIRTIO_PCI_QUEUE_SEL, 0);                      /* select queue 0 ... */
            vcfg_w16(VIRTIO_MSIX_QUEUE_VEC, 0);                     /* ... -> MSI-X table entry 0 */
            if (vcfg_r16(VIRTIO_MSIX_QUEUE_VEC) == 0)               /* device accepted the vector */
                vr.msi_vec = vec;
        }
    }

    vr_add_status(VIRTIO_STATUS_DRIVER_OK);

    vr.present = 1;
    return 0;
}

int virtio_rng_present(void) { return vr.present; }

/* Fill `buf` with up to `max` random bytes from the device. Returns the number
 * of bytes the device actually wrote (>0), or -1 on no-device / error / timeout.
 * One outstanding request at a time (a simple blocking driver), so we always use
 * descriptor 0 and avail/used slot 0. */
long virtio_rng_read(void *buf, unsigned long max) {
    if (!vr.present || !buf || max == 0 || vr.qsz < 1)
        return -1;
    if (max > 0xFFFFFFFFu) max = 0xFFFFFFFFu;

    /* One device-writable descriptor: the device fills it with entropy. */
    vr.desc[0].addr  = phys_of(buf);
    vr.desc[0].len   = (uint32_t)max;
    vr.desc[0].flags = VRING_DESC_F_WRITE;
    vr.desc[0].next  = 0;

    /* Publish descriptor 0's head in the available ring and bump idx. */
    vr.avail->ring[vr.avail->idx % vr.qsz] = 0;
    __asm__ volatile("" ::: "memory");
    vr.avail->idx++;
    __asm__ volatile("" ::: "memory");

    vcfg_w16(VIRTIO_PCI_QUEUE_NOTIFY, 0);          /* kick queue 0 */

    /* Poll the used ring until the device reports our buffer filled. No IRQ. */
    int done = 0;
    for (int i = 0; i < 100000000; i++) {
        if (vr.used->idx != vr.used_seen) { done = 1; break; }
        __asm__ volatile("pause");
    }
    if (!done) return -1;                          /* timeout */

    /* The used element's len = bytes the device wrote (may be < max). */
    uint32_t slot = vr.used_seen % vr.qsz;
    uint32_t got  = vr.used->ring[slot].len;
    vr.used_seen++;
    (void)vcfg_r8(VIRTIO_PCI_ISR);                 /* ack any pending IRQ */

    if (got > max) got = (uint32_t)max;            /* defensive: never report > buffer */
    return (long)got;
}

/* ---- boot-time verification ---------------------------------------------- */

/* A static, page-aligned DMA buffer for the self-test (identity-mapped low RAM,
 * so its physical address is its own address). */
static uint8_t rng_buf[64] __attribute__((aligned(PAGE_SIZE)));
static uint8_t rng_buf2[64] __attribute__((aligned(PAGE_SIZE)));

/* Draw two batches of entropy and log them, asserting the device DMA'd real,
 * varying random bytes. No-op if no virtio-rng device is attached. */
void virtio_rng_selftest(void) {
    if (!vr.present) {
        kprintf("[virtio-rng] no virtio entropy device found (none attached).\n\n");
        return;
    }

    kprintf("[ ok ] virtio-rng up: hardware entropy source via virtqueue.\n");

    long n1 = virtio_rng_read(rng_buf, sizeof rng_buf);
    long n2 = virtio_rng_read(rng_buf2, sizeof rng_buf2);
    if (n1 <= 0 || n2 <= 0) {
        kprintf("[virtio-rng] READ FAILED (n1=%ld n2=%ld)\n", n1, n2);
        return;
    }

    /* Two properties prove real entropy moved over DMA: (1) at least one byte is
     * non-zero (the device didn't just leave our zeroed buffer alone), and (2)
     * the two independent batches differ (it's not a constant). */
    int nonzero = 0;
    for (long i = 0; i < n1; i++) if (rng_buf[i]) { nonzero = 1; break; }
    int differ = (n1 != n2);
    for (long i = 0; i < n1 && i < n2 && !differ; i++)
        if (rng_buf[i] != rng_buf2[i]) differ = 1;

    kprintf("[virtio-rng] batch1 (%ld B) first8=", n1);
    for (int i = 0; i < 8 && i < n1; i++) kprintf("%02x", rng_buf[i]);
    kprintf(" batch2 (%ld B) first8=", n2);
    for (int i = 0; i < 8 && i < n2; i++) kprintf("%02x", rng_buf2[i]);
    kprintf("\n");

    if (nonzero && differ)
        kprintf("[ ok ] virtio-rng entropy OK (nonzero + batch1 != batch2, used ring advanced).\n\n");
    else
        kprintf("[virtio-rng] ENTROPY MISMATCH (nonzero=%d differ=%d)\n\n", nonzero, differ);

    /* MSI-X (M1288): the two reads above each advanced queue 0's used ring, so if
     * we routed it to a message-signaled interrupt the device should have signaled
     * our vector. Confirm BOTH our driver handler ran and the kernel's per-vector
     * tally agree (they count the same deliveries, from opposite sides). */
    if (vr.msi_vec) {
        for (volatile int i = 0; i < 5000000 && vr_msi_fires == 0; i++)
            __asm__ volatile("pause");
        uint64_t kn = msi_irq_count((uint8_t)vr.msi_vec);
        if (vr_msi_fires > 0 && kn > 0)
            kprintf("[ ok ] virtio-rng MSI-X: queue 0 -> vector 0x%x; device signaled it %u time(s) "
                    "(our handler ran, LAPIC-delivered) -- MSI-X OK\n\n", vr.msi_vec, (unsigned)vr_msi_fires);
        else
            kprintf("[virtio-rng] MSI-X NO INTERRUPT (vec=0x%x handler_fires=%u kernel_count=%lu)\n\n",
                    vr.msi_vec, (unsigned)vr_msi_fires, kn);
    } else {
        kprintf("[virtio-rng] MSI-X: no MSI-X capability on this device (poll-only)\n\n");
    }
}
