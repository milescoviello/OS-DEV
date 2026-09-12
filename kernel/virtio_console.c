/*
 * virtio_console.c — virtio-console driver: a paravirtual serial port to the
 * host. The guest writes bytes to the port's transmit virtqueue and they come
 * out of whatever the hypervisor wired the chardev to (a host file, a pipe, a
 * pty). It's the standard "talk to the host out-of-band" channel under QEMU.
 *
 * Like kernel/virtio_blk.c and kernel/virtio_rng.c we speak the LEGACY transport
 * (virtio 0.9.5) over PCI, which QEMU exposes with
 *   -device virtio-serial-pci,disable-modern=on,disable-legacy=off
 *   -device virtconsole,chardev=c  -chardev file,id=c,path=...
 *
 *   - vendor 0x1AF4, device 0x1003 (legacy console; modern id 0x1043).
 *   - Config registers behind the I/O-port BAR0, poked with in/out.
 *   - Init handshake through Device Status: reset, ACK, DRIVER, negotiate
 *     features = 0 (in particular we do NOT take VIRTIO_CONSOLE_F_MULTIPORT, so
 *     the device is a single implicit port and needs no control queue), set up
 *     the two port virtqueues, DRIVER_OK.
 *   - Port 0 receiveq = queue 0, transmitq = queue 1. To emit bytes we publish
 *     one device-READABLE descriptor on queue 1, kick Queue Notify, and poll the
 *     used ring. (We don't consume console input, so queue 0 is set up but left
 *     unpopulated — its presence keeps QEMU happy at DRIVER_OK.)
 *
 * SAFE SCOPE: purely additive. virtio_console_init() probes PCI; with no
 * virtio-console device attached it is a clean no-op (every existing boot is
 * unchanged) and nothing depends on it. Mirrors the additive shape of the other
 * virtio drivers. All vring memory comes from pmm_alloc_frame() (identity-mapped
 * low RAM: phys == virt, 4 KiB-aligned — exactly what the legacy PFN scheme
 * needs).
 */
#include "virtio_console.h"
#include "pci.h"
#include "pmm.h"
#include "vmm.h"
#include "string.h"
#include "console.h"
#include "io.h"

/* ---- legacy virtio-over-PCI config registers (I/O-port BAR, byte offsets) --- */
#define VIRTIO_PCI_HOST_FEATURES  0x00
#define VIRTIO_PCI_GUEST_FEATURES 0x04
#define VIRTIO_PCI_QUEUE_PFN      0x08
#define VIRTIO_PCI_QUEUE_SIZE     0x0C
#define VIRTIO_PCI_QUEUE_SEL      0x0E
#define VIRTIO_PCI_QUEUE_NOTIFY   0x10
#define VIRTIO_PCI_STATUS         0x12
#define VIRTIO_PCI_ISR            0x13

#define VIRTIO_STATUS_ACKNOWLEDGE 0x01
#define VIRTIO_STATUS_DRIVER      0x02
#define VIRTIO_STATUS_DRIVER_OK   0x04
#define VIRTIO_STATUS_FAILED      0x80

#define VRING_DESC_F_NEXT  1
#define VRING_DESC_F_WRITE 2

#define VIRTIO_QUEUE_ALIGN 4096

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
    uint32_t id;
    uint32_t len;
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

/* One split virtqueue. */
struct vq {
    uint16_t            qsz;
    struct vring_desc  *desc;
    struct vring_avail *avail;
    struct vring_used  *used;
    uint16_t            used_seen;
};

static struct {
    int       present;
    uint16_t  io_base;
    struct vq rxq;     /* queue 0: port receive (unused — we don't read input) */
    struct vq txq;     /* queue 1: port transmit (our writes) */
} vc;

static uint8_t  vcfg_r8 (uint16_t off)            { return inb(vc.io_base + off); }
static void     vcfg_w8 (uint16_t off, uint8_t v) { outb(vc.io_base + off, v); }
static uint16_t vcfg_r16(uint16_t off)            { return inw(vc.io_base + off); }
static void     vcfg_w16(uint16_t off, uint16_t v){ outw(vc.io_base + off, v); }
static uint32_t vcfg_r32(uint16_t off)            { return inl(vc.io_base + off); }
static void     vcfg_w32(uint16_t off, uint32_t v){ outl(vc.io_base + off, v); }

static void vc_add_status(uint8_t bits) {
    vcfg_w8(VIRTIO_PCI_STATUS, (uint8_t)(vcfg_r8(VIRTIO_PCI_STATUS) | bits));
}

static uint64_t phys_of(const void *p) {
    uint64_t t = vmm_translate((uint64_t)(uintptr_t)p);
    return t ? t : hhdm_phys(p);   /* no translation: it is an HHDM pointer, so subtract the base (M1970) */
}

/* Select queue `idx`, allocate its contiguous split-vring, hand the device the
 * page-frame number, and fill *q. Returns 0/-1. */
static int setup_vq(uint16_t idx, struct vq *q) {
    vcfg_w16(VIRTIO_PCI_QUEUE_SEL, idx);
    uint16_t qsz = vcfg_r16(VIRTIO_PCI_QUEUE_SIZE);
    if (qsz == 0) return -1;
    if (qsz > 256) qsz = 256;
    q->qsz = qsz;

    uint32_t need = vring_size(qsz);
    uint32_t frames = (need + (PAGE_SIZE - 1)) / PAGE_SIZE;
    uint64_t base = pmm_alloc_frame();
    if (!base) return -1;
    uint64_t prev = base;
    for (uint32_t i = 1; i < frames; i++) {
        uint64_t f = pmm_alloc_frame();
        if (!f || f != prev + PAGE_SIZE) return -1;   /* need a contiguous run */
        prev = f;
    }
    memset(hhdm(base), 0, (size_t)frames * PAGE_SIZE);

    q->desc  = (struct vring_desc *)hhdm(base);
    q->avail = (struct vring_avail *)hhdm(base + qsz * sizeof(struct vring_desc));
    uint64_t used_off = (uint64_t)qsz * sizeof(struct vring_desc)
                      + sizeof(uint16_t) * (2 + qsz);
    used_off = (used_off + (VIRTIO_QUEUE_ALIGN - 1)) & ~(uint64_t)(VIRTIO_QUEUE_ALIGN - 1);
    q->used  = (struct vring_used *)hhdm(base + used_off);
    q->used_seen = 0;

    vcfg_w32(VIRTIO_PCI_QUEUE_PFN, (uint32_t)(base >> 12));
    return 0;
}

int virtio_console_init(void) {
    memset(&vc, 0, sizeof(vc));

    pci_device_t dev = pci_find(0x1AF4, 0x1003);   /* legacy virtio console */
    if (!dev.valid)
        return -1;

    pci_enable_bus_master(&dev);
    uint32_t cmd = pci_read32(dev.bus, dev.slot, dev.func, 0x04);
    cmd |= (1u << 0);                              /* I/O-space enable */
    pci_write32(dev.bus, dev.slot, dev.func, 0x04, cmd);

    uint32_t bar0 = pci_bar(&dev, 0);
    vc.io_base = (uint16_t)(bar0 & 0xFFFF);

    vcfg_w8(VIRTIO_PCI_STATUS, 0);                 /* reset */
    vc_add_status(VIRTIO_STATUS_ACKNOWLEDGE);
    vc_add_status(VIRTIO_STATUS_DRIVER);

    /* Negotiate 0: in particular drop VIRTIO_CONSOLE_F_MULTIPORT, so this is a
     * single implicit port with no control queue — just rx (q0) + tx (q1). */
    (void)vcfg_r32(VIRTIO_PCI_HOST_FEATURES);
    vcfg_w32(VIRTIO_PCI_GUEST_FEATURES, 0);

    if (setup_vq(0, &vc.rxq) != 0) { vc_add_status(VIRTIO_STATUS_FAILED); return -1; }
    if (setup_vq(1, &vc.txq) != 0) { vc_add_status(VIRTIO_STATUS_FAILED); return -1; }

    vc_add_status(VIRTIO_STATUS_DRIVER_OK);
    vc.present = 1;
    return 0;
}

int virtio_console_present(void) { return vc.present; }

/* Emit `len` bytes out the console transmit queue. One device-readable
 * descriptor per call (a simple blocking driver: descriptor 0 / avail slot 0).
 * Returns bytes written (>=0) or -1. The buffer must outlive the call; we copy
 * into a static DMA buffer so callers can pass transient strings. */
static uint8_t tx_dma[2048] __attribute__((aligned(PAGE_SIZE)));

long virtio_console_write(const void *buf, unsigned long len) {
    if (!vc.present || !buf || len == 0) return -1;
    if (vc.txq.qsz < 1) return -1;
    if (len > sizeof tx_dma) len = sizeof tx_dma;
    for (unsigned long i = 0; i < len; i++) tx_dma[i] = ((const uint8_t *)buf)[i];

    struct vq *q = &vc.txq;
    q->desc[0].addr  = phys_of(tx_dma);
    q->desc[0].len   = (uint32_t)len;
    q->desc[0].flags = 0;                          /* device-READABLE (it reads our bytes out) */
    q->desc[0].next  = 0;

    q->avail->ring[q->avail->idx % q->qsz] = 0;
    __asm__ volatile("" ::: "memory");
    q->avail->idx++;
    __asm__ volatile("" ::: "memory");

    vcfg_w16(VIRTIO_PCI_QUEUE_NOTIFY, 1);          /* kick queue 1 (transmitq) */

    int done = 0;
    for (int i = 0; i < 100000000; i++) {
        if (q->used->idx != q->used_seen) { done = 1; break; }
        __asm__ volatile("pause");
    }
    if (!done) return -1;                           /* timeout */
    q->used_seen++;
    (void)vcfg_r8(VIRTIO_PCI_ISR);

    return (long)len;
}

/* Boot-time self-test: if a virtio-console is attached, emit a recognizable
 * line out the transmit queue (the host's chardev sink receives it) and log a
 * marker. No-op if no device. */
void virtio_console_selftest(void) {
    if (!vc.present) {
        kprintf("[virtio-console] no virtio console device found (none attached).\n\n");
        return;
    }
    static const char msg[] = "hello from OS-DEV virtio-console (M1260)\n";
    long n = virtio_console_write(msg, sizeof(msg) - 1);
    if (n == (long)(sizeof(msg) - 1))
        kprintf("[ ok ] virtio-console up: wrote %ld bytes out the transmit virtqueue "
                "(host chardev sink received them).\n\n", n);
    else
        kprintf("[virtio-console] WRITE FAILED (n=%ld)\n\n", n);
}
