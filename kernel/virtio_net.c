/*
 * virtio_net.c — virtio-net driver: the paravirtual NIC over PCI.
 *
 * The third member of the virtio family in this kernel. virtio_blk.c is the
 * model for the mechanics: a virtio device is not emulated register by register
 * like the e1000/RTL8139; the hypervisor and guest agree on a shared-memory
 * protocol and exchange work through *virtqueues* — rings of descriptors in RAM
 * that we fill and the device consumes. virtio-net just has TWO of them:
 *
 *   - queue 0 = RECEIVE: we pre-fill it with empty, device-WRITABLE buffers and
 *     publish them; the device DMAs each accepted frame into one and reports it
 *     done in the used ring. We drain the used ring, hand the frame up, and
 *     recycle the buffer back onto the avail ring.
 *   - queue 1 = TRANSMIT: to send, we take a free buffer, write the frame into
 *     it (device-READABLE), publish it, and notify; the device DMAs it onto the
 *     wire and reports done. We poll the used ring to reclaim the buffer.
 *   - queue 2 = CONTROL: SKIPPED. We don't negotiate VIRTIO_NET_F_CTRL_VQ, so it
 *     isn't used — keeps the driver dead simple.
 *
 * Every frame on BOTH queues is prefixed by a 10-byte `struct virtio_net_hdr`
 * (legacy layout, no num_buffers field — we don't negotiate MRG_RXBUF). On TX we
 * zero it (no checksum offload, GSO_NONE). On RX it precedes the frame and we
 * skip it.
 *
 * We speak the LEGACY transport (virtio 0.9.5) over PCI, which QEMU exposes with
 * `-device virtio-net-pci,disable-modern=on,disable-legacy=off`:
 *   - found on the PCI bus as vendor 0x1AF4, device 0x1000;
 *   - config registers live behind an I/O-port BAR (BAR0), poked with in/out;
 *   - init is the Device Status handshake: reset, ACK, DRIVER, negotiate
 *     features (only VIRTIO_NET_F_MAC, to read the MAC), FEATURES_OK, set up the
 *     virtqueues by page-frame number, DRIVER_OK.
 *
 * This driver plugs into the NIC-agnostic seam (kernel/nic.c) exactly like
 * rtl8139.c: it provides get-MAC / send / poll-receive and a virtio_net_init()
 * that returns 0 / -1; nic_init() probes it after the e1000 and RTL8139. With a
 * virtio NIC present and no e1000, the whole net.c stack runs over it. If no
 * virtio NIC is attached, virtio_net_init() is a clean no-op and the kernel
 * boots unchanged.
 *
 * All shared structures come from pmm_alloc_frame(): the PMM returns low physical
 * RAM that the boot page tables identity-map (phys == virt), so a frame address
 * is BOTH a CPU-usable pointer AND the physical address the device needs — the
 * same path virtio_blk.c / e1000.c / rtl8139.c use for their DMA structures.
 */
#include "virtio_net.h"
#include "pci.h"
#include "pmm.h"
#include "vmm.h"
#include "string.h"
#include "console.h"
#include "io.h"

/* ---- legacy virtio-over-PCI config registers (I/O-port BAR, byte offsets) ----
 * The "legacy common configuration" header at the start of the device's I/O
 * space when MSI-X is not enabled — identical to virtio_blk.c. */
#define VIRTIO_PCI_HOST_FEATURES  0x00   /* 32-bit: features the device offers (RO)   */
#define VIRTIO_PCI_GUEST_FEATURES 0x04   /* 32-bit: features we accept (WO)           */
#define VIRTIO_PCI_QUEUE_PFN      0x08   /* 32-bit: queue page-frame number (phys>>12)*/
#define VIRTIO_PCI_QUEUE_SIZE     0x0C   /* 16-bit: size of the selected queue (RO)   */
#define VIRTIO_PCI_QUEUE_SEL      0x0E   /* 16-bit: which queue subsequent regs act on*/
#define VIRTIO_PCI_QUEUE_NOTIFY   0x10   /* 16-bit: write a queue index to kick it    */
#define VIRTIO_PCI_STATUS         0x12   /* 8-bit: device status handshake            */
#define VIRTIO_PCI_ISR            0x13   /* 8-bit: interrupt status (read to ack)     */
/* Device-specific config begins here (MSI-X disabled). For virtio-net, when
 * VIRTIO_NET_F_MAC is offered, the first field is the 6-byte MAC address. */
#define VIRTIO_PCI_CONFIG         0x14

/* Device Status bits. */
#define VIRTIO_STATUS_ACKNOWLEDGE 0x01   /* we noticed the device                     */
#define VIRTIO_STATUS_DRIVER      0x02   /* we know how to drive it                   */
#define VIRTIO_STATUS_DRIVER_OK   0x04   /* setup complete, may use the device        */
#define VIRTIO_STATUS_FEATURES_OK 0x08   /* feature negotiation accepted (legacy: ok) */
#define VIRTIO_STATUS_FAILED      0x80   /* we gave up (so the device can react)      */

/* The single virtio-net feature we care about: the device exposes a MAC in its
 * config space. We negotiate ONLY this — no checksum/offload, no GSO, no
 * mergeable RX buffers (MRG_RXBUF), no control queue. */
#define VIRTIO_NET_F_MAC          (1u << 5)

/* virtqueue descriptor flags. */
#define VRING_DESC_F_NEXT  1             /* this descriptor chains to ->next          */
#define VRING_DESC_F_WRITE 2             /* device-WRITABLE (else device-readable)    */

#define VIRTIO_QUEUE_ALIGN 4096          /* legacy: used ring sits at the next 4K page */

/* virtio-net queue indices (legacy, no CTRL_VQ). */
#define VNET_RXQ 0
#define VNET_TXQ 1

/* One Ethernet frame plus slack; the device writes hdr+frame into an RX buffer
 * and reads hdr+frame from a TX buffer. 1514 = max Ethernet payload without VLAN
 * (6+6+2 header + 1500 MTU). */
#define VNET_FRAME_MAX 1514

/* Cap the per-queue descriptor count we actually use. QEMU's virtio-net queues
 * are 256 deep; we use a modest number of buffers (one descriptor each, no
 * chaining) and bound the queue defensively so the whole vring + buffers stay in
 * a handful of frames. */
#define VNET_MAX_QSZ   256
#define VNET_RX_BUFS    32              /* receive buffers we keep posted            */
#define VNET_TX_BUFS    16              /* transmit buffers in flight (round-robin)  */

/* One 16-byte split-virtqueue descriptor (identical to virtio_blk.c). */
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

/* The 10-byte legacy virtio-net header that prefixes every frame on both queues.
 * No `num_buffers` field — that only exists with VIRTIO_NET_F_MRG_RXBUF, which we
 * deliberately do NOT negotiate. */
struct virtio_net_hdr {
    uint8_t  flags;        /* VIRTIO_NET_HDR_F_* (0 = no checksum offload)          */
    uint8_t  gso_type;     /* 0 = VIRTIO_NET_HDR_GSO_NONE                           */
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
} __attribute__((packed));

/* One split virtqueue: the descriptor table + avail ring + (page-aligned) used
 * ring, all in one physically-contiguous region, plus our bookkeeping. */
struct virtq {
    uint16_t            qsz;        /* queue size (number of descriptors)            */
    struct vring_desc  *desc;       /* descriptor table (qsz entries)                */
    struct vring_avail *avail;      /* available ring                                */
    struct vring_used  *used;       /* used ring (page-aligned after the avail ring) */
    uint64_t            queue_phys; /* physical base of the contiguous vring region  */
    uint16_t            used_seen;  /* used->idx we've already processed             */
};

/* Driver state for the one virtio-net device we support. */
static struct {
    int               present;
    uint16_t          io_base;      /* I/O-port BAR base for the config registers    */
    uint8_t           mac[6];

    struct virtq      rx;
    struct virtq      tx;

    /* Buffers. Each is one frame's worth: hdr (10 B) + up to 1514 B of Ethernet.
     * They are PMM frames (identity-mapped: phys == virt), each used by exactly
     * one descriptor (no chaining). RX descriptor i points at rx_buf[i]; TX
     * descriptor i points at tx_buf[i]. */
    uint8_t          *rx_buf[VNET_RX_BUFS];
    uint8_t          *tx_buf[VNET_TX_BUFS];
    uint16_t          tx_next;      /* next TX buffer to use (round-robin)           */
    uint16_t          rx_count;     /* number of RX buffers actually allocated       */
    uint16_t          tx_count;     /* number of TX buffers actually allocated       */
} vn;

/* The size of one frame buffer: the 10-byte header followed by a full frame. */
#define VNET_BUF_SIZE (sizeof(struct virtio_net_hdr) + VNET_FRAME_MAX)

/* ---- I/O-port config accessors (legacy BAR0 is in I/O space) ------------- */
static uint8_t  vcfg_r8 (uint16_t off)            { return inb(vn.io_base + off); }
static void     vcfg_w8 (uint16_t off, uint8_t v) { outb(vn.io_base + off, v); }
static uint16_t vcfg_r16(uint16_t off)            { return inw(vn.io_base + off); }
static void     vcfg_w16(uint16_t off, uint16_t v){ outw(vn.io_base + off, v); }
static uint32_t vcfg_r32(uint16_t off)            { return inl(vn.io_base + off); }
static void     vcfg_w32(uint16_t off, uint32_t v){ outl(vn.io_base + off, v); }

/* Set a Device Status bit (status is cumulative — read, OR, write back). */
static void vn_add_status(uint8_t bits) {
    vcfg_w8(VIRTIO_PCI_STATUS, (uint8_t)(vcfg_r8(VIRTIO_PCI_STATUS) | bits));
}

/* Physical address of a kernel pointer, for handing buffers to the device.
 * Our structures live in identity-mapped low RAM (phys == virt), but translating
 * is the correct general way to obtain the physical address — as virtio_blk.c. */
static uint64_t phys_of(const void *p) {
    uint64_t t = vmm_translate((uint64_t)(uintptr_t)p);
    return t ? t : hhdm_phys(p);   /* no translation: it is an HHDM pointer, so subtract the base (M1970) */
}

/* Allocate one physically-contiguous, page-aligned region of `frames` PMM frames
 * and zero it. Returns the base physical address (== usable pointer), or 0 if the
 * frames did not come back contiguous / the PMM is exhausted. (The PMM is a
 * bump/bitmap allocator, so a fresh run is contiguous in practice — we check
 * rather than assume, exactly like virtio_blk.c.) */
static uint64_t alloc_contig(uint32_t frames) {
    if (frames == 0)
        return 0;
    uint64_t base = pmm_alloc_frame();
    if (!base)
        return 0;
    uint64_t prev = base;
    for (uint32_t i = 1; i < frames; i++) {
        uint64_t f = pmm_alloc_frame();
        if (!f || f != prev + PAGE_SIZE)
            return 0;       /* non-contiguous / OOM: bail (partial leak is harmless) */
        prev = f;
    }
    memset(hhdm(base), 0, (size_t)frames * PAGE_SIZE);
    return base;
}

/* Lay out one split virtqueue of the given size in a freshly-allocated contiguous
 * region and program the device's Queue Address (PFN). Returns 0 on success, -1
 * on allocation failure. The layout is the legacy one: descriptor table, then the
 * available ring, then the used ring at the next VIRTIO_QUEUE_ALIGN boundary —
 * byte-for-byte the same computation virtio_blk.c does. */
static int virtq_setup(struct virtq *q, uint16_t queue_index, uint16_t qsz) {
    /* desc table + avail ring, rounded up to the alignment, then the used ring. */
    uint64_t desc_avail = (uint64_t)qsz * sizeof(struct vring_desc)
                        + sizeof(uint16_t) * (2 + qsz);
    uint64_t used_off = (desc_avail + (VIRTIO_QUEUE_ALIGN - 1))
                      & ~(uint64_t)(VIRTIO_QUEUE_ALIGN - 1);
    uint64_t used_bytes = sizeof(uint16_t) * 2
                        + (uint64_t)qsz * sizeof(struct vring_used_elem);
    uint64_t total = used_off + used_bytes;
    uint32_t frames = (uint32_t)((total + (PAGE_SIZE - 1)) / PAGE_SIZE);

    uint64_t base = alloc_contig(frames);
    if (!base)
        return -1;

    q->qsz        = qsz;
    q->queue_phys = base;
    q->desc       = (struct vring_desc  *)hhdm(base);
    q->avail      = (struct vring_avail *)hhdm(base + (uint64_t)qsz * sizeof(struct vring_desc));
    q->used       = (struct vring_used  *)hhdm(base + used_off);
    q->used_seen  = 0;

    /* Select the queue and hand the device its region by page-frame number
     * (legacy: PFN = phys >> 12). The region is page-aligned, so this is exact. */
    vcfg_w16(VIRTIO_PCI_QUEUE_SEL, queue_index);
    vcfg_w32(VIRTIO_PCI_QUEUE_PFN, (uint32_t)(base >> 12));
    return 0;
}

/* Post one RX buffer (descriptor `i`) into the avail ring: a single
 * device-WRITABLE descriptor pointing at rx_buf[i], holding hdr+frame. The
 * caller bumps avail->idx + notifies after a batch (or per-recycle). */
static void rx_post(uint16_t i) {
    struct virtq *q = &vn.rx;
    q->desc[i].addr  = phys_of(vn.rx_buf[i]);
    q->desc[i].len   = VNET_BUF_SIZE;
    q->desc[i].flags = VRING_DESC_F_WRITE;     /* device writes the received frame  */
    q->desc[i].next  = 0;
    /* Publish descriptor i at the next avail slot. */
    q->avail->ring[q->avail->idx % q->qsz] = i;
    __asm__ volatile("" ::: "memory");
    q->avail->idx++;
}

int virtio_net_init(void) {
    if (vn.present)            /* idempotent: nic.c and kmain.c may both call us */
        return 0;

    memset(&vn, 0, sizeof(vn));

    /* Legacy virtio-net over PCI: vendor 0x1AF4 (Red Hat / virtio), device
     * 0x1000 (legacy network; the modern device id is 0x1041). */
    pci_device_t dev = pci_find(0x1AF4, 0x1000);
    if (!dev.valid)
        return -1;

    /* Enable bus mastering (the device DMAs our virtqueues) + memory-space, then
     * also I/O-space decode (bit 0) since our BAR0 is in I/O space. */
    pci_enable_bus_master(&dev);
    uint32_t cmd = pci_read32(dev.bus, dev.slot, dev.func, 0x04);
    cmd |= (1u << 0);                       /* I/O space enable */
    pci_write32(dev.bus, dev.slot, dev.func, 0x04, cmd);

    /* BAR0 is the legacy I/O-port window; pci_bar masks off the low flag bits. */
    uint32_t bar0 = pci_bar(&dev, 0);
    vn.io_base = (uint16_t)(bar0 & 0xFFFF);

    /* --- init handshake (virtio 0.9.5 §2.2.1) -------------------------------- */
    vcfg_w8(VIRTIO_PCI_STATUS, 0);          /* reset the device */
    vn_add_status(VIRTIO_STATUS_ACKNOWLEDGE);
    vn_add_status(VIRTIO_STATUS_DRIVER);

    /* Feature negotiation: accept ONLY VIRTIO_NET_F_MAC (and only if offered) so
     * we can read the device MAC. No offload, no GSO, no mergeable RX buffers, no
     * control queue — the simplest valid driver. */
    uint32_t host_features = vcfg_r32(VIRTIO_PCI_HOST_FEATURES);
    uint32_t want = host_features & VIRTIO_NET_F_MAC;
    vcfg_w32(VIRTIO_PCI_GUEST_FEATURES, want);

    /* Acknowledge our feature selection. Legacy devices predate FEATURES_OK, but
     * setting it is harmless (a legacy device ignores the bit) and correct for a
     * transitional device negotiating the legacy interface — mirrors the spec's
     * recommended sequence. We don't require the device to keep the bit set. */
    vn_add_status(VIRTIO_STATUS_FEATURES_OK);

    /* MAC: read 6 bytes from device-specific config (offset 0x14, MSI-X absent)
     * if the device offered VIRTIO_NET_F_MAC; otherwise synthesize a locally-
     * administered address (bit 1 of the first octet set, bit 0 clear). */
    if (want & VIRTIO_NET_F_MAC) {
        for (int i = 0; i < 6; i++)
            vn.mac[i] = vcfg_r8(VIRTIO_PCI_CONFIG + i);
    } else {
        static const uint8_t la[6] = {0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF};
        memcpy(vn.mac, la, 6);
    }

    /* --- queue sizes: probe RX (queue 0) and TX (queue 1) -------------------- */
    vcfg_w16(VIRTIO_PCI_QUEUE_SEL, VNET_RXQ);
    uint16_t rxsz = vcfg_r16(VIRTIO_PCI_QUEUE_SIZE);
    vcfg_w16(VIRTIO_PCI_QUEUE_SEL, VNET_TXQ);
    uint16_t txsz = vcfg_r16(VIRTIO_PCI_QUEUE_SIZE);

    /* A queue size of 0 means the device doesn't have that queue: bail cleanly.
     * Cap absurd sizes defensively so the vring stays within a few frames. */
    if (rxsz == 0 || txsz == 0) {
        vn_add_status(VIRTIO_STATUS_FAILED);
        return -1;
    }
    if (rxsz > VNET_MAX_QSZ) rxsz = VNET_MAX_QSZ;
    if (txsz > VNET_MAX_QSZ) txsz = VNET_MAX_QSZ;

    /* We use one descriptor per buffer (no chaining), so we need at most as many
     * descriptors as buffers; clamp the buffer counts to the queue sizes too. */
    uint16_t rx_bufs = VNET_RX_BUFS;
    uint16_t tx_bufs = VNET_TX_BUFS;
    if (rx_bufs > rxsz) rx_bufs = rxsz;
    if (tx_bufs > txsz) tx_bufs = txsz;
    if (rx_bufs == 0 || tx_bufs == 0) {     /* paranoia: a 0-after-clamp is unusable */
        vn_add_status(VIRTIO_STATUS_FAILED);
        return -1;
    }

    /* --- lay out both virtqueues + program their PFNs ------------------------ */
    if (virtq_setup(&vn.rx, VNET_RXQ, rxsz) != 0) {
        vn_add_status(VIRTIO_STATUS_FAILED);
        return -1;
    }
    if (virtq_setup(&vn.tx, VNET_TXQ, txsz) != 0) {
        vn_add_status(VIRTIO_STATUS_FAILED);
        return -1;
    }

    /* --- allocate the frame buffers (one PMM frame each: 4 KiB >> 1524 B) ----
     * Each buffer is one page; the buffer's physical address (== its pointer on
     * this identity-mapped kernel) goes straight into the descriptor. */
    for (uint16_t i = 0; i < rx_bufs; i++) {
        uint64_t f = pmm_alloc_frame();
        if (!f) { vn_add_status(VIRTIO_STATUS_FAILED); return -1; }
        vn.rx_buf[i] = (uint8_t *)hhdm(f);
    }
    vn.rx_count = rx_bufs;
    for (uint16_t i = 0; i < tx_bufs; i++) {
        uint64_t f = pmm_alloc_frame();
        if (!f) { vn_add_status(VIRTIO_STATUS_FAILED); return -1; }
        vn.tx_buf[i] = (uint8_t *)hhdm(f);
    }
    vn.tx_count = tx_bufs;
    vn.tx_next  = 0;

    /* --- pre-fill the RX queue with all our receive buffers ------------------ */
    for (uint16_t i = 0; i < rx_bufs; i++)
        rx_post(i);                          /* posts desc i + bumps avail->idx     */
    __asm__ volatile("" ::: "memory");

    /* Setup done: the device may now process the queues. */
    vn_add_status(VIRTIO_STATUS_DRIVER_OK);

    /* Kick the RX queue so the device picks up the buffers we just published. */
    vcfg_w16(VIRTIO_PCI_QUEUE_NOTIFY, VNET_RXQ);

    vn.present = 1;
    return 0;
}

int virtio_net_present(void) { return vn.present; }

const uint8_t *virtio_net_get_mac(void) { return vn.mac; }

int virtio_net_send(const void *frame, uint16_t len) {
    if (!vn.present || !frame || len == 0 || len > VNET_FRAME_MAX)
        return -1;

    struct virtq *q = &vn.tx;
    uint16_t i = vn.tx_next;                  /* round-robin TX buffer + descriptor  */
    if (i >= vn.tx_count)                     /* paranoia (tx_next is kept in range) */
        i = 0;

    /* Write a zeroed virtio_net_hdr, then the frame right after it, into the
     * buffer. No offload (flags=0), GSO_NONE (gso_type=0). */
    uint8_t *buf = vn.tx_buf[i];
    memset(buf, 0, sizeof(struct virtio_net_hdr));
    memcpy(buf + sizeof(struct virtio_net_hdr), frame, len);

    /* One device-READABLE descriptor covering hdr+frame (no F_WRITE). */
    q->desc[i].addr  = phys_of(buf);
    q->desc[i].len   = (uint32_t)(sizeof(struct virtio_net_hdr) + len);
    q->desc[i].flags = 0;                     /* device-readable, no chain           */
    q->desc[i].next  = 0;

    /* Publish the descriptor head in the avail ring and bump idx. A compiler
     * barrier orders the ring-entry store before the idx store; x86's strong
     * memory model needs no fence (matches virtio_blk.c). This send is
     * synchronous (we poll the used ring to completion below before returning),
     * so used_seen == used->idx on entry and a single advance is OUR completion. */
    q->avail->ring[q->avail->idx % q->qsz] = i;
    __asm__ volatile("" ::: "memory");
    q->avail->idx++;
    __asm__ volatile("" ::: "memory");

    /* Advance the round-robin pointer for the next send. */
    vn.tx_next = (uint16_t)((i + 1) % vn.tx_count);

    /* Notify the device that the TX queue has work. */
    vcfg_w16(VIRTIO_PCI_QUEUE_NOTIFY, VNET_TXQ);

    /* Poll the used ring for this transmit to complete (finite timeout, no IRQ).
     * Synchronous + simple: one frame is on the wire before we return. */
    for (int spin = 0; spin < 100000000; spin++) {
        if (q->used->idx != q->used_seen) {
            q->used_seen++;                   /* consume exactly the one we submitted */
            (void)vcfg_r8(VIRTIO_PCI_ISR);    /* ack any pending IRQ                 */
            return 0;
        }
        __asm__ volatile("pause");
    }
    return -1;                                /* timeout */
}

int virtio_net_poll_receive(void *out, uint16_t max) {
    if (!vn.present || !out || max == 0)
        return 0;

    struct virtq *q = &vn.rx;

    /* Nothing new in the used ring => nothing to hand up. */
    if (q->used->idx == q->used_seen)
        return 0;

    /* Read one completed entry. Barrier so we read the entry AFTER observing the
     * bumped used->idx (matches virtio_blk.c's read ordering). */
    __asm__ volatile("" ::: "memory");
    uint16_t slot = (uint16_t)(q->used_seen % q->qsz);
    uint32_t desc_id = q->used->ring[slot].id;
    uint32_t used_len = q->used->ring[slot].len;
    q->used_seen++;

    uint16_t framelen = 0;

    /* desc_id is the buffer index we posted. Guard it (the device is untrusted)
     * and only copy if it's in range and the buffer pointer is valid. */
    if (desc_id < vn.rx_count && vn.rx_buf[desc_id]) {
        uint8_t *buf = vn.rx_buf[desc_id];

        /* used_len counts the bytes the device wrote: the 10-byte header + the
         * Ethernet frame. Strip the header. Clamp the reported length to our
         * buffer first (never trust the device), then derive the frame length. */
        if (used_len > VNET_BUF_SIZE)
            used_len = VNET_BUF_SIZE;
        if (used_len > sizeof(struct virtio_net_hdr)) {
            uint32_t fl = used_len - (uint32_t)sizeof(struct virtio_net_hdr);
            /* Clamp the copy to BOTH the caller's max AND the (already buffer-
             * clamped) reported frame length, so we never read past the buffer
             * nor write past `out`. */
            if (fl > max)
                fl = max;
            memcpy(out, buf + sizeof(struct virtio_net_hdr), fl);
            framelen = (uint16_t)fl;
        }

        /* Recycle this buffer back onto the RX avail ring so the device can fill
         * it again, then notify. */
        rx_post(desc_id);
        __asm__ volatile("" ::: "memory");
        vcfg_w16(VIRTIO_PCI_QUEUE_NOTIFY, VNET_RXQ);
    }

    (void)vcfg_r8(VIRTIO_PCI_ISR);            /* ack any pending IRQ                 */
    return framelen;
}

/* ---- boot-time log ------------------------------------------------------- */
void virtio_net_selftest(void) {
    if (!vn.present)
        return;                               /* no device: stay quiet (clean no-op) */
    kprintf("[ ok ] virtio-net up: MAC = %02x:%02x:%02x:%02x:%02x:%02x "
            "(RX %u / TX %u buffers via virtqueues).\n",
            vn.mac[0], vn.mac[1], vn.mac[2], vn.mac[3], vn.mac[4], vn.mac[5],
            vn.rx_count, vn.tx_count);
}
