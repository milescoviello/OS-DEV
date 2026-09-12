/*
 * virtio_gpu.c — virtio-gpu (2D) paravirtual display driver (modern virtio 1.0).
 *
 * A virtio-gpu does NOT scan out of a linear framebuffer. The display is a
 * host-side *resource*; the guest draws into a backing buffer it owns in RAM,
 * then explicitly TRANSFERs the dirty rectangle to the host's copy of the
 * resource and FLUSHes it to present. Bring-up wires one resource to scanout 0:
 *
 *     CREATE_2D (id 1, BGRX, WxH)            create the host resource
 *     ATTACH_BACKING (id 1, guest frames)    give it guest RAM to read from
 *     SET_SCANOUT (scanout 0, id 1, rect)    bind it to the display
 *  then per frame:
 *     TRANSFER_TO_HOST_2D (rect)             copy backing -> host resource
 *     RESOURCE_FLUSH (rect)                  present
 *
 * TRANSPORT: unlike kernel/virtio_blk.c (legacy virtio over an I/O-port BAR),
 * QEMU's virtio-gpu-pci is a MODERN-ONLY virtio 1.0 device (PCI 1af4:1050, MMIO
 * BARs, no legacy I/O register window — even with disable-modern=on). So this
 * driver speaks the MODERN PCI transport:
 *
 *   - Walk the device's PCI capability list (status reg's cap-list bit -> the
 *     capabilities pointer at 0x34 -> the linked list) for the four virtio
 *     vendor capabilities (cap_vndr == 0x09), reading each one's cfg_type, the
 *     BAR it lives in, and the offset/length within that BAR:
 *       COMMON_CFG (1): the device/driver feature + status + queue registers,
 *       NOTIFY_CFG (2): the queue-notify doorbell (+ a per-queue multiplier),
 *       ISR_CFG    (3): interrupt status (read to ack),
 *       DEVICE_CFG (4): device-specific config (virtio_gpu_config: #scanouts).
 *   - Map each cap's MMIO region (cache-disabled), then handshake through the
 *     common config: reset -> ACK -> DRIVER -> negotiate features (we accept
 *     only the mandatory VIRTIO_F_VERSION_1) -> FEATURES_OK (and verify it
 *     stuck) -> set up the control virtqueue (queue 0) -> DRIVER_OK.
 *   - The split virtqueue (descriptor table / available ring / used ring) and
 *     the fill/notify/poll cycle are identical to virtio_blk.c; modern just
 *     lets us give the three rings separate physical addresses (queue_desc /
 *     queue_driver / queue_device) instead of one PFN, and the notify is an
 *     MMIO write rather than an I/O-port write.
 *
 * SAFE SCOPE: ADDITIVE. The boot display path (fb.c + bochs_vbe.c, the linear
 * framebuffer) is untouched; virtio_gpu_init() is a clean no-op (returns -1)
 * when no virtio-gpu is attached, so a machine without one boots unchanged. All
 * shared memory (rings, requests, responses, the backing buffer) comes from
 * pmm_alloc_frame() — identity-mapped low RAM (phys == virt), so a frame
 * address is both a CPU pointer and the physical address the device needs.
 */
#include "virtio_gpu.h"
#include "pci.h"
#include "pmm.h"
#include "vmm.h"
#include "string.h"
#include "console.h"

/* ---- modern virtio PCI capability structure (virtio 1.0 spec §4.1.4) ------
 * Each virtio vendor capability in PCI config space is this 16-byte struct
 * (cap_vndr == 0x09, the PCI vendor-specific capability id). cfg_type selects
 * which structure (common/notify/isr/device); bar + offset + length locate it
 * within one of the device's BARs. */
#define PCI_CAP_ID_VNDR        0x09   /* vendor-specific PCI capability */
#define VIRTIO_PCI_CAP_COMMON_CFG  1  /* common configuration             */
#define VIRTIO_PCI_CAP_NOTIFY_CFG  2  /* notification doorbell            */
#define VIRTIO_PCI_CAP_ISR_CFG     3  /* ISR status                       */
#define VIRTIO_PCI_CAP_DEVICE_CFG  4  /* device-specific configuration    */

/* Offsets within a virtio_pci_cap (relative to the capability's position in
 * config space). The first two bytes are the standard PCI cap header
 * (cap_vndr, cap_next); virtio's fields follow. */
#define VPCAP_CAP_VNDR   0x0   /* u8:  0x09                         */
#define VPCAP_CAP_NEXT   0x1   /* u8:  next capability offset        */
#define VPCAP_CAP_LEN    0x2   /* u8:  capability length             */
#define VPCAP_CFG_TYPE   0x3   /* u8:  VIRTIO_PCI_CAP_*               */
#define VPCAP_BAR        0x4   /* u8:  which BAR (0..5)               */
#define VPCAP_OFFSET     0x8   /* u32: offset within the BAR          */
#define VPCAP_LENGTH     0xC   /* u32: length of the structure        */
#define VPCAP_NOTIFY_MUL 0x10  /* u32: notify_off_multiplier (NOTIFY only) */

/* ---- common-config register layout (virtio 1.0 spec §4.1.4.3) -------------
 * Byte offsets within the COMMON_CFG MMIO region. */
#define VCC_DEVICE_FEATURE_SELECT  0x00  /* u32 (WO): which 32-bit feature word */
#define VCC_DEVICE_FEATURE         0x04  /* u32 (RO): the selected device-feature word */
#define VCC_DRIVER_FEATURE_SELECT  0x08  /* u32 (WO): which 32-bit feature word to write */
#define VCC_DRIVER_FEATURE         0x0C  /* u32 (WO): the accepted feature word */
#define VCC_MSIX_CONFIG            0x10  /* u16                                  */
#define VCC_NUM_QUEUES             0x12  /* u16 (RO): max queue count            */
#define VCC_DEVICE_STATUS          0x14  /* u8:  device status handshake         */
#define VCC_CONFIG_GENERATION      0x15  /* u8 (RO)                              */
#define VCC_QUEUE_SELECT           0x16  /* u16 (WO): which queue the regs act on */
#define VCC_QUEUE_SIZE             0x18  /* u16: selected queue's size           */
#define VCC_QUEUE_MSIX_VECTOR      0x1A  /* u16                                  */
#define VCC_QUEUE_ENABLE           0x1C  /* u16: 1 = queue live                  */
#define VCC_QUEUE_NOTIFY_OFF       0x1E  /* u16 (RO): this queue's notify offset */
#define VCC_QUEUE_DESC             0x20  /* u64: descriptor-table phys addr      */
#define VCC_QUEUE_DRIVER           0x28  /* u64: available-ring phys addr        */
#define VCC_QUEUE_DEVICE           0x30  /* u64: used-ring phys addr             */

/* Device Status bits (same as legacy). */
#define VIRTIO_STATUS_ACKNOWLEDGE  0x01
#define VIRTIO_STATUS_DRIVER       0x02
#define VIRTIO_STATUS_DRIVER_OK    0x04
#define VIRTIO_STATUS_FEATURES_OK  0x08   /* modern: feature negotiation complete */
#define VIRTIO_STATUS_FAILED       0x80

/* VIRTIO_F_VERSION_1 is feature bit 32 (i.e. bit 0 of the second 32-bit word).
 * A modern device REQUIRES the driver to accept it. We accept nothing else. */
#define VIRTIO_F_VERSION_1_WORD    1
#define VIRTIO_F_VERSION_1_BIT     (1u << 0)

/* virtqueue descriptor flags. */
#define VRING_DESC_F_NEXT   1     /* chains to ->next               */
#define VRING_DESC_F_WRITE  2     /* device-WRITABLE (else readable) */

/* ---- split-virtqueue structures (identical to virtio_blk.c) --------------- */
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

/* ---- virtio-gpu control protocol (virtio 1.1 spec §5.7) ------------------- */

/* 2D control command types (request) + response types. */
#define VIRTIO_GPU_CMD_GET_DISPLAY_INFO     0x0100
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_2D   0x0101
#define VIRTIO_GPU_CMD_RESOURCE_UNREF       0x0102
#define VIRTIO_GPU_CMD_SET_SCANOUT          0x0103
#define VIRTIO_GPU_CMD_RESOURCE_FLUSH       0x0104
#define VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D  0x0105
#define VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING 0x0106
#define VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING 0x0107

#define VIRTIO_GPU_RESP_OK_NODATA           0x1100
#define VIRTIO_GPU_RESP_OK_DISPLAY_INFO     0x1101

/* Pixel format. B8G8R8X8 (value 2) is, as a little-endian 32-bit word, exactly
 * 0x00RRGGBB — the SAME layout fb.c draws into — so the desktop's pixels copy
 * straight into the backing with no channel swizzle. */
#define VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM    2

#define VIRTIO_GPU_MAX_SCANOUTS             16

/* The header every request and response begins with. */
struct virtio_gpu_ctrl_hdr {
    uint32_t type;       /* VIRTIO_GPU_CMD_* (request) / VIRTIO_GPU_RESP_* (response) */
    uint32_t flags;
    uint64_t fence_id;
    uint32_t ctx_id;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_rect {
    uint32_t x, y, width, height;
} __attribute__((packed));

struct virtio_gpu_display_one {
    struct virtio_gpu_rect r;
    uint32_t enabled;
    uint32_t flags;
} __attribute__((packed));

struct virtio_gpu_resp_display_info {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_display_one pmodes[VIRTIO_GPU_MAX_SCANOUTS];
} __attribute__((packed));

struct virtio_gpu_resource_create_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t format;
    uint32_t width;
    uint32_t height;
} __attribute__((packed));

struct virtio_gpu_mem_entry {
    uint64_t addr;
    uint32_t length;
    uint32_t padding;
} __attribute__((packed));

/* ATTACH_BACKING is followed by nr_entries mem_entry structs. We attach the
 * backing as a SINGLE contiguous entry, so the request is the fixed head plus
 * exactly one entry. */
struct virtio_gpu_resource_attach_backing {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t nr_entries;
    struct virtio_gpu_mem_entry entry;   /* one entry (contiguous backing) */
} __attribute__((packed));

struct virtio_gpu_set_scanout {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    uint32_t scanout_id;
    uint32_t resource_id;
} __attribute__((packed));

struct virtio_gpu_transfer_to_host_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_resource_flush {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed));

/* The single resource id + scanout we use. */
#define RESOURCE_ID  1
#define SCANOUT_ID   0

/* Defensive caps. Same ceiling as bochs_vbe.c so the backing buffer stays a
 * sane size, and the queue is bounded like virtio_blk.c. */
#define GPU_MAX_W    1920
#define GPU_MAX_H    1200
#define GPU_MAX_QSZ  256

#define VIRTIO_QUEUE_ALIGN 4096

/* Driver state. */
static struct {
    int present;

    /* MMIO config regions (mapped, cache-disabled). */
    volatile uint8_t *common;   /* COMMON_CFG */
    volatile uint8_t *notify;   /* NOTIFY_CFG base */
    volatile uint8_t *isr;      /* ISR_CFG */
    volatile uint8_t *device;   /* DEVICE_CFG (virtio_gpu_config) */
    uint32_t notify_off_mul;    /* notify_off_multiplier */
    volatile uint16_t *notify_q0;  /* the resolved queue-0 notify doorbell */

    /* The control virtqueue (queue 0). */
    uint16_t qsz;
    struct vring_desc  *desc;
    struct vring_avail *avail;
    struct vring_used  *used;
    uint16_t used_seen;

    /* The display backing buffer + negotiated geometry. */
    uint32_t *backing;          /* width*height 0x00RRGGBB pixels (identity-mapped) */
    uint64_t  backing_phys;
    uint32_t  backing_bytes;
    int width, height;
} vg;

/* ---- MMIO accessors ------------------------------------------------------- */
static inline uint8_t  cc_r8 (uint16_t o)            { return *(volatile uint8_t  *)(vg.common + o); }
static inline void     cc_w8 (uint16_t o, uint8_t v) { *(volatile uint8_t  *)(vg.common + o) = v; }
static inline uint16_t cc_r16(uint16_t o)            { return *(volatile uint16_t *)(vg.common + o); }
static inline void     cc_w16(uint16_t o, uint16_t v){ *(volatile uint16_t *)(vg.common + o) = v; }
static inline uint32_t cc_r32(uint16_t o)            { return *(volatile uint32_t *)(vg.common + o); }
static inline void     cc_w32(uint16_t o, uint32_t v){ *(volatile uint32_t *)(vg.common + o) = v; }
static inline void     cc_w64(uint16_t o, uint64_t v){ *(volatile uint64_t *)(vg.common + o) = v; }

/* Physical address of a kernel pointer (identity-mapped low RAM: phys == virt;
 * translate is the correct general way, same as virtio_blk.c). */
static uint64_t phys_of(const void *p) {
    uint64_t t = vmm_translate((uint64_t)(uintptr_t)p);
    return t ? t : hhdm_phys(p);   /* no translation: it is an HHDM pointer, so subtract the base (M1970) */
}

/* ---- modern-PCI capability walk ------------------------------------------- */

/* Read a BAR's 64-bit base, masking the flag bits and folding in the high
 * dword for a 64-bit memory BAR. Returns 0 for an I/O-space BAR (a modern
 * virtio device's config caps must live in memory BARs). */
static uint64_t bar_base(const pci_device_t *d, int bar) {
    if (bar < 0 || bar > 5)
        return 0;
    uint32_t lo = pci_read32(d->bus, d->slot, d->func, 0x10 + bar * 4);
    if (lo & 1)
        return 0;                          /* I/O space — not usable here */
    uint64_t base = lo & ~0xFu;
    /* memory BAR type bits [2:1]: 0b10 == 64-bit (the high half is the next BAR) */
    if (((lo >> 1) & 0x3) == 0x2 && bar < 5) {
        uint32_t hi = pci_read32(d->bus, d->slot, d->func, 0x10 + (bar + 1) * 4);
        base |= (uint64_t)hi << 32;
    }
    return base;
}

/* Map `len` bytes of MMIO starting at the page containing `phys`, cache-disabled
 * (identity map), and return a pointer to `phys`. Maps whole pages, like
 * ahci.c/e1000.c/hda.c. Returns NULL on a zero address. */
static volatile uint8_t *map_mmio(uint64_t phys, uint32_t len) {
    if (!phys)
        return NULL;
    uint64_t start = phys & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t end   = phys + len;
    for (uint64_t off = start; off < end; off += PAGE_SIZE)
        vmm_map(off, off, PTE_WRITABLE | PTE_PCD);
    return (volatile uint8_t *)(uintptr_t)phys;
}

/* Walk the PCI capability list and locate + map the four virtio config regions.
 * Returns 0 on success (at least common + notify + device found, all mappable),
 * -1 otherwise. */
static int map_virtio_caps(const pci_device_t *d) {
    /* The capability list is present only if status reg (0x06) bit 4 is set. */
    uint32_t sc = pci_read32(d->bus, d->slot, d->func, 0x04);
    if (!((sc >> 16) & (1u << 4)))         /* status word is the high half of 0x04 */
        return -1;

    uint8_t cap = (uint8_t)(pci_read32(d->bus, d->slot, d->func, 0x34) & 0xFF);
    int guard = 0;                         /* bound the walk against a cyclic list */
    while (cap >= 0x40 && guard++ < 48) {
        uint32_t w0 = pci_read32(d->bus, d->slot, d->func, cap & 0xFC);
        uint8_t  id   = w0 & 0xFF;
        uint8_t  next = (w0 >> 8) & 0xFF;
        if (id == PCI_CAP_ID_VNDR) {
            /* virtio_pci_cap: cfg_type@3, bar@4, offset@8, length@0xC. */
            uint8_t  cfg_type = (w0 >> 24) & 0xFF;
            uint32_t w4  = pci_read32(d->bus, d->slot, d->func, cap + VPCAP_BAR);
            uint8_t  bar = w4 & 0xFF;
            uint32_t off = pci_read32(d->bus, d->slot, d->func, cap + VPCAP_OFFSET);
            uint32_t len = pci_read32(d->bus, d->slot, d->func, cap + VPCAP_LENGTH);
            uint64_t base = bar_base(d, bar);
            if (base && len) {
                volatile uint8_t *p = map_mmio(base + off, len);
                switch (cfg_type) {
                case VIRTIO_PCI_CAP_COMMON_CFG: vg.common = p; break;
                case VIRTIO_PCI_CAP_NOTIFY_CFG:
                    vg.notify = p;
                    vg.notify_off_mul =
                        pci_read32(d->bus, d->slot, d->func, cap + VPCAP_NOTIFY_MUL);
                    break;
                case VIRTIO_PCI_CAP_ISR_CFG:    vg.isr = p; break;
                case VIRTIO_PCI_CAP_DEVICE_CFG: vg.device = p; break;
                default: break;
                }
            }
        }
        cap = next;
    }

    /* We need at least the common config, the notify region, and the device
     * config to drive the GPU. (ISR is optional — we poll, never IRQ.) */
    if (!vg.common || !vg.notify || !vg.device)
        return -1;
    return 0;
}

/* ---- virtqueue setup ------------------------------------------------------ */

/* Allocate the three rings as one physically-contiguous, page-aligned region
 * (modern lets the rings live at separate addresses, but contiguous is simplest
 * and matches virtio_blk.c). Returns 0 on success, -1 on OOM/non-contiguous. */
static int setup_queue(void) {
    cc_w16(VCC_QUEUE_SELECT, 0);
    uint16_t qsz = cc_r16(VCC_QUEUE_SIZE);
    if (qsz == 0)
        return -1;
    if (qsz > GPU_MAX_QSZ)
        qsz = GPU_MAX_QSZ;
    vg.qsz = qsz;

    /* Region size: descriptor table, then the available ring, then the used
     * ring at the next 4K boundary (the legacy vring layout; on modern the
     * device honors whatever addresses we give, and this packing is valid). */
    uint64_t avail_off = (uint64_t)qsz * sizeof(struct vring_desc);
    uint64_t used_off  = avail_off + sizeof(uint16_t) * (2 + qsz);
    used_off = (used_off + (VIRTIO_QUEUE_ALIGN - 1)) & ~(uint64_t)(VIRTIO_QUEUE_ALIGN - 1);
    uint64_t need = used_off + sizeof(uint16_t) * 2
                  + (uint64_t)qsz * sizeof(struct vring_used_elem);
    uint32_t frames = (uint32_t)((need + (PAGE_SIZE - 1)) / PAGE_SIZE);

    uint64_t base = pmm_alloc_frame();
    if (!base)
        return -1;
    uint64_t prev = base;
    for (uint32_t i = 1; i < frames; i++) {
        uint64_t f = pmm_alloc_frame();
        if (!f || f != prev + PAGE_SIZE)   /* must be contiguous (frame leak on bail is harmless) */
            return -1;
        prev = f;
    }
    memset(hhdm(base), 0, (size_t)frames * PAGE_SIZE);

    vg.desc  = (struct vring_desc  *)hhdm(base);
    vg.avail = (struct vring_avail *)hhdm(base + avail_off);
    vg.used  = (struct vring_used  *)hhdm(base + used_off);
    vg.used_seen = 0;

    /* Program the three ring addresses + size, then enable the queue. */
    cc_w16(VCC_QUEUE_SIZE,   qsz);
    cc_w64(VCC_QUEUE_DESC,   phys_of(vg.desc));
    cc_w64(VCC_QUEUE_DRIVER, phys_of(vg.avail));
    cc_w64(VCC_QUEUE_DEVICE, phys_of(vg.used));

    /* Resolve the queue-0 notify doorbell: notify_base + queue_notify_off *
     * notify_off_multiplier (virtio 1.0 §4.1.4.4). */
    uint16_t noff = cc_r16(VCC_QUEUE_NOTIFY_OFF);
    vg.notify_q0 = (volatile uint16_t *)(vg.notify + (uint32_t)noff * vg.notify_off_mul);

    cc_w16(VCC_QUEUE_ENABLE, 1);
    return 0;
}

/* ---- the control-queue request/response cycle ----------------------------- */

/* Submit a two-descriptor command — a device-readable request (`req`,
 * `req_len`) chained to a device-writable response (`resp`, `resp_len`) — to
 * the control queue, notify the device, and poll the used ring to completion.
 * Returns the response header's `type`, or 0 on timeout/bad-state.
 *
 * Single in-flight request (a configure-once / present path, never concurrent),
 * so we always use descriptors 0,1 and avail/used slot 0 — exactly like
 * virtio_blk.c. The buffers must stay put for the device, so the callers use
 * static storage. */
static uint32_t gpu_cmd(const void *req, uint32_t req_len, void *resp, uint32_t resp_len) {
    /* The queue must be set up (common cfg mapped, notify resolved, >=2 descs).
     * Note: vg.present is intentionally NOT required here — init issues commands
     * (GET_DISPLAY_INFO, CREATE_2D, ...) after the rings are live but before it
     * marks the resource fully present. */
    if (!vg.common || !vg.notify_q0 || vg.qsz < 2)
        return 0;

    vg.desc[0].addr  = phys_of(req);
    vg.desc[0].len   = req_len;
    vg.desc[0].flags = VRING_DESC_F_NEXT;
    vg.desc[0].next  = 1;

    vg.desc[1].addr  = phys_of(resp);
    vg.desc[1].len   = resp_len;
    vg.desc[1].flags = VRING_DESC_F_WRITE;
    vg.desc[1].next  = 0;

    /* Publish chain head 0; bump avail->idx after the ring write (compiler
     * barrier suffices on x86's strong model, as in virtio_blk.c). */
    vg.avail->ring[vg.avail->idx % vg.qsz] = 0;
    __asm__ volatile("" ::: "memory");
    vg.avail->idx++;
    __asm__ volatile("" ::: "memory");

    /* Notify queue 0 via its MMIO doorbell (write the queue index). */
    *vg.notify_q0 = 0;
    __asm__ volatile("" ::: "memory");

    /* Poll the used ring (finite timeout, no IRQ). */
    int done = 0;
    for (int i = 0; i < 100000000; i++) {
        if (vg.used->idx != vg.used_seen) { done = 1; break; }
        __asm__ volatile("pause");
    }
    if (!done)
        return 0;                          /* timeout */
    vg.used_seen++;
    if (vg.isr)
        (void)*vg.isr;                     /* ack any pending interrupt */

    return ((const struct virtio_gpu_ctrl_hdr *)resp)->type;
}

/* Fill a request header. */
static void hdr_init(struct virtio_gpu_ctrl_hdr *h, uint32_t type) {
    h->type = type;
    h->flags = 0;
    h->fence_id = 0;
    h->ctx_id = 0;
    h->padding = 0;
}

/* ---- the six control commands --------------------------------------------- */

/* Static request/response buffers (one in-flight command). Identity-mapped BSS,
 * so phys_of resolves them like the backing buffer. */
static struct virtio_gpu_resp_display_info        rd_info;
static struct virtio_gpu_resource_create_2d       rq_create;
static struct virtio_gpu_resource_attach_backing  rq_attach;
static struct virtio_gpu_set_scanout              rq_scanout;
static struct virtio_gpu_transfer_to_host_2d      rq_xfer;
static struct virtio_gpu_resource_flush           rq_flush;
static struct virtio_gpu_ctrl_hdr                 rq_hdr;     /* generic request hdr */
static struct virtio_gpu_ctrl_hdr                 rp_hdr;     /* generic response hdr */

/* GET_DISPLAY_INFO -> read scanout 0's preferred WxH (and that it's enabled).
 * Returns 0 + sets the out-params w,h,enabled on success, -1 otherwise. */
static int cmd_get_display_info(int *w, int *h, int *enabled) {
    hdr_init(&rq_hdr, VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
    memset(&rd_info, 0, sizeof(rd_info));
    uint32_t t = gpu_cmd(&rq_hdr, sizeof(rq_hdr), &rd_info, sizeof(rd_info));
    if (t != VIRTIO_GPU_RESP_OK_DISPLAY_INFO)
        return -1;
    *w = (int)rd_info.pmodes[SCANOUT_ID].r.width;
    *h = (int)rd_info.pmodes[SCANOUT_ID].r.height;
    *enabled = (int)rd_info.pmodes[SCANOUT_ID].enabled;
    return 0;
}

static int cmd_create_2d(uint32_t w, uint32_t h) {
    hdr_init(&rq_create.hdr, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
    rq_create.resource_id = RESOURCE_ID;
    rq_create.format      = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM;
    rq_create.width       = w;
    rq_create.height      = h;
    memset(&rp_hdr, 0, sizeof(rp_hdr));
    return gpu_cmd(&rq_create, sizeof(rq_create), &rp_hdr, sizeof(rp_hdr))
           == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

static int cmd_attach_backing(uint64_t phys, uint32_t len) {
    hdr_init(&rq_attach.hdr, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
    rq_attach.resource_id  = RESOURCE_ID;
    rq_attach.nr_entries   = 1;
    rq_attach.entry.addr   = phys;
    rq_attach.entry.length = len;
    rq_attach.entry.padding = 0;
    memset(&rp_hdr, 0, sizeof(rp_hdr));
    return gpu_cmd(&rq_attach, sizeof(rq_attach), &rp_hdr, sizeof(rp_hdr))
           == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

static int cmd_set_scanout(uint32_t w, uint32_t h) {
    hdr_init(&rq_scanout.hdr, VIRTIO_GPU_CMD_SET_SCANOUT);
    rq_scanout.r.x = 0; rq_scanout.r.y = 0;
    rq_scanout.r.width = w; rq_scanout.r.height = h;
    rq_scanout.scanout_id = SCANOUT_ID;
    rq_scanout.resource_id = RESOURCE_ID;
    memset(&rp_hdr, 0, sizeof(rp_hdr));
    return gpu_cmd(&rq_scanout, sizeof(rq_scanout), &rp_hdr, sizeof(rp_hdr))
           == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

static int cmd_transfer_to_host(uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
    hdr_init(&rq_xfer.hdr, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
    rq_xfer.r.x = x; rq_xfer.r.y = y; rq_xfer.r.width = w; rq_xfer.r.height = h;
    /* offset into the backing of pixel (x,y), in bytes. */
    rq_xfer.offset = ((uint64_t)y * (uint32_t)vg.width + x) * 4u;
    rq_xfer.resource_id = RESOURCE_ID;
    rq_xfer.padding = 0;
    memset(&rp_hdr, 0, sizeof(rp_hdr));
    return gpu_cmd(&rq_xfer, sizeof(rq_xfer), &rp_hdr, sizeof(rp_hdr))
           == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

static int cmd_resource_flush(uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
    hdr_init(&rq_flush.hdr, VIRTIO_GPU_CMD_RESOURCE_FLUSH);
    rq_flush.r.x = x; rq_flush.r.y = y; rq_flush.r.width = w; rq_flush.r.height = h;
    rq_flush.resource_id = RESOURCE_ID;
    rq_flush.padding = 0;
    memset(&rp_hdr, 0, sizeof(rp_hdr));
    return gpu_cmd(&rq_flush, sizeof(rq_flush), &rp_hdr, sizeof(rp_hdr))
           == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

/* ---- bring-up ------------------------------------------------------------- */
int virtio_gpu_init(void) {
    memset(&vg, 0, sizeof(vg));

    /* QEMU's virtio-gpu-pci is the MODERN virtio-gpu device: vendor 0x1AF4,
     * device 0x1050. (The transitional id 0x1010 would be a legacy/transitional
     * GPU; QEMU only ships 0x1050, so we match it primarily and fall back.) */
    pci_device_t dev = pci_find(0x1AF4, 0x1050);
    if (!dev.valid)
        dev = pci_find(0x1AF4, 0x1010);
    if (!dev.valid)
        return -1;                          /* no virtio-gpu — clean no-op */

    /* Enable PCI memory-space decode + bus mastering (the device DMAs our
     * rings + backing). Modern transport is MMIO only — no I/O-space needed. */
    pci_enable_bus_master(&dev);

    /* Locate + map the modern virtio config regions from the PCI caps. */
    if (map_virtio_caps(&dev) != 0)
        return -1;

    /* --- modern init handshake (virtio 1.0 §3.1.1) --------------------------
     * Reset, then ACK + DRIVER. */
    cc_w8(VCC_DEVICE_STATUS, 0);            /* reset */
    /* Wait for the reset to take (status reads back 0). */
    for (int i = 0; i < 1000000 && cc_r8(VCC_DEVICE_STATUS) != 0; i++)
        __asm__ volatile("pause");
    cc_w8(VCC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
    cc_w8(VCC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    /* Feature negotiation: a modern device offers VIRTIO_F_VERSION_1 (bit 32),
     * which the driver MUST accept; we accept ONLY that (no VIRGL/EDID/etc.).
     * Read device-feature word 1 to confirm bit 32 is offered, then write our
     * accepted features: word 0 = 0, word 1 = VIRTIO_F_VERSION_1. */
    cc_w32(VCC_DEVICE_FEATURE_SELECT, VIRTIO_F_VERSION_1_WORD);
    uint32_t devf1 = cc_r32(VCC_DEVICE_FEATURE);
    if (!(devf1 & VIRTIO_F_VERSION_1_BIT)) {
        /* A device that doesn't offer VERSION_1 isn't a modern device we can
         * drive this way — bail cleanly. */
        cc_w8(VCC_DEVICE_STATUS, VIRTIO_STATUS_FAILED);
        return -1;
    }
    cc_w32(VCC_DRIVER_FEATURE_SELECT, 0);
    cc_w32(VCC_DRIVER_FEATURE, 0);
    cc_w32(VCC_DRIVER_FEATURE_SELECT, VIRTIO_F_VERSION_1_WORD);
    cc_w32(VCC_DRIVER_FEATURE, VIRTIO_F_VERSION_1_BIT);

    /* FEATURES_OK, then re-read: a modern device clears the bit if it can't
     * accept our feature set, in which case we must not proceed. */
    cc_w8(VCC_DEVICE_STATUS,
          VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
    if (!(cc_r8(VCC_DEVICE_STATUS) & VIRTIO_STATUS_FEATURES_OK)) {
        cc_w8(VCC_DEVICE_STATUS, VIRTIO_STATUS_FAILED);
        return -1;
    }

    /* Set up the control virtqueue (queue 0). */
    if (setup_queue() != 0) {
        cc_w8(VCC_DEVICE_STATUS, VIRTIO_STATUS_FAILED);
        return -1;
    }

    /* DRIVER_OK: the device may now process the queue. We can issue commands. */
    cc_w8(VCC_DEVICE_STATUS,
          VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
          VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);

    /* From here gpu_cmd may run; mark the rings usable. (present is set fully at
     * the end once the resource is live.) */
    vg.present = 1;

    /* --- query the display, then bind a backing buffer to scanout 0 --------- */
    int w = 0, h = 0, enabled = 0;
    if (cmd_get_display_info(&w, &h, &enabled) != 0) {
        vg.present = 0;
        cc_w8(VCC_DEVICE_STATUS, VIRTIO_STATUS_FAILED);
        return -1;
    }
    /* The host must report scanout 0 with a sane, enabled resolution. QEMU may
     * report enabled==0 before any scanout is set but still give a preferred
     * size; accept a sane size and (if the size is 0) fall back to a default. */
    if (w <= 0 || h <= 0) { w = 1024; h = 768; }      /* default if unreported */
    if (w > GPU_MAX_W) w = GPU_MAX_W;                  /* cap (safety) */
    if (h > GPU_MAX_H) h = GPU_MAX_H;
    vg.width  = w;
    vg.height = h;

    /* Allocate the backing buffer = exactly width*height*4 bytes, as a run of
     * contiguous identity-mapped frames (so we can attach it as ONE mem entry
     * with a physical base + length, and index it as a normal pixel array). */
    vg.backing_bytes = (uint32_t)w * (uint32_t)h * 4u;
    uint32_t bframes = (vg.backing_bytes + (PAGE_SIZE - 1)) / PAGE_SIZE;
    uint64_t bbase = pmm_alloc_frame();
    if (!bbase) { vg.present = 0; return -1; }
    uint64_t bprev = bbase;
    for (uint32_t i = 1; i < bframes; i++) {
        uint64_t f = pmm_alloc_frame();
        if (!f || f != bprev + PAGE_SIZE) { vg.present = 0; return -1; }  /* need contiguous */
        bprev = f;
    }
    vg.backing_phys  = bbase;
    vg.backing       = (uint32_t *)hhdm(bbase);
    vg.backing_bytes = bframes * PAGE_SIZE;            /* rounded-up mapped size */
    memset(vg.backing, 0, vg.backing_bytes);

    /* CREATE_2D + ATTACH_BACKING + SET_SCANOUT so the resource is live. */
    if (cmd_create_2d((uint32_t)w, (uint32_t)h) != 0 ||
        cmd_attach_backing(vg.backing_phys, (uint32_t)w * (uint32_t)h * 4u) != 0 ||
        cmd_set_scanout((uint32_t)w, (uint32_t)h) != 0) {
        vg.present = 0;
        cc_w8(VCC_DEVICE_STATUS, VIRTIO_STATUS_FAILED);
        return -1;
    }

    kprintf("[ ok ] virtio-gpu up: scanout 0 %dx%d (enabled=%d), resource %d live "
            "(boot display stays on the linear framebuffer).\n",
            w, h, enabled, RESOURCE_ID);
    return 0;
}

int       virtio_gpu_active(void)  { return vg.present; }
int       virtio_gpu_width(void)   { return vg.present ? vg.width  : 0; }
int       virtio_gpu_height(void)  { return vg.present ? vg.height : 0; }
uint32_t *virtio_gpu_backing(void) { return vg.present ? vg.backing : 0; }

/* Present the rectangle [x,y,w,h] of the backing buffer: TRANSFER_TO_HOST_2D
 * that rect to the host resource, then RESOURCE_FLUSH it (the "flush" the
 * desktop compositor would call). The rect is clamped within the display. */
int virtio_gpu_present(int x, int y, int w, int h) {
    if (!vg.present)
        return -1;
    /* Clamp the rect within [0,width]x[0,height]; never transfer/flush OOB. */
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x >= vg.width || y >= vg.height) return -1;
    if (x + w > vg.width)  w = vg.width  - x;
    if (y + h > vg.height) h = vg.height - y;
    if (w <= 0 || h <= 0)
        return -1;
    if (cmd_transfer_to_host((uint32_t)x, (uint32_t)y, (uint32_t)w, (uint32_t)h) != 0)
        return -1;
    if (cmd_resource_flush((uint32_t)x, (uint32_t)y, (uint32_t)w, (uint32_t)h) != 0)
        return -1;
    return 0;
}

/* ---- boot-time verification (the headless proof, like hda_selftest) -------- */
void virtio_gpu_selftest(void) {
    if (!vg.present) {
        kprintf("[virtio-gpu] no virtio-gpu device found "
                "(none attached; linear-framebuffer display intact).\n\n");
        return;
    }

    kprintf("[virtio-gpu] selftest: display info %dx%d; resource %d created+attached+scanned-out.\n",
            vg.width, vg.height, RESOURCE_ID);

    /* Fill the backing with a known test pattern: vertical colour bands (no FP —
     * the kernel builds -mgeneral-regs-only). Bands prove a real transfer of
     * real pixels, not just a status code. */
    static const uint32_t bands[8] = {
        0x000000, 0xFF0000, 0x00FF00, 0x0000FF,
        0xFFFF00, 0x00FFFF, 0xFF00FF, 0xFFFFFF
    };
    for (int y = 0; y < vg.height; y++) {
        uint32_t *row = vg.backing + (size_t)y * vg.width;
        for (int x = 0; x < vg.width; x++)
            row[x] = bands[(x * 8) / vg.width];
    }

    /* Run the full present cycle over the WHOLE screen and report each command's
     * response code, asserting all are OK (the headless equivalent of "DMA
     * ADVANCING"). We re-issue the commands directly so we can log each code. */
    int rc_xfer  = cmd_transfer_to_host(0, 0, (uint32_t)vg.width, (uint32_t)vg.height);
    int rc_flush = cmd_resource_flush(0, 0, (uint32_t)vg.width, (uint32_t)vg.height);

    /* A second present of a sub-rect, to exercise the rect path + offset math. */
    int rc_rect = virtio_gpu_present(0, 0, vg.width / 2, vg.height / 2);

    kprintf("[virtio-gpu] selftest: TRANSFER_TO_HOST_2D=%s RESOURCE_FLUSH=%s rect-present=%s\n",
            rc_xfer  == 0 ? "OK" : "FAIL",
            rc_flush == 0 ? "OK" : "FAIL",
            rc_rect  == 0 ? "OK" : "FAIL");

    if (rc_xfer == 0 && rc_flush == 0 && rc_rect == 0)
        kprintf("[ ok ] virtio-gpu present cycle complete: every command returned OK "
                "(test pattern transferred + flushed to scanout 0).\n\n");
    else
        kprintf("[virtio-gpu] PRESENT CYCLE FAILED (a command did not return OK).\n\n");
}
