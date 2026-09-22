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
#include "task.h"   /* task_yield/task_current_id for the queue lock (M2348) */

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

/* 3D control commands (M2346). The 2D set above is all a framebuffer needs;
 * these are what a GL driver needs, and nothing in the tree had ever asked the
 * device whether it offered them. */
#define VIRTIO_GPU_CMD_GET_CAPSET_INFO      0x0108
#define VIRTIO_GPU_CMD_GET_CAPSET           0x0109
#define VIRTIO_GPU_CMD_CTX_CREATE           0x0200
#define VIRTIO_GPU_CMD_CTX_DESTROY          0x0201
#define VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE  0x0202
#define VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE  0x0203
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_3D   0x0204
#define VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D  0x0205
#define VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D 0x0206
#define VIRTIO_GPU_CMD_SUBMIT_3D            0x0207

#define VIRTIO_GPU_RESP_OK_NODATA           0x1100
#define VIRTIO_GPU_RESP_OK_DISPLAY_INFO     0x1101
#define VIRTIO_GPU_RESP_OK_CAPSET_INFO      0x1102
#define VIRTIO_GPU_RESP_OK_CAPSET           0x1103

/* THE FEATURE BIT THAT WAS BEING REFUSED ON PURPOSE (M2346). The driver's own
 * comment said "we accept ONLY that (no VIRGL/EDID/etc.)", which was the right
 * call for a 2D framebuffer and is the wall for anything that wants a GPU. */
#define VIRTIO_GPU_F_VIRGL                  0   /* device offers 3D / virgl   */
#define VIRTIO_GPU_F_EDID                   1
#define VIRTIO_GPU_F_RESOURCE_UUID          2
#define VIRTIO_GPU_F_RESOURCE_BLOB          3
#define VIRTIO_GPU_F_CONTEXT_INIT           4

/* Capsets. virglrenderer publishes its capabilities as an opaque blob the
 * guest's Mesa parses; the kernel only has to fetch it verbatim. */
#define VIRTIO_GPU_CAPSET_VIRGL             1
#define VIRTIO_GPU_CAPSET_VIRGL2            2

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

struct virtio_gpu_get_capset_info {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t capset_index;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_resp_capset_info {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t capset_id;
    uint32_t capset_max_version;
    uint32_t capset_max_size;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_get_capset {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t capset_id;
    uint32_t capset_version;
} __attribute__((packed));

/* ---- the 3D structs (M2348) -----------------------------------------------
 *
 * A `box` is a 3D region; 2D transfers use d=1. Note the ORDER of the trailing
 * fields in a 3D transfer -- offset, resource_id, level, stride, layer_stride
 * -- because getting resource_id and level the wrong way round produces a
 * command the host accepts and then applies to mip level N of resource 0,
 * which draws nothing and reports success. */
struct virtio_gpu_box {
    uint32_t x, y, z, w, h, d;
} __attribute__((packed));

struct virtio_gpu_ctx_create {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t nlen;
    uint32_t context_init;
    char debug_name[64];
} __attribute__((packed));

struct virtio_gpu_ctx_resource {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_resource_create_3d {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t target;
    uint32_t format;
    uint32_t bind;
    uint32_t width;
    uint32_t height;
    uint32_t depth;
    uint32_t array_size;
    uint32_t last_level;
    uint32_t nr_samples;
    uint32_t flags;
    uint32_t padding;
} __attribute__((packed));

struct virtio_gpu_transfer_host_3d {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_box box;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t level;
    uint32_t stride;
    uint32_t layer_stride;
} __attribute__((packed));

/* SUBMIT_3D is the header, a size, then `size` bytes of virgl command stream
 * IMMEDIATELY FOLLOWING. The command data is Mesa's on one end and
 * virglrenderer's on the other and is opaque here by design -- a kernel that
 * parsed it would be inventing a third opinion about GL. */
#define GPU_CMDBUF_MAX (1024u * 1024u)
struct virtio_gpu_cmd_submit {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t size;
    uint32_t padding;
} __attribute__((packed));

/* GET_CAPSET's reply is the header followed by `capset_max_size` opaque bytes.
 * The device decides how many; the guest must provide room for the number it
 * was told at GET_CAPSET_INFO time. virgl2 reports 1384 here, so 4 KiB of
 * slack is a whole capset's worth of headroom and still one page. */
#define GPU_CAPSET_MAX 4096
struct virtio_gpu_resp_capset {
    struct virtio_gpu_ctrl_hdr hdr;
    uint8_t capset_data[GPU_CAPSET_MAX];
} __attribute__((packed));

/* The device-specific config region (virtio 1.1 §5.7.4). `num_capsets` is the
 * only field here that has ever mattered to us and it was never read. */
struct virtio_gpu_config {
    uint32_t events_read;
    uint32_t events_clear;
    uint32_t num_scanouts;
    uint32_t num_capsets;
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

/* A SCATTER LIST, BECAUSE CONTIGUITY IS NOT AVAILABLE ON DEMAND (M2349).
 *
 * The single-entry form below is what the 2D scanout uses, and it is exactly
 * why the 2D scanout became unreliable: a 1280x800 backing is a thousand
 * frames and it has to be ONE unbroken physical run. That worked for a while
 * and then stopped, with nothing between the two boots but a few kilobytes of
 * new BSS moving where the PMM had reached.
 *
 * A GL driver makes this far worse. Mesa allocates vertex buffers, uniform
 * buffers, staging textures and readback surfaces continuously, at sizes it
 * chooses, for the whole life of the process -- there is no moment at which
 * asking for four megabytes of contiguous physical memory is a reasonable
 * thing to do. ATTACH_BACKING takes `nr_entries` entries precisely so a guest
 * does not have to: each entry is an (address, length) pair, and the device
 * gathers them. So allocate frames however they come, coalesce the runs that
 * happen to be adjacent, and hand over the list.
 *
 * GPU_SG_MAX 4096 entries covers a 16 MiB resource even in the worst case
 * where no two frames are adjacent, at a 64 KiB static cost. */
#define GPU_SG_MAX 4096

/* ATTACH_BACKING is followed by nr_entries mem_entry structs. */
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
/* Why init failed, for the caller to print. A pointer to a literal, so there
 * is nothing to allocate on a path that may be failing because allocation
 * failed. (M2348) */
static const char *g_vg_why;
const char *virtio_gpu_why(void) { return g_vg_why ? g_vg_why : "no reason was recorded"; }

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

    /* 3D (M2346). `virgl` is what the DEVICE offered and we accepted;
     * `ncapsets`/`capset_*` are what it then told us about its renderer. A
     * host with virgl compiled in but no GL context answers the feature bit
     * and then reports zero capsets, so these are separate facts on purpose. */
    int scanout;                /* is the 2D scanout resource live? (M2348) */
    int virgl;
    uint32_t ncapsets;
    uint32_t capset_id, capset_ver, capset_size;
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
/* MAP DEVICE MMIO IN THE SHARED HIGHER HALF, NOT IDENTITY (M2349).
 *
 * This used to identity-map the BAR -- `vmm_map(off, off, ...)` -- exactly like
 * ahci.c, e1000.c, ehci.c, svga.c and hpet.c still do. That is fine for every
 * one of those, because they are only ever touched from kernel threads. It is
 * NOT fine here, and the difference is that this driver is now reachable from
 * a SYSCALL: a GL driver in ring 3 calls an ioctl, and the ioctl rings the
 * device's notify doorbell while running on that PROCESS's CR3.
 *
 * On this host QEMU puts the device's 64-bit BAR at physical ~0xe06_00000000
 * -- about 14.4 TB, in the high PCI hole -- so the identity mapping landed in
 * PML4[28]. Read vmm_create_address_space: a new address space shares
 * PML4[256..511] BY POINTER and copies PML4[0]'s PDPT entries by value.
 * PML4[28] is in neither set. So the doorbell existed only in the kernel's
 * address space, and the first ioctl that rang it took:
 *
 *     Page Fault err=0x2  CR2=0x00000e0600007000
 *     rip=...  mov %dx,(%rax)          <- *vg.notify_q0 = 0
 *     [0] gpu_cmd_locked  [1] virtio_gpu_get_capset  [2] drm_ioctl
 *
 * Every 2D command at boot worked, because boot runs on the kernel CR3. That
 * is why this looked like a capset bug for two boots: the failing thing was
 * neither the capset nor the buffer, it was WHOSE PAGE TABLES WERE LOADED.
 *
 * The HHDM only huge-maps [0, RAM), so HHDM_BASE + a 14 TB BAR is untouched
 * address space in the higher half -- shared by pointer, therefore visible in
 * every process from the moment it is mapped. */
static volatile uint8_t *map_mmio(uint64_t phys, uint32_t len) {
    if (!phys)
        return NULL;
    uint64_t start = phys & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t end   = phys + len;
    for (uint64_t off = start; off < end; off += PAGE_SIZE)
        vmm_map((uint64_t)(uintptr_t)hhdm(off), off, PTE_WRITABLE | PTE_PCD);
    return (volatile uint8_t *)hhdm(phys);
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
/* THE CONTROL QUEUE IS NOW A SHARED RESOURCE, AND IT WAS NOT LOCKED (M2348).
 *
 * Everything above this point runs ONCE, from one thread, during boot -- which
 * is why `gpu_cmd` gets to use descriptors 0 and 1 unconditionally, and why
 * the request bodies are file-scope statics. Perfectly sound for a
 * configure-once path.
 *
 * It stops being sound the moment a GL driver is submitting command buffers:
 * Mesa submits from whatever thread the application drew on, and this OS has
 * eight cores. Two threads in `gpu_cmd` at once would write the same
 * descriptor pair, publish the same avail slot twice, and then each consume
 * one used entry for a response that belongs to the other -- the exact shape
 * of the find-then-fill class this codebase has now found eleven times. Worse,
 * the failure is silent: both callers get A response, so both succeed and one
 * of them reads the other's answer.
 *
 * So the queue gets a real lock, with the yielding-spin shape from ata.c
 * (M1911): spin briefly because most commands are quick, then yield rather
 * than burn the timeslice the holder needs to finish. */
static volatile int gq_lock;
static volatile int gq_owner = -1;
static void gq_take(void) {
    uint32_t spins = 0;
    while (__atomic_exchange_n(&gq_lock, 1, __ATOMIC_ACQUIRE)) {
        if (++spins >= 1000) { spins = 0; task_yield(); }
        else __asm__ volatile("pause");
    }
    gq_owner = task_current_id();
}
static void gq_give(void) {
    gq_owner = -1;
    __atomic_store_n(&gq_lock, 0, __ATOMIC_RELEASE);
}

static uint32_t gpu_cmd_locked(const void *req, uint32_t req_len, void *resp, uint32_t resp_len);

static uint32_t gpu_cmd(const void *req, uint32_t req_len, void *resp, uint32_t resp_len) {
    gq_take();
    uint32_t t = gpu_cmd_locked(req, req_len, resp, resp_len);
    gq_give();
    return t;
}

static uint32_t gpu_cmd_locked(const void *req, uint32_t req_len, void *resp, uint32_t resp_len) {
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

/* EVERY BUFFER THE DEVICE TOUCHES COMES FROM THE PMM, NOT FROM BSS (M2349).
 *
 * This driver's request/response buffers have always been file-scope statics,
 * with a comment explaining it: "Identity-mapped BSS, so phys_of resolves them
 * like the backing buffer." True for the small ones that were there. It stopped
 * being true the moment M2346 added a 4 KiB capset response, which landed at
 * 0xffffffff86c3ebe0 -- past the end of the kernel image -- and the first
 * GET_CAPSET took a KERNEL PAGE FAULT inside phys_of's page walk:
 *
 *     Page Fault err=0x2  CR2=0x00000e0600007000
 *     rsi=000ffffffffff000              <- a PTE address mask
 *     [0] gpu_cmd_locked  [1] gpu_cmd  [2] virtio_gpu_get_capset  [3] drm_ioctl
 *
 * A device-visible buffer needs a physical address we KNOW, not one recovered
 * by translating a kernel virtual address that may not be mapped the way the
 * translation assumes. So: one contiguous arena from the PMM, carved up for
 * the large request and response bodies. The small statics stay -- they work,
 * they are proven, and moving them would be churn -- but nothing new joins
 * them.
 *
 * `pmm_alloc_contiguous` is the right allocator and this driver was not using
 * it anywhere: the 2D backing hoped that a thousand consecutive
 * `pmm_alloc_frame()` calls would come back adjacent, which is not what that
 * function promises and is why the scanout failed with "a run of 67". */
#define GPU_DMA_FRAMES 32                 /* 128 KiB: capset response + a 4096-entry sg list */
static uint8_t  *g_dma;
static uint64_t  g_dma_phys;

static int gpu_dma_init(void) {
    if (g_dma) return 0;
    uint64_t base = pmm_alloc_contiguous(GPU_DMA_FRAMES, 1);
    if (!base) {
        kprintf("[virtio-gpu] could not reserve %d contiguous frames for a DMA arena; "
                "commands with large bodies (capset, scatter-gather attach) cannot run\n",
                GPU_DMA_FRAMES);
        return -1;
    }
    g_dma = (uint8_t *)hhdm(base);
    g_dma_phys = base;
    memset(g_dma, 0, GPU_DMA_FRAMES * PAGE_SIZE);
    return 0;
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
/* ---- 3D: what the host's renderer can do (M2346) --------------------------
 *
 * Two questions, and the whole point of asking them separately is that the
 * answers can disagree. The feature bit says the DEVICE MODEL has virgl
 * compiled in. `num_capsets` and the capset info say the RENDERER actually
 * came up -- QEMU built with virglrenderer but started without a GL context
 * offers the bit and then reports zero capsets, which is exactly the state
 * this machine was in an hour ago (no libEGL installed, so `-display
 * egl-headless` failed to create a context while the device was still there).
 * A driver that only checked the bit would have reported 3D support and then
 * failed on the first draw with nothing to point at. */
static struct virtio_gpu_get_capset_info   rq_capsinfo;
static struct virtio_gpu_resp_capset_info  rp_capsinfo;

static uint32_t cfg_num_capsets(void) {
    if (!vg.device) return 0;
    return *(volatile uint32_t *)(vg.device + __builtin_offsetof(struct virtio_gpu_config, num_capsets));
}

/* GET_CAPSET_INFO for one index -> id / max version / max size. */
static int cmd_get_capset_info(uint32_t index, uint32_t *id, uint32_t *ver, uint32_t *size) {
    hdr_init(&rq_capsinfo.hdr, VIRTIO_GPU_CMD_GET_CAPSET_INFO);
    rq_capsinfo.capset_index = index;
    rq_capsinfo.padding = 0;
    memset(&rp_capsinfo, 0, sizeof(rp_capsinfo));
    uint32_t t = gpu_cmd(&rq_capsinfo, sizeof(rq_capsinfo), &rp_capsinfo, sizeof(rp_capsinfo));
    if (t != VIRTIO_GPU_RESP_OK_CAPSET_INFO) return -1;
    *id   = rp_capsinfo.capset_id;
    *ver  = rp_capsinfo.capset_max_version;
    *size = rp_capsinfo.capset_max_size;
    return 0;
}

/* GET_CAPSET -> copy the renderer's capability blob into the caller's buffer.
 * Returns the number of bytes written, or -1.
 *
 * The blob is OPAQUE TO US ON PURPOSE. It is virglrenderer's description of
 * itself -- GL version, limits, format support -- and the only thing that
 * parses it is the guest's Mesa. A kernel that tried to interpret it would be
 * inventing a second opinion about the host's GPU; its job is to hand the
 * bytes across unmodified and to be honest about how many there were. */
/* The request head lives at arena offset 0, the response at 4 KiB. Both are
 * inside one contiguous PMM run, so their physical addresses are g_dma_phys +
 * the offset and no page walk is involved. */
#define GPU_DMA_REQ_OFF   0u
#define GPU_DMA_RESP_OFF  4096u

int virtio_gpu_get_capset(uint32_t id, uint32_t ver, void *out, uint32_t out_len) {
    if (!vg.present || !out || !out_len) return -1;
    if (gpu_dma_init() != 0) return -1;
    if (out_len > GPU_CAPSET_MAX) out_len = GPU_CAPSET_MAX;
    gq_take();
    struct virtio_gpu_get_capset  *rq = (struct virtio_gpu_get_capset *)(g_dma + GPU_DMA_REQ_OFF);
    struct virtio_gpu_resp_capset *rp = (struct virtio_gpu_resp_capset *)(g_dma + GPU_DMA_RESP_OFF);
    hdr_init(&rq->hdr, VIRTIO_GPU_CMD_GET_CAPSET);
    rq->capset_id = id;
    rq->capset_version = ver;
    memset(rp, 0, sizeof(struct virtio_gpu_ctrl_hdr) + out_len);
    /* Ask for exactly the header plus what the caller can hold: a device that
     * would write more than that must be told so by the descriptor length,
     * not discovered afterwards by a smashed buffer. */
    uint32_t t = gpu_cmd_locked(rq, (uint32_t)sizeof *rq,
                                rp, (uint32_t)sizeof(struct virtio_gpu_ctrl_hdr) + out_len);
    int rc = -1;
    if (t == VIRTIO_GPU_RESP_OK_CAPSET) { memcpy(out, rp->capset_data, out_len); rc = (int)out_len; }
    gq_give();
    return rc;
}

/* ---- the 3D commands (M2348) ----------------------------------------------
 *
 * Each is a thin, honest wrapper: fill the request, send it, return 0 only if
 * the device said OK_NODATA. No retries and no "probably fine" -- a 3D command
 * that half-worked leaves host GL state the guest thinks it set and does not
 * have, and that is not debuggable from the guest side at all.
 *
 * `hdr.ctx_id` is what makes these 3D: the same RESOURCE_UNREF is a 2D command
 * with ctx 0 and a context resource release with a real one. */
static struct virtio_gpu_ctx_create          rq_ctxc;
static struct virtio_gpu_ctx_resource        rq_ctxr;
static struct virtio_gpu_resource_create_3d  rq_c3d;
static struct virtio_gpu_transfer_host_3d    rq_x3d;
static struct virtio_gpu_ctrl_hdr            rp_3d;

static void hdr_init_ctx(struct virtio_gpu_ctrl_hdr *h, uint32_t type, uint32_t ctx) {
    hdr_init(h, type);
    h->ctx_id = ctx;
}

int virtio_gpu_ctx_create(uint32_t ctx_id, const char *name) {
    if (!virtio_gpu_has_3d()) return -1;
    hdr_init_ctx(&rq_ctxc.hdr, VIRTIO_GPU_CMD_CTX_CREATE, ctx_id);
    memset(rq_ctxc.debug_name, 0, sizeof rq_ctxc.debug_name);
    uint32_t n = 0;
    if (name) { while (name[n] && n < sizeof rq_ctxc.debug_name - 1) { rq_ctxc.debug_name[n] = name[n]; n++; } }
    rq_ctxc.nlen = n;
    rq_ctxc.context_init = 0;
    return gpu_cmd(&rq_ctxc, sizeof rq_ctxc, &rp_3d, sizeof rp_3d) == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

int virtio_gpu_ctx_destroy(uint32_t ctx_id) {
    if (!virtio_gpu_has_3d()) return -1;
    hdr_init_ctx(&rq_hdr, VIRTIO_GPU_CMD_CTX_DESTROY, ctx_id);
    return gpu_cmd(&rq_hdr, sizeof rq_hdr, &rp_3d, sizeof rp_3d) == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

int virtio_gpu_ctx_attach(uint32_t ctx_id, uint32_t res_id, int attach) {
    if (!virtio_gpu_has_3d()) return -1;
    hdr_init_ctx(&rq_ctxr.hdr, attach ? VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE
                                      : VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE, ctx_id);
    rq_ctxr.resource_id = res_id;
    rq_ctxr.padding = 0;
    return gpu_cmd(&rq_ctxr, sizeof rq_ctxr, &rp_3d, sizeof rp_3d) == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

int virtio_gpu_res_create_3d(uint32_t ctx_id, uint32_t res_id, uint32_t target, uint32_t format,
                             uint32_t bind, uint32_t w, uint32_t h, uint32_t depth,
                             uint32_t array_size, uint32_t last_level, uint32_t nr_samples,
                             uint32_t flags) {
    if (!virtio_gpu_has_3d()) return -1;
    hdr_init_ctx(&rq_c3d.hdr, VIRTIO_GPU_CMD_RESOURCE_CREATE_3D, ctx_id);
    rq_c3d.resource_id = res_id; rq_c3d.target = target; rq_c3d.format = format;
    rq_c3d.bind = bind; rq_c3d.width = w; rq_c3d.height = h; rq_c3d.depth = depth;
    rq_c3d.array_size = array_size; rq_c3d.last_level = last_level;
    rq_c3d.nr_samples = nr_samples; rq_c3d.flags = flags; rq_c3d.padding = 0;
    return gpu_cmd(&rq_c3d, sizeof rq_c3d, &rp_3d, sizeof rp_3d) == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

int virtio_gpu_res_unref(uint32_t res_id) {
    if (!vg.present) return -1;
    static struct virtio_gpu_resource_unref { struct virtio_gpu_ctrl_hdr hdr;
                                              uint32_t resource_id; uint32_t padding; } ru;
    hdr_init(&ru.hdr, VIRTIO_GPU_CMD_RESOURCE_UNREF);
    ru.resource_id = res_id; ru.padding = 0;
    return gpu_cmd(&ru, sizeof ru, &rp_3d, sizeof rp_3d) == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

/* The multi-entry request. Separate from `rq_attach` on purpose: the 2D path's
 * fixed one-entry struct is still correct for the scanout, and widening it
 * would make every 2D boot pay 64 KiB of BSS for a list it never uses. */
static struct {
    struct virtio_gpu_ctrl_hdr hdr;
    uint32_t resource_id;
    uint32_t nr_entries;
    struct virtio_gpu_mem_entry entry[GPU_SG_MAX];
} rq_attach_sg;

int virtio_gpu_attach_backing_sg(uint32_t res_id, const uint64_t *phys,
                                 const uint32_t *len, uint32_t n) {
    if (!vg.present || !phys || !len || !n || n > GPU_SG_MAX) return -1;
    gq_take();
    hdr_init(&rq_attach_sg.hdr, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
    rq_attach_sg.resource_id = res_id;
    rq_attach_sg.nr_entries  = n;
    for (uint32_t i = 0; i < n; i++) {
        rq_attach_sg.entry[i].addr    = phys[i];
        rq_attach_sg.entry[i].length  = len[i];
        rq_attach_sg.entry[i].padding = 0;
    }
    /* SEND ONLY THE ENTRIES WE FILLED. The descriptor length is what tells the
     * device how much to read; sending sizeof(the whole array) would have it
     * read 4096 entries of which most are zero, and a zero-length entry at a
     * zero address is a request to gather physical page 0. */
    uint32_t sz = (uint32_t)(sizeof rq_attach_sg.hdr + 8 + n * sizeof(struct virtio_gpu_mem_entry));
    uint32_t t = gpu_cmd_locked(&rq_attach_sg, sz, &rp_3d, sizeof rp_3d);
    gq_give();
    return t == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

int virtio_gpu_attach_backing_phys(uint32_t res_id, uint64_t phys, uint32_t len) {
    if (!vg.present) return -1;
    hdr_init(&rq_attach.hdr, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
    rq_attach.resource_id = res_id;
    rq_attach.nr_entries = 1;
    rq_attach.entry.addr = phys;
    rq_attach.entry.length = len;
    rq_attach.entry.padding = 0;
    return gpu_cmd(&rq_attach, sizeof rq_attach, &rp_3d, sizeof rp_3d) == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

int virtio_gpu_transfer_3d(uint32_t ctx_id, uint32_t res_id, int to_host,
                           uint32_t x, uint32_t y, uint32_t z,
                           uint32_t w, uint32_t h, uint32_t d,
                           uint64_t offset, uint32_t level, uint32_t stride, uint32_t layer_stride) {
    if (!virtio_gpu_has_3d()) return -1;
    hdr_init_ctx(&rq_x3d.hdr, to_host ? VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D
                                      : VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D, ctx_id);
    rq_x3d.box.x = x; rq_x3d.box.y = y; rq_x3d.box.z = z;
    rq_x3d.box.w = w; rq_x3d.box.h = h; rq_x3d.box.d = d;
    rq_x3d.offset = offset; rq_x3d.resource_id = res_id; rq_x3d.level = level;
    rq_x3d.stride = stride; rq_x3d.layer_stride = layer_stride;
    return gpu_cmd(&rq_x3d, sizeof rq_x3d, &rp_3d, sizeof rp_3d) == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

/* SUBMIT_3D. The command stream has to be PHYSICALLY CONTIGUOUS with the
 * header for the two-descriptor chain this driver uses, so it is staged into a
 * single contiguous kernel buffer. Copying is the point, not a cost to
 * apologise for: the alternative is handing the device a pointer into a user
 * page, and a user page can be a COW alias that the device then writes through
 * or reads stale -- the bug class that cost four milestones in the socket
 * path. */
static uint8_t *g_cmdbuf;              /* header + up to GPU_CMDBUF_MAX bytes */
static uint64_t g_cmdbuf_phys;

int virtio_gpu_submit_3d(uint32_t ctx_id, const void *data, uint32_t size) {
    if (!virtio_gpu_has_3d() || !data || !size) return -1;
    if (size > GPU_CMDBUF_MAX) return -1;
    if (!g_cmdbuf) {
        uint32_t need = (uint32_t)sizeof(struct virtio_gpu_cmd_submit) + GPU_CMDBUF_MAX;
        uint32_t frames = (need + PAGE_SIZE - 1) / PAGE_SIZE;
        uint64_t base = pmm_alloc_frame(), prev = base;
        if (!base) return -1;
        for (uint32_t i = 1; i < frames; i++) {
            uint64_t f = pmm_alloc_frame();
            if (!f || f != prev + PAGE_SIZE) {
                kprintf("[gpu3d] the %u-frame command buffer could not be allocated "
                        "CONTIGUOUSLY -- physical memory is too fragmented for a "
                        "single-entry descriptor\n", frames);
                return -1;
            }
            prev = f;
        }
        g_cmdbuf = (uint8_t *)hhdm(base);
        g_cmdbuf_phys = base;
    }
    gq_take();
    struct virtio_gpu_cmd_submit *sb = (struct virtio_gpu_cmd_submit *)g_cmdbuf;
    hdr_init_ctx(&sb->hdr, VIRTIO_GPU_CMD_SUBMIT_3D, ctx_id);
    sb->size = size;
    sb->padding = 0;
    memcpy(g_cmdbuf + sizeof *sb, data, size);
    uint32_t t = gpu_cmd_locked(g_cmdbuf, (uint32_t)sizeof *sb + size, &rp_3d, sizeof rp_3d);
    gq_give();
    return t == VIRTIO_GPU_RESP_OK_NODATA ? 0 : -1;
}

int virtio_gpu_has_3d(void)        { return vg.virgl && vg.capset_size > 0; }
uint32_t virtio_gpu_capset_id(void)   { return vg.capset_id; }
uint32_t virtio_gpu_capset_ver(void)  { return vg.capset_ver; }
uint32_t virtio_gpu_capset_size(void) { return vg.capset_size; }

int virtio_gpu_init(void) {
    memset(&vg, 0, sizeof(vg));

    /* QEMU's virtio-gpu-pci is the MODERN virtio-gpu device: vendor 0x1AF4,
     * device 0x1050. (The transitional id 0x1010 would be a legacy/transitional
     * GPU; QEMU only ships 0x1050, so we match it primarily and fall back.) */
    /* WHICH STEP FAILED (M2348). Every `return -1` below used to surface as
     * the caller's one message, "no virtio-gpu device found (none attached)" --
     * which names the FIRST of five unrelated causes and is a lie for the
     * other four. It cost a debugging session: the PCI enumeration printed
     * `00:1c.0 1af4:1050` in the same boot that claimed no device was
     * attached, and the two statements cannot both be true. Say which. */
    pci_device_t dev = pci_find(0x1AF4, 0x1050);
    if (!dev.valid)
        dev = pci_find(0x1AF4, 0x1010);
    if (!dev.valid) {
        g_vg_why = "no 1af4:1050 or 1af4:1010 on the PCI bus -- none attached";
        return -1;
    }

    /* Enable PCI memory-space decode + bus mastering (the device DMAs our
     * rings + backing). Modern transport is MMIO only — no I/O-space needed. */
    pci_enable_bus_master(&dev);

    /* Locate + map the modern virtio config regions from the PCI caps. */
    if (map_virtio_caps(&dev) != 0) {
        g_vg_why = "the device is on the bus but its modern virtio config caps "
                   "could not be mapped";
        return -1;
    }

    /* --- modern init handshake (virtio 1.0 §3.1.1) --------------------------
     * Reset, then ACK + DRIVER. */
    cc_w8(VCC_DEVICE_STATUS, 0);            /* reset */
    /* Wait for the reset to take (status reads back 0). */
    for (int i = 0; i < 1000000 && cc_r8(VCC_DEVICE_STATUS) != 0; i++)
        __asm__ volatile("pause");
    cc_w8(VCC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
    cc_w8(VCC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    /* Feature negotiation: a modern device offers VIRTIO_F_VERSION_1 (bit 32),
     * which the driver MUST accept.
     *
     * AND NOW VIRGL TOO, IF THE DEVICE OFFERS IT (M2346). This used to accept
     * only VERSION_1, by a decision its own comment recorded -- "no
     * VIRGL/EDID/etc." -- which was correct for a driver whose whole job was
     * one scanout and is the wall for anything that wants to run a shader.
     * Taking the bit is free when the host is `virtio-vga-gl` and impossible
     * when it is not, which makes it a clean probe as well as a capability:
     * `vg.virgl` afterwards is a measured fact about the host, not a guess. */
    cc_w32(VCC_DEVICE_FEATURE_SELECT, VIRTIO_F_VERSION_1_WORD);
    uint32_t devf1 = cc_r32(VCC_DEVICE_FEATURE);
    if (!(devf1 & VIRTIO_F_VERSION_1_BIT)) {
        /* A device that doesn't offer VERSION_1 isn't a modern device we can
         * drive this way — bail cleanly. */
        g_vg_why = "the device does not offer VIRTIO_F_VERSION_1 (legacy transport)";
        cc_w8(VCC_DEVICE_STATUS, VIRTIO_STATUS_FAILED);
        return -1;
    }
    cc_w32(VCC_DEVICE_FEATURE_SELECT, 0);
    uint32_t devf0 = cc_r32(VCC_DEVICE_FEATURE);
    uint32_t want0 = 0;
    if (devf0 & (1u << VIRTIO_GPU_F_VIRGL)) { want0 |= 1u << VIRTIO_GPU_F_VIRGL; vg.virgl = 1; }
    cc_w32(VCC_DRIVER_FEATURE_SELECT, 0);
    cc_w32(VCC_DRIVER_FEATURE, want0);
    cc_w32(VCC_DRIVER_FEATURE_SELECT, VIRTIO_F_VERSION_1_WORD);
    cc_w32(VCC_DRIVER_FEATURE, VIRTIO_F_VERSION_1_BIT);

    /* FEATURES_OK, then re-read: a modern device clears the bit if it can't
     * accept our feature set, in which case we must not proceed. */
    cc_w8(VCC_DEVICE_STATUS,
          VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
    if (!(cc_r8(VCC_DEVICE_STATUS) & VIRTIO_STATUS_FEATURES_OK) && want0) {
        /* A REFUSED OPTIONAL FEATURE MUST NOT COST US THE DEVICE (M2348).
         *
         * Before M2346 this driver asked for exactly one feature, which every
         * modern device must offer, so FEATURES_OK could only fail if
         * something was badly wrong. Now that it asks for VIRGL as well, a
         * device that offers the bit and then declines the combination takes
         * the whole GPU down with it -- and the caller reports "none
         * attached", about a device the PCI enumeration printed two lines
         * earlier. 3D is a bonus; the 2D scanout is not. So: renegotiate
         * without it, from a full reset, because the spec does not allow
         * rewriting the driver features once FEATURES_OK has been set. */
        kprintf("[gpu3d] the device declined VERSION_1+VIRGL together; "
                "retrying 2D-only so the display is not lost\n");
        vg.virgl = 0; want0 = 0;
        cc_w8(VCC_DEVICE_STATUS, 0);
        for (int i = 0; i < 1000000 && cc_r8(VCC_DEVICE_STATUS) != 0; i++)
            __asm__ volatile("pause");
        cc_w8(VCC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
        cc_w8(VCC_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
        cc_w32(VCC_DRIVER_FEATURE_SELECT, 0);
        cc_w32(VCC_DRIVER_FEATURE, 0);
        cc_w32(VCC_DRIVER_FEATURE_SELECT, VIRTIO_F_VERSION_1_WORD);
        cc_w32(VCC_DRIVER_FEATURE, VIRTIO_F_VERSION_1_BIT);
        cc_w8(VCC_DEVICE_STATUS,
              VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
    }
    if (!(cc_r8(VCC_DEVICE_STATUS) & VIRTIO_STATUS_FEATURES_OK)) {
        g_vg_why = "the device cleared FEATURES_OK even for VIRTIO_F_VERSION_1 alone";
        cc_w8(VCC_DEVICE_STATUS, VIRTIO_STATUS_FAILED);
        return -1;
    }

    /* Set up the control virtqueue (queue 0). */
    if (setup_queue() != 0) {
        g_vg_why = "the control virtqueue could not be set up";
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
        g_vg_why = "GET_DISPLAY_INFO got no answer: the queue is live but the device is not replying";
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
    /* A FAILED 2D SCANOUT MUST NOT COST US THE 3D DEVICE (M2348).
     *
     * This is the bug that produced "NOT AVAILABLE: no reason was recorded" --
     * `vg.present = 0; return -1;` on three paths none of which had been
     * instrumented, in a block that sets up a DISPLAY BUFFER THE CALLER DOES
     * NOT WANT. The device is attached headless specifically for 3D; the
     * desktop draws through the linear framebuffer and always has.
     *
     * And the failure is a real fragility, not bad luck: the backing is handed
     * to the device as a SINGLE mem entry, so it needs one physically
     * contiguous run of `w*h*4` bytes -- a thousand frames at 1280x800. That
     * allocation succeeded one boot and failed the next, with nothing between
     * them but a few kilobytes of new BSS shifting where the PMM had got to.
     * A capability that depends on allocator luck is not a capability.
     *
     * So: try it, report exactly what happened, and keep going either way.
     * `vg.scanout` records whether 2D is usable so `virtio_gpu_present` can
     * refuse honestly instead of drawing into a buffer the host never saw. */
    /* USE THE CONTIGUOUS ALLOCATOR THAT EXISTS (M2349). This loop used to call
     * `pmm_alloc_frame()` a thousand times and give up the moment two results
     * were not adjacent -- which is not a property that function promises. It
     * reported "a run of 67" against 1000 needed, and the 2D scanout was lost
     * on a machine with gigabytes free. `pmm_alloc_contiguous` searches. */
    vg.backing_bytes = (uint32_t)w * (uint32_t)h * 4u;
    uint32_t bframes = (vg.backing_bytes + (PAGE_SIZE - 1)) / PAGE_SIZE;
    uint64_t bbase = pmm_alloc_contiguous(bframes, 1);
    uint64_t got = bbase ? bframes : 0;
    if (got == bframes) {
        vg.backing_phys  = bbase;
        vg.backing       = (uint32_t *)hhdm(bbase);
        vg.backing_bytes = bframes * PAGE_SIZE;        /* rounded-up mapped size */
        memset(vg.backing, 0, vg.backing_bytes);
        if (cmd_create_2d((uint32_t)w, (uint32_t)h) == 0 &&
            cmd_attach_backing(vg.backing_phys, (uint32_t)w * (uint32_t)h * 4u) == 0 &&
            cmd_set_scanout((uint32_t)w, (uint32_t)h) == 0) {
            vg.scanout = 1;
            kprintf("[ ok ] virtio-gpu up: scanout 0 %dx%d (enabled=%d), resource %d live "
                    "(boot display stays on the linear framebuffer).\n",
                    w, h, enabled, RESOURCE_ID);
        } else {
            kprintf("[virtio-gpu] 2D scanout setup was REFUSED by the device "
                    "(CREATE_2D/ATTACH_BACKING/SET_SCANOUT); 3D is unaffected.\n");
        }
    } else {
        kprintf("[virtio-gpu] no 2D scanout: pmm_alloc_contiguous could not find %u "
                "contiguous frames for a %dx%d backing. 3D does not use this buffer "
                "at all, so continuing.\n", bframes, w, h);
    }

    /* AND NOW ASK ABOUT 3D, reporting each step so a failure names itself. */
    vg.ncapsets = cfg_num_capsets();
    if (!vg.virgl) {
        kprintf("[gpu3d] the device did NOT offer VIRTIO_GPU_F_VIRGL -- this is a 2D-only "
                "virtio-gpu. On QEMU that means `-device virtio-vga` rather than "
                "`virtio-vga-gl`.\n");
    } else if (!vg.ncapsets) {
        kprintf("[gpu3d] VIRGL was offered and accepted, but the device reports 0 capsets: "
                "the device model has 3D compiled in and its RENDERER did not come up. "
                "On QEMU that is a host-side GL failure, not a guest one.\n");
    } else {
        for (uint32_t i = 0; i < vg.ncapsets; i++) {
            uint32_t id = 0, ver = 0, sz = 0;
            if (cmd_get_capset_info(i, &id, &ver, &sz) != 0) {
                kprintf("[gpu3d] capset %u: the device refused GET_CAPSET_INFO\n", i);
                continue;
            }
            kprintf("[gpu3d] capset %u: id %u (%s), max version %u, max size %u bytes\n",
                    i, id, id == VIRTIO_GPU_CAPSET_VIRGL  ? "VIRGL"  :
                            id == VIRTIO_GPU_CAPSET_VIRGL2 ? "VIRGL2" : "unknown",
                    ver, sz);
            /* Prefer VIRGL2 -- it is the one Mesa's virgl driver wants. */
            if (sz && (id == VIRTIO_GPU_CAPSET_VIRGL2 ||
                       (id == VIRTIO_GPU_CAPSET_VIRGL && vg.capset_id == 0))) {
                vg.capset_id = id; vg.capset_ver = ver; vg.capset_size = sz;
            }
        }
        if (virtio_gpu_has_3d())
            kprintf("[ ok ] virtio-gpu 3D IS AVAILABLE: capset %u version %u, %u bytes of "
                    "renderer capabilities to hand a GL driver.\n",
                    vg.capset_id, vg.capset_ver, vg.capset_size);
    }
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
    /* NO SCANOUT MEANS NO PRESENT (M2348). Returning success here would have
     * this function copy pixels into a buffer the host was never told about,
     * which is a display that silently shows nothing. */
    if (!vg.scanout) return -1;
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
        kprintf("[virtio-gpu] NOT AVAILABLE: %s (linear-framebuffer display "
                "intact).\n\n", virtio_gpu_why());
        return;
    }

    if (!vg.scanout) {
        kprintf("[virtio-gpu] selftest: SKIPPED the 2D present cycle -- this device has no "
                "scanout resource (see above). 3D availability is reported separately.\n\n");
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
