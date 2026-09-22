/*
 * virtio_gpu.h — virtio-gpu (2D) paravirtual display, the MODERN virtio path.
 *
 * Where kernel/fb.c + kernel/bochs_vbe.c drive a continuously-scanned LINEAR
 * framebuffer (QEMU std-VGA: you write a pixel and the card scans it out), a
 * virtio-gpu presents the display as a host-side *resource*. You don't scan
 * out of guest RAM — instead you draw into a guest backing buffer, then
 * explicitly TRANSFER the dirty rectangle from that backing to the host's copy
 * of the resource and FLUSH it to present. This is the modern paravirtual GPU
 * path (QEMU `-device virtio-gpu-pci`).
 *
 * TRANSPORT NOTE — this is NOT the legacy virtio transport kernel/virtio_blk.c
 * uses. QEMU's virtio-gpu-pci is a MODERN-ONLY virtio 1.0 device: it always
 * enumerates as PCI 1af4:1050 with MMIO BARs and NO legacy I/O-port register
 * window, even with disable-modern=on. So virtio_gpu.c speaks the modern PCI
 * transport: it walks the device's PCI vendor capabilities to find the
 * common-config / notify / ISR / device-config MMIO regions, negotiates the
 * mandatory VIRTIO_F_VERSION_1 feature, and programs the split virtqueue's
 * three rings by separate physical address. The virtqueue ring layout and the
 * fill/notify/poll cycle are otherwise identical to virtio_blk.c's.
 *
 * SAFE SCOPE: this is ADDITIVE. The boot display stays on the linear
 * framebuffer (fb.c / bochs_vbe.c) unchanged; virtio_gpu_init() probes PCI and
 * is a clean no-op (returns -1) when no virtio-gpu is attached, so a machine
 * without one boots byte-identically. Like kernel/hda.c proves its audio DMA
 * advances without audible output, virtio_gpu_selftest() proves the full
 * present cycle (every control command returns OK) headlessly.
 */
#pragma once
#include <stdint.h>

/* Probe the PCI bus for a virtio-gpu device and bring it up: negotiate
 * VIRTIO_F_VERSION_1, set up the control virtqueue, read scanout 0's preferred
 * resolution, then CREATE_2D + ATTACH_BACKING + SET_SCANOUT so a guest-RAM
 * backing buffer is bound to the display and live. Returns 0 if a usable device
 * was initialized, -1 if none is present / init failed (a clean no-op — the
 * linear-framebuffer display path is untouched either way). */
int virtio_gpu_init(void);

/* 1 if virtio_gpu_init() brought a device up (resource live on scanout 0),
 * else 0. (Used by an integrator to decide whether to route present through
 * virtio-gpu — see the conservative fb.c fallback note in the .c.) */
int virtio_gpu_active(void);

/* The negotiated scanout 0 resolution (the backing buffer is exactly
 * width*height*4 bytes). 0 if no device. */
int virtio_gpu_width(void);
int virtio_gpu_height(void);

/* The guest-RAM backing buffer the resource is attached to: a contiguous
 * width*height array of 0x00RRGGBB pixels (the SAME pixel layout fb.c uses, so
 * the desktop's pixels can be copied straight in). NULL if no device. Draw into
 * this, then call virtio_gpu_present() to show it. */
uint32_t *virtio_gpu_backing(void);

/* Present the rectangle [x,y,w,h] of the backing buffer to the screen:
 * TRANSFER_TO_HOST_2D that rect from the backing to the host resource, then
 * RESOURCE_FLUSH it. The rect is clamped within [0,width]x[0,height]. Returns 0
 * on success, -1 on bad-arg / device error / timeout / no device. This is the
 * "flush" the desktop's compositor would call after drawing a frame. */
int virtio_gpu_present(int x, int y, int w, int h);

/* Bring-up self-test (the headless proof, like hda_selftest): fill the backing
 * with a known colour-band test pattern, run the full present cycle over the
 * whole screen, and log each control command's response code, asserting every
 * one is VIRTIO_GPU_RESP_OK_*. No-op (logs "none attached") if no device. */
void virtio_gpu_selftest(void);

/* ---- 3D / virgl (M2346) ---------------------------------------------------
 * `virtio_gpu_has_3d()` is TWO facts and-ed together: the device offered and we
 * accepted VIRTIO_GPU_F_VIRGL, AND it then reported a non-empty capset. They
 * come apart in practice -- QEMU built with virglrenderer but unable to create
 * a host GL context offers the bit and reports zero capsets -- so a caller that
 * checked only the feature would claim 3D and then fail on the first draw. */
int      virtio_gpu_has_3d(void);
uint32_t virtio_gpu_capset_id(void);
uint32_t virtio_gpu_capset_ver(void);
uint32_t virtio_gpu_capset_size(void);

/* Copy the host renderer's capability blob (`virtio_gpu_capset_size()` bytes
 * for `virtio_gpu_capset_id()`) into `out`. Opaque to the kernel by design --
 * only the guest's GL driver parses it. Returns bytes written, or -1. */
int virtio_gpu_get_capset(uint32_t id, uint32_t ver, void *out, uint32_t out_len);

/* ---- 3D submission (M2348) -------------------------------------------------
 * The device-side half of a GL driver's needs. Each returns 0 only when the
 * device answered OK -- no retries and no optimism, because a 3D command that
 * half-worked leaves host GL state the guest believes it set and does not
 * have, which is not diagnosable from the guest at all. */
int virtio_gpu_ctx_create(uint32_t ctx_id, const char *name);
int virtio_gpu_ctx_destroy(uint32_t ctx_id);
int virtio_gpu_ctx_attach(uint32_t ctx_id, uint32_t res_id, int attach);
int virtio_gpu_res_create_3d(uint32_t ctx_id, uint32_t res_id, uint32_t target, uint32_t format,
                             uint32_t bind, uint32_t w, uint32_t h, uint32_t depth,
                             uint32_t array_size, uint32_t last_level, uint32_t nr_samples,
                             uint32_t flags);
int virtio_gpu_res_unref(uint32_t res_id);
int virtio_gpu_attach_backing_phys(uint32_t res_id, uint64_t phys, uint32_t len);
int virtio_gpu_transfer_3d(uint32_t ctx_id, uint32_t res_id, int to_host,
                           uint32_t x, uint32_t y, uint32_t z,
                           uint32_t w, uint32_t h, uint32_t d,
                           uint64_t offset, uint32_t level, uint32_t stride, uint32_t layer_stride);
int virtio_gpu_submit_3d(uint32_t ctx_id, const void *data, uint32_t size);

/* Why virtio_gpu_init() returned -1. Five unrelated causes used to share one
 * message that named only the first of them. (M2348) */
const char *virtio_gpu_why(void);
