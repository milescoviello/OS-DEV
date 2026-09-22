/* kernel/drm.c — the DRM render node Mesa's virgl driver opens. (M2347)
 *
 * WHY THIS IS A SEPARATE FILE FROM virtio_gpu.c. Two different jobs that keep
 * getting conflated in drivers that combine them: virtio_gpu.c speaks to a
 * DEVICE (virtqueues, descriptors, physical addresses), and this file speaks
 * to a PROGRAM (ioctl numbers, user pointers, handles, errnos). Every bug this
 * project has had in the Linux ABI has been in the second kind of code --
 * struct layouts that lie, errnos that name the wrong thing -- and none of
 * them in the first.
 *
 * THE IOCTL NUMBERS ARE NOT COMPUTED HERE, THEY ARE VERIFIED. _IOC arithmetic
 * that is one struct-size off yields a number the kernel does not recognise,
 * which returns ENOTTY, which is indistinguishable from "not implemented" --
 * so getting it subtly wrong costs a debugging session that finds nothing.
 * Each constant below was printed from the SAME uapi headers Mesa compiles
 * against (tools/lx/lxdrm.c uses those headers directly, so the two agree by
 * construction and disagree loudly if this table drifts):
 *
 *     DRM_IOCTL_VERSION                     0xc0406400   size 64
 *     DRM_IOCTL_GET_CAP                     0xc010640c   size 16
 *     DRM_IOCTL_VIRTGPU_MAP                 0xc0106441   size 16
 *     DRM_IOCTL_VIRTGPU_EXECBUFFER          0xc0406442   size 64
 *     DRM_IOCTL_VIRTGPU_GETPARAM            0xc0106443   size 16
 *     DRM_IOCTL_VIRTGPU_RESOURCE_CREATE     0xc0386444   size 56
 *     DRM_IOCTL_VIRTGPU_RESOURCE_INFO       0xc0106445   size 16
 *     DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST  0xc02c6446   size 44
 *     DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST    0xc02c6447   size 44
 *     DRM_IOCTL_VIRTGPU_WAIT                0xc0086448   size 8
 *     DRM_IOCTL_VIRTGPU_GET_CAPS            0xc0186449   size 24
 *     DRM_IOCTL_VIRTGPU_CONTEXT_INIT        0xc010644b   size 16
 */
#include "drm.h"
#include "virtio_gpu.h"
#include "console.h"
#include "string.h"
#include "vmm.h"
#include "pmm.h"
#include "kheap.h"
#include "app.h"

#define DRM_IOCTL_VERSION                    0xc0406400ul
#define DRM_IOCTL_GET_CAP                    0xc010640cul
#define DRM_IOCTL_GEM_CLOSE                  0x40086409ul
#define DRM_IOCTL_VIRTGPU_MAP                0xc0106441ul
#define DRM_IOCTL_VIRTGPU_EXECBUFFER         0xc0406442ul
#define DRM_IOCTL_VIRTGPU_GETPARAM           0xc0106443ul
#define DRM_IOCTL_VIRTGPU_RESOURCE_CREATE    0xc0386444ul
#define DRM_IOCTL_VIRTGPU_RESOURCE_INFO      0xc0106445ul
#define DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST 0xc02c6446ul
#define DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST   0xc02c6447ul
#define DRM_IOCTL_VIRTGPU_WAIT               0xc0086448ul
#define DRM_IOCTL_VIRTGPU_GET_CAPS           0xc0186449ul
#define DRM_IOCTL_VIRTGPU_CONTEXT_INIT       0xc010644bul

/* Struct layouts copied VERBATIM from <drm/drm.h> and <drm/virtgpu_drm.h>.
 * Retyped by hand is how a 4-byte pad goes missing and a field reads as the
 * next one's low half; these are the header's own lines with __u32/__u64
 * spelled as uint32_t/uint64_t and the doc comments kept so a future reader
 * can diff them against the header without opening it. */
struct drm_version {
    int version_major;
    int version_minor;
    int version_patchlevel;
    uint64_t name_len;          /* __kernel_size_t */
    uint64_t name;              /* char *          */
    uint64_t date_len;
    uint64_t date;
    uint64_t desc_len;
    uint64_t desc;
};
struct drm_get_cap      { uint64_t capability; uint64_t value; };
struct drm_virtgpu_getparam { uint64_t param; uint64_t value; };
struct drm_virtgpu_get_caps { uint32_t cap_set_id; uint32_t cap_set_ver;
                              uint64_t addr; uint32_t size; uint32_t pad; };

/* More layouts, same provenance -- copied from <drm/virtgpu_drm.h> and
 * <drm/drm.h>, sizes cross-checked against _IOC_SIZE of the ioctl numbers
 * above (56, 16, 64, 44, 8, 16, 8). Note `drm_virtgpu_3d_transfer_*` puts
 * `bo_handle` FIRST and then the box -- not the other way round, which is what
 * you would guess from the wire format, where the box comes first. */
struct drm_virtgpu_resource_create {
    uint32_t target, format, bind, width, height, depth, array_size;
    uint32_t last_level, nr_samples, flags, bo_handle, res_handle, size, stride;
};
struct drm_virtgpu_map { uint64_t offset; uint32_t handle; uint32_t pad; };
struct drm_virtgpu_execbuffer {
    uint32_t flags, size;
    uint64_t command;
    uint64_t bo_handles;
    uint32_t num_bo_handles;
    int32_t  fence_fd;
    uint32_t ring_idx, syncobj_stride, num_in_syncobjs, num_out_syncobjs;
    uint64_t in_syncobjs, out_syncobjs;
};
struct drm_virtgpu_3d_box { uint32_t x, y, z, w, h, d; };
struct drm_virtgpu_3d_transfer {
    uint32_t bo_handle;
    struct drm_virtgpu_3d_box box;
    uint32_t level, offset, stride, layer_stride;
};
struct drm_virtgpu_3d_wait { uint32_t handle, flags; };
struct drm_virtgpu_resource_info { uint32_t bo_handle, res_handle, size, blob_mem; };
struct drm_gem_close { uint32_t handle, pad; };

/* VIRTGPU_PARAM_*, from the same header. */
#define VIRTGPU_PARAM_3D_FEATURES        1
#define VIRTGPU_PARAM_CAPSET_QUERY_FIX   2
#define VIRTGPU_PARAM_RESOURCE_BLOB      3
#define VIRTGPU_PARAM_HOST_VISIBLE       4
#define VIRTGPU_PARAM_CROSS_DEVICE       5
#define VIRTGPU_PARAM_CONTEXT_INIT       6
#define VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs 7

/* Linux errnos, negated, as this ABI returns them. */
#define E_INVAL  (-22)
#define E_NOTTY  (-25)
#define E_FAULT  (-14)
#define E_NODEV  (-19)
#define E_NOSPC  (-28)
#define E_MFILE  (-24)

/* One open node per descriptor. Nothing per-node yet beyond "is it open" --
 * contexts and resources arrive in M2348 and hang off here, which is why this
 * is a table and not a boolean. */
#define DRM_NODES 16
static struct {
    int used;
    int ctx;            /* has this node's virgl context been created? */
} g_node[DRM_NODES];

/* GEM OBJECTS.
 *
 * A "handle" is this table's index plus one, because handle 0 is reserved as
 * invalid throughout the DRM uAPI -- `drm_virtgpu_3d_wait` documents it in so
 * many words -- and an off-by-one that makes object 0 addressable turns "the
 * caller passed nothing" into "the caller passed the first object".
 *
 * `res_id` is the HOST's name for the same thing and is deliberately a
 * different number space: RESOURCE_ID 1 is the 2D scanout, so 3D ids start
 * well clear of it. Reusing one counter for both would have a GL driver's
 * first texture land on the display's resource.
 *
 * Backing is a scatter list of frames. Not contiguous, on purpose: see the
 * note on virtio_gpu_attach_backing_sg -- asking the PMM for a contiguous
 * multi-megabyte run is not a thing that reliably succeeds, and it is what
 * made the 2D scanout unreliable. */
#define DRM_BO_N      512
#define DRM_BO_FRAMES 4096              /* 16 MiB per object */
static struct drm_bo {
    int      used;
    int      node;                      /* which open node owns it */
    uint32_t res_id;
    uint32_t bytes;                     /* what the caller asked for */
    uint32_t nframes;
    uint64_t *frames;                   /* nframes physical addresses */
} g_bo[DRM_BO_N];

static uint32_t g_next_res = 64;        /* clear of RESOURCE_ID 1 */

/* THE MAP OFFSET NAMESPACE. VIRTGPU_MAP hands userspace a file offset that a
 * later mmap() of the same fd must resolve back to this object. Linux uses a
 * real address-space allocator; one page-aligned slot per handle is enough
 * here, and making it handle*16MiB means an offset can be decoded back to a
 * handle by division, with no second table to keep in step with this one. */
#define DRM_MAP_STRIDE (16ull * 1024 * 1024)

static struct drm_bo *bo_of(uint32_t handle) {
    if (!handle || handle > DRM_BO_N) return 0;
    struct drm_bo *b = &g_bo[handle - 1];
    return b->used ? b : 0;
}

static void bo_free(struct drm_bo *b) {
    if (!b || !b->used) return;
    if (b->res_id) virtio_gpu_res_unref(b->res_id);
    if (b->frames) {
        for (uint32_t i = 0; i < b->nframes; i++)
            if (b->frames[i]) pmm_free_frame(b->frames[i]);
        kfree(b->frames);
    }
    b->used = 0; b->frames = 0; b->nframes = 0; b->res_id = 0; b->bytes = 0;
}

/* Allocate `bytes` of guest backing as frames, coalesce adjacent ones into as
 * few (addr,len) entries as they happen to form, and hand the list to the
 * device. Returns 0 on success. */
static int bo_attach_backing(struct drm_bo *b, uint32_t bytes) {
    uint32_t nf = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    if (!nf || nf > DRM_BO_FRAMES) return -1;
    b->frames = (uint64_t *)kmalloc(nf * sizeof(uint64_t));
    if (!b->frames) return -1;
    for (uint32_t i = 0; i < nf; i++) {
        b->frames[i] = pmm_alloc_frame();
        if (!b->frames[i]) { b->nframes = i; return -1; }
        /* Zero it. A GL driver reads back buffers it has written and a texture
         * it has not; handing over whatever the last process left there is an
         * information leak across processes, not just uninitialised data. */
        memset(hhdm(b->frames[i]), 0, PAGE_SIZE);
    }
    b->nframes = nf;

    /* Coalesce into runs. */
    static uint64_t sg_addr[DRM_BO_FRAMES];
    static uint32_t sg_len[DRM_BO_FRAMES];
    uint32_t n = 0;
    for (uint32_t i = 0; i < nf; i++) {
        if (n && sg_addr[n - 1] + sg_len[n - 1] == b->frames[i]) {
            sg_len[n - 1] += PAGE_SIZE;
        } else {
            sg_addr[n] = b->frames[i]; sg_len[n] = PAGE_SIZE; n++;
        }
    }
    return virtio_gpu_attach_backing_sg(b->res_id, sg_addr, sg_len, n);
}

/* The node's virgl context, created on first use. Lazily, because a process
 * may open the node only to read its capabilities -- Mesa does exactly that
 * during device enumeration -- and creating host GL state for a query that
 * will be thrown away is a leak with no upside. */
static uint32_t node_ctx(int node) {
    if (node < 0 || node >= DRM_NODES) return 0;
    uint32_t ctx = (uint32_t)node + 1;
    if (!g_node[node].ctx) {
        if (virtio_gpu_ctx_create(ctx, "osdev") != 0) return 0;
        g_node[node].ctx = 1;
    }
    return ctx;
}

/* For app.c's mmap: which frame backs page `page` of the object named by map
 * offset `off`, and how big is it. Kept here so the handle namespace has
 * exactly one owner. */
uint64_t drm_map_frame(uint64_t off, uint64_t page) {
    struct drm_bo *b = bo_of((uint32_t)(off / DRM_MAP_STRIDE));
    if (!b || page >= b->nframes) return 0;
    return b->frames[page];
}
uint64_t drm_map_size(uint64_t off) {
    struct drm_bo *b = bo_of((uint32_t)(off / DRM_MAP_STRIDE));
    return b ? (uint64_t)b->nframes * PAGE_SIZE : 0;
}

int drm_open_node(void) {
    if (!virtio_gpu_has_3d()) return -1;
    for (int i = 0; i < DRM_NODES; i++)
        if (!g_node[i].used) { g_node[i].used = 1; return i; }
    return -1;
}
void drm_close_node(int id) {
    if (id < 0 || id >= DRM_NODES) return;
    /* EVERY OBJECT THIS NODE MADE GOES WITH IT. A GL process that exits
     * without calling GEM_CLOSE on each buffer -- which is every process that
     * crashes, and most that do not -- would otherwise leak both guest frames
     * and HOST GL resources, and the host ones are invisible from here. */
    for (int i = 0; i < DRM_BO_N; i++)
        if (g_bo[i].used && g_bo[i].node == id) bo_free(&g_bo[i]);
    if (g_node[id].ctx) { virtio_gpu_ctx_destroy((uint32_t)id + 1); g_node[id].ctx = 0; }
    g_node[id].used = 0;
}

/* WHICH PATHS ARE THIS DEVICE.
 *
 * `renderD128` is the render node -- the one a GL driver wants, and the only
 * one we serve. `card0` is the PRIMARY node, which additionally carries
 * modesetting, and we deliberately do NOT claim it: a program that opens
 * card0 expecting to set a mode and gets a node that refuses every KMS ioctl
 * is worse off than one told the file does not exist, because the first
 * failure mode looks like a broken driver and the second looks like a machine
 * without a GPU -- which is the truth. */
int drm_is_node_path(const char *path) {
    if (!path) return 0;
    return strcmp(path, "/dev/dri/renderD128") == 0;
}

/* THE ONE-SHOT TRACE. Every distinct request once, so an unimplemented ioctl
 * is visible by name the first time Mesa asks for it rather than being
 * inferred from a fallback to software three layers up. */
static void drm_seen(unsigned long req, const char *what, long rc) {
    static unsigned long seen[32]; static int nseen;
    for (int i = 0; i < nseen; i++) if (seen[i] == req) return;
    if (nseen < 32) seen[nseen++] = req;
    kprintf("[drm] %s (0x%lx) -> %ld\n", what, req, rc);
}

/* The node behind a descriptor. app.c stores it in the fdent's `obj`. */
static int drm_node_of_fd(int fd) {
    int n = app_fd_obj(fd);
    return (n >= 0 && n < DRM_NODES && g_node[n].used) ? n : -1;
}

long drm_ioctl(int fd, unsigned long req, void *uarg) {
    if (!virtio_gpu_has_3d()) { drm_seen(req, "any ioctl with no 3D device", E_NODEV); return E_NODEV; }

    switch (req) {

    /* ---- who are you ----------------------------------------------------- */
    case DRM_IOCTL_VERSION: {
        struct drm_version v;
        if (!uarg || !vmm_user_ok((uint64_t)(uintptr_t)uarg, sizeof v)) return E_FAULT;
        memcpy(&v, uarg, sizeof v);
        /* The version a real virtio_gpu kernel driver reports. Mesa checks it:
         * virgl wants >= 0.1 and refuses to load below that. */
        v.version_major = 0; v.version_minor = 1; v.version_patchlevel = 0;
        /* Each of the three strings is copied only as far as the caller said
         * it could hold, and the LENGTH IS WRITTEN BACK as the amount copied.
         * libdrm calls this twice -- once with zero lengths to learn the
         * sizes, then again with buffers -- so reporting the full length on
         * the first call and a truncated copy on the second is how you get a
         * driver name with its tail missing. */
        static const char *nm = "virtio_gpu";
        static const char *dt = "0";
        static const char *ds = "virtio GPU (OS-DEV)";
        struct { uint64_t *len; uint64_t ptr; const char *src; } f[3] = {
            { &v.name_len, v.name, nm }, { &v.date_len, v.date, dt }, { &v.desc_len, v.desc, ds }
        };
        for (int i = 0; i < 3; i++) {
            uint64_t n = strlen(f[i].src);
            if (f[i].ptr && *f[i].len) {
                uint64_t cap = *f[i].len;
                uint64_t cp = n < cap ? n : cap;
                if (!vmm_user_ok(f[i].ptr, cp)) return E_FAULT;
                memcpy((void *)(uintptr_t)f[i].ptr, f[i].src, cp);
                *f[i].len = cp;
            } else {
                *f[i].len = n;             /* the sizing call */
            }
        }
        memcpy(uarg, &v, sizeof v);
        drm_seen(req, "VERSION", 0);
        return 0;
    }

    /* ---- what can you do ------------------------------------------------- */
    case DRM_IOCTL_VIRTGPU_GETPARAM: {
        struct drm_virtgpu_getparam gp;
        if (!uarg || !vmm_user_ok((uint64_t)(uintptr_t)uarg, sizeof gp)) return E_FAULT;
        memcpy(&gp, uarg, sizeof gp);
        /* NOTE THE SHAPE: `value` is a POINTER TO a u64, not a u64. Reading it
         * as the value is the single most common way to implement this wrong,
         * and it "works" for param 0 because a null pointer and a false answer
         * look the same. */
        uint64_t out = 0;
        switch (gp.param) {
        case VIRTGPU_PARAM_3D_FEATURES:      out = 1; break;
        case VIRTGPU_PARAM_CAPSET_QUERY_FIX: out = 1; break;   /* we honour cap_set_ver */
        case VIRTGPU_PARAM_RESOURCE_BLOB:    out = 0; break;   /* not yet (M2348+) */
        case VIRTGPU_PARAM_HOST_VISIBLE:     out = 0; break;
        case VIRTGPU_PARAM_CROSS_DEVICE:     out = 0; break;
        case VIRTGPU_PARAM_CONTEXT_INIT:     out = 0; break;
        case VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs:
            /* A bitmask of capset ids, not a count. */
            out = (1ull << virtio_gpu_capset_id());
            break;
        default:
            /* AN UNKNOWN PARAM IS EINVAL, NOT ZERO. Answering 0 to a param we
             * have never heard of tells the caller "this GPU cannot do that",
             * which is a claim about the hardware; EINVAL tells it "this
             * kernel does not know what you asked", which is the truth and is
             * what Mesa's feature detection is written to handle. */
            drm_seen(req, "GETPARAM(unknown)", E_INVAL);
            return E_INVAL;
        }
        if (!gp.value || !vmm_user_ok(gp.value, sizeof out)) return E_FAULT;
        memcpy((void *)(uintptr_t)gp.value, &out, sizeof out);
        drm_seen(req, "GETPARAM", 0);
        return 0;
    }

    case DRM_IOCTL_VIRTGPU_GET_CAPS: {
        struct drm_virtgpu_get_caps gc;
        if (!uarg || !vmm_user_ok((uint64_t)(uintptr_t)uarg, sizeof gc)) return E_FAULT;
        memcpy(&gc, uarg, sizeof gc);
        if (!gc.addr || !gc.size) return E_INVAL;
        /* REFUSE A CAPSET WE WERE NOT OFFERED, rather than fetching whatever
         * the host happens to return for it. A capset the renderer does not
         * publish is a different thing from an empty one, and Mesa asks about
         * both. */
        if (gc.cap_set_id != virtio_gpu_capset_id()) {
            drm_seen(req, "GET_CAPS(capset we were not offered)", E_INVAL);
            return E_INVAL;
        }
        if (gc.size > virtio_gpu_capset_size()) gc.size = virtio_gpu_capset_size();
        if (!vmm_user_ok(gc.addr, gc.size)) return E_FAULT;
        /* Into a kernel staging buffer first, then out to the user. The device
         * writes into a physical descriptor and a user page can be a COW
         * alias; handing the device a user address directly is the class of
         * bug that took four milestones to find in the socket path. */
        static uint8_t stage[4096];
        int n = virtio_gpu_get_capset(gc.cap_set_id, gc.cap_set_ver, stage,
                                      gc.size < sizeof stage ? gc.size : (uint32_t)sizeof stage);
        if (n <= 0) { drm_seen(req, "GET_CAPS(device refused)", E_INVAL); return E_INVAL; }
        memcpy((void *)(uintptr_t)gc.addr, stage, (uint64_t)n);
        drm_seen(req, "GET_CAPS", n);
        return 0;
    }

    /* ---- generic DRM capabilities ---------------------------------------- */
    case DRM_IOCTL_GET_CAP: {
        struct drm_get_cap gp;
        if (!uarg || !vmm_user_ok((uint64_t)(uintptr_t)uarg, sizeof gp)) return E_FAULT;
        memcpy(&gp, uarg, sizeof gp);
        /* Every DRM_CAP_* here is about DUMB BUFFERS, PRIME sharing and
         * modesetting, none of which a render node has. Zero is the correct
         * answer for a render-only node and is what Linux returns. */
        gp.value = 0;
        memcpy(uarg, &gp, sizeof gp);
        drm_seen(req, "GET_CAP", 0);
        return 0;
    }

    /* ---- the 3D submission path: named, and honestly unimplemented ------- */
    /* ---- objects ---------------------------------------------------------- */
    case DRM_IOCTL_VIRTGPU_RESOURCE_CREATE: {
        struct drm_virtgpu_resource_create rc;
        if (!uarg || !vmm_user_ok((uint64_t)(uintptr_t)uarg, sizeof rc)) return E_FAULT;
        memcpy(&rc, uarg, sizeof rc);
        int node = drm_node_of_fd(fd);
        uint32_t ctx = node_ctx(node);
        if (!ctx) { drm_seen(req, "RESOURCE_CREATE but no virgl context", E_NODEV); return E_NODEV; }

        int slot = -1;
        for (int i = 0; i < DRM_BO_N; i++) if (!g_bo[i].used) { slot = i; break; }
        if (slot < 0) { drm_seen(req, "RESOURCE_CREATE: object table full", E_NOSPC); return E_NOSPC; }
        struct drm_bo *b = &g_bo[slot];
        /* CLAIM THE SLOT BEFORE DOING ANYTHING THAT CAN BLOCK. Every command
         * below goes to the device and yields; a second thread scanning this
         * table in the meantime would pick the same free slot. Nine instances
         * of exactly this in this codebase, so: claim first. */
        memset(b, 0, sizeof *b);
        b->used = 1; b->node = node;
        b->res_id = __atomic_fetch_add(&g_next_res, 1, __ATOMIC_RELAXED);

        if (virtio_gpu_res_create_3d(ctx, b->res_id, rc.target, rc.format, rc.bind,
                                     rc.width, rc.height, rc.depth, rc.array_size,
                                     rc.last_level, rc.nr_samples, rc.flags) != 0) {
            b->used = 0;
            drm_seen(req, "RESOURCE_CREATE: the device refused CREATE_3D", E_INVAL);
            return E_INVAL;
        }
        /* `size` 0 means a host-only resource -- a renderbuffer the guest never
         * touches. Giving it guest backing would allocate megabytes nothing
         * reads. */
        if (rc.size) {
            if (bo_attach_backing(b, rc.size) != 0) {
                bo_free(b);
                drm_seen(req, "RESOURCE_CREATE: backing could not be allocated/attached", E_NOSPC);
                return E_NOSPC;
            }
            b->bytes = rc.size;
        }
        if (virtio_gpu_ctx_attach(ctx, b->res_id, 1) != 0) {
            bo_free(b);
            drm_seen(req, "RESOURCE_CREATE: CTX_ATTACH_RESOURCE refused", E_INVAL);
            return E_INVAL;
        }
        rc.bo_handle  = (uint32_t)slot + 1;
        rc.res_handle = b->res_id;
        memcpy(uarg, &rc, sizeof rc);
        drm_seen(req, "RESOURCE_CREATE", 0);
        return 0;
    }

    case DRM_IOCTL_VIRTGPU_RESOURCE_INFO: {
        struct drm_virtgpu_resource_info ri;
        if (!uarg || !vmm_user_ok((uint64_t)(uintptr_t)uarg, sizeof ri)) return E_FAULT;
        memcpy(&ri, uarg, sizeof ri);
        struct drm_bo *b = bo_of(ri.bo_handle);
        if (!b) return E_INVAL;
        ri.res_handle = b->res_id;
        ri.size       = (uint32_t)b->nframes * PAGE_SIZE;
        ri.blob_mem   = 0;
        memcpy(uarg, &ri, sizeof ri);
        drm_seen(req, "RESOURCE_INFO", 0);
        return 0;
    }

    case DRM_IOCTL_VIRTGPU_MAP: {
        struct drm_virtgpu_map mp;
        if (!uarg || !vmm_user_ok((uint64_t)(uintptr_t)uarg, sizeof mp)) return E_FAULT;
        memcpy(&mp, uarg, sizeof mp);
        struct drm_bo *b = bo_of(mp.handle);
        if (!b) return E_INVAL;
        if (!b->nframes) {
            /* A HOST-ONLY RESOURCE CANNOT BE MAPPED, and saying so is the
             * point: returning an offset that mmap would then fail on moves
             * the error one syscall away from its cause. */
            drm_seen(req, "MAP of a resource with no guest backing", E_INVAL);
            return E_INVAL;
        }
        mp.offset = (uint64_t)mp.handle * DRM_MAP_STRIDE;
        memcpy(uarg, &mp, sizeof mp);
        drm_seen(req, "MAP", 0);
        return 0;
    }

    case DRM_IOCTL_GEM_CLOSE: {
        struct drm_gem_close gc;
        if (!uarg || !vmm_user_ok((uint64_t)(uintptr_t)uarg, sizeof gc)) return E_FAULT;
        memcpy(&gc, uarg, sizeof gc);
        struct drm_bo *b = bo_of(gc.handle);
        if (!b) return E_INVAL;
        bo_free(b);
        drm_seen(req, "GEM_CLOSE", 0);
        return 0;
    }

    /* ---- submission ------------------------------------------------------- */
    case DRM_IOCTL_VIRTGPU_EXECBUFFER: {
        struct drm_virtgpu_execbuffer eb;
        if (!uarg || !vmm_user_ok((uint64_t)(uintptr_t)uarg, sizeof eb)) return E_FAULT;
        memcpy(&eb, uarg, sizeof eb);
        int node = drm_node_of_fd(fd);
        uint32_t ctx = node_ctx(node);
        if (!ctx) return E_NODEV;
        if (!eb.command || !eb.size) return E_INVAL;
        if (!vmm_user_ok(eb.command, eb.size)) return E_FAULT;
        /* THE bo_handles LIST IS DELIBERATELY NOT PINNED, and that is sound
         * ONLY because this submit is synchronous: virtio_gpu_submit_3d does
         * not return until the device has consumed the command, so nothing
         * the caller passed can be freed underneath it. The moment submission
         * becomes asynchronous -- which is the obvious next performance move
         * -- this becomes a use-after-free and the handles must be validated
         * and referenced here. Written down because the bug it would cause
         * would look like random host GL corruption. */
        int rc = virtio_gpu_submit_3d(ctx, (const void *)(uintptr_t)eb.command, eb.size);
        if (rc != 0) { drm_seen(req, "EXECBUFFER: the device refused SUBMIT_3D", E_INVAL); return E_INVAL; }
        /* No out-fence fd: we have already waited. Reporting -1 is what an
         * unset fence looks like, and Mesa handles it. */
        if (eb.fence_fd >= 0) { eb.fence_fd = -1; memcpy(uarg, &eb, sizeof eb); }
        drm_seen(req, "EXECBUFFER", 0);
        return 0;
    }

    case DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST:
    case DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST: {
        struct drm_virtgpu_3d_transfer tr;
        if (!uarg || !vmm_user_ok((uint64_t)(uintptr_t)uarg, sizeof tr)) return E_FAULT;
        memcpy(&tr, uarg, sizeof tr);
        struct drm_bo *b = bo_of(tr.bo_handle);
        if (!b) return E_INVAL;
        int node = drm_node_of_fd(fd);
        uint32_t ctx = node_ctx(node);
        if (!ctx) return E_NODEV;
        int to_host = (req == DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST);
        int rc = virtio_gpu_transfer_3d(ctx, b->res_id, to_host,
                                        tr.box.x, tr.box.y, tr.box.z,
                                        tr.box.w, tr.box.h, tr.box.d,
                                        tr.offset, tr.level, tr.stride, tr.layer_stride);
        if (rc != 0) {
            drm_seen(req, to_host ? "TRANSFER_TO_HOST refused" : "TRANSFER_FROM_HOST refused", E_INVAL);
            return E_INVAL;
        }
        drm_seen(req, to_host ? "TRANSFER_TO_HOST" : "TRANSFER_FROM_HOST", 0);
        return 0;
    }

    case DRM_IOCTL_VIRTGPU_WAIT: {
        struct drm_virtgpu_3d_wait wt;
        if (!uarg || !vmm_user_ok((uint64_t)(uintptr_t)uarg, sizeof wt)) return E_FAULT;
        memcpy(&wt, uarg, sizeof wt);
        if (!bo_of(wt.handle)) return E_INVAL;
        /* NOTHING TO WAIT FOR, HONESTLY. Every command this node issues is
         * complete before its ioctl returns, so an object is never busy. This
         * is a true answer today and a lie the instant submission goes
         * asynchronous -- at which point this needs real fences, not a
         * relaxation of the check. */
        drm_seen(req, "WAIT (submission is synchronous: never busy)", 0);
        return 0;
    }

    case DRM_IOCTL_VIRTGPU_CONTEXT_INIT:
        /* We report VIRTGPU_PARAM_CONTEXT_INIT as 0, so a well-behaved Mesa
         * does not call this. Answering EINVAL rather than ENOTTY says "the
         * kernel understood and declines", which is what the feature bit
         * already told it. */
        drm_seen(req, "CONTEXT_INIT (we advertise it as unsupported)", E_INVAL);
        return E_INVAL;

    default:
        /* AND SAY SO. An ioctl nobody named is the thing Mesa will have
         * fallen back over, and "ENOTTY on 0x...." with the number is enough
         * to look it up; silence is not. */
        drm_seen(req, "an ioctl this node does not implement", E_NOTTY);
        return E_NOTTY;
    }
}
