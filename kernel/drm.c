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

#define DRM_IOCTL_VERSION                    0xc0406400ul
#define DRM_IOCTL_GET_CAP                    0xc010640cul
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
static struct { int used; } g_node[DRM_NODES];

int drm_open_node(void) {
    if (!virtio_gpu_has_3d()) return -1;
    for (int i = 0; i < DRM_NODES; i++)
        if (!g_node[i].used) { g_node[i].used = 1; return i; }
    return -1;
}
void drm_close_node(int id) {
    if (id >= 0 && id < DRM_NODES) g_node[id].used = 0;
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

long drm_ioctl(int fd, unsigned long req, void *uarg) {
    (void)fd;
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
    case DRM_IOCTL_VIRTGPU_RESOURCE_CREATE:
        drm_seen(req, "RESOURCE_CREATE -- not implemented yet (M2348)", E_NOTTY); return E_NOTTY;
    case DRM_IOCTL_VIRTGPU_RESOURCE_INFO:
        drm_seen(req, "RESOURCE_INFO -- not implemented yet (M2348)", E_NOTTY); return E_NOTTY;
    case DRM_IOCTL_VIRTGPU_MAP:
        drm_seen(req, "MAP -- not implemented yet (M2348)", E_NOTTY); return E_NOTTY;
    case DRM_IOCTL_VIRTGPU_EXECBUFFER:
        drm_seen(req, "EXECBUFFER -- not implemented yet (M2348)", E_NOTTY); return E_NOTTY;
    case DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST:
        drm_seen(req, "TRANSFER_TO_HOST -- not implemented yet (M2348)", E_NOTTY); return E_NOTTY;
    case DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST:
        drm_seen(req, "TRANSFER_FROM_HOST -- not implemented yet (M2348)", E_NOTTY); return E_NOTTY;
    case DRM_IOCTL_VIRTGPU_WAIT:
        drm_seen(req, "WAIT -- not implemented yet (M2348)", E_NOTTY); return E_NOTTY;
    case DRM_IOCTL_VIRTGPU_CONTEXT_INIT:
        drm_seen(req, "CONTEXT_INIT -- not implemented yet (M2348)", E_NOTTY); return E_NOTTY;

    default:
        /* AND SAY SO. An ioctl nobody named is the thing Mesa will have
         * fallen back over, and "ENOTTY on 0x...." with the number is enough
         * to look it up; silence is not. */
        drm_seen(req, "an ioctl this node does not implement", E_NOTTY);
        return E_NOTTY;
    }
}
