/* lxdrm — does OS-DEV offer a DRM render node a GL driver could use? (M2347)
 *
 * A PROBE SMALLER THAN THE PROGRAM. The program is Mesa: ~40 MB of gallium
 * that opens /dev/dri/renderD128, asks four questions, and if any answer is
 * wrong falls back to software with a message nobody sees. Debugging the
 * kernel through it would mean reading a swrast fallback as "the ioctl is
 * broken", which is the shape of failure this project has been burned by
 * repeatedly. So: ask the same four questions directly, print every answer,
 * and name which one failed.
 *
 * The questions, in the order Mesa asks them:
 *   1. DRM_IOCTL_VERSION            -- who are you? ("virtio_gpu")
 *   2. GETPARAM(3D_FEATURES)        -- can you do 3D at all?
 *   3. GETPARAM(CAPSET_QUERY_FIX)   -- is GET_CAPS the fixed ABI or the old one?
 *   4. GET_CAPS(virgl2)             -- hand over the renderer's capabilities
 *
 * Uses the REAL uapi headers, not hand-computed ioctl numbers. _IOC arithmetic
 * that is one struct-size off produces ENOTTY, which is indistinguishable from
 * "not implemented" -- so the numbers come from the same header Mesa compiles
 * against or the probe proves nothing. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <drm/drm.h>
#include <drm/virtgpu_drm.h>

static int fails;
#define OK(c, ...)  do { printf("LXDRM: " __VA_ARGS__); printf("\n"); if (!(c)) fails++; } while (0)

int main(void) {
    const char *node = "/dev/dri/renderD128";
    int fd = open(node, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("LXDRM: open(%s) FAILED: %s\n", node, strerror(errno));
        printf("LXDRM: RESULT FAIL (no render node -- nothing else can be asked)\n");
        return 1;
    }
    printf("LXDRM: open(%s) = %d\n", node, fd);

    /* 1. Who are you. */
    {   char name[64] = {0}, date[64] = {0}, desc[64] = {0};
        struct drm_version v;
        memset(&v, 0, sizeof v);
        v.name_len = sizeof name - 1; v.name = name;
        v.date_len = sizeof date - 1; v.date = date;
        v.desc_len = sizeof desc - 1; v.desc = desc;
        int r = ioctl(fd, DRM_IOCTL_VERSION, &v);
        OK(r == 0 && name[0], "VERSION -> rc %d (%s), driver \"%s\" %d.%d.%d, desc \"%s\"",
           r, r ? strerror(errno) : "ok", name, v.version_major, v.version_minor,
           v.version_patchlevel, desc);
    }

    /* 2 + 3. The two params Mesa's virgl driver refuses to load without. */
    {   struct drm_virtgpu_getparam gp;
        uint64_t val = 0;
        memset(&gp, 0, sizeof gp);
        gp.param = VIRTGPU_PARAM_3D_FEATURES; gp.value = (uint64_t)(uintptr_t)&val;
        int r = ioctl(fd, DRM_IOCTL_VIRTGPU_GETPARAM, &gp);
        OK(r == 0 && val, "GETPARAM(3D_FEATURES) -> rc %d (%s), value %llu",
           r, r ? strerror(errno) : "ok", (unsigned long long)val);

        val = 0;
        memset(&gp, 0, sizeof gp);
        gp.param = VIRTGPU_PARAM_CAPSET_QUERY_FIX; gp.value = (uint64_t)(uintptr_t)&val;
        r = ioctl(fd, DRM_IOCTL_VIRTGPU_GETPARAM, &gp);
        OK(r == 0, "GETPARAM(CAPSET_QUERY_FIX) -> rc %d (%s), value %llu",
           r, r ? strerror(errno) : "ok", (unsigned long long)val);
    }

    /* 4. The capability blob itself. Its SIZE is the assertion: the kernel
     * reported 1384 bytes for virgl2 at boot, so a short read means the
     * copy-out is wrong even though the ioctl "succeeded". */
    {   static unsigned char caps[4096];
        struct drm_virtgpu_get_caps gc;
        memset(&gc, 0, sizeof gc);
        memset(caps, 0, sizeof caps);
        gc.cap_set_id = 2;                 /* VIRGL2 */
        gc.cap_set_ver = 2;
        gc.addr = (uint64_t)(uintptr_t)caps;
        gc.size = 1384;
        int r = ioctl(fd, DRM_IOCTL_VIRTGPU_GET_CAPS, &gc);
        int nonzero = 0;
        for (unsigned i = 0; i < 1384; i++) if (caps[i]) nonzero++;
        OK(r == 0 && nonzero > 0,
           "GET_CAPS(virgl2, 1384 bytes) -> rc %d (%s), %d non-zero byte(s) of 1384",
           r, r ? strerror(errno) : "ok", nonzero);
        if (r == 0 && nonzero)
            printf("LXDRM: first 8 words: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                   ((uint32_t *)caps)[0], ((uint32_t *)caps)[1], ((uint32_t *)caps)[2],
                   ((uint32_t *)caps)[3], ((uint32_t *)caps)[4], ((uint32_t *)caps)[5],
                   ((uint32_t *)caps)[6], ((uint32_t *)caps)[7]);
    }

    close(fd);
    printf("LXDRM: RESULT %s (%d check(s) failed)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
