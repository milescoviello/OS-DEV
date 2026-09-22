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
#include <sys/mman.h>
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

    /* ---- part 2: an object, a mapping, and a round trip THROUGH the host ----
     *
     * Everything above is a conversation about capabilities. This is the part
     * that proves the host actually holds our pages: create a 64x64 render
     * target, mmap its guest backing, write a pattern, TRANSFER_TO_HOST, wipe
     * the guest copy, TRANSFER_FROM_HOST, and compare.
     *
     * The wipe is the whole point. Without it the comparison passes whether or
     * not either transfer did anything -- the bytes would still be in the
     * buffer we wrote them to. It is the same trap as an fps counter on a page
     * that never started: the check has to be one that a do-nothing
     * implementation FAILS. */
    {
        struct drm_virtgpu_resource_create rc;
        memset(&rc, 0, sizeof rc);
        rc.target = 2;              /* PIPE_TEXTURE_2D */
        rc.format = 1;              /* VIRGL_FORMAT_B8G8R8A8_UNORM */
        rc.bind   = 2;              /* PIPE_BIND_RENDER_TARGET */
        rc.width = 64; rc.height = 64; rc.depth = 1; rc.array_size = 1;
        rc.size = 64 * 64 * 4; rc.stride = 64 * 4;
        int r = ioctl(fd, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE, &rc);
        OK(r == 0 && rc.bo_handle && rc.res_handle,
           "RESOURCE_CREATE 64x64 BGRA -> rc %d (%s), bo_handle %u, res_handle %u",
           r, r ? strerror(errno) : "ok", rc.bo_handle, rc.res_handle);
        if (r != 0) { printf("LXDRM: RESULT FAIL (%d)\n", ++fails); close(fd); return 1; }

        struct drm_virtgpu_map mp;
        memset(&mp, 0, sizeof mp);
        mp.handle = rc.bo_handle;
        r = ioctl(fd, DRM_IOCTL_VIRTGPU_MAP, &mp);
        OK(r == 0, "MAP(handle %u) -> rc %d (%s), offset 0x%llx",
           rc.bo_handle, r, r ? strerror(errno) : "ok", (unsigned long long)mp.offset);

        unsigned char *p = MAP_FAILED;
        if (r == 0) {
            p = mmap(NULL, rc.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)mp.offset);
            OK(p != MAP_FAILED, "mmap(%u bytes at that offset) -> %p (%s)",
               rc.size, p, p == MAP_FAILED ? strerror(errno) : "ok");
        }

        if (p != MAP_FAILED) {
            /* A pattern no zero-fill and no memcpy-of-itself can produce. */
            for (unsigned i = 0; i < rc.size; i++) p[i] = (unsigned char)(i * 7 + 13);

            struct drm_virtgpu_3d_transfer_to_host tr;   /* same layout as _from_host */
            memset(&tr, 0, sizeof tr);
            tr.bo_handle = rc.bo_handle;
            tr.box.w = 64; tr.box.h = 64; tr.box.d = 1;
            tr.stride = 64 * 4;
            r = ioctl(fd, DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST, &tr);
            OK(r == 0, "TRANSFER_TO_HOST(64x64) -> rc %d (%s)", r, r ? strerror(errno) : "ok");

            /* WIPE, so the read-back cannot be satisfied by what is already here. */
            memset(p, 0, rc.size);
            int nonzero_after_wipe = 0;
            for (unsigned i = 0; i < rc.size; i++) if (p[i]) { nonzero_after_wipe = 1; break; }
            OK(!nonzero_after_wipe, "the guest buffer is zero after the wipe (so the "
               "read-back below cannot pass by accident)");

            r = ioctl(fd, DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST, &tr);
            OK(r == 0, "TRANSFER_FROM_HOST(64x64) -> rc %d (%s)", r, r ? strerror(errno) : "ok");

            unsigned bad = 0, first_bad = 0;
            for (unsigned i = 0; i < rc.size; i++)
                if (p[i] != (unsigned char)(i * 7 + 13)) { if (!bad) first_bad = i; bad++; }
            OK(bad == 0, "the pattern came back through the HOST: %u of %u bytes differ%s",
               bad, rc.size, bad ? "" : " -- the host really holds our pages");
            if (bad) printf("LXDRM: first mismatch at %u: got %u, want %u\n",
                            first_bad, p[first_bad], (unsigned char)(first_bad * 7 + 13));

            struct drm_virtgpu_3d_wait wt;
            memset(&wt, 0, sizeof wt);
            wt.handle = rc.bo_handle;
            r = ioctl(fd, DRM_IOCTL_VIRTGPU_WAIT, &wt);
            OK(r == 0, "WAIT(handle %u) -> rc %d (%s)", rc.bo_handle, r, r ? strerror(errno) : "ok");
            munmap(p, rc.size);
        }

        struct drm_gem_close gc;
        memset(&gc, 0, sizeof gc);
        gc.handle = rc.bo_handle;
        r = ioctl(fd, DRM_IOCTL_GEM_CLOSE, &gc);
        OK(r == 0, "GEM_CLOSE(handle %u) -> rc %d (%s)", rc.bo_handle, r, r ? strerror(errno) : "ok");
    }

    close(fd);
    printf("LXDRM: RESULT %s (%d check(s) failed)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
