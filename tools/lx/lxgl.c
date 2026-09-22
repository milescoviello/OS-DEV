/* lxgl — is there a real GPU behind our render node? (M2349)
 *
 * The chain this exercises, end to end, is the whole point of the GPU work:
 *
 *     lxgl -> libEGL -> Mesa virgl -> /dev/dri/renderD128 -> virtio-gpu
 *          -> QEMU virtio-gpu-gl -> virglrenderer -> host GL -> Arrow Lake iGPU
 *
 * Eight links. Firefox exercises the same eight and reports a failure in any
 * of them as "WebGL is slow", because it silently falls back to SWGL -- so
 * asking through Firefox tells you nothing about which link broke. This asks
 * directly and prints what each step answered.
 *
 * THE ASSERTION IS THE RENDERER STRING AND THE PIXEL, not that EGL
 * initialised. Mesa will happily bring up a context on llvmpipe or softpipe
 * and report success; GL_RENDERER is how you tell which one you got, and a
 * clear-then-readback proves something actually executed rather than merely
 * configured. "virgl" in the renderer string is the answer we want; "llvmpipe"
 * or "softpipe" means the software fallback, which is the state we are trying
 * to leave.
 *
 * Surfaceless on purpose: this is a compute/offscreen test, and dragging in a
 * Wayland surface would mean a failure in the compositor path reads as a
 * failure in the GPU path. One question at a time. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <dirent.h>
#include <limits.h>
#include <xf86drm.h>
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>

static int fails;
#define CHK(c, ...) do { printf("LXGL: " __VA_ARGS__); printf("\n"); if (!(c)) { fails++; } } while (0)

int main(void) {
    /* Say what we are asking for, so a log with no GL in it at all is still
     * distinguishable from one where this never ran. */
    printf("LXGL: start -- asking EGL for a surfaceless display\n");
    /* MESA LOGS TO STDERR, AND IT PRINTED NOTHING ON THE FIRST RUN (M2351).
     * Unbuffered, and echoed through stdout as well, so "Mesa said nothing"
     * means Mesa said nothing rather than "Mesa's buffer was never flushed
     * because the process exited through a path that does not flush". */
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("LXGL: env EGL_LOG_LEVEL=%s MESA_DEBUG=%s LD_LIBRARY_PATH=%.80s\n",
           getenv("EGL_LOG_LEVEL") ? getenv("EGL_LOG_LEVEL") : "(unset)",
           getenv("MESA_DEBUG") ? getenv("MESA_DEBUG") : "(unset)",
           getenv("LD_LIBRARY_PATH") ? getenv("LD_LIBRARY_PATH") : "(unset)");

    /* WHAT MESA WILL SEE WHEN IT OPENS THE NODE ITSELF.
     *
     * Mesa's surfaceless platform loops renderD128..renderD191, opens each,
     * and hands the fd to libdrm. libdrm's drmGetDevice2 begins with
     * fstat(fd) and REQUIRES S_ISCHR and a DRM major/minor -- 226 and >=128
     * for a render node -- before it will look at anything else. If our fstat
     * reports a regular file, every later step is unreachable and the only
     * symptom is EGL_NOT_INITIALIZED, which is what the first run got. Print
     * it, because it is a one-line answer to a question that would otherwise
     * cost a boot each to guess at. */
    {
        int t = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC);
        printf("LXGL: open(/dev/dri/renderD128) = %d%s\n", t, t < 0 ? strerror(errno) : "");
        if (t >= 0) {
            struct stat st;
            if (fstat(t, &st) == 0)
                printf("LXGL: fstat -> mode 0%o (S_ISCHR=%d), rdev major %u minor %u, size %lld\n",
                       (unsigned)st.st_mode, S_ISCHR(st.st_mode) ? 1 : 0,
                       (unsigned)major(st.st_rdev), (unsigned)minor(st.st_rdev),
                       (long long)st.st_size);
            else
                printf("LXGL: fstat FAILED: %s\n", strerror(errno));
            close(t);
        }
        /* AND CAN IT BE READ AS A DIRECTORY? libdrm's drmGetDevices2 -- which
         * is what builds EGL's device list, and therefore the thing that
         * decides whether a hardware driver is even attempted -- enumerates by
         * opendir("/dev/dri") and readdir, not by opening a known name. A
         * directory that stats correctly and lists nothing yields an empty
         * device list, which surfaces three layers up as "DRI2: failed to load
         * driver". (M2353) */
        {   DIR *d = opendir("/dev/dri");
            if (!d) printf("LXGL: opendir(/dev/dri) FAILED: %s\n", strerror(errno));
            else {
                struct dirent *e; int n = 0;
                printf("LXGL: readdir(/dev/dri):");
                while ((e = readdir(d))) { printf(" %s", e->d_name); n++; }
                printf("  (%d entr%s)\n", n, n == 1 ? "y" : "ies");
                closedir(d);
            }
        }
        /* And the two sysfs steps libdrm takes next, in its order, because a
         * failure in either is silent in every log above this one. */
        {   struct stat s1;
            printf("LXGL: stat(/sys/dev/char/226:128/device/drm) -> %s\n",
                   stat("/sys/dev/char/226:128/device/drm", &s1) == 0 ? "ok" : strerror(errno));
            char rp[4096];
            const char *r2 = realpath("/sys/dev/char/226:128/device/subsystem", rp);
            printf("LXGL: realpath(.../device/subsystem) -> %s\n", r2 ? r2 : strerror(errno));
        }
        /* ASK libdrm DIRECTLY (M2353). Every prerequisite this probe checks now
         * holds -- the node opens, fstats as a character device with the right
         * rdev, appears in readdir, and its sysfs subsystem link resolves to
         * /sys/bus/virtio -- and Mesa still says "DRI2: failed to load driver"
         * with no reason. Mesa's device list comes from drmGetDevices2, and
         * its driver name from drmGetVersion; asking both here separates "the
         * kernel is missing something libdrm needs" from "libdrm is fine and
         * Mesa's lookup is the problem", which need completely different
         * fixes. One level down is cheaper than one more guess. */
        {   drmVersionPtr v = 0;
            int t2 = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC);
            if (t2 >= 0) {
                v = drmGetVersion(t2);
                if (v) {
                    printf("LXGL: drmGetVersion -> \"%s\" %d.%d.%d (name_len %d)\n",
                           v->name ? v->name : "(null)", v->version_major,
                           v->version_minor, v->version_patchlevel, v->name_len);
                    drmFreeVersion(v);
                } else printf("LXGL: drmGetVersion FAILED\n");
                printf("LXGL: drmGetNodeTypeFromFd -> %d (2 = DRM_NODE_RENDER)\n",
                       drmGetNodeTypeFromFd(t2));
                drmDevicePtr one = 0;
                int r1 = drmGetDevice2(t2, 0, &one);
                printf("LXGL: drmGetDevice2(fd) -> %d%s", r1, r1 ? " " : "");
                if (r1) printf("(%s)\n", strerror(-r1));
                else {
                    printf(", bustype %d, available_nodes 0x%x\n",
                           one->bustype, one->available_nodes);
                    drmFreeDevice(&one);
                }
                close(t2);
            }
            drmDevicePtr devs[8];
            int nd = drmGetDevices2(0, devs, 8);
            printf("LXGL: drmGetDevices2 -> %d device(s)%s\n", nd,
                   nd < 0 ? strerror(-nd) : "");
            for (int i = 0; i < nd; i++) {
                printf("LXGL:   device %d: bustype %d, available_nodes 0x%x\n",
                       i, devs[i]->bustype, devs[i]->available_nodes);
            }
            if (nd > 0) drmFreeDevices(devs, nd);
        }
        struct stat sd;
        printf("LXGL: stat(/dev/dri) -> %s%s\n",
               stat("/dev/dri", &sd) == 0 ? "ok" : "FAILED: ",
               stat("/dev/dri", &sd) == 0 ? (S_ISDIR(sd.st_mode) ? " (a directory)" : " (NOT a directory)")
                                          : strerror(errno));
    }
    fflush(stdout);

    EGLDisplay dpy = EGL_NO_DISPLAY;
    PFNEGLGETPLATFORMDISPLAYEXTPROC getpd =
        (PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
    if (getpd) dpy = getpd(EGL_PLATFORM_SURFACELESS_MESA, EGL_DEFAULT_DISPLAY, NULL);
    if (dpy == EGL_NO_DISPLAY) dpy = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    CHK(dpy != EGL_NO_DISPLAY, "eglGetDisplay -> %p", (void *)dpy);
    if (dpy == EGL_NO_DISPLAY) { printf("LXGL: RESULT FAIL (no EGL display)\n"); return 1; }

    EGLint maj = 0, min = 0;
    EGLBoolean ok = eglInitialize(dpy, &maj, &min);
    CHK(ok, "eglInitialize -> %d, EGL %d.%d, vendor \"%s\"",
        (int)ok, maj, min, ok ? eglQueryString(dpy, EGL_VENDOR) : "-");
    if (!ok) { printf("LXGL: RESULT FAIL (eglInitialize, 0x%x)\n", eglGetError()); return 1; }
    printf("LXGL: EGL extensions: %.400s\n", eglQueryString(dpy, EGL_EXTENSIONS));

    eglBindAPI(EGL_OPENGL_ES_API);
    EGLint cfga[] = { EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
                      EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
                      EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8,
                      EGL_NONE };
    EGLConfig cfg; EGLint ncfg = 0;
    ok = eglChooseConfig(dpy, cfga, &cfg, 1, &ncfg);
    CHK(ok && ncfg > 0, "eglChooseConfig -> %d, %d config(s)", (int)ok, ncfg);
    if (!ok || !ncfg) { printf("LXGL: RESULT FAIL (no config)\n"); return 1; }

    EGLint ctxa[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    EGLContext ctx = eglCreateContext(dpy, cfg, EGL_NO_CONTEXT, ctxa);
    CHK(ctx != EGL_NO_CONTEXT, "eglCreateContext -> %p", (void *)ctx);
    if (ctx == EGL_NO_CONTEXT) { printf("LXGL: RESULT FAIL (no context, 0x%x)\n", eglGetError()); return 1; }

    EGLint pba[] = { EGL_WIDTH, 64, EGL_HEIGHT, 64, EGL_NONE };
    EGLSurface surf = eglCreatePbufferSurface(dpy, cfg, pba);
    /* Surfaceless contexts need no surface; a pbuffer is nicer if available. */
    ok = eglMakeCurrent(dpy, surf, surf, ctx);
    if (!ok && surf == EGL_NO_SURFACE)
        ok = eglMakeCurrent(dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, ctx);
    CHK(ok, "eglMakeCurrent(surface %p) -> %d", (void *)surf, (int)ok);
    if (!ok) { printf("LXGL: RESULT FAIL (makeCurrent, 0x%x)\n", eglGetError()); return 1; }

    /* THE ANSWER. */
    const char *vend = (const char *)glGetString(GL_VENDOR);
    const char *rend = (const char *)glGetString(GL_RENDERER);
    const char *vers = (const char *)glGetString(GL_VERSION);
    printf("LXGL: GL_VENDOR   = %s\n", vend ? vend : "(null)");
    printf("LXGL: GL_RENDERER = %s\n", rend ? rend : "(null)");
    printf("LXGL: GL_VERSION  = %s\n", vers ? vers : "(null)");
    int hw = rend && strstr(rend, "virgl") != NULL;
    CHK(hw, "is this the HOST GPU? %s", hw ? "YES -- virgl"
        : "NO -- this is a SOFTWARE renderer, the fallback we are trying to leave");

    /* Did anything actually execute? Clear to a known colour and read it back.
     * A configured-but-dead context passes every check above and fails this. */
    if (surf != EGL_NO_SURFACE) {
        unsigned char px[4] = {0, 0, 0, 0};
        glViewport(0, 0, 64, 64);
        glClearColor(0.0f, 1.0f, 0.0f, 1.0f);            /* opaque green */
        glClear(GL_COLOR_BUFFER_BIT);
        glFinish();
        glReadPixels(32, 32, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, px);
        GLenum e = glGetError();
        CHK(e == GL_NO_ERROR && px[1] > 200 && px[0] < 60 && px[2] < 60,
            "clear+readback -> rgba(%u,%u,%u,%u), glGetError 0x%x (want green)",
            px[0], px[1], px[2], px[3], e);
    } else {
        printf("LXGL: no pbuffer, skipping the readback (context is surfaceless)\n");
    }

    printf("LXGL: RESULT %s (%d check(s) failed)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
