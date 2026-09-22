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
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>

static int fails;
#define CHK(c, ...) do { printf("LXGL: " __VA_ARGS__); printf("\n"); if (!(c)) { fails++; } } while (0)

int main(void) {
    /* Say what we are asking for, so a log with no GL in it at all is still
     * distinguishable from one where this never ran. */
    printf("LXGL: start -- asking EGL for a surfaceless display\n");
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
