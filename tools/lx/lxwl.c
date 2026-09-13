#define _GNU_SOURCE
/*
 * lxwl.c -- a REAL Wayland client, against OS-DEV's compositor (M1978).
 *
 * Deliberately built on libwayland-client rather than hand-rolled. A hand-rolled
 * client would only prove that our compositor agrees with our own idea of the
 * protocol; libwayland is the same code Firefox and GTK use, so if it is
 * satisfied then the wire format, the message framing, the object ids and the
 * sync/done ordering are right by the standard rather than by agreement.
 *
 * What it exercises:
 *   wl_display_connect()   - the AF_UNIX socket, found through XDG_RUNTIME_DIR
 *   wl_display_get_registry() + roundtrip
 *                          - the framing, and the sync/done ORDERING that tells
 *                            a client the global list is complete. Get that
 *                            wrong and roundtrip hangs forever with no error.
 *   the registry listener  - every global, by name and version
 *   wl_registry_bind()     - binding one for real
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wayland-client.h>
#include <poll.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

static int n_globals;
static struct wl_compositor *comp;
static struct wl_shm *shm;

static void on_global(void *data, struct wl_registry *reg, uint32_t name,
                      const char *iface, uint32_t version) {
    (void)data;
    n_globals++;
    printf("LXWL-GLOBAL: %s v%u (name %u)\n", iface, version, name);
    fflush(stdout);
    if (!strcmp(iface, "wl_compositor"))
        comp = wl_registry_bind(reg, name, &wl_compositor_interface, version < 4 ? version : 4);
    else if (!strcmp(iface, "wl_shm"))
        shm = wl_registry_bind(reg, name, &wl_shm_interface, 1);
}
static void on_global_remove(void *data, struct wl_registry *reg, uint32_t name) {
    (void)data; (void)reg; (void)name;
}
static const struct wl_registry_listener reg_listener = { on_global, on_global_remove };

/* Progress markers. A client that stalls inside libwayland makes no syscalls
 * at all, so from the kernel side it is indistinguishable from one that
 * finished -- these are the only way to see which call did not return. */
#define STEP(msg) do { printf("LXWL-STEP: " msg "\n"); fflush(stdout); } while (0)

int main(void) {
    /* WAYLAND_DEBUG=1 in the environment makes libwayland log every message
     * both ways -- the only view into its own parsing, and what finally showed
     * this client receiving every byte and dispatching none of them. */
    STEP("start");
    struct wl_display *dpy = wl_display_connect(NULL);
    if (!dpy) { printf("LXWL: wl_display_connect failed\n"); fflush(stdout); return 1; }
    STEP("connected");

    struct wl_registry *reg = wl_display_get_registry(dpy);
    if (!reg) { printf("LXWL: get_registry failed\n"); fflush(stdout); return 2; }
    wl_registry_add_listener(reg, &reg_listener, NULL);
    STEP("registry requested, entering roundtrip");

    /* The standard call. It sends wl_display.sync and blocks until the
     * compositor answers `done` -- and every `global` must already have been
     * delivered by then, because events are ordered. Driving the same sequence
     * by hand was how the MSG_DONTWAIT hang was found; using the real API here
     * is the stronger statement. */
    if (wl_display_roundtrip(dpy) < 0) {
        printf("LXWL: roundtrip failed (err %d)\n", wl_display_get_error(dpy));
        fflush(stdout); return 3;
    }
    STEP("first roundtrip returned");
    if (n_globals < 1) { printf("LXWL: no globals advertised\n"); fflush(stdout); return 4; }
    if (!comp) { printf("LXWL: wl_compositor was not advertised\n"); fflush(stdout); return 5; }

    /* A second roundtrip proves the bind above did not desync the stream: a
     * compositor that mis-parsed it would go quiet here. */
    STEP("bound, entering second roundtrip");
    if (wl_display_roundtrip(dpy) < 0) {
        printf("LXWL: post-bind roundtrip failed\n"); fflush(stdout); return 6;
    }

    printf("LXWL: connected, %d globals, wl_compositor bound, 2 roundtrips OK\n", n_globals);
    fflush(stdout);

    /* --- and now actual PIXELS ------------------------------------------- *
     * A surface, a shared-memory pool backed by a memfd, a buffer inside it,
     * and a commit. The pool's descriptor goes to the compositor over the same
     * socket as the protocol (SCM_RIGHTS), so the pixels themselves are never
     * copied -- the compositor reads the very bytes written below. */
    if (!shm) { printf("LXWL: wl_shm was not advertised\n"); fflush(stdout); return 7; }

    const int W = 64, H = 32, STRIDE = W * 4;
    const int SZ = STRIDE * H;
    int fd = memfd_create("lxwl-pool", 0);
    if (fd < 0 || ftruncate(fd, SZ) != 0) { printf("LXWL: memfd setup failed\n"); fflush(stdout); return 8; }
    uint32_t *px = mmap(NULL, SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (px == MAP_FAILED) { printf("LXWL: pool mmap failed\n"); fflush(stdout); return 9; }
    /* A colour the compositor cannot produce by accident. */
    for (int i = 0; i < W * H; i++) px[i] = 0xFF3366CC;

    struct wl_shm_pool *pool = wl_shm_create_pool(shm, fd, SZ);
    if (!pool) { printf("LXWL: create_pool failed\n"); fflush(stdout); return 10; }
    struct wl_buffer *buf = wl_shm_pool_create_buffer(pool, 0, W, H, STRIDE, WL_SHM_FORMAT_ARGB8888);
    if (!buf) { printf("LXWL: create_buffer failed\n"); fflush(stdout); return 11; }
    struct wl_surface *surf = wl_compositor_create_surface(comp);
    if (!surf) { printf("LXWL: create_surface failed\n"); fflush(stdout); return 12; }

    wl_surface_attach(surf, buf, 0, 0);
    wl_surface_damage(surf, 0, 0, W, H);
    wl_surface_commit(surf);
    if (wl_display_roundtrip(dpy) < 0) {
        printf("LXWL: commit roundtrip failed (err %d)\n", wl_display_get_error(dpy));
        fflush(stdout); return 13;
    }

    printf("LXWL-SURFACE: committed %dx%d ARGB8888, %d KiB pool, pixel 0x%08X\n",
           W, H, SZ / 1024, px[0]);
    fflush(stdout);
    wl_display_disconnect(dpy);
    return 0;
}
