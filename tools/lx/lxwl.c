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

static int n_globals;
static struct wl_compositor *comp;

static void on_global(void *data, struct wl_registry *reg, uint32_t name,
                      const char *iface, uint32_t version) {
    (void)data;
    n_globals++;
    printf("LXWL-GLOBAL: %s v%u (name %u)\n", iface, version, name);
    fflush(stdout);
    if (!strcmp(iface, "wl_compositor"))
        comp = wl_registry_bind(reg, name, &wl_compositor_interface, version < 4 ? version : 4);
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
    wl_display_disconnect(dpy);
    return 0;
}
