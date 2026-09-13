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
#include "xdg-shell-client-protocol.h"
#include <poll.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <xkbcommon/xkbcommon.h>

static int n_globals;
static struct wl_compositor *comp;
static struct wl_shm *shm;
static struct xdg_wm_base *wm_base;
static struct wl_seat *seat;
static struct wl_keyboard *kbd;
static struct wl_pointer *ptr;
static int configured;
static int n_keys, n_motion, n_buttons;
/* libxkbcommon: the SAME library GTK uses to turn a keycode into text. */
static struct xkb_context *xkb_ctx;
static struct xkb_keymap  *xkb_km;
static struct xkb_state   *xkb_st;

/* The listeners below take every event in the interface because libwayland
 * calls through a table -- a NULL entry for an event the compositor sends is a
 * crash, not a no-op. */
static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t sz) {
    (void)d;(void)k;
    printf("LXWL-INPUT: keymap format %u, fd %d, %u bytes\n", f, fd, sz); fflush(stdout);
    /* This is exactly what GTK does with the event: map the descriptor the
     * compositor passed, hand the text to libxkbcommon, and keep the compiled
     * keymap for the rest of the connection. If any of it fails there is no
     * text input -- only raw keycodes, which no toolkit will use. */
    char *map = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        printf("LXWL-XKB: mmap of the keymap fd FAILED\n"); fflush(stdout); close(fd); return;
    }
    /* NO_DEFAULT_INCLUDES: the keymap must be self-contained, because the guest
     * has no /usr/share/X11/xkb tree for an `include` to resolve against. */
    xkb_ctx = xkb_context_new(XKB_CONTEXT_NO_DEFAULT_INCLUDES);
    if (xkb_ctx)
        xkb_km = xkb_keymap_new_from_string(xkb_ctx, map, XKB_KEYMAP_FORMAT_TEXT_V1, 0);
    munmap(map, sz); close(fd);
    if (!xkb_km) { printf("LXWL-XKB: the keymap did NOT compile\n"); fflush(stdout); return; }
    xkb_st = xkb_state_new(xkb_km);
    printf("LXWL-XKB: compiled the compositor's keymap (%u bytes, %u keycodes)\n",
           sz, (unsigned)(xkb_keymap_max_keycode(xkb_km) - xkb_keymap_min_keycode(xkb_km) + 1));
    fflush(stdout);
}
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su, struct wl_array *keys) {
    (void)d;(void)k;(void)s;(void)su;(void)keys;
    printf("LXWL-INPUT: keyboard entered the surface\n"); fflush(stdout);
}
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *su) { (void)d;(void)k;(void)s;(void)su; }
static void kb_key(void *d, struct wl_keyboard *k, uint32_t s, uint32_t t, uint32_t key, uint32_t st) {
    (void)d;(void)k;(void)s;(void)t;
    if (st) {
        n_keys++;
        printf("LXWL-KEY: evdev keycode %u pressed\n", key); fflush(stdout);
        if (xkb_st) {
            /* XKB keycodes are evdev + 8. Getting that offset wrong yields a
             * plausible WRONG character for every key rather than an error. */
            char txt[32] = {0}, nm[64] = {0};
            xkb_keysym_t sym = xkb_state_key_get_one_sym(xkb_st, key + 8);
            xkb_keysym_get_name(sym, nm, sizeof nm);
            xkb_state_key_get_utf8(xkb_st, key + 8, txt, sizeof txt);
            printf("LXWL-XKB-KEY: evdev %u -> keysym %s, text \"%s\"\n", key, nm, txt);
            fflush(stdout);
        }
    }
}
static void kb_mods(void *d, struct wl_keyboard *k, uint32_t s, uint32_t dep, uint32_t lat, uint32_t lock, uint32_t grp) {
    (void)d;(void)k;(void)s;
    /* Feed the compositor's modifier state into xkb, or Shift+a stays 'a'. */
    if (xkb_st) xkb_state_update_mask(xkb_st, dep, lat, lock, 0, 0, grp);
}
static void kb_repeat(void *d, struct wl_keyboard *k, int32_t rate, int32_t delay) { (void)d;(void)k;(void)rate;(void)delay; }
static const struct wl_keyboard_listener kbd_listener = {
    kb_keymap, kb_enter, kb_leave, kb_key, kb_mods, kb_repeat
};

static void pt_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *su, wl_fixed_t x, wl_fixed_t y) {
    (void)d;(void)p;(void)s;(void)su;
    printf("LXWL-INPUT: pointer entered at %d,%d\n", wl_fixed_to_int(x), wl_fixed_to_int(y)); fflush(stdout);
}
static void pt_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *su) {
    (void)d;(void)p;(void)s;(void)su;
    printf("LXWL-LEAVE: pointer left the surface\n"); fflush(stdout);
}
static void pt_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y) {
    (void)d;(void)p;(void)t;
    if (n_motion < 3) { printf("LXWL-MOTION: %d,%d\n", wl_fixed_to_int(x), wl_fixed_to_int(y)); fflush(stdout); }
    n_motion++;
}
static void pt_button(void *d, struct wl_pointer *p, uint32_t s, uint32_t t, uint32_t b, uint32_t st) {
    (void)d;(void)p;(void)s;(void)t;
    if (st) { n_buttons++; printf("LXWL-BUTTON: 0x%x pressed\n", b); fflush(stdout); }
}
static void pt_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t a, wl_fixed_t v) { (void)d;(void)p;(void)t;(void)a;(void)v; }
static void pt_frame(void *d, struct wl_pointer *p) { (void)d;(void)p; }
static void pt_axis_src(void *d, struct wl_pointer *p, uint32_t s) { (void)d;(void)p;(void)s; }
static void pt_axis_stop(void *d, struct wl_pointer *p, uint32_t t, uint32_t a) { (void)d;(void)p;(void)t;(void)a; }
static void pt_axis_disc(void *d, struct wl_pointer *p, uint32_t a, int32_t v) { (void)d;(void)p;(void)a;(void)v; }
static void pt_axis_v120(void *d, struct wl_pointer *p, uint32_t a, int32_t v) { (void)d;(void)p;(void)a;(void)v; }
static void pt_axis_dir(void *d, struct wl_pointer *p, uint32_t a, uint32_t dir) { (void)d;(void)p;(void)a;(void)dir; }
static const struct wl_pointer_listener ptr_listener = {
    pt_enter, pt_leave, pt_motion, pt_button, pt_axis, pt_frame,
    pt_axis_src, pt_axis_stop, pt_axis_disc, pt_axis_v120, pt_axis_dir
};

static void xs_configure(void *d, struct xdg_surface *xs, uint32_t serial) {
    (void)d;
    xdg_surface_ack_configure(xs, serial);   /* required: the surface is not mapped until this */
    configured = 1;
}
static const struct xdg_surface_listener xs_listener = { xs_configure };

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
    else if (!strcmp(iface, "wl_seat"))
        seat = wl_registry_bind(reg, name, &wl_seat_interface, version < 5 ? version : 5);
    else if (!strcmp(iface, "xdg_wm_base"))
        wm_base = wl_registry_bind(reg, name, &xdg_wm_base_interface, version < 3 ? version : 3);
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

    /* xdg_shell: the protocol that turns a bare surface into a real WINDOW --
     * one the client can title, and that the compositor can size. GTK and
     * Firefox do exactly this, and a compositor that does not answer the
     * initial configure leaves them waiting forever having done nothing wrong.
     * The ordering below is the protocol's, not a preference: commit with NO
     * buffer first, wait for configure, acknowledge it, and only then attach. */
    if (!wm_base) { printf("LXWL: xdg_wm_base was not advertised\n"); fflush(stdout); return 14; }
    struct xdg_surface *xs = xdg_wm_base_get_xdg_surface(wm_base, surf);
    struct xdg_toplevel *tl = xdg_surface_get_toplevel(xs);
    xdg_surface_add_listener(xs, &xs_listener, NULL);
    xdg_toplevel_set_title(tl, "OS-DEV Wayland demo");
    wl_surface_commit(surf);                       /* the initial, buffer-less commit */
    if (wl_display_roundtrip(dpy) < 0) { printf("LXWL: configure roundtrip failed\n"); fflush(stdout); return 15; }
    if (!configured) { printf("LXWL: never received xdg_surface.configure\n"); fflush(stdout); return 16; }
    printf("LXWL-XDG: toplevel configured and acknowledged\n"); fflush(stdout);

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

    /* --- INPUT ------------------------------------------------------------ *
     * A window that can be drawn to but not typed into is not a usable window.
     * Ask the seat for a keyboard and a pointer and report what arrives; the
     * test drives real keystrokes and mouse events at the VM and checks they
     * come out here. */
    if (seat) {
        kbd = wl_seat_get_keyboard(seat);
        ptr = wl_seat_get_pointer(seat);
        if (kbd) wl_keyboard_add_listener(kbd, &kbd_listener, NULL);
        if (ptr) wl_pointer_add_listener(ptr, &ptr_listener, NULL);
        wl_display_roundtrip(dpy);
        printf("LXWL-INPUT: keyboard=%s pointer=%s, waiting for events\n",
               kbd ? "yes" : "no", ptr ? "yes" : "no");
        fflush(stdout);
        /* Dispatch until the harness has driven input at us. The desktop comes
         * up AFTER this client does -- the compositor hands over once a surface
         * exists -- so the wait has to outlast the desktop's own startup, or
         * the client exits before there is anything to send it. */
        for (int i = 0; i < 4000 && (n_motion < 1 || n_buttons < 1 || n_keys < 1); i++) {
            int d = wl_display_dispatch(dpy);
            if (d < 0) {
                printf("LXWL-INPUT: dispatch failed (err %d) after %d motion\n",
                       wl_display_get_error(dpy), n_motion);
                fflush(stdout);
                break;
            }
        }
        printf("LXWL-INPUT-RESULT: %d key event(s), %d motion, %d button\n",
               n_keys, n_motion, n_buttons);
        fflush(stdout);
    }

    wl_display_disconnect(dpy);
    return 0;
}
