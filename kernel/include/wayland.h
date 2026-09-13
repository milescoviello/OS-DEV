/* wayland.h — a Wayland compositor inside OS-DEV's own window manager (M1978).
 *
 * The user's call, and the right one: not a ported X server. The protocol is a
 * Unix-domain socket plus shared-memory buffers, and we have both. An X server
 * would be a far larger surface for a worse fit, and it would put a foreign
 * server in charge of windows instead of kernel/desktop.c.
 *
 * A Wayland compositor IS a window manager, so this is additive to the desktop
 * rather than parallel to it: a committed wl_surface becomes the contents of an
 * OS-DEV window, and our existing keyboard/mouse events go back out as
 * wl_keyboard/wl_pointer.
 */
#pragma once
#include <stdint.h>

/* Bring the display up: bind the socket clients connect to. 0/-1. */
extern int g_wl_verbose;        /* -append wlverbose: trace every message both ways */
int  wl_compositor_init(void);
/* One non-blocking pass: accept new clients, drain and answer their messages.
 * Called from the compositor task; never blocks. Returns messages handled. */
int  wl_compositor_poll(void);
void wl_server_task(void);      /* the display server's own task (M1978) */
/* Counters for the boot self-test to assert against, rather than inferring
 * success from output that could have come from anywhere. */
unsigned wl_clients_connected(void);
unsigned wl_messages_handled(void);
unsigned wl_globals_sent(void);
unsigned wl_commits(void);      /* surfaces committed with a readable buffer (M1979) */
uint32_t wl_last_pixel(void);   /* top-left pixel of the last commit */
uint32_t wl_last_width(void);
uint32_t wl_last_height(void);
/* The last committed surface, for the window manager to draw. NULL until one
 * exists; the pixels are the client's own memory, not a copy. (M1980) */
const uint32_t *wl_surface_pixels(uint32_t *w, uint32_t *h, uint32_t *stride);
