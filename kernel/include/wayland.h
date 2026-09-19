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
/* Answer every outstanding wl_surface.frame callback. Vsync is a periodic
 * signal from the compositor, not a reply to a commit -- and Gecko's refresh
 * driver, which is what paints page content, runs on it. (M2110) */
void wl_frame_tick(void);
unsigned wl_frame_ticks(void);
unsigned wl_frame_callbacks_sent(void);
unsigned wl_frame_requests(void);   /* wl_surface.frame requests RECEIVED -- "never asked" and "answered by the other path" are different things (M2115) */
unsigned wl_frame_by_commit(void);
/* Counters for the boot self-test to assert against, rather than inferring
 * success from output that could have come from anywhere. */
unsigned wl_clients_connected(void);
unsigned wl_messages_handled(void);
unsigned wl_globals_sent(void);
unsigned wl_unhandled_count(void);  /* distinct requests we had no handler for (M1998) */
unsigned wl_commits(void);      /* surfaces committed with a readable buffer (M1979) */
unsigned wl_surfaces(void);     /* wl_compositor.create_surface, ever -- the first thing a client must do to draw (M2081) */
unsigned wl_roles(void);        /* surfaces given a role: toplevel/popup/subsurface/cursor (M2081) */
unsigned wl_destroys(void);     /* objects released back to a client's table (M2058) */
unsigned wl_proto_errors(void); /* wl_display.error events we had to post (M2058) */
uint32_t wl_last_pixel(void);   /* top-left pixel of the DRAWN surface */
uint32_t wl_last_width(void);
uint32_t wl_last_height(void);
/* THE SURFACE THE WINDOW MANAGER DRAWS -- the client's mapped xdg_toplevel,
 * not whichever surface committed most recently (M2058). NULL until one
 * exists; the pixels are the client's own memory, not a copy. (M1980) */
const uint32_t *wl_surface_pixels(uint32_t *w, uint32_t *h, uint32_t *stride);
/* A WINDOW IS A TREE OF SURFACES (M2089). GTK gives an xdg_toplevel no buffer
 * of its own and renders into a subsurface of it, so a compositor that draws
 * one surface draws nothing at all for Firefox. `x`/`y` are relative to the
 * window's origin and MAY be negative -- a subsurface is allowed to overhang,
 * and the caller clips. */
struct wl_layer { int x, y; uint32_t w, h, stride, format; const uint32_t *px; };
/* `format` is the wl_shm format: 0 = ARGB8888 with PREMULTIPLIED alpha,
 * 1 = XRGB8888 whose alpha byte is undefined and must be read as opaque. A
 * compositor that ignores it paints a toolkit's transparent drop shadow as a
 * black border. (M2115) */
int  wl_layers(struct wl_layer *out, int max);       /* how many were written, parents first */
void wl_window_extent(uint32_t *w, uint32_t *h);     /* the bounding box of all of them */
/* ...AND PER CLIENT (M2089). A compositor serves clients, plural. One global
 * window meant the 64x32 test client kept the only slot while Firefox painted
 * full-size frames with nowhere to go. */
int  wl_client_used(int ci);
int  wl_client_window_ready(int ci);   /* 1 = it has a toplevel (or no shell at all) -- M2200 */
int  wl_client_pid(int ci);            /* the pid on the other end of that connection (M2202) */
int  wl_client_count(void);
int  wl_client_layers(int ci, struct wl_layer *out, int max);
void wl_client_extent(int ci, uint32_t *w, uint32_t *h);
const char *wl_client_title_of(int ci);
void wl_largest_window(uint32_t *w, uint32_t *h);
/* Sample the CONTENT area of the biggest window and report what colour
 * dominates it. "Painted" has meant a >=640x480 extent, which chrome around an
 * empty page satisfies just as well as a page. (M2106) */
int wl_page_probe(uint32_t want_rgb);   /* 1 = the page is on screen (M2200) */
void wl_fs_health_line(void);           /* the filesystem's counters, printable with no window (M2225) */
/* The composited window as a small PPM in hex, so it can be LOOKED at rather
 * than inferred from a colour histogram. (M2110) */
void wl_page_dump(void);   /* has ANY client painted a real window? (M2089) */
const char     *wl_surface_title(void);   /* that surface's xdg_toplevel.set_title (M1981) */
/* Drive the dispatcher with a multi-surface client and assert the compositor
 * draws the toplevel rather than the cursor. No socket, no client, no display:
 * it runs inside the same boot as the real libwayland test. (M2058) */
void wl_selftest(void);

/* Input, forwarded from the window manager to the focused client (M1983).
 * Coordinates are SURFACE-relative; keycodes are raw evdev, not characters. */
void     wl_post_pointer_leave(void);
void     wl_post_motion(int x, int y);
void     wl_post_button(int x, int y, unsigned button, int pressed);
void     wl_set_focus_client(int ci);   /* the WM names the focused client; input goes there (M2275) */
void     wl_post_axis(int x, int y, int ticks_down);   /* wl_pointer.axis: vertical scroll (M2245) */
void     wl_post_key(unsigned keycode, int pressed);
unsigned wl_keys_sent(void);
unsigned wl_pointer_sent(void);
