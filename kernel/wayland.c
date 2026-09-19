/*
 * wayland.c — the Wayland display server, inside OS-DEV. See wayland.h.
 *
 * --- The wire format, because everything here is built on it ----------------
 * Every message is a header plus arguments, all 32-bit aligned:
 *
 *     u32 object_id
 *     u32 (size << 16) | opcode        <- size COUNTS THE 8-BYTE HEADER
 *     ... arguments ...
 *
 * Arguments are u32/i32/new_id (4 bytes), string (u32 length INCLUDING the
 * trailing NUL, then the bytes padded up to 4), and array (u32 size then bytes
 * padded). There is no framing beyond the size field, so a reader has to
 * accumulate until it has a whole message -- a socket read can split one
 * message or deliver several, and treating a read as a message is the classic
 * way to write a server that works until it doesn't.
 *
 * --- What a client does first ----------------------------------------------
 * libwayland's wl_display_connect creates object 1 (wl_display) locally, then:
 *
 *     -> wl_display@1.get_registry(new_id)     opcode 1
 *     -> wl_display@1.sync(new_id)             opcode 0
 *     <- wl_registry@N.global(name, iface, ver) opcode 0, once per global
 *     <- wl_callback@M.done(serial)             opcode 0
 *     <- wl_display@1.delete_id(M)              opcode 1
 *
 * The sync/done pair is how a client knows the registry is complete: events are
 * ordered, so once `done` arrives for a callback created AFTER get_registry,
 * every `global` has already been delivered. Getting that ordering wrong makes
 * wl_display_roundtrip() hang with no error, which is the failure mode this
 * comment exists to prevent.
 */
#include "wayland.h"
#include "unixsock.h"
#include "console.h"
#include "fb.h"      /* wl_output reports the real framebuffer geometry (M1986) */
#include "string.h"
#include "timer.h"
#include "task.h"
#include "app.h"    /* app_scm_take_memfd: the client's pixels (M1979) */
#include "kheap.h"  /* the self-test's stand-in pool (M2058) */
#include "xkbmap.h" /* our own XKB keymap, handed over as a memfd (M1984) */

/* The path clients connect to. It carries the compat root because a Linux
 * program's socket path goes through the ABI layer's translation, and both
 * sides have to name the same object -- the client asks for
 * $XDG_RUNTIME_DIR/wayland-0 with XDG_RUNTIME_DIR=/run. */
#define WL_SOCK_PATH "/disk2/run/wayland-0"

#define WL_MAXCLIENT 8
#define WL_INBUF     16384
#define WL_OUTBUF 262144   /* a slow client must never cost us a message (M2000) */

/* Object ids. 1 is always wl_display; a client allocates the rest from 2 up. */
#define WL_DISPLAY_ID 1

/* wl_display requests */
#define WL_DISPLAY_SYNC          0
#define WL_DISPLAY_GET_REGISTRY  1
/* wl_display events */
#define WL_DISPLAY_EV_ERROR      0
#define WL_DISPLAY_EV_DELETE_ID  1
/* wl_registry requests/events */
#define WL_REGISTRY_BIND         0
#define WL_REGISTRY_EV_GLOBAL    0
/* wl_callback events */
#define WL_CALLBACK_EV_DONE      0
/* wl_compositor requests */
#define WL_COMPOSITOR_CREATE_SURFACE 0
#define WL_COMPOSITOR_CREATE_REGION  1
/* wl_shm requests/events */
#define WL_SHM_CREATE_POOL       0
#define WL_SHM_RELEASE           1
#define WL_SHM_EV_FORMAT         0
/* wl_shm errors, for the `code` word of wl_display.error */
#define WL_SHM_ERR_INVALID_FD    2
/* wl_shm_pool requests */
#define WL_SHM_POOL_CREATE_BUFFER 0
#define WL_SHM_POOL_DESTROY       1
#define WL_SHM_POOL_RESIZE        2
/* wl_surface requests */
#define WL_SURFACE_DESTROY       0
#define WL_SURFACE_ATTACH        1
#define WL_SURFACE_DAMAGE        2
#define WL_SURFACE_FRAME         3
#define WL_SURFACE_COMMIT        6
unsigned long g_wl_shm_mismatch, g_wl_shm_ok;   /* M2200: does the compositor read what the client wrote? */
extern uint64_t vmm_translate(uint64_t virt);
extern int app_memfd_mapper_at(int mfd, unsigned long off, uint64_t *out_va, uint64_t *out_phys);
/* wl_buffer requests/events */
#define WL_BUFFER_DESTROY        0
#define WL_BUFFER_EV_RELEASE     0
/* wl_region requests */
#define WL_REGION_DESTROY        0
/* xdg_wm_base / xdg_surface / xdg_toplevel -- the shell protocol GTK and
 * Firefox use to get a real, titled, sized window. */
#define XDG_WM_BASE_DESTROY           0
#define XDG_WM_BASE_CREATE_POSITIONER 1
#define XDG_WM_BASE_GET_XDG_SURFACE 2
#define XDG_WM_BASE_PONG            3
#define XDG_SURFACE_DESTROY         0
#define XDG_SURFACE_GET_TOPLEVEL    1
#define XDG_SURFACE_GET_POPUP       2
#define XDG_SURFACE_ACK_CONFIGURE   4
#define XDG_SURFACE_EV_CONFIGURE    0
#define XDG_TOPLEVEL_DESTROY        0
#define XDG_TOPLEVEL_SET_TITLE      2
#define XDG_TOPLEVEL_SET_MAXIMIZED    9
#define XDG_TOPLEVEL_UNSET_MAXIMIZED 10
/* xdg_toplevel.state. ACTIVATED is the one that decides whether a toolkit
 * thinks its window is in the FOREGROUND, and Gecko throttles painting for a
 * window it believes is not. (M2113) */
#define XDG_STATE_MAXIMIZED   1
#define XDG_STATE_ACTIVATED   4
#define XDG_TOPLEVEL_EV_CONFIGURE   0
#define XDG_POPUP_DESTROY           0
#define XDG_POSITIONER_DESTROY      0
/* wl_seat / wl_pointer / wl_keyboard -- input, back out to the client. */
#define WL_SEAT_GET_POINTER      0
#define WL_SEAT_GET_KEYBOARD     1
#define WL_SEAT_RELEASE          3
/* wl_pointer.set_cursor is what makes a surface A CURSOR, and it is the only
 * way to know: a cursor's buffer is a wl_shm buffer like any other. A
 * compositor that cannot tell one apart from a window eventually paints a
 * window with a mouse pointer. (M2058) */
#define WL_POINTER_SET_CURSOR    0
#define WL_POINTER_RELEASE       1
#define WL_KEYBOARD_RELEASE      0
#define WL_SEAT_EV_CAPABILITIES  0
#define WL_SEAT_EV_NAME          1
#define WL_SEAT_CAP_POINTER      1
#define WL_SEAT_CAP_KEYBOARD     2
#define WL_POINTER_EV_ENTER      0
#define WL_POINTER_EV_LEAVE      1
#define WL_POINTER_EV_MOTION     2
#define WL_POINTER_EV_BUTTON     3
static int ksnprint_u(char *out, unsigned v) {
    char t[12]; int n = 0;
    if (!v) { out[0] = '0'; return 1; }
    while (v && n < 11) { t[n++] = (char)('0' + v % 10); v /= 10; }
    for (int i = 0; i < n; i++) out[i] = t[n - 1 - i];
    return n;
}
unsigned long g_inpreg_calls, g_inpreg_obj;   /* set_input_region: total, and how many named a region OBJECT (M2249) */
#define WL_SURFACE_EV_ENTER      0   /* wl_surface.enter(output) -- M2247 */
#define WL_POINTER_EV_AXIS       4
/* A MOUSE WHEEL IS DISCRETE, AND SAYING SO IS THE WHOLE DIFFERENCE (M2301).
 *
 * This compositor sent a bare wl_pointer.axis and nothing else. A toolkit
 * reads that as a SMOOTH scroll -- a trackpad gesture measured in pixels --
 * and GTK divides the 24.8 value by 10, so our ten-units-per-notch became
 * 1.0 pixel per notch. Twelve wheel clicks moved the page twelve pixels,
 * which is indistinguishable from not scrolling and is exactly what the
 * probe measured: 21 px of screen change on a page with 5200 px to scroll.
 *
 * axis_source says WHERE the scroll came from (0 = a wheel), axis_discrete
 * says it arrived in whole notches, and axis_stop ends the gesture so the
 * toolkit does not wait for more. All three are version 5, which is why they
 * are sent per resource -- the two seats Firefox binds are at 5 and 7. */
#define WL_POINTER_EV_AXIS_SOURCE   6
#define WL_POINTER_EV_AXIS_STOP     7
#define WL_POINTER_EV_AXIS_DISCRETE 8
#define WL_AXIS_SOURCE_WHEEL        0
#define WL_AXIS_VERTICAL            0
#define WL_POINTER_EV_FRAME      5
#define WL_KEYBOARD_EV_KEYMAP    0
#define WL_KEYBOARD_EV_ENTER     1
#define WL_KEYBOARD_EV_LEAVE     2
#define WL_KEYBOARD_EV_KEY       3
#define WL_KEYBOARD_EV_MODIFIERS 4
#define WL_KEYBOARD_EV_REPEAT    5
#define WL_KEYBOARD_KEYMAP_NONE  0    /* "no keymap": the client uses raw evdev codes */

/* wl_output -- the MONITOR. A toolkit sizes and scales its windows against
 * one, and GTK with no output at all has no screen geometry to work from. */
#define WL_OUTPUT_EV_GEOMETRY    0
#define WL_OUTPUT_EV_MODE        1
#define WL_OUTPUT_EV_DONE        2
#define WL_OUTPUT_EV_SCALE       3
#define WL_OUTPUT_EV_NAME        4
#define WL_OUTPUT_EV_DESCRIPTION 5
#define WL_OUTPUT_MODE_CURRENT   0x1
#define WL_OUTPUT_MODE_PREFERRED 0x2
/* wl_data_device_manager -- the CLIPBOARD and drag-and-drop. Nothing here
 * needs it to move data yet, but GDK refuses to create a seat without it
 * (gdk_registry_handle_global postpones the seat until wl_compositor AND
 * wl_data_device_manager have both arrived), and a display with no seat fails
 * later and somewhere else: gdk_seat_get_keyboard() asserts, GTK falls back to
 * building an XKB keymap from names, and aborts. */
#define WL_DDM_CREATE_DATA_SOURCE 0
#define WL_DDM_GET_DATA_DEVICE    1
/* wl_subcompositor -- subsurfaces. GTK uses them for tooltips and popups. */
#define WL_SUBCOMP_DESTROY        0
#define WL_SUBCOMP_GET_SUBSURFACE 1
#define WL_SUBSURFACE_DESTROY     0
#define WL_DATA_SOURCE_DESTROY    1
#define WL_DATA_DEVICE_RELEASE    2
#define WL_OUTPUT_RELEASE         0

/* Pixel formats, by the protocol's numbering. These two are the ones every
 * client can produce and the only ones worth claiming until we composite. */
#define WL_SHM_FORMAT_ARGB8888   0
#define WL_SHM_FORMAT_XRGB8888   1

/* Object kinds, so a request can be routed by what its target IS rather than
 * by guessing from the opcode -- opcode 0 means something different on every
 * interface. */
enum wl_kind { WLK_NONE = 0, WLK_COMPOSITOR, WLK_SHM, WLK_SEAT, WLK_XDG_WM_BASE,
               WLK_SURFACE, WLK_SHM_POOL, WLK_BUFFER,
               WLK_XDG_SURFACE, WLK_XDG_TOPLEVEL, WLK_POINTER, WLK_KEYBOARD,
               WLK_OUTPUT, WLK_DDM, WLK_DATA_DEVICE, WLK_DATA_SOURCE,
               WLK_SUBCOMPOSITOR, WLK_SUBSURFACE,
               WLK_REGION, WLK_XDG_POPUP, WLK_XDG_POSITIONER,
               WLK_ACTIVATION, WLK_ACTIVATION_TOKEN };   /* xdg_activation_v1 (M2113) */

/* WHAT A SURFACE IS FOR -- and why a compositor has to know (M2058).
 *
 * A wl_surface on its own is a rectangle of pixels with no meaning. What it
 * MEANS comes from the ROLE object the client attaches to it afterwards, and
 * the role is the only thing separating "this is the window" from "this is the
 * mouse cursor": the buffers are indistinguishable. So a compositor that keeps
 * one "last committed surface" and draws that draws whatever the client
 * touched most recently -- which for any real toolkit is a cursor, a tooltip,
 * or a popup's shadow, not the window. A single-surface demo client never
 * shows it; Firefox shows it immediately.
 *
 * Wayland gives a surface exactly one role, permanently, set by the request
 * that creates the role object: xdg_surface.get_toplevel,
 * xdg_surface.get_popup, wl_subcompositor.get_subsurface,
 * wl_pointer.set_cursor. */
enum wl_role { WLR_NONE = 0,     /* no role yet -- or a client with no shell at all */
               WLR_TOPLEVEL,     /* xdg_toplevel: THE window */
               WLR_POPUP,        /* xdg_popup: a menu, positioned against a parent */
               WLR_SUBSURFACE,   /* wl_subsurface: part of a parent's window */
               WLR_CURSOR };     /* wl_pointer.set_cursor: never a window */

struct wl_global { const char *iface; uint32_t version; int kind; };
/* Advertised in this order; `name` is the index + 1. Version numbers are the
 * ones we intend to implement, not the newest that exists -- a client binds at
 * min(its version, ours) and will use features we claim.
 *
 * The KIND is stated here rather than derived from the name. It used to be
 * guessed from two characters of the interface string, which worked for four
 * globals and is exactly the kind of thing that silently routes a fifth to the
 * wrong handler. */
static const struct wl_global g_globals[] = {
    /* ORDER IS LOAD-BEARING, which the protocol nowhere says. GDK POSTPONES
     * creating a seat until wl_compositor AND wl_data_device_manager have both
     * been advertised -- so a compositor that announces wl_seat first has its
     * seat created in a LATER round trip, and anything that asks for the
     * keyboard before then (GTK asks almost immediately) finds no keyboard,
     * falls back to building an XKB keymap from RMLVO names, and aborts with
     * "Failed to create XKB keymap". Announcing the manager first costs
     * nothing and is what every real compositor happens to do. (M1986) */
    { "wl_compositor",           4, WLK_COMPOSITOR },
    { "wl_subcompositor",        1, WLK_SUBCOMPOSITOR },
    { "wl_data_device_manager",  3, WLK_DDM },
    { "wl_shm",                  1, WLK_SHM },
    { "wl_output",               4, WLK_OUTPUT },
    { "wl_seat",                 7, WLK_SEAT },
    { "xdg_wm_base",             3, WLK_XDG_WM_BASE },
    /* FIREFOX ASKS FOR THIS BY NAME (M2113):
     *   D/Widget RequestWaylandFocusPromise() missing xdg_activation
     * It is how a client says "please give this window focus" and how a
     * launcher hands a startup token to the app it started. Gecko builds a
     * focus promise on it and, without it, gives up on focusing its own
     * window -- which is one half of why it believed it had none. */
    { "xdg_activation_v1",       1, WLK_ACTIVATION },
};
#define WL_NGLOBAL (int)(sizeof(g_globals) / sizeof(g_globals[0]))

/* A demo client makes a dozen objects; GTK makes hundreds before it draws
 * anything, and running out mid-handshake presents as a client that stops
 * talking. (M1986) */
#define WL_MAXOBJ 512
/* How many wl_pointer / wl_keyboard resources one connection may hold. Firefox
 * needs two of each (GDK's and Gecko's); eight is room for a toolkit that
 * rebinds without leaving slack for a client that leaks them. (M2298) */
#define WL_MAXSEATRES 8
struct wl_object {
    uint32_t id;                   /* 0 = a FREE slot (see obj_free) */
    int      kind;
    /* wl_shm_pool: the client's shared memory, taken from the passed memfd.
     * wl_buffer: geometry into its pool.
     * wl_surface: THE COMMITTED FRAME -- base already includes the buffer's
     *   offset, so base/stride/width/height is exactly what the window manager
     *   blits, and `size` is how many bytes from base are known readable. A
     *   surface with width==0 is UNMAPPED and must not be drawn. This is the
     *   state that used to live in four file-scope globals. (M2058) */
    uint8_t *base; unsigned long size;
    uint32_t off, width, height, stride, format;
    int      shmchk;               /* M2200: the compositor-vs-client frame check ran once */
    /* wl_shm_pool: how many bytes the BACKING OBJECT actually owns, which is
     * the ceiling a resize may not pass. The client's claimed size and the
     * memfd's real capacity are different numbers and only one of them is
     * safe to read through. (M2058) */
    unsigned long cap;
    int      mfd;                  /* wl_shm_pool: the memfd object behind it, -1 = none */
    /* wl_region: the bounding box of everything add()ed to it, and whether
     * anything was. wl_surface: the input region last set on it. (M2249) */
    int      rgn_any;              /* wl_region: at least one add() */
    int      rgn_x, rgn_y, rgn_w, rgn_h;
    int      in_rgn_set;           /* wl_surface: set_input_region named a region OBJECT */
    int      in_any, in_x, in_y, in_w, in_h;
    uint32_t attached;             /* wl_surface: the wl_buffer id last attached (PENDING, applied on commit) */
    int      attach_set;           /* wl_surface: an attach arrived since the last commit. Distinguishes
                                    * "attached nothing" (keep showing the current frame) from
                                    * "attached NULL", which is how a toolkit UNMAPS a window. */
    int      role;                 /* wl_surface: enum wl_role -- what it IS */
    uint32_t role_id;              /* wl_surface: the role object that gave it that role */
    /* THE VERSION THE CLIENT BOUND AT. A compositor may not send an event that
     * is newer than the interface version its client asked for: the client's
     * proxy has no listener slot for the opcode, and libwayland treats an
     * out-of-range opcode as a fatal protocol error rather than something to
     * skip. It kills the connection, and a client whose display is dead just
     * stops -- which from outside is indistinguishable from a hang. (M1998) */
    uint32_t version;
    uint32_t link;                 /* xdg_surface -> its wl_surface; xdg_toplevel/xdg_popup -> its xdg_surface;
                                    * wl_subsurface -> its wl_surface; wl_buffer -> its wl_shm_pool */
    uint32_t frame_cb;             /* wl_surface: a pending wl_surface.frame callback id (M2042) */
    /* SUBSURFACE PLACEMENT (M2089). A wl_surface that has been made a
     * subsurface records which surface it is a child OF, and where inside it.
     * Both were thrown away: get_subsurface's third argument -- the parent --
     * was read past, and wl_subsurface.set_position fell through to
     * wl_unhandled. Without them a compositor cannot place a child, so it can
     * only ever draw ONE surface, and for Firefox the one with the pixels in
     * it is a child. */
    uint32_t parent;               /* wl_surface: the surface this is a subsurface of, 0 = none */
    int32_t  sub_x, sub_y;         /* wl_surface: its offset inside that parent */
};

struct wl_client {
    int      used;
    int      ep;                   /* AF_UNIX endpoint (unixsock.c) */
    uint8_t  in[WL_INBUF];
    /* AN OUTPUT QUEUE, because a compositor may not drop a message (M2000).
     * unix_send writes what fits in the peer's ring and reports how much --
     * and wl_send used to hand it a whole message and move on. A partial write
     * leaves HALF A MESSAGE in the stream: the client reads a header saying 44
     * bytes, gets 20, and every byte after that is interpreted at the wrong
     * offset. Firefox says so out loud --
     *
     *   [GFX1-]: Wayland protocol error: message too short, object (2),
     *            message global(usu)
     *
     * -- and then closes the connection, after which every later send returns
     * -1 and the log fills with failures that are consequences, not causes.
     *
     * Queue instead: append the whole message, flush as much as the ring takes,
     * and resume at the exact byte next time. The stream stays byte-exact
     * however slow the client is. */
    uint8_t  out[WL_OUTBUF];
    int      outlen;
    /* EVERY BYTE WE HANDED TO unix_send (M2292). Paired with the ring's
     * occupancy it says what the client has actually CONSUMED -- see the
     * [wlio] line in wl_fs_health_line for why `outlen` alone cannot. */
    unsigned long sent;
    /* AND WHAT IT HAS SAID BACK (M2292). Firefox runs four connections; the
     * global g_nmsg cannot tell a connection that has gone quiet from three
     * busy ones around it. Gecko's renderer owns its own wl_display, so
     * "frame callbacks are answered" may be describing a different socket
     * entirely from the one GDK's seat proxies live on. Per client, then. */
    unsigned long nin;
    int      inlen;                /* bytes accumulated but not yet consumed */
    uint32_t registry;             /* the client's wl_registry object id, 0 = none yet */
    uint32_t serial;               /* configure serials, monotonic per client */
    uint32_t pointer, keyboard;    /* the MOST RECENT wl_pointer / wl_keyboard, 0 = not asked for.
                                    * Kept only so get_keyboard can address the keymap it is
                                    * replying to; input goes to ptrs[]/kbds[], see below. */
    /* EVERY wl_pointer AND wl_keyboard THE CLIENT MADE (M2298).
     *
     * THE FIREFOX INPUT BUG, and it is a compositor bug, not Gecko's. A
     * client may bind wl_seat as many times as it likes, and every resource
     * it derives from those binds is entitled to the seat's events -- that is
     * what "resource" means in this protocol. Firefox binds it TWICE, and its
     * own WAYLAND_DEBUG says so:
     *
     *   -> wl_registry#2.bind(6, "wl_seat", 5, new id #11)    <- GDK's registry
     *   -> wl_seat#11.get_pointer(new id wl_pointer#9)        <- GDK's, WITH a listener
     *   -> wl_seat#11.get_keyboard(new id wl_keyboard#16)
     *   -> wl_registry#17.bind(6, "wl_seat", 7, new id #24)   <- Gecko's OWN registry
     *   -> wl_seat#24.get_pointer(new id wl_pointer#27)       <- no listener on this one
     *   -> wl_seat#24.get_keyboard(new id wl_keyboard#28)
     *
     * With one slot per client the second bind OVERWROTE the first, so every
     * motion, button, axis and key went to #27/#28 -- proxies Gecko creates
     * and never listens to -- and libwayland threw them away where we could
     * not see it:
     *
     *   [Default Queue] discarded wl_pointer#27.enter(5, wl_surface#32, ...)
     *   [Default Queue] discarded wl_pointer#27.button(6, 56750, 272, 1)
     *
     * "discarded" is libwayland's word for an event delivered to a proxy with
     * no implementation. Which is why every measurement said the bytes were
     * consumed and nothing happened: both were true. GDK's wl_pointer#9, the
     * only one that turns an event into a GdkEvent, was never sent anything.
     *
     * The GTK3 control binds the seat once, so it could never reproduce this
     * -- the control was right about GTK3 and silent about the real defect. */
    uint32_t ptrs[WL_MAXSEATRES]; uint8_t ptrv[WL_MAXSEATRES]; int nptr;
    uint32_t kbds[WL_MAXSEATRES]; uint8_t kbdv[WL_MAXSEATRES]; int nkbd;
    uint32_t surface;              /* the surface input is delivered to */
    /* POINTER FOCUS IS A SUBSURFACE, NOT THE TOPLEVEL (M2245). */
    uint32_t output;               /* the client's wl_output, for wl_surface.enter (M2247) */
    uint32_t surf_entered;         /* the surface we have already told is on that output */
    uint32_t ptr_surface;          /* the surface wl_pointer.enter last named */
    int      ptr_ox, ptr_oy;       /* ...and its offset inside the window */
    int      ptr_in, kbd_in;       /* enter() already sent. Pointer focus follows the CURSOR and
                                    * keyboard focus follows the WINDOW -- they are separate in
                                    * Wayland, and a client ignores input for a surface it has
                                    * not been told it has. */
    /* SUPERSEDED BY THE PER-RESOURCE VERSION IN ptrv[]/kbdv[] (M2298). Kept
     * only as the last-bound value for the log; nothing gates an opcode on it
     * any more, because two binds of the same seat can be at two versions --
     * Firefox's are 5 and 7 -- and one number cannot answer for both. */
    uint32_t seat_version;
    char     title[64];            /* the most recent xdg_toplevel.set_title, as a fallback */
    /* TITLES ARE PER TOPLEVEL, not per client (M2058). Firefox names every
     * window it owns, and one `title` for the whole connection means the
     * titlebar shows whichever window was named last. Small and keyed by
     * object id rather than an array slot, because a toplevel can be destroyed
     * and remade. */
    struct { uint32_t tl; char s[64]; } tl_title[8];
    struct wl_object obj[WL_MAXOBJ]; int nobj;
};
static struct wl_client g_cl[WL_MAXCLIENT];
static int g_listener = -1;
int g_wl_verbose;                 /* -append wlverbose: log every message both ways */
static unsigned g_nconn, g_nmsg, g_nglobal, g_ncommit;
/* THREE FRAME COUNTERS, BECAUSE ONE OF THEM WAS A TRAP (M2115).
 *
 * The first version counted only the answers sent by the periodic TICK. The
 * commit handler answers callbacks too and incremented nothing -- so the probe
 * printed "0 frame callback(s) answered" about a browser whose every callback
 * had been answered promptly by the other path, and I spent a run concluding
 * that Firefox never asks for vsync. It asks; the commit answered it first.
 * Requests and the two answer paths are now separate numbers. */
static unsigned g_frame_ticks, g_frame_done, g_frame_done_commit, g_frame_req;
/* SURFACES AND ROLES (M2081). The headline question about a stalled toolkit is
 * "did it ever create a wl_surface", and nothing here could answer it: obj_add
 * is silent, and the exported counters covered commits, destroys, protocol
 * errors, clients, messages and globals -- everything except the one object
 * whose existence is the difference between a client that is starting up and a
 * client that is never going to draw. The only way to see it was -append
 * wlverbose, which dumps every message and, before M2080, was the flag most
 * likely to wedge the machine. */
static unsigned g_nsurface;       /* wl_compositor.create_surface, ever */
static unsigned g_nrole;          /* surfaces that were given a role (toplevel/popup/subsurface/cursor) */
static unsigned g_ndestroy;       /* objects released back to the table (M2058) */
static unsigned g_nprotoerr;      /* wl_display.error events we had to post (M2058) */

static struct wl_object *obj_find(struct wl_client *c, uint32_t id) {
    if (!id) return 0;                      /* 0 is the free-slot marker, never an object */
    for (int i = 0; i < c->nobj; i++) if (c->obj[i].id == id) return &c->obj[i];
    return 0;
}
static struct wl_object *obj_find_kind(struct wl_client *c, uint32_t id, int kind) {
    struct wl_object *o = obj_find(c, id);
    return (o && o->kind == kind) ? o : 0;
}
/* A FREED SLOT IS REUSED, so every field has to be reset here (M2058).
 *
 * The table used to be append-only: obj_add took c->obj[c->nobj++] and nothing
 * ever came back, so 512 objects was a hard ceiling on a connection's
 * LIFETIME rather than on how many objects it holds at once. It got away with
 * initialising only some fields because a fresh slot was always zero BSS. Now
 * that slots come back round, a missed field is a value inherited from an
 * unrelated object -- a stale `link` or `role` is exactly the sort of thing
 * that reads as "the compositor drew the wrong surface". */
static struct wl_object *obj_add(struct wl_client *c, uint32_t id, int kind) {
    struct wl_object *o = 0;
    for (int i = 0; i < c->nobj; i++) if (!c->obj[i].id) { o = &c->obj[i]; break; }
    if (!o) {
        if (c->nobj >= WL_MAXOBJ) { kprintf("[wl] object table full\n"); return 0; }
        o = &c->obj[c->nobj++];
    }
    for (unsigned b = 0; b < sizeof *o; b++) ((char *)o)[b] = 0;
    o->id = id; o->kind = kind; o->mfd = -1;
    return o;
}

/* --- which surface is the WINDOW (M2058) ---------------------------------- *
 *
 * This replaced four file-scope globals -- last base, stride, width, height --
 * that the commit handler overwrote every time ANY surface committed. For the
 * single-surface demo client that is the same thing as "the window". For a
 * toolkit it is not: GTK commits a cursor surface as soon as the pointer
 * enters, so the window's contents became a 24x24 cursor, and Firefox commits
 * subsurfaces and popups on top of that.
 *
 * The committed frame now lives ON THE SURFACE, and this picks one. The rule is
 * the ROLE, not the clock:
 *
 *   - a mapped xdg_toplevel is the window,
 *   - a surface with no role at all is the window only if there is no
 *     toplevel: a client that never binds xdg_wm_base (our raw test client,
 *     and weston-simple-shm) still deserves to be drawn,
 *   - a popup, a subsurface or a cursor is NEVER the window on its own.
 *
 * Ties go to the lowest object id, which is the earliest-created surface, so
 * the choice is STABLE frame to frame. Picking "most recent" among equals
 * would make the window flicker between a toolkit's own windows. */
/* A TOPLEVEL WITH NO BUFFER OF ITS OWN IS STILL THE WINDOW (M2089), provided
 * something inside it has one. GTK renders into a subsurface and leaves the
 * toplevel blank, so "unmapped" as a test of `base` disqualified exactly the
 * surface that identifies Firefox's window -- and promoted the child, which
 * then had nowhere to be placed. `has_content` is passed in because only the
 * caller can walk the client's other objects. */
static int wl_surface_rank_ex(const struct wl_object *o, int has_content) {
    if (o->kind != WLK_SURFACE) return 0;
    int mapped = o->base && o->width && o->height && o->stride;
    if (!mapped && !has_content) return 0;
    switch (o->role) {
    case WLR_TOPLEVEL:   return 3;
    case WLR_NONE:       return mapped ? 2 : 0;   /* a roleless surface speaks only for itself */
    case WLR_POPUP:
    case WLR_SUBSURFACE: return mapped ? 1 : 0;
    default:             return 0;      /* WLR_CURSOR: not a window, ever */
    }
}
/* Does anything in this client's tree, below `id`, have pixels? One level of
 * children is enough to answer it for every toolkit we have seen, and it is
 * the question wl_surface_rank_ex needs rather than a general walk. */
static int wl_has_mapped_child(struct wl_client *c, uint32_t id) {
    for (int j = 0; j < c->nobj; j++) {
        struct wl_object *o = &c->obj[j];
        if (!o->id || o->kind != WLK_SURFACE || o->parent != id) continue;
        if (o->base && o->width && o->height && o->stride) return 1;
        /* One more level, spelled out rather than recursed: GTK nests a
         * content child inside a toplevel and nothing we run goes deeper, and
         * a client-supplied parent link can be a cycle -- which recursion
         * would follow until the kernel stack ran out. */
        for (int k = 0; k < c->nobj; k++) {
            struct wl_object *g = &c->obj[k];
            if (!g->id || g->kind != WLK_SURFACE || g->parent != o->id) continue;
            if (g->base && g->width && g->height && g->stride) return 1;
        }
    }
    return 0;
}
static struct wl_object *wl_draw_surface(struct wl_client **owner) {
    struct wl_object *best = 0; int bestrank = 0; struct wl_client *bestc = 0;
    for (int i = 0; i < WL_MAXCLIENT; i++) {
        struct wl_client *c = &g_cl[i];
        if (!c->used) continue;
        for (int j = 0; j < c->nobj; j++) {
            struct wl_object *o = &c->obj[j];
            int r = wl_surface_rank_ex(o, wl_has_mapped_child(c, o->id));
            if (!r) continue;
            if (r > bestrank) { best = o; bestrank = r; bestc = c; }
            /* Among equals: the same client's earliest surface. A DIFFERENT
             * client of equal rank does not displace one already chosen, so
             * the desktop's one Wayland window keeps belonging to whoever
             * mapped first. */
            else if (r == bestrank && c == bestc && best && o->id < best->id) best = o;
        }
    }
    if (owner) *owner = bestc;
    return best;
}

/* The surface the window manager should draw. NULL until one exists. The
 * pointer is into the CLIENT'S shared memory, so what the desktop blits is what
 * the client wrote -- there is no intermediate copy anywhere in the path.
 * (M1980) */
const uint32_t *wl_surface_pixels(uint32_t *w, uint32_t *h, uint32_t *stride) {
    struct wl_object *o = wl_draw_surface(0);
    if (!o) return 0;
    if (w) *w = o->width;
    if (h) *h = o->height;
    if (stride) *stride = o->stride;
    return (const uint32_t *)o->base;
}

/* THE WINDOW IS A TREE, NOT A SURFACE (M2089).
 *
 * wl_surface_pixels returns ONE surface, and that is the whole reason Firefox
 * committed 768 frames at 1204x916 without anything appearing on screen: GTK
 * gives the xdg_toplevel no buffer of its own and renders the page into a
 * SUBSURFACE of it. wl_surface_rank scores a subsurface 1 and a toplevel 3, so
 * the window chosen was another client's -- and had Firefox been alone, the
 * subsurface would have been drawn with no idea where inside the window it
 * belonged.
 *
 * So enumerate instead: the chosen window's own surface first (it may have no
 * pixels, which is legal), then every descendant subsurface in creation order,
 * each with the offset it was given. Creation order is the z-order we have --
 * place_above/place_below are accepted and do not reorder yet, which is honest
 * and is written down at their handler rather than implied here.
 *
 * Returns how many layers were written. Coordinates are relative to the
 * window's origin and may be negative: a subsurface is allowed to stick out,
 * and the caller clips. */
/* ONE WINDOW PER CLIENT, NOT ONE PER MACHINE (M2089).
 *
 * wl_draw_surface picks a single surface across every client, and its
 * tie-break deliberately keeps the window belonging to whoever mapped first.
 * That was right when there was one test client. With Firefox it is fatal: the
 * 64x32 lxwl window is created two minutes earlier, ranks equal, and keeps the
 * only window slot -- so a browser painting 1204x916 frames had nowhere to be
 * drawn. A compositor serves clients, plural, and so must the window manager.
 *
 * `ci` is a client slot index; wl_client_used says whether it holds one. */
static int wl_layers_of(struct wl_client *c, struct wl_object *root, struct wl_layer *out, int max);
/* THE BIGGEST WINDOW ANY CLIENT HAS PAINTED (M2089). The boot needs to know
 * "has a real application window appeared", and the global wl_window_extent
 * answers for whichever client mapped FIRST -- which is the 64x32 test client,
 * every time. */
void wl_largest_window(uint32_t *w, uint32_t *h) {
    uint32_t bw = 0, bh = 0;
    for (int ci = 0; ci < WL_MAXCLIENT; ci++) {
        uint32_t cw = 0, ch = 0;
        wl_client_extent(ci, &cw, &ch);
        if ((unsigned long)cw * ch > (unsigned long)bw * bh) { bw = cw; bh = ch; }
    }
    if (w) *w = bw;
    if (h) *h = bh;
}
int wl_client_used(int ci) {
    return ci >= 0 && ci < WL_MAXCLIENT && g_cl[ci].used;
}
int wl_client_count(void) { return WL_MAXCLIENT; }

/* That client's own window root: the same ranking, scoped to one client. */
static struct wl_object *wl_client_root(struct wl_client *c) {
    if (!c || !c->used) return 0;
    struct wl_object *best = 0; int bestrank = 0;
    for (int j = 0; j < c->nobj; j++) {
        struct wl_object *o = &c->obj[j];
        int r = wl_surface_rank_ex(o, wl_has_mapped_child(c, o->id));
        if (!r) continue;
        if (r > bestrank) { best = o; bestrank = r; }
        else if (r == bestrank && best && o->id < best->id) best = o;
    }
    return best;
}

int wl_client_layers(int ci, struct wl_layer *out, int max) {
    if (!wl_client_used(ci) || !out || max <= 0) return 0;
    struct wl_client *c = &g_cl[ci];
    struct wl_object *root = wl_client_root(c);
    if (!root) return 0;
    return wl_layers_of(c, root, out, max);
}

void wl_client_extent(int ci, uint32_t *w, uint32_t *h) {
    struct wl_layer l[24];
    int n = wl_client_layers(ci, l, 24);
    int maxx = 0, maxy = 0;
    for (int i = 0; i < n; i++) {
        int rx = l[i].x + (int)l[i].w, ry = l[i].y + (int)l[i].h;
        if (rx > maxx) maxx = rx;
        if (ry > maxy) maxy = ry;
    }
    if (w) *w = maxx > 0 ? (uint32_t)maxx : 0;
    if (h) *h = maxy > 0 ? (uint32_t)maxy : 0;
}

/* IS THIS CLIENT A WINDOW, OR JUST A CONNECTION? (M2200)
 *
 * The window manager opened a desktop window for every client with a non-zero
 * extent, and that is not the same question. A Wayland surface with NO ROLE is
 * not displayable -- the protocol says so -- and Firefox's child processes each
 * connect, bind xdg_wm_base, create surfaces and commit to them without ever
 * asking for a toplevel. wl_client_root's roleless-but-mapped fallback then
 * scored those 2, they got an extent, and the desktop opened a black window per
 * content process ON TOP of the browser it had just opened. The screenshot of
 * the first ffshow run shows exactly that: a real rendered page with an empty
 * black window covering a third of it.
 *
 * The fallback itself has to stay: our own raw test client (tools/lx/lxwl)
 * never binds a shell at all, and it is the thing the compositor was first
 * proven against. So the test is "a toplevel, OR no shell to ask one from" --
 * which admits the raw client and excludes a client that HAS a shell and has
 * not made a window with it. */
/* THE PID ON THE OTHER END OF A CLIENT CONNECTION (M2202). The window manager
 * needs it to answer one question: has this process asked the compositor for a
 * display? If it has, the terminal window the desktop opened for its stdout is
 * covering the window it actually draws in. */
int wl_client_pid(int ci) {
    if (!wl_client_used(ci)) return -1;
    return unix_peer_pid(g_cl[ci].ep);
}

static int wl_client_has_shell(int ci) {
    if (!wl_client_used(ci)) return 0;
    struct wl_client *c = &g_cl[ci];
    for (int j = 0; j < c->nobj; j++)
        if (c->obj[j].id && c->obj[j].kind == WLK_XDG_WM_BASE) return 1;
    return 0;
}

int wl_client_window_ready(int ci) {
    if (!wl_client_used(ci)) return 0;
    struct wl_client *c = &g_cl[ci];
    int has_shell = 0;
    for (int j = 0; j < c->nobj; j++) {
        struct wl_object *o = &c->obj[j];
        if (!o->id) continue;
        if (o->kind == WLK_XDG_WM_BASE) has_shell = 1;
        if (o->kind == WLK_SURFACE && o->role == WLR_TOPLEVEL) return 1;
    }
    if (has_shell) return 0;
    /* THE SHELL-LESS FALLBACK WAS PER-CLIENT, AND THAT IS WHY NOTHING COULD BE
     * CLICKED (M2243).
     *
     * `return !has_shell` admits any client that never bound xdg_wm_base. It
     * exists for tools/lx/lxwl, our own raw test client, which binds no shell
     * and is what this compositor was first proven against. But FIREFOX'S
     * CONTENT PROCESSES EACH CONNECT AS THEIR OWN CLIENT -- five of them in a
     * normal boot -- and they create surfaces without ever binding a shell.
     * So each one passed this test and got its own desktop window, opened
     * cascaded ON TOP of the browser and painted black.
     *
     * desktop.c delivers every key and every click to windows[win_count - 1],
     * the topmost window. So input was never lost: it was being handed,
     * correctly and precisely, to an empty surface sitting over the page. From
     * the outside that is indistinguishable from a frozen desktop, and it is
     * what "i cant click or scroll or anything / or type" was.
     *
     * The rule a compositor actually wants is global, not per-client: a
     * surface with no role is not a window, and the fallback is only
     * defensible when NOTHING on this display speaks xdg_shell. That keeps
     * lxwl working when it runs alone -- the case the fallback was written for
     * -- and excludes every roleless surface the moment a real toolkit is
     * present. */
    for (int k = 0; k < WL_MAXCLIENT; k++)
        if (k != ci && wl_client_has_shell(k)) return 0;
    return 1;
}

const char *wl_client_title_of(int ci) {
    if (!wl_client_used(ci)) return "";
    struct wl_client *c = &g_cl[ci];
    struct wl_object *o = wl_client_root(c);
    if (!o) return "";
    if (o->role == WLR_TOPLEVEL && o->role_id)
        for (int i = 0; i < (int)(sizeof c->tl_title / sizeof c->tl_title[0]); i++)
            if (c->tl_title[i].tl == o->role_id && c->tl_title[i].s[0])
                return c->tl_title[i].s;
    return c->title[0] ? c->title : "Wayland client";
}

static int wl_layers_of(struct wl_client *c, struct wl_object *root, struct wl_layer *out, int max) {
    int n = 0;
    /* The root itself, if it has anything to draw. */
    if (root->base && root->width && root->height && root->stride) {
        out[n].x = 0; out[n].y = 0;
        out[n].w = root->width; out[n].h = root->height;
        out[n].stride = root->stride;
        out[n].format = root->format;
        out[n].px = (const uint32_t *)root->base;
        n++;
    }
    /* Then its descendants. Walked as a bounded number of GENERATIONS rather
     * than recursively: the parent links come from a client and a client can
     * make a cycle, which recursion would follow until the kernel stack ran
     * out. Four levels is deeper than any real toolkit nests. */
    /* A SUBSURFACE POSITION IS RELATIVE TO ITS PARENT, NOT TO THE WINDOW
     * (M2110). This wrote `o->sub_x` straight into a field the caller treats
     * as an offset from the window origin, which is right for a direct child
     * of the root and wrong for everything deeper: a grandchild at +8,+4
     * inside a child at +26,+23 was reported at +8,+4 from the window, so it
     * would be composited 26 and 23 pixels out of place. The walk has handled
     * four generations since M2089 and only the first of them had correct
     * coordinates. Carry the parent's absolute offset down with the id. */
    struct { uint32_t id; int x, y; } gen[16], next[16];
    int ngen = 1; gen[0].id = root->id; gen[0].x = 0; gen[0].y = 0;
    for (int depth = 0; depth < 4 && ngen && n < max; depth++) {
        int nnext = 0;
        for (int j = 0; j < c->nobj && n < max; j++) {
            struct wl_object *o = &c->obj[j];
            if (!o->id || o->kind != WLK_SURFACE || !o->parent) continue;
            int px = 0, py = 0, isChild = 0;
            for (int g = 0; g < ngen; g++)
                if (o->parent == gen[g].id) { isChild = 1; px = gen[g].x; py = gen[g].y; break; }
            if (!isChild) continue;
            int ax = px + o->sub_x, ay = py + o->sub_y;
            if (nnext < 16) { next[nnext].id = o->id; next[nnext].x = ax; next[nnext].y = ay; nnext++; }
            if (!o->base || !o->width || !o->height || !o->stride) continue;   /* unmapped child */
            out[n].x = ax; out[n].y = ay;
            out[n].w = o->width; out[n].h = o->height;
            out[n].stride = o->stride;
            out[n].format = o->format;
            out[n].px = (const uint32_t *)o->base;
            n++;
        }
        ngen = nnext;
        for (int g = 0; g < ngen; g++) gen[g] = next[g];
    }
    return n;
}

/* The single-window view, kept for the callers that still want "the" window
 * (the boot's readiness print, and the selftest). */
int wl_layers(struct wl_layer *out, int max) {
    struct wl_client *c = 0;
    struct wl_object *root = wl_draw_surface(&c);
    if (!root || !c || !out || max <= 0) return 0;
    return wl_layers_of(c, root, out, max);
}

/* The window's extent: the bounding box of everything wl_layers would draw.
 * For a toplevel with no buffer of its own -- which is what GTK gives us --
 * the size comes entirely from its children, and reporting the toplevel's own
 * zero would size the window to nothing. */
void wl_window_extent(uint32_t *w, uint32_t *h) {
    struct wl_layer l[24];
    int n = wl_layers(l, 24);
    int maxx = 0, maxy = 0;
    for (int i = 0; i < n; i++) {
        int rx = l[i].x + (int)l[i].w, ry = l[i].y + (int)l[i].h;
        if (rx > maxx) maxx = rx;
        if (ry > maxy) maxy = ry;
    }
    if (w) *w = maxx > 0 ? (uint32_t)maxx : 0;
    if (h) *h = maxy > 0 ? (uint32_t)maxy : 0;
}

/* That surface's window title, or "" if it has none (a client that uses
 * wl_surface without xdg_shell has no title to give). Looked up from the
 * surface's own role object, so a client with several windows gets the right
 * one rather than whichever it named last. */
const char *wl_surface_title(void) {
    struct wl_client *c = 0;
    struct wl_object *o = wl_draw_surface(&c);
    if (!o || !c) return "";
    if (o->role == WLR_TOPLEVEL && o->role_id)
        for (int i = 0; i < (int)(sizeof c->tl_title / sizeof c->tl_title[0]); i++)
            if (c->tl_title[i].tl == o->role_id && c->tl_title[i].s[0])
                return c->tl_title[i].s;
    return c->title[0] ? c->title : "Wayland client";
}

unsigned wl_commits(void)      { return g_ncommit; }
unsigned wl_surfaces(void)     { return g_nsurface; }
unsigned wl_roles(void)        { return g_nrole; }
unsigned wl_destroys(void)     { return g_ndestroy; }
unsigned wl_proto_errors(void) { return g_nprotoerr; }
uint32_t wl_last_pixel(void) {
    struct wl_object *o = wl_draw_surface(0);
    return o ? ((uint32_t)o->base[0] | ((uint32_t)o->base[1] << 8) |
                ((uint32_t)o->base[2] << 16) | ((uint32_t)o->base[3] << 24)) : 0;
}
uint32_t wl_last_width(void)  { struct wl_object *o = wl_draw_surface(0); return o ? o->width : 0; }
uint32_t wl_last_height(void) { struct wl_object *o = wl_draw_surface(0); return o ? o->height : 0; }

unsigned wl_clients_connected(void) { return g_nconn; }
unsigned wl_messages_handled(void)  { return g_nmsg; }
unsigned wl_globals_sent(void)      { return g_nglobal; }

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* Build and send one event. `body` is already-marshalled argument bytes. */
/* THE OUTPUT QUEUE HAS TWO WRITERS (M2000).
 *
 * wl_send is called from the compositor task (protocol replies) AND from the
 * window manager task (wl_pointer/wl_keyboard events, via wl_post_*). They are
 * different tasks on different cores, and the queue's append is
 * read-modify-write on c->outlen -- two of them interleaved splice one message
 * into the middle of another, which is exactly the desync libwayland reports as
 *
 *   Wayland protocol error: message too short, object (2), message global(usu)
 *
 * Intermittently, which is what a race looks like from outside. unix_send was
 * already atomic per call, so before the queue existed the equivalent hazard
 * was a SHORT write leaving half a message behind; the queue fixed that one and
 * opened this one. A message must reach the wire whole and in order, and that
 * is a property of the queue, not of the socket underneath it. */
static volatile int g_wl_out_lock;
static inline uint64_t wl_out_take(void) {
    uint64_t fl;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
    while (__atomic_exchange_n(&g_wl_out_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return fl;
}
static inline void wl_out_give(uint64_t fl) {
    __atomic_store_n(&g_wl_out_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(fl) : "memory", "cc");
}

static void wl_flush_locked(struct wl_client *c);
static void wl_flush(struct wl_client *c);
static void wl_send(struct wl_client *c, uint32_t obj, uint16_t opcode,
                    const uint8_t *body, int blen) {
    uint8_t msg[512];
    int total = 8 + blen;
    if (total > (int)sizeof msg) return;            /* refuse rather than truncate a message */
    wr32(msg + 0, obj);
    wr32(msg + 4, ((uint32_t)total << 16) | opcode);
    for (int i = 0; i < blen; i++) msg[8 + i] = body[i];
    uint64_t ofl = wl_out_take();
    if (c->outlen + total > WL_OUTBUF) {
        /* 256 KiB behind and still not reading: this is not slowness, and
         * there is no correct recovery -- the stream cannot skip a message. */
        kprintf("[wl] output queue FULL (%d bytes): dropping obj=%u op=%u size=%d, "
                "the connection is now desynced\n", c->outlen, obj, opcode, total);
        wl_out_give(ofl);
        return;
    }
    for (int i = 0; i < total; i++) c->out[c->outlen + i] = msg[i];
    c->outlen += total;
    if (g_wl_verbose) {
        /* THE ACTUAL BYTES. Firefox rejects a wl_registry.global as "message
         * too short" while our own raw client parses the same burst with
         * nothing left over, so one of the two is wrong about what was sent
         * and reasoning about the encoder has not settled it. Print the wire
         * form and decode it by hand. (M2000) */
        kprintf("[wl] -> obj=%u op=%u size=%d :", obj, opcode, total);
        for (int i = 0; i < total; i++) kprintf(" %02x", msg[i]);
        kprintf("\n");
    }
    wl_flush_locked(c);
    wl_out_give(ofl);
}

/* Push as much of the queue as the peer's ring will take, and keep the rest.
 * Resuming mid-message is fine and is the whole point: the peer reads a byte
 * stream, not a datagram sequence. */
static void wl_flush(struct wl_client *c) {
    uint64_t fl = wl_out_take();
    wl_flush_locked(c);
    wl_out_give(fl);
}
static void wl_flush_locked(struct wl_client *c) {
    int sent_any = 0;
    while (c->outlen > 0) {
        long n = unix_send(c->ep, c->out, (unsigned long)c->outlen);
        if (n <= 0) break;                       /* ring full, or the peer is gone */
        sent_any = 1;
        c->sent += (unsigned long)n;
        if (n >= c->outlen) { c->outlen = 0; break; }
        for (int i = 0; i + (int)n < c->outlen; i++) c->out[i] = c->out[i + (int)n];
        c->outlen -= (int)n;
    }
    /* ...and tell the client's epoll/poll that there is something to read
     * (M2262). unix_send wakes a task blocked in unix_recv; a Linux client
     * blocked in epoll_wait is a different sleeper entirely. */
    if (sent_any) app_unix_peer_ready(c->ep ^ 1);
}

/* A Wayland string: u32 length INCLUDING the NUL, then the bytes, padded to 4. */
static int put_string(uint8_t *b, int p, const char *s) {
    int n = 0; while (s[n]) n++;
    int len = n + 1;                                 /* the NUL is counted */
    wr32(b + p, (uint32_t)len); p += 4;
    for (int i = 0; i < n; i++) b[p + i] = (uint8_t)s[i];
    b[p + n] = 0;
    p += len;
    while (p & 3) b[p++] = 0;                        /* pad to the next 32-bit boundary */
    return p;
}

static void send_global(struct wl_client *c, int idx) {
    uint8_t body[128];
    int p = 0;
    wr32(body + p, (uint32_t)(idx + 1)); p += 4;      /* name */
    p = put_string(body, p, g_globals[idx].iface);
    wr32(body + p, g_globals[idx].version); p += 4;   /* version */
    wl_send(c, c->registry, WL_REGISTRY_EV_GLOBAL, body, p);
    g_nglobal++;
}

/* An unhandled request is the one failure mode this protocol gives you NO
 * signal for. `if (!o) return;` and falling off the end of wl_dispatch are both
 * correct-by-design -- killing the connection over a request we do not model
 * yet would turn a missing feature into a crash -- but they are also silent,
 * and a client that asked for something and got nothing back waits forever
 * having done nothing wrong. That reads from outside as "the program hung".
 *
 * So: name the gap. Report each (object kind, opcode) pair ONCE, which keeps a
 * chatty client from flooding the log while still printing every distinct
 * request we do not implement. (M1998) */
static const char *wl_kind_name(int k) {
    switch (k) {
    case WLK_COMPOSITOR: return "wl_compositor";
    case WLK_SHM: return "wl_shm";
    case WLK_SHM_POOL: return "wl_shm_pool";
    case WLK_BUFFER: return "wl_buffer";
    case WLK_SURFACE: return "wl_surface";
    case WLK_SEAT: return "wl_seat";
    case WLK_POINTER: return "wl_pointer";
    case WLK_KEYBOARD: return "wl_keyboard";
    case WLK_XDG_WM_BASE: return "xdg_wm_base";
    case WLK_ACTIVATION: return "xdg_activation_v1";
    case WLK_ACTIVATION_TOKEN: return "xdg_activation_token_v1";
    case WLK_XDG_SURFACE: return "xdg_surface";
    case WLK_XDG_TOPLEVEL: return "xdg_toplevel";
    case WLK_OUTPUT: return "wl_output";
    case WLK_DDM: return "wl_data_device_manager";
    case WLK_DATA_DEVICE: return "wl_data_device";
    case WLK_DATA_SOURCE: return "wl_data_source";
    case WLK_SUBCOMPOSITOR: return "wl_subcompositor";
    case WLK_SUBSURFACE: return "wl_subsurface";
    case WLK_NONE: return "an object we never created";
    default: return "?";
    }
}
static struct { int kind; int op; } g_unhandled[64];
static int g_nunhandled;
static void wl_unhandled(int kind, uint32_t obj, int opcode) {
    for (int i = 0; i < g_nunhandled; i++)
        if (g_unhandled[i].kind == kind && g_unhandled[i].op == opcode) return;
    if (g_nunhandled < 64) {
        g_unhandled[g_nunhandled].kind = kind;
        g_unhandled[g_nunhandled].op = opcode;
        g_nunhandled++;
    }
    kprintf("[wl] UNHANDLED request: %s(id %u).opcode %d -- the client gets no reply\n",
            wl_kind_name(kind), obj, opcode);
}
unsigned wl_unhandled_count(void) { return (unsigned)g_nunhandled; }

/* wl_display.error(object_id, code, message) -- and then the connection is
 * OVER: libwayland treats it as fatal, stops dispatching, and reports it
 * through wl_display_get_error. That is the point. A request we cannot honour
 * and answer with SILENCE leaves the client waiting for a frame that will never
 * arrive, which from outside is a hang with no cause anywhere. Naming it costs
 * the connection and buys a diagnosis. (M2058) */
static void wl_post_error(struct wl_client *c, uint32_t obj, uint32_t code, const char *msg) {
    uint8_t b[256]; int p = 0;
    wr32(b + p, obj);  p += 4;
    wr32(b + p, code); p += 4;
    p = put_string(b, p, msg);
    wl_send(c, WL_DISPLAY_ID, WL_DISPLAY_EV_ERROR, b, p);
    g_nprotoerr++;
    kprintf("[wl] protocol error posted on object %u: code %u, \"%s\"\n", obj, code, msg);
}

static const char *wl_role_name(int r) {
    switch (r) {
    case WLR_TOPLEVEL:   return "toplevel";
    case WLR_POPUP:      return "popup";
    case WLR_SUBSURFACE: return "subsurface";
    case WLR_CURSOR:     return "cursor";
    default:             return "no role";
    }
}

/* An unmapped surface has no frame and is not drawn. Attaching a NULL buffer
 * and committing is how a toolkit hides a window, and losing a role object
 * does the same thing implicitly. */
static void wl_surface_unmap(struct wl_object *sf) {
    sf->base = 0; sf->size = 0;
    sf->off = sf->width = sf->height = sf->stride = sf->format = 0;
    /* ...AND GIVE BACK THE FRAME'S REFERENCE (M2087). An unmap is the one
     * place a surface stops reading its pixels while remaining alive, so it is
     * the one place the frame's hold must end without the object being
     * destroyed. A toolkit unmaps and remaps a window (a tooltip, a menu) many
     * times per session. */
    if (sf->mfd >= 0) { app_memfd_obj_unref(sf->mfd); sf->mfd = -1; }
}

/* From a ROLE object back to the wl_surface it speaks for. The links are the
 * ones the creating requests recorded: one hop for an xdg_surface or a
 * subsurface, two for a toplevel or a popup. */
static struct wl_object *wl_role_surface(struct wl_client *c, struct wl_object *o) {
    switch (o->kind) {
    case WLK_XDG_SURFACE:
    case WLK_SUBSURFACE:
        return obj_find_kind(c, o->link, WLK_SURFACE);
    case WLK_XDG_TOPLEVEL:
    case WLK_XDG_POPUP: {
        struct wl_object *xs = obj_find_kind(c, o->link, WLK_XDG_SURFACE);
        return xs ? obj_find_kind(c, xs->link, WLK_SURFACE) : 0;
    }
    default: return 0;
    }
}

/* Give `sid` a role. A Wayland surface has exactly one, for life, so an
 * attempt to change it is a client bug -- and refusing to overwrite is also
 * what stops a bug HERE from quietly demoting a window to a cursor. */
static void wl_give_role(struct wl_client *c, uint32_t sid, int role, uint32_t role_id) {
    struct wl_object *sf = obj_find_kind(c, sid, WLK_SURFACE);
    if (!sf) return;
    if (sf->role != WLR_NONE && sf->role != role) {
        kprintf("[wl] surface %u already has the %s role; refusing to make it a %s\n",
                sid, wl_role_name(sf->role), wl_role_name(role));
        return;
    }
    if (sf->role == WLR_NONE) g_nrole++;        /* a surface that can now be shown (M2081) */
    sf->role = role; sf->role_id = role_id;
    kprintf("[wl] surface %u is a %s (role object %u)\n", sid, wl_role_name(role), role_id);
}

/* A surface whose role object is destroyed is unmapped: it is no longer a
 * window, a popup or anything else, and a compositor that keeps drawing it
 * shows a window the client has already taken down. */
/* --- the seat's RESOURCES, all of them (M2298) ---------------------------- *
 *
 * wl_seat is not a singleton from the client's side: each bind makes a new
 * resource, each get_pointer/get_keyboard makes another, and the seat's events
 * go to EVERY one of them. Keeping a single id per connection quietly made the
 * compositor deliver to whichever was created last -- see the long note on
 * `ptrs` in struct wl_client for what that did to Firefox.
 *
 * add() is idempotent on the id so a re-request cannot double-send. */
static void wl_seat_res_add(struct wl_client *c, uint32_t id, uint32_t ver, int kbd) {
    if (!id) return;
    uint32_t *v = kbd ? c->kbds : c->ptrs;
    uint8_t  *w = kbd ? c->kbdv : c->ptrv;
    int      *n = kbd ? &c->nkbd : &c->nptr;
    for (int i = 0; i < *n; i++) if (v[i] == id) { w[i] = (uint8_t)ver; return; }
    if (*n >= WL_MAXSEATRES) {
        kprintf("[wl] client ep %d has %d %s resources already -- NOT tracking id %u, "
                "it will receive no input\n", c->ep, *n, kbd ? "keyboard" : "pointer", id);
        return;
    }
    v[*n] = id; w[*n] = (uint8_t)ver; (*n)++;
}
static void wl_seat_res_del(struct wl_client *c, uint32_t id, int kbd) {
    uint32_t *v = kbd ? c->kbds : c->ptrs;
    uint8_t  *w = kbd ? c->kbdv : c->ptrv;
    int      *n = kbd ? &c->nkbd : &c->nptr;
    for (int i = 0; i < *n; i++)
        if (v[i] == id) {
            for (int j = i; j < *n - 1; j++) { v[j] = v[j + 1]; w[j] = w[j + 1]; }
            (*n)--;
            return;
        }
}

static void wl_role_gone(struct wl_client *c, struct wl_object *role) {
    struct wl_object *sf = wl_role_surface(c, role);
    if (!sf) return;
    if (!sf->role_id || sf->role_id == role->id) { sf->role = WLR_NONE; sf->role_id = 0; }
    wl_surface_unmap(sf);
}

/* THE DESTRUCTOR OPCODE OF EACH INTERFACE, from the protocol XML. It is not
 * always 0: wl_shm_pool.destroy is 1 (create_buffer took 0), wl_pointer.release
 * is 1, wl_data_device.release is 2, wl_seat.release is 3. Getting one wrong
 * turns a live object into a freed slot, or leaks it forever. -1 = the
 * interface has no destructor (wl_compositor, wl_data_device_manager). */
static int wl_destructor_op(int kind) {
    switch (kind) {
    case WLK_SURFACE:        return WL_SURFACE_DESTROY;
    case WLK_BUFFER:         return WL_BUFFER_DESTROY;
    case WLK_REGION:         return WL_REGION_DESTROY;
    case WLK_SUBSURFACE:     return WL_SUBSURFACE_DESTROY;
    case WLK_SUBCOMPOSITOR:  return WL_SUBCOMP_DESTROY;
    case WLK_XDG_WM_BASE:    return XDG_WM_BASE_DESTROY;
    case WLK_XDG_SURFACE:    return XDG_SURFACE_DESTROY;
    case WLK_XDG_TOPLEVEL:   return XDG_TOPLEVEL_DESTROY;
    case WLK_XDG_POPUP:      return XDG_POPUP_DESTROY;
    case WLK_XDG_POSITIONER: return XDG_POSITIONER_DESTROY;
    case WLK_KEYBOARD:       return WL_KEYBOARD_RELEASE;
    case WLK_OUTPUT:         return WL_OUTPUT_RELEASE;
    case WLK_SHM_POOL:       return WL_SHM_POOL_DESTROY;
    case WLK_POINTER:        return WL_POINTER_RELEASE;
    case WLK_SHM:            return WL_SHM_RELEASE;
    case WLK_DATA_SOURCE:    return WL_DATA_SOURCE_DESTROY;
    case WLK_DATA_DEVICE:    return WL_DATA_DEVICE_RELEASE;
    case WLK_SEAT:           return WL_SEAT_RELEASE;
    default:                 return -1;
    }
}

/* OBJECT DESTRUCTION (M2058).
 *
 * There was none at all: obj_add only ever appended, so WL_MAXOBJ was a budget
 * for a connection's whole LIFETIME and every destroyed object stayed in the
 * table with its state intact. The visible consequence is not the ceiling but
 * the staleness -- a destroyed surface kept its committed frame, so a window
 * the client had already taken down was still eligible to be drawn.
 *
 * Releasing the slot means dropping everything that names it first, and then
 * telling the client, because a client may NOT reuse an object id until the
 * server has sent wl_display.delete_id for it. Without that a toolkit's ids
 * climb forever, which is why WL_MAXOBJ had to be raised to 512 to begin
 * with. */
static void wl_destroy_obj(struct wl_client *c, struct wl_object *o) {
    uint32_t id = o->id;
    int kind = o->kind;
    switch (kind) {
    case WLK_SURFACE:
        /* Input may not keep being delivered to a surface that is gone, and
         * clearing ptr_in/kbd_in makes the next enter() be sent for whatever
         * surface replaces it. */
        if (c->surface == id) { c->surface = 0; c->ptr_in = c->kbd_in = 0; }
        if (o->mfd >= 0) { app_memfd_obj_unref(o->mfd); o->mfd = -1; }   /* the committed frame (M2087) */
        break;
    case WLK_BUFFER:
        /* The COMMITTED frame stays: a wl_surface owns its content and the
         * pool owns the memory, which is what the protocol says and what lets
         * a client destroy a buffer the moment it has committed it. But no
         * surface may keep the id PENDING, because it is about to be handed
         * back out -- possibly to an object of a different kind, and then the
         * next commit would resolve it to something that is not a buffer. */
        for (int i = 0; i < c->nobj; i++)
            if (c->obj[i].id && c->obj[i].kind == WLK_SURFACE && c->obj[i].attached == id)
                { c->obj[i].attached = 0; c->obj[i].attach_set = 0; }
        if (o->mfd >= 0) { app_memfd_obj_unref(o->mfd); o->mfd = -1; }   /* the buffer's own hold (M2087) */
        break;
    case WLK_SHM_POOL:
        /* Buffers cut from this pool stay valid -- the protocol is explicit
         * that destroying a pool does not invalidate them -- so they keep the
         * base and size they copied. They only lose the BACKLINK, so a reused
         * pool id cannot be mistaken for their pool.
         *
         * RELEASED HERE NOW (M2087): the memfd reference app_scm_take_memfd
         * took. This used to be left deliberately leaked, and the reasoning in
         * this comment was right -- dropping it while buffers still read
         * through the memory would be far worse -- so the fix was never the
         * unref, it was giving the other holders references of their own.
         * Every buffer cut from this pool, and every surface showing a frame
         * out of it, now holds one. So this drops only the POOL's hold, and
         * the object survives exactly as long as something still reads it. */
        if (o->mfd >= 0) { app_memfd_obj_unref(o->mfd); o->mfd = -1; }
        break;
    case WLK_XDG_SURFACE:
    case WLK_XDG_TOPLEVEL:
    case WLK_XDG_POPUP:
    case WLK_SUBSURFACE:
        wl_role_gone(c, o);
        if (kind == WLK_XDG_TOPLEVEL)
            for (int i = 0; i < (int)(sizeof c->tl_title / sizeof c->tl_title[0]); i++)
                if (c->tl_title[i].tl == id) { c->tl_title[i].tl = 0; c->tl_title[i].s[0] = 0; }
        break;
    case WLK_POINTER:
        wl_seat_res_del(c, id, 0);
        if (c->pointer  == id) { c->pointer  = c->nptr ? c->ptrs[c->nptr - 1] : 0; }
        if (!c->nptr) c->ptr_in = 0;
        break;
    case WLK_KEYBOARD:
        wl_seat_res_del(c, id, 1);
        if (c->keyboard == id) { c->keyboard = c->nkbd ? c->kbds[c->nkbd - 1] : 0; }
        if (!c->nkbd) c->kbd_in = 0;
        break;
    default: break;
    }
    /* NOBODY MAY STILL NAME IT. The id is about to be handed back out, so a
     * surviving `link` would silently re-point at whatever object takes the
     * slot next: a toplevel would find a stranger's xdg_surface, a buffer a
     * stranger's pool. One sweep covers every relationship in the table rather
     * than one per kind, which is also one fewer place to forget. */
    for (int i = 0; i < c->nobj; i++)
        if (c->obj[i].id && c->obj[i].link == id) c->obj[i].link = 0;
    for (unsigned b = 0; b < sizeof *o; b++) ((char *)o)[b] = 0;   /* id 0 = the slot is free */
    o->mfd = -1;
    g_ndestroy++;
    uint8_t d[4]; wr32(d, id);
    wl_send(c, WL_DISPLAY_ID, WL_DISPLAY_EV_DELETE_ID, d, 4);
    if (g_wl_verbose) kprintf("[wl] destroyed %s@%u\n", wl_kind_name(kind), id);
}

/* A DISCONNECTING CLIENT MUST HAND BACK WHAT IT WAS HOLDING (M2087).
 *
 * `c->used = 0` was the whole of the teardown, which is a leak of every memfd
 * object the client's pools, buffers and committed frames held -- and unlike
 * wl_shm_pool.destroy, this one fires for a client that did everything right
 * and simply exited. Firefox's content processes each open a connection, so a
 * single startup burns several, against NMEMFD 256.
 *
 * Not routed through wl_destroy_obj on purpose: that sends wl_display.delete_id
 * for each object, and there is nobody to send it to -- the socket is already
 * closed, so every one of those would queue into an output buffer that is
 * about to be discarded. What is needed here is the RELEASE, not the protocol
 * courtesy. */
static void wl_client_release(struct wl_client *c) {
    int freed = 0;
    for (int i = 0; i < c->nobj; i++) {
        if (!c->obj[i].id) continue;
        if (c->obj[i].mfd >= 0) { app_memfd_obj_unref(c->obj[i].mfd); c->obj[i].mfd = -1; freed++; }
        c->obj[i].id = 0;
    }
    c->nobj = 0; c->inlen = 0; c->outlen = 0; c->registry = 0;
    c->surface = 0; c->pointer = 0; c->keyboard = 0; c->ptr_in = 0; c->kbd_in = 0;
    c->nptr = 0; c->nkbd = 0;
    if (freed)
        kprintf("[wl] client ep %d released %d shared-memory reference(s) on disconnect\n", c->ep, freed);
    unix_close(c->ep);
    c->ep = -1;
    c->used = 0;
}

/* Handle one complete message. Returns 0 always (an unknown object or opcode is
 * ignored rather than fatal: a client may create objects we do not model yet,
 * and killing the connection would turn a missing feature into a hang). */
/* One place that builds an xdg_toplevel.configure, because there are now three
 * callers and the states array is the part that was wrong. `maximized` adds
 * that state and a concrete size; ACTIVATED is always present, because this
 * compositor has exactly one focused window and it is this one. (M2113) */
static void wl_toplevel_configure(struct wl_client *c, struct wl_object *o, uint32_t tid,
                                  uint32_t w, uint32_t h, int maximized) {
    uint8_t b[32]; int p = 0;
    wr32(b + p, w); p += 4;
    wr32(b + p, h); p += 4;
    /* wl_array: byte length, then the u32 values, padded to 4. */
    if (maximized) {
        wr32(b + p, 8); p += 4;
        wr32(b + p, XDG_STATE_MAXIMIZED); p += 4;
        wr32(b + p, XDG_STATE_ACTIVATED); p += 4;
    } else {
        wr32(b + p, 4); p += 4;
        wr32(b + p, XDG_STATE_ACTIVATED); p += 4;
    }
    wl_send(c, tid, XDG_TOPLEVEL_EV_CONFIGURE, b, p);
    uint8_t sb[4]; wr32(sb, ++c->serial);
    wl_send(c, o->id, XDG_SURFACE_EV_CONFIGURE, sb, 4);
}

static void wl_kbd_enter(struct wl_client *c);   /* focus is granted on map, not on a keypress (M2113) */
static int wl_focus_client(void);   /* the WM-named client, area rule as fallback (M2275/M2281) */
/* See the M2190 note in the commit path: the high-water mark of page-coloured
 * pixels over EVERY commit, so a paint that happened between two 15-second
 * samples is still reported. */
static uint32_t g_wl_watch_colour;
static unsigned g_wl_page_best, g_wl_page_commits, g_wl_commits_seen;
void wl_page_watch(uint32_t argb) { g_wl_watch_colour = argb; }

static void wl_dispatch(struct wl_client *c, const uint8_t *m, int len) {
    uint32_t obj = rd32(m + 0);
    uint32_t sz_op = rd32(m + 4);
    uint16_t opcode = (uint16_t)(sz_op & 0xFFFF);
    if (g_wl_verbose) kprintf("[wl] <- obj=%u op=%u size=%d\n", obj, opcode, len);
    const uint8_t *args = m + 8;
    int alen = len - 8;
    g_nmsg++;
    c->nin++;

    if (obj == WL_DISPLAY_ID && opcode == WL_DISPLAY_GET_REGISTRY && alen >= 4) {
        c->registry = rd32(args);
        for (int i = 0; i < WL_NGLOBAL; i++) send_global(c, i);
        return;
    }
    if (obj == WL_DISPLAY_ID && opcode == WL_DISPLAY_SYNC && alen >= 4) {
        uint32_t cb = rd32(args);
        /* done() first, THEN delete_id: the client destroys the callback when
         * done arrives, and a delete_id for an object it still holds is a
         * protocol error on its side. */
        uint8_t body[4]; wr32(body, 0);              /* callback_data: a serial, 0 is fine */
        wl_send(c, cb, WL_CALLBACK_EV_DONE, body, 4);
        uint8_t d[4]; wr32(d, cb);
        wl_send(c, WL_DISPLAY_ID, WL_DISPLAY_EV_DELETE_ID, d, 4);
        return;
    }
    if (c->registry && obj == c->registry && opcode == WL_REGISTRY_BIND && alen >= 4) {
        /* bind(name, interface:string, version, new_id). The NAME tells us
         * which global, so the new object gets the right kind -- opcode 0 means
         * a different request on every interface, and routing by kind is the
         * only way to tell them apart. */
        uint32_t name = rd32(args + 0);
        int p = 4;
        if (p + 4 > alen) return;
        uint32_t slen = rd32(args + p); p += 4;
        p += (int)((slen + 3) & ~3u);
        uint32_t ver = (p + 4 <= alen) ? rd32(args + p) : 1;
        p += 4;                                      /* version */
        if (p + 4 > alen) return;
        uint32_t nid = rd32(args + p);
        int kind = WLK_NONE;
        if (name >= 1 && name <= (uint32_t)WL_NGLOBAL) kind = g_globals[name - 1].kind;
        struct wl_object *bo = obj_add(c, nid, kind);
        if (bo) bo->version = ver;
        if (kind == WLK_SEAT) c->seat_version = ver;   /* wl_pointer/wl_keyboard inherit it */
        /* WHAT A CLIENT ACTUALLY BINDS is the single most useful thing this
         * server can say. A toolkit that binds four of seven globals and then
         * stops has told you exactly which one it could not live without, and
         * from outside it looks identical to a client that hung. (M1986) */
        kprintf("[wl] bind %s -> id %u\n",
                (name >= 1 && name <= (uint32_t)WL_NGLOBAL) ? g_globals[name - 1].iface : "?", nid);
        if (kind == WLK_OUTPUT) {
            c->output = nid;                          /* remember it: wl_surface.enter needs it (M2247) */
            /* A monitor announces itself IMMEDIATELY on bind and ends with
             * `done`: a toolkit treats the description as incomplete until it
             * arrives, so an output that never sends one is an output that
             * never exists. Geometry comes from the real framebuffer. */
            uint32_t ow = fb_width(), oh = fb_height();
            uint8_t g[96]; int gp = 0;
            wr32(g + gp, 0); gp += 4;                  /* x */
            wr32(g + gp, 0); gp += 4;                  /* y */
            wr32(g + gp, (uint32_t)(ow / 4)); gp += 4; /* physical width, mm (~96 dpi) */
            wr32(g + gp, (uint32_t)(oh / 4)); gp += 4; /* physical height, mm */
            wr32(g + gp, 0); gp += 4;                  /* subpixel: unknown */
            gp = put_string(g, gp, "OS-DEV");          /* make */
            gp = put_string(g, gp, "Framebuffer");     /* model */
            wr32(g + gp, 0); gp += 4;                  /* transform: normal */
            wl_send(c, nid, WL_OUTPUT_EV_GEOMETRY, g, gp);
            uint8_t m[16]; int mp = 0;
            wr32(m + mp, WL_OUTPUT_MODE_CURRENT | WL_OUTPUT_MODE_PREFERRED); mp += 4;
            wr32(m + mp, ow); mp += 4;
            wr32(m + mp, oh); mp += 4;
            wr32(m + mp, 60000); mp += 4;              /* refresh, mHz */
            wl_send(c, nid, WL_OUTPUT_EV_MODE, m, mp);
            uint8_t sc[4]; wr32(sc, 1);
            wl_send(c, nid, WL_OUTPUT_EV_SCALE, sc, 4);
            /* name/description are wl_output version 4. Sending them to a
             * version-3 proxy is the protocol error described on wl_object. */
            if (ver >= 4) {
                uint8_t nb2[64]; int np2 = put_string(nb2, 0, "OSDEV-1");
                wl_send(c, nid, WL_OUTPUT_EV_NAME, nb2, np2);
                uint8_t db[64]; int dp = put_string(db, 0, "OS-DEV built-in display");
                wl_send(c, nid, WL_OUTPUT_EV_DESCRIPTION, db, dp);
            }
            wl_send(c, nid, WL_OUTPUT_EV_DONE, 0, 0);
        }
        /* wl_shm MUST advertise its formats on bind. A client asks wl_shm what
         * it supports and will not create a buffer for a format it was never
         * offered, so a silent bind looks to it like a compositor that cannot
         * display anything. */
        if (kind == WLK_SEAT) {
            /* A client asks the seat what it HAS before asking for a pointer
             * or a keyboard. A seat that never says makes a client assume it
             * has neither and never request either -- silently, with no
             * error. */
            uint8_t cb2[4];
            wr32(cb2, WL_SEAT_CAP_POINTER | WL_SEAT_CAP_KEYBOARD);
            wl_send(c, nid, WL_SEAT_EV_CAPABILITIES, cb2, 4);
            if (ver >= 2) {                     /* wl_seat.name arrived in version 2 */
                uint8_t nb[64]; int np = put_string(nb, 0, "osdev-seat0");
                wl_send(c, nid, WL_SEAT_EV_NAME, nb, np);
            }
        }
        if (kind == WLK_SHM) {
            uint8_t b[4];
            wr32(b, WL_SHM_FORMAT_ARGB8888); wl_send(c, nid, WL_SHM_EV_FORMAT, b, 4);
            wr32(b, WL_SHM_FORMAT_XRGB8888); wl_send(c, nid, WL_SHM_EV_FORMAT, b, 4);
        }
        return;
    }

    struct wl_object *o = obj_find(c, obj);
    if (!o) { wl_unhandled(WLK_NONE, obj, opcode); return; }   /* an object we do not model: ignore, never fatal -- but SAY SO */

    /* DESTRUCTORS FIRST (M2058). Every one of them is checked here rather than
     * scattered through the handlers below, because the opcode differs per
     * interface and a destructor that falls through to wl_unhandled leaks the
     * object AND leaves the client unable to reuse its id. No opcode below
     * collides with its own interface's destructor -- see wl_destructor_op. */
    if (opcode == wl_destructor_op(o->kind)) { wl_destroy_obj(c, o); return; }

    if (o->kind == WLK_COMPOSITOR && opcode == WL_COMPOSITOR_CREATE_SURFACE && alen >= 4) {
        uint32_t sid = rd32(args);
        obj_add(c, sid, WLK_SURFACE);
        if (!c->surface) c->surface = sid;      /* input goes to the first surface, until a toplevel appears */
        g_nsurface++;
        kprintf("[wl] surface %u created (client ep %d, %u so far)\n", sid, c->ep, g_nsurface);
        return;
    }
    /* wl_region: a shape, used for the opaque and input regions. We model the
     * OBJECT and nothing else -- we do not clip yet -- but it has to exist, or
     * its destroy has no object to find and the client never gets a delete_id
     * for an id it makes one of per window per frame. */
    if (o->kind == WLK_COMPOSITOR && opcode == WL_COMPOSITOR_CREATE_REGION && alen >= 4) {
        obj_add(c, rd32(args), WLK_REGION);
        return;
    }
    if (o->kind == WLK_SHM && opcode == WL_SHM_CREATE_POOL && alen >= 8) {
        /* create_pool(new_id, fd, size). The fd is NOT in the argument list --
         * it travels out of band as an SCM_RIGHTS control message, and the
         * `fd` slot in the wire format is a placeholder. Take the memfd the
         * client passed and remember where its pixels live. */
        uint32_t nid = rd32(args + 0);
        uint32_t size = rd32(args + 4);
        struct wl_object *po = obj_add(c, nid, WLK_SHM_POOL);
        if (!po) return;
        void *base = 0; unsigned long msz = 0; int mi = -1;
        if (app_scm_take_memfd_idx(c->ep, &base, &msz, &mi) == 0) {
            po->base = (uint8_t *)base;
            po->size = msz < size ? msz : size;
            /* KEEP THE OBJECT, not just the pointer (M2058). wl_shm_pool.resize
             * has to ask how big the backing memfd actually IS: the client's
             * claimed size is the size it WANTED, and its ftruncate can have
             * been refused. */
            po->mfd  = mi;
            po->cap  = po->size;
            unsigned long mcap = 0;
            if (app_memfd_obj_info(mi, 0, 0, &mcap) == 0 && mcap > po->cap) po->cap = mcap;
            kprintf("[wl] shm pool %u: %lu bytes of the client's own memory (%lu usable)\n",
                    nid, po->size, po->cap);
        } else {
            kprintf("[wl] shm pool %u: NO descriptor arrived (SCM_RIGHTS missing)\n", nid);
        }
        return;
    }
    /* wl_shm_pool.resize(size) -- the client grew the file behind the pool and
     * is telling us so. THIS IS NOT A FORMALITY: GTK doubles its pool whenever
     * a window grows, and until now the request fell through to wl_unhandled,
     * so the compositor kept the old size, every buffer cut past it failed the
     * bounds check in commit, and the window stayed blank with no error
     * anywhere.
     *
     * The size is CHECKED against the object rather than believed, because a
     * client can reach this request having failed to grow anything and a
     * compositor that takes the number on trust reads off the end of the pool.
     * (M2058)
     *
     * Until M2082 that failure was the NORMAL case rather than the exception:
     * growing a memfd that any process had already mapped was refused outright,
     * and resizing an already-mapped pool is what every wl_shm client does.
     * Firefox's startup made that call 107 times, got ENOSPC every time, and
     * the only thing the compositor could do about it was kill the connection
     * with the protocol error below. A mapped object can grow now; the check
     * remains because a grow can still legitimately fail (at MEMFD_MAX), and a
     * client is not told when it did. */
    if (o->kind == WLK_SHM_POOL && opcode == WL_SHM_POOL_RESIZE && alen >= 4) {
        uint32_t want = rd32(args + 0);
        void *nb = 0; unsigned long mcap = 0;
        if (o->mfd >= 0 && app_memfd_obj_info(o->mfd, &nb, 0, &mcap) == 0) {
            o->base = (uint8_t *)nb;              /* the object is the truth, not our copy */
            o->cap  = mcap;
        }
        if ((unsigned long)want <= o->size) {
            kprintf("[wl] shm pool %u: resize to %u is not bigger than the current %lu -- "
                    "the protocol only allows growing\n", o->id, want, o->size);
            wl_post_error(c, o->id, WL_SHM_ERR_INVALID_FD,
                          "wl_shm_pool.resize can only make a pool bigger");
            return;
        }
        if ((unsigned long)want > o->cap) {
            kprintf("[wl] shm pool %u: resize to %u but the backing memfd owns only %lu bytes -- "
                    "the client's own ftruncate/fallocate must have failed (MEMFD_MAX is the "
                    "remaining reason it can). Refusing rather than reading past the pool.\n",
                    o->id, want, o->cap);
            wl_post_error(c, o->id, WL_SHM_ERR_INVALID_FD,
                          "the file behind this pool is smaller than the requested size");
            return;
        }
        o->size = want;
        /* Every buffer already cut from this pool now has more room behind it.
         * They keep their own base/size so they survive the pool's destruction,
         * which means they have to be refreshed here rather than re-deriving
         * it at commit. */
        for (int i = 0; i < c->nobj; i++)
            if (c->obj[i].id && c->obj[i].kind == WLK_BUFFER && c->obj[i].link == o->id) {
                c->obj[i].base = o->base; c->obj[i].size = o->size;
            }
        kprintf("[wl] shm pool %u: resized to %lu bytes\n", o->id, o->size);
        return;
    }
    if (o->kind == WLK_SHM_POOL && opcode == WL_SHM_POOL_CREATE_BUFFER && alen >= 24) {
        /* create_buffer(new_id, offset, width, height, stride, format) */
        struct wl_object *bo = obj_add(c, rd32(args + 0), WLK_BUFFER);
        if (!bo) return;
        bo->base   = o->base; bo->size = o->size;
        bo->link   = o->id;                          /* its pool, so a resize can refresh it */
        /* AND A REFERENCE OF ITS OWN (M2087). The protocol is explicit that
         * destroying a pool does not invalidate the buffers cut from it, so a
         * buffer outlives its pool by the client's choice -- and a buffer that
         * merely copied `base` would be reading freed heap the moment the pool
         * released the object. */
        bo->mfd = o->mfd;
        if (bo->mfd >= 0) app_memfd_obj_ref(bo->mfd);
        bo->off    = rd32(args + 4);
        bo->width  = rd32(args + 8);
        bo->height = rd32(args + 12);
        bo->stride = rd32(args + 16);
        bo->format = rd32(args + 20);
        return;
    }
    if (o->kind == WLK_DDM && opcode == WL_DDM_CREATE_DATA_SOURCE && alen >= 4) {
        obj_add(c, rd32(args), WLK_DATA_SOURCE);
        return;
    }
    if (o->kind == WLK_DDM && opcode == WL_DDM_GET_DATA_DEVICE && alen >= 8) {
        /* get_data_device(new_id, seat). We model the object and send nothing:
         * a data device with no selection and no drag in progress has nothing
         * to say, and saying nothing is the correct empty clipboard. */
        obj_add(c, rd32(args + 0), WLK_DATA_DEVICE);
        return;
    }
    if (o->kind == WLK_SUBCOMPOSITOR && opcode == WL_SUBCOMP_GET_SUBSURFACE && alen >= 12) {
        /* get_subsurface(new_id, surface, PARENT) -- and the parent is the
         * whole point (M2089). It was read past: the handler took the first
         * two arguments and discarded the third, so a subsurface knew which
         * surface it wrapped and not which surface it belonged to. A child
         * with no parent cannot be placed, and a compositor that cannot place
         * children can only draw one surface. */
        uint32_t sid = rd32(args + 4);                /* the wl_surface it wraps */
        uint32_t pid = rd32(args + 8);                /* ...and the surface it is a child OF */
        struct wl_object *ss = obj_add(c, rd32(args + 0), WLK_SUBSURFACE);
        if (ss) {
            ss->link = sid;
            wl_give_role(c, sid, WLR_SUBSURFACE, ss->id);
            struct wl_object *child = obj_find_kind(c, sid, WLK_SURFACE);
            if (child) { child->parent = pid; child->sub_x = child->sub_y = 0; }
            kprintf("[wl] subsurface %u: surface %u is now a child of surface %u\n",
                    ss->id, sid, pid);
        }
        return;
    }
    if (o->kind == WLK_SUBSURFACE && opcode == 1 /*set_position*/ && alen >= 8) {
        /* WHERE THE CHILD SITS INSIDE ITS PARENT. Swallowed by wl_unhandled
         * until now, which means every child was drawn at the parent's origin
         * -- fine for Firefox, whose content child sits at 0,0, and wrong for
         * any menu or tooltip, which is what subsurfaces are usually for. */
        struct wl_object *child = obj_find_kind(c, o->link, WLK_SURFACE);
        if (child) { child->sub_x = (int32_t)rd32(args + 0); child->sub_y = (int32_t)rd32(args + 4); }
        return;
    }
    if (o->kind == WLK_SUBSURFACE && (opcode == 2 || opcode == 3 || opcode == 4 || opcode == 5)) {
        /* place_above / place_below / set_sync / set_desync. Accepted rather
         * than swallowed: we draw children in creation order and commit them
         * immediately, so these are requests whose effect we already have. The
         * distinction matters because wl_unhandled is what SCOPES the next
         * milestone, and a request listed there that needs nothing done is
         * noise in the one instrument that names real gaps. */
        return;
    }
    /* wl_pointer.set_cursor(serial, surface, hotspot_x, hotspot_y). THE REASON
     * THIS EXISTS HERE (M2058): a cursor is a wl_surface with a wl_shm buffer,
     * indistinguishable from a window unless the compositor listens to this.
     * GTK sets a cursor as soon as the pointer enters, so with a single
     * "last committed surface" the window's contents became a 24x24 cursor
     * bitmap the moment the mouse moved over it. `surface` may be nil, which
     * means "hide the pointer". */
    if (o->kind == WLK_POINTER && opcode == WL_POINTER_SET_CURSOR && alen >= 8) {
        uint32_t sid = rd32(args + 4);
        if (sid) wl_give_role(c, sid, WLR_CURSOR, o->id);
        return;
    }
    if (o->kind == WLK_SEAT && opcode == WL_SEAT_GET_POINTER && alen >= 4) {
        c->pointer = rd32(args);
        struct wl_object *po = obj_add(c, c->pointer, WLK_POINTER);
        /* THE VERSION IS THE SEAT'S, PER RESOURCE (M2298). Two binds of the
         * same global can be at different versions -- Firefox's are 5 and 7 --
         * and wl_pointer.frame only exists from 5. One c->seat_version for the
         * whole connection would send a v3 proxy an opcode it has no slot for,
         * which libwayland treats as a fatal protocol error. */
        if (po) po->version = o->version ? o->version : 1;
        wl_seat_res_add(c, c->pointer, o->version ? o->version : 1, 0);
        kprintf("[wl] client ep %d asked the seat for a POINTER (id %u, seat v%u) "
                "-- it now holds %d pointer resource(s)\n",
                c->ep, c->pointer, o->version, c->nptr);
        return;
    }
    if (o->kind == WLK_SEAT && opcode == WL_SEAT_GET_KEYBOARD && alen >= 4) {
        c->keyboard = rd32(args);
        struct wl_object *ko = obj_add(c, c->keyboard, WLK_KEYBOARD);
        if (ko) ko->version = o->version ? o->version : 1;
        wl_seat_res_add(c, c->keyboard, o->version ? o->version : 1, 1);
        kprintf("[wl] client ep %d asked the seat for a KEYBOARD (id %u, seat v%u) "
                "-- it now holds %d keyboard resource(s)\n",
                c->ep, c->keyboard, o->version, c->nkbd);
        /* THE KEYMAP (M1984). wl_keyboard.keymap is (format, fd, size), and a
         * client that never receives one cannot turn a keycode into a
         * character at all -- GTK, and therefore Firefox, does no text input
         * without it.
         *
         * `fd` is an OUT-OF-BAND argument: it occupies NO SPACE IN THE MESSAGE
         * BODY and travels as an SCM_RIGHTS control message. The body is two
         * words, format and size. Writing a placeholder word for the fd -- as
         * this did at first -- produces a message libwayland parses as
         * malformed and answers by killing the connection, which presents as a
         * client that asked for a keyboard and then received nothing at all,
         * including events with nothing to do with the keyboard.
         *
         * The order matters too: the descriptor must be queued BEFORE the
         * bytes are written, because libwayland pops the next descriptor when
         * it demarshals an argument declared as one. */
        unsigned long klen = 0; while (osdev_xkb_keymap[klen]) klen++;
        klen++;                                     /* the protocol's size INCLUDES the NUL */
        if (app_scm_give_kernel_memfd(c->ep, "osdev-keymap", osdev_xkb_keymap, klen) == 0) {
            uint8_t kb[8];
            wr32(kb + 0, 1);                        /* XKB_V1 */
            wr32(kb + 4, (uint32_t)klen);           /* ...and NO word for the fd */
            wl_send(c, c->keyboard, WL_KEYBOARD_EV_KEYMAP, kb, 8);
            kprintf("[wl] sent xkb keymap (%u bytes) as a memfd\n", (unsigned)klen);
        } else {
            kprintf("[wl] could not hand over the keymap\n");
        }
        uint8_t ri[8];
        wr32(ri + 0, 25); wr32(ri + 4, 400); /* repeat: 25/s after 400 ms */
        if ((o->version ? o->version : 1) >= 4)   /* repeat_info arrived in wl_keyboard version 4 */
            wl_send(c, c->keyboard, WL_KEYBOARD_EV_REPEAT, ri, 8);
        return;
    }
    if (o->kind == WLK_XDG_WM_BASE && opcode == XDG_WM_BASE_GET_XDG_SURFACE && alen >= 8) {
        struct wl_object *xs = obj_add(c, rd32(args + 0), WLK_XDG_SURFACE);
        if (xs) xs->link = rd32(args + 4);              /* the wl_surface it wraps */
        return;
    }
    if (o->kind == WLK_XDG_WM_BASE && opcode == XDG_WM_BASE_CREATE_POSITIONER && alen >= 4) {
        obj_add(c, rd32(args + 0), WLK_XDG_POSITIONER);
        return;
    }
    /* xdg_positioner.set_size(width, height): the only thing we read off a
     * positioner. Placement -- anchor, gravity, constraint adjustment -- is
     * NOT implemented, so a popup appears at the origin of its parent rather
     * than where the client asked. */
    if (o->kind == WLK_XDG_POSITIONER && opcode == 1 && alen >= 8) {
        o->width = rd32(args + 0); o->height = rd32(args + 4);
        return;
    }
    /* get_popup(new_id, parent, positioner). A popup is a menu: it has pixels
     * and commits like anything else, and it is NOT the window.
     *
     * It needs BOTH configures, in this order. xdg_popup.configure carries the
     * geometry and xdg_surface.configure closes the sequence; a popup that gets
     * only the second one has been told it is configured without being told how
     * big it is, and a popup that gets neither -- which is what fell out of
     * get_popup having no handler at all -- never maps and never says why. */
    if (o->kind == WLK_XDG_SURFACE && opcode == XDG_SURFACE_GET_POPUP && alen >= 12) {
        uint32_t pid = rd32(args + 0);
        struct wl_object *ps = obj_find_kind(c, rd32(args + 8), WLK_XDG_POSITIONER);
        struct wl_object *pp = obj_add(c, pid, WLK_XDG_POPUP);
        if (pp) { pp->link = o->id; wl_give_role(c, o->link, WLR_POPUP, pid); }
        uint8_t pb[16]; int pq = 0;
        wr32(pb + pq, 0); pq += 4;                             /* x: see the positioner note */
        wr32(pb + pq, 0); pq += 4;                             /* y */
        wr32(pb + pq, ps && ps->width  ? ps->width  : 1); pq += 4;
        wr32(pb + pq, ps && ps->height ? ps->height : 1); pq += 4;
        wl_send(c, pid, 0 /* xdg_popup.configure */, pb, pq);
        uint8_t sb2[4]; wr32(sb2, ++c->serial);
        wl_send(c, o->id, XDG_SURFACE_EV_CONFIGURE, sb2, 4);
        return;
    }
    if (o->kind == WLK_XDG_SURFACE && opcode == XDG_SURFACE_GET_TOPLEVEL && alen >= 4) {
        uint32_t tid = rd32(args + 0);
        struct wl_object *tl = obj_add(c, tid, WLK_XDG_TOPLEVEL);
        if (tl) tl->link = o->id;
        /* THE SURFACE IS NOW THE WINDOW. This is the one fact the compositor
         * needs in order to draw the right buffer, and it arrives here -- in
         * the request that creates the role -- not at commit time. */
        wl_give_role(c, o->link, WLR_TOPLEVEL, tid);
        /* Input follows the window, not creation order. "the first surface
         * created" is right for a one-surface demo and wrong for a toolkit,
         * which makes cursor and popup surfaces too. */
        if (o->link && c->surface != o->link) {
            c->surface = o->link; c->ptr_in = c->kbd_in = 0;
        }
        /* A toplevel is not mapped until the client has acknowledged a
         * configure, so the compositor has to send one UNPROMPTED -- a client
         * that never gets configure never attaches a buffer, and waits
         * forever having done nothing wrong. 0x0 means "you choose your own
         * size", which is what a client wants for its first frame. */
        /* ...AND IT MUST SAY THE WINDOW IS ACTIVATED (M2113).
         *
         * The states array was EMPTY. That is a well-formed configure and it
         * tells a toolkit its window is not focused, not maximized, not
         * anything -- and Gecko throttles painting for a window it believes is
         * in the background. Firefox's own log said what it thought:
         *
         *     D/Widget nsWindow::SetSizeMode 2
         *     D/Widget     set maximized
         *
         * and this compositor answered that request with
         *
         *     [wl] UNHANDLED request: xdg_toplevel(id 27).opcode 9
         *
         * -- nothing. So the browser asked to be maximized, was never told it
         * had been, and was never told it was active either. It painted its
         * chrome once and then never painted a page, which is exactly what the
         * framebuffer showed for this entire campaign. */
        wl_toplevel_configure(c, o, tid, 0, 0, 0);
        return;
    }
    /* --- xdg_activation_v1 (M2113) -------------------------------------- *
     *
     * Firefox names this in its own log when it gives up on focusing itself:
     *
     *     D/Widget RequestWaylandFocusPromise() missing xdg_activation
     *
     * The shape is a two-step handshake, because the point of the protocol is
     * that a token can be MINTED by one client and REDEEMED by another (a
     * launcher starting an app, and the app then asking to be raised). A
     * client asks for a token object, sets whatever it knows on it, commits,
     * and is handed a string back; later, someone calls activate() with that
     * string and a surface.
     *
     * The token is a plain counter here. That is the whole of its contract --
     * it is opaque to the client and only ever compared for equality by us --
     * and inventing a cryptographic one would be dressing up a single-user
     * machine as a multi-tenant compositor. */
    if (o->kind == WLK_ACTIVATION && opcode == 1 && alen >= 4) {   /* get_activation_token */
        uint32_t nid = rd32(args + 0);
        if (obj_add(c, nid, WLK_ACTIVATION_TOKEN))
            kprintf("[wl] xdg_activation: token object %u created\n", nid);
        return;
    }
    if (o->kind == WLK_ACTIVATION && opcode == 2 && alen >= 4) {   /* activate(token, surface) */
        /* The surface follows the string, which is length-prefixed and padded.
         * Focus is what is being asked for, and this compositor's focus rule is
         * one window, so honour it by entering the keyboard on this client. */
        uint32_t slen = rd32(args + 0);
        uint32_t pad = (slen + 3u) & ~3u;
        uint32_t sid = (4 + pad + 4 <= (uint32_t)alen) ? rd32(args + 4 + pad) : 0;
        kprintf("[wl] xdg_activation: activate surface %u -- granting keyboard focus\n", sid);
        wl_kbd_enter(c);
        return;
    }
    if (o->kind == WLK_ACTIVATION_TOKEN) {
        if (opcode == 3) {                                          /* commit */
            /* done(token). A client that committed a token and got no `done`
             * waits for it, which is the failure mode this interface's absence
             * already produced by another route. */
            static uint32_t g_tok;
            char tok[24]; int tp = 0;
            const char *pre = "osdev-";
            while (pre[tp]) { tok[tp] = pre[tp]; tp++; }
            uint32_t v = ++g_tok;
            char dg[12]; int nd = 0;
            do { dg[nd++] = (char)('0' + v % 10); v /= 10; } while (v);
            while (nd) tok[tp++] = dg[--nd];
            tok[tp] = 0;
            uint8_t b[32]; int p2 = put_string(b, 0, tok);
            wl_send(c, obj, 0 /* done */, b, p2);
            kprintf("[wl] xdg_activation: token committed -> done(\"%s\")\n", tok);
            return;
        }
        if (opcode == 0 || opcode == 1 || opcode == 2) return;      /* set_serial/app_id/surface */
        if (opcode == 4) { wl_destroy_obj(c, o); return; }          /* destroy */
    }
    if (o->kind == WLK_XDG_TOPLEVEL &&
        (opcode == XDG_TOPLEVEL_SET_MAXIMIZED || opcode == XDG_TOPLEVEL_UNSET_MAXIMIZED)) {
        /* GRANT IT, and say so with a configure (M2113). The protocol is a
         * request/confirm pair: a client asks, and it is the compositor's
         * configure that makes it true. Swallowing the request leaves the
         * client waiting for a state change that never arrives -- and Firefox
         * asks to be maximized during startup, every time.
         *
         * Maximized means the whole screen here, because this window manager
         * has one output and it is the framebuffer. */
        int maxi = (opcode == XDG_TOPLEVEL_SET_MAXIMIZED);
        uint32_t mw = maxi ? fb_width() : 0, mh = maxi ? fb_height() : 0;
        /* An xdg_toplevel's `link` is its xdg_surface, and the paired
         * xdg_surface.configure has to go to THAT object -- the serial in it is
         * what the client acks. */
        struct wl_object *surf = 0;
        for (int i = 0; i < c->nobj; i++)
            if (c->obj[i].id == o->link && c->obj[i].kind == WLK_XDG_SURFACE)
                { surf = &c->obj[i]; break; }
        if (!surf) surf = o;                 /* fall back: still better than silence */
        kprintf("[wl] xdg_toplevel %s -> configure %ux%u with states\n",
                maxi ? "set_maximized" : "unset_maximized", mw, mh);
        wl_toplevel_configure(c, surf, obj, mw, mh, maxi);
        return;
    }
    if (o->kind == WLK_XDG_TOPLEVEL && opcode == XDG_TOPLEVEL_SET_TITLE && alen >= 4) {
        uint32_t slen = rd32(args + 0);
        if (slen > 0 && 4 + slen <= (uint32_t)alen) {
            unsigned n = slen - 1;                        /* the length counts the NUL */
            if (n > sizeof c->title - 1) n = sizeof c->title - 1;
            for (unsigned i = 0; i < n; i++) c->title[i] = (char)args[4 + i];
            c->title[n] = 0;
            /* ...and keyed by the TOPLEVEL, so a client with several windows
             * does not have them all named after the last one it titled. */
            int nt = (int)(sizeof c->tl_title / sizeof c->tl_title[0]), slot = -1;
            for (int i = 0; i < nt; i++) if (c->tl_title[i].tl == o->id) { slot = i; break; }
            if (slot < 0) for (int i = 0; i < nt; i++) if (!c->tl_title[i].tl) { slot = i; break; }
            if (slot >= 0) {
                c->tl_title[slot].tl = o->id;
                for (unsigned i = 0; i <= n; i++) c->tl_title[slot].s[i] = c->title[i];
            }
            kprintf("[wl] toplevel title: \"%s\"\n", c->title);
        }
        return;
    }
    if (o->kind == WLK_XDG_SURFACE && opcode == XDG_SURFACE_ACK_CONFIGURE) return;  /* nothing to do yet */

    if (o->kind == WLK_SURFACE && opcode == WL_SURFACE_ATTACH && alen >= 4) {
        o->attached = rd32(args + 0);                /* the wl_buffer id, or 0 = detach */
        o->attach_set = 1;                           /* ...applied at the next commit */
        return;
    }
    /* Requests a surface makes constantly and that need no reply. Named
     * explicitly so the log stops reporting them as gaps the client is waiting
     * on -- they are not. We do not clip to regions or scale buffers yet, which
     * is a missing FEATURE rather than a missing answer. */
    if (o->kind == WLK_SURFACE && opcode == 5 /* set_input_region */) {
        /* SWALLOWED SINCE THE COMPOSITOR WAS WRITTEN, AND IT IS IN THE INPUT
         * PATH (M2249). A NULL region means "the whole surface takes input",
         * which is the default and harmless. A REGION OBJECT can be empty,
         * and an empty input region means this surface takes NO pointer
         * events -- they belong to its parent. If GTK does that to the
         * subsurface it renders into, then "deliver to the deepest surface"
         * is wrong, and if it does it to the TOPLEVEL then delivering there
         * is wrong too. Either way it decides where a click goes, so stop
         * throwing it away silently and say what is actually being asked. */
        uint32_t rid = (alen >= 4) ? rd32(args) : 0;
        g_inpreg_calls++;
        if (rid) g_inpreg_obj++;
        o->in_rgn_set = rid ? 1 : 0;
        o->in_any = 0;
        if (rid) {
            for (int j = 0; j < c->nobj; j++)
                if (c->obj[j].id == rid && c->obj[j].kind == WLK_REGION) {
                    o->in_any = c->obj[j].rgn_any;
                    o->in_x = c->obj[j].rgn_x; o->in_y = c->obj[j].rgn_y;
                    o->in_w = c->obj[j].rgn_w; o->in_h = c->obj[j].rgn_h;
                    break;
                }
        }
        static int shown;
        if (shown < 12) { shown++;
            kprintf("[wl] set_input_region on surface %u (%ux%u) -> %s [%d,%d %dx%d]\n",
                    o->id, o->width, o->height,
                    !rid ? "NULL (whole surface)"
                         : (o->in_any ? "a region WITH area" : "an EMPTY region -- takes no input"),
                    o->in_x, o->in_y, o->in_w, o->in_h); }
        return;
    }
    if (o->kind == WLK_SURFACE && (opcode == WL_SURFACE_DAMAGE || opcode == 4 /* set_opaque_region */ ||
                                   opcode == 7 /* set_buffer_transform */ ||
                                   opcode == 8 /* set_buffer_scale */ || opcode == 9 /* damage_buffer */ ||
                                   opcode == 10 /* offset */)) return;
    if (o->kind == WLK_REGION) {
        /* A REGION IS NOT DECORATION -- IT DECIDES WHERE CLICKS GO (M2249).
         * wl_region.add(x,y,w,h) is opcode 1. Tracked as a bounding box,
         * which is enough for the one question the input path asks: does this
         * surface accept a pointer here, and does it accept one anywhere at
         * all. subtract() is deliberately not modelled -- a box that is too
         * generous delivers an event a real compositor also would, whereas
         * treating a set region as empty would silently swallow input, and
         * that is the failure this is here to end. */
        if (opcode == 1 && alen >= 16) {
            int rx = (int)rd32(args), ry = (int)rd32(args + 4);
            int rw = (int)rd32(args + 8), rh = (int)rd32(args + 12);
            if (rw > 0 && rh > 0) {
                if (!o->rgn_any) { o->rgn_x = rx; o->rgn_y = ry; o->rgn_w = rw; o->rgn_h = rh; o->rgn_any = 1; }
                else {
                    int x0 = o->rgn_x < rx ? o->rgn_x : rx;
                    int y0 = o->rgn_y < ry ? o->rgn_y : ry;
                    int x1 = (o->rgn_x + o->rgn_w) > (rx + rw) ? (o->rgn_x + o->rgn_w) : (rx + rw);
                    int y1 = (o->rgn_y + o->rgn_h) > (ry + rh) ? (o->rgn_y + o->rgn_h) : (ry + rh);
                    o->rgn_x = x0; o->rgn_y = y0; o->rgn_w = x1 - x0; o->rgn_h = y1 - y0;
                }
            }
        }
        return;
    }
    if (o->kind == WLK_XDG_POSITIONER) return;       /* the whole interface is setters */
    if (o->kind == WLK_XDG_SURFACE && opcode == 3 /* set_window_geometry */) return;
    /* wl_surface.frame HAD NO DISPATCH AT ALL (M2042).
     *
     * The opcode was #defined and then fell through to wl_unhandled, so the
     * callback the client allocated was never answered. A toolkit asks "tell me
     * when it is a good time to draw again" before nearly every frame and will
     * not produce the next one until it hears back -- so this is a client that
     * connects, binds every global, builds its widgets, commits once at most,
     * and then waits for ever. No error, no protocol violation, nothing in any
     * log but a single "UNHANDLED request" line.
     *
     * The id is the client's to allocate; we only have to send done on it. The
     * timestamp is milliseconds, and clients use it only for animation timing,
     * so the tick clock is precise enough. */
    if (o->kind == WLK_SURFACE && opcode == WL_SURFACE_FRAME && alen >= 4) {
        o->frame_cb = rd32(args + 0);
        g_frame_req++;
        return;
    }
    if (o->kind == WLK_SURFACE && opcode == WL_SURFACE_COMMIT) {
        /* THE POINT OF ALL OF IT: the client's pixels are now ours to read,
         * in the memory it wrote them to. Nothing was copied to get here.
         *
         * A commit applies the PENDING state. No attach since the last commit
         * means "keep showing the current frame" (a client commits to answer a
         * frame callback or to update damage); an attach of NULL means UNMAP,
         * which is how a toolkit hides a window. Treating the two the same
         * either loses a frame or keeps drawing a window that is gone. */
        struct wl_object *b = obj_find_kind(c, o->attached, WLK_BUFFER);
        if (o->attach_set && !o->attached) {
            wl_surface_unmap(o);
            o->attach_set = 0;
            kprintf("[wl] commit: surface %u attached NULL -- unmapped\n", o->id);
        } else if (b && b->base && b->height && b->stride) {
            unsigned long need = (unsigned long)b->off + (unsigned long)b->stride * b->height;
            if (need <= b->size) {
                /* THE COMMITTED FRAME BELONGS TO THE SURFACE (M2058). This used
                 * to be four file-scope globals, so the last surface to commit
                 * anything became the window's contents. */
                /* AND THE FRAME TAKES A REFERENCE TOO (M2087), because a
                 * client may destroy the buffer as soon as it has committed
                 * it -- libwayland's own double-buffering does exactly that --
                 * and the window manager blits from this base on every redraw
                 * long afterwards. The frame being REPLACED gives its
                 * reference back, so a client drawing 60 frames a second does
                 * not accumulate them. */
                if (o->mfd != b->mfd) {
                    if (o->mfd >= 0) app_memfd_obj_unref(o->mfd);
                    o->mfd = b->mfd;
                    if (o->mfd >= 0) app_memfd_obj_ref(o->mfd);
                }   /* same object as last frame: no net change, so redrawing
                     * at 60 Hz touches the refcount not at all */
                o->base   = b->base + b->off;
                o->size   = b->size - b->off;
                o->off    = 0;
                o->width  = b->width; o->height = b->height;
                o->stride = b->stride; o->format = b->format;
                g_ncommit++;
                /* THE FIRST PIXEL IS THE WRONG PIXEL TO REPORT (M2089).
                 *
                 * It was the only one printed, and for 762 consecutive Firefox
                 * frames it read 0x00000000 -- which is equally consistent with
                 * "the window is blank" and "the top-left corner of a
                 * client-side-decorated window is transparent, as it is meant
                 * to be". Those are opposite conclusions from one number, and
                 * the difference decides whether the compositor or the client
                 * is the thing to fix.
                 *
                 * So: sample the whole buffer on a strided walk and say how
                 * much of it is non-transparent, plus the middle pixel. Rate-
                 * limited hard, because a browser commits at 60 Hz and this
                 * reads a megabyte. */
                /* RATE-LIMIT THE SCAN, NOT THE LINE (M2094).
                 *
                 * M2089 put the whole report behind `nth % 64` because the
                 * buffer scan reads a megabyte and a browser commits at 60 Hz.
                 * That also silenced 63 of every 64 COMMIT LINES -- and the
                 * Wayland suite asserts on lxwl's commit, which is number one.
                 * So a test that had passed for five milestones began failing
                 * on a fact that was still perfectly true, and the compositor
                 * looked as though it had stopped seeing commits.
                 *
                 * The line is cheap: four numbers already in hand. Only the
                 * strided walk over the client's pixels is not. Print always,
                 * scan occasionally. */
                {   static unsigned nth;
                    int loud = (nth++ % 64) == 0;
                    {
                        unsigned long need2 = (unsigned long)b->stride * b->height;
                        /* WATCH EVERY COMMIT, NOT EVERY FIFTEENTH SECOND (M2190).
                         *
                         * `wl_page_probe` SAMPLES: it looks at whatever is on
                         * screen when it happens to run, every 15 seconds. A
                         * page that painted and was then replaced between two
                         * samples is invisible to it, and "the content area is
                         * not the page right now" is not the same claim as "the
                         * page was never presented". Those need opposite
                         * investigations, and the probe cannot tell them apart.
                         *
                         * Every committed buffer passes through here, so the
                         * high-water mark of page-coloured pixels across ALL
                         * commits answers the second question outright and
                         * costs one comparison per already-sampled pixel. The
                         * concurrent session's point: ask our own compositor
                         * what it was handed rather than asking Gecko to
                         * narrate -- and unlike a MOZ_LOG spec, this cannot be
                         * silent, because the commits are ours. */
                        unsigned nz = 0, seen = 0, pagepx = 0, pageseen = 0;
                        if (loud && need2 <= o->size) {
                            for (unsigned y = 0; y < b->height; y += 16)
                                for (unsigned x = 0; x < b->width; x += 16) {
                                    uint32_t px = rd32(o->base + (unsigned long)y * b->stride + (unsigned long)x * 4);
                                    if (px & 0x00FFFFFFu) nz++;
                                    seen++;
                                    /* The content area only: above the chrome's
                                     * height the answer is always "chrome". */
                                    if (g_wl_watch_colour && y >= 92) {
                                        pageseen++;
                                        if ((px & 0x00FFFFFFu) ==
                                            (g_wl_watch_colour & 0x00FFFFFFu)) pagepx++;
                                    }
                                }
                        }
                        if (pageseen) {
                            unsigned pct = pagepx * 100 / pageseen;
                            if (pct > g_wl_page_best) g_wl_page_best = pct;
                            if (pct >= 50) g_wl_page_commits++;
                            g_wl_commits_seen++;
                        }
                        /* IS THE COMPOSITOR READING THE MEMORY THE CLIENT WROTE? (M2200)
                         *
                         * The compositor reads a committed buffer through the
                         * memfd's KERNEL-HEAP pointer; the client writes through
                         * its OWN mapping of that memfd. Nothing has ever
                         * verified that those two resolve to the same physical
                         * pages -- and if they do not, the compositor blits
                         * memory the client never wrote, which presents as a
                         * frame of the client's blank canvas with every other
                         * layer healthy -- which is the SHAPE of the 1-core
                         * failure: document fetched, parsed, ACTIVE in the
                         * window, 181 commits at the right size, content area
                         * showing something else.
                         *
                         * IT IS NOT THAT FAILURE, AND THIS CHECK IS WHAT SAYS
                         * SO. Measured across four boots it fires on runs that
                         * render the page perfectly (page=39 of 39 samples,
                         * mismatch=1) as often as on blank ones, and the pool
                         * it fires on was 8 MiB from creation and never grew.
                         * So the mismatch is real, rare, and NOT the blank
                         * page; keeping the check is how the next theory gets
                         * tested instead of believed.
                         *
                         * Compare the frames. The compositor's side is
                         * `vmm_translate` of its heap pointer; the client's side
                         * is the same offset inside whichever of its VMAs is
                         * backed by this memfd, translated in ITS address space.
                         * A mismatch is the answer; a match eliminates the last
                         * mechanism that leaves no other trace.
                         *
                         * Once per buffer, bounded: this runs on every commit. */
                        if (b->mfd >= 0 && !b->shmchk) {
                            b->shmchk = 1;
                            /* COMPARE THE SAME OFFSET (M2200).
                             *
                             * The first cut compared `o->base` -- which already
                             * includes the buffer's offset within the pool --
                             * against the client's VMA START, i.e. offset 0 of
                             * its mapping. Two different offsets of one object
                             * are two different pages, so it reported a
                             * "mismatch" for buffers that were shared perfectly.
                             * It fired once in a run that RENDERED, which is the
                             * tell. Take the object's base from the memfd and
                             * compare at a single offset on both sides. */
                            void *mb = 0;
                            unsigned long moff = 0;
                            if (app_memfd_obj_info(b->mfd, &mb, 0, 0) == 0 && mb &&
                                (uint8_t *)o->base >= (uint8_t *)mb)
                                moff = (unsigned long)((uint8_t *)o->base - (uint8_t *)mb);
                            uint64_t kp = vmm_translate((uint64_t)o->base);
                            uint64_t up = 0, uva = 0;
                            int upid = app_memfd_mapper_at(b->mfd, moff, &uva, &up);
                            if (kp && up && kp != up) {
                                g_wl_shm_mismatch++;
                                kprintf("[wl] ** THE COMPOSITOR IS NOT READING THE CLIENT'S "
                                        "MEMORY: memfd %d, compositor heap %lx -> phys %lx, "
                                        "client pid %d va %lx -> phys %lx. Every pixel blitted "
                                        "from this buffer is memory the client never wrote. **\n",
                                        b->mfd, (unsigned long)o->base, (unsigned long)kp,
                                        upid, (unsigned long)uva, (unsigned long)up);
                            } else if (kp && up) {
                                g_wl_shm_ok++;
                            }
                        }
                        uint32_t mid = 0;
                        if (need2 <= o->size && b->height && b->width)
                            mid = rd32(o->base + (unsigned long)(b->height / 2) * b->stride + (unsigned long)(b->width / 2) * 4);
                        if (loud)
                            kprintf("[wl] commit: %ux%u stride %u format %u -> first 0x%08x mid 0x%08x, "
                                    "%u/%u sampled pixels have colour (surface %u, %s)\n",
                                    b->width, b->height, b->stride, b->format, rd32(o->base), mid,
                                    nz, seen, o->id, wl_role_name(o->role));
                        else
                            kprintf("[wl] commit: %ux%u stride %u format %u -> first 0x%08x "
                                    "(surface %u, %s)\n",
                                    b->width, b->height, b->stride, b->format, rd32(o->base),
                                    o->id, wl_role_name(o->role));
                    }
                }
            } else {
                kprintf("[wl] commit: buffer claims %lu bytes but the pool holds %lu -- refusing\n",
                        need, b->size);
            }
            o->attach_set = 0;
            /* Tell the client it may reuse the buffer. Without this a client
             * that double-buffers waits forever for its first frame back. */
            wl_send(c, b->id, WL_BUFFER_EV_RELEASE, 0, 0);
        }
        /* ...and answer the frame callback, AFTER the commit that presented it
         * (M2042). Fired here rather than on request so the ordering a client
         * expects -- frame, commit, done -- actually holds. */
        if (o->frame_cb) {
            uint8_t ts[4]; uint32_t ms = (uint32_t)(timer_ticks() * 10u);
            ts[0] = (uint8_t)ms; ts[1] = (uint8_t)(ms >> 8);
            ts[2] = (uint8_t)(ms >> 16); ts[3] = (uint8_t)(ms >> 24);
            wl_send(c, o->frame_cb, WL_CALLBACK_EV_DONE, ts, 4);
            /* ...and RELEASE THE ID. A wl_callback has no destructor request:
             * the server destroys it after `done`, and the client cannot reuse
             * the id until delete_id says so. A toolkit asks for a frame
             * callback before every frame, so leaving this out leaks an id per
             * frame -- thousands of them in a minute of animation, which is the
             * other half of why the object table only ever grew. (M2058) */
            uint8_t dq[4]; wr32(dq, o->frame_cb);
            wl_send(c, WL_DISPLAY_ID, WL_DISPLAY_EV_DELETE_ID, dq, 4);
            o->frame_cb = 0;                       /* one done per request */
            g_frame_done_commit++;
        }
        return;
    }
    wl_unhandled(o->kind, obj, opcode);
}


/* ===== SELF-TEST: WHICH SURFACE IS THE WINDOW? (M2058) ====================
 *
 * The bug this exists to keep dead: the compositor kept ONE file-scope "last
 * committed surface" -- base, stride, width, height -- and the window blit read
 * it. Every client we had ever run made exactly one surface, so it looked
 * right. Every real toolkit makes several, and the LAST one to commit won: GTK
 * commits a cursor surface as soon as the pointer enters a window, so the
 * window's contents became a 24x24 cursor bitmap.
 *
 * That cannot be caught by a single-surface client, which is why the existing
 * libwayland test passed throughout. So this drives the dispatcher with the
 * exact message sequence that produces it, on a synthetic client whose socket
 * goes nowhere, and asserts the compositor picks the TOPLEVEL. It needs no
 * client, no socket and no display, so it runs in the same boot as the real
 * one.
 *
 * Every event the compositor sends is read back OUT OF THE OUTPUT QUEUE and
 * checked as bytes (st_seen), because "we called wl_send" and "the client will
 * receive a well-formed message" are different claims.
 */
static int g_st_fail, g_st_checks;
static void st_ck(const char *what, int ok) {
    g_st_checks++;
    if (!ok) g_st_fail++;
    kprintf("WLSELFTEST: %s -- %s\n", ok ? "ok" : "FAIL", what);
}

/* One request, straight into the dispatcher: all-u32 arguments covers every
 * request this test needs except set_title. */
static void st_req(struct wl_client *c, uint32_t obj, uint16_t op, const uint32_t *a, int n) {
    uint8_t m[128];
    int total = 8 + 4 * n;
    wr32(m + 0, obj);
    wr32(m + 4, ((uint32_t)total << 16) | op);
    for (int i = 0; i < n; i++) wr32(m + 8 + 4 * i, a[i]);
    wl_dispatch(c, m, total);
}
static void st_title(struct wl_client *c, uint32_t tl, const char *t) {
    uint8_t m[128];
    int p = put_string(m, 8, t);
    wr32(m + 0, tl);
    wr32(m + 4, ((uint32_t)p << 16) | XDG_TOPLEVEL_SET_TITLE);
    wl_dispatch(c, m, p);
}
/* Did we actually put that event on the wire? The queue is never drained here
 * (the endpoint is -1, so unix_send fails), which makes it a transcript. */
static int st_seen(struct wl_client *c, uint32_t obj, uint16_t op, uint32_t a0, int check_a0) {
    int off = 0;
    while (off + 8 <= c->outlen) {
        uint32_t o = rd32(c->out + off);
        uint32_t so = rd32(c->out + off + 4);
        int sz = (int)(so >> 16);
        uint16_t opc = (uint16_t)(so & 0xFFFF);
        if (sz < 8 || off + sz > c->outlen) break;
        if (o == obj && opc == op &&
            (!check_a0 || (sz >= 12 && rd32(c->out + off + 8) == a0))) return 1;
        off += sz;
    }
    return 0;
}
static int st_streq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}
static void st_fill(uint8_t *p, int npix, uint32_t v) {
    for (int i = 0; i < npix; i++) wr32(p + 4 * i, v);
}

void wl_selftest(void) {
    /* THE COUNTERS ARE RESTORED AT THE END. The boot self-test and the harness
     * both read wl_commits()/wl_messages_handled(), and kmain hands over to the
     * desktop as soon as a commit has been seen -- a self-test that leaves
     * those moved would break the very test it is meant to protect. */
    unsigned s_nmsg = g_nmsg, s_ncommit = g_ncommit, s_nglobal = g_nglobal;
    unsigned s_ndestroy = g_ndestroy, s_nproto = g_nprotoerr, s_nconn = g_nconn;
    int s_nunh = g_nunhandled;
    int slot = -1;
    for (int i = 0; i < WL_MAXCLIENT; i++) if (!g_cl[i].used) { slot = i; break; }
    if (slot < 0) { kprintf("WLSELFTEST: FAIL -- no free client slot\n"); return; }
    struct wl_client *c = &g_cl[slot];
    for (unsigned b = 0; b < sizeof *c; b++) ((char *)c)[b] = 0;
    c->used = 1;
    c->ep = -1;                  /* goes nowhere: the queue fills and stays */
    g_st_fail = 0; g_st_checks = 0;

    const unsigned long PSZ = 64 * 1024;
    uint8_t *pool = kmalloc(PSZ);
    if (!pool) { kprintf("WLSELFTEST: FAIL -- out of memory\n"); c->used = 0; return; }
    for (unsigned long i = 0; i < PSZ; i++) pool[i] = 0;
    st_fill(pool + 0,     32 * 16, 0x11223344u);   /* window one   32x16 */
    st_fill(pool + 4096,  24 * 24, 0xCC00CC00u);   /* a CURSOR     24x24 */
    st_fill(pool + 8192,  48 *  8, 0x33333333u);   /* window two   48x8  */

    /* The objects a bind would have made, made directly: the real client test
     * covers the registry and SCM_RIGHTS paths, and this one is about what
     * happens afterwards. */
    obj_add(c, 2, WLK_COMPOSITOR);
    obj_add(c, 3, WLK_XDG_WM_BASE);
    obj_add(c, 4, WLK_SEAT);
    struct wl_object *po = obj_add(c, 10, WLK_SHM_POOL);
    po->base = pool; po->size = 16384; po->cap = PSZ; po->mfd = -1;

    uint32_t a[6];
    /* create_buffer(new_id, offset, width, height, stride, format) */
    a[0]=20; a[1]=0;    a[2]=32; a[3]=16; a[4]=128; a[5]=0; st_req(c, 10, WL_SHM_POOL_CREATE_BUFFER, a, 6);
    a[0]=21; a[1]=4096; a[2]=24; a[3]=24; a[4]=96;  a[5]=0; st_req(c, 10, WL_SHM_POOL_CREATE_BUFFER, a, 6);
    a[0]=22; a[1]=8192; a[2]=48; a[3]=8;  a[4]=192; a[5]=0; st_req(c, 10, WL_SHM_POOL_CREATE_BUFFER, a, 6);
    a[0]=30; st_req(c, 2, WL_COMPOSITOR_CREATE_SURFACE, a, 1);
    a[0]=31; st_req(c, 2, WL_COMPOSITOR_CREATE_SURFACE, a, 1);
    a[0]=32; st_req(c, 2, WL_COMPOSITOR_CREATE_SURFACE, a, 1);
    /* surface 30 becomes a WINDOW */
    a[0]=40; a[1]=30; st_req(c, 3, XDG_WM_BASE_GET_XDG_SURFACE, a, 2);
    a[0]=41;          st_req(c, 40, XDG_SURFACE_GET_TOPLEVEL, a, 1);
    st_title(c, 41, "window one");
    /* surface 31 becomes a CURSOR */
    a[0]=50; st_req(c, 4, WL_SEAT_GET_POINTER, a, 1);
    a[0]=1; a[1]=31; a[2]=12; a[3]=12; st_req(c, 50, WL_POINTER_SET_CURSOR, a, 4);

    uint32_t w = 0, h = 0, st = 0;
    st_ck("a surface with no committed buffer is not drawn", wl_surface_pixels(&w, &h, &st) == 0);

    /* Commit the window. */
    a[0]=20; a[1]=0; a[2]=0; st_req(c, 30, WL_SURFACE_ATTACH, a, 3);
    st_req(c, 30, WL_SURFACE_COMMIT, 0, 0);
    const uint32_t *px = wl_surface_pixels(&w, &h, &st);
    st_ck("the committed toplevel is the drawn surface (32x16, stride 128)",
          px && w == 32 && h == 16 && st == 128 && px[0] == 0x11223344u);
    st_ck("wl_buffer.release was sent for the committed buffer",
          st_seen(c, 20, WL_BUFFER_EV_RELEASE, 0, 0));
    st_ck("the title comes from that toplevel", st_streq(wl_surface_title(), "window one"));

    /* THE BUG, exactly: commit a CURSOR surface afterwards. With one global
     * "last committed surface" the window's contents became this 24x24 buffer. */
    a[0]=21; a[1]=0; a[2]=0; st_req(c, 31, WL_SURFACE_ATTACH, a, 3);
    st_req(c, 31, WL_SURFACE_COMMIT, 0, 0);
    px = wl_surface_pixels(&w, &h, &st);
    st_ck("a CURSOR committing last does NOT become the window's contents",
          px && w == 32 && h == 16 && px[0] == 0x11223344u);

    /* A second window. The choice has to be STABLE, or the desktop's one
     * Wayland window flickers between a toolkit's own toplevels. */
    a[0]=42; a[1]=32; st_req(c, 3, XDG_WM_BASE_GET_XDG_SURFACE, a, 2);
    a[0]=43;          st_req(c, 42, XDG_SURFACE_GET_TOPLEVEL, a, 1);
    st_title(c, 43, "window two");
    a[0]=22; a[1]=0; a[2]=0; st_req(c, 32, WL_SURFACE_ATTACH, a, 3);
    st_req(c, 32, WL_SURFACE_COMMIT, 0, 0);
    px = wl_surface_pixels(&w, &h, &st);
    st_ck("a second toplevel does not displace the first", px && w == 32 && h == 16);
    st_ck("and the title is still the first window's", st_streq(wl_surface_title(), "window one"));

    /* Destroying the first window hands the display to the second -- which
     * only works if destruction actually drops the surface's state. */
    int nobj_before = c->nobj;
    st_req(c, 30, WL_SURFACE_DESTROY, 0, 0);
    st_ck("wl_display.delete_id was sent for the destroyed surface",
          st_seen(c, WL_DISPLAY_ID, WL_DISPLAY_EV_DELETE_ID, 30, 1));
    px = wl_surface_pixels(&w, &h, &st);
    st_ck("destroying the drawn surface promotes the other toplevel (48x8)",
          px && w == 48 && h == 8 && st == 192 && px[0] == 0x33333333u);
    st_ck("...and the titlebar follows it", st_streq(wl_surface_title(), "window two"));

    /* A freed slot is REUSED rather than appended, so a client that churns
     * objects no longer walks into WL_MAXOBJ. */
    a[0]=30; st_req(c, 2, WL_COMPOSITOR_CREATE_SURFACE, a, 1);
    st_ck("a destroyed object's table slot is reused, not leaked",
          c->nobj == nobj_before);
    struct wl_object *re = obj_find(c, 30);
    st_ck("and the reused slot carries none of the old object's state",
          re && re->role == WLR_NONE && re->width == 0 && re->base == 0 &&
          re->link == 0 && re->attached == 0);

    /* Losing the ROLE unmaps the surface: a window the client has taken down
     * must stop being drawn, and a cursor is never a fallback for it. */
    st_req(c, 43, XDG_TOPLEVEL_DESTROY, 0, 0);
    st_ck("destroying an xdg_toplevel unmaps its surface, and no cursor takes over",
          wl_surface_pixels(&w, &h, &st) == 0);

    /* Attaching NULL and committing is how a toolkit HIDES a window. */
    a[0]=44; a[1]=30; st_req(c, 3, XDG_WM_BASE_GET_XDG_SURFACE, a, 2);
    a[0]=45;          st_req(c, 44, XDG_SURFACE_GET_TOPLEVEL, a, 1);
    a[0]=21; a[1]=0; a[2]=0; st_req(c, 30, WL_SURFACE_ATTACH, a, 3);
    st_req(c, 30, WL_SURFACE_COMMIT, 0, 0);
    st_ck("a remapped surface is drawn again", wl_surface_pixels(&w, &h, &st) != 0);
    a[0]=0; a[1]=0; a[2]=0; st_req(c, 30, WL_SURFACE_ATTACH, a, 3);
    st_req(c, 30, WL_SURFACE_COMMIT, 0, 0);
    st_ck("attaching NULL and committing unmaps it", wl_surface_pixels(&w, &h, &st) == 0);

    /* wl_shm_pool.resize: within what the backing object holds it works, and
     * past it the client is TOLD rather than left with a blank window. */
    unsigned perr = g_nprotoerr;
    a[0]=32768; st_req(c, 10, WL_SHM_POOL_RESIZE, a, 1);
    struct wl_object *b21 = obj_find(c, 21);
    st_ck("wl_shm_pool.resize grows the pool within the object's capacity",
          po->size == 32768 && b21 && b21->size == 32768 && g_nprotoerr == perr);
    a[0]=1048576; st_req(c, 10, WL_SHM_POOL_RESIZE, a, 1);
    st_ck("a resize past the backing memfd is refused, not believed",
          po->size == 32768 && g_nprotoerr == perr + 1);
    st_ck("...and the client is told with wl_display.error",
          st_seen(c, WL_DISPLAY_ID, WL_DISPLAY_EV_ERROR, 10, 1));
    a[0]=4096; st_req(c, 10, WL_SHM_POOL_RESIZE, a, 1);
    st_ck("a SHRINKING resize is refused too", po->size == 32768 && g_nprotoerr == perr + 2);

    st_ck("every request this test sent had a handler", g_nunhandled == s_nunh);

    /* Hand the slot back exactly as it was found, and only then free the pool
     * the surfaces point into. */
    c->nobj = 0; c->used = 0; c->ep = -1;
    kfree(pool);
    g_nmsg = s_nmsg; g_ncommit = s_ncommit; g_nglobal = s_nglobal;
    g_ndestroy = s_ndestroy; g_nprotoerr = s_nproto; g_nconn = s_nconn;
    g_nunhandled = s_nunh;
    kprintf("WLSELFTEST: %s -- %d check(s), %d failure(s)\n",
            g_st_fail ? "FAILED" : "PASSED", g_st_checks, g_st_fail);
}

int wl_compositor_init(void) {
    g_listener = unix_listen(WL_SOCK_PATH);
    if (g_listener < 0) { kprintf("[wl] could not bind %s\n", WL_SOCK_PATH); return -1; }
    kprintf("[ ok ] wayland: display up at %s (%d globals advertised)\n", WL_SOCK_PATH, WL_NGLOBAL);
    return 0;
}

/* The display server's own task: serve clients for as long as the system runs.
 * 5 ms is a compromise -- a display that polls is not what we want long term
 * (the AF_UNIX layer can wake a waiter), but it is honest about what this is
 * today, and it keeps the server responsive without spinning a core. */
/* IS A PAGE ON SCREEN, OR ONLY THE CHROME? (M2106)
 *
 * "Firefox has painted" has meant `wl_largest_window() >= 640x480` for three
 * milestones, and that is a statement about GEOMETRY. A browser showing its own
 * chrome around an empty content area satisfies it exactly as well as one
 * showing a web page, so the one question this campaign exists to answer was
 * the one thing not being measured -- and I have been answering it by taking a
 * screenshot and reading a pixel out of it by hand, once per run, at the centre
 * of the window, which lands on whatever happens to be there.
 *
 * So: sample a grid across the CONTENT area -- below the chrome, which is about
 * 90px of tab strip and toolbar -- and report what colour actually dominates
 * it, with the top few runners-up. A page whose background we chose (#101820,
 * tools/lx/ffpage.html) is then a fact about the framebuffer rather than an
 * impression: either most of the content area is that colour or it is not.
 *
 * Reporting the DISTRIBUTION rather than a single yes/no is deliberate. The
 * failure modes are not binary -- a page that loaded but painted white, a page
 * behind a translucent overlay, and a content area that never got a buffer are
 * three different bugs, and they are distinguishable only by what else is
 * there. A bare "no" would have sent me looking in the wrong place. */
/* LOOK AT IT (M2110).
 *
 * "84% of the content area is #f9f9fb" has been the whole description of what
 * Firefox is showing for this entire campaign, and a colour histogram cannot
 * tell a blank page from a page rendered somewhere unexpected, from a page
 * scrolled off, from chrome drawn twice. The highest-yield thing anyone has
 * ever done to this project's browser work was render a real page and LOOK at
 * the pixels -- one screenshot of example.com exposed three separate gaps.
 *
 * So emit the composited window as a small PPM, nearest-neighbour downscaled,
 * in hex over the serial line, and reassemble it on the host. 64x48 is big
 * enough to see where a dark page background is and is not, and costs 18 KB of
 * log rather than the 4.4 MB the real buffer would. */
#define WL_DUMP_W 64
#define WL_DUMP_H 48
void wl_page_dump(void) {
    int best = -1; uint64_t barea = 0;
    for (int ci = 0; ci < WL_MAXCLIENT; ci++) {
        if (!g_cl[ci].used) continue;
        uint32_t w = 0, h = 0; wl_client_extent(ci, &w, &h);
        if ((uint64_t)w * h > barea) { barea = (uint64_t)w * h; best = ci; }
    }
    if (best < 0 || !barea) { kprintf("[dump] no window to dump\n"); return; }
    uint32_t ww = 0, wh = 0; wl_client_extent(best, &ww, &wh);
    struct wl_layer L[32];
    int nl = wl_client_layers(best, L, 32);
    if (nl <= 0) { kprintf("[dump] no layers\n"); return; }
    kprintf("[dump] PPMBEGIN %d %d (from a %ux%u window, %d layer(s))\n",
            WL_DUMP_W, WL_DUMP_H, ww, wh, nl);
    for (int gy = 0; gy < WL_DUMP_H; gy++) {
        for (int gx = 0; gx < WL_DUMP_W; gx++) {
            uint32_t x = (uint32_t)((uint64_t)gx * ww / WL_DUMP_W);
            uint32_t y = (uint32_t)((uint64_t)gy * wh / WL_DUMP_H);
            /* Topmost NON-TRANSPARENT pixel, which is what the desktop
             * actually blits now that alpha is honoured (M2115). Taking the
             * topmost pixel regardless made the instrument disagree with the
             * screen wherever a toolkit's shadow overhangs. */
            uint32_t got = 0;
            for (int i = 0; i < nl; i++) {
                if (!L[i].px) continue;
                if ((int)x < L[i].x || (int)y < L[i].y) continue;
                uint32_t lx = x - (uint32_t)L[i].x, ly = y - (uint32_t)L[i].y;
                if (lx >= L[i].w || ly >= L[i].h) continue;
                uint32_t v = L[i].px[ly * (L[i].stride / 4) + lx];
                if (L[i].format == 0 && !(v >> 24)) continue;      /* fully transparent */
                got = v;
            }
            kprintf("%02x%02x%02x", (got >> 16) & 0xff, (got >> 8) & 0xff, got & 0xff);
        }
        kprintf("\n");
    }
    kprintf("[dump] PPMEND\n");
}

#define WL_PROBE_GRID 32
/* RETURNS 1 WHEN THE PAGE IS ACTUALLY ON SCREEN (M2200), 0 otherwise.
 *
 * It was void, and the caller therefore had no way to know what it had just
 * printed -- so the ffwl run sampled a fixed forty times at fifteen seconds
 * whatever the answer was, and the window manager was not allowed to run for
 * ten minutes after the page had already rendered. The demo is a human looking
 * at the screen; a probe that has proved the thing and then blocks the screen
 * for another nine minutes is measuring instead of delivering. */
/* THE FILESYSTEM'S HEALTH, PRINTABLE WITHOUT A WINDOW (M2225).
 *
 * This lived inside wl_page_probe, which only runs once a client has a
 * >=640x480 window -- so the boots that most needed it, the ones where Firefox
 * never got a window at all, printed nothing. A health line gated behind the
 * very success whose absence it exists to explain is not an instrument. */
void wl_fs_health_line(void) {
    /* AND WHETHER THE FILESYSTEM BELIEVES ITSELF (M2221). These counters only
     * ever appeared inside a fault report, so a boot that did not fault showed
     * none of them -- and the ones that matter most describe reads that
     * SUCCEEDED while returning the wrong bytes. Printed every sample, where a
     * zero is as informative as a number. */
    {   extern unsigned long g_e2_sb_readfail, g_e2_sb_badmagic, g_e2_sb_badfield;
        extern unsigned long g_e2_sb_retried, g_e2_sb_retry_ok, g_e2_holes;
        extern unsigned long g_e2_bad_itable, g_e2_bad_ptrs, g_e2_distrust;
        extern unsigned long g_e2_itable_reread, g_e2_itable_differed, g_e2_itable_secondgood;
        extern uint64_t g_e2_itable_lba;
        extern unsigned char g_e2_itable_saw[8];
        extern unsigned long g_fill_exec_refused, g_fill_exec_hole, g_fill_distrust;
        extern unsigned long g_fill_cachedrop, g_fill_cachedrop_ok;
        extern unsigned long g_memfd_remapped, g_memfd_unretired;
        extern unsigned long g_bd_fail_n[9];
        extern int g_bd_badidx, g_bd_badndev;
        extern unsigned long g_bd_init_calls, g_bd_reg_skipped;
        extern unsigned long g_bd_wtrip_n, g_bd_wr_total;
        extern unsigned long g_bd_wr_refused; extern uint64_t g_bd_wr_ref_lba;
        extern unsigned long g_e2_gd_badread, g_e2_gd_reread_ok, g_e2_gd_writeref;
        extern unsigned long g_e2_gd_pio_good, g_e2_gd_pio_same, g_e2_gd_pio_fail;
        extern unsigned long g_tab_polls, g_tab_reports, g_tab_errs, g_tab_short;
        extern unsigned long g_tab_cs, g_tab_elem, g_tab_frnum, g_tab_cmd, g_tab_sts;
        extern unsigned long g_dk_keys, g_dk_fwd, g_dk_mot, g_dk_btn; extern int g_dk_focus_kind;
        unsigned wl_keys_sent(void);
        extern unsigned g_axis_sent;
        extern unsigned g_ptr_enters;   /* the per-client array below is what is printed (M2246) */
        extern unsigned g_ptr_enter_by[];
        extern unsigned long g_peerready_calls, g_peerready_hits;
        /* 80 WAS TOO SMALL FOR ITS OWN GUARD (M2292): the loop admitted an
         * entry at en=67 and then wrote about twenty-two bytes without
         * checking again, so four clients could run off the end of a stack
         * buffer -- inside the diagnostics, which is the worst place to
         * corrupt a frame because it only fires when something is already
         * wrong. Sized for what it holds. */
        char ent[192]; int en = 0;
        for (int q = 0; q < WL_MAXCLIENT && en < 160; q++) {
            if (!g_cl[q].used) continue;
            en += ksnprint_u(ent + en, (unsigned)q); ent[en++] = ':';
            en += ksnprint_u(ent + en, g_ptr_enter_by[q]);
            ent[en++] = '/'; en += ksnprint_u(ent + en, g_cl[q].surface);
            /* ALL of them, not the last one (M2298). `p27` was the whole
             * bug printed in two characters and read as a fact: Firefox's
             * pointer is 27 -- when Firefox's pointer was ALSO 9, and 9 was
             * the one with a listener on it. A census that shows one member
             * of a set cannot show that the set has two. */
            ent[en++] = 'p';
            for (int r = 0; r < g_cl[q].nptr && en < 170; r++) {
                if (r) ent[en++] = '+';
                en += ksnprint_u(ent + en, g_cl[q].ptrs[r]);
            }
            if (!g_cl[q].nptr) ent[en++] = '-';
            ent[en++] = 'k';
            for (int r = 0; r < g_cl[q].nkbd && en < 170; r++) {
                if (r) ent[en++] = '+';
                en += ksnprint_u(ent + en, g_cl[q].kbds[r]);
            }
            if (!g_cl[q].nkbd) ent[en++] = '-';
            /* BYTES STILL IN OUR OUTPUT BUFFER (M2261). wl_flush_locked stops
             * on a full socket ring and leaves the remainder queued, retried
             * only by the NEXT send. If a client's queue is persistently
             * non-zero, events we believe we delivered are sitting here. */
            ent[en++] = 'q'; en += ksnprint_u(ent + en, (unsigned)g_cl[q].outlen);
            /* AN ID THAT MEANS TWO THINGS (M2248). Object ids are unique per
             * CONNECTION; if our table ever holds one id as both a surface and
             * a pointer, every lookup after that is a coin toss. Flag it here
             * rather than reasoning about whether it can happen. */
            {   int dup = 0;
                for (int j1 = 0; j1 < g_cl[q].nobj && !dup; j1++)
                    for (int j2 = j1 + 1; j2 < g_cl[q].nobj && !dup; j2++)
                        if (g_cl[q].obj[j1].id && g_cl[q].obj[j1].id == g_cl[q].obj[j2].id &&
                            g_cl[q].obj[j1].kind != g_cl[q].obj[j2].kind) dup = 1;
                if (dup) ent[en++] = '!';
            }
            ent[en++] = ' ';
        }
        ent[en] = 0;
        /* WHICH client is getting these? The one with the toplevel -- the one
         * whose window the user is looking at -- must have a pointer and a
         * keyboard bound, or we are broadcasting input to content processes
         * and none of it reaches the browser. (M2245) */
        char who[96]; int wn = 0;
        for (int q = 0; q < WL_MAXCLIENT && wn < 80; q++) {
            if (!g_cl[q].used) continue;
            int tl = 0;
            for (int j = 0; j < g_cl[q].nobj; j++)
                if (g_cl[q].obj[j].id && g_cl[q].obj[j].kind == WLK_SURFACE &&
                    g_cl[q].obj[j].role == WLR_TOPLEVEL) tl = 1;
            who[wn++] = (char)('0' + q);
            who[wn++] = tl ? 'T' : '-';
            who[wn++] = (char)('0' + (g_cl[q].nptr > 9 ? 9 : g_cl[q].nptr)); who[wn++] = 'P';
            who[wn++] = (char)('0' + (g_cl[q].nkbd > 9 ? 9 : g_cl[q].nkbd)); who[wn++] = 'K';
            who[wn++] = ' ';
        }
        who[wn] = 0;
        int kbclients = 0;
        for (int q = 0; q < WL_MAXCLIENT; q++) if (g_cl[q].used && g_cl[q].nkbd) kbclients++;
        extern int g_tab_lastx, g_tab_lasty, g_tab_lastbtn;
        extern uint64_t g_bd_fail_cap4, g_bd_fail_lba4;
        /* Declared here rather than in ata.h, the same way app.c's fault
         * report reaches them: they are diagnostics, not driver API. */
        extern void ata_error_counts(uint64_t *retries, uint64_t *failures);
        extern uint64_t ata_dma_short_count(void);
        uint64_t atretr = 0, atfail = 0; ata_error_counts(&atretr, &atfail);
        kprintf("[fs] superblock: %lu readfail %lu BADMAGIC %lu badfield, %lu retried %lu "
                "RETRY-OK | %lu itable (re-read %lu: %lu DIFFERED, %lu then VALID; last from LBA %lu, "
                "bytes %02x %02x %02x %02x %02x %02x %02x %02x) %lu badptr "
                "%lu hole(s) | distrust %lu | refused: "
                "%lu exec %lu exec-hole %lu device | cache-drop retries %lu, %lu RECOVERED | "
                "ata: %lu retr %lu FAIL %lu dma-short | memfd: %lu remap %lu unretired | "
                "blockdev refusals by reason: idx %lu nohook %lu zerocount %lu LBA>=cap %lu "
                "ovf %lu past-cap %lu driver %lu BADIDX %lu (last cap-refusal: lba %lu vs cap %lu; "
                "last bad index %d against g_ndev %d) | blockdev_init x%lu, %lu re-reg skipped | "
                "writes: %lu total, %lu BELOW LBA 32, %lu REFUSED out-of-range (last lba %lu) | "
                "gdt: %lu bad on read, %lu fixed by re-read, %lu REFUSED at write; "
                "PIO says: %lu DISK-WAS-FINE (recovered), %lu disk really bad, %lu read failed | "
                "tablet: %lu polls, %lu reports, %lu err, %lu short, last %d,%d btn %d | "
                "td.cs %lx elem %lx frnum %lu cmd %lx sts %lx | "
                "keys: %lu dequeued, %lu forwarded to wayland, focus kind %d, "
                "%lu SENT on the wire to %d client(s) with a wl_keyboard, %lu axis event(s) | "
                "clients [slot/Toplevel/nPointer/nKeyboard]: %s | ptr fwd: %lu motion, %lu BUTTON | "
                "peer-ready: %lu calls, %lu MATCHED an fd | "
                "%u enter(s) | per-client enter surface/root: %s\n",
                g_e2_sb_readfail, g_e2_sb_badmagic, g_e2_sb_badfield,
                g_e2_sb_retried, g_e2_sb_retry_ok,
                g_e2_bad_itable, g_e2_itable_reread, g_e2_itable_differed,
                g_e2_itable_secondgood, (unsigned long)g_e2_itable_lba,
                g_e2_itable_saw[0], g_e2_itable_saw[1], g_e2_itable_saw[2], g_e2_itable_saw[3],
                g_e2_itable_saw[4], g_e2_itable_saw[5], g_e2_itable_saw[6], g_e2_itable_saw[7],
                g_e2_bad_ptrs, g_e2_holes, g_e2_distrust,
                g_fill_exec_refused, g_fill_exec_hole, g_fill_distrust,
                g_fill_cachedrop, g_fill_cachedrop_ok,
                (unsigned long)atretr, (unsigned long)atfail,
                (unsigned long)ata_dma_short_count(),
                g_memfd_remapped, g_memfd_unretired,
                g_bd_fail_n[1], g_bd_fail_n[2], g_bd_fail_n[3], g_bd_fail_n[4],
                g_bd_fail_n[5], g_bd_fail_n[6], g_bd_fail_n[7], g_bd_fail_n[8],
                (unsigned long)g_bd_fail_lba4, (unsigned long)g_bd_fail_cap4,
                g_bd_badidx, g_bd_badndev, g_bd_init_calls, g_bd_reg_skipped,
                g_bd_wr_total, g_bd_wtrip_n, g_bd_wr_refused, (unsigned long)g_bd_wr_ref_lba,
                g_e2_gd_badread, g_e2_gd_reread_ok, g_e2_gd_writeref,
                g_e2_gd_pio_good, g_e2_gd_pio_same, g_e2_gd_pio_fail,
                g_tab_polls, g_tab_reports, g_tab_errs, g_tab_short,
                g_tab_lastx, g_tab_lasty, g_tab_lastbtn,
                g_tab_cs, g_tab_elem, g_tab_frnum, g_tab_cmd, g_tab_sts,
                g_dk_keys, g_dk_fwd, g_dk_focus_kind,
                (unsigned long)wl_keys_sent(), kbclients, (unsigned long)g_axis_sent, who, g_dk_mot, g_dk_btn,
                g_peerready_calls, g_peerready_hits,
                g_ptr_enters, ent); }

    /* WHAT THE CLIENT HAS ACTUALLY TAKEN OFF THE SOCKET (M2292).
     *
     * `q0` has been read three separate times in this campaign as "the events
     * reached Firefox", and it does not say that. `q` is OUR queue: wl_send
     * appends to it and wl_flush_locked drains it into unix_send, which
     * copies into a 64 KiB ring inside the kernel. A client that has not
     * called read() since it started still leaves q at 0, because a whole
     * click burst -- 13 motions, 24 buttons, their frames -- is about 1.5 KiB,
     * two percent of that ring. The one row of the evidence table that was
     * supposed to prove delivery proved only that we let go of the bytes.
     *
     * So count both ends. `sent` is every byte handed to unix_send; `unread`
     * is what is still sitting in the ring. The difference is what the guest
     * process has genuinely consumed, and it is the last hop we can see:
     *
     *   unread climbs by a click's worth and STAYS  -> nobody is reading that
     *      socket, and that is ours: a poll/epoll/futex or scheduling fault
     *      in the thread that owns the fd.
     *   unread returns to 0                         -> Gecko read the events
     *      and did nothing with them, and the fault is above us.
     *
     * Two numbers, and they separate the two halves of a question this
     * campaign has spent four days unable to answer. */
    {   char io[192]; int n = 0;
        int cap = unix_ring_bytes();
        for (int q = 0; q < WL_MAXCLIENT && n < 150; q++) {
            if (!g_cl[q].used) continue;
            int room = unix_txroom(g_cl[q].ep);
            int unread = room < 0 ? -1 : cap - room;
            n += ksnprint_u(io + n, (unsigned)q); io[n++] = ':';
            n += ksnprint_u(io + n, (unsigned)g_cl[q].sent); io[n++] = 's';
            io[n++] = '/';
            n += ksnprint_u(io + n, (unsigned)g_cl[q].nin); io[n++] = 'm';
            io[n++] = '/';
            if (unread < 0) { io[n++] = 'X'; }
            else n += ksnprint_u(io + n, (unsigned)unread);
            io[n++] = 'u'; io[n++] = '/';
            /* AND WHO IS READING IT (M2292). */
            {   int nt = 0, lt = 0; unsigned long rc = 0;
                unix_peer_readers(g_cl[q].ep, &nt, &lt, &rc);
                n += ksnprint_u(io + n, (unsigned)(nt < 0 ? 0 : nt)); io[n++] = 't';
                n += ksnprint_u(io + n, (unsigned)lt); io[n++] = '#'; }
            io[n++] = ' ';
        }
        io[n] = 0;
        extern unsigned long g_poll_nfds_refused; extern long g_poll_nfds_high;
        extern unsigned long g_scm_held_back;
        kprintf("[wlio] per-client Ns sent / Nm msgs received / Nu UNREAD in the "
                "ring / Nt distinct reader threads #last-tid (ring holds %d): %s "
                "| poll: biggest nfds seen %ld, %lu REFUSED for too many fds "
                "| scm: %lu sendmsg(s) carried descriptors the socket could not "
                "take, so they were NOT queued twice\n",
                cap, io, g_poll_nfds_high, g_poll_nfds_refused, g_scm_held_back);
    }
}

int wl_page_probe(uint32_t want) {
    int best = -1; uint64_t barea = 0;
    for (int ci = 0; ci < WL_MAXCLIENT; ci++) {
        if (!g_cl[ci].used) continue;
        uint32_t w = 0, h = 0; wl_client_extent(ci, &w, &h);
        if ((uint64_t)w * h > barea) { barea = (uint64_t)w * h; best = ci; }
    }
    if (best < 0 || barea == 0) { kprintf("[page] no client has a window to sample\n"); return 0; }
    uint32_t ww = 0, wh = 0; wl_client_extent(best, &ww, &wh);
    struct wl_layer L[WL_MAXOBJ > 32 ? 32 : WL_MAXOBJ];
    int nl = wl_client_layers(best, L, (int)(sizeof L / sizeof L[0]));
    if (nl <= 0) { kprintf("[page] client %d has a %ux%u extent but no layers\n", best, ww, wh); return 0; }

    /* The chrome is at the top. Sample below it, and never outside the window. */
    uint32_t y0 = wh > 200 ? 92 : 0;
    struct { uint32_t c; int n; } tally[10];
    int nt = 0, sampled = 0, hit = 0, uncovered = 0;
    for (int gy = 0; gy < WL_PROBE_GRID; gy++) {
        for (int gx = 0; gx < WL_PROBE_GRID; gx++) {
            uint32_t x = (uint32_t)((uint64_t)gx * ww / WL_PROBE_GRID);
            uint32_t y = y0 + (uint32_t)((uint64_t)gy * (wh - y0) / WL_PROBE_GRID);
            /* Topmost layer covering the point wins: wl_layers writes parents
             * first, so the LAST match is the one actually visible. */
            uint32_t got = 0; int found = 0;
            for (int i = 0; i < nl; i++) {
                if (!L[i].px) continue;
                if ((int)x < L[i].x || (int)y < L[i].y) continue;
                uint32_t lx = x - (uint32_t)L[i].x, ly = y - (uint32_t)L[i].y;
                if (lx >= L[i].w || ly >= L[i].h) continue;
                uint32_t v = L[i].px[ly * (L[i].stride / 4) + lx];
                if (L[i].format == 0 && !(v >> 24)) continue;      /* transparent: not what is shown (M2115) */
                got = v; found = 1;
            }
            sampled++;
            if (!found) { uncovered++; continue; }
            if ((got & 0x00ffffffu) == (want & 0x00ffffffu)) hit++;
            int f = -1;
            for (int i = 0; i < nt; i++) if (tally[i].c == got) { f = i; break; }
            if (f < 0 && nt < 10) { f = nt++; tally[f].c = got; tally[f].n = 0; }
            if (f >= 0) tally[f].n++;
        }
    }
    kprintf("[page] client %d ('%s') %ux%u, %d layer(s): %d samples of the content area (y >= %u)\n",
            best, wl_client_title_of(best), ww, wh, nl, sampled, y0);
    /* VSYNC, because the refresh driver that paints page content runs on it
     * and a stalled one is indistinguishable from a page that will not render
     * (M2110). Callbacks SENT against ticks OFFERED: if the first is ~0 while
     * the second climbs, the client is not asking -- which is a different bug
     * from a compositor that is not answering. */
    kprintf("[page]   vsync: %u requested, %u answered (%u by the tick, %u by a commit), "
            "%u tick(s) offered, %u commit(s)\n",
            wl_frame_requests(), wl_frame_callbacks_sent(),
            wl_frame_callbacks_sent() - wl_frame_by_commit(), wl_frame_by_commit(),
            wl_frame_ticks(), wl_commits());
    /* NAME THE LAYERS (M2107). "2 layer(s)" cannot distinguish a window whose
     * content surface is present and blank from one whose content surface was
     * never created -- and those are opposite bugs. A toolkit puts the page in
     * its own subsurface, so the geometry of each layer says which. */
    for (int i = 0; i < nl; i++)
        kprintf("[page]   layer %d: %ux%u at +%d,+%d stride %u%s\n",
                i, L[i].w, L[i].h, L[i].x, L[i].y, L[i].stride,
                L[i].px ? "" : "  (NO BUFFER)");
    /* WHAT IS IN EACH LAYER, SEPARATELY (M2132).
     *
     * The tally above reports what is VISIBLE -- the topmost non-transparent
     * pixel at each sample point -- which is the right question for "is the
     * page on screen" and the wrong one for "did the page arrive at all".
     * This window consistently presents TWO full-size layers at the same
     * origin, and if the page were in the lower one and something blank
     * were on top, or if one of them were a stale buffer, the visible tally
     * could not tell. So sample the page's own colour in each layer
     * independently: a layer that contains it is a layer Gecko painted. */
    for (int i = 0; i < nl; i++) {
        if (!L[i].px) continue;
        int n = 0, hits = 0, opaque = 0;
        uint32_t first = 0; int uniform = 1;
        for (int gy = 0; gy < WL_PROBE_GRID; gy++)
            for (int gx = 0; gx < WL_PROBE_GRID; gx++) {
                uint32_t lx2 = (uint32_t)((uint64_t)gx * L[i].w / WL_PROBE_GRID);
                uint32_t ly2 = (uint32_t)((uint64_t)gy * L[i].h / WL_PROBE_GRID);
                uint32_t v = L[i].px[ly2 * (L[i].stride / 4) + lx2];
                if (!n) first = v;
                else if (v != first) uniform = 0;
                n++;
                if (L[i].format != 0 || (v >> 24)) opaque++;
                if ((v & 0x00ffffffu) == (want & 0x00ffffffu)) hits++;
            }
        kprintf("[page]   layer %d content: %d/%d sample(s) are the page's %06x, "
                "%d opaque, %s (first px %08x)\n",
                i, hits, n, (unsigned)(want & 0x00ffffffu), opaque,
                uniform ? "UNIFORM -- one colour everywhere" : "varied", first);
    }
    /* Selection sort by count -- ten entries, and the order is the whole point. */
    for (int i = 0; i < nt; i++) {
        int m = i;
        for (int j = i + 1; j < nt; j++) if (tally[j].n > tally[m].n) m = j;
        if (m != i) { uint32_t c = tally[i].c; int n = tally[i].n;
                      tally[i] = tally[m]; tally[m].c = c; tally[m].n = n; }
    }
    for (int i = 0; i < nt && i < 5; i++)
        kprintf("[page]   %08x  %d (%d%%)%s\n", tally[i].c, tally[i].n,
                sampled ? tally[i].n * 100 / sampled : 0,
                (tally[i].c & 0x00ffffffu) == (want & 0x00ffffffu) ? "   <-- the page background" : "");
    if (uncovered) kprintf("[page]   %d sample(s) were not covered by any layer at all\n", uncovered);
    /* AND WHETHER THE PIXELS CAME FROM THE CLIENT AT ALL (M2200). Both of
     * these counters existed and neither was ever printed, so the question
     * "is the compositor reading the client's own memory" could only be
     * answered by a log line that fires when the answer is no -- and a
     * counter with no report cannot say that the answer was YES. */
    {   extern unsigned long g_memfd_remapped;
        kprintf("[page]   shm: %lu commit(s) blitted the client's OWN frame, %lu did not; "
                "%lu page(s) re-pointed after a mapped memfd grew\n",
                g_wl_shm_ok, g_wl_shm_mismatch, g_memfd_remapped); }
    /* AND THE SAME QUESTION ABOUT EVERY OTHER SHARED MAPPING (M2203). The
     * commit check above covers the wl_shm pool the compositor is blitting; the
     * content process ships its rendering to the parent through memfds of its
     * own, and a window with working chrome and a background-coloured content
     * area is what a broken one of THOSE looks like. */
    {   extern unsigned long app_memfd_share_audit(int verbose);
        app_memfd_share_audit(1); }
    /* State the verdict, and state it against a threshold, so a page that
     * painted a thin strip of itself cannot read as a page that loaded. */
    int pct = sampled ? hit * 100 / sampled : 0;
    if (pct >= 50) {
        /* WHEN, TO THE MILLISECOND (M2169). The goal for this work is the word
         * "fast", and until now the only timing available was the page-probe
         * sampler -- which fires every FIFTEEN SECONDS, so it cannot tell 9
         * seconds from 24. A whole day's A/B of the block cache came back
         * "both arms reached the page inside the first sample", which measures
         * nothing. One `timer_ms()` makes the thing the goal names observable.
         * Printed ONCE, from a flag, so the repeated per-sample verdicts do not
         * each claim to be the first. */
        {   static int said;
            if (!said) { said = 1;
                kprintf("[time] PAGE ON SCREEN at %lu ms since boot\n",
                        (unsigned long)timer_ms()); } }
        kprintf("[page] VERDICT: the PAGE is on screen -- %d%% of the content area is %06x\n",
                pct, want & 0x00ffffffu);
    } else
        /* SAY WHAT THE DOCUMENT DID, IN THIS LINE (M2174). "Only the chrome" on
         * its own sends the reader to the renderer. Whether the document was
         * FETCHED is what decides between "the page did not load" and "the page
         * loaded and painted nothing", and those need opposite investigations.
         * Measured across a failing and a passing boot, the reads are
         * byte-identical -- so this line saying so is what stops the next
         * person re-deriving it from two log copies. */
        {   unsigned long ho = 0, hr = 0, hb = 0;
            extern void lx_html_stats(unsigned long *, unsigned long *, unsigned long *);
            lx_html_stats(&ho, &hr, &hb);
            kprintf("[page]   the document was OPENED %lu time(s) and %lu read(s) delivered %lu "
                    "byte(s) -- %s\n", ho, hr, hb,
                    hb ? "so it was fetched and the content area is still blank: look at "
                         "navigation, not at paint"
                       : "so it was never fetched: look at the load, not at the renderer"); }
        /* AND WHAT EVERY COMMIT EVER CARRIED (M2190). The sampled verdict is
         * about this instant; this is about the whole run, so "not the page
         * now" and "never the page" stop being the same sentence. */
        if (g_wl_commits_seen)
            kprintf("[page]   across ALL %u commit(s) the content area was at most %u%% the "
                    "page's colour, and %u commit(s) were mostly it -- %s\n",
                    g_wl_commits_seen, g_wl_page_best, g_wl_page_commits,
                    g_wl_page_commits ? "so the page WAS presented and is not on screen now"
                                      : "so the page was NEVER presented in any frame");
        kprintf("[page] VERDICT: only the CHROME -- %d%% of the content area is the page's %06x, "
                "so the content area is showing something else\n", pct, want & 0x00ffffffu);
    return pct >= 50;
}

/* VSYNC IS A PERIODIC SIGNAL, NOT A REPLY TO A COMMIT (M2110).
 *
 * M2042 answered wl_surface.frame from inside the commit handler for the
 * surface the callback was requested on. That is enough for a client which
 * requests a callback and then commits that same surface -- our own test client
 * does exactly that -- and it is NOT what a compositor does, because the
 * protocol's meaning of the callback is "it is a good time to draw the next
 * frame", which is a property of the compositor's repaint cycle and not of the
 * client's last request.
 *
 * It matters because GECKO'S REFRESH DRIVER RUNS ON THIS. Firefox's content is
 * painted by the refresh driver, the refresh driver is driven by vsync, and on
 * Wayland vsync IS the frame callback. Firefox commits its content subsurface
 * 127 times in a startup and its toplevel twice -- so any callback outstanding
 * on a surface that is not the one being committed was answered late or never,
 * and a refresh driver that stops ticking paints the chrome once and never
 * paints a page. Which is precisely what the framebuffer showed for this whole
 * campaign.
 *
 * So: answer every outstanding callback on a steady tick. Firing one for a
 * surface the client has not committed is correct and is the point -- it means
 * "draw again now". Each is cleared as it fires, so nothing is answered twice,
 * and the id is released with delete_id exactly as before. */
unsigned wl_frame_ticks(void) { return g_frame_ticks; }
unsigned wl_frame_callbacks_sent(void) { return g_frame_done + g_frame_done_commit; }
unsigned wl_frame_requests(void) { return g_frame_req; }
unsigned wl_frame_by_commit(void) { return g_frame_done_commit; }
void wl_frame_tick(void) {
    g_frame_ticks++;
    /* GIVE THE WINDOW KEYBOARD FOCUS (M2113).
     *
     * wl_keyboard.enter was only ever sent from the INPUT path -- so a client
     * received focus when somebody pressed a key, and never otherwise. With
     * nobody typing, Firefox spent every run believing it had no focused
     * window, and said so itself:
     *
     *     D/Widget nsWindowWayland::TransferFocusTo() gFocusWindow 0
     *     D/Widget   quit, failed to create focus promise
     *
     * A compositor gives focus when a window is mapped, not when a key
     * arrives. The biggest mapped window gets it, which is the same rule the
     * rest of this file uses to decide which window is the real one. */
    {   /* THE SAME TWO-RULES BUG, FOR THE KEYBOARD (M2281).
         *
         * M2275 made the window manager the authority for POINTER delivery,
         * because the compositor's "biggest surface" heuristic and the WM's
         * "topmost visible window" are unrelated rules that disagree while
         * windows are appearing. This site was left on the old rule, so
         * keyboard FOCUS could be granted to one client while the WM was
         * sending that client's keystrokes to another -- and Firefox runs
         * four connections for the heuristic to choose between.
         *
         * One authority, both devices. The area rule stays only as the
         * fallback for when nothing has been focused yet, which is exactly
         * what wl_focus_client already encodes. */
        int best = wl_focus_client();
        if (best >= 0) wl_kbd_enter(&g_cl[best]);   /* no-ops if already entered */
        /* AND TELL EVERY MAPPED TOPLEVEL WHICH OUTPUT IT IS ON (M2247).
         *
         * wl_surface.enter is how a client learns its surface is actually on a
         * display -- it is where GTK gets the scale factor, and a toolkit that
         * never receives one can treat the window as not yet on screen. This
         * compositor advertised wl_output, answered the bind, and then never
         * associated a single surface with it.
         *
         * Sent once per client, from the same steady tick that grants keyboard
         * focus, because both answer the same question: this window is real
         * and it is visible. */
        for (int ci2 = 0; ci2 < WL_MAXCLIENT; ci2++) {
            struct wl_client *cc = &g_cl[ci2];
            if (!cc->used || !cc->surface || !cc->output) continue;
            if (cc->surf_entered == cc->surface) continue;
            uint8_t ob[4]; wr32(ob, cc->output);
            wl_send(cc, cc->surface, WL_SURFACE_EV_ENTER, ob, 4);
            cc->surf_entered = cc->surface;
            kprintf("[wl] surface %u is on output %u (wl_surface.enter)\n",
                    cc->surface, cc->output);
        }
    }
    uint32_t ms = (uint32_t)timer_ms();
    for (int i = 0; i < WL_MAXCLIENT; i++) {
        struct wl_client *c = &g_cl[i];
        if (!c->used) continue;
        for (int o = 0; o < c->nobj; o++) {
            struct wl_object *ob = &c->obj[o];
            if (!ob->id || !ob->frame_cb) continue;
            uint32_t cb = ob->frame_cb;
            ob->frame_cb = 0;                    /* one done per request */
            uint8_t ts[4]; wr32(ts, ms);
            wl_send(c, cb, WL_CALLBACK_EV_DONE, ts, 4);
            uint8_t dq[4]; wr32(dq, cb);
            wl_send(c, WL_DISPLAY_ID, WL_DISPLAY_EV_DELETE_ID, dq, 4);
            g_frame_done++;
        }
    }
}

void wl_server_task(void) {
    /* ~60 Hz, which is what a client asking for vsync expects to get. The poll
     * itself stays on its 5 ms cadence: draining the socket promptly and
     * pacing repaints are different jobs and were previously the same one. */
    unsigned n = 0;
    for (;;) {
        wl_compositor_poll();
        if (++n % 3 == 0) wl_frame_tick();       /* 3 x 5 ms ~= 60 Hz */
        task_sleep_ms(5);
    }
}

/* --- input, from the window manager out to the client (M1983) ------------- *
 *
 * The desktop owns the keyboard and the mouse; a Wayland client only ever sees
 * what the compositor forwards, and only while it has focus. That is the whole
 * security model of the protocol, and it falls out naturally here because the
 * events arrive from kernel/desktop.c's own input path.
 *
 * enter() must come first. A client ignores motion, buttons and keys for a
 * surface it has not been told it has -- so a compositor that forwards input
 * without entering first sends events that are correctly parsed and silently
 * dropped, which looks exactly like input not working. */
static unsigned g_keys_sent, g_ptr_sent;
unsigned g_axis_sent;   /* wl_pointer.axis events actually put on the wire (M2245) */
/* WHICH surface pointer focus actually landed on (M2245). The hit-test falls
 * back to the toplevel when it finds nothing, and a fallback that fires every
 * time is indistinguishable from the bug it was meant to fix. */
unsigned g_ptr_enter_sid, g_ptr_enters; int g_ptr_enter_root;
unsigned g_ptr_enter_by[WL_MAXCLIENT];   /* ...and which surface EACH client was told (M2246) */
int g_ptr_focus_root;   /* -append ffptroot: give pointer focus to the TOPLEVEL, not the subsurface (M2248) */
unsigned wl_keys_sent(void)    { return g_keys_sent; }
unsigned wl_pointer_sent(void) { return g_ptr_sent; }

static uint32_t wl_now_ms(void) { return (uint32_t)timer_ms(); }

/* wl_fixed_t: signed 24.8 fixed point. Surface coordinates use it, and passing
 * a plain integer puts the pointer at 1/256th of where it should be. */
static uint32_t wl_fixed(int v) { return (uint32_t)(v * 256); }

/* THE DEEPEST MAPPED SURFACE UNDER A POINT (M2245).
 *
 * wl_pointer.enter names THE SURFACE THE POINTER IS OVER. This compositor
 * always named c->surface -- the xdg_toplevel's surface -- which is correct
 * only for a client that draws directly into its toplevel. GTK does not:
 * Firefox's toplevel carries no buffer and every pixel the user sees is in a
 * SUBSURFACE (2947 subsurface events in one boot). A toolkit told the pointer
 * entered a surface that is not the one under the cursor maps the event to no
 * widget, which is exactly what "clicking does nothing" looks like from
 * outside while every event is demonstrably on the wire.
 *
 * Same generation walk as wl_layers_of, for the same reason it uses one: the
 * parent links come from the client and a client can make a cycle. Deeper
 * hits win, which is what "topmost" means for a subsurface tree. */
/* WHAT THE TREE ACTUALLY LOOKS LIKE (M2246). The hit-test fell back to the
 * toplevel every time while Firefox was committing 1280x960 frames into
 * "surface 18, subsurface" -- so either that surface is not reachable from
 * c->surface by parent links, or it is not shaped the way the walk assumes.
 * Guessing has cost two rounds; print the tree once. */
static void wl_dump_tree(struct wl_client *c) {
    /* PER CLIENT, not once globally (M2246). A single static latch dumped the
     * first client to take pointer focus -- which is lxwl, the 64x32 test
     * client -- and never the browser, so the one tree that mattered was the
     * one it could not print. */
    static unsigned char dumped[WL_MAXCLIENT];
    int ci = (int)(c - g_cl);
    if (ci < 0 || ci >= WL_MAXCLIENT || dumped[ci]) return;
    dumped[ci] = 1;
    kprintf("[wl] surface tree of the client with the toplevel (root=%u):\n", c->surface);
    for (int j = 0; j < c->nobj; j++) {
        struct wl_object *o = &c->obj[j];
        if (!o->id || o->kind != WLK_SURFACE) continue;
        kprintf("[wl]   surface %u parent %u at %d,%d size %ux%u %s role %d\n",
                o->id, o->parent, o->sub_x, o->sub_y, o->width, o->height,
                o->base ? "MAPPED" : "unmapped", (int)o->role);
    }
}

static uint32_t wl_surface_at(struct wl_client *c, int x, int y, int *ox, int *oy) {
    struct wl_object *root = 0;
    for (int j = 0; j < c->nobj; j++)
        if (c->obj[j].id == c->surface) { root = &c->obj[j]; break; }
    if (!root) return 0;
    uint32_t best = 0; int bx = 0, by = 0;
    if (root->base && root->width && root->height &&
        x >= 0 && y >= 0 && x < (int)root->width && y < (int)root->height) {
        best = root->id; bx = 0; by = 0;
    }
    struct { uint32_t id; int x, y; } gen[16], next[16];
    int ngen = 1; gen[0].id = root->id; gen[0].x = 0; gen[0].y = 0;
    for (int depth = 0; depth < 4 && ngen; depth++) {
        int nnext = 0;
        for (int j = 0; j < c->nobj; j++) {
            struct wl_object *o = &c->obj[j];
            if (!o->id || o->kind != WLK_SURFACE || !o->parent) continue;
            int px = 0, py = 0, isChild = 0;
            for (int g = 0; g < ngen; g++)
                if (o->parent == gen[g].id) { isChild = 1; px = gen[g].x; py = gen[g].y; break; }
            if (!isChild) continue;
            int ax = px + o->sub_x, ay = py + o->sub_y;
            if (nnext < 16) { next[nnext].id = o->id; next[nnext].x = ax; next[nnext].y = ay; nnext++; }
            if (!o->base || !o->width || !o->height) continue;      /* unmapped: not hittable */
            if (x >= ax && y >= ay && x < ax + (int)o->width && y < ay + (int)o->height) {
                /* ...unless the client said this surface takes no input there
                 * (M2249). An empty input region is a client telling the
                 * compositor "my pixels are here but my clicks are not". */
                if (o->in_rgn_set && !o->in_any) continue;
                if (o->in_rgn_set && o->in_any &&
                    (x - ax < o->in_x || y - ay < o->in_y ||
                     x - ax >= o->in_x + o->in_w || y - ay >= o->in_y + o->in_h)) continue;
                best = o->id; bx = ax; by = ay;                     /* deeper wins */
            }
        }
        for (int k = 0; k < nnext; k++) gen[k] = next[k];
        ngen = nnext;
    }
    if (ox) *ox = bx;
    if (oy) *oy = by;
    return best;
}

/* INPUT GOES TO ONE CLIENT, NOT ALL OF THEM (M2251).
 *
 * wl_post_* looped over every client with a pointer or keyboard and sent each
 * of them enter + the event. With a single-client app that is invisible. With
 * Firefox it means FOUR connections are simultaneously told they hold pointer
 * and keyboard focus -- the parent, and three helper processes that are
 * showing nothing. zenity, one client, acts on a click; Firefox, four, acts on
 * none, and this is the only structural difference between them on our side.
 *
 * A Wayland seat has exactly one focused surface at a time. Pick the client
 * whose mapped toplevel is biggest -- the same rule wl_frame_tick already uses
 * to grant keyboard focus and the window manager uses to decide which window
 * is the real one -- and send to that one alone. */
/* THE WINDOW MANAGER DECIDES FOCUS, NOT THE COMPOSITOR'S GUESS (M2275).
 *
 * desktop.c hit-tests the topmost VISIBLE window, computes the pointer
 * position relative to THAT window, and calls wl_post_motion/button. The
 * compositor then delivered those coordinates to whichever client had the
 * biggest surface -- a completely independent rule. When the two disagree,
 * coordinates measured against window A are handed to client B, and the
 * client that the user is actually pointing at gets nothing.
 *
 * Two rules for one question is one rule too many. The window manager is the
 * authority -- it owns stacking, visibility and hit-testing -- so it says
 * which client it means, and the area heuristic survives only as the
 * fallback for input that arrives before any window has been focused. */
static int g_focus_ci = -1;
void wl_set_focus_client(int ci) { g_focus_ci = ci; }

static int wl_focus_client(void) {
    if (g_focus_ci >= 0 && g_focus_ci < WL_MAXCLIENT && g_cl[g_focus_ci].used)
        return g_focus_ci;
    int best = -1; uint64_t barea = 0;
    for (int i = 0; i < WL_MAXCLIENT; i++) {
        if (!g_cl[i].used) continue;
        uint32_t w = 0, h = 0; wl_client_extent(i, &w, &h);
        if ((uint64_t)w * h > barea) { barea = (uint64_t)w * h; best = i; }
    }
    return barea ? best : -1;
}

/* ONE EVENT, EVERY RESOURCE (M2298). wl_pointer.frame is version 5, and two
 * binds of the same seat can sit at different versions, so the gate is per
 * resource and not per connection. `frame` closes a logical event group, so
 * it is sent after whatever the caller just sent -- not as an event of its
 * own. */
static void wl_ptr_bcast(struct wl_client *c, uint16_t opcode,
                         const uint8_t *body, int n) {
    for (int i = 0; i < c->nptr; i++) {
        wl_send(c, c->ptrs[i], opcode, body, n);
        if (c->ptrv[i] >= 5) wl_send(c, c->ptrs[i], WL_POINTER_EV_FRAME, 0, 0);
    }
}
/* ONE WHEEL NOTCH, PER RESOURCE (M2301).
 *
 * A wheel click is not one event, it is a group: axis_source says it came
 * from a wheel, axis_discrete says how many notches, axis carries the value,
 * axis_stop ends the gesture, and frame closes the group. All but `axis` are
 * version 5, so this cannot be composed out of wl_ptr_bcast calls -- that
 * would either frame after every part (splitting one notch into four
 * gestures) or drop the axis entirely for a version 4 resource. A per
 * resource loop is the only shape that is correct for both. */
static void wl_ptr_wheel(struct wl_client *c, int ticks_down, uint32_t t) {
    uint8_t sb[4], db[8], ab[12], tb[8];
    wr32(sb, WL_AXIS_SOURCE_WHEEL);
    wr32(db, WL_AXIS_VERTICAL);      wr32(db + 4, (uint32_t)(int32_t)ticks_down);
    wr32(ab, t); wr32(ab + 4, WL_AXIS_VERTICAL);
    wr32(ab + 8, (uint32_t)(int32_t)(ticks_down * 2560));   /* 10.0 per notch, 24.8 fixed */
    wr32(tb, t); wr32(tb + 4, WL_AXIS_VERTICAL);
    for (int i = 0; i < c->nptr; i++) {
        if (c->ptrv[i] >= 5) {
            wl_send(c, c->ptrs[i], WL_POINTER_EV_AXIS_SOURCE,   sb, 4);
            wl_send(c, c->ptrs[i], WL_POINTER_EV_AXIS_DISCRETE, db, 8);
        }
        wl_send(c, c->ptrs[i], WL_POINTER_EV_AXIS, ab, 12);
        if (c->ptrv[i] >= 5) {
            wl_send(c, c->ptrs[i], WL_POINTER_EV_AXIS_STOP, tb, 8);
            wl_send(c, c->ptrs[i], WL_POINTER_EV_FRAME, 0, 0);
        }
    }
}
static void wl_kbd_bcast(struct wl_client *c, uint16_t opcode,
                         const uint8_t *body, int n) {
    for (int i = 0; i < c->nkbd; i++) wl_send(c, c->kbds[i], opcode, body, n);
}

static void wl_ptr_enter(struct wl_client *c, int x, int y) {
    if (!c->surface || !c->nptr) return;
    int ox = 0, oy = 0;
    if (c->surface) wl_dump_tree(c);
    uint32_t want = wl_surface_at(c, x, y, &ox, &oy);
    /* WHICH SURFACE SHOULD OWN POINTER FOCUS -- BOTH ARMS, TESTABLE (M2248).
     *
     * M2245 changed this from the toplevel to the deepest mapped subsurface,
     * which is what the protocol says. But GTK normally declares an EMPTY
     * INPUT REGION on the subsurfaces it renders into (wl_surface.
     * set_input_region, which this compositor ignores), and a surface with an
     * empty input region must NOT receive pointer events -- they belong to
     * the parent. If Firefox does that, "deepest wins" is exactly wrong here.
     *
     * The toplevel arm was last tried when the window manager ran at 0.15 Hz,
     * a black console covered the page and there was no axis event, so it was
     * never a fair test of anything. `-append ffptroot` runs it under today's
     * conditions instead of arguing about it. */
    if (g_ptr_focus_root) { want = 0; }
    if (!want) {
        /* DO NOT ENTER AN UNMAPPED SURFACE (M2246).
         *
         * The fallback handed the client its toplevel id whatever state that
         * surface was in, and the per-client instrument shows two of Firefox's
         * helper processes being told `enter` on surface 12 -- which the tree
         * dump reports as `size 0x0 unmapped`. wl_pointer.enter names the
         * surface the pointer is OVER, and a surface with no buffer is not
         * under anything; libwayland is entitled to treat that as a protocol
         * error and drop the connection, which would take the client's input
         * with it and look exactly like a client that ignores the mouse.
         *
         * If there is nothing mapped under the cursor, say nothing. */
        struct wl_object *root = 0;
        for (int j = 0; j < c->nobj; j++)
            if (c->obj[j].id == c->surface) { root = &c->obj[j]; break; }
        if (!root || !root->base || !root->width || !root->height) return;
        want = c->surface; ox = oy = 0;
    }
    if (c->ptr_in && c->ptr_surface == want) return;
    if (c->ptr_in) {                                   /* crossed into another surface: leave first */
        uint8_t lv[8]; int q = 0;
        wr32(lv + q, ++c->serial);   q += 4;
        wr32(lv + q, c->ptr_surface); q += 4;
        wl_ptr_bcast(c, WL_POINTER_EV_LEAVE, lv, q);
    }
    uint8_t b[16]; int p = 0;
    wr32(b + p, ++c->serial); p += 4;
    wr32(b + p, want);        p += 4;
    wr32(b + p, wl_fixed(x - ox)); p += 4;
    wr32(b + p, wl_fixed(y - oy)); p += 4;
    wl_ptr_bcast(c, WL_POINTER_EV_ENTER, b, p);
    c->ptr_in = 1; c->ptr_surface = want; c->ptr_ox = ox; c->ptr_oy = oy;
    /* PER CLIENT (M2246). A single global last-value has four writers here --
     * the broadcast loop visits every client -- so it always showed whichever
     * one happened to be last, which is a content process whose surfaces are
     * all unmapped. It read "hit-test found nothing" while the browser's
     * hit-test was very likely succeeding. Same rule as M2221: a global is
     * only a measurement if the caller is its only writer. */
    {   int ci = (int)(c - g_cl);
        if (ci >= 0 && ci < WL_MAXCLIENT) g_ptr_enter_by[ci] = want; }
    g_ptr_enter_sid = want; g_ptr_enter_root = (want == c->surface);
    g_ptr_enters++;
}

static void wl_kbd_enter(struct wl_client *c) {
    if (c->kbd_in || !c->surface || !c->nkbd) return;
    uint8_t b[16]; int p = 0;
    wr32(b + p, ++c->serial); p += 4;
    wr32(b + p, c->surface);  p += 4;
    wr32(b + p, 0);           p += 4;          /* keys: an empty array (none held) */
    wl_kbd_bcast(c, WL_KEYBOARD_EV_ENTER, b, p);
    /* modifiers must follow enter: a client that never gets one keeps whatever
     * modifier state it had from a previous focus. All clear, group 0.
     *
     * FIVE words -- serial, depressed, latched, locked, GROUP. Sending four
     * is not a missing field, it is a malformed message: libwayland measures
     * the body against the signature, fails the whole connection with EINVAL,
     * and the client stops receiving everything, not just modifiers. */
    uint8_t m[20]; p = 0;
    wr32(m + p, ++c->serial); p += 4;
    wr32(m + p, 0); p += 4;                    /* mods_depressed */
    wr32(m + p, 0); p += 4;                    /* mods_latched */
    wr32(m + p, 0); p += 4;                    /* mods_locked */
    wr32(m + p, 0); p += 4;                    /* group */
    wl_kbd_bcast(c, WL_KEYBOARD_EV_MODIFIERS, m, p);
    c->kbd_in = 1;
}

/* The cursor left the surface. Without this a client believes the pointer is
 * still inside it forever -- it keeps a hover highlight up, and it never sees
 * the enter() that should follow the cursor coming back. */
void wl_post_pointer_leave(void) {
    for (int i = 0; i < WL_MAXCLIENT; i++) {
        struct wl_client *c = &g_cl[i];
        if (!c->used || !c->nptr || !c->ptr_in) continue;
        /* LEAVE THE SURFACE WE ENTERED, not the root (M2292). Since M2245
         * enter() names the subsurface under the cursor, which for Firefox is
         * not `surface` at all -- so this told the client the pointer had left
         * a surface it was never on, and left the real one entered forever. */
        uint8_t b[8]; int p = 0;
        wr32(b + p, ++c->serial);  p += 4;
        wr32(b + p, c->ptr_surface ? c->ptr_surface : c->surface); p += 4;
        wl_ptr_bcast(c, WL_POINTER_EV_LEAVE, b, p);
        c->ptr_in = 0; c->ptr_surface = 0;
    }
}

void wl_post_motion(int x, int y) {
    int focus = wl_focus_client();
    if (focus < 0) return;
    for (int i = 0; i < WL_MAXCLIENT; i++) {
        struct wl_client *c = &g_cl[i];
        if (i != focus || !c->used || !c->nptr) continue;
        wl_ptr_enter(c, x, y);
        /* RELATIVE TO THE SURFACE THAT WAS ENTERED, not to the window (M2245).
         * enter() now names the subsurface under the cursor, so motion has to
         * be expressed in that surface's coordinates or the toolkit places the
         * pointer at an offset from where it really is. */
        uint8_t b[12]; int p = 0;
        wr32(b + p, wl_now_ms()); p += 4;
        wr32(b + p, wl_fixed(x - c->ptr_ox)); p += 4;
        wr32(b + p, wl_fixed(y - c->ptr_oy)); p += 4;
        wl_ptr_bcast(c, WL_POINTER_EV_MOTION, b, p);
        g_ptr_sent++;
    }
}

void wl_post_button(int x, int y, unsigned button, int pressed) {
    int focus = wl_focus_client();
    if (focus < 0) return;
    for (int i = 0; i < WL_MAXCLIENT; i++) {
        struct wl_client *c = &g_cl[i];
        if (i != focus || !c->used || !c->nptr) continue;
        wl_ptr_enter(c, x, y);
        uint8_t b[16]; int p = 0;
        wr32(b + p, ++c->serial);  p += 4;
        wr32(b + p, wl_now_ms());  p += 4;
        wr32(b + p, button);       p += 4;     /* evdev: BTN_LEFT is 0x110 */
        wr32(b + p, pressed ? 1u : 0u); p += 4;
        wl_ptr_bcast(c, WL_POINTER_EV_BUTTON, b, p);
        g_ptr_sent++;
    }
}

/* SCROLLING (M2245).
 *
 * The desktop's wheel handler routed a tick to KIND_BROWSER and to KIND_APP,
 * and had no case for KIND_WAYLAND at all -- so a Wayland client, which is to
 * say Firefox, was never told the wheel had moved. There was no wl_post_axis
 * in the tree to tell it with. "i cant click or scroll or anything": the
 * scroll half of that was not a bug in delivery, it was a feature that did
 * not exist.
 *
 * wl_pointer.axis carries (time, axis, value) with value in 24.8 FIXED point,
 * and axis 0 is the vertical scroll. Toolkits treat ~10.0 as one notch, so a
 * tick is 10 << 8 = 2560, POSITIVE meaning the surface content moves up (the
 * user scrolls down) -- the opposite sign to this desktop's `up` flag, which
 * is the kind of inversion that is invisible until someone scrolls the wrong
 * way. */
void wl_post_axis(int x, int y, int ticks_down) {
    int focus = wl_focus_client();
    if (focus < 0) return;
    if (!ticks_down) return;
    for (int i = 0; i < WL_MAXCLIENT; i++) {
        struct wl_client *c = &g_cl[i];
        if (i != focus || !c->used || !c->nptr) continue;
        wl_ptr_enter(c, x, y);
        wl_ptr_wheel(c, ticks_down, wl_now_ms());
        g_ptr_sent++;
        g_axis_sent++;
    }
}

void wl_post_key(unsigned keycode, int pressed) {
    int focus = wl_focus_client();
    if (focus < 0) return;
    for (int i = 0; i < WL_MAXCLIENT; i++) {
        struct wl_client *c = &g_cl[i];
        if (i != focus || !c->used || !c->nkbd) continue;
        wl_kbd_enter(c);
        uint8_t b[16]; int p = 0;
        wr32(b + p, ++c->serial); p += 4;
        wr32(b + p, wl_now_ms()); p += 4;
        wr32(b + p, keycode);     p += 4;      /* evdev keycode, NOT a character */
        wr32(b + p, pressed ? 1u : 0u); p += 4;
        wl_kbd_bcast(c, WL_KEYBOARD_EV_KEY, b, p);
        g_keys_sent++;
    }
}

int wl_compositor_poll(void) {
    if (g_listener < 0) return 0;
    int worked = 0;

    while (unix_pending(g_listener)) {               /* accept every waiting client */
        int ep = unix_accept_nb(g_listener);
        if (ep < 0) break;
        int slot = -1;
        for (int i = 0; i < WL_MAXCLIENT; i++) if (!g_cl[i].used) { slot = i; break; }
        if (slot < 0) { unix_close(ep); kprintf("[wl] client table full\n"); break; }
        struct wl_client *c = &g_cl[slot];
        c->used = 1; c->ep = ep; c->inlen = 0; c->outlen = 0; c->registry = 0; c->nobj = 0;
        c->serial = 0; c->title[0] = 0;
        c->pointer = c->keyboard = c->surface = 0;
        c->nptr = c->nkbd = 0;
        c->ptr_in = c->kbd_in = 0;
        c->seat_version = 0;
        for (unsigned t = 0; t < sizeof c->tl_title / sizeof c->tl_title[0]; t++)
            { c->tl_title[t].tl = 0; c->tl_title[t].s[0] = 0; }
        g_nconn++;
        kprintf("[wl] client connected (ep %d)\n", ep);
        worked++;
    }

    for (int i = 0; i < WL_MAXCLIENT; i++) {
        struct wl_client *c = &g_cl[i];
        if (!c->used) continue;
        /* FLUSH FIRST, every pass. A client that was behind last time has had a
         * scheduling quantum to drain its ring, and anything we still hold is
         * the head of its stream -- it cannot make progress until it arrives.
         * (M2000) */
        if (c->outlen) { wl_flush(c); worked++; }
        if (!unix_readable(c->ep)) continue;
        /* NEVER ASK FOR ZERO BYTES. unix_recv returns what it read, and a
         * zero-length request reads zero -- which this loop treats as EOF and
         * uses to drop a perfectly healthy client. Reachable whenever the
         * input buffer is full of a partial message, i.e. exactly when a
         * client is busiest. (M2002) */
        int room = WL_INBUF - c->inlen;
        if (room <= 0) {
            kprintf("[wl] input buffer full (%d bytes) with no complete message: dropping client\n", c->inlen);
            wl_client_release(c);
            continue;
        }
        long n = unix_recv(c->ep, c->in + c->inlen, (unsigned long)room);
        if (n <= 0) {                                /* EOF or error: drop the client */
            /* WHICH of the two, and with how much still queued for it. "client
             * disconnected" was true of both a client that hung up and a
             * receive that errored, and those need different fixes. (M2002) */
            kprintf("[wl] client disconnected (ep %d, recv -> %ld, %d byte(s) still queued to send)\n",
                    c->ep, n, c->outlen);
            wl_client_release(c);
            continue;
        }
        c->inlen += (int)n;
        worked++;
        /* Drain every COMPLETE message; leave a partial one for the next pass. */
        int off = 0;
        while (c->inlen - off >= 8) {
            uint32_t sz_op = rd32(c->in + off + 4);
            int msz = (int)(sz_op >> 16);
            if (msz < 8 || msz > WL_INBUF) { off = c->inlen; break; }   /* desynced: drop the buffer */
            if (c->inlen - off < msz) break;         /* incomplete: wait for more */
            wl_dispatch(c, c->in + off, msz);
            off += msz;
        }
        if (off > 0) {                               /* shuffle the remainder down */
            int rem = c->inlen - off;
            for (int k = 0; k < rem; k++) c->in[k] = c->in[off + k];
            c->inlen = rem;
        }
    }
    return worked;
}
