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
#include "xkbmap.h" /* our own XKB keymap, handed over as a memfd (M1984) */

/* The path clients connect to. It carries the compat root because a Linux
 * program's socket path goes through the ABI layer's translation, and both
 * sides have to name the same object -- the client asks for
 * $XDG_RUNTIME_DIR/wayland-0 with XDG_RUNTIME_DIR=/run. */
#define WL_SOCK_PATH "/disk2/run/wayland-0"

#define WL_MAXCLIENT 8
#define WL_INBUF     16384

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
/* wl_shm requests/events */
#define WL_SHM_CREATE_POOL       0
#define WL_SHM_EV_FORMAT         0
/* wl_shm_pool requests */
#define WL_SHM_POOL_CREATE_BUFFER 0
/* wl_surface requests */
#define WL_SURFACE_DESTROY       0
#define WL_SURFACE_ATTACH        1
#define WL_SURFACE_DAMAGE        2
#define WL_SURFACE_FRAME         3
#define WL_SURFACE_COMMIT        6
/* wl_buffer events */
#define WL_BUFFER_EV_RELEASE     0
/* xdg_wm_base / xdg_surface / xdg_toplevel -- the shell protocol GTK and
 * Firefox use to get a real, titled, sized window. */
#define XDG_WM_BASE_GET_XDG_SURFACE 2
#define XDG_WM_BASE_PONG            3
#define XDG_SURFACE_GET_TOPLEVEL    1
#define XDG_SURFACE_ACK_CONFIGURE   4
#define XDG_SURFACE_EV_CONFIGURE    0
#define XDG_TOPLEVEL_SET_TITLE      2
#define XDG_TOPLEVEL_EV_CONFIGURE   0
/* wl_seat / wl_pointer / wl_keyboard -- input, back out to the client. */
#define WL_SEAT_GET_POINTER      0
#define WL_SEAT_GET_KEYBOARD     1
#define WL_SEAT_EV_CAPABILITIES  0
#define WL_SEAT_EV_NAME          1
#define WL_SEAT_CAP_POINTER      1
#define WL_SEAT_CAP_KEYBOARD     2
#define WL_POINTER_EV_ENTER      0
#define WL_POINTER_EV_LEAVE      1
#define WL_POINTER_EV_MOTION     2
#define WL_POINTER_EV_BUTTON     3
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
#define WL_SUBCOMP_GET_SUBSURFACE 1

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
               WLK_SUBCOMPOSITOR, WLK_SUBSURFACE };

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
    { "wl_output",               3, WLK_OUTPUT },
    { "wl_seat",                 7, WLK_SEAT },
    { "xdg_wm_base",             3, WLK_XDG_WM_BASE },
};
#define WL_NGLOBAL (int)(sizeof(g_globals) / sizeof(g_globals[0]))

/* A demo client makes a dozen objects; GTK makes hundreds before it draws
 * anything, and running out mid-handshake presents as a client that stops
 * talking. (M1986) */
#define WL_MAXOBJ 512
struct wl_object {
    uint32_t id;
    int      kind;
    /* wl_shm_pool: the client's shared memory, taken from the passed memfd.
     * wl_buffer: geometry into its pool. wl_surface: the attached buffer. */
    uint8_t *base; unsigned long size;
    uint32_t off, width, height, stride, format;
    uint32_t attached;             /* wl_surface: the wl_buffer id last attached */
    uint32_t link;                 /* xdg_surface -> its wl_surface; xdg_toplevel -> its xdg_surface */
};

struct wl_client {
    int      used;
    int      ep;                   /* AF_UNIX endpoint (unixsock.c) */
    uint8_t  in[WL_INBUF];
    int      inlen;                /* bytes accumulated but not yet consumed */
    uint32_t registry;             /* the client's wl_registry object id, 0 = none yet */
    uint32_t serial;               /* configure serials, monotonic per client */
    uint32_t pointer, keyboard;    /* the client's wl_pointer / wl_keyboard, 0 = not asked for */
    uint32_t surface;              /* the surface input is delivered to */
    int      ptr_in, kbd_in;       /* enter() already sent. Pointer focus follows the CURSOR and
                                    * keyboard focus follows the WINDOW -- they are separate in
                                    * Wayland, and a client ignores input for a surface it has
                                    * not been told it has. */
    char     title[64];            /* xdg_toplevel.set_title, for the window's titlebar */
    struct wl_object obj[WL_MAXOBJ]; int nobj;
};
static struct wl_client g_cl[WL_MAXCLIENT];
static int g_listener = -1;
int g_wl_verbose;                 /* -append wlverbose: log every message both ways */
static unsigned g_nconn, g_nmsg, g_nglobal, g_ncommit;
static uint32_t g_last_pixel;     /* the top-left pixel of the last committed surface */
static uint32_t g_last_w, g_last_h;

/* The most recently committed surface, for the desktop to draw. Returns NULL
 * until a client has actually committed one. The pointer is into the CLIENT'S
 * shared memory, so what the desktop blits is what the client wrote -- there is
 * no intermediate copy anywhere in the path. (M1980) */
static uint8_t *g_last_base; static uint32_t g_last_stride;
const uint32_t *wl_surface_pixels(uint32_t *w, uint32_t *h, uint32_t *stride) {
    if (!g_last_base || !g_last_w || !g_last_h) return 0;
    if (w) *w = g_last_w;
    if (h) *h = g_last_h;
    if (stride) *stride = g_last_stride;
    return (const uint32_t *)g_last_base;
}

/* The last committed surface's window title, or "" if the client never set
 * one (a client that uses wl_surface without xdg_shell has no title to give). */
static const char *g_last_title = "";
const char *wl_surface_title(void) { return g_last_title; }

unsigned wl_commits(void)      { return g_ncommit; }
uint32_t wl_last_pixel(void)   { return g_last_pixel; }
uint32_t wl_last_width(void)   { return g_last_w; }
uint32_t wl_last_height(void)  { return g_last_h; }

static struct wl_object *obj_find(struct wl_client *c, uint32_t id) {
    for (int i = 0; i < c->nobj; i++) if (c->obj[i].id == id) return &c->obj[i];
    return 0;
}
static struct wl_object *obj_add(struct wl_client *c, uint32_t id, int kind) {
    if (c->nobj >= WL_MAXOBJ) { kprintf("[wl] object table full\n"); return 0; }
    struct wl_object *o = &c->obj[c->nobj++];
    o->id = id; o->kind = kind;
    o->base = 0; o->size = 0;
    o->off = o->width = o->height = o->stride = o->format = 0;
    o->attached = 0;
    return o;
}

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
static void wl_send(struct wl_client *c, uint32_t obj, uint16_t opcode,
                    const uint8_t *body, int blen) {
    uint8_t msg[512];
    int total = 8 + blen;
    if (total > (int)sizeof msg) return;            /* refuse rather than truncate a message */
    wr32(msg + 0, obj);
    wr32(msg + 4, ((uint32_t)total << 16) | opcode);
    for (int i = 0; i < blen; i++) msg[8 + i] = body[i];
    long w = unix_send(c->ep, msg, (unsigned long)total);
    /* A SHORT send is not a warning here, it is a desynced protocol stream:
     * the client will read a partial header and every message after it is
     * garbage. Say so rather than let it look like a hang. */
    if (w != total)
        kprintf("[wl] send obj=%u op=%u size=%d -> %ld (SHORT)\n", obj, opcode, total, w);
    else if (g_wl_verbose)
        kprintf("[wl] -> obj=%u op=%u size=%d\n", obj, opcode, total);
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

/* Handle one complete message. Returns 0 always (an unknown object or opcode is
 * ignored rather than fatal: a client may create objects we do not model yet,
 * and killing the connection would turn a missing feature into a hang). */
static void wl_dispatch(struct wl_client *c, const uint8_t *m, int len) {
    uint32_t obj = rd32(m + 0);
    uint32_t sz_op = rd32(m + 4);
    uint16_t opcode = (uint16_t)(sz_op & 0xFFFF);
    if (g_wl_verbose) kprintf("[wl] <- obj=%u op=%u size=%d\n", obj, opcode, len);
    const uint8_t *args = m + 8;
    int alen = len - 8;
    g_nmsg++;

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
        p += 4;                                      /* version */
        if (p + 4 > alen) return;
        uint32_t nid = rd32(args + p);
        int kind = WLK_NONE;
        if (name >= 1 && name <= (uint32_t)WL_NGLOBAL) kind = g_globals[name - 1].kind;
        obj_add(c, nid, kind);
        /* WHAT A CLIENT ACTUALLY BINDS is the single most useful thing this
         * server can say. A toolkit that binds four of seven globals and then
         * stops has told you exactly which one it could not live without, and
         * from outside it looks identical to a client that hung. (M1986) */
        kprintf("[wl] bind %s -> id %u\n",
                (name >= 1 && name <= (uint32_t)WL_NGLOBAL) ? g_globals[name - 1].iface : "?", nid);
        if (kind == WLK_OUTPUT) {
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
            uint8_t nb2[64]; int np2 = put_string(nb2, 0, "OSDEV-1");
            wl_send(c, nid, WL_OUTPUT_EV_NAME, nb2, np2);
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
            uint8_t nb[64]; int np = put_string(nb, 0, "osdev-seat0");
            wl_send(c, nid, WL_SEAT_EV_NAME, nb, np);
        }
        if (kind == WLK_SHM) {
            uint8_t b[4];
            wr32(b, WL_SHM_FORMAT_ARGB8888); wl_send(c, nid, WL_SHM_EV_FORMAT, b, 4);
            wr32(b, WL_SHM_FORMAT_XRGB8888); wl_send(c, nid, WL_SHM_EV_FORMAT, b, 4);
        }
        return;
    }

    struct wl_object *o = obj_find(c, obj);
    if (!o) return;                                  /* an object we do not model: ignore, never fatal */

    if (o->kind == WLK_COMPOSITOR && opcode == WL_COMPOSITOR_CREATE_SURFACE && alen >= 4) {
        uint32_t sid = rd32(args);
        obj_add(c, sid, WLK_SURFACE);
        if (!c->surface) c->surface = sid;      /* input goes to the first surface */
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
        void *base = 0; unsigned long msz = 0;
        if (app_scm_take_memfd(c->ep, &base, &msz) == 0) {
            po->base = (uint8_t *)base;
            po->size = msz < size ? msz : size;
            kprintf("[wl] shm pool %u: %lu bytes of the client's own memory\n", nid, po->size);
        } else {
            kprintf("[wl] shm pool %u: NO descriptor arrived (SCM_RIGHTS missing)\n", nid);
        }
        return;
    }
    if (o->kind == WLK_SHM_POOL && opcode == WL_SHM_POOL_CREATE_BUFFER && alen >= 24) {
        /* create_buffer(new_id, offset, width, height, stride, format) */
        struct wl_object *bo = obj_add(c, rd32(args + 0), WLK_BUFFER);
        if (!bo) return;
        bo->base   = o->base; bo->size = o->size;
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
        struct wl_object *ss = obj_add(c, rd32(args + 0), WLK_SUBSURFACE);
        if (ss) ss->link = rd32(args + 4);            /* the wl_surface it wraps */
        return;
    }
    if (o->kind == WLK_SEAT && opcode == WL_SEAT_GET_POINTER && alen >= 4) {
        c->pointer = rd32(args); obj_add(c, c->pointer, WLK_POINTER);
        kprintf("[wl] client asked the seat for a POINTER (id %u)\n", c->pointer);
        return;
    }
    if (o->kind == WLK_SEAT && opcode == WL_SEAT_GET_KEYBOARD && alen >= 4) {
        c->keyboard = rd32(args); obj_add(c, c->keyboard, WLK_KEYBOARD);
        kprintf("[wl] client asked the seat for a KEYBOARD (id %u)\n", c->keyboard);
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
        wl_send(c, c->keyboard, WL_KEYBOARD_EV_REPEAT, ri, 8);
        return;
    }
    if (o->kind == WLK_XDG_WM_BASE && opcode == XDG_WM_BASE_GET_XDG_SURFACE && alen >= 8) {
        struct wl_object *xs = obj_add(c, rd32(args + 0), WLK_XDG_SURFACE);
        if (xs) xs->link = rd32(args + 4);              /* the wl_surface it wraps */
        return;
    }
    if (o->kind == WLK_XDG_SURFACE && opcode == XDG_SURFACE_GET_TOPLEVEL && alen >= 4) {
        uint32_t tid = rd32(args + 0);
        struct wl_object *tl = obj_add(c, tid, WLK_XDG_TOPLEVEL);
        if (tl) tl->link = o->id;
        /* A toplevel is not mapped until the client has acknowledged a
         * configure, so the compositor has to send one UNPROMPTED -- a client
         * that never gets configure never attaches a buffer, and waits
         * forever having done nothing wrong. 0x0 means "you choose your own
         * size", which is what a client wants for its first frame. */
        uint8_t b[16]; int p = 0;
        wr32(b + p, 0); p += 4;                          /* width  */
        wr32(b + p, 0); p += 4;                          /* height */
        wr32(b + p, 0); p += 4;                          /* states: an empty array */
        wl_send(c, tid, XDG_TOPLEVEL_EV_CONFIGURE, b, p);
        uint8_t sb[4]; wr32(sb, ++c->serial);
        wl_send(c, o->id, XDG_SURFACE_EV_CONFIGURE, sb, 4);
        return;
    }
    if (o->kind == WLK_XDG_TOPLEVEL && opcode == XDG_TOPLEVEL_SET_TITLE && alen >= 4) {
        uint32_t slen = rd32(args + 0);
        if (slen > 0 && 4 + slen <= (uint32_t)alen) {
            unsigned n = slen - 1;                        /* the length counts the NUL */
            if (n > sizeof c->title - 1) n = sizeof c->title - 1;
            for (unsigned i = 0; i < n; i++) c->title[i] = (char)args[4 + i];
            c->title[n] = 0;
            kprintf("[wl] toplevel title: \"%s\"\n", c->title);
        }
        return;
    }
    if (o->kind == WLK_XDG_SURFACE && opcode == XDG_SURFACE_ACK_CONFIGURE) return;  /* nothing to do yet */

    if (o->kind == WLK_SURFACE && opcode == WL_SURFACE_ATTACH && alen >= 4) {
        o->attached = rd32(args + 0);                /* the wl_buffer id */
        return;
    }
    if (o->kind == WLK_SURFACE && opcode == WL_SURFACE_COMMIT) {
        /* THE POINT OF ALL OF IT: the client's pixels are now ours to read,
         * in the memory it wrote them to. Nothing was copied to get here. */
        struct wl_object *b = o->attached ? obj_find(c, o->attached) : 0;
        if (b && b->base && b->height && b->stride) {
            unsigned long need = (unsigned long)b->off + (unsigned long)b->stride * b->height;
            if (need <= b->size) {
                g_last_pixel = rd32(b->base + b->off);
                g_last_w = b->width; g_last_h = b->height;
                g_last_base = b->base + b->off; g_last_stride = b->stride;
                g_last_title = c->title[0] ? c->title : "Wayland client";
                g_ncommit++;
                kprintf("[wl] commit: %ux%u stride %u format %u -> first pixel 0x%08x\n",
                        b->width, b->height, b->stride, b->format, g_last_pixel);
            } else {
                kprintf("[wl] commit: buffer claims %lu bytes but the pool holds %lu -- refusing\n",
                        need, b->size);
            }
            /* Tell the client it may reuse the buffer. Without this a client
             * that double-buffers waits forever for its first frame back. */
            wl_send(c, b->id, WL_BUFFER_EV_RELEASE, 0, 0);
        }
        return;
    }
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
void wl_server_task(void) {
    for (;;) {
        wl_compositor_poll();
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
unsigned wl_keys_sent(void)    { return g_keys_sent; }
unsigned wl_pointer_sent(void) { return g_ptr_sent; }

static uint32_t wl_now_ms(void) { return (uint32_t)timer_ms(); }

/* wl_fixed_t: signed 24.8 fixed point. Surface coordinates use it, and passing
 * a plain integer puts the pointer at 1/256th of where it should be. */
static uint32_t wl_fixed(int v) { return (uint32_t)(v * 256); }

static void wl_ptr_enter(struct wl_client *c, int x, int y) {
    if (c->ptr_in || !c->surface || !c->pointer) return;
    uint8_t b[16]; int p = 0;
    wr32(b + p, ++c->serial); p += 4;
    wr32(b + p, c->surface);  p += 4;
    wr32(b + p, wl_fixed(x)); p += 4;
    wr32(b + p, wl_fixed(y)); p += 4;
    wl_send(c, c->pointer, WL_POINTER_EV_ENTER, b, p);
    wl_send(c, c->pointer, WL_POINTER_EV_FRAME, 0, 0);
    c->ptr_in = 1;
}

static void wl_kbd_enter(struct wl_client *c) {
    if (c->kbd_in || !c->surface || !c->keyboard) return;
    uint8_t b[16]; int p = 0;
    wr32(b + p, ++c->serial); p += 4;
    wr32(b + p, c->surface);  p += 4;
    wr32(b + p, 0);           p += 4;          /* keys: an empty array (none held) */
    wl_send(c, c->keyboard, WL_KEYBOARD_EV_ENTER, b, p);
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
    wl_send(c, c->keyboard, WL_KEYBOARD_EV_MODIFIERS, m, p);
    c->kbd_in = 1;
}

/* The cursor left the surface. Without this a client believes the pointer is
 * still inside it forever -- it keeps a hover highlight up, and it never sees
 * the enter() that should follow the cursor coming back. */
void wl_post_pointer_leave(void) {
    for (int i = 0; i < WL_MAXCLIENT; i++) {
        struct wl_client *c = &g_cl[i];
        if (!c->used || !c->pointer || !c->ptr_in) continue;
        uint8_t b[8]; int p = 0;
        wr32(b + p, ++c->serial); p += 4;
        wr32(b + p, c->surface);  p += 4;
        wl_send(c, c->pointer, WL_POINTER_EV_LEAVE, b, p);
        wl_send(c, c->pointer, WL_POINTER_EV_FRAME, 0, 0);
        c->ptr_in = 0;
    }
}

void wl_post_motion(int x, int y) {
    for (int i = 0; i < WL_MAXCLIENT; i++) {
        struct wl_client *c = &g_cl[i];
        if (!c->used || !c->pointer) continue;
        wl_ptr_enter(c, x, y);
        uint8_t b[12]; int p = 0;
        wr32(b + p, wl_now_ms()); p += 4;
        wr32(b + p, wl_fixed(x)); p += 4;
        wr32(b + p, wl_fixed(y)); p += 4;
        wl_send(c, c->pointer, WL_POINTER_EV_MOTION, b, p);
        wl_send(c, c->pointer, WL_POINTER_EV_FRAME, 0, 0);
        g_ptr_sent++;
    }
}

void wl_post_button(int x, int y, unsigned button, int pressed) {
    for (int i = 0; i < WL_MAXCLIENT; i++) {
        struct wl_client *c = &g_cl[i];
        if (!c->used || !c->pointer) continue;
        wl_ptr_enter(c, x, y);
        uint8_t b[16]; int p = 0;
        wr32(b + p, ++c->serial);  p += 4;
        wr32(b + p, wl_now_ms());  p += 4;
        wr32(b + p, button);       p += 4;     /* evdev: BTN_LEFT is 0x110 */
        wr32(b + p, pressed ? 1u : 0u); p += 4;
        wl_send(c, c->pointer, WL_POINTER_EV_BUTTON, b, p);
        wl_send(c, c->pointer, WL_POINTER_EV_FRAME, 0, 0);
        g_ptr_sent++;
    }
}

void wl_post_key(unsigned keycode, int pressed) {
    for (int i = 0; i < WL_MAXCLIENT; i++) {
        struct wl_client *c = &g_cl[i];
        if (!c->used || !c->keyboard) continue;
        wl_kbd_enter(c);
        uint8_t b[16]; int p = 0;
        wr32(b + p, ++c->serial); p += 4;
        wr32(b + p, wl_now_ms()); p += 4;
        wr32(b + p, keycode);     p += 4;      /* evdev keycode, NOT a character */
        wr32(b + p, pressed ? 1u : 0u); p += 4;
        wl_send(c, c->keyboard, WL_KEYBOARD_EV_KEY, b, p);
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
        c->used = 1; c->ep = ep; c->inlen = 0; c->registry = 0; c->nobj = 0;
        c->serial = 0; c->title[0] = 0;
        c->pointer = c->keyboard = c->surface = 0;
        c->ptr_in = c->kbd_in = 0;
        g_nconn++;
        kprintf("[wl] client connected (ep %d)\n", ep);
        worked++;
    }

    for (int i = 0; i < WL_MAXCLIENT; i++) {
        struct wl_client *c = &g_cl[i];
        if (!c->used) continue;
        if (!unix_readable(c->ep)) continue;
        long n = unix_recv(c->ep, c->in + c->inlen, (unsigned long)(WL_INBUF - c->inlen));
        if (n <= 0) {                                /* EOF or error: drop the client */
            unix_close(c->ep); c->used = 0;
            kprintf("[wl] client disconnected\n");
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
