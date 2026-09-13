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
#include "string.h"
#include "task.h"
#include "app.h"    /* app_scm_take_memfd: the client's pixels (M1979) */

/* The path clients connect to. It carries the compat root because a Linux
 * program's socket path goes through the ABI layer's translation, and both
 * sides have to name the same object -- the client asks for
 * $XDG_RUNTIME_DIR/wayland-0 with XDG_RUNTIME_DIR=/run. */
#define WL_SOCK_PATH "/disk2/run/wayland-0"

#define WL_MAXCLIENT 8
#define WL_INBUF     4096

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

/* Pixel formats, by the protocol's numbering. These two are the ones every
 * client can produce and the only ones worth claiming until we composite. */
#define WL_SHM_FORMAT_ARGB8888   0
#define WL_SHM_FORMAT_XRGB8888   1

struct wl_global { const char *iface; uint32_t version; };
/* Advertised in this order; `name` is the index + 1. Version numbers are the
 * ones we intend to implement, not the newest that exists -- a client binds at
 * min(its version, ours) and will use features we claim. */
static const struct wl_global g_globals[] = {
    { "wl_compositor", 4 },
    { "wl_shm",        1 },
    { "wl_seat",       7 },
    { "xdg_wm_base",   3 },
};
#define WL_NGLOBAL (int)(sizeof(g_globals) / sizeof(g_globals[0]))

/* Object kinds, so a request can be routed by what its target IS rather than
 * by guessing from the opcode -- opcode 0 means something different on every
 * interface. */
enum wl_kind { WLK_NONE = 0, WLK_COMPOSITOR, WLK_SHM, WLK_SEAT, WLK_XDG_WM_BASE,
               WLK_SURFACE, WLK_SHM_POOL, WLK_BUFFER };

#define WL_MAXOBJ 64
struct wl_object {
    uint32_t id;
    int      kind;
    /* wl_shm_pool: the client's shared memory, taken from the passed memfd.
     * wl_buffer: geometry into its pool. wl_surface: the attached buffer. */
    uint8_t *base; unsigned long size;
    uint32_t off, width, height, stride, format;
    uint32_t attached;             /* wl_surface: the wl_buffer id last attached */
};

struct wl_client {
    int      used;
    int      ep;                   /* AF_UNIX endpoint (unixsock.c) */
    uint8_t  in[WL_INBUF];
    int      inlen;                /* bytes accumulated but not yet consumed */
    uint32_t registry;             /* the client's wl_registry object id, 0 = none yet */
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
        if (name >= 1 && name <= (uint32_t)WL_NGLOBAL) {
            const char *i2 = g_globals[name - 1].iface;
            if      (i2[3] == 'c') kind = WLK_COMPOSITOR;   /* wl_compositor */
            else if (i2[3] == 's' && i2[4] == 'h') kind = WLK_SHM;
            else if (i2[3] == 's' && i2[4] == 'e') kind = WLK_SEAT;
            else kind = WLK_XDG_WM_BASE;
        }
        obj_add(c, nid, kind);
        /* wl_shm MUST advertise its formats on bind. A client asks wl_shm what
         * it supports and will not create a buffer for a format it was never
         * offered, so a silent bind looks to it like a compositor that cannot
         * display anything. */
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
        obj_add(c, rd32(args), WLK_SURFACE);
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
