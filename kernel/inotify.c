/*
 * inotify.c — pollable filesystem-watch fds (M1266). See inotify.h.
 *
 * A fixed table of inotify instances, each with a few path watches and a small
 * event queue. inotify_feed() is called from fsevents_record() (the single VFS
 * mutation chokepoint) on every create/write/delete/rename; it maps the op to a
 * mask bit, matches the event path against each instance's watches, and queues
 * an event on the matches. read() drains the queue; app_fd_ready() reports
 * POLLIN when it's non-empty, so an inotify fd is epoll-able like any other.
 */
#include "inotify.h"

#define INOT_MAX    8       /* concurrent inotify instances    */
#define INOT_WATCH  8       /* watches per instance            */
#define INOT_QUEUE  32      /* queued events per instance      */
#define INOT_NAME   32      /* event name field (fixed)        */

struct watch { int used; int wd; char path[64]; uint32_t mask; };
struct iev   { int wd; uint32_t mask; char name[INOT_NAME]; };
struct inot {
    int used;
    int refs;               /* dup()/fork() aliases of the same fd (M1603) */
    struct watch w[INOT_WATCH];
    int next_wd;
    struct iev q[INOT_QUEUE];
    int qhead, qtail;       /* empty when equal */
};
static struct inot g_inot[INOT_MAX];

/* needle a substring of hay? (the MVP path-match rule) */
static int contains(const char *hay, const char *needle) {
    if (!needle[0]) return 1;
    for (int i = 0; hay[i]; i++) {
        int j = 0; while (needle[j] && hay[i + j] == needle[j]) j++;
        if (!needle[j]) return 1;
    }
    return 0;
}
static const char *basename_of(const char *p) {
    const char *b = p; for (const char *s = p; *s; s++) if (*s == '/') b = s + 1; return b;
}

int inotify_new(void) {
    for (int i = 0; i < INOT_MAX; i++) if (!g_inot[i].used) {
        for (int j = 0; j < INOT_WATCH; j++) g_inot[i].w[j].used = 0;
        g_inot[i].next_wd = 1; g_inot[i].qhead = g_inot[i].qtail = 0;
        g_inot[i].used = 1; g_inot[i].refs = 1;
        return i;
    }
    return -1;
}

int inotify_add(int idx, const char *path, uint32_t mask) {
    if (idx < 0 || idx >= INOT_MAX || !g_inot[idx].used || !path) return -1;
    struct inot *n = &g_inot[idx];
    for (int j = 0; j < INOT_WATCH; j++) if (!n->w[j].used) {
        int k = 0; while (path[k] && k < 63) { n->w[j].path[k] = path[k]; k++; } n->w[j].path[k] = 0;
        n->w[j].mask = mask ? mask : 0xffffffffu;   /* mask 0 = all events */
        n->w[j].wd = n->next_wd++;
        n->w[j].used = 1;
        return n->w[j].wd;
    }
    return -1;
}

void inotify_ref(int idx) { if (idx >= 0 && idx < INOT_MAX && g_inot[idx].used) g_inot[idx].refs++; }
void inotify_free(int idx) {
    if (idx < 0 || idx >= INOT_MAX || !g_inot[idx].used) return;
    if (--g_inot[idx].refs > 0) return;   /* another dup()/fork() alias still holds it (M1603) */
    g_inot[idx].used = 0;
}

/* inotify_rm_watch (M1568): a fixed INOT_WATCH-slot table could previously
 * only be freed a whole instance at a time (inotify_free, on fd close) --
 * any long-lived watcher process leaked watches for good once it stopped
 * caring about a given path but kept the fd open for others. Removal is
 * exactly the mirror of inotify_add: find the slot by wd, clear `used`. */
int inotify_rm(int idx, int wd) {
    if (idx < 0 || idx >= INOT_MAX || !g_inot[idx].used) return -1;
    struct inot *n = &g_inot[idx];
    for (int j = 0; j < INOT_WATCH; j++)
        if (n->w[j].used && n->w[j].wd == wd) { n->w[j].used = 0; return 0; }
    return -1;
}

int inotify_ready(int idx) {
    if (idx < 0 || idx >= INOT_MAX || !g_inot[idx].used) return 0;
    return g_inot[idx].qhead != g_inot[idx].qtail;
}

static uint32_t op_mask(char op) {
    switch (op) {
        case 'w': return IN_MODIFY;     /* write / create-by-write */
        case 'd': return IN_DELETE;
        case 'm': return IN_CREATE;     /* mkdir */
        case 'r': return IN_MOVED_TO;   /* rename */
        case 'l': return IN_CREATE;     /* symlink */
        default:  return IN_MODIFY;
    }
}

void inotify_feed(char op, const char *path) {
    if (!path) return;
    uint32_t m = op_mask(op);
    for (int i = 0; i < INOT_MAX; i++) {
        if (!g_inot[i].used) continue;
        struct inot *n = &g_inot[i];
        for (int j = 0; j < INOT_WATCH; j++) {
            if (!n->w[j].used || !(n->w[j].mask & m)) continue;
            if (!contains(path, n->w[j].path)) continue;          /* path matches the watch */
            int nxt = (n->qhead + 1) % INOT_QUEUE;
            if (nxt == n->qtail) continue;                        /* queue full -> drop (IN_Q_OVERFLOW-ish) */
            struct iev *e = &n->q[n->qhead];
            e->wd = n->w[j].wd; e->mask = m;
            const char *bn = basename_of(path);
            int k = 0; while (bn[k] && k < INOT_NAME - 1) { e->name[k] = bn[k]; k++; }
            while (k < INOT_NAME) e->name[k++] = 0;
            n->qhead = nxt;
        }
    }
}

/* FIONREAD on an inotify fd (M2086): Linux reports the byte total of the
 * queued events, and our records are a fixed 48 bytes, so the count is exact
 * rather than an estimate -- which matters, because the documented idiom is to
 * size a buffer from this number and then read it in one call. */
long inotify_nread(int idx) {
    if (idx < 0 || idx >= INOT_MAX || !g_inot[idx].used) return -1;
    struct inot *n = &g_inot[idx];
    int q = (n->qhead - n->qtail + INOT_QUEUE) % INOT_QUEUE;
    return (long)q * 48;
}

/* Drain queued events into buf as fixed 48-byte records:
 *   wd(4) | mask(4) | cookie(4)=0 | len(4)=32 | name[32]
 * Returns bytes written (0 if no events — a non-blocking read). */
long inotify_read(int idx, void *buf, unsigned long max) {
    if (idx < 0 || idx >= INOT_MAX || !g_inot[idx].used) return -1;
    struct inot *n = &g_inot[idx];
    unsigned char *out = (unsigned char *)buf;
    unsigned long off = 0;
    while (n->qtail != n->qhead && off + 48 <= max) {
        struct iev *e = &n->q[n->qtail];
        uint32_t hdr[4] = { (uint32_t)e->wd, e->mask, 0, INOT_NAME };
        for (int b = 0; b < 16; b++) out[off + b] = ((unsigned char *)hdr)[b];
        for (int b = 0; b < INOT_NAME; b++) out[off + 16 + b] = (unsigned char)e->name[b];
        off += 48;
        n->qtail = (n->qtail + 1) % INOT_QUEUE;
    }
    return (long)off;
}
