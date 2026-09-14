/*
 * vfs.c — dispatch filesystem calls to whatever driver is mounted.
 *
 * Deliberately tiny: we support a single mounted filesystem, so the "VFS" is
 * just an indirection through one ops table. But it's the same shape a real
 * VFS has, and it means kmain/syscalls never mention FAT32 directly — swapping
 * in ext2 later would touch only the driver, not its callers.
 */
#include "kheap.h"   /* directory listings are sized to the caller, from the heap (M1962) */
#include "vfs.h"
#include "procfs.h"
#include "blockdev.h"
#include "tmpfs.h"
#include "syscall.h"   /* struct statx, S_IF* (M1173) */
#include "fsevents.h"
#include "mbox.h"
#include "notify.h"
#include "eventfd.h"
#include "pci.h"
#include "bpf.h"
#include "fanfs.h"
#include "net.h"
#include "app.h"          /* app_current / app_ns_id — per-process mount namespaces (M1122) */

static struct vfs_ops *fs;

/* Synthetic /proc + /dev, a writable RAM /tmp, AND read-only secondary-disk
 * mounts (/disk1, /disk2, …) all live alongside the mounted boot FS. Since the
 * VFS is name-based, we route those paths before delegating to FAT32. A small
 * cwd flag remembers which one the current directory is. */
static int synth_cwd;   /* 0 = boot FS, 1 = /proc, 2 = /dev, 3 = /tmp, >=4 = mount (synth_cwd-4) */
/* When synth_cwd >= 4 (inside a mounted disk), the current directory WITHIN that
 * volume, relative to its root with no leading '/'. "" = the volume root (M1070). */
static char mount_sub[128];

/* --- per-process current directory (M1144) -------------------------------- *
 * synth_cwd + mount_sub above (and the boot FS's fat32 cwd cluster) are the LIVE
 * cwd; they belong to whichever app last ran a syscall. vfs_sync_cwd() swaps that
 * live state to the calling app on each app switch (called once at syscall entry),
 * so each process has its own cwd — no more one app's `cd` leaking into another. */
uint32_t fat32_get_cwd(void);
void     fat32_set_cwd(uint32_t c);
static app_t *cwd_owner;        /* whose cwd is currently live in the globals */

void vfs_sync_cwd(void) {
    app_t *a = app_current();
    if (!a || a == cwd_owner) return;                  /* same app -> globals already theirs */
    if (cwd_owner) app_cwd_save(cwd_owner, synth_cwd, mount_sub, fat32_get_cwd());   /* stash outgoing */
    int s; char sub[128]; uint32_t f;
    app_cwd_load(a, &s, sub, sizeof sub, &f);          /* restore incoming */
    synth_cwd = s;
    int i = 0; for (; sub[i] && i < 127; i++) mount_sub[i] = sub[i]; mount_sub[i] = 0;
    fat32_set_cwd(f);
    cwd_owner = a;
}
/* An exiting app must not be saved into after its slot is freed (M1144). */
void vfs_cwd_forget(app_t *a) { if (cwd_owner == a) cwd_owner = 0; }
/* fork: the child inherits the parent's LIVE cwd (the globals, which are the parent's). */
void vfs_cwd_inherit(app_t *child) { app_cwd_save(child, synth_cwd, mount_sub, fat32_get_cwd()); }

static int mount_path(const char *name, int *midx, char *path, int max);   /* fwd */

/* Give a not-yet-running app a starting directory, by absolute path (M1960).
 *
 * A Linux process needs this because the ABI CANNOT translate a relative path
 * -- it has no idea what the program means it to be relative to -- so a
 * process whose cwd is outside its own root writes relative files into the
 * wrong volume, or nowhere. gcc hit exactly that: it creates its intermediate
 * .s as "./ccXXXXXX.s" and died with
 *
 *     Cannot create temporary file in ./: No such file or directory
 *
 * ...but only on a boot where nothing else had chdir'd first, which made it
 * look intermittent. Returns 0, or -1 if the path is not inside a mount. */
int vfs_cwd_set_for(app_t *a, const char *abs) {
    if (!a || !abs) return -1;
    int midx; char sub[VFS_PATH_MAX];
    if (!mount_path(abs, &midx, sub, sizeof sub)) return -1;
    app_cwd_save(a, 4 + midx, sub[0] ? sub : "/", 0);   /* synth_cwd >= 4 means "inside mount (n-4)" */
    return 0;
}

static int veq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }
static int vstarts(const char *s, const char *pre) { while (*pre) { if (*s++ != *pre++) return 0; } return 1; }

/* --- bind mounts (M1091) + per-process mount namespaces (M1122) ---------------
 * `bind FROM TO` makes the path TO also resolve to FROM (Plan 9 style): a single
 * rewrite applied to every absolute path BEFORE the /proc·/dev·/tmp·/diskN
 * routing. One pass only (no recursion), so even a cyclic bind can't loop.
 *
 * Bindings live in NUMBERED namespaces (M1122): ns[0] is the shared/global one
 * every process starts in (so existing global binds are unchanged); unshare()
 * gives the caller a private COPY it can modify without anyone else seeing it,
 * and fork() inherits the parent's namespace id (shared until unshared). Each
 * process's app_t carries only its ns_id; the tables live here. Containers fall
 * out of fork + unshare + a private bind. */
#define NBINDS 8
#define NNS    8
struct bind_ent { char from[64], to[64]; int used; };
static struct { struct bind_ent ent[NBINDS]; int alloc; } ns[NNS];   /* ns[0] = shared (always valid) */

/* The bind table of the current process's namespace (ns[0] for kernel context). */
static struct bind_ent *cur_ns(void) {
    int id = 0;
    app_t *a = app_current();
    if (a) id = app_ns_id(a);
    if (id < 0 || id >= NNS) id = 0;
    return ns[id].ent;
}

int vfs_bind(const char *from, const char *to) {
    if (!from || !to || from[0] != '/' || to[0] != '/') return -1;
    struct bind_ent *t = cur_ns();
    int slot = -1;
    for (int i = 0; i < NBINDS; i++) if (!t[i].used) { slot = i; break; }
    if (slot < 0) return -1;
    int i = 0; while (from[i] && i < 63) { t[slot].from[i] = from[i]; i++; } t[slot].from[i] = 0;
    int j = 0; while (to[j] && j < 63) { t[slot].to[j] = to[j]; j++; } t[slot].to[j] = 0;
    t[slot].used = 1;
    return 0;
}

/* unshare the mount namespace (M1122): copy the caller's current bindings into a
 * fresh namespace slot and switch the caller to it, so later binds are private. */
int vfs_unshare(void) {
    app_t *a = app_current();
    if (!a) return -1;
    int cur = app_ns_id(a); if (cur < 0 || cur >= NNS) cur = 0;
    int slot = -1;
    for (int i = 1; i < NNS; i++) if (!ns[i].alloc) { slot = i; break; }
    if (slot < 0) return -1;                                /* out of namespace slots */
    for (int j = 0; j < NBINDS; j++) ns[slot].ent[j] = ns[cur].ent[j];   /* snapshot current bindings */
    ns[slot].alloc = 1;
    app_set_ns_id(a, slot);
    return 0;
}

/* Rewrite an absolute `name` through the longest-matching bind (TO -> FROM) in
 * the CURRENT namespace into out[max]; returns `name` unchanged if no match. */
/* Returns the bind-resolved path, or NULL if `name` is too long to represent.
 *
 * Failing closed matters more than it looks: the old code truncated at max-1 and
 * returned the SHORTER string, and a truncated path names a DIFFERENT FILE -- so
 * a read returns some other file's contents and a write destroys it. M1936
 * measured exactly that shape with the old 64-byte per-fd path: openat() on a
 * 105-char path SUCCEEDED and the fd then read the wrong file. (M1937) */
static const char *bind_resolve(const char *name, char *out, int max) {
    { int n = 0; while (name[n]) if (++n >= max) return 0; }   /* unrepresentable -> refuse */
    if (name[0] != '/') return name;                /* binds are absolute */
    struct bind_ent *t = cur_ns();
    int best = -1, bestlen = 0;
    for (int i = 0; i < NBINDS; i++) {
        if (!t[i].used) continue;
        int tl = 0; while (t[i].to[tl]) tl++;
        if (!vstarts(name, t[i].to)) continue;
        if (name[tl] != 0 && name[tl] != '/') continue;   /* must match a whole component */
        if (tl > bestlen) { best = i; bestlen = tl; }
    }
    if (best < 0) return name;
    int p = 0; const char *f = t[best].from;
    while (*f && p < max - 1) out[p++] = *f++;
    for (const char *rest = name + bestlen; *rest && p < max - 1; rest++) out[p++] = *rest;
    out[p] = 0;
    return out;
}

int vfs_binds_format(char *b, int max) {            /* backs /proc/binds (the caller's namespace) */
    struct bind_ent *t = cur_ns();
    int p = 0; const char *hdr = "  TO                    FROM\n";
    while (*hdr && p < max - 1) b[p++] = *hdr++;
    int any = 0;
    for (int i = 0; i < NBINDS; i++) if (t[i].used) {
        if (p < max - 1) b[p++] = ' '; if (p < max - 1) b[p++] = ' ';
        int tl = 0; const char *to = t[i].to; while (*to && p < max - 1) { b[p++] = *to++; tl++; }
        for (int k = tl; k < 22 && p < max - 1; k++) b[p++] = ' ';
        const char *f = t[i].from; while (*f && p < max - 1) b[p++] = *f++;
        if (p < max - 1) b[p++] = '\n';
        any = 1;
    }
    if (!any) { const char *m = "  (none — `bind <from> <to>`)\n"; while (*m && p < max - 1) b[p++] = *m++; }
    if (p < max) b[p] = 0;
    return p;
}

/* Join a relative path `rel` onto the volume-relative base `cur`, collapsing "."
 * and ".." components, into `out` (no leading '/', "" = the volume root). Used to
 * track the cwd as the user descends/ascends a mounted disk's subdirectories. */
static void mount_sub_join(const char *cur, const char *rel, char *out, int max) {
    int p = 0;
    for (int i = 0; cur[i] && p < max - 1; i++) out[p++] = cur[i];
    out[p] = 0;
    const char *s = rel;
    while (*s) {
        while (*s == '/') s++;
        if (!*s) break;
        const char *c = s; int len = 0;
        while (s[len] && s[len] != '/') len++;
        s += len;
        if (len == 1 && c[0] == '.') continue;                 /* "." : stay */
        if (len == 2 && c[0] == '.' && c[1] == '.') {          /* ".." : pop a component */
            while (p > 0 && out[p - 1] != '/') p--;
            if (p > 0) p--;                                    /* drop the separator */
            out[p] = 0;
            continue;
        }
        if (p > 0 && p < max - 1) out[p++] = '/';
        for (int i = 0; i < len && p < max - 1; i++) out[p++] = c[i];
        out[p] = 0;
    }
}

/* Route an absolute /ipc/<name> path to a named message queue (mbox). Returns 1
 * + the queue name if it targets /ipc/, else 0. Absolute-only (no cwd). */
static int ipc_path(const char *name, const char **q) {
    if (!vstarts(name, "/ipc/")) return 0;
    *q = name + 5;
    return **q != 0;
}

/* Route an absolute /notify/<name> path to a notification object. Returns 1 +
 * the object name if it targets /notify/, else 0. Absolute-only (no cwd). */
static int notify_path(const char *name, const char **q) {
    if (!vstarts(name, "/notify/")) return 0;
    *q = name + 8;
    return **q != 0;
}

/* Route an absolute /net/tcp/<...> path to the TCP sockets-as-files layer
 * (M1110). Returns 1 + the sub-path ("clone", "<n>/ctl", "<n>/data"), else 0. */
static int nettcp_path(const char *name, const char **q) {
    if (!vstarts(name, "/net/tcp/")) return 0;
    *q = name + 9;
    return **q != 0;
}

/* Route /timer/<ms> (a sleepable file) and /event/<name> (a counting eventfd) to
 * the eventfd layer (M1113). Absolute-only. Each returns 1 + the sub-path. */
static int timer_path(const char *name, const char **q) {
    if (!vstarts(name, "/timer/")) return 0;
    *q = name + 7;
    return **q != 0;
}
static int event_path(const char *name, const char **q) {
    if (!vstarts(name, "/event/")) return 0;
    *q = name + 7;
    return **q != 0;
}

/* Non-blocking readiness of a path for fswait (M1125): would a read return
 * without blocking? The blockable IPC objects answer truthfully; everything else
 * (regular files, /proc, /dev) is treated as always-ready (its read won't park). */
int vfs_ready(const char *name) {
    const char *q;
    if (veq(name, "/proc/self/sigfd")) return app_sigfd_ready(app_current());  /* signalfd (M1126) */
    if (event_path(name, &q))  return eventfd_ready(q);
    if (notify_path(name, &q)) return notify_ready(q);
    if (ipc_path(name, &q))    return mbox_ready(q);
    return 1;
}

/* Route /bpf (M1127): write bytecode here to load an eBPF-lite packet filter. */
static int bpf_path(const char *name) { return veq(name, "/bpf"); }

/* Route /fan/<name> (M1128): a userspace-materialized file. Returns 1 + the name. */
static int fan_path(const char *name, const char **q) {
    if (!vstarts(name, "/fan/")) return 0;
    *q = name + 5;
    return **q != 0;
}

/* Route /pci (M1120): "/pci" or "/pci/" -> list (q=""), "/pci/<rest>" -> q. */
static int pci_path(const char *name, const char **q) {
    if (!vstarts(name, "/pci")) return 0;
    const char *p = name + 4;
    if (*p == 0) { *q = p; return 1; }            /* "/pci" -> list */
    if (*p == '/') { *q = p + 1; return 1; }      /* "/pci/..." */
    return 0;                                     /* e.g. "/pcithing" is not ours */
}

/* Route /snap (CoW tmpfs snapshots, M1115): "/snap" or "/snap/" -> list (q=""),
 * "/snap/<rest>" -> q = the remainder ("ctl", or "<gen>/<name>"). */
static int snap_path(const char *name, const char **q) {
    if (!vstarts(name, "/snap")) return 0;
    const char *p = name + 5;
    if (*p == 0) { *q = p; return 1; }            /* "/snap" -> list */
    if (*p == '/') { *q = p + 1; return 1; }      /* "/snap/..." */
    return 0;                                     /* e.g. "/snapshot-something" is not ours */
}

/* Route a (possibly relative) name to the RAM /tmp filesystem. Returns 1 + the
 * basename within /tmp if it targets /tmp, else 0. */
static int tmp_path(const char *name, const char **base) {
    if (name[0] == '/') { if (!vstarts(name, "/tmp/")) return 0; *base = name + 5; return **base != 0; }
    if (synth_cwd == 3) { *base = name; return 1; }
    return 0;
}

/* Resolve a (possibly relative) name to an absolute synthetic path. Returns 1
 * if it belongs to /proc or /dev (and fills out), else 0 (use the mounted FS). */
static int synth_path(const char *name, char *out, int max) {
    if (name[0] == '/') {
        if (!procfs_owns(name)) return 0;
        int i = 0; while (name[i] && i < max - 1) { out[i] = name[i]; i++; } out[i] = 0;
        return 1;
    }
    if (synth_cwd != 1 && synth_cwd != 2) return 0;   /* /tmp + disk mounts route elsewhere */
    const char *base = synth_cwd == 1 ? "/proc/" : "/dev/";
    int p = 0; while (base[p] && p < max - 1) { out[p] = base[p]; p++; }
    int i = 0; while (name[i] && p < max - 1) out[p++] = name[i++];
    out[p] = 0;
    return 1;
}

/* Route a (possibly relative) name to a mounted disk volume. Returns 1 + sets
 * *midx (mount index) and fills `path` with the file's location relative to the
 * volume root if it targets /disk<N> (absolute) or we're cwd'd inside a mount
 * (relative, resolved against mount_sub); else 0 (use /proc·/dev·boot FS).
 * Subdirectory-aware (M1070): /diskN/a/b/file and relative names both resolve. */
static int mount_path(const char *name, int *midx, char *path, int max) {
    if (name[0] == '/') {
        char comp[12]; int c = 0; const char *p = name + 1;
        while (*p && *p != '/' && c < 11) comp[c++] = *p++;
        comp[c] = 0;
        int idx = blockdev_mount_index(comp);
        if (idx < 0) return 0;
        *midx = idx;
        const char *rest = (*p == '/') ? p + 1 : p;
        int i = 0; while (rest[i] && i < max - 1) { path[i] = rest[i]; i++; } path[i] = 0;
        return 1;
    }
    if (synth_cwd >= 4) {                          /* relative name inside the cwd mount */
        *midx = synth_cwd - 4;
        int p = 0;
        for (int i = 0; mount_sub[i] && p < max - 1; i++) path[p++] = mount_sub[i];
        if (p > 0 && p < max - 1) path[p++] = '/';
        for (int i = 0; name[i] && p < max - 1; i++) path[p++] = name[i];
        path[p] = 0;
        return 1;
    }
    return 0;
}

void vfs_register(struct vfs_ops *ops) { fs = ops; }

/* --- overlay filesystem (M1142): a union mount at /over of a read-only LOWER
 * directory and a writable UPPER directory. Reads check the upper first, then
 * fall through to the lower; writes go to the upper (copy-up on write), leaving
 * the lower untouched — the mechanism behind container images and live-CD
 * overlays. Implemented as a thin router that composes the existing per-FS ops
 * via vfs_read/vfs_write on the rebased path (so the lower can be any FS — ISO,
 * ext2 — and the upper any writable one — tmpfs). One overlay at a time. */
#define OVER_CWD 50                                   /* synth_cwd value while inside /over */
static char ov_lower[96], ov_upper[96];
static int  ov_active;
static int  ov_lower_midx;                            /* if the lower is /diskN, its mount index (for listing); else -1 */
void vfs_overlay_mount(const char *lower, const char *upper) {
    int i = 0; for (; lower[i] && i < 95; i++) ov_lower[i] = lower[i]; ov_lower[i] = 0;
    i = 0;     for (; upper[i] && i < 95; i++) ov_upper[i] = upper[i]; ov_upper[i] = 0;
    ov_active = (ov_lower[0] && ov_upper[0]);
    ov_lower_midx = -1;                               /* parse a "/diskN" lower for the merged listing */
    if (ov_lower[0] == '/') {
        char comp[12]; int c = 0; const char *p = ov_lower + 1;
        while (*p && *p != '/' && c < 11) comp[c++] = *p++;
        comp[c] = 0;
        if (*p == 0) ov_lower_midx = blockdev_mount_index(comp);
    }
}
/* Build the upper-layer whiteout marker path for `rel` (ov_upper + "/.wh." + rel). */
static void ov_wh(const char *rel, char *out, int max) {
    int o = 0;
    for (; ov_upper[o] && o < max - 6; o++) out[o] = ov_upper[o];
    if (o > 0 && out[o - 1] != '/') out[o++] = '/';
    const char *w = ".wh."; for (int j = 0; w[j] && o < max - 1; j++) out[o++] = w[j];
    for (int j = 0; rel[j] && o < max - 1; j++) out[o++] = rel[j];
    out[o] = 0;
}
/* Does a whiteout exist for `rel` in the upper layer? */
static int ov_whiteouted(const char *rel) {
    char wh[192], one[1]; ov_wh(rel, wh, sizeof wh);
    return vfs_read(wh, one, 1) >= 0;
}
static int over_path(const char *name, const char **rel) {
    if (!ov_active) return 0;
    if (vstarts(name, "/over/")) { *rel = name + 6; return **rel != 0; }   /* absolute */
    if (synth_cwd == OVER_CWD && name[0] != '/') { *rel = name; return *name != 0; }  /* relative, cwd inside /over */
    return 0;
}
/* join base + "/" + rel into out (e.g. "/tmp" + "X" -> "/tmp/X") */
static void ov_join(const char *base, const char *rel, char *out, int max) {
    int o = 0;
    for (; base[o] && o < max - 2; o++) out[o] = base[o];
    if (o > 0 && out[o - 1] != '/') out[o++] = '/';
    for (int j = 0; rel[j] && o < max - 1; j++) out[o++] = rel[j];
    out[o] = 0;
}

/* Merged listing of the overlay (M1143): upper entries (minus whiteout markers),
 * then lower entries that the upper doesn't shadow and that aren't whiteouted.
 * v1 lists a tmpfs upper + a /diskN lower (the usual config). */
static int over_list(vfs_dirent *out, int max) {
    vfs_dirent up[64]; int nup = 0;
    if (veq(ov_upper, "/tmp")) nup = tmpfs_list(up, 64);
    int n = 0;
    for (int i = 0; i < nup && n < max; i++) {
        if (vstarts(up[i].name, ".wh.")) continue;        /* hide whiteout markers */
        out[n++] = up[i];
    }
    if (ov_lower_midx >= 0) {
        fatvol_dirent lo[64];
        int nlo = blockdev_mount_list(ov_lower_midx, "", lo, 64);
        for (int i = 0; i < nlo && n < max; i++) {
            int hidden = ov_whiteouted(lo[i].name);
            for (int j = 0; !hidden && j < nup; j++) if (veq(lo[i].name, up[j].name)) hidden = 1;  /* shadowed */
            if (hidden) continue;
            int k = 0; while (lo[i].name[k] && k < 60) { out[n].name[k] = lo[i].name[k]; k++; }
            if (lo[i].is_dir) out[n].name[k++] = '/';
            out[n].name[k] = 0;
            out[n].size = lo[i].size; out[n].date = 0; out[n].time = 0;
            n++;
        }
    }
    return n;
}

int vfs_list(vfs_dirent *out, int max) {
    if (synth_cwd == OVER_CWD) return over_list(out, max);  /* the merged overlay (M1143) */
    if (synth_cwd == 1 || synth_cwd == 2)
        return procfs_list(synth_cwd == 1 ? "/proc" : "/dev", out, max);
    if (synth_cwd == 3) return tmpfs_list(out, max);       /* the RAM /tmp */
    if (synth_cwd >= 4) {                                  /* a mounted disk volume's root */
        fatvol_dirent fe[64];
        int cap = max < 64 ? max : 64;
        int n = blockdev_mount_list(synth_cwd - 4, mount_sub, fe, cap);
        for (int i = 0; i < n; i++) {
            int k = 0; while (fe[i].name[k] && k < 60) { out[i].name[k] = fe[i].name[k]; k++; }
            if (fe[i].is_dir) out[i].name[k++] = '/';     /* match fat32_list's dir marker */
            out[i].name[k] = 0;
            out[i].size = fe[i].size; out[i].date = 0; out[i].time = 0;
        }
        return n;
    }
    return fs ? fs->list(out, max) : -1;
}

/* List a directory by PATH on the boot filesystem, independent of the live
 * per-process cwd -- so the GUI Files window can browse the disk without
 * disturbing any shell/app's current directory (M1761). Boot FS only; the
 * synthetic (/proc /dev /tmp) and secondary-mount (/diskN) directories keep
 * using the cwd-based vfs_list(). Returns the entry count, or -1. */
/* List a directory by path. Unlike every sibling here this went STRAIGHT to
 * the boot filesystem with no routing, so a /diskN mount could not be listed at
 * all -- `opendir("/disk2")` returned zero entries with no error (M1946). It
 * now dispatches like vfs_read/vfs_stat do. */
int vfs_list_path(const char *path, vfs_dirent *out, int max) {
    if (!out || max <= 0) return -1;
    const char *p = (path && path[0]) ? path : "/";
    char rb[VFS_PATH_MAX];
    p = bind_resolve(p, rb, sizeof rb);
    if (!p) return -1;                             /* path too long to represent (M1937) */

    int midx; char fpath[VFS_PATH_MAX];
    if (mount_path(p, &midx, fpath, sizeof fpath)) {
        /* fatvol_dirent carries is_dir, vfs_dirent does not, so the two are
         * NOT layout-compatible -- copy field by field rather than casting. */
        /* Sized to what the CALLER asked for, from the heap (M1962). This was
         * `static fatvol_dirent fe[64]` with max clamped to 64 -- a silent
         * wrong answer for any directory with more entries, and a shared
         * buffer besides. OS-DEV's own kernel/ has 136 .c files, so GNU make's
         * $(wildcard kernel/*.c) saw 62 of them and the in-guest build linked a
         * PARTIAL object list; it came back as pages of "undefined reference to
         * kmalloc / pci_find / wav_parse", every one a file alphabetically
         * after the cut, with nothing pointing at directory listing. */
        fatvol_dirent *fe = kmalloc((unsigned long)max * sizeof *fe);
        if (!fe) return -1;
        int n = blockdev_mount_list(midx, fpath, fe, max);
        if (n < 0) { kfree(fe); return -1; }
        for (int i = 0; i < n; i++) {
            int k = 0;
            while (fe[i].name[k] && k < (int)sizeof out[i].name - 1) { out[i].name[k] = fe[i].name[k]; k++; }
            out[i].name[k] = 0;
            out[i].size = fe[i].size;
            out[i].date = out[i].time = 0;
        }
        kfree(fe);
        return n;
    }
    if (!fs || !fs->list_path) return -1;
    return fs->list_path(p, out, max);
}

/* Positioned read: up to `max` bytes of `name` starting at byte `off`. Backs
 * file-backed mmap (M1136) and read+write file fds (M1193/M1196). tmpfs and ext2
 * mounts now read natively at the offset (seek-efficient, uncapped, M1196); the
 * boot filesystem uses its fs->pread; ISO/FAT mounts read-prefix-slice inside
 * blockdev_mount_pread. A boot-FS path matches neither tmpfs nor a mount, so it
 * still hits fs->pread exactly as before (mmap unaffected). */
long vfs_pread(const char *name, void *buf, unsigned long max, uint64_t off) {
    char rb[VFS_PATH_MAX]; const char *rn = bind_resolve(name, rb, sizeof rb);
    if (!rn) return -1;                            /* path too long to represent (M1937) */
    const char *tb;
    { /* /proc and /dev (M1965). Without this an open()ed synthetic file became
       * a FILE fd whose reads all went to the boot filesystem and returned -1;
       * the node existed, the open succeeded, and every read failed.
       * procfs_read generates the WHOLE file each call and has no notion of an
       * offset, so generate and slice. These files are small (a few hundred
       * bytes); a reader at a non-zero offset is on its second read and is
       * about to be told EOF. */
        char ap[VFS_PATH_MAX];
        if (synth_path(rn, ap, sizeof ap)) {
            int chardev = 0;
            if (!procfs_exists(ap, &chardev)) return -1;
            /* A character device is a STREAM, not a file with an end: reading
             * /dev/urandom at offset 4096 must produce more random bytes, not
             * EOF. Only the /proc files -- which are a snapshot with a
             * definite length -- get the offset applied. */
            if (chardev) return procfs_read(ap, buf, max);
            char *tmp = (char *)kmalloc(65536);      /* off the kernel stack; /proc/kallsyms is large */
            if (!tmp) return -1;
            long got = procfs_read(ap, tmp, 65536);
            long out = -1;
            if (got >= 0) {
                if (off >= (uint64_t)got) out = 0;                   /* EOF */
                else {
                    unsigned long n = (unsigned long)got - (unsigned long)off;
                    if (n > max) n = max;
                    for (unsigned long i = 0; i < n; i++) ((char *)buf)[i] = tmp[off + i];
                    out = (long)n;
                }
            }
            kfree(tmp);
            return out;
        }
    }
    if (tmp_path(rn, &tb)) return tmpfs_pread(tb, buf, max, (unsigned long)off);   /* tmpfs native (M1196) */
    int midx; char fpath[VFS_PATH_MAX];
    if (mount_path(rn, &midx, fpath, sizeof fpath))
        return blockdev_mount_pread(midx, fpath, buf, max, (unsigned long)off);    /* ext2 native / iso-fat prefix (M1196) */
    return (fs && fs->pread) ? fs->pread(name, buf, max, off) : -1;                /* boot FS (M1136) */
}

/* Positional WRITE — the streaming counterpart of vfs_pread (M1935).
 *
 * Only the touched bytes reach the filesystem, so a caller can build a file
 * far larger than any buffer it holds, and the cost of a write is proportional
 * to its length rather than to the size of the file.
 *
 * Returns bytes written, -1 on a real error, or VFS_PWRITE_UNSUPPORTED when
 * this filesystem has no positional write and the caller should fall back to
 * read-modify-write. That distinction matters: the FAT32 boot volume IS
 * writable, just not positionally, so it must be told apart from an ISO mount
 * where a write genuinely fails. */
long vfs_pwrite(const char *name, const void *buf, unsigned long len, uint64_t off) {
    char rb[VFS_PATH_MAX]; const char *rn = bind_resolve(name, rb, sizeof rb);
    if (!rn) return -1;                            /* path too long to represent (M1937) */
    const char *tb;
    if (tmp_path(rn, &tb)) return VFS_PWRITE_UNSUPPORTED;      /* tmpfs: whole-file replace only */
    int midx; char fpath[VFS_PATH_MAX];
    if (mount_path(rn, &midx, fpath, sizeof fpath))
        return blockdev_mount_pwrite(midx, fpath, buf, len, off);   /* ext2 native */
    return (fs && fs->pwrite) ? fs->pwrite(name, buf, len, off) : VFS_PWRITE_UNSUPPORTED;
}

long vfs_read(const char *name, void *buf, unsigned long max) {
    char ap[VFS_PATH_MAX]; const char *tb;
    char rb[VFS_PATH_MAX]; name = bind_resolve(name, rb, sizeof rb);     /* bind mounts (M1091) */
    if (!name) return -1;                            /* path too long to represent (M1937) */
    if (over_path(name, &tb)) {                                 /* /over: upper, then lower (M1142) */
        if (ov_whiteouted(tb)) return -1;                       /* deleted via the overlay (M1143) */
        char up[VFS_PATH_MAX]; ov_join(ov_upper, tb, up, sizeof up);
        long r = vfs_read(up, buf, max);                        /* recurses, but `up` is not under /over */
        if (r >= 0) return r;
        char lo[VFS_PATH_MAX]; ov_join(ov_lower, tb, lo, sizeof lo);
        return vfs_read(lo, buf, max);
    }
    if (synth_path(name, ap, sizeof ap)) return procfs_read(ap, buf, max);
    if (ipc_path(name, &tb)) return mbox_read(tb, buf, max);   /* /ipc/<q>: dequeue a message (blocks if empty) */
    if (notify_path(name, &tb)) return notify_wait(tb, buf, max);   /* /notify/<n>: block until signalled, return+clear the mask */
    if (nettcp_path(name, &tb)) return netfs_read(tb, buf, max);    /* /net/tcp/<...>: sockets-as-files */
    if (pci_path(name, &tb)) return pcifs_read(tb, (char *)buf, (int)max);  /* /pci: device tree as files (M1120) */
    if (timer_path(name, &tb)) return timer_read(tb, buf, max);     /* /timer/<ms>: block <ms> then "tick" */
    if (event_path(name, &tb)) return eventfd_read(tb, buf, max);   /* /event/<n>: block until >0, return+drain */
    if (fan_path(name, &tb)) return fanfs_read(tb, buf, max);       /* /fan/<name>: userspace-materialized file (M1128) */
    if (snap_path(name, &tb)) {                                     /* /snap: CoW tmpfs snapshots (M1115) */
        if (!tb[0]) return tmpfs_snap_list((char *)buf, (int)max);  /* "/snap" -> list generations */
        int g = 0; const char *s = tb;
        if (*s < '0' || *s > '9') return -1;                        /* expect "/snap/<gen>/<name>" */
        while (*s >= '0' && *s <= '9') { g = g * 10 + (*s - '0'); s++; }
        if (*s != '/') return -1;
        return tmpfs_snap_read(g, s + 1, buf, max);
    }
    if (tmp_path(name, &tb)) return tmpfs_read(tb, buf, max);
    int midx; char fpath[VFS_PATH_MAX];
    if (mount_path(name, &midx, fpath, sizeof fpath)) return blockdev_mount_read(midx, fpath, buf, max);
    return fs ? fs->read(name, buf, max) : -1;
}

/* statx (M1173): fill `st` with a path's metadata. The RAM /tmp backend gives a
 * real mtime (M1173 stamps it on write); for other paths the dirent channel
 * carries only size, so we report size + a regular-file type (mtime 0). Returns
 * 0, or -1 if the path isn't found. */
/* A stable, distinct inode number for a filesystem that has none of its own
 * (FAT32, ISO9660, tmpfs, the synthetic mount roots). 32-bit FNV-1a over the
 * resolved path: the same path always yields the same number and two different
 * paths practically never collide, which is the property callers rely on.
 *
 * This is not cosmetic. A dynamic linker decides "have I already loaded this
 * object?" by comparing (st_dev, st_ino), so reporting a CONSTANT inode makes
 * every shared library look like the first one already mapped -- ld.so opened
 * libz, libzstd and libc, matched them all against libbfd, and mapped none of
 * them, which surfaced as `undefined symbol: free, version GLIBC_2.2.5`
 * with no indication of the cause. (M1955) */
static unsigned path_ino(const char *p) {
    unsigned h = 2166136261u;
    for (int i = 0; p && p[i]; i++) { h ^= (unsigned char)p[i]; h *= 16777619u; }
    return h ? h : 1u;                          /* 0 means "none", so never return it */
}

static int vfs_stat_inner(const char *path, struct statx *st);

/* Normalise what the filesystems report into what a Linux program is entitled
 * to assume. Two fields were wrong everywhere and only showed up under a real
 * runtime (M1998):
 *
 *   stx_ino = 0 -- the mount-point directory itself returned before it set an
 *     inode, so stat("/") gave inode ZERO. Zero is not an inode; it is what a
 *     program reads as "this has no identity". Anything that keys a cache on
 *     (dev, ino), compares two paths for sameness, or detects a hardlink gets a
 *     collision between every such directory. Linux's root is inode 2.
 *
 *   stx_nlink = 1 on a directory -- a directory always has at least 2 links
 *     ("." and its entry in its parent). find(1)'s leaf optimisation subtracts
 *     2 from it and walks a negative number of subdirectories. */
int vfs_stat(const char *path, struct statx *st) {
    int rc = vfs_stat_inner(path, st);
    if (rc == 0) {
        if ((st->stx_mode & 0170000u) == 0040000u && st->stx_nlink < 2) st->stx_nlink = 2;
        if (!st->stx_ino) st->stx_ino = 2;          /* the root's inode on every real Linux */
    }
    return rc;
}

static int vfs_stat_inner(const char *path, struct statx *st) {
    for (unsigned i = 0; i < sizeof(*st); i++) ((char *)st)[i] = 0;
    st->stx_blksize = 512; st->stx_nlink = 1;
    /* bind mounts (M1622 follow-up) -- every other vfs_* function does this;
     * vfs_stat was the one exception, so stat-ing a path only reachable via a
     * bind mount reported not-found. */
    char rb[VFS_PATH_MAX]; path = bind_resolve(path, rb, sizeof rb);
    if (!path) return -1;                            /* path too long to represent (M1937) */
    const char *tb;
    /* directory roots: the boot root + the synthetic/RAM mount points (tmp_path
     * wants a trailing slash, so the bare "/tmp" mount dir lands here) (M1173) */
    if (veq(path, "/") || veq(path, "/tmp") || veq(path, "/tmp/") || veq(path, "/proc") || veq(path, "/proc/") ||
        veq(path, "/dev") || veq(path, "/dev/") || veq(path, "/snap") || veq(path, "/snap/")) {
        st->stx_mode = S_IFDIR | 0755u; st->stx_ino = path_ino(path); return 0;
    }
    { /* /proc and /dev FILES (M1965). The directories were already handled
       * above; their contents were not, so stat said "no such file" for every
       * one of them and open() therefore refused to open any. Size is reported
       * as 0, exactly as Linux does for a generated /proc file -- the content
       * does not exist until it is read. */
        char ap[VFS_PATH_MAX];
        if (synth_path(path, ap, sizeof ap)) {
            int chardev = 0;
            if (!procfs_exists(ap, &chardev)) return -1;
            st->stx_mode = (unsigned)(chardev ? S_IFCHR : S_IFREG) | (chardev ? 0666u : 0444u);
            st->stx_ino = path_ino(ap);
            return 0;
        }
    }
    if (tmp_path(path, &tb)) {                          /* RAM /tmp: full metadata */
        int islink = 0; unsigned long sz = 0, mt = 0;
        if (tmpfs_stat(tb, &islink, &sz, &mt) != 0) return -1;
        st->stx_mode = (unsigned)(islink ? S_IFLNK : S_IFREG) | 0644u;
        st->stx_size = sz; st->stx_blocks = (sz + 511) / 512;
        st->stx_mtime = st->stx_ctime = st->stx_atime = mt;
        st->stx_ino = path_ino(path);
        return 0;
    }
    { /* a /diskN mount (M1624) -- ABSOLUTE regardless of cwd, or relative while
       * cwd is inside it; mount_path() already handles both, exactly like every
       * other vfs_* function's own /diskN gate (vfs_read/vfs_write/etc. above).
       * Closes the gap the M1622 fallback below deliberately left open: its
       * FAT32-only resolve() has no notion of a mount name as a path component. */
        int midx; char fpath[VFS_PATH_MAX];
        if (mount_path(path, &midx, fpath, sizeof fpath)) {
            /* The mount ROOT itself -- "/disk2" with no subpath -- is a
             * directory by definition, and there is no entry for
             * blockdev_mount_stat to look up, so it failed. That made
             * stat("/disk2") report not-found, which made app_open refuse to
             * hand out a directory fd, which is why opendir() on a mount
             * returned nothing at all. mount_path() leaves fpath empty in
             * exactly this case. (M1947) */
            if (!fpath[0] || (fpath[0] == '/' && !fpath[1])) {
                st->stx_mode = S_IFDIR | 0755u;
                return 0;
            }
            uint32_t fsize; int fisdir; uint32_t fino = 0;
            if (blockdev_mount_stat(midx, fpath, &fsize, &fisdir, &fino) != 0) return -1;
            st->stx_mode = (unsigned)(fisdir ? S_IFDIR : S_IFREG) | (fisdir ? 0755u : 0644u);
            st->stx_size = fsize; st->stx_blocks = (fsize + 511) / 512;
            /* The real ext2 inode when the filesystem has one; a path hash
             * otherwise. Hash the FULL path, not fpath, so the same name on
             * two different mounts gets two different inodes. */
            st->stx_ino = fino ? fino : path_ino(path);
            return 0;
        }
    }
    /* generic best-effort: walk the path's OWN components from wherever it's
     * rooted (M1622) -- previously stripped to a bare basename and matched
     * against vfs_list()'s listing of the CURRENT cwd, so an absolute path
     * silently reported not-found whenever cwd wasn't "/". Also previously
     * had a trailing-slash shortcut here that reported ANY path ending in
     * '/' as an existing directory unconditionally, without checking
     * anything -- fat32_stat_path's own resolve() call now does that check
     * for real.
     *
     * fs->stat_path's resolve() is FAT32-internal: for an ABSOLUTE path it
     * always starts at the real root, correctly, regardless of synth_cwd.
     * But for a RELATIVE path it uses FAT32's own cwd_cluster -- which
     * vfs_chdir does NOT update when entering a /diskN mount (that only
     * moves synth_cwd + mount_sub, see vfs_chdir above), so it goes stale.
     * A relative stat while cwd is logically inside a mount (synth_cwd >= 4,
     * or any other synthetic cwd) still needs the OLD vfs_list()-based
     * match, since vfs_list() IS synth_cwd-aware. (M1622 follow-up) */
    if (path[0] == '/' || synth_cwd == 0) {
        uint32_t fsize; int fisdir;
        if (fs && fs->stat_path && fs->stat_path(path, &fsize, &fisdir) == 0) {
            st->stx_mode = (unsigned)(fisdir ? S_IFDIR : S_IFREG) | (fisdir ? 0755u : 0644u);
            st->stx_size = fsize; st->stx_blocks = (fsize + 511) / 512;
            return 0;
        }
        return -1;
    }
    const char *base = path; for (const char *p = path; *p; p++) if (*p == '/') base = p + 1;
    if (!*base) { st->stx_mode = S_IFDIR | 0755u; st->stx_ino = path_ino(path); return 0; }   /* trailing slash -> a directory */
    vfs_dirent ents[64]; int n = vfs_list(ents, 64);
    for (int i = 0; i < n; i++) if (veq(ents[i].name, base)) {
        st->stx_mode = S_IFREG | 0644u;                /* the dirent carries no type bit -> assume regular */
        st->stx_size = ents[i].size; st->stx_blocks = (ents[i].size + 511) / 512;
        st->stx_ino = path_ino(path);
        return 0;
    }
    return -1;
}

long vfs_write(const char *name, const void *buf, unsigned long len) {
    char ap[VFS_PATH_MAX]; const char *tb;
    char rb[VFS_PATH_MAX]; name = bind_resolve(name, rb, sizeof rb);     /* bind mounts (M1091) */
    if (!name) return -1;                            /* path too long to represent (M1937) */
    if (over_path(name, &tb)) {                                 /* /over: copy-up — writes go to the upper (M1142) */
        char up[VFS_PATH_MAX]; ov_join(ov_upper, tb, up, sizeof up);
        long r = vfs_write(up, buf, len);
        if (r >= 0) {
            char wh[192]; ov_wh(tb, wh, sizeof wh); vfs_remove(wh);   /* writing un-deletes it (M1143) */
            fsevents_record('w', name);
        }
        return r;
    }
    if (synth_path(name, ap, sizeof ap)) { long r = procfs_write(ap, buf, len); return r == -2 ? -1 : r; }
    if (ipc_path(name, &tb)) return mbox_write(tb, buf, len);   /* /ipc/<q>: enqueue a message */
    if (notify_path(name, &tb)) return notify_signal(tb, buf, len);   /* /notify/<n>: OR bits into the mask + wake */
    if (nettcp_path(name, &tb)) return netfs_write(tb, buf, len);     /* /net/tcp/<...>: connect / send */
    if (event_path(name, &tb)) return eventfd_write(tb, buf, len);    /* /event/<n>: counter += N, wake a reader */
    if (snap_path(name, &tb) && vstarts(tb, "ctl")) return tmpfs_snap_control(buf, len);  /* /snap/ctl: create / drop (M1115) */
    if (bpf_path(name)) return bpf_load(buf, len) < 0 ? -1 : (long)len;   /* /bpf: load an eBPF-lite filter (M1127) */
    long r;
    if (tmp_path(name, &tb)) r = tmpfs_write(tb, buf, len);
    else {
        int midx; char fpath[VFS_PATH_MAX];
        if (mount_path(name, &midx, fpath, sizeof fpath))             /* a /diskN mount: ext2 is writable (M1132) */
            r = blockdev_mount_write(midx, fpath, buf, len);
        else
            r = (fs && fs->write) ? fs->write(name, buf, len) : -1;
    }
    if (r >= 0) fsevents_record('w', name);    /* a real file changed (M1085) */
    return r;
}

long vfs_remove(const char *name) {
    const char *tb;
    char rb[VFS_PATH_MAX]; name = bind_resolve(name, rb, sizeof rb);     /* bind mounts (M1091) */
    if (!name) return -1;                            /* path too long to represent (M1937) */
    if (over_path(name, &tb)) {                                 /* delete via the overlay: whiteout (M1143) */
        char up[VFS_PATH_MAX]; ov_join(ov_upper, tb, up, sizeof up);
        vfs_remove(up);                                         /* drop the upper copy, if any */
        char wh[192]; ov_wh(tb, wh, sizeof wh);
        vfs_write(wh, "x", 1);                                  /* lay a whiteout to hide the lower */
        fsevents_record('w', name);
        return 0;
    }
    long r;
    if (tmp_path(name, &tb)) r = tmpfs_remove(tb);
    else {
        int midx; char fpath[VFS_PATH_MAX];
        if (mount_path(name, &midx, fpath, sizeof fpath))             /* a /diskN mount: ext2 is writable (M1135) */
            r = blockdev_mount_remove(midx, fpath);
        else
            r = (fs && fs->remove) ? fs->remove(name) : -1;
    }
    if (r >= 0) fsevents_record('d', name);
    return r;
}

long vfs_mkdir(const char *path) {
    char rb[VFS_PATH_MAX]; const char *p = bind_resolve(path, rb, sizeof rb);   /* bind mounts */
    if (!p) return -1;                            /* path too long to represent (M1937) */
    long r;
    int midx; char fpath[VFS_PATH_MAX];
    if (mount_path(p, &midx, fpath, sizeof fpath))                     /* a /diskN mount: ext2 is writable (M1137) */
        r = blockdev_mount_mkdir(midx, fpath);
    else
        r = (fs && fs->mkdir) ? fs->mkdir(p) : -1;
    if (r >= 0) fsevents_record('m', p);
    return r;
}

/* Create a symlink `linkpath` -> `target`: the RAM /tmp backend (M1081), or a
 * real on-disk /diskN ext2 symlink (M1146) -- the synthetic /proc·/dev stay
 * read-only, and FAT32 has no native symlink support. Returns 0 / -1. */
long vfs_symlink(const char *linkpath, const char *target) {
    char rb[VFS_PATH_MAX]; linkpath = bind_resolve(linkpath, rb, sizeof rb);
    if (!linkpath) return -1;                            /* path too long to represent (M1937) */
    const char *base;
    if (tmp_path(linkpath, &base)) {
        long r = tmpfs_symlink(base, target);
        if (r >= 0) fsevents_record('l', linkpath);
        return r;
    }
    int midx; char fpath[VFS_PATH_MAX];
    if (mount_path(linkpath, &midx, fpath, sizeof fpath)) {     /* /diskN ext2: a real on-disk symlink (M1146) */
        long r = blockdev_mount_symlink(midx, fpath, target);
        if (r >= 0) fsevents_record('l', linkpath);
        return r;
    }
    return -1;
}

/* readlink (M1233; real ext2 on-disk symlinks M1594): read a symlink's TARGET
 * path WITHOUT following it (so e.g. `ls -l` can show "a -> b"). tmpfs
 * symlinks (the ones SYS_symlink creates) and now real /diskN ext2 ones too
 * -- vfs_symlink has been able to CREATE the latter since M1146, but nothing
 * could ever read one back until now. Returns bytes (un-terminated) or -1. */
long vfs_readlink(const char *path, void *buf, unsigned long max) {
    char rb[VFS_PATH_MAX]; const char *p = bind_resolve(path, rb, sizeof rb);
    if (!p) return -1;                            /* path too long to represent (M1937) */
    const char *base;
    if (tmp_path(p, &base)) return tmpfs_readlink(base, buf, max);
    int midx; char fpath[VFS_PATH_MAX];
    if (mount_path(p, &midx, fpath, sizeof fpath)) return blockdev_mount_readlink(midx, fpath, buf, max);
    return -1;
}

/* Hard link (M1207): a second name (newpath) for oldpath's inode. POSIX hard
 * links can't cross filesystems, so both must resolve to the SAME ext2 /diskN
 * mount (boot FAT32 / tmpfs / synth don't support hard links -> -1). */
long vfs_link(const char *oldpath, const char *newpath) {
    char ob[160], nb[160];
    oldpath = bind_resolve(oldpath, ob, sizeof ob);
    if (!oldpath) return -1;                            /* path too long to represent (M1937) */
    newpath = bind_resolve(newpath, nb, sizeof nb);
    if (!newpath) return -1;                            /* path too long to represent (M1937) */
    int omid, nmid; char ofp[192], nfp[192];
    if (mount_path(oldpath, &omid, ofp, sizeof ofp) &&
        mount_path(newpath, &nmid, nfp, sizeof nfp) && omid == nmid) {
        long r = blockdev_mount_link(omid, ofp, nfp);
        if (r >= 0) fsevents_record('l', newpath);
        return r;
    }
    return -1;
}
/* rename(oldpath, newpath) when both resolve to the SAME ext2 /diskN mount
 * (atomic, metadata-preserving, works on directories) — M1213. Returns -1 for a
 * cross-mount or non-ext2 move, so a caller can fall back to copy+delete. */
long vfs_rename_path(const char *oldpath, const char *newpath) {
    char ob[160], nb[160];
    oldpath = bind_resolve(oldpath, ob, sizeof ob);
    if (!oldpath) return -1;                            /* path too long to represent (M1937) */
    newpath = bind_resolve(newpath, nb, sizeof nb);
    if (!newpath) return -1;                            /* path too long to represent (M1937) */
    int omid, nmid; char ofp[192], nfp[192];
    if (mount_path(oldpath, &omid, ofp, sizeof ofp) &&
        mount_path(newpath, &nmid, nfp, sizeof nfp) && omid == nmid) {
        long r = blockdev_mount_rename(omid, ofp, nfp);
        if (r >= 0) fsevents_record('r', newpath);
        return r;
    }
    return -1;
}
/* renameat2 (M1232): rename with RENAME_NOREPLACE / RENAME_EXCHANGE flags.
 * flags==0 is the plain M1213 move. Same-ext2-mount only (like vfs_rename_path). */
long vfs_rename2(const char *oldpath, const char *newpath, int flags) {
    char ob[160], nb[160];
    oldpath = bind_resolve(oldpath, ob, sizeof ob);
    if (!oldpath) return -1;                            /* path too long to represent (M1937) */
    newpath = bind_resolve(newpath, nb, sizeof nb);
    if (!newpath) return -1;                            /* path too long to represent (M1937) */
    int omid, nmid; char ofp[192], nfp[192];
    if (mount_path(oldpath, &omid, ofp, sizeof ofp) &&
        mount_path(newpath, &nmid, nfp, sizeof nfp) && omid == nmid) {
        long r = blockdev_mount_rename2(omid, ofp, nfp, flags);
        if (r >= 0) fsevents_record('r', newpath);
        return r;
    }
    return -1;
}
/* truncate(path, newlen) (M1228): resize a regular file — tmpfs (/tmp) natively,
 * or a file on an ext2 /diskN mount. Returns -1 for the boot FAT fs / not found. */
long vfs_truncate(const char *path, uint64_t newlen) {
    char rb[VFS_PATH_MAX]; const char *p = bind_resolve(path, rb, sizeof rb);
    if (!p) return -1;                            /* path too long to represent (M1937) */
    const char *tb;
    if (tmp_path(p, &tb)) return tmpfs_truncate(tb, newlen);          /* RAM /tmp */
    int mid; char fp[192];
    if (mount_path(p, &mid, fp, sizeof fp)) {
        long r = blockdev_mount_truncate(mid, fp, newlen);
        if (r >= 0) fsevents_record('w', path);
        return r;
    }
    return -1;
}

/* SEEK_HOLE/SEEK_DATA (M1229): find the next hole/data boundary at/after `off`.
 * ext2 /diskN mounts have a real block map (sparse via truncate-grow / punch-
 * hole); everything else (/tmp, FAT32, ISO) is never sparse, so the only hole
 * is the implicit one at EOF. Returns the offset, or -1 (ENXIO / bad off). */
long vfs_seek_data_hole(const char *path, long off, int find_hole) {
    if (off < 0) return -1;
    char rb[VFS_PATH_MAX]; const char *p = bind_resolve(path, rb, sizeof rb);
    if (!p) return -1;                            /* path too long to represent (M1937) */
    const char *tb;
    if (!tmp_path(p, &tb)) {                                  /* not RAM /tmp: try an ext2 block map */
        int mid; char fp[192];
        if (mount_path(p, &mid, fp, sizeof fp)) {
            long r = blockdev_mount_seek_data_hole(mid, fp, off, find_hole);
            if (r != -2) return r;                            /* ext2 answered (offset, or -1 ENXIO) */
        }
    }
    struct statx st;                                          /* generic: data everywhere, hole only at EOF */
    if (vfs_stat(path, &st) != 0) return -1;
    long size = (long)st.stx_size;
    if (off >= size) return -1;                               /* ENXIO: at/after EOF */
    return find_hole ? size : off;
}

/* utimensat (M1230): set a file's atime/mtime. Negative = leave that field
 * unchanged (the syscall layer resolves UTIME_NOW to a concrete epoch and maps
 * UTIME_OMIT to negative first). tmpfs tracks only mtime; ext2 mounts set both.
 * Other paths (FAT32 boot disk, synthetic) are unsupported (-1). */
long vfs_utimes(const char *path, long atime, long mtime) {
    char rb[VFS_PATH_MAX]; const char *p = bind_resolve(path, rb, sizeof rb);
    if (!p) return -1;                            /* path too long to represent (M1937) */
    const char *tb;
    if (tmp_path(p, &tb)) return tmpfs_utimes(tb, atime, mtime);      /* RAM /tmp */
    int mid; char fp[192];
    if (mount_path(p, &mid, fp, sizeof fp)) {
        long r = blockdev_mount_utimes(mid, fp, atime, mtime);
        if (r >= 0) fsevents_record('w', path);
        return r;
    }
    return -1;
}

/* chmod (M1241): change a file's permission bits. Only ext2 /diskN mounts store
 * Unix modes; tmpfs / boot FAT32 have none, so they return -1 (EPERM-ish). */
long vfs_chmod(const char *path, uint32_t mode) {
    char rb[VFS_PATH_MAX]; const char *p = bind_resolve(path, rb, sizeof rb);
    if (!p) return -1;                            /* path too long to represent (M1937) */
    int mid; char fp[192];
    if (mount_path(p, &mid, fp, sizeof fp)) {
        long r = blockdev_mount_chmod(mid, fp, mode);
        if (r >= 0) fsevents_record('w', path);
        return r;
    }
    return -1;
}

/* chown (M1243): change a file's owner/group (negative = leave). ext2 /diskN
 * mounts only (tmpfs / boot FAT32 have no Unix ownership -> -1). */
long vfs_chown(const char *path, long uid, long gid) {
    char rb[VFS_PATH_MAX]; const char *p = bind_resolve(path, rb, sizeof rb);
    if (!p) return -1;                            /* path too long to represent (M1937) */
    int mid; char fp[192];
    if (mount_path(p, &mid, fp, sizeof fp)) {
        long r = blockdev_mount_chown(mid, fp, uid, gid);
        if (r >= 0) fsevents_record('w', path);
        return r;
    }
    return -1;
}

/* FIEMAP (M1152): a file's physical extent map. Only ext2 /diskN mounts carry
 * real block layout, so route there; other paths (boot FAT32, /tmp, synth) are
 * unsupported (-1). Read-only. */
int vfs_fiemap(const char *path, ext2_extent_t *out, int max) {
    char rb[VFS_PATH_MAX]; path = bind_resolve(path, rb, sizeof rb);
    if (!path) return -1;                            /* path too long to represent (M1937) */
    int midx; char fpath[VFS_PATH_MAX];
    if (mount_path(path, &midx, fpath, sizeof fpath))
        return blockdev_mount_fiemap(midx, fpath, out, max);
    return -1;
}

/* fallocate PUNCH_HOLE (M1153): deallocate whole blocks in [offset,offset+len)
 * of an ext2-mount file, leaving a sparse hole. Only ext2 /diskN mounts support
 * it (real block allocation); other paths are unsupported (-1). */
long vfs_punch_hole(const char *path, uint64_t offset, uint64_t len) {
    char rb[VFS_PATH_MAX]; path = bind_resolve(path, rb, sizeof rb);
    if (!path) return -1;                            /* path too long to represent (M1937) */
    int midx; char fpath[VFS_PATH_MAX];
    if (mount_path(path, &midx, fpath, sizeof fpath)) {
        long r = blockdev_mount_punch(midx, fpath, offset, len);
        if (r >= 0) fsevents_record('w', path);
        return r;
    }
    return -1;
}

/* Extended attributes (M1182): user.* xattrs on ext2 /diskN files, stored
 * in-inode. Other paths (FAT32 boot, /tmp, synth) are unsupported (-1). */
long vfs_setxattr(const char *path, const char *name, const void *val, unsigned long vlen) {
    char rb[VFS_PATH_MAX]; path = bind_resolve(path, rb, sizeof rb);
    if (!path) return -1;                            /* path too long to represent (M1937) */
    int midx; char fpath[VFS_PATH_MAX];
    if (mount_path(path, &midx, fpath, sizeof fpath)) {
        long r = blockdev_mount_setxattr(midx, fpath, name, val, vlen);
        if (r >= 0) fsevents_record('w', path);
        return r;
    }
    return -1;
}
long vfs_getxattr(const char *path, const char *name, void *out, unsigned long max) {
    char rb[VFS_PATH_MAX]; path = bind_resolve(path, rb, sizeof rb);
    if (!path) return -1;                            /* path too long to represent (M1937) */
    int midx; char fpath[VFS_PATH_MAX];
    if (mount_path(path, &midx, fpath, sizeof fpath))
        return blockdev_mount_getxattr(midx, fpath, name, out, max);
    return -1;
}
long vfs_listxattr(const char *path, char *out, unsigned long max) {
    char rb[VFS_PATH_MAX]; path = bind_resolve(path, rb, sizeof rb);
    if (!path) return -1;                            /* path too long to represent (M1937) */
    int midx; char fpath[VFS_PATH_MAX];
    if (mount_path(path, &midx, fpath, sizeof fpath))
        return blockdev_mount_listxattr(midx, fpath, out, max);
    return -1;
}
long vfs_removexattr(const char *path, const char *name) {
    char rb[VFS_PATH_MAX]; path = bind_resolve(path, rb, sizeof rb);
    if (!path) return -1;                            /* path too long to represent (M1937) */
    int midx; char fpath[VFS_PATH_MAX];
    if (mount_path(path, &midx, fpath, sizeof fpath)) {
        long r = blockdev_mount_removexattr(midx, fpath, name);
        if (r >= 0) fsevents_record('w', path);
        return r;
    }
    return -1;
}

/* Copy a validated subpath into mount_sub (bounded). */
static void set_mount_sub(const char *sub) {
    int i = 0; while (sub[i] && i < (int)sizeof mount_sub - 1) { mount_sub[i] = sub[i]; i++; }
    mount_sub[i] = 0;
}

int vfs_chdir(const char *path) {
    char rb[VFS_PATH_MAX]; path = bind_resolve(path, rb, sizeof rb);     /* bind mounts (M1091) */
    if (!path) return -1;                            /* path too long to represent (M1937) */
    if (veq(path, "/proc")) { synth_cwd = 1; return 0; }   /* enter synthetic dirs */
    if (veq(path, "/dev"))  { synth_cwd = 2; return 0; }
    if (veq(path, "/tmp"))  { synth_cwd = 3; return 0; }   /* the RAM filesystem */
    if (ov_active && veq(path, "/over")) { synth_cwd = OVER_CWD; return 0; }   /* the overlay (M1143) */
    if (path[0] == '/') {                                  /* enter a mounted disk: /diskN[/sub...] */
        char comp[12]; int c = 0; const char *p = path + 1;
        while (*p && *p != '/' && c < 11) comp[c++] = *p++;
        comp[c] = 0;
        int idx = blockdev_mount_index(comp);
        if (idx >= 0) {
            const char *rest = (*p == '/') ? p + 1 : p;
            char sub[128]; mount_sub_join("", rest, sub, sizeof sub);
            if (sub[0] == 0 || blockdev_mount_isdir(idx, sub) == 1) {   /* root, or a real subdir (==1; isdir returns -1 for absent — M1213) */
                synth_cwd = 4 + idx; set_mount_sub(sub);
                return 0;
            }
            return -1;                                     /* /diskN/<not a directory> */
        }
    } else if (synth_cwd >= 4) {                           /* relative cd inside a mounted disk */
        if (mount_sub[0] == 0 && veq(path, "..")) {        /* ".." at the volume root: leave the mount */
            synth_cwd = 0;
            return (fs && fs->chdir) ? fs->chdir(path) : -1;
        }
        char sub[128]; mount_sub_join(mount_sub, path, sub, sizeof sub);
        if (sub[0] == 0 || blockdev_mount_isdir(synth_cwd - 4, sub) == 1) {   /* ==1: a real subdir (M1213) */
            set_mount_sub(sub);
            return 0;
        }
        return -1;                                         /* no such subdirectory */
    }
    synth_cwd = 0;                                          /* any other cd leaves them */
    return (fs && fs->chdir) ? fs->chdir(path) : -1;
}

long vfs_tree(char *out, int max) {
    return (fs && fs->tree) ? fs->tree(out, max) : -1;
}

void vfs_df(uint64_t *freeb, uint64_t *totalb) {
    if (fs && fs->df) fs->df(freeb, totalb);
    else { *freeb = 0; *totalb = 0; }
}

long vfs_find(const char *want, char *out, int max) {
    return (fs && fs->find) ? fs->find(want, out, max) : -1;
}

long vfs_rename(const char *path, const char *newname) {
    long r = (fs && fs->rename) ? fs->rename(path, newname) : -1;
    if (r >= 0) fsevents_record('r', path);
    return r;
}
