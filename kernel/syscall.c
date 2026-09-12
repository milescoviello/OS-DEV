/*
 * syscall.c — the kernel side of the system-call interface.
 *
 * Reached via `int 0x80` from ring 3. The interrupt stub saved the user's
 * registers into `struct registers`; we read the call number from rax and the
 * arguments from rdi/rsi/rdx, do the work, and store the result back in rax
 * (which the stub restores into the user's rax on the way out).
 */
#define __KERNEL__
#include "syscall.h"
#include "interrupts.h"
#include "console.h"
#include "app.h"
#include "bpf.h"
#include "module.h"
#include "strace.h"
#include "vfs.h"
#include "mqueue.h"
#include "sysvipc.h"
#include "sem.h"
#include "shm.h"
#include "unixsock.h"
#include "pty.h"
#include "flock.h"
#include "fanfs.h"
#include "iouring.h"
#include "fb.h"
#include "rtc.h"
#include "speaker.h"
#include "pmm.h"
#include "vmm.h"
#include "timer.h"
#include "smp.h"      /* smp_current_cpu for sched_getcpu (M1246) */
#include "task.h"
#include "io.h"
#include "net.h"
#include "tls.h"
#include "js.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "aes.h"
#include "string.h"
#include "kheap.h"
#include "inflate.h"
#include "zip.h"
#include "tar.h"
#include "audio.h"
#include "desktop.h"
#include "pci.h"
#include "blockdev.h"
#include "random.h"
#include "cas.h"
#include "acpi.h"
#include "hpet.h"   /* HPET high-res clocksource syscall (M1273) */
#include "vdso.h"   /* vdso_set_realtime/vdso_tick for clock_settime (M1280) */
#include <stdint.h>

/* Validate a user-supplied syscall pointer argument: the range [p, p+n) must
 * lie entirely within the calling app's own user (PTE_USER) pages. A syscall
 * runs in ring 0 with the app's CR3 active, where kernel memory is mapped and
 * writable — so without this an app could hand a kernel pointer to a handler
 * and have the kernel read or (worse) write its own memory. On failure the
 * handler returns -1 instead of touching the bogus address. `n` is the exact
 * number of bytes the handler will access through the pointer. */
static int ubuf(uint64_t p, uint64_t n) { return vmm_user_ok(p, n); }

/* Validate a user-supplied NUL-terminated string argument (filename, hostname,
 * URL, script): every byte up to the terminator must be in the app's own user
 * pages. Bounds the scan generously (16 MiB) — longer than any real arg, but
 * larger than a page-table walk needs to reject a non-terminated/forged string.
 * A handler that reads a string from the arg checks this before dereferencing. */
static int ustr(uint64_t p) { return vmm_user_str_ok(p, 16u << 20); }

static char g_hostname[64] = "osdev";   /* the system hostname (set/gethostname, uname.nodename) — M1237 */

/* *at resolver (M1251): build the effective path from (dirfd, path). Absolute
 * paths + AT_FDCWD pass through (the base ops resolve cwd-relative names); a real
 * dirfd joins the directory fd's stored path (via app_fd_path). 0/-1. */
static int at_resolve(long dirfd, const char *path, char *out, int max) {
    if (!path) return -1;
    if (path[0] == '/' || dirfd == AT_FDCWD) {
        int i = 0; for (; path[i] && i < max - 1; i++) out[i] = path[i]; out[i] = 0; return 0;
    }
    const char *dp = app_fd_path((int)dirfd);
    if (!dp) return -1;
    int p = 0; for (; dp[p] && p < max - 1; p++) out[p] = dp[p];
    if (p && out[p - 1] != '/' && p < max - 1) out[p++] = '/';
    for (int i = 0; path[i] && p < max - 1; i++) out[p++] = path[i];
    out[p] = 0; return 0;
}

/* access(2)'s core check (M1224), factored out so faccessat2 (M1556) can
 * share it after resolving its own dirfd-relative path. */
static int access_check(const char *path, int amode) {
    struct statx st;
    if (vfs_stat(path, &st) != 0) return -1;          /* doesn't exist */
    int ok = 1;
    if ((amode & R_OK) && !(st.stx_mode & 0444u)) ok = 0;
    if ((amode & W_OK) && !(st.stx_mode & 0222u)) ok = 0;
    if ((amode & X_OK) && !(st.stx_mode & 0111u)) ok = 0;
    return ok ? 0 : -1;
}

/* SYS_unzip helper: extract callback. Mangles each archived path to an 8.3 name
 * (basename, upper-cased, <=8 chars + '.' + <=3-char ext) and writes it via the
 * VFS, counting successes in ctx. */
struct unzip_ctx { int written; };
static void unzip_emit(void *vctx, const char *name, int namelen,
                       const uint8_t *data, int datalen) {
    struct unzip_ctx *c = (struct unzip_ctx *)vctx;
    int base = 0;
    for (int i = 0; i < namelen; i++) if (name[i] == '/') base = i + 1;   /* drop directories */
    int dot = -1;
    for (int i = base; i < namelen; i++) if (name[i] == '.') dot = i;
    int nend = (dot >= 0) ? dot : namelen;
    char fn[13]; int p = 0;
    for (int i = base; i < nend && p < 8; i++) {
        char ch = name[i]; if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 32);
        fn[p++] = ch;
    }
    if (dot >= 0) {
        fn[p++] = '.';
        for (int i = dot + 1; i < namelen && p < 12; i++) {
            char ch = name[i]; if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 32);
            fn[p++] = ch;
        }
    }
    fn[p] = 0;
    if (p == 0 || (p == 1 && fn[0] == '.')) return;          /* nothing usable */
    if (vfs_write(fn, data, (unsigned long)datalen) >= 0) c->written++;
}

static void put2(char *p, int v) { p[0] = '0' + (v / 10) % 10; p[1] = '0' + v % 10; }

static int sappend(char *d, int n, int max, const char *s) {
    while (*s && n + 1 < max) d[n++] = *s++;     /* n+1<max: safe even if max<=0 */
    return n;
}
static int snum(char *d, int n, int max, uint64_t v) {
    char t[21]; int i = 0;
    if (!v) t[i++] = '0';
    while (v) { t[i++] = '0' + v % 10; v /= 10; }
    while (i && n + 1 < max) d[n++] = t[--i];
    return n;
}

/* Minimal unsigned-int-to-decimal for the directory listing. */
static int u32_to_dec(uint32_t v, char *out) {
    char tmp[12];
    int i = 0, n = 0;
    if (v == 0) tmp[i++] = '0';
    while (v) { tmp[i++] = '0' + v % 10; v /= 10; }
    while (i) out[n++] = tmp[--i];
    return n;
}

/* Read an entire file into a freshly kmalloc'd buffer. The read API has no size
 * query, so grow the buffer (re-reading) until the read no longer fills it —
 * the whole file is returned, not a fixed-size prefix. Returns the length (and
 * sets *out, which the caller kfree's), or -1 on missing file / >=32MB / OOM. */
static long read_whole_file(const char *name, uint8_t **out) {
    size_t cap = 65536;
    uint8_t *buf = kmalloc(cap);
    long n = buf ? vfs_read(name, buf, cap) : -1;
    while (buf && n == (long)cap && cap < (32u << 20)) {   /* filled the buffer: file may be larger */
        cap <<= 1; kfree(buf); buf = kmalloc(cap);
        if (buf) n = vfs_read(name, buf, cap);
    }
    if (!buf) return -1;
    if (n < 0 || n == (long)cap) { kfree(buf); return -1; }   /* read error, or file >= 32MB */
    *out = buf;
    return n;
}

/* Append two lowercase hex digits of `v` (0..255). Used by the lspci formatter
 * for the bus/slot/func and vendor:device:class fields. */
static int shex2(char *d, int n, int max, uint8_t v) {
    static const char hx[] = "0123456789abcdef";
    if (n + 1 < max) d[n++] = hx[(v >> 4) & 0xF];
    if (n + 1 < max) d[n++] = hx[v & 0xF];
    return n;
}
static int shex4(char *d, int n, int max, uint16_t v) {
    n = shex2(d, n, max, (uint8_t)(v >> 8));
    n = shex2(d, n, max, (uint8_t)v);
    return n;
}

/* Human-readable name for one PCI device, for the lspci listing. We pick a name
 * by class (more useful than the vendor for "what is this"), refining a few
 * subclasses; unknown classes fall back to the vendor name, then to "device".
 * Just the common QEMU/PC hardware — anything unrecognized still shows as hex. */
static const char *pci_class_name(uint8_t cls, uint8_t sub) {
    switch (cls) {
    case 0x00: return "unclassified";
    case 0x01:                                  /* mass storage */
        switch (sub) {
        case 0x01: return "IDE controller";
        case 0x06: return "SATA controller (AHCI)";
        case 0x08: return "NVMe controller";
        default:   return "storage controller";
        }
    case 0x02: return "Ethernet controller";
    case 0x03: return "VGA display";
    case 0x04:                                  /* multimedia */
        return (sub == 0x01) ? "audio controller" : "multimedia controller";
    case 0x05: return "memory controller";
    case 0x06:                                  /* bridge */
        switch (sub) {
        case 0x00: return "host bridge";
        case 0x01: return "ISA bridge";
        case 0x04: return "PCI bridge";
        case 0x80: return "bridge";
        default:   return "bridge";
        }
    case 0x07: return "communication controller";
    case 0x0C:                                  /* serial bus */
        switch (sub) {
        case 0x03: return "USB controller";
        case 0x05: return "SMBus controller";
        default:   return "serial bus controller";
        }
    default:   return 0;                        /* let the caller try the vendor */
    }
}
static const char *pci_vendor_name(uint16_t v) {
    switch (v) {
    case 0x8086: return "Intel";
    case 0x10EC: return "Realtek";
    case 0x1AF4: return "Red Hat / virtio";
    case 0x1B36: return "Red Hat";
    case 0x1234: return "QEMU / Bochs";
    case 0x80EE: return "VirtualBox";
    case 0x1022: return "AMD";
    case 0x106B: return "Apple";
    default:     return 0;
    }
}

/* Format the full PCI device list into [buf,max) as lines of the form
 *   "BB:SS.F vendor:device class CC:SS  <name>\n"
 * one per device. Returns the byte count written (NUL-terminated if room).
 * Caller has already validated [buf,max) lies in the app's own pages. */
static int pci_format(char *b, int max) {
    pci_device_t devs[64];
    int total = pci_collect(devs, 64);
    int cnt = (total < 64) ? total : 64;            /* only `cnt` were stored */
    int p = 0;
    for (int i = 0; i < cnt; i++) {
        pci_device_t *d = &devs[i];
        p = shex2(b, p, max, d->bus);
        p = sappend(b, p, max, ":");
        p = shex2(b, p, max, d->slot);
        p = sappend(b, p, max, ".");
        if (p + 1 < max) b[p++] = (char)('0' + (d->func & 7));
        p = sappend(b, p, max, " ");
        p = shex4(b, p, max, d->vendor_id);
        p = sappend(b, p, max, ":");
        p = shex4(b, p, max, d->device_id);
        p = sappend(b, p, max, " class ");
        p = shex2(b, p, max, d->class_id);
        p = sappend(b, p, max, ":");
        p = shex2(b, p, max, d->subclass);
        p = sappend(b, p, max, "  ");
        const char *name = pci_class_name(d->class_id, d->subclass);
        if (!name) name = pci_vendor_name(d->vendor_id);
        if (!name) name = "device";
        p = sappend(b, p, max, name);
        /* tack the vendor on for recognized-class devices, so e.g. an Ethernet
         * line reads "Ethernet controller (Intel)" — handy for picking drivers */
        const char *vn = pci_vendor_name(d->vendor_id);
        if (vn && pci_class_name(d->class_id, d->subclass)) {
            p = sappend(b, p, max, " (");
            p = sappend(b, p, max, vn);
            p = sappend(b, p, max, ")");
        }
        p = sappend(b, p, max, "\n");
    }
    if (cnt == 0) p = sappend(b, p, max, "  (no PCI devices)\n");
    if (p < max) b[p] = 0;
    return p;
}

/* Which pledge() promise class a syscall needs (0 = always allowed even when
 * pledged: exit, sigreturn, getpid, and pledge itself). See app.h for the bits. */
static uint32_t syscall_class(uint64_t nr) {
    switch (nr) {
    case SYS_exit: case SYS_sigreturn: case SYS_getpid: case SYS_pledge:
    case SYS_gettid: case SYS_thread_exit: case SYS_set_tls: case SYS_set_robust_list: return 0;
    case SYS_write: case SYS_read: case SYS_pread: case SYS_pwrite: case SYS_readv: case SYS_writev: case SYS_preadv: case SYS_pwritev: case SYS_time: case SYS_sysinfo: case SYS_clear:
    case SYS_pollkey: case SYS_sleep: case SYS_uptime_ms: case SYS_sbrk: case SYS_getarg:
    case SYS_history: case SYS_setcolor: case SYS_caret: case SYS_signal: case SYS_sigaction: case SYS_sigqueue: case SYS_sigaltstack: case SYS_raise:
    case SYS_timer_create: case SYS_timer_settime: case SYS_timer_gettime: case SYS_timer_delete: case SYS_hpet: case SYS_ptsname: case SYS_oom: case SYS_clock_settime: case SYS_pidfd_getfd: case SYS_acpi: case SYS_aslr:
    case SYS_alarm: case SYS_getrusage: case SYS_setitimer: case SYS_getitimer:
    case SYS_mq_open: case SYS_mq_send: case SYS_mq_receive: case SYS_mq_getattr: case SYS_mq_setattr: case SYS_mq_unlink:
    case SYS_semget: case SYS_semop: case SYS_semctl:
    case SYS_sem_open: case SYS_sem_close: case SYS_sem_unlink: case SYS_sem_wait: case SYS_sem_trywait: case SYS_sem_post: case SYS_sem_getvalue:
    case SYS_msgget: case SYS_msgsnd: case SYS_msgrcv: case SYS_msgctl:
    case SYS_unix_listen: case SYS_unix_connect: case SYS_unix_accept:
    case SYS_unix_send: case SYS_unix_recv: case SYS_unix_close: case SYS_unix_wait_any: case SYS_socketpair:
    case SYS_unix_shutdown: case SYS_unix_unlisten:
    case SYS_sendfd: case SYS_recvfd:
    case SYS_pty_open: case SYS_pty_read: case SYS_pty_write: case SYS_pty_close: case SYS_pty_ctl:
    case SYS_pipe: case SYS_pipe2: case SYS_eventfd: case SYS_fdread: case SYS_fdwrite: case SYS_fdclose: case SYS_dup2: case SYS_dup:
    case SYS_mkfifo: case SYS_fifo_open: case SYS_lseek:
    case SYS_nice: case SYS_sched_setscheduler: case SYS_sched_get_priority_max: case SYS_sched_get_priority_min:
    case SYS_sched_getscheduler: case SYS_sched_getparam: case SYS_sched_rr_get_interval:
    case SYS_sched_setaffinity: case SYS_tcgetattr: case SYS_tcsetattr: case SYS_tcflush: case SYS_tcdrain:
    case SYS_getrlimit: case SYS_setrlimit:
    case SYS_getrandom: case SYS_getentropy: case SYS_setkbmode: case SYS_getkbevent: case SYS_mouse:
    case SYS_mouse_rel: case SYS_beep:
    case SYS_io_uring_enter:               /* the floor to call enter; ops gate themselves per-op */
        return PL_STDIO;
    case SYS_statx: case SYS_flock: case SYS_access: case SYS_faccessat2:
    case SYS_readfile: case SYS_list: case SYS_tree: case SYS_df: case SYS_find:
    case SYS_chdir: case SYS_fchdir: case SYS_lsblk: case SYS_lspci: case SYS_mounts:
    case SYS_sha1: case SYS_sha256: case SYS_sha512: case SYS_cas_fetch: case SYS_losetup:
    case SYS_fiemap: case SYS_getxattr: case SYS_listxattr: case SYS_fgetxattr: case SYS_flistxattr: case SYS_open:
    case SYS_readlink: case SYS_statfs: case SYS_getcwd: case SYS_openat: case SYS_fstatat: case SYS_readlinkat:
        return PL_RPATH;
    case SYS_writefile: case SYS_delete: case SYS_mkdir: case SYS_truncate: case SYS_crypt:
    case SYS_fsync: case SYS_fdatasync: case SYS_sync_file_range: case SYS_sync:
    case SYS_utimens: case SYS_futimens: case SYS_utimensat: case SYS_renameat2: case SYS_chmod: case SYS_fchmod:
    case SYS_chown: case SYS_fchown: case SYS_unlinkat: case SYS_mkdirat:
    case SYS_fchmodat: case SYS_fchownat: case SYS_symlinkat: case SYS_linkat:
    case SYS_gzip: case SYS_gunzip: case SYS_unzip: case SYS_untar:
    case SYS_savebmp: case SYS_screenshot: case SYS_setwall: case SYS_cas_store:
    case SYS_fallocate: case SYS_copy_file_range: case SYS_setxattr: case SYS_removexattr:
    case SYS_fsetxattr: case SYS_fremovexattr:
        return PL_WPATH;
    case SYS_ping: case SYS_resolve: case SYS_http: case SYS_https: case SYS_browse:
    case SYS_pinghost: case SYS_netinfo: case SYS_dhcp: case SYS_tftp: case SYS_sntp:
    case SYS_tcp_serve: case SYS_tcp_accept: case SYS_tcp_respond:
    case SYS_ws_open: case SYS_ws_exchange: case SYS_ws_serve:
        return PL_INET;
    case SYS_gfx_init: case SYS_gfx_blit: case SYS_pcm: case SYS_playwav:
    case SYS_pcm_stream: case SYS_pcm_avail: case SYS_playbg: case SYS_audiostop:
    case SYS_clip_get: case SYS_clip_set: case SYS_font: case SYS_loadimg:
        return PL_GFX;
    case SYS_process_vm_read: case SYS_process_vm_write: case SYS_ptrace: case SYS_process_madvise:
    case SYS_setpgid: case SYS_getpgid: case SYS_getsid: case SYS_setsid: case SYS_tcsetpgrp: case SYS_tcgetpgrp: case SYS_killpg:
    case SYS_spawn: case SYS_fork: case SYS_waitpid: case SYS_waitid: case SYS_exec: case SYS_kill: case SYS_ps: case SYS_apps: case SYS_js:
        return PL_PROC;
    case SYS_clone: case SYS_join:          /* threads sharing THIS address space, not a new process (M1533) */
        return PL_THREAD;
    case SYS_mmap: case SYS_munmap: case SYS_mremap: case SYS_madvise: case SYS_swapout: case SYS_shm_open: case SYS_shm_unlink: case SYS_futex:
    case SYS_mseal: case SYS_uffd_register: case SYS_uffd_read: case SYS_uffd_copy: case SYS_mmap_file: case SYS_msync:
    case SYS_mincore: case SYS_mlock: case SYS_munlock: case SYS_mmap_huge: case SYS_mlockall: case SYS_munlockall:
    case SYS_shmget: case SYS_shmat: case SYS_shmdt: case SYS_shmctl:
        return PL_VM;
    case SYS_poweroff: case SYS_reboot:
        return PL_POWER;
    default:
        return 0;        /* unmapped -> always allowed (never brick on an unknown call) */
    }
}

/* Human-readable syscall names for the strace channel (M1084). Designated
 * initialisers keep it in sync with syscall.h by number. */
static const char *syscall_name(uint64_t n) {
    static const char *const nm[] = {
        [SYS_write]="write",[SYS_exit]="exit",[SYS_getpid]="getpid",[SYS_read]="read",
        [SYS_list]="list",[SYS_readfile]="readfile",[SYS_time]="time",[SYS_beep]="beep",
        [SYS_sysinfo]="sysinfo",[SYS_clear]="clear",[SYS_reboot]="reboot",[SYS_writefile]="writefile",
        [SYS_ping]="ping",[SYS_resolve]="resolve",[SYS_delete]="delete",[SYS_spawn]="spawn",
        [SYS_sleep]="sleep",[SYS_http]="http",[SYS_browse]="browse",[SYS_mkdir]="mkdir",
        [SYS_chdir]="chdir",[SYS_fchdir]="fchdir",[SYS_tree]="tree",[SYS_ps]="ps",[SYS_font]="font",[SYS_pollkey]="pollkey",
        [SYS_df]="df",[SYS_find]="find",[SYS_sha256]="sha256",[SYS_crypt]="crypt",
        [SYS_history]="history",[SYS_https]="https",[SYS_js]="js",[SYS_setcolor]="setcolor",
        [SYS_pinghost]="pinghost",[SYS_netinfo]="netinfo",[SYS_apps]="apps",[SYS_sha512]="sha512",
        [SYS_screenshot]="screenshot",[SYS_gunzip]="gunzip",[SYS_gzip]="gzip",[SYS_unzip]="unzip",
        [SYS_untar]="untar",[SYS_sbrk]="sbrk",[SYS_uptime_ms]="uptime_ms",[SYS_gfx_init]="gfx_init",
        [SYS_gfx_blit]="gfx_blit",[SYS_setkbmode]="setkbmode",[SYS_getkbevent]="getkbevent",[SYS_pcm]="pcm",
        [SYS_playwav]="playwav",[SYS_pcm_stream]="pcm_stream",[SYS_pcm_avail]="pcm_avail",[SYS_mouse]="mouse",
        [SYS_playbg]="playbg",[SYS_audiostop]="audiostop",[SYS_mouse_rel]="mouse_rel",[SYS_caret]="caret",
        [SYS_clip_get]="clip_get",[SYS_clip_set]="clip_set",[SYS_getarg]="getarg",[SYS_savebmp]="savebmp",
        [SYS_setwall]="setwall",[SYS_loadimg]="loadimg",[SYS_lspci]="lspci",[SYS_lsblk]="lsblk",[SYS_poweroff]="poweroff",
        [SYS_kill]="kill",[SYS_mounts]="mounts",[SYS_mmap]="mmap",[SYS_munmap]="munmap",
        [SYS_signal]="signal",[SYS_raise]="raise",[SYS_sigreturn]="sigreturn",[SYS_getrandom]="getrandom",
        [SYS_pledge]="pledge",[SYS_unveil]="unveil",[SYS_symlink]="symlink",
        [SYS_jail]="jail",[SYS_ringbuf]="ringbuf",[SYS_mprotect]="mprotect",[SYS_bind]="bind",
        [SYS_dhcp]="dhcp",[SYS_cas_store]="cas_store",[SYS_cas_fetch]="cas_fetch",
        [SYS_tftp]="tftp",[SYS_madvise]="madvise",[SYS_alarm]="alarm",[SYS_setitimer]="setitimer",[SYS_getitimer]="getitimer",[SYS_sntp]="sntp",
        [SYS_fsync]="fsync",[SYS_fdatasync]="fdatasync",[SYS_sync_file_range]="sync_file_range",[SYS_sync]="sync",[SYS_epoll_pwait]="epoll_pwait",[SYS_inotify_rm_watch]="inotify_rm_watch",
        [SYS_fsetxattr]="fsetxattr",[SYS_fgetxattr]="fgetxattr",[SYS_flistxattr]="flistxattr",[SYS_fremovexattr]="fremovexattr",
        [SYS_swapout]="swapout",[SYS_losetup]="losetup",[SYS_shm_open]="shm_open",[SYS_shm_unlink]="shm_unlink",[SYS_futex]="futex",
        [SYS_fork]="fork",[SYS_waitpid]="waitpid",[SYS_exec]="exec",[SYS_unshare]="unshare",
        [SYS_singlestep]="singlestep",
        [SYS_seccomp]="seccomp",[SYS_seccomp_wait]="seccomp_wait",[SYS_seccomp_reply]="seccomp_reply",
        [SYS_seccomp_filter]="seccomp_filter",
        [SYS_fswait]="fswait",[SYS_signalfd]="signalfd",
        [SYS_fanotify_serve]="fanotify_serve",[SYS_fanotify_wait]="fanotify_wait",[SYS_fanotify_provide]="fanotify_provide",
        [SYS_io_uring_enter]="io_uring_enter",[SYS_mseal]="mseal",[SYS_tcp_serve]="tcp_serve",[SYS_tcp_accept]="tcp_accept",[SYS_tcp_respond]="tcp_respond",
        [SYS_uffd_register]="uffd_register",[SYS_uffd_read]="uffd_read",[SYS_uffd_copy]="uffd_copy",
        [SYS_mmap_file]="mmap_file",[SYS_msync]="msync",[SYS_fchmodat]="fchmodat",[SYS_fchownat]="fchownat",[SYS_utimensat]="utimensat",
        [SYS_symlinkat]="symlinkat",[SYS_readlinkat]="readlinkat",[SYS_linkat]="linkat",
        [SYS_setsockopt]="setsockopt",[SYS_getsockopt]="getsockopt",[SYS_getsockname]="getsockname",[SYS_getpeername]="getpeername",[SYS_sigsuspend]="sigsuspend",[SYS_pause]="pause",[SYS_process_madvise]="process_madvise",
        [SYS_faccessat2]="faccessat2",[SYS_sched_setaffinity]="sched_setaffinity",[SYS_sched_getaffinity]="sched_getaffinity",[SYS_clone]="clone",[SYS_gettid]="gettid",[SYS_thread_exit]="thread_exit",[SYS_join]="join",[SYS_set_tls]="set_tls",[SYS_set_robust_list]="set_robust_list",[SYS_overlay]="overlay",
        [SYS_mincore]="mincore",[SYS_mlock]="mlock",[SYS_munlock]="munlock",[SYS_getrusage]="getrusage",
        [SYS_fiemap]="fiemap",[SYS_fallocate]="fallocate",
        [SYS_mq_open]="mq_open",[SYS_mq_send]="mq_send",[SYS_mq_receive]="mq_receive",[SYS_mq_getattr]="mq_getattr",[SYS_mq_setattr]="mq_setattr",[SYS_mq_unlink]="mq_unlink",
        [SYS_mmap_huge]="mmap_huge",
        [SYS_semget]="semget",[SYS_semop]="semop",[SYS_semctl]="semctl",
        [SYS_sem_open]="sem_open",[SYS_sem_close]="sem_close",[SYS_sem_unlink]="sem_unlink",
        [SYS_sem_wait]="sem_wait",[SYS_sem_trywait]="sem_trywait",[SYS_sem_post]="sem_post",[SYS_sem_getvalue]="sem_getvalue",
        [SYS_msgget]="msgget",[SYS_msgsnd]="msgsnd",[SYS_msgrcv]="msgrcv",[SYS_msgctl]="msgctl",
        [SYS_shmget]="shmget",[SYS_shmat]="shmat",[SYS_shmdt]="shmdt",[SYS_shmctl]="shmctl",
        [SYS_process_vm_read]="process_vm_read",[SYS_process_vm_write]="process_vm_write",
        [SYS_unix_listen]="unix_listen",[SYS_unix_connect]="unix_connect",[SYS_unix_accept]="unix_accept",
        [SYS_unix_send]="unix_send",[SYS_unix_recv]="unix_recv",[SYS_unix_close]="unix_close",[SYS_socketpair]="socketpair",
        [SYS_unix_wait_any]="unix_wait_any",[SYS_nice]="nice",[SYS_sched_setscheduler]="sched_setscheduler",
        [SYS_sched_get_priority_max]="sched_get_priority_max",[SYS_sched_get_priority_min]="sched_get_priority_min",
        [SYS_sched_getscheduler]="sched_getscheduler",[SYS_sched_getparam]="sched_getparam",[SYS_sched_rr_get_interval]="sched_rr_get_interval",
        [SYS_statx]="statx",[SYS_tcgetattr]="tcgetattr",[SYS_tcsetattr]="tcsetattr",[SYS_tcflush]="tcflush",[SYS_tcdrain]="tcdrain",
        [SYS_setpgid]="setpgid",[SYS_getpgid]="getpgid",[SYS_getsid]="getsid",[SYS_setsid]="setsid",[SYS_tcsetpgrp]="tcsetpgrp",[SYS_tcgetpgrp]="tcgetpgrp",[SYS_killpg]="killpg",
        [SYS_flock]="flock",[SYS_mremap]="mremap",[SYS_copy_file_range]="copy_file_range",
        [SYS_pty_open]="pty_open",[SYS_pty_read]="pty_read",[SYS_pty_write]="pty_write",
        [SYS_pty_close]="pty_close",[SYS_pty_ctl]="pty_ctl",
        [SYS_pipe]="pipe",[SYS_fdread]="fdread",[SYS_fdwrite]="fdwrite",[SYS_fdclose]="fdclose",[SYS_dup2]="dup2",[SYS_dup]="dup",
        [SYS_mkfifo]="mkfifo",[SYS_fifo_open]="fifo_open",
        [SYS_open]="open",[SYS_lseek]="lseek",[SYS_pread]="pread",[SYS_pwrite]="pwrite",[SYS_ppoll]="ppoll",[SYS_select]="select",[SYS_readv]="readv",[SYS_writev]="writev",[SYS_preadv]="preadv",[SYS_pwritev]="pwritev",
        [SYS_getrlimit]="getrlimit",[SYS_setrlimit]="setrlimit",
    };
    return (n < sizeof nm / sizeof nm[0] && nm[n]) ? nm[n] : "?";
}

/* /proc/syscalls (M1203): render the eBPF tracepoint histogram (the bpf_map a
 * loaded count-by-number probe fills, M1202) with syscall NAMES — a syscount /
 * bpftrace-style "which syscalls are firing" view. Empty until `syscount` loads
 * the probe. */
int syscall_histogram_format(char *b, int max) {
    int p = 0;
    for (unsigned i = 0; i < BPF_MAP_N && p < max - 40; i++) {
        uint64_t c = bpf_map_get(i);
        if (!c) continue;
        const char *nm = syscall_name(i);
        int j = 0;
        while (nm[j] && p < max - 1) b[p++] = nm[j++];
        while (j++ < 18 && p < max - 1) b[p++] = ' ';      /* pad to a column */
        char t[20]; int k = 0; uint64_t v = c;
        if (!v) t[k++] = '0';
        while (v) { t[k++] = (char)('0' + v % 10); v /= 10; }
        while (k && p < max - 1) b[p++] = t[--k];
        if (p < max - 1) b[p++] = '\n';
    }
    if (p == 0) {
        const char *m = "(no syscall trace loaded -- run `syscount` to start counting)\n";
        for (int z = 0; m[z] && p < max - 1; z++) b[p++] = m[z];
    }
    if (p < max) b[p] = 0;
    return p;
}

void syscall_dispatch(struct registers *r) {
    app_t *self = app_current();
    vfs_sync_cwd();                     /* make the live cwd this process's own (M1144) */

    /* strace (M1084): snapshot the call BEFORE the switch (args, in case a handler
     * reuses the register slots); emitted after, with the result, if traced. */
    int traced = app_is_traced(self);
    uint64_t tr_nr = r->rax, tr_a = r->rdi, tr_b = r->rsi, tr_c = r->rdx;

    /* eBPF syscall tracepoint (M1202): if a trace program is loaded, run it on
     * this syscall enter — it counts by number into the BPF map (read via
     * /proc/bpf or SYS_bpf_map_get). dtrace/bpftrace-style, on the verified VM. */
    if (bpf_trace_loaded()) {
        struct bpf_ctx tctx = { (uint32_t)r->rax, (uint32_t)r->rdi,
                                (uint32_t)r->rsi, (uint32_t)r->rdx, 0 };
        bpf_trace_run(&tctx);
    }

    /* pledge() enforcement: a pledged app that calls a syscall outside its kept
     * classes is killed on the spot (like OpenBSD's SIGABRT). Unpledged apps —
     * every existing program — are unaffected. */
    if (self && app_is_pledged(self)) {
        uint32_t need = syscall_class(r->rax);
        if (need && !(app_promises(self) & need)) {
            kprintf("[pledge] pid %d (%s) called a syscall outside its pledge (sys %lu) -- killing\n",
                    app_sys_getpid(), app_title(self), (unsigned long)r->rax);
            app_sys_exit(-1);               /* terminate the violating app; does not return */
        }
    }

    /* seccomp-notify (M1124): a supervised process traps masked syscalls to its
     * supervisor, which can deny or emulate them. Unsupervised apps unaffected. */
    if (self && app_seccomp_traps(self, r->rax)) {
        int run_real = 1;
        long ret = app_seccomp_notify(self, r->rax, r->rdi, r->rsi, r->rdx, &run_real);
        if (!run_real) { r->rax = (uint64_t)ret; goto sc_done; }   /* denied/emulated: skip the real syscall */
    }

    /* seccomp-BPF self-filter (M1190, M1192): a process installs a bpf.c program
     * that vets its own syscalls. Verdict 0 => DENY (-1, skip the real syscall);
     * 2 => KILL (terminate, like real seccomp's hard sandbox); else ALLOW.
     * Unfiltered apps (no program) take one cheap branch and are unaffected. */
    if (self && app_seccomp_filter_active(self)) {
        long verdict = app_seccomp_filter_check(self, r->rax, r->rdi, r->rsi, r->rdx);
        if (verdict == 2) {                 /* SECCOMP_RET_KILL */
            kprintf("[seccomp] pid %d (%s) hit a KILL filter (sys %lu) -- terminating\n",
                    app_sys_getpid(), app_title(self), (unsigned long)r->rax);
            app_sys_exit(-1);               /* does not return */
        }
        if (verdict == 0) { r->rax = (uint64_t)-1; goto sc_done; }   /* SECCOMP_RET_DENY */
    }

    switch (r->rax) {
    case SYS_write:
        /* fd 1/2 -> the app's window grid by default; but if the fd has been
         * redirected to a pipe (dup2, M1187) route the bytes there (stdio over
         * fds, M1191). An app that never redirects hits the grid as before. */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        if (app_fd_is_redirected(self, (int)r->rdi)) {
            r->rax = (uint64_t)(int64_t)app_fd_write((int)r->rdi, (const void *)r->rsi, r->rdx);
        } else {
            app_sys_write((const char *)r->rsi, (unsigned)r->rdx);
            r->rax = r->rdx;
        }
        break;
    case SYS_read:
        /* fd 0 <- the app's window input (blocks until Enter) by default; a
         * redirected fd 0 reads from its pipe instead (M1191). */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        if (app_fd_is_redirected(self, (int)r->rdi)) {
            r->rax = (uint64_t)(int64_t)app_fd_read((int)r->rdi, (void *)r->rsi, r->rdx);
        } else {
            r->rax = (uint64_t)app_sys_read((char *)r->rsi, (unsigned)r->rdx);
        }
        break;
    case SYS_getpid:
        r->rax = (uint64_t)app_sys_getpid();
        break;
    case SYS_fork:                         /* copy-on-write fork: child gets 0, parent gets the child pid (M1116) */
        r->rax = (uint64_t)app_fork(r);
        break;
    case SYS_waitpid: {                    /* block until a child exits; collect its status (M1117) */
        int *st = (int *)r->rsi;
        if (st && !ubuf(r->rsi, sizeof(int))) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)app_waitpid((int)r->rdi, st);
        break;
    }
    case SYS_exec: {                       /* replace this process's image in place (M1121) */
        const char *nm = (const char *)r->rdi, *ag = (const char *)r->rsi;
        if (!ustr(r->rdi) || (ag && !ustr(r->rsi))) { r->rax = (uint64_t)-1; break; }
        if (app_exec(r, nm, ag) < 0) r->rax = (uint64_t)-1;   /* only reached on failure; success rewrote r */
        break;
    }
    case SYS_list: {
        /* Format the root directory into the user buffer: "name  size\n". */
        char       *buf = (char *)r->rsi;
        uint64_t    max = r->rdx;
        if (max == 0 || !ubuf((uint64_t)buf, max)) { r->rax = (uint64_t)-1; break; }  /* max==0 would underflow `max-1` below */
        static vfs_dirent ents[256];   /* static (not stack): 256*sizeof too big for the 16KB kernel stack */
        int         count = vfs_list(ents, 256);
        uint64_t    n = 0;
        for (int i = 0; i < count; i++) {
            if (n >= max - 1) break;
            for (int j = 0; j < 63 && ents[i].name[j] && n < max - 1; j++)   /* j<63: defensive name bound */
                buf[n++] = ents[i].name[j];
            if (n < max - 1) buf[n++] = ' ';
            char num[12];
            int  ln = u32_to_dec(ents[i].size, num);
            for (int k = 0; k < ln && n < max - 1; k++) buf[n++] = num[k];
            if (ents[i].date && n + 18 < max) {       /* "  YYYY-MM-DD HH:MM" for timestamped files */
                int yr = (ents[i].date >> 9) + 1980, mo = (ents[i].date >> 5) & 15, dy = ents[i].date & 31;
                int hh = (ents[i].time >> 11) & 31,  mi = (ents[i].time >> 5) & 63;
                buf[n++] = ' '; buf[n++] = ' ';
                buf[n++] = '0'+(yr/1000)%10; buf[n++]='0'+(yr/100)%10; buf[n++]='0'+(yr/10)%10; buf[n++]='0'+yr%10;
                buf[n++] = '-'; buf[n++]='0'+(mo/10)%10; buf[n++]='0'+mo%10;
                buf[n++] = '-'; buf[n++]='0'+(dy/10)%10; buf[n++]='0'+dy%10;
                buf[n++] = ' '; buf[n++]='0'+(hh/10)%10; buf[n++]='0'+hh%10;
                buf[n++] = ':'; buf[n++]='0'+(mi/10)%10; buf[n++]='0'+mi%10;
            }
            if (n < max - 1) buf[n++] = '\n';
        }
        buf[n] = '\0';
        r->rax = n;
        break;
    }
    case SYS_readfile: {
        const char *name = (const char *)r->rdi;
        void       *buf  = (void *)r->rsi;
        uint64_t    max  = r->rdx;
        if (!ustr(r->rdi) || !ubuf((uint64_t)buf, max)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, name, 0)) { r->rax = (uint64_t)-1; break; }   /* hidden by unveil() */
        r->rax = (uint64_t)vfs_read(name, buf, max);
        break;
    }
    case SYS_time: {
        /* write "YYYY-MM-DD HH:MM:SS\n" into the user buffer */
        char *buf = (char *)r->rsi;
        if (r->rdx >= 21) {
            if (!ubuf(r->rsi, 21)) { r->rax = (uint64_t)-1; break; }
            struct rtc_time tm; rtc_now(&tm);
            put2(buf+0, tm.year/100); put2(buf+2, tm.year%100); buf[4]='-';
            put2(buf+5, tm.month); buf[7]='-'; put2(buf+8, tm.day); buf[10]=' ';
            put2(buf+11, tm.hour); buf[13]=':'; put2(buf+14, tm.min);
            buf[16]=':'; put2(buf+17, tm.sec); buf[19]='\n'; buf[20]=0;
            r->rax = 20;
        } else r->rax = 0;
        break;
    }
    case SYS_beep:
        __asm__ volatile("sti");           /* beep() blocks on the timer; need IF=1 */
        beep((uint32_t)r->rdi, (uint32_t)r->rsi);
        break;
    case SYS_sysinfo: {
        char *b = (char *)r->rsi; int max = (int)r->rdx, n = 0;
        if (max <= 0 || !ubuf(r->rsi, (uint64_t)max)) { r->rax = (uint64_t)-1; break; }
        n = sappend(b, n, max, "RAM:    ");
        n = snum(b, n, max, pmm_free_bytes() / (1024*1024));
        n = sappend(b, n, max, " MiB free / ");
        n = snum(b, n, max, pmm_total_bytes() / (1024*1024));
        n = sappend(b, n, max, " MiB\nuptime: ");
        n = snum(b, n, max, timer_ticks() / 100);
        n = sappend(b, n, max, " s\ntasks:  ");
        n = snum(b, n, max, (uint64_t)task_count());
        n = sappend(b, n, max, "\n");
        b[n] = 0; r->rax = (uint64_t)n;
        break;
    }
    case SYS_clear:
        app_sys_clear();
        break;
    case SYS_setcolor:
        app_setcolor((int)r->rdi);
        break;
    case SYS_clip_get:
        if (!ubuf(r->rdi, r->rsi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)clip_get((char *)r->rdi, (int)r->rsi);
        break;
    case SYS_clip_set:
        if (!ubuf(r->rdi, r->rsi)) { r->rax = (uint64_t)-1; break; }
        clip_set((const char *)r->rdi, (int)r->rsi);
        break;
    case SYS_getarg:
        if (!ubuf(r->rdi, r->rsi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_getarg((char *)r->rdi, (int)r->rsi);
        break;
    case SYS_writefile:
        if (!ustr(r->rdi) || !ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, (const char *)r->rdi, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)vfs_write((const char *)r->rdi, (const void *)r->rsi, r->rdx);
        break;
    case SYS_delete:
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, (const char *)r->rdi, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)vfs_remove((const char *)r->rdi);
        break;
    case SYS_spawn: {
        const char *nm = (const char *)r->rdi;
        const char *arg = (const char *)r->rsi;    /* optional launch arg (e.g. a filename for the editor) */
        if (!ustr(r->rdi) || (arg && !ustr(r->rsi))) { r->rax = (uint64_t)-1; break; }
        int rc = (arg && arg[0]) ? app_spawn_named_arg(nm, arg) : app_spawn_named(nm);  /* a built-in program? */
        if (rc < 0) rc = app_spawn_from_file(nm);  /* else try loading it from disk */
        r->rax = (uint64_t)(int64_t)rc;
        break;
    }
    case SYS_sleep:
        app_kill_check();                  /* WM close-request: a paced game exits instead of sleeping on */
        __asm__ volatile("sti");           /* timer drives the wait */
        timer_wait(r->rdi / 10 + 1);
        break;
    case SYS_sched_yield:                  /* voluntarily give up the CPU (M1234) */
        __asm__ volatile("sti");
        task_yield();
        r->rax = 0;
        break;
    case SYS_sched_getcpu:                 /* () -> APIC id of the CPU running this call (M1246) */
        r->rax = (uint64_t)(int64_t)smp_current_cpu();
        break;
    case SYS_sched_setaffinity:            /* (mask) -> restrict the calling task to a CPU subset; 0/-1 (M1557) */
        r->rax = (uint64_t)(int64_t)task_set_affinity((uint32_t)r->rdi);
        break;
    case SYS_sched_getaffinity:            /* () -> the calling task's current affinity mask (M1557) */
        r->rax = (uint64_t)task_get_affinity();
        break;
    case SYS_nanosleep: {                  /* (sec, nsec) -> sleep, rounded to the 100Hz tick (M1234) */
        app_kill_check();
        __asm__ volatile("sti");
        uint64_t ms = (uint64_t)r->rdi * 1000 + (uint64_t)r->rsi / 1000000;
        if (ms || r->rdi || r->rsi) timer_wait(ms / 10 + 1);   /* >0 request -> at least one 10ms tick */
        else task_yield();                                     /* {0,0} -> just yield */
        r->rax = 0;
        break;
    }
    case SYS_clock_nanosleep: {            /* (clockid, flags, sec, nsec) -> sleep; TIMER_ABSTIME = absolute deadline (M1257) */
        app_kill_check();
        __asm__ volatile("sti");
        int clockid = (int)r->rdi, flags = (int)r->rsi;
        uint64_t req_ms = (uint64_t)r->rdx * 1000 + (uint64_t)r->r10 / 1000000;
        uint64_t sleep_ms;
        if (flags & TIMER_ABSTIME) {
            /* Deadline is on the named clock: monotonic = uptime ms, realtime =
             * wall epoch (second-resolution from the RTC). A deadline already in
             * the past returns immediately (sleep 0). */
            uint64_t now_ms = (clockid == CLOCK_REALTIME) ? (uint64_t)rtc_unix() * 1000 : timer_ms();
            sleep_ms = (req_ms > now_ms) ? req_ms - now_ms : 0;
        } else {
            sleep_ms = req_ms;                                 /* relative: like nanosleep */
        }
        if (sleep_ms) timer_wait(sleep_ms / 10 + 1);           /* >0 -> at least one 10ms tick */
        else task_yield();
        r->rax = 0;
        break;
    }
    case SYS_clock_getres:                 /* (clockid) -> resolution in ns; every clock ticks at the 100Hz timer (M1257) */
        (void)r->rdi;
        r->rax = 10000000;                 /* 10,000,000 ns = 10 ms (the 100Hz tick) */
        break;
    case SYS_ping:
        __asm__ volatile("sti");           /* needs the timer for its timeout */
        r->rax = (uint64_t)(int64_t)net_ping_gateway();
        break;
    case SYS_pinghost:
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        __asm__ volatile("sti");           /* DNS + ICMP both need the timer running */
        r->rax = (uint64_t)(int64_t)net_ping_host((const char *)r->rdi);
        break;
    case SYS_dhcp:
        __asm__ volatile("sti");           /* the DORA handshake needs the timer for its timeouts */
        r->rax = (uint64_t)(int64_t)net_dhcp();
        break;
    case SYS_sntp:
        __asm__ volatile("sti");           /* the query waits for a reply (needs the timer) */
        r->rax = (uint64_t)(int64_t)net_sntp();
        break;
    case SYS_udp_send: {                   /* (dstip[4], (dport<<16)|sport, payload, plen) -> 0/-1 (M1258) */
        if (!ubuf(r->rdi, 4) || (r->r10 && !ubuf(r->rdx, r->r10))) { r->rax = (uint64_t)-1; break; }
        uint16_t dport = (uint16_t)(r->rsi >> 16), sport = (uint16_t)(r->rsi & 0xFFFF);
        __asm__ volatile("sti");           /* ARP + TX need the timer/IRQs */
        r->rax = (uint64_t)(int64_t)net_udp_send((const uint8_t *)r->rdi, dport, sport,
                                                 (const void *)r->rdx, (int)r->r10);
        break;
    }
    case SYS_udp_recv: {                   /* (sport, buf, max, from{u8 ip[4];u16 port}|0) -> bytes/-1 (M1258) */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        if (r->r10 && !ubuf(r->r10, 6)) { r->rax = (uint64_t)-1; break; }
        uint8_t sip[4] = {0,0,0,0}; uint16_t sp = 0;
        __asm__ volatile("sti");           /* polling the RX ring needs the timer */
        int n = net_udp_recv((uint16_t)r->rdi, (void *)r->rsi, (int)r->rdx, sip, &sp, 2000);
        if (n >= 0 && r->r10) {            /* fill the caller's {ip[4], port} sender struct */
            uint8_t *f = (uint8_t *)r->r10;
            f[0] = sip[0]; f[1] = sip[1]; f[2] = sip[2]; f[3] = sip[3];
            f[4] = (uint8_t)(sp & 0xFF); f[5] = (uint8_t)(sp >> 8);
        }
        r->rax = (uint64_t)(int64_t)n;
        break;
    }
    case SYS_raw_send:                     /* (frame, len) -> send a raw Ethernet frame; 0/-1 (M1259) */
        if (!ubuf(r->rdi, r->rsi)) { r->rax = (uint64_t)-1; break; }
        __asm__ volatile("sti");
        r->rax = (uint64_t)(int64_t)net_raw_send((const void *)r->rdi, (int)r->rsi);
        break;
    case SYS_raw_recv:                     /* (buf, max) -> next Ethernet frame, 2s timeout; length/-1 (M1259) */
        if (!ubuf(r->rdi, r->rsi)) { r->rax = (uint64_t)-1; break; }
        __asm__ volatile("sti");           /* polling the RX ring needs the timer */
        r->rax = (uint64_t)(int64_t)net_raw_recv((void *)r->rdi, (int)r->rsi, 2000);
        break;
    case SYS_insmod:                       /* () -> load the built-in .ko (relocate+resolve+run); retval/-err (M1261) */
        r->rax = (uint64_t)(int64_t)module_load_builtin();
        break;
    case SYS_insmod_path: {                /* (path) -> load a .ko module from a real file (M1595) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        uint8_t *buf; long n = read_whole_file((const char *)r->rdi, &buf);
        if (n < 0) { r->rax = (uint64_t)-1; break; }
        const char *p = (const char *)r->rdi, *base = p;
        for (const char *q = p; *q; q++) if (*q == '/') base = q + 1;
        char name[32]; int k = 0;
        while (base[k] && k < 31) { name[k] = base[k]; k++; }
        if (k >= 3 && name[k - 3] == '.' && (name[k - 2] == 'k' || name[k - 2] == 'K') && (name[k - 1] == 'o' || name[k - 1] == 'O')) k -= 3;  /* strip .ko/.KO */
        name[k] = 0;
        r->rax = (uint64_t)(int64_t)module_load_named(buf, (unsigned long)n, name);
        kfree(buf);
        break;
    }
    case SYS_sendfd:                       /* (ep, fd) -> SCM_RIGHTS: pass an fd over an AF_UNIX endpoint (M1265) */
        r->rax = (uint64_t)(int64_t)app_scm_send((int)r->rdi, (int)r->rsi);
        break;
    case SYS_recvfd:                       /* (ep) -> SCM_RIGHTS: install a passed fd; new fd/-1 (M1265) */
        r->rax = (uint64_t)(int64_t)app_scm_recv((int)r->rdi);
        break;
    case SYS_inotify_init:                 /* () -> a pollable filesystem-watch fd (M1266) */
        r->rax = (uint64_t)(int64_t)app_inotify_init();
        break;
    case SYS_inotify_add_watch:            /* (fd, path, mask) -> register a watch; wd/-1 (M1266) */
        if (!ustr(r->rsi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_inotify_add((int)r->rdi, (const char *)r->rsi, (unsigned int)r->rdx);
        break;
    case SYS_inotify_rm_watch:             /* (fd, wd) -> unregister a watch; 0/-1 (M1568) */
        r->rax = (uint64_t)(int64_t)app_inotify_rm((int)r->rdi, (int)r->rsi);
        break;
    case SYS_socket:                       /* (domain, type) -> AF_INET datagram socket fd (M1267) */
        r->rax = (uint64_t)(int64_t)app_socket((int)r->rdi, (int)r->rsi);
        break;
    case SYS_sock_bind:                    /* (fd, port) -> bind a datagram socket (M1267) */
        r->rax = (uint64_t)(int64_t)app_sock_bind((int)r->rdi, (int)r->rsi);
        break;
    case SYS_sendto: {                     /* (fd, addr{u8 ip[4];u16 port}, buf, len) -> bytes/-1 (M1267) */
        if (!ubuf(r->rsi, 6) || (r->r10 && !ubuf(r->rdx, r->r10))) { r->rax = (uint64_t)-1; break; }
        const uint8_t *ad = (const uint8_t *)r->rsi;
        uint8_t ip[4] = { ad[0], ad[1], ad[2], ad[3] };
        uint16_t port = (uint16_t)(ad[4] | (ad[5] << 8));
        __asm__ volatile("sti");
        r->rax = (uint64_t)(int64_t)app_sendto((int)r->rdi, ip, port, (const void *)r->rdx, (int)r->r10);
        break;
    }
    case SYS_recvfrom: {                   /* (fd, buf, max, from{u8 ip[4];u16 port}|0) -> bytes/-1 (M1267) */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        if (r->r10 && !ubuf(r->r10, 6)) { r->rax = (uint64_t)-1; break; }
        uint8_t sip[4] = {0,0,0,0}; uint16_t sp = 0;
        __asm__ volatile("sti");
        long n = app_recvfrom((int)r->rdi, (void *)r->rsi, (int)r->rdx, sip, &sp);
        if (n >= 0 && r->r10) { uint8_t *f = (uint8_t *)r->r10; f[0]=sip[0];f[1]=sip[1];f[2]=sip[2];f[3]=sip[3]; f[4]=(uint8_t)(sp&0xFF); f[5]=(uint8_t)(sp>>8); }
        r->rax = (uint64_t)(int64_t)n;
        break;
    }
    case SYS_connect: {                    /* (fd, addr{u8 ip[4];u16 port}) -> active-open a TCP socket (M1268) */
        if (!ubuf(r->rsi, 6)) { r->rax = (uint64_t)-1; break; }
        const uint8_t *ad = (const uint8_t *)r->rsi;
        uint8_t ip[4] = { ad[0], ad[1], ad[2], ad[3] };
        int port = ad[4] | (ad[5] << 8);
        __asm__ volatile("sti");           /* the 3-way handshake needs the timer */
        r->rax = (uint64_t)(int64_t)app_connect((int)r->rdi, ip, port);
        break;
    }
    case SYS_setsockopt: {                 /* (fd, level, optname, optval*, optlen) (M1554) */
        if (!ubuf(r->r10, sizeof(int))) { r->rax = (uint64_t)-1; break; }   /* optlen unused beyond this: every option here is a plain int */
        int val = *(const int *)r->r10;
        r->rax = (uint64_t)(int64_t)app_setsockopt((int)r->rdi, (int)r->rsi, (int)r->rdx, val);
        break;
    }
    case SYS_getsockopt: {                 /* (fd, level, optname, optval*, optlen*) (M1554) */
        if (!ubuf(r->r10, sizeof(int))) { r->rax = (uint64_t)-1; break; }
        int val = 0;
        long rc = app_getsockopt((int)r->rdi, (int)r->rsi, (int)r->rdx, &val);
        if (rc == 0) {
            *(int *)r->r10 = val;
            if (r->r8 && ubuf(r->r8, sizeof(int))) *(int *)r->r8 = sizeof(int);
        }
        r->rax = (uint64_t)rc;
        break;
    }
    case SYS_getsockname: {                /* (fd, addr[6]) -> this socket's own address (M1560); same 6-byte
                                             * {ip[4],port} wire format connect() (M1268) already uses */
        if (!ubuf(r->rsi, 6)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_getsockname((int)r->rdi, (unsigned char *)r->rsi);
        break;
    }
    case SYS_getpeername: {                /* (fd, addr[6]) -> the connected peer's address (M1560) */
        if (!ubuf(r->rsi, 6)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_getpeername((int)r->rdi, (unsigned char *)r->rsi);
        break;
    }
    case SYS_rmmod:                        /* (name) -> run mod_exit + free the module slot; 0/-1 (M1262) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)module_unload((const char *)r->rdi);
        break;
    case SYS_cas_store:                    /* (buf, len, hash32) -> store; write the SHA-256 key */
        if (!ubuf(r->rdi, r->rsi) || !ubuf(r->rdx, 32)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)cas_store((const void *)r->rdi, (uint32_t)r->rsi, (uint8_t *)r->rdx);
        break;
    case SYS_cas_fetch:                    /* (hash32, buf, max) -> fetch by key */
        if (!ubuf(r->rdi, 32) || !ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)cas_fetch((const uint8_t *)r->rdi, (void *)r->rsi, (uint32_t)r->rdx);
        break;
    case SYS_tftp: {                       /* (filename, buf, max) -> TFTP-fetch from the gateway's server */
        if (!ustr(r->rdi) || !ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        const uint8_t *g = net_gateway();  /* SLIRP's TFTP server lives on the gateway */
        char gw[16]; int n = 0;
        for (int o = 0; o < 4; o++) {
            if (o) gw[n++] = '.';
            int v = g[o];
            if (v >= 100) gw[n++] = (char)('0' + v / 100);
            if (v >= 10)  gw[n++] = (char)('0' + (v / 10) % 10);
            gw[n++] = (char)('0' + v % 10);
        }
        gw[n] = 0;
        __asm__ volatile("sti");           /* the lock-step transfer needs the timer for its timeouts */
        r->rax = (uint64_t)(int64_t)net_tftp_get(gw, (const char *)r->rdi, (void *)r->rsi, (uint32_t)r->rdx);
        break;
    }
    case SYS_apps:
        if (!ubuf(r->rdi, r->rsi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_list_names((char *)r->rdi, (int)r->rsi);
        break;
    case SYS_netinfo: {                    /* our IP/MAC/gateway/DNS as aligned text */
        char *b = (char *)r->rdi; int max = (int)r->rsi;
        if (max < 128) { r->rax = (uint64_t)-1; break; }   /* worst case ~96 B; require headroom */
        if (!ubuf(r->rdi, (uint64_t)max)) { r->rax = (uint64_t)-1; break; }
        const uint8_t *ip = net_ip(), *gw = net_gateway(), *dns = net_dns(), *m = net_mac();
        static const char H[] = "0123456789abcdef";
        int n = 0;
        const char *labels[4] = { "IP    ", "MAC   ", "GW    ", "DNS   " };
        const uint8_t *v4[4]  = { ip, NULL, gw, dns };     /* slot 1 (MAC) handled specially */
        /* Every raw write is guarded by `n + 1 < max` (leaving room for the
         * trailing NUL), exactly like SYS_resolve above — so the formatter stays
         * memory-safe for ANY buffer size even if fields are added later, rather
         * than relying on the worst-case length staying under the guard. */
        for (int row = 0; row < 4; row++) {
            for (const char *s = labels[row]; *s; s++) if (n + 1 < max) b[n++] = *s;
            if (row == 1) {                                /* MAC: 6 hex bytes, colon-separated */
                for (int i = 0; i < 6; i++) {
                    if (n + 1 < max) b[n++] = H[m[i] >> 4];
                    if (n + 1 < max) b[n++] = H[m[i] & 15];
                    if (i < 5 && n + 1 < max) b[n++] = ':';
                }
            } else {                                       /* IPv4 dotted quad */
                for (int i = 0; i < 4; i++) { n = snum(b, n, max, v4[row][i]); if (i < 3 && n + 1 < max) b[n++] = '.'; }
            }
            if (n + 1 < max) b[n++] = '\n';
        }
        b[n] = 0; r->rax = (uint64_t)n;
        break;
    }
    case SYS_http:
        if (!ustr(r->rdi) || !ustr(r->rsi) || !ubuf(r->rdx, r->r10)) { r->rax = (uint64_t)-1; break; }  /* host, path, response buf */
        __asm__ volatile("sti");           /* TCP needs the timer running */
        r->rax = (uint64_t)(int64_t)http_get((const char *)r->rdi,
                                             (const char *)r->rsi,
                                             (char *)r->rdx, (int)r->r10);
        break;
    case SYS_https:
        if (!ustr(r->rdi) || !ustr(r->rsi) || !ubuf(r->rdx, r->r10)) { r->rax = (uint64_t)-1; break; }  /* host, path, response buf */
        __asm__ volatile("sti");           /* TLS/TCP need the timer running */
        r->rax = (uint64_t)(int64_t)tls_get((const char *)r->rdi,
                                            (const char *)r->rsi,
                                            (uint8_t *)r->rdx, (int)r->r10,
                                            (uint32_t)timer_ticks());
        break;
    case SYS_ws_open:                      /* (url, status*) -> WebSocket connect + handshake (M1846) */
        if (!ustr(r->rdi) || !ubuf(r->rsi, sizeof(int))) { r->rax = (uint64_t)-1; break; }
        __asm__ volatile("sti");           /* TCP needs the timer running */
        r->rax = (uint64_t)(int64_t)ws_open((const char *)r->rdi, (int *)r->rsi);
        break;
    case SYS_ws_exchange: {                /* (id, sendbuf, sendtot, out, outmax, nrecv*) (M1846) */
        int st = (int)r->rdx, om = (int)r->r8;
        if (st < 0 || om <= 0 || (st > 0 && !ubuf(r->rsi, (uint64_t)st)) ||
            !ubuf(r->r10, (uint64_t)om) || !ubuf(r->r9, sizeof(int))) { r->rax = (uint64_t)-1; break; }
        __asm__ volatile("sti");
        r->rax = (uint64_t)(int64_t)ws_exchange((int)r->rdi, (const char *)r->rsi, st,
                                                (char *)r->r10, om, (int *)r->r9);
        break;
    }
    case SYS_ws_serve: {                   /* (port, lastmsg, lastmax, nframes*) -> WS echo server (M1849) */
        int lm = (int)r->rdx;
        if (lm < 0 || (lm > 0 && !ubuf(r->rsi, (uint64_t)lm)) || !ubuf(r->r10, sizeof(int))) { r->rax = (uint64_t)-1; break; }
        __asm__ volatile("sti");
        r->rax = (uint64_t)(int64_t)ws_serve((uint16_t)r->rdi, (char *)r->rsi, lm, (int *)r->r10);
        break;
    }
    case SYS_browse:
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        app_browse((const char *)r->rdi);  /* WM opens the browser window */
        r->rax = 0;
        break;
    case SYS_js:
        if (!ustr(r->rdi) || !ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }  /* script src + result buffer */
        __asm__ volatile("sti");           /* keep the timer live during long scripts */
        r->rax = (uint64_t)(int64_t)js_run((const char *)r->rdi,
                                           (char *)r->rsi, (int)r->rdx);
        break;
    case SYS_mkdir:
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, (const char *)r->rdi, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_mkdir((const char *)r->rdi);
        break;
    case SYS_chdir: {
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, (const char *)r->rdi, 0)) { r->rax = (uint64_t)-1; break; }
        long cr = vfs_chdir((const char *)r->rdi);
        if (cr == 0) app_chdir_track((const char *)r->rdi);   /* track the cwd string for getcwd (M1248) */
        r->rax = (uint64_t)(int64_t)cr;
        break;
    }
    case SYS_fchdir: {                     /* (fd) -> chdir via an already-open directory fd (M1586) */
        const char *p = app_fd_path((int)r->rdi);
        if (!p) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, p, 0)) { r->rax = (uint64_t)-1; break; }
        long cr = vfs_chdir(p);
        if (cr == 0) app_chdir_track(p);
        r->rax = (uint64_t)(int64_t)cr;
        break;
    }
    case SYS_getcwd:                       /* (buf, size) -> the absolute cwd; length/-1 (M1248) */
        if (!ubuf(r->rdi, r->rsi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_getcwd((char *)r->rdi, (unsigned long)r->rsi);
        break;
    case SYS_tree:
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_tree((char *)r->rsi, (int)r->rdx);
        break;
    case SYS_pollkey:
        r->rax = (uint64_t)(int64_t)app_sys_pollkey();
        break;
    case SYS_find:
        if (!ustr(r->rdi) || !ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }  /* search term + result buffer */
        r->rax = (uint64_t)(int64_t)vfs_find((const char *)r->rdi,
                                             (char *)r->rsi, (int)r->rdx);
        break;
    case SYS_sha1: {
        if ((int)r->rdx < 41) { r->rax = (uint64_t)-1; break; }   /* need room for 40 hex + NUL */
        if (!ustr(r->rdi) || !ubuf(r->rsi, 41)) { r->rax = (uint64_t)-1; break; }  /* filename + hex output */
        uint8_t *fbuf; long fn = read_whole_file((const char *)r->rdi, &fbuf);
        if (fn < 0) { r->rax = (uint64_t)-1; break; }
        uint8_t dg[20]; sha1_hash(fbuf, (size_t)fn, dg); kfree(fbuf);
        char *hx = (char *)r->rsi; const char *H = "0123456789abcdef";
        for (int i = 0; i < 20; i++) { hx[i*2] = H[dg[i]>>4]; hx[i*2+1] = H[dg[i]&0xF]; }
        hx[40] = 0; r->rax = 0;
        break;
    }
    case SYS_sha256: {
        if ((int)r->rdx < 65) { r->rax = (uint64_t)-1; break; }   /* need room for 64 hex + NUL */
        if (!ustr(r->rdi) || !ubuf(r->rsi, 65)) { r->rax = (uint64_t)-1; break; }  /* filename + hex output */
        uint8_t *fbuf; long fn = read_whole_file((const char *)r->rdi, &fbuf);   /* whole file, not a 16KB prefix */
        if (fn < 0) { r->rax = (uint64_t)-1; break; }
        uint8_t dg[32]; sha256(fbuf, (size_t)fn, dg); kfree(fbuf);
        char *hx = (char *)r->rsi; const char *H = "0123456789abcdef";
        for (int i = 0; i < 32; i++) { hx[i*2] = H[dg[i]>>4]; hx[i*2+1] = H[dg[i]&0xF]; }
        hx[64] = 0; r->rax = 0;
        break;
    }
    case SYS_sha512: {
        if ((int)r->rdx < 129) { r->rax = (uint64_t)-1; break; }   /* need room for 128 hex + NUL */
        if (!ustr(r->rdi) || !ubuf(r->rsi, 129)) { r->rax = (uint64_t)-1; break; }  /* filename + hex output */
        uint8_t *fbuf; long fn = read_whole_file((const char *)r->rdi, &fbuf);   /* whole file, not a 16KB prefix */
        if (fn < 0) { r->rax = (uint64_t)-1; break; }
        uint8_t dg[64]; sha512(fbuf, (size_t)fn, dg); kfree(fbuf);
        char *hx = (char *)r->rsi; const char *H = "0123456789abcdef";
        for (int i = 0; i < 64; i++) { hx[i*2] = H[dg[i]>>4]; hx[i*2+1] = H[dg[i]&0xF]; }
        hx[128] = 0; r->rax = 0;
        break;
    }
    case SYS_screenshot: {
        const char *sn = (const char *)r->rdi;          /* a ".png" name -> PNG, else BMP */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        int L = 0; while (sn[L]) L++;
        int png = (L >= 4 && sn[L-4]=='.' && (sn[L-3]|32)=='p' && (sn[L-2]|32)=='n' && (sn[L-1]|32)=='g');
        r->rax = (uint64_t)(int64_t)(png ? fb_save_png(sn) : fb_save_bmp(sn));
        break;
    }
    case SYS_gunzip: {
        const char *insrc = (const char *)r->rdi, *outname = (const char *)r->rsi;
        if (!ustr(r->rdi) || !ustr(r->rsi)) { r->rax = (uint64_t)-1; break; }
        uint8_t *in = 0; long gn = read_whole_file(insrc, &in);   /* whole .gz, not a 256KB prefix */
        if (gn < 0) { r->rax = (uint64_t)-1; break; }
        if (gn < 18) { kfree(in); r->rax = (uint64_t)-1; break; }   /* too short to be gzip */
        /* gzip trailer's ISIZE (last 4 bytes) = original size mod 2^32 — size the output to it */
        size_t isize = (size_t)((uint32_t)in[gn-4] | ((uint32_t)in[gn-3]<<8) |
                                ((uint32_t)in[gn-2]<<16) | ((uint32_t)in[gn-1]<<24));
        if (isize == 0) isize = 1;
        if (isize > (32u << 20)) { kfree(in); r->rax = (uint64_t)-1; break; }   /* implausible/too large */
        uint8_t *out = kmalloc(isize);
        long dl = out ? gz_inflate(in, (int)gn, out, (int)isize) : -1;
        if (dl > 0 && vfs_write(outname, out, (unsigned long)dl) < 0) dl = -1;
        if (out) kfree(out);
        kfree(in);                          /* `in` is always allocated here: free unconditionally */
        r->rax = (uint64_t)(int64_t)dl;
        break;
    }
    case SYS_gzip: {
        const char *insrc = (const char *)r->rdi, *outname = (const char *)r->rsi;
        if (!ustr(r->rdi) || !ustr(r->rsi)) { r->rax = (uint64_t)-1; break; }
        uint8_t *in = 0; long gn = read_whole_file(insrc, &in);   /* whole input, not a 256KB prefix */
        if (gn < 0) { r->rax = (uint64_t)-1; break; }
        size_t ocap = (size_t)gn + (size_t)gn / 2 + 1024;   /* >= fixed-Huffman worst case (~input*9/8) */
        uint8_t *out = kmalloc(ocap);
        long dl = out ? gz_deflate(in, (int)gn, out, (int)ocap) : -1;   /* empty input is a valid gzip */
        if (dl > 0 && vfs_write(outname, out, (unsigned long)dl) < 0) dl = -1;
        if (out) kfree(out);
        kfree(in);                          /* `in` is always allocated here: free unconditionally */
        r->rax = (uint64_t)(int64_t)dl;
        break;
    }
    case SYS_unzip: {
        const char *zn = (const char *)r->rdi;
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        uint8_t *zbuf; long zl = read_whole_file(zn, &zbuf);   /* the whole .zip (was a fixed 1MB read) */
        uint8_t *scr = (zl >= 0) ? kmalloc(1048576) : 0;       /* one decompressed entry at a time (<= 1 MB) */
        if (zl < 0 || !scr) { if (zl >= 0) kfree(zbuf); if (scr) kfree(scr); r->rax = (uint64_t)-1; break; }
        struct unzip_ctx uc = { 0 };
        int cnt = zip_extract(zbuf, (int)zl, unzip_emit, &uc, scr, 1048576);
        kfree(zbuf); kfree(scr);
        r->rax = (uint64_t)(int64_t)(cnt < 0 ? -1 : uc.written);   /* files actually written */
        break;
    }
    case SYS_untar: {
        const char *tn = (const char *)r->rdi;
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        uint8_t *buf; long fl = read_whole_file(tn, &buf);   /* the whole .tar/.tar.gz (was a fixed 1MB read) */
        if (fl <= 0) { if (fl == 0) kfree(buf); r->rax = (uint64_t)-1; break; }
        struct unzip_ctx uc = { 0 };
        int cnt;
        if (fl > 2 && buf[0] == 0x1f && buf[1] == 0x8b) {   /* .tar.gz: gunzip the tar first */
            uint8_t *tar = kmalloc(4194304);    /* decompressed tar (<= 4 MB) */
            if (!tar) { kfree(buf); r->rax = (uint64_t)-1; break; }
            int tl = gz_inflate(buf, (int)fl, tar, 4194304);
            cnt = tl > 0 ? tar_extract(tar, tl, unzip_emit, &uc) : -1;
            kfree(tar);
        } else {
            cnt = tar_extract(buf, (int)fl, unzip_emit, &uc);
        }
        kfree(buf);
        r->rax = (uint64_t)(int64_t)(cnt < 0 ? -1 : uc.written);
        break;
    }
    case SYS_crypt: {
        const char *name = (const char *)r->rdi, *pass = (const char *)r->rsi;
        if (!ustr(r->rdi) || !ustr(r->rsi)) { r->rax = (uint64_t)-1; break; }
        uint8_t *cbuf; long cn = read_whole_file(name, &cbuf);   /* whole file (was capped at 16KB) */
        if (cn < 0) { r->rax = (uint64_t)-1; break; }            /* missing / >=32MB / OOM */
        uint8_t kd[32]; sha256((const uint8_t *)pass, strlen(pass), kd);  /* key||nonce */
        aes128_ctr(cbuf, (size_t)cn, kd, kd + 16);
        long w = vfs_write(name, cbuf, (unsigned long)cn);
        kfree(cbuf);
        r->rax = (uint64_t)(int64_t)w;
        break;
    }
    case SYS_df: {
        uint64_t fb, tb; vfs_df(&fb, &tb);
        char *b = (char *)r->rsi; int max = (int)r->rdx, p = 0;
        if (max > 0 && !ubuf(r->rsi, (uint64_t)max)) { r->rax = (uint64_t)-1; break; }
        p = sappend(b, p, max, "  disk: ");
        p = snum(b, p, max, fb / 1024);
        p = sappend(b, p, max, " KiB free / ");
        p = snum(b, p, max, tb / 1024);
        p = sappend(b, p, max, " KiB total\n");
        if (p < max) b[p] = 0;
        r->rax = (uint64_t)p;
        break;
    }
    case SYS_statfs: {                     /* (path, struct statvfs*) -> filesystem free/total (M1240) */
        if (!ustr(r->rdi) || !ubuf(r->rsi, sizeof(struct statvfs))) { r->rax = (uint64_t)-1; break; }
        struct statx stx;
        if (vfs_stat((const char *)r->rdi, &stx) != 0) { r->rax = (uint64_t)-1; break; }   /* the path must exist */
        uint64_t fb, tb; vfs_df(&fb, &tb);                 /* free / total bytes of the (single) root fs */
        struct statvfs sv;
        sv.f_bsize = sv.f_frsize = 512;
        sv.f_blocks = tb / 512;
        sv.f_bfree = sv.f_bavail = fb / 512;
        sv.f_files = sv.f_ffree = 0;                       /* global inode counts not tracked */
        sv.f_namemax = 255;
        for (unsigned i = 0; i < sizeof sv; i++) ((uint8_t *)r->rsi)[i] = ((uint8_t *)&sv)[i];
        r->rax = 0;
        break;
    }
    case SYS_font: {                          /* copy the 8x16 console font so gfx apps can render real text (M1362) */
        extern const unsigned char font_glyphs[128][16];
        char *b = (char *)r->rsi; int max = (int)r->rdx;
        int need = (int)sizeof(font_glyphs);  /* 128 * 16 = 2048 bytes */
        if (max < need || !ubuf(r->rsi, (uint64_t)need)) { r->rax = (uint64_t)-1; break; }
        for (int i = 0; i < need; i++) b[i] = ((const unsigned char *)font_glyphs)[i];
        r->rax = (uint64_t)need;
        break;
    }
    case SYS_loadimg: {                       /* decode + fit-scale an image file into a gfx app's XRGB buffer (M1392) */
        int cw = (int)((r->rdx >> 16) & 0xFFFF), ch = (int)(r->rdx & 0xFFFF);
        if (cw <= 0 || ch <= 0) { r->rax = (uint64_t)-1; break; }
        if (!ustr(r->rdi) || !ubuf(r->rsi, (uint64_t)cw * ch * 4) || !ubuf(r->r10, 8)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)desktop_load_image((const char *)r->rdi, (unsigned *)r->rsi, cw, ch, (int *)r->r10);
        break;
    }
    case SYS_ps: {
        task_info_t ti[16];
        int cnt = task_snapshot(ti, 16);
        char *b = (char *)r->rsi; int max = (int)r->rdx, p = 0;
        if (max > 0 && !ubuf(r->rsi, (uint64_t)max)) { r->rax = (uint64_t)-1; break; }
        static const char *st[5] = { "ready", "run  ", "block", "dead ", "stop " };
        for (int i = 0; i < cnt; i++) {
            if (ti[i].state == 3) continue;          /* skip dead tasks */
            p = sappend(b, p, max, "  [");
            p = snum(b, p, max, (uint64_t)ti[i].id);
            p = sappend(b, p, max, "] ");
            p = sappend(b, p, max, st[(unsigned)ti[i].state < 5 ? ti[i].state : 0]);
            p = sappend(b, p, max, "  ");
            p = sappend(b, p, max, ti[i].proc ? app_title((app_t *)ti[i].proc) : "(kernel)");
            p = sappend(b, p, max, "\n");
        }
        if (p < max) b[p] = 0;
        r->rax = (uint64_t)p;
        break;
    }
    case SYS_history:
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)app_sys_history((char *)r->rsi, (int)r->rdx);
        break;
    case SYS_resolve: {
        __asm__ volatile("sti");
        const char *host = (const char *)r->rdi;
        char *buf = (char *)r->rsi; int max = (int)r->rdx;
        uint8_t ip[4];
        if (max <= 0) { r->rax = (uint64_t)-1; break; }
        if (!ustr(r->rdi) || !ubuf(r->rsi, (uint64_t)max)) { r->rax = (uint64_t)-1; break; }  /* host + result buf */
        if (dns_resolve(host, ip) == 0) {
            int n = 0;
            for (int i = 0; i < 4; i++) {
                n = snum(buf, n, max, ip[i]);
                if (n + 1 < max) buf[n++] = (i < 3) ? '.' : '\n';   /* keep room for NUL */
            }
            buf[n] = 0; r->rax = 0;
        } else r->rax = (uint64_t)-1;
        break;
    }
    case SYS_reboot:
        acpi_reboot();                     /* ACPI reset register, else 8042 pulse */
        for (;;) __asm__ volatile("hlt");
        break;
    case SYS_poweroff:
        acpi_poweroff();                   /* enter ACPI S5: power the machine off */
        for (;;) __asm__ volatile("hlt");
        break;
    case SYS_kill: {                       /* ask the app with this pid to close (cooperative, like the X button) */
        int pid = (int)r->rdi;
        task_info_t ti[24];
        int cnt = task_snapshot(ti, 24);
        r->rax = (uint64_t)-1;
        for (int i = 0; i < cnt; i++)
            if (ti[i].id == pid && ti[i].proc && ti[i].state != 3) {
                app_request_kill((app_t *)ti[i].proc);
                r->rax = 0;
                break;
            }
        break;
    }
    case SYS_sbrk:
        r->rax = app_sbrk((long)r->rdi);   /* grow the heap; old break, or (uint64_t)-1 */
        break;
    case SYS_mmap:
        r->rax = app_mmap(r->rdi);         /* reserve a demand-paged anon region; base VA or 0 */
        break;
    case SYS_mmap_huge:                    /* (len) -> 2 MiB-backed demand-paged region (M1155) */
        r->rax = app_mmap_huge(r->rdi);
        break;
    case SYS_semget:                       /* (key, nsems, flags) -> SysV semaphore set (M1159) */
        r->rax = (uint64_t)(int64_t)sysv_semget((int)r->rdi, (int)r->rsi, (int)r->rdx);
        break;
    case SYS_semop: {                      /* (semid, struct sembuf*, nsops) -> atomic semop (M1159) */
        unsigned nsops = (unsigned)r->rdx;
        if (nsops == 0 || nsops > 16 || !ubuf(r->rsi, nsops * sizeof(struct sembuf))) { r->rax = (uint64_t)-1; break; }
        struct sembuf ksops[16];           /* copy in (semop may block + re-read across task switches) */
        for (unsigned i = 0; i < nsops; i++) ksops[i] = ((struct sembuf *)r->rsi)[i];
        r->rax = (uint64_t)(int64_t)sysv_semop((int)r->rdi, ksops, nsops);
        break;
    }
    case SYS_semctl:                       /* (semid, semnum, cmd, arg) -> SETVAL/GETVAL/IPC_RMID (M1159) */
        r->rax = (uint64_t)(int64_t)sysv_semctl((int)r->rdi, (int)r->rsi, (int)r->rdx, (int)r->r10);
        break;
    case SYS_sem_open:                     /* (name, oflag, value) -> POSIX named semaphore (M1575) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)sem_named_open((const char *)r->rdi, (int)r->rsi, (unsigned int)r->rdx);
        break;
    case SYS_sem_close:                    /* (idx) -> drop this handle (M1575) */
        r->rax = (uint64_t)(int64_t)sem_named_close((int)r->rdi);
        break;
    case SYS_sem_unlink:                   /* (name) -> remove the name (M1575) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)sem_named_unlink((const char *)r->rdi);
        break;
    case SYS_sem_wait:                     /* (idx) -> block until value>0, then decrement (M1575) */
        r->rax = (uint64_t)(int64_t)sem_named_wait((int)r->rdi);
        break;
    case SYS_sem_trywait:                  /* (idx) -> non-blocking sem_wait (M1575) */
        r->rax = (uint64_t)(int64_t)sem_named_trywait((int)r->rdi);
        break;
    case SYS_sem_post:                     /* (idx) -> increment + wake waiters (M1575) */
        r->rax = (uint64_t)(int64_t)sem_named_post((int)r->rdi);
        break;
    case SYS_sem_getvalue: {               /* (idx, int*) -> the current value (M1575) */
        if (!ubuf(r->rsi, sizeof(int))) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)sem_named_getvalue((int)r->rdi, (int *)r->rsi);
        break;
    }
    case SYS_msgget:                       /* (key, flags) -> SysV message queue (M1160) */
        r->rax = (uint64_t)(int64_t)sysv_msgget((int)r->rdi, (int)r->rsi);
        break;
    case SYS_msgsnd: {                     /* (msqid, msgbuf{long mtype; char data[sz]}, sz, flags) (M1160) */
        int sz = (int)r->rdx;
        if (sz < 0 || sz > 192 || !ubuf(r->rsi, 8 + (uint64_t)sz)) { r->rax = (uint64_t)-1; break; }
        char kb[8 + 192];
        for (int i = 0; i < 8 + sz; i++) kb[i] = ((char *)r->rsi)[i];
        r->rax = (uint64_t)(int64_t)sysv_msgsnd((int)r->rdi, *(long *)kb, kb + 8, sz, (int)r->r10);
        break;
    }
    case SYS_msgrcv: {                     /* (msqid, msgbuf*, sz, mtyp) -> receive by type (M1160) */
        int sz = (int)r->rdx;
        if (sz < 0 || sz > 192 || !ubuf(r->rsi, 8 + (uint64_t)sz)) { r->rax = (uint64_t)-1; break; }
        char kb[192]; long mt = 0;
        long n = sysv_msgrcv((int)r->rdi, (long)r->r10, kb, sz, &mt, 0);
        if (n < 0) { r->rax = (uint64_t)-1; break; }
        *(long *)r->rsi = mt;                          /* mtype goes at the start of the user msgbuf */
        for (long i = 0; i < n; i++) ((char *)r->rsi)[8 + i] = kb[i];
        r->rax = (uint64_t)n;
        break;
    }
    case SYS_msgctl:                       /* (id, cmd) -> IPC_RMID only, frees the id slot (M1576) */
        r->rax = (uint64_t)(int64_t)sysv_msgctl((int)r->rdi, (int)r->rsi);
        break;
    case SYS_shmget:                       /* (key, size, flags) -> SysV shm segment id (M1161) */
        r->rax = (uint64_t)(int64_t)sysv_shmget((int)r->rdi, r->rsi, (int)r->rdx);
        break;
    case SYS_shmat:                        /* (shmid) -> attach: base VA, or 0 (M1161) */
        r->rax = sysv_shmat((int)r->rdi);
        break;
    case SYS_shmdt:                        /* (addr) -> detach (unmap) the shm mapping (M1161) */
        r->rax = (uint64_t)(int64_t)app_munmap(r->rdi, 0);
        break;
    case SYS_shmctl:                       /* (id, cmd) -> IPC_RMID only, frees the id slot (M1576) */
        r->rax = (uint64_t)(int64_t)sysv_shmctl((int)r->rdi, (int)r->rsi);
        break;
    case SYS_process_vm_read:              /* (pid, raddr, local, len) -> read another process's memory (M1162) */
        if (!ubuf(r->rdx, r->r10)) { r->rax = (uint64_t)-1; break; }    /* local buffer writable for len */
        r->rax = (uint64_t)(int64_t)app_process_vm_read((int)r->rdi, r->rsi, (void *)r->rdx, r->r10);
        break;
    case SYS_process_vm_write:             /* (pid, raddr, local, len) -> write another process's memory (M1165) */
        if (!ubuf(r->rdx, r->r10)) { r->rax = (uint64_t)-1; break; }    /* local source buffer readable for len */
        r->rax = (uint64_t)(int64_t)app_process_vm_write((int)r->rdi, r->rsi, (const void *)r->rdx, r->r10);
        break;
    case SYS_unix_listen:                  /* (path) -> AF_UNIX listener id (M1169) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)unix_listen((const char *)r->rdi);
        break;
    case SYS_unix_connect:                 /* (path) -> client endpoint id (M1169) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)unix_connect((const char *)r->rdi);
        break;
    case SYS_unix_accept:                  /* (lid) -> server endpoint id, blocks (M1169) */
        r->rax = (uint64_t)(int64_t)unix_accept((int)r->rdi);
        break;
    case SYS_unix_send:                    /* (ep, buf, len) -> bytes written (M1169) */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)unix_send((int)r->rdi, (const void *)r->rsi, r->rdx);
        break;
    case SYS_unix_recv:                    /* (ep, buf, max) -> bytes read; 0 EOF (M1169) */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)unix_recv((int)r->rdi, (void *)r->rsi, r->rdx);
        break;
    case SYS_unix_close:                   /* (ep) -> 0/-1 (M1169) */
        r->rax = (uint64_t)(int64_t)unix_close((int)r->rdi);
        break;
    case SYS_unix_wait_any:                /* (int*eps, n) -> index of first readable ep, blocks once (M1170) */
        if ((int)r->rsi <= 0 || (int)r->rsi > 16 || !ubuf(r->rdi, (uint64_t)(int)r->rsi * sizeof(int))) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)unix_wait_any((const int *)r->rdi, (int)r->rsi);
        break;
    case SYS_unix_shutdown:                /* (ep, how) -> half-close this side's write direction (M1965) */
        r->rax = (uint64_t)(int64_t)unix_shutdown((int)r->rdi, (int)r->rsi);
        break;
    case SYS_unix_unlisten:                /* (lid) -> release a listener's bound name (M1965) */
        r->rax = (uint64_t)(int64_t)unix_unlisten((int)r->rdi);
        break;
    case SYS_socketpair: {                 /* (int sv[2]) -> a pre-connected AF_UNIX endpoint pair (M1254) */
        if (!ubuf(r->rdi, 2 * sizeof(int))) { r->rax = (uint64_t)-1; break; }
        int sv[2];
        if (unix_socketpair(&sv[0], &sv[1]) != 0) { r->rax = (uint64_t)-1; break; }
        ((int *)r->rdi)[0] = sv[0]; ((int *)r->rdi)[1] = sv[1];
        r->rax = 0;
        break;
    }
    case SYS_nice:                         /* (nice) -> set current task's CFS nice; returns the clamped value (M1171) */
        r->rax = (uint64_t)(int64_t)task_set_nice((int)r->rdi);
        break;
    case SYS_sched_setscheduler:           /* (policy, rt_priority) -> set the current task's scheduling class (M1172) */
        r->rax = (uint64_t)(int64_t)task_set_sched((int)r->rdi, (int)r->rsi);
        break;
    case SYS_sched_get_priority_max:       /* (policy) -> the valid rt_priority ceiling for SCHED_* (M1589) */
        r->rax = (uint64_t)(int64_t)task_sched_get_priority_max((int)r->rdi);
        break;
    case SYS_sched_get_priority_min:       /* (policy) -> the valid rt_priority floor for SCHED_* (M1589) */
        r->rax = (uint64_t)(int64_t)task_sched_get_priority_min((int)r->rdi);
        break;
    case SYS_sched_getscheduler:           /* () -> the caller's own scheduling policy (M1591) */
        r->rax = (uint64_t)(int64_t)task_get_sched();
        break;
    case SYS_sched_getparam:               /* () -> the caller's own rt_priority (M1591) */
        r->rax = (uint64_t)(int64_t)task_get_sched_priority();
        break;
    case SYS_sched_rr_get_interval: {      /* (sec*, nsec*) -> the SCHED_RR timeslice as a real duration (M1591) */
        if ((r->rdi && !ubuf(r->rdi, sizeof(long))) || (r->rsi && !ubuf(r->rsi, sizeof(long)))) { r->rax = (uint64_t)-1; break; }
        long sec = 0, nsec = 0;
        task_sched_rr_get_interval(&sec, &nsec);
        if (r->rdi) *(long *)r->rdi = sec;
        if (r->rsi) *(long *)r->rsi = nsec;
        r->rax = 0;
        break;
    }
    case SYS_access: {                     /* (path, amode) -> 0 if accessible, -1 (M1224) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)access_check((const char *)r->rdi, (int)r->rsi);
        break;
    }
    case SYS_faccessat2: {                 /* (dirfd, path, amode, flags) -> access() relative to a dir fd (M1556);
                                             * no AT_SYMLINK_NOFOLLOW/AT_EACCESS -- same unused-flags precedent as
                                             * unlinkat/fchmodat/fchownat, no symlink-follow-choice or seteuid-vs-
                                             * real-uid distinction exists in this codebase to gate on either. */
        char eff[256];
        if (!ustr(r->rsi) || at_resolve((long)r->rdi, (const char *)r->rsi, eff, sizeof eff) < 0) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)access_check(eff, (int)r->rdx);
        break;
    }
    case SYS_prctl:                        /* (option, arg2) -> PR_SET_NAME/PR_GET_NAME/PR_SET_PDEATHSIG/PR_GET_PDEATHSIG (M1225, M1562) */
        if (r->rdi == PR_SET_NAME) { if (!ustr(r->rsi)) { r->rax = (uint64_t)-1; break; } }
        else if (r->rdi == PR_GET_NAME) { if (!ubuf(r->rsi, 16)) { r->rax = (uint64_t)-1; break; } }
        else if (r->rdi == PR_GET_PDEATHSIG) { if (!ubuf(r->rsi, sizeof(int))) { r->rax = (uint64_t)-1; break; } }
        r->rax = (uint64_t)app_prctl((int)r->rdi, r->rsi);
        break;
    case SYS_set_tid_address:              /* (tidptr) -> register clear_child_tid; returns the tid (M1226) */
        r->rax = (uint64_t)app_set_tid_address(r->rdi);
        break;
    case SYS_waitid:                       /* (idtype, id, siginfo*, options) -> 0/-1 (M1227) */
        if (r->rdx && !ubuf(r->rdx, sizeof(struct siginfo))) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_waitid((int)r->rdi, (int)r->rsi, (struct siginfo *)r->rdx, (int)r->r10);
        break;
    case SYS_truncate:                     /* (path, len) -> resize a real file; 0/-1 (M1228) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, (const char *)r->rdi, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_truncate((const char *)r->rdi, (uint64_t)r->rsi);
        break;
    case SYS_utimens:                      /* (path, atime, mtime) -> set timestamps (M1230) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, (const char *)r->rdi, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_utimens((const char *)r->rdi, (long)r->rsi, (long)r->rdx);
        break;
    case SYS_futimens:                     /* (fd, atime, mtime) -> set timestamps on an open fd (M1230) */
        r->rax = (uint64_t)(int64_t)app_futimens((int)r->rdi, (long)r->rsi, (long)r->rdx);
        break;
    case SYS_chmod:                        /* (path, mode) -> set permission bits (M1241) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, (const char *)r->rdi, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_chmod((const char *)r->rdi, (uint32_t)r->rsi);
        break;
    case SYS_fchmod: {                     /* (fd, mode) -> set permission bits on an open fd (M1241) */
        const char *fp = app_fd_path((int)r->rdi);
        r->rax = fp ? (uint64_t)(int64_t)vfs_chmod(fp, (uint32_t)r->rsi) : (uint64_t)-1;
        break;
    }
    case SYS_chown:                        /* (path, uid, gid) -> set owner/group (M1243) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, (const char *)r->rdi, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_chown((const char *)r->rdi, (long)r->rsi, (long)r->rdx);
        break;
    case SYS_fchown: {                     /* (fd, uid, gid) -> set owner/group on an open fd (M1243) */
        const char *fp = app_fd_path((int)r->rdi);
        r->rax = fp ? (uint64_t)(int64_t)vfs_chown(fp, (long)r->rsi, (long)r->rdx) : (uint64_t)-1;
        break;
    }
    case SYS_statx:                        /* (path, struct statx*) -> file metadata (M1173) */
        if (!ustr(r->rdi) || !ubuf(r->rsi, sizeof(struct statx))) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_stat((const char *)r->rdi, (struct statx *)r->rsi);
        break;
    case SYS_tcgetattr:                    /* (struct termios*) -> read the TTY mode (M1174) */
        if (!ubuf(r->rdi, sizeof(struct termios))) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_tcgetattr((struct termios *)r->rdi);
        break;
    case SYS_tcsetattr:                    /* (struct termios*) -> set cooked/raw TTY mode (M1174) */
        if (!ubuf(r->rdi, sizeof(struct termios))) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_tcsetattr((const struct termios *)r->rdi);
        break;
    case SYS_tcflush:                      /* (queue_selector) -> discard unread input; 0/-1 (M1570) */
        r->rax = (uint64_t)(int64_t)app_tcflush((int)r->rdi);
        break;
    case SYS_tcdrain:                      /* () -> wait for pending output; a no-op here; 0/-1 (M1570) */
        r->rax = (uint64_t)(int64_t)app_tcdrain();
        break;
    case SYS_setpgid:                      /* (pid, pgid) -> set process group (M1176) */
        r->rax = (uint64_t)(int64_t)app_setpgid((int)r->rdi, (int)r->rsi);
        break;
    case SYS_getpgid:                      /* (pid) -> process group id (M1176) */
        r->rax = (uint64_t)(int64_t)app_getpgid((int)r->rdi);
        break;
    case SYS_getsid:                       /* (pid) -> session id; pid==0 = caller's own (M1580) */
        r->rax = (uint64_t)(int64_t)app_getsid((int)r->rdi);
        break;
    case SYS_setsid:                       /* () -> become session+group leader (M1176) */
        r->rax = (uint64_t)(int64_t)app_setsid();
        break;
    case SYS_tcsetpgrp:                    /* (pgid) -> set the console foreground group (M1176) */
        r->rax = (uint64_t)(int64_t)app_tcsetpgrp((int)r->rdi);
        break;
    case SYS_tcgetpgrp:                    /* () -> the console's foreground process group (M1558) */
        r->rax = (uint64_t)(int64_t)app_tcgetpgrp();
        break;
    case SYS_killpg:                       /* (pgid, signo) -> signal every process in the group (M1176) */
        r->rax = (uint64_t)(int64_t)app_killpg((int)r->rdi, (int)r->rsi);
        break;
    case SYS_flock:                        /* (path, op) -> advisory whole-file lock (M1177) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)flock_op((const char *)r->rdi, app_sys_getpid(), (int)r->rsi);
        break;
    case SYS_getrlimit:                    /* (resource, struct rlimit*) -> read a resource limit (M1163) */
        if (!ubuf(r->rsi, sizeof(struct rlimit))) { r->rax = (uint64_t)-1; break; }
        { struct rlimit *rl = (struct rlimit *)r->rsi; uint64_t v = app_getrlimit((int)r->rdi); rl->rlim_cur = v; rl->rlim_max = v; }
        r->rax = 0;
        break;
    case SYS_setrlimit:                    /* (resource, struct rlimit*) -> set a resource limit (M1163) */
        if (!ubuf(r->rsi, sizeof(struct rlimit))) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_setrlimit((int)r->rdi, ((struct rlimit *)r->rsi)->rlim_cur);
        break;
    case SYS_munmap:
        r->rax = (uint64_t)(int64_t)app_munmap(r->rdi, r->rsi);
        break;
    case SYS_mremap:                       /* (old_addr, old_len, new_len, flags) -> resize/move (M1179) */
        r->rax = app_mremap(r->rdi, r->rsi, r->rdx, (int)r->r10);
        break;
    case SYS_copy_file_range: {            /* (src_path, dst_path, len) -> in-kernel copy; dst /net/tcp = sendfile (M1181) */
        if (!ustr(r->rdi) || !ustr(r->rsi)) { r->rax = (uint64_t)-1; break; }
        unsigned long want = r->rdx, cap = (want && want < (4UL << 20)) ? want : (4UL << 20);   /* cap one shot at 4 MiB */
        char *kb = kmalloc(cap);
        if (!kb) { r->rax = (uint64_t)-1; break; }
        long n = vfs_read((const char *)r->rdi, kb, cap);      /* kernel<-src; no user buffer crosses */
        long w = (n >= 0) ? vfs_write((const char *)r->rsi, kb, (unsigned long)n) : -1;  /* dst<-kernel (a /net/tcp dst SENDS) */
        kfree(kb);
        r->rax = (uint64_t)(int64_t)w;
        break;
    }
    case SYS_setxattr: {                   /* (path, name, value, vlen) -> set a user.* xattr (M1182) */
        if (!ustr(r->rdi) || !ustr(r->rsi) || !ubuf(r->rdx, r->r10)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_setxattr((const char *)r->rdi, (const char *)r->rsi,
                                                 (const void *)r->rdx, r->r10);
        break;
    }
    case SYS_getxattr: {                   /* (path, name, out, max) -> read a user.* xattr (M1182) */
        if (!ustr(r->rdi) || !ustr(r->rsi) || !ubuf(r->rdx, r->r10)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_getxattr((const char *)r->rdi, (const char *)r->rsi,
                                                 (void *)r->rdx, r->r10);
        break;
    }
    case SYS_listxattr:                    /* (path, out, max) -> NUL-separated user.* names (M1182) */
        if (!ustr(r->rdi) || !ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_listxattr((const char *)r->rdi, (char *)r->rsi, r->rdx);
        break;
    case SYS_removexattr:                  /* (path, name) -> remove a user.* xattr (M1182) */
        if (!ustr(r->rdi) || !ustr(r->rsi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_removexattr((const char *)r->rdi, (const char *)r->rsi);
        break;
    /* f{set,get,list,remove}xattr (M1569): the fd-based siblings openat/fstatat's
     * own family already established a pattern for -- app_fd_path (M1221)
     * resolves an open FILE fd to its path, then straight into the SAME
     * vfs_*xattr this syscall's own path-based version already calls. */
    case SYS_fsetxattr: {                  /* (fd, name, value, vlen) -> set a user.* xattr (M1569) */
        if (!ustr(r->rsi) || !ubuf(r->rdx, r->r10)) { r->rax = (uint64_t)-1; break; }
        const char *p = app_fd_path((int)r->rdi);
        if (!p) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_setxattr(p, (const char *)r->rsi, (const void *)r->rdx, r->r10);
        break;
    }
    case SYS_fgetxattr: {                  /* (fd, name, out, max) -> read a user.* xattr (M1569) */
        if (!ustr(r->rsi) || !ubuf(r->rdx, r->r10)) { r->rax = (uint64_t)-1; break; }
        const char *p = app_fd_path((int)r->rdi);
        if (!p) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_getxattr(p, (const char *)r->rsi, (void *)r->rdx, r->r10);
        break;
    }
    case SYS_flistxattr: {                 /* (fd, out, max) -> NUL-separated user.* names (M1569) */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        const char *p = app_fd_path((int)r->rdi);
        if (!p) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_listxattr(p, (char *)r->rsi, r->rdx);
        break;
    }
    case SYS_fremovexattr: {               /* (fd, name) -> remove a user.* xattr (M1569) */
        if (!ustr(r->rsi)) { r->rax = (uint64_t)-1; break; }
        const char *p = app_fd_path((int)r->rdi);
        if (!p) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_removexattr(p, (const char *)r->rsi);
        break;
    }
    case SYS_pty_open:                     /* () -> pseudoterminal master id (M1185) */
        r->rax = (uint64_t)(int64_t)pty_open();
        break;
    case SYS_pty_read:                     /* (id, buf, max) -> bytes; 0 EOF (M1185) */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)pty_read((int)r->rdi, (void *)r->rsi, r->rdx);
        break;
    case SYS_pty_write:                    /* (id, buf, len) -> bytes (master write feeds the ldisc) (M1185) */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)pty_write((int)r->rdi, (const void *)r->rsi, r->rdx);
        break;
    case SYS_pty_close:                    /* (id) -> close one end (M1185) */
        r->rax = (uint64_t)(int64_t)pty_close((int)r->rdi);
        break;
    case SYS_pty_ctl:                      /* (id, cmd, arg) -> set mode / fg pgid (M1185) */
        r->rax = (uint64_t)(int64_t)pty_ctl((int)r->rdi, (int)r->rsi, (int)r->rdx);
        break;
    case SYS_pipe: {                       /* (int fds[2]) -> anonymous pipe (M1187) */
        if (!ubuf(r->rdi, 2 * sizeof(int))) { r->rax = (uint64_t)-1; break; }
        int fds[2];
        long rc = app_pipe(fds);
        if (rc == 0) { ((int *)r->rdi)[0] = fds[0]; ((int *)r->rdi)[1] = fds[1]; }
        r->rax = (uint64_t)(int64_t)rc;
        break;
    }
    case SYS_pipe2: {                      /* (int fds[2], flags) -> pipe + atomic O_CLOEXEC (M1239) */
        if (!ubuf(r->rdi, 2 * sizeof(int))) { r->rax = (uint64_t)-1; break; }
        int fds[2];
        long rc = app_pipe2(fds, (int)r->rsi);
        if (rc == 0) { ((int *)r->rdi)[0] = fds[0]; ((int *)r->rdi)[1] = fds[1]; }
        r->rax = (uint64_t)(int64_t)rc;
        break;
    }
    case SYS_fdread: {                     /* (fd, buf, max) -> read a pipe/socket fd (M1187) */
        /* Enable interrupts for the read (M1863): a syscall enters through the
         * 0xEE INTERRUPT gate with IF=0. A blocking read on a TCP SOCKET fd
         * (app_fd_read -> net_tcp_sock_recv -> tcp_read) uses timer_ticks()
         * DEADLINES to bound its waits -- but with IF=0 on a uniprocessor the PIT
         * never fires, so timer_ticks() is frozen and every one of those timeouts
         * becomes infinite: the read blocks until the next packet physically
         * arrives. The ring-3 TLS client (webview, M1863) hit this hard -- after
         * receiving the server's whole ServerHello+cert flight it must think +
         * send its Finished, but the intervening read never returned, so the peer
         * timed the handshake out (~15 s) and RST/FIN'd. The kernel's own
         * sys_https path never saw it because it runs in a KERNEL TASK (IF=1), not
         * this syscall. sti here (same idiom as beep/sleep above) lets the timer
         * advance so the read's own timeouts work; the iret restores the caller's
         * flags. Harmless for pipe/eventfd reads (they task_block(), which already
         * yields with IF=1). */
        __asm__ volatile("sti");
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        long n = app_fd_read((int)r->rdi, (void *)r->rsi, r->rdx);
        if (n > 0) app_io_account(0, n);   /* /proc/<pid>/io rchar (M1244) */
        r->rax = (uint64_t)(int64_t)n;
        break;
    }
    case SYS_fdwrite: {                    /* (fd, buf, len) -> write a pipe fd (M1187) */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        long n = app_fd_write((int)r->rdi, (const void *)r->rsi, r->rdx);
        if (n > 0) app_io_account(1, n);   /* /proc/<pid>/io wchar (M1244) */
        r->rax = (uint64_t)(int64_t)n;
        break;
    }
    case SYS_fdclose:                      /* (fd) -> close an fd (M1187) */
        r->rax = (uint64_t)(int64_t)app_fd_close((int)r->rdi);
        break;
    case SYS_dup2:                         /* (oldfd, newfd) -> redirect newfd (M1187) */
        r->rax = (uint64_t)(int64_t)app_dup2((int)r->rdi, (int)r->rsi);
        break;
    case SYS_dup:                          /* (fd) -> duplicate onto the lowest free fd (M1587) */
        r->rax = (uint64_t)(int64_t)app_fcntl((int)r->rdi, F_DUPFD, 0);
        break;
    case SYS_mkfifo:                       /* (path) -> create a named pipe (M1188) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_mkfifo((const char *)r->rdi);
        break;
    case SYS_fifo_open:                    /* (path, write) -> open a FIFO end -> fd (M1188) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_fifo_open((const char *)r->rdi, (int)r->rsi);
        break;
    case SYS_open:                         /* (path, flags) -> a file fd; O_RDONLY/WRONLY/APPEND/TRUNC/CREAT (M1193/M1195) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_open((const char *)r->rdi, (int)r->rsi);
        break;
    case SYS_openat: {                     /* (dirfd, path, flags) -> open relative to a dir fd (M1251) */
        char eff[256];
        if (!ustr(r->rsi) || at_resolve((long)r->rdi, (const char *)r->rsi, eff, sizeof eff) < 0) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_open(eff, (int)r->rdx);
        break;
    }
    case SYS_unlinkat: {                   /* (dirfd, path, flags) -> remove relative to a dir fd (M1251) */
        char eff[256];
        if (!ustr(r->rsi) || at_resolve((long)r->rdi, (const char *)r->rsi, eff, sizeof eff) < 0) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, eff, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_remove(eff);
        break;
    }
    case SYS_mkdirat: {                    /* (dirfd, path, mode) -> mkdir relative to a dir fd (M1251) */
        char eff[256];
        if (!ustr(r->rsi) || at_resolve((long)r->rdi, (const char *)r->rsi, eff, sizeof eff) < 0) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, eff, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_mkdir(eff);
        break;
    }
    case SYS_fstatat: {                    /* (dirfd, path, statx*, flags) -> stat relative to a dir fd (M1251) */
        char eff[256];
        if (!ustr(r->rsi) || !ubuf(r->rdx, sizeof(struct statx))) { r->rax = (uint64_t)-1; break; }
        if (at_resolve((long)r->rdi, (const char *)r->rsi, eff, sizeof eff) < 0) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_stat(eff, (struct statx *)r->rdx);
        break;
    }
    case SYS_fchmodat: {                   /* (dirfd, path, mode) -> chmod relative to a dir fd (M1553); no
                                             * AT_SYMLINK_NOFOLLOW flags arg -- unlinkat's own flags already
                                             * goes unused here too, no symlink-follow-choice infra to gate on */
        char eff[256];
        if (!ustr(r->rsi) || at_resolve((long)r->rdi, (const char *)r->rsi, eff, sizeof eff) < 0) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, eff, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_chmod(eff, (uint32_t)r->rdx);
        break;
    }
    case SYS_fchownat: {                   /* (dirfd, path, uid, gid) -> chown relative to a dir fd (M1553) */
        char eff[256];
        if (!ustr(r->rsi) || at_resolve((long)r->rdi, (const char *)r->rsi, eff, sizeof eff) < 0) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, eff, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_chown(eff, (long)r->rdx, (long)r->r10);
        break;
    }
    case SYS_symlinkat: {                  /* (target, newdirfd, linkpath) -> symlink relative to a dir fd (M1582) */
        char eff[256];
        if (!ustr(r->rdi) || !ustr(r->rdx)) { r->rax = (uint64_t)-1; break; }
        if (at_resolve((long)r->rsi, (const char *)r->rdx, eff, sizeof eff) < 0) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, eff, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_symlink(eff, (const char *)r->rdi);
        break;
    }
    case SYS_readlinkat: {                 /* (dirfd, path, buf, size) -> a symlink's target relative to a dir fd,
                                             * not followed (M1582) */
        char eff[256];
        if (!ustr(r->rsi) || !ubuf(r->rdx, r->r10)) { r->rax = (uint64_t)-1; break; }
        if (at_resolve((long)r->rdi, (const char *)r->rsi, eff, sizeof eff) < 0) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, eff, 0)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_readlink(eff, (void *)r->rdx, (unsigned long)r->r10);
        break;
    }
    case SYS_linkat: {                     /* (olddirfd, oldpath, newdirfd, newpath) -> hard link relative to dir
                                             * fds (M1585); no AT_SYMLINK_FOLLOW flags arg -- same established
                                             * simplification as fchmodat/fchownat/unlinkat, no symlink-follow-
                                             * choice infra to gate on */
        char oeff[256], neff[256];
        if (!ustr(r->rsi) || !ustr(r->r10)) { r->rax = (uint64_t)-1; break; }
        if (at_resolve((long)r->rdi, (const char *)r->rsi, oeff, sizeof oeff) < 0) { r->rax = (uint64_t)-1; break; }
        if (at_resolve((long)r->rdx, (const char *)r->r10, neff, sizeof neff) < 0) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, neff, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_link(oeff, neff);
        break;
    }
    case SYS_utimensat: {                  /* (dirfd, path, atime, mtime) -> set timestamps relative to a dir fd
                                             * (M1559); same shape as fchownat -- atime/mtime are the actual
                                             * UTIME_NOW/OMIT-sentinel-capable values directly (M1230's own
                                             * simplification), not a timespec[2]+flags pair, so no
                                             * AT_SYMLINK_NOFOLLOW here either, matching every other *at syscall */
        char eff[256];
        if (!ustr(r->rsi) || at_resolve((long)r->rdi, (const char *)r->rsi, eff, sizeof eff) < 0) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, eff, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_utimens(eff, (long)r->rdx, (long)r->r10);
        break;
    }
    case SYS_lseek:                        /* (fd, off, whence) -> reposition a file fd (M1193) */
        r->rax = (uint64_t)(int64_t)app_lseek((int)r->rdi, (long)r->rsi, (int)r->rdx);
        break;
    case SYS_pread:                        /* (fd, buf, max, off) -> read without moving the cursor (M1572) */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_pread((int)r->rdi, (void *)r->rsi, r->rdx, (long)r->r10);
        break;
    case SYS_pwrite:                       /* (fd, buf, len, off) -> write without moving the cursor (M1572) */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_pwrite((int)r->rdi, (const void *)r->rsi, r->rdx, (long)r->r10);
        break;
    case SYS_readv: {                      /* (fd, iov, iovcnt) -> read into each segment in turn (M1574);
                                             * real fds only (pipes/files/sockets/etc. -- whatever app_fd_read
                                             * already handles) -- fd 0/1/2's window-grid special case that
                                             * plain read() has is deliberately out of scope for this pass. */
        struct iovec *iov = (struct iovec *)r->rsi;
        int iovcnt = (int)r->rdx;
        if (iovcnt < 1 || iovcnt > 16 || !ubuf(r->rsi, (uint64_t)(unsigned)iovcnt * sizeof(struct iovec))) { r->rax = (uint64_t)-1; break; }
        long total = 0;
        for (int i = 0; i < iovcnt; i++) {
            if (iov[i].iov_len == 0) continue;
            if (!ubuf((uint64_t)iov[i].iov_base, iov[i].iov_len)) { total = total ? total : -1; break; }
            long n = app_fd_read((int)r->rdi, iov[i].iov_base, iov[i].iov_len);
            if (n < 0) { total = total ? total : -1; break; }
            total += n;
            if ((unsigned long)n < iov[i].iov_len) break;   /* short read (EOF/would-block) -- stop, matching real readv */
        }
        r->rax = (uint64_t)total;
        break;
    }
    case SYS_writev: {                     /* (fd, iov, iovcnt) -> write each segment in turn (M1574); same
                                             * real-fds-only scope as readv above. */
        struct iovec *iov = (struct iovec *)r->rsi;
        int iovcnt = (int)r->rdx;
        if (iovcnt < 1 || iovcnt > 16 || !ubuf(r->rsi, (uint64_t)(unsigned)iovcnt * sizeof(struct iovec))) { r->rax = (uint64_t)-1; break; }
        long total = 0;
        for (int i = 0; i < iovcnt; i++) {
            if (iov[i].iov_len == 0) continue;
            if (!ubuf((uint64_t)iov[i].iov_base, iov[i].iov_len)) { total = total ? total : -1; break; }
            long n = app_fd_write((int)r->rdi, iov[i].iov_base, iov[i].iov_len);
            if (n < 0) { total = total ? total : -1; break; }
            total += n;
            if ((unsigned long)n < iov[i].iov_len) break;   /* short write -- stop */
        }
        r->rax = (uint64_t)total;
        break;
    }
    case SYS_preadv: {                     /* (fd, iov, iovcnt, offset) -> like readv, but at an explicit
                                             * offset that advances per-segment, cursor never touched (M1577) --
                                             * app_pread (M1572) is the exact per-segment primitive this needed. */
        struct iovec *iov = (struct iovec *)r->rsi;
        int iovcnt = (int)r->rdx;
        long off = (long)r->r10;
        if (iovcnt < 1 || iovcnt > 16 || !ubuf(r->rsi, (uint64_t)(unsigned)iovcnt * sizeof(struct iovec))) { r->rax = (uint64_t)-1; break; }
        long total = 0;
        for (int i = 0; i < iovcnt; i++) {
            if (iov[i].iov_len == 0) continue;
            if (!ubuf((uint64_t)iov[i].iov_base, iov[i].iov_len)) { total = total ? total : -1; break; }
            long n = app_pread((int)r->rdi, iov[i].iov_base, iov[i].iov_len, off);
            if (n < 0) { total = total ? total : -1; break; }
            total += n; off += n;
            if ((unsigned long)n < iov[i].iov_len) break;
        }
        r->rax = (uint64_t)total;
        break;
    }
    case SYS_pwritev: {                    /* (fd, iov, iovcnt, offset) -> like writev, at an explicit
                                             * offset, cursor never touched (M1577); app_pwrite's per-segment. */
        struct iovec *iov = (struct iovec *)r->rsi;
        int iovcnt = (int)r->rdx;
        long off = (long)r->r10;
        if (iovcnt < 1 || iovcnt > 16 || !ubuf(r->rsi, (uint64_t)(unsigned)iovcnt * sizeof(struct iovec))) { r->rax = (uint64_t)-1; break; }
        long total = 0;
        for (int i = 0; i < iovcnt; i++) {
            if (iov[i].iov_len == 0) continue;
            if (!ubuf((uint64_t)iov[i].iov_base, iov[i].iov_len)) { total = total ? total : -1; break; }
            long n = app_pwrite((int)r->rdi, iov[i].iov_base, iov[i].iov_len, off);
            if (n < 0) { total = total ? total : -1; break; }
            total += n; off += n;
            if ((unsigned long)n < iov[i].iov_len) break;
        }
        r->rax = (uint64_t)total;
        break;
    }
    case SYS_madvise:                      /* (addr, len, advice) -> MADV_DONTNEED reclaims resident anon pages */
        r->rax = (uint64_t)(int64_t)app_madvise(r->rdi, r->rsi, (int)r->rdx);
        break;
    case SYS_process_madvise:              /* (pidfd, addr, len, advice) -> MADV_COLD on another process (M1555) */
        r->rax = (uint64_t)(int64_t)app_process_madvise((int)r->rdi, r->rsi, r->rdx, (int)r->r10);
        break;
    case SYS_mincore: {                    /* (addr, len, vec) -> per-page residency of an mmap range (M1147) */
        uint64_t np = (r->rsi + PAGE_SIZE - 1) / PAGE_SIZE;     /* vec needs one byte per page */
        if (r->rsi == 0 || !ubuf(r->rdx, np)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_mincore(r->rdi, r->rsi, (uint8_t *)r->rdx);
        break;
    }
    case SYS_mlock:                        /* (addr, len) -> pin mmap pages against reclaim (M1149) */
        r->rax = (uint64_t)(int64_t)app_mlock(r->rdi, r->rsi);
        break;
    case SYS_munlock:                      /* (addr, len) -> unpin mlock'd mmap pages (M1149) */
        r->rax = (uint64_t)(int64_t)app_munlock(r->rdi, r->rsi);
        break;
    case SYS_getrusage: {                  /* (who, struct rusage*) -> resource usage of the caller (M1150) */
        if (!ubuf(r->rsi, sizeof(struct rusage))) { r->rax = (uint64_t)-1; break; }
        struct rusage ru;
        for (unsigned i = 0; i < sizeof ru; i++) ((uint8_t *)&ru)[i] = 0;
        if ((long)r->rdi == RUSAGE_SELF) {          /* RUSAGE_CHILDREN -> all-zero (no child-time accounting) */
            task_t *t = task_self();
            if (t) {
                ru.ru_utime.tv_sec = (long)(t->utime_ms / 1000); ru.ru_utime.tv_usec = (long)((t->utime_ms % 1000) * 1000);
                ru.ru_stime.tv_sec = (long)(t->stime_ms / 1000); ru.ru_stime.tv_usec = (long)((t->stime_ms % 1000) * 1000);
                ru.ru_nvcsw = (long)t->nvcsw; ru.ru_nivcsw = (long)t->nivcsw;
            }
            uint64_t mn = 0, mj = 0; app_self_faults(&mn, &mj);
            ru.ru_minflt = (long)mn; ru.ru_majflt = (long)mj;
            vmm_wss_t w; vmm_wss(app_cr3(app_current()), &w);
            ru.ru_maxrss = (long)(w.resident * PAGE_SIZE / 1024);   /* resident pages -> KiB */
        }
        for (unsigned i = 0; i < sizeof ru; i++) ((uint8_t *)r->rsi)[i] = ((uint8_t *)&ru)[i];
        r->rax = 0;
        break;
    }
    case SYS_times: {                      /* (struct tms*) -> CPU times in 100Hz ticks; returns boot ticks (M1235) */
        if (!ubuf(r->rdi, sizeof(struct tms))) { r->rax = (uint64_t)-1; break; }
        struct tms tm;
        for (unsigned i = 0; i < sizeof tm; i++) ((uint8_t *)&tm)[i] = 0;
        task_t *t = task_self();
        if (t) { tm.tms_utime = (long)(t->utime_ms / 10); tm.tms_stime = (long)(t->stime_ms / 10); }
        /* tms_cutime/tms_cstime: no reaped-child CPU accounting -> 0 */
        for (unsigned i = 0; i < sizeof tm; i++) ((uint8_t *)r->rdi)[i] = ((uint8_t *)&tm)[i];
        r->rax = (uint64_t)(timer_ms() / 10);   /* clock_t: elapsed ticks since boot */
        break;
    }
    case SYS_uname: {                      /* (struct utsname*) -> system identity strings (M1236) */
        if (!ubuf(r->rdi, sizeof(struct utsname))) { r->rax = (uint64_t)-1; break; }
        struct utsname u;
        for (unsigned i = 0; i < sizeof u; i++) ((uint8_t *)&u)[i] = 0;
        const char *src[5] = { "OS-DEV", g_hostname, "1.0", "#1 x86_64 " __DATE__, "x86_64" };
        char *dst[5] = { u.sysname, u.nodename, u.release, u.version, u.machine };
        for (int f = 0; f < 5; f++) { const char *s = src[f]; char *d = dst[f]; int i = 0; while (s[i] && i < 64) { d[i] = s[i]; i++; } d[i] = 0; }
        for (unsigned i = 0; i < sizeof u; i++) ((uint8_t *)r->rdi)[i] = ((uint8_t *)&u)[i];
        r->rax = 0;
        break;
    }
    case SYS_getppid: r->rax = (uint64_t)app_sys_getppid(); break;   /* (M1236) */
    case SYS_getuid: case SYS_getgid:                                /* single-user: uid/gid are root (0) (M1236) */
    case SYS_geteuid: case SYS_getegid: r->rax = 0; break;
    case SYS_sethostname: {                /* (buf, len) -> set the system hostname (M1237) */
        uint64_t len = r->rsi;
        if (len >= sizeof g_hostname) len = sizeof g_hostname - 1;
        if (!ubuf(r->rdi, len)) { r->rax = (uint64_t)-1; break; }
        const char *s = (const char *)r->rdi;
        unsigned i = 0; for (; i < len; i++) g_hostname[i] = s[i];
        g_hostname[i] = 0;
        r->rax = 0;
        break;
    }
    case SYS_gethostname: {                /* (buf, len) -> copy the system hostname (M1237) */
        uint64_t len = r->rsi;
        if (!ubuf(r->rdi, len) || len == 0) { r->rax = (uint64_t)-1; break; }
        char *d = (char *)r->rdi;
        unsigned i = 0; for (; g_hostname[i] && i + 1 < len; i++) d[i] = g_hostname[i];
        d[i] = 0;
        r->rax = 0;
        break;
    }
    case SYS_fiemap: {                     /* (path, struct fiemap_extent*, max) -> physical extent map (M1152) */
        int umax = (int)r->rdx;
        if (umax <= 0 || !ustr(r->rdi) || !ubuf(r->rsi, (uint64_t)umax * sizeof(struct fiemap_extent))) { r->rax = (uint64_t)-1; break; }
        ext2_extent_t kext[64];
        int cap = umax < 64 ? umax : 64;
        int n = vfs_fiemap((const char *)r->rdi, kext, cap);
        if (n < 0) { r->rax = (uint64_t)-1; break; }
        struct fiemap_extent *u = (struct fiemap_extent *)r->rsi;
        for (int i = 0; i < n; i++) {      /* map the kernel extents into the user ABI struct + mark the last */
            struct fiemap_extent e;
            e.fe_logical = kext[i].logical; e.fe_physical = kext[i].physical; e.fe_length = kext[i].length;
            e.fe_flags = (i == n - 1) ? FIEMAP_EXTENT_LAST : 0; e._pad = 0;
            for (unsigned b = 0; b < sizeof e; b++) ((uint8_t *)&u[i])[b] = ((uint8_t *)&e)[b];
        }
        r->rax = (uint64_t)n;
        break;
    }
    case SYS_fallocate:                    /* (path, mode, offset, len) -> punch a hole (M1153) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        if ((int)r->rsi & FALLOC_FL_PUNCH_HOLE)
            r->rax = (uint64_t)(int64_t)vfs_punch_hole((const char *)r->rdi, r->rdx, r->r10);
        else
            r->rax = (uint64_t)-1;         /* only PUNCH_HOLE is supported for now */
        break;
    case SYS_mq_open:                      /* (name, maxmsg, msgsize) -> priority msg queue index (M1154) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)mqueue_open((const char *)r->rdi, (int)r->rsi, (int)r->rdx);
        break;
    case SYS_mq_unlink:                    /* (name) -> remove a named message queue (M1593) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)mqueue_unlink((const char *)r->rdi);
        break;
    case SYS_mq_send:                      /* (idx, buf, len, prio) -> enqueue (M1154) */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)mqueue_send((int)r->rdi, (const void *)r->rsi, r->rdx, (unsigned)r->r10);
        break;
    case SYS_mq_receive:                   /* (idx, buf, max, uint*prio) -> dequeue highest prio (M1154) */
        if (!ubuf(r->rsi, r->rdx) || (r->r10 && !ubuf(r->r10, sizeof(unsigned int)))) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)mqueue_receive((int)r->rdi, (void *)r->rsi, r->rdx, (unsigned int *)r->r10);
        break;
    case SYS_mq_getattr: {                 /* (idx, struct mq_attr*) -> read flags/maxmsg/msgsize/curmsgs (M1571) */
        if (!ubuf(r->rsi, sizeof(struct mq_attr))) { r->rax = (uint64_t)-1; break; }
        struct mq_attr *out = (struct mq_attr *)r->rsi;
        r->rax = (uint64_t)(int64_t)mqueue_getattr((int)r->rdi, &out->mq_flags, &out->mq_maxmsg, &out->mq_msgsize, &out->mq_curmsgs);
        break;
    }
    case SYS_mq_setattr: {                 /* (idx, newattr*, oldattr* or 0) -> set O_NONBLOCK only (M1571);
                                             * mq_maxmsg/mq_msgsize in *newattr are ignored, matching real
                                             * mq_setattr -- those are fixed at mq_open time. */
        if (!ubuf(r->rsi, sizeof(struct mq_attr)) || (r->rdx && !ubuf(r->rdx, sizeof(struct mq_attr)))) { r->rax = (uint64_t)-1; break; }
        struct mq_attr *newattr = (struct mq_attr *)r->rsi;
        long old_flags = 0;
        long rc = mqueue_setattr((int)r->rdi, newattr->mq_flags, &old_flags);
        if (rc == 0 && r->rdx) {           /* *oldattr, if requested, gets the FULL previous attr set */
            struct mq_attr *oldattr = (struct mq_attr *)r->rdx;
            oldattr->mq_flags = old_flags;
            mqueue_getattr((int)r->rdi, 0, &oldattr->mq_maxmsg, &oldattr->mq_msgsize, &oldattr->mq_curmsgs);
        }
        r->rax = (uint64_t)rc;
        break;
    }
    case SYS_swapout:                      /* (addr, len) -> page out anon pages to swap */
        __asm__ volatile("sti");           /* the disk writes may wait on an IRQ (virtio) */
        r->rax = (uint64_t)(int64_t)app_swap_out(r->rdi, r->rsi);
        break;
    case SYS_shm_open:                     /* (name, size) -> map a named shared-memory object */
        if (!ustr(r->rdi)) { r->rax = 0; break; }
        r->rax = app_shm_open((const char *)r->rdi, r->rsi);
        break;
    case SYS_shm_unlink:                   /* (name) -> remove the name -> object association (M1590) */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)shm_unlink((const char *)r->rdi);
        break;
    case SYS_futex:                        /* (uaddr, op, val, timeout_ms) -> FUTEX_WAIT/WAKE; timeout_ms<0 = wait forever (M1578) */
        r->rax = (uint64_t)(int64_t)app_futex(r->rdi, (int)r->rsi, (int)r->rdx, (long)r->r10);
        break;
    case SYS_losetup: {                    /* (path) -> mount a FS image file as a loop device */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        uint64_t cap = 4u * 1024 * 1024;   /* image size limit */
        uint8_t *img = kmalloc(cap);
        if (!img) { r->rax = (uint64_t)-1; break; }
        long n = vfs_read((const char *)r->rdi, img, cap);
        int idx = (n > 1024) ? blockdev_losetup(img, (uint64_t)n) : -1;
        if (idx < 0) kfree(img);           /* not a recognised FS -> losetup kept nothing */
        r->rax = (uint64_t)(int64_t)idx;
        break;
    }
    case SYS_ringbuf:                      /* (len): a magic mirrored ring buffer; base VA or 0 */
        r->rax = app_ringbuf(r->rdi);
        break;
    case SYS_mprotect:                     /* (addr, len, prot): change R/W/X of a mapped range */
        r->rax = (uint64_t)(int64_t)app_mprotect(r->rdi, r->rsi, (int)r->rdx);
        break;
    case SYS_mseal:                        /* (addr, len): irreversibly seal mmap regions (M1130) */
        r->rax = (uint64_t)(int64_t)app_mseal(r->rdi, r->rsi);
        break;
    case SYS_mmap_file:                    /* (path, len, shared): file-backed mmap (M1136; shared=MAP_SHARED, M1544) */
        if (!ustr(r->rdi)) { r->rax = 0; break; }
        r->rax = app_mmap_file((const char *)r->rdi, r->rsi, (int)r->rdx);
        break;
    case SYS_msync:                        /* (addr, len): flush a MAP_SHARED file-backed mmap's dirty pages to disk (M1544) */
        r->rax = (uint64_t)(int64_t)app_msync(r->rdi, r->rsi);
        break;
    case SYS_clone:                        /* (fn, stack, arg): spawn a thread sharing this AS (M1138) */
        r->rax = (uint64_t)app_clone(r, r->rdi, r->rsi, r->rdx);
        break;
    case SYS_gettid:                       /* (): the calling thread's id (M1138) */
        r->rax = (uint64_t)(int64_t)app_gettid();
        break;
    case SYS_thread_exit:                  /* (): end just this thread (M1138) */
        app_thread_exit();                 /* does not return to this task */
        break;
    case SYS_join:                         /* (tid): wait for a thread to exit + reap it (M1139) */
        r->rax = (uint64_t)app_join((int)r->rdi);
        break;
    case SYS_set_tls:                      /* (base): set this thread's %fs TLS base (M1140) */
        task_set_fs_base(r->rdi);          /* a bare base; ring-3 %fs accesses are CPU-checked */
        r->rax = 0;
        break;
    case SYS_set_robust_list:              /* (robust_t*): register this thread's robust-futex list (M1141) */
        task_set_robust(r->rdi);           /* stored only; validated when walked on thread exit */
        r->rax = 0;
        break;
    case SYS_overlay:                      /* (lower, upper): mount a union overlay at /over (M1142) */
        if (!ustr(r->rdi) || !ustr(r->rsi)) { r->rax = (uint64_t)-1; break; }
        vfs_overlay_mount((const char *)r->rdi, (const char *)r->rsi);
        r->rax = 0;
        break;
    case SYS_uffd_register:                /* (addr, len): route this region's faults to a monitor (M1134) */
        r->rax = (uint64_t)(int64_t)app_uffd_register(r->rdi, r->rsi);
        break;
    case SYS_uffd_read:                    /* (): monitor blocks until a fault; returns the faulting addr */
        __asm__ volatile("sti");           /* may block; the scheduler needs the timer */
        r->rax = (uint64_t)app_uffd_read();
        break;
    case SYS_uffd_copy:                    /* (addr, data, len): fill the faulting page + wake the owner */
        if (!ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_uffd_copy(r->rdi, (const void *)r->rsi, r->rdx);
        break;
    case SYS_tcp_serve: {                  /* (port, resp, resp_len, reqbuf, reqmax): serve one TCP conn (M1133) */
        const uint8_t *resp = (const uint8_t *)r->rsi; int resp_len = (int)r->rdx;
        uint8_t *reqbuf = (uint8_t *)r->r10;           int reqmax  = (int)r->r8;
        if (resp_len < 0 || reqmax < 0 ||
            (resp_len && !ubuf(r->rsi, (uint64_t)resp_len)) ||
            (reqmax  && !ubuf(r->r10, (uint64_t)reqmax))) { r->rax = (uint64_t)-1; break; }
        __asm__ volatile("sti");           /* the poll deadlines need the timer running */
        r->rax = (uint64_t)(int64_t)net_tcp_serve((uint16_t)r->rdi, resp, resp_len, reqbuf, reqmax, 300 /*~3s*/);
        break;
    }
    case SYS_tcp_accept: {                  /* (port, reqbuf, reqmax): passive-open + read one request, hold the conn (M1327) */
        uint8_t *reqbuf = (uint8_t *)r->rsi; int reqmax = (int)r->rdx;
        if (reqmax < 0 || (reqmax && !ubuf(r->rsi, (uint64_t)reqmax))) { r->rax = (uint64_t)-1; break; }
        __asm__ volatile("sti");
        r->rax = (uint64_t)(int64_t)net_tcp_accept((uint16_t)r->rdi, reqbuf, reqmax, 300 /*~3s*/);
        break;
    }
    case SYS_tcp_respond: {                 /* (resp, resp_len): reply on the accepted conn + close (M1327) */
        const uint8_t *resp = (const uint8_t *)r->rdi; int resp_len = (int)r->rsi;
        if (resp_len < 0 || (resp_len && !ubuf(r->rdi, (uint64_t)resp_len))) { r->rax = (uint64_t)-1; break; }
        __asm__ volatile("sti");
        r->rax = (uint64_t)(int64_t)net_tcp_respond(resp, resp_len);
        break;
    }
    case SYS_bind:                         /* (from, to): graft FROM's subtree onto the path TO */
        if (!ustr(r->rdi) || !ustr(r->rsi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_bind((const char *)r->rdi, (const char *)r->rsi);
        break;
    case SYS_unshare:                      /* detach into a private mount namespace (M1122) */
        r->rax = (uint64_t)(int64_t)vfs_unshare();
        break;
    case SYS_singlestep:                   /* hardware single-step the next n user instructions (M1123) */
        r->rax = (uint64_t)(int64_t)app_singlestep(r, (int)r->rdi);
        break;
    case SYS_ptrace:                       /* (request, pid, addr, data): trace a child process (M1199) */
        r->rax = (uint64_t)app_ptrace((long)r->rdi, (int)r->rsi, r->rdx, r->r10);
        break;
    case SYS_seccomp:                      /* child: trap syscall `nr` to the supervisor (M1124) */
        r->rax = (uint64_t)(int64_t)app_seccomp_arm((int)r->rdi);
        break;
    case SYS_seccomp_filter: {             /* install a self-imposed BPF syscall filter (M1190) */
        unsigned long bytes = r->rsi;
        if (!ubuf(r->rdi, bytes) || bytes % 8 != 0) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_seccomp_filter_install((const void *)r->rdi, (int)(bytes / 8));
        break;
    }
    case SYS_bpf_trace: {                  /* load the global syscall-tracepoint BPF program (M1202) */
        unsigned long bytes = r->rsi;
        if (bytes && (!ubuf(r->rdi, bytes) || bytes % sizeof(struct bpf_insn) != 0)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)bpf_trace_load((const void *)r->rdi, bytes);
        break;
    }
    case SYS_bpf_map_get:                  /* read a BPF histogram cell (M1202) */
        r->rax = bpf_map_get((unsigned)r->rdi);
        break;
    case SYS_seccomp_wait: {               /* supervisor: block until the child parks; fill ev[4] */
        uint64_t *uev = (uint64_t *)r->rsi;
        if (!ubuf(r->rsi, 4 * sizeof(uint64_t))) { r->rax = (uint64_t)-1; break; }
        uint64_t kev[4] = {0,0,0,0};
        long rc = app_seccomp_wait((int)r->rdi, kev);
        if (rc > 0) for (int i = 0; i < 4; i++) uev[i] = kev[i];   /* copy out (supervisor's space active) */
        r->rax = (uint64_t)rc;
        break;
    }
    case SYS_seccomp_reply:                /* supervisor: deliver the verdict (M1124) */
        r->rax = (uint64_t)(int64_t)app_seccomp_reply((int)r->rdi, (int)r->rsi, (long)r->rdx);
        break;
    case SYS_fswait: {                     /* block until one of n paths is readable (select/poll, M1125) */
        const char *p = (const char *)r->rdi; int n = (int)r->rsi; long timeout = (long)r->rdx;
        const char *names[8];
        if (n < 1 || n > 8) { r->rax = (uint64_t)-1; break; }
        int bad = 0;
        for (int i = 0; i < n; i++) {       /* validate + collect the NUL-separated names */
            if (!ustr((uint64_t)(uintptr_t)p)) { bad = 1; break; }
            names[i] = p; while (*p) p++; p++;   /* advance past this name's NUL */
        }
        if (bad) { r->rax = (uint64_t)-1; break; }
        __asm__ volatile("sti");            /* the poll loop sleeps on the timer */
        uint64_t start = timer_ms();
        long idx = -1;
        for (;;) {
            for (int i = 0; i < n; i++) if (vfs_ready(names[i])) { idx = i; break; }
            if (idx >= 0) break;
            if (timeout >= 0 && (long)(timer_ms() - start) >= timeout) break;   /* -1 = timeout */
            task_sleep_ms(10);              /* off-CPU poll interval */
        }
        r->rax = (uint64_t)idx;
        break;
    }
    case SYS_poll: {                       /* readiness-multiplex an fd set over the fd table (M1210) */
        struct pollfd *fds = (struct pollfd *)r->rdi;
        int nfds = (int)r->rsi; long timeout = (long)r->rdx;
        if (nfds < 1 || nfds > 64 || !ubuf(r->rdi, (uint64_t)(unsigned)nfds * sizeof(struct pollfd))) { r->rax = (uint64_t)-1; break; }
        app_t *self = app_current();
        __asm__ volatile("sti");           /* the poll loop sleeps on the timer */
        uint64_t start = timer_ms();
        int ready = 0;
        for (;;) {
            ready = 0;
            for (int i = 0; i < nfds; i++) {
                int re = app_fd_ready(self, fds[i].fd, fds[i].events);
                fds[i].revents = (short)re;
                if (re) ready++;
            }
            if (ready) break;
            if (timeout >= 0 && (long)(timer_ms() - start) >= timeout) break;   /* -1 = block forever */
            task_sleep_ms(10);             /* off-CPU poll interval */
        }
        r->rax = (uint64_t)ready;
        break;
    }
    case SYS_select: {                     /* (nfds, readfds*, writefds*, exceptfds*, timeout*) (M1584) */
        int nfds = (int)r->rdi;
        fd_set *rfds = (fd_set *)r->rsi, *wfds = (fd_set *)r->rdx, *efds = (fd_set *)r->r10;
        struct timeval *tv = (struct timeval *)r->r8;
        if (nfds < 0 || nfds > FD_SETSIZE) { r->rax = (uint64_t)-1; break; }   /* this fd_set's own bit width */
        if ((rfds && !ubuf(r->rsi, sizeof(fd_set))) || (wfds && !ubuf(r->rdx, sizeof(fd_set))) ||
            (efds && !ubuf(r->r10, sizeof(fd_set))) || (tv && !ubuf(r->r8, sizeof(struct timeval)))) {
            r->rax = (uint64_t)-1; break;
        }
        app_t *self = app_current();
        long timeout_ms = tv ? (long)(tv->tv_sec * 1000 + tv->tv_usec / 1000) : -1;   /* no timeval = block forever */
        fd_set orig_r = rfds ? *rfds : (fd_set){0};
        fd_set orig_w = wfds ? *wfds : (fd_set){0};
        if (efds) *efds = (fd_set){0};      /* no OOB/urgent-data concept here -- always empty */
        __asm__ volatile("sti");           /* the select loop sleeps on the timer */
        uint64_t start = timer_ms();
        int ready = 0, badfd = 0;
        for (;;) {
            ready = 0; badfd = 0;
            fd_set outr = {0}, outw = {0};
            for (int fd = 0; fd < nfds; fd++) {
                int want = 0;
                if (rfds && FD_ISSET(fd, &orig_r)) want |= POLLIN;
                if (wfds && FD_ISSET(fd, &orig_w)) want |= POLLOUT;
                if (!want) continue;
                int re = app_fd_ready(self, fd, want);
                if (re == POLLNVAL) { badfd = 1; break; }   /* a never-opened fd -> EBADF, like real select (M1584) */
                if ((want & POLLIN)  && (re & POLLIN))  { FD_SET(fd, &outr); ready++; }
                if ((want & POLLOUT) && (re & POLLOUT)) { FD_SET(fd, &outw); ready++; }
            }
            if (badfd) { ready = -1; break; }
            if (ready || (timeout_ms >= 0 && (long)(timer_ms() - start) >= timeout_ms)) {
                if (rfds) *rfds = outr;
                if (wfds) *wfds = outw;
                break;
            }
            task_sleep_ms(10);             /* off-CPU poll interval, same as poll/ppoll */
        }
        r->rax = (uint64_t)ready;
        break;
    }
    case SYS_ppoll: {                      /* (fds, nfds, timeout_ms, sigmask) -> like poll, but breaks early
                                             * on a deliverable signal (M1573) -- the exact same wrapper
                                             * epoll_pwait (M1567) already applies to epoll_wait's own loop,
                                             * applied to poll's. */
        struct pollfd *fds = (struct pollfd *)r->rdi;
        int nfds = (int)r->rsi; long timeout = (long)r->rdx;
        if (nfds < 1 || nfds > 64 || !ubuf(r->rdi, (uint64_t)(unsigned)nfds * sizeof(struct pollfd))) { r->rax = (uint64_t)-1; break; }
        app_t *self = app_current();
        uint32_t old_mask = app_sigprocmask(2 /* SIG_SETMASK */, (uint32_t)r->r10);
        app_kill_check();
        __asm__ volatile("sti");
        uint64_t start = timer_ms();
        int ready = 0, interrupted = 0;
        for (;;) {
            ready = 0;
            for (int i = 0; i < nfds; i++) {
                int re = app_fd_ready(self, fds[i].fd, fds[i].events);
                fds[i].revents = (short)re;
                if (re) ready++;
            }
            if (ready) break;
            if (app_signal_deliverable()) { interrupted = 1; break; }
            if (timeout >= 0 && (long)(timer_ms() - start) >= timeout) break;
            task_sleep_ms(10);
        }
        if (interrupted) { r->rax = (uint64_t)-1; app_deliver_pending(r); }   /* r->rax baked in before the snapshot (M1561) */
        else r->rax = (uint64_t)ready;
        app_sigprocmask(2, old_mask);
        break;
    }
    case SYS_splice:                       /* zero-copy pipe->pipe move, consuming the source (M1211) */
        r->rax = (uint64_t)app_splice((int)r->rdi, (int)r->rsi, (unsigned long)r->rdx);
        break;
    case SYS_tee:                          /* duplicate pipe->pipe without consuming the source (M1211) */
        r->rax = (uint64_t)app_tee((int)r->rdi, (int)r->rsi, (unsigned long)r->rdx);
        break;
    case SYS_memfd_create: {               /* anonymous, sealable in-RAM file fd (M1212) */
        const char *name = (const char *)r->rdi;
        if (r->rdi && !ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_memfd_create(name, (int)r->rsi);
        break;
    }
    case SYS_memfd_seal:                   /* add F_SEAL_* (one-way); returns the new seal set (M1212) */
        r->rax = (uint64_t)app_memfd_seal((int)r->rdi, (unsigned)r->rsi);
        break;
    case SYS_ftruncate:                    /* resize a memfd, seal-checked (M1212) */
        r->rax = (uint64_t)app_ftruncate((int)r->rdi, (long)r->rsi);
        break;
    case SYS_fsync: case SYS_fdatasync:    /* (fd) -> 0 for a real file fd, -1 otherwise (M1566) */
        r->rax = (uint64_t)app_fsync((int)r->rdi);
        break;
    case SYS_sync_file_range:              /* (fd, offset, nbytes, flags) -> same as fsync (M1566) */
        r->rax = (uint64_t)app_sync_file_range((int)r->rdi, (uint64_t)r->rsi, (uint64_t)r->rdx, (unsigned)r->r10);
        break;
    case SYS_sync:                         /* () -> whole-system flush, never fails (M1588) */
        app_sync();
        r->rax = 0;
        break;
    case SYS_signalfd:                     /* route masked signals to /proc/self/sigfd (M1126) */
        r->rax = (uint64_t)(int64_t)app_signalfd((uint32_t)r->rdi);
        break;
    case SYS_fanotify_serve:               /* become the /fan materialization daemon (M1128) */
        r->rax = (uint64_t)(int64_t)fanfs_serve();
        break;
    case SYS_fanotify_wait: {              /* daemon: block until a /fan read request */
        char *ub = (char *)r->rsi; int max = (int)r->rdx;
        if (max <= 0 || !ubuf(r->rsi, (uint64_t)max)) { r->rax = (uint64_t)-1; break; }
        char kb[80]; int km = max < 80 ? max : 80;
        long n = fanfs_wait(kb, km);
        if (n > 0) for (long i = 0; i < n; i++) ub[i] = kb[i];   /* copy out (daemon's space active) */
        r->rax = (uint64_t)n;
        break;
    }
    case SYS_fanotify_provide:             /* daemon: hand bytes back to the blocked reader */
        if (!ubuf(r->rdi, r->rsi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)fanfs_provide((const void *)r->rdi, r->rsi);
        break;
    case SYS_io_uring_enter:               /* drain a userspace submission ring (M1129) */
        r->rax = (uint64_t)io_uring_enter(r->rdi);   /* validates the ring + each SQE pointer */
        break;
    case SYS_signal:                       /* (signo, handler, restorer): install a handler */
        app_signal_set((int)r->rdi, r->rsi, r->rdx);
        r->rax = 0;
        break;
    case SYS_sigaction:                    /* (signo, handler, restorer, flags): handler w/ sa_flags (M1270) */
        app_sigaction((int)r->rdi, r->rsi, r->rdx, (uint32_t)r->r10);
        r->rax = 0;
        break;
    case SYS_sigqueue:                     /* (pid, signo, value): queue an RT signal w/ a sigval payload (M1271) */
        r->rax = (uint64_t)(long)app_sigqueue((int)r->rdi, (int)r->rsi, r->rdx);
        break;
    case SYS_timer_create:                 /* (clockid, signo, value): create a POSIX interval timer (M1272) */
        r->rax = (uint64_t)app_timer_create((int)r->rsi, r->rdx);   /* clockid (rdi) is advisory; deadlines are uptime-ms */
        break;
    case SYS_timer_settime:                /* (id, flags, value_ms, interval_ms): arm/disarm (M1272) */
        r->rax = (uint64_t)app_timer_settime((int)r->rdi, (int)r->rsi & TIMER_ABSTIME, r->rdx, r->r10);
        break;
    case SYS_timer_gettime:                /* (id): ms until next fire (M1272) */
        r->rax = (uint64_t)app_timer_gettime((int)r->rdi);
        break;
    case SYS_timer_delete:                 /* (id): destroy the timer (M1272) */
        r->rax = (uint64_t)app_timer_delete((int)r->rdi);
        break;
    case SYS_hpet:                         /* (what): HPET high-res clock — 0=ns 1=hz 2=counter 3=present (M1273) */
        switch ((int)r->rdi) {
            case 1:  r->rax = hpet_hz();      break;
            case 2:  r->rax = hpet_counter(); break;
            case 3:  r->rax = (uint64_t)hpet_present(); break;
            default: r->rax = hpet_ns();      break;
        }
        break;
    case SYS_ptsname:                      /* (fd): the /dev/pts/<n> index for a /dev/ptmx master fd (M1274) */
        r->rax = (uint64_t)app_pts_number((int)r->rdi);
        break;
    case SYS_oom:                          /* (cmd,arg): OOM killer — set adj / trigger kill / get score (M1275) */
        r->rax = (uint64_t)app_oom((int)r->rdi, (int)r->rsi);
        break;
    case SYS_sigaltstack:                  /* (ss_sp, ss_size): set the alternate signal stack (M1276) */
        r->rax = (uint64_t)app_sigaltstack(r->rdi, r->rsi);
        break;
    case SYS_clock_settime:                /* (clockid, sec, nsec): set the wall clock (M1280) */
        if ((int)r->rdi == CLOCK_REALTIME) {   /* rebase realtime + refresh the vDSO page now (don't wait a tick) */
            vdso_set_realtime(r->rsi); vdso_tick(timer_ticks()); r->rax = 0;
        } else r->rax = (uint64_t)-1;          /* CLOCK_MONOTONIC is not settable */
        break;
    case SYS_pidfd_getfd:                  /* (pidfd, targetfd, flags): duplicate another process's fd (M1281) */
        r->rax = (uint64_t)(int64_t)app_pidfd_getfd((int)r->rdi, (int)r->rsi);
        break;
    case SYS_mlockall:                     /* (flags): pin all current/future pages (M1283) */
        r->rax = (uint64_t)(int64_t)app_mlockall((int)r->rdi);
        break;
    case SYS_munlockall:                   /* (): unpin all pages (M1283) */
        r->rax = (uint64_t)(int64_t)app_munlockall();
        break;
    case SYS_aslr:                         /* (pid): the ASLR-randomized mmap base of pid (M1287) */
        r->rax = app_aslr_base((int)r->rdi);
        break;
    case SYS_acpi:                         /* (what): ACPI AML namespace query (M1284) */
        switch ((int)r->rdi) {
            case 1:  r->rax = (uint64_t)aml_count(AML_DEVICE); break;
            case 2:  r->rax = (uint64_t)aml_count(AML_METHOD); break;
            case 3:  r->rax = (uint64_t)aml_has("PCI0"); break;
            case 4:  r->rax = (uint64_t)aml_has("_SB_"); break;
            case 5:  r->rax = (uint64_t)(int64_t)aml_eval_s5(); break;      /* AML-evaluate \\_S5_ (M1286) */
            case 6:  r->rax = (uint64_t)(int64_t)acpi_s5_values(); break;   /* the byte-scan value, to cross-check (M1286) */
            default: r->rax = (uint64_t)aml_count(0); break;   /* 0 = total objects */
        }
        break;
    case SYS_raise:                        /* (signo): queue the signal; delivered to a handler at this
                                            * syscall's return (app_deliver_pending tail), or left pending
                                            * for signalfd if it has no handler (M1126). */
        r->rax = 0;
        /* ptrace: if this process is traced, raise() becomes a trace-stop that
         * parks it + notifies the tracer (returns here when continued). */
        if (!app_trace_on_signal((app_t *)app_current(), (int)r->rdi))
            app_request_signal((app_t *)app_current(), (int)r->rdi);
        break;
    case SYS_sigreturn:                    /* return from a handler: restore the saved context */
        app_sigreturn(r);
        break;
    case SYS_alarm:                        /* (ticks): arm a periodic SIGALRM (0 = disarm) */
        app_set_alarm(r->rdi);
        r->rax = 0;
        break;
    case SYS_setitimer:                    /* (delay_ticks, interval_ticks) -> ITIMER_REAL; 0 (M1565) */
        app_setitimer(r->rdi, r->rsi);
        r->rax = 0;
        break;
    case SYS_getitimer: {                  /* (remain_ticks*, interval_ticks*) -> 0/-1 (M1565) */
        if ((r->rdi && !ubuf(r->rdi, sizeof(uint64_t))) || (r->rsi && !ubuf(r->rsi, sizeof(uint64_t)))) { r->rax = (uint64_t)-1; break; }
        uint64_t remain = 0, interval = 0;
        app_getitimer(&remain, &interval);
        if (r->rdi) *(uint64_t *)r->rdi = remain;
        if (r->rsi) *(uint64_t *)r->rsi = interval;
        r->rax = 0;
        break;
    }
    case SYS_uptime_ms:
        r->rax = timer_ms();               /* monotonic milliseconds since boot */
        break;
    case SYS_gfx_init:
        r->rax = (uint64_t)(int64_t)app_gfx_init((int)r->rdi, (int)r->rsi);
        break;
    case SYS_gfx_blit:
        r->rax = (uint64_t)(int64_t)app_gfx_blit((const uint32_t *)r->rdi);
        break;
    case SYS_setkbmode:
        app_set_rawkb((int)r->rdi);
        break;
    case SYS_caret:
        app_set_caret((int)r->rdi);
        break;
    case SYS_getkbevent:
        r->rax = (uint64_t)(int64_t)app_sys_getkbevent();
        break;
    case SYS_pcm:
        if ((int)r->rsi > 0 && !ubuf(r->rdi, (uint64_t)(int)r->rsi * 4)) { r->rax = (uint64_t)-1; break; }  /* nframes stereo 16-bit = 4 B each */
        __asm__ volatile("sti");           /* audio_play blocks on the timer */
        audio_play((const int16_t *)r->rdi, (int)r->rsi);
        break;
    case SYS_pcm_stream:
        if ((int)r->rsi > 0 && !ubuf(r->rdi, (uint64_t)(int)r->rsi * 4)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)audio_stream_write((const int16_t *)r->rdi, (int)r->rsi);
        break;
    case SYS_pcm_avail:
        r->rax = (uint64_t)(int64_t)audio_stream_avail();
        break;
    case SYS_mouse:
        r->rax = (uint64_t)app_get_mouse();
        break;
    case SYS_mouse_rel:
        r->rax = (uint64_t)app_get_mouse_rel();
        break;
    case SYS_playbg: {
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        __asm__ volatile("sti");                  /* the file read can be slow; stay preemptible */
        uint8_t *wb = kmalloc(8 * 1024 * 1024);
        long n = wb ? vfs_read((const char *)r->rdi, wb, 8 * 1024 * 1024) : -1;
        int rc = (n > 0) ? audio_play_wav_bg(wb, (int)n) : -1;
        if (wb) kfree(wb);                         /* decoded copy is independent of this buffer */
        r->rax = (uint64_t)(int64_t)rc;
        break;
    }
    case SYS_audiostop:
        audio_stop_bg();
        break;
    case SYS_playwav: {
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        __asm__ volatile("sti");
        uint8_t *wb = kmalloc(8 * 1024 * 1024);   /* the .wav file (<= 8 MB) */
        long n = wb ? vfs_read((const char *)r->rdi, wb, 8 * 1024 * 1024) : -1;
        int rc = (n > 0) ? audio_play_wav(wb, (int)n) : -1;
        if (wb) kfree(wb);
        r->rax = (uint64_t)(int64_t)rc;
        break;
    }
    case SYS_savebmp: {
        /* rdi=name, rsi=pixels, rdx=w, r10=h: save a w*h 0x00RRGGBB buffer as a
         * 24-bit BMP. Validate the name string + the pixel buffer (w*h*4 bytes,
         * the app's own pages) and require positive, sane dimensions before
         * touching either — same ring3->ring0 pointer boundary as the others. */
        int w = (int)r->rdx, h = (int)r->r10;
        if (!ustr(r->rdi) || w <= 0 || h <= 0 || (long)w * h > 4000000L ||
            !ubuf(r->rsi, (uint64_t)w * (uint64_t)h * 4)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)fb_save_bmp_buf((const char *)r->rdi,
                                                    (const uint32_t *)r->rsi, w, h);
        break;
    }
    case SYS_setwall:
        /* rdi=name: load that image as the desktop wallpaper. Validate the name
         * string (the app's own pages) before the kernel reads it; the decode +
         * buffer swap go through desktop.c's own wallpaper_lock (M1613) so the
         * WM render task never sees a half-updated wallpaper OR reads a buffer
         * this call has already freed, and a failed load keeps the current one. */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)desktop_set_wallpaper((const char *)r->rdi);
        break;
    case SYS_lspci: {
        /* rdi=buf, rsi=len: format the PCI device list as text into the caller's
         * buffer. Validate the buffer lies in the app's own pages before writing
         * (the ring3->ring0 pointer boundary), exactly like SYS_ps / SYS_df. */
        int max = (int)r->rsi;
        if (max <= 0 || !ubuf(r->rdi, (uint64_t)max)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)pci_format((char *)r->rdi, max);
        break;
    }
    case SYS_lsblk: {
        /* rdi=buf, rsi=len: format the block-device + FAT32-volume listing into
         * the caller's buffer. Validate it lies in the app's own pages, like
         * SYS_lspci / SYS_ps / SYS_df. */
        int max = (int)r->rsi;
        if (max <= 0 || !ubuf(r->rdi, (uint64_t)max)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)blockdev_format((char *)r->rdi, max);
        break;
    }
    case SYS_mounts: {                     /* rdi=buf, rsi=len: list the read-only /diskN mounts */
        int max = (int)r->rsi;
        if (max <= 0 || !ubuf(r->rdi, (uint64_t)max)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)blockdev_mounts_format((char *)r->rdi, max);
        break;
    }
    case SYS_getrandom: {                  /* rdi=buf, rsi=len: fill with CSPRNG bytes */
        uint64_t len = r->rsi;
        if (len == 0 || !ubuf(r->rdi, len)) { r->rax = (uint64_t)-1; break; }
        random_bytes((void *)r->rdi, (size_t)len);
        r->rax = len;
        break;
    }
    case SYS_getentropy: {                 /* (buf, len<=256) -> CSPRNG bytes; 0/-1 (M1238) */
        uint64_t len = r->rsi;
        if (len > 256 || !ubuf(r->rdi, len)) { r->rax = (uint64_t)-1; break; }
        if (len) random_bytes((void *)r->rdi, (size_t)len);
        r->rax = 0;                        /* getentropy returns 0/-1, not a byte count */
        break;
    }
    case SYS_getpriority:                  /* (which, who) -> caller's nice; self (who==0) only (M1238) */
        if ((int)r->rdi != PRIO_PROCESS || !(r->rsi == 0 || (int)r->rsi == app_sys_getpid())) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)task_get_nice();
        break;
    case SYS_setpriority:                  /* (which, who, prio) -> set caller's nice; self only (M1238) */
        if ((int)r->rdi != PRIO_PROCESS || !(r->rsi == 0 || (int)r->rsi == app_sys_getpid())) { r->rax = (uint64_t)-1; break; }
        task_set_nice((int)r->rdx);
        r->rax = 0;
        break;
    case SYS_pledge: {                     /* rdi = promise string ("stdio rpath ...") */
        if (!ustr(r->rdi)) { r->rax = (uint64_t)-1; break; }
        uint32_t mask;
        if (app_pledge_parse((const char *)r->rdi, &mask) < 0) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)app_pledge(app_current(), mask);
        break;
    }
    case SYS_unveil: {                     /* rdi = path (0 to lock), rsi = perms string ("rwc") */
        if (r->rdi == 0) { r->rax = (uint64_t)(int64_t)app_unveil(self, 0, 0); break; }  /* lock */
        if (!ustr(r->rdi) || (r->rsi && !ustr(r->rsi))) { r->rax = (uint64_t)-1; break; }
        uint32_t perms = app_unveil_parse((const char *)r->rsi);
        r->rax = (uint64_t)(int64_t)app_unveil(self, (const char *)r->rdi, perms);
        break;
    }
    case SYS_symlink:                      /* rdi = linkpath (under /tmp), rsi = target */
        if (!ustr(r->rdi) || !ustr(r->rsi)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, (const char *)r->rdi, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_symlink((const char *)r->rdi, (const char *)r->rsi);
        break;
    case SYS_link:                         /* rdi = oldpath, rsi = newpath (hard link; M1207) */
        if (!ustr(r->rdi) || !ustr(r->rsi)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, (const char *)r->rsi, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_link((const char *)r->rdi, (const char *)r->rsi);
        break;
    case SYS_rename:                       /* rdi = oldpath, rsi = newpath (ext2 same-mount move; M1213) */
        if (!ustr(r->rdi) || !ustr(r->rsi)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, (const char *)r->rsi, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_rename_path((const char *)r->rdi, (const char *)r->rsi);
        break;
    case SYS_renameat2:                    /* (oldpath, newpath, flags) -> renameat2 NOREPLACE/EXCHANGE (M1232) */
        if (!ustr(r->rdi) || !ustr(r->rsi)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, (const char *)r->rdi, 1) || !app_unveil_ok(self, (const char *)r->rsi, 1)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_rename2((const char *)r->rdi, (const char *)r->rsi, (int)r->rdx);
        break;
    case SYS_readlink:                     /* (path, buf, size) -> a symlink's target, not followed (M1233) */
        if (!ustr(r->rdi) || !ubuf(r->rsi, r->rdx)) { r->rax = (uint64_t)-1; break; }
        if (!app_unveil_ok(self, (const char *)r->rdi, 0)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)(int64_t)vfs_readlink((const char *)r->rdi, (void *)r->rsi, (unsigned long)r->rdx);
        break;
    case SYS_prlimit:                      /* (pid, resource, newval, do_set) -> old/current value (M1214) */
        r->rax = (uint64_t)app_prlimit((int)r->rdi, (int)r->rsi, (uint64_t)r->rdx, (int)r->r10);
        break;
    case SYS_timerfd_create:               /* () -> a pollable one-shot timer fd (M1217) */
        r->rax = (uint64_t)(int64_t)app_timerfd_create();
        break;
    case SYS_eventfd:                      /* (initval, flags) -> a pollable u64-counter fd (M1242) */
        r->rax = (uint64_t)(int64_t)app_eventfd_create((unsigned int)r->rdi, (int)r->rsi);
        break;
    case SYS_timerfd_settime:              /* (fd, delay_ms, interval_ms) -> arm/disarm; interval>0 = periodic; 0/-1 (M1217, periodic M1302) */
        r->rax = (uint64_t)app_timerfd_settime((int)r->rdi, (long)r->rsi, (long)r->rdx);
        break;
    case SYS_fcntl: {                      /* (fd, cmd, arg) -> fd flags (M1218) + record locks (M1221) */
        int cfd = (int)r->rdi, cmd = (int)r->rsi;
        if (cmd == F_SETLK || cmd == F_SETLKW || cmd == F_GETLK) {
            if (!ubuf(r->rdx, sizeof(struct flock))) { r->rax = (uint64_t)-1; break; }
            struct flock *lf = (struct flock *)r->rdx;
            const char *path = app_fd_path(cfd);
            if (!path) { r->rax = (uint64_t)-1; break; }      /* record locks need a FILE fd */
            int pid = app_sys_getpid();
            if (cmd == F_GETLK) {
                int hp, ht; long hs, hl;
                if (rlock_get(path, pid, lf->l_type, lf->l_start, lf->l_len, &hp, &ht, &hs, &hl)) {
                    lf->l_type = (short)ht; lf->l_pid = hp; lf->l_start = hs; lf->l_len = hl;
                } else lf->l_type = F_UNLCK;                  /* no conflict: the lock could be placed */
                r->rax = 0;
            } else {                                          /* F_SETLK (fails on conflict) / F_SETLKW (blocks) (M1597) */
                r->rax = (uint64_t)(int64_t)rlock_set(path, pid, lf->l_type, lf->l_start, lf->l_len, cmd == F_SETLKW);
            }
            break;
        }
        r->rax = (uint64_t)app_fcntl(cfd, cmd, (long)r->rdx);
        break;
    }
    case SYS_dup3:                         /* (oldfd, newfd, flags) (M1218) */
        r->rax = (uint64_t)(int64_t)app_dup3((int)r->rdi, (int)r->rsi, (int)r->rdx);
        break;
    case SYS_close_range:                  /* (lo, hi, flags) (M1218) */
        r->rax = (uint64_t)app_close_range((unsigned)r->rdi, (unsigned)r->rsi, (int)r->rdx);
        break;
    case SYS_sendfile: {                   /* (out_fd, in_fd, off_ptr, count) zero-copy fd->fd (M1219) */
        long off = -1; long *offp = (long *)r->rdx;
        if (offp) { if (!ubuf(r->rdx, sizeof(long))) { r->rax = (uint64_t)-1; break; } off = *offp; }
        long n = app_sendfile((int)r->rdi, (int)r->rsi, &off, (unsigned long)r->r10);
        if (offp && n >= 0) *offp = off;
        r->rax = (uint64_t)n;
        break;
    }
    case SYS_epoll_create1:                /* () -> an epoll fd (M1220) */
        r->rax = (uint64_t)(int64_t)app_epoll_create();
        break;
    case SYS_epoll_ctl: {                  /* (epfd, op, fd, event_ptr) (M1220) */
        unsigned ev = 0; unsigned long data = 0;
        if (r->r10) {
            if (!ubuf(r->r10, sizeof(struct epoll_event))) { r->rax = (uint64_t)-1; break; }
            struct epoll_event *e = (struct epoll_event *)r->r10; ev = e->events; data = e->data;
        }
        r->rax = (uint64_t)app_epoll_ctl((int)r->rdi, (int)r->rsi, (int)r->rdx, ev, data);
        break;
    }
    case SYS_epoll_wait: {                 /* (epfd, events_array, maxevents, timeout_ms) (M1220) */
        struct epoll_event *out = (struct epoll_event *)r->rsi;
        int maxev = (int)r->rdx; long timeout = (long)r->r10;
        if (maxev < 1 || maxev > 64 || !ubuf(r->rsi, (uint64_t)(unsigned)maxev * sizeof(struct epoll_event))) { r->rax = (uint64_t)-1; break; }
        __asm__ volatile("sti");           /* the wait loop sleeps on the timer */
        uint64_t start = timer_ms(); int k = 0;
        for (;;) {
            k = app_epoll_check((int)r->rdi, out, maxev);
            if (k != 0) break;             /* ready (k>0) or error (k<0) */
            if (timeout >= 0 && (long)(timer_ms() - start) >= timeout) break;
            task_sleep_ms(10);
        }
        r->rax = (uint64_t)(int64_t)k;
        break;
    }
    case SYS_epoll_pwait: {                /* (epfd, events, maxevents, timeout_ms, sigmask) -> like epoll_wait,
                                             * but the wait breaks early on a deliverable signal (M1567). Reuses
                                             * app_sigprocmask (M1208) for the swap+restore rather than touching
                                             * sig_blocked directly -- syscall.c has no visibility into struct
                                             * app at all, only app.c's own opaque accessors. */
        struct epoll_event *out = (struct epoll_event *)r->rsi;
        int maxev = (int)r->rdx; long timeout = (long)r->r10;
        if (maxev < 1 || maxev > 64 || !ubuf(r->rsi, (uint64_t)(unsigned)maxev * sizeof(struct epoll_event))) { r->rax = (uint64_t)-1; break; }
        uint32_t old_mask = app_sigprocmask(2 /* SIG_SETMASK */, (uint32_t)r->r8);
        app_kill_check();
        __asm__ volatile("sti");
        uint64_t start = timer_ms(); int k = 0; int interrupted = 0;
        for (;;) {
            k = app_epoll_check((int)r->rdi, out, maxev);
            if (k != 0) break;
            if (app_signal_deliverable()) { interrupted = 1; break; }
            if (timeout >= 0 && (long)(timer_ms() - start) >= timeout) break;
            task_sleep_ms(10);
        }
        if (interrupted) { r->rax = (uint64_t)-1; app_deliver_pending(r); }   /* r->rax baked in BEFORE the snapshot (M1561's own lesson) */
        else r->rax = (uint64_t)(int64_t)k;
        app_sigprocmask(2, old_mask);
        break;
    }
    case SYS_pidfd_open:                   /* (pid, flags) -> a pollable process handle (M1222) */
        r->rax = (uint64_t)(int64_t)app_pidfd_open((int)r->rdi);
        break;
    case SYS_pidfd_send_signal:            /* (pidfd, sig) -> signal the process; 0/-1 (M1222) */
        r->rax = (uint64_t)app_pidfd_send_signal((int)r->rdi, (int)r->rsi);
        break;
    case SYS_getdents64:                   /* (buf, max, start_idx) -> packed dirent64 of the cwd (M1223) */
        if (!ubuf(r->rdi, r->rsi)) { r->rax = (uint64_t)-1; break; }
        r->rax = (uint64_t)app_getdents64((void *)r->rdi, (unsigned long)r->rsi, (int)r->rdx);
        break;
    case SYS_sigprocmask:                  /* (how, set): block/unblock signals; returns the old mask (M1208) */
        r->rax = (uint64_t)app_sigprocmask((int)r->rdi, (uint32_t)r->rsi);
        break;
    case SYS_sigpending:                   /* (): the pending (raised-but-blocked) signal set (M1209) */
        r->rax = (uint64_t)app_sigpending();
        break;
    case SYS_sigsuspend:                   /* (mask) -> swap blocked mask, block for a signal, deliver it, restore; always -1 (M1561) */
        app_kill_check();                  /* WM close-request: don't block a paced app told to exit (same as sleep/nanosleep) */
        __asm__ volatile("sti");           /* the wake comes via an IRQ-driven app_request_signal */
        r->rax = (uint64_t)(int64_t)app_sigsuspend(r, (uint32_t)r->rdi);
        break;
    case SYS_pause:                        /* () -> block until a signal is delivered, current mask unchanged; always -1 (M1563) */
        app_kill_check();
        __asm__ volatile("sti");
        r->rax = (uint64_t)(int64_t)app_pause(r);
        break;
    case SYS_jail: {                       /* rdi=prog, rsi=promises, rdx=path (0=none): spawn pre-confined */
        if (!ustr(r->rdi) || !ustr(r->rsi) || (r->rdx && !ustr(r->rdx))) { r->rax = (uint64_t)-1; break; }
        uint32_t mask;
        if (app_pledge_parse((const char *)r->rsi, &mask) < 0) { r->rax = (uint64_t)-1; break; }
        app_jail_next(mask, (const char *)r->rdx);
        r->rax = (uint64_t)(int64_t)app_spawn_named((const char *)r->rdi);
        break;
    }
    case SYS_exit:
        app_sys_exit((int)r->rdi);         /* records the exit status, marks app dead + task_exit; no return */
        break;
    default:
        kprintf("[kernel] unknown syscall %lu\n", r->rax);
        r->rax = (uint64_t)-1;
        break;
    }

sc_done:                      /* seccomp-notify lands here after denying/emulating a syscall (M1124) */
    if (traced) {             /* strace (M1084): one line to dmesg + the readable ring (M1118) */
        kprintf("[strace %d] %s(0x%lx, 0x%lx, 0x%lx) = 0x%lx\n",
                app_sys_getpid(), syscall_name(tr_nr), tr_a, tr_b, tr_c, r->rax);
        strace_record(task_current_id(), syscall_name(tr_nr), tr_a, tr_b, tr_c, r->rax);  /* tag with the task id, matching /proc/<pid> */
    }

    app_deliver_pending(r);   /* an async signal (e.g. Ctrl-C->SIGINT) raised during the syscall (M1083) */
}
