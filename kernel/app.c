/*
 * app.c — userspace apps as windowed, isolated, preemptive processes.
 *
 * Each app: a fresh address space (M21), the shell ELF loaded into it, a user
 * stack, and a kernel task whose trampoline drops to ring 3. The app's text
 * output lands in a character grid (app->grid); its keyboard input waits in a
 * small queue the window manager fills when the app's window is focused.
 *
 * The syscall dispatcher routes write/read/getpid/exit here, acting on
 * whichever app owns the task that trapped (task_self()->proc).
 */
#include "app.h"
#include "flock.h"   /* flock_release_pid on process exit (M1177) */
#include "inotify.h" /* inotify fd type 8 (M1266) */
#include "net.h"     /* net_udp_send/recv for AF_INET datagram sockets, fd type 9 (M1267) */
#include "pty.h"     /* pty_release_pid on process exit (M1185) */
#include "pipe.h"    /* anonymous pipe objects for the fd table (M1187) */
#include "fifo.h"    /* named pipes (FIFOs), path-keyed (M1188) */
#include "bpf.h"     /* seccomp-BPF self-filter (M1190) */
#include "task.h"
#include "timer.h"
#include "interrupts.h"   /* struct registers, for ring-3 signal delivery */
#include "vmm.h"
#include "pmm.h"
#include "vdso.h"
#include "elf.h"
#include "linuxabi.h"
#include "measure.h"
#include "fb.h"
#include "font.h"
#include "string.h"
#include "random.h"   /* random_bytes for ASLR (M1287) */
#include "vfs.h"
#include "kheap.h"
#include "tmpfs.h"
#include "swap.h"
#include "shm.h"
#include "syscall.h"   /* FUTEX_WAIT / FUTEX_WAKE op constants */
#include "rtc.h"       /* rtc_unix, to resolve UTIME_NOW (M1230) */
#include "robust.h"    /* robust_t + FUTEX_OWNER_DIED (M1141) */
#include "complete.h"
#include "console.h"   /* kprintf — log app-launch failures (don't fail silently) */
#include "desktop.h"   /* desktop_wallpaper_sample — translucent terminal cell backgrounds (M1527) */
#include <stdint.h>

/* The terminal grid is now LIVE-RESIZABLE (M1473): the arrays are sized to a
 * generous maximum, while each app tracks its CURRENT visible size (a->cols /
 * a->rows), which the window manager derives from the window's pixel size as it
 * is dragged. The ops below all work in terms of the current size; only the
 * array declarations use the _MAX bounds. */
#define APP_COLS_MAX 160     /* grid array width  (fills a 1280px screen at 8px/glyph) */
#define APP_ROWS_MAX 56      /* grid array height (fills ~960px at 16px/glyph) */
#define APP_DEF_COLS 80      /* default size a terminal opens at (classic 80x24) */
#define APP_DEF_ROWS 24
#define APP_MIN_COLS 24      /* smallest the grid may shrink to on resize */
#define APP_MIN_ROWS 6
#define SB_ROWS  72          /* scrollback: ~3 screens of history */
#define IQ_SIZE  128
/* Raised 8 -> 32 (M1936). Eight concurrent processes is nowhere near enough
 * for a real userland: one `gcc foo.c` alone is gcc + cc1 + as + ld, and a
 * `make` driving several of those in parallel exhausted the old table outright.
 * Each struct app is a few tens of KB (mostly its fd table), so 32 costs low
 * single-digit MB of .bss -- cheap against a 256 MB machine. */
#define MAX_APPS 32
#define HIST_N   32          /* command-history depth (up/down recall) */
#define CLIP_MAX 2048        /* system clipboard + per-app paste buffer size */

#define USTACK_BASE  0x50000000ull
#define USTACK_PAGES 129             /* 128 usable pages (512 KiB — DOOM's BSP renderer recurses deeply) + 1 unmapped guard page at USTACK_BASE: a user-stack overflow faults cleanly instead of silently corrupting the heap below it (M1499) */

/* Userspace heap: grows up from 1 GiB + 64 MiB (clear of any app image, which
 * loads at 1 GiB and is at most a couple of MiB) toward the stack at 0x50000000.
 * That leaves ~192 MiB of per-process heap virtual space for malloc (sbrk). */
/* --- the ring-3 address map (M1961) ------------------------------------
 * Written out because it USED TO OVERLAP and that cost a real bug: the heap
 * ran 0x44000000..0x50000000 while the dynamic linker was mapped at
 * 0x48000000, so any program whose heap grew past 64 MiB paged straight over
 * ld.so's code. Only something big and allocation-hungry reached it -- cc1
 * compiling a large source file -- and it surfaced as a wild-pointer page
 * fault deep inside the compiler, naming nothing.
 *
 *   0x40000000  executable (ELF_DYN_BASE)      128 MiB
 *   0x48000000  heap / brk (UHEAP_BASE)        128 MiB
 *   0x50000000  user stack (USTACK_BASE)       512 KiB + guard
 *   0x60000000  mmap window                      1 GiB
 *   0xB0000000  dynamic linker (ELF_INTERP_BASE)
 */
#define UHEAP_BASE   0x48000000ull
#define UHEAP_LIMIT  USTACK_BASE

struct app {
    int         used;
    int         pid;
    task_t     *task;
#define APP_MAXTHREAD 32   /* 16 -> 32 (M1936) */
    task_t     *thr[APP_MAXTHREAD];      /* worker threads (M1138/M1139); 0 = free slot */
    const char *title;
    char        titlebuf[24];            /* persistent copy of the title */
    char        exe_path[64];            /* the spawn/exec file path, for /proc/<pid>/exe — NOT changed by prctl (M1250) */
    uint64_t cr3, entry, ustack;
    uint64_t heap_end;                   /* current program break (0 = not yet started) */
/* 16 -> 64 (M1936). A dynamically-linked or JIT-ing program wants dozens of
 * regions; 16 was tight even for our own apps once mmap'd thread stacks and
 * file mappings were in play. */
#define APP_MAXVMA 192   /* 64 -> 192 (M1961): ld.so maps EIGHT shared libraries for cc1, each costing several VMAs once MAP_FIXED carving splits the reservation, plus the executable, its BSS and the allocator */
#define HUGE_SIZE  0x200000ull           /* 2 MiB hugepage (M1155) */
/* Zero the next free VMA slot before filling it. Slots are RECYCLED -- the
 * carve compacts the list by swapping the last entry down -- so a field a
 * creation site forgets to assign silently inherits the previous tenant's
 * value. That is not hypothetical: app_mmap_file_at never assigned .prot, so
 * a freshly MAP_FIXED'd read-WRITE data segment inherited prot=1 from the
 * read-only reservation it replaced, and ld.so faulted zeroing the BSS tail.
 * Resetting the whole slot makes every field opt-in. (M1956) */
#define VMA_NEW(a) do { for (unsigned _b = 0; _b < sizeof (a)->vma[0]; _b++) ((char *)&(a)->vma[(a)->nvma])[_b] = 0; } while (0)

/* Linux PROT_* bits, as recorded on a VMA and honoured by app_fault_handle (M1956) */
#define VMA_PROT_READ  0x1
#define VMA_PROT_WRITE 0x2
#define VMA_PROT_EXEC  0x4
    struct { uint64_t start, len; int sealed, uffd, file_backed, locked, huge, shared; uint64_t foff; char fpath[256]; uint8_t prot; uint64_t fvalid; } vma[APP_MAXVMA];  /* mmap'd demand-paged regions; sealed=mseal'd; uffd=userfault; file_backed=mmap'd file (M1136); locked=mlock'd (M1149); huge=2 MiB-backed (M1155); shared=MAP_SHARED, writes flow back to the file via msync/munmap/exit (M1544); fpath is 256 like the fd table's, NOT 64 -- see M1955; prot = Linux PROT_* bits honoured by the fault handler, fvalid = file bytes from foff before zero-fill begins (M1956) */
    int      nvma;
    uint64_t mmap_next;                  /* bump allocator for mmap addresses */
    int      mlock_future;               /* mlockall(MCL_FUTURE): new mmaps are born locked (M1283) */
    uint64_t aslr_mmap_base;             /* ASLR: per-exec randomized mmap-region start (M1287) */
    uint64_t minflt, majflt;             /* page-fault counters: minor (no I/O) / major (disk I/O), getrusage (M1150) */
    /* per-process current directory (M1144): synth_cwd state + the in-mount/overlay
     * subpath + the boot-FS (fat32) cwd cluster. The VFS keeps the live cwd in its
     * own globals and syncs them to/from here on each app switch. */
    int      cwd_synth; char cwd_sub[128]; uint32_t cwd_fat;
    uint64_t last_fault_page, last_fault_err;   /* the same fault repeating is an infinite retry loop, not a race (M1961) */
    int      fault_repeat;
    char     cwd_path[160];              /* canonical absolute cwd string, for getcwd(2) (M1248) */
#define APP_NSIG 32
    uint64_t sig_handler[APP_NSIG];      /* ring-3 signal handlers (0 = none) */
    uint32_t sig_flags[APP_NSIG];        /* per-signal sa_flags (SA_SIGINFO etc.) (M1270) */
    uint64_t sig_restorer;               /* ulib trampoline that calls sigreturn */
    struct registers sig_saved;          /* pre-signal context, restored by sigreturn */
    uint64_t sig_uctx;                   /* SA_SIGINFO: user addr of the delivered ucontext/mcontext; sigreturn restores edits from it (M1270) */
    int      sig_in;                     /* 1 while a handler runs (no nesting) */
    volatile uint32_t pending_sigs;      /* bitset of pending signals (bit n = signo n); delivered on the next return to ring 3. A bitset, not one slot, so a 2nd async signal isn't dropped (M1126) */
    volatile uint32_t sig_blocked;       /* sigprocmask: blocked-signal bitset; a blocked signal stays pending until unblocked (M1208) */
    int      sigfd_armed;                /* 1 if this process routes some signals to signalfd (M1126) */
    uint32_t sigfd_mask;                 /* which signos are delivered via /proc/self/sigfd instead of a handler */
#define APP_SIGQ_MAX 32
    struct { int signo, code; uint64_t value; } sigq[APP_SIGQ_MAX];  /* RT/sigqueue payload FIFO: real-time signals QUEUE (not coalesce) and carry a sigval (M1271) */
    int      sigq_n;                     /* # valid queued payloads, [0..sigq_n) in arrival (FIFO) order */
    uint64_t sig_q_value;                /* scratch: si_value for the signal currently being delivered */
    int      sig_q_code;                 /* scratch: si_code  for the signal currently being delivered */
    uint64_t sig_alt_base, sig_alt_size; /* sigaltstack: alternate signal-handler stack; 0 size = none (M1276) */
    uint64_t alarm_interval, alarm_next; /* SIGALRM (M1102): periodic timer; 0 interval = disarmed */
#define APP_NPTIMER 8
    struct { int used; int signo; uint64_t value; uint64_t next_ms, interval_ms; } ptimer[APP_NPTIMER];  /* POSIX timer_create() per-process interval timers: fire signo (carrying value) through the sigqueue FIFO when due (M1272) */
    int      traced;                     /* 1 = log each syscall to dmesg (strace), toggled via /proc/<pid>/ctl */
    uint32_t *gfx;                       /* graphics-mode pixel canvas (kernel heap), or NULL */
    int       gfx_w, gfx_h;              /* canvas dimensions (valid when gfx != NULL) */
    int       rawkb;                     /* raw keyboard mode (games get make/break events) */
    volatile unsigned short rawiq[64];   /* raw key-event queue (WM fills, app drains) */
    volatile int rqh, rqt;
    volatile int ms_x, ms_y, ms_btn;     /* cursor relative to the gfx canvas (-1 outside) + buttons */
    volatile int ms_dx, ms_dy;           /* accumulated relative motion (mouselook) */
    char     grid[APP_ROWS_MAX][APP_COLS_MAX];
    uint8_t  gcol[APP_ROWS_MAX][APP_COLS_MAX];   /* per-cell colour (palette index, 0 = default) for the live grid */
    int      cols, rows;                 /* CURRENT visible grid size (<= _MAX); the WM sets it from the window size on resize (M1473) */
    uint8_t  curcol;                     /* colour applied to chars printed now (set via SYS_setcolor) */
    uint8_t  esc;                        /* ANSI escape state: 0 normal, 1 saw ESC, 2 in CSI */
    uint8_t  csilen;                     /* bytes buffered in csi[] */
    char     csi[24];                    /* CSI parameter bytes (between '[' and the final letter) */
    int      cx, cy;
    char     sb[SB_ROWS][APP_COLS_MAX];  /* scrollback: lines that scrolled off */
    int      sb_count;                   /* how many scrollback lines are stored */
    int      view;                       /* rows scrolled up from the live bottom */
    char     iq[IQ_SIZE];
    volatile int ih, it;
    volatile int exited;
    volatile int kill;                   /* WM asked this app to close: it self-exits at its input wait */
    int      oom_adj;                    /* OOM victim bias (oom_score_adj-like): higher = killed sooner, <= -1000 = never (M1275) */
    char     hist[HIST_N][96];           /* recent input lines (for up/down) */
    int      hist_n, hist_pos;
    volatile int gdirty;                 /* grid changed -> WM should repaint */
    int      caret_off;                  /* 1 = suppress the system caret (app draws its own) */
    int      sel_on;                     /* a text selection is shown/in progress */
    int      sel_r0, sel_c0;             /* selection anchor (visible-grid cell) */
    int      sel_r1, sel_c1;             /* selection end (visible-grid cell) */
    char     pastebuf[CLIP_MAX];         /* middle-click paste text, drained before the key queue */
    volatile int paste_len, paste_pos;   /* so a long paste isn't capped by the small key queue */
    char     launch_arg[128];            /* optional launch argument (e.g. a filename for the editor) */
    uint32_t promises;                   /* pledge() promise bitmask (valid once pledged) */
    int      pledged;                    /* 1 once pledge() has been called (then promises are enforced) */
#define APP_NUNVEIL 8
    struct { char path[48]; uint8_t perms; } uv[APP_NUNVEIL];  /* unveil() allowed path prefixes */
    int      nuv;                        /* number of unveil entries */
    int      uv_active;                  /* 1 once unveil() has been called (then file paths are checked) */
    int      uv_locked;                  /* 1 after unveil(NULL): no more unveils accepted */
    const void *exec_img; uint64_t exec_imgsz;          /* execve hand-off, PER-PROCESS (M1952) */
    const char *const *exec_argv; const char *const *exec_envp;
    struct registers fork_frame;         /* a forked child's saved trap frame (rax=0); iret_to_user resumes it (M1116) */
    int      parent;                     /* pid of the process that fork()ed us (0 = none) — for waitpid (M1117) */
    int      pgid;                        /* process group id (job control, M1176); inherited on fork, set by setpgid */
    int      sid;                         /* session id (M1176); a setsid() leader has sid==pgid==pid */
    uint64_t rchar, wchar;               /* bytes read/written via fd ops, for /proc/<pid>/io (M1244) */
    uint64_t rlim_nproc;                 /* RLIMIT_NPROC: max live children (0 = unlimited), inherited on fork (M1163) */
    uint64_t rlim_as;                    /* RLIMIT_AS: max total mmap bytes (0 = unlimited) (M1164) */
    uint64_t rlim_data;                  /* RLIMIT_DATA: max heap bytes (0 = unlimited) (M1164) */
    uint64_t rlim_nofile;                /* RLIMIT_NOFILE: max open fds (0 = unlimited), inherited on fork (M1547) */
    uint64_t rlim_cpu;                   /* RLIMIT_CPU: max CPU seconds (0 = unlimited) -> SIGXCPU, inherited on fork (M1548) */
    uint64_t cpulimit_next;              /* next timer_ticks() allowed to re-raise SIGXCPU (M1548); see app_cpulimit_tick */
    uint64_t rlim_fsize;                 /* RLIMIT_FSIZE: max file size in bytes (0 = unlimited) -> SIGXFSZ, inherited on fork (M1549) */
    uint64_t rlim_memlock;               /* RLIMIT_MEMLOCK: max mlock()'d bytes (0 = unlimited), inherited on fork (M1550) */
    uint64_t rlim_core;                   /* RLIMIT_CORE: max core-dump bytes (0 = unlimited, capped by CORE_MAX either way), inherited on fork (M1551) */
    int      pdeathsig;                   /* prctl(PR_SET_PDEATHSIG): signal to send THIS process when its parent dies;
                                            * 0 = none. Deliberately NOT inherited on fork/exec, matching real Linux
                                            * (a child must opt in for itself each time) (M1562) */
    int      exit_code;                  /* exit status, captured at SYS_exit */
    int      zombie;                     /* exited + resources freed, slot retained until a parent collects it */
    volatile int waiting;                /* this process is blocked in waitpid() */
    int      ns_id;                      /* mount-namespace id (0 = the shared/global namespace); unshare() detaches (M1122) */
#define APP_SSTEP_N 64
    uint64_t sstep_rips[APP_SSTEP_N];    /* hardware single-step instruction trace (M1123) */
    int      sstep_n;                    /* RIPs recorded so far */
    int      sstep_remaining;            /* instructions still to single-step (0 = not tracing) */
    /* seccomp-notify: userspace syscall supervision (M1124). A supervisor (the
     * parent) intercepts + can deny/emulate the child's masked syscalls. */
    uint64_t sc_mask[2];                 /* which syscalls (0-127) trap to the supervisor */
    int      sc_armed;                   /* 1 = this process is supervised */
    volatile int sc_pending;             /* 1 = parked with a pending call awaiting a verdict */
    volatile uint64_t sc_nr, sc_a, sc_b, sc_c;  /* the parked call (number + 3 args) */
    volatile long sc_retval;             /* the verdict's return value (when not run-real) */
    volatile int sc_run_real;            /* verdict: 1 = run the real syscall, 0 = use sc_retval */
    void    *sc_sup;                     /* a supervisor task_t blocked in seccomp_wait */
    /* ptrace (M1199): a tracer (the parent) stops + inspects/modifies this task.
     * Same rendezvous shape as seccomp-notify above. */
    int      ptraced;                    /* 1 = being traced by our parent (ptrace) */
    volatile int trace_stopped;          /* 1 = parked at a trace stop */
    volatile int trace_sig;              /* the signal that caused the stop */
    void    *trace_sup;                  /* a tracer task_t blocked in ptrace(WAIT) */
    int      trace_stepping;             /* 1 = resumed for a single ptrace step (re-stop on #DB) */
    /* per-process file-descriptor table (M1187). Additive: zero on spawn/fork,
     * only touched by pipe()/fd{read,write,close}/dup2; an app that never calls
     * them has an empty table, so fork-copy + reap-close are no-ops for it. */
/* 24 -> 128 (M1936). 24 fds is below what ordinary tools open at startup, and
 * fd 0-2 are reserved on top of that. Bounded by fd_set's FD_SETSIZE (256,
 * syscall.h) -- select() cannot express an fd at or past that. */
#define APP_NFD 128
    /* type: 0=free, 1=pipe (obj=pipe index, write_end), 2=file (path+off, M1193). */
    /* path 64 -> 256 (M1936): 63 usable bytes could not even hold a moderately
     * nested source path, and the truncation was silent.
     *
     * It is still INLINE, which is what caps it here: struct fdent is copied by
     * VALUE in app_fd_fork / app_dup2 / app_pidfd_getfd / the SCM_RIGHTS table,
     * so a `char *` would be aliased by every one of those paths and need
     * refcounting to free safely -- exactly the use-after-free shape the M1926
     * review found. A real 4096-byte PATH_MAX therefore wants an interned path
     * pool, which is its own milestone rather than a constant bump. */
    struct fdent { uint8_t used, type, write_end; int obj; char path[256]; long off; uint8_t cloexec; } fd[APP_NFD];   /* cloexec at END to keep the positional initializers valid (M1218) */
    /* seccomp-BPF self-filter (M1190): a process installs a bpf.c program that
     * vets its own syscalls. Zero on spawn/fork; inherited across fork; once set
     * it's permanent (privilege drop is one-way). Empty => no filtering overhead. */
    struct bpf_insn seccomp_prog[BPF_MAXINSN];
    int      seccomp_n;                  /* program length (0 = no filter) */
};

static struct app apps[MAX_APPS];
static int next_pid = 100;
static int fg_pgid;             /* the controlling terminal's foreground process group (job control, M1176; 0 = none) */
int app_oom_kill(void);         /* OOM killer (M1275): defined below, called from the sbrk exhaustion path above it */

/* Save/disable + restore interrupts, ATOMICALLY against a concurrent writer,
 * for every check-then-block / produce-then-wake pairing in this file (key
 * delivery, waitpid/waitid, futex, uffd, eventfd, seccomp-notify, ptrace).
 *
 * M1612: this used to be a bare cli/popfq pair at each individual site --
 * correct for a single core, but the reader and writer in every one of these
 * pairings are two DIFFERENT processes, routinely scheduled on two different
 * cores since M1531 (task_create's pin_core=-1 for every ordinary task). A
 * bare cli only stops a LOCAL interrupt from reentering -- it does nothing
 * to a second core running the matching wake logic at the same instant, so
 * several of these sites' own comments claimed single-CPU safety ("the
 * mailbox discipline", "IF=0 here -> atomic (single CPU)", "every ring-3
 * task is scheduled on the BSP") that M1531 had already invalidated -- the
 * last claim is flatly false today: only task 0 (the desktop/WM) is
 * BSP-pinned, no ordinary app task is. One spinlock (nested in cli, same
 * idiom as the eight other files fixed earlier this session) now covers all
 * of them; one coarse lock rather than one per mechanism, since none of them
 * touch each other's state and all are rare enough that it costs nothing
 * measurable. Defined this early so every consumer below it (starting with
 * app_waitpid) can see it. */
static volatile int app_wake_lock;
static inline uint64_t irq_save(void) {
    uint64_t f;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory");
    while (__atomic_exchange_n(&app_wake_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return f;
}
static inline void irq_restore(uint64_t f) {
    __atomic_store_n(&app_wake_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(f) : "memory", "cc");
}

/* userfaultfd state (M1134); defined here so app_reap + app_fault_handle (both
 * above the uffd functions) can see it. One registered region at a time. */
static struct {
    int        active;            /* a region is registered                     */
    struct app *owner;            /* the registrant; only ITS faults route here */
    uint64_t   cr3;               /* the owner's address-space root              */
    volatile int      pending;    /* a fault awaits service                      */
    volatile uint64_t addr;       /* the faulting page (page-aligned)            */
    task_t    *faulter;           /* the parked faulting task                    */
    task_t    *monitor;           /* the monitor task (blocked in uffd_read)     */
    int        monitor_waiting;
} g_uffd;
static char g_pend_arg[128];             /* arg for the next app_spawn, copied into its launch_arg */
/* A FULL argv for the next Linux spawn (M1955). One arg was enough to pick an
 * applet out of a multi-call binary; a real tool invocation is not -- `as -o
 * out.o in.s` is three. Safe as a one-shot global for the same reason
 * g_pend_arg is: app_spawn is called synchronously and spawns are serialised.
 * execve is NOT (it is called concurrently by unrelated processes), which is
 * why its argv lives per-process in exec_argv instead -- see M1952. */
#define LX_PEND_ARGS   28
#define LX_PEND_ARGLEN 192
static char g_pend_lxargs[LX_PEND_ARGS][LX_PEND_ARGLEN];
static int  g_pend_lxargc;
static int  g_last_spawn_pid;            /* pid of the last successful app_spawn (M1955) */
/* One-shot: when set, app_spawn MAPS the executable's PT_LOADs from this path
 * instead of copying them out of a buffer the caller had to slurp whole.
 * Only used for DYNAMICALLY LINKED images -- a static PIE needs its
 * R_X86_64_RELATIVE relocations applied by elf_load, and those are small
 * anyway; a dynamically linked one is relocated by ld.so, so the kernel only
 * has to place the segments. That is what makes a 42 MB cc1 loadable at all:
 * app_spawn_from_file's whole-image kmalloc has a 16 MB ceiling. (M1956) */
static char g_pend_mappath[VFS_PATH_MAX];
static int  lx_stage_interp(const char *path);   /* fwd: defined with the spawn path, used by execve too (M1958) */
static void lx_drop_interp(void);
static uint64_t g_pend_mapsize;          /* and its real on-disk size: segment offsets are validated against THAT, not against the header buffer */
static int  g_have_pend;
/* A pending "jail" for the next app_spawn (M1088): pledge promises + an optional
 * unveil prefix applied to the child BEFORE it runs (a parent-enforced sandbox). */
static int      g_pend_jail;
static uint32_t g_jail_promises;
static char     g_jail_path[64];
/* One-shot: the next app_spawn() is a LINUX binary and needs a System V initial
 * stack (argc/argv/envp/auxv) rather than the bare RSP our own apps get. Same
 * one-shot shape as g_pend_arg/g_pend_jail. (M1940) */
static volatile int g_pend_linux;
static char         g_pend_lxpath[256];
/* Pending INTERPRETER image for a dynamically-linked Linux binary (M1954).
 * Read before the spawn so no disk I/O happens inside app_spawn's cli/CR3
 * critical section. A pending global is acceptable HERE, unlike execve's --
 * spawns are serialised (kmain at boot, the window manager afterwards),
 * whereas execve is called concurrently by unrelated processes, which is
 * exactly what bit M1952. */
static void        *g_pend_interp; static unsigned long g_pend_interp_sz;
/* Image override for Linux execve(2) (M1948, moved per-process M1952).
 *
 * app_exec resolves names in the compiled-in progs[] table, which a Linux
 * binary is obviously not in. Rather than duplicate app_exec's ~70-line
 * CR3-swap body -- the riskiest code in the file -- execve stages the
 * already-read image and app_exec uses that instead of the table.
 *
 * These were GLOBALS, copying the g_pend_arg/g_pend_jail one-shot pattern.
 * That pattern is only safe because those spawns are serialised by the window
 * manager; execve is called CONCURRENTLY by unrelated processes. Two execves
 * in flight raced, and a loser saw exec_argv == NULL, skipped building the
 * System V stack, and entered ring 3 with RSP at the bare stack top -- one
 * page PAST the last mapped stack page -- so its first read of argc faulted at
 * CR2=0x50081000. Per-process fields cannot race: app_exec only ever looks at
 * cur(). (Second time this bill came due: the argv string buffers were static
 * for the same reason, M1951.) */

/* text-colour palette for apps (index 0 = the default green, so an app that never
 * calls SYS_setcolor renders byte-identically). Vivid hues on the dark app background. */
static const uint32_t app_palette[16] = {
    0x33FF66, 0xEAEAEA, 0xFF5555, 0xFFE048, 0x44E0FF, 0xFF6CE0, 0x6E9CFF, 0xFF9A3C,
    0x9098A0, 0xB6FF4A, 0x2FE0C0, 0xB98CFF, 0xE8C040, 0xFF7A5C, 0x40C0FF, 0x6CFFB0,
};

/* apps awaiting a window from the window manager */
static struct app *pending[MAX_APPS];
static int pend_h, pend_t;

/* the embedded programs (see kernel/asm/user_blob.asm) */
extern char shell_elf_start[], clock_elf_start[], calc_elf_start[], snake_elf_start[],
            editor_elf_start[], g2048_elf_start[], life_elf_start[], tetris_elf_start[],
            breakout_elf_start[], mines_elf_start[], sudoku_elf_start[], calendar_elf_start[],
            timer_elf_start[],
            mandel_elf_start[], piano_elf_start[], maze_elf_start[], adv_elf_start[],
            matrix_elf_start[], paint_elf_start[], hangman_elf_start[], jukebox_elf_start[],
            ttt_elf_start[], bj_elf_start[], typing_elf_start[], simon_elf_start[],
            c4_elf_start[], wordle_elf_start[], pietest_elf_start[], gfxdemo_elf_start[],
            scene3d_elf_start[], terrain_elf_start[], demoscene_elf_start[], doom_elf_start[],
            quake_elf_start[], nes_elf_start[], reversi_elf_start[], lights_elf_start[],
            fifteen_elf_start[], mastermind_elf_start[], pong_elf_start[], halflife_elf_start[],
            memory_elf_start[], sokoban_elf_start[], battleship_elf_start[], pig_elf_start[],
            raycast_elf_start[], tron_elf_start[], spaceinv_elf_start[], asteroids_elf_start[],
            flappy_elf_start[], gb_elf_start[], lander_elf_start[], yahtzee_elf_start[],
            checkers_elf_start[], gomoku_elf_start[], frogger_elf_start[],
            chess_elf_start[], vpoker_elf_start[], mancala_elf_start[],
            dotsbox_elf_start[], missile_elf_start[], pacman_elf_start[],
            solitaire_elf_start[], gems_elf_start[], columns_elf_start[], freecell_elf_start[],
            spider_elf_start[], sandbox_elf_start[], forth_elf_start[], cc_elf_start[], crash_elf_start[], futex_elf_start[], nettcp_elf_start[], crashinfo_elf_start[], forktest_elf_start[], execdemo_elf_start[], nstest_elf_start[], steptest_elf_start[], scnotify_elf_start[], fswaittest_elf_start[], sigfdtest_elf_start[], bpftest_elf_start[], fantest_elf_start[], iouringtest_elf_start[], msealtest_elf_start[], httpd_elf_start[], uffdtest_elf_start[], mmapfile_elf_start[], threads_elf_start[], robustfutex_elf_start[], overlay_elf_start[], pcwd_elf_start[], hexedit_elf_start[], aclock_elf_start[], sysgraph_elf_start[], taskman_elf_start[], gcal_elf_start[], gauges_elf_start[], gsw_elf_start[], bclock_elf_start[], gfont_elf_start[], gtimer_elf_start[], imgview_elf_start[], gcalc_elf_start[], gcolor_elf_start[], gfire_elf_start[], gmetro_elf_start[], gconv_elf_start[], gbase_elf_start[], gpass_elf_start[], gclip_elf_start[], gtodo_elf_start[], gseq_elf_start[], jsrun_elf_start[], imgdec_elf_start[], httpget_elf_start[], webview_elf_start[], sheet_elf_start[], plot_elf_start[], gpaint_elf_start[], gjson_elf_start[], gregex_elf_start[], gdiff_elf_start[], garc_elf_start[], ghash_elf_start[];
static const struct { const char *name; char *elf; const char *title; } progs[] = {
    { "shell",  shell_elf_start,  "Shell"  },
    { "clock",  clock_elf_start,  "Clock"  },
    { "calc",   calc_elf_start,   "Calc"   },
    { "snake",  snake_elf_start,  "Snake"  },
    { "editor", editor_elf_start, "Editor" },
    { "2048",   g2048_elf_start,  "2048"   },
    { "life",   life_elf_start,   "Life"   },
    { "tetris", tetris_elf_start, "Tetris" },
    { "breakout", breakout_elf_start, "Breakout" },
    { "mines",  mines_elf_start,  "Mines"  },
    { "sudoku", sudoku_elf_start, "Sudoku" },
    { "calendar", calendar_elf_start, "Calendar" },
    { "timer",  timer_elf_start,  "Timer" },
    { "mandel", mandel_elf_start, "Mandelbrot" },
    { "piano",  piano_elf_start,  "Piano" },
    { "maze",   maze_elf_start,   "Maze" },
    { "adv",    adv_elf_start,    "Adventure" },
    { "matrix", matrix_elf_start, "Matrix" },
    { "paint",  paint_elf_start,  "Paint" },
    { "hangman", hangman_elf_start, "Hangman" },
    { "jukebox", jukebox_elf_start, "Jukebox" },
    { "ttt",    ttt_elf_start,    "Tic-Tac-Toe" },
    { "bj",     bj_elf_start,     "Blackjack" },
    { "typing", typing_elf_start, "Typing Test" },
    { "simon",  simon_elf_start,  "Simon" },
    { "c4",     c4_elf_start,     "Connect Four" },
    { "wordle", wordle_elf_start, "Wordle" },
    { "pietest", pietest_elf_start, "PIE Test" },   /* a position-independent (ET_DYN) executable — tests elf_load_dyn (M1465) */
    { "gfxdemo", gfxdemo_elf_start, "Graphics Demo" },
    { "scene3d", scene3d_elf_start, "3D Engine" },
    { "terrain", terrain_elf_start, "Terrain" },
    { "demoscene", demoscene_elf_start, "Demoscene" },
    { "doom",   doom_elf_start,   "DOOM" },
    { "quake",  quake_elf_start,  "Quake" },
    { "nes",    nes_elf_start,    "NES" },
    { "reversi", reversi_elf_start, "Reversi" },
    { "lights", lights_elf_start, "Lights Out" },
    { "fifteen", fifteen_elf_start, "15 Puzzle" },
    { "mastermind", mastermind_elf_start, "Mastermind" },
    { "pong",   pong_elf_start,   "Pong" },
    { "halflife", halflife_elf_start, "Half-Life" },
    { "memory", memory_elf_start, "Memory" },
    { "sokoban", sokoban_elf_start, "Sokoban" },
    { "battleship", battleship_elf_start, "Battleship" },
    { "pig",    pig_elf_start,    "Pig" },
    { "raycast", raycast_elf_start, "Raycaster" },
    { "tron",   tron_elf_start,   "Tron" },
    { "spaceinv", spaceinv_elf_start, "Space Invaders" },
    { "asteroids", asteroids_elf_start, "Asteroids" },
    { "flappy", flappy_elf_start, "Flappy" },
    { "gb",     gb_elf_start,     "Game Boy" },
    { "lander", lander_elf_start, "Lunar Lander" },
    { "yahtzee", yahtzee_elf_start, "Yahtzee" },
    { "checkers", checkers_elf_start, "Checkers" },
    { "gomoku", gomoku_elf_start, "Gomoku" },
    { "frogger", frogger_elf_start, "Frogger" },
    { "chess", chess_elf_start, "Chess" },
    { "vpoker", vpoker_elf_start, "Video Poker" },
    { "mancala", mancala_elf_start, "Mancala" },
    { "dotsbox", dotsbox_elf_start, "Dots and Boxes" },
    { "missile", missile_elf_start, "Missile Command" },
    { "pacman", pacman_elf_start, "Pac-Man" },
    { "solitaire", solitaire_elf_start, "Solitaire" },
    { "gems",   gems_elf_start,   "Gems" },
    { "columns", columns_elf_start, "Columns" },
    { "freecell", freecell_elf_start, "FreeCell" },
    { "spider", spider_elf_start, "Spider" },
    { "sandbox", sandbox_elf_start, "Sandbox (pledge demo)" },
    { "forth", forth_elf_start, "Forth" },
    { "hexedit", hexedit_elf_start, "Hex Editor" },
    { "sheet", sheet_elf_start, "Spreadsheet" },
    { "plot", plot_elf_start, "Graphing Calculator" },
    { "gpaint", gpaint_elf_start, "Paint" },
    { "gjson", gjson_elf_start, "JSON Viewer" },
    { "gregex", gregex_elf_start, "Regex Tester" },
    { "gdiff", gdiff_elf_start, "Diff Viewer" },
    { "garc", garc_elf_start, "Archive Browser" },
    { "ghash", ghash_elf_start, "Hash / Checksum" },
    { "aclock", aclock_elf_start, "Analog Clock" },
    { "sysgraph", sysgraph_elf_start, "System Monitor" },
    { "taskman", taskman_elf_start, "Task Manager" },
    { "gcal", gcal_elf_start, "Calendar (gfx)" },
    { "gauges", gauges_elf_start, "Gauges" },
    { "gsw", gsw_elf_start, "Stopwatch" },
    { "bclock", bclock_elf_start, "Binary Clock" },
    { "gfont", gfont_elf_start, "Char Map" },
    { "gtimer", gtimer_elf_start, "Countdown" },
    { "imgview", imgview_elf_start, "Image Viewer" },
    { "jsrun", jsrun_elf_start, "JS (ring 3)" },
    { "imgdec", imgdec_elf_start, "Image decode (ring 3)" },
    { "httpget", httpget_elf_start, "HTTPS fetch (ring 3)" },
    { "webview", webview_elf_start, "Browser (ring 3)" },
    { "gcalc", gcalc_elf_start, "Calculator" },
    { "gcolor", gcolor_elf_start, "Colour Picker" },
    { "gfire", gfire_elf_start, "Fireworks" },
    { "gmetro", gmetro_elf_start, "Metronome" },
    { "gconv", gconv_elf_start, "Unit Convert" },
    { "gbase", gbase_elf_start, "Base Convert" },
    { "gpass", gpass_elf_start, "Password Gen" },
    { "gclip", gclip_elf_start, "Clipboard" },
    { "gtodo", gtodo_elf_start, "To-Do" },
    { "gseq", gseq_elf_start, "Sequencer" },
    { "cc", cc_elf_start, "C Compiler" },
    { "crash", crash_elf_start, "Crash (core-dump demo)" },
    { "futex", futex_elf_start, "Futex demo" },
    { "nettcp", nettcp_elf_start, "TCP-over-files demo" },
    { "crashinfo", crashinfo_elf_start, "Core-dump reader" },
    { "forktest", forktest_elf_start, "COW fork demo" },
    { "execdemo", execdemo_elf_start, "fork+exec demo" },
    { "nstest", nstest_elf_start, "mount-namespace demo" },
    { "steptest", steptest_elf_start, "single-step demo" },
    { "scnotify", scnotify_elf_start, "syscall-supervisor demo" },
    { "fswaittest", fswaittest_elf_start, "fswait multi-wait demo" },
    { "sigfdtest", sigfdtest_elf_start, "signalfd demo" },
    { "bpftest", bpftest_elf_start, "eBPF packet-filter demo" },
    { "fantest", fantest_elf_start, "userspace-FS demo" },
    { "iouringtest", iouringtest_elf_start, "io_uring batch demo" },
    { "msealtest", msealtest_elf_start, "mseal hardening demo" },
    { "httpd", httpd_elf_start, "in-guest HTTP server" },
    { "uffdtest", uffdtest_elf_start, "userfaultfd demo" },
    { "mmapfile", mmapfile_elf_start, "file-backed mmap demo" },
    { "threads", threads_elf_start, "kernel threads demo" },
    { "robustfutex", robustfutex_elf_start, "robust futex demo" },
    { "overlay", overlay_elf_start, "overlayfs demo" },
    { "pcwd", pcwd_elf_start, "per-process cwd demo" },
};
#define NPROGS (int)(sizeof(progs)/sizeof(progs[0]))

extern void enter_user(uint64_t entry, uint64_t ustack);
extern void iret_to_user(struct registers *r);   /* resume ring3 from a cloned trap frame (fork child); asm, no return */

int app_cols(void) { return APP_DEF_COLS; }   /* default open size (the WM opens a terminal window at this) */
int app_rows(void) { return APP_DEF_ROWS; }
int app_grid_cols(app_t *a) { return (a && a->cols) ? a->cols : APP_DEF_COLS; }   /* CURRENT visible grid size */
int app_grid_rows(app_t *a) { return (a && a->rows) ? a->rows : APP_DEF_ROWS; }
int app_is_gfx(app_t *a) { return a && a->gfx != 0; }                            /* gfx-canvas app vs text terminal */
/* The WM calls this as a text-app window is dragged-resized: clamp to [MIN,_MAX],
 * keep the cursor in-bounds, and subsequent output uses the new size (M1473). */
void app_set_grid(app_t *a, int cols, int rows) {
    if (!a) return;
    if (cols < APP_MIN_COLS) cols = APP_MIN_COLS; if (cols > APP_COLS_MAX) cols = APP_COLS_MAX;
    if (rows < APP_MIN_ROWS) rows = APP_MIN_ROWS; if (rows > APP_ROWS_MAX) rows = APP_ROWS_MAX;
    if (cols == a->cols && rows == a->rows) return;
    a->cols = cols; a->rows = rows;
    if (a->cx >= cols) a->cx = cols - 1;
    if (a->cy >= rows) a->cy = rows - 1;
    a->gdirty = 1;
}
const char *app_title(app_t *a) { return a->title; }
const char *app_cwd_str(app_t *a) { return (a && a->cwd_path[0]) ? a->cwd_path : "/"; }  /* cwd path of any app, for /proc/<pid>/cwd (M1249) */
const char *app_exe_str(app_t *a) { return (a && a->exe_path[0]) ? a->exe_path : "?"; }   /* spawn/exec path, for /proc/<pid>/exe (M1250) */
const char *app_arg(app_t *a) { return a ? a->launch_arg : ""; }          /* /proc/<pid>/cmdline */
void       *app_task(app_t *a) { return a ? (void *)a->task : 0; }        /* the task_t*, for /proc/<pid>/ctl stop/cont */
uint64_t    app_cr3(app_t *a) { return a ? a->cr3 : 0; }                  /* the app's address space, for /proc/<pid>/wss */
uint64_t    app_heap_bytes(app_t *a) { return (a && a->heap_end) ? a->heap_end - UHEAP_BASE : 0; }
int         app_vma_count(app_t *a) { return a ? a->nvma : 0; }
int         app_ppid(app_t *a)    { return a ? a->parent : 0; }   /* parent pid, for /proc/<pid>/stat (M1231) */
void        app_io_counts(app_t *a, uint64_t *rc, uint64_t *wc) { if (rc) *rc = a ? a->rchar : 0; if (wc) *wc = a ? a->wchar : 0; }  /* /proc/<pid>/io (M1244) */
int         app_pgid_of(app_t *a) { return a ? a->pgid : 0; }     /* process-group id (M1231) */
int         app_sid_of(app_t *a)  { return a ? a->sid : 0; }      /* session id (M1231) */

/* Format the app's user-space memory map (/proc/<pid>/maps): each region as a
 * "0xSTART-0xEND perm [label]" line, like Linux. Bounded by `max`. */
static int maps_hex(char *b, int p, int max, uint64_t v) {
    char t[16]; int n = 0;
    if (v == 0) t[n++] = '0';
    while (v) { t[n++] = "0123456789abcdef"[v & 0xF]; v >>= 4; }
    if (p < max - 1) b[p++] = '0';
    if (p < max - 1) b[p++] = 'x';
    while (n > 0 && p < max - 1) b[p++] = t[--n];
    return p;
}
static int maps_str(char *b, int p, int max, const char *s) {
    while (*s && p < max - 1) b[p++] = *s++;
    return p;
}
int app_format_maps(app_t *a, char *b, int max) {
    if (!a || max <= 0) return 0;
    int p = 0;
    if (a->heap_end > UHEAP_BASE) {     /* the program break heap */
        p = maps_hex(b, p, max, UHEAP_BASE); p = maps_str(b, p, max, "-");
        p = maps_hex(b, p, max, a->heap_end); p = maps_str(b, p, max, " rw-  [heap]\n");
    }
    for (int i = 0; i < a->nvma; i++) {  /* demand-paged mmap regions */
        p = maps_hex(b, p, max, a->vma[i].start); p = maps_str(b, p, max, "-");
        p = maps_hex(b, p, max, a->vma[i].start + a->vma[i].len);
        p = maps_str(b, p, max, a->vma[i].huge ? " rw-  [mmap-huge]\n" : " rw-  [mmap]\n");
    }
    p = maps_hex(b, p, max, USTACK_BASE);   /* the user stack region */
    p = maps_str(b, p, max, "  rw-  [stack]\n");
    if (p < max) b[p] = 0;
    return p;
}

static int maps_dec(char *b, int p, int max, uint64_t v) {
    char t[24]; int n = 0;
    if (v == 0) t[n++] = '0';
    while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
    while (n > 0 && p < max - 1) b[p++] = t[--n];
    return p;
}
static int smaps_kv(char *b, int p, int max, const char *k, uint64_t kb) {   /* "Key: <n> kB" */
    p = maps_str(b, p, max, k); p = maps_str(b, p, max, " ");
    p = maps_dec(b, p, max, kb); p = maps_str(b, p, max, " kB\n");
    return p;
}
/* One /proc/<pid>/smaps block for [start,end) of app `a`: the address header
 * then Rss / Pss / Referenced / Dirty / Swap, computed by walking the region's
 * leaf PTEs in the app's own address space (vmm_pte_in). Pss (proportional set
 * size) divides each resident page by its sharer count (pmm_refcount+1), so a
 * COW-shared frame counts fractionally — the metric that makes shared memory
 * accountable. Bounded by `max`. (M1151) */
static int app_smaps_region(char *b, int p, int max, app_t *a, uint64_t start, uint64_t end, const char *label) {
    uint64_t rss = 0, pss_b = 0, dirty = 0, ref = 0, swap = 0;
    for (uint64_t va = start; va < end; va += PAGE_SIZE) {
        uint64_t pte = vmm_pte_in(a->cr3, va);
        if (pte & PTE_PRESENT) {
            rss++;
            if (pte & PTE_DIRTY)    dirty++;
            if (pte & PTE_ACCESSED) ref++;
            int rc = pmm_refcount(pte & PTE_ADDR_MASK);     /* extra refs; sharers = rc+1 */
            pss_b += (uint64_t)PAGE_SIZE / (uint64_t)(rc + 1);
        } else if (pte & PTE_SWAP) {
            swap++;
        }
    }
    p = maps_hex(b, p, max, start); p = maps_str(b, p, max, "-");
    p = maps_hex(b, p, max, end);   p = maps_str(b, p, max, " rw-p ");
    p = maps_str(b, p, max, label); p = maps_str(b, p, max, "\n");
    p = smaps_kv(b, p, max, "Rss:",        rss   * PAGE_SIZE / 1024);
    p = smaps_kv(b, p, max, "Pss:",        pss_b / 1024);
    p = smaps_kv(b, p, max, "Referenced:", ref   * PAGE_SIZE / 1024);
    p = smaps_kv(b, p, max, "Dirty:",      dirty * PAGE_SIZE / 1024);
    p = smaps_kv(b, p, max, "Swap:",       swap  * PAGE_SIZE / 1024);
    return p;
}
/* /proc/<pid>/fd: list the process's open descriptors with type + target — pipe
 * (read/write end + pipe id), FIFO/file (path + offset). Read-only; makes the fd
 * table (M1187 pipes / M1188 FIFOs / M1193 files) observable. (M1194) */
int app_format_fds(app_t *a, char *b, int max) {
    if (!a || max <= 0) return 0;
    int p = 0;
    for (int i = 0; i < APP_NFD; i++) {
        if (!a->fd[i].used) continue;
        p = maps_dec(b, p, max, (uint64_t)i); p = maps_str(b, p, max, ": ");
        if (a->fd[i].type == 1) {                       /* anonymous pipe / FIFO end */
            p = maps_str(b, p, max, a->fd[i].write_end ? "pipe [write] #" : "pipe [read] #");
            p = maps_dec(b, p, max, (uint64_t)a->fd[i].obj);
        } else if (a->fd[i].type == 2) {                /* regular file */
            p = maps_str(b, p, max, "file ");
            p = maps_str(b, p, max, a->fd[i].path);
            p = maps_str(b, p, max, " @");
            p = maps_dec(b, p, max, (uint64_t)a->fd[i].off);
        } else {
            p = maps_str(b, p, max, "?");
        }
        p = maps_str(b, p, max, "\n");
    }
    if (p == 0) p = maps_str(b, p, max, "(no open fds)\n");
    if (p < max) b[p] = 0;
    return p;
}
/* /proc/<pid>/smaps: a per-region memory breakdown (heap + each mmap VMA), the
 * Linux idiom `pmap -x` / smaps reads. Reuses the demand-paging machinery's own
 * page tables; read-only. (M1151) */
int app_format_smaps(app_t *a, char *b, int max) {
    if (!a || max <= 0) return 0;
    int p = 0;
    if (a->heap_end > UHEAP_BASE)
        p = app_smaps_region(b, p, max, a, UHEAP_BASE, a->heap_end, "[heap]");
    for (int i = 0; i < a->nvma; i++)
        p = app_smaps_region(b, p, max, a, a->vma[i].start, a->vma[i].start + a->vma[i].len,
                             a->vma[i].huge ? "[mmap-huge]" : (a->vma[i].file_backed ? "[mmap-file]" : (a->vma[i].locked ? "[mmap-locked]" : "[mmap]")));
    if (p < max) b[p] = 0;
    return p;
}

/* One /proc/<pid>/pagemap region: the [start,end) header, then ONE line per
 * non-absent page — its virtual address, physical frame number (PFN) and flags
 * (C=COW-shared, D=dirty/written, A=accessed) for a resident page, or "swap"
 * for a swapped-out page. Absent (never-faulted) pages are omitted so a sparse
 * demand-paged region stays compact. Walks the app's own leaf PTEs via
 * vmm_pte_in; read-only. The text form of Linux's /proc/<pid>/pagemap. (M1167) */
static int app_pagemap_region(char *b, int p, int max, app_t *a, uint64_t start, uint64_t end, const char *label) {
    p = maps_hex(b, p, max, start); p = maps_str(b, p, max, "-");
    p = maps_hex(b, p, max, end);   p = maps_str(b, p, max, " ");
    p = maps_str(b, p, max, label); p = maps_str(b, p, max, "\n");
    for (uint64_t va = start; va < end && p < max - 80; va += PAGE_SIZE) {
        uint64_t pte = vmm_pte_in(a->cr3, va);
        if (pte & PTE_PRESENT) {
            p = maps_str(b, p, max, "  ");  p = maps_hex(b, p, max, va);
            p = maps_str(b, p, max, " pfn=");
            p = maps_hex(b, p, max, (pte & PTE_ADDR_MASK) >> 12);
            p = maps_str(b, p, max, " ");
            if (pte & PTE_COW)      p = maps_str(b, p, max, "C");
            if (pte & PTE_DIRTY)    p = maps_str(b, p, max, "D");
            if (pte & PTE_ACCESSED) p = maps_str(b, p, max, "A");
            p = maps_str(b, p, max, "\n");
        } else if (pte & PTE_SWAP) {
            p = maps_str(b, p, max, "  ");  p = maps_hex(b, p, max, va);
            p = maps_str(b, p, max, " swap\n");
        }
    }
    return p;
}
/* /proc/<pid>/pagemap: per-page residency + PFN for the heap and each mmap VMA.
 * Read-only; reuses the demand-paging machinery's page tables. (M1167) */
int app_format_pagemap(app_t *a, char *b, int max) {
    if (!a || max <= 0) return 0;
    int p = 0;
    if (a->heap_end > UHEAP_BASE)
        p = app_pagemap_region(b, p, max, a, UHEAP_BASE, a->heap_end, "[heap]");
    for (int i = 0; i < a->nvma; i++)
        p = app_pagemap_region(b, p, max, a, a->vma[i].start, a->vma[i].start + a->vma[i].len,
                               a->vma[i].huge ? "[mmap-huge]" : (a->vma[i].file_backed ? "[mmap-file]" : (a->vma[i].locked ? "[mmap-locked]" : "[mmap]")));
    if (p < max) b[p] = 0;
    return p;
}

static struct app *cur(void) { return (struct app *)task_self()->proc; }

/* SCM_RIGHTS — fd passing over AF_UNIX (M1265). A per-connection mailbox holds
 * one in-flight descriptor (a snapshot of the sender's fdent); the peer's
 * recvfd installs a FRESH fd in its own table referring to the SAME underlying
 * object (pipe/file/memfd/...), exactly as Unix ancillary-data fd passing does.
 * Keyed by the AF_UNIX connection index (unix_ep_conn), so a sendfd on one
 * endpoint is delivered to the other. */
extern int unix_ep_conn(int ep);   /* kernel/unixsock.c */
#define SCM_SLOTS 16
static struct { int valid; struct fdent fe; } g_scm[SCM_SLOTS];

int app_scm_send(int ep, int fd) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    int ci = unix_ep_conn(ep); if (ci < 0 || ci >= SCM_SLOTS) return -1;
    if (g_scm[ci].valid) return -1;            /* one in-flight fd per connection */
    g_scm[ci].fe = a->fd[fd];                  /* snapshot the descriptor (shares the underlying object) */
    g_scm[ci].fe.cloexec = 0;                  /* a freshly-received fd is not close-on-exec */
    g_scm[ci].valid = 1;
    return 0;
}

int app_scm_recv(int ep) {
    struct app *a = cur(); if (!a) return -1;
    int ci = unix_ep_conn(ep); if (ci < 0 || ci >= SCM_SLOTS) return -1;
    if (!g_scm[ci].valid) return -1;           /* nothing pending */
    int fd = -1;
    for (int i = 3 /*APP_FD_FIRST: 0-2 are stdio*/; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }
    if (fd < 0) return -1;                     /* receiver's fd table is full */
    a->fd[fd] = g_scm[ci].fe;                  /* install the passed descriptor */
    g_scm[ci].valid = 0;
    return fd;
}

/* getcwd (M1248): canonicalize an absolute-ish path (resolve "."/".."/"//") into
 * out. Component-stack: push names, pop on "..". Pure string work — the cwd_path
 * is cosmetic-for-getcwd (the real cwd is the component state above), so a bad
 * input can only make getcwd wrong, never corrupt an open. */
static void app_norm_abs(const char *in, char *out, int max) {
    int st[64], ln[64], nc = 0, i = 0;
    while (in[i]) {
        while (in[i] == '/') i++;
        if (!in[i]) break;
        int s = i; while (in[i] && in[i] != '/') i++;
        int len = i - s;
        if (len == 1 && in[s] == '.') continue;
        if (len == 2 && in[s] == '.' && in[s + 1] == '.') { if (nc > 0) nc--; continue; }
        if (nc < 64) { st[nc] = s; ln[nc] = len; nc++; }
    }
    int p = 0;
    if (nc == 0) { if (max > 1) { out[0] = '/'; out[1] = 0; } else if (max > 0) out[0] = 0; return; }
    for (int c = 0; c < nc; c++) { if (p < max - 1) out[p++] = '/'; for (int k = 0; k < ln[c] && p < max - 1; k++) out[p++] = in[st[c] + k]; }
    out[p] = 0;
}
/* Update the calling process's cwd_path after a successful chdir(rel). */
void app_chdir_track(const char *rel) {
    struct app *a = cur(); if (!a || !rel) return;
    const char *base = a->cwd_path[0] ? a->cwd_path : "/";
    char joined[288]; int t = 0;
    if (rel[0] == '/') { for (int i = 0; rel[i] && t < 287; i++) joined[t++] = rel[i]; }
    else { for (int i = 0; base[i] && t < 287; i++) joined[t++] = base[i];
           if (t < 287) joined[t++] = '/';
           for (int i = 0; rel[i] && t < 287; i++) joined[t++] = rel[i]; }
    joined[t] = 0;
    app_norm_abs(joined, a->cwd_path, (int)sizeof a->cwd_path);
}
/* getcwd: copy the cwd string out. Returns its length, or -1 if it won't fit. */
long app_getcwd(char *buf, unsigned long max) {
    struct app *a = cur(); if (!a || max == 0) return -1;
    const char *p = a->cwd_path[0] ? a->cwd_path : "/";
    unsigned long n = 0; while (p[n]) n++;
    if (n + 1 > max) return -1;
    for (unsigned long i = 0; i <= n; i++) buf[i] = p[i];
    return (long)n;
}
void app_io_account(int is_write, long n) {   /* tally fd read/write bytes for /proc/<pid>/io (M1244) */
    struct app *a = cur();
    if (a && n > 0) { if (is_write) a->wchar += (uint64_t)n; else a->rchar += (uint64_t)n; }
}

/* --- pledge() sandbox (M1074) --------------------------------------------- */
app_t *app_current(void) { return cur(); }
int  app_ns_id(app_t *a)        { return a ? a->ns_id : 0; }      /* mount-namespace id (M1122) */
void app_set_ns_id(app_t *a, int id) { if (a) a->ns_id = id; }
void app_self_faults(uint64_t *minflt, uint64_t *majflt) {        /* the current app's page-fault counters (getrusage, M1150) */
    app_t *a = cur();
    if (minflt) *minflt = a ? a->minflt : 0;
    if (majflt) *majflt = a ? a->majflt : 0;
}
void app_faults(app_t *a, uint64_t *minflt, uint64_t *majflt) {   /* page-fault counters of ANY app, for /proc/<pid>/stat (M1252) */
    if (minflt) *minflt = a ? a->minflt : 0;
    if (majflt) *majflt = a ? a->majflt : 0;
}

/* per-process cwd (M1144): the VFS stashes/loads an app's current directory here
 * across app switches. A fresh app is zeroed -> synth 0 + "" + fat 0 = boot root. */
void app_cwd_save(app_t *a, int synth, const char *sub, uint32_t fat) {
    if (!a) return;
    a->cwd_synth = synth; a->cwd_fat = fat;
    int i = 0; for (; sub[i] && i < 127; i++) a->cwd_sub[i] = sub[i]; a->cwd_sub[i] = 0;
}
void app_cwd_load(app_t *a, int *synth, char *sub, int submax, uint32_t *fat) {
    if (!a) { *synth = 0; sub[0] = 0; *fat = 0; return; }
    *synth = a->cwd_synth; *fat = a->cwd_fat;
    int i = 0; for (; a->cwd_sub[i] && i < submax - 1; i++) sub[i] = a->cwd_sub[i]; sub[i] = 0;
}

/* Restrict the calling app's promises. Monotonic, like OpenBSD's pledge: the
 * first call sets the set; later calls may only DROP promises (the new mask
 * must be a subset of the current), never regain them. Returns 0 / -1. */
int app_pledge(app_t *a, uint32_t mask) {
    if (!a) return -1;
    if (a->pledged && (mask & ~a->promises)) return -1;   /* tried to add a promise back */
    a->promises = mask;
    a->pledged  = 1;
    return 0;
}
int      app_is_pledged(app_t *a) { return a && a->pledged; }
uint32_t app_promises(app_t *a)   { return a ? a->promises : 0; }

/* The promise name <-> bit table — the user ABI shared by SYS_pledge parsing
 * and /proc/<pid>/status formatting. */
static const struct { const char *name; uint32_t bit; } pledge_tab[] = {
    {"stdio",PL_STDIO},{"rpath",PL_RPATH},{"wpath",PL_WPATH},{"inet",PL_INET},
    {"gfx",PL_GFX},{"proc",PL_PROC},{"vm",PL_VM},{"power",PL_POWER},{"thread",PL_THREAD},
};
#define PLEDGE_NTAB (int)(sizeof(pledge_tab)/sizeof(pledge_tab[0]))

int app_pledge_parse(const char *s, uint32_t *out) {
    uint32_t mask = 0;
    while (*s) {
        while (*s == ' ' || *s == '\t') s++;
        if (!*s) break;
        const char *w = s; int len = 0;
        while (s[len] && s[len] != ' ' && s[len] != '\t') len++;
        s += len;
        int matched = 0;
        for (int i = 0; i < PLEDGE_NTAB; i++) {
            const char *n = pledge_tab[i].name; int j = 0;
            while (j < len && n[j] && n[j] == w[j]) j++;
            if (j == len && n[j] == 0) { mask |= pledge_tab[i].bit; matched = 1; break; }
        }
        if (!matched) return -1;                     /* unknown promise name */
    }
    *out = mask;
    return 0;
}

int app_pledge_format(uint32_t mask, char *buf, int max) {
    int p = 0;
    for (int i = 0; i < PLEDGE_NTAB; i++)
        if (mask & pledge_tab[i].bit) {
            if (p && p < max - 1) buf[p++] = ' ';
            const char *n = pledge_tab[i].name;
            while (*n && p < max - 1) buf[p++] = *n++;
        }
    if (p < max) buf[p] = 0;
    return p;
}

/* --- unveil(): restrict which filesystem paths a process can touch -----------
 * Like OpenBSD's unveil: before the first call every path is visible; the first
 * unveil() flips the process to "only the unveiled prefixes are reachable", with
 * per-prefix r/w permission. A denied access fails (-1, as if absent) — it does
 * NOT kill (that's pledge's job). unveil(NULL) locks the set. */
uint32_t app_unveil_parse(const char *s) {
    uint32_t b = 0;
    for (; s && *s; s++) {
        if (*s == 'r' || *s == 'R') b |= UV_R;
        else if (*s == 'w' || *s == 'W' || *s == 'c' || *s == 'C') b |= UV_W;  /* c(reate) implies write */
    }
    return b;
}

int app_unveil(app_t *a, const char *path, uint32_t perms) {
    if (!a) return -1;
    if (!path || !path[0]) { a->uv_locked = 1; a->uv_active = 1; return 0; }  /* unveil(NULL): lock */
    if (a->uv_locked || a->nuv >= APP_NUNVEIL) return -1;
    int i = 0; while (path[i] && i < (int)sizeof a->uv[0].path - 1) { a->uv[a->nuv].path[i] = path[i]; i++; }
    a->uv[a->nuv].path[i] = 0;
    a->uv[a->nuv].perms = (uint8_t)perms;
    a->nuv++;
    a->uv_active = 1;
    return 0;
}

static int uv_ci(char c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }
/* `prefix` matches `path` if it is path itself or a parent directory of it. */
static int uv_match(const char *prefix, const char *path) {
    int i = 0;
    while (prefix[i] && uv_ci(prefix[i]) == uv_ci(path[i])) i++;
    if (prefix[i] != 0) return 0;                       /* prefix not fully consumed */
    return path[i] == 0 || path[i] == '/';              /* exact, or a sub-path boundary */
}

int app_unveil_ok(app_t *a, const char *path, int need_write) {
    if (!a || !a->uv_active) return 1;                  /* unveil never called -> all allowed */
    for (int i = 0; i < a->nuv; i++)
        if (uv_match(a->uv[i].path, path) &&
            (need_write ? (a->uv[i].perms & UV_W) : (a->uv[i].perms & UV_R)))
            return 1;
    return 0;
}

/* ---- text grid ---- */
static void grid_clear(struct app *a) {
    if (a->cols <= 0) { a->cols = APP_DEF_COLS; a->rows = APP_DEF_ROWS; }   /* first use: default size */
    for (int r = 0; r < APP_ROWS_MAX; r++)                                 /* blank the FULL array so cells exposed by a later grow are clean */
        for (int c = 0; c < APP_COLS_MAX; c++) { a->grid[r][c] = ' '; a->gcol[r][c] = 0; }
    a->cx = a->cy = 0;
    a->sb_count = 0; a->view = 0;
    a->gdirty = 1;
}
static void grid_scroll(struct app *a) {
    /* the top line is about to scroll off — keep it in the scrollback ring */
    if (a->sb_count < SB_ROWS) {
        memcpy(a->sb[a->sb_count++], a->grid[0], a->cols);
        if (a->view > 0 && a->view < a->sb_count) a->view++;   /* stay on the same lines */
    } else {
        for (int r = 1; r < SB_ROWS; r++) memcpy(a->sb[r-1], a->sb[r], a->cols);
        memcpy(a->sb[SB_ROWS-1], a->grid[0], a->cols);
    }
    for (int r = 1; r < a->rows; r++) memcpy(a->grid[r-1], a->grid[r], a->cols);
    for (int c = 0; c < a->cols; c++) a->grid[a->rows-1][c] = ' ';
    for (int r = 1; r < a->rows; r++) memcpy(a->gcol[r-1], a->gcol[r], a->cols);   /* live colours scroll with their rows */
    for (int c = 0; c < a->cols; c++) a->gcol[a->rows-1][c] = 0;
    a->cy = a->rows - 1;
}
static void grid_nl(struct app *a) { a->cx = 0; if (++a->cy >= a->rows) grid_scroll(a); }
/* Erase up to `n` echoed chars, but never past the input start (cx0,cy0) — so
 * history recall can't blank the prompt or earlier output. Handles wrapping. */
static void grid_erase(struct app *a, int n, int cx0, int cy0) {
    int avail = (a->cy - cy0) * a->cols + (a->cx - cx0);
    if (n > avail) n = avail;
    for (int i = 0; i < n; i++) {
        if (a->cx > 0) a->cx--;
        else if (a->cy > 0) { a->cy--; a->cx = a->cols - 1; }
        a->grid[a->cy][a->cx] = ' ';
    }
}
static void grid_putc(struct app *a, char ch) {
    a->gdirty = 1;
    if (ch == '\n') { grid_nl(a); return; }
    if (ch == '\r') { a->cx = 0; return; }
    a->grid[a->cy][a->cx] = ch;
    a->gcol[a->cy][a->cx] = a->curcol;
    if (++a->cx >= a->cols) grid_nl(a);
}

/* Move the echo cursor over already-painted cells (no clearing), for in-line
 * editing (left/right/home/end). Wrapping mirrors grid_putc/grid_erase. */
static void cursor_back(struct app *a, int k) {
    while (k-- > 0) {
        if (a->cx > 0) a->cx--;
        else if (a->cy > 0) { a->cy--; a->cx = a->cols - 1; }
    }
    a->gdirty = 1;
}
static void cursor_fwd(struct app *a, int k) {
    while (k-- > 0)
        if (++a->cx >= a->cols) { a->cx = 0; if (++a->cy >= a->rows) grid_scroll(a); }
    a->gdirty = 1;
}
static void emit_range(struct app *a, const char *buf, unsigned i, unsigned j) {
    for (; i < j; i++) grid_putc(a, buf[i]);
}

/* ---- system clipboard (one buffer shared by every app) -------------------
 * Set by a terminal text selection, read by middle-click paste — so text can
 * be carried between windows (e.g. a URL from the browser into the shell). */
static char g_clip[CLIP_MAX];
static int  g_clip_len;
void clip_set(const char *s, int n) {
    if (n < 0) n = 0;
    if (n > CLIP_MAX - 1) n = CLIP_MAX - 1;
    for (int i = 0; i < n; i++) g_clip[i] = s[i];
    g_clip[n] = 0; g_clip_len = n;
}
int clip_get(char *out, int max) {
    int n = g_clip_len;
    if (n > max - 1) n = max - 1;
    for (int i = 0; i < n; i++) out[i] = g_clip[i];
    if (max > 0) out[n] = 0;
    return n;
}

/* The character currently displayed at visible row r, column c — reading from
 * the scrollback or the live grid exactly as app_render does, so selection
 * highlighting and text extraction match what's on screen. */
static char app_cell(struct app *a, int r, int c) {
    if (r < 0 || r >= a->rows || c < 0 || c >= a->cols) return ' ';
    int L = (a->sb_count - a->view) + r;
    if (L >= 0 && L < a->sb_count) return a->sb[L][c];
    if (L >= a->sb_count && (L - a->sb_count) < a->rows) return a->grid[L - a->sb_count][c];
    return ' ';
}

/* Order the selection so (r0,c0) is the top-left end and (r1,c1) the bottom-right. */
static void sel_ordered(struct app *a, int *r0, int *c0, int *r1, int *c1) {
    *r0 = a->sel_r0; *c0 = a->sel_c0; *r1 = a->sel_r1; *c1 = a->sel_c1;
    if (*r1 < *r0 || (*r1 == *r0 && *c1 < *c0)) {
        int tr = *r0, tc = *c0; *r0 = *r1; *c0 = *c1; *r1 = tr; *c1 = tc;
    }
}

/* A low-alpha blend of the terminal's near-black base tint with a sampled
 * wallpaper color — the translucent-terminal effect (M1527). Blending
 * against desktop_wallpaper_sample (the STABLE cached backdrop) rather than
 * whatever's currently in the live framebuffer matters: a terminal that
 * redraws often (typing, output arriving) would otherwise blend toward its
 * OWN previous frame each time and get muddier with every redraw instead of
 * staying a consistent tint. ~18% wallpaper keeps text solidly readable
 * while still showing real color bleeding through. */
static uint32_t term_bg_blend(uint32_t wp) {
    int wr = (int)((wp >> 16) & 0xFF), wg = (int)((wp >> 8) & 0xFF), wb = (int)(wp & 0xFF);
    int r = 10 + (wr - 10) * 18 / 100, g = 10 + (wg - 10) * 18 / 100, b = 10 + (wb - 10) * 18 / 100;
    return (uint32_t)(r << 16 | g << 8 | b);
}
void app_render(app_t *a, int px, int py, int focused) {
    /* Show a 17-row window into [scrollback ... live grid], scrolled up by view. */
    for (int r = 0; r < a->rows; r++) {
        int L = (a->sb_count - a->view) + r;        /* logical row in the combined buffer */
        for (int c = 0; c < a->cols; c++) {
            char ch = ' '; uint32_t fg = 0x33FF66;
            if (L >= 0 && L < a->sb_count) ch = a->sb[L][c];               /* scrollback: default green */
            else if (L >= a->sb_count && (L - a->sb_count) < a->rows) {
                int gr = L - a->sb_count; ch = a->grid[gr][c];
                fg = app_palette[a->gcol[gr][c] & 15];                     /* live grid: per-cell colour */
            }
            int cx = px + c * font_width, cy = py + r * font_height;
            fb_glyph(cx, cy, ch, fg, term_bg_blend(desktop_wallpaper_sample(cx, cy)));
        }
    }
    /* Scrollback scrollbar on the right edge (only when there's scrollback): a
     * dark track with a thumb whose size = visible/total and whose position
     * tracks `view`. Gives the wheel/PgUp scrollback visible feedback. */
    if (a->sb_count > 0) {
        int total = a->sb_count + a->rows;
        int sbx = px + a->cols * font_width + 1;
        int trackh = a->rows * font_height;
        fb_fill_rect(sbx, py, 3, trackh, 0x202428);
        int th = trackh * a->rows / total; if (th < 8) th = 8;
        int top = a->sb_count - a->view;                       /* first visible logical row */
        int ty = py + (trackh - th) * top / (a->sb_count ? a->sb_count : 1);
        fb_fill_rect(sbx, ty, 3, th, 0x6A7480);
    } else if (a->view > 0)                          /* (fallback) scrolled-up indicator */
        fb_glyph(px + (a->cols - 1) * font_width, py, '^', 0xFFD060, 0x0A0A0A);
    /* Text selection highlight (white on blue), drawn over the cells. Linear,
     * line-spanning: the first row runs from c0, the last to c1, rows between
     * are full-width — matching app_sel_commit's extraction. */
    if (a->sel_on) {
        int r0, c0, r1, c1; sel_ordered(a, &r0, &c0, &r1, &c1);
        for (int r = r0; r <= r1 && r < a->rows; r++) {
            if (r < 0) continue;
            int cs = (r == r0) ? c0 : 0, ce = (r == r1) ? c1 : a->cols;
            for (int c = cs; c < ce && c < a->cols; c++)
                fb_glyph(px + c * font_width, py + r * font_height, app_cell(a, r, c), 0xFFFFFF, 0x2C66D6);
        }
    }
    /* Block caret on the focused window at the live cursor, when it's in view
     * (hidden while scrolled up into the scrollback). Drawn over the cell so it
     * tracks left/right/home/end edits, not just the end of the line. Blinks
     * once a second (M1527, a "moving part") — the desktop's main loop forces
     * a full redraw on the same clock_tick edge this reads (app_shows_caret),
     * so the two always agree on when the state actually changes; drawing the
     * plain character (translucent bg, like every other cell) on the "off"
     * phase instead of nothing keeps the text underneath legible throughout. */
    if (focused && !a->gfx && !a->caret_off) {
        int cr = a->cy + a->view;
        if (cr >= 0 && cr < a->rows && a->cx >= 0 && a->cx < a->cols) {
            char ch = a->grid[a->cy][a->cx];
            int cx = px + a->cx * font_width, cy = py + cr * font_height;
            if ((timer_ticks() / 100) & 1)
                fb_glyph(cx, cy, (ch && ch != ' ') ? ch : ' ', 0x0A0A0A, 0x33FF66);
            else
                fb_glyph(cx, cy, ch ? ch : ' ', 0x33FF66, term_bg_blend(desktop_wallpaper_sample(cx, cy)));
        }
    }
}

int app_alive(app_t *a) { return a && a->used && !a->exited; }

/* Does this app's window currently show the blinking text caret (app_render,
 * M1527)? Lets the desktop's main loop know it must force a full redraw on
 * the once-a-second clock tick even when otherwise idle, so the blink is
 * actually observed — without exposing struct app's fields to desktop.c. */
int app_shows_caret(app_t *a) { return a && !a->gfx && !a->caret_off; }

/* --- waitpid support (M1117) ---------------------------------------------- */
static struct app *app_by_pid(int pid) {
    for (int i = 0; i < MAX_APPS; i++) if (apps[i].used && apps[i].pid == pid) return &apps[i];
    return 0;
}

/* process_vm_read (M1162): copy `len` bytes from process `pid`'s address space at
 * `raddr` into the CALLER's buffer `local` (which lives in the active address
 * space, so a plain write reaches it). Cross-address-space reads use the proven
 * vmm_translate_in + the HHDM, page by page; it stops at the first unmapped page
 * in the target. Permission: the target must be self, the caller's parent, or
 * the caller's child (a debugger over the process tree) — like ptrace's
 * same-tree rule. Returns bytes copied, or -1. Read-only; touches no fault path. */
long app_process_vm_read(int pid, uint64_t raddr, void *local, uint64_t len) {
    struct app *me = cur(), *t = app_by_pid(pid);
    if (!me || !t || !t->used) return -1;
    if (t != me && t->parent != me->pid && me->parent != t->pid) return -1;   /* same-tree only */
    uint8_t *out = (uint8_t *)local;
    uint64_t done = 0;
    while (done < len) {
        uint64_t va = raddr + done;
        uint64_t phys = vmm_translate_in(t->cr3, va);     /* phys (incl. page offset) in the target's AS */
        if (!phys) break;                                 /* unmapped page in the target -> stop */
        uint64_t chunk = 0x1000 - (va & 0xFFF);           /* up to the page boundary */
        if (chunk > len - done) chunk = len - done;
        const uint8_t *src = (const uint8_t *)hhdm(phys);
        for (uint64_t i = 0; i < chunk; i++) out[done + i] = src[i];
        done += chunk;
    }
    return (long)done;
}

/* process_vm_write (M1165): the symmetric poke — copy `len` bytes from the
 * caller's buffer `local` into process `pid`'s address space at `raddr`. Same
 * same-tree permission as the read. The correctness crux is COW: writing a
 * target page that is COW-marked or shared (pmm_refcount > 0) would clobber the
 * sharer, so we first PRIVATISE it — allocate a fresh frame, copy the page,
 * remap the target's PTE writable (vmm_set_pte_in), drop the old ref — exactly
 * app_fault_handle's COW break, applied to the target's CR3. A genuinely
 * read-only (non-COW) page is refused (write stops there). Returns bytes
 * written, or -1. */
long app_process_vm_write(int pid, uint64_t raddr, const void *local, uint64_t len) {
    struct app *me = cur(), *t = app_by_pid(pid);
    if (!me || !t || !t->used) return -1;
    if (t != me && t->parent != me->pid && me->parent != t->pid) return -1;   /* same-tree only */
    const uint8_t *in = (const uint8_t *)local;
    uint64_t done = 0;
    while (done < len) {
        uint64_t va = raddr + done;
        uint64_t vpage = va & ~(uint64_t)0xFFF;
        uint64_t pte = vmm_pte_in(t->cr3, vpage);
        if (!(pte & PTE_PRESENT)) break;                  /* unmapped/swapped -> stop */
        uint64_t frame = pte & PTE_ADDR_MASK;
        if ((pte & PTE_COW) || pmm_refcount(frame) != 0) {        /* shared -> privatise before writing */
            uint64_t nf = pmm_alloc_frame();
            if (!nf) break;
            uint8_t *s = (uint8_t *)hhdm(frame), *d = (uint8_t *)hhdm(nf);
            for (int b = 0; b < PAGE_SIZE; b++) d[b] = s[b];
            vmm_set_pte_in(t->cr3, vpage, nf | PTE_PRESENT | PTE_USER | PTE_WRITABLE | (pte & PTE_NX));
            pmm_free_frame(frame);                        /* drop the old shared reference */
            frame = nf;
        } else if (!(pte & PTE_WRITABLE)) {
            break;                                        /* genuinely read-only (e.g. code) -> refuse */
        }
        uint64_t off = va & 0xFFF;
        uint64_t chunk = 0x1000 - off; if (chunk > len - done) chunk = len - done;
        uint8_t *dst = (uint8_t *)hhdm(frame + off);
        for (uint64_t i = 0; i < chunk; i++) dst[i] = in[done + i];
        done += chunk;
    }
    return (long)done;
}

/* setrlimit/getrlimit (M1163): per-process resource limits. Only RLIMIT_NPROC
 * (live-child cap) is enforced so far (in app_fork). Stored as 0 = unlimited;
 * reported back as RLIM_INFINITY. Inherited across fork. */
int app_setrlimit(int resource, uint64_t val) {
    struct app *a = cur(); if (!a) return -1;
    uint64_t v = (val == RLIM_INFINITY) ? 0 : val;      /* stored: 0 = unlimited */
    if (resource == RLIMIT_NPROC)  { a->rlim_nproc  = v; return 0; }
    if (resource == RLIMIT_AS)     { a->rlim_as     = v; return 0; }
    if (resource == RLIMIT_DATA)   { a->rlim_data   = v; return 0; }
    if (resource == RLIMIT_NOFILE) { a->rlim_nofile = v; return 0; }
    if (resource == RLIMIT_CPU)    { a->rlim_cpu    = v; return 0; }
    if (resource == RLIMIT_FSIZE)  { a->rlim_fsize  = v; return 0; }
    if (resource == RLIMIT_MEMLOCK) { a->rlim_memlock = v; return 0; }
    if (resource == RLIMIT_CORE)   { a->rlim_core    = v; return 0; }
    return -1;                                          /* other resources not yet enforced */
}
uint64_t app_getrlimit(int resource) {
    struct app *a = cur(); if (!a) return RLIM_INFINITY;
    uint64_t v = (resource == RLIMIT_NPROC)  ? a->rlim_nproc  :
                 (resource == RLIMIT_AS)     ? a->rlim_as     :
                 (resource == RLIMIT_DATA)   ? a->rlim_data   :
                 (resource == RLIMIT_NOFILE) ? a->rlim_nofile :
                 (resource == RLIMIT_CPU)    ? a->rlim_cpu    :
                 (resource == RLIMIT_FSIZE)  ? a->rlim_fsize  :
                 (resource == RLIMIT_MEMLOCK) ? a->rlim_memlock :
                 (resource == RLIMIT_CORE)   ? a->rlim_core   : 0;
    return v ? v : RLIM_INFINITY;
}
/* prlimit (M1214): get — and optionally set — ANOTHER process's resource limit
 * (the cross-process complement of get/setrlimit). pid==0 means the caller.
 * Returns the old/current value (RLIM_INFINITY if unset / bad pid / bad
 * resource). Single-user OS: any pid is addressable. */
long app_prlimit(int pid, int resource, uint64_t newval, int do_set) {
    struct app *t = pid ? app_by_pid(pid) : cur();
    if (!t) return (long)RLIM_INFINITY;
    uint64_t *slot = (resource == RLIMIT_NPROC)  ? &t->rlim_nproc :
                     (resource == RLIMIT_AS)     ? &t->rlim_as :
                     (resource == RLIMIT_DATA)   ? &t->rlim_data :
                     (resource == RLIMIT_NOFILE) ? &t->rlim_nofile :
                     (resource == RLIMIT_CPU)    ? &t->rlim_cpu :
                     (resource == RLIMIT_FSIZE)  ? &t->rlim_fsize :
                     (resource == RLIMIT_MEMLOCK) ? &t->rlim_memlock :
                     (resource == RLIMIT_CORE)   ? &t->rlim_core : 0;
    if (!slot) return (long)RLIM_INFINITY;
    uint64_t old = *slot ? *slot : RLIM_INFINITY;       /* 0 stored = unlimited */
    if (do_set) *slot = (newval == RLIM_INFINITY) ? 0 : newval;
    return (long)old;
}
/* /proc/<pid>/limits (M1214): the per-process resource limits the kernel
 * actually enforces, as a Linux-style table (0/unset shows "unlimited"). */
static int lim_dec(char *b, int p, int max, uint64_t v) {
    char t[24]; int n = 0;
    if (v == 0) t[n++] = '0';
    while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
    while (n > 0 && p < max - 1) b[p++] = t[--n];
    return p;
}
int app_format_limits(app_t *ap, char *b, int max) {
    struct app *a = (struct app *)ap;
    if (!a || max <= 0) return 0;
    int p = 0;
    p = maps_str(b, p, max, "Limit           Value\n");
    struct { const char *name; uint64_t v; } row[8] = {
        { "RLIMIT_AS       ", a->rlim_as },
        { "RLIMIT_DATA     ", a->rlim_data },
        { "RLIMIT_NPROC    ", a->rlim_nproc },
        { "RLIMIT_NOFILE   ", a->rlim_nofile },
        { "RLIMIT_CPU      ", a->rlim_cpu },
        { "RLIMIT_FSIZE    ", a->rlim_fsize },
        { "RLIMIT_MEMLOCK  ", a->rlim_memlock },
        { "RLIMIT_CORE     ", a->rlim_core },
    };
    for (int i = 0; i < 8; i++) {
        p = maps_str(b, p, max, row[i].name);
        if (row[i].v == 0) p = maps_str(b, p, max, "unlimited");
        else                p = lim_dec(b, p, max, row[i].v);
        p = maps_str(b, p, max, "\n");
    }
    return p;
}
/* /proc/<pid>/auxv (M1215): a synthetic ELF auxiliary vector as (a_type, a_val)
 * little-endian u64 pairs, AT_NULL-terminated — what a libc would read to learn
 * the page size, entry point, clock tick, etc. (Our loader doesn't push an auxv
 * onto the user stack, so this is synthesized from what the kernel knows.) */
static int auxv_put(char *b, int p, int max, uint64_t type, uint64_t val) {
    for (int k = 0; k < 8 && p < max; k++) b[p++] = (char)(type >> (8 * k));
    for (int k = 0; k < 8 && p < max; k++) b[p++] = (char)(val  >> (8 * k));
    return p;
}
int app_format_auxv(app_t *ap, char *b, int max) {
    struct app *a = (struct app *)ap;
    if (!a || max <= 0) return 0;
    int p = 0;
    p = auxv_put(b, p, max, AT_PAGESZ, PAGE_SIZE);
    p = auxv_put(b, p, max, AT_ENTRY,  a->entry);
    p = auxv_put(b, p, max, AT_CLKTCK, 100);
    p = auxv_put(b, p, max, AT_UID,    0);
    p = auxv_put(b, p, max, AT_EUID,   0);
    p = auxv_put(b, p, max, AT_GID,    0);
    p = auxv_put(b, p, max, AT_EGID,   0);
    p = auxv_put(b, p, max, AT_SECURE, 0);
    p = auxv_put(b, p, max, AT_NULL,   0);
    return p;
}
/* Total bytes currently held by the app's mmap VMAs (for RLIMIT_AS, M1164). */
static uint64_t app_vma_total(struct app *a) {
    uint64_t t = 0;
    for (int i = 0; i < a->nvma; i++) t += a->vma[i].len;
    return t;
}
static int app_pid_alive(int pid) {            /* a live (un-exited) process with this pid? */
    struct app *a = app_by_pid(pid);
    return a && !a->exited;
}
static void app_wake_waiter(int pid) {         /* wake a parent blocked in waitpid() */
    struct app *a = app_by_pid(pid);
    if (a && a->waiting && a->task) task_wake(a->task);
}
static void app_free_zombie_children(int ppid) {  /* a dying parent orphans its uncollected zombies */
    for (int i = 0; i < MAX_APPS; i++)
        if (apps[i].used && apps[i].zombie && apps[i].parent == ppid) apps[i].used = 0;
}
/* prctl(PR_SET_PDEATHSIG) (M1562): a dying parent signals any still-LIVE
 * child that registered for it -- the counterpart to app_free_zombie_children
 * above, which only ever touches already-zombie (dead) children. Opt-in via
 * the usual app_request_signal gate (0/no-handler = silently no-op). */
static void app_notify_pdeathsig(int ppid) {
    for (int i = 0; i < MAX_APPS; i++)
        if (apps[i].used && !apps[i].exited && apps[i].parent == ppid && apps[i].pdeathsig)
            app_request_signal(&apps[i], apps[i].pdeathsig);
}

/* Block until a child (specific pid, or -1 = any) has exited, then collect it:
 * read its exit status, free its (now-zombie) slot, and return its pid. -1 if the
 * caller has no matching children. The forked child is turned into a zombie by
 * app_reap (resources already freed), which also wakes us.
 *
 * M1612: the scan-then-set-waiting-then-block sequence below, and app_reap's
 * zombify-then-wake sequence, now share app_wake_lock (see its own comment) --
 * this used to rely on the interrupt gate's local IF=0 alone ("same discipline
 * as the mailbox"), which M1531 made insufficient the moment the parent and
 * the WM (which runs app_reap) could be on two different cores, exactly like
 * mbox.c's own version of this, fixed as M1608 earlier this session. Only the
 * check+flag-set is locked; the block itself must NOT happen while holding it
 * (would deadlock the WM's own wake attempt against this now-parked core). */
long app_waitpid(int pid, int *status) {
    struct app *me = cur();
    if (!me) return -1;
    for (;;) {
        uint64_t f = irq_save();
        struct app *z = 0; int have = 0;
        for (int i = 0; i < MAX_APPS; i++) {
            struct app *c = &apps[i];
            if (!c->used || c->parent != me->pid) continue;
            if (pid > 0 && c->pid != pid) continue;
            have = 1;
            if (c->zombie) { z = c; break; }
        }
        if (z) {
            int code = z->exit_code, cpid = z->pid;
            z->used = 0; z->zombie = 0;            /* collect the zombie slot */
            irq_restore(f);
            if (status) *status = code;
            return cpid;
        }
        if (!have) { irq_restore(f); return -1; }  /* no matching children to wait for */
        me->waiting = 1;
        irq_restore(f);
        task_block();                              /* woken by app_reap when a child zombifies */
        me->waiting = 0;
    }
}
/* waitid (M1227): the superset of waitpid — supports WNOHANG (non-blocking reap,
 * so an event loop can supervise children) and fills a siginfo. idtype P_PID (a
 * specific child), P_ALL (any), or P_PIDFD (a pidfd carrying the pid). Returns 0
 * on success (result in *si; si_pid==0 means WNOHANG found nothing ready), or -1
 * if there are no matching children. */
long app_waitid(int idtype, int id, struct siginfo *si, int options) {
    struct app *me = cur(); if (!me) return -1;
    int want = id;
    if (idtype == P_PIDFD) {                       /* translate a pidfd -> its target pid */
        if (id < 0 || id >= APP_NFD || !me->fd[id].used || me->fd[id].type != 7) return -1;
        want = me->fd[id].obj; idtype = P_PID;
    }
    for (;;) {
        uint64_t f = irq_save();
        struct app *z = 0; int have = 0;
        for (int i = 0; i < MAX_APPS; i++) {
            struct app *c = &apps[i];
            if (!c->used || c->parent != me->pid) continue;
            if (idtype == P_PID && c->pid != want) continue;
            have = 1;
            if (c->zombie) { z = c; break; }
        }
        if (z) {
            int code = z->exit_code, cpid = z->pid;
            z->used = 0; z->zombie = 0;             /* collect the zombie slot */
            irq_restore(f);
            if (si) { si->si_signo = SIGCHLD; si->si_errno = 0; si->si_code = CLD_EXITED;
                      si->si_pid = cpid; si->si_uid = 0; si->si_status = code; }
            return 0;
        }
        if (!have) { irq_restore(f); return -1; }  /* no matching children */
        if (options & WNOHANG) { irq_restore(f); if (si) { si->si_pid = 0; si->si_signo = SIGCHLD; } return 0; }
        me->waiting = 1;
        irq_restore(f);
        task_block(); me->waiting = 0;
    }
}

/* Reclaim a self-exited app's resources. Called by the window manager from ITS
 * own context (not the app's), so it can free the app's task_t + 256 KB kernel
 * stack and release the apps[] slot — lifting the per-boot spawn cap for apps
 * that exit cleanly. Only acts once the task is fully dead (off-CPU; see
 * task_free), so a still-running task is never freed under it. Returns 1 when
 * the slot is free (the WM may then drop the window), 0 if the app exited but
 * its task isn't off-CPU yet (retry next pass). Frees the task_t + kernel stack,
 * the app's address space (a->cr3 — page tables + user frames, via
 * vmm_destroy_address_space), and the apps[] slot. */
static void app_fd_release(struct app *a);   /* close the process's fds/pipes (M1187; defined below) */
int app_reap(app_t *a) {
    if (!a) return 1;
    if (a->zombie) return 1;                  /* already reaped to a zombie: resources freed, slot kept for waitpid */
    /* off_cpu, not just TASK_DEAD: the state is set BEFORE the dying task's
     * final context_switch, which still writes to its own task_t. Freeing it
     * on state alone is a use-after-free of a live kernel stack. (M1961) */
    if (a->used && a->exited && (!a->task || (a->task->state == TASK_DEAD &&
                                              __atomic_load_n(&a->task->off_cpu, __ATOMIC_ACQUIRE)))) {
        {
            uint64_t uf = irq_save();      /* pairs with app_uffd_read/app_fault_handle's own lock (M1612) */
            if (g_uffd.active && g_uffd.owner == a) {     /* uffd owner gone: tear down, free any blocked monitor (M1134) */
                g_uffd.active = 0; g_uffd.pending = 0;
                if (g_uffd.monitor_waiting && g_uffd.monitor) task_wake(g_uffd.monitor);
            }
            irq_restore(uf);
        }
        vfs_cwd_forget(a);                               /* don't stash cwd into a freed slot (M1144) */
        flock_release_pid(a->pid);                       /* drop any advisory file locks it held (M1177) */
        pty_release_pid(a->pid);                          /* close any pseudoterminals it owned (M1185) */
        app_fd_release(a);                                /* close its open fds/pipes (M1187) */
        if (a->task) task_free(a->task);
        a->task = 0;
        /* Un-joined worker threads (M1139): free the dead ones; STOP any still
         * alive so the scheduler skips them — they must never run once we free
         * the shared address space just below. */
        for (int i = 0; i < APP_MAXTHREAD; i++) {
            task_t *t = a->thr[i];
            if (!t) continue;
            /* Same off_cpu rule as the main task above: a DEAD thread may still
             * be finishing its final context_switch. (M1961) */
            if (t->state == TASK_DEAD && __atomic_load_n(&t->off_cpu, __ATOMIC_ACQUIRE)) task_free(t);
            else task_stop(t);
            a->thr[i] = 0;
        }
        /* Flush any dirty MAP_SHARED pages back to their files before the
         * teardown below frees the frames it reads (M1602). app_reap runs in
         * the REAPER's own context (desktop.c's window-manager loop), not
         * this dying process's -- app_msync dereferences dirty pages as
         * plain pointers, so it needs `a`'s OWN address space active, not
         * whatever the caller's happens to be. Same save-switch-restore
         * shape app_spawn/app_process_vm_read already use for the same
         * reason. */
        {
            uint64_t flags2;
            __asm__ volatile("pushfq; pop %0; cli" : "=r"(flags2) :: "memory");
            uint64_t old_cr3_reap;
            __asm__ volatile("mov %%cr3, %0" : "=r"(old_cr3_reap));
            __asm__ volatile("mov %0, %%cr3" : : "r"(a->cr3) : "memory");
            app_msync(0, (uint64_t)-1);
            __asm__ volatile("mov %0, %%cr3" : : "r"(old_cr3_reap) : "memory");
            __asm__ volatile("push %0; popfq" : : "r"(flags2) : "memory", "cc");
        }
        vmm_destroy_address_space(a->cr3);   /* free page tables + user frames */
        a->cr3 = 0;
        if (a->gfx) { kfree(a->gfx); a->gfx = 0; }   /* graphics canvas (kernel heap) */
        /* `a` is fully dead from here on (resources above already freed) --
         * regardless of whether its OWN slot zombifies or frees immediately
         * below, notify any LIVE child that registered via PR_SET_PDEATHSIG
         * (M1562) now, once, unconditionally. */
        app_notify_pdeathsig(a->pid);
        /* A forked child whose parent is still alive becomes a collectable
         * zombie (M1117): its resources are freed now, but the slot + exit_code
         * linger until the parent waitpid()s it. Spawned apps (parent==0) and
         * orphans free their slot immediately, exactly as before. */
        if (a->parent && app_pid_alive(a->parent)) {
            uint64_t wf = irq_save();        /* pairs with app_waitpid/app_waitid's own lock (M1612) */
            a->zombie = 1;
            app_wake_waiter(a->parent);      /* wake the parent if it's blocked in waitpid */
            irq_restore(wf);
            app_request_signal(app_by_pid(a->parent), SIGCHLD);  /* + async-notify a parent that ISN'T (M1562) */
            return 1;                        /* window removable; slot persists as a zombie */
        }
        app_free_zombie_children(a->pid);    /* this app is leaving: orphan-free any zombies of its own */
        a->used = 0;
    }
    return !a->used;
}

/* Ask a running app to close (e.g. the user clicked the window's X or pressed
 * the close key). We can't safely free a running task from outside, so instead
 * we raise a flag and wake the app: it next returns from its blocking input
 * read, sees the flag, and calls task_exit() from its OWN context — a clean
 * exit. The WM then reaps it (app_reap) like any other exited app. Apps that
 * are busy (not waiting for input) close once they next read input. */
void app_request_kill(app_t *a) {
    if (a && a->used && !a->exited) {
        uint64_t f = irq_save();
        a->kill = 1;
        task_wake(a->task);   /* unblock it if it's sleeping in app_sys_read */
        irq_restore(f);
    }
}

/* Honor a pending WM kill from a NON-blocking per-frame syscall (pollkey /
 * gfx_blit / sleep). A polling or graphics app never calls the blocking
 * app_sys_read where the kill is otherwise observed, so without this F8 / the
 * window [x] / the context-menu Close couldn't close it (it'd only exit on its
 * own quit key). Exit cleanly — the WM then reaps it — exactly as app_sys_read
 * does on a->kill. Called every frame, so the close lands within ~one frame. */
void app_kill_check(void) {
    struct app *a = cur();
    if (a && a->kill) { a->exited = 1; task_exit(); }
}

/* WM polls this: returns 1 (and clears) if the app's grid changed since asked. */
int app_dirty_clear(app_t *a) { int d = a->gdirty; a->gdirty = 0; return d; }

/* ---- input queue (filled by the WM, drained by SYS_read) ---- */
#define SIGINT 2
void app_key(app_t *a, char c) {
    /* Ctrl-C (0x83): if this app installed a SIGINT handler, raise it asynchronously
     * (interrupting even a runaway compute loop) instead of queueing the key. Opt-in,
     * so the shell — which polls 0x83 to break its own loops — is unaffected. M1083. */
    if ((unsigned char)c == 0x83 && fg_pgid) { app_killpg(fg_pgid, SIGINT); return; }   /* job control: ^C -> the foreground group (M1176) */
    if ((unsigned char)c == 0x83 && a->sig_handler[SIGINT]) { app_request_signal(a, SIGINT); return; }
    /* PgUp/PgDn scroll the scrollback for ordinary terminals; a full-screen app
     * that draws its own view (caret_off, e.g. the editor) gets them as keys to
     * page its own content instead. */
    if (c == 0x15 && !a->caret_off) {        /* PgUp: scroll into the scrollback history */
        if (a->view < a->sb_count) { a->view += 4; if (a->view > a->sb_count) a->view = a->sb_count; a->gdirty = 1; }
        return;                  /* a UI control — the program never sees it */
    }
    if (c == 0x16 && !a->caret_off) {        /* PgDn: scroll back toward the live bottom */
        if (a->view > 0) { a->view -= 4; if (a->view < 0) a->view = 0; a->gdirty = 1; }
        return;
    }
    if (a->view != 0) { a->view = 0; a->gdirty = 1; }   /* typing returns to the live view */
    uint64_t f = irq_save();
    int n = (a->ih + 1) % IQ_SIZE;
    if (n != a->it) { a->iq[a->ih] = c; a->ih = n; }
    task_wake(a->task);          /* unblock the app if it's waiting in read() */
    irq_restore(f);
}
static int iq_get(struct app *a) {
    if (a->paste_pos < a->paste_len)            /* drain a pending paste first (not capped by IQ_SIZE) */
        return (unsigned char)a->pastebuf[a->paste_pos++];
    if (a->ih == a->it) return -1;
    char c = a->iq[a->it]; a->it = (a->it + 1) % IQ_SIZE; return (unsigned char)c;
}

/* Non-blocking: next key for the calling app, or -1 if none (for games). */
int app_sys_pollkey(void) { app_kill_check(); return iq_get(cur()); }

/* ---- syscall-facing ---- */
/* ANSI/VT100: map an SGR colour code (30-37 normal / 90-97 bright) onto our
 * 16-entry app_palette (which isn't in ANSI order). */
static uint8_t ansi_color(int code, int bold) {
    static const uint8_t base[8]   = { 8, 2, 0, 3, 6, 5, 4, 1 };   /* blk red grn yel blu mag cyn wht */
    static const uint8_t bright[8] = { 8, 13, 9, 12, 14, 11, 10, 1 };
    if (code >= 90 && code <= 97) return bright[code - 90];
    if (code >= 30 && code <= 37) return (bold ? bright : base)[code - 30];
    return 0;
}

/* Execute one buffered CSI sequence (a->csi[0..csilen)) ending in `final`. A
 * tiny VT100 subset: SGR colours (m), cursor moves (A/B/C/D/H/f), erase (J/K). */
static void ansi_csi(struct app *a, char final) {
    int p[8] = {0}, np = 0, cur = 0;
    for (int i = 0; i < a->csilen; i++) {
        char c = a->csi[i];
        if (c >= '0' && c <= '9') cur = cur * 10 + (c - '0');
        else if (c == ';') { if (np < 7) p[np++] = cur; cur = 0; }
    }
    p[np++] = cur;                       /* the last/only param; np >= 1 */
    int n = p[0] ? p[0] : 1;             /* default-1 count for cursor moves */
    switch (final) {
    case 'm': {                          /* SGR: text colour */
        int bold = 0;
        for (int i = 0; i < np; i++) {
            int v = p[i];
            if (v == 0) { a->curcol = 0; bold = 0; }
            else if (v == 1) bold = 1;
            else if (v == 39) a->curcol = 0;
            else if ((v >= 30 && v <= 37) || (v >= 90 && v <= 97)) a->curcol = ansi_color(v, bold);
        }
        break;
    }
    case 'A': a->cy -= n; if (a->cy < 0) a->cy = 0; break;
    case 'B': a->cy += n; if (a->cy >= a->rows) a->cy = a->rows - 1; break;
    case 'C': a->cx += n; if (a->cx >= a->cols) a->cx = a->cols - 1; break;
    case 'D': a->cx -= n; if (a->cx < 0) a->cx = 0; break;
    case 'H': case 'f': {                /* cursor to row;col (1-based) */
        int row = p[0] ? p[0] : 1, col = (np >= 2 && p[1]) ? p[1] : 1;
        a->cy = row - 1; a->cx = col - 1;
        if (a->cy < 0) a->cy = 0; if (a->cy >= a->rows) a->cy = a->rows - 1;
        if (a->cx < 0) a->cx = 0; if (a->cx >= a->cols) a->cx = a->cols - 1;
        break;
    }
    case 'J': {                          /* erase in display (2 = whole screen) */
        int m = p[0];
        int y0 = (m == 2) ? 0 : a->cy;
        if (m == 2) { a->cx = a->cy = 0; }
        for (int x = (m == 2 ? 0 : a->cx); x < a->cols; x++) { a->grid[y0][x] = ' '; a->gcol[y0][x] = 0; }
        for (int y = y0 + 1; y < a->rows; y++)
            for (int x = 0; x < a->cols; x++) { a->grid[y][x] = ' '; a->gcol[y][x] = 0; }
        break;
    }
    case 'K': {                          /* erase in line (0 to-eol, 1 from-bol, 2 whole) */
        int m = p[0];
        int x0 = (m == 1 || m == 2) ? 0 : a->cx;
        int x1 = (m == 1) ? a->cx + 1 : a->cols;
        for (int x = x0; x < x1 && x < a->cols; x++) { a->grid[a->cy][x] = ' '; a->gcol[a->cy][x] = 0; }
        break;
    }
    }
    a->gdirty = 1;
}

/* App stdout. Bytes pass straight to the grid EXCEPT ANSI escape sequences
 * (ESC [ ... <letter>), which are parsed for colour/cursor/erase. Output with
 * no ESC byte renders byte-identically to before, so existing apps are
 * unaffected. */
void app_sys_write(const char *buf, unsigned len) {
    struct app *a = cur();
    for (unsigned i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)buf[i];
        if (a->esc == 0) {
            if (ch == 0x1B) a->esc = 1;          /* ESC: maybe a sequence */
            else grid_putc(a, (char)ch);
        } else if (a->esc == 1) {                /* after ESC */
            if (ch == '[') { a->esc = 2; a->csilen = 0; }
            else a->esc = 0;                     /* unsupported ESC x: consume + drop */
        } else {                                 /* in CSI: collect until the final byte */
            if (ch >= 0x40 && ch <= 0x7E) { ansi_csi(a, (char)ch); a->esc = 0; }
            else if (a->csilen < sizeof(a->csi)) a->csi[a->csilen++] = (char)ch;
            else a->esc = 0;                     /* overlong: bail (no runaway) */
        }
    }
}

/* Replace the on-screen line with history entry `idx` (or empty); returns len. */
static unsigned hist_recall(struct app *a, char *buf, unsigned max, unsigned cur_n,
                            int idx, int cx0, int cy0) {
    grid_erase(a, (int)cur_n, cx0, cy0);
    unsigned n = 0;
    if (idx >= 0 && idx < a->hist_n) {
        const char *h = a->hist[idx];
        while (h[n] && n < max - 1) { grid_putc(a, h[n]); buf[n] = h[n]; n++; }
    }
    return n;
}

/* The foreground TTY line-discipline mode (M1174). Default = cooked: ICANON
 * (line editing below) + ECHO + ISIG — byte-identical to the historical
 * behaviour, so every app that never calls tcsetattr is unaffected. An app that
 * clears ICANON gets raw, unbuffered, per-keystroke reads (what an editor or a
 * game's text input wants). Global (single foreground TTY); apps should restore
 * it, as on real Unix. */
static struct termios g_termios = { ICANON | ECHO | ISIG, { [VINTR] = 3, [VEOF] = 4, [VERASE] = 0x7f, [VKILL] = 0x15 } };
int app_tcgetattr(struct termios *t) { if (!t) return -1; *t = g_termios; return 0; }
int app_tcsetattr(const struct termios *t) { if (!t) return -1; g_termios = *t; return 0; }
/* tcflush/tcdrain (M1570): the same iq[]/it/ih ring iq_get/iq_put already
 * manipulate. TCIFLUSH/TCIOFLUSH discard unread input by fast-forwarding the
 * tail to the head; TCOFLUSH and tcdrain are honest no-ops -- console output
 * goes straight through app_sys_write synchronously, no output buffer exists
 * to discard or wait on here at all (same reasoning as M1566's fsync). */
int app_tcflush(int queue_selector) {
    struct app *a = cur();
    if (!a) return -1;
    if (queue_selector != TCIFLUSH && queue_selector != TCOFLUSH && queue_selector != TCIOFLUSH) return -1;
    if (queue_selector == TCIFLUSH || queue_selector == TCIOFLUSH) a->it = a->ih;
    return 0;
}
int app_tcdrain(void) { return cur() ? 0 : -1; }

/* Raw-mode read (M1174): no line editing — block for the first keystroke, then
 * drain whatever else is immediately queued (VMIN=1 semantics), echoing if ECHO
 * is set. Control keys are delivered literally: the keyboard's Ctrl+x sentinel
 * (0x80|letter) maps back to the raw control code (1..26). */
static int tty_raw_read(struct app *a, char *buf, unsigned max) {
    unsigned n = 0;
    while (n < max) {
        uint64_t f = irq_save();
        if (a->kill) { irq_restore(f); a->exited = 1; task_exit(); }
        int c = iq_get(a);
        if (c < 0) {
            irq_restore(f);           /* release BEFORE blocking (M1612) -- holding a real cross-core
                                        * spinlock across task_block() would deadlock: this core never
                                        * releases it until woken, and app_key/app_request_kill on any
                                        * OTHER core would spin on it forever trying to deliver that wake */
            if (n > 0) break;         /* got something -> return it */
            task_block(); continue;   /* else block for the first byte */
        }
        irq_restore(f);
        if (c >= 0x81 && c <= 0x9A) c -= 0x80;       /* Ctrl+letter sentinel -> raw control code */
        else if (c >= 0x80) continue;                /* arrows/other cooked sentinels: drop in raw */
        buf[n++] = (char)c;
        if (g_termios.c_lflag & ECHO) { char e = (char)c; app_sys_write(&e, 1); }
    }
    return (int)n;
}

int app_sys_read(char *buf, unsigned max) {
    struct app *a = cur();
    if (!(g_termios.c_lflag & ICANON)) return tty_raw_read(a, buf, max);   /* raw mode (M1174) */
    unsigned n = 0;                                 /* line length          */
    unsigned cur_i = 0;                             /* caret index in [0,n] */
    int cx0 = a->cx, cy0 = a->cy;                   /* where the input starts */
    a->hist_pos = a->hist_n;                        /* start just past the newest */
    while (n < max) {
        uint64_t f = irq_save();                    /* check kill + queue + block ATOMICALLY: if the kill check sat outside this region, a kill+task_wake from the WM landing between the check and task_block() would be lost (the wake no-ops on a not-yet-blocked task) -> the app sleeps forever and its window is never reaped */
        if (a->kill) { irq_restore(f); a->exited = 1; task_exit(); }  /* WM asked us to close: exit cleanly (WM then reaps) */
        int c = iq_get(a);
        if (c < 0) { irq_restore(f); task_block(); continue; }  /* sleep until woken (incl. by a kill request); release BEFORE
                                                                  * blocking (M1612) -- see tty_raw_read's sibling comment */
        irq_restore(f);
        /* Ctrl+letter arrives as 0x81..0x9A. Map the readline navigation aliases
         * onto the existing key codes; the kill/cancel ones are handled below. */
        switch (c) {
            case 0x81: c = 0x01; break;   /* Ctrl-A -> Home   */
            case 0x85: c = 0x05; break;   /* Ctrl-E -> End    */
            case 0x82: c = 0x13; break;   /* Ctrl-B -> left   */
            case 0x86: c = 0x14; break;   /* Ctrl-F -> right  */
            case 0x90: c = 0x11; break;   /* Ctrl-P -> prev (history up)   */
            case 0x8e: c = 0x12; break;   /* Ctrl-N -> next (history down) */
            case 0x84: c = 0x04; break;   /* Ctrl-D -> Delete */
            case 0x88: c = 0x08; break;   /* Ctrl-H -> backspace */
        }
        if (c == 0x83) {                  /* Ctrl-C: abandon the current line */
            cursor_fwd(a, (int)(n - cur_i));
            grid_putc(a, '^'); grid_putc(a, 'C'); grid_putc(a, '\n');
            buf[0] = 0; return 0;
        }
        if (c == 0x8b || c == 0x95 || c == 0x97) {   /* Ctrl-K / Ctrl-U / Ctrl-W: kill operations */
            unsigned oldlen = n, oldcur = cur_i;
            if (c == 0x8b) { n = cur_i; }                          /* kill to end of line */
            else if (c == 0x95) {                                  /* kill the whole line */
                for (unsigned k = cur_i; k < n; k++) buf[k - cur_i] = buf[k];
                n -= cur_i; cur_i = 0;
            } else {                                               /* Ctrl-W: kill the word before the caret */
                unsigned ws = cur_i;
                while (ws > 0 && buf[ws-1] == ' ') ws--;
                while (ws > 0 && buf[ws-1] != ' ') ws--;
                unsigned del = cur_i - ws;
                for (unsigned k = cur_i; k < n; k++) buf[k - del] = buf[k];
                n -= del; cur_i = ws;
            }
            cursor_back(a, (int)oldcur);                           /* repaint: start -> content -> blank tail */
            emit_range(a, buf, 0, n);
            for (unsigned k = n; k < oldlen; k++) grid_putc(a, ' ');
            cursor_back(a, (int)((oldlen > n ? oldlen : n) - cur_i));
            continue;
        }
        if (c == 0x8c) {                  /* Ctrl-L: clear the screen, keep the current line at the top */
            int oy = cy0, span = a->cy - cy0; if (span < 0) span = 0;
            for (int r = 0; r <= span && oy + r < a->rows; r++)   /* move the prompt+input rows up */
                for (int col = 0; col < a->cols; col++) {
                    a->grid[r][col] = a->grid[oy + r][col];
                    a->gcol[r][col] = a->gcol[oy + r][col];
                }
            for (int r = span + 1; r < a->rows; r++)              /* blank everything below */
                for (int col = 0; col < a->cols; col++) { a->grid[r][col] = ' '; a->gcol[r][col] = 0; }
            a->cy -= oy; cy0 = 0; a->view = 0; a->gdirty = 1;
            continue;
        }
        if (c >= 0x80) continue;          /* any other Ctrl-combo: ignore (don't echo) */
        if (c == '\n' || c == '\r') {
            cursor_fwd(a, (int)(n - cur_i)); cur_i = n;  /* commit from end of line */
            if (n > 0) {                            /* save this line to history */
                int len = n < 95 ? (int)n : 95, slot;
                if (a->hist_n < HIST_N) slot = a->hist_n++;
                else { for (int k = 1; k < HIST_N; k++) memcpy(a->hist[k-1], a->hist[k], 96); slot = HIST_N - 1; }
                for (int i = 0; i < len; i++) a->hist[slot][i] = buf[i];
                a->hist[slot][len] = 0;
            }
            grid_putc(a, '\n'); buf[n++] = '\n'; break;
        }
        if (c == '\b' || c == 127) {                /* backspace: delete char before caret */
            if (cur_i > 0) {
                for (unsigned i = cur_i; i < n; i++) buf[i-1] = buf[i];
                n--; cur_i--;
                cursor_back(a, 1);
                emit_range(a, buf, cur_i, n); grid_putc(a, ' ');
                cursor_back(a, (int)(n - cur_i) + 1);
            }
            continue;
        }
        if (c == 0x04) {                            /* Delete: delete char at caret */
            if (cur_i < n) {
                for (unsigned i = cur_i + 1; i < n; i++) buf[i-1] = buf[i];
                n--;
                emit_range(a, buf, cur_i, n); grid_putc(a, ' ');
                cursor_back(a, (int)(n - cur_i) + 1);
            }
            continue;
        }
        if (c == 0x13) { if (cur_i > 0) { cursor_back(a, 1); cur_i--; } continue; }       /* left  */
        if (c == 0x14) { if (cur_i < n) { cursor_fwd(a, 1); cur_i++; } continue; }        /* right */
        if (c == 0x01) { if (cur_i > 0) { cursor_back(a, (int)cur_i); cur_i = 0; } continue; }      /* Home */
        if (c == 0x05) { if (cur_i < n) { cursor_fwd(a, (int)(n - cur_i)); cur_i = n; } continue; } /* End  */
        if (c == 0x11) {                            /* up-arrow: older command */
            if (a->hist_pos > 0) {
                cursor_fwd(a, (int)(n - cur_i));
                n = hist_recall(a, buf, max, n, --a->hist_pos, cx0, cy0); cur_i = n;
            }
            continue;
        }
        if (c == 0x12) {                            /* down-arrow: newer command */
            if (a->hist_pos < a->hist_n) {
                cursor_fwd(a, (int)(n - cur_i));
                n = hist_recall(a, buf, max, n, ++a->hist_pos, cx0, cy0); cur_i = n;
            }
            continue;
        }
        if (c == '\t') {                            /* Tab: complete a filename from the cwd */
            cursor_fwd(a, (int)(n - cur_i)); cur_i = n;   /* completion acts at end of line */
            int ws = (int)n; while (ws > 0 && buf[ws-1] != ' ') ws--;
            int plen = (int)n - ws, slash = 0;
            for (int i = ws; i < (int)n; i++) if (buf[i] == '/') slash = 1;
            /* Complete when there is a word to extend (plen>0) or an empty
             * argument after a command (ws>0) — `cmd <Tab>` lists every file,
             * like bash. A wholly empty line (ws==0, plen==0) does nothing. */
            if ((plen > 0 || ws > 0) && !slash) {
                /* Complete to the longest common prefix of every cwd entry whose
                 * name starts with the typed word (case-insensitive). A unique
                 * match fills in the whole name; several matches advance to the
                 * point where they first disagree — bash's default Tab. */
                vfs_dirent e[32]; int ne = vfs_list(e, 32);
                const char *names[32];
                for (int i = 0; i < ne; i++) names[i] = e[i].name;
                int nm, fmi, cpl = complete_scan(names, ne, buf + ws, plen, &nm, &fmi);
                if (nm >= 1 && cpl > plen) {        /* extend the word to the common prefix (canonical case) */
                    grid_erase(a, plen, cx0, cy0); n -= (unsigned)plen;
                    for (int k = 0; k < cpl && n + 1 < max; k++) {
                        grid_putc(a, e[fmi].name[k]); buf[n++] = e[fmi].name[k];
                    }
                    if (nm == 1 && n + 1 < max) {   /* unique: '/' to descend a dir, else a space for the next arg */
                        char tail = e[fmi].name[cpl] == '/' ? '/' : ' ';
                        grid_putc(a, tail); buf[n++] = tail;
                    }
                } else if (nm > 1) {               /* already at the common prefix: list the candidates,
                                                    * then redraw the prompt + line (bash's second Tab) */
                    char psave[APP_COLS_MAX]; uint8_t csave[APP_COLS_MAX];
                    int pn = cx0 < a->cols ? cx0 : a->cols;
                    for (int k = 0; k < pn; k++) { psave[k] = a->grid[cy0][k]; csave[k] = a->gcol[cy0][k]; }
                    grid_putc(a, '\n');
                    for (int i = 0; i < ne; i++) {
                        if (!complete_match(e[i].name, buf + ws, plen)) continue;
                        for (int k = 0; e[i].name[k]; k++) grid_putc(a, e[i].name[k]);
                        grid_putc(a, ' '); grid_putc(a, ' ');
                    }
                    grid_putc(a, '\n');
                    uint8_t savecol = a->curcol;   /* repaint the prompt in its original colours */
                    for (int k = 0; k < pn; k++) { a->curcol = csave[k]; grid_putc(a, psave[k]); }
                    a->curcol = savecol;
                    cx0 = a->cx; cy0 = a->cy;       /* input restarts after the redrawn prompt */
                    emit_range(a, buf, 0, n);
                }
            }
            cur_i = n;
            continue;
        }
        if (c < 32) continue;                       /* other control keys: ignore */
        if (n + 1 < max) {                          /* printable: insert at the caret */
            for (unsigned i = n; i > cur_i; i--) buf[i] = buf[i-1];
            buf[cur_i] = (char)c; n++;
            emit_range(a, buf, cur_i, n); cur_i++;
            cursor_back(a, (int)(n - cur_i));       /* park caret just after the new char */
        }
    }
    return (int)n;
}

/* SYS_sbrk: grow the calling app's heap by `inc` bytes (rounded up to whole
 * pages), mapping fresh USER|WRITABLE frames into its address space, and return
 * the PREVIOUS break so ulib's malloc can carve allocations from [old, new).
 * Returns (uint64_t)-1 on out-of-memory or if the heap would reach the stack.
 * We only ever grow: a non-positive inc just reports the current break, since
 * ulib's allocator reuses freed space itself (the kernel never has to shrink).
 * Frames mapped here are reclaimed wholesale by vmm_destroy_address_space when
 * the app exits, so even the OOM path below leaks nothing past the app's life. */
uint64_t app_sbrk(long inc) {
    struct app *a = cur();
    if (!a) return (uint64_t)-1;
    if (!a->heap_end) a->heap_end = UHEAP_BASE;       /* lazily start at the heap base */
    uint64_t old = a->heap_end;
    if (inc <= 0) return old;
    uint64_t pages  = ((uint64_t)inc + PAGE_SIZE - 1) / PAGE_SIZE;
    uint64_t newend = old + pages * PAGE_SIZE;
    if (newend > UHEAP_LIMIT || newend < old) return (uint64_t)-1;   /* hit the stack / overflow */
    if (a->rlim_data && (newend - UHEAP_BASE) > a->rlim_data) return (uint64_t)-1;   /* RLIMIT_DATA (M1164) */
    for (uint64_t v = old; v < newend; v += PAGE_SIZE) {
        uint64_t frame = pmm_alloc_frame();
        if (!frame) {                                 /* OOM: undo this call's partial mapping */
            for (uint64_t u = old; u < v; u += PAGE_SIZE) {
                uint64_t ph = vmm_translate(u);
                vmm_unmap(u);
                if (ph) pmm_free_frame(ph);
            }
            /* Make memory exhaustion visible instead of a silent app death — this
             * is the path Quake hit at 128 MB (M599). The app's malloc gets NULL
             * next and usually exits, so this logs about once, not in a spin. */
            kprintf("[app] '%s' out of memory: sbrk(%ld) failed, no free frames (increase QEMU -m?)\n",
                    a->title ? a->title : "?", inc);
            app_oom_kill();          /* shed the fattest other process so the system recovers (M1275; cooperative) */
            return (uint64_t)-1;
        }
        vmm_map(v, frame, PTE_WRITABLE | PTE_USER | PTE_NX);   /* heap: data, never code (W^X) */
    }
    a->heap_end = newend;
    return old;
}

/* --- mmap: demand-paged anonymous memory (M1063) ---------------------------
 * SYS_mmap reserves a region in a private VA window; its pages are NOT mapped
 * up front — the first touch of each page faults, and app_fault_handle (called
 * from the #PF handler) lazily allocates + maps a zeroed frame. This is the
 * core demand-paging mechanism, and the seed for file-backed mmap + COW/fork. */
/* Forward: defined next to app_munmap, which is its other caller. MAP_FIXED
 * and munmap are the same operation on the VMA list. */
static int app_vma_carve(struct app *a, uint64_t addr, uint64_t len);

#define MMAP_BASE  0x60000000ull        /* above the 0x50000000 user stack, clear of the heap */
#define MMAP_TOP   0xA0000000ull      /* 256 MiB -> 1 GiB: a compiler's allocator outgrew it (M1961) */

/* ASLR (M1287): pick a per-exec random start for the mmap region, drawn from
 * the CSPRNG (kernel/random.c). 14 bits of entropy => the base lands anywhere
 * in the first 64 MiB of the 256 MiB mmap window, so dlopen'd .so / JIT / mmap
 * buffers no longer sit at a fixed address — the partner of W^X. */
static uint64_t aslr_mmap_pick(void) {
    uint16_t r = 0; random_bytes(&r, sizeof r);
    return MMAP_BASE + ((uint64_t)(r & 0x3FFF) * PAGE_SIZE);   /* [MMAP_BASE, MMAP_BASE+64 MiB), page-aligned */
}
/* The randomized mmap base of process `pid` (0 = self), for the ASLR self-test
 * to confirm two independently-exec'd processes landed at different bases. */
uint64_t app_aslr_base(int pid) {
    struct app *t = pid ? app_by_pid(pid) : cur();
    return t ? t->aslr_mmap_base : 0;
}

/* MAP_FIXED anonymous mmap (M1952): reserve a demand-paged region at an
 * ADDRESS THE CALLER CHOOSES, rather than one we pick.
 *
 * Needed by anything that lays out its own address space. `ld.so` maps shared
 * objects at chosen addresses (Phase 4 cannot run a dynamically-linked
 * toolchain without it) and V8 reserves its heap cage the same way (Phase 6).
 * The old ABI was app_mmap(len) -- length only, address ours -- so MAP_FIXED
 * could not be expressed at all and had to be REFUSED, because handing back a
 * different address than the caller demanded corrupts it silently.
 *
 * Deliberately strict: the range must be page-aligned, inside the mmap window,
 * and must not overlap an existing VMA. Linux's MAP_FIXED silently replaces an
 * existing mapping, which we cannot do safely yet (no partial munmap / VMA
 * splitting), so an overlap is refused rather than half-honoured. */
uint64_t app_mmap_fixed(uint64_t addr, uint64_t len) {
    struct app *a = cur();
    if (!a || len == 0) return 0;
    if (addr & (PAGE_SIZE - 1)) return 0;                       /* must be page-aligned */
    len = (len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (a->nvma >= APP_MAXVMA) return 0;
    if (a->rlim_as && app_vma_total(a) + len > a->rlim_as) return 0;   /* RLIMIT_AS (M1164) */
    if (addr < MMAP_BASE || addr + len > MMAP_TOP || addr + len < addr) return 0;
    /* MAP_FIXED REPLACES whatever is there -- that is its defining behaviour,
     * not a detail. Refusing on overlap (which is what this did) is what broke
     * ld.so: it reserves a span and then MAP_FIXEDs its segments into it. */
    if (app_vma_carve(a, addr, len) != 0) return 0;
    if (a->nvma >= APP_MAXVMA) return 0;                        /* re-check: the carve may have split */
    VMA_NEW(a);
    a->vma[a->nvma].start = addr;
    a->vma[a->nvma].len   = len;
    a->vma[a->nvma].sealed = 0;
    a->vma[a->nvma].uffd  = 0;
    a->vma[a->nvma].file_backed = 0;
    a->vma[a->nvma].locked = a->mlock_future;
    a->vma[a->nvma].huge = 0;
    a->vma[a->nvma].shared = 0;          /* slots are recycled by the carve: never inherit */
    a->vma[a->nvma].foff = 0;
    a->vma[a->nvma].fpath[0] = 0;
    a->nvma++;
    if (addr + len + PAGE_SIZE > a->mmap_next) a->mmap_next = addr + len + PAGE_SIZE;
    return addr;
}

uint64_t app_mmap(uint64_t len) {
    struct app *a = cur();
    if (!a || len == 0) return 0;
    len = (len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (a->nvma >= APP_MAXVMA) return 0;
    if (a->rlim_as && app_vma_total(a) + len > a->rlim_as) return 0;   /* RLIMIT_AS (M1164) */
    if (a->mmap_next < MMAP_BASE) a->mmap_next = MMAP_BASE;
    uint64_t addr = a->mmap_next;
    if (len >= HUGE_SIZE) addr = (addr + HUGE_SIZE - 1) & ~(HUGE_SIZE - 1);   /* 2 MiB-align big anon regions so MADV_COLLAPSE can fold them (M1168) */
    if (addr + len > MMAP_TOP || addr + len < addr) return 0;
    VMA_NEW(a);
    a->vma[a->nvma].start = addr;
    a->vma[a->nvma].len   = len;
    a->vma[a->nvma].sealed = 0;
    a->vma[a->nvma].uffd  = 0;
    a->vma[a->nvma].file_backed = 0;
    a->vma[a->nvma].locked = a->mlock_future;       /* MCL_FUTURE: born locked if mlockall(MCL_FUTURE) is in effect (M1283) */
    a->vma[a->nvma].huge = 0;
    a->nvma++;
    a->mmap_next = addr + len + PAGE_SIZE;          /* leave an unmapped guard gap */
    return addr;
}

/* Hugepage mmap (M1155): reserve a 2 MiB-aligned, 2 MiB-granular demand-paged
 * region whose first touch maps the whole enclosing 2 MiB with a single PD entry
 * (PS bit) via app_fault_handle — one TLB entry for 512 pages, real x86-64 huge
 * paging. Returns the (2 MiB-aligned) base VA, or 0. */
uint64_t app_mmap_huge(uint64_t len) {
    struct app *a = cur();
    if (!a || len == 0) return 0;
    len = (len + HUGE_SIZE - 1) & ~(HUGE_SIZE - 1);          /* whole 2 MiB pages */
    if (a->nvma >= APP_MAXVMA) return 0;
    if (a->rlim_as && app_vma_total(a) + len > a->rlim_as) return 0;   /* RLIMIT_AS (M1164) */
    if (a->mmap_next < MMAP_BASE) a->mmap_next = MMAP_BASE;
    uint64_t addr = (a->mmap_next + HUGE_SIZE - 1) & ~(HUGE_SIZE - 1);   /* 2 MiB-align the base */
    if (addr + len > MMAP_TOP || addr + len < addr) return 0;
    VMA_NEW(a);
    a->vma[a->nvma].start = addr;
    a->vma[a->nvma].len   = len;
    a->vma[a->nvma].sealed = 0;
    a->vma[a->nvma].uffd  = 0;
    a->vma[a->nvma].file_backed = 0;
    a->vma[a->nvma].locked = 0;
    a->vma[a->nvma].huge = 1;
    a->nvma++;
    a->mmap_next = addr + len + HUGE_SIZE;          /* guard gap, preserving 2 MiB alignment */
    return addr;
}

/* File-backed mmap (M1136): reserve a demand-paged region whose pages are filled
 * lazily from file `path` (offset 0) on first touch — see app_fault_handle.
 * shared=0 is MAP_PRIVATE: writes stay in RAM and never reach the file. shared=1
 * is MAP_SHARED (M1544): writes are flushed back to the file by an explicit
 * msync(), by munmap, or (best-effort) at process exit -- see app_msync. Returns
 * the base VA, or 0. */
/* File-backed mmap with an OFFSET, and optionally at an address the caller
 * chooses (M1953). This is what a dynamic linker actually needs: ld.so maps
 * each PT_LOAD of a shared object separately, from a file offset, at an
 * address it picked when it reserved the object's span -- none of which the
 * old path-and-offset-zero form could express.
 *
 * `addr == 0` means "anywhere" (the old behaviour); non-zero is MAP_FIXED and
 * is refused on overlap, exactly as app_mmap_fixed does and for the same
 * reason (no VMA splitting yet). `off` must be page-aligned, because the
 * demand-fault handler reads file bytes at vma.foff + (fault - vma.start).
 *
 * Returns the base VA, or 0. */
uint64_t app_mmap_file_at(const char *path, uint64_t addr, uint64_t len,
                          uint64_t off, int shared) {
    struct app *a = cur();
    if (!a || len == 0 || !path) return 0;
    if ((addr | off) & (PAGE_SIZE - 1)) return 0;          /* both must be page-aligned */
    len = (len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (a->nvma >= APP_MAXVMA) return 0;
    if (a->rlim_as && app_vma_total(a) + len > a->rlim_as) return 0;   /* RLIMIT_AS (M1164) */
    if (!addr) {
        if (a->mmap_next < MMAP_BASE) a->mmap_next = MMAP_BASE;
        addr = a->mmap_next;
    } else if (app_vma_carve(a, addr, len) != 0) {
        return 0;                                          /* MAP_FIXED: replace what is there */
    }
    if (addr < MMAP_BASE || addr + len > MMAP_TOP || addr + len < addr) return 0;
    if (a->nvma >= APP_MAXVMA) return 0;                   /* re-check: the carve may have split */
    VMA_NEW(a);
    a->vma[a->nvma].start = addr;
    a->vma[a->nvma].len   = len;
    a->vma[a->nvma].sealed = 0;
    a->vma[a->nvma].uffd  = 0;
    a->vma[a->nvma].file_backed = 1;
    a->vma[a->nvma].locked = 0;
    a->vma[a->nvma].huge = 0;
    a->vma[a->nvma].shared = shared ? 1 : 0;
    a->vma[a->nvma].foff = off;
    int i = 0; for (; path[i] && i < 255; i++) a->vma[a->nvma].fpath[i] = path[i];
    a->vma[a->nvma].fpath[i] = 0;
    /* REFUSE rather than truncate. This buffer was 64 bytes, and binutils'
     * libbfd lives 98 characters down /usr/lib64/binutils/<triplet>/<ver>/ --
     * so every demand-fault on that mapping read a path that does not exist,
     * got a page of zeros, and handed ld.so a shared object whose entire
     * dynamic section was NULL. It surfaced as a page fault at CR2=0x8 deep
     * inside _dl_check_map_versions, with nothing pointing at the cause.
     * A short path is now an error, which is a diagnosable failure. */
    if (path[i]) return 0;               /* nvma not yet incremented: nothing to undo */
    a->nvma++;
    if (addr + len + PAGE_SIZE > a->mmap_next) a->mmap_next = addr + len + PAGE_SIZE;
    return addr;
}

uint64_t app_mmap_file(const char *path, uint64_t len, int shared) {
    struct app *a = cur();
    if (!a || len == 0 || !path) return 0;
    len = (len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (a->nvma >= APP_MAXVMA) return 0;
    if (a->rlim_as && app_vma_total(a) + len > a->rlim_as) return 0;   /* RLIMIT_AS (M1164) */
    if (a->mmap_next < MMAP_BASE) a->mmap_next = MMAP_BASE;
    uint64_t addr = a->mmap_next;
    if (addr + len > MMAP_TOP || addr + len < addr) return 0;
    VMA_NEW(a);
    a->vma[a->nvma].start = addr;
    a->vma[a->nvma].len   = len;
    a->vma[a->nvma].sealed = 0;
    a->vma[a->nvma].uffd  = 0;
    a->vma[a->nvma].file_backed = 1;
    a->vma[a->nvma].locked = 0;
    a->vma[a->nvma].huge = 0;
    a->vma[a->nvma].shared = shared ? 1 : 0;
    a->vma[a->nvma].foff = 0;
    int i = 0; for (; path[i] && i < 255; i++) a->vma[a->nvma].fpath[i] = path[i];
    a->vma[a->nvma].fpath[i] = 0;
    /* REFUSE rather than truncate. This buffer was 64 bytes, and binutils'
     * libbfd lives 98 characters down /usr/lib64/binutils/<triplet>/<ver>/ --
     * so every demand-fault on that mapping read a path that does not exist,
     * got a page of zeros, and handed ld.so a shared object whose entire
     * dynamic section was NULL. It surfaced as a page fault at CR2=0x8 deep
     * inside _dl_check_map_versions, with nothing pointing at the cause.
     * A short path is now an error, which is a diagnosable failure. */
    if (path[i]) return 0;               /* nvma not yet incremented: nothing to undo */
    a->nvma++;
    a->mmap_next = addr + len + PAGE_SIZE;
    return addr;
}

/* Write back the dirty pages of a MAP_SHARED file-backed VMA overlapping
 * [addr, addr+len) to their backing file (M1544) -- the actual "page cache"
 * behavior: a MAP_PRIVATE region (or a non-overlapping range, or one with
 * nothing dirty) is a no-op, matching msync(2). Uses the hardware-maintained
 * PTE_DIRTY bit (the CPU sets it on any write) rather than separate software
 * tracking, then clears it + invlpg's the page so the next write re-dirties
 * it for the NEXT sync -- the same bit `vmm_wss`'s working-set scan already
 * reads, just scoped to one VMA's range instead of the whole address space.
 * No new per-filesystem write primitive needed: this reuses the exact
 * read-modify-write pattern app_fd_write already uses for a positioned FILE
 * fd write (M1195) -- read the whole file via vfs_read, patch the dirty
 * page(s) in memory, write it back via vfs_write. One RMW per VMA (not per
 * page), and skipped entirely when nothing in range is actually dirty. */
int app_msync(uint64_t addr, uint64_t len) {
    struct app *a = cur();
    if (!a) return -1;
    uint64_t end = addr + len;
    for (int i = 0; i < a->nvma; i++) {
        if (!a->vma[i].file_backed || !a->vma[i].shared) continue;
        uint64_t vstart = a->vma[i].start, vend = vstart + a->vma[i].len;
        uint64_t lo = addr > vstart ? addr : vstart;
        uint64_t hi = end   < vend  ? end   : vend;
        if (lo >= hi) continue;
        int any_dirty = 0;
        for (uint64_t page = lo & ~(uint64_t)(PAGE_SIZE - 1); page < hi; page += PAGE_SIZE)
            if (vmm_pte_in(a->cr3, page) & PTE_DIRTY) { any_dirty = 1; break; }
        if (!any_dirty) continue;

        struct statx st; long sz = (vfs_stat(a->vma[i].fpath, &st) == 0) ? (long)st.stx_size : 0;
        uint64_t need = a->vma[i].foff + a->vma[i].len;      /* the mapping's own span sets the ceiling */
        if ((uint64_t)sz > need) need = (uint64_t)sz;        /* preserve any bytes past the mapping */
        if (need == 0 || need > (16u << 20)) continue;       /* refuse to RMW something absurd (16 MiB cap) */
        char *tmp = kmalloc((size_t)need);
        if (!tmp) continue;
        long got = vfs_read(a->vma[i].fpath, tmp, need);
        if (got < 0) got = 0;
        for (long b = got; b < (long)need; b++) tmp[b] = 0;  /* zero-fill any gap, mirrors app_fd_write */

        for (uint64_t page = lo & ~(uint64_t)(PAGE_SIZE - 1); page < hi; page += PAGE_SIZE) {
            uint64_t pte = vmm_pte_in(a->cr3, page);
            if (!(pte & PTE_PRESENT) || !(pte & PTE_DIRTY)) continue;
            uint64_t fileoff = a->vma[i].foff + (page - vstart);
            uint64_t n = PAGE_SIZE; if (fileoff + n > need) n = need - fileoff;
            for (uint64_t b = 0; b < n; b++) tmp[fileoff + b] = ((const char *)page)[b];
            vmm_set_pte_in(a->cr3, page, pte & ~PTE_DIRTY);
            __asm__ volatile("invlpg (%0)" : : "r"(page) : "memory");
        }
        vfs_write(a->vma[i].fpath, tmp, need);
        kfree(tmp);
    }
    return 0;
}

/* Split the VMA containing `addr` so that `addr` becomes a boundary. No-op if
 * nothing contains it, or if it is already a start/end. Returns 0, or -1 if
 * there is no free slot.
 *
 * mprotect needs this: ld.so's RELRO pass protects only the FRONT of the data
 * segment, and recording that stricter protection on the whole VMA would make
 * the rest of .data read-only -- a fault on the first write to a global. (M1956) */
static int app_vma_split_at(struct app *a, uint64_t addr) {
    if (!a) return -1;
    for (int i = 0; i < a->nvma; i++) {
        uint64_t s0 = a->vma[i].start, e0 = s0 + a->vma[i].len;
        if (addr <= s0 || addr >= e0) continue;
        if (a->nvma >= APP_MAXVMA) return -1;
        a->vma[a->nvma] = a->vma[i];       /* a COPY on purpose: no VMA_NEW here */
        a->vma[a->nvma].start = addr;
        a->vma[a->nvma].len   = e0 - addr;
        if (a->vma[a->nvma].file_backed) {
            a->vma[a->nvma].foff += addr - s0;
            /* fvalid is measured from the VMA start, so the tail's shrinks by
             * exactly what the head keeps -- and clamps at zero when the split
             * lands past the last file-backed byte. */
            uint64_t used = addr - s0;
            a->vma[a->nvma].fvalid = (a->vma[i].fvalid > used) ? a->vma[i].fvalid - used : 0;
            if (a->vma[i].fvalid && a->vma[a->nvma].fvalid == 0) a->vma[a->nvma].fvalid = 1;  /* 0 means "no limit"; keep "nothing valid" expressible */
        }
        a->nvma++;
        a->vma[i].len = addr - s0;
        return 0;
    }
    return 0;
}

/* Remove [addr, addr+len) from this process's VMA list, splitting any VMA it
 * partially covers and freeing the frames inside the range (M1954).
 *
 * This is the primitive Linux's mmap semantics are built on and the one thing
 * we did not have. A dynamic linker maps a shared object by FIRST reserving
 * the whole span with one file-backed mmap and THEN overwriting sub-ranges of
 * its own reservation with MAP_FIXED -- so "refuse if it overlaps" (which is
 * what app_mmap_fixed and app_mmap_file_at did) rejects the second segment of
 * every library. glibc reports that as
 *
 *     libc.so.6: failed to map segment from shared object
 *
 * which is how this surfaced: ld.so itself ran fine, found libc, and then
 * could not lay it out. Partial munmap() has the same shape, so both go
 * through here.
 *
 * Validated in full BEFORE anything is mutated: a carve that runs out of VMA
 * slots half way through would leave the address space describing memory that
 * is no longer mapped. Returns 0, or -1 with nothing changed. */
static int app_vma_carve(struct app *a, uint64_t addr, uint64_t len) {
    if (!a || !len) return -1;
    uint64_t end = addr + len;
    if (end < addr) return -1;

    /* --- pre-flight: refuse for the whole range or not at all --- */
    int extra = 0;                      /* VMA slots the splits will need */
    for (int i = 0; i < a->nvma; i++) {
        uint64_t s0 = a->vma[i].start, e0 = s0 + a->vma[i].len;
        if (end <= s0 || e0 <= addr) continue;                  /* no overlap */
        if (a->vma[i].sealed) return -1;                        /* mseal'd (M1130) */
        uint64_t cs = addr > s0 ? addr : s0, ce = end < e0 ? end : e0;
        /* A hugepage can only be freed as a whole 2 MiB run, so a carve that
         * cuts one in half has no correct answer -- refusing is the only
         * honest one. Nothing maps hugepages through the Linux path today. */
        if (a->vma[i].huge && ((cs | ce) & (HUGE_SIZE - 1))) return -1;
        if (cs > s0 && ce < e0) extra++;                        /* middle: becomes two VMAs */
    }
    if (a->nvma + extra > APP_MAXVMA) return -1;

    /* --- mutate --- */
    for (int i = 0; i < a->nvma; ) {
        uint64_t s0 = a->vma[i].start, e0 = s0 + a->vma[i].len;
        if (end <= s0 || e0 <= addr) { i++; continue; }
        uint64_t cs = addr > s0 ? addr : s0, ce = end < e0 ? end : e0;

        /* Flush before the frames go away: munmap()ing a MAP_SHARED mapping
         * without an explicit msync() first is the common pattern (M1602). */
        if (a->vma[i].file_backed && a->vma[i].shared) app_msync(cs, ce - cs);

        if (a->vma[i].huge) {
            for (uint64_t p = cs; p < ce; p += HUGE_SIZE) {
                uint64_t ph = vmm_translate(p);
                if (ph) { vmm_unmap_huge(p); pmm_free_contiguous(ph & ~(HUGE_SIZE - 1), HUGE_SIZE / PAGE_SIZE); }
            }
        } else {
            for (uint64_t p = cs; p < ce; p += PAGE_SIZE) {
                uint64_t ph = vmm_translate(p);
                if (ph) { vmm_unmap(p); pmm_free_frame(ph); }
            }
        }

        if (cs == s0 && ce == e0) {                 /* whole VMA goes */
            a->vma[i] = a->vma[a->nvma - 1];
            a->nvma--;
            continue;                               /* re-test the swapped-in entry at this index */
        }
        if (cs == s0) {                             /* head trimmed */
            a->vma[i].start = ce;
            a->vma[i].len   = e0 - ce;
            /* The file offset tracks the VMA's new start, or every later
             * demand-fault in this region reads the wrong part of the file. */
            if (a->vma[i].file_backed) a->vma[i].foff += ce - s0;
        } else if (ce == e0) {                      /* tail trimmed */
            a->vma[i].len = cs - s0;
        } else {                                    /* hole punched: split in two */
            a->vma[a->nvma] = a->vma[i];        /* a COPY on purpose (slot reserved by the pre-flight count): no VMA_NEW here */
            a->vma[a->nvma].start = ce;
            a->vma[a->nvma].len   = e0 - ce;
            if (a->vma[a->nvma].file_backed) a->vma[a->nvma].foff += ce - s0;
            a->nvma++;
            a->vma[i].len = cs - s0;
        }
        i++;
    }
    return 0;
}

int app_munmap(uint64_t addr, uint64_t len) {
    struct app *a = cur();
    if (!a) return -1;
    /* Was: "find a VMA starting at exactly addr, free all of it, ignore len".
     * That is wrong for both of munmap's real uses -- unmapping the middle of
     * a region, and unmapping the tail of one -- and it silently freed MORE
     * than asked when len was smaller than the VMA. Now a true range
     * operation, and the range need not correspond to a whole mapping. */
    if (addr & (PAGE_SIZE - 1)) return -1;
    len = (len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (!len) return -1;
    return app_vma_carve(a, addr, len);
}

/* mremap (M1179): resize the anonymous mmap region that starts at old_addr.
 *   - shrink: free the tail pages, keep the start.
 *   - grow in place: extend the VMA if [old_end,new_end) is free + in-window
 *     (the new pages demand-fault in lazily, like the original mmap).
 *   - grow when blocked + MREMAP_MAYMOVE: reserve a fresh region, COPY the
 *     resident pages over (untouched ones stay demand-paged), free the old.
 * Plain anon only (sealed/file-backed/huge/uffd/locked regions are refused).
 * Returns the (possibly new) base, or (uint64_t)-1. */
#define MREMAP_MAYMOVE 1
uint64_t app_mremap(uint64_t old_addr, uint64_t old_len, uint64_t new_len, int flags) {
    struct app *a = cur();
    if (!a || new_len == 0) return (uint64_t)-1;
    old_len = (old_len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    new_len = (new_len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    int vi = -1;
    for (int i = 0; i < a->nvma; i++) if (a->vma[i].start == old_addr) { vi = i; break; }
    if (vi < 0) return (uint64_t)-1;
    if (a->vma[vi].sealed || a->vma[vi].file_backed || a->vma[vi].huge || a->vma[vi].uffd || a->vma[vi].locked)
        return (uint64_t)-1;
    if (new_len == old_len) return old_addr;

    if (new_len < old_len) {                              /* SHRINK: free [old_addr+new_len, old_addr+old_len) */
        for (uint64_t p = old_addr + new_len; p < old_addr + old_len; p += PAGE_SIZE) {
            uint64_t ph = vmm_translate(p);
            if (ph) { vmm_unmap(p); pmm_free_frame(ph); }
        }
        a->vma[vi].len = new_len;
        return old_addr;
    }

    /* GROW: extend in place if the tail [old_end,new_end) is free + in-window */
    uint64_t old_end = old_addr + old_len, new_end = old_addr + new_len;
    if (new_end <= MMAP_TOP && new_end > old_addr) {
        int overlap = 0;
        for (int i = 0; i < a->nvma; i++) if (i != vi) {
            uint64_t s = a->vma[i].start, e = s + a->vma[i].len;
            if (old_end < e && new_end > s) { overlap = 1; break; }
        }
        if (!overlap) {
            if (a->rlim_as && app_vma_total(a) - old_len + new_len > a->rlim_as) return (uint64_t)-1;
            a->vma[vi].len = new_len;                     /* new pages demand-fault in lazily */
            return old_addr;
        }
    }
    if (!(flags & MREMAP_MAYMOVE)) return (uint64_t)-1;   /* blocked, and not allowed to move */

    /* MOVE: reserve a fresh region (bump allocator, like app_mmap), copy, free old */
    if (a->nvma >= APP_MAXVMA) return (uint64_t)-1;
    if (a->mmap_next < MMAP_BASE) a->mmap_next = MMAP_BASE;
    uint64_t nbase = a->mmap_next;
    if (nbase + new_len > MMAP_TOP || nbase + new_len < nbase) return (uint64_t)-1;
    if (a->rlim_as && app_vma_total(a) + new_len > a->rlim_as) return (uint64_t)-1;
    uint64_t copy_len = old_len < new_len ? old_len : new_len;
    for (uint64_t off = 0; off < copy_len; off += PAGE_SIZE) {
        uint64_t ph = vmm_translate(old_addr + off);
        if (!ph) continue;                                /* old page never faulted -> leave new demand-paged */
        uint64_t nf = pmm_alloc_frame();
        if (!nf) {                                         /* OOM mid-move: undo the new pages, bail (old untouched) */
            for (uint64_t u = 0; u < off; u += PAGE_SIZE) { uint64_t q = vmm_translate(nbase + u); if (q) { vmm_unmap(nbase + u); pmm_free_frame(q); } }
            return (uint64_t)-1;
        }
        uint8_t *s = (uint8_t *)hhdm(ph), *d = (uint8_t *)hhdm(nf);
        for (int b = 0; b < PAGE_SIZE; b++) d[b] = s[b];
        vmm_map(nbase + off, nf, PTE_WRITABLE | PTE_USER | PTE_NX);
    }
    VMA_NEW(a);
    a->vma[a->nvma].start = nbase; a->vma[a->nvma].len = new_len;
    a->vma[a->nvma].sealed = a->vma[a->nvma].uffd = a->vma[a->nvma].file_backed = a->vma[a->nvma].locked = a->vma[a->nvma].huge = 0;
    a->nvma++;
    a->mmap_next = nbase + new_len + PAGE_SIZE;
    app_munmap(old_addr, old_len);                        /* free the old region's frames + VMA */
    return nbase;
}

/* mseal (M1130): irreversibly seal every mmap region overlapping [addr,addr+len)
 * so its mapping can no longer be changed — munmap and mprotect on it are denied
 * from here on (the seal even survives fork). The point is forward security: an
 * app that has built and mprotect'd a region the way it wants (e.g. flipped JIT'd
 * code to R-X under W^X) seals it, so a later bug that hands an attacker an
 * mprotect/munmap primitive still cannot make that code writable again or swap a
 * fresh page under it. Linux's mseal(2) (2024). Returns the number of regions
 * sealed, or -1 if the range matched no mapping. */
int app_mseal(uint64_t addr, uint64_t len) {
    struct app *a = cur();
    if (!a || len == 0) return -1;
    uint64_t end = addr + len;
    if (end < addr) return -1;
    int sealed = 0;
    for (int i = 0; i < a->nvma; i++) {
        uint64_t vs = a->vma[i].start, ve = vs + a->vma[i].len;
        if (addr < ve && vs < end) { a->vma[i].sealed = 1; sealed++; }   /* overlaps the range */
    }
    return sealed ? sealed : -1;
}

/* ===================== userfaultfd (M1134) =============================== *
 * Userspace page-fault handling. An OWNER process mmap's a region and registers
 * it (app_uffd_register); thereafter the owner faulting on an unbacked page in
 * that region does NOT demand-zero — it PARKS, and the page address is handed to
 * a MONITOR process. The monitor reads the fault (app_uffd_read), produces the
 * page's contents, and fills it (app_uffd_copy) — which maps a fresh frame into
 * the OWNER's (other) address space via vmm_map_to and wakes the owner, whose
 * faulting instruction now re-executes successfully. It's the primitive under
 * live migration / post-copy / on-demand paging. One region at a time; the
 * owner≠monitor split is provided by fork(). Reuses the cross-address-space
 * mapping (M1114) and the park/wait rendezvous (M1124). g_uffd is defined up top
 * (above app_reap / app_fault_handle, which reference it). */
int app_uffd_register(uint64_t addr, uint64_t len) {
    struct app *a = cur();
    if (!a || len == 0) return -1;
    uint64_t end = addr + len; if (end < addr) return -1;
    int found = 0;
    for (int i = 0; i < a->nvma; i++) {            /* flag the overlapping mmap region(s) */
        uint64_t vs = a->vma[i].start, ve = vs + a->vma[i].len;
        if (addr < ve && vs < end) { a->vma[i].uffd = 1; found = 1; }
    }
    if (!found) return -1;                          /* must cover an mmap region */
    g_uffd.active = 1; g_uffd.owner = a; g_uffd.cr3 = a->cr3;
    g_uffd.pending = 0; g_uffd.monitor = 0; g_uffd.monitor_waiting = 0; g_uffd.faulter = 0;
    return 0;
}

/* Monitor: block until the owner faults; returns the faulting page address, or -1. */
long app_uffd_read(void) {
    uint64_t f = irq_save();
    if (!g_uffd.active) { irq_restore(f); return -1; }
    g_uffd.monitor = task_self();
    while (!g_uffd.pending) {
        g_uffd.monitor_waiting = 1;
        irq_restore(f);                 /* released BEFORE blocking (M1612) */
        task_block();
        f = irq_save();
        g_uffd.monitor_waiting = 0;
        if (!g_uffd.active) { irq_restore(f); return -1; }   /* owner vanished */
    }
    long addr = (long)g_uffd.addr;
    irq_restore(f);
    return addr;
}

/* Monitor: fill the faulting page with `data` (in the OWNER's address space) and
 * wake the owner. `data` is the monitor's pointer (validated by the caller). */
int app_uffd_copy(uint64_t addr, const void *data, uint64_t len) {
    uint64_t f = irq_save();
    int ok = g_uffd.active && g_uffd.pending;
    uint64_t cr3 = g_uffd.cr3;
    irq_restore(f);
    if (!ok) return -1;
    uint64_t page = addr & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t frame = pmm_alloc_frame();
    if (!frame) return -1;
    uint8_t *d = (uint8_t *)hhdm(frame);
    const uint8_t *s = (const uint8_t *)data;
    uint64_t n = len < PAGE_SIZE ? len : PAGE_SIZE;
    for (uint64_t i = 0; i < n; i++) d[i] = s[i];
    for (uint64_t i = n; i < PAGE_SIZE; i++) d[i] = 0;
    /* map the frame into the owner's (currently inactive) space; its CR3 reload
     * on resume makes the new PTE visible — no invlpg needed for an off-CPU space. */
    if (vmm_map_to(cr3 & PTE_ADDR_MASK, page, frame, PTE_WRITABLE | PTE_USER | PTE_NX) < 0) {
        pmm_free_frame(frame);
        return -1;
    }
    f = irq_save();
    g_uffd.pending = 0;
    if (g_uffd.faulter) task_wake(g_uffd.faulter);
    irq_restore(f);
    return 0;
}

/* MADV_COLLAPSE (Linux 6.1+): synchronously fold a fully-resident, single-owner
 * anonymous mmap VMA into 2 MiB transparent hugepages — the inverse of letting
 * khugepaged do it lazily. ALL-OR-NOTHING: phase 1 validates every page (present,
 * 4 KiB-mapped, refcount 0), phase 2 captures each block's page-table frame and
 * reserves one contiguous 2 MiB frame per 2 MiB block, and only if every step
 * succeeds does phase 3 mutate anything — so a failure leaves the region exactly
 * as it was. Each block: copy the 512 pages' bytes into the contiguous frame
 * (read straight out of the still-intact PT via the HHDM), install one huge PD
 * entry (vmm_map_huge), then free the 512 scattered 4 KiB frames and the orphaned
 * page table. Same address space as the caller + single CPU ⇒ no cross-AS TLB
 * shootdown. The VMA is marked `huge` so munmap/teardown free it as 2 MiB runs
 * (matching app_mmap_huge). Returns pages collapsed, or 0 if nothing qualified. (M1168) */
static int app_collapse(uint64_t addr, uint64_t len) {
    struct app *a = cur();
    if (!a || (addr & (HUGE_SIZE - 1))) return 0;                /* must be 2 MiB-aligned */
    int vi = -1;
    for (int i = 0; i < a->nvma; i++) if (a->vma[i].start == addr) { vi = i; break; }
    if (vi < 0) return 0;
    if (a->vma[vi].huge || a->vma[vi].file_backed || a->vma[vi].sealed) return 0;   /* plain anon, not already huge */
    uint64_t vlen = a->vma[vi].len;
    if (vlen == 0 || (vlen & (HUGE_SIZE - 1)) || len < vlen) return 0;   /* collapse the WHOLE 2 MiB-multiple VMA */
    uint64_t nblk = vlen / HUGE_SIZE;
    if (nblk > 16) return 0;                                     /* bound the pre-capture arrays (≤ 32 MiB) */
    uint64_t cr3 = a->cr3;

    for (uint64_t b = 0; b < nblk; b++)                          /* phase 1: validate */
        for (int i = 0; i < 512; i++) {
            uint64_t pte = vmm_pte_in(cr3, addr + b * HUGE_SIZE + (uint64_t)i * PAGE_SIZE);
            if (!(pte & PTE_PRESENT) || (pte & PTE_HUGE)) return 0;       /* hole / swapped / already huge */
            if (pmm_refcount(pte & PTE_ADDR_MASK) != 0) return 0;        /* COW-shared: collapsing would unshare */
        }

    uint64_t newphys[16], ptphys[16];                           /* phase 2: capture PTs + reserve frames */
    for (uint64_t b = 0; b < nblk; b++) {
        ptphys[b]  = vmm_pt_phys_in(cr3, addr + b * HUGE_SIZE);
        newphys[b] = ptphys[b] ? pmm_alloc_contiguous(512, 512) : 0;
        if (!ptphys[b] || !newphys[b]) {                        /* roll back: free what we reserved, touch nothing else */
            for (uint64_t u = 0; u < b; u++) pmm_free_contiguous(newphys[u], 512);
            if (newphys[b]) pmm_free_contiguous(newphys[b], 512);
            return 0;
        }
    }

    for (uint64_t b = 0; b < nblk; b++) {                        /* phase 3: commit (cannot fail now) */
        uint64_t base = addr + b * HUGE_SIZE;
        uint64_t *pt  = (uint64_t *)hhdm(ptphys[b]);             /* the soon-to-be-orphaned page table */
        for (int i = 0; i < 512; i++) {                         /* preserve the data */
            uint8_t *s = (uint8_t *)hhdm(pt[i] & PTE_ADDR_MASK);
            uint8_t *d = (uint8_t *)hhdm(newphys[b] + (uint64_t)i * PAGE_SIZE);
            for (int by = 0; by < PAGE_SIZE; by++) d[by] = s[by];
        }
        vmm_map_huge(base, newphys[b], PTE_WRITABLE | PTE_USER | PTE_NX);   /* replaces the PD entry (current AS) */
        for (int i = 0; i < 512; i++) pmm_free_frame(pt[i] & PTE_ADDR_MASK);  /* release the scattered frames */
        pmm_free_frame(ptphys[b]);                              /* and the orphaned page table */
    }
    a->vma[vi].huge = 1;                                        /* now a hugepage VMA (M1155-shaped) */
    return (int)(nblk * 512);
}

/* madvise(MADV_DONTNEED) (M1099): reclaim the resident frames of [addr,addr+len)
 * NOW, so RAM drops immediately and the next touch demand-faults a fresh zero
 * page (app_fault_handle). The mmap VMA stays reserved. We only drop pages that
 * are (a) inside an mmap region and (b) single-owner (pmm_refcount == 0) — so a
 * shared/ring-mirror frame (mapped more than once, M1089) is never pulled out
 * from under its other mapping. Other advices are accepted as no-ops. Returns
 * the number of pages dropped, or -1 on a bad range. */
#define MADV_DONTNEED 4
#define MADV_COLD     20   /* deactivate: clear accessed bits so the range is a reclaim candidate (M1158) */
#define MADV_PAGEOUT  21   /* proactively page the range out to swap (zram) NOW (M1158) */
#define MADV_COLLAPSE 25   /* synchronously fold the range into 2 MiB hugepage(s) (M1168) */
int app_madvise(uint64_t addr, uint64_t len, int advice) {
    struct app *a = cur();
    if (!a || len == 0) return -1;
    if (advice == MADV_PAGEOUT)                       /* reclaim NOW by swapping the range out (M1099 swap / M1156 zram) */
        return app_swap_out(addr, len);
    if (advice == MADV_COLLAPSE)                      /* fold into a 2 MiB hugepage NOW (M1168) */
        return app_collapse(addr, len);
    uint64_t start = addr & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t end   = (addr + len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (advice == MADV_COLD) {                        /* clear the Accessed bit on resident pages (deactivate) */
        int n = 0;
        for (uint64_t p = start; p < end; p += PAGE_SIZE) {
            uint64_t pte = vmm_pte_raw(p);
            if (pte & PTE_PRESENT) { vmm_set_raw(p, pte & ~(uint64_t)PTE_ACCESSED); n++; }
        }
        return n;
    }
    if (advice != MADV_DONTNEED) return 0;            /* NORMAL/WILLNEED/FREE/etc: accepted no-op */
    int dropped = 0;
    for (uint64_t p = start; p < end; p += PAGE_SIZE) {
        int in_vma = 0, locked = 0;
        for (int i = 0; i < a->nvma; i++)
            if (p >= a->vma[i].start && p < a->vma[i].start + a->vma[i].len) { in_vma = 1; locked = a->vma[i].locked; break; }
        if (!in_vma || locked) continue;              /* demand-paged mmap regions; mlock'd pages are pinned (M1149) */
        uint64_t ph = vmm_translate(p);
        if (ph && pmm_refcount(ph) == 0) {            /* single-owner anon page: safe to reclaim */
            vmm_unmap(p);
            pmm_free_frame(ph);
            dropped++;
        }
    }
    return dropped;
}

/* process_madvise (M1555): advise about ANOTHER process's memory, named by a
 * pidfd (never a raw pid -- avoids the PID-reuse race a bare integer would
 * have) rather than cur(). Same-tree permission as process_vm_read/write and
 * ptrace (self, parent, or child). Deliberately scoped to MADV_COLD only:
 * DONTNEED needs the target's OWN nvma/locked bookkeeping consulted (fine)
 * but then actually FREES the frame via vmm_unmap/pmm_free_frame, which
 * assume the CURRENTLY-loaded address space; PAGEOUT/COLLAPSE go through
 * app_swap_out/app_collapse, which are cur()-coupled even more deeply. COLD
 * only touches one PTE bit through the already-proven cr3-parameterized
 * vmm_pte_in/vmm_set_pte_in pair (the same ones app_msync already uses,
 * M1544) -- clean, safe, and honestly everything that's a small slice here;
 * the rest is real follow-on work, not attempted in this milestone. */
int app_process_madvise(int pidfd, uint64_t addr, uint64_t len, int advice) {
    struct app *me = cur(); if (!me || len == 0) return -1;
    if (pidfd < 0 || pidfd >= APP_NFD || !me->fd[pidfd].used || me->fd[pidfd].type != 7) return -1;
    struct app *t = app_by_pid(me->fd[pidfd].obj);
    if (!t || t->exited) return -1;                                        /* gone: ESRCH */
    if (t != me && t->parent != me->pid && me->parent != t->pid) return -1; /* same-tree only */
    if (advice != MADV_COLD) return -1;
    uint64_t start = addr & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t end   = (addr + len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    int n = 0;
    for (uint64_t p = start; p < end; p += PAGE_SIZE) {
        uint64_t pte = vmm_pte_in(t->cr3, p);
        if (pte & PTE_PRESENT) { vmm_set_pte_in(t->cr3, p, pte & ~(uint64_t)PTE_ACCESSED); n++; }
    }
    return n;
}

/* mincore(addr,len,vec) (M1147): report per-page residency for [addr,addr+len)
 * of the CALLING app. `addr` must be page-aligned; the WHOLE range must lie
 * inside the app's mmap VMAs (else -1 / ENOMEM, matching POSIX). For each page
 * it writes vec[i] = 1 if that page is RESIDENT (already demand-faulted in, so
 * vmm_translate yields a frame) or 0 if it is reserved-but-not-yet-faulted.
 * This is the READ side of the demand pager (app_fault_handle) + COW + madvise
 * (MADV_DONTNEED): userspace can SEE exactly which pages RAM actually backs,
 * proving lazy allocation. `vec` must hold ceil(len/PAGE) bytes (the syscall
 * validates that). Returns 0 on success, -1 on a bad/unaligned/unmapped range. */
int app_mincore(uint64_t addr, uint64_t len, uint8_t *vec) {
    struct app *a = cur();
    if (!a || len == 0) return -1;
    if (addr & (uint64_t)(PAGE_SIZE - 1)) return -1;          /* POSIX: addr must be page-aligned */
    uint64_t end = addr + ((len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1));
    int idx = 0;
    for (uint64_t p = addr; p < end; p += PAGE_SIZE, idx++) {
        int in_vma = 0;
        for (int i = 0; i < a->nvma; i++)
            if (p >= a->vma[i].start && p < a->vma[i].start + a->vma[i].len) { in_vma = 1; break; }
        if (!in_vma) return -1;                                /* ENOMEM: range crosses an unmapped page */
        vec[idx] = vmm_translate(p) ? 1 : 0;                   /* bit0 = page resident */
    }
    return 0;
}

/* mlock/munlock (M1149): pin (lock=1) or unpin (lock=0) the mmap pages that
 * overlap [addr,addr+len) so they are exempt from reclaim — both swap-out
 * (app_swap_out) and madvise(MADV_DONTNEED) skip a VMA whose `locked` flag is
 * set. We set the flag on every VMA the range overlaps. NB unlike Linux this
 * does NOT force-fault the range resident on lock (no kernel touch of a user
 * page); a not-yet-faulted page simply faults in on first access as usual and
 * is then pinned (its VMA is locked). Returns 0, or -1 if the range overlaps
 * no mmap VMA. Pairs with mincore (M1147) for query+control of residency. */
static int app_mlock_set(uint64_t addr, uint64_t len, int lock) {
    struct app *a = cur();
    if (!a || len == 0) return -1;
    uint64_t start = addr & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t end   = (addr + len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (lock && a->rlim_memlock) {          /* RLIMIT_MEMLOCK (M1550): whole-VMA granularity, like the lock itself */
        uint64_t locked_now = 0, newly = 0;
        for (int i = 0; i < a->nvma; i++) {
            if (a->vma[i].locked) { locked_now += a->vma[i].len; continue; }
            uint64_t vs = a->vma[i].start, ve = vs + a->vma[i].len;
            if (start < ve && vs < end) newly += a->vma[i].len;   /* overlaps + not already locked */
        }
        if (locked_now + newly > a->rlim_memlock) return -1;
    }
    int any = 0;
    for (int i = 0; i < a->nvma; i++) {
        uint64_t vs = a->vma[i].start, ve = vs + a->vma[i].len;
        if (start < ve && vs < end) { a->vma[i].locked = lock; any = 1; }   /* overlaps the range */
    }
    return any ? 0 : -1;
}
int app_mlock(uint64_t addr, uint64_t len)   { return app_mlock_set(addr, len, 1); }
int app_munlock(uint64_t addr, uint64_t len) { return app_mlock_set(addr, len, 0); }
/* mlockall/munlockall (M1283): MCL_CURRENT (1) pins every current VMA;
 * MCL_FUTURE (2) makes subsequent anonymous mmaps born-locked (via mlock_future,
 * honored in app_mmap). munlockall clears both. Returns 0/-1. */
int app_mlockall(int flags) {
    struct app *a = cur(); if (!a) return -1;
    if (flags & 1) {
        if (a->rlim_memlock) {              /* RLIMIT_MEMLOCK (M1550): mlock()'s own per-call cap must apply here too */
            uint64_t total = 0;
            for (int i = 0; i < a->nvma; i++) total += a->vma[i].len;
            if (total > a->rlim_memlock) return -1;
        }
        for (int i = 0; i < a->nvma; i++) a->vma[i].locked = 1;   /* MCL_CURRENT */
    }
    a->mlock_future = (flags & 2) ? 1 : 0;                                   /* MCL_FUTURE */
    return 0;
}
int app_munlockall(void) {
    struct app *a = cur(); if (!a) return -1;
    for (int i = 0; i < a->nvma; i++) a->vma[i].locked = 0;
    a->mlock_future = 0;
    return 0;
}

/* mprotect (M1090): change the R/W/X protection of an already-mapped range in
 * the calling app (PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4). Enables W^X and
 * write-then-execute JIT pages. The range must be the app's own user pages. */
int app_mprotect(uint64_t addr, uint64_t len, int prot) {
    if (len == 0) return -1;
    uint64_t a0 = addr & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t end = (addr + len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (end <= a0) return -1;
    struct app *a = cur();                                     /* deny if the range hits a sealed region (M1130) */
    if (a) for (int i = 0; i < a->nvma; i++)
        if (a->vma[i].sealed && a0 < a->vma[i].start + a->vma[i].len && a->vma[i].start < end) return -1;
    uint64_t flags = PTE_USER;
    if (prot & 0x2) flags |= PTE_WRITABLE;       /* PROT_WRITE  */
    if (!(prot & 0x4)) flags |= PTE_NX;          /* not PROT_EXEC -> no-execute */

    /* Is the whole range inside this app's own demand-paged regions? If so,
     * record the protection ON THE VMA and touch only the pages that are
     * actually resident. The old code validated with vmm_user_ok first --
     * and vmm_user_ok MATERIALISES a lazily-resolvable page, so an mprotect
     * over an untouched mapping read every page of it from disk just to set
     * a PTE bit. That is why an mmap with a non-default prot was never lazy.
     * (M1956) */
    int covered = 0;
    if (a) {
        covered = 1;
        for (uint64_t p = a0; p < end && covered; p += PAGE_SIZE) {
            int in = 0;
            for (int i = 0; i < a->nvma; i++)
                if (p >= a->vma[i].start && p < a->vma[i].start + a->vma[i].len) { in = 1; break; }
            if (!in) covered = 0;
        }
    }
    if (covered) {
        /* PROT_NONE records as READ, because we have no "reserved but
         * inaccessible" state -- which is exactly what the old code did too
         * (PTE_USER|PTE_NX), so this changes nothing. 0 is reserved for
         * "never recorded". */
        uint8_t np = (uint8_t)((prot & 0x7) ? (prot & 0x7) : VMA_PROT_READ);
        /* Make a0 and end VMA boundaries first, so only fully-covered VMAs
         * take the new protection. */
        if (app_vma_split_at(a, a0) != 0 || app_vma_split_at(a, end) != 0) return -1;
        for (int i = 0; i < a->nvma; i++) {
            uint64_t s0 = a->vma[i].start, e0 = s0 + a->vma[i].len;
            if (s0 >= a0 && e0 <= end) a->vma[i].prot = np;
        }
        for (uint64_t p = a0; p < end; p += PAGE_SIZE)
            if (vmm_translate(p)) { if (vmm_protect(p, flags) < 0) return -1; }
        return 0;
    }
    if (!vmm_user_ok(a0, end - a0)) return -1;   /* must be the caller's mapped user pages */
    for (uint64_t p = a0; p < end; p += PAGE_SIZE)
        if (vmm_protect(p, flags) < 0) return -1;
    return 0;
}

/* Magic (mirrored) ring buffer (M1089): reserve `len` bytes of physical frames
 * and map them TWICE, back to back, so the region [base, base+2*len) has its
 * second half alias the first. A wraparound queue then needs no split-handling
 * or modulo — a read/write that crosses base+len continues seamlessly into the
 * same frames. Mapped eagerly (no demand faults); each frame is pmm_addref'd for
 * its second mapping so exit/munmap (which frees every PTE's frame) releases it
 * exactly once. Returns the base VA, or 0. */
uint64_t app_ringbuf(uint64_t len) {
    struct app *a = cur();
    if (!a || len == 0) return 0;
    len = (len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t total = len * 2;
    if (total < len) return 0;                       /* overflow */
    if (a->nvma >= APP_MAXVMA) return 0;
    if (a->mmap_next < MMAP_BASE) a->mmap_next = MMAP_BASE;
    uint64_t base = a->mmap_next;
    if (base + total > MMAP_TOP || base + total < base) return 0;
    uint64_t mapped = 0;
    for (uint64_t off = 0; off < len; off += PAGE_SIZE) {
        uint64_t frame = pmm_alloc_frame();
        if (!frame) {                                /* OOM: unwind what we mapped */
            for (uint64_t u = 0; u < mapped; u += PAGE_SIZE) {
                uint64_t ph = vmm_translate(base + u);
                vmm_unmap(base + len + u); vmm_unmap(base + u);
                if (ph) pmm_free_frame(ph);          /* drops the addref, then frees */
            }
            return 0;
        }
        uint8_t *z = (uint8_t *)hhdm(frame);
        for (int b = 0; b < PAGE_SIZE; b++) z[b] = 0;
        vmm_map(base + off, frame, PTE_WRITABLE | PTE_USER | PTE_NX);          /* primary */
        pmm_addref(frame);
        vmm_map(base + len + off, frame, PTE_WRITABLE | PTE_USER | PTE_NX);    /* mirror */
        __asm__ volatile("invlpg (%0)" : : "r"(base + off) : "memory");
        __asm__ volatile("invlpg (%0)" : : "r"(base + len + off) : "memory");
        mapped += PAGE_SIZE;
    }
    VMA_NEW(a);
    a->vma[a->nvma].start = base;
    a->vma[a->nvma].len   = total;
    a->vma[a->nvma].sealed = 0;
    a->vma[a->nvma].uffd  = 0;
    a->vma[a->nvma].file_backed = 0;
    a->vma[a->nvma].locked = 0;
    a->vma[a->nvma].huge = 0;
    a->nvma++;
    a->mmap_next = base + total + PAGE_SIZE;
    return base;
}

/* Map the named shared-memory object `name` (created at `size` on first use)
 * into the caller, returning its base VA (M1108). The object's frames live in
 * the kernel SHM table; each mapping pmm_addref's them, so two mappings — here
 * or in another process — share the same RAM, and teardown releases each ref
 * (the frames persist at refcount 0, owned by the table). 0 on failure. */
uint64_t app_shm_open(const char *name, uint64_t size) {
    struct app *a = cur();
    if (!a) return 0;
    uint64_t *frames; int np;
    if (shm_get(name, size, &frames, &np) < 0) return 0;
    if (a->nvma >= APP_MAXVMA) return 0;
    if (a->mmap_next < MMAP_BASE) a->mmap_next = MMAP_BASE;
    uint64_t base = a->mmap_next, total = (uint64_t)np * PAGE_SIZE;
    if (base + total > MMAP_TOP || base + total < base) return 0;
    for (int p = 0; p < np; p++) {
        vmm_map(base + (uint64_t)p * PAGE_SIZE, frames[p], PTE_WRITABLE | PTE_USER | PTE_NX);
        pmm_addref(frames[p]);                       /* this mapping holds a ref on the shared frame */
        __asm__ volatile("invlpg (%0)" : : "r"(base + (uint64_t)p * PAGE_SIZE) : "memory");
    }
    VMA_NEW(a);
    a->vma[a->nvma].start = base; a->vma[a->nvma].len = total; a->vma[a->nvma].sealed = 0; a->vma[a->nvma].uffd = 0; a->vma[a->nvma].file_backed = 0; a->vma[a->nvma].locked = 0; a->vma[a->nvma].huge = 0; a->nvma++;
    a->mmap_next = base + total + PAGE_SIZE;
    return base;
}

/* futex (M1109): a userspace fast mutex. The uncontended path is a userspace CAS
 * (zero syscalls); only on contention does a task trap here. op 0 = WAIT(uaddr,
 * val): if *uaddr still equals val, block until woken; op 1 = WAKE(uaddr, val):
 * wake up to `val` waiters. Wait buckets are keyed by the word's PHYSICAL address,
 * so a futex in shared memory (mapped at different VAs in two processes) matches.
 *
 * M1612: the WAIT compare+register and the WAKE scan+wake now share
 * app_wake_lock -- this used to claim atomicity from "the syscall path runs
 * interrupts-off on this single CPU (same guarantee as mbox)", the exact
 * assumption M1531 invalidated and M1608 already fixed in mbox.c itself.
 * Futexes exist specifically to synchronize across threads/cores, so a real
 * WAIT-vs-WAKE race here (unlike most of this file's other sites) is not a
 * rare corner case -- it's the primitive's own primary use. */
/* 32 -> 256 (M1959): one GLOBAL table shared by every process, and a real
 * threaded program parks most of its threads on a futex at once. 32 was a
 * hard ceiling on how many threads could block anywhere in the system. */
#define FUTEX_NWAIT 256
static struct { uint64_t key; void *task; int used; } g_futex[FUTEX_NWAIT];

/* Release our futex slot after waking, and report whether we were STILL
 * registered (i.e. nobody woke us -- a timeout).
 *
 * The ownership check is the whole point. The old code did a bare
 * `g_futex[slot].used = 0`, calling it "idempotent w/ WAKE" -- which is true
 * with one waiter and false the moment there are two:
 *
 *   1. thread A waits, claims slot 3, blocks
 *   2. a WAKE clears slot 3 and marks A runnable
 *   3. before A is scheduled, thread B waits, finds slot 3 free, claims it
 *   4. A finally resumes and zeroes slot 3 -- ERASING B's registration
 *   5. B is now blocked and invisible; the next WAKE finds nothing and B
 *      sleeps forever
 *
 * That is exactly what the timeout dump showed: threads BLOCKED with no futex
 * slot, and one lone registration left in the table. Harmless until real
 * threads arrived, then a hang in roughly three runs out of four. (M1959) */
static int futex_release(int slot) {
    uint64_t f = irq_save();
    int still_ours = (g_futex[slot].used && g_futex[slot].task == task_self());
    if (still_ours) g_futex[slot].used = 0;
    irq_restore(f);
    return still_ours;
}

/* Who is parked on a futex right now, and on what key. Printed when a
 * synchronous run times out -- a threaded hang is a lost wakeup until proven
 * otherwise, and this is the evidence. (M1959) */
void app_futex_dump(void) {
    for (int i = 0; i < FUTEX_NWAIT; i++)
        if (g_futex[i].used)
            kprintf("[futex] slot %d key=%lx task=%d\n", i, g_futex[i].key,
                    g_futex[i].task ? ((task_t *)g_futex[i].task)->id : -1);
}

long app_futex(uint64_t uaddr, int op, int val, long timeout_ms) {
    if (!vmm_user_ok(uaddr, 4)) return -1;
    uint64_t phys = vmm_translate(uaddr & ~(uint64_t)(PAGE_SIZE - 1));
    if (!phys) return -1;
    uint64_t key = phys | (uaddr & (PAGE_SIZE - 1));        /* per-physical-word key */

    if (op == FUTEX_WAIT) {
        uint64_t f = irq_save();
        if (*(volatile int *)uaddr != val) { irq_restore(f); return -1; }   /* value changed -> EAGAIN, don't block */
        int slot = -1;
        for (int i = 0; i < FUTEX_NWAIT; i++) if (!g_futex[i].used) { slot = i; break; }
        if (slot < 0) { irq_restore(f); return -1; }        /* too many waiters */
        g_futex[slot].key = key; g_futex[slot].task = task_self(); g_futex[slot].used = 1;
        irq_restore(f);                 /* release BEFORE blocking (M1612) -- see app_wake_lock's own comment */
        if (timeout_ms >= 0) {          /* bounded wait (M1578): matches epoll_wait/poll's own -1=forever, else ms convention */
            task_block_timeout(timer_ms() + (uint64_t)timeout_ms);   /* woken by a WAKE, the deadline, a kill, or a signal */
            int timed_out = futex_release(slot);
            return timed_out ? -1 : 0;
        }
        task_block();                                       /* woken by a WAKE, a kill, or a signal (unbounded, unchanged) */
        futex_release(slot);
        return 0;
    }
    if (op == FUTEX_WAKE) {
        uint64_t f = irq_save();
        int woke = 0;
        for (int i = 0; i < FUTEX_NWAIT && woke < val; i++)
            if (g_futex[i].used && g_futex[i].key == key) {
                g_futex[i].used = 0;
                task_wake((task_t *)g_futex[i].task);
                woke++;
            }
        irq_restore(f);
        return woke;
    }
    return -1;
}

/* #PF hook (called from the ring-3 path of the page-fault handler). If `cr2` is
 * inside a reserved mmap region, map a fresh zeroed frame into the (active) app
 * space and report it resolved so the instruction retries; else 0 = a real
 * fault, and the app is terminated as before. */
/* PTE flags for a VMA's Linux PROT_* bits. prot == 0 means "not recorded":
 * every VMA creator predating M1956 leaves it zero and gets exactly the old
 * behaviour, read-write and never executable. */
static uint64_t vma_pte_flags(uint8_t prot) {
    if (!prot) return PTE_WRITABLE | PTE_USER | PTE_NX;
    uint64_t f = PTE_USER;
    if (prot & VMA_PROT_WRITE) f |= PTE_WRITABLE;
    if (!(prot & VMA_PROT_EXEC)) f |= PTE_NX;
    return f;
}

int app_fault_handle(uint64_t cr2, uint64_t err) {
    struct app *a = cur();
    if (!a) return 0;
    uint64_t fpage = cr2 & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t pte = vmm_pte_raw(fpage);
    /* Copy-on-write (M1116): a WRITE fault (err bit 1) to a present, COW-marked
     * page — a frame shared by a fork. If we're the sole remaining owner just
     * make it writable again; otherwise allocate a private copy and drop our ref
     * on the shared frame (the other process keeps it). vmm_set_raw invlpg's. */
    if ((pte & PTE_PRESENT) && (pte & PTE_COW) && (err & 2)) {
        uint64_t old = pte & PTE_ADDR_MASK;
        if (pmm_refcount(old) == 0) {
            vmm_set_raw(fpage, (pte & ~PTE_COW) | PTE_WRITABLE);
        } else {
            uint64_t nf = pmm_alloc_frame();
            if (!nf) return 0;                      /* OOM -> let it fault/die */
            uint8_t *s = (uint8_t *)hhdm(old), *d = (uint8_t *)hhdm(nf);
            for (int b = 0; b < PAGE_SIZE; b++) d[b] = s[b];
            vmm_set_raw(fpage, nf | PTE_PRESENT | (pte & (PTE_USER | PTE_NX)) | PTE_WRITABLE);
            pmm_free_frame(old);                    /* decrements the shared frame's refcount */
        }
        a->minflt++;                                /* COW resolve: no disk I/O => minor fault (M1150) */
        return 1;
    }
    if (!(pte & 1) && (pte & PTE_SWAP)) {           /* a swapped-out page (M1105): fault it back in */
        int slot = (int)(pte >> 12);
        uint64_t frame = pmm_alloc_frame();
        if (!frame) return 0;                       /* OOM -> let it fault/die */
        __asm__ volatile("sti");                    /* swap I/O may wait on an IRQ (virtio); kernel-only addrs, so re-entrancy-safe */
        int rc = swap_in(slot, frame);
        __asm__ volatile("cli");
        if (rc < 0) { pmm_free_frame(frame); return 0; }
        swap_release(slot);                         /* page is resident again; the slot is free */
        vmm_map(fpage, frame, PTE_WRITABLE | PTE_USER | PTE_NX);   /* restores PRESENT + invlpg */
        a->majflt++;                                /* swapped in from disk => major fault (M1150) */
        return 1;
    }
    for (int i = 0; i < a->nvma; i++) {
        if (cr2 >= a->vma[i].start && cr2 < a->vma[i].start + a->vma[i].len) {
            uint64_t page = cr2 & ~(uint64_t)(PAGE_SIZE - 1);
            uint64_t cpte = vmm_pte_raw(page);
            if (cpte & PTE_PRESENT) {
                /* The page IS mapped, so this is a PERMISSION fault, not a
                 * missing one -- and "return 1" (retry) on a permission fault
                 * is an infinite loop: the instruction re-executes and faults
                 * again forever. That is a hang with no diagnostic at all,
                 * which is exactly what honouring VMA prot first produced.
                 * (M1956) */
                if ((err & 2) && !(cpte & PTE_WRITABLE)) {
                    /* MAP_PRIVATE means a write gets a private copy. If the
                     * mapping is writable per its VMA, the PTE simply predates
                     * an mprotect; otherwise the program really did write to a
                     * read-only mapping and deserves to hear about it. */
                    if (a->vma[i].prot & VMA_PROT_WRITE) {
                        vmm_protect(page, vma_pte_flags(a->vma[i].prot));
                        return 1;
                    }
                    kprintf("[fault] write to a read-only mapping at %lx (vma prot=%d)\n", page, a->vma[i].prot);
                    return 0;
                }
                if (err & 0x10) {
                    kprintf("[fault] instruction fetch from a non-executable mapping at %lx (vma prot=%d)\n", page, a->vma[i].prot);
                    return 0;
                }
                /* A "race" the first time is plausible: another core mapped
                 * the page between our fault and this check. The SAME fault
                 * repeating is not -- it is an infinite retry loop, and the
                 * instruction will re-execute and fault forever with NO
                 * syscalls and NO allocation, which looks exactly like a
                 * program that has hung for no reason. Count them. (M1961) */
                if (page == a->last_fault_page && err == a->last_fault_err) {
                    if (++a->fault_repeat > 64) {
                        kprintf("[fault] UNRESOLVABLE fault looping at %lx err=%lx pte=%lx (vma prot=%d) -- killing\n",
                                page, err, cpte, a->vma[i].prot);
                        return 0;
                    }
                } else {
                    a->last_fault_page = page; a->last_fault_err = err; a->fault_repeat = 0;
                }
                return 1;                               /* a genuine race: another core mapped it */
            }
            if (a->vma[i].huge) {                        /* 2 MiB hugepage: map the whole enclosing 2 MiB at once (M1155) */
                uint64_t hpage = cr2 & ~(HUGE_SIZE - 1);
                uint64_t phys = pmm_alloc_contiguous(HUGE_SIZE / PAGE_SIZE, HUGE_SIZE / PAGE_SIZE);  /* 512 contiguous, 2 MiB-aligned */
                if (!phys) return 0;                     /* no contiguous run -> let it fault/die */
                uint8_t *z = (uint8_t *)hhdm(phys);
                for (uint64_t b = 0; b < HUGE_SIZE; b++) z[b] = 0;   /* never leak stale RAM */
                vmm_map_huge(hpage, phys, PTE_WRITABLE | PTE_USER | PTE_NX);
                a->minflt++;                             /* one fault mapped the whole 2 MiB (M1150/M1155) */
                return 1;
            }
            /* userfaultfd (M1134): the OWNER faulting in a registered region parks
             * here; a monitor process fills the page (app_uffd_copy) and wakes us,
             * after which the instruction re-executes against the now-present page.
             * M1612: set-pending+check-wake and the poll of `pending` below now go
             * through app_wake_lock (was bare "IF=0 -> atomic (single CPU)", the
             * exact assumption M1531 invalidated: the owner and the monitor are
             * two different processes, routinely on two different cores). */
            if (a->vma[i].uffd) {
                uint64_t uf = irq_save();
                if (g_uffd.active && a == g_uffd.owner) {
                    g_uffd.addr = page;
                    g_uffd.faulter = task_self();
                    g_uffd.pending = 1;
                    if (g_uffd.monitor_waiting) { task_wake(g_uffd.monitor); g_uffd.monitor_waiting = 0; }
                    irq_restore(uf);
                    for (;;) {
                        uf = irq_save();
                        int pending = g_uffd.pending;
                        irq_restore(uf);
                        if (!pending) break;
                        task_block();          /* released above BEFORE blocking (M1612) */
                    }
                    return 1;
                }
                irq_restore(uf);
            }
            uint64_t frame = pmm_alloc_frame();
            if (!frame) return 0;                       /* OOM -> let it fault/die */
            uint8_t *z = (uint8_t *)hhdm(frame);
            for (int b = 0; b < PAGE_SIZE; b++) z[b] = 0; /* never leak stale RAM to userspace */
            if (a->vma[i].file_backed) {                /* fill the page from the backing file (M1136) */
                uint64_t voff = page - a->vma[i].start;
                uint64_t fileoff = a->vma[i].foff + voff;
                /* fvalid bounds how much of this mapping comes from the file.
                 * An ELF data segment's last page holds real bytes up to
                 * filesz and .bss after it -- and the file does NOT end there,
                 * so "bytes past EOF stay zero" is not enough: without this the
                 * start of .bss would be filled with whatever follows the
                 * segment in the file. 0 means "no limit" (a plain mmap of a
                 * whole file), which is what every pre-M1956 caller wants. */
                uint64_t want = PAGE_SIZE;
                if (a->vma[i].fvalid) {
                    want = (voff >= a->vma[i].fvalid) ? 0 : a->vma[i].fvalid - voff;
                    if (want > PAGE_SIZE) want = PAGE_SIZE;
                }
                if (want) {
                    __asm__ volatile("sti");            /* the FS read may touch the disk */
                    vfs_pread(a->vma[i].fpath, z, want, fileoff);   /* bytes past EOF stay zero; MAP_PRIVATE: writable copy */
                    __asm__ volatile("cli");
                }
                a->majflt++;                            /* page filled from disk => major fault (M1150) */
            } else {
                a->minflt++;                            /* demand-zero anonymous page => minor fault (M1150) */
            }
            /* Honour the VMA's protection. This used to be unconditionally
             * WRITABLE|NX, which was survivable only because app_mprotect goes
             * through vmm_user_ok -- and vmm_user_ok MATERIALISES lazily
             * resolvable pages, so every mmap with a non-default prot faulted
             * its whole range in eagerly and then fixed the PTEs. Correct, but
             * it means an mmap was never actually lazy; a 42 MB executable
             * would be read in full before its first instruction. (M1956) */
            vmm_map(page, frame, vma_pte_flags(a->vma[i].prot));
            __asm__ volatile("invlpg (%0)" : : "r"(page) : "memory");
            return 1;
        }
    }
    return 0;
}

/* Page out the anonymous (mmap) pages of [addr,addr+len) to swap (M1105): like
 * Linux's MADV_PAGEOUT. Each resident, single-owner page in an mmap VMA is
 * written to a swap slot, its PTE rewritten to the not-present swapped encoding
 * (slot + PTE_SWAP), and its frame freed — reclaiming RAM now. The next touch
 * faults it back via app_fault_handle. Shared/ring frames (refcount>0) and
 * non-mmap pages (code/stack) are skipped. Returns the page count, or -1. */
int app_swap_out(uint64_t addr, uint64_t len) {
    struct app *a = cur();
    if (!a || len == 0 || !swap_active()) return -1;
    uint64_t start = addr & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t end   = (addr + len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    int n = 0;
    for (uint64_t p = start; p < end; p += PAGE_SIZE) {
        int in_vma = 0, locked = 0;
        for (int i = 0; i < a->nvma; i++)
            if (p >= a->vma[i].start && p < a->vma[i].start + a->vma[i].len) { in_vma = 1; locked = a->vma[i].locked; break; }
        if (!in_vma || locked) continue;             /* anon mmap regions only; mlock'd pages are pinned (M1149) */
        uint64_t phys = vmm_translate(p);
        if (!phys || pmm_refcount(phys) != 0) continue;   /* not resident, or shared/mirrored -> skip */
        int slot = swap_out(phys);
        if (slot < 0) break;                         /* swap full / error */
        vmm_set_raw(p, ((uint64_t)slot << 12) | PTE_SWAP);   /* PRESENT=0, marker + slot */
        pmm_free_frame(phys);
        n++;
    }
    return n;
}

/* --- ring-3 signals (M1067) ------------------------------------------------
 * A registered handler runs on the app's own user stack; the interrupted
 * context is saved kernel-side (sig_saved), so the user stack only needs the
 * trampoline return address. When the handler returns it falls into the ulib
 * trampoline, which calls SYS_sigreturn to restore the saved context. No
 * nesting (sig_in guards). Dormant unless an app registers a handler. */
void app_signal_set(int signo, uint64_t handler, uint64_t restorer) {
    struct app *a = cur();
    if (!a || signo <= 0 || signo >= APP_NSIG) return;
    a->sig_handler[signo] = handler;
    a->sig_flags[signo] = 0;                 /* plain 1-arg handler */
    if (restorer) a->sig_restorer = restorer;
}

/* sigaction with flags (M1270): SA_SIGINFO selects the 3-arg form
 * h(signo, siginfo*, ucontext*) and the sigreturn-restores-from-user-ucontext
 * path (so a handler can inspect the fault + REWRITE the interrupted registers). */
void app_sigaction(int signo, uint64_t handler, uint64_t restorer, uint32_t flags) {
    struct app *a = cur();
    if (!a || signo <= 0 || signo >= APP_NSIG) return;
    a->sig_handler[signo] = handler;
    a->sig_flags[signo] = flags;
    if (restorer) a->sig_restorer = restorer;
}

#define APP_SA_SIGINFO 4u
#define APP_SA_ONSTACK 0x08000000u
int app_signal_deliver(struct registers *r, int signo) {
    struct app *a = cur();
    if (!a || signo <= 0 || signo >= APP_NSIG) return 0;
    if (!a->sig_handler[signo] || !a->sig_restorer || a->sig_in) return 0;

    /* SA_ONSTACK (M1276): run the handler on the alternate signal stack set by
     * sigaltstack(), instead of growing down from the interrupted rsp. This is
     * what lets a SIGSEGV handler survive a stack-overflow fault (the normal
     * stack is unusable). The frame is still built downward from the alt top. */
    uint64_t base_sp = r->rsp;
    if ((a->sig_flags[signo] & APP_SA_ONSTACK) && a->sig_alt_size)
        base_sp = a->sig_alt_base + a->sig_alt_size;

    if (a->sig_flags[signo] & APP_SA_SIGINFO) {
        /* 3-arg form (M1270): place {mcontext = the interrupted regs, siginfo} on
         * the user stack; the handler gets &siginfo + &mcontext and may EDIT the
         * mcontext, which sigreturn restores. */
        uint64_t sp = (base_sp - 128) & ~15ull;           /* skip red zone, align (base_sp = alt stack if SA_ONSTACK) */
        sp -= sizeof(struct registers); sp &= ~15ull; uint64_t mctx_addr = sp;
        sp -= 32; uint64_t si_addr = sp;                  /* {si_signo, si_code, si_addr, si_value} (24B, 16-aligned) */
        uint64_t ret = (sp & ~15ull) - 8;                 /* ret-addr slot (entry rsp%16==8) */
        if (!vmm_user_ok(ret, 8) || !vmm_user_ok(mctx_addr, sizeof(struct registers))
            || !vmm_user_ok(si_addr, 32)) return 0;
        *(struct registers *)mctx_addr = *r;              /* the interrupted context = the ucontext */
        ((int *)si_addr)[0] = signo;                      /* si_signo @0  */
        ((int *)si_addr)[1] = a->sig_q_code;              /* si_code  @4  (SI_QUEUE=-1 from sigqueue, else SI_USER=0) */
        ((uint64_t *)si_addr)[1] = 0;                     /* si_addr  @8  (0 for a raised/queued signal) */
        ((uint64_t *)si_addr)[2] = a->sig_q_value;        /* si_value @16 (the sigqueue sigval payload, M1271) */
        *(volatile uint64_t *)ret = a->sig_restorer;
        a->sig_saved = *r;                                /* safe baseline: cs/ss/rflags for sigreturn */
        a->sig_uctx = mctx_addr;
        a->sig_in = 1;
        r->rsp = ret;
        r->rip = a->sig_handler[signo];
        r->rdi = (uint64_t)signo;                         /* h(signo, */
        r->rsi = si_addr;                                 /*   siginfo*, */
        r->rdx = mctx_addr;                               /*   ucontext*) */
        return 1;
    }

    uint64_t nrsp = ((base_sp - 128) & ~15ull) - 8;  /* skip red zone, 16-align, room for ret addr (base_sp = alt stack if SA_ONSTACK) */
    if (!vmm_user_ok(nrsp, 8)) return 0;             /* bad user stack -> don't deliver */
    a->sig_saved = *r;                               /* save the interrupted context */
    a->sig_uctx = 0;
    a->sig_in = 1;
    *(volatile uint64_t *)nrsp = a->sig_restorer;    /* handler's return address -> trampoline */
    r->rsp = nrsp;
    r->rip = a->sig_handler[signo];
    r->rdi = (uint64_t)signo;                        /* handler(int signo) */
    return 1;
}

void app_sigreturn(struct registers *r) {
    struct app *a = cur();
    if (!a || !a->sig_in) return;
    /* Restore the interrupted context kernel-side. (SA_SIGINFO hands the handler
     * a READABLE ucontext on the stack for fault inspection; resuming at a
     * handler-rewritten register state — JIT-trap style — is a follow-on, which
     * needs the user ucontext restored with cs/ss/rflags forced safe.) */
    *r = a->sig_saved;
    a->sig_uctx = 0;
    a->sig_in = 0;
}

/* sigaltstack (M1276): register an alternate stack for handlers installed with
 * SA_ONSTACK. ss_size 0 disables. The region must be user-accessible (mapped).
 * Returns 0/-1. Pairs with SA_SIGINFO so a SIGSEGV handler can run even when
 * the normal stack has overflowed. */
long app_sigaltstack(uint64_t ss_sp, uint64_t ss_size) {
    struct app *a = cur(); if (!a) return -1;
    if (ss_size == 0) { a->sig_alt_base = 0; a->sig_alt_size = 0; return 0; }
    if (ss_size < 2048 || !vmm_user_ok(ss_sp, ss_size)) return -1;   /* min usable size + must be mapped */
    a->sig_alt_base = ss_sp;
    a->sig_alt_size = ss_size;
    return 0;
}

/* Raise a signal ASYNCHRONOUSLY on app `a` (e.g. the WM mapping Ctrl-C on the
 * focused window to SIGINT). Opt-in: only if the app installed a handler for it
 * — otherwise we leave the keystroke alone, so the shell's existing 0x83 loop-
 * break and every non-handling app are unaffected. The pending signal is
 * delivered when the app next returns to ring 3 (app_deliver_pending). M1083. */
void app_request_signal(app_t *a, int signo) {
    struct app *ap = (struct app *)a;
    if (!ap || signo <= 0 || signo >= APP_NSIG) return;
    /* Job-control default actions (M1178), applied with no handler required —
     * SIGCONT resumes a stopped process, SIGSTOP/SIGTSTP suspend it (the
     * scheduler skips a STOPPED task, so its work simply freezes). task_stop
     * is a no-op on self, which is correct: a group ^C/^Z from the foreground
     * reader stops the OTHER group members. */
    if (signo == SIGCONT) { task_cont((task_t *)ap->task); return; }
    if (signo == SIGSTOP || signo == SIGTSTP) { task_stop((task_t *)ap->task); return; }
    /* opted in via a handler, OR routed to signalfd (M1126) — else ignore, the
     * existing default for handler-less signals. */
    int sigfd = ap->sigfd_armed && (ap->sigfd_mask & (1u << signo));
    if (!ap->sig_handler[signo] && !sigfd) return;
    /* M1612: paired with app_sigsuspend/app_pause/app_sigfd_read's own lock
     * around their check-then-block loops below -- previously unsynchronized,
     * relying purely on task_wake's own state check with no shared flag or
     * lock of any kind (unlike this file's OTHER blocking primitives, none
     * of which had even a bare cli here). A sender (kill/sigqueue/killpg, or
     * the timer for SIGALRM) is routinely a different process on a different
     * core than the one about to block. */
    uint64_t f = irq_save();
    ap->pending_sigs |= (1u << signo);       /* OR into the bitset, so a 2nd async signal isn't dropped */
    task_wake(ap->task);                     /* unblock it if it's parked in read()/sigfd */
    irq_restore(f);
}

/* sigprocmask (M1208): change the caller's blocked-signal mask and return the
 * previous one. A blocked signal that's raised stays pending (app_deliver_pending
 * skips it) and is delivered once unblocked. SIGKILL/SIGSTOP can't be blocked. */
uint32_t app_sigprocmask(int how, uint32_t set) {
    struct app *a = cur();
    if (!a) return 0;
    uint32_t old = a->sig_blocked;
    switch (how) {
        case 0: a->sig_blocked |= set;  break;       /* SIG_BLOCK */
        case 1: a->sig_blocked &= ~set; break;       /* SIG_UNBLOCK */
        case 2: a->sig_blocked = set;   break;       /* SIG_SETMASK */
        default: break;
    }
    a->sig_blocked &= ~((1u << 9) | (1u << 19));      /* SIGKILL(9)/SIGSTOP(19) are never blockable */
    return old;
}

/* sigpending (M1209): the set of signals raised on this process but not yet
 * delivered (because they're blocked) — POSIX sigpending(2). */
uint32_t app_sigpending(void) {
    struct app *a = cur();
    return a ? a->pending_sigs : 0;
}

/* Mirrors app_deliver_pending's own inner gate exactly (pending, has a real
 * handler, not blocked) rather than the broader "pending_sigs & ~sig_blocked"
 * — a signal that's only routed to signalfd (no handler) can be pending and
 * unblocked without being "deliverable" in the sigsuspend sense; real POSIX
 * sigsuspend only wakes for a signal whose action actually runs. Public +
 * no-arg (matching app_sigpending's own cur()-internally style) since
 * epoll_pwait (M1567), in syscall.c, needs it too, to break its poll loop on
 * a deliverable signal the same way sigsuspend/pause break their own wait. */
int app_signal_deliverable(void) {
    struct app *a = cur();
    if (!a) return 0;
    for (int sig = 1; sig < APP_NSIG; sig++)
        if ((a->pending_sigs & (1u << sig)) && a->sig_handler[sig] && !(a->sig_blocked & (1u << sig)))
            return 1;
    return 0;
}
/* sigsuspend (M1561): atomically swap the blocked mask, block until a signal
 * is deliverable, deliver it, THEN restore the original mask — real POSIX
 * ordering, where the temporary mask is what's in effect while the signal's
 * action runs, not the restored one. That ordering is why this takes `r`
 * and calls app_deliver_pending itself instead of just setting pending_sigs
 * and letting the syscall-return tail (kernel/syscall.c's sc_done) handle it
 * like every other async signal: by the time that tail runs, this function
 * has already restored the mask, which would be one syscall too late for a
 * handler that itself calls sigprocmask to check what was blocked. Calling
 * app_deliver_pending twice (here, then again at sc_done) is safe — the
 * second call finds sig_in already 1 and no-ops.
 * r->rax is set to the eventual return value (-1, always — sigsuspend never
 * "succeeds" by definition) BEFORE app_deliver_pending runs, since it snap-
 * shots *r verbatim into a->sig_saved for sigreturn to restore later; setting
 * it after would leave the wrong value in that snapshot. */
long app_sigsuspend(struct registers *r, uint32_t mask) {
    struct app *a = cur();
    if (!a) return -1;
    uint32_t old = a->sig_blocked;
    a->sig_blocked = mask & ~((1u << 9) | (1u << 19));   /* SIGKILL/SIGSTOP never blockable (matches sigprocmask) */
    for (;;) {
        uint64_t f = irq_save();               /* pairs with app_request_signal's own lock (M1612) */
        int deliverable = app_signal_deliverable();
        irq_restore(f);
        if (deliverable) break;
        task_block();
        if (!a->used) return -1;    /* killed while suspended */
    }
    r->rax = (uint64_t)-1;
    app_deliver_pending(r);
    a->sig_blocked = old;
    return -1;
}

/* pause (M1563): block until a signal is delivered, using the CURRENT mask
 * unchanged -- exactly sigsuspend with mask == a->sig_blocked, which makes
 * its own swap-then-restore a no-op (same value both ways) and its wait
 * condition/delivery-ordering fix (M1561) apply here for free. */
long app_pause(struct registers *r) {
    struct app *a = cur();
    if (!a) return -1;
    return app_sigsuspend(r, a->sig_blocked);
}

/* --- RT signals / sigqueue(3) (M1271) -----------------------------------
 * Real-time signals differ from standard signals in two ways: they QUEUE
 * (multiple pending instances are kept and delivered one-by-one, in FIFO
 * order, instead of coalescing into a single bit) and they carry a sigval
 * PAYLOAD delivered via siginfo.si_value (with SA_SIGINFO). We model both with
 * a per-process payload FIFO (sigq[]): sigqueue() appends {signo,value}, the
 * pending bit just says "≥1 queued for this signo", and app_deliver_pending
 * drains one record per delivery, clearing the bit only when the last record
 * for that signo is gone. The standard coalescing path (app_request_signal)
 * is unchanged — it sets the bit with no payload record (delivered SI_USER). */
#define SI_USER   0
#define SI_QUEUE  (-1)
#define SI_TIMER  (-2)
/* index of the OLDEST queued payload for `signo`, or -1 */
static int sigq_peek(struct app *a, int signo) {
    for (int i = 0; i < a->sigq_n; i++) if (a->sigq[i].signo == signo) return i;
    return -1;
}
/* remove entry `i`, shifting the tail down (keeps FIFO order, O(n), n<=32) */
static void sigq_drop(struct app *a, int i) {
    for (int j = i + 1; j < a->sigq_n; j++) a->sigq[j - 1] = a->sigq[j];
    a->sigq_n--;
}
/* Enqueue a payload-carrying signal onto a SPECIFIC app — shared by sigqueue
 * (code SI_QUEUE) and the POSIX timer tick (code SI_TIMER). Returns 0, or -1
 * (bad target/signo / not opted in / queue full). Job-control signals keep
 * their default action. */
static int app_sigqueue_to(struct app *t, int signo, uint64_t value, int code) {
    if (!t || signo <= 0 || signo >= APP_NSIG) return -1;
    if (signo == SIGCONT) { task_cont((task_t *)t->task); return 0; }
    if (signo == SIGSTOP || signo == SIGTSTP) { task_stop((task_t *)t->task); return 0; }
    int sigfd = t->sigfd_armed && (t->sigfd_mask & (1u << signo));
    if (!t->sig_handler[signo] && !sigfd) return -1;     /* not opted in -> ignored, like app_request_signal */
    if (t->sig_handler[signo]) {                          /* payload only matters for a handler */
        if (t->sigq_n >= APP_SIGQ_MAX) return -1;         /* queue full -> EAGAIN */
        t->sigq[t->sigq_n].signo = signo;
        t->sigq[t->sigq_n].code  = code;
        t->sigq[t->sigq_n].value = value;
        t->sigq_n++;
    }
    t->pending_sigs |= (1u << signo);                     /* mark pending; the queue holds the multiplicity */
    task_wake(t->task);
    return 0;
}
/* POSIX sigqueue(pid, signo, value): queue a signal carrying a payload. pid 0
 * = self. Returns 0/-1. */
int app_sigqueue(int pid, int signo, uint64_t value) {
    return app_sigqueue_to(pid ? app_by_pid(pid) : cur(), signo, value, SI_QUEUE);
}

/* --- POSIX per-process interval timers: timer_create(2) (M1272) ----------
 * Real timer objects (vs the single one-shot alarm/SIGALRM, M1102): each app
 * holds up to APP_NPTIMER timers, each firing a signal (carrying a sigval) via
 * the sigqueue FIFO when its deadline passes. app_timer_tick() runs on every
 * timer IRQ and scans ALL apps (not just cur(), unlike app_alarm_tick) so a
 * timer fires even while its owner is blocked — the firing wakes it. */
long app_timer_create(int signo, uint64_t value) {
    struct app *a = cur();
    if (!a || signo <= 0 || signo >= APP_NSIG) return -1;
    for (int i = 0; i < APP_NPTIMER; i++) {
        if (!a->ptimer[i].used) {
            a->ptimer[i].used = 1; a->ptimer[i].signo = signo; a->ptimer[i].value = value;
            a->ptimer[i].next_ms = 0; a->ptimer[i].interval_ms = 0;   /* created disarmed */
            return i;                                                 /* the timer id */
        }
    }
    return -1;                                                        /* out of timer slots */
}
/* arm/disarm timer `id`: value_ms 0 disarms; else fire after value_ms, then
 * every interval_ms (0 = one-shot). abs=1 => value_ms is an absolute
 * CLOCK_MONOTONIC-ms deadline (TIMER_ABSTIME). Returns 0/-1. */
long app_timer_settime(int id, int abs, uint64_t value_ms, uint64_t interval_ms) {
    struct app *a = cur();
    if (!a || id < 0 || id >= APP_NPTIMER || !a->ptimer[id].used) return -1;
    if (value_ms == 0) { a->ptimer[id].next_ms = 0; a->ptimer[id].interval_ms = 0; return 0; }
    a->ptimer[id].next_ms     = abs ? value_ms : timer_ms() + value_ms;
    a->ptimer[id].interval_ms = interval_ms;
    return 0;
}
/* remaining ms until timer `id` next fires (0 if disarmed), or -1 if bad id */
long app_timer_gettime(int id) {
    struct app *a = cur();
    if (!a || id < 0 || id >= APP_NPTIMER || !a->ptimer[id].used) return -1;
    if (!a->ptimer[id].next_ms) return 0;
    uint64_t now = timer_ms();
    return a->ptimer[id].next_ms > now ? (long)(a->ptimer[id].next_ms - now) : 0;
}
long app_timer_delete(int id) {
    struct app *a = cur();
    if (!a || id < 0 || id >= APP_NPTIMER || !a->ptimer[id].used) return -1;
    a->ptimer[id].used = 0; a->ptimer[id].next_ms = 0; a->ptimer[id].interval_ms = 0;
    return 0;
}
/* timer IRQ hook: fire every armed timer whose deadline has passed, on every
 * app (so it works regardless of who's currently scheduled). */
void app_timer_tick(void) {
    uint64_t now = timer_ms();
    for (int p = 0; p < MAX_APPS; p++) {
        struct app *a = &apps[p];
        if (!a->used) continue;
        for (int i = 0; i < APP_NPTIMER; i++) {
            if (!a->ptimer[i].used || !a->ptimer[i].next_ms) continue;
            if (now >= a->ptimer[i].next_ms) {
                app_sigqueue_to(a, a->ptimer[i].signo, a->ptimer[i].value, SI_TIMER);
                if (a->ptimer[i].interval_ms) a->ptimer[i].next_ms += a->ptimer[i].interval_ms;  /* periodic re-arm */
                else                          a->ptimer[i].next_ms = 0;                          /* one-shot: disarm */
            }
        }
    }
}

/* --- Job control: process groups, sessions, foreground TTY group (M1176) --- */
int app_setpgid(int pid, int pgid) {
    struct app *me = cur(); if (!me) return -1;
    struct app *t = pid ? app_by_pid(pid) : me;
    if (!t) return -1;
    t->pgid = pgid ? pgid : t->pid;        /* pgid 0 => the target leads its own group */
    return 0;
}
int app_getpgid(int pid) { struct app *t = pid ? app_by_pid(pid) : cur(); return t ? t->pgid : -1; }
int app_getsid(int pid)  { struct app *t = pid ? app_by_pid(pid) : cur(); return t ? t->sid : -1; }   /* (M1580) */
int app_setsid(void)     { struct app *me = cur(); if (!me) return -1; me->sid = me->pgid = me->pid; return me->sid; }
int app_tcsetpgrp(int pgid) { fg_pgid = pgid; return 0; }   /* set the foreground process group of the console */
int app_tcgetpgrp(void)     { return fg_pgid; }
/* Deliver `signo` to every app in process group `pgid` — POSIX killpg / kill(-pgid).
 * Returns the count signalled. (app_request_signal is a no-op for a signal the
 * target installed no handler for — the existing default; so a group member only
 * acts on it if it opted in, exactly like a single-process signal.) (M1176) */
int app_killpg(int pgid, int signo) {
    if (pgid <= 0) return -1;
    int n = 0;
    for (int i = 0; i < MAX_APPS; i++)
        if (apps[i].used && !apps[i].exited && apps[i].pgid == pgid) { app_request_signal(&apps[i], signo); n++; }
    return n;
}

#define SIGALRM 14
/* Arm/disarm a periodic SIGALRM for the calling app (M1102): every `ticks`
 * timer ticks, raise SIGALRM (delivered to a ring-3 handler via the same async
 * path as Ctrl-C). ticks==0 disarms. Composes SYS_signal (M1067) + the IRQ-tail
 * delivery (M1083) — no new delivery machinery. */
void app_set_alarm(uint64_t ticks) {
    struct app *a = cur();
    if (!a) return;
    a->alarm_interval = ticks;
    a->alarm_next = ticks ? timer_ticks() + ticks : 0;
}
/* Called from the timer IRQ: if the CURRENT app's alarm is due, raise SIGALRM
 * (a no-op if it never installed a handler). Checking cur() keeps it cheap —
 * an app times its own run while it is the one executing.
 * Gates on alarm_next (armed?), not alarm_interval (M1565): app_set_alarm
 * always pairs them (both zero or both nonzero), but setitimer's whole point
 * is a ONE-SHOT timer (nonzero delay, zero interval) -- gating on interval
 * would silently never fire it. On fire: a periodic timer (interval!=0)
 * advances to the next deadline; a one-shot (interval==0) disarms instead of
 * re-triggering on every subsequent tick forever (alarm_next += 0). */
void app_alarm_tick(void) {
    task_t *t = task_self();
    if (!t || !t->proc) return;                  /* before sched_init / a kernel task */
    struct app *a = (struct app *)t->proc;
    if (!a->alarm_next) return;
    if (timer_ticks() >= a->alarm_next) {
        a->alarm_next = a->alarm_interval ? a->alarm_next + a->alarm_interval : 0;
        app_request_signal(a, SIGALRM);          /* opt-in: only fires if a SIGALRM handler is installed */
    }
}
/* setitimer/getitimer(ITIMER_REAL) (M1565): the generalization app_set_alarm
 * never needed -- a delay to first fire INDEPENDENT of the repeat interval
 * (alarm()/app_set_alarm always force them equal). No `which` argument: this
 * codebase has no separate user/system-CPU-time itimer types to select
 * between, matching app_set_alarm's own no-`which` precedent. Ticks, not
 * seconds+microseconds, for the same reason -- alarm()'s own established
 * unit in this file, not real setitimer's struct itimerval shape. */
void app_setitimer(uint64_t delay_ticks, uint64_t interval_ticks) {
    struct app *a = cur();
    if (!a) return;
    if (!delay_ticks) { a->alarm_next = 0; a->alarm_interval = 0; return; }   /* it_value==0 -> disarm regardless of interval (real setitimer) */
    a->alarm_next = timer_ticks() + delay_ticks;
    a->alarm_interval = interval_ticks;   /* 0 = one-shot, matching real setitimer */
}
void app_getitimer(uint64_t *remain_ticks, uint64_t *interval_ticks) {
    struct app *a = cur();
    uint64_t now = a ? timer_ticks() : 0;
    if (remain_ticks)   *remain_ticks   = (a && a->alarm_next && a->alarm_next > now) ? a->alarm_next - now : 0;
    if (interval_ticks) *interval_ticks = a ? a->alarm_interval : 0;
}

#define SIGXCPU 25   /* real Linux uses 24, but that number is already SIGWINCH here (M1548) */
#define SIGXFSZ 26   /* real Linux uses 25, but that number is SIGXCPU here (M1549) */
/* Called from the timer IRQ: if the CURRENT task's own accumulated CPU time
 * (utime_ms+stime_ms, the same tick-sampled fields getrusage already reads)
 * has crossed its app's RLIMIT_CPU, raise SIGXCPU. Deliberately scoped to the
 * task that's actually running right now, like app_alarm_tick -- an app with
 * several cloned threads (M1138) gets each thread checked against the SAME
 * limit independently rather than a summed total, which is a simplification,
 * not the POSIX-exact semantics (that would need a running total kept on the
 * shared struct app instead of each task_t), but this is the honest, cheap
 * version and matches every other per-app CPU/fd accounting in this file. */
void app_cpulimit_tick(void) {
    task_t *t = task_self();
    if (!t || !t->proc) return;                  /* before sched_init / a kernel task */
    struct app *a = (struct app *)t->proc;
    if (!a->rlim_cpu) return;                     /* 0 = unlimited */
    if (t->utime_ms + t->stime_ms < a->rlim_cpu * 1000) return;
    if (timer_ticks() < a->cpulimit_next) return;
    /* Found via a real, reproduced livelock: utime_ms/stime_ms never go back
     * down once over the limit, so an unconditional re-request every tick (no
     * deadline advance, unlike app_alarm_tick's alarm_next) meant the signal
     * was still pending again by the time sigreturn's own syscall-return check
     * ran -- app_deliver_pending kept re-entering the handler before control
     * ever made it back to the interrupted C code that would've observed the
     * flag the handler set and exited its loop. Re-arming only once/second
     * (matching real POSIX SIGXCPU's own re-notify cadence once over the
     * soft limit) gives every delivery a full round trip to actually land. */
    a->cpulimit_next = timer_ticks() + 100;
    app_request_signal(a, SIGXCPU);
}

/* If the app this trap returns to has an async signal pending AND we're heading
 * back to ring-3 code (never mid-syscall), deliver it now. Called from the
 * syscall return and the IRQ tail. Returns 1 if a handler was entered. M1083. */
/* Arm a jail for the very next app_spawn (M1088): the child starts pledged to
 * `promises` and, if `path` is non-empty, unveil-confined to that prefix (rw) —
 * a parent-enforced sandbox the child can't escape (pledge only shrinks). */
void app_jail_next(uint32_t promises, const char *path) {
    g_jail_promises = promises;
    int i = 0; if (path) while (path[i] && i < 63) { g_jail_path[i] = path[i]; i++; }
    g_jail_path[i] = 0;
    g_pend_jail = 1;
}

/* strace (M1084): toggle/read whether an app's syscalls are logged to dmesg. */
void app_set_traced(app_t *a, int on) { struct app *ap = (struct app *)a; if (ap) ap->traced = on ? 1 : 0; }
int  app_is_traced(app_t *a)          { struct app *ap = (struct app *)a; return ap ? ap->traced : 0; }

int app_deliver_pending(struct registers *r) {
    task_t *t = task_self();                 /* called from the IRQ tail on EVERY irq, incl. before
                                              * sched_init (current==NULL) and on kernel tasks -> guard */
    if (!t || !t->proc) return 0;
    struct app *a = (struct app *)t->proc;
    if (!a->pending_sigs) return 0;
    if ((r->cs & 3) != 3) return 0;          /* resuming kernel code (mid-syscall) -> defer */
    /* deliver the lowest pending signal that has a handler (one per return, like
     * Linux); handler-less signals stay pending for signalfd to drain. */
    for (int sig = 1; sig < APP_NSIG; sig++) {
        if (!(a->pending_sigs & (1u << sig)) || !a->sig_handler[sig]) continue;
        if (a->sig_blocked & (1u << sig)) continue;   /* sigprocmask: blocked -> stays pending (M1208) */
        int qi = sigq_peek(a, sig);                   /* RT/sigqueue payload (M1271), or -1 = coalesced/no payload */
        a->sig_q_code  = (qi >= 0) ? a->sigq[qi].code  : SI_USER;
        a->sig_q_value = (qi >= 0) ? a->sigq[qi].value : 0;
        if (app_signal_deliver(r, sig)) {
            if (qi >= 0) sigq_drop(a, qi);            /* consumed one queued instance */
            if (sigq_peek(a, sig) < 0) a->pending_sigs &= ~(1u << sig);  /* clear the bit only when none remain -> the next queued instance delivers on the next return to ring 3 (RT queuing) */
            return 1;
        }
        return 0;                            /* couldn't deliver yet (already in a handler) -> stay pending */
    }
    return 0;                                /* only handler-less (signalfd) signals pending */
}

/* signalfd (M1126): route signals in `mask` to /proc/self/sigfd instead of a
 * handler. A read there returns the lowest such pending signo (blocking if none),
 * and it's fswait-ready when one is pending — signals as a file, composable with
 * the M1125 event loop. */
long app_signalfd(uint32_t mask) {
    struct app *a = cur();
    if (!a) return -1;
    a->sigfd_armed = 1;
    a->sigfd_mask |= mask;
    return 0;
}
static int sigfd_pick(struct app *a) {       /* lowest pending signal routed to sigfd, or 0 */
    for (int s = 1; s < APP_NSIG; s++)
        if ((a->pending_sigs & (1u << s)) && (a->sigfd_mask & (1u << s)) && !a->sig_handler[s]) return s;
    return 0;
}
int app_sigfd_ready(app_t *a) { return a && sigfd_pick((struct app *)a) != 0; }   /* fswait peek */
long app_sigfd_read(app_t *a, char *buf, int max) {
    struct app *ap = (struct app *)a;
    if (!ap || max < 3) return -1;
    int s;
    for (;;) {                                /* block until a sigfd signal is pending (woken by app_request_signal) */
        uint64_t f = irq_save();              /* pairs with app_request_signal's own lock (M1612) */
        s = sigfd_pick(ap);
        irq_restore(f);
        if (s != 0) break;
        task_block();
        if (!ap->used) return -1;             /* killed while parked */
    }
    ap->pending_sigs &= ~(1u << s);           /* consume it */
    int p = 0; char t[6]; int n = 0; int v = s;
    if (!v) t[n++] = '0'; while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
    while (n) buf[p++] = t[--n];
    buf[p++] = '\n'; buf[p] = 0;
    return p;
}

/* ---- graphics mode: a per-app pixel canvas the WM composites --------------
 * An app calls app_gfx_init(w,h) to swap its text grid for a w*h pixel canvas
 * (0x00RRGGBB), draws into a userspace buffer, and app_gfx_blit()s it across.
 * The window manager draws the canvas (sized to fit) instead of the grid. This
 * is what lets a real graphical program — DOOM — render to a window. */
#define GFX_MAX_W 1024
#define GFX_MAX_H 768

int app_gfx_init(int w, int h) {
    struct app *a = cur();
    if (!a || w <= 0 || h <= 0 || w > GFX_MAX_W || h > GFX_MAX_H) return -1;
    if (a->gfx && (a->gfx_w != w || a->gfx_h != h)) { kfree(a->gfx); a->gfx = 0; }
    if (!a->gfx) {
        a->gfx = kmalloc((size_t)w * (size_t)h * 4);
        if (!a->gfx) return -1;
    }
    a->gfx_w = w; a->gfx_h = h;
    for (int i = 0; i < w * h; i++) a->gfx[i] = 0;     /* start black */
    a->gdirty = 1;
    return 0;
}

/* Copy the caller's w*h pixel buffer into the canvas and mark the window dirty.
 * The source lives in the app's address space (CR3 is the app's during the
 * syscall) and is validated to be the app's own user pages before the read —
 * otherwise a forged kernel pointer would have the kernel copy its own memory
 * into the canvas and paint it on screen. The destination is exactly
 * gfx_w*gfx_h*4 (kernel-allocated), so it can't be overrun. 0, or -1. */
int app_gfx_blit(const uint32_t *pixels) {
    app_kill_check();                       /* WM close-request: exit before painting the next frame */
    struct app *a = cur();
    if (!a || !a->gfx) return -1;
    if (!vmm_user_ok((uint64_t)pixels, (uint64_t)a->gfx_w * (uint64_t)a->gfx_h * 4)) return -1;
    memcpy(a->gfx, pixels, (size_t)a->gfx_w * (size_t)a->gfx_h * 4);
    a->gdirty = 1;
    return 0;
}

/* WM: the app's canvas + dims (1 if in graphics mode, else 0). */
int app_gfx_get(app_t *a, uint32_t **buf, int *w, int *h) {
    if (!a || !a->gfx) return 0;
    *buf = a->gfx; *w = a->gfx_w; *h = a->gfx_h;
    return 1;
}

/* ---- raw keyboard mode (games) ----
 * In raw mode the WM routes make/break key events (scancode + pressed/released
 * + extended) to this app instead of, or alongside, the cooked ASCII it still
 * gets. DOOM needs key-down AND key-up for held movement/fire. */
void app_set_rawkb(int on) { struct app *a = cur(); if (a) a->rawkb = on ? 1 : 0; }
/* SYS_caret: a full-screen text app that draws its own cursor (e.g. the editor)
 * opts out of the system block caret so the two don't both show. */
void app_set_caret(int on) { struct app *a = cur(); if (a) a->caret_off = on ? 0 : 1; }
int  app_caret_hidden(app_t *a) { return a && a->caret_off; }   /* WM: full-screen self-drawing app? */
int  app_get_rawkb(app_t *a) { return a && a->rawkb; }

/* ---- text selection + paste (driven by the WM's mouse handling) ---------- */
static int clampc(int v, int hi) { return v < 0 ? 0 : (v > hi ? hi : v); }

void app_sel_begin(app_t *a, int row, int col) {
    if (!a) return;
    a->sel_r0 = a->sel_r1 = clampc(row, a->rows - 1);
    a->sel_c0 = a->sel_c1 = clampc(col, a->cols);
    a->sel_on = 1; a->gdirty = 1;
}
void app_sel_extend(app_t *a, int row, int col) {
    if (!a || !a->sel_on) return;
    a->sel_r1 = clampc(row, a->rows - 1);
    a->sel_c1 = clampc(col, a->cols);
    a->gdirty = 1;
}
void app_sel_clear(app_t *a) { if (a && a->sel_on) { a->sel_on = 0; a->gdirty = 1; } }

/* Scroll so the scrollbar thumb sits at fraction num/den down its track (0 =
 * top = oldest scrollback, den = bottom = live). For click/drag on the bar. */
void app_scroll_frac(app_t *a, int num, int den) {
    if (!a || den <= 0) return;
    if (num < 0) num = 0;
    if (num > den) num = den;
    int v = a->sb_count * (den - num) / den;            /* top of track -> view = sb_count */
    if (v < 0) v = 0;
    if (v > a->sb_count) v = a->sb_count;
    if (v != a->view) { a->view = v; a->gdirty = 1; }
}

/* Double-click: select the whitespace-delimited word at (row,col) and copy it. */
void app_sel_word(app_t *a, int row, int col) {
    if (!a || row < 0 || row >= a->rows) return;
    if (col < 0) col = 0;
    if (col >= a->cols) col = a->cols - 1;
    if (app_cell(a, row, col) == ' ') { app_sel_clear(a); return; }   /* clicked whitespace */
    int s = col, e = col;
    while (s > 0 && app_cell(a, row, s - 1) != ' ') s--;
    while (e < a->cols - 1 && app_cell(a, row, e + 1) != ' ') e++;
    a->sel_r0 = a->sel_r1 = row; a->sel_c0 = s; a->sel_c1 = e + 1;
    a->sel_on = 1; a->gdirty = 1;
    app_sel_commit(a);                                  /* -> clipboard */
}

/* Release: extract the selected cells (trailing spaces trimmed per line, rows
 * joined with '\n') into the clipboard. The highlight stays until next input. */
void app_sel_commit(app_t *a) {
    if (!a || !a->sel_on) return;
    if (a->sel_r0 == a->sel_r1 && a->sel_c0 == a->sel_c1) {   /* a plain click, not a drag */
        app_sel_clear(a); return;                             /* clear highlight, keep the clipboard */
    }
    int r0, c0, r1, c1; sel_ordered(a, &r0, &c0, &r1, &c1);
    char buf[CLIP_MAX]; int n = 0;
    for (int r = r0; r <= r1 && r < a->rows && n < CLIP_MAX - 1; r++) {
        if (r < 0) continue;
        int cs = (r == r0) ? c0 : 0, ce = (r == r1) ? c1 : a->cols;
        int lineend = n;
        for (int c = cs; c < ce && c < a->cols && n < CLIP_MAX - 1; c++) {
            char ch = app_cell(a, r, c);
            buf[n++] = ch;
            if (ch != ' ') lineend = n;          /* remember last non-blank for trimming */
        }
        n = lineend;                              /* trim trailing spaces */
        if (r < r1 && n < CLIP_MAX - 1) buf[n++] = '\n';
    }
    clip_set(buf, n);
}

/* Middle-click paste: feed the clipboard into the app's input queue as if typed
 * (newlines included — for a shell, a multi-line paste runs each line). */
void app_paste(app_t *a) {
    if (!a) return;
    a->paste_len = 0;                                    /* stop any in-flight drain before we refill */
    int n = clip_get(a->pastebuf, sizeof a->pastebuf);   /* fill the app's paste buffer... */
    a->paste_pos = 0;
    a->paste_len = n;                                    /* ...set last so iq_get sees a complete buffer */
    if (a->view) { a->view = 0; a->gdirty = 1; }         /* a paste returns to the live view */
    task_wake(a->task);                                  /* unblock it if waiting in read() */
}

/* WM: deliver one raw key event to a raw-mode app's queue. */
void app_key_raw(app_t *a, unsigned short ev) {
    int n = (a->rqh + 1) % 64;
    if (n != a->rqt) { a->rawiq[a->rqh] = ev; a->rqh = n; }   /* drop on overflow */
}

/* WM: store the cursor position (relative to the gfx canvas; -1,-1 if outside)
 * and button bitmask for an app, each frame, for the focused window. */
void app_set_mouse(app_t *a, int x, int y, int btn) {
    if (!a) return;
    a->ms_x = x; a->ms_y = y; a->ms_btn = btn;
}

/* SYS_mouse: pack the caller's last cursor state — x in bits 0-15 (signed),
 * y in 16-31, buttons in 32-34. ulib unpacks it. */
long app_get_mouse(void) {
    struct app *a = cur();
    if (!a) return 0;
    return ((long)(a->ms_btn & 0x7) << 32)
         | ((long)(a->ms_y & 0xFFFF) << 16)
         | ((long)(a->ms_x & 0xFFFF));
}

/* WM: accumulate relative mouse motion for an app (mouselook). */
void app_add_mouse_rel(app_t *a, int dx, int dy) {
    if (!a) return;
    a->ms_dx += dx; a->ms_dy += dy;
}

/* SYS_mouse_rel: the caller's accumulated relative motion, read + cleared.
 * dx in bits 0-31, dy in bits 32-63 (both signed). */
long app_get_mouse_rel(void) {
    struct app *a = cur();
    if (!a) return 0;
    int dx = a->ms_dx, dy = a->ms_dy;
    a->ms_dx = 0; a->ms_dy = 0;
    return ((long)(uint32_t)dy << 32) | (long)(uint32_t)dx;
}

/* SYS_getkbevent: next raw key event for the caller, or -1 if none (non-blocking). */
int app_sys_getkbevent(void) {
    struct app *a = cur();
    if (!a || a->rqh == a->rqt) return -1;
    unsigned short ev = a->rawiq[a->rqt];
    a->rqt = (a->rqt + 1) % 64;
    return (int)ev;
}

int  app_sys_getpid(void) { return cur()->pid; }
int  app_sys_getppid(void) { struct app *a = cur(); return a ? a->parent : 0; }   /* parent pid (M1236) */
void app_sys_clear(void)  { grid_clear(cur()); }
void app_setcolor(int idx) { struct app *a = cur(); if (a) a->curcol = (uint8_t)(idx & 15); }
void app_sys_exit(int code) { struct app *a = cur(); a->exit_code = code; a->exited = 1; task_exit(); }
/* --- ELF core dump (M1104) -------------------------------------------------
 * When a ring-3 app dies on an unhandled fault, write an ET_CORE ELF to
 * /tmp/core capturing its registers (a PT_NOTE/NT_PRSTATUS) and its writable
 * memory (a PT_LOAD per region: active stack, heap, each mmap). The post-mortem
 * complement to the kernel panic backtrace (M1078) — and a real, host-gdb-
 * loadable artifact. Built in one kheap buffer then written to tmpfs (RAM, so
 * the write is safe with interrupts off in the fault path); reads each page via
 * vmm_translate + the HHDM, zero-filling any demand-paged hole, so it never
 * faults while dumping. */
#define CORE_MAX (2u * 1024 * 1024)
static void cd_p16(uint8_t *b, uint16_t v) { b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8); }
static void cd_p32(uint8_t *b, uint32_t v) { for (int i = 0; i < 4; i++) b[i] = (uint8_t)(v >> (8 * i)); }
static void cd_p64(uint8_t *b, uint64_t v) { for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i)); }

void app_core_dump(struct registers *r) {
    task_t *t = task_self();
    struct app *a = t ? (struct app *)t->proc : 0;
    if (!a || !r) return;

    struct { uint64_t va, len; } reg[2 + APP_MAXVMA]; int nreg = 0;
    uint64_t sp = r->rsp & ~(uint64_t)(PAGE_SIZE - 1);          /* active stack: from the faulting RSP up to the top */
    uint64_t stop = USTACK_BASE + (uint64_t)USTACK_PAGES * PAGE_SIZE;
    if (sp >= USTACK_BASE && sp < stop) { reg[nreg].va = sp; reg[nreg].len = stop - sp; nreg++; }
    if (a->heap_end > UHEAP_BASE) { reg[nreg].va = UHEAP_BASE; reg[nreg].len = a->heap_end - UHEAP_BASE; nreg++; }
    for (int i = 0; i < a->nvma && nreg < (int)(sizeof reg / sizeof reg[0]); i++) {
        reg[nreg].va = a->vma[i].start; reg[nreg].len = a->vma[i].len; nreg++;
    }

    /* RLIMIT_CORE (M1551): an ADDITIONAL cap on top of the existing CORE_MAX
     * ceiling, not a replacement for it -- same "0 = unlimited" convention
     * every other rlimit in this file uses (real POSIX's own literal-0-means-
     * "no dump at all" special case is NOT implemented; this governs dump
     * SIZE truncation only, an honest, scoped simplification like several
     * others in this codebase). A limit above CORE_MAX has no effect. */
    uint64_t core_cap = (a->rlim_core && a->rlim_core < CORE_MAX) ? a->rlim_core : CORE_MAX;
    const int NOTESZ = 12 + 8 + 336;                            /* nhdr + "CORE\0\0\0\0" + prstatus(336) */
    int phnum = 1 + nreg;
    uint64_t off_note = 64 + (uint64_t)phnum * 56;
    uint64_t off_data = off_note + NOTESZ;
    uint64_t total = off_data; for (int i = 0; i < nreg; i++) total += reg[i].len;
    if (total > core_cap) {                                     /* too big: keep just the stack */
        nreg = (nreg >= 1) ? 1 : 0; phnum = 1 + nreg;
        off_note = 64 + (uint64_t)phnum * 56; off_data = off_note + NOTESZ;
        total = off_data + (nreg ? reg[0].len : 0);
        if (total > core_cap) return;
    }
    uint8_t *buf = kzalloc(total);     /* zeroed: demand-paged holes stay zero in the core */
    if (!buf) return;

    /* ELF64 header (ET_CORE, x86-64) */
    buf[0] = 0x7F; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    buf[4] = 2; buf[5] = 1; buf[6] = 1;                         /* 64-bit, little-endian, v1 */
    cd_p16(buf + 16, 4);    cd_p16(buf + 18, 62);               /* e_type=ET_CORE, e_machine=EM_X86_64 */
    cd_p32(buf + 20, 1);    cd_p64(buf + 32, 64);               /* e_version, e_phoff */
    cd_p16(buf + 52, 64);   cd_p16(buf + 54, 56);               /* e_ehsize, e_phentsize */
    cd_p16(buf + 56, (uint16_t)phnum);                          /* e_phnum */

    /* PT_NOTE program header (entry 0) */
    uint8_t *ph = buf + 64;
    cd_p32(ph + 0, 4);                                          /* PT_NOTE */
    cd_p64(ph + 8, off_note); cd_p64(ph + 32, NOTESZ);          /* p_offset, p_filesz */
    /* PT_LOAD per region */
    uint64_t doff = off_data;
    for (int i = 0; i < nreg; i++) {
        uint8_t *p = buf + 64 + (uint64_t)(1 + i) * 56;
        cd_p32(p + 0, 1);  cd_p32(p + 4, 6);                    /* PT_LOAD, flags=RW */
        cd_p64(p + 8, doff); cd_p64(p + 16, reg[i].va);         /* p_offset, p_vaddr */
        cd_p64(p + 32, reg[i].len); cd_p64(p + 40, reg[i].len); /* p_filesz, p_memsz */
        cd_p64(p + 48, PAGE_SIZE);                              /* p_align */
        doff += reg[i].len;
    }

    /* PT_NOTE contents: NT_PRSTATUS with the GP registers at offset 112 */
    uint8_t *n = buf + off_note;
    cd_p32(n + 0, 5); cd_p32(n + 4, 336); cd_p32(n + 8, 1);     /* namesz, descsz, type=NT_PRSTATUS */
    n[12] = 'C'; n[13] = 'O'; n[14] = 'R'; n[15] = 'E';         /* name (padded to 8) */
    uint8_t *pr = n + 20 + 112;                                /* user_regs_struct within prstatus */
    uint64_t gp[27] = { r->r15, r->r14, r->r13, r->r12, r->rbp, r->rbx, r->r11, r->r10,
                        r->r9, r->r8, r->rax, r->rcx, r->rdx, r->rsi, r->rdi, r->rax /*orig_rax*/,
                        r->rip, r->cs, r->rflags, r->rsp, r->ss, 0, 0, 0, 0, 0, 0 };
    for (int i = 0; i < 27; i++) cd_p64(pr + i * 8, gp[i]);

    /* region bytes, page by page (real bytes if mapped, else left zero) */
    for (int i = 0; i < nreg; i++) {
        uint64_t fo = off_data; for (int k = 0; k < i; k++) fo += reg[k].len;   /* this region's file offset */
        uint8_t *dst = buf + fo;
        for (uint64_t o = 0; o < reg[i].len; o += PAGE_SIZE) {
            uint64_t phys = vmm_translate(reg[i].va + o);
            if (!phys) continue;                               /* demand-paged hole -> stays zero */
            uint8_t *src = (uint8_t *)hhdm(phys);
            uint64_t n2 = reg[i].len - o; if (n2 > PAGE_SIZE) n2 = PAGE_SIZE;
            for (uint64_t b = 0; b < n2; b++) dst[o + b] = src[b];
        }
    }

    tmpfs_write("core", buf, total);                           /* -> /tmp/core */
    kfree(buf);
    kprintf("[core] wrote /tmp/core (%lu bytes) for pid %d at rip=%p\n",
            (unsigned long)total, a->pid, (void *)r->rip);
}

/* A ring-3 task hit a CPU exception (divide error, page fault, …). Write a core
 * dump, mark its app exited so the WM tears down the window, then terminate just
 * this task — the kernel and the rest of the desktop keep running. No return. */
void app_fault_current(struct registers *r) {
    struct app *a = (struct app *)task_self()->proc;
    if (a && r) app_core_dump(r);
    if (a) {
        a->exited = 1;
        /* 128 + SIGSEGV, the shell's convention for "killed by a signal".
         * exit_code was left at its memset-0 value, so a process that DIED on
         * a fault reported SUCCESS to anything that waited on it -- which is
         * how a crashed `as` came back as "as --version -> 0". (M1956) */
        a->exit_code = 139;
    }
    task_exit();
}

/* --- OOM killer (M1275) ---------------------------------------------------
 * Under memory pressure, survive by terminating the worst memory hog rather
 * than failing/panicking. score = RSS pages + oom_adj bias (oom_adj <= -1000
 * = OOM-protected, never chosen). The kill is COOPERATIVE — exactly the WM
 * close-button path: we set the victim's `kill` flag and wake it, and it
 * self-exits at its next syscall/fault boundary (app_reap then frees its
 * frames). No risky synchronous cross-address-space teardown. */
static long oom_score(struct app *a) {
    if (!a || !a->used || a->exited || a->zombie) return -1;
    if (a->oom_adj <= -1000) return -1;                   /* OOM-protected */
    vmm_wss_t w; vmm_wss(a->cr3, &w);
    return (long)w.resident + (long)a->oom_adj * 256;     /* RSS pages + adj bias */
}
/* Pick the highest-scoring app other than the caller and cooperatively kill it.
 * Returns the victim's pid, or -1 if there's nothing eligible to reap. */
int app_oom_kill(void) {
    struct app *me = cur();
    struct app *victim = 0; long best = -1;
    for (int i = 0; i < MAX_APPS; i++) {
        struct app *a = &apps[i];
        if (a == me) continue;                            /* never the caller */
        long s = oom_score(a);
        if (s > best) { best = s; victim = a; }
    }
    if (!victim) return -1;
    victim->kill = 1;                                     /* cooperative terminate */
    if (victim->task) task_wake((task_t *)victim->task);  /* unblock it so it notices + exits */
    kprintf("[oom] reclaiming memory: killed pid %d (score %ld pages)\n", victim->pid, best);
    return victim->pid;
}
/* SYS_oom multiplexer: cmd 0 = set the caller's oom_adj to `arg`; cmd 1 = invoke
 * the OOM killer now (sysrq-f style), returns the killed pid; cmd 2 = the
 * oom_score of pid `arg`. */
long app_oom(int cmd, int arg) {
    struct app *a = cur(); if (!a) return -1;
    if (cmd == 0) { a->oom_adj = arg; return 0; }
    if (cmd == 1) return app_oom_kill();
    if (cmd == 2) { struct app *t = app_by_pid(arg); return t ? oom_score(t) : -1; }
    return -1;
}
/* /proc/<pid>/oom_score accessor (M1277): the OOM score of an arbitrary app. */
long app_oom_score_of(app_t *a) { return oom_score((struct app *)a); }
/* /proc/<pid>/oom_score_adj accessors (M1282): the tunable victim bias (rw). */
int  app_oom_adj_get(app_t *a) { struct app *p = (struct app *)a; return p ? p->oom_adj : 0; }
void app_oom_adj_set(app_t *a, int v) { struct app *p = (struct app *)a; if (p) { if (v < -1000) v = -1000; if (v > 1000) v = 1000; p->oom_adj = v; } }

/* Format the caller's command history (oldest first) as "  N  command\n"
 * lines into buf. Returns bytes written (excluding the NUL terminator). The
 * history ring is the same one up/down-arrow recall uses (app_sys_read). */
int app_sys_history(char *buf, int max) {
    if (max <= 0) return 0;
    struct app *a = cur();
    int p = 0;
    for (int i = 0; i < a->hist_n; i++) {
        const char *h = a->hist[i];
        char line[112];
        int q = 0;
        line[q++] = ' '; line[q++] = ' ';
        int v = i + 1; char num[4]; int k = 0;
        do { num[k++] = (char)('0' + v % 10); v /= 10; } while (v && k < 4);
        while (k) line[q++] = num[--k];
        line[q++] = ' '; line[q++] = ' ';
        for (int j = 0; h[j] && q < (int)sizeof(line) - 1; j++) line[q++] = h[j];
        line[q++] = '\n';
        for (int j = 0; j < q && p + 1 < max; j++) buf[p++] = line[j];
    }
    buf[p < max ? p : max - 1] = 0;
    return p;
}

/* ---- spawn ---- */
static void app_trampoline(void) {
    task_finish_switch();   /* complete whoever we just preempted (M1531) — see task.h */
    struct app *a = cur();
    enter_user(a->entry, a->ustack);   /* -> ring 3; returns only via SYS_exit */
}

/* Add a VMA directly, WITHOUT the [MMAP_BASE, MMAP_TOP) window check that
 * app_mmap* enforces. That window exists for the mmap ALLOCATOR, which picks
 * addresses; an executable's segments live at ELF_DYN_BASE, far below it, and
 * are placed by the image itself. Returns 1/0. (M1956) */
static int app_vma_add_mapped(struct app *a, const char *path, uint64_t addr, uint64_t len,
                              uint64_t foff, uint64_t fvalid, int prot) {
    if (!a || !len || a->nvma >= APP_MAXVMA) return 0;
    VMA_NEW(a);
    a->vma[a->nvma].start = addr;
    a->vma[a->nvma].len   = len;
    a->vma[a->nvma].prot  = (uint8_t)(prot & 0x7);
    if (path) {
        a->vma[a->nvma].file_backed = 1;
        a->vma[a->nvma].foff = foff;
        a->vma[a->nvma].fvalid = fvalid;
        int i = 0; for (; path[i] && i < 255; i++) a->vma[a->nvma].fpath[i] = path[i];
        a->vma[a->nvma].fpath[i] = 0;
        if (path[i]) return 0;               /* refuse a truncated path (M1955) */
    }
    a->nvma++;
    return 1;
}

/* Place a dynamically-linked executable's PT_LOADs as demand-paged mappings,
 * reading only its header. Returns the entry point (biased), or 0.
 *
 * The whole point is that nothing but the ELF header is read at spawn time:
 * pages arrive on first touch, from the file, so the resident cost is what the
 * program actually executes rather than its size on disk. (M1956) */
static uint64_t app_load_mapped(struct app *a, const char *path, const void *hdr, uint64_t hdrsz, uint64_t imgsz) {
    elf_pt_load_t segs[8];
    unsigned long entry = 0, phoff = 0, bias = 0; unsigned phent = 0, phnum = 0;
    int n = elf_pt_loads(hdr, hdrsz, imgsz, segs, 8, &entry, &bias, &phoff, &phent, &phnum);
    if (n <= 0) { kprintf("[mapload] %s: elf_pt_loads -> %d (hdrsz=%lu imgsz=%lu)\n", path, n, hdrsz, imgsz); return 0; }
    for (int i = 0; i < n; i++) {
        uint64_t va = bias + segs[i].vaddr;
        /* A file mapping can only express a segment whose in-page offset
         * matches the file's. Every real toolchain uses p_align >= 4096, so
         * this holds; refusing is the honest answer if it ever does not. */
        if ((va & (PAGE_SIZE - 1)) != (segs[i].file_off & (PAGE_SIZE - 1))) { kprintf("[mapload] seg %d: va %lx vs off %lx misaligned\n", i, va, segs[i].file_off); return 0; }
        uint64_t vstart = va & ~(uint64_t)(PAGE_SIZE - 1);
        uint64_t fstart = segs[i].file_off & ~(uint64_t)(PAGE_SIZE - 1);
        uint64_t fend = (va + segs[i].filesz + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
        uint64_t mend = (va + segs[i].memsz  + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
        /* p_flags: PF_X=1, PF_W=2, PF_R=4 (elf.c keeps its own copies private) */
        int prot = ((segs[i].flags & 0x4) ? VMA_PROT_READ  : 0)
                 | ((segs[i].flags & 0x2) ? VMA_PROT_WRITE : 0)
                 | ((segs[i].flags & 0x1) ? VMA_PROT_EXEC  : 0);
        if (!prot) prot = VMA_PROT_READ;
        if (fend > vstart) {
            /* fvalid stops the file read at filesz: the last page of a data
             * segment holds real bytes up to filesz and .bss after it, and the
             * file does NOT end there -- without the limit, .bss would start
             * out holding whatever follows the segment in the file. */
            uint64_t fvalid = (va - vstart) + segs[i].filesz;
            if (!app_vma_add_mapped(a, path, vstart, fend - vstart, fstart, fvalid, prot)) { kprintf("[mapload] seg %d: vma add failed (nvma=%d)\n", i, a->nvma); return 0; }
        }
        if (mend > fend)                     /* the whole-page .bss tail: anonymous, demand-zero */
            if (!app_vma_add_mapped(a, 0, fend, mend - fend, 0, 0, prot)) return 0;
    }
    return bias + entry;
}

app_t *app_spawn(const void *elf, const char *title, uint64_t elfsz) {
    struct app *a = 0;
    for (int i = 0; i < MAX_APPS; i++) if (!apps[i].used) { a = &apps[i]; break; }
    if (!a || !elf) return 0;

    memset(a, 0, sizeof(*a));
    a->used = 1;
    a->pid = next_pid++;
    a->pgid = a->sid = a->pid;           /* a spawned app leads its own group + session (M1176) */
    /* copy the title into our own buffer (the caller's string — e.g. a filename
     * from another address space — may not outlive this call). Done here, before
     * the CR3 switch below, while the caller's pointer is still valid. */
    int ti = 0; if (title) while (title[ti] && ti < 23) { a->titlebuf[ti] = title[ti]; ti++; }
    a->titlebuf[ti] = 0;
    a->title = a->titlebuf;
    int ei = 0; if (title) while (title[ei] && ei < 63) { a->exe_path[ei] = title[ei]; ei++; }  /* untruncated exe path (M1250) */
    a->exe_path[ei] = 0;
    /* Measured boot (M1096): fold this app's exact ELF image into PCR1 + the
     * event log, in launch order. `elf` is kernel-accessible here (embedded
     * .rodata or a kernel read buffer), before the CR3 switch below. */
    measure_extend(PCR_APPS, elf, elf_image_size(elf, elfsz), a->title);
    if (g_have_pend) {                    /* consume a pending launch arg (one-shot, race-free) */
        int ai = 0; while (g_pend_arg[ai] && ai < 127) { a->launch_arg[ai] = g_pend_arg[ai]; ai++; }
        a->launch_arg[ai] = 0; g_have_pend = 0;
    }
    if (g_pend_jail) {                    /* consume a pending jail: confine the child before it runs (M1088) */
        a->promises = g_jail_promises; a->pledged = 1;
        if (g_jail_path[0]) {
            int pi = 0; while (g_jail_path[pi] && pi < (int)sizeof a->uv[0].path - 1) { a->uv[0].path[pi] = g_jail_path[pi]; pi++; }
            a->uv[0].path[pi] = 0; a->uv[0].perms = UV_R | UV_W; a->nuv = 1; a->uv_active = 1;
        }
        g_pend_jail = 0;
    }
    int take_linux = g_pend_linux;        /* consume before the CR3 switch, like the two above */
    g_pend_linux = 0;
    char mappath[VFS_PATH_MAX];           /* likewise one-shot: copy it out before anything can re-enter */
    { int mi = 0; while (g_pend_mappath[mi] && mi < VFS_PATH_MAX - 1) { mappath[mi] = g_pend_mappath[mi]; mi++; }
      mappath[mi] = 0; g_pend_mappath[0] = 0; }
    grid_clear(a);
    a->cr3 = vmm_create_address_space();
    if (!a->cr3) { a->used = 0; return 0; }   /* OOM: no address space — loading CR3=0 would triple-fault */
    vdso_map(a->cr3);                         /* map the read-only vDSO time page into this space (M1111) */

    /* Load the ELF + user stack into the app's address space. We switch CR3 to
     * it (interrupts off) so the loader's writes land in the right space. */
    uint64_t flags;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(flags) :: "memory");
    uint64_t old;
    __asm__ volatile("mov %%cr3, %0" : "=r"(old));
    __asm__ volatile("mov %0, %%cr3" : : "r"(a->cr3) : "memory");

    elf_lazy_range_t lazy[4]; int nlazy = 0;
    if (mappath[0]) a->entry = app_load_mapped(a, mappath, elf, elfsz, g_pend_mapsize);
    else            a->entry = elf_load(elf, elfsz, lazy, 4, &nlazy);
    if (!a->entry) goto fail_in_space;       /* bad ELF: don't spawn a null task */
    /* Register each deferred whole-BSS range as a demand-zero VMA (a->nvma is
     * 0 here — freshly memset above) so its pages are lazily allocated+zeroed
     * on first touch by app_fault_handle instead of all at spawn time; a large
     * static arena (e.g. the JS engine's, several MB) is mapped once actual
     * code reaches into it, not up front for a page count most runs never
     * fully use. Same effective permissions either way (writable, non-exec —
     * enforced by elf_load only ever deferring !PF_X segments). */
    for (int li = 0; li < nlazy && a->nvma < APP_MAXVMA; li++) {
        VMA_NEW(a);
        a->vma[a->nvma].start = lazy[li].start; a->vma[a->nvma].len = lazy[li].len;
        a->vma[a->nvma].sealed = 0; a->vma[a->nvma].uffd = 0;
        a->vma[a->nvma].file_backed = 0; a->vma[a->nvma].locked = 0; a->vma[a->nvma].huge = 0;
        a->nvma++;
    }

    for (int i = 1; i < USTACK_PAGES; i++) {   /* i=0 (USTACK_BASE) left unmapped: a guard page below the user stack (M1499) */
        uint64_t frame = pmm_alloc_frame();  /* stack: non-executable (W^X) */
        if (!frame) goto fail_in_space;      /* OOM: reclaim the partial space below */
        if (vmm_map(USTACK_BASE + (uint64_t)i * PAGE_SIZE, frame,
                    PTE_WRITABLE | PTE_USER | PTE_NX) != 0) {
            pmm_free_frame(frame);
            goto fail_in_space;
        }
    }
    a->ustack = USTACK_BASE + USTACK_PAGES * PAGE_SIZE;
    uint64_t prog_entry = a->entry;          /* auxv AT_ENTRY: the EXECUTABLE's entry, even when the interpreter runs first (M1954) */

    /* A Linux binary reads argc/argv/envp/auxv off its stack before main, so
     * build the frame HERE -- while the new address space is still active and
     * its stack pages are mapped -- and start it at the frame instead of at a
     * bare stack top. (M1940) */
    if (take_linux) {
        /* Start it INSIDE its own root. A Linux process sees /disk2 as "/",
         * and a relative path is the one thing the ABI cannot translate --
         * so without this, "./out.s" lands on the boot volume or nowhere at
         * all. gcc creates its intermediate .s exactly that way. (M1960) */
        vfs_cwd_set_for(a, "/disk2");
        { const char *r = "/disk2"; int k = 0; while (r[k]) { a->cwd_path[k] = r[k]; k++; } a->cwd_path[k] = 0; }
        static const char *argv0[2 + LX_PEND_ARGS], *envp0[4];
        /* argv[0] is what the PROGRAM sees, so strip the /disk2 mount prefix:
         * inside a Linux process that volume IS the root, and a program that
         * re-execs itself by argv[0] (lxbox does) would otherwise ask for
         * /disk2/disk2/... (M1954) */
        argv0[0] = g_pend_lxpath;
        { const char *pre = "/disk2"; int k = 0;
          while (pre[k] && g_pend_lxpath[k] == pre[k]) k++;
          if (!pre[k] && g_pend_lxpath[k] == '/') argv0[0] = g_pend_lxpath + k; }
        /* The native one-shot launch arg (g_pend_arg, consumed into
         * a->launch_arg above) becomes argv[1] for a Linux binary -- that is
         * how a multi-call binary is told which applet to be. */
        int an = 1;
        for (int i = 0; i < g_pend_lxargc && an < 1 + LX_PEND_ARGS; i++) argv0[an++] = g_pend_lxargs[i];
        if (an == 1 && a->launch_arg[0]) argv0[an++] = a->launch_arg;
        argv0[an] = 0;
        g_pend_lxargc = 0;                   /* one-shot: never leak into a later spawn */
        envp0[0] = "PATH=/bin:/usr/bin"; envp0[1] = "HOME=/"; envp0[2] = "TERM=osdev"; envp0[3] = 0;
        /* Dynamically linked? Map the interpreter too and enter IT: a
         * dynamically-linked program cannot be started directly, ld.so has to
         * map its shared libraries first and only then jump to the entry. */
        uint64_t interp_base = 0;
        if (g_pend_interp) {
            uint64_t ie = elf_load_at(g_pend_interp, g_pend_interp_sz, ELF_INTERP_BASE);
            if (!ie) goto fail_in_space;
            interp_base = ELF_INTERP_BASE;
            a->entry = ie;                   /* the INTERPRETER runs first */
        }
        uint64_t rsp = lx_spawn_stack_dyn(elf, ELF_DYN_BASE, prog_entry, interp_base,
                                          a->ustack, USTACK_BASE + PAGE_SIZE, argv0, envp0);
        if (!rsp) goto fail_in_space;        /* stack too small for the frame */
        a->ustack = rsp;
    }

    a->aslr_mmap_base = aslr_mmap_pick(); a->mmap_next = a->aslr_mmap_base;   /* ASLR: randomize the mmap region start (M1287) */

    __asm__ volatile("mov %0, %%cr3" : : "r"(old) : "memory");
    __asm__ volatile("push %0; popfq" : : "r"(flags) : "memory", "cc");

    /* 256 KB kernel stack (vs the 16 KB default): a ring-3 app's syscalls run on
     * its kernel stack, and SYS_https (shell get/wget) runs the TLS handshake +
     * bignum/RSA/ECDSA cert verification there — which overflows a small stack. */
    a->task = task_create_stack(app_trampoline, a->cr3, a, 256 * 1024);
    if (!a->task) {                          /* couldn't create the task (OOM): don't queue a taskless app */
        vmm_destroy_address_space(a->cr3);   /* CR3 already restored to `old` above, so this is safe */
        a->used = 0;
        return 0;
    }

    /* queue it for the window manager to give it a window */
    int n = (pend_h + 1) % MAX_APPS;
    if (n != pend_t) { pending[pend_h] = a; pend_h = n; }
    g_last_spawn_pid = a->pid;           /* so a kernel-context caller can wait for it (M1955) */
    return a;

fail_in_space:
    /* A failure while the app's CR3 was active (bad ELF, or OOM mapping the
     * stack). Restore the caller's CR3 first, THEN tear down the partial address
     * space — vmm_destroy_address_space refuses to free the active space, and
     * leaving it mapped would leak the PML4/PDPT + every frame elf_load mapped. */
    __asm__ volatile("mov %0, %%cr3" : : "r"(old) : "memory");
    __asm__ volatile("push %0; popfq" : : "r"(flags) : "memory", "cc");
    vmm_destroy_address_space(a->cr3);
    a->used = 0;
    return 0;
}

/* The kernel-thread entry for a forked child: resume ring 3 from the trap frame
 * we cloned from the parent at fork time (rax = 0). Never returns — it iretq's
 * into userspace, and the child later exits via the normal task_exit path. */
static void fork_child_trampoline(void) {
    task_finish_switch();   /* complete whoever we just preempted (M1531) — see task.h */
    struct app *a = cur();
    iret_to_user(&a->fork_frame);
}

/* A thread's entry (M1138): iret into ring 3 at the frame app_clone built (which
 * starts it at fn(arg) on its own stack, in the SHARED address space), then free
 * that frame. Never returns; the thread ends via SYS_thread_exit -> task_exit. */
static void thread_trampoline(void) {
    task_finish_switch();   /* complete whoever we just preempted (M1531) — see task.h */
    task_t *t = task_self();
    struct registers f = *t->start_frame;          /* copy out before freeing */
    kfree(t->start_frame);
    t->start_frame = 0;
    iret_to_user(&f);
}

/* ---- per-process file descriptors (M1187) -------------------------------------
 * A small fd table in struct app maps fds to pipe ends (the only fd type so far).
 * Additive: an app that never calls these has an empty table, so the fork-copy and
 * reap-close below are no-ops for it and existing behaviour is unchanged. */
static int fd_pipe_idx(struct app *a, int fd, int want_write) {   /* validate + resolve to a pipe index */
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 1) return -1;
    if (a->fd[fd].write_end != (want_write ? 1 : 0)) return -1;    /* read on a write-end (or vice versa) */
    return a->fd[fd].obj;
}

/* ---- memfd: anonymous, sealable memory-backed file objects (M1212) ------------
 * A small global table of growable kheap-backed buffers, referenced by the fd
 * table as type 3 (obj = memfd index). Distinct from mseal (M1153, which seals
 * virtual-ADDRESS ranges): these are FILE objects carrying one-way F_SEAL_* flags
 * (WRITE/SHRINK/GROW/SEAL). Refcounted across fork/dup2 exactly like a pipe. */
#define NMEMFD 16
#define MEMFD_MAX (16ul * 1024 * 1024)   /* 16 MiB per object (kheap-bounded) */
static struct memfd { int used, refs; unsigned seals; unsigned long size, cap; char *buf; char name[32]; } memfds[NMEMFD];

static int memfd_alloc(const char *name) {
    for (int i = 0; i < NMEMFD; i++) if (!memfds[i].used) {
        struct memfd *m = &memfds[i];
        m->used = 1; m->refs = 1; m->seals = 0; m->size = 0; m->cap = 0; m->buf = 0;
        int j = 0; if (name) while (name[j] && j < (int)sizeof m->name - 1) { m->name[j] = name[j]; j++; }
        m->name[j] = 0;
        return i;
    }
    return -1;
}
static void memfd_ref(int idx) { if (idx >= 0 && idx < NMEMFD && memfds[idx].used) memfds[idx].refs++; }
static void memfd_unref(int idx) {
    if (idx < 0 || idx >= NMEMFD || !memfds[idx].used) return;
    if (--memfds[idx].refs > 0) return;
    if (memfds[idx].buf) kfree(memfds[idx].buf);
    memfds[idx].used = 0; memfds[idx].buf = 0; memfds[idx].size = memfds[idx].cap = 0;
}
/* Ensure cap >= need (doubling), preserving the first `size` bytes. 0/-1. */
static int memfd_grow(struct memfd *m, unsigned long need) {
    if (need <= m->cap) return 0;
    if (need > MEMFD_MAX) return -1;
    unsigned long nc = m->cap ? m->cap * 2 : 64;
    while (nc < need) nc *= 2;
    if (nc > MEMFD_MAX) nc = MEMFD_MAX;
    char *nb = kmalloc(nc); if (!nb) return -1;
    for (unsigned long i = 0; i < m->size; i++) nb[i] = m->buf[i];
    if (m->buf) kfree(m->buf);
    m->buf = nb; m->cap = nc;
    return 0;
}
/* fd 0/1/2 are reserved for stdin/stdout/stderr (M1191): unused-in-table means
 * the window/keyboard, and dup2 can redirect them to a pipe. So pipe()/fifo_open
 * hand out fds from 3 up, like Unix, leaving 0/1/2 for stdio. */
#define APP_FD_FIRST 3
/* RLIMIT_NOFILE (M1547): true if `a` already has rlim_nofile fds open, so any
 * NEW fd allocation should be refused (0/unset = unlimited, always false).
 * Call this right before the "scan for a free slot" loop at every fd-
 * creating site below, so a limited process can't out-run its own cap
 * regardless of which specific syscall it uses to open one more fd. */
static int app_fd_over_limit(struct app *a) {
    if (!a->rlim_nofile) return 0;
    int used = 0;
    for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (a->fd[i].used) used++;
    return used >= (int)a->rlim_nofile;
}
/* pipe(out[2]): out[0]=read end, out[1]=write end. 0/-1. */
int app_pipe(int *out) {
    struct app *a = cur(); if (!a) return -1;
    int idx = pipe_new(); if (idx < 0) return -1;
    int rfd = -1, wfd = -1;
    /* RLIMIT_NOFILE (M1547): a pipe needs TWO slots, so require room for both up
     * front rather than the usual single-slot app_fd_over_limit check -- a
     * process sitting at exactly limit-1 would otherwise pass a single-slot
     * check twice in a row (neither slot is marked used between the two scans)
     * and land one fd over its cap. */
    int nofile_used = 0;
    for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (a->fd[i].used) nofile_used++;
    if (!a->rlim_nofile || nofile_used + 2 <= (int)a->rlim_nofile) {
        for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { rfd = i; break; }
        for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used && i != rfd) { wfd = i; break; }
    }
    if (rfd < 0 || wfd < 0) { pipe_close_end(idx, 0); pipe_close_end(idx, 1); return -1; }   /* table full (or over RLIMIT_NOFILE) */
    a->fd[rfd] = (struct fdent){ 1, 1, 0, idx, {0}, 0 };          /* used, type=pipe, read end */
    a->fd[wfd] = (struct fdent){ 1, 1, 1, idx, {0}, 0 };          /* used, type=pipe, write end */
    out[0] = rfd; out[1] = wfd; return 0;
}
/* pipe2 (M1239): pipe() + atomically set FD_CLOEXEC on both ends when O_CLOEXEC
 * is requested (the race-free way to avoid leaking the pipe across an exec). */
int app_pipe2(int *out, int flags) {
    if (app_pipe(out) < 0) return -1;
    if (flags & O_CLOEXEC) { struct app *a = cur(); if (a) { a->fd[out[0]].cloexec = 1; a->fd[out[1]].cloexec = 1; } }
    return 0;
}
#define FILEFD_CAP (1u << 20)   /* the write-RMW bound (M1195); reads are now uncapped via vfs_pread (M1196) */
/* Blocked eventfd readers (M1579), keyed by (owning app, fd) rather than a
 * field on struct fdent -- fork/dup2/dup3/pidfd_getfd/SCM_RIGHTS all move a
 * fdent around with a raw struct copy (app_fd_fork, app_dup2, app_pidfd_getfd,
 * g_scm[]); a "task blocked here" pointer living ON that struct would get
 * silently duplicated by every one of those copies, and a later write on the
 * DUPLICATE fd (which has its own independent counter -- eventfd has no
 * shared-object table, so it doesn't alias post-fork/dup2 either) would wake a
 * task that never touched that fd at all. Keeping this table separate means
 * none of those copy paths need to know it exists. */
#define EVFD_NWAIT 16
static struct { struct app *a; int fd; void *task; int used; } g_evfd_wait[EVFD_NWAIT];
long app_fd_read(int fd, void *buf, unsigned long max) {
    struct app *a = cur(); if (!a) return -1;
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 2) {   /* FILE fd: positioned read (M1193/M1196) */
        long off = a->fd[fd].off;
        if (off < 0) return -1;
        long n = vfs_pread(a->fd[fd].path, buf, max, (uint64_t)off);   /* native positioned read (tmpfs/ext2); uncapped */
        if (n > 0) a->fd[fd].off = off + n;
        return n;                                             /* 0 => EOF (offset at/after end) */
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 3) {   /* memfd: positioned read (M1212) */
        struct memfd *m = &memfds[a->fd[fd].obj];
        long off = a->fd[fd].off; if (off < 0) return -1;
        if ((unsigned long)off >= m->size) return 0;          /* at/after EOF */
        unsigned long n = m->size - (unsigned long)off; if (n > max) n = max;
        for (unsigned long i = 0; i < n; i++) ((char *)buf)[i] = m->buf[off + i];
        a->fd[fd].off = off + (long)n;
        return (long)n;
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 4) {   /* timerfd: read the expiration count (M1217) */
        if (max < 8) return -1;
        long exp = a->fd[fd].off;
        if (exp != 0 && (uint64_t)timer_ms() >= (uint64_t)exp) {
            long interval = a->fd[fd].obj;                                     /* periodic interval (ms); 0 = one-shot */
            uint64_t count = 1;
            if (interval > 0) {                                               /* periodic: count missed firings + re-arm */
                count += ((uint64_t)timer_ms() - (uint64_t)exp) / (uint64_t)interval;
                a->fd[fd].off = exp + (long)(count * (uint64_t)interval);      /* next future expiry */
            } else {
                a->fd[fd].off = 0;                                            /* one-shot: disarm */
            }
            for (int i = 0; i < 8; i++) ((char *)buf)[i] = (char)(count >> (i * 8));   /* expiration count (LE u64) */
            return 8;
        }
        return 0;                                                             /* not expired yet */
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 5) {   /* eventfd: read the counter (M1242) */
        if (max < 8) return -1;
        while (a->fd[fd].off <= 0) {            /* empty: block for real unless EFD_NONBLOCK (M1579) */
            uint64_t f = irq_save();             /* M1612: pairs with app_fd_write's own lock below --
                                                    * was unsynchronized, so a writer's check of g_evfd_wait[]
                                                    * could run before this reader finishes registering */
            if (a->fd[fd].off > 0) { irq_restore(f); break; }   /* a writer raced in since the check above */
            if (a->fd[fd].obj) { irq_restore(f); return -1; }   /* obj doubles as the EFD_NONBLOCK flag for this type -> EAGAIN */
            int slot = -1;
            for (int i = 0; i < EVFD_NWAIT; i++) if (!g_evfd_wait[i].used) { slot = i; break; }
            if (slot < 0) { irq_restore(f); return -1; }        /* too many blocked eventfd readers system-wide; fail rather than hang */
            g_evfd_wait[slot].a = a; g_evfd_wait[slot].fd = fd; g_evfd_wait[slot].task = task_self(); g_evfd_wait[slot].used = 1;
            irq_restore(f);                      /* released BEFORE blocking (M1612) */
            task_block();                       /* woken by eventfd_write, a kill, or a signal */
            g_evfd_wait[slot].used = 0;          /* reclaim our slot on resume (idempotent w/ the WAKE below) */
        }
        long cnt = a->fd[fd].off;
        uint64_t val = a->fd[fd].write_end ? 1u : (uint64_t)cnt;              /* SEMAPHORE: 1, else the whole count */
        for (int i = 0; i < 8; i++) ((char *)buf)[i] = (char)(val >> (i * 8));
        a->fd[fd].off = a->fd[fd].write_end ? cnt - 1 : 0;                    /* SEMAPHORE: decrement, else drain */
        return 8;
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 8) {   /* inotify: drain queued events (M1266) */
        return inotify_read(a->fd[fd].obj, buf, max);
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 10) {  /* TCP socket: recv (M1268) */
        return net_tcp_sock_recv(a->fd[fd].obj, buf, max);
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 11) {  /* pty endpoint: read through the line discipline (M1274) */
        return pty_read(a->fd[fd].obj, buf, max);
    }
    int idx = fd_pipe_idx(a, fd, 0); if (idx < 0) return -1;
    return pipe_read(idx, buf, max);
}
/* Shared by app_fd_write's FILE-fd case and app_pwrite (M1572): the whole
 * read-modify-write-the-file body, keyed on an EXPLICIT offset rather than
 * a->fd[fd].off, so pwrite's defining property (never moves the cursor) and
 * write()'s (always advances it) can both be one-line wrappers around the
 * identical logic — including the identical RLIMIT_FSIZE/SIGXFSZ enforcement,
 * matching real POSIX where pwrite() is bound by the exact same limit. */
static long app_file_write_at(struct app *a, int fd, const void *buf, unsigned long len, long off) {
    if (!a->fd[fd].write_end) return -1;                  /* opened read-only */
    if (off < 0) return -1;
    if (a->rlim_fsize && (unsigned long)off + len > a->rlim_fsize) {   /* RLIMIT_FSIZE (M1549) */
        app_request_signal(a, SIGXFSZ);
        return -1;
    }

    /* Straight to the filesystem where it has a positional write (ext2, M1935):
     * no whole-file buffer, so no FILEFD_CAP and no O(filesize) cost per write.
     * That is the difference between "can append to a log" and "can link a
     * 200 MB binary". The read-modify-write below remains for filesystems with
     * no pwrite -- notably the FAT32 boot volume, which is writable but only
     * whole-file -- so FILEFD_CAP is now checked on THAT path only. */
    long pw = vfs_pwrite(a->fd[fd].path, buf, len, (uint64_t)off);
    if (pw != VFS_PWRITE_UNSUPPORTED) return pw;

    if ((unsigned long)off + len > FILEFD_CAP) return -1;
    /* read-modify-write the whole file (via vfs_read/vfs_write — no per-FS work;
     * bounded to FILEFD_CAP). Read existing, patch [off, off+len), grow if needed. */
    struct statx st; long sz = (vfs_stat(a->fd[fd].path, &st) == 0) ? (long)st.stx_size : 0;
    unsigned long need = (unsigned long)off + len;
    if ((unsigned long)sz > need) need = (unsigned long)sz;   /* preserve bytes past the write */
    char *tmp = kmalloc(need ? need : 1); if (!tmp) return -1;
    long got = vfs_read(a->fd[fd].path, tmp, need);
    if (got < 0) got = 0;
    for (long i = got; i < off; i++) tmp[i] = 0;          /* zero-fill a gap (sparse extend) */
    for (unsigned long i = 0; i < len; i++) tmp[off + i] = ((const char *)buf)[i];
    long w = vfs_write(a->fd[fd].path, tmp, need);
    kfree(tmp);
    if (w < 0) return -1;
    return (long)len;
}
#define SIGPIPE 13   /* real Linux's own number; free here (M1581) */
long app_fd_write(int fd, const void *buf, unsigned long len) {
    struct app *a = cur(); if (!a) return -1;
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 2) {   /* FILE fd: positioned write (M1195) */
        long off = a->fd[fd].off;
        long n = app_file_write_at(a, fd, buf, len, off);
        if (n > 0) a->fd[fd].off = off + n;
        return n;
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 3) {   /* memfd: seal-checked positioned write (M1212) */
        struct memfd *m = &memfds[a->fd[fd].obj];
        if (m->seals & F_SEAL_WRITE) return -1;
        long off = a->fd[fd].off; if (off < 0) return -1;
        unsigned long end = (unsigned long)off + len;
        if (end > m->size) {                                  /* the write grows the file */
            if (m->seals & F_SEAL_GROW) return -1;
            if (memfd_grow(m, end) != 0) return -1;
            for (unsigned long i = m->size; i < (unsigned long)off; i++) m->buf[i] = 0;   /* zero a sparse gap */
            m->size = end;
        }
        for (unsigned long i = 0; i < len; i++) m->buf[off + i] = ((const char *)buf)[i];
        a->fd[fd].off = off + (long)len;
        return (long)len;
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 5) {   /* eventfd: add to the counter (M1242) */
        if (len < 8) return -1;
        uint64_t add = 0;
        for (int i = 0; i < 8; i++) add |= (uint64_t)(unsigned char)((const char *)buf)[i] << (i * 8);
        if (add == 0xFFFFFFFFFFFFFFFFull) return -1;                          /* ~0 is reserved/invalid for eventfd */
        long nc = a->fd[fd].off + (long)add;
        if (nc < a->fd[fd].off) return -1;                                   /* overflow -> would block; reject */
        uint64_t f = irq_save();
        a->fd[fd].off = nc;
        for (int i = 0; i < EVFD_NWAIT; i++)                                  /* wake every reader blocked on THIS (app, fd) (M1579) */
            if (g_evfd_wait[i].used && g_evfd_wait[i].a == a && g_evfd_wait[i].fd == fd) {
                g_evfd_wait[i].used = 0;
                task_wake((task_t *)g_evfd_wait[i].task);
            }
        irq_restore(f);
        return 8;
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 10) {  /* TCP socket: send (M1268) */
        return net_tcp_sock_send(a->fd[fd].obj, buf, (int)len);
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 11) {  /* pty endpoint: master write feeds the ldisc, slave write -> master output (M1274) */
        return pty_write(a->fd[fd].obj, buf, len);
    }
    int idx = fd_pipe_idx(a, fd, 1); if (idx < 0) return -1;
    long pw = pipe_write(idx, buf, len);
    if (pw == -1) app_request_signal(a, SIGPIPE);   /* no readers left (EPIPE) -> also SIGPIPE, like real POSIX (M1581) */
    return pw;
}
/* pread/pwrite (M1572): read/write at an explicit offset WITHOUT touching
 * a->fd[fd].off — the one thing that distinguishes them from read()/write()
 * on the same fd. FILE fds only (type 2); real POSIX allows pread/pwrite on
 * anything seekable, but everything else here (pipes, sockets, memfd's own
 * separate cursor semantics) isn't worth the extra surface for this pass. */
long app_pread(int fd, void *buf, unsigned long max, long off) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 2 || off < 0) return -1;
    return vfs_pread(a->fd[fd].path, buf, max, (uint64_t)off);
}
long app_pwrite(int fd, const void *buf, unsigned long len, long off) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 2) return -1;
    return app_file_write_at(a, fd, buf, len, off);
}
static void epoll_ref(int idx);    /* defined with the epoll table below (M1220) */
static void epoll_unref(int idx);
int app_fd_close(int fd) {
    struct app *a = cur(); if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    if (a->fd[fd].type == 1) pipe_close_end(a->fd[fd].obj, a->fd[fd].write_end);
    else if (a->fd[fd].type == 3) memfd_unref(a->fd[fd].obj);   /* drop a memfd reference (M1212) */
    else if (a->fd[fd].type == 6) epoll_unref(a->fd[fd].obj);   /* drop an epoll reference (M1220) */
    else if (a->fd[fd].type == 8) inotify_free(a->fd[fd].obj);  /* free the inotify instance (M1266) */
    else if (a->fd[fd].type == 10) net_tcp_sock_close(a->fd[fd].obj);  /* close the TCP connection (M1268) */
    else if (a->fd[fd].type == 11) pty_close(a->fd[fd].obj);    /* close this pty end, waking the peer (M1274) */
    a->fd[fd].used = 0; a->fd[fd].type = 0;
    return 0;
}
/* ptsname (M1274): the pts index N for a /dev/ptmx master fd, so userspace can
 * open the matching /dev/pts/N slave. -1 if fd isn't a pty-master fd. */
long app_pts_number(int fd) {
    struct app *a = cur(); if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    if (a->fd[fd].type != 11 || (a->fd[fd].obj & 1)) return -1;   /* must be a master end (even id) */
    return a->fd[fd].obj >> 1;
}
int app_dup2(int oldfd, int newfd) {
    struct app *a = cur(); if (!a || oldfd < 0 || oldfd >= APP_NFD || !a->fd[oldfd].used) return -1;
    if (newfd < 0 || newfd >= APP_NFD) return -1;
    if (oldfd == newfd) return newfd;
    if (a->fd[newfd].used && a->fd[newfd].type == 1) pipe_close_end(a->fd[newfd].obj, a->fd[newfd].write_end);
    else if (a->fd[newfd].used && a->fd[newfd].type == 3) memfd_unref(a->fd[newfd].obj);   /* (M1212) */
    else if (a->fd[newfd].used && a->fd[newfd].type == 6) epoll_unref(a->fd[newfd].obj);   /* (M1220) */
    else if (a->fd[newfd].used && a->fd[newfd].type == 8) inotify_free(a->fd[newfd].obj);       /* (M1603) */
    else if (a->fd[newfd].used && a->fd[newfd].type == 10) net_tcp_sock_close(a->fd[newfd].obj); /* (M1603) */
    a->fd[newfd] = a->fd[oldfd];                                  /* newfd now references the same end */
    if (a->fd[newfd].type == 1) pipe_open_end(a->fd[newfd].obj, a->fd[newfd].write_end);
    else if (a->fd[newfd].type == 3) memfd_ref(a->fd[newfd].obj);   /* (M1212) */
    else if (a->fd[newfd].type == 6) epoll_ref(a->fd[newfd].obj);   /* (M1220) */
    else if (a->fd[newfd].type == 8) inotify_ref(a->fd[newfd].obj);       /* (M1603) */
    else if (a->fd[newfd].type == 10) net_tcp_sock_ref(a->fd[newfd].obj); /* (M1603) */
    return newfd;
}
/* mkfifo(path): create a named pipe (M1188). 0/-1. */
int app_mkfifo(const char *path) { return fifo_make(path); }
/* fifo_open(path, write): open one end of a named FIFO -> a new fd. -1 if no
 * such FIFO or the table is full. */
int app_fifo_open(const char *path, int write) {
    struct app *a = cur(); if (!a) return -1;
    int idx = fifo_pipe(path); if (idx < 0) return -1;
    int fd = -1;
    if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }   /* RLIMIT_NOFILE (M1547) */
    if (fd < 0) return -1;
    pipe_open_end(idx, write ? 1 : 0);
    a->fd[fd] = (struct fdent){ 1, 1, (uint8_t)(write ? 1 : 0), idx, {0}, 0 };
    return fd;
}

/* open(path): a read-only FILE fd (M1193). Positioned reads via app_fd_read +
 * app_lseek; close via app_fd_close. Returns the fd (>=3), or -1. */
int app_open(const char *path, int flags) {
    struct app *a = cur(); if (!a) return -1;
    /* /dev/ptmx (M1274): open the MASTER end of a fresh pty pair (the slave then
     * appears at /dev/pts/<n>). /dev/pts/<n> opens that slave. Both become
     * type-11 fds over pty.c (obj = the pty endpoint id; master ids are even,
     * slave = master|1). This is the Unix98 PTY naming over the existing M1185
     * line-discipline engine — programs find their tty by path, not a magic id. */
    int is_pts = 1; { const char *pfx = "/dev/pts/"; for (int k = 0; pfx[k]; k++) if (path[k] != pfx[k]) { is_pts = 0; break; } }
    if (strcmp(path, "/dev/ptmx") == 0 || is_pts) {
        int id;
        if (strcmp(path, "/dev/ptmx") == 0) {
            id = pty_open(); if (id < 0) return -1;              /* even master id */
        } else {
            int n = 0; const char *q = path + 9;                /* parse /dev/pts/<n> */
            if (*q < '0' || *q > '9') return -1;
            while (*q >= '0' && *q <= '9') n = n * 10 + (*q++ - '0');
            if (*q) return -1;                                   /* trailing junk */
            if (!pty_pts_valid(n)) return -1;                    /* no such live pty */
            id = (n << 1) | 1;                                   /* slave id */
        }
        int fd = -1;
        if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }   /* RLIMIT_NOFILE (M1547) */
        if (fd < 0) { if (!(id & 1)) pty_close(id); return -1; } /* no fd slot: undo the master open */
        a->fd[fd] = (struct fdent){ 1, 11, 1, id, {0}, 0 };      /* used, type=11 pty, write_end=1 (bidirectional) */
        int j = 0; while (path[j] && j < (int)sizeof a->fd[fd].path - 1) { a->fd[fd].path[j] = path[j]; j++; }
        a->fd[fd].path[j] = 0;
        a->fd[fd].cloexec = (flags & O_CLOEXEC) ? 1 : 0;
        return fd;
    }
    struct statx st;
    int exists = (vfs_stat(path, &st) == 0);
    if (!exists) {
        if (!(flags & O_CREAT)) return -1;                    /* must exist unless O_CREAT */
        if (vfs_write(path, "", 0) < 0) return -1;            /* create empty */
        st.stx_size = 0;
    } else if ((flags & O_TRUNC) && (flags & O_WRONLY)) {
        if (vfs_write(path, "", 0) < 0) return -1;            /* truncate to 0 */
        st.stx_size = 0;
    }
    int fd = -1;
    if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }   /* RLIMIT_NOFILE (M1547) */
    if (fd < 0) return -1;
    uint8_t wr = (flags & O_WRONLY) ? 1 : 0;                  /* write_end=1 => writable file fd (M1195) */
    a->fd[fd] = (struct fdent){ 1, 2, wr, 0, {0}, 0 };        /* used, type=file */
    int j = 0; while (path[j] && j < (int)sizeof a->fd[fd].path - 1) { a->fd[fd].path[j] = path[j]; j++; }
    a->fd[fd].path[j] = 0;
    a->fd[fd].off = (flags & O_APPEND) ? (long)st.stx_size : 0;   /* O_APPEND starts at EOF */
    a->fd[fd].cloexec = (flags & O_CLOEXEC) ? 1 : 0;              /* close-on-exec (M1218) */
    return fd;
}
/* lseek(fd, off, whence): 0=SET, 1=CUR, 2=END. Returns the new offset, or -1. */
long app_lseek(int fd, long off, int whence) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || (a->fd[fd].type != 2 && a->fd[fd].type != 3)) return -1;
    if (whence == SEEK_DATA || whence == SEEK_HOLE) {        /* sparse-aware seek (M1229) */
        int find_hole = (whence == SEEK_HOLE);
        long r;
        if (a->fd[fd].type == 3) {                           /* memfd: contiguous, no holes */
            long size = (long)memfds[a->fd[fd].obj].size;
            if (off < 0 || off >= size) return -1;           /* ENXIO */
            r = find_hole ? size : off;
        } else r = vfs_seek_data_hole(a->fd[fd].path, off, find_hole);
        if (r < 0) return -1;
        a->fd[fd].off = r;                                   /* POSIX: the seek also repositions the fd */
        return r;
    }
    long base = 0;
    if (whence == 1) base = a->fd[fd].off;
    else if (whence == 2) {                                  /* SEEK_END: file size (memfd size for type 3, M1212) */
        if (a->fd[fd].type == 3) base = (long)memfds[a->fd[fd].obj].size;
        else { struct statx st; if (vfs_stat(a->fd[fd].path, &st) != 0) return -1; base = (long)st.stx_size; }
    }
    long n = base + off;
    if (n < 0) return -1;
    a->fd[fd].off = n;
    return n;
}

/* utimensat (M1230): set a path's atime/mtime. UTIME_NOW -> the current epoch,
 * UTIME_OMIT (any negative) -> leave that field unchanged; vfs_utimes handles
 * the FS dispatch. Returns 0/-1. */
long app_utimens(const char *path, long atime, long mtime) {
    long now = (long)rtc_unix();
    if (atime == UTIME_NOW) atime = now;                     /* else: epoch (>=0 set) or UTIME_OMIT (<0 leave) */
    if (mtime == UTIME_NOW) mtime = now;
    return vfs_utimes(path, atime, mtime);
}

/* futimens (M1230): same, on an open FILE fd (resolved to its path). */
long app_futimens(int fd, long atime, long mtime) {
    const char *p = app_fd_path(fd);
    if (!p) return -1;
    return app_utimens(p, atime, mtime);
}
/* memfd_create(name, flags): a new anonymous, sealable in-RAM file fd (M1212).
 * Returns the fd (>=3), or -1. `flags` reserved (sealing is always permitted
 * until F_SEAL_SEAL is added). */
int app_memfd_create(const char *name, int flags) {
    (void)flags;
    struct app *a = cur(); if (!a) return -1;
    int idx = memfd_alloc(name); if (idx < 0) return -1;
    int fd = -1;
    if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }   /* RLIMIT_NOFILE (M1547) */
    if (fd < 0) { memfd_unref(idx); return -1; }
    a->fd[fd] = (struct fdent){ 1, 3, 1, idx, {0}, 0 };      /* used, type=memfd, writable, obj=idx */
    return fd;
}
/* Add memfd seals (one-way OR of F_SEAL_*). Returns the new seal set, or -1
 * (bad fd, or already F_SEAL_SEAL'd). `add`==0 just queries the current seals. */
long app_memfd_seal(int fd, unsigned add) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 3) return -1;
    struct memfd *m = &memfds[a->fd[fd].obj];
    if (add && (m->seals & F_SEAL_SEAL)) return -1;          /* sealing is itself sealed */
    m->seals |= add;
    return (long)m->seals;
}
/* ftruncate(fd, len): resize a memfd, honoring the WRITE/SHRINK/GROW seals. 0/-1. */
long app_ftruncate(int fd, long len) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used || len < 0) return -1;
    if (a->fd[fd].type == 2) return vfs_truncate(a->fd[fd].path, (uint64_t)len);   /* a real file fd (M1228) */
    if (a->fd[fd].type != 3) return -1;                    /* otherwise it must be a memfd */
    struct memfd *m = &memfds[a->fd[fd].obj];
    unsigned long n = (unsigned long)len;
    if (n == m->size) return 0;
    if (n < m->size) {                                       /* shrink */
        if (m->seals & (F_SEAL_SHRINK | F_SEAL_WRITE)) return -1;
        m->size = n; return 0;
    }
    if (m->seals & (F_SEAL_GROW | F_SEAL_WRITE)) return -1;  /* grow */
    if (memfd_grow(m, n) != 0) return -1;
    for (unsigned long i = m->size; i < n; i++) m->buf[i] = 0;
    m->size = n;
    return 0;
}
/* fsync/fdatasync/sync_file_range (M1566): honestly free, not a lying stub --
 * blockdev.c's buffer cache is write-through (bcache_flush's own comment),
 * and neither fat32.c nor ext2.c keep any dirty/deferred metadata of their
 * own on top of it (grepped: zero hits for "dirty"/"_flush" in either), so
 * by the time write()/writefile() has already returned, the data is already
 * as durable as this stack ever makes it -- there is nothing left to flush.
 * Scoped to a real FILE fd (type 2) only: a memfd/pipe/socket/etc. has no
 * notion of "reached stable storage" here at all, so -1 for those is real
 * enforcement, not an arbitrary restriction. fdatasync is identical to
 * fsync (no separate metadata-vs-data distinction exists to relax); the
 * range/flags arguments of sync_file_range are accepted but unused --
 * nothing is deferred for ANY range to begin with. */
long app_fsync(int fd) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    return a->fd[fd].type == 2 ? 0 : -1;
}
long app_sync_file_range(int fd, uint64_t offset, uint64_t nbytes, unsigned flags) {
    (void)offset; (void)nbytes; (void)flags;
    return app_fsync(fd);
}
/* sync(2) (M1588): whole-system flush, no fd. Same reasoning as app_fsync's own
 * comment above, minus the per-fd type check -- nothing anywhere is ever
 * deferred, so there is nothing for a WHOLE-system flush to do either. Real
 * sync() has no failure mode; this one genuinely never has one to report. */
void app_sync(void) { }
/* timerfd (M1217; periodic M1302): a pollable timer as an fd. The absolute expiry
 * (ms, 0 = disarmed) lives in the fd's own `off` field and the periodic interval
 * (ms, 0 = one-shot) in `obj` — no separate object, so fork copies them and close
 * needs no teardown. read() returns the 8-byte expiration count; a periodic timer
 * re-arms to its next firing (count = firings missed since the last read), a
 * one-shot disarms; poll() reports POLLIN at/after expiry. */
int app_timerfd_create(void) {
    struct app *a = cur(); if (!a) return -1;
    int fd = -1;
    if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }   /* RLIMIT_NOFILE (M1547) */
    if (fd < 0) return -1;
    a->fd[fd] = (struct fdent){ 1, 4, 0, 0, {0}, 0 };       /* used, type=timerfd, off=0 disarmed, obj=0 one-shot */
    return fd;
}
long app_timerfd_settime(int fd, long delay_ms, long interval_ms) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 4) return -1;
    a->fd[fd].off = (delay_ms <= 0) ? 0 : (long)(timer_ms() + (uint64_t)delay_ms);   /* absolute expiry; <=0 disarms */
    a->fd[fd].obj = (delay_ms > 0 && interval_ms > 0) ? (int)interval_ms : 0;         /* periodic interval (ms); 0 = one-shot */
    return 0;
}
/* eventfd (M1242): a pollable u64-counter fd. The counter lives in the fd's own
 * `off` field (like timerfd — no object table, so fork copies it + close needs no
 * teardown); write() adds to it, read() drains it (or decrements by 1 in
 * EFD_SEMAPHORE mode, flagged via write_end), poll() reports POLLIN when >0.
 * `obj` (otherwise unused here) doubles as the EFD_NONBLOCK flag (M1579): a
 * real per-fd flag, since unlike every other blocking fd type in this table,
 * eventfd shipped (M1242) with reads hard-coded to never block at all. */
int app_eventfd_create(unsigned int initval, int flags) {
    struct app *a = cur(); if (!a) return -1;
    int fd = -1;
    if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }   /* RLIMIT_NOFILE (M1547) */
    if (fd < 0) return -1;
    a->fd[fd] = (struct fdent){ 1, 5, (flags & EFD_SEMAPHORE) ? (uint8_t)1 : (uint8_t)0,
                                (flags & EFD_NONBLOCK) ? 1 : 0, {0}, (long)initval, (flags & EFD_CLOEXEC) ? (uint8_t)1 : (uint8_t)0 };
    return fd;
}

/* inotify (M1266): a pollable filesystem-watch fd. fd type 8, obj = the kernel
 * inotify-instance index (kernel/inotify.c). read() drains queued events;
 * app_fd_ready reports POLLIN when events pend; close frees the instance. */
int app_inotify_init(void) {
    struct app *a = cur(); if (!a) return -1;
    int idx = inotify_new(); if (idx < 0) return -1;
    int fd = -1;
    if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }   /* RLIMIT_NOFILE (M1547) */
    if (fd < 0) { inotify_free(idx); return -1; }
    a->fd[fd] = (struct fdent){ 1, 8, 0, idx, {0}, 0, 0 };   /* used, type=inotify, obj=instance */
    return fd;
}
int app_inotify_add(int fd, const char *path, unsigned int mask) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 8) return -1;
    return inotify_add(a->fd[fd].obj, path, mask);
}
int app_inotify_rm(int fd, int wd) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 8) return -1;
    return inotify_rm(a->fd[fd].obj, wd);
}

/* AF_INET datagram sockets (M1267): a BSD socket() fd API over the userspace
 * UDP path (M1258) + loopback (M1264). fd type 9; the bound local port lives in
 * fdent.off (0 = unbound -> an ephemeral port is assigned on first sendto). */
static uint16_t g_ephemeral = 49152;
int app_socket(int domain, int type) {
    struct app *a = cur(); if (!a) return -1;
    if (domain != 2 /*AF_INET*/) return -1;
    if (type != 2 /*SOCK_DGRAM*/ && type != 1 /*SOCK_STREAM*/) return -1;
    int fd = -1;
    if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }   /* RLIMIT_NOFILE (M1547) */
    if (fd < 0) return -1;
    if (type == 1) {                                       /* SOCK_STREAM: a TCP client socket (M1268) */
        int idx = net_tcp_sock_open(); if (idx < 0) return -1;
        a->fd[fd] = (struct fdent){ 1, 10, 0, idx, {0}, 0, 0 };  /* type=AF_INET stream, obj=TCB slot */
    } else {
        a->fd[fd] = (struct fdent){ 1, 9, 0, 0, {0}, 0, 0 };     /* type=AF_INET dgram, off=0 (unbound) */
    }
    return fd;
}
/* connect(2) for a TCP socket fd (M1268): active-open to ip:port. */
int app_connect(int fd, const uint8_t ip[4], int port) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 10) return -1;
    return net_tcp_sock_connect(a->fd[fd].obj, ip, (uint16_t)port);
}
/* setsockopt/getsockopt (M1554): TCP client sockets (type 10) only -- these
 * are the fds SO_REUSEADDR/TCP_NODELAY/SO_KEEPALIVE actually apply to. */
int app_setsockopt(int fd, int level, int optname, int val) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 10) return -1;
    return net_tcp_sock_setopt(a->fd[fd].obj, level, optname, val);
}
int app_getsockopt(int fd, int level, int optname, int *val) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 10) return -1;
    return net_tcp_sock_getopt(a->fd[fd].obj, level, optname, val);
}
/* getsockname/getpeername (M1560): same TCP-client-socket-only scope as
 * setsockopt/getsockopt above. */
int app_getsockname(int fd, unsigned char out[6]) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 10) return -1;
    return net_tcp_sock_getname(a->fd[fd].obj, out);
}
int app_getpeername(int fd, unsigned char out[6]) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 10) return -1;
    return net_tcp_sock_getpeer(a->fd[fd].obj, out);
}
int app_sock_bind(int fd, int port) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 9) return -1;
    if (port <= 0 || port > 65535) return -1;
    a->fd[fd].off = port;
    return 0;
}
long app_sendto(int fd, const uint8_t ip[4], int port, const void *buf, int len) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 9) return -1;
    if (a->fd[fd].off == 0) { a->fd[fd].off = g_ephemeral++; if (g_ephemeral == 0) g_ephemeral = 49152; }
    return net_udp_send(ip, (uint16_t)port, (uint16_t)a->fd[fd].off, buf, len) == 0 ? len : -1;
}
long app_recvfrom(int fd, void *buf, int max, uint8_t srcip[4], uint16_t *srcport) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 9) return -1;
    if (a->fd[fd].off == 0) return -1;                     /* unbound -> nothing to receive on */
    return net_udp_recv((uint16_t)a->fd[fd].off, buf, max, srcip, srcport, 2000);
}
/* fd hygiene (M1218): fcntl(F_GETFD/F_SETFD/F_DUPFD/F_DUPFD_CLOEXEC), dup3,
 * close_range — over the per-fd FD_CLOEXEC bit (honored by app_exec above; fork
 * copies the whole fdent so it survives a fork, as POSIX requires). */
long app_fcntl(int fd, int cmd, long arg) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    if (cmd == F_GETFD) return a->fd[fd].cloexec ? FD_CLOEXEC : 0;
    if (cmd == F_SETFD) { a->fd[fd].cloexec = (arg & FD_CLOEXEC) ? 1 : 0; return 0; }
    if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        int lo = (int)arg; if (lo < APP_FD_FIRST) lo = APP_FD_FIRST;
        int nf = -1; for (int i = lo; i < APP_NFD; i++) if (!a->fd[i].used) { nf = i; break; }
        if (nf < 0 || app_dup2(fd, nf) != nf) return -1;
        a->fd[nf].cloexec = (cmd == F_DUPFD_CLOEXEC) ? 1 : 0;
        return nf;
    }
    return -1;
}
int app_dup3(int oldfd, int newfd, int flags) {
    struct app *a = cur(); if (!a) return -1;
    if (oldfd == newfd) return -1;                          /* dup3 differs from dup2: EINVAL on equal fds */
    if (app_dup2(oldfd, newfd) != newfd) return -1;
    a->fd[newfd].cloexec = (flags & O_CLOEXEC) ? 1 : 0;
    return newfd;
}
long app_close_range(unsigned lo, unsigned hi, int flags) {
    struct app *a = cur(); if (!a) return -1;
    (void)flags;
    if (hi >= APP_NFD) hi = APP_NFD - 1;
    for (unsigned i = lo; i <= hi && i < APP_NFD; i++) if (a->fd[i].used) app_fd_close((int)i);
    return 0;
}
/* sendfile (M1219): copy up to `count` bytes from in_fd to out_fd through a
 * kernel bounce buffer — no userspace round-trip (the canonical zero-copy path,
 * generalizing splice off pipes). If *off >= 0, read in_fd at that absolute
 * offset (a FILE fd) and advance *off, leaving the fd cursor untouched; if
 * *off < 0, read sequentially via the fd cursor (any fd kind). Returns bytes
 * copied, or -1. Loops in 4 KiB chunks; stops at EOF or a short write. */
/* The file path behind a FILE fd (type 2), for fcntl record locks (M1221). */
/* Is `fd` a live entry in the calling app's fd table? Lets the Linux ABI tell
 * a REDIRECTED stdio fd (dup2'd onto a pipe) from an untouched one, which must
 * still go to the console. (M1949) */
int app_fd_is_open(int fd) {
    struct app *a = cur();
    return (a && fd >= 0 && fd < APP_NFD && a->fd[fd].used) ? 1 : 0;
}

const char *app_fd_path(int fd) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 2) return 0;
    return a->fd[fd].path;
}
long app_sendfile(int out_fd, int in_fd, long *off, unsigned long count) {
    struct app *a = cur(); if (!a) return -1;
    if (in_fd  < 0 || in_fd  >= APP_NFD || !a->fd[in_fd].used)  return -1;
    if (out_fd < 0 || out_fd >= APP_NFD || !a->fd[out_fd].used) return -1;
    char buf[4096]; long total = 0;
    while ((unsigned long)total < count) {
        unsigned long chunk = count - (unsigned long)total;
        if (chunk > sizeof buf) chunk = sizeof buf;
        long got;
        if (*off >= 0) {                                    /* positioned read of a FILE fd */
            if (a->fd[in_fd].type != 2) return total ? total : -1;
            got = vfs_pread(a->fd[in_fd].path, buf, chunk, (uint64_t)*off);
            if (got > 0) *off += got;
        } else {
            got = app_fd_read(in_fd, buf, chunk);           /* sequential (advances the cursor) */
        }
        if (got <= 0) break;                                /* EOF or read error */
        long w = app_fd_write(out_fd, buf, (unsigned long)got);
        if (w < 0) return total ? total : -1;
        total += w;
        if (w < got) break;                                 /* short write (e.g. pipe full) */
    }
    return total;
}

/* ---- epoll: scalable readiness multiplexing as an fd object (M1220) ----------
 * A small global table of interest sets, referenced by the fd table as type 6.
 * epoll_wait reuses the per-type readiness ladder (app_fd_ready) the poll(2)
 * loop already drives; refcounted across fork/dup2 like a memfd/pipe. */
#define NEPOLL 8
#define EP_MAX 32
static struct epollobj { int used, refs, n; struct { int fd, events, last_ready; unsigned long data; } items[EP_MAX]; } epolls[NEPOLL];
static void epoll_ref(int idx)   { if (idx >= 0 && idx < NEPOLL && epolls[idx].used) epolls[idx].refs++; }
static void epoll_unref(int idx) { if (idx >= 0 && idx < NEPOLL && epolls[idx].used && --epolls[idx].refs <= 0) epolls[idx].used = 0; }

int app_epoll_create(void) {
    struct app *a = cur(); if (!a) return -1;
    int idx = -1; for (int i = 0; i < NEPOLL; i++) if (!epolls[i].used) { idx = i; break; }
    if (idx < 0) return -1;
    epolls[idx].used = 1; epolls[idx].refs = 1; epolls[idx].n = 0;
    int fd = -1; if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }   /* RLIMIT_NOFILE (M1547) */
    if (fd < 0) { epolls[idx].used = 0; return -1; }
    a->fd[fd] = (struct fdent){ 1, 6, 0, idx, {0}, 0, 0 };   /* used, type=epoll, obj=idx */
    return fd;
}
int app_epoll_ctl(int epfd, int op, int fd, unsigned events, unsigned long data) {
    struct app *a = cur();
    if (!a || epfd < 0 || epfd >= APP_NFD || !a->fd[epfd].used || a->fd[epfd].type != 6) return -1;
    if (fd < 0 || fd >= APP_NFD) return -1;
    struct epollobj *e = &epolls[a->fd[epfd].obj];
    if (op == EPOLL_CTL_ADD) {
        for (int i = 0; i < e->n; i++) if (e->items[i].fd == fd) return -1;   /* already registered */
        if (e->n >= EP_MAX) return -1;
        e->items[e->n].fd = fd; e->items[e->n].events = (int)events; e->items[e->n].data = data;
        e->items[e->n].last_ready = 0;   /* M1545: no edge reported yet */
        e->n++;
        return 0;
    }
    if (op == EPOLL_CTL_MOD) {
        for (int i = 0; i < e->n; i++) if (e->items[i].fd == fd) {
            e->items[i].events = (int)events; e->items[i].data = data;
            e->items[i].last_ready = 0;   /* M1545: a changed interest set re-arms the edge, same spirit as a fresh ADD */
            return 0;
        }
        return -1;
    }
    if (op == EPOLL_CTL_DEL) {
        for (int i = 0; i < e->n; i++) if (e->items[i].fd == fd) { e->items[i] = e->items[--e->n]; return 0; }
        return -1;
    }
    return -1;
}
/* One non-blocking pass: fill `out` with the ready members. Returns the count,
 * or -1 for a bad epfd. The SYS_epoll_wait dispatch wraps this in the poll
 * sleep/timeout loop.
 *
 * Level- vs edge-triggered (M1545): by default (no EPOLLET in an item's
 * registered events) this reports "ready" on EVERY call for as long as the
 * fd stays ready -- unchanged from the original behavior, so an existing
 * level-triggered caller sees no difference. EPOLLET instead reports it only
 * on the RISING edge (not-ready -> ready): once reported, the SAME item
 * won't fire again until app_fd_ready sees it go not-ready and then ready
 * again. last_ready tracks that per-item, independent of level/edge mode, so
 * switching an item's mode (via EPOLL_CTL_MOD) starts from a clean edge. */
int app_epoll_check(int epfd, struct epoll_event *out, int maxevents) {
    struct app *a = cur();
    if (!a || epfd < 0 || epfd >= APP_NFD || !a->fd[epfd].used || a->fd[epfd].type != 6) return -1;
    struct epollobj *e = &epolls[a->fd[epfd].obj];
    int k = 0;
    for (int i = 0; i < e->n && k < maxevents; i++) {
        int re = app_fd_ready((app_t *)a, e->items[i].fd, e->items[i].events & ~(int)EPOLLET);
        int fire = (re > 0) && (!(e->items[i].events & EPOLLET) || !e->items[i].last_ready);
        e->items[i].last_ready = (re > 0);
        if (fire) { out[k].events = (unsigned)re; out[k].data = e->items[i].data; k++; }
    }
    return k;
}

/* ---- seccomp-BPF self-filter (M1190) ------------------------------------------
 * Install a bpf.c program that vets the calling process's own syscalls. One-way
 * (privilege drop can't be undone); inherited across fork. `prog` is a verified
 * user pointer (the syscall ubuf-validated it). 0/-1. */
int app_seccomp_filter_install(const void *progv, int n) {
    struct app *a = cur(); if (!a) return -1;
    const struct bpf_insn *prog = (const struct bpf_insn *)progv;
    if (n <= 0 || n > BPF_MAXINSN || bpf_verify(prog, n) != 0) return -1;
    for (int i = 0; i < n; i++) a->seccomp_prog[i] = prog[i];
    a->seccomp_n = n;
    return 0;
}
/* Is fd in this app's table a redirected pipe? SYS_read/SYS_write consult this to
 * route stdio (fd 0/1/2) through the fd table when redirected, else the window
 * grid / keyboard. An app that never redirects has an empty table -> always the
 * default path, byte-identical (M1191). */
int app_fd_is_redirected(app_t *ap, int fd) {
    struct app *a = (struct app *)ap;
    return a && fd >= 0 && fd < APP_NFD && a->fd[fd].used &&
           (a->fd[fd].type == 1 || a->fd[fd].type == 2 || a->fd[fd].type == 3);   /* pipe (M1187) / file (M1193) / memfd (M1212) */
}
/* poll(2) readiness for one fd (M1210). Returns the subset of `events`
 * (POLLIN/POLLOUT) that won't block right now. A pipe read-end is POLLIN-ready
 * iff data or EOF; a pipe write-end is POLLOUT-ready iff space. A file fd never
 * blocks (positioned r/w), so it reports both. An unopened fd -> POLLNVAL. */
int app_fd_ready(app_t *ap, int fd, int events) {
    struct app *a = (struct app *)ap;
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return POLLNVAL;
    int re = 0;
    if (a->fd[fd].type == 2) {                              /* file: never blocks */
        if (events & POLLIN)  re |= POLLIN;
        if (events & POLLOUT) re |= POLLOUT;
    } else if (a->fd[fd].type == 1) {                       /* pipe end */
        if (a->fd[fd].write_end) {
            if ((events & POLLOUT) && pipe_writable(a->fd[fd].obj)) re |= POLLOUT;
        } else {
            if ((events & POLLIN) && pipe_readable(a->fd[fd].obj)) re |= POLLIN;
        }
    } else if (a->fd[fd].type == 4) {                      /* timerfd: POLLIN at/after expiry (M1217) */
        if ((events & POLLIN) && a->fd[fd].off != 0 && (uint64_t)timer_ms() >= (uint64_t)a->fd[fd].off) re |= POLLIN;
    } else if (a->fd[fd].type == 5) {                      /* eventfd: POLLIN when counter>0, always writable (M1242) */
        if ((events & POLLIN) && a->fd[fd].off > 0) re |= POLLIN;
        if (events & POLLOUT) re |= POLLOUT;
    } else if (a->fd[fd].type == 7) {                      /* pidfd: POLLIN once the target process has exited (M1222) */
        if ((events & POLLIN) && !app_pid_alive(a->fd[fd].obj)) re |= POLLIN;
    } else if (a->fd[fd].type == 8) {                      /* inotify: POLLIN when events are queued (M1266) */
        if ((events & POLLIN) && inotify_ready(a->fd[fd].obj)) re |= POLLIN;
    } else if (a->fd[fd].type == 11) {                     /* pty: POLLIN when readable, always writable (M1274) */
        if ((events & POLLIN) && pty_ready(a->fd[fd].obj)) re |= POLLIN;
        if (events & POLLOUT) re |= POLLOUT;
    } else {
        return POLLNVAL;
    }
    return re;
}
/* pidfd (M1222): a pid-reuse-aware-ish process handle as an fd. It stores the
 * target pid (a plain value — no shared object, so fork/dup2 just copy it and
 * close needs no teardown). poll/epoll report POLLIN once the process has
 * exited (app_pid_alive goes false), so a server can wait on child exits in the
 * same loop as its sockets/timers. */
int app_pidfd_open(int pid) {
    struct app *a = cur(); if (!a) return -1;
    if (!app_pid_alive(pid)) return -1;                    /* must name a live process */
    int fd = -1; if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }   /* RLIMIT_NOFILE (M1547) */
    if (fd < 0) return -1;
    a->fd[fd] = (struct fdent){ 1, 7, 0, pid, {0}, 0, 0 };  /* used, type=pidfd, obj=pid */
    return fd;
}
int app_pidfd_send_signal(int pidfd, int sig) {
    struct app *a = cur();
    if (!a || pidfd < 0 || pidfd >= APP_NFD || !a->fd[pidfd].used || a->fd[pidfd].type != 7) return -1;
    struct app *t = app_by_pid(a->fd[pidfd].obj);
    if (!t || t->exited) return -1;                        /* gone: ESRCH */
    app_request_signal(t, sig);
    return 0;
}
/* pidfd_getfd (M1281): duplicate descriptor `targetfd` from the process named by
 * `pidfd` into the caller's fd table — the container/debugger primitive for
 * reaching into another process's open files. Snapshots the target's fdent,
 * sharing the underlying object (same model as SCM_RIGHTS, M1265). Returns the
 * new fd, or -1 (bad pidfd / dead target / bad targetfd / table full). */
int app_pidfd_getfd(int pidfd, int targetfd) {
    struct app *a = cur();
    if (!a || pidfd < 0 || pidfd >= APP_NFD || !a->fd[pidfd].used || a->fd[pidfd].type != 7) return -1;
    struct app *t = app_by_pid(a->fd[pidfd].obj);
    if (!t || t->exited || targetfd < 0 || targetfd >= APP_NFD || !t->fd[targetfd].used) return -1;
    int fd = -1; if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }   /* RLIMIT_NOFILE (M1547) */
    if (fd < 0) return -1;
    a->fd[fd] = t->fd[targetfd];                           /* snapshot (shares the underlying object) */
    a->fd[fd].cloexec = 0;                                 /* a freshly-obtained fd is not close-on-exec */
    return fd;
}
/* getdents64 (M1223): pack the cwd's entries as Linux dirent64 records starting
 * at index `start`. d_type comes from vfs_list's trailing-'/' dir marker (the
 * convention the real filesystems use). Returns bytes written (0 = no more from
 * `start`), or -1; the caller resumes from the last record's d_off. */
long app_getdents64(void *buf, unsigned long max, int start) {
    vfs_dirent ents[128];
    int n = vfs_list(ents, 128);
    if (n < 0) return -1;
    unsigned long off = 0;
    for (int i = (start < 0 ? 0 : start); i < n; i++) {
        const char *nm = ents[i].name;
        int nl = 0; while (nm[nl]) nl++;
        int isdir = (nl > 0 && nm[nl - 1] == '/');
        int dlen = isdir ? nl - 1 : nl;                          /* strip the dir marker from d_name */
        unsigned short reclen = (unsigned short)((19 + (unsigned)dlen + 1 + 7) & ~7u);
        if (off + reclen > max) break;                           /* full: caller resumes from d_off */
        unsigned char *rec = (unsigned char *)buf + off;
        *(unsigned long  *)(rec +  0) = (unsigned long)(i + 1);  /* d_ino (synthetic: 1-based index) */
        *(long           *)(rec +  8) = (long)(i + 1);           /* d_off: next start index */
        *(unsigned short *)(rec + 16) = reclen;                  /* d_reclen */
        rec[18] = isdir ? DT_DIR : DT_REG;                       /* d_type */
        for (int k = 0; k < dlen; k++) rec[19 + k] = (unsigned char)nm[k];
        rec[19 + dlen] = 0;
        off += reclen;
    }
    return (long)off;
}
/* prctl (M1225): PR_SET_NAME / PR_GET_NAME — a process renames itself at runtime
 * (visible in ps + /proc/<pid>/comm). The name lives in the existing titlebuf
 * (<=15 chars). The user pointers were validated by the syscall dispatch. */
long app_prctl(int option, uint64_t arg2) {
    struct app *a = cur(); if (!a) return -1;
    if (option == PR_SET_NAME) {
        const char *nm = (const char *)arg2; if (!nm) return -1;
        int i = 0; while (nm[i] && i < 15) { a->titlebuf[i] = nm[i]; i++; }
        a->titlebuf[i] = 0; a->title = a->titlebuf;
        return 0;
    }
    if (option == PR_GET_NAME) {
        char *out = (char *)arg2; if (!out) return -1;
        const char *t = a->title ? a->title : "";
        int i = 0; while (t[i] && i < 15) { out[i] = t[i]; i++; } out[i] = 0;
        return 0;
    }
    /* PR_SET_PDEATHSIG/PR_GET_PDEATHSIG (M1562): ask to be sent a signal when
     * THIS process's parent dies -- delivered from app_reap's death path via
     * app_notify_pdeathsig, same opt-in app_request_signal every other async
     * signal here goes through (0 disables; a signal number with no handler
     * installed is simply dropped, matching this codebase's usual default). */
    if (option == PR_SET_PDEATHSIG) { a->pdeathsig = (int)arg2; return 0; }
    if (option == PR_GET_PDEATHSIG) {
        int *out = (int *)arg2; if (!out) return -1;
        *out = a->pdeathsig;
        return 0;
    }
    return -1;
}
/* splice(in_fd, out_fd, len): move bytes from a pipe read-end fd to a pipe
 * write-end fd, entirely in-kernel (no userspace bounce) (M1211). bytes/0/-1. */
long app_splice(int in_fd, int out_fd, unsigned long len) {
    struct app *a = cur(); if (!a) return -1;
    int i = fd_pipe_idx(a, in_fd, 0), o = fd_pipe_idx(a, out_fd, 1);
    if (i < 0 || o < 0) return -1;
    return pipe_splice(i, o, len);
}
/* tee(in_fd, out_fd, len): copy bytes between two pipe fds without consuming the
 * source (M1211). bytes/0/-1. */
long app_tee(int in_fd, int out_fd, unsigned long len) {
    struct app *a = cur(); if (!a) return -1;
    int i = fd_pipe_idx(a, in_fd, 0), o = fd_pipe_idx(a, out_fd, 1);
    if (i < 0 || o < 0) return -1;
    return pipe_tee(i, o, len);
}
int app_seccomp_filter_active(app_t *ap) { return ap && ((struct app *)ap)->seccomp_n > 0; }
/* Raw verdict for one syscall (M1190; M1192 adds KILL). The program reads ctx
 * fields 0..3 = syscall nr + the low 32 bits of args 0..2 (LDCTX) and RETs:
 *   0 = DENY (the syscall returns -1), 2 = KILL (the process is terminated),
 *   anything else = ALLOW. The dispatch interprets the value. */
long app_seccomp_filter_check(app_t *ap, uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2) {
    struct app *a = (struct app *)ap;
    struct bpf_ctx ctx = { (uint32_t)nr, (uint32_t)a0, (uint32_t)a1, (uint32_t)a2, 0 };
    return bpf_run_prog(a->seccomp_prog, a->seccomp_n, &ctx);
}
/* fork: the child inherits the parent's fds (each shared end gains a reference). */
static void app_fd_fork(struct app *child, struct app *parent) {
    for (int i = 0; i < APP_NFD; i++) {
        child->fd[i] = parent->fd[i];
        if (parent->fd[i].used && parent->fd[i].type == 1) pipe_open_end(parent->fd[i].obj, parent->fd[i].write_end);
        else if (parent->fd[i].used && parent->fd[i].type == 3) memfd_ref(parent->fd[i].obj);   /* memfd inherited (M1212) */
        else if (parent->fd[i].used && parent->fd[i].type == 6) epoll_ref(parent->fd[i].obj);   /* epoll inherited (M1220) */
        else if (parent->fd[i].used && parent->fd[i].type == 8) inotify_ref(parent->fd[i].obj);        /* inotify inherited (M1603) */
        else if (parent->fd[i].used && parent->fd[i].type == 10) net_tcp_sock_ref(parent->fd[i].obj);  /* TCP socket inherited (M1603) */
    }
}
/* exit/reap: close every fd the process still held. Must mirror app_fd_close's
 * own dispatch (M1602) -- this only ever handled pipes, so a process that
 * exited without itself calling close() on a memfd/epoll/inotify/TCP-socket
 * fd leaked that global table's slot permanently (TCPSOCK_N is just 2, so
 * two such exits exhausted socket() for the whole OS until reboot). Type 11
 * (pty) is deliberately NOT here: it's already released by pid, not by fd,
 * via pty_release_pid() a few lines up in app_reap -- adding it here would
 * double-close it. */
static void app_fd_release(struct app *a) {
    for (int i = 0; i < APP_NFD; i++) if (a->fd[i].used) {
        if (a->fd[i].type == 1) pipe_close_end(a->fd[i].obj, a->fd[i].write_end);
        else if (a->fd[i].type == 3) memfd_unref(a->fd[i].obj);
        else if (a->fd[i].type == 6) epoll_unref(a->fd[i].obj);
        else if (a->fd[i].type == 8) inotify_free(a->fd[i].obj);
        else if (a->fd[i].type == 10) net_tcp_sock_close(a->fd[i].obj);
        a->fd[i].used = 0;
    }
}

/* COW fork() (M1116). Clone the calling process: a new app_t with its own blank
 * window, a copy-on-write clone of the address space (vmm_fork_cow), and a child
 * task that resumes at the parent's instruction after `int 0x80` with rax = 0.
 * The parent returns the child's pid. `r` is the parent's live trap frame. */
/* COW fork, optionally giving the CHILD a different stack pointer (M1958).
 *
 * child_rsp != 0 serves clone(CLONE_VM|CLONE_VFORK, stack) -- the shape
 * glibc's posix_spawn uses, and therefore the one GNU make needs to run a
 * recipe. We deliberately do NOT share the address space: the child gets a COW
 * copy and resumes at the same RIP with rax=0 and rsp=stack, which is exactly
 * what glibc's clone wrapper expects (it pops the function pointer off that
 * stack and calls it). Honouring CLONE_VM literally would mean the child's
 * execve tears down the address space its PARENT is still running in.
 *
 * The one real divergence: with CLONE_VM the child reports an exec failure by
 * writing an errno into memory the parent can see, and a COW copy loses that
 * write. The child still _exit(127)s, so a failed exec surfaces in the wait
 * status -- which is what make actually reports on. */
long app_fork_at(struct registers *r, uint64_t child_rsp) {
    struct app *p = cur();
    if (!p || !r) return -1;

    if (p->rlim_nproc) {                                /* RLIMIT_NPROC: cap this process's live children (M1163) */
        uint64_t nch = 0;
        for (int i = 0; i < MAX_APPS; i++) if (apps[i].used && !apps[i].exited && apps[i].parent == p->pid) nch++;
        if (nch >= p->rlim_nproc) return -1;            /* at the limit -> EAGAIN */
    }

    struct app *a = 0;
    for (int i = 0; i < MAX_APPS; i++) if (!apps[i].used) { a = &apps[i]; break; }
    if (!a) return -1;                                  /* process table full */

    memset(a, 0, sizeof(*a));
    a->used = 1;
    a->pid = next_pid++;                                /* a FRESH pid (not the parent's) */
    /* title: the parent's, marked as a fork */
    int ti = 0; const char *pt = p->title ? p->title : "app";
    while (pt[ti] && ti < 16) { a->titlebuf[ti] = pt[ti]; ti++; }
    const char *sfx = " (fork)"; for (int s = 0; sfx[s] && ti < 23; s++) a->titlebuf[ti++] = sfx[s];
    a->titlebuf[ti] = 0; a->title = a->titlebuf;
    grid_clear(a);

    /* Build the child's address space as a COW clone of the parent (current). */
    a->cr3 = vmm_create_address_space();
    if (!a->cr3) { a->used = 0; return -1; }
    vdso_map(a->cr3);                                   /* the RO vDSO page (shared, RO — not COW) */
    if (vmm_fork_cow(a->cr3) != 0) { vmm_destroy_address_space(a->cr3); a->used = 0; return -1; }

    /* Inherit the parent's process state (NOT its window/grid/task/identity). */
    a->entry = p->entry; a->ustack = p->ustack; a->heap_end = p->heap_end;
    a->mmap_next = p->mmap_next; a->nvma = p->nvma; a->aslr_mmap_base = p->aslr_mmap_base;   /* inherit the ASLR layout across fork (M1287) */
    for (int i = 0; i < APP_MAXVMA; i++) a->vma[i] = p->vma[i];
    for (int i = 0; i < APP_NSIG; i++) a->sig_handler[i] = p->sig_handler[i];
    a->sig_restorer = p->sig_restorer; a->curcol = p->curcol;
    a->rlim_nproc = p->rlim_nproc;                      /* RLIMIT_NPROC is inherited across fork (M1163) */
    a->rlim_as = p->rlim_as; a->rlim_data = p->rlim_data;   /* RLIMIT_AS/DATA inherited too (M1164) */
    a->rlim_nofile = p->rlim_nofile;                    /* RLIMIT_NOFILE inherited too (M1547) */
    a->rlim_cpu = p->rlim_cpu;                          /* RLIMIT_CPU inherited too (M1548) */
    a->rlim_fsize = p->rlim_fsize;                      /* RLIMIT_FSIZE inherited too (M1549) */
    a->rlim_memlock = p->rlim_memlock;                  /* RLIMIT_MEMLOCK inherited too (M1550) */
    a->rlim_core = p->rlim_core;                        /* RLIMIT_CORE inherited too (M1551) */
    /* sandbox is inherited (a child can't escape its parent's pledge/unveil) */
    a->promises = p->promises; a->pledged = p->pledged;
    a->nuv = p->nuv; a->uv_active = p->uv_active; a->uv_locked = p->uv_locked;
    for (int i = 0; i < APP_NUNVEIL; i++) a->uv[i] = p->uv[i];
    int li = 0; while (p->launch_arg[li] && li < 127) { a->launch_arg[li] = p->launch_arg[li]; li++; }
    a->launch_arg[li] = 0;
    a->parent = p->pid;                                 /* so the parent can waitpid() us (M1117) */
    a->pgid = p->pgid; a->sid = p->sid;                 /* fork inherits the parent's group + session (M1176) */
    a->ns_id  = p->ns_id;                               /* inherit the parent's mount namespace (shared; unshare detaches) (M1122) */
    vfs_cwd_inherit(a);                                 /* inherit the parent's current directory (M1144) */
    /* ...INCLUDING its path string. vfs_cwd_inherit copies the mount-relative
     * cwd but not cwd_path, so a forked child's getcwd(2) reported "/" -- and
     * once lx_xlate started resolving relative paths against it, every
     * relative path in a forked child resolved against the wrong root. cc1 is
     * forked by the gcc driver and writes "./ccXXXXXX.s". (M1960) */
    { int ci = 0; for (; p->cwd_path[ci] && ci < (int)sizeof a->cwd_path - 1; ci++) a->cwd_path[ci] = p->cwd_path[ci];
      a->cwd_path[ci] = 0; }
    app_fd_fork(a, p);                                   /* inherit the parent's open fds/pipes (M1187) */
    a->seccomp_n = p->seccomp_n;                          /* inherit the parent's seccomp filter (M1190) */
    for (int i = 0; i < p->seccomp_n && i < BPF_MAXINSN; i++) a->seccomp_prog[i] = p->seccomp_prog[i];
    /* NOT inherited (POSIX): pending signals, alarms, strace, gfx-mode canvas. */

    /* The child's resume context: the parent's trap frame, but returning 0. */
    a->fork_frame = *r;
    a->fork_frame.rax = 0;
    if (child_rsp) a->fork_frame.rsp = child_rsp;       /* clone() with a caller-supplied child stack */
    a->fork_frame.rflags |= 0x200;                      /* ensure IF is set in ring 3 */

    a->task = task_create_stack(fork_child_trampoline, a->cr3, a, 256 * 1024);
    if (!a->task) { vmm_destroy_address_space(a->cr3); a->used = 0; return -1; }
    /* copy the parent's live FP/SSE state so a child mid-float-computation is correct */
    task_copy_fpu(a->task, p->task);
    task_copy_tls(a->task, p->task);   /* the child must see the parent's %fs base (M1949) */

    /* give the child its own window (the WM consumes the pending queue) */
    int n = (pend_h + 1) % MAX_APPS;
    if (n != pend_t) { pending[pend_h] = a; pend_h = n; }
    return a->pid;
}

long app_fork(struct registers *r) { return app_fork_at(r, 0); }

/* clone (M1138): create a THREAD — a task sharing this process's address space
 * (same CR3, same app_t) that begins in ring 3 at fn(arg) on `stack`. Unlike
 * fork (a separate COW address space), threads share ALL memory, so they can
 * cooperate on shared data (the hardware `lock` prefix gives atomicity). It runs
 * concurrently under the existing preemptive scheduler and ends via
 * SYS_thread_exit. Returns the new thread id (its task id), or -1. `r` is the
 * caller's live trap frame (we inherit its user segment selectors + rflags).
 *
 * No window, no new app_t: the thread shares the caller's window for output.
 * Race-free because the int-0x80 gate keeps IF=0 through here, so the new task
 * can't be scheduled until we've stored its start_frame and returned. */
long app_clone(struct registers *r, uint64_t fn, uint64_t stack, uint64_t arg) {
    struct app *a = cur();
    if (!a || !r || !fn || !stack) return -1;
    struct registers *f = kmalloc(sizeof *f);
    if (!f) return -1;
    *f = *r;
    f->rip = fn; f->rsp = stack; f->rdi = arg; f->rax = 0;
    f->rflags |= 0x200;                                 /* IF set in ring 3 */
    task_t *t = task_create_stack(thread_trampoline, a->cr3, a, 256 * 1024);   /* SHARED cr3 + app. 256K (was 64K): a clone'd thread that calls sys_https runs the bignum/RSA TLS handshake on THIS kernel stack — the ring-3 browser's async fetch worker does exactly that, and 64K overflowed (corrupting the task ring -> task_wake_sleepers GPF). Matches the in-kernel browser worker's 256K. */
    if (!t) { kfree(f); return -1; }
    t->start_frame = f;
    for (int i = 0; i < APP_MAXTHREAD; i++) if (!a->thr[i]) { a->thr[i] = t; break; }   /* track for join/reap (M1139) */
    return t->id;
}

/* Linux clone(2) for a THREAD (M1959).
 *
 * The difference from app_clone is the entry convention, and it is the whole
 * reason this exists: our native clone starts the new thread at fn(arg),
 * whereas Linux's clone RETURNS IN THE CHILD -- same RIP as the parent, rax 0,
 * rsp the caller's stack. glibc's pthread_create relies on exactly that: its
 * wrapper checks rax and branches to the start routine itself.
 *
 * Everything else the thread layer already had (M1138/M1226): a task sharing
 * this process's CR3 and app_t, a per-task %fs base, and CLONE_CHILD_CLEARTID
 * zeroing + FUTEX_WAKE'ing the tid word on exit, which is what a blocking
 * pthread_join waits on.
 *
 * Returns the new tid, or -1. */
#define LXC_SETTLS          0x00080000
#define LXC_PARENT_SETTID   0x00100000
#define LXC_CHILD_CLEARTID  0x00200000
#define LXC_CHILD_SETTID    0x01000000
long app_clone_linux(struct registers *r, unsigned long flags, uint64_t stack,
                     uint64_t ptid, uint64_t ctid, uint64_t tls) {
    struct app *a = cur();
    if (!a || !r || !stack) return -1;
    /* Refuse when the thread table is full rather than creating a task nothing
     * can join or reap. */
    int slot = -1;
    for (int i = 0; i < APP_MAXTHREAD; i++) if (!a->thr[i]) { slot = i; break; }
    if (slot < 0) return -1;

    struct registers *f = kmalloc(sizeof *f);
    if (!f) return -1;
    *f = *r;
    f->rsp = stack;
    f->rax = 0;                                         /* the child's clone() returns 0 */
    f->rflags |= 0x200;                                 /* IF set in ring 3 */
    task_t *t = task_create_stack(thread_trampoline, a->cr3, a, 256 * 1024);   /* SHARED cr3 + app */
    if (!t) { kfree(f); return -1; }
    t->start_frame = f;
    /* TLS: CLONE_SETTLS carries the new thread's %fs base. Without it a thread
     * would inherit the CREATOR's TLS block and every __thread variable in it
     * would alias the parent's. */
    t->fs_base = (flags & LXC_SETTLS) ? tls : task_fs_base();
    if (flags & LXC_CHILD_CLEARTID) t->clear_child_tid = ctid;
    if ((flags & LXC_CHILD_SETTID) && vmm_user_ok(ctid, 4)) *(volatile int *)ctid = t->id;
    /* PARENT_SETTID is written HERE, in the parent, before we return -- the
     * caller may read it the instant clone() returns, and the child may not
     * have run yet. */
    if ((flags & LXC_PARENT_SETTID) && vmm_user_ok(ptid, 4)) *(volatile int *)ptid = t->id;
    a->thr[slot] = t;
    return t->id;
}

/* Is the calling task this process's MAIN thread? exit(2) ends one thread,
 * exit_group(2) ends the process -- and the main thread calling exit(2) must
 * end the process, or a program that returns from main would leave a husk
 * behind that nothing ever reaps. (M1959) */
int app_is_main_thread(void) {
    struct app *a = cur();
    return !a || !a->task || a->task == task_self();
}

/* End just the calling thread's task (not the whole process). M1138. Before
 * exiting, honour robust futexes (M1141): if this thread holds any robust locks,
 * mark each OWNER_DIED and wake a waiter, so a peer recovers the lock instead of
 * blocking on it forever. The list lives in this thread's (still-mapped) user
 * memory; we bound the count and validate every pointer before touching it. */
void app_thread_exit(void) {
    uint64_t rp = task_robust();
    if (rp && vmm_user_ok(rp, sizeof(robust_t))) {
        robust_t *r = (robust_t *)rp;
        int n = r->n, tid = task_current_id();
        if (n < 0) n = 0;
        if (n > ROBUST_MAX) n = ROBUST_MAX;
        for (int i = 0; i < n; i++) {
            uint64_t fa = (uint64_t)r->held[i];
            if (!vmm_user_ok(fa, 4)) continue;
            volatile int *w = (volatile int *)fa;
            if ((*w & FUTEX_TID_MASK) == tid) {        /* a lock we still hold */
                *w |= FUTEX_OWNER_DIED;
                app_futex(fa, FUTEX_WAKE, 1, -1);          /* wake one waiter to recover it */
            }
        }
    }
    /* CLONE_CHILD_CLEARTID (M1226): zero the registered tid address + wake any
     * futex waiter on it — the kernel side of a real blocking pthread_join. Done
     * here while the dying thread's CR3 is active (threads share the AS). */
    uint64_t ct = task_self()->clear_child_tid;
    if (ct && vmm_user_ok(ct, 4)) { *(volatile int *)ct = 0; app_futex(ct, FUTEX_WAKE, 1, -1); }
    task_exit();
}

/* set_tid_address (M1226): register the address the kernel zeroes + FUTEX_WAKEs
 * on this thread's exit (what glibc/musl pthread_join blocks on). Returns the tid. */
long app_set_tid_address(uint64_t tidptr) {
    task_t *t = task_self(); if (!t) return -1;
    t->clear_child_tid = tidptr;
    return task_current_id();
}

/* The calling thread's id = its task id (each thread is a distinct task). M1138. */
int app_gettid(void) { return task_current_id(); }

/* join (M1139): block until thread `tid` (of this process) has exited, then reap
 * its task (freeing the struct+kstack a finished thread would otherwise leak).
 * 0 on success, -1 if `tid` isn't a thread of this process. */
long app_join(int tid) {
    struct app *a = cur();
    if (!a) return -1;
    int slot = -1;
    for (int i = 0; i < APP_MAXTHREAD; i++) if (a->thr[i] && a->thr[i]->id == tid) { slot = i; break; }
    if (slot < 0) return -1;
    task_t *t = a->thr[slot];
    __asm__ volatile("sti");                        /* the poll sleeps on the timer */
    while (t->state != TASK_DEAD) task_sleep_ms(5); /* wait for the thread to exit (it switches off-CPU first) */
    a->thr[slot] = 0;                               /* drop our reference before freeing */
    task_free(t);                                   /* DEAD + unlinked + off-CPU -> safe to reap */
    return 0;
}

/* exec() (M1121): replace the CURRENT process's program image with the registered
 * program `name`, in place — same pid, same task, same window. Loads the new ELF
 * into a fresh address space, switches to it, frees the old, resets the program
 * state, and rewrites the trap frame `r` to enter the new program. On success it
 * does NOT return to the old program (the rewritten frame iretq's into the new
 * one); returns -1 (frame untouched) on failure, so the caller's exec()
 * "returns -1" like POSIX. The pid/parent/pledge sandbox are preserved. */
long app_exec(struct registers *r, const char *name, const char *arg) {
    struct app *a = cur();
    if (!a || !r || !name) return -1;

    const void *elf = 0; const char *title = 0;
    for (int i = 0; i < NPROGS; i++) {
        const char *pa = progs[i].name, *pb = name; int eq = 1;
        while (*pa && *pb) { if (*pa++ != *pb++) { eq = 0; break; } }
        if (eq && !*pa && !*pb) { elf = progs[i].elf; title = progs[i].title; break; }
    }
    uint64_t img_sz = ~0ull;
    if (a->exec_img) { elf = a->exec_img; img_sz = a->exec_imgsz; title = name; }   /* execve (M1948/M1952) */
    if (!elf) return -1;                                /* no such program */

    /* Consume the mapped-load / interpreter one-shots here, before anything
     * can re-enter. app_execve_linux still owns the interpreter buffer and
     * frees it when we return, so this only borrows it. (M1958) */
    char exec_mappath[VFS_PATH_MAX];
    { int mi = 0; while (g_pend_mappath[mi] && mi < VFS_PATH_MAX - 1) { exec_mappath[mi] = g_pend_mappath[mi]; mi++; }
      exec_mappath[mi] = 0; }
    uint64_t exec_mapsize = g_pend_mapsize;
    void *exec_interp = g_pend_interp; unsigned long exec_interp_sz = g_pend_interp_sz;

    uint64_t new_cr3 = vmm_create_address_space();
    if (!new_cr3) return -1;
    vdso_map(new_cr3);

    uint64_t old_cr3 = a->cr3;
    app_msync(0, (uint64_t)-1);              /* flush the OLD image's dirty MAP_SHARED pages first (M1602) --
                                               * MUST run before the cr3 switch below: app_msync dereferences
                                               * each dirty page as a plain pointer through whatever address
                                               * space is currently active, so it has to run while the OLD
                                               * image (not the new, not-yet-populated one) is still live */
    uint64_t flags;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(flags) :: "memory");
    __asm__ volatile("mov %0, %%cr3" : : "r"(new_cr3) : "memory");   /* become the new space */

    elf_lazy_range_t lazy[4]; int nlazy = 0;
    /* A mapped load registers VMAs as it goes, so a->nvma has to be reset
     * BEFORE it runs -- the reset further down would otherwise wipe the
     * segments it just mapped. Snapshotted so the fail path, which leaves the
     * caller running in its OLD address space, restores its VMA list. */
    int saved_nvma = a->nvma;
    uint64_t entry;
    if (exec_mappath[0]) {
        a->nvma = 0;
        entry = app_load_mapped(a, exec_mappath, elf, img_sz, exec_mapsize);
    } else {
        entry = elf_load(elf, img_sz, lazy, 4, &nlazy);
    }
    if (!entry) { a->nvma = saved_nvma; goto fail; }
    uint64_t prog_entry = entry, interp_base = 0;
    if (exec_interp) {
        /* Dynamically linked: map the interpreter too and enter IT. The
         * program's own entry still goes in the auxv as AT_ENTRY. (M1958) */
        uint64_t ie = elf_load_at(exec_interp, exec_interp_sz, ELF_INTERP_BASE);
        if (!ie) { a->nvma = saved_nvma; goto fail; }
        interp_base = ELF_INTERP_BASE;
        entry = ie;
    }
    for (int i = 1; i < USTACK_PAGES; i++) {   /* i=0 = unmapped guard page below the user stack (M1499) */
        uint64_t frame = pmm_alloc_frame();
        if (!frame) goto fail;
        if (vmm_map(USTACK_BASE + (uint64_t)i * PAGE_SIZE, frame, PTE_WRITABLE | PTE_USER | PTE_NX) != 0) {
            pmm_free_frame(frame); goto fail;
        }
    }

    /* committed: we are now the new program. Free the OLD space (non-active now). */
    vmm_destroy_address_space(old_cr3);
    a->cr3 = new_cr3; a->task->cr3 = new_cr3;
    a->entry = entry; a->ustack = USTACK_BASE + USTACK_PAGES * PAGE_SIZE;

    /* A Linux execve needs argc/argv/envp/auxv on the stack, built HERE while
     * the new address space is active and its stack pages are mapped -- the
     * same frame app_spawn builds, but with the caller's argv rather than a
     * synthesised one. (M1948) */
    if (a->exec_argv) {
        uint64_t rsp = lx_spawn_stack_dyn(elf, ELF_DYN_BASE, prog_entry, interp_base,
                                          a->ustack, USTACK_BASE + PAGE_SIZE,
                                          a->exec_argv, a->exec_envp);
        /* A failure here must be FATAL, not a fallback. The old code kept the
         * bare stack top on failure -- but that address is USTACK_BASE +
         * USTACK_PAGES*PAGE_SIZE, i.e. one page PAST the last mapped stack
         * page, so the new image entered ring 3 with an unmapped RSP and took
         * an immediate page fault at CR2=0x50081000. Silently entering a
         * program at a bad stack is far worse than refusing the exec. */
        if (!rsp) { kprintf("[linuxabi] execve: could not build the initial stack\n"); goto fail; }
        a->ustack = rsp;
    }

    /* reset per-program state (the new image starts clean); keep pid/parent/pledge */
    a->heap_end = 0; a->mlock_future = 0;   /* mlockall(MCL_FUTURE) does not survive exec (M1283) */
    /* NOT unconditional any more: a mapped load already reset nvma and then
     * FILLED it with the new image's segments, so zeroing here would throw
     * them away and every page of the new program would fault unbacked. */
    if (!exec_mappath[0]) a->nvma = 0;
    /* Register the NEW image's deferred whole-BSS range(s) (see app_spawn) —
     * done here, after a->nvma was just reset above, not right after elf_load
     * ran (which is before this reset would wipe them back out). */
    for (int li = 0; li < nlazy && a->nvma < APP_MAXVMA; li++) {
        VMA_NEW(a);
        a->vma[a->nvma].start = lazy[li].start; a->vma[a->nvma].len = lazy[li].len;
        a->vma[a->nvma].sealed = 0; a->vma[a->nvma].uffd = 0;
        a->vma[a->nvma].file_backed = 0; a->vma[a->nvma].locked = 0; a->vma[a->nvma].huge = 0;
        a->nvma++;
    }
    a->aslr_mmap_base = aslr_mmap_pick(); a->mmap_next = a->aslr_mmap_base;   /* ASLR: a fresh randomized mmap base per exec (M1287) */
    for (int i = 0; i < APP_NSIG; i++) a->sig_handler[i] = 0;
    a->sig_in = 0; a->pending_sigs = 0; a->sig_blocked = 0; a->sigfd_armed = 0; a->sigfd_mask = 0; a->alarm_interval = 0; a->alarm_next = 0;
    a->sigq_n = 0;                                                  /* drop any queued RT-signal payloads (M1271) */
    a->sig_alt_base = 0; a->sig_alt_size = 0;                       /* the alternate signal stack is gone across exec (M1276) */
    for (int i = 0; i < APP_NPTIMER; i++) a->ptimer[i].used = 0;    /* POSIX timers are not preserved across exec (M1272) */
    if (a->gfx) { kfree(a->gfx); a->gfx = 0; a->gfx_w = a->gfx_h = 0; }
    int ti = 0; if (title) while (title[ti] && ti < 23) { a->titlebuf[ti] = title[ti]; ti++; }
    a->titlebuf[ti] = 0; a->title = a->titlebuf;
    int ei = 0; if (name) while (name[ei] && ei < 63) { a->exe_path[ei] = name[ei]; ei++; }   /* exec'd path, for /proc/<pid>/exe (M1250) */
    a->exe_path[ei] = 0;
    int li = 0; if (arg) while (arg[li] && li < 127) { a->launch_arg[li] = arg[li]; li++; }
    a->launch_arg[li] = 0;
    for (int i = 0; i < APP_NFD; i++) if (a->fd[i].used && a->fd[i].cloexec) app_fd_close(i);   /* FD_CLOEXEC: drop on exec (M1218) */
    grid_clear(a);

    /* rewrite the trap frame to enter the new program (mirrors enter_user's iret frame) */
    r->r15 = r->r14 = r->r13 = r->r12 = r->r11 = r->r10 = r->r9 = r->r8 = 0;
    r->rbp = r->rdi = r->rsi = r->rdx = r->rcx = r->rbx = r->rax = 0;
    r->rip = entry; r->rsp = a->ustack; r->rflags = 0x202;   /* IF set */
    r->cs = 0x1B; r->ss = 0x23;                              /* USER_CS / USER_DS */

    __asm__ volatile("push %0; popfq" : : "r"(flags) : "memory", "cc");
    return 0;                                               /* frame rewritten; iretq enters the new program */

fail:
    __asm__ volatile("mov %0, %%cr3" : : "r"(old_cr3) : "memory");   /* restore the old space */
    __asm__ volatile("push %0; popfq" : : "r"(flags) : "memory", "cc");
    vmm_destroy_address_space(new_cr3);
    return -1;
}

/* Hardware single-step instruction trace (M1123). app_singlestep(n) arms the
 * next `n` userspace instructions: it sets the x86 TRAP flag in the syscall's
 * own return frame, so the iretq back to ring 3 traps after one instruction.
 * Each #DB (app_singlestep_trap, from the IDT) records the RIP and re-arms TF
 * until n instructions are traced, then clears it. The process reads its trace
 * back via /proc/<pid>/sstrace — the instruction-level complement to the syscall
 * strace ring (M1118), and the core of any single-step debugger. */
#define RFLAGS_TF (1ull << 8)

long app_singlestep(struct registers *r, int n) {
    struct app *a = cur();
    if (!a || !r) return -1;
    if (n < 1) n = 1;
    if (n > APP_SSTEP_N) n = APP_SSTEP_N;
    a->sstep_n = 0;
    a->sstep_remaining = n;
    r->rflags |= RFLAGS_TF;                  /* trap after the first instruction back in ring 3 */
    return n;
}

static long app_trace_stop(int signo);   /* fwd: defined with the ptrace block below (M1200) */

void app_singlestep_trap(struct registers *r) {
    struct app *a = cur();
    /* ptrace single-step (M1200): a PT_SINGLESTEP'd tracee traps here after one
     * instruction — re-stop it as SIGTRAP and notify the tracer, instead of the
     * /proc/sstrace recording path below. */
    if (a && a->ptraced && a->trace_stepping) {
        if (r) r->rflags &= ~RFLAGS_TF;
        a->trace_stepping = 0;
        app_trace_stop(SIGTRAP);
        return;
    }
    if (!a || a->sstep_remaining <= 0) {     /* not tracing (or a stray #DB): stop stepping, never kill */
        if (r) r->rflags &= ~RFLAGS_TF;
        return;
    }
    if (a->sstep_n < APP_SSTEP_N) a->sstep_rips[a->sstep_n++] = r->rip;
    if (--a->sstep_remaining > 0) r->rflags |= RFLAGS_TF;   /* more to step */
    else                          r->rflags &= ~RFLAGS_TF;  /* done */
}

int app_sstep_get(app_t *a, uint64_t *out, int max) {       /* copy the recorded RIPs; returns count */
    if (!a || !out) return 0;
    int n = a->sstep_n; if (n > max) n = max;
    for (int i = 0; i < n; i++) out[i] = a->sstep_rips[i];
    return n;
}

/* seccomp-notify (M1124): userspace syscall supervision. A child arms a set of
 * syscalls; when it calls one, syscall_dispatch parks it (app_seccomp_notify)
 * and a supervisor (typically the parent) reads the pending call
 * (app_seccomp_wait) and replies with allow / deny / emulate
 * (app_seccomp_reply).
 *
 * M1612: the two-way rendezvous now goes through app_wake_lock -- was "runs
 * interrupts-off... so there's no lost wakeup, the mailbox discipline",
 * exactly the assumption M1531 invalidated and M1608 already fixed in
 * mbox.c itself. Child and supervisor are two different processes, routinely
 * on two different cores. */
long app_seccomp_arm(int nr) {
    struct app *a = cur();
    if (!a || nr < 0 || nr >= 128) return -1;
    a->sc_mask[nr >> 6] |= (1ull << (nr & 63));
    a->sc_armed = 1;
    return 0;
}
int app_seccomp_traps(app_t *a, uint64_t nr) {
    return a && a->sc_armed && nr < 128 && (a->sc_mask[nr >> 6] & (1ull << (nr & 63))) != 0;
}
/* Park the calling (child) task with a pending notification; returns the verdict
 * value, and sets *run_real to whether the real syscall should still run. */
long app_seccomp_notify(app_t *a, uint64_t nr, uint64_t b1, uint64_t b2, uint64_t b3, int *run_real) {
    uint64_t f = irq_save();
    a->sc_nr = nr; a->sc_a = b1; a->sc_b = b2; a->sc_c = b3;
    a->sc_run_real = 1; a->sc_retval = 0;
    a->sc_pending = 1;
    if (a->sc_sup) { task_wake((task_t *)a->sc_sup); a->sc_sup = 0; }   /* wake a waiting supervisor */
    irq_restore(f);                                     /* released BEFORE blocking (M1612) */
    task_block();                                       /* the child blocks until the supervisor replies */
    *run_real = a->sc_run_real;
    return a->sc_retval;
}
/* Supervisor: block until childpid parks, then fill ev[4] = {nr,a,b,c}. 1/0/-1. */
long app_seccomp_wait(int childpid, uint64_t *ev) {
    struct app *c = app_by_pid(childpid);
    if (!c) return -1;                                  /* no such child */
    uint64_t f = irq_save();
    if (!c->sc_pending) {                               /* block until the child parks (even if not armed yet) */
        c->sc_sup = (void *)task_self();                /* register self as the waiter; the child's park wakes us */
        irq_restore(f);                                 /* released BEFORE blocking (M1612) */
        task_block();
        f = irq_save();
        c->sc_sup = 0;
    }
    int pending = c->sc_pending;
    uint64_t nr = c->sc_nr, a1 = c->sc_a, a2 = c->sc_b, a3 = c->sc_c;
    irq_restore(f);
    if (!pending) return 0;                             /* stray wake (e.g. the child exited without parking) */
    ev[0] = nr; ev[1] = a1; ev[2] = a2; ev[3] = a3;
    return 1;
}
/* Supervisor: deliver the verdict and resume the child. run_real!=0 lets the real
 * syscall run; otherwise the child's syscall returns `retval`. 0/-1. */
long app_seccomp_reply(int childpid, int run_real, long retval) {
    struct app *c = app_by_pid(childpid);
    if (!c) return -1;
    uint64_t f = irq_save();
    if (!c->sc_pending) { irq_restore(f); return -1; }
    c->sc_run_real = run_real; c->sc_retval = retval;
    c->sc_pending = 0;
    if (c->task) task_wake((task_t *)c->task);          /* resume the child */
    irq_restore(f);
    return 0;
}

/* ptrace (M1199): the canonical Unix process-tracing syscall. A tracer (the
 * parent) stops a tracee, reads/modifies its registers + memory, and continues
 * it — the mechanism strace/gdb are built on. Assembled from pieces already in
 * the tree: the stop/wait/cont rendezvous mirrors seccomp-notify above;
 * PEEK/POKE reuse app_process_vm_read/write (same-tree-gated, COW-aware); GETREGS
 * reuses the tracee's saved trap frame (task_uframe). The PT_* request codes are
 * shared with userspace in syscall.h.
 *
 * M1612: the stop/wait/cont rendezvous now goes through app_wake_lock -- was
 * "interrupts-off so there's no lost wakeup -- every ring-3 task is scheduled
 * on the BSP, so tracer and tracee never truly run at once", which is simply
 * false since M1531: task_create sets pin_core=-1 for every ordinary task
 * (only task 0, the desktop/WM, is BSP-pinned), and kernel/smp.c confirms
 * every AP joins the general scheduler -- a tracer and its tracee are two
 * ordinary tasks the CFS picker can and does place on two different cores. */

/* The tracee parks here, from its own raise() syscall, until the tracer resumes
 * it. Runs in the tracee's syscall trap context — safe to block, exactly like
 * app_seccomp_notify. */
static long app_trace_stop(int signo) {
    struct app *a = cur();
    uint64_t f = irq_save();
    a->trace_sig = signo;
    a->trace_stopped = 1;
    if (a->trace_sup) { task_wake((task_t *)a->trace_sup); a->trace_sup = 0; }  /* wake the tracer */
    irq_restore(f);                                 /* released BEFORE blocking (M1612) */
    task_block();                                  /* resumed by the tracer's PT_CONT */
    a->trace_stopped = 0;
    return 0;
}

/* SYS_raise hook: a traced process stops + notifies its tracer instead of taking
 * the signal's default action. Returns 1 (and blocks until continued) if traced. */
int app_trace_on_signal(app_t *a, int signo) {
    struct app *ap = (struct app *)a;
    if (!ap || !ap->ptraced) return 0;
    app_trace_stop(signo);
    return 1;
}

long app_ptrace(long req, int pid, uint64_t addr, uint64_t data) {
    struct app *me = cur();
    if (!me) return -1;
    if (req == PT_TRACEME) { me->ptraced = 1; return 0; }

    struct app *t = app_by_pid(pid);
    if (!t || t->parent != me->pid) return -1;     /* must be our own child */

    /* PT_WAIT blocks until the child enters a trace-stop. It must NOT require
     * ptraced upfront: the child may not have run PT_TRACEME yet (a fork-order
     * race), and registering as the waiter "even if not armed yet" — like
     * app_seccomp_wait — is what closes that race (the child's trace-stop wakes
     * us). The check-then-block goes through app_wake_lock (M1612), not BSP
     * co-scheduling — see the header comment above. */
    if (req == PT_WAIT) {
        uint64_t f = irq_save();
        if (!t->trace_stopped) {
            t->trace_sup = (void *)task_self();
            irq_restore(f);                 /* released BEFORE blocking (M1612) */
            task_block();
            f = irq_save();
            t->trace_sup = 0;
        }
        int stopped = t->trace_stopped, sig = t->trace_sig;
        irq_restore(f);
        return stopped ? sig : -1;
    }

    /* Every other request inspects/continues a child that must be traced AND
     * currently stopped (so its trap frame + memory are quiescent). */
    if (!t->ptraced || !t->trace_stopped) return -1;
    switch (req) {
    case PT_PEEKDATA: {                            /* read one word from the tracee's memory */
        uint64_t word = 0;
        if (app_process_vm_read(pid, addr, &word, sizeof word) != (long)sizeof word) return -1;
        return (long)word;
    }
    case PT_POKEDATA:                              /* write one word into the tracee's memory */
        return app_process_vm_write(pid, addr, &data, sizeof data) == (long)sizeof data ? 0 : -1;
    case PT_GETREGS: {                             /* copy the tracee's trap frame to the tracer's buffer */
        struct registers *u = task_uframe((task_t *)t->task);
        if (!u || !vmm_user_ok(addr, sizeof *u)) return -1;
        __builtin_memcpy((void *)addr, u, sizeof *u);
        return 0;
    }
    case PT_SETREGS: {                             /* write the tracee's registers from the tracer's buffer */
        struct registers *u = task_uframe((task_t *)t->task);
        if (!u || !vmm_user_ok(addr, sizeof *u)) return -1;
        struct registers nw; __builtin_memcpy(&nw, (void *)addr, sizeof nw);
        /* Preserve the privilege-critical fields so the tracee's iret stays
         * legal — the tracer may set the GP regs + rip + rsp, but not the
         * segment selectors; and sanitize rflags to the user-settable bits with
         * IF forced on (no IOPL/TF/NT changes from a SETREGS). */
        nw.cs = u->cs; nw.ss = u->ss; nw.int_no = u->int_no; nw.err_code = u->err_code;
        nw.rflags = (nw.rflags & 0x0CD5ull) | 0x202ull;
        *u = nw;
        return 0;
    }
    case PT_CONT: {                                 /* resume the stopped tracee */
        uint64_t f = irq_save();
        t->trace_stopped = 0;
        if (t->task) task_wake((task_t *)t->task);
        irq_restore(f);
        return 0;
    }
    case PT_SINGLESTEP: {                          /* resume for ONE instruction, then re-stop (SIGTRAP) */
        struct registers *u = task_uframe((task_t *)t->task);
        if (!u) return -1;
        u->rflags |= RFLAGS_TF;                    /* trap after the next instruction back in ring 3 */
        t->trace_stepping = 1;
        uint64_t f = irq_save();
        t->trace_stopped = 0;
        if (t->task) task_wake((task_t *)t->task);
        irq_restore(f);
        return 0;
    }
    }
    return -1;
}

/* Load and run an ELF program from a FAT32 file (e.g. `run calc.elf`). The ELF
 * bytes are read into a kernel buffer; app_spawn/elf_load copy the segments into
 * the new address space synchronously, so the buffer is freed right after. */
/* Load and run a LINUX static-PIE binary from a file. Same loader as our own
 * ELFs -- elf_load already dispatches ET_DYN to the PIE path -- but the new
 * process gets a real SysV initial stack, which a libc reads before main. */
/* Linux execve(2): replace this process's image with the ELF at `path`, and
 * enter it with a real System V stack carrying `argv`/`envp`. Reuses app_exec's
 * address-space machinery through the one-shot override above rather than
 * duplicating it. Returns only on FAILURE -- on success the trap frame has been
 * rewritten and the iretq at the end of the syscall enters the new image.
 * (M1948) */
long app_execve_linux(struct registers *r, const char *path,
                      const char *const *argv, const char *const *envp) {
    if (!r || !path) return -1;
    /* Dynamically linked? Stage its interpreter and switch to a mapped load,
     * exactly as the spawn path does -- this used to be spawn-only, so
     * execve of any dynamically-linked binary simply failed, which is what
     * `make` hit forking and exec'ing /usr/bin/cc1. (M1958) */
    if (lx_stage_interp(path) < 0) return -1;
    int exec_mapped = g_pend_mappath[0] != 0;

    /* Read the image BEFORE touching any process state: a failed read must
     * leave the caller running, which is what execve promises. */
    struct statx xst;
    unsigned long CAP = (vfs_stat(path, &xst) == 0 && xst.stx_size) ? (unsigned long)xst.stx_size : (1u << 20);
    if (exec_mapped && CAP > 8192) CAP = 8192;           /* headers only: the segments are mapped */
    if (CAP > (16u << 20)) { lx_drop_interp(); return -1; }   /* see app_spawn_from_file (M1952) */
    uint8_t *buf = kmalloc(CAP);
    if (!buf) { lx_drop_interp(); return -1; }
    long n = exec_mapped ? vfs_pread(path, buf, CAP, 0) : vfs_read(path, buf, CAP);
    if (n <= 0) { kfree(buf); lx_drop_interp(); return -1; }

    struct app *me = cur();
    if (!me) { kfree(buf); lx_drop_interp(); return -1; }
    me->exec_img = buf; me->exec_imgsz = (uint64_t)n;
    me->exec_argv = argv; me->exec_envp = envp;
    long rc = app_exec(r, path, 0);
    me->exec_img = 0; me->exec_imgsz = 0; me->exec_argv = 0; me->exec_envp = 0;
    lx_drop_interp();                       /* app_exec consumed it (or the exec failed) */

    /* Safe either way: app_exec copies the segments into the new address space
     * synchronously, so the image buffer is dead by the time it returns. */
    kfree(buf);
    return rc;
}

int app_spawn_linux_from_file_arg(const char *path, const char *arg) {
    /* Same one-shot the native app_spawn_named_arg uses; app_spawn consumes it
     * into a->launch_arg, which the Linux stack builder turns into argv[1]. */
    int ai = 0; if (arg) while (arg[ai] && ai < 127) { g_pend_arg[ai] = arg[ai]; ai++; }
    g_pend_arg[ai] = 0; g_have_pend = 1;
    int rc = app_spawn_linux_from_file(path);
    if (rc < 0) g_have_pend = 0;          /* spawn failed: don't leak the arg */
    return rc;
}

/* Is `path` dynamically linked? If so, read its interpreter into g_pend_interp
 * NOW and arrange for its segments to be mapped from the file.
 *
 * "NOW" is the point: app_spawn and app_exec both do their loading with
 * interrupts off and a foreign CR3 loaded, which is no place to start disk
 * I/O. Both call this first. Returns 1 dynamic, 0 static, -1 error (the
 * interpreter is named but missing, or out of memory). (M1954, shared M1958)
 *
 * Factoring this out is what made execve work for a dynamically-linked
 * binary: it lived inside the SPAWN path only, so `make` forking and exec'ing
 * /usr/bin/cc1 produced a bare _exit(127) with no diagnostic at all. */
static int lx_stage_interp(const char *path) {
    g_pend_interp = 0; g_pend_interp_sz = 0;
    g_pend_mappath[0] = 0; g_pend_mapsize = 0;
    /* vfs_pread, not vfs_read: this is a deliberate PARTIAL read of the first
     * pages, and some read paths refuse a buffer smaller than the file rather
     * than returning a short count. */
    uint8_t hdr[2048];
    long hn = vfs_pread(path, hdr, sizeof hdr, 0);
    char interp[192];
    if (hn <= 64 || !elf_interp_path(hdr, (uint64_t)hn, interp, sizeof interp)) return 0;

    /* The interpreter path is absolute in the LINUX process's world
     * (/lib64/...), so it needs the same /disk2 root prefix the ABI applies to
     * every other path. (M1954) */
    char ipath[256];
    { int k = 0; const char *pre = "/disk2";
      while (pre[k]) { ipath[k] = pre[k]; k++; }
      for (int j = 0; interp[j] && k < (int)sizeof ipath - 1; j++) ipath[k++] = interp[j];
      ipath[k] = 0; }
    struct statx ist;
    unsigned long isz = (vfs_stat(ipath, &ist) == 0 && ist.stx_size) ? (unsigned long)ist.stx_size : 0;
    if (!isz || isz > (16u << 20)) {
        kprintf("[linuxabi] %s needs interpreter %s (%s), which is missing\n", path, interp, ipath);
        return -1;                   /* refuse rather than enter a program that cannot start */
    }
    void *ib = kmalloc(isz);
    if (!ib) return -1;
    if (vfs_read(ipath, ib, isz) <= 0) { kfree(ib); return -1; }
    g_pend_interp = ib; g_pend_interp_sz = isz;

    /* ld.so does the relocating, so the kernel only has to PLACE the segments
     * -- map them from the file instead of buffering the whole image. (M1956) */
    struct statx mst;
    if (vfs_stat(path, &mst) == 0 && mst.stx_size) {
        int mi = 0; while (path[mi] && mi < VFS_PATH_MAX - 1) { g_pend_mappath[mi] = path[mi]; mi++; }
        g_pend_mappath[mi] = 0;
        g_pend_mapsize = (uint64_t)mst.stx_size;
    }
    kprintf("[linuxabi] %s is dynamically linked; loading %s\n", path, interp);
    return 1;
}

/* Release whatever lx_stage_interp reserved. Safe to call twice. */
static void lx_drop_interp(void) {
    if (g_pend_interp) kfree(g_pend_interp);
    g_pend_interp = 0; g_pend_interp_sz = 0;
    g_pend_mappath[0] = 0; g_pend_mapsize = 0;
}

static int lx_spawn_file(const char *path) {
    int i = 0; while (path[i] && i < (int)sizeof g_pend_lxpath - 1) { g_pend_lxpath[i] = path[i]; i++; }
    g_pend_lxpath[i] = 0;

    if (lx_stage_interp(path) < 0) return -1;

    g_pend_linux = 1;
    int rc = app_spawn_from_file(path);
    g_pend_linux = 0;                       /* never leak the flag to a later spawn */
    g_pend_mappath[0] = 0;                  /* and never leak the map request either */
    if (g_pend_interp) { kfree(g_pend_interp); g_pend_interp = 0; g_pend_interp_sz = 0; }
    return rc;
}

int app_spawn_linux_from_file(const char *path) {
    g_pend_lxargc = 0;                      /* argv[0] only */
    return lx_spawn_file(path);
}

/* Launch a Linux binary with a real argv: argv[0] is the path itself (minus the
 * mount prefix), and `args[0..n)` become argv[1..n]. This is what lets the
 * borrowed host toolchain be driven -- `as -o /t.o /t.s` (M1955). */
int app_spawn_linux_from_file_argv(const char *path, const char *const *args, int n) {
    if (n < 0) n = 0;
    if (n > LX_PEND_ARGS) n = LX_PEND_ARGS;
    for (int i = 0; i < n; i++) {
        int k = 0;
        if (args[i]) while (args[i][k] && k < LX_PEND_ARGLEN - 1) { g_pend_lxargs[i][k] = args[i][k]; k++; }
        g_pend_lxargs[i][k] = 0;
    }
    g_pend_lxargc = n;
    int rc = lx_spawn_file(path);
    g_pend_lxargc = 0;                      /* spawn may have failed before consuming it */
    return rc;
}

/* Run a Linux binary and wait, IN KERNEL CONTEXT, until it exits (M1955).
 *
 * app_waitpid cannot serve this: it needs cur() to be the parent app, and the
 * boot task is not an app at all. It also only sees children of the caller.
 * So this polls the slot directly and yields, which is what a kernel thread
 * can legitimately do.
 *
 * Sequencing is the whole point. A toolchain is a PIPELINE -- `as` must have
 * finished writing the object file before `ld` opens it -- and every earlier
 * demo in this file fired its spawns off concurrently, which is why their log
 * lines interleave. Returns the exit status, or -1 if it never started, or
 * -2 on timeout. */
int app_run_linux_sync(const char *path, const char *const *args, int n, int timeout_ms) {
    g_last_spawn_pid = 0;
    if (app_spawn_linux_from_file_argv(path, args, n) < 0 || !g_last_spawn_pid) return -1;
    int pid = g_last_spawn_pid;
    for (int waited = 0; waited < timeout_ms; waited += 5) {
        uint64_t f = irq_save();
        struct app *found = 0;
        for (int i = 0; i < MAX_APPS; i++)
            if (apps[i].used && apps[i].pid == pid) { found = &apps[i]; break; }
        /* Gone from the table entirely (already reaped) counts as finished --
         * treating that as "still running" would spin until the timeout. */
        if (!found) { irq_restore(f); return 0; }
        if (found->exited || found->zombie) {
            int code = found->exit_code;
            found->used = 0; found->zombie = 0;   /* collect it: nobody else will */
            irq_restore(f);
            return code;
        }
        irq_restore(f);
        /* Drive reaping ourselves. app_reap is otherwise called ONLY from the
         * desktop's window loop -- and this runner blocks the boot task before
         * the desktop has started, so during these demos nothing reaps at all.
         * A child that exits therefore never becomes a zombie, and a parent
         * blocked in wait4() is never woken: GNU make forked cc1, cc1 compiled
         * and exited cleanly, and make then waited forever. Grandchildren, not
         * just our own child, which is why this scans every slot. (M1958) */
        for (int i = 0; i < MAX_APPS; i++)
            if (apps[i].used && apps[i].exited && !apps[i].zombie && apps[i].pid != pid)
                app_reap(&apps[i]);           /* returns 0 and retries if it is not off-CPU yet */
        task_sleep_ms(5);
        /* A long in-guest run is worth a heartbeat: free memory plus the fault
         * counters distinguish "slow" from "stuck" at a glance, which is
         * exactly the question a stalled build raises. Once a minute. */
        if ((waited % 60000) == 0 && waited) {
            int live = 0; unsigned long maj = 0, min = 0;
            for (int i = 0; i < MAX_APPS; i++)
                if (apps[i].used) { live++; maj += apps[i].majflt; min += apps[i].minflt; }
            kprintf("[runsync] t=%ds free=%luK apps=%d majflt=%lu minflt=%lu\n", waited / 1000,
                    (unsigned long)(pmm_free_bytes() >> 10), live, maj, min);
        }
    }
    /* Say WHY it timed out instead of just reporting -2. A hang in a threaded
     * program is almost always a lost wakeup, and the one thing that
     * distinguishes it is which tasks are BLOCKED and where. (M1959) */
    {
        uint64_t f = irq_save();
        /* EVERY live process, not just the one we are waiting on: when a build
         * stalls, the interesting process is a grandchild. */
        for (int i = 0; i < MAX_APPS; i++) {
            if (!apps[i].used) continue;
            kprintf("[runsync] pid %d '%s' state=%d wchan=%lx exited=%d zombie=%d\n",
                    apps[i].pid, apps[i].title ? apps[i].title : "?",
                    apps[i].task ? (int)apps[i].task->state : -1,
                    apps[i].task ? (unsigned long)apps[i].task->wchan : 0UL,
                    apps[i].exited, apps[i].zombie);
            for (int k = 0; k < APP_MAXTHREAD; k++)
                if (apps[i].thr[k])
                    kprintf("[runsync]   thread %d state=%d wchan=%lx wake_pending=%d\n",
                            apps[i].thr[k]->id, (int)apps[i].thr[k]->state,
                            (unsigned long)apps[i].thr[k]->wchan, apps[i].thr[k]->wake_pending);
        }
        irq_restore(f);
        app_futex_dump();
    }
    return -2;
}

int app_spawn_from_file(const char *path) {
    /* Allocate what the FILE actually needs, not a fixed ceiling (M1952).
     * A flat 8 MiB per load looked harmless until several Linux binaries were
     * launched at once: seven concurrent processes wanted 56 MiB of kernel
     * heap on a 256 MiB machine, the allocation started failing, and a failed
     * execve made a pipeline's writer _exit(127) so the reader saw an empty
     * pipe. Sizing from the file makes the common case ~13 KB-800 KB.
     * Still buffers the WHOLE image, which will not scale to a 100 MB gcc --
     * that wants mmap-backed demand loading and is its own milestone. */
    struct statx est;
    unsigned long ELFBUF = (vfs_stat(path, &est) == 0 && est.stx_size) ? (unsigned long)est.stx_size : (1u << 20);
    /* A mapped load needs the ELF header and program-header table and nothing
     * else -- that is the whole point of it. 8 KiB covers both with room to
     * spare (a phdr is 56 bytes). (M1956) */
    int mapped = g_pend_mappath[0] != 0;
    if (mapped && ELFBUF > 8192) ELFBUF = 8192;
    if (ELFBUF > (16u << 20)) return -1;                 /* refuse absurd images rather than exhaust the heap */
    uint8_t *buf = kmalloc(ELFBUF);
    if (!buf) return -1;
    long n = mapped ? vfs_pread(path, buf, ELFBUF, 0) : vfs_read(path, buf, ELFBUF);
    int rc = (n > 0 && app_spawn(buf, path, (uint64_t)n)) ? 0 : -1;  /* title = filename */
    kfree(buf);
    return rc;
}

/* Launch a program by name (used by the Apps menu and the `run` syscall). */
int app_spawn_named(const char *name) {
    for (int i = 0; i < NPROGS; i++) {
        const char *a = progs[i].name, *b = name; int eq = 1;
        while (*a && *b) { if (*a++ != *b++) { eq = 0; break; } }
        if (eq && !*a && !*b) {
            if (app_spawn(progs[i].elf, progs[i].title, ~0ull)) return 0;  /* trusted embedded */
            /* don't fail silently: a failed launch (no free app slot, or the ELF's
             * frames/heap didn't fit) is otherwise invisible — no window, no log.
             * (This is exactly how Quake's out-of-memory failure hid before M599.) */
            kprintf("[app] '%s' failed to launch (no free slot, or out of memory loading it)\n", name);
            return -1;
        }
    }
    kprintf("[app] no such program: '%s'\n", name);
    return -1;
}

/* Launch a registered program with a one-shot launch argument (e.g. a filename
 * the app reads via SYS_getarg). The arg is copied into the new app's struct. */
int app_spawn_named_arg(const char *name, const char *arg) {
    int ai = 0; if (arg) while (arg[ai] && ai < 127) { g_pend_arg[ai] = arg[ai]; ai++; }
    g_pend_arg[ai] = 0; g_have_pend = 1;
    int rc = app_spawn_named(name);
    if (rc < 0) g_have_pend = 0;          /* spawn failed: don't leak the arg to the next app */
    return rc;
}

/* Copy the calling app's launch argument into out (NUL-terminated); returns its
 * length, or 0 if it was launched without one. */
int app_getarg(char *out, int max) {
    struct app *a = cur();
    int n = 0;
    if (a) while (a->launch_arg[n] && n < max - 1) { out[n] = a->launch_arg[n]; n++; }
    if (max > 0) out[n] = 0;
    return n;
}

/* List the registered program names, space-separated, into buf (for the shell's
 * `apps` command). Single source of truth = progs[]. Returns bytes written. */
int app_list_names(char *buf, int max) {
    int n = 0;
    for (int i = 0; i < NPROGS; i++) {
        const char *s = progs[i].name;
        if (i && n + 1 < max) buf[n++] = ' ';
        while (*s && n + 1 < max) buf[n++] = *s++;
    }
    if (max > 0) buf[n] = 0;
    return n;
}

/* The window manager calls this to claim freshly-spawned apps. */
app_t *app_take_pending(void) {
    if (pend_t == pend_h) return 0;
    app_t *a = pending[pend_t];
    pend_t = (pend_t + 1) % MAX_APPS;
    return a;
}

/* pending browse-URL requests (shell `browse <url>` -> WM opens a browser). */
#define MAX_BROWSE 4
static char browse_q[MAX_BROWSE][160];
static int  bq_h, bq_t;

void app_browse(const char *url) {                 /* SYS_browse: queue a URL */
    int n = (bq_h + 1) % MAX_BROWSE;
    if (n == bq_t) return;                          /* full -> drop */
    int i = 0; while (url[i] && i < 159) { browse_q[bq_h][i] = url[i]; i++; }
    browse_q[bq_h][i] = 0;
    bq_h = n;
}
int app_take_browse(char *out, int max) {          /* WM drains; 1 if returned */
    if (bq_t == bq_h) return 0;
    const char *s = browse_q[bq_t]; int i = 0;
    while (s[i] && i < max - 1) { out[i] = s[i]; i++; }
    out[i] = 0;
    bq_t = (bq_t + 1) % MAX_BROWSE;
    return 1;
}
