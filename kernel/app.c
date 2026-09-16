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
#include "smp.h"     /* per-core fault-recursion depth (M1987) */
#include "timer.h"
#include "interrupts.h"   /* struct registers, for ring-3 signal delivery */
#include "vmm.h"
#include "unixsock.h"   /* AF_UNIX sockets live in the fd table now (M1965) */
#include "mbox.h"      /* mbox_forget_task: a freed task must not stay a stored waiter (M2053) */
#include "mqueue.h"    /* mqueue_forget_task (M2053) */
#include "sem.h"       /* psem_forget_task (M2053) */
#include "sysvipc.h"   /* sysvsem_forget_task (M2053) */
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

/* THE ALTERNATE SCREEN (M2057). ESC[?1049h saves the primary screen and hands
 * the program a blank one; ESC[?1049l puts the original back, cursor and
 * colours included. Every full-screen TUI opens with it, and without it the
 * shell's scrollback and prompt stay underneath whatever the TUI paints -- and
 * are lost for good when it exits.
 *
 * Heap-allocated on first use: this is 27 KB, and most programs never ask. */
struct altscreen {
    char    grid[APP_ROWS_MAX][APP_COLS_MAX];
    uint8_t gcol[APP_ROWS_MAX][APP_COLS_MAX];
    uint8_t gbg[APP_ROWS_MAX][APP_COLS_MAX];
    int     cx, cy;
    uint8_t curcol, curbg, bold, inv;
    int     sr_top, sr_bot;
    int     sb_count, view;
};

#define USTACK_BASE  0x50000000ull
/* 512 KiB was sized for our own apps (DOOM's BSP renderer recurses deeply).
 * It is nowhere near what a Linux program expects: Linux's default is 8 MiB,
 * and a big runtime asks for more -- Claude Code's PT_GNU_STACK requests
 * 12.2 MiB, and JavaScriptCore checks its stack bounds at startup and refuses
 * to run in less.
 *
 * EAGER_PAGES are mapped up front because the kernel writes the initial SysV
 * frame (argv/envp/auxv) there before the process runs; the rest is a
 * demand-zero VMA, so a program that never recurses deeply pays nothing for
 * the headroom. Page 0 at USTACK_BASE stays outside the VMA and unmapped, so
 * an overflow still faults cleanly instead of corrupting the heap below
 * (M1499). (M1975) */
#define USTACK_PAGES 4097            /* 16 MiB usable + 1 guard page */
#define USTACK_EAGER 64              /* top pages mapped at spawn: the initial frame lives here */

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
/* 16 -> 32 (M1936) -> 192 (M2009).
 *
 * Firefox's PARENT process alone wants more than 32, and what it does when a
 * thread cannot be created is crash on purpose: the last syscall before it
 * died was clone3 returning EAGAIN, from a process that already had exactly 32
 * threads. Thread creation is not a place a browser accepts "no" -- a compositor
 * thread or an IPC I/O thread that does not exist has no fallback behaviour. */
#define APP_MAXTHREAD 192
    task_t     *thr[APP_MAXTHREAD];      /* worker threads (M1138/M1139); 0 = free slot */
    const char *title;
    char        titlebuf[24];            /* persistent copy of the title */
    /* The spawn/exec file path, for /proc/<pid>/exe -- NOT changed by prctl
     * (M1250). 64 bytes truncated a path like
     * /disk2/usr/lib/gcc/x86_64-pc-linux-gnu/15/cc1 well before the end, and a
     * truncated exe path is not a cosmetic problem: a Node single-executable
     * app finds its own embedded payload by reading /proc/self/exe and opening
     * the result. (M1970) */
    char        exe_path[VFS_PATH_MAX];
    uint64_t cr3, entry, ustack;
    uint64_t heap_end;                   /* current program break (0 = not yet started) */
/* 16 -> 64 (M1936). A dynamically-linked or JIT-ing program wants dozens of
 * regions; 16 was tight even for our own apps once mmap'd thread stacks and
 * file mappings were in play. */
/* 64 -> 192 (M1961) -> 1024 (M1962). ld.so alone costs several VMAs per shared
 * library once MAP_FIXED carving splits each reservation, and GCC's garbage
 * collector then makes HUNDREDS of small mappings -- cc1 died with "virtual
 * memory exhausted" having run out of SLOTS with a gigabyte of address space
 * still free. Affordable only because the backing-file path is interned
 * (see fpaths) rather than stored inline per region. */
/* 1024 -> 4096 (M2009). Firefox's parent process reached 833 regions before it
 * died of something else; a browser with content processes and a JIT routinely
 * wants thousands, and running OUT of slots does not report as "out of slots"
 * -- it reports as mmap failing with a gigabyte of address space free. */
#define APP_MAXVMA 4096
#define HUGE_SIZE  0x200000ull           /* 2 MiB hugepage (M1155) */
/* Zero the next free VMA slot before filling it. Slots are RECYCLED -- the
 * carve compacts the list by swapping the last entry down -- so a field a
 * creation site forgets to assign silently inherits the previous tenant's
 * value. That is not hypothetical: app_mmap_file_at never assigned .prot, so
 * a freshly MAP_FIXED'd read-WRITE data segment inherited prot=1 from the
 * read-only reservation it replaced, and ld.so faulted zeroing the BSS tail.
 * Resetting the whole slot makes every field opt-in. (M1956) */
/* TOMBSTONES (M1988). Removal used to fill the hole it made by moving the LAST
 * entry down into it. Every thread of a process shares this table, so that
 * relocates an unrelated mapping to an index a concurrent scan has already
 * walked past -- and the scan then reports the address as unmapped, which kills
 * a process for touching memory it mapped itself and had already written.
 *
 * Now an entry NEVER MOVES. Removal leaves a tombstone (start = len = 0, inert
 * to every range test in this file) and VMA_NEW reuses one before it extends
 * the table, so the slot count does not grow without bound. A scan racing a
 * removal can see the entry or see the tombstone; it cannot see a DIFFERENT
 * mapping wearing the same index, which was the whole bug.
 *
 * VMA_NEW writes to a->vma_slot, not to a->vma[a->nvma]: every site that used
 * the old idiom names the slot instead, and commits with VMA_COMMIT. Sites
 * check vma_full() beforehand rather than `nvma >= APP_MAXVMA`, because a full
 * high-water mark with tombstones in it still has room. */
#define vma_full(a) (vma_pick_slot(a) < 0)
/* CLAIMING A SLOT IS THE ONE PART THAT MUST BE MUTUALLY EXCLUSIVE (M1988).
 *
 * Tombstoning fixed removal; allocation was still racing. Two threads calling
 * mmap at once both ran vma_pick_slot, both got the same free index, and both
 * wrote their mapping into it. One mapping simply vanished -- its caller got an
 * address back and faulted on the first byte, with the table containing no
 * overlap and nothing wrong with it. (The overlap audit is clean throughout,
 * which is what pointed here.)
 *
 * This critical section is safe to spin on where the earlier whole-operation
 * lock was not: it touches only the kernel's own table, does no I/O, and
 * accesses no user memory, so nothing inside it can block or fault. The slot is
 * CLAIMED by writing a non-zero len before the lock is dropped -- every other
 * allocator looks for len == 0 -- and the high-water mark is published in the
 * same section. A half-built entry is inert to range tests because its start is
 * still 0, and x86's store ordering means a scanner that sees the caller's
 * final `len` has already seen its `start`. */
#define VMA_NEW(a, slot) do { uint64_t _vf = vma_alloc_lock(a);                                          \
                        (slot) = vma_pick_slot(a);                                                 \
                        if ((slot) < 0) (slot) = 0;                 /* caller checked vma_full */  \
                        for (unsigned _b = 0; _b < sizeof (a)->vma[0]; _b++) ((char *)&(a)->vma[(slot)])[_b] = 0; \
                        (a)->vma[(slot)].fidx = -1; (a)->vma[(slot)].mfd = -1;                     \
                        (a)->vma[(slot)].prot = VMA_PROT_READ | VMA_PROT_WRITE;                    \
                        (a)->vma[(slot)].len = 1;                   /* claimed: start is still 0 */ \
                        if ((slot) >= (a)->nvma) (a)->nvma = (slot) + 1;                           \
                        vma_alloc_unlock(a, _vf); } while (0)
/* 0 is a VALID path/memfd index, so zeroing is not "none" (M1962/M1985) -- and
 * ZERO PROT MEANS PROT_NONE, which is not what any of these regions are.
 *
 * app_mmap never set prot at all, so every ordinary anonymous mapping carried
 * prot 0. The fault handler's MISSING-page path does not consult prot, so this
 * was invisible for as long as a page could only be absent; the PERMISSION
 * path reads it literally, and a page that is present-but-read-only under a
 * prot-0 VMA is reported as "write to a read-only mapping" and the process is
 * killed. It took mprotect() churn in the same address space to expose, which
 * is why a compiler and a browser hit it and nothing else did. The default is
 * now what these mappings actually are; every caller that wants something
 * narrower still says so. (M1987) */

/* Linux PROT_* bits, as recorded on a VMA and honoured by app_fault_handle (M1956) */
#define VMA_PROT_READ  0x1
#define VMA_PROT_WRITE 0x2
#define VMA_PROT_EXEC  0x4
    struct { uint64_t start, len; int sealed, uffd, file_backed, locked, huge, shared; uint64_t foff; short fidx; short mfd; uint8_t prot; uint64_t fvalid; } vma[APP_MAXVMA];  /* mmap'd demand-paged regions; sealed=mseal'd; uffd=userfault; file_backed=mmap'd file (M1136); locked=mlock'd (M1149); huge=2 MiB-backed (M1155); shared=MAP_SHARED, writes flow back to the file via msync/munmap/exit (M1544); fidx indexes the global path table (M1962: an inline 256-byte path made the struct so big the TABLE was the limit, not the address space); prot = Linux PROT_* bits honoured by the fault handler, fvalid = file bytes from foff before zero-fill begins (M1956) */
    int      nvma;
    /* THE VMA TABLE IS SHARED BY EVERY THREAD, and until M1987 it was mutated
     * with no serialisation at all. Two threads mmap()ing at once both wrote
     * a->vma[a->nvma] and both incremented it; a munmap racing an mmap moved
     * the last entry down over the one being written. The loser's mapping was
     * returned to the caller and then did not exist -- so the first write to it
     * faulted with "no VMA", pages away from anything the program did wrong.
     * Anonymous, file-backed and memfd mappings all go through here, so this
     * one lock covers them; it is nested inside cli, like every other lock in
     * this file. */
    volatile int vma_lk;
    struct app *out_to;                  /* a Linux child writes its stdout into THIS app's window (M1988) */
    /* REAL vfork (M2006). CLONE_VM|CLONE_VFORK means: share the caller's
     * address space, and SUSPEND the caller until the child execs or exits.
     * glibc's posix_spawn is written against exactly that -- its child sets up
     * signal masks and file actions and then execs, reporting a failure back
     * through memory the two of them share. We faked it with a copy-on-write
     * fork, so the child wrote its answer into a private copy nobody read, and
     * both of the faults that broke self-hosting landed in that code. */
    int      cr3_borrowed;               /* this cr3 belongs to our vfork PARENT: never destroy it */
    int      vfork_parent;               /* pid to release when we exec or exit, 0 = none */
    volatile int vfork_waiting;          /* set on the PARENT while it is suspended */
    unsigned long lxcalls;               /* Linux syscalls this process has made, for the stall watchdog (M2004) */
    unsigned long lxcalls_seen; int stall_ticks, stall_told;
    int      out_announced;              /* the routing has been logged once */
    void    *vma_owner;                  /* the task holding it; re-entry by the SAME task is allowed */
    int      vma_depth;
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
/* 32 -> 65 (M2063). Linux has 64 signals and glibc uses SIGRTMIN(34)+0..2
 * internally for setxid and thread cancellation, so a 32-signal table cannot
 * even hold the numbers a real libc uses. The masks below widen with it. */
#define APP_NSIG 65
/* SIG_IGN is not a code address. Linux encodes SIG_DFL as 0 and SIG_IGN as 1
 * in the same field, and `sig_handler[signo] = 1` used to mean "there is a
 * handler, at virtual address 1" -- a jump to 1 and a fault. Kept as the same
 * sentinel Linux uses so the ABI needs no translation, and checked everywhere
 * a handler is about to run. (M2063) */
#define APP_SIG_IGN 1ull
    uint64_t sig_handler[APP_NSIG];      /* ring-3 signal handlers (0 = none) */
    uint32_t sig_flags[APP_NSIG];        /* per-signal sa_flags (SA_SIGINFO etc.) (M1270) */
    uint64_t sig_samask[APP_NSIG];       /* per-signal sa_mask: blocked FOR THE DURATION of that handler (M2063) */
    uint64_t sig_restorer;               /* ulib trampoline that calls sigreturn */
    struct registers sig_saved;          /* pre-signal context, restored by sigreturn */
    uint64_t sig_uctx;                   /* SA_SIGINFO: user addr of the delivered ucontext/mcontext; sigreturn restores edits from it (M1270) */
    int      sig_in;                     /* 1 while a handler runs (no nesting) */
    volatile uint64_t pending_sigs;      /* bitset of pending signals (bit n = signo n); delivered on the next return to ring 3. A bitset, not one slot, so a 2nd async signal isn't dropped (M1126) */
    volatile uint64_t sig_blocked;       /* sigprocmask: blocked-signal bitset; a blocked signal stays pending until unblocked (M1208) */
    int      sigfd_armed;                /* 1 if this process routes some signals to signalfd (M1126) */
    uint64_t sigfd_mask;                 /* which signos are delivered via /proc/self/sigfd instead of a handler */
#define APP_SIGQ_MAX 32
    struct { int signo, code; uint64_t value; } sigq[APP_SIGQ_MAX];  /* RT/sigqueue payload FIFO: real-time signals QUEUE (not coalesce) and carry a sigval (M1271) */
    int      sigq_n;                     /* # valid queued payloads, [0..sigq_n) in arrival (FIFO) order */
    uint64_t fork_sig_blocked;           /* the mask the CLONING thread had, handed to the new task (M2075) */
    uint64_t sig_q_value;                /* scratch: si_value for the signal currently being delivered */
    int      sig_q_code;                 /* scratch: si_code  for the signal currently being delivered */
    /* WHERE THE FAULT WAS (M2073). si_addr was hardcoded to 0 for every
     * signal, and the comment said "0 for a raised/queued signal" -- true
     * of kill() and sigqueue(), and wrong for exactly the signals whose
     * whole point is an address. A SIGSEGV handler reads si_addr to decide
     * whether the fault is one it can handle, so answering 0 turns every
     * recoverable fault into an unrecognised one. Bun printed
     * "Segmentation fault at address 0x0" while CR2 was 0x500000020 -- our
     * number, not its bug. Set by the fault handler immediately before it
     * delivers, and consumed once. */
    uint64_t sig_fault_addr;
    int      sig_fault_code, sig_fault_valid;
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
    /* PER-CELL BACKGROUND (M2057). 0 = "the window's own translucent backdrop",
     * otherwise 1 + a palette index -- so a zeroed grid means default, which is
     * what grid_clear and grid_scroll already produce.
     *
     * Its absence was not cosmetic. A terminal with no background has no way to
     * render dark-text-on-light, and ansi_rgb folds every dark near-grey onto
     * palette 8 -- so Claude Code's black-on-white panels came out as dim grey
     * on near-black. Every cell was painted and the window looked empty. */
    uint8_t  gbg[APP_ROWS_MAX][APP_COLS_MAX];
    int      cols, rows;                 /* CURRENT visible grid size (<= _MAX); the WM sets it from the window size on resize (M1473) */
    uint8_t  curcol;                     /* colour applied to chars printed now (set via SYS_setcolor) */
    uint8_t  curbg;                      /* background for chars printed now: 0 = default, else 1 + palette index (M2057) */
    uint8_t  sgr_bold, sgr_inv;          /* SGR attributes that PERSIST between sequences (M2057) */
    uint8_t  esc;                        /* ANSI escape state: 0 normal, 1 saw ESC, 2 in CSI, 3/4 OSC, 5 string, 6 string+ESC, 7 discard one */
    uint8_t  csilen;                     /* bytes buffered in csi[] */
    /* 24 -> 64 (M2057). A single SGR that sets foreground AND background in
     * truecolour is 27 parameter bytes ("38;2;255;255;255;48;2;0;0;0"), and the
     * old buffer bailed out of the sequence on byte 25 -- which dropped the
     * parser back to ground state MID-SEQUENCE, so the tail ";0m" was printed
     * into the grid as literal text. That is where the stray characters in an
     * otherwise blank window came from. */
    char     csi[64];                    /* CSI parameter bytes (between '[' and the final letter) */
    char     csipriv;                    /* the private-mode introducer, if any: '?', '>', '<', '=' (M2057) */
    /* DEFERRED WRAP (M2057) -- the single biggest rendering defect this
     * terminal had. grid_putc line-fed as soon as the cursor passed the last
     * column, so writing exactly `cols` characters moved to the next row
     * immediately and, on the bottom row, SCROLLED THE WHOLE SCREEN. A real
     * VT100 parks the cursor in the last column behind a pending-wrap flag and
     * only wraps when the NEXT printable character arrives. A TUI that draws
     * full-width box borders -- which is every frame Claude Code paints -- was
     * scrolling itself off the top of the grid as it drew. */
    uint8_t  wrap_pend;
    uint8_t  no_wrap;                    /* DECAWM off: ESC[?7l -- print in place at the margin */
    uint8_t  bracket_paste;              /* ESC[?2004h: wrap a paste in ESC[200~ / ESC[201~ */
    int      sr_top, sr_bot;             /* DECSTBM scroll region, 0-based inclusive; sr_bot <= 0 = whole screen */
    int      sv_cx, sv_cy;               /* DECSC / ESC[s saved cursor + attributes */
    uint8_t  sv_col, sv_bg, sv_bold, sv_inv, sv_valid;
    /* The primary screen, parked while the ALTERNATE screen is active
     * (ESC[?1049h). Allocated on first use -- most programs never ask, and a
     * second full screen in every one of the 32 process slots is 27 KB each
     * for nothing. */
    struct altscreen *alt;
    uint8_t  alt_on;
    /* UTF-8 decoder state (M2015): bytes still owed on the current character,
     * and the code point built so far. One code point becomes one cell. */
    uint8_t  u8need;
    unsigned long u8cp;
    /* Bytes owed to a Linux reader from a key that expands to an ESCAPE
     * SEQUENCE -- arrows, Home, End, Delete (M2024). Our keyboard hands the
     * kernel one sentinel byte per key; a terminal sends three or four. */
    char     keyseq[8];
    uint8_t  keyseq_n, keyseq_i;
    int      cx, cy;
    char     sb[SB_ROWS][APP_COLS_MAX];  /* scrollback: lines that scrolled off */
    uint8_t  sbcol[SB_ROWS][APP_COLS_MAX];   /* ...and their colours: the render path used to hardcode green (M2057) */
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
    /* THE TERMINAL SETTINGS A PROGRAM ASKED FOR (M2014). TCSETS used to be
     * accepted and discarded, on the reasoning that our console already
     * delivers keys one at a time so there was nothing to change. There is:
     * the FLAGS say how the keys should be encoded, and getting that wrong
     * makes a TUI unusable in a way that looks like the keyboard not working.
     * Zeroed = never set; the cooked defaults are filled in on first use. */
    uint32_t tio_iflag, tio_oflag, tio_cflag, tio_lflag;
    uint8_t  tio_cc[19];
    int      tio_valid;
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
    volatile int reaping;                /* one reaper only: see app_reap (M2072) */
#define LX_SYSHIST_N 460                 /* Linux x86-64 numbers we could plausibly see; 460 covers every one staged here */
    unsigned int syshist[LX_SYSHIST_N];      /* per-syscall-number call counts (M2066) */
    unsigned int syshist_seen[LX_SYSHIST_N]; /* ...as of the previous sample, so a dump shows a DELTA */
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
/* 128 -> 512 (M1962). A LINKER opens every object file at once: OS-DEV's own
 * kernel is 146 of them, so a 128-fd ceiling meant ld simply never saw the
 * tail of its own command line. It reported "undefined reference to kmalloc"
 * about a file that defines it perfectly well. */
/* 1024, which is Linux's conventional RLIMIT_NOFILE and therefore the number
 * real programs assume. They do not all read the limit before using it: Claude
 * Code asks for fcntl(0, F_DUPFD_CLOEXEC, 1023) outright -- "put this at the
 * top of the descriptor space" -- and a 512-entry table can only answer EBADF.
 * At ~288 bytes per entry and MAX_APPS 32 this costs about 9 MB of BSS. (M1972) */
#define APP_NFD 1024
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
    /* peer_ip/peer_port: a CONNECTED datagram socket (M1967). glibc's resolver
     * does not use sendto/recvfrom -- it connect()s the UDP socket and then
     * send()/recv()s on it, so a connect that only understood TCP made every
     * getaddrinfo fail with EAI_AGAIN, an error meaning "try later" about a
     * lookup that was never going to happen. */
    /* `sndbuf`/`rcvbuf`/`sockflags` are the socket options a program SET and
     * may read back (M2088). 0 in the size fields means "never set", which is
     * how a get reports the real capacity rather than a stored fiction. At the
     * END, like every field added since M1218, so the positional initializers
     * scattered through this file stay valid. */
    struct fdent { uint8_t used, type, write_end; int obj; char path[256]; long off; uint8_t cloexec; uint8_t nonblock; uint8_t peer_ip[4]; uint16_t peer_port; uint8_t epwatch; int sndbuf, rcvbuf; uint32_t sockflags; } fd[APP_NFD];   /* cloexec/nonblock/peer at END to keep the positional initializers valid (M1218/M1965/M1967) */
    /* seccomp-BPF self-filter (M1190): a process installs a bpf.c program that
     * vets its own syscalls. Zero on spawn/fork; inherited across fork; once set
     * it's permanent (privilege drop is one-way). Empty => no filtering overhead. */
    struct bpf_insn seccomp_prog[BPF_MAXINSN];
    int      seccomp_n;                  /* program length (0 = no filter) */
};

/* -append lxnettrace: log every socket read/write a Linux process makes, with
 * byte counts (M2016). Off by default; one line per call is far too much for a
 * normal boot and exactly right when a handshake is not completing. */
unsigned long g_readahead_pages;   /* pages filled by readahead rather than by a fault (M2019) */
int g_net_trace;
static unsigned long g_net_calls;   /* socket reads+writes, to notice a connection going quiet (M2016) */
static struct app apps[MAX_APPS];

/* SELF-AUDIT (-append vmaaudit, M1988). Two VMAs must never describe the same
 * address: that is the invariant every "no VMA" fault suggests is broken, and
 * inferring it from fault addresses is guesswork. O(n^2) in the table size, so
 * it is opt-in -- a browser with a thousand mappings would feel it. */
int g_vma_audit;
static void vma_audit(struct app *a, const char *why) {
    if (!g_vma_audit || !a) return;
    for (int i = 0; i < a->nvma; i++) {
        if (!a->vma[i].len) continue;
        uint64_t s1 = a->vma[i].start, e1 = s1 + a->vma[i].len;
        if (e1 <= s1) { kprintf("[vma] AUDIT %s: vma[%d] %lx len %lx is degenerate\n", why, i, s1, a->vma[i].len); continue; }
        for (int j = i + 1; j < a->nvma; j++) {
            if (!a->vma[j].len) continue;
            uint64_t s2 = a->vma[j].start, e2 = s2 + a->vma[j].len;
            if (s1 < e2 && s2 < e1)
                kprintf("[vma] AUDIT %s: OVERLAP vma[%d] %lx-%lx and vma[%d] %lx-%lx\n",
                        why, i, s1, e1, j, s2, e2);
        }
    }
}

/* See the tombstone note on VMA_NEW. (M1988) */
static inline int vma_pick_slot(struct app *a) {
    for (int i = 0; i < a->nvma; i++) if (!a->vma[i].len) return i;
    return a->nvma < APP_MAXVMA ? a->nvma : -1;
}

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
/* Per-process VMA-table lock (M1987). Taken at the PUBLIC entry points only:
 * the static helpers below (vma_find_gap, app_vma_carve, app_vma_split_at)
 * assume it is already held, which keeps it non-recursive and makes the
 * ownership obvious at every call site.
 *
 * Deliberately NOT held across disk I/O: app_msync and the swap path can block,
 * and a lock that can be held across a sleep is a lock that serialises the
 * whole process on one slow read. */
struct app;
static inline uint64_t vma_lock(struct app *a);
static inline void vma_unlock(struct app *a, uint64_t f);

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

/* NOT A LOCK YET, and saying so is the point (M1987).
 *
 * The VMA table IS shared by every thread and IS raced -- see the milestone
 * notes: app_vma_carve fills the hole it makes by moving the last entry down,
 * so a concurrent munmap relocates a mapping to an index a scan has already
 * passed, and the scan concludes the address is unmapped. tools/lx/lxstress.c
 * reproduces it in about a minute.
 *
 * A per-process spinlock was tried here and REMOVED, because it hangs the
 * machine rather than fixing the race: several of these operations block while
 * holding it (app_msync writes to disk from inside app_vma_carve; the
 * file-backed fault path reads through the VFS), and a spinlock held across a
 * blocking call, taken by other cores with interrupts off, means the holder can
 * never be rescheduled to release it. That is the same failure M1912 fixed in
 * the scheduler, and it is worse than the bug it was meant to fix.
 *
 * The real fix is a blocking-call audit plus tombstoned removal so entries
 * never MOVE -- which is the actual hazard -- and it is its own milestone.
 * These stubs keep the call sites, and the interrupt discipline, in place.
 */
/* The slot-claim lock. Short, non-blocking, no user memory: see VMA_NEW. */
static inline uint64_t vma_alloc_lock(struct app *a) {
    uint64_t f;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory");
    if (a) while (__atomic_exchange_n(&a->vma_lk, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return f;
}
static inline void vma_alloc_unlock(struct app *a, uint64_t f) {
    if (a) __atomic_store_n(&a->vma_lk, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(f) : "memory", "cc");
}

static inline uint64_t vma_lock(struct app *a) {
    (void)a;
    uint64_t f;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory");
    return f;
}
static inline void vma_unlock(struct app *a, uint64_t f) {
    (void)a;
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
/* 192 -> 1024 (M1964). A `node -e '<script>'` invocation puts an entire
 * program in ONE argument; at 192 characters it was silently cut mid-string
 * and Node reported a SyntaxError about source it had never been given. */
#define LX_PEND_ARGLEN 1024
static char g_pend_lxargs[LX_PEND_ARGS][LX_PEND_ARGLEN];
static void app_stop_siblings(struct app *a);   /* end every OTHER thread of a dying process (M1999) */
static int  g_pend_lxargc;
#define LX_PEND_ENV 4
static const char *g_pend_env_extra[LX_PEND_ENV];
/* WHERE THE NEXT SPAWNED LINUX PROCESS'S OUTPUT GOES, and whose child it is.
 *
 * Both used to be set AFTER app_spawn returned, which is a race the child wins
 * whenever it prints early -- and worse, it meant nothing could wait for it,
 * because a spawned app has no parent and waitpid only finds children. Handing
 * them to the spawn itself closes both. (M2004) */
static struct app *g_pend_out_to;
static int         g_pend_parent;
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
/* The cwd a newly spawned Linux process should start in (M2033). Captured from
 * the REQUESTER at request time, because by the time the window manager
 * performs the spawn, cur() is the WM and the shell's directory is gone. */
static char         g_pend_lxcwd[VFS_PATH_MAX];
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
/* Spawned-but-windowless apps, waiting for the window manager's next pass.
 * The PID is carried alongside the pointer on purpose (M2011): `apps[]` slots
 * are recycled, so a bare pointer cannot tell "the app I queued" from "whatever
 * moved into its slot afterwards". */
/* THE WINDOW QUEUE (M2076).
 *
 * Every app reaches the window manager through this ring, and it used to drop
 * a push silently when full -- `if (n != pend_t)` and no else. Nothing ever
 * removed an entry for a process that had since exited, either, so a boot that
 * creates and reaps thirty-one short-lived processes (the IPC self-test alone
 * accounts for a dozen) fills all thirty-two slots with corpses. The next
 * spawn is then discarded, and the next spawn is THE SHELL: the desktop came
 * up with a Welcome window, a Files window and no terminal, looking entirely
 * deliberate. Every keystroke I then typed went to the file manager, where 'd'
 * deletes and 'n' creates a directory.
 *
 * So: reclaim the dead before declaring the queue full, and if it genuinely is
 * full of live processes, say which one is being dropped. A queue that lies
 * about having space is worse than one that is too small. */
struct pendent { struct app *a; int pid; };
static struct pendent pending[MAX_APPS];
static int pend_h, pend_t;

/* Drop every queued entry whose process is gone, in place, preserving order.
 * Called before declaring the ring full: a corpse must never cost a live app
 * its window. */
static void pend_reclaim(void) {
    int rd = pend_t, wr = pend_t, dead = 0;
    while (rd != pend_h) {
        struct app *a = pending[rd].a;
        if (a && a->used && a->pid == pending[rd].pid) {
            if (wr != rd) pending[wr] = pending[rd];
            wr = (wr + 1) % MAX_APPS;
        } else dead++;
        rd = (rd + 1) % MAX_APPS;
    }
    pend_h = wr;
    if (dead) kprintf("[app] window queue: reclaimed %d entr%s for processes that had exited\n",
                      dead, dead == 1 ? "y" : "ies");
}

int app_pendq_selftest(void);   /* below: the invariant this queue exists for */

/* Queue an app for the window manager. Returns 0 if it could not be queued --
 * which now means the queue is full of LIVE apps, and says so. */
static int pend_push(struct app *a) {
    int n = (pend_h + 1) % MAX_APPS;
    if (n == pend_t) { pend_reclaim(); n = (pend_h + 1) % MAX_APPS; }
    if (n == pend_t) {
        kprintf("[app] window queue FULL of live apps: '%s' (pid %d) will not get a window\n",
                a->title ? a->title : "?", a->pid);
        return 0;
    }
    pending[pend_h].a = a; pending[pend_h].pid = a->pid; pend_h = n;
    return 1;
}

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
/* The real ceilings, so the ABI layer can report them instead of claiming
 * RLIM_INFINITY. A program that is told its descriptor limit is unlimited will
 * cheerfully ask for fd 1023 -- and get EBADF from a 512-entry table. (M1972) */
int         app_nfd_max(void)  { return APP_NFD; }
uint64_t    app_stack_bytes(void) { return (uint64_t)(USTACK_PAGES - 1) * PAGE_SIZE; }   /* usable user stack, for RLIMIT_STACK (M1975) */
int         app_proc_max(void) { return MAX_APPS; }
int         app_vma_count(app_t *a) { return a ? a->nvma : 0; }
/* Read one VMA's extent and protection, for diagnostics that need to ask
 * "is this address executable in this process?" -- a stack scan looking for
 * return addresses, for instance. 0 on success. (M1970) */
int app_vma_info(app_t *ap, int i, uint64_t *start, uint64_t *len, int *prot) {
    struct app *a = (struct app *)ap;
    if (!a || i < 0 || i >= a->nvma) return -1;
    if (start) *start = a->vma[i].start;
    if (len)   *len   = a->vma[i].len;
    if (prot)  *prot  = a->vma[i].prot;
    return 0;
}
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
/* Linux's /proc/<pid>/maps format, exactly (M1975):
 *
 *   start-end perms offset dev inode    pathname
 *   55a1b2c00000-55a1b2c21000 r--p 00000000 08:02 1234    /usr/bin/foo
 *
 * The format is not cosmetic and the STACK line is not optional. glibc's
 * pthread_getattr_np finds the main thread's stack by reading this file and
 * looking for the entry whose range CONTAINS __libc_stack_end, parsing each
 * line with "%lx-%lx %4s". Ours printed the stack as a single bare address
 * with no "-end" at all:
 *
 *   0000000050000000  rw-  [stack]
 *
 * so no line ever matched, pthread_getattr_np failed, and anything that asks
 * the system how much stack it has got an error instead of an answer. A
 * JavaScript engine asks that before it will run a line of code. */
static const char *vma_path(struct app *a, int i);   /* defined with the VMA table below */
static int maps_hexraw(char *b, int p, int max, uint64_t v) {   /* no 0x prefix: Linux has none */
    char t[16]; int n = 0;
    if (v == 0) t[n++] = '0';
    while (v) { t[n++] = "0123456789abcdef"[v & 0xF]; v >>= 4; }
    while (n > 0 && p < max - 1) b[p++] = t[--n];
    return p;
}
static int maps_line(char *b, int p, int max, uint64_t start, uint64_t end,
                     int prot, const char *path) {
    p = maps_hexraw(b, p, max, start);
    p = maps_str(b, p, max, "-");
    p = maps_hexraw(b, p, max, end);
    p = maps_str(b, p, max, " ");
    char perms[5];
    perms[0] = (prot & VMA_PROT_READ)  ? 'r' : '-';
    perms[1] = (prot & VMA_PROT_WRITE) ? 'w' : '-';
    perms[2] = (prot & VMA_PROT_EXEC)  ? 'x' : '-';
    perms[3] = 'p';                     /* everything here is MAP_PRIVATE */
    perms[4] = 0;
    p = maps_str(b, p, max, perms);
    p = maps_str(b, p, max, " 00000000 00:00 0 ");
    if (path && path[0]) { p = maps_str(b, p, max, "                 "); p = maps_str(b, p, max, path); }
    p = maps_str(b, p, max, "\n");
    return p;
}

int app_format_maps(app_t *a, char *b, int max) {
    if (!a || max <= 0) return 0;
    int p = 0;
    uint64_t stk_lo = USTACK_BASE + PAGE_SIZE;                               /* page 0 is the guard */
    uint64_t stk_hi = USTACK_BASE + (uint64_t)USTACK_PAGES * PAGE_SIZE;
    if (a->heap_end > UHEAP_BASE)       /* the program break heap */
        p = maps_line(b, p, max, UHEAP_BASE, a->heap_end,
                      VMA_PROT_READ | VMA_PROT_WRITE, "[heap]");
    for (int i = 0; i < a->nvma; i++) {
        /* The lazily-faulted part of the stack is a VMA too; it is reported as
         * part of the single [stack] range below, not twice. */
        if (a->vma[i].start >= stk_lo && a->vma[i].start < stk_hi) continue;
        /* No "0 means rw" fallback any more: VMA_NEW gives every mapping its
         * real protection now, so this file and the fault handler finally
         * agree. The fallback here was the bug's camouflage -- /proc/self/maps
         * read correctly while the fault handler read the same field literally
         * and killed the process. (M1987) */
        int prot = a->vma[i].prot;
        p = maps_line(b, p, max, a->vma[i].start, a->vma[i].start + a->vma[i].len,
                      prot, a->vma[i].huge ? "[mmap-huge]" : vma_path((struct app *)a, i));
    }
    /* ONE contiguous stack entry covering everything a program may use, so the
     * line containing __libc_stack_end exists and is findable. */
    p = maps_line(b, p, max, stk_lo, stk_hi, VMA_PROT_READ | VMA_PROT_WRITE, "[stack]");
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

/* memfd reference counting, forward-declared: the fd table, munmap, fork and
 * process teardown all hold references to a memfd object, and they live far
 * above its definition. (M1985) */
static void memfd_ref(int idx);
static void memfd_unref(int idx);

/* SCM_RIGHTS — fd passing over AF_UNIX (M1265). A per-connection mailbox holds
 * one in-flight descriptor (a snapshot of the sender's fdent); the peer's
 * recvfd installs a FRESH fd in its own table referring to the SAME underlying
 * object (pipe/file/memfd/...), exactly as Unix ancillary-data fd passing does.
 * Keyed by the AF_UNIX connection index (unix_ep_conn), so a sendfd on one
 * endpoint is delivered to the other. */
extern int unix_ep_conn(int ep);   /* kernel/unixsock.c */
#define SCM_SLOTS 16
#define SCM_QDEPTH 4
/* DIRECTIONAL, and a queue (M1984).
 *
 * This was a single slot per connection, shared by both sides. Two bugs came
 * with that, and neither is theoretical now that a real protocol runs over it:
 *
 *  - A process could RECEIVE BACK THE FD IT JUST SENT. A Wayland client passes
 *    its pool memfd and then immediately reads the compositor's reply; with one
 *    shared slot, that read hands it its own descriptor.
 *  - Only one descriptor could be in flight. GTK passes several (a keymap, a
 *    pool, dma-bufs), and the second `sendmsg` silently failed.
 *
 * Indexed [connection][sender's side]: a sender pushes onto its own side's
 * queue and a receiver pops the PEER's. FIFO, because the protocol matches
 * descriptors to messages by ORDER -- libwayland pops the next fd when it
 * demarshals an argument declared as one, so a reordered queue attaches the
 * wrong file to the wrong message. */
struct scmq { struct fdent fe[SCM_QDEPTH]; int head, tail; };
static struct scmq g_scm[SCM_SLOTS][2];
static int scmq_empty(struct scmq *q) { return q->head == q->tail; }
static int scmq_full(struct scmq *q)  { return (q->tail + 1) % SCM_QDEPTH == q->head; }
static struct scmq *scm_out(int ep) {                 /* where THIS endpoint sends */
    int ci = unix_ep_conn(ep); if (ci < 0 || ci >= SCM_SLOTS) return 0;
    return &g_scm[ci][ep & 1];
}
static struct scmq *scm_in(int ep) {                  /* where THIS endpoint receives from */
    int ci = unix_ep_conn(ep); if (ci < 0 || ci >= SCM_SLOTS) return 0;
    return &g_scm[ci][(ep & 1) ^ 1];
}

int app_scm_send(int ep, int fd) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    struct scmq *q = scm_out(ep); if (!q) return -1;
    if (scmq_full(q)) return -1;               /* the peer has not drained its queue */
    q->fe[q->tail] = a->fd[fd];                /* snapshot the descriptor (shares the underlying object) */
    q->fe[q->tail].cloexec = 0;                /* a freshly-received fd is not close-on-exec */
    /* A DESCRIPTOR IN FLIGHT MUST OWN ITS OBJECT (M2082).
     *
     * The queue held a COPY OF THE fdent and nothing else -- and for a memfd an
     * fdent is just an index. So the moment the sender closed its own fd, the
     * last reference went, memfd_unref freed the object, and the queued entry
     * named a slot that was no longer in use. The receiver then found nothing
     * and said "NO descriptor arrived (SCM_RIGHTS missing)", which is true of
     * the descriptor and wrong about the cause.
     *
     * That is exactly what libwayland does: wl_shm_create_pool passes the fd
     * and the client closes it immediately, because the protocol says the
     * compositor now owns it. Every shm pool in the system depended on the
     * sender happening not to close before the compositor got round to
     * reading. It worked until a cursor theme put a second pool in flight.
     *
     * The reference is handed on: app_scm_recv gives it to the fd it installs,
     * and app_scm_take_memfd_idx releases it after taking the compositor's
     * own -- so the count is unchanged for both, and the object simply cannot
     * die while it is in the queue. */
    if (q->fe[q->tail].type == 3) memfd_ref(q->fe[q->tail].obj);
    q->tail = (q->tail + 1) % SCM_QDEPTH;
    return 0;
}

int app_scm_recv(int ep) {
    struct app *a = cur(); if (!a) return -1;
    struct scmq *q = scm_in(ep); if (!q) return -1;
    if (scmq_empty(q)) return -1;              /* nothing pending */
    int fd = -1;
    for (int i = 3 /*APP_FD_FIRST: 0-2 are stdio*/; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }
    if (fd < 0) return -1;                     /* receiver's fd table is full */
    a->fd[fd] = q->fe[q->head];                /* install the passed descriptor */
    q->head = (q->head + 1) % SCM_QDEPTH;
    return fd;
}

/* IS THERE STILL A DESCRIPTOR QUEUED? (M2090) Non-consuming, because the
 * caller is asking in order to set MSG_CTRUNC -- "there were more than fitted"
 * -- and consuming one to find out would be the opposite of the answer. */
int app_scm_peek(int ep) {
    struct scmq *q = scm_in(ep); if (!q) return -1;
    return scmq_empty(q) ? -1 : 0;
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
/* The rows the scroll region covers. sr_bot <= 0 means "never set" = the whole
 * screen, which is also what a reset leaves behind. Clamped on READ rather
 * than on write, so a window resize can never leave a region pointing off the
 * bottom of a grid that just shrank. (M2057) */
static int sr_bottom(struct app *a) {
    return (a->sr_bot > 0 && a->sr_bot < a->rows) ? a->sr_bot : a->rows - 1;
}
static int sr_topr(struct app *a) {
    int t = (a->sr_top > 0 && a->sr_top < a->rows) ? a->sr_top : 0;
    return (t <= sr_bottom(a)) ? t : 0;
}
static int sr_is_full(struct app *a) { return sr_topr(a) == 0 && sr_bottom(a) == a->rows - 1; }

static void grid_blank_row(struct app *a, int r) {
    for (int c = 0; c < a->cols; c++) { a->grid[r][c] = ' '; a->gcol[r][c] = 0; a->gbg[r][c] = 0; }
}
static void grid_clear(struct app *a) {
    if (a->cols <= 0) { a->cols = APP_DEF_COLS; a->rows = APP_DEF_ROWS; }   /* first use: default size */
    for (int r = 0; r < APP_ROWS_MAX; r++)                                 /* blank the FULL array so cells exposed by a later grow are clean */
        for (int c = 0; c < APP_COLS_MAX; c++) { a->grid[r][c] = ' '; a->gcol[r][c] = 0; a->gbg[r][c] = 0; }
    a->cx = a->cy = 0;
    a->wrap_pend = 0;
    a->sb_count = 0; a->view = 0;
    a->gdirty = 1;
}
/* Scroll the region up by one row. Only the PRIMARY screen with NO scroll
 * region feeds the scrollback: a TUI that pins a header and scrolls a pane
 * inside it is not producing history, and an alternate screen never is. */
static void grid_scroll(struct app *a) {
    int top = sr_topr(a), bot = sr_bottom(a);
    if (sr_is_full(a) && !a->alt_on) {
        /* the top line is about to scroll off -- keep it in the scrollback ring */
        if (a->sb_count < SB_ROWS) {
            memcpy(a->sb[a->sb_count], a->grid[0], a->cols);
            memcpy(a->sbcol[a->sb_count], a->gcol[0], a->cols);   /* WITH its colours (M2057) */
            a->sb_count++;
            if (a->view > 0 && a->view < a->sb_count) a->view++;   /* stay on the same lines */
        } else {
            for (int r = 1; r < SB_ROWS; r++) {
                memcpy(a->sb[r-1], a->sb[r], a->cols);
                memcpy(a->sbcol[r-1], a->sbcol[r], a->cols);
            }
            memcpy(a->sb[SB_ROWS-1], a->grid[0], a->cols);
            memcpy(a->sbcol[SB_ROWS-1], a->gcol[0], a->cols);
        }
    }
    for (int r = top + 1; r <= bot; r++) {
        memcpy(a->grid[r-1], a->grid[r], a->cols);
        memcpy(a->gcol[r-1], a->gcol[r], a->cols);
        memcpy(a->gbg[r-1],  a->gbg[r],  a->cols);
    }
    grid_blank_row(a, bot);
    a->cy = bot;
}
/* Scroll the region DOWN by one row (ESC[L, ESC M). Nothing enters the
 * scrollback: these rows are moving away from history, not into it. */
static void grid_rscroll(struct app *a) {
    int top = sr_topr(a), bot = sr_bottom(a);
    for (int r = bot; r > top; r--) {
        memcpy(a->grid[r], a->grid[r-1], a->cols);
        memcpy(a->gcol[r], a->gcol[r-1], a->cols);
        memcpy(a->gbg[r],  a->gbg[r-1],  a->cols);
    }
    grid_blank_row(a, top);
}
/* Index: down one row, column kept -- ESC D, and what a deferred wrap does. */
static void grid_index(struct app *a) {
    if (a->cy == sr_bottom(a)) { int x = a->cx; grid_scroll(a); a->cx = x; }
    else if (a->cy < a->rows - 1) a->cy++;
}
static void grid_nl(struct app *a) { a->cx = 0; a->wrap_pend = 0; grid_index(a); }
/* Erase up to `n` echoed chars, but never past the input start (cx0,cy0) — so
 * history recall can't blank the prompt or earlier output. Handles wrapping. */
static void grid_erase(struct app *a, int n, int cx0, int cy0) {
    int avail = (a->cy - cy0) * a->cols + (a->cx - cx0);
    if (n > avail) n = avail;
    for (int i = 0; i < n; i++) {
        if (a->cx > 0) a->cx--;
        else if (a->cy > 0) { a->cy--; a->cx = a->cols - 1; }
        a->grid[a->cy][a->cx] = ' ';
        a->gcol[a->cy][a->cx] = 0; a->gbg[a->cy][a->cx] = 0;
    }
    a->wrap_pend = 0;
}
/* The colours a cell printed NOW should carry, inverse video applied (M2057).
 * SGR 7 swaps foreground and background, and with no background set that means
 * "default foreground on the current foreground" -- which is how every TUI
 * draws a selected row. Without it, a highlighted line was indistinguishable
 * from an unhighlighted one. */
static void cur_attrs(struct app *a, uint8_t *fg, uint8_t *bg) {
    uint8_t f = a->curcol, b = a->curbg;
    if (a->sgr_inv) {
        uint8_t nf = b ? (uint8_t)(b - 1) : 1;      /* default background reads as white */
        uint8_t nb = (uint8_t)(f + 1);
        f = nf; b = nb;
    }
    *fg = f; *bg = b;
}
static void grid_putc(struct app *a, char ch) {
    a->gdirty = 1;
    if (ch == '\n') { grid_nl(a); return; }
    if (ch == '\r') { a->cx = 0; a->wrap_pend = 0; return; }
    /* TAB IS NOT A GLYPH (M2057). font_glyphs[] populates rows 0x00-0x1F with
     * CP437 dingbats and dither blocks, and grid_putc drew them -- so a tab
     * painted a 25%-dither cell (a grey smudge) and advanced ONE column
     * instead of to the next tab stop. Those smudges were the visible
     * "artifacts" in an otherwise empty-looking terminal. */
    if (ch == '\t') {
        int stop = (a->cx + 8) & ~7;
        if (stop > a->cols - 1) stop = a->cols - 1;
        while (a->cx < stop) { a->grid[a->cy][a->cx] = ' '; a->cx++; }
        a->wrap_pend = 0;
        return;
    }
    if (ch == 8) { if (a->cx > 0) a->cx--; a->wrap_pend = 0; return; }     /* BS */
    if ((unsigned char)ch < 0x20 || (unsigned char)ch == 0x7F) return;     /* every other C0: not printable */
    /* DEFERRED WRAP: the pending flag set by the PREVIOUS character is spent
     * here, not when that character was printed. */
    if (a->wrap_pend) {
        if (a->no_wrap) a->cx = a->cols - 1;
        else { a->cx = 0; grid_index(a); }
        a->wrap_pend = 0;
    }
    if (a->cx >= a->cols) a->cx = a->cols - 1;
    uint8_t fg, bg; cur_attrs(a, &fg, &bg);
    a->grid[a->cy][a->cx] = ch;
    a->gcol[a->cy][a->cx] = fg;
    a->gbg[a->cy][a->cx]  = bg;
    if (a->cx + 1 >= a->cols) a->wrap_pend = 1;    /* park in the last column */
    else a->cx++;
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
        if (++a->cx >= a->cols) { a->cx = 0; grid_index(a); }
    a->wrap_pend = 0;
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
            char ch = ' '; uint32_t fg = 0x33FF66; uint8_t bgi = 0;
            if (L >= 0 && L < a->sb_count) {
                ch = a->sb[L][c];
                /* SCROLLBACK KEEPS ITS COLOURS (M2057). This used to hardcode
                 * green, so anything that scrolled off turned uniformly green
                 * -- including a diff, a syntax-highlighted listing, or the
                 * error a program printed before the prompt came back. */
                uint8_t sc = a->sbcol[L][c];
                fg = sc ? app_palette[sc & 15] : 0x33FF66;
            } else if (L >= a->sb_count && (L - a->sb_count) < a->rows) {
                int gr = L - a->sb_count; ch = a->grid[gr][c];
                fg = app_palette[a->gcol[gr][c] & 15];                     /* live grid: per-cell colour */
                bgi = a->gbg[gr][c];
            }
            int cx = px + c * font_width, cy = py + r * font_height;
            /* A cell with no background of its own keeps the window's own
             * translucent wallpaper tint; one that has asked for a background
             * gets it OPAQUE, because a highlight blended 18% into the desktop
             * is not a highlight. (M2057) */
            uint32_t bg = bgi ? app_palette[(bgi - 1) & 15]
                              : term_bg_blend(desktop_wallpaper_sample(cx, cy));
            fb_glyph(cx, cy, ch, fg, bg);
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

/* Process-slot enumeration for the reaper (M2025). Returns slot `i` only if it
 * holds a process that has EXITED and is still waiting to be reaped -- the WM
 * uses it to sweep up processes that own no window, which its windows[] loop
 * cannot see. Nothing else should walk apps[] from outside. */
int app_slot_max(void) { return MAX_APPS; }
app_t *app_exited_slot(int i) {
    if (i < 0 || i >= MAX_APPS) return 0;
    struct app *a = &apps[i];
    if (!a->used || !a->exited || a->zombie) return 0;
    return (app_t *)a;
}

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
    if (!a || !a->waiting) return;
    /* EVERY THREAD, NOT JUST THE MAIN ONE (M2083).
     *
     * wait4 may be called from any thread, and this woke only a->task. A
     * worker thread that forked and then waited blocked for ever: the child
     * exited, exit_group ran, this fired -- and the one task it woke was not
     * the one waiting. Same shape as M2075's app_request_signal, which woke
     * only the main thread for a process-directed signal, and for the same
     * reason: "the process" is not a single task and has not been since
     * threads arrived.
     *
     * Waking a thread that is not in wait4 is harmless -- it re-checks its own
     * condition and blocks again -- so there is nothing to be clever about
     * here. Guessing which thread is the one costs a wrong answer; waking all
     * of them costs a re-check. */
    if (a->task) task_wake((task_t *)a->task);
    for (int k = 0; k < APP_MAXTHREAD; k++)
        if (a->thr[k] && a->thr[k]->state != TASK_DEAD) task_wake(a->thr[k]);
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
/* Turn any of MY exited children into collectable zombies, in the WAITER's own
 * context (M2025).
 *
 * app_reap is the only thing that zombifies an exited child, and until now the
 * only thing that called it was the window manager's loop over windows[]. So a
 * child was reapable only if it owned a window -- and the WM stops handing out
 * windows at the MAX_WINDOWS cap, deliberately leaving the app PENDING rather
 * than dropping it. A child parked in that queue never zombified, so its
 * parent's wait4() blocked forever.
 *
 * That is a true deadlock, not a delay: the pending child can only get a window
 * once one CLOSES, closing goes through this same reap loop, and the window
 * that would have to close belongs to the parent -- which is the process stuck
 * in wait4(). Claude Code spawning its 17th helper wedged the machine, with
 * every core halted and no syscall for 45 seconds.
 *
 * Reaping from the waiter removes the dependency on the WM entirely: the parent
 * is by definition a different context from the dying child, which is all
 * app_reap's off_cpu rule requires. */
static int app_reap_children_of(struct app *me) {
    int did = 0;
    for (int i = 0; i < MAX_APPS; i++) {
        struct app *c = &apps[i];
        /* Read the flags once, unlocked, exactly as the WM's own reap loop
         * does: app_reap re-checks every one of them under its own rules. */
        if (!c->used || !c->exited || c->zombie || c->parent != me->pid) continue;
        if (app_reap((app_t *)c)) did = 1;
    }
    return did;
}

/* wait4's blocking and WNOHANG forms. `nohang` returns 0 (not -1) when children
 * exist but none is ready, which is what Linux does and what an event loop
 * polling its subprocesses depends on -- see the LXS_wait4_ case, which until
 * M2025 discarded the options argument and so blocked forever on WNOHANG. */
long app_wait4(int pid, int *status, int nohang) {
    struct app *me = cur();
    if (!me) return -1;
    for (;;) {
        app_reap_children_of(me);                  /* collect before looking (M2025) */
        uint64_t f = irq_save();
        struct app *z = 0; int have = 0, finishing = 0;
        for (int i = 0; i < MAX_APPS; i++) {
            struct app *c = &apps[i];
            if (!c->used || c->parent != me->pid) continue;
            if (pid > 0 && c->pid != pid) continue;
            have = 1;
            if (c->zombie) { z = c; break; }
            /* Exited, but app_reap above declined it: the task has set
             * TASK_DEAD and not yet finished its final context switch. It will
             * zombify within a tick, so poll rather than block -- nothing will
             * wake us, because the wake happens inside the reap we just
             * refused to complete. */
            if (c->exited) finishing = 1;
        }
        if (z) {
            int code = z->exit_code, cpid = z->pid;
            z->used = 0; z->zombie = 0;            /* collect the zombie slot */
            irq_restore(f);
            if (status) *status = code;
            return cpid;
        }
        if (!have) { irq_restore(f); return -1; }  /* no matching children to wait for */
        if (nohang) { irq_restore(f); return 0; }  /* children exist, none ready */
        if (finishing) { irq_restore(f); task_sleep_ms(1); continue; }
        me->waiting = 1;
        irq_restore(f);
        task_block();                              /* woken by app_reap when a child zombifies */
        me->waiting = 0;
    }
}
long app_waitpid(int pid, int *status) { return app_wait4(pid, status, 0); }
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
        app_reap_children_of(me);                  /* same self-reaping as wait4 (M2025) */
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
void app_task_forget_everywhere(void *t);   /* every stored waiter drops this task (M2053) */
static void app_fd_release(struct app *a);   /* close the process's fds/pipes (M1187; defined below) */
/* A task a reaper may now free: dead (and off its stack), or stopped for good
 * by app_stop_siblings (and off its stack). Anything else is still finishing
 * and must be left for the next pass. (M2025) */
static int app_task_reapable(task_t *t) {
    if (!t) return 1;
    if (t->state == TASK_DEAD)
        return __atomic_load_n(&t->off_cpu, __ATOMIC_ACQUIRE) != 0;
    if (t->state == TASK_STOPPED) return task_off_stack(t);
    return 0;
}
/* Free a task the gate above accepted -- but ONLY one that actually DIED.
 *
 * A STOPPED task must NOT have its memory freed, however certain we are that it
 * will never run again. Its task_t is still pointed at by whatever it was
 * blocked on when exit_group stopped it: mbox's `waiter`, mqueue's
 * send_waiter/recv_waiter, the uffd monitor, and every other subsystem that
 * parks a task_t* to wake later. Freeing it there hands those a poisoned
 * pointer, which is a General Protection Fault with rbx=dededededededede --
 * the heap's own free pattern -- in whatever touches it next.
 *
 * That is why this is not the place to reclaim them. The HANG fix is the gate
 * above accepting TASK_STOPPED so the process can zombify and release its
 * parent; the task_t is left allocated exactly as it was before M2025. It
 * leaks, as it always has, and reclaiming it needs every one of those
 * subsystems to drop its waiter first -- a separate piece of work, not a
 * side-effect of this one. */
static void app_task_release(task_t *t) {
    if (!t) return;
    if (t->state == TASK_DEAD && __atomic_load_n(&t->off_cpu, __ATOMIC_ACQUIRE))
        task_free(t);
    else
        task_stop(t);                  /* never scheduled again, never freed here */
}
int app_reap(app_t *a) {
    if (!a) return 1;
    if (a->zombie) return 1;                  /* already reaped to a zombie: resources freed, slot kept for waitpid */
    /* off_cpu, not just TASK_DEAD: the state is set BEFORE the dying task's
     * final context_switch, which still writes to its own task_t. Freeing it
     * on state alone is a use-after-free of a live kernel stack. (M1961) */
    /* A STOPPED MAIN TASK COUNTS AS GONE TOO (M2025). This gate used to demand
     * TASK_DEAD, and app_stop_siblings leaves the main task STOPPED whenever a
     * non-main thread is the one that called exit_group -- the normal shape for
     * every Linux runtime. A STOPPED task never reaches TASK_DEAD (it is never
     * scheduled again to run task_exit), so the gate was unsatisfiable: the
     * process stayed un-reaped and un-zombified for ever and its parent hung in
     * wait4(). See task_off_stack for why STOPPED needs its own proof. */
    if (a->used && a->exited && (!a->task || app_task_reapable(a->task))) {
        /* ONE REAPER, ATOMICALLY (M2072).
         *
         * This function frees the address space, every memfd mapping, the
         * graphics canvas, the alternate screen, the main task and every
         * thread -- and it had NO serialisation of any kind while being called
         * from four independent places: the window manager's loop, a parent
         * inside wait4 (app_reap_children_of), app_run_linux_sync's own loop,
         * and desktop.c's windowless sweep. Two cores entering together both
         * see a child that is not yet a zombie, both run the whole teardown,
         * and both free the same task_t.
         *
         * The kernel said so exactly:
         *
         *   *** KERNEL PANIC: General Protection Fault
         *     rbx=dededededededede  rdi=dededededededede
         *     [0] kfree+0x40  [1] task_free+0x2c  [2] app_reap+0x602
         *     [3] app_reap_children_of+0x5e  [4] app_wait4+0x38
         *
         * -- kfree handed the heap's own poison, because the second reaper
         * read a pointer out of a struct the first had already freed. Claude
         * Code spawns `git` children and wait4()s them while the window
         * manager is sweeping the same slots, so it hit this constantly: the
         * TUI never appeared because the MACHINE died.
         *
         * Both exits from the body below are terminal -- the slot becomes a
         * zombie or is freed outright, and either makes a later reap a no-op --
         * so the claim is never released. A loser returns 0, "not reaped yet",
         * and its caller simply looks again. */
        if (__atomic_exchange_n(&a->reaping, 1, __ATOMIC_ACQ_REL)) return 0;
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
        /* THE off_cpu RULE APPLIES TO THE MAIN TASK TOO (M1994). The thread
         * loop below says "same rule as the main task above" -- describing a
         * check that was not there. A task sets TASK_DEAD and only then
         * performs its final context switch, and the reaper runs on some other
         * core, so the dying task may still be on its own stack. Freeing it
         * there returns the kernel stack to the allocator while it is in use. */
        if (a->task) {
            task_t *mt = a->task;
            app_task_forget_everywhere(mt);
            if (app_task_reapable(mt))
                app_task_release(mt);           /* dead, or stopped for good -- either way off its stack */
            else
                task_stop(mt);                  /* still finishing: never scheduled again, never freed here */
        }
        a->task = 0;
        /* Un-joined worker threads (M1139): free the dead ones; STOP any still
         * alive so the scheduler skips them — they must never run once we free
         * the shared address space just below. */
        for (int i = 0; i < APP_MAXTHREAD; i++) {
            task_t *t = a->thr[i];
            if (!t) continue;
            /* Same off_cpu rule as the main task above: a DEAD thread may still
             * be finishing its final context_switch. (M1961) */
            app_task_forget_everywhere(t);       /* and not from the reaper's side either (M1990) */
            /* Same rule as the main task: a STOPPED thread is never scheduled
             * again either, so once it is off its stack its 256 KB kernel stack
             * can go back. Leaving them STOPPED-but-allocated leaked a stack
             * per thread per exited process. (M2025) */
            if (app_task_reapable(t)) app_task_release(t);
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
        /* Release this process's memfd mappings BEFORE the address space goes
         * away. The teardown below decrements each frame's reference (they are
         * kernel-heap pages the process only borrowed), but nothing there
         * knows about the OBJECT -- and a memfd whose last fd was closed while
         * still mapped is kept alive precisely by this reference. (M1985) */
        for (int vi = 0; vi < a->nvma; vi++)
            if (a->vma[vi].mfd >= 0) { memfd_unref(a->vma[vi].mfd); a->vma[vi].mfd = -1; }
        /* A vfork child that never exec'd still BORROWS its parent's address
         * space; freeing it here would free the parent's memory. (M2006) */
        if (!a->cr3_borrowed) vmm_destroy_address_space(a->cr3);
        a->cr3_borrowed = 0;
        a->cr3 = 0;
        if (a->gfx) { kfree(a->gfx); a->gfx = 0; }   /* graphics canvas (kernel heap) */
        if (a->alt) { kfree(a->alt); a->alt = 0; a->alt_on = 0; }   /* alternate screen (M2057) */
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

/* ONE-REAPER SELF-TEST (M2072).
 *
 * The bug is a RACE -- two cores inside app_reap for the same process -- and a
 * race cannot be reproduced by calling the function twice in a row: the first
 * call finishes and leaves a terminal state the second correctly ignores. What
 * CAN be tested directly is the invariant the fix installs: a reaper that
 * arrives while another is mid-teardown must be turned away and must change
 * nothing.
 *
 * So set the claim by hand -- exactly the state another core leaves while it is
 * inside the body -- and assert the second entry does nothing. Without the
 * claim, app_reap runs the whole teardown and frees the slot, which is the
 * double free the kernel died on.
 *
 * Uses a REAL apps[] slot with no task, no threads, no VMAs, and the caller's
 * own CR3 (so the msync context switch is a no-op and nothing is destroyed). */
int app_reap_selftest(void) {
    int fails = 0, slot = -1;
    for (int i = 0; i < MAX_APPS; i++) if (!apps[i].used) { slot = i; break; }
    if (slot < 0) { kprintf("[reaptest] no free app slot (skipped)\n"); return 0; }
    struct app *a = &apps[slot];
    memset(a, 0, sizeof *a);
    a->used = 1; a->exited = 1; a->task = 0; a->parent = 0;
    a->pid = 0x7000 + slot;                     /* not a real pid: nothing else refers to it */
    a->nvma = 0;
    __asm__ volatile("mov %%cr3, %0" : "=r"(a->cr3));
    a->cr3_borrowed = 1;                        /* never destroy the caller's own address space */

    /* 1. A second reaper, arriving while the first is inside the body, must be
     *    turned away and must not touch the slot. */
    a->reaping = 1;
    int rc = app_reap((app_t *)a);
    if (rc != 0)   { kprintf("[reaptest] FAIL a second reaper reported success (%d)\n", rc); fails++; }
    else             kprintf("[reaptest] ok   a second reaper is turned away\n");
    if (!a->used)  { kprintf("[reaptest] FAIL a second reaper FREED the slot -- this is the double free\n"); fails++; }
    else             kprintf("[reaptest] ok   ...and changed nothing: the slot is still allocated\n");

    /* 2. Once the claim is clear, a reaper does its job. */
    a->reaping = 0;
    rc = app_reap((app_t *)a);
    if (!rc)       { kprintf("[reaptest] FAIL an unclaimed reap did not complete\n"); fails++; }
    else             kprintf("[reaptest] ok   an unclaimed reap completes normally\n");
    if (a->used)   { kprintf("[reaptest] FAIL the slot was not released\n"); fails++; }
    else             kprintf("[reaptest] ok   ...and releases the slot\n");

    a->used = 0;
    if (fails) kprintf("[reaptest] REAPSELFTEST FAILED (%d)\n", fails);
    else       kprintf("[reaptest] REAPSELFTEST PASSED (4 checks)\n");
    return fails;
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
    if (a && a->kill) { a->exited = 1; app_stop_siblings(a); task_exit(); }   /* threads die with it (M1999) */
}

/* WM polls this: returns 1 (and clears) if the app's grid changed since asked. */
int app_dirty_clear(app_t *a) { int d = a->gdirty; a->gdirty = 0; return d; }

/* ---- input queue (filled by the WM, drained by SYS_read) ---- */
#define SIGINT 2
/* --- termios, for real (M2014) ---------------------------------------------
 *
 * Linux's cooked defaults, which is what a fresh terminal reports. ICRNL is
 * the load-bearing one: it says "translate the Return key's CR into NL", and
 * a program that CLEARS it is telling us it wants the raw CR.
 *
 * Our keyboard produces NL for Return natively, because every OS-DEV app
 * expects that. So the translation runs the other way here: cooked stays NL,
 * and raw becomes CR. Getting this backwards is exactly what stopped Claude
 * Code's login -- Ink maps \r to `key.return` and nothing else does, so the
 * selection list could be moved but never chosen. The onboarding rendered
 * perfectly and the Enter key did nothing. */
#define TIO_ICRNL  0x0100u          /* c_iflag */
#define TIO_ISIG   0x0001u          /* c_lflag */
#define TIO_ICANON 0x0002u
#define TIO_ECHO   0x0008u
static void tio_defaults(struct app *a) {
    if (!a || a->tio_valid) return;
    a->tio_iflag = 0x0500;   /* ICRNL | IXON */
    a->tio_oflag = 0x0005;   /* OPOST | ONLCR */
    a->tio_cflag = 0x00BF;   /* B38400 | CS8 | CREAD */
    a->tio_lflag = 0x8A3B;   /* ISIG ICANON ECHO ECHOE ECHOK ECHOCTL IEXTEN */
    for (int i = 0; i < 19; i++) a->tio_cc[i] = 0;
    a->tio_cc[0] = 3; a->tio_cc[1] = 28; a->tio_cc[2] = 127; a->tio_cc[3] = 21;
    a->tio_cc[4] = 4; a->tio_cc[6] = 1;  a->tio_cc[8] = 17;  a->tio_cc[9] = 19;
    a->tio_cc[10] = 26;
    a->tio_valid = 1;
}
int app_termios_get(uint32_t *ifl, uint32_t *ofl, uint32_t *cfl, uint32_t *lfl, uint8_t *cc) {
    struct app *a = cur(); if (!a) return -1;
    tio_defaults(a);
    if (ifl) *ifl = a->tio_iflag; if (ofl) *ofl = a->tio_oflag;
    if (cfl) *cfl = a->tio_cflag; if (lfl) *lfl = a->tio_lflag;
    if (cc) for (int i = 0; i < 19; i++) cc[i] = a->tio_cc[i];
    return 0;
}
int app_termios_set(uint32_t ifl, uint32_t ofl, uint32_t cfl, uint32_t lfl, const uint8_t *cc) {
    struct app *a = cur(); if (!a) return -1;
    tio_defaults(a);
    /* REPORT THE MODE CHANGE ONCE. "The keyboard does nothing" and "the program
     * never asked for raw mode" are indistinguishable from the outside, and one
     * line separates them. */
    if (((a->tio_iflag ^ ifl) & TIO_ICRNL) || ((a->tio_lflag ^ lfl) & (TIO_ICANON | TIO_ECHO | TIO_ISIG)))
        kprintf("[tty] pid %d set termios: %s, echo %s, signals %s, Return -> %s\n",
                a->pid, (lfl & TIO_ICANON) ? "canonical" : "RAW",
                (lfl & TIO_ECHO) ? "on" : "off", (lfl & TIO_ISIG) ? "on" : "off",
                (ifl & TIO_ICRNL) ? "NL" : "CR");
    a->tio_iflag = ifl; a->tio_oflag = ofl; a->tio_cflag = cfl; a->tio_lflag = lfl;
    if (cc) for (int i = 0; i < 19; i++) a->tio_cc[i] = cc[i];
    return 0;
}
/* Does this app want the Return key as CR rather than NL? */
static int tio_wants_cr(struct app *a) {
    if (!a) return 0;
    tio_defaults(a);
    return (a->tio_iflag & TIO_ICRNL) ? 0 : 1;
}
/* ...and should Ctrl-C be a SIGNAL, or the byte 0x03? A raw-mode TUI handles
 * its own interrupt key: Claude Code cancels a running turn with it. */
static int tio_wants_isig(struct app *a) {
    if (!a) return 1;
    tio_defaults(a);
    return (a->tio_lflag & TIO_ISIG) ? 1 : 0;
}
int app_tio_echo(void) {
    struct app *a = cur(); if (!a) return 1;
    tio_defaults(a);
    return (a->tio_lflag & TIO_ECHO) ? 1 : 0;
}

void app_key(app_t *a, char c) {
    /* Ctrl-C (0x83): if this app installed a SIGINT handler, raise it asynchronously
     * (interrupting even a runaway compute loop) instead of queueing the key. Opt-in,
     * so the shell — which polls 0x83 to break its own loops — is unaffected. M1083. */
    if ((unsigned char)c == 0x83 && !tio_wants_isig(a)) {
        /* ISIG cleared: the program asked to see the interrupt character
         * ITSELF rather than be signalled by it (M2014). A raw-mode TUI
         * always does -- Claude Code cancels a running turn on Ctrl-C -- and
         * signalling it instead kills the program the user was trying to
         * interrupt. Fall through as the byte 0x03, which is what a terminal
         * in raw mode actually delivers. */
        c = 0x03;
    } else {
        if ((unsigned char)c == 0x83 && fg_pgid) { app_killpg(fg_pgid, SIGINT); return; }   /* job control: ^C -> the foreground group (M1176) */
        if ((unsigned char)c == 0x83 && a->sig_handler[SIGINT]) { app_request_signal(a, SIGINT); return; }
    }
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
static int iq_has(struct app *a) {
    return a && (a->paste_pos < a->paste_len || a->ih != a->it);
}
/* How many bytes iq_get would hand over before blocking (M2086). A paste is
 * not capped by IQ_SIZE, so it is counted separately and first -- the same
 * order iq_get drains them in. */
static int iq_count(struct app *a) {
    if (!a) return 0;
    int paste = (a->paste_pos < a->paste_len) ? (a->paste_len - a->paste_pos) : 0;
    int ring  = (a->ih - a->it + IQ_SIZE) % IQ_SIZE;
    return paste + ring;
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
static uint8_t ansi_color(int code, int bold);   /* fwd: the 256-colour mappers use it */
/* The xterm 256-colour cube, folded onto our 16-entry palette (M2004): 0-15
 * are the ANSI colours, 16-231 a 6x6x6 RGB cube, 232-255 a grey ramp. */
static uint8_t ansi_rgb(int r, int g, int b);
static uint8_t ansi_256(int idx) {
    if (idx < 0) idx = 0;
    if (idx < 8)   return ansi_color(30 + idx, 0);
    if (idx < 16)  return ansi_color(90 + (idx - 8), 0);
    if (idx < 232) { int c = idx - 16;
                     int r = (c / 36) * 51, g = ((c / 6) % 6) * 51, b = (c % 6) * 51;
                     return ansi_rgb(r, g, b); }
    { int v = 8 + (idx - 232) * 10; return ansi_rgb(v, v, v); }
}
/* Nearest of our sixteen by brightness + dominant channel -- exact matching is
 * not the point, legibility is. */
static uint8_t ansi_rgb(int r, int g, int b) {
    int mx = r > g ? (r > b ? r : b) : (g > b ? g : b);
    int mn = r < g ? (r < b ? r : b) : (g < b ? g : b);
    int bright = mx > 160;
    if (mx - mn < 40) return mx < 64 ? 8 : (mx < 170 ? 0 : 1);    /* grey ramp: dark, normal, white */
    if (r == mx && g > b + 40) return bright ? 12 : 3;            /* yellow */
    if (r == mx) return (b > g + 40) ? (bright ? 11 : 5) : (bright ? 13 : 2);   /* magenta / red */
    if (g == mx) return (b > r + 40) ? (bright ? 10 : 4) : (bright ? 9 : 0);    /* cyan / green */
    return bright ? 14 : 6;                                       /* blue */
}

static const uint8_t ansi_base8[8]   = { 8, 2, 0, 3, 6, 5, 4, 1 };   /* blk red grn yel blu mag cyn wht */
static const uint8_t ansi_bright8[8] = { 8, 13, 9, 12, 14, 11, 10, 1 };
static uint8_t ansi_color(int code, int bold) {
    if (code >= 90 && code <= 97) return ansi_bright8[code - 90];
    if (code >= 30 && code <= 37) return (bold ? ansi_bright8 : ansi_base8)[code - 30];
    return 0;
}
/* Brighten a colour ALREADY CHOSEN, for "ESC[1m" arriving on its own after the
 * foreground was set -- which is the normal order, and which the old local-
 * variable `bold` could not express at all. (M2057) */
static uint8_t ansi_bold(uint8_t col) {
    for (int i = 0; i < 8; i++) if (ansi_base8[i] == col) return ansi_bright8[i];
    return col;
}

/* ---- the CSI layer (M2057) -------------------------------------------------
 *
 * What used to be here was "a tiny VT100 subset": SGR foreground, four cursor
 * moves, J and K. Everything else was swallowed, and an unrecognised final
 * byte left no trace -- which made the gaps invisible. They were not small:
 *
 *   - no background colour at all, so dark-on-light was unrenderable
 *   - no alternate screen, so a TUI painted over the shell's own scrollback
 *   - no scroll region, so a pinned header scrolled with its pane
 *   - no cursor hide, so the blinking block caret ate a cell of every frame
 *   - no DSR reply, so a program that asks where the cursor is waits forever
 *   - no insert/delete, so a redraw that shifts a line had to repaint it
 *
 * The parser keeps its shape: buffer the parameter bytes, dispatch on the
 * final. The private-mode introducer ('?', '>', '<', '=') is now RECORDED
 * rather than parsed as a digit -- without it "ESC[?25l" and "ESC[25l" are the
 * same sequence, and "ESC[>4;2m" was being executed as an SGR. */
static void iq_push_raw(struct app *a, char c) {
    if (!a) return;
    uint64_t f = irq_save();
    int n = (a->ih + 1) % IQ_SIZE;
    if (n != a->it) { a->iq[a->ih] = c; a->ih = n; }
    irq_restore(f);
}
/* Answer a query ON THE INPUT QUEUE -- the terminal talking back to the
 * program, which nothing here had ever done. A TUI that sends ESC[6n and
 * blocks until it reads the report hangs forever against a terminal that never
 * replies, and "hangs with every core idle" is exactly the symptom that is
 * hardest to attribute. */
static void term_reply(struct app *a, const char *s) {
    for (int i = 0; s[i]; i++) iq_push_raw(a, s[i]);
    if (a->task) task_wake(a->task);
}
static void term_num(char *out, int v) {          /* small unsigned -> decimal */
    char t[8]; int n = 0;
    if (v <= 0) { out[0] = '0'; out[1] = 0; return; }
    while (v && n < 7) { t[n++] = (char)('0' + v % 10); v /= 10; }
    int k = 0; while (n) out[k++] = t[--n];
    out[k] = 0;
}
static void term_erase_cells(struct app *a, int r, int x0, int x1) {
    if (r < 0 || r >= a->rows) return;
    if (x0 < 0) x0 = 0;
    if (x1 > a->cols) x1 = a->cols;
    /* Erasing paints the CURRENT background, which is what makes "ESC[41m
     * ESC[2J" a red screen rather than a transparent one. */
    uint8_t fg, bg; cur_attrs(a, &fg, &bg); (void)fg;
    for (int x = x0; x < x1; x++) { a->grid[r][x] = ' '; a->gcol[r][x] = 0; a->gbg[r][x] = bg; }
}
static void alt_enter(struct app *a) {
    if (a->alt_on) return;
    if (!a->alt) { a->alt = kmalloc(sizeof *a->alt); if (!a->alt) return; }
    struct altscreen *s = a->alt;
    memcpy(s->grid, a->grid, sizeof s->grid);
    memcpy(s->gcol, a->gcol, sizeof s->gcol);
    memcpy(s->gbg,  a->gbg,  sizeof s->gbg);
    s->cx = a->cx; s->cy = a->cy;
    s->curcol = a->curcol; s->curbg = a->curbg; s->bold = a->sgr_bold; s->inv = a->sgr_inv;
    s->sr_top = a->sr_top; s->sr_bot = a->sr_bot;
    s->sb_count = a->sb_count; s->view = a->view;
    a->alt_on = 1;
    /* A fresh screen, and NO scrollback: an alternate screen has none, which is
     * why scrolling a full-screen TUI must not push history. */
    for (int r = 0; r < a->rows; r++) grid_blank_row(a, r);
    a->cx = a->cy = 0; a->wrap_pend = 0;
    a->sr_top = 0; a->sr_bot = 0;
    a->view = 0;
    a->gdirty = 1;
}
static void alt_leave(struct app *a) {
    if (!a->alt_on || !a->alt) { a->alt_on = 0; return; }
    struct altscreen *s = a->alt;
    memcpy(a->grid, s->grid, sizeof s->grid);
    memcpy(a->gcol, s->gcol, sizeof s->gcol);
    memcpy(a->gbg,  s->gbg,  sizeof s->gbg);
    a->cx = s->cx; a->cy = s->cy; a->wrap_pend = 0;
    a->curcol = s->curcol; a->curbg = s->curbg; a->sgr_bold = s->bold; a->sgr_inv = s->inv;
    a->sr_top = s->sr_top; a->sr_bot = s->sr_bot;
    a->sb_count = s->sb_count; a->view = s->view;
    a->alt_on = 0;
    a->gdirty = 1;
}
/* ESC[?<n>h / ESC[?<n>l -- the DEC private modes. Recognising the four that
 * matter and IGNORING the rest deliberately: mouse reporting (1000/1002/1003/
 * 1006) and focus events (1004) have no input path to encode into, and
 * pretending otherwise would be the "granted in name only" mistake again. */
static void term_priv_mode(struct app *a, int n, int set) {
    switch (n) {
    case 7:    a->no_wrap = set ? 0 : 1; break;            /* DECAWM */
    case 25:   a->caret_off = set ? 0 : 1; break;          /* DECTCEM: show/hide the cursor */
    case 1047:
    case 1049: if (set) alt_enter(a); else alt_leave(a); break;
    case 2004: a->bracket_paste = set ? 1 : 0; break;
    default:   break;
    }
}
static void ansi_csi(struct app *a, char final) {
    int p[16] = {0}, np = 0, cur = 0;
    for (int i = 0; i < a->csilen; i++) {
        char c = a->csi[i];
        if (c >= '0' && c <= '9') cur = cur * 10 + (c - '0');
        else if (c == ';') { if (np < 15) p[np++] = cur; cur = 0; }
    }
    if (np < 16) p[np++] = cur;          /* the last/only param; np >= 1 */
    int n = p[0] ? p[0] : 1;             /* default-1 count for cursor moves */
    int top = sr_topr(a), bot = sr_bottom(a);

    if (a->csipriv == '?') {             /* a DEC private mode, not a cursor op */
        if (final == 'h' || final == 'l')
            for (int i = 0; i < np; i++) term_priv_mode(a, p[i], final == 'h');
        a->gdirty = 1;
        return;
    }
    if (a->csipriv) { a->gdirty = 1; return; }   /* '>' / '<' / '=' : queries we do not answer */

    switch (final) {
    case 'm': {                          /* SGR: colour + the attributes that persist */
        for (int i = 0; i < np; i++) {
            int v = p[i];
            if (v == 0) { a->curcol = 0; a->curbg = 0; a->sgr_bold = 0; a->sgr_inv = 0; }
            /* BOLD IS STATE, NOT A MODIFIER ON THIS SEQUENCE. It used to be a
             * local `int`, so "ESC[1m" alone did nothing and only "ESC[1;31m"
             * brightened -- which is not how any program emits it. */
            else if (v == 1) { a->sgr_bold = 1; a->curcol = ansi_bold(a->curcol); }
            else if (v == 22) a->sgr_bold = 0;
            else if (v == 7)  a->sgr_inv = 1;
            else if (v == 27) a->sgr_inv = 0;
            else if (v == 39) a->curcol = 0;
            else if (v == 49) a->curbg = 0;
            else if ((v >= 30 && v <= 37) || (v >= 90 && v <= 97)) a->curcol = ansi_color(v, a->sgr_bold);
            else if (v >= 40 && v <= 47) a->curbg = (uint8_t)(1 + ansi_color(v - 10, 0));
            else if (v >= 100 && v <= 107) a->curbg = (uint8_t)(1 + ansi_color(v - 60, 0));
            /* 256-COLOUR (M2004): "38;5;N" is a foreground index, and it is
             * what every modern TUI actually emits -- Claude Code uses almost
             * nothing else. Skipping it left the colour at whatever came
             * before AND left the two following parameters to be misread as
             * colours in their own right. Fold the cube onto our 16. */
            else if (v == 38 && i + 2 < np && p[i + 1] == 5) { a->curcol = ansi_256(p[i + 2]); i += 2; }
            else if (v == 48 && i + 2 < np && p[i + 1] == 5) { a->curbg = (uint8_t)(1 + ansi_256(p[i + 2])); i += 2; }
            else if (v == 38 && i + 4 < np && p[i + 1] == 2) { a->curcol = ansi_rgb(p[i+2], p[i+3], p[i+4]); i += 4; }
            else if (v == 48 && i + 4 < np && p[i + 1] == 2) { a->curbg = (uint8_t)(1 + ansi_rgb(p[i+2], p[i+3], p[i+4])); i += 4; }
        }
        break;
    }
    case 'G':                            /* CHA: cursor to an absolute COLUMN (M2004) */
        /* A TUI that draws boxes positions by column constantly -- "ESC[4G" is
         * the single most common sequence Claude Code emits. Without it every
         * one of them printed as text and nothing lined up. */
        a->cx = (p[0] ? p[0] : 1) - 1;
        if (a->cx < 0) a->cx = 0; if (a->cx >= a->cols) a->cx = a->cols - 1;
        a->wrap_pend = 0;
        break;
    case 'd':                            /* VPA: cursor to an absolute ROW */
        a->cy = (p[0] ? p[0] : 1) - 1;
        if (a->cy < 0) a->cy = 0; if (a->cy >= a->rows) a->cy = a->rows - 1;
        break;
    case 'A': a->cy -= n; if (a->cy < 0) a->cy = 0; a->wrap_pend = 0; break;
    case 'B': a->cy += n; if (a->cy >= a->rows) a->cy = a->rows - 1; a->wrap_pend = 0; break;
    case 'C': a->cx += n; if (a->cx >= a->cols) a->cx = a->cols - 1; a->wrap_pend = 0; break;
    case 'D': a->cx -= n; if (a->cx < 0) a->cx = 0; a->wrap_pend = 0; break;
    case 'E': a->cx = 0; a->cy += n; if (a->cy >= a->rows) a->cy = a->rows - 1; a->wrap_pend = 0; break;  /* CNL */
    case 'F': a->cx = 0; a->cy -= n; if (a->cy < 0) a->cy = 0; a->wrap_pend = 0; break;                   /* CPL */
    case 'H': case 'f': {                /* cursor to row;col (1-based) */
        int row = p[0] ? p[0] : 1, col = (np >= 2 && p[1]) ? p[1] : 1;
        a->cy = row - 1; a->cx = col - 1;
        if (a->cy < 0) a->cy = 0; if (a->cy >= a->rows) a->cy = a->rows - 1;
        if (a->cx < 0) a->cx = 0; if (a->cx >= a->cols) a->cx = a->cols - 1;
        a->wrap_pend = 0;
        break;
    }
    case 'J': {                          /* erase in display: 0 fwd, 1 back, 2 all, 3 all + scrollback */
        int m = p[0];
        if (m == 1) {                    /* BACKWARD -- this used to erase forward (M2057) */
            for (int y = 0; y < a->cy; y++) term_erase_cells(a, y, 0, a->cols);
            term_erase_cells(a, a->cy, 0, a->cx + 1);
        } else if (m == 2 || m == 3) {
            for (int y = 0; y < a->rows; y++) term_erase_cells(a, y, 0, a->cols);
            /* ED does NOT home the cursor. Doing it anyway was harmless only
             * because Ink follows ESC[2J with ESC[H; anything that does not
             * got its cursor moved out from under it. */
            if (m == 3) { a->sb_count = 0; a->view = 0; }
        } else {
            term_erase_cells(a, a->cy, a->cx, a->cols);
            for (int y = a->cy + 1; y < a->rows; y++) term_erase_cells(a, y, 0, a->cols);
        }
        a->wrap_pend = 0;
        break;
    }
    case 'K': {                          /* erase in line (0 to-eol, 1 from-bol, 2 whole) */
        int m = p[0];
        int x0 = (m == 1 || m == 2) ? 0 : a->cx;
        int x1 = (m == 1) ? a->cx + 1 : a->cols;
        term_erase_cells(a, a->cy, x0, x1);
        a->wrap_pend = 0;
        break;
    }
    case 'L':                            /* IL: insert n blank lines at the cursor, within the region */
        if (a->cy >= top && a->cy <= bot)
            for (int k = 0; k < n; k++) {
                for (int r = bot; r > a->cy; r--) {
                    memcpy(a->grid[r], a->grid[r-1], a->cols);
                    memcpy(a->gcol[r], a->gcol[r-1], a->cols);
                    memcpy(a->gbg[r],  a->gbg[r-1],  a->cols);
                }
                grid_blank_row(a, a->cy);
            }
        break;
    case 'M':                            /* DL: delete n lines at the cursor, within the region */
        if (a->cy >= top && a->cy <= bot)
            for (int k = 0; k < n; k++) {
                for (int r = a->cy; r < bot; r++) {
                    memcpy(a->grid[r], a->grid[r+1], a->cols);
                    memcpy(a->gcol[r], a->gcol[r+1], a->cols);
                    memcpy(a->gbg[r],  a->gbg[r+1],  a->cols);
                }
                grid_blank_row(a, bot);
            }
        break;
    case 'P': {                          /* DCH: delete n characters, shifting the rest of the line left */
        int cnt = n; if (cnt > a->cols - a->cx) cnt = a->cols - a->cx;
        for (int x = a->cx; x < a->cols - cnt; x++) {
            a->grid[a->cy][x] = a->grid[a->cy][x + cnt];
            a->gcol[a->cy][x] = a->gcol[a->cy][x + cnt];
            a->gbg[a->cy][x]  = a->gbg[a->cy][x + cnt];
        }
        term_erase_cells(a, a->cy, a->cols - cnt, a->cols);
        break;
    }
    case '@': {                          /* ICH: insert n blanks, shifting the rest of the line right */
        int cnt = n; if (cnt > a->cols - a->cx) cnt = a->cols - a->cx;
        for (int x = a->cols - 1; x >= a->cx + cnt; x--) {
            a->grid[a->cy][x] = a->grid[a->cy][x - cnt];
            a->gcol[a->cy][x] = a->gcol[a->cy][x - cnt];
            a->gbg[a->cy][x]  = a->gbg[a->cy][x - cnt];
        }
        term_erase_cells(a, a->cy, a->cx, a->cx + cnt);
        break;
    }
    case 'X':                            /* ECH: erase n characters in place */
        term_erase_cells(a, a->cy, a->cx, a->cx + n);
        break;
    case 'S': for (int k = 0; k < n; k++) grid_scroll(a);  break;   /* SU */
    case 'T': for (int k = 0; k < n; k++) grid_rscroll(a); break;   /* SD */
    case 'r': {                          /* DECSTBM: set the scroll region */
        int t = p[0] ? p[0] : 1;
        int b = (np >= 2 && p[1]) ? p[1] : a->rows;
        if (t < 1) t = 1;
        if (b > a->rows) b = a->rows;
        if (t >= b) { a->sr_top = 0; a->sr_bot = 0; }     /* degenerate = reset to full screen */
        else { a->sr_top = t - 1; a->sr_bot = b - 1; }
        a->cx = 0; a->cy = sr_topr(a); a->wrap_pend = 0;  /* DECSTBM homes into the region */
        break;
    }
    case 's':                            /* SCOSC: save cursor */
        a->sv_cx = a->cx; a->sv_cy = a->cy; a->sv_col = a->curcol; a->sv_bg = a->curbg;
        a->sv_bold = a->sgr_bold; a->sv_inv = a->sgr_inv; a->sv_valid = 1;
        break;
    case 'u':                            /* SCORC: restore cursor */
        if (a->sv_valid) {
            a->cx = a->sv_cx; a->cy = a->sv_cy; a->curcol = a->sv_col; a->curbg = a->sv_bg;
            a->sgr_bold = a->sv_bold; a->sgr_inv = a->sv_inv;
            if (a->cx >= a->cols) a->cx = a->cols - 1;
            if (a->cy >= a->rows) a->cy = a->rows - 1;
            a->wrap_pend = 0;
        }
        break;
    case 'n': {                          /* DSR: the terminal ANSWERS */
        if (p[0] == 6) {
            char b[16]; char rr[8], cc[8];
            term_num(rr, a->cy + 1); term_num(cc, a->cx + 1);
            int k = 0; b[k++] = 0x1B; b[k++] = '[';
            for (int i = 0; rr[i]; i++) b[k++] = rr[i];
            b[k++] = ';';
            for (int i = 0; cc[i]; i++) b[k++] = cc[i];
            b[k++] = 'R'; b[k] = 0;
            term_reply(a, b);
        } else if (p[0] == 5) term_reply(a, "\x1b[0n");    /* "terminal OK" */
        break;
    }
    case 'c':                            /* DA: primary device attributes -- "a VT102" */
        term_reply(a, "\x1b[?6c");
        break;
    default: break;
    }
    a->gdirty = 1;
}

/* App stdout. Bytes pass straight to the grid EXCEPT ANSI escape sequences
 * (ESC [ ... <letter>), which are parsed for colour/cursor/erase. Output with
 * no ESC byte renders byte-identically to before, so existing apps are
 * unaffected. */
/* Write into a SPECIFIC app's window grid (M1988).
 *
 * A Linux process has no window of its own: its stdout goes to the kernel
 * console, which the desktop covers -- so `linux /usr/bin/claude --help`
 * rendered five hundred lines of help into a console nobody could see, and
 * from the shell it looked like nothing happened at all. A Linux binary
 * launched from a shell now writes into THAT SHELL's window, which is what
 * anyone typing the command expects. */
void app_write_to(app_t *dest, const char *buf, unsigned len) {
    struct app *a = (struct app *)dest;
    if (!a || !a->used) return;
    /* Say it ONCE per destination. The property worth asserting is not "the
     * program produced output" -- the serial log shows that either way, which
     * is why the bug survived -- but "the output went to a WINDOW rather than
     * the console". One line names exactly that, and a screenshot heuristic
     * that tries to infer it from pixels turns out not to be able to: the
     * output lands on the line that already holds the next prompt, so a broken
     * run and a working one have the same number of text lines. */
    if (!a->out_announced) {
        a->out_announced = 1;
        kprintf("[app] a Linux child's stdout is going to the window of pid %d\n", a->pid);
    }
    /* `-append lxout` MIRRORS IT HERE, not at the syscall (M2056).
     *
     * M2023 put the mirror in linuxabi.c's lx_emit, which only runs while fd
     * 1 and 2 are UNTOUCHED. Claude Code's are not: app_open_console_alias
     * gives every Linux process real type-14 fd-table entries for 0/1/2
     * precisely so a dup of stdout keeps working, so its output takes
     * app_fd_write -> here and never passes lx_emit at all.
     *
     * The consequence was not a missing line, it was a silent, total one: I
     * ran the program the flag was built for, grepped the log for the TUI it
     * had just painted on screen, found not one escape byte in 1067 lines,
     * and concluded the program had printed nothing. It had printed
     * everything. This is the one funnel every windowed write passes through
     * -- fd 1, fd 2, and every dup of either -- so the mirror belongs here. */
    { extern int g_lx_out_log; if (g_lx_out_log) console_write_n(buf, len); }
    grid_write(a, buf, len);      /* the SAME terminal a native app writes to (M2004) */
}

/* Arm the NEXT Linux spawn: its output goes to `dest`'s window and it becomes
 * a child of `ppid`, both from the moment it exists. One-shot. (M2004) */
void app_arm_next_spawn(app_t *dest, int ppid) {
    g_pend_out_to = (struct app *)dest;
    g_pend_parent = ppid;
}

/* Is this app's output routed into ANOTHER app's window? Then it is a
 * foreground job of that window and must not get one of its own. (M2004) */
/* A fresh descriptor for this process's controlling terminal: the same console
 * alias fd 0/1/2 are. This is what open("/dev/tty") returns. (M2004) */
int app_open_console_alias(void) {
    struct app *a = cur();
    if (!a) return -1;
    for (int fd = 0; fd < APP_NFD; fd++) {
        if (a->fd[fd].used) continue;
        a->fd[fd].used = 1; a->fd[fd].type = 14; a->fd[fd].obj = 0;
        a->fd[fd].off = 0; a->fd[fd].cloexec = 0; a->fd[fd].nonblock = 0;
        return fd;
    }
    return -1;
}

/* THE STALL WATCHDOG (M2004).
 *
 * A Linux program that stops making syscalls has stopped doing anything, and
 * from outside that is indistinguishable from one that is merely slow -- which
 * is the single most common thing to be wrong here and the most expensive to
 * diagnose. Every process gets a syscall counter; this notices when one stops
 * moving and prints, once, what each of its threads is parked on.
 *
 * Called from the window manager's loop, which runs anyway.
 */
/* WHAT IT IS DOING, NOT JUST WHETHER IT IS DOING SOMETHING (M2066).
 *
 * `lxcalls` alone answers "is this process making syscalls", and that is the
 * wrong question. Claude Code parks with its event loop still running: it
 * makes plenty of calls, so the stall watchdog stays quiet, and it makes no
 * progress, so nothing else says anything either. The only two readings
 * available were "no syscall in 45s" (parked) and silence -- and silence meant
 * both "healthy" and "looping for ever".
 *
 * A per-number histogram separates them at a glance: all clock_gettime and
 * epoll_pwait2 is a loop waiting for something that is not coming; all futex
 * is lock churn; read/openat in the mix is real work. The global syscall RING
 * cannot answer this, because it is shared -- the last process to run,
 * normally a short-lived `git` child, overwrites the parent's history
 * completely, which is why every dump I took of a stalled Claude Code showed
 * the same git exit. */
void app_count_lx_syscall(unsigned long nr) {
    struct app *a = cur();
    if (!a) return;
    a->lxcalls++;
    if (nr < LX_SYSHIST_N) a->syshist[nr]++;
}
/* The top `want` syscall numbers by count SINCE THE PREVIOUS CALL, for one
 * process. Deltas, not totals: what it is doing now is the question. */
void app_lx_syshist_dump(app_t *ap, int want) {
    struct app *a = (struct app *)ap;
    if (!a || !a->used) return;
    unsigned long total = 0;
    for (int i = 0; i < LX_SYSHIST_N; i++) total += (unsigned long)(a->syshist[i] - a->syshist_seen[i]);
    /* FREE RAM in the same line (M2066). A runtime that collects in a loop is
     * either being lied to about memory or genuinely out of it, and those two
     * want opposite fixes. Printing both numbers together is the difference. */
    kprintf("[syshist] pid %d '%s': %lu call(s) since the last sample, %luK free of %luK\n",
            a->pid, a->title ? a->title : "?", total,
            (unsigned long)(pmm_free_bytes() >> 10), (unsigned long)(pmm_total_bytes() >> 10));
    for (int n = 0; n < want; n++) {
        int best = -1; unsigned long bestv = 0;
        for (int i = 0; i < LX_SYSHIST_N; i++) {
            unsigned long d = (unsigned long)(a->syshist[i] - a->syshist_seen[i]);
            if (d > bestv) { bestv = d; best = i; }
        }
        if (best < 0) break;
        kprintf("[syshist]   %6lu x syscall %d (%s)\n", bestv, best, lx_syscall_name(best));
        a->syshist_seen[best] = a->syshist[best];      /* consumed: let the next-highest win */
    }
    for (int i = 0; i < LX_SYSHIST_N; i++) a->syshist_seen[i] = a->syshist[i];
    /* ...and, when the sample is SMALL, the actual calls. A histogram says
     * "it is idling"; only the sequence says what it is idling ON. (M2069) */
    if (total && total < 400) lx_trace_dump_pid("this sample", 24, a->pid);
}

/* A CONNECTION THAT HAS GONE QUIET (M2016).
 *
 * app_stall_watchdog asks "has this process stopped making syscalls", which a
 * process waiting on a socket has not -- it is busy with timers and its event
 * loop. The question that matters for a stalled HTTPS request is narrower:
 * nothing has been read from or written to ANY socket for seconds, while a
 * socket is still open. The ten seconds before "connection timed out" are
 * silent on the wire and are exactly the interval worth seeing, and the
 * program will not tell us what it did in them. */
void app_net_stall_watch(void) {
    static unsigned long seen; static uint64_t next; static int told;
    if (!g_net_trace) return;
    uint64_t now = timer_ms();
    if (now < next) return;
    next = now + 5000;
    if (g_net_calls != seen) { seen = g_net_calls; told = 0; return; }
    if (told) return;
    for (int i = 0; i < MAX_APPS; i++) {
        if (!apps[i].used || apps[i].exited || !apps[i].lxcalls) continue;
        int nsock = 0;
        for (int fd = 0; fd < APP_NFD; fd++)
            if (apps[i].fd[fd].used && apps[i].fd[fd].type == 10) nsock++;
        if (!nsock) continue;
        told = 1;
        kprintf("[nettrace] pid %d has %d open socket(s) and has not touched one in 5s "
                "-- what it is doing instead:\n", apps[i].pid, nsock);
        lx_trace_dump_last("the quiet socket", 0);   /* the WHOLE ring: the loop is longer than 48 calls */
        for (int fd = 0; fd < APP_NFD; fd++)
            if (apps[i].fd[fd].used && apps[i].fd[fd].type == 6)
                app_epoll_dump_of((app_t *)&apps[i], fd);
        app_dump_threads(apps[i].pid);
        return;
    }
}

/* Environment entries added by the kernel command line, for bisecting a
 * runtime's own behaviour from outside it. (M2073) */
const char *g_lx_env_cmdline[LX_ENV_CMDLINE];

int g_lx_keytrace;  /* -append lxkeys: print each byte a Linux process reads from the console (M2078) */
int g_lx_syshist;   /* -append lxhist: sample every live Linux process every 15 s (M2066) */

void app_stall_watchdog(void) {
    static uint64_t next_check;
    uint64_t now = timer_ms();
    if (now < next_check) return;
    next_check = now + 15000;
    /* WHAT, not just WHETHER (M2066). The loop below only speaks when a
     * process has gone quiet, and the interesting failure is the opposite: a
     * process whose event loop is running and whose work is not. Sample every
     * one of them, unconditionally, when asked. */
    if (g_lx_syshist)
        for (int i = 0; i < MAX_APPS; i++)
            if (apps[i].used && !apps[i].exited && apps[i].lxcalls)
                app_lx_syshist_dump((app_t *)&apps[i], 8);
    for (int i = 0; i < MAX_APPS; i++) {
        struct app *a = &apps[i];
        if (!a->used || a->exited || !a->lxcalls) continue;
        /* A RATE, NOT A CHANGE. "Did the counter move at all" is too generous:
         * a program parked on a long timer ticks over one syscall every
         * fifteen seconds, which resets an equality test forever while the
         * program does precisely nothing. Claude Code idles at exactly that
         * rate. Fewer than a handful of calls in a whole interval is not
         * progress. (M2004) */
        unsigned long made = a->lxcalls - a->lxcalls_seen;
        a->lxcalls_seen = a->lxcalls;
        if (made >= 8) { a->stall_ticks = 0; a->stall_told = 0; continue; }
        if (++a->stall_ticks < 3 || a->stall_told) continue;   /* ~45s of nothing */
        a->stall_told = 1;
        kprintf("[stall] pid %d '%s' has made no syscall in 45s (%lu total) -- threads:\n",
                a->pid, a->title ? a->title : "?", a->lxcalls);
        kprintf("[stall]   main state=%d wchan=%lx\n",
                a->task ? (int)a->task->state : -1,
                a->task ? (unsigned long)a->task->wchan : 0UL);
        task_report_why_idle(a->task);            /* which of the three reasons it is (M2039) */
        for (int k = 0; k < APP_MAXTHREAD; k++)
            if (a->thr[k]) {
                kprintf("[stall]   thread %d state=%d wchan=%lx wake_pending=%d\n",
                        a->thr[k]->id, (int)a->thr[k]->state,
                        (unsigned long)a->thr[k]->wchan, a->thr[k]->wake_pending);
                if (a->thr[k]->state == TASK_READY) task_report_why_idle(a->thr[k]);
            }
        app_futex_dump();
        lx_trace_dump_pid("the stall", 40, a->pid);   /* THIS process's history, not a child's (M2069) */
    }
}

app_t *app_out_to_of(app_t *a) { return a ? (app_t *)((struct app *)a)->out_to : 0; }

int app_pid_of(app_t *a) { return a ? ((struct app *)a)->pid : 0; }   /* an app's pid, for callers holding the handle (M2004) */

void app_set_out_to(int pid, app_t *dest) {
    for (int i = 0; i < MAX_APPS; i++)
        if (apps[i].used && apps[i].pid == pid) { apps[i].out_to = (struct app *)dest; return; }
}
/* The pid of the most recent successful spawn. app_spawn_linux_from_file_argv
 * returns 0/-1 (started or not), not a pid -- which is fine for a kernel caller
 * that then waits, and wrong for anything that needs to NAME the child, like
 * routing its stdout back to the window that launched it. (M1988) */
int app_last_spawn_pid(void) { return g_last_spawn_pid; }

/* Is this pid still alive, and in what task state? -1 if the slot is gone or
 * the process has exited. Used by the Firefox heartbeat, where silence and
 * death look identical from the log. (M1996) */
/* Where is every thread of this process parked? (M1996)
 *
 * "state=2, zero syscalls" says a process is blocked and says nothing about
 * where -- and with several threads the global syscall ring cannot tell you
 * either, because a thread blocked INSIDE a call makes no new entries. The
 * wchan is the return address of whoever called task_block, so it names the
 * kernel function each thread is waiting in. */
/* Name the mapping an address falls in: the FILE and the offset inside it.
 *
 * A ring-3 fault prints a bare `rip`, and the VMA table printed with it is
 * capped -- a browser has hundreds of mappings and the one that matters is
 * usually past the cap. The file plus the offset is what `addr2line -e` on the
 * host resolves, which is the difference between "a fault somewhere in libxul"
 * and a function name. (M2003) */
/* Describe the page a fault happened ON: its VMA, its recorded protection, and
 * the actual PTE bits. An err=0x7 fault (present + write + user) is a write to
 * a read-only page, and there are three quite different reasons for that -- a
 * copy-on-write page the handler declined, a VMA whose prot really is
 * read-only, and a page present in the tables with no VMA at all. The bare
 * address cannot tell them apart and the existing report only dumps the VMA
 * table for NOT-PRESENT faults. (M2005) */
void app_describe_fault_addr(void) {
    struct app *a = cur();
    uint64_t cr2; __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
    uint64_t page = cr2 & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t pte = vmm_pte_raw(page);
    kprintf("[fault] the faulting page %lx: pte=%lx (present=%d write=%d user=%d cow=%d) phys=%lx refs=%d\n",
            page, pte, !!(pte & PTE_PRESENT), !!(pte & PTE_WRITABLE), !!(pte & PTE_USER),
            !!(pte & PTE_COW), pte & 0x000FFFFFFFFFF000ull,
            (pte & PTE_PRESENT) ? pmm_refcount(pte & 0x000FFFFFFFFFF000ull) : -1);
    if (!a) return;
    uint64_t fl = vma_lock(a);
    int found = 0;
    for (int i = 0; i < a->nvma; i++) {
        if (!a->vma[i].len) continue;
        if (page < a->vma[i].start || page >= a->vma[i].start + a->vma[i].len) continue;
        /* NAME THE FILE (M2091). "inside a file-backed vma with prot=1" is one
         * fact short of a diagnosis: a read-only mapping of libxul's .rodata
         * is correct and a read-only mapping of something the program asked to
         * write is a bug in us, and the only thing that tells them apart is
         * WHICH file. Firefox faulted writing into a prot=1 file mapping three
         * runs in a row and this line could not say what it was. */
        kprintf("[fault]   inside vma[%d] %lx-%lx prot=%d%s%s '%s' +%lx (%lu file bytes valid)\n",
                i, a->vma[i].start, a->vma[i].start + a->vma[i].len, a->vma[i].prot,
                a->vma[i].file_backed ? " file" : "", a->vma[i].shared ? " shared" : "",
                a->vma[i].file_backed ? vma_path(a, i) : "anon",
                a->vma[i].foff, a->vma[i].fvalid);
        found = 1; break;
    }
    vma_unlock(a, fl);
    if (!found) kprintf("[fault]   in NO VMA of this process (%d vmas)\n", a->nvma);
}

void app_describe_addr(uint64_t addr) {
    struct app *a = cur();
    if (!a) return;
    uint64_t fl = vma_lock(a);
    for (int i = 0; i < a->nvma; i++) {
        if (!a->vma[i].len) continue;
        if (addr < a->vma[i].start || addr >= a->vma[i].start + a->vma[i].len) continue;
        kprintf("[fault] %lx is in %s + %lx (mapping %lx-%lx prot=%d)\n",
                addr, vma_path(a, i), addr - a->vma[i].start + a->vma[i].foff,
                a->vma[i].start, a->vma[i].start + a->vma[i].len, a->vma[i].prot);
        vma_unlock(a, fl);
        return;
    }
    vma_unlock(a, fl);
    kprintf("[fault] %lx is in no mapping of this process\n", addr);
}

/* WHERE IN THE PROGRAM IS THIS THREAD PARKED (M2012)?
 *
 * A kernel wchan says which of OUR functions a thread is blocked in, which for
 * a stalled Linux process is almost always app_futex -- true, and useless. The
 * question worth answering is which of THEIR functions asked. Every blocked
 * thread has a saved ring-3 trap frame, so its user RIP is the return address
 * into the library that made the syscall, and the VMA table can name the
 * library and the offset inside it. That offset is resolvable off-box against
 * the same file the guest mapped.
 *
 * Firefox parks a hundred threads on condition variables while it is working
 * normally, so the useful output is not "who is waiting" -- it is that the
 * addresses are all the SAME handful when it is idle and a different one when
 * it is stuck. */
/* Name the library and offset an address falls in, or 0 if none. */
static const char *addr_site(struct app *a, uint64_t addr, uint64_t *out_off, int want_exec) {
    for (int i = 0; i < a->nvma; i++) {
        if (!a->vma[i].len) continue;
        if (addr < a->vma[i].start || addr >= a->vma[i].start + a->vma[i].len) continue;
        if (want_exec && !(a->vma[i].prot & 4)) return 0;       /* PROT_EXEC */
        *out_off = addr - a->vma[i].start + a->vma[i].foff;
        return vma_path(a, i);
    }
    return 0;
}
static void dump_user_site(struct app *a, task_t *t) {
    struct registers *uf = task_uframe(t);
    if (!uf || !uf->rip) return;
    uint64_t off = 0;
    const char *lib = addr_site(a, uf->rip, &off, 0);
    if (lib) kprintf("[app]        at %s + %lx\n", lib, off);
    else     kprintf("[app]        at %lx (no mapping)\n", uf->rip);
    /* ...AND WHO CALLED IT. The saved RIP is inside libc's syscall wrapper for
     * every blocked thread, which is the same answer for all of them and
     * therefore no answer at all. The frames above it are the ones that name
     * the subsystem. There are no frame pointers to walk in optimised code, so
     * scan the stack for words that land in an EXECUTABLE mapping -- the same
     * technique the fault reporter uses -- and report the first few outside
     * libc, which are the caller's own code. */
    /* Read the stack through the HHDM using the TARGET's page tables, not by
     * dereferencing user pointers: this runs from the window manager's own
     * context, where the reported process's address space is not the live one,
     * so a plain read would fault or -- worse -- silently read whatever is at
     * that address in the CURRENT space. vmm_translate_in answers in the right
     * space without switching CR3. */
    if (!uf->rsp) return;
    int shown = 0;
    for (int w = 0; w < 256 && shown < 4; w++) {
        uint64_t sp = uf->rsp + (uint64_t)w * 8;
        uint64_t ph = vmm_translate_in(a->cr3, sp);
        if (!ph) { if ((sp & 0xFFF) < 8) break; else continue; }
        uint64_t v = *(const volatile uint64_t *)hhdm(ph);
        if (v < 0x10000) continue;
        uint64_t o2 = 0;
        const char *l2 = addr_site(a, v, &o2, 1);
        if (!l2) continue;
        /* libc frames are the wrapper we already reported; skip them so the
         * four lines we do print are the interesting ones. */
        { const char *b = l2; for (const char *q = l2; *q; q++) if (*q == '/') b = q + 1;
          if (b[0]=='l'&&b[1]=='i'&&b[2]=='b'&&b[3]=='c'&&b[4]=='.') continue;
          if (b[0]=='l'&&b[1]=='i'&&b[2]=='b'&&b[3]=='p'&&b[4]=='t') continue; }
        kprintf("[app]        <- %s + %lx\n", l2, o2);
        shown++;
    }
}

void app_dump_threads(int pid) {
    for (int i = 0; i < MAX_APPS; i++) {
        if (!apps[i].used || apps[i].pid != pid) continue;
        struct app *a = &apps[i];
        kprintf("[app] pid %d main '%s' state=%d wchan=%lx\n", pid,
                a->task ? task_name_of(a->task) : "",
                a->task ? (int)a->task->state : -1,
                a->task ? (unsigned long)a->task->wchan : 0UL);
        if (a->task) dump_user_site(a, a->task);
        for (int k = 0; k < APP_MAXTHREAD; k++)
            if (a->thr[k]) {
                kprintf("[app]   thread %d '%s' state=%d wchan=%lx wake_pending=%d\n",
                        a->thr[k]->id, task_name_of(a->thr[k]), (int)a->thr[k]->state,
                        (unsigned long)a->thr[k]->wchan,
                        a->thr[k]->wake_pending);
                dump_user_site(a, a->thr[k]);
            }
        return;
    }
}

int app_state_of(int pid) {
    for (int i = 0; i < MAX_APPS; i++)
        if (apps[i].used && apps[i].pid == pid) {
            if (apps[i].exited) return -1;
            return apps[i].task ? (int)apps[i].task->state : -2;
        }
    return -1;
}

app_t *app_out_to(void) {
    struct app *a = cur();
    return a ? (app_t *)a->out_to : 0;
}

/* The character grid a process's output actually lands on, and therefore the
 * size a terminal program must be told (M2004).
 *
 * A Linux binary started with `linux` from a shell has no window of its own --
 * its stdout is routed to the LAUNCHING shell's window -- so its terminal size
 * is that window's grid, not its own. Returns 0 if there is no window at all,
 * in which case the caller should say "not a terminal" rather than invent a
 * size: a program told it has an 80x24 terminal when it has none will try to
 * draw one. */
int app_console_size(int *cols, int *rows) {
    struct app *a = cur();
    if (!a) return 0;
    struct app *t = (struct app *)a->out_to;
    if (!t) t = a;                       /* no routing: our own window, if we have one */
    if (!t || t->cols <= 0 || t->rows <= 0) return 0;
    if (cols) *cols = t->cols;
    if (rows) *rows = t->rows;
    return 1;
}

/* FIONREAD on the console (M2086): how many keystrokes are already queued for
 * whichever window this process reads from. Same source app_fd_ready's type-14
 * arm polls, so a program told "readable" and then asking "how much" gets two
 * answers that agree. */
long app_console_nread(void) {
    struct app *a = cur(); if (!a) return 0;
    struct app *src = a->out_to ? a->out_to : a;
    return (long)iq_count(src);
}

/* Write bytes into an app's terminal grid, interpreting escape sequences.
 *
 * BOTH writers go through here now (M2004). app_write_to -- the path a Linux
 * child's output takes -- called grid_putc directly, so every escape sequence
 * was printed as literal text: Claude Code's interface arrived as thousands of
 * visible "ESC[38;5;246m" instead of coloured, positioned characters. The
 * terminal existed; one of its two entry points simply did not use it. */
/* THE TERMINAL IS UTF-8 NOW (M2015).
 *
 * It used to store one BYTE per cell, which is two bugs at once. The visible
 * one is that a 3-byte box-drawing character renders as three garbage glyphs.
 * The one that actually breaks a TUI is the COLUMN ACCOUNTING: those three
 * bytes advance the cursor three cells, so every line containing a box
 * character is two or three times too wide, wraps early, and overwrites the
 * line below. Claude Code's onboarding came out as fields of '?' with the
 * login prompt written on top of the theme list, and the second symptom is the
 * one that made it unusable rather than merely ugly.
 *
 * One code point, one cell. Continuation bytes are folded into the code point
 * instead of being drawn; font_cp_to_glyph then maps it onto a real glyph, a
 * readable ASCII stand-in, or nothing (zero-width). A malformed sequence is
 * dropped rather than resynchronised into text: a terminal that prints the
 * pieces of a broken character is noisier than one that prints nothing. */
void grid_write(struct app *a, const char *buf, unsigned len) {
    if (!a) return;
    for (unsigned i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)buf[i];
        if (a->esc == 0) {
            if (a->u8need) {                     /* mid-character */
                if ((ch & 0xC0) == 0x80) {
                    a->u8cp = (a->u8cp << 6) | (ch & 0x3F);
                    if (--a->u8need == 0) {
                        unsigned char g = font_cp_to_glyph(a->u8cp);
                        if (g) grid_putc(a, (char)g);
                    }
                    continue;
                }
                a->u8need = 0;                   /* truncated: drop it and re-read this byte */
            }
            if (ch == 0x1B) { a->esc = 1; continue; }
            if (ch < 0x80) { grid_putc(a, (char)ch); continue; }
            if ((ch & 0xE0) == 0xC0)      { a->u8cp = ch & 0x1F; a->u8need = 1; }
            else if ((ch & 0xF0) == 0xE0) { a->u8cp = ch & 0x0F; a->u8need = 2; }
            else if ((ch & 0xF8) == 0xF0) { a->u8cp = ch & 0x07; a->u8need = 3; }
            /* else: a stray continuation or 0xFE/0xFF -- not a character, drop it */
        } else if (a->esc == 1) {                /* after ESC */
            if (ch == '[') { a->esc = 2; a->csilen = 0; a->csipriv = 0; }
            /* OSC: ESC ] Ps ; Pt (BEL | ESC \) -- an OPERATING SYSTEM COMMAND,
             * and dropping only the two-byte introducer leaves its whole
             * payload to be printed as text. Claude Code's login screen is
             * built from OSC 8 hyperlinks, so the sign-in URL came out three
             * times over, each copy prefixed with `8;id=fgcesq;` and trailing
             * a stray `%`. The visible link text is the part between the two
             * OSC 8 sequences, which is exactly what survives once the
             * sequences themselves are consumed. (M2020) */
            else if (ch == ']') { a->esc = 3; }
            /* THE OTHER STRING-INTRODUCERS (M2057). DCS, APC, PM and SOS all
             * run to an ST exactly like an OSC does, and consuming only the
             * two-byte introducer printed their whole payload as text -- the
             * same defect M2020 fixed for OSC, left in place for its four
             * siblings. tmux passthrough and DECRQSS use DCS. */
            else if (ch == 'P' || ch == '_' || ch == '^' || ch == 'X') a->esc = 5;
            /* Charset designation and friends take ONE more byte, which used to
             * be printed: "ESC(B" put a literal B on the screen. */
            else if (ch == '(' || ch == ')' || ch == '*' || ch == '+' ||
                     ch == '-' || ch == '.' || ch == '/' || ch == '#' || ch == '%') a->esc = 7;
            else if (ch == '7') {                /* DECSC: save cursor + attributes */
                a->sv_cx = a->cx; a->sv_cy = a->cy; a->sv_col = a->curcol; a->sv_bg = a->curbg;
                a->sv_bold = a->sgr_bold; a->sv_inv = a->sgr_inv; a->sv_valid = 1; a->esc = 0;
            } else if (ch == '8') {              /* DECRC: restore it */
                if (a->sv_valid) {
                    a->cx = a->sv_cx; a->cy = a->sv_cy; a->curcol = a->sv_col; a->curbg = a->sv_bg;
                    a->sgr_bold = a->sv_bold; a->sgr_inv = a->sv_inv;
                    if (a->cx >= a->cols) a->cx = a->cols - 1;
                    if (a->cy >= a->rows) a->cy = a->rows - 1;
                    a->wrap_pend = 0; a->gdirty = 1;
                }
                a->esc = 0;
            }
            else if (ch == 'D') { grid_index(a); a->gdirty = 1; a->esc = 0; }        /* IND */
            else if (ch == 'E') { grid_nl(a); a->gdirty = 1; a->esc = 0; }           /* NEL */
            else if (ch == 'M') {                                                    /* RI: reverse index */
                if (a->cy == sr_topr(a)) grid_rscroll(a); else if (a->cy > 0) a->cy--;
                a->wrap_pend = 0; a->gdirty = 1; a->esc = 0;
            }
            else if (ch == 'c') {                                                    /* RIS: full reset */
                a->curcol = 0; a->curbg = 0; a->sgr_bold = 0; a->sgr_inv = 0;
                a->sr_top = 0; a->sr_bot = 0; a->no_wrap = 0; a->bracket_paste = 0;
                a->caret_off = 0; a->sv_valid = 0;
                if (a->alt_on) alt_leave(a);
                grid_clear(a);
                a->esc = 0;
            }
            else if (ch == '\\') a->esc = 0;      /* a stray ST: nothing to end */
            else a->esc = 0;                     /* unsupported ESC x: consume + drop */
        } else if (a->esc == 3 || a->esc == 5) { /* in an OSC/DCS/APC string: swallow to BEL or ST */
            if (ch == 0x07) a->esc = 0;          /* BEL terminates */
            else if (ch == 0x1B) a->esc = (a->esc == 3) ? 4 : 6;   /* maybe ESC \ */
        } else if (a->esc == 4 || a->esc == 6) { /* saw ESC inside a string */
            a->esc = (ch == '\\') ? 0 : (a->esc == 4 ? 3 : 5);   /* ESC \ ends it; anything else stays in the string */
        } else if (a->esc == 7) {                /* ESC ( B and friends: one byte to drop */
            a->esc = 0;
        } else {                                 /* in CSI: collect until the final byte */
            /* The PRIVATE-MODE INTRODUCER is not a parameter (M2057). Held
             * separately, because "ESC[?25l" and "ESC[25l" mean entirely
             * different things and the digit-only parser could not tell them
             * apart -- so every "?" mode looked like a cursor operation with a
             * huge argument, and "ESC[>4;2m" ran as an SGR. */
            if (a->csilen == 0 && (ch == '?' || ch == '>' || ch == '<' || ch == '=')) { a->csipriv = (char)ch; }
            else if (ch >= 0x40 && ch <= 0x7E) { ansi_csi(a, (char)ch); a->esc = 0; }
            else if (a->csilen < sizeof(a->csi)) a->csi[a->csilen++] = (char)ch;
            /* OVERLONG: STAY IN THE SEQUENCE (M2057). Dropping to ground state
             * here printed the tail of the sequence -- including its final
             * letter -- as literal text. Keep discarding parameter bytes and
             * still honour the final, which is the only byte that could change
             * anything the extra parameters would have. */
        }
    }
}

void app_sys_write(const char *buf, unsigned len) { grid_write(cur(), buf, len); }

/* ---- terminal self-test (M2057) ------------------------------------------
 *
 * Why this exists AT ALL: every defect this milestone fixes was invisible to
 * the tests we had, because the terminal's only output is PIXELS and the only
 * way anyone ever checked it was to look at a screenshot. A sequence that was
 * silently dropped and a sequence that was correctly honoured produced the
 * same green tree. So drive grid_write on a scratch grid and assert on CELLS.
 *
 * Every check below fails if its fix is reverted -- which is the point, and
 * which was verified by reverting each one.
 *
 * Gated behind `-append termtest`: it costs a few milliseconds, and this OS
 * keeps boot-to-desktop under a second on purpose. */
static struct app g_termtest;          /* .bss: a struct app is far too big for a stack frame */
static int g_tt_pass, g_tt_fail;

static void tt_ck(const char *what, int ok) {
    if (ok) { g_tt_pass++; kprintf("[termtest] ok   %s\n", what); }
    else    { g_tt_fail++; kprintf("[termtest] FAIL %s\n", what); }
}
static void tt_w(const char *s) {
    unsigned n = 0; while (s[n]) n++;
    grid_write(&g_termtest, s, n);
}
static void tt_fresh(void) {
    struct app *a = &g_termtest;
    a->cols = 20; a->rows = 5;
    a->esc = 0; a->csilen = 0; a->csipriv = 0; a->u8need = 0;
    a->curcol = 0; a->curbg = 0; a->sgr_bold = 0; a->sgr_inv = 0;
    a->sr_top = 0; a->sr_bot = 0; a->no_wrap = 0; a->bracket_paste = 0;
    a->caret_off = 0; a->sv_valid = 0; a->alt_on = 0;
    a->ih = a->it = 0; a->paste_len = a->paste_pos = 0;
    a->task = 0;
    grid_clear(a);
}
static int tt_row_is(int r, const char *want) {
    struct app *a = &g_termtest;
    for (int c = 0; want[c]; c++) if (a->grid[r][c] != want[c]) return 0;
    return 1;
}
void app_term_selftest(void) {
    struct app *a = &g_termtest;
    g_tt_pass = g_tt_fail = 0;
    kprintf("[termtest] driving grid_write on a %dx%d scratch grid\n", 20, 5);

    /* 1. DEFERRED WRAP. Exactly `cols` characters on the LAST row must leave
     *    the cursor parked in the last column with nothing scrolled. The old
     *    eager wrap line-fed on the 20th character and scrolled the screen,
     *    which is what made a full-width TUI frame march off the top. */
    tt_fresh();
    tt_w("TOPROW\n");                                  /* row 0 = TOPROW */
    tt_w("\x1b[5;1H");                                 /* to the last row */
    tt_w("12345678901234567890");                      /* exactly 20 = cols */
    tt_ck("20 chars on the last row does not scroll", tt_row_is(0, "TOPROW"));
    tt_ck("cursor parks in the last column", a->cx == 19 && a->cy == 4 && a->wrap_pend);
    tt_w("A");                                         /* the 21st: NOW it wraps */
    tt_ck("the next character wraps and scrolls", a->cy == 4 && a->cx == 1 && tt_row_is(4, "A"));

    /* 2. PER-CELL BACKGROUND. Without it there is no way to render a
     *    highlight, a selected row, or dark-on-light text at all. */
    tt_fresh();
    tt_w("\x1b[41mR\x1b[0mP");
    tt_ck("SGR 41 sets a cell background", a->gbg[0][0] != 0 && a->gbg[0][1] == 0);
    tt_fresh();
    tt_w("\x1b[48;5;21mB");
    tt_ck("SGR 48;5;N sets a cell background", a->gbg[0][0] != 0);
    tt_fresh();
    tt_w("\x1b[48;2;200;30;30mT");
    tt_ck("SGR 48;2;R;G;B sets a cell background", a->gbg[0][0] != 0);

    /* 3. INVERSE VIDEO swaps them -- how every TUI draws a selected line. */
    tt_fresh();
    tt_w("\x1b[32mN\x1b[7mI\x1b[27mN");
    tt_ck("SGR 7 inverts, SGR 27 restores",
          a->gbg[0][0] == 0 && a->gbg[0][1] != 0 && a->gbg[0][2] == 0);

    /* 4. BOLD IS STATE. "ESC[31m" then "ESC[1m" is the order programs use, and
     *    a bold flag local to one sequence could not represent it. */
    tt_fresh();
    tt_w("\x1b[31mr");
    { uint8_t plain = a->gcol[0][0];
      tt_fresh();
      tt_w("\x1b[31m\x1b[1mb");
      tt_ck("ESC[1m after a colour brightens it", a->gcol[0][0] != plain); }

    /* 5. THE CSI PARAMETER BUFFER. 27 parameter bytes used to overflow a
     *    24-byte buffer, drop the parser to ground state mid-sequence, and
     *    print the tail (";0m") into the grid as text. */
    tt_fresh();
    tt_w("\x1b[38;2;255;255;255;48;2;0;0;0mZ");
    tt_ck("a 27-byte SGR leaves no literal text", tt_row_is(0, "Z") && a->cx == 1);

    /* 6. CURSOR VISIBILITY. Without it the blinking block caret stamps itself
     *    over a cell of every frame a full-screen program paints. */
    tt_fresh();
    tt_w("\x1b[?25l");
    tt_ck("ESC[?25l hides the caret", a->caret_off == 1);
    tt_w("\x1b[?25h");
    tt_ck("ESC[?25h shows it again", a->caret_off == 0);

    /* 7. THE ALTERNATE SCREEN. Enter, scribble, leave: the primary screen and
     *    its cursor must come back exactly. */
    tt_fresh();
    tt_w("PRIMARY\n");
    tt_w("\x1b[?1049h");
    tt_ck("entering the alternate screen blanks it", tt_row_is(0, "       ") && a->alt_on);
    tt_w("ALT");
    tt_w("\x1b[?1049l");
    tt_ck("leaving it restores the primary screen", tt_row_is(0, "PRIMARY") && !a->alt_on);
    tt_ck("...and the cursor with it", a->cy == 1 && a->cx == 0);

    /* 8. SAVE / RESTORE CURSOR, both spellings. */
    tt_fresh();
    tt_w("\x1b[3;5H\x1b[s\x1b[1;1H\x1b[u");
    tt_ck("ESC[s / ESC[u round-trip the cursor", a->cy == 2 && a->cx == 4);
    tt_w("\x1b[2;2H\x1b""7\x1b[5;5H\x1b""8");
    tt_ck("ESC 7 / ESC 8 round-trip the cursor", a->cy == 1 && a->cx == 1);

    /* 9. DSR. A program that asks where the cursor is and BLOCKS on the answer
     *    hangs forever against a terminal that never replies -- and "hangs with
     *    every core idle" is the hardest symptom there is to attribute. */
    tt_fresh();
    tt_w("\x1b[4;3H\x1b[6n");
    { char got[16]; int n = 0;
      while (n < 15) { int c = iq_get(a); if (c < 0) break; got[n++] = (char)c; }
      got[n] = 0;
      int ok = (n == 6 && got[0] == 0x1B && got[1] == '[' && got[2] == '4' &&
                got[3] == ';' && got[4] == '3' && got[5] == 'R');
      tt_ck("ESC[6n is answered with the cursor position", ok); }

    /* 10. THE SCROLL REGION. Rows outside it must not move. */
    tt_fresh();
    tt_w("R0\nR1\nR2\nR3\nR4");
    tt_w("\x1b[2;4r");                                 /* region = rows 1..3 */
    tt_w("\x1b[4;1H\n");                               /* newline on the region's last row */
    tt_ck("a scroll inside a region leaves row 0 alone", tt_row_is(0, "R0"));
    tt_ck("...scrolls only the region", tt_row_is(1, "R2") && tt_row_is(2, "R3"));
    tt_ck("...and leaves the rows below it alone", tt_row_is(4, "R4"));

    /* 11. TAB. It used to paint a CP437 dither block and advance one column --
     *     those smudges were the visible artifacts in a blank-looking window. */
    tt_fresh();
    tt_w("ab\tc");
    tt_ck("TAB advances to the next 8-column stop", a->cx == 9 && tt_row_is(0, "ab      c"));
    tt_fresh();
    tt_w("x\x07y");                                    /* BEL is not a glyph */
    tt_ck("BEL prints nothing", tt_row_is(0, "xy") && a->cx == 2);

    /* 12. ERASE, in the right direction. ESC[1J erased FORWARD. */
    tt_fresh();
    tt_w("ABCDE\x1b[1;3H\x1b[1J");
    tt_ck("ESC[1J erases backward, not forward", tt_row_is(0, "   DE"));

    /* 13-14. INSERT / DELETE, which a redraw uses instead of repainting. */
    tt_fresh();
    tt_w("ABCDE\x1b[1;2H\x1b[P");
    tt_ck("ESC[P deletes a character and shifts left", tt_row_is(0, "ACDE"));
    tt_fresh();
    tt_w("ABCDE\x1b[1;2H\x1b[2@");
    tt_ck("ESC[@ inserts blanks and shifts right", tt_row_is(0, "A  BCD"));
    tt_fresh();
    tt_w("R0\nR1\nR2");
    tt_w("\x1b[2;1H\x1b[L");
    tt_ck("ESC[L inserts a line", tt_row_is(0, "R0") && tt_row_is(1, "  ") && tt_row_is(2, "R1"));
    tt_fresh();
    tt_w("R0\nR1\nR2");
    tt_w("\x1b[1;1H\x1b[M");
    tt_ck("ESC[M deletes a line", tt_row_is(0, "R1") && tt_row_is(1, "R2"));

    /* 15-16. ESCAPES THAT ARE NOT CSI. Their payloads used to print. */
    tt_fresh();
    tt_w("\x1b(B" "ok");
    tt_ck("ESC ( B prints no literal B", tt_row_is(0, "ok"));
    tt_fresh();
    tt_w("\x1bPtmux;something\x1b\\" "ok");
    tt_ck("a DCS string prints nothing", tt_row_is(0, "ok"));
    tt_fresh();
    tt_w("\x1b_apc payload\x1b\\" "ok");
    tt_ck("an APC string prints nothing", tt_row_is(0, "ok"));

    /* 17-18. SCROLLBACK: it exists, it keeps its colours, and ESC[3J drops it.
     *     The render path used to hardcode green for every scrolled-off line. */
    tt_fresh();
    tt_w("\x1b[31mRED\x1b[0m\n\n\n\n\n\n");            /* push row 0 off the top */
    tt_ck("a scrolled-off line enters the scrollback", a->sb_count >= 1 && a->sb[0][0] == 'R');
    tt_ck("...with its colour", a->sbcol[0][0] != 0);
    tt_w("\x1b[3J");
    tt_ck("ESC[3J clears the scrollback", a->sb_count == 0);

    /* 19. A PRIVATE MODE IS NOT A CURSOR MOVE. The digit-only parser could not
     *     tell "ESC[?25l" from "ESC[25l", so every "?" mode ran as something
     *     else -- and "ESC[>4;2m" ran as an SGR. */
    tt_fresh();
    tt_w("\x1b[3;3H\x1b[>4;2m" "X");
    tt_ck("ESC[>4;2m is not executed as an SGR", a->cy == 2 && tt_row_is(2, "  X"));

    kprintf("[termtest] %d ok, %d FAILED\n", g_tt_pass, g_tt_fail);
    if (!g_tt_fail) kprintf("[termtest] TERMSELFTEST PASSED (%d checks)\n", g_tt_pass);
    else            kprintf("[termtest] TERMSELFTEST FAILED\n");
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
        if (a->kill) { irq_restore(f); a->exited = 1; app_stop_siblings(a); task_exit(); }   /* threads die with it (M1999) */
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
        if (a->kill) { irq_restore(f); a->exited = 1; app_stop_siblings(a); task_exit(); }   /* threads die with it (M1999) */  /* WM asked us to close: exit cleanly (WM then reaps) */
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
                /* HEAP (M2062): 32 x 256-byte names is 8 KB, half the kernel
                 * stack, and this runs inside the keystroke path. */
                vfs_dirent *e = kmalloc(32 * sizeof *e);
                int ne = e ? vfs_list(e, 32) : 0;
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
                if (e) kfree(e);
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
/* The heap base, and a way to LOWER the recorded break (M2049). brk(addr) with
 * addr below the current break must succeed and report addr -- see the
 * LXS_brk case for what looping on that costs. The pages stay mapped; only the
 * bookkeeping moves, which is all the caller can observe. */
uint64_t app_heap_base(void) { return UHEAP_BASE; }
void app_set_break(uint64_t addr) {
    struct app *a = cur();
    if (!a) return;
    if (!a->heap_end) a->heap_end = UHEAP_BASE;
    if (addr < UHEAP_BASE) addr = UHEAP_BASE;
    if (addr <= a->heap_end) a->heap_end = addr;      /* only ever lowers, never grows */
}

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
        /* ZERO IT FIRST. Two separate bugs in one omission (M1962):
         *
         * 1. An information leak. The frame still holds whatever its last
         *    owner wrote -- another process's data, or its CODE. The mmap
         *    demand-fault path has always zeroed for exactly this reason
         *    ("never leak stale RAM to userspace"); brk was the hole.
         *
         * 2. Corruption, because Linux GUARANTEES brk memory is zero-filled
         *    and glibc's calloc RELIES on it: for memory freshly obtained
         *    from the kernel it skips the memset entirely. GCC allocates its
         *    hash tables with xcalloc, so it read recycled frames as
         *    populated slots and dereferenced them. The faulting register
         *    held 0x2e6666001f0f0000 -- `0f 1f 00 66 66 2e`, x86 NOP padding
         *    -- i.e. a previous process's INSTRUCTIONS, used as a pointer.
         *    It presented as cc1 either faulting or looping forever, and only
         *    on inputs big enough to reach recycled frames. */
        { uint8_t *z = (uint8_t *)hhdm(frame); for (int b = 0; b < PAGE_SIZE; b++) z[b] = 0; }
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

/* The mmap window moved ABOVE 4 GiB and grew to 252 GiB (M1964).
 *
 * V8 reserves an enormous contiguous region for its pointer-compression cage
 * -- gigabytes of PROT_NONE address space it then commits into piecemeal --
 * and with a 1 GiB window Node died at startup with
 *
 *     Fatal process out of memory: SegmentedTable::InitializeTable
 *
 * There was never a reason to keep user mappings inside the first 4 GiB
 * beyond our own constants: this is 4-level paging with a 48-bit address
 * space, and everything from 4 GiB to 256 GiB sits in PML4[0], whose PDPT is
 * allocated PER ADDRESS SPACE. Reserving address space costs one VMA; only
 * touched pages cost memory.
 *
 * The layout below 4 GiB is unchanged: executable at ELF_DYN_BASE, heap,
 * stack, interpreter at 0xB0000000. */
#define MMAP_BASE  0x100000000ull       /* 4 GiB: clear of the executable, heap, stack and interpreter */
/* 32 TiB (M2000). Not because anything needs 32 TiB of mappings -- because
 * allocators CHOOSE THEIR OWN ADDRESSES and expect to get them.
 *
 * mimalloc, which is what Bun allocates with, computes a hint in [2 TiB, 30
 * TiB) and passes it to mmap; Linux honours a free hint, so on Linux mimalloc's
 * arenas land exactly where it picked. Every such request here fell outside a
 * 256 GiB window, so we ignored the hint and packed everything into the low few
 * gigabytes instead -- on top of the region JavaScriptCore had reserved for its
 * pointer cage. This is 4-level paging with a 48-bit user half; the PML4 entry
 * for 30 TiB is index 61 and its PDPT is allocated on demand, per address
 * space, exactly like index 0. Reserving address space costs one VMA. */
#define MMAP_TOP   0x200000000000ull /* 32 TiB. A compiler outgrew 256 MiB (M1961); V8's cage outgrew 1 GiB (M1964); mimalloc picks its own addresses (M2000) */

/* Interned backing-file paths for file-backed VMAs (M1962).
 *
 * ONE GLOBAL TABLE, not one per process. Paths are immutable strings, so
 * sharing them costs nothing and dedupes across processes; a per-process table
 * has to be copied on fork and sized for the worst case in every slot. It was
 * 24 per process at first, which a LINKER blows through instantly: ld mmaps
 * every object file, and OS-DEV's own kernel is 146 of them. The failure was
 * silent -- the mapping was refused, ld saw an object with no symbols, and the
 * link reported "undefined reference to kmalloc" about a file that defines it
 * perfectly well.
 *
 * Interning is what makes a big VMA table affordable at all: storing a
 * 256-byte path per REGION rather than per FILE is what kept APP_MAXVMA at 64
 * when GCC's allocator needs hundreds. */
#define VMA_NPATH 1024
static char g_vma_paths[VMA_NPATH][256];
static int  g_vma_npath;

static short vma_intern_path(const char *p) {
    if (!p || !p[0]) return -1;
    for (int i = 0; i < g_vma_npath; i++) {
        int k = 0;
        while (g_vma_paths[i][k] && g_vma_paths[i][k] == p[k]) k++;
        if (!g_vma_paths[i][k] && !p[k]) return (short)i;
    }
    if (g_vma_npath >= VMA_NPATH) {
        kprintf("[app] VMA path table FULL (%d) -- refusing to map %s\n", VMA_NPATH, p);
        return -1;
    }
    int k = 0; for (; p[k] && k < 255; k++) g_vma_paths[g_vma_npath][k] = p[k];
    g_vma_paths[g_vma_npath][k] = 0;
    if (p[k]) return -1;                  /* refuse a truncated path (M1955) */
    return (short)g_vma_npath++;
}
static const char *vma_path(struct app *a, int vi) {
    short f = a->vma[vi].fidx;
    return (f >= 0 && f < g_vma_npath) ? g_vma_paths[f] : "";
}

/* First-fit search for `len` bytes of free address space in the mmap window
 * (M1962).
 *
 * This replaces a BUMP POINTER that never recycled: every mmap moved
 * mmap_next forward and munmap never gave anything back, so a program that
 * maps and unmaps in a loop marched through the window and then failed --
 * however much of it was actually free. GCC's garbage collector does exactly
 * that, and cc1 died with "virtual memory exhausted: Cannot allocate memory"
 * on a large source file with the window almost entirely unused.
 *
 * Reuse only became correct once munmap really removed VMAs (the carve in
 * M1954); before that a "free" gap was not necessarily free.
 *
 * Starts at the per-process ASLR base and wraps once, so the randomised
 * layout is preserved while still being able to use everything below it.
 * O(nvma) per probe with nvma <= APP_MAXVMA, which is nothing next to the
 * page faults the mapping will take. */
static uint64_t vma_find_gap(struct app *a, uint64_t len, uint64_t align);

/* FIND A GAP AND CLAIM IT IN ONE STEP (M1988).
 *
 * Searching for a free range and recording the mapping used to be two separate
 * unsynchronised acts, and every caller did them in that order. Two threads
 * calling mmap at once both searched, both found the SAME gap, and both went on
 * to record a mapping there -- in different slots, so nothing looked wrong in
 * the table and the overlap audit stayed clean. Then one of them munmap'd and
 * took the other's memory with it. The victim faulted on an address it had been
 * given and had already written to.
 *
 * Serialising slot allocation alone was not enough; the SEARCH has to be inside
 * the same critical section as the claim. It is safe to put it there: the
 * search touches only the kernel's own table, does no I/O and reads no user
 * memory, so nothing inside can block or fault.
 *
 * Returns the claimed slot, with start/len already set, and writes the address
 * to *out. -1 if there is no gap or no slot. The caller fills in the rest of
 * the entry; `len` is already non-zero, so no other allocator can take it. */
static int vma_reserve(struct app *a, uint64_t len, uint64_t align, uint64_t *out) {
    uint64_t f = vma_alloc_lock(a);
    uint64_t addr = vma_find_gap(a, len, align);
    int slot = -1;
    if (addr) {
        slot = vma_pick_slot(a);
        if (slot >= 0) {
            for (unsigned b = 0; b < sizeof a->vma[0]; b++) ((char *)&a->vma[slot])[b] = 0;
            a->vma[slot].fidx = -1; a->vma[slot].mfd = -1;
            a->vma[slot].prot = VMA_PROT_READ | VMA_PROT_WRITE;
            a->vma[slot].start = addr;
            a->vma[slot].len   = len;          /* claimed and published together */
            if (slot >= a->nvma) a->nvma = slot + 1;
        }
    }
    vma_alloc_unlock(a, f);
    if (slot >= 0 && out) *out = addr;
    return slot;
}

static uint64_t vma_find_gap(struct app *a, uint64_t len, uint64_t align) {
    if (!len) return 0;
    for (int pass = 0; pass < 2; pass++) {
        uint64_t cand = pass == 0 ? (a->aslr_mmap_base ? a->aslr_mmap_base : MMAP_BASE) : MMAP_BASE;
        if (cand < MMAP_BASE) cand = MMAP_BASE;
        if (align) cand = (cand + align - 1) & ~(align - 1);
        for (;;) {
            uint64_t end = cand + len;
            if (end > MMAP_TOP || end < cand) break;       /* off the end: try the next pass */
            int clash = 0;
            for (int i = 0; i < a->nvma; i++) {
                uint64_t s0 = a->vma[i].start, e0 = s0 + a->vma[i].len;
                if (cand < e0 && s0 < end) {               /* overlaps: skip past it */
                    cand = e0 + PAGE_SIZE;                 /* + a guard gap, as the bump allocator left */
                    if (align) cand = (cand + align - 1) & ~(align - 1);
                    clash = 1;
                    break;
                }
            }
            if (!clash) return cand;
        }
    }
    return 0;
}

/* ASLR (M1287): pick a per-exec random start for the mmap region, drawn from
 * the CSPRNG (kernel/random.c). 14 bits of entropy => the base lands anywhere
 * in the first 64 MiB of the 256 MiB mmap window, so dlopen'd .so / JIT / mmap
 * buffers no longer sit at a fixed address — the partner of W^X. */
static uint64_t aslr_mmap_pick(void) {
    uint16_t r = 0; random_bytes(&r, sizeof r);
    return MMAP_BASE + ((uint64_t)(r & 0x3FFF) * PAGE_SIZE);   /* [MMAP_BASE, MMAP_BASE+64 MiB), page-aligned; vma_find_gap wraps to MMAP_BASE if the tail fills */
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
static uint64_t app_mmap_fixed_nl(uint64_t addr, uint64_t len) {
    struct app *a = cur();
    if (!a || len == 0) return 0;
    if (addr & (PAGE_SIZE - 1)) return 0;                       /* must be page-aligned */
    len = (len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (vma_full(a)) return 0;
    if (a->rlim_as && app_vma_total(a) + len > a->rlim_as) return 0;   /* RLIMIT_AS (M1164) */
    if (addr < MMAP_BASE || addr + len > MMAP_TOP || addr + len < addr) return 0;
    /* MAP_FIXED REPLACES whatever is there -- that is its defining behaviour,
     * not a detail. Refusing on overlap (which is what this did) is what broke
     * ld.so: it reserves a span and then MAP_FIXEDs its segments into it. */
    if (app_vma_carve(a, addr, len) != 0) return 0;
    if (vma_full(a)) return 0;                        /* re-check: the carve may have split */
    int vs0; VMA_NEW(a, vs0);
    a->vma[vs0].start = addr;
    a->vma[vs0].len   = len;
    a->vma[vs0].sealed = 0;
    a->vma[vs0].uffd  = 0;
    a->vma[vs0].file_backed = 0;
    a->vma[vs0].locked = a->mlock_future;
    a->vma[vs0].huge = 0;
    a->vma[vs0].shared = 0;          /* slots are recycled by the carve: never inherit */
    a->vma[vs0].foff = 0;
    a->vma[vs0].fidx = -1;
    
    if (addr + len + PAGE_SIZE > a->mmap_next) a->mmap_next = addr + len + PAGE_SIZE;
    return addr;
}
/* PLACE AT AN ADDRESS, BUT NEVER OVER ANYTHING (M2000).
 *
 * This is mmap's `addr` WITHOUT MAP_FIXED: advice, not a demand. The
 * distinction is the whole point and getting it wrong is silent and fatal --
 * app_mmap_fixed REPLACES what is already mapped, because that is what
 * MAP_FIXED means and ld.so depends on it. Routing a hint through it hands a
 * caller that merely had a preference the power to destroy a mapping it knows
 * nothing about, and the owner of that mapping dies later with a SIGSEGV that
 * names nothing. (I did exactly that for one build, and `make check` caught it
 * in a forked child two suites away.)
 *
 * So: refuse on ANY overlap and let the caller fall back to a free address,
 * which is precisely what Linux does. */
static uint64_t app_mmap_hint_nl(uint64_t addr, uint64_t len) {
    struct app *a = cur();
    if (!a || len == 0) return 0;
    if (addr & (PAGE_SIZE - 1)) return 0;
    len = (len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (vma_full(a)) return 0;
    if (a->rlim_as && app_vma_total(a) + len > a->rlim_as) return 0;
    if (addr < MMAP_BASE || addr + len > MMAP_TOP || addr + len < addr) return 0;
    for (int i = 0; i < a->nvma; i++) {
        if (!a->vma[i].len) continue;
        uint64_t s = a->vma[i].start, e = s + a->vma[i].len;
        if (addr < e && s < addr + len) return 0;      /* occupied: the caller chooses instead */
    }
    int vs0; VMA_NEW(a, vs0);
    a->vma[vs0].start = addr;
    a->vma[vs0].len   = len;
    a->vma[vs0].sealed = 0;
    a->vma[vs0].uffd  = 0;
    a->vma[vs0].file_backed = 0;
    a->vma[vs0].locked = a->mlock_future;
    a->vma[vs0].huge = 0;
    a->vma[vs0].shared = 0;
    a->vma[vs0].foff = 0;
    a->vma[vs0].fidx = -1;
    if (addr + len + PAGE_SIZE > a->mmap_next) a->mmap_next = addr + len + PAGE_SIZE;
    return addr;
}
uint64_t app_mmap_hint(uint64_t addr, uint64_t len) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    uint64_t r_ = app_mmap_hint_nl(addr, len);
    vma_unlock(a_, f_);
    return r_;
}

uint64_t app_mmap_fixed(uint64_t addr, uint64_t len) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    uint64_t r_ = app_mmap_fixed_nl(addr, len);
    vma_unlock(a_, f_);
    return r_;
}


static uint64_t app_mmap_nl(uint64_t len) {
    struct app *a = cur();
    if (!a || len == 0) return 0;
    if (vma_full(a))
        kprintf("[app] '%s': OUT OF VMA SLOTS (%d) -- mmap refused with the window still free\n",
                a->title ? a->title : "?", APP_MAXVMA);
    len = (len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (vma_full(a)) return 0;
    if (a->rlim_as && app_vma_total(a) + len > a->rlim_as) return 0;   /* RLIMIT_AS (M1164) */
    /* Ask for the alignment UP FRONT. This used to find an unaligned gap and
     * then round the result up to 2 MiB afterwards (M1168, so MADV_COLLAPSE
     * could fold big regions) -- which walks the mapping up to 2 MiB - 4 KiB
     * PAST the gap that was just verified, onto whatever VMA follows it, and
     * nothing re-checked. Two VMAs then owned the same pages, and the first
     * munmap of either freed the frames out from under the other.
     *
     * It presented as Node intermittently dying AFTER a successful socket
     * round-trip, reading a pointer out of a region it still owned:
     *   [fault] UNMAPPED 700000000 err=4: no VMA (nearest below 160021000-164000000)
     * Only mappings >= 2 MiB were affected, and only when a VMA happened to
     * sit right after the chosen gap, which is why it came and went. V8
     * allocates many multi-MiB regions, so Node reproduced it in roughly one
     * run in three; smaller allocations never could. (M1965)
     *
     * vma_find_gap has always taken an `align` argument -- it was simply never
     * passed one. */
    uint64_t addr = 0;
    int vs1 = vma_reserve(a, len, len >= HUGE_SIZE ? HUGE_SIZE : 0, &addr);
    if (vs1 < 0) return 0;
    if (addr + len > MMAP_TOP || addr + len < addr) { a->vma[vs1].start = 0; a->vma[vs1].len = 0; return 0; }
    a->vma[vs1].locked = a->mlock_future;       /* MCL_FUTURE: born locked if mlockall(MCL_FUTURE) is in effect (M1283) */
    
    a->mmap_next = addr + len + PAGE_SIZE;          /* leave an unmapped guard gap */
    vma_audit(a, "mmap");
    return addr;
}
uint64_t app_mmap(uint64_t len) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    uint64_t r_ = app_mmap_nl(len);
    vma_unlock(a_, f_);
    return r_;
}


/* Hugepage mmap (M1155): reserve a 2 MiB-aligned, 2 MiB-granular demand-paged
 * region whose first touch maps the whole enclosing 2 MiB with a single PD entry
 * (PS bit) via app_fault_handle — one TLB entry for 512 pages, real x86-64 huge
 * paging. Returns the (2 MiB-aligned) base VA, or 0. */
static uint64_t app_mmap_huge_nl(uint64_t len) {
    struct app *a = cur();
    if (!a || len == 0) return 0;
    len = (len + HUGE_SIZE - 1) & ~(HUGE_SIZE - 1);          /* whole 2 MiB pages */
    if (vma_full(a)) return 0;
    if (a->rlim_as && app_vma_total(a) + len > a->rlim_as) return 0;   /* RLIMIT_AS (M1164) */
    uint64_t addr = vma_find_gap(a, len, HUGE_SIZE);   /* 2 MiB-aligned base */
    if (!addr) return 0;
    if (addr + len > MMAP_TOP || addr + len < addr) return 0;
    int vs2; VMA_NEW(a, vs2);
    a->vma[vs2].start = addr;
    a->vma[vs2].len   = len;
    a->vma[vs2].sealed = 0;
    a->vma[vs2].uffd  = 0;
    a->vma[vs2].file_backed = 0;
    a->vma[vs2].locked = 0;
    a->vma[vs2].huge = 1;
    
    a->mmap_next = addr + len + HUGE_SIZE;          /* guard gap, preserving 2 MiB alignment */
    return addr;
}
uint64_t app_mmap_huge(uint64_t len) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    uint64_t r_ = app_mmap_huge_nl(len);
    vma_unlock(a_, f_);
    return r_;
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
    if (vma_full(a)) return 0;
    if (a->rlim_as && app_vma_total(a) + len > a->rlim_as) return 0;   /* RLIMIT_AS (M1164) */
    /* SAME ATOMIC RESERVE AS app_mmap (M1993). Finding a gap and recording the
     * mapping were two separate acts here too -- and this is the path a dynamic
     * runtime uses for every shared object it loads, from several threads at
     * once. Two of them picked the same gap, recorded into different slots, and
     * the first munmap took the other's memory. A browser reaches three hundred
     * mappings before it draws anything; that is how often the window is open. */
    int vs3;
    if (!addr) {
        vs3 = vma_reserve(a, len, 0, &addr);
        if (vs3 < 0) return 0;
        if (addr < MMAP_BASE || addr + len > MMAP_TOP || addr + len < addr) {
            a->vma[vs3].start = 0; a->vma[vs3].len = 0; return 0;
        }
    } else {
        if (app_vma_carve(a, addr, len) != 0) return 0;     /* MAP_FIXED: replace what is there */
        if (addr < MMAP_BASE || addr + len > MMAP_TOP || addr + len < addr) return 0;
        if (vma_full(a)) return 0;               /* re-check: the carve may have split */
        VMA_NEW(a, vs3);
        a->vma[vs3].start = addr;
        a->vma[vs3].len   = len;
    }
    a->vma[vs3].sealed = 0;
    a->vma[vs3].uffd  = 0;
    a->vma[vs3].file_backed = 1;
    a->vma[vs3].locked = 0;
    a->vma[vs3].huge = 0;
    a->vma[vs3].shared = shared ? 1 : 0;
    a->vma[vs3].foff = off;
    a->vma[vs3].fidx = vma_intern_path(path);
    /* REFUSE rather than truncate. This buffer was 64 bytes, and binutils'
     * libbfd lives 98 characters down /usr/lib64/binutils/<triplet>/<ver>/ --
     * so every demand-fault on that mapping read a path that does not exist,
     * got a page of zeros, and handed ld.so a shared object whose entire
     * dynamic section was NULL. It surfaced as a page fault at CR2=0x8 deep
     * inside _dl_check_map_versions, with nothing pointing at the cause.
     * A short path is now an error, which is a diagnosable failure. */
    if (a->vma[vs3].fidx < 0) { a->vma[vs3].start = 0; a->vma[vs3].len = 0; return 0; }   /* release the slot */
    
    if (addr + len + PAGE_SIZE > a->mmap_next) a->mmap_next = addr + len + PAGE_SIZE;
    return addr;
}

uint64_t app_mmap_file(const char *path, uint64_t len, int shared) {
    struct app *a = cur();
    if (!a || len == 0 || !path) return 0;
    len = (len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (vma_full(a)) return 0;
    if (a->rlim_as && app_vma_total(a) + len > a->rlim_as) return 0;   /* RLIMIT_AS (M1164) */
    uint64_t addr = vma_find_gap(a, len, 0);
    if (!addr) return 0;
    if (addr + len > MMAP_TOP || addr + len < addr) return 0;
    int vs4; VMA_NEW(a, vs4);
    a->vma[vs4].start = addr;
    a->vma[vs4].len   = len;
    a->vma[vs4].sealed = 0;
    a->vma[vs4].uffd  = 0;
    a->vma[vs4].file_backed = 1;
    a->vma[vs4].locked = 0;
    a->vma[vs4].huge = 0;
    a->vma[vs4].shared = shared ? 1 : 0;
    a->vma[vs4].foff = 0;
    a->vma[vs4].fidx = vma_intern_path(path);
    /* REFUSE rather than truncate. This buffer was 64 bytes, and binutils'
     * libbfd lives 98 characters down /usr/lib64/binutils/<triplet>/<ver>/ --
     * so every demand-fault on that mapping read a path that does not exist,
     * got a page of zeros, and handed ld.so a shared object whose entire
     * dynamic section was NULL. It surfaced as a page fault at CR2=0x8 deep
     * inside _dl_check_map_versions, with nothing pointing at the cause.
     * A short path is now an error, which is a diagnosable failure. */
    if (a->vma[vs4].fidx < 0) return 0;   /* nvma not yet incremented: nothing to undo */
    
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

        struct statx st; long sz = (vfs_stat(vma_path(a, i), &st) == 0) ? (long)st.stx_size : 0;
        uint64_t need = a->vma[i].foff + a->vma[i].len;      /* the mapping's own span sets the ceiling */
        if ((uint64_t)sz > need) need = (uint64_t)sz;        /* preserve any bytes past the mapping */
        if (need == 0 || need > (16u << 20)) continue;       /* refuse to RMW something absurd (16 MiB cap) */
        char *tmp = kmalloc((size_t)need);
        if (!tmp) continue;
        long got = vfs_read(vma_path(a, i), tmp, need);
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
        vfs_write(vma_path(a, i), tmp, need);
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
        if (vma_full(a)) return -1;
        /* Claim under the ALLOCATOR's lock (M1988). A split and a concurrent
         * mmap both called vma_pick_slot unsynchronised, got the same free
         * index, and each wrote its entry there -- one of the two mappings
         * simply ceased to exist, with the table looking perfectly consistent
         * afterwards. */
        uint64_t sfl = vma_alloc_lock(a);
        int ss = vma_pick_slot(a);
        if (ss < 0) { vma_alloc_unlock(a, sfl); return -1; }   /* no slot: the caller must not split */
        a->vma[ss] = a->vma[i];       /* a COPY on purpose: no VMA_NEW here */
        a->vma[ss].start = addr;
        a->vma[ss].len   = e0 - addr;
        if (a->vma[ss].file_backed) {
            a->vma[ss].foff += addr - s0;
            /* fvalid is measured from the VMA start, so the tail's shrinks by
             * exactly what the head keeps -- and clamps at zero when the split
             * lands past the last file-backed byte. */
            uint64_t used = addr - s0;
            a->vma[ss].fvalid = (a->vma[i].fvalid > used) ? a->vma[i].fvalid - used : 0;
            if (a->vma[i].fvalid && a->vma[ss].fvalid == 0) a->vma[ss].fvalid = 1;  /* 0 means "no limit"; keep "nothing valid" expressible */
        }
        if (ss >= a->nvma) a->nvma = ss + 1;   /* publish the tail: this path does not go through VMA_NEW (M1988) */
        vma_alloc_unlock(a, sfl);
        a->vma[i].len = addr - s0;
        return 0;
    }
    return 0;
}

/* Make other cores drop cached translations for this process, if it can
 * actually be running on one (M1963).
 *
 * Only a MULTI-TASK address space can be live on two cores at once: a
 * single-threaded process is on exactly one core, and after fork the parent
 * and child have different CR3s. So this is free for the common case and only
 * pays the IPI where it is genuinely needed -- which, now that real threads
 * exist, it is.
 *
 * Called AFTER the mapping change and OUTSIDE the vmm lock: a core spinning
 * for that lock with interrupts off could never ack. */
static int app_tlb_sync(struct app *a) {
    if (!a) return 1;
    for (int i = 0; i < APP_MAXTHREAD; i++)
        if (a->thr[i] && a->thr[i]->state != TASK_DEAD) return vmm_tlb_shootdown();
    return 1;                      /* single-threaded: this core's invlpg was enough */
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
        /* WHO TOOK A BITE OUT OF THE CAGE? A JS engine's pointer region is
         * gigabytes and it is supposed to stay whole; when part of it goes
         * missing the program dies later reading through a base that used to
         * be mapped, and nothing in the log connects the two. Name the carve
         * that touches a very large mapping, with both ranges, so the culprit
         * is identified at the moment it acts. (M2000) */
        if (a->vma[i].len >= (256ull << 20))
            kprintf("[vma] carve %lx-%lx cuts into vma[%d] %lx-%lx (%lu MiB)\n",
                    addr, end, i, s0, e0, (unsigned long)(a->vma[i].len >> 20));
        if (a->vma[i].sealed) return -1;                        /* mseal'd (M1130) */
        uint64_t cs = addr > s0 ? addr : s0, ce = end < e0 ? end : e0;
        /* A hugepage can only be freed as a whole 2 MiB run, so a carve that
         * cuts one in half has no correct answer -- refusing is the only
         * honest one. Nothing maps hugepages through the Linux path today. */
        if (a->vma[i].huge && ((cs | ce) & (HUGE_SIZE - 1))) return -1;
        if (cs > s0 && ce < e0) extra++;                        /* middle: becomes two VMAs */
    }
    /* Count FREE slots, not the distance to the high-water mark: tombstones
     * left by earlier removals are usable. (M1988) */
    {
        int free_slots = APP_MAXVMA - a->nvma;
        for (int i = 0; i < a->nvma; i++) if (!a->vma[i].len) free_slots++;
        if (extra > free_slots) return -1;
    }

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
            if (a->vma[i].mfd >= 0) memfd_unref(a->vma[i].mfd);   /* the mapping's reference (M1985) */
            /* TOMBSTONE, not a swap-down (M1988). Moving the last entry into
             * this slot is what let a concurrent scan miss a live mapping; a
             * zeroed entry matches no range test, so a racing scan sees either
             * the mapping or nothing -- never a different one. */
            uint64_t tfl = vma_alloc_lock(a);
            a->vma[i].start = 0;
            a->vma[i].fidx = -1; a->vma[i].mfd = -1;
            a->vma[i].file_backed = 0; a->vma[i].shared = 0;
            a->vma[i].huge = 0; a->vma[i].sealed = 0; a->vma[i].uffd = 0;
            a->vma[i].locked = 0; a->vma[i].prot = 0;
            a->vma[i].len = 0;                  /* LAST: len == 0 is what frees the slot */
            vma_alloc_unlock(a, tfl);
            i++;
            continue;
        }
        if (cs == s0) {                             /* head trimmed */
            /* start and len describe ONE region and must change together
             * (M1995). A concurrent gap search reading the new start with the
             * old len -- or the reverse -- sees a region that never existed,
             * and either hands out an address that is still in use or refuses
             * one that is free. Same lock the allocator uses; no I/O inside. */
            uint64_t hfl = vma_alloc_lock(a);
            a->vma[i].start = ce;
            a->vma[i].len   = e0 - ce;
            vma_alloc_unlock(a, hfl);
            /* The file offset tracks the VMA's new start, or every later
             * demand-fault in this region reads the wrong part of the file. */
            if (a->vma[i].file_backed) a->vma[i].foff += ce - s0;
        } else if (ce == e0) {                      /* tail trimmed */
            uint64_t tfl2 = vma_alloc_lock(a);
            a->vma[i].len = cs - s0;
            vma_alloc_unlock(a, tfl2);
        } else {                                    /* hole punched: split in two */
            uint64_t cfl = vma_alloc_lock(a);
            int ns = vma_pick_slot(a);
            if (ns < 0) { vma_alloc_unlock(a, cfl); return -1; }   /* pre-flight counted the slots; belt and braces */
            a->vma[ns] = a->vma[i];             /* a COPY on purpose: no VMA_NEW here */
            if (a->vma[i].mfd >= 0) memfd_ref(a->vma[i].mfd);   /* now TWO mappings hold it (M1985) */
            a->vma[ns].start = ce;
            a->vma[ns].len   = e0 - ce;
            if (a->vma[ns].file_backed) a->vma[ns].foff += ce - s0;
            if (ns >= a->nvma) a->nvma = ns + 1;
            vma_alloc_unlock(a, cfl);
            a->vma[i].len = cs - s0;
        }
        i++;
    }
    /* Reclaim the high-water mark from the END only. Lowering a->nvma past
     * trailing tombstones shortens a concurrent scan, which can only make it
     * skip entries that are already empty. */
    while (a->nvma > 0 && a->vma[a->nvma - 1].len == 0) a->nvma--;
    vma_audit(a, "carve");
    app_tlb_sync(a);                    /* the pages are gone; no core may keep a translation (M1963) */
    return 0;
}

static int app_munmap_nl(uint64_t addr, uint64_t len) {
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
int app_munmap(uint64_t addr, uint64_t len) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    int r_ = app_munmap_nl(addr, len);
    vma_unlock(a_, f_);
    return r_;
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
static uint64_t app_mremap_nl(uint64_t old_addr, uint64_t old_len, uint64_t new_len, int flags) {
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
        /* THE SHOOTDOWN THIS PATH NEVER HAD (M2060). Every other place that
         * takes a mapping away -- munmap, mprotect, madvise, the COW privatise
         * -- calls app_tlb_sync, because pmm_free_frame has no quarantine: the
         * instant a frame's count reaches zero it is handed to the next
         * allocation on any core, while a sibling thread still holds a cached
         * translation for it. That is silent cross-process corruption, and it
         * does not fault anywhere near where it was caused. mremap's shrink
         * was doing exactly what M2000 fixed in madvise, in a function nobody
         * revisited. mimalloc shrinks with mremap, so a threaded allocator is
         * the thing that reaches it.
         *
         * Unmap everything first, then flush ONCE, then free -- and only free
         * if every other core acked, for the same reason the COW path leaks
         * rather than frees on a timed-out IPI. */
        uint64_t freed[64]; int nfreed = 0; int leaked = 0;
        for (uint64_t p = old_addr + new_len; p < old_addr + old_len; p += PAGE_SIZE) {
            uint64_t ph = vmm_translate(p);
            if (!ph) continue;
            vmm_unmap(p);
            if (nfreed < 64) freed[nfreed++] = ph;
            else {                                        /* batch full: flush and drain */
                if (app_tlb_sync(a)) { for (int k = 0; k < nfreed; k++) pmm_free_frame(freed[k]); }
                else leaked += nfreed;
                nfreed = 0;
                freed[nfreed++] = ph;
            }
        }
        if (nfreed) {
            if (app_tlb_sync(a)) { for (int k = 0; k < nfreed; k++) pmm_free_frame(freed[k]); }
            else leaked += nfreed;
        }
        if (leaked) {
            static int told;
            if (!told) { told = 1;
                kprintf("[vmm] mremap LEAKED %d frame(s) rather than freeing them: the shootdown "
                        "did not complete, so another core may still be using them\n", leaked); }
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
    if (vma_full(a)) return (uint64_t)-1;
    uint64_t nbase = vma_find_gap(a, new_len, 0);
    if (!nbase) return (uint64_t)-1;
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
    int vs5; VMA_NEW(a, vs5);
    a->vma[vs5].start = nbase; a->vma[vs5].len = new_len;
    a->vma[vs5].sealed = a->vma[vs5].uffd = a->vma[vs5].file_backed = a->vma[vs5].locked = a->vma[vs5].huge = 0;
    
    a->mmap_next = nbase + new_len + PAGE_SIZE;
    app_munmap_nl(old_addr, old_len);                     /* free the old region's frames + VMA (the lock is already held) */
    return nbase;
}
uint64_t app_mremap(uint64_t old_addr, uint64_t old_len, uint64_t new_len, int flags) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    uint64_t r_ = app_mremap_nl(old_addr, old_len, new_len, flags);
    vma_unlock(a_, f_);
    return r_;
}


/* mseal (M1130): irreversibly seal every mmap region overlapping [addr,addr+len)
 * so its mapping can no longer be changed — munmap and mprotect on it are denied
 * from here on (the seal even survives fork). The point is forward security: an
 * app that has built and mprotect'd a region the way it wants (e.g. flipped JIT'd
 * code to R-X under W^X) seals it, so a later bug that hands an attacker an
 * mprotect/munmap primitive still cannot make that code writable again or swap a
 * fresh page under it. Linux's mseal(2) (2024). Returns the number of regions
 * sealed, or -1 if the range matched no mapping. */
static int app_mseal_nl(uint64_t addr, uint64_t len) {
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
int app_mseal(uint64_t addr, uint64_t len) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    int r_ = app_mseal_nl(addr, len);
    vma_unlock(a_, f_);
    return r_;
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
static int app_uffd_register_nl(uint64_t addr, uint64_t len) {
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
int app_uffd_register(uint64_t addr, uint64_t len) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    int r_ = app_uffd_register_nl(addr, len);
    vma_unlock(a_, f_);
    return r_;
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
static int app_madvise_nl(uint64_t addr, uint64_t len, int advice) {
    struct app *a = cur();
    if (!a || len == 0) return -1;
    /* PAGEOUT and COLLAPSE are handled by app_madvise BEFORE the lock is taken
     * -- both write to disk or shoot down TLBs, and neither may be done with a
     * spinlock held. (M2000) */
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
    (void)start; (void)end;
    return 0;                                        /* DONTNEED is served by app_madvise itself (M2000) */
}

/* MADV_DONTNEED FREED THE FRAME WITHOUT TELLING THE OTHER CORES (M2000).
 *
 * Every other place that takes a mapping away calls app_tlb_sync -- munmap
 * does, mprotect does, and M1963 added both for exactly this reason. madvise
 * did not, and it is the one a JavaScript engine calls constantly: JSC
 * decommits its GC blocks 64 KiB at a time and the syscall ring is full of
 *
 *     28(10c760000, 10000, 4) = 0        <- madvise(..., 64 KiB, MADV_DONTNEED)
 *
 * So: core A dropped the PTE and handed the frame back to the allocator while
 * core B still held a cached translation for it. The frame was immediately
 * reissued to something else, and B kept reading and writing it. The damage
 * lands wherever that frame went, which is why it presented as Claude Code
 * dereferencing NULL in a process with a perfectly healthy VMA table -- and
 * ONLY on more than one core. Single-core runs are correct; four-core runs
 * die. That split is what named it.
 *
 * The ORDER matters as much as the shootdown. Unmapping, freeing and then
 * shooting down would still leave a window in which the frame belongs to
 * someone else and B can still reach it. So: unmap a bounded chunk, drop the
 * lock, make every core forget, and only THEN return the frames. The chunk
 * keeps the frame list on the stack without bounding how much a caller may
 * advise at once.
 *
 * The lock must be dropped before the IPI: a core spinning for it with
 * interrupts off can never acknowledge, which is the deadlock M1993 fixed. */
int app_madvise(uint64_t addr, uint64_t len, int advice) {
    struct app *a_ = cur();
    if (!a_ || !len) return -1;
    /* Neither of these may run under the VMA lock: app_swap_out writes every
     * page to DISK and now shoots down TLBs, and app_collapse allocates. A
     * spinlock held across either is the failure M1912 and M1993 both were.
     * (M2000) */
    if (advice == MADV_PAGEOUT)  return app_swap_out(addr, len);
    if (advice == MADV_COLLAPSE) return app_collapse(addr, len);
    if (advice != MADV_DONTNEED) {
        uint64_t f_ = vma_lock(a_);
        int r_ = app_madvise_nl(addr, len, advice);
        vma_unlock(a_, f_);
        return r_;
    }
    uint64_t start = addr & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t end   = (addr + len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (end < start) return -1;
    int dropped = 0;
    while (start < end) {
        uint64_t frames[64]; int nf = 0;
        uint64_t chunk = start + 64ull * PAGE_SIZE;
        if (chunk > end || chunk < start) chunk = end;
        uint64_t f_ = vma_lock(a_);
        for (uint64_t p = start; p < chunk; p += PAGE_SIZE) {
            int in_vma = 0, locked = 0;
            for (int i = 0; i < a_->nvma; i++)
                if (a_->vma[i].len && p >= a_->vma[i].start &&
                    p < a_->vma[i].start + a_->vma[i].len) { in_vma = 1; locked = a_->vma[i].locked; break; }
            if (!in_vma || locked) continue;          /* demand-paged mmap regions; mlock'd pages are pinned (M1149) */
            uint64_t ph = vmm_translate(p);
            if (ph && pmm_refcount(ph) == 0) {        /* single-owner anon page: safe to reclaim */
                vmm_unmap(p);
                frames[nf++] = ph;
            }
        }
        vma_unlock(a_, f_);
        if (nf) {
            app_tlb_sync(a_);                         /* no core may still reach these frames */
            for (int i = 0; i < nf; i++) pmm_free_frame(frames[i]);
            dropped += nf;
        }
        start = chunk;
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
static int app_mincore_nl(uint64_t addr, uint64_t len, uint8_t *vec) {
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
int app_mincore(uint64_t addr, uint64_t len, uint8_t *vec) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    int r_ = app_mincore_nl(addr, len, vec);
    vma_unlock(a_, f_);
    return r_;
}


/* mlock/munlock (M1149): pin (lock=1) or unpin (lock=0) the mmap pages that
 * overlap [addr,addr+len) so they are exempt from reclaim — both swap-out
 * (app_swap_out) and madvise(MADV_DONTNEED) skip a VMA whose `locked` flag is
 * set. We set the flag on every VMA the range overlaps. NB unlike Linux this
 * does NOT force-fault the range resident on lock (no kernel touch of a user
 * page); a not-yet-faulted page simply faults in on first access as usual and
 * is then pinned (its VMA is locked). Returns 0, or -1 if the range overlaps
 * no mmap VMA. Pairs with mincore (M1147) for query+control of residency. */
static int app_mlock_set_nl(uint64_t addr, uint64_t len, int lock) {
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
static int app_mlock_set(uint64_t addr, uint64_t len, int lock) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    int r_ = app_mlock_set_nl(addr, len, lock);
    vma_unlock(a_, f_);
    return r_;
}

int app_mlock(uint64_t addr, uint64_t len)   { return app_mlock_set(addr, len, 1); }
int app_munlock(uint64_t addr, uint64_t len) { return app_mlock_set(addr, len, 0); }
/* mlockall/munlockall (M1283): MCL_CURRENT (1) pins every current VMA;
 * MCL_FUTURE (2) makes subsequent anonymous mmaps born-locked (via mlock_future,
 * honored in app_mmap). munlockall clears both. Returns 0/-1. */
static int app_mlockall_nl(int flags) {
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
int app_mlockall(int flags) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    int r_ = app_mlockall_nl(flags);
    vma_unlock(a_, f_);
    return r_;
}

static int app_munlockall_nl(void) {
    struct app *a = cur(); if (!a) return -1;
    for (int i = 0; i < a->nvma; i++) a->vma[i].locked = 0;
    a->mlock_future = 0;
    return 0;
}
int app_munlockall(void) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    int r_ = app_munlockall_nl();
    vma_unlock(a_, f_);
    return r_;
}


/* mprotect (M1090): change the R/W/X protection of an already-mapped range in
 * the calling app (PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4). Enables W^X and
 * write-then-execute JIT pages. The range must be the app's own user pages. */
static int app_mprotect_nl(uint64_t addr, uint64_t len, int prot) {
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
    /* Record the protection on the VMA REGARDLESS of whether every page of the
     * range is currently inside one. The VMA is what app_fault_handle consults
     * for pages that are not resident yet, so skipping this leaves a
     * later-faulted page with the OLD protection -- which is fatal for a JIT:
     * V8 maps a code region RW, writes into it, mprotects it RX, and then
     * EXECUTES pages that had never been touched. They faulted in read-only
     * and Node died with "instruction fetch from a non-executable mapping".
     * (M1965) */
    {
        uint8_t np = (uint8_t)((prot & 0x7) ? (prot & 0x7) : VMA_PROT_READ);
        if (a && app_vma_split_at(a, a0) == 0 && app_vma_split_at(a, end) == 0)
            for (int i = 0; i < a->nvma; i++) {
                uint64_t s0 = a->vma[i].start, e0 = s0 + a->vma[i].len;
                if (s0 >= a0 && e0 <= end) a->vma[i].prot = np;
            }
    }
    if (covered) {
        /* (the VMA prot was already recorded above, for both paths) */
        for (uint64_t p = a0; p < end; p += PAGE_SIZE)
            if (vmm_translate(p)) { if (vmm_protect(p, flags) < 0) return -1; }
        app_tlb_sync(a);                /* a tightened mapping another core still caches is a write-after-revoke (M1963) */
        return 0;
    }
    if (!vmm_user_ok(a0, end - a0)) return -1;   /* must be the caller's mapped user pages */
    for (uint64_t p = a0; p < end; p += PAGE_SIZE)
        if (vmm_protect(p, flags) < 0) return -1;
    app_tlb_sync(a);                    /* same reason as the covered path above (M1963) */
    return 0;
}
int app_mprotect(uint64_t addr, uint64_t len, int prot) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    int r_ = app_mprotect_nl(addr, len, prot);
    vma_unlock(a_, f_);
    return r_;
}


/* Magic (mirrored) ring buffer (M1089): reserve `len` bytes of physical frames
 * and map them TWICE, back to back, so the region [base, base+2*len) has its
 * second half alias the first. A wraparound queue then needs no split-handling
 * or modulo — a read/write that crosses base+len continues seamlessly into the
 * same frames. Mapped eagerly (no demand faults); each frame is pmm_addref'd for
 * its second mapping so exit/munmap (which frees every PTE's frame) releases it
 * exactly once. Returns the base VA, or 0. */
static uint64_t app_ringbuf_nl(uint64_t len) {
    struct app *a = cur();
    if (!a || len == 0) return 0;
    len = (len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t total = len * 2;
    if (total < len) return 0;                       /* overflow */
    if (vma_full(a)) return 0;
    uint64_t base = vma_find_gap(a, total, 0);
    if (!base) return 0;
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
        /* The ring's DOUBLE mapping needs a real second reference; above
         * PMM_MAXREFS pmm_addref is a no-op, so unmapping the mirror would
         * free the frame the primary still uses. (M1985) */
        if (!pmm_refcountable(frame)) {
            pmm_free_frame(frame);
            for (uint64_t u = 0; u < mapped; u += PAGE_SIZE) {
                uint64_t ph = vmm_translate(base + u);
                vmm_unmap(base + len + u); vmm_unmap(base + u);
                if (ph) pmm_free_frame(ph);
            }
            return 0;
        }
        vmm_map(base + off, frame, PTE_WRITABLE | PTE_USER | PTE_NX);          /* primary */
        pmm_addref(frame);
        vmm_map(base + len + off, frame, PTE_WRITABLE | PTE_USER | PTE_NX);    /* mirror */
        __asm__ volatile("invlpg (%0)" : : "r"(base + off) : "memory");
        __asm__ volatile("invlpg (%0)" : : "r"(base + len + off) : "memory");
        mapped += PAGE_SIZE;
    }
    int vs6; VMA_NEW(a, vs6);
    a->vma[vs6].start = base;
    a->vma[vs6].len   = total;
    a->vma[vs6].sealed = 0;
    a->vma[vs6].uffd  = 0;
    a->vma[vs6].file_backed = 0;
    a->vma[vs6].locked = 0;
    a->vma[vs6].huge = 0;
    
    a->mmap_next = base + total + PAGE_SIZE;
    return base;
}
uint64_t app_ringbuf(uint64_t len) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    uint64_t r_ = app_ringbuf_nl(len);
    vma_unlock(a_, f_);
    return r_;
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
    if (vma_full(a)) return 0;
    uint64_t total = (uint64_t)np * PAGE_SIZE;
    uint64_t base = vma_find_gap(a, total, 0);
    if (!base) return 0;
    if (base + total > MMAP_TOP || base + total < base) return 0;
    /* Above PMM_MAXREFS pmm_addref SILENTLY DOES NOTHING, so the mapping below
     * would not hold the reference it claims to and the first unmap would free
     * a frame the SHM object still owns. Refuse instead: an honest failure to
     * share beats a mapping that outlives its own memory. (M1985) */
    for (int p = 0; p < np; p++) if (!pmm_refcountable(frames[p])) return 0;
    for (int p = 0; p < np; p++) {
        vmm_map(base + (uint64_t)p * PAGE_SIZE, frames[p], PTE_WRITABLE | PTE_USER | PTE_NX);
        pmm_addref(frames[p]);                       /* this mapping holds a ref on the shared frame */
        __asm__ volatile("invlpg (%0)" : : "r"(base + (uint64_t)p * PAGE_SIZE) : "memory");
    }
    int vs7; VMA_NEW(a, vs7);
    a->vma[vs7].start = base; a->vma[vs7].len = total; a->vma[vs7].sealed = 0; a->vma[vs7].uffd = 0; a->vma[vs7].file_backed = 0; a->vma[vs7].locked = 0; a->vma[vs7].huge = 0; 
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
int g_futex_trace;              /* -append futextrace (M1997) */
static int g_futex_traced;
#define FUTEX_NWAIT 256
/* `uaddr` and `val` are carried purely so the dump can ANSWER THE QUESTION
 * rather than pose it (M2073). A slot that says only "task 14 is parked on
 * key 10b32620" leaves the two possibilities that matter indistinguishable:
 * the waker never signalled, or it signalled a key we no longer answer to.
 * The word's own physical address is the key, so its CURRENT value can be
 * read through the HHDM from any address space, and re-translating `uaddr`
 * in the owner's CR3 says whether a WAKE issued now would still find us. */
static struct { uint64_t key; void *as; void *task; int used; uint64_t uaddr; int val; } g_futex[FUTEX_NWAIT];

/* WHAT A FUTEX IS NAMED BY (M2073) -- the bug that stopped Claude Code.
 *
 * The key was the word's PHYSICAL address. For memory shared between
 * processes that is the only key that can work, and for everything else it
 * is a lie that holds right up until the page moves. Ours move: fork marks
 * every page COW, so the parent's next write to a page allocates a FRESH
 * frame, and madvise(MADV_DONTNEED) plus a refault does the same. A thread
 * parked before that point keeps the old frame's key; every WAKE afterwards
 * computes the new one, matches nothing, and reports success.
 *
 * Nothing fails. FUTEX_WAKE's contract is 'wake up to N waiters and tell me
 * how many' -- zero is a perfectly ordinary answer, returned by every
 * uncontended unlock -- so a lost wakeup and an idle lock are the same
 * syscall return. This is the fourteenth thing granted in name only, and
 * the worst placed: a futex is what every other synchronisation primitive
 * in a threaded program is built out of. Claude Code forks to run `git`
 * during startup, and from that fork onward its threads could no longer
 * wake each other: the main thread parked on a condition variable, a worker
 * parked on the mutex it was waiting to hand over, and the machine went
 * completely idle with the TUI never painted.
 *
 * Linux does not key on physical addresses for this reason. get_futex_key
 * uses (mm, virtual address) whenever the mapping is private -- which is
 * stable across COW by construction, because the identity of the mapping is
 * what the waiters agree on, not the frame currently behind it -- and only
 * uses (inode, page index) for a genuinely shared one. FUTEX_PRIVATE_FLAG
 * is an optimisation hint, not the decision: the VMA is.
 *
 * So: a shared VMA keeps the physical key, everything else is named by
 * (address space, virtual address). An address with no VMA at all -- a main
 * thread's stack, the brk heap -- is private by default, which is both true
 * and the safe way to be wrong, since the physical key is the one that
 * silently breaks. */
static void futex_key_of(uint64_t uaddr, uint64_t *key, void **as) {
    struct app *a = cur();
    int shared = 0;
    if (a) {
        uint64_t f = vma_alloc_lock(a);
        for (int i = 0; i < a->nvma; i++)
            if (uaddr >= a->vma[i].start && uaddr < a->vma[i].start + a->vma[i].len) {
                shared = a->vma[i].shared; break;
            }
        vma_alloc_unlock(a, f);
    }
    if (shared) {
        uint64_t phys = vmm_translate(uaddr & ~(uint64_t)(PAGE_SIZE - 1));
        *key = phys | (uaddr & (PAGE_SIZE - 1));
        *as  = 0;                       /* the frame IS the identity; no address space qualifies it */
    } else {
        *key = uaddr;
        *as  = a;                       /* two processes' private words at the same VA are different futexes */
    }
}

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

/* FORGET EVERY FUTEX SLOT BELONGING TO A TASK (M1990).
 *
 * A waiter records `task_self()` in g_futex[] and FUTEX_WAKE later calls
 * task_wake() on that stored pointer. Nothing cleared the slot when the task
 * DIED -- so a thread that exited while parked on a futex, or that timed out
 * and then exited, left a dangling pointer behind. A later wake on the same key
 * put a FREED TASK on the run queue, and the next schedule restored a context
 * whose saved rip was whatever the reused memory happened to hold:
 *
 *     call trace:
 *       [0] 0x0000000000000010
 *       [1] task_block_timeout+0xa3
 *       [2] app_futex+0x1ba
 *
 * The key makes it worse rather than better: it is a PHYSICAL address, so once
 * the dead thread's pages are recycled another process can hash to the same key
 * and fire the stale entry without ever having touched that futex.
 *
 * Called from every path a task can end on -- thread exit, process exit, and
 * the reaper -- because any one of them left alone is the whole bug. */
void app_futex_forget(void *t) {
    if (!t) return;
    uint64_t f = irq_save();
    for (int i = 0; i < FUTEX_NWAIT; i++)
        if (g_futex[i].used && (void *)g_futex[i].task == t) g_futex[i].used = 0;
    irq_restore(f);
}

/* Who is parked on a futex right now, and on what key. Printed when a
 * synchronous run times out -- a threaded hang is a lost wakeup until proven
 * otherwise, and this is the evidence. (M1959) */
/* THE LAST FUTEX OPERATIONS, kept in a ring rather than streamed (M2004).
 *
 * -append futextrace printed each one as it happened and stopped after 240
 * lines, which is a few hundred milliseconds of a sixteen-thread browser --
 * long before the stall it was meant to explain. The interesting window is the
 * one right BEFORE everything went quiet, so keep the last few and print them
 * when something asks why nothing is moving. The question a lost wakeup poses
 * is precise: was a WAKE issued for the key a thread is still parked on? */
/* 96 -> 384 (M2081). Firefox parks sixty-odd threads at once, and each one
 * makes several futex calls on its way down; 96 entries is a fraction of a
 * single quiesce, so the WAKE being hunted had already been overwritten by the
 * WAITs that followed it. The ring only has to outlast one stall. */
#define FUTEX_RING_N 384
struct futex_note { int tid, wake, woke; uint64_t uaddr, key; };
static struct futex_note g_futex_ring[FUTEX_RING_N];
static unsigned long g_futex_ring_i;
static void futex_note(int wake, uint64_t uaddr, uint64_t key, int woke) {
    unsigned long i = __atomic_fetch_add(&g_futex_ring_i, 1, __ATOMIC_RELAXED);
    struct futex_note *e = &g_futex_ring[i % FUTEX_RING_N];
    e->tid = task_current_id(); e->wake = wake; e->uaddr = uaddr; e->key = key; e->woke = woke;
}

void app_futex_dump(void) {
    for (int i = 0; i < FUTEX_NWAIT; i++) {
        if (!g_futex[i].used) continue;
        task_t *wt = (task_t *)g_futex[i].task;
        uint64_t va = g_futex[i].uaddr;
        /* Re-translate in the WAITER's address space, not ours: this runs from
         * the desktop task and `vmm_translate` would answer about the wrong
         * CR3 -- an instrument that reads the wrong memory is worse than none. */
        uint64_t nowp = (wt && wt->cr3) ? vmm_translate_in(wt->cr3, va & ~(uint64_t)(PAGE_SIZE - 1)) : 0;
        int cur = nowp ? *(volatile int *)hhdm(nowp | (va & (PAGE_SIZE - 1))) : 0;
        kprintf("[futex] slot %d key=%lx as=%lx uaddr=%lx task=%d parked because *uaddr==%d; it is %d now%s\n",
                i, g_futex[i].key, (unsigned long)(uintptr_t)g_futex[i].as, va,
                wt ? wt->id : -1, g_futex[i].val, cur,
                nowp ? "" : " -- ITS PAGE IS NOT MAPPED ANY MORE");
    }
    /* ...and the last operations, with a verdict per line: a WAKE for a key
     * nobody is parked on is ordinary (an uncontended unlock does it every
     * time); a key that is STILL PARKED and was never woken is the hang. */
    unsigned long n = g_futex_ring_i < FUTEX_RING_N ? g_futex_ring_i : FUTEX_RING_N;
    if (!n) return;
    kprintf("[futex] the last %lu operations (oldest first):\n", n);
    for (unsigned long k = 0; k < n; k++) {
        unsigned long idx = (g_futex_ring_i - n + k) % FUTEX_RING_N;
        int parked = 0;
        for (int i = 0; i < FUTEX_NWAIT; i++)
            if (g_futex[i].used && g_futex[i].key == g_futex_ring[idx].key) { parked = 1; break; }
        kprintf("[futex]   t%d %s uaddr=%lx key=%lx%s%s\n",
                g_futex_ring[idx].tid, g_futex_ring[idx].wake ? "WAKE" : "WAIT",
                g_futex_ring[idx].uaddr, g_futex_ring[idx].key,
                g_futex_ring[idx].wake ? (g_futex_ring[idx].woke ? " -> woke one" : " -> woke NOBODY") : "",
                parked ? "  [a thread is STILL parked on this key]" : "");
    }
}

long app_futex(uint64_t uaddr, int op, int val, long timeout_ms) {
    if (!vmm_user_ok(uaddr, 4)) return -1;
    if (!vmm_translate(uaddr & ~(uint64_t)(PAGE_SIZE - 1))) return -1;   /* must be mapped to be read */
    uint64_t key; void *as;
    futex_key_of(uaddr, &key, &as);
    if (!key) return -1;

    if (op == FUTEX_WAIT) {
        uint64_t f = irq_save();
        if (*(volatile int *)uaddr != val) { irq_restore(f); return -1; }   /* value changed -> EAGAIN, don't block */
        int slot = -1;
        for (int i = 0; i < FUTEX_NWAIT; i++) if (!g_futex[i].used) { slot = i; break; }
        if (slot < 0) {                                     /* too many waiters */
            /* AND SAY SO (M2081). A full table makes FUTEX_WAIT return the
             * same -1 as a timeout, so the caller is told its wait EXPIRED
             * when in fact it never happened -- the "answers with a plausible
             * wrong value instead of failing" shape this campaign keeps
             * finding. Whether it ever actually fills is a question nobody
             * could answer from the log, because nothing said. */
            static int moaned;
            if (!moaned) { moaned = 1;
                kprintf("[futex] the wait table is FULL (%d slots) -- a wait is being "
                        "reported as a timeout that never waited\n", FUTEX_NWAIT); }
            irq_restore(f); return -1;
        }
        g_futex[slot].key = key; g_futex[slot].as = as; g_futex[slot].task = task_self();
        g_futex[slot].uaddr = uaddr; g_futex[slot].val = val;
        g_futex[slot].used = 1;
        futex_note(0, uaddr, key, 0);
        if (g_futex_trace && g_futex_traced < 240) {
            g_futex_traced++;
            kprintf("[futex] WAIT tid %d uaddr %lx key %lx\n", task_current_id(), uaddr, key);
        }
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
            if (g_futex[i].used && g_futex[i].key == key && g_futex[i].as == as) {
                task_t *wt = (task_t *)g_futex[i].task;
                g_futex[i].used = 0;
                /* A DEAD task must never go back on the run queue. The slots
                 * are cleared on every exit path now, so this should be
                 * unreachable -- and it is one comparison against scheduling a
                 * freed context, which halts the machine. */
                if (wt && task_state_of(wt) != TASK_DEAD) { task_wake(wt); woke++; }
            }
        irq_restore(f);
        /* A WAKE THAT WOKE NOBODY is the interesting one: either there is
         * genuinely no waiter (normal, and common), or there is one whose key
         * does not match ours -- which is a lost wakeup and a hang. Printing
         * the address lets the two be told apart against the WAIT lines.
         * (M1997) */
        /* ...and now SAY WHICH (M2073). The two cases above are not equally
         * likely and are not equally harmless, and for four milestones I have
         * been reading "woke NOBODY" lines unable to tell them apart. The key
         * is a PHYSICAL address; a waiter parked on the same VIRTUAL address in
         * the same address space, whose key no longer matches ours, is a lost
         * wakeup already in progress -- it will never be woken again. That is
         * not a diagnosis to be inferred later from a ring, it is an invariant
         * this function can check while it still has both halves in hand. */
        if (!woke) {
            uint64_t g = irq_save();
            for (int i = 0; i < FUTEX_NWAIT; i++)
                if (g_futex[i].used && g_futex[i].uaddr == uaddr &&
                    (g_futex[i].key != key || g_futex[i].as != as)) {
                    kprintf("[futex] LOST WAKEUP: tid %d woke uaddr %lx (key %lx) and task %d is "
                            "parked on the SAME uaddr under key %lx -- the page moved under it\n",
                            task_current_id(), uaddr, key,
                            g_futex[i].task ? ((task_t *)g_futex[i].task)->id : -1, g_futex[i].key);
                    break;
                }
            irq_restore(g);
        }
        futex_note(1, uaddr, key, woke);
        if (g_futex_trace && g_futex_traced < 240) {
            g_futex_traced++;
            kprintf("[futex] WAKE tid %d uaddr %lx key %lx -> %d\n",
                    task_current_id(), uaddr, key, woke);
        }
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
/* No "0 means read-write" special case any more (M1987). It was the second of
 * two places papering over a field nothing ever set -- /proc/self/maps had the
 * other -- and between them they hid the fact that an anonymous mapping had no
 * recorded protection at all. The one place that read the field LITERALLY was
 * the permission branch of the fault handler, which therefore saw PROT_NONE and
 * killed processes for writing to their own read-write memory. VMA_NEW gives
 * every mapping a real protection now, so zero can mean what it says. */
static uint64_t vma_pte_flags(uint8_t prot) {
    uint64_t f = PTE_USER;
    if (prot & VMA_PROT_WRITE) f |= PTE_WRITABLE;
    if (!(prot & VMA_PROT_EXEC)) f |= PTE_NX;
    return f;
}

/* FAULT RECURSION GUARD (M1987).
 *
 * Resolving a fault can itself fault: the file-backed path reads through the
 * VFS, vmm_user_ok materialises pages, and a locked caller can re-enter here.
 * One level of that is normal. Unbounded levels overrun the 256 KiB kernel
 * stack, and a kernel-stack overflow presents as the kernel EXECUTING ITS OWN
 * STACK -- a page fault with error_code 0x11 (instruction fetch, supervisor)
 * at an address that is not code. That is exactly what Firefox produced, and
 * what it looks like is "random memory corruption", which is a bad place to
 * start looking.
 *
 * Four levels is more than any legitimate chain needs. Beyond it, fail the
 * fault and SAY SO: killing one process with a named reason beats taking the
 * machine down with an unnamed one. */
static volatile uint64_t g_fault_chain[16][6];
unsigned long g_spurious_faults;   /* stale-TLB faults invalidated and retried (M2005) */
/* Fill the pages AFTER `page` from the same file in one read (M2019).
 *
 * Deliberately best-effort: every failure path simply stops, because the
 * demand-fault handler above will do the work again correctly if this does
 * nothing at all. It must never make a page DIFFERENT from what a fault would
 * have produced -- only earlier.
 *
 * `vcopy` is the caller's private snapshot of the VMA, taken under the lock;
 * re-reading the table here would race a concurrent munmap. */
#define FAULT_READAHEAD_PAGES 16          /* 64 KiB: one disk request instead of sixteen */
static void app_fault_readahead(struct app *a, const void *vcopy, uint64_t page) {
    const struct { uint64_t start, len; int sealed, uffd, file_backed, locked, huge, shared;
                   uint64_t foff; short fidx; short mfd; uint8_t prot; uint64_t fvalid; } *v = vcopy;
    uint64_t first = page + PAGE_SIZE;
    uint64_t vend  = v->start + v->len;
    if (first >= vend) return;
    uint64_t n = (vend - first) / PAGE_SIZE;
    if (n > FAULT_READAHEAD_PAGES) n = FAULT_READAHEAD_PAGES;
    if (!n) return;
    /* Never past the file-backed length: beyond it the correct content is
     * zero, and a demand fault already produces that without any I/O. */
    if (v->fvalid) {
        uint64_t voff = first - v->start;
        if (voff >= v->fvalid) return;
        uint64_t avail = (v->fvalid - voff + PAGE_SIZE - 1) / PAGE_SIZE;
        if (n > avail) n = avail;
        if (!n) return;
    }
    /* Stop at the first page that is already present -- past it we would be
     * guessing about a region someone else is managing. */
    uint64_t todo = 0;
    for (todo = 0; todo < n; todo++)
        if (vmm_pte_raw(first + todo * PAGE_SIZE) & PTE_PRESENT) break;
    if (!todo) return;

    uint8_t *buf = kmalloc(todo * PAGE_SIZE);
    if (!buf) return;
    uint64_t voff = first - v->start;
    unsigned long want = todo * PAGE_SIZE;
    if (v->fvalid && voff + want > v->fvalid) want = v->fvalid - voff;
    const char *fp = g_vma_paths[v->fidx];
    __asm__ volatile("sti");
    long got = vfs_pread(fp, buf, want, v->foff + voff);
    __asm__ volatile("cli");
    if (got <= 0) { kfree(buf); return; }

    for (uint64_t k = 0; k < todo; k++) {
        uint64_t off = k * PAGE_SIZE;
        if ((long)off >= got) break;                  /* short read: stop, let faults finish it */
        uint64_t va = first + off;
        uint64_t frame = pmm_alloc_frame();
        if (!frame) break;
        uint8_t *z = (uint8_t *)hhdm(frame);
        long have = got - (long)off; if (have > PAGE_SIZE) have = PAGE_SIZE;
        for (long b = 0; b < have; b++) z[b] = buf[off + b];
        for (long b = have; b < PAGE_SIZE; b++) z[b] = 0;
        uint64_t mfl = vma_alloc_lock(a);
        if (vmm_pte_raw(va) & PTE_PRESENT) {          /* someone got there first */
            vma_alloc_unlock(a, mfl); pmm_free_frame(frame); break;
        }
        if (vmm_map(va, frame, vma_pte_flags(v->prot)) != 0) {
            vma_alloc_unlock(a, mfl); pmm_free_frame(frame); break;
        }
        vma_alloc_unlock(a, mfl);
        __asm__ volatile("invlpg (%0)" : : "r"(va) : "memory");
        a->majflt++;                                   /* it came from disk, like any other filled page */
        g_readahead_pages++;
    }
    kfree(buf);
}

static int app_fault_handle_inner(uint64_t cr2, uint64_t err);
int app_fault_handle(uint64_t cr2, uint64_t err) {
    /* PER-TASK depth (M1992). This counted per CORE, which is wrong for the
     * reason that makes it hard to see: the file-backed path enables
     * interrupts to read from disk, so a core routinely has several tasks part
     * way through their own faults at once. Six threads all touching the same
     * library page produced a "depth 4 recursion" that was really four separate
     * tasks -- and the guard then killed a process that had done nothing wrong.
     * The chain print said so plainly once it existed: the same address three
     * times, which is what concurrent faults on one shared page look like. */
    task_t *ft = task_self();
    int cpu = (int)(smp_current_cpu() & 15);
    int d = ft ? ft->fault_depth : 0;
    if (d >= 4) {
        /* Print the WHOLE CHAIN, not just the top. "Depth 4 resolving X" says a
         * recursion happened; the addresses that got us there say WHICH access
         * inside the fault path is itself faulting, which is the only thing
         * that leads to a fix. */
        kprintf("[fault] RECURSION: refusing at depth %d -- the chain was:\n", d);
        for (int q = 0; q < d && q < 6; q++)
            kprintf("    [%d] %lx\n", q, (unsigned long)g_fault_chain[cpu][q]);
        kprintf("    [%d] %lx (err %lx) <- refused\n", d, cr2, err);
        return 0;
    }
    if (d < 6) g_fault_chain[cpu][d] = cr2;
    if (ft) ft->fault_depth = d + 1;
    int r = app_fault_handle_inner(cr2, err);
    if (ft) ft->fault_depth = d;
    return r;
}

static int app_fault_handle_inner(uint64_t cr2, uint64_t err) {
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
        /* ALWAYS COPY (M2044, and re-affirmed in M2050).
         *
         * The "refcount is 0, so I am the sole owner, so just make it writable
         * in place" fast path is a race: the count is an unlocked read, and
         * vmm_fork_cow on another core can take its reference and map the frame
         * into a child between the read and the commit -- leaving this process
         * writable and non-COW on a page the child shares, so every later write
         * leaks across silently.
         *
         * M2046 made the decision atomic by taking vmm_lock here, since M2045
         * had fork take the same lock. Both are reverted: the locked fork
         * stalled the machine (a baseline kernel ran the in-guest compile at
         * 46% CPU, the locked one at 4-6%), and without fork holding the lock
         * there is nothing here to be atomic against.
         *
         * So: copy unconditionally, which is correct in every interleaving. No
         * concurrent fork -> we copy and free the old frame, which really is
         * free. A fork in the middle -> it has already taken its own
         * reference, so our free drops only ours and the child becomes sole
         * owner. The cost is a 4 KiB copy on a fault that could sometimes have
         * been a flag flip, and it is the honest price of not holding a global
         * lock in the fault path. */
        {
            uint64_t nf = pmm_alloc_frame();
            if (!nf) return 0;                      /* OOM -> let it fault/die */
            uint8_t *s = (uint8_t *)hhdm(old), *d = (uint8_t *)hhdm(nf);
            for (int b = 0; b < PAGE_SIZE; b++) d[b] = s[b];
            /* ONE BREAK PER PAGE (M2077).
             *
             * M1995 gave the demand-zero path a locked re-check for exactly
             * this reason and the COW path kept none, so two threads of one
             * process on two cores could both break the SAME page:
             *
             *   both read the PTE as present+COW, both allocate, both copy,
             *   A installs its frame and its instruction writes a word, then
             *   B installs ITS frame over A's mapping -- and A's word is gone.
             *   Worse, both then pmm_free_frame(old), so the shared frame's
             *   count is decremented twice for one reference and it is handed
             *   to the next allocation on any core while a FORKED CHILD still
             *   maps it.
             *
             * The shape matched what Claude Code did: nothing on -smp 1, and
             * on -smp 4 a different garbage pointer every run -- a JSValue of
             * 0x300000000, a non-canonical address out of a call, a null field
             * in a JIT worker, and once a cell pointer that was ASCII text.
             * Only a process that forks has COW pages at all, which is why a
             * pure allocation workload never reproduced it and the same
             * workload with one Bun.spawnSync per round did.
             *
             * The lock covers the re-check and the install and nothing else.
             * It must NOT cover app_tlb_sync below: that sends IPIs and waits
             * for acknowledgements, and a core spinning on this lock with
             * interrupts off cannot answer one. That is the deadlock the
             * earlier whole-operation VMA lock died of. */
            int won;
            {
                uint64_t cfl = vma_alloc_lock(a);
                uint64_t now = vmm_pte_raw(fpage);
                won = (now & PTE_PRESENT) && (now & PTE_COW) && ((now & PTE_ADDR_MASK) == old);
                if (won)
                    vmm_set_raw(fpage, nf | PTE_PRESENT | (now & (PTE_USER | PTE_NX)) | PTE_WRITABLE);
                vma_alloc_unlock(a, cfl);
            }
            if (!won) {
                /* Somebody else broke it. Their page is the real one; drop ours
                 * and let the instruction re-execute against theirs. Crucially
                 * we do NOT free `old`: our reference to it was consumed by
                 * the winner's free, and freeing it again is the corruption. */
                pmm_free_frame(nf);
                a->minflt++;
                return 1;
            }
            /* SHOOT THE OTHER CORES DOWN BEFORE DROPPING THE FRAME (M2034).
             *
             * vmm_set_raw invlpg's THIS core only. A sibling thread -- same
             * address space, another core -- still holds a cached translation
             * for `old`. The moment pmm_free_frame takes the last reference the
             * frame goes back to the allocator and is handed to somebody else,
             * while that core is still reading and writing it through a stale
             * entry. That is silent cross-process memory corruption, and it
             * does not fault anywhere near where it was caused.
             *
             * Unreachable before M2031, because fork only ever COW-marked the
             * bottom 512 GiB and every threaded runtime keeps its heap far
             * above that. The first thing to exercise it was Claude Code, whose
             * JavaScriptCore values came back as non-canonical pointers:
             *
             *   GPF at claude+4388900: mov 0x20(%rbx),%ecx  rbx=7c3b4b88a9eac000
             *
             * mprotect and munmap were given this in M1963; the COW path was
             * the one that kept a local invlpg. */
            /* ONLY RELEASE IT IF EVERY OTHER CORE ACTUALLY ACKED (M2043). A
             * shootdown that timed out leaves a sibling holding a cached
             * translation, and pmm_free_frame has no quarantine -- a frame
             * whose count reaches zero is handed to the very next allocation on
             * any core. Freeing anyway turns a missed IPI into a
             * use-after-free. Leaking one 4 KiB frame is the strictly better
             * failure: bounded, harmless, and reported. */
            if (app_tlb_sync(a)) {
                pmm_free_frame(old);                /* decrements the shared frame's refcount */
            } else {
                static int told;
                if (!told) { told = 1;
                    kprintf("[vmm] a COW frame was LEAKED rather than freed: the shootdown "
                            "did not complete, so another core may still be using it\n"); }
            }
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
    /* A STALE TLB ENTRY IS NOT A VMA QUESTION (M2078).
     *
     * M2005 added this check and put it INSIDE the branch that has found a
     * VMA, where it has sat ever since -- so the one repair for a
     * hardware/page-table disagreement was conditional on our own bookkeeping
     * describing the address. It is not: when a PTE is made more permissive,
     * x86 does not require the TLB to be updated, and a stale entry may fault
     * on an access the table now allows. The table is authoritative, and
     * whether a VMA happens to cover the page has nothing to do with it.
     *
     * JavaScriptCore's JIT region is mapped and has no VMA, so every such
     * fault in it fell through to the bottom and killed the process:
     *
     *   err=0x7 at rip=b000b918 (CR2=b0038798) [tid 133 'HeapHelper']
     *   the faulting page b0038000: pte=800000001f4b2067
     *                               (present=1 write=1 user=1 cow=0)
     *     in NO VMA of this process (74 vmas)
     *
     * A WRITE fault on a page the table reports present, writable and user.
     * There is no other way to reach that state, and the process was told it
     * had segfaulted -- which is how the interactive TUI died about fifty
     * seconds in, having already painted.
     *
     * Retrying is safe and cannot loop: an invlpg'd entry is reloaded from the
     * table that already permits the access, and app_fault_handle's recursion
     * guard bounds it either way. */
    {
        uint64_t cpte0 = vmm_pte_raw(fpage);
        int wants_write0 = (err & 2) != 0, wants_exec0 = (err & 0x10) != 0;
        if ((cpte0 & PTE_PRESENT) && (cpte0 & PTE_USER) &&
            (!wants_write0 || (cpte0 & PTE_WRITABLE)) &&
            (!wants_exec0  || !(cpte0 & PTE_NX))) {
            vmm_invlpg_one(fpage);
            if (!g_spurious_faults)
                kprintf("[fault] SPURIOUS fault at %lx: err=%lx but pte=%lx already permits it "
                        "-- stale TLB entry, invalidated and retried (M2005/M2078)\n", fpage, err, cpte0);
            g_spurious_faults++;
            return 1;
        }
    }
    /* FIND THE VMA IN ONE LOCKED SCAN, then work from a COPY (M1987).
     *
     * The scan must not drop the lock between iterations, and the first
     * version of this fix did. app_vma_carve fills the hole it makes by MOVING
     * THE LAST ENTRY DOWN into it -- so a concurrent munmap relocates an
     * unrelated mapping to an index the scan has already walked past, and the
     * scan concludes the address is unmapped. That is a "no VMA" fault on
     * memory the process mapped itself and had already written twice, with the
     * VMA plainly present in the table a moment later.
     *
     * The lock is released before the demand-zero / file-read work below,
     * which can do disk I/O; the copy is what makes that safe to do outside
     * it. */
    __typeof__(a->vma[0]) v;
    int have_vma = 0;
    {
        uint64_t fl_ = vma_lock(a);
        for (int i = 0; i < a->nvma; i++)
            if (cr2 >= a->vma[i].start && cr2 < a->vma[i].start + a->vma[i].len) {
                v = a->vma[i]; have_vma = 1; break;
            }
        vma_unlock(a, fl_);
    }
    {
        if (have_vma) {
            uint64_t page = cr2 & ~(uint64_t)(PAGE_SIZE - 1);
            uint64_t cpte = vmm_pte_raw(page);
            /* PROT_NONE READ AS ZEROS (M2060).
             *
             * Nothing in this handler ever consulted VMA_PROT_READ. Only WRITE
             * and EXEC were checked, so a READ of a PROT_NONE page inside a
             * recorded VMA took the demand-zero path below, got a fresh zeroed
             * frame, and SUCCEEDED. A reservation the program made precisely so
             * that touching it would fail instead answered every question with
             * zero.
             *
             * This is the same class as M2031's fork bug, and just as
             * invisible: a missing mapping that returns zeros instead of
             * faulting passes every assertion. What made it matter is what a
             * 64-bit runtime uses PROT_NONE for. JavaScriptCore reserves its
             * 4 GiB structure heap PROT_NONE and deliberately leaves BLOCK
             * ZERO uncommitted so that `StructureID 0` is an invalid id --
             * `decode(0)` is meant to be a segfault. Here it read zeros, so a
             * zeroed JSCell decoded to a Structure of all zeros, whose
             * m_classInfo was null, and the GC's
             *
             *     call *0xd0(%rax)      with rax = 0
             *
             * faulted at CR2=0xd0 inside SlotVisitor::visitChildren -- pages
             * away from the thing that was actually wrong, and with the one
             * check that would have named it (JSC's own decoded-Structure
             * validation) reading a zero it should never have been able to
             * read.
             *
             * A write or an instruction fetch is rejected further down by the
             * WRITE/EXEC checks; this is the read case, which had no check at
             * all. mprotect(PROT_NONE) sets prot = 0 and VMA_NEW defaults to
             * READ|WRITE, so a prot of exactly 0 is always deliberate. */
            if (!(v.prot & (VMA_PROT_READ | VMA_PROT_WRITE | VMA_PROT_EXEC))) {
                static int told;
                if (++told <= 8)
                    kprintf("[fault] access to a PROT_NONE mapping at %lx (vma %lx+%lx) -- "
                            "refusing, not zero-filling\n", cr2, v.start, v.len);
                return 0;
            }
            if (cpte & PTE_PRESENT) {
                /* The page IS mapped, so this is a PERMISSION fault, not a
                 * missing one -- and "return 1" (retry) on a permission fault
                 * is an infinite loop: the instruction re-executes and faults
                 * again forever. That is a hang with no diagnostic at all,
                 * which is exactly what honouring VMA prot first produced.
                 * (M1956) */
                /* A SPURIOUS FAULT: everything this access needed is
                 * already permitted by the PTE (M2005).
                 *
                 * That is not a contradiction, it is architecture. When a PTE
                 * is made MORE permissive, x86 does not require the TLB to be
                 * updated, and a stale entry may fault even though the table
                 * now allows the access. The only correct response is to
                 * invalidate the entry and retry -- Linux has a function for
                 * exactly this case. We instead fell through to the bottom and
                 * killed the process, which is the long-standing "cc1 crashes
                 * intermittently" that has blocked self-hosting since M1962:
                 *
                 *   err=0x7 (present+write+user) on a page reported
                 *   present=1 write=1 user=1 cow=0
                 *
                 * -- a write fault on a writable page, which is impossible to
                 * reach any other way. The COW handler above had just made the
                 * page writable; this core's TLB had not caught up.
                 *
                 * Retrying is safe and cannot loop: app_fault_handle's own
                 * recursion guard bounds it, and an invlpg'd entry is reloaded
                 * from the table that already permits the access. */
                int wants_write = (err & 2) != 0, wants_exec = (err & 0x10) != 0;
                if ((!wants_write || (cpte & PTE_WRITABLE)) &&
                    (!wants_exec  || !(cpte & PTE_NX)) &&
                    (cpte & PTE_USER)) {
                    vmm_invlpg_one(page);
                    if (!g_spurious_faults)
                        kprintf("[fault] SPURIOUS fault at %lx: err=%lx but pte=%lx already permits it "
                                "-- stale TLB entry, invalidated and retried (M2005)\n", page, err, cpte);
                    g_spurious_faults++;
                    return 1;
                }
                if ((err & 2) && !(cpte & PTE_WRITABLE)) {
                    /* MAP_PRIVATE means a write gets a private copy. If the
                     * mapping is writable per its VMA, the PTE simply predates
                     * an mprotect; otherwise the program really did write to a
                     * read-only mapping and deserves to hear about it. */
                    if (v.prot & VMA_PROT_WRITE) {
                        vmm_protect(page, vma_pte_flags(v.prot));
                        return 1;
                    }
                    kprintf("[fault] write to a read-only mapping at %lx (vma prot=%d)\n", page, v.prot);
                    return 0;
                }
                if (err & 0x10) {
                    /* Symmetric with the write case above: the VMA is the
                     * authority on protection, so a PTE that is NX while its
                     * VMA says executable simply predates the prot being
                     * recorded -- fix it rather than kill the process. Only a
                     * mapping whose VMA genuinely is not executable is an
                     * error worth reporting. (M1962) */
                    if (v.prot & VMA_PROT_EXEC) {
                        vmm_protect(page, vma_pte_flags(v.prot));
                        return 1;
                    }
                    kprintf("[fault] instruction fetch from a non-executable mapping at %lx (vma prot=%d)\n", page, v.prot);
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
                                page, err, cpte, v.prot);
                        return 0;
                    }
                } else {
                    a->last_fault_page = page; a->last_fault_err = err; a->fault_repeat = 0;
                }
                return 1;                               /* a genuine race: another core mapped it */
            }
            if (v.huge) {                        /* 2 MiB hugepage: map the whole enclosing 2 MiB at once (M1155) */
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
            if (v.uffd) {
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
            if (!frame) {
                /* SAY THAT IT WAS OUT OF MEMORY (M2036). This returned 0 and
                 * the caller killed the process with no message at all, so a
                 * frame shortage was indistinguishable from a genuine bad
                 * access -- and it presents as the most misleading possible
                 * fault: a WRITE to a page that is not present but IS inside a
                 * perfectly good read-write VMA, at a rip somewhere in glibc's
                 * AVX memset. Nothing about that says "the machine is full". */
                static int told;
                if (!told) {
                    told = 1;
                    kprintf("[fault] OUT OF PHYSICAL MEMORY resolving %lx for pid %d "
                            "(%lu KiB free of %lu KiB) -- this is a frame shortage, not a bad access\n",
                            cr2, a->pid,
                            (unsigned long)(pmm_free_bytes() >> 10),
                            (unsigned long)(pmm_total_bytes() >> 10));
                }
                return 0;
            }
            uint8_t *z = (uint8_t *)hhdm(frame);
            for (int b = 0; b < PAGE_SIZE; b++) z[b] = 0; /* never leak stale RAM to userspace */
            if (v.file_backed) {                /* fill the page from the backing file (M1136) */
                uint64_t voff = page - v.start;
                uint64_t fileoff = v.foff + voff;
                /* fvalid bounds how much of this mapping comes from the file.
                 * An ELF data segment's last page holds real bytes up to
                 * filesz and .bss after it -- and the file does NOT end there,
                 * so "bytes past EOF stay zero" is not enough: without this the
                 * start of .bss would be filled with whatever follows the
                 * segment in the file. 0 means "no limit" (a plain mmap of a
                 * whole file), which is what every pre-M1956 caller wants. */
                uint64_t want = PAGE_SIZE;
                if (v.fvalid) {
                    want = (voff >= v.fvalid) ? 0 : v.fvalid - voff;
                    if (want > PAGE_SIZE) want = PAGE_SIZE;
                }
                if (want) {
                    __asm__ volatile("sti");            /* the FS read may touch the disk */
                    /* The interned path index came out with the copy, so the
                     * lookup does not have to re-find the VMA. */
                    const char *fp = (v.fidx >= 0 && v.fidx < g_vma_npath) ? g_vma_paths[v.fidx] : "";
                    long got = vfs_pread(fp, z, want, fileoff);   /* bytes past EOF stay zero; MAP_PRIVATE: writable copy */
                    __asm__ volatile("cli");
                    /* A SHORT OR FAILED READ LEAVES THE PAGE ZERO, and nothing
                     * downstream can tell that from a page the file genuinely
                     * zeroes. The program starts, runs real code, and dies at
                     * the first instruction of whatever function happened to
                     * live in the hole -- which is how a 214 MB demand-paged
                     * executable presents as "random corruption". Say it here,
                     * where the cause is. (M1992) */
                    /* A partial read is NORMAL at end-of-file -- the last
                     * page of a shared object is short by construction and the
                     * remainder is legitimately zero. Only NO progress at all
                     * means the page is a hole nobody will notice. */
                    /* Past end-of-file is not a hole: a mapping may legally
                     * extend beyond the file and those pages ARE zero. Only
                     * complain when the VMA itself says these bytes should
                     * have been there (fvalid is the file-backed length). */
                    if (got <= 0 && v.fvalid && voff < v.fvalid)
                        kprintf("[fault] EMPTY READ filling %lx from %s+%lx: wanted %lu, got %ld -- the page is a HOLE\n",
                                page, fp, (unsigned long)fileoff, (unsigned long)want, got);
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
            /* PUBLISH THE PAGE ONLY IF NOBODY ELSE ALREADY DID (M1995).
             *
             * Interrupts are off, which stops preemption on THIS core and
             * nothing else. Two threads of one process, on two cores, can be
             * inside this handler for the SAME address at once: both see it
             * absent, both allocate, both fill, and the second vmm_map replaces
             * the first -- discarding everything the first thread's faulting
             * instruction went on to write. For a garbage-collected runtime
             * that is objects turning into small integers, which is exactly how
             * it presented: near-NULL dereferences at a different address every
             * run, deep inside JavaScriptCore.
             *
             * The re-check has to be under the same lock the mapping is taken
             * under, or it is just a narrower window. This one is safe to hold:
             * it covers a PTE check and a page-table walk -- no I/O, no user
             * memory, nothing that can block. The loser frees its frame and
             * returns 1 so the instruction simply re-executes against the
             * winner's page. */
            {
                uint64_t mfl = vma_alloc_lock(a);
                uint64_t now_pte = vmm_pte_raw(page);
                if (now_pte & PTE_PRESENT) {
                    vma_alloc_unlock(a, mfl);
                    pmm_free_frame(frame);      /* someone else won the race */
                    return 1;
                }
                vmm_map(page, frame, vma_pte_flags(v.prot));
                vma_alloc_unlock(a, mfl);
            }
            __asm__ volatile("invlpg (%0)" : : "r"(page) : "memory");
            /* READAHEAD (M2019). One 4 KiB disk read per page fault is why a
             * 214 MB demand-paged executable takes minutes to start: Claude
             * Code touches well over a hundred megabytes before it draws
             * anything, and every single page of it was a separate trip
             * through the filesystem and the ATA driver. The bytes are
             * contiguous in the file and the driver's per-request overhead
             * dwarfs the transfer, so reading a cluster costs barely more than
             * reading one page and saves fifteen faults.
             *
             * PRIVATE file mappings only -- a MAP_SHARED page has writeback
             * semantics that a speculative fill has no business guessing at --
             * and strictly inside the VMA and its fvalid bound, so readahead
             * can never invent bytes a demand fault would not have produced.
             * Pages another thread already mapped are skipped, not replaced. */
            if (v.file_backed && !v.shared && v.fidx >= 0 && v.fidx < g_vma_npath)
                app_fault_readahead(a, &v, page);
            return 1;
        }
    }
    /* Falling out of the VMA walk means NOTHING maps this address. The caller
     * only says "terminating it", which cannot distinguish a wild jump from a
     * mapping we failed to create -- and those need opposite fixes. Name the
     * two neighbours so the gap is visible. (M1965) */
    {
        uint64_t below = 0, below_end = 0, above = ~0ull;
        uint64_t rfl = vma_lock(a);
        for (int i = 0; i < a->nvma; i++) {
            uint64_t st = a->vma[i].start, en = st + a->vma[i].len;
            if (en <= fpage && en > below_end) { below = st; below_end = en; }
            if (st > fpage && st < above)      { above = st; }
        }
        vma_unlock(a, rfl);
        kprintf("[fault] UNMAPPED %lx err=%lx: no VMA (nearest below %lx-%lx, next above %lx, %d vmas, tid %d)\n",
                fpage, err, below, below_end, above == ~0ull ? 0 : above, a->nvma,
                task_self() ? task_self()->id : -1);
        /* The WHOLE table, once. Two neighbours are enough to see that an
         * address is outside every mapping; they are not enough to see WHY --
         * whether the region was never recorded, recorded with the wrong
         * length, or recorded and then carved by another thread. At a couple
         * of dozen entries this is a few lines, and it only prints on a fault
         * that is about to kill the process anyway. (M1987) */
        uint64_t dfl = vma_lock(a);
        int dn = a->nvma; if (dn > 48) dn = 48;
        for (int q = 0; q < dn; q++)
            kprintf("    vma[%d] %lx-%lx prot=%d%s%s\n", q, a->vma[q].start,
                    a->vma[q].start + a->vma[q].len, a->vma[q].prot,
                    a->vma[q].file_backed ? " file" : "", a->vma[q].huge ? " huge" : "");
        vma_unlock(a, dfl);
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
        /* THE SAME RULE AS madvise (M2000): the frame goes back to the
         * allocator here, so no core may still hold a translation for it. One
         * IPI per page is not the cost that matters on this path -- the page
         * was just written to DISK. */
        app_tlb_sync(a);
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
/* rt_sigaction is a QUERY as well as a setter, and answering a query with
 * nothing is how a caller ends up restoring an uninitialised stack word as a
 * signal handler. These report what is actually installed. (M2063) */
uint64_t app_sig_handler_of(int signo) {
    struct app *a = cur();
    return (a && signo > 0 && signo < APP_NSIG) ? a->sig_handler[signo] : 0;
}
uint32_t app_sig_flags_of(int signo) {
    struct app *a = cur();
    return (a && signo > 0 && signo < APP_NSIG) ? a->sig_flags[signo] : 0;
}
uint64_t app_sig_restorer_of(void) { struct app *a = cur(); return a ? a->sig_restorer : 0; }
uint64_t app_sig_mask_of(int signo) {
    struct app *a = cur();
    return (a && signo > 0 && signo < APP_NSIG) ? a->sig_samask[signo] : 0;
}
/* ...and the full Linux action, sa_mask included.
 *
 * sa_mask is RECORDED and REPORTED, not separately enforced, and that is a
 * deliberate statement rather than a gap: `sig_in` already refuses to deliver
 * ANY signal while a handler is running, which is strictly stronger than
 * blocking the handled signal plus sa_mask. What matters is that
 * rt_sigaction's oldact hands back the mask the caller installed instead of
 * zero -- a runtime that reads back an action and reinstalls it must get the
 * same action. (M2063) */
void app_sigaction_full(int signo, uint64_t handler, uint64_t restorer, uint32_t flags, uint64_t samask) {
    struct app *a = cur();
    if (!a || signo <= 0 || signo >= APP_NSIG) return;
    a->sig_handler[signo] = handler;
    a->sig_flags[signo] = flags;
    a->sig_samask[signo] = samask & ~((1ull << 9) | (1ull << 19));   /* KILL/STOP are never blockable */
    if (restorer) a->sig_restorer = restorer;
}

#define APP_SA_SIGINFO 4u
#define APP_SA_ONSTACK 0x08000000u
/* Tell the next signal delivery WHERE the fault was (M2073). Called from the
 * fault handler just before app_signal_deliver, because that is the only place
 * that knows CR2 and the error code; `code` is SEGV_MAPERR(1) when the page was
 * not present and SEGV_ACCERR(2) when it was there and the access was not
 * allowed -- a distinction a handler acts on differently. */
void app_set_fault_siginfo(uint64_t addr, int code) {
    struct app *a = cur(); if (!a) return;
    a->sig_fault_addr = addr; a->sig_fault_code = code; a->sig_fault_valid = 1;
}

/* The dying thread's saved-context slot, allocated on first use: most threads
 * never take a signal. (M2075) */
static struct registers *sig_frame_of(task_t *t) {
    if (!t) return 0;
    if (!t->sig_saved) t->sig_saved = kmalloc(sizeof(struct registers));
    return (struct registers *)t->sig_saved;
}

int app_signal_deliver(struct registers *r, int signo) {
    struct app *a = cur();
    task_t *th = task_self();
    if (!a || !th || signo <= 0 || signo >= APP_NSIG) return 0;
    /* DISPOSITIONS ARE PROCESS-WIDE, the rest is this thread's (M2075). That
     * split is not a simplification, it is what Linux does: sigaction is
     * shared by every thread, the mask, the alternate stack and the
     * interrupted context are not. */
    if (!a->sig_handler[signo] || a->sig_handler[signo] == APP_SIG_IGN || !a->sig_restorer || th->sig_in) return 0;
    struct registers *saveto = sig_frame_of(th);
    if (!saveto) return 0;                   /* cannot save the context -> do not enter the handler */

    /* SA_ONSTACK (M1276): run the handler on the alternate signal stack set by
     * sigaltstack(), instead of growing down from the interrupted rsp. This is
     * what lets a SIGSEGV handler survive a stack-overflow fault (the normal
     * stack is unusable). The frame is still built downward from the alt top. */
    uint64_t base_sp = r->rsp;
    if ((a->sig_flags[signo] & APP_SA_ONSTACK) && th->sig_alt_size)
        base_sp = th->sig_alt_base + th->sig_alt_size;

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
        /* A FAULT SIGNAL CARRIES ITS ADDRESS (M2073); a raised or queued one
         * genuinely has none. sig_fault_valid distinguishes them, so kill()
         * still reports SI_USER with a zero address as it always did. */
        ((int *)si_addr)[1] = a->sig_fault_valid ? a->sig_fault_code : th->sig_q_code;  /* si_code @4 */
        ((uint64_t *)si_addr)[1] = a->sig_fault_valid ? a->sig_fault_addr : 0;          /* si_addr @8 */
        a->sig_fault_valid = 0;                           /* consumed: one delivery, one fault */
        ((uint64_t *)si_addr)[2] = th->sig_q_value;       /* si_value @16 (the sigqueue sigval payload, M1271) */
        *(volatile uint64_t *)ret = a->sig_restorer;
        *saveto = *r;                                     /* safe baseline: cs/ss/rflags for sigreturn */
        th->sig_uctx = mctx_addr;
        th->sig_in = 1;
        r->rsp = ret;
        r->rip = a->sig_handler[signo];
        r->rdi = (uint64_t)signo;                         /* h(signo, */
        r->rsi = si_addr;                                 /*   siginfo*, */
        r->rdx = mctx_addr;                               /*   ucontext*) */
        return 1;
    }

    uint64_t nrsp = ((base_sp - 128) & ~15ull) - 8;  /* skip red zone, 16-align, room for ret addr (base_sp = alt stack if SA_ONSTACK) */
    if (!vmm_user_ok(nrsp, 8)) return 0;             /* bad user stack -> don't deliver */
    *saveto = *r;                                    /* save the interrupted context */
    th->sig_uctx = 0;
    th->sig_in = 1;
    *(volatile uint64_t *)nrsp = a->sig_restorer;    /* handler's return address -> trampoline */
    r->rsp = nrsp;
    r->rip = a->sig_handler[signo];
    r->rdi = (uint64_t)signo;                        /* handler(int signo) */
    return 1;
}

/* RAISE A LINUX SIGNAL AT A PROCESS (M2063).
 *
 * kill/tkill/tgkill used to `return 0` for everything except a hard-coded list
 * of fatal self-signals: "other signals: accepted, undelivered". That is the
 * thirteenth "granted in name only" defect this campaign -- and it is the one
 * that makes every OTHER piece of signal support pointless, because nothing
 * could ever raise anything. `raise(SIGUSR1)` returned success and the handler
 * never ran.
 *
 * Returns 0 = raised, discarded (SIG_IGN) or dropped (no handler, non-fatal
 * default); 1 = the CALLER must terminate with 128+signo; 2 = the target was
 * killed; -1 = no such process.
 *
 * Kept in app.c because the decision needs struct app: whether a handler is
 * installed, whether it is SIG_IGN, and what the default action is. The ABI
 * layer should not be reaching into any of that. */
int app_raise_signal_to(int pid, int signo) {
    struct app *me = cur();
    if (signo <= 0 || signo >= APP_NSIG) return -1;
    struct app *t = (pid <= 0 || (me && pid == me->pid)) ? me : app_by_pid(pid);
    if (!t) return -1;
    if (t->sig_handler[signo] == APP_SIG_IGN) return 0;      /* explicitly ignored: discard */
    if (t->sig_handler[signo]) { app_request_signal((app_t *)t, signo); return 0; }
    /* SIG_DFL. The signals whose default action is to terminate -- everything
     * else defaults to ignore here, which is the safe direction for a
     * compatibility layer that cannot stop, continue or dump core on demand. */
    switch (signo) {
    case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8:
    case 9: case 11: case 13: case 14: case 15: case 24: case 25: case 31:
        if (t == me) return 1;
        t->kill = 1;                                         /* cooperative terminate, as the OOM killer does */
        if (t->task) task_wake((task_t *)t->task);
        return 2;
    default:
        return 0;                                            /* default-ignore */
    }
}

void app_sigreturn(struct registers *r) {
    struct app *a = cur();
    task_t *th = task_self();
    if (!a || !th || !th->sig_in || !th->sig_saved) return;
    /* Restore the interrupted context kernel-side. (SA_SIGINFO hands the handler
     * a READABLE ucontext on the stack for fault inspection; resuming at a
     * handler-rewritten register state — JIT-trap style — is a follow-on, which
     * needs the user ucontext restored with cs/ss/rflags forced safe.) */
    *r = *(struct registers *)th->sig_saved;
    th->sig_uctx = 0;
    th->sig_in = 0;
}

/* sigaltstack (M1276): register an alternate stack for handlers installed with
 * SA_ONSTACK. ss_size 0 disables. The region must be user-accessible (mapped).
 * Returns 0/-1. Pairs with SA_SIGINFO so a SIGSEGV handler can run even when
 * the normal stack has overflowed. */
long app_sigaltstack(uint64_t ss_sp, uint64_t ss_size) {
    struct app *a = cur(); task_t *th = task_self();
    if (!a || !th) return -1;
    if (ss_size == 0) { th->sig_alt_base = 0; th->sig_alt_size = 0; return 0; }
    if (ss_size < 2048 || !vmm_user_ok(ss_sp, ss_size)) return -1;   /* min usable size + must be mapped */
    th->sig_alt_base = ss_sp;                   /* PER-THREAD: a shared one meant a second thread's
                                                 * SA_ONSTACK handler ran on the first thread's stack (M2075) */
    th->sig_alt_size = ss_size;
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
    if (signo == SIGSTOP || signo == SIGTSTP) {
        kprintf("[app] pid %d STOPPED by signal %d\n", ap->pid, signo);
        task_stop((task_t *)ap->task); return;
    }
    /* opted in via a handler, OR routed to signalfd (M1126) — else ignore, the
     * existing default for handler-less signals. */
    int sigfd = ap->sigfd_armed && (ap->sigfd_mask & (1ull << signo));
    if (!ap->sig_handler[signo] && !sigfd) return;
    /* M1612: paired with app_sigsuspend/app_pause/app_sigfd_read's own lock
     * around their check-then-block loops below -- previously unsynchronized,
     * relying purely on task_wake's own state check with no shared flag or
     * lock of any kind (unlike this file's OTHER blocking primitives, none
     * of which had even a bare cli here). A sender (kill/sigqueue/killpg, or
     * the timer for SIGALRM) is routinely a different process on a different
     * core than the one about to block. */
    uint64_t f = irq_save();
    ap->pending_sigs |= (1ull << signo);       /* OR into the bitset, so a 2nd async signal isn't dropped */
    /* WAKE EVERY THREAD THAT COULD TAKE IT, not just the main one (M2075).
     * A process-directed signal is delivered by whichever thread does not
     * block it, and the main thread is routinely the one parked longest -- in
     * a futex wait behind the very worker that would have handled it. Waking
     * only ap->task meant the signal sat pending until something unrelated
     * happened to return to ring 3. */
    if (ap->task && !(((task_t *)ap->task)->sig_blocked & (1ull << signo))) task_wake(ap->task);
    else task_wake(ap->task);                  /* still wake it: a blocked mask can change under us */
    for (int k = 0; k < APP_MAXTHREAD; k++)
        if (ap->thr[k] && ap->thr[k]->state != TASK_DEAD &&
            !(ap->thr[k]->sig_blocked & (1ull << signo)))
            task_wake(ap->thr[k]);
    irq_restore(f);
}

/* RAISE A SIGNAL AT ONE THREAD (M2075).
 *
 * tkill/tgkill/pthread_kill name a thread, and until now that name was
 * discarded: the bit went into the process-wide pending set and was delivered
 * to whichever thread next returned to ring 3. For most uses of kill() that is
 * indistinguishable; for the one that matters it is the whole bug.
 *
 * JavaScriptCore suspends a thread for a collection by pthread_kill-ing it and
 * having the handler record ITS OWN registers, then scans that thread's stack
 * from the recorded stack pointer. Deliver to the wrong thread and the wrong
 * thread's registers are recorded as the target's: the target never suspends,
 * the scan starts from an unrelated stack pointer, live roots are invisible,
 * and the collector frees objects that are still referenced. The crash arrives
 * later, in the marker, on a pointer like 0x9000900090, with nothing left to
 * connect it to a signal.
 *
 * Same return convention as app_raise_signal_to: 0 = delivered/discarded,
 * 1 = the CALLER must terminate, 2 = the target process was killed,
 * -1 = no such thread. */
int app_raise_signal_to_thread(int pid, int tid, int signo) {
    struct app *me = cur();
    if (signo <= 0 || signo >= APP_NSIG) return -1;
    struct app *t = (pid <= 0 || (me && pid == me->pid)) ? me : app_by_pid(pid);
    if (!t) return -1;
    task_t *th = 0;
    if (t->task && ((task_t *)t->task)->id == tid) th = (task_t *)t->task;
    if (!th) for (int k = 0; k < APP_MAXTHREAD; k++)
        if (t->thr[k] && t->thr[k]->id == tid) { th = t->thr[k]; break; }
    if (!th) return -1;                                  /* ESRCH: name a thread that exists */
    if (th->state == TASK_DEAD) return -1;
    if (t->sig_handler[signo] == APP_SIG_IGN) return 0;  /* explicitly ignored: discard */
    if (t->sig_handler[signo]) {
        uint64_t f = irq_save();
        th->sig_pending |= (1ull << signo);
        task_wake(th);
        irq_restore(f);
        return 0;
    }
    /* No handler: a thread-directed signal whose default action is to
     * terminate takes the WHOLE process down, exactly as on Linux. */
    switch (signo) {
    case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8:
    case 9: case 11: case 13: case 14: case 15: case 24: case 25: case 31:
        if (th == task_self()) return 1;
        t->kill = 1;
        if (t->task) task_wake((task_t *)t->task);
        return 2;
    default:
        return 0;                                        /* default-ignore */
    }
}

/* sigprocmask (M1208): change the caller's blocked-signal mask and return the
 * previous one. A blocked signal that's raised stays pending (app_deliver_pending
 * skips it) and is delivered once unblocked. SIGKILL/SIGSTOP can't be blocked. */
uint64_t app_sigprocmask(int how, uint64_t set) {
    struct app *a = cur(); task_t *th = task_self();
    if (!a || !th) return 0;
    /* THE MASK IS THE THREAD'S (M2075). pthread_sigmask and sigprocmask are
     * the same syscall, and it has always been per-thread; a shared mask meant
     * one thread blocking SIGUSR1 -- which is exactly what a runtime does
     * around its own critical sections -- blocked it for every sibling, so the
     * signal that suspends a thread for a collection could not be delivered to
     * any of them. */
    uint64_t old = th->sig_blocked;
    switch (how) {
        case 0: th->sig_blocked |= set;  break;      /* SIG_BLOCK */
        case 1: th->sig_blocked &= ~set; break;      /* SIG_UNBLOCK */
        case 2: th->sig_blocked = set;   break;      /* SIG_SETMASK */
        case 3: break;                               /* query only: report `old` and change nothing (M2063) */
        default: break;
    }
    th->sig_blocked &= ~((1ull << 9) | (1ull << 19));     /* SIGKILL(9)/SIGSTOP(19) are never blockable */
    return old;
}

/* sigpending (M1209): the set of signals raised on this process but not yet
 * delivered (because they're blocked) — POSIX sigpending(2). */
uint64_t app_sigpending(void) {
    struct app *a = cur();
    /* Both sets: what was raised at THIS thread and what was raised at the
     * process and not yet taken by anyone (M2075). */
    task_t *th = task_self();
    return a ? (a->pending_sigs | (th ? th->sig_pending : 0)) : 0;
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
    task_t *th = task_self();
    if (!a) return 0;
    uint64_t thp = th ? th->sig_pending : 0;
    uint64_t thb = th ? th->sig_blocked : 0;
    for (int sig = 1; sig < APP_NSIG; sig++)
        if (((a->pending_sigs | thp) & (1ull << sig)) && a->sig_handler[sig] && a->sig_handler[sig] != APP_SIG_IGN && !(thb & (1ull << sig)))
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
long app_sigsuspend(struct registers *r, uint64_t mask) {
    struct app *a = cur();
    if (!a) return -1;
    task_t *th = task_self(); if (!th) return -1;
    uint64_t old = th->sig_blocked;
    th->sig_blocked = mask & ~((1ull << 9) | (1ull << 19));  /* SIGKILL/SIGSTOP never blockable (matches sigprocmask) */
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
    th->sig_blocked = old;
    return -1;
}

/* pause (M1563): block until a signal is delivered, using the CURRENT mask
 * unchanged -- exactly sigsuspend with mask == a->sig_blocked, which makes
 * its own swap-then-restore a no-op (same value both ways) and its wait
 * condition/delivery-ordering fix (M1561) apply here for free. */
long app_pause(struct registers *r) {
    struct app *a = cur();
    if (!a) return -1;
    { task_t *th = task_self(); return app_sigsuspend(r, th ? th->sig_blocked : 0); }
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
    if (signo == SIGSTOP || signo == SIGTSTP) {
        kprintf("[app] pid %d STOPPED by signal %d (queued)\n", t->pid, signo);
        task_stop((task_t *)t->task); return 0;
    }
    int sigfd = t->sigfd_armed && (t->sigfd_mask & (1ull << signo));
    if (!t->sig_handler[signo] && !sigfd) return -1;     /* not opted in -> ignored, like app_request_signal */
    if (t->sig_handler[signo]) {                          /* payload only matters for a handler */
        if (t->sigq_n >= APP_SIGQ_MAX) return -1;         /* queue full -> EAGAIN */
        t->sigq[t->sigq_n].signo = signo;
        t->sigq[t->sigq_n].code  = code;
        t->sigq[t->sigq_n].value = value;
        t->sigq_n++;
    }
    t->pending_sigs |= (1ull << signo);                     /* mark pending; the queue holds the multiplicity */
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

/* SIGXCPU/SIGXFSZ used to be defined here, one number off Linux's, because 24
 * was SIGWINCH. M2063 renumbered SIGWINCH to 28 and put both at Linux's own
 * numbers in syscall.h, so these local overrides are gone -- they would have
 * silently shadowed the header and raised the WRONG signal. */
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
    task_t *th = task_self();
    uint64_t thp = th ? th->sig_pending : 0;
    uint64_t thb = th ? th->sig_blocked : 0;
    if (!a->pending_sigs && !thp) return 0;
    if ((r->cs & 3) != 3) return 0;          /* resuming kernel code (mid-syscall) -> defer */
    /* deliver the lowest pending signal that has a handler (one per return, like
     * Linux); handler-less signals stay pending for signalfd to drain. */
    for (int sig = 1; sig < APP_NSIG; sig++) {
        /* THIS THREAD'S first, then the process-wide set: a thread-directed
         * signal names its target and a process-directed one does not. (M2075) */
        int mine = (thp & (1ull << sig)) != 0;
        if (!mine && !(a->pending_sigs & (1ull << sig))) continue;
        /* SIG_IGN: DISCARD it, do not leave it pending for ever (M2063). */
        if (a->sig_handler[sig] == APP_SIG_IGN) {
            a->pending_sigs &= ~(1ull << sig);
            if (th) th->sig_pending &= ~(1ull << sig);
            continue;
        }
        if (!a->sig_handler[sig]) continue;
        if (thb & (1ull << sig)) continue;             /* this thread blocks it -> stays pending (M1208) */
        int qi = sigq_peek(a, sig);                   /* RT/sigqueue payload (M1271), or -1 = coalesced/no payload */
        if (th) {
            th->sig_q_code  = (qi >= 0) ? a->sigq[qi].code  : SI_USER;
            th->sig_q_value = (qi >= 0) ? a->sigq[qi].value : 0;
        }
        if (app_signal_deliver(r, sig)) {
            if (qi >= 0) sigq_drop(a, qi);            /* consumed one queued instance */
            if (sigq_peek(a, sig) < 0) {   /* clear only when none remain -> the next queued instance delivers on the next return to ring 3 (RT queuing) */
                a->pending_sigs &= ~(1ull << sig);
                if (th) th->sig_pending &= ~(1ull << sig);
            }
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
        if ((a->pending_sigs & (1ull << s)) && (a->sigfd_mask & (1ull << s)) && !a->sig_handler[s]) return s;
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
    ap->pending_sigs &= ~(1ull << s);           /* consume it */
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
    int n;
    /* BRACKETED PASTE (M2057). A program that asked for it with ESC[?2004h
     * expects the text fenced by ESC[200~ / ESC[201~, and the fence is the ONLY
     * thing that tells it "these newlines are data, not Enter". Without it a
     * multi-line paste into an editor or a TUI prompt arrives as a burst of
     * Return presses -- which for a shell means running every line, and for
     * Claude Code's prompt box means submitting the first line and losing the
     * rest. We were advertising nothing and sending raw bytes; now we honour
     * the mode we were silently dropping. */
    if (a->bracket_paste) {
        static const char pre[] = "\x1b[200~", post[] = "\x1b[201~";
        int pl = (int)sizeof pre - 1, sl = (int)sizeof post - 1;
        int room = (int)sizeof a->pastebuf - pl - sl - 1;
        char tmp[CLIP_MAX];
        int m = clip_get(tmp, sizeof tmp);
        if (m > room) m = room;
        int k = 0;
        for (int i = 0; i < pl; i++) a->pastebuf[k++] = pre[i];
        for (int i = 0; i < m; i++)  a->pastebuf[k++] = tmp[i];
        for (int i = 0; i < sl; i++) a->pastebuf[k++] = post[i];
        n = k;
    } else {
        n = clip_get(a->pastebuf, sizeof a->pastebuf);   /* fill the app's paste buffer... */
    }
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
/* END EVERY OTHER THREAD OF THIS PROCESS, NOW.
 *
 * Every way a process can die has to come through here, and until M1998/M1999
 * none of them did -- each one exited the calling task and left the siblings
 * running until app_reap got round to them, which is the window manager's
 * schedule, not the process's. A sibling parked in poll() or nanosleep()
 * outlived even that (see task_stop in task.c) and woke up after the address
 * space had been freed, executing user code whose pages were gone:
 *
 *     [fault] UNMAPPED 110910000 err=6: no VMA (... 4 vmas, tid 44)
 *
 * -- and the "4 vmas" are the NEXT process's, because the slot had already
 * been reused. That kills an unrelated program.
 *
 * There were two doorways, and fixing one left the other open: exit_group(2)
 * and dying on a fault. A process killed by SIGSEGV must end its threads for
 * exactly the same reason a process that exits cleanly must.
 *
 * Safe from any of these contexts: task_stop only changes scheduling
 * eligibility. A sibling holding a spinlock holds it with interrupts off and
 * cannot be descheduled mid-hold; a sibling blocked in a syscall holds no
 * spinlock, because this kernel's rule is never to block with one held. */
static void app_stop_siblings(struct app *a) {
    if (!a) return;
    /* SAY SO (M2014). exit_group ending every thread is correct, and it is also
     * indistinguishable -- from the outside -- from the bug where a process
     * loses eighty threads and keeps running. One line naming the pid and the
     * caller's own thread separates them at a glance. */
    if (a->lxcalls)
        kprintf("[app] pid %d: exit_group from thread %d -- stopping every sibling\n",
                a->pid, task_current_id());
    for (int i = 0; i < APP_MAXTHREAD; i++) {
        task_t *t = a->thr[i];
        if (t && t != task_self()) { app_futex_forget(t); task_stop(t); }
    }
    if (a->task && a->task != task_self()) { app_futex_forget(a->task); task_stop(a->task); }
}

void app_sys_exit(int code) {
    struct app *a = cur();
    a->exit_code = code; a->exited = 1;
    app_futex_forget(task_self());      /* never leave a waiter pointing at us (M1990) */
    app_stop_siblings(a);        /* exit_group(2) ends EVERY thread (M1998) */
    app_vfork_release((app_t *)a);   /* a vfork child that exits instead of exec'ing (M2006) */
    task_exit();
}
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
 * dump, mark its app exited so the WM tears down the window, then terminate the
 * whole process — the kernel and the rest of the desktop keep running. Its
 * SIBLING THREADS end here too (M1999): they are about to have their address
 * space freed out from under them. No return. */
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
        /* ...and its threads die with it (M1999). A process killed by SIGSEGV
         * has to end its siblings for exactly the reason a process that exits
         * cleanly does: app_reap is about to free the address space they are
         * running in, and one of them is asleep with a timer that will wake it
         * afterwards. */
        app_stop_siblings(a);
        app_vfork_release((app_t *)a);   /* never leave a vfork parent suspended forever (M2006) */
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
    if (!a || !len || vma_full(a)) return 0;
    int vs8; VMA_NEW(a, vs8);
    a->vma[vs8].start = addr;
    a->vma[vs8].len   = len;
    a->vma[vs8].prot  = (uint8_t)(prot & 0x7);
    if (path) {
        a->vma[vs8].file_backed = 1;
        a->vma[vs8].foff = foff;
        a->vma[vs8].fvalid = fvalid;
        a->vma[vs8].fidx = vma_intern_path(path);
        if (a->vma[vs8].fidx < 0) return 0;   /* no slot, or too long: refuse (M1955) */
    }
    
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
    /* Consume the one-shot arming from app_arm_next_spawn, BEFORE the process
     * can run a single instruction: a child that prints immediately used to
     * print to the console because out_to was still being set. (M2004) */
    if (g_pend_out_to || g_pend_parent) {
        a->out_to = g_pend_out_to;
        if (g_pend_parent) a->parent = g_pend_parent;
        /* REAL DESCRIPTORS FOR 0/1/2 (M2004). They used to be "the console"
         * only by virtue of NOT being in the fd table, which works right up
         * until a program dups one -- and then the copy is an fd-table entry
         * pointing at nothing. Claude Code writes its output to a dup, so
         * every word of it went missing. Give them entries from the start and
         * dup, dup2 and fork all do the right thing for free. */
        g_pend_out_to = 0; g_pend_parent = 0;
    }
    /* EVERY Linux process gets real descriptors for 0/1/2, window or not
     * (M2005). Doing this only for the ones with a window fixed the case I was
     * looking at and left the others exactly as broken: a program launched
     * from the kernel still had fd 1 that was "the console" by virtue of not
     * existing, so a dup of it pointed at nothing and its output vanished.
     * Firefox dups its stdio like everything else. With no window behind them
     * these route to the kernel console, which is where that output belongs. */
    if (g_pend_linux) for (int q = 0; q < 3; q++) {
        a->fd[q].used = 1; a->fd[q].type = 14; a->fd[q].obj = 0;
        a->fd[q].off = 0; a->fd[q].cloexec = 0; a->fd[q].nonblock = 0;
    }
    /* copy the title into our own buffer (the caller's string — e.g. a filename
     * from another address space — may not outlive this call). Done here, before
     * the CR3 switch below, while the caller's pointer is still valid. */
    int ti = 0; if (title) while (title[ti] && ti < 23) { a->titlebuf[ti] = title[ti]; ti++; }
    a->titlebuf[ti] = 0;
    a->title = a->titlebuf;
    int ei = 0; if (title) while (title[ei] && ei < (int)sizeof a->exe_path - 1) { a->exe_path[ei] = title[ei]; ei++; }  /* untruncated exe path (M1250/M1970) */
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
    for (int li = 0; li < nlazy && !vma_full(a); li++) {
        int vs9; VMA_NEW(a, vs9);
        a->vma[vs9].start = lazy[li].start; a->vma[vs9].len = lazy[li].len;
        a->vma[vs9].sealed = 0; a->vma[vs9].uffd = 0;
        a->vma[vs9].file_backed = 0; a->vma[vs9].locked = 0; a->vma[vs9].huge = 0;
        
    }

    /* Only the TOP pages eagerly (the initial frame is written into them);
     * the rest is demand-zero through a VMA. (M1975) */
    for (int i = USTACK_PAGES - USTACK_EAGER; i < USTACK_PAGES; i++) {
        uint64_t frame = pmm_alloc_frame();  /* stack: non-executable (W^X) */
        if (!frame) goto fail_in_space;      /* OOM: reclaim the partial space below */
        if (vmm_map(USTACK_BASE + (uint64_t)i * PAGE_SIZE, frame,
                    PTE_WRITABLE | PTE_USER | PTE_NX) != 0) {
            pmm_free_frame(frame);
            goto fail_in_space;
        }
    }
    if (!vma_full(a)) {              /* the lazily-faulted remainder */
        int vs10; VMA_NEW(a, vs10);
        a->vma[vs10].start = USTACK_BASE + PAGE_SIZE;   /* page 0 stays the guard */
        a->vma[vs10].len   = (uint64_t)(USTACK_PAGES - 1 - USTACK_EAGER) * PAGE_SIZE;
        a->vma[vs10].sealed = 0; a->vma[vs10].uffd = 0;
        a->vma[vs10].file_backed = 0; a->vma[vs10].locked = 0; a->vma[vs10].huge = 0;
        a->vma[vs10].prot = VMA_PROT_READ | VMA_PROT_WRITE;
        
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
        /* INHERIT THE SPAWNER'S DIRECTORY (M2033). This used to plant every
         * Linux process at "/disk2" unconditionally -- the volume root -- so a
         * shell that had cd'd somewhere handed its child a cwd of "/", and
         * getcwd(2) said so. Claude Code launched from inside OS-DEV's own
         * source tree therefore took the whole VOLUME as its workspace, git
         * reported "not a git repository", and ripgrep walked 2 GB of
         * libraries instead of the project. Fall back to the volume root only
         * when the requester has no usable directory of its own. */
        const char *startcwd = "/disk2";
        { const char *pre = "/disk2"; int k = 0;
          while (pre[k] && g_pend_lxcwd[k] == pre[k]) k++;
          if (!pre[k] && (g_pend_lxcwd[k] == 0 || g_pend_lxcwd[k] == '/')) startcwd = g_pend_lxcwd; }
        vfs_cwd_set_for(a, startcwd);
        { int k = 0; while (startcwd[k] && k < (int)sizeof a->cwd_path - 1) { a->cwd_path[k] = startcwd[k]; k++; } a->cwd_path[k] = 0; }
        static const char *argv0[2 + LX_PEND_ARGS], *envp0[48];
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
        /* TERM NAMES A TERMINAL THE PROGRAM HAS TO RECOGNISE (M2004).
         *
         * "osdev" is in no terminfo database anywhere, so a TUI looks it up,
         * finds nothing, concludes it is driving something with no cursor
         * addressing and no colour, and renders NOTHING rather than garbage.
         * That is the correct thing for it to do and it left Claude Code
         * sitting on a blank window having written not one byte.
         *
         * xterm-256color is the honest name for what the grid actually is: it
         * takes CSI cursor positioning, SGR colour and the usual erases, which
         * is what this terminal implements. Claiming a capability we lack would
         * be worse than claiming none -- but we are not; we are naming one we
         * have. */
        envp0[0] = "PATH=/bin:/usr/bin"; envp0[1] = "HOME=/root"; envp0[2] = "TERM=xterm-256color";
        /* We have no /etc/ld.so.cache, so anything outside ld.so's default
         * directories is invisible to it. Naming the non-default library
         * directories explicitly is the portable substitute, and it
         * propagates to everything a program execs. (M1964) */
        envp0[3] = "LD_LIBRARY_PATH=/usr/lib64:/lib64:/usr/lib/gcc/x86_64-pc-linux-gnu/15:/usr/lib64/binutils/x86_64-pc-linux-gnu/2.46.0";
        /* Wayland finds its display socket through the environment and
         * nothing else: libwayland's wl_display_connect(NULL) reads
         * XDG_RUNTIME_DIR and WAYLAND_DISPLAY, and simply fails if the first
         * is unset -- which is what a real client did here before this line.
         * The socket lives at $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY, so these two
         * have to name what kernel/wayland.c actually bound. (M1978) */
        envp0[4] = "XDG_RUNTIME_DIR=/run";
        envp0[5] = "WAYLAND_DISPLAY=wayland-0";
        /* GTK picks a backend by probing, and it probes X11 FIRST. Naming the
         * backend is what stops Firefox from failing on a DISPLAY we will
         * never have -- there is no X server here and there is not going to be
         * one; the display path is our own compositor. (M1985) */
        envp0[6]  = "GDK_BACKEND=wayland";
        envp0[7]  = "MOZ_ENABLE_WAYLAND=1";
        /* Firefox's sandbox is built on Linux namespaces and seccomp-bpf
         * filters applied to its own children. We have neither, and a sandbox
         * that cannot be installed is a hard startup failure rather than a
         * degraded mode. Turning it off is honest: this is a compat layer, not
         * a security boundary, and saying so is better than a silent stub that
         * claims a sandbox exists. */
        envp0[8]  = "MOZ_DISABLE_CONTENT_SANDBOX=1";
        envp0[9]  = "MOZ_DISABLE_GMP_SANDBOX=1";
        envp0[10] = "MOZ_DISABLE_RDD_SANDBOX=1";
        envp0[11] = "MOZ_DISABLE_SOCKET_PROCESS=1";
        /* A GTK app writes: a profile, a font cache, a dconf directory. All of
         * them land under these, and an unset XDG_*_HOME falls back to
         * $HOME/.config, which has to exist and be writable. */
        envp0[12] = "XDG_CONFIG_HOME=/root/.config";
        envp0[13] = "XDG_CACHE_HOME=/root/.cache";
        envp0[14] = "XDG_DATA_HOME=/root/.local/share";
        envp0[15] = "FONTCONFIG_PATH=/etc/fonts";
        envp0[16] = "LANG=C.UTF-8";
        /* Firefox PROXIES the Wayland socket for its content processes -- it
         * listens on one of its own and relays. That is a second socket layer
         * to get right before anything can be drawn, and it fails closed:
         * "ProxiedConnection::Process(): Failed to read data from client" and
         * then "we don't have any display". Talking to the compositor directly
         * is the same thing minus a hop. (M1986) */
        envp0[17] = "MOZ_DISABLE_WAYLAND_PROXY=1";
        /* NO GPU, AND SAYING SO IS BETTER THAN LETTING IT FIND OUT (M2003).
         *
         * There is no DRM device here and no Mesa vendor library, so the whole
         * EGL/glvnd path has nothing to bind to. Firefox probes it anyway --
         * the trace shows it loading libGLdispatch.so.0 -- and a dispatch layer
         * that resolves no vendor hands back null function tables. Software
         * rendering is not a degraded mode we are settling for: it is the mode
         * whose output is a shared-memory buffer, which is exactly what wl_shm
         * and this compositor are built to carry. */
        envp0[18] = "LIBGL_ALWAYS_SOFTWARE=1";
        envp0[19] = "MOZ_ACCELERATED=0";
        envp0[20] = "MOZ_X11_EGL=0";
        envp0[21] = "MOZ_DISABLE_GPU_PROCESS=1";
        envp0[22] = "MOZ_WEBRENDER_SOFTWARE=1";
        /* Claude Code runs a connectivity preflight against platform.claude.com
         * and exits if it does not like the answer. Our stack completes that
         * exchange -- the capture shows the TLS handshake finishing in 0.3s and
         * the full response being read -- so what it dislikes is the answer,
         * not the transport. This is the switch it documents for networks that
         * restrict non-essential traffic, and the preflight is exactly that.
         * (M2004) */
        envp0[23] = "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1";

        /* THERE IS NO D-BUS HERE, AND THE WAY TO SAY SO IS PER-SUBSYSTEM
         * (M2013).
         *
         * GTK's accessibility bridge opens a SECOND bus (org.a11y.Bus) by
         * asking the session bus for its address, and GDBus's own diagnosis of
         * the failure went past unnoticed as a warning:
         *
         *   Failed to create DBus proxy for org.a11y.Bus: Cannot spawn a
         *   message bus without a machine-id
         *
         * Firefox's MAIN THREAD then sat in a glib condition variable inside
         * libgio -- thirty threads idle behind it and no syscalls at all --
         * because the reply it was waiting for can never arrive. NO_AT_BRIDGE
         * and GTK_A11Y are the documented way to tell GTK not to try; a
         * deliberately unusable bus address makes anything that still asks
         * fail at connect() instead of waiting for an autolaunch that cannot
         * happen; and GTK_USE_PORTAL=0 keeps the file-chooser and settings
         * portals off the same road.
         *
         * The honest framing: this is not a stub pretending a bus exists. It
         * is telling each subsystem the truth up front, so it takes its own
         * documented no-bus path instead of blocking. */
        envp0[24] = "NO_AT_BRIDGE=1";
        envp0[25] = "GTK_A11Y=none";
        envp0[26] = "GTK_USE_PORTAL=0";
        envp0[27] = "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/dbus-absent";
        envp0[28] = "MOZ_DISABLE_A11Y=1";
        /* ...and the two GLib subsystems that reach a bus WITHOUT being asked
         * to (M2014). GSettings' default backend is dconf, which talks to the
         * session bus the first time anything reads a key -- and GTK reads keys
         * during startup, on the main thread. GIO's default VFS is gvfs, same
         * story. Naming the local/in-memory implementations is not a stub: they
         * are real GLib backends, and they are the correct ones for a machine
         * with no bus and no gvfs daemon. */
        envp0[29] = "GSETTINGS_BACKEND=memory";
        envp0[30] = "GIO_USE_VFS=local";
        envp0[31] = "GVFS_DISABLE_FUSE=1";
        /* One extra entry, one-shot, for a caller that needs to hand a specific
         * program something the whole system should NOT have -- see
         * app_set_next_env. (M1999) */
        /* TMPDIR, because a tool that cannot write a temp file cannot run
         * (M2079). Claude Code swaps each tool's output through a file under
         * $TMPDIR and refuses the tool if the directory is not there; the
         * guest had no /tmp at all, so every Bash tool call failed for a
         * reason that had nothing to do with the command. Named explicitly
         * rather than left to the default so it is visible here next to the
         * directory the image now creates. */
        envp0[32] = "TMPDIR=/tmp";
        int en = 33;
        /* ...and entries set from the KERNEL COMMAND LINE, which unlike the
         * one-shot slot above persist for every program in the boot (M2073).
         * A JIT and a concurrent collector can each be turned off by a JSC
         * option, and "does it still corrupt its heap with the JIT off" is a
         * one-bit answer that no amount of reading the fault address gives. A
         * bisect switch belongs in the kernel here because the environment is
         * built here and nothing else can reach it. */
        for (int k = 0; k < LX_ENV_CMDLINE && en < 44; k++)
            if (g_lx_env_cmdline[k]) envp0[en++] = g_lx_env_cmdline[k];
        for (int k = 0; k < LX_PEND_ENV; k++)
            if (g_pend_env_extra[k]) { envp0[en++] = g_pend_env_extra[k]; g_pend_env_extra[k] = 0; }
        envp0[en] = 0;
        /* Dynamically linked? Map the interpreter too and enter IT: a
         * dynamically-linked program cannot be started directly, ld.so has to
         * map its shared libraries first and only then jump to the entry. */
        uint64_t interp_base = 0;
        if (g_pend_interp) {
            uint64_t ie = elf_load_at(g_pend_interp, g_pend_interp_sz, ELF_INTERP_BASE);
            if (!ie) goto fail_in_space;
            interp_base = ELF_INTERP_BASE;
            a->entry = ie;                   /* the INTERPRETER runs first */
            /* VERIFY THE LOADER'S OWN WORK (M1985). A loader that silently
             * places a DIFFERENT image than the file is the worst failure
             * shape here: the program starts, runs real code for a while, and
             * dies somewhere unrelated -- a zero page inside ld.so's text
             * presents as a fault at the first instruction of whichever
             * function happened to live there. Sampling is enough to catch it,
             * costs microseconds, and names the problem where it happened
             * instead of 30 syscalls later. */
            {
                const uint8_t *src = (const uint8_t *)g_pend_interp;
                int bad = 0;
                for (unsigned long off = 0x1000; off + 16 < g_pend_interp_sz && off < 0x30000; off += 0x1000) {
                    const uint8_t *dst = (const uint8_t *)(ELF_INTERP_BASE + off);
                    if (!vmm_translate((uint64_t)dst)) continue;       /* not part of a mapped segment */
                    for (int q = 0; q < 16; q++) if (dst[q] != src[off + q]) { bad = 1; break; }
                    if (bad) {
                        kprintf("[linuxabi] INTERPRETER MISLOADED at +%lx: mapped %02x %02x %02x %02x, file %02x %02x %02x %02x\n",
                                off, dst[0], dst[1], dst[2], dst[3], src[off], src[off+1], src[off+2], src[off+3]);
                        break;
                    }
                }
            }
        }
        uint64_t rsp = lx_spawn_stack_dyn(elf, elf_image_bias(elf), prog_entry, interp_base,
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
    pend_push(a);
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
    /* A SHARED TRAMPOLINE DEFENDS ITSELF (M2014). Three different callers
     * build a task that starts here, and each has to store `start_frame`
     * before the task becomes runnable. Two of them got that wrong at some
     * point, and the cost of being wrong was a NULL dereference IN RING 0 --
     * a kernel panic for a mistake whose blast radius should be one thread.
     * Refusing to run is the correct answer and it names the condition. */
    if (!t || !t->start_frame) {
        kprintf("[task] thread %d reached its trampoline with no start frame -- "
                "it was made runnable before its context was complete (M2014)\n",
                t ? t->id : -1);
        task_exit();
    }
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
#define NMEMFD 256      /* Firefox wants one /dev/shm object per content process, plus GTK's pools (M2008) */
#define MEMFD_MAX (16ul * 1024 * 1024)   /* 16 MiB per object (kheap-bounded) */
/* `raw` is the allocation; `buf` is the PAGE-ALIGNED view inside it, and the
 * capacity is a whole number of pages. Both are needed to mmap a memfd
 * (M1977): mapping it into a process means aliasing its pages, which requires
 * the region to start on a page boundary AND to own every page it spans --
 * otherwise the last page could be shared with an unrelated kernel allocation
 * and get handed to userspace along with it.
 *
 * `mapped` freezes the size once a process has mapped it. Growing would
 * kmalloc a new buffer and copy, leaving every existing mapping pointing at
 * freed memory. wl_shm sizes a pool once and then maps it, so refusing is
 * both correct and sufficient. */
/* RETIRED BUFFERS: how a MAPPED memfd is allowed to grow at all (M2082).
 *
 * Growing means kmalloc'ing a bigger buffer and copying, and the old buffer's
 * pages are ALIASED INTO USERSPACE by every live mmap of the object. kfree()ing
 * it hands those pages back to the kernel heap while a process still has them
 * mapped read-write, so growth was simply refused whenever `mapped` was set.
 *
 * Refusing is safe and wrong. Resizing an already-mapped pool is what every
 * wl_shm client does -- libwayland-cursor's shm_pool_resize and Firefox's
 * WaylandShmPool::Resize are both posix_fallocate/ftruncate on a mapped fd,
 * followed by munmap + mmap -- and wayland.c's own M2058 comment records the
 * consequence: the client's grow fails, it sends wl_shm_pool.resize anyway, and
 * the compositor has to answer with a FATAL protocol error. Firefox's startup
 * makes this call 107 times and gets ENOSPC every time.
 *
 * So don't free the old buffer: RETIRE it. It stays allocated, so the live
 * mapping keeps pointing at memory that is still ours, and it is released when
 * the object itself dies -- which cannot happen while a mapping exists, because
 * a mapping holds a reference (see app_mmap_memfd_nl's ownership note).
 *
 * Sixteen slots is more than the number of doublings from one page to
 * MEMFD_MAX, so the array cannot be the limit in practice; if it ever is, the
 * old refusal is what happens, which is exactly as safe as before. */
#define MEMFD_RETIRED_N 16
static struct memfd { int used, refs; unsigned seals; unsigned long size, cap;
                      char *buf, *raw; int mapped; char name[64];
                      char *retired[MEMFD_RETIRED_N]; int nretired;
                      /* POSIX shared memory (M2008): a memfd is anonymous, but
                       * /dev/shm/NAME is the same object to everyone who opens
                       * that name. `named` marks the ones that are reachable by
                       * name, so memfd_create's anonymous objects never collide
                       * with them. */
                      int named; } memfds[NMEMFD];

static inline uint64_t memfd_lock_take(void);
static inline void memfd_lock_give(uint64_t f);
/* CLAIMING A SLOT IS A SCAN-AND-CLAIM AND THEREFORE NEEDS THE LOCK (M2087).
 *
 * `if (!memfds[i].used) { m->used = 1; ... }` unlocked is the same shape as
 * unixsock.c's table claim before M1609 and pmm.c's before M1912: two cores
 * both see slot i free, both claim it, and one of them silently gets a handle
 * to an object the other is initialising. Every other access to this table has
 * been under g_memfd_lock since M2043; this one was missed because it reads
 * like an allocator rather than like shared state.
 *
 * The count is taken here too, under the same lock, so it cannot report a
 * half-initialised slot. */
static int memfd_alloc(const char *name) {
    int got = -1, live = 0;
    char nm[32]; nm[0] = 0;
    uint64_t f = memfd_lock_take();
    for (int i = 0; i < NMEMFD; i++) if (!memfds[i].used) {
        struct memfd *m = &memfds[i];
        m->used = 1; m->refs = 1; m->seals = 0; m->size = 0; m->cap = 0;
        m->buf = 0; m->raw = 0; m->mapped = 0;
        m->nretired = 0;
        for (int k = 0; k < MEMFD_RETIRED_N; k++) m->retired[k] = 0;
        int j = 0; if (name) while (name[j] && j < (int)sizeof m->name - 1) { m->name[j] = name[j]; j++; }
        m->name[j] = 0;
        for (j = 0; m->name[j] && j < (int)sizeof nm - 1; j++) nm[j] = m->name[j];
        nm[j] = 0;
        got = i;
        break;
    }
    if (got >= 0) for (int k = 0; k < NMEMFD; k++) if (memfds[k].used) live++;
    memfd_lock_give(f);
    if (got < 0) {
        /* THE TABLE IS FULL, AND SAYING SO IS THE WHOLE POINT. Every caller
         * turns this -1 into an errno of its own and none of them can say
         * which of NMEMFD's several exhaustion causes it was. (M2087) */
        static int moaned;
        if (!moaned) { moaned = 1;
            kprintf("[memfd] TABLE FULL: all %d shared-memory objects are in use, "
                    "refusing to create '%s'. Something is not giving references back.\n",
                    NMEMFD, name ? name : "(anon)");
        }
        return -1;
    }
    /* A HIGH-WATER MARK, NOT A PER-CALL LINE (M2087). A leak of one object per
     * operation is invisible in a per-operation log -- the lines all look the
     * same -- and unmistakable in this one: the mark climbs monotonically to
     * NMEMFD and the table is then exhausted for the rest of the boot. A
     * correct create/destroy cycle never moves it at all, so a healthy boot
     * prints a handful of lines and a leaking one prints a staircase. */
    {   static int peak;
        if (live > peak) {
            peak = live;
            kprintf("[memfd] %d of %d shared-memory objects live (new peak) -- '%s'\n",
                    live, NMEMFD, nm);
        }
    }
    return got;
}
/* THE memfd REFCOUNT IS SHARED ACROSS PROCESSES, so it needs a lock (M2043).
 *
 * `refs++` and `--refs` were plain non-atomic read-modify-writes on an object
 * designed to be shared -- inherited across fork, passed over a socket with
 * SCM_RIGHTS, opened by name under /dev/shm. Two cores dropping the last two
 * references at once can both read 2, both compute 1, and both store 1: the
 * object leaks a slot out of NMEMFD for the rest of the boot.
 *
 * The worse case is both reading 1. Then both compute 0 and both run
 * `kfree(raw)` -- a DOUBLE FREE of kernel-heap memory, which corrupts the
 * allocator's own free list. After that any unrelated kmalloc anywhere in the
 * kernel can return an overlapping block, which is a fully generic mechanism
 * for "memory that has nothing to do with this reads back wrong". That is the
 * shape of the corruption being hunted, and this is one way to produce it.
 *
 * One lock around the count and the teardown it guards. Same irq_save + spin
 * idiom the rest of this file uses. */
static volatile int g_memfd_lock;
static inline uint64_t memfd_lock_take(void) {
    uint64_t f; __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory");
    while (__atomic_exchange_n(&g_memfd_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return f;
}
static inline void memfd_lock_give(uint64_t f) {
    __atomic_store_n(&g_memfd_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(f) : "memory", "cc");
}
static void memfd_ref(int idx) {
    if (idx < 0 || idx >= NMEMFD) return;
    uint64_t f = memfd_lock_take();
    if (memfds[idx].used) memfds[idx].refs++;
    memfd_lock_give(f);
}

/* A memfd's current size, or -1 if this fd is not one (M2000).
 *
 * fstat had no memfd case, so a memfd fell into the catch-all that reports
 * S_IFIFO -- and glibc's posix_fallocate starts by fstat-ing and returns
 * ESPIPE for a FIFO WITHOUT TRYING ANYTHING. That is exactly how every Wayland
 * client sizes its shared-memory pool, so the pool was never sized, the mmap
 * that followed failed, and GDK reported the whole chain as
 *
 *     Gdk-WARNING: Failed to load cursor theme Adwaita
 *
 * A memfd is a regular file on Linux -- an unlinked tmpfs one -- and saying so
 * is both correct and what unblocks it. */
long app_memfd_size(int fd) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 3) return -1;
    int idx = a->fd[fd].obj;
    if (idx < 0 || idx >= NMEMFD || !memfds[idx].used) return -1;
    return (long)memfds[idx].size;
}
static void memfd_unref(int idx) {
    if (idx < 0 || idx >= NMEMFD) return;
    /* Decide who frees UNDER the lock, and take the buffer pointer with us, so
     * exactly one caller can ever reach the kfree for a given object. (M2043) */
    void *doomed = 0;
    /* ...and every buffer this object OUTGREW while it was mapped (M2082).
     * Taken under the same lock and by the same single winner, for the same
     * reason the live buffer is: reaching refs==0 means no fd and no MAPPING
     * holds the object any more, so nothing can still be aliasing these. */
    void *retired[MEMFD_RETIRED_N]; int nret = 0;
    uint64_t f = memfd_lock_take();
    if (memfds[idx].used && --memfds[idx].refs <= 0) {
        doomed = memfds[idx].raw;
        for (int k = 0; k < memfds[idx].nretired; k++) retired[nret++] = memfds[idx].retired[k];
        memfds[idx].nretired = 0;
        for (int k = 0; k < MEMFD_RETIRED_N; k++) memfds[idx].retired[k] = 0;
        memfds[idx].used = 0; memfds[idx].buf = 0; memfds[idx].raw = 0;
        memfds[idx].mapped = 0; memfds[idx].size = memfds[idx].cap = 0;
    }
    memfd_lock_give(f);
    if (doomed) kfree(doomed);            /* outside the lock: kfree can be slow */
    for (int k = 0; k < nret; k++) kfree(retired[k]);
}
/* Ensure cap >= need (doubling), preserving the first `size` bytes. 0/-1.
 *
 * A MAPPED object can grow now (M2082). Two things make that safe, and the
 * first one is what makes it cheap:
 *
 *  - Growth WITHIN the existing capacity moves nothing. That is the
 *    `need <= m->cap` line, and it was always there -- what was missing was any
 *    reason for the capacity to be bigger than the exact first request. A pool
 *    asked for 2304 bytes got one page, so the very next resize had to
 *    reallocate. A mapped object that must move once is given room to grow
 *    several more times without moving again.
 *
 *  - When it does have to move, the old buffer is RETIRED rather than freed,
 *    so the pages a process still has mapped stay ours. See the `retired`
 *    note on struct memfd.
 *
 * The one honest divergence from Linux: there, growing a file never moves
 * anything, so a client that keeps writing through its OLD mapping keeps
 * writing to the object. Here that client would write to the retired copy and
 * the new one would not see it. Every wl_shm client resizes with
 * ftruncate-then-munmap-then-mmap and writes nothing in between, and the
 * headroom above means the realloc usually does not happen at all -- whereas
 * refusing to grow was guaranteed to break all of them. */
static int memfd_grow(struct memfd *m, unsigned long need) {
    if (need <= m->cap) return 0;                  /* nothing moves: mappings stay valid */
    if (need > MEMFD_MAX) return -1;
    /* No slot to remember the outgoing buffer in -> refuse, exactly as before. */
    if (m->mapped && m->nretired >= MEMFD_RETIRED_N) return -1;
    unsigned long nc = m->cap ? m->cap * 2 : PAGE_SIZE;
    while (nc < need) nc *= 2;
    /* HEADROOM for an object somebody has already mapped: this is the
     * expensive, copying, divergent case, so buy several more resizes with one
     * of them. 2304 -> 32 KiB holds a whole cursor theme; a 1.9 MiB window pool
     * gets 8 MiB and survives two doublings. */
    if (m->mapped) { while (nc < need * 4 && nc < MEMFD_MAX) nc *= 2; }
    if (nc > MEMFD_MAX) nc = MEMFD_MAX;
    nc = (nc + PAGE_SIZE - 1) & ~(unsigned long)(PAGE_SIZE - 1);   /* whole pages: see the struct comment */
    char *nr = kmalloc(nc + PAGE_SIZE); if (!nr) return -1;
    char *nb = (char *)(((uintptr_t)nr + PAGE_SIZE - 1) & ~(uintptr_t)(PAGE_SIZE - 1));
    for (unsigned long i = 0; i < m->size; i++) nb[i] = m->buf[i];
    for (unsigned long i = m->size; i < nc; i++) nb[i] = 0;        /* never hand stale kernel bytes to a mapping */
    if (m->raw) {
        if (m->mapped) m->retired[m->nretired++] = m->raw;   /* still aliased into a process */
        else           kfree(m->raw);
    }
    m->raw = nr; m->buf = nb; m->cap = nc;
    return 0;
}

/* ---- memfd growth self-test (M2082) ---------------------------------------
 *
 * Boot-time, in-kernel, and it has to be: the property being asserted lives
 * entirely in `memfd_grow`, which is static, and the interesting input is the
 * `mapped` flag -- which from outside this file can only be set by an actual
 * mmap from an actual process. Driving the object directly is what lets the
 * test say "a MAPPED object" without needing one.
 *
 * The sizes are not invented. 2304 and 6912 are exactly what libwayland-cursor
 * asks for: a 24x24 ARGB cursor, and the pool after two more images are added
 * to it. Firefox's startup makes that second call 107 times and every one of
 * them returned ENOSPC.
 *
 * Two independent things can break, and there is an assertion for each. Put
 * back the `if (m->mapped) return -1` and the SUCCEEDS check fails. Remove it
 * without retiring the outgoing buffer and the churn check fails instead --
 * because the kernel heap hands that block straight back out, while a process
 * still has its pages mapped. That second failure is the one worth having a
 * test for: it is silent, it corrupts an unrelated allocation, and it is the
 * reason the restriction was there in the first place. */
static int memfd_st_pass, memfd_st_fail;
static void memfd_ck(int cond, const char *what) {
    if (cond) { memfd_st_pass++; kprintf("[ ok ] memfd: %s\n", what); }
    else      { memfd_st_fail++; kprintf("[FAIL] memfd: %s\n", what); }
}
#define MEMFD_ST_CHURN 48
void app_memfd_selftest(void) {
    const unsigned long first = 2304, second = 6912;   /* one cursor, then three */
    const char PAT = (char)0xA5;
    int idx = memfd_alloc("memfdselftest");
    if (idx < 0) { memfd_ck(0, "a memfd object was available"); goto summary; }
    struct memfd *m = &memfds[idx];

    if (memfd_grow(m, first) != 0) { memfd_ck(0, "a fresh memfd grew to a cursor pool's size"); goto cleanup; }
    memfd_ck(1, "a fresh memfd grew to a cursor pool's size");
    m->size = first;
    for (unsigned long i = 0; i < first; i++) m->buf[i] = PAT;

    unsigned long cap0 = m->cap;
    char *old = m->buf, *oldraw = m->raw;
    /* The premise: 2304 bytes fits in one page, so the very next resize is
     * past the capacity and cannot be served without reallocating. If this
     * ever stops being true the test below stops testing anything. */
    memfd_ck(second > cap0, "the second resize really is past the capacity, so it must reallocate");

    m->mapped = 1;                      /* a client has mmap'd it; its pages are aliased */
    int grew = memfd_grow(m, second);
    memfd_ck(grew == 0, "growing a MAPPED memfd past its capacity SUCCEEDS");
    if (grew != 0) goto cleanup;
    memfd_ck(m->cap >= second, "the capacity really did grow to hold the request");

    int intact = 1;
    for (unsigned long i = 0; i < first; i++) if (m->buf[i] != PAT) { intact = 0; break; }
    memfd_ck(intact, "the bytes written before the grow survived it");

    /* Was the OUTGOING buffer retired or freed? If it was freed it is on the
     * kernel heap's free list, and allocations of the same size class get it
     * back -- with a live user mapping still pointing at it. */
    memfd_ck(m->nretired == 1 && m->retired[0] == oldraw,
             "the pre-grow buffer was RETIRED rather than freed");
    void *churn[MEMFD_ST_CHURN]; int nch = 0;
    for (int k = 0; k < MEMFD_ST_CHURN; k++) {
        churn[nch] = kmalloc(cap0 + PAGE_SIZE);      /* the same request the old buffer came from */
        if (!churn[nch]) break;
        for (unsigned long i = 0; i < cap0 + PAGE_SIZE; i++) ((char *)churn[nch])[i] = (char)0x5A;
        nch++;
    }
    int survived = 1;
    for (unsigned long i = 0; i < first; i++) if (old[i] != PAT) { survived = 0; break; }
    for (int k = 0; k < nch; k++) kfree(churn[k]);
    memfd_ck(survived, "and the retired buffer's pages were NOT handed back out by the heap");

    /* The headroom: the point of over-allocating a mapped object is that the
     * NEXT resize does not move anything, so a live mapping stays correct. */
    char *stable = m->buf;
    int again = memfd_grow(m, second + PAGE_SIZE);
    memfd_ck(again == 0 && m->buf == stable,
             "a further resize within the new capacity moves nothing at all");

  cleanup:
    m->mapped = 0;                      /* nothing is really mapped: let teardown free it */
    memfd_unref(idx);
    memfd_ck(!memfds[idx].used && memfds[idx].nretired == 0,
             "teardown released the object and every buffer it outgrew");
  summary:
    kprintf("memfd self-test: %d passed, %d failed\n", memfd_st_pass, memfd_st_fail);
}

/* mmap(MAP_SHARED) of a memfd (M1977): alias its pages into the caller.
 *
 * This is how wl_shm works -- a client and the compositor both map the same
 * object and neither copies a pixel. The frames come from the memfd's own
 * page-aligned buffer, so both mappings resolve to the same physical memory
 * and a write through one is immediately visible through the other. */
static uint64_t app_mmap_memfd_nl(int fd, uint64_t len, uint64_t off) {
    struct app *a = cur(); if (!a || !len) return 0;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 3) return 0;
    struct memfd *m = &memfds[a->fd[fd].obj];
    if (!m->used || !m->buf) return 0;
    len = (len + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (off & (PAGE_SIZE - 1)) return 0;                  /* must start on a page */
    if (off + len > m->cap) return 0;                     /* beyond the object */
    uint64_t base = vma_find_gap(a, len, 0);
    if (!base) return 0;
    if (vma_full(a)) return 0;   /* no slot to record it: see the ownership note below */
    /* OWNERSHIP (M1985). These frames belong to the KERNEL HEAP -- they are the
     * memfd's kmalloc'd buffer, aliased into the process, not pages this
     * process allocated. Two things follow, and neither was true before:
     *
     *  - The frames must be REFCOUNTED. munmap and address-space teardown both
     *    call pmm_free_frame on every present user page; without a reference
     *    the first one hands a live kernel-heap page back to the PMM, and the
     *    next pmm_alloc_frame gets memory the heap is still using. That is
     *    exactly what happened: a page of ld.so's text was loaded through a
     *    buffer whose frame had been re-handed out, so the image came up with
     *    a hole of zeros and the program died at the first instruction of
     *    whatever function lived there.
     *  - The MAPPING must hold a reference to the object. Every toolkit does
     *    mmap() and then close() immediately -- that is the documented way to
     *    use a memfd -- and the last close used to kfree the buffer out from
     *    under a live mapping.
     *
     * Above PMM_MAXREFS a frame cannot be refcounted at all, so the honest
     * answer there is to refuse the mapping rather than make one that will be
     * freed from under the heap. */
    for (uint64_t i = 0; i < len; i += PAGE_SIZE) {
        uint64_t phys = vmm_translate((uint64_t)(uintptr_t)(m->buf + off + i));
        if (!phys || !pmm_refcountable(phys)) goto unwind;   /* unbacked or unshareable: map no hole */
        if (vmm_map(base + i, phys, PTE_WRITABLE | PTE_USER | PTE_NX) != 0) goto unwind;
        pmm_addref(phys);
        continue;
      unwind:
        for (uint64_t u = 0; u < i; u += PAGE_SIZE) {
            uint64_t up = vmm_translate(base + u);
            if (up) { vmm_unmap(base + u); pmm_free_frame(up); }
        }
        return 0;
    }
    m->mapped = 1;
    memfd_ref(a->fd[fd].obj);            /* the MAPPING keeps the object alive, not the fd */
    int vs11; VMA_NEW(a, vs11);                          /* recorded so munmap/poll/maps see it */
    a->vma[vs11].start = base; a->vma[vs11].len = len;
    a->vma[vs11].shared = 1;
    a->vma[vs11].mfd = (short)a->fd[fd].obj;
    a->vma[vs11].prot = VMA_PROT_READ | VMA_PROT_WRITE;
    
    return base;
}
uint64_t app_mmap_memfd(int fd, uint64_t len, uint64_t off) {
    struct app *a_ = cur();
    uint64_t f_ = vma_lock(a_);
    uint64_t r_ = app_mmap_memfd_nl(fd, len, off);
    vma_unlock(a_, f_);
    return r_;
}


/* Take a passed memfd as an OBJECT rather than as a descriptor (M1979).
 *
 * app_scm_recv installs the fd into the receiving PROCESS's table. The Wayland
 * compositor is the kernel: it has no fd table, and what it actually wants is
 * the client's pixels. This hands back the memfd's mapping and size directly.
 *
 * The pointer is the memfd's own page-aligned buffer, so the compositor reads
 * exactly the memory the client wrote -- the same object, not a copy. Returns
 * 0 on success. */
/* FIVE WAYS TO FAIL, ONE MESSAGE (M2082).
 *
 * Every one of these returned a bare -1, and the compositor reported all of
 * them as "NO descriptor arrived (SCM_RIGHTS missing)" -- which names only the
 * second of the five and sent me looking at the wrong layer. The causes have
 * nothing to do with each other: a connection index past the table, an empty
 * queue, a descriptor that is not a memfd, and an object that has gone away
 * are four different bugs with four different fixes. Say which. */
int app_scm_take_memfd_idx(int ep, void **base, unsigned long *size, int *idx_out) {
    static int told;
    struct scmq *q = scm_in(ep);
    if (!q) {
        if (told++ < 8)
            kprintf("[scm] ep %d (conn %d) has NO QUEUE: the connection index is past "
                    "SCM_SLOTS (%d) -- this connection can never pass a descriptor\n",
                    ep, unix_ep_conn(ep), SCM_SLOTS);
        return -1;
    }
    if (scmq_empty(q)) {
        if (told++ < 8)
            kprintf("[scm] ep %d (conn %d) queue is EMPTY -- the sender either never "
                    "queued one or an earlier take consumed it\n", ep, unix_ep_conn(ep));
        return -1;
    }
    if (q->fe[q->head].type != 3) {                  /* not a memfd: not ours to interpret */
        if (told++ < 8)
            kprintf("[scm] ep %d queue head is fd type %d, not a memfd\n",
                    ep, q->fe[q->head].type);
        return -1;
    }
    int idx = q->fe[q->head].obj;
    if (idx < 0 || idx >= NMEMFD || !memfds[idx].used || !memfds[idx].buf) {
        if (told++ < 8)
            kprintf("[scm] ep %d queue head names memfd %d, which is %s\n", ep, idx,
                    (idx < 0 || idx >= NMEMFD) ? "out of range"
                      : !memfds[idx].used ? "not in use" : "in use but has no buffer");
        return -1;
    }
    if (base) *base = memfds[idx].buf;
    if (size) *size = memfds[idx].size ? memfds[idx].size : memfds[idx].cap;
    if (idx_out) *idx_out = idx;
    memfd_ref(idx);                                  /* the compositor holds it now */
    memfd_unref(idx);                                /* ...and the in-flight reference is spent (M2082) */
    q->head = (q->head + 1) % SCM_QDEPTH;
    return 0;
}
int app_scm_take_memfd(int ep, void **base, unsigned long *size) {
    return app_scm_take_memfd_idx(ep, base, size, 0);
}

/* WHY A COMPOSITOR MAY NOT BELIEVE THE CLIENT'S SIZE (M2058).
 *
 * wl_shm_pool.resize(size) says "the fd is now this big". The truthful answer
 * lives here, in the object, because nothing makes the request and the object
 * agree: a client can name any number, and a compositor that takes it on trust
 * reads off the end of the pool.
 *
 * M2082 removed the reason this used to fire constantly -- a mapped memfd can
 * be grown now, so the common case is that the client's ftruncate DID work and
 * the object really is that big. What is left is the honest remainder: a grow
 * can still fail at MEMFD_MAX, or because the object has run out of retired-
 * buffer slots, and the client is not told which. So the check stays.
 *
 * `cap` is the useful bound: whole pages the object already owns and has
 * zeroed, which a resize can claim without anything moving. */
int app_memfd_obj_info(int idx, void **base, unsigned long *size, unsigned long *cap) {
    if (idx < 0 || idx >= NMEMFD) return -1;
    uint64_t f = memfd_lock_take();
    int ok = memfds[idx].used && memfds[idx].buf;
    if (ok) {
        if (base) *base = memfds[idx].buf;
        if (size) *size = memfds[idx].size;
        if (cap)  *cap  = memfds[idx].cap;
    }
    memfd_lock_give(f);
    return ok ? 0 : -1;
}

/* THE COMPOSITOR IS A REFERENCE HOLDER LIKE ANY OTHER (M2087).
 *
 * app_scm_take_memfd_idx hands the compositor one reference and there was no
 * way to give it back, nor to take a second. So the compositor leaked the
 * object on every wl_shm_pool.destroy -- which Firefox does on every window
 * resize -- and, worse, leaked one per POOL of every client that merely
 * disconnected, which each of its content processes does. NMEMFD is 256.
 *
 * Giving it back needs the ability to take more than one first: a pool, every
 * buffer cut from it, and a surface's committed frame all read through the
 * same memory and outlive each other in an order the CLIENT chooses. The
 * protocol says so explicitly -- destroying a pool does not invalidate its
 * buffers, and a buffer may be destroyed the moment it is committed. Freeing
 * on the pool's destroy would hand the heap a buffer the window manager is
 * still blitting from. */
void app_memfd_obj_ref(int idx)   { memfd_ref(idx); }
void app_memfd_obj_unref(int idx) { memfd_unref(idx); }
/* How many memfd objects are alive, for a leak assertion: a create/destroy
 * loop must return to the number it started at (M2087). */
int app_memfd_inuse(void) {
    int n = 0;
    uint64_t f = memfd_lock_take();
    for (int i = 0; i < NMEMFD; i++) if (memfds[i].used) n++;
    memfd_lock_give(f);
    return n;
}

/* The OTHER direction: the KERNEL hands a client a descriptor (M1984).
 *
 * app_scm_send passes a descriptor out of a process's fd table. The compositor
 * is the kernel and has no fd table, but Wayland's `wl_keyboard.keymap` obliges
 * it to hand the client a readable file. So: build a memfd from a kernel
 * buffer, own it outright, and queue it for the peer's next recvmsg -- which
 * installs it in the CLIENT's table as an ordinary descriptor it can mmap.
 *
 * The content is copied, deliberately. A keymap is a few kilobytes read once;
 * aliasing a kernel .rodata string into a user mapping to save that copy would
 * hand a process a page of kernel image. */
int app_scm_give_kernel_memfd(int ep, const char *name, const void *data, unsigned long len) {
    struct scmq *q = scm_out(ep); if (!q) return -1;
    if (scmq_full(q)) return -1;
    int idx = memfd_alloc(name); if (idx < 0) return -1;
    struct memfd *m = &memfds[idx];
    if (memfd_grow(m, len) != 0) { memfd_unref(idx); return -1; }
    for (unsigned long i = 0; i < len; i++) m->buf[i] = ((const char *)data)[i];
    m->size = len;
    struct fdent fe;
    for (unsigned long i = 0; i < sizeof fe; i++) ((char *)&fe)[i] = 0;
    fe.used = 1; fe.type = 3 /* memfd */; fe.obj = idx; fe.off = 0;
    q->fe[q->tail] = fe;
    q->tail = (q->tail + 1) % SCM_QDEPTH;
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
/* A READ THAT KEEPS RETURNING EOF IS A SPIN (M2016). Zero means "there will
 * never be more", so a caller that asks again has been told something it did
 * not believe -- and a thread doing that in a loop burns a core forever. Say
 * which fd and what it is, once, rather than leaving it to a syscall histogram
 * to notice. */
static void eof_spin_watch(struct app *a, int fd, long n) {
    static int lastfd = -1; static unsigned long run; static int told;
    if (n != 0) { if (fd == lastfd) run = 0; return; }
    if (fd != lastfd) { lastfd = fd; run = 0; }
    if (++run == 200 && !told) {
        told = 1;
        kprintf("[nettrace] pid %d fd %d (type %d) has read EOF 200 times in a row -- "
                "this thread is spinning on a descriptor that will never have data\n",
                a->pid, fd, a->fd[fd].used ? a->fd[fd].type : -1);
        if (a->fd[fd].used && a->fd[fd].type == 2)
            kprintf("[nettrace]   it is the file '%s' at offset %ld\n",
                    a->fd[fd].path, (long)a->fd[fd].off);
    }
}
/* RUN A BLOCKING NETWORK CALL WITH INTERRUPTS ON (M2068).
 *
 * Every syscall arrives with IF clear (the gate is 0xEE), and net.c's receive
 * wait is measured in TIMER TICKS -- which only advance from the PIT
 * interrupt. So a socket read entered with interrupts off cannot ever reach
 * its own timeout: it spins on a frozen clock, on a core that can no longer be
 * preempted or take the NIC's IRQ. Two cores doing that is a dead machine, and
 * that is exactly what a monitor dump showed the first time Claude Code did
 * enough socket I/O to block.
 *
 * M1863 recorded this trap for the NATIVE syscalls and fixed SYS_fdread; the
 * Linux ABI's read/recv/send paths were never given the same treatment. Save
 * the caller's flag and restore it, so a caller that legitimately had
 * interrupts off gets them back. */
#define NET_BLOCKING(expr) ({                                             \
    uint64_t _nf; __asm__ volatile("pushfq; pop %0" : "=r"(_nf));          \
    __asm__ volatile("sti");                                               \
    __typeof__(expr) _nr = (expr);                                         \
    if (!(_nf & (1u << 9))) __asm__ volatile("cli");                       \
    _nr; })

static long app_fd_read_inner(int fd, void *buf, unsigned long max);
/* AN EDGE THAT HAPPENS BETWEEN TWO POLLS (M2059/M2062). See epoll_note_drain
 * for the consumer side and epoll_note_post for the producer side. */
static void epoll_note_drain(struct app *a, int fd);
static void epoll_note_post(struct app *a, int fd);
long app_fd_read(int fd, void *buf, unsigned long max) {
    long n = app_fd_read_inner(fd, buf, max);
    if (g_net_trace) { struct app *a = cur(); if (a) eof_spin_watch(a, fd, n); }
    if (n > 0) { struct app *a = cur(); if (a) epoll_note_drain(a, fd); }
    return n;
}
static long app_fd_read_inner(int fd, void *buf, unsigned long max) {
    struct app *a = cur(); if (!a) return -1;
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 2) {   /* FILE fd: positioned read (M1193/M1196) */
        long off = a->fd[fd].off;
        if (off < 0) return -1;
        /* A DIRECTORY IS NOT AN UNREADABLE FILE (M2071). ext2_pread refuses a
         * directory with a bare -1, which the Linux layer turns into EBADF --
         * the least informative answer available for a descriptor the kernel
         * itself reports as open and regular. Linux says EISDIR, and programs
         * depend on it: Claude Code opens `/src/.git` and reads it to learn
         * whether it is a real repository (a directory -> EISDIR) or a
         * worktree pointer (a file holding `gitdir: ...`). Told EBADF it
         * learns neither. */
        { struct statx st;
          if (vfs_stat(a->fd[fd].path, &st) == 0 && (st.stx_mode & S_IFMT) == S_IFDIR)
              return APP_FD_EISDIR; }
        long n = vfs_pread(a->fd[fd].path, buf, max, (uint64_t)off);   /* native positioned read (tmpfs/ext2); uncapped */
        if (n > 0) a->fd[fd].off = off + n;
        /* A READ OF AN OPEN FILE THAT FAILS SAYS WHICH FILE (M2071). The Linux
         * ABI turns a bare -1 into EBADF, and "bad file descriptor" on a
         * descriptor the kernel itself reports as open and regular is the most
         * misleading answer available -- it sends you to the fd table, which
         * is fine. The path and offset are the whole question. */
        if (n < 0) {
            static int told;
            if (++told <= 12)
                kprintf("[app] read(fd %d) FAILED on an open regular file: \"%s\" off=%ld max=%lu\n",
                        fd, a->fd[fd].path, off, max);
        }
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
        /* AN EMPTY INOTIFY IS NOT EOF (M2016). Zero from read() means "there
         * will never be more", and a watcher told that about a descriptor it
         * knows is live simply asks again -- forever. Linux blocks here, or
         * answers EAGAIN on a non-blocking fd, and never returns 0. Claude
         * Code's file watcher burned a core on exactly this. */
        for (;;) {
            long n = inotify_read(a->fd[fd].obj, buf, max);
            if (n != 0) return n;
            if (app_fd_nonblock(fd)) return APP_FD_EAGAIN;
            if (a->kill || a->exited) return 0;
            task_sleep_ms(10);
            if (!a->fd[fd].used || a->fd[fd].type != 8) return -1;   /* closed under us */
        }
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 16) {  /* accepted AF_INET connection (M2020) */
        long n = NET_BLOCKING(net_tcp_accept_recv((uint8_t *)buf, (int)max, app_fd_nonblock(fd) ? 0 : 20));
        if (n < 0) return 0;                       /* peer closed: EOF */
        if (n == 0 && app_fd_nonblock(fd)) return APP_FD_EAGAIN;
        return n;
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 14) {  /* console alias (M2004) */
        /* THE KEYBOARD OF THE WINDOW WE WRITE TO.
         *
         * A foreground program's input is whatever is typed at the window it
         * is printing into -- the shell that launched it is blocked in
         * waitpid, so it is not competing for those keys. Reading from our own
         * queue instead would read an empty one forever: the window belongs to
         * the shell, so that is where the keystrokes land.
         *
         * Byte at a time, as a terminal in raw mode delivers them; a TUI wants
         * each key as it is pressed, not a line at a time. EOF only when there
         * is no window at all -- otherwise a program that reads stdin would
         * see a closed one and give up. */
        struct app *src = a->out_to ? a->out_to : a;
        if (!max) return 0;
        if (!a->out_to && !src->cols) return 0;        /* genuinely no terminal */
        /* Finish handing over a sequence started by a previous read, before
         * looking for another key (M2024). */
        if (a->keyseq_i < a->keyseq_n) {
            unsigned long k = 0;
            while (k < max && a->keyseq_i < a->keyseq_n) ((char *)buf)[k++] = a->keyseq[a->keyseq_i++];
            if (a->keyseq_i >= a->keyseq_n) a->keyseq_i = a->keyseq_n = 0;
            return (long)k;
        }
        for (;;) {
            int c = iq_get(src);
            if (c >= 0) {
                /* ARROW KEYS ARE ESCAPE SEQUENCES (M2024).
                 *
                 * Our keyboard delivers one sentinel byte per extended key --
                 * 0x11..0x14 for the arrows -- which is what every OS-DEV app
                 * reads. A terminal sends `ESC [ A`, and a Linux TUI matches on
                 * exactly that. So Claude Code's menus could be SEEN but not
                 * NAVIGATED: every arrow press arrived as a control character
                 * it had no meaning for, and the selection never moved. Same
                 * class as the Return key in M2014 -- the key was delivered,
                 * in an encoding the program does not speak. */
                const char *seq = 0;
                switch (c) {
                case 0x11: seq = "\x1b[A"; break;   /* up    */
                case 0x12: seq = "\x1b[B"; break;   /* down  */
                case 0x13: seq = "\x1b[D"; break;   /* left  */
                case 0x14: seq = "\x1b[C"; break;   /* right */
                case 0x15: seq = "\x1b[5~"; break;  /* page up   */
                case 0x16: seq = "\x1b[6~"; break;  /* page down */
                default: break;
                }
                if (seq) {
                    a->keyseq_n = 0;
                    for (int q = 0; seq[q] && q < (int)sizeof a->keyseq; q++)
                        a->keyseq[a->keyseq_n++] = seq[q];
                    a->keyseq_i = 0;
                    unsigned long k = 0;
                    while (k < max && a->keyseq_i < a->keyseq_n) ((char *)buf)[k++] = a->keyseq[a->keyseq_i++];
                    if (a->keyseq_i >= a->keyseq_n) a->keyseq_i = a->keyseq_n = 0;
                    return (long)k;
                }
                /* RETURN IS CR IN RAW MODE (M2014). See tio_wants_cr: our
                 * keyboard produces NL because every native app expects it,
                 * and a program that cleared ICRNL is asking for the CR a
                 * real terminal would have delivered. */
                if (c == '\n' && tio_wants_cr(a)) c = '\r';
                /* -append lxkeys: THE BYTES, AS DELIVERED (M2078).
                 *
                 * Claude Code's input box accepted every typed character and
                 * ignored Return, and from the outside there is no way to tell
                 * "the key never arrived" from "it arrived as the wrong byte"
                 * -- which is the same ambiguity M2014 and M2024 both turned
                 * out to be. One hex byte per key answers it. */
                { extern int g_lx_keytrace; static int shown;
                  if (g_lx_keytrace && shown < 64) {
                      shown++;
                      kprintf("[keys] pid %d reads 0x%02x%s\n", a->pid, (unsigned char)c,
                              (c == '\r') ? " (CR)" : (c == '\n') ? " (LF)" : ""); } }
                ((char *)buf)[0] = (char)c;
                /* ECHO, when the program asked for it (M2014). A cooked-mode
                 * Linux program expects the TERMINAL to show what was typed;
                 * a raw one draws its own and must not be doubled. */
                if ((a->tio_valid ? (a->tio_lflag & TIO_ECHO) : 1) && !a->out_to) {
                    char e = (char)((c == '\r') ? '\n' : c);
                    if ((unsigned char)e >= 0x20 || e == '\n' || e == '\t') grid_write(a, &e, 1);
                }
                return 1;
            }
            /* O_NONBLOCK means DO NOT WAIT. An event loop sets it on stdin and
             * reads until EAGAIN; blocking there instead is the same deadlock
             * the poll predicate above describes. */
            if (app_fd_nonblock(fd)) return APP_FD_EAGAIN;
            if (a->kill) return 0;                     /* asked to die: stop waiting */
            task_sleep_ms(10);
        }
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 9) {   /* connected UDP socket: recv (M1967) */
        if (!a->fd[fd].peer_port) return -1;                                  /* ENOTCONN */
        return app_recvfrom(fd, buf, (int)max, 0, 0);
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 10) {  /* TCP socket: recv (M1268) */
        net_tcp_sock_set_nonblock(a->fd[fd].obj, a->fd[fd].nonblock);   /* O_NONBLOCK is a per-FD property (M1967) */
        long n = NET_BLOCKING(net_tcp_sock_recv(a->fd[fd].obj, buf, max));
        /* WHERE A TLS HANDSHAKE ACTUALLY STOPS (M2016). "Connection timed out
         * after 10 seconds" is the only thing the application can tell us, and
         * it is true of a socket that never connected, one that connected and
         * sent nothing, and one that sent a ClientHello and got no reply --
         * three different bugs. Byte counts in both directions separate them,
         * and nothing else here can. */
        g_net_calls++;
        if (g_net_trace)
            kprintf("[nettrace] t=%lums pid %d fd %d recv(%lu) -> %ld%s\n",
                    (unsigned long)timer_ms(), a->pid, fd, max, n,
                    (n == NET_SOCK_EAGAIN) ? " (EAGAIN)" : "");
        return (n == NET_SOCK_EAGAIN) ? APP_FD_EAGAIN : n;
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 11) {  /* pty endpoint: read through the line discipline (M1274) */
        return pty_read(a->fd[fd].obj, buf, max);
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 12) {  /* AF_UNIX endpoint: recv (M1965) */
        if (a->fd[fd].obj < 0) return -1;                                     /* socket() but never connected */
        /* unix_recv BLOCKS. An event loop reads until EAGAIN, so on a
         * non-blocking socket "no data" must come back as EAGAIN and not as a
         * task_block() that never returns -- that would hang the loop with the
         * one thread that was supposed to service it. */
        if (app_fd_nonblock(fd) && !unix_readable(a->fd[fd].obj)) return APP_FD_EAGAIN;
        return unix_recv(a->fd[fd].obj, buf, max);
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 13) return -1;  /* a listener is not readable */
    int idx = fd_pipe_idx(a, fd, 0); if (idx < 0) return -1;
    /* THE PIPE WAS THE LAST FD TYPE THAT IGNORED O_NONBLOCK, and it wedged
     * Firefox's main thread permanently (M2009).
     *
     * Every event loop of this shape owns a self-pipe: another thread writes
     * one byte to wake the poll, and the loop then DRAINS the pipe by reading
     * until EAGAIN. The last read of that drain is expected to find the pipe
     * empty -- that is how the loop knows it is done. Blocking there instead
     * stops the one thread that services the loop, so every other thread ends
     * up futex-waiting on work it will now never post: 33 threads asleep
     * because of one read that should have returned -EAGAIN.
     *
     * pipe_readable() is the same predicate poll() answers with, so a
     * non-blocking read agrees with the poll that preceded it -- including on
     * EOF, which must still read as 0 rather than EAGAIN. */
    if (app_fd_nonblock(fd) && !pipe_readable(idx)) return APP_FD_EAGAIN;
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
static long app_fd_write_inner(int fd, const void *buf, unsigned long len);
long app_fd_write(int fd, const void *buf, unsigned long len) {
    long n = app_fd_write_inner(fd, buf, len);
    /* A write can consume WRITABILITY the same way a read consumes readability
     * -- fill a pipe or a socket's send ring and the fd goes not-writable. An
     * edge-triggered EPOLLOUT waiter needs that transition recorded, or it
     * never hears about the space that opens up later. (M2059) */
    if (n > 0) { struct app *a = cur(); if (a) epoll_note_drain(a, fd); }
    return n;
}
static long app_fd_write_inner(int fd, const void *buf, unsigned long len) {
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
        /* EVERY WRITE IS AN EDGE ON AN EVENTFD (M2062). See epoll_note_post:
         * this is the wake-up primitive a thread pool posts work on, and the
         * counter staying non-zero across two posts must not swallow the
         * second one. */
        epoll_note_post(a, fd);
        return 8;
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 16) {  /* accepted AF_INET connection (M2020) */
        int w = NET_BLOCKING(net_tcp_accept_send((const uint8_t *)buf, (int)len));
        return (w < 0) ? APP_FD_EPIPE : (long)len;
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 14) {  /* console alias (M1972) */
        /* TO THE WINDOW THAT LAUNCHED US, not the kernel console (M2004).
         *
         * This is what makes stdout survive a dup. Claude Code writes its
         * startup error to fd SEVEN -- a dup of stdout -- so a hook that only
         * looked at fd 1 and 2 never saw a word of it, and the program looked
         * like it produced no output at all. Once fd 0/1/2 are real fd-table
         * entries, dup copies the entry and every copy lands in the same
         * place, which is the property a shell actually needs. */
        if (a->out_to) { app_write_to((app_t *)a->out_to, (const char *)buf, (unsigned)len); return (long)len; }
        console_write_n((const char *)buf, len);
        return (long)len;
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 9) {   /* connected UDP socket: send (M1967) */
        if (!a->fd[fd].peer_port) return -1;                                  /* ENOTCONN: no default peer */
        return app_sendto(fd, a->fd[fd].peer_ip, a->fd[fd].peer_port, buf, (int)len);
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 10) {  /* TCP socket: send (M1268) */
        long w = NET_BLOCKING(net_tcp_sock_send(a->fd[fd].obj, buf, (int)len));
        g_net_calls++;
        if (g_net_trace)
            kprintf("[nettrace] t=%lums pid %d fd %d send(%u) -> %ld\n",
                    (unsigned long)timer_ms(), a->pid, fd, len, w);
        return w;
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 11) {  /* pty endpoint: master write feeds the ldisc, slave write -> master output (M1274) */
        return pty_write(a->fd[fd].obj, buf, len);
    }
    if (fd >= 0 && fd < APP_NFD && a->fd[fd].used && a->fd[fd].type == 12) {  /* AF_UNIX endpoint: send (M1965) */
        if (a->fd[fd].obj < 0) return -1;
        /* O_NONBLOCK IS THE CALLER'S, AND A FULL RING IS NOT A SUCCESS (M2090).
         * unix_send returned whatever fitted -- including ZERO -- and nothing
         * ever waited. A write of 0 makes a caller loop for ever making no
         * progress while believing it is working; Firefox's fork server hit
         * the ENETUNREACH this got turned into and tore its channel down. */
        long w = unix_send_ex(a->fd[fd].obj, buf, len, app_fd_nonblock(fd));
        if (w == UNIX_EAGAIN) return APP_FD_EAGAIN;
        /* A dead peer is EPIPE, not EBADF. Node reported "write EBADF" on a
         * connection that was fine, because this whole case was MISSING and
         * the write fell through to fd_pipe_idx() -- which of course found no
         * pipe behind a socket fd and returned -1. Every socket call in the
         * trace had succeeded; the byte path simply did not exist. */
        if (w < 0) { app_request_signal(a, SIGPIPE); return APP_FD_EPIPE; }
        return w;
    }
    int idx = fd_pipe_idx(a, fd, 1); if (idx < 0) return -1;
    /* ...and the write side, for the same reason (M2009): the thread POSTING a
     * wakeup must not block because the pipe is full -- it is full precisely
     * because a wakeup is already pending, so the correct answer is a short
     * count (or EAGAIN when nothing at all fits) and the caller drops the
     * redundant byte. This cannot be a readiness check in FRONT of the write:
     * a 4096-byte write into a ring with 100 bytes free must move those 100 and
     * say so, not block on the remainder. */
    long pw = pipe_write_ex(idx, buf, len, app_fd_nonblock(fd));
    if (pw == PIPE_EAGAIN) return APP_FD_EAGAIN;
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
/* O_NONBLOCK as a real per-fd property (M1965). fcntl(F_SETFL) used to be a
 * no-op that returned 0, which is the worst of both worlds: the caller
 * believes the fd is non-blocking and then a read blocks its event loop
 * forever. */
int app_fd_nonblock(int fd) {
    struct app *a = cur(); if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return 0;
    return a->fd[fd].nonblock ? 1 : 0;
}
int app_fd_set_nonblock(int fd, int on) {
    struct app *a = cur(); if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    a->fd[fd].nonblock = on ? 1 : 0;
    return 0;
}
int app_fd_set_cloexec(int fd, int on) {
    struct app *a = cur(); if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    a->fd[fd].cloexec = on ? 1 : 0;
    return 0;
}
int app_current_pid(void) { struct app *a = cur(); return a ? a->pid : -1; }

/* The object index behind an fd (pipe number, memfd index, ...), or -1. Needed
 * by a diagnostic that has to ask the object itself a question. (M2004) */
int app_fd_obj(int fd) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    return a->fd[fd].obj;
}

int app_fd_type(int fd) {
    struct app *a = cur(); if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    return a->fd[fd].type;
}

int app_fd_close(int fd) {
    struct app *a = cur(); if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    if (a->fd[fd].type == 1) pipe_close_end(a->fd[fd].obj, a->fd[fd].write_end);
    else if (a->fd[fd].type == 3) memfd_unref(a->fd[fd].obj);   /* drop a memfd reference (M1212) */
    else if (a->fd[fd].type == 6) epoll_unref(a->fd[fd].obj);   /* drop an epoll reference (M1220) */
    else if (a->fd[fd].type == 8) inotify_free(a->fd[fd].obj);  /* free the inotify instance (M1266) */
    else if (a->fd[fd].type == 10) {
        /* How long the connection lasted and how much crossed it: a TLS
         * handshake that is merely SLOW and one that is not happening look
         * identical from outside, and the byte counts tell them apart. (M2004) */
        net_tcp_sock_close(a->fd[fd].obj);  /* close the TCP connection (M1268) */
    }
    else if (a->fd[fd].type == 11) pty_close(a->fd[fd].obj);    /* close this pty end, waking the peer (M1274) */
    else if (a->fd[fd].type == 12) { if (a->fd[fd].obj >= 0) unix_close(a->fd[fd].obj); }   /* AF_UNIX endpoint: wake the peer with EOF (M1965) */
    else if (a->fd[fd].type == 13) unix_unlisten(a->fd[fd].obj);                            /* AF_UNIX listener: release the name (M1965) */
    else if (a->fd[fd].type == 16) net_tcp_accept_close();                                  /* accepted AF_INET connection (M2020) */
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
    else if (a->fd[newfd].used && a->fd[newfd].type == 12 && a->fd[newfd].obj >= 0) unix_close(a->fd[newfd].obj); /* (M2002) */
    a->fd[newfd] = a->fd[oldfd];                                  /* newfd now references the same end */
    /* dup2 NEVER CARRIES FD_CLOEXEC (M2037). POSIX is explicit: the new
     * descriptor does not inherit the close-on-exec flag, whatever oldfd has;
     * only dup3(..., O_CLOEXEC) may ask for it, and this kernel does not even
     * implement dup3 as a Linux syscall. Copying the whole fdent struct copied
     * the flag with it.
     *
     * That one bit is why Claude Code never received a word from any child it
     * spawned. The idiom is pipe2(fds, O_CLOEXEC) -- so the pipe cannot leak
     * into unrelated descendants -- then dup2(fds[1], 1) in the child, which on
     * Linux clears the flag, which is precisely WHY the pattern is written that
     * way. Here fd 1 stayed CLOEXEC, so app_exec's cloexec sweep closed it
     * again immediately before the new image took over. The exec'd program's
     * write(1, ...) then found fd 1 unbound and fell through to the console
     * fallback -- ripgrep's output scrolled over the terminal and destroyed the
     * TUI -- while Claude Code's end of the pipe saw an instant EOF.
     *
     * The existing pipeline test never caught it because tools/lx/lxbox.c uses
     * plain pipe(), so the precondition never arises. Two other callers already
     * worked around this by re-setting .cloexec themselves after calling here
     * (app_fcntl's F_DUPFD path and app_dup3); the raw Linux dup2(2) was the
     * one that did not, so the fix belongs here rather than at the call sites. */
    a->fd[newfd].cloexec = 0;
    if (a->fd[newfd].type == 1) pipe_open_end(a->fd[newfd].obj, a->fd[newfd].write_end);
    else if (a->fd[newfd].type == 3) memfd_ref(a->fd[newfd].obj);   /* (M1212) */
    else if (a->fd[newfd].type == 6) epoll_ref(a->fd[newfd].obj);   /* (M1220) */
    else if (a->fd[newfd].type == 8) inotify_ref(a->fd[newfd].obj);       /* (M1603) */
    else if (a->fd[newfd].type == 10) net_tcp_sock_ref(a->fd[newfd].obj); /* (M1603) */
    else if (a->fd[newfd].type == 12 && a->fd[newfd].obj >= 0) unix_ref(a->fd[newfd].obj); /* AF_UNIX: a descriptor is a reference (M2002) */
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
/* POSIX SHARED MEMORY: open /dev/shm/NAME (M2008).
 *
 * Firefox does not treat this as optional. Its parent and content processes
 * talk through a shared segment, and when the open failed it crashed on
 * purpose rather than continue:
 *
 *   openat("/dev/shm/org.mozilla.ipc.106.1", O_RDWR|O_CREAT|O_EXCL) = -ENOENT
 *   ... mov %rcx,(%rax) with rax = 0, then two noreturn calls
 *
 * shm_open(3) on Linux IS open("/dev/shm/NAME"), so this needs no new syscall
 * -- only for that path to resolve to an object two processes can both map. A
 * memfd is already exactly that object: app_mmap_memfd hands both mappers the
 * same physical pages, which is what makes wl_shm a zero-copy pixel handoff and
 * is proven by lxscm. The only thing missing was a NAME to find it by.
 *
 * Returns an fd, or a negative Linux errno. */
int app_shm_fd(const char *name, int o_creat, int o_excl) {
    struct app *a = cur();
    if (!a || !name || !name[0]) return -22;   /* EINVAL */
    /* memfd_alloc TRUNCATES the name it stores, and a truncated name is a name
     * collision waiting to happen: two segments differing only past the cut
     * would be the same object to every lookup below. Refuse instead. */
    int nlen = 0; while (name[nlen]) nlen++;
    if (nlen >= (int)sizeof memfds[0].name) return -36;   /* ENAMETOOLONG */
    int idx = -1;
    for (int i = 0; i < NMEMFD; i++) {
        if (!memfds[i].used || !memfds[i].named) continue;
        int k = 0;
        while (memfds[i].name[k] && memfds[i].name[k] == name[k]) k++;
        if (!memfds[i].name[k] && !name[k]) { idx = i; break; }
    }
    if (idx >= 0 && o_creat && o_excl) return -17;   /* EEXIST */
    if (idx < 0) {
        if (!o_creat) return -2;    /* ENOENT */
        idx = memfd_alloc(name);
        if (idx < 0) return -28;   /* ENOSPC */
        memfds[idx].named = 1;
        memfds[idx].refs++;        /* the NAME is a reference: see app_shm_unlink */
    } else {
        memfd_ref(idx);                     /* another descriptor on the same object */
    }
    int fd = -1;
    if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }
    if (fd < 0) { memfd_unref(idx); return -24; }   /* EMFILE */
    a->fd[fd] = (struct fdent){ 1, 3, 1, idx, {0}, 0 };   /* used, type=memfd, writable */
    return fd;
}

/* shm_unlink(3): the NAME goes away now; the object itself lives until the last
 * descriptor and mapping are gone, which is what POSIX requires. Firefox
 * creates with O_EXCL and unlinks immediately, so without this the second run
 * of any process would collide with the first one's name. */
int app_shm_unlink(const char *name) {
    if (!name || !name[0]) return -22;   /* EINVAL */
    for (int i = 0; i < NMEMFD; i++) {
        if (!memfds[i].used || !memfds[i].named) continue;
        int k = 0;
        while (memfds[i].name[k] && memfds[i].name[k] == name[k]) k++;
        if (!memfds[i].name[k] && !name[k]) {
            memfds[i].named = 0;
            memfd_unref(i);         /* drop the name's reference; open fds keep it alive */
            return 0;
        }
    }
    return -2;    /* ENOENT */
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
/* What timerfd_gettime has to answer, and what timerfd_settime's `old_value`
 * has to report: the time left and the period. Both live in the fd entry
 * already; nothing could read them out before, so the Linux side had to either
 * fake them or refuse. (M2073) */
long app_timerfd_remaining_ms(int fd) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 4) return -1;
    if (!a->fd[fd].off) return 0;                       /* disarmed */
    uint64_t now = timer_ms(), due = (uint64_t)a->fd[fd].off;
    return (due > now) ? (long)(due - now) : 0;         /* already expired reads as 0, as on Linux */
}
long app_timerfd_interval_ms(int fd) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 4) return 0;
    return (long)a->fd[fd].obj;
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
/* ---- AF_INET SERVER SOCKETS: bind / listen / accept (M2020) ---------------
 *
 * bind() on an AF_INET socket used to be accepted and ignored, with the
 * reasoning that we are single-homed and nothing depended on a specific local
 * port. Something does: Claude Code's OAuth login starts a local HTTP server
 * for the callback, asks the kernel which port it got, and puts that port in
 * the URL it shows you. Accepting the bind and then failing the listen gave
 *
 *     OAuth error: Failed to start OAuth callback server.
 *                  Failed to start server. Is port 0 in use?
 *
 * which is the third time in this arc that saying "yes" without meaning it has
 * been worse than saying "no" (see pipe2 M2009, socketpair M2012, eventfd2
 * M2017).
 *
 * net.c has had a passive open since M1327 -- SYN/SYN-ACK, recv, send, close --
 * used by the in-guest httpd. What was missing was the SOCKET surface over it.
 * One connection at a time, which is what that primitive supports and what an
 * OAuth callback needs; a second accept simply waits.
 *
 * fd type 15 = a listening AF_INET socket (off = the bound port)
 * fd type 16 = a connection returned by accept() on one
 */
static uint16_t g_inet_next_ephemeral = 45000;
static int inet_port_taken(uint16_t port) {
    for (int i = 0; i < MAX_APPS; i++) {
        if (!apps[i].used) continue;
        for (int f = 0; f < APP_NFD; f++)
            if (apps[i].fd[f].used && (apps[i].fd[f].type == 15) &&
                (uint16_t)apps[i].fd[f].off == port) return 1;
    }
    return 0;
}
/* Record the local port. Port 0 means "choose one", which is what a program
 * that only needs *a* port asks for -- and it then has to be able to find out
 * WHICH, so the chosen port is stored where getsockname can read it. */
/* The local port recorded by bind(), for getsockname. */
long app_fd_port(int fd) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return 0;
    return a->fd[fd].off;
}
int app_inet_bind(int fd, uint16_t port) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    if (a->fd[fd].type != 10 && a->fd[fd].type != 9) return -1;
    if (port == 0) {
        for (int tries = 0; tries < 1000; tries++) {
            uint16_t p = g_inet_next_ephemeral++;
            if (g_inet_next_ephemeral > 60000) g_inet_next_ephemeral = 45000;
            if (!inet_port_taken(p)) { port = p; break; }
        }
        if (!port) return -1;
    } else if (inet_port_taken(port)) {
        return -2;                                   /* EADDRINUSE */
    }
    a->fd[fd].off = (long)port;                      /* where getsockname reads it */
    return (int)port;
}
/* Turn a bound socket into a listener. The TCP state machine itself lives in
 * net.c; this only records that this descriptor is the one accept() waits on. */
int app_inet_listen(int fd, int backlog) {
    (void)backlog;
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    if (a->fd[fd].type != 10) return -1;
    if (!a->fd[fd].off) {                            /* listen() without bind(): choose a port now */
        int p = app_inet_bind(fd, 0);
        if (p < 0) return -1;
    }
    if (a->fd[fd].obj >= 0) net_tcp_sock_close(a->fd[fd].obj);   /* it was a client TCB; it is a listener now */
    a->fd[fd].obj = -1;
    a->fd[fd].type = 15;
    return 0;
}
/* One non-blocking attempt at a passive open. Returns a new fd for the
 * connection, -11 (EAGAIN) if nobody is knocking, or -1 on a bad descriptor. */
int app_inet_accept(int fd) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 15) return -1;
    uint16_t port = (uint16_t)a->fd[fd].off;
    if (net_tcp_accept_open(port, 1) != 0) return APP_FD_EAGAIN;   /* ~10ms look, then EAGAIN */
    int nfd = -1;
    if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { nfd = i; break; }
    if (nfd < 0) { net_tcp_accept_close(); return -1; }
    a->fd[nfd] = (struct fdent){ 1, 16, 0, -1, {0}, (long)port, 0 };
    return nfd;
}

int app_socket(int domain, int type) {
    struct app *a = cur(); if (!a) return -1;
    /* SOCK_NONBLOCK (0x800) and SOCK_CLOEXEC (0x80000) ride in the type
     * argument on Linux -- libuv always passes both, so `type` arrives as
     * 0x80801 for SOCK_STREAM. Masking them off without RECORDING them is how
     * a socket ends up blocking despite the caller having asked for the
     * opposite. (M1965) */
    int nb = (type & 0x800) ? 1 : 0, coe = (type & 0x80000) ? 1 : 0;
    type &= 0xF;
    if (domain != 2 /*AF_INET*/ && domain != 1 /*AF_UNIX*/) return -1;
    if (type != 2 /*SOCK_DGRAM*/ && type != 1 /*SOCK_STREAM*/) return -1;
    int fd = -1;
    if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { fd = i; break; }   /* RLIMIT_NOFILE (M1547) */
    if (fd < 0) return -1;
    if (domain == 1) {
        /* AF_UNIX (M1965). unixsock.c has been a complete implementation since
         * M1169, but its endpoints were bare integers OUTSIDE the fd table --
         * so they could not be read(), written(), closed() or POLLED like
         * anything else, which is exactly what a program expects of a socket.
         * obj = -1 means created but neither bound nor connected yet; bind
         * records the path on the fdent, listen turns it into type 13. */
        a->fd[fd] = (struct fdent){ 1, 12, 0, -1, {0}, 0, 0, 0 };
        a->fd[fd].nonblock = (uint8_t)nb; a->fd[fd].cloexec = (uint8_t)coe;
        return fd;
    }
    if (type == 1) {                                       /* SOCK_STREAM: a TCP client socket (M1268) */
        int idx = net_tcp_sock_open(); if (idx < 0) return -1;
        a->fd[fd] = (struct fdent){ 1, 10, 0, idx, {0}, 0, 0 };  /* type=AF_INET stream, obj=TCB slot */
    } else {
        a->fd[fd] = (struct fdent){ 1, 9, 0, 0, {0}, 0, 0 };     /* type=AF_INET dgram, off=0 (unbound) */
    }
    a->fd[fd].nonblock = (uint8_t)nb; a->fd[fd].cloexec = (uint8_t)coe;
    return fd;
}
/* --- AF_UNIX over the fd table (M1965) -------------------------------------
 * Thin adapters: all the real work has existed in unixsock.c since M1169.
 * fd type 12 = a connected endpoint (obj = ep id), 13 = a listener
 * (obj = listener id). Linux splits naming across bind() and listen(), so
 * bind just records the path on the fdent (which already has a 256-byte path
 * field) and listen is what actually claims the name. */
int app_unix_bind(int fd, const char *path) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 12) return -1;
    int i = 0; for (; path[i] && i < (int)sizeof a->fd[fd].path - 1; i++) a->fd[fd].path[i] = path[i];
    a->fd[fd].path[i] = 0;
    return path[i] ? -1 : 0;                  /* refuse a truncated name rather than bind the wrong one */
}
int app_unix_listen(int fd) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 12) return -1;
    if (!a->fd[fd].path[0]) return -1;         /* listen() before bind() */
    int lid = unix_listen(a->fd[fd].path);
    if (lid < 0) return -1;
    a->fd[fd].type = 13; a->fd[fd].obj = lid;
    return 0;
}
int app_unix_accept(int fd) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 13) return -1;
    int ep = unix_accept_nb(a->fd[fd].obj);    /* never block: a server polls first */
    /* "No connection waiting" is EAGAIN, not a bad descriptor. libuv calls
     * accept in a loop until it gets EAGAIN; any other error makes it tear the
     * listener down. */
    if (ep < 0) return APP_FD_EAGAIN;
    int nf = -1;
    if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { nf = i; break; }
    if (nf < 0) { unix_close(ep); return -1; } /* no fd for it: don't leak the endpoint */
    a->fd[nf] = (struct fdent){ 1, 12, 0, ep, {0}, 0, 0 };
    a->fd[nf].nonblock = a->fd[fd].nonblock;   /* accept4 flags override this at the ABI layer */
    return nf;
}
int app_unix_connect(int fd, const char *path) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 12) return -1;
    int ep = unix_connect(path);
    if (ep < 0) return -1;
    a->fd[fd].obj = ep;
    return 0;
}
/* SCM_RIGHTS over a SOCKET FD (M1977).
 *
 * app_scm_send/app_scm_recv have existed since M1265 but take an ENDPOINT id,
 * the pre-fd-table handle. Everything that speaks Wayland passes descriptors
 * this way -- a client hands the compositor a memfd holding its pixels -- so
 * the ABI layer needs a version keyed on the socket fd it actually has. */
int app_unix_send_fd(int sockfd, int fd) {
    struct app *a = cur(); if (!a) return -1;
    if (sockfd < 0 || sockfd >= APP_NFD || !a->fd[sockfd].used || a->fd[sockfd].type != 12) return -1;
    if (a->fd[sockfd].obj < 0) return -1;
    return app_scm_send(a->fd[sockfd].obj, fd);
}
int app_unix_recv_fd(int sockfd) {
    struct app *a = cur(); if (!a) return -1;
    if (sockfd < 0 || sockfd >= APP_NFD || !a->fd[sockfd].used || a->fd[sockfd].type != 12) return -1;
    if (a->fd[sockfd].obj < 0) return -1;
    return app_scm_recv(a->fd[sockfd].obj);
}

/* Are there MORE descriptors queued than the receiver took? For MSG_CTRUNC. */
int app_unix_peek_fd(int sockfd) {
    struct app *a = cur(); if (!a) return -1;
    if (sockfd < 0 || sockfd >= APP_NFD || !a->fd[sockfd].used || a->fd[sockfd].type != 12) return -1;
    if (a->fd[sockfd].obj < 0) return -1;
    return app_scm_peek(a->fd[sockfd].obj);
}

/* shutdown(2) on an AF_UNIX fd (M1965): end this side's write direction so the
 * peer reads EOF. */
int app_unix_shutdown(int fd, int how) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used || a->fd[fd].type != 12) return -1;
    if (a->fd[fd].obj < 0) return -1;
    return unix_shutdown(a->fd[fd].obj, how);
}
/* socketpair(2): two already-connected endpoints, each in its own fd. */
int app_unix_socketpair(int *out) {
    struct app *a = cur(); if (!a || !out) return -1;
    int x = -1, y = -1;
    if (unix_socketpair(&x, &y) != 0) return -1;
    int f0 = -1, f1 = -1;
    if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { f0 = i; break; }
    if (f0 >= 0) { a->fd[f0] = (struct fdent){ 1, 12, 0, x, {0}, 0, 0 }; }
    if (!app_fd_over_limit(a)) for (int i = APP_FD_FIRST; i < APP_NFD; i++) if (!a->fd[i].used) { f1 = i; break; }
    if (f0 < 0 || f1 < 0) {                    /* unwind: never hand back half a pair */
        if (f0 >= 0) { a->fd[f0].used = 0; }
        unix_close(x); unix_close(y);
        return -1;
    }
    a->fd[f1] = (struct fdent){ 1, 12, 0, y, {0}, 0, 0 };
    out[0] = f0; out[1] = f1;
    return 0;
}

/* getsockname(2) for an AF_INET fd (M1967): the local address a packet from
 * this socket would carry. Single-homed, so the IP is always the interface's;
 * only the port varies, and it is 0 until something assigns one. */
int app_sock_localaddr(int fd, uint8_t ip[4], uint16_t *port) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    const uint8_t *me = net_ip();
    for (int i = 0; i < 4; i++) ip[i] = me[i];
    if (a->fd[fd].type == 9) { *port = (uint16_t)a->fd[fd].off; return 0; }
    if (a->fd[fd].type == 10) {
        uint8_t na[6];
        if (net_tcp_sock_getname(a->fd[fd].obj, na) == 0) {
            for (int i = 0; i < 4; i++) ip[i] = na[i];
            *port = (uint16_t)(na[4] | (na[5] << 8));
            return 0;
        }
        *port = 0; return 0;
    }
    return -1;
}

/* getpeername(2) for an AF_INET fd (M1986): the REMOTE address. The fd table
 * already records it -- peer_ip/peer_port are set by connect and by the first
 * datagram received -- so this only has to report it. Reporting AF_UNIX for an
 * AF_INET socket is what made glibc abort in M1967; the same trap applies
 * here. */
int app_sock_peeraddr(int fd, uint8_t ip[4], uint16_t *port) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    if (a->fd[fd].type != 9 && a->fd[fd].type != 10) return -1;
    for (int i = 0; i < 4; i++) ip[i] = a->fd[fd].peer_ip[i];
    *port = a->fd[fd].peer_port;
    return 0;
}

/* connect(2) for a TCP socket fd (M1268): active-open to ip:port.
 * For a DATAGRAM socket connect() sets a default peer, it does not handshake --
 * subsequent send()/recv() behave like sendto()/recvfrom() to that address.
 * That is the shape glibc's resolver uses. (M1967) */
int app_connect(int fd, const uint8_t ip[4], int port) {
    struct app *a = cur(); if (!a) return -1;
    if (fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -1;
    if (a->fd[fd].type == 9) {
        for (int i = 0; i < 4; i++) a->fd[fd].peer_ip[i] = ip[i];
        a->fd[fd].peer_port = (uint16_t)port;
        if (a->fd[fd].off == 0) {                 /* bind a source port now, so recv has one to match */
            a->fd[fd].off = g_ephemeral++;
            if (g_ephemeral == 0) g_ephemeral = 49152;
        }
        return 0;
    }
    if (a->fd[fd].type != 10) return -1;
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
    /* O_NONBLOCK means 0 ms: take a queued datagram or say EAGAIN. An event
     * loop polls first and then reads, and a 2-second wait inside the read
     * would stall every other socket it owns. (M1967) */
    int tmo = a->fd[fd].nonblock ? 0 : 2000;
    long n = net_udp_recv((uint16_t)a->fd[fd].off, buf, max, srcip, srcport, tmo);
    if (n < 0 && a->fd[fd].nonblock) return APP_FD_EAGAIN;
    return n;
}
/* fd hygiene (M1218): fcntl(F_GETFD/F_SETFD/F_DUPFD/F_DUPFD_CLOEXEC), dup3,
 * close_range — over the per-fd FD_CLOEXEC bit (honored by app_exec above; fork
 * copies the whole fdent so it survives a fork, as POSIX requires). */
long app_fcntl(int fd, int cmd, long arg) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD) return -1;
    /* fds 0/1/2 are the CONSOLE while untouched, and have no fd-table entry --
     * so every fcntl on them failed with EBADF, where Linux answers happily.
     * `fcntl(0, F_DUPFD_CLOEXEC, 1023)` is a real thing real programs do at
     * startup. Give them the answers a tty would, and materialise a genuine
     * descriptor (type 14) when one is actually asked for. (M1972) */
    if (!a->fd[fd].used) {
        if (fd > 2) return -1;                       /* genuinely not open */
        if (cmd == F_GETFD) return 0;                /* no FD_CLOEXEC on stdio */
        if (cmd == F_SETFD) return 0;
        if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
            int lo = (int)arg; if (lo < APP_FD_FIRST) lo = APP_FD_FIRST;
            if (lo >= APP_NFD) return -1;
            int nf = -1; for (int i = lo; i < APP_NFD; i++) if (!a->fd[i].used) { nf = i; break; }
            if (nf < 0) return -1;
            a->fd[nf] = (struct fdent){ 1, 14, 1, fd, {0}, 0, 0 };   /* obj = which stdio fd it aliases */
            a->fd[nf].cloexec = (cmd == F_DUPFD_CLOEXEC) ? 1 : 0;
            return nf;
        }
        return -1;
    }
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

/* The path behind ANY fd that has one -- a FILE fd or a DIRECTORY fd. The
 * *at() syscalls need this to resolve a relative path against the directory a
 * dirfd names, which is how every real directory walker reads a tree. The
 * type-2-only app_fd_path above cannot answer for a directory. (M2032) */
const char *app_fd_path_of(int fd) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return 0;
    /* ONLY fd TYPES WHOSE `path` REALLY IS A FILESYSTEM PATH (M2038). An
     * AF_UNIX socket (type 12) stores its bind() NAME in this same field, so
     * answering for it would hand *at() a socket name as a base directory and
     * resolve every relative path under it. Nothing does that today -- as, ld,
     * cc1 and make never pass a socket as a dirfd -- which is exactly what
     * makes it worth closing now rather than after something does. */
    if (a->fd[fd].type != 2) return 0;            /* 2 is the only type whose `path` is a real path */
    return a->fd[fd].path[0] ? a->fd[fd].path : 0;
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
#define NEPOLL 32                /* concurrent epoll instances; Node makes one per loop, plus libuv internals (M1965) */
/* M1965: 32 watched fds per epoll instance was sized for the in-tree shell
 * test. A Node event loop registers every socket, pipe, timerfd and signalfd
 * it owns in ONE instance, so 32 is an arbitrary ceiling on how much a program
 * may do at once -- and hitting it looked like a random socket failure. */
#define EP_MAX 256
static struct epollobj { int used, refs, n; struct { int fd, events, last_ready, disarmed; unsigned long data; } items[EP_MAX]; } epolls[NEPOLL];
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
/* Returns 0, or a NEGATIVE LINUX ERRNO (M1965).
 *
 * It used to return a bare -1 for every failure, and that is not a detail an
 * epoll caller can shrug off: libuv ADDs a descriptor it may already be
 * watching and treats EEXIST as "fine, MOD it instead" -- while any OTHER
 * error is a hard abort(). Node died on
 *   uv__io_poll: Assertion `errno == EEXIST' failed
 * because we answered EINVAL. Callers of the native path only ever test
 * != 0, so widening the contract costs them nothing. */
int app_epoll_ctl(int epfd, int op, int fd, unsigned events, unsigned long data) {
    struct app *a = cur();
    if (!a || epfd < 0 || epfd >= APP_NFD || !a->fd[epfd].used || a->fd[epfd].type != 6) return -9;   /* EBADF */
    if (fd < 0 || fd >= APP_NFD) return -9;                                                           /* EBADF */
    struct epollobj *e = &epolls[a->fd[epfd].obj];
    if (op == EPOLL_CTL_ADD) {
        for (int i = 0; i < e->n; i++) if (e->items[i].fd == fd) return -17;   /* EEXIST: already registered */
        if (e->n >= EP_MAX) return -28;                                        /* ENOSPC: instance full */
        e->items[e->n].fd = fd; e->items[e->n].events = (int)events; e->items[e->n].data = data;
        e->items[e->n].last_ready = 0;   /* M1545: no edge reported yet */
        e->items[e->n].disarmed = 0;     /* EPOLLONESHOT has not fired yet (M2016) */
        e->n++;
        a->fd[fd].epwatch = 1;           /* this descriptor is worth a drain check (M2059) */
        return 0;
    }
    if (op == EPOLL_CTL_MOD) {
        for (int i = 0; i < e->n; i++) if (e->items[i].fd == fd) {
            e->items[i].events = (int)events; e->items[i].data = data;
            e->items[i].last_ready = 0;   /* M1545: a changed interest set re-arms the edge, same spirit as a fresh ADD */
            e->items[i].disarmed = 0;     /* ...and re-arms EPOLLONESHOT, which is what MOD is FOR (M2016) */
            a->fd[fd].epwatch = 1;
            return 0;
        }
        return -2;                                                             /* ENOENT: not registered */
    }
    if (op == EPOLL_CTL_DEL) {
        for (int i = 0; i < e->n; i++) if (e->items[i].fd == fd) { e->items[i] = e->items[--e->n]; return 0; }
        return -2;                                                             /* ENOENT */
    }
    return -22;                                                                /* EINVAL: unknown op */
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
/* The registered set of an epoll instance, for the poll-stall diagnostic: a
 * program blocked in epoll_wait is waiting on fds it registered at some earlier
 * point, and nothing else in the log says which ones. (M1998) */
/* The same report for a process that is NOT the caller (M2016): the quiet-
 * socket watchdog runs in the window manager's context, and "which fds is that
 * program waiting on" is exactly the question it needs to answer. */
void app_epoll_dump_of(app_t *ap, int epfd) {
    struct app *a = (struct app *)ap;
    if (!a || epfd < 0 || epfd >= APP_NFD || !a->fd[epfd].used || a->fd[epfd].type != 6) return;
    struct epollobj *e = &epolls[a->fd[epfd].obj];
    for (int i = 0; i < e->n; i++)
        kprintf("[poll]   epfd %d: fd %d type %d want %x -> %x%s%s%s\n", epfd, e->items[i].fd,
                a->fd[e->items[i].fd].used ? a->fd[e->items[i].fd].type : -1,
                (unsigned)e->items[i].events,
                app_fd_ready(ap, e->items[i].fd,
                             e->items[i].events & ~(int)(EPOLLET | EPOLLONESHOT)),
                e->items[i].last_ready ? " (edge reported)" : "",
                (e->items[i].events & EPOLLONESHOT) ? " oneshot" : "",
                e->items[i].disarmed ? " DISARMED" : "");
}
void app_epoll_dump(int epfd) {
    struct app *a = cur();
    if (!a || epfd < 0 || epfd >= APP_NFD || !a->fd[epfd].used || a->fd[epfd].type != 6) {
        kprintf("[poll]   (fd %d is not an epoll instance)\n", epfd);
        return;
    }
    struct epollobj *e = &epolls[a->fd[epfd].obj];
    for (int i = 0; i < e->n; i++)
        kprintf("[poll]   fd %d type %d want %x -> %x%s%s%s\n", e->items[i].fd,
                app_fd_type(e->items[i].fd), (unsigned)e->items[i].events,
                app_fd_ready((app_t *)a, e->items[i].fd,
                             e->items[i].events & ~(int)(EPOLLET | EPOLLONESHOT)),
                e->items[i].last_ready ? " (edge already reported)" : "",
                (e->items[i].events & EPOLLONESHOT) ? " oneshot" : "",
                e->items[i].disarmed ? " DISARMED" : "");
}

int app_epoll_check(int epfd, struct epoll_event *out, int maxevents) {
    struct app *a = cur();
    if (!a || epfd < 0 || epfd >= APP_NFD || !a->fd[epfd].used || a->fd[epfd].type != 6) return -1;
    struct epollobj *e = &epolls[a->fd[epfd].obj];
    int k = 0;
    for (int i = 0; i < e->n && k < maxevents; i++) {
        /* EPOLLONESHOT: already delivered, and not re-armed. Linux keeps the
         * registration but stops reporting until EPOLL_CTL_MOD sets a new
         * event mask; `disarmed` is exactly that state. (M2016) */
        if (e->items[i].disarmed) continue;
        int want = e->items[i].events & ~(int)(EPOLLET | EPOLLONESHOT);
        int re = app_fd_ready((app_t *)a, e->items[i].fd, want);
        int fire = (re > 0) && (!(e->items[i].events & EPOLLET) || !e->items[i].last_ready);
        e->items[i].last_ready = (re > 0);
        if (fire) {
            out[k].events = (unsigned)re; out[k].data = e->items[i].data; k++;
            if (e->items[i].events & EPOLLONESHOT) e->items[i].disarmed = 1;
        }
    }
    return k;
}

/* AN EDGE THAT HAPPENS BETWEEN TWO POLLS (M2059).
 *
 * THE BUG. Our epoll is a POLLING loop: app_epoll_check asks app_fd_ready for
 * each item and, for an EPOLLET item, reports it only when `last_ready` was 0.
 * `last_ready` was updated nowhere else -- so the only way an item could ever
 * become eligible again was for a check to personally OBSERVE it not-ready.
 *
 * A wake-up eventfd is never observed in that state. The sequence is:
 *
 *   1. epoll_wait   -> eventfd counter is 1, report it, last_ready = 1
 *   2. the woken thread read()s the eventfd    -> counter 0   (NOT OBSERVED)
 *   3. another thread write()s the eventfd     -> counter 1
 *   4. epoll_wait   -> ready == last_ready == 1, SUPPRESSED
 *
 * and step 4 repeats forever. Linux cannot lose this: readiness there is
 * PUSHED -- the eventfd's own wake path puts the file on the instance's ready
 * list, so the 0 -> 1 transition in step 3 is an event whether or not anybody
 * was looking. Sampling can only ever see the state, never the transition.
 *
 * WHAT IT COST. This is the Claude Code hang. Its dump reads:
 *
 *   [poll] epfd 3: fd 4 type 5 want 80000001 -> 1 (edge reported)
 *   t25 441(3, 548129800e0, 400) = <still blocked in this call>
 *
 * thread 25 parked in epoll_pwait2 on epfd 3, while fd 4 -- the eventfd
 * registered EPOLLIN|EPOLLET on that very instance -- sits READY and
 * suppressed. Every core idle, no fault in minutes, nothing wrong with the
 * network: an HTTP/2 POST to api.anthropic.com returns 401 from Node in nine
 * seconds on this same kernel. The loop simply never woke again.
 *
 * THE FIX. Close the sampling gap at the only other moment readiness changes
 * for a reason we know about: when the process itself consumes it. After a
 * read or a write, re-ask app_fd_ready; if the fd has gone not-ready, record
 * that as the transition the poll loop missed. The next arrival is then a
 * fresh edge.
 *
 * Deliberately NOT level-triggered-by-accident: last_ready is cleared only
 * when the fd really is not ready, so an item that stays ready keeps its
 * reported edge and an EPOLLET loop cannot spin (which is the M2016 defect).
 *
 * The remaining gap is a readiness change caused by something OUTSIDE this
 * process -- a peer writing into a pipe, a segment arriving -- between two
 * checks. That one is benign for EPOLLET: the fd is still ready at the next
 * check, so the level is seen even though the edge was not. The pathological
 * case is exactly the one above, where the process's own drain hid the dip. */
/* THE OTHER HALF OF THE EDGE (M2062).
 *
 * M2059 closed the CONSUMER side: a drain that no poll observed. This is the
 * PRODUCER side, and it is a different fact about Linux rather than the same
 * one restated.
 *
 * On Linux an epoll item becomes ready because the file's own wake path says
 * so. `eventfd_write` calls `wake_up_locked_poll`, which runs
 * `ep_poll_callback`, which puts the item on the instance's ready list -- and
 * it does that on EVERY write, whether or not the counter was already
 * non-zero. So for an eventfd, edge-triggered does not mean "0 -> non-zero",
 * it means "each write". Sampling readiness cannot express that: the state is
 * "non-zero" before and after, and an implementation that compares states sees
 * nothing happen.
 *
 * It matters because this is the wake-up primitive every thread pool and event
 * loop is built on. A producer posts work with a write and a consumer drains
 * with a read; if a consumer is told once and then handles the batch without
 * reading the counter to zero, the NEXT post has to wake it, and here it did
 * not. Claude Code's dump is exactly that picture -- a thread parked in
 * epoll_pwait2 on an instance whose waker eventfd is ready and latched.
 *
 * So treat a post as an edge, which is what Linux does. This cannot spin: it
 * requires an actual write each time, and a write is work the producer chose
 * to do. */
static void epoll_note_post(struct app *a, int fd) {
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].epwatch) return;
    for (int j = 0; j < APP_NFD; j++) {
        if (!a->fd[j].used || a->fd[j].type != 6) continue;
        struct epollobj *e = &epolls[a->fd[j].obj];
        for (int i = 0; i < e->n; i++) {
            if (e->items[i].fd != fd || !e->items[i].last_ready) continue;
            if (!(e->items[i].events & EPOLLET)) continue;   /* level-triggered already re-reports */
            int want = e->items[i].events & ~(int)(EPOLLET | EPOLLONESHOT);
            if (!app_fd_ready((app_t *)a, fd, want)) continue;
            /* This is the instant a wake-up WOULD have been lost. Say so once:
             * it names the posting thread and the epoll instance, at the moment
             * the hang used to be created rather than minutes later. */
            static int told;
            if (!told) {
                told = 1;
                kprintf("[poll] a post to fd %d found epfd %d's edge for it ALREADY REPORTED "
                        "(tid %d) -- re-arming; before M2062 this wake-up was dropped\n",
                        fd, j, task_current_id());
            }
            e->items[i].last_ready = 0;                      /* a fresh post is a fresh edge */
        }
    }
}
static void epoll_note_drain(struct app *a, int fd) {
    if (!a || fd < 0 || fd >= APP_NFD) return;
    /* EVERY read and write reaches here, so the uninteresting case has to be
     * free: APP_NFD is 1024, and scanning the whole table per transfer would
     * be a real slowdown for a process (a compiler, a build) that never
     * epolls anything.
     *
     * `epwatch` is set when epoll_ctl registers this descriptor and is never
     * cleared. It lives on the FD ENTRY on purpose: fork and dup2 copy fdents
     * wholesale, so the flag is inherited automatically -- a counter on
     * `struct app` would have needed a matching update in app_fd_fork,
     * app_dup2, app_fcntl's F_DUPFD and exec, and forgetting one would make
     * this hook silently stop working in a child. Monotonic also means the
     * only possible error is scanning when we need not, which costs time and
     * cannot lose an edge. */
    if (!a->fd[fd].epwatch) return;
    for (int j = 0; j < APP_NFD; j++) {
        /* Only epoll instances THIS process owns: items hold fd NUMBERS, and
         * fd 4 means something different in another address space. */
        if (!a->fd[j].used || a->fd[j].type != 6) continue;
        struct epollobj *e = &epolls[a->fd[j].obj];
        for (int i = 0; i < e->n; i++) {
            if (e->items[i].fd != fd) continue;
            if (!e->items[i].last_ready) continue;              /* no edge outstanding */
            if (!(e->items[i].events & EPOLLET)) continue;      /* level-triggered: last_ready is not a gate */
            int want = e->items[i].events & ~(int)(EPOLLET | EPOLLONESHOT);
            if (!app_fd_ready((app_t *)a, fd, want)) e->items[i].last_ready = 0;
        }
    }
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
    } else if (a->fd[fd].type == 12) {                     /* AF_UNIX endpoint (M1965) */
        /* This is the whole point of putting AF_UNIX in the fd table: an event
         * loop has to be able to POLL a socket, and POLLNVAL made that
         * impossible. unix_readable is the same predicate unix_wait_any uses,
         * exported so it can be asked without blocking. */
        if ((events & POLLIN) && a->fd[fd].obj >= 0 && unix_readable(a->fd[fd].obj)) re |= POLLIN;
        if (events & POLLOUT) re |= POLLOUT;               /* the ring drains quickly; a blocked send is brief */
    } else if (a->fd[fd].type == 13) {                     /* AF_UNIX listener (M1965) */
        /* POLLIN on a listening socket means "accept() would not block", which
         * is exactly what a server's event loop waits for. */
        if ((events & POLLIN) && unix_pending(a->fd[fd].obj)) re |= POLLIN;
    } else if (a->fd[fd].type == 15) {                     /* AF_INET listener (M2020) */
        /* "Would accept() block?" cannot be answered without looking at the
         * wire, and looking means completing the handshake -- so a positive
         * answer here has already done the passive open and accept() just
         * hands the descriptor over. That is why accept() checks for an
         * already-open connection before trying again. */
        if ((events & POLLIN) && net_tcp_accept_ready((uint16_t)a->fd[fd].off)) re |= POLLIN;
    } else if (a->fd[fd].type == 16) {                     /* accepted AF_INET connection (M2020) */
        if ((events & POLLIN) && net_tcp_accept_readable()) re |= POLLIN;
        if (events & POLLOUT) re |= POLLOUT;               /* send goes straight out */
    } else if (a->fd[fd].type == 14) {                     /* console alias (M2004) */
        /* READABLE ONLY WHEN A KEY IS ACTUALLY WAITING.
         *
         * This used to answer "always readable", which was harmless while the
         * only read was an immediate EOF. Once the console became a real
         * terminal it became a deadlock: an event loop polls stdin, is told it
         * is ready, calls read -- and the read blocks until somebody types.
         * The loop is now stuck inside a read it was promised would not block,
         * so nothing else it was supposed to do can happen, including drawing
         * the interface that would tell you to type. Claude Code sat on a
         * blank window having written not one byte. */
        struct app *src = a->out_to ? a->out_to : a;
        if ((events & POLLIN) && iq_has(src)) re |= POLLIN;
        if (events & POLLOUT) re |= POLLOUT;
    } else if (a->fd[fd].type == 9) {                      /* AF_INET datagram socket (M1967) */
        /* An unbound socket has no port to receive on, so it is never readable;
         * it is always writable (sendto binds one on first use). */
        if ((events & POLLIN) && a->fd[fd].off != 0 && net_udp_readable((uint16_t)a->fd[fd].off)) re |= POLLIN;
        if (events & POLLOUT) re |= POLLOUT;
    } else if (a->fd[fd].type == 10) {                     /* AF_INET stream socket (M1967) */
        /* The last POLLNVAL. tcp_read pulls frames straight off the NIC, so
         * until M1967 there was no way to answer this question without
         * CONSUMING the answer -- and an event loop asks it about every socket
         * it owns before reading any of them. net_tcp_sock_readable pumps the
         * NIC into the socket's own receive ring and reports on the ring, so
         * asking is now free of side effects the caller can observe. */
        if ((events & POLLIN)  && net_tcp_sock_readable(a->fd[fd].obj)) re |= POLLIN;
        if ((events & POLLOUT) && net_tcp_sock_writable(a->fd[fd].obj)) re |= POLLOUT;
    } else {
        return POLLNVAL;
    }
    return re;
}
/* FIONREAD: HOW MANY BYTES CAN BE READ WITHOUT BLOCKING (M2086).
 *
 * The bug this exists to fix: the Linux ioctl handler computes "is this fd a
 * terminal", and answers ENOTTY to everything that is not. FIONREAD is not a
 * terminal ioctl -- it is valid on sockets, pipes, ptys and regular files, and
 * on Linux it is one of the few ioctls a portable program may assume. So
 * Firefox's IPC channel asked how many bytes were waiting on its socket, was
 * told "that descriptor is not a terminal", and aborted -- while 142 bytes sat
 * in the ring, which the very next recvfrom on the same fd collected.
 *
 * EVERY ANSWER HERE WAS CHECKED AGAINST A REAL LINUX KERNEL, and three of my
 * first guesses were wrong in the way that matters -- a plausible number where
 * Linux fails, which is this project's dominant bug class:
 *
 *   - a pipe's WRITE end reports the ring contents too, not 0. FIONREAD on a
 *     pipe is a property of the pipe, not of the end you hold.
 *   - an eventfd, a timerfd, a signalfd, a DIRECTORY fd and a character device
 *     all answer ENOTTY. Reporting 8 for an eventfd (one u64 waiting) is a
 *     tidy-looking fabrication.
 *   - a LISTENING socket answers EINVAL, not 0. There is no byte stream to
 *     count, and "0" would tell a caller the stream is merely drained.
 *
 * The other rule followed throughout: a pending EOF or hangup is READINESS,
 * not a byte count. app_fd_ready must report it (a poller learns of a hangup
 * no other way); a count must not, because a caller that sizes a read from
 * this number and then reads that many bytes would block for ever on the
 * phantom byte. Every ...nread primitive therefore reports 0, not 1, at EOF.
 *
 * Returns 0 with *out set, or APP_NREAD_ENOTTY / APP_NREAD_EINVAL -- never a
 * plausible zero, which a caller cannot tell from "drained". The ENOTTY types
 * log themselves once each, so "we cannot answer this" is not invisible. */
int app_fd_nread(int fd, long *out) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used || !out) return APP_NREAD_ENOTTY;
    long n = -1;
    int ty = a->fd[fd].type;
    switch (ty) {
    case 1: {                                               /* pipe: either end, same answer */
        int q = -1;
        pipe_state(a->fd[fd].obj, 0, 0, &q, 0);
        n = q;
        break;
    }
    case 2: {                                               /* regular file: size - offset */
        struct statx st;
        if (vfs_stat(a->fd[fd].path, &st) != 0) return APP_NREAD_ENOTTY;
        if ((st.stx_mode & 0xF000) == 0x4000) return APP_NREAD_ENOTTY;   /* a DIRECTORY is not a byte stream */
        long sz = (long)st.stx_size, off = a->fd[fd].off;
        n = sz > off ? sz - off : 0;
        break;
    }
    case 3: {                                               /* memfd: a shmem file, same rule */
        long sz = (long)memfds[a->fd[fd].obj].size, off = a->fd[fd].off;
        n = sz > off ? sz - off : 0;
        break;
    }
    case 8:                                                 /* inotify: 48 bytes per queued event */
        n = inotify_nread(a->fd[fd].obj);
        break;
    case 9:                                                 /* AF_INET datagram: the NEXT datagram's length */
        n = a->fd[fd].off ? net_udp_nread((uint16_t)a->fd[fd].off) : 0;
        break;
    case 10:                                                /* AF_INET stream */
        n = net_tcp_sock_nread(a->fd[fd].obj);
        if (n < 0) return APP_NREAD_EINVAL;                 /* a socket in no state to have a stream */
        break;
    case 11:                                                /* pty */
        n = pty_nread(a->fd[fd].obj);
        break;
    case 12:                                                /* AF_UNIX endpoint */
        n = unix_nread(a->fd[fd].obj);
        if (n < 0) return APP_NREAD_EINVAL;
        break;
    case 13: case 15:                                       /* listeners: no byte stream exists yet */
        return APP_NREAD_EINVAL;
    case 14: {                                              /* console alias */
        struct app *src = a->out_to ? a->out_to : a;
        n = iq_count(src);
        break;
    }
    default: {
        static uint32_t moaned;
        if (ty < 32 && !(moaned & (1u << ty))) {
            moaned |= (1u << ty);
            kprintf("[linuxabi] FIONREAD: fd type %d keeps no byte count; answering ENOTTY\n", ty);
        }
        return APP_NREAD_ENOTTY;
    }
    }
    if (n < 0) return APP_NREAD_ENOTTY;
    *out = n;
    return 0;
}

/* ======================= SOCKET OPTIONS (M2088) =========================
 *
 * WHAT WAS HERE: getsockopt wrote a 4-byte ZERO into the caller's buffer and
 * returned success, for every option, at every level, without reading optname
 * at all. The comment explained the one case it was written for -- SO_ERROR,
 * where 0 means "the connection is fine" -- and that case is right. Every
 * other option got the same answer.
 *
 * WHAT IT COST: Firefox's IPC I/O thread creates its channel with
 * socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK) and then asks
 * how big the send buffer is. It was told ZERO BYTES, and aborted:
 *
 *     t219 53(1, 80801, 0) = 0     socketpair(AF_UNIX, ...|CLOEXEC|NONBLOCK)
 *     t219 55(3d, 1, 7)    = 0     getsockopt(fd 61, SOL_SOCKET, SO_SNDBUF)
 *     t219 39(...)         = df    getpid()  -- formatting the message
 *     t219 1(2, ..., 78)   = 78    "###!!! ABORT: ... ipc_channel_posix.cc:128"
 *
 * A socket you cannot send one byte through is not a socket, and it is the
 * project's dominant bug shape in one line: a plausible wrong value where the
 * honest answers were either the real number or ENOPROTOOPT.
 *
 * EVERY VALUE AND EVERY ERRNO BELOW WAS MEASURED ON A REAL LINUX KERNEL, and
 * three of them are not what I would have written: setting SO_SNDBUF makes a
 * later get report DOUBLE what you asked for, an unknown option is
 * ENOPROTOOPT (92) rather than EINVAL, and any of these on a non-socket fd is
 * ENOTSOCK (88) rather than ENOTTY.
 *
 * The sizes reported are OURS, not Linux's 212992 -- our AF_UNIX ring really
 * is 16 KiB per direction, and a program that sizes a write from this number
 * must get the number that is there. */
#define SOCKF_REUSEADDR  (1u << 0)
#define SOCKF_KEEPALIVE  (1u << 1)
#define SOCKF_BROADCAST  (1u << 2)
#define SOCKF_PASSCRED   (1u << 3)
#define SOCKF_NODELAY    (1u << 4)
#define SOCKF_OOBINLINE  (1u << 5)
#define SOCKF_DONTROUTE  (1u << 6)
#define SOCKF_REUSEPORT  (1u << 7)

/* Is this descriptor a socket at all, and of what shape? */
static int fd_is_sock(int ty) {
    return ty == 9 || ty == 10 || ty == 12 || ty == 13 || ty == 15 || ty == 16;
}
static int fd_sock_type(int ty)   { return ty == 9 ? 2 /*SOCK_DGRAM*/ : 1 /*SOCK_STREAM*/; }
static int fd_sock_domain(int ty) { return (ty == 12 || ty == 13) ? 1 /*AF_UNIX*/ : 2 /*AF_INET*/; }
static int fd_sock_listening(int ty) { return ty == 13 || ty == 15; }
/* The capacity that is really behind this descriptor, per direction. */
static int fd_sock_capacity(int ty) {
    if (ty == 12 || ty == 13) return unix_ring_bytes();
    if (ty == 10 || ty == 15 || ty == 16) return net_tcp_sock_bufbytes();
    return 8192;                                   /* AF_INET datagram: one queued datagram */
}

/* Which flag bit an option name maps to, or 0 if it is not a simple boolean. */
static uint32_t sockopt_flagbit(int opt) {
    switch (opt) {
    case 2:  return SOCKF_REUSEADDR;
    case 5:  return SOCKF_DONTROUTE;
    case 6:  return SOCKF_BROADCAST;
    case 9:  return SOCKF_KEEPALIVE;
    case 10: return SOCKF_OOBINLINE;
    case 15: return SOCKF_REUSEPORT;
    case 16: return SOCKF_PASSCRED;
    default: return 0;
    }
}

/* getsockopt(2). Returns the number of bytes written to `out`, or a negative
 * Linux errno. `max` is what the caller said it had room for. */
int app_sock_getopt(int fd, int level, int opt, void *out, int max) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -9;    /* EBADF */
    int ty = a->fd[fd].type;
    if (!fd_is_sock(ty)) return -88;                                   /* ENOTSOCK */
    if (!out || max < 4) return -14;                                   /* EFAULT */
    int32_t v;
    if (level == 6 /*SOL_TCP*/) {
        if (opt == 1 /*TCP_NODELAY*/) { v = (a->fd[fd].sockflags & SOCKF_NODELAY) ? 1 : 0; goto give4; }
        return -92;                                                    /* ENOPROTOOPT */
    }
    if (level != 1 /*SOL_SOCKET*/) return -92;
    switch (opt) {
    case 3:  v = fd_sock_type(ty); break;                              /* SO_TYPE */
    case 4:  v = 0; break;                                             /* SO_ERROR: no pending error */
    case 7:  v = a->fd[fd].sndbuf ? a->fd[fd].sndbuf : fd_sock_capacity(ty); break;   /* SO_SNDBUF */
    case 8:  v = a->fd[fd].rcvbuf ? a->fd[fd].rcvbuf : fd_sock_capacity(ty); break;   /* SO_RCVBUF */
    case 17: {                                                         /* SO_PEERCRED: struct ucred */
        if (max < 12) return -14;
        int pid = (ty == 12) ? unix_peer_pid(a->fd[fd].obj) : 0;
        if (pid < 0) pid = 0;
        int32_t *u = (int32_t *)out;
        u[0] = pid; u[1] = 0; u[2] = 0;                                /* pid, uid 0, gid 0: single-user */
        return 12;
    }
    case 18: case 19: v = 1; break;                                    /* SO_RCVLOWAT / SO_SNDLOWAT */
    case 20: case 21: {                                                /* SO_RCVTIMEO / SO_SNDTIMEO: struct timeval */
        if (max < 16) return -14;
        int64_t *t = (int64_t *)out;
        t[0] = 0; t[1] = 0;                                            /* no timeout set */
        return 16;
    }
    case 13: {                                                         /* SO_LINGER: struct linger */
        if (max < 8) return -14;
        int32_t *l = (int32_t *)out;
        l[0] = 0; l[1] = 0;
        return 8;
    }
    case 30: v = fd_sock_listening(ty) ? 1 : 0; break;                 /* SO_ACCEPTCONN */
    case 38: v = 0; break;                                             /* SO_PROTOCOL */
    case 39: v = fd_sock_domain(ty); break;                            /* SO_DOMAIN */
    default: {
        uint32_t bit = sockopt_flagbit(opt);
        if (!bit) {
            /* UNKNOWN MEANS UNKNOWN. This is the line that used to answer 0.
             * Named once per option so the next program to want one says so
             * instead of silently believing a zero. */
            static uint32_t moaned[8];
            if (opt >= 0 && opt < 256 && !(moaned[opt >> 5] & (1u << (opt & 31)))) {
                moaned[opt >> 5] |= 1u << (opt & 31);
                kprintf("[sock] getsockopt(level %d, option %d) is not implemented -- "
                        "answering ENOPROTOOPT rather than 0\n", level, opt);
            }
            return -92;                                                /* ENOPROTOOPT */
        }
        v = (a->fd[fd].sockflags & bit) ? 1 : 0;
        break;
    }
    }
give4:
    *(int32_t *)out = v;
    return 4;
}

/* setsockopt(2). 0, or a negative Linux errno. */
int app_sock_setopt(int fd, int level, int opt, const void *in, int len) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) return -9;    /* EBADF */
    int ty = a->fd[fd].type;
    if (!fd_is_sock(ty)) return -88;                                   /* ENOTSOCK */
    int32_t v = 0;
    if (in && len >= 4) v = *(const int32_t *)in;
    if (level == 6 /*SOL_TCP*/) {
        if (opt == 1) { if (v) a->fd[fd].sockflags |= SOCKF_NODELAY; else a->fd[fd].sockflags &= ~SOCKF_NODELAY; return 0; }
        return -92;
    }
    if (level != 1 /*SOL_SOCKET*/) return -92;
    switch (opt) {
    case 7: case 8: {                                                  /* SO_SNDBUF / SO_RCVBUF */
        /* LINUX DOUBLES IT, and then clamps to the system maximum. Both halves
         * matter: a program that sets N and reads back N/2 concludes the set
         * failed, and one that sets a gigabyte must be told a real number
         * rather than the gigabyte. Ours is clamped to what is actually there,
         * which is exactly what Linux does at wmem_max. */
        if (len < 4) return -14;
        if (v < 0) return -22;                                         /* EINVAL */
        int cap = fd_sock_capacity(ty);
        int got = v * 2;
        if (got < 2048) got = 2048;                                    /* SOCK_MIN_SNDBUF-ish floor */
        if (got > cap) got = cap;
        if (opt == 7) a->fd[fd].sndbuf = got; else a->fd[fd].rcvbuf = got;
        return 0;
    }
    case 13: case 20: case 21:                                         /* SO_LINGER / timeouts: accepted, nothing to store */
        return 0;
    case 4: return -92;                                                /* SO_ERROR is read-only */
    case 3: case 30: case 38: case 39: return -92;                     /* SO_TYPE/ACCEPTCONN/PROTOCOL/DOMAIN are read-only */
    default: {
        uint32_t bit = sockopt_flagbit(opt);
        if (!bit) {
            static uint32_t moaned[8];
            if (opt >= 0 && opt < 256 && !(moaned[opt >> 5] & (1u << (opt & 31)))) {
                moaned[opt >> 5] |= 1u << (opt & 31);
                kprintf("[sock] setsockopt(level %d, option %d) is not implemented -- "
                        "answering ENOPROTOOPT rather than pretending it took\n", level, opt);
            }
            return -92;
        }
        if (v) a->fd[fd].sockflags |= bit; else a->fd[fd].sockflags &= ~bit;
        return 0;
    }
    }
}

/* WHAT IS THIS DESCRIPTOR, AND WHAT STATE IS IT IN? (M2087)
 *
 * Written for the EAGAIN spin detector, which found a thread reading an empty
 * non-blocking pipe a hundred thousand times in a row and could say only
 * "fd type 1". The question that decides whether that is our bug or the
 * program's is a different one: is a writer still open on the other end, has
 * one ever been, and did the program ask for non-blocking at all? Those facts
 * exist in three different modules and none of them was reachable from the
 * place that needed to print them.
 *
 * It PRINTS rather than formatting into a buffer because this kernel has no
 * sprintf -- kprintf is the only formatter -- and one printer per fd type here
 * is one fewer place for a caller to print a field that means something else
 * for the type it actually got. */
void app_fd_print(int fd) {
    struct app *a = cur();
    if (!a || fd < 0 || fd >= APP_NFD || !a->fd[fd].used) { kprintf("fd %d: not open", fd); return; }
    int ty = a->fd[fd].type, obj = a->fd[fd].obj;
    int nb = a->fd[fd].nonblock, cx = a->fd[fd].cloexec;
    switch (ty) {
    case 1: {
        int ro = -1, wo = -1, q = -1, hw = -1;
        pipe_state(obj, &ro, &wo, &q, &hw);
        kprintf("pipe %d %s-end readers=%d writers=%d queued=%d ever_had_writer=%d nonblock=%d cloexec=%d",
                obj, a->fd[fd].write_end ? "write" : "read", ro, wo, q, hw, nb, cx);
        break;
    }
    case 2: kprintf("file '%s' off=%ld nonblock=%d cloexec=%d", a->fd[fd].path, a->fd[fd].off, nb, cx); break;
    case 3: kprintf("memfd obj %d off=%ld nonblock=%d cloexec=%d", obj, a->fd[fd].off, nb, cx); break;
    case 12: kprintf("AF_UNIX ep %d queued=%ld readable=%d nonblock=%d cloexec=%d",
                     obj, unix_nread(obj), unix_readable(obj), nb, cx); break;
    case 10: kprintf("AF_INET stream sock %d queued=%ld nonblock=%d cloexec=%d",
                     obj, net_tcp_sock_nread(obj), nb, cx); break;
    case 14: kprintf("console alias, %d key(s) queued, nonblock=%d", iq_count(a->out_to ? a->out_to : a), nb); break;
    default: kprintf("fd type %d obj %d nonblock=%d cloexec=%d", ty, obj, nb, cx); break;
    }
}

/* WHAT IS ACTUALLY OPEN IN THIS PROCESS? (M2091)
 *
 * The question an EBADF raises, and nothing could answer it. A Firefox content
 * process starts, does set_robust_list / rt_sigaction / close(4), then
 * recvmsg(fd 12) = -EBADF and aborts -- and "fd 12 is not open" is only half a
 * finding. Which descriptors ARE open, and what are they, decides whether the
 * fork lost one, the dup2 went somewhere else, or the number was never right.
 *
 * One line per open descriptor, printed through app_fd_print so each type
 * describes itself rather than being guessed at from a number. */
void app_fd_dump(const char *why) {
    struct app *a = cur(); if (!a) return;
    int n = 0;
    kprintf("[fd] pid %d open descriptors (%s):\n", a->pid, why ? why : "");
    for (int i = 0; i < APP_NFD; i++) {
        if (!a->fd[i].used) continue;
        kprintf("[fd]   %d = ", i);
        app_fd_print(i);
        kprintf("\n");
        n++;
        if (n >= 48) { kprintf("[fd]   ... (stopping at 48)\n"); break; }
    }
    if (!n) kprintf("[fd]   NONE -- not one descriptor is open, so 0/1/2 are the console alias\n");
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
    /* HEAP (M2062): a dirent name is 256 bytes now, so 128 of them is 33 KB
     * against a 16 KB kernel stack. Widening the name is what stopped every
     * listing truncating a filename at 31 characters. */
    vfs_dirent *ents = kmalloc(128 * sizeof *ents);
    if (!ents) return -1;
    int n = vfs_list(ents, 128);
    if (n < 0) { kfree(ents); return -1; }
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
    kfree(ents);
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
        /* AF_UNIX WAS THE ONE TYPE MISSING FROM THIS LIST (M2002). Without a
         * reference, the child's inherited socket was the SAME endpoint as the
         * parent's and the first close() in either process hung up both. Every
         * child closes its inherited descriptors after exec, so a program that
         * forks lost its own live connection moments later -- which is exactly
         * how Firefox's display connection died right after it had bound every
         * global and taken its keymap. */
        else if (parent->fd[i].used && parent->fd[i].type == 12) unix_ref(parent->fd[i].obj);   /* AF_UNIX endpoint inherited (M2002) */
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
        /* AF_UNIX, which this never handled either (M2002). Harmless while an
         * endpoint was closed by whoever got there first; now that a descriptor
         * is a REFERENCE, an exiting process that skipped its sockets would
         * leave the connection open forever -- the peer never sees EOF and the
         * compositor's client table fills with the dead. */
        else if (a->fd[i].type == 12) { if (a->fd[i].obj >= 0) unix_close(a->fd[i].obj); }
        else if (a->fd[i].type == 13) unix_unlisten(a->fd[i].obj);
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
/* An extra environment variable for the NEXT Linux spawn only, then forgotten.
 *
 * The case that needs it: proving Claude Code's network path. "Not logged in"
 * is a LOCAL check -- it short-circuits before any DNS, TCP or TLS happens, so
 * a clean exit there says nothing about whether this kernel can carry an HTTPS
 * request. Handing that one process a deliberately FAKE key makes it do the
 * whole round trip and get a 401 back from the server, which exercises every
 * layer and proves them. One-shot because an API key in the global environment
 * would be inherited by every program the system ever starts. (M1999) */
/* Up to LX_PEND_ENV one-shot entries (M2013): diagnosing a program that has
 * stopped talking usually means turning on two or three of ITS logging
 * switches at once, and one slot made that a choice between them. */
void app_set_next_env(const char *e) {
    for (int k = 0; k < LX_PEND_ENV; k++)
        if (!g_pend_env_extra[k]) { g_pend_env_extra[k] = e; return; }
}

static long app_fork_common(struct registers *r, uint64_t child_rsp, int share_vm) {
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

    /* Build the child's address space as a COW clone of the parent (current).
     *
     * EVEN FOR vfork (M2006). vfork promises two things -- a shared address
     * space and a suspended parent -- and they are separable. Sharing it for
     * real is what a kernel does, and I tried: the child exec's into a fresh
     * space and the parent keeps the old one, which is correct on paper. In
     * practice it produced corrupted control flow in freshly-exec'd processes
     * (instruction fetches at 0x50fff001, 0x237d8, a write to gcc's read-only
     * text) that I could not account for, so it is not in.
     *
     * The SUSPENSION is the half that actually mattered here, and it is safe.
     * The fault that broke self-hosting was the parent running on after clone
     * and munmapping the stack the child was still executing on:
     *
     *   435 clone3(...) = 161
     *   11  munmap(0x10315b000, 0x9000)      <- the child's stack
     *   ...  fault in clone + 0x21a at rsp-8
     *
     * A suspended parent cannot do that. What a copy-on-write child loses is
     * the ability to hand its exec errno back through shared memory -- and
     * glibc's fallback for that is the child exiting 127, which the parent
     * already learns through wait4. A worse diagnostic on a rare failure path
     * is a good trade for memory that cannot be corrupted. */
    a->cr3 = vmm_create_address_space();
    if (!a->cr3) { a->used = 0; return -1; }
    vdso_map(a->cr3);                                   /* the RO vDSO page (shared, RO — not COW) */
    if (vmm_fork_cow(a->cr3) != 0) { vmm_destroy_address_space(a->cr3); a->used = 0; return -1; }
    /* NOW make the parent's siblings drop their WRITABLE entries (M2047).
     *
     * vmm_fork_cow just write-protected every shared page of the PARENT, and
     * that is only effective if every core that could write one takes the
     * fault. A sibling thread on another core still holds a cached writable
     * translation and would scribble straight into a frame the child now
     * shares.
     *
     * Done here rather than inside fork_cow because only this side knows
     * whether the address space is live elsewhere at all. app_tlb_sync fires
     * only when the parent has a live thread -- and the overwhelmingly common
     * fork is single-threaded (a shell, make, the gcc driver), where there is
     * nothing to shoot down and an unconditional IPI plus its bounded ack wait
     * on every fork is pure cost. gcc forks once per compilation stage. */
    app_tlb_sync(p);
    if (share_vm) a->vfork_parent = p->pid;             /* suspend the parent until we exec or exit */

    /* Inherit the parent's process state (NOT its window/grid/task/identity). */
    a->entry = p->entry; a->ustack = p->ustack; a->heap_end = p->heap_end;
    a->mmap_next = p->mmap_next; a->nvma = p->nvma; a->aslr_mmap_base = p->aslr_mmap_base;   /* inherit the ASLR layout across fork (M1287) */
    for (int i = 0; i < APP_MAXVMA; i++) a->vma[i] = p->vma[i];
    /* A memfd mapping is inherited by the child, so the CHILD holds a
     * reference too -- otherwise the parent's exit frees a buffer the child is
     * still reading. (M1985) */
    for (int i = 0; i < a->nvma; i++) if (a->vma[i].mfd >= 0) memfd_ref(a->vma[i].mfd);
    /* The path table the VMAs index into is GLOBAL, so a forked child inherits
     * it for free -- and cannot be handed indices into an empty one. (M1962) */
    for (int i = 0; i < APP_NSIG; i++) a->sig_handler[i] = p->sig_handler[i];
    a->sig_restorer = p->sig_restorer; a->curcol = p->curcol;
    /* A CHILD'S OUTPUT BELONGS WHERE ITS PARENT'S WENT (M2004). Firefox and
     * Claude Code both fork helpers that print; without this, a helper's
     * diagnostics went to the kernel console while the program it belongs to
     * wrote into a window, and the two could not be read together. */
    a->out_to = p->out_to;
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
    /* The signal MASK is inherited, and it is per-thread now, so it has to be
     * copied from the CALLING thread rather than from the process (M2075).
     * glibc's pthread_create blocks every signal around the clone and has the
     * child restore the saved mask, so a child that starts with an empty mask
     * has a window in which it can take a signal meant for its creator. */
    { task_t *pt = task_self();
      a->fork_sig_blocked = pt ? pt->sig_blocked : 0; }

    /* The child's resume context: the parent's trap frame, but returning 0. */
    a->fork_frame = *r;
    a->fork_frame.rax = 0;
    if (child_rsp) a->fork_frame.rsp = child_rsp;       /* clone() with a caller-supplied child stack */
    a->fork_frame.rflags |= 0x200;                      /* ensure IF is set in ring 3 */

    /* SUSPENDED: the copies below are what make this a working thread, and a
     * child that gets scheduled before them runs with %fs = 0. (M2006) */
    a->task = task_create_stack_suspended(fork_child_trampoline, a->cr3, a, 256 * 1024);
    if (a->task) ((task_t *)a->task)->sig_blocked = a->fork_sig_blocked;   /* inherited mask (M2075) */
    if (!a->task) {
        if (!a->cr3_borrowed) vmm_destroy_address_space(a->cr3);
        a->used = 0; return -1;
    }
    /* copy the parent's live FP/SSE state so a child mid-float-computation is correct */
    task_copy_fpu(a->task, p->task);
    /* THE FORKING THREAD'S TLS, NOT THE PROCESS'S MAIN ONE (M2083).
     *
     * M1949 got the direction right and the source wrong: it copies from
     * p->task, which is the parent process's MAIN task. fork() from any other
     * thread therefore handed the child the main thread's thread-control-block
     * address, so every __thread variable in the child aliased a thread that
     * is not the one that called fork -- and the child is the only thread it
     * has, so nothing else could ever correct it.
     *
     * Measured: a child forked from a worker thread read its own __thread
     * variable as someone else's and exited 3. glibc's own pthread bookkeeping
     * lives in that block, which is why the failure presents as a canary read
     * at %fs:0x28 rather than as a wrong value. */
    { task_t *forker = task_self();
      task_copy_tls(a->task, forker ? forker : p->task); }
    task_cont(a->task);                /* context complete: now it may run */

    /* give the child its own window (the WM consumes the pending queue) */
    pend_push(a);
    if (share_vm) {
        /* SUSPEND THE PARENT until the child execs or exits -- the other half
         * of vfork, and the half that makes sharing an address space safe at
         * all: two processes must not run on one stack at the same time.
         * Released by app_vfork_release, from execve or from exit. */
        int child_pid = a->pid;
        p->vfork_waiting = 1;
        __asm__ volatile("sti");
        while (p->vfork_waiting) {
            if (!app_pid_alive(child_pid)) break;   /* child vanished without telling us */
            task_sleep_ms(1);
        }
        p->vfork_waiting = 0;
        return child_pid;
    }
    return a->pid;
}

long app_fork_at(struct registers *r, uint64_t child_rsp) { return app_fork_common(r, child_rsp, 0); }

/* clone(CLONE_VM|CLONE_VFORK, stack): share the address space AND suspend the
 * caller. This is what glibc's posix_spawn asks for, and what it is written
 * against. (M2006) */
long app_vfork_at(struct registers *r, uint64_t child_rsp) { return app_fork_common(r, child_rsp, 1); }

/* Let a suspended vfork parent run again: the child has exec'd (and so now has
 * an address space of its own) or has exited. Idempotent -- both paths reach
 * it, and a child that execs then exits must not release a second parent. */
void app_vfork_release(app_t *ap) {
    struct app *a = (struct app *)ap;
    if (!a || !a->vfork_parent) return;
    int ppid = a->vfork_parent;
    a->vfork_parent = 0;
    for (int i = 0; i < MAX_APPS; i++)
        if (apps[i].used && apps[i].pid == ppid) { apps[i].vfork_waiting = 0; return; }
}

long app_fork(struct registers *r) { return app_fork_at(r, 0); }

/* Claim a thread-table slot, RECLAIMING finished ones first (M2009).
 *
 * Slots were only ever released by an explicit join or by process teardown, so
 * a DETACHED thread that ran to completion held its slot for the life of the
 * process. That makes the table a lifetime budget rather than a concurrency
 * limit: Firefox's thread pools create and retire threads continuously, so it
 * ran out of slots with a handful of threads actually running, and what it does
 * when a thread cannot be created is crash on purpose.
 *
 * Only a task that is DEAD *and* off_cpu is freed -- a dead task may still be
 * finishing its final context_switch on another core, and freeing its stack
 * underneath that is the bug M1961 fixed elsewhere. Returns a slot index, or
 * -1 when every slot really is a live thread. */
/* Tell EVERY subsystem that parks a task_t* that this one is going away (M2053).
 *
 * app_futex_forget existed and was called faithfully; nothing else had a hook
 * at all. mbox, mqueue, POSIX semaphores, SysV semaphores and AF_UNIX accept
 * each store a waiter to wake later, and each kept a stale pointer after the
 * task was freed. A later wake then calls task_wake() on reclaimed memory,
 * which writes a state field and puts it back on the run queue -- so a FREED
 * task_t gets scheduled and its trampoline runs on whatever the allocator has
 * since put in those bytes. The kernel said so out loud during a Claude Code
 * run, and the guard that printed it is the only reason it was not silent:
 *
 *   [task] thread 66 reached its trampoline with no start frame
 *          -- it was made runnable before its context was complete
 *
 * One call site so a sixth subsystem cannot be forgotten by accident. */
void app_task_forget_everywhere(void *t) {
    if (!t) return;
    app_futex_forget(t);
    mbox_forget_task(t);
    mqueue_forget_task(t);
    psem_forget_task(t);
    sysvsem_forget_task(t);
    unix_forget_task(t);
    {   /* the userfaultfd monitor, which lives here rather than in its own file */
        uint64_t uf = irq_save();
        if (g_uffd.monitor == (task_t *)t) { g_uffd.monitor = 0; g_uffd.monitor_waiting = 0; }
        irq_restore(uf);
    }
}

static int app_thr_slot(struct app *a) {
    for (int i = 0; i < APP_MAXTHREAD; i++) if (!a->thr[i]) return i;
    for (int i = 0; i < APP_MAXTHREAD; i++) {
        task_t *t = a->thr[i];
        if (!t || t->state != TASK_DEAD) continue;
        if (!__atomic_load_n(&t->off_cpu, __ATOMIC_ACQUIRE)) continue;
        app_task_forget_everywhere(t);
        a->thr[i] = 0;
        task_free(t);
        return i;
    }
    return -1;
}

/* clone (M1138): create a THREAD — a task sharing this process's address space
 * (same CR3, same app_t) that begins in ring 3 at fn(arg) on `stack`. Unlike
 * fork (a separate COW address space), threads share ALL memory, so they can
 * cooperate on shared data (the hardware `lock` prefix gives atomicity). It runs
 * concurrently under the existing preemptive scheduler and ends via
 * SYS_thread_exit. Returns the new thread id (its task id), or -1. `r` is the
 * caller's live trap frame (we inherit its user segment selectors + rflags).
 *
 * No window, no new app_t: the thread shares the caller's window for output.
 *
 * BORN SUSPENDED (M2014). This used to say it was "race-free because the
 * int-0x80 gate keeps IF=0 through here, so the new task can't be scheduled
 * until we've stored its start_frame" -- which was true on one core and has
 * not been true since M1531. IF=0 stops THIS core; another core picks the task
 * out of the ready ring the instant it is published, runs thread_trampoline,
 * and dereferences a start_frame that is still NULL:
 *
 *   *** KERNEL PANIC: CPU EXCEPTION ***
 *     Page Fault (vector 14)  CR2 = 0x0  at thread_trampoline+0x33
 *
 * Four of them at once, from a desktop spawning native apps beside a Firefox
 * with eighty threads. M2006 fixed exactly this for the Linux clone path and
 * for fork children; this is the third caller of the same trampoline. */
long app_clone(struct registers *r, uint64_t fn, uint64_t stack, uint64_t arg) {
    struct app *a = cur();
    if (!a || !r || !fn || !stack) return -1;
    struct registers *f = kmalloc(sizeof *f);
    if (!f) return -1;
    *f = *r;
    f->rip = fn; f->rsp = stack; f->rdi = arg; f->rax = 0;
    f->rflags |= 0x200;                                 /* IF set in ring 3 */
    task_t *t = task_create_stack_suspended(thread_trampoline, a->cr3, a, 256 * 1024);   /* SHARED cr3 + app. 256K (was 64K): a clone'd thread that calls sys_https runs the bignum/RSA TLS handshake on THIS kernel stack — the ring-3 browser's async fetch worker does exactly that, and 64K overflowed (corrupting the task ring -> task_wake_sleepers GPF). Matches the in-kernel browser worker's 256K. */
    if (!t) { kfree(f); return -1; }
    t->start_frame = f;
    { int sl = app_thr_slot(a); if (sl >= 0) a->thr[sl] = t; }   /* track for join/reap (M1139); reclaims finished slots (M2009) */
    task_cont(t);                      /* the start frame is stored: NOW it may run (M2014) */
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
    int slot = app_thr_slot(a);
    if (slot < 0) return -1;

    struct registers *f = kmalloc(sizeof *f);
    if (!f) return -1;
    *f = *r;
    f->rsp = stack;
    f->rax = 0;                                         /* the child's clone() returns 0 */
    f->rflags |= 0x200;                                 /* IF set in ring 3 */
    /* Suspended for the same reason as fork's child (M2006): the TLS base is
     * set below, and pthread_create's whole purpose is a thread with its OWN
     * TLS -- one that runs before CLONE_SETTLS is applied reads another
     * thread's __thread variables, or none at all. */
    task_t *t = task_create_stack_suspended(thread_trampoline, a->cr3, a, 256 * 1024);   /* SHARED cr3 + app */
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
    task_cont(t);                      /* TLS + tid pointers are set: now it may run */
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
    app_futex_forget(task_self());      /* never leave a waiter pointing at us (M1990) */
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
    /* DEAD is not enough, and app_reap has known that since M1961: a task sets
     * TASK_DEAD and only THEN performs its final context_switch, so between the
     * two it is still executing on its own stack. Freeing it there hands the
     * kstack back while it is in use, and -- because glibc unmaps a joined
     * thread's stack the instant join returns -- the thread faults on memory
     * that no longer belongs to anyone. It shows up as a fault with the
     * process down to a single VMA, from a tid that should not exist any more.
     * Wait for off_cpu as well, exactly as the reaper does. (M1988) */
    while (t->state != TASK_DEAD || !__atomic_load_n(&t->off_cpu, __ATOMIC_ACQUIRE))
        task_sleep_ms(5);
    a->thr[slot] = 0;                               /* drop our reference before freeing */
    app_futex_forget(t);                            /* no stale waiter may outlive it (M1990) */
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
    /* Same split as the spawn path: eager at the top for the initial frame,
     * demand-zero below it, guard page at USTACK_BASE. (M1975) */
    for (int i = USTACK_PAGES - USTACK_EAGER; i < USTACK_PAGES; i++) {
        uint64_t frame = pmm_alloc_frame();
        if (!frame) goto fail;
        if (vmm_map(USTACK_BASE + (uint64_t)i * PAGE_SIZE, frame, PTE_WRITABLE | PTE_USER | PTE_NX) != 0) {
            pmm_free_frame(frame); goto fail;
        }
    }
    if (!vma_full(a)) {
        int vs12; VMA_NEW(a, vs12);
        a->vma[vs12].start = USTACK_BASE + PAGE_SIZE;
        a->vma[vs12].len   = (uint64_t)(USTACK_PAGES - 1 - USTACK_EAGER) * PAGE_SIZE;
        a->vma[vs12].sealed = 0; a->vma[vs12].uffd = 0;
        a->vma[vs12].file_backed = 0; a->vma[vs12].locked = 0; a->vma[vs12].huge = 0;
        a->vma[vs12].prot = VMA_PROT_READ | VMA_PROT_WRITE;
        
    }

    /* committed: we are now the new program. Free the OLD space (non-active now). */
    /* A vfork CHILD's old address space is its PARENT's -- destroying it here
     * would take the parent down with it. exec is also the moment the parent
     * may run again: the child has its own space now, so the sharing is over.
     * (M2006) */
    int was_borrowed = a->cr3_borrowed;
    a->cr3_borrowed = 0;
    if (!was_borrowed) vmm_destroy_address_space(old_cr3);
    a->cr3 = new_cr3; a->task->cr3 = new_cr3;
    /* RELEASE THE vfork PARENT ONLY NOW, with the switch completely done
     * (M2006). Waking it one line earlier left this task's saved cr3 still
     * naming the space we had just left while the CPU was already running in
     * the new one -- so a preemption in that window reloaded the OLD space and
     * the child executed its new image against the previous address space:
     *
     *   err=0x14 (instruction fetch, user) at an unmapped page in the image
     *
     * The window existed before; waking another process inside it is what made
     * it reachable. */
    if (was_borrowed) app_vfork_release((app_t *)a);
    a->entry = entry; a->ustack = USTACK_BASE + USTACK_PAGES * PAGE_SIZE;

    /* A Linux execve needs argc/argv/envp/auxv on the stack, built HERE while
     * the new address space is active and its stack pages are mapped -- the
     * same frame app_spawn builds, but with the caller's argv rather than a
     * synthesised one. (M1948) */
    if (a->exec_argv) {
        uint64_t rsp = lx_spawn_stack_dyn(elf, elf_image_bias(elf), prog_entry, interp_base,
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
    for (int li = 0; li < nlazy && !vma_full(a); li++) {
        int vs13; VMA_NEW(a, vs13);
        a->vma[vs13].start = lazy[li].start; a->vma[vs13].len = lazy[li].len;
        a->vma[vs13].sealed = 0; a->vma[vs13].uffd = 0;
        a->vma[vs13].file_backed = 0; a->vma[vs13].locked = 0; a->vma[vs13].huge = 0;
        
    }
    a->aslr_mmap_base = aslr_mmap_pick(); a->mmap_next = a->aslr_mmap_base;   /* ASLR: a fresh randomized mmap base per exec (M1287) */
    for (int i = 0; i < APP_NSIG; i++) a->sig_handler[i] = 0;
    a->pending_sigs = 0; a->sigfd_armed = 0; a->sigfd_mask = 0; a->alarm_interval = 0; a->alarm_next = 0;
    /* The per-thread half as well (M2075): exec keeps the calling thread and
     * discards every sibling, so the mask, the pending set, the alternate
     * stack and any in-flight handler all belong to the old program. */
    { task_t *th = task_self();
      if (th) { th->sig_in = 0; th->sig_pending = 0; th->sig_blocked = 0;
                th->sig_uctx = 0; th->sig_alt_base = 0; th->sig_alt_size = 0; } }
    a->sigq_n = 0;                                                  /* drop any queued RT-signal payloads (M1271) */

    for (int i = 0; i < APP_NPTIMER; i++) a->ptimer[i].used = 0;    /* POSIX timers are not preserved across exec (M1272) */
    if (a->gfx) { kfree(a->gfx); a->gfx = 0; a->gfx_w = a->gfx_h = 0; }
    int ti = 0; if (title) while (title[ti] && ti < 23) { a->titlebuf[ti] = title[ti]; ti++; }
    a->titlebuf[ti] = 0; a->title = a->titlebuf;
    int ei = 0; if (name) while (name[ei] && ei < (int)sizeof a->exe_path - 1) { a->exe_path[ei] = name[ei]; ei++; }   /* exec'd path, for /proc/<pid>/exe (M1250/M1970) */
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

/* The cwd a newly spawned Linux process should start in (M2033). Captured
 * from the REQUESTER here, because by the time the window manager performs the
 * spawn, cur() is the WM and the shell's directory is long gone. */
static char g_pend_lxcwd[VFS_PATH_MAX];
/* An explicit cwd for the NEXT spawn, for callers that have no app context to
 * inherit one from (M2056). A boot-task-driven run had cur() == 0 and so
 * always started at the volume root, which is not where a program that cares
 * about its working directory -- a repo tool, say -- should be run. One-shot. */
static char g_pend_lxcwd_set[VFS_PATH_MAX];
void app_set_next_cwd(const char *p) {
    int k = 0;
    if (p) while (p[k] && k < (int)sizeof g_pend_lxcwd_set - 1) { g_pend_lxcwd_set[k] = p[k]; k++; }
    g_pend_lxcwd_set[k] = 0;
}
static int lx_spawn_file(const char *path) {
    int i = 0; while (path[i] && i < (int)sizeof g_pend_lxpath - 1) { g_pend_lxpath[i] = path[i]; i++; }
    g_pend_lxpath[i] = 0;
    g_pend_lxcwd[0] = 0;
    if (g_pend_lxcwd_set[0]) {
        int k = 0; while (g_pend_lxcwd_set[k] && k < (int)sizeof g_pend_lxcwd - 1) { g_pend_lxcwd[k] = g_pend_lxcwd_set[k]; k++; }
        g_pend_lxcwd[k] = 0;
        g_pend_lxcwd_set[0] = 0;                /* one-shot: never leak it to a later spawn */
    } else {
        struct app *rq = cur();
        if (rq && rq->cwd_path[0]) {
            int k = 0; while (rq->cwd_path[k] && k < (int)sizeof g_pend_lxcwd - 1) { g_pend_lxcwd[k] = rq->cwd_path[k]; k++; }
            g_pend_lxcwd[k] = 0;
        }
    }

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
        if (args[i] && args[i][k])
            kprintf("[app] launch argv[%d] TRUNCATED at %d chars -- the program sees a short argument\n",
                    i + 1, LX_PEND_ARGLEN - 1);
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
    unsigned long prev_maj = (unsigned long)-1, prev_min = (unsigned long)-1;   /* the previous heartbeat's fault counts (M2004) */
    int stall_told = 0;
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
            kprintf("[runsync] t=%ds free=%luK apps=%d majflt=%lu minflt=%lu readahead=%lu\n", waited / 1000,
                    (unsigned long)(pmm_free_bytes() >> 10), live, maj, min, g_readahead_pages);
            /* FROZEN COUNTERS MEAN STUCK, AND STUCK SHOULD SAY SO NOW (M2004).
             *
             * The full thread dump below only ran when the whole budget expired
             * -- twenty-five minutes for a browser -- so a run that stalled in
             * its first minute reported nothing but an unchanging pair of
             * numbers for the rest of its life. If not one page fault has
             * happened in a whole minute then nothing is executing, and the
             * question the heartbeat just answered with "stuck" deserves the
             * answer it already has: every thread's state and what it is
             * parked on. Once, so a long stall does not fill the log. */
            if (maj == prev_maj && min == prev_min && !stall_told) {
                stall_told = 1;
                kprintf("[runsync] NOTHING has faulted in 60s -- every thread, and what it waits on:\n");
                /* app_dump_threads, not a second copy of the same loop: it
                 * also names WHERE IN THE PROGRAM each thread is parked
                 * (M2012), and a wchan of app_futex for every thread -- which
                 * is what this used to print -- answers nothing. */
                for (int i = 0; i < MAX_APPS; i++) {
                    if (!apps[i].used) continue;
                    kprintf("[runsync]   pid %d '%s' exited=%d\n",
                            apps[i].pid, apps[i].title ? apps[i].title : "?", apps[i].exited);
                    app_dump_threads(apps[i].pid);
                }
                app_futex_dump();
                lx_trace_dump_last("the stall", 220);
            }
            prev_maj = maj; prev_min = min;
            /* ...and WHERE a still-running one is. Frozen counters plus a
             * RUNNING task means a userspace loop, and the only thing that
             * identifies it is the ring-3 RIP together with the mapping that
             * contains it -- otherwise "it hangs" is all you ever learn. */
            for (int i = 0; i < MAX_APPS; i++) {
                if (!apps[i].used || !apps[i].task || apps[i].task->state != TASK_RUNNING) continue;
                struct registers *uf = task_uframe(apps[i].task);
                if (!uf) continue;
                uint64_t rip = uf->rip;
                const char *where = "(no mapping)"; uint64_t voff = 0;
                for (int v = 0; v < apps[i].nvma; v++)
                    if (rip >= apps[i].vma[v].start && rip < apps[i].vma[v].start + apps[i].vma[v].len) {
                        where = apps[i].vma[v].fidx >= 0 ? vma_path(&apps[i], v) : "(anon)";
                        voff = apps[i].vma[v].foff + (rip - apps[i].vma[v].start);
                        break;
                    }
                kprintf("[runsync]   pid %d RUNNING at rip=%lx in %s +%lx\n",
                        apps[i].pid, (unsigned long)rip, where, (unsigned long)voff);
            }
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
        /* WHAT WAS IT DOING? The thread states say where each one is parked;
         * the syscall ring says what the process was actually doing, which is
         * the difference between "blocked on a futex" and "polling a socket
         * that will never answer". A timeout without this is a dead end.
         * (M1996) */
        lx_trace_dump_last("the sync run timing out", 32);
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
/* A WINDOW FOR A PROCESS THAT IS ALREADY GONE IS A WINDOW NOBODY GETS BACK
 * (M2011).
 *
 * app_run_linux_sync collects its child itself (`used = 0`) because nothing
 * else reaps during the boot demos -- so by the time the window manager starts,
 * every probe binary that ran at boot is still sitting in this queue pointing
 * at a slot that is free or has been reused. The WM gave each one a window, the
 * reap loop could not drop them (app_reap on an already-collected app never
 * reports success), and the table filled with corpses: adding two probes to the
 * boot sequence took win_count to exactly MAX_WINDOWS and the Wayland demo's
 * surface then had no slot to be drawn in. It failed as "the surface never
 * appeared on screen", naming neither the queue nor the probes.
 *
 * An app that has EXITED but not yet been reaped still gets its window -- it
 * may have printed something worth reading, and the reap loop will close it a
 * moment later. What is skipped is a slot that is no longer the app we queued. */
/* -append selftest: A LIVE APP MUST NOT LOSE ITS WINDOW TO A DEAD ONE (M2076).
 *
 * The queue is a 32-entry ring, nothing ever removed an entry for a process
 * that had exited, and a push into a full one was discarded with no else
 * branch. A boot that creates and reaps thirty-one short-lived processes -- the
 * IPC self-test alone accounts for a dozen -- filled every slot with corpses,
 * and the next spawn was THE SHELL. The desktop came up with a Welcome window,
 * a Files window, and no terminal, which looks exactly like a design decision.
 *
 * Asserted here rather than from a boot marker because a boot only fills the
 * ring when it happens to run enough processes: the Shell-window marker in the
 * boot suite proves the system works, and this proves the property that makes
 * it work, on every boot, whatever else the boot does. */
int app_pendq_selftest(void) {
    int fails = 0, checks = 0;
    int sh = pend_h, st = pend_t;
    static struct pendent save[MAX_APPS];
    for (int i = 0; i < MAX_APPS; i++) save[i] = pending[i];

    /* A slot that passes the liveness check. Fabricated, because the test has
     * to be deterministic and the real apps at this point in boot are not. */
    struct app *live = 0;
    for (int i = 0; i < MAX_APPS; i++) if (!apps[i].used) { live = &apps[i]; break; }
    if (!live) { kprintf("[pendqtest] FAIL no free app slot to test with\n"); return 1; }
    live->used = 1; live->pid = 31337; live->out_to = 0; live->exited = 0;

    /* Fill the ring with entries for processes that do not exist. */
    pend_h = pend_t = 0;
    for (int i = 0; i < MAX_APPS - 1; i++) {
        pending[pend_h].a = 0; pending[pend_h].pid = 9000 + i;
        pend_h = (pend_h + 1) % MAX_APPS;
    }
    checks++;
    if (!pend_push(live)) {
        kprintf("[pendqtest] FAIL a live app was DROPPED by a queue full of EXITED processes"
                " -- this is the missing Shell window\n");
        fails++;
    } else kprintf("[pendqtest] ok   a live app is queued even when the ring is full of exited processes\n");

    checks++;
    { app_t *got = app_take_pending();
      if (got != (app_t *)live) { kprintf("[pendqtest] FAIL the queue returned a different app than the one pushed\n"); fails++; }
      else kprintf("[pendqtest] ok   ...and it is the app that comes back out\n"); }

    /* And a ring full of LIVE apps must still refuse -- reclaiming must not
     * become "overwrite something that is still waiting". */
    checks++;
    pend_h = pend_t = 0;
    for (int i = 0; i < MAX_APPS - 1; i++) {
        pending[pend_h].a = live; pending[pend_h].pid = live->pid;
        pend_h = (pend_h + 1) % MAX_APPS;
    }
    if (pend_push(live)) { kprintf("[pendqtest] FAIL a ring full of LIVE apps accepted another push\n"); fails++; }
    else kprintf("[pendqtest] ok   a ring full of LIVE apps refuses, and names the app it dropped\n");

    live->used = 0; live->pid = 0;
    for (int i = 0; i < MAX_APPS; i++) pending[i] = save[i];
    pend_h = sh; pend_t = st;
    kprintf("[pendqtest] %s (%d checks)\n",
            fails ? "PENDQSELFTEST FAILED" : "PENDQSELFTEST PASSED", checks);
    return fails;
}

app_t *app_take_pending(void) {
    while (pend_t != pend_h) {
        struct app *a = pending[pend_t].a;
        int pid = pending[pend_t].pid;
        pend_t = (pend_t + 1) % MAX_APPS;
        if (a && a->used && a->pid == pid) return a;
        /* SAY WHEN AN ENTRY IS DROPPED (M2076). This queue is how every app
         * gets a window, and the stale-entry check discards silently -- so a
         * process that spawned fine and then died, or whose slot was reused
         * before the desktop looked, produces a desktop with a window
         * missing and nothing anywhere saying which. */
        kprintf("[app] the window queue dropped pid %d (slot %s, now pid %d)\n",
                pid, (a && a->used) ? "reused" : "free", a ? a->pid : 0);
    }
    return 0;
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
