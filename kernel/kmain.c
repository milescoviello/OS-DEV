/*
 * kmain.c — kernel entry from the assembly trampoline (long mode, C land).
 *
 * Brings up every subsystem in order, runs a couple of demos (preemption,
 * per-process isolation), then hands the screen to the windowing desktop, which
 * hosts real ring-3 userspace programs as windows.
 */
#include "console.h"
#include "vga.h"
#include "gdt.h"
#include "unixsock.h"   /* g_unix_verbose (M1978) */
#include "wayland.h"    /* Wayland display server (M1978) */
#include "syscall.h"    /* struct statx, for the root-stat probe (M1992) */
#include "linuxabi.h"
#include "interrupts.h"
#include "timer.h"
#include "keyboard.h"
#include "serial.h"
#include "pmm.h"
#include "vmm.h"
#include "kheap.h"
#include "acpi.h"
#include "hpet.h"   /* high-resolution HPET clocksource (M1273) */
#include "smp.h"
#include "ioapic.h"      /* ioapic_init — I/O APIC routing foundation (M1856) */
#include "smpthread.h"
#include "multiboot.h"
#include "gdbstub.h"
#include "random.h"
#include "vdso.h"
#include "measure.h"
#include "task.h"
#include "app.h"    /* app_spawn_named_arg — the ring-3 user-stack overflow test (M1500) */
#include "fat32.h"
#include "vfs.h"
#include "partition.h"
#include "blockdev.h"
#include "ext2.h"   /* ext2_set_clock (M1175) */
#include "rtc.h"    /* rtc_unix (M1175) */
#include "dm.h"
#include "ata.h"
#include "journal.h"   /* write-ahead journal + its in-guest crash-recovery self-test (M1865) */
#include "pci.h"
#include "ahci.h"
#include "virtio_blk.h"
#include "virtio_rng.h"
#include "virtio_console.h"
#include "bpf.h"           /* bpf_jit_selftest (M1290) */
#include "nvme.h"
#include "floppy.h"
#include "virtio_net.h"
#include "virtio_gpu.h"
#include "svga.h"
#include "nic.h"
#include "e1000.h"      /* nic_init — needed when the boot demo is skipped (M1909) */
#include "net.h"
#include "netcon.h"
#include "watchdog.h"
#include "fbcon.h"
#include "fb.h"            /* fb_init_mb: consume a Multiboot/GRUB framebuffer (M1292) */
#include "string.h"        /* memset for the Multiboot2 shim (M1293) */
#include "mouse.h"
#include "usb.h"
#include "usb_storage.h"
#include "atapi.h"           /* atapi_selftest — ATAPI CD-ROM read driver (M1852) */
#include "usb_kbd.h"
#include "ehci.h"
#include "xhci.h"
#include "speaker.h"
#include "audio.h"
#include "hda.h"
#include "ipcselftest.h"   /* boot-time POSIX IPC self-test (M1906) */
#include "desktop.h"
#include <stdint.h>

extern void fpu_init(void);      /* kernel/asm/fpu.asm: enable x87 + SSE */

/* --- preemption demo: a worker that never yields -------------------------- */
static volatile uint64_t spin_count;
static volatile int       demo_stop;
static volatile int       worker_done;

static void spin_worker(void) {
    while (!demo_stop)
        spin_count++;          /* tight loop, NEVER calls task_yield() */
    worker_done = 1;
    task_exit();
}

/* --- per-process isolation demo --- */
static volatile int iso_live;

static void iso_worker(void) {
    int id = task_current_id();
    volatile int *v = (volatile int *)0x40000000;   /* same vaddr in every proc */
    *v = id * 100;                                   /* write into MY private page */
    for (int i = 0; i < 3; i++) {
        kprintf("    [proc %d] *0x40000000 = %d (mine=%d)%s\n",
                id, *v, id * 100, (*v == id * 100) ? "  isolated" : "  LEAK!");
        task_yield();
    }
    iso_live--;
    task_exit();
}

static void isolation_demo(void) {
    kprintf("[demo] memory isolation: 3 processes each map a PRIVATE page at the\n");
    kprintf("       same address 0x40000000 and write their id; none see another's:\n");
    iso_live = 3;
    for (int i = 0; i < 3; i++) {
        uint64_t cr3 = vmm_create_address_space();
        vmm_map_to(cr3, 0x40000000, pmm_alloc_frame(), PTE_WRITABLE | PTE_USER | PTE_NX);
        task_create(iso_worker, cr3, 0);
    }
    while (iso_live > 0)
        task_yield();
    kprintf("[demo] all isolated => each process has its own address space.\n\n");
}

static void preemption_demo(void) {
    kprintf("[demo] preemption: spawning a worker stuck in an infinite,\n");
    kprintf("       never-yielding loop. Under cooperative scheduling this\n");
    kprintf("       would freeze main forever. With preemption, both run:\n");
    task_create(spin_worker, 0, 0);
    /* 2 short readings (~0.1s total) are enough to show the counter moving
     * between them -- boot-time cost, not a correctness test (this only
     * narrates; nothing asserts specific tick/count values), so it doesn't
     * need the dramatic ~1.6s four-reading version this used to be. */
    for (int i = 0; i < 2; i++) {
        uint64_t target = timer_ticks() + 5;      /* ~50ms of wall time */
        while (timer_ticks() < target) { }         /* main also gets preempted */
        kprintf("    [main] alive at %lu ticks  |  worker spin_count = %lu\n",
                timer_ticks(), spin_count);
    }
    demo_stop = 1;
    while (!worker_done)
        task_yield();
    kprintf("[demo] worker counted to %lu while main kept printing"
            " => preemption works.\n\n", spin_count);
}

/* substring search (the kernel libc has no strstr) — for the gdbstub cmdline gate */
static int cmdline_has(const char *hay, const char *needle) {
    for (const char *p = hay; *p; p++) {
        const char *a = p, *b = needle;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return 1;
    }
    return 0;
}

/* CPU security hardening (M1269): enable SMEP (CR4 bit 20 — the kernel #PFs if it
 * ever tries to EXECUTE a ring-3 page) and UMIP (CR4 bit 11 — ring-3
 * SGDT/SIDT/SLDT/STR/SMSW #GP, closing those kernel-address info leaks), each
 * gated on CPUID.7:0 support. SMAP (CR4 bit 21) is deliberately NOT set: the
 * kernel reads/writes user buffers directly (syscall args) without stac/clac,
 * which SMAP would fault on. BSP only — ring-3 code runs on the BSP. */
static void cpu_harden(void) {
    uint32_t a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0u), "c"(0u));
    if (a < 7) { kprintf("[cpu] CPUID leaf 7 unavailable; no SMEP/UMIP\n"); return; }
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(7u), "c"(0u));
    int have_smep = (b >> 7) & 1;    /* CPUID.(EAX=7,ECX=0).EBX[7] */
    int have_umip = (c >> 2) & 1;    /* CPUID.(EAX=7,ECX=0).ECX[2] */
    uint64_t cr4; __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    if (have_smep) cr4 |= (1ull << 20);
    if (have_umip) cr4 |= (1ull << 11);
    __asm__ volatile("mov %0, %%cr4" :: "r"(cr4) : "memory");
    uint64_t now; __asm__ volatile("mov %%cr4, %0" : "=r"(now));
    kprintf("[ ok ] CPU hardening: SMEP=%d UMIP=%d (CR4=%lx)\n",
            (int)((now >> 20) & 1), (int)((now >> 11) & 1), (unsigned long)now);
}

/* Multiboot2 -> Multiboot1 shim (M1293, bare-metal graphics). GRUB booted via
 * `multiboot2` passes a TAG LIST, not the Multiboot1 struct the kernel reads —
 * and, unlike Multiboot1, it reliably provides a framebuffer. Walk the tags and
 * fill an MB1-format struct (memory map converted entry-by-entry + the
 * framebuffer) so pmm_init / fb consumption / everything downstream work
 * unchanged. The static buffers live in the (low, identity-mapped) kernel image,
 * so their addresses fit MB1's u32 mmap_addr. */
#define MULTIBOOT2_MAGIC 0x36d76289u
static struct multiboot_info       mb1_shim;
static struct multiboot_mmap_entry mb1_shim_mmap[96];
static char                        mb1_shim_cmdline[256];
static uint64_t mb2_to_mb1(uint64_t mb2) {
    const uint8_t *p = (const uint8_t *)(uintptr_t)mb2;
    uint32_t total = *(const uint32_t *)p;          /* total_size, then reserved, then tags */
    memset(&mb1_shim, 0, sizeof mb1_shim);
    int nm = 0;
    for (uint32_t off = 8; off + 8 <= total; ) {
        const uint8_t *tag = p + off;
        uint32_t type = *(const uint32_t *)tag;
        uint32_t size = *(const uint32_t *)(tag + 4);
        if (type == 0) break;                                  /* end tag */
        if (type == 1) {                                       /* boot command line */
            const char *s = (const char *)(tag + 8);
            uint32_t i = 0;
            while (i < sizeof mb1_shim_cmdline - 1 && s[i]) { mb1_shim_cmdline[i] = s[i]; i++; }
            mb1_shim_cmdline[i] = 0;
            mb1_shim.cmdline = (uint32_t)(uintptr_t)mb1_shim_cmdline;
            mb1_shim.flags  |= (1u << 2);                       /* MB1 flag bit 2 = cmdline present */
        } else if (type == 4) {                                /* basic meminfo */
            mb1_shim.mem_lower = *(const uint32_t *)(tag + 8);
            mb1_shim.mem_upper = *(const uint32_t *)(tag + 12);
            mb1_shim.flags |= MULTIBOOT_FLAG_MEM;
        } else if (type == 6) {                                /* memory map */
            uint32_t esz = *(const uint32_t *)(tag + 8);
            if (esz >= 24)
                for (const uint8_t *e = tag + 16; e + esz <= tag + size && nm < 96; e += esz) {
                    mb1_shim_mmap[nm].size = 20;               /* MB1 entry: size excludes itself */
                    mb1_shim_mmap[nm].addr = *(const uint64_t *)e;
                    mb1_shim_mmap[nm].len  = *(const uint64_t *)(e + 8);
                    mb1_shim_mmap[nm].type = *(const uint32_t *)(e + 16);
                    nm++;
                }
        } else if (type == 8) {                                /* framebuffer */
            mb1_shim.framebuffer_addr   = *(const uint64_t *)(tag + 8);
            mb1_shim.framebuffer_pitch  = *(const uint32_t *)(tag + 16);
            mb1_shim.framebuffer_width  = *(const uint32_t *)(tag + 20);
            mb1_shim.framebuffer_height = *(const uint32_t *)(tag + 24);
            mb1_shim.framebuffer_bpp    = *(const uint8_t  *)(tag + 28);
            mb1_shim.framebuffer_type   = *(const uint8_t  *)(tag + 29);
            mb1_shim.flags |= MULTIBOOT_FLAG_FB;
        }
        off += (size + 7u) & ~7u;                              /* tags are padded to 8 bytes */
    }
    if (nm) {
        mb1_shim.mmap_addr   = (uint32_t)(uintptr_t)mb1_shim_mmap;
        mb1_shim.mmap_length = (uint32_t)(nm * (int)sizeof(struct multiboot_mmap_entry));
        mb1_shim.flags |= MULTIBOOT_FLAG_MMAP;
    }
    return (uint64_t)(uintptr_t)&mb1_shim;
}

/* ---- deliberate kernel-stack-overflow test (M1498) ----------------------------
 * Gated behind `-append kstackover`: spawn a kernel task that recurses until it
 * runs off its guarded stack, exercising the WHOLE M1495/M1496 path end-to-end —
 * the guard-page #PF, the "KERNEL STACK OVERFLOW" diagnosis, and a panic backtrace
 * that has to walk a high-VA stack. Normal boots (no flag) never touch this. */
static volatile int g_kstack_overflow_test;
static volatile int g_ustack_overflow_test;   /* -append ustackover: spawn a ring-3 app that overflows its USER stack (M1500) */
static volatile int g_wx_test;                /* -append wxtest: prove W^X is enforced -- executing a no-execute data page must fault (M1501) */
static volatile int g_smep_test;              /* -append smeptest: prove SMEP -- the kernel executing a ring-3 (user) page must fault (M1502) */
static volatile int g_e2big_test;             /* -append e2big: concurrent reads of one 171 MB library (M2166) */
static volatile int g_lxmapcmp;               /* -append lxmapcmp: compare whole mapped libraries against their files (M2168) */
static volatile int g_e2pcrace_test;          /* -append e2pcrace: hammer the ext2 path cache from every core (M2155) */
static volatile int g_smpthread_test;         /* -append smpthreadtest: prove real cross-core kernel threads work (M1530) */
static volatile int g_smpsched_test;          /* -append smpschedtest: prove the GENERAL (M1531) scheduler runs ordinary pin_core=-1 tasks across cores */
static volatile int g_journal_test;           /* -append journalguest: prove the write-ahead journal + crash recovery on REAL ata hardware (M1865) */
static volatile int g_fatjournal_test;        /* -append fatjournaltest: prove a live FAT32 file create is crash-atomic (M1866) */
/* -append noprobes: bring the Linux ABI up and skip the probe SUITE (M2103).
 *
 * Every Firefox run implies g_lxabi_test, so every measurement of a browser
 * startup was preceded by twenty-two in-guest probes -- minutes of them, and
 * at one point a single probe sat in app_run_linux_sync for sixty seconds
 * while the thing being measured had not started. A loop whose iteration is
 * dominated by work unrelated to the question is a loop that does not get run
 * often enough. The probes still run in their own boots, which is where the
 * test suites ask for them. */
static volatile int g_noprobes;
static volatile int g_force_probes;           /* -append probes: run the ABI battery even on a demo boot (M2283) */
static volatile int g_lxfull_test;            /* -append lxfulltest: the whole Linux demo set (only useful under -cpu max) (M1954) */
static volatile int g_lxtool_test;            /* -append lxtooltest: drive the BORROWED host toolchain in-guest (M1955) */
static volatile int g_lxnode_test;            /* -append lxnodetest: PHASE 6 -- run real Node.js in-guest (M1964) */
static volatile int g_lxinet_test;            /* -append lxinettest: AF_INET sockets (DNS + HTTP) through the ABI (M1967) */
static volatile int g_lxport;                 /* -append lxport: are two datagram sockets ever handed one local port? (M2324) */
static volatile int g_lxdrm;                  /* -append lxdrm: does the DRM render node answer the four questions Mesa asks? (M2347) */
static volatile int g_lxgl;                   /* -append lxgl: eight links from a GL call to the host iGPU (M2351) */
static volatile int g_lxdns_spawned;          /* lxdns already runs alongside the browser -- do not ALSO run the quiet-machine arms (M2321) */
static volatile int g_lxdns;                  /* -append lxdns: two hundred getaddrinfo calls, so the 1-in-N EAI_AGAIN can be SAMPLED (M2320) */
static volatile int g_fftest;                 /* -append fftest: run Firefox against our Wayland compositor (M1982) */
static volatile int g_wlraw;                  /* -append wlraw: also run the raw handshake client (M1978) */

static volatile int g_lxstress;              /* -append lxstress: hammer mmap/threads/futexes/signals (M1987) */
static volatile int g_lxcage;                /* -append lxcagetest: the huge-reservation probes, on demand (M2041) */
static volatile int g_ffwl;                   /* -append ffwl: run Firefox against our compositor and hand over to the desktop (M1985) */
/* -append ffshow: the same thing FOR LOOKING AT (M2200).
 *
 * `ffwl` is the measurement harness. It spawns Firefox and then holds the
 * framebuffer for its own diagnostics -- ninety one-second heartbeats, then up
 * to forty fifteen-second page samples -- so the window manager does not run
 * for the first ten minutes and the SCREEN shows the log the whole time. That
 * is the right trade when the output is a measurement and the wrong one when
 * somebody is sitting in front of it: the boot renders the page and the person
 * watching sees scrolling text.
 *
 * ffshow spawns Firefox exactly the same way and goes straight to the desktop.
 * The diagnostics do not stop -- console output is serial-only once the window
 * manager owns the screen (console_gfx_release), so the page probe keeps
 * reporting into boot.log from a watcher thread while the screen shows the
 * actual window. */
static volatile int g_ffshow;
static volatile int g_ffdata;                 /* -append ffdata: render a data: URL instead of the staged file, so the filesystem is not part of the question (M2107) */
/* ext2 -> blockdev cache drop (M2220). The ctx ext2 carries for a mounted
 * volume is the blockdev index, cast through a pointer the same way
 * bd_blk_read reads it back. */
static void ext2_cache_drop_hook(void *ctx, uint64_t lba, uint32_t n) {
    blockdev_drop_cache((int)(intptr_t)ctx, lba, n);
}
/* The independent second opinion, same shim shape (M2240): ext2 holds the
 * blockdev index as an opaque ctx, so the cast lives here rather than in a
 * device-agnostic file. */
static int ext2_raw_read_hook(void *ctx, uint64_t lba, uint32_t n, void *buf) {
    return blockdev_read_raw((int)(intptr_t)ctx, lba, n, buf);
}
static volatile int g_wlmt;                   /* -append wlmt: multi-threaded libwayland in the test client (M2265) */
static volatile int g_ffnowr;                 /* -append ffnowr: disable WebRender (M2264) */
static volatile int g_ffe10s;                 /* -append ffe10s: do NOT force E10S off (M2252) */
static volatile int g_lxgtk3;                 /* -append lxgtk3: a GTK3 client, the toolkit Firefox uses (M2272) */
static volatile int g_lxgtk;                  /* -append lxgtk: run zenity (GTK) instead of Firefox, for a fast input loop (M2250) */
static volatile int g_ffurl;                  /* -append ffurl: the URL comes from /disk2/ffurl.txt, which is NOT in the repo (M2241) */
static volatile int g_gtksub;                 /* -append gtksub: lxgtk3 + Gecko's empty-input-region subsurface (M2297) */
static volatile int g_ffimsimple;             /* -append ffimsimple: force GTK's pass-through input method (M2300) */
static volatile int g_ffimlog;                /* -append ffimlog: MOZ_LOG IMEHandler + KeyboardHandler (M2300) */
#define FF_MAXTABS 8                          /* URLs from ffurl.txt, one tab each (M2333) */
static volatile int g_ffnav;                  /* -append ffnav: file:///ffnav.html, one huge link -- does clicking it navigate? (M2331) */
static volatile int g_ffin;                   /* -append ffin: file:///ffinput.html, the page that makes input visible (M2296) */
static volatile int g_ffnet;                  /* -append ffnet: load a page off the real internet, so the network half of the browser is measured at all (M2210) */
/* THE ffshow WATCHER (M2200). Everything the ffwl loops printed to the screen
 * still gets printed -- just to COM1, from a thread, while the framebuffer
 * belongs to the window manager. It stops reporting once it has seen the page,
 * because after that the screen is the report. */
static void ffshow_watch_task(void) {
    extern uint64_t g_pf_count;
    unsigned long ps = lx_syscalls_made();
    uint64_t pf0 = g_pf_count;
    int seen = 0;
    for (int k = 0; k < 80; k++) {
        task_sleep_ms(15000);
        unsigned long ns = lx_syscalls_made();
        uint64_t pf1 = g_pf_count;
        uint32_t pw = 0, ph = 0;
        wl_largest_window(&pw, &ph);
        kprintf("[ffshow] t=%ds: largest window %ux%u, %u Wayland client(s), "
                "+%lu syscalls, +%lu faults\n", (k + 1) * 15, pw, ph,
                wl_clients_connected(), ns - ps, (unsigned long)(pf1 - pf0));
        /* ZERO SYSCALLS IS NOT "QUIET", IT IS STOPPED (M2202). The first
         * ffshow run to fail did it like this: 58 calls in the first fifteen
         * seconds and then not one more, no crash, no fault, for five minutes
         * -- and the watcher printed fifteen identical lines saying so without
         * once asking WHAT everything was blocked on. Ask, twice, and then
         * stop: the dumps are long and the answer does not change. */
        if (ns == ps) {
            static int dumped;
            if (dumped++ < 2) {
                int bp = app_biggest_pid();
                kprintf("[ffshow] ZERO syscalls in that interval -- every Linux thread is "
                        "blocked. Who is waiting for what:\n");
                app_wait_summary(bp > 0 ? bp : 0);
                app_futex_dump();
                lx_trace_dump_last("the last calls before everything stopped", 24);
            }
        }
        ps = ns; pf0 = pf1;
        /* THE FILESYSTEM, EVERY SAMPLE, WINDOW OR NOT (M2225). The boots that
         * need this line are the ones where nothing ever appears. */
        wl_fs_health_line();
        {   int cpid = 0, csig = lx_fatal_signal(&cpid);
            if (csig) kprintf("[ffshow] *** pid %d CRASHED with signal %d -- what is on the "
                              "screen from here is the corpse ***\n", cpid, csig); }
        /* THE FULL PAGE PROBE, EVERY SAMPLE, NOT ONCE (M2214).
         *
         * The watcher used to run wl_page_probe only until the first success,
         * because `ffwl` -- which held the framebuffer for its own diagnostics
         * -- was where the real series lived. Booting to the desktop is now the
         * rule rather than a mode (the user's: "we should almost always be
         * booting to desktop as there's no reason not to"), so the series has to
         * live HERE, on serial, where it costs the screen nothing.
         *
         * console_gfx_release means every line below goes to COM1 only once the
         * window manager owns the display, so this is the same measurement the
         * blocking loop produced and the same log a suite greps -- with the
         * machine showing the desktop the whole time. */
        if (pw >= 640 && ph >= 480) {
            {   extern void lx_syscall_top(int);
                extern void lx_syscall_time_top(int);
                lx_syscall_top(6);
                lx_syscall_time_top(6); }
            {   static uint64_t pc, psx, ph2;
                uint64_t c = 0, se = 0, h = 0, cx = 0, chh = 0;
                ata_io_stats(&c, &se, &h, &cx, &chh);
                kprintf("[diskrate] +%lu command(s), +%lu sector(s), +%lu cache hit(s) "
                        "since the last sample\n",
                        (unsigned long)(c > pc ? c - pc : 0),
                        (unsigned long)(se > psx ? se - psx : 0),
                        (unsigned long)(h > ph2 ? h - ph2 : 0));
                pc = c; psx = se; ph2 = h; }
            int onscreen = wl_page_probe(0x101820);
            if (onscreen && !seen) {
                seen = 1;
                kprintf("[time] PAGE ON SCREEN at %lu ms since boot -- it is on the "
                        "display right now; go and look at it\n", (unsigned long)timer_ms());
            }
            if (!onscreen) {
                int bp = app_biggest_pid();
                app_wait_summary(bp > 0 ? bp : 0);
            }
        }
    }
    kprintf("[ffshow] the watcher has finished its window; the desktop keeps running\n");
}

static volatile int g_wltest;                 /* -append wltest: bring the Wayland display up and run a real client (M1978) */
static volatile int g_lxdesktop;              /* -append lxdesktop: stage the Linux environment, then go straight to the desktop (M2004) */
static volatile int g_ffmozlog;               /* -append ffmozlog: ask Firefox itself where it is, via MOZ_LOG (M2010) */
static volatile int g_ffgl;                   /* -append ffgl: ask Firefox why it is not using the GPU (M2357) */
static volatile int g_ffshot;                 /* -append ffshot: Firefox headless, --screenshot to a real PNG (M2003) */
static volatile int g_lxclaude_test;          /* -append lxclaudetest: run Claude Code alone, without the Node suite ahead of it (M1970) */
/* -append lxask: THE PHASE 7 DEMO, and nothing else (M2056).
 *
 * lxclaudetest runs --version, --help and two -p attempts, which is four
 * program starts of a 214 MB Bun binary under TCG before the one that
 * matters. The north star is a single question answered, so make that a
 * target on its own: one `claude -p` in the source tree, with whatever login
 * the image happens to hold, and the whole guest side mirrored to the log.
 * Implies lxout -- there is no point running this and not being able to read
 * what it said. */
static volatile int g_lxask;
static volatile int g_lxbash;      /* -append lxbash: ask Claude Code to RUN A COMMAND, which is the Bash-tool demo (M2118) */
static volatile int g_ffnavlog;    /* -append ffnavlog: DocumentChannel logging -- costs ~26s of time-to-page (M2189) */
static volatile int g_wlspy;       /* -append wlspy: WAYLAND_DEBUG=1 in the client, because GDK_DEBUG is a no-op in a release libgdk (M2298) */
static volatile int g_lxedit;      /* -append lxedit: ask Claude Code to EDIT A FILE in OS-DEV's own tree (M2170) */
static volatile int g_termtest;               /* -append termtest: the VT/ANSI terminal self-test (M2057) */
/* -append lxhist: every 15 s, print the top syscall numbers each live Linux
 * process has made SINCE THE LAST SAMPLE (M2066). The one instrument that
 * distinguishes "parked", "looping on a timer" and "doing work" -- three
 * states that were previously all silent. */
static volatile int g_lxhist;
static volatile int g_lxbuild_test;           /* -append lxbuildtest: build OS-DEV's OWN KERNEL in-guest (M1961) */
static volatile int g_lxgcc_test;             /* -append lxgcctest: compile OS-DEV's OWN source in-guest, on its own boot (M1960) */
static volatile int g_lxtrace_make;           /* -append lxsystrace: syscall-trace the make run only -- tracing the whole boot is unreadable */
static volatile int g_lxfault_test;           /* -append lxfaulttest: also launch a binary that faults, proving a ring-3 fault mid-print is REPORTED and never deadlocks the console lock (M1941) */
static volatile int g_diskbench;               /* -append diskbench: measure one ATA command's cost in isolation (M2091) */
static volatile int g_lxabi_test;             /* -append lxabitest: launch a real Linux static-PIE binary off the ext2 volume (M1939) */
static volatile int g_netcon;                 /* -append netcon: start the network debug console on TCP 2323 (M1870, real-HW bring-up) */
static volatile int g_nodisk;                 /* -append nodisk: skip ALL disk-WRITE self-tests + FS mount (M1872) — safe to boot on a machine with real disks; the bring-up image sets this */
/* -append nonetdemo: skip the boot network self-test (M1909). net_demo() runs as a
 * BACKGROUND task whose TLS handshake ends in a CPU-bound bignum CertificateVerify
 * that is far slower than it should be, so it competes with ring-3 work for a
 * while after the desktop appears. This flag exists as a DIAGNOSTIC LEVER for
 * separating "kernel network task load" from "app networking" — it is not required
 * by any suite. It was written for a hypothesis about httpdtest's flakiness that
 * measurement then REJECTED (httpdtest passes 6/6 with the demo on, once the test
 * waits for the real listen marker), so don't read a known bug into its existence. */
static volatile int g_nonetdemo;
/* -append selftest: run the CONCURRENCY self-tests (M1912-M1915: CFS vruntime
 * charging, CMOS index/data atomicity, PCI config address/data atomicity,
 * kprintf line serialisation). Gated because together they cost ~0.9 s of boot,
 * and boot-to-desktop is a number this project deliberately keeps low (~1.5 s).
 * run-boot-tests.sh passes it, so the gate still runs them on every `make check`
 * -- it is the only consumer of their markers. */
static volatile int g_selftest;
static volatile int g_watchdog;               /* -append watchdog: arm the HW watchdog + panic-auto-reboot so a hang/crash self-heals via PXE (M1881) */
static volatile int g_wdhang;                 /* -append wdhang: deliberately wedge the CPU to prove the HW watchdog resets a true hang (M1881) */

static int __attribute__((noinline)) kstack_blow(int d) {
    volatile char buf[512];
    for (int i = 0; i < 512; i++) buf[i] = (char)(d + i);    /* real per-frame stack use */
    int r = 0;
    if (g_kstack_overflow_test) r = kstack_blow(d + 1);      /* volatile guard: recurse, but the compiler can't fold it to infinite */
    return r + buf[(unsigned)d & 511];                       /* use buf AFTER the call: not a tail call */
}
static void kstack_overflow_task(void) {
    kprintf("[kstacktest] deliberately overflowing this task's kernel stack...\n");
    volatile int sink = kstack_blow(0);
    (void)sink;                                              /* unreachable: the recursion faults into the guard page first */
}

/* W^X end-to-end check (M1501): vmm_harden_kernel marks .data/.bss no-execute, so
 * trying to EXECUTE bytes placed in a .bss buffer must fault (instruction-fetch
 * #PF). If it instead runs, W^X/NX is NOT enforced — the headline anti-code-
 * injection guarantee would be a lie. Gated behind `-append wxtest`. */
static volatile unsigned char wx_nx_buf[16];   /* uninitialised -> .bss -> NX after vmm_harden_kernel */
static void wx_test(void) {
    wx_nx_buf[0] = 0xC3;                        /* x86 RET: a valid 1-byte function, were it executable */
    kprintf("[wxtest] calling into a no-execute .bss buffer (W^X/NX must fault)...\n");
    ((void (*)(void))(void *)wx_nx_buf)();      /* NX enforced -> instruction-fetch #PF (ring-0 panic); else it returns */
    kprintf("[wxtest] FAILED: executed bytes from a no-execute data page -- W^X is NOT enforced!\n");
}

/* SMEP end-to-end check (M1502): cpu_harden sets CR4.SMEP, which forbids ring 0
 * from EXECUTING any user-accessible (PTE_USER) page — the classic ret2user
 * defence. Map such a page, put a RET in it, and call it: SMEP must fault
 * (instruction-fetch #PF) rather than run it. Gated behind `-append smeptest`. */
static void smep_test(void) {
    uint64_t va = 0xFFFF903800000000ull;        /* free scratch slot in the shared PML4[288] (between the kheap + kstack windows) */
    uint64_t frame = pmm_alloc_frame();
    if (!frame || vmm_map(va, frame, PTE_WRITABLE | PTE_USER) != 0) {   /* user-accessible + executable (no NX) */
        if (frame) pmm_free_frame(frame);
        kprintf("[smeptest] setup failed (OOM) -- skipping\n");
        return;
    }
    *(volatile unsigned char *)va = 0xC3;       /* x86 RET (SMAP is off, so ring 0 may still WRITE a user page) */
    kprintf("[smeptest] executing a ring-3 (user) page from ring 0 (SMEP must fault)...\n");
    ((void (*)(void))(void *)va)();             /* SMEP enforced -> instruction-fetch #PF (ring-0 panic); else it returns */
    kprintf("[smeptest] FAILED: the kernel executed a user page -- SMEP is NOT enforced!\n");
    vmm_unmap(va); pmm_free_frame(frame);       /* only reached if SMEP is off */
}

/* smp_thread end-to-end check (M1530): unlike smp_parallel_for's short-lived
 * "split N work items, dispatch, join" batch model, an smp_thread is a real,
 * independently-progressing kernel thread pinned to one core for its life —
 * this proves several threads spawned across cores actually run concurrently
 * (each records which core it landed on) and that smp_thread_yield() lets
 * more threads than cores share fairly (round robin within a core's ring)
 * without corrupting the shared counter they all race to increment.
 * Gated behind `-append smpthreadtest`. */
#define SMPTT_THREADS 4
#define SMPTT_ITERS   200000
struct smpthread_test_ctx { volatile long *counter; int core_seen; };
static void smpthread_test_worker(void *argp) {
    struct smpthread_test_ctx *c = argp;
    c->core_seen = smp_current_cpu();
    for (int i = 0; i < SMPTT_ITERS; i++) {
        __atomic_add_fetch(c->counter, 1, __ATOMIC_SEQ_CST);
        if ((i & 4095) == 0) smp_thread_yield();     /* give a same-core sibling a turn */
    }
}
static void smpthread_test(void) {
    kprintf("[smpthreadtest] spawning %d real kernel threads across cores...\n", SMPTT_THREADS);
    volatile long counter = 0;
    struct smpthread_test_ctx ctx[SMPTT_THREADS];
    smp_thread_t *th[SMPTT_THREADS];
    for (int i = 0; i < SMPTT_THREADS; i++) {
        ctx[i].counter = &counter; ctx[i].core_seen = -1;
        th[i] = smp_thread_spawn(smpthread_test_worker, &ctx[i]);
    }
    for (int i = 0; i < SMPTT_THREADS; i++) smp_thread_join(th[i]);

    int seen[SMPTT_THREADS], nseen = 0;
    for (int i = 0; i < SMPTT_THREADS; i++) {
        int c = ctx[i].core_seen, dup = 0;
        for (int j = 0; j < nseen; j++) if (seen[j] == c) dup = 1;
        if (!dup) seen[nseen++] = c;
        kprintf("[smpthreadtest]   thread %d ran on core apic=%d\n", i, c);
    }
    long want = (long)SMPTT_THREADS * SMPTT_ITERS;
    kprintf("[smpthreadtest] counter=%ld (want %ld), %d distinct core(s) used: %s\n",
            counter, want, nseen, counter == want ? "OK" : "MISMATCH");
}

/* General-scheduler cross-core check (M1862): smpthread_test above proves the
 * SEPARATE M1530 smp_thread mechanism (per-core-pinned kernel threads drained by
 * each AP's own ap_tick). This proves the DIFFERENT, and until now untested,
 * claim that the general M1531 CFS scheduler genuinely runs *ordinary* tasks --
 * the pin_core=-1 kind that task_create makes for every kernel thread AND every
 * ring-3 process -- concurrently across multiple cores. Each worker is spawned
 * with task_create (so it enters the shared ready ring and is migratable by any
 * core's switch_to_next, exactly like a user app), races to atomically bump a
 * shared counter, and ORs the core it observes into a shared mask. Pass = the
 * counter is EXACT (no lost/duplicated updates under real cross-core concurrency)
 * AND, when >1 CPU is online, more than one distinct core actually ran a worker.
 * Gated behind `-append smpschedtest`. */
#define SMPSCHED_TASKS 8
#define SMPSCHED_ITERS 1500000
static volatile long     smpsched_counter;
static volatile unsigned smpsched_coremask;
static volatile int      smpsched_done;
static void smpsched_worker(void) {
    for (long i = 0; i < SMPSCHED_ITERS; i++) {
        __atomic_add_fetch(&smpsched_counter, 1, __ATOMIC_SEQ_CST);
        if ((i & 8191) == 0) {                       /* sample the core we're on periodically */
            int c = smp_current_cpu() & 31;
            __atomic_or_fetch(&smpsched_coremask, 1u << c, __ATOMIC_SEQ_CST);
        }
    }
    __atomic_add_fetch(&smpsched_done, 1, __ATOMIC_SEQ_CST);
}
static void smpsched_test(void) {
    kprintf("[smpschedtest] spawning %d ordinary (pin_core=-1) tasks via the GENERAL scheduler...\n", SMPSCHED_TASKS);
    smpsched_counter = 0; smpsched_coremask = 0; smpsched_done = 0;
    for (int i = 0; i < SMPSCHED_TASKS; i++)
        task_create(smpsched_worker, 0, 0);          /* cr3=0 => kernel address space (like the kstack test) */
    uint64_t deadline = timer_ms() + 30000;          /* generous cap so a stall reports instead of hanging boot */
    while (__atomic_load_n(&smpsched_done, __ATOMIC_SEQ_CST) < SMPSCHED_TASKS && timer_ms() < deadline)
        task_yield();                                 /* task 0 is BSP-pinned; yielding lets a worker run here too */
    long want = (long)SMPSCHED_TASKS * SMPSCHED_ITERS;
    int distinct = 0;
    for (unsigned m = smpsched_coremask; m; m &= m - 1) distinct++;   /* popcount (no libgcc in the freestanding kernel) */
    int multi_ok = (smp_cpu_count <= 1) || (distinct > 1);   /* on a real uniprocessor, 1 core is correct */
    kprintf("[smpschedtest] counter=%ld (want %ld), %d distinct core(s) used (mask=0x%x, %d online): %s\n",
            smpsched_counter, want, distinct, smpsched_coremask, smp_cpu_count,
            (smpsched_counter == want && smpsched_done == SMPSCHED_TASKS && multi_ok) ? "OK" : "FAIL");
}

/* Write-ahead journal crash-recovery check on REAL ata hardware (M1865): the
 * host journaltest proves the LOGIC under fault injection; this proves the same
 * code drives an actual disk and survives a simulated power loss. mkfatfs
 * reserves the disk tail [FS_SECTORS, TOTAL_SECTORS) = [130944, 131072) OUTSIDE
 * the filesystem, so this touches only sectors the FS never uses. Journal region
 * = [130944, 130944+JRNL_MINLEN); test targets sit past it, still in the tail.
 * Gated behind `-append journalguest`. */
static int jt_read(void *ctx, uint64_t lba, void *buf)        { (void)ctx; return ata_read((uint32_t)lba, 1, buf) < 0 ? -1 : 0; }
static int jt_write(void *ctx, uint64_t lba, const void *buf) { (void)ctx; return ata_write((uint32_t)lba, 1, (void *)buf) < 0 ? -1 : 0; }
static void jt_flush(void *ctx)                               { (void)ctx; ata_cache_flush(); }
#define JT_JSTART 130944u                      /* = FS_SECTORS in tools/mkfatfs.c */
#define JT_TGT0   131010u                      /* target sectors: past [jstart, jstart+64), still inside the reserved tail */
static void journal_guest_test(void) {
    journal_t j; memset(&j, 0, sizeof j);
    j.read = jt_read; j.write = jt_write; j.flush = jt_flush;
    j.jstart = JT_JSTART; j.jlen = JRNL_MINLEN;
    uint8_t buf[512], got[512];
    int ok = 1;

    /* (1) format + a normal committed transaction: targets go OLD(0xA1) -> NEW(0xB2) */
    if (journal_format(&j) != 0) ok = 0;
    memset(buf, 0xA1, 512); ata_write(JT_TGT0, 1, buf); ata_write(JT_TGT0 + 1, 1, buf);
    journal_begin(&j);
    memset(buf, 0xB2, 512);
    journal_write(&j, JT_TGT0, buf); journal_write(&j, JT_TGT0 + 1, buf);
    int rc = journal_commit(&j);
    ata_cache_flush();
    ata_read(JT_TGT0,     1, got); int c0 = (got[0] == 0xB2 && got[511] == 0xB2);
    ata_read(JT_TGT0 + 1, 1, got); int c1 = (got[0] == 0xB2 && got[511] == 0xB2);
    int clean = (journal_recover(&j) == 0);     /* clean journal after a completed commit */

    /* (2) CRASH case: commit stops right after the commit point (dbg_crash), so
     * the targets stay OLD(0xC3) on disk but the journal holds a committed txn.
     * journal_recover() must REPLAY it, making the targets NEW(0xD4). */
    memset(buf, 0xC3, 512); ata_write(JT_TGT0, 1, buf); ata_write(JT_TGT0 + 1, 1, buf);
    ata_cache_flush();
    j.dbg_crash = 1;
    journal_begin(&j);
    memset(buf, 0xD4, 512);
    journal_write(&j, JT_TGT0, buf); journal_write(&j, JT_TGT0 + 1, buf);
    int crc = journal_commit(&j);               /* returns 2: committed, NOT checkpointed */
    j.dbg_crash = 0;
    ata_cache_flush();
    ata_read(JT_TGT0, 1, got); int pre_old = (got[0] == 0xC3);   /* checkpoint really didn't run */
    int rep = journal_recover(&j);              /* replay the committed txn */
    ata_cache_flush();
    ata_read(JT_TGT0,     1, got); int r0 = (got[0] == 0xD4 && got[511] == 0xD4);
    ata_read(JT_TGT0 + 1, 1, got); int r1 = (got[0] == 0xD4 && got[511] == 0xD4);
    int idem = (journal_recover(&j) == 0);      /* idempotent: nothing left to replay */

    if (!(rc == 0 && c0 && c1 && clean && crc == 2 && pre_old && rep == 1 && r0 && r1 && idem)) ok = 0;
    kprintf("[journalguest] commit rc=%d chk=%d,%d clean=%d | crash crc=%d preOLD=%d replay=%d new=%d,%d idem=%d: %s\n",
            rc, c0, c1, clean, crc, pre_old, rep, r0, r1, idem, ok ? "OK" : "FAIL");
}

/* THE DENOMINATOR (M2091). Every "the disk is N% of the boot" claim needs one
 * number that cannot be argued with: the cycles from the kernel's first
 * instruction to the moment being measured. Same counter the per-subsystem
 * budgets use, so a share can never exceed 100% without the instrument itself
 * being wrong -- which is the property that makes it worth printing. */
static uint64_t g_boot_tsc0;
static inline uint64_t km_tsc(void) {
    uint32_t lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* WHO IS RUNNING US -- MEASURED, NOT ASSERTED (M2343).
 *
 * What used to sit at the bottom of this function was the string "so MOST OF
 * THE BOOT IS GUEST CODE UNDER TCG, and no amount of work on the disk, the
 * faults or the console will change how long it takes." It was printed
 * whenever the largest named cost fell under half of busy -- that is, it was a
 * conclusion drawn from a residual the instrument could not account for, which
 * is exactly backwards. And it was FALSE: the machine this project develops on
 * runs KVM, so there was no TCG in the reading at all. Being wrong in the
 * confident direction, it spent months telling every reader that the work
 * which later took click-to-pixel from 224 ms to 34 ms was pointless.
 *
 * Nothing in the tree had ever asked. So ask: CPUID.1:ECX[31] is the
 * hypervisor-present bit, and leaf 0x40000000 returns a 12-byte vendor
 * signature in EBX:ECX:EDX. QEMU's emulator answers "TCGTCGTCGTCG" and its
 * accelerator answers "KVMKVMKVM\0\0\0", which is the entire distinction the
 * old line was guessing at. */
static const char *km_hypervisor(void) {
    static char sig[16];
    uint32_t a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1u), "c"(0u));
    if (!((c >> 31) & 1)) return "BARE METAL (no hypervisor-present bit)";
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0x40000000u), "c"(0u));
    if (a < 0x40000000u) return "a hypervisor that declines to name itself";
    for (int i = 0; i < 4; i++) {
        sig[i]     = (char)((b >> (i * 8)) & 0xff);
        sig[i + 4] = (char)((c >> (i * 8)) & 0xff);
        sig[i + 8] = (char)((d >> (i * 8)) & 0xff);
    }
    sig[12] = 0;
    if (sig[0] == 'T' && sig[1] == 'C' && sig[2] == 'G')
        return "QEMU TCG -- every guest instruction is EMULATED";
    if (sig[0] == 'K' && sig[1] == 'V' && sig[2] == 'M')
        return "KVM -- guest code runs NATIVE on the host CPU";
    return sig;
}
/* Print every budget against that denominator. Called at the two moments that
 * matter: when a client has painted (what the user waits for) and when the
 * desktop takes over (the end of the scrolling wall of text). */
void kmain_budget(const char *when) {
    extern uint64_t g_idle_cycles;
    extern uint64_t g_pf_count, g_pf_cycles, g_pf_repaired;
    uint64_t wall = km_tsc() - g_boot_tsc0;
    int nc = smp_cpu_count > 0 ? smp_cpu_count : 1;
    /* THE DENOMINATOR IS CORE-CYCLES, NOT WALL-CYCLES (M2091).
     *
     * Two mistakes in a row here, both worth writing down because both made
     * the instrument confidently wrong:
     *
     *  1. Dividing by wall time. The TSC runs through `hlt`, so a boot that
     *     sleeps six minutes in a heartbeat loop credited all of it to "guest
     *     code under TCG" and the budget read 91% UNATTRIBUTED.
     *  2. Subtracting a per-core idle SUM from a single-core wall time. Four
     *     cores idling for the whole boot produce four times the wall in idle
     *     cycles, so the subtraction went negative and every share came out
     *     over 100% -- disk 109%, faults 253%.
     *
     * The available budget is wall x cores; idle is already a sum over cores;
     * busy is the difference. */
    uint64_t avail = wall * (uint64_t)nc;
    uint64_t idle = g_idle_cycles;
    uint64_t busy = avail > idle ? avail - idle : 0;

    uint64_t cmds = 0, sect = 0, hits = 0, cx = 0, chh = 0;
    ata_io_stats(&cmds, &sect, &hits, &cx, &chh);
    uint64_t ch = 0, ln = 0, sc = 0, cg = 0, cs = 0;
    fbcon_stats(&ch, &ln, &sc, &cg, &cs);
    uint64_t io = cx + chh, con = cg + cs, pf = g_pf_cycles;

    kprintf("\n[budget] %s\n", when);
    kprintf("[budget]   %lu Mcycles wall x %d cores = %lu Mcycles available, %lu idle, %lu BUSY\n",
            wall / 1000000, nc, avail / 1000000, idle / 1000000, busy / 1000000);
    /* AND THESE ARE ELAPSED SUMS, NOT CPU TIME. The third instrument mistake,
     * and the one that matters most: a disk read spin-yields and a fault
     * handler can block, so the TSC delta across either spans whatever else
     * this core ran in the meantime. They are UPPER BOUNDS. A figure over
     * 100% is not a bug in the arithmetic -- it is this overlap being visible,
     * and it is why the counts below are the numbers to reason from. */
    kprintf("[budget]   these are ELAPSED sums and overlap each other and idle -- upper bounds,\n");
    kprintf("[budget]   not shares. The COUNTS are exact; reason from those.\n");
    kprintf("[budget]   disk     %7lu Mcycles elapsed   %lu commands (%lu by DMA), %lu sectors (%lu KiB), %lu cache hits\n",
            io / 1000000, cmds, ata_dma_commands(), sect, sect / 2, hits);
    if (cmds) kprintf("[budget]                                 %lu sectors per command -- 1 means every "
                      "multi-sector request is being shredded\n", sect / cmds);
    kprintf("[budget]   faults   %7lu Mcycles elapsed   %lu ring-3 faults, %lu repaired by demand paging\n",
            pf / 1000000, g_pf_count, g_pf_repaired);
    {   uint64_t maj = 0, min = 0, cow = 0, spur = 0, oth = 0;
        app_fault_kinds(&maj, &min, &cow, &spur, &oth);
        kprintf("[budget]     %8lu MAJOR   filled from a file (16-page readahead in front of them)\n", maj);
        kprintf("[budget]     %8lu MINOR   demand-zero anonymous: no readahead, no disk\n", min);
        kprintf("[budget]     %8lu COW     a write to a page inherited from a fork\n", cow);
        kprintf("[budget]     %8lu STALE   the PTE already allowed it: a stale TLB entry, invalidated and retried\n", spur);
        uint64_t named = maj + min + cow + spur;
        /* A SPLIT THAT DOES NOT ADD UP IS NOT A SPLIT. The first version of
         * this had only MAJOR and MINOR and they came to 81215 of 462065 --
         * four fifths of the biggest cost in the boot sat in a bucket nobody
         * had named. Printing the remainder is what made that visible, so it
         * stays printed even when it is zero. (M2093) */
        if (g_pf_count > named)
            kprintf("[budget]     %8lu UNCLASSIFIED -- faults the handler took that none of the above explains\n",
                    g_pf_count - named);
        {   extern uint64_t g_fsbase_repairs;
            if (g_fsbase_repairs)
                kprintf("[budget]     %8lu FS_BASE REPAIRS -- a thread found running with a ZERO TLS base\n"
                        "[budget]              against a good saved one, reloaded and retried. Each one is a\n"
                        "[budget]              crash that did not happen and a bug that is still unfound.\n",
                        g_fsbase_repairs);
        }
        if (cow > maj + min)
            kprintf("[budget]     COPY-ON-WRITE DOMINATES: the cost is fork, not the disk and not demand-zero\n");
    }
    /* AND THE CLOSEST ANY KERNEL STACK CAME TO ITS BOTTOM (M2212). The canary
     * is a tripwire that fires after the damage and only if the overrun reached
     * the very bottom; this is the margin, sampled from the timer tick across
     * the whole boot. The ext2 read path was at 90% of 16 KiB with interrupts
     * enabled across it, which is how a 4 KiB buffer in read_inode turned into
     * 204 rejected inode tables and a crash. */
    {   const char *who = "?"; uint64_t tot = 0;
        uint64_t freeb = task_stack_low_water(&who, &tot);
        if (freeb && tot)
            kprintf("[budget]   kstack   %lu byte(s) free at the deepest sample, of %lu "
                    "(%lu%% used), in '%s'%s\n",
                    (unsigned long)freeb, (unsigned long)tot,
                    (unsigned long)((tot - freeb) * 100 / tot), who,
                    freeb < tot / 8 ? "  <-- UNDER 12% LEFT: an interrupt at that depth "
                                      "can write past the bottom" : "");
        /* HOW MANY SAMPLES THAT DEPTH IS DRAWN FROM (M2238). A low-water mark
         * says nothing without the population behind it: the old bound threw
         * away every sample from a task with a non-default stack, and the
         * reading that produced looked like a healthy 3% rather than like an
         * instrument that had measured almost nothing. */
        {   extern unsigned long g_stack_samples, g_stack_offstack;
            kprintf("[budget]   kstack   from %lu on-stack sample(s), %lu discarded off-stack\n",
                    g_stack_samples, g_stack_offstack); } }
    {   extern unsigned long g_poll_naps, g_poll_nap_ms;
        /* WALL-CLOCK MILLISECONDS, not cycles, because a nap is time nobody
         * spent -- and that is exactly the quantity the 95%-idle reading is
         * asking about. Against the wall clock, not the busy total: sleeping
         * does not consume the busy budget, it extends the wall one. (M2102) */
        /* THREAD-milliseconds, and say so. The first version of this line
         * divided by a made-up "wall in ms" and printed 90677%, which is the
         * instrument describing the wrong quantity yet again: these naps are
         * CONCURRENT across threads, so their sum is thread-time and has no
         * business being compared to one wall clock. (M2102) */
        {   extern unsigned long g_poll_yields;
            /* YIELDS ARE NOT NAPS (M2111). A yield reschedules without arming
             * a timer, so it costs a context switch and not a millisecond --
             * adding the two together would inflate a figure this budget
             * reports as a share of the wall clock, which is exactly the
             * instrument mistake this campaign keeps making. */
            /* ASKED FOR vs ACTUALLY SLEPT (M2208). The first number is what
             * the nap policy requested; the second is what the 100 Hz timer
             * delivered, measured in TSC cycles. They differ by a factor of
             * two or more, because task_sleep_ms(1) parks until the NEXT TICK
             * -- 0-10 ms -- and the old line reported its own input. */
            extern unsigned long g_poll_nap_real_ms;
            kprintf("[budget]   polling  %7lu thread-ms ASKED FOR across %lu naps, %lu ACTUALLY "
                    "SLEPT (the tick is 100 Hz, so a 1 ms nap lasts until the next one), plus "
                    "%lu yields, in poll/epoll (concurrent: NOT a share of the wall clock)\n",
                    g_poll_nap_ms, g_poll_naps, g_poll_nap_real_ms, g_poll_yields);
            {   extern unsigned long g_poll_nap_woken, g_poll_nap_expired, g_poll_nap_late_ms;
                kprintf("[budget]   polling  %7lu nap(s) ended because somebody WOKE them, %lu ran "
                        "their deadline out (%lu ms of that was overshoot past what they asked "
                        "for) -- only the woken ones had work waiting\n",
                        g_poll_nap_woken, g_poll_nap_expired, g_poll_nap_late_ms); }
        }
        {   /* AND HOW LATE THE ANSWERS WERE (M2322). The naps above are what
             * this costs a waiter; this is what it cost the one waiter whose
             * deadline is set by somebody else -- glibc's resolver gives an
             * attempt two seconds and then abandons the socket. */
            extern uint64_t net_udpq_dwell_ms(void), net_udpq_slow(void), net_udpq_stale(void);
            extern uint64_t net_rx_ring_dropped(void);
            kprintf("[budget]   udp rx   worst %lu ms between a datagram landing in our queue and "
                    "the guest taking it; %lu handed over late (>200 ms); %lu aged out with "
                    "nobody left to take them; %lu frame(s) DIED in our software RX ring with no "
                    "consumer draining it (the card dropped none of these -- we did)\n",
                    (unsigned long)net_udpq_dwell_ms(), (unsigned long)net_udpq_slow(),
                    (unsigned long)net_udpq_stale(), (unsigned long)net_rx_ring_dropped());
        }
        {   extern unsigned long g_lx_dispatch_cycles;
            unsigned long n = lx_syscalls_made();
            /* ELAPSED, AND THEREFORE NOT A PER-SYSCALL COST (M2102). I wrapped
             * the dispatcher in rdtsc to find out what a syscall costs, and it
             * reported 9.4 MILLION cycles each -- a total forty times the wall
             * clock. Of course: a syscall that blocks accumulates every
             * millisecond it waits, and dozens of threads block at once, so
             * this sum is thread-time and has no per-call meaning at all.
             *
             * Fifth instrument this session to describe the wrong quantity,
             * and the same mistake each time: ELAPSED IS NOT COST WHENEVER THE
             * CODE CAN BLOCK. Kept, because "threads spent 9.4 Tcycles inside
             * syscalls" is a real statement about how much of this boot is
             * spent waiting in the kernel -- which is the question. It is just
             * not the statement I went looking for. Per-call CPU cost needs a
             * microbenchmark of a syscall that cannot block. */
            kprintf("[budget]   syscalls %7lu Mcycles of THREAD-TIME inside the Linux dispatcher "
                    "across %lu calls\n", g_lx_dispatch_cycles / 1000000, n);
            kprintf("[budget]            (elapsed, so it includes every block and overlaps itself "
                    "across threads -- NOT a per-call cost)\n");
        }
    }
    {   unsigned long ph = 0, pm = 0, pn = 0, pf2 = 0;
        ext2_path_cache_stats(&ph, &pm, &pn, &pf2);
        if (ph + pm + pn)
            kprintf("[budget]   paths    %lu resolutions served from cache (%lu of them NEGATIVE -- "
                    "a path known not to exist), %lu walked, %lu whole-cache flushes\n",
                    ph + pn, pn, pm, pf2);
    }
    kprintf("[budget]   console  %7lu Mcycles elapsed   %lu lines, %lu full-screen scrolls\n",
            con / 1000000, ln, sc);
    kprintf("[budget]   running under: %s\n", km_hypervisor());
    if (busy) {
        uint64_t named = io > pf ? io : pf;          /* the fault bucket contains the disk one */
        named += con;
        uint64_t npct = named * 100 / busy;
        if (npct > 100) npct = 100;                 /* elapsed sums can exceed busy; see above */
        uint64_t upct = 100 - npct;
        kprintf("[budget]   the largest NAMED cost is %lu Mcycles against %lu Mcycles busy: at most %lu%%\n",
                named / 1000000, busy / 1000000, npct);
        /* THE NAMED RESIDUAL. Every bucket above is something somebody
         * instrumented; this is the part nobody has. It is the only honest
         * summary line this function can print, because it is the one number
         * that says what the instrument does NOT know. */
        kprintf("[budget]   UNATTRIBUTED %lu Mcycles = %lu%% of busy -- %s\n",
                (busy - (named < busy ? named : busy)) / 1000000, upct,
                upct > 25 ? "THE BUDGET CANNOT SAY WHERE THAT WENT. Do not draw a "
                            "conclusion from it; go instrument it."
                          : "within tolerance: the named buckets do explain this boot.");
        /* AND THE SHAPE, which is the question the old line was really trying
         * to answer and answered wrong. If most of the available core-time went
         * to `hlt`, then no named cost getting cheaper can move the wall clock,
         * because nothing was waiting on a core -- it was waiting on a reply.
         * That is a measured statement about THIS boot, and it flips with the
         * measurement instead of being compiled in. */
        {   uint64_t ipct = avail ? idle * 100 / avail : 0;
            kprintf("[budget]   SHAPE: %lu%% of core-time was IDLE, so this boot is %s\n", ipct,
                    ipct >= 60 ? "LATENCY-bound: making the named work cheaper cannot"
                               : "THROUGHPUT-bound: the named work is on the critical path");
            if (ipct >= 60)
                kprintf("[budget]          move the wall clock. Find what the critical path WAITS FOR.\n");
        }
        /* The NIC's own view, because a frame this machine never received is
         * invisible to every counter above (M2365). */
        e1000_report();
    }
}

void kmain(uint64_t mb_info, uint64_t magic) {
    g_boot_tsc0 = km_tsc();
    console_init();

    /* GRUB `multiboot2` hands a tag list, not the Multiboot1 struct; convert it
     * up front so the rest of boot (pmm, framebuffer, ...) is identical. (M1293) */
    if (magic == MULTIBOOT2_MAGIC)
        mb_info = mb2_to_mb1(mb_info);

    /* Detect `-append gdbstub` NOW, before pmm_init/kheap_init can allocate over
     * the multiboot command-line string (which QEMU places in high usable RAM).
     * Just sets a flag; the actual break into the stub happens after smp_init. */
    {
        struct multiboot_info *mbi = (struct multiboot_info *)(uintptr_t)mb_info;
        const char *cl = ((mbi->flags & (1u << 2)) && mbi->cmdline) ? (const char *)(uintptr_t)mbi->cmdline : "";
        if (cmdline_has(cl, "nonetdemo"))  g_nonetdemo = 1;      /* M1909 */
        if (cmdline_has(cl, "selftest"))   g_selftest = 1;       /* M1916 */
        if (cmdline_has(cl, "gdbstub"))    gdbstub_arm();
        if (cmdline_has(cl, "kstackover")) g_kstack_overflow_test = 1;   /* deliberate KERNEL-stack overflow test (M1498) */
        if (cmdline_has(cl, "ustackover")) g_ustack_overflow_test = 1;   /* deliberate USER-stack overflow test (M1500) */
        if (cmdline_has(cl, "wxtest"))     g_wx_test = 1;                /* deliberate W^X/NX enforcement test (M1501) */
        if (cmdline_has(cl, "smeptest"))   g_smep_test = 1;              /* deliberate SMEP enforcement test (M1502) */
        if (cmdline_has(cl, "smpthreadtest")) g_smpthread_test = 1;      /* real cross-core kernel-thread test (M1530) */
        if (cmdline_has(cl, "smpschedtest"))  g_smpsched_test = 1;       /* general-scheduler cross-core migration test (M1862) */
        if (cmdline_has(cl, "journalguest"))  g_journal_test = 1;        /* on-ata write-ahead-journal crash-recovery test (M1865) */
        if (cmdline_has(cl, "fatjournaltest")) g_fatjournal_test = 1;    /* live FAT32 create crash-atomicity test (M1866) */
        if (cmdline_has(cl, "nodma")) { extern int g_ata_dma_reads; g_ata_dma_reads = 0; }   /* A/B the DMA read path (M2091) */
        if (cmdline_has(cl, "nodmawrite")) { extern int g_ata_dma_writes; g_ata_dma_writes = 0; }   /* A/B the DMA write path (M2142) */
        if (cmdline_has(cl, "ffshot")) { g_lxabi_test = 1; g_ffshot = 1; }   /* Gecko's renderer, no compositor (M2107) */
        if (cmdline_has(cl, "ffdata")) g_ffdata = 1;   /* a data: URL: take the filesystem out of it (M2107) */
        if (cmdline_has(cl, "freepoison")) { extern int g_freepoison; g_freepoison = 1;
            kprintf("[boot] freepoison: every guest frame that becomes free is filled with "
                    "0xDEADF00DDEADF00D -- if the guest faults on that, we freed a page it still maps\n"); }
        if (cmdline_has(cl, "cowbatch")) { extern int g_cow_batch; g_cow_batch = 1;
            kprintf("[boot] cowbatch: M2102's batched COW free re-enabled -- this CORRUPTS the "
                    "guest on more than one core (M2106), for bisection only\n"); }
        if (cmdline_has(cl, "e2big")) g_e2big_test = 1;               /* hammer ONE big file from every core (M2166) */
        if (cmdline_has(cl, "e2pcwiden")) { extern int g_e2pc_widen; g_e2pc_widen = 1; }  /* widen the insert window in BOTH arms (M2155) */
        if (cmdline_has(cl, "e2pcracy")) { extern int g_e2pc_racy; g_e2pc_racy = 1; }   /* the pre-M2155 racy insert (M2155) */
        if (cmdline_has(cl, "lxmapcmp")) { g_lxabi_test = 1; g_lxmapcmp = 1; }   /* whole-library mapping integrity (M2168) */
        if (cmdline_has(cl, "e2pcrace")) g_e2pcrace_test = 1;         /* concurrent ext2 path-cache test (M2155) */
        if (cmdline_has(cl, "bcachesmall")) { extern int g_bcache_small; g_bcache_small = 1; }
                                                                          /* A/B the block cache back to 64 KiB (M2154) */
        if (cmdline_has(cl, "faultvaddr")) { extern int g_fault_vaddr_test; g_fault_vaddr_test = 1; }
                                                                          /* prove the fault report's offset is objdump-able (M2153) */
        if (cmdline_has(cl, "nopathcache")) g_e2_path_cache = 0;          /* A/B the ext2 path cache (M2104) */
        if (cmdline_has(cl, "noreadrun"))   g_e2_read_runs = 0;           /* A/B the ext2 run coalescing (M2104) */
        if (cmdline_has(cl, "diskbench")) g_diskbench = 1;                /* per-command disk cost (M2091) */
        if (cmdline_has(cl, "noflush")) { extern int g_ata_write_flush; g_ata_write_flush = 0; }   /* A/B the write cache flush (M2143) */
        if (cmdline_has(cl, "lxabitest"))  g_lxabi_test = 1;              /* run a host-built static-PIE LINUX binary (M1939) */
        if (cmdline_has(cl, "lxfaulttest")) { g_lxabi_test = 1; g_lxfault_test = 1; }   /* + ONE binary that FAULTS, to prove the fault is reported and does not wedge (M1941) */
        /* The full demo set (M1954). Separate from lxfaulttest on purpose: those
         * binaries are glibc, so under QEMU's DEFAULT (no-AVX) CPU every one of
         * them faults, and five fault register-dumps over the slow serial
         * console dragged that boot past any sensible wait budget. They only do
         * useful work under -cpu max anyway, so only that boot launches them. */
        if (cmdline_has(cl, "noprobes"))   g_noprobes = 1;                /* ABI up, probe suite skipped (M2103) */
        /* ...and the other direction (M2283). M2278 turned the battery OFF
         * for the Claude demos so a stress probe could not decide whether
         * the north star ran. But the freeze that motivated it (M2277) only
         * appears on those heavier boots, and M2282 could not reproduce it
         * with the probes alone -- so debugging it needs the combination the
         * switch now forbids. `probes` forces them back on; it is parsed
         * AFTER every flag that sets g_noprobes so it always wins. */
        if (cmdline_has(cl, "probes"))     g_force_probes = 1;
        if (cmdline_has(cl, "lxfulltest")) { g_lxabi_test = 1; g_lxfault_test = 1; g_lxfull_test = 1; }
        if (cmdline_has(cl, "lxtooltest")) { g_lxabi_test = 1; g_lxtool_test = 1; }   /* toolchain only: no glibc demo binaries, no fault dumps */
        if (cmdline_has(cl, "futextrace")) { extern int g_futex_trace; g_futex_trace = 1; }   /* log every futex wait/wake (M1997) */
        if (cmdline_has(cl, "lxout")) { extern int g_lx_out_log; g_lx_out_log = 1; }   /* guest output -> the log, as TEXT (M2023) */
        if (cmdline_has(cl, "lxnettrace")) g_net_trace = 1;              /* socket byte counts, both directions (M2016) */
        if (cmdline_has(cl, "polltrace")) { extern int g_poll_trace; g_poll_trace = 1; }     /* name the fds a stalled poll waits on (M1998) */
        if (cmdline_has(cl, "vmaaudit"))   { extern int g_vma_audit; g_vma_audit = 1; }   /* check the no-overlap invariant on every mmap/munmap (M1988) */
        if (cmdline_has(cl, "lxstress"))   { g_lxabi_test = 1; g_lxstress = 1; }   /* mmap/thread/futex churn, on its own boot (M1987) */
        if (cmdline_has(cl, "lxcagetest")) { g_lxabi_test = 1; g_lxcage = 1; }    /* the 8 GiB reservation probes (M2041) */
        if (cmdline_has(cl, "lxnodetest"))  { g_lxabi_test = 1; g_lxnode_test = 1; }    /* its own boot: Node is 102 MB (M1964) */
        if (cmdline_has(cl, "lxinettest")) { g_lxabi_test = 1; g_lxinet_test = 1; }    /* AF_INET sockets: needs a NIC and the real internet (M1967) */
        if (cmdline_has(cl, "lxport"))     { g_lxabi_test = 1; g_lxport = 1; }   /* the ephemeral port allocator race (M2324) */
        /* NOT g_lxabi_test. These two run from their own site after
         * virtio_gpu_init, not from the lxabi block, so setting that flag only
         * made every boot of a GPU probe run the whole thirty-probe ABI suite
         * first -- a minute and a half of unrelated work per measurement, on a
         * loop whose round trip is already several minutes. */
        if (cmdline_has(cl, "lxdrm"))      g_lxdrm = 1;    /* the DRM render node, asked directly (M2347) */
        if (cmdline_has(cl, "lxgl"))       g_lxgl = 1;     /* EGL -> Mesa virgl -> the host GPU (M2351) */
        /* -append ffgpu: advertise wl_drm and let Firefox take the hardware
         * path. OFF by default because it currently costs the page entirely
         * (M2358) -- see the note on g_wl_drm_enable in wayland.c. */
        if (cmdline_has(cl, "ffgpu"))    { extern int g_wl_drm_enable; g_wl_drm_enable = 1; }
        if (cmdline_has(cl, "lxdns"))      { g_lxabi_test = 1; g_lxdns = 1; }    /* hammer getaddrinfo instead of sampling it ten times per Claude boot (M2320) */
        if (cmdline_has(cl, "wlraw"))      g_wlraw = 1;
        if (cmdline_has(cl, "fftest"))     { g_lxabi_test = 1; g_wltest = 1; g_fftest = 1; }
        /* BOOTING TO THE DESKTOP IS THE RULE, NOT A MODE (M2214).
         *
         * The user's, and it is a hard one: "we should almost always be booting
         * to desktop as there's no reason not to." There genuinely is no reason:
         * console output is serial-only once the window manager owns the screen
         * (console_gfx_release), so a boot that hands over loses nothing from
         * the log and gains a machine somebody can look at. `ffwl` held the
         * framebuffer for ninety one-second heartbeats and then up to forty
         * fifteen-second page samples -- ten minutes of scrolling text on a boot
         * that had already rendered the page, which is exactly what the user was
         * staring at when they asked where Firefox was.
         *
         * So `ffwl`, `ffnet` and `ffshow` are one thing now, and the diagnostics
         * run on a watcher thread (ffshow_watch_task) printing the same series
         * to COM1. `ffhold` is the escape hatch for the rare boot that dies
         * before the desktop starts and therefore needs the log ON SCREEN. */
        /* `ffurl` SELECTS A URL, SO IT MUST ALSO SELECT THE MODE (M2241).
         * The first cut set g_ffurl and nothing else, so `-append ffurl`
         * booted to a desktop with no browser in it at all -- the flag that
         * spawns Firefox is this one, and a URL with no spawn is not a mode. */
        if (cmdline_has(cl, "ffwl") || cmdline_has(cl, "ffshow") ||
            cmdline_has(cl, "ffnet") || cmdline_has(cl, "ffurl") ||
            cmdline_has(cl, "ffin") || cmdline_has(cl, "ffnav") || cmdline_has(cl, "gtksub")) {
            g_lxabi_test = 1; g_wltest = 1; g_ffwl = 1; g_ffshow = 1; g_noprobes = 1;
        }
        /* -append ffalone: Firefox as the ONLY Wayland client (M2287).
         *
         * Every Firefox boot also starts lxwl, so the compositor always has
         * at least two clients and the focus machinery always has a choice to
         * make. M2275 and M2281 made that choice the window manager's rather
         * than a size heuristic, which should make it moot -- but "should"
         * is what the last ten hours have been made of. One flag removes the
         * variable instead of arguing that it does not matter. */
        if (cmdline_has(cl, "ffalone")) g_wltest = 0;
        if (cmdline_has(cl, "ffurl")) g_ffurl = 1;
        if (cmdline_has(cl, "ffptroot")) { extern int g_ptr_focus_root; g_ptr_focus_root = 1; }   /* pointer focus on the toplevel (M2248) */
        if (cmdline_has(cl, "ffe10s")) g_ffe10s = 1;
        if (cmdline_has(cl, "ffnowr")) g_ffnowr = 1;
        if (cmdline_has(cl, "wlmt")) g_wlmt = 1;   /* the test client, Gecko-shaped: two threads on one display (M2265) */   /* no WebRender: no renderer-owned Wayland queue (M2264) */   /* leave content processes ENABLED (M2252) */
        if (cmdline_has(cl, "gtksub")) { g_lxgtk3 = 1; g_gtksub = 1; }   /* the control, in Gecko's shape (M2297) */
        if (cmdline_has(cl, "lxgtk3")) g_lxgtk3 = 1;   /* the GTK3 control -- the toolkit Firefox actually uses (M2272) */
        if (cmdline_has(cl, "lxgtk")) g_lxgtk = 1;   /* a tiny GTK client instead of Firefox (M2250) */   /* URL from a file in the image, never from the source tree (M2241) */
        if (cmdline_has(cl, "ffnet"))      g_ffnet = 1;                   /* ...against a REAL URL (M2210) */
        if (cmdline_has(cl, "ffimsimple")) g_ffimsimple = 1;   /* GTK_IM_MODULE=gtk-im-context-simple (M2300) */
        if (cmdline_has(cl, "ffimlog"))    g_ffimlog = 1;      /* Gecko's IME + keyboard log (M2300) */
        if (cmdline_has(cl, "ffin"))       g_ffin = 1;                    /* the CSS-only input probe page (M2296) */
        if (cmdline_has(cl, "ffnav"))      g_ffnav = 1;                   /* one huge link, and a destination with a distinct title (M2331) */
        if (cmdline_has(cl, "ffhold"))     { g_lxabi_test = 1; g_wltest = 1; g_ffwl = 1;
                                             g_ffshow = 0; }              /* the old screen-holding diagnostics (M2214) */
        if (cmdline_has(cl, "lxdesktop")) { g_lxabi_test = 1; g_lxdesktop = 1; }   /* the Linux environment + the desktop, no tests (M2004) */
        if (cmdline_has(cl, "ffmozlog"))   g_ffmozlog = 1;                /* + Firefox's OWN widget/Wayland logging, to stderr (M2010) */
        /* AND ffgl IMPLIES lxout (M2357). The first ffgl run produced the line
         * `[lx] env[33] = MOZ_LOG=timestamp,sync,DocumentChannel:5,...` -- so
         * the spec reached the process -- and then NOTHING, not even from the
         * DocumentChannel control that exists precisely to prove the mechanism
         * works. The reason was not Firefox: MOZ_LOG writes to stderr, and
         * guest stderr only reaches this log when `lxout` is on. A diagnostic
         * flag that cannot deliver its own output is worse than no flag,
         * because its silence reads as an answer. */
        if (cmdline_has(cl, "ffgl"))     { g_ffgl = 1; extern int g_lx_out_log; g_lx_out_log = 1; }
        if (cmdline_has(cl, "ffshot"))     { g_lxabi_test = 1; g_ffshot = 1; }   /* Firefox HEADLESS, rendering a page to a PNG (M2003) */
        if (cmdline_has(cl, "wlverbose")) { g_wl_verbose = 1; g_unix_verbose = 1; }
        if (cmdline_has(cl, "wltest"))     { g_lxabi_test = 1; g_wltest = 1; }   /* Wayland: compositor + a real libwayland client (M1978) */
        if (cmdline_has(cl, "lxclaudetest")) { g_lxabi_test = 1; g_lxclaude_test = 1; }  /* Claude Code ALONE: the Node suite ahead of it costs 20 minutes per attempt (M1970) */
        if (cmdline_has(cl, "termtest")) g_termtest = 1;                               /* assert on the terminal's CELLS (M2057) */
        if (cmdline_has(cl, "lxhist")) { g_lxhist = 1; extern int g_lx_syshist; g_lx_syshist = 1; }
        if (cmdline_has(cl, "lxkeys")) { extern int g_lx_keytrace; g_lx_keytrace = 1; }   /* the bytes a TUI actually receives (M2078) */
        /* BISECT SWITCHES FOR A FOREIGN RUNTIME (M2073). JSC reads its options
         * from the environment, so turning its JIT or its concurrent collector
         * off is the cheapest way to ask which of them is involved in a heap
         * corruption -- and the answer is one bit, where the fault address has
         * so far given none. */
        if (cmdline_has(cl, "lxnojit"))  g_lx_env_cmdline[0] = "BUN_JSC_useJIT=0";
        if (cmdline_has(cl, "lxnogc"))   g_lx_env_cmdline[1] = "BUN_JSC_useConcurrentGC=0";
        if (cmdline_has(cl, "lxnogen"))  g_lx_env_cmdline[2] = "BUN_JSC_useGenerationalGC=0";   /* what each Linux process is actually doing (M2066) */
        /* MAKE MESA EXPLAIN ITSELF (M2351). A GL driver that cannot use the
         * hardware falls back to software and says so only at debug level --
         * precisely the failure this campaign must be able to see, because
         * "it is slow" is the same symptom as "the ioctl is wrong". */
        if (cmdline_has(cl, "glverbose")) {
            g_lx_env_cmdline[3] = "EGL_LOG_LEVEL=debug";
            g_lx_env_cmdline[4] = "MESA_DEBUG=1";
            /* LIBGL_DEBUG is what turns on the LOADER's own log -- the part
             * that says which driver name it derived and where it looked --
             * and that is the layer reporting "DRI2: failed to load driver"
             * with no reason attached. */
            g_lx_env_cmdline[5] = "LIBGL_DEBUG=verbose";
        }
        /* THE PHASE 7 DEMO IS NOT GATED ON A 120-THREAD STRESS PROBE (M2278).
         *
         * lxask/lxbash/lxedit set g_lxabi_test, which runs the whole ABI
         * probe battery FIRST -- forty-odd programs ending in a 120-thread
         * TLS stress test. Measured over six 8-core boots: the demo answered
         * correctly in under 60 s on four of them, and the other two never
         * reached it, because that probe froze the machine in concurrent
         * mmap (M2277). So the reliability of the north-star demo was being
         * set by scaffolding that has nothing to do with it.
         *
         * ffwl has skipped the battery since M2103 for exactly this reason.
         * The probes still run on their own flags and in `make check`; they
         * simply no longer stand between a boot and the thing it is for.
         * This does NOT paper over M2277 -- that freeze is a real allocator
         * bug and is still open -- it stops one bug's blast radius covering
         * a demo it has no business touching. */
        if (cmdline_has(cl, "lxbash")) { g_lxabi_test = 1; g_lxask = 1; g_lxbash = 1; g_noprobes = 1; }   /* the Bash-tool demo (M2118) */
        if (cmdline_has(cl, "ffnavlog")) g_ffnavlog = 1;              /* navigation logging, at ~26s of time-to-page (M2189) */
        if (cmdline_has(cl, "wlspy")) g_wlspy = 1;                    /* libwayland's own event trace inside the client (M2298) */
        if (cmdline_has(cl, "lxedit")) { g_lxabi_test = 1; g_lxask = 1; g_lxedit = 1;  g_noprobes = 1;}   /* the file-EDIT demo (M2170) */
        if (cmdline_has(cl, "lxask")) { g_lxabi_test = 1; g_lxask = 1;                 /* ONE claude -p, the Phase 7 demo (M2056) */
                                        extern int g_lx_out_log; g_lx_out_log = 1;  g_noprobes = 1;}
        if (g_force_probes) g_noprobes = 0;   /* `probes` beats every skip (M2283) */
        if (cmdline_has(cl, "lxbuildtest")) { g_lxabi_test = 1; g_lxbuild_test = 1; }   /* the Phase 5 demo: minutes of in-guest compiling, its own boot (M1961) */
        if (cmdline_has(cl, "lxgcctest"))  { g_lxabi_test = 1; g_lxgcc_test = 1; }            /* its OWN boot: compiling kernel/elf.c under TCG is minutes of work, and piling it onto lxtooltest made that boot flaky (M1960) */
        if (cmdline_has(cl, "lxmmaptrace")) g_lx_mmap_trace = 1;        /* trace every Linux mmap/mprotect (M1955) */
        if (cmdline_has(cl, "lxsystrace")) g_lxtrace_make = 1;          /* trace every Linux syscall, but only around the make run (M1958) */
        if (cmdline_has(cl, "netcon"))     g_netcon = 1;                 /* network debug console for real-HW bring-up (M1870) */
        if (cmdline_has(cl, "nodisk"))     g_nodisk = 1;                 /* skip disk-write self-tests + FS mount — safe on a machine with real disks (M1872) */
        if (cmdline_has(cl, "watchdog"))   g_watchdog = 1;              /* HW watchdog + panic-auto-reboot for the autonomous PXE loop (M1881) */
        if (cmdline_has(cl, "wdhang"))     g_wdhang = 1;               /* deliberate CPU wedge to prove the watchdog resets a hang (M1881) */
    }
    vga_set_color(VGA_LIGHT_CYAN, VGA_BLACK);
    kprintf("OS-DEV  -  x86_64 kernel\n");
    vga_set_color(VGA_LIGHT_GREY, VGA_BLACK);
    kprintf("========================\n\n");

    gdt_init();
    interrupts_init();
    linux_abi_init_this_cpu();   /* arm the `syscall` instruction on the BSP (M1938) */
    fpu_init();                    /* enable x87 + SSE so userspace can use floating point */
    { extern void fpu_xsave_arm(void); fpu_xsave_arm(); }   /* + AVX via XSAVE where the CPU has it (M1942) */
    cpu_harden();                  /* SMEP + UMIP: kernel can't run ring-3 pages; ring-3 can't SGDT/etc (M1269) */
    timer_init(100);
    keyboard_init();
    interrupts_enable();
    /* AFTER interrupts are on, because calibration WAITS FOR PIT TICKS -- with
     * them still masked it would spin for ever on a counter nothing increments.
     * Gives the monotonic clock real resolution before anything measures
     * anything: the PIT alone moves in 10 ms steps, which is coarser than the
     * 16.7 ms frame interval a browser's refresh driver tries to measure.
     * (M2114) */
    timer_calibrate_tsc();
    serial_enable_rx_irq();        /* let the serial line feed keyboard input */
    pmm_init(mb_info);
    vmm_init();
    kheap_init();
    acpi_init();                   /* find the ACPI tables for clean poweroff/reboot (uses hhdm) */
    hpet_init();                   /* high-resolution clocksource via the ACPI HPET table (M1273) */
    smp_init();                    /* enable the LAPIC + bring the other cores online (M1197) */
    ioapic_init();                 /* M1856: locate + map the I/O APIC (foundation for interrupt-driven I/O; entries masked, PIC still live) */
    /* Move the live ISA IRQs off the 8259 PIC onto the I/O APIC. M1857 did this
     * for the keyboard alone, to prove the LAPIC-EOI delivery path end to end;
     * M1890 finishes the job for every ISA line whose handler is already
     * installed by this point — the PIT tick (IRQ0, the scheduler's heartbeat)
     * and the serial RX line (IRQ4) — now that the redirection entries honour
     * the MADT override's polarity/trigger flags instead of assuming
     * edge/active-high. The mouse (IRQ12) and the NIC's PCI line route
     * themselves at their own init, which runs later. Handlers are unchanged;
     * only the delivery path and the EOI target move. */
    if (ioapic_present()) {
        irq_route_ioapic(0);       /* PIT tick — usually MADT-overridden to GSI 2 */
        irq_route_ioapic(1);       /* keyboard (M1857) */
        irq_route_ioapic(4);       /* serial RX */
        kprintf("[ ok ] ISA IRQs 0 (PIT), 1 (keyboard), 4 (serial) routed via the I/O APIC "
                "(off the 8259 PIC; GSI + polarity/trigger from the ACPI MADT).\n\n");
    }

    /* Arm the hardware watchdog + panic-auto-reboot now (interrupts/timer are up,
     * so the PIT IRQ can pet it) — covers the desktop, the device battery, and
     * steady state. On the PXE bring-up box a hang/crash self-heals into a fresh
     * kernel; a normal boot (no `watchdog` flag) is unaffected. (M1881) */
    if (g_watchdog)
        watchdog_enable(20);
    /* -append wdhang: deliberately wedge the CPU (no more timer IRQs -> no pets) to
     * prove the hardware watchdog resets a true hang. Never set in normal use. */
    if (g_wdhang) { kprintf("[wdhang] wedging the CPU to test the watchdog...\n"); for (;;) __asm__ volatile("cli; hlt"); }

    /* GDB remote-serial stub (M1204): if `-append gdbstub` was seen (detected at
     * the top of kmain, before allocations could clobber the cmdline), break into
     * the stub here so a host gdb can attach over COM2 — kmain int3's and the #BP
     * handler runs the RSP loop. `continue`/`detach` from gdb resumes the boot. */
    if (gdbstub_armed()) {
        kprintf("[gdbstub] waiting for gdb on COM2 (target remote :PORT); 'continue' resumes boot\n");
        __asm__ volatile("int3");
    }

    random_init();                 /* seed the CSPRNG from RDSEED/RDRAND (TSC fallback) */
    vdso_init();                   /* alloc the vDSO time page + seed the wall clock from the RTC (M1111) */

    /* Measured boot (M1096): fold the kernel's read-only image (.text+.rodata,
     * which includes every embedded app ELF) into PCR0 before anything runs.
     * Each app then extends PCR1 at spawn, building a replayable attestation log. */
    {
        extern char _kimage_start[], _kimage_end[];
        measure_init();
        measure_extend(PCR_KERNEL, _kimage_start, (uint64_t)(_kimage_end - _kimage_start), "kernel");
    }

    /* W^X: split the boot huge-pages over the kernel image into 4 KiB pages and
     * tighten them — .text read-only+executable, .rodata read-only+NX, .data/.bss/
     * stack writable+NX (the eBPF/module .jitexec scratch stays RWX). Done here:
     * pmm/vmm are up and we are still single-threaded in the kernel address space. */
    vmm_harden_kernel();
    kstack_selftest();             /* prove the guarded task-stack guard pages are really unmapped (M1495) */

    sched_init();

    /* On real hardware / a GRUB ISO, the bootloader honors our Multiboot header's
     * video request and reports a linear framebuffer here; use it. (QEMU -kernel
     * honors the request too, so this path is exercised under QEMU as well.) If
     * absent/unusable, fbcon_init falls back to the Bochs std-VGA mode-set. (M1292) */
    {
        struct multiboot_info *fbi = (struct multiboot_info *)(uintptr_t)mb_info;
        if ((fbi->flags & MULTIBOOT_FLAG_FB) && fbi->framebuffer_type == 1 &&
            fb_init_mb(fbi->framebuffer_addr, (int)fbi->framebuffer_width,
                       (int)fbi->framebuffer_height, (int)fbi->framebuffer_pitch,
                       fbi->framebuffer_bpp) == 0)
            kprintf("[ ok ] Multiboot framebuffer %ux%u %u-bpp @ %p -- bare-metal graphics path\n",
                    fbi->framebuffer_width, fbi->framebuffer_height, fbi->framebuffer_bpp,
                    (void *)(uintptr_t)fbi->framebuffer_addr);
    }

    /* Switch the console to the framebuffer: from here, all output renders
     * graphically with a real font. */
    if (fbcon_init() == 0) {
        console_enable_gfx();
        vga_set_color(VGA_LIGHT_CYAN, VGA_BLACK);   /* (no-op in gfx, harmless) */
    }

    kprintf("OS-DEV  -  x86_64 kernel  (graphical console)\n");
    kprintf("=============================================\n\n");
    /* Late, not during smp_init: the APs have to be running their idle loops
     * with interrupts on before any of them can ack. Doing it at bring-up
     * caught the first version spinning 15.9 SECONDS for acks that were never
     * coming, which is exactly the failure this is here to make obvious. */
    smp_tlb_shootdown_selftest();
    kprintf("[ ok ] full bring-up complete (%lu MiB RAM).\n\n",
            pmm_total_bytes() / (1024 * 1024));

    if (g_kstack_overflow_test)            /* -append kstackover: prove the KERNEL guarded-stack fault path end-to-end (M1498) */
        task_create(kstack_overflow_task, 0, 0);
    if (g_ustack_overflow_test)            /* -append ustackover: prove the ring-3 USER-stack guard page (M1499/M1500) */
        app_spawn_named_arg("crash", "stack");
    if (g_wx_test)                         /* -append wxtest: prove W^X/NX is enforced -- executing data must fault (M1501) */
        wx_test();
    if (g_smep_test)                       /* -append smeptest: prove SMEP -- ring 0 executing a user page must fault (M1502) */
        smep_test();
    if (g_smpthread_test)                  /* -append smpthreadtest: prove real cross-core kernel threads (M1530) */
        smpthread_test();
    if (g_smpsched_test)                   /* -append smpschedtest: prove the general scheduler migrates ordinary tasks across cores (M1862) */
        smpsched_test();
    if (g_journal_test)                    /* -append journalguest: prove the write-ahead journal + crash recovery on real ata (M1865) */
        journal_guest_test();
    /* g_fatjournal_test runs AFTER fat32_mount() below (it needs the FS mounted) */

    preemption_demo();
    isolation_demo();

    kprintf("[ ok ] PCI devices on the bus:\n");
    pci_enumerate();
    kprintf("\n");

    audio_init();     /* bring up audio: HDA if present, else AC'97 (no-op if neither) */
    kprintf("[ ok ] audio output: %s\n", audio_name());
    hda_selftest();   /* if HDA is active: prove the stream DMA advances (no-op otherwise) */

    /* Bring up virtio-net (the paravirtual NIC) and log its MAC if present — a
     * no-op if no virtio network device is attached. net_demo()'s nic_init()
     * binds whichever NIC is present (e1000, then rtl8139, then this); the call
     * here is idempotent and just surfaces the MAC before the stack demo runs. */
    virtio_net_init();
    virtio_net_selftest();

    bpf_jit_selftest();            /* prove the eBPF JIT matches the interpreter (M1290) */

    /* net_demo() does REAL network round-trips (ARP, 3x ICMP ping, an HTTP GET,
     * and a full TLS 1.3 handshake, all to the real internet) to prove the
     * network/TLS stack at every boot -- valuable, but there's no reason a
     * user has to stare at a blank screen for it: internet round-trip latency
     * made this alone ~2.5s of the boot, more than any other single thing.
     * Spawn it as a background kernel task instead (same pattern as the
     * ring-3 browser's fetch worker, M1487) so the rest of boot -- and the
     * desktop itself -- proceeds immediately; the ARP/ping/HTTP/TLS results
     * still land in the serial log a couple seconds later, just concurrently
     * with an already-usable desktop instead of blocking it. */
    /* 512K, not the default task_create() stack (bumped from 256K, M1530):
     * net_demo() calls tls_get(), which runs the bignum/RSA/ECDSA TLS 1.3
     * handshake on THIS task's kernel stack -- the exact scenario that
     * overflowed a 64K stack for the ring-3 browser's fetch worker (M1491)
     * and corrupted the task ring. 256K was matched to everywhere else this
     * same pattern occurs (kernel/app.c, kernel/browser.c) and was sufficient
     * for a single sequential chain-link verify -- but M1528's smp_parallel_for
     * chain-verify hit a real, in-guest, live-network kernel stack overflow
     * even at 256K (nested interrupts during a busy-wait join can stack up
     * real depth on top of ECDSA's own call chain in a way a quiet `make
     * check` run doesn't reliably exercise). Bumped with real headroom rather
     * than the smallest number that happens to stop reproducing it. */
    /* GET AN ADDRESS BEFORE ANYTHING USES THE NETWORK (M2125).
     *
     * net_demo runs as a TASK, and M2120 put net_dhcp() inside it -- so the
     * lease was acquired concurrently with everything else the boot goes on to
     * do, including launching Linux programs. A guest that sent a datagram in
     * that window used the SLIRP default 10.0.2.15 as its source address, and
     * the reply went to a host that does not exist on this segment. The
     * evidence was in the receive log all along, in the parenthesis nobody was
     * reading:
     *
     *   [udpq] NOT OURS: dst 192.168.1.255 port 32412 (we are 10.0.2.15)
     *   ...
     *   [udpq] NOT OURS: dst 192.168.1.255 port 32412 (we are 192.168.1.224)
     *
     * -- the address changed HALFWAY THROUGH the boot. And it explains why
     * `-append nonetdemo` worked while the default did not: the nonetdemo
     * branch below does its DHCP synchronously, in this thread, before any
     * program runs.
     *
     * So bring the interface up and lease an address HERE, synchronously, for
     * every configuration. An address is not a diagnostic and has no business
     * being acquired by one. */
    if (!g_netcon) {
        int nr = nic_init();                       /* idempotent since M2125 */
        int leased = (nr == 0) && (net_dhcp() == 0);
        const uint8_t *bip = net_ip();
        kprintf("[net] %s up, IP = %u.%u.%u.%u (%s)\n",
                nr == 0 ? nic_name() : "no NIC",
                bip[0], bip[1], bip[2], bip[3],
                leased ? "DHCP" : "no lease -- SLIRP default, only valid under QEMU user-mode");
    }
    /* BEING REACHABLE IS NOT A SERVICE ANY ONE CONSUMER CAN PROVIDE (M2127).
     * M2126 made every loop that takes a frame off the card answer ARP for this
     * host. That still leaves the case where no loop is running at all -- the
     * desktop idle, no socket open -- and the router's ARP request sits unread
     * in the software queue until its neighbour entry for us expires and the
     * machine drops off its own LAN. So this runs for EVERY configuration,
     * including netcon and nonetdemo: it is not a diagnostic. */
    if (nic_name() && nic_name()[0])
        task_create_stack(net_rx_service, 0, 0, 64 * 1024);
    if (!g_netcon && !g_nonetdemo)
        task_create_stack(net_demo, 0, 0, 512 * 1024);
    else if (g_nonetdemo) {
        /* nic_init() lives INSIDE net_demo() (and inside netcon), so skipping the
         * demo without this leaves the NIC uninitialised and every later network
         * user dead — the first attempt at this flag turned httpdtest from flaky
         * into failing 100%. */
        /* The address was already leased above, synchronously, for every
         * configuration (M2125). */
        int nr = nic_init();
        /* (historical note) net_dhcp() lived inside
         * net_demo, so `nonetdemo` -- which every test in the tree passes --
         * skipped the lease as well as the self-test and left the machine on
         * the SLIRP default. That is right under QEMU user-mode networking and
         * useless on real hardware, so a flag meant to skip a diagnostic was
         * quietly deciding whether the machine had an address at all.
         *
         * Separating them also makes the guest's network testable with no
         * prior kernel traffic on the wire, which is the one configuration
         * that has not been tried while chasing why a guest datagram gets no
         * reply in a boot where the kernel's own does. */
        kprintf("[net] boot network self-test skipped (-append nonetdemo); NIC %s\n\n",
                nr == 0 ? "initialised" : "absent");
    }

    /* Network debug console (M1870): a kernel task listening on TCP 2323 that
     * serves a remote inspection shell (dmesg/ps/mem/pci/ls/cat/reboot/...). Built
     * for real-hardware bring-up — if the framebuffer handoff doesn't light up the
     * screen on a physical box, this is the window into the machine over ethernet.
     * It blocks in accept (sleeping the core) until a client connects, so it costs
     * nothing at idle; it shares net.c's single server-conn slot, so don't run it
     * alongside wsserve/on-demand httpd.
     *
     * OPT-IN (`-append netcon`), not default — and it REPLACES net_demo (above)
     * rather than running beside it. The net stack has no cross-connection RX demux
     * (every receiver polls nic_receive directly), and the NIC drivers' RX rings
     * aren't safe for two concurrent pollers — an always-listening console racing
     * net_demo's boot self-test faulted the box on real hardware. So on a netcon
     * boot, netcon_task owns bring-up (its own nic_init + DHCP + listen) and the
     * internet self-test is skipped; a normal desktop boot runs net_demo and leaves
     * netcon off. The bring-up image bakes `netcon` into its kernel cmdline, so the
     * console is up even if the framebuffer stays dark. */
    if (g_netcon)
        task_create(netcon_task, 0, 0);

    /* Mount the FAT32 disk and show it works from the kernel side. Skipped under
     * `nodisk` (real-HW bring-up): fat32_mount reads a real disk to validate it,
     * and a match would arm the write-ahead journal on it — neither is wanted when
     * the attached disks hold someone else's data. */
    /* -append lxabitest (M1939): launch a REAL Linux binary. Deliberately does
     * not need the keyboard, so the whole check is a COM1 assertion -- the
     * Linux write(2) lands on the kernel console, which is mirrored to serial,
     * unlike ring-3 print() from our own apps. */
    /* BRING UP EVERY DISK BEFORE ANYTHING MOUNTS ONE (M2145).
     *
     * virtio_blk_init() used to run ~1600 lines below this, which is fine
     * while the Linux root lives on ATA and pointless work otherwise -- and
     * fatal once it does not. With the root moved to virtio-blk the mount
     * table came out as:
     *
     *   [mount] disk1 = blockdev 0 (ata0) at LBA 0, fstype fat
     *   [lxabi] root /disk2: vfs_stat FAILED
     *   [mount] disk2 = blockdev 1 (virtio-blk) at LBA 0, fstype ext2
     *
     * The root was stat'd BEFORE the device it lives on existed. M2144's
     * late-device rescan is what let it mount at all; this is what makes it
     * mount in time. The call below is idempotent, so the original site can
     * stay where it is and keep its self-test. */
    /* THE BLOCK CACHE, BEFORE ANYTHING READS A DISK IN EARNEST (M2154). The
     * heap and the pmm are both up (line ~765), and every mount, path walk and
     * demand-paged library read after this point gets the big pool instead of
     * the 64 KiB one. */
    { extern void bcache_init(void); bcache_init(); }

    virtio_blk_init();

    /* AND THE GPU BEFORE ANYTHING THAT DECIDES WHETHER THERE IS ONE (M2358).
     *
     * virtio_gpu_init() ran at line ~3806, ELEVEN HUNDRED LINES after Firefox
     * is spawned at ~2661. So when app.c built the environment for it,
     * `virtio_gpu_has_3d()` was false and M2352's conditional handed Firefox
     * LIBGL_ALWAYS_SOFTWARE=1 -- on a boot where the GPU works. Mesa's
     * `dri2_initialize_wayland` reads that as ForceSoftware and goes straight
     * to `dri2_initialize_wayland_swrast`, never binding the wl_drm global we
     * had just added for it. Symptom: our own test client logs
     * `LXWL-GLOBAL: wl_drm v2 (name 9)` on the same boot where Firefox never
     * binds it and never issues a single DRM ioctl.
     *
     * EXACTLY the shape of M2347's `lxdrm` probe asking a true question before
     * the answer could be yes -- second time in one session, and both times a
     * capability query ran earlier in kmain than the capability. A feature
     * test is only meaningful after the feature exists, so the feature has to
     * come up before anything that tests it. The init is idempotent and the
     * original call site keeps its self-test. */
    virtio_gpu_init();

    if (g_lxabi_test) {
        /* FIRST, because every other probe in this block -- and every program
         * the kernel will ever run -- depends on it, and because the suite
         * below it intermittently wedges. JSC's parallel marker crashed on a
         * JSValue of 0x9000900090: a repeating 16-bit pattern, which is what
         * recycled memory looks like and what zeroed memory does not. A
         * garbage collector reads every word it ever allocated, so it is the
         * most sensitive consumer of "anonymous memory arrives zero" in the
         * system and the least able to name the page that was wrong. */
        /* -append noprobes: skip the SUITE, keep the ABI (M2103). Everything
         * above this point is the ABI coming up and is not optional; from here
         * to the stress block is the probe suite, which a Firefox measurement
         * has no use for. */
        if (g_noprobes) goto probes_done;
        kprintf("[lxabi] launching the zero-fill/COW probe...\n");
        {   int zrc = app_run_linux_sync("/disk2/lxzero", 0, 0, 180000);
            kprintf("[lxabi] LXZERO exit -> %d\n", zrc); }
        /* ...and whether PROT_NONE actually FAULTS (M2175). A reservation a
         * program made precisely so that touching it would fail was answering
         * reads with a demand-zeroed page, because mprotect recorded a
         * requested PROT_NONE as READ-ONLY. glibc protects the gaps between a
         * shared object's segments that way, and JavaScriptCore reserves its
         * 4 GiB structure heap that way so that StructureID 0 is an invalid
         * id -- if that reservation reads as zeroes, id 0 resolves to a zeroed
         * Structure and it surfaces as a garbage JSValue somewhere unrelated.
         * A counter could not have caught that; only taking the signal can. */
        kprintf("[lxabi] launching the PROT_NONE probe...\n");
        {   int nrc = app_run_linux_sync("/disk2/lxnone", 0, 0, 120000);
            kprintf("[lxabi] LXNONE exit -> %d\n", nrc); }
        /* ...and whether an mprotect over a COW page keeps it copy-on-write
         * (M2178). vmm_protect replaced the PTE flags wholesale, so granting
         * write dropped the bit that makes the copy happen -- two processes
         * writing one physical frame, neither told. Firefox forks its content
         * processes; a JIT mprotecting a region it has just forked over is the
         * ordinary case. */
        kprintf("[lxabi] launching the mprotect-over-COW probe...\n");
        {   int cprc = app_run_linux_sync("/disk2/lxcowprot", 0, 0, 120000);
            kprintf("[lxabi] LXCOWPROT exit -> %d\n", cprc); }
        /* ...and whether a thread can find its own stack, for the same
         * reason: a conservative collector scans between the stack pointer
         * and the base it was told, so the bounds are a correctness input. */
        kprintf("[lxabi] launching the stack-bounds probe...\n");
        {   int strc2 = app_run_linux_sync("/disk2/lxstack", 0, 0, 120000);
            kprintf("[lxabi] LXSTACK exit -> %d\n", strc2); }
        /* ...and whether a signal sent to a thread arrives at that thread,
         * which is how a collector suspends one. (M2075) */
        kprintf("[lxabi] launching the per-thread signal probe...\n");
        {   int tsrc = app_run_linux_sync("/disk2/lxtsig", 0, 0, 180000);
            kprintf("[lxabi] LXTSIG exit -> %d\n", tsrc); }
        /* Firefox died reading the stack canary at %fs:0x28 -- a thread with
         * NO TLS. Nothing asserted that a thread's own __thread storage is
         * its own, nor that a child forked from a non-main thread keeps the
         * FORKING thread's TLS rather than the process's main one. (M2083) */
        kprintf("[lxabi] launching the per-thread TLS probe...\n");
        {   int tlrc = app_run_linux_sync("/disk2/lxtls", 0, 0, 180000);
            kprintf("[lxabi] LXTLS exit -> %d\n", tlrc); }
        /* fcntl record locks and flock(2) both existed in kernel/flock.c and
         * neither was reachable from a Linux program -- the fallthrough turned
         * "no such command" into EBADF on a valid fd. (M2085) */
        kprintf("[lxabi] launching the record-lock probe...\n");
        {   int lkrc = app_run_linux_sync("/disk2/lxlock", 0, 0, 120000);
            kprintf("[lxabi] LXLOCK exit -> %d\n", lkrc); }
        /* FIONREAD -- not a terminal ioctl, and answered by the "not a
         * terminal" branch anyway, so a socket with 142 bytes waiting was told
         * the question did not apply to it. Firefox's IPC channel asked and
         * then aborted. (M2086) */
        kprintf("[lxabi] launching the readable-byte-count probe...\n");
        {   int nrrc = app_run_linux_sync("/disk2/lxnread", 0, 0, 120000);
            kprintf("[lxabi] LXNREAD exit -> %d\n", nrrc); }
        /* MADV_DONTNEED KEPT EVERY FORK-SHARED PAGE AND RETURNED SUCCESS, so
         * the caller was promised zeroes and read back stale bytes. mozjemalloc
         * is built on that promise, Firefox forks, and mozjemalloc fills freed
         * memory with 0xe5 -- which is how a pointer came back as
         * 0xe5e5e5e5e5e5e5e5 and #GP'd pthread_mutex_lock. The FORK is the
         * test: without one every page is single-owner and the old code looks
         * correct. (M2106) */
        kprintf("[lxabi] launching the madvise purge probe...\n");
        {   int mvrc = app_run_linux_sync("/disk2/lxmadv", 0, 0, 120000);
            kprintf("[lxabi] LXMADV exit -> %d\n", mvrc); }
        /* sendmsg answered ENETUNREACH -- impossible on a Unix socket -- for
         * six different failures, and Firefox's FORK SERVER got it after
         * successfully forking a content process. Every content process died
         * that way. (M2090) */
        kprintf("[lxabi] launching the sendmsg/recvmsg errno probe...\n");
        {   int mgrc = app_run_linux_sync("/disk2/lxmsg", 0, 0, 120000);
            kprintf("[lxabi] LXMSG exit -> %d\n", mgrc); }
        /* ...and the same invariant at FIREFOX'S SCALE. Eight threads never
         * reproduced the FS_BASE loss; a hundred and twenty might. (M2089) */
        kprintf("[lxabi] launching the 120-thread TLS probe...\n");
        {   int tmrc = app_run_linux_sync("/disk2/lxtlsmany", 0, 0, 600000);   /* -cpu max emulates AVX-512: 120 threads take a while (M2095) */
            kprintf("[lxabi] LXTLSMANY exit -> %d\n", tmrc); }
        /* getsockopt answered a confident ZERO to every option ever asked, so
         * Firefox's IPC channel was told its send buffer was nought bytes and
         * aborted at ipc_channel_posix.cc:128. (M2088) */
        kprintf("[lxabi] launching the socket-option probe...\n");
        {   int sorc = app_run_linux_sync("/disk2/lxsockopt", 0, 0, 120000);
            kprintf("[lxabi] LXSOCKOPT exit -> %d\n", sorc); }
        /* ...and whether a COW break loses a write when several threads take
         * one at the same moment, which is what fork() in a threaded process
         * makes happen. (M2076) */
        kprintf("[lxabi] launching the concurrent-COW probe...\n");
        {   int cwrc = app_run_linux_sync("/disk2/lxcow", 0, 0, 300000);
            kprintf("[lxabi] LXCOW exit -> %d\n", cwrc); }
        /* ...and whether a MAP_PRIVATE FILE mapping is private ACROSS
         * PROCESSES, which is the shape ld.so relies on for every PT_LOAD
         * (M2167). Two Firefox failures on eight cores are both a bad POINTER
         * rather than a bad protection -- a write into libxul's RELRO, which
         * readelf confirms ld.so is right to have made read-only, and an
         * instruction fetch at the exact base of libgtk's read-only segment.
         * One process seeing another's relocations produces both, because each
         * process loads a library at its own ASLR base. lxcow covers ANONYMOUS
         * memory after fork and lxfmap covers a non-zero offset; neither asks
         * this. */
        /* THE KERNEL HALF OF THE EDIT TOOL (M2180). Phase 7's demo is Claude
         * Code editing a file in OS-DEV's own tree, and it cannot run at all
         * right now: the staged OAuth access token expired and the CLI declines
         * to refresh it, so every run stops before a tool call. Renewing the
         * login needs a human.
         *
         * The API is half of that demo. The other half is a kernel path, and a
         * DIFFERENT one from the Bash tool M2130 proved -- Write and Edit go
         * through openat(O_CREAT|O_TRUNC)/write/fsync/rename against ext2,
         * where Bash goes through fork, execve and a pipe. Nothing exercised
         * the write path against the real source tree, so when the login comes
         * back the only untested thing left should be Claude Code itself. */
        /* DID ld.so COMPUTE THE RELOCATIONS CORRECTLY? (M2187)
         *
         * The last standing hypothesis for Firefox's remaining fault, and the
         * only one not yet ruled out by measurement. An indirect call through a
         * GOT slot holding a non-canonical pointer, plus a write into libxul's
         * RELRO -- with the library's bytes proven to be the FILE's bytes
         * (M2173, hashed on the host), private mappings proven private across
         * processes (M2167), the RELRO page proven UNCHANGED since it was made
         * read-only (M2177, so the kernel did not lose it), and the protections
         * proven correct (GNU_RELRO covers exactly that LOAD). What is left is
         * the relocation itself.
         *
         * 4096 R_X86_64_RELATIVE pointers in `.data.rel.ro` -- thousands
         * because the symptom is ONE wrong pointer among many -- each compared
         * against the address taken at runtime by different arithmetic, and
         * then CALLED, with the target counting its own invocations. */
        kprintf("[lxabi] launching the ld.so relocation probe...\n");
        {   int rrc = app_run_linux_sync("/disk2/lxrelo", 0, 0, 120000);
            kprintf("[lxabi] LXRELO exit -> %d\n", rrc); }
        kprintf("[lxabi] launching the edit-tool write-path probe...\n");
        /* `/src`, NOT `/disk2/src`. A Linux program's paths are relative to
         * LX_ROOT and the kernel prepends `/disk2` itself, so handing it the
         * kernel-side path makes it open `/disk2/disk2/src/Makefile` and the
         * probe SKIPPED with "does not look like the source tree" -- a clean
         * miss that reads exactly like a legitimate skip. Same double-translation
         * that cost two attempts at /proc/self/fd/N in M2129. (M2182) */
        {   static const char *av_w[] = { "/src" };
            int wrc = app_run_linux_sync("/disk2/lxwrite", av_w, 1, 120000);
            kprintf("[lxabi] LXWRITE exit -> %d\n", wrc); }
        kprintf("[lxabi] launching the private-file-mapping probe...\n");
        {   int pvrc = app_run_linux_sync("/disk2/lxpriv", 0, 0, 180000);
            kprintf("[lxabi] LXPRIV exit -> %d\n", pvrc); }
        /* ...and whether a WHOLE mapped library equals its own file (M2168).
         * The in-kernel `code check` compares sixteen bytes at a faulting rip;
         * this compares tens of megabytes, from userspace, where it is cheap
         * and needs no interrupts. It is the direct test of the class that
         * produced this whole arc -- a page of a mapped library holding the
         * wrong bytes -- and it is what decides whether ld.so's relocation
         * INPUT is sound before anyone argues about its output. Opt-in
         * (`lxmapcmp`), because reading 200 MB twice is not free. */
        if (g_lxmapcmp) {
            kprintf("[lxabi] comparing whole mapped libraries against their files...\n");
            int mcrc = app_run_linux_sync("/disk2/lxmapcmp", 0, 0, 900000);
            kprintf("[lxabi] LXMAPCMP exit -> %d\n", mcrc);
        }
        /* HOME, and the XDG directories under it (M1985). A GTK program writes
         * before it draws -- a profile, a font cache, a dconf directory -- and
         * glib treats a config directory it cannot create as fatal rather than
         * as a reason to skip caching. Made here, not in the image, so a fresh
         * ext2 volume needs no special preparation to run one. */
        probes_done:
        if (g_lxstress) {
            /* The reproducer for the corruption Firefox dies in, on its own
             * boot because it is deliberately the heaviest thing here and
             * nothing else should be competing for the answer. (M1987) */
            kprintf("[lxabi] STRESS: mmap/thread/futex/signal churn...\n");
            int strc = app_run_linux_sync("/disk2/lxstress", 0, 0, 900000);
            kprintf("[lxabi] LXSTRESS exit -> %d\n", strc);
        }
        {   /* What does the Linux view of "/" actually look like? A program
             * checks its working directory before it does anything else, and
             * "Path / does not exist" is a claim about THIS. (M1992) */
            struct statx rs;
            if (vfs_stat("/disk2", &rs) == 0)
                kprintf("[lxabi] root /disk2: mode 0%x size %lu (dir=%d)\n",
                        (unsigned)rs.stx_mode, (unsigned long)rs.stx_size,
                        (rs.stx_mode & 0170000u) == 0040000u);
            else
                kprintf("[lxabi] root /disk2: vfs_stat FAILED -- a Linux process cannot stat its own cwd\n");
        }
        vfs_mkdir("/disk2/root");
        vfs_mkdir("/disk2/root/.config");
        vfs_mkdir("/disk2/root/.cache");
        vfs_mkdir("/disk2/root/.local");
        vfs_mkdir("/disk2/root/.local/share");
        /* Claude Code's own state tree. It creates these itself, one level at
         * a time -- but only if their parent exists, and a failed mkdir here is
         * fatal to it rather than cosmetic. (M1992) */
        vfs_mkdir("/disk2/etc");            /* BEFORE anything writes into it (M1997) */
        /* /etc/hosts and /etc/host.conf. glibc's resolver reads both before it
         * will look anything up, and Firefox asks for them by name. A
         * loopback entry is the truthful minimum. (M1996) */
        { const char *h = "127.0.0.1\tlocalhost\n::1\tlocalhost\n";
          unsigned long hl = 0; while (h[hl]) hl++;
          vfs_write("/disk2/etc/hosts", h, hl); }
        { const char *h = "multi on\n";
          unsigned long hl = 0; while (h[hl]) hl++;
          vfs_write("/disk2/etc/host.conf", h, hl); }
        /* Firefox writes a profile and a lock under these before it opens a
         * window; a mkdir whose parent is missing fails, and it treats that as
         * fatal rather than cosmetic. */
        vfs_mkdir("/disk2/tmp/firefox");
        vfs_mkdir("/disk2/root/.mozilla");
        vfs_mkdir("/disk2/root/.mozilla/firefox");
        vfs_mkdir("/disk2/root/.cache/mozilla");
        vfs_mkdir("/disk2/root/.cache/mozilla/firefox");
        vfs_mkdir("/disk2/root/.claude");
        vfs_mkdir("/disk2/root/.claude/telemetry");
        vfs_mkdir("/disk2/root/.claude/plugins");
        vfs_mkdir("/disk2/root/.claude/projects");
        vfs_mkdir("/disk2/root/.claude/statsig");
        vfs_mkdir("/disk2/root/.claude/todos");
        vfs_mkdir("/disk2/root/.claude/backups");
        vfs_mkdir("/disk2/root/.claude/skills");
        /* ...and the ones it does NOT create itself (M2033). A missing
         * plugins/cache surfaced as ripgrep reporting an "IO error" on the
         * directory, which reads like a disk fault and is a missing mkdir. */
        vfs_mkdir("/disk2/root/.claude/plugins/cache");
        vfs_mkdir("/disk2/root/.claude/plans");
        vfs_mkdir("/disk2/root/.claude/sessions");
        vfs_mkdir("/disk2/root/.claude/shell-snapshots");
        vfs_mkdir("/disk2/tmp");
        vfs_mkdir("/disk2/root/.cache/fontconfig");
        vfs_mkdir("/disk2/var");
        vfs_mkdir("/disk2/var/cache");
        vfs_mkdir("/disk2/var/cache/fontconfig");
        vfs_mkdir("/disk2/var/lib");
        vfs_mkdir("/disk2/var/lib/dbus");
        /* /etc/machine-id -- AND IT MUST BE 32 LOWERCASE HEX DIGITS (M2013).
         *
         * It used to read "05dev05dev05dev05dev05dev05dev05": the right
         * length, and spelling "osdev" in it was a nice touch, except that `v`
         * is not a hex digit. D-Bus validates the file and rejects it, which
         * is not a cosmetic complaint -- GDBus then cannot autolaunch a
         * session bus, and Firefox's MAIN THREAD parked in a glib condition
         * variable inside libgio waiting for a bus that could never appear:
         *
         *   Failed to create DBus proxy for org.a11y.Bus: Cannot spawn a
         *   message bus without a machine-id: Invalid machine ID in
         *   /var/lib/dbus/machine-id or /etc/machine-id
         *
         * printed as a WARNING, forty minutes before the process stopped
         * making syscalls. A fixed value is still correct: this is one
         * machine's identity, not a secret, and a random one per boot would
         * make every cache in the image miss. Both paths are written, because
         * D-Bus checks /var/lib/dbus/machine-id first and only then /etc. */
        vfs_mkdir("/disk2/etc");
        { const char *mid = "05de05de05de05de05de05de05de05de\n";
          unsigned long ml = 0; while (mid[ml]) ml++;
          vfs_write("/disk2/etc/machine-id", mid, ml);
          vfs_write("/disk2/var/lib/dbus/machine-id", mid, ml); }
        /* /etc/resolv.conf, written from the address DHCP actually leased
         * (M1967).
         *
         * glibc's getaddrinfo reads this file and nothing else; with no
         * resolver configured it returns EAI_AGAIN, which is what Node
         * reported for every hostname -- an error that says "try later" about
         * a lookup that was never going to happen. Our own resolver had the
         * right server the whole time: net_dns() holds what the DHCP lease
         * carried.
         *
         * Generated at boot rather than staged into the image on purpose. A
         * baked-in nameserver is correct only on the network it was baked for,
         * and this kernel boots on real hardware too. */
        {
            const uint8_t *ns = net_dns();
            /* THE LEASE'S RESOLVER, NOT THE GATEWAY (M2125).
             *
             * M2124 preferred the gateway whenever the lease's nameserver was
             * off-segment, reasoning that one hop needs no routing and that
             * every consumer router answers DNS. Measured: it does not. The
             * guest's query reached 192.168.1.1:53 -- transmitted correctly,
             * right ports, the router's own MAC --
             *
             *   [udp] tx 29 bytes 49152 -> 192.168.1.1:53 via 192.168.1.1
             *
             * and nothing ever answered. A DHCP server that hands out 1.1.1.1
             * is quite often a server whose own host does NOT resolve, which is
             * exactly why it hands out someone else's. So the guess made things
             * worse: it replaced a resolver that answers with one that does
             * not, and then the failure looked identical.
             *
             * Use what the lease says. It is the one address on the network
             * that something has actually promised to answer on. */            if (ns && (ns[0] | ns[1] | ns[2] | ns[3])) {
                char rc_buf[256]; int n = 0;   /* two nameserver lines + the options line (M2284/M2318): 128 fit the old content with 46 bytes spare, which is not a margin worth defending */
                const char *pfx = "nameserver ";
                for (int i = 0; pfx[i]; i++) rc_buf[n++] = pfx[i];
                for (int o = 0; o < 4; o++) {
                    int v = ns[o];
                    if (v >= 100) rc_buf[n++] = (char)('0' + v / 100);
                    if (v >= 10)  rc_buf[n++] = (char)('0' + (v / 10) % 10);
                    rc_buf[n++] = (char)('0' + v % 10);
                    rc_buf[n++] = (o == 3) ? '\n' : '.';
                }
                /* AND RESOLVER OPTIONS, BECAUSE ONE LOST PACKET SHOULD NOT
                 * FAIL A BOOT (M2284).
                 *
                 * With no `options` line glibc uses its defaults -- timeout 5,
                 * attempts 2 -- against the single nameserver the lease gave
                 * us. One dropped UDP query therefore costs five seconds and
                 * gets one retry, and if that is also unlucky getaddrinfo
                 * returns EAI_AGAIN. Measured: one boot in three of the Phase
                 * 7 demo failed with
                 *     API Error: Can't reach the API server -- check your
                 *     internet or DNS (EAI_AGAIN)
                 * which is not Claude failing, not authentication, and not
                 * the OS's own network stack -- it is a name lookup given one
                 * short retry and no second chance.
                 *
                 * Shorter timeout, more attempts, and single-request so the A
                 * and AAAA queries go one after the other rather than as a
                 * pair whose loss looks like a server that is down. */
                /* A SECOND NAMESERVER, BECAUSE ONE LOST DATAGRAM SHOULD NOT
                 * FAIL A LOOKUP (M2318).
                 *
                 * Thirty-six 8-core boots of the Claude file-edit demo: four
                 * failed, every one of them EAI_AGAIN. The receive path is
                 * fully accounted for by counters placed where each event
                 * happens -- the query IS transmitted, the NIC discards
                 * nothing (its own MPC/RNBC registers read 0), every datagram
                 * that arrives is filed, none are destroyed or evicted -- and
                 * the reply for the waiting port simply never reaches the
                 * machine. That profile is packet loss between here and the
                 * resolver, not a defect in this stack.
                 *
                 * The fix for loss is not to hunt it, it is to survive it.
                 * `attempts:5` already retries; a SECOND server multiplies
                 * that by two independent paths, so a lookup now needs ten
                 * consecutive losses to fail instead of five. The primary
                 * still comes from the DHCP lease -- this only appends a
                 * public fallback after it, and only if the lease did not
                 * already give a second one. */
                {   const char *fb = "nameserver 8.8.8.8\n";
                    for (int i = 0; fb[i]; i++) rc_buf[n++] = fb[i]; }
                const char *opts = "options timeout:2 attempts:5 single-request\n";
                for (int i = 0; opts[i]; i++) rc_buf[n++] = opts[i];
                rc_buf[n] = 0;
                vfs_mkdir("/disk2/etc");
                if (vfs_write("/disk2/etc/resolv.conf", rc_buf, (unsigned long)n) >= 0)
                    /* "FROM THE DHCP LEASE" WAS NOT NECESSARILY TRUE (M2120).
                     * net_dhcp() was never called on an ordinary boot, so this
                     * printed that phrase over the SLIRP default 10.0.2.3 --
                     * and a nameserver that came from a lease and one that came
                     * from a compiled-in constant read identically. On a
                     * bridged VM the constant is a machine that does not exist,
                     * and the only symptom was EAI_AGAIN inside a guest program
                     * an hour later. Say which it is. */
                    /* Say that the FALLBACK is there too (M2318). The line
                     * named only the primary, so a second nameserver could be
                     * added and silently not written and the log would read
                     * exactly the same -- which is how the whole "from the
                     * DHCP lease" phrase was wrong for years (M2120). */
                    kprintf("[lxabi] /etc/resolv.conf -> %d bytes, nameserver %u.%u.%u.%u (%s) "
                            "+ fallback 8.8.8.8, timeout:2 attempts:5\n", n,
                            ns[0], ns[1], ns[2], ns[3],
                            net_have_lease() ? "from the DHCP lease"
                                             : "the compiled-in SLIRP default -- NO DHCP LEASE, so this "
                                               "only resolves under QEMU user-mode networking");
                else
                    kprintf("[lxabi] could not write /etc/resolv.conf -- getaddrinfo will report EAI_AGAIN\n");
            } else {
                kprintf("[lxabi] no DNS server in the lease; getaddrinfo will report EAI_AGAIN\n");
            }
        }
        /* -append lxdesktop: THE LINUX ENVIRONMENT, AND NOTHING ELSE (M2004).
         *
         * Everything above this line is setup a Linux program needs before it
         * can do anything -- $HOME and the XDG directories, /etc/machine-id,
         * the font cache directories, and /etc/resolv.conf written from the
         * DHCP lease. Everything below it is a TEST. They were welded together,
         * so the only way to get a usable Linux environment was to sit through
         * a suite first, and a plain desktop boot had no /etc/resolv.conf at
         * all -- which means no DNS, which means nothing that talks to the
         * internet can work. That is the boot a person actually wants when they
         * mean to sit down and use the machine. */
        if (g_lxdesktop) {
            kprintf("[lxabi] Linux environment ready; skipping the test suite (lxdesktop)\n");
            goto lx_env_ready;
        }
        kprintf("[lxabi] launching a host-built static-PIE Linux binary from /disk2...\n");
        if (app_spawn_linux_from_file("/disk2/hellofree") < 0)
            kprintf("[FAIL] lxabi: could not load /disk2/hellofree\n");
        /* NOT launched yet: /disk2/hellolibc is a glibc static-PIE binary and it
         * does not run. It loads, gets a correct SysV stack (verified: 16-byte
         * aligned RSP, entry matching the ELF), is entered -- and then makes
         * ZERO syscalls and never faults, so the boot wedges behind it.
         *
         * The cause is structural, not a bug in the stack: the image carries 22
         * R_X86_64_IRELATIVE relocations and a PT_TLS segment. IRELATIVE means
         * ifunc -- the loader must CALL a resolver and store its result -- and
         * glibc does that itself in _dl_relocate_static_pie, before its first
         * syscall, which is exactly where it stops. musl is the right first
         * libc target (no ifunc, far smaller startup); this stays staged in the
         * image as the next milestone's subject.
         *
         * M1941 UPDATE: with the console deadlock fixed, the real cause is
         * visible -- it faults with Invalid Opcode on `vpxor %xmm0,%xmm0,%xmm0`
         * inside glibc's _dl_aux_init, i.e. it successfully parsed the auxv
         * this stack provides and then executed an AVX instruction. AVX is not
         * enabled here: fpu_init sets only CR4.OSFXSR/OSXMMEXCPT and the
         * context switch is FXSAVE/FXRSTOR, which does not preserve YMM. That
         * is M1942's job.
         *
         * Under `lxfaulttest` it IS launched, as M1941's regression test: it
         * raises a ring-3 fault while the boot task is printing, which is
         * exactly the shape that used to deadlock on the console lock and
         * swallow the report. The suite asserts the [fault] line appears AND
         * that the boot still runs to completion. */
        /* THE ROOT DIRECTORY, asked about every way a runtime knows how.
         * Claude Code stops at startup with
         *
         *     Error: Can't access working directory /: Path "/" does not exist
         *
         * and the syscall trace cannot say which question failed, because it
         * only prints calls that fail BY PATH. stat/lstat/statx/access/
         * open(O_DIRECTORY)/opendir/realpath/chdir all reach different code
         * here, and a program only has to be told "no" by one of them. Runs on
         * every lxabi boot: it costs a second and it is the shape of question
         * that every ported program asks before it does anything. (M1998) */
        kprintf("[lxabi] launching the root-directory probe...\n");
        int cwdrc = app_run_linux_sync("/disk2/lxcwd", 0, 0, 60000);
        kprintf("[lxabi] LXCWD exit -> %d\n", cwdrc);
        /* ...and the memory shape a JS engine actually needs: reserve twice
         * what you want, round up to an alignment, give back the head and the
         * tail, then use what is left. Both trims report success either way --
         * the claim being tested is that the KEPT range is still there.
         * (M1999) */
        kprintf("[lxabi] launching the reserve/align/trim (pointer cage) probe...\n");
        int cagerc = app_run_linux_sync("/disk2/lxcage", 0, 0, 120000);
        kprintf("[lxabi] LXCAGE exit -> %d\n", cagerc);
        /* ...and the one a Wayland client makes before it can show a cursor:
         * memfd + seals + posix_fallocate + MAP_SHARED. GDK reports the whole
         * chain as one warning that names none of its four possible causes.
         * (M2000) */
        kprintf("[lxabi] launching the anonymous-shared-file probe...\n");
        int anonrc = app_run_linux_sync("/disk2/lxanon", 0, 0, 60000);
        kprintf("[lxabi] LXANON exit -> %d\n", anonrc);
        /* ...and which vector instruction sets can actually EXECUTE here. A
         * #UD on an instruction CPUID advertised is indistinguishable from a
         * kernel that forgot to enable its state, and Firefox died on exactly
         * that. This says which, definitively. (M2007) */
        kprintf("[lxabi] launching the vector-ISA probe...\n");
        int isarc = app_run_linux_sync("/disk2/lxisa", 0, 0, 60000);
        kprintf("[lxabi] LXISA exit -> %d\n", isarc);
        /* ...and O_NONBLOCK on a pipe, which is how every event loop wakes
         * itself up. Firefox's main thread blocked in the drain loop's final
         * read and took 33 futex-waiting threads down with it; the pipe was
         * the last fd type here that ignored O_NONBLOCK. (M2009) */
        kprintf("[lxabi] launching the non-blocking-pipe probe...\n");
        int nbrc = app_run_linux_sync("/disk2/lxnbpipe", 0, 0, 60000);
        kprintf("[lxabi] LXNB exit -> %d\n", nbrc);
        /* ...AND WHETHER POLL TELLS THE TRUTH ABOUT WRITING (M2202). The same
         * shape one layer over: the pipe ignored O_NONBLOCK, and the AF_UNIX
         * socket honoured it and then had poll promise the write it was about
         * to refuse. The pipe's version cost one wedged thread; this one costs
         * a core spinning, in every Firefox boot this tree has produced. */
        kprintf("[lxabi] launching the POLLOUT-honesty probe...\n");
        int porc = app_run_linux_sync("/disk2/lxpollout", 0, 0, 60000);
        kprintf("[lxabi] LXPOLLOUT exit -> %d\n", porc);
        /* ...AND WHETHER A LINUX BINARY CAN GET A PTY AT ALL (M2206). The pty
         * has been complete since M1274 and openpty() could not reach it,
         * because glibc asks the master for its slave number (TIOCGPTN) and
         * unlocks it (TIOCSPTLCK) and both answered ENOTTY. Same probe checks
         * that a FULL pty reports what it actually took. */
        kprintf("[lxabi] launching the pty probe...\n");
        int ptrc = app_run_linux_sync("/disk2/lxpty", 0, 0, 60000);
        kprintf("[lxabi] LXPTY exit -> %d\n", ptrc);
        /* ...AND WHETHER A fork() QUIETLY UNSHARES A MAP_SHARED MAPPING
         * (M2209). vmm_fork_cow write-protects every page of the parent
         * because the page tables do not record which mappings are shared, and
         * nothing undid it for the shared ones -- so the first write to a
         * shared page got a private copy and the mapping stopped being the
         * object. Firefox forks per content process and every IPC buffer it
         * held across a fork was one write away from that. */
        kprintf("[lxabi] launching the shared-mapping-across-fork probe...\n");
        int shrc = app_run_linux_sync("/disk2/lxshcow", 0, 0, 60000);
        kprintf("[lxabi] LXSHCOW exit -> %d\n", shrc);
        /* ...and ABSOLUTE deadlines. FUTEX_WAIT_BITSET and
         * clock_nanosleep(TIMER_ABSTIME) both take a timestamp, and reading
         * one as a duration is a fifty-six-year wait while substituting a
         * constant is a thousand-hertz spin. Neither is visible from in here:
         * the wait proceeds exactly as asked. (M2010) */
        /* ...and the SUBPROCESS LIFECYCLE: fork, exit, wait4, WNOHANG. Claude
         * Code hung here with every core halted and no syscall for 45 seconds,
         * its main thread parked in wait4() for children that had already
         * exited. A process whose exit_group came from a non-main thread was
         * left with its main task merely STOPPED, which the reaper's gate could
         * never satisfy, so the child never became a collectable zombie; and
         * wait4 discarded its options, so WNOHANG blocked for ever. (M2025) */
        /* ...and the RESERVE-TRIM-COMMIT pattern JavaScriptCore's pointer
         * cage is built from, which is where Claude Code died. (M2035) */
        /* ON DEMAND ONLY (M2041). These reserve 8 GiB, trim it, and commit
         * dozens of slabs -- minutes of TCG each. Adding them to the default
         * boot pushed the whole lxfulltest sequence past the harness's wait, so
         * the assertions that come AFTER them never ran and reported themselves
         * as failures ("real threads did not work") in a boot that was merely
         * unfinished. They have already served their purpose -- proving the
         * mmap subsystem innocent -- so they are a diagnostic to reach for, not
         * a tax on every run. */
        if (g_lxcage) {
            kprintf("[lxabi] launching the EXACT-ARGUMENTS cage probe...\n");
            int c3 = app_run_linux_sync("/disk2/lxcage3", 0, 0, 120000);
            kprintf("[lxabi] LXCAGE3 exit -> %d\n", c3);
        }
        if (g_lxcage) {
            kprintf("[lxabi] launching the pointer-cage probe...\n");
            int gcrc = app_run_linux_sync("/disk2/lxgcage", 0, 0, 120000);
            kprintf("[lxabi] LXGCAGE exit -> %d\n", gcrc);
        }
        kprintf("[lxabi] launching the subprocess-lifecycle probe...\n");
        int wrc = app_run_linux_sync("/disk2/lxwait", 0, 0, 120000);
        kprintf("[lxabi] LXWAIT exit -> %d\n", wrc);
        /* An edge-triggered epoll losing one edge is a whole-process hang, and
         * nothing here had ever tested the case that loses it: a drain with no
         * wait in between. (M2059) */
        kprintf("[lxabi] launching the edge-triggered epoll probe...\n");
        int erc = app_run_linux_sync("/disk2/lxepoll", 0, 0, 90000);
        kprintf("[lxabi] LXEPOLL exit -> %d\n", erc);
        /* A listing that truncates a filename hands a program a name that does
         * not exist, and nothing here had ever asserted the bytes come back
         * unchanged. (M2062) */
        kprintf("[lxabi] launching the long-filename round-trip probe...\n");
        int lnrc = app_run_linux_sync("/disk2/lxlongname", 0, 0, 90000);
        kprintf("[lxabi] LXLONGNAME exit -> %d\n", lnrc);
        /* rt_sigaction and rt_sigprocmask returned 0 and did nothing until
         * M2063, including for the QUERY form -- which hands a caller its own
         * uninitialised stack as a signal handler. */
        kprintf("[lxabi] launching the signal-disposition probe...\n");
        int sgrc = app_run_linux_sync("/disk2/lxsig", 0, 0, 90000);
        kprintf("[lxabi] LXSIG exit -> %d\n", sgrc);
        /* The futex key was a PHYSICAL address, so fork -- which makes every
         * page COW -- silently disconnected wakers from waiters. (M2073) */
        kprintf("[lxabi] launching the futex-across-a-COW-break probe...\n");
        int furc = app_run_linux_sync("/disk2/lxfutex", 0, 0, 120000);
        kprintf("[lxabi] LXFUTEX exit -> %d\n", furc);
        kprintf("[lxabi] launching the absolute-deadline probe...\n");
        int trc = app_run_linux_sync("/disk2/lxtime", 0, 0, 90000);
        kprintf("[lxabi] LXTIME exit -> %d\n", trc);
        if (g_lxfault_test) {
            kprintf("[lxabi] launching a binary expected to FAULT (M1941 regression)...\n");
            app_spawn_linux_from_file("/disk2/hellolibc");
            /* A demanding one: real file I/O + a directory listing, i.e. what a
             * `cat` and an `ls` need. Drives the next ENOSYS batch. */
        }
        if (g_lxfull_test) {
            kprintf("[lxabi] launching a glibc file-I/O binary...\n");
            app_spawn_linux_from_file("/disk2/lxfileio");
            /* Phase 3's real deliverable: a busybox-shaped multi-call binary
             * that FORKS, re-EXECVEs ITSELF twice with different argv, wires
             * the two together with a real PIPE, and wait4()s both. */
            kprintf("[lxabi] launching the fork/execve/pipe demo...\n");
            app_spawn_linux_from_file_arg("/disk2/lxbox", "pipe");
            kprintf("[lxabi] launching the MAP_FIXED mmap test...\n");
            app_spawn_linux_from_file("/disk2/lxmmap");
            kprintf("[lxabi] launching the file-backed mmap (offset) test...\n");
            app_spawn_linux_from_file("/disk2/lxfmap");
            /* A big anonymous mmap must not land on top of an existing
             * mapping. app_mmap used to align the result to 2 MiB AFTER
             * finding its gap, walking it onto the next VMA -- see
             * tools/lx/lxvmagap.c. (M1965) */
            kprintf("[lxabi] launching the big-mmap VMA overlap test...\n");
            app_spawn_linux_from_file("/disk2/lxvmagap");
            /* A NON-PIE (ET_EXEC) binary: linked at a fixed low address and
             * therefore impossible to run until the kernel left the low 1 GiB
             * (M1968) and stopped inheriting the identity map into every
             * address space (M1969). Synchronous, because the assertion is on
             * its exit status as much as its output. */
            kprintf("[lxabi] launching a NON-PIE (ET_EXEC) binary...\n");
            int nprc = app_run_linux_sync("/disk2/lxnopie", 0, 0, 120000);
            kprintf("[lxabi] LXNOPIE exit -> %d\n", nprc);
            /* Claude Code's exact shape: ET_EXEC *and* dynamically linked, so
             * ld.so has to find program headers that are not at base+e_phoff. */
            /* The wl_shm foundation: a descriptor passed over a socket, and
             * memory shared through it. Everything Wayland does with pixels
             * rests on this. (M1977) */
            kprintf("[lxabi] launching the memfd + SCM_RIGHTS test...\n");
            int scmrc = app_run_linux_sync("/disk2/lxscm", 0, 0, 120000);
            kprintf("[lxabi] LXSCM exit -> %d\n", scmrc);
            /* ...and WHO OWNS those shared pages. A memfd's buffer is kernel
             * heap; mapping it aliases the heap into a process, so unmapping
             * or closing it wrong hands live kernel memory back to the
             * allocator. That corrupts something else entirely, which is why
             * it needs a test that looks for the corruption on purpose.
             * (M1985) */
            kprintf("[lxabi] launching the memfd OWNERSHIP test...\n");
            int mfrc = app_run_linux_sync("/disk2/lxmemfd", 0, 0, 120000);
            kprintf("[lxabi] LXMEMFD exit -> %d\n", mfrc);
            kprintf("[lxabi] launching a NON-PIE DYNAMIC binary...\n");
            int ndrc = app_run_linux_sync("/disk2/lxnopiedyn", 0, 0, 120000);
            kprintf("[lxabi] LXNOPIEDYN exit -> %d\n", ndrc);
            /* The Phase 4 gate: a DYNAMICALLY-LINKED binary, which needs
             * PT_INTERP + ld.so + libc.so.6 all working. */
            kprintf("[lxabi] launching a DYNAMICALLY-LINKED binary...\n");
            app_spawn_linux_from_file("/disk2/lxdyn");
            /* REAL THREADS (M1959): glibc's own NPTL -- pthread_create, a
             * mutex, a condvar and pthread_join -- which needs clone with the
             * full pthread flag set, CLONE_SETTLS, set_tid_address and futex.
             * The shared blocker for Node, Claude Code AND Firefox. */
            /* SYNCHRONOUS, unlike the demos above. Fire-and-forget left it
             * competing for a 256 MiB machine with eight other live glibc
             * processes, and it simply never finished dynamic loading -- no
             * fault, no error, just still searching for libc when the boot
             * ended. Running it after the others have drained makes it
             * deterministic, and the exit status is then assertable directly
             * rather than inferred from output that the console can drop under
             * load. (M1959) */
            kprintf("[lxabi] launching a REAL PTHREADS binary...\n");
            if (g_lxtrace_make) g_lx_systrace = 1;
            int trc = app_run_linux_sync("/disk2/lxthread", 0, 0, 120000);
            g_lx_systrace = 0;
            kprintf("[lxabi] LXTHREAD exit -> %d\n", trc);
            /* A stale-TLB test would be timing-dependent and therefore flaky;
             * this proves the MECHANISM fires on a genuinely multi-threaded
             * process, which is the part that can be asserted reliably. */
            kprintf("[lxabi] TLB shootdowns performed: %lu\n", vmm_tlb_shootdown_count());
        }
        if (g_wltest) {
            /* PHASE 8 (M1978): bring the display up, then run a REAL
             * libwayland client against it -- the same library Firefox uses,
             * so a pass means the wire format is right by the standard rather
             * than by agreement with our own idea of it.
             *
             * The compositor is polled from HERE rather than a background
             * task: the client is run synchronously, so the two have to take
             * turns, and app_run_linux_sync returns only when the client has
             * exited. A background task is the next step, once the compositor
             * owns a window. */
            vfs_mkdir("/disk2/run");
            /* Before any client exists, so it owns the object tables outright:
             * the surface-SELECTION assertions (M2058). A real client can only
             * ever exercise one surface at a time; this one drives a toplevel,
             * a cursor and a second window through the dispatcher and checks
             * which of them the window manager would draw. */
            wl_selftest();
            if (wl_compositor_init() == 0) {
                /* The compositor runs as its OWN TASK. Driving it from here in
                 * lockstep with one synchronous client was a scaffold, and a
                 * misleading one: when the loop's budget ran out the display
                 * simply stopped answering, which looks exactly like a client
                 * that has hung. A display server has to keep serving whatever
                 * its clients are doing. */
                /* 256 KiB, NOT THE 16 KiB DEFAULT (M2198).
                 *
                 * tools/check-stack-usage.py measured this task's deepest
                 * chain at 15,344 of 16,384 bytes -- 93%, and that is a LOWER
                 * bound, because calls through function pointers are
                 * invisible to it. The chain is not exotic either:
                 *
                 *   wl_server_task -> wl_compositor_poll -> wl_client_release
                 *   -> unix_close -> app_scm_drop_conn -> net_tcp_sock_close
                 *   -> tcp_close -> tcp_send_seg -> nic_send -> bpf_run
                 *   -> bpf_jit_compile
                 *
                 * i.e. a Wayland client disconnecting, which is what happens
                 * every time a Firefox content process exits. M2198 also cut
                 * app_scm_drop_conn's frame from 9,472 bytes to 256, but a
                 * compositor is not the place to run close to the edge of a
                 * stack whose overflow lands past one guard page in another
                 * task's stack -- and every app task already gets 256 KiB. */
                task_create_stack(wl_server_task, 0, 0, 256 * 1024);
                /* The raw client first: it proves whether the BYTES arrive
                 * intact, independently of libwayland's opinion of them. */
                if (g_wlraw) {
                    kprintf("[wl] raw handshake client...\n");
                    app_run_linux_sync("/disk2/lxwlraw", 0, 0, 60000);
                }
                kprintf("[wl] spawning a real libwayland client...\n");
                /* -append wlmt: run the test client the way GECKO drives
                 * libwayland -- a second thread owning prepare_read/
                 * read_events while the main thread dispatches (M2265). If
                 * input stops arriving with that one change, Firefox's
                 * failure is reproduced in a client we control. */
                if (g_wlmt) {
                    static const char *av_mt[] = { "--mtread" };
                    app_spawn_linux_from_file_argv("/disk2/lxwl", av_mt, 1);
                } else
                app_spawn_linux_from_file("/disk2/lxwl");
                /* Wait for a surface, then FALL THROUGH to the desktop: the
                 * window manager is what draws it, so the display has to come
                 * up for there to be anything to look at. */
                for (int t = 0; t < 6000; t++) {
                    task_sleep_ms(10);
                    if (wl_commits() > 0 && t > 60) break;
                }
                if (g_ffwl) {
                    /* FIREFOX ON OUR OWN DISPLAY (M1985). Spawned
                     * ASYNCHRONOUSLY and then left alone: the desktop below is
                     * what draws a surface, so blocking here would mean
                     * nothing could ever appear. Firefox takes minutes to
                     * reach a first paint under TCG; the compositor task and
                     * the window manager both keep running while it does. */
                    /* A REAL PAGE, NOT about:blank (M2105). about:blank proves
                     * a window exists; it does not prove that Gecko parsed
                     * HTML, applied CSS, laid out boxes and painted them --
                     * which is the difference between "the chrome renders"
                     * and "the browser works". file:// needs no network, so it
                     * can be asserted on any boot. */
                    /* `--window-size` IS A FLAG OF `--screenshot` (M2107).
                     *
                     * Firefox's own --help says so: "--window-size
                     * width[,height]  Width and optionally height of
                     * SCREENSHOT." With no --screenshot it sizes nothing --
                     * and, worse, it leaves `800,600` sitting in argv as the
                     * FIRST non-flag argument. Firefox's default command-line
                     * handler opens the first non-flag argument as a URL, so
                     * the browser has been dutifully trying to visit
                     * "800,600" this whole time and `file:///ffpage.html` was
                     * never the URL at all.
                     *
                     * That is why the content area is 90% #f9f9fb: it is not a
                     * renderer that cannot paint a page, it is a browser that
                     * was asked for a different page -- one that cannot
                     * resolve, with no network to tell it so.
                     *
                     * I added the flag in M2105 assuming it meant what the same
                     * spelling means to Chrome. `--new-window <url>` is named
                     * in --help as taking a URL, so the URL can no longer be
                     * positional and cannot be displaced by an argument that
                     * happens to precede it. */
                    /* A data: URL, SELECTABLE, so the filesystem is not part
                     * of the question (M2107). If a page whose entire source is
                     * in argv does not paint, then nothing about file://
                     * resolution, the ext2 path walk or the document loader's
                     * I/O is responsible and the renderer itself is blocked. If
                     * it DOES paint, those are exactly where to look.
                     * `-append ffdata` picks it. */
                    /* The URL is positional AND the homepage is set in the
                     * staged prefs (M2110). Belt and braces deliberately: the
                     * command line is what a desktop launcher uses, and the
                     * homepage pref is what the initial tab loads with no
                     * handler, remote-command path or process-assignment step
                     * in between. The document was opened on some runs and not
                     * others with the command line alone. */
                    /* VERIFY THE STATIC INPUTS FIRST (M2175).
                     *
                     * The 1-in-4 blank page has the parent alive, compositing
                     * normally, and the document fetched byte-for-byte as in a
                     * passing run -- so the decision that goes wrong is made
                     * from data, and until now nothing checked the two pieces
                     * of data it is made from. `ffpage.html` and the staged
                     * prefs are the whole static input to that navigation, and
                     * the concurrent session's finding makes it concrete: a
                     * single unchecked inode-table pointer produced NINE
                     * MILLION garbage block pointers in one run, so a small
                     * file coming back wrong is not a hypothetical.
                     *
                     * `[html] read -> 1068` only ever said the LENGTH matched.
                     * This checks the BYTES, against a hash computed on the
                     * host, for every file in the manifest at or under 64 KiB
                     * -- milliseconds, so it runs on every boot rather than
                     * being an opt-in nobody remembers to pass. */
                    /* Arm the commit-time page watcher BEFORE Firefox starts, so
                     * the very first commit is counted (M2190). */
                    { extern void wl_page_watch(uint32_t argb); wl_page_watch(0x101820); }
                    {   static const char *av_small[] = { "--small", "65536" };
                        int src = app_run_linux_sync("/disk2/lxmapcmp", av_small, 2, 60000);
                        kprintf("[ff] static-input check -> %d (0 = ffpage.html and the prefs "
                                "are byte-identical to the host's copies)\n", src); }
                    static const char *av_fw[] = { "--no-remote", "--new-instance",
                                                   "file:///ffpage.html" };
                    /* -append ffin: THE PAGE THAT MAKES INPUT VISIBLE (M2296).
                     *
                     * Every input measurement before this one aimed a click
                     * at a fixed screen coordinate on a page that had nothing
                     * there, and scrolled a document shorter than the window.
                     * Both correctly produced no change on screen, and both
                     * were read as Firefox ignoring input. This page is pure
                     * CSS -- :hover, :active, :focus over a 6000px body -- so
                     * a pointer move with no click at all repaints a 1280x300
                     * band, and a scroll repaints nearly everything. */
                    static const char *av_fi[] = { "--no-remote", "--new-instance",
                                                   "file:///ffinput.html" };
                    /* A LINK BIG ENOUGH THAT A CLICK CANNOT MISS IT (M2331).
                     * Three attempts to test navigation against a real site
                     * failed because that page's text is generated from live
                     * cluster readings -- "82 milliseconds" becomes "87" --
                     * so the paragraph rewraps between runs and a fixed click
                     * coordinate landed on plain prose every time. The target
                     * here is 70% of the viewport and the destination's TITLE
                     * is the oracle, which only changes when a new document
                     * commits. */
                    static const char *av_nv[] = { "--no-remote", "--new-instance",
                                                   "file:///ffnav.html" };
                    static const char *av_fd[] = { "--no-remote", "--new-instance",
                                                   "data:text/html,<body%20style%3D%22background%3A%23101820%22>"
                                                   "<h1%20style%3D%22color%3A%234fd1c5%22>OS-DEV</h1>" };
                    /* -append ffnet: A PAGE OFF THE ACTUAL INTERNET (M2210).
                     *
                     * Everything measured so far is `file:///ffpage.html`,
                     * which exercises layout, style, the compositor and our
                     * own filesystem and says nothing about the half of a
                     * browser that is a network client. Firefox does NOT use
                     * the kernel's TLS or resolver -- it brings its own NSS and
                     * its own necko -- so "Claude Code reaches the internet"
                     * (M1967) does not transfer: what it needs from us is
                     * sockets, poll, getaddrinfo and a clock, on its own
                     * code paths.
                     *
                     * http, not https, deliberately: a failure at the TCP
                     * layer and a failure inside NSS are different bugs, and
                     * starting with the one that has fewer moving parts is how
                     * the first reading means something. example.com is the
                     * page whose bytes are stable and whose owner expects to
                     * be fetched by test clients.
                     *
                     * The page probe's colour key does not apply to a page
                     * this kernel did not write, so the verdict for this mode
                     * is the SCREENSHOT plus whether the content area stops
                     * being the browser's background -- which is what the
                     * probe's "varied / UNIFORM" line already reports. */
                    static const char *av_fn[] = { "--no-remote", "--new-instance",
                                                   "http://example.com/" };
                    /* A URL THAT IS NOT IN THE SOURCE TREE (M2241).
                     *
                     * Every page measured so far is `file:///ffpage.html` -- a
                     * LOCAL FILE -- so "Firefox works" has never once meant a
                     * real site, and the person asking for it had never seen
                     * one. `ffnet` fixed that for example.com; this fixes it
                     * for any site, without the address becoming part of the
                     * repository.
                     *
                     * The URL lives in /disk2/ffurl.txt, staged from a
                     * gitignored ffurl.txt at the top of the tree. Reading it
                     * at spawn time keeps it out of the kernel image's
                     * strings, out of every commit, and out of the build logs.
                     * Trimmed at the first control character so a trailing
                     * newline cannot become part of the address. */
                    /* ONE URL PER LINE, AND EACH BECOMES A TAB (M2333).
                     *
                     * This read the file and cut it at the first control
                     * character, so a multi-line ffurl.txt silently became its
                     * first line -- one address, one tab. Firefox opens every
                     * URL on its command line as a tab of one window, so the
                     * whole of multi-tab is: stop truncating, and pass them
                     * all. The addresses still never reach the kernel image,
                     * a commit or a build log; only the COUNT is printed. */
                    static char urlbuf[2048];
                    const char *av_uf[2 + FF_MAXTABS];
                    int have_url = 0, nurl = 0;
                    if (g_ffurl) {
                        long un = vfs_pread("/disk2/ffurl.txt", urlbuf, sizeof urlbuf - 1, 0);
                        if (un > 0) {
                            urlbuf[un] = 0;
                            /* Split in place on any control character. Blank
                             * lines and a trailing newline collapse away,
                             * which is what a hand-edited file will have. */
                            av_uf[0] = "--no-remote"; av_uf[1] = "--new-instance";
                            for (long k = 0; k < un && nurl < FF_MAXTABS; ) {
                                while (k < un && (unsigned char)urlbuf[k] < 0x20) urlbuf[k++] = 0;
                                if (k >= un) break;
                                av_uf[2 + nurl++] = &urlbuf[k];
                                while (k < un && (unsigned char)urlbuf[k] >= 0x20) k++;
                            }
                            if (nurl > 0) {
                                have_url = 1;
                                /* Length and scheme only: enough to prove the
                                 * file was read and parsed, without printing
                                 * the address to a console someone may share. */
                                /* kprintf HAS NO PRECISION (M2241). `%.5s`
                                 * printed the four characters "%.5s"
                                 * literally -- console.c's 's' case copies to
                                 * the NUL and never parses a `.N`. So say the
                                 * scheme with a comparison instead of asking
                                 * the formatter for something it does not
                                 * implement. */
                                int is_tls = urlbuf[0]=='h'&&urlbuf[1]=='t'&&urlbuf[2]=='t'&&
                                             urlbuf[3]=='p'&&urlbuf[4]=='s';
                                kprintf("[ff] %d URL(s) from /disk2/ffurl.txt -> %d tab(s); "
                                        "first is %d chars, %s\n", nurl, nurl,
                                        (int)__builtin_strlen(urlbuf),
                                        is_tls ? "https" : "not https");
                            }
                        }
                        if (!have_url)
                            kprintf("[ff] -append ffurl given but /disk2/ffurl.txt is missing or empty "
                                    "-- put the address in ./ffurl.txt and rebuild build/ext2.img\n");
                    }
                    int av_use_n = have_url ? 2 + nurl : 3;
                    const char **av_use = have_url ? av_uf
                                        : (g_ffnav ? av_nv
                                        : (g_ffin ? av_fi
                                        : (g_ffnet ? av_fn : (g_ffdata ? av_fd : av_fw))));
                    /* When Firefox parks, the syscall trace shows a futex
                     * address and nothing else -- it cannot name the Gecko
                     * code that is waiting. Firefox can: MOZ_LOG prints the
                     * widget and Wayland layers' own view of what they are
                     * doing, to stderr, which is our console. (M2010) */
                    if (g_ffmozlog) {
                        /* WEBRENDER, because that is where the question is now
                         * (M2111). The document is loaded and active -- the
                         * window title proves it -- the chrome paints, and the
                         * content area in Firefox's OWN buffer is blank. That
                         * is a compositing question, and `webrender` is the
                         * module that answers it. Widget/nsWindow stay because
                         * they name the surface and size decisions that feed
                         * it; Event and DBus are dropped, because every line
                         * costs serial time and neither is in the path. */
                        /* ipcmessages LOGS EVERY IPDL MESSAGE (M2113), which is
                         * the one thing that can settle the remaining question:
                         * does the content process ever send the parent a
                         * display list? Everything else has been inferred. The
                         * `webrender` module produced nothing at level 5, so it
                         * is not a log module here whatever the string table
                         * says -- checking that cost one run. */
                        /* KNOWN-GOOD MODULE NAMES ONLY (M2114). `webrender`
                         * produced nothing at level 5 and `ipcmessages`
                         * produced nothing AND took Widget down with it -- one
                         * unrecognised name appears to void the whole spec, so
                         * a bad guess does not cost one module, it costs the
                         * run. Widget/nsWindow are the two that have actually
                         * reported anything here. */
                        /* THE DOCUMENT LOAD, NOT THE WINDOW (M2132).
                         *
                         * Widget/nsWindow have said everything they can: the
                         * window exists, it is 1280x960, it is ACTIVATED and
                         * not occluded, and it paints. What is missing is a
                         * DOCUMENT -- the content area shows an in-content
                         * background and the title never leaves "Mozilla
                         * Firefox" -- so the question is which URI Gecko ever
                         * tried to load, and these are the modules that say so.
                         *
                         * M2114's rule applies: one unrecognised module name
                         * appears to void the whole spec, so a bad guess costs
                         * the run rather than one module. Both of these appear
                         * as exact standalone strings in libxul, which is the
                         * check `webrender` and `ipcmessages` failed. */
                        app_set_next_env("G_MESSAGES_DEBUG=all");
                        app_set_next_env("GIO_USE_VFS=local");
                    }
                    if (g_ffgl) {
                        /* WHY IS FIREFOX NOT USING THE GPU? (M2357)
                         *
                         * The GPU works: `lxgl` draws on the host iGPU and
                         * reads the pixel back on the same kernel. Firefox, on
                         * the same boot, never opens /dev/dri at all -- zero
                         * [drm] lines -- and volumeshaderbm runs at 2.7 fps on
                         * the software rasteriser. So the question is not
                         * whether the hardware is reachable but what Firefox
                         * DECIDED, and only Firefox can answer that.
                         *
                         * GLContext logs EGL initialisation and every reason a
                         * context is refused; WebGL logs the backend choice.
                         * DocumentChannel stays as the CONTROL -- it is the one
                         * module M2132 confirmed produces output here, so its
                         * presence tests that MOZ_LOG reached the process at
                         * all. Without that, silence from GLContext and
                         * "MOZ_LOG is not working" are indistinguishable,
                         * which is the mistake M2253 made. */
                        app_set_next_env("MOZ_LOG=timestamp,sync,DocumentChannel:5,GLContext:5,WebGL:5");
                    }
                    /* AND IT IS OPT-IN AGAIN, BECAUSE IT COST 26 SECONDS (M2189).
                     *
                     * Measured, which is what I failed to do when turning it
                     * on. Time from boot to the page on screen, same 1-core
                     * configuration:
                     *
                     *     without this log   36650 / 39280 ms
                     *     with it            64660 / 65670 / 64960 / 80850 ms
                     *
                     * I justified enabling it with "the cost is measured: 209
                     * lines, nothing against what this boot already emits". I
                     * measured the LINE COUNT and called it the cost. The cost
                     * is `sync`, which makes each line block until the serial
                     * console drains -- 208 lines, twenty-six seconds, on a
                     * goal whose first word is "fast".
                     *
                     * It is worse than a slow boot. Those 26 seconds pushed the
                     * slow tail of runs past the capture window, and the
                     * "1-in-4 blank page" I was hunting turned out to be boots
                     * with ZERO and ONE page-probe samples against a passing
                     * boot's seventeen -- they never reached first paint before
                     * the capture closed. The instrument manufactured the
                     * failures it was measuring, which is this campaign's
                     * signature defect and I reproduced it exactly.
                     *
                     * Kept behind `-append ffnavlog` so a deliberate hunt can
                     * still have it. The evidence it was turned on to get has
                     * been got (M2188: the navigation COMPLETES in a failing
                     * boot), so paying for it on every boot buys nothing. */
                    /* NAVIGATION LOGGING, ONCE UNCONDITIONAL (M2185).
                     *
                     * The remaining Firefox defect is a blank page in roughly
                     * one run in four: the parent alive, compositing normally,
                     * the document fetched byte-for-byte as in a passing run,
                     * and the content area showing Firefox's own blank-canvas
                     * grey instead of the page. The document is retrieved and
                     * then never becomes the DISPLAYED document, which makes
                     * this a navigation question -- and `DocumentChannel` plus
                     * `nsDocShell` is the pair that answers it.
                     *
                     * It was behind `-append ffmozlog`, so catching a failure
                     * meant guessing in advance which boot would fail. Four
                     * boots with the flag set all rendered; the failures all
                     * happened in boots without it. That is not bad luck, it is
                     * the same mistake as the static-input check being
                     * opt-in: an instrument you have to predict the bug to
                     * enable is an instrument you do not have.
                     *
                     * It costs 209 lines in a passing run -- measured, not
                     * guessed -- which is nothing against the serial traffic
                     * this boot already produces. In a PASSING run
                     * `uri=file:///ffpage.html` gets five DocumentChannel
                     * records; a failing run either shows them (the navigation
                     * happened and something later discarded it) or does not
                     * (the initial browsing context was never navigated, which
                     * is what M2133 suspected and could not confirm). Either
                     * answer is worth more than a rate.
                     *
                     * M2114's rule still applies: one unrecognised module name
                     * appears to void the whole spec, and both of these appear
                     * as exact standalone strings in libxul -- the check that
                     * `webrender` and `ipcmessages` failed. */
                    /* `nsDocShell` IS EFFECTIVELY SILENT, and that cost half the
                     * spec (M2188). At level 5 it produced exactly ONE line in
                     * a whole boot. The name is real -- it appears as an exact
                     * standalone string in libxul, so M2114's void-the-spec
                     * rule is satisfied and DocumentChannel logged fine -- it
                     * simply has almost nothing at that level. A module that is
                     * valid and silent looks identical to a module that is
                     * answering "nothing happened".
                     *
                     * `DocLoader` and `PresShell` are what the remaining
                     * question needs. The failing boot's navigation COMPLETES:
                     * same destination browsing context as a passing one,
                     * `RedirectToRealChannelFinished aRv=0`,
                     * `FinishReplacementChannelSetup aResult=0`,
                     * `ResumeSuspendedChannel`. So the document is fetched,
                     * navigated and handed over, and the content area still
                     * shows Firefox's blank-canvas grey -- which makes the next
                     * question whether that document ever got a PRESENTATION,
                     * and those two modules are where that is decided. Both
                     * checked against libxul as exact strings.
                     *
                     * Level 3, not 5: PresShell logs paints, and a spec chatty
                     * enough to change the boot's timing would perturb the very
                     * intermittency being chased. */
                    /* AND `DocLoader` AND `PresShell` ARE SILENT TOO (M2189).
                     *
                     * Zero lines across four boots at level 3, after
                     * `nsDocShell:5` produced one line in a whole boot. All
                     * three are exact standalone strings in libxul, so M2114's
                     * void-the-whole-spec rule is satisfied and DocumentChannel
                     * logs normally beside them -- they simply do not emit
                     * here. Three guesses, three silences.
                     *
                     * Dead modules in an always-on spec are cost with no
                     * benefit, and worse, they look like evidence: "PresShell
                     * logged nothing" reads as "the document got no
                     * presentation" when it means "this module does not talk".
                     * So they are removed rather than left in hopefully.
                     *
                     * The presentation question is answerable WITHOUT Gecko's
                     * cooperation: a rendered page commits a 1280x960
                     * wl_surface whose pixels are the page's own background,
                     * and `wl_page_probe` already samples exactly that. Asking
                     * our own compositor what it was handed is cheaper and more
                     * direct than asking Firefox to narrate. (The concurrent
                     * session made this point and it is the right one.) */
                    if (g_ffnavlog)
                        /* WIDGET, BECAUSE THE QUESTION IS NOW INPUT (M2247).
                         * DocumentChannel answered the navigation question
                         * back in M2132 and has nothing to say about a click.
                         * Widget/nsWindow are the two modules M2114 recorded
                         * as actually producing output in this environment --
                         * an unrecognised name voids the whole spec, so this
                         * is not the place to guess. */
                        /* VERIFY THE INSTRUMENT BEFORE TRUSTING ITS SILENCE
                         * (M2253). Widget:5,nsWindow:5 produced ZERO lines,
                         * and "Gecko has nothing to say about input" and
                         * "MOZ_LOG is not reaching Firefox" look identical
                         * from outside. DocumentChannel is the module M2132
                         * confirmed DOES log in this environment, so asking
                         * for it alongside tests the mechanism and the
                         * question in one boot. */
                        app_set_next_env("MOZ_LOG=timestamp,sync,DocumentChannel:5,Widget:5,nsWindow:5");

                        /* GDK'S OWN EVENT TRACE (M2253).
                         *
                         * Widget:5 turned out to log only window lifecycle --
                         * Create, Configure, Resize, occlusion -- and not one
                         * input event, so it cannot answer the only question
                         * left: does GDK RECEIVE the pointer events the
                         * compositor demonstrably puts on the wire? GDK_DEBUG
                         * prints every event it dispatches, which splits
                         * "never arrived" from "arrived and was discarded
                         * above GDK" -- and those need opposite fixes. */
                    /* GDK_DEBUG IS A DEAD INSTRUMENT HERE, AND IT WAS NOT
                     * EVEN GUARDED (M2298).
                     *
                     * Two defects in three lines. First, the `if (g_ffnavlog)`
                     * above has NO BRACES, so it covers the MOZ_LOG line only
                     * and this one ran on every Firefox boot -- a brace-less
                     * if silently capturing one statement of an intended two.
                     *
                     * Second, and the reason it never mattered: GDK_NOTE()
                     * compiles to NOTHING unless libgdk was built with
                     * G_ENABLE_DEBUG, and the host's was not. Checked, not
                     * assumed -- the format strings GDK_DEBUG=events would
                     * print ("motion %f %f", "enter, seat %p surface %p") are
                     * absent from /usr/lib64/libgdk-3.so.0 entirely. So
                     * M2253's "GDK said nothing" was an instrument that
                     * cannot speak, not a GDK that had nothing to say.
                     *
                     * libwayland's WAYLAND_DEBUG is always compiled in, and it
                     * prints one line per event DISPATCHED to a listener plus
                     * a distinct "discarded" line for an event delivered to a
                     * proxy with no listener. That splits the three cases that
                     * matter and cannot be confused: dispatched (the fault is
                     * above libwayland), discarded (the proxy is dead or
                     * unlistened), or absent (the event is sitting in a queue
                     * nobody pumps). */
                    if (g_wlspy) app_set_next_env("WAYLAND_DEBUG=1");
                    /* TYPING IS THE LAST THING FIREFOX IGNORES (M2300).
                     *
                     * M2298 fixed pointer, clicks and scroll -- the compositor
                     * was addressing a wl_pointer nobody listened on. Keys now
                     * reach GDK's wl_keyboard and are dispatched, and still no
                     * text appears, while the SAME keystrokes on the SAME boot
                     * reach a GTK 3.24 client with correct keysyms and a raw
                     * libwayland client turns them into text. So the loss is
                     * Gecko's, above GDK.
                     *
                     * The sharpest difference: lxgtk3 handles key-press-event
                     * directly, and Gecko routes every key through
                     * IMContextWrapper -> gtk_im_context_filter_keypress()
                     * first. Nothing here sets GTK_IM_MODULE, and
                     * gschemas.compiled is missing from the image so GSettings
                     * cannot answer either -- so which module GTK picked is
                     * currently unknown, and one of the candidates
                     * (gtk-im-context-wayland) speaks zwp_text_input_v3, which
                     * this compositor does not implement. A key handed to a
                     * protocol nobody answers is a key that vanishes exactly
                     * like this.
                     *
                     * Two arms, because a fix that works for an unknown reason
                     * is not a fix:
                     *   -append ffimsimple  force the module that just passes
                     *                       keys through
                     *   -append ffimlog     make Gecko say what it did with
                     *                       the key instead of guessing */
                    if (g_ffimsimple) {
                        app_set_next_env("GTK_IM_MODULE=gtk-im-context-simple");
                        app_set_next_env("XMODIFIERS=@im=none");
                        kprintf("[ff] GTK_IM_MODULE forced to gtk-im-context-simple\n");
                    }
                    if (g_ffimlog)
                        app_set_next_env("MOZ_LOG=timestamp,sync,IMEHandler:5,KeyboardHandler:5,Widget:5");
                    /* RENDER THE PAGE IN THE PARENT (M2107).
                     *
                     * Seven of Firefox's child processes exit with status 1 per
                     * startup, silently, and the content area has never shown
                     * anything but Firefox's own blank white. A content process
                     * that cannot start is a content process that cannot lay
                     * out a page, so every page-rendering question was gated
                     * behind a child-process question -- and the two need
                     * completely different fixes.
                     *
                     * MOZ_FORCE_DISABLE_E10S is still honoured by this build
                     * (the string is in libxul; checked, not assumed), and it
                     * puts the content in the parent process. That separates
                     * the two questions: if a page paints this way, Gecko can
                     * parse, style, lay out and paint on OS-DEV and the
                     * remaining work is child-process startup. If it still does
                     * not, the renderer itself is blocked on something and the
                     * child processes were never the reason. */
                    /* E10S OFF IS NOT HOW FIREFOX IS NORMALLY RUN (M2252).
                     *
                     * MOZ_FORCE_DISABLE_E10S puts content in the PARENT
                     * process, which was the right call while the question was
                     * whether child processes could start at all. It is also a
                     * configuration Mozilla barely ships, and Gecko routes
                     * input differently when the content lives in the parent
                     * -- so an input path that works for every normal Firefox
                     * user might simply not be the one we are exercising.
                     *
                     * zenity (M2250) proves the compositor delivers clicks to
                     * a GTK client, so the remaining difference is inside
                     * Gecko; this is the largest non-default thing we do to
                     * it. `-append ffe10s` leaves E10S alone so both arms can
                     * be measured instead of argued about. */
                    if (!g_ffe10s) app_set_next_env("MOZ_FORCE_DISABLE_E10S=1");
                    /* -append ffnowr: TAKE THE RENDERER'S OWN WAYLAND QUEUE
                     * OUT OF THE PICTURE (M2264).
                     *
                     * M2263 localised the input failure to libwayland's
                     * per-proxy event queues inside Gecko: the renderer pumps
                     * its own queue, which is exactly why frame callbacks and
                     * configure work and the page keeps painting, while the
                     * queue GDK's seat proxies live on is never dispatched.
                     * WebRender is what runs that separate renderer thread.
                     * Turning it off is the one lever this side of the ABI
                     * that can test the hypothesis instead of reasoning about
                     * it. */
                    if (g_ffnowr) {
                        app_set_next_env("MOZ_WEBRENDER=0");
                        app_set_next_env("MOZ_ACCELERATED=0");
                    }
                    app_set_next_env("MOZ_DISABLE_CONTENT_SANDBOX=1");
                    /* Snapshot the unaligned-madvise count HERE so the
                     * heartbeat can report Firefox's OWN calls as a delta
                     * (M2195). The probe battery above deliberately makes one,
                     * so the absolute count can never answer "does Firefox do
                     * this" -- it starts at 1 in a healthy boot. A difference
                     * of two samples can. */
                    unsigned long madv0  = app_madv_unaligned();
                    unsigned long mprot0 = app_mprot_unaligned();
                    unsigned long trunc0 = lx_path_truncations();
                    kprintf("[ff] spawning FIREFOX against our compositor "
                            "(content in the PARENT process: MOZ_FORCE_DISABLE_E10S)...\n");
                    /* A GTK CLIENT THAT STARTS IN SECONDS (M2250).
                     *
                     * Every input hypothesis so far has cost a three-minute
                     * Firefox boot to test, which is the wrong debugging loop
                     * for a binary search through a protocol. zenity is GTK --
                     * the same GDK Wayland backend Firefox drives -- in 130 KB
                     * that draws a dialog with a button. If its button
                     * responds to a click, GTK input works here and the fault
                     * is Gecko's; if it does not, the bug reproduces in
                     * something small enough to instrument on both sides. */
                    int spid;
                    if (g_lxgtk3) {
                        /* THE GTK3 CONTROL (M2272). zenity is GTK4 and
                         * Firefox is GTK3 -- different toolkits, different
                         * Wayland backends -- so the zenity result never
                         * applied to Firefox at all. This is the arm that
                         * does. */
                        /* -append gtksub: THE SAME CONTROL, IN GECKO'S SHAPE
                         * (M2297). lxgtk3 responds to a click and Firefox does
                         * not, on the same compositor and the same
                         * libgtk-3.so.0. The difference the compositor's log
                         * shows is that Gecko paints into a SUBSURFACE with an
                         * EMPTY input region, created outside GDK, sitting in
                         * front of everything. --subsurface makes lxgtk3 do
                         * exactly that, so the same binary is its own control:
                         * if the button stops responding, Firefox's bug is
                         * reproduced in a hundred lines instead of thirty
                         * million. */
                        static const char *av_sub[] = { "--subsurface" };
                        if (g_gtksub) {
                            kprintf("[ff] spawning the GTK3 control WITH Gecko's "
                                    "empty-input-region subsurface in front of it\n");
                            spid = app_spawn_linux_from_file_argv("/disk2/lxgtk3", av_sub, 1);
                        } else {
                            kprintf("[ff] spawning the GTK3 control instead of Firefox\n");
                            spid = app_spawn_linux_from_file("/disk2/lxgtk3");
                        }
                    } else if (g_lxgtk) {
                        static const char *av_z[] = { "--info", "--text=OSDEV-GTK-CLICK-ME" };
                        kprintf("[ff] spawning ZENITY (GTK) instead of Firefox: the same toolkit, "
                                "seconds instead of minutes\n");
                        spid = app_spawn_linux_from_file_argv("/disk2/usr/bin/zenity", av_z, 2);
                    } else {
                        spid = app_spawn_linux_from_file_argv("/disk2/usr/lib64/firefox/firefox", av_use, av_use_n);
                    }
                    kprintf("[ff] firefox rc %d pid %d\n", spid, app_last_spawn_pid());
                    if (g_lxdns) {
                        /* THE DNS PROBE, UNDER REAL LOAD (M2321).
                         *
                         * 1160 lookups on a quiet machine came back 1160/1160
                         * clean -- serial AND twelve-way concurrent -- so the
                         * EAI_AGAIN that fails one Claude boot in eight is not
                         * the resolver path being lossy and is not contention
                         * between resolvers. What is left is the state of the
                         * machine around it, and Firefox produces that state
                         * for free: dozens of processes, a saturated eight
                         * cores, gigabytes of COW churn and a NIC already busy
                         * with its own connections. Same load, no quota.
                         *
                         * Spawned ASYNC and deliberately alongside, not after:
                         * running it once Firefox has settled would measure the
                         * quiet machine again with extra steps. */
                        static const char *av_dl[] = { "6", "400", "60" };
                        int dpid = app_spawn_linux_from_file_argv("/disk2/lxdns", av_dl, 3);
                        g_lxdns_spawned = 1;
                        kprintf("[lxabi] lxdns spawned ALONGSIDE the browser (6 threads x 400 "
                                "lookups): rc %d pid %d\n", dpid, app_last_spawn_pid());
                    }
                    /* A HEARTBEAT, because silence is ambiguous (M1996).
                     * Firefox spends minutes relocating an 83-library closure
                     * with no syscalls at all, which is indistinguishable from
                     * having died -- no output, no fault, no window. The global
                     * syscall counter separates the two: if it is advancing the
                     * process is working, and if it is flat it is stuck or
                     * gone. Printed before handing over to the desktop, so it
                     * is not competing with the window manager for the log. */
                    if (g_ffshow) {
                        /* THE VIEWING PATH (M2200): no diagnostic loop holds the
                         * screen. Firefox is already spawned and starting; the
                         * window manager takes the framebuffer now, and
                         * wl_window_poll opens a desktop window for the browser
                         * the moment it commits its first frame -- which is what
                         * somebody sitting in front of the machine wants to
                         * watch happen. A watcher thread keeps the page verdict
                         * flowing to COM1, where it is not in the way. */
                        kprintf("[ff] ffshow: Firefox is starting; handing the framebuffer to the "
                                "desktop NOW. Its window appears when it commits its first frame; "
                                "the page probe keeps reporting on the serial log.\n");
                        task_create_stack(ffshow_watch_task, 0, 0, 64 * 1024);
                    } else {
                        int fpid = app_last_spawn_pid();
                        unsigned long prev = lx_syscalls_made();
                        /* A ONE-SECOND TIMELINE, NOT A FIFTEEN-SECOND ONE (M2102).
                         * The budget says this boot is 95% idle -- twenty
                         * core-seconds of work across fifty of wall -- so the
                         * question is WHERE the wall time goes, and a
                         * fifteen-second heartbeat cannot see a gap smaller
                         * than fifteen seconds. Per second, with the syscall
                         * and fault deltas, the log becomes a timeline and the
                         * quiet stretch names itself. */
                        {   unsigned long ps = lx_syscalls_made();
                            extern uint64_t g_pf_count;
                            uint64_t pf0 = g_pf_count;
                            for (int q = 0; q < 90; q++) {
                                task_sleep_ms(1000);
                                unsigned long ns = lx_syscalls_made();
                                uint64_t pf1 = g_pf_count;
                                /* No width or flag specifiers: this kernel's
                                 * kprintf does not implement them, and asking
                                 * for %-8lu prints the format string itself.
                                 * (M2102) */
                                kprintf("[t] %ds syscalls +%lu faults +%lu\n",
                                        q + 1, ns - ps, (unsigned long)(pf1 - pf0));
                                /* Only when it is plainly spinning: a busy
                                 * second is normal, 50000 calls in one is not,
                                 * and sampling every second would bury the
                                 * timeline in its own output. */
                                /* Sample a BUSY second, and a QUIET one too:
                                 * a stretch making fifty calls a second is
                                 * waiting for something, and which fifty calls
                                 * those are is the only clue to what. The
                                 * middle -- ordinary progress -- is the part
                                 * that needs no sample. (M2103) */
                                if (ns - ps > 50000) lx_ring_top();
                                /* A QUIET SECOND NEEDS A DIFFERENT QUESTION.
                                 * The ring sample is useless below a few
                                 * thousand calls a second -- at sixty a second
                                 * it holds a MINUTE of stale history. What is
                                 * wanted then is not "which call" but "what is
                                 * everyone blocked on", grouped. (M2103) */
                                else if (ns - ps < 400) {
                                    /* ZERO syscalls for a whole second is not
                                     * "quiet", it is DEADLOCK -- every thread
                                     * blocked with nothing to wake them. That
                                     * is this codebase's dominant bug class,
                                     * and app_futex_dump has been able to name
                                     * it since M1959: was a WAKE ever issued
                                     * for a key somebody is STILL parked on?
                                     * (M2105) */
                                    int bp = app_biggest_pid();
                                    app_wait_summary(bp > 0 ? bp : fpid);
                                    if (ns == ps) {
                                        static int dumped;
                                        if (dumped++ < 2) {
                                            kprintf("[t] ZERO syscalls in a second -- every thread is "
                                                    "blocked. The futex ledger:\n");
                                            app_futex_dump();
                                        }
                                    }
                                    /* AND THE FEW CALLS THAT DID HAPPEN. The
                                     * ring TOP is meaningless at forty calls a
                                     * second -- it reports a minute of stale
                                     * history -- but the ring filtered to THIS
                                     * process is exactly the last few things
                                     * it asked for, which is the only clue to
                                     * what it is waiting on. (M2103) */
                                    lx_trace_dump_pid("this quiet second", 10, bp > 0 ? bp : fpid);
                                }
                                ps = ns; pf0 = pf1;
                                {   uint32_t pw = 0, ph = 0; wl_largest_window(&pw, &ph);
                                    if (pw >= 640 && ph >= 480) {
                                        kprintf("[t] PAINTED at t=%ds\n", q + 1);
                                        /* ...AND IS IT A PAGE, OR JUST CHROME?
                                         * A >=640x480 extent is geometry, and
                                         * chrome around an empty content area
                                         * satisfies it exactly as well as a
                                         * loaded page does. (M2106) */
                                        /* A PAGE ARRIVES AFTER THE CHROME
                                         * DOES (M2107). Both probes so far
                                         * fired within seconds of the first
                                         * >=640x480 window -- which is the
                                         * CHROME appearing -- and then the
                                         * loop broke and handed over, so
                                         * nothing ever looked again. "The
                                         * content area is blank" was
                                         * therefore a statement about the
                                         * first few seconds of a browser's
                                         * life, which is blank on any
                                         * machine. Sample a time series. */
                                        /* TWENTY SAMPLES, NOT EIGHT (M2110).
                                         * The homepage is not requested until
                                         * about ninety seconds in on one core
                                         * -- the document's open appeared in
                                         * the log AFTER the last sample -- so
                                         * a sixty-four second window was
                                         * measuring a browser that had not got
                                         * to the page yet and reporting it as
                                         * "only the chrome". */
                                        /* FORTY SAMPLES AT FIFTEEN SECONDS (M2117).
                                         * The headless --screenshot run took
                                         * the better part of ten minutes to
                                         * produce its PNG on one core -- and
                                         * that is the SAME engine doing the
                                         * same layout. So a 160-second window
                                         * after the chrome appears may simply
                                         * be shorter than the work takes, and
                                         * "the content area is blank" would be
                                         * a statement about a browser that has
                                         * not finished yet. Ten minutes. */
                                        for (int k = 0; k < 40; k++) {
                                            task_sleep_ms(15000);
                                            /* IS IT WORKING OR IS IT WAITING?
                                             * (M2136) The page arrives about
                                             * 150s after first paint, and the
                                             * t= heartbeat stops AT first
                                             * paint -- so the whole interval
                                             * that matters had no activity
                                             * data at all. Syscalls and faults
                                             * per sample separate "grinding
                                             * through work" from "parked on a
                                             * timer", which decide completely
                                             * different fixes. */
                                            {   static unsigned long psc, ppf;
                                                unsigned long sc = lx_syscalls_made(), pfn = g_pf_count;
                                                kprintf("[page] --- sample %d, %ds after the first paint "
                                                        "(+%lu syscalls, +%lu faults since the last) ---\n",
                                                        k + 1, (k + 1) * 15,
                                                        sc > psc ? sc - psc : 0,
                                                        pfn > ppf ? pfn - ppf : 0);
                                                psc = sc; ppf = pfn; }
                                            {   extern void lx_syscall_top(int);
                                                extern void lx_syscall_time_top(int);
                                                lx_syscall_top(6);
                                                lx_syscall_time_top(6); }
                                            /* AND WHAT THE DISK DID (M2141).
                                             * pwrite64 costs ~37ms a call and
                                             * that is not the write: it is
                                             * whatever the write has to read
                                             * first. Commands per call is the
                                             * number that says so, and it can
                                             * only be had by counting both. */
                                            {   static uint64_t pc, ps, ph;
                                                uint64_t c = 0, se = 0, h = 0, cx = 0, chh = 0;
                                                ata_io_stats(&c, &se, &h, &cx, &chh);
                                                kprintf("[diskrate] +%lu command(s), +%lu sector(s), "
                                                        "+%lu cache hit(s) since the last sample\n",
                                                        (unsigned long)(c > pc ? c - pc : 0),
                                                        (unsigned long)(se > ps ? se - ps : 0),
                                                        (unsigned long)(h > ph ? h - ph : 0));
                                                pc = c; ps = se; ph = h; }
                                            /* STOP SAMPLING THE MOMENT THE
                                             * PAGE IS THERE (M2200). Forty
                                             * fifteen-second samples ran
                                             * unconditionally, so a boot that
                                             * rendered the page in the FIRST
                                             * sample still held the framebuffer
                                             * for another nine and a half
                                             * minutes before the window manager
                                             * was allowed to draw it. The whole
                                             * point of the display is to be
                                             * looked at, and the probe now says
                                             * whether there is anything to look
                                             * at. */
                                            /* SAY IT, AND KEEP SAMPLING (M2203).
                                             *
                                             * M2201 broke out of this loop on
                                             * the first page verdict, which was
                                             * right for the demo and WRONG for
                                             * the measurement it is part of: a
                                             * rendering run then observed ~50
                                             * seconds of the guest and a blank
                                             * run observed 570, so every other
                                             * per-run count in the series was
                                             * being compared across unequal
                                             * windows. It cost me a correlation
                                             * -- `spin=0` in the one run that
                                             * rendered and 2 in each blank one
                                             * -- that is fully explained by the
                                             * rendering run having been watched
                                             * for a tenth as long.
                                             *
                                             * `ffwl` is the measuring path and
                                             * keeps its whole window. `ffshow`
                                             * is the looking-at path and hands
                                             * the screen over immediately, so
                                             * nothing needs this shortcut. */
                                            if (wl_page_probe(0x101820)) {
                                                static int said_page;
                                                if (!said_page) {
                                                    said_page = 1;
                                                    kprintf("[page] the page is on screen at sample %d "
                                                            "-- sampling on to the end of the window so "
                                                            "this run is comparable with one that never "
                                                            "renders (use ffshow to watch instead)\n",
                                                            k + 1);
                                                }
                                            }
                                            /* AND WHAT EVERY LINUX PROCESS IS
                                             * WAITING FOR (M2108). The page
                                             * area is blank while the content
                                             * process is alive, so the
                                             * question is what that process is
                                             * parked on -- and until now
                                             * nothing could even name it: the
                                             * reports were all keyed on the
                                             * browser PARENT. wchan is a
                                             * kernel PC; tools/wchan.sh turns
                                             * it into a function name. */
                                            if (k == 19 || k == 39) wl_page_dump();
                                            /* POKE IT (M2117). An on-screen
                                             * content paint is driven by the
                                             * refresh driver; a headless
                                             * --screenshot forces one
                                             * synchronously, and that is the
                                             * one that works. So give the
                                             * browser a reason to repaint --
                                             * real pointer motion, a click and
                                             * a keypress, through the same
                                             * path the desktop uses for a
                                             * human. If the content area
                                             * changes after this and not
                                             * before, nothing was ever
                                             * TRIGGERING a content paint, which
                                             * is a different bug from one that
                                             * cannot paint. */
                                            if (k == 6 || k == 14 || k == 24) {
                                                uint32_t pw2 = 0, ph2 = 0;
                                                wl_largest_window(&pw2, &ph2);
                                                int mx = (int)pw2 / 2, my = (int)ph2 / 2;
                                                kprintf("[page] poking the browser: motion to %d,%d, a click and a key\n",
                                                        mx, my);
                                                wl_post_motion(mx, my);
                                                wl_post_motion(mx + 3, my + 2);
                                                wl_post_button(mx + 3, my + 2, 0x110 /*BTN_LEFT*/, 1);
                                                wl_post_button(mx + 3, my + 2, 0x110, 0);
                                                wl_post_key(31 /*evdev 's'*/, 1);
                                                wl_post_key(31, 0);
                                            }
                                            if (k == 4 || k == 20 || k == 38) {
                                                int pids[16];
                                                int np = app_live_pids(pids, 16);
                                                /* EVERY LIVE PROCESS, WITH ITS
                                                 * THREAD COUNT, BEFORE ANY
                                                 * FILTERING (M2131). The detail
                                                 * dump below skips a process
                                                 * with <=2 threads, on the
                                                 * reasoning that it has not
                                                 * started yet -- but "the
                                                 * content process has two
                                                 * threads" IS the answer to
                                                 * why the page is blank, and
                                                 * the filter was hiding
                                                 * exactly that. Every reading
                                                 * so far showed only the
                                                 * 44-thread parent, which
                                                 * looks healthy and is not the
                                                 * process in question. */
                                                kprintf("[page] %d live Linux process(es):", np);
                                                for (int j = 0; j < np; j++)
                                                    kprintf(" pid %d (%d thr)", pids[j],
                                                            app_thread_count(pids[j]));
                                                kprintf("\n");
                                                for (int j = 0; j < np; j++)
                                                    if (app_thread_count(pids[j]) > 2) {
                                                        app_wait_summary(pids[j]);
                                                        app_unix_fds_report(pids[j]);
                                                        /* ...and WHAT IT LAST
                                                         * ASKED FOR. A wchan
                                                         * says where a thread
                                                         * parked; the ring says
                                                         * what the process was
                                                         * doing before it did.
                                                         * "Waiting for a
                                                         * message that never
                                                         * comes" and "never
                                                         * asked for one" are
                                                         * the same wchan. */
                                                        lx_trace_dump_pid("this process", 8, pids[j]);
                                                    }
                                            }
                                            {   int cp2 = 0, cs2 = lx_fatal_signal(&cp2);
                                                if (cs2) { kprintf("[page] pid %d CRASHED with signal %d "
                                                                   "during the page wait\n", cp2, cs2); break; } }
                                        }
                                        break;
                                    }
                                }
                                /* THE LAUNCHER'S PID IS NOT THE BROWSER'S
                                 * (M2105). This broke the loop the moment
                                 * app_state_of(fpid) went negative and called
                                 * it "the process is GONE" -- and Firefox's
                                 * launcher EXITS after re-exec'ing the real
                                 * browser, so that happens at about four
                                 * seconds every single time while the browser
                                 * goes on to create eight surfaces and commit
                                 * frames.
                                 *
                                 * So the reading was of the instrument, not
                                 * the program, and it cut every measurement
                                 * short at four seconds. Liveness is now
                                 * "does a Wayland client still hold a
                                 * connection" -- which is a property of the
                                 * thing being measured rather than of a pid
                                 * that was only ever the first process. */
                                /* A CRASH IS AN EVENT, NOT A COUNTER (M2106).
                                 * Checking liveness by polling could only ever
                                 * report the silence AFTER the crash, and the
                                 * crash line itself was four thousand lines
                                 * back in the log. Ask what killed it. */
                                {   int cpid = 0, csig = lx_fatal_signal(&cpid);
                                    if (csig) {
                                        kprintf("[t] *** pid %d CRASHED with signal %d at t=%ds -- "
                                                "everything after this is the corpse, not a hang ***\n",
                                                cpid, csig, q + 1);
                                        break;
                                    }
                                }
                                if (app_state_of(fpid) < 0 && wl_clients_connected() < 2) {
                                    kprintf("[t] no Wayland client left at t=%ds "
                                            "(launcher pid %d also gone)\n", q + 1, fpid);
                                    break;
                                }
                            }
                        }
                        for (int t = 0; t < 24; t++) {
                            task_sleep_ms(15000);
                            unsigned long now = lx_syscalls_made();
                            int st = app_state_of(fpid);
                            /* THE SAME FALSE SIGNAL, IN THE OTHER LOOP (M2106).
                             * M2105 fixed the launcher-is-not-the-browser
                             * confusion in the timeline above and left this
                             * copy of it fifteen lines below -- so the run was
                             * still cut short by `[ff] the process is GONE`,
                             * just one heartbeat later. Adding a fix to one of
                             * two paths is the mistake this campaign keeps
                             * making; the only defence is to grep for the
                             * other one every time. */
                            int bp2 = app_biggest_pid();
                            kprintf("[ff] t=%ds launcher pid %d state=%d, browser pid %d, "
                                    "%u Wayland client(s), syscalls +%lu, %lu unaligned madvise, "
                                    "%lu unaligned mprotect, %lu truncated path(s)\n",
                                    (t + 1) * 15, fpid, st, bp2, wl_clients_connected(), now - prev,
                                    app_madv_unaligned() - madv0, app_mprot_unaligned() - mprot0,
                                    lx_path_truncations() - trunc0);
                            prev = now;
                            {   int cpid = 0, csig = lx_fatal_signal(&cpid);
                                if (csig) { kprintf("[ff] *** pid %d CRASHED with signal %d ***\n",
                                                    cpid, csig); break; } }
                            if (st < 0 && wl_clients_connected() < 2) {
                                kprintf("[ff] no Wayland client left (launcher pid %d also gone)\n", fpid);
                                break;
                            }
                            /* IF IT HAS PAINTED A WINDOW, STOP WATCHING AND GO
                             * SHOW IT (M2089). This loop spent a fixed six
                             * minutes diagnosing a startup before the window
                             * manager was allowed to run -- which was right
                             * while Firefox never committed anything, and is
                             * exactly backwards now that it commits a full
                             * 1204x916 frame at about two minutes. The point
                             * of the display is to be looked at. 640x480 is
                             * the threshold because lxwl's own 64x32 window is
                             * also in this tree, and handing over for that one
                             * is what used to happen. */
                            {   uint32_t pw = 0, ph = 0; wl_largest_window(&pw, &ph);
                                if (pw >= 640 && ph >= 480) {
                                    kprintf("[time] FIRST PAINT at %lu ms since boot\n",
                                            (unsigned long)timer_ms());
                                    kprintf("[ff] it has PAINTED: a %ux%u window is ready -- "
                                            "handing over to the desktop now rather than at t=360s\n", pw, ph);
                                    wl_page_probe(0x101820);      /* chrome, or a PAGE? (M2106) */
                                    kmain_budget("Firefox has painted its first frame");
                                    break;
                                }
                            }
                            /* Blocked and quiet is the interesting case: the
                             * ring says WHAT it last asked for, which is the
                             * only way to tell "waiting for the compositor"
                             * from "waiting for a file that will never
                             * appear". */
                            /* EVERY tick, not every eighth: correlating a
                             * thread dump with a RIP sample taken from outside
                             * requires them to describe the SAME moment, and
                             * combining two different runs is how I convinced
                             * myself of something that was not true. (M1998) */
                            app_dump_threads(fpid);
                            if (t == 7 || t == 15 || t == 23) {
                                lx_trace_dump_last("the Firefox heartbeat", 24);
                                /* ...AND THE FUTEX LEDGER (M2081).
                                 *
                                 * Every thread in the dump above is parked in
                                 * app_futex, and "blocked on a futex" is the
                                 * answer for a healthy idle browser as much as
                                 * a hung one -- the thread dump cannot tell
                                 * them apart. The question that can is
                                 * narrower, and app_futex_dump has answered it
                                 * since M1959: was a WAKE ever issued for a
                                 * key somebody is STILL parked on? That is a
                                 * lost wakeup, and it is the only reading here
                                 * that separates "waiting for work" from
                                 * "waiting for a signal that already came and
                                 * went". It was wired into the synchronous-run
                                 * timeout only, and Firefox is spawned
                                 * ASYNCHRONOUSLY -- so the one path that most
                                 * needed it was the one path that never
                                 * called it. */
                                app_futex_dump();
                            }
                        }
                    }
                }
                if (g_fftest) {
                    /* FIREFOX, against our own compositor. It is far heavier
                     * than anything run here before -- a 268 MB install with
                     * an 83-library closure -- so this is its own boot, and
                     * the first run is about finding out what it asks for. */
                    static const char *av_ff[] = { "--version" };
                    kprintf("[ff] running FIREFOX --version...\n");
                    int frc = app_run_linux_sync("/disk2/usr/lib64/firefox/firefox", av_ff, 1, 1200000);
                    kprintf("[ff] firefox --version -> %d\n", frc);
                }
                {   uint32_t ew = 0, eh = 0; wl_largest_window(&ew, &eh);
                    kprintf("[wl] window ready: root surface %ux%u, biggest client tree %ux%u -- "
                            "handing over to the desktop\n",
                            wl_last_width(), wl_last_height(), ew, eh); }
                /* If the client stalled, the ring says what it was doing --
                 * a compositor that sent everything correctly and a client
                 * that never reads look identical from this side. */
                if (wl_messages_handled() < 4) lx_trace_dump("a stalled Wayland client");
                kprintf("[wl] summary: %u client(s), %u message(s), %u global(s) sent\n",
                        wl_clients_connected(), wl_messages_handled(), wl_globals_sent());
            }
        }
        if (g_ffshot) {
            /* FIREFOX HEADLESS, RENDERING A REAL PAGE TO A REAL PNG (M2003).
             *
             * Two things at once. As a DEMO it is the whole browser -- parse,
             * style, lay out, paint, encode -- producing a file we can look at,
             * with no compositor involved at all. As a DIAGNOSTIC it splits the
             * question in half: Firefox dies 30 seconds into startup writing
             * through a null pointer, and if it dies the same way with no
             * display then the display is not what is wrong.
             *
             * Synchronous: the assertion is on the PNG existing afterwards. */
            vfs_mkdir("/disk2/tmp");
            /* RENDER THE PAGE WE ACTUALLY WANT TO SEE (M2107). /etc/hosts is
             * plain text: it proves the encoder runs, and says nothing about
             * the cascade or about box layout. ffpage.html has a body
             * background, a heading colour and three positioned boxes, so the
             * PNG's own pixels answer whether Gecko styles and lays out on
             * this kernel -- which is the question left after the on-screen
             * content area turned out to be a blank document. */
            static const char *av_fs[] = { "--headless", "--no-remote", "--new-instance",
                                           "--screenshot", "/tmp/ffshot.png",
                                           "--window-size", "400,300",
                                           "file:///ffpage.html" };
            kprintf("[ff] FIREFOX HEADLESS: rendering a page to /tmp/ffshot.png...\n");
            int src = app_run_linux_sync("/disk2/usr/lib64/firefox/firefox", av_fs, 8, 1500000);
            kprintf("[ff] firefox --screenshot -> %d\n", src);
            struct statx sx;
            if (vfs_stat("/disk2/tmp/ffshot.png", &sx) == 0 && sx.stx_size > 0) {
                uint8_t hdr[8]; long got = vfs_pread("/disk2/tmp/ffshot.png", hdr, 8, 0);
                kprintf("[ff] FFSHOT: %lu bytes, first 8 = %02x %02x %02x %02x %02x %02x %02x %02x (want 89 50 4e 47)\n",
                        (unsigned long)sx.stx_size, hdr[0], hdr[1], hdr[2], hdr[3],
                        hdr[4], hdr[5], hdr[6], hdr[7]);
                (void)got;
                /* AND THE PIXELS THEMSELVES (M2107). "A PNG exists and starts
                 * with the right magic" is a statement about the encoder. It
                 * was true while the on-screen content area was blank, so it
                 * cannot distinguish a rendered page from a rendered blank
                 * one -- which is the only distinction that matters now.
                 *
                 * The image lives on a -snapshot disk that is discarded at
                 * power off, so there is nothing to copy out afterwards: it
                 * has to leave through the serial line. Hex, in 48-byte lines,
                 * reassembled and decoded on the host. */
                {
                    static uint8_t pb[2048];
                    long off = 0, total = (long)sx.stx_size;
                    kprintf("[ff] FFSHOT-PNGBEGIN %ld\n", total);
                    while (off < total) {
                        long want = total - off; if (want > (long)sizeof pb) want = (long)sizeof pb;
                        long n = vfs_pread("/disk2/tmp/ffshot.png", pb, (unsigned long)want, (uint64_t)off);
                        if (n <= 0) { kprintf("\n[ff] FFSHOT-PNGCUT at %ld (pread -> %ld)\n", off, n); break; }
                        for (long i = 0; i < n; i++) {
                            kprintf("%02x", pb[i]);
                            if (((off + i + 1) % 48) == 0) kprintf("\n");
                        }
                        off += n;
                    }
                    kprintf("\n[ff] FFSHOT-PNGEND %ld\n", off);
                }
            } else {
                kprintf("[ff] FFSHOT: no PNG was written\n");
            }
        }
        if (g_lxclaude_test) {
            /* Claude Code on its own boot. It is a 214 MB non-PIE ET_EXEC
             * image linked at 0x200000, so it is the first thing this OS has
             * ever run that needs the low 1 GiB to belong to the process
             * rather than to the kernel. */
            /* DEEP FILE READS (M1974). Claude Code's data segment is
             * demand-paged from file offsets up to 223 MB -- far past anything
             * else here -- and a read that fails or short-reads at depth does
             * not raise an error, it silently leaves the page zero-filled.
             * That would look exactly like what we see: the image loads, runs,
             * and its allocator finds nonsense. Check it directly against
             * bytes taken from the host copy. */
            {
                static const struct { uint64_t off; const char *want; } deep[] = {
                    { 0u,         "7f454c46" },
                    { 67108864u,  "3741b801" },
                    { 134217728u, "9f404025" },
                    { 201326592u, "4f662874" },
                };
                for (int d = 0; d < 4; d++) {
                    uint8_t rb[4] = {0,0,0,0};
                    long got = vfs_pread("/disk2/usr/bin/claude", rb, 4, deep[d].off);
                    kprintf("[lxclaude] read@%lu -> %ld bytes %02x%02x%02x%02x (want %s)\n",
                            (unsigned long)deep[d].off, got, rb[0], rb[1], rb[2], rb[3], deep[d].want);
                }
            }
            static const char *av_cv1[] = { "--version" };
            kprintf("[lxclaude] running CLAUDE CODE (214 MB non-PIE ET_EXEC at 0x200000)...\n");
            if (g_lxtrace_make) g_lx_systrace = 1;
            int crc1 = app_run_linux_sync("/disk2/usr/bin/claude", av_cv1, 1, 900000);
            g_lx_systrace = 0;
            kprintf("[lxclaude] claude --version -> %d\n", crc1);

            /* --help is a far larger exercise than --version: it runs the whole
             * argument parser and help renderer, i.e. a real amount of the
             * bundled JavaScript rather than printing one constant. Needs no
             * network and no credentials. (M1976) */
            static const char *av_ch[] = { "--help" };
            kprintf("[lxclaude] running CLAUDE CODE --help (the full CLI, not a constant)...\n");
            int crc2 = app_run_linux_sync("/disk2/usr/bin/claude", av_ch, 1, 900000);
            kprintf("[lxclaude] claude --help -> %d\n", crc2);
            /* AND NOW A REAL REQUEST (M1988). -p is non-interactive print mode:
             * it loads the config, resolves api.anthropic.com, opens TLS and
             * asks for a completion. There are DELIBERATELY no credentials in
             * this image -- staging the developer's own ~/.claude into a guest
             * disk is not something a test should do -- so the expected answer
             * is an authentication error. That is still the result worth
             * having: an auth error means DNS, TCP, TLS and the HTTP client all
             * worked, and anything earlier names which one did not. */
            static const char *av_cp[] = { "-p", "say hi" };
            kprintf("[lxclaude] running CLAUDE CODE -p (config + DNS + TLS + HTTP)...\n");
            int crc3 = app_run_linux_sync("/disk2/usr/bin/claude", av_cp, 2, 300000);
            kprintf("[lxclaude] claude -p -> %d\n", crc3);
            /* AND THE NETWORK PATH, which the run above never reaches (M1999).
             *
             * "Not logged in - Please run /login" is the correct answer for an
             * image with no credentials, but it is a LOCAL check: Claude Code
             * short-circuits there before any DNS lookup, TCP connect or TLS
             * handshake happens, so exiting cleanly says nothing at all about
             * whether this kernel can carry an HTTPS request.
             *
             * Hand it a DELIBERATELY FAKE key and it stops short-circuiting:
             * it resolves api.anthropic.com over our DNS, opens a TCP
             * connection over our stack, completes a TLS handshake with
             * Node's bundled OpenSSL, sends a real POST and reads a real
             * response. The server answers 401, which is exactly right for a
             * key that is not a key -- and a 401 that came back over the wire
             * proves every layer underneath it.
             *
             * The key is a placeholder, in the source, carrying nothing. The
             * developer's own ~/.claude is never staged into a guest image. */
            app_set_next_env("ANTHROPIC_API_KEY=sk-ant-api03-osdev-placeholder-this-is-not-a-real-key");
            kprintf("[lxclaude] running CLAUDE CODE -p WITH a (fake) key: DNS + TLS + HTTP for real...\n");
            int crc4 = app_run_linux_sync("/disk2/usr/bin/claude", av_cp, 2, 300000);
            kprintf("[lxclaude] claude -p (fake key) -> %d\n", crc4);
        }
        if (g_lxask) {
            /* PHASE 7, asked as plainly as it can be asked: one question, in
             * the OS-DEV source tree, answered by Claude Code running on this
             * kernel. -p is print mode, so there is no TUI and no trust
             * prompt to get past -- the answer is bytes on stdout, which
             * lxout puts in this log as text.
             *
             * --dangerously-skip-permissions because print mode in a
             * directory the config has never seen otherwise stops to ask, and
             * a synchronous run has no one to answer. */
            /* --debug because this flag exists to DIAGNOSE. Claude Code's own
             * HTTP/retry/stream logging is the only thing that can say what it
             * believes is happening on a connection we cannot decrypt, and
             * with lxout it lands in this log as text. (M2056) */
            /* ...AND WITH -append lxbash, ASK IT TO RUN A COMMAND (M2118).
             *
             * The Bash tool has never worked inside OS-DEV, and M2107 found
             * why: st_dev came back 0x801 from stat and ZERO from statx, so
             * Bun's Zig standard library -- which records (st_dev, st_ino) for
             * the working directory and re-checks it before spawning -- decided
             * the directory had been swapped underneath it and refused. The
             * guest Claude diagnosed that itself, from the inside.
             *
             * A fix for that has to be demonstrated by a TOOL CALL, not by
             * `claude --version`. So the prompt asks for one, and asks for a
             * string that cannot appear by accident: if OSDEV-BASH-OK reaches
             * this log, a Linux program running on this kernel spawned a
             * subprocess, read its output back, and returned it through a live
             * HTTPS conversation. */
            static const char *av_ask[] = { "--dangerously-skip-permissions", "--debug", "-p",
                                            "Reply with exactly: OS-DEV" };
            static const char *av_bash[] = { "--dangerously-skip-permissions", "--debug", "-p",
                                             "Use the Bash tool to run exactly: echo OSDEV-BASH-OK" };
            /* ...AND WITH -append lxedit, ASK IT TO EDIT A FILE (M2170).
             *
             * This is the phase's actual DEMO, in the plan's own words: "claude
             * starts in a window, authenticates, and edits a file in the OS-DEV
             * source tree -- inside OS-DEV." The Bash tool being met (M2130)
             * proves a subprocess and a pipe; it does not prove a WRITE. Those
             * are different paths -- Write/Edit go through the Linux ABI's
             * openat(O_CREAT|O_TRUNC)/write/close against ext2, not through
             * fork and a pipe -- and this OS-DEV's own source tree is what is
             * mounted at /disk2/src, so the file it edits is the real thing.
             *
             * The prompt names a file OUTSIDE the tree's tracked content and a
             * string that cannot appear by accident, so the marker can only
             * reach the log by travelling: the API decided to call the tool,
             * the tool opened and wrote a file on ext2 through this kernel, and
             * the read-back came home. It asks for the read-back explicitly
             * because "the tool reported success" is exactly the kind of claim
             * this project has learned not to accept. */
            static const char *av_edit[] = { "--dangerously-skip-permissions", "--debug", "-p",
                                             /* `/src`, the GUEST's view. The first run said
                                              * `/disk2/src/...`, which the ABI translated to
                                              * `/disk2/disk2/src/...`; the demo still passed
                                              * because Claude Code probed, got ENOENT and wrote
                                              * to the right place, but the log carries three
                                              * misleading ENOENTs for a path nobody asked for.
                                              * (M2182) */
                                             "Create the file /src/OSDEV-EDIT.txt containing "
                                             "exactly the line OSDEV-EDIT-OK, then read it back with "
                                             "the Read tool and reply with its contents." };
            const char **av_use2 = g_lxedit ? av_edit : (g_lxbash ? av_bash : av_ask);
            /* IS_SANDBOX=1, because we are uid 0 and Claude Code refuses
             * --dangerously-skip-permissions as root (M2119):
             *
             *   --dangerously-skip-permissions cannot be used with root/sudo
             *   privileges for security reasons
             *
             * Its own code names the escape: refuseBypassUnderRoot() calls
             * isRootOutsideDeliberateSandbox(), and IS_SANDBOX is what makes
             * the sandbox deliberate. This whole OS is one address space with
             * one user; there is no less-privileged account to drop to, and
             * inventing one to satisfy a check would be pretending to a
             * separation that does not exist here. Saying so is the honest
             * answer, and it is the answer the tool provides for. */
            app_set_next_env("IS_SANDBOX=1");
            app_set_next_cwd("/disk2/src");
            kprintf("[lxask] PHASE 7 DEMO: claude -p, in /src, on this kernel...\n");
            int arc = app_run_linux_sync("/disk2/usr/bin/claude", av_use2, 4, 900000);
            kprintf("[lxask] claude -p -> %d\n", arc);
        }
        if (g_lxinet_test) {
            /* AF_INET through the ABI (M1967): a DNS lookup over UDP and an
             * HTTP request over TCP, both driven by poll(). Its OWN boot --
             * it needs a working NIC and the real internet, and running it
             * beside eight other glibc processes on a 256 MiB machine would
             * make it a test of the host's network rather than of ours. */
            kprintf("[lxabi] launching the AF_INET socket test (DNS + HTTP over poll)...\n");
            int inetrc = app_run_linux_sync("/disk2/lxinet", 0, 0, 60000);
            kprintf("[lxabi] lxinet exit -> %d\n", inetrc);
            /* ...AND THEN THE SAME QUESTION THROUGH GLIBC (M2128). lxinet builds
             * its own DNS query, so it proves the wire works and says nothing
             * about getaddrinfo -- which is the only thing Node and Claude Code
             * use, and which fails with EAI_AGAIN while lxinet succeeds on the
             * same boot. lxgai is dynamically linked for exactly that reason. */
            kprintf("[lxabi] launching the glibc getaddrinfo probe...\n");
            int gairc = app_run_linux_sync("/disk2/lxgai", 0, 0, 60000);
            kprintf("[lxabi] lxgai exit -> %d\n", gairc);
        }
        if (g_lxport) {
            /* THE PORT ALLOCATOR, ASKED DIRECTLY (M2324). The DNS symptom needs
             * load, concurrency and about ten minutes to show itself once. The
             * cause -- two live sockets on one local port -- is a fact that
             * getsockname will state in a second, with no network involved. */
            kprintf("[lxabi] 480 datagram sockets at once: does any local port repeat?...\n");
            int prc = app_run_linux_sync("/disk2/lxport", 0, 0, 120000);
            kprintf("[lxabi] lxport exit -> %d\n", prc);
        }
        if (g_lxdns && !g_lxdns_spawned) {
            /* THE SAME CALL, TWO HUNDRED TIMES (M2320).
             *
             * lxgai asks getaddrinfo once and names which step failed. That is
             * the right shape for a lookup that ALWAYS fails, and the wrong one
             * for a lookup that fails one time in fifty: a single sample of an
             * intermittent failure is a coin toss reported as a finding.
             *
             * Every sample taken of this bug so far has cost a twelve-minute
             * `claude -p` boot and a slice of an account quota to produce about
             * ten lookups -- and the quota is not hypothetical, four boots of
             * the last batch died on "You've hit your session limit" and were
             * very nearly read as a kernel failure. This produces two hundred
             * lookups in fifteen seconds and spends nothing.
             */
            /* TWO ARMS, ONE BOOT (M2321). The serial sweep came back 200/200
             * clean, so the resolver path is not simply lossy and the failure
             * needs something a Claude boot has that the probe did not. The
             * first candidate is concurrency: Claude Code resolves from a
             * dozen threads at once. Running the control and the treatment in
             * the same boot is what makes that a discriminator rather than two
             * numbers from two afternoons. */
            static const char *av_serial[] = { "1", "200", "50" };
            static const char *av_conc[]   = { "12", "80", "30" };
            kprintf("[lxabi] getaddrinfo, ARM 1 of 2: 1 thread x 200 lookups (the control)...\n");
            int dnsrc = app_run_linux_sync("/disk2/lxdns", av_serial, 3, 300000);
            kprintf("[lxabi] lxdns serial exit -> %d\n", dnsrc);
            kprintf("[lxabi] getaddrinfo, ARM 2 of 2: 12 threads x 80 lookups (the treatment)...\n");
            int dnsrc2 = app_run_linux_sync("/disk2/lxdns", av_conc, 3, 300000);
            kprintf("[lxabi] lxdns concurrent exit -> %d\n", dnsrc2);
        }
        if (g_lxtool_test) {
            /* PHASE 4 (M1955): drive the BORROWED host toolchain inside OS-DEV.
             *
             * Everything else that runs here is written from scratch in this
             * repo. These four binaries are not: they are unmodified host
             * binutils, copied in whole and run through the Linux ABI shim.
             * That is the deal -- we never port a toolchain, we run one.
             *
             * Sequential on purpose, via app_run_linux_sync: `ld` must not
             * open the object file before `as` has finished writing it. */
            static const char *av_asver[] = { "--version" };
            static const char *av_as[]    = { "-o", "/t.o", "/hello.s" };
            static const char *av_ld[]    = { "--no-dynamic-linker", "-pie", "-e", "_start",
                                              "-o", "/t.elf", "/t.o" };
            /* Delete the outputs FIRST. The ext2 volume is persistent across
             * boots, so without this a stale /t.elf from an earlier run
             * satisfies the "ran the program it just built" assertion even
             * when the assembler never started -- which is exactly what a
             * mutation test caught: reverting the st_ino fix broke as and ld,
             * and that last check still passed. */
            vfs_remove("/disk2/t.o");
            vfs_remove("/disk2/t.elf");
            kprintf("[lxtool] running the borrowed GNU assembler...\n");
            /* 60000 -> 120000 (M2038). This step was given HALF the budget of
             * every neighbouring one while doing equivalent-or-more work: it is
             * the first dynamically-linked program of the run, so it pays for
             * the loader plus five shared objects with nothing warm. Under host
             * CPU contention -- and this suite is deliberately run concurrently
             * with others -- it blew the budget, app_run_linux_sync killed it
             * before its fully-buffered non-tty stdout ever flushed the "GNU
             * assembler" banner, and the first assertion failed with every
             * later one cascading off it. That reads exactly like a broken
             * toolchain and is a stopwatch. */
            int rc = app_run_linux_sync("/disk2/usr/bin/as", av_asver, 1, 120000);
            kprintf("[lxtool] as --version -> %d\n", rc);
            kprintf("[lxtool] assembling /hello.s -> /t.o ...\n");
            rc = app_run_linux_sync("/disk2/usr/bin/as", av_as, 3, 120000);
            kprintf("[lxtool] as -> %d\n", rc);
            kprintf("[lxtool] linking /t.o -> /t.elf ...\n");
            rc = app_run_linux_sync("/disk2/usr/bin/ld", av_ld, 7, 120000);
            kprintf("[lxtool] ld -> %d\n", rc);
            /* The only assertion that matters: RUN what the guest just built.
             * Exit status 23 is hello.s's own, so it proves the bytes on disk
             * came from this assemble+link and not from a staged binary. */
            kprintf("[lxtool] running the program OS-DEV just built...\n");
            rc = app_run_linux_sync("/disk2/t.elf", 0, 0, 60000);
            kprintf("[lxtool] SELFBUILT exit -> %d\n", rc);

            /* And the real thing: a C COMPILER. cc1 is a 42 MB dynamically
             * linked PIE, which only became loadable once the kernel stopped
             * buffering an executable's whole image and started mapping its
             * segments from the file. (M1957) */
            vfs_remove("/disk2/t.s");
            vfs_remove("/disk2/tc.o");
            vfs_remove("/disk2/tc.elf");
            static const char *av_cc1[] = { "-quiet", "-nostdinc", "/hello.c", "-o", "/t.s" };   /* -nostdinc: the source is freestanding, and without it cc1 goes looking for stdc-predef.h */
            static const char *av_as2[] = { "-o", "/tc.o", "/t.s" };
            static const char *av_ld2[] = { "--no-dynamic-linker", "-pie", "-e", "_start",
                                            "-o", "/tc.elf", "/tc.o" };
            kprintf("[lxtool] COMPILING /hello.c with real GCC (cc1)...\n");
            rc = app_run_linux_sync("/disk2/usr/bin/cc1", av_cc1, 5, 180000);
            kprintf("[lxtool] cc1 -> %d\n", rc);
            kprintf("[lxtool] assembling the compiler's output...\n");
            rc = app_run_linux_sync("/disk2/usr/bin/as", av_as2, 3, 120000);
            kprintf("[lxtool] as(cc1 output) -> %d\n", rc);
            rc = app_run_linux_sync("/disk2/usr/bin/ld", av_ld2, 7, 120000);
            kprintf("[lxtool] ld(cc1 output) -> %d\n", rc);
            kprintf("[lxtool] running the C program OS-DEV just compiled...\n");
            rc = app_run_linux_sync("/disk2/tc.elf", 0, 0, 60000);
            kprintf("[lxtool] CCSELF exit -> %d\n", rc);

            /* PHASE 5's first step: GNU make, driving that toolchain. make is
             * a different kind of demand on the ABI from a compiler -- it
             * stats targets, compares timestamps, forks a SHELL per recipe
             * line and waits for it. /bin/sh is a real bash. (M1958) */
            vfs_remove("/disk2/mk.s");
            vfs_remove("/disk2/mk.o");
            vfs_remove("/disk2/mk.elf");
            static const char *av_make[] = { "-f", "/Makefile.guest" };
            kprintf("[lxtool] running GNU make inside OS-DEV...\n");
            if (g_lxtrace_make) g_lx_systrace = 1;
            rc = app_run_linux_sync("/disk2/usr/bin/make", av_make, 2, 240000);
            g_lx_systrace = 0;
            kprintf("[lxtool] make -> %d\n", rc);
            kprintf("[lxtool] running what make built...\n");
            rc = app_run_linux_sync("/disk2/mk.elf", 0, 0, 60000);
            kprintf("[lxtool] MAKEBUILT exit -> %d\n", rc);

        }
        if (g_lxnode_test) {
            /* PHASE 6: real Node.js, unmodified, through the compatibility
             * shim. Start with --version -- the cheapest thing that still
             * requires the whole 102 MB image to load, ld.so to resolve 21
             * shared libraries, and V8 to initialise. (M1964) */
            int rc;
            static const char *av_nv[] = { "--version" };
            kprintf("[lxnode] running real Node.js...\n");
            rc = app_run_linux_sync("/disk2/usr/bin/node", av_nv, 1, 600000);
            kprintf("[lxnode] node --version -> %d\n", rc);

            /* Now actually EXECUTE JavaScript: V8 has to parse, compile and
             * JIT it. The arithmetic is deliberate -- "2" can only be printed
             * by a working engine, not by a startup path that happens to
             * survive. (M1964) */
            static const char *av_ne[] = { "-e", "console.log('LXNODE:', 1+1, process.platform, process.arch)" };
            kprintf("[lxnode] running JavaScript...\n");
            rc = app_run_linux_sync("/disk2/usr/bin/node", av_ne, 2, 600000);
            kprintf("[lxnode] node -e -> %d\n", rc);

            /* Real FILE I/O from JavaScript: write a file, read it back,
             * stat it, and list a directory -- the whole fs module path
             * through libuv onto our ext2 driver. */
            static const char *av_nf[] = { "-e",
                "const fs=require('fs');fs.writeFileSync('/nodetest.txt','hello from node in OS-DEV\\n');"
                "const s=fs.readFileSync('/nodetest.txt','utf8');"
                "console.log('LXNODEFS:', s.trim().length, fs.statSync('/nodetest.txt').size, fs.readdirSync('/').length>0);" };
            kprintf("[lxnode] running JavaScript that does FILE I/O...\n");
            rc = app_run_linux_sync("/disk2/usr/bin/node", av_nf, 2, 600000);
            kprintf("[lxnode] node fs -> %d\n", rc);

            /* REAL SOCKETS: a server and a client over AF_UNIX, driven by
             * Node's own event loop. This is the assertion that matters for
             * Phase 6 -- it exercises socket/bind/listen/accept/connect plus
             * epoll readiness and read/write, all through the fd table. */
            vfs_remove("/disk2/nodesock");
            static const char *av_ns[] = { "-e",
                "const net=require('net');"
                "const s=net.createServer(c=>c.on('data',d=>c.write('echo:'+d)));"
                "s.listen('/nodesock',()=>{const k=net.connect('/nodesock',()=>k.write('ping'));"
                "k.on('data',d=>{console.log('LXNODESOCK:',d.toString());k.end();s.close();});});" };
            kprintf("[lxnode] running JavaScript that uses SOCKETS...\n");
            if (g_lxtrace_make) g_lx_systrace = 1;
            rc = app_run_linux_sync("/disk2/usr/bin/node", av_ns, 2, 600000);
            g_lx_systrace = 0;
            kprintf("[lxnode] node net -> %d\n", rc);

            /* PHASE 6'S ACTUAL GATE (M1967): "do not claim the phase until a
             * script that touches the network runs." A DNS lookup and an HTTP
             * request, from Node, over AF_INET sockets that libuv polls --
             * which needed a per-socket receive ring and a non-blocking pump
             * before poll() could answer for them at all. */
            static const char *av_nn[] = { "-e",
                "const http=require('http');"
                "http.get('http://example.com/',r=>{let n=0;"
                "r.on('data',d=>{n+=d.length;});"
                "r.on('end',()=>console.log('LXNODEHTTP:',r.statusCode,n));})"
                ".on('error',e=>console.log('LXNODEHTTP-ERR:',e.message));" };
            kprintf("[lxnode] running JavaScript that uses the NETWORK (DNS + HTTP)...\n");
            rc = app_run_linux_sync("/disk2/usr/bin/node", av_nn, 2, 900000);
            kprintf("[lxnode] node http -> %d\n", rc);

            /* PHASE 7's first gate (M1968): HTTPS. Node's own bundled OpenSSL
             * doing a TLS 1.3 handshake over our TCP stack -- a far harder
             * exercise of it than plain HTTP, because a handshake is a
             * multi-round-trip conversation where a single lost or truncated
             * record kills the connection. Claude Code talks to nothing that
             * is not TLS. */
            static const char *av_nt[] = { "-e",
                "const https=require('https');"
                "https.get('https://example.com/',r=>{let n=0;"
                "r.on('data',d=>{n+=d.length;});"
                "r.on('end',()=>console.log('LXNODETLS:',r.statusCode,n));})"
                ".on('error',e=>console.log('LXNODETLS-ERR:',e.message));" };
            kprintf("[lxnode] running JavaScript that uses HTTPS (TLS via Node's OpenSSL)...\n");
            rc = app_run_linux_sync("/disk2/usr/bin/node", av_nt, 2, 900000);
            kprintf("[lxnode] node https -> %d\n", rc);

            /* Does V8 hold up at SCALE? Claude Code is ~50 MB of bundled JS
             * and sweeps its data segment with 1000+ MADV_WILLNEED calls
             * before it aborts; every Node test so far has been a one-line
             * script. Allocate and collect a few hundred MB so the GC, the
             * page allocator and the demand-fault path are all exercised
             * properly, and print a number only a working engine produces.
             * (M1974) */
            static const char *av_hs[] = { "-e",
                "let keep=[];let total=0;"
                "for(let r=0;r<12;r++){let a=[];"
                "for(let i=0;i<24;i++){a.push(Buffer.alloc(1<<20,r+i));total+=1<<20;}"
                "keep.push(a[0]);if(global.gc)global.gc();}"
                "let sum=0;for(const b of keep)sum+=b[0];"
                "console.log('LXNODEHEAP:',(total>>20),'MiB churned, keep',keep.length,'sum',sum);" };
            kprintf("[lxnode] running a JavaScript HEAP STRESS (hundreds of MB)...\n");
            rc = app_run_linux_sync("/disk2/usr/bin/node", av_hs, 2, 900000);
            kprintf("[lxnode] node heap -> %d\n", rc);

            /* PHASE 7 (M1968): Claude Code itself. A single 214 MB
             * dynamically-linked ELF -- a Node single-executable app, runtime
             * and JS in one image -- so it loads the same way node does, only
             * bigger. --version first: it is the smallest thing that proves
             * the image loaded, relocated and reached its own JS. */
            static const char *av_cv[] = { "--version" };
            kprintf("[lxnode] running CLAUDE CODE (214 MB single-file Node app)...\n");
            rc = app_run_linux_sync("/disk2/usr/bin/claude", av_cv, 1, 900000);
            kprintf("[lxnode] claude --version -> %d\n", rc);
        }
        if (g_lxgcc_test) {
            /* PHASE 5, ON ITS OWN BOOT: the real GCC DRIVER compiling OS-DEV's
             * OWN SOURCE with OS-DEV's own CFLAGS. Not a toy .c -- kernel/elf.c,
             * the actual ELF loader this kernel uses, built freestanding exactly
             * as the host Makefile builds it. The driver is a step beyond cc1:
             * it forks and execs cc1 AND as itself, by absolute path.
             *
             * Separate from lxtooltest deliberately. That boot already runs
             * eleven in-guest programs, and compiling a real kernel source file
             * under TCG is minutes more on top -- bundling them made a working
             * compile fail for want of wall-clock, and made one failure
             * indistinguishable from the other. (M1960) */
            int rc;
            vfs_remove("/disk2/elf.o");
            static const char *av_gcc[] = {
                "-std=gnu11", "-ffreestanding", "-nostdlib", "-fno-stack-protector",
                "-fno-pic", "-fno-pie", "-mno-red-zone", "-mgeneral-regs-only",
                "-fwrapv", "-fno-omit-frame-pointer", "-Wall", "-Wextra",
                "-I/src/kernel/include", "-O2", "-c", "/src/kernel/elf.c", "-o", "/elf.o"
            };
            /* Assemble a LARGE pre-generated .s first: it reproduces in
             * seconds what the full compile takes fifteen minutes to reach. */
            vfs_remove("/disk2/big.o");
            static const char *av_bigas[] = { "-o", "/big.o", "/big.s" };
            kprintf("[lxtool] assembling a large .s (496 KB)...\n");
            rc = app_run_linux_sync("/disk2/usr/bin/as", av_bigas, 3, 240000);
            kprintf("[lxtool] as(big.s) -> %d\n", rc);
            if (g_lxtrace_make) g_lx_systrace = 1;
            kprintf("[lxtool] COMPILING OS-DEV's OWN kernel/elf.c with the real gcc driver...\n");
            /* 300000 -> 600000 (M2045). This is the single heaviest thing the
             * project does: the real gcc driver running the real 42 MB cc1 over
             * one of OS-DEV's own kernel sources, entirely under TCG with no
             * KVM on this host. M2044 removed copy-on-write's in-place
             * "sole owner" upgrade because it was a race no ordering could fix,
             * so every COW fault now copies a page -- and a compile forks
             * constantly. Correctness is not negotiable and the budget was
             * tuned before it, so the budget moves. */
            rc = app_run_linux_sync("/disk2/usr/bin/gcc", av_gcc, 18, 1200000);
            g_lx_systrace = 0;
            kprintf("[lxtool] gcc(kernel/elf.c) -> %d\n", rc);
            /* Prove the object is REAL by reading its symbol table with nm --
             * an empty or truncated file still "exists". */
            static const char *av_nm[] = { "/elf.o" };
            rc = app_run_linux_sync("/disk2/usr/bin/nm", av_nm, 1, 60000);
            kprintf("[lxtool] nm(elf.o) -> %d\n", rc);
        }
        if (g_lxbuild_test) {
            /* PHASE 5's DEMO: OS-DEV builds its OWN KERNEL, inside itself.
             * GNU make drives gcc over all 136 kernel sources, nasm over the
             * assembly, then ld and objcopy -- the same CFLAGS, the same
             * linker script, the same multiboot container the host build
             * produces. What it does NOT rebuild is OS-DEV's userspace: the
             * 128 application ELFs are reused as prebuilt blobs. (M1961) */
            int rc;
            kprintf("[lxbuild] building OS-DEV's OWN KERNEL inside OS-DEV...\n");
            /* Up to four passes. Individual cc1 invocations still crash
             * intermittently under this much process churn -- a different
             * source file each run -- and make stops at the first failure.
             * Object files persist, so each pass resumes where the last left
             * off. This is a WORKAROUND for a real bug, not a fix, and it is
             * recorded as such. */
            /* --jobserver-style=pipe: the default fifo jobserver needs mknodat, and
             * make only WARNS when it cannot create the fifo -- then silently runs
             * serially. Pipes work with what we have. */
            static const char *av_kb[] = { "-C", "/src", "-j4", "--jobserver-style=pipe" };
            rc = -1;
            for (int pass = 1; pass <= 4 && rc != 0; pass++) {
                rc = app_run_linux_sync("/disk2/usr/bin/make", av_kb, 4, 2400000);
                kprintf("[lxbuild] make pass %d -> %d\n", pass, rc);
            }
            kprintf("[lxbuild] make -> %d\n", rc);
            vfs_dirent *kents = kmalloc(64 * sizeof *kents);   /* heap: 256-byte names (M2062) */
            int kn = kents ? vfs_list_path("/disk2/src", kents, 64) : 0, ksz = -1;
            for (int i = 0; i < kn; i++) {
                const char *nm = kents[i].name;
                if (nm[0]=='k'&&nm[1]=='e'&&nm[2]=='r'&&nm[3]=='n'&&nm[4]=='e'&&nm[5]=='l'&&
                    nm[6]=='3'&&nm[7]=='2'&&nm[8]=='.'&&nm[9]=='e'&&nm[10]=='l'&&nm[11]=='f'&&!nm[12])
                    ksz = (int)kents[i].size;
            }
            if (kents) kfree(kents);
            if (ksz > 0) kprintf("[lxbuild] kernel32.elf built in-guest: %d bytes\n", ksz);
            else         kprintf("[lxbuild] kernel32.elf MISSING -- the build produced no kernel\n");
        }
        lx_env_ready: ;   /* -append lxdesktop lands here: setup done, no tests (M2004) */
    }

    if (!g_nodisk && fat32_mount() == 0) {
        kprintf("[ ok ] mounted FAT32 volume (ATA primary master).\n\n");
        if (g_fatjournal_test)             /* -append fatjournaltest: live FAT32 create crash-atomicity (M1866) */
            fat32_journal_selftest();
        vfs_dirent *ents = kmalloc(32 * sizeof *ents);   /* heap: 256-byte names (M2062) */
        int n = ents ? vfs_list(ents, 32) : 0;
        kprintf("  / contains %d file(s):\n", n);
        for (int i = 0; i < n; i++)
            kprintf("    %s  (%u bytes)\n", ents[i].name, ents[i].size);
        if (ents) kfree(ents);
        char fbuf[256];
        long r = vfs_read("README.TXT", fbuf, sizeof(fbuf) - 1);
        if (r > 0) {
            fbuf[r] = '\0';
            kprintf("  --- README.TXT ---\n%s  -------------------\n\n", fbuf);
        }
    } else {
        kprintf("[warn] no FAT32 disk found (run with a disk image).\n\n");
    }

    /* Enumerate ALL legacy ATA drives (primary/secondary bus x master/slave) and
     * parse each one's MBR/GPT partition table, logging every partition as a
     * (drive, type, start-LBA, sectors) volume. This is purely additive: the boot
     * mount above still reads the bare FAT32 off drive 0 at LBA 0. With no extra
     * disks attached, only drive 0 is present and (being a bare FS) reports no
     * partition table — a clean no-op. */
    partition_enumerate();
    kprintf("\n");

    /* Prove the ADDITIVE bus-master IDE DMA path (kernel/ata.c) against the boot
     * disk: the boot disk sits on the PIIX3 IDE controller (bus-master capable),
     * so this DMA-reads a few of its sectors and compares them byte-for-byte
     * against a PIO read of the same sectors, logging "DMA==PIO OK" per sector.
     * This is purely additive: fat32/vfs/boot still use the PIO ata_read/write
     * above; the DMA path is a separate, proven-identical capability. A clean
     * no-op (logs "DMA unavailable") if no PIIX3 BMIDE controller is present. */
    if (g_nodisk) {
        kprintf("[boot] nodisk: skipping ALL disk-write self-tests (ata/ahci/nvme/virtio-blk/blockdev/raid) — real disks left untouched\n");
    } else {
    ata_dma_selftest();
    ata_lba48_selftest();   /* M1721: high-LBA round-trip if a >128 GiB ATA disk is attached (else no-op) */
    ata_cache_selftest();   /* M1855: single-sector read cache fill+hit+write-invalidate coherence */
    /* AND WHAT ONE COMMAND COSTS (M2091). The boot budget's elapsed sums are
     * upper bounds -- a PIO transfer spin-yields, so the TSC across one spans
     * whatever else the core ran -- which makes them useless for PREDICTING a
     * win. This measures the number a prediction needs, in isolation, and it
     * is the difference between "not shredding requests should help" and a
     * figure that can be checked afterwards. */
    if (g_diskbench) { extern void bcache_selftest(void); bcache_selftest(); ata_diskbench(); }
    }

    /* Bring up AHCI/SATA as an ADDITIONAL storage driver (the boot disk above
     * stays on legacy ATA). No-op if no AHCI HBA + disk is attached. The
     * self-test reads real sectors off the AHCI disk and logs their bytes. */
    ahci_init();
    ahci_selftest();

    /* Bring up ATAPI CD-ROM (SCSI PACKET over ATA) as an ADDITIONAL read-only
     * storage driver — boot stays on legacy ATA. No-op unless a CD image is
     * attached; the self-test reads + verifies an ISO 9660 PVD off the CD (M1852). */
    atapi_selftest();

    /* Bring up virtio-blk (the paravirtual "fast VM disk") as ANOTHER additional
     * storage driver — boot still uses legacy ATA above. No-op if no virtio block
     * device is attached. The self-test reads real sectors off it (and does a
     * write round-trip) and logs their bytes. */
    virtio_blk_init();
    if (!g_nodisk) virtio_blk_selftest();       /* writes a scratch sector — skip under nodisk */

    /* Bring up virtio-rng (the paravirtual hardware entropy source) — the
     * simplest virtio device: hand it a buffer over a virtqueue and it DMAs
     * random bytes in. No-op if no virtio-rng device is attached; the self-test
     * draws two batches and logs them to prove real entropy moved. */
    virtio_rng_init();
    virtio_rng_selftest();

    /* Bring up virtio-console (a paravirtual serial port to the host): the guest
     * writes bytes to the transmit virtqueue and they land in whatever chardev
     * the hypervisor wired up. No-op if no virtio-console device is attached;
     * the self-test emits one line so the host sink + serial log show it. */
    virtio_console_init();
    virtio_console_selftest();

    /* Bring up NVMe (modern PCIe storage) as YET ANOTHER additional storage
     * driver — boot still uses legacy ATA above. No-op if no NVMe controller is
     * attached. The self-test identifies namespace 1, reads real sectors off it
     * (and does a write round-trip) and logs their bytes/checksum. */
    nvme_init();
    if (!g_nodisk) nvme_selftest();             /* writes a scratch LBA — skip under nodisk (real NVMe likely holds the host OS) */

    /* Bring up the legacy floppy controller (82077AA) as ANOTHER additional
     * block device — boot still uses legacy ATA above. Unlike every other DMA
     * driver here (which bus-master over PCI), the floppy moves its data through
     * the legacy 8237 ISA DMA controller (channel 2 + a low-RAM bounce buffer
     * that must not cross a 64 KiB boundary). No-op if no FDC/diskette is
     * attached. The self-test resets+recalibrates the controller and ISA-DMA
     * reads real sectors off the diskette, logging their bytes/checksum. */
    floppy_init();
    floppy_selftest();

    /* Bring up virtio-gpu (the modern paravirtual 2D GPU) as an ADDITIONAL
     * display device — the boot display stays on the linear framebuffer
     * (fb.c/bochs_vbe.c) above. No-op if no virtio-gpu is attached. The self-test
     * runs the full present cycle (CREATE_2D + ATTACH_BACKING + SET_SCANOUT done
     * at init; then TRANSFER_TO_HOST_2D + RESOURCE_FLUSH of a test pattern) and
     * asserts every command returned OK — the headless proof, like hda_selftest. */
    virtio_gpu_init();
    virtio_gpu_selftest();

    /* THE RENDER-NODE PROBE RUNS HERE, NOT WITH THE OTHER lxabi PROBES (M2347).
     *
     * It was in the lxabi block four hundred lines above this, and it reported
     * `open(/dev/dri/renderD128) FAILED: No such file or directory`. Both ends
     * were behaving exactly as designed: `drm_open_node()` refuses to hand out
     * a node when there is no 3D device behind it, and at that point in the
     * boot there wasn't one, because `virtio_gpu_init()` is RIGHT HERE. The
     * probe asked a true question at a moment when the answer had to be no.
     *
     * Another instrument measuring the wrong moment -- the same shape as the
     * fps meter counting an unstarted benchmark. Worth the comment because the
     * failure was perfectly legible and still pointed at the wrong component:
     * every line of it was about the kernel, and the defect was in when it
     * was called. */
    if (g_lxgl) {
        /* THE WHOLE CHAIN, IN ONE PROGRAM (M2351): EGL -> Mesa virgl ->
         * /dev/dri/renderD128 -> virtio-gpu -> virglrenderer -> host GL.
         * Eight links. Firefox exercises the same eight and answers a failure
         * in any of them by silently falling back to SWGL, so asking through
         * Firefox cannot say which link broke. The assertion is GL_RENDERER
         * containing "virgl" and a clear that reads back green --
         * configured-but-dead contexts pass every other check. */
        /* WAYLAND MODE WHEN THE HARDWARE PATH IS ON (M2363). `ffgpu` advertises
         * wl_drm and is the configuration Firefox fails in, so run the probe
         * the same way -- otherwise it tests a path nobody is complaining
         * about. Surfaceless already passes; the Wayland platform is the one
         * structural difference between this probe and the browser. */
        { extern int g_wl_drm_enable;
          if (g_wl_drm_enable) app_set_next_env("LXGL_WAYLAND=1"); }
        kprintf("[lxabi] the GL chain: EGL -> Mesa virgl -> our render node -> the host GPU (%s)...\n",
                ({ extern int g_wl_drm_enable; g_wl_drm_enable; })
                    ? "WAYLAND platform, as Firefox does it" : "surfaceless");
        int grc = app_run_linux_sync("/disk2/lxgl", 0, 0, 60000);
        kprintf("[lxabi] lxgl exit -> %d\n", grc);
    }
    if (g_lxdrm) {
        /* THE RENDER NODE, ASKED DIRECTLY (M2347). The program that will
         * really ask these questions is Mesa, which answers a wrong answer
         * by silently falling back to software -- so a kernel bug here
         * presents as "WebGL is slow", three layers away from its cause.
         * A 30 KB probe that prints every answer is the difference between
         * a bug with an address and a bug with a symptom. */
        kprintf("[lxabi] the DRM render node: VERSION, GETPARAM, GET_CAPS...\n");
        int drc = app_run_linux_sync("/disk2/lxdrm", 0, 0, 30000);
        kprintf("[lxabi] lxdrm exit -> %d\n", drc);
    }


    /* Bring up VMware SVGA-II (PCI 0x15AD:0x0405) as YET ANOTHER additional
     * display device — the boot display stays on the linear framebuffer
     * (fb.c/bochs_vbe.c) above. No-op if no vmware-svga is attached. Driven
     * through an I/O-port index/value register file + a linear framebuffer
     * (BAR1) + a command FIFO (BAR2). The self-test confirms SVGA_ID_2, sets a
     * mode, writes a colour-band test pattern to the framebuffer, emits an
     * SVGA_CMD_UPDATE into the FIFO + syncs, and reads registers back to
     * confirm — the headless proof, like virtio_gpu_selftest. */
    svga_init();
    svga_selftest();

    /* Prefer the USB tablet (absolute pointer, tracks the host 1:1); fall back
     * to the relative PS/2 mouse if there's no tablet. */
    if (usb_tablet_init() == 0) {
        kprintf("[ ok ] USB tablet active (absolute pointer).\n");
    } else {
        mouse_init();
        kprintf("[ ok ] PS/2 mouse on IRQ12 (relative fallback).\n");
    }

    /* Bring up USB mass-storage (a USB flash disk) as an ADDITIONAL block device,
     * sharing the one UHCI controller with the tablet above — boot still uses
     * legacy ATA. No-op if no USB mass-storage device is attached (the tablet
     * path is unaffected). The self-test READ-CAPACITYs it and reads real sectors
     * off it via Bulk-Only Transport + SCSI, logging their bytes/checksum. */
    usb_storage_init();
    usb_storage_selftest();

    ext2_set_clock(rtc_unix);      /* real inode timestamps on ext2 writes (M1175) */
    /* AND THE CACHE-DROP HOOK (M2220), so ext2_open can drop the two
     * superblock sectors and read them again when the magic comes back wrong.
     * ext2.c is host-compiled and cannot reach bcache; blockdev knows which
     * owner key this transport uses. The ctx it gets is the one it passed
     * down, which for a mounted volume is the blockdev index. */
    ext2_set_cache_drop(ext2_cache_drop_hook);
    ext2_set_raw_read(ext2_raw_read_hook);   /* an independent, cache-and-DMA-free second opinion (M2240) */

    /* Bring up a USB HID boot keyboard, sharing the one UHCI controller with the
     * tablet + mass-storage above (skipping the tablet's port, using the shared
     * USB address allocator) — the PS/2 keyboard above stays the primary input.
     * No-op if no USB keyboard is attached (PS/2 + tablet + storage unaffected).
     * The self-test reports the enumerated HID boot keyboard + decodes any
     * keystroke injected around boot, and the desktop polls it alongside the
     * tablet so USB keystrokes reach the shell/apps like PS/2 ones. */
    usb_kbd_init();
    usb_kbd_selftest();

    /* Bring up an EHCI (USB 2.0) host controller as an ADDITIONAL USB host — the
     * UHCI controller above (with its tablet / mass-storage / keyboard) is
     * untouched. No-op if no EHCI controller is attached. ehci_init() resets the
     * HC, builds the async (QH+qTD) schedule, routes the root ports to EHCI,
     * resets the first populated high-speed port, and ENUMERATES the device behind
     * it over control transfers; the self-test logs the HC version + port count,
     * the port reset, and the enumerated device descriptor (idVendor/idProduct/
     * class) read over EHCI — the headless proof, like the storage self-tests. */
    ehci_init();
    ehci_selftest();

    /* Bring up an xHCI (USB 3.0) host controller as an ADDITIONAL USB host — the
     * UHCI + EHCI controllers above (with their tablet / mass-storage / keyboard)
     * are untouched. No-op if no xHCI controller is attached. xhci_init() resets
     * the HC, sets up the device-context base-address array + command ring + event
     * ring, runs the controller, resets the first populated root port, ENABLE SLOT
     * + ADDRESS DEVICE for the device behind it, and ENUMERATES it over EP0 control
     * transfers (TRB rings); the self-test logs the HC version + slot/port counts,
     * the ENABLE SLOT slot id, the port reset, and the enumerated device descriptor
     * (idVendor/idProduct/class) read over xHCI — the headless proof, like the
     * EHCI/storage self-tests. Completes the USB host-controller trilogy. */
    xhci_init();
    xhci_selftest();

    /* Generic block-device browsing across EVERY storage driver brought up above.
     * Each driver (ATA/AHCI/virtio-blk/NVMe/USB-storage over UHCI/EHCI/xHCI) only
     * SELF-TESTED its raw sectors; this registers every present device behind one
     * uniform read interface (kernel/blockdev.c) and then, for each, MOUNTS any
     * FAT32 volume it carries (bare at LBA 0, or inside an MBR/GPT partition)
     * READ-ONLY and LISTS its root directory — proving the disks are genuinely
     * browsable, not just readable. Purely additive + read-only: the boot FAT32
     * mount (ATA primary master, LBA 0) above and fat32.c/vfs.c are untouched. A
     * clean no-op listing if a device carries no FAT32.
     *
     * ORDERING (M1889): this now runs AFTER the EHCI + xHCI bring-up, because a
     * USB disk behind either is registered as a blockdev and blockdev_init() can
     * only see the drivers that are already up. The USB host controllers keep
     * their original relative order — every UHCI device (tablet, mass-storage,
     * keyboard) is enumerated BEFORE ehci_init() routes shared root ports over to
     * EHCI, which is what keeps the UHCI devices alive on real hardware. */
    blockdev_enumerate();
    if (!g_nodisk) {
        blockdev_selftest();       /* verify the write vtable + buffer-cache coherence (M1095) — writes a scratch sector */
        dm_selftest();             /* RAID-1 mirror self-test, iff 2 non-boot writable disks (M1157) — writes LBA 64 */
    }
    kprintf("\n");

    /* Exercise the POSIX IPC surface (message queues, named semaphores, shared
     * memory, ptys, advisory locks, inotify, eventfd) — ~2,700 lines that had no
     * automated assertions at all until M1906. Non-blocking operations only; see
     * ipcselftest.c for why. Leaves no objects behind. */
    if (g_selftest) {           /* -append selftest (M1916): ~0.9 s, so opt-in */
        sched_selftest();   /* M1912: fast yields must advance vruntime */
        rtc_selftest();     /* M1913: CMOS index/data pair is atomic under concurrency */
        pci_selftest();     /* M1914: PCI config address/data pair is indivisible */
        console_selftest(); /* M1915: concurrent kprintf lines are never spliced */
        vmm_tlb_selftest(); /* M2065: a shootdown that times out must KEEP the flush obligation */
        app_reap_selftest();/* M2072: two cores must not tear the same process down */
        app_pendq_selftest();/* M2076: a live app must not lose its window to a dead one */
        console_panic_selftest();/* M2080: the panic path must not wait for a lock it cannot win */
    }
    /* UNCONDITIONAL, like ipc_selftest below it (M2082): it is a few dozen
     * kmallocs, and the bug it guards is a silent kernel-heap double-use that
     * nothing else in the tree would notice. Asserted by
     * tests/run-ipc-tests.sh, which already boots headless and greps COM1. */
    app_memfd_selftest();
    /* UNCONDITIONAL: three page-table walks, and the invariant it guards is a
     * kernel panic under memory pressure (M2159). */
    { extern void vmm_hhdm_selftest(void); vmm_hhdm_selftest(); }
    { extern void app_fault_vaddr_selftest(void); app_fault_vaddr_selftest(); }
    if (g_e2pcrace_test) { extern void ext2_path_cache_race_test(void); ext2_path_cache_race_test(); }
    if (g_e2big_test) { extern void ext2_bigfile_race_test(void); ext2_bigfile_race_test(); }
    ipc_selftest();
    /* The terminal, asserted on CELLS rather than on a screenshot (M2057).
     * Opt-in for the same reason as the block above: boot-to-desktop under a
     * second is a number this project keeps deliberately low. */
    if (g_termtest) app_term_selftest();

    /* WHAT THE BOOT LOG COST TO DRAW (M2091). Printed here, at the end of the
     * scrolling wall of text and before the desktop replaces it, because this
     * is the moment whose length the user actually experiences: "took like
     * forever for the scrolling wall of text to go away".
     *
     * A per-pixel glyph write and a 4.9 MB full-screen memmove per line are
     * both MMIO under TCG, where a store is a device access rather than a
     * store. Whether that is the boot's cost or a rounding error is a
     * measurement, not a hunch -- and this is the measurement. */
    kmain_budget("the desktop is taking over");

    kprintf("[main] launching the desktop environment...\n");
    speaker_chime();              /* a little startup arpeggio */
    desktop_run();
}
