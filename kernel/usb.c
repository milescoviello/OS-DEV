/*
 * usb.c — a minimal UHCI driver: drives QEMU's usb-tablet AND provides the
 * generic transfer plumbing kernel/usb_storage.c reuses for a USB flash disk.
 *
 * Why: a PS/2 mouse is *relative*, so its cursor can't match the host pointer
 * in a window. The usb-tablet is *absolute* — it reports an (x,y) in 0..32767 —
 * so the cursor tracks 1:1. To read it we need a USB host controller. UHCI
 * (USB 1.1) is the simplest: it's driven through I/O ports plus DMA data
 * structures in RAM.
 *
 * The model: a 1024-entry **frame list** the controller walks 1000x/sec; each
 * entry points at a **queue head** (QH); a QH points at a chain of **transfer
 * descriptors** (TDs), each describing one packet (SETUP/IN/OUT) with a buffer.
 * We use one QH for control transfers (enumeration), one for the tablet's
 * interrupt-IN endpoint (the stream of HID reports), and one for BULK transfers
 * (the flash disk's Bulk-Only Transport). All these structures and buffers live
 * in identity-mapped low RAM so their physical == virtual address, which is what
 * the controller's DMA needs.
 *
 * Layering: the controller bring-up (usb_uhci_init), root-port reset
 * (usb_uhci_reset_ports), USB-address allocator (usb_alloc_address), and the
 * generic control/bulk/interrupt transfer primitives (usb_control_xfer /
 * usb_bulk_xfer / usb_interrupt_xfer) are exported via usb.h. The tablet path
 * here, kernel/usb_storage.c (a flash disk), and kernel/usb_kbd.c (a HID boot
 * keyboard) are all *clients* of that shared layer — so multiple devices share
 * one UHCI controller without any disturbing another. The transfer primitives
 * are serialized (each polls its TD chain to completion before returning), and
 * the tablet's interrupt endpoint lives on its own QH that the controller walks
 * every frame, so a bulk transfer on qh_bulk never perturbs it. usb_interrupt_xfer
 * runs one interrupt-IN transfer on a SEPARATE dedicated QH (qh_intx) — distinct
 * from the tablet's continuously-armed qh_int — so a polled keyboard read can't
 * disturb the live tablet endpoint.
 */
#include "usb.h"
#include "pci.h"
#include "pmm.h"
#include "vmm.h"   /* hhdm(): CPU access to DMA memory (M1970) */
#include "mouse.h"
#include "fb.h"
#include "console.h"
#include "string.h"
#include "timer.h"
#include "io.h"
#include <stdint.h>

/* UHCI I/O registers (offsets from the I/O base, BAR4). */
#define REG_CMD     0x00
#define REG_STS     0x02
#define REG_INTR    0x04
#define REG_FRNUM   0x06
#define REG_FRBASE  0x08
#define REG_SOF     0x0C
#define REG_PORTSC1 0x10
#define REG_PORTSC2 0x12

struct uhci_td {
    volatile uint32_t link;
    volatile uint32_t cs;       /* control + status */
    volatile uint32_t token;
    volatile uint32_t buffer;
    uint32_t reserved[4];       /* pad to 32 bytes */
} __attribute__((packed));

struct uhci_qh {
    volatile uint32_t head;     /* horizontal link (next QH) */
    volatile uint32_t element;  /* vertical link (first TD)   */
    uint32_t reserved[2];
} __attribute__((packed));

#define TD_ACTIVE   (1u << 23)
#define TD_ERRMASK  (0x7E0000u)     /* status error bits 17..22 */
#define PID_SETUP   0x2D
#define PID_IN      0x69
#define PID_OUT     0xE1

static uint16_t io;
static uint32_t *framelist;
static struct uhci_qh *qh_ctrl, *qh_int, *qh_bulk, *qh_intx;
static struct uhci_td *tds;        /* control transfer TD pool   */
static struct uhci_td *int_td;     /* tablet interrupt endpoint TD */
static struct uhci_td *btds;       /* bulk transfer TD pool      */
static struct uhci_td *itds;       /* generic interrupt-IN TD pool (usb_interrupt_xfer) */
static uint8_t  *setup_buf, *data_buf, *report_buf, *bulk_buf, *intx_buf;

static int dev_addr, ep_in, ep_maxp, int_toggle, ready;

/* Shared-layer state for the generic plumbing usb_storage.c reuses. */
static int uhci_up;                /* 1 once usb_uhci_init() has run        */
static int next_addr = 1;          /* next free USB device address          */
static int tablet_port = -1;       /* root-port index (0/1) the tablet owns */

/* Sizes of the control/bulk TD pools and the bulk bounce buffer. The control
 * pool holds a SETUP + the (small) enumeration data stages + status; the bulk
 * pool must cover one Bulk-Only-Transport phase: a 31-byte CBW, or a data phase
 * of up to USB_BULK_MAX bytes (chunked by usb_storage), or a 13-byte CSW. At
 * the UHCI max packet of 64 bytes, USB_BULK_MAX/64 + a couple of slack TDs is
 * the worst case. */
#define CTRL_TD_COUNT 16
#define BULK_TD_COUNT (USB_BULK_MAX / 64 + 4)
/* A generic interrupt-IN transfer (usb_interrupt_xfer) moves one HID report,
 * which fits in a single full-speed packet (<=64 bytes); a couple of TDs of
 * slack lets it span packets if a future client uses a larger report. */
#define INTX_TD_COUNT 4
#define INTX_BUF_SIZE 64

static uint16_t rd(uint16_t o)            { return inw(io + o); }
static void     wr(uint16_t o, uint16_t v){ outw(io + o, v); }

static uint32_t phys(void *p) { return (uint32_t)hhdm_phys(p); }   /* UHCI is 32-bit DMA; PMM frames are low (M1970) */

/* Build a TD. mlen is the data length (0 allowed). */
static void make_td(struct uhci_td *td, uint32_t next, uint8_t pid,
                    uint8_t addr, uint8_t ep, int toggle, int mlen, void *buf) {
    td->link = next;
    td->cs = TD_ACTIVE | (3u << 27);                       /* 3 error retries */
    uint32_t maxlen = (mlen == 0) ? 0x7FF : (uint32_t)(mlen - 1) & 0x7FF;
    td->token = pid | ((uint32_t)addr << 8) | ((uint32_t)ep << 15)
              | ((uint32_t)(toggle & 1) << 19) | (maxlen << 21);
    td->buffer = buf ? phys(buf) : 0;
}

/* Run a TD chain in `pool[0..ntd-1]` through queue head `qh`, wait for it to
 * finish, and report the number of bytes the *last* TD actually transferred (so
 * a caller can detect a short IN). `deadline_ticks` bounds the wait; a stalled
 * or absent endpoint returns -1 cleanly instead of spinning forever. */
static int run_qh_chain(struct uhci_qh *qh, struct uhci_td *pool, int ntd,
                        uint64_t deadline_ticks, int *last_actlen) {
    for (int i = 0; i < ntd - 1; i++)
        pool[i].link = phys(&pool[i + 1]) | 0x4; /* Q=0, T=0, Vf=1 (depth-first) */
    pool[ntd - 1].link = 1;                      /* terminate */

    qh->element = phys(&pool[0]);
    uint64_t deadline = timer_ticks() + deadline_ticks;
    while (timer_ticks() < deadline) {
        if (qh->element & 1) {                   /* QH drained -> all TDs done */
            for (int i = 0; i < ntd; i++)
                if (pool[i].cs & TD_ERRMASK) {
                    qh->element = 1;             /* unlink the failed chain */
                    return -1;
                }
            if (last_actlen) {
                /* actual length is (status & 0x7FF) + 1, with 0x7FF meaning 0 */
                uint32_t a = (pool[ntd - 1].cs & 0x7FF);
                *last_actlen = (a == 0x7FF) ? 0 : (int)a + 1;
            }
            return 0;
        }
    }
    qh->element = 1;                             /* timed out: unlink the chain */
    return -1;
}

/* Run the control QH's TD chain and wait for it to finish. 0 = ok. */
static int run_control(int ntd) {
    return run_qh_chain(qh_ctrl, tds, ntd, 30 /* ~300 ms */, 0);
}

/* A standard control transfer to device `addr`, endpoint 0 with max packet
 * `ep0_maxp`. setup[8] is the request; data/len is the data stage (may be 0).
 * `in` = data direction is device->host. This is the generic primitive; the
 * tablet path's control() below is a thin wrapper that fills in its own
 * address/max-packet, so both it and usb_storage.c share one code path. */
int usb_control_xfer(uint8_t addr, uint16_t ep0_maxp, const uint8_t setup[8],
                     void *data, int len, int in) {
    if (!uhci_up || len < 0 || ep0_maxp == 0)
        return -1;
    if (len > 256)                               /* data_buf is 304 bytes */
        return -1;
    memcpy(setup_buf, setup, 8);
    if (!in && len)
        memcpy(data_buf, data, len);

    int n = 0;
    make_td(&tds[n++], 0, PID_SETUP, addr, 0, 0, 8, setup_buf);

    int toggle = 1, off = 0;
    uint8_t dpid = in ? PID_IN : PID_OUT;
    while (off < len && n < CTRL_TD_COUNT - 1) {
        int chunk = len - off;
        if (chunk > (int)ep0_maxp) chunk = ep0_maxp;
        make_td(&tds[n++], 0, dpid, addr, 0, toggle, chunk, data_buf + off);
        toggle ^= 1;
        off += chunk;
    }

    make_td(&tds[n++], 0, in ? PID_OUT : PID_IN, addr, 0, 1, 0, 0);  /* status */

    int rc = run_control(n);
    if (rc == 0 && in && len)
        memcpy(data, data_buf, len);
    return rc;
}

/* The tablet path's control transfer: delegate to the generic primitive with
 * this device's current address + endpoint-0 max packet. */
static int control(const uint8_t setup[8], void *data, int len, int in) {
    return usb_control_xfer((uint8_t)dev_addr, (uint16_t)ep_maxp, setup, data, len, in);
}

/* A generic BULK transfer to device `addr`, endpoint `ep` (max packet `maxp`),
 * carrying `len` bytes to/from `buf` (`in` selects IN vs OUT). The caller's data
 * toggle is threaded through *toggle and updated. The actual byte count is
 * written to *actual (so a short IN is visible). Runs on the dedicated bulk QH,
 * isolated from control + interrupt traffic. Returns 0 on success, -1 on error /
 * stall / timeout. `len` must be <= USB_BULK_MAX. */
int usb_bulk_xfer(uint8_t addr, uint8_t ep, uint16_t maxp, int *toggle,
                  void *buf, int len, int in, int *actual) {
    if (actual) *actual = 0;
    if (!uhci_up || !qh_bulk || maxp == 0 || len < 0 || len > USB_BULK_MAX)
        return -1;
    if (!in && len)
        memcpy(bulk_buf, buf, len);

    int tg = toggle ? (*toggle & 1) : 0;
    uint8_t pid = in ? PID_IN : PID_OUT;
    int n = 0, off = 0;

    /* A zero-length bulk transfer is one packet; otherwise one TD per maxp. */
    if (len == 0) {
        make_td(&btds[n++], 0, pid, addr, ep, tg, 0, 0);
        tg ^= 1;
    } else {
        while (off < len && n < BULK_TD_COUNT) {
            int chunk = len - off;
            if (chunk > (int)maxp) chunk = maxp;
            make_td(&btds[n++], 0, pid, addr, ep, tg, chunk, bulk_buf + off);
            tg ^= 1;
            off += chunk;
        }
        if (off < len)                           /* didn't fit the pool */
            return -1;
    }

    int last = 0;
    /* Bulk reads of a sector are quick; give them a generous but finite bound. */
    int rc = run_qh_chain(qh_bulk, btds, n, 60 /* ~600 ms */, &last);
    if (toggle) *toggle = tg;
    if (rc != 0)
        return -1;

    /* Total bytes moved = full packets for all but the last TD, + the last TD's
     * actual length (which may be short, signalling the device sent less). */
    int total;
    if (len == 0) {
        total = 0;
    } else {
        total = (n - 1) * (int)maxp + last;
        if (total > len) total = len;            /* never claim more than asked */
    }
    if (rc == 0 && in && total > 0)
        memcpy(buf, bulk_buf, (size_t)total);
    if (actual) *actual = total;
    return 0;
}

/* A generic single INTERRUPT-IN transfer from device `addr`, endpoint `ep` (max
 * packet `maxp`): read up to `len` bytes into `buf`. The data toggle is threaded
 * through *toggle (read + updated). *actual receives the byte count actually
 * received (0 if the endpoint had nothing pending — NAK). Runs on its OWN
 * dedicated QH (qh_intx), so it never perturbs the tablet's continuously-armed
 * interrupt endpoint (qh_int) nor control/bulk traffic. `len` must be 1..INTX_BUF_SIZE.
 *
 * Non-blocking-ish: the deadline is short, so a poll that finds nothing pending
 * (the endpoint NAKs) times out cleanly and returns 0 with *actual == 0 — it does
 * NOT spin. A stalled/absent endpoint (error bits set) returns -1. The data
 * toggle is only advanced when a report was actually received, so a NAK doesn't
 * desync the toggle. */
int usb_interrupt_xfer(uint8_t addr, uint8_t ep, uint16_t maxp, int *toggle,
                       void *buf, int len, int *actual) {
    if (actual) *actual = 0;
    if (!uhci_up || !qh_intx || maxp == 0 || len <= 0 || len > INTX_BUF_SIZE)
        return -1;

    int tg = toggle ? (*toggle & 1) : 0;
    int n = 0, off = 0;
    while (off < len && n < INTX_TD_COUNT) {
        int chunk = len - off;
        if (chunk > (int)maxp) chunk = maxp;
        make_td(&itds[n], 0, PID_IN, addr, ep, (n == 0) ? tg : (tg ^ (n & 1)),
                chunk, intx_buf + off);
        off += chunk;
        n++;
    }
    if (off < len)                               /* didn't fit the pool */
        return -1;

    int last = 0;
    /* A short, finite bound (1 timer tick, ~10 ms at 100 Hz): an interrupt poll
     * either has a report queued (the TD completes almost immediately) or the
     * endpoint NAKs. The tick bound catches a pending report without spinning on
     * an idle keyboard; a timeout here just means "no new report", reported as 0. */
    int rc = run_qh_chain(qh_intx, itds, n, 1, &last);
    if (rc != 0) {
        /* Distinguish a clean "nothing pending" (TD still ACTIVE -> we unlinked it
         * on timeout, no error bits) from a real stall/error (error bits set). */
        for (int i = 0; i < n; i++)
            if (itds[i].cs & TD_ERRMASK)
                return -1;                       /* genuine stall/error */
        return 0;                                /* no report this poll (NAK) */
    }

    int total = (n - 1) * (int)maxp + last;
    if (total < 0) total = 0;
    if (total > len) total = len;                /* never claim more than asked */
    if (total > 0) {
        memcpy(buf, intx_buf, (size_t)total);
        if (toggle) *toggle = tg ^ 1;            /* advance toggle only on a real report */
    }
    if (actual) *actual = total;
    return 0;
}

static int get_descriptor(int type, int index, void *out, int len) {
    uint8_t s[8] = { 0x80, 0x06, (uint8_t)index, (uint8_t)type,
                     0, 0, (uint8_t)len, (uint8_t)(len >> 8) };
    return control(s, out, len, 1);
}

static int set_address(int addr) {
    uint8_t s[8] = { 0x00, 0x05, (uint8_t)addr, 0, 0, 0, 0, 0 };
    return control(s, 0, 0, 0);
}

static int set_configuration(int cfg) {
    uint8_t s[8] = { 0x00, 0x09, (uint8_t)cfg, 0, 0, 0, 0, 0 };
    return control(s, 0, 0, 0);
}

/* Reset and enable a root port; returns 1 if a device is attached + enabled. */
static int reset_port(uint16_t portsc) {
    if (!(rd(portsc) & 0x1))
        return 0;                          /* nothing connected */
    wr(portsc, rd(portsc) | (1 << 9));     /* assert reset */
    timer_wait(6);                         /* ~60 ms */
    wr(portsc, rd(portsc) & ~(1 << 9));    /* deassert */
    timer_wait(1);
    wr(portsc, rd(portsc) | (1 << 2));     /* enable port */
    timer_wait(1);
    return (rd(portsc) & 0x4) ? 1 : 0;     /* enabled? */
}

/* The two UHCI root ports, by index (0 -> PORTSC1, 1 -> PORTSC2). */
static const uint16_t portsc_reg[2] = { REG_PORTSC1, REG_PORTSC2 };

/* Bring the UHCI controller up once: probe PCI, reset the HC, allocate the DMA
 * frame list + QH/TD pools + buffers, chain the interrupt -> control -> bulk
 * QHs into every frame, and start the controller. Idempotent: a second call
 * (e.g. usb_storage_init() after usb_tablet_init()) is a no-op that just reports
 * success. Returns 0 if the controller is up, -1 if there's no UHCI controller. */
int usb_uhci_init(void) {
    if (uhci_up)
        return 0;

    pci_device_t dev = pci_find(0x8086, 0x7020);   /* PIIX3 UHCI */
    if (!dev.valid) { kprintf("[usb] no UHCI controller\n"); return -1; }
    pci_enable_bus_master(&dev);
    pci_write32(dev.bus, dev.slot, dev.func, 0xC0, 0x8F00);  /* disable legacy/SMI */
    io = (uint16_t)pci_bar(&dev, 4);

    /* reset the controller */
    wr(REG_CMD, 0x0004); timer_wait(2); wr(REG_CMD, 0);      /* global reset */
    wr(REG_CMD, 0x0002);                                     /* HC reset */
    for (int i = 0; i < 100000 && (rd(REG_CMD) & 0x0002); i++) {}
    wr(REG_INTR, 0);                                         /* no interrupts; we poll */

    /* allocate DMA structures (identity-mapped low RAM). The control pool +
     * interrupt TD share one frame; the bulk QH + its (larger) TD pool get
     * their own frame; control/setup/report buffers share one frame; the bulk
     * bounce buffer gets its own frame(s). */
    framelist = (uint32_t *)dma_alloc_page();
    uint8_t *pool  = (uint8_t *)dma_alloc_page();
    uint8_t *bpool = (uint8_t *)dma_alloc_page();
    uint8_t *bufs  = (uint8_t *)dma_alloc_page();
    if (!framelist || !pool || !bpool || !bufs) { kprintf("[usb] DMA alloc failed\n"); return -1; }
    qh_int  = (struct uhci_qh *)(pool + 0);
    qh_ctrl = (struct uhci_qh *)(pool + 16);
    qh_bulk = (struct uhci_qh *)(pool + 32);
    qh_intx = (struct uhci_qh *)(pool + 48);      /* dedicated polled interrupt-IN QH */
    tds     = (struct uhci_td *)(pool + 64);
    int_td  = (struct uhci_td *)(pool + 64 + CTRL_TD_COUNT * sizeof(struct uhci_td));
    itds    = (struct uhci_td *)(pool + 64 + (CTRL_TD_COUNT + 1) * sizeof(struct uhci_td));
    btds    = (struct uhci_td *)(bpool);          /* BULK_TD_COUNT TDs in its own frame */
    setup_buf  = bufs + 0;
    data_buf   = bufs + 16;                        /* 304 bytes of control data stage */
    report_buf = bufs + 320;                       /* tablet HID report               */
    intx_buf   = bufs + 384;                       /* generic interrupt-IN bounce buf (64B) */
    bulk_buf   = (uint8_t *)dma_alloc_page();   /* USB_BULK_MAX bounce buf */
    /* USB_BULK_MAX may exceed one frame; grab the rest contiguously (the PMM is a
     * simple bump allocator, so a fresh run is contiguous — verified, not assumed). */
    {
        uint64_t prev = (uint64_t)(uintptr_t)bulk_buf;
        if (!prev) { kprintf("[usb] bulk buffer alloc failed\n"); return -1; }
        for (int i = 1; i < (USB_BULK_MAX + PAGE_SIZE - 1) / PAGE_SIZE; i++) {
            uint64_t f = pmm_alloc_frame();
            if (!f || f != prev + PAGE_SIZE) { kprintf("[usb] bulk buffer not contiguous\n"); return -1; }
            prev = f;
        }
    }

    qh_intx->head = 1;                       /* terminate (last in the QH chain) */
    qh_intx->element = 1;                    /* idle until usb_interrupt_xfer arms it */
    qh_bulk->head = phys(qh_intx) | 2;       /* bulk -> polled interrupt-IN QH (Q bit) */
    qh_bulk->element = 1;
    qh_ctrl->head = phys(qh_bulk) | 2;       /* control -> bulk QH (Q bit) */
    qh_ctrl->element = 1;
    qh_int->head = phys(qh_ctrl) | 2;        /* interrupt -> control QH (Q bit) */
    qh_int->element = 1;
    for (int i = 0; i < 1024; i++)
        framelist[i] = phys(qh_int) | 2;     /* every frame -> interrupt QH */

    outl(io + REG_FRBASE, phys(framelist));   /* 32-bit register! */
    wr(REG_FRNUM, 0);
    outb(io + REG_SOF, 0x40);
    wr(REG_STS, 0xFFFF);                      /* clear status */
    wr(REG_CMD, 0x0081);                      /* Run + Max Packet 64 */

    uhci_up = 1;
    return 0;
}

/* Reset + enable a single root port (0 -> PORTSC1, 1 -> PORTSC2). Returns 1 if a
 * device is connected + enabled there, else 0 (or for an out-of-range index).
 *
 * USB requires enumerating ONE port at a time: every freshly-reset, unaddressed
 * device answers control transfers to address 0, so two enabled-but-unaddressed
 * devices on the shared bus would collide. Callers therefore enable a port, fully
 * enumerate the device behind it (assign it a unique address), and only then move
 * to the next port — which is exactly how the tablet + a flash disk coexist. */
int usb_uhci_enable_port(int port) {
    if (port < 0 || port > 1)
        return 0;
    int r = reset_port(portsc_reg[port]);
    timer_wait(2);
    return r;
}

/* The number of UHCI root ports we drive. */
int usb_uhci_port_count(void) { return 2; }

/* The root-port index the tablet claimed (-1 if none yet), so usb_storage can
 * skip it (leaving the live tablet endpoint undisturbed). */
int usb_uhci_tablet_port(void) { return tablet_port; }

/* --- claimed root ports (M1889) --------------------------------------------
 * usb_uhci_enable_port() RESETS the port, which knocks the device behind it
 * back to address 0 and invalidates the address its driver assigned it. So a
 * driver probing for its own device type must never re-enable a port another
 * driver has already enumerated. The tablet had a bespoke tablet_port for this,
 * but that only ever protected the tablet: usb_kbd_init() probing for a HID
 * keyboard would happily re-enable — and thereby break — an already-working
 * mass-storage device. (It did exactly that; the disk stayed registered in the
 * block layer but every later read failed.) This is the general version: each
 * driver claims the port it enumerated, and every probe skips claimed ports. */
static uint8_t port_claimed;        /* bit p set => root port p is spoken for */

void usb_uhci_claim_port(int port) {
    if (port >= 0 && port < usb_uhci_port_count())
        port_claimed |= (uint8_t)(1u << port);
}
int usb_uhci_port_claimed(int port) {
    if (port < 0 || port >= usb_uhci_port_count())
        return 1;                   /* out of range: treat as unavailable */
    if (port == tablet_port)
        return 1;                   /* the tablet claims its port implicitly */
    return (port_claimed >> port) & 1;
}

/* Allocate the next free USB device address (1, 2, ...). Shared by the tablet
 * and usb_storage so two devices on one controller never collide. */
uint8_t usb_alloc_address(void) {
    if (next_addr > 127) return 0;
    return (uint8_t)next_addr++;
}

int usb_uhci_is_up(void) { return uhci_up; }

int usb_tablet_init(void) {
    if (usb_uhci_init() != 0)
        return -1;

    /* Enable the FIRST root port with a device on it. We enable ports one at a
     * time (not all at once): an unaddressed device answers address-0 control
     * transfers, so leaving the other port disabled until we've addressed this
     * device away from 0 is what lets a flash disk on the other port coexist. */
    int port = -1;
    for (int p = 0; p < 2; p++) {
        if (usb_uhci_enable_port(p)) { port = p; break; }
    }
    if (port < 0) {
        kprintf("[usb] no device on either root port\n");
        return -1;
    }

    /* enumerate: addr 0, ep0 max packet defaults to 8 */
    dev_addr = 0; ep_maxp = 8;
    uint8_t devdesc[18];
    if (get_descriptor(1, 0, devdesc, 8) != 0) { kprintf("[usb] device descriptor failed\n"); return -1; }
    ep_maxp = devdesc[7] ? devdesc[7] : 8;

    int addr = usb_alloc_address();
    if (addr <= 0 || set_address(addr) != 0) { kprintf("[usb] SET_ADDRESS failed\n"); return -1; }
    dev_addr = addr;
    timer_wait(1);

    /* config descriptor: header first (to learn total length), then all of it */
    uint8_t cfg[256];
    if (get_descriptor(2, 0, cfg, 9) != 0) { kprintf("[usb] GET cfg hdr failed\n"); return -1; }
    int total = cfg[2] | (cfg[3] << 8);
    if (total > (int)sizeof(cfg)) total = sizeof(cfg);
    if (get_descriptor(2, 0, cfg, total) != 0) { kprintf("[usb] config descriptor failed\n"); return -1; }

    /* walk the config descriptor for an interrupt-IN endpoint */
    ep_in = 0;
    for (int i = 0; i + 1 < total; ) {
        int blen = cfg[i], btype = cfg[i + 1];
        if (blen == 0) break;
        if (btype == 0x05) {                         /* ENDPOINT descriptor */
            /* `eaddr`, not `addr`: in this file `addr` means the USB DEVICE
             * address, and shadowing it with an ENDPOINT address inside the
             * descriptor walk is a trap for later edits. Matches the name
             * usb_storage.c / ehci.c already use for the same field. */
            uint8_t eaddr = cfg[i + 2], attr = cfg[i + 3];
            if ((eaddr & 0x80) && (attr & 0x03) == 0x03) {   /* IN + interrupt */
                ep_in = eaddr & 0x0F;
                ep_maxp = cfg[i + 4] | (cfg[i + 5] << 8);
            }
        }
        i += blen;
    }
    if (!ep_in) { kprintf("[usb] no interrupt-IN endpoint\n"); return -1; }

    if (set_configuration(cfg[5]) != 0) { kprintf("[usb] SET_CONFIG failed\n"); return -1; }

    /* arm the interrupt endpoint */
    int_toggle = 0;
    make_td(int_td, 1, PID_IN, dev_addr, ep_in, int_toggle, ep_maxp, report_buf);
    qh_int->element = phys(int_td);

    mouse_set_abs(fb_width() / 2, fb_height() / 2, 0);
    tablet_port = port;          /* claimed: usb_storage will skip this port */
    ready = 1;
    kprintf("[usb] tablet ready: ep%d maxp=%d (absolute pointer)\n", ep_in, ep_maxp);
    return 0;
}

void usb_tablet_poll(void) {
    if (!ready)
        return;
    if (int_td->cs & TD_ACTIVE)
        return;                              /* no new report yet */

    int actlen = (int)((int_td->cs & 0x7FF) + 1) & 0x7FF;  /* 0x7FF -> 0 */
    if ((int_td->cs & TD_ERRMASK) == 0 && actlen >= 5) {
        /* QEMU tablet report: [buttons][x_lo][x_hi][y_lo][y_hi][wheel] */
        int buttons = report_buf[0] & 0x07;
        int rx = report_buf[1] | (report_buf[2] << 8);
        int ry = report_buf[3] | (report_buf[4] << 8);
        int x = rx * (fb_width() - 1) / 32767;
        int y = ry * (fb_height() - 1) / 32767;
        mouse_set_abs(x, y, buttons);
        if (actlen >= 6 && report_buf[5])         /* 6th byte: signed wheel delta (+up / -down) */
            mouse_add_wheel((int)(int8_t)report_buf[5]);
    }

    int_toggle ^= 1;                          /* re-arm with toggled data bit */
    make_td(int_td, 1, PID_IN, dev_addr, ep_in, int_toggle, ep_maxp, report_buf);
    qh_int->element = phys(int_td);
}
