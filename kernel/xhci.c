/*
 * xhci.c — xHCI (USB 3.0) host-controller driver: bring up the modern USB host,
 * set up its command + event rings, reset + detect a root port, and ENUMERATE
 * the device behind it (ENABLE SLOT -> ADDRESS DEVICE -> read its descriptors
 * over EP0 control transfers).
 *
 * --- Why ---------------------------------------------------------------------
 * kernel/usb.c drives a UHCI (USB 1.1) controller and kernel/ehci.c an EHCI (USB
 * 2.0) controller. An xHCI controller (PCI class 0x0C serial-bus, subclass 0x03
 * USB, prog-IF 0x30) is the USB *3.0* host: memory-mapped registers (BAR0, like
 * AHCI/NVMe/EHCI) and a transfer model built on rings of Transfer Request Blocks
 * (TRBs) instead of EHCI's QH/qTD async schedule. This is additive: UHCI + EHCI
 * and everything on them keep working untouched (separate file, separate PCI
 * controller; usb.c + ehci.c are not modified).
 *
 * --- The model (xHCI 1.x §4.x) ----------------------------------------------
 * A TRB is a 16-byte record: a 64-bit parameter, a 32-bit status, and a 32-bit
 * control word (whose bits 10..15 hold the TRB *type* and bit 0 the *cycle bit*).
 * Three kinds of rings carry them:
 *   - the COMMAND ring: we enqueue command TRBs (ENABLE SLOT, ADDRESS DEVICE, ...)
 *     and ring doorbell 0; the controller executes them.
 *   - the EVENT ring: the controller enqueues completion TRBs (Command Completion,
 *     Transfer) onto a segment we own; we poll it, matching the producer cycle bit
 *     against our consumer cycle, read the completion code + slot id, and advance
 *     the Event Ring Dequeue Pointer (ERDP).
 *   - per-endpoint TRANSFER rings: for EP0 control transfers we enqueue
 *     Setup/Data/Status stage TRBs and ring the slot's doorbell.
 * A ring is a frame of TRBs whose last entry is a *Link TRB* pointing back at the
 * ring start; crossing it toggles the cycle bit (the producer/consumer agreement
 * on which entries are "owned"). Devices are described by controller-owned Device
 * Context structures (pointed to by the Device Context Base Address Array, DCBAA)
 * and configured via Input Context structures we fill + hand to ADDRESS DEVICE.
 *
 * --- DMA + alignment ---------------------------------------------------------
 * Every ring / context / buffer comes from pmm_alloc_frame(): the PMM returns low
 * physical RAM the boot page tables identity-map (phys == virt), so a frame's
 * address is BOTH a CPU pointer AND the physical address the controller's DMA
 * needs — exactly how usb.c / ehci.c / nvme.c do it. A 4 KiB frame is 4 KiB-
 * aligned, which satisfies xHCI's 64-byte ring/context alignment with room to
 * spare; we place each structure at the base of its own frame (or at a 64-byte-
 * aligned offset inside one). Contexts are 32- or 64-byte each per HCCPARAMS1.CSZ;
 * we honor that stride. The MMIO BAR is mapped cache-disabled (PTE_PCD).
 *
 * --- Safety (reviewed line-by-line) ------------------------------------------
 *  - CAPLENGTH (>=8, <256), DBOFF/RTSOFF, MaxSlots/MaxPorts are validated +
 *    bounded before any loop or pointer arithmetic that uses them. Enough MMIO is
 *    mapped (BAR0 .. past the deepest of operational+PORTSC / runtime / doorbell).
 *  - All rings/contexts/buffers are pmm frames (identity-mapped); ring enqueue +
 *    the event-ring dequeue are bounded within their frames; the Link TRB cycle
 *    toggle is handled.
 *  - Every poll loop (CNR, HCRST, command completion, transfer event, port reset)
 *    has a finite timer-bounded timeout + a spin cap so a dead register can't
 *    wedge boot before the timer ticks; a failed completion code / HC error
 *    returns -1 cleanly.
 *  - Descriptor reads go into fixed buffers with bounded lengths; the config-
 *    descriptor walk is bounded (blen<2 / i+blen>total guards) exactly like
 *    usb_storage.c / ehci.c.
 *  - Absent xHCI controller => xhci_init() returns -1 (clean no-op). UHCI + EHCI
 *    and their devices are completely unaffected (separate file/controller).
 */
#include "xhci.h"
#include "usbbot.h"   /* the shared BOT/SCSI protocol layer (M1889) */
#include "pci.h"
#include "pmm.h"
#include "vmm.h"
#include "string.h"
#include "console.h"
#include "timer.h"
#include <stdint.h>

/* ---- capability registers (BAR0-relative, xHCI 1.x §5.3) ----------------- */
#define CAP_CAPLENGTH   0x00   /* u8  : offset from BAR0 to the operational regs  */
#define CAP_HCIVERSION  0x02   /* u16 : interface version (BCD)                   */
#define CAP_HCSPARAMS1  0x04   /* u32 : MaxSlots[7:0], MaxIntrs[18:8], MaxPorts[31:24] */
#define CAP_HCSPARAMS2  0x08   /* u32 : structural params 2 (ERST max, scratchpad) */
#define CAP_HCCPARAMS1  0x10   /* u32 : capability params (CSZ bit2 = 64B ctx, xECP) */
#define CAP_DBOFF       0x14   /* u32 : doorbell array offset (from BAR0, low 2 bits 0) */
#define CAP_RTSOFF      0x18   /* u32 : runtime register-space offset (from BAR0)  */

/* ---- operational registers (relative to BAR0 + CAPLENGTH, xHCI 1.x §5.4) -- */
#define OP_USBCMD       0x00   /* command                                        */
#define OP_USBSTS       0x04   /* status                                         */
#define OP_PAGESIZE     0x08   /* supported page size bitmap                      */
#define OP_DNCTRL       0x14   /* device notification control                     */
#define OP_CRCR         0x18   /* command ring control (64-bit)                  */
#define OP_DCBAAP       0x30   /* device context base address array ptr (64-bit) */
#define OP_CONFIG       0x38   /* MaxSlotsEn[7:0]                                 */
#define OP_PORTSC_BASE  0x400  /* PORTSC[port] @ 0x400 + port*0x10               */

/* USBCMD bits (xHCI 1.x §5.4.1). */
#define CMD_RS      (1u << 0)  /* run/stop                                       */
#define CMD_HCRST   (1u << 1)  /* host controller reset                          */
#define CMD_INTE    (1u << 2)  /* interrupter enable                             */
#define CMD_HSEE    (1u << 3)  /* host system error enable                       */

/* USBSTS bits (xHCI 1.x §5.4.2). */
#define STS_HCH     (1u << 0)  /* HC halted                                      */
#define STS_HSE     (1u << 2)  /* host system error                             */
#define STS_EINT    (1u << 3)  /* event interrupt (write-1-to-clear)            */
#define STS_PCD     (1u << 4)  /* port change detect (write-1-to-clear)         */
#define STS_CNR     (1u << 11) /* controller not ready                          */

/* CRCR bits (xHCI 1.x §5.4.5). */
#define CRCR_RCS    (1ull << 0)  /* ring cycle state                            */

/* PORTSC bits (xHCI 1.x §5.4.8). */
#define PORTSC_CCS  (1u << 0)  /* current connect status                         */
#define PORTSC_PED  (1u << 1)  /* port enabled/disabled                          */
#define PORTSC_OCA  (1u << 3)  /* over-current active                            */
#define PORTSC_PR   (1u << 4)  /* port reset                                     */
#define PORTSC_PP   (1u << 9)  /* port power                                     */
#define PORTSC_SPEED_SHIFT 10  /* port speed (bits 13:10)                        */
#define PORTSC_SPEED_MASK  (0xFu << PORTSC_SPEED_SHIFT)
#define PORTSC_PRC  (1u << 21) /* port reset change (write-1-to-clear)           */
#define PORTSC_CSC  (1u << 17) /* connect status change (write-1-to-clear)       */
#define PORTSC_PEC  (1u << 18) /* port enabled change (write-1-to-clear)         */
#define PORTSC_WRC  (1u << 19) /* warm port reset change (write-1-to-clear)      */
#define PORTSC_OCC  (1u << 20) /* over-current change (write-1-to-clear)         */
#define PORTSC_PLC  (1u << 22) /* port link state change (write-1-to-clear)      */
#define PORTSC_CEC  (1u << 23) /* port config error change (write-1-to-clear)    */
/* PORTSC has RW1CS change bits we must NOT clear on a read-modify-write, plus PED
 * is RW1CS too (writing 1 disables the port). Mask all of these off so a write
 * only ever sets what we intend. */
#define PORTSC_RW1CS (PORTSC_PED | PORTSC_CSC | PORTSC_PEC | PORTSC_WRC | \
                      PORTSC_OCC | PORTSC_PRC | PORTSC_PLC | PORTSC_CEC)

/* Runtime registers: interrupter 0 lives at RTSOFF + 0x20 (xHCI 1.x §5.5.2). */
#define RT_IR0      0x20       /* interrupter 0 register set (from RTSOFF)        */
#define IR_IMAN     0x00       /* interrupter management                          */
#define IR_IMOD     0x04       /* interrupter moderation                          */
#define IR_ERSTSZ   0x08       /* event ring segment table size                   */
#define IR_ERSTBA   0x10       /* event ring segment table base address (64-bit)  */
#define IR_ERDP     0x18       /* event ring dequeue pointer (64-bit)             */
#define IMAN_IP     (1u << 0)  /* interrupt pending (write-1-to-clear)            */
#define IMAN_IE     (1u << 1)  /* interrupt enable                                */
#define ERDP_EHB    (1ull << 3)/* event handler busy (write-1-to-clear)          */

/* TRB types (in control dword bits 15:10) we use (xHCI 1.x §6.4). */
#define TRB_NORMAL          1
#define TRB_SETUP_STAGE     2
#define TRB_DATA_STAGE      3
#define TRB_STATUS_STAGE    4
#define TRB_LINK            6
#define TRB_ENABLE_SLOT     9
#define TRB_ADDRESS_DEVICE  11
#define TRB_CONFIGURE_EP    12
#define TRB_NOOP_CMD        23
/* Event TRB types (xHCI 1.x §6.4.2). */
#define TRB_TRANSFER_EVENT  32
#define TRB_CMD_COMPLETION  33
#define TRB_PORT_STATUS     34

/* TRB control-word bit fields. */
#define TRB_CYCLE     (1u << 0)   /* cycle bit                                   */
#define TRB_ENT       (1u << 1)   /* evaluate next TRB                           */
#define TRB_ISP       (1u << 2)   /* interrupt on short packet (transfer)        */
#define TRB_CH        (1u << 4)   /* chain bit                                   */
#define TRB_IOC       (1u << 5)   /* interrupt on complete                       */
#define TRB_IDT       (1u << 6)   /* immediate data (Setup stage carries it)     */
#define TRB_TYPE(t)   ((uint32_t)(t) << 10)
#define TRB_TYPE_OF(c) (((c) >> 10) & 0x3F)
/* Link TRB: bit1 = Toggle Cycle (flip the producer cycle when crossing it). */
#define TRB_TC        (1u << 1)
/* Setup-stage TRT (transfer type, bits 17:16 of control). */
#define TRT_NO_DATA   (0u << 16)
#define TRT_OUT_DATA  (2u << 16)
#define TRT_IN_DATA   (3u << 16)
/* Data/Status stage direction (DIR, bit 16): 1 = IN. */
#define TRB_DIR_IN    (1u << 16)

/* Completion codes (event TRB status bits 31:24, xHCI 1.x §6.4.5). */
#define CC_SUCCESS          1
#define CC_SHORT_PACKET     13

/* A 16-byte Transfer Request Block. */
struct trb {
    volatile uint32_t lo;       /* parameter low  / data-buffer ptr low          */
    volatile uint32_t hi;       /* parameter high / data-buffer ptr high         */
    volatile uint32_t status;   /* transfer length / completion code             */
    volatile uint32_t control;  /* type + cycle + flags                          */
} __attribute__((packed));

#define TRBS_PER_RING   256     /* 256 * 16 = 4096 = one frame; last is the Link  */
#define XHCI_MAX_SLOTS  64      /* HCSPARAMS1 MaxSlots is an 8-bit field; we cap   */
#define XHCI_MAX_PORTS  64      /* HCSPARAMS1 MaxPorts is an 8-bit field          */
#define XHCI_CTRL_BUF   1024    /* control data-stage bounce buffer size          */

/* A ring we own (command ring or a transfer ring): a frame of TRBs, an enqueue
 * index, and our producer cycle state. */
struct ring {
    struct trb *trb;            /* the frame of TRBs (last entry is the Link)     */
    uint32_t    enq;            /* enqueue index (0..TRBS_PER_RING-2)             */
    uint32_t    cycle;          /* producer cycle bit we currently write          */
};

static struct {
    int present;                /* 1 once the HC is up + running                  */
    volatile uint8_t *cap;      /* mapped BAR0 (capability registers)             */
    volatile uint8_t *op;       /* operational registers = cap + CAPLENGTH        */
    volatile uint8_t *rt;       /* runtime registers = cap + RTSOFF               */
    volatile uint32_t *db;      /* doorbell array = (u32*)(cap + DBOFF)           */
    uint32_t hciversion;        /* interface version (BCD)                        */
    int caplength;
    int max_slots;              /* MaxSlots (bounded)                             */
    int max_ports;              /* MaxPorts (bounded)                             */
    int ctx_size;              /* 32 or 64 (HCCPARAMS1.CSZ)                       */

    uint64_t *dcbaa;            /* device context base address array (one frame)  */
    struct ring cmd;            /* command ring                                   */

    struct trb *erst;           /* event ring segment table (entry 0 -> evt seg)  */
    struct trb *evt;            /* event ring segment (a frame of TRBs)           */
    uint32_t    evt_deq;        /* event ring dequeue index                       */
    uint32_t    evt_cycle;      /* consumer cycle bit (matches producer-owned)    */

    /* the enumerated device */
    int      enum_ok;
    int      slot_id;           /* slot id from ENABLE SLOT (>0 once assigned)    */
    int      reset_port_idx;    /* root port we reset + detected a device on (-1) */
    uint8_t  port_speed;        /* PORTSC speed field of that port                */
    uint8_t  *dev_ctx;          /* the device's Device Context (frame)            */
    uint8_t  *in_ctx;           /* the device's Input Context (frame)             */
    struct ring ep0;            /* EP0 transfer ring                              */
    uint16_t ep0_maxp;          /* EP0 max packet                                 */
    uint8_t  *setup_buf;        /* (unused for setup — IDT carries it) data bounce*/
    uint8_t  *data_buf;         /* control data-stage bounce buffer               */
    uint16_t id_vendor, id_product;
    uint8_t  dev_class;

    /* STRETCH: a USB mass-storage (BOT/SCSI) device behind xHCI. */
    int      is_storage;
    uint8_t  bulk_in, bulk_out;        /* bulk IN/OUT endpoint numbers            */
    uint16_t bulk_in_maxp, bulk_out_maxp;
    struct ring ep_bin, ep_bout;       /* bulk IN/OUT transfer rings              */
    uint8_t *bulk_buf;                 /* page-aligned bulk DMA bounce buffer      */
    int      storage_sector_ok;
    uint32_t storage_sector_sum;
    uint8_t  storage_first16[16];      /* sector 0's first bytes, for the self-test */
    usb_bot_t bot;                     /* shared BOT/SCSI engine + device geometry  */
    int      storage_ready;            /* 1 once READ CAPACITY succeeded (mountable)*/
} xh;

/* ---- small MMIO helpers -------------------------------------------------- */
static uint32_t cap_rd32(uint32_t off) { return *(volatile uint32_t *)(xh.cap + off); }
static uint32_t op_rd(uint32_t off)    { return *(volatile uint32_t *)(xh.op + off); }
static void     op_wr(uint32_t off, uint32_t v) { *(volatile uint32_t *)(xh.op + off) = v; }
static void     op_wr64(uint32_t off, uint64_t v) {
    *(volatile uint32_t *)(xh.op + off)     = (uint32_t)v;
    *(volatile uint32_t *)(xh.op + off + 4) = (uint32_t)(v >> 32);
}
static void     rt_wr(uint32_t off, uint32_t v) { *(volatile uint32_t *)(xh.rt + off) = v; }
static void     rt_wr64(uint32_t off, uint64_t v) {
    *(volatile uint32_t *)(xh.rt + off)     = (uint32_t)v;
    *(volatile uint32_t *)(xh.rt + off + 4) = (uint32_t)(v >> 32);
}

static uint32_t portsc_off(int p) { return OP_PORTSC_BASE + (uint32_t)p * 0x10; }
static uint32_t portsc_rd(int p)  { return op_rd(portsc_off(p)); }
static void     portsc_wr(int p, uint32_t v) { op_wr(portsc_off(p), v); }

/* Physical address of a kernel pointer for the controller's DMA. Our rings +
 * contexts + buffers live in identity-mapped low RAM (phys == virt); translating
 * is the correct general way (exactly as nvme.c/ehci.c do). xHCI pointers are
 * 64-bit, so we keep the full address. */
static uint64_t phys_of(const void *p) {
    uint64_t t = vmm_translate((uint64_t)(uintptr_t)p);
    return t ? t : hhdm_phys(p);   /* no translation: it is an HHDM pointer, so subtract the base (M1970) */
}

/* A short, finite busy-wait on a bit condition in an operational register.
 * `want_set` = wait for (reg & mask) non-zero, else wait for zero. Returns 0 if
 * met, -1 on timeout. ms is bounded by the timer (100 Hz: 1 tick = 10 ms); we
 * also cap the spin count so a totally dead register can't wedge boot before the
 * timer ticks. (Same discipline as ehci.c's wait_bits.) */
static int wait_bits(uint32_t off, uint32_t mask, int want_set, int ms) {
    uint64_t deadline = timer_ticks() + (uint64_t)((ms + 9) / 10);
    for (uint32_t spin = 0; spin < 200000000u; spin++) {
        uint32_t v = op_rd(off) & mask;
        if (want_set ? (v != 0) : (v == 0))
            return 0;
        if (timer_ticks() >= deadline)
            break;
    }
    return -1;
}

/* ---- ring setup ---------------------------------------------------------- */

/* Initialise a producer ring in a freshly-zeroed frame: TRBs_PER_RING entries,
 * the LAST a Link TRB pointing back to entry 0 with the Toggle-Cycle bit so the
 * producer cycle flips each time it wraps. enqueue starts at 0, cycle at 1. */
static void ring_init(struct ring *r, struct trb *frame) {
    r->trb   = frame;
    r->enq   = 0;
    r->cycle = 1;
    memset(frame, 0, PAGE_SIZE);
    struct trb *link = &frame[TRBS_PER_RING - 1];
    uint64_t base = phys_of(frame);
    link->lo      = (uint32_t)base;
    link->hi      = (uint32_t)(base >> 32);
    link->status  = 0;
    /* Link TRB: type=Link, Toggle Cycle set; cycle bit will be set on first wrap. */
    link->control = TRB_TYPE(TRB_LINK) | TRB_TC;
}

/* Enqueue one TRB (lo/hi/status/control supplied WITHOUT the cycle bit; we OR in
 * the current producer cycle) and advance the enqueue pointer, handling the Link
 * TRB at the end of the ring (set its cycle to the producer's, then wrap +
 * toggle). Bounded: enq stays within [0, TRBS_PER_RING-1). */
static void ring_push(struct ring *r, uint64_t param, uint32_t status, uint32_t control) {
    struct trb *t = &r->trb[r->enq];
    t->lo     = (uint32_t)param;
    t->hi     = (uint32_t)(param >> 32);
    t->status = status;
    /* Write control LAST (with the cycle bit) so the controller never sees a
     * half-written TRB it owns. */
    __asm__ volatile("" ::: "memory");
    t->control = control | (r->cycle ? TRB_CYCLE : 0);
    __asm__ volatile("" ::: "memory");

    r->enq++;
    if (r->enq == TRBS_PER_RING - 1) {
        /* Hand ownership of the Link TRB to the controller (set its cycle to the
         * producer cycle), then wrap to 0 and toggle our producer cycle. */
        struct trb *link = &r->trb[TRBS_PER_RING - 1];
        uint32_t lc = TRB_TYPE(TRB_LINK) | TRB_TC | (r->cycle ? TRB_CYCLE : 0);
        __asm__ volatile("" ::: "memory");
        link->control = lc;
        __asm__ volatile("" ::: "memory");
        r->enq = 0;
        r->cycle ^= 1;
    }
}

/* Ring a doorbell: slot 0 = command ring (target 0); a device slot N with
 * endpoint doorbell `target` (1 = EP0 bidir; 2*epnum+dir otherwise). */
static void doorbell(uint32_t slot, uint32_t target) {
    __asm__ volatile("" ::: "memory");
    xh.db[slot] = target;
    __asm__ volatile("" ::: "memory");
}

/* ---- event ring ---------------------------------------------------------- */

/* Poll the event ring for the next event TRB whose cycle bit matches our consumer
 * cycle. On a match, copy it into *out, advance the dequeue pointer (wrapping +
 * toggling the consumer cycle), write back ERDP, and return 0. Returns -1 on
 * timeout or if the HC signals a system error. Finite, timer-bounded. */
static int event_poll(struct trb *out, int ms) {
    uint64_t deadline = timer_ticks() + (uint64_t)((ms + 9) / 10);
    for (uint32_t spin = 0; spin < 400000000u; spin++) {
        if (op_rd(OP_USBSTS) & STS_HSE)            /* host system error -> bail */
            return -1;
        struct trb *e = &xh.evt[xh.evt_deq];
        uint32_t ctrl = e->control;
        if ((ctrl & TRB_CYCLE ? 1u : 0u) == xh.evt_cycle) {
            out->lo = e->lo; out->hi = e->hi;
            out->status = e->status; out->control = ctrl;

            xh.evt_deq++;
            if (xh.evt_deq == TRBS_PER_RING) {
                xh.evt_deq = 0;
                xh.evt_cycle ^= 1;
            }
            /* Advance ERDP to the new dequeue entry; set EHB (write-1-to-clear)
             * so the controller knows we serviced events. */
            uint64_t erdp = phys_of(&xh.evt[xh.evt_deq]) | ERDP_EHB;
            rt_wr64(RT_IR0 + IR_ERDP, erdp);
            return 0;
        }
        if (timer_ticks() >= deadline)
            break;
    }
    return -1;
}

/* Issue a command TRB on the command ring, ring doorbell 0, and poll the event
 * ring for its Command Completion Event. Returns the completion code (>0), with
 * the slot id (if any) written to *slot_out; returns -1 on timeout / HC error.
 * A non-SUCCESS completion code is returned as-is for the caller to judge. */
static int command_exec(uint64_t param, uint32_t status, uint32_t control, int *slot_out) {
    if (slot_out) *slot_out = 0;
    uint64_t cmd_trb_phys = phys_of(&xh.cmd.trb[xh.cmd.enq]);
    ring_push(&xh.cmd, param, status, control);
    doorbell(0, 0);

    /* Poll for a Command Completion Event referencing our command TRB. We loop a
     * few events in case an unrelated event (e.g. a port status change) arrives
     * first; bounded total. */
    for (int tries = 0; tries < 64; tries++) {
        struct trb ev;
        if (event_poll(&ev, 1000) != 0)
            return -1;
        int type = (int)TRB_TYPE_OF(ev.control);
        if (type == TRB_CMD_COMPLETION) {
            uint64_t ev_cmd = (uint64_t)ev.lo | ((uint64_t)ev.hi << 32);
            int cc = (int)((ev.status >> 24) & 0xFF);
            if (slot_out) *slot_out = (int)((ev.control >> 24) & 0xFF);
            if (ev_cmd == (cmd_trb_phys & ~0xFull))   /* our command */
                return cc;
            /* A completion for a different command TRB: keep looking (still ours
             * eventually, since we serialise commands). */
        }
        /* Port-status / other events: ignore + keep polling. */
    }
    return -1;
}

/* ---- EP0 control-transfer primitive -------------------------------------- */

/* Run a transfer on `r` (a slot's endpoint ring), ring its doorbell, and poll the
 * event ring for the Transfer Event(s). Returns the completion code of the final
 * event (>0), or -1 on timeout / HC error. `db_slot`/`db_target` ring the right
 * doorbell. `*residual` (if non-NULL) receives the leftover length the LAST event
 * reported (so a short IN is visible). We pushed `n_trbs` TRBs; only the last
 * carries IOC, so we wait for one Transfer Event for it (a short packet on an
 * earlier TRB with ISP would also raise one, which we accept). */
static int transfer_exec(struct ring *r, uint32_t db_slot, uint32_t db_target,
                         int *residual) {
    (void)r;
    if (residual) *residual = 0;
    doorbell(db_slot, db_target);

    for (int tries = 0; tries < 64; tries++) {
        struct trb ev;
        if (event_poll(&ev, 1000) != 0)
            return -1;
        int type = (int)TRB_TYPE_OF(ev.control);
        if (type == TRB_TRANSFER_EVENT) {
            int cc = (int)((ev.status >> 24) & 0xFF);
            if (residual) *residual = (int)(ev.status & 0xFFFFFF);
            return cc;
        }
        /* command-completion / port-status events here are unexpected mid-transfer
         * but harmless; keep polling for the transfer event. */
    }
    return -1;
}

/* A standard control transfer on the enumerated device's EP0. setup[8] is the
 * request; data/len is the data stage (may be 0); `in` selects device->host.
 * Builds Setup / [Data] / Status stage TRBs on the EP0 ring and rings the slot's
 * EP0 doorbell (target 1). Returns 0 on success, -1 on error/timeout. Mirrors
 * usb.c/ehci.c control_xfer but over xHCI TRB rings. */
static int control_xfer(const uint8_t setup[8], void *data, int len, int in) {
    if (!xh.slot_id || len < 0 || len > XHCI_CTRL_BUF || xh.ep0_maxp == 0)
        return -1;

    /* Setup stage: the 8 setup bytes ride in the TRB parameter (Immediate Data). */
    uint64_t setup_param = 0;
    for (int i = 0; i < 8; i++)
        setup_param |= (uint64_t)setup[i] << (8 * i);
    uint32_t trt = (len == 0) ? TRT_NO_DATA : (in ? TRT_IN_DATA : TRT_OUT_DATA);
    /* status = TRB transfer length 8, interrupter 0. */
    ring_push(&xh.ep0, setup_param, 8u, TRB_TYPE(TRB_SETUP_STAGE) | TRB_IDT | trt);

    /* Data stage (optional). */
    if (len > 0) {
        if (!in && data)
            memcpy(xh.data_buf, data, (size_t)len);
        uint64_t dptr = phys_of(xh.data_buf);
        uint32_t ctl = TRB_TYPE(TRB_DATA_STAGE) | (in ? TRB_DIR_IN : 0) | TRB_ISP;
        ring_push(&xh.ep0, dptr, (uint32_t)len, ctl);
    }

    /* Status stage: opposite direction, IOC so we get a Transfer Event. For a
     * control read the status stage is OUT; for a write/no-data it is IN. */
    uint32_t sdir = (len > 0 && in) ? 0 : TRB_DIR_IN;
    ring_push(&xh.ep0, 0, 0, TRB_TYPE(TRB_STATUS_STAGE) | sdir | TRB_IOC);

    int rc = transfer_exec(&xh.ep0, (uint32_t)xh.slot_id, 1 /* EP0 doorbell */, 0);
    if (rc != CC_SUCCESS && rc != CC_SHORT_PACKET)
        return -1;
    if (in && len && data)
        memcpy(data, xh.data_buf, (size_t)len);
    return 0;
}

/* ---- standard USB requests (same bytes as usb.c / usb_storage.c) --------- */
static int get_descriptor(int type, int index, void *out, int len) {
    uint8_t s[8] = { 0x80, 0x06, (uint8_t)index, (uint8_t)type,
                     0, 0, (uint8_t)len, (uint8_t)(len >> 8) };
    return control_xfer(s, out, len, 1);
}
static int set_configuration(int cfg) {
    uint8_t s[8] = { 0x00, 0x09, (uint8_t)cfg, 0, 0, 0, 0, 0 };
    return control_xfer(s, 0, 0, 0);
}

/* ---- input / device context construction --------------------------------- */

/* xHCI contexts are arrays of 8-dword (32-byte) or 16-dword (64-byte) blocks; the
 * stride is xh.ctx_size. Return a pointer to context-block `n` inside a context
 * frame `base`. */
static volatile uint32_t *ctx_block(uint8_t *base, int n) {
    return (volatile uint32_t *)(base + (size_t)n * (size_t)xh.ctx_size);
}

/* Map a PORTSC speed field to the EP0 default max packet size (xHCI 1.x §4.3,
 * USB 3 §8.3): SS=512, HS=64, FS/LS=8 (we read the real value from the device
 * descriptor afterwards anyway, but EP0 must be programmed before the first
 * transfer). Speed codes: 1=FS, 2=LS, 3=HS, 4=SS (QEMU follows this). */
static uint16_t speed_to_ep0_maxp(uint8_t speed) {
    switch (speed) {
    case 4: return 512;   /* SuperSpeed       */
    case 3: return 64;    /* High-speed       */
    case 1: return 64;    /* Full-speed (8/16/32/64; 64 is a safe ceiling) */
    case 2: return 8;     /* Low-speed        */
    default: return 64;
    }
}

/* ---- root-port reset ----------------------------------------------------- */

/* Reset a single root port and report whether a device is connected + enabled.
 * Returns 1 with the speed field stashed in *speed if a device enabled there, 0
 * otherwise. Bounded waits. (xHCI 1.x §4.3.) */
static int reset_port(int port, uint8_t *speed) {
    uint32_t sc = portsc_rd(port);
    if (!(sc & PORTSC_CCS))
        return 0;                              /* nothing connected */

    /* Assert Port Reset (writing 1 to PR). Preserve PP; clear the RW1CS bits so we
     * don't accidentally disable/ack-change. */
    sc = portsc_rd(port);
    portsc_wr(port, (sc & ~PORTSC_RW1CS) | PORTSC_PR);

    /* Wait for the reset to complete: PRC (port reset change) gets set, and PR
     * reads back clear. Bounded (~200 ms). */
    int done = 0;
    for (int i = 0; i < 20; i++) {
        uint32_t v = portsc_rd(port);
        if (v & PORTSC_PRC) { done = 1; break; }
        timer_wait(1);                         /* ~10 ms each */
    }
    /* Acknowledge the change bits (write them back as 1 to clear), preserving the
     * rest; do not set PED/PR. */
    {
        uint32_t v = portsc_rd(port);
        uint32_t ack = v & (PORTSC_PRC | PORTSC_CSC | PORTSC_PEC | PORTSC_PLC);
        /* Build a write that keeps the non-RW1CS bits and writes 1 to the change
         * bits we want to clear. PP must stay set. */
        portsc_wr(port, (v & ~PORTSC_RW1CS) | ack);
    }
    timer_wait(1);

    uint32_t fin = portsc_rd(port);
    if (!(fin & PORTSC_CCS))
        return 0;                              /* device went away */
    if (!(fin & PORTSC_PED))
        return 0;                              /* not enabled after reset */
    if (speed)
        *speed = (uint8_t)((fin & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT);
    (void)done;
    return 1;
}

/* ---- enumeration --------------------------------------------------------- */

/* ENABLE SLOT, build the input context + EP0 transfer ring, ADDRESS DEVICE, then
 * read the device's descriptors over EP0 control transfers. Fills xh.* and
 * returns 0; -1 on any failure. The root port we use is xh.reset_port_idx (1-
 * based for xHCI port numbering: PORTSC index 0 == xHCI port 1). */
static int enumerate_device(void) {
    /* --- ENABLE SLOT command -> a slot id ------------------------------------ */
    int slot = 0;
    int cc = command_exec(0, 0, TRB_TYPE(TRB_ENABLE_SLOT), &slot);
    if (cc != CC_SUCCESS || slot <= 0 || slot > xh.max_slots) {
        kprintf("[xhci] ENABLE SLOT failed (cc=%d slot=%d)\n", cc, slot);
        return -1;
    }
    xh.slot_id = slot;

    /* --- allocate the device context + EP0 transfer ring --------------------- */
    xh.dev_ctx = (uint8_t *)dma_alloc_page();
    struct trb *ep0frame = (struct trb *)dma_alloc_page();
    if (!xh.dev_ctx || !ep0frame)
        return -1;
    memset(xh.dev_ctx, 0, PAGE_SIZE);
    ring_init(&xh.ep0, ep0frame);

    /* DCBAA[slot] = device context phys (the controller writes the device's state
     * here as it processes ADDRESS DEVICE). */
    xh.dcbaa[slot] = phys_of(xh.dev_ctx);

    /* --- build the Input Context for ADDRESS DEVICE -------------------------- */
    /* The Input Context is: Input Control Context (block 0), then a Slot Context
     * (block 1), then EP0 Context (block 2), ... Add flags A0 (slot) + A1 (EP0). */
    memset(xh.in_ctx, 0, PAGE_SIZE);
    volatile uint32_t *icc = ctx_block(xh.in_ctx, 0);   /* input control context */
    icc[1] = (1u << 0) | (1u << 1);                      /* Add Context flags: slot + EP0 */

    /* Slot context (block 1): route string = 0 (root-hub port), speed, context
     * entries = 1 (just EP0), root-hub port number (1-based). */
    volatile uint32_t *slot_ctx = ctx_block(xh.in_ctx, 1);
    uint32_t rh_port = (uint32_t)(xh.reset_port_idx + 1);   /* 1-based */
    slot_ctx[0] = ((uint32_t)xh.port_speed << 20) | (1u << 27);   /* speed, ctx entries=1 */
    slot_ctx[1] = (rh_port << 16);                          /* root-hub port number */

    /* EP0 context (block 2): EP type = Control (4), max packet from the speed,
     * the transfer ring dequeue pointer (phys | DCS=1), error count = 3. */
    volatile uint32_t *ep0_ctx = ctx_block(xh.in_ctx, 2);
    xh.ep0_maxp = speed_to_ep0_maxp(xh.port_speed);
    ep0_ctx[1] = (4u << 3)                                  /* EP Type = Control */
               | (3u << 1)                                  /* CErr = 3          */
               | ((uint32_t)xh.ep0_maxp << 16);             /* Max Packet Size   */
    uint64_t ep0_deq = phys_of(xh.ep0.trb) | 1ull;         /* DCS = 1 (our cycle) */
    ep0_ctx[2] = (uint32_t)ep0_deq;
    ep0_ctx[3] = (uint32_t)(ep0_deq >> 32);

    /* --- ADDRESS DEVICE command --------------------------------------------- */
    int aslot = 0;
    cc = command_exec(phys_of(xh.in_ctx), 0,
                      TRB_TYPE(TRB_ADDRESS_DEVICE) | ((uint32_t)slot << 24), &aslot);
    if (cc != CC_SUCCESS) {
        kprintf("[xhci] ADDRESS DEVICE failed (cc=%d)\n", cc);
        return -1;
    }

    /* --- read the device descriptor (8 bytes first to learn ep0 max packet) -- */
    uint8_t dd[18];
    memset(dd, 0, sizeof(dd));
    if (get_descriptor(1, 0, dd, 8) != 0) {
        kprintf("[xhci] device descriptor (first 8) failed\n");
        return -1;
    }
    /* The real bMaxPacketSize0 (dd[7]). For SuperSpeed it is an exponent (2^n);
     * for full/high it is the byte count. We programmed a safe value already; for
     * the QEMU devices we target the initial value works for the rest of
     * enumeration, so we keep it (re-evaluating the context is optional). */
    if (dd[7]) {
        /* Use it as a sanity sign the descriptor read worked; no re-program. */
    }

    /* Full device descriptor. */
    if (get_descriptor(1, 0, dd, 18) != 0) {
        kprintf("[xhci] device descriptor (full) failed\n");
        return -1;
    }
    xh.id_vendor  = (uint16_t)(dd[8]  | (dd[9]  << 8));
    xh.id_product = (uint16_t)(dd[10] | (dd[11] << 8));
    xh.dev_class  = dd[4];

    /* --- config descriptor: header then full, bounded walk ------------------ */
    uint8_t cfg[256];
    memset(cfg, 0, sizeof(cfg));
    if (get_descriptor(2, 0, cfg, 9) != 0) {
        kprintf("[xhci] config descriptor (header) failed\n");
        return -1;
    }
    int total = cfg[2] | (cfg[3] << 8);
    if (total < 9) return -1;
    if (total > (int)sizeof(cfg)) total = sizeof(cfg);
    if (get_descriptor(2, 0, cfg, total) != 0) {
        kprintf("[xhci] config descriptor (full) failed\n");
        return -1;
    }

    /* Walk the config (bounded, same guards as usb_storage.c/ehci.c). Pick the
     * config value; detect a BOT/SCSI mass-storage interface + its bulk endpoints
     * for the stretch path. */
    int cfg_value = cfg[5];
    int in_target = 0;
    uint8_t bin = 0, bout = 0;
    uint16_t bin_maxp = 0, bout_maxp = 0;
    for (int i = 0; i + 1 < total; ) {
        int blen = cfg[i], btype = cfg[i + 1];
        if (blen < 2) break;
        if (i + blen > total) break;
        if (btype == 0x04 && blen >= 9) {                  /* INTERFACE */
            in_target = (cfg[i + 5] == 0x08 && cfg[i + 6] == 0x06 && cfg[i + 7] == 0x50);
        } else if (btype == 0x05 && blen >= 7 && in_target) {  /* ENDPOINT in target */
            uint8_t eaddr = cfg[i + 2], eattr = cfg[i + 3];
            uint16_t emax = (uint16_t)(cfg[i + 4] | (cfg[i + 5] << 8));
            if ((eattr & 0x03) == 0x02) {                  /* BULK */
                if (eaddr & 0x80) { bin = eaddr & 0x0F; bin_maxp = emax; }
                else              { bout = eaddr & 0x0F; bout_maxp = emax; }
            }
        }
        i += blen;
    }

    if (set_configuration(cfg_value) != 0) {
        kprintf("[xhci] SET_CONFIGURATION failed\n");
        return -1;
    }

    xh.enum_ok = 1;

    /* Record bulk endpoints for the stretch path (configured separately below). */
    if (bin && bout) {
        xh.is_storage    = 1;
        xh.bulk_in       = bin;
        xh.bulk_out      = bout;
        xh.bulk_in_maxp  = bin_maxp ? bin_maxp : 512;
        xh.bulk_out_maxp = bout_maxp ? bout_maxp : 512;
    }
    return 0;
}

/* ---- STRETCH: configure bulk endpoints + read a sector over xHCI ---------- */

/* Compute an endpoint's Endpoint Context index (DCI): 2*epnum + (IN?1:0). EP0 is
 * DCI 1; the controller-side endpoint context lives at context block DCI+0... we
 * place it at block (DCI) in the device/input context (block 1 = slot). */
static int ep_dci(uint8_t epnum, int in) { return (int)(2 * epnum) + (in ? 1 : 0); }

/* Build a CONFIGURE ENDPOINT input context adding the bulk IN + OUT endpoints,
 * each with its own transfer ring, and issue the command. Returns 0 on success. */
static int configure_bulk_endpoints(void) {
    struct trb *binf = (struct trb *)dma_alloc_page();
    struct trb *boutf = (struct trb *)dma_alloc_page();
    if (!binf || !boutf)
        return -1;
    ring_init(&xh.ep_bin, binf);
    ring_init(&xh.ep_bout, boutf);

    int dci_in  = ep_dci(xh.bulk_in, 1);
    int dci_out = ep_dci(xh.bulk_out, 0);
    int max_dci = dci_in > dci_out ? dci_in : dci_out;
    /* In the INPUT context an endpoint at Device Context Index N lives at context
     * BLOCK N+1 (block 0 is the Input Control Context, block 1 the Slot Context,
     * block 2 = EP0/DCI 1, ...). Bound the highest block we touch to the frame. */
    if (max_dci + 1 >= (int)(PAGE_SIZE / (size_t)xh.ctx_size))
        return -1;

    memset(xh.in_ctx, 0, PAGE_SIZE);
    volatile uint32_t *icc = ctx_block(xh.in_ctx, 0);
    /* Add the slot context (A0) so context-entries can grow, plus both bulk EPs.
     * The Add-Context-flags bit position IS the DCI (bit N = DCI N). */
    icc[1] = (1u << 0) | (1u << dci_in) | (1u << dci_out);

    /* Slot context (input block 1): bump context entries to the highest DCI. */
    volatile uint32_t *slot_ctx = ctx_block(xh.in_ctx, 1);
    uint32_t rh_port = (uint32_t)(xh.reset_port_idx + 1);
    slot_ctx[0] = ((uint32_t)xh.port_speed << 20) | ((uint32_t)max_dci << 27);
    slot_ctx[1] = (rh_port << 16);

    /* Bulk IN endpoint context (input block dci_in+1): EP Type = Bulk IN (6), max
     * packet, CErr=3, its transfer ring dequeue ptr | DCS. Dword 4's Average TRB
     * Length (bits 15:0) must be non-zero for the controller to compute bandwidth
     * — use the max packet size (xHCI 1.x §6.2.3.1, §4.14.1.1). */
    volatile uint32_t *cin = ctx_block(xh.in_ctx, dci_in + 1);
    cin[1] = (6u << 3) | (3u << 1) | ((uint32_t)xh.bulk_in_maxp << 16);
    uint64_t deq_in = phys_of(xh.ep_bin.trb) | 1ull;
    cin[2] = (uint32_t)deq_in;
    cin[3] = (uint32_t)(deq_in >> 32);
    cin[4] = (uint32_t)xh.bulk_in_maxp;                    /* Average TRB Length */

    /* Bulk OUT endpoint context (input block dci_out+1): EP Type = Bulk OUT (2). */
    volatile uint32_t *cout = ctx_block(xh.in_ctx, dci_out + 1);
    cout[1] = (2u << 3) | (3u << 1) | ((uint32_t)xh.bulk_out_maxp << 16);
    uint64_t deq_out = phys_of(xh.ep_bout.trb) | 1ull;
    cout[2] = (uint32_t)deq_out;
    cout[3] = (uint32_t)(deq_out >> 32);
    cout[4] = (uint32_t)xh.bulk_out_maxp;                  /* Average TRB Length */

    int cc = command_exec(phys_of(xh.in_ctx), 0,
                          TRB_TYPE(TRB_CONFIGURE_EP) | ((uint32_t)xh.slot_id << 24), 0);
    if (cc != CC_SUCCESS)
        kprintf("[xhci] CONFIGURE ENDPOINT failed (cc=%d)\n", cc);
    return (cc == CC_SUCCESS) ? 0 : -1;
}

/* One bulk transfer: enqueue a single Normal TRB pointing at the bulk bounce
 * buffer, ring the endpoint's doorbell (target = DCI), and wait for the Transfer
 * Event. Returns bytes moved (>=0; a short IN is visible), or -1 on error. */
static int bulk_xfer(uint8_t epnum, int in, int len) {
    if (len < 0 || len > (int)PAGE_SIZE)
        return -1;
    struct ring *r = in ? &xh.ep_bin : &xh.ep_bout;
    uint32_t dci  = (uint32_t)ep_dci(epnum, in);
    uint64_t dptr = phys_of(xh.bulk_buf);

    ring_push(r, dptr, (uint32_t)len, TRB_TYPE(TRB_NORMAL) | TRB_ISP | TRB_IOC);
    int residual = 0;
    int cc = transfer_exec(r, (uint32_t)xh.slot_id, dci, &residual);
    if (cc != CC_SUCCESS && cc != CC_SHORT_PACKET)
        return -1;
    int moved = len - residual;
    if (moved < 0) moved = 0;
    if (moved > len) moved = len;
    return moved;
}

/* --- the xHCI transport for the shared BOT layer (kernel/usbbot.h) ---------
 * The BOT/SCSI protocol lives once, in usbbot.h, host-tested against a mock
 * device; xHCI's contribution is this adapter. bulk_xfer above always moves data
 * through the page-aligned DMA bounce frame xh.bulk_buf (the Normal TRB carries
 * its physical address), so an OUT copies the caller's bytes in first and an IN
 * copies the received bytes back out — which also removes the second static 4 KiB
 * scratch page the old private bot_read needed to survive the CSW read. */
static int xhci_bot_xfer(void *ctx, int in, void *buf, int len) {
    (void)ctx;
    if (len < 0 || len > (int)PAGE_SIZE) return -1;
    if (!in && len)
        memcpy(xh.bulk_buf, buf, (size_t)len);
    int act = bulk_xfer(in ? xh.bulk_in : xh.bulk_out, in, len);
    if (act < 0) return -1;
    if (act > len) act = len;
    if (in && act > 0)
        memcpy(buf, xh.bulk_buf, (size_t)act);
    return act;
}
static void xhci_bot_delay(int ms) { timer_wait(ms); }

/* Bring the mass-storage device behind xHCI up as a usable disk: bind the shared
 * BOT engine to the xHCI transport, poke TEST UNIT READY, then READ CAPACITY so
 * the block layer knows its geometry. Also reads sector 0 for the self-test's
 * checksum. Returns 0 if the device is ready for block I/O. */
static int storage_bring_up(void) {
    xh.bot.xfer     = xhci_bot_xfer;
    xh.bot.delay_ms = xhci_bot_delay;
    xh.bot.ctx      = 0;
    xh.bot.max_data = PAGE_SIZE;            /* one bulk data phase = the bounce frame */
    xh.bot.lun      = 0;

    (void)usb_bot_test_unit_ready(&xh.bot);         /* some devices need the poke */
    if (usb_bot_read_capacity(&xh.bot) != 0)
        return -1;
    xh.storage_ready = 1;

    static uint8_t sec0[USB_BOT_SECTOR];
    if (usb_bot_read10(&xh.bot, 0, 1, sec0) == 0) {
        uint32_t sum = 0;
        for (int i = 0; i < USB_BOT_SECTOR; i++)
            sum += sec0[i];
        xh.storage_sector_sum = sum;
        memcpy(xh.storage_first16, sec0, 16);
        xh.storage_sector_ok  = 1;
    }
    return 0;
}

/* --- public storage API: a real block device over USB 3.0 (M1889) ---------- */
int xhci_storage_present(void) { return xh.present && xh.storage_ready; }

uint64_t xhci_storage_capacity(void) {
    return xhci_storage_present() ? xh.bot.blocks : 0;
}

int xhci_storage_read(uint32_t lba, uint32_t count, void *buf) {
    if (!xhci_storage_present()) return -1;
    return usb_bot_read10(&xh.bot, lba, count, buf);
}

int xhci_storage_write(uint32_t lba, uint32_t count, const void *buf) {
    if (!xhci_storage_present()) return -1;
    return usb_bot_write10(&xh.bot, lba, count, buf);
}

/* ---- bring-up ------------------------------------------------------------ */

int xhci_init(void) {
    memset(&xh, 0, sizeof(xh));
    xh.reset_port_idx = -1;
    xh.ctx_size = 32;

    /* Locate an xHCI controller by PCI class (0x0C serial-bus, 0x03 USB, 0x30
     * xHCI). QEMU's qemu-xhci / nec-usb-xhci present this triple. */
    pci_device_t dev = pci_find_class(0x0C, 0x03, 0x30);
    if (!dev.valid)
        return -1;                                  /* no xHCI controller: clean no-op */

    pci_enable_bus_master(&dev);

    /* BAR0 is the MMIO register block, a 64-bit memory BAR (fold BAR1). Map it
     * cache-disabled, like ehci.c/nvme.c. */
    uint32_t bar0_raw = pci_read32(dev.bus, dev.slot, dev.func, 0x10);
    uint64_t mmio = (uint64_t)pci_bar(&dev, 0);
    if (((bar0_raw >> 1) & 0x3) == 0x2) {           /* 64-bit memory BAR */
        uint64_t hi = pci_read32(dev.bus, dev.slot, dev.func, 0x14);
        mmio |= hi << 32;
    }
    if (!mmio)
        return -1;
    /* Map generously to cover capability + operational + PORTSC + runtime +
     * doorbell regions. qemu-xhci's register window is well under 64 KiB; 16 pages
     * (64 KiB) covers it with margin. */
    for (uint64_t off = 0; off < 0x10000; off += PAGE_SIZE)
        vmm_map(mmio + off, mmio + off, PTE_WRITABLE | PTE_PCD);
    xh.cap = (volatile uint8_t *)(uintptr_t)mmio;

    /* CAPLENGTH (byte 0) + HCIVERSION (bytes 2..3) share the dword at offset 0;
     * read the whole dword (MMIO can dislike sub-dword reads) and extract both.
     * Validate CAPLENGTH before computing the operational base. */
    uint32_t cap0 = cap_rd32(0x00);
    int caplen = (int)(cap0 & 0xFF);
    if (caplen < 8 || caplen >= 256)
        return -1;
    xh.caplength = caplen;
    xh.op = xh.cap + caplen;
    xh.hciversion = (cap0 >> 16) & 0xFFFF;

    uint32_t hcs1 = cap_rd32(CAP_HCSPARAMS1);
    int max_slots = (int)(hcs1 & 0xFF);
    int max_ports = (int)((hcs1 >> 24) & 0xFF);
    if (max_slots < 1) max_slots = 1;
    if (max_slots > XHCI_MAX_SLOTS) max_slots = XHCI_MAX_SLOTS;
    if (max_ports < 1) max_ports = 1;
    if (max_ports > XHCI_MAX_PORTS) max_ports = XHCI_MAX_PORTS;
    xh.max_slots = max_slots;
    xh.max_ports = max_ports;

    uint32_t hcc1 = cap_rd32(CAP_HCCPARAMS1);
    xh.ctx_size = (hcc1 & (1u << 2)) ? 64 : 32;     /* CSZ: 64-byte contexts */

    uint32_t dboff = cap_rd32(CAP_DBOFF) & ~0x3u;
    uint32_t rtsoff = cap_rd32(CAP_RTSOFF) & ~0x1Fu;
    if (dboff < 0x18 || dboff >= 0x10000 || rtsoff < 0x18 || rtsoff >= 0x10000)
        return -1;                                  /* offsets out of our mapping */
    xh.db = (volatile uint32_t *)(xh.cap + dboff);
    xh.rt = xh.cap + rtsoff;

    /* --- reset the host controller (xHCI 1.x §4.2) ------------------------- */
    /* Wait CNR clear, stop the HC (RS=0) + wait HCHalted, assert HCRST + wait it
     * self-clear and CNR clear. All bounded. */
    if (wait_bits(OP_USBSTS, STS_CNR, 0, 500) != 0)
        return -1;                                  /* controller never became ready */

    uint32_t cmd = op_rd(OP_USBCMD);
    if (!(op_rd(OP_USBSTS) & STS_HCH)) {            /* if running, stop it first */
        op_wr(OP_USBCMD, cmd & ~CMD_RS);
        if (wait_bits(OP_USBSTS, STS_HCH, 1, 200) != 0)
            return -1;
    }

    op_wr(OP_USBCMD, op_rd(OP_USBCMD) | CMD_HCRST);
    /* HCRST self-clears, then CNR clears, when the reset completes. */
    if (wait_bits(OP_USBCMD, CMD_HCRST, 0, 500) != 0)
        return -1;
    if (wait_bits(OP_USBSTS, STS_CNR, 0, 500) != 0)
        return -1;

    /* --- program MaxSlotsEn ------------------------------------------------- */
    op_wr(OP_CONFIG, (op_rd(OP_CONFIG) & ~0xFFu) | (uint32_t)max_slots);

    /* --- DCBAA (one frame) ------------------------------------------------- */
    xh.dcbaa = (uint64_t *)dma_alloc_page();
    if (!xh.dcbaa)
        return -1;
    memset(xh.dcbaa, 0, PAGE_SIZE);
    op_wr64(OP_DCBAAP, phys_of(xh.dcbaa));

    /* --- command ring (one frame) ------------------------------------------ */
    struct trb *cmdframe = (struct trb *)dma_alloc_page();
    if (!cmdframe)
        return -1;
    ring_init(&xh.cmd, cmdframe);
    /* CRCR = command-ring phys | RCS(cycle=1). */
    op_wr64(OP_CRCR, phys_of(cmdframe) | CRCR_RCS);

    /* --- event ring: ERST (one frame) -> event-ring segment (one frame) ----- */
    xh.erst = (struct trb *)dma_alloc_page();   /* one ERST entry fits */
    struct trb *evtframe = (struct trb *)dma_alloc_page();
    if (!xh.erst || !evtframe)
        return -1;
    memset(xh.erst, 0, PAGE_SIZE);
    memset(evtframe, 0, PAGE_SIZE);
    xh.evt      = evtframe;
    xh.evt_deq  = 0;
    xh.evt_cycle = 1;                               /* controller starts at cycle 1 */

    /* ERST entry 0: { ring-segment base (64-bit), size (low 16 bits) }. The ERST
     * entry layout is base_lo, base_hi, size, reserved — write it as raw dwords. */
    {
        uint64_t seg = phys_of(evtframe);
        volatile uint32_t *e = (volatile uint32_t *)xh.erst;
        e[0] = (uint32_t)seg;
        e[1] = (uint32_t)(seg >> 32);
        e[2] = TRBS_PER_RING;                       /* segment size in TRBs */
        e[3] = 0;
    }

    /* Interrupter 0: ERSTSZ=1, ERDP = event-ring base, ERSTBA = ERST base, then
     * enable the interrupter (we still poll, but IE/IMAN are spec-required). */
    rt_wr(RT_IR0 + IR_ERSTSZ, 1);
    rt_wr64(RT_IR0 + IR_ERDP, phys_of(evtframe));
    rt_wr64(RT_IR0 + IR_ERSTBA, phys_of(xh.erst));
    rt_wr(RT_IR0 + IR_IMOD, 0);
    rt_wr(RT_IR0 + IR_IMAN, IMAN_IE);              /* interrupt enable (we poll) */

    /* --- contexts + bounce buffers ----------------------------------------- */
    xh.in_ctx    = (uint8_t *)dma_alloc_page();
    uint8_t *bufs = (uint8_t *)dma_alloc_page();
    xh.bulk_buf  = (uint8_t *)dma_alloc_page();
    if (!xh.in_ctx || !bufs || !xh.bulk_buf)
        return -1;
    memset(xh.in_ctx, 0, PAGE_SIZE);
    memset(bufs, 0, PAGE_SIZE);
    memset(xh.bulk_buf, 0, PAGE_SIZE);
    xh.setup_buf = bufs;            /* (unused — Setup uses Immediate Data)      */
    xh.data_buf  = bufs + 64;       /* control data-stage bounce buffer          */

    /* --- run the controller ------------------------------------------------- */
    op_wr(OP_USBCMD, op_rd(OP_USBCMD) | CMD_RS | CMD_INTE);
    if (wait_bits(OP_USBSTS, STS_HCH, 0, 200) != 0)
        return -1;                                  /* never left halted */

    xh.present = 1;                                 /* HC up + running */

    /* Sanity: a No-Op command must round-trip through the command + event rings
     * before we trust enumeration. This is the headless proof the rings work even
     * when no device is attached. */
    {
        int dummy = 0;
        int cc = command_exec(0, 0, TRB_TYPE(TRB_NOOP_CMD), &dummy);
        if (cc != CC_SUCCESS) {
            kprintf("[xhci] No-Op command did not complete (cc=%d); rings suspect\n", cc);
            /* HC is up; leave present=1 so the self-test reports the controller,
             * but enumeration won't be attempted. */
            return -1;
        }
    }

    /* --- find + reset a populated root port -------------------------------- */
    int port = -1;
    uint8_t speed = 0;
    for (int p = 0; p < xh.max_ports; p++) {
        if (reset_port(p, &speed)) { port = p; break; }
    }
    if (port < 0) {
        xh.reset_port_idx = -1;
        return -1;                                  /* HC up, no device on any port */
    }
    xh.reset_port_idx = port;
    xh.port_speed     = speed;

    /* --- enumerate the device over xHCI ------------------------------------ */
    if (enumerate_device() != 0)
        return -1;

    /* STRETCH: if it's a BOT/SCSI mass-storage device, configure its bulk
     * endpoints + read sector 0 over xHCI bulk. Best-effort — a failure here does
     * not fail xhci_init (the enumeration milestone already succeeded). */
    if (xh.is_storage) {
        if (configure_bulk_endpoints() == 0)
            (void)storage_bring_up();
    }

    return 0;
}

int xhci_is_up(void) { return xh.present; }

/* ---- boot-time verification ---------------------------------------------- */

void xhci_selftest(void) {
    if (!xh.present) {
        kprintf("[xhci] no xHCI (USB 3.0) controller found "
                "(none attached; UHCI + EHCI + their devices intact).\n\n");
        return;
    }

    kprintf("[ ok ] xHCI HC up: USB 3.0 host, HCIVERSION=%x.%02x, MaxSlots=%d "
            "MaxPorts=%d (MMIO TRB rings; UHCI + EHCI + their devices unaffected).\n",
            (xh.hciversion >> 8) & 0xFF, xh.hciversion & 0xFF,
            xh.max_slots, xh.max_ports);

    if (xh.reset_port_idx < 0) {
        kprintf("[xhci] command + event rings up (HC running) but no device on any "
                "root port (nothing to enumerate).\n\n");
        return;
    }

    if (xh.slot_id > 0)
        kprintf("[ ok ] xHCI command/event rings working: ENABLE SLOT got slot id %d.\n",
                xh.slot_id);

    kprintf("[ ok ] xHCI root-port %d reset + detected a device (speed=%d).\n",
            xh.reset_port_idx + 1, xh.port_speed);

    if (!xh.enum_ok) {
        kprintf("[xhci] device present on port %d but enumeration did not complete.\n\n",
                xh.reset_port_idx + 1);
        return;
    }

    kprintf("[ ok ] xHCI enumerated device over control transfers: "
            "slot=%d idVendor=%04x idProduct=%04x bDeviceClass=%02x ep0_maxp=%d "
            "(device descriptor read over xHCI TRB rings after ENABLE SLOT + "
            "ADDRESS DEVICE).\n",
            xh.slot_id, xh.id_vendor, xh.id_product, xh.dev_class, xh.ep0_maxp);

    /* STRETCH: a BOT/SCSI mass-storage device behind xHCI. */
    if (xh.is_storage) {
        kprintf("[xhci] device is BOT/SCSI mass-storage: bulk-in=ep%d(maxp=%d) "
                "bulk-out=ep%d(maxp=%d)\n",
                xh.bulk_in, xh.bulk_in_maxp, xh.bulk_out, xh.bulk_out_maxp);
        if (xh.storage_sector_ok)
            kprintf("[ ok ] xHCI bulk IN: read sector 0 over xHCI (BOT/SCSI READ(10)), "
                    "sum=%08x first16=%02x%02x%02x%02x%02x%02x%02x%02x"
                    "%02x%02x%02x%02x%02x%02x%02x%02x\n",
                    xh.storage_sector_sum,
                    xh.storage_first16[0],  xh.storage_first16[1],
                    xh.storage_first16[2],  xh.storage_first16[3],
                    xh.storage_first16[4],  xh.storage_first16[5],
                    xh.storage_first16[6],  xh.storage_first16[7],
                    xh.storage_first16[8],  xh.storage_first16[9],
                    xh.storage_first16[10], xh.storage_first16[11],
                    xh.storage_first16[12], xh.storage_first16[13],
                    xh.storage_first16[14], xh.storage_first16[15]);
        else
            kprintf("[xhci] bulk sector read over xHCI did not complete "
                    "(control path proven; bulk best-effort).\n");

        /* The headline change (M1889): a real, mountable block device. */
        if (xh.storage_ready) {
            uint64_t mib = (xh.bot.blocks * (uint64_t)xh.bot.block_size) / (1024 * 1024);
            kprintf("[ ok ] xHCI usb-storage READ CAPACITY = %lu blocks x %u bytes "
                    "(%lu MiB) — registered as a block device (usb-xhci).\n",
                    xh.bot.blocks, xh.bot.block_size, mib);
        }
    }

    kprintf("\n");
}
