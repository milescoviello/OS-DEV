/*
 * ehci.c — EHCI (USB 2.0) host-controller driver: bring up a high-speed USB host,
 * route + reset a root port, build the asynchronous schedule, and enumerate the
 * device behind it via control transfers.
 *
 * --- Why ---------------------------------------------------------------------
 * kernel/usb.c drives a UHCI (USB 1.1) controller — through I/O ports, a 1024-
 * entry frame list, and QH/TD chains the controller walks every 1 ms. An EHCI
 * controller is the USB *2.0* host: a PCI device (class 0x0C serial-bus, subclass
 * 0x03 USB, prog-IF 0x20 EHCI) whose registers are MEMORY-MAPPED (BAR0, like
 * AHCI/NVMe), and whose transfers ride a fundamentally different structure — an
 * *asynchronous schedule*: a circular linked list of Queue Heads (QH), each
 * carrying a chain of queue Transfer Descriptors (qTD). This is additive: UHCI and
 * everything on it (tablet, mass-storage, keyboard) keep working untouched.
 *
 * --- The model ---------------------------------------------------------------
 * To run a transfer we build a QH describing the target endpoint (device address,
 * endpoint number, max packet, high-speed) and a chain of qTDs (one per stage of a
 * control transfer: SETUP / DATA / STATUS). Each qTD names its own data buffer(s)
 * and carries a PID, a data toggle, and a byte count. We link the qTDs, point the
 * QH's transfer overlay at the first qTD, splice the QH onto the async list (right
 * after the list's head QH), set the controller running with the async schedule
 * enabled, and POLL the qTDs' status: the controller clears each qTD's Active bit
 * when it completes; the halt/error bits tell us if it faulted. A finite timeout
 * bounds every poll. The async list always has one permanent "head" QH (its H bit
 * set, pointing back at itself) so the controller has a valid ring to walk even
 * when idle; we keep the transfer QH spliced in (its endpoint inactive between
 * transfers) so the ring topology never changes mid-run.
 *
 * --- DMA + alignment ---------------------------------------------------------
 * Every QH / qTD / data buffer comes from pmm_alloc_frame(): the PMM returns low
 * physical RAM that the boot page tables identity-map (phys == virt), so a frame's
 * address is BOTH a CPU pointer AND the physical address the controller's DMA
 * needs — exactly how usb.c / ahci.c / nvme.c do it. EHCI requires QH and qTD on
 * 32-byte boundaries; a 4 KiB frame is 4 KiB-aligned, and we sub-allocate the
 * fixed schedule structures at 32-byte-aligned offsets inside one frame. The MMIO
 * BAR is mapped cache-disabled (PTE_PCD), like nvme.c's register block.
 *
 * --- Safety (reviewed line-by-line) ------------------------------------------
 *  - CAPLENGTH is validated (>= 8 and < 256) before computing the operational
 *    base; N_PORTS is read from HCSPARAMS and capped (EHCI_MAX_PORTS) before any
 *    port loop.
 *  - Enough MMIO is mapped to cover the operational registers + every PORTSC.
 *  - Every poll loop (HC halt, HC reset, port reset, qTD completion) has a finite
 *    timeout; a halted/errored HC or a qTD error returns -1 cleanly.
 *  - Each control transfer's data stage is bounded to a fixed page-sized buffer;
 *    descriptor reads go into fixed buffers with bounded lengths; the config-
 *    descriptor walk is bounded (blen<2 / i+blen>total guards) exactly like
 *    usb_storage.c's.
 *  - Absent EHCI controller => ehci_init() returns -1 (clean no-op). UHCI + its
 *    devices are completely unaffected (this is a separate file; usb.c untouched).
 */
#include "ehci.h"
#include "usbbot.h"   /* the shared BOT/SCSI protocol layer (M1889) */
#include "pci.h"
#include "pmm.h"
#include "vmm.h"
#include "string.h"
#include "console.h"
#include "timer.h"
#include <stdint.h>

/* ---- capability registers (BAR0-relative, EHCI 1.0 §2.2) ----------------- */
#define CAP_CAPLENGTH   0x00   /* u8  : offset from BAR0 to the operational regs */
#define CAP_HCIVERSION  0x02   /* u16 : interface version (BCD)                  */
#define CAP_HCSPARAMS   0x04   /* u32 : structural params (N_PORTS in bits 3..0) */
#define CAP_HCCPARAMS   0x08   /* u32 : capability params (bit0 = 64-bit addr)   */

/* ---- operational registers (relative to BAR0 + CAPLENGTH, EHCI 1.0 §2.3) -- */
#define OP_USBCMD        0x00  /* command                                       */
#define OP_USBSTS        0x04  /* status                                        */
#define OP_USBINTR       0x08  /* interrupt enable                              */
#define OP_FRINDEX       0x0C  /* frame index                                   */
#define OP_CTRLDSSEG     0x10  /* control-data-structure segment (high 32 bits) */
#define OP_PERIODICBASE  0x14  /* periodic frame list base                      */
#define OP_ASYNCLISTADDR 0x18  /* async list address (a QH's physical address)  */
#define OP_CONFIGFLAG    0x40  /* configured flag (route ports to EHCI)         */
#define OP_PORTSC        0x44  /* port status/control[] (one u32 per port)      */

/* USBCMD bits (EHCI 1.0 §2.3.1). */
#define CMD_RS      (1u << 0)   /* run/stop                                     */
#define CMD_HCRESET (1u << 1)   /* host controller reset                        */
#define CMD_PSE     (1u << 4)   /* periodic schedule enable                     */
#define CMD_ASE     (1u << 5)   /* asynchronous schedule enable                 */
#define CMD_IAAD    (1u << 6)   /* interrupt on async advance doorbell          */

/* USBSTS bits (EHCI 1.0 §2.3.2). */
#define STS_HCHALTED (1u << 12) /* HC halted                                    */

/* PORTSC bits (EHCI 1.0 §2.3.9). */
#define PORTSC_CCS   (1u << 0)  /* current connect status                       */
#define PORTSC_CSC   (1u << 1)  /* connect status change (write-1-to-clear)     */
#define PORTSC_PED   (1u << 2)  /* port enabled                                 */
#define PORTSC_PEDC  (1u << 3)  /* port enable change (write-1-to-clear)        */
#define PORTSC_PR    (1u << 8)  /* port reset                                   */
#define PORTSC_LS    (3u << 10) /* line status (bits 11..10)                    */
#define PORTSC_PP    (1u << 12) /* port power                                   */
#define PORTSC_PO    (1u << 13) /* port owner (1 = companion/UHCI owns it)      */
/* bits we must preserve-and-not-clear when doing read-modify-write on PORTSC:
 * CSC/PEDC/OCC (bits 1,3,5) are write-1-to-clear, so a naive write-back would
 * clear them; mask them off so we only ever set what we intend. */
#define PORTSC_RWC_MASK (PORTSC_CSC | PORTSC_PEDC | (1u << 5))

/* A low-speed device parks line-status at K-state (01b) at connect; EHCI hands
 * those (and any device that fails to enable high-speed) to a companion
 * controller via the port-owner bit. We only drive high-speed devices. */
#define PORTSC_LS_KSTATE (1u << 10)

/* qTD token field bits (EHCI 1.0 §3.5). */
#define QTD_STS_ACTIVE  (1u << 7)   /* set by us, cleared by HC on completion    */
#define QTD_STS_HALTED  (1u << 6)   /* endpoint halted (STALL)                   */
#define QTD_STS_BUFERR  (1u << 5)   /* data buffer error                         */
#define QTD_STS_BABBLE  (1u << 4)   /* babble detected                           */
#define QTD_STS_XACTERR (1u << 3)   /* transaction error (CRC/timeout/bad PID)   */
#define QTD_STS_MISSED  (1u << 2)   /* missed micro-frame (periodic only)        */
#define QTD_ERR_MASK    (QTD_STS_HALTED | QTD_STS_BUFERR | QTD_STS_BABBLE | QTD_STS_XACTERR)
#define QTD_PID_OUT     0u
#define QTD_PID_IN      1u
#define QTD_PID_SETUP   2u
#define QTD_CERR_3      (3u << 10)  /* 3 error retries                           */
#define QTD_IOC         (1u << 15)  /* interrupt on complete                     */
#define QTD_TOGGLE      (1u << 31)  /* data toggle (DATA0/DATA1)                 */
#define QTD_PTR_TERM    1u          /* T-bit: pointer is invalid (end of chain)  */

/* QH endpoint-characteristics (dword 1) bits (EHCI 1.0 §3.6). */
#define QH_EPS_HIGH     (2u << 12)  /* endpoint speed = high                     */
#define QH_DTC          (1u << 14)  /* data-toggle control: take toggle from qTD */
#define QH_HEAD         (1u << 15)  /* head of the reclamation (async) list      */
/* QH horizontal-link type field (bits 2..1): 01b = QH. */
#define QH_LINK_TYPE_QH (1u << 1)

/* A queue Transfer Descriptor (qTD), 32-byte aligned (EHCI 1.0 Figure 3-7).
 * We expose the five buffer pointers; for our small single-page transfers only
 * buf[0] (+ at most buf[1] for a page-crossing) is ever used. */
struct ehci_qtd {
    volatile uint32_t next;        /* next qTD pointer (or T-bit terminate)      */
    volatile uint32_t alt_next;    /* alternate next qTD (on short packet)       */
    volatile uint32_t token;       /* status / PID / bytes / toggle              */
    volatile uint32_t buf[5];      /* buffer page pointers                       */
    /* pad to a 32-byte multiple so the next sub-allocated qTD stays aligned.
     * (The struct above is 32 bytes already — buf[5] makes 8 dwords.) */
} __attribute__((packed));

/* A Queue Head (QH), 32-byte aligned (EHCI 1.0 Figure 3-5). The transfer
 * "overlay" (the working copy of the current qTD the HC executes from) occupies
 * dwords 4..11; we initialise overlay.next to point at the first qTD of a chain. */
struct ehci_qh {
    volatile uint32_t hlink;       /* horizontal link to the next QH (+ type/T)  */
    volatile uint32_t epchar;      /* endpoint characteristics (dword 1)         */
    volatile uint32_t epcaps;      /* endpoint capabilities (dword 2)            */
    volatile uint32_t cur_qtd;     /* current qTD pointer (HC-maintained)        */
    /* transfer overlay (a qTD-shaped working area) */
    volatile uint32_t ov_next;     /* overlay: next qTD pointer                  */
    volatile uint32_t ov_alt;      /* overlay: alternate next qTD                */
    volatile uint32_t ov_token;    /* overlay: token                             */
    volatile uint32_t ov_buf[5];   /* overlay: buffer pointers                   */
} __attribute__((packed));

#define EHCI_MAX_PORTS  15         /* HCSPARAMS N_PORTS is a 4-bit field          */
#define EHCI_DATA_OFF   64         /* control data stage starts here in its frame */
#define EHCI_CTRL_BUF   (4096 - EHCI_DATA_OFF) /* usable control data-stage bytes  */

static struct {
    int present;                   /* 1 once the HC is up + running               */
    volatile uint8_t *cap;         /* mapped BAR0 (capability registers)          */
    volatile uint8_t *op;          /* operational registers = cap + CAPLENGTH     */
    uint32_t hciversion;           /* interface version (BCD)                     */
    int nports;                    /* number of root ports (bounded)              */
    int caplength;                 /* operational-register offset                 */

    struct ehci_qh  *async_head;   /* the permanent async-list head QH (H-bit)    */
    struct ehci_qh  *qh;           /* the transfer QH (endpoint 0 of the device)  */
    struct ehci_qtd *qtd;          /* a small pool of qTDs for one transfer       */
    int              nqtd;         /* number of qTDs in the pool                  */

    uint8_t *setup_buf;            /* 8-byte SETUP packet bounce buffer           */
    uint8_t *data_buf;             /* control data-stage bounce buffer            */

    /* the enumerated device, for the self-test log */
    int      enum_ok;
    uint8_t  dev_addr;
    uint16_t id_vendor, id_product;
    uint8_t  dev_class;
    uint16_t ep0_maxp;
    int      reset_port_idx;       /* which root port we reset + enabled (-1 none)*/

    /* STRETCH: a USB mass-storage (Bulk-Only Transport) device behind EHCI. If
     * the enumerated device exposes a BOT/SCSI interface we record its bulk
     * endpoints + toggles and read a sector over EHCI to prove the bulk path. */
    int      is_storage;           /* 1 if the device is a BOT/SCSI mass-storage  */
    uint8_t  bulk_in, bulk_out;    /* bulk IN/OUT endpoint numbers                */
    uint16_t bulk_in_maxp, bulk_out_maxp;
    int      tog_in, tog_out;      /* persistent bulk data toggles                */
    uint8_t *bulk_buf;             /* page-aligned bulk DMA bounce buffer          */
    int      storage_sector_ok;    /* 1 once a sector was read over EHCI bulk      */
    uint32_t storage_sector_sum;   /* additive checksum of that sector            */
    uint8_t  storage_first16[16];  /* its first 16 bytes, kept for the self-test   */
    uint8_t  iface;                /* bInterfaceNumber of the BOT interface        */
    usb_bot_t bot;                 /* shared BOT/SCSI engine + device geometry     */
    int      storage_ready;        /* 1 once READ CAPACITY succeeded (mountable)   */
} eh;

/* ---- small MMIO helpers -------------------------------------------------- */
static uint32_t op_rd(uint32_t off)            { return *(volatile uint32_t *)(eh.op + off); }
static void     op_wr(uint32_t off, uint32_t v){ *(volatile uint32_t *)(eh.op + off) = v; }
static uint32_t cap_rd32(uint32_t off)         { return *(volatile uint32_t *)(eh.cap + off); }

/* PORTSC[n] register offset (operational-relative). */
static uint32_t portsc_off(int n) { return OP_PORTSC + (uint32_t)n * 4; }
static uint32_t portsc_rd(int n)  { return op_rd(portsc_off(n)); }
static void     portsc_wr(int n, uint32_t v) { op_wr(portsc_off(n), v); }

/* Physical address of a kernel pointer for the controller's DMA. Our schedule +
 * buffers live in identity-mapped low RAM (phys == virt); translating is the
 * correct general way (exactly as nvme.c/ahci.c do). EHCI list pointers are
 * 32-bit (we keep CTRLDSSEGMENT=0), so a frame in low RAM fits. */
static uint32_t phys_of(const void *p) {
    uint64_t t = vmm_translate((uint64_t)(uintptr_t)p);
    uint64_t a = t ? t : (uint64_t)(uintptr_t)p;
    return (uint32_t)a;
}

/* A short, finite busy-wait on a bit condition in an operational register.
 * `want_set` = wait for (reg & mask) to become non-zero, else wait for it to
 * become zero. Returns 0 if the condition was met, -1 on timeout. ms is bounded
 * by the timer (100 Hz: 1 tick = 10 ms); we also cap the spin count so a totally
 * dead register can't wedge boot even before the timer is ticking. */
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

/* ---- the async-schedule control-transfer primitive ----------------------- */

/* Build one qTD into `q`: PID, data toggle, byte length, buffer (phys), and the
 * link to the next qTD (or T-bit terminate if next==NULL). Up to two buffer
 * pages are programmed so a transfer that crosses a 4 KiB boundary still works;
 * our buffers are page-aligned frames, so buf[0] alone covers <= one page. */
static void make_qtd(struct ehci_qtd *q, struct ehci_qtd *next, uint32_t pid,
                     int toggle, int len, void *buf) {
    q->next     = next ? (phys_of(next) & ~0x1Fu) : QTD_PTR_TERM;
    q->alt_next = QTD_PTR_TERM;
    uint32_t tok = QTD_STS_ACTIVE | QTD_CERR_3
                 | (pid << 8)
                 | ((uint32_t)(len & 0x7FFF) << 16);
    if (toggle) tok |= QTD_TOGGLE;
    q->token = tok;
    for (int i = 0; i < 5; i++) q->buf[i] = 0;
    if (buf && len > 0) {
        uint32_t pa = phys_of(buf);
        q->buf[0] = pa;
        /* If the region spills past its page, point buf[1] at the next page
         * (its low 12 bits must be zero — the HC continues at that page's base). */
        uint32_t end = pa + (uint32_t)len - 1;
        if ((pa & ~0xFFFu) != (end & ~0xFFFu))
            q->buf[1] = (pa & ~0xFFFu) + 0x1000u;
    }
}

/* Run the qTD chain currently linked off the transfer QH and poll to completion.
 * The QH is permanently spliced into the async ring; we (re)point its overlay at
 * the first qTD, which "activates" the endpoint, then wait for the last qTD's
 * Active bit to clear. Returns 0 on success, -1 on any qTD error / HC halt /
 * timeout. `nused` is how many qTDs of the pool the chain occupies. If
 * `req_last`>0 and `act_last`!=NULL, *act_last receives how many of those
 * `req_last` bytes the LAST qTD actually moved (the HC decrements the qTD's
 * Total-Bytes field as it transfers, so transferred = requested - remaining) —
 * this makes a short bulk IN visible. */
static int run_qtds_ex(int nused, int req_last, int *act_last) {
    struct ehci_qh  *qh   = eh.qh;
    struct ehci_qtd *last = &eh.qtd[nused - 1];
    if (act_last) *act_last = 0;

    /* Point the QH's overlay at the first qTD and clear the overlay status so the
     * HC reloads from qtd[0]. Writing ov_next + clearing the Active/Halted status
     * in the overlay token is the documented way to (re)start a queued QH. */
    qh->cur_qtd  = QTD_PTR_TERM;
    qh->ov_alt   = QTD_PTR_TERM;
    qh->ov_token = 0;                      /* not Active/Halted -> HC fetches ov_next */
    __asm__ volatile("" ::: "memory");
    qh->ov_next  = phys_of(&eh.qtd[0]) & ~0x1Fu;
    __asm__ volatile("" ::: "memory");

    /* Poll the LAST qTD: when the HC finishes the chain its Active bit clears.
     * ~500 ms is generous for a control transfer yet finite. */
    uint64_t deadline = timer_ticks() + 50;            /* 50 ticks @100Hz = 500 ms */
    for (;;) {
        if (op_rd(OP_USBSTS) & STS_HCHALTED)           /* HC died -> bail clean */
            return -1;
        uint32_t tok = last->token;
        if (!(tok & QTD_STS_ACTIVE)) {
            /* Chain drained. Scan every qTD for an error/halt bit. */
            for (int i = 0; i < nused; i++)
                if (eh.qtd[i].token & QTD_ERR_MASK)
                    return -1;
            if (act_last && req_last > 0) {
                int remaining = (int)((tok >> 16) & 0x7FFF);
                int moved = req_last - remaining;
                *act_last = (moved < 0) ? 0 : (moved > req_last ? req_last : moved);
            }
            return 0;
        }
        if (timer_ticks() >= deadline)
            return -1;
    }
}
static int run_qtds(int nused) { return run_qtds_ex(nused, 0, 0); }

/* A standard control transfer to the device at `addr`, endpoint 0 (max packet
 * `ep0_maxp`). setup[8] is the request; data/len is the data stage (may be 0);
 * `in` selects device->host. Mirrors usb.c's usb_control_xfer but over EHCI's
 * QH+qTD async schedule. Returns 0 on success, -1 on error/timeout. */
static int control_xfer(uint8_t addr, uint16_t ep0_maxp, const uint8_t setup[8],
                        void *data, int len, int in) {
    if (!eh.present || len < 0 || ep0_maxp == 0)
        return -1;
    if (len > EHCI_CTRL_BUF)                            /* bounded to the bounce buf */
        return -1;

    /* Program the transfer QH for this endpoint: address, ep 0, high-speed, max
     * packet, data-toggle taken from the qTDs (DTC=1), and Nak-count-reload in
     * epcaps (mult=1 transaction per micro-frame). The QH stays spliced in the
     * async ring; we just retarget it. */
    eh.qh->epchar = ((uint32_t)addr & 0x7F)
                  | (0u << 8)                            /* endpoint 0 */
                  | QH_EPS_HIGH
                  | QH_DTC
                  | ((uint32_t)(ep0_maxp & 0x7FF) << 16);
    eh.qh->epcaps = (1u << 30);                          /* Mult = 1 */

    memcpy(eh.setup_buf, setup, 8);
    if (!in && len)
        memcpy(eh.data_buf, data, (size_t)len);

    /* Build SETUP -> [DATA] -> STATUS. Control toggles: SETUP is DATA0, the data
     * stage starts at DATA1, the status stage is always DATA1. */
    int n = 0;
    make_qtd(&eh.qtd[n], 0, QTD_PID_SETUP, 0, 8, eh.setup_buf);
    int setup_idx = n++;

    int toggle = 1;
    if (len > 0) {
        /* Single data qTD: a high-speed control endpoint's qTD can carry up to
         * 5 buffer pages; our data stage is <= one page bounce buffer, so one
         * qTD suffices and the HC splits it into ep0_maxp packets itself. */
        if (n >= eh.nqtd - 1) return -1;
        make_qtd(&eh.qtd[n], 0, in ? QTD_PID_IN : QTD_PID_OUT, toggle, len, eh.data_buf);
        n++;
    }
    if (n >= eh.nqtd) return -1;
    make_qtd(&eh.qtd[n], 0, in ? QTD_PID_OUT : QTD_PID_IN, 1, 0, 0);  /* STATUS */
    int status_idx = n++;

    /* Link the chain: setup -> (data) -> status -> terminate. */
    for (int i = 0; i < n - 1; i++)
        eh.qtd[i].next = (phys_of(&eh.qtd[i + 1]) & ~0x1Fu);
    eh.qtd[n - 1].next = QTD_PTR_TERM;
    (void)setup_idx; (void)status_idx;

    int rc = run_qtds(n);
    if (rc == 0 && in && len)
        memcpy(data, eh.data_buf, (size_t)len);
    return rc;
}

/* ---- standard USB requests (same bytes as usb.c / usb_storage.c) --------- */
static int get_descriptor(uint8_t addr, uint16_t ep0, int type, int index,
                          void *out, int len) {
    uint8_t s[8] = { 0x80, 0x06, (uint8_t)index, (uint8_t)type,
                     0, 0, (uint8_t)len, (uint8_t)(len >> 8) };
    return control_xfer(addr, ep0, s, out, len, 1);
}
static int set_address(uint16_t ep0, int addr) {
    uint8_t s[8] = { 0x00, 0x05, (uint8_t)addr, 0, 0, 0, 0, 0 };
    return control_xfer(0, ep0, s, 0, 0, 0);    /* device is still at address 0 */
}
static int set_configuration(uint8_t addr, uint16_t ep0, int cfg) {
    uint8_t s[8] = { 0x00, 0x09, (uint8_t)cfg, 0, 0, 0, 0, 0 };
    return control_xfer(addr, ep0, s, 0, 0, 0);
}

/* ---- STRETCH: a bulk transfer + Bulk-Only-Transport over EHCI ------------ */

/* One BULK transfer to the storage device's endpoint `ep` (max packet `maxp`),
 * moving `len` bytes to/from the bulk bounce buffer (`in` selects IN vs OUT). The
 * data toggle is threaded through *toggle (read + advanced per packet). *actual
 * data toggle is advanced per packet via *toggle. Reprograms the transfer QH for
 * the bulk endpoint and runs a single qTD (the HC splits it into maxp packets).
 * `len` is bounded to one page (the bulk bounce frame). Returns the number of
 * bytes actually moved (>=0; a short IN is thus visible), or -1 on
 * error/stall/timeout. On an IN the data lands in eh.bulk_buf. */
static int bulk_xfer(uint8_t ep, uint16_t maxp, int *toggle, int len, int in) {
    if (!eh.present || maxp == 0 || len < 0 || len > (int)PAGE_SIZE)
        return -1;

    /* Reprogram the transfer QH for the bulk endpoint of the storage device. */
    eh.qh->epchar = ((uint32_t)eh.dev_addr & 0x7F)
                  | (((uint32_t)ep & 0xF) << 8)
                  | QH_EPS_HIGH
                  | QH_DTC
                  | ((uint32_t)(maxp & 0x7FF) << 16);
    eh.qh->epcaps = (1u << 30);                          /* Mult = 1 */

    int tg = toggle ? (*toggle & 1) : 0;
    make_qtd(&eh.qtd[0], 0, in ? QTD_PID_IN : QTD_PID_OUT, tg, len, eh.bulk_buf);
    eh.qtd[0].next = QTD_PTR_TERM;

    int act = 0;
    int rc = run_qtds_ex(1, len, &act);
    if (rc != 0)
        return -1;
    if (act > len) act = len;
    /* Advance the toggle by the number of maxp packets the transfer ACTUALLY
     * consumed — derived from `act`, not `len` (M1891). EHCI issues ONE qTD for
     * the whole transfer and the HC splits it into maxp packets internally, so a
     * short IN ends the qTD early having moved fewer packets than we asked for;
     * advancing by the requested count then leaves our toggle out of step with
     * the device's and every later transfer on this endpoint NAKs or
     * mis-sequences. (Only a parity difference is observable, which is why this
     * stayed latent — see usb_bot_packets in usbbot.h.) */
    if (toggle)
        *toggle = (tg + usb_bot_packets(act, (int)maxp)) & 1;
    /* On an IN, the data now sits in eh.bulk_buf for the caller to read. */
    return act;                                          /* >=0 bytes moved */
}

/* --- the EHCI transport for the shared BOT layer (kernel/usbbot.h) ---------
 * The BOT/SCSI protocol itself lives once, in usbbot.h, host-tested against a
 * mock device. EHCI's contribution is this adapter: bulk_xfer above always moves
 * data through the page-aligned DMA bounce frame eh.bulk_buf (the HC needs a
 * physical address), so an OUT copies the caller's bytes in first and an IN
 * copies the received bytes back out. That copy is what used to force the old
 * private bot_read to snapshot the data phase into a second static page before
 * reading the CSW; routing through the caller's own buffer removes both the
 * duplicated protocol and that 4 KiB static scratch buffer. */
static int ehci_bot_xfer(void *ctx, int in, void *buf, int len) {
    (void)ctx;
    if (len < 0 || len > (int)PAGE_SIZE) return -1;
    if (!in && len)
        memcpy(eh.bulk_buf, buf, (size_t)len);
    int act = bulk_xfer(in ? eh.bulk_in : eh.bulk_out,
                        in ? eh.bulk_in_maxp : eh.bulk_out_maxp,
                        in ? &eh.tog_in : &eh.tog_out, len, in);
    if (act < 0) return -1;
    if (act > len) act = len;
    if (in && act > 0)
        memcpy(buf, eh.bulk_buf, (size_t)act);
    return act;
}
static void ehci_bot_delay(int ms) { timer_wait(ms); }

/* BOT reset recovery over EHCI (M1899) — the same USB Mass Storage §5.3.4
 * sequence usb_storage.c performs for UHCI: Bulk-Only Mass Storage Reset, then
 * Clear Feature ENDPOINT_HALT on both bulk endpoints (which is what resets the
 * DEVICE's data toggles), then resynchronise ours.
 *
 * This matters more on EHCI than anywhere else: EHCI is the transport that keeps
 * per-endpoint data toggles in software AND issues one qTD per transfer, so it is
 * the one where a desync silently mis-sequences every later transfer — exactly
 * the class of bug M1891 fixed in the non-error path. Best-effort; the caller
 * treats a still-failing command as failed. */
static int ehci_bot_reset_recovery(void *ctx) {
    (void)ctx;
    int ok = 0;
    uint8_t reset[8] = { 0x21, 0xFF, 0, 0, eh.iface, 0, 0, 0 };
    if (control_xfer(eh.dev_addr, eh.ep0_maxp, reset, 0, 0, 0) != 0) ok = -1;

    uint8_t chi[8] = { 0x02, 0x01, 0x00, 0x00, (uint8_t)(eh.bulk_in | 0x80), 0, 0, 0 };
    if (control_xfer(eh.dev_addr, eh.ep0_maxp, chi, 0, 0, 0) != 0) ok = -1;

    uint8_t cho[8] = { 0x02, 0x01, 0x00, 0x00, (uint8_t)(eh.bulk_out & 0x7F), 0, 0, 0 };
    if (control_xfer(eh.dev_addr, eh.ep0_maxp, cho, 0, 0, 0) != 0) ok = -1;

    eh.tog_in = eh.tog_out = 0;      /* match a freshly-unhalted endpoint */
    return ok;
}

/* Bring the mass-storage device behind EHCI up as a usable disk: bind the shared
 * BOT engine to the EHCI transport, poke TEST UNIT READY, then READ CAPACITY so
 * the block layer knows its geometry. Also reads sector 0 to fill the self-test's
 * checksum. Returns 0 if the device is ready for I/O. */
static int storage_bring_up(void) {
    eh.bot.xfer           = ehci_bot_xfer;
    eh.bot.delay_ms       = ehci_bot_delay;
    eh.bot.reset_recovery = ehci_bot_reset_recovery;
    eh.bot.ctx      = 0;
    eh.bot.max_data = PAGE_SIZE;            /* one bulk data phase = the bounce frame */
    eh.bot.lun      = 0;

    (void)usb_bot_test_unit_ready(&eh.bot);         /* some devices need the poke */
    if (usb_bot_read_capacity(&eh.bot) != 0)
        return -1;
    eh.storage_ready = 1;

    /* Prove the read path end-to-end and record sector 0's checksum for the
     * self-test log (the same value the old LBA-0-only path reported). */
    static uint8_t sec0[USB_BOT_SECTOR];
    if (usb_bot_read10(&eh.bot, 0, 1, sec0) == 0) {
        uint32_t sum = 0;
        for (int i = 0; i < USB_BOT_SECTOR; i++)
            sum += sec0[i];
        eh.storage_sector_sum = sum;
        memcpy(eh.storage_first16, sec0, 16);
        eh.storage_sector_ok  = 1;
    }
    return 0;
}

/* --- public storage API: a real block device over USB 2.0 (M1889) ---------- */
int ehci_storage_present(void) { return eh.present && eh.storage_ready; }

uint64_t ehci_storage_capacity(void) {
    return ehci_storage_present() ? eh.bot.blocks : 0;
}

int ehci_storage_read(uint32_t lba, uint32_t count, void *buf) {
    if (!ehci_storage_present()) return -1;
    return usb_bot_read10(&eh.bot, lba, count, buf);
}

int ehci_storage_write(uint32_t lba, uint32_t count, const void *buf) {
    if (!ehci_storage_present()) return -1;
    return usb_bot_write10(&eh.bot, lba, count, buf);
}

/* ---- root-port reset ----------------------------------------------------- */

/* Reset + enable a single EHCI root port. Returns 1 if a high-speed device is
 * connected + enabled there, 0 otherwise (nothing connected, or a full/low-speed
 * device that EHCI hands to a companion controller — we don't drive those). */
static int reset_port(int port) {
    uint32_t sc = portsc_rd(port);
    if (!(sc & PORTSC_CCS))
        return 0;                                  /* nothing connected */

    /* A device that connects at low-speed line-state is not ours: release it to
     * the companion (set port-owner) and report "no high-speed device". */
    if ((sc & PORTSC_LS) == PORTSC_LS_KSTATE) {
        portsc_wr(port, (sc & ~PORTSC_RWC_MASK) | PORTSC_PO);
        return 0;
    }

    /* Assert reset: clear Port Enable + set Port Reset (must not be set together
     * with Run-stop; the HC is running, that's fine). Hold ~50 ms (USB 2.0 §7.1.7.5
     * requires >=10 ms; QEMU is forgiving but we follow the spec). */
    sc = portsc_rd(port) & ~PORTSC_RWC_MASK;
    sc &= ~PORTSC_PED;
    sc |= PORTSC_PR;
    portsc_wr(port, sc);
    timer_wait(6);                                 /* ~60 ms */

    /* Deassert reset; the HC then takes >=2 ms to complete the reset + (for a
     * high-speed device) enable the port automatically. */
    sc = portsc_rd(port) & ~PORTSC_RWC_MASK;
    sc &= ~PORTSC_PR;
    portsc_wr(port, sc);

    /* Wait for Port Reset to read back as cleared (HC finished the reset). */
    for (int i = 0; i < 20; i++) {
        if (!(portsc_rd(port) & PORTSC_PR))
            break;
        timer_wait(1);                             /* ~10 ms each */
    }
    timer_wait(1);

    sc = portsc_rd(port);
    if (sc & PORTSC_PED)
        return 1;                                  /* enabled => high-speed device */

    /* Not enabled after reset => a full/low-speed device the EHCI core can't run;
     * hand it to the companion controller and report none. */
    portsc_wr(port, (portsc_rd(port) & ~PORTSC_RWC_MASK) | PORTSC_PO);
    return 0;
}

/* ---- enumeration --------------------------------------------------------- */

/* Enumerate the high-speed device on the freshly-enabled port: read 8 bytes of
 * the device descriptor (to learn the real ep0 max packet), assign an address,
 * re-read the full device descriptor (idVendor/idProduct/class), then fetch the
 * config descriptor and SET_CONFIGURATION. Fills eh.* and returns 0; -1 on any
 * failure. Mirrors usb.c's tablet enumeration + usb_storage.c's config walk. */
static int enumerate_device(void) {
    uint16_t ep0 = 8;                              /* ep0 default max packet */

    uint8_t dd[18];
    memset(dd, 0, sizeof(dd));
    if (get_descriptor(0, ep0, 1, 0, dd, 8) != 0) {
        kprintf("[ehci] device descriptor (first 8) failed\n");
        return -1;
    }
    ep0 = dd[7] ? dd[7] : 8;                        /* bMaxPacketSize0 */

    int addr = 1;                                   /* EHCI bus is independent of UHCI */
    if (set_address(ep0, addr) != 0) {
        kprintf("[ehci] SET_ADDRESS failed\n");
        return -1;
    }
    timer_wait(1);                                  /* device needs <=2 ms to switch */

    /* Full device descriptor at the new address. */
    if (get_descriptor((uint8_t)addr, ep0, 1, 0, dd, 18) != 0) {
        kprintf("[ehci] device descriptor (full) failed\n");
        return -1;
    }
    eh.id_vendor  = (uint16_t)(dd[8]  | (dd[9]  << 8));
    eh.id_product = (uint16_t)(dd[10] | (dd[11] << 8));
    eh.dev_class  = dd[4];

    /* Config descriptor: header first (total length), then the whole thing,
     * bounded to a fixed buffer + the bounds guards usb_storage.c uses. */
    uint8_t cfg[256];
    memset(cfg, 0, sizeof(cfg));
    if (get_descriptor((uint8_t)addr, ep0, 2, 0, cfg, 9) != 0) {
        kprintf("[ehci] config descriptor (header) failed\n");
        return -1;
    }
    int total = cfg[2] | (cfg[3] << 8);
    if (total < 9) return -1;
    if (total > (int)sizeof(cfg)) total = sizeof(cfg);
    if (get_descriptor((uint8_t)addr, ep0, 2, 0, cfg, total) != 0) {
        kprintf("[ehci] config descriptor (full) failed\n");
        return -1;
    }

    /* Walk the config descriptor (bounded, same guards as usb_storage.c). Confirm
     * it is well-formed, pick the bConfigurationValue to SET_CONFIGURATION with,
     * and — for the STRETCH bulk path — detect a Mass-Storage / SCSI-transparent /
     * Bulk-Only-Transport interface (class 0x08 / subclass 0x06 / proto 0x50) and
     * its BULK IN + BULK OUT endpoints. Endpoints belong to the most recent
     * interface; we only capture them while inside the target interface. */
    int cfg_value = cfg[5];
    int in_target = 0;
    uint8_t bin = 0, bout = 0;
    uint16_t bin_maxp = 0, bout_maxp = 0;
    for (int i = 0; i + 1 < total; ) {
        int blen = cfg[i], btype = cfg[i + 1];
        if (blen < 2) break;
        if (i + blen > total) break;
        if (btype == 0x04 && blen >= 9) {              /* INTERFACE */
            in_target = (cfg[i + 5] == 0x08 && cfg[i + 6] == 0x06 && cfg[i + 7] == 0x50);
            if (in_target) eh.iface = cfg[i + 2];      /* bInterfaceNumber, for BOT reset (M1899) */
        } else if (btype == 0x05 && blen >= 7 && in_target) {  /* ENDPOINT in target */
            uint8_t eaddr = cfg[i + 2], eattr = cfg[i + 3];
            uint16_t emax = (uint16_t)(cfg[i + 4] | (cfg[i + 5] << 8));
            if ((eattr & 0x03) == 0x02) {              /* BULK */
                if (eaddr & 0x80) { bin = eaddr & 0x0F; bin_maxp = emax; }
                else              { bout = eaddr & 0x0F; bout_maxp = emax; }
            }
        }
        i += blen;
    }

    if (set_configuration((uint8_t)addr, ep0, cfg_value) != 0) {
        kprintf("[ehci] SET_CONFIGURATION failed\n");
        return -1;
    }

    eh.dev_addr = (uint8_t)addr;
    eh.ep0_maxp = ep0;
    eh.enum_ok  = 1;

    /* STRETCH: if this is a complete BOT/SCSI interface, record its bulk
     * endpoints so the self-test can read a sector over EHCI bulk. */
    if (bin && bout) {
        eh.is_storage    = 1;
        eh.bulk_in       = bin;
        eh.bulk_out      = bout;
        eh.bulk_in_maxp  = bin_maxp ? bin_maxp : 512;
        eh.bulk_out_maxp = bout_maxp ? bout_maxp : 512;
        eh.tog_in = 0;
        eh.tog_out = 0;
    }
    return 0;
}

/* ---- bring-up ------------------------------------------------------------ */

int ehci_init(void) {
    memset(&eh, 0, sizeof(eh));
    eh.reset_port_idx = -1;

    /* Locate an EHCI controller by PCI class (0x0C serial-bus, 0x03 USB, 0x20
     * EHCI). QEMU's usb-ehci presents this triple. */
    pci_device_t dev = pci_find_class(0x0C, 0x03, 0x20);
    if (!dev.valid)
        return -1;                                  /* no EHCI controller: clean no-op */

    /* Enable PCI memory-space decode + bus mastering so the HC can DMA the schedule. */
    pci_enable_bus_master(&dev);

    /* BAR0 is the MMIO register block. EHCI's BAR0 may be 32- or 64-bit; read the
     * high dword from BAR1 when the type bits say 64-bit (bits 2:1 == 10b). Map it
     * cache-disabled, like nvme.c's register block. */
    uint32_t bar0_raw = pci_read32(dev.bus, dev.slot, dev.func, 0x10);
    uint64_t mmio = (uint64_t)pci_bar(&dev, 0);
    if (((bar0_raw >> 1) & 0x3) == 0x2) {           /* 64-bit memory BAR */
        uint64_t hi = pci_read32(dev.bus, dev.slot, dev.func, 0x14);
        mmio |= hi << 32;
    }
    if (!mmio)
        return -1;
    /* Map a few pages: capability + operational registers + all PORTSC fit easily.
     * Two pages (8 KiB) more than covers OP_PORTSC + 15*4 for the deepest layout. */
    for (uint64_t off = 0; off < 0x2000; off += PAGE_SIZE)
        vmm_map(mmio + off, mmio + off, PTE_WRITABLE | PTE_PCD);
    eh.cap = (volatile uint8_t *)(uintptr_t)mmio;

    /* CAPLENGTH gives the operational-register offset; validate it before use. */
    int caplen = *(volatile uint8_t *)(eh.cap + CAP_CAPLENGTH);
    if (caplen < 8 || caplen >= 256)
        return -1;
    eh.caplength = caplen;
    eh.op = eh.cap + caplen;
    eh.hciversion = *(volatile uint16_t *)(eh.cap + CAP_HCIVERSION);

    uint32_t hcsparams = cap_rd32(CAP_HCSPARAMS);
    int nports = (int)(hcsparams & 0xF);
    if (nports < 1) nports = 1;
    if (nports > EHCI_MAX_PORTS) nports = EHCI_MAX_PORTS;
    eh.nports = nports;

    /* --- reset the host controller (EHCI 1.0 §4.1) ------------------------- */
    /* Stop it first (RS=0) and wait for HCHalted, then assert HCRESET and wait for
     * it to self-clear. Both waits are bounded. */
    uint32_t cmd = op_rd(OP_USBCMD);
    cmd &= ~CMD_RS;
    op_wr(OP_USBCMD, cmd);
    if (wait_bits(OP_USBSTS, STS_HCHALTED, 1, 200) != 0)
        return -1;                                  /* never halted: bail clean */

    op_wr(OP_USBCMD, op_rd(OP_USBCMD) | CMD_HCRESET);
    if (wait_bits(OP_USBCMD, CMD_HCRESET, 0, 500) != 0)
        return -1;                                  /* reset never completed */

    /* No interrupts — we poll. 32-bit data structures (CTRLDSSEGMENT = 0). */
    op_wr(OP_USBINTR, 0);
    op_wr(OP_CTRLDSSEG, 0);

    /* --- allocate the async schedule (identity-mapped low RAM) ------------- */
    /* One frame holds: the head QH, the transfer QH, and the qTD pool — each on a
     * 32-byte boundary (sizeof(struct ehci_qh)=48, ehci_qtd=32; we lay them out at
     * explicit 64-byte-aligned offsets so every structure is 32-byte aligned with
     * room to spare). A second frame holds the SETUP + data bounce buffers. */
    uint8_t *sched = (uint8_t *)dma_alloc_page();
    uint8_t *bufs  = (uint8_t *)dma_alloc_page();
    uint8_t *bbuf  = (uint8_t *)dma_alloc_page();   /* bulk bounce (STRETCH) */
    if (!sched || !bufs || !bbuf)
        return -1;
    memset(sched, 0, PAGE_SIZE);
    memset(bufs, 0, PAGE_SIZE);
    memset(bbuf, 0, PAGE_SIZE);

    eh.async_head = (struct ehci_qh  *)(sched + 0);    /* offset 0   (64-aligned) */
    eh.qh         = (struct ehci_qh  *)(sched + 64);   /* offset 64  (64-aligned) */
    eh.qtd        = (struct ehci_qtd *)(sched + 128);  /* offset 128 (64-aligned) */
    eh.nqtd       = 8;                                 /* SETUP+DATA+STATUS + slack */
    eh.setup_buf  = bufs + 0;                          /* 8 bytes (page-aligned)   */
    eh.data_buf   = bufs + EHCI_DATA_OFF;              /* control data stage       */
    eh.bulk_buf   = bbuf;                              /* page-aligned bulk DMA buf */

    /* The permanent async-list head QH: H-bit set, horizontal link points back at
     * itself (a one-element ring the HC always has to walk), endpoint inactive. */
    struct ehci_qh *ah = eh.async_head;
    ah->epchar  = QH_HEAD;                             /* H=1; addr 0, inactive    */
    ah->epcaps  = 0;
    ah->cur_qtd = QTD_PTR_TERM;
    ah->ov_next = QTD_PTR_TERM;
    ah->ov_alt  = QTD_PTR_TERM;
    ah->ov_token = QTD_STS_HALTED;                     /* not Active (so the HC skips it) */
    for (int i = 0; i < 5; i++) ah->ov_buf[i] = 0;

    /* The transfer QH: spliced in right after the head. epchar is reprogrammed per
     * transfer in control_xfer; start it inactive (overlay Halted, not Active). */
    struct ehci_qh *q = eh.qh;
    q->epchar  = 0;
    q->epcaps  = (1u << 30);                           /* Mult = 1 */
    q->cur_qtd = QTD_PTR_TERM;
    q->ov_next = QTD_PTR_TERM;
    q->ov_alt  = QTD_PTR_TERM;
    q->ov_token = QTD_STS_HALTED;
    for (int i = 0; i < 5; i++) q->ov_buf[i] = 0;

    /* Link the ring: head -> transfer QH -> head. Both links are QH-typed. */
    q->hlink  = (phys_of(ah) & ~0x1Fu) | QH_LINK_TYPE_QH;
    ah->hlink = (phys_of(q)  & ~0x1Fu) | QH_LINK_TYPE_QH;
    __asm__ volatile("" ::: "memory");

    /* Program ASYNCLISTADDR to the head QH, then run with the async schedule
     * enabled. We do NOT enable the periodic schedule (no interrupt/iso traffic). */
    op_wr(OP_ASYNCLISTADDR, phys_of(ah) & ~0x1Fu);
    op_wr(OP_USBCMD, op_rd(OP_USBCMD) | CMD_ASE | CMD_RS);

    /* Wait for the HC to leave the halted state (it is now running). */
    if (wait_bits(OP_USBSTS, STS_HCHALTED, 0, 200) != 0)
        return -1;

    /* CONFIGFLAG = 1: route all root ports from the companion (UHCI) controllers
     * to this EHCI controller, so a high-speed device enumerates here. */
    op_wr(OP_CONFIGFLAG, 1);
    timer_wait(1);                                      /* let the routing settle */

    eh.present = 1;                                     /* HC is up + running */

    /* --- find + reset a populated high-speed root port --------------------- */
    int port = -1;
    for (int p = 0; p < eh.nports; p++) {
        if (reset_port(p)) { port = p; break; }
    }
    if (port < 0) {
        /* HC is up but no high-speed device on any root port. Leave present=1 so
         * ehci_is_up() reports the controller; the self-test notes "no device". */
        eh.reset_port_idx = -1;
        return -1;
    }
    eh.reset_port_idx = port;

    /* --- enumerate the device over EHCI control transfers ------------------ */
    if (enumerate_device() != 0)
        return -1;

    /* If the enumerated device is a BOT/SCSI mass-storage device, bring it up as
     * a real disk (READ CAPACITY -> geometry) so blockdev_init can register it.
     * Best-effort — a failure here does not fail ehci_init (the control-path
     * milestone already succeeded and the controller stays usable). */
    if (eh.is_storage)
        (void)storage_bring_up();

    return 0;
}

int ehci_is_up(void) { return eh.present; }

/* ---- boot-time verification ---------------------------------------------- */

void ehci_selftest(void) {
    if (!eh.present) {
        kprintf("[ehci] no EHCI (USB 2.0) controller found "
                "(none attached; UHCI + its devices intact).\n\n");
        return;
    }

    kprintf("[ ok ] EHCI HC up: USB 2.0 host, HCIVERSION=%x.%02x, N_PORTS=%d "
            "(MMIO async schedule; UHCI + its devices unaffected).\n",
            (eh.hciversion >> 8) & 0xFF, eh.hciversion & 0xFF, eh.nports);

    if (eh.reset_port_idx < 0) {
        kprintf("[ehci] no high-speed device on any root port "
                "(HC up + async schedule running; nothing to enumerate).\n\n");
        return;
    }

    kprintf("[ ok ] EHCI root-port %d reset + enabled a high-speed device.\n",
            eh.reset_port_idx);

    if (!eh.enum_ok) {
        kprintf("[ehci] device present on port %d but enumeration did not complete.\n\n",
                eh.reset_port_idx);
        return;
    }

    kprintf("[ ok ] EHCI enumerated device over control transfers: "
            "addr=%d idVendor=%04x idProduct=%04x bDeviceClass=%02x ep0_maxp=%d "
            "(device descriptor read over EHCI's QH+qTD async schedule).\n",
            eh.dev_addr, eh.id_vendor, eh.id_product, eh.dev_class, eh.ep0_maxp);

    /* STRETCH: a BOT/SCSI mass-storage device behind EHCI — report the bulk read. */
    if (eh.is_storage) {
        kprintf("[ehci] device is BOT/SCSI mass-storage: bulk-in=ep%d(maxp=%d) "
                "bulk-out=ep%d(maxp=%d)\n",
                eh.bulk_in, eh.bulk_in_maxp, eh.bulk_out, eh.bulk_out_maxp);
        if (eh.storage_sector_ok)
            kprintf("[ ok ] EHCI bulk IN: read sector 0 over EHCI (BOT/SCSI READ(10)), "
                    "sum=%08x first16=%02x%02x%02x%02x%02x%02x%02x%02x"
                    "%02x%02x%02x%02x%02x%02x%02x%02x\n",
                    eh.storage_sector_sum,
                    eh.storage_first16[0],  eh.storage_first16[1],
                    eh.storage_first16[2],  eh.storage_first16[3],
                    eh.storage_first16[4],  eh.storage_first16[5],
                    eh.storage_first16[6],  eh.storage_first16[7],
                    eh.storage_first16[8],  eh.storage_first16[9],
                    eh.storage_first16[10], eh.storage_first16[11],
                    eh.storage_first16[12], eh.storage_first16[13],
                    eh.storage_first16[14], eh.storage_first16[15]);
        else
            kprintf("[ehci] bulk sector read over EHCI did not complete "
                    "(control path proven; bulk best-effort).\n");

        /* The headline change (M1889): it is now a real, mountable block device,
         * not a one-sector self-test curiosity. */
        if (eh.storage_ready) {
            uint64_t mib = (eh.bot.blocks * (uint64_t)eh.bot.block_size) / (1024 * 1024);
            kprintf("[ ok ] EHCI usb-storage READ CAPACITY = %lu blocks x %u bytes "
                    "(%lu MiB) — registered as a block device (usb-ehci).\n",
                    eh.bot.blocks, eh.bot.block_size, mib);
        }
    }

    kprintf("\n");
}
