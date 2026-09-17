/*
 * nic.c — NIC dispatcher: pick a supported network card and route the stack's
 * send/receive/mac through that driver.
 *
 * The stack in net.c is card-agnostic; this is the one place that knows which
 * concrete drivers exist. At bring-up we probe each supported card in priority
 * order and bind a set of function pointers to the first one that initialises.
 * net.c then calls nic_send / nic_receive / nic_mac and the bytes flow over
 * whichever card answered — the e1000 today, the RTL8139 when that's the only
 * card present (or a future third card with one more probe line here).
 *
 * Priority when several cards are present: e1000 first. It's the richer gigabit
 * part, it's what the headless test suite boots with, and preferring it keeps
 * the default path byte-identical to before this dispatcher existed. With only
 * an RTL8139 on the bus, the whole stack runs over the RTL8139; with only a
 * virtio-net device, it runs over virtio-net (the paravirtual NIC).
 */
#include "nic.h"
#include "fw.h"
#include "e1000.h"
#include "rtl8139.h"
#include "virtio_net.h"

/* The bound driver: each field points at the active card's implementation. NULL
 * driver => nic_init() found no supported card (every call no-ops safely). */
static const uint8_t *(*drv_mac)(void);
static int            (*drv_send)(const void *frame, uint16_t len);
static int            (*drv_receive)(void *out, uint16_t max);
static const char     *drv_name = "none";

int nic_init(void) {
    /* IDEMPOTENT (M2125). Three places call this -- net_demo, netcon and now
     * kmain's own bring-up -- and each was written believing it was the only
     * one, which is why netcon's comment worries about a "double-init hazard".
     * Re-running a driver's init re-arms its DMA rings under a card that is
     * already using them. Once a driver is bound, this is a no-op. */
    if (drv_send) return 0;
    /* e1000 first (preferred when both are present). */
    if (e1000_init() == 0) {
        drv_mac     = e1000_mac;
        drv_send    = e1000_send;
        drv_receive = e1000_receive;
        drv_name    = "e1000";
        return 0;
    }
    /* Otherwise the RTL8139, if present. */
    if (rtl8139_init() == 0) {
        drv_mac     = rtl8139_mac;
        drv_send    = rtl8139_send;
        drv_receive = rtl8139_receive;
        drv_name    = "rtl8139";
        return 0;
    }
    /* Otherwise the paravirtual virtio-net NIC, if present. */
    if (virtio_net_init() == 0) {
        drv_mac     = virtio_net_get_mac;
        drv_send    = virtio_net_send;
        drv_receive = virtio_net_poll_receive;
        drv_name    = "virtio-net";
        return 0;
    }
    return -1;                /* no supported NIC on the bus */
}

const char *nic_name(void) { return drv_name; }

static const uint8_t zero_mac[6] = {0};
const uint8_t *nic_mac(void) {
    return drv_mac ? drv_mac() : zero_mac;
}

/* 0 = the frame was handled (sent, or deliberately dropped by the firewall),
 * -1 = it was not. THE TWO ZEROES ARE NOT THE SAME THING (M2125): a firewall
 * drop reports success on purpose -- a filter that announced itself to every
 * caller would not be a filter -- but a caller then waits for a reply to a
 * datagram that never left, and nothing anywhere counted how often that
 * happened. It is counted now. (And e1000_send's 0 means SENT, which is worth
 * saying out loud: reading this function as "nonzero is good" is wrong, and I
 * misread it that way while instrumenting the UDP path.) */
static uint64_t g_fw_out_drops;
uint64_t nic_fw_out_drops(void) { return g_fw_out_drops; }

/* ONE CARD, MANY CORES (M2127). Both of these functions walk driver-owned ring
 * indices: e1000_send advances a TX tail, and e1000_receive pops a software RX
 * queue whose tail it is the sole owner of -- "sole" being an assumption that
 * held only while exactly one loop in the kernel ever polled. It is no longer
 * true. A Linux guest with several sockets polls from several threads, the
 * background RX service added alongside this polls too, and any two of them can
 * be on different cores at the same instant; two consumers popping one tail
 * hand the same 1600-byte buffer to both and then advance it twice, losing a
 * frame and duplicating another. This is the same shared-hardware-state class
 * as the CMOS and PCI config races (M1913-M1916), in the one device where the
 * symptom would look like packet loss on the network rather than a bug.
 *
 * TX and RX get separate locks: the rings are independent, so one lock would be
 * pure false contention, and neither is ever taken while holding the other --
 * the ARP answer in net.c's rx_next sends AFTER nic_receive has returned. Plain
 * spinlocks, per pci.c's reasoning: no interrupt handler calls either function
 * (e1000's ISR drains the hardware ring into the software queue directly, and
 * only ever advances the head this side does not touch). */
static volatile int rx_lock, tx_lock;
static inline void take(volatile int *l) {
    while (__atomic_exchange_n(l, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
}
static inline void give(volatile int *l) { __atomic_store_n(l, 0, __ATOMIC_RELEASE); }

int nic_send(const void *frame, uint16_t len) {
    if (!fw_check(FW_OUT, frame, len)) { g_fw_out_drops++; return 0; }   /* firewall: dropped, reported as handled */
    if (!drv_send) return -1;
    take(&tx_lock);
    int r = drv_send(frame, len);
    give(&tx_lock);
    return r;
}

/* EVERY FRAME THIS HANDS OUT (M2125). The stack has no single demux point --
 * its own comments say so -- and the question "is somebody else eating the
 * frames the guest is waiting for" cannot be answered without counting them at
 * the one place they all come through. */
static uint64_t g_nic_rx_total;
uint64_t nic_rx_total(void) { return g_nic_rx_total; }

int nic_receive(void *out, uint16_t max) {
    if (!drv_receive) return 0;
    take(&rx_lock);
    int n = drv_receive(out, max);
    if (n > 0) g_nic_rx_total++;
    give(&rx_lock);
    if (n > 0 && !fw_check(FW_IN, out, n)) return 0;   /* firewall: drop -> "no packet" */
    return n;
}
