/*
 * e1000.c — driver for the Intel 82540EM ("e1000") network card.
 *
 * A modern NIC isn't driven by poking bytes one at a time; it uses **DMA**. We
 * hand it two rings of "descriptors" in RAM — one for receive, one for transmit
 * — where each descriptor points at a packet buffer. To send, we fill a TX
 * descriptor and bump the tail pointer; the card DMAs the buffer onto the wire
 * and sets a "done" bit. To receive, the card DMAs incoming frames into RX
 * buffers and sets their done bits, which we poll.
 *
 * The card's control registers are memory-mapped (PCI BAR0); the descriptor
 * rings and buffers are plain RAM frames from the PMM (their physical addresses
 * double as virtual ones via the identity map, which is what the card's DMA
 * engine needs).
 */
#include "e1000.h"
#include "pci.h"
#include "pmm.h"
#include "vmm.h"
#include "string.h"
#include "interrupts.h"   /* irq_install_handler — interrupt-driven RX (M1858) */
#include "console.h"

/* register offsets */
#define REG_CTRL   0x0000
#define REG_EERD   0x0014
#define REG_ICR    0x00C0
#define REG_IMS    0x00D0    /* Interrupt Mask Set (enable causes) */
#define REG_IMC    0x00D8
#define ICR_RXT0   (1u << 7) /* receiver timer (a packet arrived) */
#define ICR_RXDMT0 (1u << 4) /* RX descriptor min threshold */
#define REG_RCTL   0x0100
#define REG_TCTL   0x0400
#define REG_TIPG   0x0410
#define REG_RDBAL  0x2800
#define REG_RDBAH  0x2804
#define REG_RDLEN  0x2808
#define REG_RDH    0x2810
#define REG_RDT    0x2818
#define REG_TDBAL  0x3800
#define REG_TDBAH  0x3804
#define REG_TDLEN  0x3808
#define REG_TDH    0x3810
#define REG_TDT    0x3818
#define REG_RAL0   0x5400
#define REG_RAH0   0x5404
#define REG_MTA    0x5200

#define CTRL_SLU   (1 << 6)    /* Set Link Up — the e1000e/I217/I218 need it */
#define CTRL_RST   (1u << 26)  /* device software reset (recover from firmware/PXE-left state) */
#define REG_STATUS 0x0008
#define STATUS_LU  (1 << 1)    /* link up */

#define RCTL_EN    (1 << 1)
#define RCTL_BAM   (1 << 15)   /* accept broadcast */
#define RCTL_SECRC (1 << 26)   /* strip ethernet CRC */

#define TCTL_EN    (1 << 1)
#define TCTL_PSP   (1 << 3)    /* pad short packets */

#define TXCMD_EOP  (1 << 0)
#define TXCMD_IFCS (1 << 1)
#define TXCMD_RS   (1 << 3)
#define TXSTAT_DD  (1 << 0)
#define RXSTAT_DD  (1 << 0)

/* A deeper RX ring absorbs fast bursts (e.g. a CDN sending a dozen back-to-back
 * full-size segments) before the poll loop drains them — fewer descriptor
 * overflows means fewer dropped segments for the TCP layer's out-of-order
 * reassembly to recover. 64 descriptors fit one 4 KB frame (64*16 = 1024 B, and
 * RDLEN stays 128-byte aligned); each needs a 4 KB receive buffer (+128 KB). */
#define RX_COUNT   64
#define TX_COUNT   8
#define BUF_SIZE   2048

struct rx_desc {
    volatile uint64_t addr;
    volatile uint16_t length;
    volatile uint16_t checksum;
    volatile uint8_t  status;
    volatile uint8_t  errors;
    volatile uint16_t special;
} __attribute__((packed));

struct tx_desc {
    volatile uint64_t addr;
    volatile uint16_t length;
    volatile uint8_t  cso;
    volatile uint8_t  cmd;
    volatile uint8_t  status;
    volatile uint8_t  css;
    volatile uint16_t special;
} __attribute__((packed));

static volatile uint8_t *mmio;
static uint8_t  mac[6];

/* DMA memory has TWO addresses (M1970).
 *
 * The device is given the PHYSICAL address; the CPU must reach the same bytes
 * through a virtual one. Those used to be identical -- the low 1 GiB was
 * identity-mapped -- so a PMM frame could be cast straight to a pointer. Since
 * M1969 the low 1 GiB belongs to the PROCESS, not the kernel, and that cast
 * dereferences whatever the current user program has mapped there instead:
 *
 *   KERNEL PANIC: Page Fault, CR2=0x04c74000
 *     memcpy <- arp_resolve <- net_udp_send <- app_sendto
 *
 * -- a DNS query from a Linux binary, writing an ARP frame into a buffer that
 * exists only in the kernel's own address space. The frames are unchanged; the
 * CPU-side accesses go through hhdm(), which is mapped in every address space. */
static uint64_t rx_ring_phys, tx_ring_phys;
static struct rx_desc *rx_ring;        /* hhdm(rx_ring_phys) */
static struct tx_desc *tx_ring;        /* hhdm(tx_ring_phys) */
static uint64_t rx_buf[RX_COUNT];      /* PHYSICAL: handed to the device */
static uint64_t tx_buf[TX_COUNT];      /* PHYSICAL: handed to the device */
static uint32_t rx_cur, tx_cur;

static uint32_t reg_read(uint32_t off)            { return *(volatile uint32_t *)(mmio + off); }
static void     reg_write(uint32_t off, uint32_t v){ *(volatile uint32_t *)(mmio + off) = v; }

static uint16_t eeprom_read(uint8_t addr) {
    reg_write(REG_EERD, ((uint32_t)addr << 8) | 1);
    uint32_t v = 0;
    /* BOUNDED wait (M1876): the e1000e/I217/I218 EERD interface differs from the
     * classic 82540's, so the DONE bit may never set — an unbounded loop would
     * hang boot. We only reach here as a fallback anyway (MAC normally comes from
     * the firmware-loaded RAL0/RAH0 below). */
    for (int i = 0; i < 1000000; i++) { v = reg_read(REG_EERD); if (v & (1 << 4)) break; }
    return (v >> 16) & 0xFFFF;
}

const uint8_t *e1000_mac(void) { return mac; }

/* Interrupt-driven RX (M1858): the card raises its PCI IRQ when a packet arrives,
 * which wakes net.c's receive wait from hlt (instead of tight-spinning). The
 * handler's real job is to READ ICR — that clears the cause, which is what stops
 * the level-triggered PCI line re-firing into a storm. The RX ring itself is
 * still drained by the existing e1000_receive() poll, so this is purely a
 * "wake the sleeper" signal + a safe fallback (a missed IRQ just means the net
 * loop falls back to its timer-tick wakeups). */
static volatile uint64_t g_e1000_irqs;
uint64_t e1000_irq_count(void) { return g_e1000_irqs; }
static void e1000_isr(struct registers *r) {
    (void)r;
    uint32_t cause = reg_read(REG_ICR);              /* read = ack/clear the causes (no storm) */
    if (cause) g_e1000_irqs++;                        /* 0 => not our (shared) IRQ */
}

/* Intel Gigabit controllers this driver supports. 0x100E is the classic 82540EM
 * (QEMU's default e1000). The rest are e1000e-family: 0x10D3 = 82574L (QEMU's
 * `e1000e`), then the I217/I218 PCH LOMs on Haswell/Broadwell laptops (0x153A/
 * 0x153B = I217-LM/V, 0x1559/0x155A = I218-V/LM — e.g. the Dell Latitude 3340)
 * and common I219 variants. Their RX/TX register interface matches the classic
 * e1000; the differences handled below are the MAC source (firmware-loaded
 * RAL0/RAH0, not the 82540 EEPROM) and setting the link up. (M1876) */
static const uint16_t SUPPORTED_IDS[] = {
    0x100E,                                     /* 82540EM (QEMU e1000)  */
    0x10D3,                                     /* 82574L  (QEMU e1000e) */
    0x153A, 0x153B,                             /* I217-LM / I217-V      */
    0x1559, 0x155A,                             /* I218-V  / I218-LM     */
    0x15B7, 0x15B8, 0x15D7, 0x15D8, 0x15E3,     /* I219 variants         */
};

int e1000_init(void) {
    pci_device_t dev = { 0 };
    for (unsigned k = 0; k < sizeof SUPPORTED_IDS / sizeof SUPPORTED_IDS[0]; k++) {
        dev = pci_find(0x8086, SUPPORTED_IDS[k]);
        if (dev.valid) break;
    }
    if (!dev.valid)
        return -1;
    pci_enable_bus_master(&dev);

    /* Map the register block (BAR0) as cache-disabled MMIO. */
    uint64_t bar0 = pci_bar(&dev, 0);
    for (uint64_t off = 0; off < 0x20000; off += PAGE_SIZE)
        vmm_map(bar0 + off, bar0 + off, PTE_WRITABLE | PTE_PCD);
    mmio = (volatile uint8_t *)(uintptr_t)bar0;

    reg_write(REG_IMC, 0xFFFFFFFF);    /* mask all NIC interrupts; we poll */

    /* NOTE (M1883): a CTRL.RST software reset here (to recover the I218 after the
     * UEFI PXE stack drove it) HUNG the real Latitude — a bare MAC reset wedges the
     * I218's PCH PHY. Reverted. Proper e1000e PHY re-init after PXE is a bigger,
     * hardware-only effort; without it a PXE boot leaves the I218 on the static IP
     * (netcon unreachable), but a USB boot — where firmware only POST-inits the NIC
     * — works fully. So this driver stays reset-free (works on QEMU + USB boot). */

    /* Set the link up (SLU) — the e1000e/I217/I218 need it; harmless on the 82540. */
    reg_write(REG_CTRL, reg_read(REG_CTRL) | CTRL_SLU);

    /* MAC address: prefer the receive-address filter RAL0/RAH0, which the firmware
     * pre-loads on every card here (and is the only reliable source on the I217/
     * I218 — their EEPROM interface differs from the 82540's). Fall back to the
     * classic EEPROM only if RAH0's Address-Valid bit isn't set. (M1876) */
    uint32_t ral = reg_read(REG_RAL0), rah = reg_read(REG_RAH0);
    if ((rah & (1u << 31)) && (ral || (rah & 0xFFFF))) {
        mac[0] = ral; mac[1] = ral >> 8; mac[2] = ral >> 16; mac[3] = ral >> 24;
        mac[4] = rah; mac[5] = rah >> 8;
    } else {
        uint16_t w0 = eeprom_read(0), w1 = eeprom_read(1), w2 = eeprom_read(2);
        mac[0] = w0; mac[1] = w0 >> 8;
        mac[2] = w1; mac[3] = w1 >> 8;
        mac[4] = w2; mac[5] = w2 >> 8;
    }

    /* Program the receive-address filter so unicast to us is accepted. */
    reg_write(REG_RAL0, (uint32_t)(mac[0] | mac[1] << 8 | mac[2] << 16 | (uint32_t)mac[3] << 24));
    reg_write(REG_RAH0, (uint32_t)(mac[4] | mac[5] << 8) | (1u << 31));   /* AV = valid */
    for (int i = 0; i < 128; i++)
        reg_write(REG_MTA + i * 4, 0);

    /* RX ring + buffers. */
    rx_ring_phys = pmm_alloc_frame();
    rx_ring = (struct rx_desc *)hhdm(rx_ring_phys);
    memset(rx_ring, 0, RX_COUNT * sizeof(struct rx_desc));
    for (int i = 0; i < RX_COUNT; i++) {
        rx_buf[i] = pmm_alloc_frame();
        rx_ring[i].addr = rx_buf[i];
        rx_ring[i].status = 0;
    }
    reg_write(REG_RDBAL, (uint32_t)rx_ring_phys);                /* the DEVICE gets the physical address */
    reg_write(REG_RDBAH, (uint32_t)(rx_ring_phys >> 32));
    reg_write(REG_RDLEN, RX_COUNT * sizeof(struct rx_desc));
    reg_write(REG_RDH, 0);
    reg_write(REG_RDT, RX_COUNT - 1);
    reg_write(REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_SECRC);
    rx_cur = 0;

    /* TX ring + buffers. */
    tx_ring_phys = pmm_alloc_frame();
    tx_ring = (struct tx_desc *)hhdm(tx_ring_phys);
    memset(tx_ring, 0, TX_COUNT * sizeof(struct tx_desc));
    for (int i = 0; i < TX_COUNT; i++) {
        tx_buf[i] = pmm_alloc_frame();
        tx_ring[i].status = TXSTAT_DD;   /* mark free */
    }
    reg_write(REG_TDBAL, (uint32_t)tx_ring_phys);                /* the DEVICE gets the physical address */
    reg_write(REG_TDBAH, (uint32_t)(tx_ring_phys >> 32));
    reg_write(REG_TDLEN, TX_COUNT * sizeof(struct tx_desc));
    reg_write(REG_TDH, 0);
    reg_write(REG_TDT, 0);
    reg_write(REG_TIPG, 0x0060200A);
    reg_write(REG_TCTL, TCTL_EN | TCTL_PSP | (0x0F << 4) | (0x40 << 12));
    tx_cur = 0;

    /* Interrupt-driven RX (M1858): install the ISR on the card's PCI IRQ line
     * and enable ONLY the RX causes. reg_read(REG_ICR) once clears any stale
     * cause before we unmask.
     *
     * M1890: deliver it through the I/O APIC when one is present. This uses the
     * PCI routing variant, not the ISA one — PCI INTx is LEVEL-triggered and
     * ACTIVE-LOW, and a redirection entry left at the ISA default (edge,
     * active-high) on a level/low line either never fires or latches on. Falls
     * back to the 8259 PIC when there is no I/O APIC. */
    uint8_t irq = pci_irq_line(&dev);
    if (irq < 16) {
        (void)reg_read(REG_ICR);
        irq_install_handler(irq, e1000_isr);         /* also pic_unmask(irq) */
        irq_route_ioapic_pci(irq);                   /* no-op without an I/O APIC */
        reg_write(REG_IMS, ICR_RXT0 | ICR_RXDMT0);   /* raise IRQ when a packet is received */
        kprintf("[ ok ] e1000: interrupt-driven RX enabled (IRQ %u, %s) — net waits now sleep, not spin (M1858).\n",
                irq, irq_is_ioapic_routed(irq) ? "I/O APIC, level/active-low" : "8259 PIC");
    }
    return 0;
}

int e1000_send(const void *frame, uint16_t len) {
    if (len > BUF_SIZE) return -1;      /* every tx_buf[] slot is one BUF_SIZE-capacity buffer -- no caller needs more today, but nothing stopped a future one overrunning it */
    uint32_t i = tx_cur;
    memcpy(hhdm(tx_buf[i]), frame, len);                          /* CPU side: through the HHDM */
    tx_ring[i].addr = tx_buf[i];
    tx_ring[i].length = len;
    tx_ring[i].cmd = TXCMD_EOP | TXCMD_IFCS | TXCMD_RS;
    tx_ring[i].status = 0;

    tx_cur = (i + 1) % TX_COUNT;
    reg_write(REG_TDT, tx_cur);

    /* wait for the card to mark the descriptor done */
    for (int spin = 0; spin < 1000000; spin++)
        if (tx_ring[i].status & TXSTAT_DD)
            return 0;
    return -1;
}

int e1000_receive(void *out, uint16_t max) {
    uint32_t i = rx_cur;
    if (!(rx_ring[i].status & RXSTAT_DD))
        return 0;                       /* nothing received */

    uint16_t len = rx_ring[i].length;
    if (len > max) len = max;
    memcpy(out, hhdm(rx_buf[i]), len);                            /* CPU side: through the HHDM (M1970) */

    rx_ring[i].status = 0;
    reg_write(REG_RDT, i);              /* return the buffer to the card */
    rx_cur = (i + 1) % RX_COUNT;
    return len;
}
