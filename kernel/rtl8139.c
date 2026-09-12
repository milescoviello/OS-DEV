/*
 * rtl8139.c — driver for the Realtek RTL8139 ("8139too") 10/100 PCI NIC.
 *
 * The RTL8139 is the textbook NIC: cheap, ubiquitous, and DMA-driven but far
 * simpler than the e1000. Where the e1000 hands the card two rings of
 * descriptors, the 8139 has just two DMA regions:
 *
 *   - RECEIVE: one big circular buffer (RBSTART). The card DMAs every accepted
 *     frame into it back-to-back, each prefixed with a 4-byte header
 *     (rx-status + length), and tracks how far it has written via a register we
 *     read; we track how far we've consumed via CAPR. It's a classic ring.
 *   - TRANSMIT: four fixed slots (TSAD0..3 / TSD0..3). To send, copy the frame
 *     to a slot's buffer, write its physical address + length, and the card
 *     DMAs it onto the wire and sets an OWN/TOK bit when done. We round-robin
 *     the four slots.
 *
 * Control registers live in PCI BAR0 (an I/O-port region — the 8139's classic
 * access path) so we poke them with in/out, not MMIO. The DMA buffers are plain
 * PMM frames whose physical addresses we hand the card; on this identity-mapped
 * kernel a physical frame address doubles as a usable virtual pointer (exactly
 * how e1000.c reaches its descriptor rings), so no separate mapping is needed.
 *
 * Like e1000.c this is poll-driven: the stack calls rtl8139_receive() in a loop
 * rather than taking an interrupt. We still program IMR/ISR per the datasheet
 * bring-up and clear ISR as we drain, but the RX path is the BUFE/CAPR ring walk
 * the receive() poll performs, not an IRQ handler — a true drop-in for the
 * poll-based net.c stack the e1000 already plugs into.
 */
#include "rtl8139.h"
#include "pci.h"
#include "pmm.h"
#include "vmm.h"   /* hhdm(): CPU access to DMA memory (M1970) */
#include "io.h"
#include "string.h"

/* --- register offsets (from BAR0, the I/O-port base) --- */
#define REG_IDR0    0x00        /* MAC address, 6 bytes IDR0..IDR5            */
#define REG_TSD0    0x10        /* Transmit Status of descriptor 0 (4 regs)   */
#define REG_TSAD0   0x20        /* Transmit Start Address of descriptor 0     */
#define REG_RBSTART 0x30        /* Receive Buffer Start (physical addr)       */
#define REG_CR      0x37        /* Command Register (8 bit)                   */
#define REG_CAPR    0x38        /* Current Address of Packet Read (16 bit)    */
#define REG_CBR     0x3A        /* Current Buffer Address — card's write ptr  */
#define REG_IMR     0x3C        /* Interrupt Mask Register (16 bit)           */
#define REG_ISR     0x3E        /* Interrupt Status Register (16 bit)         */
#define REG_TCR     0x40        /* Transmit Configuration Register (32 bit)   */
#define REG_RCR     0x44        /* Receive Configuration Register (32 bit)    */
#define REG_CONFIG1 0x52        /* Config register 1 (power management)       */

/* Command Register bits */
#define CR_BUFE     (1 << 0)    /* RX buffer empty (RO): set => nothing to read*/
#define CR_TE       (1 << 2)    /* transmitter enable                         */
#define CR_RE       (1 << 3)    /* receiver enable                            */
#define CR_RST      (1 << 4)    /* software reset (self-clears when done)     */

/* Interrupt (ISR/IMR) bits */
#define INT_ROK     (1 << 0)    /* receive OK                                 */
#define INT_RER     (1 << 1)    /* receive error                              */
#define INT_TOK     (1 << 2)    /* transmit OK                                */
#define INT_TER     (1 << 3)    /* transmit error                            */

/* Receive Configuration */
#define RCR_AAP     (1 << 0)    /* accept all (promiscuous) — left off        */
#define RCR_APM     (1 << 1)    /* accept physical match (our MAC)            */
#define RCR_AM      (1 << 2)    /* accept multicast                           */
#define RCR_AB      (1 << 3)    /* accept broadcast                           */
#define RCR_WRAP    (1 << 7)    /* don't wrap mid-packet (overrun the buffer) */
/* RBLEN bits 11:12 select the RX buffer size: 00=8K+16, 01=16K+16, ... */
#define RCR_RBLEN_8K (0 << 11)

/* Transmit Status (TSD) bits */
#define TSD_OWN     (1 << 13)   /* set by us=ready/owned-by-NIC; clears at done*/
#define TSD_TOK     (1 << 15)   /* transmit OK (descriptor sent)              */

/* The card never wraps a packet across the end of the RX buffer when WRAP is
 * set; instead it can write up to 1500 (+ header/CRC) bytes PAST the nominal
 * end, so the allocation is 8K + 16 (header slack) + 1500, per the datasheet. */
#define RX_BUF_SIZE   8192
#define RX_BUF_PAD    16
#define RX_BUF_WRAP   1500
#define RX_BUF_TOTAL  (RX_BUF_SIZE + RX_BUF_PAD + RX_BUF_WRAP)

#define TX_COUNT      4         /* the chip has exactly four TX descriptors    */
#define TX_BUF_SIZE   2048      /* one Ethernet frame fits comfortably         */

static uint16_t iobase;                  /* BAR0 I/O port base                 */
static uint8_t  mac[6];

static uint8_t *rx_buf;                  /* RX ring (identity-mapped phys frame)*/
static uint64_t rx_buf_phys;
static uint16_t rx_off;                  /* our read offset into the ring       */

static uint8_t *tx_buf[TX_COUNT];        /* one DMA buffer per TX descriptor    */
static uint64_t tx_buf_phys[TX_COUNT];
static uint32_t tx_cur;                  /* next descriptor to use (round-robin)*/

/* register access (BAR0 is I/O-port space) */
static inline void  io_write8 (uint16_t off, uint8_t  v) { outb(iobase + off, v); }
static inline void  io_write16(uint16_t off, uint16_t v) { outw(iobase + off, v); }
static inline void  io_write32(uint16_t off, uint32_t v) { outl(iobase + off, v); }
static inline uint8_t  io_read8 (uint16_t off) { return inb(iobase + off); }
static inline uint16_t io_read16(uint16_t off) { return inw(iobase + off); }
static inline uint32_t io_read32(uint16_t off) { return inl(iobase + off); }

const uint8_t *rtl8139_mac(void) { return mac; }

int rtl8139_init(void) {
    pci_device_t dev = pci_find(0x10EC, 0x8139);
    if (!dev.valid)
        return -1;

    /* The RTL8139 is a DMA bus master; without this it can't write the RX ring
     * or read TX buffers. Also enables I/O+memory space decoding. */
    pci_enable_bus_master(&dev);

    /* BAR0 is the I/O-port register window (bit 0 set). pci_bar() masks the
     * flag bits off for us; the 8139 only needs 256 ports here. */
    iobase = (uint16_t)pci_bar(&dev, 0);

    /* Power on: clear CONFIG1 (LWAKE + drivers). On a freshly reset chip this is
     * a no-op, but a card left in a low-power state needs it before it responds. */
    io_write8(REG_CONFIG1, 0x00);

    /* Software reset: set RST and spin until the chip clears it (reset done). */
    io_write8(REG_CR, CR_RST);
    for (int spin = 0; spin < 1000000; spin++)
        if (!(io_read8(REG_CR) & CR_RST))
            break;

    /* MAC address from IDR0..IDR5 (readable straight after reset). */
    for (int i = 0; i < 6; i++)
        mac[i] = io_read8(REG_IDR0 + i);

    /* RX ring: one physically-contiguous region the card DMAs into. The total
     * must cover the 8K window + header pad + a max frame of WRAP slack. A 4 KB
     * PMM frame is too small, so grab enough contiguous frames. On this kernel
     * the PMM hands out frames sequentially from a bump pointer, so a run of
     * pmm_alloc_frame() calls is physically contiguous; verify and use the first
     * frame's physical address as the ring base. */
    int rx_frames = (RX_BUF_TOTAL + PAGE_SIZE - 1) / PAGE_SIZE;
    rx_buf_phys = pmm_alloc_frame();
    if (!rx_buf_phys)
        return -1;
    uint64_t expect = rx_buf_phys + PAGE_SIZE;
    for (int i = 1; i < rx_frames; i++) {
        uint64_t f = pmm_alloc_frame();
        if (f != expect)                 /* non-contiguous: can't use as one ring */
            return -1;
        expect = f + PAGE_SIZE;
    }
    rx_buf = (uint8_t *)hhdm(rx_buf_phys);
    memset(rx_buf, 0, RX_BUF_TOTAL);
    /* RBSTART is a 32-bit register: the ring's physical address must fit in
     * 32 bits (it does — low RAM under this kernel's identity map). */
    io_write32(REG_RBSTART, (uint32_t)rx_buf_phys);
    rx_off = 0;

    /* TX buffers: one contiguous DMA buffer per descriptor. */
    for (int i = 0; i < TX_COUNT; i++) {
        tx_buf_phys[i] = pmm_alloc_frame();
        if (!tx_buf_phys[i])
            return -1;
        tx_buf[i] = (uint8_t *)hhdm(tx_buf_phys[i]);
    }
    tx_cur = 0;

    /* Enable the interrupts we care about, then clear any stale status. We poll
     * rather than take the IRQ, but programming IMR/ISR is part of the datasheet
     * bring-up and keeps the chip's status bits meaningful for the poll loop. */
    io_write16(REG_IMR, INT_ROK | INT_TOK | INT_RER | INT_TER);
    io_write16(REG_ISR, 0xFFFF);

    /* Receive config: accept broadcast + frames addressed to our MAC, set WRAP
     * (so a packet near the end isn't split — the card writes into the slack
     * past the 8K mark instead), and select the 8K buffer length. */
    io_write32(REG_RCR, RCR_APM | RCR_AB | RCR_WRAP | RCR_RBLEN_8K);

    /* Enable the receiver and transmitter. (Datasheet: set RE/TE last.) */
    io_write8(REG_CR, CR_RE | CR_TE);

    return 0;
}

int rtl8139_send(const void *frame, uint16_t len) {
    if (len > TX_BUF_SIZE)
        return -1;
    /* The 8139 won't transmit a runt; pad short frames to the 60-byte Ethernet
     * minimum (the chip appends the 4-byte CRC, making 64 on the wire). */
    uint16_t txlen = len;
    if (txlen < 60) txlen = 60;

    uint32_t i = tx_cur;
    memcpy(tx_buf[i], frame, len);
    if (txlen > len)
        memset(tx_buf[i] + len, 0, txlen - len);

    /* Point the descriptor at the buffer's physical address, then write the
     * length into TSD — the length field doubles as the "start" trigger, and
     * writing it (with OWN clear) hands the buffer to the card to DMA out. */
    io_write32(REG_TSAD0 + i * 4, (uint32_t)tx_buf_phys[i]);
    io_write32(REG_TSD0  + i * 4, txlen);    /* OWN(bit13) left 0 => start */

    tx_cur = (i + 1) % TX_COUNT;

    /* Wait for the card to mark this descriptor transmitted (TOK). */
    for (int spin = 0; spin < 1000000; spin++)
        if (io_read32(REG_TSD0 + i * 4) & TSD_TOK)
            return 0;
    return -1;
}

int rtl8139_receive(void *out, uint16_t max) {
    /* BUFE set => the RX ring is empty, nothing to hand up. */
    if (io_read8(REG_CR) & CR_BUFE)
        return 0;

    /* Acknowledge the receive interrupt status bits (we polled them). Leaving
     * ROK latched is harmless under polling, but clearing keeps ISR honest. */
    uint16_t isr = io_read16(REG_ISR);
    if (isr & (INT_ROK | INT_RER))
        io_write16(REG_ISR, INT_ROK | INT_RER);

    /* Each packet in the ring is: [u16 rx-status][u16 length][frame bytes...].
     * `length` includes the 4-byte Ethernet CRC the card kept. */
    uint8_t  *p      = rx_buf + rx_off;
    uint16_t  status = (uint16_t)(p[0] | (p[1] << 8));
    uint16_t  length = (uint16_t)(p[2] | (p[3] << 8));

    /* A length of 0/0xFFF0 means the card is mid-DMA on this slot; treat the
     * ring as empty for now (the next poll will see the finished packet). A bad
     * status bit (ROK clear) means a runt/error frame — skip it but still
     * advance so the ring drains. */
    if (length == 0 || length == 0xFFF0)
        return 0;

    uint16_t framelen = 0;
    if ((status & 0x01) && length >= 4) {        /* bit0 = ROK (good frame) */
        framelen = length - 4;                    /* strip the CRC */
        if (framelen > max)
            framelen = max;
        /* WRAP is set, so the card never split this frame across the buffer end
         * — the bytes are contiguous starting at p+4, even past the 8K mark. */
        memcpy(out, p + 4, framelen);
    }

    /* Advance to the next packet: skip the 4-byte header + the frame, then round
     * UP to the next 4-byte (dword) boundary, and wrap modulo the 8K window. */
    rx_off = (uint16_t)((rx_off + length + 4 + 3) & ~3u);
    rx_off %= RX_BUF_SIZE;

    /* Tell the card how far we've consumed. The hardware quirk: CAPR reads/writes
     * are offset by 0x10 (16 bytes) from the real ring offset, so write
     * (offset - 0x10). The 16-bit wrap of (rx_off - 16) is exactly what the chip
     * expects (e.g. rx_off==0 -> 0xFFF0). */
    io_write16(REG_CAPR, (uint16_t)(rx_off - 0x10));

    return framelen;
}
