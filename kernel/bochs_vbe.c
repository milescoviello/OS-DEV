/*
 * bochs_vbe.c — Bochs/QEMU VBE (DISPI) display driver.
 *
 * QEMU's std-VGA / bochs-display (PCI 1234:1111) exposes the "Bochs DISPI"
 * register interface through two I/O ports — an index port (0x01CE) and a data
 * port (0x01CF). Writing an index then a value to those ports lets the OS set
 * its own video mode: a width, a height, a bit depth, and a "virtual width"
 * (the pitch, in pixels). After enabling the mode with the LFB bit on, the
 * card's linear framebuffer (every pixel as 0x00RRGGBB at 32 bpp) is mapped at
 * the VGA's PCI BAR0.
 *
 * This is the one place that touches the DISPI hardware. fb.c does the actual
 * drawing; once we've set the mode and found the LFB we hand fb.c the new base
 * address and dimensions via fb_repoint(), so every existing draw primitive and
 * the whole desktop come up at the new resolution with no other changes.
 *
 * SAFETY: the display is boot-critical. set_mode validates w/h and that the LFB
 * BAR is large enough BEFORE touching the live framebuffer pointer, and returns
 * -1 (leaving the current mode untouched) if anything is wrong — never a black
 * screen. If the DISPI interface is absent entirely (a config without std-VGA),
 * bochs_vbe_available() returns 0 and callers keep the existing mode.
 */
#include "bochs_vbe.h"
#include "fb.h"
#include "pci.h"
#include "io.h"

/* DISPI register access ports. */
#define VBE_DISPI_IOPORT_INDEX  0x01CE
#define VBE_DISPI_IOPORT_DATA   0x01CF

/* DISPI register indices. */
#define VBE_DISPI_INDEX_ID          0x0
#define VBE_DISPI_INDEX_XRES        0x1
#define VBE_DISPI_INDEX_YRES        0x2
#define VBE_DISPI_INDEX_BPP         0x3
#define VBE_DISPI_INDEX_ENABLE      0x4
#define VBE_DISPI_INDEX_VIRT_WIDTH  0x6

/* DISPI_INDEX_ID values: the interface reports its version here. Anything
 * >= 0xB0C0 ("BOCHS") means a usable DISPI is present (QEMU reports 0xB0C5). */
#define VBE_DISPI_ID0           0xB0C0

/* ENABLE register bits. */
#define VBE_DISPI_DISABLED      0x00
#define VBE_DISPI_ENABLED       0x01   /* bit0: mode enabled */
#define VBE_DISPI_LFB_ENABLED   0x40   /* bit6: linear framebuffer (vs. banked) */

#define VBE_DISPI_BPP_32        32

/* Sanity ceiling: refuse absurd requests. 1920x1200x4 = ~9.2 MB, well within
 * QEMU's default 16 MB of VGA memory; anything bigger we reject outright. */
/* 1920x1200 -> 2560x1440 (M2367): the cap was below the 1440p the browser is
 * required to be measured at, so the DISPI fallback path could not have
 * reached it even when the loader could. The BAR-size check below is the real
 * guard -- it refuses a mode the video memory cannot hold. */
#define VBE_MAX_W  2560
#define VBE_MAX_H  1440

static void vbe_write(uint16_t index, uint16_t value) {
    outw(VBE_DISPI_IOPORT_INDEX, index);
    outw(VBE_DISPI_IOPORT_DATA, value);
}

static uint16_t vbe_read(uint16_t index) {
    outw(VBE_DISPI_IOPORT_INDEX, index);
    return inw(VBE_DISPI_IOPORT_DATA);
}

int bochs_vbe_available(void) {
    /* Two independent signals, both must hold: the DISPI ID register reports a
     * Bochs-class interface, AND the QEMU std-VGA PCI device is on the bus
     * (its BAR0 is where the LFB will live). Requiring both avoids a false
     * positive from a stray I/O-port read on hardware that lacks the device. */
    uint16_t id = vbe_read(VBE_DISPI_INDEX_ID);
    if (id < VBE_DISPI_ID0)
        return 0;
    pci_device_t vga = pci_find(0x1234, 0x1111);
    return vga.valid ? 1 : 0;
}

/* Probe a 32-bit memory BAR's size via the standard PCI trick: save it, write
 * all-ones, read back, restore. The size is (~(readback & ~0xF)) + 1. Returns 0
 * if the BAR looks like I/O space or reads back empty. */
static uint64_t pci_bar_size(const pci_device_t *d, int bar) {
    uint8_t off = 0x10 + bar * 4;
    uint32_t orig = pci_read32(d->bus, d->slot, d->func, off);
    if (orig & 1)
        return 0;                         /* I/O space BAR, not a framebuffer */
    pci_write32(d->bus, d->slot, d->func, off, 0xFFFFFFFFu);
    uint32_t probe = pci_read32(d->bus, d->slot, d->func, off);
    pci_write32(d->bus, d->slot, d->func, off, orig);   /* restore */
    probe &= ~0xFu;                        /* mask the memory-BAR flag bits */
    if (probe == 0)
        return 0;
    return (uint64_t)(~probe) + 1;
}

int bochs_vbe_set_mode(int w, int h) {
    /* Validate the request before touching any hardware. */
    if (w <= 0 || h <= 0 || w > VBE_MAX_W || h > VBE_MAX_H)
        return -1;

    pci_device_t vga = pci_find(0x1234, 0x1111);   /* QEMU std VGA */
    if (!vga.valid)
        return -1;

    /* Confirm the DISPI interface is really there before reprogramming it. */
    if (vbe_read(VBE_DISPI_INDEX_ID) < VBE_DISPI_ID0)
        return -1;

    /* The LFB lives at BAR0; make sure it can hold a w*h 32-bpp framebuffer
     * before we commit. (A 0 size means we couldn't probe it — accept it
     * rather than fail closed, since the BAR address itself is valid; QEMU's
     * default is 16 MB regardless.) */
    uint64_t base  = pci_bar(&vga, 0);
    uint64_t need  = (uint64_t)w * (uint64_t)h * 4u;
    uint64_t barsz = pci_bar_size(&vga, 0);
    if (base == 0)
        return -1;
    if (barsz != 0 && need > barsz)
        return -1;

    /* Program the mode: disable, set geometry + 32 bpp + pitch, re-enable with
     * the linear framebuffer on. VIRT_WIDTH (the pitch in pixels) is set equal
     * to XRES so the hardware stride is exactly w*4 bytes — fb.c indexes the
     * LFB as y*w + x, so the software pitch must match the hardware pitch. */
    vbe_write(VBE_DISPI_INDEX_ENABLE,     VBE_DISPI_DISABLED);
    vbe_write(VBE_DISPI_INDEX_XRES,       (uint16_t)w);
    vbe_write(VBE_DISPI_INDEX_YRES,       (uint16_t)h);
    vbe_write(VBE_DISPI_INDEX_BPP,        VBE_DISPI_BPP_32);
    vbe_write(VBE_DISPI_INDEX_VIRT_WIDTH, (uint16_t)w);
    vbe_write(VBE_DISPI_INDEX_ENABLE,     VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED);

    /* Re-point fb.c at the (possibly re-based) LFB with the new dims. fb.c maps
     * the region and updates its globals; pitch is implicit (w*4). */
    fb_repoint(base, w, h);
    return 0;
}
