/*
 * nvgpu.c — NVIDIA GPU bring-up, from scratch.
 *
 * Phase 1 of the GT 1030 campaign: find the card, describe its BARs, map the
 * register aperture, and read a value out of it that only real silicon can
 * produce. Everything after this (devinit, instmem, MMU, FIFO, ACR/secboot,
 * GR) stands on that, and none of it is worth writing until the register
 * window is known good.
 *
 * WHY PMC_BOOT_0 IS THE RIGHT FIRST READ. It is at offset 0 of BAR0, it is
 * readable with no initialisation whatsoever, and it encodes the chip id --
 * so a correct value cannot be produced by a stub, by a mis-mapped window
 * (which reads 0xFFFFFFFF or 0), or by reading the wrong device. This project
 * has shipped a hardcoded "UNDER TCG" string, a DRM version invented for
 * verisimilitude, and a DRM_CAP_PRIME that answered 0: an unfalsifiable probe
 * is worse than none.
 */
#include "nvgpu.h"
#include "pci.h"
#include "vmm.h"
#include "console.h"
#include "kheap.h"
#include <stdint.h>
#include <stddef.h>

#define NV_VENDOR       0x10DE
#define NV_PMC_BOOT_0   0x000000      /* chip id; readable before any init */

static pci_device_t  nv;
static volatile uint8_t *nv_bar0;
static uint32_t      nv_boot0;
static uint8_t      *nv_rom;
static unsigned      nv_romlen;

/* A BAR pair, 64-bit aware. Returns the base; *size gets the region length and
 * *is64 whether this BAR consumed the next slot too.
 *
 * Sizing writes all-ones and reads back the mask, so the memory decode bit is
 * cleared first: while a BAR holds 0xFFFFFFFF the device claims a colossal
 * window, and anything else probing the bus in that instant sees an address
 * space that does not exist. Restore both, always. */
static uint64_t bar_probe(const pci_device_t *d, int i, uint64_t *size, int *is64) {
    uint8_t off = (uint8_t)(0x10 + i * 4);
    uint32_t lo = pci_read32(d->bus, d->slot, d->func, off);
    *is64 = 0; *size = 0;
    if (lo == 0) return 0;
    if (lo & 1) return 0;                       /* I/O BAR: not interesting here */

    int mem64 = ((lo >> 1) & 3) == 2;
    uint32_t hi = mem64 ? pci_read32(d->bus, d->slot, d->func, (uint8_t)(off + 4)) : 0;
    uint64_t base = ((uint64_t)hi << 32) | (lo & ~0xFu);

    uint32_t cmd = pci_read32(d->bus, d->slot, d->func, 0x04);
    pci_write32(d->bus, d->slot, d->func, 0x04, cmd & ~0x2u);   /* memory decode off */

    pci_write32(d->bus, d->slot, d->func, off, 0xFFFFFFFFu);
    uint32_t mlo = pci_read32(d->bus, d->slot, d->func, off);
    uint32_t mhi = 0xFFFFFFFFu;
    if (mem64) {
        pci_write32(d->bus, d->slot, d->func, (uint8_t)(off + 4), 0xFFFFFFFFu);
        mhi = pci_read32(d->bus, d->slot, d->func, (uint8_t)(off + 4));
    }
    pci_write32(d->bus, d->slot, d->func, off, lo);             /* restore */
    if (mem64) pci_write32(d->bus, d->slot, d->func, (uint8_t)(off + 4), hi);
    pci_write32(d->bus, d->slot, d->func, 0x04, cmd);           /* decode back on */

    uint64_t mask = ((uint64_t)mhi << 32) | (mlo & ~0xFu);
    if (mask) *size = (~mask) + 1;
    *is64 = mem64;
    return base;
}

static volatile uint8_t *map_mmio(uint64_t phys, uint64_t len) {
    /* HIGHER-HALF, NOT IDENTITY. An identity-mapped BAR above 512 GiB lands in
     * a PML4 slot that vmm_create_address_space never copies, so it exists
     * only in the kernel address space and faults the instant a syscall path
     * touches it -- two boots of register-guessing were spent on exactly that
     * with virtio-gpu's doorbell. */
    if (!phys || !len) return NULL;
    uint64_t start = phys & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t end   = phys + len;
    for (uint64_t off = start; off < end; off += PAGE_SIZE)
        vmm_map((uint64_t)(uintptr_t)hhdm(off), off, PTE_WRITABLE | PTE_PCD);
    return (volatile uint8_t *)hhdm(phys);
}

static uint32_t nv_rd32(uint32_t reg) {
    return *(volatile uint32_t *)(nv_bar0 + reg);
}

/* ---------------------------------------------------------------- VBIOS --
 *
 * devinit (step 4) executes scripts that live in the card's own VBIOS, so
 * before any of that can be written the ROM has to be readable and provably
 * the right ROM. This is also the second falsifiable check on the register
 * window: PMC_BOOT_0 proves offset 0 works, the ROM proves a mapping 3 MiB
 * deep into the aperture works AND that the bytes coming back are structured
 * data rather than a pattern.
 *
 * The PROM aperture is at BAR0+0x300000. ROM shadowing has to be turned off
 * first or the read returns the shadow copy in system memory rather than the
 * card: PCI config 0x50 bit 0 is NV_PBUS_PCI_NV_20_ROM_SHADOW. Restore it
 * afterwards, unconditionally -- leaving shadowing off changes how every
 * later ROM access behaves, which is the kind of state change that shows up
 * three milestones later as something unrelated.
 */
#define NV_PROM_OFFSET  0x300000
#define NV_PROM_SIZE    0x20000

static int nvgpu_vbios(void) {
    uint32_t cfg50 = pci_read32(nv.bus, nv.slot, nv.func, 0x50);
    pci_write32(nv.bus, nv.slot, nv.func, 0x50, cfg50 & ~1u);   /* shadow OFF */

    const volatile uint8_t *rom = nv_bar0 + NV_PROM_OFFSET;
    uint8_t b0 = rom[0], b1 = rom[1];
    int ok = (b0 == 0x55 && b1 == 0xAA);
    if (!ok) {
        kprintf("[nv] VBIOS: PROM at BAR0+%x starts %02x %02x, not 55 AA -- no ROM "
                "signature. devinit cannot be written against a ROM we cannot read.\n",
                NV_PROM_OFFSET, b0, b1);
        pci_write32(nv.bus, nv.slot, nv.func, 0x50, cfg50);
        return -1;
    }
    unsigned romlen = (unsigned)rom[2] * 512;

    /* PCIR: the PCI Data Structure the ROM header points at. Its vendor and
     * DEVICE id must match the card we are talking to -- that is what makes
     * this a check rather than a hex dump. */
    unsigned pcir = (unsigned)rom[0x18] | ((unsigned)rom[0x19] << 8);
    unsigned vend = 0, devid = 0; int pcir_ok = 0;
    if (pcir && pcir + 8 < NV_PROM_SIZE &&
        rom[pcir] == 'P' && rom[pcir+1] == 'C' && rom[pcir+2] == 'I' && rom[pcir+3] == 'R') {
        vend  = (unsigned)rom[pcir+4] | ((unsigned)rom[pcir+5] << 8);
        devid = (unsigned)rom[pcir+6] | ((unsigned)rom[pcir+7] << 8);
        pcir_ok = 1;
    }
    pci_write32(nv.bus, nv.slot, nv.func, 0x50, cfg50);         /* shadow restored */

    kprintf("[nv] VBIOS: signature 55 AA, %u bytes, PCIR at %x\n", romlen, pcir);
    if (!pcir_ok) {
        kprintf("[nv] VBIOS: no PCIR structure where the header points -- the ROM is "
                "readable but not parseable; treat its contents as unknown.\n");
        return -1;
    }
    kprintf("[nv] VBIOS: PCIR says vendor %04x device %04x\n", vend, devid);
    if (vend != nv.vendor_id || devid != nv.device_id) {
        kprintf("[nv] VBIOS: ** THAT DOES NOT MATCH THE CARD (%04x:%04x). We are "
                "reading somebody else's ROM, or the aperture is misplaced. **\n",
                nv.vendor_id, nv.device_id);
        return -1;
    }
    kprintf("[nv] VBIOS: matches the card -- the ROM is ours, and BAR0 is coherent "
            "3 MiB deep, not just at offset 0.\n");

    /* Copy it into RAM once. Everything after this parses structures with
     * back-references and bounds checks, and doing that against MMIO means
     * every field read is a device access with the ROM shadow state having to
     * be right at that instant. One copy, then plain memory. */
    if (romlen == 0 || romlen > NV_PROM_SIZE) romlen = NV_PROM_SIZE;
    nv_rom = (uint8_t *)kmalloc(romlen);
    if (!nv_rom) { kprintf("[nv] VBIOS: no memory for a %u-byte copy\n", romlen); return -1; }
    cfg50 = pci_read32(nv.bus, nv.slot, nv.func, 0x50);
    pci_write32(nv.bus, nv.slot, nv.func, 0x50, cfg50 & ~1u);
    for (unsigned k = 0; k < romlen; k++) nv_rom[k] = rom[k];
    pci_write32(nv.bus, nv.slot, nv.func, 0x50, cfg50);
    nv_romlen = romlen;
    return 0;
}

/* ------------------------------------------------------------------ BIT --
 *
 * The VBIOS's table of tables. devinit's scripts hang off the 'I' entry, so
 * this is the last hop before there is something to execute.
 *
 * The header layout was determined by PARSING THE REAL ROM, not from memory:
 * a first attempt using a half-remembered field order produced 70 entries of
 * 50 bytes with random ids, which is exactly what a wrong offset looks like.
 * Ground truth for this card, checked on the host before this code was
 * written: token at 0x1e0, header_len 12, entry_size 6, 17 entries, and the
 * 'I' entry at off 0x02b3 len 34. 16 of 17 ids are ASCII letters -- that
 * ratio is the check, because a misparse destroys it immediately. */
static int nvgpu_bit(void) {
    if (!nv_rom) return -1;
    unsigned bit = 0;
    for (unsigned k = 0; k + 5 < nv_romlen; k++)
        if (nv_rom[k] == 0xFF && nv_rom[k+1] == 0xB8 &&
            nv_rom[k+2] == 'B' && nv_rom[k+3] == 'I' && nv_rom[k+4] == 'T') { bit = k; break; }
    if (!bit) { kprintf("[nv] BIT: no \\xff\\xb8BIT token in %u bytes of ROM\n", nv_romlen); return -1; }

    unsigned hlen = nv_rom[bit + 8], esz = nv_rom[bit + 9], nent = nv_rom[bit + 10];
    if (!esz || !nent || bit + hlen + nent * esz > nv_romlen) {
        kprintf("[nv] BIT: header at %x says hlen %u esz %u entries %u -- that does not "
                "fit in the ROM, so the layout is wrong, not the data.\n", bit, hlen, esz, nent);
        return -1;
    }

    unsigned letters = 0, init_off = 0, init_len = 0;
    for (unsigned e = 0; e < nent; e++) {
        const uint8_t *q = nv_rom + bit + hlen + e * esz;
        uint8_t id = q[0];
        if ((id >= 'A' && id <= 'Z') || (id >= 'a' && id <= 'z')) letters++;
        if (id == 'I') { init_len = (unsigned)q[2] | ((unsigned)q[3] << 8);
                         init_off = (unsigned)q[4] | ((unsigned)q[5] << 8); }
    }
    kprintf("[nv] BIT at %x: %u entries of %u bytes (header %u), %u/%u ids are letters\n",
            bit, nent, esz, hlen, letters, nent);
    if (letters * 2 < nent) {
        kprintf("[nv] BIT: most ids are not letters -- this is a MISPARSE, not a ROM.\n");
        return -1;
    }
    if (!init_off) { kprintf("[nv] BIT: no 'I' entry -- no devinit scripts to run.\n"); return -1; }
    kprintf("[nv] BIT: 'I' (devinit) at %x, %u bytes -- devinit has something to execute.\n",
            init_off, init_len);
    return 0;
}

int nvgpu_bit_probe(void) { return nvgpu_bit(); }

int nvgpu_present(void)   { return nv.valid; }
uint32_t nvgpu_boot0(void){ return nv_boot0; }

int nvgpu_init(void) {
    /* Any NVIDIA display device, not just the one id we expect: "no 10de:1d01"
     * and "an NVIDIA card is here but it is a different one" are different
     * facts and the log should not conflate them. */
    for (int bus = 0; bus < 256 && !nv.valid; bus++)
        for (int slot = 0; slot < 32 && !nv.valid; slot++)
            for (int func = 0; func < 8; func++) {
                uint32_t id = pci_read32((uint8_t)bus, (uint8_t)slot, (uint8_t)func, 0x00);
                if ((id & 0xFFFF) != NV_VENDOR) continue;
                uint32_t cls = pci_read32((uint8_t)bus, (uint8_t)slot, (uint8_t)func, 0x08);
                if (((cls >> 24) & 0xFF) != 0x03) continue;      /* display controller */
                nv.bus = (uint8_t)bus; nv.slot = (uint8_t)slot; nv.func = (uint8_t)func;
                nv.vendor_id = 0x10DE; nv.device_id = (uint16_t)(id >> 16);
                nv.class_id = 0x03; nv.valid = 1;
                break;
            }

    if (!nv.valid) {
        kprintf("[nv] NO NVIDIA DISPLAY DEVICE ON THE PCI BUS. If this VM was "
                "meant to have one passed through, the passthrough did not "
                "happen -- check hostpci and the IOMMU group, not this driver.\n");
        return -1;
    }
    kprintf("[nv] found NVIDIA %04x:%04x at %02x:%02x.%x\n",
            nv.vendor_id, nv.device_id, nv.bus, nv.slot, nv.func);

    uint64_t b0 = 0, b0sz = 0;
    for (int i = 0; i < 6; i++) {
        uint64_t sz; int is64;
        uint64_t base = bar_probe(&nv, i, &sz, &is64);
        if (base || sz)
            kprintf("[nv]   BAR%d %s base %lx size %lu %s\n", i, is64 ? "64-bit" : "32-bit",
                    (unsigned long)base, (unsigned long)(sz >= (1u<<20) ? sz >> 20 : sz >> 10),
                    sz >= (1u<<20) ? "MiB" : "KiB");
        if (i == 0) { b0 = base; b0sz = sz; }
        if (is64) i++;                       /* the pair consumed the next slot */
    }

    if (!b0 || !b0sz) {
        kprintf("[nv] BAR0 is not assigned -- no register window, cannot continue.\n");
        return -1;
    }
    /* Only the first 16 MiB is the register aperture; map that much. */
    uint64_t maplen = b0sz > (16u << 20) ? (16u << 20) : b0sz;
    nv_bar0 = map_mmio(b0, maplen);
    if (!nv_bar0) { kprintf("[nv] could not map BAR0\n"); return -1; }

    nv_boot0 = nv_rd32(NV_PMC_BOOT_0);
    if (nv_boot0 == 0xFFFFFFFFu || nv_boot0 == 0) {
        kprintf("[nv] PMC_BOOT_0 reads %08x -- that is the bus answering, not the "
                "chip. The BAR is mapped but the device is not responding.\n", nv_boot0);
        return -1;
    }
    /* PMC_BOOT_0: architecture in bits 24-28, implementation in 20-23, so the
     * chipset id is (val >> 20) & 0x1ff. GP108 is 0x138. */
    unsigned chipset = (nv_boot0 >> 20) & 0x1FF;
    kprintf("[nv] PMC_BOOT_0 = %08x -> chipset 0x%x, revision %02x\n",
            nv_boot0, chipset, nv_boot0 & 0xFF);
    kprintf("[nv] %s\n",
            chipset == 0x138 ? "THAT IS GP108 -- the GT 1030 is alive and answering "
                               "register reads over a higher-half BAR mapping."
                             : "An NVIDIA chip is answering, but it is not the GP108 "
                               "this campaign expects -- check which card got passed.");
    if (nvgpu_vbios() == 0) nvgpu_bit();   /* devinit's scripts live in there (M2369) */
    return 0;
}
