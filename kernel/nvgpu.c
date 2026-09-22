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

/* Forward declarations, kept together. Adding a function that uses a helper
 * defined further down has now broken this build three times; one block at
 * the top is cheaper than rediscovering the order each time. */
static uint32_t nv_reg_rd(uint32_t reg);
static void     nv_reg_wr(uint32_t reg, uint32_t val);
static unsigned nv_rd16(unsigned off);
static uint32_t nv_rom32(unsigned o);
static int      nvgpu_vbios_pramin(uint8_t *dst, unsigned len);
int             g_nv_exec;
static unsigned g_nv_skipped_vga, g_nv_skipped_i2c, g_nv_skipped_gpio;

static pci_device_t  nv;
static volatile uint8_t *nv_bar0;
static uint32_t      nv_boot0;
static unsigned      g_nv_bitM_off, g_nv_bitM_len, g_nv_bitM_ver;
static unsigned      g_nv_bit_i;     /* BIT 'I' offset, for the PMU args */
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

    /* COPY THE WHOLE APERTURE, NOT THE FIRST IMAGE (M2371).
     *
     * rom[2]*512 is the length of the FIRST PCIR image only, and an NVIDIA
     * ROM is a chain of them -- image 0 here reports `last=false`. Sizing the
     * copy that way gave 60416 bytes, and the PMU table pointer is 0xece4,
     * 228 bytes past the end: "table pointer ece4 is outside the 60416-byte
     * ROM". The bounds check caught it, which is the only reason this was a
     * one-line diagnosis instead of a parser walking uninitialised heap.
     *
     * So take the whole 128 KiB PROM window. Reads past the real ROM return
     * 0xff or 0, and every parser here bounds-checks against nv_romlen, so a
     * larger window costs a bigger buffer and nothing else. */
    romlen = NV_PROM_SIZE;
    nv_rom = (uint8_t *)kmalloc(romlen);
    if (!nv_rom) { kprintf("[nv] VBIOS: no memory for a %u-byte copy\n", romlen); return -1; }
    cfg50 = pci_read32(nv.bus, nv.slot, nv.func, 0x50);
    pci_write32(nv.bus, nv.slot, nv.func, 0x50, cfg50 & ~1u);
    /* 32-BIT READS, NOT BYTE READS (M2371). nouveau's nvbios_prom copies the
     * PROM aperture with nvkm_rd32; a byte-wise copy of an MMIO window is not
     * guaranteed to return the same data, and this one already disagreed with
     * an independent copy about byte 2 of the ROM header. Read dwords and
     * split them, which is what every other consumer of this aperture does. */
    {   volatile const uint32_t *r32 = (volatile const uint32_t *)rom;
        for (unsigned k = 0; k + 3 < romlen; k += 4) {
            uint32_t w = r32[k >> 2];
            nv_rom[k+0] = (uint8_t)w; nv_rom[k+1] = (uint8_t)(w >> 8);
            nv_rom[k+2] = (uint8_t)(w >> 16); nv_rom[k+3] = (uint8_t)(w >> 24);
        }
    }
    pci_write32(nv.bus, nv.slot, nv.func, 0x50, cfg50);
    nv_romlen = romlen;

    /* PREFER PRAMIN, AS NOUVEAU DOES. The PROM copy's BIT 'p' pointer lands
     * in the EFI image on this card; the VRAM image is the self-consistent
     * one. Only replace the PROM copy if PRAMIN actually returns a signed
     * image -- a half-read window would be worse than the PROM copy. */
    {   uint8_t *alt = (uint8_t *)kmalloc(NV_PROM_SIZE);
        if (alt) {
            if (nvgpu_vbios_pramin(alt, NV_PROM_SIZE) == 0) {
                nv_rom = alt; nv_romlen = NV_PROM_SIZE;
                kprintf("[nv] VBIOS: using the PRAMIN (VRAM) image\n");
            } else {
                kfree(alt);
                kprintf("[nv] VBIOS: falling back to the PROM image\n");
            }
        }
    }

    /* IS THE REGION ABOVE IMAGE 0 EVEN BACKED? (M2372)
     *
     * The bytes at 0xece4 are high-entropy, which reads as "encrypted
     * firmware" but reads equally well as "an unbacked MMIO window returning
     * bus noise". Those are opposite conclusions and the difference is one
     * experiment: read the same address twice. Real ROM is stable; a
     * floating bus is not. Do it at an offset inside image 0 as the control,
     * so a stable result above the image cannot be explained by the test
     * itself being broken. */
    {   volatile const uint32_t *r32 = (volatile const uint32_t *)rom;
        unsigned ctl = 0x100 >> 2, hi = 0xece4 >> 2;
        uint32_t c1 = r32[ctl], h1 = r32[hi];
        for (volatile int d = 0; d < 100000; d++) { }
        uint32_t c2 = r32[ctl], h2 = r32[hi];
        kprintf("[nv] VBIOS: reread test -- inside image 0 @100: %08x then %08x (%s); "
                "above it @ece4: %08x then %08x (%s)\n",
                c1, c2, c1 == c2 ? "stable" : "UNSTABLE",
                h1, h2, h1 == h2 ? "stable" : "UNSTABLE -- unbacked window, not data");
    }

    /* DOES THE APERTURE MIRROR? (M2371) image 0 is 60416 bytes and a second
     * "image" appears at exactly 0xec00 = 60416. That is suspicious: a PROM
     * window that wraps at the ROM size would manufacture a fake image there,
     * and would explain a BIT pointer of 0xece4 that lands on rubbish --
     * 0xece4 would really be offset 0xe4. Compare the two regions instead of
     * theorising: if they are byte-identical, the ROM is 60416 bytes and
     * everything above it is an illusion. */
    {   unsigned rl = (unsigned)nv_rom[2] * 512, same = 0, n = 0;
        if (rl && rl + 256 <= nv_romlen) {
            for (unsigned k = 0; k < 256; k++, n++) if (nv_rom[k] == nv_rom[rl + k]) same++;
            kprintf("[nv] VBIOS: first 256 bytes vs the same at %x: %u/%u identical -- %s\n",
                    rl, same, n, same == n
                    ? "THE APERTURE MIRRORS. The ROM is one image; anything above it is a wrap."
                    : "not a mirror, the region above image 0 is real data.");
        }
    }

    /* Report the real extent by walking the PCIR image chain, so "the ROM is
     * bigger than its first image" is visible rather than inferred. */
    {   unsigned img = 0, total = 0;
        for (int n = 0; n < 8 && img + 0x1a < nv_romlen; n++) {
            if (nv_rom[img] != 0x55 || nv_rom[img+1] != 0xAA) break;
            unsigned pc = img + ((unsigned)nv_rom[img+0x18] | ((unsigned)nv_rom[img+0x19] << 8));
            if (pc + 0x16 >= nv_romlen || nv_rom[pc] != 'P' || nv_rom[pc+1] != 'C' ||
                nv_rom[pc+2] != 'I' || nv_rom[pc+3] != 'R') break;
            unsigned ilen = ((unsigned)nv_rom[pc+0x10] | ((unsigned)nv_rom[pc+0x11] << 8)) * 512;
            unsigned ctype = nv_rom[pc+0x14], last = nv_rom[pc+0x15] & 0x80;
            /* NPDE OVERRIDES PCIR (nouveau's nvbios_imagen). For any image
             * that is not code type 0x70, NVIDIA puts the authoritative size
             * and last-image flag in an NPDE structure sitting just past the
             * PCIR header, 16-byte aligned. Trusting PCIR alone gets image
             * boundaries wrong, and image boundaries are how a pointer that
             * lands "past the end" is judged. */
            if (ctype != 0x70) {
                unsigned phdr = (unsigned)nv_rom[pc+0x0a] | ((unsigned)nv_rom[pc+0x0b] << 8);
                unsigned np = (pc + phdr + 0x0f) & ~0x0fu;
                if (np + 0x0b < nv_romlen && nv_rom[np] == 'N' && nv_rom[np+1] == 'P' &&
                    nv_rom[np+2] == 'D' && nv_rom[np+3] == 'E') {
                    ilen = ((unsigned)nv_rom[np+8] | ((unsigned)nv_rom[np+9] << 8)) * 512;
                    last = nv_rom[np+0x0a] & 0x80;
                }
            }
            kprintf("[nv] VBIOS: image %d @ %x, %u bytes, code type %02x%s\n",
                    n, img, ilen, ctype, last ? " (last)" : "");
            total = img + ilen;
            if (last || !ilen) break;
            img += ilen;
        }
        kprintf("[nv] VBIOS: %u bytes of images in a %u-byte window\n", total, nv_romlen);
    }
    return 0;
}


/* ------------------------------------------------------ VBIOS: PRAMIN ---
 *
 * nouveau tries VBIOS sources in order and PRAMIN comes BEFORE PROM:
 *   { nvbios_of }, { nvbios_ramin }, { nvbios_prom }, { acpi }, ...
 * PRAMIN is the image the card itself placed in VRAM when it POSTed, and its
 * internal pointers are the self-consistent ones. The PROM copy on this card
 * is NOT: its BIT 'p' entry points at 0xece4, which is 228 bytes inside the
 * ROM's second (EFI) image, and the bytes there are high-entropy rubbish
 * rather than a PMU table. The pointer read is right -- proved by dumping
 * the bytes it came from, e4 ec 00 00 -- so the image is the thing that is
 * wrong, and reading the source nouveau actually prefers is the fix.
 *
 * Sequence, from shadowramin.c, for GM100+ (Pascal is GM100+):
 *   addr = rd32(0x021c04);            bit 0 set  -> display disabled, no PRAMIN
 *   addr = rd32(0x619f04);            !(bit 3)   -> window not enabled
 *                                     (addr & 3) != 1 -> not in VRAM
 *   addr = (addr & 0xffffff00) << 8;  if 0: addr = (rd32(0x001700) << 16) + 0xf0000
 *   save 0x001700, set it to addr >> 16, read dwords from 0x700000 + i, restore.
 *
 * It writes one register (the PRAMIN window) and puts it back unconditionally,
 * including on every early return -- leaving that window moved would silently
 * change what every later PRAMIN access sees. */
static int nvgpu_vbios_pramin(uint8_t *dst, unsigned len) {
    if (!nv_bar0) return -1;
    uint32_t a = nv_reg_rd(0x021c04);
    if (a & 1) { kprintf("[nv] PRAMIN: display disabled (0x021c04=%x)\n", a); return -1; }
    a = nv_reg_rd(0x619f04);
    if (!(a & 8))       { kprintf("[nv] PRAMIN: window not enabled (0x619f04=%x)\n", a); return -1; }
    if ((a & 3) != 1)   { kprintf("[nv] PRAMIN: image not in VRAM (0x619f04=%x)\n", a); return -1; }
    uint64_t addr = (uint64_t)(a & 0xffffff00u) << 8;
    if (!addr) addr = ((uint64_t)nv_reg_rd(0x001700) << 16) + 0xf0000;

    /* NOT GATED BEHIND nvexec, deliberately. This moves the PRAMIN window and
     * puts it straight back; nouveau does exactly this on every boot. The
     * nvexec gate exists to stop UPLOADING AND EXECUTING MICROCODE on a
     * misunderstanding -- applying it to a restored read window would leave
     * the driver unable to read the only self-consistent VBIOS it has, which
     * blocks every later step for no safety gained. */
    uint32_t saved = nv_reg_rd(0x001700);
    *(volatile uint32_t *)(nv_bar0 + 0x001700) = (uint32_t)(addr >> 16);
    for (unsigned i = 0; i + 3 < len && i < 0x100000; i += 4) {
        uint32_t w = *(volatile uint32_t *)(nv_bar0 + 0x700000 + i);
        dst[i+0] = (uint8_t)w;       dst[i+1] = (uint8_t)(w >> 8);
        dst[i+2] = (uint8_t)(w >> 16); dst[i+3] = (uint8_t)(w >> 24);
    }
    *(volatile uint32_t *)(nv_bar0 + 0x001700) = saved;   /* always restored */
    kprintf("[nv] PRAMIN: read %u bytes from VRAM image at %lx (window restored)\n",
            len, (unsigned long)addr);
    return (dst[0] == 0x55 && dst[1] == 0xAA) ? 0 : -1;
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
static int nvgpu_devinit_tables(unsigned bit_i_off, unsigned bit_i_len);
static int nvgpu_pmu_find(unsigned bit_p_off, unsigned bit_p_len, unsigned bit_p_ver);

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
    unsigned pmu_off = 0, pmu_len = 0, pmu_ver = 0;
    for (unsigned e = 0; e < nent; e++) {
        const uint8_t *q = nv_rom + bit + hlen + e * esz;
        uint8_t id = q[0];
        if ((id >= 'A' && id <= 'Z') || (id >= 'a' && id <= 'z')) letters++;
        if (id == 'I') { init_len = (unsigned)q[2] | ((unsigned)q[3] << 8);
                         init_off = (unsigned)q[4] | ((unsigned)q[5] << 8); }
        if (id == 'M') { g_nv_bitM_ver = q[1];
                         g_nv_bitM_len = (unsigned)q[2] | ((unsigned)q[3] << 8);
                         g_nv_bitM_off = (unsigned)q[4] | ((unsigned)q[5] << 8); }
        if (id == 'p') { pmu_ver = q[1];
                         pmu_len = (unsigned)q[2] | ((unsigned)q[3] << 8);
                         pmu_off = (unsigned)q[4] | ((unsigned)q[5] << 8); }
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
    g_nv_bit_i = init_off;
    nvgpu_devinit_tables(init_off, init_len);
    if (pmu_off) nvgpu_pmu_find(pmu_off, pmu_len, pmu_ver);
    else kprintf("[nv] pmu: no BIT 'p' entry -- no PMU applications in this ROM.\n");
    return 0;
}

/* --------------------------------------------------------- devinit ------
 *
 * The 'I' entry is a block of u16 sub-table pointers, at offsets fixed by
 * nouveau's init_table_(): +0x00 script table, +0x02 macro index, +0x04
 * macro, +0x06 condition, +0x08 io condition, +0x0a io flag condition,
 * +0x0c function, +0x10 xlat. init_script(i) is u16(script_table + i*2), and
 * the list ends at the first zero.
 *
 * These offsets are from the nouveau source on this machine, not memory --
 * the BIT header layout was already guessed wrong once today and produced
 * "70 entries of 50 bytes" of pure garbage. */
static unsigned nv_rd16(unsigned off) {
    if (!nv_rom || off + 1 >= nv_romlen) return 0;
    return (unsigned)nv_rom[off] | ((unsigned)nv_rom[off + 1] << 8);
}


/* --------------------------------------------------- devinit opcodes ----
 *
 * Lengths EXTRACTED MECHANICALLY from nouveau's init.c, not transcribed:
 * each handler advances init->offset by a constant, so a script scraped
 * those constants out of the 69-entry dispatch table. 47 are a fixed size;
 * the other 22 compute their length from their own operands and need real
 * interpretation. 0 here means "not fixed-length" -- and the walker STOPS
 * and names it rather than guessing a stride, because a wrong stride
 * desynchronises the stream and every opcode after it is fiction.
 *
 * kprintf has no '-' flag. This file already shipped a "%-18s" that printed
 * literally and shifted every argument after it, which is the second time
 * today -- the first was a "%-4s" in the SYN-ACK tracer. Plain %s only. */
static const uint8_t nv_oplen[256] = {
    [0x36]=1,[0x37]=11,[0x38]=1,[0x39]=2,[0x3a]=3,[0x3b]=2,[0x3c]=2,
    [0x47]=9,[0x48]=9,[0x4b]=9,[0x4f]=5,[0x52]=4,[0x53]=3,[0x57]=3,
    [0x59]=7,[0x5a]=7,[0x5b]=3,[0x5c]=3,[0x5e]=6,[0x5f]=22,[0x62]=5,
    [0x63]=1,[0x65]=13,[0x67]=1,[0x68]=1,[0x69]=5,[0x6b]=2,[0x6d]=3,
    [0x6e]=13,[0x6f]=2,[0x71]=1,[0x72]=1,[0x73]=9,[0x74]=3,[0x75]=2,
    [0x76]=2,[0x77]=7,[0x78]=6,[0x79]=7,[0x7a]=9,[0x8c]=1,[0x8d]=1,
    [0x8e]=1,[0x90]=9,[0x96]=17,[0x97]=13,[0x9a]=7,
};

/* Walk a script without executing it: how long is it, which opcodes does it
 * actually use, and does it terminate? That is the scope of the interpreter
 * measured instead of guessed. Returns the number of opcodes walked. */
static int nv_walk(unsigned at, int depth, uint8_t *seen, unsigned *subs, int *nsub) {
    int n = 0;
    while (at && at < nv_romlen && n < 4096) {
        uint8_t op = nv_rom[at];
        seen[op] = 1;
        if (op == 0x71) { n++; return n; }            /* INIT_DONE */
        unsigned len = nv_oplen[op];
        /* Opcodes whose length is computable from their own operands. These
         * are not hard, they just are not constants, and leaving them out of
         * the walk stops it dead on a script that is otherwise fine.
         *   0x58 ZM_REG_SEQUENCE: 6 header bytes then count u32s. */
        /* The variable-length opcodes this ROM actually uses, each computed
         * the way nouveau's handler advances its offset:
         *   0x58 ZM_REG_SEQUENCE            6 + count*4        count = rd08(+5)
         *   0x91 ZM_REG_GROUP               6 + count*4        count = rd08(+5)
         *   0x8f RAM_RESTRICT_ZM_REG_GROUP  7 + num*gcount*4   num = rd08(+6),
         *        gcount = nvbios_ramcfg_count() out of BIT 'M'
         *   0xac is in NO nouveau version (their table stops at 0xaa), but the
         *        bytes say what it is: `ac f4 13 02 00 | 01 00 00 00 |
         *        01 00 00 00 | 5b ...` is opcode + three u32s = 13 bytes, and
         *        13 lands exactly on a 0x5b SUB_DIRECT. Same shape as
         *        INIT_RESET. Treated as 13 and the walk is the test: if every
         *        script now reaches DONE, the stride was right; if it derails,
         *        it was not. */
        if (op == 0x58 || op == 0x91) len = 6 + (unsigned)nv_rom[at + 5] * 4;
        if (op == 0x8f) {
            unsigned gcount = 0;
            if (g_nv_bitM_ver == 1 && g_nv_bitM_len >= 5) gcount = nv_rom[g_nv_bitM_off + 2];
            else if (g_nv_bitM_ver == 2 && g_nv_bitM_len >= 3) gcount = nv_rom[g_nv_bitM_off + 0];
            len = gcount ? 7 + (unsigned)nv_rom[at + 6] * gcount * 4 : 0;
        }
        if (op == 0xac) len = 13;
        /* Round two, after 0xac=13 let the walk reach 60+ more instructions
         * and surface these. All four are in nouveau's table; all four just
         * compute their own length:
         *   0x4d ZM_I2C_BYTE    4 + count*2      count = rd08(+3)
         *   0x56 CONDITION_TIME 3
         *   0xa9 GPIO_NE        2 + count        count = rd08(+1)
         * 0x9e, like 0xac, is in NO nouveau version -- left unknown so the
         * walk stops on it and prints its bytes rather than inventing a
         * second stride on the strength of the first one working. */
        if (op == 0x4d) len = 4 + (unsigned)nv_rom[at + 3] * 2;
        if (op == 0x56) len = 3;
        /* 0x33 REPEAT is a loop header: 2 bytes, then the following opcodes
         * run count times. For a LINEAR walk the stride is just the header --
         * the body is walked once, which is what we want when the question is
         * "which opcodes does this script contain". */
        if (op == 0x33) len = 2;
        /* GT 710 (Kepler) set. Its scripts contain NO 0xac and NO 0xaf --
         * every opcode is one nouveau implements, which is what "these are
         * meant to be host-executed" looks like in the data.
         *   0x4c I2C_BYTE  4 + count*3   count = rd08(+3) */
        if (op == 0x4c) len = 4 + (unsigned)nv_rom[at + 3] * 3;
        if (op == 0xa9) len = 2 + (unsigned)nv_rom[at + 1];
        if (!len) {
            /* Be precise about WHICH kind of unknown this is: 0x8f and 0x91
             * ARE in nouveau's table and merely compute their own length,
             * whereas 0xac is in no nouveau version on this machine (6.14,
             * 7.1, 7.1-gentoo all stop at 0xaa). Conflating those two was a
             * misleading message in the first version of this walker. */
            kprintf("[nv] devinit:   stopped at %x: opcode %02x has no fixed stride "
                    "(either variable-length in nouveau, or unknown to it). "
                    "Bytes around it:\n", at, op);
            /* SIX LINES, NOT THREE. Inferring a stride needs to see where
             * the NEXT plausible opcode begins: 0xac was only inferable
             * because 13 bytes landed exactly on a 0x5b SUB_DIRECT. Three
             * lines was not enough context for 0xaf. */
            unsigned from = at > 16 ? at - 16 : 0;
            for (int r = 0; r < 6; r++) {
                unsigned b = from + r * 16;
                if (b + 16 > nv_romlen) break;
                kprintf("[nv] devinit:     %05x: %02x %02x %02x %02x %02x %02x %02x %02x "
                        "%02x %02x %02x %02x %02x %02x %02x %02x%s\n", b,
                        nv_rom[b+0],nv_rom[b+1],nv_rom[b+2],nv_rom[b+3],
                        nv_rom[b+4],nv_rom[b+5],nv_rom[b+6],nv_rom[b+7],
                        nv_rom[b+8],nv_rom[b+9],nv_rom[b+10],nv_rom[b+11],
                        nv_rom[b+12],nv_rom[b+13],nv_rom[b+14],nv_rom[b+15],
                        (at >= b && at < b + 16) ? "   <-- stop is on this line" : "");
            }
            return -n;
        }
        if (op == 0x5b && depth == 0 && *nsub < 32) {  /* SUB_DIRECT: record the target */
            unsigned t = nv_rd16(at + 1);
            int dup = 0;
            for (int k = 0; k < *nsub; k++) if (subs[k] == t) dup = 1;
            if (!dup) subs[(*nsub)++] = t;
        }
        at += len; n++;
    }
    return n;
}


/* ------------------------------------------------- devinit interpreter --
 *
 * This ROM's scripts use NINE opcodes, not nouveau's sixty-nine -- measured
 * by walking the real scripts rather than assumed. Eight are register
 * read/modify/write plus flow control, and they are implemented here exactly
 * as nouveau's handlers do it (semantics read from the source on this
 * machine, not from memory -- the BIT layout and two kprintf format strings
 * were already got wrong from memory today):
 *
 *   0x7a ZM_REG           R[reg] = data        (+ the addr==0x200 |= 1 quirk)
 *   0x6e NV_REG           R[reg] = (R[reg] & mask) | data
 *   0x5f COPY_NV_REG      R[d] = (R[d] & dmask) | ((shift(R[s]) & smask) ^ sxor)
 *   0x58 ZM_REG_SEQUENCE  count u32s into consecutive registers
 *   0x5b SUB_DIRECT       call a sub-script
 *   0x75 CONDITION        suspend unless (R[reg] & msk) == val
 *   0x72 RESUME           resume
 *   0x71 DONE             stop
 *
 * DRY RUN BY DEFAULT. Executing devinit means writing to a real GPU's
 * registers from a from-scratch driver, and getting it wrong can wedge the
 * card or the host. So the interpreter computes every read, write and branch
 * and PRINTS them without touching the hardware unless -append nvexec says
 * otherwise. A trace that looks right is the prerequisite for letting it
 * write, not a substitute for it. */

static uint32_t nv_rom32(unsigned o) {
    if (!nv_rom || o + 3 >= nv_romlen) return 0;
    return (uint32_t)nv_rom[o] | ((uint32_t)nv_rom[o+1] << 8) |
           ((uint32_t)nv_rom[o+2] << 16) | ((uint32_t)nv_rom[o+3] << 24);
}
static uint32_t nv_reg_rd(uint32_t reg) {
    if (!nv_bar0 || reg + 3 >= (16u << 20)) return 0;
    return *(volatile uint32_t *)(nv_bar0 + reg);
}
static void nv_reg_wr(uint32_t reg, uint32_t val) {
    if (!g_nv_exec) return;                      /* dry run */
    if (!nv_bar0 || reg + 3 >= (16u << 20)) return;
    *(volatile uint32_t *)(nv_bar0 + reg) = val;
}
static uint32_t nv_shift(uint32_t d, uint8_t sh) {
    return sh < 0x80 ? (d >> sh) : (d << (0x100 - sh));
}

static unsigned nv_cond_table;       /* set from the 'I' entry */
static int nv_cond_met(uint8_t cond) {
    if (!nv_cond_table) return 0;
    unsigned e = nv_cond_table + cond * 12;
    uint32_t reg = nv_rom32(e), msk = nv_rom32(e + 4), val = nv_rom32(e + 8);
    return (nv_reg_rd(reg) & msk) == val;
}

static int nv_run(unsigned at, int depth, int *exec, int *ops) {
    while (at && at < nv_romlen && *ops < 4096) {
        uint8_t op = nv_rom[at];
        (*ops)++;
        switch (op) {
        case 0x71:                                             /* DONE */
            return 0;
        case 0x72:                                             /* RESUME */
            *exec = 1; at += 1; break;
        case 0x75: {                                           /* CONDITION */
            uint8_t c = nv_rom[at + 1];
            int met = nv_cond_met(c);
            if (!met) *exec = 0;
            at += 2; break; }
        case 0x5b: {                                           /* SUB_DIRECT */
            unsigned t = nv_rd16(at + 1);
            if (depth < 4) nv_run(t, depth + 1, exec, ops);
            at += 3; break; }
        case 0x7a: {                                           /* ZM_REG */
            uint32_t reg = nv_rom32(at + 1), data = nv_rom32(at + 5);
            if (reg == 0x000200) data |= 1;                    /* nouveau's quirk */
            if (*exec) nv_reg_wr(reg, data);
            at += 9; break; }
        case 0x6e: {                                           /* NV_REG */
            uint32_t reg = nv_rom32(at + 1), mask = nv_rom32(at + 5), data = nv_rom32(at + 9);
            if (*exec) nv_reg_wr(reg, (nv_reg_rd(reg) & mask) | data);
            at += 13; break; }
        case 0x5f: {                                           /* COPY_NV_REG */
            uint32_t sreg = nv_rom32(at + 1); uint8_t sh = nv_rom[at + 5];
            uint32_t smask = nv_rom32(at + 6), sxor = nv_rom32(at + 10);
            uint32_t dreg = nv_rom32(at + 14), dmask = nv_rom32(at + 18);
            if (*exec) {
                uint32_t d = (nv_shift(nv_reg_rd(sreg), sh) & smask) ^ sxor;
                nv_reg_wr(dreg, (nv_reg_rd(dreg) & dmask) | d);
            }
            at += 22; break; }
        case 0x38:                                             /* NOT: invert exec */
            *exec = !*exec; at += 1; break;
        case 0x56: {                                           /* CONDITION_TIME */
            uint8_t c = nv_rom[at + 1];
            if (!nv_cond_met(c)) *exec = 0;                    /* retry loop is a wait */
            at += 3; break; }
        case 0x90: {                                           /* COPY_ZM_REG */
            uint32_t sreg = nv_rom32(at + 1), dreg = nv_rom32(at + 5);
            if (*exec) nv_reg_wr(dreg, nv_reg_rd(sreg));
            at += 9; break; }
        case 0x8e:                                             /* GPIO */
            g_nv_skipped_gpio++; at += 1; break;
        case 0xa9:                                             /* GPIO_NE */
            g_nv_skipped_gpio++; at += 2 + (unsigned)nv_rom[at + 1]; break;
        case 0x36:                                             /* END_REPEAT */
        case 0x8c:                                             /* RESET_BEGUN */
        case 0x8d:                                             /* RESET_END   */
            at += 1; break;                                    /* no register effect */
        case 0x33:                                             /* REPEAT (loop hdr) */
            at += 2; break;
        case 0x74: {                                           /* TIME: delay usec */
            unsigned us = nv_rd16(at + 1);
            if (*exec) for (volatile unsigned d = 0; d < us * 40u; d++) { }
            at += 3; break; }
        case 0x97: {                                           /* ZM_MASK_ADD */
            uint32_t reg = nv_rom32(at + 1), mask = nv_rom32(at + 5), add = nv_rom32(at + 9);
            if (*exec) {
                uint32_t v = nv_reg_rd(reg);
                nv_reg_wr(reg, (v & mask) | ((v + add) & ~mask));
            }
            at += 13; break; }
        case 0x53:                                             /* ZM_CR: VGA CRTC */
        case 0x69:                                             /* IO: VGA port     */
            /* Both are legacy VGA PORT I/O, not MMIO. vfio-pci is loaded
             * with disable_vga=1 on this host, so the guest has no VGA port
             * access to the card at all -- these cannot be executed here and
             * are stepped over rather than faked. Counted, so the report can
             * say how much of devinit was skipped. */
            g_nv_skipped_vga++;
            at += (op == 0x53) ? 3 : 5; break;
        case 0x4c: {                                           /* I2C_BYTE */
            g_nv_skipped_i2c++;                                /* needs an I2C engine */
            at += 4 + (unsigned)nv_rom[at + 3] * 3; break; }
        case 0x58: {                                           /* ZM_REG_SEQUENCE */
            uint32_t base = nv_rom32(at + 1); unsigned cnt = nv_rom[at + 5];
            unsigned o = at + 6;
            for (unsigned k = 0; k < cnt; k++, o += 4, base += 4)
                if (*exec) nv_reg_wr(base, nv_rom32(o));
            at = o; break; }
        default:
            kprintf("[nv] devinit: UNIMPLEMENTED opcode %02x at %x after %d op(s) -- "
                    "stopping rather than guessing a stride\n", op, at, *ops);
            return -1;
        }
    }
    return 0;
}

static void nvgpu_devinit_run(unsigned script0, unsigned cond_table) {
    nv_cond_table = cond_table;
    int exec = 1, ops = 0;
    kprintf("[nv] devinit: %s the script\n",
            g_nv_exec ? "** EXECUTING ** (nvexec given: this WRITES to the GPU)"
                      : "dry run (computing every read/write, touching nothing; "
                        "-append nvexec to arm it)");
    int r = nv_run(script0, 0, &exec, &ops);
    kprintf("[nv] devinit: %s after %d opcode(s), exec flag %d\n",
            r == 0 ? "COMPLETED" : "ABORTED", ops, exec);
    if (g_nv_skipped_vga || g_nv_skipped_i2c || g_nv_skipped_gpio)
        kprintf("[nv] devinit: SKIPPED %u VGA port, %u I2C, %u GPIO op(s) -- those need "
                "engines this driver does not have yet, so this is NOT a complete POST "
                "and saying so is the point\n",
                g_nv_skipped_vga, g_nv_skipped_i2c, g_nv_skipped_gpio);
}

static void nvgpu_devinit_scope(unsigned script0) {
    static uint8_t seen[256];
    static unsigned subs[32];
    int nsub = 0;
    int n = nv_walk(script0, 0, seen, subs, &nsub);
    kprintf("[nv] devinit: main script %s after %d opcode(s), %d sub-script(s) called\n",
            n < 0 ? "STOPPED" : "walked cleanly", n < 0 ? -n : n, nsub);
    for (int i = 0; i < nsub; i++) {
        int m = nv_walk(subs[i], 1, seen, subs, &nsub);
        kprintf("[nv] devinit:   sub %x: %s after %d opcode(s)\n", subs[i],
                m < 0 ? "STOPPED" : "ok", m < 0 ? -m : m);
    }
    int distinct = 0, needlogic = 0;
    for (int i = 0; i < 256; i++)
        if (seen[i]) { distinct++; if (!nv_oplen[i] && i != 0x71) needlogic++; }
    kprintf("[nv] devinit: THIS ROM's scripts use %d distinct opcode(s); %d of them are "
            "variable-length and need real interpretation (nouveau defines 69 total).\n",
            distinct, needlogic);
    kprintf("[nv] devinit: opcodes used:");
    for (int i = 0; i < 256; i++) if (seen[i]) kprintf(" %02x%s", i, nv_oplen[i] ? "" : "*");
    kprintf("   (* = variable-length)\n");
}


/* ------------------------------------------------------------- PMU ------
 *
 * GP108's devinit is a PMU application stored in the VBIOS, so finding it is
 * the prerequisite for falcon bring-up. The chain, from nouveau's pmu.c:
 *
 *   BIT 'p' (version 2, length >= 4)  ->  u32 at +0x00 = PMU table
 *   table: +0 ver, +1 header_len, +2 entry_len, +3 entry_count
 *   entry: +0x00 type (u8), +0x02 data (u32)
 *   type 0x04 = DEVINIT, 0x01 = PRE_OS
 *   descriptor at `data`:
 *     +0x08 init_addr_pmu   +0x0c args_addr_pmu
 *     boot: rom data+0x30, pmu u32(+0x10)+u32(+0x18), size u32(+0x1c)-u32(+0x18)
 *     code: follows boot in both spaces, size u32(+0x20)
 *     data: rom data+0x30+u32(+0x24), pmu u32(+0x28), size u32(+0x2c)
 *
 * Every field is bounds-checked against the ROM and the sizes sanity-checked:
 * microcode is kilobytes, so a "size" of 0 or several megabytes means the
 * descriptor was misread, and saying so beats uploading rubbish to a falcon. */

/* ------------------------------------------------- PMU falcon upload ---
 *
 * gm200_devinit_post's sequence, which is what GP108 actually uses. Register
 * offsets are the PMU falcon at 0x10a000 plus nouveau's falcon offsets:
 *
 *   reset:  mask(0x10a048, 3, 0); wr(0x10a014, ~0); <PMC toggle>;
 *           mask(0x10a040, 0, 0); wait !(rd(0x10a10c) & 6); wr(0x10a084, PMC_BOOT_0)
 *   code:   wr(0x10a180, 0x01000000 | (sec ? 0x10000000 : 0) | dst)
 *           per 0x100: wr(0x10a188, (dst + i) >> 8);  each word: wr(0x10a184, w)
 *           pad with zeros to the next 0x100 boundary
 *   data:   wr(0x10a1c0, 0x01000000 | dst);  each word: wr(0x10a1c4, w)
 *   args:   wr(0x10a1c0, argp); wr(0x10a1c0, rd(0x10a1c4) + argi); rd(0x10a1c4)
 *   exec:   wr(0x10a104, init_addr); wr(0x10a10c, 0); wr(0x10a100, 2)
 *           then wait for 0x10a040 & 0x2000, having set 0x10a040 = 0x5000
 *
 * DRY RUN unless -append nvexec. In dry run this counts and describes every
 * transfer without issuing one: uploading microcode to a falcon on a live
 * GPU, from a driver whose first attempt at this file got two format strings
 * and a table layout wrong, is not something to do on a hunch. */
#define PMU_BASE 0x10a000

static void pmu_wr(uint32_t reg, uint32_t val) { nv_reg_wr(reg, val); }
static uint32_t pmu_rd(uint32_t reg) { return nv_reg_rd(reg); }

static unsigned nv_pmu_code(uint32_t dst, unsigned img, unsigned len, int sec) {
    unsigned words = 0;
    pmu_wr(PMU_BASE + 0x180, 0x01000000u | (sec ? 0x10000000u : 0u) | dst);
    unsigned i = 0;
    for (; i < len; i += 4) {
        if ((i & 0xff) == 0) pmu_wr(PMU_BASE + 0x188, (dst + i) >> 8);
        pmu_wr(PMU_BASE + 0x184, nv_rom32(img + i));
        words++;
    }
    while (i & 0xff) { pmu_wr(PMU_BASE + 0x184, 0); i += 4; words++; }   /* pad */
    return words;
}
static unsigned nv_pmu_data(uint32_t dst, unsigned img, unsigned len) {
    unsigned words = 0;
    pmu_wr(PMU_BASE + 0x1c0, 0x01000000u | dst);
    for (unsigned i = 0; i < len; i += 4) { pmu_wr(PMU_BASE + 0x1c4, nv_rom32(img + i)); words++; }
    return words;
}
static uint32_t nv_pmu_args(uint32_t argp, uint32_t argi) {
    pmu_wr(PMU_BASE + 0x1c0, argp);
    pmu_wr(PMU_BASE + 0x1c0, pmu_rd(PMU_BASE + 0x1c4) + argi);
    return pmu_rd(PMU_BASE + 0x1c4);
}

/* Upload and (optionally) run the VBIOS DEVINIT application. */
static int nvgpu_pmu_devinit(unsigned da, unsigned bit_i_off) {
    unsigned boot_rom = da + 0x30;
    uint32_t boot_pmu = nv_rom32(da + 0x10) + nv_rom32(da + 0x18);
    unsigned boot_sz  = nv_rom32(da + 0x1c) - nv_rom32(da + 0x18);
    unsigned code_sz  = nv_rom32(da + 0x20);
    unsigned data_rom = da + 0x30 + nv_rom32(da + 0x24);
    uint32_t data_pmu = nv_rom32(da + 0x28);
    unsigned data_sz  = nv_rom32(da + 0x2c);
    uint32_t init_pmu = nv_rom32(da + 0x08), args_pmu = nv_rom32(da + 0x0c);

    kprintf("[nv] pmu: %s DEVINIT\n", g_nv_exec
            ? "** UPLOADING AND EXECUTING **" : "dry run (no register is written)");

    if (g_nv_exec) {                      /* falcon reset, per gm200_flcn_* */
        pmu_wr(PMU_BASE + 0x048, pmu_rd(PMU_BASE + 0x048) & ~3u);
        pmu_wr(PMU_BASE + 0x014, 0xFFFFFFFFu);
        pmu_wr(PMU_BASE + 0x040, pmu_rd(PMU_BASE + 0x040));
        int ok = 0;
        for (int t = 0; t < 100000; t++)
            if (!(pmu_rd(PMU_BASE + 0x10c) & 6)) { ok = 1; break; }
        if (!ok) { kprintf("[nv] pmu: memory scrubbing never finished -- falcon not ready\n"); return -1; }
        pmu_wr(PMU_BASE + 0x084, nv_boot0);
    }

    unsigned wb = nv_pmu_code(boot_pmu, boot_rom, boot_sz, 0);
    unsigned wc = nv_pmu_code(boot_pmu + boot_sz, boot_rom + boot_sz, code_sz, 1);
    unsigned wd = nv_pmu_data(data_pmu, data_rom, data_sz);
    kprintf("[nv] pmu:   boot %u word(s) -> %x | code %u -> %x | data %u -> %x\n",
            wb, boot_pmu, wc, boot_pmu + boot_sz, wd, data_pmu);

    /* Tables and boot scripts the DEVINIT app needs, from BIT 'I'. */
    if (g_nv_exec) {
        uint32_t at = nv_pmu_args(args_pmu + 0x08, 0x08);
        nv_pmu_data(at, nv_rd16(bit_i_off + 0x14), nv_rd16(bit_i_off + 0x16));
        uint32_t bs = nv_pmu_args(args_pmu + 0x08, 0x10);
        nv_pmu_data(bs, nv_rd16(bit_i_off + 0x18), nv_rd16(bit_i_off + 0x1a));
        pmu_wr(0x10a040, 0x00005000);
        pmu_wr(PMU_BASE + 0x104, init_pmu);
        pmu_wr(PMU_BASE + 0x10c, 0x00000000);
        pmu_wr(PMU_BASE + 0x100, 0x00000002);
        int done = 0;
        for (int t = 0; t < 2000000; t++)
            if (pmu_rd(0x10a040) & 0x00002000) { done = 1; break; }
        kprintf("[nv] pmu: DEVINIT %s (0x10a040 = %x)\n",
                done ? "SIGNALLED COMPLETE" : "TIMED OUT", pmu_rd(0x10a040));
        return done ? 0 : -1;
    }
    kprintf("[nv] pmu:   would then load tables from BIT 'I' +14/+16 (%x/%u) and boot "
            "scripts +18/+1a (%x/%u), set 0x10a040=0x5000, exec at %x and wait for "
            "bit 0x2000\n", nv_rd16(bit_i_off + 0x14), nv_rd16(bit_i_off + 0x16),
            nv_rd16(bit_i_off + 0x18), nv_rd16(bit_i_off + 0x1a), init_pmu);
    return 0;
}

static int nvgpu_pmu_find(unsigned bit_p_off, unsigned bit_p_len, unsigned bit_p_ver) {
    if (bit_p_ver != 2 || bit_p_len < 4) {
        kprintf("[nv] pmu: BIT 'p' is version %u length %u; nouveau requires v2 len>=4\n",
                bit_p_ver, bit_p_len);
        return -1;
    }
    unsigned tbl = nv_rom32(bit_p_off);
    /* Show the bytes the pointer came from and the bytes it lands on. The
     * first attempt read 0xece4, which is 228 bytes into the ROM's SECOND
     * (EFI) image rather than a PMU table, and produced 219 entries of noise
     * -- with only the decoded values printed there is no way to tell a
     * misread pointer from a misread table. */
    kprintf("[nv] pmu: BIT 'p' @ %x: %02x %02x %02x %02x %02x %02x -> table %x\n",
            bit_p_off, nv_rom[bit_p_off], nv_rom[bit_p_off+1], nv_rom[bit_p_off+2],
            nv_rom[bit_p_off+3], nv_rom[bit_p_off+4], nv_rom[bit_p_off+5], tbl);
    if (tbl && tbl + 16 < nv_romlen)
        kprintf("[nv] pmu: bytes at %x: %02x %02x %02x %02x %02x %02x %02x %02x "
                "%02x %02x %02x %02x %02x %02x %02x %02x\n", tbl,
                nv_rom[tbl+0],nv_rom[tbl+1],nv_rom[tbl+2],nv_rom[tbl+3],
                nv_rom[tbl+4],nv_rom[tbl+5],nv_rom[tbl+6],nv_rom[tbl+7],
                nv_rom[tbl+8],nv_rom[tbl+9],nv_rom[tbl+10],nv_rom[tbl+11],
                nv_rom[tbl+12],nv_rom[tbl+13],nv_rom[tbl+14],nv_rom[tbl+15]);
    if (!tbl || tbl >= nv_romlen) {
        kprintf("[nv] pmu: table pointer %x is outside the %u-byte ROM\n", tbl, nv_romlen);
        return -1;
    }
    unsigned ver = nv_rom[tbl], hdr = nv_rom[tbl+1], len = nv_rom[tbl+2], cnt = nv_rom[tbl+3];
    kprintf("[nv] pmu: table @ %x  ver %02x header %u entry %u count %u\n",
            tbl, ver, hdr, len, cnt);
    if (!len || !cnt || tbl + hdr + cnt * len > nv_romlen) {
        kprintf("[nv] pmu: that header does not fit the ROM -- misparse, not data.\n");
        return -1;
    }
    if (cnt > 32 || hdr > 64 || len > 64) {
        /* SEARCH INSTEAD OF GUESSING A BASE. The pointer is read correctly
         * (its source bytes are printed above) and the data it lands on is
         * not a table. Rather than invent an offset adjustment, scan the ROM
         * for a structurally valid PMU table -- sane header, at least one
         * entry, and a type 0x04 (DEVINIT) among them. If exactly one turns
         * up, the delta from the stated pointer names the correction; if
         * none does, this ROM does not carry one and that is the answer. */
        unsigned hits = 0, where = 0;
        for (unsigned o = 0x100; o + 0x40 < nv_romlen; o += 4) {
            unsigned h = nv_rom[o+1], l = nv_rom[o+2], c = nv_rom[o+3];
            if (h < 4 || h > 32 || l < 4 || l > 32 || c < 1 || c > 24) continue;
            if (o + h + c * l > nv_romlen) continue;
            unsigned devinit = 0, plausible = 1;
            for (unsigned i = 0; i < c && plausible; i++) {
                unsigned e = o + h + i * l, ty = nv_rom[e], dp = nv_rom32(e + 2);
                if (ty == 0x04) devinit = dp;
                if (dp && (dp >= nv_romlen)) plausible = 0;      /* entry points off the end */
            }
            if (plausible && devinit && devinit + 0x30 < nv_romlen) {
                if (hits < 4) kprintf("[nv] pmu: candidate table @ %x (hdr %u entry %u count %u), "
                                      "DEVINIT data @ %x\n", o, h, l, c, devinit);
                hits++; where = o;
            }
        }
        kprintf("[nv] pmu: scan found %u candidate table(s)%s\n", hits,
                hits == 1 ? " -- one is a usable answer" : hits ? " -- ambiguous" : "");
        if (hits == 1) kprintf("[nv] pmu: stated pointer %x, found %x, delta %d\n",
                               nv_rom32(bit_p_off), where, (int)where - (int)nv_rom32(bit_p_off));

        kprintf("[nv] pmu: header %u entries of %u bytes is not a PMU table -- "
                "refusing to print %u lines of noise.\n", cnt, len, cnt);
        return -1;
    }
    int found = 0;
    for (unsigned i = 0; i < cnt; i++) {
        unsigned e = tbl + hdr + i * len;
        unsigned type = nv_rom[e], da = nv_rom32(e + 2);
        const char *what = type == 0x04 ? "  <-- DEVINIT" : type == 0x01 ? "  <-- PRE_OS" : "";
        kprintf("[nv] pmu:   [%u] type %02x data %x%s\n", i, type, da, what);
        if (type != 0x04) continue;
        if (!da || da + 0x30 > nv_romlen) {
            kprintf("[nv] pmu:   DEVINIT descriptor at %x is out of range\n", da);
            continue;
        }
        unsigned boot_rom = da + 0x30;
        unsigned boot_pmu = nv_rom32(da + 0x10) + nv_rom32(da + 0x18);
        unsigned boot_sz  = nv_rom32(da + 0x1c) - nv_rom32(da + 0x18);
        unsigned code_sz  = nv_rom32(da + 0x20);
        unsigned data_rom = da + 0x30 + nv_rom32(da + 0x24);
        unsigned data_pmu = nv_rom32(da + 0x28);
        unsigned data_sz  = nv_rom32(da + 0x2c);
        kprintf("[nv] pmu:     init_addr_pmu %x  args_addr_pmu %x\n",
                nv_rom32(da + 0x08), nv_rom32(da + 0x0c));
        kprintf("[nv] pmu:     boot: rom %x -> pmu %x, %u bytes\n", boot_rom, boot_pmu, boot_sz);
        kprintf("[nv] pmu:     code: rom %x -> pmu %x, %u bytes\n",
                boot_rom + boot_sz, boot_pmu + boot_sz, code_sz);
        kprintf("[nv] pmu:     data: rom %x -> pmu %x, %u bytes\n", data_rom, data_pmu, data_sz);
        /* Microcode is kilobytes. Anything else means a misread descriptor. */
        int sane = boot_sz && boot_sz < 0x10000 && code_sz && code_sz < 0x40000 &&
                   data_sz < 0x40000 && boot_rom + boot_sz + code_sz <= nv_romlen &&
                   data_rom + data_sz <= nv_romlen;
        kprintf("[nv] pmu:     %s\n", sane
                ? "sizes and ranges are sane -- this is a real PMU image to upload."
                : "** THESE SIZES ARE NOT PLAUSIBLE. Do not upload this. **");
        found = sane;
        if (sane) nvgpu_pmu_devinit(da, g_nv_bit_i);
    }
    if (!found) kprintf("[nv] pmu: no usable DEVINIT (type 0x04) application found.\n");
    return found ? 0 : -1;
}

static int nvgpu_devinit_tables(unsigned bit_i_off, unsigned bit_i_len) {
    static const struct { unsigned off; const char *name; } tbl[] = {
        { 0x00, "script" }, { 0x02, "macro index" }, { 0x04, "macro" },
        { 0x06, "condition" }, { 0x08, "io condition" },
        { 0x0a, "io flag condition" }, { 0x0c, "function" }, { 0x10, "xlat" },
    };
    for (unsigned k = 0; k < sizeof tbl / sizeof tbl[0]; k++) {
        if (bit_i_len < tbl[k].off + 2) continue;
        unsigned v = nv_rd16(bit_i_off + tbl[k].off);
        if (v) kprintf("[nv] devinit:   %s table @ %x\n", tbl[k].name, v);
    }
    unsigned st = nv_rd16(bit_i_off + 0x00);
    if (!st) { kprintf("[nv] devinit: no script table -- nothing to execute.\n"); return -1; }

    int n = 0;
    for (int i = 0; i < 16; i++) {
        unsigned p = nv_rd16(st + i * 2);
        if (!p) break;
        n++;
        /* The first byte must be an opcode. nouveau's dispatch table ends at
         * 0xaa, so anything above that means this is not a script and the
         * pointer chain is wrong -- say so instead of "executing" it. */
        unsigned op = (p < nv_romlen) ? nv_rom[p] : 0xFFFF;
        kprintf("[nv] devinit:   script[%d] @ %x, first byte %02x%s\n", i, p, op,
                op > 0xAA ? "  <-- NOT A VALID OPCODE (max is 0xaa)" : "");
        if (p + 8 < nv_romlen)
            kprintf("[nv] devinit:     %02x %02x %02x %02x %02x %02x %02x %02x\n",
                    nv_rom[p], nv_rom[p+1], nv_rom[p+2], nv_rom[p+3],
                    nv_rom[p+4], nv_rom[p+5], nv_rom[p+6], nv_rom[p+7]);
    }
    kprintf("[nv] devinit: %d script(s) in the table at %x\n", n, st);
    if (n) {
        nvgpu_devinit_scope(nv_rd16(st));
        nvgpu_devinit_run(nv_rd16(st), nv_rd16(bit_i_off + 0x06));
    }
    return n ? 0 : -1;
}

int nvgpu_bit_probe(void) { return nvgpu_bit(); }


/* ---------------------------------------------------------------- VRAM --
 *
 * How much memory does the card have, asked of the card rather than assumed?
 * This is the fb subdev's first job and it is all READS, so it works on a
 * card that has not been POSTed -- unlike everything hanging off devinit.
 *
 * The walk is nouveau's gf100_ram_ctor + gm107/gm200/gp100 probes for GP108:
 *   fbps  = rd32(0x022438)   how many FBPs
 *   fbpao = rd32(0x021c14)   per-FBPA disable mask
 *   fbpas = rd32(0x022458)   FBPAs per FBP
 *   an FBP is disabled if rd32(0x021d38) has its bit
 *   each live FBPA contributes rd32(0x90020c + fbpa*0x4000) MiB
 *
 * CHECKABLE: the host's nouveau reports "fb: 2048 MiB GDDR5" for this exact
 * card, so this has a right answer that was known before the code was
 * written. A number that merely looks plausible is not evidence -- four
 * instruments in this campaign produced plausible numbers for things they
 * never measured. */
static void nvgpu_vram(void) {
    if (!nv_bar0) return;
    uint32_t fbps  = nv_reg_rd(0x022438);
    uint32_t fbpao = nv_reg_rd(0x021c14);
    uint32_t fbpas = nv_reg_rd(0x022458);
    uint32_t dis   = nv_reg_rd(0x021d38);
    if (!fbps || fbps > 32 || !fbpas || fbpas > 32) {
        kprintf("[nv] fb: FBP layout reads fbps=%x fbpas=%x -- not plausible, so the "
                "card is not answering these registers; no VRAM size claimed.\n",
                fbps, fbpas);
        return;
    }
    uint32_t total = 0; unsigned live = 0;
    for (uint32_t fbp = 0; fbp < fbps; fbp++) {
        if (dis & (1u << fbp)) continue;
        uint32_t fbpa = fbp * fbpas, sub = 0;
        for (uint32_t k = 0; k < fbpas; k++, fbpa++) {
            if (fbpao & (1u << fbpa)) continue;
            sub += nv_reg_rd(0x90020c + fbpa * 0x4000);
        }
        if (sub) { live++; total += sub; }
    }
    kprintf("[nv] fb: %u FBP(s), %u per-FBP FBPA(s), %u live -> %u MiB of VRAM\n",
            fbps, fbpas, live, total);
    kprintf("[nv] fb: %s\n", total == 2048
            ? "2048 MiB -- matches what nouveau reports for this card on the host."
            : "that is NOT the 2048 MiB nouveau reports for this card; the walk is wrong.");
}

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
    /* Name the chip. GK208B (0x106) matters as much as GP108 (0x138) now:
     * Kepler's devinit is gf100_devinit -> nv04_devinit_post -> nvbios_post,
     * which interprets init scripts ON THE HOST CPU, and its chipset entry
     * has no .acr at all. Both blockers that closed the GT 1030 -- a
     * PMU-only devinit whose descriptor is invalid, and signed firmware --
     * simply do not exist on this part. */
    kprintf("[nv] %s\n",
            chipset == 0x138 ? "GP108 (GT 1030): devinit is PMU-only and its VBIOS "
                               "descriptor is invalid -- see M2373/M2374."
          : chipset == 0x106 ? "GK208B (GT 710): KEPLER. devinit runs init scripts on "
                               "the CPU and needs no signed firmware."
                             : "An NVIDIA chip is answering, but not one this campaign "
                               "has a plan for -- check which card got passed.");
    /* nouveau decides whether a card needs POSTing from this bit. */
    {   uint32_t p = nv_reg_rd(0x02240c);
        kprintf("[nv] 0x2240c = %08x -> the card %s POSTing\n", p,
                (p & 2) ? "does NOT need" : "NEEDS");
    }
    nvgpu_vram();                          /* all reads; works on a cold card (M2373) */
    if (nvgpu_vbios() == 0) nvgpu_bit();   /* devinit's scripts live in there (M2369) */
    return 0;
}
