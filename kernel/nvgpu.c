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
#include "task.h"
#include "vfs.h"
#include "syscall.h"         /* struct statx */
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
static int      nv_gpio_reset(uint8_t match);
static void     nv_vram_probe(const char *when);
int             g_nv_exec;
static unsigned g_nv_skipped_vga, g_nv_skipped_i2c, g_nv_skipped_gpio;

static pci_device_t  nv;
static volatile uint8_t *nv_bar0;
static uint32_t      nv_boot0;
static unsigned      g_nv_bitM_off, g_nv_bitM_len, g_nv_bitM_ver;
static unsigned      g_nv_bit_i;     /* BIT 'I' offset, for the PMU args */
/* nouveau's nvbios_addr remap (M2380): see nv_A(). */
static unsigned      g_nv_img0, g_nv_imgd;
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
/* 128 KiB -> 256 KiB (M2380). The 128 KiB figure was my own arbitrary cap;
 * nouveau's PROM reader goes to 1 MiB. On this card the ROM is 235008 bytes
 * in FIVE images, and the DEVINIT ucode lives in image 2 (0x1f400-0x2d000),
 * mostly past the old limit -- so the application could never have been
 * uploaded from what this driver copied, whatever the pointers said. */
#define NV_PROM_SIZE    0x40000

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
            /* nouveau's nvbios_imagen accepts three ROM signatures and
             * nvbios_pcirTe three data-structure signatures. Accepting only
             * 55AA/PCIR hid images 2-4 -- including the one that holds the
             * DEVINIT ucode -- because they are "NV"/NPDS (M2380). */
            unsigned sig = (unsigned)nv_rom[img] | ((unsigned)nv_rom[img+1] << 8);
            if (sig != 0xAA55 && sig != 0xBB77 && sig != 0x4E56) break;
            unsigned pc = img + ((unsigned)nv_rom[img+0x18] | ((unsigned)nv_rom[img+0x19] << 8));
            if (pc + 0x16 >= nv_romlen) break;
            int ok_pcir = (nv_rom[pc]=='P'&&nv_rom[pc+1]=='C'&&nv_rom[pc+2]=='I'&&nv_rom[pc+3]=='R') ||
                          (nv_rom[pc]=='N'&&nv_rom[pc+1]=='P'&&nv_rom[pc+2]=='D'&&nv_rom[pc+3]=='S') ||
                          (nv_rom[pc]=='R'&&nv_rom[pc+1]=='G'&&nv_rom[pc+2]=='I'&&nv_rom[pc+3]=='S');
            if (!ok_pcir) break;
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
            if (n == 0) g_nv_img0 = ilen;
            else if (ctype == 0xe0 && !g_nv_imgd) g_nv_imgd = img;
            if (ctype == 0x70) last = 0x80;                  /* nouveau: type 0x70 is last */
            total = img + ilen;
            if (last || !ilen) break;
            img += ilen;
        }
        kprintf("[nv] VBIOS: %u bytes of images in a %u-byte window\n", total, nv_romlen);
        kprintf("[nv] VBIOS: image remap -- image0 is %u bytes, first type-0xe0 image at %x: "
                "%s\n", g_nv_img0, g_nv_imgd,
                g_nv_imgd ? "pointers past image 0 are re-based onto it, as nouveau does"
                          : "NO type-0xe0 image, so no remap (pointers are used raw)");
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
/* THE IMAGE REMAP, WITHOUT WHICH EVERY POINTER PAST IMAGE 0 IS WRONG (M2380).
 *
 * nouveau, in nvkm_bios_new, with the comment "Some tables have weird
 * pointers that need adjustment before they're dereferenced. I'm not
 * entirely sure why...":
 *
 *     image0_size = size of image 0;
 *     imaged_addr = base of the first image of type 0xe0;
 *     nvbios_addr: if (addr >= image0_size) addr = addr - image0_size + imaged_addr;
 *
 * Pointers inside the VBIOS are written for a layout in which NVIDIA's own
 * images follow image 0 directly. An EFI image (67584 bytes here) was
 * inserted between them afterwards, and nothing re-based the pointers.
 *
 * Not applying this is the entire reason M2373 and M2374 declared the GT 1030
 * unPOSTable. BIT 'p' says the PMU table is at 0xece4; read raw, that is 228
 * bytes into the EFI image and parses as "ver 7f hdr 41 len 175 count 219",
 * and the "DEVINIT descriptor 0x300b0ecc outside every image" came out of
 * that garbage. Remapped, 0xece4 -> 0x1f4e4 is "ver 01 hdr 6 len 6 count 5"
 * with a DEVINIT entry whose boot/code/data are 256/15120/1248 bytes. */
static unsigned nv_A(unsigned a) {
    if (g_nv_img0 && g_nv_imgd && a >= g_nv_img0) return a - g_nv_img0 + g_nv_imgd;
    return a;
}
static uint8_t nv_rom8(unsigned off) {
    off = nv_A(off);
    return (nv_rom && off < nv_romlen) ? nv_rom[off] : 0;
}
static unsigned nv_rd16(unsigned off) {
    off = nv_A(off);
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
    o = nv_A(o);
    if (!nv_rom || o + 3 >= nv_romlen) return 0;
    return (uint32_t)nv_rom[o] | ((uint32_t)nv_rom[o+1] << 8) |
           ((uint32_t)nv_rom[o+2] << 16) | ((uint32_t)nv_rom[o+3] << 24);
}
/* init_nvreg, WHICH EVERY nouveau SCRIPT REGISTER ACCESS GOES THROUGH (M2379).
 *
 * Script register addresses are not raw offsets. nouveau clears the low two
 * bits, and on NV_50+ treats bits 31/30/29 as FLAGS -- +head*0x800,
 * +or*0x800, +link*0x80 -- rather than address bits. During a POST head, OR
 * and link are unset and resolve to 0, and gf100 has no .mmio hook, so for
 * this card it reduces to clearing those five bits.
 *
 * This driver did none of it, so a flagged address like 0x80xxxxxx failed
 * the 16 MiB bound below and the write was SILENTLY DROPPED. Counted, so it
 * is visible whether this ROM actually uses such addresses. */
static unsigned g_nv_reg_lowbits, g_nv_reg_flagged, g_nv_reg_oob;
static uint32_t nv_xlate(uint32_t reg) {
    if (reg & 0x3u) g_nv_reg_lowbits++;
    if (reg & 0xE0000000u) g_nv_reg_flagged++;
    reg &= ~0x00000003u;
    reg &= ~0xE0000000u;                          /* head/OR/link = 0 during POST */
    if (reg + 3 >= (16u << 20)) { g_nv_reg_oob++; return ~0u; }
    return reg;
}
static uint32_t nv_reg_rd(uint32_t reg) {
    reg = nv_xlate(reg);
    if (!nv_bar0 || reg == ~0u) return 0;
    return *(volatile uint32_t *)(nv_bar0 + reg);
}
static void nv_reg_wr(uint32_t reg, uint32_t val) {
    if (!g_nv_exec) return;                      /* dry run */
    reg = nv_xlate(reg);
    if (!nv_bar0 || reg == ~0u) return;
    *(volatile uint32_t *)(nv_bar0 + reg) = val;
}
/* VGA registers on NV_50+ live in MMIO at BAR0+0x601000 (nvkm_wrport). */
static void nv_vga_wr(unsigned port, uint8_t v) {
    if (!nv_bar0 || !g_nv_exec) return;
    *(volatile uint8_t *)(nv_bar0 + 0x601000 + port) = v;
}
static uint8_t nv_vga_rd(unsigned port) {
    if (!nv_bar0) return 0;
    return *(volatile uint8_t *)(nv_bar0 + 0x601000 + port);
}

/* A real delay, from the calibrated TSC (timer_cycles_per_ms, M2139), not a
 * guessed busy loop. Falls back to a conservative spin if uncalibrated. */
static unsigned g_nv_ctime_calls, g_nv_ctime_waited, g_nv_ctime_timeouts;
static void nv_mdelay(unsigned ms) {
    extern uint64_t timer_cycles_per_ms(void);
    uint64_t cpm = timer_cycles_per_ms();
    if (!cpm) { for (volatile unsigned long d = 0; d < 4000000ul * ms; d++) { } return; }
    uint64_t t0, t;
    __asm__ volatile("rdtsc; shl $32, %%rdx; or %%rdx, %%rax" : "=a"(t0) :: "rdx");
    do { __asm__ volatile("rdtsc; shl $32, %%rdx; or %%rdx, %%rax" : "=a"(t) :: "rdx");
    } while (t - t0 < cpm * ms);
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

/* Run a repeat body once; returns the offset just past its END_REPEAT, or 0
 * if it ran off the end. Separate from nv_run so a loop can re-enter it. */
static unsigned nv_run_body(unsigned at, int depth, int *exec, int *ops, unsigned *n);

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
            /* A POLLING WAIT, NOT A SINGLE CHECK (M2379). nouveau:
             *     wait = min(retry * 50, 100);
             *     while (wait--) { if (met) return; mdelay(20); }
             *     init_exec_set(init, false);
             * i.e. it waits up to 2 s for a condition -- a PLL locking, memory
             * training settling -- and only suspends execution if it NEVER
             * becomes true. This checked ONCE and, if the PLL had not locked
             * at that exact instant, skipped the whole block that follows.
             * Memory stopping at 512 of 2048 MiB is what that looks like. */
            uint8_t c = nv_rom[at + 1], retry = nv_rom[at + 2];
            if (*exec) {
                unsigned wait = (unsigned)retry * 50u;
                if (wait > 100) wait = 100;
                int met = 0; unsigned polls = 0;
                while (wait--) {
                    polls++;
                    if (nv_cond_met(c)) { met = 1; break; }
                    nv_mdelay(20);
                }
                if (!met) *exec = 0;
                g_nv_ctime_calls++; if (polls > 1) g_nv_ctime_waited++;
                if (!met) g_nv_ctime_timeouts++;
            }
            at += 3; break; }
        case 0x90: {                                           /* COPY_ZM_REG */
            uint32_t sreg = nv_rom32(at + 1), dreg = nv_rom32(at + 5);
            if (*exec) nv_reg_wr(dreg, nv_reg_rd(sreg));
            at += 9; break; }
        case 0x8e:                                             /* GPIO: reset all */
            if (*exec) { if (nv_gpio_reset(0xff) < 0) g_nv_skipped_gpio++; }
            at += 1; break;
        case 0xa9:                                             /* GPIO_NE */
            /* nouveau resets every GPIO whose func is NOT in the list that
             * follows; resetting all is a superset and the list is short.
             * Recorded as a known deviation rather than hidden. */
            if (*exec) { if (nv_gpio_reset(0xff) < 0) g_nv_skipped_gpio++; }
            at += 2 + (unsigned)nv_rom[at + 1]; break;
        case 0x8c:                                             /* RESET_BEGUN */
        case 0x8d:                                             /* RESET_END   */
            at += 1; break;                                    /* no register effect */
        case 0x33: {
            /* REPEAT IS A LOOP, AND TREATING IT AS A 2-BYTE SKIP WAS A REAL
             * BUG (M2378). nouveau runs the body `count` times: it records
             * the position after the header, re-executes from there, and
             * END_REPEAT (0x36) terminates each pass. Skipping it executed
             * every repeated block exactly ONCE.
             *
             * That matters because nouveau POSTs this very card from cold
             * using these same scripts -- so a devinit that runs them and
             * does not POST it is running them WRONG, not running the wrong
             * thing. Loops are the obvious candidate: memory training and
             * PLL settling are exactly the work a VBIOS repeats. */
            unsigned cnt = nv_rom[at + 1];
            unsigned body = at + 2, endp = body;
            for (unsigned k = 0; k < cnt && k < 256; k++) {
                unsigned sub_ops = 0;
                endp = nv_run_body(body, depth, exec, ops, &sub_ops);
                if (!endp) return -1;
            }
            at = endp; break; }
        case 0x36:                                             /* END_REPEAT */
            return (int)at + 1;                                /* ends one pass */
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
        case 0x53: {                                           /* ZM_CR */
            /* NOT LEGACY PORT I/O AFTER ALL (M2378). I skipped 0x53 and 0x69
             * believing they needed VGA ports the guest cannot reach with
             * vfio's disable_vga=1. nouveau's nvkm_wrport shows otherwise:
             * on NV_50 and later, VGA registers are MMIO-mapped --
             *     nvkm_wr08(device, 0x601000 + port, data)
             * -- so they go through BAR0 like everything else, and the two
             * most likely load-bearing skips become implementable.
             * ZM_CR is CRTC index/data at 0x3d4/0x3d5. */
            uint8_t idx = nv_rom[at + 1], val = nv_rom[at + 2];
            if (*exec) { nv_vga_wr(0x03d4, idx); nv_vga_wr(0x03d5, val); }
            at += 3; break; }
        case 0x69: {                                           /* IO */
            unsigned port = nv_rd16(at + 1);
            uint8_t mask = nv_rom[at + 3], data = nv_rom[at + 4];
            if (*exec) {
                /* nouveau special-cases exactly this on NV_50+: port 0x03c3
                 * with data 1 is not a port write at all, it is four MMIO
                 * masks and a delay. Reproduced rather than approximated. */
                if (port == 0x03c3 && data == 0x01) {
                    nv_reg_wr(0x614100, (nv_reg_rd(0x614100) & ~0xf0800000u) | 0x00800000u);
                    nv_reg_wr(0x00e18c, (nv_reg_rd(0x00e18c) & ~0x00020000u) | 0x00020000u);
                    nv_reg_wr(0x614900, (nv_reg_rd(0x614900) & ~0xf0800000u) | 0x00800000u);
                    nv_reg_wr(0x000200, (nv_reg_rd(0x000200) & ~0x40000000u));
                    for (volatile unsigned d = 0; d < 400000u; d++) { }   /* ~10 ms */
                } else {
                    nv_vga_wr(port, (uint8_t)((nv_vga_rd(port) & mask) | data));
                }
            }
            at += 5; break; }
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

static unsigned nv_run_body(unsigned at, int depth, int *exec, int *ops, unsigned *n) {
    /* One pass of a REPEAT body: reuse nv_run, which returns the offset after
     * END_REPEAT as a positive value. */
    int r = nv_run(at, depth, exec, ops);
    (void)n;
    return r > 0 ? (unsigned)r : 0;
}


/* VRAM SIZE, THE WAY NOUVEAU ACTUALLY GETS IT (M2378).
 *
 * The previous check read 0x022548 as an "FBPA count" -- a register I made up.
 * It is not how nouveau sizes memory, so "the FB is not answering" was partly
 * a finding about my own invention. gf100_ram_ctor + gf100_ram_probe_fbp:
 *
 *   fbps  = rd32(0x022438)                  number of FBPs
 *   fbpao = rd32(0x022554)                  bit n set = FBP n disabled
 *   size  = rd32(0x11020c + fbp * 0x1000)   MiB behind FBP n
 *
 * The GT 710 has a known answer: nouveau printed "fb: 2048 MiB GDDR5" for this
 * exact card. So this probe can be WRONG in a way that shows, which is the
 * only kind worth having. Read before and after devinit for a real pair. */
/* PASCAL SIZES VRAM FROM ONE REGISTER (M2382).
 *
 * The probe below ports gf100_ram_ctor + gf108_ram_probe_fbp_amount, which is
 * right for Kepler (gk104_ram) and WRONG for GP108: its fb is gp102_fb, whose
 * ram is gp102_ram_new, which never probes FBPAs at all -- it asks
 * fb->func->vidmem.size, i.e. gp102_fb_vidmem_size:
 *
 *     data = rd32(0x100ce0);
 *     size = (u64)((data >> 4) & 0x3f) << ((data & 0xf) + 20);
 *     if (data & 0x40000000) size = size / 16 * 15;
 *
 * The "PRI error, FB not up" after the GT 1030 POSTed (M2381) was this
 * driver reading 0x022554 and 0x11020c -- Fermi/Kepler registers that do not
 * exist on Pascal. Checked which variant GP108 lands on before porting it;
 * the two before it had both been the wrong one. */
/* THE CLOCK CEILING, MEASURED EARLY (M2383).
 *
 * The goal's own risk clause: nouveau cannot reclock Pascal -- nv138_chipset
 * has NO .clk entry, while GP10B right below it does -- so the card runs at
 * whatever the VBIOS devinit left it at, and 30 fps depends on that number.
 *
 * The VBIOS does not answer it: this ROM's perf table is version 0x50 and its
 * vpstate 0x20, and nouveau parses neither (0x40 and 0x10 only). I decoded
 * them with the older layouts once and got "5700 MHz" -- discarded.
 *
 * So read the hardware. This is gk104_clk's read path, which nouveau also
 * uses for Maxwell1 (GM107): the same PLL block at 0x137000 on every part it
 * drives. It is READ-ONLY. It is also UNVERIFIED on Pascal -- the raw
 * registers are printed beside every decoded value, so a wrong layout shows
 * up as an impossible number rather than as a plausible lie. The definitive
 * figure is a timed shader, once GR runs. */
static uint64_t g_nv_bar1_phys, g_nv_bar1_size;
static unsigned g_nv_vram_mib;
static uint32_t g_nv_crystal;
static uint32_t nv_clk_pll(uint32_t pll, int depth);
static uint32_t nv_clk_vco(uint32_t dsrc, int depth) {
    return nv_clk_pll((nv_reg_rd(dsrc) & 0x100) ? 0x00e820 : 0x00e800, depth + 1);
}
static uint32_t nv_clk_div(int doff, uint32_t dsrc, uint32_t dctl, int depth) {
    uint32_t ssrc = nv_reg_rd(dsrc + doff * 4), sctl = nv_reg_rd(dctl + doff * 4);
    switch (ssrc & 3) {
    case 0:  return ((ssrc & 0x30000) != 0x30000) ? g_nv_crystal : 108000;
    case 2:  return 100000;
    case 3: {
        uint32_t v = nv_clk_vco(dsrc + doff * 4, depth);
        return (sctl & 0x80000000u) ? v * 2 / ((sctl & 0x3f) + 2) : v;
    }
    default: return 0;
    }
}
static uint32_t nv_clk_pll(uint32_t pll, int depth) {
    if (depth > 4) return 0;
    uint32_t ctrl = nv_reg_rd(pll), coef = nv_reg_rd(pll + 4);
    uint32_t P = (coef >> 16) & 0x3f, N = (coef >> 8) & 0xff, M = coef & 0xff, ref;
    uint16_t fN = 0xf000;
    if (!(ctrl & 1) || !M) return 0;
    switch (pll) {
    case 0x00e800: case 0x00e820: ref = g_nv_crystal; P = 1; break;
    case 0x132000: ref = nv_clk_pll(0x132020, depth + 1); P = (coef & 0x10000000u) ? 2 : 1; break;
    case 0x132020: ref = nv_clk_div(0, 0x137320, 0x137330, depth + 1); fN = nv_reg_rd(pll + 0x10) >> 16; break;
    case 0x137000: case 0x137020: case 0x137040: case 0x1370e0:
        ref = nv_clk_div((pll & 0xff) / 0x20, 0x137120, 0x137140, depth + 1); break;
    default: return 0;
    }
    if (!P) P = 1;
    uint64_t v = (uint64_t)ref * N + (((uint64_t)(uint16_t)(fN + 4096) * ref) >> 13);
    return (uint32_t)(v / (M * P));
}
static uint32_t nv_clk_read(int idx) {
    uint32_t sctl = nv_reg_rd(0x137250 + idx * 4), sclk, sdiv;
    if (idx < 7) {
        if (nv_reg_rd(0x137100) & (1u << idx)) { sclk = nv_clk_pll(0x137000 + idx * 0x20, 0); sdiv = 1; }
        else                                    { sclk = nv_clk_div(idx, 0x137160, 0x1371d0, 0); sdiv = 0; }
    } else {
        uint32_t ssrc = nv_reg_rd(0x137160 + idx * 4);
        sclk = nv_clk_div(idx, 0x137160, 0x1371d0, 0); sdiv = 0;
        if ((ssrc & 3) == 3 && (ssrc & 0x100)) {
            if (ssrc & 0x40000000u) sclk = nv_clk_pll(0x1370e0, 0);
            sdiv = 1;
        }
    }
    if (sctl & 0x80000000u) {
        sdiv = sdiv ? ((sctl >> 8) & 0x3f) + 2 : (sctl & 0x3f) + 2;
        return sclk * 2 / sdiv;
    }
    return sclk;
}
static void nv_clk_report(const char *when) {
    uint32_t strap = nv_reg_rd(0x101000) & 0x00400040u;
    g_nv_crystal = strap == 0x00400000u ? 27000 : strap == 0x00400040u ? 25000
                 : strap == 0x00000040u ? 14318 : 13500;
    kprintf("[nv] clk %s: raw 137100=%08x 137000=%08x/%08x 137250=%08x 137120=%08x 137140=%08x 1373f4=%08x 132000=%08x/%08x 132020=%08x/%08x\n",
            when, nv_reg_rd(0x137100), nv_reg_rd(0x137000), nv_reg_rd(0x137004), nv_reg_rd(0x137250),
            nv_reg_rd(0x137120), nv_reg_rd(0x137140), nv_reg_rd(0x1373f4),
            nv_reg_rd(0x132000), nv_reg_rd(0x132004), nv_reg_rd(0x132020), nv_reg_rd(0x132024));
    uint32_t mem = 0, m = nv_reg_rd(0x1373f4) & 0xf;
    if (m == 1) mem = nv_clk_pll(0x132020, 0); else if (m == 2) mem = nv_clk_pll(0x132000, 0);
    uint32_t gpcpll = nv_reg_rd(0x137000);
    if ((gpcpll & 0xFFF00000u) == 0xBAD00000u)
        kprintf("[nv] clk %s: GPC PLL 0x137000 reads %08x -- a PRI error, so NO gpc clock is claimed. "
                "On Pascal the clock block answers only NVIDIA's signed PMU firmware, which is why "
                "nouveau has no .clk for GP108; the GPC number must come from timing real work.\n",
                when, gpcpll);
    kprintf("[nv] clk %s: crystal %u kHz | mem %u MHz  pmu %u MHz%s  (Kepler-layout decode, UNVERIFIED on Pascal; "
            "GT 1030 GDDR5 is rated 1502 MHz, core 1227 base / 1468 boost)\n",
            when, g_nv_crystal, mem / 1000, nv_clk_read(0x0c) / 1000,
            ((gpcpll & 0xFFF00000u) == 0xBAD00000u) ? "" : "  (gpc/rop decoded below)");
    if ((gpcpll & 0xFFF00000u) != 0xBAD00000u)
        kprintf("[nv] clk %s: gpc %u MHz  rop %u MHz\n", when, nv_clk_read(0) / 1000, nv_clk_read(1) / 1000);
}

/* THE GPU MMU, PROVEN BY A ROUND TRIP (M2384).
 *
 * Goal step 4. Everything after this -- channels, pushbuffers, GR, Mesa's
 * buffer objects -- lives behind the card's own page tables, so the first
 * thing to establish is that we can build them and that the card walks them.
 *
 * Pascal's MMU is "version 2": five levels for 4 KiB pages, per nouveau's
 * gp100_vmm_desc_12 and NVIDIA's published dev_mmu.h --
 *     PD3 2 bits | PD2 9 | PD1 9 | PD0 8 (16-byte DUAL entries) | PT 9 | 12
 *     PDE        = aperture << 1 | addr >> 4        (VRAM aperture = 1)
 *     dual PDE   = { big-page PDE, SMALL-page PDE } (small in the high qword)
 *     PTE        = valid | aperture << 1 | addr >> 4 | kind << 56  (VRAM = 0)
 * and an instance block holding the PD3 address at 0x200 (bit 10 = ver2
 * format, bit 11 = 64 KiB big pages, as gp100_vmm_join) and the limit at
 * 0x208. BAR1 -- PCI BAR1, the CPU's window onto VRAM -- is bound to that
 * block through 0x1704, exactly as gf100_bar_bar1_init.
 *
 * Everything is built in VRAM through the PRAMIN window (0x1700), which is
 * how this driver already reads the VBIOS shadow, so no step depends on a
 * mapping this test is trying to create.
 *
 * THE ORACLE IS TRANSLATION, NOT ACCESS. BAR1 page N is mapped to VRAM page
 * (3 - N): a reversed mapping. An identity window, a BAR that ignores the
 * page tables, or a PRAMIN alias would all return page N's own tag; only a
 * card walking OUR tables returns page (3 - N)'s. Then the write direction:
 * a word stored through BAR1 must appear at the translated address when read
 * back through PRAMIN. */
#define NV_MMU_BASE   0x10000000u          /* 256 MiB into VRAM: clear of the VGA/VBIOS areas */
#define NV_MMU_INST   (NV_MMU_BASE + 0x0000)
#define NV_MMU_PD3    (NV_MMU_BASE + 0x1000)
#define NV_MMU_PD2    (NV_MMU_BASE + 0x2000)
#define NV_MMU_PD1    (NV_MMU_BASE + 0x3000)
#define NV_MMU_PD0    (NV_MMU_BASE + 0x4000)
#define NV_MMU_PT     (NV_MMU_BASE + 0x5000)
#define NV_MMU_DATA   (NV_MMU_BASE + 0x100000)
static uint32_t g_nv_pramin_win = 0xffffffffu;
static void nv_vram_win(uint32_t a) {
    if ((a >> 16) != g_nv_pramin_win) { g_nv_pramin_win = a >> 16; nv_reg_wr(0x1700, g_nv_pramin_win); }
}
static void nv_vram_wr32(uint32_t a, uint32_t v) {
    nv_vram_win(a); *(volatile uint32_t *)(nv_bar0 + 0x700000 + (a & 0xffff)) = v;
}
static uint32_t nv_vram_rd32(uint32_t a) {
    nv_vram_win(a); return *(volatile uint32_t *)(nv_bar0 + 0x700000 + (a & 0xffff));
}
static void nv_vram_wr64(uint32_t a, uint64_t v) { nv_vram_wr32(a, (uint32_t)v); nv_vram_wr32(a + 4, (uint32_t)(v >> 32)); }
static int nv_wait(uint32_t reg, uint32_t mask, uint32_t want, unsigned ms) {
    for (unsigned t = 0; t <= ms; t++) {
        if ((nv_reg_rd(reg) & mask) == want) return 1;
        nv_mdelay(1);
    }
    return 0;
}
static volatile uint32_t *g_nv_b1;
static int nv_mmu_bar1_test(void) {
    if (!g_nv_bar1_phys || g_nv_bar1_size < (1u << 20)) { kprintf("[nv] mmu: no BAR1 aperture recorded -- skipped\n"); return 0; }
    if (g_nv_vram_mib < 512) { kprintf("[nv] mmu: VRAM not verified (%u MiB) -- skipped\n", g_nv_vram_mib); return 0; }
    uint32_t saved1700 = nv_reg_rd(0x1700);
    g_nv_pramin_win = 0xffffffffu;

    /* zero every table page: a zero entry is an invalid one */
    for (uint32_t a = NV_MMU_INST; a < NV_MMU_PT + 0x1000; a += 4) nv_vram_wr32(a, 0);
    /* tag four data pages and scribble a sentinel over their write slot */
    for (int n = 0; n < 4; n++) {
        nv_vram_wr32(NV_MMU_DATA + n * 0x1000,       0xC0DE0000u | n);
        nv_vram_wr32(NV_MMU_DATA + n * 0x1000 + 0x40, 0x5EED0000u | n);
    }
    nv_vram_wr64(NV_MMU_PD3, (1ull << 1) | (NV_MMU_PD2 >> 4));
    nv_vram_wr64(NV_MMU_PD2, (1ull << 1) | (NV_MMU_PD1 >> 4));
    nv_vram_wr64(NV_MMU_PD1, (1ull << 1) | (NV_MMU_PD0 >> 4));
    nv_vram_wr64(NV_MMU_PD0 + 0, 0);                                   /* no big-page table */
    nv_vram_wr64(NV_MMU_PD0 + 8, (1ull << 1) | (NV_MMU_PT >> 4));      /* small-page table   */
    for (int n = 0; n < 4; n++)                                        /* REVERSED mapping   */
        nv_vram_wr64(NV_MMU_PT + n * 8, 1ull | ((uint64_t)(NV_MMU_DATA + (3 - n) * 0x1000) >> 4));
    nv_vram_wr64(NV_MMU_INST + 0x200, (1ull << 10) | (1ull << 11) | NV_MMU_PD3);
    nv_vram_wr64(NV_MMU_INST + 0x208, g_nv_bar1_size - 1);
    /* read one table entry back: if PRAMIN writes do not land, say so here */
    uint32_t pt0 = nv_vram_rd32(NV_MMU_PT), inst200 = nv_vram_rd32(NV_MMU_INST + 0x200);
    kprintf("[nv] mmu: tables built in VRAM @%x (PT[0] reads back %08x, inst+0x200 %08x)\n",
            NV_MMU_BASE, pt0, inst200);
    nv_reg_wr(0x1700, saved1700); g_nv_pramin_win = 0xffffffffu;

    uint32_t old1704 = nv_reg_rd(0x1704);
    nv_reg_wr(0x1704, 0x80000000u | (NV_MMU_INST >> 12));
    int bound = nv_wait(0x1710, 0x3, 0, 2000);
    /* invalidate: gf100_vmm_invalidate with gp100's 64-bit PDB, PAGE_ALL|HUB_ONLY */
    int slot = 0;                                    /* ANY free slot, not all of them */
    for (unsigned t = 0; t <= 2000 && !(slot = !!(nv_reg_rd(0x100c80) & 0x00ff0000u)); t++) nv_mdelay(1);
    uint64_t pdb = (uint64_t)(NV_MMU_PD3 >> 12) << 4;                  /* aperture 0 = VRAM */
    nv_reg_wr(0x100cb8, (uint32_t)pdb);
    nv_reg_wr(0x100cec, (uint32_t)(pdb >> 32));
    nv_reg_wr(0x100cbc, 0x80000000u | 0x1 | 0x4);
    int inval = nv_wait(0x100c80, 0x00008000u, 0x00008000u, 2000);
    kprintf("[nv] mmu: BAR1 bound (0x1704 %08x -> %08x, 0x1710 %s), invalidate slot %s / %s\n",
            old1704, nv_reg_rd(0x1704), bound ? "idle" : "STUCK BUSY",
            slot ? "free" : "none", inval ? "queued" : "NOT ACKED");

    volatile uint32_t *b1 = (volatile uint32_t *)map_mmio(g_nv_bar1_phys, 0x20000);
    if (!b1) { kprintf("[nv] mmu: could not map BAR1\n"); return 0; }
    g_nv_b1 = b1;
    int ok_rd = 0;
    for (int n = 0; n < 4; n++) {
        uint32_t v = b1[n * 0x400], want = 0xC0DE0000u | (3 - n);
        kprintf("[nv] mmu: BAR1 page %d reads %08x (tag of VRAM page %d would be %08x) %s\n",
                n, v, 3 - n, want, v == want ? "TRANSLATED" : v == (0xC0DE0000u | n) ? "IDENTITY -- tables ignored" : "WRONG");
        ok_rd += v == want;
    }
    b1[0x10] = 0xB1A5B1A5u;                                            /* BAR1 page 0, +0x40 */
    nv_reg_wr(0x070000, 1);
    int fl = nv_wait(0x070000, 0x2, 0, 2000);
    g_nv_pramin_win = 0xffffffffu;
    uint32_t landed = nv_vram_rd32(NV_MMU_DATA + 3 * 0x1000 + 0x40);   /* page 0 -> VRAM page 3 */
    uint32_t other  = nv_vram_rd32(NV_MMU_DATA + 0 * 0x1000 + 0x40);
    nv_reg_wr(0x1700, saved1700); g_nv_pramin_win = 0xffffffffu;
    kprintf("[nv] mmu: write via BAR1 page 0 -> VRAM page 3 reads %08x (want b1a5b1a5), page 0 still %08x (want 5eed0000), flush %s\n",
            landed, other, fl ? "done" : "TIMED OUT");
    int pass = ok_rd == 4 && landed == 0xB1A5B1A5u && other == 0x5EED0000u;
    kprintf("[nv] mmu: %s -- %s\n", pass ? "PASS" : "FAIL",
            pass ? "the card walks OUR five-level page tables, both directions"
                 : "see the lines above for which direction broke");
    return pass;
}

/* WHICH ENGINE IS ON WHICH RUNLIST (M2384) -- read-only, gk104_top_parse.
 *
 * The first channel must NOT go on the GR runlist: switching GR's context is
 * FECS's job, and FECS is signed firmware that is not loaded yet, so a GR
 * channel would hang at its first context load. A copy engine's context is
 * switched by the host itself. The device-info table at 0x22700 names every
 * engine with its runlist, and 0x2390+i*4 says which runlists each PBDMA
 * serves (gk104_fifo_oneinit), so this is where the first channel's home is
 * read, not assumed. */
static int g_nv_ce_runl = -1, g_nv_ce_reset = -1, g_nv_gr_runl = -1, g_nv_ce_pbdma = -1;
static uint32_t g_nv_npbdma;
static struct { uint32_t type; int runl, reset; } g_nv_eng[16];
static int g_nv_neng;
static void nv_top_report(void) {
    static const char *const names[] = { "GR", "CE0", "CE1", "CE2", "?", "?", "?", "?", "MSPDEC", "MSPPP",
                                         "MSVLD", "MSENC", "VIC", "SEC2", "NVENC", "NVENC1", "NVDEC", "?",
                                         "IOCTRL", "LCE", "GSP", "NVJPG" };
    uint32_t type = ~0u, inst = 0, addr = 0; int runl = -1, eng = -1, reset = -1, intr = -1, fault = -1, n = 0;
    for (int i = 0; i < 64; i++) {
        uint32_t d = nv_reg_rd(0x022700 + i * 4);
        if ((d & 0xFFF00000u) == 0xBAD00000u) { kprintf("[nv] top: entry %d reads %08x -- PRI error, table not readable\n", i, d); return; }
        switch (d & 3) {
        case 0: continue;
        case 1:
            inst = (d >> 26) & 0xf; addr = d & 0x00fff000u;
            if (d & 4) fault = (d >> 3) & 0x7f;
            break;
        case 2:
            if (d & 0x20) eng   = (d >> 26) & 0xf;
            if (d & 0x10) runl  = (d >> 21) & 0xf;
            if (d & 0x08) intr  = (d >> 15) & 0x1f;
            if (d & 0x04) reset = (d >> 9) & 0x1f;
            break;
        case 3: type = (d >> 2) & 0x1fffffff; break;
        }
        if (d & 0x80000000u) continue;
        const char *nm = type < sizeof(names) / sizeof(names[0]) ? names[type] : "?";
        kprintf("[nv] top: %s inst %u  runlist %d  engine %d  addr %06x  reset %d  intr %d  fault %d\n",
                nm, inst, runl, eng, addr, reset, intr, fault);
        if (g_nv_neng < 16) { g_nv_eng[g_nv_neng].type = type; g_nv_eng[g_nv_neng].runl = runl; g_nv_eng[g_nv_neng].reset = reset; g_nv_neng++; }
        if (type == 0) g_nv_gr_runl = runl;
        type = ~0u; inst = 0; addr = 0; runl = eng = reset = intr = fault = -1; n++;
    }
    uint32_t npb = nv_reg_rd(0x002004) & 0xff;
    g_nv_npbdma = npb;
    kprintf("[nv] top: %d engine(s); %u PBDMA(s):", n, npb);
    for (uint32_t i = 0; i < npb && i < 16; i++) kprintf(" pbdma%u->runlists %03x", i, nv_reg_rd(0x002390 + i * 4));
    /* A COPY ENGINE THAT DOES NOT SHARE GR'S RUNLIST (M2385). The first
     * version took the first CE it saw -- LCE0, which on GP108 sits on
     * runlist 0 WITH GR, so the channel landed on the one runlist this
     * comment says to avoid, and never ran. */
    for (int e = 0; e < g_nv_neng && g_nv_ce_runl < 0; e++) {
        uint32_t t = g_nv_eng[e].type;
        if ((t == 1 || t == 2 || t == 3 || t == 0x13) && g_nv_eng[e].runl >= 0 && g_nv_eng[e].runl != g_nv_gr_runl) {
            g_nv_ce_runl = g_nv_eng[e].runl; g_nv_ce_reset = g_nv_eng[e].reset;
        }
    }
    for (uint32_t i = 0; i < npb && i < 16 && g_nv_ce_runl >= 0; i++)
        if (nv_reg_rd(0x002390 + i * 4) & (1u << g_nv_ce_runl)) { g_nv_ce_pbdma = (int)i; break; }
    kprintf("\n[nv] top: GR is on runlist %d; first channel goes on runlist %d (a copy engine of its own: "
            "host-switched, no firmware), served by PBDMA %d\n", g_nv_gr_runl, g_nv_ce_runl, g_nv_ce_pbdma);
}


/* THE FIRST CHANNEL: THE CARD EXECUTES A COMMAND STREAM OF OURS (M2385).
 *
 * The smallest proof that the command processor runs our work, with no
 * firmware anywhere in the path: one channel, one GPFIFO entry, one five-word
 * pushbuffer whose only job is a host SEMAPHORE RELEASE -- a PBDMA method
 * (0x10-0x1c, class-independent), so neither GR nor FECS is involved. If the
 * payload appears at the semaphore's address and USERD's GP_GET advances to
 * GP_PUT, the host fetched our GPFIFO through our page tables, parsed our
 * method header, and wrote memory on our behalf.
 *
 * Every step is nouveau's, for the chip it actually uses:
 *   gm107_chan    bind = 0x800000 <- 0x80000000 | inst>>12, start = 0x800004 |= 0x400
 *   gk104 ramfc   the RAMFC words at 0x08..0xfc (USERD, GP_BASE, limit2, devm = BIT(0))
 *   gp100 runl    a TSG header (gk110_runl_insert_cgrp, .force on gp100) then the
 *                 channel: chid | runq<<14, inst>>12; commit 0x2270/0x2274,
 *                 wait for 0x2284 pending to clear
 *   gk104 fifo    0x2254 = 0x10000000 | USERD's BAR1 address >> 12; PBDMAs on via
 *                 0x204; gk208 runq init
 * and the channel lives on a COPY ENGINE's runlist, read from the TOP table,
 * because a GR channel's first context load needs FECS.
 *
 * FIFO and PBDMA interrupts stay MASKED: OS-DEV has no NVIDIA interrupt
 * handler yet, and an unmasked line would storm. Their status registers
 * latch regardless and are read back below.
 *
 * GPU VA 0x10000-0x1ffff maps 1:1 onto VRAM NV_MMU_BASE + VA, in the same
 * page tables the BAR1 test proved, so the CPU reaches every structure
 * through BAR1 at the same offset the GPU uses. */
#define NV_CH_INST    0x10000u
#define NV_CH_USERD   0x11000u
#define NV_CH_RUNL    0x12000u
#define NV_CH_GPFIFO  0x13000u
#define NV_CH_PUSH    0x14000u
#define NV_CH_SEM     0x15000u
#define NV_CH_PAYLOAD 0xFACE1030u
static void nv_channel_test(void) {
    if (g_nv_ce_runl < 0 || !g_nv_b1) { kprintf("[nv] chan: no copy-engine runlist or no BAR1 -- skipped\n"); return; }
    int runl = g_nv_ce_runl;
    uint32_t saved1700 = nv_reg_rd(0x1700);
    g_nv_pramin_win = 0xffffffffu;

    /* engines on: PFIFO (bit 8) and the copy engine's own reset bit; PBDMAs via 0x204 */
    uint32_t pmc0 = nv_reg_rd(0x000200), want = pmc0 | 0x100u | (g_nv_ce_reset >= 0 ? 1u << g_nv_ce_reset : 0);
    nv_reg_wr(0x000200, want);
    uint32_t pbmask = g_nv_npbdma >= 32 ? 0xffffffffu : (1u << g_nv_npbdma) - 1;
    nv_reg_wr(0x000204, pbmask);
    for (uint32_t i = 0; i < g_nv_npbdma && i < 16; i++) {                /* gk208_runq_init */
        uint32_t o = i * 0x2000;
        nv_reg_wr(0x04013c + o, nv_reg_rd(0x04013c + o) & ~0x10000100u);
        nv_reg_wr(0x040108 + o, 0xffffffffu);
        nv_reg_wr(0x040148 + o, 0xffffffffu);
        nv_reg_wr(0x04012c + o, 0x000f4240u);
    }
    nv_reg_wr(0x002a04, nv_reg_rd(0x002a04) | 0xbfffffffu);
    nv_reg_wr(0x002100, 0xffffffffu);
    kprintf("[nv] chan: PMC 0x200 %08x -> %08x, 0x204 = %08x (%u PBDMAs), CE reset bit %d, runlist %d\n",
            pmc0, nv_reg_rd(0x000200), nv_reg_rd(0x000204), g_nv_npbdma, g_nv_ce_reset, runl);

    /* the structures, zeroed, then filled -- all in VRAM through PRAMIN */
    for (uint32_t a = NV_CH_INST; a < NV_CH_SEM + 0x1000; a += 4) nv_vram_wr32(NV_MMU_BASE + a, 0);
    nv_vram_wr32(NV_MMU_BASE + NV_CH_SEM, 0xDEADDEADu);                   /* sentinel */
    const uint32_t hdr = 0x20000000u | (4u << 16) | (0u << 13) | (0x0010u >> 2);
    const uint32_t push[5] = { hdr, 0, NV_CH_SEM, NV_CH_PAYLOAD, 0x01000002u }; /* SEM A,B,C,D = RELEASE, 4 bytes */
    for (int i = 0; i < 5; i++) nv_vram_wr32(NV_MMU_BASE + NV_CH_PUSH + i * 4, push[i]);
    nv_vram_wr32(NV_MMU_BASE + NV_CH_GPFIFO + 0, NV_CH_PUSH);
    nv_vram_wr32(NV_MMU_BASE + NV_CH_GPFIFO + 4, 5u << 10);              /* length in dwords */
    const uint32_t ci = NV_MMU_BASE + NV_CH_INST, userd = NV_MMU_BASE + NV_CH_USERD;
    nv_vram_wr32(ci + 0x08, userd);            nv_vram_wr32(ci + 0x0c, 0);
    nv_vram_wr32(ci + 0x10, 0x0000face);       nv_vram_wr32(ci + 0x30, 0xfffff902);
    nv_vram_wr32(ci + 0x48, NV_CH_GPFIFO);     nv_vram_wr32(ci + 0x4c, 9u << 16);   /* 512 entries */
    nv_vram_wr32(ci + 0x84, 0x20400000);       nv_vram_wr32(ci + 0x94, 0x30000000 | 1u);
    nv_vram_wr32(ci + 0x9c, 0x00000100);       nv_vram_wr32(ci + 0xac, 0x0000001f);
    nv_vram_wr32(ci + 0xe4, 0);                nv_vram_wr32(ci + 0xe8, 0);          /* not priv; chid 0 */
    nv_vram_wr32(ci + 0xb8, 0xf8000000);       nv_vram_wr32(ci + 0xf8, 0x10003080);
    nv_vram_wr32(ci + 0xfc, 0x10000010);
    nv_vram_wr64(ci + 0x200, (1ull << 10) | (1ull << 11) | NV_MMU_PD3);  /* same VMM as BAR1 */
    nv_vram_wr64(ci + 0x208, g_nv_bar1_size - 1);
    const uint32_t rl = NV_MMU_BASE + NV_CH_RUNL;
    nv_vram_wr32(rl + 0, (1u << 26) | (128u << 18) | (3u << 14) | 0x2000u | 0);  /* TSG 0, 1 channel */
    nv_vram_wr32(rl + 4, 0);
    nv_vram_wr32(rl + 8, 0 | (0u << 14));                                /* chid 0, runq 0 */
    nv_vram_wr32(rl + 12, ci >> 12);
    for (uint32_t va = 0x10000; va < 0x20000; va += 0x1000)               /* VA -> NV_MMU_BASE + VA */
        nv_vram_wr64(NV_MMU_PT + (va >> 12) * 8, 1ull | ((uint64_t)(NV_MMU_BASE + va) >> 4));
    uint32_t chk = nv_vram_rd32(NV_MMU_BASE + NV_CH_PUSH);
    nv_reg_wr(0x1700, saved1700); g_nv_pramin_win = 0xffffffffu;

    for (unsigned t = 0; t <= 2000 && !(nv_reg_rd(0x100c80) & 0x00ff0000u); t++) nv_mdelay(1);
    uint64_t pdb = (uint64_t)(NV_MMU_PD3 >> 12) << 4;
    nv_reg_wr(0x100cb8, (uint32_t)pdb); nv_reg_wr(0x100cec, (uint32_t)(pdb >> 32));
    nv_reg_wr(0x100cbc, 0x80000000u | 0x1);                               /* PAGE_ALL, every TLB */
    int inval = nv_wait(0x100c80, 0x00008000u, 0x00008000u, 2000);
    uint32_t viab1 = g_nv_b1[NV_CH_PUSH / 4];
    kprintf("[nv] chan: structures built (push[0] %08x via PRAMIN, %08x via BAR1), TLB invalidate %s\n",
            chk, viab1, inval ? "queued" : "NOT ACKED");

    nv_reg_wr(0x002254, 0x10000000u | (NV_CH_USERD >> 12));
    nv_reg_wr(0x800000, 0x80000000u | (ci >> 12));                        /* bind chid 0 */
    nv_reg_wr(0x800004, nv_reg_rd(0x800004) | 0x400u);                    /* enable */
    uint32_t blk = nv_reg_rd(0x002630);                                   /* gk104_runl_allow */
    nv_reg_wr(0x002630, blk & ~(1u << runl));
    nv_reg_wr(0x002270, (0u << 28) | (rl >> 12));
    nv_reg_wr(0x002274, ((uint32_t)runl << 20) | 2);
    int rlok = nv_wait(0x002284 + runl * 8, 0x00100000u, 0, 2000);
    kprintf("[nv] chan: bound + enabled (0x800000 %08x, 0x800004 %08x), runlist %d committed: %s, sched block %08x -> %08x\n",
            nv_reg_rd(0x800000), nv_reg_rd(0x800004), runl, rlok ? "not pending" : "STILL PENDING",
            blk, nv_reg_rd(0x002630));

    g_nv_b1[(NV_CH_USERD + 0x8c) / 4] = 1;                                 /* GP_PUT = 1: go */
    nv_reg_wr(0x070000, 1); nv_wait(0x070000, 0x2, 0, 2000);
    uint32_t sem = 0, gpget = 0; unsigned ms = 0;
    for (; ms <= 2000; ms++) {
        sem = g_nv_b1[NV_CH_SEM / 4]; gpget = g_nv_b1[(NV_CH_USERD + 0x88) / 4];
        if (sem == NV_CH_PAYLOAD && gpget == 1) break;
        nv_mdelay(1);
    }
    uint32_t pb = g_nv_ce_pbdma >= 0 ? (uint32_t)g_nv_ce_pbdma * 0x2000 : 0;
    kprintf("[nv] chan: after %u ms: semaphore %08x (want %08x), USERD GP_GET %u (want 1), "
            "chan 0x800004 %08x (status %u), PFIFO intr %08x\n",
            ms, sem, NV_CH_PAYLOAD, gpget, nv_reg_rd(0x800004), (nv_reg_rd(0x800004) >> 24) & 0xf,
            nv_reg_rd(0x002100));
    kprintf("[nv] chan: PBDMA %d: intr0 %08x  mthd-addr %08x  data %08x  chid %08x  intr1 %08x (%08x %08x)\n",
            g_nv_ce_pbdma, nv_reg_rd(0x040108 + pb), nv_reg_rd(0x0400c0 + pb), nv_reg_rd(0x0400c4 + pb),
            nv_reg_rd(0x040120 + pb), nv_reg_rd(0x040148 + pb), nv_reg_rd(0x040150 + pb), nv_reg_rd(0x040154 + pb));
    int pass = sem == NV_CH_PAYLOAD && gpget == 1;
    kprintf("[nv] chan: %s -- %s\n", pass ? "PASS" : "FAIL",
            pass ? "the GT 1030 fetched OUR GPFIFO, parsed OUR pushbuffer, and released OUR semaphore"
                 : sem == 0xDEADDEADu ? "the semaphore was never written; see the channel/intr state above"
                                      : "the semaphore holds something unexpected");
    nv_reg_wr(0x800004, nv_reg_rd(0x800004) | 0x800u);                    /* stop: gk104_chan_stop */
}

/* NVIDIA'S SIGNED FIRMWARE, FROM OUR ROOT FILESYSTEM (M2386).
 *
 * Goal step 5 (ACR/secure boot, then FECS/GPCCS for GR) consumes the gp108
 * blobs the Makefile stages into the ext2 root -- 20 files, counted there.
 * They are read from the VFS, which does not exist yet when nvgpu_init runs
 * (PCI enumeration is long before the disks mount), and where the disks
 * mount depends on which controller they sit behind. So the late half of
 * the driver is a kernel thread that waits until the firmware is actually
 * readable, instead of a call placed at a line of kmain that is right for
 * one VM's disk layout. */
#define NV_FW_ROOT "/disk2/lib/firmware/nvidia/gp108/"
static const char *const nv_fw_files[] = {
    "acr/bl.bin", "acr/ucode_load.bin", "acr/unload_bl.bin", "acr/ucode_unload.bin",
    "gr/fecs_bl.bin", "gr/fecs_inst.bin", "gr/fecs_data.bin", "gr/fecs_sig.bin",
    "gr/gpccs_bl.bin", "gr/gpccs_inst.bin", "gr/gpccs_data.bin", "gr/gpccs_sig.bin",
    "gr/sw_ctx.bin", "gr/sw_nonctx.bin", "gr/sw_bundle_init.bin", "gr/sw_method_init.bin",
    "sec2/desc.bin", "sec2/image.bin", "sec2/sig.bin", "nvdec/scrubber.bin",
};
static uint8_t *nv_fw_load(const char *rel, unsigned *len) {
    char path[128]; unsigned n = 0;
    for (const char *p = NV_FW_ROOT; *p && n < sizeof(path) - 1; ) path[n++] = *p++;
    for (const char *p = rel; *p && n < sizeof(path) - 1; ) path[n++] = *p++;
    path[n] = 0;
    struct statx st;
    if (vfs_stat(path, &st) != 0) { kprintf("[nv] fw: %s: NOT FOUND\n", path); return NULL; }
    unsigned long sz = st.stx_size;
    uint8_t *b = kmalloc(sz ? sz : 1);
    if (!b) { kprintf("[nv] fw: %s: no memory for %lu bytes\n", path, sz); return NULL; }
    long got = vfs_read(path, b, sz);
    if (got < 0 || (unsigned long)got != sz) {         /* a short read is not a firmware image */
        kprintf("[nv] fw: %s: read %ld of %lu bytes -- refused\n", path, got, sz);
        kfree(b); return NULL;
    }
    *len = (unsigned)sz;
    return b;
}
/* ============================================================================
 * GOAL STEP 5: ACR ON SEC2 (M2387).
 *
 * On Pascal, GR's two falcons (FECS, GPCCS) will only run NVIDIA-signed code,
 * and only after the ACR -- an NVIDIA-signed "heavy secure" program -- has
 * verified them into a write-protected region (WPR) of VRAM. On GP108 the ACR
 * runs on SEC2 (gp108_acr_load_fwif: NVKM_ACR_HSF_SEC2), and SEC2's own
 * signed RTOS is then what starts FECS and GPCCS on request.
 *
 * This is nouveau's sequence, followed step by step for the chip it uses:
 *   lsfw.c        FECS/GPCCS from bl+inst+data+sig; SEC2 from sig+image+desc
 *   gp102.c       wpr_layout, wpr_build(_lsb), wpr_alloc (shadow | wpr halves),
 *                 wpr_patch (+wpr_start), load_setup (two regions, >>8)
 *   gp108.c       the ACR's own bootloader descriptor (flcn_bl_dmem_desc_v2,
 *                 ctx_dma VIRT), GR's LS descriptors (ctx_dma UCODE)
 *   falcon/fw.c   ctor_hs (0x10de indirection for patch_loc/patch_sig),
 *                 boot: patch sig -> reset -> setup -> load -> boot
 *   falcon/gm200  signature (debug fuse at +0x408), enable/disable, bind_inst,
 *                 PIO (IMEM 256-byte tagged blocks), boot + halt + mbox0
 * The oracle is 0x100cd4: the WPR bounds the memory controller enforces. Only
 * the signed ACR can program them, so reading OUR region back from there
 * means NVIDIA's firmware ran on this card, under this driver.
 * ========================================================================== */
#define SEC2_BASE       0x087000u
#define SEC2_PMC_BIT    14                     /* TOP: SEC2 reset 14 */
#define NV_ACR_INST     0x20000u               /* VRAM NV_MMU_BASE + this */
#define NV_ACR_HS_VA    0x40000u               /* HS image: VA == offset from NV_MMU_BASE */
#define NV_WPR_BASE     0x20000000u            /* 512 MiB into VRAM, 256 KiB aligned */
enum { LSF_FECS = 2, LSF_GPCCS = 3, LSF_SEC2 = 7 };
struct nv_lsfw {
    int id; uint32_t flags; int sec2;
    uint8_t *img; uint32_t img_size; uint8_t *sig; uint32_t sig_size;
    uint32_t bl_size, bl_imem_off, app_start, app_size, app_entry;
    uint32_t rc_off, rc_size, rd_off, rd_size, ucode_size, data_size;
    uint32_t off_lsb, off_img, off_bld;
};
static uint32_t le32(const uint8_t *b) { return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24; }
static void put32(uint8_t *b, uint32_t v) { b[0] = v; b[1] = v >> 8; b[2] = v >> 16; b[3] = v >> 24; }
#define ALN(x, a) (((x) + (a) - 1) & ~((uint32_t)(a) - 1))
static uint32_t fl_rd(uint32_t o) { return nv_reg_rd(SEC2_BASE + o); }
static void fl_wr(uint32_t o, uint32_t v) { nv_reg_wr(SEC2_BASE + o, v); }
static void fl_mask(uint32_t o, uint32_t m, uint32_t v) { fl_wr(o, (fl_rd(o) & ~m) | v); }

static void nv_vram_write(uint32_t a, const uint8_t *b, uint32_t len) {
    for (uint32_t i = 0; i < len; i += 4) {
        uint32_t w = 0;
        for (uint32_t k = 0; k < 4 && i + k < len; k++) w |= (uint32_t)b[i + k] << (8 * k);
        nv_vram_wr32(a + i, w);
    }
}
static void nv_mmu_invalidate(void) {
    for (unsigned t = 0; t <= 2000 && !(nv_reg_rd(0x100c80) & 0x00ff0000u); t++) nv_mdelay(1);
    uint64_t pdb = (uint64_t)(NV_MMU_PD3 >> 12) << 4;
    nv_reg_wr(0x100cb8, (uint32_t)pdb); nv_reg_wr(0x100cec, (uint32_t)(pdb >> 32));
    nv_reg_wr(0x100cbc, 0x80000000u | 0x1);
    nv_wait(0x100c80, 0x00008000u, 0x00008000u, 2000);
}
/* gm200_flcn_reset_wait_mem_scrubbing / gp102_flcn_reset_eng / enable / disable */
static int fl_scrub(void) {
    for (unsigned t = 0; t <= 10; t++) { if (!(fl_rd(0x10c) & 6)) return 1; nv_mdelay(1); }
    return 0;
}
static int fl_reset_eng(void) {
    fl_mask(0x3c0, 1, 1); nv_mdelay(1); fl_mask(0x3c0, 1, 0);
    return fl_scrub();
}
static int fl_enable(void) {
    int ok = fl_reset_eng();
    nv_reg_wr(0x000200, nv_reg_rd(0x000200) | (1u << SEC2_PMC_BIT)); (void)nv_reg_rd(0x000200);
    ok &= fl_scrub();
    fl_wr(0x084, nv_reg_rd(0x000000));
    return ok;
}
static int fl_disable(void) {
    fl_mask(0x048, 3, 0);
    fl_wr(0x014, 0xffffffffu);
    nv_reg_wr(0x000200, nv_reg_rd(0x000200) & ~(1u << SEC2_PMC_BIT)); (void)nv_reg_rd(0x000200);
    return fl_reset_eng();
}
static void fl_imem_wr(uint32_t dst, const uint8_t *b, uint32_t len, uint32_t tag, int sec) {
    fl_wr(0x180, (sec ? 1u << 28 : 0) | 1u << 24 | dst);
    for (uint32_t i = 0; i < len; i += 256, tag++) {
        fl_wr(0x188, tag);
        for (uint32_t k = 0; k < 256; k += 4) fl_wr(0x184, i + k + 3 < len ? le32(b + i + k) : 0);
    }
}
static void fl_dmem_wr(uint32_t dst, const uint8_t *b, uint32_t len) {
    fl_wr(0x1c0, 1u << 24 | dst);
    for (uint32_t i = 0; i < len; i += 4) fl_wr(0x1c4, le32(b + i));
}

static const char *nv_cat(char *n, const char *a, const char *b) {
    unsigned i = 0;
    while (*a && i < 47) n[i++] = *a++;
    while (*b && i < 47) n[i++] = *b++;
    n[i] = 0;
    return n;
}
/* nvkm_acr_lsfw_load_bl_inst_data_sig */
static int nv_lsfw_gr(struct nv_lsfw *l, int id, const char *pfx) {
    char n[48]; unsigned bl_len, in_len, da_len, sg_len;
    uint8_t *bl = nv_fw_load(nv_cat(n, pfx, "bl.bin"), &bl_len);
    uint8_t *in = nv_fw_load(nv_cat(n, pfx, "inst.bin"), &in_len);
    uint8_t *da = nv_fw_load(nv_cat(n, pfx, "data.bin"), &da_len);
    uint8_t *sg = nv_fw_load(nv_cat(n, pfx, "sig.bin"), &sg_len);
    if (!bl || !in || !da || !sg || bl_len < 24) return 0;
    uint32_t hoff = le32(bl + 12), doff = le32(bl + 16);
    if (hoff + 24 > bl_len || doff > bl_len) return 0;
    uint32_t start_tag = le32(bl + hoff + 0), code_size = le32(bl + hoff + 12);
    l->id = id; l->sec2 = 0; l->flags = id == LSF_GPCCS ? 0x8 : 0;  /* FORCE_PRIV_LOAD for GPCCS */
    l->sig = sg; l->sig_size = sg_len;
    l->bl_size = ALN(code_size, 256); l->bl_imem_off = start_tag << 8;
    l->app_start = l->bl_size; l->app_entry = 0;
    l->rc_off = 0; l->rc_size = ALN(in_len, 256);
    l->rd_off = l->rc_size; l->rd_size = ALN(da_len, 256);
    l->app_size = l->rc_size + l->rd_size;
    l->img_size = l->bl_size + l->app_size;
    l->img = kmalloc(l->img_size);
    if (!l->img) return 0;
    for (uint32_t i = 0; i < l->img_size; i++) l->img[i] = 0;
    for (uint32_t i = 0; i < l->bl_size && doff + i < bl_len; i++) l->img[i] = bl[doff + i];
    for (uint32_t i = 0; i < in_len; i++) l->img[l->app_start + l->rc_off + i] = in[i];
    for (uint32_t i = 0; i < da_len; i++) l->img[l->app_start + l->rd_off + i] = da[i];
    l->ucode_size = ALN(l->rd_off, 256) + l->bl_size;
    l->data_size = l->app_size + l->bl_size - l->ucode_size;
    kfree(bl); kfree(in); kfree(da);
    return 1;
}
/* nvkm_acr_lsfw_load_sig_image_desc_v1 + nvkm_acr_lsfw_from_desc */
static int nv_lsfw_sec2(struct nv_lsfw *l) {
    unsigned sg_len, im_len, de_len;
    uint8_t *sg = nv_fw_load("sec2/sig.bin", &sg_len), *im = nv_fw_load("sec2/image.bin", &im_len);
    uint8_t *de = nv_fw_load("sec2/desc.bin", &de_len);
    if (!sg || !im || !de || de_len < 132) return 0;
    l->id = LSF_SEC2; l->sec2 = 1; l->flags = 0;
    l->sig = sg; l->sig_size = sg_len; l->img = im; l->img_size = im_len;
    l->bl_size = ALN(le32(de + 84), 256); l->bl_imem_off = le32(de + 88);
    l->app_size = ALN(le32(de + 100), 256); l->app_start = le32(de + 96);
    l->app_entry = le32(de + 108);
    l->rc_off = le32(de + 116); l->rc_size = le32(de + 120);
    l->rd_off = le32(de + 124); l->rd_size = le32(de + 128);
    l->ucode_size = ALN(l->rd_off, 256) + l->bl_size;
    l->data_size = l->app_size + l->bl_size - l->ucode_size;
    kfree(de);
    return 1;
}

static int nv_acr_run(void) {
    static struct nv_lsfw ls[3];
    if (!nv_lsfw_gr(&ls[0], LSF_FECS, "gr/fecs_") || !nv_lsfw_gr(&ls[1], LSF_GPCCS, "gr/gpccs_") || !nv_lsfw_sec2(&ls[2])) {
        kprintf("[nv] acr: could not assemble the LS firmware -- stopped\n"); return 0;
    }
    for (int i = 0; i < 3; i++)
        if (ls[i].sig_size != 192) { kprintf("[nv] acr: falcon %d signature is %u bytes, not lsf_signature_v1's 192 -- stopped\n", ls[i].id, ls[i].sig_size); return 0; }

    /* gp102_acr_wpr_layout */
    uint32_t w = ALN(11 * 24, 256) + 0x100;
    for (int i = 0; i < 3; i++) {
        w = ALN(w, 256);  ls[i].off_lsb = w; w += 240;
        w = ALN(w, 4096); ls[i].off_img = w; w += ls[i].img_size;
        w = ALN(w, 256);  ls[i].off_bld = w; w += 256;               /* ALIGN(sizeof bl_dmem_desc_v2, 256) */
        kprintf("[nv] acr: LSF %d: lsb %05x img %05x (%u B: bl %u app %u ucode %u data %u) bld %05x\n",
                ls[i].id, ls[i].off_lsb, ls[i].off_img, ls[i].img_size, ls[i].bl_size, ls[i].app_size,
                ls[i].ucode_size, ls[i].data_size, ls[i].off_bld);
    }
    uint32_t half = ALN(w, 0x40000);
    uint32_t shadow = NV_WPR_BASE, wpr_start = shadow + half, wpr_end = wpr_start + half;
    kprintf("[nv] acr: WPR image %u bytes; shadow %08x, WPR %08x-%08x\n", w, shadow, wpr_start, wpr_end);

    /* gp102_acr_wpr_build (+ wpr_patch folded in: every DMA base gets +wpr_start) */
    uint32_t saved1700 = nv_reg_rd(0x1700); g_nv_pramin_win = 0xffffffffu;
    for (uint32_t a = 0; a < w; a += 4) nv_vram_wr32(shadow + a, 0);
    for (int i = 0; i < 3; i++) {
        struct nv_lsfw *l = &ls[i];
        uint8_t hdr[24];
        put32(hdr + 0, l->id); put32(hdr + 4, l->off_lsb); put32(hdr + 8, LSF_SEC2);
        put32(hdr + 12, l->id != LSF_SEC2); put32(hdr + 16, le32(l->sig + 80)); put32(hdr + 20, 1);
        nv_vram_write(shadow + i * 24, hdr, 24);
        uint8_t lsb[240];
        for (int k = 0; k < 192; k++) lsb[k] = l->sig[k];
        uint32_t t[12] = { l->off_img, l->ucode_size, l->data_size, l->bl_size, l->bl_imem_off, l->off_bld, 256,
                           l->app_start + l->rc_off, l->rc_size, l->app_start + l->rd_off, l->rd_size, l->flags };
        for (int k = 0; k < 12; k++) put32(lsb + 192 + k * 4, t[k]);
        nv_vram_write(shadow + l->off_lsb, lsb, 240);
        nv_vram_write(shadow + l->off_img, l->img, l->img_size);
        uint8_t bd[84];
        for (int k = 0; k < 84; k++) bd[k] = 0;
        uint64_t code = (uint64_t)wpr_start + l->off_img + l->app_start + (l->sec2 ? 0 : l->rc_off);
        uint64_t data = (uint64_t)wpr_start + l->off_img + l->app_start + l->rd_off;
        put32(bd + 32, l->sec2 ? 6 : 0);                                /* FALCON_SEC2_DMAIDX_UCODE / DMAIDX_UCODE */
        put32(bd + 36, (uint32_t)code); put32(bd + 40, (uint32_t)(code >> 32));
        put32(bd + 44, l->rc_off); put32(bd + 48, l->rc_size); put32(bd + 60, l->app_entry);
        put32(bd + 64, (uint32_t)data); put32(bd + 68, (uint32_t)(data >> 32)); put32(bd + 72, l->rd_size);
        if (l->sec2) { put32(bd + 76, 1); put32(bd + 80, 0x01000000u); } /* argc 1, argv = emem_addr */
        nv_vram_write(shadow + l->off_bld, bd, 84);
    }
    nv_vram_wr32(shadow + 3 * 24, 0xffffffffu);                         /* WPR_HEADER_V1_FALCON_ID_INVALID */
    uint32_t chk = nv_vram_rd32(shadow + 0), chk2 = nv_vram_rd32(shadow + ls[2].off_img);

    /* the HS ACR: falcon/fw.c nvkm_falcon_fw_ctor_hs on acr/ucode_load.bin + acr/bl.bin */
    unsigned hl, bll; uint8_t *hs = nv_fw_load("acr/ucode_load.bin", &hl), *blb = nv_fw_load("acr/bl.bin", &bll);
    if (!hs || !blb || le32(hs) != 0x10de || le32(blb) != 0x10de) { kprintf("[nv] acr: HS images missing or not 0x10de -- stopped\n"); goto out; }
    uint32_t hh = le32(hs + 12), hdoff = le32(hs + 16), hdsz = le32(hs + 20);
    uint32_t sig_dbg_off = le32(hs + hh + 0), sig_prod_off = le32(hs + hh + 8), sig_prod_sz = le32(hs + hh + 12);
    uint32_t loc = le32(hs + le32(hs + hh + 16)), sgo = le32(hs + le32(hs + hh + 20)), lh = le32(hs + hh + 24);
    uint32_t nsc_off = le32(hs + lh + 0), nsc_sz = le32(hs + lh + 4), dbase = le32(hs + lh + 8), dsz = le32(hs + lh + 12);
    uint32_t napps = le32(hs + lh + 16), app0 = le32(hs + lh + 20), app0sz = le32(hs + lh + 20 + 4 * napps);
    uint8_t *img = hs + hdoff;
    kprintf("[nv] acr: HS image %u B; non-sec %x+%x, sec %x+%x, data %x+%x, sig %u B patched at %x\n",
            hdsz, nsc_off, nsc_sz, app0, app0sz, dbase, dsz, sig_prod_sz, loc);
    uint32_t bhoff = le32(blb + 12), bdoff = le32(blb + 16);
    uint32_t b_tag = le32(blb + bhoff + 0), b_code_off = le32(blb + bhoff + 8), b_code_sz = le32(blb + bhoff + 12);

    /* signature: gm200_flcn_fw_signature enables the falcon, reads the debug fuse */
    fl_enable();
    int dbg = !!(fl_rd(0x408) & 0x00100000u);
    const uint8_t *sgsrc = hs + (dbg ? sig_dbg_off : sig_prod_off) + sgo;
    for (uint32_t k = 0; k < sig_prod_sz; k++) img[loc + k] = sgsrc[k];
    /* reset (disable + enable), then gp102_acr_load_setup on the descriptor at dmem_base_img */
    fl_disable(); int en = fl_enable();
    uint8_t *d = img + dbase;
    int pass = 0;
    put32(d + 0x210, 1); put32(d + 0x21c, 2);
    put32(d + 0x220, wpr_start >> 8); put32(d + 0x224, wpr_end >> 8); put32(d + 0x228, 1);
    put32(d + 0x22c, 0xf); put32(d + 0x230, 0xc); put32(d + 0x234, 0x2); put32(d + 0x238, shadow >> 8);
    /* the image into VRAM, mapped at NV_ACR_HS_VA, and an instance block for SEC2's virtual DMA */
    nv_vram_write(NV_MMU_BASE + NV_ACR_HS_VA, img, hdsz);
    for (uint32_t va = NV_ACR_HS_VA; va < NV_ACR_HS_VA + ALN(hdsz, 4096); va += 0x1000)
        nv_vram_wr64(NV_MMU_PT + (va >> 12) * 8, 1ull | ((uint64_t)(NV_MMU_BASE + va) >> 4));
    for (uint32_t a = 0; a < 0x1000; a += 4) nv_vram_wr32(NV_MMU_BASE + NV_ACR_INST + a, 0);
    nv_vram_wr64(NV_MMU_BASE + NV_ACR_INST + 0x200, (1ull << 10) | (1ull << 11) | NV_MMU_PD3);
    nv_vram_wr64(NV_MMU_BASE + NV_ACR_INST + 0x208, g_nv_bar1_size - 1);
    nv_reg_wr(0x1700, saved1700); g_nv_pramin_win = 0xffffffffu;
    nv_mmu_invalidate();
    kprintf("[nv] acr: debug fuse %s -> %s signature; falcon %s; WPR shadow reads back %08x / SEC2 img %08x\n",
            dbg ? "SET" : "clear", dbg ? "DEBUG" : "PRODUCTION", en ? "enabled" : "ENABLE TIMED OUT", chk, chk2);

    /* gm200_flcn_fw_load: bind the instance block */
    fl_mask(0x048, 1, 1);
    fl_mask(0x604, 7, 0);
    fl_wr(0x054, (1u << 30) | (0u << 28) | ((NV_MMU_BASE + NV_ACR_INST) >> 12));
    fl_mask(0x090, 0x10000, 0x10000);
    fl_mask(0x0a4, 0x8, 0x8);
    int b5 = 0, b0 = 0;
    for (unsigned t = 0; t <= 10 && !b5; t++) { b5 = (fl_rd(0x008) & 8) && ((fl_rd(0x0dc) >> 12) & 7) == 5; if (!b5) nv_mdelay(1); }
    fl_mask(0x004, 8, 8); fl_mask(0x058, 2, 2);
    for (unsigned t = 0; t <= 10 && !b0; t++) { b0 = ((fl_rd(0x0dc) >> 12) & 7) == 0; if (!b0) nv_mdelay(1); }
    /* the bootloader at the top of IMEM, then its descriptor into DMEM 0 */
    uint32_t imem = (fl_rd(0x108) & 0x1ff) << 8, boot_addr = b_tag << 8;
    fl_imem_wr(imem - b_code_sz, blb + bdoff + b_code_off, b_code_sz, b_tag, 0);
    uint8_t bd[84];
    for (int k = 0; k < 84; k++) bd[k] = 0;
    uint64_t cb = NV_ACR_HS_VA, db = (uint64_t)NV_ACR_HS_VA + dbase;
    put32(bd + 32, 1);                                                  /* FALCON_DMAIDX_VIRT */
    put32(bd + 36, (uint32_t)cb); put32(bd + 40, (uint32_t)(cb >> 32));
    put32(bd + 44, nsc_off); put32(bd + 48, nsc_sz);
    put32(bd + 52, ALN(app0, 0x100)); put32(bd + 56, app0sz);
    put32(bd + 64, (uint32_t)db); put32(bd + 68, (uint32_t)(db >> 32)); put32(bd + 72, dsz);
    fl_dmem_wr(0, bd, 84);
    kprintf("[nv] acr: SEC2 bound to our VMM (%s, %s), IMEM %u B, bootloader %u B at %x tag %x\n",
            b5 ? "bind 5" : "BIND NOT 5", b0 ? "idle" : "BIND NOT IDLE", imem, b_code_sz, imem - b_code_sz, b_tag);

    /* gm200_flcn_fw_boot */
    fl_wr(0x040, 0xcafebeefu);
    fl_wr(0x104, boot_addr);
    fl_wr(0x100, 2);
    unsigned ms = 0; int halted = 0;
    for (; ms <= 2000 && !(halted = !!(fl_rd(0x100) & 0x10)); ms++) nv_mdelay(1);
    uint32_t mb0 = fl_rd(0x040), mb1 = fl_rd(0x044);
    fl_mask(0x004, 0xffffffffu, 0x10);
    nv_reg_wr(0x100cd4, 2); uint64_t ws = (uint64_t)(nv_reg_rd(0x100cd4) & 0xffffff00u) << 8;
    nv_reg_wr(0x100cd4, 3); uint64_t wl = ((uint64_t)(nv_reg_rd(0x100cd4) & 0xffffff00u) << 8) + 0x20000;
    kprintf("[nv] acr: HS ACR %s after %u ms: mbox0 %08x (want 0) mbox1 %08x; memory controller WPR %lx-%lx (ours %x-%x)\n",
            halted ? "HALTED" : "DID NOT HALT", ms, mb0, mb1, (unsigned long)ws, (unsigned long)wl, wpr_start, wpr_end);
    pass = halted && mb0 == 0 && ws == wpr_start && wl == wpr_end;
    kprintf("[nv] acr: %s -- %s\n", pass ? "PASS" : "FAIL",
            pass ? "NVIDIA's signed ACR ran on SEC2 and locked OUR WPR" :
            mb0 == 0xcafebeefu ? "the ACR never wrote its mailbox (did not start, or trapped early)"
                               : "see mbox0 -- the ACR's own error code");
    nv_reg_wr(0x1700, saved1700); g_nv_pramin_win = 0xffffffffu;
    return pass;
out:
    nv_reg_wr(0x1700, saved1700); g_nv_pramin_win = 0xffffffffu;
    return 0;
}

/* ============================================================================
 * SEC2'S RTOS STARTS FECS AND GPCCS (M2388).
 *
 * After the ACR halts, SEC2 holds its own signed LS firmware -- an RTOS --
 * and is started with a plain falcon start (nvkm_sec2_init). It announces
 * itself with an init message in its message queue, naming where in EMEM its
 * command and message queues live (gp102_sec2_initmsg). Commands are 4-byte
 * headers (unit, size, flags, seq) + payload, pushed at the command queue's
 * head; replies come back in the message queue carrying the same seq
 * (falcon/cmdq.c, msgq.c). ACR_CMD_BOOTSTRAP_FALCON (unit 0x08) is what makes
 * SEC2 reset FECS/GPCCS and load their verified images out of the WPR.
 *
 * No interrupt handler exists, so everything nouveau does from SEC2's IRQ is
 * done here by polling the queue registers themselves.
 *
 * GR must be ENABLED in PMC first: after devinit 0x200 reads 40002121, and
 * GR's bit (12, from TOP) is clear -- a falcon cannot be reset or loaded
 * inside an engine that is switched off.
 * ========================================================================== */
/* A QUEUE ADDRESS IS DMEM OR EMEM BY VALUE (nvkm_falcon_pio): at or above
 * emem_addr (0x01000000) it is EMEM, below it the same number is DMEM. The
 * first version assumed EMEM and read the init message back as zeros. */
static void sec2_emem_rd(uint32_t a, uint8_t *dst, uint32_t len) {
    int em = a >= 0x01000000u;
    fl_wr(em ? 0xac0 : 0x1c0, (1u << 25) | (em ? a - 0x01000000u : a));
    for (uint32_t i = 0; i < len; i += 4) put32(dst + i, fl_rd(em ? 0xac4 : 0x1c4));
}
static void sec2_emem_wr(uint32_t a, const uint8_t *src, uint32_t len) {
    int em = a >= 0x01000000u;
    fl_wr(em ? 0xac0 : 0x1c0, (1u << 24) | (em ? a - 0x01000000u : a));
    for (uint32_t i = 0; i < len; i += 4) fl_wr(em ? 0xac4 : 0x1c4, le32(src + i));
}
static uint32_t g_cq_head, g_cq_tail, g_cq_off, g_cq_size, g_mq_head, g_mq_tail, g_mq_off;
/* one message from SEC2's msgq into m (<=128 bytes); returns its size or 0 */
static uint32_t sec2_msg(uint8_t *m, unsigned ms) {
    uint32_t pos = fl_rd(g_mq_tail), head;
    for (unsigned t = 0; t <= ms; t++) { head = fl_rd(g_mq_head); if (head != pos) break; nv_mdelay(1); }
    if (head == pos) return 0;
    if (head < pos) pos = g_mq_off;                                    /* the ring looped */
    sec2_emem_rd(pos, m, 4);
    uint32_t sz = m[1];
    if (sz < 4 || sz > 128) { kprintf("[nv] sec2: message of %u bytes -- refused\n", sz); return 0; }
    if (sz > 4) sec2_emem_rd(pos + 4, m + 4, ALN(sz - 4, 4));
    fl_wr(g_mq_tail, pos + ALN(sz, 4));
    return sz;
}
static int sec2_bootstrap(int id, uint8_t seq) {
    uint8_t c[16] = { 0x08, 16, 0x3, seq, 0 /* BOOTSTRAP_FALCON */ };
    put32(c + 8, 0);                                                   /* FLAGS_RESET_YES */
    put32(c + 12, (uint32_t)id);
    uint32_t pos = fl_rd(g_cq_head);
    if (pos + 16 + 4 > g_cq_off + g_cq_size) { kprintf("[nv] sec2: cmdq would need a rewind -- not implemented\n"); return 0; }
    sec2_emem_wr(pos, c, 16);
    fl_wr(g_cq_head, pos + 16);
    uint8_t m[128];
    uint32_t sz = sec2_msg(m, 1000);
    if (!sz) { kprintf("[nv] sec2: BOOTSTRAP_FALCON %d: no reply in 1000 ms\n", id); return 0; }
    uint32_t err = sz >= 12 ? le32(m + 8) : ~0u, fid = sz >= 16 ? le32(m + 12) : ~0u;
    kprintf("[nv] sec2: BOOTSTRAP_FALCON %s -> reply unit %02x seq %u (sent %u), error %08x, falcon %u\n",
            id == LSF_FECS ? "FECS" : "GPCCS", m[0], m[3], seq, err, fid);
    return m[0] == 0x08 && m[3] == seq && err == 0 && fid == (uint32_t)id;
}
static void fl_start(uint32_t base) {                                  /* nvkm_falcon_v1_start */
    if (nv_reg_rd(base + 0x100) & (1u << 6)) nv_reg_wr(base + 0x130, 2);
    else nv_reg_wr(base + 0x100, 2);
}
static void nv_rtos_and_gr_falcons(void) {
    /* nvkm_sec2_init */
    fl_wr(0x014, 0xffffffffu);
    fl_start(SEC2_BASE);
    g_mq_head = 0xa30; g_mq_tail = 0xa34;
    /* THE RTOS SETS BOTH QUEUE POINTERS ITSELF, then raises SWGEN0 (0x40 in
     * 0x008) -- which is when nouveau reads the tail (recv_initmsg). The
     * first version captured the tail BEFORE the start, got 0, and read
     * locked DMEM at address 0 while the message sat in EMEM. */
    unsigned ms = 0;
    for (; ms <= 2000 && !(fl_rd(0x008) & 0x40); ms++) nv_mdelay(1);
    uint32_t pos = fl_rd(0xa34), head = fl_rd(0xa30);
    fl_wr(0x004, 0x40);
    if (head == pos) {
        kprintf("[nv] sec2: RTOS sent no init message in 2000 ms (cpuctl %08x mbox %08x/%08x irqstat %08x)\n",
                fl_rd(0x100), fl_rd(0x040), fl_rd(0x044), fl_rd(0x008));
        return;
    }
    uint8_t im[32];
    sec2_emem_rd(pos, im, 32);
    kprintf("[nv] sec2: msgq tail %08x head %08x (%s); bytes:", pos, head, pos >= 0x01000000u ? "EMEM" : "DMEM");
    for (int k = 0; k < 32; k += 4) kprintf(" %08x", le32(im + k));
    kprintf("\n");
    fl_wr(0xa34, pos + 32);
    kprintf("[nv] sec2: RTOS up after %u ms: init msg unit %02x size %u type %u, %u queues\n",
            ms, im[0], im[1], im[4], im[5]);
    if (im[0] != 0x01 || im[4] != 0x00 || im[1] != 32) { kprintf("[nv] sec2: not the gp102 init message -- stopped\n"); return; }
    for (int q = 0; q < 2; q++) {
        const uint8_t *qi = im + 8 + q * 8;
        uint32_t off = le32(qi), sz = (uint32_t)qi[4] | (uint32_t)qi[5] << 8, idx = qi[6], qid = qi[7];
        kprintf("[nv] sec2:   %s: index %u, EMEM %08x, %u bytes\n", qid ? "msgq" : "cmdq", idx, off, sz);
        if (qid == 0) { g_cq_head = 0xa00 + idx * 8; g_cq_tail = 0xa04 + idx * 8; g_cq_off = off; g_cq_size = sz; }
        else          { g_mq_head = 0xa30 + idx * 8; g_mq_tail = 0xa34 + idx * 8; g_mq_off = off; }
    }
    /* GR on, then have SEC2 bootstrap FECS and GPCCS out of the WPR */
    uint32_t pmc = nv_reg_rd(0x000200);
    nv_reg_wr(0x000200, pmc | (1u << 12)); (void)nv_reg_rd(0x000200);
    kprintf("[nv] gr: PMC 0x200 %08x -> %08x (GR enabled)\n", pmc, nv_reg_rd(0x000200));
    int f = sec2_bootstrap(LSF_FECS, 1), g = sec2_bootstrap(LSF_GPCCS, 2);
    if (!f || !g) { kprintf("[nv] gr: SEC2 did not bootstrap both falcons -- stopped\n"); return; }
    /* gf100_gr_init_ctxctl_ext: start both, wait for FECS to say ready */
    nv_reg_wr(0x409800, 0); nv_reg_wr(0x41a10c, 0); nv_reg_wr(0x40910c, 0);
    fl_start(0x41a000);
    fl_start(0x409000);
    for (ms = 0; ms <= 2000 && !(nv_reg_rd(0x409800) & 1); ms++) nv_mdelay(1);
    uint32_t r = nv_reg_rd(0x409800);
    kprintf("[nv] gr: FECS 0x409800 = %08x after %u ms (FECS cpuctl %08x, GPCCS cpuctl %08x)\n",
            r, ms, nv_reg_rd(0x409100), nv_reg_rd(0x41a100));
    if (!(r & 1)) { kprintf("[nv] gr: FAIL -- FECS never signalled ready\n"); return; }
    /* gf100_gr_fecs_set_watchdog_timeout + discover_image_size (method 0x10) */
    nv_reg_wr(0x409800, 0); nv_reg_wr(0x409500, 0x7fffffff); nv_reg_wr(0x409504, 0x21);
    nv_mdelay(1);
    nv_reg_wr(0x409800, 0); nv_reg_wr(0x409500, 0); nv_reg_wr(0x409504, 0x10);
    uint32_t size = 0;
    for (ms = 0; ms <= 2000 && !(size = nv_reg_rd(0x409800)); ms++) nv_mdelay(1);
    kprintf("[nv] gr: FECS answers method 0x10 (context image size): %u bytes after %u ms\n", size, ms);
    kprintf("[nv] gr: %s -- %s\n", size ? "PASS" : "FAIL",
            size ? "FECS and GPCCS run NVIDIA's signed firmware and FECS answers our methods"
                 : "FECS is up but did not answer method 0x10");
}

static void nvgpu_late_task(void) {
    struct statx st; unsigned waited = 0;
    while (vfs_stat(NV_FW_ROOT "acr/bl.bin", &st) != 0 && waited < 120000) { task_sleep_ms(100); waited += 100; }
    if (waited >= 120000) { kprintf("[nv] fw: the root filesystem never offered " NV_FW_ROOT " -- step 5 cannot start\n"); task_exit(); }
    unsigned ok = 0, total = 0;
    for (unsigned i = 0; i < sizeof(nv_fw_files) / sizeof(nv_fw_files[0]); i++) {
        unsigned len = 0; uint8_t *b = nv_fw_load(nv_fw_files[i], &len);
        if (!b) continue;
        uint32_t w0 = len >= 4 ? (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24 : 0;
        kprintf("[nv] fw: %s %u bytes, word0 %08x\n", nv_fw_files[i], len, w0);
        ok++; total += len; kfree(b);
    }
    kprintf("[nv] fw: %u of %u gp108 firmware files read from the root filesystem (%u bytes) after %u ms\n",
            ok, (unsigned)(sizeof(nv_fw_files) / sizeof(nv_fw_files[0])), total, waited);
    if (ok == sizeof(nv_fw_files) / sizeof(nv_fw_files[0]) && nv_acr_run()) nv_rtos_and_gr_falcons();
    task_exit();
}

static void nv_vram_probe_gp102(const char *when) {
    uint32_t d = nv_reg_rd(0x100ce0);
    if ((d & 0xFFF00000u) == 0xBAD00000u) {
        kprintf("[nv] %s: 0x100ce0 reads %08x -- PRI error, FB not up\n", when, d);
        return;
    }
    uint32_t lmag = (d >> 4) & 0x3f, lsca = d & 0xf;
    uint64_t bytes = (uint64_t)lmag << (lsca + 20);
    if (d & 0x40000000u) bytes = bytes / 16 * 15;
    uint64_t mib = bytes >> 20;
    g_nv_vram_mib = (unsigned)mib;
    kprintf("[nv] %s: 0x100ce0 = %08x -> VRAM %lu MiB -- %s\n", when, d, (unsigned long)mib,
            mib == 2048 ? "MATCHES nouveau's 2048 MiB: memory is initialised"
          : mib == 0    ? "zero: memory not initialised"
                        : "does NOT match nouveau's 2048 MiB");
}

static void nv_vram_probe(const char *when) {
    unsigned chip = (nv_boot0 >> 20) & 0x1ff;
    if (chip >= 0x132 && chip <= 0x13f) { nv_vram_probe_gp102(when); return; }   /* GP102..GP108 */
    /* gf108_ram_probe_fbp_amount, WHICH IS WHAT KEPLER USES (M2379). The
     * first version copied gf100_ram_probe_fbp_amount -- one FBPA per FBP --
     * and read 512 MiB. gk104_ram points at the gf108 variant instead, which
     * takes the FBPA count from 0x02243c and SUMS every FBPA behind each FBP.
     * 512 x 4 = 2048, which is exactly nouveau's number for this card, so the
     * "partial POST" may have been nothing but this probe under-counting. */
    uint32_t fbps = nv_reg_rd(0x022438), fbpat = nv_reg_rd(0x02243c);
    uint32_t fbpao = nv_reg_rd(0x022554);
    unsigned per = (fbps && fbpat >= fbps && fbpat < 64) ? fbpat / fbps : 1;
    kprintf("[nv] %s: %u FBP(s), %u FBPA(s) total -> %u per FBP, disabled mask %08x\n",
            when, fbps, fbpat, per, fbpao);
    uint64_t total = 0; unsigned live = 0;
    for (unsigned fbp = 0; fbp < fbps && fbp < 8; fbp++)
    for (unsigned k = 0; k < per; k++) {
        unsigned f = fbp * per + k;
        if (fbpao & (1u << f)) continue;
        uint32_t mib = nv_reg_rd(0x11020c + f * 0x1000);
        /* 0xBAD0____ AND 0xBADF____ are both NVIDIA PRI errors. Matching only
         * the first let 0xBADF3000 through as "3135188992 MiB" before
         * devinit (M2378) -- the mask has to be 0xFFF00000. */
        if ((mib & 0xFFF00000u) == 0xBAD00000u) {
            kprintf("[nv] %s: FBP %u size register reads %08x -- PRI error, FB not up\n",
                    when, f, mib);
            return;
        }
        total += mib; live++;
    }
    kprintf("[nv] %s: VRAM %lu MiB across %u live FBPA(s) -- %s\n", when,
            (unsigned long)total, live,
            total == 2048 ? "MATCHES nouveau's 2048 MiB: memory is initialised"
          : total == 0    ? "zero: memory not initialised"
                          : "does NOT match nouveau's 2048 MiB");
}


/* ------------------------------------------------------------- GPIO ------
 *
 * 0x8e GPIO and 0xa9 GPIO_NE both call nvkm_gpio_reset(), which drives every
 * GPIO the VBIOS lists to its default state. GPIOs switch power rails, fans
 * and panel enables, so these are plausible POST blockers and were skipped
 * only because this driver had no GPIO engine. This is gf119_gpio_reset (used
 * by gk104, hence by GK208B), following nouveau exactly:
 *
 *   DCB    = rd16(0x36); ver >= 0x30 requires signature 0x4edcbdcb at +6
 *   GPIO   = rd16(DCB + 0x0a), header per version
 *   entry  = decoded per DCB GPIO version (<0x40 u16, 0x40 u32, >=0x41 u32+u8)
 *   drive  = mask(0xd610 + line*4, 0x3000, ((dir^1)<<13) | (out<<12))
 *            then mask(0xd604, 1, 1) -- the update strobe
 *
 * The DCB signature is a free falsifiability check: a wrong DCB pointer
 * fails it instead of driving arbitrary pins from garbage. */
static void nv_mask(uint32_t reg, uint32_t m, uint32_t v) {
    nv_reg_wr(reg, (nv_reg_rd(reg) & ~m) | v);
}
static unsigned g_nv_gpio_driven;

static int nv_gpio_reset(uint8_t match) {
    unsigned dcb = nv_rd16(0x36);
    if (!dcb || dcb + 8 >= nv_romlen) { kprintf("[nv] gpio: no DCB pointer at 0x36\n"); return -1; }
    unsigned dver = nv_rom[dcb];
    if (dver < 0x30 || dver >= 0x42 || nv_rom32(dcb + 6) != 0x4edcbdcbu) {
        kprintf("[nv] gpio: DCB @%x ver %02x sig %08x -- not a DCB this driver trusts\n",
                dcb, dver, nv_rom32(dcb + 6));
        return -1;
    }
    if (nv_rom[dcb + 1] < 0x0c) return -1;
    unsigned gt = nv_rd16(dcb + 0x0a);
    if (!gt || gt + 4 >= nv_romlen) { kprintf("[nv] gpio: DCB has no GPIO table\n"); return -1; }
    unsigned gver = nv_rom[gt], ghdr, gcnt, glen;
    if (gver < 0x30)       { ghdr = 3; gcnt = nv_rom[gt + 2]; glen = nv_rom[gt + 1]; }
    else if (gver <= 0x41) { ghdr = nv_rom[gt + 1]; gcnt = nv_rom[gt + 2]; glen = nv_rom[gt + 3]; }
    else { kprintf("[nv] gpio: GPIO table version %02x unknown\n", gver); return -1; }

    unsigned n = 0;
    for (unsigned e = 0; e < gcnt && e < 64; e++) {
        unsigned ent = gt + ghdr + e * glen;
        if (ent + 5 >= nv_romlen) break;
        uint32_t raw = nv_rom32(ent);
        unsigned line, func, log0, log1;
        if (gver < 0x40) {
            unsigned info = nv_rd16(ent);
            line = info & 0x1f; func = (info & 0x07e0) >> 5;
            log0 = (info & 0x1800) >> 11; log1 = (info & 0x6000) >> 13;
        } else if (gver < 0x41) {
            line = raw & 0x1f; func = (raw & 0xff00) >> 8;
            log0 = (raw & 0x18000000u) >> 27; log1 = (raw & 0x60000000u) >> 29;
        } else {
            uint8_t info1 = nv_rom[ent + 4];
            line = raw & 0x3f; func = (raw & 0xff00) >> 8;
            log0 = (info1 & 0x30) >> 4; log1 = (info1 & 0xc0) >> 6;
        }
        if (func == 0xff || (match != 0xff && match != func)) continue;
        unsigned defs = !!(raw & 0x80);
        unsigned lg = defs ? log1 : log0;
        unsigned dir = !!(lg & 2), out = !!(lg & 1);
        if (g_nv_exec) {
            nv_mask(0x00d610 + line * 4, 0x00003000, ((dir ^ 1u) << 13) | (out << 12));
            nv_mask(0x00d604, 0x00000001, 0x00000001);
            uint8_t unk0 = (raw >> 16) & 0xff, unk1 = (raw >> 24) & 0x1f;
            nv_mask(0x00d610 + line * 4, 0xff, unk0);
            if (unk1) nv_mask(0x00d740 + (unk1 - 1) * 4, 0xff, line);
        }
        n++;
    }
    g_nv_gpio_driven += n;
    return (int)n;
}

static void nvgpu_devinit_run(unsigned script0, unsigned cond_table) {
    nv_cond_table = cond_table;
    int exec = 1, ops = 0;
    /* HOST-SIDE SCRIPTS ARE A FERMI/KEPLER MECHANISM ONLY (M2380).
     * nouveau: gf100_devinit (post = nv04_devinit_post -> nvbios_post) runs
     * init scripts on the CPU; gm200_devinit, used by every chip from GM20x
     * (0x120) on, uploads a PMU application and lets THE PMU run them. On
     * those parts the scripts contain PMU-only opcodes (0xac, 0xaf) and are
     * not meant for the host at all. So on 0x120+ this interpreter is
     * forced to a dry run even under nvexec -- it stays useful as a decoder,
     * and it cannot issue a write the reference driver would never issue. */
    unsigned chip = (nv_boot0 >> 20) & 0x1ff;
    int saved_exec = g_nv_exec;
    if (chip >= 0x120 && g_nv_exec) {
        kprintf("[nv] devinit: chipset %x is Maxwell2+ -- its init scripts are PMU input, "
                "so the host interpreter runs DRY; the PMU path does the real POST\n", chip);
        g_nv_exec = 0;
    }
    kprintf("[nv] devinit: %s the script\n",
            g_nv_exec ? "** EXECUTING ** (nvexec given: this WRITES to the GPU)"
                      : "dry run (computing every read/write, touching nothing; "
                        "-append nvexec to arm it)");
    nv_vram_probe("BEFORE devinit");
    nv_clk_report("BEFORE devinit");
    int r = nv_run(script0, 0, &exec, &ops);
    kprintf("[nv] devinit: %s after %d opcode(s), exec flag %d\n",
            r == 0 ? "COMPLETED" : "ABORTED", ops, exec);
    g_nv_exec = saved_exec;
    /* RE-READ THE STATE AFTER, NOT BEFORE (M2377).
     *
     * Every POST indicator -- 0x2240c, 0x619f04, the FB registers -- was
     * being read in nvgpu_init(), which runs BEFORE this. So the armed run
     * reported "the card NEEDS POSTing" and "PRAMIN not enabled" from a
     * snapshot taken before devinit had executed a single opcode, which
     * says nothing about whether it worked. Same shape as the two earlier
     * ordering faults in this project: a capability tested before the
     * capability was created. The only honest comparison is before/after. */
    {   uint32_t post = nv_reg_rd(0x02240c), pram = nv_reg_rd(0x619f04);
        kprintf("[nv] AFTER devinit: 0x2240c = %08x -> the card %s POSTing\n",
                post, (post & 2) ? "does NOT need" : "STILL NEEDS");
        kprintf("[nv] AFTER devinit: 0x619f04 = %08x -> PRAMIN %s\n",
                pram, (pram & 8) ? "IS NOW ENABLED" : "still not enabled");
        nv_vram_probe("AFTER devinit");
    }
    if (g_nv_skipped_vga || g_nv_skipped_i2c || g_nv_skipped_gpio)
        kprintf("[nv] devinit: drove %u GPIO line(s) to their VBIOS defaults\n", g_nv_gpio_driven);
    kprintf("[nv] devinit: register addresses -- %u had low bits set, %u carried "
            "head/OR/link FLAGS, %u were out of range after translation\n",
            g_nv_reg_lowbits, g_nv_reg_flagged, g_nv_reg_oob);
        kprintf("[nv] devinit: CONDITION_TIME ran %u time(s): %u had to WAIT for their "
                "condition, %u TIMED OUT and suspended execution\n",
                g_nv_ctime_calls, g_nv_ctime_waited, g_nv_ctime_timeouts);
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

    if (g_nv_exec) {
        /* nvkm_falcon_reset for GP102's PMU = gm200_flcn_disable +
         * gm200_flcn_enable, with gp102_flcn_reset_eng rather than a PMC-bit
         * toggle (gp102_pmu_flcn sets .reset_eng and NOT .reset_pmc).
         * The first version of this omitted the 0x3c0 engine-reset pulse
         * entirely, so it would have uploaded ucode into a falcon that had
         * never been reset (M2380). */
        pmu_wr(PMU_BASE + 0x048, pmu_rd(PMU_BASE + 0x048) & ~3u);   /* IRQ enables off */
        pmu_wr(PMU_BASE + 0x014, 0xFFFFFFFFu);                      /* IRQMCLR */
        for (int pass = 0; pass < 2; pass++) {                      /* disable, then enable */
            pmu_wr(PMU_BASE + 0x3c0, pmu_rd(PMU_BASE + 0x3c0) | 1u);
            nv_mdelay(1);                                           /* >= 10 us */
            pmu_wr(PMU_BASE + 0x3c0, pmu_rd(PMU_BASE + 0x3c0) & ~1u);
            int ok = 0;
            for (int t = 0; t < 10; t++) {                          /* nouveau: 10 ms */
                if (!(pmu_rd(PMU_BASE + 0x10c) & 6)) { ok = 1; break; }
                nv_mdelay(1);
            }
            if (!ok) {
                kprintf("[nv] pmu: falcon memory scrubbing never finished (pass %d, "
                        "0x10a10c=%08x) -- refusing to upload into a falcon that is not ready\n",
                        pass, pmu_rd(PMU_BASE + 0x10c));
                return -1;
            }
        }
        pmu_wr(PMU_BASE + 0x084, nv_reg_rd(0x000000));              /* PMC_BOOT_0 */
        kprintf("[nv] pmu: falcon reset complete (engine-reset pulse x2, scrubbing done)\n");
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
        {   uint32_t post = nv_reg_rd(0x02240c);
            kprintf("[nv] AFTER PMU devinit: 0x2240c = %08x -> the card %s POSTing\n", post,
                    (post & 2) ? "does NOT need" : "STILL NEEDS");
            nv_vram_probe("AFTER PMU devinit");
            nv_clk_report("AFTER PMU devinit");
            if (post & 2) {
                nv_top_report();
                if (nv_mmu_bar1_test()) nv_channel_test();
                task_create(nvgpu_late_task, 0, 0);          /* step 5 starts once the root is mounted */
            }
        }
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
    if (!tbl || nv_A(tbl) >= nv_romlen) {
        kprintf("[nv] pmu: table pointer %x is outside the %u-byte ROM\n", tbl, nv_romlen);
        return -1;
    }
    unsigned ver = nv_rom8(tbl), hdr = nv_rom8(tbl+1), len = nv_rom8(tbl+2), cnt = nv_rom8(tbl+3);
    kprintf("[nv] pmu: table @ %x  ver %02x header %u entry %u count %u\n",
            tbl, ver, hdr, len, cnt);
    if (!len || !cnt || nv_A(tbl + hdr + cnt * len) > nv_romlen) {
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
                unsigned e = o + h + i * l, ty = nv_rom8(e), dp = nv_rom32(e + 2);
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
        unsigned type = nv_rom8(e), da = nv_rom32(e + 2);
        const char *what = type == 0x04 ? "  <-- DEVINIT" : type == 0x01 ? "  <-- PRE_OS" : "";
        kprintf("[nv] pmu:   [%u] type %02x data %x%s\n", i, type, da, what);
        if (type != 0x04) continue;
        if (!da || nv_A(da + 0x30) > nv_romlen) {
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
                   data_sz < 0x40000 && nv_A(boot_rom + boot_sz + code_sz) <= nv_romlen &&
                   nv_A(data_rom + data_sz) <= nv_romlen;
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
    /* Pascal answers through 0x100ce0 (M2383): this FBPA walk read PRI-error
     * words on the GT 1030 and summed them into "3135188992 MiB". */
    unsigned chip = (nv_boot0 >> 20) & 0x1ff;
    if (chip >= 0x132 && chip <= 0x13f) { nv_vram_probe("at init"); return; }
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
            uint32_t v = nv_reg_rd(0x90020c + fbpa * 0x4000);
            if ((v & 0xFFF00000u) == 0xBAD00000u) {
                kprintf("[nv] fb: FBPA %u size reads %08x -- a PRI error, not a size; no VRAM size claimed.\n", fbpa, v);
                return;
            }
            sub += v;
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
        if (i == 1) { g_nv_bar1_phys = base; g_nv_bar1_size = sz; }
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

    /* DO OUR WRITES EVEN LAND? (M2377)
     *
     * 231 register writes from devinit changed nothing observable, and there
     * are two completely different explanations: devinit is incomplete, or
     * this driver cannot write to the card at all. Reads demonstrably work
     * (PMC_BOOT_0), but a read-only BAR mapping, a missing PCI memory-space
     * enable, or a stray const would all look exactly like "devinit did not
     * help". Test it on a scratch register before blaming the interpreter.
     *
     * NV_PBUS_SCRATCH at 0x1400 is a plain scratch register: it exists to be
     * written and read back, and nothing depends on its value. Restore it
     * anyway. */
    {   /* PICK A REGISTER THAT IS ACTUALLY THERE. The first attempt used
         * 0x1400 and read back 0xbad0011f -- NVIDIA's PRI-error magic, not
         * data. That proved only that 0x1400 is unreachable on this card,
         * NOT that writes fail, and reporting it as "writes do not reach the
         * card" would have been a false finding about the whole driver.
         *
         * 0x1700 is the PRAMIN window register: this driver already reads it
         * successfully, nouveau writes it on every VBIOS shadow, and a
         * 0xbad0 pattern there would be unambiguous. Values are restored. */
        static const uint32_t probe[] = { 0x001700, 0x000200, 0x022400 };
        for (unsigned i = 0; i < sizeof probe / sizeof probe[0]; i++) {
            volatile uint32_t *r = (volatile uint32_t *)(nv_bar0 + probe[i]);
            uint32_t save = *r;
            if ((save & 0xFFF00000u) == 0xBAD00000u) {
                kprintf("[nv] MMIO probe %06x: reads %08x -- PRI error, register not "
                        "reachable (not a write-path failure)\n", probe[i], save);
                continue;
            }
            *r = save ^ 0x00000001u;              /* flip one harmless bit */
            uint32_t rb = *r;
            *r = save;                            /* restore immediately */
            kprintf("[nv] MMIO probe %06x: was %08x, wrote %08x, read %08x -- writes %s\n",
                    probe[i], save, save ^ 1u, rb,
                    rb == (save ^ 1u) ? "LAND HERE" :
                    rb == save ? "are IGNORED here (read-only or gated)" : "read back differently");
        }
    }

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
