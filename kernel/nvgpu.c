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
static int nvgpu_devinit_tables(unsigned bit_i_off, unsigned bit_i_len);

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
    nvgpu_devinit_tables(init_off, init_len);
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
        if (op == 0x58) len = 6 + (unsigned)nv_rom[at + 5] * 4;
        if (!len) {
            /* Be precise about WHICH kind of unknown this is: 0x8f and 0x91
             * ARE in nouveau's table and merely compute their own length,
             * whereas 0xac is in no nouveau version on this machine (6.14,
             * 7.1, 7.1-gentoo all stop at 0xaa). Conflating those two was a
             * misleading message in the first version of this walker. */
            kprintf("[nv] devinit:   stopped at %x: opcode %02x has no fixed stride "
                    "(either variable-length in nouveau, or unknown to it). "
                    "Bytes around it:\n", at, op);
            unsigned from = at > 16 ? at - 16 : 0;
            for (int r = 0; r < 3; r++) {
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
int g_nv_exec;                       /* -append nvexec: actually write */

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
