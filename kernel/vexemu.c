/* vexemu.c — execute the vector instructions the EMULATOR does not have.
 *
 * WHY THIS EXISTS. Every binary on this development host is built
 * `-march=arrowlake-s`, and Arrow Lake has GFNI, so GCC emits
 * `vgf2p8affineqb` UNCONDITIONALLY -- no CPUID dispatch to fall back to.
 * Firefox's libxul contains 702 of them. QEMU's TCG (10.2.3) advertises gfni in
 * `-cpu max` and then cannot execute the instruction, and there is no KVM on
 * this machine, so Firefox died on instruction one of its first crypto routine:
 *
 *     [fault] Invalid Opcode (vector 6) at libxul.so + 788f4eb
 *     [fault] bytes at rip: c4 e3 d1 ce ea 00 ...
 *
 * tools/lx/lxisa.c proves where the gap is: SSE2, AVX, AVX2, FMA, AES-NI and
 * PCLMULQDQ all execute under us, and GFNI alone faults. So this is not a
 * missing XCR0 bit or a kernel that forgot to enable state -- it is an
 * instruction the CPU underneath us does not implement.
 *
 * A kernel is allowed to fix that. Trapping #UD and completing the instruction
 * in software is exactly what the vector is for, and it is what real kernels do
 * for unimplemented FPU and unaligned access on other architectures. The
 * alternative is that no `-march=native` binary from this host will ever run
 * under emulation.
 *
 * SEMANTICS, derived against the real instruction rather than from memory:
 * tools/gfni/gfderive.c ran a software model against the hardware over 500
 * random vectors and settled two things I would otherwise have guessed wrong --
 * the matrix comes from src2 (not src1), and its rows are indexed 7-b, not b.
 * Verified for 128- and 256-bit forms and arbitrary imm8.
 *
 *   for each 64-bit lane q:
 *     for each byte j in 0..7:
 *       for each result bit b in 0..7:
 *         dest[q].byte[j].bit[b] = parity(src2[q].byte[7-b] & src1[q].byte[j])
 *                                  XOR imm8.bit[b]
 */
#include <stdint.h>
#include "app.h"
#include "vmm.h"
#include "task.h"
#include "console.h"
#include "interrupts.h"

extern void     fpu_xsave_to(void *area64);
extern void     fpu_xrstor_from(const void *area64);
extern uint32_t fpu_xsave_size(void);
extern uint32_t fpu_avx_offset(void);
extern uint64_t fpu_xcr0(void);

static inline uint64_t irq_save(void) {
    uint64_t f; __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory"); return f;
}
static inline void irq_restore(uint64_t f) {
    __asm__ volatile("push %0; popfq" : : "r"(f) : "memory", "cc");
}

unsigned long g_vexemu_count;          /* instructions completed in software */

/* XSAVE standard-format offsets. XMM0-15 live in the legacy region; the upper
 * halves of YMM0-15 live in the AVX component, wherever CPUID says. */
#define XSAVE_XMM0    160
#define XSAVE_HEADER  512              /* XSTATE_BV is the first 8 bytes */

static int parity8(uint8_t v) {
    v ^= (uint8_t)(v >> 4); v ^= (uint8_t)(v >> 2); v ^= (uint8_t)(v >> 1);
    return v & 1;
}

/* The verified transform, over `nq` 64-bit lanes. */
static void gf_affine(uint8_t *dst, const uint8_t *vec, const uint8_t *mat,
                      uint8_t imm, int nq) {
    for (int q = 0; q < nq; q++)
        for (int j = 0; j < 8; j++) {
            uint8_t r = 0;
            for (int b = 0; b < 8; b++) {
                int bit = parity8((uint8_t)(mat[q * 8 + (7 - b)] & vec[q * 8 + j]))
                          ^ ((imm >> b) & 1);
                r |= (uint8_t)(bit << b);
            }
            dst[q * 8 + j] = r;
        }
}

/* One 64-bit GPR out of the trap frame, by encoded register number. */
static uint64_t gpr(const struct registers *r, int n) {
    switch (n) {
    case 0:  return r->rax; case 1:  return r->rcx; case 2:  return r->rdx;
    case 3:  return r->rbx; case 4:  return r->rsp; case 5:  return r->rbp;
    case 6:  return r->rsi; case 7:  return r->rdi;
    case 8:  return r->r8;  case 9:  return r->r9;  case 10: return r->r10;
    case 11: return r->r11; case 12: return r->r12; case 13: return r->r13;
    case 14: return r->r14; default: return r->r15;
    }
}

/* Read/write a 128- or 256-bit vector register inside an XSAVE image. */
static void vreg_read(const uint8_t *area, int n, int bytes, uint8_t *out) {
    for (int i = 0; i < 16; i++) out[i] = area[XSAVE_XMM0 + n * 16 + i];
    if (bytes == 32) {
        uint32_t off = fpu_avx_offset();
        for (int i = 0; i < 16; i++) out[16 + i] = off ? area[off + n * 16 + i] : 0;
    }
}
static void vreg_write(uint8_t *area, int n, int bytes, const uint8_t *in) {
    for (int i = 0; i < 16; i++) area[XSAVE_XMM0 + n * 16 + i] = in[i];
    uint32_t off = fpu_avx_offset();
    if (!off) return;
    /* A VEX.128 operation ZEROES the upper half of its destination -- omitting
     * that leaves stale bits that later 256-bit code will read. */
    for (int i = 0; i < 16; i++)
        area[off + n * 16 + i] = (bytes == 32) ? in[16 + i] : 0;
}

/* Decode a ModRM memory operand's effective address. Returns the number of
 * bytes the ModRM+SIB+displacement occupied, or 0 if we cannot do it. */
static int modrm_addr(const struct registers *r, const uint8_t *p, int mod, int rm,
                      int rex_x, int rex_b, uint64_t rip_after_insn_start,
                      uint64_t *out_addr) {
    int len = 1;                                   /* the ModRM byte itself */
    uint64_t addr = 0;
    int base = (rm & 7) | (rex_b << 3);
    if ((rm & 7) == 4) {                           /* SIB */
        uint8_t sib = p[1]; len++;
        int scale = 1 << (sib >> 6);
        int index = ((sib >> 3) & 7) | (rex_x << 3);
        int sbase = (sib & 7) | (rex_b << 3);
        if (index != 4) addr += gpr(r, index) * (uint64_t)scale;   /* 4 = no index */
        if ((sib & 7) == 5 && mod == 0) {          /* disp32, no base */
            addr += (uint64_t)(int64_t)(int32_t)(p[len] | (p[len+1] << 8) |
                                                 (p[len+2] << 16) | (p[len+3] << 24));
            len += 4;
        } else {
            addr += gpr(r, sbase);
        }
    } else if ((rm & 7) == 5 && mod == 0) {        /* RIP-relative */
        int32_t d = (int32_t)(p[1] | (p[2] << 8) | (p[3] << 16) | (p[4] << 24));
        len += 4;
        /* RIP-relative is measured from the END of the whole instruction, which
         * includes the imm8 that follows -- hence the +1 here. */
        addr = rip_after_insn_start + (uint64_t)len + 1 + (uint64_t)(int64_t)d;
        *out_addr = addr;
        return len;
    } else {
        addr += gpr(r, base);
    }
    if (mod == 1) { addr += (uint64_t)(int64_t)(int8_t)p[len]; len += 1; }
    else if (mod == 2) {
        addr += (uint64_t)(int64_t)(int32_t)(p[len] | (p[len+1] << 8) |
                                             (p[len+2] << 16) | (p[len+3] << 24));
        len += 4;
    }
    *out_addr = addr;
    return len;
}

/* Try to complete the faulting instruction in software. 1 = done, rip advanced. */
int vexemu_try(struct registers *r) {
    if (!(fpu_xcr0() & 0x4)) return 0;             /* no AVX state: nothing to emulate into */
    if (!vmm_user_ok(r->rip, 6)) return 0;
    const uint8_t *p = (const uint8_t *)r->rip;
    if (p[0] != 0xC4) return 0;                    /* 3-byte VEX only */

    uint8_t b1 = p[1], b2 = p[2];
    if ((b1 & 0x1F) != 0x03) return 0;             /* map must be 0F3A */
    if ((b2 & 0x03) != 0x01) return 0;             /* pp must be 66 */
    if (!(b2 & 0x80)) return 0;                    /* W must be 1 */
    if (p[3] != 0xCE) return 0;                    /* VGF2P8AFFINEQB */

    int rex_r = !(b1 & 0x80), rex_x = !(b1 & 0x40), rex_b = !(b1 & 0x20);
    int wide  = (b2 & 0x04) ? 32 : 16;             /* L bit: 256- or 128-bit */
    int src1  = (~(b2 >> 3)) & 0x0F;               /* vvvv, inverted */
    uint8_t modrm = p[4];
    int mod = modrm >> 6;
    int dest = ((modrm >> 3) & 7) | (rex_r << 3);
    int rm   = (modrm & 7) | (rex_b << 3);

    uint8_t a[32], bsrc[32], out[32];
    int oplen;                                     /* modrm (+sib+disp) length */
    if (mod == 3) {
        oplen = 1;
    } else {
        uint64_t ea = 0;
        oplen = modrm_addr(r, p + 4, mod, modrm & 7, rex_x, rex_b, r->rip + 4, &ea);
        if (!oplen) return 0;
        if (!vmm_user_ok(ea, (uint64_t)wide)) return 0;
        for (int i = 0; i < wide; i++) bsrc[i] = ((const uint8_t *)ea)[i];
    }
    uint64_t insn_len = 3 + 1 + (uint64_t)oplen + 1;      /* VEX + op + modrm.. + imm8 */
    if (!vmm_user_ok(r->rip, insn_len)) return 0;
    uint8_t imm = p[3 + 1 + oplen];

    /* The registers are live in this CPU right now: spill them, edit the image,
     * reload it. Indexing an XSAVE area is the only way to reach a register
     * chosen at runtime. */
    uint32_t asz = fpu_xsave_size();
    if (asz < 576 + 256) asz = 576 + 256;
    static uint8_t area[4096] __attribute__((aligned(64)));
    static volatile int busy;                      /* emulating is not re-entrant */
    if (asz > sizeof area) return 0;
    uint64_t fl = irq_save();
    if (busy) { irq_restore(fl); return 0; }
    busy = 1;
    for (uint32_t i = 0; i < asz; i++) area[i] = 0;
    fpu_xsave_to(area);
    /* XRSTOR INITIALISES a component whose XSTATE_BV bit is clear instead of
     * loading it -- so a component we are about to write must have its bit set,
     * and the zeroing above makes that safe for one XSAVE chose to skip. */
    *(uint64_t *)(area + XSAVE_HEADER) |= 0x6;     /* SSE | AVX */

    vreg_read(area, src1, wide, a);
    if (mod == 3) vreg_read(area, rm, wide, bsrc);
    gf_affine(out, a, bsrc, imm, wide / 8);
    vreg_write(area, dest, wide, out);

    fpu_xrstor_from(area);
    busy = 0;
    irq_restore(fl);

    if (!g_vexemu_count)
        kprintf("[vexemu] completing vgf2p8affineqb in software -- this CPU does not "
                "implement GFNI, and every binary here is built for one that does (M2007)\n");
    g_vexemu_count++;
    r->rip += insn_len;
    return 1;
}
