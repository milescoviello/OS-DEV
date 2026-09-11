/*
 * gdt.c — build and load a proper GDT + TSS.
 *
 * In 64-bit long mode the CPU mostly ignores segmentation: base and limit are
 * forced to 0 / full, so segments no longer carve up memory. But the GDT is
 * still mandatory because a few things are encoded in segment *descriptors*:
 *
 *   - the privilege level (ring 0 kernel vs ring 3 user) of code/data,
 *   - whether a code segment runs in 64-bit mode (the "L" bit),
 *   - and the Task State Segment (TSS).
 *
 * The TSS in long mode no longer holds a task's registers (no hardware task
 * switching here). It holds two things we care about:
 *   - RSP0: the stack the CPU switches to when an interrupt takes us from
 *     ring 3 into ring 0 (needed once we have userspace), and
 *   - the IST table: up to 7 known-good stacks an interrupt gate can demand,
 *     so e.g. a double fault runs on a fresh stack even if RSP was garbage.
 */
#include "gdt.h"
#include "string.h"
#include "smp.h"
#include "linuxabi.h"
#include <stdint.h>

/* 64-bit TSS, packed exactly as the CPU expects (104 bytes). */
struct tss {
    uint32_t reserved0;
    uint64_t rsp[3];     /* rsp0..rsp2: stacks for ring 0..2 */
    uint64_t reserved1;
    uint64_t ist[7];     /* ist[0] == IST1 .. ist[6] == IST7 */
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iomap_base;
} __attribute__((packed));

/* One TSS PER CORE (M1531): a genuinely multi-core scheduler needs a ring-3
 * task to be able to trap into ring 0 on WHICHEVER core it happens to be
 * running on, and RSP0 (and the #DF IST stack) is a per-core CPU resource —
 * two cores sharing one TSS would stomp each other's RSP0 the moment two
 * ring-3 tasks trapped in on different cores at once. GDT_MAX_CPUS matches
 * the MAX_CPUS convention already used by kernel/smp.c / ecdsa.c / smpthread.c
 * (index = APIC id & (GDT_MAX_CPUS-1)). Each gets its own 16-byte TSS
 * descriptor (2 GDT slots) built once at boot; an AP calls gdt_load_ap() to
 * `ltr` ITS OWN selector instead of skipping ltr entirely as before. */
#define GDT_MAX_CPUS 16
static uint64_t gdt[5 + GDT_MAX_CPUS * 2];
static struct tss tss[GDT_MAX_CPUS];

/* Stacks the TSS points at. .bss isn't guaranteed zeroed by the loader, but
 * stacks don't care — we only ever write before we read. */
static uint8_t kernel_stack[GDT_MAX_CPUS][16384] __attribute__((aligned(16)));
static uint8_t df_stack[GDT_MAX_CPUS][8192]      __attribute__((aligned(16)));

static inline int this_core(void) { return smp_current_cpu() & (GDT_MAX_CPUS - 1); }

struct gdtr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

/* Defined in gdt_flush.asm: loads the GDTR and reloads CS/SS/data selectors. */
extern void gdt_flush(struct gdtr *ptr);

/* Encode one ordinary 8-byte descriptor. In long mode base/limit are ignored
 * for code/data, but we fill conventional values anyway. `flags` is the high
 * nibble (G, D/B, L, AVL); `access` is the type/DPL/present byte. */
static uint64_t make_desc(uint32_t base, uint32_t limit,
                          uint8_t access, uint8_t flags) {
    uint64_t d = 0;
    d |= (uint64_t)(limit & 0xFFFF);
    d |= (uint64_t)(base & 0xFFFFFF) << 16;
    d |= (uint64_t)access << 40;
    d |= (uint64_t)((limit >> 16) & 0xF) << 48;
    d |= (uint64_t)(flags & 0xF) << 52;
    d |= (uint64_t)((base >> 24) & 0xFF) << 56;
    return d;
}

void gdt_init(void) {
    /* access bytes: P=1. code=0x1A|.., data=0x12|.. ; ring in bits 5-6.
     *   0x9A kernel code, 0x92 kernel data, 0xFA user code, 0xF2 user data.
     * flags: code uses L=1 (0xA), data uses D/B=1 (0xC). G=1 in both. */
    gdt[0] = 0;                                   /* null */
    gdt[1] = make_desc(0, 0xFFFFF, 0x9A, 0xA);    /* kernel code */
    gdt[2] = make_desc(0, 0xFFFFF, 0x92, 0xC);    /* kernel data */
    gdt[3] = make_desc(0, 0xFFFFF, 0xFA, 0xA);    /* user code   */
    gdt[4] = make_desc(0, 0xFFFFF, 0xF2, 0xC);    /* user data   */

    /* Build every core's TSS + descriptor up front (BSP builds all of them —
     * simpler than growing the GDT later once APs are up, and costs nothing:
     * an AP that never comes up just leaves its slot unused). */
    memset(tss, 0, sizeof(tss));
    for (int i = 0; i < GDT_MAX_CPUS; i++) {
        tss[i].rsp[0]     = (uint64_t)(kernel_stack[i] + sizeof(kernel_stack[i]));
        tss[i].ist[0]     = (uint64_t)(df_stack[i] + sizeof(df_stack[i]));   /* IST1 */
        tss[i].iomap_base = sizeof(tss[i]);       /* no I/O permission bitmap */

        /* Each TSS descriptor is a 16-byte *system* descriptor (2 GDT slots).
         * access 0x89 = present, type 0x9 (available 64-bit TSS), G=0. */
        uint64_t base  = (uint64_t)&tss[i];
        uint32_t limit = (uint32_t)sizeof(tss[i]) - 1;
        gdt[5 + i * 2]     = make_desc((uint32_t)base, limit, 0x89, 0x0);
        gdt[5 + i * 2 + 1] = (base >> 32) & 0xFFFFFFFF;   /* high 32 bits of base */
    }

    struct gdtr gdtr = { .limit = sizeof(gdt) - 1, .base = (uint64_t)&gdt };
    gdt_flush(&gdtr);                             /* lgdt + reload CS/DS/SS */

    __asm__ volatile("ltr %0" : : "r"((uint16_t)TSS_SEL)); /* BSP: load its own (slot 0) task register */
}

void tss_set_rsp0(uint64_t rsp0) {
    int c = this_core();
    tss[c].rsp[0] = rsp0;             /* always targets the CORE CALLING THIS, not a fixed one (M1531) */
    /* The `syscall` instruction does NOT consult the TSS -- it hands the kernel
     * no stack at all -- so the Linux ABI entry path keeps its own per-core
     * mirror of exactly this value, reached through KERNEL_GS_BASE. Updated
     * here so the two can never drift: a stale mirror would run a Linux
     * syscall on some other task's kernel stack. (M1938) */
    linux_abi_set_kernel_rsp(c, rsp0);
}

/* Load the shared kernel GDT on an application processor, reload its segment
 * registers (so KERNEL_CS resolves to the 64-bit kernel code segment when the
 * AP takes an interrupt — its trampoline GDT had a different layout), and
 * `ltr` ITS OWN TSS selector (M1531: was skipped entirely before — fine when
 * APs only ever ran kernel-only code with no ring3->ring0 transitions of
 * their own, no longer fine now that a ring-3 task can be scheduled onto any
 * core and needs a valid RSP0 to trap into on THIS specific core). M1198. */
void gdt_load_ap(void) {
    struct gdtr gdtr = { .limit = sizeof(gdt) - 1, .base = (uint64_t)&gdt };
    gdt_flush(&gdtr);
    uint16_t sel = (uint16_t)(TSS_SEL + this_core() * 16);   /* this core's own 16-byte TSS descriptor */
    __asm__ volatile("ltr %0" : : "r"(sel));
}
