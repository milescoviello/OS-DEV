/*
 * idt.c — the Interrupt Descriptor Table.
 *
 * The IDT is an array of 256 "gate descriptors", one per interrupt vector.
 * When vector N fires, the CPU looks up entry N, switches to the code segment
 * and (optionally) the IST stack named there, and jumps to the handler
 * address stored in the entry. We point each vector at its matching assembly
 * stub (isr0..isr47), which the linker collected into isr_stub_table.
 */
#include "idt.h"
#include "gdt.h"
#include "string.h"
#include "msi.h"          /* MSI_VEC_BASE / MSI_VEC_COUNT + msi_stub_table block */
#include <stdint.h>

#define IDT_ENTRIES 256
#define NUM_STUBS   48          /* 0..31 exceptions + 32..47 PIC IRQs */

/* One 16-byte long-mode interrupt gate. */
struct idt_entry {
    uint16_t offset_low;        /* handler address bits 0..15  */
    uint16_t selector;          /* code segment selector       */
    uint8_t  ist;               /* bits 0..2: IST index (0 = none) */
    uint8_t  type_attr;         /* P | DPL | gate type         */
    uint16_t offset_mid;        /* handler address bits 16..31 */
    uint32_t offset_high;       /* handler address bits 32..63 */
    uint32_t zero;
} __attribute__((packed));

struct idtr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static struct idt_entry idt[IDT_ENTRIES];

/* The assembly stub table: 48 entries, each the address of isrN. */
extern uint64_t isr_stub_table[NUM_STUBS];

/* The MSI/MSI-X stub table (kernel/asm/isr_stubs.asm): MSI_VEC_COUNT entries
 * for the reserved message-signaled-interrupt vector block (M1288). */
extern uint64_t msi_stub_table[MSI_VEC_COUNT];

static void set_gate(int vec, uint64_t handler, uint8_t ist, uint8_t type_attr) {
    idt[vec].offset_low  = handler & 0xFFFF;
    idt[vec].selector    = KERNEL_CS;
    idt[vec].ist         = ist & 0x7;
    idt[vec].type_attr   = type_attr;
    idt[vec].offset_mid  = (handler >> 16) & 0xFFFF;
    idt[vec].offset_high = (handler >> 32) & 0xFFFFFFFF;
    idt[vec].zero        = 0;
}

void idt_init(void) {
    memset(idt, 0, sizeof(idt));   /* unset vectors stay "not present" */

    /* 0x8E = present, DPL 0, 64-bit interrupt gate (clears IF on entry). */
    for (int i = 0; i < NUM_STUBS; i++)
        set_gate(i, isr_stub_table[i], 0, 0x8E);

    /* Run the double fault (#DF, vector 8) on IST1 — a guaranteed-good stack,
     * so we can report it even if the kernel stack is what got corrupted. */
    set_gate(8, isr_stub_table[8], 1, 0x8E);

    /* The syscall trap (int 0x80). DPL 3 (0xEE) so ring-3 code may invoke it;
     * without that, a user `int 0x80` would itself fault with #GP. */
    extern void isr128(void);
    set_gate(128, (uint64_t)isr128, 0, 0xEE);

    /* SMP (M1198, +0x42 M1532): vector 0x40 = the AP wake inter-processor
     * interrupt, 0x42 = a core's OWN local LAPIC timer (the real per-core
     * preemption source once lapic_timer_start_this_cpu has run for it —
     * every AP), and 0xFF = the LAPIC spurious-interrupt vector (must have a
     * gate or a stray spurious IRQ would #GP). All kernel-only gates. */
    extern void isr64(void), isr65(void), isr66(void), isr255(void);
    set_gate(0x40, (uint64_t)isr64,  0, 0x8E);
    set_gate(0x41, (uint64_t)isr65,  0, 0x8E);   /* TLB shootdown (M1963) */
    set_gate(0x42, (uint64_t)isr66,  0, 0x8E);
    set_gate(0xFF, (uint64_t)isr255, 0, 0x8E);

    /* MSI / MSI-X message-signaled interrupt vectors (M1288): give the whole
     * reserved block (0x90..0x9F) interrupt gates so a message-signaled
     * interrupt — or a stray one — vectors into a stub instead of #GP'ing. */
    for (int i = 0; i < MSI_VEC_COUNT; i++)
        set_gate(MSI_VEC_BASE + i, msi_stub_table[i], 0, 0x8E);

    idt_load();
}

/* Point this CPU's IDTR at the shared, already-built IDT. The BSP calls this at
 * the end of idt_init(); each AP calls it once in long mode so it shares the
 * same gates (the wake IPI + the exception handlers). M1198. */
void idt_load(void) {
    struct idtr idtr = { .limit = sizeof(idt) - 1, .base = (uint64_t)&idt };
    __asm__ volatile("lidt %0" : : "m"(idtr));
}
