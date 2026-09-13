/*
 * interrupts.c — the C side of interrupt handling.
 *
 * Every interrupt funnels through isr_dispatch() with the saved CPU state.
 * Two cases:
 *
 *   vector  0..31  -> a CPU *exception*. Something the running code did (or
 *                     the demo `int3`). Fatal ones print a register dump and
 *                     halt; breakpoint (#BP) we just report and resume.
 *   vector 32..47  -> a hardware *IRQ* from the PIC. Call the registered
 *                     driver handler (if any), then acknowledge with an EOI.
 */
#define __KERNEL__
#include "interrupts.h"
#include "idt.h"
#include "pic.h"
#include "console.h"
#include "syscall.h"
#include "app.h"
#include "linuxabi.h"
#include "task.h"
#include "timer.h"      /* timer_tick_ms — per-core CPU-time accounting (M1548) */
#include "vmm.h"        /* kstack_is_guard — flag a kernel-stack-overflow #PF (M1495) */
#include "ksyms.h"
#include "ioapic.h"     /* I/O APIC routing — move a live IRQ off the PIC (M1857) */
#include "acpi.h"       /* acpi_madt_gsi_for_irq — ISA IRQ -> GSI (M1857) */
#include "smp.h"        /* lapic_eoi — ack an I/O APIC-delivered IRQ (M1857) */
#include "smp.h"
#include "watchdog.h"
#include "gdbstub.h"
#include "msi.h"          /* MSI vector block + msi_install_handler/msi_irq_count */
#include <stdint.h>

static const char *const exception_names[32] = {
    "Divide Error", "Debug", "Non-Maskable Interrupt", "Breakpoint",
    "Overflow", "BOUND Range Exceeded", "Invalid Opcode",
    "Device Not Available", "Double Fault", "Coprocessor Segment Overrun",
    "Invalid TSS", "Segment Not Present", "Stack-Segment Fault",
    "General Protection Fault", "Page Fault", "Reserved",
    "x87 Floating-Point", "Alignment Check", "Machine Check",
    "SIMD Floating-Point", "Virtualization", "Control Protection",
    "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved",
    "Hypervisor Injection", "VMM Communication", "Security", "Reserved",
};

static irq_handler_fn irq_handlers[16];
static uint64_t irq_counts[16];                  /* IRQ fire tally (for /proc/interrupts) */
uint64_t irq_count(int i) { return (i >= 0 && i < 16) ? irq_counts[i] : 0; }

/* MSI/MSI-X vectors (M1288): a parallel registry over the reserved MSI vector
 * block. Populated by kernel/msi.c (msi_alloc_vector -> msi_install_handler) and
 * fired from isr_dispatch's MSI branch below. */
static irq_handler_fn msi_handlers[MSI_VEC_COUNT];
static uint64_t       msi_counts[MSI_VEC_COUNT];

void msi_install_handler(uint8_t vector, irq_handler_fn fn) {
    if (vector >= MSI_VEC_BASE && vector < MSI_VEC_BASE + MSI_VEC_COUNT)
        msi_handlers[vector - MSI_VEC_BASE] = fn;
}
uint64_t msi_irq_count(uint8_t vector) {
    return (vector >= MSI_VEC_BASE && vector < MSI_VEC_BASE + MSI_VEC_COUNT)
         ? msi_counts[vector - MSI_VEC_BASE] : 0;
}

void interrupts_init(void) {
    idt_init();
    pic_init();
}

void interrupts_enable(void)  { __asm__ volatile("sti"); }
void interrupts_disable(void) { __asm__ volatile("cli"); }

void irq_install_handler(uint8_t irq, irq_handler_fn fn) {
    if (irq < 16) {
        irq_handlers[irq] = fn;
        pic_unmask(irq);
    }
}

/* IRQs whose delivery has been moved from the 8259 PIC to the I/O APIC (M1857):
 * the same handler runs (same vector 32+irq), but the dispatch must acknowledge
 * via the LOCAL APIC, not the PIC. */
static uint32_t g_ioapic_routed;

/* Perform the PIC -> I/O APIC handover for one IRQ ATOMICALLY (M1895).
 *
 * This ordering is load-bearing, and getting it wrong is a permanent hang rather
 * than a glitch. kmain enables interrupts long before it routes anything, so the
 * handover runs with IRQs live. The original code unmasked the I/O APIC entry
 * FIRST and set g_ioapic_routed two statements later — so an interrupt delivered
 * by the I/O APIC inside that window found the bit still clear, took the
 * `else pic_send_eoi(irq)` path in isr_dispatch, and never sent the LAPIC EOI.
 * The LAPIC's in-service bit for that vector then stays set forever and the
 * vector is NEVER delivered again. On the keyboard (M1857) that would lose a
 * key; on the PIT (M1890) it kills the scheduler's heartbeat outright — the boot
 * wedges at the preemption demo. It was hit for real, intermittently, by
 * `make check`, and reproduces deterministically if the window is widened.
 *
 * So: mask interrupts for the whole handover, and publish g_ioapic_routed BEFORE
 * the I/O APIC entry is unmasked, so the very first interrupt from the new source
 * is already acknowledged to the right controller. */
static void irq_handover_to_ioapic(uint8_t irq, uint32_t gsi, int active_low, int level) {
    uint64_t fl;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(fl) :: "memory");

    g_ioapic_routed |= (1u << irq);      /* dispatch now EOIs this vector to the LAPIC */
    pic_mask(irq);                        /* the 8259 stops delivering the line       */
    ioapic_route_ex((uint8_t)gsi, (uint8_t)(32 + irq), 0 /* BSP APIC id */,
                    0 /* unmasked */, active_low, level);

    __asm__ volatile("push %0; popfq" : : "r"(fl) : "memory", "cc");
}

/* Route ISA `irq`'s delivery through the I/O APIC (to vector 32+irq on the BSP's
 * local APIC), masking it on the PIC. No-op if no I/O APIC. The handler is
 * unchanged; only the delivery path + EOI target change.
 *
 * The electrical configuration comes from the MADT Interrupt Source Override if
 * the firmware supplied one, else the ISA bus default (edge-triggered,
 * active-high). Before M1890 the override's flags word was parsed past and
 * discarded, so every routed line was programmed edge/active-high regardless of
 * what the firmware asked for. */
void irq_route_ioapic(uint8_t irq) {
    if (irq >= 16 || !ioapic_present()) return;
    uint32_t gsi   = irq;                     /* identity unless overridden */
    uint16_t flags = 0;                       /* 0 = "conforms to bus default" */
    (void)acpi_madt_irq_override(irq, &gsi, &flags);

    /* ISA bus defaults: active high, edge triggered. A polarity/trigger field of
     * 0 means exactly "the bus default", so only an explicit 3 (low / level)
     * changes anything; 1 restates the default. */
    int active_low = (ACPI_MADT_POLARITY(flags) == 3);
    int level      = (ACPI_MADT_TRIGGER(flags)  == 3);

    irq_handover_to_ioapic(irq, gsi, active_low, level);
}

/* Route a PCI device's interrupt line through the I/O APIC (M1890).
 *
 * PCI INTx is LEVEL-triggered and ACTIVE-LOW by definition, and shared: several
 * functions can drive the same line, and the line stays asserted until every
 * sharer's handler has quiesced its device. That is why this cannot reuse the
 * ISA path — an edge/active-high redirection entry on a level/low line either
 * never fires or latches on. A MADT override still wins if the firmware
 * supplied one (some chipsets remap the legacy line). */
void irq_route_ioapic_pci(uint8_t irq) {
    if (irq >= 16 || !ioapic_present()) return;
    uint32_t gsi   = irq;
    uint16_t flags = 0;
    (void)acpi_madt_irq_override(irq, &gsi, &flags);

    /* PCI bus defaults: active LOW, LEVEL triggered. Here a field of 0 ("bus
     * default") means low/level, and only an explicit 1 forces high/edge. */
    int active_low = (ACPI_MADT_POLARITY(flags) != 1);
    int level      = (ACPI_MADT_TRIGGER(flags)  != 1);

    irq_handover_to_ioapic(irq, gsi, active_low, level);
}

/* 1 if `irq`'s delivery has been moved onto the I/O APIC. */
int irq_is_ioapic_routed(uint8_t irq) {
    return (irq < 16) && ((g_ioapic_routed >> irq) & 1);
}

static void dump_registers(struct registers *r) {
    kprintf("  rax=%016lx rbx=%016lx rcx=%016lx\n", r->rax, r->rbx, r->rcx);
    kprintf("  rdx=%016lx rsi=%016lx rdi=%016lx\n", r->rdx, r->rsi, r->rdi);
    kprintf("  rbp=%016lx rsp=%016lx rip=%016lx\n", r->rbp, r->rsp, r->rip);
    kprintf("  r8 =%016lx r9 =%016lx r10=%016lx\n", r->r8,  r->r9,  r->r10);
    kprintf("  r11=%016lx r12=%016lx r13=%016lx\n", r->r11, r->r12, r->r13);
    kprintf("  r14=%016lx r15=%016lx\n",            r->r14, r->r15);
    kprintf("  cs=%lx ss=%lx rflags=%016lx\n",      r->cs,  r->ss,  r->rflags);
}

void isr_dispatch(struct registers *r) {
    /* Remember the most recent ring-3 trap frame for /proc/<pid>/regs (M1119):
     * while a task is stopped, this stays valid (frozen on its kernel stack). */
    if ((r->cs & 3) == 3) { task_t *ct = task_self(); if (ct) ct->uframe = r; }

    if (r->int_no == SYSCALL_VECTOR) {     /* int 0x80 from userspace */
        syscall_dispatch(r);
        return;
    }

    /* SMP inter-processor interrupts (M1198): an AP takes the wake IPI to break
     * out of its idle hlt (the work-drain happens in its idle loop after iret);
     * the LAPIC spurious vector needs no EOI. Both just acknowledge + return. */
    if (r->int_no == 0x40) { lapic_eoi(); return; }
    if (r->int_no == 0x41) { vmm_tlb_shootdown_ack(); lapic_eoi(); return; }   /* TLB shootdown (M1963) */
    /* This core's own local LAPIC timer (M1532): the real per-core preemption
     * source, armed by lapic_timer_start_this_cpu() on every AP (never the
     * BSP, which keeps its own working PIT-driven tick_handler). EOI FIRST,
     * exactly like the IRQ 32-47 branch below and for the identical reason:
     * sched_tick() can context_switch away and not return here until this
     * exact task/core is picked again, so the EOI must already be sent or the
     * LAPIC would never deliver this vector again — an earlier version of
     * this same mechanism (M1531's broadcast-IPI predecessor to this) hit
     * exactly that as a real in-guest crash (an interrupt pileup deep enough
     * to double-fault) before the order was fixed; kept EOI-first here from
     * the start. */
    if (r->int_no == 0x42) {
        lapic_eoi();
        /* Charge THIS core's own current task, same as timer_handler does for
         * the BSP -- task_cpu_tick/app_alarm_tick/app_cpulimit_tick all key off
         * task_self()/current (whichever task is running on the core executing
         * this code right now), so calling them here is correct, not a double-
         * count. Found via a real, reproducible bug: utime_ms/stime_ms stayed
         * 0 forever for a task that happened not to be BSP-resident, because
         * task_cpu_tick was ONLY ever invoked from timer.c's PIT handler --
         * legacy IRQ0 has exactly one target, so that path is BSP-exclusive by
         * construction (M1548). Deliberately NOT adding app_timer_tick() or
         * anything else from timer_handler here: those scan ALL apps globally
         * per call, so running them once per core per tick would fire them
         * (cores) times too often instead of once. */
        task_cpu_tick(timer_tick_ms(), (r->cs & 3) == 3);
        app_alarm_tick();
        app_cpulimit_tick();
        sched_tick();
        return;
    }
    if (r->int_no == 0xFF) { return; }

    /* MSI / MSI-X message-signaled interrupts (M1288): a device wrote its
     * configured vector to the LAPIC. Run the registered handler (if any), tally
     * the delivery, and acknowledge the LOCAL APIC — MSI bypasses the PIC. */
    if (r->int_no >= MSI_VEC_BASE && r->int_no < MSI_VEC_BASE + MSI_VEC_COUNT) {
        int idx = (int)r->int_no - MSI_VEC_BASE;
        msi_counts[idx]++;
        if (msi_handlers[idx]) msi_handlers[idx](r);
        lapic_eoi();
        return;
    }

    if (r->int_no < 32) {
        /* Breakpoint is recoverable — report and continue past the int3. */
        if (r->int_no == 3) {
            if (gdbstub_armed()) { gdbstub_serve(r); return; }   /* GDB stub: hand gdb the trap frame, resume on continue/detach (M1204) */
            kprintf("[int] #BP breakpoint trap at rip=%p (resuming)\n",
                    (void *)r->rip);
            return;
        }

        /* #DB single-step trap from ring 3 (M1123): record the instruction and
         * either keep stepping or stop. Never kills (a #DB just means we stepped
         * one instruction); app_singlestep_trap clears TF if it's not tracing. */
        if (r->int_no == 1) {
            /* gdb single-step lands here as a RING-0 #DB (the kernel was stepped);
             * clear TF and re-enter the stub so gdb sees the new state (M1205). */
            if ((r->cs & 3) == 0 && gdbstub_armed()) { r->rflags &= ~(1ull << 8); gdbstub_serve(r); return; }
            if ((r->cs & 3) == 3) { app_singlestep_trap(r); return; }
        }

        /* A fault from ring 3 (CS RPL == 3) is a userspace app bug, not a kernel
         * bug: report it and terminate just that task, leaving the kernel and the
         * rest of the desktop running. (A ring-0 fault falls through and panics —
         * that IS a real kernel bug.) */
        if ((r->cs & 3) == 3) {
            uint64_t cr2 = 0;
            if (r->int_no == 14) {                 /* page fault: maybe a demand-paged mmap region */
                __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
                if (app_fault_handle(cr2, r->err_code)) return;  /* COW copy / swap-in / mapped a reserved page -> retry */
            }
            if (app_signal_deliver(r, 11)) return;  /* SIGSEGV: a registered handler catches the fault */
            kprintf("[fault] %s (vector %lu) err=0x%lx in a ring-3 task at rip=%p (CR2=%p) -- terminating it\n",
                    exception_names[r->int_no], r->int_no, r->err_code, (void *)r->rip, (void *)cr2);
            /* Dump the registers for a ring-3 fault too (M1945). The panic path
             * has always done this, but a userspace fault printed a single line
             * -- which is exactly the case where you most need to know WHICH
             * register held the bad value. Chasing a ring-3 jump to a kernel
             * address, the one line could not distinguish "computed garbage"
             * from "a kernel pointer was copied into the program". */
            dump_registers(r);
            /* A LINUX-ABI process faulting is the case where a register dump
             * says least: the code is someone else's, unsymbolised, and the
             * useful history is the SYSCALLS it made on the way here. Dump the
             * ring and walk the user stack -- the abort() path has done this
             * since M1970, and a fault is the same question. Skipped entirely
             * when nothing has used the Linux ABI, so native faults read
             * exactly as before. (M1985) */
            /* THE BYTES AT RIP. A fault reported at a function's first
             * instruction, or an access whose direction does not match any
             * instruction there, means the frame is being read wrong -- and
             * there is no way to tell that apart from a genuine fault without
             * looking at the opcode. Sixteen bytes is enough to disassemble by
             * hand. (M1985) */
            /* vmm_translate, not vmm_user_ok: the latter MATERIALISES a
             * lazily-mappable page, which on the fault path re-enters the
             * fault handler. (M1991) */
            if (vmm_translate(r->rip & ~(uint64_t)0xFFF) &&
                vmm_translate((r->rip + 15) & ~(uint64_t)0xFFF)) {
                /* ONE kprintf, not sixteen. Every call takes the console lock,
                 * and on a busy machine sixteen of them are interleaved
                 * character-by-character with whatever another core is
                 * printing -- which is both unreadable and slow enough to blow
                 * a test's boot budget. Format first, print once. */
                static const char hx[] = "0123456789abcdef";
                const uint8_t *ip = (const uint8_t *)r->rip;
                char line[16 * 3 + 1];
                for (int bi = 0; bi < 16; bi++) {
                    line[bi * 3 + 0] = ' ';
                    line[bi * 3 + 1] = hx[ip[bi] >> 4];
                    line[bi * 3 + 2] = hx[ip[bi] & 15];
                }
                line[16 * 3] = 0;
                kprintf("[fault] bytes at rip:%s\n", line);
            }
            /* The last few syscalls, not the last 256: on a fault the tail is
             * what matters, and the full ring is hundreds of console-locked
             * lines. abort() still dumps the whole thing. */
            if (lx_syscalls_made()) { lx_trace_dump_last("a ring-3 fault", 16); lx_user_backtrace(r); }
            app_fault_current(r);  /* dump a core, mark the app exited + task_exit(); does not return */
        }

        interrupts_disable();
        kprintf("\n*** KERNEL PANIC: CPU EXCEPTION ***\n");
        kprintf("  %s (vector %lu)", exception_names[r->int_no], r->int_no);
        kprintf("   error_code=0x%lx\n", r->err_code);
        if (r->int_no == 14) {           /* page fault: CR2 = faulting address */
            uint64_t cr2;
            __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
            kprintf("  faulting address (CR2) = %p\n", (void *)cr2);
            if (kstack_is_guard(cr2))    /* CR2 in the guarded-stack window -> a task overran its kernel stack into a guard page (M1495) */
                kprintf("  >>> KERNEL STACK OVERFLOW: a task overran its kernel stack into a guard page <<<\n");
        }
        /* A stack overflow usually surfaces as a #DF, not a clean #PF: once RSP is in
         * the guard page, the CPU can't push the #PF's own exception frame, so it
         * escalates to a double fault (taken on IST1). Diagnose that too (M1498). */
        if (r->int_no == 8 && kstack_is_guard(r->rsp))
            kprintf("  >>> KERNEL STACK OVERFLOW: a task overran its kernel stack (its #PF escalated to a #DF) <<<\n");
        dump_registers(r);
        backtrace(r->rip, r->rbp);       /* symbolized call trace (kernel/ksyms.c) */
        /* Autonomous bring-up (M1881): with the watchdog enabled, a panic REBOOTS
         * instead of halting forever, so a bad change self-heals — the machine
         * PXE-boots the latest kernel. The brief spin leaves the panic on the
         * framebuffer/serial first. (Off by default: `make check`'s deliberate
         * faults still halt for inspection.) */
        if (watchdog_enabled()) {
            kprintf("  watchdog: rebooting in ~10s...\n");
            for (volatile uint64_t d = 0; d < 8000000000ULL; d++) { }
            acpi_reboot();
        }
        kprintf("  system halted.\n");
        for (;;)
            __asm__ volatile("cli; hlt");
    }

    if (r->int_no >= 32 && r->int_no < 48) {
        uint8_t irq = (uint8_t)(r->int_no - 32);
        irq_counts[irq]++;                       /* per-IRQ tally for /proc/interrupts */
        /* Acknowledge FIRST, then run the handler. This matters for preemption:
         * the timer handler context-switches away and won't return here until
         * this task runs again, so the EOI must already be sent or the PIC
         * would never deliver another tick. Safe because interrupt gates keep
         * IF clear during the handler (no re-entry). */
        if (g_ioapic_routed & (1u << irq)) lapic_eoi();   /* I/O APIC-delivered: ack the LOCAL APIC (M1857) */
        else                               pic_send_eoi(irq);
        if (irq_handlers[irq])
            irq_handlers[irq](r);
        /* On the way back to ring 3 (after the timer may have rescheduled us),
         * deliver any async signal pending on the resuming app — this is what
         * lets Ctrl-C interrupt a runaway ring-3 compute loop. No-op unless an
         * app opted in with a SIGINT handler and has one pending. (M1083) */
        app_deliver_pending(r);
    }
}
