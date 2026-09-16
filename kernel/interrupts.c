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
    /* THE PANIC NMI, FIRST AND UNCONDITIONALLY (M2080).
     *
     * A panicking core broadcasts an all-but-self NMI so nothing else can write
     * to the console while it prints. This has to be the very first thing
     * checked: the cores worth stopping are the ones mid-line in kvprintf or
     * spinning in con_take with interrupts off, and anything we do before this
     * branch is another chance for them to emit a byte. Non-maskable is why it
     * works at all -- a core spinning with IF clear would never see a fixed
     * vector, which is exactly the wedge this fixes.
     *
     * Park for good. The machine is going down; the only job left is silence. */
    if (r->int_no == 2 && console_in_panic())
        for (;;) __asm__ volatile("cli; hlt");

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
            /* An Invalid Opcode may be an instruction the CPU under us simply
             * does not implement -- every binary on this host is built for a
             * CPU with GFNI, and the emulator has no GFNI. Complete it in
             * software and retry rather than killing the process. (M2007) */
            if (r->int_no == 6) {
                extern int vexemu_try(struct registers *r);
                if (vexemu_try(r)) return;
            }
            /* SAY SO WHEN A PROCESS CATCHES ITS OWN FAULT (M2073).
             *
             * A delivered SIGSEGV used to leave nothing in the log but the
             * one line app_fault_handle prints on its way out -- no rip, no
             * library, no thread. So Bun printing "Segmentation fault at
             * address 0x0" was the ONLY record of a null dereference, and it
             * gives an address that is null by definition and nothing about
             * where the code was. The handler runs instead of the report, so
             * the report has to happen here or not at all. Bounded, because a
             * program can fault in a loop and a flood would push the history
             * that explains it out of the log. */
            /* app_signal_deliver REWRITES the frame to enter the handler, so
             * the faulting rip has to be taken before the call -- reading it
             * after reports the handler's own entry point, which is the same
             * address every time and tells you nothing. */
            uint64_t frip = r->rip;
            /* THE WHOLE FRAME, not just rip (M2078). app_signal_deliver
             * rewrites this frame to enter the handler -- rip becomes the
             * handler, rdi the signal number, rsi and rdx the siginfo and
             * ucontext pointers -- so dumping `r` after the call reports the
             * handler's entry state and nothing about the fault. I read
             * "rdi=0xb" as a corrupt pointer for three runs before noticing it
             * was SIGSEGV's number. Snapshot first, report the snapshot. */
            struct registers fregs = *r;
            /* SEGV_MAPERR(1) = not mapped, SEGV_ACCERR(2) = mapped and refused.
             * Bit 0 of a page-fault error code is "the page WAS present". */
            if (r->int_no == 14) app_set_fault_siginfo(cr2, (r->err_code & 1) ? 2 : 1);
            if (app_signal_deliver(r, 11)) {       /* SIGSEGV: a registered handler catches the fault */
                static int told;
                if (told < 8) {
                    told++;
                    kprintf("[fault] %s (vector %lu) err=0x%lx at rip=%p (CR2=%p) [tid %d '%s'] "
                            "-- DELIVERED to the process's own handler\n",
                            exception_names[r->int_no], r->int_no, r->err_code,
                            (void *)frip, (void *)cr2, task_current_id(), task_name_of(task_self()));
                    app_describe_addr(frip);
                    /* NAME THE CANARY READ HERE TOO (M2083). The diagnostic
                     * below is on the TERMINATE path only, and a runtime that
                     * installs a SIGSEGV handler -- Bun, Firefox, anything
                     * with a crash reporter -- never reaches it. So the one
                     * fault whose report points at the wrong subsystem by
                     * default was invisible in exactly the processes that
                     * matter: CR2=0x28 reads as a generic null dereference in
                     * libc, and the cause is always the FS base, never the
                     * reported address. */
                    if (r->int_no == 14 && cr2 == 0x28) {
                        uint64_t live = 0, cached = 0; int core = -1;
                        task_fs_base_live(&live, &cached, &core);
                        kprintf("[fault] CR2=0x28 is the `mov %%fs:0x28` stack canary: FS BASE is "
                                "saved=%p live=%p cached=%p core=%d -- if those are 0 this thread "
                                "is running with NO TLS, and the bug is in clone/CLONE_SETTLS or "
                                "the context switch's FS_BASE restore\n",
                                (void *)task_fs_base(), (void *)live, (void *)cached, core);
                        /* AND WHO WROTE THAT ZERO (M2089). saved-good/live-zero
                         * narrows it to "the MSR was last written with zero on
                         * this core", and the remaining question -- by which
                         * task, and has anything happened since -- is the one
                         * that names the bug. Guessing it from the call sites
                         * cost most of a session: they all look right. */
                        {   int who = -1; uint64_t seq = 0, now = 0;
                            task_fs_base_last(&who, &seq, &now);
                            kprintf("[fault]   this core's FS_BASE was last written by tid %d "
                                    "(write #%lu of %lu -- %lu FS_BASE load(s) have happened "
                                    "elsewhere since), and this thread has been switched in %lu time(s)\n",
                                    who, seq, now, now - seq, task_nswitch_of(task_self()));
                        }
                    }
                    /* AND WHAT THE FAULTING PAGE IS. "present and not
                     * writable" and "present, not writable and COW" are
                     * completely different bugs -- the second is a copy-on-
                     * write break the handler should have taken, the first is
                     * a protection the program asked for -- and the error code
                     * alone cannot tell them apart. The terminate path has
                     * printed this since M2005; the caught path had nothing. */
                    if (r->int_no == 14) app_describe_fault_addr();
                    /* AND THE REGISTERS. A caught fault on `mov (%rax),%edx`
                     * says nothing without rax: a #GP there means the address
                     * is NON-CANONICAL, which is a different bug from a page
                     * that is merely absent, and the two are indistinguishable
                     * from the instruction alone. The terminate path below has
                     * dumped them since M1945; the caught path had nothing. */
                    dump_registers(&fregs);
                    /* AND WHAT IT WAS DOING. lx_trace_dump_fault runs on the
                     * terminate path only, so a caught fault left no history
                     * at all -- the one case where the program's own message
                     * is written by someone else's crash handler. */
                    if (lx_syscalls_made()) {
                        lx_trace_dump_fault();
                        /* ...and the address's own history (M2088). Both fault
                         * paths need it, and adding it to one of them is how a
                         * diagnostic ends up missing from exactly the case
                         * that fires: MOZ_CRASH writes to null and is CAUGHT,
                         * so the terminate path never sees a Firefox abort. */
                        if (r->int_no == 14) lx_trace_dump_addr("this caught fault", (unsigned long)cr2);
                    }
                }
                return;
            }
            /* REPORT FS_BASE (M2054). A ring-3 fault at CR2=0x28 is almost
             * always `mov %fs:0x28,%rax` -- glibc's stack canary -- read with
             * a ZERO thread pointer, and the dump could not distinguish "the
             * TLS base is zero" from "something dereferenced a null struct at
             * offset 0x28". Those are completely different bugs and they look
             * identical. One number separates them. */
            kprintf("[fault] FS_BASE=%p (a CR2 of 0x28 with FS_BASE=0 is the stack canary, not a null deref)\n",
                    (void *)(unsigned long)task_fs_base_live_value());
            /* WHICH THREAD (M2060). This line named neither the tid nor the
             * thread's own name, so attributing a fault in a program with
             * fifteen named threads meant matching `rsp` against a stack
             * address that happened to appear in the syscall ring -- and
             * getting it wrong sends you to the wrong subsystem entirely. A
             * runtime names its threads for exactly this purpose; print it. */
            kprintf("[fault] %s (vector %lu) err=0x%lx in a ring-3 task at rip=%p (CR2=%p) "
                    "[tid %d '%s'] -- terminating it\n",
                    exception_names[r->int_no], r->int_no, r->err_code, (void *)r->rip, (void *)cr2,
                    task_current_id(), task_name_of(task_self()));
            app_describe_addr(r->rip);   /* which library, and where inside it (M2003) */
            if (r->int_no == 14) app_describe_fault_addr();   /* ...and what the FAULTING page is (M2005) */
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
                /* NAME THE CANARY READ (M2012). `64 48 8b 04 25 28 00 00 00`
                 * is `mov %fs:0x28,%rax` -- the stack-protector canary, which
                 * every glibc function with a local buffer does on entry. When
                 * CR2 is 0x28 the FS base was ZERO, so this is not a wild
                 * pointer or a corrupted stack: it is a thread running with no
                 * TLS at all, and the fix is always in clone/CLONE_SETTLS or
                 * the context switch's FS_BASE restore rather than anywhere
                 * near the reported address. Worth a line, because the raw
                 * report reads as a generic null dereference in libc and sends
                 * you to the wrong place. */
                if (r->int_no == 14 && cr2 == 0x28 &&
                    ip[0] == 0x64 && ip[1] == 0x48 && ip[2] == 0x8b &&
                    ip[3] == 0x04 && ip[4] == 0x25 && ip[5] == 0x28)
                {
                    uint64_t live = 0, cached = 0; int core = -1;
                    task_fs_base_live(&live, &cached, &core);
                    kprintf("[fault] that is `mov %%fs:0x28,%%rax` -- the stack-protector canary, "
                            "read with a ZERO FS BASE (saved=%p live=%p cached=%p core=%d)\n",
                            (void *)task_fs_base(), (void *)live, (void *)cached, core);
                }
            }
            /* The last few syscalls, not the last 256: on a fault the tail is
             * what matters, and the full ring is hundreds of console-locked
             * lines. abort() still dumps the whole thing. */
            if (lx_syscalls_made()) {
                lx_trace_dump_fault();
                /* ...AND WHAT DECIDED THE FAULTING PAGE'S FATE (M2088). For a
                 * memory fault the thread's own recent history is usually
                 * three layers above the cause; the call that matters is the
                 * mmap or munmap that made this address what it is, and that
                 * can be thousands of syscalls back. Only for vector 14 --
                 * there is no faulting address to trace for anything else. */
                if (r->int_no == 14) lx_trace_dump_addr("this fault", (unsigned long)cr2);
                lx_user_backtrace(r);
            }
            app_fault_current(r);  /* dump a core, mark the app exited + task_exit(); does not return */
        }

        interrupts_disable();
        /* ONE PANIC, ONE PRINTER (M2080).
         *
         * Two cores faulting at once used to interleave two complete panic
         * reports into the same console, and the second one's registers are
         * noise. The loser goes quiet without emitting a byte -- its own fault
         * is real, but a second report nobody can parse is worth less than one
         * that reads cleanly. */
        {
            static volatile int panic_core = -1;
            int me = (int)smp_current_cpu(), none = -1;
            if (!__atomic_compare_exchange_n(&panic_core, &none, me, 0,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                for (;;) __asm__ volatile("cli; hlt");
        }
        /* Order matters, and it is the reverse of what it was. Panic mode goes
         * on FIRST so nothing below touches the console lock, then the NMI
         * silences the other cores, and console_gfx_reclaim() moves to the END
         * (below) so the screen copy is not paid for with a full-screen scroll
         * per line while interrupts are off. */
        console_panic_mode();
        smp_send_panic_nmi();
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
        /* The invariant this path depends on, asserted rather than assumed: if
         * anything above reached for the console lock, say so. A silent
         * violation is how the deadlock came back. */
        if (console_panic_lock_attempts())
            kprintf("  [con] %u attempt(s) to take the console lock IN PANIC MODE -- refused\n",
                    console_panic_lock_attempts());
        /* NOW the screen copy (M2011 still holds: a panic has to be visible
         * without a serial cable). fbcon clamps instead of scrolling while
         * panic mode is set, so this is one screenful, not a memmove per line. */
        console_gfx_reclaim();
        kprintf("*** KERNEL PANIC ***\n");
        kprintf("  %s (vector %lu) err=0x%lx rip=%p\n",
                exception_names[r->int_no], r->int_no, r->err_code, (void *)r->rip);
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
