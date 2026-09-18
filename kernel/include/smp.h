/* smp.h — symmetric multiprocessing: bring the application processors online
 * and run work on them.
 *
 * The kernel boots on the bootstrap processor (BSP); smp_init() enables the
 * local APIC, parses the ACPI MADT for the other cores, and brings each
 * application processor (AP) up through a real->long-mode trampoline
 * (kernel/asm/ap_trampoline.asm). Each AP adopts the kernel GDT+IDT, joins the
 * GENERAL scheduler (task_register_ap_core, M1531 — any task, kernel or ring-3,
 * can run on any core, preemptively), and idles in hlt when it has nothing
 * ready, waking on: the job-pool wake IPI (0x40, smp_parallel_for), its OWN
 * local LAPIC timer (0x42, M1532 — real per-core preemption), or (rarely) a
 * spurious/other IPI. The BSP can also run a pure-compute workload across all
 * cores in parallel via smp_parallel_for(), and hand off a long-lived kernel
 * thread to one specific core via kernel/smpthread.c's smp_thread_spawn.
 */
#pragma once
#include <stdint.h>

/* A parallel work function: process the half-open index range [lo, hi). It must
 * be PURE COMPUTE — no kmalloc / filesystem / other unsynchronised kernel state
 * (the pool gives no locking around it). */
typedef void (*smp_fn)(int lo, int hi, void *ctx);

extern int smp_cpu_count;          /* CPUs online: 1 (BSP) + each AP that started */
extern int smp_selftest_cores;     /* cores that ran a chunk in the boot self-test */
extern int smp_selftest_ok;        /* 1 = the boot parallel self-test matched */

void smp_init(void);               /* BSP: enable LAPIC, parse MADT, start the APs */
void ap_main(void);                /* AP 64-bit entry, called from the trampoline */
void lapic_enable_this_cpu(void);  /* software-enable the local APIC on this core */
void lapic_eoi(void);              /* end-of-interrupt to this core's local APIC */
void smp_parallel_for(int n, smp_fn fn, void *ctx);   /* run fn over [0,n) across all cores */
void smp_wake_aps(void);           /* IPI every AP awake (M1198's wake vector 0x40) */
void smp_send_tlb_shootdown_ipi(void);  /* all-but-self IPI at vector 0x41 (M1963) */
void smp_send_resched_ipi(void);   /* wake ONE idle core to pick up a newly-runnable task, vector 0x42 (M2216) */
void smp_resched_ack(int apic);    /* the 0x42 handler, clearing the in-flight flag (M2216) */
extern volatile unsigned char smp_core_idle[16];   /* set while that core is halted in the idle task (M2216) */
void smp_send_panic_nmi(void);           /* all-but-self NMI: stop every other core so a panic can print (M2080) */
void smp_tlb_shootdown_selftest(void); /* fire one at boot so the IPI path is exercised every time (M1963) */
void lapic_timer_start_this_cpu(void);  /* this core's own real periodic preemption source (M1532's vector 0x42) */
int  smp_current_cpu(void);        /* APIC id of the core running now, for sched_getcpu (M1246) */
