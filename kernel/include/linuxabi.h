/* linuxabi.h — the Linux x86-64 ABI compatibility layer (M1938). See
 * kernel/linuxabi.c for what this is and, importantly, what it is not: a
 * bolt-on second syscall entry path for running other people's binaries. The
 * native int 0x80 ABI is untouched. */
#pragma once
#include <stdint.h>

/* Arm the `syscall` instruction on the CALLING core. Must run on the BSP and
 * on every AP -- EFER.SCE, LSTAR, STAR, SFMASK and KERNEL_GS_BASE are all
 * per-core MSRs. */
void linux_abi_init_this_cpu(void);

/* Mirror a core's ring-0 stack top for the syscall entry path, which gets no
 * stack from the CPU and so cannot read the TSS. Called from tss_set_rsp0. */
void linux_abi_set_kernel_rsp(int cpu, uint64_t rsp);

/* Boot self-test: prove the entry path is real (M1938). */
void linux_abi_selftest(void);
