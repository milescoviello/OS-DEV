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

/* Build a System V initial process stack (argc/argv/envp/auxv) for a Linux
 * binary at the top of an already-mapped user stack, and return the RSP it
 * should start with (0 on failure). Must be called with the TARGET address
 * space active. `image` is the raw ELF, needed for AT_PHDR/PHENT/PHNUM. M1939. */
/* As lx_spawn_stack, but for a DYNAMICALLY-LINKED image: interp_base is the
 * interpreter's load bias and becomes auxv AT_BASE, while AT_PHDR/AT_ENTRY
 * still describe the executable. (M1954) */
uint64_t lx_spawn_stack_dyn(const void *image, uint64_t base, uint64_t entry,
                            uint64_t interp_base,
                            uint64_t stack_top, uint64_t stack_bottom,
                            const char *const *argv, const char *const *envp);
uint64_t lx_spawn_stack(const void *image, uint64_t base, uint64_t entry,
                        uint64_t stack_top, uint64_t stack_bottom,
                        const char *const *argv, const char *const *envp);

extern int g_lx_mmap_trace;    /* -append lxmmaptrace: log every Linux mmap/mprotect (M1955) */
extern int g_lx_systrace;      /* -append lxsystrace: log EVERY Linux syscall */
void lx_trace_dump(const char *why);
/* The last fatal signal a Linux process died of, and which pid. Returns 0 if
 * nothing has crashed. A crash is an event; the boot timeline polls counters
 * and cannot see one. (M2106) */
void lx_watch_fd(int fd);   /* follow the reads on a document's descriptor: a successful open is not a successful load (M2107) */
void lx_fatal_record(int pid, int sig);
int  lx_fatal_signal(int *pid);
unsigned long lx_path_truncations(void);   /* paths silently shortened into a DIFFERENT file -- all three join points (M2197) */
void lx_trace_dump_last(const char *why, unsigned long want);  /* ...or just the last `want` (M1985) */
void lx_trace_dump_fault(void);   /* the ring at a ring-3 fault: deep under lxsystrace, modest otherwise (M2003) */
void lx_trace_dump_addr(const char *why, unsigned long addr);   /* every mmap/munmap/mprotect that covered ONE address (M2088) */
void lx_user_backtrace(struct registers *r);   /* walk the user stack for return addresses (M1970) */
unsigned long lx_syscalls_made(void);          /* 0 = nothing has used the Linux ABI this boot */
const char *lx_syscall_name(unsigned long nr);   /* a readable name for a syscall number, for the per-process histogram (M2066) */
void lx_trace_dump_pid(const char *why, unsigned long want, int only_pid);   /* the ring, filtered to ONE process (M2069) */
void lx_trace_dump_tid(const char *why, unsigned long want, int only_tid);   /* ...and to ONE THREAD, which is what a fault needs (M2086) */
void lx_ring_top(void);   /* which syscall the ring is FULL of: a sample of what is spinning (M2102) */
