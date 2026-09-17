/* pmm.h — physical memory manager: hands out 4 KiB physical page frames. */
#pragma once
#include <stdint.h>

#define PAGE_SIZE 4096

void     pmm_init(uint64_t multiboot_info_phys);
uint64_t pmm_alloc_frame(void);          /* returns a physical address, or 0 */
void     pmm_free_frame(uint64_t phys);  /* drops one reference; releases the frame at the last */
uint64_t pmm_alloc_contiguous(uint64_t n, uint64_t align);  /* n contiguous frames, base aligned to `align` frames; phys/0 (M1155) */
void     pmm_free_contiguous(uint64_t phys, uint64_t n);    /* free a run from pmm_alloc_contiguous (M1155) */
void     pmm_addref(uint64_t phys);      /* add an extra reference (a frame mapped more than once) */
int      pmm_refcount(uint64_t phys);    /* extra-ref count: 0 = single-owner, >0 = shared/mirrored */
int      pmm_refcountable(uint64_t phys); /* 1 if the frame is within the refcount array (safe to COW-share) */

uint64_t pmm_total_bytes(void);
uint64_t pmm_free_bytes(void);
/* The physical ADDRESS SPAN the allocator can return frames from -- larger than
 * pmm_total_bytes whenever there is a PCI/MMIO hole. Anything that must REACH a
 * frame (the HHDM) needs this; anything REPORTING memory needs total. (M2159) */
uint64_t pmm_span_bytes(void);
