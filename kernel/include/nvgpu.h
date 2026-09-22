/* nvgpu.h — NVIDIA GPU bring-up (GT 1030 / GP108). See nvgpu.c. */
#pragma once
#include <stdint.h>

/* Find the card, describe its BARs, map BAR0 higher-half, and read
 * PMC_BOOT_0. 0 if a real NVIDIA chip answered, -1 otherwise (and it says
 * WHICH of "no device", "no BAR", "no response" it was). */
int      nvgpu_init(void);
int      nvgpu_present(void);
uint32_t nvgpu_boot0(void);
