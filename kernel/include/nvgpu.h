/* nvgpu.h — NVIDIA GPU bring-up (GT 1030 / GP108). See nvgpu.c. */
#pragma once
#include <stdint.h>

/* Find the card, describe its BARs, map BAR0 higher-half, and read
 * PMC_BOOT_0. 0 if a real NVIDIA chip answered, -1 otherwise (and it says
 * WHICH of "no device", "no BAR", "no response" it was). */
int      nvgpu_init(void);
int      nvgpu_present(void);
uint32_t nvgpu_boot0(void);

/* For the nouveau DRM personality (kernel/nvdrm.c, M2390): what the card
 * is, as the kernel measured it -- never a table of assumed values. */
int      nvgpu_drm_ok(void);                 /* present AND POSTed */
void     nvgpu_pci_bdf(unsigned *bus, unsigned *slot, unsigned *func);
uint16_t nvgpu_device_id(void);
uint64_t nvgpu_vram_bytes(void);             /* 0 until 0x100ce0 has been read */
uint32_t nvgpu_pci_cfg(unsigned off);        /* a dword of the card's PCI config space */
