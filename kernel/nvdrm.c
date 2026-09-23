/* nvdrm.c -- the nouveau DRM uAPI, served for OS-DEV's own GT 1030 driver
 * (M2390).
 *
 * Goal step 6 reuses Mesa's nvc0 gallium driver as-is. Mesa 26 carries its
 * own copy of libdrm_nouveau (src/gallium/winsys/nouveau/drm/nouveau.c), so
 * the contract is exactly what that one file asks of a render node, read from
 * its source rather than guessed:
 *
 *   drmGetVersion        name "nouveau", version >= 1.3.1 (nouveau_drm_new)
 *   NVIF NEW NV_DEVICE   the device object            (nouveau_device_new)
 *   NVIF MTHD INFO       chipset / platform / VRAM    (nouveau_device_info)
 *   drmGetDevice2        answered by procfs's sysfs, from the real PCI ids
 *   GETPARAM FB_SIZE, AGP_SIZE, and the loader's HAS_VMA_TILEMODE/CHIPSET_ID
 *   CHANNEL_ALLOC        the first thing nvc0_screen_create needs a GPU for
 *
 * WHAT IS NOT HERE, SAID PLAINLY: a channel. A GR channel needs GR's hardware
 * init and a golden context image, and this driver does not have them -- so
 * CHANNEL_ALLOC is refused BY NAME, and every ioctl not listed above is logged
 * once by number and refused. An unimplemented ioctl must surface as itself,
 * not as "WebGL fell back to software" three layers up (the lesson of the
 * virgl probe, M2347).
 *
 * Every answer comes from what nvgpu.c measured on the card: PMC_BOOT_0 for
 * the chipset, 0x100ce0 for VRAM, PCI config space for the ids. */
#include "nvgpu.h"
#include "console.h"
#include "string.h"
#include "vmm.h"
#include <stdint.h>

#define E_INVAL  (-22)
#define E_FAULT  (-14)
#define E_NODEV  (-19)
#define E_NOSYS  (-38)

/* DRM ioctl numbers: dir<<30 | size<<16 | 'd'<<8 | nr. nouveau's are
 * DRM_COMMAND_BASE (0x40) + index, and drmCommandWrite() encodes the CALLER's
 * struct size -- NVIF's is variable -- so dispatch is on nr, with the size
 * taken from the number itself. */
#define IOC_NR(r)   ((unsigned)((r) & 0xff))
#define IOC_SIZE(r) ((unsigned)(((r) >> 16) & 0x3fff))
#define NR_VERSION        0x00
#define NR_GET_CAP        0x0c
#define NR_NV_GETPARAM    0x40
#define NR_NV_CHAN_ALLOC  0x42
#define NR_NV_NVIF        0x47

static void nv_seen(unsigned long req, const char *what, long rc) {
    static unsigned long seen[48]; static int nseen;
    for (int i = 0; i < nseen; i++) if (seen[i] == req) return;
    if (nseen < 48) seen[nseen++] = req;
    kprintf("[nvdrm] %s (0x%lx) -> %ld\n", what, req, rc);
}

static long nv_version(void *uarg) {
    struct drm_version { int version_major, version_minor, version_patchlevel; int pad;
                         uint64_t name_len, name, date_len, date, desc_len, desc; } v;
    if (!uarg || !vmm_user_ok((uint64_t)(uintptr_t)uarg, sizeof v)) return E_FAULT;
    memcpy(&v, uarg, sizeof v);
    /* 1.3.1 is the floor nouveau_drm_new enforces (drm->version < 0x01000301
     * fails). Nothing in Mesa's nvc0 gates a feature on a higher number, so
     * claim exactly the floor rather than a version whose features we lack. */
    v.version_major = 1; v.version_minor = 3; v.version_patchlevel = 1;
    static const char *nm = "nouveau", *dt = "0", *ds = "nVidia Riva/TNT/GeForce/Quadro/Tesla/Tegra K1+ (OS-DEV)";
    struct { uint64_t *len; uint64_t ptr; const char *src; } f[3] = {
        { &v.name_len, v.name, nm }, { &v.date_len, v.date, dt }, { &v.desc_len, v.desc, ds } };
    for (int i = 0; i < 3; i++) {
        uint64_t n = strlen(f[i].src);
        if (f[i].ptr && *f[i].len) {
            uint64_t cp = n < *f[i].len ? n : *f[i].len;
            if (!vmm_user_ok(f[i].ptr, cp)) return E_FAULT;
            memcpy((void *)(uintptr_t)f[i].ptr, f[i].src, cp);
            *f[i].len = cp;
        } else *f[i].len = n;
    }
    memcpy(uarg, &v, sizeof v);
    return 0;
}

static long nv_getparam(void *uarg) {
    uint64_t r[2];
    if (!uarg || !vmm_user_ok((uint64_t)(uintptr_t)uarg, sizeof r)) return E_FAULT;
    memcpy(r, uarg, sizeof r);
    unsigned b, s, f; nvgpu_pci_bdf(&b, &s, &f);
    long rc = 0;
    switch (r[0]) {
    case 3:  r[1] = 0x10de; break;                                   /* PCI_VENDOR */
    case 4:  r[1] = nvgpu_device_id(); break;                        /* PCI_DEVICE */
    case 5:  r[1] = 2; break;                                        /* BUS_TYPE: PCIE is 2 (nouveau_abi16.c; 3 is SOC) */
    case 8:  r[1] = nvgpu_vram_bytes(); break;                       /* FB_SIZE */
    case 9:  r[1] = 0; break;                                        /* AGP_SIZE: no GART aperture yet */
    case 11: r[1] = (nvgpu_boot0() >> 20) & 0x1ff; break;            /* CHIPSET_ID, from PMC_BOOT_0 */
    case 15: r[1] = 1; break;                                        /* HAS_BO_USAGE */
    default: rc = E_INVAL; break;                                    /* incl. HAS_VMA_TILEMODE: not supported */
    }
    kprintf("[nvdrm] GETPARAM %lu -> %s%lx\n", (unsigned long)r[0], rc ? "EINVAL " : "", (unsigned long)(rc ? 0 : r[1]));
    if (rc) return rc;
    memcpy(uarg, r, sizeof r);
    return 0;
}

/* NVIF: nvif_ioctl_v0 { u8 version, type, pad[4], owner, route; u64 token,
 * object; data[] } followed by the per-type struct (nvif/ioctl.h). */
#define NV_DEVICE 0x0080
static long nv_nvif(unsigned size, void *uarg) {
    uint8_t a[512];
    if (!uarg || size < 24 || size > sizeof a || !vmm_user_ok((uint64_t)(uintptr_t)uarg, size)) return E_FAULT;
    memcpy(a, uarg, size);
    uint8_t type = a[1];
    long rc = E_NOSYS;
    switch (type) {
    case 2: {                                                        /* NEW */
        if (size < 56) { rc = E_INVAL; break; }
        int32_t oclass; memcpy(&oclass, a + 52, 4);
        rc = oclass == NV_DEVICE ? 0 : E_NOSYS;
        kprintf("[nvdrm] NVIF NEW oclass %04x -> %s\n", (unsigned)oclass, rc ? "not implemented" : "device");
        break;
    }
    case 3: rc = 0; break;                                           /* DEL */
    case 4: {                                                        /* MTHD */
        if (size < 32) { rc = E_INVAL; break; }
        uint8_t method = a[25];
        if (method == 0x00 && size >= 32 + 104) {                    /* NV_DEVICE_V0_INFO */
            uint8_t *i = a + 32;
            uint32_t boot0 = nvgpu_boot0();
            uint16_t chip = (boot0 >> 20) & 0x1ff;
            uint64_t vram = nvgpu_vram_bytes();
            i[1] = 0x03;                                             /* PCIE */
            memcpy(i + 2, &chip, 2);
            i[4] = boot0 & 0xff;                                     /* revision */
            i[5] = 0x0a;                                             /* family: Pascal (kernel nouveau's NV_DEVICE_INFO_V0_PASCAL) */
            memcpy(i + 8, &vram, 8); memcpy(i + 16, &vram, 8);
            static const char chipname[] = "GP108", name[] = "GeForce GT 1030 (OS-DEV nvgpu)";
            memset(i + 24, 0, 80);
            memcpy(i + 24, chipname, sizeof chipname);
            memcpy(i + 40, name, sizeof name);
            rc = 0;
            kprintf("[nvdrm] NVIF MTHD DEVICE_INFO -> chipset %03x rev %02x, %lu MiB, PCIe\n",
                    chip, boot0 & 0xff, (unsigned long)(vram >> 20));
        } else {
            kprintf("[nvdrm] NVIF MTHD %02x (size %u) -> not implemented\n", method, size);
        }
        break;
    }
    case 1: {                                                        /* SCLASS */
        /* What GP108 exposes (gp107_gr sclass, gp100 fifo/ce): the channel
         * class and the engine classes a channel binds with SET_OBJECT. */
        static const int32_t cls[] = { 0xc06f, 0xc197, 0xc1c0, 0x902d, 0xa140, 0xc0b5 };
        unsigned n = sizeof cls / sizeof cls[0], cap = a[25];
        for (unsigned k = 0; k < n && k < cap && 32 + (k + 1) * 8 <= size; k++) {
            memcpy(a + 32 + k * 8, &cls[k], 4);
            memset(a + 36 + k * 8, 0, 4);
        }
        a[25] = (uint8_t)n;
        rc = 0;
        kprintf("[nvdrm] NVIF SCLASS -> %u classes (room for %u)\n", n, cap);
        break;
    }
    default:
        kprintf("[nvdrm] NVIF type %u -> not implemented\n", type);
    }
    if (rc == 0) memcpy(uarg, a, size);
    return rc;
}

long nvdrm_ioctl(unsigned long req, void *uarg) {
    if (!nvgpu_drm_ok()) { nv_seen(req, "ioctl on a card that has not POSTed", E_NODEV); return E_NODEV; }
    long rc;
    switch (IOC_NR(req)) {
    case NR_VERSION:       rc = nv_version(uarg); nv_seen(req, "VERSION (nouveau 1.3.1)", rc); return rc;
    case NR_NV_GETPARAM:   return nv_getparam(uarg);
    case NR_NV_NVIF:       return nv_nvif(IOC_SIZE(req), uarg);
    case NR_NV_CHAN_ALLOC:
        kprintf("[nvdrm] CHANNEL_ALLOC -> refused: GR has no hardware init and no golden context in this "
                "driver, so there is no graphics channel to give. nvc0_screen_create stops HERE.\n");
        return E_NODEV;
    default:
        nv_seen(req, "not implemented", E_NOSYS);
        return E_NOSYS;
    }
}
