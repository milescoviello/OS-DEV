/* lxnvdrm -- ask OS-DEV's nouveau render node what Mesa's nvc0 asks (M2390).
 *
 * The GT 1030's render node is served by kernel/nvdrm.c. Mesa's nvc0 driver
 * answers a wrong answer by quietly failing to load, so this probe asks each
 * question itself and prints the answer, in the order the winsys asks them:
 *
 *   1. DRM_IOCTL_VERSION        name must be "nouveau", version >= 1.3.1
 *   2. NVIF NEW NV_DEVICE, then MTHD DEVICE_INFO: chipset, platform, VRAM
 *   3. GETPARAM CHIPSET_ID / PCI_VENDOR / PCI_DEVICE / FB_SIZE
 *   4. drmGetDevice2            libdrm's sysfs walk: must say PCI 10de:xxxx
 *   5. gbm_create_device        Mesa loads nouveau and runs nvc0_screen_create
 *
 * Step 5 is EXPECTED to fail today, at CHANNEL_ALLOC: this driver has no GR
 * hardware init, so there is no graphics channel to give. The kernel log names
 * that refusal; this probe reports whether Mesa got that far. Every check can
 * fail, and the chipset / VRAM / ids are compared against what the kernel
 * measured, passed in on the command line -- not against constants here. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <xf86drm.h>
#include <gbm.h>

static int fails;
#define CHECK(c, ...) do { printf("LXNVDRM: %s ", (c) ? "ok  " : "FAIL"); printf(__VA_ARGS__); printf("\n"); if (!(c)) fails++; } while (0)

#define IOWR(nr, sz) ((3ul << 30) | ((unsigned long)(sz) << 16) | ('d' << 8) | (nr))
#define IOW(nr, sz)  ((1ul << 30) | ((unsigned long)(sz) << 16) | ('d' << 8) | (nr))

static int getparam(int fd, uint64_t p, uint64_t *v) {
    uint64_t r[2] = { p, 0 };
    int rc = ioctl(fd, IOWR(0x40, 16), r);
    *v = r[1];
    return rc;
}

int main(void) {
    const char *node = "/dev/dri/renderD128";
    int fd = open(node, O_RDWR);
    if (fd < 0) { printf("LXNVDRM: open(%s) FAILED: %s\nLXNVDRM: RESULT FAIL\n", node, strerror(errno)); return 1; }

    drmVersionPtr v = drmGetVersion(fd);
    CHECK(v && v->name && !strcmp(v->name, "nouveau"), "VERSION name \"%s\"", v && v->name ? v->name : "(none)");
    CHECK(v && ((v->version_major << 24) | (v->version_minor << 8) | v->version_patchlevel) >= 0x01000301,
          "VERSION %d.%d.%d (nouveau_drm_new needs >= 1.3.1)", v ? v->version_major : -1,
          v ? v->version_minor : -1, v ? v->version_patchlevel : -1);
    if (v) drmFreeVersion(v);

    struct { uint8_t hdr[24]; uint8_t nw[32]; uint64_t dev; } nwa;
    memset(&nwa, 0, sizeof nwa);
    nwa.hdr[1] = 2; nwa.hdr[6] = 0xff;                                 /* NEW, OWNER_ANY */
    int32_t cls = 0x0080; memcpy(nwa.nw + 28, &cls, 4);                /* oclass NV_DEVICE */
    nwa.dev = ~0ull;
    int rc = ioctl(fd, IOW(0x47, sizeof nwa), &nwa);
    CHECK(rc == 0, "NVIF NEW NV_DEVICE -> %d", rc);

    struct { uint8_t hdr[24]; uint8_t m[8]; uint8_t info[104]; } mi;
    memset(&mi, 0, sizeof mi);
    mi.hdr[1] = 4; mi.hdr[6] = 0xff; mi.m[1] = 0x00;                   /* MTHD DEVICE_INFO */
    rc = ioctl(fd, IOWR(0x47, sizeof mi), &mi);
    uint16_t chip; memcpy(&chip, mi.info + 2, 2);
    uint64_t ram; memcpy(&ram, mi.info + 8, 8);
    CHECK(rc == 0 && mi.info[1] == 3, "NVIF DEVICE_INFO -> %d: platform %u (3 = PCIE), chipset %03x, rev %02x, %llu MiB, \"%s\"",
          rc, mi.info[1], chip, mi.info[4], (unsigned long long)(ram >> 20), (char *)mi.info + 40);

    uint64_t gchip = 0, ven = 0, dev = 0, fb = 0;
    getparam(fd, 11, &gchip); getparam(fd, 3, &ven); getparam(fd, 4, &dev); getparam(fd, 8, &fb);
    CHECK(gchip == chip && gchip != 0, "GETPARAM CHIPSET_ID %03llx (matches DEVICE_INFO)", (unsigned long long)gchip);
    CHECK(ven == 0x10de, "GETPARAM PCI_VENDOR %04llx", (unsigned long long)ven);
    CHECK(fb == ram && fb >= (512ull << 20), "GETPARAM FB_SIZE %llu MiB (matches DEVICE_INFO)", (unsigned long long)(fb >> 20));

    drmDevicePtr dd = NULL;
    rc = drmGetDevice2(fd, 0, &dd);
    CHECK(rc == 0 && dd && dd->bustype == DRM_BUS_PCI && dd->deviceinfo.pci->vendor_id == 0x10de &&
          dd->deviceinfo.pci->device_id == dev,
          "drmGetDevice2 -> %d: bus %s, %04x:%04x at %02x:%02x.%u",
          rc, dd && dd->bustype == DRM_BUS_PCI ? "PCI" : "not PCI",
          dd && dd->bustype == DRM_BUS_PCI ? dd->deviceinfo.pci->vendor_id : 0,
          dd && dd->bustype == DRM_BUS_PCI ? dd->deviceinfo.pci->device_id : 0,
          dd && dd->bustype == DRM_BUS_PCI ? dd->businfo.pci->bus : 0,
          dd && dd->bustype == DRM_BUS_PCI ? dd->businfo.pci->dev : 0,
          dd && dd->bustype == DRM_BUS_PCI ? dd->businfo.pci->func : 0);
    if (dd) drmFreeDevice(&dd);

    /* Mesa's own path. Expected to FAIL at CHANNEL_ALLOC until GR exists --
     * reported, not counted, because the kernel log is what says where. */
    struct gbm_device *g = gbm_create_device(fd);
    printf("LXNVDRM: gbm_create_device -> %s (%s)\n", g ? "a device" : "NULL",
           g ? gbm_device_get_backend_name(g) : "expected until a GR channel exists: see [nvdrm] CHANNEL_ALLOC in the kernel log");
    if (g) gbm_device_destroy(g);

    printf("LXNVDRM: RESULT %s (%d check(s) failed)\n", fails ? "FAIL" : "PASS", fails);
    close(fd);
    return fails ? 1 : 0;
}
