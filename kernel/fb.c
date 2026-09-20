/*
 * fb.c — linear framebuffer graphics over QEMU's std VGA (Bochs VBE).
 *
 * VGA text mode is a grid of characters; a *framebuffer* is a flat array of
 * pixels you draw anything into. We ask QEMU's display adapter (the "Bochs VBE"
 * interface, via I/O ports 0x1CE/0x1CF) for a 32-bit-per-pixel linear mode,
 * find the framebuffer's physical address in the VGA card's PCI BAR0, map it,
 * and write pixels: each is 0x00RRGGBB.
 *
 * Text is rasterized with the 8x16 bitmap font in font.c (font_glyphs).
 */
#include "fb.h"
#include "font.h"
#include "pci.h"
#include "vmm.h"
#include "pmm.h"
#include "io.h"
#include "string.h"
#include "vfs.h"
#include "png.h"          /* png_encode */
#include "kheap.h"        /* kmalloc/kfree for the transient PNG buffers */
#include "bochs_vbe.h"    /* the DISPI mode-set driver fb_init delegates to */

static volatile uint32_t *lfb;
static uint32_t *target;      /* if set, draw here instead of the live screen */
static int fb_w, fb_h;
static int fb_stride;         /* LFB pixels per row: == fb_w for a tight LFB (QEMU/bochs); larger for a padded GOP framebuffer (some real-hw / OVMF modes) */

/* Re-point the framebuffer at a linear-framebuffer base of w*h 32-bpp pixels:
 * identity-map the LFB region (PAGE_SIZE at a time) and update the dims + LFB
 * pointer. Called by bochs_vbe_set_mode() after it programs the DISPI mode and
 * locates the BAR0 base. The pitch is implicit — every draw indexes the LFB as
 * y*fb_w + x — so the caller must have programmed VIRT_WIDTH = w to match.
 * Mapping is idempotent (a re-set to the same BAR just re-maps the same pages),
 * and fb_w/fb_h are updated LAST so a concurrent reader never sees a new size
 * against an unmapped page. */
void fb_repoint(uint64_t base, int w, int h) {
    uint64_t bytes = (uint64_t)w * (uint64_t)h * 4u;
    for (uint64_t off = 0; off < bytes; off += PAGE_SIZE)
        vmm_map(base + off, base + off, PTE_WRITABLE);
    lfb  = (volatile uint32_t *)(uintptr_t)base;
    fb_w = w;
    fb_h = h;
    fb_stride = w;            /* tight: this path (Bochs DISPI) programs VIRT_WIDTH = w */
}

/* Set a 32-bpp linear video mode of width*height via the Bochs DISPI driver,
 * which programs the mode, locates the LFB (the VGA's BAR0), maps it, and
 * re-points us at it. Returns 0 on success, -1 if DISPI is unavailable (no
 * std-VGA) — in which case the caller keeps whatever mode was already set. The
 * dedicated driver (bochs_vbe.c) owns the register sequence + validation; this
 * stays as the entry point the console (fbcon_init) calls. */
int fb_init(uint16_t width, uint16_t height) {
    return bochs_vbe_set_mode(width, height);
}

/* Use a Multiboot/GRUB-provided linear framebuffer (real hardware / a GRUB ISO,
 * and also QEMU -kernel, which honors our header's video request). The loader
 * set the mode and reported the LFB base + geometry in the multiboot info. We
 * accept ONLY a 32-bpp, tightly-packed (pitch == w*4) LFB, because every draw
 * indexes it as y*w + x with no separate pitch; anything else -> -1 so the
 * caller falls back to the Bochs DISPI path. Returns 0 on success. (M1292) */
int fb_init_mb(uint64_t base, int w, int h, int pitch, int bpp) {
    if (!base || w <= 0 || h <= 0 || bpp != 32 || (pitch & 3) || pitch < w * 4)
        return -1;            /* 32-bpp; pitch a dword multiple, at least a tight row */
    /* Map the FULL strided LFB (pitch may exceed w*4 on real GOP modes — drawing
     * indexes rows by the stride, so the padding bytes must be mapped too). */
    uint64_t bytes = (uint64_t)pitch * (uint64_t)h;
    for (uint64_t off = 0; off < bytes; off += PAGE_SIZE)
        vmm_map(base + off, base + off, PTE_WRITABLE);
    lfb = (volatile uint32_t *)(uintptr_t)base;
    fb_w = w; fb_h = h; fb_stride = pitch / 4;   /* honor the bootloader's row stride */
    return 0;
}

int fb_width(void)  { return fb_w; }
int fb_height(void) { return fb_h; }

/* Optional clip rectangle [x0,x1) x [y0,y1) in screen pixels, enforced by every
 * draw primitive in addition to the screen bounds. Defaults to "everything"
 * (0..INT_MAX) so it's a NO-OP until set — existing draws stay byte-identical.
 * The WM narrows it to a window's body around draw_content so a window's content
 * can never bleed past its edge onto a neighbour / the taskbar. */
static int clip_x0 = 0, clip_y0 = 0, clip_x1 = 0x7fffffff, clip_y1 = 0x7fffffff;
void fb_set_clip(int x0, int y0, int x1, int y1) { clip_x0 = x0; clip_y0 = y0; clip_x1 = x1; clip_y1 = y1; }
void fb_reset_clip(void) { clip_x0 = 0; clip_y0 = 0; clip_x1 = 0x7fffffff; clip_y1 = 0x7fffffff; }

void fb_pixel(int x, int y, uint32_t color) {
    if (x < clip_x0 || x >= clip_x1 || y < clip_y0 || y >= clip_y1) return;   /* clip rect (no-op at the default full range) */
    if ((unsigned)x < (unsigned)fb_w && (unsigned)y < (unsigned)fb_h) {
        if (target) target[y * fb_w + x] = color;
        else        lfb[y * fb_w + x]    = color;
    }
}

uint32_t fb_get_pixel(int x, int y) {
    if ((unsigned)x < (unsigned)fb_w && (unsigned)y < (unsigned)fb_h)
        return (target ? target[y * fb_w + x] : lfb[y * fb_w + x]) & 0xFFFFFF;
    return 0;
}

void fb_set_target(uint32_t *backbuffer) {
    target = backbuffer;
}

/* WRITE ONLY THE ROWS THAT ACTUALLY CHANGED (M2311).
 *
 * This copied the whole 1280x960 surface to the linear framebuffer on every
 * scene change -- about 4.9 MB, every frame. That is tolerable as memory
 * traffic and RUINOUS everywhere the framebuffer is watched: QEMU decides
 * what to send a remote console from the pages the guest DIRTIED, so touching
 * every page means the entire screen is re-encoded and pushed over the
 * network for a frame in which three pixels moved. The user's report was
 * "everything is so slow" on a Proxmox console, and this is the largest
 * single reason a fast guest looks slow through one.
 *
 * So compare the row against what the framebuffer already holds and skip the
 * write when they match. The comparison reads the LFB, which is slower than
 * RAM, so it is done in 16-row bands: one memcmp per band, one memcpy per
 * band that differs. A frame where nothing moved writes nothing at all; a
 * frame where a caret blinked writes one band.
 *
 * `fb_present_force()` stays for the cases that must not be elided -- a mode
 * set, or a screenshot reading back what it just drew. */
/* The comparison is against a RAM SHADOW of what was last written, never
 * against the framebuffer itself: the LFB is uncached MMIO, and reading
 * 4.9 MB of it per frame would cost far more than the blind write this is
 * meant to avoid. The shadow costs one screen of RAM. */
static uint32_t *fb_shadow;
static int       fb_shadow_ok;
void fb_present_force(void) {
    if (!target) return;
    if (fb_stride == fb_w) { memcpy((void *)lfb, target, (size_t)fb_w * fb_h * 4); return; }
    for (int y = 0; y < fb_h; y++)
        memcpy((void *)(lfb + (size_t)y * fb_stride), target + (size_t)y * fb_w, (size_t)fb_w * 4);
}
void fb_present(void) {
    if (!target) return;
    if (!fb_shadow) {
        fb_shadow = (uint32_t *)kmalloc((size_t)fb_w * fb_h * 4);
        fb_shadow_ok = 0;
    }
    if (!fb_shadow) { fb_present_force(); return; }      /* no memory: behave as before */
    if (!fb_shadow_ok) {                                  /* first frame: write it all */
        fb_present_force();
        memcpy(fb_shadow, target, (size_t)fb_w * fb_h * 4);
        fb_shadow_ok = 1;
        return;
    }
    for (int y = 0; y < fb_h; y++) {
        const uint32_t *src = target    + (size_t)y * fb_w;
        uint32_t       *shd = fb_shadow + (size_t)y * fb_w;
        if (memcmp(shd, src, (size_t)fb_w * 4) == 0) continue;   /* row unchanged */
        memcpy((void *)(lfb + (size_t)y * fb_stride), src, (size_t)fb_w * 4);
        memcpy(shd, src, (size_t)fb_w * 4);
    }
}

/* Save a screenshot of the live screen to `name` as a 24-bit BMP, downscaled to
 * at most SHOT_W x SHOT_H (every Nth pixel) so the file stays small (~576 KB) and
 * the write is light. Returns 0 on success, -1 on failure. */
#define SHOT_W 512
#define SHOT_H 384
static uint8_t g_shot[54 + SHOT_W * SHOT_H * 3];   /* BMP header + 24-bit pixels (BSS) */
int fb_save_bmp(const char *name) {
    if (!lfb || fb_w < 1 || fb_h < 1) return -1;
    const volatile uint32_t *src = lfb;   /* the live presented screen (a complete frame), not the WIP back buffer */
    int ow = fb_w < SHOT_W ? fb_w : SHOT_W;
    int oh = fb_h < SHOT_H ? fb_h : SHOT_H;
    int sx = fb_w / ow, sy = fb_h / oh;            /* integer downscale step */
    int row = ow * 3;                              /* 24-bit; ow is even so the row is 4-aligned */
    long datasz = (long)row * oh, total = 54 + datasz;
    uint8_t *h = g_shot;
    for (int i = 0; i < 54; i++) h[i] = 0;
    h[0] = 'B'; h[1] = 'M';
    h[2] = total; h[3] = total >> 8; h[4] = total >> 16; h[5] = total >> 24;
    h[10] = 54;                                    /* pixel-data offset */
    h[14] = 40;                                    /* DIB (BITMAPINFOHEADER) size */
    h[18] = ow; h[19] = ow >> 8; h[20] = ow >> 16; h[21] = ow >> 24;
    h[22] = oh; h[23] = oh >> 8; h[24] = oh >> 16; h[25] = oh >> 24;
    h[26] = 1;                                     /* planes */
    h[28] = 24;                                    /* bits per pixel */
    h[34] = datasz; h[35] = datasz >> 8; h[36] = datasz >> 16; h[37] = datasz >> 24;
    uint8_t *px = g_shot + 54;
    for (int oy = 0; oy < oh; oy++) {
        int iy = (oh - 1 - oy) * sy;               /* BMP scanlines are bottom-up */
        if (iy >= fb_h) iy = fb_h - 1;
        uint8_t *r = px + (long)oy * row;
        for (int ox = 0; ox < ow; ox++) {
            int ix = ox * sx; if (ix >= fb_w) ix = fb_w - 1;
            uint32_t c = src[(long)iy * fb_w + ix];   /* 0x00RRGGBB */
            r[ox*3+0] = c & 0xff;                  /* B */
            r[ox*3+1] = (c >> 8) & 0xff;           /* G */
            r[ox*3+2] = (c >> 16) & 0xff;          /* R */
        }
    }
    return vfs_write(name, g_shot, (unsigned long)total) < 0 ? -1 : 0;
}

/* Save a caller-supplied w*h 0x00RRGGBB buffer (e.g. a paint canvas) as a 24-bit
 * BMP file — same on-disk format as fb_save_bmp (14-byte file header + 40-byte
 * DIB, 24bpp BGR, bottom-up rows each padded to a 4-byte boundary) but full
 * resolution (no downscale) and reading the caller's `src` instead of the live
 * screen. The output size is caller-chosen, so the buffer is kmalloc'd (and
 * freed) rather than a fixed BSS array; w*h is capped first so a bogus size
 * can't request a huge or overflowing allocation. Returns 0 / -1. */
int fb_save_bmp_buf(const char *name, const uint32_t *src, int w, int h) {
    if (!src || w < 1 || h < 1) return -1;
    if ((long)w * h > 4000000L) return -1;         /* cap before allocating (guards overflow/huge alloc) */
    int row = w * 3;
    int pad = (4 - (row & 3)) & 3;                 /* each scanline padded to a 4-byte boundary */
    int stride = row + pad;
    long datasz = (long)stride * h, total = 54 + datasz;
    uint8_t *buf = kmalloc((unsigned long)total);
    if (!buf) return -1;
    uint8_t *hd = buf;
    for (int i = 0; i < 54; i++) hd[i] = 0;
    hd[0] = 'B'; hd[1] = 'M';
    hd[2] = total; hd[3] = total >> 8; hd[4] = total >> 16; hd[5] = total >> 24;
    hd[10] = 54;                                    /* pixel-data offset */
    hd[14] = 40;                                    /* DIB (BITMAPINFOHEADER) size */
    hd[18] = w; hd[19] = w >> 8; hd[20] = w >> 16; hd[21] = w >> 24;
    hd[22] = h; hd[23] = h >> 8; hd[24] = h >> 16; hd[25] = h >> 24;
    hd[26] = 1;                                     /* planes */
    hd[28] = 24;                                    /* bits per pixel */
    hd[34] = datasz; hd[35] = datasz >> 8; hd[36] = datasz >> 16; hd[37] = datasz >> 24;
    uint8_t *px = buf + 54;
    for (int oy = 0; oy < h; oy++) {
        int iy = h - 1 - oy;                        /* BMP scanlines are bottom-up */
        uint8_t *r = px + (long)oy * stride;
        for (int ox = 0; ox < w; ox++) {
            uint32_t c = src[(long)iy * w + ox];    /* 0x00RRGGBB */
            r[ox*3+0] = c & 0xff;                   /* B */
            r[ox*3+1] = (c >> 8) & 0xff;            /* G */
            r[ox*3+2] = (c >> 16) & 0xff;           /* R */
        }
        for (int p = 0; p < pad; p++) r[row + p] = 0;   /* pad bytes */
    }
    int rc = vfs_write(name, buf, (unsigned long)total) < 0 ? -1 : 0;
    kfree(buf);
    return rc;
}

/* Save a screenshot as a PNG (our from-scratch png_encode + DEFLATE). Same
 * 2x-downscale as fb_save_bmp, but PNG rows are top-down and RGB, and the file
 * is far smaller (the screen compresses well). Buffers are transient kmalloc
 * (RGB + filtered scratch + compressed out), freed before returning. */
int fb_save_png(const char *name) {
    if (!lfb || fb_w < 1 || fb_h < 1) return -1;
    const volatile uint32_t *src = lfb;            /* the presented frame, a complete scene */
    int ow = fb_w < SHOT_W ? fb_w : SHOT_W;
    int oh = fb_h < SHOT_H ? fb_h : SHOT_H;
    int sx = fb_w / ow, sy = fb_h / oh;            /* integer downscale step */
    long rgbsz = (long)ow * oh * 3;
    long scrsz = (1 + (long)ow * 3) * oh;          /* filtered scanlines png_encode needs */
    long outsz = scrsz + scrsz / 2 + 1024;         /* headroom for fixed-Huffman worst case + chunks */
    uint8_t *rgb = kmalloc((unsigned long)rgbsz);
    uint8_t *scr = kmalloc((unsigned long)scrsz);
    uint8_t *out = kmalloc((unsigned long)outsz);
    if (!rgb || !scr || !out) { if (rgb) kfree(rgb); if (scr) kfree(scr); if (out) kfree(out); return -1; }
    for (int oy = 0; oy < oh; oy++) {              /* capture top-down RGB */
        int iy = oy * sy; if (iy >= fb_h) iy = fb_h - 1;
        uint8_t *r = rgb + (long)oy * ow * 3;
        for (int ox = 0; ox < ow; ox++) {
            int ix = ox * sx; if (ix >= fb_w) ix = fb_w - 1;
            uint32_t c = src[(long)iy * fb_w + ix];   /* 0x00RRGGBB */
            r[ox*3+0] = (c >> 16) & 0xff;          /* R */
            r[ox*3+1] = (c >> 8) & 0xff;           /* G */
            r[ox*3+2] = c & 0xff;                  /* B */
        }
    }
    int n = png_encode(rgb, ow, oh, out, (int)outsz, scr, (int)scrsz);
    int rc = (n > 0 && vfs_write(name, out, (unsigned long)n) >= 0) ? 0 : -1;
    kfree(rgb); kfree(scr); kfree(out);
    return rc;
}

/* Copy just a clipped rectangle from the back buffer to the visible screen.
 * Used by the compositor to flush a small dirty area (e.g. the cursor) instead
 * of the whole ~3 MB framebuffer. */
void fb_present_rect(int x, int y, int w, int h) {
    if (!target) return;
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > fb_w) w = fb_w - x;
    if (y + h > fb_h) h = fb_h - y;
    if (w <= 0 || h <= 0) return;
    for (int j = 0; j < h; j++)
        memcpy((void *)(lfb + (size_t)(y + j) * fb_stride + x),
               target + (size_t)(y + j) * fb_w + x, (size_t)w * 4);
}

void fb_clear(uint32_t color) {
    for (int i = 0; i < fb_w * fb_h; i++)
        lfb[i] = color;
}

void fb_fill_rect(int x, int y, int w, int h, uint32_t color) {
    /* Clip the rectangle and resolve the destination ONCE, then fill with a
     * tight loop — instead of a bounds-checked, target-branching fb_pixel per
     * pixel. This is the hottest draw primitive (wallpaper, every window/title/
     * taskbar fill), run on every scene change. */
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > fb_w) w = fb_w - x;
    if (y + h > fb_h) h = fb_h - y;
    if (x < clip_x0) { w -= (clip_x0 - x); x = clip_x0; }     /* intersect the clip rect (no-op at the default full range) */
    if (y < clip_y0) { h -= (clip_y0 - y); y = clip_y0; }
    if (x + w > clip_x1) w = clip_x1 - x;
    if (y + h > clip_y1) h = clip_y1 - y;
    if (w <= 0 || h <= 0) return;
    uint32_t *dst = target ? target : (uint32_t *)lfb;
    for (int j = 0; j < h; j++) {
        uint32_t *row = dst + (size_t)(y + j) * fb_w + x;
        for (int i = 0; i < w; i++) row[i] = color;
    }
}

/* Scale each existing pixel's RGB by pct/100 in place — the soft-shadow
 * primitive. Same clip-and-resolve-once shape as fb_fill_rect, reading and
 * writing `row[i]` directly instead of a fb_get_pixel+fb_pixel call pair per
 * pixel: profiling a window-drag-heavy session found the desktop's 4-layer
 * drop shadow (kernel/desktop.c draw_window(), 4 full-window-sized passes per
 * redraw) alone was ~38% of all kernel-mode samples, almost entirely the two
 * calls' per-pixel bounds/clip checks and function-call overhead. */
void fb_darken_rect(int x, int y, int w, int h, int pct) {
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > fb_w) w = fb_w - x;
    if (y + h > fb_h) h = fb_h - y;
    if (x < clip_x0) { w -= (clip_x0 - x); x = clip_x0; }
    if (y < clip_y0) { h -= (clip_y0 - y); y = clip_y0; }
    if (x + w > clip_x1) w = clip_x1 - x;
    if (y + h > clip_y1) h = clip_y1 - y;
    if (w <= 0 || h <= 0) return;
    uint32_t *dst = target ? target : (uint32_t *)lfb;
    for (int j = 0; j < h; j++) {
        uint32_t *row = dst + (size_t)(y + j) * fb_w + x;
        for (int i = 0; i < w; i++) {
            uint32_t p = row[i];
            uint32_t r = ((p >> 16) & 0xFF) * pct / 100, g = ((p >> 8) & 0xFF) * pct / 100, b = (p & 0xFF) * pct / 100;
            row[i] = r << 16 | g << 8 | b;
        }
    }
}

/* Blit a caller's sw*sh 0x00RRGGBB canvas at (x,y), scaled up by an integer
 * factor (nearest-neighbour), masking each pixel to 24-bit colour. This is
 * the WM's per-frame path for painting a graphics app's pixel canvas into its
 * window body (DOOM/Quake/NES/scene3d/aclock/sysgraph/...) -- same
 * clip-and-resolve-once shape as fb_darken_rect/fb_glyph: when the whole
 * destination rect is on-screen (the common case), each destination row is
 * written directly once, and for scale > 1 the remaining (scale-1) copies of
 * that row are memcpy'd from the row just written instead of re-expanding
 * pixel by pixel -- avoiding a fb_pixel call (bounds check + clip check +
 * target branch) for every one of up to sw*sh*scale*scale pixels, every
 * redraw. Falls back to the original per-pixel path (still correct, just
 * slow) when the rect doesn't fully fit on-screen, e.g. a partially
 * off-screen or edge-dragged window. */
void fb_blit_scaled(int x, int y, const uint32_t *src, int sw, int sh, int scale) {
    int dw = sw * scale, dh = sh * scale;
    if (scale >= 1 &&
        x >= clip_x0 && y >= clip_y0 && x + dw <= clip_x1 && y + dh <= clip_y1 &&
        x >= 0 && y >= 0 && x + dw <= fb_w && y + dh <= fb_h) {
        uint32_t *dst = target ? target : (uint32_t *)lfb;
        for (int sy = 0; sy < sh; sy++) {
            uint32_t *row0 = dst + (size_t)(y + sy * scale) * fb_w + x;
            const uint32_t *srow = src + (size_t)sy * sw;
            if (scale == 1) {
                for (int sx = 0; sx < sw; sx++) row0[sx] = srow[sx] & 0xFFFFFF;
            } else {
                for (int sx = 0; sx < sw; sx++) {
                    uint32_t c = srow[sx] & 0xFFFFFF;
                    uint32_t *p = row0 + (size_t)sx * scale;
                    for (int k = 0; k < scale; k++) p[k] = c;
                }
                for (int oy = 1; oy < scale; oy++)
                    memcpy(dst + (size_t)(y + sy * scale + oy) * fb_w + x, row0, (size_t)dw * 4);
            }
        }
        return;
    }
    for (int yy = 0; yy < sh; yy++)                         /* clipped fallback: identical to the pre-fast-path code */
        for (int xx = 0; xx < sw; xx++) {
            uint32_t px = src[(size_t)yy * sw + xx] & 0xFFFFFF;
            if (scale == 1) { fb_pixel(x + xx, y + yy, px); continue; }
            for (int oy = 0; oy < scale; oy++)
                for (int ox = 0; ox < scale; ox++)
                    fb_pixel(x + xx * scale + ox, y + yy * scale + oy, px);
        }
}

/* Write `w` explicit, already-computed colours into one row at (x,y) -- for a
 * caller whose per-pixel colour is data-dependent (the browser's alpha-blended
 * <img> compositing: arbitrary nearest-neighbour scale, not a clean integer
 * factor like fb_blit_scaled, so there's no fixed source pixel to memcpy-repeat)
 * and so must compute each pixel itself, but still wants to skip a fb_pixel
 * call (bounds check + clip check + target branch) per pixel. Same
 * clip-and-resolve-once shape: writes the whole row directly when it's fully
 * on-screen, falls back to fb_pixel per pixel otherwise (e.g. a horizontally
 * clipped or partially off-screen row). */
void fb_row(int x, int y, int w, const uint32_t *colors) {
    if (y >= clip_y0 && y < clip_y1 && x >= clip_x0 && x + w <= clip_x1 &&
        y >= 0 && y < fb_h && x >= 0 && x + w <= fb_w) {
        uint32_t *dst = target ? target : (uint32_t *)lfb;
        uint32_t *row = dst + (size_t)y * fb_w + x;
        for (int i = 0; i < w; i++) row[i] = colors[i];
        return;
    }
    for (int i = 0; i < w; i++) fb_pixel(x + i, y, colors[i]);
}

void fb_glyph(int x, int y, char c, uint32_t fg, uint32_t bg) {
    unsigned char uc = (unsigned char)c;
    /* 0x80+ is the extended TUI set now, not an error (M2015) */
    const unsigned char *g = font_row(uc);
    /* fast path: the whole glyph is on-screen → write directly, no per-pixel
     * bounds test or target branch. This is the hot path for window text. */
    if (x >= clip_x0 && y >= clip_y0 && x + font_width <= clip_x1 && y + font_height <= clip_y1 &&
        x >= 0 && y >= 0 && x + font_width <= fb_w && y + font_height <= fb_h) {
        uint32_t *dst = target ? target : (uint32_t *)lfb;
        for (int row = 0; row < font_height; row++) {
            uint32_t *p = dst + (size_t)(y + row) * fb_w + x;
            unsigned bits = g[row];
            for (int col = 0; col < font_width; col++)
                p[col] = (bits & (0x80 >> col)) ? fg : bg;
        }
        return;
    }
    for (int row = 0; row < font_height; row++)            /* clipped fallback */
        for (int col = 0; col < font_width; col++)
            fb_pixel(x + col, y + row, (g[row] & (0x80 >> col)) ? fg : bg);
}

/* Transparent glyph: paint only the set pixels in `fg`, leaving the background
 * untouched. Used for UI labels drawn over an existing scene. */
void fb_glyph_fg(int x, int y, char c, uint32_t fg) {
    unsigned char uc = (unsigned char)c;
    /* 0x80+ is the extended TUI set now, not an error (M2015) */
    const unsigned char *g = font_row(uc);
    if (x >= clip_x0 && y >= clip_y0 && x + font_width <= clip_x1 && y + font_height <= clip_y1 &&
        x >= 0 && y >= 0 && x + font_width <= fb_w && y + font_height <= fb_h) {
        uint32_t *dst = target ? target : (uint32_t *)lfb;
        for (int row = 0; row < font_height; row++) {
            uint32_t *p = dst + (size_t)(y + row) * fb_w + x;
            unsigned bits = g[row];
            for (int col = 0; col < font_width; col++)
                if (bits & (0x80 >> col)) p[col] = fg;
        }
        return;
    }
    for (int row = 0; row < font_height; row++)            /* clipped fallback */
        for (int col = 0; col < font_width; col++)
            if (g[row] & (0x80 >> col)) fb_pixel(x + col, y + row, fg);
}

void fb_text(int x, int y, const char *s, uint32_t color, int scale) {
    for (int i = 0; s[i]; i++) {
        unsigned char uc = (unsigned char)s[i];
        /* 0x80+ is the extended TUI set now, not an error (M2015) */
        const unsigned char *g = font_row(uc);
        for (int row = 0; row < font_height; row++)
            for (int col = 0; col < font_width; col++)
                if (g[row] & (0x80 >> col))
                    fb_fill_rect(x + i * font_width * scale + col * scale,
                                 y + row * scale, scale, scale, color);
    }
}

void fb_scroll(int px, uint32_t bg) {
    /* memmove, not a per-pixel loop (same reasoning as fb_present's comment:
     * lfb is volatile, so an element loop can't be vectorised) -- called once
     * per text line from the early boot console (fbcon.c), so a screenful's
     * worth of pixels shifted one row at a time adds up across a busy boot log. */
    memmove((void *)lfb, (void *)(lfb + (size_t)px * fb_w), (size_t)(fb_h - px) * fb_w * 4);
    for (int y = fb_h - px; y < fb_h; y++)
        for (int x = 0; x < fb_w; x++)
            lfb[y * fb_w + x] = bg;
}
