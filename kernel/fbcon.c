/*
 * fbcon.c — a scrolling text console drawn on the framebuffer.
 *
 * Once graphics mode is up, the kernel no longer has the VGA text grid; this
 * module recreates a terminal on top of raw pixels. It keeps a character grid
 * (columns × rows derived from the screen and font size) and a cursor, draws
 * each glyph with fb_glyph, and scrolls by shifting the framebuffer up a line.
 *
 * console.c routes all kernel/shell output here once graphics is enabled, so
 * everything you'd normally see in text mode now renders graphically.
 */
#include "fbcon.h"
#include "fb.h"
#include "font.h"

static int cols, rows, cx, cy;
static uint32_t fg = 0xD0D0D0, bg = 0x0A0A18;

void fbcon_set_colors(unsigned f, unsigned b) { fg = f; bg = b; }

int fbcon_init(void) {
    /* Ask the Bochs DISPI driver for a 32-bpp linear mode. 1280x960 is a 4:3
     * step up from the old 1024x768 that QEMU's std-VGA supports (its 16 MB of
     * VGA memory holds the 4.9 MB framebuffer with room to spare). Because this
     * runs at boot — before desktop_run() reads fb_width()/fb_height() — the
     * whole desktop comes up at the new resolution with no live re-layout.
     * If DISPI is absent (a config without std-VGA), fb_init returns -1 and we
     * fall back to leaving the boot/VGA mode untouched (no black screen). */
    /* If a framebuffer is already up (a Multiboot/GRUB-provided LFB set in kmain
     * via fb_init_mb — real hardware, a GRUB ISO, or QEMU honoring our header's
     * video request), use it as-is. Otherwise ask the Bochs DISPI driver for a
     * 1280x960x32 mode (QEMU std-VGA). DISPI absent + no Multiboot FB -> -1,
     * leaving the boot mode untouched (no black screen). */
    if (fb_width() == 0 && fb_init(1280, 960) != 0)
        return -1;
    cols = fb_width() / font_width;
    rows = fb_height() / font_height;
    cx = cy = 0;
    fb_clear(bg);
    return 0;
}

static void newline(void) {
    cx = 0;
    if (++cy >= rows) {
        /* NOT WHILE PANICKING (M2080). fb_scroll shifts the whole framebuffer
         * -- 4.9 MB of memmove at 1280x960x32 -- and the panic path calls this
         * once per line with interrupts off on its own core. Clamping keeps the
         * first screenful, which is the part with the exception, the registers
         * and the top of the backtrace; the complete text is on serial. */
        extern int console_in_panic(void);
        if (console_in_panic()) { cy = rows - 1; return; }
        fb_scroll(font_height, bg);
        cy = rows - 1;
    }
}

void fbcon_putc(char c) {
    switch (c) {
    case '\n':
        newline();
        break;
    case '\r':
        cx = 0;
        break;
    case '\b':
        if (cx > 0) {
            cx--;
            fb_glyph(cx * font_width, cy * font_height, ' ', fg, bg);
        }
        break;
    case '\t':
        cx = (cx + 4) & ~3;
        if (cx >= cols)
            newline();
        break;
    default:
        fb_glyph(cx * font_width, cy * font_height, c, fg, bg);
        if (++cx >= cols)
            newline();
        break;
    }
}
