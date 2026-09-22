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
#include "console.h"
#include "font.h"

static int cols, rows, cx, cy;
static uint32_t fg = 0xD0D0D0, bg = 0x0A0A18;

/* WHAT THE BOOT LOG COSTS TO DRAW (M2091).
 *
 * The user's complaint was "took like forever for the scrolling wall of text
 * to go away", and the wall of text is not a symptom of the slowness -- it is
 * a candidate for being the slowness. Every character is a per-pixel write and
 * every newline past the last row is fb_scroll, which memmoves the WHOLE
 * framebuffer: 4.9 MB at 1280x960x32. Into MMIO, under TCG, where each write
 * is a device access rather than a store.
 *
 * So measure it before touching it. rdtsc because the PIT is 10 ms and a
 * per-line cost is far below that; reported as cycles, which is comparable
 * across runs on one host without needing a calibrated clock. */
static uint64_t con_chars, con_lines, con_scrolls, con_cyc_glyph, con_cyc_scroll;
static inline uint64_t fbc_tsc(void) {
    uint32_t lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
void fbcon_stats(uint64_t *chars, uint64_t *lines, uint64_t *scrolls,
                 uint64_t *cyc_glyph, uint64_t *cyc_scroll) {
    if (chars)     *chars     = con_chars;
    if (lines)     *lines     = con_lines;
    if (scrolls)   *scrolls   = con_scrolls;
    if (cyc_glyph) *cyc_glyph = con_cyc_glyph;
    if (cyc_scroll)*cyc_scroll= con_cyc_scroll;
}

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
    /* 1280x960 -> 2560x1440 (M2367). This hardcoded pair was the ACTUAL screen
     * size: QEMU's -kernel multiboot loader ignores our header's video request
     * (there is no "[ ok ] Multiboot framebuffer" line in any boot log), so
     * fb_width() is 0 here and this call is what sets the mode. Editing the
     * boot header alone changed nothing.
     *
     * The goal requires the browser to be measured at 1440p or better, and a
     * benchmark run at a smaller resolution than claimed is not a measurement.
     * Largest first, falling back so a host with less video memory still comes
     * up rather than going black: 2560x1440x32 needs 14.75 MB, over QEMU's
     * 16 MB stdvga default once the console's own use is counted, so
     * tools/pve-run.sh asks for `--vga std,memory=32`. bochs_vbe_set_mode
     * refuses a mode the BAR cannot hold, which is what makes the fallback
     * safe rather than hopeful. */
    if (fb_width() == 0) {
        /* An explicit -append fbres=WxH wins, so a resolution A/B is a flag
         * rather than a rebuild (M2367). */
        extern int g_fbres_w, g_fbres_h;
        if (g_fbres_w && g_fbres_h && fb_init(g_fbres_w, g_fbres_h) == 0) {
            kprintf("[fb] %dx%d 32-bpp via Bochs DISPI (requested by fbres=)\n",
                    g_fbres_w, g_fbres_h);
            goto sized;
        }
        static const struct { int w, h; } modes[] = {
            { 2560, 1440 }, { 1920, 1200 }, { 1280, 960 },
        };
        unsigned i = 0;
        for (; i < sizeof modes / sizeof modes[0]; i++)
            if (fb_init(modes[i].w, modes[i].h) == 0) break;
        if (i == sizeof modes / sizeof modes[0])
            return -1;
        /* SAY WHICH ONE (M2367). Nothing printed the mode, so "the screenshot
         * is 1280x960" and "the mode-set failed back to 1280x960" looked
         * identical -- and the first 1440p attempt changed the boot header,
         * which this path never reads, with no way to tell from the log. */
        kprintf("[fb] %dx%d 32-bpp via Bochs DISPI%s\n", modes[i].w, modes[i].h,
                i ? " (a LARGER mode was refused -- not enough video memory)" : "");
    }
sized:
    cols = fb_width() / font_width;
    rows = fb_height() / font_height;
    cx = cy = 0;
    fb_clear(bg);
    return 0;
}

/* SCROLL BY A BLOCK, NOT BY A LINE (M2091).
 *
 * MEASURED FIRST, and the measurement is what makes this worth doing: a plain
 * boot spends 985 Mcycles in this console, of which 967 -- 98% -- is fb_scroll.
 * 272 scrolls at 3.56 MILLION cycles each, because each one memmoves the whole
 * 4.9 MB framebuffer, and on a framebuffer that is MMIO every one of those
 * bytes is a device access rather than a store. Drawing the glyphs costs 17
 * Mcycles, which is 2%; the per-character path was never the problem.
 *
 * A scroll cannot be avoided -- there is no panning register here, so the text
 * has to physically move -- but it does not have to happen once per line. Move
 * a BLOCK of lines and then use the freed rows one at a time: one memmove per
 * SCROLL_LINES lines instead of per line, which is the whole win, and the cost
 * per memmove is the same because it is one pass over the framebuffer either
 * way.
 *
 * The visible difference is that a full screen jumps by a quarter rather than
 * creeping by a line. For a boot log that is if anything easier to read, and
 * it is what every serial console has always done.
 *
 * BE HONEST ABOUT WHAT THIS DOES NOT FIX. It takes the console's share of a
 * noisy Firefox boot from about eight seconds to under one. The boot itself
 * takes two and a half MINUTES, and the rest of that is Firefox's own work
 * under TCG. The scrolling wall of text is not the slowness; it is what you
 * watch while the slowness happens. */
#define SCROLL_LINES 8

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
        uint64_t t0 = fbc_tsc();
        int n = SCROLL_LINES;
        if (n > rows) n = rows;
        fb_scroll(font_height * n, bg);
        con_cyc_scroll += fbc_tsc() - t0;
        con_scrolls++;
        cy = rows - n;                      /* n blank rows to fill before the next scroll */
    }
    con_lines++;
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
    default: {
        uint64_t t0 = fbc_tsc();
        fb_glyph(cx * font_width, cy * font_height, c, fg, bg);
        con_cyc_glyph += fbc_tsc() - t0;
        con_chars++;
        if (++cx >= cols)
            newline();
        break;
    }
    }
}
