/*
 * term.c — a terminal widget: a small shell that lives inside a window.
 *
 * Unlike the ring-3 shell from M9 (which takes over the whole screen via
 * enter_user), this is a kernel-side shell rendered into a character grid that
 * the window manager paints inside a window's body. The WM feeds it keystrokes
 * when its window is focused. It reuses the real VFS, so `ls`/`cat` read the
 * actual FAT32 disk.
 */
#include "term.h"
#include "fb.h"
#include "font.h"
#include "vfs.h"
#include "kheap.h"   /* listings are heap-allocated: a dirent name is 256 bytes (M2062) */
#include "timer.h"
#include "string.h"

#define TCOLS 40
#define TROWS 12

static char grid[TROWS][TCOLS];
static int  cx, cy;
static char inbuf[TCOLS];
static int  inlen;

int term_cols(void) { return TCOLS; }
int term_rows(void) { return TROWS; }

static void clear(void) {
    for (int r = 0; r < TROWS; r++)
        for (int c = 0; c < TCOLS; c++)
            grid[r][c] = ' ';
    cx = cy = 0;
}

static void scroll(void) {
    for (int r = 1; r < TROWS; r++)
        memcpy(grid[r - 1], grid[r], TCOLS);
    for (int c = 0; c < TCOLS; c++)
        grid[TROWS - 1][c] = ' ';
    cy = TROWS - 1;
}

static void newline(void) { cx = 0; if (++cy >= TROWS) scroll(); }

static void put(char ch) {
    if (ch == '\n') { newline(); return; }
    grid[cy][cx] = ch;
    if (++cx >= TCOLS) newline();
}

static void print(const char *s) { for (; *s; s++) put(*s); }
static void prompt(void) { print("$ "); }

static int eq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == *b;
}
static int starts(const char *s, const char *p) {
    while (*p) { if (*s != *p) return 0; s++; p++; }
    return 1;
}

static void print_uint(uint64_t v) {
    char b[21]; int i = 0;
    if (!v) { put('0'); return; }
    while (v) { b[i++] = '0' + v % 10; v /= 10; }
    while (i) put(b[--i]);
}

static void run(const char *cmd) {
    if (eq(cmd, "help"))
        print("cmds: help ver ls cat<f> echo<x> time clear\n");
    else if (eq(cmd, "ver"))
        print("OS-DEV 0.2 (desktop edition)\n");
    else if (eq(cmd, "clear"))
        { clear(); return; }
    else if (starts(cmd, "echo ")) { print(cmd + 5); put('\n'); }
    else if (eq(cmd, "ls")) {
        vfs_dirent *e = kmalloc(32 * sizeof *e);    /* heap: 256-byte names (M2062) */
        int n = e ? vfs_list(e, 32) : -1;
        for (int i = 0; i < n; i++) { print(e[i].name); put(' '); }
        put('\n');
        if (e) kfree(e);
    } else if (starts(cmd, "cat ")) {
        char buf[512];
        long r = vfs_read(cmd + 4, buf, sizeof(buf) - 1);
        if (r < 0) print("no such file\n");
        else { buf[r] = 0; print(buf); if (r && buf[r - 1] != '\n') put('\n'); }
    } else if (eq(cmd, "time")) {
        uint64_t s = timer_ticks() / 100;
        print("uptime "); print_uint(s); print("s\n");
    } else if (cmd[0]) {
        print("unknown: "); print(cmd); put('\n');
    }
}

void term_init(void) {
    clear();
    print("OS-DEV terminal - type 'help'\n");
    prompt();
    inlen = 0;
}

void term_input(char c) {
    if (c == '\r' || c == '\n') {
        put('\n');
        inbuf[inlen] = 0;
        run(inbuf);
        inlen = 0;
        prompt();
    } else if (c == '\b') {
        if (inlen > 0) {
            inlen--;
            if (cx > 0) cx--;
            else { cx = TCOLS - 1; if (cy > 0) cy--; }   /* backspacing back across a put()-inserted wrap */
            grid[cy][cx] = ' ';
        }
    } else if (inlen < TCOLS - 1) {
        inbuf[inlen++] = c;
        put(c);
    }
}

void term_render(int px, int py, uint32_t fg, uint32_t bg) {
    for (int r = 0; r < TROWS; r++)
        for (int c = 0; c < TCOLS; c++)
            fb_glyph(px + c * font_width, py + r * font_height, grid[r][c], fg, bg);
}
