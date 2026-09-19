/*
 * desktop.c — the window manager / compositor + desktop apps.
 *
 * Compositor: every frame the whole scene is redrawn into an off-screen back
 * buffer (wallpaper -> windows back-to-front -> start menu -> cursor) and
 * blitted at once (fb_present), so overlap never flickers. Stacking is array
 * order; windows[count-1] is on top. Title bar moves a window, the corner grip
 * resizes it, the red box closes it, and the Apps menu launches more.
 *
 * Windows come in two flavours: kernel-drawn info windows (Welcome, Files,
 * Clock, About) and **app windows** (KIND_APP) that host a real ring-3
 * userspace process (see app.c) — its text grid is drawn here and keystrokes
 * are delivered to it when it's focused.
 */
#include "console.h"   /* console_gfx_release: the log must not scroll the desktop (M2011) */
#include "desktop.h"
#include "wayland.h"   /* draw a committed Wayland surface (M1980) */
#include "fb.h"
#include "speaker.h"
#include "font.h"
#include "mouse.h"
#include "usb.h"
#include "usb_kbd.h"
#include "kheap.h"
#include "keyboard.h"
#include "timer.h"
#include "app.h"
#include "browser.h"
#include "acpi.h"
#include "net.h"
#include "vfs.h"
#include "rtc.h"
#include "image.h"   /* decode_image(): any format the OS decodes (PNG/BMP/JPEG/GIF/SVG) */
#include "string.h"
#include "pmm.h"
#include "task.h"
#include <stddef.h>
#include <stdint.h>

#define MAX_WINDOWS 16
#define TITLEBAR_H  26
#define TASKBAR_H   34
#define GRIP        16

enum { KIND_PLAIN, KIND_WELCOME, KIND_FILES, KIND_APP, KIND_CLOCK, KIND_ABOUT,
       KIND_BROWSER, KIND_SYSMON, KIND_POWEROFF, KIND_REBOOT,
       KIND_WAYLAND };  /* a Wayland client's surface, drawn from its own shared memory (M1980) */
                        /* power actions above are not windows: they call ACPI */

/* ---- cyberpunk theme palette ----
 * Named so the ~180 call sites that used to carry independent 0xRRGGBB
 * literals (no theme table existed before this) can share one place to
 * retune. Semantic, not decorative: THEME_MAGENTA is "the accent used for
 * focus/active/primary interaction" wherever that concept shows up (it
 * replaces what used to be an ad-hoc blue accent at ~15 different call
 * sites), not "the color that happens to be magenta." */
#define THEME_VOID        0x050208   /* deepest background: taskbar/sky base */
#define THEME_PANEL       0x120A1F   /* window/panel body */
#define THEME_PANEL_TITLE 0x1A0F2E   /* title bar / taskbar flat fill */
#define THEME_MAGENTA     0xFF2BD6   /* primary: focus / active / primary accent */
#define THEME_CYAN        0x2BE8FF   /* secondary: info / links / secondary accent */
#define THEME_VIOLET      0x8B2BFF   /* tertiary: decorative accent */
#define THEME_GREEN       0x39FF88   /* status: success / low usage */
#define THEME_AMBER       0xFFB02B   /* status: warning / mid usage */
#define THEME_RED         0xFF2050   /* status: danger / high usage / close */
#define THEME_TEXT        0xD6F6FF   /* primary body text */
#define THEME_TEXT_DIM    0x7A6A99   /* secondary/dim text */
#define THEME_BORDER_DIM  0x3A2255   /* unfocused border/divider */
#define THEME_SELECT      0x3A1030   /* dim magenta selection/hover-row tint */

typedef struct {
    int x, y, w, h;
    uint32_t body;
    const char *title;
    int kind;
    void *app;            /* app_t* for KIND_APP windows */
    int maximized;        /* F4 toggle: filling the screen */
    int sx, sy, sw, sh;   /* saved geometry to restore from maximize */
    int fsel;             /* KIND_FILES: selected row (keyboard nav) */
    int fconfirm;         /* KIND_FILES: a delete is armed, awaiting a 2nd d/y (else any key cancels) */
    int editing;          /* KIND_FILES: 0=none, 1=rename, 2=new-folder (a text-input modal) */
    char editbuf[16];     /* the typed name (8.3 = max 12 chars + NUL) */
    int editlen;          /* chars in editbuf */
    int minimized;        /* F3: hidden to its taskbar chip */
    char fcwd[128];       /* KIND_FILES: this window's OWN browse directory (M1762),
                             independent of the shared per-process cwd. "" == "/".
                             Last field: the positional literal in make_app_window
                             omits it, so C zero-inits it (empty = root), and the
                             `{0}` literal in spawn_app zeroes it too. */
} window_t;

static window_t windows[MAX_WINDOWS];

/* ---- virtual desktops / workspaces (M1923) ----------------------------------
 * The last standard desktop feature genuinely missing: macOS has Spaces, Windows
 * has Task View, every Linux DE has workspaces.
 *
 * Implemented by SWAPPING THE WHOLE WINDOW ARRAY rather than tagging each window
 * with a workspace id. That matters: sixteen separate loops in this file iterate
 * `windows[]` to draw, hit-test, build taskbar chips, populate the switcher, cycle
 * focus and route the wheel. Filtering all sixteen on a workspace id would work
 * until one was missed, and a missed filter means a window that is invisible but
 * still clickable, or reachable by Alt+Tab but never drawn. Swapping the array
 * means every one of those loops sees exactly the current workspace with no
 * change at all, so there is nothing to miss.
 *
 * Apps on other workspaces keep RUNNING, which is the point of workspaces. A
 * stored window's app_t stays valid even if the app exits meanwhile, because
 * app_reap() -- the only thing that frees it -- is driven from the reap loop over
 * `windows[]`, so a cold-stored app is simply dead-but-unreaped and gets cleaned
 * up on the first frame after switching back. */
#define WS_N 4
#define WS_PILL_W (WS_N * 16 + 8)      /* width of the taskbar workspace indicator */
static int chips_right_bound(void);    /* fwd: the taskbar draw sits above its definition */
static window_t ws_store[WS_N][MAX_WINDOWS];
static int      ws_count[WS_N];
static int      cur_ws;
static int win_count;
static uint32_t *backbuffer;
static uint32_t *scenebuf;          /* cached rendered scene (no cursor) */
static int screen_w, screen_h;
static int spawn_n, menu_open, menu_sel;   /* menu_sel: keyboard-highlighted item */
static int help_open;                       /* F1: keyboard-shortcut help overlay */
static int sw_open, sw_sel;                 /* F7: Alt-Tab-style window switcher overlay (sw_sel: highlighted window) */
/* Real Alt+Tab (M1920). The switcher above already existed and worked, but only
 * F7 opened it — and nobody discovers F7. Everyone presses Alt+Tab, and pressing
 * it did nothing at all, which reads as "this desktop has no window switching".
 * Driven from the RAW scancode stream because the cooked layer reports no
 * modifier state. sw_alt marks a switcher opened by the chord, so releasing Alt
 * commits the selection (the Windows/macOS model: hold Alt, tab to choose,
 * release to switch) while an F7-opened switcher still needs Enter. */
static int alt_down, shift_down, super_down, ctrl_down, sw_alt;
static int super_used;   /* Super acted as a MODIFIER: don't also open the menu on release */

/* Close the focused window. Shared by F8 and Alt+F4 (M1921) so the two chords
 * cannot drift apart. An APP window is asked to exit and the reap loop drops it;
 * everything else (browser, files, ...) goes immediately. Returns 1 if anything
 * was closed, so the caller knows whether to mark the screen dirty. */
static void remove_window(int idx);                     /* fwd */
static int close_focused_window(void) {
    if (win_count <= 0) return 0;
    int fi = win_count - 1;
    if (windows[fi].kind == KIND_APP && windows[fi].app)
        app_request_kill((app_t *)windows[fi].app);
    else
        remove_window(fi);
    return 1;
}
static int ctx_open, ctx_x, ctx_y, ctx_win; /* right-click menu (window kind: ctx_win is always the topmost window, win_count-1) */
static int ctx_kind;                        /* 0 = window title-bar menu (ctx_win), 1 = desktop-background menu */
/* Close every modal overlay. Called by each overlay's open path so at most one is
 * ever up at a time (the open paths are otherwise asymmetric — e.g. F1 is handled
 * before the switcher's modal key-swallow, so F1-while-switcher would leave both
 * open; a right-click while a menu is up would stack a context menu on top). */
static void close_overlays(void) { menu_open = help_open = sw_open = ctx_open = 0; }
static int start_x = 8, start_y, start_w = 110, start_h = 24;

struct menu_item { const char *label; int kind; const char *prog; };
static const struct menu_item menu[] = {
    { "Browser", KIND_APP, "webview" },                /* the ring-3 browser is now the default */
    { "Browser (kernel)", KIND_BROWSER, 0 },           /* the in-kernel browser kept as a fallback */
    { "Shell", KIND_APP, "shell" },
    { "Clock", KIND_APP, "clock" }, { "Analog Clock", KIND_APP, "aclock" }, { "Calc", KIND_APP, "calc" },
    { "Spreadsheet", KIND_APP, "sheet" },
    { "Graphing Calc", KIND_APP, "plot" },
    { "Paint (gfx)", KIND_APP, "gpaint" },
    { "JSON Viewer", KIND_APP, "gjson" },
    { "Regex Tester", KIND_APP, "gregex" },
    { "Diff Viewer", KIND_APP, "gdiff" },
    { "Archive Browser", KIND_APP, "garc" },
    { "Hash / Checksum", KIND_APP, "ghash" },
    { "System Monitor", KIND_APP, "sysgraph" },
    { "Task Manager", KIND_APP, "taskman" },
    { "Calendar (gfx)", KIND_APP, "gcal" },
    { "Gauges", KIND_APP, "gauges" },
    { "Stopwatch", KIND_APP, "gsw" },
    { "Binary Clock", KIND_APP, "bclock" },
    { "Char Map", KIND_APP, "gfont" },
    { "Countdown", KIND_APP, "gtimer" },
    { "Image Viewer", KIND_APP, "imgview" },
    { "Calculator", KIND_APP, "gcalc" },
    { "Colour Picker", KIND_APP, "gcolor" },
    { "Fireworks", KIND_APP, "gfire" },
    { "Metronome", KIND_APP, "gmetro" },
    { "Unit Convert", KIND_APP, "gconv" },
    { "Base Convert", KIND_APP, "gbase" },
    { "Password Gen", KIND_APP, "gpass" },
    { "Clipboard", KIND_APP, "gclip" },
    { "To-Do", KIND_APP, "gtodo" },
    { "Sequencer", KIND_APP, "gseq" },
    { "Snake", KIND_APP, "snake" }, { "Editor", KIND_APP, "editor" },
    { "2048", KIND_APP, "2048" }, { "Life", KIND_APP, "life" }, { "Mines", KIND_APP, "mines" },
    { "Tetris", KIND_APP, "tetris" }, { "Breakout", KIND_APP, "breakout" },
    { "Sudoku", KIND_APP, "sudoku" }, { "Maze", KIND_APP, "maze" }, { "Mandelbrot", KIND_APP, "mandel" },
    { "Hangman", KIND_APP, "hangman" }, { "Adventure", KIND_APP, "adv" },
    { "Tic-Tac-Toe", KIND_APP, "ttt" }, { "Blackjack", KIND_APP, "bj" }, { "Typing", KIND_APP, "typing" },
    { "Simon", KIND_APP, "simon" }, { "Connect 4", KIND_APP, "c4" },
    { "Wordle", KIND_APP, "wordle" },
    { "Graphics Demo", KIND_APP, "gfxdemo" },
    { "3D Engine", KIND_APP, "scene3d" },
    { "Terrain", KIND_APP, "terrain" },
    { "Demoscene", KIND_APP, "demoscene" },
    { "DOOM", KIND_APP, "doom" },
    { "Quake", KIND_APP, "quake" },
    { "NES", KIND_APP, "nes" },
    { "Reversi", KIND_APP, "reversi" },
    { "Lights Out", KIND_APP, "lights" },
    { "15 Puzzle", KIND_APP, "fifteen" },
    { "Mastermind", KIND_APP, "mastermind" },
    { "Pong", KIND_APP, "pong" },
    { "Half-Life", KIND_APP, "halflife" },
    { "Memory", KIND_APP, "memory" },
    { "Sokoban", KIND_APP, "sokoban" },
    { "Battleship", KIND_APP, "battleship" },
    { "Pig", KIND_APP, "pig" },
    { "Raycaster", KIND_APP, "raycast" },
    { "Tron", KIND_APP, "tron" },
    { "Space Invaders", KIND_APP, "spaceinv" },
    { "Asteroids", KIND_APP, "asteroids" },
    { "Flappy", KIND_APP, "flappy" },
    { "Game Boy", KIND_APP, "gb" },
    { "Lunar Lander", KIND_APP, "lander" },
    { "Yahtzee", KIND_APP, "yahtzee" },
    { "Checkers", KIND_APP, "checkers" },
    { "Gomoku", KIND_APP, "gomoku" },
    { "Frogger", KIND_APP, "frogger" },
    { "Chess", KIND_APP, "chess" },
    { "Video Poker", KIND_APP, "vpoker" },
    { "Mancala", KIND_APP, "mancala" },
    { "Dots and Boxes", KIND_APP, "dotsbox" },
    { "Missile Command", KIND_APP, "missile" },
    { "Pac-Man", KIND_APP, "pacman" },
    { "Solitaire", KIND_APP, "solitaire" },
    { "Gems", KIND_APP, "gems" },
    { "Columns", KIND_APP, "columns" },
    { "FreeCell", KIND_APP, "freecell" },
    { "Spider", KIND_APP, "spider" },
    { "Paint", KIND_APP, "paint" }, { "Piano", KIND_APP, "piano" }, { "Jukebox", KIND_APP, "jukebox" },
    { "Matrix", KIND_APP, "matrix" }, { "Calendar", KIND_APP, "calendar" },
    { "Timer", KIND_APP, "timer" },
    { "Sandbox", KIND_APP, "sandbox" },
    { "Forth", KIND_APP, "forth" },
    { "Hex Edit", KIND_APP, "hexedit" },
    { "System Info", KIND_SYSMON, 0 },
    { "Files", KIND_FILES, 0 }, { "Welcome", KIND_WELCOME, 0 },
    { "About", KIND_ABOUT, 0 },
    { "Restart", KIND_REBOOT, 0 }, { "Shut Down", KIND_POWEROFF, 0 },
};
/* The Apps menu is laid out in 5 columns rendered upward from the taskbar, so
 * MENU_PERCOL*MENU_ITEM_H must fit the screen height (with 74 entries that is
 * ceil(74/5)*24+4 = 364px << 734); 5*150 = 750px wide << 1280. That holds
 * ~5*30 = 150 entries before the per-column height clips. */
#define MENU_N      (int)(sizeof(menu) / sizeof(menu[0]))
#define MENU_W      150
#define MENU_ITEM_H 24
#define MENU_COLS   5
#define MENU_PERCOL ((MENU_N + MENU_COLS - 1) / MENU_COLS)
#define TB_CHIPW    124                 /* taskbar window-chip width */
#define TB_CHIPGAP  6
#define TB_CHIPX0   (start_x + start_w + 10)
/* Right-click context menus, sized like a slim Apps menu. Two kinds share the same
 * popup machinery (ctx_kind): the window title-bar menu (5 rows; row 0's label is
 * Maximize or Restore depending on the window's `maximized` flag) and the desktop-
 * background menu (3 rows). Row count + width are per-kind via ctx_nrows()/ctx_w();
 * the row height is shared. */
#define CTX_ROWS    5                       /* window menu */
#define CTX_W       128                     /* window menu */
#define CTX_DESK_ROWS 3                     /* desktop menu: Show Desktop / Show All Windows / Change Wallpaper */
#define CTX_DESK_W  160                     /* desktop menu: wider so "Show All Windows" fits */
#define CTX_ROW_H   22

static void draw_text(int x, int y, const char *s, uint32_t fg) {
    for (int i = 0; s[i]; i++)
        fb_glyph_fg(x + i * font_width, y, s[i], fg);
}
/* file-type tint for the Files list (RGB, readable on the light rows); parallels
 * the shell's ls_color. FAT32 8.3 names are upper-case, so compare upper-case. M1332 */
static int ext_is(const char *x, const char *s) {
    int i = 0; for (; x[i] && s[i]; i++) if (x[i] != s[i]) return 0;
    return x[i] == 0 && s[i] == 0;
}
/* File-type category, shared by file_color() (text tint) and draw_file_icon()
 * (icon shape) so the two never drift apart into disagreeing about a file's
 * type. */
enum { FK_TEXT, FK_IMAGE, FK_CODE, FK_ARCHIVE, FK_AUDIO, FK_EXEC, FK_ROM };
static int file_kind(const char *name) {
    int dot = -1; for (int i = 0; name[i]; i++) if (name[i] == '.') dot = i;
    if (dot < 0) return FK_TEXT;
    const char *x = name + dot + 1;
    if (ext_is(x,"SVG")||ext_is(x,"PNG")||ext_is(x,"BMP")||ext_is(x,"GIF")||ext_is(x,"JPG")||ext_is(x,"JPE")) return FK_IMAGE;
    if (ext_is(x,"C")||ext_is(x,"H")||ext_is(x,"JS"))                       return FK_CODE;
    if (ext_is(x,"GZ")||ext_is(x,"TAR")||ext_is(x,"TGZ")||ext_is(x,"ZIP"))  return FK_ARCHIVE;
    if (ext_is(x,"WAV"))                                                    return FK_AUDIO;
    if (ext_is(x,"ELF")||ext_is(x,"SH"))                                    return FK_EXEC;
    if (ext_is(x,"NES")||ext_is(x,"GB"))                                    return FK_ROM;
    return FK_TEXT;                                                        /* text/web/default */
}
static uint32_t file_color(const char *name) {
    switch (file_kind(name)) {
    case FK_IMAGE:   return THEME_VIOLET;
    case FK_CODE:    return THEME_AMBER;
    case FK_ARCHIVE: return THEME_RED;
    case FK_AUDIO:   return THEME_CYAN;
    case FK_EXEC:    return THEME_GREEN;
    case FK_ROM:     return THEME_MAGENTA;
    default:         return THEME_TEXT_DIM;
    }
}
static void box(int x, int y, int w, int h, uint32_t c) {
    fb_fill_rect(x, y, w, 1, c); fb_fill_rect(x, y + h - 1, w, 1, c);
    fb_fill_rect(x, y, 1, h, c); fb_fill_rect(x + w - 1, y, 1, h, c);
}
static void draw_file_icon(int x, int y, int isdir, const char *name);  /* fwd: defined near draw_icon below (needs fcircle); called from draw_content above that point */

/* --- theming helpers --- */
static uint32_t lerp(uint32_t a, uint32_t b, int n, int d) {
    if (d <= 0) d = 1;
    int ar=(a>>16)&0xFF, ag=(a>>8)&0xFF, ab=a&0xFF;
    int br=(b>>16)&0xFF, bg=(b>>8)&0xFF, bb=b&0xFF;
    int r=ar+(br-ar)*n/d, g=ag+(bg-ag)*n/d, bl=ab+(bb-ab)*n/d;
    return (uint32_t)(r<<16 | g<<8 | bl);
}
static void vgrad(int x, int y, int w, int h, uint32_t top, uint32_t bot) {
    for (int j = 0; j < h; j++)
        fb_fill_rect(x, y + j, w, 1, lerp(top, bot, j, h - 1));
}
/* Darken whatever is already in the back buffer (for soft shadows). Delegates
 * to fb_darken_rect (fb.c), which clips + resolves the destination buffer
 * ONCE and writes each row directly — a per-pixel fb_get_pixel+fb_pixel call
 * pair here was ~38% of all kernel-mode time during a window-drag-heavy
 * profiling run (this runs 4x, full-window-sized, on every draw_window()). */
/* An N-px unfilled rectangle outline (box() below is the 1px case). */
static void stroke_rect(int x, int y, int w, int h, int thick, uint32_t c) {
    fb_fill_rect(x, y, w, thick, c);
    fb_fill_rect(x, y + h - thick, w, thick, c);
    fb_fill_rect(x, y, thick, h, c);
    fb_fill_rect(x + w - thick, y, thick, h, c);
}
/* Cheap glow approximation (fb.c has no alpha-blend primitive to do a real
 * one): a dim 1px halo just outside the rect, then a bright 2px edge on the
 * rect's own bounds — two solid strokes, not a blend, but it reads as glow
 * at desktop scale. Replaces the old rounded-corner + soft-drop-shadow look
 * for the sharp/HUD cyberpunk theme. */
static void glow_border(int x, int y, int w, int h, uint32_t bright, uint32_t dim) {
    stroke_rect(x - 1, y - 1, w + 2, h + 2, 1, dim);
    stroke_rect(x, y, w, h, 2, bright);
}
/* Four short L-shaped marks at a rect's corners — reads as instrumentation
 * marking a boundary (a real sci-fi-HUD convention) rather than decoration,
 * and costs 8 short solid strokes, no glow/blend of any kind. Deliberately
 * NOT a full outline: a small accent, meant to sit alongside glow_border
 * rather than compete with it. */
static void hud_corners(int x, int y, int w, int h, int len, uint32_t c) {
    fb_fill_rect(x, y, len, 1, c);                     fb_fill_rect(x, y, 1, len, c);
    fb_fill_rect(x + w - len, y, len, 1, c);           fb_fill_rect(x + w - 1, y, 1, len, c);
    fb_fill_rect(x, y + h - 1, len, 1, c);             fb_fill_rect(x, y + h - len, 1, len, c);
    fb_fill_rect(x + w - len, y + h - 1, len, 1, c);   fb_fill_rect(x + w - 1, y + h - len, 1, len, c);
}
/* A 2x2 ordered (checkerboard) dither between two close shades — a genuine
 * limited-palette-era depth technique (how old low-color hardware faked more
 * shades), not a blur/gradient. At native screenshot resolution this reads as
 * a fine two-tone texture, not a smoothly blended color — judged as that, on
 * a small popup-scale surface only (NOT the taskbar: that redraws every
 * frame, and this is a per-pixel fb_pixel loop — exactly the antipattern
 * M1507/M1509/M1512 already spent real effort eliminating from anything
 * always-visible; a popup title strip only redraws while that popup is open). */
static void dither_rect(int x, int y, int w, int h, uint32_t a, uint32_t b) {
    for (int dy = 0; dy < h; dy++)
        for (int dx = 0; dx < w; dx++)
            fb_pixel(x + dx, y + dy, ((x + dx + y + dy) & 1) ? a : b);
}

#define WP_TOP 0x050208   /* fallback gradient (no cached wallpaper_bmp yet/OOM) — matches make_wallpaper's void sky */
#define WP_BOT 0x03010A   /* ... and its near-black ground */

static int wp_h;
static uint32_t *wallpaper_bmp;   /* a screen-sized image loaded from disk, or NULL = gradient */
static volatile int wallpaper_repaint;   /* set by desktop_set_wallpaper (off-task) to force a redraw */
/* M1613: wallpaper_bmp's swap-then-kfree in desktop_set_wallpaper used to rely
 * on "this runs inside a syscall with IF=0, so it's atomic w.r.t. the desktop
 * render task" -- the same invalidated single-CPU assumption as M1604-M1612,
 * and a genuinely worse failure mode than a lost wakeup: task 0 (this WM) is
 * BSP-pinned, but the app calling the `wallpaper` syscall is an ordinary
 * pin_core=-1 task that M1531's scheduler can place on any OTHER core --
 * meaning render_scene()'s multi-millisecond memcpy of the OLD buffer (a
 * full screen: ~5 MB at 1280x960) could still be reading it when kfree()
 * hands those pages back to the allocator, a real use-after-free. Widened by
 * desktop_wallpaper_sample being called from kernel/app.c's own terminal
 * redraw path too -- any app, any core, far more often than the rare
 * wallpaper-change syscall. One spinlock, held only around each individual
 * read/swap (never across the memcpy AND a later sample call in the same
 * render pass, which would self-deadlock on this non-reentrant lock). */
static volatile int wallpaper_lock;
static inline uint64_t wp_irq_save(void) {
    uint64_t f;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory");
    while (__atomic_exchange_n(&wallpaper_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return f;
}
static inline void wp_irq_restore(uint64_t f) {
    __atomic_store_n(&wallpaper_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(f) : "memory", "cc");
}
/* The wallpaper's own color at absolute screen coords (x,y) — the STABLE
 * backdrop bitmap, not whatever a window most recently drew there. Lets a
 * translucent window (kernel/app.c's terminal cells) blend toward the real
 * background each redraw instead of toward its own previous frame, which
 * would just get muddier every repaint. THEME_VOID fallback covers the two
 * edge cases (OOM at boot: wallpaper_bmp never allocated; a stale coordinate
 * from a since-resized screen) without a caller needing to know about either. */
uint32_t desktop_wallpaper_sample(int x, int y) {
    if (x < 0 || y < 0 || x >= screen_w || y >= screen_h) return THEME_VOID;
    uint64_t f = wp_irq_save();
    uint32_t px = wallpaper_bmp ? wallpaper_bmp[(size_t)y * screen_w + x] : 0;
    int have = wallpaper_bmp != 0;
    wp_irq_restore(f);
    return have ? px : THEME_VOID;
}
static void u2(uint64_t v, char *o) { o[0]='0'+(v/10)%10; o[1]='0'+v%10; o[2]=0; }
static int lc_ascii(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }   /* ASCII lowercase */
/* Width of the taskbar clock pill ("YYYY-MM-DD  HH:MM:SS" = 20 chars + padding).
 * Used by BOTH the renderer and the chip hit-test so they agree on where the
 * clock starts (otherwise a click in the clock area mis-hits a window chip). */
static int clk_pill_w(void) { return 20 * font_width + 26; }
static int unum(uint64_t v, char *o) {           /* general unsigned -> string; returns len */
    char t[24]; int i = 0;
    if (!v) t[i++] = '0';
    while (v) { t[i++] = (char)('0' + v % 10); v /= 10; }
    int j = 0; while (i) o[j++] = t[--i];
    o[j] = 0; return j;
}

static int gfx_scale(int gw, int gh);   /* forward decl (defined just below) */
static void win_min(const window_t *w, int *mw, int *mh) {
    if (w->kind == KIND_APP) {
        uint32_t *cb; int gw, gh;
        if (w->app && app_gfx_get((app_t *)w->app, &cb, &gw, &gh)) {   /* gfx app: pinned to its (scaled) canvas */
            int s = gfx_scale(gw, gh);
            *mw = gw * s + 14; *mh = gh * s + TITLEBAR_H + 14;
        } else {                                                       /* text terminal: small min -> live-resizable (M1473) */
            *mw = 24 * font_width + 14; *mh = 6 * font_height + TITLEBAR_H + 14;
        }
    } else if (w->kind == KIND_BROWSER) { *mw = 340; *mh = 240; }
    else if (w->kind == KIND_SYSMON)  { *mw = 320; *mh = 272; }  /* a fixed-layout info panel (= its open size): can't be shrunk below its Memory/Network/Disk content, which would otherwise draw past the bottom edge */
    else if (w->kind == KIND_WELCOME) { *mw = 360; *mh = 290; }  /* likewise a fixed-layout panel pinned to its open size */
    else if (w->kind == KIND_ABOUT)   { *mw = 300; *mh = 196; }  /* likewise */
    else { *mw = 170; *mh = 110; }
}

/* Integer upscale for a small graphics canvas, so e.g. DOOM's native 320x200
 * shows in a comfortable 640x400 window (crisp nearest-neighbour, and it keeps
 * DOOM on its correct 1:1 render path rather than its buggy internal scaler). */
static int gfx_scale(int gw, int gh) {
    int s = 1;
    while ((s + 1) * gw <= 700 && (s + 1) * gh <= 520) s++;
    return s;
}

/* Files-window sort key: 0 = name (A-Z), 1 = size (largest first), 2 = date
 * (newest first); directories always sort before files. Cycled by 'o'. */
static int g_fsort;
static int fl_isdir(const vfs_dirent *d) { int n = 0; while (d->name[n]) n++; return n > 0 && d->name[n-1] == '/'; }
static int fl_cmp(const vfs_dirent *a, const vfs_dirent *b) {
    int ad = fl_isdir(a), bd = fl_isdir(b);
    if (ad != bd) return bd - ad;
    if (g_fsort == 1) return (a->size < b->size) - (a->size > b->size);
    if (g_fsort == 2) { unsigned long ak = ((unsigned long)a->date << 16) | a->time, bk = ((unsigned long)b->date << 16) | b->time;
                        return (ak < bk) - (ak > bk); }
    for (int i = 0; ; i++) { unsigned char ca = a->name[i], cb = b->name[i]; if (ca != cb) return (int)ca - (int)cb; if (!ca) return 0; }
}
/* vfs_list_path + sort in place. Lists `path` -- the Files window's OWN browse
 * directory (M1762) -- via the cwd-independent primitive, so a shell/app `cd`
 * no longer changes what Files shows, and Files navigation no longer moves any
 * app's cwd. */
static int flist(const char *path, vfs_dirent *e, int max) {
    int n = vfs_list_path(path, e, max);
    if (n < 0) n = 0;
    for (int i = 1; i < n; i++) { vfs_dirent t = e[i]; int j = i - 1;
        while (j >= 0 && fl_cmp(&e[j], &t) > 0) { e[j + 1] = e[j]; j--; }
        e[j + 1] = t;
    }
    return n;
}
static int path_eq(const char *a, const char *b) { int i = 0; for (; a[i] && b[i]; i++) if (a[i] != b[i]) return 0; return a[i] == b[i]; }
/* Absolute path of `name` within a window's browse dir (M1762). */
static void files_abspath(const window_t *w, const char *name, char *out, int max) {
    int p = 0; const char *d = w->fcwd[0] ? w->fcwd : "/";
    for (int i = 0; d[i] && p < max - 1; i++) out[p++] = d[i];
    if (p > 0 && out[p-1] != '/' && p < max - 1) out[p++] = '/';   /* separator (root "/" already ends in '/') */
    for (int i = 0; name[i] && p < max - 1; i++) out[p++] = name[i];
    out[p] = 0;
}
static void fcwd_descend(window_t *w, const char *dir) {           /* into subdirectory `dir` (no trailing slash) */
    char nw[128]; files_abspath(w, dir, nw, sizeof nw);
    int i = 0; for (; nw[i] && i < 127; i++) w->fcwd[i] = nw[i]; w->fcwd[i] = 0;
}
static void fcwd_ascend(window_t *w) {                             /* up one level (no-op at root) */
    if (!w->fcwd[0]) return;
    int len = 0; while (w->fcwd[len]) len++;
    if (len > 0 && w->fcwd[len-1] == '/') len--;                   /* ignore a trailing slash */
    while (len > 0 && w->fcwd[len-1] != '/') len--;                /* back to and including the last '/' */
    if (len <= 1) w->fcwd[0] = 0;                                  /* "/X" -> root ("") */
    else w->fcwd[len-1] = 0;                                       /* "/A/B" -> "/A" */
}
/* Copy/cut clipboard for the Files window (M1763): a remembered SOURCE abspath
 * and whether the pending paste should move (delete the source). */
static char files_clip[160];
static int  files_clip_move;
/* In-kernel file copy by path (read src -> write dst), same shape as the
 * copy_file_range syscall; one shot capped at 4 MiB. 0 on success, -1 on error. */
static int files_copy(const char *src, const char *dst) {
    unsigned long cap = 4UL << 20;
    char *kb = kmalloc(cap);
    if (!kb) return -1;
    long n = vfs_read(src, kb, cap);
    long w = (n >= 0) ? vfs_write(dst, kb, (unsigned long)n) : -1;
    kfree(kb);
    return (w >= 0) ? 0 : -1;
}

/* Both draw_content's KIND_FILES case and files_key() used to call flist()
 * unconditionally -- a full from-disk directory re-scan on every redraw AND
 * every keypress, tens of times a second under any UI activity at all. That
 * was already wasteful; combined with M1541's ata_lock (which correctly
 * serializes ALL disk access across tasks/cores, closing a real hardware
 * race) it meant this one hot, high-frequency caller could starve other
 * tasks' disk I/O for unpredictable stretches -- found via an intermittent
 * httpd-server test hang immediately after ata_lock landed. Cache the
 * listing and only actually hit disk if it's stale (>= 1s old) or the
 * caller demands a fresh one (force=1, used right after a mutation --
 * delete/rename/mkdir/chdir -- so those still feel immediate). A whole
 * second of passive staleness is unnoticeable for a background panel
 * (any real user action already forces a fresh read), and cuts this hot
 * caller's disk-lock contention window by roughly another 4x on top of the
 * first throttling pass. */
static vfs_dirent g_files_cache[256];
static int g_files_cache_n;
static uint64_t g_files_cache_at;
static char g_files_cache_path[128];
static int files_list_cached(const char *path, vfs_dirent **out, int force) {
    uint64_t now = timer_ms();
    if (force || !path_eq(g_files_cache_path, path) || !g_files_cache_at || now - g_files_cache_at >= 1000) {
        g_files_cache_n = flist(path, g_files_cache, 256);
        g_files_cache_at = now;
        int i = 0; for (; path[i] && i < 127; i++) g_files_cache_path[i] = path[i]; g_files_cache_path[i] = 0;
    }
    *out = g_files_cache;
    return g_files_cache_n;
}
/* The browse dir to list for window `w` ("" -> root). */
#define FCWD(w) ((w)->fcwd[0] ? (w)->fcwd : "/")

static void draw_content(const window_t *w, int focused) {
    int bx = w->x + 8, by = w->y + TITLEBAR_H + 8;
    switch (w->kind) {
    case KIND_WELCOME: {
        const char *L[] = { "Welcome to OS-DEV!", "",
            "A from-scratch x86_64 OS: kernel, FAT32",
            "disk, desktop and apps, all hand-built.", "",
            "Open the Apps menu (F9) and try:",
            "- Browser: the real web over HTTPS + JS",
            "- Shell: scriptable (functions, loops, $())",
            "- Editor: undo/redo, find & replace",
            "- Clock, Calc, Images, Fireworks +", "",
            "Drag the title bar or corner to move.",
            "F9 = Apps menu     F1 = all shortcuts" };
        for (unsigned i = 0; i < sizeof(L)/sizeof(L[0]); i++) {           /* dusk-themed intro (M1476): light text on a slate panel */
            const char *s = L[i];
            if (s[0] == '-' && s[1] == ' ') {                            /* app bullet: green label, soft desc */
                int colon = -1; for (int k = 0; s[k]; k++) if (s[k] == ':') { colon = k; break; }
                if (colon > 0) {
                    char seg[48]; int p = 0; for (int k = 0; k <= colon && p < 47; k++) seg[p++] = s[k]; seg[p] = 0;
                    draw_text(bx, by + i*18, seg, THEME_GREEN);
                    draw_text(bx + (colon + 1)*font_width, by + i*18, s + colon + 1, THEME_TEXT_DIM);
                    continue;
                }
            }
            uint32_t col = (i == 0) ? THEME_CYAN                         /* heading: neon cyan (echoes the wallpaper sun) */
                         : (s[0] == 'F' && s[1] == '9') ? THEME_TEXT_DIM  /* shortcut hint: muted */
                         : THEME_TEXT;                                    /* body */
            draw_text(bx, by + i*18, s, col);
        }
        fb_fill_rect(bx, by + 16, w->w - 24, 1, THEME_BORDER_DIM);        /* dim rule under the heading */
        break;
    }
    case KIND_FILES: {
        vfs_dirent *e; int n = files_list_cached(FCWD(w), &e, 0);   /* throttled render; lists THIS window's browse dir, not the shared cwd (M1762) */
        if (w->editing) {                                      /* a text-input is open: prompt + the typed name + a cursor */
            char pr[48]; int p = 0;
            const char *a = w->editing == 1 ? "Rename to: " : "New folder: ";
            while (*a && p < (int)sizeof(pr) - 1) pr[p++] = *a++;
            for (int j = 0; w->editbuf[j] && p < (int)sizeof(pr) - 2; j++) pr[p++] = w->editbuf[j];
            pr[p++] = '_';                                     /* a simple text cursor */
            pr[p] = 0;
            draw_text(bx, by, pr, THEME_CYAN);                 /* distinct: an input prompt, not the file list */
        } else if (w->fconfirm && w->fsel >= 0 && w->fsel < n) {  /* a delete is armed: replace the header with a bright confirm prompt */
            char pr[64]; int p = 0; const char *a = "Delete ";
            while (*a) pr[p++] = *a++;
            for (int j = 0; e[w->fsel].name[j] && p < 28; j++) pr[p++] = e[w->fsel].name[j];
            const char *b = "?  d/y=confirm  any key=cancel";
            for (int j = 0; b[j] && p < (int)sizeof(pr) - 1; j++) pr[p++] = b[j];
            pr[p] = 0;
            draw_text(bx, by, pr, THEME_RED);                  /* this action destroys a file */
        } else {
            const char *sm = g_fsort == 1 ? "size" : g_fsort == 2 ? "date" : "name";
            char hdr[160]; int hp = 0;
            const char *cwd = FCWD(w);                              /* the window's browse dir (M1762) */
            for (int j = 0; cwd[j] && hp < 40; j++) hdr[hp++] = cwd[j];
            const char *base = "   Enter:open bksp:up  d:del r:ren n:new  c/x/v:copy/cut/paste  w:wall o:sort=";
            for (int j = 0; base[j] && hp < (int)sizeof(hdr) - 8; j++) hdr[hp++] = base[j];
            for (int j = 0; sm[j] && hp < (int)sizeof(hdr) - 1; j++) hdr[hp++] = sm[j];
            hdr[hp] = 0;
            draw_text(bx, by, hdr, THEME_TEXT);
        }
        fb_fill_rect(bx - 2, by + 17, w->w - 14, 1, THEME_BORDER_DIM);   /* rule under the header */
        draw_text(bx, by + 20, "NAME", THEME_TEXT_DIM);                 /* column labels (M1525) — same columns the row loop below lays out */
        draw_text(bx + 22 * font_width, by + 20, "SIZE / DATE", THEME_TEXT_DIM);
        fb_fill_rect(bx - 2, by + 36, w->w - 14, 1, THEME_BORDER_DIM);   /* rule under the column labels */
        int rows = (w->h - TITLEBAR_H - 66) / 18;          /* rows that fit in the body (18 more now reserved, for the column-header row; last 18px still for the footer) */
        if (rows < 1) rows = 1;
        int top = 0;                                       /* scroll so the selection stays visible */
        if (w->fsel >= rows) top = w->fsel - rows + 1;
        for (int i = top; i < n && i < top + rows; i++) {
            int ry = by + 40 + (i - top)*18;
            if (i == w->fsel)                              /* highlight the selected row */
                fb_fill_rect(bx - 2, ry - 2, w->w - 14, 18, THEME_SELECT);
            else if ((i - top) & 1)                        /* zebra striping for scanability */
                fb_fill_rect(bx - 2, ry - 2, w->w - 14, 18, THEME_PANEL_TITLE);
            int nl = 0; while (e[i].name[nl]) nl++;
            int isdir = (nl > 0 && e[i].name[nl-1] == '/');   /* vfs marks directories with a trailing '/' */
            draw_file_icon(bx - 1, ry, isdir, e[i].name);     /* drawn into the row's existing 2-space text prefix (16px == ICON_SZ+gap) */
            char line[48]; int p = 0; line[p++]=' '; line[p++]=' ';
            for (int j = 0; e[i].name[j] && p < 28; j++) line[p++] = e[i].name[j];
            int name_end = p;                              /* end of the "  NAME" segment (M1332) */
            while (p < 22) line[p++] = ' ';
            if (isdir) {                                   /* directory: show "(dir)", no size/date */
                const char *d = "(dir)"; for (int z = 0; d[z]; z++) line[p++] = d[z];
            } else {
                line[p++]='('; uint32_t s=e[i].size; char num[12]; int k=0;
                if (!s) num[k++]='0';
                while (s) { num[k++]='0'+s%10; s/=10; }
                while (k) line[p++]=num[--k];
                line[p++]='b'; line[p++]=')';
                if (e[i].date && p < 36) {                 /* last-write date (YYYY-MM-DD) for stamped files */
                    int yr=(e[i].date>>9)+1980, mo=(e[i].date>>5)&15, dy=e[i].date&31;
                    line[p++]=' ';
                    line[p++]='0'+(yr/1000)%10; line[p++]='0'+(yr/100)%10; line[p++]='0'+(yr/10)%10; line[p++]='0'+yr%10;
                    line[p++]='-'; line[p++]='0'+(mo/10)%10; line[p++]='0'+mo%10;
                    line[p++]='-'; line[p++]='0'+(dy/10)%10; line[p++]='0'+dy%10;
                }
            }
            line[p]=0;
            uint32_t namecol = isdir ? THEME_AMBER : file_color(e[i].name);   /* dirs amber, files by type (M1332) */
            char nsave = line[name_end]; line[name_end] = 0;
            draw_text(bx, ry, line, namecol);                              /* name in its type tint */
            line[name_end] = nsave;
            draw_text(bx + name_end * font_width, ry, line + name_end, THEME_TEXT_DIM);   /* size/date */
        }
        {   /* status footer: entry count + total size (M1427) */
            unsigned long tot = 0; for (int i = 0; i < n; i++) tot += e[i].size;
            char ft[48]; int p = 0; char num[16]; int k;
            int v = n; k = 0; if (!v) num[k++] = '0'; while (v) { num[k++] = '0' + v % 10; v /= 10; } while (k) ft[p++] = num[--k];
            const char *a = " items, "; for (int z = 0; a[z]; z++) ft[p++] = a[z];
            unsigned long kb = tot / 1024; k = 0; if (!kb) num[k++] = '0'; while (kb) { num[k++] = '0' + (int)(kb % 10); kb /= 10; } while (k) ft[p++] = num[--k];
            const char *b2 = " KB"; for (int z = 0; b2[z]; z++) ft[p++] = b2[z]; ft[p] = 0;
            draw_text(bx, w->y + w->h - 18, ft, THEME_TEXT_DIM);
        }
        break;
    }
    case KIND_APP: {
        uint32_t *cb; int gw, gh;
        if (w->app && app_gfx_get((app_t *)w->app, &cb, &gw, &gh)) {
            /* graphics mode: blit the app's pixel canvas into the body, scaled
             * up by an integer factor (nearest-neighbour) for small canvases. */
            int s = gfx_scale(gw, gh);
            fb_blit_scaled(bx - 2, by - 2, cb, gw, gh, s);
        } else if (w->app) {                                  /* text terminal: size the live grid to the window, then render (M1473) */
            app_set_grid((app_t *)w->app, (w->w - 14) / font_width, (w->h - TITLEBAR_H - 14) / font_height);
            app_render((app_t *)w->app, bx - 2, by - 2, focused);
        }
        break;
    }
    case KIND_WAYLAND: {
        /* A Wayland client's surface. The pixels are the CLIENT'S memory,
         * mapped into the compositor by wl_shm -- this blit is the only copy
         * in the whole path, and it goes straight to the framebuffer. */
        /* EVERY LAYER, NOT ONE SURFACE (M2089). A toolkit's window is a
         * toplevel plus its subsurfaces, and GTK puts the pixels in a child --
         * so drawing "the surface" drew a blank toplevel, or the child with no
         * idea where in the window it belonged. wl_layers gives the tree,
         * parents first, each with its offset. */
        struct wl_layer ly[24];
        /* w->app carries the CLIENT SLOT this window belongs to, plus one so
         * that zero still means "no client chosen" for any window created
         * before per-client windows existed (M2089). */
        int wci = (int)(long)w->app - 1;
        int nly = (wci >= 0) ? wl_client_layers(wci, ly, 24) : wl_layers(ly, 24);
        if (nly > 0) {
            int maxw = w->w - 8, maxh = w->h - TITLEBAR_H - 8;
            for (int i = 0; i < nly; i++) {
                if (!ly[i].px) continue;
                for (uint32_t yy = 0; yy < ly[i].h; yy++) {
                    int dy = ly[i].y + (int)yy;
                    if (dy < 0 || dy >= maxh) continue;            /* a child may overhang */
                    const uint32_t *row = (const uint32_t *)((const uint8_t *)ly[i].px + (unsigned long)yy * ly[i].stride);
                    for (uint32_t xx = 0; xx < ly[i].w; xx++) {
                        int dx = ly[i].x + (int)xx;
                        if (dx < 0 || dx >= maxw) continue;
                        /* HONOUR THE ALPHA (M2115).
                         *
                         * This masked the alpha off and wrote the RGB
                         * opaquely, so a FULLY TRANSPARENT pixel -- 0x00000000
                         * -- was painted black. GTK draws its client-side
                         * decoration shadow in exactly those pixels, which is
                         * why Firefox's window has a black border around it in
                         * a framebuffer dump instead of the desktop showing
                         * through.
                         *
                         * wl_shm ARGB8888 is PREMULTIPLIED, so the composite
                         * is dst = src + dst*(1-a) with no divide. XRGB8888's
                         * alpha byte is undefined and must be read as opaque,
                         * which is what `format` is carried for. */
                        uint32_t src = row[xx];
                        uint32_t a = (ly[i].format == 0) ? (src >> 24) : 255u;
                        if (!a) continue;                       /* transparent: leave what is under it */
                        uint32_t out;
                        if (a == 255u) out = src & 0x00FFFFFFu;
                        else {
                            uint32_t d = fb_get_pixel(bx - 2 + dx, by - 2 + dy);
                            uint32_t inv = 255u - a;
                            uint32_t r = ((src >> 16) & 0xff) + (((d >> 16) & 0xff) * inv) / 255u;
                            uint32_t g = ((src >>  8) & 0xff) + (((d >>  8) & 0xff) * inv) / 255u;
                            uint32_t b = ( src        & 0xff) + (( d        & 0xff) * inv) / 255u;
                            if (r > 255u) r = 255u; if (g > 255u) g = 255u; if (b > 255u) b = 255u;
                            out = (r << 16) | (g << 8) | b;
                        }
                        fb_pixel(bx - 2 + dx, by - 2 + dy, out);
                    }
                }
            }
        } else {
            fb_text(bx + 4, by + 4, "waiting for a client to commit a surface...", THEME_TEXT_DIM, 1);
        }
        break;
    }
    case KIND_BROWSER:
        if (w->app) browser_render((browser_t *)w->app, w->x, w->y + TITLEBAR_H,
                                   w->w, w->h - TITLEBAR_H);
        break;
    case KIND_CLOCK: {
        uint64_t sec = timer_ticks() / timer_hz();
        char t[6]; u2(sec/60, t); t[2]=':'; u2(sec%60, t+3);
        fb_text(w->x + 28, by + 18, t, THEME_GREEN, 5);
        break;
    }
    case KIND_SYSMON: {
        uint64_t tot = pmm_total_bytes(), fre = pmm_free_bytes();
        uint64_t used = tot > fre ? tot - fre : 0;
        int barw = w->w - 32, pct = tot ? (int)(used * 100 / tot) : 0;
        char line[64];

        draw_text(bx, by, "Memory", THEME_CYAN);
        int yb = by + 18;
        fb_fill_rect(bx, yb, barw, 14, THEME_PANEL_TITLE);            /* bar track */
        uint32_t bc = pct < 70 ? THEME_GREEN : (pct < 90 ? THEME_AMBER : THEME_RED);
        fb_fill_rect(bx, yb, barw * pct / 100, 14, bc);              /* used */
        box(bx, yb, barw, 14, THEME_BORDER_DIM);
        int p = 0;
        p += unum(used/(1024*1024), line+p); line[p++]=' '; line[p++]='/'; line[p++]=' ';
        p += unum(tot/(1024*1024), line+p);
        const char *u = " MiB used"; for (int i=0;u[i];i++) line[p++]=u[i]; line[p]=0;
        draw_text(bx, yb + 20, line, THEME_TEXT);

        draw_text(bx, yb + 46, "Tasks", THEME_CYAN);
        int nt = task_count();
        for (int i = 0; i < nt && i < 20; i++)                        /* one block per task */
            fb_fill_rect(bx + 60 + i*10, yb + 46, 7, 11, THEME_MAGENTA);
        p = 0; p += unum((uint64_t)nt, line+p); line[p]=0;
        draw_text(bx + 60 + (nt<20?nt:20)*10 + 6, yb + 46, line, THEME_TEXT);

        char up[40]; p = 0;
        const char *uh = "Uptime "; for (int i=0;uh[i];i++) up[p++]=uh[i];
        p += unum(timer_ticks()/timer_hz(), up+p); up[p++]='s'; up[p]=0;
        draw_text(bx, yb + 72, up, THEME_TEXT);

        /* network: our IP + gateway (a connected, internet-capable OS) */
        draw_text(bx, yb + 98, "Network", THEME_CYAN);
        const uint8_t *ip = net_ip(), *gw = net_gateway();
        char net[64]; p = 0;
        const char *ih = "IP "; for (int i=0;ih[i];i++) net[p++]=ih[i];
        for (int k=0;k<4;k++){ p+=unum(ip[k],net+p); if(k<3)net[p++]='.'; }
        const char *gh = "  gw "; for (int i=0;gh[i];i++) net[p++]=gh[i];
        for (int k=0;k<4;k++){ p+=unum(gw[k],net+p); if(k<3)net[p++]='.'; }
        net[p]=0;
        draw_text(bx, yb + 116, net, THEME_TEXT);

        /* Disk (FAT32 volume). vfs_df() scans the whole FAT (disk I/O), so cache
         * it and refresh only every ~5s rather than on every render frame. */
        static uint64_t df_free, df_total, df_at = (uint64_t)-1;
        uint64_t nowt = timer_ticks();
        if (df_at == (uint64_t)-1 || nowt - df_at > 500) { vfs_df(&df_free, &df_total); df_at = nowt; }
        draw_text(bx, yb + 142, "Disk", THEME_CYAN);
        if (df_total) {
            uint64_t dused = df_total > df_free ? df_total - df_free : 0;
            int dpct = (int)(dused * 100 / df_total), yd = yb + 160;
            fb_fill_rect(bx, yd, barw, 14, THEME_PANEL_TITLE);
            uint32_t dc = dpct < 70 ? THEME_GREEN : (dpct < 90 ? THEME_AMBER : THEME_RED);
            fb_fill_rect(bx, yd, barw * dpct / 100, 14, dc);
            box(bx, yd, barw, 14, THEME_BORDER_DIM);
            p = 0;
            p += unum(dused/(1024*1024), line+p); line[p++]=' '; line[p++]='/'; line[p++]=' ';
            p += unum(df_total/(1024*1024), line+p);
            const char *du = " MiB used"; for (int i=0;du[i];i++) line[p++]=du[i]; line[p]=0;
            draw_text(bx, yd + 20, line, THEME_TEXT);
        } else {
            draw_text(bx, yb + 160, "no disk", THEME_TEXT_DIM);
        }
        break;
    }
    case KIND_ABOUT: {
        const char *L[] = { "OS-DEV", "", "x86_64, built from scratch", "",
            "kernel . memory . tasks",
            "FAT32 . TCP . TLS 1.3",
            "JS engine . web browser",
            "scriptable shell . editor",
            "calc . image viewer . games" };
        for (unsigned i = 0; i < sizeof(L)/sizeof(L[0]); i++)
            draw_text(bx, by + i*16, L[i], (i == 0 || i >= 4) ? THEME_CYAN : THEME_TEXT);   /* heading + tech-stack lines (M1334) */
        fb_fill_rect(bx, by + 14, w->w - 24, 1, THEME_BORDER_DIM);          /* rule under the heading */
        break;
    }
    default:
        draw_text(bx, by, w->title, THEME_TEXT);
        break;
    }
}

/* A filled circle (no FPU; integer radius test) for the icon glyphs. */
static void fcircle(int cx, int cy, int r, uint32_t c) {
    for (int dy = -r; dy <= r; dy++)
        for (int dx = -r; dx <= r; dx++)
            if (dx*dx + dy*dy <= r*r) fb_pixel(cx + dx, cy + dy, c);
}
/* A small per-kind icon (ICON_SZ square) for the title bar + taskbar chip, so a
 * window is identifiable at a glance. Clean colored glyphs that read on both the
 * title-bar gradient and the dark taskbar. */
#define ICON_SZ 14
static void draw_icon(int kind, int x, int y) {
    int cx = x + 7, cy = y + 7;
    switch (kind) {
    case KIND_FILES:
        fb_fill_rect(x + 1, y + 3, 6, 2, 0xB8860A);          /* folder tab */
        fb_fill_rect(x + 1, y + 4, 12, 8, THEME_AMBER);      /* folder body */
        fb_fill_rect(x + 1, y + 4, 12, 1, THEME_TEXT);       /* top highlight */
        break;
    case KIND_BROWSER:
        fcircle(cx, cy, 6, THEME_CYAN);                      /* globe */
        fb_fill_rect(x + 1, cy, 12, 1, THEME_TEXT);          /* equator */
        fb_fill_rect(cx, y + 1, 1, 12, THEME_TEXT);          /* meridian */
        break;
    case KIND_CLOCK:
        fcircle(cx, cy, 6, THEME_TEXT);                      /* clock face */
        fb_fill_rect(cx, cy - 4, 1, 5, THEME_VOID);          /* minute hand */
        fb_fill_rect(cx, cy, 4, 1, THEME_VOID);              /* hour hand */
        break;
    case KIND_SYSMON:
        fb_fill_rect(x + 2,  y + 8, 2, 4, THEME_GREEN);      /* bar chart */
        fb_fill_rect(x + 6,  y + 5, 2, 7, THEME_AMBER);
        fb_fill_rect(x + 10, y + 3, 2, 9, THEME_CYAN);
        break;
    case KIND_WELCOME:
    case KIND_ABOUT:
        fcircle(cx, cy, 6, THEME_TEXT);                      /* info badge */
        fb_fill_rect(cx, y + 3, 1, 2, THEME_MAGENTA);        /* i dot */
        fb_fill_rect(cx, y + 6, 1, 5, THEME_MAGENTA);        /* i stem */
        break;
    default:                                                 /* KIND_APP etc.: a generic-program diamond */
        for (int dy = -6; dy <= 6; dy++) {
            int half = 6 - (dy < 0 ? -dy : dy);              /* widest at the center row, tapering to points top/bottom */
            if (half > 0) fb_fill_rect(cx - half, cy + dy, half * 2, 1, THEME_TEXT_DIM);
        }
        fb_fill_rect(cx - 1, cy - 1, 2, 2, THEME_MAGENTA);   /* center accent dot */
        break;
    }
}
/* A small per-file-type icon (ICON_SZ square) for the Files list, so a row is
 * identifiable by shape as well as by file_color()'s text tint — the two
 * always agree since both read file_kind(). Flat-filled, no outlines, same
 * convention as draw_icon() above (whose folder shape this reuses verbatim
 * for isdir, so a folder looks identical everywhere it appears). Any "cut
 * into the icon" detail (the text file's ruled lines) uses a darkened shade
 * of the icon's OWN color rather than a hardcoded background color, since the
 * row behind it varies (plain/zebra/selected) — matching against `c` always
 * contrasts regardless of what's actually behind the icon. */
static void draw_file_icon(int x, int y, int isdir, const char *name) {
    if (isdir) {
        fb_fill_rect(x + 1, y + 3, 6, 2, 0xB8860A);          /* folder tab */
        fb_fill_rect(x + 1, y + 4, 12, 8, THEME_AMBER);      /* folder body */
        fb_fill_rect(x + 1, y + 4, 12, 1, THEME_TEXT);       /* top highlight */
        return;
    }
    uint32_t c = file_color(name);
    switch (file_kind(name)) {
    case FK_IMAGE: {                                          /* frame + mountain + sun */
        static const int mw[4] = {1,3,5,7};                   /* symmetric triangle, apex at top, widening toward the base */
        box(x + 1, y + 2, 12, 10, c);
        for (int i = 0; i < 4; i++) fb_fill_rect(x + 7 - mw[i] / 2, y + 8 + i, mw[i], 1, c);
        fcircle(x + 10, y + 5, 1, c);                         /* sun, upper-right corner of the frame */
        break;
    }
    case FK_CODE: {                                           /* '<' '>' angle brackets */
        static const int lx[5] = {4,3,2,3,4}, rx[5] = {8,9,10,9,8};
        for (int i = 0; i < 5; i++) {
            fb_fill_rect(x + lx[i], y + 4 + i, 2, 1, c);
            fb_fill_rect(x + rx[i], y + 4 + i, 2, 1, c);
        }
        break;
    }
    case FK_ARCHIVE:                                          /* a sealed crate: box + tape seam */
        box(x + 2, y + 2, 10, 10, c);
        fb_fill_rect(x + 2, y + 6, 10, 1, c);                 /* horizontal seam */
        fb_fill_rect(x + 6, y + 2, 1, 4, c);                  /* seam onto the lid */
        break;
    case FK_AUDIO:                                            /* eighth note: head + stem + flag */
        fcircle(x + 4, y + 10, 2, c);
        fb_fill_rect(x + 5, y + 3, 1, 7, c);
        fb_fill_rect(x + 6, y + 3, 2, 3, c);
        break;
    case FK_EXEC: {                                           /* solid play triangle */
        static const int w0[8] = {1,2,3,4,4,3,2,1};
        for (int i = 0; i < 8; i++) fb_fill_rect(x + 4, y + 3 + i, w0[i], 1, c);
        break;
    }
    case FK_ROM:                                              /* cartridge: body + top connector tab */
        fb_fill_rect(x + 2, y + 4, 10, 8, c);
        fb_fill_rect(x + 5, y + 2, 4, 2, c);
        break;
    default: {                                                /* generic text file: page + ruled lines */
        uint32_t dim = (c >> 1) & 0x7F7F7F;
        fb_fill_rect(x + 3, y + 1, 8, 12, c);
        fb_fill_rect(x + 4, y + 4, 6, 1, dim);
        fb_fill_rect(x + 4, y + 7, 6, 1, dim);
        fb_fill_rect(x + 4, y + 10, 4, 1, dim);
        break;
    }
    }
}

static void draw_window(const window_t *w, int focused) {
    int x = w->x, y = w->y, ww = w->w, hh = w->h;

    /* body */
    fb_fill_rect(x, y, ww, hh, w->body);
    fb_set_clip(x, y, x + ww, y + hh);    /* bound this window's content to its rect — a long line / future layout can't bleed onto a neighbour or the taskbar (the per-kind min-sizes above are belt-and-braces) */
    draw_content(w, focused);
    fb_reset_clip();

    /* flat title bar + a neon underline (replaces the soft gradient + sheen —
     * the sheen line was already invisible, overpainted by the border drawn
     * after it, so this loses nothing) */
    fb_fill_rect(x, y, ww, TITLEBAR_H, focused ? THEME_PANEL_TITLE : THEME_PANEL);
    fb_fill_rect(x, y + TITLEBAR_H - 1, ww, 1, focused ? THEME_MAGENTA : THEME_BORDER_DIM);
    const char *titletext = (w->kind == KIND_BROWSER && w->app) ? browser_title((browser_t *)w->app) : w->title;   /* browser windows show the page <title> / document.title */
    draw_icon(w->kind, x + 8, y + (TITLEBAR_H - ICON_SZ) / 2);                /* per-kind icon */
    draw_text(x + 28, y + (TITLEBAR_H - font_height) / 2 + 1, titletext, focused ? THEME_TEXT : THEME_TEXT_DIM);

    /* close button: a sharp square, thin neon border, "x" glyph — no gradient
     * chip, no rounding. Geometry (14x14 at x+ww-21,y+6) now matches its
     * mouse hit-test exactly (they'd drifted apart under the old rounded
     * chip — see the hit-test near in_rect(mx,my,w->x+w->w-21,...) below). */
    int cbx = x + ww - 21, cby = y + 6;
    fb_fill_rect(cbx, cby, 14, 14, THEME_VOID);
    stroke_rect(cbx, cby, 14, 14, 1, focused ? THEME_RED : THEME_BORDER_DIM);
    draw_text(cbx + 3, cby - 1, "x", focused ? THEME_TEXT : THEME_TEXT_DIM);

    /* resize grip hatching */
    for (int i = 4; i < GRIP; i += 4)
        fb_fill_rect(x + ww - i, y + hh - 3, i - 2, 2, THEME_BORDER_DIM);

    /* sharp border + a dim outer glow line — no rounding, no drop shadow */
    glow_border(x, y, ww, hh, focused ? THEME_MAGENTA : THEME_BORDER_DIM, THEME_VOID);
    fb_fill_rect(x + 1, y + TITLEBAR_H, ww - 2, 1, focused ? THEME_MAGENTA : THEME_BORDER_DIM);
    if (focused) hud_corners(x - 2, y - 2, ww + 4, hh + 4, 8, THEME_CYAN);   /* a small accent marking the active window, distinct from the magenta glow */
}

/* Decode image file `name` into a freshly-allocated screen-sized 0x00RRGGBB
 * bitmap, scaling the decoded image (nearest-neighbour) to screen_w*screen_h so
 * ANY image — not just a screen-exact one — works as wallpaper. Returns the
 * buffer (caller owns it), or NULL on any failure (missing / undecodable / OOM).
 * All scratch is freed before returning; no partial allocation is leaked.
 *
 * decode_image() (browser.c) dispatches on the magic bytes to png/bmp/jpeg/gif/
 * svg_decode and returns the image at its NATIVE w*h, so any format the OS reads
 * works here — including a source larger than the screen (capped 2048x2048/1M
 * px by the decoder; oversize -> NULL, leaving the caller's wallpaper untouched). */
static uint32_t *decode_wallpaper(const char *name) {
    long npix = (long)screen_w * screen_h;
    uint8_t *file = kmalloc(512 * 1024);
    if (!file) return NULL;
    long n = vfs_read(name, file, 512 * 1024);
    if (n <= 0) { kfree(file); return NULL; }
    int w = 0, h = 0;
    uint8_t *rgba = decode_image(file, (int)n, &w, &h);     /* native-size RGBA (we own it) */
    kfree(file);
    if (!rgba || w <= 0 || h <= 0) { if (rgba) kfree(rgba); return NULL; }
    uint32_t *bmp = kmalloc((size_t)npix * 4);
    if (!bmp) { kfree(rgba); return NULL; }
    for (int dy = 0; dy < screen_h; dy++) {                 /* nearest-neighbour scale to screen */
        int sy = (int)((long)dy * h / screen_h);            /* src_y = dst_y * src_h / screen_h */
        for (int dx = 0; dx < screen_w; dx++) {
            int sx = (int)((long)dx * w / screen_w);        /* src_x = dst_x * src_w / screen_w */
            const uint8_t *p = &rgba[((long)sy * w + sx) * 4];   /* RGBA bytes -> 0x00RRGGBB */
            bmp[(long)dy * screen_w + dx] = ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
        }
    }
    kfree(rgba);
    return bmp;
}

/* Decode an image file and fit-scale it into a caller-supplied cw*ch XRGB buffer
 * (centred, aspect-preserved, letterboxed), reporting the native size in outwh.
 * Backs SYS_loadimg for the image viewer (imgview). The buffer is the app's,
 * already validated by the syscall layer; this runs with IF=0 inside a syscall.
 * Reuses decode_image() so PNG/BMP/JPEG/GIF/SVG all work. 0 ok, -1 fail. */
int desktop_load_image(const char *name, unsigned *buf, int cw, int ch, int *outwh) {
    if (cw <= 0 || ch <= 0) return -1;
    uint8_t *file = kmalloc(512 * 1024);
    if (!file) return -1;
    long n = vfs_read(name, file, 512 * 1024);
    if (n <= 0) { kfree(file); return -1; }
    int w = 0, h = 0;
    uint8_t *rgba = decode_image(file, (int)n, &w, &h);     /* native-size RGBA (we own it) */
    kfree(file);
    if (!rgba || w <= 0 || h <= 0) { if (rgba) kfree(rgba); return -1; }

    int dw = cw, dh = (int)((long)cw * h / w);              /* fit within cw*ch, preserve aspect */
    if (dh > ch) { dh = ch; dw = (int)((long)ch * w / h); }
    if (dw < 1) dw = 1;
    if (dh < 1) dh = 1;
    int ox = (cw - dw) / 2, oy = (ch - dh) / 2;             /* centre; letterbox the rest */
    for (int y = 0; y < ch; y++)
        for (int x = 0; x < cw; x++) {
            int rx = x - ox, ry = y - oy;
            unsigned px = THEME_VOID;                        /* letterbox background */
            if (rx >= 0 && rx < dw && ry >= 0 && ry < dh) {
                int sx = (int)((long)rx * w / dw), sy = (int)((long)ry * h / dh);
                const uint8_t *p = &rgba[((long)sy * w + sx) * 4];   /* RGBA -> 0x00RRGGBB */
                px = ((unsigned)p[0] << 16) | ((unsigned)p[1] << 8) | p[2];
            }
            buf[(long)y * cw + x] = px;
        }
    kfree(rgba);
    outwh[0] = w; outwh[1] = h;
    return 0;
}

/* Procedural desktop background (visual refresh): drawn once into a cached
 * buffer at boot, so there's no per-frame cost regardless of complexity.
 * Integer-only (the kernel has no FPU). Needs no image on disk, so the
 * desktop looks right even on bare metal where WALL.PNG may be absent. */
static inline int wp_cl(int v) { return v < 0 ? 0 : (v > 255 ? 255 : v); }
static void wp_px(uint32_t *buf, int w, int h, int x, int y, uint32_t c) {
    if ((unsigned)x < (unsigned)w && (unsigned)y < (unsigned)h) buf[(size_t)y * w + x] = c;
}
/* Integer Bresenham (the same one this codebase's gfx apps each carry their
 * own copy of, e.g. user/aclock.c's line() — ported here since the wallpaper
 * writes directly into its own detached buffer, not through fb_pixel/the
 * live framebuffer, so it can't just call an fb.c primitive). */
static void wp_line(uint32_t *buf, int w, int h, int x0, int y0, int x1, int y1, uint32_t c) {
    int dx = x1 - x0, dy = y1 - y0;
    int adx = dx < 0 ? -dx : dx, ady = dy < 0 ? -dy : dy;
    int sx = dx < 0 ? -1 : 1, sy = dy < 0 ? -1 : 1;
    int err = (adx > ady ? adx : -ady) / 2, e2;
    for (;;) {
        wp_px(buf, w, h, x0, y0, c);
        if (x0 == x1 && y0 == y1) break;
        e2 = err;
        if (e2 > -adx) { err -= ady; x0 += sx; }
        if (e2 <  ady) { err += adx; y0 += sy; }
    }
}

/* The boot desktop background: a synthwave grid horizon — a near-black void
 * sky fading to deep violet at the horizon, a faint hashed star field (kept
 * from the earlier dusk scene — still cheap, deterministic, and reads well
 * here), a "sliced" neon sun straddling the horizon (concentric alternating
 * bright/gap rings via squared-distance, no sqrt/FPU needed), and a receding
 * perspective grid on the ground plane below: horizontal bands quadratically
 * spaced (bunched near the horizon, spread out near the bottom, the way real
 * evenly-spaced lines look in perspective) plus lines converging from the
 * bottom edge to a single vanishing point at the horizon's centre. */
static void make_wallpaper(uint32_t *buf, int w, int h) {
    const uint32_t SKY_TOP = THEME_VOID, SKY_HOR = 0x2A0A3E;   /* void -> deep violet at the horizon */
    const uint32_t GROUND = 0x03010A;                           /* near-black ground, under the grid */
    int horizon = h * 58 / 100;
    int gx = w / 2;                                             /* sun + vanishing point: dead centre */

    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            uint32_t base = (y < horizon) ? lerp(SKY_TOP, SKY_HOR, y, horizon - 1) : GROUND;
            int r = (base >> 16) & 0xFF, g = (base >> 8) & 0xFF, b = base & 0xFF;
            if (y < horizon) {                                  /* faint stars, fading toward the horizon */
                unsigned hs = (unsigned)x * 374761393u + (unsigned)y * 668265263u;
                hs ^= hs >> 13; hs *= 1274126177u;
                if ((hs % 1700u) < 3u) { int br = (90 + (int)(hs % 130u)) * (horizon - y) / horizon; r += br; g += br; b += br; }
            }
            buf[(size_t)y * w + x] = (uint32_t)(wp_cl(r) << 16 | wp_cl(g) << 8 | wp_cl(b));
        }

    /* A BACKGROUND MUST NOT COMPETE WITH THE FOREGROUND (M1988).
     *
     * Every element below used to be drawn at FULL theme intensity -- the same
     * THEME_MAGENTA and THEME_CYAN the titlebars, borders and accents use. So
     * the sun and the grid were exactly as loud as the windows in front of
     * them, and nothing on screen read as being nearer than anything else.
     * That is not a taste problem, it is a depth-cue problem: a desktop needs
     * the wallpaper, the window body, the chrome and the FOCUSED window to sit
     * at visibly different intensities, or the eye has nothing to order them
     * by. The identity is unchanged; the volume is turned down to where the
     * foreground can be heard over it. */
    #define WP_DIM(c, pct) ((uint32_t)((((((c) >> 16) & 0xFF) * (pct) / 100) << 16) | \
                                       (((((c) >>  8) & 0xFF) * (pct) / 100) <<  8) | \
                                        ((((c)        & 0xFF) * (pct) / 100))))

    /* sliced neon sun: 3 bright rings (0/2/4) separated by 2 gap rings (1/3,
     * sky/stars show through), clipped to the sky region so it appears to
     * sit on/behind the horizon+grid below it. */
    int sr = h * 18 / 100, gy = horizon;
    long sr2 = (long)sr * sr;
    for (int y = 0; y < horizon; y++)
        for (int x = 0; x < w; x++) {
            long dx = x - gx, dy = y - gy, d2 = dx * dx + dy * dy;
            if (d2 >= sr2) continue;
            int ring = (int)(d2 * 6 / sr2);
            if (ring & 1) continue;                              /* odd ring = gap: leave sky/stars visible */
            uint32_t rc = (ring == 0) ? THEME_MAGENTA : (ring == 2) ? THEME_CYAN : THEME_VIOLET;
            buf[(size_t)y * w + x] = WP_DIM(rc, 34);
        }

    /* bright horizon line, anchoring the sun above it to the grid below it */
    wp_line(buf, w, h, 0, horizon, w - 1, horizon, WP_DIM(THEME_MAGENTA, 44));
    if (horizon + 1 < h) wp_line(buf, w, h, 0, horizon + 1, w - 1, horizon + 1, WP_DIM(THEME_MAGENTA, 28));

    /* perspective grid: lines converging to the vanishing point (chromatic
     * alternation for visual richness), then horizontal bands on top so
     * they stay crisp/unbroken at every crossing. */
    for (int i = 0; i <= 20; i++) {
        int bx = (int)((long)i * (w - 1) / 20);
        wp_line(buf, w, h, bx, h - 1, gx, horizon, WP_DIM((i & 1) ? THEME_VIOLET : THEME_CYAN, 20));
    }
    for (int i = 1; i <= 12; i++) {
        long t = (long)i * 1024 / 12;
        int gy2 = horizon + (int)((long)(h - horizon) * (t * t) / (1024L * 1024L));
        wp_line(buf, w, h, 0, gy2, w - 1, gy2, WP_DIM(lerp(THEME_CYAN, THEME_VIOLET, i, 12), 24));
    }

    /* Sparse scanline texture (Phase 4 texture experiment): darken every 3rd
     * row a little — a CRT reference. Zero per-frame cost either way (this
     * whole buffer is generated once at boot and memcpy'd every frame after),
     * and confined to the wallpaper only, never window content/text, so
     * nothing readable is put at risk. */
    for (int y = 0; y < h; y += 3)
        for (int x = 0; x < w; x++) {
            uint32_t c = buf[(size_t)y * w + x];
            int r = (int)((c >> 16) & 0xFF) * 80 / 100, g = (int)((c >> 8) & 0xFF) * 80 / 100, b = (int)(c & 0xFF) * 80 / 100;
            buf[(size_t)y * w + x] = (uint32_t)(r << 16 | g << 8 | b);
        }
}

/* The boot desktop background. A clean PROCEDURAL gradient is the default (works
 * with no image on disk, incl. bare metal); a user can still load a custom image
 * at runtime with the `wallpaper` shell builtin (desktop_set_wallpaper). */
static void load_wallpaper(void) {
    wallpaper_bmp = kmalloc((size_t)screen_w * screen_h * 4);
    if (wallpaper_bmp) make_wallpaper(wallpaper_bmp, screen_w, screen_h);
}

/* Change the desktop wallpaper at runtime (the `wallpaper` shell builtin, via
 * SYS_setwall). Decode-into-new-then-swap: a failed load NEVER disturbs the live
 * wallpaper. The swap itself goes through wallpaper_lock (M1613); kfree(old)
 * happens AFTER releasing it, which is still safe -- any reader that acquires
 * the lock from this point on sees `next`, not `old`, and every existing
 * reader (desktop_wallpaper_sample, render_scene's memcpy) only ever touches
 * the raw pointer while holding the lock itself, never past its own release.
 * Returns 0 on success, -1 on any failure (the current wallpaper is kept). */
int desktop_set_wallpaper(const char *name) {
    uint32_t *next = decode_wallpaper(name);
    if (!next) return -1;                                  /* keep the current wallpaper */
    uint64_t f = wp_irq_save();
    uint32_t *old = wallpaper_bmp;
    wallpaper_bmp = next;
    wp_irq_restore(f);
    kfree(old);                                            /* free(NULL) is a no-op (boot gradient) */
    wallpaper_repaint = 1;                                 /* nudge the WM loop to redraw promptly */
    return 0;
}

/* Row count + width of the currently-open context menu (per ctx_kind). Shared by
 * the open/render/hit-test so the popup is always sized for whichever kind is up. */
static int ctx_nrows(void) { return ctx_kind == 1 ? CTX_DESK_ROWS : CTX_ROWS; }
static int ctx_w(void)     { return ctx_kind == 1 ? CTX_DESK_W    : CTX_W;     }

/* Context-menu hit-test: which row (0..ctx_nrows()-1) is at cursor (px,py), or -1
 * if outside the popup. Shared by the renderer's hover highlight and the click
 * handler so they always agree on the row boundaries (cf. clk_pill_w). */
static int ctx_row_at(int px, int py) {
    if (px < ctx_x || px >= ctx_x + ctx_w()) return -1;
    int r = (py - (ctx_y + 2)) / CTX_ROW_H;
    return (r >= 0 && r < ctx_nrows()) ? r : -1;
}

/* Redraw the taskbar clock pill (date+time) at its fixed rect, into whatever
 * fb_set_target() currently points at. Called both from render_scene() (a
 * full-scene pass) and standalone by the main loop's once-a-second fast path
 * below, which redraws just this small rect instead of the whole screen. */
static void draw_clock_pill(void) {
    struct rtc_time tm; rtc_now(&tm);
    char clk[24]; int q = 0;                                  /* "YYYY-MM-DD  HH:MM:SS" */
    clk[q++]='0'+(tm.year/1000)%10; clk[q++]='0'+(tm.year/100)%10;
    clk[q++]='0'+(tm.year/10)%10;   clk[q++]='0'+tm.year%10;
    clk[q++]='-'; u2((uint64_t)tm.month, clk+q); q+=2;
    clk[q++]='-'; u2((uint64_t)tm.day,   clk+q); q+=2;
    clk[q++]=' '; clk[q++]=' ';
    u2((uint64_t)tm.hour, clk+q); q+=2; clk[q++]=':';
    u2((uint64_t)tm.min,  clk+q); q+=2; clk[q++]=':';
    u2((uint64_t)tm.sec,  clk+q); q+=2; clk[q]=0;
    int clkw = clk_pill_w(), clkx = screen_w - clkw - 8;
    fb_fill_rect(clkx, start_y, clkw, start_h, THEME_PANEL_TITLE);
    glow_border(clkx, start_y, clkw, start_h, THEME_CYAN, THEME_VOID);
    draw_text(clkx + 14, start_y + 4, clk, THEME_TEXT);
}

/* Render the whole scene (wallpaper, windows, taskbar — but NOT the cursor)
 * into the cached scene buffer. This is the expensive part, so we only do it
 * when the scene actually changes; plain cursor moves reuse the cache. */
/* --- snap zones (M1892) -----------------------------------------------------
 * Dragging a window against a screen edge tiles it. The geometry each zone
 * produces lives in ONE function, snap_zone_rect, which both the action and the
 * on-screen preview call — a preview computed separately would be free to drift
 * from what the release actually does, which is exactly the kind of "looks
 * right, behaves differently" bug that makes a DE feel untrustworthy. */
enum { SNAP_NONE = 0, SNAP_LEFT, SNAP_RIGHT, SNAP_MAX };

/* The trigger band, in pixels, around a screen edge. This was 2px, which is
 * technically reachable (the tablet delivers absolute coordinates, so the
 * pointer can land exactly on 0) but miserable to hit on purpose — you aimed for
 * an edge and usually just dropped the window there instead. A band this size is
 * what makes the gesture feel like it's helping rather than resisting. */
#define SNAP_EDGE 12

/* Which snap zone (if any) the pointer at (mx,my) is in. Top edge wins over the
 * sides so the top corners maximize rather than half-tiling, matching the order
 * the release path has always used. */
static int snap_zone_at(int mx, int my) {
    if (my <= SNAP_EDGE)              return SNAP_MAX;
    if (mx <= SNAP_EDGE)              return SNAP_LEFT;
    if (mx >= screen_w - 1 - SNAP_EDGE) return SNAP_RIGHT;
    return SNAP_NONE;
}

/* The exact rectangle a snap zone yields. Single source of truth. */
static void snap_zone_rect(int zone, int *x, int *y, int *w, int *h) {
    int half = screen_w / 2;
    *y = 0; *h = screen_h - TASKBAR_H;
    switch (zone) {
        case SNAP_LEFT:  *x = 0;    *w = half;     break;
        case SNAP_RIGHT: *x = half; *w = half;     break;
        default:         *x = 0;    *w = screen_w; break;   /* SNAP_MAX */
    }
}

/* The zone the in-progress drag would snap into, or SNAP_NONE. Set by the main
 * loop while a title-bar drag is live; read by render_scene to draw the preview.
 * File-scope because `dragging` itself is a main-loop local. */
static int snap_hint = SNAP_NONE;

/* Blend every pixel under the rect `num/den` of the way toward `c` — a real
 * translucent tint, so the snap preview reads as a TARGET REGION you can see
 * through rather than an opaque slab dropped over the desktop (the first cut of
 * this used dither_rect, which fills solid and hid the wallpaper and every window
 * behind it — it looked like a bug, not a preview).
 *
 * Writes scenebuf rows directly instead of calling fb_get_pixel/fb_pixel per
 * pixel: a half-screen preview is ~590k pixels and this runs on every frame of a
 * drag inside a snap zone, which is exactly the "bounds-checked call per pixel in
 * a hot loop" pattern fb.c's own comments call out. render_scene has already
 * pointed the draw target at scenebuf when this is called. */
static void tint_rect(int x, int y, int w, int h, uint32_t c, int num, int den) {
    if (!scenebuf) return;
    if (x < 0) { w += x; x = 0; }                     /* clip to the screen */
    if (y < 0) { h += y; y = 0; }
    if (x + w > screen_w) w = screen_w - x;
    if (y + h > screen_h) h = screen_h - y;
    if (w <= 0 || h <= 0) return;
    for (int dy = 0; dy < h; dy++) {
        uint32_t *row = scenebuf + (size_t)(y + dy) * screen_w + x;
        for (int dx = 0; dx < w; dx++)
            row[dx] = lerp(row[dx], c, num, den);
    }
}

static void render_scene(void) {
    fb_set_target(scenebuf);
    wp_h = screen_h;
    {
        uint64_t f = wp_irq_save();      /* held for the whole copy (M1613) -- see wallpaper_lock's own comment */
        if (wallpaper_bmp)                                      /* image from disk */
            memcpy(scenebuf, wallpaper_bmp, (size_t)screen_w * screen_h * 4);
        else
            vgrad(0, 0, screen_w, screen_h, WP_TOP, WP_BOT);    /* fallback: gradient */
        wp_irq_restore(f);
    }

    for (int i = 0; i < win_count; i++)
        if (!windows[i].minimized)                          /* minimized = hidden to its chip */
            draw_window(&windows[i], i == win_count - 1);

    /* Snap preview (M1892): while a title-bar drag sits in an edge zone, show
     * exactly where releasing would put the window. Drawn OVER the windows (so it
     * reads as a target, not as another window) but UNDER the overlays and cursor.
     * Deliberately just a dithered wash + a bright outline + the HUD corner
     * brackets already used elsewhere in this theme — no gradient, no glow. The
     * rectangle comes from snap_zone_rect, the same function the release uses. */
    if (snap_hint != SNAP_NONE) {
        int px, py, pw, ph;
        snap_zone_rect(snap_hint, &px, &py, &pw, &ph);
        tint_rect(px, py, pw, ph, THEME_MAGENTA, 22, 100);   /* ~22% wash: see-through */
        stroke_rect(px, py, pw, ph, 2, THEME_MAGENTA);
        hud_corners(px, py, pw, ph, 22, THEME_CYAN);
    }

    /* taskbar: flat panel with a bright neon accent line on top */
    int ty = screen_h - TASKBAR_H;
    fb_fill_rect(0, ty, screen_w, TASKBAR_H, THEME_PANEL_TITLE);
    fb_fill_rect(0, ty, screen_w, 2, THEME_CYAN);

    /* Apps button: flat fill + neon glow border, brighter (magenta) when the menu is open */
    fb_fill_rect(start_x, start_y, start_w, start_h, menu_open ? THEME_PANEL : THEME_PANEL_TITLE);
    glow_border(start_x, start_y, start_w, start_h, menu_open ? THEME_MAGENTA : THEME_CYAN, THEME_VOID);
    int gi_x = start_x + 9, gi_y = start_y + (start_h - 10) / 2;  /* 2x2 "apps" grid icon */
    fb_fill_rect(gi_x,     gi_y,     4, 4, THEME_TEXT);
    fb_fill_rect(gi_x + 6, gi_y,     4, 4, THEME_TEXT);
    fb_fill_rect(gi_x,     gi_y + 6, 4, 4, THEME_TEXT);
    fb_fill_rect(gi_x + 6, gi_y + 6, 4, 4, THEME_TEXT);
    draw_text(start_x + 26, start_y + 4, "Apps", THEME_TEXT);

    /* real-time clock (RTC) pill on the right — drawn by draw_clock_pill()
     * below (also called standalone by the once-a-second fast path in the
     * main loop); just need its x/width here for the window-chips' "out of
     * room" check. */
    int clkw = clk_pill_w(), clkx = screen_w - clkw - 8;

    /* one chip per open window (the focused one — topmost — is highlighted) */
    for (int i = 0; i < win_count; i++) {
        int cx = TB_CHIPX0 + i * (TB_CHIPW + TB_CHIPGAP);
        if (cx + TB_CHIPW > chips_right_bound()) break;       /* out of room (the ws pill keeps its strip) */
        int foc = (i == win_count - 1);
        int mini = windows[i].minimized;                      /* hidden: dim its chip */
        fb_fill_rect(cx, start_y, TB_CHIPW, start_h, foc ? THEME_PANEL_TITLE : THEME_PANEL);
        glow_border(cx, start_y, TB_CHIPW, start_h, foc ? THEME_MAGENTA : THEME_BORDER_DIM, THEME_VOID);
        draw_icon(windows[i].kind, cx + 6, start_y + (start_h - ICON_SZ) / 2);   /* per-kind icon */
        char t[18]; int n = 0; const char *s = windows[i].title;
        while (s && s[n] && n < 12) { t[n] = s[n]; n++; } t[n] = 0;
        draw_text(cx + 26, start_y + 4, t, mini ? THEME_TEXT_DIM : THEME_TEXT);
    }
    /* workspace indicator (M1923): a compact 1-2-3-4 strip, current one lit, so
     * which desktop you are on is visible rather than inferred from the windows. */
    {
        int wsw = WS_PILL_W, wsx = clkx - wsw - 8;
        if (wsx > TB_CHIPX0) {
            fb_fill_rect(wsx, start_y, wsw, start_h, THEME_PANEL);
            glow_border(wsx, start_y, wsw, start_h, THEME_BORDER_DIM, THEME_VOID);
            for (int k = 0; k < WS_N; k++) {
                int bx = wsx + 4 + k * 16;
                int here = (k == cur_ws), used = here ? win_count : ws_count[k];
                if (here) fb_fill_rect(bx, start_y + 3, 14, start_h - 6, THEME_SELECT);
                char d[2] = { (char)('1' + k), 0 };
                draw_text(bx + 4, start_y + 4, d,
                          here ? THEME_MAGENTA : (used ? THEME_TEXT_DIM : THEME_BORDER_DIM));
            }
        }
    }
    draw_clock_pill();

    if (menu_open) {
        int mh = MENU_PERCOL * MENU_ITEM_H + 4, mw = MENU_COLS * MENU_W, my0 = ty - mh;
        fb_fill_rect(start_x, my0, mw, mh, THEME_PANEL);             /* flat panel */
        fb_fill_rect(start_x, my0, mw, 2, THEME_CYAN);               /* bright top accent */
        for (int c = 1; c < MENU_COLS; c++)                          /* faint column rules */
            fb_fill_rect(start_x + c * MENU_W, my0 + 4, 1, mh - 8, THEME_BORDER_DIM);
        glow_border(start_x, my0, mw, mh, THEME_CYAN, THEME_VOID);
        hud_corners(start_x - 2, my0 - 2, mw + 4, mh + 4, 10, THEME_CYAN);
        for (int i = 0; i < MENU_N; i++) {
            int col = i / MENU_PERCOL, row = i % MENU_PERCOL;
            int ix = start_x + col * MENU_W, iy = my0 + 4 + row * MENU_ITEM_H;
            if (i == menu_sel) {                                     /* keyboard highlight: dim magenta bar + left accent */
                fb_fill_rect(ix + 2, iy, MENU_W - 4, MENU_ITEM_H, THEME_SELECT);
                fb_fill_rect(ix + 2, iy, 2, MENU_ITEM_H, THEME_MAGENTA);
            }
            draw_icon(menu[i].kind, ix + 8, iy + (MENU_ITEM_H - ICON_SZ) / 2);
            draw_text(ix + 28, iy + 2, menu[i].label, i == menu_sel ? THEME_TEXT : THEME_TEXT_DIM);
        }
    }

    /* Right-click context menu: a small popup at the click point, drawn on top of
     * the windows (like the Apps menu). Two kinds share this block (ctx_kind): the
     * window title-bar menu (ctx_win names the topmost window, so a closed/reordered
     * window can't leave a stale row — render is skipped if it's no longer valid)
     * and the desktop-background menu (no window dependency). The row under the
     * cursor is highlighted (same colours as the Apps menu's keyboard highlight). */
    if (ctx_open && (ctx_kind == 1 || (ctx_win >= 0 && ctx_win < win_count))) {
        static const char *desk_rows[CTX_DESK_ROWS] = {
            "Show Desktop", "Show All Windows", "Change Wallpaper",
        };
        const char *win_rows[CTX_ROWS] = {
            windows[ctx_kind == 0 ? ctx_win : 0].maximized ? "Restore" : "Maximize",
            "Minimize", "Snap Left", "Snap Right", "Close",
        };
        const char **rows = (ctx_kind == 1) ? desk_rows : win_rows;
        int nr = ctx_nrows(), cw = ctx_w(), ch = nr * CTX_ROW_H + 4;
        fb_fill_rect(ctx_x, ctx_y, cw, ch, THEME_PANEL);     /* flat panel (matches the Apps menu) */
        fb_fill_rect(ctx_x, ctx_y, cw, 2, THEME_CYAN);       /* bright top accent */
        glow_border(ctx_x, ctx_y, cw, ch, THEME_CYAN, THEME_VOID);
        int sel = ctx_row_at(mouse_x(), mouse_y());          /* row under the cursor (-1 = none) */
        for (int i = 0; i < nr; i++) {
            int iy = ctx_y + 2 + i * CTX_ROW_H;
            if (i == sel) {                                      /* hover highlight: dim magenta bar + left accent */
                fb_fill_rect(ctx_x + 2, iy, cw - 4, CTX_ROW_H, THEME_SELECT);
                fb_fill_rect(ctx_x + 2, iy, 2, CTX_ROW_H, THEME_MAGENTA);
            }
            draw_text(ctx_x + 12, iy + 3, rows[i], i == sel ? THEME_TEXT : THEME_TEXT_DIM);
        }
    }

    /* F1 help overlay: a centered panel listing every keyboard shortcut + the
     * mouse gestures. Drawn last so it sits on top of everything. */
    if (help_open) {
        static const char *H[] = {
            "F1    this help",        "F2    switch window",
            "F3 / Super+Down  min",   "F4 / Super+Up  maximize",
            "F5 / Super+Left  snap",  "F6 / Super+Right snap",
            "F7 / Alt+Tab  switcher", "F8 / Alt+F4  close",
            "F9 / Super   Apps menu",
            "F12   screenshot to disk",
            "Ctrl+Alt+Left/Right  workspace",
            "Super+1..4  go to workspace",
            "+Shift  send window there",
            "",
            "MOUSE:",
            "Drag the title bar to move a window",
            "(double-click it, or drag to the top edge, to",
            "maximize; drag to a side edge to tile that half),",
            "drag the bottom-right corner to resize,",
            "click [x] to close, click a taskbar chip to",
            "raise (or restore) that window.",
            "Right-click a title bar for a menu (maximize,",
            "minimize, snap left/right, close).",
            "Right-click the desktop for a menu (show",
            "desktop, show all windows, change wallpaper).",
            "",
            "TIPS:",
            "Wheel scrolls the window under the cursor.",
            "In a terminal: drag (or double-click a word)",
            "to select + copy; middle-click pastes.",
            "In the browser: right-click a link to copy",
            "its URL; middle-click pastes into the bar.",
            "In Files: Enter opens, d deletes (press d/y",
            "again to confirm), r renames, n makes a new",
            "folder, w sets an image as wallpaper.",
            "",
            "Press Esc or F1 to close this help.",
        };
        int n = (int)(sizeof(H) / sizeof(H[0]));
        int pw = 380, ph = n * 18 + 40;
        int px = (screen_w - pw) / 2, py = (screen_h - TASKBAR_H - ph) / 2;
        fb_fill_rect(px, py, pw, ph, THEME_PANEL);           /* flat panel body */
        glow_border(px, py, pw, ph, THEME_CYAN, THEME_VOID);
        hud_corners(px - 2, py - 2, pw + 4, ph + 4, 10, THEME_CYAN);
        dither_rect(px, py, pw, 26, THEME_PANEL_TITLE, 0x33224E);   /* title bar, dithered (Phase 4 texture experiment) */
        fb_fill_rect(px, py, pw, 1, THEME_CYAN);
        draw_text(px + 12, py + (26 - font_height) / 2 + 1, "Keyboard Shortcuts", THEME_TEXT);
        for (int i = 0; i < n; i++) {                          /* a line ending ':' is a section label (M1525) */
            int len = 0; while (H[i][len]) len++;
            uint32_t col = (len > 0 && H[i][len - 1] == ':') ? THEME_CYAN : THEME_TEXT;
            draw_text(px + 16, py + 34 + i * 18, H[i], col);
        }
    }

    /* F7 window switcher: a centered panel listing every window (incl. minimized,
     * marked "(min)") with the highlighted one selected; Enter raises+restores it.
     * Drawn last so it sits on top of everything. */
    if (sw_open) {
        if (sw_sel >= win_count) sw_sel = win_count - 1;   /* a window closed while open: clamp */
        if (sw_sel < 0) sw_sel = 0;
        int rows = win_count > 0 ? win_count : 1;
        int pw = 320, ph = rows * MENU_ITEM_H + 40;
        int px = (screen_w - pw) / 2, py = (screen_h - TASKBAR_H - ph) / 2;
        fb_fill_rect(px, py, pw, ph, THEME_PANEL);           /* flat panel body */
        glow_border(px, py, pw, ph, THEME_CYAN, THEME_VOID);
        hud_corners(px - 2, py - 2, pw + 4, ph + 4, 10, THEME_CYAN);
        dither_rect(px, py, pw, 26, THEME_PANEL_TITLE, 0x33224E);   /* title bar, dithered (Phase 4 texture experiment) */
        fb_fill_rect(px, py, pw, 1, THEME_CYAN);
        draw_text(px + 12, py + (26 - font_height) / 2 + 1, "Windows", THEME_TEXT);
        if (win_count == 0) {
            draw_text(px + 16, py + 34, "(no windows)", THEME_TEXT_DIM);
        } else for (int i = 0; i < win_count; i++) {
            int iy = py + 30 + i * MENU_ITEM_H;
            if (i == sw_sel) {                                /* keyboard highlight: dim magenta bar + left accent */
                fb_fill_rect(px + 4, iy, pw - 8, MENU_ITEM_H, THEME_SELECT);
                fb_fill_rect(px + 4, iy, 2, MENU_ITEM_H, THEME_MAGENTA);
            }
            draw_icon(windows[i].kind, px + 10, iy + (MENU_ITEM_H - ICON_SZ) / 2);
            char t[40]; int n = 0; const char *s = windows[i].title;
            while (s && s[n] && n < 28) { t[n] = s[n]; n++; }
            if (windows[i].minimized) {                       /* mark hidden windows */
                const char *m = " (min)";
                for (int j = 0; m[j] && n < (int)sizeof(t) - 1; j++) t[n++] = m[j];
            }
            t[n] = 0;
            draw_text(px + 32, iy + 4, t, i == sw_sel ? THEME_TEXT : THEME_TEXT_DIM);
        }
    }
}

/* Last position at which we painted the cursor into the back buffer, so a
 * cursor-only update can repair exactly that rectangle. -1 = none painted yet. */
static int cur_px = -1, cur_py = -1;

/* Copy a clipped rectangle from the cached scene back into the back buffer
 * (erasing whatever — e.g. the old cursor — was drawn over the scene there). */
static void restore_scene_rect(int x, int y, int w, int h) {
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > screen_w) w = screen_w - x;
    if (y + h > screen_h) h = screen_h - y;
    if (w <= 0 || h <= 0) return;
    for (int j = 0; j < h; j++)
        memcpy(backbuffer + (size_t)(y + j) * screen_w + x,
               scenebuf   + (size_t)(y + j) * screen_w + x, (size_t)w * 4);
}

/* Copy the cached scene to the back buffer, draw the cursor on top, and blit
 * the whole screen. Used whenever the scene itself changed. */
static void present_frame(void) {
    int nx = mouse_x(), ny = mouse_y();              /* one consistent snapshot */
    memcpy(backbuffer, scenebuf, (size_t)screen_w * screen_h * 4);
    fb_set_target(backbuffer);
    mouse_paint_at(nx, ny);
    fb_present();
    cur_px = nx; cur_py = ny;
}

/* The cursor moved but the scene didn't: repair the old cursor rectangle from
 * the scene cache, draw the cursor at its new spot, and flush ONLY those two
 * small rectangles — instead of memcpy-ing and blitting the whole ~3 MB frame.
 * (M52 left this as a future optimisation; this is it.) */
static void present_cursor(void) {
    if (cur_px < 0) { present_frame(); return; }    /* nothing painted yet */
    int cw = mouse_cursor_w(), ch = mouse_cursor_h();
    int nx = mouse_x(), ny = mouse_y();             /* sample position ONCE */
    fb_set_target(backbuffer);
    restore_scene_rect(cur_px, cur_py, cw, ch);     /* erase old cursor */
    mouse_paint_at(nx, ny);                         /* draw cursor at the snapshot */
    fb_present_rect(cur_px, cur_py, cw, ch);        /* flush repaired old rect */
    fb_present_rect(nx, ny, cw, ch);                /* flush new cursor rect */
    cur_px = nx; cur_py = ny;
}

static int rects_overlap(int ax, int ay, int aw, int ah, int bx, int by, int bw, int bh) {
    return ax < bx + bw && bx < ax + aw && ay < by + bh && by < ay + ah;
}

/* The once-a-second clock tick, and nothing else, changed: redraw just the
 * clock pill's small rect (into the scene cache too, so it stays correct for
 * present_cursor()'s later restore_scene_rect reads) instead of the whole
 * scene + a full-screen memcpy+blit. Profiling found the full path here was
 * ~40% of ALL kernel-mode samples during otherwise-idle desktop time (nothing
 * running, just the clock ticking once a second) — this is the present_cursor
 * (M52/M105) treatment applied to the clock. */
static void present_clock(void) {
    int clkw = clk_pill_w(), clkx = screen_w - clkw - 8, ty = screen_h - TASKBAR_H;
    fb_set_target(scenebuf);
    draw_clock_pill();
    fb_set_target(backbuffer);
    restore_scene_rect(clkx, ty, clkw, TASKBAR_H);
    fb_present_rect(clkx, ty, clkw, TASKBAR_H);
}

/* Move to workspace `to`, parking the current window set (M1923). */
/* Right edge available to the window chips. ONE definition, used by BOTH the draw
 * and the click hit-test: they each spelled `clkx - 8`, and that bound overlapped
 * the workspace indicator -- with enough windows a chip was drawn, painted over by
 * the indicator, and STILL raised its window when you clicked what looked like a
 * workspace button. (M1926) */
static int chips_right_bound(void) {
    return screen_w - clk_pill_w() - 8 - WS_PILL_W - 8;
}

static void switch_ws(int to) {
    if (to < 0 || to >= WS_N || to == cur_ws) return;
    for (int i = 0; i < win_count; i++) ws_store[cur_ws][i] = windows[i];
    ws_count[cur_ws] = win_count;
    for (int i = 0; i < ws_count[to]; i++) windows[i] = ws_store[to][i];
    win_count = ws_count[to];
    cur_ws = to;
}

/* Send the focused window to workspace `to` (M1924). Switching between workspaces
 * is only half the feature — without this, a window is stuck where it opened.
 *
 * Deliberately does NOT reuse remove_window(): that calls browser_destroy() on a
 * KIND_BROWSER window, which would free the very page being moved. This unlinks
 * the window without touching what it owns. */
static void move_focused_to_ws(int to) {
    if (to < 0 || to >= WS_N || to == cur_ws || win_count <= 0) return;
    if (ws_count[to] >= MAX_WINDOWS) return;     /* target full: refuse, never drop a window */
    int fi = win_count - 1;                      /* the focused window is the topmost */
    ws_store[to][ws_count[to]++] = windows[fi];  /* arrives on top over there */
    win_count--;                                 /* fi was the last slot: nothing to shift */
}

static void raise_window(int idx) {
    window_t tmp = windows[idx];
    for (int i = idx; i < win_count - 1; i++) windows[i] = windows[i + 1];
    windows[win_count - 1] = tmp;
    windows[win_count - 1].minimized = 0;       /* raising a window also restores it */
}
/* F3: send a window to the bottom of the z-order (used when minimizing, so the
 * next window below becomes focused). The reverse of raise_window. */
static void sink_window(int idx) {
    window_t tmp = windows[idx];
    for (int i = idx; i > 0; i--) windows[i] = windows[i - 1];
    windows[0] = tmp;
}

/* F4: fill the screen (above the taskbar), or restore the saved geometry. */
static void toggle_maximize(int idx) {
    window_t *w = &windows[idx];
    if (w->maximized) {
        w->x = w->sx; w->y = w->sy; w->w = w->sw; w->h = w->sh;
        w->maximized = 0;
    } else {
        w->sx = w->x; w->sy = w->y; w->sw = w->w; w->sh = w->h;
        snap_zone_rect(SNAP_MAX, &w->x, &w->y, &w->w, &w->h);
        w->maximized = 1;
    }
}
/* F5/F6: snap the window to the left/right half of the screen (tiling). Saves
 * the original geometry the same way maximize does, so F4 / a drag restores. */
static void snap_window(int idx, int rightside) {
    window_t *w = &windows[idx];
    if (!w->maximized) { w->sx = w->x; w->sy = w->y; w->sw = w->w; w->sh = w->h; }
    snap_zone_rect(rightside ? SNAP_RIGHT : SNAP_LEFT, &w->x, &w->y, &w->w, &w->h);
    w->maximized = 1;
}
static void remove_window(int idx) {
    if (windows[idx].kind == KIND_BROWSER && windows[idx].app)
        browser_destroy((browser_t *)windows[idx].app);   /* free its buffers */
    for (int i = idx; i < win_count - 1; i++) windows[i] = windows[i + 1];
    win_count--;
}

/* Run the right-click context-menu row `row` on window `idx`. Each branch wraps
 * the exact helper the matching F-key uses, so behaviour is identical. Returns 1
 * if it reordered/removed the window array (the caller must then drop any active
 * mouse gesture, as the F3/F8 paths do); 0 if geometry-only. `idx` must be valid. */
static int ctx_action(int idx, int row) {
    switch (row) {
        case 0: toggle_maximize(idx); return 0;                  /* Maximize / Restore (F4) */
        case 1: {                                                /* Minimize (F3) */
            int vis = 0;                                         /* never hide the LAST visible window */
            for (int i = 0; i < win_count; i++) if (!windows[i].minimized) vis++;
            if (vis > 1) { windows[idx].minimized = 1; sink_window(idx); return 1; }
            return 0;
        }
        case 2: snap_window(idx, 0); return 0;                   /* Snap Left (F5) */
        case 3: snap_window(idx, 1); return 0;                   /* Snap Right (F6) */
        case 4:                                                  /* Close (F8) */
            if (windows[idx].kind == KIND_APP && windows[idx].app)
                app_request_kill((app_t *)windows[idx].app);     /* app self-exits; reap loop drops the window */
            else
                remove_window(idx);                              /* browser/files/etc: drop immediately */
            return 1;
    }
    return 0;
}

static int files_is_image(const char *name, int len);   /* defined below (shared with the Files 'w' key) */

/* Run the desktop-background context-menu row `row`. Returns 1 if it reordered the
 * window array (so the caller drops any active mouse gesture), 0 otherwise.
 *   0 Show Desktop      minimize EVERY window (no last-window guard, unlike F3)
 *   1 Show All Windows  restore every minimized window
 *   2 Change Wallpaper  cycle to the next image file on disk */
static int ctx_desktop_action(int row) {
    switch (row) {
        case 0:                                                  /* Show Desktop: minimize EVERY window */
            for (int i = 0; i < win_count; i++)                  /* a flag-only pass (no array mutation, */
                windows[i].minimized = 1;                        /* so none is skipped); z-order among */
            return 0;                                            /* hidden windows is irrelevant, so no sink */
        case 1:                                                  /* Show All Windows: restore every minimized one */
            for (int i = 0; i < win_count; i++)                  /* flag-only pass too: raise_window would */
                windows[i].minimized = 0;                        /* shift the array mid-iteration and skip */
            return 0;                                            /* one; z-order is preserved (all visible) */
        case 2: {                                                /* Change Wallpaper: cycle to the next image on disk */
            static int wp_idx;
            vfs_dirent *e; int n = files_list_cached("/", &e, 0);  /* wallpaper images live at the boot-FS root (M1762) */
            if (n <= 0) return 0;
            for (int step = 0; step < n; step++) {               /* try each candidate from wp_idx onward; */
                int i = (wp_idx + step) % n;                     /* a non-image / decode failure is skipped */
                const char *name = e[i].name;
                int len = 0; while (name[len]) len++;
                if (len > 0 && files_is_image(name, len) && desktop_set_wallpaper(name) == 0) {
                    wp_idx = (i + 1) % n;                        /* next call starts past the one we just set */
                    return 0;
                }
            }
            return 0;                                            /* no usable image: no-op */
        }
    }
    return 0;
}

/* Give a freshly-spawned app a window (called by the WM as it drains the
 * spawn queue, so apps launched from anywhere get a window here). */
static int wl_window_open;   /* a Wayland client has a desktop window (declared here: make_app_window needs it, M2243) */
static void make_app_window(app_t *a) {
    if (win_count >= MAX_WINDOWS) return;
    /* A PROGRAM RUNNING INSIDE SOMEONE ELSE'S WINDOW DOES NOT GET ITS OWN
     * (M2004). `claude` typed at the shell is a foreground job of that shell:
     * its output goes into the shell's window and its input comes from there.
     * Giving it a second, empty window of its own put the program's UI
     * somewhere the person who typed the command was not looking, and left the
     * terminal they WERE looking at frozen behind it. */
    if (app_out_to_of(a)) {
        /* SAY WHOSE. This is the only silent `return` in the window path, and
         * an app that wrongly believes it is someone's foreground job simply
         * never appears -- which is what a missing Shell window looks like.
         * (M2076) */
        kprintf("[desktop] '%s' (pid %d) gets NO window: its output is routed to pid %d's\n",
                app_title(a) ? app_title(a) : "?", app_pid_of(a), app_pid_of(app_out_to_of(a)));
        return;
    }
    /* NAME EVERY WINDOW AS IT IS CREATED (M2076). The desktop's own state was
     * unobservable from a log: a window that was never created and one that
     * was never asked for look identical, and the boot suite could assert
     * neither. The Shell is the one that matters -- without it the desktop has
     * no terminal at all, and every keystroke goes to whatever else has
     * focus. */
    kprintf("[desktop] window for '%s' (pid %d)\n",
            app_title(a) ? app_title(a) : "?", app_pid_of(a));
    spawn_n++;
    /* Open to the RIGHT of the boot column and cascade there, instead of at a
     * fixed 150,60 that lands on top of it. Clamped so a window can never open
     * with its titlebar off-screen, which is how one becomes unmovable. */
    int aw = app_cols()*font_width + 14, ah = app_rows()*font_height + TITLEBAR_H + 14;
    int m = screen_w / 24, left = m + screen_w * 30 / 100 + m / 2;
    int x = left + (spawn_n % 5) * 22, y = m + (spawn_n % 5) * 22;
    if (x + aw > screen_w - m / 2) x = screen_w - m / 2 - aw;
    if (y + ah > screen_h - TASKBAR_H - m / 2) y = screen_h - TASKBAR_H - m / 2 - ah;
    if (x < m / 2) x = m / 2;
    if (y < m / 2) y = m / 2;
    windows[win_count++] = (window_t){ x, y, aw, ah,
        THEME_PANEL, app_title(a), KIND_APP, a, 0,0,0,0,0,0,0, 0,{0},0, 0, {0} };  /* maximized,sx,sy,sw,sh,fsel,fconfirm, editing,editbuf,editlen, minimized */
    /* A GRAPHICAL APP'S HELPER PROCESSES DO NOT GET THE SCREEN (M2243).
     *
     * Firefox spawns several children, and each one the desktop sees gets a
     * terminal window for its stdout, opened cascaded ON TOP of the browser
     * and painted black. Input goes to the topmost visible window, so the
     * browser became unreachable: "i cant click or scroll or anything".
     *
     * wl_hide_console_for_clients() handles the children that connect to the
     * compositor themselves, by pid. It cannot handle the ones that never
     * connect -- and those are exactly the ones left covering the page.
     *
     * So once a Wayland client owns a window, a newly spawned program's
     * console opens MINIMIZED. Its output is still captured, its window is
     * still in the taskbar one click away, and the graphical application that
     * owns the display keeps it. Before any Wayland window exists this changes
     * nothing, which is the ordinary desktop case (the Shell still opens
     * normally at boot, long before a browser). */
    if (wl_window_open) {
        windows[win_count - 1].minimized = 1;
        kprintf("[desktop] '%s' (pid %d) opens MINIMIZED: a Wayland client owns the display\n",
                app_title(a) ? app_title(a) : "?", app_pid_of(a));
    }
}

/* Open a window for a Wayland client's surface (M1980).
 *
 * The desktop polls for this rather than the compositor calling in: a Wayland
 * compositor IS the window manager, and having the display server reach into
 * the desktop's window array from its own task would be a data race on
 * `windows[]` for no benefit. One window, opened on the first commit, sized to
 * the surface -- the multi-surface case arrives with xdg_shell. */
/* Our cooked keyboard layer hands out CHARACTERS; Wayland carries evdev
 * KEYCODES. This is the minimal honest mapping for the letters and the few
 * keys a demo actually presses -- a full layout belongs with a real xkb
 * keymap, which is the next piece of this. (M1983) */
/* THE WHOLE US LAYOUT, AND WHETHER IT NEEDS SHIFT (M2244).
 *
 * The old table covered letters, digits, space, Enter and Escape, and returned
 * 0 -- not a valid evdev code -- for everything else. So a Wayland client
 * received NOTHING for `.`, `/`, `:`, `-`, backspace or tab.
 *
 * That is not a rough edge, it is the difference between a browser you can use
 * and one you cannot: **there was no way to type a URL**. It is also why my own
 * attempt to verify input by typing `/miles` (Firefox's quick-find) proved
 * nothing -- the `/` was silently dropped before it ever left the desktop, so
 * a working key path and a broken one looked identical.
 *
 * Shifted characters need the modifier sent too. The desktop's cooked layer
 * has no modifier state (see M1920: modifiers live in the raw scancode layer),
 * so a client told "apostrophe" when the user typed `"` gets the wrong
 * character. Returning the shift requirement alongside the keycode lets the
 * caller bracket the press with LEFTSHIFT, which is what a real keyboard
 * sends. */
#define EV_LEFTSHIFT 42
static unsigned desktop_key_to_evdev_shift(int ch, int *need_shift) {
    static const char *r1 = "qwertyuiop", *r2 = "asdfghjkl", *r3 = "zxcvbnm";
    static const unsigned row1[] = { 16,17,18,19,20,21,22,23,24,25 };
    static const unsigned row2[] = { 30,31,32,33,34,35,36,37,38 };
    static const unsigned row3[] = { 44,45,46,47,48,49,50 };
    /* (unshifted, shifted) sharing one keycode, US layout. */
    static const char  *unsh = "1234567890-=[]\\;',./`";
    static const char  *shft = "!@#$%^&*()_+{}|:\"<>?~";
    static const unsigned pun[] = { 2,3,4,5,6,7,8,9,10,11,12,13,26,27,43,39,40,51,52,53,41 };
    int sh = 0;
    int c2 = ch;
    if (ch >= 'A' && ch <= 'Z') { c2 = ch + 32; sh = 1; }
    if (need_shift) *need_shift = sh;
    for (int i = 0; r1[i]; i++) if (r1[i] == c2) return row1[i];
    for (int i = 0; r2[i]; i++) if (r2[i] == c2) return row2[i];
    for (int i = 0; r3[i]; i++) if (r3[i] == c2) return row3[i];
    for (int i = 0; unsh[i]; i++) if (unsh[i] == c2) return pun[i];
    for (int i = 0; shft[i]; i++)
        if (shft[i] == c2) { if (need_shift) *need_shift = 1; return pun[i]; }
    if (c2 == ' ')   return 57;
    if (c2 == '\n')  return 28;                   /* Enter */
    if (c2 == '\r')  return 28;
    if (c2 == 27)    return 1;                    /* Escape */
    if (c2 == '\b' || c2 == 127) return 14;       /* Backspace */
    if (c2 == '\t')  return 15;                   /* Tab */
    /* ARROWS -- WHICH IS HOW YOU SCROLL A PAGE (M2244).
     *
     * The desktop's cooked codes for the four arrows are 0x11..0x14 (see the
     * file manager and window-switcher handlers). They were not in this table,
     * so a Wayland client got nothing for them and a browser could not be
     * scrolled from the keyboard at all.
     *
     * The values are checked against OUR OWN keymap rather than assumed:
     * kernel/include/xkbmap.h declares <UP> = 111, <DOWN> = 116, <LEFT> = 113,
     * <RGHT> = 114, and an xkb keycode is the evdev code plus 8 -- so 103,
     * 108, 105 and 106. A table that disagreed with the keymap we ship would
     * translate to the wrong key and be very hard to see. */
    if (c2 == 0x11) return 103;                   /* KEY_UP    (<UP>   = 111) */
    if (c2 == 0x12) return 108;                   /* KEY_DOWN  (<DOWN> = 116) */
    if (c2 == 0x13) return 105;                   /* KEY_LEFT  (<LEFT> = 113) */
    if (c2 == 0x14) return 106;                   /* KEY_RIGHT (<RGHT> = 114) */
    return 0;
}

/* A PROCESS THAT DRAWS ITS OWN WINDOW DOES NOT NEED A TERMINAL ON TOP OF IT
 * (M2202).
 *
 * make_app_window gives every spawned Linux process a terminal window for its
 * stdout, which is exactly right for `claude` and exactly wrong for Firefox:
 * it spawns copies of itself, each one gets a black terminal, and the newest
 * opens ABOVE the browser window the same program is painting into. The first
 * ffshow screenshot is a fully rendered page with a black rectangle over a
 * third of it, titled /disk2/usr/lib64/firefo.
 *
 * The question that separates the two cases is already answerable: has this
 * process opened a Wayland connection? If it has, its display is the window it
 * draws in. Minimize the terminal rather than destroying it -- the taskbar
 * entry stays, the output is still there, and one click brings it back -- and
 * do it ONCE per pid, so a person who restores it keeps it. */
static int wlpid_seen[16], nwlpid_seen;
/* The topmost window the user can actually see -- the one that owns input.
 * -1 when every window is minimized (or there are none), which is the only
 * case where a keystroke legitimately has nowhere to go. (M2243) */
/* DID THE KEY EVEN GET HERE? (M2244) Three counters that separate the three
 * places a keystroke can die: never dequeued by the desktop, dequeued but the
 * focused window is not a Wayland client, or forwarded and ignored by the
 * client. Without these, all three look the same from a screenshot. */
unsigned long g_dk_keys, g_dk_fwd;
int g_dk_focus_kind = -2;
static int focus_index(void) {
    for (int i = win_count - 1; i >= 0; i--)
        if (!windows[i].minimized) return i;
    return -1;
}
static void wl_hide_console_for_clients(void) {
    for (int ci = 0; ci < wl_client_count(); ci++) {
        if (!wl_client_used(ci)) continue;
        int pid = wl_client_pid(ci);
        if (pid <= 0) continue;
        /* SCAN EVERY TIME, NOT ONCE PER PID (M2243).
         *
         * This used to `continue` as soon as the pid was already known, so the
         * window scan below ran exactly once per process -- on the iteration
         * that first saw the Wayland connection. A process that connects to
         * the compositor BEFORE the desktop gets round to opening a terminal
         * window for its stdout therefore keeps that window forever: the pid
         * was already "known" by the time the window existed.
         *
         * That is the ordinary case for Firefox's children, and it is what the
         * user was looking at -- a black window titled
         * `/disk2/usr/lib64/firefo` sitting on top of the page. Input goes to
         * the topmost window, so every click and keystroke went into it.
         *
         * The latch now only suppresses the repeated LOG LINE; the scan itself
         * is unconditional and costs one pass over at most MAX_WINDOWS. */
        int known = 0;
        for (int i = 0; i < nwlpid_seen; i++) if (wlpid_seen[i] == pid) { known = 1; break; }
        if (!known && nwlpid_seen < (int)(sizeof wlpid_seen / sizeof wlpid_seen[0]))
            wlpid_seen[nwlpid_seen++] = pid;
        for (int i = 0; i < win_count; i++) {
            if (windows[i].kind != KIND_APP || !windows[i].app) continue;
            if (app_pid_of((app_t *)windows[i].app) != pid) continue;
            if (windows[i].minimized) continue;
            windows[i].minimized = 1;
            if (!known)
                kprintf("[desktop] pid %d is a Wayland client, so its terminal window is "
                        "minimized -- it draws its own\n", pid);
        }
    }
}
static void wl_window_poll(void) {
    /* ONE WINDOW PER CLIENT (M2089). This used to open exactly one, ever,
     * latched by wl_window_open -- so the first client to commit anything took
     * the display for the rest of the boot. lxwl commits a 64x32 test pattern
     * two minutes before Firefox finishes starting, which is how a browser
     * painting full-size frames ended up with nowhere to be drawn.
     *
     * SIZED BY THE WHOLE TREE, too. GTK gives its xdg_toplevel no buffer and
     * renders into a subsurface, so asking the root surface for its pixels
     * answered NULL for a client that was committing 1204x916 frames. */
    for (int ci = 0; ci < wl_client_count(); ci++) {
        if (win_count >= MAX_WINDOWS) return;
        if (!wl_client_used(ci)) continue;
        int taken = 0;
        for (int i = 0; i < win_count; i++)
            if (windows[i].kind == KIND_WAYLAND && (int)(long)windows[i].app - 1 == ci) { taken = 1; break; }
        if (taken) continue;
        /* AND IT HAS TO BE A WINDOW (M2200). A non-zero extent is not the
         * same as "the client asked for a window": see
         * wl_client_window_ready. Firefox's content processes each committed a
         * roleless surface and each got a black desktop window opened over the
         * browser. */
        if (!wl_client_window_ready(ci)) continue;
        uint32_t sw2 = 0, sh2 = 0;
        wl_client_extent(ci, &sw2, &sh2);
        if (!sw2 || !sh2) continue;
        spawn_n++;
        int x = 150 + (spawn_n % 6) * 26, y = 60 + (spawn_n % 6) * 26;
        int ww = (int)sw2 + 14, wh = (int)sh2 + TITLEBAR_H + 14;
        /* A 1204x916 browser plus chrome is wider than an 800x600 display, and
         * a window bigger than the screen cannot be moved to where its close
         * button is. Clamp to the framebuffer; the blit already clips. */
        if (ww > fb_width() - 8)  ww = fb_width() - 8;
        if (wh > fb_height() - 8) wh = fb_height() - 8;
        /* AND IT HAS TO FIT ON THE SCREEN AT THAT POSITION (M2202). The size
         * was clamped and the position was not, so a browser window as wide as
         * the framebuffer opened at x=150 and lost 150 pixels of the page off
         * the right edge -- visible in the first ffshow screenshot as a page
         * cut off mid-sentence. Cascade only as far as there is room. */
        if (x + ww > fb_width() - 4)  x = fb_width() - 4 - ww;
        if (y + wh > fb_height() - TASKBAR_H - 4) y = fb_height() - TASKBAR_H - 4 - wh;
        if (x < 2) x = 2;
        if (y < 2) y = 2;
        /* The title comes from xdg_toplevel.set_title, which is how a Wayland
         * client names its own window -- the same call Firefox uses to put a
         * page title in the titlebar. */
        windows[win_count++] = (window_t){ x, y, ww, wh,
                                           THEME_PANEL, wl_client_title_of(ci), KIND_WAYLAND,
                                           (void *)(long)(ci + 1),
                                           0,0,0,0,0,0,0, 0,{0},0, 0, {0} };
        kprintf("[wl] desktop window for client slot %d: %ux%u ('%s')\n",
                ci, sw2, sh2, wl_client_title_of(ci));
        wl_window_open = 1;
    }
}

/* Open a browser window at `url` (NULL -> its default). */
static void spawn_browser(const char *url) {
    if (win_count >= MAX_WINDOWS) return;
    spawn_n++;
    int x = 150 + (spawn_n % 6) * 26, y = 60 + (spawn_n % 6) * 26;
    windows[win_count++] = (window_t){ x, y, 960, 700, 0xFFFFFF, "Browser",   /* roomy by default (M1433) */
                                       KIND_BROWSER, browser_create(url), 0,0,0,0,0,0,0, 0,{0},0, 0, {0} };
}

/* Is `name` a plain-text / source file we'd rather edit than view? (case-
 * insensitive extension match; FAT names are upper-case). */
static int files_editable(const char *name, int len) {
    int dot = -1; for (int i = 0; i < len; i++) if (name[i] == '.') dot = i;
    if (dot < 0) return 0;
    static const char *exts[] = { "TXT","MD","C","H","SH","LOG","CFG","INI","JS","ASM","JSON", 0 };
    for (int i = 0; exts[i]; i++) {
        const char *a = name + dot + 1, *b = exts[i]; int eq = 1;
        while (*a && *b) { char ca = (*a >= 'a' && *a <= 'z') ? *a - 32 : *a; if (ca != *b) { eq = 0; break; } a++; b++; }
        if (eq && !*a && !*b) return 1;
    }
    return 0;
}

/* Is `name` an image we can set as the wallpaper? (case-insensitive extension
 * match — same formats decode_image() handles: PNG/BMP/JPG/JPEG/GIF/SVG.) */
static int files_is_image(const char *name, int len) {
    int dot = -1; for (int i = 0; i < len; i++) if (name[i] == '.') dot = i;
    if (dot < 0) return 0;
    static const char *exts[] = { "PNG","BMP","JPG","JPEG","GIF","SVG", 0 };
    for (int i = 0; exts[i]; i++) {
        const char *a = name + dot + 1, *b = exts[i]; int eq = 1;
        while (*a && *b) { char ca = (*a >= 'a' && *a <= 'z') ? *a - 32 : *a; if (ca != *b) { eq = 0; break; } a++; b++; }
        if (eq && !*a && !*b) return 1;
    }
    return 0;
}

/* Keyboard handling for the Files window. up/down move the selection; Enter
 * opens the highlighted file (text/source -> editor, image -> image viewer,
 * else a browser window).
 * 'd'/Delete arms a two-key delete confirm (a second d/y commits it; ANY other
 * key cancels it — so a stray 'd' is harmless); 'w' sets an image as the
 * wallpaper. The dirent list is re-read each call, so it refreshes for free
 * after a delete. */
static void files_key(window_t *w, int k) {
    vfs_dirent *e; int n = files_list_cached(FCWD(w), &e, 0);   /* a keypress can act on the throttled cache; forced below only after an actual mutation */

    if (w->editing) {                                         /* a rename / new-folder text-input is open */
        if (k == 27) { w->editing = 0; return; }               /* Esc cancels: leave the name untouched */
        if (k == '\n' || k == '\r') {                          /* Enter commits */
            w->editbuf[w->editlen] = 0;
            if (w->editlen > 0) {                              /* empty input is a no-op (vfs_rename/mkdir would reject it anyway) */
                if (w->editing == 1) {                         /* rename the selected entry */
                    if (n > 0 && w->fsel >= 0 && w->fsel < n) {
                        char old[64]; int p = 0;
                        for (int j = 0; e[w->fsel].name[j] && p < (int)sizeof(old) - 1; j++) old[p++] = e[w->fsel].name[j];
                        if (p > 0 && old[p-1] == '/') p--;     /* the listing marks dirs with a trailing '/' */
                        old[p] = 0;
                        char oa[160]; files_abspath(w, old, oa, sizeof oa);   /* resolve against THIS window's browse dir (M1762) */
                        vfs_rename(oa, w->editbuf);            /* -1 (bad name / clobber / missing) leaves the disk unchanged */
                    }
                } else {                                       /* editing == 2: make a new folder */
                    char na[160]; files_abspath(w, w->editbuf, na, sizeof na);
                    vfs_mkdir(na);                             /* -1 on a bad name / existing entry: no-op */
                }
            }
            w->editing = 0;
            n = files_list_cached(FCWD(w), &e, 1);          /* forced: re-list so the new/renamed entry shows + the clamp is correct */
            if (w->fsel >= n) w->fsel = n - 1;
            if (w->fsel < 0)  w->fsel = 0;
            return;
        }
        if (k == 8 || k == 0x7F) {                             /* Backspace / Delete: drop the last char */
            if (w->editlen > 0) w->editbuf[--w->editlen] = 0;
            return;
        }
        if (k >= ' ' && k < 0x7F && w->editlen < 12) {         /* printable: append (8.3 = max 12 chars), upper-cased like the FS stores */
            char c = (k >= 'a' && k <= 'z') ? (char)(k - 32) : (char)k;
            w->editbuf[w->editlen++] = c;
            w->editbuf[w->editlen] = 0;
        }
        return;                                                /* swallow every key while editing — don't fall through to nav */
    }

    /* These must work even when the current directory is EMPTY (n==0) -- otherwise
     * descending into an empty folder would trap you (M1762). Handle them before
     * the n<=0 guard below (which only gates the per-selection actions). */
    if (k == 8) { fcwd_ascend(w); files_list_cached(FCWD(w), &e, 1); w->fsel = 0; w->fconfirm = 0; return; }   /* Backspace: up one directory */
    if (k == 'n') { w->editbuf[0] = 0; w->editlen = 0; w->editing = 2; w->fconfirm = 0; return; }             /* new folder */
    if (k == 'v' && files_clip[0]) {                           /* paste the copied/cut file into THIS dir (M1763) -- works in an empty dir too */
        const char *base = files_clip; for (const char *t = files_clip; *t; t++) if (*t == '/') base = t + 1;
        char dst[160]; files_abspath(w, base, dst, sizeof dst);
        if (!path_eq(dst, files_clip)) {                       /* pasting onto itself would delete the file on a cut -> skip */
            if (files_copy(files_clip, dst) == 0 && files_clip_move) vfs_remove(files_clip);
        }
        files_clip[0] = 0;                                     /* clipboard consumed (a cut is one-shot) */
        files_list_cached(FCWD(w), &e, 1); w->fsel = 0; w->fconfirm = 0;
        return;
    }

    if (n <= 0) { w->fconfirm = 0; return; }
    if (w->fsel >= n) w->fsel = n - 1;
    if (w->fsel < 0)  w->fsel = 0;

    if (w->fconfirm) {                                         /* a delete is armed */
        if (k == 'd' || k == 'y' || k == 0x7F) {               /* second d/y (or Delete) -> commit */
            char buf[64]; int p = 0;
            for (int j = 0; e[w->fsel].name[j] && p < (int)sizeof(buf) - 1; j++) buf[p++] = e[w->fsel].name[j];
            if (p > 0 && buf[p-1] == '/') p--;                 /* strip the listing's trailing '/' on dirs */
            buf[p] = 0;
            char ba[160]; files_abspath(w, buf, ba, sizeof ba);   /* delete the file in THIS window's browse dir, not the shared cwd (M1762) */
            vfs_remove(ba);                                    /* deletes a file or empty dir; refuses a non-empty dir (no crash) */
            w->fconfirm = 0;
            n = files_list_cached(FCWD(w), &e, 1);          /* forced: re-list so the clamp uses the post-delete count */
            if (w->fsel >= n) w->fsel = n - 1;
            if (w->fsel < 0)  w->fsel = 0;
        } else {                                               /* ANY other key cancels; the key is otherwise ignored */
            w->fconfirm = 0;
        }
        return;
    }

    if (k == 0x11)       { if (w->fsel > 0)     w->fsel--; }   /* up   */
    else if (k == 0x12)  { if (w->fsel < n - 1) w->fsel++; }   /* down */
    else if (k == 'd' || k == 0x7F) {                          /* arm the delete confirm (render shows the prompt) */
        w->fconfirm = 1;
    }
    else if (k == 'w') {                                       /* set an image file as the desktop wallpaper */
        const char *name = e[w->fsel].name;
        int len = 0; while (name[len]) len++;
        if (len > 0 && files_is_image(name, len)) {
            char wa[160]; files_abspath(w, name, wa, sizeof wa);
            desktop_set_wallpaper(wa);                         /* visible bg change is the feedback; a decode failure is a no-op */
        }
    }
    else if (k == 'c' || k == 'x') {                           /* copy / cut the selected FILE onto the clipboard; 'v' pastes into any dir (M1763) */
        const char *name = e[w->fsel].name;
        int len = 0; while (name[len]) len++;
        if (len > 0 && name[len-1] != '/') {                   /* files only -- no recursive directory copy */
            files_abspath(w, name, files_clip, sizeof files_clip);
            files_clip_move = (k == 'x');
        }
    }
    else if (k == 'r') {                                       /* rename: open a text-input pre-filled with the selected name */
        int p = 0;
        for (int j = 0; e[w->fsel].name[j] && p < 12; j++) w->editbuf[p++] = e[w->fsel].name[j];
        if (p > 0 && w->editbuf[p-1] == '/') p--;              /* drop the dir-marker '/' so the buffer holds just the name */
        w->editbuf[p] = 0; w->editlen = p;
        w->editing = 1;
    }
    else if (k == 'o' || k == 'O') {                           /* cycle the sort order: name -> size -> date (M1426) */
        g_fsort = (g_fsort + 1) % 3; w->fsel = 0;
    }
    else if (k == '\n' || k == '\r') {
        const char *name = e[w->fsel].name;
        int len = 0; while (name[len]) len++;
        if (len > 0 && name[len-1] == '/') {                   /* a directory: descend into THIS window's browse dir (M1762) */
            char d[64]; int p = 0;
            for (int j = 0; j < len - 1 && p < (int)sizeof(d) - 1; j++) d[p++] = name[j];  /* strip trailing '/' */
            d[p] = 0;
            fcwd_descend(w, d); n = files_list_cached(FCWD(w), &e, 1); w->fsel = 0;   /* enter folder + re-list (no cwd change) */
        } else if (len > 0) {                                  /* a file: open it by absolute path (so it opens the right file regardless of any app's cwd) */
            char ap[160]; files_abspath(w, name, ap, sizeof ap);
            if (files_editable(name, len)) {
                app_spawn_named_arg("editor", ap);             /* edit text/source files */
            } else if (files_is_image(name, len)) {
                app_spawn_named_arg("imgview", ap);            /* view images in the image viewer (M1393) */
            } else {
                char url[168]; int p = 0; const char *pre = "file:";
                while (*pre) url[p++] = *pre++;
                for (int j = 0; ap[j] && p < (int)sizeof(url) - 1; j++) url[p++] = ap[j];
                url[p] = 0;
                spawn_browser(url);                            /* view everything else */
            }
        }
    }
}

/* A click in the Files window body: pick the file row under the cursor, select
 * it, and open it (the mouse equivalent of arrowing to it and pressing Enter).
 * `my` is the screen y of the click; the row math mirrors the KIND_FILES render. */
static void files_click(window_t *w, int my) {
    vfs_dirent *e; int n = files_list_cached(FCWD(w), &e, 0);   /* just hit-testing which row was clicked; files_key (below) does any real navigation */
    if (n <= 0) return;
    int by = w->y + TITLEBAR_H + 8;                    /* body content origin (matches draw) */
    int rows = (w->h - TITLEBAR_H - 66) / 18; if (rows < 1) rows = 1;   /* M1753: match the render. The M1525 column-label header pushed the first file row to by+40 (highlight band by+38) and the row count to -66; this hit-test kept the stale -30 / by+22, so every click landed ~1 row low (opened the file below the one clicked). */
    int top = (w->fsel >= rows) ? w->fsel - rows + 1 : 0;   /* same scroll as the render */
    if (my < by + 38) return;                          /* above the first row's highlight band -> header, not a file */
    int row = top + (my - (by + 38)) / 18;
    if (row < 0 || row >= n) return;                   /* clicked below the last file */
    w->fsel = row;
    files_key(w, '\n');                                /* select + open via the shared Enter path */
}

static void spawn_app(int kind, const char *prog) {
    if (kind == KIND_APP)     { app_spawn_named(prog); return; }  /* WM drains it */
    if (kind == KIND_BROWSER) { spawn_browser(0); return; }
    if (kind == KIND_POWEROFF) { acpi_poweroff(); return; }       /* ACPI S5 — the machine powers off */
    if (kind == KIND_REBOOT)   { acpi_reboot();   return; }       /* ACPI reset (8042 fallback) */
    if (win_count >= MAX_WINDOWS) return;
    spawn_n++;
    int x = 150 + (spawn_n % 6) * 26, y = 60 + (spawn_n % 6) * 26;
    window_t w = { 0 };
    w.x = x; w.y = y; w.kind = kind;
    switch (kind) {
    case KIND_FILES:   w.w=500; w.h=200; w.body=THEME_PANEL; w.title="Files";   break;  /* wide enough for the d-delete / w-wallpaper hint + confirm prompt */
    case KIND_WELCOME: w.w=360; w.h=290; w.body=THEME_PANEL; w.title="Welcome"; break;   /* dark slate panel (M1476) */
    case KIND_ABOUT:   w.w=300; w.h=196; w.body=THEME_PANEL; w.title="About";   break;
    case KIND_SYSMON:  w.w=320; w.h=272; w.body=THEME_PANEL; w.title="System Info"; break;
    default:           w.w=240; w.h=150; w.body=THEME_PANEL; w.title="Window";  break;
    }
    windows[win_count++] = w;
}

static int in_rect(int px, int py, int x, int y, int w, int h) {
    return px >= x && px < x + w && py >= y && py < y + h;
}

void desktop_run(void) {
    /* THE WINDOW MANAGER MUST NOT BE SCHEDULED LIKE A BATCH JOB (M2243).
     *
     * This loop IS the user interface: it polls the tablet, drains the
     * keyboard, hit-tests windows and forwards pointer and key events to
     * Wayland clients. Every one of those happens once per iteration.
     *
     * Measured with Firefox up on one core: `tablet: 9 polls, 0 reports`.
     * NINE iterations of this loop in a whole run -- roughly 0.15 Hz. Input
     * was not broken, it was being SAMPLED once every several seconds, which
     * from the outside is a desktop that ignores the mouse entirely. That is
     * what "i cant click or scroll or anything / or type" was measuring.
     *
     * The cause is ordinary CFS fairness: Firefox runs dozens of threads, all
     * SCHED_OTHER at nice 0, and the window manager is one more runnable task
     * among them. Fair shares are exactly wrong here -- the WM needs LATENCY,
     * not throughput.
     *
     * nice -20 rather than SCHED_FIFO/RR deliberately. The loop ends in
     * idle_hlt(), so it sleeps whenever there is nothing to do and cannot
     * monopolise anything; what the weight buys is being picked PROMPTLY on
     * wake, because a task that has consumed almost no CPU has the smallest
     * vruntime. A real-time class would give the same latency and would also
     * let any future spin in this loop lock the machine out. */
    task_set_nice(-20);

    /* The framebuffer is ours from here. Kernel log lines drawn into it scroll
     * the whole desktop up a row at a time -- see console_gfx_release. (M2011) */
    console_gfx_release();
    screen_w = fb_width();
    screen_h = fb_height();
    backbuffer = kmalloc((size_t)screen_w * screen_h * 4);
    scenebuf   = kmalloc((size_t)screen_w * screen_h * 4);
    fb_set_target(backbuffer);
    load_wallpaper();                    /* WALL.PNG from disk, else the gradient */
    start_y = screen_h - TASKBAR_H + 5;

    /* THE BOOT LAYOUT IS PROPORTIONAL NOW (M1988). It used to be three fixed
     * rectangles sized for a much smaller screen: on 1280x960 they all landed
     * inside the top-left third, overlapping each other -- Files was clipped by
     * the shell and Welcome was half-covered -- while 60% of the desktop sat
     * empty. Placement is derived from the actual framebuffer, in a left
     * column that does not overlap the shell to its right. */
    {
        int m = screen_w / 24;                            /* margin, ~53px at 1280 */
        int colw = screen_w * 30 / 100;                   /* left column width */
        int usable = screen_h - TASKBAR_H - m * 2;
        /* Welcome gets its CONTENT's height, not a percentage of the screen:
         * it is a fixed-layout panel (win_min_size pins it at 360x290), so a
         * proportional height clips its last line on some screens and leaves a
         * gap on others. Files takes whatever is left. */
        int wel_h = 290 + TITLEBAR_H;
        if (wel_h > usable / 2) wel_h = usable / 2;
        windows[win_count++] = (window_t){ m, m, colw, wel_h, THEME_PANEL, "Welcome", KIND_WELCOME, 0, 0,0,0,0,0,0,0, 0,{0},0, 0, {0} };  /* dark slate (M1476) */
        windows[win_count++] = (window_t){ m, m + wel_h + m / 2, colw, usable - wel_h - m / 2,
                                           THEME_PANEL, "Files", KIND_FILES, 0, 0,0,0,0,0,0,0, 0,{0},0, 0, {0} };
    }
    /* SAY IF IT DID NOT START. A missing Shell window is the most visible
     * failure this desktop has and the least explained: app_spawn_named
     * returns -1 and the loop below simply has nothing to give a window to,
     * so the desktop comes up looking deliberate. Twice in a row I typed a
     * command into a desktop with no terminal and the keystrokes went to the
     * file manager, where 'd' deletes and 'n' creates. (M2076) */
    if (app_spawn_named("shell") != 0)
        kprintf("[desktop] the SHELL DID NOT START -- there will be no terminal window\n");

    int dragging = -1, resizing = -1, gdx = 0, gdy = 0;
    int selecting = -1;                  /* window index whose text we're drag-selecting (terminal) */
    int bselecting = -1;                 /* window index whose text we're drag-selecting (browser) */
    int sbdrag = -1;                     /* window index whose terminal scrollbar we're dragging */
    int bsbdrag = -1;                    /* window index whose browser scrollbar we're dragging */
    int prev_btn = 0, prev_x = -1, prev_y = -1;
    uint64_t last_sec = (uint64_t)-1;
    uint64_t last_tb_click = 0; int last_tb_x = -100, last_tb_y = -100;  /* double-click-to-maximize */
    uint64_t last_body_click = 0; int last_body_x = -100, last_body_y = -100;  /* double-click-to-word-select */
    int drag_ox = 0, drag_oy = 0;        /* where a title-bar drag began (move-threshold + restore) */

    render_scene();
    present_frame();
    for (;;) {
        app_stall_watchdog();   /* say when a Linux process has stopped doing anything (M2004) */
        app_net_stall_watch();  /* ...and when a socket has gone quiet with a request outstanding (M2016) */
        int dirty = 0;
        usb_tablet_poll();
        usb_kbd_poll();          /* feed any USB-keyboard keystrokes into the input queue */

        /* give any newly-spawned program a window — but only while there's a free
         * window slot. At the cap, leave the app PENDING (don't drain it) so it isn't
         * dropped-and-leaked; it gets a window once one closes (make_app_window's own
         * cap check stays as a belt-and-braces guard). */
        app_t *na;
        while (win_count < MAX_WINDOWS && (na = app_take_pending())) { make_app_window(na); dirty = 1; }
        { int before = win_count; wl_window_poll(); if (win_count != before) dirty = 1; }
        { int nb = nwlpid_seen; wl_hide_console_for_clients(); if (nwlpid_seen != nb) dirty = 1; }

        /* open browser windows requested by the shell (`browse <url>`) */
        char burl[160];
        while (app_take_browse(burl, sizeof(burl))) { spawn_browser(burl); dirty = 1; }

        /* let any browser finish an async page load (parsed on this thread) */
        for (int i = 0; i < win_count; i++)
            if (windows[i].kind == KIND_BROWSER && windows[i].app) {
                browser_t *b = (browser_t *)windows[i].app;
                if (browser_poll(b)) dirty = 1;
                windows[i].title = browser_title(b);   /* keep title in sync */
            }

        /* repaint promptly when an app produced output (typing, clock, games) */
        for (int i = 0; i < win_count; i++)
            if (windows[i].kind == KIND_APP && windows[i].app) {
                if (app_dirty_clear((app_t *)windows[i].app)) dirty = 1;
                /* a graphics-mode app sizes its window to its canvas (+ borders) */
                uint32_t *cb; int gw, gh;
                if (app_gfx_get((app_t *)windows[i].app, &cb, &gw, &gh)) {
                    int s = gfx_scale(gw, gh), dw = s * gw + 12, dh = s * gh + TITLEBAR_H + 12;
                    if (windows[i].w != dw || windows[i].h != dh) {
                        windows[i].w = dw; windows[i].h = dh;
                        if (windows[i].x + dw > screen_w) windows[i].x = screen_w - dw;
                        if (windows[i].y + dh > screen_h - TASKBAR_H) windows[i].y = screen_h - TASKBAR_H - dh;
                        if (windows[i].x < 0) windows[i].x = 0;
                        if (windows[i].y < 0) windows[i].y = 0;
                        dirty = 1;
                    }
                }
            }

        /* raw make/break key events -> the focused app, if it opted into raw mode
         * (games like DOOM). Always drained so they never accumulate; delivered
         * only to a focused raw-mode app, else discarded. */
        {
            int ev;
            while ((ev = input_pop_raw()) >= 0) {
                /* Recomputed PER EVENT, not once before the loop (M1926). The
                 * chords below raise, move and close windows, so a `top` captured
                 * up front goes stale mid-drain -- and since it is
                 * `&windows[win_count-1]` it then names a DIFFERENT window while
                 * `rawmode` still says "this is a raw-keyboard app". That handed
                 * app_key_raw() a browser_t* cast to app_t*: a type-confused write
                 * into another window's memory. */
                window_t *top = (win_count > 0) ? &windows[win_count - 1] : 0;
                int rawmode = top && !top->minimized && top->kind == KIND_APP &&
                              top->app && app_get_rawkb((app_t *)top->app);
                int code = ev & 0x7F, rel = (ev & 0x100) != 0;
                /* Track the modifiers but STILL forward them: a raw-mode app
                 * (DOOM) uses Alt and Shift itself. Only the Tab of an actual
                 * Alt+Tab is swallowed. */
                if (code == 0x38)                    alt_down   = !rel;   /* Alt (either side; 0x200 = right) */
                else if (code == 0x2A || code == 0x36) shift_down = !rel; /* Shift */
                else if (code == 0x1D)                 ctrl_down  = !rel; /* Ctrl  */

                /* Ctrl+Alt+Left/Right: previous/next workspace (the Linux chord).
                 * Super+1..4 jumps straight to one. (M1923) */
                /* Super+Shift+1..4 / Ctrl+Alt+Shift+Left/Right: MOVE the window
                 * there (M1924). Checked before the plain switch chords below, so
                 * Shift takes precedence rather than being ignored. */
                if (shift_down && !rel &&
                    ((ctrl_down && alt_down && (code == 0x4B || code == 0x4D)) ||
                     (super_down && code >= 0x02 && code <= 0x02 + WS_N - 1))) {
                    int to;
                    if (super_down && code >= 0x02 && code <= 0x02 + WS_N - 1) {
                        super_used = 1;
                        to = code - 0x02;
                    } else {
                        to = (code == 0x4B) ? (cur_ws + WS_N - 1) % WS_N : (cur_ws + 1) % WS_N;
                    }
                    move_focused_to_ws(to);
                    close_overlays();
                    dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1;
                    dirty = 1;
                    continue;
                }
                if (ctrl_down && alt_down && !rel && (code == 0x4B || code == 0x4D)) {
                    int to = (code == 0x4B) ? (cur_ws + WS_N - 1) % WS_N : (cur_ws + 1) % WS_N;
                    switch_ws(to);
                    close_overlays();
                    dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1;
                    dirty = 1;
                    continue;
                }
                if (super_down && !rel && code >= 0x02 && code <= 0x02 + WS_N - 1) {  /* 1..4 */
                    super_used = 1;
                    switch_ws(code - 0x02);
                    close_overlays();
                    dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1;
                    dirty = 1;
                    continue;
                }

                if (code == 0x0F && !rel && alt_down) {       /* Alt+Tab / Alt+Shift+Tab */
                    if (win_count > 1) {
                        if (!sw_open) {                        /* open it and step off the current window */
                            close_overlays();                  /* one overlay at a time */
                            sw_open = 1; sw_alt = 1;
                            sw_sel = win_count - 1;
                        }
                        sw_sel = shift_down ? (sw_sel + 1) % win_count
                                            : (sw_sel + win_count - 1) % win_count;
                        dirty = 1;
                    }
                    continue;                                  /* never let Tab reach the app */
                }
                if (code == 0x3E && !rel && alt_down) {        /* Alt+F4: close the window (M1921) */
                    if (ctx_open) ctx_open = 0;   /* a window vanishes: ctx_win would go stale (M1926) */
                    if (close_focused_window()) {
                        dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1;
                        dirty = 1;
                    }
                    continue;
                }
                if (code == 0x5B) {                           /* Super/Windows key (M1921/M1922) */
                    if (!rel) { super_down = 1; super_used = 0; }
                    else {
                        super_down = 0;
                        /* Fire on RELEASE, and only if Super was not used as a
                         * modifier -- otherwise Super+Left would snap AND leave the
                         * launcher open on top of it. This is also what Windows and
                         * GNOME do: the launcher opens on the tap, not the press. */
                        if (!super_used) {
                            int o = menu_open; close_overlays(); menu_open = !o; menu_sel = 0;
                            dirty = 1;
                        }
                    }
                    continue;
                }
                /* Super + arrows: the window-management chords everyone arrives with
                 * (M1922). Snapping and maximizing already existed on F4/F5/F6; these
                 * are the gestures people actually try. Arrows are E0-prefixed, but
                 * `code` masks the extended flag off so both encodings match. */
                if (super_down && !rel &&
                    (code == 0x4B || code == 0x4D || code == 0x48 || code == 0x50)) {
                    super_used = 1;
                    if (win_count > 0) {
                        int fi = win_count - 1;
                        if (code == 0x4B)      snap_window(fi, 0);        /* Left  */
                        else if (code == 0x4D) snap_window(fi, 1);        /* Right */
                        else if (code == 0x48) toggle_maximize(fi);       /* Up    */
                        else {                                            /* Down: minimize */
                            int vis = 0;
                            for (int i = 0; i < win_count; i++) if (!windows[i].minimized) vis++;
                            if (vis > 1) { windows[fi].minimized = 1; sink_window(fi); }
                        }
                        dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1;
                        dirty = 1;
                    }
                    continue;
                }
                if (code == 0x38 && rel && sw_open && sw_alt) {  /* Alt released: commit */
                    /* Clamp (M1926): the reap loop removes windows every frame and
                     * the switcher stays open across frames while Alt is held, so
                     * an app exiting meanwhile can leave sw_sel past the end.
                     * Raising an out-of-range index copies a stale slot over the
                     * focused window -> a duplicate pointing at a freed app_t. */
                    if (sw_sel >= win_count) sw_sel = win_count - 1;
                    if (sw_sel < 0) { sw_open = sw_alt = 0; continue; }
                    raise_window(sw_sel);
                    dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1;
                    sw_open = sw_alt = 0;
                    dirty = 1;
                    continue;                    /* do NOT fall through: `top` just changed */
                }
                if (rawmode) app_key_raw((app_t *)top->app, (unsigned short)ev);
            }
        }

        /* Cooked keys AFTER the raw drain (M1926). The cooked layer carries no
         * modifier state, so the only way it can know a key was already consumed
         * as a chord is for the raw pass to have run first and set the modifier
         * flags for THIS frame. With the old order the guards below tested
         * modifiers that had not been updated yet. */
        int k;
        while ((k = input_trygetchar()) >= 0) {
            if (ctx_open) {                     /* context menu (either kind) is modal: Esc closes it, swallow */
                if (k == 27) { ctx_open = 0; dirty = 1; }   /* the rest so no F-key reorders under it */
                continue;
            }
            /* Every chord the raw pass consumed ALSO arrives here as an ordinary
             * key and would fire a second, different action: Alt+F4 delivers
             * cooked F4 and would MAXIMIZE the window before the raw pass closed
             * it; Super+1..4 would type "1".."4" into the focused app; Super /
             * Ctrl+Alt arrows would scroll or move a cursor. M1920 handled only
             * Tab; this covers the rest. (M1926) */
            if (alt_down && (k == '\t' || k == 0x9B || k == 0x0F)) continue;  /* Alt+Tab / Alt+Shift+Tab / Alt+F4 */
            if (super_down && k >= '1' && k <= '9') continue;                   /* Super+N */
            if ((super_down || (ctrl_down && alt_down)) && k >= 0x11 && k <= 0x14) continue;  /* arrows */
            if (k == 0x1D) {                    /* F1: toggle the keyboard-shortcut help overlay */
                int o = help_open; close_overlays(); help_open = !o; dirty = 1;   /* one overlay at a time */
                continue;
            }
            if (help_open) {                    /* help overlay has focus: Esc/F1 close, swallow the rest */
                if (k == 27) { help_open = 0; dirty = 1; }
                continue;
            }
            if (k == 0x1E) {                    /* F7: toggle the Alt-Tab window switcher overlay */
                int o = sw_open; close_overlays(); sw_open = !o;          /* one overlay at a time */
                sw_alt = 0;                                               /* F7-opened: Enter commits, not Alt-release */
                if (sw_open) sw_sel = win_count - 1;                      /* start on the focused (topmost) window */
                dirty = 1;
                continue;
            }
            if (sw_open) {                      /* switcher has keyboard focus while open */
                if (win_count > 0) {
                    if (k == 0x11 || k == 0x13)      sw_sel = (sw_sel + win_count - 1) % win_count;   /* up/left -> prev */
                    else if (k == 0x12 || k == 0x14) sw_sel = (sw_sel + 1) % win_count;               /* down/right -> next */
                    else if (k == '\n' || k == '\r') {                    /* Enter: raise + restore it */
                        raise_window(sw_sel);
                        dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1;   /* the array reordered: drop any active gesture */
                        sw_open = 0;
                    }
                    else if (k == 27) sw_open = 0;                        /* Esc: cancel */
                } else sw_open = 0;             /* nothing to switch to */
                dirty = 1;
                continue;                       /* swallow all keys while the switcher is up */
            }
            if (k == 0x19) {                    /* F9: toggle the Apps menu (keyboard) */
                int o = menu_open; close_overlays(); menu_open = !o; menu_sel = 0; dirty = 1;   /* one overlay at a time */
                continue;
            }
            if (menu_open) {                    /* menu has keyboard focus while open */
                if (k == 0x11) { menu_sel = (menu_sel + MENU_N - 1) % MENU_N; dirty = 1; }      /* up */
                else if (k == 0x12) { menu_sel = (menu_sel + 1) % MENU_N; dirty = 1; }          /* down */
                else if (k == 0x13) { menu_sel = (menu_sel + MENU_N - MENU_PERCOL) % MENU_N; dirty = 1; } /* left col */
                else if (k == 0x14) { menu_sel = (menu_sel + MENU_PERCOL) % MENU_N; dirty = 1; }          /* right col */
                else if (k == '\n' || k == '\r') { int s = menu_sel; menu_open = 0; dirty = 1;
                                                   spawn_app(menu[s].kind, menu[s].prog); }
                else if (k == 27) { menu_open = 0; dirty = 1; }                                 /* Esc */
                else if ((k >= 'a' && k <= 'z') || (k >= 'A' && k <= 'Z') || (k >= '0' && k <= '9')) {
                    /* type-to-jump: hop to the next menu item whose label starts with this
                     * letter (wrapping), so a 34-entry menu is fast from the keyboard. */
                    int c = lc_ascii(k);
                    for (int n = 1; n <= MENU_N; n++) {
                        int j = (menu_sel + n) % MENU_N;
                        if (lc_ascii(menu[j].label[0]) == c) { menu_sel = j; dirty = 1; break; }
                    }
                }
                continue;                       /* swallow all keys while the menu is up */
            }
            if (k == 0x0E) {                    /* F2: cycle focus to the next window */
                if (win_count > 1) { raise_window(0); dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1; dirty = 1; }
                continue;
            }
            if (k == 0x0F) {                    /* F4: maximize/restore focused window */
                if (win_count > 0) { toggle_maximize(win_count - 1); dirty = 1; }
                continue;
            }
            if (k == 0x18) {                    /* F3: minimize the focused window to its chip */
                int vis = 0;                    /* never hide the LAST visible window */
                for (int i = 0; i < win_count; i++) if (!windows[i].minimized) vis++;
                if (vis > 1) {
                    windows[win_count - 1].minimized = 1;
                    sink_window(win_count - 1); /* focus falls to the window below; F2 or */
                    dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1;   /* the array reordered: drop any active gesture */
                    dirty = 1;                  /* its taskbar chip restores it (raise_window) */
                }
                continue;
            }
            if (k == 0x10 || k == 0x17) {       /* F5/F6: snap focused window left/right */
                if (win_count > 0) { snap_window(win_count - 1, k == 0x17); dirty = 1; }
                continue;
            }
            if (k == 0x1A) {                    /* F8: close the focused window */
                if (close_focused_window()) {
                    dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1; dirty = 1;
                }
                continue;
            }
            if (k == 0x1C) {                    /* F12: screenshot to SHOT0.PNG, SHOT1.PNG, ... */
                static int shot_n;              /* auto-incrementing so a shot never overwrites the last */
                char name[16]; int q = 0;
                name[q++]='S'; name[q++]='H'; name[q++]='O'; name[q++]='T';
                int n = shot_n;
                if (n >= 100) name[q++] = (char)('0' + (n/100)%10);
                if (n >= 10)  name[q++] = (char)('0' + (n/10)%10);
                name[q++] = (char)('0' + n%10);
                name[q++]='.'; name[q++]='P'; name[q++]='N'; name[q++]='G'; name[q]=0;
                if (fb_save_png(name) == 0) { beep(1800, 30); if (shot_n < 999) shot_n++; }   /* PNG: ~9 KB vs ~576 KB BMP */
                continue;
            }
            /* THE TOPMOST WINDOW MAY BE MINIMIZED, AND THEN THE KEY WAS
             * SWALLOWED (M2243). Minimizing a window does not remove it from
             * `windows[]`, so windows[win_count-1] can be a hidden console --
             * and this used to answer "no visible focused window" and drop the
             * keystroke, with a perfectly good browser visible underneath it.
             * Focus belongs to the topmost window the user can actually SEE. */
            g_dk_keys++;
            int fi = focus_index();
            g_dk_focus_kind = (fi >= 0) ? (int)windows[fi].kind : -1;
            if (fi >= 0) {
                window_t *top = &windows[fi];
                if (top->kind == KIND_APP && top->app) { app_sel_clear((app_t *)top->app); app_key((app_t *)top->app, (char)k); dirty = 1; }
                else if (top->kind == KIND_BROWSER && top->app) { browser_key((browser_t *)top->app, k); dirty = 1; }
                else if (top->kind == KIND_FILES) { files_key(top, k); dirty = 1; }
                else if (top->kind == KIND_WAYLAND) {
                    /* Forward to the Wayland client, as a KEY PRESS AND
                     * RELEASE. The desktop's cooked layer gives us a character,
                     * not a make/break pair, and a client that only ever sees
                     * presses treats every key as held down forever. The value
                     * is an evdev keycode, which is what the protocol carries
                     * -- not the character. (M1983) */
                    g_dk_fwd++;
                    int nsh = 0;
                    unsigned ev = desktop_key_to_evdev_shift(k, &nsh);
                    if (!ev) {
                        /* AN UNMAPPED KEY MUST NOT BE SILENT (M2244). Sending
                         * keycode 0 is indistinguishable, from the client's
                         * side, from sending nothing -- and that is exactly
                         * how `/` went missing without a trace. */
                        static int moaned;
                        if (moaned < 8) { moaned++;
                            kprintf("[desktop] key %d has no evdev mapping -- NOT forwarded\n", k); }
                    } else {
                        if (nsh) wl_post_key(EV_LEFTSHIFT, 1);
                        wl_post_key(ev, 1);
                        wl_post_key(ev, 0);
                        if (nsh) wl_post_key(EV_LEFTSHIFT, 0);
                    }
                }
            }
        }


        int mx = mouse_x(), my = mouse_y(), btn = mouse_buttons(), left = btn & 1;

        /* feed the focused graphics app its cursor position (canvas-relative,
         * undoing the integer upscale) + buttons, plus relative motion for
         * mouselook, so apps (and games like DOOM) can use the mouse */
        int rdx, rdy; mouse_read_rel(&rdx, &rdy);   /* always drain so it can't pile up */
        int fmi = focus_index();
        if (fmi >= 0) {
            window_t *fw = &windows[fmi];
            uint32_t *cb; int gw, gh;
            if (!fw->minimized && fw->kind == KIND_APP && fw->app &&
                app_gfx_get((app_t *)fw->app, &cb, &gw, &gh)) {
                int s = gfx_scale(gw, gh);
                int rx = (mx - (fw->x + 6)) / s, ry = (my - (fw->y + TITLEBAR_H + 6)) / s;
                if (rx < 0 || ry < 0 || rx >= gw || ry >= gh) { rx = -1; ry = -1; }
                app_set_mouse((app_t *)fw->app, rx, ry, btn);
                app_add_mouse_rel((app_t *)fw->app, rdx, rdy);
            }
            /* A focused Wayland window gets the pointer, in SURFACE-relative
             * coordinates -- the client knows nothing about where its window
             * sits on our desktop, and sending screen coordinates would put
             * every click in the wrong place. Motion is only forwarded when it
             * CHANGES: a Wayland client redraws on motion, and re-sending the
             * same position every frame would keep it busy forever. (M1983) */
            if (!fw->minimized && fw->kind == KIND_WAYLAND) {
                int sw3 = fw->w - 14, sh3 = fw->h - TITLEBAR_H - 14;
                int rx = mx - (fw->x + 6), ry = my - (fw->y + TITLEBAR_H + 6);
                /* HIT-TEST against the surface, not just the window: pointer
                 * focus in Wayland follows the cursor, so a client outside
                 * whose bounds the cursor sits must get a leave() and no
                 * motion. Forwarding out-of-bounds coordinates is worse than
                 * useless -- the client happily acts on a click it should
                 * never have seen. */
                if (rx >= 0 && ry >= 0 && rx < sw3 && ry < sh3) {
                    if (mx != prev_x || my != prev_y) wl_post_motion(rx, ry);
                    if ((btn & 1) != (prev_btn & 1)) wl_post_button(rx, ry, 0x110, btn & 1);   /* BTN_LEFT */
                    if ((btn & 2) != (prev_btn & 2)) wl_post_button(rx, ry, 0x111, (btn & 2) ? 1 : 0);  /* BTN_RIGHT */
                } else if (mx != prev_x || my != prev_y) {
                    wl_post_pointer_leave();
                }
            }
        }

        /* Mouse wheel: scroll the topmost non-minimized window under the cursor.
         * wheel > 0 = rolled up (show content above); reused for the browser's
         * arrow-scroll and a text app's PgUp/PgDn scrollback. */
        int wheel = mouse_read_wheel();
        if (wheel && !menu_open && !help_open) {   /* drain the wheel always, but the Apps menu / help overlay is modal: don't scroll a window behind it */
            int up = wheel > 0, ticks = up ? wheel : -wheel;
            if (ticks > 8) ticks = 8;                    /* clamp a violent spin */
            for (int i = win_count - 1; i >= 0; i--) {
                window_t *w = &windows[i];
                if (w->minimized || !in_rect(mx, my, w->x, w->y, w->w, w->h)) continue;
                if (w->kind == KIND_WAYLAND) {
                    /* Surface-relative, like every other pointer event (M2245). */
                    int rx = mx - (w->x + 6), ry = my - (w->y + TITLEBAR_H + 6);
                    if (rx < 0) rx = 0;
                    if (ry < 0) ry = 0;
                    wl_post_axis(rx, ry, up ? -ticks : ticks);
                } else if (w->kind == KIND_BROWSER && w->app) {
                    for (int t = 0; t < ticks * 3; t++) browser_key((browser_t *)w->app, up ? 0x11 : 0x12);
                    dirty = 1;
                } else if (w->kind == KIND_APP && w->app) {
                    uint32_t *cb; int gw, gh;             /* text apps only (skip gfx canvases) */
                    if (!app_gfx_get((app_t *)w->app, &cb, &gw, &gh)) {
                        if (app_caret_hidden((app_t *)w->app))   /* editor etc.: scroll its own view a few lines */
                            for (int t = 0; t < ticks * 3; t++) app_key((app_t *)w->app, up ? 0x11 : 0x12);
                        else                                     /* terminal: PgUp/PgDn into the scrollback */
                            for (int t = 0; t < ticks; t++) app_key((app_t *)w->app, up ? 0x15 : 0x16);
                        dirty = 1;
                    }
                }
                break;                                   /* only the topmost window the cursor is over */
            }
        }

        /* Middle-click: paste the clipboard into the text app under the cursor
         * (X11 primary-selection style — no focus change needed). */
        if ((btn & 4) && !(prev_btn & 4)) {
            for (int i = win_count - 1; i >= 0; i--) {
                window_t *w = &windows[i];
                if (w->minimized || !in_rect(mx, my, w->x, w->y, w->w, w->h)) continue;
                if (w->kind == KIND_APP && w->app) {
                    uint32_t *cb; int gw, gh;
                    if (!app_gfx_get((app_t *)w->app, &cb, &gw, &gh)) { app_paste((app_t *)w->app); dirty = 1; }
                } else if (w->kind == KIND_BROWSER && w->app) {
                    char cbuf[512]; int n = clip_get(cbuf, sizeof cbuf);
                    browser_t *bp = (browser_t *)w->app;
                    raise_window(i);                     /* focus it so Enter submits after the paste */
                    dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1;   /* array reordered -> drop any in-flight gesture, like every other raise_window site (M1754) */
                    if (n > 0) browser_paste(bp, cbuf, n);
                    dirty = 1;
                }
                break;
            }
        }

        /* Right-click: a window's TITLE BAR opens the window context menu (Maximize/
         * Restore, Minimize, Snap Left/Right, Close); browser CONTENT still copies a
         * link's URL; the EMPTY desktop (no window under the cursor) opens the
         * desktop-background menu (Show Desktop / Show All Windows / Change
         * Wallpaper). A right-click while any menu is open just dismisses it. */
        if ((btn & 2) && !(prev_btn & 2)) {
            if (ctx_open || menu_open || help_open || sw_open) {
                close_overlays(); dirty = 1;             /* a right-click dismisses any open overlay, no new menu */
            } else {
                int hit = 0;                             /* did the click land on a (visible) window? */
                for (int i = win_count - 1; i >= 0; i--) {
                    window_t *w = &windows[i];
                    if (w->minimized || !in_rect(mx, my, w->x, w->y, w->w, w->h)) continue;
                    hit = 1;
                    if (my < w->y + TITLEBAR_H) {        /* on the title bar -> open the window menu (ctx_kind 0) */
                        raise_window(i);                 /* normal title interaction: focus it first */
                        dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1;   /* array reordered */
                        ctx_kind = 0;
                        ctx_win = win_count - 1;          /* now topmost; the menu always targets the top window */
                        int ch = ctx_nrows() * CTX_ROW_H + 4, cw = ctx_w();
                        ctx_x = mx; if (ctx_x > screen_w - cw) ctx_x = screen_w - cw; if (ctx_x < 0) ctx_x = 0;
                        ctx_y = my; if (ctx_y > screen_h - TASKBAR_H - ch) ctx_y = screen_h - TASKBAR_H - ch; if (ctx_y < 0) ctx_y = 0;
                        ctx_open = 1; dirty = 1;
                    } else if (w->kind == KIND_BROWSER && w->app) {   /* browser content: copy a link's URL */
                        char lb[1024];
                        int n = browser_rclick((browser_t *)w->app, mx - w->x, my - (w->y + TITLEBAR_H), lb, sizeof lb);
                        if (n > 0) { clip_set(lb, n); dirty = 1; }
                    }
                    break;
                }
                /* fell through the loop with no window under the cursor -> desktop
                 * menu (only when over the desktop proper, not the taskbar) */
                if (!hit && my < screen_h - TASKBAR_H) {
                    ctx_kind = 1; ctx_win = -1;
                    int ch = ctx_nrows() * CTX_ROW_H + 4, cw = ctx_w();
                    ctx_x = mx; if (ctx_x > screen_w - cw) ctx_x = screen_w - cw; if (ctx_x < 0) ctx_x = 0;
                    ctx_y = my; if (ctx_y > screen_h - TASKBAR_H - ch) ctx_y = screen_h - TASKBAR_H - ch; if (ctx_y < 0) ctx_y = 0;
                    ctx_open = 1; dirty = 1;
                }
            }
        }

        if (left && !(prev_btn & 1) && help_open) {
            help_open = 0; dirty = 1;        /* the help overlay is modal: a click anywhere dismisses it */
        } else if (left && !(prev_btn & 1) && ctx_open) {
            /* the context menu is modal: a click on a row runs that action, a click
             * anywhere else just dismisses it. Either way the window beneath is NOT
             * actioned. Close the menu BEFORE acting (so Close/minimize can't act on
             * a stale popup). The window kind re-validates ctx_win (a window may have
             * been reaped since the menu opened) so a stale index is never used; the
             * desktop kind has no window dependency. */
            int row = ctx_row_at(mx, my), kind = ctx_kind, win = ctx_win;
            ctx_open = 0; dirty = 1;
            if (row >= 0) {
                int reordered = 0;
                if (kind == 1)                  /* desktop-background menu */
                    reordered = ctx_desktop_action(row);
                else if (win >= 0 && win < win_count)   /* window menu */
                    reordered = ctx_action(win, row);
                if (reordered)                  /* reordered/removed the array: drop any active gesture */
                    dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1;
            }
        } else if (left && !(prev_btn & 1)) {
            int ty = screen_h - TASKBAR_H, mh = MENU_PERCOL*MENU_ITEM_H + 4;
            int mw = MENU_COLS*MENU_W, my0 = ty - mh;
            if (menu_open) {
                if (in_rect(mx, my, start_x, my0, mw, mh)) {
                    int col = (mx - start_x) / MENU_W, row = (my - (my0 + 4)) / MENU_ITEM_H;
                    int idx = col * MENU_PERCOL + row;
                    if (col >= 0 && col < MENU_COLS && row >= 0 && idx >= 0 && idx < MENU_N)
                        spawn_app(menu[idx].kind, menu[idx].prog);
                }
                menu_open = 0; dirty = 1;
            } else if (in_rect(mx, my, start_x, start_y, start_w, start_h)) {
                menu_open = 1; menu_sel = 0; dirty = 1;  /* reset kbd highlight to top */
            } else if (my >= start_y) {                 /* the taskbar row */
                int clkx = screen_w - clk_pill_w() - 8;
                if (mx >= clkx) {                        /* clicking the clock opens the Calendar */
                    spawn_app(KIND_APP, "calendar"); dirty = 1;
                } else for (int i = 0; i < win_count; i++) {     /* else a window chip? */
                    int cx = TB_CHIPX0 + i * (TB_CHIPW + TB_CHIPGAP);
                    if (cx + TB_CHIPW > chips_right_bound()) break;   /* SAME bound as the draw (M1926) */
                    if (mx >= cx && mx < cx + TB_CHIPW) { raise_window(i); dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1; dirty = 1; break; }
                }
            } else {
                for (int i = win_count - 1; i >= 0; i--) {
                    window_t *w = &windows[i];
                    if (w->minimized) continue;                 /* hidden: not clickable */
                    if (!in_rect(mx, my, w->x, w->y, w->w, w->h)) continue;
                    if (in_rect(mx, my, w->x + w->w - 21, w->y + 6, 14, 14)) {   /* matches the drawn close-button rect exactly (draw_window) */
                        if (w->kind == KIND_APP && w->app)
                            app_request_kill((app_t *)w->app);  /* app self-exits; reap loop drops the window */
                        else
                            remove_window(i);                   /* browser/files/etc: drop immediately */
                    } else if (in_rect(mx, my, w->x + w->w - GRIP, w->y + w->h - GRIP, GRIP, GRIP)) {
                        raise_window(i); resizing = win_count - 1;
                    } else {
                        raise_window(i);
                        window_t *t = &windows[win_count - 1];
                        if (my < t->y + TITLEBAR_H) {
                            /* a second title-bar click within ~0.4s near the first =
                             * double-click -> maximize/restore (the F4 toggle). Otherwise
                             * begin a move drag and arm the double-click timer. */
                            uint64_t now = timer_ticks();
                            int near = (mx - last_tb_x < 8 && last_tb_x - mx < 8 &&
                                        my - last_tb_y < 8 && last_tb_y - my < 8);
                            if (now - last_tb_click < 40 && near) {
                                toggle_maximize(win_count - 1);
                                last_tb_click = 0;            /* consume: a 3rd click starts fresh */
                            } else {
                                dragging = win_count - 1; gdx = mx - t->x; gdy = my - t->y;
                                drag_ox = mx; drag_oy = my;
                                last_tb_click = now; last_tb_x = mx; last_tb_y = my;
                            }
                        }
                        else if (t->kind == KIND_BROWSER && t->app) {
                            int rbx = mx - t->x, rby = my - (t->y + TITLEBAR_H);
                            uint64_t now = timer_ticks();
                            int near = (mx - last_body_x < 8 && last_body_x - mx < 8 &&
                                        my - last_body_y < 8 && last_body_y - my < 8);
                            if (now - last_body_click < 40 && near) {     /* double-click: select the word */
                                char wb[256];
                                int n = browser_sel_word((browser_t *)t->app, rbx, rby, wb, sizeof wb);
                                if (n > 0) clip_set(wb, n);
                                last_body_click = 0;
                            } else if (browser_in_scrollbar((browser_t *)t->app, rbx, rby, t->w, t->h - TITLEBAR_H)) {
                                browser_scroll_track((browser_t *)t->app, rby, t->h - TITLEBAR_H);
                                bsbdrag = win_count - 1;
                            } else {
                                last_body_click = now; last_body_x = mx; last_body_y = my;
                                if (!browser_click((browser_t *)t->app, rbx, rby, t->w, t->h - TITLEBAR_H)) {
                                    browser_sel_begin((browser_t *)t->app, rbx, rby);   /* plain content: start text selection */
                                    bselecting = win_count - 1;
                                }
                            }
                        }
                        else if (t->kind == KIND_FILES)
                            files_click(t, my);          /* click a file row -> select + open it */
                        else if (t->kind == KIND_APP && t->app) {
                            uint32_t *cb; int gw, gh;    /* text app: scrollbar / word-select / drag-select */
                            if (!app_gfx_get((app_t *)t->app, &cb, &gw, &gh)) {
                                int px = t->x + 6, py = t->y + TITLEBAR_H + 6;
                                int sbx = px + app_grid_cols((app_t *)t->app) * font_width + 1, trackh = app_grid_rows((app_t *)t->app) * font_height;
                                if (mx >= sbx - 4 && mx <= sbx + 6 && my >= py && my < py + trackh) {
                                    app_scroll_frac((app_t *)t->app, my - py, trackh);   /* click the scrollbar */
                                    sbdrag = win_count - 1;
                                    dirty = 1; break;
                                }
                                int row = (my - py) / font_height, col = (mx - px) / font_width;
                                uint64_t now = timer_ticks();
                                int near = (mx - last_body_x < 8 && last_body_x - mx < 8 &&
                                            my - last_body_y < 8 && last_body_y - my < 8);
                                if (now - last_body_click < 40 && near) {     /* double-click: select the word */
                                    app_sel_word((app_t *)t->app, row, col);
                                    selecting = -1; last_body_click = 0;
                                } else {                                      /* single: begin a drag-selection */
                                    app_sel_begin((app_t *)t->app, row, col);
                                    selecting = win_count - 1;
                                    last_body_click = now; last_body_x = mx; last_body_y = my;
                                }
                            }
                        }
                    }
                    dirty = 1; break;
                }
            }
        } else if (!left && (prev_btn & 1)) {
            /* The mouse button was just RELEASED (edge, not level: this must not
             * fire on every idle frame just because the button happens to be up —
             * profiling found that bug alone forced a full-scene redraw on
             * ~every single main-loop iteration, all the time, even at complete
             * idle with no window open at all).
             * aero-snap: release a dragged window against a screen edge to tile it
             * (top -> maximize, left/right -> that half). Only when it actually
             * moved (drag_ox/oy set on press) so a plain click never snaps. */
            if (dragging >= 0) {
                int moved = (mx - drag_ox > 3 || drag_ox - mx > 3 ||
                             my - drag_oy > 3 || drag_oy - my > 3);
                if (moved) {
                    /* Same zone test the live preview used, so what you saw is
                     * what you get (M1892). */
                    switch (snap_zone_at(mx, my)) {
                        case SNAP_MAX:   if (!windows[dragging].maximized) toggle_maximize(dragging); break;
                        case SNAP_LEFT:  snap_window(dragging, 0); break;
                        case SNAP_RIGHT: snap_window(dragging, 1); break;
                        default: break;
                    }
                }
            }
            if (snap_hint != SNAP_NONE) { snap_hint = SNAP_NONE; dirty = 1; }   /* drop the preview */
            if (selecting >= 0) {                  /* finished a terminal text drag-selection: copy it */
                app_sel_commit((app_t *)windows[selecting].app); selecting = -1; dirty = 1;
            }
            if (bselecting >= 0) {                 /* finished a browser text drag-selection: copy it */
                char sbuf[2048];
                int n = browser_sel_commit((browser_t *)windows[bselecting].app, sbuf, sizeof sbuf);
                if (n > 0) clip_set(sbuf, n);
                bselecting = -1; dirty = 1;
            }
            dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1; sbdrag = -1; bsbdrag = -1; dirty = 1;
        }

        if (sbdrag >= 0 && left) {                 /* dragging the terminal scrollbar */
            window_t *w = &windows[sbdrag];
            int py = w->y + TITLEBAR_H + 6, trackh = app_grid_rows((app_t *)w->app) * font_height;
            app_scroll_frac((app_t *)w->app, my - py, trackh);
            dirty = 1;
        }
        if (bsbdrag >= 0 && left) {                 /* dragging the browser scrollbar */
            window_t *w = &windows[bsbdrag];
            browser_scroll_track((browser_t *)w->app, my - (w->y + TITLEBAR_H), w->h - TITLEBAR_H);
            dirty = 1;
        }
        if (selecting >= 0 && left) {              /* dragging a terminal text selection: extend it */
            window_t *w = &windows[selecting];
            int px = w->x + 6, py = w->y + TITLEBAR_H + 6;
            app_sel_extend((app_t *)w->app, (my - py) / font_height, (mx - px) / font_width);
            dirty = 1;
        }
        if (bselecting >= 0 && left) {             /* dragging a browser text selection: extend it */
            window_t *w = &windows[bselecting];
            browser_sel_extend((browser_t *)w->app, mx - w->x, my - (w->y + TITLEBAR_H));
            dirty = 1;
        }
        if (dragging >= 0 && left) {
            /* Only treat it as a move once the cursor actually leaves the press
             * point (a few px). A bare click on the title bar then does NOT move
             * or un-maximize the window -- which is what lets a double-click
             * maximize/restore land cleanly, and matches normal DE behavior. */
            int moved = (mx - drag_ox > 3 || drag_ox - mx > 3 ||
                         my - drag_oy > 3 || drag_oy - my > 3);
            if (moved) {
                window_t *w = &windows[dragging];
                if (w->maximized) {                   /* dragging a maximized window restores its */
                    toggle_maximize(dragging);        /* pre-max size, then re-grabs at the title  */
                    gdx = w->w / 2; gdy = TITLEBAR_H / 2; /* center so it follows the cursor */
                }
                w->x = mx - gdx; w->y = my - gdy;
                if (w->y < 0) w->y = 0;                                                       /* keep the title bar on-screen at the top */
                else if (w->y > screen_h - TASKBAR_H - TITLEBAR_H) w->y = screen_h - TASKBAR_H - TITLEBAR_H;   /* and above the taskbar (else it hides behind it -> mouse-unreachable) */

                /* Live snap preview (M1892): show where a release right now would
                 * land the window. Only redraw when the zone actually CHANGES —
                 * the drag already marks the scene dirty every frame it moves, and
                 * an unconditional dirty=1 here would be the same level-vs-edge
                 * mistake that once forced a full redraw at idle. */
                int z = snap_zone_at(mx, my);
                if (z != snap_hint) { snap_hint = z; dirty = 1; }
            }
        }
        /* Safety net: if a drag ended by any route other than the button-release
         * path above (the window was closed, the array reordered under us), make
         * sure the preview does not linger. Fires at most once per drag because it
         * clears the flag it tests, so it is not the level-check redraw trap. */
        if (dragging < 0 && snap_hint != SNAP_NONE) { snap_hint = SNAP_NONE; dirty = 1; }

        if (resizing >= 0 && left) {
            window_t *w = &windows[resizing];
            int mw, mh; win_min(w, &mw, &mh);
            int nw = mx - w->x, nh = my - w->y;
            w->w = nw < mw ? mw : nw; w->h = nh < mh ? mh : nh;
            w->maximized = 0;                         /* a manual resize un-maximizes */
        }

        /* reap windows whose app has exited: free the app's task/stack/slot
         * (only once its task is fully off-CPU), then drop the window. If it
         * exited but isn't off-CPU yet, app_reap returns 0 — leave the window
         * for the next pass so we never drop it without reclaiming the slot. */
        for (int i = win_count - 1; i >= 0; i--)
            if (windows[i].kind == KIND_APP && !app_alive((app_t *)windows[i].app)) {
                if (!app_reap((app_t *)windows[i].app)) continue;
                remove_window(i); dirty = 1;
                dragging = resizing = selecting = bselecting = sbdrag = bsbdrag = -1;             /* the array shifted: drop any active gesture */
                if (ctx_open) ctx_open = 0;     /* a window vanished: close the menu so ctx_win can't go stale */
                if (sw_open && sw_sel >= win_count) sw_sel = win_count - 1;   /* ...and the switcher's index (M1926) */
            }

        /* ...and reap exited processes that own NO window (M2025). The loop
         * above can only see processes that got one, and the pending queue
         * deliberately STOPS handing them out at MAX_WINDOWS. A fork()ed child
         * parked in that queue was therefore never reaped, never became a
         * waitpid()-collectable zombie, and hung its parent in wait4() forever
         * -- a deadlock, because the slot it was waiting for could only be
         * freed by reaping, and the window that would have to close belonged to
         * the parent that was stuck. Nothing else here needs a window either:
         * app_reap frees the task, the address space and the slot. */
        for (int i = 0; i < app_slot_max(); i++) {
            app_t *a = app_exited_slot(i);
            if (!a) continue;
            int owned = 0;
            for (int w = 0; w < win_count && !owned; w++)
                if (windows[w].kind == KIND_APP && (app_t *)windows[w].app == a) owned = 1;
            if (!owned && app_reap(a)) dirty = 1;
        }

        uint64_t sec = timer_ticks() / timer_hz();
        int clock_tick = (sec != last_sec);
        if (clock_tick) last_sec = sec;
        if (wallpaper_repaint) { wallpaper_repaint = 0; dirty = 1; }   /* `wallpaper` builtin swapped the bg */
        int moved = (mx != prev_x || my != prev_y || btn != prev_btn);
        if (moved && (dragging >= 0 || resizing >= 0)) dirty = 1;  /* drag moves the scene */
        /* The focused terminal's caret blinks on this same once-a-second tick
         * (app_render, M1527) — force the full redraw path so it's actually
         * seen, instead of the clock-pill-only path below (which never
         * touches a window's content). Still just 1 Hz, not a continuous
         * animation loop, so an idle desktop with a terminal focused costs
         * one full redraw/sec, not one every frame. */
        if (clock_tick && win_count > 0 && windows[win_count - 1].kind == KIND_APP &&
            app_shows_caret((app_t *)windows[win_count - 1].app))
            dirty = 1;

        if (dirty) { render_scene(); present_frame(); }  /* scene changed: full redraw + blit */
        else if (clock_tick) {
            /* Just the clock changed — the common once-a-second case with an
             * otherwise-idle desktop. Redraw only its pill (present_clock, the
             * present_cursor treatment) instead of the whole scene. Falls back
             * to a full redraw if the cursor happens to be sitting over the
             * pill, so the cursor is never left stale. */
            int clkw = clk_pill_w(), clkx = screen_w - clkw - 8, ty = screen_h - TASKBAR_H;
            int cw = mouse_cursor_w(), ch = mouse_cursor_h();
            if (cur_px >= 0 && rects_overlap(clkx, ty, clkw, TASKBAR_H, cur_px, cur_py, cw, ch)) {
                render_scene(); present_frame();
            } else {
                present_clock();
                if (moved) present_cursor();
            }
        }
        else if (moved) present_cursor();                 /* cursor only: tiny rect blit */
        prev_x = mx; prev_y = my; prev_btn = btn;
        idle_hlt();    /* halt till the next IRQ; credits the wait to idle so /proc CPU% is real (M1361) */
    }
}
