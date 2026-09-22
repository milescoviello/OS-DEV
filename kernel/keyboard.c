/*
 * keyboard.c — PS/2 keyboard driver + the shared input queue.
 *
 * The IRQ1 handler translates scan codes to ASCII and pushes them into a small
 * ring buffer. Serial input (serial.c) pushes into the *same* buffer, so the
 * shell reads from keyboard or serial interchangeably — which is what lets us
 * drive the shell headlessly in tests by piping bytes to the serial port.
 *
 * Note: the handler no longer echoes. Echo now happens in the SYS_read path,
 * so typed characters appear exactly once regardless of which device they came
 * from.
 */
#include "keyboard.h"
extern void kprintf(const char *fmt, ...);   /* M2335: the dropped-keystroke line */
#include "interrupts.h"
#include "io.h"
#include <stdint.h>
#include <stdbool.h>

#define KBD_DATA 0x60

static const char keymap[128] = {
    0,    27,  '1', '2', '3', '4', '5', '6', '7', '8',
    '9',  '0', '-', '=', '\b','\t','q', 'w', 'e', 'r',
    't',  'y', 'u', 'i', 'o', 'p', '[', ']', '\n',0,
    'a',  's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';',
    '\'', '`', 0,   '\\','z', 'x', 'c', 'v', 'b', 'n',
    'm',  ',', '.', '/', 0,   '*', 0,   ' ',
};
static const char keymap_shift[128] = {
    0,    27,  '!', '@', '#', '$', '%', '^', '&', '*',
    '(',  ')', '_', '+', '\b','\t','Q', 'W', 'E', 'R',
    'T',  'Y', 'U', 'I', 'O', 'P', '{', '}', '\n',0,
    'A',  'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':',
    '"',  '~', 0,   '|', 'Z', 'X', 'C', 'V', 'B', 'N',
    'M',  '<', '>', '?', 0,   '*', 0,   ' ',
};

#define SC_LSHIFT 0x2A
#define SC_RSHIFT 0x36
#define SC_LCTRL  0x1D
#define SC_RELEASE 0x80

/* ---- shared input ring buffer ----------------------------------------- */

#define IBUF_SIZE 256
static volatile char     ibuf[IBUF_SIZE];
static volatile uint32_t ihead, itail;

/* WHERE DOES A LOST KEYSTROKE GO? (M2335)
 *
 * Typing "example.net" into Firefox's address bar produced "exampl" and the
 * missing five characters never arrived, even after ten seconds. Three places
 * could have eaten them -- QEMU's 8042 queue (16 bytes, and each key is a
 * make AND a break, so a 12-character URL is 24), this 256-entry ring, or the
 * desktop's dequeue loop -- and the existing counters could not tell them
 * apart: "18 dequeued, 18 forwarded" is consistent with all three.
 *
 * So count what was PUSHED and what this ring refused. pushed == dequeued
 * means nothing was lost here and the loss is upstream in the 8042; pushed >
 * dequeued with drops means this ring overflowed; pushed > dequeued with no
 * drops means the desktop simply has not caught up yet. */
uint64_t g_in_pushed, g_in_dropped;

void input_push(char c) {
    uint32_t next = (ihead + 1) % IBUF_SIZE;
    g_in_pushed++;
    if (next != itail) {          /* drop on overflow rather than clobber */
        ibuf[ihead] = c;
        ihead = next;
    } else {
        g_in_dropped++;
        if (g_in_dropped <= 4)
            kprintf("[kbd] ** the input ring is FULL: dropped a keystroke "
                    "(%lu pushed, %lu dropped) **\n",
                    (unsigned long)g_in_pushed, (unsigned long)g_in_dropped);
    }
}

static int input_try(void) {
    if (ihead == itail)
        return -1;
    char c = ibuf[itail];
    itail = (itail + 1) % IBUF_SIZE;
    return (unsigned char)c;
}

int input_trygetchar(void) {
    return input_try();
}

/* ---- raw make/break event ring (games) -------------------------------- */
#define RAWQ_SIZE 256
static volatile unsigned short rawq[RAWQ_SIZE];
static volatile uint32_t       rawh, rawt;

void input_push_raw(unsigned short ev) {
    uint32_t next = (rawh + 1) % RAWQ_SIZE;
    if (next != rawt) { rawq[rawh] = ev; rawh = next; }   /* drop on overflow */
}
int input_pop_raw(void) {
    if (rawh == rawt) return -1;
    unsigned short ev = rawq[rawt];
    rawt = (rawt + 1) % RAWQ_SIZE;
    return (int)ev;
}

int input_getchar(void) {
    for (;;) {
        int c = input_try();
        if (c >= 0)
            return c;
        __asm__ volatile("sti; hlt");   /* sleep until some device IRQ wakes us */
    }
}

/* ---- the keyboard IRQ ------------------------------------------------- */

static bool shift_down;
static bool ctrl_down;

static void keyboard_handler(struct registers *r) {
    (void)r;
    uint8_t sc = inb(KBD_DATA);

    /* Extended keys (arrows, etc.) arrive as 0xE0 then a scancode. Deliver the
     * arrows as control codes 0x11-0x14 (up/down/left/right) for apps to use. */
    static bool ext;
    if (sc == 0xE0) { ext = true; return; }

    /* Raw make/break event for games (DOOM), independent of the cooking below:
     * record every press and release with its scancode + extended flag. */
    {
        unsigned short ev = (unsigned short)(sc & 0x7F);
        if (sc & SC_RELEASE) ev |= 0x100;     /* key released (break code) */
        if (ext)             ev |= 0x200;     /* extended (E0-prefixed) key */
        input_push_raw(ev);
    }

    if (ext) {
        ext = false;
        if (!(sc & SC_RELEASE)) {
            char c = 0;
            switch (sc) {
            case 0x48: c = 0x11; break;   /* up        */
            case 0x50: c = 0x12; break;   /* down      */
            case 0x4B: c = 0x13; break;   /* left      */
            case 0x4D: c = 0x14; break;   /* right     */
            case 0x49: c = 0x15; break;   /* page up   */
            case 0x51: c = 0x16; break;   /* page down */
            case 0x47: c = 0x01; break;   /* home   -> ^A (line start) */
            case 0x4F: c = 0x05; break;   /* end    -> ^E (line end)   */
            case 0x53: c = 0x04; break;   /* delete -> ^D (fwd delete) */
            }
            if (c) input_push(c);
        }
        return;
    }

    if (sc & SC_RELEASE) {
        uint8_t code = sc & 0x7F;
        if (code == SC_LSHIFT || code == SC_RSHIFT)
            shift_down = false;
        if (code == SC_LCTRL)
            ctrl_down = false;
        return;
    }
    if (sc == SC_LSHIFT || sc == SC_RSHIFT) {
        shift_down = true;
        return;
    }
    if (sc == SC_LCTRL) {            /* Ctrl held: letters become 0x81..0x9A (see below) */
        ctrl_down = true;
        return;
    }
    if (sc == 0x3B) { input_push(0x1D); return; }   /* F1 -> WM: keyboard-shortcut help */
    if (sc == 0x3C) { input_push(0x0E); return; }   /* F2 -> WM: cycle window focus  */
    if (sc == 0x3D) { input_push(0x18); return; }   /* F3 -> WM: minimize window     */
    if (sc == 0x3E) { input_push(0x0F); return; }   /* F4 -> WM: maximize/restore    */
    if (sc == 0x3F) { input_push(0x10); return; }   /* F5 -> WM: snap window left    */
    if (sc == 0x40) { input_push(0x17); return; }   /* F6 -> WM: snap window right   */
    if (sc == 0x41) { input_push(0x1E); return; }   /* F7 -> WM: toggle window switcher */
    if (sc == 0x42) { input_push(0x1A); return; }   /* F8 -> WM: close focused window */
    if (sc == 0x43) { input_push(0x19); return; }   /* F9 -> WM: toggle Apps menu    */
    if (sc == 0x44) { input_push(0x0B); return; }   /* F10 -- no WM action; forwarded to the focused app (M2293) */
    if (sc == 0x57) { input_push(0x0C); return; }   /* F11 -- likewise. Both were DROPPED here entirely, so
                                                     * fullscreen in a browser was not a key that did nothing,
                                                     * it was a key that did not exist. */
    if (sc == 0x58) { input_push(0x1C); return; }   /* F12 -> WM: screenshot         */
    if (sc == 0x0F && shift_down) { input_push(0x9B); return; }   /* Shift+Tab -> backtab (editor: dedent) */
    if (sc < 128) {
        char c = shift_down ? keymap_shift[sc] : keymap[sc];
        if (c) {
            if (ctrl_down) {        /* Ctrl+letter -> 0x81..0x9A (apps read these as readline shortcuts) */
                char lo = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
                if (lo >= 'a' && lo <= 'z') c = (char)(0x80 | (lo & 0x1f));
            }
            input_push(c);
        }
    }
}

void keyboard_init(void) {
    irq_install_handler(1, keyboard_handler);
}
