/*
 * usb_kbd.c — a USB HID boot-protocol keyboard over the UHCI host controller
 * (kernel/usb.c). Enumerate a HID boot keyboard, put it in boot protocol, poll
 * its interrupt-IN endpoint for the 8-byte boot report, translate the HID usage
 * codes to the kernel's ASCII/control representation, and push each newly-pressed
 * key into the SAME input queue (keyboard.c's input_push) the PS/2 keyboard and
 * serial line feed — so a USB keyboard drives the shell + apps identically.
 *
 * --- The protocol, briefly --------------------------------------------------
 * A HID boot keyboard is interface class 0x03 (HID), subclass 0x01 (Boot),
 * protocol 0x01 (Keyboard). After SET_CONFIGURATION we issue two HID class
 * control transfers: SET_PROTOCOL(0) selects the fixed BOOT report format, and
 * SET_IDLE(0) tells the device to report only on a change (no auto-repeat from
 * the device — the kernel/app layer owns repeat). The boot report is 8 bytes:
 *
 *   byte 0 : modifier bitmap (bit0 LCtrl, bit1 LShift, bit2 LAlt, bit3 LGui,
 *            bit4 RCtrl, bit5 RShift, bit6 RAlt, bit7 RGui)
 *   byte 1 : reserved
 *   bytes 2..7 : up to 6 currently-pressed HID usage IDs (0 = empty slot)
 *
 * We poll the interrupt-IN endpoint each tick; a new report is diffed against the
 * previous one — a usage present now but NOT in the previous report is a fresh
 * key DOWN, which we translate + enqueue (key releases and held keys produce no
 * event; the kernel input layer doesn't model auto-repeat for USB, same as it
 * cooks one char per PS/2 make code).
 *
 * --- Safety (reviewed line-by-line) -----------------------------------------
 *  - The interrupt-IN read targets a fixed 8-byte buffer; usb_interrupt_xfer is
 *    told len=8 and bounds the copy. The report-diff + decode only ever index
 *    bytes [0..7]; the 6 usage slots are bytes [2..7].
 *  - A usage ID is bounded (< sizeof table) before the table lookup, so a bogus
 *    usage can't read past the translation table.
 *  - Every transfer has a finite, bounded timeout in kernel/usb.c; a poll that
 *    finds nothing pending returns cleanly (does NOT spin); a stalled/absent
 *    endpoint returns -1 and we just skip this poll.
 *  - Enumeration SKIPS the tablet's port and uses the shared USB address
 *    allocator (usb_alloc_address), so it never collides with the tablet or a
 *    USB flash disk; those paths stay functional.
 *  - No HID boot-keyboard interface on the bus => usb_kbd_init() returns -1 (a
 *    clean no-op); the PS/2 keyboard + USB tablet + USB mass-storage are
 *    unaffected.
 */
#include "usb_kbd.h"
#include "usb.h"
#include "keyboard.h"
#include "console.h"
#include "string.h"
#include "timer.h"
#include <stdint.h>

/* HID modifier-byte bits (boot report byte 0). */
#define MOD_LCTRL  0x01
#define MOD_LSHIFT 0x02
#define MOD_LALT   0x04
#define MOD_LGUI   0x08     /* Super / Windows key */
#define MOD_RCTRL  0x10
#define MOD_RSHIFT 0x20
#define MOD_RALT   0x40
#define MOD_RGUI   0x80

/* Driver state for the one USB HID boot keyboard we support. */
static struct {
    int      present;
    uint8_t  addr;        /* USB device address                       */
    uint8_t  ep_in;       /* INTERRUPT IN endpoint number             */
    uint16_t maxp_in;     /* interrupt-IN max packet                  */
    int      tog_in;      /* interrupt-IN data toggle (persists)      */
    uint8_t  iface;       /* the HID interface number (for SET_PROTOCOL/IDLE) */
    uint8_t  prev[6];     /* the previous report's 6 usage slots (for key-down diff) */
    uint8_t  prev_mods;   /* previous modifier bitmap, for raw make/break edges (M1927) */
} kb;

/* HID Keyboard/Keypad usage (page 0x07) -> the kernel's unshifted ASCII/control
 * byte. 0 = no mapping (modifier keys, F-keys we don't surface, etc.). Indexed by
 * usage ID; sized to cover the boot set we translate (0x00..0x65). Letters/digits/
 * symbols map to ASCII; Enter/Backspace/Tab/Esc/Space map to their control bytes;
 * arrows + Home/End/Delete/PageUp/PageDown map to the SAME control codes the PS/2
 * handler emits (kernel/keyboard.c), so apps read USB + PS/2 navigation alike. */
#define HID_USAGE_MAX 0x66
static const char usage_ascii[HID_USAGE_MAX] = {
    /* 0x00 */ 0, 0, 0, 0,
    /* 0x04 a..z (0x04..0x1D) */
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    /* 0x1E 1..9,0 (0x1E..0x27) */
    '1','2','3','4','5','6','7','8','9','0',
    /* 0x28 Enter, Esc, Backspace, Tab, Space */
    '\n', 27, '\b', '\t', ' ',
    /* 0x2D - = [ ] backslash */
    '-', '=', '[', ']', '\\',
    /* 0x32 non-US '#' (treat as backslash family); 0x33 ; 0x34 ' 0x35 ` 0x36 , 0x37 . 0x38 / */
    '\\', ';', '\'', '`', ',', '.', '/',
    /* 0x39 CapsLock (no char) */
    0,
    /* 0x3A..0x45 F1..F12 (no surfaced char here) */
    0,0,0,0,0,0,0,0,0,0,0,0,
    /* 0x46 PrintScreen, 0x47 ScrollLock, 0x48 Pause (no char) */
    0,0,0,
    /* 0x49 Insert (no char), 0x4A Home -> ^A, 0x4B PageUp -> 0x15 */
    0, 0x01, 0x15,
    /* 0x4C Delete -> ^D, 0x4D End -> ^E, 0x4E PageDown -> 0x16 */
    0x04, 0x05, 0x16,
    /* 0x4F Right -> 0x14, 0x50 Left -> 0x13, 0x51 Down -> 0x12, 0x52 Up -> 0x11 */
    0x14, 0x13, 0x12, 0x11,
    /* 0x53 NumLock (no char), 0x54 KP/ 0x55 KP* 0x56 KP- 0x57 KP+ */
    0, '/', '*', '-', '+',
    /* 0x58 KP Enter */
    '\n',
    /* 0x59..0x62 KP 1..9,0 */
    '1','2','3','4','5','6','7','8','9','0',
    /* 0x63 KP . , 0x64 non-US backslash, 0x65 Application (no char) */
    '.', '\\', 0,
};

/* Shifted ASCII for the printable keys (digits -> symbols, symbol row shifted).
 * Letters get upper-cased in code (so we don't duplicate 26 entries); only the
 * entries that DIFFER when shifted are filled here. 0 means "same as unshifted /
 * shift doesn't apply", which keeps control bytes (Enter/arrows/...) intact. */
static const char usage_shift[HID_USAGE_MAX] = {
    /* 0x1E 1..9,0 shifted */
    [0x1E] = '!', [0x1F] = '@', [0x20] = '#', [0x21] = '$', [0x22] = '%',
    [0x23] = '^', [0x24] = '&', [0x25] = '*', [0x26] = '(', [0x27] = ')',
    /* symbol row shifted */
    [0x2D] = '_', [0x2E] = '+', [0x2F] = '{', [0x30] = '}', [0x31] = '|',
    [0x32] = '|', [0x33] = ':', [0x34] = '"', [0x35] = '~', [0x36] = '<',
    [0x37] = '>', [0x38] = '?',
};

/* ---- raw events, so the desktop's modifier CHORDS work on a USB keyboard -----
 * The window-manager chords (Alt+Tab, Alt+F4, Super, Super+Arrow, Ctrl+Alt+Arrow,
 * the workspace keys) are driven from the RAW scancode queue, because the cooked
 * layer carries no modifier state. That queue was fed ONLY by the PS/2 IRQ
 * handler, so on a machine driven by a USB keyboard every one of those chords
 * silently did nothing -- the exact "pressing it does nothing" failure they were
 * added to fix, and it would only ever show up on real hardware. (M1927)
 *
 * The boot report already carries what is needed: byte 0 is the modifier bitmap
 * (including LGui = Super) and bytes 2..7 are the held usages. Translate both into
 * the PS/2 scancodes the desktop expects, in keyboard.c's encoding (`| 0x100` on
 * release). Only the keys the chords look at are mapped; ordinary typing keeps
 * going through the cooked path exactly as before. */
#define RAW_REL 0x100

static const struct { uint8_t usage, sc; } HID_RAW[] = {
    { 0x2B, 0x0F },   /* Tab   */
    { 0x3D, 0x3E },   /* F4    */
    { 0x4F, 0x4D },   /* Right */
    { 0x50, 0x4B },   /* Left  */
    { 0x51, 0x50 },   /* Down  */
    { 0x52, 0x48 },   /* Up    */
    { 0x1E, 0x02 },   /* 1     */
    { 0x1F, 0x03 },   /* 2     */
    { 0x20, 0x04 },   /* 3     */
    { 0x21, 0x05 },   /* 4     */
};

static uint8_t hid_raw_sc(uint8_t usage) {
    for (unsigned i = 0; i < sizeof HID_RAW / sizeof HID_RAW[0]; i++)
        if (HID_RAW[i].usage == usage) return HID_RAW[i].sc;
    return 0;
}

/* Modifier bitmap -> raw make/break events on each EDGE. Left and right variants
 * collapse to one scancode, since the desktop masks the extended bit off anyway. */
static void push_mod_edges(uint8_t now, uint8_t before) {
    static const struct { uint8_t mask, sc; } M[] = {
        { MOD_LCTRL  | MOD_RCTRL,  0x1D },
        { MOD_LSHIFT | MOD_RSHIFT, 0x2A },
        { MOD_LALT   | MOD_RALT,   0x38 },
        { MOD_LGUI   | MOD_RGUI,   0x5B },
    };
    for (unsigned i = 0; i < sizeof M / sizeof M[0]; i++) {
        int was = (before & M[i].mask) != 0, is = (now & M[i].mask) != 0;
        if (is && !was)      input_push_raw(M[i].sc);
        else if (!is && was) input_push_raw((unsigned short)(M[i].sc | RAW_REL));
    }
}

/* Translate a HID usage ID + the modifier byte into the kernel's input byte, or
 * 0 if it maps to nothing. Bounds the usage before either table lookup. */
static char translate(uint8_t usage, uint8_t mods) {
    if (usage == 0 || usage >= HID_USAGE_MAX)
        return 0;
    int shift = (mods & (MOD_LSHIFT | MOD_RSHIFT)) != 0;
    int ctrl  = (mods & (MOD_LCTRL  | MOD_RCTRL )) != 0;

    char c = usage_ascii[usage];
    if (c == 0)
        return 0;

    if (shift) {
        if (c >= 'a' && c <= 'z')
            c = (char)(c - 'a' + 'A');           /* letters: upper-case */
        else if (usage_shift[usage])
            c = usage_shift[usage];              /* digits/symbols: shifted glyph */
    }

    /* Ctrl+letter -> 0x81..0x9A, matching kernel/keyboard.c's readline shortcuts
     * (the PS/2 handler does the same remap). Only for letters; leaves Enter/Tab/
     * arrows/etc. as their own bytes. */
    if (ctrl) {
        char lo = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
        if (lo >= 'a' && lo <= 'z')
            c = (char)(0x80 | (lo & 0x1f));
    }
    return c;
}

/* Was `usage` present in the previous report's 6 slots? (Used to fire only on a
 * key's first appearance — a key DOWN — not while it's held.) */
static int was_pressed(uint8_t usage) {
    for (int i = 0; i < 6; i++)
        if (kb.prev[i] == usage)
            return 1;
    return 0;
}

/* --- enumeration ----------------------------------------------------------- */

static int get_descriptor(uint8_t addr, uint16_t ep0_maxp, int type, int index,
                          void *out, int len) {
    uint8_t s[8] = { 0x80, 0x06, (uint8_t)index, (uint8_t)type,
                     0, 0, (uint8_t)len, (uint8_t)(len >> 8) };
    return usb_control_xfer(addr, ep0_maxp, s, out, len, 1);
}
static int set_address(uint16_t ep0_maxp, int addr) {
    uint8_t s[8] = { 0x00, 0x05, (uint8_t)addr, 0, 0, 0, 0, 0 };
    return usb_control_xfer(0, ep0_maxp, s, 0, 0, 0);   /* still at address 0 */
}
static int set_configuration(uint8_t addr, uint16_t ep0_maxp, int cfg) {
    uint8_t s[8] = { 0x00, 0x09, (uint8_t)cfg, 0, 0, 0, 0, 0 };
    return usb_control_xfer(addr, ep0_maxp, s, 0, 0, 0);
}
/* HID SET_PROTOCOL: bmRequestType 0x21 (host->dev, class, interface), bRequest
 * 0x0B, wValue 0 = boot protocol, wIndex = interface. */
static int set_protocol(uint8_t addr, uint16_t ep0_maxp, int iface, int proto) {
    uint8_t s[8] = { 0x21, 0x0B, (uint8_t)proto, 0, (uint8_t)iface, 0, 0, 0 };
    return usb_control_xfer(addr, ep0_maxp, s, 0, 0, 0);
}
/* HID SET_IDLE: bmRequestType 0x21, bRequest 0x0A, wValue hi = duration (0 =
 * indefinite, report only on change), wIndex = interface. */
static int set_idle(uint8_t addr, uint16_t ep0_maxp, int iface, int duration) {
    uint8_t s[8] = { 0x21, 0x0A, 0, (uint8_t)duration, (uint8_t)iface, 0, 0, 0 };
    return usb_control_xfer(addr, ep0_maxp, s, 0, 0, 0);
}

/* Enumerate the device on the freshly-enabled port as a USB HID boot keyboard.
 * On success fills `kb` (address, interrupt-IN endpoint, interface, config set +
 * boot protocol selected) and returns 0; returns -1 if the device there isn't a
 * usable HID boot keyboard. */
static int enumerate_one(void) {
    uint16_t ep0 = 8;                             /* ep0 default max packet */

    /* Device descriptor: first 8 bytes for the real ep0 max packet, then assign
     * an address and (re-)read at it. */
    uint8_t dd[18];
    if (get_descriptor(0, ep0, 1, 0, dd, 8) != 0)
        return -1;
    ep0 = dd[7] ? dd[7] : 8;

    int addr = usb_alloc_address();
    if (addr <= 0 || set_address(ep0, addr) != 0)
        return -1;
    timer_wait(1);

    /* Config descriptor: header first (total length), then the whole thing. */
    uint8_t cfg[256];
    if (get_descriptor((uint8_t)addr, ep0, 2, 0, cfg, 9) != 0)
        return -1;
    int total = cfg[2] | (cfg[3] << 8);
    if (total < 9) return -1;
    if (total > (int)sizeof(cfg)) total = sizeof(cfg);
    if (get_descriptor((uint8_t)addr, ep0, 2, 0, cfg, total) != 0)
        return -1;

    /* Walk the config: find a HID / Boot / Keyboard interface (class 0x03,
     * subclass 0x01, protocol 0x01), then within it the INTERRUPT IN endpoint.
     * Endpoints belong to the most recently-seen interface. */
    int found_iface = 0, in_target = 0;
    uint8_t ep_in = 0, iface_num = 0;
    uint16_t maxp_in = 0;
    uint8_t iface_class = 0, iface_sub = 0, iface_proto = 0;

    for (int i = 0; i + 1 < total; ) {
        int blen = cfg[i], btype = cfg[i + 1];
        if (blen < 2) break;
        if (i + blen > total) break;

        if (btype == 0x04 && blen >= 9) {         /* INTERFACE descriptor */
            uint8_t inum = cfg[i + 2];
            uint8_t icls = cfg[i + 5], isub = cfg[i + 6], iproto = cfg[i + 7];
            in_target = (icls == 0x03 && isub == 0x01 && iproto == 0x01);
            if (in_target && !found_iface) {
                iface_num   = inum;
                iface_class = icls; iface_sub = isub; iface_proto = iproto;
            }
        } else if (btype == 0x05 && blen >= 7 && in_target) {  /* ENDPOINT in target iface */
            uint8_t eaddr = cfg[i + 2], eattr = cfg[i + 3];
            uint16_t emax = cfg[i + 4] | (cfg[i + 5] << 8);
            if ((eaddr & 0x80) && (eattr & 0x03) == 0x03) {    /* INTERRUPT IN */
                if (!found_iface) {
                    ep_in = eaddr & 0x0F;
                    maxp_in = emax;
                    found_iface = 1;              /* a complete boot-keyboard interface */
                }
            }
        }
        i += blen;
    }

    if (!found_iface || !ep_in)
        return -1;
    if (maxp_in == 0 || maxp_in > 8) maxp_in = 8; /* boot report is 8 bytes */

    if (set_configuration((uint8_t)addr, ep0, cfg[5]) != 0)
        return -1;

    /* Put the interface in BOOT protocol + tell it to report only on change.
     * SET_PROTOCOL is required for the fixed boot report layout; SET_IDLE is
     * best-effort (some devices STALL it, which is harmless — we ignore that). */
    if (set_protocol((uint8_t)addr, ep0, iface_num, 0 /* boot */) != 0) {
        kprintf("[usb-kbd] SET_PROTOCOL(boot) failed\n");
        return -1;
    }
    (void)set_idle((uint8_t)addr, ep0, iface_num, 0 /* indefinite */);

    kb.addr    = (uint8_t)addr;
    kb.ep_in   = ep_in;
    kb.maxp_in = maxp_in;
    kb.tog_in  = 0;
    kb.iface   = iface_num;
    memset(kb.prev, 0, sizeof(kb.prev));

    kprintf("[usb-kbd] enumerated HID boot keyboard: class=%02x subclass=%02x "
            "proto=%02x  interrupt-in=ep%d(maxp=%d)  SET_PROTOCOL(boot)=ok\n",
            iface_class, iface_sub, iface_proto, ep_in, maxp_in);
    return 0;
}

/* --- public API ------------------------------------------------------------ */

int usb_kbd_init(void) {
    memset(&kb, 0, sizeof(kb));

    /* Bring the UHCI controller up (shared with the tablet/storage; idempotent). */
    if (usb_uhci_init() != 0)
        return -1;                                /* no controller: clean no-op */

    /* Probe each root port for a HID boot keyboard, one port at a time and
     * SKIPPING every port another driver has already claimed. One-port-at-a-time
     * is required because two unaddressed devices would both answer address 0.
     *
     * The skip is not just politeness: usb_uhci_enable_port() RESETS the port,
     * knocking the device behind it back to address 0. Skipping only the tablet
     * (as this loop used to) meant that on a machine with a USB flash disk, this
     * probe reset the already-enumerated mass-storage device — which stayed
     * registered in the block layer while every subsequent read failed (M1889). */
    int ok = -1;
    for (int p = 0; p < usb_uhci_port_count() && ok != 0; p++) {
        if (usb_uhci_port_claimed(p))
            continue;
        if (!usb_uhci_enable_port(p))
            continue;                             /* nothing connected/enabled */
        if (enumerate_one() == 0) {
            usb_uhci_claim_port(p);
            ok = 0;
        }
    }
    if (ok != 0)
        return -1;                                /* no boot keyboard: clean no-op */

    kb.present = 1;
    return 0;
}

int usb_kbd_present(void) { return kb.present; }

void usb_kbd_poll(void) {
    if (!kb.present)
        return;

    uint8_t report[8];
    memset(report, 0, sizeof(report));
    int got = 0;
    /* One interrupt-IN poll. usb_interrupt_xfer is non-blocking-ish: it returns
     * 0/got==0 if the keyboard had nothing to report (a NAK), and -1 on a real
     * stall — in either non-report case we just leave kb.prev unchanged and bail. */
    if (usb_interrupt_xfer(kb.addr, kb.ep_in, kb.maxp_in, &kb.tog_in,
                           report, (int)sizeof(report), &got) != 0)
        return;                                   /* stall/error this poll: skip */
    if (got < 3)
        return;                                   /* no new report (or too short to hold a key) */

    uint8_t mods = report[0];
    push_mod_edges(mods, kb.prev_mods);           /* raw modifier edges (M1927) */

    /* Slots are bytes [2..7]. A usage present now but NOT in the previous report
     * is a fresh key DOWN; translate it and enqueue. (Held keys + releases produce
     * nothing — matching the PS/2 path's one-char-per-make-code cooking.) */
    for (int i = 2; i < 8; i++) {
        uint8_t usage = report[i];
        if (usage == 0)
            continue;
        /* Usage 0x01 in a slot is "ErrorRollOver" (too many keys held) — skip. */
        if (usage == 0x01)
            continue;
        if (was_pressed(usage))
            continue;                             /* still held since last report */
        uint8_t sc = hid_raw_sc(usage);           /* chord keys also go out RAW (M1927) */
        if (sc) input_push_raw(sc);
        char c = translate(usage, mods);
        if (c)
            input_push(c);
    }

    /* Key RELEASES: a usage in the previous report but not this one. The cooked
     * path ignores releases, but the raw consumer needs them -- without a break
     * event a held-key latch never clears. (M1927) */
    for (int i = 0; i < 6; i++) {
        uint8_t usage = kb.prev[i];
        if (usage == 0 || usage == 0x01) continue;
        int still = 0;
        for (int j = 2; j < 8; j++) if (report[j] == usage) { still = 1; break; }
        if (still) continue;
        uint8_t sc = hid_raw_sc(usage);
        if (sc) input_push_raw((unsigned short)(sc | RAW_REL));
    }

    /* Remember this report's slots for the next diff. */
    memcpy(kb.prev, &report[2], 6);
    kb.prev_mods = mods;
}

void usb_kbd_selftest(void) {
    if (!kb.present) {
        kprintf("[usb-kbd] no USB HID boot keyboard found "
                "(none attached; PS/2 keyboard + USB tablet intact).\n\n");
        return;
    }

    /* Run a few polls so a keystroke injected around boot is observed + decoded;
     * each poll is bounded + non-blocking, so this can't hang if the user isn't
     * typing. Log any decoded byte so the in-guest test can assert a real key was
     * received and translated (the headline proof the interrupt-IN path works). */
    int polls = 200, decoded = 0;
    for (int n = 0; n < polls; n++) {
        uint8_t report[8];
        memset(report, 0, sizeof(report));
        int got = 0;
        if (usb_interrupt_xfer(kb.addr, kb.ep_in, kb.maxp_in, &kb.tog_in,
                               report, (int)sizeof(report), &got) == 0 && got >= 3) {
            uint8_t mods = report[0];
            for (int i = 2; i < 8; i++) {
                uint8_t usage = report[i];
                if (usage == 0 || usage == 0x01)
                    continue;
                if (was_pressed(usage))
                    continue;
                char c = translate(usage, mods);
                if (c) input_push(c);              /* feed the real input path too (M1600) --
                                                     * `c ? c : 0` was identical to plain `c`, so
                                                     * this unconditionally pushed a NUL for any
                                                     * unmapped key (CapsLock/F-keys/etc.); the
                                                     * sibling usb_kbd_poll() a few lines up
                                                     * already gated on `c` correctly */
                if (c >= 0x20 && c < 0x7F) {
                    kprintf("[usb-kbd] decoded key: usage=%02x -> '%c'\n", usage, c);
                    decoded++;
                } else if (c) {
                    kprintf("[usb-kbd] decoded key: usage=%02x -> 0x%02x\n", usage, (uint8_t)c);
                    decoded++;
                }
            }
            memcpy(kb.prev, &report[2], 6);
        }
        timer_wait(1);                            /* ~10 ms between polls */
    }

    kprintf("[ ok ] usb-kbd up: HID boot keyboard on UHCI, interrupt-IN ep%d "
            "polled (%d poll(s), %d key(s) decoded). PS/2 keyboard still active.\n\n",
            kb.ep_in, polls, decoded);
}
