/* Host regression for OS-DEV's own XKB keymap (kernel/include/xkbmap.h).
 *
 * The keymap is a string the kernel hands to a Wayland client, which compiles
 * it with libxkbcommon. Nothing in the kernel can tell whether it is valid --
 * a typo produces a client that receives keycodes and turns none of them into
 * characters, several layers away from the cause. So the same library the
 * client uses compiles it here, with the same flags, and the characters are
 * checked.
 *
 * XKB_CONTEXT_NO_DEFAULT_INCLUDES is the important flag: it forbids resolving
 * `include` against /usr/share/X11/xkb, which the guest does not have. A keymap
 * that only compiles WITH the default includes would pass a laxer test here and
 * fail in the guest.
 */
#include <stdio.h>
#include <string.h>
#include <xkbcommon/xkbcommon.h>
#include "xkbmap.h"

static int fails;
static void ok(int cond, const char *what) {
    printf("  %s: %s\n", cond ? "ok" : "FAIL", what);
    if (!cond) fails++;
}

static struct xkb_state *st;

/* evdev keycode -> the text a client would insert, with the given mods held. */
static const char *text_for(int evdev, int shift_evdev) {
    static char buf[32];
    if (shift_evdev) xkb_state_update_key(st, shift_evdev + 8, XKB_KEY_DOWN);
    buf[0] = 0;
    xkb_state_key_get_utf8(st, evdev + 8, buf, sizeof buf);
    if (shift_evdev) xkb_state_update_key(st, shift_evdev + 8, XKB_KEY_UP);
    return buf;
}

int main(void) {
    printf("OS-DEV xkb keymap (%u bytes) vs the real libxkbcommon:\n",
           (unsigned)(sizeof osdev_xkb_keymap - 1));

    struct xkb_context *ctx = xkb_context_new(XKB_CONTEXT_NO_DEFAULT_INCLUDES);
    if (!ctx) { printf("  FAIL: no xkb context\n"); return 1; }
    xkb_context_set_log_level(ctx, XKB_LOG_LEVEL_ERROR);
    struct xkb_keymap *km = xkb_keymap_new_from_string(ctx, osdev_xkb_keymap,
                                                       XKB_KEYMAP_FORMAT_TEXT_V1, 0);
    ok(km != NULL, "the keymap compiles with NO default includes -- it is self-contained");
    if (!km) { printf("%d failures\n", fails + 1); return 1; }
    st = xkb_state_new(km);
    ok(st != NULL, "a keyboard state can be built from it");
    if (!st) return 1;

    /* The letters. evdev 30 is 'a' -- the code the compositor actually sends. */
    ok(!strcmp(text_for(30, 0), "a"), "evdev 30 is 'a'  (the offset of 8 is applied)");
    ok(!strcmp(text_for(17, 0), "w"), "evdev 17 is 'w'");
    ok(!strcmp(text_for(44, 0), "z"), "evdev 44 is 'z'");
    /* Shift is evdev 42. Without the compat section's SetMods this silently
     * does nothing and every shifted key returns its base character. */
    ok(!strcmp(text_for(30, 42), "A"), "Shift+evdev 30 is 'A' -- the modifier actually applies");
    ok(!strcmp(text_for(2, 42), "!"),  "Shift+evdev 2 is '!' -- the symbol row's second level");
    /* Digits, punctuation, space. */
    ok(!strcmp(text_for(2, 0), "1"),  "evdev 2 is '1'");
    ok(!strcmp(text_for(11, 0), "0"), "evdev 11 is '0'");
    ok(!strcmp(text_for(57, 0), " "), "evdev 57 is a space");
    ok(!strcmp(text_for(53, 0), "/"), "evdev 53 is '/'");
    ok(!strcmp(text_for(41, 0), "`"), "evdev 41 is a backtick");
    /* Named keys produce a keysym but no text -- a client tells them apart by
     * the keysym, which is how Return and Escape reach an application. */
    ok(xkb_state_key_get_one_sym(st, 28 + 8) == XKB_KEY_Return, "evdev 28 is the Return keysym");
    ok(xkb_state_key_get_one_sym(st, 1 + 8) == XKB_KEY_Escape,  "evdev 1 is the Escape keysym");
    ok(xkb_state_key_get_one_sym(st, 103 + 8) == XKB_KEY_Up,    "evdev 103 is the Up keysym");
    ok(xkb_state_key_get_one_sym(st, 42 + 8) == XKB_KEY_Shift_L, "evdev 42 is Shift_L");
    ok(xkb_state_key_get_one_sym(st, 29 + 8) == XKB_KEY_Control_L, "evdev 29 is Control_L");

    /* The modifier NAMES a toolkit looks up by string. GTK asks for these. */
    ok(xkb_keymap_mod_get_index(km, XKB_MOD_NAME_SHIFT) != XKB_MOD_INVALID, "the keymap has a named Shift modifier");
    ok(xkb_keymap_mod_get_index(km, XKB_MOD_NAME_CTRL)  != XKB_MOD_INVALID, "...and Control");
    ok(xkb_keymap_mod_get_index(km, XKB_MOD_NAME_ALT)   != XKB_MOD_INVALID, "...and Alt");
    ok(xkb_keymap_mod_get_index(km, XKB_MOD_NAME_LOGO)  != XKB_MOD_INVALID, "...and Super");

    /* Ctrl+a must still be 'a': a keymap where Control eats the level is a
     * classic way to break every keyboard shortcut in a toolkit. */
    xkb_state_update_key(st, 29 + 8, XKB_KEY_DOWN);
    char b[8] = {0}; xkb_state_key_get_utf8(st, 30 + 8, b, sizeof b);
    xkb_mod_index_t ctrl = xkb_keymap_mod_get_index(km, XKB_MOD_NAME_CTRL);
    ok(xkb_state_mod_index_is_active(st, ctrl, XKB_STATE_MODS_EFFECTIVE) == 1,
       "holding evdev 29 makes Control active -- modifier_map is wired");
    ok(xkb_state_key_get_one_sym(st, 30 + 8) == XKB_KEY_a,
       "Ctrl+evdev 30 still reports the 'a' keysym, so shortcuts resolve");
    xkb_state_update_key(st, 29 + 8, XKB_KEY_UP);

    printf("%d failures\n", fails);
    return fails ? 1 : 0;
}
