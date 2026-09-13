/* OS-DEV's XKB data tree (tools/xkb), resolved BY NAME (M1986).
 *
 * tests/xkb/xkbmap_test.c checks the keymap the compositor hands a client over
 * a memfd. This checks the other path into the same layout: a toolkit asking
 * libxkbcommon for rules "evdev", model "pc105", layout "us" and letting it
 * find the files. GTK does that during display-open, before any compositor has
 * sent it a keymap -- and when it fails, GDK calls g_error() and the process
 * aborts, so there is no fallback to be lenient about.
 *
 * Run with XKB_CONFIG_ROOT pointing at tools/xkb, which is what the guest image
 * stages to /usr/share/X11/xkb.
 */
#include <stdio.h>
#include <string.h>
#include <xkbcommon/xkbcommon.h>

static int fails;
static void ok(int c, const char *w) { printf("  %s: %s\n", c ? "ok" : "FAIL", w); if (!c) fails++; }

int main(void) {
    struct xkb_context *ctx = xkb_context_new(0);
    if (!ctx) { printf("  FAIL: no xkb context\n"); return 1; }
    xkb_context_set_log_level(ctx, XKB_LOG_LEVEL_CRITICAL);
    struct xkb_rule_names n = { .rules = "evdev", .model = "pc105",
                                .layout = "us", .variant = "", .options = "" };
    struct xkb_keymap *km = xkb_keymap_new_from_names(ctx, &n, 0);
    ok(km != NULL, "rules=evdev model=pc105 layout=us resolves through our own rules file");
    if (!km) { printf("%d failures\n", fails); return 1; }
    struct xkb_state *st = xkb_state_new(km);
    char b[16] = {0};
    xkb_state_key_get_utf8(st, 30 + 8, b, sizeof b);
    ok(!strcmp(b, "a"), "...and produces the same 'a' for evdev 30 as the memfd keymap does");
    xkb_state_update_key(st, 42 + 8, XKB_KEY_DOWN);
    b[0] = 0; xkb_state_key_get_utf8(st, 30 + 8, b, sizeof b);
    ok(!strcmp(b, "A"), "...with Shift applied, so the compat section came through too");
    /* An unknown model/layout must still yield a keymap rather than nothing:
     * GTK asks with whatever the system's defaults say, and a NULL here is an
     * abort, not a fallback. */
    struct xkb_rule_names n2 = { .rules = "evdev", .model = "pc104",
                                 .layout = "gb", .variant = "", .options = "" };
    struct xkb_keymap *km2 = xkb_keymap_new_from_names(ctx, &n2, 0);
    ok(km2 != NULL, "an unrecognised model/layout still resolves (the rules match anything)");
    printf("%d failures\n", fails);
    return fails ? 1 : 0;
}
