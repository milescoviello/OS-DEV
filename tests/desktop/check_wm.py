#!/usr/bin/env python3
"""check_wm.py — assert desktop window-manager behaviour from framebuffer dumps.

Takes four captures, in order:
    a_ws1        workspace 1 with its windows
    b_ws2        after Ctrl+Alt+Right  (workspace 2, empty)
    c_ws1_again  after Ctrl+Alt+Left   (back on workspace 1)
    d_closed     after Alt+F4          (focused window closed)

The assertions are deliberately relative, so theme/wallpaper/window placement can
change without touching this file. The taskbar is measured as "how far right does
the chip row extend", which is a proxy for the number of open windows that does
not depend on the chip labels or icons.
"""
import sys

TASKBAR_H = 40          # bottom strip the chips live in


def read_ppm(path):
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(b"P6"):
        raise SystemExit("FAIL: %s is not a binary PPM (P6)" % path)
    fields, i = [], 2
    while len(fields) < 3:
        while i < len(data) and data[i:i + 1].isspace():
            i += 1
        if data[i:i + 1] == b"#":
            while i < len(data) and data[i] != 0x0A:
                i += 1
            continue
        j = i
        while j < len(data) and not data[j:j + 1].isspace():
            j += 1
        fields.append(int(data[i:j]))
        i = j
    w, h, maxv = fields
    if maxv != 255:
        raise SystemExit("FAIL: unsupported PPM maxval %d" % maxv)
    return w, h, data[i + 1:]


def diff_pct(a, b, windows_only=False):
    """% of pixels that differ. With windows_only, the taskbar strip is excluded:
    the clock shows SECONDS, so a full-frame comparison can never be 0 across a
    multi-second interaction -- an early version of this test asserted an exact
    restore and failed by 0.01%, which was the clock, not the window manager."""
    (wa, ha, pa), (wb, hb, pb) = a, b
    if (wa, ha) != (wb, hb):
        return 100.0
    ylim = (ha - TASKBAR_H) if windows_only else ha
    d = 0
    for y in range(ylim):
        row = y * wa * 3
        for x in range(0, wa * 3, 3):
            if pa[row + x:row + x + 3] != pb[row + x:row + x + 3]:
                d += 1
    return 100.0 * d / float(wa * ylim)


def chip_ink(img):
    """How much non-background 'ink' (chip borders, icons, labels) sits in the
    window-chip zone of the taskbar -- a proxy for how many windows are open that
    does not depend on chip labels, icons or exact widths.

    The background is taken as the MODAL colour of the zone rather than sampled
    from one pixel: an earlier version sampled a single point, guessed wrong, and
    reported an identical value for every capture, which silently made three
    assertions vacuous."""
    w, h, px = img
    y0, y1 = h - TASKBAR_H + 6, h - 6
    x0, x1 = 180, int(w * 0.62)          # past the Apps button, clear of clock/ws pill
    hist = {}
    for y in range(y0, y1, 2):
        row = y * w * 3
        for x in range(x0, x1, 2):
            c = px[row + x * 3:row + x * 3 + 3]
            hist[c] = hist.get(c, 0) + 1
    if not hist:
        return 0
    bg = max(hist, key=hist.get)
    return sum(n for c, n in hist.items() if c != bg)


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: check_wm.py a_ws1 b_ws2 c_ws1_again d_closed")
    a, b, c, d = (read_ppm(p) for p in sys.argv[1:5])

    fails, checks = [], 0

    def ck(cond, msg):
        nonlocal checks
        checks += 1
        if cond:
            print("  ok: %s" % msg)
        else:
            print("  FAIL: %s" % msg)
            fails.append(msg)

    # 1. switching to an empty workspace must visibly clear the desktop
    sw = diff_pct(a, b)
    ck(sw > 5.0,
       "Ctrl+Alt+Right switches to another workspace (%.1f%% of the screen changed)" % sw)

    # 2. and switching back must restore it EXACTLY. This is the strong one: a
    #    half-restored window set differs by a few pixels and fails here.
    # Not `== 0`: the terminal's caret BLINKS, so the window area is not byte-stable
    # across a multi-second interaction -- an exact assertion failed at 0.011% in a
    # full run. The threshold keeps essentially all of the power anyway: removing
    # the workspace-save step makes this 28.3%, a ~280x margin over the bound.
    back = diff_pct(a, c, windows_only=True)
    ck(back < 0.1,
       "Ctrl+Alt+Left restores workspace 1's windows (%.3f%% of the window area differs, <0.1%% required)" % back)

    # 3. the empty workspace really is emptier: its chip row is shorter
    ink_a, ink_b = chip_ink(a), chip_ink(b)
    ck(ink_b < ink_a,
       "the other workspace has its own (fewer) windows in the taskbar (%d vs %d ink px)"
       % (ink_b, ink_a))

    # 4. Alt+F4 closes the focused window -> one fewer chip
    ink_c, ink_d = chip_ink(c), chip_ink(d)
    ck(ink_d < ink_c,
       "Alt+F4 closed the focused window (taskbar ink %d -> %d)" % (ink_c, ink_d))

    print("%d checks, %d failures" % (checks, len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
