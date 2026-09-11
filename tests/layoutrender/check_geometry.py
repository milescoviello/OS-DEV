#!/usr/bin/env python3
"""check_geometry.py — assert the browser's SOLVED box-model geometry from a
framebuffer dump (M1902).

Why this exists: the layout rules themselves are unit-tested off-target
(tests/layout, 95 known-answer checks), but the browser-side wiring had no
automated coverage at all. Three real bugs coexisted in a fully-green tree
because of it — a background painting the content box instead of the padding box
(M1897), vertical padding landing outside the background (M1900), and a border
stroking inside its own background (M1901). Each was found by a human looking at
a screenshot. This closes that gap.

Method: LAYCHK.HTM gives every case a unique background colour, so each block's
box is findable by exact RGB match. Assertions are RELATIVE (widths, and gaps
compared against each other) rather than absolute screen coordinates, so they
survive window placement and desktop chrome changes. The full-width padded block
establishes the content column that the alignment cases are measured against.

Takes one or more dumps and MERGES them: each colour is taken from the first dump
that contains it. That serves two purposes — the fixture spans two pages (all the
cases together overflow the viewport, and a block scrolled off screen is simply
absent), and a dump grabbed before the desktop settled contributes nothing rather
than failing the run.

Usage: check_geometry.py <dump.ppm> [more.ppm ...]   ->  exit 0 = pass
"""
import sys

TOL = 3          # px slack for integer rounding / odd-slack splits

# Colours must match tools/mkfatfs.c's LAYCHK.HTM exactly.
COL = {
    "wide_bg":   (0xfe, 0x06, 0x06),   # padding:40px, no margins -> spans the column
    "wide_in":   (0xfe, 0x07, 0x07),   # a nested <p> background inside it
    "left":      (0xfe, 0x01, 0x01),   # width:300px
    "centre":    (0xfe, 0x02, 0x02),   # width:300px; margin:0 auto
    "right":     (0xfe, 0x03, 0x03),   # width:300px; margin-left:auto
    "padbox":    (0xfe, 0x04, 0x04),   # width:400px; padding:20px; margin:0 auto
    "bordered":  (0xfe, 0x05, 0x05),   # border:3px + padding:30px
    "border":    (0x01, 0xfe, 0x01),   # that block's border stroke
    "bordbox":   (0xfe, 0x08, 0x08),   # width:400px; padding:20px; box-sizing:border-box
    "mb":        (0xfe, 0x09, 0x09),   # width:200px; margin-bottom:60px
    "after_mb":  (0xfe, 0x0a, 0x0a),   # the block that follows it
    "h80":       (0xfe, 0x0b, 0x0b),   # width:200px; height:80px
    "h80bb":     (0xfe, 0x0c, 0x0c),   # same + padding:15px; box-sizing:border-box
    "minh":      (0xfe, 0x0d, 0x0d),   # width:200px; min-height:70px
    "minh_lose": (0xfe, 0x0e, 0x0e),   # min-height:20px; height:90px -> height wins
    # A trailing sentinel so the LAST interesting block still has a successor to
    # overlap. Without it a main-loop under-advance on the final block is invisible
    # (a mutation exploited exactly that and survived).
    "sentinel":  (0xfe, 0x0f, 0x0f),
    # --- page 3: max-height (M1910) ---------------------------------------------
    "maxh":      (0xfe, 0x10, 0x10),   # width:200px; max-height:40px, content ~5 lines
    "after_max": (0xfe, 0x11, 0x11),   # the follower: proves the FLOW advance clamped
    "maxh_loose":(0xfe, 0x12, 0x12),   # max-height:400px on one line -> must not bind
    "maxh_min":  (0xfe, 0x13, 0x13),   # max-height:20px; min-height:70px -> min wins
    "maxh_bb":   (0xfe, 0x14, 0x14),   # max-height:60px; padding:10px; border-box
    "clip":      (0xfe, 0x16, 0x16),   # max-height:40 + overflow:hidden
    "clipdeep":  (0xfe, 0x17, 0x17),   # a span INSIDE it, past the cap -> must be ABSENT
    "afterclip": (0xfe, 0x18, 0x18),   # the follower
    "tail":      (0xfe, 0x15, 0x15),   # page-3 sentinel
    # --- page 4: float + clear (M1928) ------------------------------------------
    "floatimg":  (0x33, 0x66, 0xcc),   # LOGO.SVG's blue rect = the floated image
    "wraptext":  (0xfe, 0x19, 0x19),   # span bg = where the wrapping text actually sits
    "cleared":   (0xfe, 0x1a, 0x1a),   # a block with clear:both after the float
    # --- page 5: box geometry from a STYLESHEET RULE + viewport units (M1929) --
    "ruleref":   (0xfe, 0x22, 0x22),   # no width -> spans the column (reference)
    "rulew":     (0xfe, 0x20, 0x20),   # width:300px; margin:0 auto -- from a RULE
    "rulevw":    (0xfe, 0x21, 0x21),   # width:40vw -- from a RULE
    "rulepad":   (0xfe, 0x24, 0x24),   # width:200px + padding:25px -- from a RULE
    "ruleht":    (0xfe, 0x25, 0x25),   # width:200px + height:70px -- from a RULE
    "liplain":   (0xfe, 0x26, 0x26),   # text in a normal <li> (has a bullet marker)
    "liflex":    (0xfe, 0x27, 0x27),   # text in a display:flex <li> (must have NONE)
}


def read_ppm(path):
    """Minimal P6 reader, tolerant of comments and whitespace layout."""
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(b"P6"):
        raise SystemExit("FAIL: %s is not a binary PPM (P6)" % path)
    fields, i = [], 2
    while len(fields) < 3:
        while i < len(data) and data[i:i + 1].isspace():
            i += 1
        if data[i:i + 1] == b"#":                      # comment to end of line
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


def bbox(px, w, h, rgb):
    """Bounding box of pixels exactly matching rgb, or None. Returns
    (left, top, right, bottom) with right/bottom INCLUSIVE."""
    target = bytes(rgb)
    l, t, r, b = w, h, -1, -1
    for y in range(h):
        row = px[y * w * 3:(y + 1) * w * 3]
        start = row.find(target)
        if start < 0:
            continue
        # scan the row properly: find() can land on a mid-pixel byte alignment
        for x in range(w):
            if row[x * 3:x * 3 + 3] == target:
                if x < l: l = x
                if x > r: r = x
                if y < t: t = y
                if y > b: b = y
    return None if r < 0 else (l, t, r, b)


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: check_geometry.py <dump.ppm> [more.ppm ...]")

    boxes = {name: None for name in COL}
    for path in sys.argv[1:]:
        try:
            w, h, px = read_ppm(path)
        except SystemExit:
            continue                      # unreadable/partial dump: skip it
        for name, rgb in COL.items():
            if boxes[name] is None:
                boxes[name] = bbox(px, w, h, rgb)
    missing = [n for n, v in boxes.items() if v is None]
    if missing:
        print("FAIL: these cases did not render at all: %s" % ", ".join(sorted(missing)))
        print("      (the page may not have loaded, or a colour changed in LAYCHK.HTM)")
        return 1

    fails, checks = [], 0

    def ck(cond, msg):
        nonlocal checks
        checks += 1
        if cond:
            print("  ok: %s" % msg)
        else:
            print("  FAIL: %s" % msg)
            fails.append(msg)

    def width(n):
        l, _, r, _ = boxes[n]
        return r - l + 1

    # The full-width padded block has no margins, so its padding box spans the
    # whole content column — that is our reference frame.
    col_l, _, col_r, _ = boxes["wide_bg"]

    # --- §10.3.3 used width -------------------------------------------------
    for name in ("left", "centre", "right"):
        ck(abs(width(name) - 300) <= TOL,
           "%s: used width is 300px (got %d)" % (name, width(name)))
    # padding is part of the width constraint: 400 content + 2*20 padding
    ck(abs(width("padbox") - 440) <= TOL,
       "padbox: width:400px + padding:20px gives a 440px box (got %d)" % width("padbox"))

    # --- horizontal alignment ------------------------------------------------
    ck(abs(boxes["left"][0] - col_l) <= TOL,
       "left: no auto margin stays at the column's left edge")
    ck(abs(boxes["right"][2] - col_r) <= TOL,
       "right: margin-left:auto pushes the box to the column's right edge")
    for name in ("centre", "padbox"):
        gl = boxes[name][0] - col_l
        gr = col_r - boxes[name][2]
        ck(abs(gl - gr) <= TOL,
           "%s: margin:0 auto centres it (gaps %d vs %d)" % (name, gl, gr))

    # --- box-sizing:border-box (M1903) --------------------------------------
    # With border-box the specified width INCLUDES the padding, so the box is
    # exactly 400px wide -- not 440px as the same declaration gives under the
    # default content-box (asserted above as `padbox`).
    ck(abs(width("bordbox") - 400) <= TOL,
       "border-box: width:400px + padding:20px stays a 400px box (got %d)" % width("bordbox"))
    ck(width("padbox") - width("bordbox") >= 2 * 20 - TOL,
       "border-box differs from content-box by the padding (%d vs %d)"
       % (width("padbox"), width("bordbox")))

    # --- margin-bottom (M1903) ----------------------------------------------
    # It was previously dropped entirely. It must push the FOLLOWING block down,
    # and it lives outside the background, so it must NOT enlarge its own box.
    gap = boxes["after_mb"][1] - boxes["mb"][3] - 1
    ck(gap >= 60 - 8,
       "margin-bottom:60px separates it from the next block (gap %d)" % gap)
    ck((boxes["mb"][3] - boxes["mb"][1] + 1) < 60,
       "margin-bottom stays OUTSIDE its own background (box height %d)"
       % (boxes["mb"][3] - boxes["mb"][1] + 1))

    # --- CSS height on a block (M1904) --------------------------------------
    def height(n):
        _, t, _, bt = boxes[n]
        return bt - t + 1
    # One line of text is ~18px, so an 80px box proves the height was honoured AND
    # that the BACKGROUND was stretched to cover it — the background's extent comes
    # from the forward scan, which is where the first attempt at this silently
    # skipped the stretch.
    ck(abs(height("h80") - 80) <= 4,
       "height:80px sets the block's height (got %d)" % height("h80"))
    # border-box: the declared 80px INCLUDES the 2x15px padding, so still 80 total.
    ck(abs(height("h80bb") - 80) <= 4,
       "height:80px + padding:15px + border-box stays 80px tall (got %d)" % height("h80bb"))

    # --- min-height (M1905) --------------------------------------------------
    # One line is ~18px, so a 70px box proves min-height raised the used height.
    ck(abs(height("minh") - 70) <= 4,
       "min-height:70px raises a short block to 70px (got %d)" % height("minh"))
    # §10.7 precedence: min-height only ever RAISES. With height:90px already above
    # the 20px minimum, height wins and the box stays 90px.
    ck(abs(height("minh_lose") - 90) <= 4,
       "min-height:20px does not shrink height:90px (got %d)" % height("minh_lose"))

    # --- blocks must not overlap vertically (M1905) --------------------------
    # This closes a real coverage gap. Every height assertion above measures a
    # BACKGROUND, whose extent comes from the renderer's forward scan — so a bug in
    # the MAIN loop's cursor advance is invisible to them (found by a mutation that
    # broke only the main loop and still passed everything). The main loop is what
    # positions FOLLOWING content, so consecutive blocks overlapping is exactly its
    # failure signature. Page 2's blocks are in source order, so their boxes must be
    # strictly stacked.
    seq = ["bordbox", "mb", "after_mb", "h80", "h80bb", "minh", "minh_lose", "sentinel"]
    for prev, nxt in zip(seq, seq[1:]):
        ck(boxes[nxt][1] >= boxes[prev][3],
           "%s starts at or below %s's bottom, no overlap (%d vs %d)"
           % (nxt, prev, boxes[nxt][1], boxes[prev][3]))

    # --- max-height (M1910) --------------------------------------------------
    # The property that SHRINKS a box. Deliberately measured by the FOLLOWER's top
    # rather than by the clamped block's own background height, for two reasons:
    #   1. it is the flow advance that max-height changes, and the flow advance is
    #      what positions everything after it -- the MAIN LOOP, not the background's
    #      forward scan. A mutation that clamped only the scan would pass a
    #      height-of-the-background check and fail this one (see the M1905 lesson).
    #   2. glyphs paint their own background rect in the block's colour, so text
    #      spilling below the cap still emits that colour; the clamped block's own
    #      bbox is therefore not a clean measure of its box.
    def advance(a, b_):
        return boxes[b_][1] - boxes[a][1]
    # Consecutive blocks are separated by a block break, which advances by one line
    # box before the next block's box begins -- so a block's top-to-top advance is
    # its own height PLUS that break. Measured 18px, the same one-line constant the
    # height checks above rely on. (Verified against every page-3 pair: a one-line
    # block advances 36 = 18 + 18.)
    BREAK = 18
    # ~5 lines of text (~90px) capped at 40px: the follower must sit at the cap.
    ck(abs(advance("maxh", "after_max") - (40 + BREAK)) <= 6,
       "max-height:40px clamps the block's flow advance to 40px, so the next block "
       "starts at the cap (advance %d, expected %d; unclamped would be ~108)"
       % (advance("maxh", "after_max"), 40 + BREAK))
    # And the painted box must not extend past the cap either. This is a SEPARATE
    # failure mode from the advance: content spilling below the cap still paints its
    # glyph background in the block's colour unless the renderer suppresses it, which
    # would leave the box looking like it never clamped at all.
    ck(height("maxh") <= 40 + 6,
       "max-height:40px also caps the PAINTED box, so spilled text carries no block "
       "background (got %d)" % height("maxh"))
    # A max-height far above the content must NOT stretch the box (it only ever
    # lowers): one line stays one line.
    ck(height("maxh_loose") <= 30,
       "max-height:400px does not stretch a one-line block (got %d)" % height("maxh_loose"))
    # CSS 2.1 §10.7 order: max-height is applied first, then min-height overrides
    # it -- so a min-height LARGER than the max-height wins outright.
    ck(abs(height("maxh_min") - 70) <= 6,
       "min-height:70px beats max-height:20px per §10.7 (got %d)" % height("maxh_min"))
    # border-box: the 60px cap INCLUDES the 2x10px padding.
    # NB: measured against `clip`, which is maxh_bb's immediate successor in the
    # fixture -- M1917 inserted the overflow cases between maxh_bb and the tail
    # sentinel, and an advance assertion is only meaningful between ADJACENT blocks.
    ck(abs(advance("maxh_bb", "clip") - (60 + BREAK)) <= 6,
       "max-height:60px + padding:10px + border-box caps the total at 60px "
       "(advance %d, expected %d)" % (advance("maxh_bb", "clip"), 60 + BREAK))
    # --- overflow:hidden clips to the box (M1917) -----------------------------
    # The decisive check is an ABSENCE. A <span> with its own background sits late
    # in a max-height:40px; overflow:hidden block, i.e. below the cap, so if
    # clipping works its colour never reaches the framebuffer at all. Asserting a
    # colour is missing is much stronger than asserting a box got shorter -- a
    # box can shrink for many reasons, but this colour can only appear if content
    # outside the box was painted.
    # The clipped block's ENTIRE text is wrapped in a span with its own background,
    # so that colour's bbox IS the painted-content extent. Asserting it stays inside
    # the box is stronger than asserting some far-below marker is absent: it also
    # catches the line that STRADDLES the clip bottom, which the first version of
    # this test missed entirely and a screenshot caught.
    ck(boxes["clipdeep"][3] <= boxes["clip"][3] + TOL,
       "overflow:hidden keeps ALL painted content inside the box (content bottom %d "
       "vs box bottom %d)" % (boxes["clipdeep"][3], boxes["clip"][3]))
    ck(abs(height("clip") - 40) <= 6,
       "the clipped block is still 40px tall (got %d)" % height("clip"))
    ck(abs(advance("clip", "afterclip") - (40 + BREAK)) <= 6,
       "overflow:hidden does not change the flow advance, only what paints "
       "(advance %d, expected %d)" % (advance("clip", "afterclip"), 40 + BREAK))

    # Page 3 must also be strictly stacked (same main-loop coverage argument).
    seq3 = ["maxh", "after_max", "maxh_loose", "maxh_min", "maxh_bb", "clip", "afterclip", "tail"]
    for prev, nxt in zip(seq3, seq3[1:]):
        ck(boxes[nxt][1] >= boxes[prev][1],
           "%s starts at or below %s's top, source order preserved (%d vs %d)"
           % (nxt, prev, boxes[nxt][1], boxes[prev][1]))

    # --- float + clear (M1928) -----------------------------------------------
    # The decisive pair: text beside a left float must start to the RIGHT of the
    # image AND overlap it vertically. Either alone is weak -- text below the
    # image also "starts to the right" of nothing, and text that merely overlaps
    # vertically could still be painted through the picture.
    fi, wt = boxes["floatimg"], boxes["wraptext"]
    ck(wt[0] > fi[2],
       "text beside a left float starts to the RIGHT of the image (text x=%d, image right=%d)"
       % (wt[0], fi[2]))
    ck(wt[1] < fi[3],
       "...and overlaps it vertically, i.e. it wraps ALONGSIDE rather than below "
       "(text top=%d, image bottom=%d)" % (wt[1], fi[3]))
    # clear:both must drop the following block past the float entirely.
    ck(boxes["cleared"][1] >= fi[3],
       "clear:both drops the next block below the float (cleared top=%d, image bottom=%d)"
       % (boxes["cleared"][1], fi[3]))

    # --- box geometry from a stylesheet RULE + viewport units (M1929) --------
    # Until now width/margin:auto only worked from an inline style= attribute, so
    # a stylesheet could not lay a page out at all. The reference block (no width)
    # gives the column these are measured against, so the vw assertion stays
    # relative rather than hard-coding a window size.
    colw = width("ruleref")
    ck(abs(width("rulew") - 300) <= TOL,
       "width:300px from a stylesheet rule is honoured (got %d)" % width("rulew"))
    gl = boxes["rulew"][0] - boxes["ruleref"][0]
    gr = boxes["ruleref"][2] - boxes["rulew"][2]
    ck(abs(gl - gr) <= TOL + 1,
       "margin:0 auto from a stylesheet rule centres it (gaps %d vs %d)" % (gl, gr))
    ck(abs(width("rulevw") - colw * 40 / 100) <= 8,
       "width:40vw resolves against the viewport (got %d, column %d)" % (width("rulevw"), colw))

    # Padding and height from a rule too (M1930): padding is part of the 10.3.3
    # width constraint, so 200 content + 2x25 padding is a 250px box.
    ck(abs(width("rulepad") - 250) <= TOL,
       "padding:25px from a stylesheet rule widens the box to 250px (got %d)" % width("rulepad"))
    ck(abs(height("ruleht") - 70) <= 4,
       "height:70px from a stylesheet rule is honoured (got %d)" % height("ruleht"))

    # display:flex REPLACES display:list-item, so a flex <li> generates no marker
    # (M1931). Measured as a position: with the bullet gone its text starts further
    # left than the same text in a plain <li>, at the same indent.
    ck(boxes["liflex"][0] < boxes["liplain"][0],
       "a display:flex <li> has no bullet marker, so its text starts further left "
       "(flex x=%d vs plain x=%d)" % (boxes["liflex"][0], boxes["liplain"][0]))

    # --- a nested background stays inside its padded parent ------------------
    il, it, ir, ib = boxes["wide_in"]
    ck(il > col_l and ir < col_r,
       "nested bg paints its OWN box, inset within the padded parent")
    ck(abs((il - col_l) - 40) <= 6,
       "nested bg is inset by the parent's 40px padding (got %d)" % (il - col_l))

    # --- the border is the OUTERMOST edge -----------------------------------
    bl, bt, br, bb_ = boxes["border"]
    pl, pt, pr, pb = boxes["bordered"]
    ck(bl <= pl and br >= pr,
       "border encloses its background horizontally (%d..%d vs %d..%d)" % (bl, br, pl, pr))
    ck(bt <= pt and bb_ >= pb,
       "border encloses its background vertically (%d..%d vs %d..%d)" % (bt, bb_, pt, pb))

    # --- vertical padding is INSIDE the background --------------------------
    # The padded block's background must be taller than one line box; a padding
    # band that leaked outside it (pre-M1900) left the background hugging the text.
    ck((pb - pt + 1) > 2 * 30,
       "padded block's background is taller than its 2x30px padding (got %d)" % (pb - pt + 1))

    print("%d checks, %d failures" % (checks, len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
