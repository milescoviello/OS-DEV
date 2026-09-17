#!/usr/bin/env python3
"""Assert a Wayland client's surface is ON SCREEN in the OS-DEV desktop.

The client fills its buffer with 0x3366CC -- a colour nothing in the desktop
theme uses -- so finding exactly its dimensions' worth of that colour, in one
contiguous block, means the pixels travelled: client memfd -> SCM_RIGHTS ->
compositor mapping -> window blit -> framebuffer.

Checking the COUNT and the BOUNDING BOX rather than "some blue is present" is
what makes this a real assertion: a stretched, clipped, torn or wrongly-strided
blit all produce blue pixels, and all produce the wrong shape.
"""
import sys

WANT = (0x33, 0x66, 0xCC)
EXP_W, EXP_H = 64, 32
# THE SUBSURFACE SITS ON TOP OF THE PARENT (M2094). lxwl now creates a real
# child surface -- 16x8 of 0x22DD55, placed at +8,+4 inside the toplevel --
# because M2089 taught the compositor that a window is a TREE and nothing in
# this suite exercised that. The child COVERS 128 of the parent's pixels, so
# the parent's count is 2048-128 and finding exactly 2048 would now mean the
# child was NOT drawn. Both counts are asserted, which makes this a stronger
# check than it was: it proves the parent's blit is whole, the child's blit
# lands, and the child lands in the right PLACE.
CHILD = (0x22, 0xDD, 0x55)
CHILD_W, CHILD_H = 16, 8
CHILD_DX, CHILD_DY = 8, 4

def main(path):
    d = open(path, 'rb').read()
    parts = d.split(b'\n', 3)
    if parts[0] != b'P6':
        print("  FAIL: not a P6 PPM"); return 1
    w, h = map(int, parts[1].split())
    px = parts[3]
    hits = []
    for y in range(h):
        base = y * w * 3
        for x in range(w):
            i = base + x * 3
            if (px[i], px[i+1], px[i+2]) == WANT:
                hits.append((x, y))
    if not hits:
        print("  FAIL: the client's colour 0x3366CC is not on screen at all")
        return 1
    xs = [p[0] for p in hits]; ys = [p[1] for p in hits]
    bw, bh = max(xs) - min(xs) + 1, max(ys) - min(ys) + 1
    print("  ok: found %d pixels of the client's colour in a %dx%d block at (%d,%d)"
          % (len(hits), bw, bh, min(xs), min(ys)))
    if (bw, bh) != (EXP_W, EXP_H):
        print("  FAIL: the block is %dx%d but the surface is %dx%d -- the blit is scaled or clipped"
              % (bw, bh, EXP_W, EXP_H))
        return 1
    # Find the child, and locate it relative to the parent's origin.
    chits = []
    for y in range(h):
        base = y * w * 3
        for x in range(w):
            i = base + x * 3
            if (px[i], px[i+1], px[i+2]) == CHILD:
                chits.append((x, y))
    want_parent = EXP_W * EXP_H - CHILD_W * CHILD_H
    if not chits:
        print("  FAIL: the SUBSURFACE's colour 0x22DD55 is not on screen -- a window is a tree of")
        print("        surfaces and only the root was drawn (M2089/M2094)")
        return 1
    cxs = [p[0] for p in chits]; cys = [p[1] for p in chits]
    cbw, cbh = max(cxs) - min(cxs) + 1, max(cys) - min(cys) + 1
    print("  ok: found %d pixels of the SUBSURFACE's colour in a %dx%d block at (%d,%d)"
          % (len(chits), cbw, cbh, min(cxs), min(cys)))
    if (cbw, cbh) != (CHILD_W, CHILD_H) or len(chits) != CHILD_W * CHILD_H:
        print("  FAIL: the child is %dx%d / %d pixels but should be %dx%d / %d"
              % (cbw, cbh, len(chits), CHILD_W, CHILD_H, CHILD_W * CHILD_H))
        return 1
    if (min(cxs) - min(xs), min(cys) - min(ys)) != (CHILD_DX, CHILD_DY):
        print("  FAIL: the child is at +%d,+%d inside the parent but set_position asked for +%d,+%d"
              % (min(cxs) - min(xs), min(cys) - min(ys), CHILD_DX, CHILD_DY))
        return 1
    print("  ok: the subsurface is at EXACTLY +%d,+%d inside its parent -- set_position is honoured"
          % (CHILD_DX, CHILD_DY))
    if len(hits) != want_parent:
        print("  FAIL: %d pixels of the parent for a %dx%d surface with a %dx%d child on it "
              "(%d expected) -- the blit has holes"
              % (len(hits), EXP_W, EXP_H, CHILD_W, CHILD_H, want_parent))
        return 1
    print("  ok: EXACTLY the parent's %d visible pixels plus the child's %d -- the blit is 1:1 "
          "and the tree composites" % (want_parent, CHILD_W * CHILD_H))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
