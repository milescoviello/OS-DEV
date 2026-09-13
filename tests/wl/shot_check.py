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
    if len(hits) != EXP_W * EXP_H:
        print("  FAIL: %d pixels for a %dx%d surface (%d expected) -- the blit has holes"
              % (len(hits), EXP_W, EXP_H, EXP_W * EXP_H))
        return 1
    print("  ok: EXACTLY the surface's %dx%d pixels, contiguous -- the blit is 1:1" % (EXP_W, EXP_H))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
