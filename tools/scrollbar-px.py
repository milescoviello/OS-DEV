#!/usr/bin/env python3
"""How much non-background sits in the browser's right-hand scrollbar column?

Used by ffprobe-input.sh to prove a page is scrollable BEFORE testing whether
the wheel scrolled it. A wheel arm on an unscrollable document cannot fail,
and that is exactly how the first version of tools/lx/ffinput.html shipped.
"""
import sys

d = open(sys.argv[1], 'rb').read()
f = d.split(b'\n', 3)
w, h = map(int, f[1].split())
b = f[3]
best = 0
for x in range(w - 30, w - 6):
    n = 0
    for y in range(200, h - 60):
        i = ((y * w) + x) * 3
        if i + 3 <= len(b) and b[i:i+3] not in (b'\x10\x18\x20', b'\x00\x00\x00'):
            n += 1
    best = max(best, n)
print(best)
