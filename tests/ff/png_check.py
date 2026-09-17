#!/usr/bin/env python3
"""Decode the PNG Gecko rendered inside OS-DEV and assert the PAGE is in it.

The image leaves the guest as HEX over the serial line, because it is written
to a `-snapshot` disk that is discarded at power off -- so there is nothing to
copy out afterwards and the log is the only channel.

What makes this an assertion rather than a smoke test is that it checks the
page's OWN colours, in proportion. A valid PNG of the right size proves the
encoder ran; it was true for a whole campaign while the on-screen content area
was blank. #101820 covering most of the image proves a stylesheet was cascaded
onto the body, and #4fd1c5 present in quantity proves text was laid out and
rasterised in the colour the stylesheet asked for -- parse, cascade, layout,
shape, paint. (M2118)
"""
import re, sys, zlib, struct, collections

WANT_BG   = (0x10, 0x18, 0x20)      # body { background:#101820 }
WANT_H1   = (0x4f, 0xd1, 0xc5)      # h1 { color:#4fd1c5 }
MIN_BG_PC = 40                      # the background is most of a 400x300 viewport
MIN_H1_PX = 500                     # a 44px heading over two lines is thousands of pixels

def extract(logpath):
    raw = open(logpath, "rb").read().decode("latin1")
    i = raw.find("FFSHOT-PNGBEGIN")
    j = raw.find("FFSHOT-PNGEND", i)
    if i < 0 or j < 0:
        return None, "no PNG was dumped (FFSHOT-PNGBEGIN/PNGEND missing)"
    seg = raw[raw.find("\n", i) + 1 : j]
    hx = "".join(l.strip() for l in seg.split("\n")
                 if re.fullmatch(r"[0-9a-f]+", l.strip()))
    if len(hx) < 64:
        return None, "the PNG hex dump is empty or truncated (%d chars)" % len(hx)
    return bytes.fromhex(hx[: len(hx) // 2 * 2]), None

def decode(d):
    if d[:8] != b"\x89PNG\r\n\x1a\n":
        return None, None, None, "not a PNG (magic is %s)" % d[:8].hex()
    pos, idat, w, h, ct = 8, b"", None, None, None
    while pos < len(d):
        ln, typ = struct.unpack(">I4s", d[pos:pos + 8]); pos += 8
        body = d[pos:pos + ln]; pos += ln + 4
        if typ == b"IHDR":
            w, h, _bd, ct = struct.unpack(">IIBB", body[:10])
        elif typ == b"IDAT":
            idat += body
        elif typ == b"IEND":
            break
    if ct != 6:
        return None, None, None, "expected RGBA (colour type 6), got %s" % ct
    raw = zlib.decompress(idat)
    nch, stride = 4, w * 4
    out, prev, p = bytearray(), bytearray(stride), 0
    for _y in range(h):
        f = raw[p]; p += 1
        line = bytearray(raw[p:p + stride]); p += stride
        if f == 1:
            for x in range(nch, stride): line[x] = (line[x] + line[x - nch]) & 255
        elif f == 2:
            for x in range(stride): line[x] = (line[x] + prev[x]) & 255
        elif f == 3:
            for x in range(stride):
                a = line[x - nch] if x >= nch else 0
                line[x] = (line[x] + ((a + prev[x]) >> 1)) & 255
        elif f == 4:
            for x in range(stride):
                a = line[x - nch] if x >= nch else 0
                b, c = prev[x], (prev[x - nch] if x >= nch else 0)
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[x] = (line[x] + pr) & 255
        out += line; prev = line
    return out, w, h, None

def main(logpath):
    d, err = extract(logpath)
    if err:
        print("  FAIL: %s" % err); return 1
    px, w, h, err = decode(d)
    if err:
        print("  FAIL: %s" % err); return 1
    print("  ok: Gecko produced a %dx%d PNG (%d bytes) and it decodes" % (w, h, len(d)))
    cnt = collections.Counter()
    for y in range(h):
        for x in range(w):
            i = (y * w + x) * 4
            cnt[(px[i], px[i + 1], px[i + 2])] += 1
    total = w * h
    bg, h1 = cnt[WANT_BG], cnt[WANT_H1]
    bgpc = bg * 100 // total
    for c, n in cnt.most_common(4):
        print("      #%02x%02x%02x  %6d  (%d%%)" % (c[0], c[1], c[2], n, n * 100 // total))
    rc = 0
    if bgpc >= MIN_BG_PC:
        print("  ok: %d%% of the page is #101820 -- the stylesheet's body background was CASCADED" % bgpc)
    else:
        print("  FAIL: only %d%% is #101820 (want >=%d%%) -- the body background did not apply"
              % (bgpc, MIN_BG_PC)); rc = 1
    if h1 >= MIN_H1_PX:
        print("  ok: %d pixels of #4fd1c5 -- the heading was LAID OUT and RASTERISED in its styled colour" % h1)
    else:
        print("  FAIL: only %d pixels of #4fd1c5 (want >=%d) -- no styled text was painted"
              % (h1, MIN_H1_PX)); rc = 1
    return rc

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
