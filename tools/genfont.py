#!/usr/bin/env python3
"""Generate kernel/fontext.c: the 128 glyphs at 0x80-0xFF that a TUI draws with.

Every glyph is 8 wide x 16 tall, one row per string, '#' = ink. Written as art
on purpose: a box-drawing set is only correct if the pieces JOIN, and that is
something you check by looking at it, not by reading hex.

Conventions, so the pieces line up:
  - a light horizontal line lives on row 7
  - a light vertical line lives on column 3
  - heavy doubles both (rows 7-8, columns 3-4)
  - double-line uses rows 5 and 9, columns 2 and 5
"""
W, H = 8, 16
HR, VC = 7, 3            # light horizontal row / vertical column

def blank(): return [["."]*W for _ in range(H)]
def hline(g, row=HR, x0=0, x1=W): 
    for x in range(x0, x1): g[row][x] = "#"
def vline(g, col=VC, y0=0, y1=H):
    for y in range(y0, y1): g[col and 0 or 0] = g[col and 0 or 0]
    for y in range(y0, y1): g[y][col] = "#"
def art(g): return ["".join(r) for r in g]

G = {}   # name -> list of 16 strings

def box(name, left=0, right=0, up=0, down=0, heavy=0, dbl=0):
    g = blank()
    rows = [HR, HR+1] if heavy else [HR]
    cols = [VC, VC+1] if heavy else [VC]
    if dbl: rows, cols = [HR-2, HR+2], [VC-1, VC+2]
    for r in rows:
        if left:  hline(g, r, 0, (cols[-1]+1) if (up or down) else W)
        if right: hline(g, r, (cols[0]) if (up or down) else 0, W)
        if left and right and not (up or down): hline(g, r, 0, W)
    for c in cols:
        if up:   vline(g, c, 0, (rows[-1]+1) if (left or right) else H)
        if down: vline(g, c, (rows[0]) if (left or right) else 0, H)
        if up and down and not (left or right): vline(g, c, 0, H)
    G[name] = art(g)

# --- light box drawing -----------------------------------------------------
box("h",  left=1, right=1)                    # U+2500
box("v",  up=1,   down=1)                     # U+2502
box("dr", right=1, down=1)                    # U+250C
box("dl", left=1,  down=1)                    # U+2510
box("ur", right=1, up=1)                      # U+2514
box("ul", left=1,  up=1)                      # U+2518
box("vr", up=1, down=1, right=1)              # U+251C
box("vl", up=1, down=1, left=1)               # U+2524
box("dh", left=1, right=1, down=1)            # U+252C
box("uh", left=1, right=1, up=1)              # U+2534
box("vh", left=1, right=1, up=1, down=1)      # U+253C
# --- heavy + double --------------------------------------------------------
box("Hh", left=1, right=1, heavy=1)           # U+2501
box("Hv", up=1, down=1, heavy=1)              # U+2503
box("Dh", left=1, right=1, dbl=1)             # U+2550
box("Dv", up=1, down=1, dbl=1)                # U+2551

# --- rounded corners: same joins, one pixel pulled in ----------------------
def rounded(name, hx, vy):
    g = blank()
    if hx > 0: hline(g, HR, VC+1, W)
    else:      hline(g, HR, 0, VC)
    if vy > 0: vline(g, VC, HR+1, H)
    else:      vline(g, VC, 0, HR)
    g[HR][VC] = "#"                            # the elbow pixel itself
    G[name] = art(g)
rounded("rdr",  1,  1)   # U+256D  .-
rounded("rdl", -1,  1)   # U+256E  -.
rounded("rul", -1, -1)   # U+256F  -'
rounded("rur",  1, -1)   # U+2570  '-

# --- blocks and shades -----------------------------------------------------
def fill(name, pred):
    g = blank()
    for y in range(H):
        for x in range(W):
            if pred(x, y): g[y][x] = "#"
    G[name] = art(g)
fill("full",  lambda x, y: True)                       # U+2588
fill("upper", lambda x, y: y < H//2)                   # U+2580
fill("lower", lambda x, y: y >= H//2)                  # U+2584
fill("lefth", lambda x, y: x < W//2)                   # U+258C
fill("righth",lambda x, y: x >= W//2)                  # U+2590
fill("light", lambda x, y: (x + y) % 4 == 0)           # U+2591 25%
fill("med",   lambda x, y: (x + y) % 2 == 0)           # U+2592 50%
fill("dark",  lambda x, y: (x + y) % 4 != 0)           # U+2593 75%
for i, nm in enumerate(["b18","b28","b38","b48","b58","b68","b78"], start=1):
    fill(nm, (lambda k: (lambda x, y: x < (k*W)//8))(i))   # U+2589..258F left eighths
fill("ltop",  lambda x, y: y < 2)                      # U+2594 upper eighth
fill("lbot",  lambda x, y: y >= H-2)                   # U+2581 lower eighth

# --- geometric shapes ------------------------------------------------------
def disc(name, r, filled=True):
    g = blank(); cx, cy = 3.5, 7.5
    for y in range(H):
        for x in range(W):
            d = ((x-cx)**2 + ((y-cy)*0.5)**2) ** 0.5
            if (d <= r) if filled else (r-0.7 <= d <= r): g[y][x] = "#"
    G[name] = art(g)
disc("cirf", 3.2, True)          # U+25CF filled circle
disc("ciro", 3.2, False)         # U+25CB open circle
disc("dotm", 1.6, True)          # U+2022 bullet / U+00B7 middot
def rect(name, x0, x1, y0, y1, filled=True):
    g = blank()
    for y in range(y0, y1):
        for x in range(x0, x1):
            if filled or x in (x0, x1-1) or y in (y0, y1-1): g[y][x] = "#"
    G[name] = art(g)
rect("sqf", 1, 7, 4, 12, True)        # U+25A0 filled square
rect("sqo", 1, 7, 4, 12, False)       # U+25A1 open square
rect("sqs", 2, 6, 6, 10, True)        # U+25AA small filled square
def tri(name, d):
    g = blank()
    if d == "r":
        for y in range(3, 13):
            k = min(y-3, 12-y)
            for x in range(1, 2+k): g[y][x] = "#"
    if d == "l":
        for y in range(3, 13):
            k = min(y-3, 12-y)
            for x in range(6-k, 7): g[y][x] = "#"
    if d == "u":
        for y in range(4, 12):
            k = y-4
            for x in range(3-k//2, 5+k//2): 
                if 0 <= x < W: g[y][x] = "#"
    if d == "d":
        for y in range(4, 12):
            k = 11-y
            for x in range(3-k//2, 5+k//2):
                if 0 <= x < W: g[y][x] = "#"
    G[name] = art(g)
tri("trir", "r"); tri("tril", "l"); tri("triu", "u"); tri("trid", "d")
def diamond(name):
    g = blank()
    for y in range(2, 14):
        k = 6 - abs(y-8)
        if k < 0: continue
        for x in range(max(0,3-k//1), min(W,5+k//1)): g[y][x] = "#"
    G[name] = art(g)
diamond("diam")                        # U+25C6

# --- marks -----------------------------------------------------------------
G["check"] = ["........","........","........",".......#","......##",".....##.","#...##..",".#.##...",
              ".####...","..##....","........","........","........","........","........","........"]
G["cross"] = ["........","........","........","#......#",".#....#.","..#..#..","...##...","...##...",
              "..#..#..",".#....#.","#......#","........","........","........","........","........"]
G["star"]  = ["........","........","...#....","...#....","#..#..#.",".#.#.#..","..###...","#######.",
              "..###...",".#.#.#..","#..#..#.","...#....","...#....","........","........","........"]
G["aster"] = ["........","........","........","...#....","#..#..#.",".#.#.#..","..###...",".#####..",
              "..###...",".#.#.#..","#..#..#.","...#....","........","........","........","........"]
G["arrr"]  = ["........","........","........","........","....#...","......#.","########","......#.",
              "....#...","........","........","........","........","........","........","........"]
G["arrl"]  = ["........","........","........","........","...#....",".#......","########",".#......",
              "...#....","........","........","........","........","........","........","........"]
G["arru"]  = ["........","...#....","..###...",".#.#.#..","#..#..#.","...#....","...#....","...#....",
              "...#....","...#....","...#....","...#....","........","........","........","........"]
G["arrd"]  = ["........","...#....","...#....","...#....","...#....","...#....","...#....","...#....",
              "...#....","#..#..#.",".#.#.#..","..###...","...#....","........","........","........"]
G["ell"]   = ["........","........","........","........","........","........","........","........",
              "........","........","#.#.#...","........","........","........","........","........"]
G["deg"]   = ["........",".###....","#...#...","#...#...","#...#...",".###....","........","........",
              "........","........","........","........","........","........","........","........"]
G["rec"]   = ["........","........","........","..##....",".####...","######..",".####...","..##....",
              "........","........","........","........","........","........","........","........"]
G["gutter"]= ["........","........","........","...#....","...#....","...#....","...#....","...#....",
              "...#....","...####.","........","........","........","........","........","........"]

# --- braille spinner frames: real 2x4 dot grids ---------------------------
# U+28xx: bit0..bit7 -> dots 1,2,3,7 (left column top..bottom) and 4,5,6,8 (right)
BR_XY = [(1,2),(1,6),(1,10),(5,2),(5,6),(5,10),(1,14),(5,14)]
def braille(bits):
    g = blank()
    for i in range(8):
        if bits & (1 << i):
            bx, by = BR_XY[i]
            for dy in range(2):
                for dx in range(2): g[by+dy][bx+dx] = "#"
    return art(g)

SPIN = [0x02,0x03,0x07,0x06,0x0E,0x0C,0x1C,0x18,0x38,0x30]   # the frames Ink's "dots" uses
for i, b in enumerate(SPIN): G["spin%d" % i] = braille(b)

# --- assemble the table in a fixed order; emit C ---------------------------
ORDER = ["h","v","dr","dl","ur","ul","vr","vl","dh","uh","vh",
         "Hh","Hv","Dh","Dv","rdr","rdl","rul","rur",
         "full","upper","lower","lefth","righth","light","med","dark",
         "b18","b28","b38","b48","b58","b68","b78","ltop","lbot",
         "cirf","ciro","dotm","sqf","sqo","sqs","trir","tril","triu","trid","diam",
         "check","cross","star","aster","arrr","arrl","arru","arrd","ell","deg","rec","gutter"]
ORDER += ["spin%d" % i for i in range(10)]
assert len(ORDER) == len(set(ORDER))
assert len(ORDER) <= 128, len(ORDER)

# Unicode code point -> slot name. Everything not listed falls back to ASCII in
# the C helper below.
CP = {
 0x2500:"h",0x2501:"Hh",0x2502:"v",0x2503:"Hv",0x250C:"dr",0x250D:"dr",0x250E:"dr",0x250F:"dr",
 0x2510:"dl",0x2511:"dl",0x2512:"dl",0x2513:"dl",0x2514:"ur",0x2515:"ur",0x2516:"ur",0x2517:"ur",
 0x2518:"ul",0x2519:"ul",0x251A:"ul",0x251B:"ul",0x251C:"vr",0x2520:"vr",0x2523:"vr",
 0x2524:"vl",0x2528:"vl",0x252B:"vl",0x252C:"dh",0x2533:"dh",0x2534:"uh",0x253B:"uh",
 0x253C:"vh",0x254B:"vh",0x2550:"Dh",0x2551:"Dv",0x2554:"dr",0x2557:"dl",0x255A:"ur",0x255D:"ul",
 0x2560:"vr",0x2563:"vl",0x2566:"dh",0x2569:"uh",0x256C:"vh",
 0x256D:"rdr",0x256E:"rdl",0x256F:"rul",0x2570:"rur",
 0x2574:"h",0x2575:"v",0x2576:"h",0x2577:"v",0x2578:"Hh",0x257A:"Hh",
 0x2580:"upper",0x2581:"lbot",0x2582:"lbot",0x2583:"lower",0x2584:"lower",0x2585:"lower",
 0x2586:"lower",0x2587:"lower",0x2588:"full",0x2589:"b78",0x258A:"b68",0x258B:"b58",
 0x258C:"lefth",0x258D:"b38",0x258E:"b28",0x258F:"b18",0x2590:"righth",
 0x2591:"light",0x2592:"med",0x2593:"dark",0x2594:"ltop",0x2595:"righth",
 0x25A0:"sqf",0x25A1:"sqo",0x25AA:"sqs",0x25AB:"sqo",0x25AC:"sqf",0x25B0:"sqf",
 0x25B2:"triu",0x25B3:"triu",0x25B6:"trir",0x25B7:"trir",0x25B8:"trir",0x25BA:"trir",
 0x25BC:"trid",0x25BD:"trid",0x25C0:"tril",0x25C1:"tril",0x25C2:"tril",0x25C4:"tril",
 0x25C6:"diam",0x25C7:"diam",0x25C8:"diam",0x25C9:"cirf",0x25CB:"ciro",0x25CE:"ciro",
 0x25CF:"cirf",0x25D0:"cirf",0x25E6:"ciro",0x25FC:"sqf",0x25FE:"sqs",
 0x2022:"dotm",0x00B7:"dotm",0x2219:"dotm",0x2027:"dotm",
 0x2026:"ell",0x22EF:"ell",0x2504:"h",0x2505:"Hh",0x2508:"h",
 0x2190:"arrl",0x2192:"arrr",0x2191:"arru",0x2193:"arrd",0x21B5:"arrl",0x27A4:"arrr",
 0x2794:"arrr",0x279C:"arrr",0x23F5:"trir",0x23F4:"tril",0x23F6:"triu",0x23F7:"trid",
 0x2713:"check",0x2714:"check",0x2705:"check",0x221A:"check",
 0x2717:"cross",0x2718:"cross",0x2715:"cross",0x2716:"cross",0x274C:"cross",0x00D7:"cross",
 0x2605:"star",0x2606:"star",0x2727:"aster",0x2731:"aster",0x2732:"aster",0x2733:"aster",
 0x273B:"aster",0x2734:"aster",0x00B0:"deg",0x23FA:"rec",0x26AB:"cirf",0x26AA:"ciro",
 0x23BF:"gutter",0x2514+0x10000:"ur",
 0x2937:"arrd",0x2938:"arrd",
}
for i, b in enumerate(SPIN): CP[0x2800 + b] = "spin%d" % i

# ASCII fallbacks for code points we do NOT have a glyph for. Chosen so a line
# of prose survives: a typographic quote must not become a '?'.
ASCII = {0x2018:"'",0x2019:"'",0x201A:"'",0x201B:"'",0x201C:'"',0x201D:'"',0x201E:'"',
         0x2039:"<",0x203A:">",0x00AB:"<",0x00BB:">",
         0x2013:"-",0x2014:"-",0x2015:"-",0x2212:"-",0x2043:"-",0x00AD:"-",
         0x00A0:" ",0x202F:" ",0x2007:" ",0x2009:" ",0x200A:" ",0x2002:" ",0x2003:" ",
         0x200B:"",0x200C:"",0x200D:"",0xFEFF:"",
         0x2264:"<",0x2265:">",0x2260:"#",0x2248:"~",0x00B1:"+",0x2032:"'",0x2033:'"',
         0x00A9:"c",0x00AE:"r",0x2122:"t",0x20AC:"E",0x00A3:"L",0x00A5:"Y",
         0x2500+0x10000:"-"}

slot = {nm: 0x80 + i for i, nm in enumerate(ORDER)}
out = []
out.append('/* fontext.c -- GENERATED by tools/genfont.py; edit that, not this.\n'
           ' *\n'
           ' * The 8x16 glyphs at 0x80-0xFF: box drawing, blocks, shades, geometric\n'
           ' * shapes, arrows, marks and the ten braille frames Ink\'s spinner cycles\n'
           ' * through. A terminal without these cannot render a modern TUI -- Claude\n'
           ' * Code\'s own onboarding came out as fields of \'?\' -- and, worse, a\n'
           ' * byte-oriented grid charges 3 cells for every 3-byte UTF-8 character, so\n'
           ' * every boxed line was three times too wide and overwrote its neighbours.\n'
           ' * (M2015) */\n'
           '#include "font.h"\n')
out.append("const unsigned char font_ext[128][16] = {")
for i, nm in enumerate(ORDER):
    rows = G[nm]
    assert len(rows) == H, (nm, len(rows))
    vals = []
    for r in rows:
        assert len(r) == W, (nm, r)
        v = 0
        for x, c in enumerate(r):
            if c == "#": v |= 0x80 >> x
        vals.append("0x%02x" % v)
    out.append("    { %s },   /* 0x%02x %s */" % (", ".join(vals), 0x80 + i, nm))
for i in range(len(ORDER), 128):
    out.append("    { 0 },   /* 0x%02x unused */" % (0x80 + i))
out.append("};")
out.append("")
out.append("/* A Unicode code point -> the byte this terminal stores in its grid.\n"
           " * Returns 0 for a code point that should be DROPPED (zero-width), and\n"
           " * falls back to a readable ASCII stand-in rather than '?' wherever one\n"
           " * exists: a typographic quote becoming '?' is worse than it becoming '. */")
out.append("unsigned char font_cp_to_glyph(unsigned long cp) {")
out.append("    if (cp < 0x80) return (unsigned char)cp;")
out.append("    switch (cp) {")
for cp in sorted(CP):
    if cp > 0x10FFFF: continue
    out.append("    case 0x%04lX: return 0x%02x;" % (cp, slot[CP[cp]]))
for cp in sorted(ASCII):
    if cp > 0x10FFFF: continue
    ch = ASCII[cp]
    out.append("    case 0x%04lX: return %s;" % (cp, ("0x%02x" % ord(ch)) if ch else "0"))
out.append("    default: break;")
out.append("    }")
out.append("    /* Whole ranges with one sensible answer. */")
out.append("    if (cp >= 0x2800 && cp <= 0x28FF) return 0x%02x;   /* any braille: a dot cluster */" % slot["spin0"])
out.append("    if (cp >= 0x2500 && cp <= 0x257F) return 0x%02x;   /* any box drawing: a light line */" % slot["h"])
out.append("    if (cp >= 0x2580 && cp <= 0x259F) return 0x%02x;   /* any block element */" % slot["med"])
out.append("    if (cp >= 0x25A0 && cp <= 0x25FF) return 0x%02x;   /* any geometric shape */" % slot["sqs"])
out.append("    if (cp >= 0x2190 && cp <= 0x21FF) return 0x%02x;   /* any arrow */" % slot["arrr"])
out.append("    if (cp >= 0x1F300 && cp <= 0x1FAFF) return 0x%02x; /* an emoji: a filled circle reads as SOMETHING */" % slot["cirf"])
out.append("    return '.';   /* unknown: a period is quieter than a '?' and never misleads */")
out.append("}")
print("\n".join(out))
