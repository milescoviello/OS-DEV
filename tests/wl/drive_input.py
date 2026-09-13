#!/usr/bin/env python3
"""Drive REAL input at the VM and assert it reaches the Wayland client (M1983).

A window a client can draw into but not be typed into is not a usable window,
so this is the half of the display path that Firefox needs and pixels alone do
not prove.

The interesting part is that nothing here is hardcoded to where the window
happens to be. The client's surface is a colour nothing in the desktop theme
uses, so the script screendumps, FINDS the surface on screen, and then aims the
mouse at a known offset inside it. What comes back out of the client is a
SURFACE-relative coordinate -- so asserting it matches the offset we aimed at
checks the whole chain of arithmetic (screen -> window -> surface) rather than
just "an event arrived".

Sequence, in order, because each step tests something the previous one cannot:
  move inside   -> wl_pointer.enter + motion at the offset we aimed at
  move outside  -> wl_pointer.leave  (pointer focus follows the cursor)
  move inside   -> a SECOND enter    (a leave that cannot be undone is a bug)
  click         -> wl_pointer.button with BTN_LEFT (0x110)
  press 'a'     -> wl_keyboard.key with evdev keycode 30, not the character
"""
import json, os, re, socket, sys, time

SCREEN_W, SCREEN_H = 1280, 960
WANT = (0x33, 0x66, 0xCC)          # the client's fill colour
EXP_W, EXP_H = 64, 32
OFF_X, OFF_Y = 20, 12              # where inside the surface we aim
TOL = 3                            # abs-axis quantisation is lossy at 1/32767

class Qmp:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX); self.s.connect(path)
        self.f = self.s.makefile("rw")
        self.f.readline()
        self._cmd({"execute": "qmp_capabilities"})
    def _cmd(self, o):
        self.f.write(json.dumps(o) + "\n"); self.f.flush()
        while True:                            # skip asynchronous events
            line = self.f.readline()
            if not line: return None
            r = json.loads(line)
            if "return" in r or "error" in r: return r
    def ev(self, events):
        self._cmd({"execute": "input-send-event", "arguments": {"events": events}})
    def move(self, x, y):
        self.ev([{"type": "abs", "data": {"axis": "x", "value": x * 32767 // SCREEN_W}},
                 {"type": "abs", "data": {"axis": "y", "value": y * 32767 // SCREEN_H}}])
    def click(self):
        self.ev([{"type": "btn", "data": {"down": True,  "button": "left"}}]); time.sleep(0.2)
        self.ev([{"type": "btn", "data": {"down": False, "button": "left"}}])
    def key(self, qcode):
        self._cmd({"execute": "send-key",
                   "arguments": {"keys": [{"type": "qcode", "data": qcode}]}})
    def screendump(self, path):
        try: os.unlink(path)
        except OSError: pass
        self._cmd({"execute": "screendump", "arguments": {"filename": path}})

def find_surface(path):
    """Return the top-left of the client's surface on screen, or None."""
    try: d = open(path, 'rb').read()
    except OSError: return None
    parts = d.split(b'\n', 3)
    if len(parts) < 4 or parts[0] != b'P6': return None
    w, h = map(int, parts[1].split()); px = parts[3]
    xs, ys = [], []
    for y in range(h):
        base = y * w * 3
        for x in range(w):
            i = base + x * 3
            if (px[i], px[i+1], px[i+2]) == WANT: xs.append(x); ys.append(y)
    if not xs: return None
    if max(xs) - min(xs) + 1 != EXP_W or max(ys) - min(ys) + 1 != EXP_H: return None
    return min(xs), min(ys)

def wait_for(log, pat, secs):
    """Wait for a regex in the serial log; return the match or None."""
    rx = re.compile(pat)
    end = time.time() + secs
    while time.time() < end:
        try: data = open(log, 'rb').read().decode('utf-8', 'replace')
        except OSError: data = ""
        m = rx.search(data)
        if m: return m
        time.sleep(0.5)
    return None

def main():
    qmp_path, log, ppm = sys.argv[1], sys.argv[2], sys.argv[3]
    q = Qmp(qmp_path)

    # The window appears when the client commits; the desktop then has to paint
    # it. Poll rather than sleep a fixed amount -- under TCG the paint can be
    # seconds late and a fixed sleep is how monitor-driven suites go flaky.
    origin = None
    for _ in range(20):
        q.screendump(ppm); time.sleep(1.0)
        origin = find_surface(ppm)
        if origin: break
        time.sleep(2.0)
    if not origin:
        print("  FAIL: could not locate the client's surface on screen to aim at"); return 1
    ox, oy = origin
    print("  ok: located the client's surface on screen at (%d,%d) -- aiming input at it" % (ox, oy))

    fail = 0
    q.move(ox + OFF_X, oy + OFF_Y); time.sleep(1.5)
    m = wait_for(log, r"LXWL-MOTION: (-?\d+),(-?\d+)", 30)
    if not m:
        print("  FAIL: the client received no wl_pointer.motion at all"); return 1
    gx, gy = int(m.group(1)), int(m.group(2))
    if abs(gx - OFF_X) <= TOL and abs(gy - OFF_Y) <= TOL:
        print("  ok: the pointer arrived at SURFACE-relative (%d,%d) for an aim of (%d,%d)"
              % (gx, gy, OFF_X, OFF_Y))
    else:
        print("  FAIL: aimed at surface offset (%d,%d) but the client reports (%d,%d)"
              % (OFF_X, OFF_Y, gx, gy)); fail = 1
    if not wait_for(log, r"LXWL-INPUT: pointer entered at", 10):
        print("  FAIL: no wl_pointer.enter -- a client drops input for a surface it was never entered into"); fail = 1
    else:
        print("  ok: wl_pointer.enter preceded the motion")

    # OUT of the surface: pointer focus follows the cursor, so this must leave.
    q.move(ox + 400, oy + 300); time.sleep(1.5)
    if wait_for(log, r"LXWL-LEAVE: pointer left the surface", 20):
        print("  ok: moving off the surface sent wl_pointer.leave")
    else:
        print("  FAIL: the cursor left the surface and the client was never told"); fail = 1

    # ...and back in, which must produce a SECOND enter.
    q.move(ox + OFF_X, oy + OFF_Y); time.sleep(1.5)
    data = open(log, 'rb').read().decode('utf-8', 'replace')
    if data.count("LXWL-INPUT: pointer entered at") >= 2:
        print("  ok: moving back on sent a second wl_pointer.enter -- focus tracks the cursor")
    else:
        print("  FAIL: the pointer re-entered the surface but no second enter arrived"); fail = 1

    q.click(); time.sleep(1.0)
    if wait_for(log, r"LXWL-BUTTON: 0x110 pressed", 30):
        print("  ok: a real mouse click arrived as wl_pointer.button BTN_LEFT (0x110)")
    else:
        print("  FAIL: the click never reached the client"); fail = 1

    q.key("a"); time.sleep(1.0)
    if wait_for(log, r"LXWL-KEY: evdev keycode 30 pressed", 30):
        print("  ok: pressing 'a' arrived as wl_keyboard.key evdev keycode 30 -- a KEYCODE, not a character")
    else:
        print("  FAIL: the keystroke never reached the client"); fail = 1

    # The whole point of the keymap: the client turns the keycode into TEXT,
    # with the same library GTK uses. A compositor that sends keycodes and no
    # keymap gets a client that can be typed at and understands nothing.
    m = wait_for(log, r'LXWL-XKB-KEY: evdev 30 -> keysym (\S+), text "([^"]*)"', 30)
    if m and m.group(1) == "a" and m.group(2) == "a":
        print("  ok: libxkbcommon turned that keycode into keysym 'a' and the text \"a\" -- real text input")
    elif m:
        print("  FAIL: evdev 30 became keysym %s / text %r, expected 'a' and \"a\""
              % (m.group(1), m.group(2))); fail = 1
    else:
        print("  FAIL: the client never translated the keycode through the keymap"); fail = 1

    m = wait_for(log, r"LXWL-INPUT-RESULT: (\d+) key event\(s\), (\d+) motion, (\d+) button", 30)
    if m:
        print("  ok: the client's own tally: %s key, %s motion, %s button" % m.groups())
    else:
        print("  FAIL: the client never reported its input tally"); fail = 1
    return fail

if __name__ == "__main__":
    sys.exit(main())
