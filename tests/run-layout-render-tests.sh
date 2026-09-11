#!/bin/sh
# In-guest regression for the browser's SOLVED box-model geometry (M1902).
#
# The layout RULES are unit-tested off-target (tests/layout), but the browser-side
# wiring had no automated coverage — which is how a background painting the
# content box (M1897), vertical padding landing outside the background (M1900),
# and a border stroking inside its own background (M1901) all coexisted in a
# fully-green tree. Each was caught by a human looking at a screenshot.
#
# This boots the desktop headlessly, opens LAYCHK.HTM (every case in a unique
# background colour), dumps the framebuffer, and asserts the geometry by finding
# each colour's bounding box. Assertions are relative, so window placement and
# desktop chrome can change without breaking them.
#
# SKIPs cleanly if QEMU/python3 are absent. Exit 0 = pass.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
if ! command -v "$QEMU" >/dev/null 2>&1; then echo "SKIP: layout-render test ($QEMU not found)"; exit 0; fi
if ! command -v python3 >/dev/null 2>&1; then echo "SKIP: layout-render test (python3 not found)"; exit 0; fi

OUT=$(mktemp -d /tmp/osdev_layrender.XXXXXX)
cleanup() { rc=$?; rm -rf "$OUT"; exit "$rc"; }
trap cleanup EXIT

# Take THREE dumps in one boot, spaced a few seconds apart, and check the first
# one that actually contains the fixture.
#
# Why: under host load the desktop can still be settling when the keys are
# injected, so the address bar never receives the URL and the dump shows nothing
# at all. That is a harness-timing miss, not a geometry regression, and it is
# cleanly distinguishable — a miss loses EVERY colour, whereas a real regression
# keeps the boxes and moves them. An earlier version rebooted the whole VM to
# retry, which cost ~40s and printed an alarming FAIL into the log on the way;
# extra dumps inside the same boot fix the same problem for a few seconds,
# because time-to-settle is exactly what was missing.
echo "booting the desktop headlessly and opening LAYCHK.HTM..."
# Apps menu (F9) -> Enter opens the Browser -> '/' focuses the address bar.
python3 tools/osdrive.py --out "$OUT" --boot-timeout 60 -c '
sleep 4;
key f9;
sleep 1.5;
key ret;
sleep 4;
key slash;
sleep 1.5;
type file:LAYCHK.HTM;
sleep 1.5;
key ret;
sleep 5;
shot p1a.ppm;
sleep 4;
shot p1b.ppm;
key slash;
sleep 1.5;
type file:LAYCHK2.HTM;
sleep 1.5;
key ret;
sleep 5;
shot p2a.ppm;
sleep 4;
shot p2b.ppm;
key slash;
sleep 1.5;
type file:LAYCHK3.HTM;
sleep 1.5;
key ret;
sleep 5;
shot p3a.ppm;
sleep 4;
shot p3b.ppm;
key slash;
sleep 1.5;
type file:LAYCHK4.HTM;
sleep 1.5;
key ret;
sleep 5;
shot p4a.ppm;
sleep 4;
shot p4b.ppm' >/dev/null 2>&1 || true

dumps=""
for f in p1a p1b p2a p2b p3a p3b p4a p4b; do
    [ -f "$OUT/$f.ppm" ] && dumps="$dumps $OUT/$f.ppm"
done
if [ -z "$dumps" ]; then
    echo "FAIL: no framebuffer dump produced (boot or navigation failed)"; exit 1
fi

echo "checking solved box-model geometry (merged across the captures)..."
# The checker merges the dumps, taking each colour from the first that has it: the
# fixture spans two pages, and a too-early dump simply contributes nothing.
python3 tests/layoutrender/check_geometry.py $dumps && rc=0 || rc=$?

if [ "$rc" = 0 ]; then
    echo "PASS: browser box-model geometry (§10.3.3 used widths incl. padding, auto-margin centring + left/right alignment, box-sizing, margin-bottom, nested background inset, border encloses the padding box)"
else
    echo "FAIL: browser box-model geometry regressed"; exit 1
fi
