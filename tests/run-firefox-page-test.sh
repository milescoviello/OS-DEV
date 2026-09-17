#!/bin/sh
# FIREFOX RENDERS A REAL WEB PAGE INSIDE OS-DEV, and this asserts the PIXELS.
#
# `-append ffshot` runs Gecko headlessly against a staged local document
# (tools/lx/ffpage.html) with `--screenshot`, so the whole engine runs -- HTML
# parsed, a stylesheet cascaded, boxes laid out, text shaped by FreeType, glyphs
# rasterised, the page composited, the result PNG-encoded -- with no display
# server anywhere in the path. The image is then hex-dumped over the serial
# line, because it is written to a `-snapshot` disk that is discarded at power
# off and there is nothing to copy out afterwards.
#
# WHY THE PIXELS AND NOT THE FILE. "A PNG exists and starts with 89 50 4e 47"
# was TRUE for this entire campaign while the on-screen content area was blank,
# so it cannot distinguish a rendered page from a rendered blank one -- which is
# the only distinction that matters. tests/ff/png_check.py decodes the image and
# requires the page's OWN colours in proportion: #101820 over most of the
# viewport (the body background, so the cascade ran) and thousands of pixels of
# #4fd1c5 (the heading, so text was laid out and rasterised in its styled
# colour). (M2118)
set -e
KERNEL=${KERNEL:-build/kernel32.elf}
DISK=${DISK:-build/fat.img}
EXT2=${EXT2:-build/ext2.img}
QEMU=${QEMU:-qemu-system-x86_64}

command -v "$QEMU" >/dev/null 2>&1 || { echo "SKIP: firefox page test ($QEMU not found)"; exit 0; }
[ -f "$EXT2" ] || { echo "SKIP: firefox page test (no $EXT2)"; exit 0; }
[ -f build/lxroot/usr/lib64/firefox/firefox ] || { echo "SKIP: firefox page test (firefox not staged)"; exit 0; }
[ -f build/lxroot/ffpage.html ] || { echo "SKIP: firefox page test (ffpage.html not staged)"; exit 0; }

TMP=$(mktemp -d /tmp/osdev_ffpage.XXXXXX)
SLOG=$TMP/serial.log
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -rf "$TMP"; exit "$rc"; }
trap cleanup EXIT

echo "booting headless and rendering a real page with Gecko (this is slow: it is a browser)..."
# 8 GiB because COW always copies since M2044 and 4G is the measured GC-thrash
# point; -smp 1 because M2106 measured the multi-core corruption this campaign
# has not finished chasing, and a test must not be the place that flakes on it.
timeout -s KILL 1800 "$QEMU" -cpu max -snapshot -no-reboot -no-shutdown -m 8G -smp 1 \
    -kernel "$KERNEL" -append "ffshot lxout noprobes nonetdemo" \
    -drive file="$DISK",format=raw,if=ide \
    -drive file="$EXT2",format=raw,if=ide \
    -display none -serial file:"$SLOG" >/dev/null 2>&1 &
QPID=$!

# WAIT FOR THE MARKER THAT MEANS FINISHED, not one that means started. PNGEND is
# printed after the last byte of the dump, so when it appears the image is whole.
i=0
while [ $i -lt 1800 ]; do
    grep -aqE "FFSHOT-PNGEND|FFSHOT: no PNG|KERNEL PANIC|Invalid Opcode" "$SLOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 1; i=$((i+1))
done
sleep 1
kill -9 "$QPID" 2>/dev/null || true; QPID=""

f=0
if grep -aq "firefox --screenshot -> 0" "$SLOG"; then
    echo "  ok: firefox --headless --screenshot exited 0"
else
    echo "  FAIL: firefox --screenshot did not exit cleanly:"
    grep -a "screenshot ->\|FFSHOT\|KERNEL PANIC" "$SLOG" | head -4; f=1
fi

if python3 tests/ff/png_check.py "$SLOG"; then
    :
else
    f=1
fi

[ $f -eq 0 ] || { echo "FAIL: Firefox page rendering"; exit 1; }
echo "PASS: FIREFOX RENDERS A REAL WEB PAGE INSIDE OS-DEV (parse + cascade + layout + text shaping + paint + PNG encode)"
