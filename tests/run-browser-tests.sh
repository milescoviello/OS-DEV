#!/bin/sh
# In-guest BROWSER render assertion. The browser's HTML tokenizer (parse_html in
# browser.c) walks untrusted page bytes but is too coupled to browser_t state to
# fuzz in isolation (cf. htmlattr.c, which was the separable piece). The right
# automated guard for it is an end-to-end one: boot, open the Apps menu and
# launch the Browser (its built-in, network-free "home" page), and assert the
# page actually painted -- a large white content area that the dark desktop
# never has. This exercises the menu->spawn_browser->parse_html->CSS->font/layout
# render path in one shot. Exit 0 = pass.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img

if ! command -v "$QEMU" >/dev/null 2>&1; then echo "SKIP: browser test ($QEMU not found)"; exit 0; fi
if ! command -v socat >/dev/null 2>&1;   then echo "SKIP: browser test (socat not found)"; exit 0; fi
if ! command -v python3 >/dev/null 2>&1; then echo "SKIP: browser test (python3 not found)"; exit 0; fi

TMP=$(mktemp -d /tmp/osdev_browser.XXXXXX)
SOCK=$TMP/mon.sock; SLOG=$TMP/serial.log; PPM=$TMP/browser.ppm
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -rf "$TMP" 2>/dev/null || true; exit "$rc"; }
trap cleanup EXIT

echo "booting + launching the browser (Apps menu -> Browser), capturing framebuffer..."
timeout -s KILL 40 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -device AC97,audiodev=snd0 -audiodev none,id=snd0 \
    -display none -serial file:"$SLOG" \
    -monitor unix:"$SOCK",server,nowait >"$TMP/qemu.err" 2>&1 &
QPID=$!

i=0; while [ ! -S "$SOCK" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
if [ ! -S "$SOCK" ]; then echo "FAIL: QEMU monitor socket never appeared"; cat "$TMP/qemu.err"; exit 1; fi

got=0; i=0          # ~25s, early-exit on the marker (offline boots delay the desktop; see run-gfx-tests.sh)
while [ $i -lt 50 ]; do
    grep -q "launching the desktop" "$SLOG" 2>/dev/null && { got=1; break; }
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
if [ "$got" -ne 1 ]; then echo "FAIL: never reached desktop launch"; exit 1; fi
sleep 2

key() { printf 'sendkey %s\n' "$1" | socat - UNIX-CONNECT:"$SOCK" >/dev/null 2>&1 || true; }
key f9                       # open the Apps menu (Browser is item 0, pre-selected)
sleep 0.6
key ret                      # launch the Browser

# Retry the capture a few times while the home page paints. Widened from 4 to
# 8 tries: the browser's own home-page load competes for ata_lock with the
# desktop's (now throttled, but not eliminated) Files-panel disk hits, same
# residual as the M1541/httpdtest one -- a couple of observed failures in a
# long sequential `make check` run, never reproduced in isolation, went away
# with more retry budget there too (see osdev-ata-pio-busywait-flakiness).
rc=1
for try in 1 2 3 4 5 6 7 8; do
    sleep 1
    printf 'screendump %s\n' "$PPM" | socat - UNIX-CONNECT:"$SOCK" >/dev/null 2>&1 || true
    sleep 0.4
    if [ -s "$PPM" ] && python3 tests/gfx/ppm_check.py --white 50000 "$PPM"; then rc=0; break; fi
    echo "  (retry $try: browser page not fully painted yet)"
done

if [ "$rc" -eq 0 ]; then
    echo "PASS: in-guest browser (Apps menu launch + home page rendered)"
    exit 0
else
    echo "FAIL: browser did not render its home page"
    exit 1
fi
