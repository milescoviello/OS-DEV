#!/bin/sh
# In-guest GRAPHICAL boot assertion. The serial boot test (run-boot-tests.sh)
# stops at "launching the desktop environment" -- it proves the kernel reached
# desktop_run(), but NOT that the compositor/framebuffer/font stack actually
# paints anything. This boots headless, lets the desktop render, captures the
# emulated VGA framebuffer via the QEMU monitor's `screendump`, and asserts the
# result looks like a real painted desktop (right resolution, many colors, not
# an all-black hang). Covers desktop.c / fb.c / fbcon.c / font.c / vga.c, which
# have no other in-guest coverage. Exit 0 = pass.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img

# Needs QEMU (to run) + socat (to drive the HMP monitor socket). SKIP otherwise
# so the host-only gate still passes where they're absent.
if ! command -v "$QEMU" >/dev/null 2>&1; then echo "SKIP: gfx test ($QEMU not found)"; exit 0; fi
if ! command -v socat >/dev/null 2>&1;   then echo "SKIP: gfx test (socat not found)"; exit 0; fi
if ! command -v python3 >/dev/null 2>&1; then echo "SKIP: gfx test (python3 not found)"; exit 0; fi

TMP=$(mktemp -d /tmp/osdev_gfx.XXXXXX)
SOCK=$TMP/mon.sock
SLOG=$TMP/serial.log
PPM=$TMP/screen.ppm
QPID=""
# Preserve the intended exit status: killing QEMU makes `wait` return 137, which
# would otherwise leak out as the script's status. Capture $? on entry, do the
# teardown, then exit with the captured code.
cleanup() {
    rc=$?
    if [ -n "$QPID" ]; then kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; fi
    rm -rf "$TMP" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT

echo "booting kernel headless (framebuffer capture via QEMU monitor)..."
timeout -s KILL 40 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -device AC97,audiodev=snd0 -audiodev none,id=snd0 \
    -display none -serial file:"$SLOG" \
    -monitor unix:"$SOCK",server,nowait >"$TMP/qemu.err" 2>&1 &
QPID=$!

# Wait for the monitor socket to appear.
i=0; while [ ! -S "$SOCK" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
if [ ! -S "$SOCK" ]; then echo "FAIL: QEMU monitor socket never appeared"; cat "$TMP/qemu.err"; exit 1; fi

# Wait until the kernel hands off to the desktop (then it paints immediately).
# Generous window (~25s, early-exit on the marker): an offline host's boot-time
# network self-test hits TCP timeouts before the desktop, so a tight cap would
# false-fail. Online the marker appears in ~3s and the loop exits at once.
got=0; i=0
while [ $i -lt 50 ]; do
    if grep -q "launching the desktop" "$SLOG" 2>/dev/null; then got=1; break; fi
    kill -0 "$QPID" 2>/dev/null || break        # QEMU exited (crash): stop waiting
    sleep 0.5; i=$((i+1))
done
if [ "$got" -ne 1 ]; then echo "FAIL: never reached desktop launch"; tail -5 "$SLOG" 2>/dev/null; exit 1; fi

# Capture, retrying a few times to absorb paint-timing jitter: re-screendump
# until the analyzer is satisfied or we run out of tries.
rc=1
for try in 1 2 3 4; do
    sleep 1
    printf 'screendump %s\n' "$PPM" | socat - UNIX-CONNECT:"$SOCK" >/dev/null 2>&1 || true
    sleep 0.4
    if [ -s "$PPM" ] && python3 tests/gfx/ppm_check.py "$PPM"; then rc=0; break; fi
    echo "  (retry $try: desktop not fully painted yet)"
done

if [ "$rc" -eq 0 ]; then
    echo "PASS: in-guest graphical desktop (framebuffer painted, $(stat -c%s "$PPM" 2>/dev/null) byte PPM)"
    exit 0
else
    echo "FAIL: graphical desktop did not render as expected"
    exit 1
fi
