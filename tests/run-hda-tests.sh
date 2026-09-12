#!/bin/sh
# In-guest HDA-audio assertion. Boots the real kernel headless under QEMU with an
# Intel HD Audio controller (-device intel-hda + -device hda-output) instead of
# AC'97, then asserts the kernel/hda.c bring-up succeeded end to end:
#   - the controller came up and a codec was enumerated (STATESTS + vendor id),
#   - an output path (DAC + pin) was found and the verbs were accepted,
#   - the audio dispatcher selected HDA ("audio output: hda"),
#   - the output stream's DMA position register (LPIB) ADVANCES while a tone
#     plays (the headless proof the stream is really running),
#   - and no fault/panic occurred anywhere in the boot.
#
# Companion to boottest, which boots the AC'97 path. Exit 0 = pass. SKIPs cleanly
# if QEMU is unavailable.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_hda.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: HDA test ($QEMU not found)"
    exit 0
fi

echo "booting kernel headless under QEMU with intel-hda (COM1 capture)..."
# Same launch as boottest but swapping AC97 for the HDA controller pair. The 25s
# timeout is a generous safety net (the boot does a real TLS handshake under TCG
# before the desktop); we poll for the desktop hand-off and stop early.
timeout -s KILL 25 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -device intel-hda -device hda-output,audiodev=snd0 -audiodev none,id=snd0 \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 50 ]; do
    grep -q "launching the desktop" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break    # QEMU exited (crash): stop waiting
    sleep 0.5; i=$((i+1))
done
sleep 0.3   # let the last few lines flush
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

fail=0
require() {
    if grep -qiF "$1" "$LOG"; then
        echo "  ok: $2"
    else
        echo "  MISSING: $2  (expected substring: '$1')"
        fail=1
    fi
}
require "HDA audio: BAR0="                   "HDA controller reset + codec output path configured"
require "audio output: hda"                  "audio dispatcher selected the HDA driver"
require "DMA ADVANCING"                       "output stream LPIB advanced (stream is running)"
require "launching the desktop environment"  "reached desktop launch (whole boot completed)"

# A codec must have been enumerated (the line carries STATESTS + vendor id).
if grep -qiE "STATESTS=[0-9a-fA-F]+ codec=[0-9]+ vendor=" "$LOG"; then
    echo "  ok: codec enumerated"
    grep -iE "STATESTS=" "$LOG" | head -1 | sed 's/^/      /'
else
    echo "  MISSING: codec enumeration (STATESTS/vendor line)"
    fail=1
fi

# The selftest line carries the actual before/after LPIB values — surface it.
grep -iE "selftest:" "$LOG" | head -1 | sed 's/^/      /' || true

# Crash markers that must NOT appear.
forbid() {
    if grep -qiE "$1" "$LOG"; then
        echo "  CRASH MARKER: $2"
        grep -inE "$1" "$LOG" | head -3 | sed 's/^/      /'
        fail=1
    fi
}
forbid "panic"                       "kernel panic"
forbid "unhandled (interrupt|excep)" "unhandled exception"
forbid "page fault"                  "page fault"
forbid "general protection"          "#GP fault"
forbid "STALLED"                     "HDA stream DMA did not advance"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest HDA audio (controller + codec + output verbs + DMA advancing, no crash)"
    exit 0
else
    echo "FAIL: in-guest HDA audio test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
