#!/bin/sh
# In-guest assertion for the USB HID boot-keyboard driver (kernel/usb_kbd.c).
# Boots the real kernel headless under QEMU with a usb-kbd attached ON THE SAME
# UHCI BUS as the existing usb-tablet, captures COM1, and asserts the driver:
#
#   - enumerated a HID boot keyboard (interface class 03 / subclass 01 = Boot /
#     protocol 01 = Keyboard) and found its INTERRUPT IN endpoint;
#   - put it in boot protocol (HID SET_PROTOCOL(0) returned ok);
#   - polled the interrupt-IN endpoint and DECODED injected keystrokes: we drive
#     QEMU's HMP `sendkey` monitor command to type a known string while the boot
#     self-test is polling, and assert the decoded characters appear in the log;
#   - boot must still mount FAT32 on the legacy ATA disk, keep the USB TABLET
#     active (it shares the controller), and reach the desktop with no fault —
#     the USB keyboard is purely additional and the PS/2 keyboard is unaffected.
#
# Exit 0 = pass. SKIPs cleanly if QEMU or socat is absent. Companion to
# run-boot-tests.sh (no usb-kbd -> the driver must cleanly no-op there, and the
# tablet + PS/2 keyboard must still come up).
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img

# Needs QEMU (to run) + socat (to drive the HMP monitor socket for `sendkey`).
# SKIP otherwise so the host-only gate still passes where they're absent.
if ! command -v "$QEMU" >/dev/null 2>&1; then echo "SKIP: usb-kbd test ($QEMU not found)"; exit 0; fi
if ! command -v socat >/dev/null 2>&1;   then echo "SKIP: usb-kbd test (socat not found)"; exit 0; fi

TMP=$(mktemp -d /tmp/osdev_usbkbd.XXXXXX)
SOCK=$TMP/mon.sock
LOG=$TMP/serial.log
QPID=""
cleanup() {
    rc=$?
    if [ -n "$QPID" ]; then kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; fi
    rm -rf "$TMP" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT

mon() { printf '%s\n' "$1" | socat - UNIX-CONNECT:"$SOCK" >/dev/null 2>&1 || true; }

echo "booting kernel headless under QEMU with a usb-kbd on the uhci bus (COM1 capture)..."
# The ONLY additions vs run-boot-tests.sh are the usb-kbd device and the monitor
# socket (so we can inject keystrokes). Boot still uses the IDE/ATA disk + the
# tablet; the USB keyboard is additional.
#
# Pin the tablet to UHCI root port 1 and the keyboard to root port 2: without
# explicit ports QEMU inserts a USB hub and puts the second device behind it,
# which a minimal UHCI driver (no hub class driver) can't reach. Pinning both to
# the two root ports keeps the topology flat -- exactly what the driver supports.
timeout -s KILL 50 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0,port=1 \
    -device usb-kbd,bus=uhci.0,port=2 \
    -device AC97,audiodev=snd0 -audiodev none,id=snd0 \
    -display none -serial file:"$LOG" \
    -monitor unix:"$SOCK",server,nowait >"$TMP/qemu.err" 2>&1 &
QPID=$!

# Wait for the monitor socket to appear.
i=0; while [ ! -S "$SOCK" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
if [ ! -S "$SOCK" ]; then echo "FAIL: QEMU monitor socket never appeared"; cat "$TMP/qemu.err"; exit 1; fi

# Wait for the keyboard to enumerate (the self-test prints this, then spends ~2s
# polling the interrupt-IN endpoint). Generous window: an offline host's boot
# network self-test hits TCP timeouts before this point, so a tight cap would
# false-fail. The keyboard bring-up happens late in boot, after storage.
got=0; i=0
while [ $i -lt 90 ]; do
    if grep -q "enumerated HID boot keyboard" "$LOG" 2>/dev/null; then got=1; break; fi
    kill -0 "$QPID" 2>/dev/null || break        # QEMU exited (crash): stop waiting
    sleep 0.5; i=$((i+1))
done
if [ "$got" -ne 1 ]; then
    echo "FAIL: USB keyboard never enumerated"; echo "----- COM1 -----"; cat "$LOG" 2>/dev/null; exit 1
fi

# The self-test polls the interrupt-IN endpoint ~200 times with ~10ms between
# polls (~2s). Inject a known keystroke sequence NOW via the HMP `sendkey` so the
# reports land while the loop is polling. With a usb-kbd present, QEMU routes
# sendkey to the USB HID keyboard, so these become boot-protocol reports on the
# interrupt endpoint -- exactly the path the driver decodes. Send a few times to
# absorb timing jitter (the driver only fires on key-DOWN, so repeats are fine).
for round in 1 2 3 4; do
    mon "sendkey h"
    mon "sendkey i"
    mon "sendkey k"
    mon "sendkey ret"
    sleep 0.25
done

# Now wait until the kernel hands off to the desktop (proves no fault on the
# usb-kbd path and the whole boot still completed).
got=0; i=0
while [ $i -lt 90 ]; do
    if grep -q "launching the desktop" "$LOG" 2>/dev/null; then got=1; break; fi
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
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

# The driver enumerated a HID boot keyboard, found its interrupt endpoint, and
# selected boot protocol.
require "enumerated HID boot keyboard: class=03 subclass=01 proto=01"  "HID boot-keyboard interface enumerated (class/subclass/proto)"
require "interrupt-in=ep"                     "interrupt-IN endpoint found"
require "SET_PROTOCOL(boot)=ok"               "HID SET_PROTOCOL(boot) succeeded"
# The interrupt-IN poll loop completed (the driver-level proof the endpoint was
# polled without fault, even if no key were injected).
require "usb-kbd up: HID boot keyboard on UHCI"  "interrupt-IN endpoint polled (poll loop completed)"
# The injected keystrokes were received + decoded over the interrupt endpoint.
# (At minimum one of these must appear; we assert the ones we sent.)
require "decoded key: usage=0b -> 'h'"        "decoded injected 'h' (HID usage 0x0b)"
require "decoded key: usage=0c -> 'i'"        "decoded injected 'i' (HID usage 0x0c)"
require "decoded key: usage=0e -> 'k'"        "decoded injected 'k' (HID usage 0x0e)"
# Boot stayed on legacy ATA, kept the USB tablet up (shared controller), and
# reached the desktop with no fault.
require "mounted FAT32 volume"                "FAT32 still mounted on legacy ATA (boot path intact)"
require "USB tablet active"                   "USB tablet still active (shares the UHCI controller)"
require "launching the desktop environment"   "reached desktop launch (no fault on the USB-keyboard path)"

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
forbid "SET_PROTOCOL\\(boot\\) failed" "usb-kbd SET_PROTOCOL failure"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest usb-kbd (HID boot keyboard enumerated, SET_PROTOCOL ok, injected keystrokes decoded over the interrupt endpoint, tablet intact, no crash)"
    exit 0
else
    echo "FAIL: in-guest usb-kbd test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
