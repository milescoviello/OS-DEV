#!/bin/sh
# In-guest assertion for the virtio-console driver (kernel/virtio_console.c).
# Boots the real kernel headless under QEMU with a virtio-serial bus + a console
# port whose host end is a FILE, captures COM1, and asserts the driver:
#
#   - found + brought up the legacy virtio-console device ("virtio-console up");
#   - actually moved bytes OUT the transmit virtqueue: the boot self-test writes
#     a recognizable line, and we assert that EXACT line shows up in the host
#     chardev FILE (proving the guest->host data path through the vring, not just
#     that the device probed);
#   - boot still reaches the desktop with no fault — the console is additional.
#
# Exit 0 = pass. SKIPs cleanly if QEMU is absent. Companion to run-boot-tests.sh
# (no virtio-console device -> the driver must cleanly no-op there).
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_vcon.XXXXXX.log)
VCON=$(mktemp /tmp/osdev_vcon_out.XXXXXX)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG" "$VCON"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: virtio-console test ($QEMU not found)"
    exit 0
fi

echo "booting kernel headless under QEMU with a virtio-console (host sink = file)..."
# The additions vs run-boot-tests.sh are the virtio-serial bus + a console port
# whose host end is $VCON (a file). The guest's transmit-queue writes land there.
timeout -s KILL 30 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -device virtio-serial-pci,disable-modern=on,disable-legacy=off \
    -chardev file,id=vcon,path="$VCON" \
    -device virtconsole,chardev=vcon \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -device AC97,audiodev=snd0 -audiodev none,id=snd0 \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 60 ]; do
    grep -q "launching the desktop" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.4
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

fail=0
require() {  # substring, description, file
    if grep -qiF "$1" "$3"; then
        echo "  ok: $2"
    else
        echo "  MISSING: $2  (expected substring: '$1')"
        fail=1
    fi
}

# The driver probed + brought up the legacy virtio console (serial log).
require "virtio-console up"                    "virtio-console device probed + virtqueues brought up" "$LOG"
# The headline proof: the bytes the guest wrote to the transmit queue arrived in
# the HOST chardev file.
require "hello from OS-DEV virtio-console"      "guest transmit-queue bytes reached the host chardev file" "$VCON"
# Boot reached the desktop with no fault on the virtio-console path.
require "launching the desktop environment"     "reached desktop launch (no fault on the virtio-console path)" "$LOG"

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
forbid "WRITE FAILED"                "virtio-console write failure"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest virtio-console (device up, guest->host bytes delivered, no crash)"
    exit 0
else
    echo "FAIL: in-guest virtio-console test"
    echo "----- captured COM1 log -----"; cat "$LOG"
    echo "----- host chardev file -----"; cat "$VCON"
    exit 1
fi
