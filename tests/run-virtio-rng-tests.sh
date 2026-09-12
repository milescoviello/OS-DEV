#!/bin/sh
# In-guest assertion for the virtio-rng driver (kernel/virtio_rng.c). Boots the
# real kernel headless under QEMU with a virtio entropy device attached
# (-device virtio-rng-pci), captures COM1, and asserts the driver:
#
#   - found + brought up the legacy virtio-rng device ("virtio-rng up");
#   - DMA'd real entropy in: the boot self-test draws TWO batches over the
#     virtqueue and logs them, asserting the bytes are nonzero (the device
#     didn't leave our zeroed buffer untouched) AND the two batches DIFFER
#     (it's not returning a constant) -> "entropy OK";
#   - boot still reaches the desktop with no fault — the rng device is purely
#     additional.
#
# Exit 0 = pass. SKIPs cleanly if QEMU or python3 is absent. Companion to
# run-boot-tests.sh (no virtio-rng device -> the driver must cleanly no-op).
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_vrng.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: virtio-rng test ($QEMU not found)"
    exit 0
fi

echo "booting kernel headless under QEMU with a virtio-rng device (COM1 capture)..."
# The ONLY addition vs run-boot-tests.sh is -device virtio-rng-pci. The default
# QEMU rng backend feeds host entropy; boot still uses the IDE/ATA disk.
timeout -s KILL 30 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0,vectors=2 \
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

# The driver found + brought up the legacy virtio entropy device.
require "virtio-rng up"                        "virtio-rng device probed + virtqueue brought up"
# It DMA'd real, varying entropy in (the headline proof the read path works).
require "entropy OK"                           "two batches drawn over the virtqueue: nonzero + differ"
# Message-signaled interrupts (M1288): queue 0 was routed to an MSI-X vector and
# the device actually fired it — our handler ran AND the kernel tallied it.
require "MSI-X OK"                             "queue 0 routed to a message-signaled (MSI-X) interrupt that fired"
# Boot reached the desktop with no fault on the virtio path.
require "launching the desktop environment"    "reached desktop launch (no fault on the virtio-rng path)"

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
forbid "\[virtio-rng\] READ FAILED"  "virtio-rng read failure"
forbid "ENTROPY MISMATCH"            "virtio-rng entropy property failure"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest virtio-rng (device up, real entropy DMA'd in, no crash)"
    exit 0
else
    echo "FAIL: in-guest virtio-rng test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
