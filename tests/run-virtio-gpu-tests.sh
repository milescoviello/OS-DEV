#!/bin/sh
# In-guest assertion for the virtio-gpu driver (kernel/virtio_gpu.c). Boots the
# real kernel headless under QEMU with a virtio-gpu device attached
# (-device virtio-gpu-pci) IN ADDITION to the std-VGA display, captures COM1,
# and asserts the driver brought the modern paravirtual GPU up end to end and
# ran the full present cycle:
#
#   - the device was probed and the modern virtio handshake succeeded; scanout 0
#     reported a sane resolution (the "virtio-gpu up: scanout 0 WxH" line),
#   - the resource was created + a guest backing buffer attached + bound to
#     scanout 0 (CREATE_2D / ATTACH_BACKING / SET_SCANOUT done at init),
#   - the present cycle ran: TRANSFER_TO_HOST_2D and RESOURCE_FLUSH each returned
#     OK, and a sub-rect present returned OK (the headless proof, like HDA's
#     "DMA ADVANCING" — every control command returned its OK response code),
#   - the std-VGA boot display path is UNAFFECTED: -vga std is still present, the
#     desktop still reaches launch, FAT32 still mounts, and there is no fault.
#
# Exit 0 = pass. SKIPs cleanly if QEMU is absent. Companion to run-boot-tests.sh
# / run-gfx-tests.sh (no virtio-gpu device there -> the driver must cleanly
# no-op, and the std-VGA desktop screenshot must still render unchanged).
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_vgpu.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: virtio-gpu test ($QEMU not found)"
    exit 0
fi

echo "booting kernel headless under QEMU with a virtio-gpu device (COM1 capture)..."
# The ONLY addition vs run-boot-tests.sh is the virtio-gpu device. We KEEP the
# std-VGA display (-vga std, QEMU's default) so the std-VGA boot path + gfxtest
# are unaffected; virtio-gpu is the additional device under test. The 30s
# timeout is a generous safety net (the boot does a real TLS handshake under TCG
# before the desktop); we poll for the desktop hand-off and stop early.
timeout -s KILL 30 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -device AC97,audiodev=snd0 -audiodev none,id=snd0 \
    -vga std -device virtio-gpu-pci \
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

# The driver found + brought up the virtio-gpu device and read scanout 0's size.
require "virtio-gpu up: scanout 0"            "virtio-gpu probed + modern handshake + display info read"
# The resource is live (created + backing attached + bound to scanout 0).
require "created+attached+scanned-out"        "RESOURCE_CREATE_2D + ATTACH_BACKING + SET_SCANOUT succeeded"
# The present cycle ran and every command returned OK (the headless proof).
require "TRANSFER_TO_HOST_2D=OK RESOURCE_FLUSH=OK rect-present=OK"  "present cycle: every command returned OK"
require "every command returned OK"           "full present cycle complete"
# The std-VGA boot display path is intact (boot stayed on the linear framebuffer).
require "mounted FAT32 volume"                "FAT32 still mounted (boot path intact)"
require "launching the desktop environment"   "reached desktop launch (no fault on the virtio-gpu path)"

# Surface the actual WxH line the driver logged (the negotiated resolution).
grep -iE "virtio-gpu up: scanout 0" "$LOG" | head -1 | sed 's/^/      /' || true

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
forbid "PRESENT CYCLE FAILED"        "virtio-gpu present cycle did not complete OK"
forbid "=FAIL"                        "a virtio-gpu control command returned non-OK"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest virtio-gpu (device up, resource live, present cycle every command OK, std-VGA boot intact, no crash)"
    exit 0
else
    echo "FAIL: in-guest virtio-gpu test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
