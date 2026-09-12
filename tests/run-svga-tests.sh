#!/bin/sh
# In-guest assertion for the VMware SVGA-II driver (kernel/svga.c). Boots the
# real kernel headless under QEMU with a VMware SVGA-II device attached
# (-device vmware-svga) IN ADDITION to the std-VGA display, captures COM1, and
# asserts the driver brought the paravirtual 2D adapter up end to end and ran
# the full present cycle:
#
#   - the device was probed and confirmed: SVGA_ID_2 was written to SVGA_REG_ID
#     and read back (the "vmware-svga up: SVGA_ID_2 confirmed" line),
#   - the framebuffer (BAR1) + command FIFO (BAR2) addresses + sizes were read
#     and the mode was set (WIDTHxHEIGHT@32),
#   - the present cycle ran: a colour-band test pattern was written into the
#     linear framebuffer, an SVGA_CMD_UPDATE was emitted into the FIFO and
#     synced, and the registers (SVGA_ID_2, ENABLE) read back OK (the headless
#     proof, like virtio-gpu's "every command returned OK"),
#   - the std-VGA boot display path is UNAFFECTED: -vga std is still present, the
#     desktop still reaches launch, FAT32 still mounts, and there is no fault.
#
# Exit 0 = pass. SKIPs cleanly if QEMU is absent. Companion to run-boot-tests.sh
# / run-gfx-tests.sh (no vmware-svga device there -> the driver must cleanly
# no-op, and the std-VGA desktop screenshot must still render unchanged).
#
# NOTE: this is named svgatest (SVGA-II display); the existing svgtest is the
# SVG image rasterizer fuzz test -- different things.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_svga.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: vmware-svga test ($QEMU not found)"
    exit 0
fi

# Confirm this QEMU even has the vmware-svga device (older builds may not); SKIP
# rather than fail if it's unavailable.
if ! "$QEMU" -device help 2>&1 | grep -qi "vmware-svga"; then
    echo "SKIP: vmware-svga test (this QEMU lacks the vmware-svga device)"
    exit 0
fi

echo "booting kernel headless under QEMU with a VMware SVGA-II device (COM1 capture)..."
# Display config: -vga vmware makes the VMware SVGA-II (PCI 15AD:0405) the
# primary VGA (the device svga.c binds), and -device VGA adds a SECOND std
# VGA-PCI (1234:1111) that carries the Bochs DISPI interface the BOOT display
# path (fb.c / bochs_vbe.c) drives -- so svga.c is exercised WITHOUT losing the
# linear-framebuffer boot display (the kernel comes up on the "(graphical
# console)" banner, FAT32 mounts, the desktop launches). We can NOT use
# `-vga std -device vmware-svga`: QEMU rejects two devices both claiming the
# migration id "vga" (vmware-svga always does), so vmware is the primary and the
# std VGA is the explicit secondary. gfxtest is unaffected -- it still boots the
# default `-vga std` with NO vmware device, so the std-VGA screenshot path is
# byte-identical there. The 30s timeout is a generous safety net (the boot does a
# real TLS handshake under TCG before the desktop); we poll + stop early.
timeout -s KILL 30 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -device AC97,audiodev=snd0 -audiodev none,id=snd0 \
    -vga vmware -device VGA \
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

# The driver found + confirmed the device (SVGA_ID_2 read back) and set a mode.
require "vmware-svga up: SVGA_ID_2 confirmed"   "vmware-svga probed + SVGA_ID_2 confirmed + mode set"
# The framebuffer + FIFO geometry was read and the selftest reported it.
require "FB phys"                                "framebuffer + FIFO addresses/sizes read"
# The present cycle ran: registers confirmed + UPDATE emitted + synced.
require "SVGA_ID_2=OK ENABLE=OK"                 "registers read back OK after mode set"
require "UPDATE(full)=OK rect-present=OK"        "present cycle: UPDATE emitted + synced, rect present OK"
require "vmware-svga present cycle complete"     "full present cycle complete"
# The std-VGA boot display path is intact (the Bochs-DISPI linear framebuffer on
# the secondary std VGA came up -- the kernel reaches its graphical console).
require "(graphical console)"                    "boot display up on the linear framebuffer (graphical console)"
require "mounted FAT32 volume"                   "FAT32 still mounted (boot path intact)"
require "launching the desktop environment"      "reached desktop launch (no fault on the svga path)"

# Surface the actual lines the driver logged (the confirmed id + mode + geometry).
grep -iE "vmware-svga up: SVGA_ID_2 confirmed" "$LOG" | head -1 | sed 's/^/      /' || true
grep -iE "vmware-svga\] selftest: device up"   "$LOG" | head -1 | sed 's/^/      /' || true

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
forbid "PRESENT CYCLE FAILED"        "vmware-svga present cycle did not complete OK"
forbid "=FAIL"                       "an svga selftest step returned non-OK"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest vmware-svga (device confirmed, mode set, FB+FIFO sized, present cycle OK, std-VGA boot intact, no crash)"
    exit 0
else
    echo "FAIL: in-guest vmware-svga test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
