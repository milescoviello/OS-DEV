#!/bin/sh
# In-guest assertion for the bus-master IDE DMA path (kernel/ata.c). Boots the
# real kernel headless under QEMU with the NORMAL IDE boot disk (-drive ...,if=ide,
# which QEMU attaches to the PIIX3 IDE controller — and that controller is
# bus-master capable), captures COM1, and asserts the kernel's DMA read path
# returns BYTE-IDENTICAL data to the trusted PIO path:
#
#   - the kernel's ata_dma_selftest() finds the PIIX3 BMIDE controller (BAR4),
#     DMA-reads a few low sectors of the boot disk AND PIO-reads the same sectors,
#     then memcmp()s the two and logs "IDE DMA: sector N DMA==PIO OK" per sector
#     (the headline proof: the new DMA path moves the same bytes the PIO path
#     does — so a subtle DMA bug could never silently corrupt the boot disk);
#   - it then does a DMA write round-trip on a scratch sector near the end of the
#     disk (save via PIO, DMA-write a marker, DMA+PIO read back + verify, restore
#     via PIO) and logs "DMA==PIO OK (wrote+read back+restored)";
#   - boot must STILL mount FAT32 on the legacy ATA disk via PIO and reach the
#     desktop with no fault — the DMA path is purely an additional capability and
#     the boot path (PIO ata_read/ata_write) is untouched.
#
# Exit 0 = pass. SKIPs cleanly if QEMU is absent. The boot disk is the SAME disk
# run-boot-tests.sh uses (no extra device needed — it's already on the bus-master
# IDE controller), so this guards the DMA path against the real boot medium.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_idedma.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: ide-dma test ($QEMU not found)"
    exit 0
fi

echo "booting kernel headless under QEMU (boot disk on the PIIX3 IDE controller; COM1 capture)..."
# Identical device set to run-boot-tests.sh: the boot disk on if=ide (the PIIX3
# IDE controller, which is bus-master capable). The DMA self-test reads it.
timeout -s KILL 30 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
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

# The driver found + brought up the PIIX3 bus-master IDE controller.
require "IDE bus-master DMA up"                "PIIX3 BMIDE found (BAR4) + set up"
require "PIIX3 BMIDE found"                    "BMIDE BAR4 I/O base logged"
# The headline proof: each compared sector read back byte-IDENTICAL to PIO.
require "IDE DMA: sector 0 DMA==PIO OK"         "sector 0 DMA read == PIO read"
require "IDE DMA: sector 1 DMA==PIO OK"         "sector 1 DMA read == PIO read"
require "IDE DMA: sector 2 DMA==PIO OK"         "sector 2 DMA read == PIO read"
# The DMA write path: round-trip on a scratch sector verified (and PIO-cross-checked).
require "IDE DMA write round-trip on sector"    "DMA write path (round-trip on a scratch sector)"
require "DMA==PIO OK (wrote+read back+restored)" "DMA write round-trip verified == PIO"
# The summary line: every compared sector matched.
require "DMA path proven identical to PIO"      "self-test summary: all sectors DMA==PIO"
# Boot stayed on legacy ATA (PIO) and reached the desktop with no fault.
require "mounted FAT32 volume"                  "FAT32 still mounted on legacy ATA via PIO (boot path intact)"
require "launching the desktop environment"     "reached desktop launch (no fault on the DMA path)"

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
forbid "DMA!=PIO"                    "DMA read mismatch vs PIO"
forbid "read FAILED"                 "DMA or PIO read failure in the self-test"
# A write-round-trip MISMATCH would print "round-trip on sector N: MISMATCH".
forbid "round-trip on sector .* MISMATCH" "DMA write round-trip mismatch"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest ide-dma (BMIDE up, sectors DMA==PIO byte-identical, write round-trip, no crash)"
    exit 0
else
    echo "FAIL: in-guest ide-dma test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
