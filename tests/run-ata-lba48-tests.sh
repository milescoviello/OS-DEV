#!/bin/sh
# In-guest assertion for the ATA driver's LBA48 path (kernel/ata.c, M1721). The
# primary PIO read/write path was LBA28-only, capping any IDE disk at 2^28
# sectors = 128 GiB. It now dispatches to an LBA48 branch for any access that
# reaches sector 2^28 or beyond (the LBA28 code is untouched for low/boot access).
#
# This boots the real kernel headless with a SECOND ATA disk of 160 GiB (a sparse
# image, so it costs ~0 real bytes) on the primary-slave channel and captures
# COM1. ata_lba48_selftest() finds that >128 GiB non-boot disk, writes a known
# pattern to a sector ~49 MiB PAST the 128 GiB boundary (which is unreachable
# with LBA28), reads it back, and confirms the round-trip. Assert:
#   - a >128 GiB ATA disk was detected;
#   - the high-LBA write + read-back matched (LBA48 addresses beyond 128 GiB);
#   - the boot FAT32 volume (all low LBAs, LBA28 path) is still mounted, and boot
#     reached the desktop with no fault.
#
# Boot stays on the legacy ATA boot disk (drive 0, LBA28); the big disk is a
# non-boot scratch disk. Exit 0 = pass. SKIPs cleanly if QEMU is absent.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
BIG=$(mktemp /tmp/osdev_lba48.XXXXXX.img)
LOG=$(mktemp /tmp/osdev_lba48.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG" "$BIG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: ATA LBA48 test ($QEMU not found)"
    exit 0
fi
truncate -s 160G "$BIG"          # sparse 160 GiB > the 128 GiB (2^28-sector) LBA28 ceiling

echo "booting kernel headless with a 160 GiB sparse ATA disk (primary slave) for the LBA48 test..."
timeout -s KILL 40 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide,index=0 \
    -drive file="$BIG",format=raw,if=ide,index=1 \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 70 ]; do
    grep -q "launching the desktop" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

fail=0
require() {
    if grep -qiF "$1" "$LOG"; then echo "  ok: $2"
    else echo "  MISSING: $2  (expected substring: '$1')"; fail=1; fi
}
require "ATA LBA48: drive"                            "a >128 GiB ATA disk was detected (LBA48 candidate)"
require "wrote + read back, data matches (LBA48 OK)"  "high-LBA write+read-back past the 128 GiB boundary (LBA48 works)"
require "mounted FAT32 volume"                        "boot FAT32 still mounted on the LBA28 path (boot intact)"
require "launching the desktop environment"           "reached desktop launch (no fault on the ATA path)"

forbid() {
    if grep -qiE "$1" "$LOG"; then echo "  CRASH MARKER: $2"; grep -inE "$1" "$LOG" | head -2 | sed 's/^/      /'; fail=1; fi
}
forbid "panic"                       "kernel panic"
forbid "page fault"                  "page fault"
forbid "general protection"          "#GP fault"
forbid "LBA48 .*MISMATCH/FAIL"       "LBA48 round-trip mismatch"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest ATA LBA48 (>128 GiB disk, high-LBA write+read-back round-trip, boot LBA28 intact)"
    exit 0
else
    echo "FAIL: in-guest ATA LBA48 test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
