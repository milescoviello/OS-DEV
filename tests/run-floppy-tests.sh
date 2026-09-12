#!/bin/sh
# In-guest assertion for the floppy controller driver (kernel/floppy.c). Boots
# the real kernel headless under QEMU with a 1.44 MB floppy image attached
# (-drive file=floppy.img,format=raw,if=floppy), captures COM1, and asserts the
# driver brought the 82077AA controller up over ISA DMA and READ ITS KNOWN
# CONTENT BACK:
#
#   - we build a 1.44 MB raw image (2880 * 512 B) whose every sector holds a
#     recognizable marker ("FLOPPY SECTOR <n>!") plus a deterministic byte
#     pattern, and compute, on the host, the additive checksum the kernel
#     self-test logs per sector;
#   - the kernel's floppy_selftest() resets+recalibrates the controller, then
#     ISA-DMA-reads sectors 0..2 (logging each sector's checksum + first 16
#     bytes) and sectors 5..8 in one 4-sector call (logging that checksum);
#   - we assert those logged checksums EXACTLY match the host-computed ones, i.e.
#     the driver really moved the right bytes off the diskette through the 8237
#     DMA controller (not a fluke);
#   - we assert the reset + recalibrate marker printed (the bring-up proof);
#   - boot must still mount FAT32 on the legacy ATA disk and reach the desktop
#     with no fault — the floppy is purely additional.
#
# Exit 0 = pass. SKIPs cleanly if QEMU or python3 is absent. Companion to
# run-boot-tests.sh (no floppy -> the driver must cleanly no-op there).
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
IMG=build/floppy_test.img
LOG=$(mktemp /tmp/osdev_floppy.XXXXXX.log)
EXP=$(mktemp /tmp/osdev_floppy_exp.XXXXXX)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG" "$EXP"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: floppy test ($QEMU not found)"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: floppy test (python3 not found)"
    exit 0
fi

# Build the known-content 1.44 MB image + print the per-sector checksums the
# kernel will log, so the assertions below compare against host-computed truth
# (the same generator the driver was verified with). A 1.44 MB diskette is
# exactly 2880 sectors of 512 B; QEMU's if=floppy needs that exact size.
python3 - "$IMG" "$EXP" <<'PY'
import sys
SEC, NSEC = 512, 2880          # 1.44 MB = 2880 * 512
buf = bytearray(SEC * NSEC)
for s in range(NSEC):
    off = s * SEC
    marker = ("FLOPPY SECTOR %d!" % s).encode()
    buf[off:off+len(marker)] = marker
    for i in range(len(marker), SEC):
        buf[off+i] = (s*13 + i) & 0xFF
with open(sys.argv[1], "wb") as f:
    f.write(buf)
# Emit the substrings of the kernel's self-test log we assert on:
#   "sector N sum=XXXXXXXX" for the single-sector reads of 0,1,2;
#   "sectors 5..8 (4-sector read) sum=XXXXXXXX" for the multi-sector read.
with open(sys.argv[2], "w") as f:
    for s in range(3):
        chk = sum(buf[s*SEC:(s+1)*SEC]) & 0xFFFFFFFF
        f.write("sector %d sum=%08x\n" % (s, chk))
    chk = sum(buf[5*SEC:9*SEC]) & 0xFFFFFFFF      # sectors 5,6,7,8
    f.write("sectors 5..8 (4-sector read) sum=%08x\n" % chk)
PY

echo "booting kernel headless under QEMU with a 1.44 MB floppy attached (COM1 capture)..."
# The ONLY addition vs run-boot-tests.sh is the floppy drive (if=floppy). Boot
# still uses the IDE/ATA disk; the floppy is additional. The floppy bring-up
# includes a ~500 ms motor spin-up + seeks, so allow a touch more time.
timeout -s KILL 35 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -drive file="$IMG",format=raw,if=floppy \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -device AC97,audiodev=snd0 -audiodev none,id=snd0 \
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
    if grep -qiF "$1" "$LOG"; then
        echo "  ok: $2"
    else
        echo "  MISSING: $2  (expected substring: '$1')"
        fail=1
    fi
}

# The driver reset + recalibrated the 82077AA and armed ISA DMA channel 2.
require "floppy 82077AA up"                   "FDC reset + recalibrate OK + ISA-DMA ch2 armed"
# It read the RIGHT bytes: every host-computed checksum must appear in the
# self-test log (the headline proof the ISA-DMA read path moves real content).
while read -r line; do
    require "$line"                           "read-back matches known content ($line)"
done < "$EXP"
# The marker string we wrote into the image surfaced in the dumped first-16 bytes.
require "FLOPPY SECTOR 0!"                     "on-disk marker string read back verbatim"
require "ISA-DMA read self-test complete"      "ISA-DMA read self-test completed"
# Write path (M1719): a pattern written to the scratch sector read back identical.
require "data matches (write path OK)"         "WRITE DATA path: pattern written + read back over ISA DMA"
# Boot stayed on legacy ATA and reached the desktop with no fault.
require "mounted FAT32 volume"                "FAT32 still mounted on legacy ATA (boot path intact)"
require "launching the desktop environment"   "reached desktop launch (no fault on the floppy path)"

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
forbid "\[floppy\] sector .* READ FAILED" "floppy sector read failure"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest floppy (FDC up, sectors read back + write round-trips over ISA DMA, no crash)"
    exit 0
else
    echo "FAIL: in-guest floppy test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
