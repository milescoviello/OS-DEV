#!/bin/sh
# In-guest assertion for the NVMe driver (kernel/nvme.c). Boots the real kernel
# headless under QEMU with a SECOND disk attached over NVMe
# (-device nvme,serial=deadbeef,drive=nvme0 + -drive ...,if=none), captures COM1,
# and asserts the driver brought the controller up and READ ITS KNOWN CONTENT BACK:
#
#   - we build a tiny raw image whose every sector holds a recognizable marker
#     ("NVME SECTOR <n>!") plus a deterministic byte pattern, and compute, on the
#     host, the additive checksum the kernel self-test logs per sector;
#   - the kernel's nvme_selftest() IDENTIFYs namespace 1, reads sectors 0..2 off
#     the NVMe disk and logs each sector's checksum + first 16 bytes;
#   - we assert those logged checksums EXACTLY match the host-computed ones, i.e.
#     the driver really moved the right bytes off the device (not a fluke);
#   - we assert the write round-trip (write a marker to the last sector, read it
#     back, restore) reported OK — proving the write path too;
#   - boot must still mount FAT32 on the legacy ATA disk and reach the desktop
#     with no fault — the NVMe disk is purely additional.
#
# Exit 0 = pass. SKIPs cleanly if QEMU or python3 is absent. Companion to
# run-boot-tests.sh (no NVMe disk -> the driver must cleanly no-op there).
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
IMG=build/nvme_test.img
LOG=$(mktemp /tmp/osdev_nvme.XXXXXX.log)
EXP=$(mktemp /tmp/osdev_nvme_exp.XXXXXX)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG" "$EXP"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: nvme test ($QEMU not found)"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: nvme test (python3 not found)"
    exit 0
fi

# Build the known-content image + print the per-sector checksums the kernel will
# log, so the assertions below compare against host-computed truth (the same
# generator the driver was verified with). 16 sectors (8 KiB) is tiny but real.
python3 - "$IMG" "$EXP" <<'PY'
import sys
SEC, NSEC = 512, 16
buf = bytearray(SEC * NSEC)
for s in range(NSEC):
    off = s * SEC
    marker = ("NVME SECTOR %d!" % s).encode()
    buf[off:off+len(marker)] = marker
    for i in range(len(marker), SEC):
        buf[off+i] = (s*7 + i) & 0xFF
with open(sys.argv[1], "wb") as f:
    f.write(buf)
# Emit "sector N sum=XXXXXXXX" lines for 0..2 (substrings of the kernel's log).
with open(sys.argv[2], "w") as f:
    for s in range(3):
        chk = sum(buf[s*SEC:(s+1)*SEC]) & 0xFFFFFFFF
        f.write("sector %d sum=%08x\n" % (s, chk))
PY

echo "booting kernel headless under QEMU with an NVMe second disk (COM1 capture)..."
# The ONLY additions vs run-boot-tests.sh are the second drive + an nvme
# controller. Boot still uses the IDE/ATA disk; NVMe is additional.
timeout -s KILL 30 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -drive id=nvme0,file="$IMG",format=raw,if=none \
    -device nvme,serial=deadbeef,drive=nvme0 \
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

# The driver found + brought up the NVMe controller and identified namespace 1.
require "NVMe up"                             "NVMe controller probed + namespace identified"
require "capacity in 512B sectors"            "IDENTIFY reported capacity + LBA size"
# It read the RIGHT bytes: every host-computed per-sector checksum must appear in
# the self-test log (the headline proof the read path moves real disk content).
while read -r line; do
    require "$line"                           "read-back matches known content ($line)"
done < "$EXP"
# The marker string we wrote into the image surfaced in the dumped first-16 bytes.
require "NVME SECTOR"                          "on-disk marker string read back verbatim"
# The write path works: write a sector, read it back, compare, restore.
require "write round-trip on sector"          "write path (round-trip on the last sector)"
require "OK (wrote+read back+restored)"       "write round-trip verified OK"
# Boot stayed on legacy ATA and reached the desktop with no fault.
require "mounted FAT32 volume"                "FAT32 still mounted on legacy ATA (boot path intact)"
require "launching the desktop environment"   "reached desktop launch (no fault on the NVMe path)"

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
forbid "\[nvme\] sector .* READ FAILED"                "nvme read failure"
forbid "\[nvme\] write round-trip on sector .* MISMATCH" "nvme write round-trip mismatch"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest nvme (controller up, known sectors read back, write round-trip, no crash)"
    exit 0
else
    echo "FAIL: in-guest nvme test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
