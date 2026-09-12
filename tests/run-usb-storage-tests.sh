#!/bin/sh
# In-guest assertion for the USB mass-storage driver (kernel/usb_storage.c).
# Boots the real kernel headless under QEMU with a USB flash disk attached as a
# usb-storage device ON THE SAME UHCI BUS as the existing usb-tablet, captures
# COM1, and asserts the driver enumerated the Bulk-Only-Transport / SCSI device
# and READ ITS KNOWN CONTENT BACK over BOT:
#
#   - we build a tiny raw image whose every sector holds a recognizable marker
#     ("USB-STORAGE SECTOR <n>!") plus a deterministic byte pattern, and compute,
#     on the host, the additive checksum the kernel self-test logs per sector;
#   - the kernel's usb_storage driver enumerates the device (logging class/
#     subclass/proto + its bulk endpoints), READ CAPACITYs it, and reads sectors
#     0..2 over BOT/SCSI, logging each sector's checksum + first 16 bytes;
#   - we assert those logged checksums EXACTLY match the host-computed ones, i.e.
#     the driver really moved the right bytes off the device (not a fluke);
#   - we assert READ CAPACITY reported the right block count + 512-byte blocks;
#   - we assert the write round-trip (write a marker to the last sector, read it
#     back, restore) reported OK — proving the WRITE(10) path too;
#   - boot must still mount FAT32 on the legacy ATA disk, keep the USB TABLET
#     active (the tablet shares the controller), and reach the desktop with no
#     fault — the USB disk is purely additional.
#
# Exit 0 = pass. SKIPs cleanly if QEMU or python3 is absent. Companion to
# run-boot-tests.sh (no usb-storage -> the driver must cleanly no-op there, and
# the tablet must still come up).
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
IMG=build/usb_storage_test.img
LOG=$(mktemp /tmp/osdev_usbstor.XXXXXX.log)
EXP=$(mktemp /tmp/osdev_usbstor_exp.XXXXXX)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG" "$EXP"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: usb-storage test ($QEMU not found)"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: usb-storage test (python3 not found)"
    exit 0
fi

# Build the known-content image + print the per-sector checksums the kernel will
# log, so the assertions below compare against host-computed truth (the same
# generator the driver was verified with). 64 sectors (32 KiB) is tiny but real
# and large enough that the kernel's chunked multi-sector path is exercised.
python3 - "$IMG" "$EXP" <<'PY'
import sys
SEC, NSEC = 512, 64
buf = bytearray(SEC * NSEC)
for s in range(NSEC):
    off = s * SEC
    marker = ("USB-STORAGE SECTOR %d!" % s).encode()
    buf[off:off+len(marker)] = marker
    for i in range(len(marker), SEC):
        buf[off+i] = (s*13 + i) & 0xFF
with open(sys.argv[1], "wb") as f:
    f.write(buf)
# Emit the lines the assertions look for: per-sector checksums for 0..2, the
# block count READ CAPACITY should report, and the marker substring.
with open(sys.argv[2], "w") as f:
    for s in range(3):
        chk = sum(buf[s*SEC:(s+1)*SEC]) & 0xFFFFFFFF
        f.write("sector %d sum=%08x\n" % (s, chk))
    # READ CAPACITY logs "= <NSEC> blocks x 512 bytes"
    f.write("= %d blocks x 512 bytes\n" % NSEC)
PY

echo "booting kernel headless under QEMU with a usb-storage flash disk on the uhci bus (COM1 capture)..."
# The ONLY additions vs run-boot-tests.sh are the extra -drive (if=none) and the
# usb-storage device on the SAME uhci.0 bus as the tablet. Boot still uses the
# IDE/ATA disk + the tablet; the USB flash disk is additional.
#
# Pin the tablet to UHCI root port 1 and the flash disk to root port 2: without
# explicit ports QEMU inserts a USB hub and puts the MSD behind it (Port 2.1),
# which a minimal UHCI driver (no hub class driver) can't reach. Pinning both to
# the two root ports keeps the topology flat — exactly what the driver supports.
timeout -s KILL 40 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0,port=1 \
    -drive id=ustick,file="$IMG",format=raw,if=none \
    -device usb-storage,bus=uhci.0,port=2,drive=ustick \
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

# The driver enumerated a Bulk-Only-Transport / SCSI mass-storage device + found
# its bulk endpoints.
require "enumerated mass-storage: class=08 subclass=06 proto=50"  "BOT/SCSI mass-storage interface enumerated (class/subclass/proto)"
require "bulk-in=ep"                          "bulk IN endpoint found"
require "bulk-out=ep"                         "bulk OUT endpoint found"
# READ CAPACITY reported the right geometry.
require "usb-storage up: READ CAPACITY"       "READ CAPACITY succeeded"
# It read the RIGHT bytes: every host-computed per-sector checksum + the block
# count must appear in the self-test log (the headline proof the BOT read path
# moves real disk content).
while read -r line; do
    require "$line"                           "read-back / capacity matches known content ($line)"
done < "$EXP"
# The marker string we wrote into the image surfaced in the dumped first-16 bytes
# (the dump shows 16 chars, so "USB-STORAGE SECT" is the visible prefix).
require "USB-STORAGE SECT"                     "on-disk marker string read back verbatim over BOT"
# The write path works: write a sector, read it back, compare, restore.
require "write round-trip on sector"          "WRITE(10) path (round-trip on the last sector)"
require "OK (wrote+read back+restored)"       "write round-trip verified OK"
# M1728: usb_storage_write is now wired into the block layer (was read-only), so
# the non-destructive block-cache durability self-test runs on usb-storage.
require "coherence+durability on usb-storage" "block layer write path on usb-storage (M1728: write wired in)"
# Boot stayed on legacy ATA, kept the USB tablet up (shared controller), and
# reached the desktop with no fault.
require "mounted FAT32 volume"                "FAT32 still mounted on legacy ATA (boot path intact)"
require "USB tablet active"                   "USB tablet still active (shares the UHCI controller)"
require "launching the desktop environment"   "reached desktop launch (no fault on the USB-storage path)"

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
forbid "\[usb-storage\] sector .* READ FAILED"              "usb-storage read failure"
forbid "READ CAPACITY failed"        "usb-storage READ CAPACITY failure"
forbid "\[usb-storage\] write round-trip on sector .* MISMATCH" "usb-storage write round-trip mismatch"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest usb-storage (BOT/SCSI device enumerated, READ CAPACITY matched, known sectors read back, write round-trip, tablet intact, no crash)"
    exit 0
else
    echo "FAIL: in-guest usb-storage test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
