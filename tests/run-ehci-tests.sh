#!/bin/sh
# In-guest assertion for the EHCI (USB 2.0) host-controller driver (kernel/ehci.c).
# Boots the real kernel headless under QEMU with an EHCI controller attached
# (-device usb-ehci) AND a USB flash disk on ITS bus (-device usb-storage,
# bus=ehci.0), captures COM1, and asserts the driver brought the USB 2.0 host up
# and drove it end to end:
#
#   - the EHCI controller was probed by PCI class (0x0C/0x03/0x20), reset, and
#     started with its asynchronous (QH+qTD) schedule running ("EHCI HC up:" +
#     N_PORTS / HCIVERSION);
#   - a root port was reset + enabled a high-speed device ("root-port N reset +
#     enabled a high-speed device");
#   - the device was ENUMERATED over EHCI control transfers — its device
#     descriptor (idVendor/idProduct/bDeviceClass) read over the QH+qTD async
#     schedule, an address assigned, the config descriptor read, SET_CONFIGURATION
#     sent ("EHCI enumerated device over control transfers");
#   - STRETCH bulk path: the device is a BOT/SCSI mass-storage; the driver read
#     SECTOR 0 over EHCI bulk (BOT + SCSI READ(10)) and logged its additive
#     checksum + first 16 bytes. We build the disk image on the host with known
#     content, compute sector 0's checksum + marker, and assert the kernel logged
#     EXACTLY those — i.e. the bulk path moved the right bytes off the device.
#   - the existing UHCI controller + its usb-tablet stay up (separate controller),
#     boot still mounts FAT32 on legacy ATA, and the desktop launches with no fault
#     — EHCI is purely additional.
#
# Exit 0 = pass. SKIPs cleanly if QEMU or python3 is absent. Companion to
# run-boot-tests.sh (no EHCI controller there -> the driver must cleanly no-op,
# and UHCI + the tablet must still come up).
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
IMG=build/ehci_test.img
LOG=$(mktemp /tmp/osdev_ehci.XXXXXX.log)
EXP=$(mktemp /tmp/osdev_ehci_exp.XXXXXX)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG" "$EXP"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: ehci test ($QEMU not found)"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: ehci test (python3 not found)"
    exit 0
fi

# Build a tiny known-content image + print the sector-0 checksum the kernel will
# log, so the assertion compares against host-computed truth. 64 sectors (32 KiB)
# is tiny but real; the kernel reads sector 0 over EHCI bulk (BOT/SCSI READ(10)).
python3 - "$IMG" "$EXP" <<'PY'
import sys
SEC, NSEC = 512, 64
buf = bytearray(SEC * NSEC)
for s in range(NSEC):
    off = s * SEC
    marker = ("EHCI-USB SECTOR %d!" % s).encode()
    buf[off:off+len(marker)] = marker
    for i in range(len(marker), SEC):
        buf[off+i] = (s*13 + i) & 0xFF
with open(sys.argv[1], "wb") as f:
    f.write(buf)
with open(sys.argv[2], "w") as f:
    chk = sum(buf[0:SEC]) & 0xFFFFFFFF
    # The kernel logs "sum=<8 hex>first16=<32 hex>" with no separators.
    f.write("sum=%08x first16=%s\n" % (chk, buf[0:16].hex()))
PY

echo "booting kernel headless under QEMU with a usb-ehci controller + a usb-storage flash disk on its bus (COM1 capture)..."
# The ONLY additions vs run-boot-tests.sh are the usb-ehci controller, an extra
# -drive (if=none), and a usb-storage device on the EHCI bus. The UHCI controller
# + its tablet stay (the EHCI host is a SEPARATE, additional USB controller); boot
# still uses the IDE/ATA disk. The 40s timeout matches the usb-storage test (the
# boot does a real TLS handshake under TCG before the desktop); we poll + stop early.
timeout -s KILL 40 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -device usb-ehci,id=ehci \
    -drive id=estick,file="$IMG",format=raw,if=none \
    -device usb-storage,bus=ehci.0,drive=estick \
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

# The EHCI controller came up: USB 2.0 host, async schedule running, N_PORTS read.
require "EHCI HC up: USB 2.0 host"            "EHCI controller probed + reset + async schedule running (N_PORTS/version)"
# A root port reset + enabled a high-speed device.
require "reset + enabled a high-speed device" "EHCI root-port reset enabled a high-speed device"
# The device was enumerated over EHCI control transfers (descriptors read).
require "EHCI enumerated device over control transfers"  "device descriptor read over EHCI (control transfers / QH+qTD async schedule)"
require "idVendor="                            "device idVendor/idProduct/class read over EHCI"
# STRETCH: it is a BOT/SCSI mass-storage; the bulk endpoints were found.
require "device is BOT/SCSI mass-storage: bulk-in=ep"  "BOT/SCSI mass-storage interface + bulk endpoints found"
require "EHCI bulk IN: read sector 0 over EHCI"  "sector 0 read over EHCI bulk (BOT/SCSI READ(10))"
# It read the RIGHT bytes: the host-computed sector-0 checksum + first-16 bytes
# must appear verbatim in the kernel's bulk-read log line (the headline proof the
# EHCI bulk path moved real disk content, not a fluke).
while read -r line; do
    require "$line"                            "EHCI bulk read matches known sector-0 content ($line)"
done < "$EXP"
# The existing UHCI controller + its tablet stay up (EHCI is a separate host),
# boot stayed on legacy ATA, and the desktop launched with no fault.
# M1889: the disk is not just readable once at LBA 0 — it is a REAL BLOCK DEVICE.
# READ CAPACITY gave it a geometry, blockdev_init registered it as "usb-ehci", and
# the block layer's own write+read-back+coherence+durability check ran against it,
# which exercises the BOT/SCSI WRITE(10) path over EHCI as well as READ(10).
require "registered as a block device (usb-ehci)"  "USB 2.0 disk registered as a block device (READ CAPACITY geometry)"
require ": usb-ehci,"                          "usb-ehci listed in the block-device registry"
require "coherence+durability on usb-ehci"     "block-layer write+read-back+coherence+durability over EHCI bulk"

require "USB tablet active"                    "UHCI USB tablet still active (EHCI is a separate, additional controller)"
require "mounted FAT32 volume"                 "FAT32 still mounted on legacy ATA (boot path intact)"
require "launching the desktop environment"    "reached desktop launch (no fault on the EHCI path)"

# Surface the actual EHCI bring-up lines the driver logged.
grep -iE "EHCI HC up|enumerated device over control|bulk IN: read sector 0|registered as a block device" "$LOG" | sed 's/^/      /' || true

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
forbid "did not complete"            "EHCI enumeration / bulk read did not complete"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest ehci (USB 2.0 HC up, port reset, device enumerated over EHCI control transfers, sector 0 read over EHCI bulk matching known content, UHCI tablet intact, no crash)"
    exit 0
else
    echo "FAIL: in-guest ehci test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
