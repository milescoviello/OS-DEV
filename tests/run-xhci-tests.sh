#!/bin/sh
# In-guest assertion for the xHCI (USB 3.0) host-controller driver (kernel/xhci.c).
# Boots the real kernel headless under QEMU with an xHCI controller attached
# (-device qemu-xhci) AND a USB flash disk on ITS bus (-device usb-storage,
# bus=xhci.0), captures COM1, and asserts the driver brought the USB 3.0 host up
# and drove it end to end:
#
#   - the xHCI controller was probed by PCI class (0x0C/0x03/0x30), reset, and
#     started with its command + event rings running ("xHCI HC up:" + MaxSlots /
#     MaxPorts / HCIVERSION);
#   - the command + event rings work end to end: ENABLE SLOT returned a slot id
#     ("ENABLE SLOT got slot id");
#   - a root port was reset + a device detected ("root-port N reset + detected a
#     device");
#   - the device was ENUMERATED over xHCI — ENABLE SLOT + ADDRESS DEVICE, then its
#     device descriptor (idVendor/idProduct/bDeviceClass) read over the EP0
#     transfer ring, the config descriptor read, SET_CONFIGURATION sent ("xHCI
#     enumerated device over control transfers");
#   - STRETCH bulk path: the device is a BOT/SCSI mass-storage; the driver
#     configured its bulk endpoints and read SECTOR 0 over xHCI bulk (BOT + SCSI
#     READ(10)) and logged its additive checksum + first 16 bytes. We build the
#     disk image on the host with known content, compute sector 0's checksum +
#     marker, and assert the kernel logged EXACTLY those — i.e. the bulk path moved
#     the right bytes off the device.
#   - the existing UHCI controller + its usb-tablet AND the EHCI controller stay up
#     (separate controllers), boot still mounts FAT32 on legacy ATA, and the
#     desktop launches with no fault — xHCI is purely additional.
#
# Exit 0 = pass. SKIPs cleanly if QEMU or python3 is absent (or if QEMU's build
# lacks the qemu-xhci device). Companion to run-boot-tests.sh (no xHCI controller
# there -> the driver must cleanly no-op, and UHCI + EHCI must still come up).
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
IMG=build/xhci_test.img
LOG=$(mktemp /tmp/osdev_xhci.XXXXXX.log)
EXP=$(mktemp /tmp/osdev_xhci_exp.XXXXXX)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG" "$EXP"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: xhci test ($QEMU not found)"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: xhci test (python3 not found)"
    exit 0
fi
# qemu-xhci must be a known device in this QEMU build, else skip cleanly.
if ! "$QEMU" -device help 2>/dev/null | grep -qi "qemu-xhci"; then
    echo "SKIP: xhci test (qemu-xhci device not available in this QEMU build)"
    exit 0
fi

# Build a tiny known-content image + print the sector-0 checksum the kernel will
# log, so the assertion compares against host-computed truth. 64 sectors (32 KiB)
# is tiny but real; the kernel reads sector 0 over xHCI bulk (BOT/SCSI READ(10)).
python3 - "$IMG" "$EXP" <<'PY'
import sys
SEC, NSEC = 512, 64
buf = bytearray(SEC * NSEC)
for s in range(NSEC):
    off = s * SEC
    marker = ("XHCI-USB SECTOR %d!" % s).encode()
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

echo "booting kernel headless under QEMU with a qemu-xhci controller + a usb-storage flash disk on its bus (COM1 capture)..."
# The ONLY additions vs run-boot-tests.sh are the qemu-xhci controller, an extra
# -drive (if=none), and a usb-storage device on the xHCI bus. The UHCI controller
# + its tablet AND the EHCI controller stay (the xHCI host is a SEPARATE,
# additional USB controller); boot still uses the IDE/ATA disk. The 40s timeout
# matches the usb-storage/ehci tests (the boot does a real TLS handshake under TCG
# before the desktop); we poll + stop early.
timeout -s KILL 40 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -device usb-ehci,id=ehci \
    -device qemu-xhci,id=xhci \
    -drive id=xstick,file="$IMG",format=raw,if=none \
    -device usb-storage,bus=xhci.0,drive=xstick \
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

# The xHCI controller came up: USB 3.0 host, command + event rings, MaxSlots/Ports.
require "xHCI HC up: USB 3.0 host"            "xHCI controller probed + reset + command/event rings running (MaxSlots/MaxPorts/version)"
# The command + event rings work end to end: ENABLE SLOT returned a slot id.
require "ENABLE SLOT got slot id"             "command + event rings working (ENABLE SLOT got a slot)"
# A root port reset + detected a device.
require "reset + detected a device"           "xHCI root-port reset detected a device"
# The device was enumerated over xHCI control transfers (descriptors read).
require "xHCI enumerated device over control transfers"  "device descriptor read over xHCI (ADDRESS DEVICE + EP0 TRB ring)"
require "idVendor="                            "device idVendor/idProduct/class read over xHCI"
# STRETCH: it is a BOT/SCSI mass-storage; the bulk endpoints were found.
require "device is BOT/SCSI mass-storage: bulk-in=ep"  "BOT/SCSI mass-storage interface + bulk endpoints found"
require "xHCI bulk IN: read sector 0 over xHCI"  "sector 0 read over xHCI bulk (BOT/SCSI READ(10))"
# It read the RIGHT bytes: the host-computed sector-0 checksum + first-16 bytes
# must appear verbatim in the kernel's bulk-read log line (the headline proof the
# xHCI bulk path moved real disk content, not a fluke).
while read -r line; do
    require "$line"                            "xHCI bulk read matches known sector-0 content ($line)"
done < "$EXP"
# M1889: the disk is not just readable once at LBA 0 — it is a REAL BLOCK DEVICE.
# READ CAPACITY gave it a geometry, blockdev_init registered it as "usb-xhci", and
# the block layer's own write+read-back+coherence+durability check ran against it,
# which exercises the BOT/SCSI WRITE(10) path over xHCI as well as READ(10).
require "registered as a block device (usb-xhci)"  "USB 3.0 disk registered as a block device (READ CAPACITY geometry)"
require ": usb-xhci,"                          "usb-xhci listed in the block-device registry"
require "coherence+durability on usb-xhci"     "block-layer write+read-back+coherence+durability over xHCI bulk"

# The existing UHCI controller + its tablet stay up (xHCI is a separate host),
# boot stayed on legacy ATA, and the desktop launched with no fault.
require "USB tablet active"                    "UHCI USB tablet still active (xHCI is a separate, additional controller)"
require "mounted FAT32 volume"                 "FAT32 still mounted on legacy ATA (boot path intact)"
require "launching the desktop environment"    "reached desktop launch (no fault on the xHCI path)"

# Surface the actual xHCI bring-up lines the driver logged.
grep -iE "xHCI HC up|ENABLE SLOT|enumerated device over control|bulk IN: read sector 0|registered as a block device" "$LOG" | sed 's/^/      /' || true

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
forbid "did not complete"            "xHCI enumeration / bulk read did not complete"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest xhci (USB 3.0 HC up, command/event rings, port reset, device enumerated over xHCI control transfers, sector 0 read over xHCI bulk matching known content, UHCI tablet intact, no crash)"
    exit 0
else
    echo "FAIL: in-guest xhci test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
