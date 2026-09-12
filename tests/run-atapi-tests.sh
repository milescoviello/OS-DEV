#!/bin/sh
# In-guest assertion for the ATAPI CD-ROM read driver (kernel/atapi.c, M1852).
# ata.c is a plain-ATA disk driver that SKIPS ATAPI-signature devices; atapi.c
# claims them and reads 2048-byte logical sectors via the SCSI PACKET protocol
# (READ CAPACITY + READ(10)), all PIO/polled.
#
# Boots the real kernel headless with a CD-ROM (a minimal ISO 9660 image made
# here, whose only real content is the Primary Volume Descriptor at logical
# sector 16) attached via -cdrom, and captures COM1. The boot disk stays on
# legacy ATA; the CD is a separate device, so make check's default config is
# untouched. Asserts:
#   - the driver detected an ATAPI CD-ROM and read its capacity;
#   - it read logical sector 16 over the PACKET transport and found the ISO 9660
#     "CD001" magic (proves detect + PACKET + READ(10) at a non-zero LBA);
#   - the boot path stayed intact (reached the desktop) with no panic.
# Exit 0 = pass. SKIPs cleanly if QEMU or python3 is absent.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_atapi.XXXXXX.log)
ISO=$(mktemp /tmp/osdev_atapi.XXXXXX.iso)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG" "$ISO"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then echo "SKIP: ATAPI test ($QEMU not found)"; exit 0; fi
if ! command -v python3 >/dev/null 2>&1; then echo "SKIP: ATAPI test (python3 not found to build the ISO)"; exit 0; fi

# A minimal but BROWSABLE ISO 9660: PVD @ sector 16 -> root directory @ sector 18
# (".", "..", "F.TXT;1") -> file data @ sector 20. Lets the driver read the PVD AND
# the block layer auto-mount + list it (M1853/M1854).
python3 - "$ISO" <<'PY'
import sys
LOG = 2048
img = bytearray(LOG * 24)
def dir_rec(off, extent, length, is_dir, name):
    nl = len(name); lendr = 33 + nl
    if lendr & 1: lendr += 1
    img[off] = lendr
    img[off+2:off+6] = extent.to_bytes(4, 'little')
    img[off+10:off+14] = length.to_bytes(4, 'little')
    img[off+25] = 2 if is_dir else 0
    img[off+32] = nl
    img[off+33:off+33+nl] = name
    return lendr
pvd = 16 * LOG
img[pvd] = 1; img[pvd+1:pvd+6] = b"CD001"; img[pvd+6] = 1
dir_rec(pvd + 156, 18, LOG, True, b"\x00")           # root directory record -> extent 18
t = 17 * LOG; img[t] = 255; img[t+1:t+6] = b"CD001"; img[t+6] = 1
off = 18 * LOG
off += dir_rec(off, 18, LOG, True, b"\x00")          # "."
off += dir_rec(off, 18, LOG, True, b"\x01")          # ".."
off += dir_rec(off, 20, 27, False, b"F.TXT;1")       # a real file
f = 20 * LOG; img[f:f+27] = b"hello iso9660 fuzz harness\n"
open(sys.argv[1], "wb").write(img)
PY

echo "booting kernel headless with an ATAPI CD-ROM attached (COM1 capture)..."
timeout -s KILL 40 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -cdrom "$ISO" \
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
require "ATAPI CD-ROM"                        "detected the ATAPI CD-ROM + read its capacity"
require "read PVD ok, CD001 found"            "PACKET READ(10) of sector 16 returned the ISO 9660 PVD"
require "ISO 9660 volume mounted"             "the block layer auto-mounted the CD as an ISO 9660 volume (M1853)"
require "F.TXT"                               "the mounted CD's root directory listed its file (M1854 browse)"
require "launching the desktop environment"   "reached desktop launch (boot path intact)"

forbid() {
    if grep -qiE "$1" "$LOG"; then echo "  CRASH MARKER: $2"; grep -inE "$1" "$LOG" | head -2 | sed 's/^/      /'; fail=1; fi
}
forbid "panic"        "kernel panic"
forbid "unhandled"    "unhandled exception"

if [ "$fail" = 0 ]; then echo "PASS: ATAPI CD-ROM driver (detect + PACKET READ(10) + ISO 9660 PVD, boot intact)"
else echo "FAIL: ATAPI CD-ROM test"; exit 1; fi
