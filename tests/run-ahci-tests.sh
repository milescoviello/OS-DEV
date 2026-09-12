#!/bin/sh
# In-guest assertion for the AHCI/SATA driver's IDENTIFY-DEVICE capacity query
# (kernel/ahci.c, M1715). Before M1715 the AHCI driver never issued IDENTIFY, so
# blockdev.c registered every SATA disk with capacity 0 (unknown) and could not
# size or bounds-check it. Now ahci_init() issues IDENTIFY DEVICE per port and
# ahci_disk_sectors() reports the real 512-byte-sector count.
#
# This boots the real kernel headless with ONE non-boot SATA disk of a KNOWN size
# (8 MiB = 16384 sectors) on an AHCI HBA and captures COM1, then asserts:
#   - the HBA came up with 1 SATA disk;
#   - IDENTIFY reported exactly 16384 sectors (the disk's true size);
#   - the block layer registered that capacity (not 0), so its cache
#     write+read-back+coherence+durability self-test runs at the TRUE last sector
#     (lba 16383) and passes -> capacity AND the DMA read/write path are correct
#     right at the disk boundary.
#
# Boot stays on the legacy ATA disk; the SATA disk is scratch (a sparse image made
# here, removed on exit). Exit 0 = pass. SKIPs cleanly if QEMU is absent.
# Companion to run-raid-tests.sh (3 SATA disks for RAID) and run-blockdev-tests.sh
# (a virtio-blk volume); this one pins down the AHCI capacity specifically.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_ahci.XXXXXX.log)
SATA=$(mktemp /tmp/osdev_ahci_disk.XXXXXX.img)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG" "$SATA"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: AHCI test ($QEMU not found)"
    exit 0
fi
truncate -s 8M "$SATA"          # 8 MiB = 16384 sectors of 512 bytes

echo "booting kernel headless with a known-size (16384-sector) SATA disk on an AHCI HBA (COM1 capture)..."
timeout -s KILL 40 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -device ahci,id=ahci0 \
    -drive if=none,id=sata0,file="$SATA",format=raw -device ide-hd,bus=ahci0.0,drive=sata0 \
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
require "AHCI HBA up: 1 SATA"                    "AHCI brought up the SATA disk"
require "ahci0: 16384 sectors"                  "IDENTIFY DEVICE reported the true capacity (16384 sectors = 8 MiB)"
require "ahci0, 16384 sectors"                  "block layer registered the real capacity (was 0 before M1715)"
require "on ahci0 lba 16383: OK"                "cache write+read-back+durability passed at the TRUE last sector"
require "launching the desktop environment"     "reached desktop launch (boot path intact, no fault)"

forbid() {
    if grep -qiE "$1" "$LOG"; then echo "  CRASH MARKER: $2"; grep -inE "$1" "$LOG" | head -2 | sed 's/^/      /'; fail=1; fi
}
forbid "panic"                       "kernel panic"
forbid "page fault"                  "page fault"
forbid "general protection"          "#GP fault"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest AHCI (IDENTIFY capacity 16384 sectors, block layer sized + last-sector I/O OK)"
    exit 0
else
    echo "FAIL: in-guest AHCI test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
