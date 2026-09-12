#!/bin/sh
# In-guest assertion for the device-mapper RAID (kernel/dm.c). Boots the real
# kernel headless with THREE non-boot SATA disks on an AHCI HBA, so dm_selftest()
# builds RAID-1 / RAID-0 / RAID-5 volumes over them and proves each one's
# defining property:
#
#   - RAID-1 mirror: a write fans out to both members AND a read survives a
#     member failure (served from the surviving member);
#   - RAID-0 stripe: consecutive logical sectors land on distinct members
#     (round-robin distribution), read back correctly;
#   - RAID-5 parity: rotating XOR parity tolerates ANY single-disk failure — a
#     failed member's data is reconstructed from parity + the survivors.
#
# Boot stays on the legacy ATA disk; the three SATA disks are scratch (8 MiB
# sparse images created here, removed on exit). Exit 0 = pass. SKIPs cleanly if
# QEMU is absent. Companion to run-boot-tests.sh (no extra disks -> dm_selftest
# is a clean no-op there, so the normal boot is unaffected).
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_raid.XXXXXX.log)
D0=$(mktemp /tmp/osdev_raidA.XXXXXX.img)
D1=$(mktemp /tmp/osdev_raidB.XXXXXX.img)
D2=$(mktemp /tmp/osdev_raidC.XXXXXX.img)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG" "$D0" "$D1" "$D2"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: RAID test ($QEMU not found)"
    exit 0
fi
for f in "$D0" "$D1" "$D2"; do truncate -s 8M "$f"; done

echo "booting kernel headless with 3 SATA disks on an AHCI HBA (COM1 capture)..."
timeout -s KILL 40 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -device ahci,id=ahci0 \
    -drive if=none,id=r0,file="$D0",format=raw -device ide-hd,bus=ahci0.0,drive=r0 \
    -drive if=none,id=r1,file="$D1",format=raw -device ide-hd,bus=ahci0.1,drive=r1 \
    -drive if=none,id=r2,file="$D2",format=raw -device ide-hd,bus=ahci0.2,drive=r2 \
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
require "AHCI HBA up: 3 SATA"   "AHCI brought up 3 SATA disks (the RAID members)"
require "dm RAID-1 mirror OK"   "RAID-1 mirror: fan-out write + read survives a member failure"
require "dm RAID-0 stripe OK"   "RAID-0 stripe: round-robin distribution across 3 members"
require "dm RAID-5 parity OK"   "RAID-5 parity: single-disk fault reconstructed from parity"
require "dm linear LV OK"       "linear LV: members concatenated into one boundary-spanning address space"

forbid() {
    if grep -qiE "$1" "$LOG"; then echo "  CRASH MARKER: $2"; grep -inE "$1" "$LOG" | head -2 | sed 's/^/      /'; fail=1; fi
}
forbid "panic"                       "kernel panic"
forbid "page fault"                  "page fault"
forbid "general protection"          "#GP fault"
forbid "RAID-[015] FAILED"           "a RAID self-test property failed"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest RAID-1/0/5 (device-mapper over 3 SATA disks, single-disk fault tolerated)"
    exit 0
else
    echo "FAIL: in-guest RAID test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
