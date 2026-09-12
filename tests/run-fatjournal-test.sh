#!/bin/sh
# In-guest proof that a REAL file create on the LIVE FAT32 boot filesystem is
# crash-atomic (M1866). Boots `-append fatjournaltest`: after mounting, it (0)
# does a normal journaled create and reads it back, then (1) creates a file with
# a simulated power loss right after the journal commit point — so the metadata
# is committed to the journal but NOT checkpointed and the file is invisible on
# disk — and asserts journal_recover() replays it so the file appears with the
# exact content, idempotently. Runs on a COPY of the disk image (the test writes
# + deletes a file) so it never perturbs the shared build/fat.img.
# Exit 0 = pass; SKIP if no QEMU.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
TMP=$(mktemp -d /tmp/osdev_fatjournal.XXXXXX)
DISK=$TMP/fat.img
LOG=$TMP/serial.log
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -rf "$TMP"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then echo "SKIP: fatjournal test ($QEMU not found)"; exit 0; fi
cp build/fat.img "$DISK"

echo "booting with -append fatjournaltest (live FAT32 create crash-atomicity)..."
timeout -s KILL 40 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -append fatjournaltest \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 80 ]; do
    grep -q "KERNEL PANIC" "$LOG" 2>/dev/null && break
    grep -q "fatjournal\]" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

if grep -qiF "KERNEL PANIC" "$LOG"; then echo "  CRASH: kernel panicked in the fatjournal test"; tail -6 "$LOG"; exit 1; fi
if grep -qE "fatjournal\].*: OK" "$LOG"; then
    echo "  ok: $(grep -oE '\[fatjournal\].*' "$LOG" | head -1)"
    echo "PASS: a live FAT32 file create is crash-atomic (journaled + recovered)"
    exit 0
elif grep -qE "fatjournal\].*SKIP" "$LOG"; then
    echo "  SKIP: $(grep -oE '\[fatjournal\].*' "$LOG" | head -1)"
    exit 0
else
    echo "FAIL: fatjournal self-test did not report OK"
    grep -a "fatjournal\]" "$LOG" || tail -6 "$LOG"
    exit 1
fi
