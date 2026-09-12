#!/bin/sh
# In-guest crash-recovery proof for the write-ahead journal on REAL ata hardware
# (M1865). The host journaltest proves the LOGIC under fault injection; this
# proves the SAME kernel code drives an actual disk: it formats a journal in the
# reserved disk tail (mkfatfs leaves [FS_SECTORS, TOTAL_SECTORS) outside the FS),
# runs a normal committed transaction (checkpoint lands), then simulates a power
# loss right after the commit point (dbg_crash) so the target sectors stay OLD,
# and asserts journal_recover() REPLAYS the committed transaction to make them
# NEW -- and is idempotent. Exit 0 = pass; SKIP if no QEMU.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_journalguest.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then echo "SKIP: journalguest test ($QEMU not found)"; exit 0; fi

echo "booting with -append journalguest (journal + crash recovery on real ata)..."
timeout -s KILL 40 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -append journalguest \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 80 ]; do
    grep -q "KERNEL PANIC" "$LOG" 2>/dev/null && break
    grep -q "journalguest\]" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

fail=0
if grep -qiF "KERNEL PANIC" "$LOG"; then echo "  CRASH: kernel panicked running the journal test"; fail=1; fi
if grep -qE "journalguest\].*: OK" "$LOG"; then
    echo "  ok: $(grep -oE '\[journalguest\].*' "$LOG" | head -1)"
    echo "PASS: write-ahead journal commit + crash-recovery replay verified on real ata"
    exit 0
else
    echo "FAIL: journalguest self-test did not report OK"
    echo "----- captured COM1 log -----"; grep -a "journalguest\]" "$LOG" || tail -6 "$LOG"
    exit 1
fi
