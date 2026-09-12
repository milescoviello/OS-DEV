#!/bin/sh
# In-guest assertion that the GENERAL (M1531) scheduler genuinely runs ordinary
# tasks -- the pin_core=-1 kind task_create makes for every kernel thread AND
# every ring-3 process -- concurrently across MULTIPLE cores, correctly.
#
# This is DISTINCT from smpthreadtest, which exercises the SEPARATE M1530
# smp_thread mechanism (per-core-pinned kernel threads drained by each AP's own
# ap_tick). The general CFS scheduler's cross-core migration of ordinary tasks --
# the thing that actually lets a user app run on an AP -- had no automated guard
# until this test (M1862).
#
# Booting `-append smpschedtest` spawns 8 ordinary task_create() workers, each
# racing to atomically bump a shared counter and ORing the core it lands on into
# a shared mask. Pass = the counter is EXACT (no lost/duplicated updates under
# real concurrency) AND more than one distinct core actually ran a worker.
# Exit 0 = pass; SKIP if no QEMU.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_smpsched.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: smpsched test ($QEMU not found)"
    exit 0
fi

echo "booting with -append smpschedtest (8 ordinary tasks across -smp 4 cores, general scheduler)..."
timeout -s KILL 60 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -smp 4 -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -append smpschedtest \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 90 ]; do
    grep -q "KERNEL PANIC" "$LOG" 2>/dev/null && break
    grep -q "smpschedtest\] counter=" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

fail=0
need() { if grep -qiF "$1" "$LOG"; then echo "  ok: $2"; else echo "  MISSING: $2 (expected '$1')"; fail=1; fi; }

if grep -qiF "KERNEL PANIC" "$LOG"; then
    echo "  CRASH: the kernel panicked running ordinary tasks across cores"
    fail=1
fi
need "smpschedtest] spawning" "the test ran (spawned ordinary tasks via the general scheduler)"
need "counter=12000000 (want 12000000)" "the shared counter is EXACT -- no lost/duplicated updates under real cross-core concurrency"

distinct=$(grep -o "[0-9]* distinct core" "$LOG" | grep -o "^[0-9]*" | head -1)
if [ -n "$distinct" ] && [ "$distinct" -gt 1 ] 2>/dev/null; then
    echo "  ok: $distinct distinct cores actually ran an ordinary task (the general scheduler migrates them, not just the BSP)"
else
    echo "  FAIL: only ran on $distinct core(s) -- the general scheduler is NOT distributing ordinary tasks"
    fail=1
fi
grep -q "smpschedtest\].*: OK" "$LOG" 2>/dev/null && echo "  ok: in-guest self-assertion reported OK" || { echo "  FAIL: in-guest self-assertion did not report OK"; fail=1; }

if [ "$fail" -eq 0 ]; then
    echo "PASS: the general (M1531) scheduler runs ordinary tasks across multiple cores concurrently, correctly"
    exit 0
else
    echo "FAIL: smpsched test"
    echo "----- captured COM1 log -----"; cat "$LOG"
    exit 1
fi
