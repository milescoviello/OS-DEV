#!/bin/sh
# In-guest assertion that a kernel stack overflow is CAUGHT and DIAGNOSED, not a
# silent corruption. Boots the real kernel with `-append kstackover` (M1498),
# which spawns a task that recurses off its guarded kernel stack (M1495); this
# asserts the guard turned the overflow into a clean, labelled panic with a
# working backtrace (M1496). It is the regression test for the exact path that
# hid the M1496 fp_ok bug (no other suite triggers a real kernel fault). The
# overflow used to corrupt the adjacent heap silently (M1491). Exit 0 = pass;
# SKIPs cleanly if QEMU is absent.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_kstack.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: kstack overflow test ($QEMU not found)"
    exit 0
fi

echo "booting kernel with -append kstackover (deliberate guarded-stack overflow)..."
# The overflow task faults (a #DF on IST1) shortly after full bring-up and halts
# the kernel, so we poll for the overflow marker rather than the desktop hand-off.
timeout -s KILL 25 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -append kstackover \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 50 ]; do
    grep -q "KERNEL STACK OVERFLOW" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

fail=0
need() {
    if grep -qiF "$1" "$LOG"; then echo "  ok: $2"
    else echo "  MISSING: $2  (expected substring: '$1')"; fail=1; fi
}
need "deliberately overflowing"  "the M1498 overflow task actually ran"
need "KERNEL STACK OVERFLOW"     "overflow caught + diagnosed via the guard page (M1495)"
need "call trace:"               "panic backtrace emitted"
need "kstack_blow"               "backtrace walked the high-VA guarded stack + symbolized it (M1496)"

# The guard must CONTAIN the overflow: we must NOT see the heap/task-ring
# corruption it used to cause (e.g. the M1491 GPF in task_wake_sleepers).
if grep -qiE "task_wake_sleepers|general protection" "$LOG"; then
    echo "  UNEXPECTED: a secondary corruption fault -- overflow not cleanly contained"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: guarded kernel stack overflow caught, diagnosed, and back-traced"
    exit 0
else
    echo "FAIL: kstack overflow test"
    echo "----- captured COM1 log -----"; cat "$LOG"
    exit 1
fi
