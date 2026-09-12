#!/bin/sh
# In-guest assertion that smp_thread (M1530) genuinely runs independent kernel
# threads across MULTIPLE cores concurrently -- not just smp_parallel_for's
# split-dispatch-join batch model. Booting `-append smpthreadtest` spawns 4
# threads (kernel/kmain.c's smpthread_test), each racing to atomically
# increment a shared counter and recording which core it landed on, with
# periodic smp_thread_yield() calls so >1 thread can round-robin-share a core.
# Pass = the counter is exact (no lost/duplicated updates under real
# concurrency) AND more than one distinct core was used. Exit 0 = pass; SKIP
# if no QEMU.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_smpthread.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: smpthread test ($QEMU not found)"
    exit 0
fi

echo "booting with -append smpthreadtest (4 real kernel threads across -smp 4 cores)..."
timeout -s KILL 25 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -smp 4 -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -append smpthreadtest \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 50 ]; do
    grep -q "KERNEL PANIC" "$LOG" 2>/dev/null && break
    grep -q "smpthreadtest\] counter=" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

fail=0
need() { if grep -qiF "$1" "$LOG"; then echo "  ok: $2"; else echo "  MISSING: $2 (expected '$1')"; fail=1; fi; }

if grep -qiF "KERNEL PANIC" "$LOG"; then
    echo "  CRASH: the kernel panicked running cross-core threads"
    fail=1
fi
need "smpthreadtest] spawning" "the test ran (spawned kernel threads across cores)"
need "counter=800000 (want 800000)" "the shared counter is EXACT -- no lost/duplicated updates under real cross-core concurrency"

distinct=$(grep -o "[0-9]* distinct core" "$LOG" | grep -o "^[0-9]*" | head -1)
if [ -n "$distinct" ] && [ "$distinct" -gt 1 ] 2>/dev/null; then
    echo "  ok: $distinct distinct cores actually ran a thread (genuine multi-core execution, not just BSP)"
else
    echo "  FAIL: only ran on $distinct core(s) -- not genuinely multi-core"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: smp_thread runs real independent kernel threads across multiple cores concurrently, correctly"
    exit 0
else
    echo "FAIL: smpthread test"
    echo "----- captured COM1 log -----"; cat "$LOG"
    exit 1
fi
