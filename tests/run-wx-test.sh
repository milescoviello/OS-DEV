#!/bin/sh
# In-guest assertion that W^X / NX is actually ENFORCED, not merely configured.
# vmm_harden_kernel (M1475) marks .data/.bss no-execute; this boots with
# `-append wxtest` (M1501), which makes the kernel try to EXECUTE a byte placed in
# a .bss buffer. That must fault with an instruction-fetch #PF (error_code 0x11 =
# present + instruction-fetch == an NX/execute violation) -- the headline
# anti-code-injection guarantee -- instead of running the byte. Exit 0 = pass;
# SKIPs cleanly if QEMU is absent.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_wx.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: wx test ($QEMU not found)"
    exit 0
fi

echo "booting with -append wxtest (deliberate execute-from-no-execute-data)..."
timeout -s KILL 25 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -append wxtest \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 50 ]; do
    grep -q "KERNEL PANIC" "$LOG" 2>/dev/null && break          # NX faulted (expected)
    grep -q "wxtest] FAILED" "$LOG" 2>/dev/null && break        # NX did NOT fault (bad)
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

fail=0
need() { if grep -qiF "$1" "$LOG"; then echo "  ok: $2"; else echo "  MISSING: $2 (expected '$1')"; fail=1; fi; }

need "[wxtest] calling into"  "the W^X test ran (attempted to execute a .bss byte)"
# The crucial one: the no-execute byte must NOT have run.
if grep -qiF "[wxtest] FAILED" "$LOG"; then
    echo "  CRASH: W^X NOT enforced -- the kernel executed bytes from a no-execute page!"
    fail=1
else
    echo "  ok: the no-execute byte did NOT run -- W^X held"
fi
need "Page Fault"        "the execute attempt took a page fault"
need "error_code=0x11"   "err 0x11 = instruction-fetch on a present page == an NX/execute violation"

if [ "$fail" -eq 0 ]; then
    echo "PASS: W^X/NX enforced -- executing a data page faults (code injection defeated)"
    exit 0
else
    echo "FAIL: wx test"
    echo "----- captured COM1 log -----"; cat "$LOG"
    exit 1
fi
