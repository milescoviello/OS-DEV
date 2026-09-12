#!/bin/sh
# In-guest assertion that SMEP is actually ENFORCED. cpu_harden sets CR4.SMEP,
# which forbids ring 0 from EXECUTING any user-accessible (PTE_USER) page -- the
# classic ret2user defence. Booting `-append smeptest` (M1502) maps such a page,
# puts a RET in it, and calls it from the kernel: that must fault (instruction-
# fetch #PF, error_code 0x11) instead of running. Exit 0 = pass; SKIP if no QEMU.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_smep.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: smep test ($QEMU not found)"
    exit 0
fi

echo "booting with -append smeptest (kernel executes a user page)..."
# SMEP is CPUID-gated: cpu_harden only sets CR4.SMEP if the CPU advertises it, and
# the default TCG CPU does NOT -- so we must request a SMEP-capable model (TCG
# emulates SMEP enforcement for it). This mirrors real hardware, where SMEP is on.
timeout -s KILL 25 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -cpu qemu64,+smep \
    -append smeptest \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 50 ]; do
    grep -q "KERNEL PANIC" "$LOG" 2>/dev/null && break
    grep -q "smeptest] FAILED" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

fail=0
need() { if grep -qiF "$1" "$LOG"; then echo "  ok: $2"; else echo "  MISSING: $2 (expected '$1')"; fail=1; fi; }

need "[smeptest] executing"  "the SMEP test ran (kernel tried to execute a user page)"
# The user page must NOT have executed.
if grep -qiF "[smeptest] FAILED" "$LOG"; then
    echo "  CRASH: SMEP NOT enforced -- ring 0 executed a user page (ret2user open)!"
    fail=1
else
    echo "  ok: the user page did NOT execute from ring 0 -- SMEP held"
fi
need "Page Fault"        "the execute attempt took a page fault"
need "error_code=0x11"   "err 0x11 = instruction-fetch == SMEP blocked ring-0 execution of a user page"

if [ "$fail" -eq 0 ]; then
    echo "PASS: SMEP enforced -- the kernel cannot execute user pages (ret2user defeated)"
    exit 0
else
    echo "FAIL: smep test"
    echo "----- captured COM1 log -----"; cat "$LOG"
    exit 1
fi
