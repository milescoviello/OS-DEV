#!/bin/sh
# In-guest assertion that a RING-3 user-stack overflow is caught by the M1499
# guard page: it must fault cleanly on the guard (a #PF with CR2 in the user-stack
# window ~0x50000000) and terminate ONLY the offending app, leaving the kernel and
# the rest of the boot running -- instead of silently corrupting the app's heap
# below the stack. Boots with `-append ustackover` (M1500), which spawns
# `crash stack` (user/crash.c): a ring-3 app that recurses off its user stack.
# Exit 0 = pass; SKIPs cleanly if QEMU is absent.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_ustack.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: ustack test ($QEMU not found)"
    exit 0
fi

echo "booting with -append ustackover (deliberate ring-3 user-stack overflow)..."
# The app is killed mid-boot; the KERNEL must boot on, so poll for the desktop.
# 30s was sized for a 512 KiB user stack. M1975 made it 16 MiB (Linux gives 8,
# and Claude Code's PT_GNU_STACK asks for 12.2), so RECURSING TO THE GUARD PAGE
# now takes ~32x as long -- and under `make check`'s parallel pool the old
# budget expired before the fault, which reads as "the guard page stopped
# working" when nothing of the sort happened.
timeout -s KILL 180 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -append ustackover \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 360 ]; do
    grep -q "launching the desktop" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

fail=0
need()  { if grep -qiF "$1" "$LOG"; then echo "  ok: $2"; else echo "  MISSING: $2 (expected '$1')"; fail=1; fi; }
neede() { if grep -qiE "$1" "$LOG"; then echo "  ok: $2"; else echo "  MISSING: $2 (expected /$1/)"; fail=1; fi; }

need  "in a ring-3 task"                "a ring-3 task faulted and was terminated"
# The crucial one: the fault address is in the user-stack GUARD page (~USTACK_BASE
# 0x50000000), proving it was a stack overflow hitting the guard -- not the app's
# default null-deref (which would be CR2=0x0) or some unrelated crash.
neede "CR2=0x0000000050000[0-9a-f]{3}"  "fault landed on the user-stack guard page (CR2 ~ USTACK_BASE 0x50000000)"
need  "launching the desktop"           "the KERNEL survived the app overflow and finished booting"

# A kernel panic would mean the overflow corrupted kernel state -- it must not.
if grep -qiE "KERNEL PANIC|Double Fault" "$LOG"; then
    echo "  CRASH: the kernel panicked -- the user overflow was NOT contained to the app"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: ring-3 user-stack overflow caught on the guard, contained to the app; kernel survived"
    exit 0
else
    echo "FAIL: ustack test"
    echo "----- captured COM1 log -----"; cat "$LOG"
    exit 1
fi
