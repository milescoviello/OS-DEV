#!/bin/sh
# Headless assertion that OS-DEV runs a REAL Linux binary (M1938-M1939).
#
# The binary under test is built by the HOST compiler as an ordinary static-PIE
# Linux executable (tools/lx/hellofree.c, staged into the ext2 volume by
# `make build/ext2.img`). Nothing about it is built for OS-DEV -- that is the
# whole point. It enters through the `syscall` instruction, which OS-DEV's own
# ABI does not use, and issues Linux write(2) and exit_group(2).
#
# This suite can exist at all only because the Linux write() lands on the
# KERNEL console, which is mirrored to COM1 -- ring-3 print() from OS-DEV's own
# apps is not, which is why the other in-guest checks need screenshots.
#
# SKIPs cleanly if QEMU or the ext2 volume is absent. Exit 0 = pass.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
EXT2=build/ext2.img
command -v "$QEMU" >/dev/null 2>&1 || { echo "SKIP: linuxabi test ($QEMU not found)"; exit 0; }
[ -f "$EXT2" ] || { echo "SKIP: linuxabi test (no $EXT2 -- mke2fs not installed?)"; exit 0; }

SLOG=$(mktemp /tmp/osdev_lxabi.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$SLOG"; exit "$rc"; }
trap cleanup EXIT

echo "booting headless and running a host-built static-PIE Linux binary..."
# The guest's init runs `run /disk2/hellofree` via the boot command line, so no
# keyboard driving is needed -- this stays a pure COM1 assertion.
timeout -s KILL 120 "$QEMU" -no-reboot -no-shutdown -m 256M -smp 4 -kernel "$KERNEL" \
    -append "lxabitest" \
    -drive file="$DISK",format=raw,if=ide \
    -drive file="$EXT2",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -display none -serial file:"$SLOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 220 ]; do
    grep -aq "linuxabi.*guest exited" "$SLOG" 2>/dev/null && break
    sleep 0.5; i=$((i+1))
done

fail=0
# 1. the binary's OWN output, produced by a Linux write(2) through our dispatcher
if grep -aq "hello from a freestanding static-PIE Linux binary" "$SLOG"; then
    echo "  ok: a host-built Linux static-PIE binary ran and printed via Linux write(2)"
else
    echo "  FAIL: the Linux binary produced no output"; fail=1
fi
# 2. exit_group's status must arrive INTACT -- 42 proves the argument register
#    survived the whole entry path, not just that something exited
if grep -aq "guest exited with status 42" "$SLOG"; then
    echo "  ok: exit_group(42) delivered its status through the ABI"
else
    echo "  FAIL: exit_group status wrong or missing:"; grep -a "linuxabi" "$SLOG" | tail -3; fail=1
fi

[ $fail -eq 0 ] || { echo "FAIL: Linux ABI test"; exit 1; }
echo "PASS: Linux ABI — a real static-PIE Linux binary runs under OS-DEV"
