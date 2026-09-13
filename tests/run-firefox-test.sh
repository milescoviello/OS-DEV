#!/bin/sh
# PHASE 8: Firefox runs inside OS-DEV (M1982).
#
# `--version` is a small thing to print and a large thing to reach: it means the
# 268 MB install loaded, ld.so resolved libxul's 83-library closure (GTK, cairo,
# pango, fontconfig, dbus and the rest), and Firefox got as far as its own code.
# It is the same shape of first step as `claude --version` was for Phase 7 -- the
# load-bearing one, not the finish line. Rendering a page in a window is the
# goal and is not done.
#
# NOT part of `make check`: a 268 MB image is minutes per start under TCG.
# SKIPs cleanly when Firefox was never staged.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
EXT2=build/ext2.img
command -v "$QEMU" >/dev/null 2>&1 || { echo "SKIP: firefox test ($QEMU not found)"; exit 0; }
[ -f "$EXT2" ] || { echo "SKIP: firefox test (no $EXT2)"; exit 0; }
[ -f build/lxroot/usr/lib64/firefox/firefox ] || { echo "SKIP: firefox test (not staged; set FIREFOX_DIR=)"; exit 0; }

SLOG=$(mktemp /tmp/osdev_ff.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$SLOG"; exit "$rc"; }
trap cleanup EXIT

echo "booting and running Firefox in-guest (minutes: a 268 MB install under TCG)..."
timeout -s KILL 1800 "$QEMU" -cpu max -snapshot -no-reboot -no-shutdown -m 4G -smp 4 -kernel "$KERNEL" \
    -append "fftest nonetdemo" \
    -drive file="$DISK",format=raw,if=ide \
    -drive file="$EXT2",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -display none -serial file:"$SLOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 3600 ]; do
    grep -aqE "firefox --version ->|KERNEL PANIC" "$SLOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

f=0
if grep -aq "KERNEL PANIC" "$SLOG"; then
    echo "  FAIL: KERNEL PANIC while running Firefox:"; grep -a -A2 "KERNEL PANIC" "$SLOG" | head -3; f=1
fi
if grep -aqE "^Mozilla Firefox [0-9]+" "$SLOG"; then
    echo "  ok: FIREFOX RAN IN OS-DEV -- $(grep -aoE '^Mozilla Firefox [0-9.]+' "$SLOG" | head -1)"
else
    echo "  FAIL: Firefox did not print its version:"; grep -aE "\[ff\]|error while loading|Mozilla" "$SLOG" | head -4; f=1
fi
if grep -aq "firefox --version -> 0" "$SLOG"; then
    echo "  ok: and exited 0"
else
    echo "  FAIL: it did not exit cleanly:"; grep -a "firefox --version ->" "$SLOG" | head -1; f=1
fi
# A clean run is worth asserting on its own: an unimplemented syscall here is a
# gap that will bite the moment Firefox does something real, and it is far
# easier to see now than inside a rendering failure later.
if grep -aq "unimplemented Linux syscall" "$SLOG"; then
    echo "  FAIL: Firefox hit unimplemented syscalls:"; grep -ao "unimplemented Linux syscall [0-9]*" "$SLOG" | sort -u | head -5; f=1
else
    echo "  ok: it asked for nothing we do not implement (zero ENOSYS)"
fi

[ $f -eq 0 ] || { echo "FAIL: Firefox in-guest"; exit 1; }
echo "PASS: PHASE 8 -- Firefox runs inside OS-DEV"
