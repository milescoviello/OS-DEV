#!/bin/sh
# PHASE 6: real Node.js runs inside OS-DEV.
#
# node is an unmodified 102 MB host binary with 21 shared libraries (libuv,
# c-ares, OpenSSL, ICU, nghttp2, simdjson, sqlite3), staged whole and executed
# through the Linux ABI shim. We do not port Node; we run it. Everything it
# runs ON -- the kernel, the scheduler, the ext2 driver, the memory manager --
# is OS-DEV's own from-scratch code.
#
# Three checks, each strictly harder than the last:
#   1. node --version        -- the 102 MB image loads, ld.so resolves 21
#                               libraries, V8 initialises
#   2. node -e '...'         -- V8 parses, compiles and JITs JavaScript
#   3. node -e 'fs...'       -- the fs module writes, reads, stats and lists,
#                               through libuv onto our ext2 driver
#
# NOT part of `make check`: each Node start is minutes under TCG emulation.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
EXT2=build/ext2.img
command -v "$QEMU" >/dev/null 2>&1 || { echo "SKIP: node test ($QEMU not found)"; exit 0; }
[ -f "$EXT2" ] || { echo "SKIP: node test (no $EXT2)"; exit 0; }

SLOG=$(mktemp /tmp/osdev_node.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$SLOG"; exit "$rc"; }
trap cleanup EXIT

echo "booting and running real Node.js in-guest (minutes: V8 under TCG)..."
timeout -s KILL 1800 "$QEMU" -cpu max -no-reboot -no-shutdown -m 3G -smp 4 -kernel "$KERNEL" \
    -append "lxnodetest nonetdemo" \
    -drive file="$DISK",format=raw,if=ide \
    -drive file="$EXT2",format=raw,if=ide \
    -display none -serial file:"$SLOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 3600 ]; do
    grep -aqE "node fs ->|KERNEL PANIC" "$SLOG" 2>/dev/null && break
    sleep 0.5; i=$((i+1))
done

f=0
if grep -aq "KERNEL PANIC" "$SLOG"; then
    echo "  FAIL: KERNEL PANIC while running Node:"; grep -a -A2 "KERNEL PANIC" "$SLOG" | head -3; f=1
fi
# 1. It loaded and reported its own version.
if grep -aq "^v26" "$SLOG" && grep -aq "\[lxnode\] node --version -> 0" "$SLOG"; then
    echo "  ok: Node ($(grep -ao '^v26[0-9.]*' "$SLOG" | head -1)) loaded -- 102 MB + 21 shared libraries -- and reported its version"
else
    echo "  FAIL: node --version did not run:"; grep -aE "\[lxnode\]|error while loading|Fatal" "$SLOG" | head -3; f=1
fi
# 2. V8 actually EXECUTED JavaScript. The arithmetic is the point: "2" can only
#    come from a working engine, not from a startup path that happened to survive.
if grep -aq "LXNODE: 2 linux x64" "$SLOG" && grep -aq "\[lxnode\] node -e -> 0" "$SLOG"; then
    echo "  ok: V8 parsed, compiled and ran JavaScript (1+1=2, platform linux, arch x64)"
else
    echo "  FAIL: JavaScript did not execute:"; grep -aE "LXNODE:|node -e ->|Fatal|SyntaxError" "$SLOG" | head -3; f=1
fi
# 3. Real file I/O through libuv onto OUR ext2 driver: write, read back, stat,
#    readdir. The three numbers are independent -- a stub that faked one would
#    not get the other two right.
if grep -aq "LXNODEFS: 25 26 true" "$SLOG" && grep -aq "\[lxnode\] node fs -> 0" "$SLOG"; then
    echo "  ok: Node's fs module wrote, re-read, stat'd and listed on the from-scratch ext2 driver"
else
    echo "  FAIL: Node file I/O wrong:"; grep -aE "LXNODEFS|node fs ->|Error" "$SLOG" | head -3; f=1
fi
[ $f -eq 0 ] || { echo "FAIL: Node.js in-guest"; exit 1; }
echo "PASS: PHASE 6 (partial) -- real Node.js runs JavaScript and does file I/O inside OS-DEV"
