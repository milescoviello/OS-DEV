#!/bin/sh
# PHASE 7: Claude Code runs inside OS-DEV.
#
# It is a single 214 MB dynamically-linked ELF -- and, unlike Node, it is
# ET_EXEC: NOT position independent, linked at fixed addresses 0x200000 to
# 0xD78F000. It cannot be relocated, so it needs the first gigabyte of the
# address space to belong to the process. That took moving the kernel to the
# higher half (M1968) and dropping the shared identity map (M1969-M1970).
#
# It is also built with Bun, so the engine inside it is JavaScriptCore, not V8 --
# which matters, because JSC asks the system for its stack bounds before it will
# run any JavaScript, and glibc answers that by parsing /proc/self/maps for the
# line whose range contains __libc_stack_end. Ours printed the stack as a bare
# address with no range at all, so the answer was always "error" and JSC aborted
# without printing a thing (M1975).
#
# NOT part of `make check`: the image is 214 MB and every start is minutes under
# TCG emulation. SKIPs cleanly if it was never staged.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
EXT2=build/ext2.img
command -v "$QEMU" >/dev/null 2>&1 || { echo "SKIP: claude test ($QEMU not found)"; exit 0; }
[ -f "$EXT2" ] || { echo "SKIP: claude test (no $EXT2)"; exit 0; }
[ -f build/lxroot/usr/bin/claude ] || { echo "SKIP: claude test (not staged; set CLAUDE_BIN=)"; exit 0; }

SLOG=$(mktemp /tmp/osdev_claude.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$SLOG"; exit "$rc"; }
trap cleanup EXIT

echo "booting and running Claude Code in-guest (minutes: a 214 MB image under TCG)..."
# -m 8G AND ONE CORE, both deliberate (M2118).
#
# 4G was measured as the point where JavaScriptCore's GC starts thrashing, so
# every timing taken from this suite was taken against the one memory size the
# project had already recorded as bad -- and COW always copies since M2044,
# which makes headroom matter more, not less.
#
# One core because M2106 measured guest memory corruption on more than one:
# Firefox took a #GP on a garbage pointer two runs out of two with M2102's COW
# batching on, and once out of two with it off. That bug is open. A test must
# not be the place that flakes on it.
timeout -s KILL 1800 "$QEMU" -cpu max -snapshot -no-reboot -no-shutdown -m 8G -smp 1 -kernel "$KERNEL" \
    -append "lxclaudetest nonetdemo" \
    -drive file="$DISK",format=raw,if=ide \
    -drive file="$EXT2",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -display none -serial file:"$SLOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 3600 ]; do
    grep -aqE "claude --help ->|KERNEL PANIC" "$SLOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

f=0
if grep -aq "KERNEL PANIC" "$SLOG"; then
    echo "  FAIL: KERNEL PANIC while running Claude Code:"; grep -a -A2 "KERNEL PANIC" "$SLOG" | head -3; f=1
fi
# The deep-read check guards the thing that would corrupt a 214 MB image
# silently: a short read at depth leaves the page zero-filled, no error raised.
if grep -aq "read@201326592 -> 4 bytes 4f662874" "$SLOG"; then
    echo "  ok: the 214 MB image reads byte-correct 192 MB in (ext2 double indirection)"
else
    echo "  FAIL: a deep read into the image was wrong:"; grep -a "read@" "$SLOG" | head -4; f=1
fi
# The version string is produced BY JAVASCRIPT, so it can only appear if the
# ET_EXEC image loaded, ld.so resolved it, JSC initialised and ran code.
if grep -aqE "^2\.[0-9]+\.[0-9]+ \(Claude Code\)" "$SLOG"; then
    echo "  ok: CLAUDE CODE RAN IN OS-DEV -- $(grep -aoE '^2\.[0-9]+\.[0-9]+ \(Claude Code\)' "$SLOG" | head -1)"
else
    echo "  FAIL: Claude Code did not print its version:"; grep -aE "lxclaude|abort|signal" "$SLOG" | head -4; f=1
fi
if grep -aq "claude --version -> 0" "$SLOG"; then
    echo "  ok: and exited 0"
else
    echo "  FAIL: it did not exit cleanly:"; grep -a "claude --version ->" "$SLOG" | head -1; f=1
fi
# --help runs the whole argument parser and help renderer -- a real amount of
# the bundled JavaScript, rather than printing one constant.
if grep -aq "Usage: claude \[options\] \[command\] \[prompt\]" "$SLOG" && grep -aq "claude --help -> 0" "$SLOG"; then
    echo "  ok: and --help rendered the full CLI (argument parser + help text), exit 0"
else
    echo "  FAIL: --help did not render:"; grep -aE "Usage: claude|claude --help ->" "$SLOG" | head -2; f=1
fi

[ $f -eq 0 ] || { echo "FAIL: Claude Code in-guest"; exit 1; }
echo "PASS: PHASE 7 -- Claude Code runs inside OS-DEV"
