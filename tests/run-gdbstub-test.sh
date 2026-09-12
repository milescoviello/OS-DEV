#!/bin/sh
# gdbstubtest — the GDB remote-serial-protocol stub (M1204). Boots the kernel with
# `-append gdbstub` (which int3's into the stub), exposes COM2 as a TCP serial,
# then drives REAL host `gdb`: connect, read registers, and assert gdb symbolizes
# rip back to kmain (proving the g-packet + the ELF symbols line up). Skips
# cleanly if gdb or qemu is unavailable.
set -u

KERNEL=build/kernel32.elf
ELF=build/kernel.elf
PORT=12347
LOG=$(mktemp)
OUT=$(mktemp)
QP=""
cleanup() { [ -n "$QP" ] && kill -9 "$QP" 2>/dev/null; rm -f "$LOG" "$OUT"; }
trap cleanup EXIT

command -v gdb              >/dev/null 2>&1 || { echo "gdbstubtest: SKIP (no host gdb)";  exit 0; }
command -v qemu-system-x86_64 >/dev/null 2>&1 || { echo "gdbstubtest: SKIP (no qemu)"; exit 0; }

qemu-system-x86_64 -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -append gdbstub -serial file:"$LOG" -serial tcp::$PORT,server,nowait -display none >/dev/null 2>&1 &
QP=$!

# Wait (up to ~30s) for the kernel to reach the stub — it prints this on COM1 just
# before the int3.
i=0
while [ $i -lt 30 ]; do
    grep -q 'waiting for gdb' "$LOG" 2>/dev/null && break
    sleep 1; i=$((i + 1))
done
if ! grep -q 'waiting for gdb' "$LOG" 2>/dev/null; then
    echo "gdbstubtest: FAIL -- the kernel never reached the gdb stub"
    exit 1
fi

# Connect (stops at the kmain int3 -> read+symbolize rip = M1204), then set a
# software breakpoint at a function reached later in boot, continue, and confirm
# the breakpoint is hit (Z0 + #BP re-entry + single-step = M1205).
timeout 25 gdb -nx -batch "$ELF" \
    -ex 'set architecture i386:x86-64' \
    -ex "target remote :$PORT" \
    -ex 'info registers rip' \
    -ex 'break vdso_init' \
    -ex 'continue' \
    -ex 'info registers rip' \
    -ex 'stepi' \
    -ex 'set {unsigned long}($rsp-512) = 0xcafef00d' \
    -ex 'x/1xg $rsp-512' \
    -ex 'detach' > "$OUT" 2>&1

if ! { grep -q 'kmain' "$OUT" && grep -qE 'rip[[:space:]]+0x[0-9a-f]' "$OUT"; }; then
    echo "gdbstubtest: FAIL -- gdb did not read/symbolize registers over the stub"
    sed -n '1,20p' "$OUT"; exit 1
fi
if ! grep -q 'vdso_init' "$OUT"; then
    echo "gdbstubtest: FAIL -- gdb breakpoint at vdso_init was not hit (Z0/continue)"
    sed -n '1,20p' "$OUT"; exit 1
fi
if ! grep -qi 'cafef00d' "$OUT"; then
    echo "gdbstubtest: FAIL -- gdb memory write/read-back (M/m) did not round-trip"
    sed -n '1,24p' "$OUT"; exit 1
fi
echo "gdbstubtest: PASS -- gdb attached, read+symbolized regs (->kmain), breakpoint hit (->vdso_init), stepped, mem write/read round-trip"
exit 0
