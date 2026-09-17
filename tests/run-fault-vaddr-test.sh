#!/bin/sh
# The fault report's library offset must be the address objdump -d uses (M2153).
#
# WHY THIS TEST EXISTS. `app_describe_addr` printed `addr - vma.start + vma.foff`
# and labelled it "+ %lx". That is a FILE OFFSET. For two sessions I fed it
# straight to `objdump --start-address=` while hunting an 8-core Firefox crash,
# and libxul's executable segment is mapped from `p_offset & ~0xfff` at
# `p_vaddr & ~0xfff` with those two a page apart -- so every instruction I
# disassembled was 0x1000 early. One of them landed in the middle of a `movabs`,
# which I then read as proof that an executable page had been corrupted.
#
# WHY IT IS NOT CIRCULAR. The expected value is computed here, on the host, by
# the host's own readelf -- binutils, the same toolchain as the objdump the
# number is meant to feed. The kernel walks the program headers itself. The test
# passes only when those two independent walks agree. Restoring the old print
# makes the kernel's number 0x1000 low and this fails.
#
# SKIPs cleanly if QEMU, the ext2 image or libxul is absent. Exit 0 = pass.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
EXT2=build/ext2.img
LIB=/usr/lib64/firefox/libxul.so
FILEOFF=0x8cbc3a0          # the real offset from the 8-core hunt

command -v "$QEMU" >/dev/null 2>&1 || { echo "SKIP: fault-vaddr test ($QEMU not found)"; exit 0; }
command -v readelf >/dev/null 2>&1 || { echo "SKIP: fault-vaddr test (no readelf)"; exit 0; }
[ -f "$EXT2" ] || { echo "SKIP: fault-vaddr test (no $EXT2)"; exit 0; }
[ -f "$LIB" ]  || { echo "SKIP: fault-vaddr test (no $LIB)"; exit 0; }

# THE ORACLE: binutils' own view of the same file. p_vaddr + (fileoff - p_offset)
# for the PT_LOAD containing the offset.
WANT=$(readelf -lW "$LIB" | awk -v off="$FILEOFF" '
    BEGIN { want = strtonum(off) }
    $1 == "LOAD" {
        po = strtonum($2); pv = strtonum($3); fs = strtonum($5);
        if (want >= po && want < po + fs) { printf "%x\n", pv + (want - po); exit }
    }')
[ -n "$WANT" ] || { echo "SKIP: fault-vaddr test (no LOAD segment of $LIB covers $FILEOFF)"; exit 0; }
echo "host readelf says $LIB file offset $FILEOFF is library vaddr 0x$WANT"

SLOG=$(mktemp /tmp/osdev_faultvaddr.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$SLOG"; exit "$rc"; }
trap cleanup EXIT

echo "booting headless and asking the kernel to resolve the same offset..."
timeout -s KILL 180 "$QEMU" -snapshot -no-reboot -no-shutdown -m 512M -kernel "$KERNEL" \
    -append "faultvaddr nonetdemo" \
    -drive file="$DISK",format=raw,if=ide \
    -drive file="$EXT2",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -display none -serial file:"$SLOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 360 ]; do
    grep -aqE "FAULTVADDR:|KERNEL PANIC" "$SLOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

if grep -aq "KERNEL PANIC" "$SLOG"; then
    echo "FAIL: KERNEL PANIC during the fault-vaddr test:"
    grep -a -A2 "KERNEL PANIC" "$SLOG" | head -3
    exit 1
fi

LINE=$(grep -a "FAULTVADDR:" "$SLOG" | head -1)
if [ -z "$LINE" ]; then
    echo "FAIL: the kernel never printed FAULTVADDR: (did libxul get staged into $EXT2?)"
    tail -5 "$SLOG" | sed 's/^/      /'
    exit 1
fi
echo "  guest: $LINE"

GOT=$(printf '%s\n' "$LINE" | sed -n 's/.*vaddr=\([0-9a-f]*\).*/\1/p')
if [ "$GOT" != "$WANT" ]; then
    echo "FAIL: the kernel resolved $FILEOFF to vaddr 0x$GOT; binutils says 0x$WANT"
    echo "      (a file offset printed as a vaddr is how M2153 got read wrong)"
    exit 1
fi
echo "  ok: the kernel and binutils agree that $FILEOFF is vaddr 0x$GOT"
echo "PASS: the fault report's library offset is the address objdump wants"
