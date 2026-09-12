#!/bin/sh
# PHASE 5: OS-DEV builds its OWN KERNEL, inside itself, and that kernel BOOTS.
#
# Two stages, and the second is the one that matters:
#   1. boot OS-DEV, and have GNU make drive the in-guest gcc/as/ld over the
#      whole kernel tree until it produces kernel32.elf;
#   2. pull that ELF out of the ext2 image and BOOT IT under QEMU.
#
# Deliberately NOT part of `make check`: stage 1 compiles 136 real source files
# with a real compiler under TCG emulation and takes roughly fifteen minutes.
# `make check` is already ~20 minutes and is run constantly; this is run when
# the self-hosting claim needs re-proving.
#
# What is self-made and what is borrowed, to be unambiguous: the kernel being
# built is entirely OS-DEV's own source. gcc, as, ld and make are unmodified
# host binaries running through the Linux ABI shim -- that is the whole point
# of the compatibility layer, and they are the only borrowed part.
#
# The userspace applications are NOT rebuilt: kernel/asm/user_blob.asm incbins
# 128 prebuilt ELFs, staged as blobs. This builds the KERNEL from source.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
EXT2=build/ext2.img
OUT=build/selfbuilt-kernel32.elf
command -v "$QEMU"   >/dev/null 2>&1 || { echo "SKIP: self-host test ($QEMU not found)"; exit 0; }
command -v debugfs   >/dev/null 2>&1 || { echo "SKIP: self-host test (debugfs not found -- needed to read the result out)"; exit 0; }
[ -f "$EXT2" ] || { echo "SKIP: self-host test (no $EXT2)"; exit 0; }

SLOG=$(mktemp /tmp/osdev_selfhost.XXXXXX.log)
BLOG=$(mktemp /tmp/osdev_selfboot.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$SLOG" "$BLOG"; exit "$rc"; }
trap cleanup EXIT

echo "stage 1/2: building OS-DEV's own kernel INSIDE OS-DEV (this takes ~15 min under TCG)..."
timeout -s KILL 2700 "$QEMU" -cpu max -no-reboot -no-shutdown -m 3G -smp 4 -kernel "$KERNEL" \
    -append "lxbuildtest nonetdemo" \
    -drive file="$DISK",format=raw,if=ide \
    -drive file="$EXT2",format=raw,if=ide \
    -display none -serial file:"$SLOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 5400 ]; do
    grep -aqE "lxbuild\] make -> |KERNEL PANIC" "$SLOG" 2>/dev/null && break
    sleep 0.5; i=$((i+1))
done
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

f=0
if grep -aq "\[lxbuild\] make -> 0" "$SLOG"; then
    echo "  ok: GNU make drove the in-guest gcc/as/ld over the whole kernel tree and exited 0"
else
    echo "  FAIL: the in-guest build did not complete:"
    grep -aE "\[lxbuild\]|Error [0-9]|undefined reference|TRUNCATED" "$SLOG" | head -6; f=1
fi
# The SIZE is the claim, not just the marker: an empty or truncated ELF would
# still let make exit 0 if the link had silently produced one.
if grep -aqE "\[lxbuild\] kernel32.elf built in-guest: [0-9]{7,} bytes" "$SLOG"; then
    echo "  ok: it produced a kernel ($(grep -ao 'built in-guest: [0-9]* bytes' "$SLOG" | head -1))"
else
    echo "  FAIL: no kernel was produced:"; grep -a "kernel32.elf" "$SLOG" | head -2; f=1
fi
[ $f -eq 0 ] || { echo "FAIL: in-guest kernel build"; exit 1; }

# --- stage 2: BOOT WHAT IT BUILT ------------------------------------------
# This is the assertion the whole phase exists for. A kernel that links is not
# a kernel that runs, and only booting it proves the toolchain produced correct
# code rather than merely well-formed object files.
mkdir -p build
debugfs -R "dump /src/kernel32.elf $OUT" "$EXT2" >/dev/null 2>&1 || true
[ -s "$OUT" ] || { echo "FAIL: could not read the self-built kernel out of the ext2 image"; exit 1; }
echo "stage 2/2: booting the kernel OS-DEV just built ($(wc -c < "$OUT") bytes)..."
timeout -s KILL 240 "$QEMU" -no-reboot -no-shutdown -m 512M -smp 4 -kernel "$OUT" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -display none -serial file:"$BLOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 400 ]; do
    grep -aqE "launching the desktop environment|KERNEL PANIC" "$BLOG" 2>/dev/null && break
    sleep 0.5; i=$((i+1))
done

f2=0
if grep -aq "KERNEL PANIC" "$BLOG"; then
    echo "  FAIL: the self-built kernel PANICKED:"; grep -a -A2 "KERNEL PANIC" "$BLOG" | head -3; f2=1
fi
# Three markers, each proving a different layer came up under the self-built
# code: the scheduler + memory (bring-up), SMP, and reaching userspace.
for m in "full bring-up complete" "CPUs online" "launching the desktop environment"; do
    if grep -aq "$m" "$BLOG"; then
        echo "  ok: self-built kernel reached '$m'"
    else
        echo "  FAIL: self-built kernel never reached '$m'"; f2=1
    fi
done
[ $f2 -eq 0 ] || { echo "FAIL: the self-built kernel did not boot"; exit 1; }
echo "PASS: PHASE 5 -- OS-DEV built its own kernel inside itself, and that kernel BOOTS"
