#!/bin/sh
# The ext2 path cache must answer correctly when every core uses it (M2155).
#
# WHAT THIS IS ABOUT. `walk_cached()` in kernel/ext2.c (added M2104) is a
# 256-entry path->inode cache. It had no lock. On eight cores two inserts scan
# the same LRU array, pick the same victim slot and interleave their field
# writes, so the slot ends up holding one path's NAME with another's INODE or
# `negative` flag. A lookup of a good library path then answers "absent",
# ext2_pread returns -1, and the page-fault fill mapped the still-zero frame
# over executable code and reported the fault resolved. Firefox died in a
# function half a megabyte from the cause, two runs in three, on 8 cores only.
#
# BOTH ARMS RUN HERE, so the script proves its own sensitivity:
#   1. the fixed cache must report 0 wrong answers
#   2. `-append e2pcracy` restores the original unlocked insert and must FAIL
# An assertion that has never been observed to fail is not an assertion.
#
# AND BOTH ARMS WIDEN THE WINDOW (`e2pcwiden`), for a reason worth stating: the
# unlocked insert's bad window is the few dozen cycles between writing the path
# and writing the inode, against millions of cycles between inserts, so the
# racy arm reported 0 failures over 32000 concurrent reads and proved nothing
# about itself. The delay goes into BOTH inserts, so the arms differ only in
# whether the entry is published atomically -- which is the property under test.
# Widened, the racy arm returns another file's bytes 123 times in 32000 reads
# and the fixed arm zero times.
#
# WHAT IT COMPARES, and why the first two versions of this test were worthless.
# Version one required only that the reads SUCCEED -- and passed with the racy
# cache restored, because a torn slot's dominant symptom is a SUCCESSFUL read
# of the wrong file. Version two compared the first 16 bytes, which on this
# volume is no signature at all: every ELF shares its first 16 and the 600 mime
# files share an XML declaration, so 547 paths collapsed to 13 distinguishable
# ones -- below the 256-entry table, so no slot was ever a victim and the
# collision could not occur. This version hashes 512 bytes, keeps the paths with
# distinct hashes, and requires the exact hash back.
#
# The in-guest test collects >256 REAL files off the ext2 volume, verifies every
# one reads cleanly single-threaded first, then hammers them from one thread per
# core. More paths than slots is the point: with a working set under 256 nothing
# is ever a victim, and the first cut of this test found only 221 files and
# passed on the broken code.
#
# SKIPs cleanly without QEMU or the ext2 image. Exit 0 = pass.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
EXT2=build/ext2.img
command -v "$QEMU" >/dev/null 2>&1 || { echo "SKIP: ext2 race test ($QEMU not found)"; exit 0; }
[ -f "$EXT2" ] || { echo "SKIP: ext2 race test (no $EXT2)"; exit 0; }

SLOG=$(mktemp /tmp/osdev_e2race.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$SLOG"; exit "$rc"; }
trap cleanup EXIT

run_arm() {   # $1 = extra append words, $2 = label
    : > "$SLOG"
    timeout -s KILL 420 "$QEMU" -snapshot -no-reboot -no-shutdown -m 2G -smp 8 \
        -kernel "$KERNEL" -append "e2pcrace e2pcwiden nonetdemo $1" \
        -drive file="$DISK",format=raw,if=ide \
        -drive file="$EXT2",format=raw,if=ide \
        -netdev user,id=net0 -device e1000,netdev=net0 \
        -display none -serial file:"$SLOG" >/dev/null 2>&1 &
    QPID=$!
    i=0
    while [ $i -lt 800 ]; do
        grep -aqE "E2PCRACE: .* -- (PASSED|FAILED)|E2PCRACE: SKIP|KERNEL PANIC" "$SLOG" 2>/dev/null && break
        kill -0 "$QPID" 2>/dev/null || break
        sleep 0.5; i=$((i+1))
    done
    sleep 0.3
    kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""
    grep -a "E2PCRACE:" "$SLOG" | sed "s/^/      [$2] /"
}

echo "hammering the ext2 path cache from 8 cores (fixed, window widened)..."
OUT=$(run_arm "" fixed)
printf '%s\n' "$OUT"
if printf '%s' "$OUT" | grep -q "SKIP"; then
    echo "SKIP: ext2 race test (the guest found too few readable files)"; exit 0
fi
if ! printf '%s' "$OUT" | grep -q "PASSED"; then
    echo "FAIL: the ext2 path cache gave a wrong answer under 8-core load"
    exit 1
fi

echo "and again with the pre-M2155 unlocked insert, which MUST fail..."
OUT2=$(run_arm "e2pcracy" racy)
printf '%s\n' "$OUT2"
if printf '%s' "$OUT2" | grep -q "PASSED"; then
    echo "FAIL: the test passed with the RACY cache restored, so it does not"
    echo "      actually measure the bug -- most likely the working set is"
    echo "      smaller than the 256-entry table, so no slot is ever a victim."
    exit 1
fi
echo "PASS: the path cache is correct under 8-core load, and the test can tell"
