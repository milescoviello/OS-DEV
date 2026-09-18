#!/bin/sh
# A cache that answers with the WRONG BLOCK is worse than no cache (M2176).
#
# Host test: tests/bcache/bcache_test.c #includes kernel/bcache.c and stubs the
# few kernel symbols it touches. No QEMU, no disk, a couple of seconds.
#
# WHY IT EXISTS. `bcache_selftest` in the guest measures the HIT RATE, which is
# the usable size and says nothing about correctness. Nothing checked that a
# lookup returns the bytes installed for that exact (owner, lba) -- and that is
# the class that cost this project a day: a sector served confidently with the
# wrong contents was read by ext2 as an inode, and 8,999,698 garbage block
# pointers came out of it.
#
# THE INVARIANT: a hit must return exactly the bytes last installed for that
# key, or it must MISS. A miss is always legal -- a cache may forget anything --
# so nothing here asserts that something IS cached, only that nothing is ever
# answered WRONG. That asymmetry keeps it immune to replacement-policy changes.
#
# Plus the chain-integrity counter, because bc_find's cycle bound turns a
# corrupt chain into a legal miss and would otherwise HIDE the bug it guards
# against. Removing the unlink from bcache_install's eviction makes the test
# fail with 58 chain-bound hits; without that check the same mutation passes.
set -e
cd "$(dirname "$0")/.."
CC=${CC:-gcc}
command -v "$CC" >/dev/null 2>&1 || { echo "SKIP: bcache test (no $CC)"; exit 0; }

BIN=$(mktemp /tmp/osdev_bcache.XXXXXX)
trap 'rm -f "$BIN"' EXIT

echo "building the block-cache correctness test (ASan + UBSan)..."
$CC -O1 -g -fsanitize=address,undefined -I kernel/include -o "$BIN" \
    tests/bcache/bcache_test.c || { echo "FAIL: bcache test did not build"; exit 1; }

if timeout 300 "$BIN"; then
    echo "PASS: bcache.c never answered with another key's bytes (ASan/UBSan clean)"
else
    echo "FAIL: bcache.c correctness test"
    exit 1
fi
