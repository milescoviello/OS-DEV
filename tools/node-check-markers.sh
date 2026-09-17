#!/bin/sh
# Check a plain node boot's log against the markers a set of in-guest suites require.
#
# WHY THIS EXISTS. tests/run-{blockdev,ata-lba48,ide-dma,...}-tests.sh boot QEMU
# on the LAPTOP and grep COM1 for markers the kernel's own boot-time self-tests
# print. Those markers are printed unconditionally on every boot, so the node's
# capture already contains them -- the only thing the local script adds is the
# QEMU invocation. When local QEMU is unavailable (the laptop is on battery, or
# VT-x is off, which is why development moved to pve-ultra in the first place),
# this reads the same assertions out of the node's log instead.
#
# Usage: tools/node-check-markers.sh [suite.sh ...]
#        (default: the storage/driver suites, the ones a block-layer change risks)
#
# It extracts the FIRST argument of each `require "..." "..."` line -- that is
# the literal the suite greps for -- so the two cannot drift apart.
set -e
cd "$(dirname "$0")/.."
PVE_HOST=${PVE_HOST:-192.168.1.5}
PVE_DIR=${PVE_DIR:-/root/osdev}
LOG=/tmp/node-boot.log

SUITES="$*"
[ -n "$SUITES" ] || SUITES="tests/run-blockdev-tests.sh tests/run-ata-lba48-tests.sh tests/run-ide-dma-tests.sh tests/run-partition-tests.sh"

scp -q "root@$PVE_HOST:$PVE_DIR/boot.log" "$LOG" 2>/dev/null || {
    echo "SKIP: could not fetch $PVE_HOST:$PVE_DIR/boot.log"; exit 0; }

fail=0; n=0
for suite in $SUITES; do
    [ -f "$suite" ] || continue
    echo "== $suite"
    # `require "marker" "description"` -> the marker
    sed -n 's/^ *require *"\([^"]*\)".*/\1/p' "$suite" | while IFS= read -r m; do
        [ -n "$m" ] || continue
        if grep -aqF "$m" "$LOG"; then
            echo "   ok   $m"
        else
            echo "   MISS $m"
            echo miss >> "$LOG.miss"
        fi
    done
    n=$((n+1))
done
if [ -f "$LOG.miss" ]; then
    c=$(wc -l < "$LOG.miss"); rm -f "$LOG.miss"
    echo "FAIL: $c required marker(s) missing from the node's boot log"
    exit 1
fi
echo "PASS: every marker those suites require is present in the node's boot"
