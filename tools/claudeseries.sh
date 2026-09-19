#!/bin/sh
# claudeseries.sh -- how reliably does Claude Code work, measured the same way
# tools/ffseries.sh measures Firefox.
#
# The goal names two programs and the whole of M2151-M2232 went into one of
# them. Everything found there is shared machinery -- the /proc/partitions
# device-table teardown (M2229/M2231) took out any disk read on any core, and
# Bun reads /proc constantly -- so Claude Code's reliability is a MEASUREMENT
# that is now owed, not an assumption that it came along for the ride.
#
#   MODE=lxask  tools/claudeseries.sh     # the Phase 7 demo: one `claude -p`
#   MODE=lxbash tools/claudeseries.sh     # the Bash-tool demo (OSDEV-BASH-OK)
#   MODE=lxedit tools/claudeseries.sh     # edit a file in OS-DEV's own tree
#
# Same discipline as every other series here: one pinned kernel digest, equal
# windows, and rows appended to build/claude-<mode>.txt AS THEY HAPPEN so a
# killed run still leaves what it measured.
set -e
cd "$(dirname "$0")/.."

MODE=${MODE:-lxask}
N=${N:-3}
CORES=${CORES:-8}
CAP=${CAP:-900}          # a 214 MB Bun binary starting up, then a network round trip
OUT=build/claude-$MODE.txt
LOGS=build/ablogs
mkdir -p "$LOGS"

if [ "${NOBUILD:-0}" != 1 ]; then
    make build/kernel32.elf >/dev/null
    make build/ext2.img   >/dev/null
fi
PIN=$(md5sum build/kernel32.elf | cut -d' ' -f1)
echo "==> pinned $PIN, mode $MODE, $N boot(s), $CORES core(s), CAP=$CAP"
: > "$OUT"

i=1
while [ "$i" -le "$N" ]; do
    NOW=$(md5sum build/kernel32.elf | cut -d' ' -f1)
    [ "$NOW" = "$PIN" ] || { echo "ABORT: kernel changed" | tee -a "$OUT"; exit 1; }
    WAIT=full NOBUILD=1 APPEND="$MODE lxout nonetdemo" CORES=$CORES CAP=$CAP \
        tools/pve-run.sh >/dev/null 2>&1
    L=$LOGS/claude-$MODE-c$CORES-r$i.log
    scp -q root@"${PVE_HOST:-192.168.1.5}":/root/osdev/boot.log "$L"
    printf '%s r%s: exit=%-4s bashok=%s crashed=%s | %s\n' "$MODE" "$i" \
      "$(grep -ao 'claude -p -> -\?[0-9]*' "$L" | tail -1 | awk '{print $NF}')" \
      "$(grep -aq 'OSDEV-BASH-OK' "$L" && echo YES || echo no)" \
      "$(grep -aq 'CRASHED with signal' "$L" && echo YES || echo no)" \
      "$(grep -a '^\[fs\] superblock' "$L" | tail -1 | sed -E 's/^\[fs\] //; s/\| refused.*//')" \
      | tee -a "$OUT"
    i=$((i+1))
done
echo "==> $OUT"
