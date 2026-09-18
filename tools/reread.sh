#!/bin/sh
# M2219's experiment: when a rejected inode-table pointer is re-read from the
# same sector, does the answer CHANGE? Different => the storage path handed
# back another sector's bytes. Same => the block number we computed was wrong.
set -e
cd "$(dirname "$0")/.."
N=${N:-3}; CORES=${CORES:-8}; CAP=${CAP:-380}
if [ "${NOBUILD:-0}" != 1 ]; then
    make build/kernel32.elf >/dev/null
    make build/ext2.img   >/dev/null
fi
PIN=$(md5sum build/kernel32.elf | cut -d' ' -f1); echo "==> pinned $PIN"
mkdir -p build/ablogs
OUT=build/reread.txt; : > "$OUT"
i=1
while [ "$i" -le "$N" ]; do
    NOW=$(md5sum build/kernel32.elf | cut -d' ' -f1)
    [ "$NOW" = "$PIN" ] || { echo "ABORT: kernel changed" | tee -a "$OUT"; exit 1; }
    WAIT=full NOBUILD=1 APPEND="ffwl lxout nonetdemo" CORES=$CORES CAP=$CAP tools/pve-run.sh >/dev/null 2>&1
    L=build/ablogs/reread-r$i.log
    scp -q root@"${PVE_HOST:-192.168.1.5}":/root/osdev/boot.log "$L"
    printf 'reread r%s: page=%s crashed=%s refused=%s itable=%s\n  %s\n' "$i" \
      "$(grep -ac 'VERDICT: the PAGE is on screen' "$L")" \
      "$(grep -aq 'CRASHED with signal' "$L" && echo YES || echo no)" \
      "$(grep -ac 'DEVICE failure, not an\|mapping is EXECUTABLE' "$L")" \
      "$(grep -ao 'inode tables rejected [0-9]*' "$L" | tail -1 | awk '{print $NF}')" \
      "$(grep -a '^\[fs\] superblock' "$L" | tail -1 | sed -E 's/^\[fs\] //')" | tee -a "$OUT"
    i=$((i+1))
done
