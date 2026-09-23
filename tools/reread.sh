#!/bin/sh
# M2219's experiment: when a rejected inode-table pointer is re-read from the
# same sector, does the answer CHANGE? Different => the storage path handed
# back another sector's bytes. Same => the block number we computed was wrong.
set -e
cd "$(dirname "$0")/.."
N=${N:-3}; CORES=${CORES:-8}; CAP=${CAP:-380}
# A REAL SITE, NOT A LOCAL FILE (M2241). Every Firefox measurement M2086-M2240
# used file:///ffpage.html; `ffnet` fetches example.com over the network, which
# is the half of a browser none of those runs touched.
APPEND=${APPEND:-"ffnet lxout nonetdemo"}
if [ "${NOBUILD:-0}" != 1 ]; then
    make build/kernel32.elf >/dev/null
    make lxroot-ready   >/dev/null
fi
PIN=$(md5sum build/kernel32.elf | cut -d' ' -f1); echo "==> pinned $PIN"
mkdir -p build/ablogs
OUT=build/reread.txt; : > "$OUT"
i=1
while [ "$i" -le "$N" ]; do
    NOW=$(md5sum build/kernel32.elf | cut -d' ' -f1)
    [ "$NOW" = "$PIN" ] || { echo "ABORT: kernel changed" | tee -a "$OUT"; exit 1; }
    WAIT=full NOBUILD=1 APPEND="$APPEND" CORES=$CORES CAP=$CAP tools/pve-run.sh >/dev/null 2>&1
    L=build/ablogs/reread-r$i.log
    scp -q root@"${PVE_HOST:-192.168.1.5}":/root/osdev/boot.log "$L"
    printf 'reread r%s: page=%s crashed=%s refused=%s itable=%s\n  %s\n  gdt-at-mount: %s\n' "$i" \
      "$(grep -ac 'VERDICT: the PAGE is on screen' "$L")" \
      "$(grep -aq 'CRASHED with signal' "$L" && echo YES || echo no)" \
      "$(grep -ac 'DEVICE failure, not an\|mapping is EXECUTABLE' "$L")" \
      "$(grep -ao 'inode tables rejected [0-9]*' "$L" | tail -1 | awk '{print $NF}')" \
      "$(grep -a '^\[fs\] superblock' "$L" | tail -1 | sed -E 's/^\[fs\] //')" \
      "$(grep -a 'ext2 GDT self-test' "$L" | tail -1 | sed -E 's/.*self-test: //')" | tee -a "$OUT"
    grep -a '^\[fs\] superblock' "$L" | tail -1 | sed -E 's/.*(gdt: .*)/  \1/' | tee -a "$OUT"
    echo "  low-LBA writes seen:" | tee -a "$OUT"
    grep -a '^\[bdwr\]' "$L" | head -8 | sed 's/^/    /' | tee -a "$OUT"
    i=$((i+1))
done
