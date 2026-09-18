#!/bin/sh
# abtest.sh -- one variable at a time, both arms, one pinned kernel, equal windows.
#
# WHY THIS IS A TOOL AND NOT A SCRATCH SCRIPT. Every A/B in this campaign has
# been a throwaway shell loop in a temp directory, and twice that has cost the
# whole run: once when a `make <suite>test` rebuilt the kernel underneath a
# four-boot series (M2191's trap, caught only because tools/ffseries.sh pins the
# digest), and once when the session ended and took the scratch directory --
# scripts, logs and all -- with it. A measurement worth running twice is worth
# keeping.
#
#   ARM=nopathcache tools/abtest.sh          # baseline vs `-append nopathcache`
#   ARM=noreadrun N=4 CORES=8 tools/abtest.sh
#
# Rows are appended to build/abtest-<arm>.txt AS THEY HAPPEN, so a run that is
# killed half way still leaves what it measured.
set -e
cd "$(dirname "$0")/.."

ARM=${ARM:?set ARM to the -append flag under test, e.g. ARM=nopathcache}
N=${N:-3}
CORES=${CORES:-8}
CAP=${CAP:-380}
BASE=${BASE:-"ffwl lxout nonetdemo"}
OUT=build/abtest-$ARM.txt
LOGS=build/ablogs
mkdir -p "$LOGS"

if [ "${NOBUILD:-0}" != 1 ]; then
    echo "==> building"
    make build/kernel32.elf >/dev/null
    make build/ext2.img >/dev/null
fi
PIN=$(md5sum build/kernel32.elf | cut -d' ' -f1)
echo "==> pinned to $PIN, $N boot(s) per arm, $CORES core(s), CAP=$CAP"
: > "$OUT"

row() {   # $1 = tag, $2 = log
    L=$2
    # `crash` is a LINE COUNT and the watcher re-reports a crash every 15s, so
    # read it as "did it crash", not "how many". `samples` counts the probe's
    # own per-sample header, which the watcher prints (M2214 moved it there and
    # the old `[page] --- sample` marker went with the blocking loop).
    printf '%-18s page=%-3s samples=%-3s crashed=%s refused=%s badblk=%-8s itable=%-5s groups=%-4s page_ms=%-7s kstack=%s\n' \
      "$1" \
      "$(grep -ac 'VERDICT: the PAGE is on screen' "$L")" \
      "$(grep -ac '^\[page\] client ' "$L")" \
      "$(grep -aq 'CRASHED with signal' "$L" && echo YES || echo no)" \
      "$(grep -ac 'DEVICE failure, not an' "$L")" \
      "$(grep -ao 'bad block pointers rejected [0-9]*' "$L" | tail -1 | awk '{print $NF}')" \
      "$(grep -ao 'inode tables rejected [0-9]*' "$L" | tail -1 | awk '{print $NF}')" \
      "$(grep -ao 'out-of-range groups [0-9]*' "$L" | tail -1 | awk '{print $NF}')" \
      "$(grep -a 'PAGE ON SCREEN at' "$L" | head -1 | sed -E 's/.*at ([0-9]+) ms.*/\1/')" \
      "$(grep -a 'kstack' "$L" | tail -1 | sed -E 's/.*kstack *([0-9]+) byte.*/\1/')" | tee -a "$OUT"
}

for arm in baseline "$ARM"; do
    EXTRA=""
    [ "$arm" = "$ARM" ] && EXTRA=" $ARM"
    i=1
    while [ "$i" -le "$N" ]; do
        NOW=$(md5sum build/kernel32.elf | cut -d' ' -f1)
        if [ "$NOW" != "$PIN" ]; then
            echo "ABORT: build/kernel32.elf changed ($PIN -> $NOW). Runs either side of"
            echo "       that are different kernels, which is not a series." | tee -a "$OUT"
            exit 1
        fi
        WAIT=full NOBUILD=1 APPEND="$BASE$EXTRA" CORES=$CORES CAP=$CAP tools/pve-run.sh >/dev/null 2>&1
        L=$LOGS/$arm-c$CORES-r$i.log
        scp -q root@"${PVE_HOST:-192.168.1.5}":/root/osdev/boot.log "$L"
        row "$arm r$i" "$L"
        i=$((i+1))
    done
done
echo "==> $OUT"
