#!/bin/sh
cd /home/miles/OS-DEV
S=/tmp/claude-1000/-home-miles-OS-DEV/026bcdb5-8d88-4ad7-9f23-58649bf4f353/scratchpad
# A SERIES IS ONLY A SERIES IF EVERY RUN USED THE SAME BINARY (M2191, and I did
# it again). pve-run.sh with NOBUILD=1 does not rebuild but it DOES rsync
# build/kernel32.elf, so rebuilding while a series is in flight silently splits
# it across two kernels. Pin the digest at the start and stop if it moves.
PIN=$(md5sum build/kernel32.elf | cut -d' ' -f1)
echo "series pinned to kernel $PIN"
TAG=${TAG:-m2202}
CORES=${CORES:-1}
N=${N:-3}
CAP=${CAP:-420}
i=1
while [ $i -le $N ]; do
    NOW=$(md5sum build/kernel32.elf | cut -d' ' -f1)
    if [ "$NOW" != "$PIN" ]; then
        echo "ABORTING at run $i: build/kernel32.elf changed ($PIN -> $NOW). The runs so far and"
        echo "the runs after would be different kernels, which is not a series."
        exit 1
    fi
    WAIT=full NOBUILD=1 APPEND="ffwl lxout nonetdemo" CORES=$CORES CAP=$CAP tools/pve-run.sh >/dev/null 2>&1
    scp -q root@192.168.1.5:/root/osdev/boot.log $S/$TAG-c$CORES-r$i.log
    L=$S/$TAG-c$CORES-r$i.log
    printf '%s c%s run %s: page=%s samples=%s crash=%s spin=%s paint_ms=%s page_ms=%s unshared=%s sharedcow=%s napms=%s\n' \
        "$TAG" "$CORES" "$i" \
        "$(grep -ac 'VERDICT: the PAGE is on screen' $L)" \
        "$(grep -ac '\[page\] --- sample' $L)" \
        "$(grep -ac 'CRASHED with signal' $L)" \
        "$(grep -ac 'SPINNING' $L)" \
        "$(grep -a 'FIRST PAINT at' $L | head -1 | sed -E 's/.*at ([0-9]+) ms.*/\1/')" \
        "$(grep -a 'PAGE ON SCREEN at' $L | head -1 | sed -E 's/.*at ([0-9]+) ms.*/\1/')" \
        "$(grep -a 'sampled page(s) agree' $L | tail -1 | sed -E 's/.*agree, ([0-9]+) do NOT.*/\1/')" \
        "$(grep -a 'COW fault(s) on a shared page' $L | tail -1 | sed -E 's/.*; ([0-9]+) COW fault.*/\1/')" \
        "$(grep -a 'ACTUALLY' $L | tail -1 | sed -E 's/.*naps, ([0-9]+) ACTUALLY.*/\1/')"
    i=$((i+1))
done
