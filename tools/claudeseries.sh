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

# AN EXPIRED CREDENTIAL IS NOT A CLAUDE FAILURE (M2291).
#
# M2239 made the in-guest token a make prerequisite, so `make build/ext2.img`
# restages it whenever the host's is newer. Every series here runs with
# NOBUILD=1 -- which is correct, because rebuilding mid-series changes the
# kernel digest the run is pinned to -- and that skips the restage too. A
# session that outlives the token then measures `Failed to authenticate` and
# records it as the demo failing. That happened: two boots of a three-boot
# series, 35 minutes, reported as Claude failures 26 minutes after the token
# expired.
#
# So check before spending the time, and say exactly what is wrong.
CRED=build/lxroot/root/.claude/.credentials.json
if [ -f "$CRED" ]; then
    if ! python3 - "$CRED" <<'PYEOF'
import json, sys, datetime
d = json.load(open(sys.argv[1]))['claudeAiOauth']
left = d['expiresAt']/1000 - datetime.datetime.now(datetime.UTC).timestamp()
print("    staged credential: %d min left" % (left/60))
sys.exit(0 if left > 300 else 1)
PYEOF
    then
        echo "    -> expired (or under 5 min). Restaging from the host and rebuilding the image."
        make build/ext2.img >/dev/null || exit 1
    fi
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
    # A QUOTA IS NOT AN EXIT CODE (M2319). If the API answered "you've hit your
    # session limit", `claude -p -> 1` is that answer, and averaging it into a
    # pass rate turns someone else's rate limiter into this kernel's flakiness.
    # Four boots of one eight-boot batch were counted that way before the line
    # was spotted. Print LIMIT, and let the reader subtract the sample.
    printf '%s r%s: exit=%-4s t=%-5s bashok=%s crashed=%s | %s\n' "$MODE" "$i" \
      "$(grep -aqiE "hit your (session|usage) limit|usage limit reached" "$L" && echo LIMIT \
         || grep -ao 'claude -p -> -\?[0-9]*' "$L" | tail -1 | awk '{print $NF}')" \
      "$(tr -d '\0' < "$L" | awk '/claude -p ->/{print (last==""?"<60s":last); exit} /runsync\] t=/{match($0,/t=[0-9]+s/); last=substr($0,RSTART+2,RLENGTH-2)}')" \
      "$(grep -aq 'OSDEV-BASH-OK' "$L" && echo YES || echo no)" \
      "$(grep -aq 'CRASHED with signal' "$L" && echo YES || echo no)" \
      "$(grep -a '^\[fs\] superblock' "$L" | tail -1 | sed -E 's/^\[fs\] //; s/\| refused.*//' \
         | grep . || echo 'NO [fs] LINE -- that health line is printed by the ffshow watcher, which these modes do not start')" \
      | tee -a "$OUT"
    grep -a 'ext2 GDT self-test' "$L" | tail -1 | sed 's/^/  /' | tee -a "$OUT"
    grep -aE '^\[lxask\]|^\[lxclaude\]' "$L" | tail -4 | sed 's/^/  /' | tee -a "$OUT"
    i=$((i+1))
done
echo "==> $OUT"
