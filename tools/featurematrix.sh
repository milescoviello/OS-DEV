#!/bin/sh
# featurematrix.sh -- "all features", defined and then measured.
#
# WHY THIS EXISTS. The standing goal says "all features", and every status
# report I have written ends with "no all-features measurement exists" --
# because nobody had ever said what the features ARE. An undefined
# requirement cannot be met and cannot be honestly reported against, so this
# file is the definition: each row is one capability, one boot, and one
# marker that is either in the log or is not.
#
# The rows are the DEMOS this campaign already defines, not a wish list:
#   claude-ask   the Phase 7 demo -- one `claude -p`, answered correctly
#   claude-bash  the Bash tool executing a command inside OS-DEV
#   claude-edit  Claude editing a file in OS-DEV's own source tree
#   ff-local     Firefox rendering a page from our filesystem
#   ff-net       Firefox rendering a page off the real internet over HTTPS
#   gtk-input    a real GTK app acting on a synthetic click (the M2250 control)
#
# Firefox INPUT is deliberately not a row yet: there is no marker for it that
# a log can carry, and the only honest test is a screenshot diff, which this
# script does not do. Adding a row that cannot fail would be worse than the
# gap it papers over.
#
#   tools/featurematrix.sh              # every row, 8 cores
#   ROWS="claude-bash ff-net" tools/featurematrix.sh
#   CORES=1 tools/featurematrix.sh
#
# Rows are appended to build/featurematrix.txt AS THEY HAPPEN, so a run that
# is killed half way still leaves what it measured.
set -e
cd "$(dirname "$0")/.."

CORES=${CORES:-8}
CAP=${CAP:-900}
# PER-ROW BUDGETS, BECAUSE THE ROWS ARE NOT THE SAME SIZE (M2288).
# claude-edit asks Claude to READ and MODIFY a file in OS-DEV's own tree --
# several tool calls and several network round trips -- where claude-ask is
# one question and one answer. At a shared 300 s cap the edit row reported
# `fail` while its heartbeats showed majflt climbing 26639 -> 27231 and a DNS
# connect at t=296s: it was working, not stuck. A budget that is too small
# for a row does not measure that row, it measures the budget.
row_cap() {
    case $1 in
        claude-edit) echo $((CAP < 700 ? 700 : CAP)) ;;
        *)           echo "$CAP" ;;
    esac
}
ROWS=${ROWS:-"gtk-input ff-local ff-net claude-ask claude-bash claude-edit"}
OUT=build/featurematrix.txt
LOGS=build/ablogs
mkdir -p "$LOGS"

if [ "${NOBUILD:-0}" != 1 ]; then
    make build/kernel32.elf >/dev/null
    make lxroot-ready    >/dev/null
fi

# AN EXPIRED CREDENTIAL IS NOT A CLAUDE FAILURE (M2291).
#
# M2239 made the in-guest token a make prerequisite, so `make lxroot-ready`
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
        make lxroot-ready >/dev/null || exit 1
    fi
fi
PIN=$(md5sum build/kernel32.elf | cut -d' ' -f1)
echo "==> pinned $PIN, $CORES core(s), CAP=$CAP"
: > "$OUT"

# append=... and the marker that proves the row, per row.
row_append() {
    case $1 in
        gtk-input)   echo "ffwl lxgtk nonetdemo" ;;
        ff-local)    echo "ffwl lxout nonetdemo" ;;
        ff-net)      echo "ffnet lxout" ;;
        claude-ask)  echo "lxask lxout nonetdemo" ;;
        claude-bash) echo "lxbash lxout nonetdemo" ;;
        claude-edit) echo "lxedit lxout nonetdemo" ;;
    esac
}
row_marker() {
    case $1 in
        # The GTK row is proved by the client getting a window AND by the
        # compositor forwarding a real button to it -- a window alone says
        # nothing about input.
        gtk-input)   echo "desktop window for client slot 1: .*Information" ;;
        ff-local)    echo "VERDICT: the PAGE is on screen" ;;
        # NOT a hardcoded size (M2260). The first cut asserted
        # "slot 1: 1280x960" and the row failed while the browser was plainly
        # up -- the window came back 1230x939, because the desktop clamps it
        # to the framebuffer minus its own chrome. A marker that encodes a
        # number the system is free to change is a false failure waiting to
        # happen, and this one arrived on its first run.
        ff-net)      echo "desktop window for client slot 1: .*Mozilla Firefox" ;;
        claude-ask)  echo "claude -p -> 0" ;;
        claude-bash) echo "OSDEV-BASH-OK" ;;
        claude-edit) echo "claude -p -> 0" ;;
    esac
}

for r in $ROWS; do
    NOW=$(md5sum build/kernel32.elf | cut -d' ' -f1)
    [ "$NOW" = "$PIN" ] || { echo "ABORT: kernel changed" | tee -a "$OUT"; exit 1; }
    A=$(row_append "$r"); M=$(row_marker "$r")
    RC=$(row_cap "$r")
    WAIT=full NOBUILD=1 APPEND="$A" CORES=$CORES CAP=$RC tools/pve-run.sh >/dev/null 2>&1
    L=$LOGS/feat-$r-c$CORES.log
    scp -q root@"${PVE_HOST:-192.168.1.5}":/root/osdev/boot.log "$L"
    if grep -aqE "$M" "$L"; then V=PASS; else V=fail; fi
    printf '%-12s %-5s  crashed=%-3s  marker: %s\n' "$r" "$V" \
        "$(grep -aq 'CRASHED with signal' "$L" && echo YES || echo no)" "$M" | tee -a "$OUT"
done
echo "==> $OUT"
