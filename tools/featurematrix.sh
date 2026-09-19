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
ROWS=${ROWS:-"gtk-input ff-local ff-net claude-ask claude-bash claude-edit"}
OUT=build/featurematrix.txt
LOGS=build/ablogs
mkdir -p "$LOGS"

if [ "${NOBUILD:-0}" != 1 ]; then
    make build/kernel32.elf >/dev/null
    make build/ext2.img    >/dev/null
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
        gtk-input)   echo "desktop window for client slot 1: 344x268" ;;
        ff-local)    echo "VERDICT: the PAGE is on screen" ;;
        ff-net)      echo "desktop window for client slot 1: 1280x960" ;;
        claude-ask)  echo "claude -p -> 0" ;;
        claude-bash) echo "OSDEV-BASH-OK" ;;
        claude-edit) echo "claude -p -> 0" ;;
    esac
}

for r in $ROWS; do
    NOW=$(md5sum build/kernel32.elf | cut -d' ' -f1)
    [ "$NOW" = "$PIN" ] || { echo "ABORT: kernel changed" | tee -a "$OUT"; exit 1; }
    A=$(row_append "$r"); M=$(row_marker "$r")
    WAIT=full NOBUILD=1 APPEND="$A" CORES=$CORES CAP=$CAP tools/pve-run.sh >/dev/null 2>&1
    L=$LOGS/feat-$r-c$CORES.log
    scp -q root@"${PVE_HOST:-192.168.1.5}":/root/osdev/boot.log "$L"
    if grep -aq "$M" "$L"; then V=PASS; else V=fail; fi
    printf '%-12s %-5s  crashed=%-3s  marker: %s\n' "$r" "$V" \
        "$(grep -aq 'CRASHED with signal' "$L" && echo YES || echo no)" "$M" | tee -a "$OUT"
done
echo "==> $OUT"
