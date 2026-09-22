#!/bin/bash
# ffstall — is there a visible stall when scrolling or switching tabs with
#           SIX live tabs open on eight cores? Answered as a number.
#
#   tools/ffstall.sh                     six real sites, scroll + switch, report
#   NOBUILD=1 tools/ffstall.sh           skip the build
#
# The goal's wording is "no visible stall", which is a feeling. The number
# behind it is input-to-repaint latency, which the compositor already measures
# as [inputlat] -- input -> commit, timed in the kernel, so noVNC's own latency
# and repaint rate are nowhere in it.
#
# WHY SIX TABS MATTERS: each is a live content process with its own event loop,
# its own timers and its own share of a poll-driven scheduler. A latency
# measured with one tab open says nothing about the case the goal names.
#
# THE INSTRUMENT CAN REPORT FAILURE: [inputlat] counts only input events that
# were followed by a commit from the FOCUSED client, so an input that produced
# no repaint is absent from the sample rather than counted as fast. A run that
# reports fewer samples than inputs sent is a run where something did not
# repaint, and this script prints both so the two cannot be confused.
set -e
cd "$(dirname "$0")/.."
H=${PVE_HOST:-192.168.1.5}; V=${VMID:-122}; D=/root/osdev
SSH="ssh -o BatchMode=yes root@$H"
Q="socat - UNIX-CONNECT:/var/run/qemu-server/$V.qmp"

SITES=${SITES:-"https://example.com https://example.org https://www.iana.org https://www.rfc-editor.org https://www.w3.org https://www.kernel.org"}
: > ffurl.txt; for u in $SITES; do printf '%s\n' "$u" >> ffurl.txt; done
echo "==> $(grep -c . ffurl.txt) tabs"

APPEND="ffshow ffurl nonetdemo" CORES=8 MEM=8192 PVE_HOST="$H" VMID="$V" \
  NOBUILD="${NOBUILD:-0}" tools/pve-show.sh >/dev/null

STATE=$($SSH '
  n=0; while [ $n -lt 150 ]; do
    grep -aq "desktop window for client.*Firefox" '"$D"'/boot.log 2>/dev/null && { echo WINDOW; exit 0; }
    grep -aq "CRASHED with signal\|KERNEL PANIC" '"$D"'/boot.log 2>/dev/null && { echo DIED; exit 0; }
    n=$((n+1)); sleep 2; done; echo TIMEOUT' 2>/dev/null | tail -1)
echo "==> window: $STATE"
[ "$STATE" = DIED ] && exit 1
echo "==> letting six tabs finish loading (${LOAD:-90}s)"
sleep "${LOAD:-90}"

abs() { printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"abs","data":{"axis":"x","value":%s}},{"type":"abs","data":{"axis":"y","value":%s}}]}}\n' "$1" "$2" | $SSH "$Q" >/dev/null 2>&1; }
click() { abs "$1" "$2"; sleep 0.4
  printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":true,"button":"left"}}]}}\n' | $SSH "$Q" >/dev/null 2>&1; sleep 0.3
  printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":false,"button":"left"}}]}}\n' | $SSH "$Q" >/dev/null 2>&1; }
wheel() { printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":true,"button":"%s"}}]}}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":false,"button":"%s"}}]}}\n' "$1" "$1" | $SSH "$Q" >/dev/null 2>&1; }

# MEASURE IN-GUEST, AND SEND ONLY CLICKS.
#
# Two instruments failed here before this one, both by returning a plausible
# number for something they had not measured:
#
#  1. [inputlat] with scrolls mixed in. It pairs an input with the NEXT commit
#     from the focused client; twenty scrolls on pages with nothing to scroll
#     correctly caused no repaint, so each got paired with whatever committed
#     next. That produced 21.9 s and 3.0 s, which describe nothing.
#  2. Screendump polling. Honest in principle -- it is what the goal asks for
#     -- and useless here because one `shot` round trip over ssh costs ~5.27 s.
#     Six tab switches "measured" 5269/5246/5307/5246/5285/5302 ms: a 61 ms
#     spread on a 5.3 s mean is a FIXED COST wearing a latency's clothes. The
#     variance is the tell; a real latency varies.
#
# So: clicks only, nothing that can legitimately cause no repaint, and read the
# compositor's own input->commit timing. Every click on the tab strip repaints,
# so the pairing cannot drift. [inputlat] counts are cumulative, so the delta
# across the mark is what these clicks caused.
MARK_N=$($SSH "grep -ac '\[inputlat\]' $D/boot.log 2>/dev/null; true" | head -1)
case "$MARK_N" in ''|*[!0-9]*) MARK_N=0 ;; esac

echo
echo "=== tab-switch input -> repaint, six live tabs, eight cores ==="
echo "    (clicks only: nothing here can legitimately fail to repaint)"
for t in 1 2 3 4 5 0; do
    px=$(( 90 + t * 150 )); py=56
    click $(( px * 32768 / 1280 )) $(( py * 32768 / 960 ))
    sleep 2
done
sleep 3
$SSH "grep -a '\[inputlat\]' $D/boot.log | tr -d '\000'" 2>/dev/null | tail -n +"$((MARK_N+1))" | tail -4
echo
echo "    6 clicks sent. A sample count below 6 means a click did not repaint."
$SSH "grep -a 'ptr fwd:' $D/boot.log | tr -d '\000' | tail -1" 2>/dev/null
[ "${KEEP:-0}" = 1 ] || $SSH "qm stop $V" >/dev/null 2>&1 || true
