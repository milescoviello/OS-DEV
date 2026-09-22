#!/bin/bash
# ttp-profile — WHERE do the 27.76 seconds of time-to-page go?
#
# The [budget] block says this boot is 89% idle, so it is latency-bound: the
# time is spent WAITING, not computing, and no amount of making the named
# costs cheaper moves it. That is a shape, not an answer. This builds the
# timeline the shape implies -- every event on the critical path, in order,
# with the gap to the previous one -- so the biggest WAIT can be named instead
# of guessed at.
#
# Every "obvious" hot spot in this project has been wrong at least once, so
# this deliberately does not assume the disk, the network or the compositor.
# It prints what happened and when.
set -e
cd "$(dirname "$0")/.."
H=${PVE_HOST:-192.168.1.5}; V=${VMID:-122}; D=/root/osdev
SSH="ssh -o BatchMode=yes -o ConnectTimeout=20 root@$H"

[ "${NOBOOT:-0}" = 1 ] || {
  : > ffurl.txt; printf '%s\n' "${URL:-https://example.com}" >> ffurl.txt
  echo "==> booting ${URL:-https://example.com}"
  # NO `|| true`, AND CHECK THE LOG IS FRESH. The first cut swallowed
  # pve-run.sh's exit status and then read a boot.log left by the PREVIOUS
  # run -- 892 lines of a boot that never started Firefox -- and reported "no
  # timeline events" as though that were a finding about the page load. The
  # harness has a freshness guard precisely for this; hiding its exit status
  # disabled it.
  T0=$(date -u +%s)
  WAIT=full APPEND="ffshow ffurl nonetdemo" CORES=8 MEM=8192 CAP=${CAP:-150} \
    tools/pve-run.sh > /tmp/ttp-run.txt 2>&1 || {
        echo "ttp-profile: pve-run.sh FAILED (exit $?):"; tail -5 /tmp/ttp-run.txt; exit 1; }
  LOGT=$($SSH "stat -c %Y $D/boot.log 2>/dev/null || echo 0")
  [ "$LOGT" -ge "$T0" ] || { echo "ttp-profile: boot.log is STALE (mtime $LOGT < start $T0) -- refusing"; exit 2; }
}

$SSH "grep -aE 'PAGE ON SCREEN|\[ff\] firefox rc|\[net\] t=|\[exec\] pid|desktop is taking over|\[resolver\]|\[sock\] connect' $D/boot.log | tr -d '\000'" > /tmp/ttp.txt 2>/dev/null || true
python3 - /tmp/ttp.txt <<'PY'
import re, sys
lines = open(sys.argv[1]).read().splitlines()
ev = []
for l in lines:
    m = re.search(r'\[net\] t=(\d+)ms connect -> ([0-9.]+):(\d+) = (\S+)', l)
    if m:
        ev.append((int(m.group(1)), f"connect {m.group(2)}:{m.group(3)} = {m.group(4)}")); continue
    m = re.search(r'PAGE ON SCREEN at (\d+) ms', l)
    if m: ev.append((int(m.group(1)), "*** PAGE ON SCREEN")); continue
ev.sort()
if not ev:
    print("no timeline events -- did the boot reach the page?"); raise SystemExit
print(f"{'t (ms)':>9}  {'gap':>8}  event")
prev = 0
big = []
for t, what in ev:
    gap = t - prev
    if gap >= 500: big.append((gap, prev, t, what))
    print(f"{t:>9}  {gap:>8}  {what}")
    prev = t
print()
print("GAPS OVER 500 ms, largest first -- this is where the wall clock went:")
for gap, a, b, what in sorted(big, reverse=True)[:10]:
    print(f"  {gap:>7} ms  {a} -> {b}  before: {what}")
PY
