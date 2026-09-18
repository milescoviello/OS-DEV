#!/bin/sh
# HOW OFTEN does Firefox actually put the page on screen? (M2171)
#
# WHY THIS EXISTS. tests/run-firefox-onscreen-test.sh boots once and requires
# the page. One boot cannot measure a rate, and the claim this project had been
# carrying -- that the page "renders in essentially every sample" -- was never
# counted. Eight runs on ONE core, the configuration called the one that works,
# came back six pages and two blanks. A 25% failure rate is not a flake to be
# retried past; it is the "consistent" half of the goal, and it needs a number
# attached to it before and after any attempt to fix it.
#
# It reports the rate and the times, and fails only below a floor you pass in,
# so it is useful as a MEASUREMENT (the default floor is the observed 6/8) and
# can be tightened as the bug is fixed rather than rewritten.
#
#   RUNS=8 FLOOR=8 tests/run-firefox-consistency-test.sh    # demand 8/8
#
# Needs the Proxmox node: this is a KVM measurement and the timings mean nothing
# under TCG. Skips cleanly without it. Each run is ~5 minutes.
set -e
cd "$(dirname "$0")/.."
NODE=${PVE_NODE:-192.168.1.5}
RUNS=${RUNS:-4}
FLOOR=${FLOOR:-3}
CAP=${CAP:-300}
VMID=${VMID:-131}
PVE_DIR=${PVE_DIR:-/root/osdev-b}

ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$NODE" true 2>/dev/null \
  || { echo "SKIP: firefox consistency ($NODE unreachable -- this is a KVM measurement)"; exit 0; }
[ -x tools/pve-run.sh ] || { echo "SKIP: firefox consistency (no tools/pve-run.sh)"; exit 0; }

LOG=$(mktemp /tmp/osdev_ffcons.XXXXXX.log)
trap 'rm -f "$LOG"' EXIT

ok=0; times=""
i=1
while [ "$i" -le "$RUNS" ]; do
    VMID="$VMID" PVE_DIR="$PVE_DIR" NOBUILD=${NOBUILD:-1} \
      APPEND="ffwl nonetdemo lxout noprobes" CORES=1 CAP="$CAP" \
      tools/pve-run.sh >/dev/null 2>&1 || true
    scp -q "root@$NODE:$PVE_DIR/boot.log" "$LOG" 2>/dev/null || true
    t=$(grep -ao 'PAGE ON SCREEN at [0-9]* ms' "$LOG" 2>/dev/null | head -1 | grep -o '[0-9]*' || true)
    if [ -n "$t" ]; then
        ok=$((ok+1)); times="$times ${t}ms"
        echo "  run $i: the page is on screen at ${t} ms"
    else
        # Say WHAT was on screen instead -- "no page" alone sends you to the
        # renderer, and the content area's actual colour says it is not there.
        c=$(grep -a 'layer 1 content:' "$LOG" 2>/dev/null | tail -1)
        echo "  run $i: NO PAGE. ${c:-（no page-probe output at all)}"
    fi
    i=$((i+1))
done

echo "firefox put the page on screen in $ok of $RUNS run(s):$times"
if [ "$ok" -lt "$FLOOR" ]; then
    echo "FAIL: $ok of $RUNS is below the floor of $FLOOR"
    exit 1
fi
echo "PASS: $ok of $RUNS (floor $FLOOR) -- raise FLOOR as the render is made reliable"
