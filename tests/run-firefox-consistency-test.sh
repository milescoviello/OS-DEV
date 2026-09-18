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
# 300 -> 650 (M2189). The old default measured the wrong thing: the page probe
# samples every 15 s after first paint, and a boot that had not finished
# starting when the window closed produced NO page verdict -- which this script
# counted as a failure to render. Two "blank" boots turned out to have ONE and
# ZERO probe samples against a passing boot's seventeen, and zero `console.`
# lines against 9-35, i.e. they were still early in startup. A capture window is
# part of the instrument, and this one was shorter than the thing it measured.
CAP=${CAP:-650}
# A run is only EVIDENCE about rendering if the probe actually sampled. Below
# this, the verdict is "we do not know" rather than "it did not render".
MIN_SAMPLES=${MIN_SAMPLES:-3}
VMID=${VMID:-131}
PVE_DIR=${PVE_DIR:-/root/osdev-b}

ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$NODE" true 2>/dev/null \
  || { echo "SKIP: firefox consistency ($NODE unreachable -- this is a KVM measurement)"; exit 0; }
[ -x tools/pve-run.sh ] || { echo "SKIP: firefox consistency (no tools/pve-run.sh)"; exit 0; }

LOG=$(mktemp /tmp/osdev_ffcons.XXXXXX.log)
trap 'rm -f "$LOG"' EXIT

ok=0; inconclusive=0; times=""
i=1
while [ "$i" -le "$RUNS" ]; do
    VMID="$VMID" PVE_DIR="$PVE_DIR" NOBUILD=${NOBUILD:-1} \
      APPEND="ffwl nonetdemo lxout noprobes" CORES=1 CAP="$CAP" \
      tools/pve-run.sh >/dev/null 2>&1 || true
    scp -q "root@$NODE:$PVE_DIR/boot.log" "$LOG" 2>/dev/null || true
    t=$(grep -ao 'PAGE ON SCREEN at [0-9]* ms' "$LOG" 2>/dev/null | head -1 | grep -o '[0-9]*' || true)
    ns=$(grep -ac 'page\] --- sample' "$LOG" 2>/dev/null || echo 0)
    if [ -n "$t" ]; then
        ok=$((ok+1)); times="$times ${t}ms"
        echo "  run $i: the page is on screen at ${t} ms ($ns probe sample(s))"
    elif [ "$ns" -lt "$MIN_SAMPLES" ]; then
        # NOT a render failure. Distinguishing these two is the whole point:
        # "it rendered nothing" and "we never looked" need opposite responses.
        inconclusive=$((inconclusive+1))
        echo "  run $i: INCONCLUSIVE -- only $ns probe sample(s), so the capture"
        echo "          window closed before the page probe could judge. Raise CAP."
    else
        # Say WHAT was on screen instead -- "no page" alone sends you to the
        # renderer, and the content area's actual colour says it is not there.
        c=$(grep -a 'layer 1 content:' "$LOG" 2>/dev/null | tail -1)
        echo "  run $i: NO PAGE. ${c:-（no page-probe output at all)}"
    fi
    i=$((i+1))
done

# THREE OUTCOMES, THREE NAMES (M2189). The probe sampling at all separates
# "never got there" from "got there"; the page verdict then separates blank from
# rendered. Collapsing those into one number is what let a rate be reported that
# mixed short capture windows with real failures -- and, on the other session's
# machine, with process crashes. One number that means three things is the same
# defect as one commit that means two authors.
echo "firefox put the page on screen in $ok of $RUNS run(s):$times"
if [ "$inconclusive" -gt 0 ]; then
    echo "$inconclusive run(s) were INCONCLUSIVE (the probe never sampled) and are NOT"
    echo "counted as failures -- a rate computed over them would measure the window."
fi
judged=$((RUNS - inconclusive))
if [ "$judged" -le 0 ]; then
    echo "SKIP: every run was inconclusive -- nothing was measured. Raise CAP."
    exit 0
fi
if [ "$ok" -lt "$FLOOR" ]; then
    echo "FAIL: $ok of $judged judged run(s) is below the floor of $FLOOR"
    exit 1
fi
echo "PASS: $ok of $judged judged run(s) (floor $FLOOR) -- raise FLOOR as the render is made reliable"
