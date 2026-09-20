#!/bin/sh
# Does clicking a LINK navigate? The most basic browser action, and nothing
# in this tree has ever tested it: every input test so far has checked that
# the page REACTS (hover colour, focus ring, scroll offset), never that a
# click followed a hyperlink and loaded a different document.
#
# The oracle is the window TITLE, which the desktop logs on every change and
# which only changes when a new document commits. A colour or pixel test
# cannot tell "the link highlighted" from "the link was followed".
set -e
cd "$(dirname "$0")/.."
H=${PVE_HOST:-192.168.1.5}; V=${VMID:-131}; D=${PVE_DIR:-/root/osdev-b}
S=${SCRATCH:-/tmp/claude-1000/-home-miles-OS-DEV/026bcdb5-8d88-4ad7-9f23-58649bf4f353/scratchpad}/nav
mkdir -p "$S"
SSH="ssh -o BatchMode=yes root@$H"
shot(){ $SSH "echo 'screendump $D/n.ppm' | qm monitor $V >/dev/null 2>&1"; sleep 2; scp -q root@$H:$D/n.ppm "$S/$1.ppm"; }
click(){ printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"abs","data":{"axis":"x","value":%s}},{"type":"abs","data":{"axis":"y","value":%s}}]}}\n' "$1" "$2" | $SSH "socat - UNIX-CONNECT:/var/run/qemu-server/$V.qmp" >/dev/null 2>&1; sleep 1
  printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":true,"button":"left"}}]}}\n' | $SSH "socat - UNIX-CONNECT:/var/run/qemu-server/$V.qmp" >/dev/null 2>&1; sleep 1
  printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":false,"button":"left"}}]}}\n' | $SSH "socat - UNIX-CONNECT:/var/run/qemu-server/$V.qmp" >/dev/null 2>&1; }

WAIT=full NOBUILD=1 APPEND="ffurl lxout" CORES=${CORES:-8} CAP=${CAP:-420} \
  VMID=$V PVE_DIR=$D tools/pve-run.sh >"$S/run.txt" 2>&1 &
RUN=$!
T0=$(date -u +%s); i=0
while [ $i -lt 300 ]; do
  if $SSH "[ \"\$(stat -c %Y $D/boot.log 2>/dev/null || echo 0)\" -ge $T0 ] && grep -aq 'Mozilla Firefox' $D/boot.log"; then break; fi
  sleep 5; i=$((i+5))
done
echo "   window at ~${i}s"; sleep 50
BEFORE=$($SSH "grep -a 'toplevel title:' $D/boot.log | tail -1")
echo "   title before: $BEFORE"
shot before
# The nav bar of that page sits near the top of the content area; click the
# first nav link. Coordinates come from the rendered layout, not a guess:
# the bar is the full-width strip under the notification bars.
click 16000 4900
sleep 25
shot after
AFTER=$($SSH "grep -a 'toplevel title:' $D/boot.log | tail -1")
echo "   title after : $AFTER"
python3 - "$S/before.ppm" "$S/after.ppm" <<'PY'
import sys
def rd(p):
    d=open(p,'rb').read(); f=d.split(b'\n',3); w,h=map(int,f[1].split()); return w,h,f[3]
w,h,a=rd(sys.argv[1]); _,_,b=rd(sys.argv[2])
n=sum(1 for i in range(0,min(len(a),len(b))-2,3) if a[i:i+3]!=b[i:i+3])
print("   screen changed by %d px %s" % (n, "<-- the page CHANGED" if n>200000 else "(little changed)"))
PY
[ "$BEFORE" != "$AFTER" ] && echo "   => NAVIGATION WORKS (the document title changed)" \
                          || echo "   => title unchanged: either the click missed a link, or navigation did not happen"
wait $RUN 2>/dev/null || true
