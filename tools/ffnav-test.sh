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

WAIT=full NOBUILD=1 APPEND="${NAVAPPEND:-ffnav} lxout nonetdemo" CORES=${CORES:-8} CAP=${CAP:-420} \
  VMID=$V PVE_DIR=$D tools/pve-run.sh >"$S/run.txt" 2>&1 &
RUN=$!
T0=$(date -u +%s); i=0
while [ $i -lt 300 ]; do
  if $SSH "[ \"\$(stat -c %Y $D/boot.log 2>/dev/null || echo 0)\" -ge $T0 ] && grep -aq 'Mozilla Firefox' $D/boot.log"; then break; fi
  sleep 5; i=$((i+5))
done
echo "   window at ~${i}s"; sleep 50
# DID THE PAGE EVEN RENDER? Two earlier runs of this test clicked at a window
# that was blank -- Firefox had segfaulted -- and the verdict blamed
# navigation. A test that cannot tell "there was nothing to click" from
# "clicking did nothing" is not measuring what it claims to.
if $SSH "grep -aq 'CRASHED with signal' $D/boot.log"; then
  echo "   => PRECONDITION FAILED: Firefox crashed before the click; nothing was on screen."
  $SSH "grep -a 'CRASHED with signal' $D/boot.log | tail -1"
  wait $RUN 2>/dev/null || true
  exit 1
fi
BEFORE=$($SSH "grep -a 'toplevel title:' $D/boot.log | tail -1")
echo "   title before: $BEFORE"
# ...and the page has to have LOADED. Firefox's error page is a perfectly good
# document with its own title, so a failed load looks like a loaded page to a
# title-diffing oracle -- and clicking empty chrome then "proves" navigation is
# broken. Name it instead.
case "$BEFORE" in
  *"Problem loading page"*|*"Server Not Found"*|*"Unable to connect"*)
    echo "   => PRECONDITION FAILED: the page never loaded, so there was no link to click."
    wait $RUN 2>/dev/null || true
    exit 1 ;;
esac
shot before
# COORDINATES FROM THE RENDERED PAGE, NOT FROM A DESCRIPTION OF IT.
#
# The first version clicked (16000,4900), which on QEMU's 0..32767 absolute
# axes is (625,143) of a 1280x960 screen -- the "security sandbox is disabled"
# notification bar. There is no link there, so the test could not have passed,
# and it reported the ambiguous "either the click missed a link, or navigation
# did not happen" -- which is the correct thing for it to say and the reason
# that wording is there.
#
# These come off a screendump of the page actually loaded: the in-paragraph
# link is at about (637,632) in 1280x960, which is a large underlined target
# rather than a 90x18 nav item, so a few pixels of layout drift cannot miss it.
#   x = 637/1280 * 32768 = 16307     y = 632/960 * 32768 = 21572
# Second correction: (16307,21572) is (637,632), which a screendump showed is
# the GAP BETWEEN TWO LINES -- the cursor landed two pixels past the end of a
# link. Aim at the MIDDLE of the longest link on the page instead of near an
# edge: "a honeypot strangers are attacking" spans x 324..635 at y~645.
#   x = 480/1280 * 32768 = 12288     y = 645/960 * 32768 = 22016
# The target is now a block link filling 70% of the viewport (tools/lx/
# ffnav.html), so the centre of the screen is inside it by a wide margin --
# which is the only way this stays true when the compositor moves the window.
#   x = 640/1280 * 32768 = 16384     y = 480/960 * 32768 = 16384
CLICK_X=${CLICK_X:-16384}
CLICK_Y=${CLICK_Y:-16384}
click $CLICK_X $CLICK_Y
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
case "$AFTER" in
  *OSDEV-NAV-ARRIVED*) echo "   => NAVIGATION WORKS: the click followed the link and the DESTINATION document committed" ;;
  *OSDEV-NAV-START*)   echo "   => the click did not follow the link: still on the start page" ;;
  *)                   [ "$BEFORE" != "$AFTER" ] \
                         && echo "   => the title changed, but not to the destination: $AFTER" \
                         || echo "   => title unchanged: the click did not navigate" ;;
esac
wait $RUN 2>/dev/null || true
