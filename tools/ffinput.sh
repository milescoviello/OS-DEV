#!/bin/sh
# ffinput.sh -- drive REAL input at a live Firefox and measure the screen.
#
# WHY THIS EXISTS. Every input experiment in this campaign so far has been a
# hand-typed ssh line and a guess at when to send it, and two of the retracted
# findings came from exactly that: M2272's "GTK3 reproduces the bug" was a
# click sent before the window existed, and the round before it clicked the
# wrong window. A stimulus whose arrival time is improvised is not a stimulus.
#
# It also separates two things that have never been separated for Firefox.
# Everything measured so far is POINTER: 24 buttons forwarded, 0 px change.
# Nobody has ever pressed a KEY at Firefox and looked at the screen -- M2255
# verified keys against zenity, which is GTK4, the same substitution that cost
# a day. Keyboard and pointer arrive over different protocol objects, take
# different paths through GDK, and land on different Gecko code. If keys move
# the screen and clicks do not, the fault is in pointer handling specifically
# and most of the "it is inside Gecko" reasoning has to be redone.
#
# The oracle is a screendump diff, not a log line, because the question is
# literally "did the screen change".
#
#   tools/ffinput.sh                     # real page over the network
#   URLPAGE=local tools/ffinput.sh       # the local test page
set -e
cd "$(dirname "$0")/.."
S=${SCRATCH:-/tmp/claude-1000/-home-miles-OS-DEV/026bcdb5-8d88-4ad7-9f23-58649bf4f353/scratchpad}
mkdir -p "$S/ffin"
H=${PVE_HOST:-192.168.1.5}
VMID=${VMID:-122}
D=/root/osdev
CAP=${CAP:-540}
CORES=${CORES:-8}
SSH="ssh -o BatchMode=yes root@$H"
case "${URLPAGE:-net}" in
    local) AP="ffwl lxout nonetdemo" ;;
    user)  AP="ffurl lxout" ;;          # the address in ./ffurl.txt, which is gitignored
    *)     AP="ffnet lxout" ;;
esac
# ASK GECKO WHAT IT SAW, in the same boot the input was driven in. Every
# previous MOZ_LOG run drove no input at all, so "Widget:5 says nothing about
# motion" meant only that nothing had moved. It is off by default because the
# log costs about 26 s of time-to-page ([[instrument-caused-the-failure]]).
#   MOZLOG=1 tools/ffinput.sh
if [ "${MOZLOG:-0}" = 1 ]; then AP="$AP ffnavlog"; fi
# Anything else worth appending for one experiment, e.g. EXTRA=ffalone to make
# Firefox the only Wayland client so focus cannot be ambiguous.
[ -n "${EXTRA:-}" ] && AP="$AP $EXTRA"
true

# WAIT FOR THE FILE TO STOP GROWING. `qm monitor screendump` returns before
# QEMU has finished writing, and the first run copied a 1280x960 header with
# 748 rows behind it -- a shot that is short by a quarter of the screen and
# says so nowhere. The diff then compares whatever both files happen to have,
# which under-counts silently. Two equal sizes in a row, then copy.
shot() {   # shot <name> -> $S/ffin/<name>.ppm
    $SSH "echo 'screendump $D/shot.ppm' | qm monitor $VMID >/dev/null 2>&1"
    prev=-1; n=0
    while [ $n -lt 20 ]; do
        cur=$($SSH "stat -c %s $D/shot.ppm 2>/dev/null || echo 0")
        [ "$cur" = "$prev" ] && [ "$cur" != 0 ] && break
        prev=$cur; n=$((n+1)); sleep 1
    done
    scp -q "root@$H:$D/shot.ppm" "$S/ffin/$1.ppm"
}
# HOW MANY PIXELS MOVED, and where. A count alone cannot tell a cursor being
# redrawn (a few hundred px, in one corner) from a page reacting (tens of
# thousands, spread out), and that difference is the entire result.
diff2() {
    python3 - "$S/ffin/$1.ppm" "$S/ffin/$2.ppm" <<'PY'
import sys
def rd(p):
    d = open(p,'rb').read()
    f = d.split(b'\n',3)
    assert f[0]==b'P6', f[0]
    w,h = map(int, f[1].split())
    return w,h,f[3]
try:
    w1,h1,a = rd(sys.argv[1]); w2,h2,b = rd(sys.argv[2])
except Exception as e:
    print("shot unreadable: %s" % e); raise SystemExit
if (w1,h1)!=(w2,h2):
    print("GEOMETRY CHANGED %dx%d -> %dx%d" % (w1,h1,w2,h2)); raise SystemExit
n=0; x0=y0=10**9; x1=y1=-1
for i in range(0, min(len(a),len(b)), 3):
    if a[i:i+3]!=b[i:i+3]:
        n+=1; px=(i//3)%w1; py=(i//3)//w1
        if px<x0:x0=px
        if px>x1:x1=px
        if py<y0:y0=py
        if py>y1:y1=py
print("%d px" % n + ("" if n==0 else "  bbox %d,%d..%d,%d" % (x0,y0,x1,y1)))
PY
}
qmp() {    # qmp <json events array body>
    { printf '{"execute":"qmp_capabilities"}\n'
      printf '{"execute":"input-send-event","arguments":{"events":[%s]}}\n' "$1"
      sleep 1; } | $SSH "socat - UNIX-CONNECT:/var/run/qemu-server/$VMID.qmp" 2>&1 | grep -c '"error"' || true
}
move()  { qmp "{\"type\":\"abs\",\"data\":{\"axis\":\"x\",\"value\":$1}},{\"type\":\"abs\",\"data\":{\"axis\":\"y\",\"value\":$2}}" >/dev/null; }
click() { qmp '{"type":"btn","data":{"down":true,"button":"left"}}' >/dev/null; sleep 1
          qmp '{"type":"btn","data":{"down":false,"button":"left"}}' >/dev/null; }
key()   { $SSH "echo 'sendkey $1' | qm monitor $VMID >/dev/null 2>&1"; }

echo "==> booting ($AP, $CORES cores, cap ${CAP}s) in the background"
WAIT=full NOBUILD=${NOBUILD:-1} APPEND="$AP" CORES=$CORES CAP=$CAP tools/pve-run.sh >"$S/ffin/run.txt" 2>&1 &
RUN=$!

# WAIT FOR A FRESH LOG, NOT JUST FOR THE MARKER. pve-run.sh spends about
# forty seconds stopping the VM, syncing 3.2 GB and starting it again -- and
# for all of that time $D/boot.log still holds the PREVIOUS run. The first
# version of this loop matched that and reported `window at ~0s`, so the
# settle timer started before the VM had booted. A marker that can be
# satisfied by the last experiment is not a marker.
T0=$(date -u +%s)
echo "==> waiting for the browser window (in a log newer than $T0)"
i=0
while [ $i -lt 300 ]; do
    if $SSH "[ \"\$(stat -c %Y $D/boot.log 2>/dev/null || echo 0)\" -ge $T0 ] && \
             grep -aqE 'desktop window for client slot [0-9]+: .*(Mozilla Firefox|Firefox)' $D/boot.log 2>/dev/null"; then break; fi
    sleep 5; i=$((i+5))
done
[ $i -lt 300 ] || { echo "NO WINDOW in ${i}s -- nothing to drive. See $D/boot.log"; wait $RUN; exit 1; }
echo "    window at ~${i}s; letting the page settle"
sleep 45

shot base
echo
echo "stimulus                 screen change"
echo "-----------------------  -------------------------"
# THE CONTROL COMES FIRST. Two shots with nothing in between: whatever this
# reports is the floor -- a blinking caret, a spinner, a clock -- and any arm
# that does not beat it has not been shown to do anything.
sleep 8; shot idle
printf '%-23s  %s\n' "nothing (control)" "$(diff2 base idle)"

# Focus the window the way a user would, then wait: a click that lands before
# the compositor has told the client it has focus proves nothing (M2273).
move 16000 3000; click; sleep 6; shot focus
printf '%-23s  %s\n' "click titlebar" "$(diff2 idle focus)"

# `escape` IS NOT A QEMU KEY NAME -- it is `esc`, and the wrong one is
# rejected with `invalid parameter: escape` on a channel this harness was
# discarding. And `f11` reaches QEMU fine but dies in OUR cooked keyboard
# layer, which has no encoding for F10/F11 and hands F1-F9/F12 to the window
# manager instead of the focused app (M2293). Both were sent for a whole run
# and both produced exactly the null result that "Firefox ignores keys" would
# have produced. Drive keys that are known to arrive, and keep f11 as the
# regression check for the F-key fix.
for k in ctrl-l ctrl-f esc f11; do
    key $k; sleep 6; shot "k-$k"
    printf '%-23s  %s\n' "key $k" "$(diff2 focus "k-$k")"
    cp "$S/ffin/k-$k.ppm" "$S/ffin/focus.ppm"
done

move 16000 16000; sleep 2; shot p-hover
printf '%-23s  %s\n' "pointer into content" "$(diff2 focus p-hover)"
click; sleep 8; shot p-click
printf '%-23s  %s\n' "click in content" "$(diff2 p-hover p-click)"

i=0; while [ $i -lt 10 ]; do
    qmp '{"type":"btn","data":{"down":true,"button":"wheel-down"}}' >/dev/null
    qmp '{"type":"btn","data":{"down":false,"button":"wheel-down"}}' >/dev/null
    i=$((i+1)); done
sleep 6; shot p-scroll
printf '%-23s  %s\n' "wheel down x10" "$(diff2 p-click p-scroll)"

echo
wait $RUN || true
scp -q "root@$H:$D/boot.log" "$S/ffin/boot.log"
echo "----- what the compositor saw -----"
grep -a 'ptr fwd' "$S/ffin/boot.log" | tail -1 | tr '|' '\n' | grep -aE 'keys:|ptr fwd|clients \[' || true
grep -a '\[wlio\]' "$S/ffin/boot.log" | tail -3 || echo "(no [wlio] line -- old kernel)"
echo "==> shots in $S/ffin, log $S/ffin/boot.log"
