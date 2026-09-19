#!/bin/sh
# ffprobe-input.sh -- does Firefox ACT on input? A test that cannot pass or
# fail by accident.
#
# WHY THIS REPLACES THE LAST ONE. tools/ffinput.sh drove a click at a fixed
# screen coordinate and a wheel at whatever page happened to be loaded. On
# example.com that click landed on blank page and the document was shorter
# than the window, so there was nothing to scroll. Both arms correctly
# produced no change on screen -- which is exactly what a browser ignoring
# input produces, and I read it that way for two rounds.
#
# So: a page built for this (tools/lx/ffinput.html, -append ffin), pure CSS,
# no JavaScript that could be disabled --
#
#   :hover   a full-width 300px band turns BRIGHT GREEN under the pointer,
#            with no click at all. This is the pure wl_pointer.motion test.
#   :active  the same band turns MAGENTA while a button is held.
#   :focus   a text box draws a thick YELLOW ring when it has keyboard focus.
#   scroll   the body is 6000px tall in solid colour bands.
#
# And the harness FINDS ITS TARGET instead of assuming one: it locates the
# band by its resting colour (#333344) in a screenshot and aims at the middle
# of it. If it cannot find the band it says so and stops, rather than
# clicking somewhere and reporting a null.
set -e
cd "$(dirname "$0")/.."
S=${SCRATCH:-/tmp/claude-1000/-home-miles-OS-DEV/026bcdb5-8d88-4ad7-9f23-58649bf4f353/scratchpad}/ffprobe
mkdir -p "$S"
H=${PVE_HOST:-192.168.1.5}
VMID=${VMID:-122}
D=/root/osdev
SSH="ssh -o BatchMode=yes root@$H"
CAP=${CAP:-420}

shot() {
    $SSH "echo 'screendump $D/shot.ppm' | qm monitor $VMID >/dev/null 2>&1"
    prev=-1; n=0
    while [ $n -lt 20 ]; do
        cur=$($SSH "stat -c %s $D/shot.ppm 2>/dev/null || echo 0")
        [ "$cur" = "$prev" ] && [ "$cur" != 0 ] && break
        prev=$cur; n=$((n+1)); sleep 1
    done
    scp -q "root@$H:$D/shot.ppm" "$S/$1.ppm"
}
qmp() {
    { printf '{"execute":"qmp_capabilities"}\n'
      printf '{"execute":"input-send-event","arguments":{"events":[%s]}}\n' "$1"
      sleep 1; } | $SSH "socat - UNIX-CONNECT:/var/run/qemu-server/$VMID.qmp" >/dev/null 2>&1 || true
}
move() { qmp "{\"type\":\"abs\",\"data\":{\"axis\":\"x\",\"value\":$1}},{\"type\":\"abs\",\"data\":{\"axis\":\"y\",\"value\":$2}}"; }
down() { qmp '{"type":"btn","data":{"down":true,"button":"left"}}'; }
up()   { qmp '{"type":"btn","data":{"down":false,"button":"left"}}'; }
key()  { $SSH "echo 'sendkey $1' | qm monitor $VMID >/dev/null 2>&1"; }

# count pixels of a colour, and the bounding box, in one shot
px() { python3 - "$S/$1.ppm" "$2" "$3" "$4" <<'PY'
import sys
d=open(sys.argv[1],'rb').read(); f=d.split(b'\n',3)
w,h=map(int,f[1].split()); b=f[3]
r,g,bl=int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4])
t=bytes((r,g,bl)); n=0; y0=10**9; y1=-1
for i in range(0,len(b)-2,3):
    if b[i:i+3]==t:
        n+=1; y=(i//3)//w
        if y<y0:y0=y
        if y>y1:y1=y
print("%d %d %d"%(n,y0 if y1>=0 else -1,y1))
PY
}

# EXTRA=ffnowr / ffptroot / ffalone / ffe10s -- the flags that were each
# "ruled out" for Firefox input using a page that could not show a positive
# result. None of those negatives mean anything and they all have to be taken
# again against this probe.
AP="ffin lxout nonetdemo${EXTRA:+ $EXTRA}"
echo "==> booting -append '$AP' (the CSS input probe page)"
WAIT=full NOBUILD=${NOBUILD:-1} APPEND="$AP" CORES=${CORES:-8} \
    CAP=$CAP tools/pve-run.sh >"$S/run.txt" 2>&1 &
RUN=$!
T0=$(date -u +%s)
i=0
while [ $i -lt 300 ]; do
    if $SSH "[ \"\$(stat -c %Y $D/boot.log 2>/dev/null || echo 0)\" -ge $T0 ] && \
             grep -aqE 'desktop window for client slot [0-9]+: .*Firefox' $D/boot.log 2>/dev/null"; then break; fi
    sleep 5; i=$((i+5))
done
[ $i -lt 300 ] || { echo "NO WINDOW in ${i}s"; wait $RUN; exit 1; }
echo "    window at ~${i}s; waiting for the page to actually paint"

# POLL FOR THE BAND, DO NOT GUESS A SETTLE TIME. The first cut slept a fixed
# forty seconds and then declared the page absent -- on a boot where the
# window manager was still showing "waiting for a client to commit a
# surface". A fixed wait turns "not yet" into "never", which is the same
# false negative this whole probe exists to stop making.
move 30000 1200; sleep 2
BAND_N=0; BAND_Y0=-1; BAND_Y1=-1; w=0
while [ $w -lt 200 ]; do
    shot rest
    set -- $(px rest 51 51 68)
    BAND_N=$1; BAND_Y0=$2; BAND_Y1=$3
    [ "$BAND_N" -gt 50000 ] && break
    printf '    ...%ss: %s px of the band so far\n' "$w" "$BAND_N"
    sleep 15; w=$((w+15))
done
echo "    resting band (#333344): $BAND_N px, rows $BAND_Y0..$BAND_Y1"
if [ "$BAND_N" -lt 50000 ]; then
    echo "PROBE: STOP -- the hover band never appeared ($BAND_N px of #333344 after ${w}s)."
    echo "       The page did not render, so nothing below would mean anything. Why:"
    $SSH "grep -acE 'tabcrashed' $D/boot.log | sed 's/^/         tab-crash pages: /'; \
          grep -ac 'Exiting due to channel error' $D/boot.log | sed 's/^/         IPC channel errors: /'; \
          grep -ac 'needs unreceived descriptors' $D/boot.log | sed 's/^/         lost-descriptor warnings: /'; \
          grep -a 'waiting for a client to commit' $D/boot.log | tail -1"
    wait $RUN; exit 1
fi
CY=$(( (BAND_Y0 + BAND_Y1) / 2 ))
AY=$(( CY * 32767 / 960 ))
echo "    aiming at screen y=$CY (tablet $AY), x=640"

echo
printf '%-26s %s\n' "arm" "result"
printf '%-26s %s\n' "--------------------------" "------------------------------------"

move 16383 $AY; sleep 4; shot hover
set -- $(px hover 0 255 102)
printf '%-26s %s\n' "HOVER (motion only)" "$1 px BRIGHT GREEN  $( [ "$1" -gt 50000 ] && echo '<-- POINTER MOTION WORKS' || echo '(band did not light)')"

down; sleep 3; shot active
set -- $(px active 255 0 204)
printf '%-26s %s\n' "BUTTON HELD (:active)" "$1 px MAGENTA  $( [ "$1" -gt 50000 ] && echo '<-- BUTTON WORKS' || echo '(band did not change)')"
up; sleep 2

# FIND THE TEXT BOX, DO NOT GUESS AN OFFSET BELOW THE BAND. `BAND_Y1 + 70`
# missed whenever the band sat lower -- the page's vertical position moves
# with Firefox's notification bars -- and a missed click reports "no focus
# ring", which is indistinguishable from the bug. Its unfocused border is
# #00cccc, a colour nothing else on the page uses.
shot findbox
set -- $(px findbox 0 204 204)
BOX_N=$1; BOX_Y0=$2; BOX_Y1=$3
echo "    text box border (#00cccc): $BOX_N px, rows $BOX_Y0..$BOX_Y1"
if [ "${BOX_N:-0}" -lt 500 ]; then
    echo "    WARNING: text box not found -- the click below is aimed at a guess"
    TY=$(( (BAND_Y1 + 70) * 32767 / 960 ))
else
    TY=$(( ((BOX_Y0 + BOX_Y1) / 2) * 32767 / 960 ))
fi
move 8000 $TY; sleep 2; down; sleep 1; up; sleep 3; shot focus
set -- $(px focus 255 221 0)
printf '%-26s %s\n' "TEXT BOX CLICK (:focus)" "$1 px YELLOW RING  $( [ "$1" -gt 2000 ] && echo '<-- KEYBOARD FOCUS WORKS' || echo '(no focus ring)')"

for c in o s d e v; do key $c; sleep 1; done
sleep 3; shot typed
set -- $(px typed 255 0 0)
printf '%-26s %s\n' "TYPED o s d e v" "$1 px RED (field not empty)  $( [ "$1" -gt 20000 ] && echo '<-- TYPING WORKS' || echo '(field still shows its placeholder)')"
printf '%-26s %s\n' "  (whole-screen delta)" "$(python3 - "$S/focus.ppm" "$S/typed.ppm" <<'PY'
import sys
def rd(p):
    d=open(p,'rb').read(); f=d.split(b'\n',3); w,h=map(int,f[1].split()); return w,h,f[3]
w,h,a=rd(sys.argv[1]); _,_,b=rd(sys.argv[2])
n=sum(1 for i in range(0,min(len(a),len(b))-2,3) if a[i:i+3]!=b[i:i+3])
print("%d px changed %s" % (n, "<-- KEYSTROKES PAINTED" if n>300 else "(nothing painted)"))
PY
)"

# PARK THE POINTER, THEN TAKE THE BASELINE (M2301).
#
# This compared the post-scroll shot against `hover`, which was taken with
# the band lit bright green. Any later shot differs from it by the whole
# 374000-pixel band regardless of whether the page moved, so the arm reported
# "SCROLL WORKS" on a page that had not scrolled at all. A baseline has to be
# taken in the same state as the thing it is compared with.
move 16383 $AY; sleep 4; shot prescroll
# AND PROVE THE PAGE CAN SCROLL AT ALL BEFORE ASKING WHETHER IT DID. A wheel
# arm on an unscrollable document cannot fail, which is how the first cut of
# this page shipped: everything was position:absolute, so the document had
# almost no in-flow height, no scrollbar existed, and "the page did not move"
# was the correct behaviour rather than a bug.
SB=$(python3 tools/scrollbar-px.py "$S/prescroll.ppm")
echo "    right-edge scrollbar: $SB px of non-background"
if [ "${SB:-0}" -lt 100 ]; then
    echo "    WARNING: no scrollbar -- the wheel arm below CANNOT FAIL, ignore it"
fi
j=0; while [ $j -lt 12 ]; do
    qmp '{"type":"btn","data":{"down":true,"button":"wheel-down"}}'
    qmp '{"type":"btn","data":{"down":false,"button":"wheel-down"}}'
    j=$((j+1)); done
sleep 4; shot scrolled
printf '%-26s %s\n' "WHEEL DOWN x12" "$(python3 - "$S/prescroll.ppm" "$S/scrolled.ppm" <<'PY'
import sys
def rd(p):
    d=open(p,'rb').read(); f=d.split(b'\n',3); w,h=map(int,f[1].split()); return w,h,f[3]
w,h,a=rd(sys.argv[1]); _,_,b=rd(sys.argv[2])
n=sum(1 for i in range(0,min(len(a),len(b))-2,3) if a[i:i+3]!=b[i:i+3])
print("%d px changed %s" % (n, "<-- SCROLL WORKS" if n>200000 else "(page did not move)"))
PY
)"

echo
wait $RUN || true
scp -q "root@$H:$D/boot.log" "$S/boot.log"
grep -a 'ptr fwd' "$S/boot.log" | tail -1 | tr '|' '\n' | grep -aE 'keys:|ptr fwd' || true
grep -a '\[wlio\]' "$S/boot.log" | tail -1 || true
echo "==> shots in $S"
