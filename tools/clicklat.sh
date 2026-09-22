#!/bin/bash
# clicklat — CLICK-TO-PIXEL as a number.
#
# Clicks the volumeshaderbm preset buttons in rotation. They are plain HTML
# with a visible selected state, so every click provably repaints -- and the
# script CHECKS that the selection moved, because a latency measured over
# clicks that did nothing is the same lie as a frame rate measured on a
# stopped benchmark.
#
# [inputlat] in the compositor times input -> the client's commit, bucketed,
# because min 1 ms / mean 68 ms / max 448 ms is consistent with two different
# faults that need opposite fixes.
set -e
cd "$(dirname "$0")/.."
H=${PVE_HOST:-192.168.1.5}; V=${VMID:-122}; D=/root/osdev
SSH="ssh -o BatchMode=yes -o ConnectTimeout=20 root@$H"
Q="socat - UNIX-CONNECT:/var/run/qemu-server/$V.qmp"
S=$(mktemp -d); N=${N:-24}
RES=${RES:-2560x1440}
printf 'https://volumeshaderbm.com/start/\n' > ffurl.txt

WAIT=full APPEND="ffshow ffurl nonetdemo fbres=$RES" CORES=8 MEM=8192 \
  CAP=${CAP:-260} tools/pve-run.sh > /tmp/clicklat-run.txt 2>&1 &
RUN=$!
echo "==> waiting for the page by TITLE"
OK=0; for i in $(seq 1 110); do
  $SSH "grep -aq 'toplevel title: \"Run Volume' $D/boot.log 2>/dev/null" && { OK=1; break; }; sleep 3; done
[ "$OK" = 1 ] || { echo ">>> page never loaded; no latency reported"; kill $RUN 2>/dev/null; exit 4; }
sleep 8

shot() { tools/shot.sh "$S/$1.png" >/dev/null || { echo ">>> screendump failed"; exit 6; }; }
shot a
read SW SH <<< "$(head -2 "$S/a.ppm" | tail -1)"

# Canvas bbox -> the four preset buttons sit in a row just below it, one per
# quarter of its width. Verified against a known screenshot: quarters give
# 465/721/976/1232 where the real centres are 459/718/975/1233.
read CX0 CY0 CX1 CY1 <<< "$(python3 - "$S/a.ppm" <<'CANV'
import sys
d=open(sys.argv[1],'rb').read(); p=d.split(b'\n',3)
w,h=(int(x) for x in p[1].split()); px=p[3]
def at(x,y):
    i=(y*w+x)*3; return px[i],px[i+1],px[i+2]
def light(c): return c[0]>200 and c[1]>200 and c[2]>200
def dark(c):  return c[0]<45 and c[1]<45 and c[2]<55
rows=[y for y in range(0,h,4) if sum(1 for x in range(0,w,8) if light(at(x,y))) > (w//8)*0.25]
cols=[x for x in range(0,w,4) if sum(1 for y in range(0,h,8) if light(at(x,y))) > (h//8)*0.15]
if not rows or not cols: print("0 0 0 0"); raise SystemExit
wy0,wy1,wx0,wx1 = rows[0],rows[-1],cols[0],cols[-1]
best=None
for y in range(wy0,wy1,3):
    cur=None
    for x in range(wx0,wx1,3):
        if dark(at(x,y)):
            if cur is None: cur=x
        else:
            if cur is not None and x-cur>250 and (best is None or x-cur>best[1]-best[0]): best=(cur,x,y)
            cur=None
if not best: print("0 0 0 0"); raise SystemExit
a,b,y0=best
def rowdark(y):
    n=t=0
    for x in range(a,b,9):
        t+=1
        if dark(at(x,y)): n+=1
    return t and n/t>0.7
top=y0; bot=y0
while top>wy0 and rowdark(top-1): top-=1
while bot<wy1-1 and rowdark(bot+1): bot+=1
print(a,top,b,bot)
CANV
)"
[ "$CX1" = 0 ] && { echo ">>> could not find the canvas"; exit 7; }
PY_=$(( CY1 + 39 )); Wq=$(( (CX1-CX0)/4 ))
B0=$(( CX0 + Wq/2 )); B1=$(( CX0 + Wq + Wq/2 )); B2=$(( CX0 + 2*Wq + Wq/2 )); B3=$(( CX0 + 3*Wq + Wq/2 ))
echo "==> canvas [$CX0,$CY0..$CX1,$CY1]; presets y=$PY_ at $B0 $B1 $B2 $B3"

sel() { python3 - "$S/$1.ppm" "$PY_" "$B0" "$B1" "$B2" "$B3" <<'SEL'
import sys
d=open(sys.argv[1],'rb').read(); p=d.split(b'\n',3)
w,h=(int(x) for x in p[1].split()); px=p[3]; y=int(sys.argv[2])
o=[]
for a in sys.argv[3:]:
    x=int(a); i=(y*w+x)*3; c=(px[i],px[i+1],px[i+2])
    o.append("SEL" if (c[2]>120 and c[2]-c[0]>60) else "-")
print(" ".join(o))
SEL
}
BEFORE=$(sel a); echo "==> presets before: $BEFORE"

click() { local AX=$(( $1 * 32768 / SW )) AY=$(( $2 * 32768 / SH ))
  printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"abs","data":{"axis":"x","value":%s}},{"type":"abs","data":{"axis":"y","value":%s}}]}}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":true,"button":"left"}}]}}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":false,"button":"left"}}]}}\n' "$AX" "$AY" | $SSH "$Q" >/dev/null 2>&1; }

click "$B1" "$PY_"; sleep 2      # focus the window first; this one is eaten
MARK=$($SSH "grep -ac '\[inputlat\]' $D/boot.log")
echo "==> $N clicks, rotating through the four presets"
i=0; while [ $i -lt $N ]; do
  for X in "$B0" "$B1" "$B2" "$B3"; do
    [ $i -ge $N ] && break
    click "$X" "$PY_"; i=$((i+1)); sleep 1.2
  done
done
sleep 3; shot b
AFTER=$(sel b); echo "==> presets after:  $AFTER"
if [ "$BEFORE" = "$AFTER" ]; then
  echo ">>> THE SELECTION NEVER MOVED. The clicks did nothing, so any latency"
  echo "    below would be measured over repaints that never happened."
  kill $RUN 2>/dev/null; exit 5
fi
echo
echo "=== CLICK-TO-PIXEL (input -> client commit), $RES ==="
$SSH "grep -a '\[inputlat\]' $D/boot.log | tail -n +$((MARK+1)) | tail -4"
wait $RUN 2>/dev/null || true
