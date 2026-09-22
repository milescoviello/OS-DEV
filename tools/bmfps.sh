#!/bin/bash
# bmfps — measure volumeshaderbm's frame rate, and REFUSE to report one unless
# the shader is demonstrably running.
#
# Three previous oracles in this tool family reported a frame rate for a
# benchmark that was not running:
#   1. a fixed pixel box written for 1280x960, which at 2560x1440 sampled
#      browser chrome (bright) instead of the canvas;
#   2. the "fraction of the screen" replacement, which sampled white page
#      background because the canvas is positioned by the WINDOW, and the
#      window is not maximised;
#   3. a fixed 8 s settle before clicking, which clicked while the page was
#      still showing "Transferring data from volumeshaderbm.com..." -- the
#      canvas was WHITE, read as bright, and 172 fps of blank-page repaints
#      got reported as a shader rate.
#
# So: find the canvas in the image instead of assuming where it is, wait for
# the page by its TITLE instead of by a clock, and compare the SAME box before
# and after. A canvas that does not change is a benchmark that did not run.
set -e
cd "$(dirname "$0")/.."
H=${PVE_HOST:-192.168.1.5}; V=${VMID:-122}; D=/root/osdev
SSH="ssh -o BatchMode=yes -o ConnectTimeout=20 root@$H"
Q="socat - UNIX-CONNECT:/var/run/qemu-server/$V.qmp"
RUNFOR=${RUNFOR:-60}
S=$(mktemp -d)
URL=${URL:-https://volumeshaderbm.com/start/}
printf '%s\n' "$URL" > ffurl.txt

GPU3D=${GPU3D:-1} WAIT=full APPEND="ffshow ffurl nonetdemo ffgpu" CORES=8 MEM=8192 \
  CAP=${CAP:-260} tools/pve-run.sh > /tmp/bmfps-run.txt 2>&1 &
RUN=$!

echo "==> waiting for the PAGE (by title), not for a clock"
OK=0
for i in $(seq 1 110); do
  if $SSH "grep -aq 'toplevel title: \"Run Volume' $D/boot.log 2>/dev/null"; then OK=1; break; fi
  sleep 3
done
[ "$OK" = 1 ] || { echo ">>> THE PAGE NEVER LOADED. No frame rate reported."; kill $RUN 2>/dev/null; wait $RUN 2>/dev/null; exit 4; }
echo "==> page title seen; letting layout settle"; sleep 8

shot() { tools/shot.sh "$S/$1.png" >/dev/null || { echo ">>> screendump failed"; exit 6; }; }

# Locate the canvas (the big dark rectangle) and the Start button inside it.
# Find the canvas. TWO STEPS, because one step picked the DESKTOP: the
# wallpaper is dark and runs to the screen edge, so "largest dark run"
# chose [1488,459..2560,648] -- off the right of the screen, nowhere near
# Firefox. Locate the BROWSER first (a big light rectangle against a dark
# desktop), then find the dark canvas strictly inside it.
findcanvas() { python3 - "$S/$1.ppm" <<'CANV'
import sys
d=open(sys.argv[1],'rb').read(); p=d.split(b'\n',3)
w,h=(int(x) for x in p[1].split()); px=p[3]
def at(x,y):
    i=(y*w+x)*3; return px[i],px[i+1],px[i+2]
def light(c): return c[0]>200 and c[1]>200 and c[2]>200
def dark(c):  return c[0]<45 and c[1]<45 and c[2]<55
rows=[y for y in range(0,h,4) if sum(1 for x in range(0,w,8) if light(at(x,y))) > (w//8)*0.25]
cols=[x for x in range(0,w,4) if sum(1 for y in range(0,h,8) if light(at(x,y))) > (h//8)*0.15]
if not rows or not cols: print("NONE"); raise SystemExit
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
if not best: print("NONE"); raise SystemExit
a,b,y0=best
# Grow by ROW, not by one column: the canvas has white text ("GPU Benchmark
# Test") and a blue button across its middle, so a single-column walk stops
# dead at the first glyph -- it gave 357..548 for a canvas that really runs
# 357..874, which cut the Start button out of the search area entirely.
def rowdark(y):
    n=t=0
    for x in range(a,b,9):
        t+=1
        if dark(at(x,y)): n+=1
    return t and n/t > 0.7
top=y0; bot=y0
while top>wy0 and rowdark(top-1): top-=1
while bot<wy1-1 and rowdark(bot+1): bot+=1
print(a,top,b,bot)
CANV
}

shot before
read CX0 CY0 CX1 CY1 <<< "$(findcanvas before)"
[ "$CX0" = "NONE" ] || [ -z "$CX1" ] && { echo ">>> could not find the canvas in the image"; exit 7; }
echo "==> canvas found at [$CX0,$CY0 .. $CX1,$CY1]"

# Start button: the blue blob inside the canvas.
read BX BY <<< "$(python3 - "$S/before.ppm" "$CX0" "$CY0" "$CX1" "$CY1" <<'PY'
import sys
d=open(sys.argv[1],'rb').read(); p=d.split(b'\n',3)
w,h=(int(x) for x in p[1].split()); px=p[3]
x0,y0,x1,y1=(int(v) for v in sys.argv[2:6])
sx=sy=n=0
for y in range(y0,y1):
    for x in range(x0,x1,2):
        i=(y*w+x)*3; r,g,b=px[i],px[i+1],px[i+2]
        if b>120 and b-r>60 and g<190:      # the blue Start button
            sx+=x; sy+=y; n+=1
print(sx//n, sy//n) if n>40 else print(0,0)
PY
)"
[ "$BX" = 0 ] && { echo ">>> no Start button found inside the canvas"; exit 8; }
echo "==> Start button at ($BX,$BY)"

SW=$(head -2 "$S/before.ppm" | tail -1 | awk '{print $1}')
SH=$(head -2 "$S/before.ppm" | tail -1 | awk '{print $2}')
bright() { python3 - "$S/$1.ppm" "$CX0" "$CY0" "$CX1" "$CY1" <<'PY'
import sys
d=open(sys.argv[1],'rb').read(); p=d.split(b'\n',3)
w,h=(int(x) for x in p[1].split()); px=p[3]
x0,y0,x1,y1=(int(v) for v in sys.argv[2:6])
t=n=0
for y in range(y0,y1,7):
    for x in range(x0,x1,11):
        i=(y*w+x)*3; t+=px[i]+px[i+1]+px[i+2]; n+=1
print(t//(3*n) if n else -1)
PY
}
B0=$(bright before); echo "==> canvas brightness BEFORE the click: $B0"

AX=$(( BX * 32768 / SW )); AY=$(( BY * 32768 / SH ))
for k in 1 2; do   # first click is eaten by click-to-focus
  printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"abs","data":{"axis":"x","value":%s}},{"type":"abs","data":{"axis":"y","value":%s}}]}}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":true,"button":"left"}}]}}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":false,"button":"left"}}]}}\n' "$AX" "$AY" | $SSH "$Q" >/dev/null 2>&1
  sleep 2
done
echo "==> clicked Start twice; settling 12 s"; sleep 12
shot after
B1=$(bright after); echo "==> canvas brightness AFTER  the click: $B1"

if [ "$B1" -lt 30 ] || [ "$B1" = "$B0" ]; then
  echo ">>> THE BENCHMARK IS NOT RUNNING (canvas $B0 -> $B1). No frame rate."
  magick "$S/after.ppm" /tmp/bmfps-fail.png 2>/dev/null && echo "    see /tmp/bmfps-fail.png"
  kill $RUN 2>/dev/null; wait $RUN 2>/dev/null; exit 5
fi

MARK=$($SSH "grep -ac '\[fps\]' $D/boot.log")
echo "==> shader is running; counting frames for $RUNFOR s"
sleep "$RUNFOR"
$SSH "grep -a '\[fps\]' $D/boot.log | tail -n +$((MARK+1))" > "$S/fps.txt" || true
awk '{for(i=1;i<=NF;i++) if($i=="fps") {print $(i-1); break}}' "$S/fps.txt" | \
  awk 'BEGIN{n=0;s=0;mn=1e9;mx=0} {n++;s+=$1; if($1<mn)mn=$1; if($1>mx)mx=$1}
       END{ if(n) printf ">>> %d sample(s): MEAN %.1f fps, min %d, max %d\n", n, s/n, mn, mx;
            else print ">>> NO FRAMES after the click." }'
magick "$S/after.ppm" /tmp/bmfps.png 2>/dev/null && echo "==> /tmp/bmfps.png"
wait $RUN 2>/dev/null || true
