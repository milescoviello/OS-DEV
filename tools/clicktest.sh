#!/bin/bash
# clicktest — does a click reach GECKO, or only the compositor?
#
# The Start button on volumeshaderbm needs WebGL, so "nothing happened" there
# is ambiguous: the click may never have arrived, or it arrived and WebGL
# failed. The preset buttons (Simple/Standard/Advanced/Extreme) are plain HTML
# with a visible selected state and no GL involved -- so clicking one and
# reading the pixel back separates those two causes outright.
set -e
cd "$(dirname "$0")/.."
H=${PVE_HOST:-192.168.1.5}; V=${VMID:-122}; D=/root/osdev
SSH="ssh -o BatchMode=yes -o ConnectTimeout=20 root@$H"
Q="socat - UNIX-CONNECT:/var/run/qemu-server/$V.qmp"
S=$(mktemp -d)

printf 'https://volumeshaderbm.com/start/\n' > ffurl.txt
WAIT=full APPEND="ffshow ffurl nonetdemo" CORES=8 MEM=8192 CAP=${CAP:-200} \
  tools/pve-run.sh > /tmp/clicktest-run.txt 2>&1 &
RUN=$!

# Wait for the page, not a fixed sleep.
echo "==> waiting for the page to load"
for i in $(seq 1 100); do
  $SSH "grep -aq 'toplevel title: \"Run Volume' $D/boot.log 2>/dev/null" && break
  sleep 3
done
$SSH "grep -aq 'toplevel title: \"Run Volume' $D/boot.log" || { echo ">>> page never loaded"; kill $RUN 2>/dev/null; exit 4; }
echo "==> page is up; settling 6 s"; sleep 6

# Use tools/shot.sh rather than a second copy of the screendump dance: the
# inline copy here was subtly broken (the file was never created and scp said
# so), and one working implementation beats two similar ones.
shot() { tools/shot.sh "$S/$1.png" >/dev/null || { echo ">>> screendump failed"; exit 6; }; }

click() {  # click(realx, realy) -- twice, because click-to-focus eats the first
  local AX=$(( $1 * 32768 / SW )) AY=$(( $2 * 32768 / SH ))
  for k in 1 2; do
    printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"abs","data":{"axis":"x","value":%s}},{"type":"abs","data":{"axis":"y","value":%s}}]}}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":true,"button":"left"}}]}}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":false,"button":"left"}}]}}\n' "$AX" "$AY" | $SSH "$Q" >/dev/null 2>&1
    sleep 2
  done; }

shot before
read SW SH <<< "$(head -2 "$S/before.ppm" | tail -1)"
echo "==> screen ${SW}x${SH}"

# Find the preset row and the four button centres from the BEFORE image.
read -r PY SX0 SX1 SX2 SX3 <<< "$(python3 - "$S/before.ppm" <<'PY'
import sys
d=open(sys.argv[1],'rb').read()
p=d.split(b'\n',3); w,h=(int(x) for x in p[1].split()); px=p[3]
def rgb(x,y):
    i=(y*w+x)*3; return (px[i],px[i+1],px[i+2])
# The selected preset is a saturated blue; find the row with the most blue px.
best=(0,0)
for y in range(int(h*0.5), int(h*0.75)):
    n=sum(1 for x in range(0,w,4) if (lambda c:(c[2]>120 and c[2]-c[0]>60))(rgb(x,y)))
    if n>best[0]: best=(n,y)
y=best[1]
runs=[];cur=None
for x in range(0,w):
    c=rgb(x,y); blue = c[2]>120 and c[2]-c[0]>60
    light = c[0]>200 and c[1]>200 and c[2]>200
    on = blue or light
    if on and cur is None: cur=x
    if not on and cur is not None:
        if x-cur>60: runs.append((cur,x))
        cur=None
print(y, *[ (a+b)//2 for a,b in runs[:4] ])
PY
)"
echo "==> preset row y=$PY, buttons at x = $SX0 $SX1 $SX2 $SX3"

probe() { python3 - "$S/$1.ppm" "$PY" "$SX0" "$SX1" "$SX2" "$SX3" <<'PY'
import sys
d=open(sys.argv[1],'rb').read(); p=d.split(b'\n',3)
w,h=(int(x) for x in p[1].split()); px=p[3]; y=int(sys.argv[2])
out=[]
for a in sys.argv[3:]:
    x=int(a); i=(y*w+x)*3; c=(px[i],px[i+1],px[i+2])
    out.append("SEL" if (c[2]>120 and c[2]-c[0]>60) else "---")
print(" ".join(out))
PY
}

echo "==> BEFORE: $(probe before)   (SEL = the highlighted preset)"
echo "==> clicking the 3rd preset (Advanced) at ($SX2,$PY)"
click "$SX2" "$PY"
shot after
echo "==> AFTER:  $(probe after)"
echo
if [ "$(probe before)" = "$(probe after)" ]; then
  echo ">>> THE CLICK DID NOT REACH GECKO. The selected preset did not move,"
  echo "    on a plain HTML button with no WebGL anywhere near it."
else
  echo ">>> THE CLICK REACHED GECKO -- the preset moved. So input works, and"
  echo "    a Start button that does nothing is a WEBGL failure, not an input one."
fi
magick "$S/after.ppm" /tmp/clicktest.png 2>/dev/null && echo "==> /tmp/clicktest.png"
wait $RUN 2>/dev/null || true
