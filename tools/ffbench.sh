#!/bin/sh
# ffbench — measure the FRAME RATE of a page in OS-DEV's Firefox, unattended.
#
#   tools/ffbench.sh https://example.com/          boot it, let it run, report fps
#   RUNFOR=90 tools/ffbench.sh URL                 how long to watch (default 60 s)
#   NOBUILD=1 tools/ffbench.sh URL                 skip the build
#   KEEP=1    tools/ffbench.sh URL                 leave the VM up to look at
#   CLICK=594,518 tools/ffbench.sh URL               click there (PAGE pixels) first,
#                                                    then measure -- for a benchmark
#                                                    that waits behind a Start button
#
# Why this and not tools/ff.sh: ff.sh is for LOOKING at the browser, so it
# leaves the VM running and opens a console. A frame-rate number must not come
# through noVNC -- the console's own network latency and its own repaint rate
# are both in the way, and neither is the guest's. So: boot, wait for the
# WINDOW (a real site never prints "PAGE ON SCREEN"), watch the guest's own
# [fps] lines on the serial log for RUNFOR seconds, screendump it so the number
# can be checked against a picture, and stop.
#
# THE INSTRUMENT CAN REPORT FAILURE, and that is the point. [fps] comes from
# wl_surface.commit, so a page that renders nothing commits nothing and prints
# NO LINE -- reported here as "NO FRAMES", never as 0 fps by omission.
set -e
cd "$(dirname "$0")/.."
H=${PVE_HOST:-192.168.1.5}; V=${VMID:-122}; D=/root/osdev
RUNFOR=${RUNFOR:-60}
S=$(mktemp -d); SSH="ssh -o BatchMode=yes root@$H"

[ -n "$1" ] && { : > ffurl.txt; for u in "$@"; do printf '%s\n' "$u" >> ffurl.txt; done; }
[ -s ffurl.txt ] || { echo "ffbench: no URL given and ffurl.txt is empty" >&2; exit 2; }
echo "==> $(grep -c . ffurl.txt) tab(s), $RUNFOR s of frames"

APPEND="ffshow ffurl nonetdemo" CORES=${CORES:-8} MEM=${MEM:-8192} \
  PVE_HOST="$H" VMID="$V" NOBUILD="${NOBUILD:-0}" tools/pve-show.sh >/dev/null

# WAIT FOR THE WINDOW, NOT A DURATION.
STATE=$($SSH '
  n=0
  while [ $n -lt 150 ]; do
    grep -aq "desktop window for client.*Firefox" '"$D"'/boot.log 2>/dev/null && { echo WINDOW; exit 0; }
    grep -aq "CRASHED with signal\|KERNEL PANIC\|the process is GONE" '"$D"'/boot.log 2>/dev/null && { echo DIED; exit 0; }
    n=$((n+1)); sleep 2
  done; echo TIMEOUT' 2>/dev/null | tail -1)
echo "==> window: $STATE"
[ "$STATE" = DIED ] && { $SSH "grep -aE 'CRASHED with signal|KERNEL PANIC|process is GONE' $D/boot.log | tr -d '\000' | tail -3"; $SSH "qm stop $V" >/dev/null 2>&1 || true; exit 1; }

# A BENCHMARK BEHIND A START BUTTON (M2345). The first reading taken here was
# 27.9 fps mean / 103 fps peak on volumeshaderbm, and it was measuring NOTHING
# TO DO WITH THE SHADER: the page had rendered, the Standard preset was already
# selected, and the canvas was sitting there waiting to be started. Those were
# load-and-layout commits. The screendump said so and the fps line could not.
# So: click, settle, THEN mark the log.
if [ -n "${CLICK:-}" ]; then
    CX=$(echo "$CLICK" | cut -d, -f1); CY=$(echo "$CLICK" | cut -d, -f2)
    AX=$(( CX * 32768 / 1280 )); AY=$(( CY * 32768 / 960 ))
    echo "==> clicking page pixel ($CX,$CY) -> abs ($AX,$AY)"
    Q="socat - UNIX-CONNECT:/var/run/qemu-server/$V.qmp"
    printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"abs","data":{"axis":"x","value":%s}},{"type":"abs","data":{"axis":"y","value":%s}}]}}\n' "$AX" "$AY" | $SSH "$Q" >/dev/null 2>&1
    sleep 1
    printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":true,"button":"left"}}]}}\n' | $SSH "$Q" >/dev/null 2>&1
    sleep 1
    printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":false,"button":"left"}}]}}\n' | $SSH "$Q" >/dev/null 2>&1
    echo "==> settling ${SETTLE:-8} s before counting"
    sleep "${SETTLE:-8}"
fi

# DID THE PAGE ACTUALLY LOAD? (M2345)
#
# The second reading taken with this script was "mean 20.5 fps, max 50" on
# volumeshaderbm, and the page it was measuring was Firefox's own "Server Not
# Found" -- DNS had hung, five threads parked in the resolver, and the fps
# counter faithfully reported the error page repainting. The number was real
# and it described nothing anybody asked about.
#
# So the harness asks the browser what it is showing. The compositor logs every
# xdg_toplevel.set_title, and a failed load renames the window -- "Problem
# loading page", "Server Not Found" -- which is an oracle the guest hands over
# for free and which cannot be satisfied by a page that merely repaints.
TITLE=$($SSH "grep -a 'toplevel title:' $D/boot.log | tr -d '\000' | tail -1" 2>/dev/null)
echo "==> window title: $TITLE"
case "$TITLE" in
  *"Problem loading"*|*"Server Not Found"*|*"not found"*|*"Unable to connect"*|*"did not connect"*)
      echo ">>> THE PAGE DID NOT LOAD. Refusing to report a frame rate for an error page."
      $SSH "grep -aiE 'DNS Resolver|resolver\]' $D/boot.log | tr -d '\000' | tail -5"
      [ "${KEEP:-0}" = 1 ] || $SSH "qm stop $V" >/dev/null 2>&1 || true
      exit 3 ;;
esac

# MARK THE LOG, so the frames counted are the ones AFTER the page had a window
# -- the load itself commits plenty and would inflate the number.
MARK=$($SSH "grep -ac '\[fps\]' $D/boot.log 2>/dev/null || echo 0")
echo "==> watching for $RUNFOR s (log already had $MARK fps lines)"
sleep "$RUNFOR"

$SSH "rm -f $D/b.ppm; echo 'screendump $D/b.ppm' | qm monitor $V >/dev/null 2>&1;
      n=0; while [ \$n -lt 40 ]; do s1=\$(stat -c %s $D/b.ppm 2>/dev/null || echo 0); sleep 0.5;
        s2=\$(stat -c %s $D/b.ppm 2>/dev/null || echo 0);
        [ \"\$s1\" = \"\$s2\" ] && [ \"\$s1\" != 0 ] && break; n=\$((n+1)); done" >/dev/null 2>&1
scp -q "root@$H:$D/b.ppm" "$S/shot.ppm" 2>/dev/null || true

$SSH "grep -a '\[fps\]' $D/boot.log | tr -d '\000'" 2>/dev/null | tail -n +"$((MARK+1))" > "$S/fps.txt" || true
$SSH "grep -a '\[frame\]' $D/boot.log | tr -d '\000'" 2>/dev/null | tail -5 > "$S/frame.txt" || true

echo
if [ -s "$S/fps.txt" ]; then
    echo "=== the page's own frame rate (wl_surface.commit) ==="
    cat "$S/fps.txt"
    awk '{for(i=1;i<=NF;i++) if($i=="fps"){r=$(i-1); n++; s+=r; if(r>mx)mx=r; if(mn==""||r<mn)mn=r}}
         END{if(n) printf "\n>>> %d sample(s): mean %.1f fps, min %d, max %d\n", n, s/n, mn, mx}' "$S/fps.txt"
else
    echo ">>> NO FRAMES. The page committed nothing in $RUNFOR s -- that is not 0 fps"
    echo "    by rounding, it is a page that never handed over a frame at all."
fi
echo
echo "=== the compositor's own rate (for contrast: its headroom is not the page's rate) ==="
cat "$S/frame.txt" 2>/dev/null || echo "(no [frame] lines)"
[ -s "$S/shot.ppm" ] && { command -v convert >/dev/null 2>&1 && convert "$S/shot.ppm" "$S/shot.png" 2>/dev/null; echo; echo "=== screendump: $S/shot.png ==="; }

[ "${KEEP:-0}" = 1 ] || $SSH "qm stop $V" >/dev/null 2>&1 || true
echo "$S" > /tmp/ffbench.last
