#!/bin/sh
# ffbench — measure the FRAME RATE of a page in OS-DEV's Firefox, unattended.
#
#   tools/ffbench.sh https://example.com/          boot it, let it run, report fps
#   RUNFOR=90 tools/ffbench.sh URL                 how long to watch (default 60 s)
#   NOBUILD=1 tools/ffbench.sh URL                 skip the build
#   KEEP=1    tools/ffbench.sh URL                 leave the VM up to look at
#   FFAPPEND="ffgl" tools/ffbench.sh URL             extra -append words (e.g. ffgl for
#                                                    Firefox's own GL decision log)
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

APPEND="ffshow ffurl nonetdemo ${FFAPPEND:-}" CORES=${CORES:-8} MEM=${MEM:-8192} \
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
    # THE SCREEN IS NOT ALWAYS 1280x960 (M2367). These divisors were hardcoded,
    # so the moment the display moved to 2560x1440 every click landed at half
    # the intended position -- silently, because a click on empty page
    # background looks exactly like a click that worked. Read the real
    # geometry out of a screendump instead of assuming it.
    $SSH "rm -f $D/geom.ppm; echo 'screendump $D/geom.ppm' | qm monitor $V >/dev/null 2>&1;
          n=0; while [ \$n -lt 40 ]; do a=\$(stat -c %s $D/geom.ppm 2>/dev/null||echo 0); sleep 0.3;
            b=\$(stat -c %s $D/geom.ppm 2>/dev/null||echo 0);
            [ \"\$a\" = \"\$b\" ] && [ \"\$a\" != 0 ] && break; n=\$((n+1)); done"
    GEOM=$($SSH "head -2 $D/geom.ppm | tail -1")
    SW=$(echo "$GEOM" | awk '{print $1}'); SH=$(echo "$GEOM" | awk '{print $2}')
    case "$SW" in ''|*[!0-9]*) echo ">>> FATAL: could not read screen geometry"; exit 5;; esac
    AX=$(( CX * 32768 / SW )); AY=$(( CY * 32768 / SH ))
    echo "==> screen is ${SW}x${SH}; clicking page pixel ($CX,$CY) -> abs ($AX,$AY)"
    Q="socat - UNIX-CONNECT:/var/run/qemu-server/$V.qmp"
    printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"abs","data":{"axis":"x","value":%s}},{"type":"abs","data":{"axis":"y","value":%s}}]}}\n' "$AX" "$AY" | $SSH "$Q" >/dev/null 2>&1
    sleep 1
    # CLICK TWICE (M2367). The first click on an unfocused window is consumed
    # by click-to-focus -- the compositor activates the window and the press
    # never reaches the client. Verified by screendump: cursor sitting exactly
    # on the Start button, title bar newly highlighted, canvas still black.
    # The second click is the one the page sees. A benchmark that silently
    # measured an idle canvas is precisely the failure this script exists to
    # refuse, so do not rely on the window happening to be focused already.
    printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":true,"button":"left"}}]}}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":false,"button":"left"}}]}}\n' | $SSH "$Q" >/dev/null 2>&1
    sleep 2
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

# DID THE BENCHMARK ACTUALLY START? (M2362)
#
# Every volumeshaderbm number reported before this check was the IDLE PAGE.
# The click went to (594,518), which was the Start button's centre in one
# layout and ~26 px left of it in the one the browser actually renders at
# 1280 px wide -- so the screendumps showed a black canvas with the Start
# button still on it, and the [fps] meter dutifully counted the page's own
# repaints. Three separate "3-7 fps" and "13.5 fps" readings, none of them the
# shader.
#
# A running volumetric shader fills the canvas with bright colour; a stopped
# one is near-black. Sample the canvas centre and refuse to report a frame
# rate when it is dark, because "the benchmark is slow" and "the benchmark is
# not running" are opposite conclusions that look identical in a frame count.
if [ -n "${CANVAS:-1}" ]; then
    $SSH "rm -f $D/c.ppm; echo 'screendump $D/c.ppm' | qm monitor $V >/dev/null 2>&1;
          n=0; while [ \$n -lt 40 ]; do a=\$(stat -c %s $D/c.ppm 2>/dev/null||echo 0); sleep 0.3;
            b=\$(stat -c %s $D/c.ppm 2>/dev/null||echo 0);
            [ \"\$a\" = \"\$b\" ] && [ \"\$a\" != 0 ] && break; n=\$((n+1)); done" >/dev/null 2>&1
    scp -q "root@$H:$D/c.ppm" "$S/canvas.ppm" 2>/dev/null || true
    BRIGHT=$(python3 - "$S/canvas.ppm" <<'PY'
import sys
try:
    d = open(sys.argv[1],'rb').read()
except Exception:
    print(-1); raise SystemExit
# P6 header: magic, w h, maxval, then binary
parts = d.split(b'\n', 3)
if len(parts) < 4 or parts[0] != b'P6': print(-1); raise SystemExit
w, h = (int(x) for x in parts[1].split())
px = parts[3]
# The canvas region as a FRACTION of the screen, not pixels: the sample box
# was written for 1280x960 and at 2560x1440 it covered only the top-left
# quadrant -- mostly browser chrome, which is bright, so a stopped benchmark
# would have read as a running one. (M2367)
tot = n = 0
for y in range(int(h*0.31), int(h*0.73), max(1, h//56)):
    for x in range(int(w*0.20), int(w*0.86), max(1, w//56)):
        i = (y*w + x)*3
        if i+2 < len(px):
            tot += px[i] + px[i+1] + px[i+2]; n += 1
print(tot // (3*n) if n else -1)
PY
)
    command -v magick >/dev/null 2>&1 && magick "$S/canvas.ppm" "$S/canvas.png" 2>/dev/null
    echo "==> canvas mean brightness: $BRIGHT (0-255; a stopped benchmark is near-black)"
    echo "==> post-click screendump: $S/canvas.png"
    echo "$S" > /tmp/ffbench.last
    if [ "$BRIGHT" != "-1" ] && [ "$BRIGHT" -lt 25 ]; then
        echo ">>> THE BENCHMARK IS NOT RUNNING. The canvas is dark, which means the"
        echo "    Start click missed or the shader never began. Refusing to report a"
        echo "    frame rate for an idle page."
        [ "${KEEP:-0}" = 1 ] || $SSH "qm stop $V" >/dev/null 2>&1 || true
        exit 4
    fi
fi

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
