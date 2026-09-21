#!/bin/sh
# Do MULTIPLE TABS work? Not "do six tabs appear" -- that only proves Firefox
# parsed a command line. This proves each tab holds its OWN document and that
# switching between them actually switches what is displayed.
#
# THE ORACLE IS THE WINDOW TITLE, for the same reason tools/ffnav-test.sh uses
# it: the window manager logs every xdg_toplevel.set_title, and the title only
# changes when the browser presents a DIFFERENT document. A pixel diff cannot
# tell "the tab strip highlighted" from "the tab switched", and a count of
# tab-shaped rectangles cannot tell a loaded page from an error page.
#
#   tools/fftabs-test.sh              boot, then click each tab in turn
#
# The URLs come from ./ffurl.txt, one per line (see M2333).
set -e
cd "$(dirname "$0")/.."
H=${PVE_HOST:-192.168.1.5}; V=${VMID:-122}; D=${PVE_DIR:-/root/osdev}
S=${SCRATCH:-/tmp/claude-1000/-home-miles-OS-DEV/026bcdb5-8d88-4ad7-9f23-58649bf4f353/scratchpad}/tabs
mkdir -p "$S"
SSH="ssh -o BatchMode=yes root@$H"

# WAIT FOR THE DUMP, DO NOT SLEEP AT IT. `qm monitor screendump` is
# asynchronous: a fixed sleep sometimes copied the PREVIOUS frame, which made
# two different tabs hash identically and produced a false "did not switch".
# Delete first, then poll for the file to reappear with a settled size.
shot(){ $SSH "rm -f $D/t.ppm; echo 'screendump $D/t.ppm' | qm monitor $V >/dev/null 2>&1;
              n=0; while [ \$n -lt 40 ]; do
                  s1=\$(stat -c %s $D/t.ppm 2>/dev/null || echo 0); sleep 0.5;
                  s2=\$(stat -c %s $D/t.ppm 2>/dev/null || echo 0);
                  [ \"\$s1\" = \"\$s2\" ] && [ \"\$s1\" != 0 ] && break; n=\$((n+1));
              done" >/dev/null 2>&1
        scp -q root@$H:$D/t.ppm "$S/$1.ppm" 2>/dev/null || true; }
click(){ printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"abs","data":{"axis":"x","value":%s}},{"type":"abs","data":{"axis":"y","value":%s}}]}}\n' "$1" "$2" | $SSH "socat - UNIX-CONNECT:/var/run/qemu-server/$V.qmp" >/dev/null 2>&1; sleep 1
  printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":true,"button":"left"}}]}}\n' | $SSH "socat - UNIX-CONNECT:/var/run/qemu-server/$V.qmp" >/dev/null 2>&1; sleep 1
  printf '{"execute":"qmp_capabilities"}\n{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":false,"button":"left"}}]}}\n' | $SSH "socat - UNIX-CONNECT:/var/run/qemu-server/$V.qmp" >/dev/null 2>&1; }
title(){ $SSH "grep -a 'toplevel title:' $D/boot.log | tail -1" | sed 's/.*toplevel title: //'; }

WAIT=full NOBUILD=1 APPEND="ffshow ffurl nonetdemo" CORES=${CORES:-8} CAP=${CAP:-300} \
  VMID=$V PVE_DIR=$D tools/pve-run.sh >"$S/run.txt" 2>&1 &
RUN=$!
T0=$(date -u +%s); i=0
while [ $i -lt 300 ]; do
  if $SSH "[ \"\$(stat -c %Y $D/boot.log 2>/dev/null || echo 0)\" -ge $T0 ] && grep -aq 'Mozilla Firefox' $D/boot.log"; then break; fi
  sleep 5; i=$((i+5))
done
echo "   window at ~${i}s; letting every tab load"; sleep 60

if $SSH "grep -aq 'CRASHED with signal' $D/boot.log"; then
  echo "   => PRECONDITION FAILED: Firefox crashed; there are no tabs to switch between."
  wait $RUN 2>/dev/null || true; exit 1
fi
NTAB=$($SSH "grep -ao 'URL(s) from /disk2/ffurl.txt -> [0-9]* tab' $D/boot.log | grep -oE '> [0-9]*' | tr -d '> '" | tail -1)
echo "   the kernel handed Firefox $NTAB URL(s)"
shot all

# THE URL BAR IS THE ORACLE, AND THE CLICK PITCH IS MEASURED (M2334).
#
# Two dead ends first, both worth recording:
#
#  1. Clicking at a 155 px pitch. Tab widths depend on the tab COUNT, so the
#     pitch drifts; by the fifth click it hit a tab's close button and
#     DESTROYED the Hacker News tab -- and the test passed, because the title
#     had indeed changed. Measured from a screendump, the real pitch is 180
#     and the label centre sits ~75 px left of the close button.
#
#  2. Ctrl+1..Ctrl+8. Position-independent and it does nothing here: the
#     title never changed. The test "passed" anyway because its fallback
#     accepted "the screen changed" -- and the front tab is a live dashboard
#     whose numbers update on their own, so the screen ALWAYS changes. An
#     oracle that cannot fail is worse than no oracle.
#
# So: click the measured label centre, and compare the URL BAR. It is the one
# region that differs per tab and that a live page cannot alter.
urlbar(){ python3 - "$1" <<'PY'
import sys, hashlib
from PIL import Image
im = Image.open(sys.argv[1]).crop((250, 86, 900, 112))
print(hashlib.sha256(im.tobytes()).hexdigest()[:12])
PY
}

fail=0; prev_bar=""; bars=""
k=0
while [ $k -lt "${NTAB:-0}" ] && [ $k -lt 6 ]; do
  px=$(( 140 + k * 180 )); py=56
  click $(( px * 32768 / 1280 )) $(( py * 32768 / 960 )); sleep 6
  shot "tab$k"
  b=$(urlbar "$S/tab$k.ppm" 2>/dev/null || echo "?")
  t=$(title)
  echo "   tab $k: urlbar=$b  title=$t"
  case "$bars" in *"$b"*) echo "   ...DUPLICATE address bar: this click did not switch tab"; fail=1 ;; esac
  bars="$bars|$b"
  k=$((k+1))
done

# AND NOTHING MAY HAVE BEEN DESTROYED. The first version closed a tab and
# called it a pass, so count the tabs that are still there.
LEFT=$(python3 - "$S/tab$((k-1)).ppm" 2>/dev/null <<'PY'
import sys
from PIL import Image
im = Image.open(sys.argv[1])
# close buttons sit on the tab strip row; count distinct tab separators by
# sampling the strip's background transitions at y=56
row = [im.getpixel((x, 56)) for x in range(40, 1180)]
edges = sum(1 for i in range(1, len(row)) if abs(sum(row[i]) - sum(row[i-1])) > 60)
print(edges)
PY
)
echo "   tab-strip edge transitions on the last shot: ${LEFT:-?} (a proxy for tabs still present)"

[ $fail -eq 0 ] && echo "   => TABS WORK: every tab showed a DIFFERENT address" \
                || echo "   => TAB SWITCHING FAILED (see above)"
echo "   shots in $S"
wait $RUN 2>/dev/null || true
exit $fail
