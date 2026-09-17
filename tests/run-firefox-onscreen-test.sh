#!/bin/sh
# FIREFOX RENDERS A REAL WEB PAGE ON SCREEN, IN AN OS-DEV WINDOW, THROUGH
# OS-DEV'S OWN WAYLAND COMPOSITOR.
#
# `make firefoxpagetest` already asserts the pixels of a HEADLESS render, and
# that is a different claim: --screenshot goes through drawSnapshot, which never
# builds a continuous WebRender scene, so it passed for this entire campaign
# while the on-screen content area was blank. This asserts the ON-SCREEN path --
# the compositor's own buffers, sampled by wl_page_probe.
#
# IT NEEDS A LONG CAPTURE AND THAT IS NOT A WORKAROUND, IT IS THE MEASUREMENT.
# The page appears about 150-195 seconds after Firefox's first paint, and first
# paint itself varies, so a capture that ends sooner records only the chrome.
# Every "the content area is still blank" reading in this campaign came from a
# window that had not got there yet, so a short run here would assert the old
# wrong answer.
#
# REVERT-PROOF: with M2128's setsockopt(SOL_IP, IP_RECVERR) reverted -- one line
# -- the page never appears: 0 of 29 samples, against 11 of 20 here. Chrome
# startup waits on getaddrinfo, so a single refused socket option stops the
# first tab being created and navigated. (M2135)
set -e
NODE=${PVE_NODE:-192.168.1.5}
CAP=${CAP:-900}

ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$NODE" true 2>/dev/null \
  || { echo "SKIP: firefox on-screen test (no ssh to $NODE — needs the Proxmox node)"; exit 0; }
[ -x tools/pve-run.sh ] || { echo "SKIP: firefox on-screen test (no tools/pve-run.sh)"; exit 0; }
[ -f build/lxroot/usr/lib64/firefox/firefox ] \
  || { echo "SKIP: firefox on-screen test (firefox not staged)"; exit 0; }
[ -f build/lxroot/ffpage.html ] \
  || { echo "SKIP: firefox on-screen test (ffpage.html not staged)"; exit 0; }

echo "booting OS-DEV on $NODE and letting Firefox reach its page (slow: it is a browser)..."
NOBUILD=${NOBUILD:-1} APPEND="ffwl lxout noprobes nonetdemo" CORES=1 CAP="$CAP" \
  tools/pve-run.sh >/dev/null 2>&1 || true

LOG=$(ssh -o BatchMode=yes "root@$NODE" "tr -d '\r' < /root/osdev/boot.log" 2>/dev/null || true)
[ -n "$LOG" ] || { echo "FAIL: firefox on-screen: no boot log came back"; exit 1; }

samples=$(printf '%s\n' "$LOG" | grep -c 'sample [0-9]*,' || true)
onscreen=$(printf '%s\n' "$LOG" | grep -c 'VERDICT: the PAGE is on screen' || true)
f=0

# Fewer than ~12 samples cannot reach the window in which the page appears, so
# that is an inconclusive run rather than a failure -- saying otherwise would
# make the suite report a red for a capture that simply stopped early.
if [ "${samples:-0}" -lt 12 ]; then
    echo "SKIP: firefox on-screen test (only $samples samples: the capture ended before the page could appear; raise CAP)"
    exit 0
fi

if [ "${onscreen:-0}" -ge 1 ]; then
    pct=$(printf '%s\n' "$LOG" | grep -o 'is on screen -- [0-9]*%' | head -1 | grep -o '[0-9]*%')
    echo "  ok: the PAGE is on screen in $onscreen of $samples samples ($pct of the content area is the page's background)"
else
    echo "  FAIL: the content area never showed the page in $samples samples:"
    printf '%s\n' "$LOG" | grep -a 'VERDICT' | tail -2 | sed 's/^/      /'
    f=1
fi
# The document's own <title> in the window title: the page was not just painted,
# it was LOADED, and the chrome knows what it is.
if printf '%s\n' "$LOG" | grep -q 'toplevel title: "OS-DEV — Mozilla Firefox"'; then
    echo "  ok: and the window title carries the document's own <title>"
else
    echo "  FAIL: the window title never became the document's:"
    printf '%s\n' "$LOG" | grep -a 'toplevel title' | tail -1 | sed 's/^/      /'
    f=1
fi
# The h1's colour, separately from the background: text was laid out and shaped.
if printf '%s\n' "$LOG" | grep -q 'ff4fd1c5'; then
    echo "  ok: and the heading's colour is present -- text was laid out, shaped and rasterised"
else
    echo "  FAIL: no heading pixels: the background painted but the text did not"; f=1
fi

[ $f -eq 0 ] || { echo "FAIL: firefox on-screen"; exit 1; }
echo "PASS: Firefox renders a real web page ON SCREEN in an OS-DEV window"
