#!/bin/sh
# ff — put Firefox on the screen in OS-DEV, in one command.
#
#   tools/ff.sh                        the last URL used (./ffurl.txt), or the local test page
#   tools/ff.sh https://example.com    that URL -- remembered for next time
#   tools/ff.sh URL URL URL ...        one TAB per URL (up to 8)
#   tools/ff.sh blank                  about:blank, the fastest thing that proves the stack
#
#   NOBUILD=1 tools/ff.sh              skip the build (seconds instead of a minute)
#   NOOPEN=1  tools/ff.sh              do not open the console in a local browser
#   CORES=8 MEM=8192 tools/ff.sh       the defaults
#
# Why this exists: booting the browser took remembering which of ffshow/ffwl/
# ffurl does what, that ffurl.txt has to be written AND restaged before the
# build, that pve-run.sh STOPS the VM when it finishes (so it is the wrong
# harness for looking at anything), and finally the Proxmox console URL. Every
# one of those is a way to end up watching the wrong thing.
set -e
cd "$(dirname "$0")/.."

PVE_HOST=${PVE_HOST:-192.168.1.5}
VMID=${VMID:-122}
NODE=${NODE:-pve13thi7}
CORES=${CORES:-8}
MEM=${MEM:-8192}

# THE URL IS AN ARGUMENT, NOT A FILE YOU HAVE TO REMEMBER TO EDIT. ./ffurl.txt
# stays the mechanism (it is gitignored on purpose -- a URL you are testing is
# nobody else's business and must not reach the repo), but writing it by hand
# and forgetting to rebuild the image meant the VM kept loading the previous
# page while the log said otherwise.
APPEND_MODE="ffshow"
case "${1:-}" in
  "")            [ -s ffurl.txt ] && APPEND_MODE="ffshow ffurl" ;;
  blank|about:blank) : ;;                       # plain ffshow = the built-in page
  -h|--help)     sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *)             # EVERY ARGUMENT IS A TAB (M2333). ffurl.txt is one URL per
                 # line and the kernel opens each as a tab, so
                 #   tools/ff.sh https://a https://b https://c
                 # is a three-tab browser. Still gitignored: the addresses
                 # being tested are nobody else's business.
                 : > ffurl.txt
                 for u in "$@"; do printf '%s\n' "$u" >> ffurl.txt; done
                 APPEND_MODE="ffshow ffurl" ;;
esac
[ -s ffurl.txt ] && echo "==> $(grep -c . ffurl.txt) tab(s):" && sed 's/^/      /' ffurl.txt

APPEND="$APPEND_MODE nonetdemo" CORES="$CORES" MEM="$MEM" \
  PVE_HOST="$PVE_HOST" VMID="$VMID" NOBUILD="${NOBUILD:-0}" tools/pve-show.sh

CONSOLE="https://$PVE_HOST:8006/?console=kvm&novnc=1&vmid=$VMID&node=$NODE&resize=off"
echo "==> waiting for the page to reach the screen..."

# WAIT FOR THE PAGE, NOT FOR A DURATION. A fixed sleep is how you end up
# looking at a blank desktop and concluding the browser is broken; these are
# the markers the boot actually prints, including the ones that mean it died.
# Straight into a variable -- an earlier cut staged this through a file under
# /tmp, which is not writable everywhere this runs, so the wait "finished"
# instantly and reported a timeout on a boot that had rendered fine.
STATE=$(ssh -o BatchMode=yes "root@$PVE_HOST" '
  n=0
  while [ $n -lt 150 ]; do
    if grep -aq "PAGE ON SCREEN" /root/osdev/boot.log 2>/dev/null; then echo READY; exit 0; fi
    # THE WINDOW COUNTS TOO. "PAGE ON SCREEN" comes from the probe that watches
    # the built-in test page; point Firefox at a real site and it may never
    # print, while the browser is sitting there fully drawn. Waiting only for
    # it reported a five-minute timeout on a boot whose window was up in forty
    # seconds.
    if grep -aq "desktop window for client.*Mozilla Firefox" /root/osdev/boot.log 2>/dev/null; then echo WINDOW; exit 0; fi
    if grep -aq "CRASHED with signal\|KERNEL PANIC\|the process is GONE" /root/osdev/boot.log 2>/dev/null; then echo DIED; exit 0; fi
    n=$((n+1)); sleep 2
  done
  echo TIMEOUT' 2>/dev/null | tail -1)

case "$STATE" in
  WINDOW)  echo "==> Firefox's window is on the desktop (a real site keeps loading after this)."
           ssh -o BatchMode=yes "root@$PVE_HOST" \
             'grep -a "desktop window for client" /root/osdev/boot.log | tr -d "\000" | tail -1' ;;
  READY)   echo "==> ON SCREEN."
           ssh -o BatchMode=yes "root@$PVE_HOST" \
             'grep -a "PAGE ON SCREEN\|desktop window for client" /root/osdev/boot.log | tr -d "\000" | tail -2' ;;
  DIED)    echo "==> IT DIED. The last thing it said:"
           ssh -o BatchMode=yes "root@$PVE_HOST" \
             'grep -aE "CRASHED with signal|KERNEL PANIC|process is GONE" /root/osdev/boot.log | tr -d "\000" | tail -3' ;;
  *)       echo "==> no page marker within 5 minutes. Look anyway -- and see the log:"
           echo "    ssh root@$PVE_HOST 'tail -40 /root/osdev/boot.log'" ;;
esac

echo
echo "    $CONSOLE"
if [ "${NOOPEN:-0}" != 1 ] && command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$CONSOLE" >/dev/null 2>&1 &
    echo "    (opened in your browser)"
fi
echo
echo "    log:  ssh root@$PVE_HOST 'tail -f /root/osdev/boot.log'"
echo "    stop: ssh root@$PVE_HOST 'qm stop $VMID'"
