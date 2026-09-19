#!/bin/sh
# gtksub-ab.sh -- does Gecko's SHAPE break input, in a program small enough to read?
#
# lxgtk3 responds to a click. Firefox does not. Same compositor, same
# libgtk-3.so.0, same keymap, same seat. Eliminating compositor hypotheses one
# ten-minute boot at a time has produced a long list of things that are not
# it, so this goes the other way: make the control look like Gecko and see
# which change breaks it.
#
# The difference this arm tests is the one the compositor's own log shows:
#
#   [wl] surface 18 is a subsurface (role object 30)
#   [wl] subsurface 30: surface 18 is now a child of surface 33
#   [wl] set_input_region on surface 18 -> an EMPTY region -- takes no input
#   [wl] commit: 1280x960 ... (surface 18, subsurface)
#
# Gecko paints into a subsurface it creates OUTSIDE GDK, declares that the
# subsurface takes no input, and leaves it covering the whole window. lxgtk3
# --subsurface does exactly that to itself. Same binary both arms, so the
# toolkit, the libraries and the build are held constant by construction --
# which is the mistake M2250 made by using zenity (GTK4) as a GTK3 control.
#
# A: -append lxgtk3   plain, the known-good control
# B: -append gtksub   the same program with Gecko's subsurface in front
set -e
cd "$(dirname "$0")/.."
H=${PVE_HOST:-192.168.1.5}
VMID=${VMID:-122}
D=/root/osdev
SSH="ssh -o BatchMode=yes root@$H"
S=${SCRATCH:-/tmp/claude-1000/-home-miles-OS-DEV/026bcdb5-8d88-4ad7-9f23-58649bf4f353/scratchpad}/gtksub
mkdir -p "$S"

arm() {                       # arm <name> <append-flag>
    echo "########## $1 (-append $2)"
    WAIT=full NOBUILD=1 APPEND="ffwl $2 nonetdemo" CORES=${CORES:-4} CAP=${CAP:-200} \
        tools/pve-run.sh >"$S/$1-run.txt" 2>&1 &
    RUN=$!
    T0=$(date -u +%s); i=0
    while [ $i -lt 180 ]; do
        if $SSH "[ \"\$(stat -c %Y $D/boot.log 2>/dev/null || echo 0)\" -ge $T0 ] && \
                 grep -aq 'LXGTK3: window shown' $D/boot.log 2>/dev/null"; then break; fi
        sleep 3; i=$((i+3))
    done
    [ $i -lt 180 ] || { echo "  FAIL: no lxgtk3 window in ${i}s"; wait $RUN; return 1; }
    sleep 6

    # AIM FROM THE COMPOSITOR'S OWN REPORT, not from a guess. M2297 made the
    # window line carry the content origin for exactly this.
    GEO=$($SSH "grep -a 'desktop window for client' $D/boot.log | grep -a OSDEV-GTK3 | tail -1")
    echo "  $GEO"
    CX=$(echo "$GEO" | sed -E 's/.*content origin ([0-9]+),([0-9]+).*/\1/')
    CY=$(echo "$GEO" | sed -E 's/.*content origin ([0-9]+),([0-9]+).*/\2/')
    WW=$(echo "$GEO" | sed -E 's/.*slot [0-9]+: ([0-9]+)x([0-9]+) .*/\1/')
    WH=$(echo "$GEO" | sed -E 's/.*slot [0-9]+: ([0-9]+)x([0-9]+) .*/\2/')
    case "$CX$CY$WW$WH" in *[!0-9]*|"") echo "  FAIL: could not parse geometry"; wait $RUN; return 1;; esac
    PX=$(( CX + WW / 2 )); PY=$(( CY + WH / 2 ))
    AX=$(( PX * 32767 / 1280 )); AY=$(( PY * 32767 / 960 ))
    echo "  clicking the button centre at screen $PX,$PY (tablet $AX,$AY)"

    { printf '{"execute":"qmp_capabilities"}\n'
      printf '{"execute":"input-send-event","arguments":{"events":[{"type":"abs","data":{"axis":"x","value":%s}},{"type":"abs","data":{"axis":"y","value":%s}}]}}\n' "$AX" "$AY"
      sleep 2
      printf '{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":true,"button":"left"}}]}}\n'
      sleep 1
      printf '{"execute":"input-send-event","arguments":{"events":[{"type":"btn","data":{"down":false,"button":"left"}}]}}\n'
      sleep 2; } | $SSH "socat - UNIX-CONNECT:/var/run/qemu-server/$VMID.qmp" >/dev/null 2>&1 || true
    sleep 8

    $SSH "grep -a 'LXGTK3' $D/boot.log | tail -8"
    if $SSH "grep -aq 'LXGTK3-CLICKED' $D/boot.log"; then echo "  => CLICK REACHED THE BUTTON"
    else echo "  => NO CLICK (the button never fired)"; fi
    $SSH "grep -ao 'ptr fwd: [^|]*' $D/boot.log | tail -1" | sed 's/^/  /'
    wait $RUN 2>/dev/null || true
    scp -q "root@$H:$D/boot.log" "$S/$1.log"
    echo
}

# THE IMAGE HAS TO CARRY THE BINARY BEING TESTED. The first run of this
# script used NOBUILD=1 throughout, which skips `make build/ext2.img` -- so
# /disk2/lxgtk3 was still the build from before --subsurface existed, it
# ignored the argument, and arm B printed the same CLICKED as arm A while
# testing nothing at all. The kernel had even logged that it passed the flag.
# A control whose binary is stale is the M2297 lesson twice in one hour.
[ -n "${ARMS:-}" ] || ARMS="A-plain:lxgtk3 B-subsurf:gtksub"
for a in $ARMS; do arm "${a%%:*}" "${a##*:}"; done
echo "==> logs in $S"
