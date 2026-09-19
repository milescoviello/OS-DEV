#!/bin/sh
# run-fkey-test.sh -- can a function key reach a real toolkit application?
#
# Until M2293 the answer was no, and it was no in two different ways at once.
# F1-F9 and F12 were bound to window-manager actions in the keyboard IRQ
# handler, so pressing F5 in a browser snapped the window left instead of
# reloading the page. F10 and F11 had no cooked encoding at all and were
# dropped where they arrived -- `sendkey f11` produced `keys: 0 dequeued`,
# a whole key that did not exist. Page Up, Page Down, Home, End and Delete
# had no evdev mapping either, so the ordinary way to scroll a web page from
# the keyboard reached nothing.
#
# That is worth a test rather than a screenshot because it cost a
# measurement: a Firefox run drove `f11`, saw the screen not change, and
# produced exactly the null result "Firefox ignores the keyboard" would have
# produced. The key died two layers below Firefox.
#
# The oracle is lxgtk3 -- GTK 3.24, the same library Firefox links -- which
# prints the GDK keyval of every key it receives. GDK_KEY_F11 is 0xffc8 =
# 65480 and GDK_KEY_Page_Down is 0xff56 = 65366, so this asserts on the
# values a real toolkit computed from our keymap, not on our own encoding.
#
# REVERT PROOF: restore `if (k == 0x1D)` etc. in kernel/desktop.c (drop the
# `!fk_to_client &&`) and F11 stops arriving -- the run prints
# "F11 did NOT reach the client".
set -e
cd "$(dirname "$0")/.."
H=${PVE_HOST:-192.168.1.5}
VMID=${VMID:-122}
D=/root/osdev
SSH="ssh -o BatchMode=yes root@$H"

# `lxgtk3` SELECTS THE CLIENT, `ffwl` SELECTS THE MODE. On its own lxgtk3
# sets a flag nothing reads: the spawn is gated on ffwl/ffshow/ffnet/ffurl,
# so `-append lxgtk3` boots to a desktop with no client in it and this test
# waits three minutes for a window that was never going to appear. Same shape
# as M2241's `-append ffurl` with no browser.
WAIT=none NOBUILD=${NOBUILD:-0} APPEND="ffwl lxgtk3 nonetdemo" CORES=${CORES:-4} \
    CAP=${CAP:-200} tools/pve-run.sh >/dev/null 2>&1 &
RUN=$!

# THE MARKER MUST BE IN A LOG THIS RUN WROTE. pve-run.sh spends the better
# part of a minute stopping the VM and syncing before it starts anything, and
# for all of it $D/boot.log still holds the PREVIOUS boot. The first revert
# proof matched that, reported `window at ~0s`, drove four keys at a machine
# that was not running yet and dutifully reported four failures -- which is
# the result the revert was SUPPOSED to produce, arrived at for the wrong
# reason. A check that cannot tell those apart proves nothing either way.
T0=$(date -u +%s)
i=0
while [ $i -lt 180 ]; do
    if $SSH "[ \"\$(stat -c %Y $D/boot.log 2>/dev/null || echo 0)\" -ge $T0 ] && \
             grep -aq 'LXGTK3: window shown' $D/boot.log 2>/dev/null"; then break; fi
    sleep 3; i=$((i+3))
done
if [ $i -ge 180 ]; then echo "FKEY: FAIL -- lxgtk3 never showed a window"; wait $RUN; exit 1; fi
echo "    lxgtk3 window at ~${i}s"
sleep 4

# One key per press, with a pause: the probe prints as it receives.
for k in f11 pgdn f5 home; do
    $SSH "echo 'sendkey $k' | qm monitor $VMID >/dev/null 2>&1"
    sleep 2
done
sleep 6
$SSH "grep -a 'LXGTK3-KEY' $D/boot.log | tail -12" > /tmp/fkey.$$ || true
KV=$(cat /tmp/fkey.$$ | sed -E 's/.*keyval ([0-9]+).*/\1/' | tr '\n' ' ')
rm -f /tmp/fkey.$$
echo "    keyvals seen: $KV"

RC=0
for want in 65480:F11 65366:Page_Down 65474:F5 65360:Home; do
    v=${want%%:*}; n=${want##*:}
    case " $KV " in
        *" $v "*) echo "    ok: $n reached the client" ;;
        *)        echo "    FAIL: $n did NOT reach the client (keyval $v absent)"; RC=1 ;;
    esac
done
wait $RUN 2>/dev/null || true
[ $RC = 0 ] && echo "FKEY: ok -- function and navigation keys reach a GTK3 client" \
            || echo "FKEY: FAIL"
exit $RC
