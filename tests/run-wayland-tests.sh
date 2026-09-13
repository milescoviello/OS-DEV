#!/bin/sh
# PHASE 8: a real Wayland client talks to OS-DEV's own compositor, hands it
# pixels through shared memory, gets a real window, and TAKES INPUT
# (M1978-M1983).
#
# The client is built against libwayland-client -- the same library Firefox and
# GTK use -- and deliberately NOT hand-rolled. A hand-rolled client would only
# prove the compositor agrees with our own idea of the protocol; libwayland
# holds us to the standard instead. It is staged into the guest with its whole
# dependency closure, unmodified.
#
# What a pass means: the AF_UNIX socket was found through XDG_RUNTIME_DIR, the
# wire format and message framing are right, the registry globals were
# delivered and parsed, a global was bound, and the sync/done ORDERING is
# correct -- wl_display_roundtrip() only returns when a `done` arrives for a
# callback created after get_registry, so it is the ordering that makes it
# return rather than hang.
#
# SKIPs cleanly if libwayland was never staged (it is only there if the host
# had the library when the image was built).
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
EXT2=build/ext2.img
command -v "$QEMU" >/dev/null 2>&1 || { echo "SKIP: wayland test ($QEMU not found)"; exit 0; }
[ -f "$EXT2" ] || { echo "SKIP: wayland test (no $EXT2)"; exit 0; }
[ -f build/lxroot/lxwl ] || { echo "SKIP: wayland test (libwayland not staged)"; exit 0; }

TMP=$(mktemp -d /tmp/osdev_wl.XXXXXX)
SLOG=$TMP/serial.log
SOCK=$TMP/mon.sock
QSOCK=$TMP/qmp.sock
PPM=$TMP/screen.ppm
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -rf "$TMP"; exit "$rc"; }
trap cleanup EXIT

echo "booting headless and running a real libwayland client against our compositor..."
timeout -s KILL 900 "$QEMU" -cpu max -snapshot -no-reboot -no-shutdown -m 2G -smp 4 -kernel "$KERNEL" \
    -append "wltest wlraw nonetdemo" \
    -drive file="$DISK",format=raw,if=ide \
    -drive file="$EXT2",format=raw,if=ide \
    -display none -serial file:"$SLOG" \
    -monitor unix:"$SOCK",server,nowait -qmp unix:"$QSOCK",server,nowait \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 760 ]; do
    grep -aqE "LXWL-SURFACE|LXWL: |KERNEL PANIC" "$SLOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.5

f=0
if grep -aq "KERNEL PANIC" "$SLOG"; then
    echo "  FAIL: KERNEL PANIC:"; grep -a -A2 "KERNEL PANIC" "$SLOG" | head -3; f=1
fi
# The raw client checks the BYTES independently of libwayland's opinion of
# them: it parses the handshake by hand, so a framing bug shows up here rather
# than as a silent stall inside the library.
if grep -aq "LXWLRAW: 6 complete message(s) in 148 bytes" "$SLOG"; then
    echo "  ok: the handshake is well-formed on the wire (6 messages, 148 bytes, parsed by hand)"
else
    echo "  FAIL: the raw handshake was malformed:"; grep -a "LXWLRAW" "$SLOG" | head -3; f=1
fi
# Every advertised global, by name -- a compositor that sent a malformed string
# or a wrong length would lose one of these rather than all of them.
for g in wl_compositor wl_shm wl_seat xdg_wm_base; do
    if grep -aq "LXWL-GLOBAL: $g " "$SLOG"; then
        echo "  ok: libwayland parsed the $g global"
    else
        echo "  FAIL: $g was not received by libwayland:"; grep -a "LXWL-GLOBAL" "$SLOG" | head -4; f=1
    fi
done
if grep -aq "LXWL: connected, 4 globals, wl_compositor bound, 2 roundtrips OK" "$SLOG"; then
    echo "  ok: A REAL libwayland CLIENT COMPLETED THE HANDSHAKE (bind + 2 roundtrips)"
else
    echo "  FAIL: the client did not complete:"; grep -aE "LXWL|roundtrip" "$SLOG" | tail -4; f=1
fi
# PIXELS. The client wrote 0xFF3366CC into a memfd, passed the DESCRIPTOR over
# the protocol socket, and committed a surface. The compositor reading that
# exact value back proves the whole zero-copy path: SCM_RIGHTS carried the
# descriptor, the pool is the client's own memory rather than a copy, and the
# buffer geometry was parsed correctly. A wrong stride or offset would give a
# different pixel; a copy would still give the right one, which is why the
# SIZE is checked too.
if grep -aq "first pixel 0xff3366cc" "$SLOG"; then
    echo "  ok: the compositor READ THE CLIENT'S PIXELS ($(grep -ao 'commit: [0-9]*x[0-9]* stride [0-9]*' "$SLOG" | head -1))"
else
    echo "  FAIL: the committed pixels did not arrive:"; grep -aE "\[wl\] (commit|shm pool)" "$SLOG" | head -3; f=1
fi
if grep -aq "shm pool .*: 8192 bytes of the client's own memory" "$SLOG"; then
    echo "  ok: the shm pool is the client's own memory, taken from a passed memfd"
else
    echo "  FAIL: the shm pool was not established:"; grep -a "shm pool" "$SLOG" | head -2; f=1
fi
# xdg_shell: the protocol that turns a bare surface into a real WINDOW -- one
# the client titles and the compositor sizes. It is what GTK and Firefox use,
# and a compositor that does not send the INITIAL configure unprompted leaves
# them waiting forever having done nothing wrong.
if grep -aq 'toplevel title: "OS-DEV Wayland demo"' "$SLOG"; then
    echo "  ok: the client named its own window through xdg_toplevel.set_title"
else
    echo "  FAIL: set_title did not arrive:"; grep -a "toplevel title" "$SLOG" | head -2; f=1
fi
if grep -aq "LXWL-XDG: toplevel configured and acknowledged" "$SLOG"; then
    echo "  ok: the xdg_surface.configure / ack_configure handshake completed"
else
    echo "  FAIL: the client never got a configure:"; grep -a "LXWL-XDG" "$SLOG" | head -2; f=1
fi
if grep -aq "LXWL-SURFACE: committed 64x32 ARGB8888" "$SLOG"; then
    echo "  ok: and the client completed its commit roundtrip"
else
    echo "  FAIL: the client did not finish its commit:"; grep -a "LXWL-SURFACE" "$SLOG" | head -2; f=1
fi

# ...and finally: is it ON SCREEN? The compositor reading the right pixels and
# the window manager DRAWING them are different claims. Wait for the desktop,
# then screendump and look for the client's colour.
if command -v socat >/dev/null 2>&1 && [ "$f" -eq 0 ]; then
    i=0
    while [ $i -lt 200 ]; do
        grep -aq "launching the desktop environment" "$SLOG" 2>/dev/null && break
        sleep 0.5; i=$((i+1))
    done
    sleep 6                      # let the desktop paint its first frames
    shot=1
    j=0
    while [ $j -lt 6 ]; do
        printf 'screendump %s\n' "$PPM" | socat - UNIX-CONNECT:"$SOCK" >/dev/null 2>&1 || true
        if [ -s "$PPM" ] && python3 tests/wl/shot_check.py "$PPM"; then shot=0; break; fi
        sleep 3; j=$((j+1))
    done
    [ "$shot" -eq 0 ] || { echo "  FAIL: the surface never appeared on screen"; f=1; }
else
    echo "  SKIP: on-screen check (socat not available)"
fi

# INPUT (M1983). Pixels prove a client can draw; this proves it can be USED.
# Real QEMU input events -- an absolute pointer and a keystroke -- are driven at
# the VM and have to come back out of libwayland inside the guest as
# wl_pointer/wl_keyboard events with the right surface-relative coordinates.
if [ "$f" -eq 0 ]; then
    python3 tests/wl/drive_input.py "$QSOCK" "$SLOG" "$TMP/in.ppm" || f=1
else
    echo "  SKIP: input check (an earlier check already failed)"
fi

kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""
[ $f -eq 0 ] || { echo "FAIL: Wayland compositor"; exit 1; }
echo "PASS: PHASE 8 -- a real libwayland client's surface is DRAWN IN AN OS-DEV WINDOW, and it takes INPUT"
