#!/bin/sh
# PHASE 8: a real Wayland client talks to OS-DEV's own compositor (M1978).
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

SLOG=$(mktemp /tmp/osdev_wl.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$SLOG"; exit "$rc"; }
trap cleanup EXIT

echo "booting headless and running a real libwayland client against our compositor..."
timeout -s KILL 400 "$QEMU" -cpu max -snapshot -no-reboot -no-shutdown -m 2G -smp 4 -kernel "$KERNEL" \
    -append "wltest wlraw nonetdemo" \
    -drive file="$DISK",format=raw,if=ide \
    -drive file="$EXT2",format=raw,if=ide \
    -display none -serial file:"$SLOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 760 ]; do
    grep -aqE "LXWL: |LXWL: connected|wl\] summary|KERNEL PANIC" "$SLOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.5
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

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

[ $f -eq 0 ] || { echo "FAIL: Wayland compositor"; exit 1; }
echo "PASS: PHASE 8 -- a real libwayland client completed the handshake against OS-DEV's own compositor"
