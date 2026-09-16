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
# WHICH SURFACE IS THE WINDOW (M2058). The compositor used to keep ONE global
# "last committed surface", so for any client with more than one surface -- and
# every real toolkit has several: a toplevel, popups, subsurfaces, a cursor --
# the window was painted from whichever committed last. GTK commits a cursor
# surface as soon as the pointer enters, so the window's contents became a
# 24x24 cursor. The libwayland client below cannot catch that: it has exactly
# one surface, which is why it passed throughout.
#
# So the compositor drives its own dispatcher with the multi-surface message
# sequence that produces the bug and asserts the toplevel is what gets drawn --
# plus object destruction, role loss, NULL-attach unmapping and
# wl_shm_pool.resize, none of which a one-surface client reaches either.
stn=$(grep -ac "^WLSELFTEST: ok" "$SLOG")
if grep -aq "WLSELFTEST: PASSED" "$SLOG" && ! grep -aq "WLSELFTEST: FAIL" "$SLOG"; then
    echo "  ok: the surface-selection self-test passed ($(grep -ao 'WLSELFTEST: PASSED -- .*' "$SLOG" | head -1 | sed 's/^WLSELFTEST: PASSED -- //'))"
else
    echo "  FAIL: the surface-selection self-test did not pass ($stn ok):"
    grep -a "WLSELFTEST: FAIL" "$SLOG" | head -8; f=1
fi
# The raw client checks the BYTES independently of libwayland's opinion of
# them: it parses the handshake by hand, so a framing bug shows up here rather
# than as a silent stall inside the library.
# The message COUNT is 2 + one per advertised global (the sync callback's done
# and the display's delete_id close the handshake), so it moves when a global is
# added -- read it from the client rather than pinning a number that has to be
# edited every time. What is asserted is that every byte parsed into a complete
# message with nothing left over, which is what a framing bug breaks.
rawn=$(grep -ao "LXWLRAW: [0-9]* complete message(s) in [0-9]* bytes" "$SLOG" | head -1)
rawg=$(grep -ac "LXWLRAW-MSG: obj=2 op=0" "$SLOG")
if [ -n "$rawn" ] && [ "$rawg" -ge 7 ]; then
    echo "  ok: the handshake is well-formed on the wire ($rawn, $rawg globals, parsed by hand)"
else
    echo "  FAIL: the raw handshake was malformed (globals seen: $rawg):"; grep -a "LXWLRAW" "$SLOG" | head -3; f=1
fi
# Every advertised global, by name -- a compositor that sent a malformed string
# or a wrong length would lose one of these rather than all of them.
# Every advertised global, including the three a real TOOLKIT needs and a demo
# client does not: GDK will not create a seat until wl_data_device_manager has
# arrived, sizes windows against wl_output, and uses wl_subcompositor for
# popups. (M1986)
for g in wl_compositor wl_shm wl_seat xdg_wm_base wl_output wl_data_device_manager wl_subcompositor; do
    if grep -aq "LXWL-GLOBAL: $g " "$SLOG"; then
        echo "  ok: libwayland parsed the $g global"
    else
        echo "  FAIL: $g was not received by libwayland:"; grep -a "LXWL-GLOBAL" "$SLOG" | head -4; f=1
    fi
done
if grep -aq "LXWL: connected, 7 globals, wl_compositor bound, 2 roundtrips OK" "$SLOG"; then
    echo "  ok: A REAL libwayland CLIENT COMPLETED THE HANDSHAKE (bind + 2 roundtrips)"
else
    echo "  FAIL: the client did not complete:"; grep -aE "LXWL|roundtrip" "$SLOG" | tail -4; f=1
fi
# M2081: the compositor never SAID a surface had been created. obj_add is
# silent, and the exported counters covered commits, destroys, protocol errors,
# clients, messages and globals -- everything except the one object whose
# existence separates a client that is starting up from a client that is never
# going to draw. Firefox's whole symptom is "never creates a wl_surface", and
# the only way to observe that was -append wlverbose, which dumps every message
# and, before M2080, was the flag most likely to wedge the machine.
# M2082: libwayland-cursor grows its shm pool with ftruncate/fallocate as it
# adds each cursor image, and our memfd refused to grow an object that was
# already mapped -- so wl_cursor_theme_load returned NULL and Firefox reported
# eight lines of "Unable to load nw-resize from the cursor theme". This is the
# real library making Firefox's real call at Firefox's real sizes; the
# in-kernel self-test is not a demo.
if grep -aqE "LXWL-CURSOR: loaded [1-9][0-9]* cursors" "$SLOG"; then
    echo "  ok: $(grep -ao 'LXWL-CURSOR: loaded .*' "$SLOG" | head -1) -- a MAPPED shm pool can grow (M2082)"
else
    echo "  FAIL: libwayland-cursor could not grow its pool:"; grep -a "LXWL-CURSOR" "$SLOG" | tail -2; f=1
fi
if grep -aqE "\[wl\] surface [0-9]+ created \(client ep [0-9]+" "$SLOG"; then
    echo "  ok: the compositor NAMES each surface as it is created ($(grep -ac "\[wl\] surface .* created" "$SLOG") seen, incl. one from the real client) (M2081)"
else
    echo "  FAIL: no surface-creation line from a real client:"; grep -a "\[wl\] surface" "$SLOG" | tail -4; f=1
fi
# M2087 -- A DESTROYED POOL KEPT ITS SHARED-MEMORY OBJECT FOR EVER.
# wl_shm_pool holds a reference on the memfd object behind it, taken by the
# kernel when the descriptor arrives over SCM_RIGHTS, and there was no call to
# hand one back -- the source said so outright and deliberately leaked, because
# freeing on the pool's destroy would pull the memory out from under buffers
# the protocol guarantees outlive their pool. So the fix was never the unref:
# it was giving the other holders references of their own. A buffer and a
# surface's committed frame each take one now.
# 300 cycles is chosen so the failure is unambiguous rather than statistical:
# NMEMFD is 256, so a leak of one per cycle exhausts the table and the client's
# own memfd_create starts failing. Reverting the unrefs fails at cycle 255 with
# "[memfd] TABLE FULL", and the high-water mark prints the whole staircase.
if grep -aq "LXWL-POOLCYCLE: 300 pools created and destroyed, none leaked" "$SLOG"; then
    echo "  ok: 300 wl_shm_pool create/destroy cycles leak nothing -- peak was $(grep -ao '\[memfd\] [0-9]* of [0-9]* shared' "$SLOG" | tail -1 | grep -oE '^\[memfd\] [0-9]+' | grep -oE '[0-9]+') live object(s) (M2087)"
else
    echo "  FAIL: a destroyed shm pool is still holding its memory:"; grep -a "LXWL-POOLCYCLE\|TABLE FULL" "$SLOG" | tail -3; f=1
fi
# M2089 -- A WINDOW IS A TREE OF SURFACES, AND THERE IS MORE THAN ONE CLIENT.
# Two defects that hid each other. get_subsurface read its first two arguments
# and discarded the third -- the PARENT -- so a subsurface knew which surface
# it wrapped and not which surface it belonged to, and wl_subsurface.set_position
# fell through to wl_unhandled. And the window manager opened exactly ONE
# Wayland window ever, latched, so the first client to commit anything took the
# display for the rest of the boot.
# Measured on Firefox: it committed 768 frames at 1204x916 into a SUBSURFACE of
# a toplevel that has no buffer of its own (which is what GTK does), while the
# 64x32 test client -- which commits two minutes earlier -- held the only
# window. Both had to be fixed before anything could appear.
if grep -aqE "\[wl\] subsurface [0-9]+: surface [0-9]+ is now a child of surface [0-9]+" "$SLOG"; then
    echo "  ok: a subsurface records the PARENT it was given, not just the surface it wraps (M2089)"
else
    echo "  FAIL: get_subsurface is still discarding its parent argument:"; grep -a "subsurface" "$SLOG" | tail -3; f=1
fi
if grep -aqE "\[wl\] desktop window for client slot [0-9]+" "$SLOG"; then
    echo "  ok: the window manager opens a window PER CLIENT ($(grep -ac 'desktop window for client slot' "$SLOG") seen) (M2089)"
else
    echo "  FAIL: no per-client Wayland window was opened:"; grep -a "desktop window" "$SLOG" | tail -3; f=1
fi
# And the pixel report must describe the WHOLE buffer. "first pixel" alone read
# 0x00000000 for 762 consecutive Firefox frames, which is equally consistent
# with a blank window and with the transparent corner of a client-side-decorated
# one -- opposite conclusions from one number.
if grep -aqE "sampled pixels have colour" "$SLOG"; then
    echo "  ok: a commit reports how much of the buffer has colour, not just pixel 0 ($(grep -ao '[0-9]*/[0-9]* sampled pixels have colour' "$SLOG" | tail -1)) (M2089)"
else
    echo "  FAIL: the commit report still describes one pixel:"; grep -a "\[wl\] commit" "$SLOG" | tail -2; f=1
fi
# PIXELS. The client wrote 0xFF3366CC into a memfd, passed the DESCRIPTOR over
# the protocol socket, and committed a surface. The compositor reading that
# exact value back proves the whole zero-copy path: SCM_RIGHTS carried the
# descriptor, the pool is the client's own memory rather than a copy, and the
# buffer geometry was parsed correctly. A wrong stride or offset would give a
# different pixel; a copy would still give the right one, which is why the
# SIZE is checked too.
if grep -aq "first pixel 0xff3366cc" "$SLOG"; then
    # ...from the line that actually carries the client's colour. `head -1` on a
    # bare "commit:" pattern would find the surface-selection self-test's own
    # commit, which is a different surface and a different size.
    echo "  ok: the compositor READ THE CLIENT'S PIXELS ($(grep -a "first pixel 0xff3366cc" "$SLOG" | head -1 | sed 's/^.*commit: /commit: /'))"
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
# THE KEYMAP (M1984). Wayland does not carry key labels -- it carries a
# descriptor to a keymap the client compiles with libxkbcommon, and a client
# that never gets one turns no keycode into a character. This is the kernel
# handing a client a file it created, over SCM_RIGHTS, in the other direction
# from the pixels above.
ksz=$(grep -ao "\[wl\] sent xkb keymap ([0-9]* bytes)" "$SLOG" | head -1 | tr -dc 0-9)
csz=$(grep -ao "LXWL-INPUT: keymap format 1, fd [0-9]*, [0-9]* bytes" "$SLOG" | head -1 | awk '{print $(NF-1)}')
if [ -n "$ksz" ] && [ "$ksz" = "$csz" ]; then
    echo "  ok: the compositor handed over its own XKB keymap as a kernel-created memfd ($ksz bytes, and the client sees the same size)"
else
    echo "  FAIL: the keymap was not delivered intact (compositor sent '$ksz', client saw '$csz'):"
    grep -a "keymap" "$SLOG" | head -3; f=1
fi
if grep -aq "LXWL-XKB: compiled the compositor's keymap" "$SLOG"; then
    echo "  ok: the client mmap'd that descriptor and libxkbcommon COMPILED it ($(grep -ao "compiled the compositor's keymap ([^)]*)" "$SLOG" | head -1))"
else
    echo "  FAIL: libxkbcommon did not compile the keymap:"; grep -a "LXWL-XKB\|LXWL-INPUT: keymap" "$SLOG" | head -3; f=1
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
