#!/bin/sh
# Headless assertion for the DESKTOP / window manager (M1925).
#
# Why this exists: the desktop had NO automated coverage at all. Window
# management, the keyboard chords and (as of M1923/M1924) virtual desktops were
# each verified once, by hand, by looking at a screenshot -- exactly the situation
# that let three box-model bugs coexist in a fully green tree until M1902. A
# regression here is silent: nothing else in `make check` opens a window.
#
# Method: drive the real desktop through the QEMU monitor with tools/osdrive.py,
# capture framebuffer dumps, and assert RELATIVE properties between them rather
# than absolute pixels, so the theme, wallpaper and window placement can all
# change freely without breaking this:
#
#   1. switching to an empty workspace must CHANGE the screen a lot (the windows
#      are gone), and
#   2. switching back must restore it EXACTLY -- byte-identical to the capture
#      taken before the switch. That is the strongest statement available about
#      workspace save/restore, and it is what makes this worth running: a
#      half-restored window set would differ by a few pixels and be caught.
#   3. Alt+F4 must actually close the focused window, which is observable as the
#      taskbar chip row getting shorter.
#
# SKIPs cleanly if QEMU or python3 is missing. Exit 0 = pass.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
command -v "$QEMU"   >/dev/null 2>&1 || { echo "SKIP: desktop test ($QEMU not found)"; exit 0; }
command -v python3   >/dev/null 2>&1 || { echo "SKIP: desktop test (python3 not found)"; exit 0; }
command -v socat     >/dev/null 2>&1 || { echo "SKIP: desktop test (socat not found)"; exit 0; }

OUT=$(mktemp -d /tmp/osdev_desk.XXXXXX)
cleanup() { rc=$?; rm -rf "$OUT"; exit "$rc"; }
trap cleanup EXIT

echo "booting the desktop headlessly and driving the window manager..."
# ws1 -> (switch) ws2 -> (switch back) ws1, then close a window on ws1.
# ONE osdrive session, not two. Two back-to-back runs each boot their own VM,
# and osdrive does not use -snapshot -- so the second opened the same fat.img
# while the first was still shutting down, failed to take the write lock, and
# booted nothing. Alone it usually won the race; under `make check` it did not.
# The `linux` command goes FIRST because it leaves text in the shell window,
# and the workspace checks compare shots taken after it, to each other.
D2=""
[ -f build/ext2.img ] && D2="--disk2 build/ext2.img"
python3 tools/osdrive.py --out "$OUT" --boot-timeout 90 $D2 -c '
sleep 6;
type linux /hellofree;
key ret;
sleep 8;
shot a_ws1.ppm;
key ctrl-alt-right;
sleep 2;
shot b_ws2.ppm;
key ctrl-alt-left;
sleep 2;
shot c_ws1_again.ppm;
key alt-f4;
sleep 2;
shot d_closed.ppm' >/dev/null 2>&1 || true

# RUNNING A LINUX BINARY FROM THE DESKTOP (M1988). Until the `linux` command
# existed, the compatibility layer could only run what a kernel boot flag told
# it to; and a Linux process's stdout went to the kernel console, which the
# desktop covers -- so the first real use of it printed five hundred lines of
# `claude --help` into a console nobody could see and looked, from the shell,
# like nothing had happened. Both halves are asserted here, in the desktop the
# user actually types into: a SMALL static binary keeps it fast enough for
# `make check` (claude itself is 214 MB and minutes per start under TCG).
# hellofree, not hellolibc: it is freestanding (-nostdlib), so it needs no AVX
# and this boot does not have to ask for -cpu max. The ext2 volume carries the
# Linux binaries, so it has to be attached -- without it there is nothing to run
# and the command fails for a reason that has nothing to do with what is tested.

for f in a_ws1 b_ws2 c_ws1_again d_closed; do
    [ -f "$OUT/$f.ppm" ] || { echo "FAIL: no framebuffer dump '$f' (boot or drive failed)"; exit 1; }
done

# Asserted from the LOG, not from pixels, and the reason is worth recording: the
# program's output is printed onto the line that already holds the next prompt,
# so a broken run and a working one produce the same number of text lines and
# the same ink. A screenshot cannot tell them apart. The kernel can, because the
# two cases take different code paths -- console or window -- and it now says
# which.
if [ ! -f build/ext2.img ]; then
    echo "  SKIP: 'linux' command check (no build/ext2.img)"
else
    # ONE line carries the whole property. It is printed by the kernel, so it
    # reaches the serial log; the shell's own "linux: started ..." message and
    # the program's output both go to the WINDOW now and deliberately do not.
    # Its presence means a Linux binary was started by a command typed into the
    # desktop AND that its stdout took the window path rather than the console.
    if grep -aq "a Linux child's stdout is going to the window of pid" "$OUT/serial.log" 2>/dev/null; then
        echo "  ok: a LINUX binary ran from the desktop shell and its stdout went to that WINDOW, not the hidden console"
    else
        echo "  FAIL: no Linux binary output reached a window:"
        grep -aE "linux|hellofree" "$OUT/serial.log" 2>/dev/null | tail -3; exit 1
    fi
fi

python3 tests/desktop/check_wm.py "$OUT/a_ws1.ppm" "$OUT/b_ws2.ppm" \
                                  "$OUT/c_ws1_again.ppm" "$OUT/d_closed.ppm" && rc=0 || rc=$?
if [ "${rc:-1}" -eq 0 ]; then
    echo "PASS: desktop window manager (workspace switch hides windows, switching back restores them exactly, Alt+F4 closes)"
else
    echo "FAIL: desktop window manager"
    exit 1
fi
