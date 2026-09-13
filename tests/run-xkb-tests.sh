#!/bin/sh
# OS-DEV's own XKB keymap, compiled by the real libxkbcommon (M1984).
#
# The kernel hands this string to a Wayland client over a memfd; libxkbcommon on
# the other side decides whether it means anything. That decision is made in the
# guest, minutes into a TCG boot, and a bad keymap presents only as "typing does
# nothing" -- so it is checked here, on the host, in under a second.
set -e
cd "$(dirname "$0")/.."
OUT=build/tests
mkdir -p $OUT
if ! pkg-config --exists xkbcommon 2>/dev/null && [ ! -f /usr/include/xkbcommon/xkbcommon.h ]; then
    echo "SKIP: xkb keymap test (libxkbcommon headers not installed)"; exit 0
fi
cc -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
   -Wall -Wextra -Ikernel/include -o $OUT/xkbmap_test tests/xkb/xkbmap_test.c -lxkbcommon
$OUT/xkbmap_test
echo "PASS: OS-DEV's own XKB keymap compiles self-contained and maps evdev keycodes to the right characters"
