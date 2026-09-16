#!/bin/bash
# vmrun.sh <tag> <nsmp> <kernel-cmdline...>   [VMDISPLAY=none|gtk]
#
# Start a long-lived OS-DEV VM with the ext2 volume, 8 GiB of RAM and both
# disks, and leave its HMP monitor on a socket so tools/vmdrive.py can drive it
# and tools/ can screenshot it. VMDISPLAY=gtk (the default) gives a window a
# person can type into; VMDISPLAY=none is for scripted runs.
#
# Rebuilds the kernel AND the ext2 image first, because `make` alone does not
# rebuild the image -- a new test binary is otherwise silently absent from the
# volume and the probe reports "exit -1".
#
# Artifacts go under $VMDIR (default ~/.osdev-vm), NOT /tmp: /tmp here is a
# tmpfs on a dual-booting laptop and does not survive a reboot.
S="${VMDIR:-$HOME/.osdev-vm}"
TAG="$1"; shift
SMP="$1"; shift
APPEND="$*"
mkdir -p "$S/$TAG"
rm -f "$S/$TAG/serial.log" "$S/$TAG/mon.sock" "$S/$TAG/qemu.err"
cd /home/miles/OS-DEV || exit 1
make -j24 >/dev/null 2>&1 || exit 1
make build/ext2.img >/dev/null 2>&1 || exit 1
setsid nohup qemu-system-x86_64 -cpu max -snapshot -no-reboot -no-shutdown \
  -m 8G -smp "$SMP" -kernel build/kernel32.elf -append "$APPEND" \
  -drive file=build/fat.img,format=raw,if=ide \
  -drive file=build/ext2.img,format=raw,if=ide \
  -netdev user,id=net0 -device e1000,netdev=net0 \
  -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
  -display "${VMDISPLAY:-gtk}" -serial "file:$S/$TAG/serial.log" \
  -monitor "unix:$S/$TAG/mon.sock,server,nowait" \
  >"$S/$TAG/qemu.err" 2>&1 </dev/null &
echo "launched $TAG smp=$SMP display=${VMDISPLAY:-gtk}: $APPEND"
echo "  monitor: $S/$TAG/mon.sock"
echo "  serial : $S/$TAG/serial.log"
