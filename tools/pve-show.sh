#!/bin/sh
# Boot OS-DEV on the node FOR LOOKING AT, and leave it running.
#
# tools/pve-run.sh is the measurement harness: it boots, captures COM1 for a
# fixed window, and then STOPS the VM so the next run gets a clean image. That
# is exactly wrong when a human wants to watch the screen. This boots the same
# image on the path that works (one core, which is the default everywhere else
# in the tree) and then gets out of the way.
#
#   tools/pve-show.sh            # Firefox against our compositor
#   APPEND=... tools/pve-show.sh # anything else
#
# The default is `ffshow`, not `ffwl` (M2201). `ffwl` is the MEASUREMENT path:
# it keeps the framebuffer for its own diagnostics -- ninety one-second
# heartbeats and then up to forty fifteen-second page samples -- so the window
# manager does not run for the first ten minutes and the screen shows the log
# the whole time. On a boot that had already rendered the page. `ffshow` spawns
# Firefox the same way and hands the screen over at once.
#
# Then open the Proxmox console:  https://192.168.1.5:8006  ->  122 (osdev)
#                                 ->  Console
# Firefox's first paint lands around 9 s and the page around 29 s; the browser
# window appears in the desktop the moment it commits its first frame.
#
# Leave it running as long as you like; `tools/pve-run.sh` will stop it when the
# next measurement needs the VM.
set -e
cd "$(dirname "$0")/.."
PVE_HOST=${PVE_HOST:-192.168.1.5}
PVE_DIR=${PVE_DIR:-/root/osdev}
VMID=${VMID:-122}
CORES=${CORES:-8}
MEM=${MEM:-8192}
APPEND=${APPEND:-"ffshow nonetdemo"}
SSH="ssh -o BatchMode=yes root@$PVE_HOST"

if [ "${NOBUILD:-0}" != 1 ]; then
    echo "==> building..."
    make build/kernel32.elf >/dev/null
    make build/ext2.img >/dev/null
fi

echo "==> stopping VM $VMID so the images are not in use..."
$SSH "qm stop $VMID >/dev/null 2>&1 || true; sleep 1" >/dev/null 2>&1 || true

echo "==> syncing..."
rsync -a --inplace --no-whole-file \
      build/kernel32.elf build/fat.img build/ext2.img "root@$PVE_HOST:$PVE_DIR/"
# Same digest guard as pve-run.sh: rsync's quick check is size + mtime, so a
# rebuild that lands on the same size can transfer nothing (M2156).
L=$(md5sum build/kernel32.elf | cut -d' ' -f1)
R=$($SSH "md5sum $PVE_DIR/kernel32.elf 2>/dev/null | cut -d' ' -f1")
if [ "$L" != "$R" ]; then
    rsync -a --whole-file build/kernel32.elf "root@$PVE_HOST:$PVE_DIR/"
    R=$($SSH "md5sum $PVE_DIR/kernel32.elf 2>/dev/null | cut -d' ' -f1")
fi
[ "$L" = "$R" ] || { echo "FATAL: the node does not have this build." >&2; exit 1; }

echo "==> booting VM $VMID ($CORES core(s), ${MEM}M, -append \"$APPEND\") -- NOT stopping it"
# THE USB TABLET, ON PURPOSE (M2242).
#
# M2241 turned it OFF, which was exactly backwards. A usb-tablet is an
# ABSOLUTE pointing device -- that is why Proxmox defaults to it -- and this
# OS already has a driver that prefers it (usb_tablet_init -> mouse_set_abs),
# falling back to the relative PS/2 mouse only when no tablet is found.
# Forcing PS/2 made the guest cursor drift from the console cursor, so clicks
# landed somewhere other than where the user pointed: "the mouse isnt in the
# same place its offset weird". Absolute input is the fix, not the problem.
$SSH "qm set $VMID --tablet 1" >/dev/null 2>&1 || true
# THE DISPLAY DEVICE IS A VARIABLE NOW (M2346). `std` is the Bochs VGA this has
# always used; `virtio-gl` is `-device virtio-vga-gl -display egl-headless,gl=core`,
# which is the only way a guest can reach a real GPU here. Set explicitly on
# every run rather than left sticky in the VM config, because a display type
# left over from a previous experiment is a confound nobody would look for.
$SSH "qm set $VMID --vga ${VGA:-std}" >/dev/null 2>&1 || true

# A 3D DEVICE THAT IS NOT THE DISPLAY (M2346).
#
# The obvious way to reach a GPU is `--vga virtio-gl`, which makes
# `virtio-vga-gl` the primary adapter. Tried, and it HANGS THIS KERNEL AT BOOT
# -- thirty-six lines in, at the memory-isolation demo, with no "Multiboot
# framebuffer" line, so `fb_init_mb` found no framebuffer tag and fbcon fell
# back to a Bochs VBE mode-set against a device whose framebuffer is not where
# stdvga's is. Replacing a display path that works with one that does not, in
# order to get at a feature that has nothing to do with display, is a bad
# trade.
#
# So: leave the display on stdvga, exactly as it has always been, and attach
# `virtio-gpu-gl` as a SECOND, headless device whose only job is 3D. QEMU wants
# `-display egl-headless,gl=core` for the host GL context either way, and
# Proxmox only passes that itself for `--vga virtio-gl`, so for `std` we add it
# and there is no duplicate.
GPU3D_ARGS=""
[ "${GPU3D:-0}" = 1 ] && GPU3D_ARGS="-display egl-headless,gl=core -device virtio-gpu-gl,id=gpu3d,bus=pci.0,addr=0x1c"
$SSH "qm set $VMID --memory $MEM --cores $CORES --args \
  '-snapshot -kernel $PVE_DIR/kernel32.elf -append \"$APPEND\" \
   -drive file=$PVE_DIR/fat.img,format=raw,if=ide,index=0 \
   -drive file=$PVE_DIR/ext2.img,format=raw,if=ide,index=1 $GPU3D_ARGS' >/dev/null"
$SSH "qm start $VMID"

# DRAIN THE SERIAL PORT, OR THE BOOT STALLS (M2163).
#
# The kernel mirrors every console line to COM1, and Proxmox gives serial0 a
# UNIX socket. With nothing reading that socket the buffer fills and the GUEST
# BLOCKS ON ITS OWN LOG -- the screen freezes mid-boot, a few lines after the
# AC97 probe, and it looks exactly like a hang in whatever came next. The first
# version of this script had no drainer and produced precisely that.
#
# pve-run.sh has always had one (it IS the capture). setsid + nohup so it
# survives this ssh session closing.
$SSH "setsid nohup socat -u UNIX-CONNECT:/var/run/qemu-server/$VMID.serial0 \
        OPEN:$PVE_DIR/boot.log,creat,trunc >/dev/null 2>&1 < /dev/null &" \
     >/dev/null 2>&1 || true
echo
echo "It is up. Watch it here:"
echo "    https://$PVE_HOST:8006   ->  122 (osdev)  ->  Console"
echo
echo "First paint ~9 s, the page on screen ~24 s. Follow the log with"
echo "    ssh root@$PVE_HOST 'tail -f $PVE_DIR/boot.log'"
