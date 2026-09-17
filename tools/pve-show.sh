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
# Then open the Proxmox console:  https://192.168.1.5:8006  ->  122 (osdev)
#                                 ->  Console
# Firefox's first paint lands around 9 s and the page around 24 s.
#
# Leave it running as long as you like; `tools/pve-run.sh` will stop it when the
# next measurement needs the VM.
set -e
cd "$(dirname "$0")/.."
PVE_HOST=${PVE_HOST:-192.168.1.5}
PVE_DIR=${PVE_DIR:-/root/osdev}
VMID=${VMID:-122}
CORES=${CORES:-1}
MEM=${MEM:-8192}
APPEND=${APPEND:-"ffwl nonetdemo"}
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
$SSH "qm set $VMID --memory $MEM --cores $CORES --args \
  '-snapshot -kernel $PVE_DIR/kernel32.elf -append \"$APPEND\" \
   -drive file=$PVE_DIR/fat.img,format=raw,if=ide,index=0 \
   -drive file=$PVE_DIR/ext2.img,format=raw,if=ide,index=1' >/dev/null"
$SSH "qm start $VMID"
echo
echo "It is up. Watch it here:"
echo "    https://$PVE_HOST:8006   ->  122 (osdev)  ->  Console"
echo
echo "First paint ~9 s, the page on screen ~24 s. The serial log is"
echo "    ssh root@$PVE_HOST 'tail -f $PVE_DIR/boot.log'   (if a capture is attached)"
