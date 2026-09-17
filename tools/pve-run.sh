#!/bin/sh
# pve-run.sh -- the change->measure loop for OS-DEV on pve-ultra under KVM.
#
# WHY THIS EXISTS. tools/pve-deploy.sh predates the ext2 root filesystem: it
# ships kernel32.elf and, optionally, fat.img -- and every Linux binary, the
# whole glibc/GTK/Firefox closure and OS-DEV's own source tree now live in
# ext2.img, which is regenerated on EVERY kernel source change. So a deploy has
# to move 3.2 GB, and rsync --inplace --no-whole-file does it in seconds once
# the first copy is there.
#
# WHY pve-ultra AND NOT THE LAPTOP. The laptop's UEFI has VT-x disabled, so
# /dev/kvm cannot exist there and everything is TCG. This node has KVM, 20
# cores at 5.2 GHz and 29 GB free -- and the first thing measuring under KVM
# established is that emulation was never the bottleneck: Firefox's first paint
# still took ~50 s, reading 803 MB from disk across 508955 page faults. Every
# "it's slow because TCG" conclusion had to be re-derived.
#
# Usage:  tools/pve-run.sh                      # ffwl, 180s of capture
#         APPEND="lxabitest nonetdemo" tools/pve-run.sh
#         CAP=300 tools/pve-run.sh
#         NOBUILD=1 tools/pve-run.sh            # deploy what is already built
set -e

PVE_HOST=${PVE_HOST:-192.168.1.5}
VMID=${VMID:-122}
PVE_DIR=${PVE_DIR:-/root/osdev}
APPEND=${APPEND:-"ffwl nonetdemo"}
CAP=${CAP:-180}
MEM=${MEM:-8192}
CORES=${CORES:-8}
SSH="ssh -o BatchMode=yes root@$PVE_HOST"

cd "$(dirname "$0")/.."

if [ "${NOBUILD:-0}" != 1 ]; then
    echo "==> building kernel + ext2 image..."
    make build/kernel32.elf >/dev/null
    make build/ext2.img >/dev/null
fi

# STOP THE VM BEFORE TOUCHING THE IMAGES, and boot it with -snapshot after.
# Both were wrong on the first run: rsync failed verification on ext2.img
# because a RUNNING guest was writing into it, and it was writing into it
# because the Proxmox args had no -snapshot -- so every boot was mutating the
# 3.2 GB image the next boot depends on. Every local run has used -snapshot
# since M1966 for exactly this reason. (M2101)
echo "==> stopping VM $VMID so the images are not in use..."
$SSH "qm stop $VMID >/dev/null 2>&1 || true; sleep 1" >/dev/null 2>&1 || true

echo "==> syncing to $PVE_HOST:$PVE_DIR (incremental)..."
rsync -a --inplace --no-whole-file \
      build/kernel32.elf build/fat.img build/ext2.img "root@$PVE_HOST:$PVE_DIR/"

# THE LINUX ROOT'S TRANSPORT (M2144).
#
# fat.img stays on IDE: it is the boot volume, it is tiny, and blockdev's mount
# names are assigned in SCAN ORDER -- ATA registers before virtio, so keeping
# the FAT disk on ATA is what keeps the ext2 volume as `disk2`, which is the
# path LX_ROOT hardcodes. Moving both would silently rename the Linux root.
#
# ext2.img is where every byte Firefox and Claude Code touch lives, and IDE
# emulation is the slowest transport QEMU offers. VIRTIO=0 forces the old IDE
# attachment for A/B measurement.
# DEFAULT OFF until the ext2 root is readable over virtio -- see M2144. IDE is
# no longer the bottleneck it was (M2142 put writes on DMA, 108x per sector),
# so this is opt-in with VIRTIO=1 rather than the default.
if [ "${VIRTIO:-0}" = 1 ]; then
    EXT2_DRIVE="-drive file=$PVE_DIR/ext2.img,format=raw,if=virtio"
else
    EXT2_DRIVE="-drive file=$PVE_DIR/ext2.img,format=raw,if=ide,index=1"
fi
echo "==> configuring VM $VMID ($CORES cores, ${MEM}M, -append \"$APPEND\")..."
$SSH "qm set $VMID --memory $MEM --cores $CORES --args \
  \"-snapshot -kernel $PVE_DIR/kernel32.elf -append \\\"$APPEND\\\" \
    -drive file=$PVE_DIR/fat.img,format=raw,if=ide,index=0 \
    $EXT2_DRIVE\"" >/dev/null

echo "==> booting; capture detaches and runs for up to ${CAP}s..."
# setsid + nohup, NOT a background job in the ssh session (M2101). `socat &`
# inside `ssh bash -s` dies when ssh's stdin closes, which cut the first
# capture off at 30 lines -- and a truncated log is indistinguishable from a
# boot that stopped. Detach it properly, then poll the file.
$SSH "qm stop $VMID >/dev/null 2>&1; sleep 1; rm -f $PVE_DIR/boot.log; \
      qm start $VMID >/dev/null 2>&1; sleep 1; \
      setsid nohup timeout $CAP socat -u \
        UNIX-CONNECT:/var/run/qemu-server/$VMID.serial0 \
        OPEN:$PVE_DIR/boot.log,creat,trunc >/dev/null 2>&1 < /dev/null & \
      sleep 1; echo started" >/dev/null

echo "==> waiting for a marker (not for a duration)..."
i=0
while [ $i -lt "$CAP" ]; do
    if $SSH "grep -aqE 'it has PAINTED|OSDEV-BASH-OK|lxask] exit|FFSHOT-PNGEND|FFSHOT: no PNG|no Wayland client left|the process is GONE|KERNEL PANIC|desktop is taking over' $PVE_DIR/boot.log 2>/dev/null"; then break; fi
    sleep 2; i=$((i+2))
done
echo "==> marker after ~${i}s"
# Keep capturing past the marker: the boot budget prints at the DESKTOP
# handover, which is after the paint, and killing the capture at the paint
# threw away every number the run was made to produce. (M2103)
sleep 20
$SSH "echo '----- markers -----'; \
      grep -aE 'it has PAINTED|desktop window for client|KERNEL PANIC|Invalid Opcode|process is GONE|ata\] DMA' $PVE_DIR/boot.log | head -8; \
      echo '----- budget -----'; \
      grep -a -A 16 '\[budget\]' $PVE_DIR/boot.log | head -18"
echo "==> done. Full log: $PVE_HOST:$PVE_DIR/boot.log"
