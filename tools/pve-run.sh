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
# BOOT TO THE DESKTOP. A hard rule (the user's): "we should almost always be
# booting to desktop as there's no reason not to." Since M2214 `ffwl` hands the
# framebuffer to the window manager as soon as Firefox is spawned and runs its
# diagnostics on a watcher thread -- console output is serial-only once the WM
# owns the screen, so the log this harness captures is unchanged. `ffhold` is
# the escape hatch for a boot that dies before the desktop starts.
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

# PROVE THE NODE IS RUNNING WHAT WAS JUST BUILT (M2156).
#
# rsync's quick check is size + mtime, and a kernel rebuild can land on the
# same size -- so a deploy can silently transfer nothing. That happened, and
# the cost was two full 8-core Firefox runs whose logs were BYTE-IDENTICAL,
# including a line my newest fix had specifically changed. I read that
# identical output as "the fix did not work" and started looking for a second
# bug. A measurement against an unknown binary is not a measurement.
#
# So compare the digests and stop if they differ. This is the same trap as the
# stale boot.log, one layer down.
echo "==> verifying the node has the kernel that was just built..."
LOCAL_MD5=$(md5sum build/kernel32.elf | cut -d' ' -f1)
REMOTE_MD5=$($SSH "md5sum $PVE_DIR/kernel32.elf 2>/dev/null | cut -d' ' -f1")
if [ "$LOCAL_MD5" != "$REMOTE_MD5" ]; then
    echo "    digests differ ($LOCAL_MD5 local, $REMOTE_MD5 remote) -- forcing a whole-file copy"
    rsync -a --whole-file build/kernel32.elf "root@$PVE_HOST:$PVE_DIR/"
    REMOTE_MD5=$($SSH "md5sum $PVE_DIR/kernel32.elf 2>/dev/null | cut -d' ' -f1")
fi
if [ "$LOCAL_MD5" != "$REMOTE_MD5" ]; then
    echo "FATAL: $PVE_HOST:$PVE_DIR/kernel32.elf is still not the local build." >&2
    echo "       Refusing to run: whatever this measured would not be this code." >&2
    exit 1
fi
echo "    ok: $LOCAL_MD5"

# RECORD WHICH BINARY THIS RUN USED (M2191).
#
# A measurement series is only a series if every run used the SAME build, and
# nothing enforced that. Rebuilding while a series was in flight -- which is the
# obvious thing to do when the runs take ten minutes each and there is other
# work to get on with -- silently split one four-boot series across two kernels.
# The later boots then lacked an instrument the earlier ones had, their logs
# showed no output from it, and I read that absence as a finding about Firefox.
#
# The digest guard above proves the NODE has what was just built. This proves
# what "just built" WAS, in the log itself, so a series can be checked for
# uniformity after the fact instead of trusted.
$SSH "printf '[harness] kernel md5 %s appended %s\n' '$LOCAL_MD5' '$APPEND' >> $PVE_DIR/harness.log" >/dev/null 2>&1 || true
export OSDEV_RUN_MD5="$LOCAL_MD5"

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

# EQUAL WINDOWS, OR IT IS NOT A SERIES (WAIT=full, M2214).
#
# Breaking on the first marker gives a run that SUCCEEDS a shorter observation
# window than one that fails -- a rendering boot stops ~20s after the page and a
# blank one runs the whole CAP -- so every other per-run count in a series is
# then compared across unequal windows. That cost me a correlation once already
# (M2203). Measurement wants WAIT=full; a human watching wants the marker.
if [ "${WAIT:-marker}" = full ]; then
    echo "==> waiting out the FULL ${CAP}s window (WAIT=full: equal windows across runs)"
    sleep "$CAP"
    i=$CAP
else
echo "==> waiting for a marker (not for a duration)..."
i=0
while [ $i -lt "$CAP" ]; do
    # 'desktop is taking over' IS NO LONGER A COMPLETION MARKER (M2214).
    #
    # It used to be the last line of a boot, so waiting for it meant "the run is
    # over". Booting to the desktop is the rule now, so it prints in the first
    # second -- and leaving it in this list would have ended every capture
    # twenty-five seconds into a run whose subject paints at thirty-six. That is
    # the trap M1911 wrote down: a completion detector must key on a marker
    # printed on every exit path AND on no other.
    #
    # What ends a Firefox run: the page appeared, the process died, or the
    # watcher ran out of window. A blank boot matches none of them and waits out
    # the full CAP, which is exactly what a measurement of a blank boot needs.
    if $SSH "grep -aqE 'PAGE ON SCREEN|OSDEV-BASH-OK|lxask] exit|FFSHOT-PNGEND|FFSHOT: no PNG|no Wayland client left|the process is GONE|CRASHED with signal|KERNEL PANIC|the watcher has finished its window' $PVE_DIR/boot.log 2>/dev/null"; then break; fi
    sleep 2; i=$((i+2))
done
fi
echo "==> waited ~${i}s"
# Keep capturing past the marker: the boot budget prints at the DESKTOP
# handover, which is after the paint, and killing the capture at the paint
# threw away every number the run was made to produce. (M2103)
sleep 20
$SSH "echo '----- markers -----'; \
      grep -aE 'it has PAINTED|desktop window for client|KERNEL PANIC|Invalid Opcode|process is GONE|ata\] DMA' $PVE_DIR/boot.log | head -8; \
      echo '----- budget -----'; \
      grep -a -A 16 '\[budget\]' $PVE_DIR/boot.log | head -18"
echo "==> done. Full log: $PVE_HOST:$PVE_DIR/boot.log"
