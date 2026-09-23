#!/bin/bash
# tools/pve-stage.sh -- put a fresh build on a Proxmox node WITHOUT shipping a
# disk image from the laptop (M2382).
#
#   PVE_HOST=192.168.1.6 PVE_DIR=/root/osdev tools/pve-stage.sh
#
# Before this, every deploy rsynced build/ext2.img -- 4.6 GB, regenerated on
# every kernel edit because the source tree is staged into it -- from the
# laptop over tailscale. The user said not to stage on the laptop. Now:
#
#   laptop  --(per-file delta, -z)---->  TrueNAS  $STAGE/lxroot
#   TrueNAS --(LAN, owner fixed)------>  node     $MIRROR
#   node:   mke2fs $(MKE2FS_FLAGS) -d $MIRROR  ->  $PVE_DIR/ext2.img
#
# A source edit moves kilobytes off the laptop. The image is built on the
# node's own disk, where the VM reads it.
#
# WHY A SECOND MIRROR ON THE NODE: the TrueNAS export squashes root, so every
# file there is owned by 65534 and chown is refused -- and mke2fs -d records
# the source file's owner. Built straight from NFS, /src would be owned by
# nobody and git's dubious-ownership check would refuse the repo that Claude
# Code works in. The node's local mirror is chowned back to 1000:1000, which
# is what the laptop build has always recorded.
#
# WHY IT CAN SKIP THE BUILD: the VM boots the image with -snapshot, so a guest
# never writes it. If the mirror did not change and the last build finished,
# the image on disk IS the image this build would make. Without -snapshot in
# the VM's args that stops being true, so the skip is refused.
set -e
set -o pipefail
cd "$(dirname "$0")/.."

PVE_HOST=${PVE_HOST:?PVE_HOST not set}
PVE_DIR=${PVE_DIR:-/root/osdev}
VMID=${VMID:-}
STAGE=${OSDEV_STAGE:-/mnt/pve/truenas-nfs/osdev-stage}
MIRROR=${OSDEV_MIRROR:-/root/osdev-lxroot}
SSH="ssh -o BatchMode=yes root@$PVE_HOST"

FLAGS=$(make -s print-MKE2FS_FLAGS)
SIZE=$(make -s print-EXT2SIZE | tr -d ' \t')
[ -n "$FLAGS" ] && [ -n "$SIZE" ] || { echo "FATAL: could not read MKE2FS_FLAGS/EXT2SIZE from the Makefile" >&2; exit 1; }
[ -d build/lxroot ] || { echo "FATAL: build/lxroot missing -- run 'make lxroot-ready'" >&2; exit 1; }

$SSH "mountpoint -q /mnt/pve/truenas-nfs" || { echo "FATAL: TrueNAS is not mounted on $PVE_HOST" >&2; exit 1; }
# $STAGE is private; $MIRROR lives under /root, which already is. Neither
# lxroot directory itself is chmod'ed: rsync copies build/lxroot's own mode
# onto it, and that is the mode mke2fs -d gives the image's root.
$SSH "mkdir -p '$STAGE/lxroot' '$MIRROR' '$PVE_DIR' && chmod 700 '$STAGE'"

echo "==> laptop -> TrueNAS: lxroot delta..."
T0=$(date +%s)
# --no-owner/--no-group: the export refuses chown, and rsync would otherwise
# report every file as an error. Ownership is restored on the node below.
# A FAILED COPY MUST NOT READ AS AN EMPTY DELTA. The first version piped
# rsync into `grep -c ... || true`, which swallowed rsync's exit status: an
# unsupported --compress-choice failed the copy outright, the script reported
# "0 file(s) sent", and the node built an EMPTY 4.6 GB image and marked it
# good. The same defect as M2330's stale boot.log, and it was mine again.
LOG=$(mktemp); trap 'rm -f "$LOG"' EXIT
rsync -rlptH --delete --no-owner --no-group -z \
      --out-format='%i %n' build/lxroot/ "root@$PVE_HOST:$STAGE/lxroot/" >"$LOG" \
    || { echo "FATAL: laptop -> TrueNAS copy failed (rsync exit $?)" >&2; exit 1; }
N_UP=$(grep -vc '^\.d' "$LOG" || true)
rsync -t --whole-file build/kernel32.elf build/fat.img "root@$PVE_HOST:$STAGE/"
echo "    $N_UP file(s) sent in $(( $(date +%s) - T0 ))s"

echo "==> TrueNAS -> $PVE_HOST: mirror + image..."
# ssh joins its arguments with spaces, so an EMPTY one vanishes and shifts
# everything after it -- VMID travels as "none" rather than as "".
$SSH bash -s -- "$STAGE" "$MIRROR" "$PVE_DIR" "$SIZE" "${VMID:-none}" "$FLAGS" <<'NODE'
set -e -o pipefail
STAGE=$1 MIRROR=$2 DIR=$3 SIZE=$4 VMID=$5; shift 5; FLAGS=$*
cp -f "$STAGE/kernel32.elf" "$STAGE/fat.img" "$DIR/"
# Counted with %i so a DELETION counts too ("*deleting"); a bare directory
# timestamp update (".d") is the only line that is not a content change.
L=$(mktemp); trap 'rm -f "$L"' EXIT
rsync -aH --delete --chown=1000:1000 --out-format='%i %n' "$STAGE/lxroot/" "$MIRROR/" >"$L" \
    || { echo "FATAL: TrueNAS -> node mirror failed (rsync exit $?)" >&2; exit 1; }
N=$(grep -vc '^\.d' "$L" || true)
# NEVER BUILD FROM A MIRROR THAT CANNOT BE THE ROOT FILESYSTEM. An empty
# mirror makes a perfectly valid, perfectly empty ext2 -- which boots, and
# fails later as "Firefox not found", nowhere near the cause.
NF=$(find "$MIRROR" -xdev -type f | wc -l)
if [ ! -d "$MIRROR/usr/bin" ] || [ "$NF" -lt 1000 ]; then
    echo "FATAL: the mirror holds $NF files and no usable /usr/bin -- refusing to build an image from it" >&2
    exit 1
fi
SNAP=1
if [ "$VMID" != none ] && ! qm config "$VMID" 2>/dev/null | grep -q -- '-snapshot'; then SNAP=0; fi
if [ "$N" = 0 ] && [ "$SNAP" = 1 ] && [ -f "$DIR/.ext2-built" ] && [ -s "$DIR/ext2.img" ]; then
    echo "    mirror unchanged and the VM boots -snapshot: reusing $DIR/ext2.img"
    exit 0
fi
[ "$SNAP" = 1 ] || echo "    VM $VMID has no -snapshot: the guest writes its image, so rebuilding"
rm -f "$DIR/.ext2-built" "$DIR/ext2.img.new"
T0=$(date +%s)
truncate -s "$SIZE" "$DIR/ext2.img.new"
mke2fs $FLAGS -d "$MIRROR" "$DIR/ext2.img.new" >/dev/null
# A FULL IMAGE MUST SAY SO AT BUILD TIME (M2305) -- the same guard the
# Makefile applies, because this is now where the image is made.
FREE=$(dumpe2fs -h "$DIR/ext2.img.new" 2>/dev/null | awk -F: '/^Free blocks/{gsub(/ /,"",$2); print $2}')
MB=$(( FREE * 4096 / 1048576 ))
if [ "$MB" -lt 500 ]; then
    echo "FATAL: the image has $MB MB free before the guest has written a byte -- raise EXT2SIZE" >&2
    exit 1
fi
mv -f "$DIR/ext2.img.new" "$DIR/ext2.img"
touch "$DIR/.ext2-built"
echo "    $N file(s) changed; built ext2.img ($SIZE, $MB MB free) in $(( $(date +%s) - T0 ))s"
NODE
