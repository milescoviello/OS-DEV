#!/bin/sh
# In-guest assertion for the generic block-device layer + read-only multi-volume
# FAT32 browsing over ALL storage drivers (kernel/blockdev.c + the generalized
# fatvol_list/fatvol_find in kernel/partition.c). Boots the real kernel headless
# under QEMU with a SECOND disk attached over LEGACY virtio-blk
# (-device virtio-blk-pci,disable-modern=on,disable-legacy=off) whose CONTENT is a
# bare FAT32 filesystem holding KNOWN files, captures COM1, and asserts that
# blockdev_enumerate():
#
#   - registered the virtio-blk device into the block-device registry, AND
#   - MOUNTED its bare FAT32 volume read-only (at start-LBA 0), AND
#   - LISTED its root directory with the KNOWN files (names + sizes) the host wrote
#     plus the known subdirectory (marked as a dir).
#
# We build, on the host, a real FAT32 volume (same layout the kernel reader +
# tools/mkfatfs expect) with: GREET.TXT, NUMBERS.DAT, and a subdirectory SUBDIR.
# The kernel logs each root entry as "<NAME>  (<size> bytes)" / "<NAME>/  (dir)";
# we assert those exact substrings appear -> the FAT walk read the real on-disk
# directory over the virtio-blk driver, not a fluke.
#
# The boot disk stays on legacy ATA (index 0, bare FAT32, no table) and must still
# mount + reach the desktop with no fault -- the virtio disk is purely additional
# and blockdev.c is read-only. Exit 0 = pass. SKIPs cleanly if QEMU or python3 is
# absent. Companion to run-boot-tests.sh (no extra disk -> only the ATA boot disk
# is registered, which IS browsable -> a clean listing, no crash).
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
IMG=build/blockdev_test.img
LOG=$(mktemp /tmp/osdev_blockdev.XXXXXX.log)
EXP=$(mktemp /tmp/osdev_blockdev_exp.XXXXXX)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG" "$EXP"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: blockdev test ($QEMU not found)"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: blockdev test (python3 not found)"
    exit 0
fi

# Build a bare FAT32 disk image (no partition table) holding known root entries,
# and emit to $EXP the exact substrings blockdev_enumerate() will log for each.
python3 - "$IMG" "$EXP" <<'PY'
import sys, struct

SEC = 512

def build_fat32(total_sectors, files, subdirs):
    """A minimal but valid FAT32 filesystem of `total_sectors` sectors.
    `files`   = list of (NAME83(11 bytes), content bytes).
    `subdirs` = list of NAME83(11 bytes) (empty dirs, just "." / "..").
    Clusters are laid out: 2 = root dir, then one cluster per file/subdir in order.
    Mirrors tools/mkfatfs.c and the kernel reader's expectations (spc=1)."""
    reserved = 32
    num_fats = 2
    spc = 1
    fatsz = 1
    while True:
        data = total_sectors - reserved - num_fats * fatsz
        clusters = data // spc
        need = ((clusters + 2) * 4 + SEC - 1) // SEC
        if need <= fatsz:
            break
        fatsz = need
    fat_start = reserved
    data_start = reserved + num_fats * fatsz
    img = bytearray(total_sectors * SEC)

    # ---- boot sector / BPB ----
    b = img
    b[0:3] = bytes([0xEB, 0x58, 0x90])
    b[3:11] = b"OSDEV1.0"
    struct.pack_into("<H", b, 11, SEC)       # bytes/sector
    b[13] = spc                              # sectors/cluster
    struct.pack_into("<H", b, 14, reserved)  # reserved sectors
    b[16] = num_fats
    struct.pack_into("<H", b, 17, 0)         # root entries (0 on FAT32)
    struct.pack_into("<H", b, 19, 0)         # total16 (0 -> total32)
    b[21] = 0xF8                             # media
    struct.pack_into("<H", b, 22, 0)         # FAT16 size (0)
    struct.pack_into("<H", b, 24, 32)        # sectors/track
    struct.pack_into("<H", b, 26, 2)         # heads
    struct.pack_into("<I", b, 28, 0)         # hidden sectors
    struct.pack_into("<I", b, 32, total_sectors)  # total sectors 32
    struct.pack_into("<I", b, 36, fatsz)     # FAT size 32
    struct.pack_into("<H", b, 40, 0)         # ext flags
    struct.pack_into("<H", b, 42, 0)         # fs version
    struct.pack_into("<I", b, 44, 2)         # root cluster
    struct.pack_into("<H", b, 48, 1)         # FSInfo sector
    struct.pack_into("<H", b, 50, 6)         # backup boot sector
    b[64] = 0x80
    b[66] = 0x29
    struct.pack_into("<I", b, 67, 0x1A2B3C4D)
    b[71:82] = b"BLOCKVOL   "[:11]
    b[82:90] = b"FAT32   "
    struct.pack_into("<H", b, 510, 0xAA55)

    # ---- assign clusters: 2 = root, then one per file, then one per subdir ----
    entries = []   # (name83, attr, first_cluster, size)
    next_cl = 3
    file_clusters = []   # (cluster, content)
    for name83, content in files:
        entries.append((name83, 0x20, next_cl, len(content)))
        file_clusters.append((next_cl, content))
        next_cl += 1
    subdir_clusters = []  # cluster
    for name83 in subdirs:
        entries.append((name83, 0x10, next_cl, 0))
        subdir_clusters.append(next_cl)
        next_cl += 1
    max_cl = next_cl  # exclusive

    # ---- FAT: 0/1 reserved; every used cluster (root + each file/subdir) = EOC ----
    fat = bytearray((clusters + 2) * 4)
    struct.pack_into("<I", fat, 0, 0x0FFFFFF8)
    struct.pack_into("<I", fat, 4, 0x0FFFFFFF)
    for cl in range(2, max_cl):
        struct.pack_into("<I", fat, cl * 4, 0x0FFFFFFF)
    for f in range(num_fats):
        off = (fat_start + f * fatsz) * SEC
        img[off:off + len(fat)] = fat

    # ---- root directory (cluster 2): the file + subdir entries ----
    root_off = data_start * SEC
    o = 0
    for name83, attr, first, size in entries:
        de = bytearray(32)
        de[0:11] = name83
        de[11] = attr
        struct.pack_into("<H", de, 20, (first >> 16) & 0xFFFF)  # first cluster high
        struct.pack_into("<H", de, 26, first & 0xFFFF)          # first cluster low
        struct.pack_into("<I", de, 28, size)                    # size
        img[root_off + o:root_off + o + 32] = de
        o += 32

    # ---- file data ----
    for cl, content in file_clusters:
        foff = (data_start + (cl - 2) * spc) * SEC
        img[foff:foff + len(content)] = content

    # ---- each subdir cluster: "." and ".." (rest zero = empty dir) ----
    for cl in subdir_clusters:
        soff = (data_start + (cl - 2) * spc) * SEC
        d = bytearray(64)
        for i in range(11):
            d[i] = 0x20; d[32 + i] = 0x20
        d[0] = ord('.'); d[11] = 0x10
        struct.pack_into("<H", d, 20, (cl >> 16) & 0xFFFF)
        struct.pack_into("<H", d, 26, cl & 0xFFFF)
        d[32] = ord('.'); d[33] = ord('.'); d[43] = 0x10        # ".." -> parent (root = 0)
        img[soff:soff + 64] = d

    return bytes(img)

# Known content: two files (distinct names + sizes) and one subdirectory.
greet = b"Hello from a bare FAT32 volume browsed over virtio-blk by blockdev.c!\n"
nums  = bytes(range(200))                    # 200 deterministic bytes
files = [
    (b"GREET   TXT", greet),
    (b"NUMBERS DAT", nums),
]
subdirs = [ b"SUBDIR     " ]

total_sectors = 4096                         # 2 MiB disk, plenty for the above
img = build_fat32(total_sectors, files, subdirs)
with open(sys.argv[1], "wb") as f:
    f.write(img)

# The exact substrings blockdev_enumerate() logs (one per line). The reader
# formats an 8.3 name "NAME    EXT" as "NAME.EXT"; a subdir prints "<NAME>/  (dir)".
with open(sys.argv[2], "w") as f:
    f.write("virtio-blk\n")                                    # device registered
    f.write("FAT32 volume mounted (read-only) at start-LBA 0\n")
    f.write("GREET.TXT  (%d bytes)\n" % len(greet))
    f.write("NUMBERS.DAT  (%d bytes)\n" % len(nums))
    f.write("SUBDIR/  (dir)\n")
PY

echo "booting kernel headless under QEMU with a virtio-blk FAT32 second disk (COM1 capture)..."
# The ONLY additions vs run-boot-tests.sh are the second drive + virtio-blk-pci
# (legacy mode). Boot still uses the IDE/ATA disk; virtio-blk is additional.
timeout -s KILL 30 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -drive id=vd1,file="$IMG",format=raw,if=none \
    -device virtio-blk-pci,drive=vd1,disable-modern=on,disable-legacy=off \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -device AC97,audiodev=snd0 -audiodev none,id=snd0 \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 60 ]; do
    grep -q "launching the desktop" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

fail=0
require() {
    if grep -qiF "$1" "$LOG"; then
        echo "  ok: $2"
    else
        echo "  MISSING: $2  (expected substring: '$1')"
        fail=1
    fi
}

# The generic block-device layer came up and registered devices.
require "block devices:"                       "block-device registry enumerated"
require "blockdev browse:"                      "blockdev browse summary printed"

# Every host-computed substring (the registered virtio-blk device, the mounted
# FAT32 volume at LBA 0, and each known root entry name + size) must appear -> the
# FAT walk read the real on-disk directory over the virtio-blk driver.
while read -r line; do
    require "$line"                            "blockdev listing matches host ($line)"
done < "$EXP"

# Boot stayed on legacy ATA (index 0, bare FAT32) and reached the desktop, no fault
# -- the virtio disk is purely additional and blockdev.c is read-only.
require "mounted FAT32 volume"                 "bare FAT32 still mounted on the boot disk (boot path intact)"
require "launching the desktop environment"    "reached desktop launch (no fault on the blockdev path)"

forbid() {
    if grep -qiE "$1" "$LOG"; then
        echo "  CRASH MARKER: $2"
        grep -inE "$1" "$LOG" | head -3 | sed 's/^/      /'
        fail=1
    fi
}
forbid "panic"                       "kernel panic"
forbid "unhandled (interrupt|excep)" "unhandled exception"
forbid "page fault"                  "page fault"
forbid "general protection"          "#GP fault"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest blockdev (virtio-blk registered, bare FAT32 mounted + root listed, no crash)"
    exit 0
else
    echo "FAIL: in-guest blockdev test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
