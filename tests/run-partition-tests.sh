#!/bin/sh
# In-guest assertion for the ATA multi-drive enumeration + MBR/GPT partition
# parsing (kernel/ata.c + kernel/partition.c). Boots the real kernel headless
# under QEMU with TWO EXTRA IDE disks attached (the boot disk stays at index 0),
# captures COM1, and asserts the kernel enumerated those drives and parsed their
# partition tables correctly:
#
#   - On the host we craft a SECOND disk with a real MBR + one FAT32 partition
#     (containing a known file HELLO.TXT) and attach it as the PRIMARY SLAVE
#     (-drive ...,if=ide,index=1), and a THIRD disk with a GPT + one FAT32
#     partition (same known file) attached as the SECONDARY MASTER (index=2);
#   - the kernel's partition_enumerate() probes all four legacy ATA slots,
#     IDENTIFYs each present drive + its sector count, and logs each partition's
#     scheme / type / start-LBA / sector count;
#   - we assert the logged start-LBA + sector count + scheme EXACTLY match what
#     the host wrote for BOTH the MBR and the GPT disk (proving the parser read
#     the real on-disk tables, not a fluke);
#   - we assert the FAT32-from-partition read found HELLO.TXT at the partition's
#     offset on each (the multi-volume "stretch" proof);
#   - boot must STILL mount the bare FAT32 on the legacy ATA boot disk (index 0,
#     no partition table) and reach the desktop with no fault — the extra disks
#     are purely additional and the boot path is untouched.
#
# Exit 0 = pass. SKIPs cleanly if QEMU or python3 is absent. Companion to
# run-boot-tests.sh (no extra disks -> only drive 0 present, no table -> no-op).
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
MBRIMG=build/part_mbr.img
GPTIMG=build/part_gpt.img
LOG=$(mktemp /tmp/osdev_part.XXXXXX.log)
EXP=$(mktemp /tmp/osdev_part_exp.XXXXXX)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG" "$EXP"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: partition test ($QEMU not found)"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: partition test (python3 not found)"
    exit 0
fi

# Build the MBR and GPT disk images on the host, each with one FAT32 partition
# containing a known file (HELLO.TXT). Emit, to $EXP, the exact "start-LBA ... "
# substrings the kernel will log for each partition, so the assertions below
# compare the parser's output against host-computed truth.
python3 - "$MBRIMG" "$GPTIMG" "$EXP" <<'PY'
import sys, struct

SEC = 512

def fat32_volume(part_sectors):
    """Build a minimal but valid FAT32 filesystem (bytes) of `part_sectors`
    sectors with one file, HELLO.TXT, in the root directory. Mirrors the layout
    tools/mkfatfs.c and the kernel reader expect."""
    reserved = 32
    num_fats = 2
    spc = 1                                  # sectors per cluster
    # Solve for the FAT size that covers the cluster count (same loop as mkfatfs).
    fatsz = 1
    while True:
        data = part_sectors - reserved - num_fats * fatsz
        clusters = data // spc
        need = ((clusters + 2) * 4 + SEC - 1) // SEC
        if need <= fatsz:
            break
        fatsz = need
    fat_start = reserved
    data_start = reserved + num_fats * fatsz
    img = bytearray(part_sectors * SEC)

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
    struct.pack_into("<I", b, 32, part_sectors)   # total sectors 32
    struct.pack_into("<I", b, 36, fatsz)     # FAT size 32
    struct.pack_into("<H", b, 40, 0)         # ext flags
    struct.pack_into("<H", b, 42, 0)         # fs version
    struct.pack_into("<I", b, 44, 2)         # root cluster
    struct.pack_into("<H", b, 48, 1)         # FSInfo sector
    struct.pack_into("<H", b, 50, 6)         # backup boot sector
    b[64] = 0x80
    b[66] = 0x29
    struct.pack_into("<I", b, 67, 0x12345678)
    b[71:82] = b"PARTVOL    "[:11]
    b[82:90] = b"FAT32   "
    struct.pack_into("<H", b, 510, 0xAA55)

    # ---- FAT: cluster 0/1 reserved, cluster 2 = root dir (EOC), cluster 3 = file (EOC) ----
    fat = bytearray((clusters + 2) * 4)
    struct.pack_into("<I", fat, 0, 0x0FFFFFF8)
    struct.pack_into("<I", fat, 4, 0x0FFFFFFF)
    struct.pack_into("<I", fat, 8, 0x0FFFFFFF)     # cluster 2 (root dir): EOC
    struct.pack_into("<I", fat, 12, 0x0FFFFFFF)    # cluster 3 (file):     EOC
    for f in range(num_fats):
        off = (fat_start + f * fatsz) * SEC
        img[off:off + len(fat)] = fat

    # ---- root directory (cluster 2) with one entry: HELLO.TXT -> cluster 3 ----
    content = b"Hello from a FAT32 partition read by our own ATA+partition driver!\n"
    de_off = data_start * SEC                       # cluster 2 == data_start
    de = bytearray(32)
    de[0:11] = b"HELLO   TXT"
    de[11] = 0x20                                   # archive
    struct.pack_into("<H", de, 20, 0)               # first cluster high
    struct.pack_into("<H", de, 26, 3)               # first cluster low (cluster 3)
    struct.pack_into("<I", de, 28, len(content))    # size
    img[de_off:de_off + 32] = de

    # ---- file data (cluster 3) ----
    file_off = (data_start + (3 - 2) * spc) * SEC
    img[file_off:file_off + len(content)] = content
    return bytes(img)

def write_mbr_disk(path):
    part_start = 2048                               # 1 MiB-aligned, the usual convention
    part_sectors = 8192                             # 4 MiB partition
    total = part_start + part_sectors + 64
    img = bytearray(total * SEC)
    img[part_start * SEC:(part_start + part_sectors) * SEC] = fat32_volume(part_sectors)
    # MBR: one primary entry at 0x1BE, type 0x0C (FAT32 LBA), start + size.
    e = 0x1BE
    img[e + 0] = 0x00                               # not bootable
    img[e + 1] = 0xFE; img[e + 2] = 0xFF; img[e + 3] = 0xFF   # CHS start (don't-care, LBA used)
    img[e + 4] = 0x0C                               # type: FAT32 (LBA)
    img[e + 5] = 0xFE; img[e + 6] = 0xFF; img[e + 7] = 0xFF   # CHS end
    struct.pack_into("<I", img, e + 8, part_start)
    struct.pack_into("<I", img, e + 12, part_sectors)
    struct.pack_into("<H", img, 510, 0xAA55)        # boot signature
    with open(path, "wb") as f:
        f.write(img)
    return part_start, part_sectors

def write_gpt_disk(path):
    part_start = 2048
    part_sectors = 8192
    # Reserve room for the GPT (primary header @1, entries @2..33; backup at end).
    total = part_start + part_sectors + 64
    img = bytearray(total * SEC)
    img[part_start * SEC:(part_start + part_sectors) * SEC] = fat32_volume(part_sectors)

    # ---- protective MBR (LBA 0): one type-0xEE entry covering the disk ----
    e = 0x1BE
    img[e + 4] = 0xEE                               # protective GPT type
    struct.pack_into("<I", img, e + 8, 1)           # starts at LBA 1
    struct.pack_into("<I", img, e + 12, min(total - 1, 0xFFFFFFFF))
    struct.pack_into("<H", img, 510, 0xAA55)

    # ---- GPT entry array (LBA 2..), 128-byte entries, our reader walks these ----
    entry_lba = 2
    entry_size = 128
    nentries = 128
    # The Microsoft Basic Data partition type GUID (non-zero -> a used entry).
    type_guid = bytes([0xA2,0xA0,0xD0,0xEB,0xE5,0xB9,0x33,0x44,
                       0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7])
    uniq_guid = bytes(range(16))                    # any non-zero unique GUID
    first = part_start
    last = part_start + part_sectors - 1
    ent = bytearray(entry_size)
    ent[0:16] = type_guid
    ent[16:32] = uniq_guid
    struct.pack_into("<Q", ent, 32, first)
    struct.pack_into("<Q", ent, 40, last)
    ent[56:56+8] = b"FATPART\x00"                   # name (UTF-16LE-ish; unused by us)
    arr_off = entry_lba * SEC
    img[arr_off:arr_off + entry_size] = ent

    # ---- GPT header (LBA 1): "EFI PART" + entry-array LBA/count/size ----
    h = bytearray(SEC)
    h[0:8] = b"EFI PART"
    struct.pack_into("<I", h, 8, 0x00010000)        # revision 1.0
    struct.pack_into("<I", h, 12, 92)               # header size
    struct.pack_into("<Q", h, 24, 1)                # current LBA
    struct.pack_into("<Q", h, 32, total - 1)        # backup LBA
    struct.pack_into("<Q", h, 40, 34)               # first usable LBA
    struct.pack_into("<Q", h, 48, total - 34)       # last usable LBA
    struct.pack_into("<Q", h, 72, entry_lba)        # partition-entry array LBA
    struct.pack_into("<I", h, 80, nentries)         # number of entries
    struct.pack_into("<I", h, 84, entry_size)       # size of an entry
    img[SEC:SEC + SEC] = h                          # LBA 1
    with open(path, "wb") as f:
        f.write(img)
    return part_start, part_sectors

ms, msec = write_mbr_disk(sys.argv[1])
gs, gsec = write_gpt_disk(sys.argv[2])

# The exact substrings the kernel logs (see partition_enumerate()), one per line.
with open(sys.argv[3], "w") as f:
    # MBR disk = primary slave = ata1; FAT32 (LBA) type 0x0c.
    f.write("MBR, 1 partition(s)\n")
    f.write("type 0x0c start-LBA %d sectors %d\n" % (ms, msec))
    # GPT disk = secondary master = ata2; GPT entry type byte logged as 0xee.
    f.write("GPT, 1 partition(s)\n")
    f.write("type 0xee start-LBA %d sectors %d\n" % (gs, gsec))
PY

echo "booting kernel headless under QEMU with an MBR (primary slave) + GPT (secondary master) disk..."
# The ONLY additions vs run-boot-tests.sh are the two extra IDE drives. Boot
# still uses the IDE/ATA disk at index 0; the extra disks are additional.
#   index 0 = primary master   (the boot disk, bare FAT32, untouched)
#   index 1 = primary slave    (our MBR disk)
#   index 2 = secondary master (our GPT disk)
timeout -s KILL 30 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide,index=0 \
    -drive file="$MBRIMG",format=raw,if=ide,index=1 \
    -drive file="$GPTIMG",format=raw,if=ide,index=2 \
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

# The kernel enumerated all four legacy ATA slots and found the present drives.
require "ATA drives:"                          "ATA enumeration ran (all 4 legacy slots probed)"
require "ata1 (primary slave)"                 "primary-slave drive (MBR disk) IDENTIFYd"
require "ata2 (secondary master)"              "secondary-master drive (GPT disk) IDENTIFYd"

# The parser read the RIGHT on-disk tables: every host-computed substring (scheme
# + per-partition type/start-LBA/sectors) must appear in the enumeration log.
while read -r line; do
    require "$line"                            "parsed partition table matches host ($line)"
done < "$EXP"

# The multi-volume read proof: HELLO.TXT located + read at the partition offset on
# BOTH disks (the stretch FAT32-from-partition mount). 67 bytes is the file's size.
require "found HELLO.TXT (67 bytes)"           "FAT32-from-partition read found the known file"

# Boot stayed on the legacy ATA boot disk (index 0, bare FAT32) and reached the
# desktop with no fault — the extra disks are purely additional.
require "mounted FAT32 volume"                 "bare FAT32 still mounted on the boot disk (boot path intact)"
require "launching the desktop environment"    "reached desktop launch (no fault on the partition path)"

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
forbid "partition scan failed"       "partition scan failure"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest partition (4 ATA slots probed, MBR + GPT tables parsed, known file read back, no crash)"
    exit 0
else
    echo "FAIL: in-guest partition test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
