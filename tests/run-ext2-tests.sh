#!/bin/sh
# Build the from-scratch ext2 read path for the host with ASan+UBSan and fuzz it
# against corrupt on-disk metadata. ext2_test.c #includes ext2.c (device-agnostic
# via blk_read_fn) and serves an in-memory image. A real golden image is built
# with mke2fs (+ debugfs to add a small file and a >12KB file so the read path
# walks single/double-indirect blocks); the test then fuzzes corrupted copies of
# the superblock/group-descriptor/inode-table region. A corrupt superblock, bad
# block_size/inode-count, or a cyclic/huge indirect chain must never OOB or hang.
# Exit 0 = pass.
set -e
cd "$(dirname "$0")/.."
CC=${CC:-gcc}
SAN="-fsanitize=address,undefined -fno-sanitize-recover=all"
G=/tmp/osdev_ext2_golden.img

if ! command -v mke2fs >/dev/null 2>&1 || ! command -v debugfs >/dev/null 2>&1; then
    echo "SKIP: ext2test (mke2fs/debugfs not on host)"; exit 0
fi

echo "building golden ext2 image (mke2fs + a big file for indirect blocks)..."
rm -f "$G"
# plain ext2: no resize_inode/dir_index(HTree)/ext_attr/journal — matches what ext2.c reads
mke2fs -F -q -b 1024 -O ^resize_inode,^dir_index,^ext_attr,^has_journal "$G" 2048 >/dev/null 2>&1
printf 'hello ext2 fuzz harness\n' > /tmp/osdev_ext2_small.txt
head -c 300000 /dev/zero | tr '\0' 'A' > /tmp/osdev_ext2_big.txt    # 300 KB -> direct + single + double indirect
debugfs -w -R "write /tmp/osdev_ext2_small.txt HELLO" "$G" >/dev/null 2>&1
debugfs -w -R "write /tmp/osdev_ext2_big.txt BIG"      "$G" >/dev/null 2>&1

# M1186: a second image with the ext4 `extent` feature, populated from a directory
# (mke2fs -d allocates extent-mapped files), to verify + fuzz the extent read path.
# Kept ext2-compatible otherwise (no 64bit/flex_bg/metadata_csum/journal) and small
# enough to fit the harness's 2 MiB in-memory disk.
X=/tmp/osdev_ext2_extent.img
rm -rf /tmp/osdev_ext_src; mkdir -p /tmp/osdev_ext_src
head -c 100000 /dev/zero | tr '\0' 'E' > /tmp/osdev_ext_src/BIG.TXT       # 100 KB -> one big extent
printf 'hello extent world\n' > /tmp/osdev_ext_src/SMALL.TXT
EXTOK=
if mke2fs -F -q -b 1024 -I 256 -O extent,^resize_inode,^dir_index,^has_journal,^64bit,^metadata_csum \
        -d /tmp/osdev_ext_src "$X" 1800 >/dev/null 2>&1; then EXTOK="$X"; fi

# M1933: an image with plenty of INODES but ordinary size, for the
# directory-growth test — 600 tiny files in one directory needs ~600 inodes,
# far more than the default bytes-per-inode ratio gives a 2 MiB volume.
D=/tmp/osdev_ext2_dirgrow.img
rm -f "$D"
DIRGROW=
if mke2fs -F -q -b 1024 -N 800 -O ^resize_inode,^dir_index,^ext_attr,^has_journal "$D" 2048 >/dev/null 2>&1; then
    DIRGROW="$D"
fi

echo "building host ext2 read path (ASan+UBSan)..."
$CC -std=gnu11 -O1 $SAN -fno-stack-protector -Ikernel -Ikernel/include \
    tests/ext2/ext2_test.c -o /tmp/osdev_ext2_test

echo "running ext2 corrupt-image fuzz (+ ext4 extent read/write/fuzz)..."
XW=/tmp/osdev_ext2_extent_written.img
[ -n "$EXTOK" ] && WARG="$XW" || WARG=
DW=/tmp/osdev_ext2_dirgrow_written.img
[ -n "$DIRGROW" ] && DWARG="$DW" || DWARG=
# Args are POSITIONAL, so pass every slot quoted even when empty — an unquoted
# empty would shift the later images into the wrong argv index. The test opens
# each by name and skips the block when fopen fails, so "" == "not supplied".
if timeout 180 /tmp/osdev_ext2_test "$G" "$EXTOK" "$WARG" "$DIRGROW" "$DWARG"; then
    echo "PASS: ext2.c read path (ASan/UBSan clean on corrupt-metadata fuzz + extent reads)"
else
    echo "FAIL: ext2.c test aborted (ASan/UBSan caught a memory error, or it hung)"; exit 1
fi

# M1189: the driver-written extent image must be e2fsck-clean and debugfs must
# see /EXTW.TXT as an EXTENT inode (not indirect) — proves the write is spec-correct.
if [ -n "$EXTOK" ] && [ -f "$XW" ]; then
    if ! e2fsck -fn "$XW" >/tmp/osdev_ext2_extw_fsck.log 2>&1; then
        echo "FAIL: e2fsck found errors in the driver-written extent image:"; cat /tmp/osdev_ext2_extw_fsck.log; exit 1
    fi
    if debugfs -R "stat /EXTW.TXT" "$XW" 2>/dev/null | grep -qi 'EXTENTS'; then
        echo "PASS: ext4 extent WRITE (driver-created /EXTW.TXT is an EXTENT inode; e2fsck clean)"
    else
        echo "FAIL: driver-written /EXTW.TXT is not extent-mapped"; exit 1
    fi
fi

# M1933: the grown directory must be SPEC-correct, not just readable by us.
# e2fsck is the independent judge: it validates every appended directory block,
# the record chain, i_size vs i_blocks, and the block bitmap accounting.
if [ -n "$DIRGROW" ] && [ -f "$DW" ]; then
    if ! e2fsck -fn "$DW" >/tmp/osdev_ext2_dirgrow_fsck.log 2>&1; then
        echo "FAIL: e2fsck found errors in the grown-directory image:"; cat /tmp/osdev_ext2_dirgrow_fsck.log; exit 1
    fi
    echo "PASS: grown multi-block directory is e2fsck-clean"
fi
