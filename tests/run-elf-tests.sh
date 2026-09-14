#!/bin/sh
# Build the from-scratch ELF64 loader for the host with ASan+UBSan and run the
# regression + fuzz test. Confirms the loader validates untrusted ELF images
# (the ring-3 boundary) against the image size and the user address range so a
# malformed program can never out-of-bounds read or escape its range, and that
# a well-formed image still loads correctly. Exit 0 = pass.
set -e
cd "$(dirname "$0")/.."
CC=${CC:-gcc}
SAN="-fsanitize=address,undefined -fno-sanitize-recover=all"
echo "building host ELF loader (ASan+UBSan)..."
$CC -std=gnu11 -O1 -g $SAN -fno-stack-protector -Ikernel -Ikernel/include \
    tests/elf/elf_test.c -o /tmp/osdev_elf_test
echo "running ELF-loader regression + fuzz..."
# If the app binaries have been built, also load every shipped ELF through the
# loader as a regression guard (the test runs the synthetic suite either way).
# Exclude every KERNEL image, not two of them by name. The list used to name
# build/kernel.elf and build/kernel32.elf and so let build/kernel_pass1.elf (an
# intermediate link) through, where it passed only because the kernel happened
# to be linked at 1 MiB and therefore looked like a user binary. Since M1968 it
# is linked at 0xFFFFFFFF80100000 and elf_load REJECTS it -- correctly: a kernel
# image is not a user program, and this check is "every app the OS ships stays
# loadable".
REAL=""
for e in build/*.elf; do
    # ...and selfbuilt-kernel32.elf, the kernel OS-DEV builds INSIDE ITSELF
    # (M2006). Same reasoning, but the name does not start with "kernel", so
    # the pattern above missed it and this test started failing the moment the
    # self-host demo had been run -- on an artifact it is right to reject.
    case "$e" in *kernel*.elf) continue ;; esac
    [ -f "$e" ] && REAL="$REAL $e"
done
if /tmp/osdev_elf_test $REAL; then
    echo "PASS: ELF loader (validators + load round-trip, fuzz/corrupt safe, ASan/UBSan clean)"
else
    echo "FAIL: ELF-loader test aborted (ASan/UBSan caught a memory error or a check failed)"; exit 1
fi
