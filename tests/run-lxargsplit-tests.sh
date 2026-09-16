#!/bin/bash
# Host test for kernel/include/lxargsplit.h (M2071): the shell's quoting
# sentinel must come off before a Linux program sees its argv.
set -e
cd "$(dirname "$0")/.."
BIN=$(mktemp /tmp/osdev_lxargsplit.XXXXXX)
trap 'rm -f "$BIN"' EXIT
echo "building the Linux-argv splitter test (ASan+UBSan)..."
gcc -std=gnu11 -Wall -Wextra -fsanitize=address,undefined -O1 -o "$BIN" tests/lxargsplit.c
"$BIN"
