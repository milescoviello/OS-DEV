#!/bin/sh
# Stage a HOST Linux binary and its whole shared-library closure into the ext2
# root we hand to OS-DEV (M1955).
#
# This is the "some Linux stuff bolted on" side of the project, and it is
# deliberately a COPY, not a port: OS-DEV runs these binaries unmodified,
# through the Linux ABI layer in kernel/linuxabi.c. Nothing here is built for
# OS-DEV and nothing here is patched.
#
# The absolute paths matter. ld.so resolves a DT_NEEDED by SONAME against
# DT_RUNPATH and then the default directories, so a library has to land at the
# path the binary was linked to expect -- binutils' libbfd lives under
# /usr/lib64/binutils/<triplet>/<ver>/ and is found only via RUNPATH. OS-DEV's
# Linux processes see this tree as "/" (the LX_ROOT chroot-style prefix), so an
# absolute host path becomes the identical absolute guest path.
#
# usage: stage-linux-tool.sh <lxroot> <name> [<binary>]
#   <name> is the command name to expose in /usr/bin; <binary> defaults to
#   `command -v <name>` resolved through its symlinks.
set -e
ROOT=$1; NAME=$2; BIN=$3
[ -n "$ROOT" ] && [ -n "$NAME" ] || { echo "usage: $0 <lxroot> <name> [binary]" >&2; exit 2; }
[ -n "$BIN" ] || BIN=$(command -v "$NAME" 2>/dev/null || true)
[ -n "$BIN" ] || { echo "  SKIP    $NAME (not installed on the host)"; exit 0; }
BIN=$(readlink -f "$BIN")
[ -f "$BIN" ] || { echo "  SKIP    $NAME ($BIN missing)"; exit 0; }

# The binary itself goes to its real path AND to /usr/bin/<name>. The real path
# is what argv[0]-relative lookups and RUNPATH-relative ($ORIGIN) resolution
# expect; /usr/bin/<name> is what a person types.
mkdir -p "$ROOT$(dirname "$BIN")" "$ROOT/usr/bin"
cp -f "$BIN" "$ROOT$BIN"
[ "$ROOT$BIN" = "$ROOT/usr/bin/$NAME" ] || cp -f "$BIN" "$ROOT/usr/bin/$NAME"

# ldd prints the RESOLVED path of every dependency, transitively, which is
# exactly the closure ld.so will ask for. linux-vdso.so.1 has no file (the
# kernel injects it via AT_SYSINFO_EHDR, which we do not supply -- glibc then
# falls back to real syscalls) so the /-anchored match skips it naturally.
n=0
for so in $(ldd "$BIN" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*'); do
    r=$(readlink -f "$so" 2>/dev/null) || continue
    [ -f "$r" ] || continue
    mkdir -p "$ROOT$(dirname "$so")"
    cp -f "$r" "$ROOT$so"
    n=$((n+1))
done
echo "  STAGE   $NAME <- $BIN (+ $n shared libs)"
