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
# `command -v echo` prints "echo" -- the SHELL BUILTIN, not a file. readlink -f
# then happily resolves it against the cwd and we stage a path that does not
# exist. Anything that is not already absolute is not a binary we can copy.
case "$BIN" in /*) ;; *) BIN=$(command -v "/usr/bin/$NAME" 2>/dev/null || true) ;; esac
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
    # ...and again in /usr/lib64, which IS a default ld.so search directory.
    # A library outside the default paths is found on the host only through
    # /etc/ld.so.cache, and we have no cache: node's libstdc++ lives under
    # /usr/lib/gcc/<triplet>/<ver>/ and ld.so simply reported
    # "libstdc++.so.6: cannot open shared object file". Generating a real
    # binary cache would be fiddly; a second copy on a path ld.so already
    # searches is the same answer for a few megabytes.
    mkdir -p "$ROOT/usr/lib64"
    cp -f "$r" "$ROOT/usr/lib64/$(basename "$so")" 2>/dev/null || true
    n=$((n+1))
done
echo "  STAGE   $NAME <- $BIN (+ $n shared libs)"
