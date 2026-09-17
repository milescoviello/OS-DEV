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

# --- the libraries ldd CANNOT tell you about (M1967) -------------------------
#
# glibc resolves hostnames through NSS, and the NSS backends are dlopen'd at
# RUNTIME from a name built out of /etc/nsswitch.conf -- they are not linked
# against, so they never appear in ldd output and were never staged. The
# result was that getaddrinfo failed for every hostname with EAI_AGAIN, an
# error meaning "try again later" about a lookup that had no way to happen:
# Node reported `getaddrinfo EAI_AGAIN example.com` with a correct
# /etc/resolv.conf sitting right there and a working resolver underneath it.
#
# Anything else dlopen'd by a program we stage will have the same shape of
# problem, and the same fix: name it here, because no tool can derive it.
# Firefox dlopen's its GRAPHICS backend by soname and falls back when it is
# absent -- so a missing libEGL is not an error anywhere, it is a browser
# quietly deciding it has no GPU path. The serial log showed it walking the
# whole search path for libEGL.so.1 over and over:
#
#   257(...) = -2  "/usr/lib64/firefox/libEGL.so.1"
#   257(...) = -2  "/usr/lib64/firefox/glibc-hwcaps/x86-64-v3/libEGL.so.1"
#
# These need their OWN closures (libEGL pulls in GLdispatch, glapi, drm, xcb),
# so stage each one the same way the main binary is staged rather than copying
# a single file. (M2000)
for extra in libEGL.so.1 libGLdispatch.so.0 libglapi.so.0 libgbm.so.1 \
             libwayland-egl.so.1 libdrm.so.2 libGL.so.1; do
    for d in /lib64 /usr/lib64 /lib/x86_64-linux-gnu; do
        [ -f "$d/$extra" ] || continue
        r=$(readlink -f "$d/$extra") || continue
        mkdir -p "$ROOT/usr/lib64" "$ROOT/lib64"
        cp -f "$r" "$ROOT/usr/lib64/$extra" 2>/dev/null || true
        cp -f "$r" "$ROOT/lib64/$extra"     2>/dev/null || true
        for so in $(ldd "$r" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*'); do
            rr=$(readlink -f "$so" 2>/dev/null) || continue
            [ -f "$rr" ] || continue
            mkdir -p "$ROOT$(dirname "$so")"
            cp -f "$rr" "$ROOT$so" 2>/dev/null || true
            cp -f "$rr" "$ROOT/usr/lib64/$(basename "$so")" 2>/dev/null || true
            n=$((n+1))
        done
        n=$((n+1))
        break
    done
done

for extra in libnss_dns.so.2 libnss_files.so.2 libresolv.so.2; do
    for d in /lib64 /usr/lib64 /lib/x86_64-linux-gnu; do
        [ -f "$d/$extra" ] || continue
        r=$(readlink -f "$d/$extra") || continue
        mkdir -p "$ROOT/lib64" "$ROOT/usr/lib64"
        cp -f "$r" "$ROOT/lib64/$extra"     2>/dev/null || true
        cp -f "$r" "$ROOT/usr/lib64/$extra" 2>/dev/null || true
        n=$((n+1))
        break
    done
done

# The CA bundle. OpenSSL verifies a server's chain against a trust store on
# disk and has no built-in one, so without this every HTTPS connection fails at
# `unable to get local issuer certificate` -- AFTER a complete TLS handshake,
# which makes it read like a protocol failure rather than a missing file.
# Copied to both of OpenSSL's default locations. (M1968)
for ca in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
          /etc/ssl/cert.pem; do
    [ -f "$ca" ] || continue
    mkdir -p "$ROOT/etc/ssl/certs" "$ROOT/etc/pki/tls/certs"
    cp -f "$ca" "$ROOT/etc/ssl/certs/ca-certificates.crt"
    cp -f "$ca" "$ROOT/etc/ssl/cert.pem"
    cp -f "$ca" "$ROOT/etc/pki/tls/certs/ca-bundle.crt"
    break
done

# nsswitch.conf itself: with no file, glibc's built-in default has varied
# across versions, and "hosts: files dns" is the answer we actually want.
mkdir -p "$ROOT/etc"
printf 'hosts:\tfiles dns\npasswd:\tfiles\ngroup:\tfiles\n' > "$ROOT/etc/nsswitch.conf"

# /etc/hosts AND /etc/host.conf, which were both missing (M2128). Every Linux
# system has them, and glibc's resolver asks for all four files on every single
# lookup -- traced from the kernel:
#
#   [resolver] the guest asked for "/etc/resolv.conf"
#   [resolver] the guest asked for "/etc/nsswitch.conf"
#   [resolver] the guest asked for "/etc/host.conf"
#   [resolver] the guest asked for "/etc/hosts"
#
# `hosts: files dns` means the `files` source runs FIRST, and it is the one that
# reads /etc/hosts. A missing file there is NSS_STATUS_UNAVAIL rather than
# "not found", which is a different thing to glibc and not the thing we mean:
# we mean "this machine has a loopback name and nothing else, go ask DNS".
printf '127.0.0.1\tlocalhost\n::1\t\tlocalhost\n' > "$ROOT/etc/hosts"
printf 'multi on\n' > "$ROOT/etc/host.conf"

# THE XDG USER DIRECTORIES (M2133).
#
# Firefox's BackupService asks the XPCOM directory service for the user's
# Documents folder during startup. With no XDG configuration and no such
# directory, the service returns NS_ERROR_FAILURE, the JS gets an empty string,
# and PathUtils.join throws -- an UNCAUGHT exception in chrome startup:
#
#   console.warn: BackupService: "There was an error while trying to get the
#     Document's directory" [nsIProperties.get] NS_ERROR_FAILURE
#   JavaScript error: BackupService.sys.mjs, line 4380:
#     NotAllowedError: PathUtils.join: PathUtils does not support empty paths
#
# These are directories every desktop Linux install has, and their absence is
# not something a browser is written to survive.
for d in Desktop Documents Downloads Music Pictures Public Templates Videos; do
    mkdir -p "$ROOT/root/$d"
done
mkdir -p "$ROOT/root/.config"
cat > "$ROOT/root/.config/user-dirs.dirs" <<'XDG'
XDG_DESKTOP_DIR="$HOME/Desktop"
XDG_DOCUMENTS_DIR="$HOME/Documents"
XDG_DOWNLOAD_DIR="$HOME/Downloads"
XDG_MUSIC_DIR="$HOME/Music"
XDG_PICTURES_DIR="$HOME/Pictures"
XDG_PUBLICSHARE_DIR="$HOME/Public"
XDG_TEMPLATES_DIR="$HOME/Templates"
XDG_VIDEOS_DIR="$HOME/Videos"
XDG

echo "  STAGE   $NAME <- $BIN (+ $n shared libs)"
