#!/bin/bash
# bash, not sh: PIPESTATUS. The first cut used /bin/sh, piped ninja to `tail`,
# and so silently ignored ninja failing -- it printed "==> what came out:" with
# an empty listing and exited 0.
# build-mesa-virgl — a Mesa that can ONLY do virgl, built for the guest.
#
#   tools/build-mesa-virgl.sh              build + stage into build/lxroot
#   OUT=/tmp/x tools/build-mesa-virgl.sh   build into a different work dir
#
# WHY BUILD IT RATHER THAN STAGE THE DISTRO'S. Debian's Mesa ships one
# "megadriver" -- `libgallium-25.0.7.so`, 42 MB, with `virtio_gpu_dri.so` a
# symlink to a 108 KB loader shim in front of it -- and that megadriver's `ldd`
# closure is LLVM 19 (~130 MB), z3, libedit, libsensors, libpciaccess and nine
# X11/xcb libraries. None of that is virgl's: virgl compiles nothing locally,
# because the SHADERS ARE COMPILED ON THE HOST by virglrenderer. It is llvmpipe
# in the same binary that needs LLVM, and llvmpipe is precisely the software
# renderer we are trying to stop using.
#
# Configuring for virgl alone drops all of it. The guest has ~688 MB free and
# every megabyte staged is a megabyte of ext2 the boot has to read through a
# disk path measured at 4.3x read amplification, so this is not tidiness.
#
# The dev laptop's own Mesa cannot be reused either: Gentoo's VIDEO_CARDS does
# not include virgl, so there is no virtio_gpu_dri.so on the box at all.
set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)
LXROOT=${LXROOT:-$ROOT/build/lxroot}
OUT=${OUT:-/tmp/mesa-virgl}
SRC=$(ls /var/cache/distfiles/mesa-*.tar.xz 2>/dev/null | sort -V | tail -1)
[ -n "$SRC" ] || { echo "build-mesa-virgl: no mesa tarball in /var/cache/distfiles" >&2; exit 2; }
VER=$(basename "$SRC" .tar.xz)

mkdir -p "$OUT"
if [ ! -d "$OUT/$VER" ]; then
    echo "==> extracting $VER"
    tar -xf "$SRC" -C "$OUT"
fi
cd "$OUT/$VER"

# -Dllvm=disabled is the whole point. -Dglx=disabled because there is no X
# server here and never will be -- the display path is our own Wayland
# compositor. -Dplatforms=wayland for the same reason.
if [ ! -d "$OUT/b" ]; then
    echo "==> configuring (virgl only, no LLVM, no GLX, wayland only)"
    # --libdir=lib64 TO MATCH THE GUEST, NOT THE HOST DISTRO. The guest root is
    # staged from a Gentoo box, so its libraries are in /usr/lib64 and /lib64,
    # and that is what envp0's LD_LIBRARY_PATH lists. A Mesa installed into
    # /usr/lib/x86_64-linux-gnu would be invisible to the loader -- the probe
    # would fail to start with "libEGL.so.1 not found" and look like a Mesa
    # problem rather than a path problem.
    meson setup "$OUT/b" \
        --prefix=/usr \
        --libdir=lib64 \
        --buildtype=release \
        -Dgallium-drivers=virgl \
        -Dvulkan-drivers= \
        -Dllvm=disabled \
        -Dshared-llvm=disabled \
        -Dplatforms=wayland \
        -Dglx=disabled \
        -Degl=enabled \
        -Dgbm=enabled \
        -Dgles1=disabled \
        -Dgles2=enabled \
        -Dopengl=true \
        -Dglvnd=disabled \
        -Dlmsensors=disabled \
        -Dgallium-va=disabled \
        -Dgallium-extra-hud=false \
        -Dvalgrind=disabled \
        -Dlibunwind=disabled \
        -Dtools= 2>&1 | tail -40 || { echo "build-mesa-virgl: meson setup FAILED" >&2; exit 1; }
fi

# PIPING TO `tail` THREW AWAY THE EXIT STATUS. The first run of this script
# printed "==> building", "ninja: error: loading 'build.ninja'", and then
# "==> what came out:" with an empty listing -- and exited 0. `set -e` cannot
# see through a pipeline, so every stage needs its own check. Same class as
# every other instrument in this tree that could not report failure.
echo "==> building"
ninja -C "$OUT/b" 2>&1 | tail -5
[ "${PIPESTATUS[0]:-0}" = 0 ] || { echo "build-mesa-virgl: ninja FAILED" >&2; exit 1; }
echo "==> installing to a staging root"
rm -rf "$OUT/stage"
DESTDIR="$OUT/stage" ninja -C "$OUT/b" install 2>&1 | tail -3
[ "${PIPESTATUS[0]:-0}" = 0 ] || { echo "build-mesa-virgl: install FAILED" >&2; exit 1; }
[ -d "$OUT/stage" ] || { echo "build-mesa-virgl: nothing was installed" >&2; exit 1; }

echo
echo "==> what came out (this is the number the LLVM argument is about):"
du -sh "$OUT/stage" 2>/dev/null
find "$OUT/stage" -name "*_dri.so" -o -name "libEGL*" -o -name "libGL*" -o -name "libgbm*" -o -name "libgallium*" \
    | while read -r f; do printf "    %8s  %s\n" "$(du -h "$f" | cut -f1)" "${f#$OUT/stage}"; done

# STAGE AT THE GUEST'S REAL ABSOLUTE PATHS. The loader searches by path, and a
# driver in the wrong directory is not a driver -- Mesa finds its DRI module by
# scanning a hardcoded list that includes the libdir it was configured with,
# which is why --libdir above matches where these land.
echo "==> staging into $LXROOT"
mkdir -p "$LXROOT"
( cd "$OUT/stage" && tar cf - . ) | ( cd "$LXROOT" && tar xf - )
echo "==> staged. DRI modules now in the guest:"
ls -la "$LXROOT/usr/lib64/" 2>/dev/null | head -20
# Mesa 26 has NO separate *_dri.so: the gallium driver is inside
# libgallium-<ver>.so and libEGL links it with DT_NEEDED rather than dlopening
# a per-driver module. So "no dri/ directory" is correct here, not a failure --
# worth saying, because the Debian layout this was modelled on does have one.
