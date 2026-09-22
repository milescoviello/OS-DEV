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
#
# -Dlegacy-wayland=bind-wayland-display IS LOAD-BEARING (M2358). Mesa's
# hardware Wayland path learns WHICH GPU to use from the compositor, and it has
# exactly two sources:
#
#   * zwp_linux_dmabuf_v1 v4+, whose default feedback carries `main_device`;
#   * wl_drm, whose `device` event names the node -- and that fallback is
#     compiled in ONLY when this option is set (`-DHAVE_BIND_WL_DISPLAY`).
#
# Without either, `dri2_initialize_wayland_drm` returns false and Firefox falls
# back to `dri2_initialize_wayland_swrast` -- which is exactly what it did:
# glxtest loaded this very Mesa and then never opened a render node, zero DRM
# ioctls in the whole boot. wl_drm is three events against dmabuf feedback's
# format table and tranches, so it is the cheaper of the two to serve from our
# own compositor. The dmabuf path is the modern one and is worth having later,
# because it is also how a browser would hand us a GPU buffer to composite.
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
        -Dlegacy-wayland=bind-wayland-display \
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
# Headers and pkgconfig are build-time artefacts; the guest runs binaries, and
# every megabyte staged is a megabyte of ext2 the boot reads through a disk
# path measured at 4.3x read amplification.
rm -rf "$OUT/stage/usr/include" "$OUT/stage/usr/lib64/pkgconfig"
( cd "$OUT/stage" && tar cf - . ) | ( cd "$LXROOT" && tar xf - )

# THE ONE DEPENDENCY THAT IS NOT ALREADY THERE. libgallium DT_NEEDEDs
# libSPIRV-Tools; libdrm, libexpat, libz, libzstd, libstdc++, libgcc_s and
# libwayland-client are all staged already for Firefox. Checked, not assumed --
# a missing DT_NEEDED presents as "libEGL.so.1 not found", which reads as a
# Mesa problem rather than a staging one.
# libwayland-server joined the list when -Dlegacy-wayland=bind-wayland-display
# was turned on: the wl_drm fallback links libwayland_drm, which is built
# against wayland-server even though it ends up inside a CLIENT library. Caught
# by the closure check below rather than by a boot, which is the whole reason
# that check exists. (M2358)
for dep in libSPIRV-Tools.so libwayland-server.so.0; do
    if [ ! -e "$LXROOT/usr/lib64/$dep" ]; then
        src=$(ls /usr/lib64/$dep 2>/dev/null | head -1)
        [ -n "$src" ] || { echo "build-mesa-virgl: $dep not found on this host" >&2; exit 1; }
        cp -L "$src" "$LXROOT/usr/lib64/$dep"
        echo "    staged dep $dep ($(du -h "$LXROOT/usr/lib64/$dep" | cut -f1))"
    fi
done

# AND PROVE EVERY DT_NEEDED RESOLVES, before a boot has to discover it.
echo "==> checking the closure resolves inside the guest root:"
miss=0
for lib in "$LXROOT"/usr/lib64/libEGL.so.1.0.0 "$LXROOT"/usr/lib64/libgallium-*.so \
           "$LXROOT"/usr/lib64/libGLESv2.so.2.0.0 "$LXROOT"/usr/lib64/libgbm.so.1.0.0; do
    [ -e "$lib" ] || continue
    for n in $(objdump -p "$lib" 2>/dev/null | awk '/NEEDED/{print $2}'); do
        case "$n" in ld-linux*|linux-vdso*) continue ;; esac
        if [ ! -e "$LXROOT/usr/lib64/$n" ] && [ ! -e "$LXROOT/lib64/$n" ] && \
           [ ! -e "$LXROOT/usr/lib/$n" ]; then
            echo "    MISSING  $n (needed by $(basename "$lib"))"; miss=$((miss+1))
        fi
    done
done
[ "$miss" = 0 ] && echo "    all DT_NEEDED entries present" || \
    { echo "build-mesa-virgl: $miss unresolved dependency(ies)" >&2; exit 1; }
# AND ASSERT THAT WHAT IS THERE IS WHAT WE BUILT (M2354).
#
# `stage-linux-tool.sh` copies a binary's whole `ldd` closure from this host,
# and lxgl links against libEGL -- so tool staging will happily overwrite this
# Mesa with the host's glvnd dispatch stub (88 KB against our 468 KB), whose
# vendor library is not staged. It did exactly that, silently, the moment the
# Makefile changed, and the resulting failure is WORD FOR WORD the failure a
# real driver problem produces: "DRI2: failed to load driver". Twenty minutes
# went into debugging a kernel that was fine.
#
# The Makefile now orders this step after .tools-staged so it always writes
# last. This is the check that the ordering held.
for f in libEGL.so.1.0.0 libGLESv2.so.2.0.0; do
    want=$(stat -Lc %s "$OUT/stage/usr/lib64/$f" 2>/dev/null || echo 0)
    got=$(stat -Lc %s "$LXROOT/usr/lib64/$f" 2>/dev/null || echo 0)
    if [ "$want" = 0 ] || [ "$want" != "$got" ]; then
        echo "build-mesa-virgl: $f in the guest root is $got bytes, ours is $want --" >&2
        echo "                  something overwrote it (the host's glvnd stub, most likely)." >&2
        exit 1
    fi
done
echo "==> verified: the guest's libEGL/libGLESv2 are the ones just built"

echo "==> staged. DRI modules now in the guest:"
ls -la "$LXROOT/usr/lib64/" 2>/dev/null | head -20
# Mesa 26 has NO separate *_dri.so: the gallium driver is inside
# libgallium-<ver>.so and libEGL links it with DT_NEEDED rather than dlopening
# a per-driver module. So "no dri/ directory" is correct here, not a failure --
# worth saying, because the Debian layout this was modelled on does have one.
