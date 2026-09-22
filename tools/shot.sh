#!/bin/bash
# shot — screendump the running VM and convert to PNG. LOOKING at the screen
# is the confirmation of last resort: a log grep for a marker this build does
# not emit reports "no page on screen" for a page that is rendering perfectly,
# which is exactly what happened before this script existed.
set -e
H=${PVE_HOST:-192.168.1.5}; V=${VMID:-122}; D=/root/osdev
OUT=${1:-/tmp/shot.png}
# RETRY, AND WAIT LONGER (M2367). One attempt with an ~18 s budget failed
# mid-page-load: `qm monitor` is slow to answer while the guest is busy, the
# file had not appeared yet, and the caller reported "screendump failed" for a
# VM that was perfectly healthy -- a measurement lost to the instrument, not
# to the thing measured. At 2560x1440 the file is 11 MB, so give it room.
ssh -o BatchMode=yes -o ConnectTimeout=30 root@$H "
  for try in 1 2 3; do
    rm -f $D/shot.ppm
    echo 'screendump $D/shot.ppm' | qm monitor $V >/dev/null 2>&1
    n=0; while [ \$n -lt 120 ]; do
      a=\$(stat -c %s $D/shot.ppm 2>/dev/null||echo 0); sleep 0.5
      b=\$(stat -c %s $D/shot.ppm 2>/dev/null||echo 0)
      [ \"\$a\" = \"\$b\" ] && [ \"\$a\" != 0 ] && break
      n=\$((n+1))
    done
    [ -s $D/shot.ppm ] && exit 0
    echo \"(screendump attempt \$try produced nothing; retrying)\" >&2
  done
  echo 'FATAL: screendump produced nothing after 3 attempts'; exit 3"
scp -q "root@$H:$D/shot.ppm" "${OUT%.png}.ppm"
DIMS=$(head -2 "${OUT%.png}.ppm" | tail -1)
magick "${OUT%.png}.ppm" "$OUT"
echo "==> $OUT   (framebuffer $DIMS)"
