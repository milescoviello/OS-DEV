#!/bin/sh
# wchan.sh -- turn `wchan=0x...` in a boot log into a function name.
#
# task_block stores __builtin_return_address(0) (kernel/task.c:840), so a
# blocked thread's wchan is the kernel PC of whatever called it. That is the
# single most useful fact about a stalled process -- and as a bare hex number
# it is unreadable, which is why "3 threads at wchan=0xffffffff8022b0e5" has
# been printed many times this campaign and acted on never.
#
# The first version of this used `printf '%d' "$addr"` in the shell, which
# OVERFLOWS on a higher-half kernel address (0xffffffff8...) and then resolved
# every wchan to the same wrong symbol with a +0x7fffffff... offset. An
# instrument that answers confidently and wrongly is worse than none, which is
# the lesson this whole block is about -- so it is Python now, where integers
# do not have a width. (M2109)
#
# Usage: tools/wchan.sh boot.log [kernel32.elf]
LOG=${1:?usage: wchan.sh LOG [ELF]}
# kernel32.elf TRUNCATES symbol addresses to 32 bits (8023cd75); kernel.elf keeps
# the real higher-half values (ffffffff8023cd75), which is what a wchan is.
ELF=${2:-build/kernel.elf}
nm -n "$ELF" | awk '$2 ~ /^[tT]$/ { print $1, $3 }' > /tmp/wchan.syms
grep -ao 'wchan=0x[0-9a-fA-F]*' "$LOG" | sort -u > /tmp/wchan.addrs
python3 - "$ELF" <<'PY'
syms = []
for line in open("/tmp/wchan.syms"):
    a, n = line.split()
    syms.append((int(a, 16), n))
syms.sort()
for line in open("/tmp/wchan.addrs"):
    line = line.strip()
    if not line:
        continue
    want = int(line.split("=")[1], 16)
    lo, hi = 0, len(syms) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if syms[mid][0] <= want:
            best = syms[mid]; lo = mid + 1
        else:
            hi = mid - 1
    if best is None:
        print("%s  (below every symbol)" % line)
    else:
        print("%s  %s+0x%x" % (line, best[1], want - best[0]))
PY
