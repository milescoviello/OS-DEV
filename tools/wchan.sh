#!/bin/sh
# wchan.sh -- turn `wchan=0x...` in a boot log into a function name.
#
# task_block stores __builtin_return_address(0) (kernel/task.c:840), so a
# blocked thread's wchan is the kernel PC of whatever called it. That is the
# single most useful fact about a hung process -- and as a bare hex number it
# is unreadable, which is why "3 threads at wchan=0xffffffff8012ab40" has been
# printed many times this campaign and acted on never. (M2106)
#
# Usage: tools/wchan.sh boot.log [kernel32.elf]
set -e
LOG=${1:?usage: wchan.sh LOG [ELF]}
ELF=${2:-build/kernel32.elf}
nm -n "$ELF" | awk '$2 ~ /^[tT]$/ { print strtonum("0x"$1), $3 }' > /tmp/wchan.syms
grep -ao 'wchan=0x[0-9a-fA-F]*' "$LOG" | sort -u | while read -r w; do
    a=${w#wchan=}
    printf '%s  ' "$w"
    awk -v want="$(printf '%d' "$a")" '
        $1 <= want { name = $2; base = $1 }
        END { if (name == "") print "(no symbol below this address)";
              else printf "%s+0x%x\n", name, want - base }' /tmp/wchan.syms
done
