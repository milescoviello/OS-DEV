#!/bin/sh
# M2324: the ephemeral port allocator must never hand one local port to two
# live datagram sockets.
#
# This is the CAUSE test for the intermittent EAI_AGAIN. The symptom test would
# be "resolve names under load and count failures", which needs Firefox, eight
# cores and ten minutes to produce one sample. This asks the kernel the same
# question directly -- open 480 datagram sockets across 12 threads, keep them
# all open, and read every local port back with getsockname -- and it answers
# in a second with no network at all.
set -e
cd "$(dirname "$0")/.."
NODE=${PVE_HOST:-192.168.1.5}
CAP=${CAP:-160}

[ -x tools/pve-run.sh ] || { echo "SKIP: udp port test (no tools/pve-run.sh)"; exit 0; }

echo "booting OS-DEV on $NODE with 8 cores and opening 480 datagram sockets at once..."
WAIT=full NOBUILD=${NOBUILD:-1} APPEND="lxport lxout nonetdemo" CORES=8 CAP="$CAP" \
    tools/pve-run.sh >/dev/null 2>&1 || true

LOG=$(ssh -o BatchMode=yes "root@$NODE" "tr -d '\r\000' < /root/osdev/boot.log" 2>/dev/null || true)
[ -n "$LOG" ] || { echo "FAIL: udp port test: no boot log came back"; exit 1; }

if ! printf '%s\n' "$LOG" | grep -q 'LXPORT:.*socket(s) open'; then
    echo "FAIL: the probe never reported -- it did not run to completion:"
    printf '%s\n' "$LOG" | grep -a 'LXPORT\|lxport exit' | head -5 | sed 's/^/      /'
    exit 1
fi

# EIGHT CORES ON PURPOSE. The race is between a read and a write of one
# counter; on one core the window is a preemption point and the test would
# pass against the broken allocator often enough to be useless.
if printf '%s\n' "$LOG" | grep -q 'LXPORT-OK'; then
    printf '%s\n' "$LOG" | grep -a 'LXPORT-OK' | head -1 | sed 's/^/  ok: /'
    echo "PASS: no two live datagram sockets share a local port"
    exit 0
fi

echo "FAIL: the allocator handed one port to two live sockets:"
printf '%s\n' "$LOG" | grep -a 'LXPORT' | head -8 | sed 's/^/      /'
exit 1
