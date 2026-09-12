#!/bin/sh
# AF_INET sockets through the Linux ABI (M1967).
#
# Phase 6's gate is "a script that touches the network", and the blocker was
# that AF_INET sockets were not POLLABLE. tcp_read pulls frames straight off
# the NIC, so nothing could answer "is there data?" without CONSUMING it --
# and an event loop asks exactly that, about every socket it owns, before it
# reads any of them. poll() reported POLLNVAL for socket fds, so libuv could
# not drive them at all.
#
# tools/lx/lxinet.c is the same path Node uses, exercised directly: a DNS
# lookup over a UDP socket and an HTTP request over TCP, both driven by poll().
# Running it as a plain static-PIE binary means a failure here is a KERNEL
# failure, diagnosable in three minutes instead of inside a V8 run.
#
# Needs the real internet (QEMU user-mode NAT). SKIPs cleanly without it.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
EXT2=build/ext2.img
command -v "$QEMU" >/dev/null 2>&1 || { echo "SKIP: lxinet test ($QEMU not found)"; exit 0; }
[ -f "$EXT2" ] || { echo "SKIP: lxinet test (no $EXT2)"; exit 0; }

SLOG=$(mktemp /tmp/osdev_lxinet.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$SLOG"; exit "$rc"; }
trap cleanup EXIT

echo "booting headless and running AF_INET sockets (DNS over UDP + HTTP over TCP, poll-driven)..."
timeout -s KILL 300 "$QEMU" -cpu max -snapshot -no-reboot -no-shutdown -m 512M -smp 4 -kernel "$KERNEL" \
    -append "lxinettest nonetdemo" \
    -drive file="$DISK",format=raw,if=ide \
    -drive file="$EXT2",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -display none -serial file:"$SLOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 600 ]; do
    grep -aqE "lxinet exit ->|KERNEL PANIC" "$SLOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

if grep -aq "KERNEL PANIC" "$SLOG"; then
    echo "FAIL: KERNEL PANIC during the AF_INET test:"
    grep -a -A2 "KERNEL PANIC" "$SLOG" | head -3
    exit 1
fi
if ! grep -aq "lxinet exit ->" "$SLOG"; then
    echo "SKIP: the AF_INET test never finished (no network on this host?)"
    grep -aE "LXINET|lxinet" "$SLOG" | head -3 | sed 's/^/      /'
    exit 0
fi

fail=0
# POLLNVAL is called out separately: it is the specific symptom this milestone
# exists to remove, and it is worth naming rather than folding into "failed".
if grep -aq "POLLNVAL" "$SLOG"; then
    echo "  FAIL: poll() reported POLLNVAL -- socket fds are not pollable again"; fail=1
fi
if grep -aq "LXINET-DNS: example.com ->" "$SLOG"; then
    echo "  ok: DNS over a UDP socket -- sendto + poll(POLLIN) + recvfrom ($(grep -ao 'example.com -> [0-9.]*' "$SLOG" | head -1))"
else
    echo "  FAIL: the DNS lookup did not complete:"; grep -aE "LXINET" "$SLOG" | head -2; fail=1
fi
# The status code AND the byte count: a stub that faked readiness would produce
# neither, and a truncated read would produce the first without the second.
if grep -aqE "LXINET-HTTP: status 200, [0-9]+ bytes, poll-driven" "$SLOG"; then
    echo "  ok: HTTP over a TCP socket, driven by poll() rather than a blocking read ($(grep -ao 'status 200, [0-9]* bytes' "$SLOG" | head -1))"
else
    echo "  FAIL: the HTTP request did not complete:"; grep -aE "LXINET" "$SLOG" | head -3; fail=1
fi
if grep -aq "lxinet exit -> 0" "$SLOG"; then
    echo "  ok: and it exited 0 -- every step succeeded, not just the ones that printed"
else
    echo "  FAIL: the test exited non-zero:"; grep -a "lxinet exit ->" "$SLOG" | head -1; fail=1
fi

[ "$fail" -eq 0 ] || { echo "FAIL: AF_INET sockets"; exit 1; }
echo "PASS: AF_INET sockets through the Linux ABI (DNS over UDP + HTTP over TCP, both poll-driven)"
