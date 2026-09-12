#!/bin/sh
# In-guest NETWORK DEBUG CONSOLE test (M1870). The kernel ships a netcon task
# (kernel/netcon.c) that, when booted with `-append netcon`, LISTENS on TCP 2323
# and serves a line-oriented inspection shell (dmesg/mem/ps/cpu/uptime/ip/pci/
# bcache/ls/cat/echo/reboot) over the from-scratch TCP stack. This is the
# real-hardware bring-up lifeline: it runs in the KERNEL, so it can dump kprintf
# history and kernel state even if the framebuffer never lights up.
#
# This boots the real kernel headless with `netcon` on the cmdline and a
# host->guest forward (host:12323 -> guest:2323), connects a plain TCP client
# FROM THE HOST, drives several commands, and asserts the expected responses come
# back. The host client's output IS the assertion -- it proves the OS accepts an
# inbound connection AND sustains a persistent, bidirectional session (multiple
# request/response round-trips on one connection), which is more than the
# one-shot httpd test exercises.
#
# Exit 0 = pass. SKIPs cleanly if qemu/socat/python3 are absent.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
HPORT=12323                        # host port forwarded to the guest's netcon (:2323)
TMP=$(mktemp -d /tmp/osdev_netcon.XXXXXX)
SOCK=$TMP/mon.sock
SLOG=$TMP/serial.log
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -rf "$TMP"; exit "$rc"; }
trap cleanup EXIT

for t in "$QEMU" python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "SKIP: netcon test ($t not found)"; exit 0; }
done

echo "booting kernel headless with -append netcon and a host->guest :$HPORT -> :2323 forward..."
timeout -s KILL 240 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -append netcon \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0,hostfwd=tcp::$HPORT-:2323 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -display none -serial file:"$SLOG" \
    -monitor unix:"$SOCK",server,nowait >"$TMP/qemu.err" 2>&1 &
QPID=$!

got=0; i=0
while [ $i -lt 120 ]; do
    grep -q "launching the desktop" "$SLOG" 2>/dev/null && { got=1; break; }
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
[ "$got" -eq 1 ] || { echo "FAIL: never reached desktop"; tail -8 "$SLOG"; exit 1; }
# Let the boot net_demo self-test finish so it isn't polling the RX ring at the
# same time as netcon (the stack has no cross-connection demux -- see netcon.c).
sleep 3

# Drive the console from the host. Connect, read the banner, send a batch of
# commands, and collect everything the guest sends back over ~a few seconds. The
# whole connect+drive is wrapped in an outer retry so a missed SYN (netcon loops
# its accept with a listen window; net_demo may still be draining RX) just tries
# again rather than failing the test.
run_client() {
python3 - "$HPORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=8)
s.settimeout(2.0)
out = b""
# read the banner/prompt netcon sends on connect
try:
    out += s.recv(4096)
except Exception:
    pass
for cmd in [b"echo NETCON_LINK_OK\n", b"mem\n", b"cpu\n", b"uptime\n",
            b"ip\n", b"ps\n", b"dmesg\n", b"pci\n", b"ls /\n",
            b"cat README.TXT\n", b"help\n", b"quit\n"]:
    s.send(cmd)
    time.sleep(0.5)
    # drain whatever came back for this command
    try:
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
s.close()
sys.stdout.buffer.write(out)
PY
}

# Same fix as run-httpd-tests.sh: one run_client pass can take ~30s (12 commands
# x 0.5s pacing + a 2s recv timeout each), so four passes budget ~120s — but the
# QEMU hard-kill was 90s. On a slow run the VM died mid-retry and the failure was
# reported as "netcon did not return the expected responses", blaming the TCP
# stack rather than the harness. Cap now exceeds the worst-case budget, and the
# guard below reports a dead VM as exactly that.
vm_dead() { ! kill -0 "$QPID" 2>/dev/null; }

ok=0
for outer in 1 2 3 4; do
    if vm_dead; then
        echo "FAIL: QEMU exited before the netcon session completed (harness/boot problem, not the TCP stack)"
        tail -12 "$SLOG" 2>/dev/null | sed 's/^/      /'
        exit 1
    fi
    out=$(run_client 2>/dev/null || true)
    if printf '%s' "$out" | grep -q "network debug console" \
       && printf '%s' "$out" | grep -q "NETCON_LINK_OK" \
       && printf '%s' "$out" | grep -q "phys mem:" \
       && printf '%s' "$out" | grep -q "cpus online:" \
       && printf '%s' "$out" | grep -q "uptime:" \
       && printf '%s' "$out" | grep -q "mac " \
       && printf '%s' "$out" | grep -q "state" \
       && printf '%s' "$out" | grep -q "launching the desktop" \
       && printf '%s' "$out" | grep -q "entries:" \
       && printf '%s' "$out" | grep -q "class " \
       && printf '%s' "$out" | grep -q "read by our own driver" \
       && printf '%s' "$out" | grep -q "commands:"; then
        ok=1; break
    fi
    echo "  (outer retry $outer: console didn't return all expected responses yet)"
    sleep 2
done

if [ "$ok" -eq 1 ]; then
    echo "PASS: in-guest netcon served a persistent multi-command session over the from-scratch TCP stack"
    echo "  echo   -> $(printf '%s' "$out" | grep -o 'NETCON_LINK_OK' | head -1)"
    echo "  mem    -> $(printf '%s' "$out" | grep 'phys mem:' | head -1)"
    echo "  cpu    -> $(printf '%s' "$out" | grep 'cpus online:' | head -1)"
    echo "  uptime -> $(printf '%s' "$out" | grep 'uptime:' | head -1)"
    exit 0
else
    echo "FAIL: netcon did not return the expected responses"
    echo "----- collected output -----"; printf '%s\n' "$out"
    echo "----- guest serial (tail) -----"; tail -12 "$SLOG" 2>/dev/null
    exit 1
fi
