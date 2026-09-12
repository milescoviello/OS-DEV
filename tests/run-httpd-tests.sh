#!/bin/sh
# In-guest HTTP SERVER test (M1304). The OS ships an `httpd` app (user/httpd.c,
# M1133) that LISTENS on TCP port 80 and serves a page via the from-scratch TCP
# server (net_tcp_serve) -- but it had no automated test. This boots the real
# kernel headless with a host->guest port forward (host:18080 -> guest:80), types
# `httpd` into the shell (which spawns the app), then curls the forwarded port
# FROM THE HOST and asserts the served page comes back. The host's curl output IS
# the assertion -- no guest-side serial marker needed. It proves the OS can accept
# an INBOUND TCP connection and serve a response end to end (passive open ->
# SYN-ACK -> read request -> send response -> close), the inbound counterpart of
# the outbound client the boot test already exercises.
#
# Exit 0 = pass. SKIPs cleanly if qemu/socat/curl are absent.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
HPORT=18080                       # host port forwarded to the guest's httpd (:80)
TMP=$(mktemp -d /tmp/osdev_httpd.XXXXXX)
SOCK=$TMP/mon.sock
SLOG=$TMP/serial.log
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -rf "$TMP"; exit "$rc"; }
trap cleanup EXIT

for t in "$QEMU" socat curl; do
    command -v "$t" >/dev/null 2>&1 || { echo "SKIP: httpd test ($t not found)"; exit 0; }
done

echo "booting kernel headless with a host->guest :$HPORT -> :80 forward..."
# Deliberately booted in the DEFAULT configuration (boot network self-test on):
# a suite that tests httpd should test it on the machine users get. An earlier
# hypothesis blamed the flakiness on that self-test starving ring-3 and this suite
# booted with `-append nonetdemo`; measurement rejected it (6/6 with the demo on).
timeout -s KILL 360 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0,hostfwd=tcp::$HPORT-:80 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -display none -serial file:"$SLOG" \
    -monitor unix:"$SOCK",server,nowait >"$TMP/qemu.err" 2>&1 &
QPID=$!

i=0; while [ ! -S "$SOCK" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
[ -S "$SOCK" ] || { echo "FAIL: QEMU monitor socket never appeared"; cat "$TMP/qemu.err"; exit 1; }

got=0; i=0
while [ $i -lt 80 ]; do
    grep -q "launching the desktop" "$SLOG" 2>/dev/null && { got=1; break; }
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
[ "$got" -eq 1 ] || { echo "FAIL: never reached desktop"; tail -6 "$SLOG"; exit 1; }
sleep 1.5

# Type `httpd<Enter>` into the focused Shell window (topmost at boot); the shell
# spawns the httpd app, which starts listening on TCP 80.
sendkey() { printf 'sendkey %s\n' "$1" | socat - UNIX-CONNECT:"$SOCK" >/dev/null 2>&1 || true; sleep 0.25; }
listening() { grep -q "tcp listening on port 80" "$SLOG" 2>/dev/null; }

# The launch is a RACE the harness cannot observe from outside: keystrokes are
# injected at a fixed delay after the desktop marker, and a key delivered before
# the Shell window is ready to consume it is simply lost -- so httpd never starts
# and every later curl fails against nothing, which the old code reported as "host
# curl did not receive the expected responses" (blaming the HTTP path for a lost
# keypress). Two changes, both M1909:
#   1. Wait for a real kernel-side listen marker ([net] tcp listening on port 80,
#      printed from the accept path) instead of a fixed `sleep 2` guess.
#   2. If it does not appear, RETYPE the command rather than failing. `ret` first,
#      so any partial line left by a half-delivered attempt is executed (and
#      errors) instead of being prefixed onto the retry.
# Only when several launch attempts all fail to reach accept() do we call it a
# failure -- and then say specifically that the app never launched.
launched=0
for attempt in 1 2 3; do
    [ "$attempt" -gt 1 ] && { echo "  (httpd did not come up; retyping the command, attempt $attempt)"; sendkey ret; }
    for c in h t t p d; do sendkey "$c"; done
    sendkey ret
    i=0
    while [ $i -lt 30 ]; do          # ~15s per attempt
        listening && { launched=1; break; }
        kill -0 "$QPID" 2>/dev/null || break
        sleep 0.5; i=$((i+1))
    done
    [ "$launched" -eq 1 ] && break
    kill -0 "$QPID" 2>/dev/null || break
done
if [ "$launched" -ne 1 ]; then
    echo "FAIL: httpd never started listening after 3 launch attempts (the app did not launch — NOT a request-path or TCP problem)"
    echo "----- guest serial (tail) -----"; tail -12 "$SLOG" 2>/dev/null | sed 's/^/      /'
    exit 1
fi

# curl the forwarded port from the host, retrying to land inside a listen window
# (net_tcp_serve loops with ~3s windows; a missed SYN just retries). The three
# fetches (dashboard / a real file / a 404) are wrapped in an OUTER retry too,
# not just each one's own inner loop: sustained disk contention right after
# M1541's ata_lock landed (the desktop's Files panel and httpd's own file
# reads serializing on the same lock) could occasionally leave the SECOND or
# THIRD request short of its own retry budget even though the first
# succeeded -- a real, reduced-but-not-zero residual after the lock was made
# to yield instead of pure-spin and its timeout budget was tightened (see the
# osdev-ata-pio-busywait-flakiness memory). Retrying the whole sequence a
# couple of times absorbs that without weakening any assertion below.
# Bail out with an ACCURATE message if the VM is gone. The retry budget below is
# (8+6+4) attempts x ~5s x 3 outer passes = up to ~270s, and the QEMU hard-kill
# used to be 70s — so on a slow run the VM was killed with most of the retries
# still queued, every remaining curl failed against nothing, and the test blamed
# "host curl did not receive the expected responses". That points at the HTTP
# server when the real cause was the harness shooting its own VM. The cap is now
# larger than the worst-case budget (it costs nothing normally: boot is ~1.5s and
# the first attempt almost always succeeds), and this guard makes the remaining
# case self-diagnosing instead of misleading.
vm_dead() { ! kill -0 "$QPID" 2>/dev/null; }

ok=0
for outer in 1 2 3; do
    if vm_dead; then
        echo "FAIL: QEMU exited before the requests completed (harness/boot problem, not the httpd path)"
        tail -12 "$SLOG" 2>/dev/null | sed 's/^/      /'
        exit 1
    fi
    out=""
    for try in 1 2 3 4 5 6 7 8; do
        out=$(curl -s --max-time 4 "http://127.0.0.1:$HPORT/" 2>/dev/null || true)
        echo "$out" | grep -q "Hello from OS-DEV" && break
        sleep 1
    done

    # Fetch a specific file by path (M1327): GET /README.TXT must return the
    # FILE's contents (parsed request -> sys_tcp_accept -> serve_file ->
    # sys_tcp_respond), not the dashboard. The asserted line is unique to it.
    file=""
    for try in 1 2 3 4 5 6; do
        file=$(curl -s --max-time 4 "http://127.0.0.1:$HPORT/README.TXT" 2>/dev/null || true)
        echo "$file" | grep -q "read by our own driver" && break
        sleep 1
    done
    # A missing file must 404 (proves per-request routing, not a canned page).
    miss=""
    for try in 1 2 3 4; do
        miss=$(curl -s --max-time 4 "http://127.0.0.1:$HPORT/NOPE.XXX" 2>/dev/null || true)
        echo "$miss" | grep -q "404" && break
        sleep 1
    done

    if echo "$out" | grep -q "Hello from OS-DEV" && echo "$out" | grep -q "README.TXT" \
       && echo "$out" | grep -q "Uptime:" && echo "$out" | grep -q "MemTotal:" \
       && echo "$out" | grep -q 'href="/README.TXT"' \
       && echo "$file" | grep -q "read by our own driver" \
       && echo "$miss" | grep -q "404"; then
        ok=1; break
    fi
    echo "  (outer retry $outer: one or more requests didn't get the expected response yet)"
done

if [ "$ok" -eq 1 ]; then
    echo "PASS: in-guest httpd served a LIVE dashboard, an individual FILE by path, and a 404 over the from-scratch TCP stack"
    echo "  GET /            -> $(echo "$out" | grep -o '<h1>[^<]*</h1>' | head -1) + live system status + a file listing"
    echo "  GET /README.TXT  -> $(echo "$file" | head -1)"
    echo "  GET /NOPE.XXX    -> 404 Not Found"
    exit 0
else
    echo "FAIL: host curl did not receive the expected responses"
    echo "----- GET / -----"; echo "$out"
    echo "----- GET /README.TXT -----"; echo "$file"
    echo "----- GET /NOPE.XXX -----"; echo "$miss"
    echo "----- guest serial (tail) -----"; tail -10 "$SLOG" 2>/dev/null
    exit 1
fi
