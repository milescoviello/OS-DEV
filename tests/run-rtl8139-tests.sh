#!/bin/sh
# In-guest assertion for the second NIC driver (kernel/rtl8139.c). Boots the real
# kernel headless under QEMU with a Realtek RTL8139 card *instead of* the e1000
# (-device rtl8139), captures COM1, and asserts the full network stack came up
# over the RTL8139: the driver bound (the boot banner names it), it read its MAC
# off the chip, and ARP + ICMP echo to the SLIRP gateway succeeded. This proves
# the RTL8139 plugs into the same net.c seam the e1000 does and really moves
# packets. Exit 0 = pass. SKIPs cleanly if QEMU is absent.
#
# Companion to run-boot-tests.sh (which boots the default e1000 path); together
# they show the NIC-agnostic stack works over either card.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_rtl8139.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: rtl8139 test ($QEMU not found)"
    exit 0
fi

echo "booting kernel headless under QEMU with an RTL8139 NIC (COM1 capture)..."
# The ONLY difference from run-boot-tests.sh is the NIC device: rtl8139, no e1000.
timeout -s KILL 25 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device rtl8139,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -device AC97,audiodev=snd0 -audiodev none,id=snd0 \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 50 ]; do
    grep -q "launching the desktop" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

fail=0
require() {
    if grep -qiF "$1" "$LOG"; then
        echo "  ok: $2"
    else
        echo "  MISSING: $2  (expected substring: '$1')"
        fail=1
    fi
}
softrequire() {
    if grep -qiF "$1" "$LOG"; then echo "  ok: $2"
    else echo "  (skip: $2 -- no marker '$1'; offline host? not fatal)"; fi
}

# The RTL8139 driver bound (the banner prints the active NIC's name) and read its
# MAC off IDR0..5 (QEMU's default RTL8139 MAC is 52:54:00:12:34:56, same OUI).
require "rtl8139 up"                          "RTL8139 driver bound + MAC read from the chip"
# The stack moved real packets over the RTL8139: ARP resolved the gateway and the
# ICMP echoes came back (this is the headline proof the card transmits+receives).
require "Networking works!"                   "RTL8139 + ARP + ICMP echo (SLIRP gateway)"
# Internet-dependent (non-fatal): a real HTTP/HTTPS GET over the RTL8139.
softrequire "200 OK"                          "TCP/HTTP GET to real example.com over RTL8139 (needs internet)"
softrequire "certverify=ok"                   "TLS 1.3 HTTPS to example.com over RTL8139 (needs internet)"
# It must still reach the desktop with no fault on the RTL8139 path.
require "launching the desktop environment"   "reached desktop launch (no fault on the RTL8139 path)"

forbid() {
    if grep -qiE "$1" "$LOG"; then
        echo "  CRASH MARKER: $2"
        grep -inE "$1" "$LOG" | head -3 | sed 's/^/      /'
        fail=1
    fi
}
forbid "panic"                       "kernel panic"
forbid "unhandled (interrupt|excep)" "unhandled exception"
forbid "page fault"                  "page fault"
forbid "general protection"          "#GP fault"
forbid "no supported NIC"            "NIC probe found nothing (rtl8139_init failed)"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest RTL8139 NIC (driver bound, MAC read, ARP+ICMP over it, no crash)"
    exit 0
else
    echo "FAIL: in-guest RTL8139 NIC test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
