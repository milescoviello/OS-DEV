#!/bin/sh
# In-guest assertion for the paravirtual NIC driver (kernel/virtio_net.c). Boots
# the real kernel headless under QEMU with a LEGACY virtio-net-pci card *instead
# of* the e1000 (-device virtio-net-pci,disable-modern=on,disable-legacy=off),
# captures COM1, and asserts the full network stack came up over virtio-net: the
# driver bound (the boot banner names it), it read its MAC out of the device's
# config space, and ARP + ICMP echo to the SLIRP gateway succeeded. This proves
# virtio-net plugs into the same net.c seam the e1000/RTL8139 do and really moves
# packets through its RX/TX virtqueues. Exit 0 = pass. SKIPs cleanly if QEMU is
# absent.
#
# Completes the in-guest NIC trio: run-boot-tests.sh (e1000), run-rtl8139-tests.sh
# (RTL8139), and this (virtio-net) all boot the SAME NIC-agnostic stack over a
# different card.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_virtionet.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: virtio-net test ($QEMU not found)"
    exit 0
fi

echo "booting kernel headless under QEMU with a legacy virtio-net NIC (COM1 capture)..."
# The ONLY difference from run-boot-tests.sh is the NIC device: a legacy
# virtio-net-pci, no e1000. disable-modern=on forces the legacy I/O-port
# transport the driver speaks.
timeout -s KILL 25 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0,disable-modern=on,disable-legacy=off \
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

# The virtio-net driver brought the device up and read its MAC out of the legacy
# device config space (QEMU's default virtio-net MAC is 52:54:00:12:34:56).
require "virtio-net up"                       "virtio-net driver up + MAC read from device config"
# The dispatcher bound virtio-net as the active NIC (no e1000/rtl8139 present),
# so the whole stack ran over it.
require "virtio-net up. our MAC"              "net.c bound virtio-net as the active NIC"
# The stack moved real packets over virtio-net: ARP resolved the gateway and the
# ICMP echoes came back (this is the headline proof RX/TX virtqueues work).
require "Networking works!"                   "virtio-net + ARP + ICMP echo (SLIRP gateway)"
# Internet-dependent (non-fatal): a real HTTP/HTTPS GET over virtio-net.
softrequire "200 OK"                          "TCP/HTTP GET to real example.com over virtio-net (needs internet)"
softrequire "certverify=ok"                   "TLS 1.3 HTTPS to example.com over virtio-net (needs internet)"
# It must still reach the desktop with no fault on the virtio-net path.
require "launching the desktop environment"   "reached desktop launch (no fault on the virtio-net path)"

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
forbid "no supported NIC"            "NIC probe found nothing (virtio_net_init failed)"

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest virtio-net NIC (driver bound, MAC read, ARP+ICMP over it, no crash)"
    exit 0
else
    echo "FAIL: in-guest virtio-net NIC test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
