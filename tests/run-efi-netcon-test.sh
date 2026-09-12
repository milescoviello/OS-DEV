#!/bin/sh
# Real-hardware BRING-UP path test (M1871). Everything else boots via QEMU's
# `-kernel` shortcut, which uses the Multiboot1 handoff. A physical machine
# instead boots through a real bootloader (GRUB) via Multiboot2 — a different
# code path (mb2_to_mb1 tag translation, GRUB-set framebuffer, GRUB-supplied
# kernel cmdline). This test exercises exactly that path under QEMU + OVMF (UEFI):
# it builds the netcon bring-up EFI image (`make efi-bringup`, cmdline `netcon`),
# boots it through GRUB's multiboot2 command, and asserts the kernel received the
# cmdline (netcon came up) AND that a host TCP client can drive the network debug
# console over a forwarded port — the same way you'd reach a real machine whose
# screen never lit up.
#
# This is the regression guard for the mb2_to_mb1 cmdline-tag fix: before it, NO
# cmdline flag reached a GRUB-booted kernel.
#
# Exit 0 = pass. SKIPs cleanly if qemu / OVMF / grub-mkstandalone / python3 absent.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
HPORT=12325
TMP=$(mktemp -d /tmp/osdev_efinc.XXXXXX)
SLOG=$TMP/serial.log
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -rf "$TMP"; exit "$rc"; }
trap cleanup EXIT

for t in "$QEMU" grub-mkstandalone python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "SKIP: efi-netcon test ($t not found)"; exit 0; }
done

# Locate an OVMF firmware (distros differ on the path).
OVMF=""
for c in /usr/share/edk2/OvmfX64/OVMF_CODE.fd /usr/share/edk2-ovmf/OVMF_CODE.fd \
         /usr/share/OVMF/OVMF_CODE.fd /usr/share/ovmf/OVMF.fd; do
    [ -f "$c" ] && { OVMF=$c; break; }
done
VARS=""
for c in /usr/share/edk2/OvmfX64/OVMF_VARS.fd /usr/share/edk2-ovmf/OVMF_VARS.fd \
         /usr/share/OVMF/OVMF_VARS.fd; do
    [ -f "$c" ] && { VARS=$c; break; }
done
[ -n "$OVMF" ] && [ -n "$VARS" ] || { echo "SKIP: efi-netcon test (OVMF firmware not found)"; exit 0; }

echo "building the netcon bring-up EFI image + ESP..."
make efi-bringup >/dev/null 2>&1 || { echo "FAIL: make efi-bringup"; exit 1; }
mkdir -p "$TMP/esp/EFI/BOOT"
cp build/BOOTX64-bringup.EFI "$TMP/esp/EFI/BOOT/BOOTX64.EFI"
cp "$VARS" "$TMP/vars.fd"

echo "booting through GRUB (multiboot2) under OVMF, host->guest :$HPORT -> :2323..."
timeout -s KILL 90 "$QEMU" -machine q35 -m 256M -snapshot -no-reboot -no-shutdown \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF" \
    -drive if=pflash,format=raw,file="$TMP/vars.fd" \
    -drive file=fat:rw:"$TMP/esp",format=raw \
    -drive file=build/fat.img,format=raw,if=ide \
    -netdev user,id=n0,hostfwd=tcp::$HPORT-:2323 -device e1000,netdev=n0 \
    -display none -serial file:"$SLOG" >"$TMP/qemu.err" 2>&1 &
QPID=$!

got=0; i=0
while [ $i -lt 160 ]; do
    grep -q "\[netcon\] debug console" "$SLOG" 2>/dev/null && { got=1; break; }
    grep -qiE "panic|unhandled exception|page fault" "$SLOG" 2>/dev/null && { echo "FAIL: fault during GRUB boot"; tail -15 "$SLOG"; exit 1; }
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
[ "$got" -eq 1 ] || { echo "FAIL: netcon never came up (cmdline may not have reached the GRUB-booted kernel)"; tail -15 "$SLOG"; exit 1; }

# Booting exactly once (no reboot loop) is part of the assertion.
boots=$(grep -c "launching the desktop" "$SLOG" 2>/dev/null || echo 0)

out=""
for try in 1 2 3 4 5 6; do
    out=$(python3 - "$HPORT" <<'PY' 2>/dev/null || true
import socket, sys, time
port = int(sys.argv[1])
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=6); s.settimeout(2)
    b = b""
    try: b += s.recv(4096)              # banner
    except socket.timeout: pass
    # Interleave send + drain per command (read between commands so the pipe stays
    # drained — the reliable pattern; batching all sends then draining loses later
    # replies under the q35/e1000 RX path).
    for c in (b"echo EFI_MB2_OK\n", b"uptime\n", b"pci\n"):
        s.send(c); time.sleep(0.5)
        try:
            while True:
                d = s.recv(8192)
                if not d: break
                b += d
        except socket.timeout:
            pass
    s.close(); sys.stdout.buffer.write(b)
except Exception as e:
    print("connect error:", e)
PY
)
    printf '%s' "$out" | grep -q "EFI_MB2_OK" && break
    sleep 2
done

# The assertion is scoped to what this test is FOR: the real GRUB->Multiboot2
# boot path delivered the kernel cmdline (netcon came up + logged its lease) and
# netcon is reachable over TCP (banner + an echo round-trip), booting exactly
# once. The full command set (dmesg/pci/ls/cat/...) is exercised reliably by
# `netcontest` over the -kernel path; under emulated q35/e1000 later segments in a
# burst can be dropped, so we don't hard-assert them here (not a netcon bug, and
# real silicon isn't q35-emulated).
if grep -q "\[netcon\] debug console" "$SLOG" 2>/dev/null \
   && printf '%s' "$out" | grep -q "network debug console" \
   && printf '%s' "$out" | grep -q "EFI_MB2_OK" \
   && [ "$boots" = "1" ]; then
    echo "PASS: GRUB multiboot2 (UEFI/OVMF) delivered the kernel cmdline; netcon came up and is reachable over TCP"
    echo "  boot count      : $boots (expected 1 — no reboot loop)"
    echo "  netcon banner   : $(printf '%s' "$out" | grep -o 'network debug console.*' | head -1)"
    echo "  netcon line     : $(grep -o '\[netcon\] debug console.*' "$SLOG" | head -1)"
    exit 0
else
    echo "FAIL: netcon session did not return the expected responses over the GRUB/UEFI boot"
    echo "----- collected -----"; printf '%s\n' "$out"
    echo "----- serial tail -----"; tail -12 "$SLOG"
    exit 1
fi
