#!/bin/sh
# In-guest boot smoke assertion. Boots the real kernel headless under QEMU
# (COM1 -> a log), then asserts every critical bring-up marker is present and
# that no fault/panic occurred. Unlike the host suites (which #include one .c
# in isolation), this exercises the whole kernel + driver stack end to end:
# preemption, address-space isolation, PCI enumeration, the e1000/IP/TCP stack
# (ARP + ICMP + a real HTTP GET over SLIRP), the FAT32 driver, the AC'97 audio
# bring-up, and the USB tablet. Exit 0 = pass.
#
# QEMU was unavailable for many milestones (a SIGSTKFLT launch failure), which
# is why so much landed host-verified only; this guard makes the boot a gated
# regression again now that it runs.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
LOG=$(mktemp /tmp/osdev_boot.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$LOG"; exit "$rc"; }
trap cleanup EXIT

if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "SKIP: boot test ($QEMU not found)"
    exit 0
fi

echo "booting kernel headless under QEMU (COM1 capture)..."
# Capture COM1 to a file and poll it in two stages, rather than always burning
# a fixed cap. Stage 1: wait for "launching the desktop" -- net_demo() now runs
# as a background kernel task (spawned just before it, boot-time optimization:
# a real internet round-trip no longer blocks reaching the desktop), so this
# now lands quickly. Stage 2: net_demo's ARP/ping/HTTP/TLS output streams in
# concurrently and can trail the desktop hand-off by several seconds (a real
# TLS 1.3 handshake is bignum-heavy under TCG) -- so wait a bit longer for
# EITHER its success or failure marker before capturing the log, or the
# softrequire checks below would always report "skip" even on an online host.
# The outer timeout is a generous safety net either way. SIGKILL because
# -no-shutdown ignores SIGTERM.
#
# M1909: the stage-2 bound and this cap were both raised (20s->45s wait, 25s->60s
# cap) because the require_either checks below turned "neither outcome printed"
# from tolerated into FATAL. Measured on this host: terminal lines at 2.0s online
# and 6.6s fully blackholed (-netdev user,restrict=on), so 45s has wide margin --
# but a firewall that DROPs rather than refuses is slower than SLIRP, and a
# false-positive hang report would be worse than the flake it replaces. Costs
# nothing normally: the poll loop breaks as soon as the marker lands.
timeout -s KILL 60 "$QEMU" -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -append selftest \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -device AC97,audiodev=snd0 -audiodev none,id=snd0 \
    -display none -serial file:"$LOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 50 ]; do
    grep -q "launching the desktop" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break    # QEMU exited (crash, or a stubbed binary): stop waiting
    sleep 0.5; i=$((i+1))
done
i=0
while [ $i -lt 90 ]; do
    grep -q "boot network self-test finished" "$LOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3   # let the last few lines flush
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

fail=0

# Markers that MUST appear, in the order the kernel prints them. Each is a
# distinct subsystem coming up; a missing one means that subsystem regressed.
require() {
    if grep -qiF "$1" "$LOG"; then
        echo "  ok: $2"
    else
        echo "  MISSING: $2  (expected substring: '$1')"
        fail=1
    fi
}
# Soft markers: depend on the host actually having outbound internet (the kernel
# GETs the real example.com). Reported but NOT fatal, so the gate stays green on
# an offline machine -- the SLIRP gateway ping below covers the stack regardless.
softrequire() {
    if grep -qiF "$1" "$LOG"; then echo "  ok: $2"
    else echo "  (skip: $2 -- no marker '$1'; offline host? not fatal)"; fi
}
# The soft markers above are tolerated because an offline host legitimately can't
# reach example.com -- but "offline" and "the fetch never returned at all" were
# INDISTINGUISHABLE, which is how a suspected mid-handshake stall stayed unprovable
# for a whole investigation (M1909). The kernel prints a DISTINCT line for the
# offline case, so the two are separable: net_demo() always reaches one of the two
# terminal lines per fetch. NEITHER appearing means the call did not return, which
# is a real hang and must fail. This is the permanent detector for that class.
require_either() {
    if grep -qE "$1" "$LOG" 2>/dev/null; then echo "  ok: $3"
    else
        echo "  MISSING: $3 -- neither outcome was printed, so the call never returned (a HANG, not an offline host)"
        echo "           (expected one of: $2)"
        # Dump where it actually stopped. Without this the report says "a hang"
        # and gives the reader nothing to diagnose it with -- and the whole reason
        # this check exists is that the ORIGINAL stall report was unusable for
        # exactly that reason.
        echo "           ----- guest serial, last network lines -----"
        grep -E "^\[net\]|^\[tls\]|^\[dns\]" "$LOG" 2>/dev/null | tail -8 | sed 's/^/           /'
        echo "           ----- very tail of the log -----"
        tail -4 "$LOG" 2>/dev/null | sed 's/^/           /'
        fail=1
    fi
}
require "full bring-up complete"             "core bring-up (PMM/VMM/IDT)"
# M1963: the TLB-shootdown IPI must round-trip. Asserting the ACK, not merely
# that we tried: the first version of this spun 15.9 SECONDS waiting for acks
# that never came, which would have stalled every mprotect on a threaded
# process. "timed out" in that line is the failure mode, so reject it.
require "TLB shootdown"                      "TLB shootdown self-test ran (M1963)"   # this boot is single-core, so it reports "nothing to shoot down"; the ACK is asserted on the 4-core linuxabi boot
if grep -aq "TLB shootdown timed out" "$LOG"; then
    echo "  FAIL: TLB shootdown IPI was not acknowledged -- other cores keep stale translations"
    grep -a "TLB shootdown" "$LOG" | head -2
    fail=1
fi
require "preemption works"                   "preemptive scheduler"
require "each process has its own address"   "per-process address-space isolation"
require "PCI devices on the bus"             "PCI enumeration"
require "AML method evaluation OK"           "ACPI AML method-evaluation VM (recursion/If + While, M1289)"
require "eBPF JIT OK"                         "eBPF JIT: bytecode compiled to native x86-64, == interpreter (M1290)"
require "sched: 64 sub-millisecond yields advanced vruntime"  "CFS charges sub-ms yields (M1912: a yield-spinner cannot starve a lock holder)"
require "concurrent CMOS reads from 2 tasks"  "RTC CMOS index/data pair is atomic under concurrent readers (M1913)"
require "concurrent config reads of 2 devices"  "PCI 0xCF8/0xCFC address/data pair is indivisible under concurrent readers (M1914)"
# M1915: kprintf had no lock, so two tasks logging at once spliced their lines
# together character-by-character -- corrupting the very serial log every headless
# suite greps (this project previously blamed that shape on harness timing). The
# guest emits 120 long lines from 2 tasks; the corruption is in the log STREAM, so
# only the host can check it. Long lines on purpose: with the lock removed this
# catches 41-51 splices of ~115 lines, where 48-char lines caught only ~1.
cs_n=$(grep -c '^\[cs\]' "$LOG" 2>/dev/null || true)
cs_bad=$(grep '^\[cs\]' "$LOG" 2>/dev/null | grep -c 'A.*B\|B.*A' || true)
if [ "${cs_n:-0}" -gt 0 ] && [ "${cs_bad:-0}" -eq 0 ]; then
    echo "  ok: concurrent kprintf lines are never spliced ($cs_n lines from 2 tasks, 0 mixed)"
elif [ "${cs_n:-0}" -eq 0 ]; then
    echo "  MISSING: console log-splicing check (no '[cs]' lines -- did console_selftest run?)"
    fail=1
else
    echo "  MISSING: $cs_bad of $cs_n concurrent kprintf lines were SPLICED -- the console lock is not serialising whole lines"
    grep '^\[cs\]' "$LOG" | grep 'A.*B\|B.*A' | head -2 | cut -c1-100 | sed 's/^/           /'
    fail=1
fi
require "Networking works!"                  "e1000 + ARP + ICMP echo (SLIRP gateway)"
softrequire "200 OK"                         "TCP/HTTP GET to real example.com (needs internet)"
softrequire "certverify=ok"                  "TLS 1.3 HTTPS to example.com: chain validated + certverify (needs internet)"
# M1911: key on net_demo's single unconditional completion marker rather than on
# the HTTP/TLS outcome lines. Those lines are skipped entirely by the function's
# EARLY RETURNS (no NIC, ARP timeout), so keying on them reported a clean early
# exit as a hang -- a false positive in the M1909 check, found by starving the
# task until ARP timed out. This marker is printed on every path, so its absence
# means the self-test genuinely never returned.
require_either "boot network self-test finished" \
               "'[net] boot network self-test finished' (printed on EVERY path)" \
               "the boot network self-test RETURNED (it did not hang mid-handshake)"
require "mounted FAT32 volume"               "FAT32 mount"
    require "ATA read cache: fill+hit+write-invalidate coherent"  "ATA single-sector read cache (fill/hit/write-invalidate coherence, M1855)"
    require "I/O APIC at 0x"  "I/O APIC detected + mapped + routing primitives verified (M1856)"
    # M1890: every live ISA line (PIT tick, keyboard, serial) is delivered via the
    # I/O APIC with GSI + polarity/trigger taken from the ACPI MADT, and the NIC's
    # PCI IRQ is routed with the PCI electrical configuration (level/active-low),
    # which the old edge/active-high-only routing could not express. That the boot
    # gets this far at all is the proof the PIT tick still arrives (the scheduler
    # heartbeat) via the LAPIC-EOI path.
    require "routed via the I/O APIC"          "ISA IRQs (PIT/keyboard/serial) moved onto the I/O APIC + LAPIC-EOI (live delivery, M1857/M1890)"
    require "polarity/trigger from the ACPI MADT"  "redirection entries honour the MADT override flags, not assumed edge/active-high (M1890)"
    require "I/O APIC, level/active-low"       "e1000 PCI IRQ routed via the I/O APIC as level-triggered/active-low (M1890)"
require "AC'97 audio: NAM="                  "AC'97 audio bring-up"
require "USB tablet active"                  "USB UHCI + tablet"
require "launching the desktop environment"  "reached desktop launch"

# Markers that must NOT appear: a crash anywhere in the boot.
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

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest boot (14 required bring-up markers present, no crash)"
    exit 0
else
    echo "FAIL: in-guest boot smoke test"
    echo "----- captured COM1 log -----"
    cat "$LOG"
    exit 1
fi
