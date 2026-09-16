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
# -smp 2 (M2065): every concurrency self-test this boot runs -- CFS vruntime
# charging, the CMOS and PCI config register pairs, kprintf line serialisation,
# and now the TLB shootdown -- is ABOUT two cores racing, and they were all
# being run on one. A single-core boot cannot fail any of them, which made a
# green result mean less than it read. The TLB shootdown check is the first one
# that says so out loud: on one core it prints "nothing to shoot down".
timeout -s KILL 60 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -smp 2 -kernel "$KERNEL" \
    -append "selftest termtest" \
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
# ...and for the desktop to hand out its windows, which happens on the first
# iteration of its event loop. Without this the Shell-window assertion below
# would be racing the kill (M2076).
i=0
while [ $i -lt 40 ]; do
    grep -q "window for 'Shell'" "$LOG" 2>/dev/null && break
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
# M2065: a TLB shootdown that times out printed "they will flush on next entry"
# and then, one line later, zeroed every per-core flag -- "give up cleanly: owe
# nothing". Both cannot be true, and clearing them is what made the message a
# lie: the only record that a core still held a stale translation was thrown
# away, so nothing would ever flush it. The obligation now survives, and every
# kernel entry plus every timer tick pays it. Reverting the one line makes the
# last check below report "only 0 of 3 non-acking core(s) still owe a flush".
require "still owe a flush after the timeout"  "a TLB shootdown that times out KEEPS the flush obligation (M2065)"
require "shootdown nobody answered reports failure"  "...and reports failure rather than success, so a caller does not free a frame another core still maps (M2065)"
require "TLBSELFTEST PASSED"                   "the TLB shootdown self-test (M2065)"
# M2072: app_reap frees the address space, every memfd mapping, the main task
# and every thread -- with no serialisation, while being called from four
# places including the window manager's loop AND a parent inside wait4. Two
# cores tore the same process down and kfree was handed the heap's own poison:
#   [0] kfree+0x40 [1] task_free+0x2c [2] app_reap+0x602 [3] app_reap_children_of
# Claude Code spawns git children and wait4()s them while the WM sweeps the
# same slots, so it hit this constantly. Remove the one-line atomic claim and
# the first two checks below fail.
require "a second reaper is turned away"       "only ONE reaper may tear a process down (M2072)"
require "the slot is still allocated"          "...and a turned-away reaper changes nothing (M2072)"
require "REAPSELFTEST PASSED"                  "the one-reaper self-test (M2072)"
if grep -aq "^\[reaptest\] FAIL" "$LOG"; then
    echo "  FAIL: the one-reaper self-test reported a failing check"
    grep -a "^\[reaptest\] FAIL" "$LOG" | head -3 | sed 's/^/           /'
    fail=1
fi
if grep -aq "^\[tlbtest\] FAIL" "$LOG"; then
    echo "  FAIL: the TLB shootdown self-test reported a failing check"
    grep -a "^\[tlbtest\] FAIL" "$LOG" | head -3 | sed 's/^/           /'
    fail=1
fi
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
# M2057: THE TERMINAL, asserted on CELLS. Everything the VT/ANSI layer got
# wrong was invisible to every test this project had, because its only output
# is pixels and the only way anyone checked was to look at a screenshot -- a
# dropped escape sequence and an honoured one produced the same green tree.
# app_term_selftest drives grid_write on a scratch grid and reads the cells
# back. Each of these was verified to FAIL when its fix is reverted.
require "20 chars on the last row does not scroll"  "deferred right-margin wrap: a full-width row does not line-feed (M2057)"
require "SGR 41 sets a cell background"             "per-cell background colour exists at all (M2057)"
require "SGR 7 inverts, SGR 27 restores"            "inverse video, which is how a TUI draws a selected row (M2057)"
require "a 27-byte SGR leaves no literal text"      "a combined fg+bg truecolour SGR does not overflow into the grid (M2057)"
require "6n is answered with the cursor position"  "DSR: the terminal answers a cursor query instead of hanging the caller (M2057)"
require "leaving it restores the primary screen"    "the alternate screen (ESC[?1049h) saves and restores (M2057)"
require "a scroll inside a region leaves row 0 alone"  "DECSTBM scroll region: a pinned header does not scroll (M2057)"
require "TAB advances to the next 8-column stop"    "TAB is a tab, not a CP437 dither glyph one column wide (M2057)"
require "4;2m is not executed as an SGR"      "a private-mode introducer is not parsed as a parameter (M2057)"
require "TERMSELFTEST PASSED"                       "the whole terminal self-test: 34 cell-level checks (M2057)"
if grep -aq "^\[termtest\] FAIL" "$LOG"; then
    echo "  FAIL: terminal self-test reported a failing check"
    grep -a "^\[termtest\] FAIL" "$LOG" | head -5 | sed 's/^/           /'
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
# M2076: the desktop's window queue is a 32-entry ring that nothing ever
# garbage-collected, and a push into a full one was discarded silently. A boot
# that creates and reaps thirty-one short-lived processes -- the IPC self-test
# alone accounts for a dozen -- filled it with corpses, and the next spawn was
# THE SHELL. The desktop came up with no terminal, looking deliberate.
require "window for 'Shell'"                 "the SHELL GOT A WINDOW (M2076: the window queue no longer fills with dead processes)"
require "PENDQSELFTEST PASSED"               "...and the window queue reclaims exited entries rather than dropping a live app (3 checks)"

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
