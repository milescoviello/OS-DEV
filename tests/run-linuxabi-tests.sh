#!/bin/sh
# Headless assertion that OS-DEV runs a REAL Linux binary (M1938-M1939).
#
# The binary under test is built by the HOST compiler as an ordinary static-PIE
# Linux executable (tools/lx/hellofree.c, staged into the ext2 volume by
# `make build/ext2.img`). Nothing about it is built for OS-DEV -- that is the
# whole point. It enters through the `syscall` instruction, which OS-DEV's own
# ABI does not use, and issues Linux write(2) and exit_group(2).
#
# This suite can exist at all only because the Linux write() lands on the
# KERNEL console, which is mirrored to COM1 -- ring-3 print() from OS-DEV's own
# apps is not, which is why the other in-guest checks need screenshots.
#
# SKIPs cleanly if QEMU or the ext2 volume is absent. Exit 0 = pass.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
EXT2=build/ext2.img
command -v "$QEMU" >/dev/null 2>&1 || { echo "SKIP: linuxabi test ($QEMU not found)"; exit 0; }
[ -f "$EXT2" ] || { echo "SKIP: linuxabi test (no $EXT2 -- mke2fs not installed?)"; exit 0; }

SLOG=$(mktemp /tmp/osdev_lxabi.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$SLOG"; exit "$rc"; }
trap cleanup EXIT

echo "booting headless and running a host-built static-PIE Linux binary..."
# The guest's init runs `run /disk2/hellofree` via the boot command line, so no
# keyboard driving is needed -- this stays a pure COM1 assertion.
timeout -s KILL 120 "$QEMU" -no-reboot -no-shutdown -m 256M -smp 4 -kernel "$KERNEL" \
    -append "lxabitest" \
    -drive file="$DISK",format=raw,if=ide \
    -drive file="$EXT2",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -display none -serial file:"$SLOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 220 ]; do
    grep -aq "linuxabi.*guest exited" "$SLOG" 2>/dev/null && break
    sleep 0.5; i=$((i+1))
done

fail=0
# 1. the binary's OWN output, produced by a Linux write(2) through our dispatcher
if grep -aq "hello from a freestanding static-PIE Linux binary" "$SLOG"; then
    echo "  ok: a host-built Linux static-PIE binary ran and printed via Linux write(2)"
else
    echo "  FAIL: the Linux binary produced no output"; fail=1
fi
# 2. exit_group's status must arrive INTACT -- 42 proves the argument register
#    survived the whole entry path, not just that something exited
if grep -aq "guest exited with status 42" "$SLOG"; then
    echo "  ok: exit_group(42) delivered its status through the ABI"
else
    echo "  FAIL: exit_group status wrong or missing:"; grep -a "linuxabi" "$SLOG" | tail -3; fail=1
fi

[ $fail -eq 0 ] || { echo "FAIL: Linux ABI test"; exit 1; }
echo "PASS: Linux ABI — a real static-PIE Linux binary runs under OS-DEV"

# --- M1941: a ring-3 fault mid-print must be REPORTED, not swallowed --------
# Exception gates clear IF, so a fault handler runs with interrupts disabled and
# then takes the console lock. When that spin was unbounded and the lock holder
# sat on the same core, the machine deadlocked AND the fault report vanished --
# the worst possible combination. /disk2/hellolibc faults reliably (glibc
# executes an AVX instruction, which is not enabled yet), so it makes a clean
# trigger for exactly that shape.
# The first QEMU is still alive here (its loop broke on a marker, it was never
# killed), and QEMU takes a WRITE LOCK on a raw drive image -- so a second
# instance opening the same ext2 volume silently fails to start and produces an
# empty log. Reap it first.
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""
SLOG2=$(mktemp /tmp/osdev_lxfault.XXXXXX.log)
QPID2=""
cleanup2() { [ -n "$QPID2" ] && { kill -9 "$QPID2" 2>/dev/null || true; wait "$QPID2" 2>/dev/null || true; }; rm -f "$SLOG2"; }
trap 'rc=$?; cleanup2; exit $rc' EXIT

echo "booting with a deliberately-faulting Linux binary (console-lock deadlock regression)..."
timeout -s KILL 120 "$QEMU" -no-reboot -no-shutdown -m 256M -smp 4 -kernel "$KERNEL" \
    -append "lxfaulttest" \
    -drive file="$DISK",format=raw,if=ide \
    -drive file="$EXT2",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -display none -serial file:"$SLOG2" >/dev/null 2>&1 &
QPID2=$!
# 280s, not 110s. This boot now launches TWO glibc binaries that both fault
# under the default (no-AVX) CPU, and each fault dumps its registers over the
# serial console, which is slow. At the old budget the loop expired under
# full-suite load and the test reported a wedge that had not happened.
i=0
while [ $i -lt 560 ]; do
    grep -aq "boot network self-test finished" "$SLOG2" 2>/dev/null && break
    sleep 0.5; i=$((i+1))
done

f2=0
if grep -aq "\[fault\].*ring-3 task" "$SLOG2"; then
    echo "  ok: the ring-3 fault was REPORTED (the console lock did not swallow it)"
else
    echo "  FAIL: no [fault] line -- the report was swallowed (console-lock deadlock?)"; f2=1
fi
# The boot must still REACH THE END. Under the old unbounded spin it stopped
# dead mid-listing at ~78 lines with all cores wedged.
if grep -aq "boot network self-test finished" "$SLOG2"; then
    echo "  ok: the boot ran to completion despite the fault (no deadlock)"
else
    # Say what was OBSERVED, not what it means. The previous wording asserted
    # "wedged", and the one time it fired the boot had merely been slow.
    echo "  FAIL: the boot did not reach its end marker within the budget ($(wc -l < "$SLOG2") log lines; a full boot is ~306)"; f2=1
fi
[ $f2 -eq 0 ] || { echo "FAIL: console-lock/fault-reporting regression"; exit 1; }
echo "PASS: a ring-3 fault mid-print is reported and never deadlocks the console"

# --- M1942: AVX via XSAVE ---------------------------------------------------
# Real Linux binaries contain AVX: glibc's _dl_aux_init opens with
# `vpxor %xmm0,%xmm0,%xmm0`, which #UDs unless CR4.OSXSAVE is set and XCR0
# enables the SSE+AVX state.
#
# This MUST run under -cpu max. QEMU's default model has no AVX at all, so the
# XSAVE path would otherwise never execute in the whole suite -- a green run
# proving nothing about the code it was added for.
if qemu-system-x86_64 -cpu help 2>/dev/null | grep -q '^  max'; then
    SLOG3=$(mktemp /tmp/osdev_lxavx.XXXXXX.log)
    kill -9 "$QPID2" 2>/dev/null || true; wait "$QPID2" 2>/dev/null || true; QPID2=""
    QPID3=""
    cleanup3() { [ -n "$QPID3" ] && { kill -9 "$QPID3" 2>/dev/null || true; wait "$QPID3" 2>/dev/null || true; }; rm -f "$SLOG3"; }
    trap 'rc=$?; cleanup3; exit $rc' EXIT

    echo "booting with -cpu max to exercise the XSAVE/AVX path..."
    # nonetdemo: -cpu max under TCG has to EMULATE AVX and is far slower, and the
    # boot network self-test does a real TLS handshake (bignum RSA/ECDSA) on top
    # of that. Skipping it keeps this boot to the part being tested.
    timeout -s KILL 300 "$QEMU" -cpu max -no-reboot -no-shutdown -m 256M -smp 4 -kernel "$KERNEL" \
        -append "lxfulltest nonetdemo" \
        -drive file="$DISK",format=raw,if=ide \
        -drive file="$EXT2",format=raw,if=ide \
        -netdev user,id=net0 -device e1000,netdev=net0 \
        -display none -serial file:"$SLOG3" >/dev/null 2>&1 &
    QPID3=$!
    # Wait for the OUTCOME being asserted, not for an unrelated later marker.
    # The first version waited on "boot network self-test finished" -- which
    # happens long AFTER the libc launch -- so under full-suite load the loop
    # expired before the boot even got there and the test failed with glibc
    # having neither reached brk nor faulted. Waiting on either real outcome
    # makes it terminate as soon as the answer exists, pass or fail.
    i=0
    while [ $i -lt 560 ]; do
        grep -aqE "unimplemented Linux syscall 12|Invalid Opcode|KERNEL PANIC" "$SLOG3" 2>/dev/null && break
        sleep 0.5; i=$((i+1))
    done

    f3=0
    # A kernel panic must be called out as such. The swapgs-pairing bug (M1943)
    # first showed up here as "glibc never reached brk", which was true but
    # buried the real event: a DOUBLE FAULT in the syscall entry stub.
    if grep -aq "KERNEL PANIC" "$SLOG3"; then
        echo "  FAIL: KERNEL PANIC during a Linux syscall:"
        grep -a -A2 "KERNEL PANIC" "$SLOG3" | head -3
        f3=1
    fi
    if grep -aq "XSAVE+AVX enabled" "$SLOG3"; then
        echo "  ok: XSAVE+AVX armed on a CPU that has it ($(grep -ao 'state area [0-9]* bytes' "$SLOG3" | head -1))"
    else
        echo "  FAIL: XSAVE/AVX was not enabled under -cpu max"; f3=1
    fi
    # The real proof is BEHAVIOURAL: glibc must now get PAST the AVX instruction
    # in _dl_aux_init. It does that by reaching its first real syscall, brk(12).
    # Asserting "no Invalid Opcode" alone would also pass if the binary never ran.
    # A real LIBC binary, end to end: glibc startup (TLS, malloc, stdio), a
    # printf that must report the argc/argv OUR stack built, and a clean exit
    # with the right status. This is the assertion that actually proves the
    # SysV initial stack and the syscall set, rather than just "it started".
    if grep -aq "static-PIE LIBC binary: argc=1 argv0=/disk2/hellolibc" "$SLOG3"; then
        echo "  ok: a real GLIBC binary ran printf() and read argc/argv from our SysV stack"
    else
        echo "  FAIL: the glibc binary did not print its argc/argv:"; grep -a "static-PIE LIBC" "$SLOG3" | head -1; f3=1
    fi
    # Real file I/O through glibc stdio onto the ext2 volume: openat, write,
    # read, lseek, close and newfstatat, all exercised by fopen/fprintf/fgets/
    # stat rather than by calling the syscalls directly.
    # dir entries>0 matters: opendir() needs openat on a directory, fstat on
    # that fd, AND getdents64 -- three separate things, and a failure in any of
    # them silently yields zero entries rather than an error.
    if grep -aqE "LXIO: wrote\+read 200 lines / 1690 bytes, stat size=1690, dir entries=[1-9]" "$SLOG3"; then
        echo "  ok: glibc stdio wrote+re-read a 200-line file on ext2 AND listed the directory"
    else
        echo "  FAIL: glibc file I/O wrong:"; grep -a "LXIO:" "$SLOG3" | head -1; f3=1
    fi
    # Phase 3's deliverable: a REAL PIPELINE between two processes. lxbox forks,
    # re-execs ITSELF twice with different argv, wires the halves with a pipe
    # and wait4s both. The COUNT is the assertion -- "pipeline done" alone
    # passed for a long time while the reader was getting no data at all, and
    # at one point while both children were running the WRITER applet.
    # ONE line, from the PARENT, carrying the reader's count back through
    # wait4. wc=4 proves the whole chain at once: fork, execve of itself with a
    # different argv, dup2 onto stdin/stdout, 19 bytes across a real pipe, a
    # clean EOF, and a non-zero exit status delivered by wait4. The reader's own
    # console output is deliberately NOT asserted -- it proved intermittently
    # lossy under load, and an assertion on it was flaky for a reason that had
    # nothing to do with the pipeline.
    if grep -aq "LXBOX: pipeline wc=4 writer=0" "$SLOG3"; then
        echo "  ok: fork+execve+dup2+pipe: reader counted all 4 lines, status returned via wait4"
    else
        echo "  FAIL: the pipeline did not deliver 4 lines:"; grep -a "LXBOX" "$SLOG3" | head -2; f3=1
    fi
    # mmap: the two shapes a dynamic linker needs. MAP_FIXED (an address the
    # caller chose) and file-backed AT AN OFFSET. The offset test asserts the
    # BYTES, not just success -- a mapping that silently ignores the offset
    # succeeds and hands back the wrong page, which is the bug worth catching.
    if grep -aq "LXMMAP: MAP_FIXED honoured" "$SLOG3"; then
        echo "  ok: mmap honoured MAP_FIXED at the caller's address"
    else
        echo "  FAIL: MAP_FIXED not honoured:"; grep -a "LXMMAP" "$SLOG3" | head -1; f3=1
    fi
    if grep -aq "LXFMAP: file-backed mmap at offset 8192 read the right page" "$SLOG3"; then
        echo "  ok: file-backed mmap at a non-zero offset read the correct page"
    else
        echo "  FAIL: file-backed mmap offset wrong:"; grep -a "LXFMAP" "$SLOG3" | head -1; f3=1
    fi
    if grep -aq "guest exited with status 7" "$SLOG3"; then
        echo "  ok: it exited cleanly through exit_group with the right status"
    else
        echo "  FAIL: the glibc binary never exited cleanly:"; grep -a "guest exited\|fault\]" "$SLOG3" | head -2; f3=1
    fi
    # NOTE: an earlier version asserted "unimplemented Linux syscall 12" here,
    # as a proxy for "glibc got past the AVX instruction". That was an assertion
    # about a TRANSIENT SYMPTOM and it broke the moment brk was implemented --
    # the two checks above supersede it, because a binary that printf'd its own
    # argc and exited with the right status has self-evidently got past AVX.
    if grep -aq "Invalid Opcode" "$SLOG3"; then
        echo "  FAIL: an Invalid Opcode fault occurred (AVX not usable?):"
        grep -a "Invalid Opcode" "$SLOG3" | head -1; f3=1
    fi
    [ $f3 -eq 0 ] || { echo "FAIL: XSAVE/AVX test"; exit 1; }
    echo "PASS: a real GLIBC static-PIE binary runs under OS-DEV (AVX via XSAVE, SysV auxv stack, clean exit)"
else
    echo "SKIP: XSAVE/AVX test (this QEMU has no -cpu max)"
fi
