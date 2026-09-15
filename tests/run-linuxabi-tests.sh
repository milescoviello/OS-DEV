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
timeout -s KILL 120 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -smp 4 -kernel "$KERNEL" \
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
# 0. M1963: this boot is -smp 4, so the TLB-shootdown IPI must actually be
#    ACKNOWLEDGED by the other three cores. Asserting the ack, not merely that
#    we tried: the first version spun 15.9 SECONDS waiting for acks that never
#    came, which would have stalled every mprotect on a threaded process.
if grep -aqE "TLB shootdown IPI: [0-9]+ core\(s\) acked" "$SLOG" && ! grep -aq "TLB shootdown timed out" "$SLOG"; then
    echo "  ok: the TLB-shootdown IPI round-tripped ($(grep -ao 'core(s) acked in [0-9]*ms' "$SLOG" | head -1))"
else
    echo "  FAIL: the TLB-shootdown IPI was not acknowledged -- other cores keep stale translations:"
    grep -a "TLB shootdown" "$SLOG" | head -2; fail=1
fi
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
# 300s, not 120s: the QEMU kill has to outlast the WAIT LOOP below (280s), or
# the VM is killed while the loop is still watching for a marker that can no
# longer arrive -- which reports a wedge that did not happen. M1985 made each
# ring-3 fault print its instruction bytes, the last syscalls and a user
# backtrace; standalone that boot still finishes in ~2s, but under the parallel
# pool the console is contended and the old kill landed first.
timeout -s KILL 300 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -smp 4 -kernel "$KERNEL" \
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
    timeout -s KILL 300 "$QEMU" -cpu max -snapshot -no-reboot -no-shutdown -m 256M -smp 4 -kernel "$KERNEL" \
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
    #
    # M1965: wait for EVERY marker this boot asserts, not just one.
    #
    # The loop used to break on "LXTHREAD exit ->" alone and kill the VM 0.3s
    # later -- but this boot launches EIGHT glibc processes CONCURRENTLY, and
    # the threaded one is not reliably the last to finish. Whichever process
    # had not printed yet lost its assertion, so the suite failed on a
    # DIFFERENT line each run (the pipeline once, the dynamic binary's exit
    # status the next) while a clean manual boot showed every marker present
    # and correct. That is a harness race, not an ABI regression, and it was
    # indistinguishable from one from the outside.
    #
    # Keep the early break for a panic or a #UD: those mean the remaining
    # markers are never coming, and waiting the full timeout for them wastes
    # five minutes per run.
    lxfull_markers="XSAVE+AVX enabled
static-PIE LIBC binary: argc=1 argv0=/hellolibc
LXIO: wrote+read 200 lines
LXBOX: pipeline wc=4 writer=0
LXMMAP: MAP_FIXED honoured
LXMMAP-PROT:
LXFMAP: file-backed mmap at offset 8192 read the right page
LXVMAGAP: a 2MiB mmap next to an unaligned gap
LXSCM: memfd + SCM_RIGHTS + MAP_SHARED
LXMEMFD-RESULT:
LXNOPIE: ET_EXEC ran below 1 GiB
LXNOPIEDYN: ET_EXEC + PT_INTERP ran
LXDYN: a dynamically-linked binary ran
guest exited with status 11
LXTHREAD: 4 threads
LXEPOLL: ALL PASSED
LXLONG: ALL PASSED
LXSIG: ALL PASSED
LXWAIT: reaped 40/40 children
[lxabi] LXTHREAD exit -> 17"
    i=0
    while [ $i -lt 560 ]; do
        grep -aqE "Invalid Opcode|KERNEL PANIC" "$SLOG3" 2>/dev/null && break
        missing=0
        IFS='
'
        for m in $lxfull_markers; do
            grep -aqF "$m" "$SLOG3" 2>/dev/null || { missing=1; break; }
        done
        unset IFS
        [ "$missing" -eq 0 ] && break
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
    # Assert the VALUE, not a sentence (M2007). This used to grep for the
    # literal "XSAVE+AVX enabled", so rewording the boot log broke the test
    # while the kernel was doing more than before. XCR0 is the thing that
    # matters: bit 1 = SSE, bit 2 = AVX, and a component whose bit is clear
    # cannot be saved, restored, or written by the #UD emulator below.
    xcr0=$(grep -ao "fpu: XSAVE enabled, XCR0=[0-9a-f]*" "$SLOG3" | head -1 | sed 's/.*XCR0=//')
    if [ -n "$xcr0" ] && [ $(( 0x$xcr0 & 6 )) -eq 6 ]; then
        echo "  ok: XSAVE armed with SSE+AVX state on a CPU that has it (XCR0=$xcr0, $(grep -ao 'state area [0-9]* bytes' "$SLOG3" | head -1))"
    else
        echo "  FAIL: XSAVE/AVX was not enabled under -cpu max (XCR0='$xcr0')"; f3=1
        grep -a "fpu:" "$SLOG3" | head -2
    fi
    # GFNI, EMULATED (M2007). Every binary on this host is built -march=
    # arrowlake-s and libxul alone has 702 unconditional VGF2P8AFFINEQB sites;
    # QEMU's TCG has no GFNI and there is no /dev/kvm here, so each of those is
    # an invalid opcode. The probe carries expected vectors taken from real
    # hardware -- the claim is not "it did not crash", it is that the bytes
    # come out IDENTICAL to a machine that has the instruction, for 128-bit,
    # 256-bit and memory operands.
    if grep -aq "LXISA: GFNI ok" "$SLOG3" &&
       [ "$(grep -ac "LXISA: gfni .* matches" "$SLOG3")" -ge 3 ] &&
       ! grep -aq "LXISA: gfni .* [1-9][0-9]* byte(s) differ" "$SLOG3"; then
        echo "  ok: GFNI executes and its results are byte-identical to hardware ($(grep -ao 'gfni 256-bit result matches[^)]*)' "$SLOG3" | head -1))"
    else
        echo "  FAIL: GFNI:"; grep -a "LXISA: gfni\|LXISA: trying GFNI\|LXISA: GFNI" "$SLOG3" | head -5; f3=1
    fi
    if grep -aq "\[vexemu\] completing vgf2p8affineqb in software" "$SLOG3"; then
        echo "  ok: ...and those results came from OUR EMULATOR, not from the CPU (the #UD handler completed the instruction)"
    else
        # If a future host/emulator grows real GFNI this is not a failure -- but
        # say which of the two happened rather than passing silently.
        echo "  ok: (GFNI ran natively on this CPU -- the emulator was not needed)"
    fi
    if grep -aq "LXISA: all probed instruction sets executed" "$SLOG3"; then
        echo "  ok: every vector ISA glibc and libxul dispatch on executed here (SSE2/AVX/AVX2/FMA/AES-NI/PCLMULQDQ/GFNI/VAES)"
    else
        echo "  FAIL: a probed instruction set did not execute:"; grep -a "LXISA" "$SLOG3" | tail -6; f3=1
    fi
    # The real proof is BEHAVIOURAL: glibc must now get PAST the AVX instruction
    # in _dl_aux_init. It does that by reaching its first real syscall, brk(12).
    # Asserting "no Invalid Opcode" alone would also pass if the binary never ran.
    # A real LIBC binary, end to end: glibc startup (TLS, malloc, stdio), a
    # printf that must report the argc/argv OUR stack built, and a clean exit
    # with the right status. This is the assertion that actually proves the
    # SysV initial stack and the syscall set, rather than just "it started".
    # argv0 is "/hellolibc", NOT "/disk2/hellolibc": a Linux process sees the ext2
    # volume as its root, so M1954 strips the mount prefix from argv[0] -- without
    # that, a program re-execing itself by argv[0] asks for /disk2/disk2/... The
    # leading "/" still matters, so this is not just a suffix match.
    if grep -aq "static-PIE LIBC binary: argc=1 argv0=/hellolibc" "$SLOG3"; then
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
    # M2059 -- AN EDGE-TRIGGERED EPOLL MUST NOT LOSE AN EDGE. Our epoll is a
    # polling loop, and it only ever cleared an item's "edge already reported"
    # memory when a wait happened to OBSERVE the fd not-ready. A wake-up
    # eventfd is never observed in that state: write, wait, drain, write again
    # -- the dip to zero fell between two waits, so the second write was
    # suppressed and the waiter slept forever with the fd ready in front of it.
    # That is the shape of Claude Code's hang (every core idle, no fault in
    # minutes, the network provably fine). lxepoll drives exactly that
    # sequence, 100 times, and also checks the OPPOSITE failure -- an fd that
    # stays ready must not fire twice, or the fix has turned edge-triggered
    # into level-triggered and an event loop spins at full speed.
    if grep -aq "LXEPOLL: ALL PASSED" "$SLOG3"; then
        echo "  ok: an edge-triggered epoll edge survives an unobserved drain, 100x, on an eventfd and a pipe"
    else
        echo "  FAIL: edge-triggered epoll lost an edge:"; grep -a "LXEPOLL" "$SLOG3" | tail -3; f3=1
    fi
    # M2063 -- SIGNALS, HONOURED RATHER THAN ACKNOWLEDGED. rt_sigaction and
    # rt_sigprocmask returned 0 and did nothing, and kill/tkill/tgkill said
    # "other signals: accepted, undelivered" -- so nothing could raise
    # anything, and rt_sigaction's QUERY form handed a caller its own
    # uninitialised stack as a function pointer. lxsig checks all of it:
    # a handler that runs, a query that reports what is installed, SIG_IGN
    # discarding instead of queueing, a block that blocks and reports pending,
    # a mask query, and SIGKILL refused. Four separate fixes, each verified by
    # reverting it alone: putting rt_sigaction back fails 6 of the 9, the
    # kill path fails 3, dropping app_deliver_pending from the Linux syscall
    # return fails 2, and removing the sigset bit shift fails 2.
    if grep -aq "LXSIG: ALL PASSED" "$SLOG3"; then
        echo "  ok: rt_sigaction/rt_sigprocmask/kill are honoured -- a handler runs, a block blocks, SIG_IGN discards"
    else
        echo "  FAIL: signal dispositions are not honoured:"; grep -a "LXSIG" "$SLOG3" | grep -a FAIL | head -4; f3=1
    fi
    # M2062 -- A DIRECTORY LISTING MUST GIVE BACK THE NAME THAT IS THERE.
    # Every listing in the kernel came through one struct whose name field was
    # 32 bytes, so every filename was truncated at 31 characters -- and a
    # truncated name is not cosmetic, it is a name that does not exist. `find`
    # inside OS-DEV said it: two files under /root/.claude reported "No such
    # file or directory" at exactly 31 characters each. Claude Code names its
    # session keys with a 64-hex hash, so nearly everything it owns was
    # invisible to it. lxlongname writes 31..240-character names, lists the
    # directory, demands the bytes back exactly, and then OPENS each one by the
    # name the listing gave -- which is the operation that actually failed.
    if grep -aq "LXLONG: ALL PASSED" "$SLOG3"; then
        echo "  ok: filenames up to 240 chars round-trip through a directory listing and are openable"
    else
        echo "  FAIL: a directory listing truncated a filename:"; grep -a "LXLONG" "$SLOG3" | head -3; f3=1
    fi
    # M2025 -- the subprocess lifecycle Claude Code depends on: 40 children
    # reaped, a threaded child whose exit_group comes from a helper thread, a
    # WNOHANG poll that does not block, and ECHILD when there is nothing left.
    if grep -aq "LXWAIT: reaped 40/40 children" "$SLOG3"; then
        echo "  ok: fork/wait4 reaped 40 of 40 children"
    else
        echo "  FAIL: wait4 did not reap every child:"; grep -a "LXWAIT" "$SLOG3" | tail -3; f3=1
    fi
    if grep -aq "WNOHANG polled without blocking" "$SLOG3"; then
        echo "  ok: wait4 honoured WNOHANG instead of blocking on it"
    else
        echo "  FAIL: WNOHANG blocked:"; grep -a "LXWAIT" "$SLOG3" | tail -3; f3=1
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
    # M1954 -- THE Phase-4 unlock: a DYNAMICALLY LINKED binary. Everything
    # before this was -static-pie, built by us. This one is an ordinary
    # `gcc -o lxdyn lxdyn.c` with no flags at all: it has a PT_INTERP, and
    # running it means ld-linux-x86-64.so.2 itself executed under OS-DEV,
    # opened libc.so.6, laid out its segments and resolved its relocations.
    # That is what makes the host toolchain (as/ld/objcopy/nasm/make, all
    # dynamically linked) reachable at all.
    #
    # argc/argv0 is the assertion, not just "it ran": a program whose argv is
    # wrong got a stack the loader built by accident. ld.so is passed the
    # EXECUTABLE's argv, and getting that wrong makes it try to load itself.
    # M1965. A mapping >= 2 MiB used to be aligned up to 2 MiB AFTER its gap was
    # chosen, which could place it on top of the VMA that followed -- two VMAs
    # owning the same pages, and the first munmap freeing the frames out from
    # under the other. The assertion is on the DATA (the neighbouring region's
    # contents survive), not on addresses: an overlap that happened to do no
    # damage is not the thing being guarded against.
    if grep -aq "LXVMAGAP: a 2MiB mmap next to an unaligned gap did not alias" "$SLOG3"; then
        echo "  ok: a big anonymous mmap next to an unaligned gap did not alias its neighbour"
    else
        echo "  FAIL: a big mmap overlapped an existing mapping:"; grep -a "LXVMAGAP" "$SLOG3" | head -2; f3=1
    fi
    # M1970: NON-PIE binaries. The low 1 GiB used to be a supervisor-only
    # identity map shared into every address space, so an ET_EXEC image linked
    # at a fixed low address could not be loaded at all. Two shapes, because
    # they fail differently: static (no interpreter) and dynamic (ld.so has to
    # be told where program headers are that are NOT at base + e_phoff).
    # M1977: the wl_shm foundation, and therefore the foundation of any Wayland
    # client including Firefox -- a client puts pixels in a memfd, passes the
    # DESCRIPTOR over the socket, and both sides map it. The assertion is on
    # SHARING (a write through one mapping seen through the other), not just on
    # the transfer: a private copy would pass everything else.
    # M1998: THE ROOT DIRECTORY, asked every way a runtime knows how. Claude
    # Code refused to start with
    #     Error: Can't access working directory /: Path "/" does not exist
    # while every glibc route to the same question -- stat, lstat, statx,
    # access, open(O_DIRECTORY), opendir, realpath, chdir -- already worked.
    # Bun is Zig, and Zig resolves a path by opening it O_PATH and reading back
    # /proc/self/fd/<n>; it also reads /proc/self/cwd. Both returned ENOENT.
    # The two named checks are separate from the aggregate because they are the
    # two that were broken: an aggregate alone would let one regress silently.
    if grep -aq "LXCWD: readlink /proc/self/cwd -> /" "$SLOG3"; then
        echo "  ok: /proc/self/cwd is a readable magic link (how Zig/Bun asks where it is)"
    else
        echo "  FAIL: /proc/self/cwd:"; grep -a "LXCWD: readlink" "$SLOG3" | head -3; f3=1
    fi
    if grep -aqE "LXCWD: readlink /proc/self/fd/[0-9]+ -> /" "$SLOG3"; then
        echo "  ok: /proc/self/fd/<n> resolves a descriptor back to its path (how Zig/Bun does realpath)"
    else
        echo "  FAIL: /proc/self/fd/<n>:"; grep -a "LXCWD: readlink" "$SLOG3" | head -3; f3=1
    fi
    # An inode of ZERO is not an inode, it is "this file has no identity", and
    # the mount-point directory returned before it set one. Anything keyed on
    # (dev, ino) -- a realpath cache, a hardlink check, "is this the same file"
    # -- collides across every such directory.
    if grep -aqE "LXCWD: stat ok mode=755 dir=1 size=[0-9]+ nlink=[2-9][0-9]* ino=[1-9]" "$SLOG3"; then
        echo "  ok: the root directory reports a real inode and a link count of at least 2 ($(grep -ao 'nlink=[0-9]* ino=[0-9]*' "$SLOG3" | head -1))"
    else
        echo "  FAIL: the root's stat fields:"; grep -a "LXCWD: stat ok" "$SLOG3" | head -2; f3=1
    fi
    # mkdir -p, one component at a time, with a component named "-" -- Claude
    # Code's own path (/root/.claude/projects/-/memory) and the shape every
    # Makefile uses to build into an output tree, so this is the self-hosting
    # path too.
    if grep -aq "LXCWD: mkdir /root/lxcwd/projects/-/memory ok" "$SLOG3" && \
       grep -aq "LXCWD: wrote a file into the deepest directory" "$SLOG3"; then
        echo "  ok: a nested directory tree can be created one level at a time and written into"
    else
        echo "  FAIL: nested mkdir:"; grep -a "LXCWD: mkdir\|LXCWD: rmdir" "$SLOG3" | head -5; f3=1
    fi
    # M1999: symlink(2), link(2) and utimensat(2) all returned ENOSYS while the
    # VFS had implemented every one of them years earlier -- vfs_symlink since
    # M1146, vfs_link since M1207, vfs_utimes since M1230. Only the Linux entry
    # points were missing. Firefox links a temporary into place to make a
    # profile write atomic; Claude Code stamps every file it writes.
    if grep -aq "LXCWD: open() FOLLOWED our symlink" "$SLOG3" && \
       grep -aq "LXCWD: opened the cursor through its symlink" "$SLOG3"; then
        echo "  ok: symlink(2) creates a real ext2 symlink, and open() follows one"
    else
        echo "  FAIL: symlinks:"; grep -a "LXCWD: .*symlink\|LXCWD: cursor" "$SLOG3" | head -4; f3=1
    fi
    if grep -aq "LXCWD: hard link shares the inode" "$SLOG3"; then
        echo "  ok: link(2) makes a hard link, and both names report the same inode ($(grep -ao 'shares the inode ([0-9]*)' "$SLOG3" | head -1))"
    else
        echo "  FAIL: hard links:"; grep -a "LXCWD: .*link" "$SLOG3" | head -3; f3=1
    fi
    # The timestamp is the one that matters for self-hosting: `make` decides
    # what to rebuild by comparing mtimes, and every file here reported the
    # epoch because ext2_stat_path read the inode and threw the time away.
    if grep -aq "LXCWD: utimensat set mtime and stat read it back" "$SLOG3"; then
        echo "  ok: utimensat(2) sets a file's mtime AND stat reads the real value back (what make compares)"
    else
        echo "  FAIL: file timestamps:"; grep -a "LXCWD: utimensat" "$SLOG3" | head -2; f3=1
    fi
    if grep -aq "LXCWD: 0 probe(s) failed" "$SLOG3"; then
        echo "  ok: every root-directory probe answered (stat/lstat/statx/access/O_DIRECTORY/opendir/realpath/O_PATH/fstatat/chdir/mkdir)"
    else
        echo "  FAIL: the root-directory probe:"; grep -a "LXCWD" "$SLOG3" | grep -a "FAILED" | head -4; f3=1
    fi
    # M1999: the memory shape a JS engine needs. JavaScriptCore reserves TWICE
    # the address space it wants, rounds the result up to a large alignment,
    # and munmaps the head and the tail -- then builds every pointer it owns as
    # `base + 32-bit offset` into what is left. Both trims report success
    # whatever they actually removed, so the assertion is on USING the kept
    # range, not on the return values. A wrong split here does not fail at the
    # call: it fails much later, reading through a base that is not mapped,
    # with no syscall anywhere near the crash.
    # M2000: the anonymous shared file every Wayland client makes, step by step.
    # GDK reports this entire chain as ONE warning -- "Failed to load cursor
    # theme Adwaita" -- which names none of its four possible causes. Two were
    # real: fstat reported a memfd as a FIFO, so glibc's posix_fallocate
    # returned ESPIPE without attempting anything and the pool was never sized;
    # and F_ADD_SEALS answered EBADF although app_memfd_seal has enforced seals
    # since M1212. Each step is asserted separately because they fail
    # independently and the aggregate alone would hide which.
    if grep -aq "LXANON: posix_fallocate(4096) ok" "$SLOG3"; then
        echo "  ok: posix_fallocate sizes a memfd (a memfd is a regular FILE, not a FIFO -- fstat has to say so)"
    else
        echo "  FAIL: sizing a memfd:"; grep -a "LXANON" "$SLOG3" | head -5; f3=1
    fi
    if grep -aq "LXANON: F_ADD_SEALS ok and F_GET_SEALS reads it back" "$SLOG3"; then
        echo "  ok: F_ADD_SEALS/F_GET_SEALS on a memfd (how a client promises a compositor its pool cannot shrink)"
    else
        echo "  FAIL: memfd seals:"; grep -a "LXANON: F_" "$SLOG3" | head -3; f3=1
    fi
    if grep -aq "LXANON: 0 failure(s)" "$SLOG3"; then
        echo "  ok: memfd + seals + posix_fallocate + MAP_SHARED -- the whole wl_shm pool path a cursor theme needs"
    else
        echo "  FAIL: the anonymous-shared-file chain:"; grep -a "LXANON" "$SLOG3" | head -6; f3=1
    fi
    # POSIX SHARED MEMORY between two real processes (M2008). Firefox does not
    # treat this as optional: parent and content processes address each other
    # through a segment they open BY NAME, and when the open failed it
    # dereferenced a null pointer on purpose. shm_open(3) is literally
    # open("/dev/shm/NAME"), so the claim is that the name resolves AND that two
    # separate address spaces see the same bytes -- the handshake runs both ways
    # because a one-way check passes if the child merely inherited the mapping
    # through fork.
    if grep -aq "LXANON: TWO PROCESSES SHARE ONE /dev/shm SEGMENT BY NAME" "$SLOG3"; then
        echo "  ok: two processes share one /dev/shm segment found by name ($(grep -ao 'BY NAME ([^)]*)' "$SLOG3" | head -1))"
    else
        echo "  FAIL: POSIX shared memory:"; grep -a "LXANON: shm\|LXANON: TWO\|LXANON: the child" "$SLOG3" | head -4; f3=1
    fi
    if grep -aq "LXANON: a second O_EXCL create is refused with EEXIST" "$SLOG3" && \
       grep -aq "LXANON: shm_unlink removed the name" "$SLOG3"; then
        echo "  ok: O_EXCL and shm_unlink -- how two processes agree on which of them owns the segment"
    else
        echo "  FAIL: shm naming:"; grep -a "LXANON: shm\|O_EXCL" "$SLOG3" | head -4; f3=1
    fi
    # O_NONBLOCK ON A PIPE (M2009): the pipe was the LAST fd type here that
    # ignored it, and Firefox's main thread blocked forever in the final read of
    # its self-pipe drain loop -- taking 33 futex-waiting threads with it,
    # because only that thread could ever post their work. The probe makes every
    # would-block call in a forked child with a parent timeout, so a regression
    # reports "IT BLOCKED" instead of becoming the hang it tests for.
    if grep -aq "LXNB: THE SELF-PIPE DRAIN LOOP TERMINATES" "$SLOG3" && \
       grep -aq "LXNB: 0 failure(s)" "$SLOG3"; then
        echo "  ok: O_NONBLOCK on a pipe -- empty reads and full writes return EAGAIN, EOF still reads as EOF"
    else
        echo "  FAIL: O_NONBLOCK on a pipe:"; grep -a "LXNB" "$SLOG3" | head -8; f3=1
    fi
    # ...and the same property asked for in a socket TYPE rather than with an
    # fcntl (M2012). Firefox's IPC channel builds its socketpair with
    # SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK and then relies on what it asked
    # for; socketpair masked both flags off, so it aborted at
    # ipc_channel_posix.cc:128 without saying anything about flags.
    if grep -aq "LXNB: socketpair(SOCK_NONBLOCK|SOCK_CLOEXEC) HONOURS BOTH FLAGS" "$SLOG3"; then
        echo "  ok: socketpair honours SOCK_NONBLOCK and SOCK_CLOEXEC (queried back through the descriptor, not remembered)"
    else
        echo "  FAIL: socketpair flags:"; grep -a "LXNB: socketpair" "$SLOG3" | head -4; f3=1
    fi
    # ABSOLUTE DEADLINES (M2010). FUTEX_WAIT_BITSET's timeout is a timestamp,
    # not a duration -- that is the entire difference between it and
    # FUTEX_WAIT -- and reading it as a duration made every glibc
    # pthread_cond_timedwait a wait of 1.79e12 milliseconds. Firefox parked 66
    # threads in those and made zero syscalls for minutes. The same class,
    # opposite direction: clock_nanosleep(TIMER_ABSTIME) was collapsed to a
    # 1 ms sleep, turning "wake me at T" into a 1 kHz busy loop (1.2 million
    # syscalls in 15 seconds). So each check asserts the wait was NEITHER too
    # long NOR too short -- too long is a hang, too short is a spin.
    if grep -aq "LXTIME: pthread_cond_timedwait waited" "$SLOG3" && \
       grep -aq "LXTIME: 0 failure(s)" "$SLOG3"; then
        echo "  ok: absolute deadlines ($(grep -ao 'pthread_cond_timedwait waited [0-9]*ms for a [0-9]*ms ABSOLUTE deadline' "$SLOG3" | head -1)), and TIMER_ABSTIME does not spin"
    else
        echo "  FAIL: absolute deadlines:"; grep -a "LXTIME" "$SLOG3" | head -8; f3=1
    fi
    if grep -aq "LXCAGE: 4GiB/4GiB wrote and read back" "$SLOG3" && \
       grep -aq "LXCAGE: 0 failure(s)" "$SLOG3"; then
        echo "  ok: reserve 8 GiB, align to 4 GiB, trim head and tail -- and the kept region is still writable end to end"
    else
        echo "  FAIL: the pointer-cage shape:"; grep -a "LXCAGE" "$SLOG3" | head -6; f3=1
    fi
    if grep -aq "LXSCM: memfd + SCM_RIGHTS + MAP_SHARED" "$SLOG3"; then
        echo "  ok: fd passing + shared memory ($(grep -ao 'fd [0-9]* passed as [0-9]*, [0-9]* KiB shared both ways' "$SLOG3" | head -1))"
    else
        echo "  FAIL: memfd/SCM_RIGHTS/MAP_SHARED:"; grep -a "LXSCM" "$SLOG3" | head -2; f3=1
    fi
    # M1985: and who OWNS those shared pages. A memfd's buffer is kernel heap,
    # so mapping it aliases the heap into a process. munmap and process exit
    # both free every page they find, and close() while still mapped is the
    # DOCUMENTED way to use a memfd -- so all three have to know the process is
    # only borrowing. When they did not, the damage landed somewhere else
    # entirely: a page of ld.so's text came up zero-filled and Firefox died at
    # the first instruction of whatever function lived there.
    # M1987: an anonymous mapping has to REMEMBER that it is read-write.
    # mprotect()ing its first page splits it, and the tail inherits the
    # original's recorded protection -- which was nothing at all, i.e.
    # PROT_NONE. The first touch of a tail page then demand-faulted into a
    # non-writable PTE and the write faulted again, so the kernel killed the
    # process for writing to memory it had just granted read-write.
    if grep -aq "LXMMAP-PROT: the tail of an mprotect-split anonymous mapping is still writable" "$SLOG3"; then
        echo "  ok: the tail of an mprotect-split anonymous mapping is still writable (the VMA records its own prot)"
    else
        echo "  FAIL: an anonymous mapping lost its protection across an mprotect split:"; grep -a "LXMMAP" "$SLOG3" | head -3; f3=1
    fi
    if grep -aq "LXMEMFD-OK: the memfd's contents SURVIVED munmap" "$SLOG3"; then
        echo "  ok: a memfd's pages survive munmap + 4 MiB of churn -- the process only BORROWS the kernel's heap"
    else
        echo "  FAIL: munmap of a memfd mapping freed kernel-heap pages:"; grep -a "LXMEMFD" "$SLOG3" | head -3; f3=1
    fi
    if grep -aq "LXMEMFD-OK: the mapping OUTLIVED the last close" "$SLOG3"; then
        echo "  ok: ...and a mapping outlives the last close() of the memfd, which is how every toolkit uses one"
    else
        echo "  FAIL: closing a mapped memfd freed its buffer:"; grep -a "LXMEMFD" "$SLOG3" | head -3; f3=1
    fi
    if grep -aq "LXMEMFD-RESULT: 0 failure" "$SLOG3"; then
        echo "  ok: the memfd ownership test reported no failures"
    else
        echo "  FAIL: the memfd ownership test failed:"; grep -a "LXMEMFD" "$SLOG3" | head -4; f3=1
    fi
    if grep -aq "LXNOPIE: ET_EXEC ran below 1 GiB" "$SLOG3"; then
        echo "  ok: a non-PIE ET_EXEC binary ran at its link-time address below 1 GiB ($(grep -ao 'main=[0-9a-f]*' "$SLOG3" | head -1))"
    else
        echo "  FAIL: the non-PIE binary did not run:"; grep -a "LXNOPIE:" "$SLOG3" | head -2; f3=1
    fi
    if grep -aq "LXNOPIEDYN: ET_EXEC + PT_INTERP ran" "$SLOG3"; then
        echo "  ok: and a non-PIE DYNAMIC one -- ld.so found program headers that are not at base+e_phoff"
    else
        echo "  FAIL: the non-PIE dynamic binary did not run:"; grep -a "LXNOPIEDYN" "$SLOG3" | head -2; f3=1
    fi
    if grep -aq "LXDYN: a dynamically-linked binary ran, argc=1 argv0=/lxdyn" "$SLOG3"; then
        echo "  ok: ld-linux-x86-64.so.2 ran, mapped libc.so.6 and started a dynamic binary"
    else
        echo "  FAIL: the dynamically-linked binary did not run:"
        grep -aE "LXDYN|dynamically linked|error while loading" "$SLOG3" | head -3; f3=1
    fi
    if grep -aq "guest exited with status 11" "$SLOG3"; then
        echo "  ok: the dynamic binary exited through glibc's exit path with status 11"
    else
        echo "  FAIL: the dynamic binary did not exit cleanly:"; grep -a "guest exited" "$SLOG3" | tail -3; f3=1
    fi
    # M1959 -- REAL THREADS, via glibc's own NPTL. The shared blocker for Node,
    # Claude Code and Firefox alike, so this is the assertion that matters most
    # for everything still ahead.
    #
    # Every number in the line is load-bearing. counter=8000 proves the four
    # threads genuinely SHARED one address space (a fork would give each its own
    # copy and the total would be 2000) and that the mutex serialised them.
    # joined=406 proves pthread_join collected each thread's return value, which
    # needs set_tid_address + the futex wake on thread exit. tls=per-thread
    # proves CLONE_SETTLS gave each thread its own %fs -- without it every
    # __thread variable aliases one slot.
    if grep -aq "LXTHREAD: 4 threads, counter=8000 (want 8000), joined=406 (want 406), tls=per-thread" "$SLOG3"; then
        echo "  ok: REAL pthreads -- 4 threads, shared memory, mutex, condvar, join, per-thread TLS"
    else
        echo "  FAIL: real threads did not work:"; grep -aE "LXTHREAD|unimplemented Linux syscall (56|202|186|435)" "$SLOG3" | head -3; f3=1
    fi
    # Asserted through the EXIT STATUS, which the runner reports directly --
    # the console drops lines under load, and this boot has eight other glibc
    # processes running concurrently.
    if grep -aq "\[lxabi\] LXTHREAD exit -> 17" "$SLOG3"; then
        echo "  ok: the threaded program exited 17 after joining every thread"
    else
        echo "  FAIL: the threaded program did not exit cleanly:"; grep -a "LXTHREAD exit" "$SLOG3" | tail -2; f3=1
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
    # KEEP THE EVIDENCE. cleanup3 deletes SLOG3 on the way out, so a failure
    # that only happens inside `make check` -- where a hundred VMs are running
    # at once and nothing reproduces by hand -- left nothing at all to look at.
    # A test that deletes its own log on the one run that matters is a harness
    # defect, not a tidy one. (M2000)
    if [ $f3 -ne 0 ]; then
        cp "$SLOG3" /tmp/osdev-linuxabi-FAIL.log 2>/dev/null && \
            echo "  (the failing boot's serial log is at /tmp/osdev-linuxabi-FAIL.log)"
    fi
    [ $f3 -eq 0 ] || { echo "FAIL: XSAVE/AVX test"; exit 1; }
    echo "PASS: a real GLIBC static-PIE binary runs under OS-DEV (AVX via XSAVE, SysV auxv stack, clean exit)"

    # --- M1955: PHASE 4 -- the BORROWED toolchain, running in-guest ----------
    # Everything else under test here is written from scratch in this repo.
    # These are not: unmodified host binutils, copied in whole and driven
    # through the Linux ABI shim. The demo assembles a real .s file with `as`,
    # links the object with `ld`, and then RUNS the result -- inside OS-DEV.
    #
    # Its own boot, because it needs 1 GiB (five shared libraries mapped per
    # process) and because bundling it into lxfulltest would make one failure
    # indistinguishable from the other.
    SLOG4=$(mktemp /tmp/osdev_lxtool.XXXXXX.log)
    kill -9 "$QPID3" 2>/dev/null || true; wait "$QPID3" 2>/dev/null || true; QPID3=""
    QPID4=""
    cleanup4() { [ -n "$QPID4" ] && { kill -9 "$QPID4" 2>/dev/null || true; wait "$QPID4" 2>/dev/null || true; }; rm -f "$SLOG4"; }
    trap 'rc=$?; cleanup4; exit $rc' EXIT

    echo "booting to assemble+link a program with the borrowed host toolchain..."
    # -m 2G: cc1 is a 42 MB image with five shared libraries, and it is a
    # compiler -- it allocates. Demand paging means only what it touches is
    # resident, but the headroom has to exist.
    timeout -s KILL 420 "$QEMU" -cpu max -snapshot -no-reboot -no-shutdown -m 2G -smp 4 -kernel "$KERNEL" \
        -append "lxtooltest nonetdemo" \
        -drive file="$DISK",format=raw,if=ide \
        -drive file="$EXT2",format=raw,if=ide \
        -display none -serial file:"$SLOG4" >/dev/null 2>&1 &
    QPID4=$!
    i=0
    while [ $i -lt 800 ]; do
        grep -aqE "MAKEBUILT exit|KERNEL PANIC" "$SLOG4" 2>/dev/null && break
        sleep 0.5; i=$((i+1))
    done

    f4=0
    if grep -aq "KERNEL PANIC" "$SLOG4"; then
        echo "  FAIL: KERNEL PANIC while running the toolchain:"
        grep -a -A2 "KERNEL PANIC" "$SLOG4" | head -3; f4=1
    fi
    # 1. the assembler's OWN output. Proves ld.so mapped five distinct shared
    #    objects -- the bug this caught was st_ino being a constant, which made
    #    ld.so treat libz/libzstd/libc as already-loaded copies of libbfd.
    if grep -aq "GNU assembler" "$SLOG4"; then
        echo "  ok: real GNU as printed its version ($(grep -ao 'GNU assembler.*' "$SLOG4" | head -1))"
    else
        echo "  FAIL: the borrowed assembler did not run:"
        grep -aE "symbol lookup|error while loading|openat.*ENOENT|fault\]" "$SLOG4" | head -3; f4=1
    fi
    # 2/3. as and ld must both exit ZERO. A non-zero status here means the tool
    #      ran but the job failed, which is a different bug from not starting.
    if grep -aq "\[lxtool\] as -> 0" "$SLOG4"; then
        echo "  ok: as assembled /hello.s -> /t.o inside OS-DEV"
    else
        echo "  FAIL: as could not assemble:"; grep -a "\[lxtool\] as ->" "$SLOG4" | tail -1; f4=1
    fi
    if grep -aq "\[lxtool\] ld -> 0" "$SLOG4"; then
        echo "  ok: ld linked /t.o -> /t.elf inside OS-DEV"
    else
        echo "  FAIL: ld could not link:"; grep -a "\[lxtool\] ld ->" "$SLOG4" | tail -1; f4=1
    fi
    # 4. THE assertion: run what the guest just built. Both halves matter --
    #    the program's own output, and its own exit status 23 through the ABI.
    #    A staged binary could produce the message; only a real assemble+link
    #    of hello.s produces it from bytes that did not exist at boot.
    if grep -aq "SELFBUILT: assembled and linked by binutils running inside OS-DEV" "$SLOG4" &&
       grep -aq "\[lxtool\] SELFBUILT exit -> 23" "$SLOG4"; then
        echo "  ok: OS-DEV RAN THE PROGRAM IT JUST BUILT (exit 23, its own status)"
    else
        echo "  FAIL: the self-built program did not run:"
        grep -aE "SELFBUILT" "$SLOG4" | head -2; f4=1
    fi
    # --- M1957: a C COMPILER. The whole point of Phase 4. -------------------
    # cc1 is a 42 MB dynamically-linked PIE. It only became loadable once the
    # kernel stopped buffering an executable's whole image in the kernel heap
    # (the old ceiling was 16 MB) and started mapping its PT_LOADs from the
    # file, demand-paged. So "cc1 ran at all" is itself the regression test for
    # the mapped loader.
    if grep -aq "\[lxtool\] cc1 -> 0" "$SLOG4"; then
        echo "  ok: real GCC (cc1, 42 MB) compiled a C file to assembly inside OS-DEV"
    else
        echo "  FAIL: cc1 did not compile:"; grep -aE "\[lxtool\] cc1 ->|cc1:|mapload" "$SLOG4" | head -3; f4=1
    fi
    # THE assertion: run the C program the guest compiled. Its own exit status
    # (29, distinct from hello.s's 23) is what makes this unfakeable -- an
    # empty .s from a failed cc1 still assembles and links, and the resulting
    # do-nothing ELF faults at its entry. That exact failure was observed.
    if grep -aq "CCSELF: compiled by real GCC running inside OS-DEV" "$SLOG4" &&
       grep -aq "\[lxtool\] CCSELF exit -> 29" "$SLOG4"; then
        echo "  ok: OS-DEV COMPILED, ASSEMBLED, LINKED AND RAN A C PROGRAM (exit 29)"
    else
        echo "  FAIL: the compiled C program did not run:"; grep -aE "CCSELF" "$SLOG4" | head -2; f4=1
    fi
    # --- M1958: GNU make drives that toolchain -- PHASE 5's foundation ------
    # A different kind of demand from a compiler: make stats targets, compares
    # timestamps, forks a child per recipe line, execs a DYNAMICALLY LINKED
    # binary in it, and wait4()s. Every one of those was a gap.
    #
    # `make -> 0` is the assertion, not just MKDONE: a recipe that fails still
    # prints everything before it, and make's own exit status is the only thing
    # that reports the build as a whole succeeded.
    if grep -aq "MKDONE" "$SLOG4" && grep -aq "\[lxtool\] make -> 0" "$SLOG4"; then
        echo "  ok: GNU make ran cc1 + as + ld in dependency order and exited 0"
    else
        echo "  FAIL: make did not complete the build:"
        grep -aE "\[lxtool\] make ->|^make:|MKDONE" "$SLOG4" | head -4; f4=1
    fi
    # And run what MAKE built (not what the earlier hand-driven steps built --
    # different output paths, same source, so the 29 here is make's own chain).
    if grep -aq "\[lxtool\] MAKEBUILT exit -> 29" "$SLOG4"; then
        echo "  ok: OS-DEV RAN THE PROGRAM ITS OWN make BUILT (exit 29)"
    else
        echo "  FAIL: make's output did not run:"; grep -aE "MAKEBUILT" "$SLOG4" | head -2; f4=1
    fi
    [ $f4 -eq 0 ] || { echo "FAIL: in-guest toolchain"; exit 1; }
    echo "PASS: real GCC/as/ld + GNU make build and run programs inside OS-DEV"

    # --- M1960: PHASE 5 -- OS-DEV compiles its OWN kernel source ------------
    # Its own boot. Compiling a real kernel source file with the real driver is
    # minutes of TCG work on top of a boot that already runs eleven in-guest
    # programs; bundling them made a WORKING compile fail for want of
    # wall-clock, and made one failure indistinguishable from the other.
    SLOG5=$(mktemp /tmp/osdev_lxgcc.XXXXXX.log)
    kill -9 "$QPID4" 2>/dev/null || true; wait "$QPID4" 2>/dev/null || true; QPID4=""
    QPID5=""
    cleanup5() { [ -n "$QPID5" ] && { kill -9 "$QPID5" 2>/dev/null || true; wait "$QPID5" 2>/dev/null || true; }; rm -f "$SLOG5"; }
    trap 'rc=$?; cleanup5; exit $rc' EXIT

    echo "booting to compile OS-DEV's OWN kernel/elf.c with the in-guest gcc..."
    timeout -s KILL 2400 "$QEMU" -cpu max -snapshot -no-reboot -no-shutdown -m 2G -smp 4 -kernel "$KERNEL" \
        -append "lxgcctest nonetdemo" \
        -drive file="$DISK",format=raw,if=ide \
        -drive file="$EXT2",format=raw,if=ide \
        -display none -serial file:"$SLOG5" >/dev/null 2>&1 &
    QPID5=$!
    i=0
    while [ $i -lt 4600 ]; do
        grep -aqE "nm\(elf.o\) ->|KERNEL PANIC" "$SLOG5" 2>/dev/null && break
        sleep 0.5; i=$((i+1))
    done

    f5=0
    # --- M1960: PHASE 5 -- the real gcc DRIVER compiling OS-DEV's OWN source --
    # Not a toy .c: kernel/elf.c, the actual ELF loader this kernel runs on,
    # built freestanding with the exact CFLAGS the host Makefile uses. The
    # driver is a step beyond cc1 -- it forks and execs cc1 AND as itself.
    #
    # This is also the regression test for the execve argv cap: the driver
    # passes cc1 ~25 arguments, and a 16-entry limit silently dropped
    # -ffreestanding, which surfaced as cc1 failing on an #include_next inside
    # GCC's own stdint.h. Nothing about that error named the cause.
    # Half a megabyte of REAL assembly through the in-guest assembler. Size
    # matters: it is the input that exercises the write path at a scale a
    # hello-world never reaches.
    if grep -aq "\[lxtool\] as(big.s) -> 0" "$SLOG5"; then
        echo "  ok: the in-guest assembler handled a 496 KB real assembly file"
    else
        echo "  FAIL: as could not assemble the large file:"; grep -a "as(big.s)" "$SLOG5" | head -1; f5=1
    fi
    if grep -aq "\[lxtool\] gcc(kernel/elf.c) -> 0" "$SLOG5"; then
        echo "  ok: the real gcc driver compiled OS-DEV's own kernel/elf.c in-guest"
    else
        echo "  FAIL: gcc could not compile kernel/elf.c:"
        cp "$SLOG5" /tmp/osdev-lxgcc-FAIL.log 2>/dev/null && \
            echo "  (the failing boot's serial log is at /tmp/osdev-lxgcc-FAIL.log)"
        grep -aE "\[lxtool\] gcc\(kernel|error:|TRUNCATED" "$SLOG5" | head -4; f5=1
    fi
    # Prove the object is REAL by reading its symbol table -- an empty or
    # truncated file still "exists", and gcc exiting 0 is not the same as gcc
    # having written a usable object.
    # NOT anchored with ^...$: the serial console emits CRLF, so every line
    # carries a trailing \r and an anchored match silently never fires -- which
    # it did, on output that was demonstrably correct. The pair is the proof:
    # nm exits 0 only on a readable object, and its output names a real OS-DEV
    # symbol.
    if grep -aq "T elf_load" "$SLOG5" && grep -aq "\[lxtool\] nm(elf.o) -> 0" "$SLOG5"; then
        echo "  ok: nm read elf_load out of the object OS-DEV compiled"
    else
        echo "  FAIL: the compiled object has no symbol table:"; grep -aE "nm\(elf.o\)|elf_load" "$SLOG5" | head -3; f5=1
    fi
    [ $f5 -eq 0 ] || { echo "FAIL: in-guest compile of OS-DEV's own source"; exit 1; }
    echo "PASS: PHASE 5 -- OS-DEV compiled its OWN kernel source with the in-guest GCC"
else
    echo "SKIP: XSAVE/AVX + toolchain tests (this QEMU has no -cpu max)"
fi
