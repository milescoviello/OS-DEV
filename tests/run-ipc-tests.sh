#!/bin/sh
# Headless assertion for the POSIX IPC surface (M1906): message queues, named
# semaphores, shared memory, ptys, advisory file locks, inotify and eventfd.
#
# A coverage survey found ~2,700 lines across these subsystems with NO automated
# assertions at all. They are reachable from userspace, so they were exercised
# incidentally, but nothing checked their semantics — the same situation that let
# three box-model bugs coexist in a green tree until M1902.
#
# The userspace test apps (user/iouringtest.c etc.) cannot be used for this: ring-3
# print() goes to an app's window text grid and is NOT mirrored to COM1, so a
# headless run cannot read it. Kernel kprintf DOES reach COM1, so the assertions
# live in kernel/ipcselftest.c and this script greps the markers — the same shape
# as the driver suites (ahcitest, nvmetest, ...).
#
# SKIPs cleanly if QEMU is absent. Exit 0 = pass.
set -e
cd "$(dirname "$0")/.."

QEMU=${QEMU:-qemu-system-x86_64}
KERNEL=build/kernel32.elf
DISK=build/fat.img
command -v "$QEMU" >/dev/null 2>&1 || { echo "SKIP: ipc test ($QEMU not found)"; exit 0; }

SLOG=$(mktemp /tmp/osdev_ipc.XXXXXX.log)
QPID=""
cleanup() { rc=$?; [ -n "$QPID" ] && { kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; }; rm -f "$SLOG"; exit "$rc"; }
trap cleanup EXIT

echo "booting kernel headless and running the POSIX IPC self-test (COM1 capture)..."
timeout -s KILL 90 "$QEMU" -snapshot -no-reboot -no-shutdown -m 256M -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device e1000,netdev=net0 \
    -device piix3-usb-uhci,id=uhci -device usb-tablet,bus=uhci.0 \
    -device AC97,audiodev=snd0 -audiodev none,id=snd0 \
    -display none -serial file:"$SLOG" >/dev/null 2>&1 &
QPID=$!
i=0
while [ $i -lt 160 ]; do
    grep -q "ipc self-test:" "$SLOG" 2>/dev/null && grep -q "memfd self-test:" "$SLOG" 2>/dev/null && break
    kill -0 "$QPID" 2>/dev/null || break
    sleep 0.5; i=$((i+1))
done
sleep 0.3
kill -9 "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; QPID=""

if ! grep -q "memfd self-test:" "$SLOG" 2>/dev/null; then
    echo "FAIL: the memfd self-test never ran (boot problem, not a memfd regression)"
    tail -12 "$SLOG" 2>/dev/null | sed 's/^/      /'
    exit 1
fi
if ! grep -q "ipc self-test:" "$SLOG" 2>/dev/null; then
    echo "FAIL: the IPC self-test never ran (boot problem, not an IPC regression)"
    tail -12 "$SLOG" 2>/dev/null | sed 's/^/      /'
    exit 1
fi

fail=0
require() {
    if grep -qF "$1" "$SLOG"; then echo "  ok: $2"
    else echo "  MISSING: $2  (expected substring: '$1')"; fail=1; fi
}

# Spot-check the semantics that a regression would actually break, rather than
# just that the suite ran. Each of these is a property, not a smoke test.
require "mq_receive returned the HIGHEST priority message first"  "mqueue is priority-ordered, not FIFO"
require "mq_unlink removed the queue"                             "mqueue unlink"
require "sem_open without O_CREAT fails for a missing name"       "sem_open honours O_CREAT (ENOENT without it)"
require "sem_open O_CREAT|O_EXCL fails on an existing name"       "sem_open honours O_EXCL (EEXIST)"
require "sem_trywait fails at 0 instead of blocking"              "sem_trywait is non-blocking at zero"
require "shm_open of the same name returned the SAME backing frames" "shm actually shares its frames"
require "shm_open past the size cap is rejected"                  "shm enforces its size cap"
require "pty_read on the slave got those bytes"                   "pty master->slave data path"
require "flock LOCK_EX refused to pid 102 while 101 holds it"     "flock exclusive locks exclude"
require "flock LOCK_SH ALSO granted to pid 102"                   "flock shared locks coexist"
require "flock LOCK_EX granted after the holders' pids were released" "flock releases a dead pid's locks"
require "inotify saw an event after a matching VFS mutation"      "inotify observes real VFS mutations"
require "inotify ignores mutations outside its watch"             "inotify does not over-report"
require "eventfd_read returned the accumulated count"             "eventfd accumulates and drains"

# M1907: the second batch of subsystems.
require "tmpfs_pread honoured the offset"                         "tmpfs positioned reads"
require "tmpfs_read sees the truncated length"                    "tmpfs truncate"
require "tmpfs_readlink returned the target, unfollowed"          "tmpfs symlinks are not followed by readlink"
require "unix_recv reports EOF once the peer closed"              "unix sockets report EOF, not an error, on peer close"
require "unix_recv read it on endpoint A"                          "unix sockets carry data BOTH directions"
require "sysv semop -9 with IPC_NOWAIT fails, not blocks"         "SysV semop honours IPC_NOWAIT"
require "the failed semop left the value UNCHANGED"               "SysV semop is all-or-nothing (no partial apply)"
require "sysv msgrcv selected mtype 9, skipping 7"                "SysV msgrcv selects by mtype, not FIFO"
require "procfs does NOT claim a real disk path"                  "procfs_owns does not over-claim"
require "procfs_read fails for a nonexistent node"                "procfs rejects unknown nodes"

# M1965: the socket + synthetic-filesystem behaviours the Linux ABI layer needs.
# Every one of these was found by running real Node.js, and every one presented
# as something other than what it was -- a half-close that did nothing looked
# like "the program hangs at exit", not like a missing shutdown().
require "the peer then reads EOF after SHUT_WR"                   "AF_UNIX half-close delivers EOF to the peer"
require "and the shut-down side may still read: the reverse direction stays open" "half-close is HALF: the reverse direction survives"
require "sending on a shut-down write side fails"                 "a shut-down write side refuses further sends"
require "connecting to the released name fails"                   "close() releases a listener's bound name"
require "the released name can be bound again"                    "a released name is rebindable (a restart works)"
require "unix_listen refuses a name too long to store"            "an over-long socket name is refused, not truncated"
require "vfs_stat resolves /proc/meminfo as a regular file"       "/proc FILES are stat-able (open() needs this)"
require "vfs_stat resolves /dev/null as a character device"       "/dev nodes report S_IFCHR"
require "vfs_stat still reports a missing /dev node as absent"    "the /dev existence check does not over-claim"
require "vfs_pread served /proc/meminfo -- this is what open()+read() goes through" "/proc files are readable through the VFS"
require "/dev/urandom yields more at a large offset: a char device is a stream, not a file" "char devices stream instead of hitting EOF"
# THE FS_BASE RESTORE INVARIANT (M2013). FS_BASE is the thread pointer: every
# TLS access goes through it and the stack-protector canary is read from
# %fs:0x28, so a thread running with the wrong one dies on its first function
# call, arbitrarily far from the cause. load_fs_base() used to skip the wrmsr
# when this core's record already matched -- a record that has to stay true
# about a register three assembly stubs zero as a side effect, across a
# scheduler that migrates tasks between cores. It did not.
require "FS_BASE: loading an FS selector really does zero it"     "the hazard itself is real: an FS selector write clears FS_BASE"
require "FS_BASE: reloading the SAME base after the register was zeroed behind us still writes it" "FS_BASE is restored unconditionally (this FAILS if the per-core cache comes back)"

# A MAPPED memfd MUST BE ABLE TO GROW (M2082). Resizing an already-mapped
# shared-memory pool is what every wl_shm client does -- libwayland-cursor's
# shm_pool_resize and Firefox's WaylandShmPool::Resize are posix_fallocate /
# ftruncate on a mapped fd -- and it was refused outright, because growing means
# reallocating and the old buffer's pages are aliased into the process. Firefox's
# startup made that call 107 times and got ENOSPC every time; wayland.c's own
# M2058 comment records that the compositor then has to answer the follow-up
# wl_shm_pool.resize with a FATAL protocol error.
#
# Two separate things can regress, so both are asserted. Put the
# `if (m->mapped) return -1` guard back and the first one fails. Remove it
# WITHOUT retiring the outgoing buffer -- the obvious fix -- and the second one
# fails instead, which is the important one: the kernel heap hands that block
# straight back out while a process still has its pages mapped, and nothing
# anywhere else in the tree would notice.
require "growing a MAPPED memfd past its capacity SUCCEEDS"                 "a mapped wl_shm pool can be resized at all"
require "the pre-grow buffer was RETIRED rather than freed"                 "the outgoing buffer is retired, not handed to kfree"
require "and the retired buffer's pages were NOT handed back out by the heap" "the retired buffer really is still ours (this FAILS if it is kfree'd)"
require "the bytes written before the grow survived it"                     "a resize preserves the pool's contents"
require "a further resize within the new capacity moves nothing at all"     "a grown mapped object has headroom, so the next resize does not move it"
require "teardown released the object and every buffer it outgrew"          "retired buffers are freed with the object, not leaked"
if grep -qE "memfd self-test: [0-9]+ passed, 0 failed" "$SLOG"; then
    n=$(grep -oE "memfd self-test: [0-9]+ passed" "$SLOG" | grep -oE "[0-9]+" | head -1)
    echo "  ok: all $n memfd-growth assertions passed in-guest"
else
    echo "  FAIL: the memfd self-test reported failures:"
    grep -E "^\[FAIL\] memfd|memfd self-test:" "$SLOG" | sed 's/^/      /'
    fail=1
fi

# And the summary must report zero failures.
if grep -qE "ipc self-test: [0-9]+ passed, 0 failed" "$SLOG"; then
    n=$(grep -oE "ipc self-test: [0-9]+ passed" "$SLOG" | grep -oE "[0-9]+" | head -1)
    echo "  ok: all $n IPC assertions passed in-guest"
else
    echo "  FAIL: the self-test reported failures:"
    grep -E "^\[FAIL\] ipc|ipc self-test:" "$SLOG" | sed 's/^/      /'
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: in-guest POSIX IPC (mqueue priority order, sem O_CREAT/O_EXCL + non-blocking trywait, shm frame sharing + size cap, pty data path, flock exclusion/sharing/pid-release, inotify filtering, eventfd accumulate+drain, tmpfs pread/truncate/symlink, unixsock bidirectional + EOF + half-close + name release, SysV IPC_NOWAIT + all-or-nothing semop + mtype selection, procfs ownership + unknown-node rejection + synthetic files stat/read through the VFS)"
else
    echo "FAIL: in-guest POSIX IPC self-test"; exit 1
fi
