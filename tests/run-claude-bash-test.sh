#!/bin/sh
# THE NORTH STAR'S TOOL CALL: Claude Code, running inside OS-DEV, decides to
# use its Bash tool, spawns /bin/bash in OS-DEV, and reads the output back.
#
# This cannot be a `make check` assertion and it is not pretending to be one.
# It needs two things that suite deliberately does not have: the real bridged
# LAN on the Proxmox node (QEMU's user-mode networking cannot exercise the ARP
# and resolver paths this depends on -- see M2126/M2128) and a live OAuth
# session in the image, which only a human can create. It skips cleanly when
# either is missing, because a test that quietly passes without them would be
# asserting nothing.
#
# What it requires is the one string that cannot appear by accident. The prompt
# asks Claude Code to run `echo OSDEV-BASH-OK`, so the marker can only reach
# the log by travelling: the API decided to call the tool, the tool spawned
# /bin/bash through the Linux ABI, bash ran inside OS-DEV, and its stdout came
# back up through the harness. (M2130)
set -e
NODE=${PVE_NODE:-192.168.1.5}
CAP=${CAP:-580}

ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$NODE" true 2>/dev/null \
  || { echo "SKIP: claude bash-tool demo (no ssh to $NODE — needs the Proxmox node)"; exit 0; }
[ -x tools/pve-run.sh ] || { echo "SKIP: claude bash-tool demo (no tools/pve-run.sh)"; exit 0; }
[ -f build/lxroot/root/.claude/.credentials.json ] \
  || { echo "SKIP: claude bash-tool demo (no in-guest login staged — a human must complete the OAuth flow)"; exit 0; }

echo "booting OS-DEV on $NODE and asking Claude Code to run a command (this is slow: it is Claude Code)..."
NOBUILD=${NOBUILD:-1} APPEND="lxbash lxout" CORES=1 CAP="$CAP" tools/pve-run.sh >/dev/null 2>&1 || true

LOG=$(ssh -o BatchMode=yes "root@$NODE" "tr -d '\r' < /root/osdev/boot.log" 2>/dev/null || true)
[ -n "$LOG" ] || { echo "FAIL: claude bash-tool demo: no boot log came back"; exit 1; }

f=0
if printf '%s\n' "$LOG" | grep -q "Failed to authenticate"; then
    echo "SKIP: claude bash-tool demo (the staged OAuth session has expired — re-login in the guest)"
    exit 0
fi
# AND THE OTHER WAY A VALID LOGIN STILL CANNOT ANSWER (M2319).
#
# The credential is good, the name resolves, the TLS session opens, the API
# replies -- with "You've hit your session limit". Claude Code then exits 1,
# which this test would report as "Claude Code did not exit 0" and every later
# reader would take for a kernel regression. It is not a regression and it is
# not skippable by re-logging in: it is a quota, and the only honest verdict is
# that this run measured nothing.
if printf '%s\n' "$LOG" | grep -qiE "hit your (session|usage) limit|usage limit reached"; then
    echo "SKIP: claude bash-tool demo (the ACCOUNT hit its usage limit — the API answered, so this run measured the quota, not the kernel)"
    printf '%s\n' "$LOG" | grep -aoiE "hit your (session|usage) limit.*" | head -1 | sed 's/^/      /'
    exit 0
fi
# The tool CALL: bash was spawned with the command in its argv.
if printf '%s\n' "$LOG" | grep -q "exec\] pid .* -> /bin/bash"; then
    echo "  ok: Claude Code spawned /bin/bash inside OS-DEV through the Linux ABI"
else
    echo "  FAIL: no /bin/bash was ever spawned -- the tool call did not happen:"
    printf '%s\n' "$LOG" | grep -a "task output swap refused\|proc/self/fd\|ENOSYS" | head -4 | sed 's/^/      /'
    f=1
fi
# The OUTPUT: the marker came back up through the harness, not just into argv.
# THE MARKER OUTSIDE THE COMMAND LINE THAT CARRIED IT (M2150).
#
# This used to require the literal `Output: \`OSDEV-BASH-OK\`` -- one exact
# formatting of a MODEL'S prose, which is not a stable interface: the same
# successful run put the marker in a fenced code block instead and the test
# called it a failure. So match the marker itself, but only on lines that are
# not the exec log -- the string necessarily appears in the argv of the bash we
# spawned (`eval 'echo OSDEV-BASH-OK'`), and counting that would pass whether
# or not anything came back, which is the one distinction this assertion
# exists to make.
if printf '%s\n' "$LOG" | grep -v 'exec\] pid' | grep -q 'OSDEV-BASH-OK'; then
    echo "  ok: and it read the command's output back -- OSDEV-BASH-OK"
else
    echo "  FAIL: the command's output never came back:"
    printf '%s\n' "$LOG" | grep -a 'OSDEV-BASH-OK\|task output swap refused' | head -3 | sed 's/^/      /'
    f=1
fi
if printf '%s\n' "$LOG" | grep -q "claude -p -> 0"; then
    echo "  ok: and Claude Code exited 0 -- every step succeeded, not just the ones that printed"
else
    echo "  FAIL: Claude Code did not exit 0:"; printf '%s\n' "$LOG" | grep -a "claude -p ->" | head -1; f=1
fi

[ $f -eq 0 ] || { echo "FAIL: claude bash-tool demo"; exit 1; }
echo "PASS: Claude Code runs a shell command inside OS-DEV and reads the result"
