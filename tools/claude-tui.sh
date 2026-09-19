#!/bin/sh
# claude-tui.sh -- drive the REAL interactive Claude Code, the way a person does.
#
# Every Claude demo in this tree is `claude -p`: one prompt in, one answer out,
# no terminal. That is the headless path, and it is the only one with a test.
# The thing a person actually wants is to type `claude` at the OS-DEV shell,
# get the TUI, type a question, and read the answer -- which exercises a
# completely different stack: raw-mode terminal, ANSI rendering, the alternate
# screen, streaming output, arrow keys, Ctrl+C, SIGWINCH. None of that is
# touched by -p, and none of it has been verified since M2006.
#
# So this types at it. No markers to game: the oracle is the screen.
#
#   tools/claude-tui.sh              # boot, run claude, ask it something
#   Q="what is 2+2" tools/claude-tui.sh
set -e
cd "$(dirname "$0")/.."
H=${PVE_HOST:-192.168.1.5}
VMID=${VMID:-122}
D=${PVE_DIR:-/root/osdev}
SSH="ssh -o BatchMode=yes root@$H"
S=${SCRATCH:-/tmp/claude-1000/-home-miles-OS-DEV/026bcdb5-8d88-4ad7-9f23-58649bf4f353/scratchpad}/tui
mkdir -p "$S"
Q=${Q:-"reply with exactly the word OSDEVTUI and nothing else"}
CAP=${CAP:-900}

key()  { $SSH "echo 'sendkey $1' | qm monitor $VMID >/dev/null 2>&1"; }
# Type an ASCII string with QEMU key names. Only what a prompt needs.
typestr() {
    s=$1
    while [ -n "$s" ]; do
        c=$(printf '%s' "$s" | cut -c1); s=$(printf '%s' "$s" | cut -c2-)
        case "$c" in
            " ") k=spc ;;
            [a-z0-9]) k=$c ;;
            [A-Z]) k="shift-$(printf '%s' "$c" | tr 'A-Z' 'a-z')" ;;
            ".") k=dot ;; ",") k=comma ;; "-") k=minus ;; "/") k=slash ;;
            "+") k="shift-equal" ;; "=") k=equal ;; "?") k="shift-slash" ;;
            "'") k=apostrophe ;; ":") k="shift-semicolon" ;;
            *) continue ;;
        esac
        key "$k"
    done
}
shot() {
    $SSH "echo 'screendump $D/shot.ppm' | qm monitor $VMID >/dev/null 2>&1"
    p=-1; n=0
    while [ $n -lt 20 ]; do
        c=$($SSH "stat -c %s $D/shot.ppm 2>/dev/null || echo 0")
        [ "$c" = "$p" ] && [ "$c" != 0 ] && break
        p=$c; n=$((n+1)); sleep 1
    done
    scp -q "root@$H:$D/shot.ppm" "$S/$1.ppm"
}
changed() { python3 - "$S/$1.ppm" "$S/$2.ppm" <<'PY'
import sys
def rd(p):
    d=open(p,'rb').read(); f=d.split(b'\n',3); w,h=map(int,f[1].split()); return w,h,f[3]
try: w,h,a=rd(sys.argv[1]); _,_,b=rd(sys.argv[2])
except Exception as e: print("unreadable"); raise SystemExit
print(sum(1 for i in range(0,min(len(a),len(b))-2,3) if a[i:i+3]!=b[i:i+3]))
PY
}

echo "==> booting -append 'lxdesktop' (the Linux environment and the desktop, no tests)"
WAIT=full NOBUILD=${NOBUILD:-1} APPEND="lxdesktop" CORES=${CORES:-8} CAP=$CAP \
    tools/pve-run.sh >"$S/run.txt" 2>&1 &
RUN=$!
T0=$(date -u +%s); i=0
while [ $i -lt 240 ]; do
    if $SSH "[ \"\$(stat -c %Y $D/boot.log 2>/dev/null || echo 0)\" -ge $T0 ] && \
             grep -aq 'desktop is taking over' $D/boot.log 2>/dev/null"; then break; fi
    sleep 5; i=$((i+5))
done
[ $i -lt 240 ] || { echo "TUI: FAIL -- no desktop in ${i}s"; wait $RUN; exit 1; }
echo "    desktop at ~${i}s"
sleep 20
shot desktop

# Focus the shell window. The desktop opens one for the Linux environment;
# click its middle rather than guessing which is on top.
GEO=$($SSH "grep -a 'window for .Shell' $D/boot.log | tail -1" || true)
echo "    shell window: ${GEO:-<not logged, clicking screen centre>}"
$SSH "printf '{\"execute\":\"qmp_capabilities\"}\n{\"execute\":\"input-send-event\",\"arguments\":{\"events\":[{\"type\":\"abs\",\"data\":{\"axis\":\"x\",\"value\":16000}},{\"type\":\"abs\",\"data\":{\"axis\":\"y\",\"value\":16000}}]}}\n{\"execute\":\"input-send-event\",\"arguments\":{\"events\":[{\"type\":\"btn\",\"data\":{\"down\":true,\"button\":\"left\"}}]}}\n{\"execute\":\"input-send-event\",\"arguments\":{\"events\":[{\"type\":\"btn\",\"data\":{\"down\":false,\"button\":\"left\"}}]}}\n' | socat - UNIX-CONNECT:/var/run/qemu-server/$VMID.qmp" >/dev/null 2>&1 || true
sleep 3

echo "==> typing: claude"
typestr "claude"; key ret
echo "    waiting for the TUI to come up (this is a 214 MB binary starting)"
w=0; PREV=desktop
while [ $w -lt 420 ]; do
    sleep 20; w=$((w+20))
    shot "tui-$w"
    D1=$(changed "$PREV" "tui-$w")
    echo "    ...${w}s: $D1 px changed since the last look"
    PREV="tui-$w"
    # The TUI is a big box: once a lot of the screen is painted and then stops
    # changing, it is up and idle at its prompt.
    [ "$D1" -lt 2000 ] && [ $w -ge 60 ] && break
done
shot tui-ready
echo "    screen vs bare desktop: $(changed desktop tui-ready) px"

# THE TRUST PROMPT IS PART OF THE REAL THING (M2299).
#
# The first run of this harness typed its question straight into Claude
# Code's "Is this a project you created or one you trust?" dialog and then
# reported 300 seconds of ~80px changes, which I could have read as "the TUI
# does not respond". It responds fine; it was waiting for an answer nobody
# gave it. `claude -p` never sees this because it runs with
# --dangerously-skip-permissions.
#
# Answering it is also a better test than skipping it: it needs ARROW KEYS
# and Enter through the raw-mode terminal, which -p exercises nothing of.
echo "==> answering the trust prompt (down, then Enter)"
key down; sleep 2; shot trust-sel
echo "    after Down: $(changed tui-ready trust-sel) px changed"
key ret
w=0; PREV=trust-sel
while [ $w -lt 180 ]; do
    sleep 15; w=$((w+15))
    shot "trust-$w"
    DT=$(changed "$PREV" "trust-$w"); PREV="trust-$w"
    echo "    ...${w}s: $DT px"
    [ "$DT" -lt 1500 ] && [ $w -ge 30 ] && break
done
shot prompt
echo "    prompt vs trust dialog: $(changed tui-ready prompt) px changed"

echo "==> asking: $Q"
typestr "$Q"; sleep 2; shot typed
echo "    after typing the question: $(changed tui-ready typed) px changed"
key ret
w=0
while [ $w -lt 300 ]; do
    sleep 20; w=$((w+20))
    shot "ans-$w"
    echo "    ...${w}s since Enter: $(changed typed "ans-$w") px changed vs the typed prompt"
done
shot answer
echo
echo "==> what the guest printed on serial (last lines):"
$SSH "grep -avE '^\[(wl|page|share|memfd|relro|vma)\]' $D/boot.log | tail -25"
wait $RUN 2>/dev/null || true
scp -q "root@$H:$D/boot.log" "$S/boot.log"
echo "==> shots in $S -- LOOK AT $S/answer.ppm"
