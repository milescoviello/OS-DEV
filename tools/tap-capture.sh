#!/bin/bash
# tap-capture — what does the WIRE say? Run a page load with tcpdump running on
# the host, so "our SYN never went out", "no SYN-ACK came back" and "a SYN-ACK
# came back and we lost it inside our stack" can be told apart. Those are three
# different bugs with opposite fixes, and the guest cannot distinguish them.
#
# WHY THE BRIDGE AND NOT THE TAP (this instrument's own first version was
# WRONG and reported "SYN out: 0" for a run that demonstrably connected twice):
# pve-run.sh STOPS the VM first, which DESTROYS tap122i0 and creates a new one
# on restart. Waiting for the tap to "exist" returns INSTANTLY because the
# PREVIOUS run's tap is still there -- tcpdump then binds to an interface that
# is about to be torn down and captures a 24-byte pcap containing nothing.
# vmbr0 outlives the VM, so capture there and select the VM by MAC instead.
#
# Also: `pkill -x tcpdump`, never `pkill -f` -- a -f pattern over a process
# list matches the invoking shell itself and kills the session.
set -e
cd "$(dirname "$0")/.."
H=${PVE_HOST:-192.168.1.5}; V=${VMID:-122}
SSH="ssh -o BatchMode=yes -o ConnectTimeout=20 root@$H"
URL=${URL:-https://volumeshaderbm.com/start/}

# BUILD BEFORE ARMING (M2365). tcpdump was started first with `timeout 300`,
# and a cold build+rsync takes far longer than that -- so the capture expired
# before the VM booted and the wire totals covered only the first seconds of
# the run. The arithmetic caught it: the guest logged 45 connects (28 ok, 17
# failed = ~96 SYNs) against 48 SYNs on the wire. Build first, then arm.
make build/kernel32.elf >/dev/null || { echo "FATAL: build failed"; exit 2; }
make build/ext2.img    >/dev/null || { echo "FATAL: ext2 build failed"; exit 2; }

MAC=$($SSH "qm config $V" | sed -nE 's/^net0:.*=([0-9A-Fa-f:]{17}),.*/\1/p')
[ -n "$MAC" ] || { echo "FATAL: could not read VM $V's MAC from qm config"; exit 2; }
echo "==> VM $V is $MAC; capturing on vmbr0 (survives the VM restart)"

: > ffurl.txt; printf '%s\n' "$URL" >> ffurl.txt

# Arm FIRST -- the bridge already exists, so there is no race to lose.
$SSH "pkill -x tcpdump >/dev/null 2>&1 || true; sleep 1; rm -f /tmp/cap.pcap
      setsid nohup timeout 900 tcpdump -i vmbr0 -n -s 96 \
        'ether host $MAC' -w /tmp/cap.pcap >/dev/null 2>&1 </dev/null &
      sleep 2
      pgrep -x tcpdump >/dev/null || { echo 'FATAL: tcpdump did not start'; exit 3; }
      echo armed, tcpdump pid \$(pgrep -x tcpdump | head -1)"

echo "==> building + booting $URL"
WAIT=full APPEND="ffshow ffurl nonetdemo" CORES=8 MEM=8192 CAP=${CAP:-170} \
  tools/pve-run.sh > /tmp/tap-run.txt 2>&1 || echo "(pve-run exit $?)"
sleep 3

$SSH 'if ! pgrep -x tcpdump >/dev/null; then
        echo ">>> WARNING: tcpdump was ALREADY GONE before the run ended -- its"
        echo "    window expired, so the wire counts below UNDERCOUNT. Do not"
        echo "    compare them against full-boot guest counters."
      fi
      echo "=== TAP: frames the host could not hand to the VM ==="
      echo "  (tx_dropped on a tap is HOST->GUEST: the bridge had the frame"
      echo "   and the VM could not take it. This is invisible in the guest.)"
      for f in tx_dropped tx_packets rx_dropped rx_packets; do
        printf "  %-12s %s\n" "$f" "$(cat /sys/class/net/tap'"$V"'i0/statistics/$f 2>/dev/null || echo n/a)"
      done
      pkill -x tcpdump >/dev/null 2>&1 || true; sleep 2
      TOT=$(tcpdump -r /tmp/cap.pcap -n 2>/dev/null | wc -l)
      echo "=== capture self-test ==="
      echo "  total frames to/from the VM: $TOT"
      if [ "$TOT" -eq 0 ]; then
        echo ">>> THE CAPTURE IS EMPTY. This is an INSTRUMENT failure, not a"
        echo "    finding: the VM demonstrably sends DHCP and DNS. Do not read"
        echo "    a packet count off this run."
        exit 4
      fi
      echo "=== port 443 handshake ==="
      tcpdump -r /tmp/cap.pcap -n "tcp port 443" 2>/dev/null | awk "
        /Flags \[S\]/   {syn++}
        /Flags \[S\.\]/ {synack++}
        /Flags \[R/     {rst++}
        END { printf \"  SYN out:      %d\n  SYN-ACK back: %d\n  RST:          %d\n\",
                     syn, synack, rst }"
      echo "=== first 20 port-443 frames ==="
      tcpdump -r /tmp/cap.pcap -n "tcp port 443" 2>/dev/null | head -20'
