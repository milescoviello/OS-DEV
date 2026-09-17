#!/bin/sh
# OS-DEV IS REACHABLE FROM ITS OWN LAN WHILE IT IS DOING NOTHING.
#
# This assertion cannot be made under QEMU's user-mode networking, which is why
# the defect it covers survived ~130 green checkpoints and 2100 milestones:
# SLIRP answers ARP on the guest's behalf and never asks the guest to identify
# itself, so a kernel that never answers an ARP request looks perfect there. On
# a real bridged LAN the router's neighbour entry for us expires in well under a
# minute, it broadcasts "who-has <us>", and from the moment that goes unanswered
# every packet addressed to this machine is dropped before it reaches the wire.
#
# So the test runs against the real thing: OS-DEV as a KVM guest on the Proxmox
# node, bridged onto the house LAN with a DHCP lease, deliberately IDLE -- the
# desktop up, no socket open, nothing polling the NIC. Then the host flushes its
# own ARP cache, so no stale answer can satisfy it, and asks on the wire.
#
# REVERT-PROOF: with M2127's RX service removed, the only code that answers ARP
# is inside the polling loops, none of which are running on an idle machine, and
# `arping` gets 0 replies. It is not a timing window -- an idle OS-DEV stays
# unreachable indefinitely. (M2127)
set -e
NODE=${PVE_NODE:-192.168.1.5}
BR=${PVE_BRIDGE:-vmbr0}
GUEST_IP=${OSDEV_IP:-192.168.1.224}
IDLE=${IDLE:-75}

ssh -o BatchMode=yes -o ConnectTimeout=5 "root@$NODE" true 2>/dev/null \
  || { echo "SKIP: LAN reachability test (no ssh to $NODE — needs the Proxmox node)"; exit 0; }
ssh -o BatchMode=yes "root@$NODE" "command -v python3 >/dev/null" 2>/dev/null \
  || { echo "SKIP: LAN reachability test (no python3 on $NODE to build the ARP request)"; exit 0; }
[ -f tools/arp-probe.py ] || { echo "SKIP: LAN reachability test (no tools/arp-probe.py)"; exit 0; }
[ -x tools/pve-run.sh ] || { echo "SKIP: LAN reachability test (no tools/pve-run.sh)"; exit 0; }

echo "booting OS-DEV on $NODE, bridged onto the real LAN, then leaving it idle..."
APPEND="nonetdemo" CORES=2 CAP="$IDLE" tools/pve-run.sh >/dev/null 2>&1 \
  || { echo "FAIL: lan-reachable: the guest did not reach its boot marker"; exit 1; }

# The machine has now been up for at least $IDLE seconds with nothing polling
# the NIC -- comfortably past the ~30-60s in which a router forgets a host.
echo "asking on the wire, with the host's own ARP cache flushed first..."
ssh -o BatchMode=yes "root@$NODE" "cat > /tmp/arp-probe.py" < tools/arp-probe.py
OUT=$(ssh -o BatchMode=yes "root@$NODE" \
      "ip neigh del $GUEST_IP dev $BR 2>/dev/null; python3 /tmp/arp-probe.py $BR $GUEST_IP 4 8 2>&1" || true)
printf '%s\n' "$OUT" | sed 's/^/    /'

REPLIES=$(printf '%s\n' "$OUT" | grep -c "^reply from $GUEST_IP" || true)
if [ "${REPLIES:-0}" -ge 1 ]; then
    echo "[ ok ] lan-reachable: an idle OS-DEV answered $REPLIES of 4 ARP requests for it"
    echo "lan-reachable: 1 checkpoint, 0 failures"
    exit 0
fi
echo "FAIL: lan-reachable: an idle OS-DEV answered NO ARP request for $GUEST_IP"
echo "  this is the M2126/M2127 defect: the machine drops off its own LAN once"
echo "  the router's neighbour entry expires, so nothing can reach it inbound."
exit 1
