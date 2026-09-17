#!/usr/bin/env python3
"""Ask on the wire whether a host is there: send an ARP request, count replies.

Written because the question "is OS-DEV reachable from its own LAN right now"
cannot be asked any other way. ping needs the target to answer ICMP; an entry
in the host's neighbour table only records that it answered at some point in
the past; and the machine this runs on (a Proxmox node) has no arping. This
builds the 42-byte request by hand on an AF_PACKET socket, which is exactly
what the router does when its neighbour entry for us expires -- the event that
M2126/M2127 are about.

  usage: arp-probe.py <iface> <target-ip> [count] [timeout-seconds]
  exit:  0 if at least one reply arrived, 1 if none did.
"""
import socket, struct, sys, time

def mac_of(iface):
    with open('/sys/class/net/%s/address' % iface) as f:
        return bytes(int(b, 16) for b in f.read().strip().split(':'))

def ip_of(iface):
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:   # SIOCGIFADDR
        return fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', iface.encode()[:15]))[20:24]
    finally:
        s.close()

def main():
    iface  = sys.argv[1]
    target = socket.inet_aton(sys.argv[2])
    count  = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    budget = float(sys.argv[4]) if len(sys.argv) > 4 else 8.0

    src_mac, src_ip = mac_of(iface), ip_of(iface)
    req = (b'\xff' * 6 + src_mac + struct.pack('!H', 0x0806) +
           struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) +
           src_mac + src_ip + b'\x00' * 6 + target)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    s.bind((iface, 0))
    s.settimeout(0.5)

    replies, deadline = 0, time.time() + budget
    for i in range(count):
        s.send(req)
        sent = time.time()
        while time.time() < sent + budget / count and time.time() < deadline:
            try:
                f = s.recv(1514)
            except socket.timeout:
                continue
            # an ARP reply whose sender protocol address is the host we asked about
            if len(f) >= 42 and struct.unpack('!H', f[20:22])[0] == 2 and f[28:32] == target:
                sender = ':'.join('%02x' % b for b in f[22:28])
                print('reply from %s is-at %s (%.1f ms)'
                      % (sys.argv[2], sender, (time.time() - sent) * 1000))
                replies += 1
                break
        else:
            print('no reply from %s' % sys.argv[2])
        if time.time() >= deadline:
            break

    print('%d request(s), %d reply(s)' % (count, replies))
    return 0 if replies else 1

if __name__ == '__main__':
    sys.exit(main())
