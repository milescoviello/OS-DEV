/*
 * net.c — a tiny taste of a network stack: ARP + ICMP echo (ping).
 *
 * This is the protocol layer on top of the NIC. It's card-agnostic: it builds
 * raw packets byte-by-byte in network (big-endian) order and hands them to
 * whichever card the nic.c dispatcher bound (the Intel e1000 or the Realtek
 * RTL8139), via nic_send / nic_receive / nic_mac. Then it polls for replies.
 * Two exchanges:
 *
 *   ARP  — "who has 10.0.2.2? tell 10.0.2.15" → the gateway answers with its
 *          MAC. (You must know a host's MAC before you can send it IP packets.)
 *   ICMP — an echo request ("ping") to the gateway → it echoes it back.
 *
 * Under QEMU's user-mode networking, the virtual gateway 10.0.2.2 answers both.
 */
#include "net.h"
#include "cookiejar.h"   /* HTTP cookies (M2029) */
#include "url.h"        /* url_host_port() — honor an explicit :port in the fetch host (M1773) */
#include "nic.h"
#include "timer.h"
#include "console.h"
#include "string.h"
#include "tls.h"
#include "rtc.h"
#include "syscall.h"    /* SOL_SOCKET, SO_REUSEADDR, IPPROTO_TCP, TCP_NODELAY (M1554) */
#include "kheap.h"      /* kmalloc/kfree — WebSocket transport working buffers (M1846) */
#include "wsframe.h"    /* RFC 6455 frame codec (M1843) */
#include "wsclient.h"   /* RFC 6455 client handshake helpers (M1845) */
#include "task.h"       /* task_sleep_ms -- a blocking UDP recv yields instead of spinning (M1967) */
#include "sha1.h"       /* SHA-1 — WebSocket server accept-key digest (M1849) */
#include <stdint.h>

/* The SLIRP defaults — used as-is until a DHCP lease (net_dhcp) overwrites them. */
static uint8_t  OUR_IP[4]  = {10, 0, 2, 15};
static uint8_t  GW_IP[4]   = {10, 0, 2, 2};
static const uint8_t  BROADCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

const uint8_t *net_ip(void)      { return OUR_IP; }
/* DID A DHCP SERVER ACTUALLY ANSWER? (M2120) Without this, an address that
 * came from a lease and one that came from a compiled-in constant are
 * indistinguishable to every caller and to every log line. */
static int g_have_lease;
int net_have_lease(void)         { return g_have_lease; }
const uint8_t *net_gateway(void) { return GW_IP; }
const uint8_t *net_mac(void)     { return nic_mac(); }

/* --- byte helpers (everything on the wire is big-endian) --- */
static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static uint16_t get16(const uint8_t *p)   { return (uint16_t)(p[0] << 8 | p[1]); }

/* Internet checksum: one's-complement sum of 16-bit big-endian words. */
static uint16_t inet_checksum(const uint8_t *data, int len) {
    uint32_t sum = 0;
    for (int i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)(data[i] << 8 | data[i + 1]);
    if (len & 1)
        sum += (uint32_t)(data[len - 1] << 8);
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Loopback (lo, 127.0.0.0/8) — M1264: a virtual interface whose "transmit"
 * re-injects the frame straight into the receive path, so two in-guest endpoints
 * can speak IP with NO NIC (and no external host). net_udp_send detects a 127.x
 * destination and enqueues here instead of arp+nic_send; recv_timeout drains
 * this ring before polling the real NIC. */
#define LO_RING 8
static struct { uint8_t buf[1600]; int len; } lo_ring[LO_RING];
static int lo_head, lo_tail;
static void lo_enqueue(const uint8_t *frame, int len) {
    if (len <= 0 || len > 1600) return;
    int nxt = (lo_head + 1) % LO_RING;
    if (nxt == lo_tail) return;                  /* ring full: drop (a real lo would too under flood) */
    for (int i = 0; i < len; i++) lo_ring[lo_head].buf[i] = frame[i];
    lo_ring[lo_head].len = len;
    lo_head = nxt;
}
static int lo_dequeue(uint8_t *out, int max) {
    if (lo_head == lo_tail) return 0;
    int len = lo_ring[lo_tail].len; if (len > max) len = max;
    for (int i = 0; i < len; i++) out[i] = lo_ring[lo_tail].buf[i];
    lo_tail = (lo_tail + 1) % LO_RING;
    return len;
}

/* Reply to an inbound ARP request for our IP so other hosts on a real LAN can
 * find us — required for INBOUND connections (netcon/httpd) on bare metal, where
 * (unlike QEMU's SLIRP) nothing proxies ARP on our behalf. net.c otherwise only
 * ever SENT ARP requests + consumed replies. Returns 1 if `buf` was an ARP
 * request for OUR_IP that we just answered. (M1878) */
static int arp_maybe_reply(const uint8_t *buf, int len) {
    if (len < 42 || get16(buf + 12) != 0x0806) return 0;   /* not ARP */
    if (get16(buf + 20) != 1) return 0;                    /* not a request */
    if (memcmp(buf + 38, OUR_IP, 4) != 0) return 0;        /* target protocol addr isn't us */
    const uint8_t *m = nic_mac();
    uint8_t pkt[42];
    memcpy(pkt + 0, buf + 22, 6);          /* eth dst   = requester's MAC */
    memcpy(pkt + 6, m, 6);                 /* eth src   = us */
    put16(pkt + 12, 0x0806);               /* ethertype = ARP */
    put16(pkt + 14, 1);                    /* htype     = ethernet */
    put16(pkt + 16, 0x0800);               /* ptype     = IPv4 */
    pkt[18] = 6; pkt[19] = 4;              /* hlen / plen */
    put16(pkt + 20, 2);                    /* oper      = reply */
    memcpy(pkt + 22, m, 6);                /* sender MAC = us */
    memcpy(pkt + 28, OUR_IP, 4);           /* sender IP  = us */
    memcpy(pkt + 32, buf + 22, 6);         /* target MAC = requester */
    memcpy(pkt + 38, buf + 28, 4);         /* target IP  = requester */
    nic_send(pkt, 42);
    return 1;
}

/* ---- ONE RX DEMUX: nothing is discarded because of who happened to poll ----
 *
 * There is one NIC and several independent consumers -- a TCP connection's
 * read loop, a UDP socket, an ARP resolve, a ping -- and each of them used to
 * drain the NIC directly and DESTROY every frame it did not recognise.
 * `udp_pump_once` said so outright: "everything else discarded".
 *
 * That makes the network non-deterministic in a way no single component looks
 * guilty for. A connect() does an ARP resolve; the ARP wait eats a TCP segment
 * belonging to a TLS handshake already in flight on another socket. A ping
 * eats a DNS reply. The TCP path eats every ICMP echo reply, which is how this
 * was finally caught: three echo requests, three replies on the wire, and the
 * guest reporting 1/3.
 *
 * M1908 fixed one quadrant of this (TCP frames parked for other TCP
 * connections) and M1967 another (a UDP queue). The general rule is the one
 * that was missing: a consumer may take what is ITS OWN and must FILE
 * everything else where its owner will find it.
 *
 * (M2017) */
static void park_put(const uint8_t *f, int len);   /* the TCP park ring, defined with the TCP demux below */
static void udpq_put(const uint8_t *f, int len);   /* the UDP datagram queue */
/* 16 -> 48 (M2022): same reasoning as PARK_N. This ring holds the protocols
 * that have nowhere else to go, and it is written by every drain site. */
#define ORING_N   48
#define ORING_MAX 1600
static struct { uint8_t buf[ORING_MAX]; int len; uint64_t at; } g_oring[ORING_N];
#define ORING_TTL 200            /* ticks (~2s): a frame nobody claimed is stale */

static void oring_put(const uint8_t *f, int len) {
    if (len <= 0 || len > ORING_MAX) return;
    uint64_t now = timer_ticks();
    int slot = -1;
    for (int i = 0; i < ORING_N; i++) {
        if (g_oring[i].len && now - g_oring[i].at > ORING_TTL) g_oring[i].len = 0;
        if (!g_oring[i].len && slot < 0) slot = i;
    }
    if (slot < 0) {                                  /* full: evict the oldest */
        uint64_t oldest = ~0ull; slot = 0;
        for (int i = 0; i < ORING_N; i++) if (g_oring[i].at < oldest) { oldest = g_oring[i].at; slot = i; }
    }
    memcpy(g_oring[slot].buf, f, (size_t)len);
    g_oring[slot].len = len; g_oring[slot].at = now;
}
static int oring_take(uint8_t *out, int max) {
    uint64_t now = timer_ticks();
    for (int i = 0; i < ORING_N; i++) {
        if (!g_oring[i].len) continue;
        if (now - g_oring[i].at > ORING_TTL) { g_oring[i].len = 0; continue; }
        int len = g_oring[i].len; if (len > max) len = max;
        memcpy(out, g_oring[i].buf, (size_t)len);
        g_oring[i].len = 0;
        return len;
    }
    return 0;
}

/* File a frame that is not ours. Returns 1 if it was filed (so the caller
 * should keep waiting), 0 if the caller may have it. TCP goes to the park ring
 * for its connection, UDP to the datagram queue for its port, and everything
 * else -- ICMP, ARP, whatever arrives next -- to the ring above. */
static int net_rx_file_foreign(const uint8_t *f, int len, int want_tcp) {
    if (len < 14) return 1;                                   /* runt: nothing can use it */
    if (get16(f + 12) != 0x0800) {                            /* not IPv4 (ARP, ...) */
        if (want_tcp) { oring_put(f, len); return 1; }
        return 0;                                             /* the caller handles ARP itself */
    }
    if (len < 34) return 1;
    uint8_t proto = f[14 + 9];
    if (proto == 6)  { park_put(f, len); return 1; }           /* TCP: its connection's */
    if (proto == 17) { udpq_put(f, len); return 1; }           /* UDP: its port's */
    if (want_tcp)    { oring_put(f, len); return 1; }          /* ICMP etc: park for ping */
    return 0;                                                  /* ICMP, and the caller wants it */
}

/* Wait up to `ticks` for a frame; return its length (0 on timeout). Loopback
 * frames (M1264) are drained first so a NIC flood can't starve them. */
static int recv_timeout(uint8_t *buf, int max, uint64_t ticks) {
    uint64_t deadline = timer_ticks() + ticks;
    /* A TICK DEADLINE IS NOT A BOUND WITH INTERRUPTS OFF (M2068).
     *
     * This loop waited on `timer_ticks()`, and the tick only advances from the
     * PIT interrupt. A caller that arrives with IF clear -- every syscall does,
     * the gate is 0xEE -- freezes the clock, so `timer_ticks() <= deadline` is
     * true FOR EVER and the `pause` branch below spins on a core that can no
     * longer be preempted, take the NIC's IRQ, or run another task.
     *
     * That is a whole-machine wedge, and it is what it looked like: the guest
     * stopped, the taskbar clock froze, the log stopped mid-line, and a
     * QEMU-monitor register dump showed TWO cores at this exact instruction
     * with RFL=0x46 -- no IF bit -- while the other two sat in HLT. Claude
     * Code reached it the first time it did enough socket I/O to block on a
     * read.
     *
     * The caller should enable interrupts, and the Linux socket paths now do.
     * But a function that can hang the machine if ONE caller forgets is the
     * wrong shape, so bound it by WORK as well: with IF clear the tick budget
     * is meaningless, so spend a spin budget instead and SAY SO, once, naming
     * the condition rather than quietly tolerating it. */
    uint64_t ifl; __asm__ volatile("pushfq; pop %0" : "=r"(ifl));
    int no_irq = !(ifl & (1u << 9));
    if (no_irq) {
        static int told;
        if (!told) { told = 1;
            kprintf("[net] recv_timeout entered with INTERRUPTS OFF -- the tick clock cannot "
                    "advance, so its timeout can never expire; spinning a bounded budget instead\n"); }
    }
    /* ZERO TICKS MEANS ONE PASS (M2068). `recv_timeout(.., 0)` is how every
     * readiness check asks "is there a frame RIGHT NOW" -- poll, epoll, and
     * M2059's drain hook all reach it through tcpsock_pump. The loop condition
     * `timer_ticks() <= deadline` is TRUE on the first iteration when the
     * deadline is now, so a zero-tick "non-blocking" wait was a LOOP: with
     * interrupts on it happened to leave after one tick, and with interrupts
     * off it never left at all. A non-blocking poll must not be able to block,
     * let alone hang the machine. */
    long budget = no_irq ? 4000000 : -1;          /* only consumed on the IF-clear path */
    int once = (ticks == 0);
    while (once || (no_irq ? (--budget > 0) : (timer_ticks() <= deadline))) {
        if (once) once = 0, budget = 1;           /* this iteration, then out */
        int l = oring_take(buf, max);                  /* frames another consumer filed for us (M2018) */
        if (l > 0) {
            if (arp_maybe_reply(buf, l)) continue;
            return l;
        }
        l = lo_dequeue(buf, max);
        if (l > 0) return l;
        int len = nic_receive(buf, max);
        if (len > 0) {
            if (arp_maybe_reply(buf, len)) continue;   /* answered an ARP query — keep waiting */
            /* TCP belongs to a connection, never to these callers: an ARP
             * resolve, a ping, a DNS query and a TFTP transfer all filter for
             * their own protocol and drop the rest. So a connect()'s ARP
             * resolve used to destroy segments of a TLS handshake already in
             * flight on another socket. Park them instead. (M2017)
             *
             * UDP is deliberately NOT filed here: dns_resolve and net_tftp_get
             * read their datagrams THROUGH this function, so filing them into
             * the UDP queue would leave those callers waiting for something
             * that had already been put away. Their own filters handle it. */
            if (len >= 34 && get16(buf + 12) == 0x0800 && buf[14 + 9] == 6) { park_put(buf, len); continue; }
            return len;
        }
        /* Nothing yet: instead of tight-spinning the CPU, SLEEP until the next
         * interrupt. Interrupt-driven RX (M1858) makes the NIC raise its IRQ the
         * moment a packet lands, waking us promptly; the ~10ms timer tick is the
         * fallback (and drives loopback). Only `hlt` with interrupts enabled —
         * else the CPU would wedge; then it degrades to the old busy-poll. */
        if (budget == 1) return 0;                     /* the zero-tick single pass found nothing */
        uint64_t fl; __asm__ volatile("pushfq; pop %0" : "=r"(fl));
        if (fl & (1u << 9)) __asm__ volatile("hlt");   /* IF set: wake on NIC IRQ or timer */
        else                __asm__ volatile("pause");
    }
    return 0;
}

static void print_mac(const uint8_t *m) {
    for (int i = 0; i < 6; i++)
        kprintf("%s%x", i ? ":" : "", m[i]);
}

/* Tiny ARP cache: the gateway/DNS MAC is otherwise re-resolved (a broadcast +
 * reply round-trip) on every TCP connection. Cache it, with a TTL so a changed
 * mapping can't be served forever. A miss/expiry just falls through to a request. */
#define ARP_CACHE_N 4
#define ARP_TTL     6000           /* 60 s at 100 Hz */
static struct { uint8_t ip[4], mac[6]; uint64_t exp; int used; } arp_cache[ARP_CACHE_N];

/* Resolve `ip` to a MAC via ARP. Returns 1 + fills `out_mac`, or 0 on timeout. */
static int arp_resolve(const uint8_t *ip, uint8_t *out_mac) {
    for (int i = 0; i < ARP_CACHE_N; i++)          /* serve a fresh cached mapping */
        if (arp_cache[i].used && timer_ticks() < arp_cache[i].exp
            && memcmp(arp_cache[i].ip, ip, 4) == 0) {
            memcpy(out_mac, arp_cache[i].mac, 6);
            return 1;
        }
    const uint8_t *mac = nic_mac();
    uint8_t pkt[42];

    /* ethernet header */
    memcpy(pkt + 0, BROADCAST, 6);
    memcpy(pkt + 6, mac, 6);
    put16(pkt + 12, 0x0806);                 /* ethertype = ARP */
    /* arp body */
    put16(pkt + 14, 1);                      /* htype = ethernet */
    put16(pkt + 16, 0x0800);                 /* ptype = IPv4 */
    pkt[18] = 6; pkt[19] = 4;                /* hlen, plen */
    put16(pkt + 20, 1);                      /* oper = request */
    memcpy(pkt + 22, mac, 6);                /* sender MAC */
    memcpy(pkt + 28, OUR_IP, 4);             /* sender IP */
    memset(pkt + 32, 0, 6);                  /* target MAC (unknown) */
    memcpy(pkt + 38, ip, 4);                 /* target IP */
    nic_send(pkt, sizeof(pkt));

    /* Deadline-bounded, not a fixed try count: after a large transfer the RX ring
     * is full of stale TCP packets that recv_timeout returns instantly, so a fixed
     * budget would be burned skipping them before the ARP reply arrives. Keep
     * draining-and-matching until the deadline instead. */
    uint8_t buf[1600];
    uint64_t deadline = timer_ticks() + 200;
    while (timer_ticks() < deadline) {
        int len = recv_timeout(buf, sizeof(buf), 20);
        if (len >= 42 && get16(buf + 12) == 0x0806 && get16(buf + 20) == 2 /*reply*/
            && memcmp(buf + 28, ip, 4) == 0) {
            memcpy(out_mac, buf + 22, 6);    /* sender MAC of the reply */
            static int rr = 0;               /* cache it (round-robin evict) */
            int slot = -1;
            for (int i = 0; i < ARP_CACHE_N; i++)
                if (arp_cache[i].used && memcmp(arp_cache[i].ip, ip, 4) == 0) { slot = i; break; }
            if (slot < 0) { slot = rr; rr = (rr + 1) % ARP_CACHE_N; }
            memcpy(arp_cache[slot].ip, ip, 4); memcpy(arp_cache[slot].mac, out_mac, 6);
            arp_cache[slot].exp = timer_ticks() + ARP_TTL; arp_cache[slot].used = 1;
            return 1;
        }
    }
    return 0;
}

/* Send one ICMP echo request to `ip` (via `dst_mac`) and await the reply. */
/* Send one echo request and DO NOT wait. Split out so a test can put another
 * NIC consumer between the request and the reply (M2018). */
static void ping_send(const uint8_t *ip, const uint8_t *dst_mac, uint16_t seq) {
    const uint8_t *mac = nic_mac();
    uint8_t pkt[42];                         /* 14 eth + 20 IP + 8 ICMP */

    /* ethernet */
    memcpy(pkt + 0, dst_mac, 6);
    memcpy(pkt + 6, mac, 6);
    put16(pkt + 12, 0x0800);                 /* IPv4 */

    /* IP header (20 bytes, at offset 14) */
    uint8_t *ip_h = pkt + 14;
    ip_h[0] = 0x45;                          /* version 4, IHL 5 */
    ip_h[1] = 0;                             /* DSCP/ECN */
    put16(ip_h + 2, 28);                     /* total length = 20 + 8 */
    put16(ip_h + 4, seq);                    /* identification */
    put16(ip_h + 6, 0);                      /* flags/fragment */
    ip_h[8] = 64;                            /* TTL */
    ip_h[9] = 1;                             /* protocol = ICMP */
    put16(ip_h + 10, 0);                     /* checksum (fill below) */
    memcpy(ip_h + 12, OUR_IP, 4);
    memcpy(ip_h + 16, ip, 4);
    put16(ip_h + 10, inet_checksum(ip_h, 20));

    /* ICMP header (8 bytes, at offset 34) */
    uint8_t *icmp = pkt + 34;
    icmp[0] = 8;                             /* type = echo request */
    icmp[1] = 0;                             /* code */
    put16(icmp + 2, 0);                      /* checksum (fill below) */
    put16(icmp + 4, 0x1234);                 /* identifier */
    put16(icmp + 6, seq);                    /* sequence */
    put16(icmp + 2, inet_checksum(icmp, 8));

    nic_send(pkt, sizeof(pkt));
}

static int ping(const uint8_t *ip, const uint8_t *dst_mac, uint16_t seq) {
    const uint8_t *mac = nic_mac();
    uint8_t pkt[42];                         /* 14 eth + 20 IP + 8 ICMP */

    /* ethernet */
    memcpy(pkt + 0, dst_mac, 6);
    memcpy(pkt + 6, mac, 6);
    put16(pkt + 12, 0x0800);                 /* IPv4 */

    /* IP header (20 bytes, at offset 14) */
    uint8_t *ip_h = pkt + 14;
    ip_h[0] = 0x45;                          /* version 4, IHL 5 */
    ip_h[1] = 0;                             /* DSCP/ECN */
    put16(ip_h + 2, 28);                     /* total length = 20 + 8 */
    put16(ip_h + 4, seq);                    /* identification */
    put16(ip_h + 6, 0);                      /* flags/fragment */
    ip_h[8] = 64;                            /* TTL */
    ip_h[9] = 1;                             /* protocol = ICMP */
    put16(ip_h + 10, 0);                     /* checksum (fill below) */
    memcpy(ip_h + 12, OUR_IP, 4);
    memcpy(ip_h + 16, ip, 4);
    put16(ip_h + 10, inet_checksum(ip_h, 20));

    /* ICMP header (8 bytes, at offset 34) */
    uint8_t *icmp = pkt + 34;
    icmp[0] = 8;                             /* type = echo request */
    icmp[1] = 0;                             /* code */
    put16(icmp + 2, 0);                      /* checksum (fill below) */
    put16(icmp + 4, 0x1234);                 /* identifier */
    put16(icmp + 6, seq);                    /* sequence */
    put16(icmp + 2, inet_checksum(icmp, 8));

    nic_send(pkt, sizeof(pkt));

    uint8_t buf[1600];
    uint64_t deadline = timer_ticks() + 200;   /* deadline-bounded (see arp_resolve) */
    while (timer_ticks() < deadline) {
        int len = recv_timeout(buf, sizeof(buf), 20);
        if (len >= 42 && get16(buf + 12) == 0x0800 && buf[14 + 9] == 1 /*ICMP*/
            && buf[34] == 0 /*echo reply*/ && memcmp(buf + 26, ip, 4) == 0) {
            return 1;
        }
    }
    return 0;
}

static uint8_t DNS_IP[4] = {10, 0, 2, 3};       /* SLIRP default; a DHCP lease may replace it */
const uint8_t *net_dns(void)     { return DNS_IP; }

int net_ping_gateway(void) {
    uint8_t mac[6];
    if (!arp_resolve(GW_IP, mac))
        return -1;
    int got = 0;
    for (uint16_t s = 1; s <= 3; s++)
        if (ping(GW_IP, mac, s))
            got++;
    return got;
}

/* Ping a host by name: DNS-resolve it, then ICMP-echo the address 3 times,
 * routed through the gateway (the next hop for any off-LAN destination — the
 * same ping() helper, just a remote target IP behind the gateway's MAC).
 * Returns the echo-reply count (0-3), or -1 if DNS or the gateway ARP fails. */
int net_ping_host(const char *host) {
    uint8_t ip[4];
    if (dns_resolve(host, ip) != 0) return -1;
    uint8_t mac[6];
    if (!arp_resolve(GW_IP, mac)) return -1;     /* route via the gateway */
    int got = 0;
    for (uint16_t s = 1; s <= 3; s++)
        if (ping(ip, mac, s))
            got++;
    return got;
}

/* Tiny DNS cache: browsing a site re-resolves the same host on every page/link
 * fetch, so cache recent answers. Entries expire after DNS_TTL ticks so a stale
 * IP is never served indefinitely; a cache miss just falls through to a query. */
#define DNS_CACHE_N 8
#define DNS_TTL     6000           /* 60 s at 100 Hz */
static struct { char host[64]; uint8_t ip[4]; uint64_t exp; int used; } dns_cache[DNS_CACHE_N];
static int dns_streq(const char *a, const char *b) {
    int i = 0; for (; a[i] && b[i]; i++) if (a[i] != b[i]) return 0;
    return a[i] == b[i];           /* equal only if both ended together */
}
static void dns_cache_put(const char *host, const uint8_t ip[4]) {
    int j = 0; while (host[j] && j < 63) j++;
    if (host[j]) return;           /* name too long to cache cleanly: skip */
    static int rr = 0;
    int slot = -1;
    for (int i = 0; i < DNS_CACHE_N; i++)
        if (dns_cache[i].used && dns_streq(dns_cache[i].host, host)) { slot = i; break; }
    if (slot < 0) { slot = rr; rr = (rr + 1) % DNS_CACHE_N; }   /* round-robin evict */
    for (int k = 0; k <= j; k++) dns_cache[slot].host[k] = host[k];
    memcpy(dns_cache[slot].ip, ip, 4);
    dns_cache[slot].exp = timer_ticks() + DNS_TTL;
    dns_cache[slot].used = 1;
}

/* Minimal DNS A-record lookup over UDP, to the SLIRP resolver at 10.0.2.3. */
int dns_resolve(const char *host, uint8_t out_ip[4]) {
    if (parse_ipv4(host, out_ip) == 0) return 0;   /* a dotted-quad literal (e.g. `ping 1.1.1.1`) is already an address — don't DNS-"resolve" it (M1879) */
    for (int i = 0; i < DNS_CACHE_N; i++)          /* serve a fresh cached answer */
        if (dns_cache[i].used && timer_ticks() < dns_cache[i].exp
            && dns_streq(dns_cache[i].host, host)) {
            memcpy(out_ip, dns_cache[i].ip, 4);
            return 0;
        }
    uint8_t mac[6];
    if (!arp_resolve(DNS_IP, mac))
        return -1;
    const uint8_t *me = nic_mac();

    /* build the DNS query payload */
    uint8_t q[256]; int dl = 0;
    put16(q + 0, 0x2A2A);          /* id */
    put16(q + 2, 0x0100);          /* flags: recursion desired */
    put16(q + 4, 1); put16(q + 6, 0); put16(q + 8, 0); put16(q + 10, 0);
    dl = 12;
    const char *p = host;
    while (*p) {
        int len = 0; while (p[len] && p[len] != '.' && len < 64) len++;  /* bound the read; a DNS label is max 63 bytes */
        if (len > 63 || dl + 1 + len > (int)sizeof(q) - 5) return -1;     /* reject a too-long label or one that would overflow q[] (leave room for root + QTYPE + QCLASS) */
        q[dl++] = (uint8_t)len;
        for (int i = 0; i < len; i++) q[dl++] = p[i];
        p += len; if (*p == '.') p++;
    }
    q[dl++] = 0;                    /* root label */
    put16(q + dl, 1); dl += 2;      /* QTYPE A */
    put16(q + dl, 1); dl += 2;      /* QCLASS IN */

    /* wrap in Ethernet/IPv4/UDP */
    uint8_t pkt[400];
    memcpy(pkt + 0, mac, 6); memcpy(pkt + 6, me, 6); put16(pkt + 12, 0x0800);
    uint8_t *ip = pkt + 14, *udp = pkt + 34;
    ip[0] = 0x45; ip[1] = 0; put16(ip + 2, 20 + 8 + dl); put16(ip + 4, 0x42);
    put16(ip + 6, 0); ip[8] = 64; ip[9] = 17; put16(ip + 10, 0);
    memcpy(ip + 12, OUR_IP, 4); memcpy(ip + 16, DNS_IP, 4);
    put16(ip + 10, inet_checksum(ip, 20));
    put16(udp + 0, 5353); put16(udp + 2, 53); put16(udp + 4, 8 + dl); put16(udp + 6, 0);
    memcpy(udp + 8, q, dl);
    nic_send(pkt, 34 + 8 + dl);

    /* await + parse the response — deadline-bounded (see arp_resolve): a fixed try
     * count would be exhausted skipping stale TCP packets left in the RX ring by a
     * prior large transfer before the DNS reply (which we keep waiting for) lands. */
    uint8_t buf[1600];
    uint64_t deadline = timer_ticks() + 500;
    while (timer_ticks() < deadline) {
        int len = recv_timeout(buf, sizeof(buf), 20);
        if (len < 42 || get16(buf + 12) != 0x0800 || buf[14 + 9] != 17) continue;   /* IPv4/UDP */
        int ihl = (buf[14] & 0x0F) * 4;        /* honor the real IP header length (IP options -> IHL>5); SLIRP uses 20 so this is a no-op there, but real routers may not */
        int doff = 14 + ihl + 8;               /* eth(14) + IP(ihl) + UDP(8) -> DNS payload (was hardcoded 42 = IHL 5) */
        if (ihl < 20 || len < doff + 12) continue;
        uint8_t *d = buf + doff;               /* DNS payload */
        int dmax = len - doff;                 /* bytes available in d[] (adversarial) */
        if (dmax < 12 || get16(d) != 0x2A2A) continue;
        int an = get16(d + 6);
        if (an < 1) continue;
        /* every offset below is driven by the reply, so bound each against dmax
         * (a malformed name chain / rdlen must never index past the packet). */
        int o = 12;
        while (o < dmax && d[o]) { if ((d[o] & 0xC0) == 0xC0) { o++; break; } o += d[o] + 1; }
        o++; o += 4;                            /* end-of-name + QTYPE/QCLASS */
        for (int a = 0; a < an; a++) {
            if (o + 1 > dmax) break;
            if ((d[o] & 0xC0) == 0xC0) o += 2;
            else { while (o < dmax && d[o]) o += d[o] + 1; o++; }
            if (o + 10 > dmax) break;           /* type(2)+class(2)+ttl(4)+rdlen(2) */
            int type = get16(d + o); o += 2; o += 2; o += 4;   /* type,class,ttl */
            int rdlen = get16(d + o); o += 2;
            if (type == 1 && rdlen == 4 && o + 4 <= dmax) { memcpy(out_ip, d + o, 4); dns_cache_put(host, out_ip); return 0; }
            o += rdlen;
        }
    }
    return -1;
}

/* ===================================================================== *
 *  DHCP client — obtain {IP, gateway, DNS} from the server (DORA).
 *
 *  Replaces the hardcoded SLIRP defaults with a real lease. Built on the
 *  same byte-wrangling as dns_resolve, but broadcast from 0.0.0.0:68 to
 *  255.255.255.255:67 (we have no IP yet, so the reply must be broadcast —
 *  that's what the BOOTP `flags` broadcast bit requests). QEMU's SLIRP
 *  runs a real DHCP server, so this works end-to-end under emulation.
 * ===================================================================== */
static const uint8_t DHCP_MAGIC[4] = { 0x63, 0x82, 0x53, 0x63 };

/* Build + send one BOOTP/DHCP message. `mtype` is the DHCP message type
 * (1=DISCOVER, 3=REQUEST). For REQUEST, reqip/srvid carry options 50/54. */
static void dhcp_send(uint32_t xid, uint8_t mtype, const uint8_t *reqip, const uint8_t *srvid) {
    const uint8_t *me = nic_mac();
    uint8_t pkt[400]; memset(pkt, 0, sizeof pkt);
    memcpy(pkt + 0, BROADCAST, 6); memcpy(pkt + 6, me, 6); put16(pkt + 12, 0x0800);
    uint8_t *ip = pkt + 14, *udp = pkt + 34, *bp = pkt + 42;
    /* BOOTP fixed header */
    bp[0] = 1; bp[1] = 1; bp[2] = 6; bp[3] = 0;            /* op=BOOTREQUEST, htype=eth, hlen=6 */
    bp[4] = xid >> 24; bp[5] = xid >> 16; bp[6] = xid >> 8; bp[7] = (uint8_t)xid;
    put16(bp + 10, 0x8000);                                /* flags: broadcast (we have no IP to unicast to) */
    memcpy(bp + 28, me, 6);                                /* chaddr = our MAC */
    memcpy(bp + 236, DHCP_MAGIC, 4);
    int o = 240;
    bp[o++] = 53; bp[o++] = 1; bp[o++] = mtype;            /* opt 53: DHCP message type */
    if (mtype == 3) {                                      /* REQUEST echoes the offered IP + server id */
        if (reqip) { bp[o++] = 50; bp[o++] = 4; memcpy(bp + o, reqip, 4); o += 4; }
        if (srvid) { bp[o++] = 54; bp[o++] = 4; memcpy(bp + o, srvid, 4); o += 4; }
    }
    bp[o++] = 55; bp[o++] = 3; bp[o++] = 1; bp[o++] = 3; bp[o++] = 6;  /* opt 55: want subnet(1), router(3), dns(6) */
    bp[o++] = 0xFF;                                        /* end */
    int blen = o;
    put16(udp + 0, 68); put16(udp + 2, 67); put16(udp + 4, (uint16_t)(8 + blen)); put16(udp + 6, 0);  /* UDP cksum 0 = none */
    ip[0] = 0x45; ip[1] = 0; put16(ip + 2, (uint16_t)(20 + 8 + blen)); put16(ip + 4, 0); put16(ip + 6, 0);
    ip[8] = 64; ip[9] = 17; put16(ip + 10, 0);
    memset(ip + 12, 0x00, 4);                              /* src 0.0.0.0 */
    memset(ip + 16, 0xFF, 4);                              /* dst 255.255.255.255 */
    put16(ip + 10, inet_checksum(ip, 20));
    nic_send(pkt, 42 + blen);
}

/* Await a DHCP reply matching `xid`. Returns the DHCP message type (2=OFFER,
 * 5=ACK, 6=NAK), filling yiaddr + any present server-id/router/dns; else 0. */
static int dhcp_recv(uint32_t xid, uint64_t ticks, uint8_t *yiaddr,
                     uint8_t *srvid, uint8_t *router, uint8_t *dns) {
    uint8_t buf[1600];
    uint64_t deadline = timer_ticks() + ticks;
    while (timer_ticks() < deadline) {
        int len = recv_timeout(buf, sizeof buf, 20);
        if (len < 282) continue;                           /* eth14+ip20+udp8+bootp240 */
        if (get16(buf + 12) != 0x0800 || buf[14 + 9] != 17) continue;   /* IPv4 + UDP */
        int ihl = (buf[14] & 0x0F) * 4; if (ihl < 20) continue;
        uint8_t *udp = buf + 14 + ihl;
        if (get16(udp + 2) != 68) continue;                /* UDP dst port 68 (DHCP client) */
        uint8_t *bp = udp + 8;
        int boff = (int)(bp - buf);
        if (boff + 240 > len || bp[0] != 2) continue;      /* room for BOOTP + op=BOOTREPLY */
        uint32_t rxid = ((uint32_t)bp[4] << 24) | ((uint32_t)bp[5] << 16) | ((uint32_t)bp[6] << 8) | bp[7];
        if (rxid != xid || memcmp(bp + 236, DHCP_MAGIC, 4) != 0) continue;
        memcpy(yiaddr, bp + 16, 4);                        /* yiaddr = the IP being offered/leased to us */
        int mtype = 0, o = 240;
        while (boff + o < len && bp[o] != 0xFF) {          /* walk TLV options, bounded by the packet */
            if (bp[o] == 0) { o++; continue; }             /* pad */
            int t = bp[o++]; if (boff + o >= len) break;
            int l = bp[o++]; if (boff + o + l > len) break;
            if      (t == 53 && l == 1) mtype = bp[o];
            else if (t == 54 && l == 4 && srvid)  memcpy(srvid,  bp + o, 4);
            else if (t == 3  && l >= 4 && router) memcpy(router, bp + o, 4);
            else if (t == 6  && l >= 4 && dns)    memcpy(dns,    bp + o, 4);
            o += l;
        }
        if (mtype) return mtype;
    }
    return 0;
}

/* The DORA handshake. On success, commits the lease into OUR_IP/GW_IP/DNS_IP
 * and returns 0; on timeout/NAK returns -1 with the prior config left intact. */
int net_dhcp(void) {
    const uint8_t *me = nic_mac();
    uint32_t xid = 0x4f534400u ^ (uint32_t)timer_ticks()
                 ^ ((uint32_t)me[2] << 24) ^ ((uint32_t)me[3] << 16)
                 ^ ((uint32_t)me[4] << 8)  ^ me[5];
    uint8_t yiaddr[4] = {0}, srvid[4] = {0}, router[4] = {0}, dns[4] = {0};

    int got = 0;
    for (int t = 0; t < 4 && !got; t++) {                  /* DISCOVER -> OFFER */
        dhcp_send(xid, 1, 0, 0);
        if (dhcp_recv(xid, 150, yiaddr, srvid, router, dns) == 2) got = 1;
    }
    if (!got) return -1;

    got = 0;
    for (int t = 0; t < 4 && !got; t++) {                  /* REQUEST -> ACK */
        dhcp_send(xid, 3, yiaddr, srvid);
        int mt = dhcp_recv(xid, 150, yiaddr, srvid, router, dns);
        if (mt == 5) got = 1;
        else if (mt == 6) return -1;                       /* NAK */
    }
    if (!got) return -1;

    memcpy(OUR_IP, yiaddr, 4);                             /* commit the lease */
    if (router[0] | router[1] | router[2] | router[3]) {
        memcpy(GW_IP, router, 4);
    } else {
        /* NO ROUTER OPTION, AND KEEPING THE OLD ONE IS THE WORST CHOICE (M2121).
         *
         * This network's DHCP server hands out an address and a nameserver and
         * no option 3 -- which it is entitled to do, and our DISCOVER does ask
         * for one (option 55 lists subnet, router and DNS). The old code then
         * left GW_IP at the compiled-in SLIRP default 10.0.2.2, which is an
         * address on a network this machine is not on. The result was a lease
         * that looked perfect and no route off the subnet:
         *
         *   [net] e1000 up, IP = 192.168.1.224 (DHCP)
         *   [lxabi] /etc/resolv.conf -> nameserver 1.1.1.1
         *   [net] HTTP GET example.com failed (no internet route?)
         *
         * A guess is unavoidable here, so make the LEAST wrong one and say it
         * is a guess: the .1 of our own /24, which is the gateway on very
         * nearly every network that hands out addresses at all. Silently
         * keeping an address from a different network is not a smaller guess,
         * it is the same guess and a worse one. */
        GW_IP[0] = yiaddr[0]; GW_IP[1] = yiaddr[1]; GW_IP[2] = yiaddr[2]; GW_IP[3] = 1;
        kprintf("[net] the lease carried NO router option; GUESSING the gateway is "
                "%u.%u.%u.1 (the .1 of our own /24) rather than keeping the SLIRP default\n",
                yiaddr[0], yiaddr[1], yiaddr[2]);
    }
    if (dns[0] | dns[1] | dns[2] | dns[3])             memcpy(DNS_IP, dns, 4);
    g_have_lease = 1;                                      /* a server really answered (M2120) */
    kprintf("[net] lease: ip %u.%u.%u.%u  gw %u.%u.%u.%u  dns %u.%u.%u.%u\n",
            OUR_IP[0], OUR_IP[1], OUR_IP[2], OUR_IP[3],
            GW_IP[0], GW_IP[1], GW_IP[2], GW_IP[3],
            DNS_IP[0], DNS_IP[1], DNS_IP[2], DNS_IP[3]);
    return 0;
}

/* ===================================================================== *
 *  A general UDP datagram send + a TFTP client (RFC 1350).
 *
 *  udp_send_to wraps a payload in Ethernet/IPv4/UDP and ships it — the
 *  reusable datagram primitive DNS/DHCP open-coded. TFTP rides on it:
 *  RRQ -> the server streams DATA blocks, we ACK each. QEMU's SLIRP has a
 *  built-in TFTP server at 10.0.2.2 (`-netdev user,tftp=DIR`), so this is
 *  verifiable with no external infrastructure.
 * ===================================================================== */
int parse_ipv4(const char *s, uint8_t out[4]) {
    int oct = 0, v = 0, any = 0;
    for (int i = 0; i < 4; i++) out[i] = 0;
    for (;; s++) {
        if (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); any = 1; if (v > 255) return -1; }
        else if (*s == '.' || *s == 0) {
            if (!any || oct > 3) return -1;
            out[oct++] = (uint8_t)v; v = 0; any = 0;
            if (*s == 0) break;
        } else return -1;
    }
    return oct == 4 ? 0 : -1;
}

/* Send a UDP datagram (payload plen bytes) from sport to dstip:dport via dstmac. */
static void udp_send_to(const uint8_t *dstmac, const uint8_t *dstip,
                        uint16_t sport, uint16_t dport, const uint8_t *payload, int plen) {
    if (plen < 0 || plen > 1400) return;
    const uint8_t *me = nic_mac();
    uint8_t pkt[1500];
    memcpy(pkt + 0, dstmac, 6); memcpy(pkt + 6, me, 6); put16(pkt + 12, 0x0800);
    uint8_t *ip = pkt + 14, *udp = pkt + 34, *pl = pkt + 42;
    ip[0] = 0x45; ip[1] = 0; put16(ip + 2, (uint16_t)(20 + 8 + plen)); put16(ip + 4, 0); put16(ip + 6, 0);
    ip[8] = 64; ip[9] = 17; put16(ip + 10, 0);
    memcpy(ip + 12, OUR_IP, 4); memcpy(ip + 16, dstip, 4);
    put16(ip + 10, inet_checksum(ip, 20));
    put16(udp + 0, sport); put16(udp + 2, dport); put16(udp + 4, (uint16_t)(8 + plen)); put16(udp + 6, 0);
    for (int i = 0; i < plen; i++) pl[i] = payload[i];
    nic_send(pkt, 42 + plen);
}

/* ===================================================================== *
 *  Userspace UDP sockets (M1258): expose the datagram primitive to ring 3
 *  via SYS_udp_send / SYS_udp_recv, so programs can speak their OWN UDP
 *  protocols (a resolver, a netcat, custom netcode) instead of relying on
 *  the kernel's built-in DNS/DHCP/TFTP/SNTP. Connectionless: the caller
 *  picks a local port; recv filters the RX ring by that port.
 * ===================================================================== */

/* Send `plen` payload bytes to dstip:dport from local port sport. ARP-resolves
 * dstip directly (on-subnet) or via the gateway. Returns 0 on success, -1 on
 * bad-arg / ARP failure. */
int net_udp_send(const uint8_t dstip[4], uint16_t dport, uint16_t sport,
                 const void *payload, int plen) {
    if (!dstip || plen < 0 || plen > 1400) return -1;
    if (dstip[0] == 127) {                          /* loopback (127.0.0.0/8) -> re-inject, no NIC (M1264) */
        const uint8_t *me = nic_mac();
        uint8_t pkt[1500];
        memcpy(pkt + 0, me, 6); memcpy(pkt + 6, me, 6); put16(pkt + 12, 0x0800);   /* eth: to/from self */
        uint8_t *ip = pkt + 14, *udp = pkt + 34, *pl = pkt + 42;
        ip[0] = 0x45; ip[1] = 0; put16(ip + 2, (uint16_t)(20 + 8 + plen)); put16(ip + 4, 0); put16(ip + 6, 0);
        ip[8] = 64; ip[9] = 17; put16(ip + 10, 0);
        memcpy(ip + 12, dstip, 4); memcpy(ip + 16, dstip, 4);   /* src=dst=127.x */
        put16(ip + 10, inet_checksum(ip, 20));
        put16(udp + 0, sport); put16(udp + 2, dport); put16(udp + 4, (uint16_t)(8 + plen)); put16(udp + 6, 0);
        for (int i = 0; i < plen; i++) pl[i] = ((const uint8_t *)payload)[i];
        lo_enqueue(pkt, 42 + plen);
        return 0;
    }
    uint8_t mac[6];
    if (!arp_resolve(dstip, mac) && !arp_resolve(GW_IP, mac)) return -1;   /* dest, else via gateway */
    udp_send_to(mac, dstip, sport, dport, (const uint8_t *)payload, plen);
    return 0;
}

/* Wait up to timeout_ms for a UDP datagram addressed to our local port `sport`.
 * Copies up to `max` payload bytes into buf; fills srcip[4] / *srcport (if
 * non-NULL) with the sender. Returns payload bytes (>=0) or -1 on timeout. */
/* --- received datagrams, queued per local port (M1967) ----------------------
 *
 * net_udp_recv used to pull frames straight off the NIC and DROP everything
 * that was not a UDP datagram for the port it was asked about. Two consequences
 * it could not avoid:
 *
 *  - Nothing could answer "does this socket have a datagram?" without
 *    CONSUMING it, so a UDP fd could not be polled -- and DNS is a UDP socket
 *    inside an event loop.
 *  - It destroyed TCP segments belonging to LIVE CONNECTIONS. A resolver
 *    running alongside an HTTP fetch silently ate that fetch's data. TCP
 *    retransmits, so this looked like "the network is slow" rather than like a
 *    bug, which is exactly why it survived.
 *
 * Now a pump parks TCP frames (the M1908 ring) and queues UDP datagrams by
 * destination port, and both recv and poll read the queue. */
/* 16 -> 48 (M2022): a DNS lookup in flight while another consumer floods the
 * NIC used to lose its reply to eviction. */
#define UDPQ_N    48
#define UDPQ_MAX  1500
#define UDPQ_TTL  500                  /* ticks (~5s): a datagram nobody claims must not hold a slot */
static struct {
    uint8_t  buf[UDPQ_MAX];
    int      len;                      /* 0 = free */
    uint16_t dport;                    /* OUR local port -- what recv matches on */
    uint8_t  srcip[4];
    uint16_t srcport;
    uint64_t at;
} g_udpq[UDPQ_N];

static void park_put(const uint8_t *f, int len);   /* defined with the TCP demux below */

static void udpq_put(const uint8_t *f, int len) {
    int ihl = (f[14] & 0x0F) * 4;
    if (ihl < 20 || len < 14 + ihl + 8) return;
    const uint8_t *udp = f + 14 + ihl;
    int plen = (int)get16(udp + 4) - 8;
    int avail = len - (14 + ihl + 8);
    if (plen < 0) plen = 0;
    if (plen > avail) plen = avail;                /* never trust the length field over what arrived */
    if (plen > UDPQ_MAX) plen = UDPQ_MAX;
    uint64_t now = timer_ticks();
    int slot = -1;
    for (int i = 0; i < UDPQ_N; i++) {
        if (g_udpq[i].len && now - g_udpq[i].at > UDPQ_TTL) g_udpq[i].len = 0;
        if (!g_udpq[i].len && slot < 0) slot = i;
    }
    if (slot < 0) {                                /* full: evict the oldest */
        uint64_t oldest = ~0ull; slot = 0;
        for (int i = 0; i < UDPQ_N; i++) if (g_udpq[i].at < oldest) { oldest = g_udpq[i].at; slot = i; }
    }
    for (int i = 0; i < plen; i++) g_udpq[slot].buf[i] = udp[8 + i];
    /* len == 0 is this table's "slot free" marker, so a zero-length datagram
     * cannot be represented and is dropped rather than queued as something it
     * is not. Nothing sends them here; saying so beats a silent quirk. */
    if (plen == 0) return;
    g_udpq[slot].len = plen;
    g_udpq[slot].dport   = get16(udp + 2);
    g_udpq[slot].srcport = get16(udp + 0);
    for (int i = 0; i < 4; i++) g_udpq[slot].srcip[i] = f[14 + 12 + i];
    g_udpq[slot].at      = now;
}

/* Dequeue a datagram for `sport`. Returns its length, or -1 if none. */
static int udpq_take(uint16_t sport, void *buf, int max, uint8_t srcip[4], uint16_t *srcport) {
    uint64_t now = timer_ticks();
    for (int i = 0; i < UDPQ_N; i++) {
        if (!g_udpq[i].len) continue;
        if (now - g_udpq[i].at > UDPQ_TTL) { g_udpq[i].len = 0; continue; }
        if (g_udpq[i].dport != sport) continue;
        int n = g_udpq[i].len; if (n > max) n = max;
        for (int k = 0; k < n; k++) ((uint8_t *)buf)[k] = g_udpq[i].buf[k];
        if (srcip)   for (int k = 0; k < 4; k++) srcip[k] = g_udpq[i].srcip[k];
        if (srcport) *srcport = g_udpq[i].srcport;
        g_udpq[i].len = 0;
        return n;
    }
    return -1;
}

/* Drain the NIC once: UDP datagrams to the queue, TCP frames to the park ring,
 * everything else discarded. Returns 1 if a datagram for `want` arrived. */
static int udp_pump_once(uint16_t want) {
    uint8_t rb[1600];
    int got = 0;
    for (;;) {
        int len = nic_receive(rb, sizeof rb);
        if (len < 14) break;
        if (get16(rb + 12) != 0x0800) continue;                 /* not IPv4 */
        if (rb[14 + 9] == 17 && len >= 14 + 20 + 8) {           /* UDP */
            int ihl = (rb[14] & 0x0F) * 4;
            if (ihl >= 20 && len >= 14 + ihl + 8) {
                uint16_t d = get16(rb + 14 + ihl + 2);
                udpq_put(rb, len);
                if (d == want) got = 1;
            }
        } else if (rb[14 + 9] == 6) {                           /* TCP: someone else's, park it */
            park_put(rb, len);
        } else {
            /* ICMP and anything else: file it, do not destroy it. This line is
             * why `ping` reported 1 reply out of 3 while all three were on the
             * wire -- a DNS lookup's pump had eaten the other two. (M2017) */
            oring_put(rb, len);
        }
    }
    return got;
}

int net_udp_recv(uint16_t sport, void *buf, int max,
                 uint8_t srcip[4], uint16_t *srcport, int timeout_ms) {
    if (!buf || max <= 0) return -1;
    if (timeout_ms < 0) timeout_ms = 0;
    int n = udpq_take(sport, buf, max, srcip, srcport);
    if (n >= 0) return n;
    udp_pump_once(sport);
    n = udpq_take(sport, buf, max, srcip, srcport);
    if (n >= 0) return n;
    if (timeout_ms == 0) return -1;                             /* non-blocking: nothing waiting */
    uint64_t deadline = timer_ticks() + (uint64_t)timeout_ms / 10 + 1;
    while (timer_ticks() < deadline) {
        udp_pump_once(sport);
        n = udpq_take(sport, buf, max, srcip, srcport);
        if (n >= 0) return n;
        task_sleep_ms(2);                                       /* let the NIC refill; do not spin a core */
    }
    return -1;
}

/* poll/epoll: is a datagram waiting for this local port? Never consumes it. */
int net_udp_readable(uint16_t sport) {
    uint64_t now = timer_ticks();
    for (int i = 0; i < UDPQ_N; i++)
        if (g_udpq[i].len && now - g_udpq[i].at <= UDPQ_TTL && g_udpq[i].dport == sport) return 1;
    udp_pump_once(sport);
    for (int i = 0; i < UDPQ_N; i++)
        if (g_udpq[i].len && now - g_udpq[i].at <= UDPQ_TTL + 1 && g_udpq[i].dport == sport) return 1;
    return 0;
}

/* FIONREAD on a datagram socket (M2086): the length of the datagram the NEXT
 * recvfrom would return, which is what Linux reports here -- not the total of
 * everything queued. It must therefore walk the queue in exactly udpq_take's
 * order, including its TTL test, or the number describes a different datagram
 * from the one that arrives. Returns 0 when nothing is waiting. */
long net_udp_nread(uint16_t sport) {
    uint64_t now = timer_ticks();
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < UDPQ_N; i++) {
            if (!g_udpq[i].len) continue;
            if (now - g_udpq[i].at > UDPQ_TTL + (uint64_t)pass) continue;
            if (g_udpq[i].dport != sport) continue;
            return (long)g_udpq[i].len;
        }
        if (pass == 0) udp_pump_once(sport);
    }
    return 0;
}

/* ===================================================================== *
 *  Raw packet sockets (M1259): AF_PACKET/SOCK_RAW — ring 3 gets the WHOLE
 *  Ethernet frame (dst+src MAC + ethertype + payload). Lets userspace build
 *  arbitrary L2 frames (a custom protocol, an ARP tool) and sniff every
 *  frame the NIC receives (a tcpdump-lite). Single-user OS: no privilege
 *  gate (matches the OS's existing low-level access surface).
 * ===================================================================== */

/* Transmit a complete Ethernet frame verbatim (the caller builds all 14+ bytes
 * of header + payload). Returns 0/-1. */
int net_raw_send(const void *frame, int len) {
    if (!frame || len < 14 || len > 1514) return -1;
    return nic_send(frame, (uint16_t)len) == 0 ? 0 : -1;
}

/* Receive the next complete Ethernet frame (up to max bytes) within timeout_ms.
 * Returns the frame length (>=14) or -1 on timeout. */
int net_raw_recv(void *buf, int max, int timeout_ms) {
    if (!buf || max < 14) return -1;
    if (timeout_ms < 0) timeout_ms = 0;
    uint8_t rb[1600];
    uint64_t deadline = timer_ticks() + (uint64_t)timeout_ms / 10 + 1;
    while (timer_ticks() < deadline) {
        int len = recv_timeout(rb, sizeof(rb), 20);
        if (len < 14) continue;                               /* runt / nothing */
        if (len > max) len = max;
        for (int i = 0; i < len; i++) ((uint8_t *)buf)[i] = rb[i];
        return len;
    }
    return -1;
}

/* ===================================================================== *
 *  TCP client sockets (M1268): persistent tcp_conn TCBs backing AF_INET
 *  SOCK_STREAM fds. The engine is single-connection, so this supports a
 *  client connecting OUT (one active conn at a time) — connect/send/recv/
 *  close. A multi-connection server (listen/accept over N TCBs) is the L
 *  follow-on. read/write on the fd map to tcp_read/tcp_write.
 * ===================================================================== */
/* 2 concurrent TCP sockets was a demo limit: the stack could open a connection
 * and nothing else. An event loop opens one per request. (M1967) */
#define TCPSOCK_N 64
#define TCPSOCK_RX 16384          /* per-socket receive ring: what poll() reports on */
/* opt_reuseaddr/opt_nodelay/opt_keepalive (M1554): setsockopt/getsockopt
 * storage. This stack has no Nagle-style write batching to disable (every
 * net_tcp_sock_send call reaches tcp_write immediately) and the client-only
 * connection model here has no listening-socket bind-conflict to bypass, so
 * neither option changes observable behavior -- store+readback is genuinely
 * all there is to implement honestly, matching real setsockopt's own
 * contract for plenty of options on plenty of stacks. The real value is
 * compatibility: ported code that calls setsockopt(SO_REUSEADDR/TCP_NODELAY)
 * before use, as a huge amount of real networking code unconditionally
 * does, no longer has to fail or be special-cased out. */
/* rx[] is the piece that makes an AF_INET socket POLLABLE (M1967).
 *
 * tcp_read pulls frames straight off the NIC, so before this there was no way
 * to answer "is this socket readable?" without CONSUMING the answer -- and an
 * event loop asks exactly that, about every socket it owns, before it reads
 * any of them. poll() therefore had to report POLLNVAL for socket fds, which
 * is why libuv could not drive them at all.
 *
 * Now a non-blocking pump drains the NIC into this ring (parking other
 * connections' frames as it goes, M1908), readiness is "is the ring
 * non-empty", and a read drains the ring. The TCP logic itself is unchanged --
 * this is a buffer in front of it, not a second implementation. */
static struct {
    int used, refs; tcp_conn c;
    int opt_reuseaddr, opt_nodelay, opt_keepalive, opt_rcvtimeo;
    uint8_t  rx[TCPSOCK_RX];
    int      rxhead, rxtail;      /* empty when head == tail */
    int      nonblock;            /* SOCK_NONBLOCK / O_NONBLOCK */
    int      eof;                 /* peer closed and the ring is the last of it */
} g_tcpsock[TCPSOCK_N];

static int rxcount(int i) { return g_tcpsock[i].rxhead - g_tcpsock[i].rxtail; }
static int rxspace(int i) { return TCPSOCK_RX - rxcount(i); }
static void rxcompact(int i) {                     /* reclaim the drained prefix */
    int n = rxcount(i);
    for (int k = 0; k < n; k++) g_tcpsock[i].rx[k] = g_tcpsock[i].rx[g_tcpsock[i].rxtail + k];
    g_tcpsock[i].rxtail = 0; g_tcpsock[i].rxhead = n;
}

/* Drain everything the NIC has for this socket into its ring. Never blocks.
 * Returns the number of bytes added. */
static int tcpsock_pump(int idx) {
    if (idx < 0 || idx >= TCPSOCK_N || !g_tcpsock[idx].used) return 0;
    if (!g_tcpsock[idx].c.up) return 0;
    if (g_tcpsock[idx].rxtail > 0 && rxspace(idx) < 1600) rxcompact(idx);
    int added = 0;
    for (;;) {
        int space = rxspace(idx);
        if (space <= 0) break;                      /* ring full: leave it on the wire */
        long n = tcp_read(&g_tcpsock[idx].c, g_tcpsock[idx].rx + g_tcpsock[idx].rxhead, space, 0);
        if (n <= 0) {
            /* tcp_read returns -1 when the connection closed (FIN/RST). That is
             * EOF, not an error, and it must be remembered: the ring may still
             * hold bytes the caller has not read, and reporting the close
             * before they are drained loses them. */
            if (n < 0) g_tcpsock[idx].eof = 1;
            break;
        }
        g_tcpsock[idx].rxhead += (int)n;
        added += (int)n;
    }
    return added;
}

/* poll/epoll: would a read return without blocking? Buffered bytes, or EOF. */
int net_tcp_sock_readable(int idx) {
    if (idx < 0 || idx >= TCPSOCK_N || !g_tcpsock[idx].used) return 0;
    if (rxcount(idx) > 0) return 1;
    tcpsock_pump(idx);
    return rxcount(idx) > 0 || g_tcpsock[idx].eof || !g_tcpsock[idx].c.up;
}
/* FIONREAD on a connected socket (M2086): how many bytes the receive ring
 * holds, pumping the NIC first for the same reason net_tcp_sock_readable does
 * -- the bytes may still be on the wire, and a count that reads zero while a
 * segment is queued in the driver is the same lie as POLLNVAL was. A pending
 * EOF counts as zero bytes, which is exactly right: read() will return 0. */
/* THE REAL RECEIVE-RING SIZE, for SO_RCVBUF (M2088). A socket option that
 * reports a number a program then sizes its logic from must be the number that
 * is actually there. */
int net_tcp_sock_bufbytes(void) { return TCPSOCK_RX; }
long net_tcp_sock_nread(int idx) {
    if (idx < 0 || idx >= TCPSOCK_N || !g_tcpsock[idx].used) return -1;
    if (rxcount(idx) == 0) tcpsock_pump(idx);
    return rxcount(idx);
}
/* A connected socket is always writable here: tcp_write sends immediately. */
int net_tcp_sock_writable(int idx) {
    if (idx < 0 || idx >= TCPSOCK_N || !g_tcpsock[idx].used) return 0;
    return g_tcpsock[idx].c.up ? 1 : 0;
}
int net_tcp_sock_set_nonblock(int idx, int on) {
    if (idx < 0 || idx >= TCPSOCK_N || !g_tcpsock[idx].used) return -1;
    g_tcpsock[idx].nonblock = on ? 1 : 0;
    return 0;
}

int net_tcp_sock_open(void) {
    for (int i = 0; i < TCPSOCK_N; i++) if (!g_tcpsock[i].used) {
        g_tcpsock[i].used = 1; g_tcpsock[i].refs = 1; g_tcpsock[i].c.up = 0;
        g_tcpsock[i].c.ooo_idx = -1;    /* no reassembly/FIN slot claimed until tcp_connect() actually runs (M1606) --
                                          * net_tcp_sock_close() calls tcp_close() unconditionally, even on a socket()
                                          * that was closed without ever connect()ing, and a fresh BSS-zeroed slot's
                                          * ooo_idx would otherwise read as 0 -- a real (in-use-or-not) table index,
                                          * not "none" -- and wrongly release whichever OTHER live connection owns it */
        g_tcpsock[i].c.sport = g_tcpsock[i].c.dport = 0;    /* clear a reused slot's stale port/peer (M1560) --
                                                              * getsockname/getpeername now make these visible,
                                                              * where before a slot's leftover values from its
                                                              * previous connection were write-only until the
                                                              * next tcp_connect() overwrote them anyway */
        for (int k = 0; k < 4; k++) g_tcpsock[i].c.ip[k] = 0;
        g_tcpsock[i].c.errno_hint = 0;   /* same staleness concern, now that SO_ERROR (M1564) makes it visible too */
        g_tcpsock[i].opt_reuseaddr = g_tcpsock[i].opt_nodelay = g_tcpsock[i].opt_keepalive = 0;
        g_tcpsock[i].opt_rcvtimeo = 3000;   /* ms; matches net_tcp_sock_recv's own prior hardcoded ~3s (M1583) */
        g_tcpsock[i].rxhead = g_tcpsock[i].rxtail = 0;   /* never inherit a previous connection's bytes (M1967) */
        g_tcpsock[i].nonblock = 0;
        g_tcpsock[i].eof = 0;
        return i;
    }
    return -1;
}
int net_tcp_sock_setopt(int idx, int level, int optname, int val) {
    if (idx < 0 || idx >= TCPSOCK_N || !g_tcpsock[idx].used) return -1;
    if (level == SOL_SOCKET && optname == SO_REUSEADDR) { g_tcpsock[idx].opt_reuseaddr = val; return 0; }
    if (level == SOL_SOCKET && optname == SO_KEEPALIVE) { g_tcpsock[idx].opt_keepalive = val; return 0; }
    if (level == IPPROTO_TCP && optname == TCP_NODELAY) { g_tcpsock[idx].opt_nodelay   = val; return 0; }
    if (level == SOL_SOCKET && optname == SO_RCVTIMEO)  { g_tcpsock[idx].opt_rcvtimeo  = val; return 0; }   /* (M1583) */
    return -1;                                              /* unknown (level, optname) pair */
}
int net_tcp_sock_getopt(int idx, int level, int optname, int *val) {
    if (idx < 0 || idx >= TCPSOCK_N || !g_tcpsock[idx].used) return -1;
    if (level == SOL_SOCKET && optname == SO_REUSEADDR) { *val = g_tcpsock[idx].opt_reuseaddr; return 0; }
    if (level == SOL_SOCKET && optname == SO_KEEPALIVE) { *val = g_tcpsock[idx].opt_keepalive; return 0; }
    if (level == IPPROTO_TCP && optname == TCP_NODELAY) { *val = g_tcpsock[idx].opt_nodelay;   return 0; }
    if (level == SOL_SOCKET && optname == SO_RCVTIMEO)  { *val = g_tcpsock[idx].opt_rcvtimeo;  return 0; }   /* (M1583) */
    if (level == SOL_SOCKET && optname == SO_ERROR) {         /* read-once (M1564): real SO_ERROR clears after reading */
        *val = g_tcpsock[idx].c.errno_hint;
        g_tcpsock[idx].c.errno_hint = 0;
        return 0;
    }
    return -1;
}
/* getsockname/getpeername (M1560): the wire format matches connect()'s own
 * (M1268) -- 6 raw bytes, {ip[4], port lo, port hi}, no sockaddr/family/
 * length -- since that's the only address shape this stack has ever used.
 * getsockname reports OUR address: this stack is single-homed (one NIC/IP,
 * net_ip()) with no per-socket local IP to track, so only the port varies;
 * it's 0 until a successful connect() assigns an ephemeral one. */
int net_tcp_sock_getname(int idx, uint8_t out[6]) {
    if (idx < 0 || idx >= TCPSOCK_N || !g_tcpsock[idx].used) return -1;
    const uint8_t *ip = net_ip();
    for (int i = 0; i < 4; i++) out[i] = ip[i];
    out[4] = (uint8_t)(g_tcpsock[idx].c.sport & 0xFF);
    out[5] = (uint8_t)(g_tcpsock[idx].c.sport >> 8);
    return 0;
}
int net_tcp_sock_getpeer(int idx, uint8_t out[6]) {
    if (idx < 0 || idx >= TCPSOCK_N || !g_tcpsock[idx].used || !g_tcpsock[idx].c.up) return -1;   /* ENOTCONN-equivalent */
    for (int i = 0; i < 4; i++) out[i] = g_tcpsock[idx].c.ip[i];
    out[4] = (uint8_t)(g_tcpsock[idx].c.dport & 0xFF);
    out[5] = (uint8_t)(g_tcpsock[idx].c.dport >> 8);
    return 0;
}
int net_tcp_sock_connect(int idx, const uint8_t ip[4], uint16_t port) {
    if (idx < 0 || idx >= TCPSOCK_N || !g_tcpsock[idx].used) return -1;
    return tcp_connect(&g_tcpsock[idx].c, ip, port);
}
long net_tcp_sock_send(int idx, const void *buf, int len) {
    if (idx < 0 || idx >= TCPSOCK_N || !g_tcpsock[idx].used) return -1;
    return tcp_write(&g_tcpsock[idx].c, (const uint8_t *)buf, len);
}
long net_tcp_sock_recv(int idx, void *buf, int max) {
    if (idx < 0 || idx >= TCPSOCK_N || !g_tcpsock[idx].used) return -1;
    /* SO_RCVTIMEO (M1583): opt_rcvtimeo is ms, tcp_read wants ticks (10ms each,
     * timer.c's tick_ms) -- round up so any nonzero request waits at least that
     * long rather than truncating a sub-tick value down to an instant return.
     * 0 -> block (near-)indefinitely, matching real SO_RCVTIMEO's own meaning;
     * tcp_read has no true infinite mode, so approximate it with a deadline far
     * enough out that no realistic caller will ever actually reach it. */
    /* Serve the ring first -- the pump may already have pulled these bytes off
     * the wire on a previous poll, and going back to tcp_read for them would
     * wait for data that has already arrived. (M1967) */
    if (rxcount(idx) == 0) tcpsock_pump(idx);
    if (rxcount(idx) > 0) {
        int n = rxcount(idx); if (n > max) n = max;
        for (int k = 0; k < n; k++) ((uint8_t *)buf)[k] = g_tcpsock[idx].rx[g_tcpsock[idx].rxtail + k];
        g_tcpsock[idx].rxtail += n;
        if (g_tcpsock[idx].rxtail == g_tcpsock[idx].rxhead) g_tcpsock[idx].rxtail = g_tcpsock[idx].rxhead = 0;
        return n;
    }
    if (g_tcpsock[idx].eof || !g_tcpsock[idx].c.up) return 0;     /* EOF, only once drained */
    if (g_tcpsock[idx].nonblock) return NET_SOCK_EAGAIN;
    /* THE BLOCKING PATH MUST GO THROUGH THE RING TOO (M2018).
     *
     * This used to call tcp_read straight into the caller's buffer, which
     * makes TWO consumers of one TCP byte stream: this call, and tcpsock_pump
     * running from any other thread's poll() or epoll() on the same socket.
     * Each tcp_read takes whatever has arrived, so the stream gets SPLIT
     * between the caller's buffer and the ring -- and then served out of
     * order, because the ring's bytes are handed to a LATER recv even when
     * they came FIRST.
     *
     * The byte COUNT still matches the wire, which is what makes it so hard to
     * see: a capture shows every byte arriving and every byte being delivered.
     * What is wrong is the ORDER, and downstream that looks like a truncated
     * HTTP response or a TLS record whose length no longer makes sense.
     *
     * One consumer. Pump into the ring with a deadline, then serve from the
     * ring exactly as the non-blocking path does. */
    /* timer_TICKS, not timer_ms: net.c is compiled into the host test harness
     * too, and only the tick clock is stubbed there. (Same coupling the
     * memory notes call out -- a cross-module call breaks the host link.) */
    uint64_t ms = (uint64_t)g_tcpsock[idx].opt_rcvtimeo;
    uint64_t deadline = timer_ticks() + (ms ? (ms + 9) / 10 : 30000);
    for (;;) {
        if (tcpsock_pump(idx) > 0 || rxcount(idx) > 0) break;
        if (g_tcpsock[idx].eof || !g_tcpsock[idx].c.up) return 0;
        /* A TIMEOUT IS NOT END-OF-STREAM (M2026).
         *
         * This returned 0, and app_fd_read hands that straight to the
         * application, where POSIX read() defines 0 as END OF FILE. So a
         * socket that simply had nothing to give YET was reported as a
         * connection the peer had closed.
         *
         * Claude Code froze mid-answer on exactly this. The capture shows the
         * whole exchange succeeding -- request out, `len=1367` of response
         * back, our own ACK for it -- and no FIN and no RST anywhere. The
         * reply was sitting in this stack while the reader was told the
         * stream had ended, so it waited for a continuation that, as far as
         * it was concerned, could never come.
         *
         * EOF is one specific thing and it is already tested one line above:
         * `eof` or the connection down. Everything else is "not yet", which
         * is what EAGAIN means. */
        if (timer_ticks() >= deadline) return NET_SOCK_EAGAIN;    /* no data YET -- not EOF */
        task_sleep_ms(2);
    }
    {
        int n = rxcount(idx); if (n > max) n = max;
        for (int k = 0; k < n; k++) ((uint8_t *)buf)[k] = g_tcpsock[idx].rx[g_tcpsock[idx].rxtail + k];
        g_tcpsock[idx].rxtail += n;
        if (g_tcpsock[idx].rxtail == g_tcpsock[idx].rxhead) g_tcpsock[idx].rxtail = g_tcpsock[idx].rxhead = 0;
        return n;
    }
}
void net_tcp_sock_ref(int idx) { if (idx >= 0 && idx < TCPSOCK_N && g_tcpsock[idx].used) g_tcpsock[idx].refs++; }
void net_tcp_sock_close(int idx) {
    if (idx < 0 || idx >= TCPSOCK_N || !g_tcpsock[idx].used) return;
    if (--g_tcpsock[idx].refs > 0) return;   /* another dup()/fork() alias still holds it (M1603) */
    tcp_close(&g_tcpsock[idx].c);
    g_tcpsock[idx].used = 0;
}

/* Fetch `filename` from the TFTP server `server_str` (dotted-quad) into `out`
 * (capacity `max`). Returns the byte length, or -1. Lock-step RRQ/DATA/ACK;
 * latches the server's transfer port (TID) from its first DATA. */
long net_tftp_get(const char *server_str, const char *filename, void *out, uint32_t max) {
    uint8_t srv[4];
    if (parse_ipv4(server_str, srv) < 0) return -1;
    uint8_t mac[6];
    if (!arp_resolve(srv, mac) && !arp_resolve(GW_IP, mac)) return -1;   /* server, else via gateway */

    const uint16_t myport = 0x8200;            /* our client TID */
    uint16_t tid = 0;                          /* server's TID, learned from its first DATA */

    uint8_t rrq[256]; int rl = 0;              /* Read Request: 01 | filename | 0 | "octet" | 0 */
    rrq[rl++] = 0; rrq[rl++] = 1;
    for (const char *p = filename; *p && rl < 220; p++) rrq[rl++] = (uint8_t)*p;
    rrq[rl++] = 0;
    for (const char *p = "octet"; *p; p++) rrq[rl++] = (uint8_t)*p;
    rrq[rl++] = 0;
    udp_send_to(mac, srv, myport, 69, rrq, rl);

    long total = 0;
    uint16_t expect = 1;                       /* next DATA block we want */
    uint8_t buf[1600];
    int idle = 0;
    for (;;) {
        int len = recv_timeout(buf, sizeof buf, 100);   /* ~1 s */
        if (len <= 0) { if (++idle > 6) return -1; if (tid == 0) udp_send_to(mac, srv, myport, 69, rrq, rl); continue; }   /* no DATA yet: re-send RRQ; mid-transfer: await the server's retransmit */
        if (get16(buf + 12) != 0x0800 || buf[14 + 9] != 17) continue;   /* IPv4/UDP */
        int ihl = (buf[14] & 0x0F) * 4; if (ihl < 20) continue;
        uint8_t *udp = buf + 14 + ihl;
        if (get16(udp + 2) != myport) continue;          /* to our client port */
        int tlen = get16(udp + 4) - 8;                   /* TFTP payload length */
        if (tlen < 4 || 14 + ihl + 8 + tlen > len) continue;
        uint8_t *tp = udp + 8;
        uint16_t op = get16(tp);
        if (op == 5) return -1;                           /* ERROR packet */
        if (op != 3) continue;                            /* only DATA */
        uint16_t sport = get16(udp + 0);
        if (tid == 0) tid = sport;                        /* latch the server's transfer port */
        else if (sport != tid) continue;                  /* stray sender */
        uint16_t blk = get16(tp + 2);
        if (blk == expect) {
            int dlen = tlen - 4;
            if ((uint32_t)(total + dlen) > max) return -1;
            for (int i = 0; i < dlen; i++) ((uint8_t *)out)[total + i] = tp[4 + i];
            total += dlen;
            uint8_t ack[4] = { 0, 4, tp[2], tp[3] };      /* ACK this block */
            udp_send_to(mac, srv, myport, tid, ack, 4);
            expect++; idle = 0;
            if (dlen < 512) return total;                 /* a short block ends the transfer */
        } else {
            uint8_t ack[4] = { 0, 4, tp[2], tp[3] };      /* re-ACK a duplicate/old block */
            udp_send_to(mac, srv, myport, tid, ack, 4);
        }
    }
}

/* ===================================================================== *
 *  SNTP client (RFC 4330) — set the wall clock from a network time server.
 *  One 48-byte UDP packet to :123; the reply's transmit timestamp (seconds
 *  since 1900) at offset 40 converts to a civil date and is written to the RTC.
 * ===================================================================== */

/* Unix seconds (UTC) -> civil date, via Howard Hinnant's days_from_civil inverse. */
static void unix_to_rtc(uint64_t u, struct rtc_time *t) {
    t->sec = (int)(u % 60); u /= 60;
    t->min = (int)(u % 60); u /= 60;
    t->hour = (int)(u % 24); u /= 24;                /* u = days since 1970-01-01 */
    long z = (long)u + 719468;                       /* shift epoch to 0000-03-01 */
    long era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);                 /* day of era [0,146096] */
    unsigned yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    long y = (long)yoe + era * 400;
    unsigned doy = doe - (365*yoe + yoe/4 - yoe/100);            /* day of year [0,365] */
    unsigned mp = (5*doy + 2)/153;                              /* month, Mar=0 */
    unsigned d  = doy - (153*mp + 2)/5 + 1;
    unsigned m  = mp < 10 ? mp + 3 : mp - 9;
    t->year = (int)(y + (m <= 2)); t->month = (int)m; t->day = (int)d;
}

/* Query pool.ntp.org and set the RTC. Returns 0 on success, -1 on failure
 * (no DNS, no route, or no reply within the timeout). */
int net_sntp(void) {
    uint8_t srv[4];
    if (dns_resolve("pool.ntp.org", srv) != 0) return -1;   /* resolve the server */
    uint8_t mac[6];
    if (!arp_resolve(GW_IP, mac)) return -1;                /* a public server routes via the gateway */

    const uint16_t myport = 0x8300;
    uint8_t pkt[48]; for (int i = 0; i < 48; i++) pkt[i] = 0;
    pkt[0] = 0x23;                                           /* LI=0, VN=4, Mode=3 (client) */
    udp_send_to(mac, srv, myport, 123, pkt, 48);

    uint8_t buf[1600];
    uint64_t deadline = timer_ticks() + 400;                /* ~4 s */
    while (timer_ticks() < deadline) {
        int len = recv_timeout(buf, sizeof buf, 50);
        if (len < 14 + 20 + 8 + 48) continue;
        if (get16(buf + 12) != 0x0800 || buf[14 + 9] != 17) continue;   /* IPv4/UDP */
        int ihl = (buf[14] & 0x0F) * 4; if (ihl < 20) continue;
        uint8_t *udp = buf + 14 + ihl;
        if (get16(udp + 2) != myport) continue;             /* to our client port */
        uint8_t *ntp = udp + 8;
        uint32_t secs = ((uint32_t)ntp[40] << 24) | ((uint32_t)ntp[41] << 16)
                      | ((uint32_t)ntp[42] << 8)  | (uint32_t)ntp[43];
        if (secs < 2208988800u) continue;                   /* before 1970 -> bogus */
        struct rtc_time t;
        unix_to_rtc((uint64_t)secs - 2208988800ull, &t);    /* NTP(1900) -> Unix(1970) */
        rtc_set(&t);
        return 0;
    }
    return -1;
}

/* ===================================================================== *
 *  Minimal TCP client + HTTP/1.0 GET.
 *
 *  Enough TCP to open a connection, send one request, and read the reply
 *  until the server closes (HTTP/1.0 + "Connection: close"). No
 *  retransmission, one connection at a time, in-order segments only — but
 *  it really does talk to real servers out on the internet through QEMU's
 *  SLIRP NAT. This is the piece that turns "we have a NIC" into "we can
 *  fetch a web page".
 * ===================================================================== */

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

static void put32(uint8_t *p, uint32_t v) { p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3]; }

/* TCP/UDP checksum: internet checksum over a pseudo-header + the segment. */
static uint16_t l4_checksum(const uint8_t *sip, const uint8_t *dip,
                            uint8_t proto, const uint8_t *seg, int len) {
    uint32_t sum = 0;
    sum += sip[0]<<8|sip[1]; sum += sip[2]<<8|sip[3];
    sum += dip[0]<<8|dip[1]; sum += dip[2]<<8|dip[3];
    sum += proto;
    sum += len;
    for (int i = 0; i + 1 < len; i += 2) sum += seg[i]<<8|seg[i+1];
    if (len & 1) sum += seg[len-1]<<8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t g_ipid = 0x100;

/* Build + send one TCP segment to dip:dport from our sport. */
static void tcp_send_seg(const uint8_t *dmac, const uint8_t *dip,
                         uint16_t sport, uint16_t dport,
                         uint32_t seq, uint32_t ack, uint8_t flags,
                         const uint8_t *data, int dlen) {
    uint8_t pkt[1600];
    const uint8_t *me = nic_mac();
    memcpy(pkt + 0, dmac, 6); memcpy(pkt + 6, me, 6); put16(pkt + 12, 0x0800);
    uint8_t *ip = pkt + 14, *tcp = pkt + 34;

    put16(tcp + 0, sport); put16(tcp + 2, dport);
    put32(tcp + 4, seq);   put32(tcp + 8, ack);
    tcp[12] = 5 << 4;                      /* data offset = 5 words, no options */
    tcp[13] = flags;
    put16(tcp + 14, 32768);                /* window */
    put16(tcp + 16, 0);                    /* checksum (fill below) */
    put16(tcp + 18, 0);                    /* urgent ptr */
    if (dlen > 0) memcpy(tcp + 20, data, dlen);
    int tcplen = 20 + dlen;
    put16(tcp + 16, l4_checksum(OUR_IP, dip, 6, tcp, tcplen));

    ip[0] = 0x45; ip[1] = 0; put16(ip + 2, 20 + tcplen);
    put16(ip + 4, g_ipid++); put16(ip + 6, 0x4000 /*DF*/); ip[8] = 64; ip[9] = 6;
    put16(ip + 10, 0); memcpy(ip + 12, OUR_IP, 4); memcpy(ip + 16, dip, 4);
    put16(ip + 10, inet_checksum(ip, 20));

    nic_send(pkt, 34 + tcplen);
}

/* Receive the next TCP segment for our connection (server dip:80 -> us:sport).
 * Returns the IP-payload TCP header pointer via *tcp_out and the data length;
 * 0 on timeout. */
/* --- parked inbound segments: cross-connection demux (M1908) ----------------
 *
 * tcp_recv_seg used to DROP every frame that did not match the polling
 * connection's 4-tuple. That silently included frames belonging to ANOTHER LIVE
 * CONNECTION, so whichever connection happened to poll first destroyed everyone
 * else's packets. Two concurrent network users therefore starved each other:
 * the boot network self-test (a background task doing a real HTTPS fetch) and
 * the in-guest httpd could not both work, which is why httpdtest failed
 * intermittently and why netcon's own test sleeps to wait the demo out. The
 * stack's comments called this "no cross-connection demux".
 *
 * Fix: a small global park ring. A TCP frame that isn't ours is stashed instead
 * of discarded, and every poll checks the ring for its own segment first. That
 * makes concurrent connections work without giving each connection its own
 * buffer (which, at OOO_N connections x 1600 bytes, would be far heavier).
 *
 * Parked frames are aged out: a connection can close with segments still parked
 * for it, and without expiry those slots would leak and eventually wedge the
 * ring. PARK_TTL is generous relative to a poll interval but short enough that a
 * dead connection's frames cannot hold a slot for long. */
/* 8 -> 64 (M2022). Eight parked frames total, evicting the oldest, is not a
 * queue -- it is a one-connection assumption. Claude Code holds two or three
 * TLS connections while the boot self-test holds another and the desktop is
 * live, and a single burst on any one of them silently evicted every frame
 * belonging to the others. 64 x 1600 B is 100 KiB and removes the assumption. */
#define PARK_N    64
#define PARK_MAX  1600
#define PARK_TTL  200            /* ticks (~2s at 100Hz) */
static struct {
    uint8_t  buf[PARK_MAX];
    int      len;                /* 0 = slot free */
    uint64_t at;                 /* tick parked, for expiry */
} g_park[PARK_N];

/* Does a parked/received frame belong to (dip, sport, dport)? Assumes the frame
 * has already been validated as IPv4/TCP with a complete header. */
static int park_matches(const uint8_t *f, int len, const uint8_t *dip,
                        uint16_t sport, uint16_t dport) {
    if (len < 34) return 0;
    if (get16(f + 12) != 0x0800 || f[14 + 9] != 6) return 0;
    if (memcmp(f + 26, dip, 4) != 0) return 0;
    int ihl = (f[14] & 0x0F) * 4;
    if (ihl < 20 || 14 + ihl + 20 > len) return 0;
    const uint8_t *t = f + 14 + ihl;
    return get16(t + 0) == dport && get16(t + 2) == sport;
}

/* Stash a frame that belongs to someone else. Drops the OLDEST parked frame when
 * full: losing a segment is recoverable (TCP retransmits), whereas refusing to
 * park would put us back to discarding the newest. */
uint64_t g_park_evicted;                  /* frames thrown away because the ring was full (M2022) */
static void park_put(const uint8_t *f, int len) {
    if (len <= 0 || len > PARK_MAX) return;
    uint64_t now = timer_ticks();
    int slot = -1;
    for (int i = 0; i < PARK_N; i++) {
        if (g_park[i].len && now - g_park[i].at > PARK_TTL) g_park[i].len = 0;  /* expire */
        if (!g_park[i].len && slot < 0) slot = i;
    }
    if (slot < 0) {                       /* full: evict the oldest -- and SAY SO.
                                           * A silent eviction here is a silently
                                           * lost TCP segment, which is the most
                                           * expensive kind of quiet. (M2022) */
        g_park_evicted++;
        uint64_t oldest = ~0ull; slot = 0;
        for (int i = 0; i < PARK_N; i++)
            if (g_park[i].at < oldest) { oldest = g_park[i].at; slot = i; }
    }
    memcpy(g_park[slot].buf, f, (size_t)len);
    g_park[slot].len = len;
    g_park[slot].at  = now;
}

/* Take a parked frame for this connection, if one is waiting. Returns its length
 * (copied into `buf`) or 0. */
static int park_take(uint8_t *buf, int max, const uint8_t *dip,
                     uint16_t sport, uint16_t dport) {
    uint64_t now = timer_ticks();
    for (int i = 0; i < PARK_N; i++) {
        if (!g_park[i].len) continue;
        if (now - g_park[i].at > PARK_TTL) { g_park[i].len = 0; continue; }
        if (!park_matches(g_park[i].buf, g_park[i].len, dip, sport, dport)) continue;
        int n = g_park[i].len; if (n > max) n = max;
        memcpy(buf, g_park[i].buf, (size_t)n);
        g_park[i].len = 0;
        return n;
    }
    return 0;
}

static int tcp_recv_seg(uint8_t *buf, int max, const uint8_t *dip,
                        uint16_t sport, uint16_t dport, uint64_t ticks,
                        uint8_t **tcp_out, int *dlen_out) {
    uint64_t deadline = timer_ticks() + ticks;
    for (;;) {
        /* Our own parked segments first: they arrived before anything we are
         * about to poll, so honouring them preserves ordering. */
        int len = park_take(buf, max, dip, sport, dport);
        if (len == 0) {
            /* ticks == 0 means "whatever is here RIGHT NOW", not "give up
             * immediately": it still makes one non-blocking pass at the NIC.
             * That is what lets poll()/epoll() answer "is this socket
             * readable?" without waiting -- an event loop asks about every
             * socket it owns on every turn, so the question has to be cheap
             * and must not block on any one of them. (M1967) */
            if (ticks == 0) {
                len = nic_receive(buf, max);
                if (len <= 0) return 0;
            } else {
                if (timer_ticks() >= deadline) return 0;
                len = nic_receive(buf, max);
            }
            if (len < 34) continue;
            /* NOT TCP IS NOT RUBBISH (M2017). This used to `continue` -- i.e.
             * destroy -- every UDP datagram and ICMP reply that happened to
             * arrive while a TCP read was polling. M1908 already established
             * that another connection's TCP frame must be parked rather than
             * dropped; the same is true of every other protocol, and a read
             * loop on a busy socket is exactly where the others land. */
            if (get16(buf + 12) != 0x0800 || buf[14 + 9] != 6) { net_rx_file_foreign(buf, len, 1); continue; }
            /* Not ours, but a valid TCP frame: PARK it rather than destroy it —
             * it may be another live connection's data (M1908). */
            if (!park_matches(buf, len, dip, sport, dport)) { park_put(buf, len); continue; }
        }
        if (memcmp(buf + 26, dip, 4) != 0) continue;                   /* from server */
        int ihl = (buf[14] & 0x0F) * 4;
        if (ihl < 20 || 14 + ihl + 20 > len) continue;     /* need a full TCP header */
        uint8_t *tcp = buf + 14 + ihl;
        if (get16(tcp + 0) != dport || get16(tcp + 2) != sport) continue;
        int thl = (tcp[12] >> 4) * 4;
        if (thl < 20 || 14 + ihl + thl > len) continue;    /* header must fit in frame */
        /* Trust only the bytes we actually received: the IP header's claimed
         * total length is server-controlled, so clamp it to `len` before using
         * it to size a memcpy (otherwise a runt/forged frame -> OOB read). */
        int iptotal = get16(buf + 16);
        if (iptotal > len - 14) iptotal = len - 14;
        int dlen = iptotal - ihl - thl;
        if (dlen < 0) dlen = 0;
        *tcp_out = tcp;
        *dlen_out = dlen;
        return 1;
    }
}

/* ---------------- reusable TCP stream (for HTTP and, later, TLS) ----------- */

static int ooo_claim(void);       /* claim a fresh reassembly+FIN slot (defined below, M1606) */
static void tcp_snd_open(int idx, uint32_t isn, uint32_t peer_wnd);  /* arm the reliable-send state on connect (M1886) */

/* Open a connection to ip:port (routed via the gateway). 0 on success, -1 on
 * failure; fills the connection state. */
int tcp_connect(tcp_conn *c, const uint8_t ip[4], uint16_t port) {
    memset(c, 0, sizeof(*c));
    c->ooo_idx = -1;               /* claimed only on success, below (M1606) -- tcp_connect has three failure
                                     * returns below, and net_tcp_sock_close() calls tcp_close() unconditionally
                                     * on a socket that failed to connect, so a claim here would leak a slot on
                                     * every failed connection attempt (bad host, refused, timed out) */
    memcpy(c->ip, ip, 4);
    if (!arp_resolve(GW_IP, c->gw)) { c->errno_hint = ENETUNREACH; return -1; }   /* can't even reach the gateway (M1564) */
    c->dport = port;
    static uint32_t conn_ctr = 0; conn_ctr++;   /* a monotonic per-connection nonce: the 100 Hz clock alone repeats across rapid reconnects (a browser's back-to-back sub-resource fetches), reusing port+ISN and risking a stale SYN-ACK/segment from the prior connection being accepted on the reused 4-tuple */
    c->sport = (uint16_t)(40000 + ((timer_ticks() + conn_ctr * 2179u) & 0x3FFF));
    c->myseq = ((uint32_t)(timer_ticks() * 2654435761u) ^ (conn_ctr * 0x9E3779B9u)) | 1;
    uint8_t buf[1600];
    for (int attempt = 0; attempt < 4; attempt++) {
        tcp_send_seg(c->gw, c->ip, c->sport, port, c->myseq, 0, TCP_SYN, 0, 0);
        uint8_t *tcp; int dlen;
        uint64_t deadline = timer_ticks() + 120;
        while (timer_ticks() < deadline) {
            if (!tcp_recv_seg(buf, sizeof(buf), c->ip, c->sport, port, 30, &tcp, &dlen)) continue;
            uint8_t fl = tcp[13];
            if (fl & TCP_RST) { c->errno_hint = ECONNREFUSED; return -1; }   /* actively refused (M1564) */
            if ((fl & TCP_SYN) && (fl & TCP_ACK) && get32(tcp + 8) == c->myseq + 1) {
                c->theirseq = get32(tcp + 4) + 1;
                c->myseq += 1;
                tcp_send_seg(c->gw, c->ip, c->sport, port, c->myseq, c->theirseq, TCP_ACK, 0, 0);
                c->up = 1;
                c->ooo_idx = ooo_claim();     /* fresh reassembly + FIN state for this conn, now that we know we need it (M1606) */
                tcp_snd_open(c->ooo_idx, c->myseq, get16(tcp + 14));  /* arm reliable send: ISN + peer's advertised window (M1886) */
                return 0;
            }
        }
    }
    c->errno_hint = ETIMEDOUT;   /* nothing ever answered the SYN (M1564) */
    return -1;
}

/* tcp_write moved below the reliable-send helpers (needs struct ooo_state), M1886. */

/* ---------------- minimal one-connection TCP SERVER (M1133) ----------------
 * The inbound counterpart of tcp_connect: LISTEN on `port`, accept one
 * connection (passive open), read the peer's request into reqbuf, send `resp`,
 * and close. The peer's MAC/IP/port are learned from its frames, so replies need
 * no ARP/gateway. No retransmission — correct on the reliable QEMU/localhost path
 * (curl via `-netdev user,hostfwd=`). Returns request bytes read (>=0), or -1 on
 * timeout/error. Lets an in-guest httpd actually serve pages. */
static int srv_rx(uint8_t *buf, int max, uint16_t port, uint16_t cport,
                  const uint8_t *cip, uint64_t deadline, uint8_t **tcp_out, int *dlen_out) {
    while (timer_ticks() < deadline) {
        int len = nic_receive(buf, max);
        if (len < 34) {
            /* Idle (no packet / a runt): SLEEP to the next interrupt instead of
             * tight-spinning. Interrupt-driven RX (M1858) wakes us the moment a
             * packet lands; the ~10ms timer tick is the fallback. This matters
             * now because netcon.c (M1870) keeps a srv_rx-based accept loop
             * running FOREVER — a busy-poll there would peg a core. Same guarded
             * hlt as recv_timeout: only with IF set, else degrade to pause. */
            uint64_t fl; __asm__ volatile("pushfq; pop %0" : "=r"(fl));
            if (fl & (1u << 9)) __asm__ volatile("hlt"); else __asm__ volatile("pause");
            continue;
        }
        if (arp_maybe_reply(buf, len)) continue;                          /* answer "who has us?" so a LAN client can connect in (M1878) */
        /* Same rule as every other drain site (M2018): a server's accept loop
         * runs FOREVER (netcon), so anything it throws away is thrown away for
         * the whole uptime of the machine. */
        if (get16(buf + 12) != 0x0800 || buf[14 + 9] != 6) { net_rx_file_foreign(buf, len, 1); continue; }
        int ihl = (buf[14] & 0x0F) * 4;
        if (ihl < 20 || 14 + ihl + 20 > len) continue;
        uint8_t *tcp = buf + 14 + ihl;
        if (get16(tcp + 2) != port) continue;                            /* our listen port */
        if (cport && get16(tcp + 0) != cport) continue;                  /* this connection's peer port */
        if (cip && memcmp(buf + 26, cip, 4) != 0) continue;              /* this connection's peer IP */
        int thl = (tcp[12] >> 4) * 4;
        if (thl < 20 || 14 + ihl + thl > len) continue;
        int iptotal = get16(buf + 16);                                   /* clamp peer-controlled length */
        if (iptotal > len - 14) iptotal = len - 14;
        int dlen = iptotal - ihl - thl; if (dlen < 0) dlen = 0;
        *tcp_out = tcp; *dlen_out = dlen;
        return len;
    }
    return 0;
}

/* Split server primitive (M1327): net_tcp_accept does the passive open + reads
 * one request, stashing the connection; net_tcp_respond sends a reply on it +
 * closes. Lets an in-guest server choose its response PER REQUEST (e.g. serve
 * the requested file). One connection at a time (the httpd serves sequentially);
 * additive -- net_tcp_serve below is unchanged. */
static struct { uint8_t cmac[6], cip[4]; uint16_t cport, lport; uint32_t our_seq, their_seq; int active; int peer_fin; } g_srvconn;

/* Announce a passive open on the SERIAL console, once per port (M1909).
 *
 * A headless test otherwise cannot distinguish "the server app never launched"
 * from "it launched but could not answer": a server is a ring-3 app and its own
 * print() goes to its window text grid, which is NOT mirrored to COM1. That
 * distinction was the unresolved crux of httpdtest's intermittent failure.
 *
 * This belongs on the ACCEPT path, not net_tcp_serve: user/httpd.c calls
 * sys_tcp_accept in a loop, so a marker in net_tcp_serve never fired for it — my
 * first attempt put it there and made the test fail 6/6 unconditionally, which
 * looked exactly like evidence that httpd wasn't launching. Once per port, because
 * accept is called in a loop. */
static void srv_announce(uint16_t port) {
    static uint16_t announced[8]; static int nann;
    for (int i = 0; i < nann; i++) if (announced[i] == port) return;
    if (nann < 8) announced[nann++] = port;
    kprintf("[net] tcp listening on port %u (server app is up)\n", (unsigned)port);
}

int net_tcp_accept(uint16_t port, uint8_t *reqbuf, int reqmax, uint64_t timeout_ticks) {
    uint8_t buf[1600], *tcp; int dlen;
    uint8_t cmac[6], cip[4]; uint16_t cport;
    uint32_t their_seq, our_seq;
    srv_announce(port);
    g_srvconn.active = 0;
    uint64_t deadline = timer_ticks() + timeout_ticks;
    for (;;) {
        if (!srv_rx(buf, sizeof buf, port, 0, 0, deadline, &tcp, &dlen)) return -1;
        if ((tcp[13] & TCP_SYN) && !(tcp[13] & TCP_ACK)) break;
    }
    memcpy(cmac, buf + 6, 6); memcpy(cip, buf + 26, 4);
    cport = get16(tcp + 0);
    their_seq = get32(tcp + 4) + 1;
    our_seq = ((uint32_t)(timer_ticks() * 2654435761u)) | 1;
    tcp_send_seg(cmac, cip, port, cport, our_seq, their_seq, TCP_SYN | TCP_ACK, 0, 0);
    our_seq += 1;
    int reqlen = 0;
    uint64_t hdl = timer_ticks() + 200;
    for (;;) {
        if (!srv_rx(buf, sizeof buf, port, cport, cip, hdl, &tcp, &dlen)) return -1;
        if (tcp[13] & TCP_RST) return -1;
        int thl = (tcp[12] >> 4) * 4;
        if (dlen > 0 && get32(tcp + 4) == their_seq) {
            int copy = dlen < reqmax ? dlen : reqmax;
            for (int i = 0; i < copy; i++) reqbuf[i] = tcp[thl + i];
            reqlen = copy;
            their_seq += dlen;
            tcp_send_seg(cmac, cip, port, cport, our_seq, their_seq, TCP_ACK, 0, 0);
            break;
        }
    }
    memcpy(g_srvconn.cmac, cmac, 6); memcpy(g_srvconn.cip, cip, 4);
    g_srvconn.cport = cport; g_srvconn.lport = port;
    g_srvconn.our_seq = our_seq; g_srvconn.their_seq = their_seq; g_srvconn.active = 1; g_srvconn.peer_fin = 0;
    return reqlen;
}

int net_tcp_respond(const uint8_t *resp, int resp_len) {
    if (!g_srvconn.active) return -1;
    uint8_t buf[1600], *tcp; int dlen;
    uint8_t *cmac = g_srvconn.cmac, *cip = g_srvconn.cip;
    uint16_t cport = g_srvconn.cport, port = g_srvconn.lport;
    uint32_t our_seq = g_srvconn.our_seq, their_seq = g_srvconn.their_seq;
    for (int off = 0; off < resp_len; ) {
        int chunk = resp_len - off; if (chunk > 1400) chunk = 1400;
        tcp_send_seg(cmac, cip, port, cport, our_seq, their_seq, TCP_PSH | TCP_ACK, resp + off, chunk);
        our_seq += chunk; off += chunk;
    }
    tcp_send_seg(cmac, cip, port, cport, our_seq, their_seq, TCP_FIN | TCP_ACK, 0, 0);
    our_seq += 1;
    uint64_t fdl = timer_ticks() + 50;
    while (srv_rx(buf, sizeof buf, port, cport, cip, fdl, &tcp, &dlen)) {
        if (tcp[13] & TCP_FIN) {
            tcp_send_seg(cmac, cip, port, cport, our_seq, get32(tcp + 4) + 1, TCP_ACK, 0, 0);
            break;
        }
    }
    g_srvconn.active = 0;
    return 0;
}

/* M1870: passive open that establishes the connection (SYN-ACK) but reads NO
 * request — for INTERACTIVE sessions (netcon) where the client may connect and
 * sit silent before typing, which net_tcp_accept's built-in 2s request-wait would
 * drop. Returns 0 on an established conn (held in g_srvconn), -1 on listen
 * timeout. Then drive it with net_tcp_accept_recv/send/close. Deliberately a
 * separate function (not a refactor of net_tcp_accept) to leave the tested
 * httpd/ws_serve accept path byte-for-byte unchanged. */
/* Is a connection waiting on `port`? (M2020)
 *
 * There is no way to answer this without touching the wire, and touching it
 * means completing the handshake -- a SYN that is looked at and not answered
 * is a SYN that gets retransmitted. So a "yes" here has already done the
 * passive open, and accept() finds the connection ready rather than doing it
 * again. An event loop can therefore poll a listening socket the same way it
 * polls everything else. */
int net_tcp_accept_ready(uint16_t port) {
    if (g_srvconn.active && g_srvconn.lport == port) return 1;
    return net_tcp_accept_open(port, 1) == 0;
}
/* Does the accepted connection have data, or has the peer finished? Both mean
 * a read will not block, which is what POLLIN promises. (M2020) */
int net_tcp_accept_readable(void) {
    if (!g_srvconn.active) return 0;
    if (g_srvconn.peer_fin) return 1;                 /* EOF is readable */
    uint8_t buf[1600], *tcp; int dlen;
    /* One non-blocking pass. srv_rx files anything that is not ours (M2017),
     * so peeking here cannot cost another connection its packets. */
    if (!srv_rx(buf, sizeof buf, g_srvconn.lport, g_srvconn.cport, g_srvconn.cip,
                timer_ticks(), &tcp, &dlen)) return 0;
    return dlen > 0 || (tcp[13] & (TCP_FIN | TCP_RST)) ? 1 : 0;
}

int net_tcp_accept_open(uint16_t port, uint64_t timeout_ticks) {
    uint8_t buf[1600], *tcp; int dlen;
    srv_announce(port);
    uint8_t cmac[6], cip[4]; uint16_t cport;
    uint32_t their_seq, our_seq;
    g_srvconn.active = 0;
    uint64_t deadline = timer_ticks() + timeout_ticks;
    for (;;) {
        if (!srv_rx(buf, sizeof buf, port, 0, 0, deadline, &tcp, &dlen)) return -1;
        if ((tcp[13] & TCP_SYN) && !(tcp[13] & TCP_ACK)) break;
    }
    memcpy(cmac, buf + 6, 6); memcpy(cip, buf + 26, 4);
    cport = get16(tcp + 0);
    their_seq = get32(tcp + 4) + 1;                      /* their SYN consumes one seq */
    our_seq = ((uint32_t)(timer_ticks() * 2654435761u)) | 1;
    tcp_send_seg(cmac, cip, port, cport, our_seq, their_seq, TCP_SYN | TCP_ACK, 0, 0);
    our_seq += 1;                                        /* our SYN consumes one */
    memcpy(g_srvconn.cmac, cmac, 6); memcpy(g_srvconn.cip, cip, 4);
    g_srvconn.cport = cport; g_srvconn.lport = port;
    g_srvconn.our_seq = our_seq; g_srvconn.their_seq = their_seq; g_srvconn.active = 1; g_srvconn.peer_fin = 0;
    return 0;
}

/* M1870: full-duplex SESSION on the connection net_tcp_accept is holding (in
 * g_srvconn) — turns the one-shot accept/respond pair into a persistent stream,
 * the way ws_serve does, but as reusable primitives. Same seq/ACK bookkeeping.
 * Used by the network debug console (netcon.c). One connection at a time, like
 * the rest of g_srvconn — don't run netcon and wsserve/on-demand-httpd at once.
 *
 * net_tcp_accept_recv: read the next inbound data on the held conn, ACKing it.
 *   Returns bytes (>0); 0 on timeout (conn still open); -1 on RST or peer-FIN
 *   (conn then closed — g_srvconn.active cleared). A FIN that carries data still
 *   delivers that data (returns >0) and closes, so `echo cmd | nc host port`
 *   (send-then-FIN) is handled as well as an interactive session. */
long net_tcp_accept_recv(uint8_t *out, int max, uint64_t timeout_ticks) {
    if (!g_srvconn.active) return -1;
    if (g_srvconn.peer_fin) return -1;   /* peer already half-closed + any trailing data delivered -> EOF */
    uint8_t buf[1600], *tcp; int dlen;
    uint64_t deadline = timer_ticks() + timeout_ticks;
    for (;;) {
        if (!srv_rx(buf, sizeof buf, g_srvconn.lport, g_srvconn.cport, g_srvconn.cip,
                    deadline, &tcp, &dlen))
            return 0;                                            /* timeout, still open */
        if (tcp[13] & TCP_RST) { g_srvconn.active = 0; return -1; }
        int thl = (tcp[12] >> 4) * 4;
        if (tcp[13] & TCP_FIN) {                                 /* peer half-close */
            int copy = 0;
            if (dlen > 0 && get32(tcp + 4) == g_srvconn.their_seq) {
                copy = dlen < max ? dlen : max;
                memcpy(out, tcp + thl, copy);
            }
            g_srvconn.their_seq += dlen + 1;                     /* FIN consumes one seq */
            tcp_send_seg(g_srvconn.cmac, g_srvconn.cip, g_srvconn.lport, g_srvconn.cport,
                         g_srvconn.our_seq, g_srvconn.their_seq, TCP_ACK, 0, 0);
            /* Half-close: the peer won't send more, but OUR side is still open, so
             * KEEP active=1 — the caller must still be able to send its reply (the
             * `echo cmd | nc` case, where data+FIN coalesce) and net_tcp_accept_close
             * must still emit our FIN. peer_fin makes the NEXT recv return EOF. (M1884) */
            g_srvconn.peer_fin = 1;
            return copy > 0 ? copy : -1;                         /* deliver trailing data, else EOF */
        }
        if (dlen <= 0 || get32(tcp + 4) != g_srvconn.their_seq) continue;  /* pure ACK / retransmit */
        int copy = dlen < max ? dlen : max;
        memcpy(out, tcp + thl, copy);
        g_srvconn.their_seq += dlen;
        tcp_send_seg(g_srvconn.cmac, g_srvconn.cip, g_srvconn.lport, g_srvconn.cport,
                     g_srvconn.our_seq, g_srvconn.their_seq, TCP_ACK, 0, 0);
        return copy;
    }
}

/* Send data on the held conn (PSH|ACK, chunked to the MSS) WITHOUT closing. */
int net_tcp_accept_send(const uint8_t *data, int len) {
    if (!g_srvconn.active) return -1;
    for (int off = 0; off < len; ) {
        int chunk = len - off; if (chunk > 1400) chunk = 1400;
        tcp_send_seg(g_srvconn.cmac, g_srvconn.cip, g_srvconn.lport, g_srvconn.cport,
                     g_srvconn.our_seq, g_srvconn.their_seq, TCP_PSH | TCP_ACK,
                     data + off, chunk);
        g_srvconn.our_seq += chunk; off += chunk;
    }
    return len;
}

/* Close the held conn (bare FIN|ACK) — the session-mode counterpart to letting
 * net_tcp_respond send-and-close. Safe to call when no conn is active. */
void net_tcp_accept_close(void) {
    if (!g_srvconn.active) return;
    tcp_send_seg(g_srvconn.cmac, g_srvconn.cip, g_srvconn.lport, g_srvconn.cport,
                 g_srvconn.our_seq, g_srvconn.their_seq, TCP_FIN | TCP_ACK, 0, 0);
    g_srvconn.our_seq += 1;
    g_srvconn.active = 0;
}

/* WebSocket SERVER (M1849): listen on `port`, accept ONE client, do the RFC 6455
 * server handshake (SHA-1 accept key), then echo each TEXT/BIN frame back
 * (unmasked) until the client sends CLOSE/FIN or ~60s elapses. `lastmsg`/`lastmax`
 * receive the last echoed payload (for a caller summary); *nframes = frames
 * echoed. Returns frames echoed (>=0), or -1 on accept/handshake failure.
 * Built on the g_srvconn segment primitive (same seq/ACK handling as
 * net_tcp_accept/respond), extended to a persistent framed exchange. Blocking. */
static int ci_find_hdr(const char *buf, const char *name, char *val, int valmax) {
    for (const char *p = buf; *p; p++) {                 /* case-insensitive header scan */
        const char *a = p, *b = name; int m = 1;
        while (*b) { char ca = *a, cb = *b; if (ca>='A'&&ca<='Z') ca+=32; if (cb>='A'&&cb<='Z') cb+=32; if (ca!=cb){m=0;break;} a++; b++; }
        if (!m) continue;
        while (*a == ' ' || *a == ':') a++;              /* skip ": " */
        int i = 0; while (*a && *a != '\r' && *a != '\n' && i < valmax-1) val[i++] = *a++;
        val[i] = 0; return i;
    }
    return 0;
}
int ws_serve(uint16_t port, char *lastmsg, int lastmax, int *nframes) {
    if (nframes) *nframes = 0;
    static uint8_t req[2048];
    int reqlen = net_tcp_accept(port, req, sizeof req - 1, 6000);   /* wait up to ~60s for a client */
    if (reqlen < 0) return -1;
    req[reqlen] = 0;

    char key[96];
    if (!ci_find_hdr((const char *)req, "sec-websocket-key:", key, sizeof key)) {
        const char *no = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nnot a WebSocket upgrade\n";
        net_tcp_respond((const uint8_t *)no, (int)strlen(no));       /* sends + FIN + clears g_srvconn */
        return -1;
    }
    char cat[160]; int cl = 0;                                       /* key + RFC 6455 magic GUID */
    for (const char *s = key; *s && cl < 120; s++) cat[cl++] = *s;
    for (const char *s = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; *s && cl < 158; s++) cat[cl++] = *s;
    uint8_t dg[20]; sha1_hash((const uint8_t *)cat, (size_t)cl, dg);
    char accept[32]; ws_base64(dg, 20, accept);

    char resp[256]; int rl = 0;
    const char *parts[] = { "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                            "Connection: Upgrade\r\nSec-WebSocket-Accept: ", accept, "\r\n\r\n" };
    for (unsigned k = 0; k < 3; k++) for (const char *s = parts[k]; *s && rl < (int)sizeof resp; s++) resp[rl++] = *s;
    tcp_send_seg(g_srvconn.cmac, g_srvconn.cip, g_srvconn.lport, g_srvconn.cport,
                 g_srvconn.our_seq, g_srvconn.their_seq, TCP_PSH | TCP_ACK, (uint8_t *)resp, rl);
    g_srvconn.our_seq += rl;

    static uint8_t rbuf[8192], of[8300], payload[8192];
    int rn = 0, frames = 0, closing = 0;
    uint8_t buf[1600], *tcp; int dlen;
    uint64_t budget = timer_ticks() + 6000;
    while (!closing && timer_ticks() < budget) {
        if (!srv_rx(buf, sizeof buf, g_srvconn.lport, g_srvconn.cport, g_srvconn.cip,
                    timer_ticks() + 100, &tcp, &dlen)) continue;      /* idle: keep waiting within budget */
        if (tcp[13] & TCP_RST) break;
        int thl = (tcp[12] >> 4) * 4;
        if (tcp[13] & TCP_FIN) { g_srvconn.their_seq += dlen + 1;      /* client half-close */
            tcp_send_seg(g_srvconn.cmac, g_srvconn.cip, g_srvconn.lport, g_srvconn.cport,
                         g_srvconn.our_seq, g_srvconn.their_seq, TCP_ACK, 0, 0);
            closing = 1; break;
        }
        if (dlen <= 0 || get32(tcp + 4) != g_srvconn.their_seq) continue;   /* pure ACK / retransmit */
        if (rn + dlen <= (int)sizeof rbuf) { memcpy(rbuf + rn, tcp + thl, dlen); rn += dlen; }
        g_srvconn.their_seq += dlen;
        tcp_send_seg(g_srvconn.cmac, g_srvconn.cip, g_srvconn.lport, g_srvconn.cport,
                     g_srvconn.our_seq, g_srvconn.their_seq, TCP_ACK, 0, 0);
        int fin, op; uint64_t pl; size_t used; int r;
        while ((r = ws_parse_frame(rbuf, (size_t)rn, &fin, &op, payload, sizeof payload - 1, &pl, &used)) == 1) {
            if (op == WS_OP_CLOSE) { closing = 1; }
            else if (op == WS_OP_TEXT || op == WS_OP_BIN) {
                long ol = ws_build_server_frame((uint8_t)op, payload, pl, of, sizeof of);
                if (ol > 0) {
                    tcp_send_seg(g_srvconn.cmac, g_srvconn.cip, g_srvconn.lport, g_srvconn.cport,
                                 g_srvconn.our_seq, g_srvconn.their_seq, TCP_PSH | TCP_ACK, of, (int)ol);
                    g_srvconn.our_seq += ol;
                }
                frames++;
                if (lastmsg && lastmax > 0) { int c = pl < (uint64_t)(lastmax - 1) ? (int)pl : lastmax - 1; memcpy(lastmsg, payload, c); lastmsg[c] = 0; }
            }
            memmove(rbuf, rbuf + used, (size_t)rn - used); rn -= (int)used;
            if (closing) break;
        }
        if (r == -1) break;
    }
    uint8_t cf[4]; long cfl = ws_build_server_frame(WS_OP_CLOSE, (const uint8_t *)"", 0, cf, sizeof cf);
    if (cfl > 0) { tcp_send_seg(g_srvconn.cmac, g_srvconn.cip, g_srvconn.lport, g_srvconn.cport,
                                g_srvconn.our_seq, g_srvconn.their_seq, TCP_PSH | TCP_ACK, cf, (int)cfl); g_srvconn.our_seq += cfl; }
    tcp_send_seg(g_srvconn.cmac, g_srvconn.cip, g_srvconn.lport, g_srvconn.cport,
                 g_srvconn.our_seq, g_srvconn.their_seq, TCP_FIN | TCP_ACK, 0, 0);
    g_srvconn.our_seq += 1;
    g_srvconn.active = 0;
    if (nframes) *nframes = frames;
    return frames;
}

int net_tcp_serve(uint16_t port, const uint8_t *resp, int resp_len,
                  uint8_t *reqbuf, int reqmax, uint64_t timeout_ticks) {
    uint8_t buf[1600], *tcp; int dlen;
    uint8_t cmac[6], cip[4]; uint16_t cport;
    uint32_t their_seq, our_seq;

    /* 1. passive open: wait for a SYN (no ACK) to our port */
    uint64_t deadline = timer_ticks() + timeout_ticks;
    for (;;) {
        if (!srv_rx(buf, sizeof buf, port, 0, 0, deadline, &tcp, &dlen)) return -1;   /* timeout */
        if ((tcp[13] & TCP_SYN) && !(tcp[13] & TCP_ACK)) break;
    }
    memcpy(cmac, buf + 6, 6); memcpy(cip, buf + 26, 4);
    cport = get16(tcp + 0);
    their_seq = get32(tcp + 4) + 1;                       /* their SYN consumes one sequence number */

    /* 2. SYN-ACK */
    our_seq = ((uint32_t)(timer_ticks() * 2654435761u)) | 1;
    tcp_send_seg(cmac, cip, port, cport, our_seq, their_seq, TCP_SYN | TCP_ACK, 0, 0);
    our_seq += 1;                                         /* our SYN consumes one */

    /* 3. read the request (the peer's first data segment; its ACK may precede it) */
    int reqlen = 0;
    uint64_t hdl = timer_ticks() + 200;                   /* ~2 s for handshake + request */
    for (;;) {
        if (!srv_rx(buf, sizeof buf, port, cport, cip, hdl, &tcp, &dlen)) return -1;
        if (tcp[13] & TCP_RST) return -1;
        int thl = (tcp[12] >> 4) * 4;
        if (dlen > 0 && get32(tcp + 4) == their_seq) {    /* in-order data = the request */
            int copy = dlen < reqmax ? dlen : reqmax;
            for (int i = 0; i < copy; i++) reqbuf[i] = tcp[thl + i];
            reqlen = copy;
            their_seq += dlen;
            tcp_send_seg(cmac, cip, port, cport, our_seq, their_seq, TCP_ACK, 0, 0);   /* ACK the request */
            break;
        }
    }

    /* 4. response */
    for (int off = 0; off < resp_len; ) {
        int chunk = resp_len - off; if (chunk > 1400) chunk = 1400;
        tcp_send_seg(cmac, cip, port, cport, our_seq, their_seq, TCP_PSH | TCP_ACK, resp + off, chunk);
        our_seq += chunk; off += chunk;
    }

    /* 5. close: FIN, then briefly mop up the peer's FIN/ACK */
    tcp_send_seg(cmac, cip, port, cport, our_seq, their_seq, TCP_FIN | TCP_ACK, 0, 0);
    our_seq += 1;
    uint64_t fdl = timer_ticks() + 50;
    while (srv_rx(buf, sizeof buf, port, cport, cip, fdl, &tcp, &dlen)) {
        if (tcp[13] & TCP_FIN) {
            tcp_send_seg(cmac, cip, port, cport, our_seq, get32(tcp + 4) + 1, TCP_ACK, 0, 0);
            break;
        }
    }
    return reqlen;
}

/* ---- out-of-order reassembly + peer-FIN tracking, per-connection --------
 * A dropped or reordered segment leaves a gap in the byte stream. The naive
 * approach (drop everything after the gap and re-ACK) forces the whole tail to
 * be retransmitted and can stall a fast CDN burst, where one segment is lost to
 * an RX-ring overflow and the next dozen arrive ahead of the retransmit. So we
 * buffer those post-gap bytes here and deliver them the instant the gap fills.
 *
 * M1606: this used to be a single global instance ("TCP here is single-
 * connection" -- true when first written, false since M1268 gave sockets a
 * 2-slot table, and more false still counting /net/tcp's own 4-slot nconn[].
 * Two genuinely live connections (two browser tabs, or a shell tcptest racing
 * a page load) shared ONE ooo_buf/fin_seen/fin_at: either one's reordered
 * segment or FIN could splice into the other's stream, and two cores each
 * running tcp_read() on a DIFFERENT connection raced the same globals with no
 * lock at all. tcp_close() even grew a comment admitting fin_seen needed to be
 * per-connection ("so a latched-but-unhonored FIN can't prematurely close the
 * NEXT connection") without actually making it per-connection — this finishes
 * that job: each live tcp_conn now gets its own slot in a small fixed table,
 * claimed by tcp_connect and released by tcp_close, the same claim/release
 * shape g_tcpsock/nconn/g_inot already use, plus the cross-core spinlock
 * those tables already learned to need (same idiom as pmm.c/swap.c/tls.c).
 *
 * `base` is the sequence number of buf[0]; `have` marks which bytes have
 * arrived; `hi` is the highest stored offset+1. */
#define OOO_CAP (96 * 1024)
/* 8 -> 24 (M2022). The comment below was written when TCPSOCK_N was 2; it is
 * 64 now, so "TCPSOCK_N(2) + NETCONN_N(4) + spare" had quietly become a
 * ceiling on how many connections could reassemble out-of-order data at once.
 * Each slot is ~140 KiB, so this is a real memory trade rather than a free
 * one -- 24 covers every concurrent user we actually have. */
#define OOO_N   24  /* was: TCPSOCK_N(2) + NETCONN_N(4) persistent, + spare for ephemeral local tcp_conns (http_get/tls) */

/* --- send-side reliability tunables (M1886) --- */
#define TCP_MSS   1400            /* our segment payload cap (matches tcp_write's historical chunking) */
#define SND_CAP   (32 * 1024)     /* per-connection unacked/unsent send buffer; also bounds in-flight */
#define RTO_MIN   30              /* retransmit timeout floor, in 100 Hz ticks (300 ms) */
#define RTO_MAX   500             /* ...and ceiling (5 s) */
#define RTO_INIT  100             /* initial RTO before any RTT sample (1 s, per RFC 6298) */
#define CWND_INIT (10 * TCP_MSS)  /* initial congestion window (IW10, RFC 6928): typical small sends still burst out at once */

struct ooo_state {
    int      used;
    uint8_t  buf[OOO_CAP];
    uint8_t  have[OOO_CAP / 8];
    uint32_t base;
    int      active;          /* 1 while buffered future bytes exist */
    int      hi;               /* highest stored offset+1 (0 = empty) */
    int      fin_seen;         /* peer FIN observed (maybe out of order) */
    uint32_t fin_at;           /* the FIN's sequence number (= data end) */
    /* --- send-side reliability (M1886): reliable, windowed, retransmitting TX.
     * sndbuf holds every byte from snd_una (oldest unacked) up to the buffered
     * end; snd_nxt (= tcp_conn.myseq) is the highest seq actually put on the wire,
     * so [snd_una,snd_nxt) is in flight and [snd_nxt,snd_una+sndbuf_len) is queued
     * but window-blocked. ACKs advance snd_una (drop from the head); the RTO timer
     * retransmits the in-flight bytes; 3 dup-ACKs fast-retransmit. */
    uint32_t snd_una;         /* oldest unacked seq; sndbuf[0] is this byte */
    uint32_t snd_nxt;         /* highest seq sent (mirrors tcp_conn.myseq) */
    int      sndbuf_len;      /* bytes buffered (sent + queued) = (snd_una+len) - snd_una */
    uint8_t  sndbuf[SND_CAP];
    uint64_t rto_at;          /* absolute tick to retransmit at (0 = timer disarmed) */
    uint32_t rto;             /* current retransmit timeout (ticks) */
    int32_t  srtt, rttvar;    /* smoothed RTT + variance (ticks); srtt < 0 => no sample yet */
    uint64_t rtt_start;       /* tick a timed segment left (Karn) */
    uint32_t rtt_seq;         /* snd_nxt when timing started; sample lands when snd_una passes it */
    int      rtt_timing;      /* 1 while an RTT sample is outstanding */
    uint32_t peer_wnd;        /* peer's most recently advertised receive window (bytes) */
    int      dupacks;         /* consecutive duplicate-ACK count (fast retransmit at 3) */
    uint32_t cwnd, ssthresh;  /* congestion window / slow-start threshold (bytes), TCP Reno (M1886) */
    int      in_fastrec;      /* 1 while in fast recovery (inflated cwnd until a new ACK) */
};
static struct ooo_state ooo_tab[OOO_N];
static volatile int ooo_lock;
static inline uint64_t ooo_irq_save(void) {
    uint64_t fl;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
    while (__atomic_exchange_n(&ooo_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return fl;
}
static inline void ooo_irq_restore(uint64_t fl) {
    __atomic_store_n(&ooo_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(fl) : "memory", "cc");
}

/* wraparound-safe 32-bit sequence comparisons */
static inline int seq_lt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }
static inline int seq_le(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }
static inline int seq_gt(uint32_t a, uint32_t b) { return (int32_t)(a - b) > 0; }
static inline int ooo_bit(struct ooo_state *o, int i) { return o->have[i >> 3] & (1 << (i & 7)); }
static inline void ooo_setbit(struct ooo_state *o, int i) { o->have[i >> 3] |= (uint8_t)(1 << (i & 7)); }

/* Claim a fresh per-connection slot (tcp_connect). -1 if the table is full --
 * that connection just runs without reassembly/out-of-order-FIN support (a
 * graceful degrade, not a crash; OOO_N is sized well past realistic concurrent
 * use, so this is not expected to ever actually trigger). */
static int ooo_claim(void) {
    uint64_t fl = ooo_irq_save();
    for (int i = 0; i < OOO_N; i++) if (!ooo_tab[i].used) {
        struct ooo_state *o = &ooo_tab[i];
        o->used = 1; o->active = 0; o->hi = 0;
        o->fin_seen = 0; o->fin_at = 0;
        /* send-side reliability state (M1886) — snd_una/snd_nxt are set to the ISN
         * by tcp_connect once the handshake fixes myseq; the rest start clean. */
        o->snd_una = o->snd_nxt = 0; o->sndbuf_len = 0;
        o->rto_at = 0; o->rto = RTO_INIT; o->srtt = -1; o->rttvar = 0;
        o->rtt_start = 0; o->rtt_seq = 0; o->rtt_timing = 0;
        o->peer_wnd = SND_CAP; o->dupacks = 0;
        ooo_irq_restore(fl);
        return i;
    }
    ooo_irq_restore(fl);
    return -1;
}
static void ooo_release(int idx) {
    if (idx < 0 || idx >= OOO_N) return;
    uint64_t fl = ooo_irq_save();
    ooo_tab[idx].used = 0;
    ooo_irq_restore(fl);
}
static struct ooo_state *ooo_lookup(int idx) {
    return (idx >= 0 && idx < OOO_N && ooo_tab[idx].used) ? &ooo_tab[idx] : 0;
}

/* Reset only the reassembly buffer. The peer FIN (fin_seen/fin_at) is NOT
 * cleared here: a FIN can be recorded while bytes are still buffered, and the
 * drain that empties the buffer calls this — clearing fin_seen there would lose
 * the FIN and the connection would never close cleanly. FIN state is per
 * connection now (M1606) and is reset when the slot is claimed in tcp_connect. */
static void ooo_reset(struct ooo_state *o) { o->active = 0; o->hi = 0; }

/* Stash a future segment [seq, seq+dlen) (seq > theirseq) for later delivery. */
static void ooo_store(struct ooo_state *o, uint32_t theirseq, uint32_t seq, const uint8_t *data, int dlen) {
    if (!o->active) {                       /* anchor a fresh window at the gap */
        o->active = 1; o->base = theirseq; o->hi = 0;
        memset(o->have, 0, sizeof(o->have));
    }
    /* off is the serial distance seq-o->base. seq_gt() upstream only proves it is
     * serially positive, so it can be as large as ~2^31 for a far-future or forged
     * segment; test it WITHOUT the addition off+dlen, which would signed-overflow
     * (no -fwrapv) and wrap negative, slipping past the bound into an OOB write.
     * dlen is bounded by the 1600-byte rx frame, so OOO_CAP-dlen is a safe int. */
    int off = (int)(seq - o->base);          /* base <= theirseq < seq => off>0  */
    if (off < 0 || dlen < 0 || dlen > OOO_CAP || off > OOO_CAP - dlen) return;  /* outside window: drop */
    memcpy(o->buf + off, data, dlen);
    for (int i = off; i < off + dlen; i++) ooo_setbit(o, i);
    if (off + dlen > o->hi) o->hi = off + dlen;
}

/* Deliver any buffered bytes now contiguous with theirseq into out[]. */
static void ooo_drain(struct ooo_state *o, tcp_conn *c, uint8_t *out, int *total, int max) {
    if (!o->active) return;
    int rel = (int)(c->theirseq - o->base);
    while (rel >= 0 && rel < o->hi && ooo_bit(o, rel) && *total < max) {
        int run = rel; while (run < o->hi && ooo_bit(o, run)) run++;
        int runlen = run - rel;
        int n = runlen; if (*total + n > max) n = max - *total;
        memcpy(out + *total, o->buf + rel, n);
        *total += n; c->theirseq += n; rel += n;
        if (n < runlen) break;               /* out filled mid-run: stop */
    }
    if (rel >= o->hi) ooo_reset(o);          /* nothing more buffered ahead */
}

/* ========================= reliable send (M1886) ===========================
 * TCP output was fire-and-forget: tcp_write blasted the data once and never
 * retransmitted, so a single dropped segment silently lost bytes — fine on the
 * loopback/QEMU path the tests use, wrong on a real lossy network (the whole
 * point of the bare-metal bring-up). This makes the sender reliable + windowed:
 * unacked bytes are buffered per-connection (in the ooo slot, so the stack-
 * allocated tcp_conn stays small), incoming ACKs free them and feed an RFC 6298
 * RTT/RTO estimator, an expired RTO or 3 duplicate ACKs retransmit the in-flight
 * window (go-back-N), and the send window honours the peer's advertised receive
 * window. It is a strict SUPERSET of the old behaviour: with no loss and a
 * typical (<=window) send, the exact same segments go out immediately, so the
 * happy-path suites (httpd/browser/ws/netcon) see identical wire traffic.
 * Deliberate follow-ons (documented, not gaps): congestion control (cwnd/slow-
 * start) and true zero-window probing — reliability + flow control is the
 * correctness core; those two are fairness/efficiency refinements. */

/* Max bytes that may be outstanding (in flight): the smaller of the congestion
 * window and the peer's advertised window, floored at one MSS (a 0-window still
 * lets one probe segment ride the RTO timer so the connection can't wedge) and
 * capped at our own send buffer. */
static uint32_t tcp_snd_wnd(struct ooo_state *o) {
    uint32_t w = o->cwnd < o->peer_wnd ? o->cwnd : o->peer_wnd;   /* min(cwnd, rwnd) */
    if (w < TCP_MSS) w = TCP_MSS;
    return w < SND_CAP ? w : SND_CAP;
}

/* Arm the reliable-send state once the handshake fixes our ISN (tcp_connect). */
static void tcp_snd_open(int idx, uint32_t isn, uint32_t peer_wnd) {
    struct ooo_state *o = ooo_lookup(idx);
    if (!o) return;
    o->snd_una = o->snd_nxt = isn;
    o->sndbuf_len = 0;
    o->rto_at = 0; o->rto = RTO_INIT;
    o->srtt = -1; o->rttvar = 0; o->rtt_timing = 0; o->dupacks = 0;
    o->peer_wnd = peer_wnd;
    o->cwnd = CWND_INIT; o->ssthresh = SND_CAP; o->in_fastrec = 0;   /* start in slow start (M1886) */
}

/* Fold one RTT sample (ticks) into srtt/rttvar and recompute rto (RFC 6298). */
static void tcp_rtt_update(struct ooo_state *o, int32_t r) {
    if (r < 0) r = 0;
    if (o->srtt < 0) { o->srtt = r; o->rttvar = r / 2; }        /* first sample */
    else {
        int32_t d = r - o->srtt; if (d < 0) d = -d;
        o->rttvar = (3 * o->rttvar + d) / 4;                    /* 1/4 gain */
        o->srtt   = (7 * o->srtt + r) / 8;                      /* 1/8 gain */
    }
    int32_t rto = o->srtt + 4 * o->rttvar;
    if (rto < RTO_MIN) rto = RTO_MIN;
    if (rto > RTO_MAX) rto = RTO_MAX;
    o->rto = (uint32_t)rto;
}

/* Transmit buffered-but-unsent bytes that fit the window, as MSS segments.
 * [snd_una,snd_nxt) is in flight; [snd_nxt, snd_una+sndbuf_len) is queued. */
static void tcp_output(tcp_conn *c, struct ooo_state *o) {
    uint32_t wnd = tcp_snd_wnd(o);
    for (;;) {
        uint32_t inflight = o->snd_nxt - o->snd_una;
        uint32_t queued   = (uint32_t)o->sndbuf_len - inflight;   /* unsent bytes */
        if (queued == 0 || inflight >= wnd) break;                /* nothing queued / window closed */
        uint32_t room = wnd - inflight;
        uint32_t n = queued; if (n > room) n = room; if (n > TCP_MSS) n = TCP_MSS;
        tcp_send_seg(c->gw, c->ip, c->sport, c->dport, o->snd_nxt, c->theirseq,
                     TCP_PSH | TCP_ACK, o->sndbuf + inflight, (int)n);
        if (!o->rtt_timing) {                                     /* start an RTT sample (Karn: fresh data only) */
            o->rtt_timing = 1; o->rtt_start = timer_ticks(); o->rtt_seq = o->snd_nxt + n;
        }
        o->snd_nxt += n; c->myseq = o->snd_nxt;
        if (!o->rto_at) o->rto_at = timer_ticks() + o->rto;       /* arm the retransmit timer */
    }
}

/* Retransmit the whole in-flight window from snd_una (go-back-N). */
static void tcp_retransmit(tcp_conn *c, struct ooo_state *o) {
    uint32_t inflight = o->snd_nxt - o->snd_una, off = 0;
    while (off < inflight) {
        uint32_t n = inflight - off; if (n > TCP_MSS) n = TCP_MSS;
        tcp_send_seg(c->gw, c->ip, c->sport, c->dport, o->snd_una + off, c->theirseq,
                     TCP_PSH | TCP_ACK, o->sndbuf + off, (int)n);
        off += n;
    }
    o->rtt_timing = 0;                          /* Karn: never sample a retransmitted segment */
    o->rto_at = timer_ticks() + o->rto;         /* restart the timer */
}

/* Process one inbound segment's ACK field + advertised window: free acked bytes,
 * update RTT/RTO, count duplicate ACKs (fast-retransmit at 3), then send whatever
 * the freshly-opened window now allows. Call for EVERY inbound segment. */
static void tcp_ack_input(tcp_conn *c, struct ooo_state *o, const uint8_t *tcp, uint8_t fl, int dlen) {
    if (!(fl & TCP_ACK)) return;
    uint32_t ackno = get32(tcp + 8);
    o->peer_wnd = get16(tcp + 14);                                /* honour the latest window (0 handled by tcp_snd_wnd) */
    uint32_t inflight = o->snd_nxt - o->snd_una;

    if (seq_gt(ackno, o->snd_una) && seq_le(ackno, o->snd_nxt)) {   /* NEW data acked */
        uint32_t acked = ackno - o->snd_una;
        /* INVARIANT (load-bearing, audited M1891): acked <= inflight <= sndbuf_len,
         * so the length below cannot underflow into a huge memmove. This is the
         * one place a remote peer's ACK field feeds a memmove length, so the chain
         * is worth stating: the guard above bounds acked by inflight; tcp_output
         * only advances snd_nxt by n <= queued (= sndbuf_len - inflight), keeping
         * inflight <= sndbuf_len; this branch decrements sndbuf_len and advances
         * snd_una by the SAME acked, preserving it; tcp_write only grows sndbuf_len;
         * and a fresh ooo slot zeroes snd_una/snd_nxt/sndbuf_len together, so the
         * guard (ackno in (0,0]) can never pass on stale state from a prior
         * connection. Keep all four of those true, or add an explicit clamp. */
        memmove(o->sndbuf, o->sndbuf + acked, (uint32_t)o->sndbuf_len - acked);   /* drop from the head */
        o->sndbuf_len -= (int)acked;
        o->snd_una = ackno;
        o->dupacks = 0;
        /* congestion window (TCP Reno): deflate out of fast recovery, else grow by
         * a segment per RTT in slow start (cwnd < ssthresh) or per cwnd in
         * congestion avoidance. */
        if (o->in_fastrec) { o->cwnd = o->ssthresh; o->in_fastrec = 0; }
        else if (o->cwnd < o->ssthresh) o->cwnd += (acked < TCP_MSS ? acked : TCP_MSS);
        else { uint32_t inc = TCP_MSS * TCP_MSS / o->cwnd; o->cwnd += inc ? inc : 1; }
        if (o->cwnd > SND_CAP) o->cwnd = SND_CAP;
        if (o->rtt_timing && seq_le(o->rtt_seq, ackno)) {          /* RTT sample landed (Karn) */
            tcp_rtt_update(o, (int32_t)(timer_ticks() - o->rtt_start));
            o->rtt_timing = 0;
        }
        o->rto_at = (o->snd_una == o->snd_nxt) ? 0 : timer_ticks() + o->rto;  /* disarm if all acked, else restart */
    } else if (inflight > 0 && ackno == o->snd_una && dlen == 0 && !(fl & (TCP_SYN | TCP_FIN))) {
        if (++o->dupacks == 3) {                                  /* 3 dup ACKs => fast retransmit + fast recovery */
            o->ssthresh = inflight / 2; if (o->ssthresh < 2 * TCP_MSS) o->ssthresh = 2 * TCP_MSS;
            o->cwnd = o->ssthresh + 3 * TCP_MSS;                  /* inflate for the 3 segments that left the network */
            o->in_fastrec = 1;
            tcp_retransmit(c, o);
        } else if (o->in_fastrec) {
            o->cwnd += TCP_MSS;                                   /* each further dup-ACK inflates the window */
            if (o->cwnd > SND_CAP) o->cwnd = SND_CAP;
        }
    }
    tcp_output(c, o);                                             /* the window may have opened */
}

/* Retransmit if the RTO timer expired with data still in flight (+ back off). A
 * timeout is the strongest congestion signal: halve ssthresh and collapse the
 * window to one segment, restarting slow start (TCP Reno). */
static void tcp_rto_check(tcp_conn *c, struct ooo_state *o) {
    if (o->rto_at && o->snd_nxt != o->snd_una && timer_ticks() >= o->rto_at) {
        uint32_t inflight = o->snd_nxt - o->snd_una;
        o->ssthresh = inflight / 2; if (o->ssthresh < 2 * TCP_MSS) o->ssthresh = 2 * TCP_MSS;
        o->cwnd = TCP_MSS; o->in_fastrec = 0;                    /* back to one segment, slow start */
        o->rto *= 2; if (o->rto > RTO_MAX) o->rto = RTO_MAX;      /* exponential backoff */
        tcp_retransmit(c, o);
    }
}

/* Send `len` bytes reliably: buffer them (retransmitted until acked), transmit
 * what the window allows now, and pump ACKs to drain the buffer if `len` exceeds
 * it. Returns len once every byte is buffered/queued, or -1 on a dead peer. The
 * no-slot path (OOO table exhausted) keeps the old fire-and-forget fallback. */
int tcp_write(tcp_conn *c, const uint8_t *data, int len) {
    if (!c->up) return -1;
    if (len <= 0) return len;
    struct ooo_state *o = ooo_lookup(c->ooo_idx);
    if (!o) {                                    /* degraded: fire-and-forget (unchanged) */
        int off = 0;
        while (off < len) {
            int chunk = len - off; if (chunk > TCP_MSS) chunk = TCP_MSS;
            tcp_send_seg(c->gw, c->ip, c->sport, c->dport, c->myseq, c->theirseq,
                         TCP_PSH | TCP_ACK, data + off, chunk);
            c->myseq += chunk; off += chunk;
        }
        return len;
    }
    int off = 0;
    uint64_t giveup = timer_ticks() + 2000;      /* ~20 s hard cap so a dead peer can't wedge the sender */
    while (off < len) {
        int room = SND_CAP - o->sndbuf_len;
        if (room > 0) {                          /* buffer as much as fits, then transmit within the window */
            int n = len - off; if (n > room) n = room;
            memcpy(o->sndbuf + o->sndbuf_len, data + off, n);
            o->sndbuf_len += n; off += n;
            tcp_output(c, o);
            if (off >= len) break;
        }
        /* buffer full with more to write: pump ACKs (+ retransmit) to drain it */
        tcp_rto_check(c, o);
        uint8_t buf[1600]; uint8_t *tcp; int dlen;
        if (tcp_recv_seg(buf, sizeof buf, c->ip, c->sport, c->dport, 20, &tcp, &dlen)) {
            uint8_t fl = tcp[13];
            if (fl & TCP_RST) { c->up = 0; return -1; }
            tcp_ack_input(c, o, tcp, fl, dlen);  /* frees buffer; carried data is dropped -> peer resends, tcp_read gets it */
        }
        if (timer_ticks() >= giveup) return -1;
    }
    return len;
}

/* Read up to `max` bytes of in-order stream data (waits up to `ticks`). Returns
 * bytes read (0 on timeout), or -1 if the connection has closed/reset. ACKs,
 * buffers out-of-order segments, and tracks the peer FIN (returns -1 once
 * everything up to and including the FIN has been delivered). */
int tcp_read(tcp_conn *c, uint8_t *out, int max, uint64_t ticks) {
    if (!c->up) return -1;
    struct ooo_state *o = ooo_lookup(c->ooo_idx);   /* this connection's own slot (M1606); NULL only if OOO_N ran out */
    uint8_t buf[1600];
    int total = 0;
    uint64_t deadline = timer_ticks() + ticks;
    if (o) ooo_drain(o, c, out, &total, max);          /* flush data buffered last call */
    if (o && o->fin_seen && seq_le(o->fin_at, c->theirseq)) {   /* honor once theirseq REACHES OR PASSES the FIN (wrap-safe; `==` hung forever on any overshoot) */ /* all data up to the FIN delivered */
        c->theirseq = o->fin_at + 1;
        tcp_send_seg(c->gw, c->ip, c->sport, c->dport, c->myseq, c->theirseq, TCP_FIN | TCP_ACK, 0, 0);
        c->up = 0; return total > 0 ? total : -1;
    }
    /* ticks == 0 is a NON-BLOCKING drain: take everything already waiting and
     * return, however little that is (including nothing). Used by poll/epoll
     * readiness and by a non-blocking read on an event loop's socket. Note the
     * inner poll below used a HARDCODED 20 ticks regardless of what the caller
     * asked for, so even a caller wanting an instant answer waited 200 ms per
     * segment -- which an event loop pays once per socket per turn. (M1967) */
    int nb = (ticks == 0);
    while ((nb || timer_ticks() < deadline) && total < max) {
        uint8_t *tcp; int dlen;
        if (o) { tcp_rto_check(c, o); tcp_output(c, o); }   /* keep retransmits + window-blocked sends moving while we poll (M1886) */
        if (!tcp_recv_seg(buf, sizeof(buf), c->ip, c->sport, c->dport, nb ? 0 : 20, &tcp, &dlen)) {
            if (nb) break;                               /* nothing more is waiting */
            if (total > 0) break;                        /* return what we have */
            continue;
        }
        uint8_t fl = tcp[13];
        uint32_t seq = get32(tcp + 4);
        if (fl & TCP_RST) { c->up = 0; return total > 0 ? total : -1; }
        int thl = (tcp[12] >> 4) * 4;
        uint8_t *data = tcp + thl;
        if (o) tcp_ack_input(c, o, tcp, fl, dlen);  /* free acked send bytes + RTT/RTO + fast-retransmit (M1886) */
        if (o && (fl & TCP_FIN)) {                  /* FIN occupies sequence seq+dlen */
            uint32_t f = seq + dlen;               /* never move fin_at BACKWARD: a stale or */
            if (!o->fin_seen || seq_gt(f, o->fin_at)) o->fin_at = f;   /* overlapping retransmitted FIN */
            o->fin_seen = 1;                        /* with a lower end must not strand the close */
        }

        if (dlen > 0 && seq_le(seq, c->theirseq) && seq_lt(c->theirseq, seq + dlen)) {
            /* segment contains the next expected byte (in-order, or an overlapping
             * retransmit) — deliver the part at/after theirseq, only what fits. */
            int skip = (int)(c->theirseq - seq);
            int n = dlen - skip; if (total + n > max) n = max - total;
            if (n > 0) { memcpy(out + total, data + skip, n); total += n; c->theirseq += n; }
            if (o) ooo_drain(o, c, out, &total, max);    /* gap may now be bridged */
            tcp_send_seg(c->gw, c->ip, c->sport, c->dport, c->myseq, c->theirseq, TCP_ACK, 0, 0);
        } else if (dlen > 0 && seq_gt(seq, c->theirseq)) {
            if (o) ooo_store(o, c->theirseq, seq, data, dlen);   /* future segment: buffer */
            tcp_send_seg(c->gw, c->ip, c->sport, c->dport, c->myseq, c->theirseq, TCP_ACK, 0, 0);
        } else {
            tcp_send_seg(c->gw, c->ip, c->sport, c->dport, c->myseq, c->theirseq, TCP_ACK, 0, 0);
        }

        /* Honour the FIN only once every byte up to it has been delivered. A FIN
         * that arrived out of order (gap still open) waits; the drain above + the
         * top-of-call check consume it as soon as theirseq reaches it. */
        if (o && o->fin_seen && seq_le(o->fin_at, c->theirseq)) {   /* honor once theirseq REACHES OR PASSES the FIN (wrap-safe; `==` hung forever on any overshoot) */
            c->theirseq = o->fin_at + 1;
            tcp_send_seg(c->gw, c->ip, c->sport, c->dport, c->myseq, c->theirseq, TCP_FIN | TCP_ACK, 0, 0);
            c->up = 0;
            return total > 0 ? total : -1;
        }
    }
    return total;
}

void tcp_close(tcp_conn *c) {
    if (c->up) {
        struct ooo_state *o = ooo_lookup(c->ooo_idx);
        if (o) {
            /* Flush unacked data before closing so a graceful close doesn't drop
             * buffered/in-flight bytes: pump ACKs + retransmit briefly. Normally a
             * no-op (a preceding tcp_read already reaped the ACKs). (M1886) */
            /* A DEADLINE IN TICKS IS NOT A BOUND IF THE CLOCK CAN STOP (M2060).
             *
             * A syscall enters through a 0xEE interrupt gate, so it runs with
             * IF=0 -- and then timer_ticks() never advances, `timer_ticks() <
             * giveup` is true forever, and this loop becomes infinite. That is
             * not hypothetical: Claude Code's HTTP client did
             * setsockopt(SO_LINGER) then close() on a live socket and the
             * close never returned:
             *
             *     t24 54(c, 1, d) = 0
             *     t24 3(c, 0, 0) = <still blocked in this call>
             *
             * The caller should enable interrupts, and the Linux close path now
             * does. But net.c is also compiled into the host test harness and
             * cannot reach for `sti` itself, and a teardown that can hang a
             * process forever if ONE caller forgets is the wrong shape. So bound
             * the work as well as the time: whichever limit is reached first
             * wins, and neither depends on a clock that may be frozen. */
            uint64_t giveup = timer_ticks() + 200;   /* ~2 s cap */
            int spins = 0;
            while (o->snd_una != o->snd_nxt && timer_ticks() < giveup && ++spins < 4000) {
                tcp_rto_check(c, o); tcp_output(c, o);
                uint8_t buf[1600]; uint8_t *tcp; int dlen;
                if (tcp_recv_seg(buf, sizeof buf, c->ip, c->sport, c->dport, 20, &tcp, &dlen)) {
                    uint8_t fl = tcp[13];
                    if (fl & TCP_RST) { c->up = 0; break; }
                    tcp_ack_input(c, o, tcp, fl, dlen);
                }
            }
        }
        if (c->up)
            tcp_send_seg(c->gw, c->ip, c->sport, c->dport, c->myseq, c->theirseq, TCP_FIN | TCP_ACK, 0, 0);
        c->up = 0;
    }
    ooo_release(c->ooo_idx); c->ooo_idx = -1;   /* release the reassembly+FIN+send slot (M1606/M1886) */
}

/* HTTP/1.0 GET http://host/path -> writes the raw response (headers+body) into
 * out (up to max bytes). Returns bytes received, or -1 on error. */
/* THE ONE COOKIE JAR (M2029). Both HTTP paths -- plaintext here and TLS in
 * tls.c -- share it, because a site that redirects http->https and sets its
 * clearance cookie on the way must have that cookie survive the scheme change.
 * Two jars would silently lose it exactly where it matters. */
static cj_jar g_jar;
/* timer_TICKS, not timer_ms. net.c is compiled into the host test harness too,
 * and only the tick clock is stubbed there -- calling timer_ms() breaks the
 * nettest/tcpreliabletest link with an "undefined reference" that names the
 * COOKIE functions and says nothing about why. Exactly the coupling M2018 hit
 * in this same file. A tick is 10 ms (timer.c's tick_ms). */
static unsigned long long cj_now_ms(void) { return (unsigned long long)timer_ticks() * 10ull; }
int cookie_header_for(const char *host, const char *path, int secure, char *out, int max) {
    return cj_header(&g_jar, host, path, secure, 1, cj_now_ms(), out, max);
}
int cookie_script_view(const char *host, const char *path, int secure, char *out, int max) {
    return cj_header(&g_jar, host, path, secure, 0, cj_now_ms(), out, max);   /* document.cookie: no HttpOnly */
}
int cookie_harvest_from(const char *host, const char *path, const char *resp, int len) {
    return cj_harvest(&g_jar, host, path, resp, len, cj_now_ms());
}
int cookie_set_one(const char *host, const char *path, const char *hdr) {
    return cj_set(&g_jar, host, path, hdr, cj_now_ms());
}
void cookie_reset(void) { cj_clear(&g_jar); }

int http_get(const char *host, const char *path, char *out, int max) {
    if (max <= 0) return 0;
    char bare[256]; uint16_t port = (uint16_t)url_host_port(host, bare, sizeof(bare), 80);   /* honor host:port (M1773); DNS gets the bare host, Host: keeps the port */
    uint8_t ip[4];
    if (dns_resolve(bare, ip) != 0) return -1;
    tcp_conn c;
    if (tcp_connect(&c, ip, port) != 0) return -1;

    char rpath[1024]; url_request_path(path, rpath, sizeof(rpath));   /* drop any #fragment from the wire request-target (M1774) */
    char req[1600]; int rl = 0;
    /* Cookies (M2029): empty unless the jar holds something for this host+path,
     * so a cookieless request is byte-identical to the pre-M2029 one. */
    static char ckbuf[1024]; ckbuf[0] = 0;
    int ckn = cookie_header_for(bare, rpath, 0, ckbuf, (int)sizeof ckbuf);
    const char *parts[] = { "GET ", rpath, " HTTP/1.0\r\nHost: ", host,
                            ckn ? "\r\nCookie: " : "", ckn ? ckbuf : "",
                            "\r\nConnection: close\r\nUser-Agent: OS-DEV/0.1\r\n\r\n" };
    for (unsigned k = 0; k < sizeof(parts)/sizeof(parts[0]); k++)
        for (const char *s = parts[k]; *s && rl < (int)sizeof(req); s++) req[rl++] = *s;
    tcp_write(&c, (uint8_t *)req, rl);

    int total = 0;
    uint64_t budget = timer_ticks() + 600;
    while (c.up && total < max && timer_ticks() < budget) {
        int n = tcp_read(&c, (uint8_t *)out + total, max - total, 60);
        if (n < 0) break;
        total += n;
    }
    if (total > 0) cookie_harvest_from(bare, rpath, out, total);   /* before the redirect is followed (M2029) */
    tcp_close(&c);
    return total;
}

/* Does buf[0..n) hold a complete first SSE event (header terminator then a blank
 * line ending the first event)? (M-eventsource — mirrors tls_sse_first_event.) */
static int http_sse_first_event(const char *buf, int n) {
    int bodyoff = -1;
    for (int i = 0; i + 1 < n; i++) {
        if (i + 3 < n && buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n') { bodyoff = i + 4; break; }
        if (buf[i]=='\n' && buf[i+1]=='\n') { bodyoff = i + 2; break; }
    }
    if (bodyoff < 0) return 0;
    for (int i = bodyoff; i + 1 < n; i++) {
        if (buf[i]=='\n' && buf[i+1]=='\n') return 1;
        if (i + 2 < n && buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r') return 1;
    }
    return 0;
}
/* HTTP SSE first-event GET (M-eventsource): like http_get, but stops + closes after
 * the first complete server-sent event so a long-lived stream doesn't stall on the
 * read budget. Returns the raw response (headers + first event) length, <0 on error. */
int http_get_sse(const char *host, const char *path, char *out, int max) {
    if (max <= 0) return 0;
    char bare[256]; uint16_t port = (uint16_t)url_host_port(host, bare, sizeof(bare), 80);   /* honor host:port (M1773) */
    uint8_t ip[4];
    if (dns_resolve(bare, ip) != 0) return -1;
    tcp_conn c;
    if (tcp_connect(&c, ip, port) != 0) return -1;
    char rpath[1024]; url_request_path(path, rpath, sizeof(rpath));   /* drop any #fragment from the wire request-target (M1774) */
    char req[512]; int rl = 0;
    const char *parts[] = { "GET ", rpath, " HTTP/1.0\r\nHost: ", host,
                            "\r\nConnection: close\r\nUser-Agent: OS-DEV/0.1\r\n\r\n" };
    for (unsigned k = 0; k < sizeof(parts)/sizeof(parts[0]); k++)
        for (const char *s = parts[k]; *s && rl < (int)sizeof(req); s++) req[rl++] = *s;
    tcp_write(&c, (uint8_t *)req, rl);
    int total = 0;
    uint64_t budget = timer_ticks() + 600;
    while (c.up && total < max && timer_ticks() < budget) {
        int n = tcp_read(&c, (uint8_t *)out + total, max - total, 60);
        if (n < 0) break;
        total += n;
        if (http_sse_first_event(out, total)) break;   /* got the first event -> stop + close */
    }
    tcp_close(&c);
    return total;
}

/* ===================================================================== *
 *  WebSocket client transport (M1846, +wss:// M1847). Glues the socket to
 *  the RFC 6455 frame codec (wsframe.h) + handshake helpers (wsclient.h).
 *  The browser-JS WebSocket object (js.c) drives it through two backings:
 *    ws_open     — connect + Upgrade handshake, hold the socket open.
 *    ws_exchange — mask+send the queued messages, read the reply frames.
 *  One session at a time (the JS pump is single-threaded). ws:// runs over
 *  a raw tcp_conn; wss:// runs the same frames as TLS application data over
 *  a persistent tls session (tls_ws_*), dispatched by g_ws_secure.
 * ===================================================================== */
static tcp_conn g_wsc;                 /* the in-flight PLAINTEXT ws:// connection */
static int      g_ws_up;               /* a WS session (ws:// or wss://) is open */
static int      g_ws_secure;           /* the open session is wss:// (TLS) */
static uint8_t  g_ws_carry[512];       /* bytes read past the handshake terminator */
static int      g_ws_carry_n;

/* Non-crypto masking key (RFC 6455 requires client frames be masked, but the key
 * only needs to vary — it is an anti-cache-poisoning measure, not a secret). */
static void ws_mask_key(uint8_t k[4]) {
    static uint32_t s;
    if (!s) s = (uint32_t)timer_ticks() ^ 0x9e3779b9u;
    for (int i = 0; i < 4; i++) { s ^= s << 13; s ^= s >> 17; s ^= s << 5; k[i] = (uint8_t)(s >> (i * 8)); }
}

/* Transport dispatch: plaintext tcp vs TLS application data (tls_ws_*).
 * wsio_read returns bytes, 0 = plaintext idle-timeout (retryable), <0 = closed
 * (or, for TLS, idle-timeout/close/alert — read_enc doesn't distinguish). */
static int  wsio_write(const uint8_t *b, int n) { return g_ws_secure ? tls_ws_write(b, n) : tcp_write(&g_wsc, b, n); }
static int  wsio_read(uint8_t *b, int n)        { return g_ws_secure ? tls_ws_read(b, n)  : tcp_read(&g_wsc, b, n, 60); }
static void wsio_teardown(void)                 { if (g_ws_secure) tls_ws_close(); else tcp_close(&g_wsc); }

/* Open a ws:// or wss:// connection and perform the RFC 6455 opening handshake.
 * Returns a (trivial) connection id >=0 on a 101 upgrade, or -1; *status gets the
 * HTTP status (or 0 if the connection/TLS setup itself failed). */
int ws_open(const char *url, int *status) {
    *status = 0;
    if (g_ws_up) { wsio_teardown(); g_ws_up = 0; }       /* drop any stale session */
    g_ws_carry_n = 0;

    const char *u = url; g_ws_secure = 0;                /* strip + classify the scheme */
    if (u[0]=='w'&&u[1]=='s'&&u[2]=='s'&&u[3]==':'&&u[4]=='/'&&u[5]=='/') { u += 6; g_ws_secure = 1; }
    else if (u[0]=='w'&&u[1]=='s'&&u[2]==':'&&u[3]=='/'&&u[4]=='/') u += 5;
    else return -1;

    char authority[256]; int ai = 0;                     /* host[:port] up to the path */
    while (*u && *u != '/' && ai < (int)sizeof(authority)-1) authority[ai++] = *u++;
    authority[ai] = 0;
    const char *path = (*u == '/') ? u : "/";

    if (g_ws_secure) {                                   /* wss://: TLS handshake (DNS/connect/:443 inside) */
        if (tls_ws_open(authority, (uint32_t)timer_ticks()) != 0) return -1;
    } else {                                             /* ws://: raw TCP */
        char bare[256]; uint16_t port = (uint16_t)url_host_port(authority, bare, sizeof(bare), 80);
        uint8_t ip[4];
        if (parse_ipv4(bare, ip) != 0 && dns_resolve(bare, ip) != 0) return -1;   /* IP literal, else DNS */
        if (tcp_connect(&g_wsc, ip, port) != 0) return -1;
    }

    uint8_t nonce[16]; for (int i = 0; i < 16; i++) nonce[i] = (uint8_t)((timer_ticks() >> (i & 7)) ^ (i * 37 + 1));
    char key[25]; ws_base64(nonce, 16, key);
    char req[640];
    long rl = ws_build_handshake(authority, path, key, req, sizeof(req));
    if (rl <= 0 || wsio_write((uint8_t *)req, (int)rl) < 0) { wsio_teardown(); return -1; }

    char resp[2048]; int total = 0, hdr_end = -1;        /* read until the blank-line header terminator */
    uint64_t budget = timer_ticks() + 300;
    while (total < (int)sizeof(resp)-1 && timer_ticks() < budget) {
        int n = wsio_read((uint8_t *)resp + total, sizeof(resp)-1 - total);
        if (n < 0) break;                                /* closed / (TLS) idle-timeout */
        if (n == 0) continue;                            /* plaintext idle: keep waiting within budget */
        total += n;
        for (int i = 3; i < total; i++)                  /* find "\r\n\r\n" */
            if (resp[i-3]=='\r'&&resp[i-2]=='\n'&&resp[i-1]=='\r'&&resp[i]=='\n') { hdr_end = i + 1; break; }
        if (hdr_end >= 0) break;
    }
    int code = ws_handshake_status(resp, (size_t)total);
    *status = code;
    if (code != 101 || hdr_end < 0) { wsio_teardown(); return -1; }

    int leftover = total - hdr_end;                      /* stash any early frame bytes for ws_exchange */
    if (leftover > 0 && leftover <= (int)sizeof(g_ws_carry)) {
        memcpy(g_ws_carry, resp + hdr_end, leftover);
        g_ws_carry_n = leftover;
    }
    g_ws_up = 1;
    return 1;
}

/* On the open connection: send each message in `sendbuf` as a masked frame, then
 * read reply frames back into `out` (*nrecv = count). Closes the connection.
 *
 * Both directions use a length-prefixed record framing — each record is
 *   [opcode:1][len:4 little-endian][payload:len]
 * where opcode is WS_OP_TEXT (0x1) or WS_OP_BIN (0x2). This replaces the old
 * NUL-separation, which couldn't carry binary payloads (they contain NULs) and
 * discarded the received TEXT/BIN type; the record header carries the type each
 * way so binary WebSocket frames round-trip (M1859). `sendtot` is a raw byte
 * count. Returns the number of bytes written to `out` (>=0), or -1 on error. */
int ws_exchange(int id, const char *sendbuf, int sendtot, char *out, int outmax, int *nrecv) {
    (void)id; *nrecv = 0;
    if (!g_ws_up) return -1;
    int RC = 131072;
    uint8_t *raw = kmalloc(RC), *tx = kmalloc(RC + 16);
    if (!raw || !tx) { if(raw)kfree(raw); if(tx)kfree(tx); wsio_teardown(); g_ws_up=0; return -1; }

    const uint8_t *p = (const uint8_t *)sendbuf, *pend = p + sendtot;   /* send the queued records */
    while (p + 5 <= pend) {                               /* each record: [op:1][len:4 LE][payload] */
        uint8_t recop = p[0];
        uint32_t L = (uint32_t)p[1] | ((uint32_t)p[2] << 8) | ((uint32_t)p[3] << 16) | ((uint32_t)p[4] << 24);
        p += 5;
        if ((uint64_t)(pend - p) < L) break;              /* truncated record */
        if (L <= (uint32_t)RC) {
            uint8_t mk[4]; ws_mask_key(mk);
            uint8_t wsop = (recop == WS_OP_BIN) ? WS_OP_BIN : WS_OP_TEXT;
            long fl = ws_build_client_frame(wsop, p, (uint64_t)L, mk, tx, RC + 16);
            if (fl > 0) wsio_write(tx, (int)fl);
        }
        p += L;
    }

    int rn = 0, ooff = 0;                                /* reply read + parse loop */
    if (g_ws_carry_n > 0 && g_ws_carry_n <= RC) { memcpy(raw, g_ws_carry, g_ws_carry_n); rn = g_ws_carry_n; g_ws_carry_n = 0; }
    uint64_t budget = timer_ticks() + 400;
    int closing = 0;
    while (!closing && timer_ticks() < budget) {
        int fin, op; uint64_t pl; size_t used;
        int r = 0;
        /* drain every complete frame currently buffered in raw[0..rn), writing each
         * TEXT/BIN frame as a [op][len:4 LE][payload] record. Parse the payload 5
         * bytes past ooff, then backfill the header (need >=5 bytes of headroom). */
        while (ooff + 5 < outmax &&
               (r = ws_parse_frame(raw, (size_t)rn, &fin, &op,
                                   (uint8_t *)out + ooff + 5, (size_t)(outmax - ooff - 5), &pl, &used)) == 1) {
            if (op == WS_OP_CLOSE) { closing = 1; }
            else if (op == WS_OP_TEXT || op == WS_OP_BIN) {
                out[ooff]     = (char)op;                 /* record header: opcode ... */
                out[ooff + 1] = (char)((uint32_t)pl & 0xff);
                out[ooff + 2] = (char)(((uint32_t)pl >> 8) & 0xff);
                out[ooff + 3] = (char)(((uint32_t)pl >> 16) & 0xff);
                out[ooff + 4] = (char)(((uint32_t)pl >> 24) & 0xff);   /* ... + LE32 length */
                ooff += 5 + (int)pl;
                (*nrecv)++;
            }
            /* PING/PONG/continuation: skip (payload already unmasked, just drop) */
            memmove(raw, raw + used, (size_t)rn - used); /* consume the frame */
            rn -= (int)used;
            if (closing || ooff + 5 >= outmax) { closing = 1; break; }
        }
        if (r == -1) { closing = 1; break; }             /* malformed / oversized -> bail */
        if (closing) break;
        if (rn >= RC) { closing = 1; break; }            /* a frame bigger than our buffer */
        int n = wsio_read(raw + rn, RC - rn);
        if (n < 0) break;                                /* peer closed / (TLS) idle-timeout */
        if (n == 0) { if (*nrecv > 0) break; else continue; }  /* plaintext idle: stop once we have replies */
        rn += n;
    }

    if (!g_ws_secure && g_wsc.up) {                      /* plaintext: send a polite CLOSE frame first */
        uint8_t mk[4]; ws_mask_key(mk);
        long cf = ws_build_client_frame(WS_OP_CLOSE, (const uint8_t *)"", 0, mk, tx, RC + 16);
        if (cf > 0) tcp_write(&g_wsc, tx, (int)cf);
    }
    wsio_teardown(); g_ws_up = 0;                        /* wss:// teardown sends TLS close_notify */
    kfree(raw); kfree(tx);
    return ooff;
}

/* ===================================================================== *
 *  /net/tcp — Plan 9 style "sockets as files" (M1110). No fd table: the
 *  VFS routes /net/tcp/<...> here. Read /net/tcp/clone -> a connection slot
 *  index; write "connect host!port" to /net/tcp/<n>/ctl; then read/write
 *  /net/tcp/<n>/data. Wraps the existing tcp_connect/tcp_write/tcp_read.
 * ===================================================================== */
#define NETCONN_N 4
static struct { int used, connected; tcp_conn c; } nconn[NETCONN_N];

static int nfs_streq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }
/* parse a leading "<digits>/" off *sub, returning the index and advancing *sub past it; -1 if malformed */
static int nfs_idx(const char **sub) {
    const char *s = *sub; int n = 0, any = 0;
    while (*s >= '0' && *s <= '9') { n = n * 10 + (*s - '0'); s++; any = 1; }
    if (!any || *s != '/') return -1;
    *sub = s + 1;
    return n;
}

long netfs_read(const char *sub, void *buf, unsigned long max) {
    if (nfs_streq(sub, "clone")) {                       /* allocate a connection slot */
        for (int i = 0; i < NETCONN_N; i++) if (!nconn[i].used) {
            nconn[i].used = 1; nconn[i].connected = 0;
            char *b = (char *)buf; int p = 0;
            if (i >= 10 && p < (int)max) b[p++] = (char)('0' + i / 10);
            if (p < (int)max) b[p++] = (char)('0' + i % 10);
            if (p < (int)max) b[p++] = '\n';
            return p;
        }
        return -1;                                       /* all slots in use */
    }
    int idx = nfs_idx(&sub);
    if (idx < 0 || idx >= NETCONN_N || !nconn[idx].used) return -1;
    if (nfs_streq(sub, "data")) {
        if (!nconn[idx].connected) return -1;
        __asm__ volatile("sti");                         /* TCP read needs the timer for its timeout */
        int n = tcp_read(&nconn[idx].c, buf, (int)max, 200);   /* up to ~2 s for data */
        return n < 0 ? 0 : n;                            /* closed -> EOF (0) */
    }
    return -1;
}

long netfs_write(const char *sub, const void *buf, unsigned long len) {
    int idx = nfs_idx(&sub);
    if (idx < 0 || idx >= NETCONN_N || !nconn[idx].used) return -1;

    if (nfs_streq(sub, "ctl")) {
        char cmd[128]; unsigned long n = len < 127 ? len : 127;
        for (unsigned long i = 0; i < n; i++) cmd[i] = ((const char *)buf)[i];
        cmd[n] = 0;
        while (n && (cmd[n-1] == '\n' || cmd[n-1] == '\r' || cmd[n-1] == ' ')) cmd[--n] = 0;
        if (cmd[0]=='c'&&cmd[1]=='l'&&cmd[2]=='o') {     /* "close" */
            if (nconn[idx].connected) { __asm__ volatile("sti"); tcp_close(&nconn[idx].c); }
            nconn[idx].used = 0; nconn[idx].connected = 0;
            return (long)len;
        }
        if (cmd[0]=='c'&&cmd[1]=='o'&&cmd[2]=='n') {     /* "connect host!port" */
            char *h = cmd; while (*h && *h != ' ') h++; while (*h == ' ') h++;   /* skip "connect " */
            char *bang = h; while (*bang && *bang != '!' && *bang != ':') bang++;   /* host!port or host:port */
            if (*bang != '!' && *bang != ':') return -1;
            *bang = 0;
            uint16_t port = 0; for (char *p = bang + 1; *p >= '0' && *p <= '9'; p++) port = (uint16_t)(port * 10 + (*p - '0'));
            if (!port) return -1;
            uint8_t ip[4];
            if (parse_ipv4(h, ip) != 0) {                /* a hostname -> resolve it */
                __asm__ volatile("sti");
                if (dns_resolve(h, ip) != 0) return -1;
            }
            __asm__ volatile("sti");                     /* the handshake needs the timer */
            if (tcp_connect(&nconn[idx].c, ip, port) != 0) return -1;
            nconn[idx].connected = 1;
            return (long)len;
        }
        return -1;
    }
    if (nfs_streq(sub, "data")) {
        if (!nconn[idx].connected) return -1;
        __asm__ volatile("sti");
        int w = tcp_write(&nconn[idx].c, (const uint8_t *)buf, (int)len);
        return w < 0 ? -1 : w;
    }
    return -1;
}

/* HTTP POST over plain TCP (M702). Sends the headers (with Content-Type + Content-Length)
 * then the body as a second write — so an arbitrary body size isn't bounded by the small
 * request buffer. Returns the raw response length (headers+body), or -1 on failure. */
int http_post(const char *host, const char *path, const char *ctype,
              const char *body, int bodylen, char *out, int max) {
    if (max <= 0) return 0;
    if (bodylen < 0) bodylen = 0;
    uint8_t ip[4];
    if (dns_resolve(host, ip) != 0) return -1;
    tcp_conn c;
    if (tcp_connect(&c, ip, 80) != 0) return -1;

    char clen[12]; { unsigned b = (unsigned)bodylen; int t = 0; char tmp[12];
        do { tmp[t++] = (char)('0' + b % 10); b /= 10; } while (b && t < 11);
        int ci = 0; while (t) clen[ci++] = tmp[--t]; clen[ci] = 0; }
    char req[640]; int rl = 0;
    const char *parts[] = { "POST ", path, " HTTP/1.0\r\nHost: ", host,
                            "\r\nContent-Type: ", ctype ? ctype : "text/plain",
                            "\r\nContent-Length: ", clen,
                            "\r\nConnection: close\r\nUser-Agent: OS-DEV/0.1\r\n\r\n" };
    for (unsigned k = 0; k < sizeof(parts)/sizeof(parts[0]); k++)
        for (const char *s = parts[k]; *s && rl < (int)sizeof(req); s++) req[rl++] = *s;
    tcp_write(&c, (uint8_t *)req, rl);
    if (bodylen > 0) tcp_write(&c, (uint8_t *)body, bodylen);

    int total = 0;
    uint64_t budget = timer_ticks() + 600;
    while (c.up && total < max && timer_ticks() < budget) {
        int n = tcp_read(&c, (uint8_t *)out + total, max - total, 60);
        if (n < 0) break;
        total += n;
    }
    tcp_close(&c);
    return total;
}

/* THE RX DEMUX, PROVEN (M2018).
 *
 * The defect this guards against was invisible for a long time because nothing
 * ever looked: there is one NIC and several independent consumers, and each of
 * them drained it directly and DESTROYED whatever it did not recognise. A DNS
 * lookup ate ICMP replies; an ARP resolve ate another socket's TCP segments.
 * It surfaced as `ping` reporting 1 reply out of 3 with all three on the wire.
 *
 * Reproduce it exactly rather than testing a proxy for it:
 *
 *   1. send an ICMP echo request
 *   2. have a DIFFERENT consumer hold the NIC while the reply arrives --
 *      net_udp_recv on a port nobody sends to does precisely that, and is what
 *      a concurrent DNS lookup is doing
 *   3. then wait for the echo reply
 *
 * Before the fix, step 2 discards the reply and step 3 times out. After it, the
 * reply is filed where its owner will find it. No timing luck is needed: the
 * UDP drain is given 300 ms and the reply takes about 5, so it is CERTAIN to be
 * the consumer that sees it. */
static void net_selftest_cookies(void);   /* M2029 */
static void net_selftest_rx_demux(const uint8_t *gw_mac) {
    uint8_t buf[1600], dummy[64], sip[4];
    uint16_t sport;

    while (recv_timeout(buf, sizeof buf, 0) > 0) { }      /* start from a clean queue */

    ping_send(GW_IP, gw_mac, 0xBEEF);
    (void)net_udp_recv(60999, dummy, sizeof dummy, sip, &sport, 300);   /* the other consumer */

    int got = 0;
    uint64_t deadline = timer_ticks() + 100;
    while (timer_ticks() < deadline) {
        int len = recv_timeout(buf, sizeof buf, 20);
        if (len >= 42 && get16(buf + 12) == 0x0800 && buf[14 + 9] == 1 &&
            buf[34] == 0 && memcmp(buf + 26, GW_IP, 4) == 0) { got = 1; break; }
    }
    kprintf("[%s] net: an ICMP reply SURVIVES another consumer draining the NIC\n",
            got ? " ok " : "FAIL");
}

/* Cookies survive a request/response round trip (M2029). Asserted at boot
 * against the jar the real HTTP paths use, so it fails here rather than as a
 * login that silently never sticks. */
static void net_selftest_cookies(void) {
    cookie_reset();
    const char *resp =
        "HTTP/1.1 302 Found\r\n"
        "Set-Cookie: clearance=abc123; Path=/\r\n"
        "Set-Cookie: hidden=zz; Path=/; HttpOnly\r\n"
        "Location: /\r\n\r\n";
    int n = 0; while (resp[n]) n++;
    int got = cookie_harvest_from("example.com", "/", resp, n);
    char buf[256];
    int hl = cookie_header_for("example.com", "/", 0, buf, sizeof buf);
    int sl = cookie_script_view("example.com", "/", 0, buf, sizeof buf);
    kprintf("[%s] net: cookies survive a response and come back on the next request (%d set, hdr=%d, script=%d)\n",
            (got == 2 && hl > 0 && sl > 0 && sl < hl) ? " ok " : "FAIL", got, hl, sl);
    cookie_reset();
}

void net_demo(void) {
    if (nic_init() != 0) {
        kprintf("[net] no supported NIC found (tried e1000, rtl8139).\n\n");
        goto done;
    }

    kprintf("[net] %s up. our MAC = ", nic_name());
    print_mac(nic_mac());
    /* ASK FOR AN ADDRESS, AND PRINT THE ONE WE HAVE (M2120).
     *
     * Two things were wrong here and they hid each other.
     *
     * net_dhcp() was called from kernel/netcon.c and from one syscall, and
     * from NOWHERE ELSE -- so an ordinary boot never requested a lease and the
     * address stayed at the SLIRP default, 10.0.2.15. That is exactly right
     * under QEMU's user-mode networking and useless anywhere else: on a
     * bridged VM or real hardware the machine holds an address from a network
     * it is not on, cannot ARP its gateway, and has no DNS. Claude Code said
     * so from inside the guest -- "Can't reach the API server (EAI_AGAIN)" --
     * on a VM whose bridge was working perfectly.
     *
     * And this line PRINTED THE ADDRESS AS A LITERAL STRING. So the log read
     * "IP = 10.0.2.15" whatever the address actually was, which is why the
     * first defect could sit here: a successful lease and no lease at all
     * produced identical output. Print the real bytes. */
    if (net_dhcp() == 0) {
        const uint8_t *ip = net_ip();
        kprintf(", IP = %u.%u.%u.%u (DHCP)\n", ip[0], ip[1], ip[2], ip[3]);
    } else {
        const uint8_t *ip = net_ip();
        kprintf(", IP = %u.%u.%u.%u (NO DHCP LEASE -- this is the SLIRP default, "
                "which only works under QEMU user-mode networking)\n",
                ip[0], ip[1], ip[2], ip[3]);
    }

    uint8_t gw_mac[6];
    if (!arp_resolve(GW_IP, gw_mac)) {
        const uint8_t *g = GW_IP;
        kprintf("[net] ARP for %u.%u.%u.%u timed out.\n\n", g[0], g[1], g[2], g[3]);
        goto done;
    }
    kprintf("[net] ARP: 10.0.2.2 is at ");
    print_mac(gw_mac);
    kprintf("\n");

    net_selftest_rx_demux(gw_mac);

    net_selftest_cookies();
    int got = 0;
    for (uint16_t seq = 1; seq <= 3; seq++) {
        if (ping(GW_IP, gw_mac, seq)) {
            kprintf("[net] ping 10.0.2.2: reply seq=%u\n", seq);
            got++;
        } else {
            kprintf("[net] ping 10.0.2.2: seq=%u timed out\n", seq);
        }
    }
    kprintf("[net] %d/3 echo replies. Networking works!\n", got);

    /* Prove the TCP/HTTP stack: fetch a real page over the internet. */
    static char page[2048];
    int n = http_get("example.com", "/", page, sizeof(page) - 1);
    if (n > 0) {
        page[n] = 0;
        int eol = 0; while (eol < n && page[eol] != '\r' && page[eol] != '\n') eol++;
        page[eol] = 0;
        kprintf("[net] HTTP GET example.com -> %d bytes, status: %s\n\n", n, page);
    } else {
        kprintf("[net] HTTP GET example.com failed (no internet route?)\n\n");
    }

    /* Prove the from-scratch TLS 1.3 stack end to end: a real HTTPS GET exercises
     * the handshake (X25519 key share), the AEAD record layer (AES-GCM/ChaCha20),
     * X.509 chain parsing + path validation to a trusted root, hostname matching,
     * and the CertificateVerify signature check (ECDSA/RSA over our own bignum).
     * Non-fatal: an offline host or a blocked :443 just reports failure. */
    static uint8_t tpage[4096];
    int tn = tls_get("example.com", "/", tpage, sizeof(tpage) - 1, (uint32_t)timer_ticks());
    if (tn > 0) {
        tpage[tn] = 0;
        int eol = 0; while (eol < tn && tpage[eol] != '\r' && tpage[eol] != '\n') eol++;
        tpage[eol] = 0;
        kprintf("[tls] HTTPS GET example.com -> %d bytes, status: %s\n", tn, (char *)tpage);
        kprintf("[tls] cert CN=%s expires %s | chain=%s host=%s certverify=%s\n\n",
                tls_leaf_cn(), tls_leaf_expiry(),
                tls_chain_anchored()      ? "trusted-root" : "UNVERIFIED",
                tls_host_match() == 1 ? "match" : tls_host_match() == 0 ? "MISMATCH" : "n/a",
                tls_cert_status() == 0  ? "ok"   : "FAIL");
    } else {
        kprintf("[tls] HTTPS GET example.com failed (no internet route, blocked :443, or handshake error)\n\n");
    }

    /* ONE unambiguous terminal marker on EVERY path (M1911).
     *
     * M1909 added a headless check that a HANG in this self-test can no longer
     * hide behind "the host is just offline". It keyed on the HTTP/TLS outcome
     * lines -- but this function has EARLY RETURNS above (no NIC, ARP timeout)
     * that never reach those lines at all, so a clean early exit was reported as
     * a hang. That is a false positive in the detector, found by starving this
     * task until ARP timed out. Printing here, on every path, makes the two
     * cases distinguishable for good: this line present = the self-test RAN TO
     * COMPLETION whatever the outcome; absent = it genuinely never returned. */
done:
    kprintf("[net] boot network self-test finished\n");
}

/* --- /proc/net (M1080): the network state nothing else exposed -------------
 * Interface (IP/MAC/gateway/DNS) plus the live ARP and DNS caches with their
 * freshness — the kernel-side counterpart to Linux's /proc/net/{arp,…}. Pure
 * read-only formatting over state already kept here; procfs.c routes it. */
static int np_str(char *b, int p, int max, const char *s) { while (*s && p < max - 1) b[p++] = *s++; return p; }
static int np_dec(char *b, int p, int max, uint64_t v) {
    char t[20]; int n = 0; if (!v) t[n++] = '0';
    while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
    while (n && p < max - 1) b[p++] = t[--n]; return p;
}
static int np_ip(char *b, int p, int max, const uint8_t *ip) {
    for (int i = 0; i < 4; i++) { if (i && p < max - 1) b[p++] = '.'; p = np_dec(b, p, max, ip[i]); }
    return p;
}
static int np_mac(char *b, int p, int max, const uint8_t *m) {
    const char *hex = "0123456789abcdef";
    for (int i = 0; i < 6; i++) {
        if (i && p < max - 1) b[p++] = ':';
        if (p < max - 1) b[p++] = hex[m[i] >> 4];
        if (p < max - 1) b[p++] = hex[m[i] & 15];
    }
    return p;
}

int net_proc(char *b, int max) {
    if (!b || max < 2) return 0;
    uint64_t now = timer_ticks();
    int p = 0;
    p = np_str(b, p, max, "iface    ip ");   p = np_ip(b, p, max, net_ip());
    p = np_str(b, p, max, "  mac ");          p = np_mac(b, p, max, net_mac());
    p = np_str(b, p, max, "\ngateway  ");     p = np_ip(b, p, max, net_gateway());
    p = np_str(b, p, max, "    dns ");        p = np_ip(b, p, max, net_dns());
    p = np_str(b, p, max, "\nroute    default via ");  p = np_ip(b, p, max, net_gateway());
    p = np_str(b, p, max, "\n\nARP cache (IP -> MAC):\n");
    int any = 0;
    for (int i = 0; i < ARP_CACHE_N; i++) if (arp_cache[i].used) {
        p = np_str(b, p, max, "  ");  p = np_ip(b, p, max, arp_cache[i].ip);
        p = np_str(b, p, max, "  ");  p = np_mac(b, p, max, arp_cache[i].mac);
        p = np_str(b, p, max, now < arp_cache[i].exp ? "  fresh\n" : "  stale\n");
        any = 1;
    }
    if (!any) p = np_str(b, p, max, "  (empty)\n");
    p = np_str(b, p, max, "\nDNS cache (host -> IP):\n");
    any = 0;
    for (int i = 0; i < DNS_CACHE_N; i++) if (dns_cache[i].used) {
        p = np_str(b, p, max, "  ");   p = np_str(b, p, max, dns_cache[i].host);
        p = np_str(b, p, max, " -> "); p = np_ip(b, p, max, dns_cache[i].ip);
        p = np_str(b, p, max, now < dns_cache[i].exp ? "  fresh\n" : "  stale\n");
        any = 1;
    }
    if (!any) p = np_str(b, p, max, "  (empty)\n");
    if (p < max) b[p] = 0;
    return p;
}
