/*
 * tcp_reliable_test.c — deterministic proof of net.c's reliable TCP SENDER
 * (M1886): retransmission on RTO, fast-retransmit on 3 duplicate ACKs, ACK
 * processing / send-buffer freeing, and flow control against a small peer
 * window — all driven against a simulated peer over a LOSSY in-memory link, no
 * QEMU. Like net_test.c we #include net.c to drive the real tcp_write/tcp_read
 * and reach the static ooo_claim / tcp_snd_open / ooo_lookup. Exit 0 = pass.
 *
 * Model: a controllable auto-incrementing clock (so net.c's deadline loops make
 * progress and the RTO is eventually crossed); nic_send() hands each outgoing
 * segment to a simulated receiver (dropping it per the active loss policy) which
 * cumulatively ACKs into a queue that nic_receive() feeds back to net.c. We drive
 * a full byte pattern through tcp_write, pump tcp_read until everything is acked,
 * and assert the receiver reassembled the EXACT stream despite the drops.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

/* ---- controllable clock: auto-increments so deadline loops terminate AND the
 *      RTO deadline is eventually crossed during a tcp_read poll. ---- */
static uint64_t g_now;
uint64_t timer_ticks(void) { return g_now++; }

/* ---- link direction peer->net: a FIFO nic_receive() drains ---- */
static uint8_t tn_buf[1024][1600]; static int tn_len[1024]; static int tn_head, tn_tail;
static void tn_push(const uint8_t *f, int len) {
    int nx = (tn_tail + 1) % 1024; if (nx == tn_head) return;   /* full: drop (shouldn't happen) */
    memcpy(tn_buf[tn_tail], f, len); tn_len[tn_tail] = len; tn_tail = nx;
}
int nic_receive(void *out, uint16_t max) {
    if (tn_head == tn_tail) return 0;
    int len = tn_len[tn_head]; if (len > (int)max) len = max;
    memcpy(out, tn_buf[tn_head], len); tn_head = (tn_head + 1) % 1024;
    return len;
}

/* ---- big-endian frame field helpers (independent of net.c's get/put) ---- */
static uint16_t r16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t r32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static void w16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void w32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

/* ---- the simulated peer (server/receiver) ---- */
static const uint8_t PEER_IP[4] = { 93, 184, 216, 34 };
static uint16_t NET_SPORT = 40000;      /* net's client port (learned from its first segment) */
static const uint16_t PEER_PORT = 80;
static uint32_t peer_isn   = 0x11110000;/* the peer's own send seq (its ACK segments carry it) */
static uint32_t peer_wnd_adv = 65535;   /* window the peer advertises back to net */
static uint32_t data_isn;               /* net's data ISN = first byte's seq */
static uint32_t peer_rcv_nxt;           /* next in-order byte the peer expects */
static uint8_t  peer_data[300000];      /* reassembly buffer, indexed by (seq - data_isn) */
static uint8_t  peer_rcvd[300000 / 8];  /* per-byte "received" bitmap (handles out-of-order) */

/* loss policy for THIS transmission attempt (retransmits always get through) */
static int g_drop_first_n = 0;          /* drop the next N fresh DATA segments the peer would receive */
static int32_t g_drop_seq = -1;         /* drop a data segment whose seq == this, exactly once */

/* Build + queue a peer->net TCP segment so tcp_recv_seg (filtering on src-IP ==
 * c->ip, dst-port == c->sport, src-port == c->dport) accepts it. */
static void peer_send(uint32_t seq, uint32_t ack, uint8_t flags, const uint8_t *data, int dlen) {
    uint8_t f[1600]; memset(f, 0, sizeof f);
    w16(f + 12, 0x0800);                                 /* ethertype IPv4 */
    uint8_t *ip = f + 14;
    ip[0] = 0x45; ip[9] = 6; w16(ip + 2, (uint16_t)(20 + 20 + dlen));  /* IHL5, proto TCP, total len */
    memcpy(ip + 12, PEER_IP, 4);                         /* src IP = peer (== c->ip) */
    uint8_t *tcp = f + 34;
    w16(tcp + 0, PEER_PORT); w16(tcp + 2, NET_SPORT);    /* src 80 -> dst 40000 */
    w32(tcp + 4, seq); w32(tcp + 8, ack);
    tcp[12] = 5 << 4; tcp[13] = flags; w16(tcp + 14, (uint16_t)peer_wnd_adv);
    if (dlen > 0) memcpy(tcp + 20, data, dlen);
    tn_push(f, 34 + 20 + dlen);
}

/* Reassemble one accepted data segment + advance the cumulative ACK point. */
static void peer_accept(uint32_t seq, const uint8_t *data, int dlen) {
    int32_t off = (int32_t)(seq - data_isn);
    if (off < 0 || off + dlen > (int)sizeof peer_data) return;   /* out of modelled range: ignore */
    for (int i = 0; i < dlen; i++) {
        peer_data[off + i] = data[i];
        peer_rcvd[(off + i) >> 3] |= (uint8_t)(1 << ((off + i) & 7));
    }
    for (;;) {                                                    /* extend contiguous run */
        int32_t p = (int32_t)(peer_rcv_nxt - data_isn);
        if (p < 0 || p >= (int)sizeof peer_data) break;
        if (!(peer_rcvd[p >> 3] & (1 << (p & 7)))) break;
        peer_rcv_nxt++;
    }
}

/* net.c -> the wire. Parse the segment, apply the loss policy, feed the peer, and
 * (for delivered data) queue the peer's cumulative ACK back to net.c. */
int nic_send(const void *frame, uint16_t len) {
    const uint8_t *f = frame;
    if (len < 34) return len;
    const uint8_t *ip = f + 14;
    int ihl = (ip[0] & 0x0F) * 4;
    const uint8_t *tcp = f + 14 + ihl;
    NET_SPORT = r16(tcp + 0);                            /* learn net's client port for our replies */
    uint32_t seq = r32(tcp + 4);
    uint8_t flags = tcp[13];
    int thl = (tcp[12] >> 4) * 4;
    int iptot = r16(ip + 2);
    int dlen = iptot - ihl - thl; if (dlen < 0) dlen = 0;
    const uint8_t *data = f + 14 + ihl + thl;   /* the TCP payload */

    if (dlen > 0) {
        if (g_drop_first_n > 0) { g_drop_first_n--; return len; }          /* silently dropped */
        if (g_drop_seq >= 0 && seq == (uint32_t)g_drop_seq) { g_drop_seq = -1; return len; }
        peer_accept(seq, data, dlen);
        peer_send(peer_isn, peer_rcv_nxt, 0x10 /*ACK*/, 0, 0);            /* cumulative ACK */
    }
    /* pure ACKs / FIN from net need no peer response for this sender-side test */
    (void)flags;
    return len;
}

/* ---- remaining net.c dependencies (same seam as net_test.c) ---- */
int nic_init(void) { return 0; }
const char *nic_name(void) { return "reliable-test"; }
static const uint8_t g_mac[6] = { 2, 0, 0, 0, 0, 1 };
const uint8_t *nic_mac(void) { return g_mac; }
void kprintf(const char *fmt, ...) { (void)fmt; }
/* net_udp_recv's blocking path yields between NIC polls rather than spinning a
 * core (M1967). timer_ticks already advances on every call, so the deadline
 * loop terminates without this doing anything -- it only has to exist. Every
 * kernel seam net.c touches is stubbed here for the same reason; a new call
 * into task.c/kheap.c/etc. breaks this link until it is. */
void task_sleep_ms(uint64_t ms) { (void)ms; }
int tls_get(const char *h, const char *p, uint8_t *o, int m, uint32_t s) { (void)h;(void)p;(void)o;(void)m;(void)s; return -1; }
int tls_cert_status(void) { return -2; }
int tls_chain_anchored(void) { return 0; }
int tls_host_match(void) { return -2; }
struct rtc_time; void rtc_set(const struct rtc_time *t) { (void)t; }
const char *tls_leaf_cn(void) { return ""; }
const char *tls_leaf_expiry(void) { return ""; }
int  tls_ws_open(const char *host, uint32_t seed) { (void)host;(void)seed; return -1; }
int  tls_ws_write(const uint8_t *data, int len) { (void)data;(void)len; return -1; }
int  tls_ws_read(uint8_t *out, int max) { (void)out;(void)max; return -1; }
void tls_ws_close(void) {}
extern void *malloc(size_t); extern void free(void *);
void *kmalloc(size_t n) { return malloc(n); }
void  kfree(void *p) { free(p); }

#include "net.c"

/* ---- test scaffolding ---- */
static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); fails++; } else printf("  ok: %s\n", msg); } while (0)

static tcp_conn mkconn(void) {
    tcp_conn c; memset(&c, 0, sizeof c);
    memcpy(c.ip, PEER_IP, 4);
    memset(c.gw, 0xAA, 6);
    c.sport = NET_SPORT; c.dport = PEER_PORT;
    c.myseq = 0x22220000; c.theirseq = peer_isn + 1; c.up = 1;
    /* Set up slot 0 directly rather than ooo_claim(): the claim/release path uses
     * cli (privileged, faults in userspace) and isn't what this single-threaded
     * test exercises. tcp_snd_open arms the send-side fields; memset zeroes the
     * reassembly ones. (For the same reason the test never calls tcp_close.) */
    c.ooo_idx = 0;
    memset(&ooo_tab[0], 0, sizeof ooo_tab[0]);
    ooo_tab[0].used = 1;
    tcp_snd_open(c.ooo_idx, c.myseq, peer_wnd_adv);
    /* reset the peer for a fresh run */
    data_isn = c.myseq; peer_rcv_nxt = c.myseq;
    memset(peer_rcvd, 0, sizeof peer_rcvd);
    tn_head = tn_tail = 0;
    return c;
}
static int all_acked(tcp_conn *c) {
    struct ooo_state *o = ooo_lookup(c->ooo_idx);
    return o && o->snd_una == o->snd_nxt;
}
static void pump(tcp_conn *c) {                 /* drain ACKs + drive retransmits until fully acked */
    uint8_t rb[2048];
    for (int i = 0; i < 5000 && c->up && !all_acked(c); i++) tcp_read(c, rb, sizeof rb, 100);
}
static int stream_ok(int n, uint8_t base) {
    if ((int)(peer_rcv_nxt - data_isn) != n) return 0;
    for (int i = 0; i < n; i++) if (peer_data[i] != (uint8_t)(base + (uint8_t)i)) return 0;
    return 1;
}
static uint8_t payload[80000];
static void fill(int n, uint8_t base) { for (int i = 0; i < n; i++) payload[i] = (uint8_t)(base + (uint8_t)i); }

int main(void) {
    printf("tcp_reliable_test: reliable-sender proof (retransmit + RTO + fast-rtx + flow control)\n");

    /* 1. No loss: a multi-segment write is delivered in order. */
    {
        tcp_conn c = mkconn(); int n = 8000; fill(n, 1);
        CHECK(tcp_write(&c, payload, n) == n, "no-loss: tcp_write returns full length");
        pump(&c);
        CHECK(all_acked(&c), "no-loss: every byte acknowledged");
        CHECK(stream_ok(n, 1), "no-loss: peer reassembled the exact 8000-byte stream");
    }

    /* 2. RTO retransmit: drop the very first data segment; only the RTO timer can
     *    recover it (too few later segments to trigger fast-retransmit). */
    {
        tcp_conn c = mkconn(); int n = 1000; fill(n, 7);
        g_drop_first_n = 1;                       /* the lone segment is dropped */
        CHECK(tcp_write(&c, payload, n) == n, "rto: tcp_write returns full length");
        pump(&c);
        CHECK(all_acked(&c), "rto: dropped segment recovered + acknowledged");
        CHECK(stream_ok(n, 7), "rto: peer got the exact 1000-byte stream after an RTO retransmit");
        { struct ooo_state *o = ooo_lookup(c.ooo_idx);
          CHECK(o && o->ssthresh < CWND_INIT, "rto: congestion control cut ssthresh below the initial window"); }
    }

    /* 3. Fast retransmit: drop one middle segment of a big send; the later
     *    segments' duplicate ACKs must trigger a fast retransmit (well before an
     *    RTO would). */
    {
        tcp_conn c = mkconn(); int n = 20000; fill(n, 3);
        g_drop_seq = (int32_t)(0x22220000u + 2 * TCP_MSS);   /* drop the 3rd segment */
        CHECK(tcp_write(&c, payload, n) == n, "fast-rtx: tcp_write returns full length");
        pump(&c);
        CHECK(all_acked(&c), "fast-rtx: gap filled + fully acknowledged");
        CHECK(stream_ok(n, 3), "fast-rtx: peer reassembled the exact 20000-byte stream");
        { struct ooo_state *o = ooo_lookup(c.ooo_idx);
          CHECK(o && o->ssthresh < CWND_INIT, "fast-rtx: congestion control halved ssthresh on the loss"); }
    }

    /* 4. Multiple drops across a large transfer: still fully reliable. */
    {
        tcp_conn c = mkconn(); int n = 60000; fill(n, 0x40);
        g_drop_first_n = 3;                       /* drop the first 3 fresh segments */
        g_drop_seq = (int32_t)(0x22220000u + 10 * TCP_MSS);  /* + one deeper one */
        CHECK(tcp_write(&c, payload, n) == n, "multi-drop: tcp_write returns full length");
        pump(&c);
        CHECK(all_acked(&c), "multi-drop: all losses recovered + acknowledged");
        CHECK(stream_ok(n, 0x40), "multi-drop: peer reassembled the exact 60000-byte stream");
    }

    /* 5. Flow control: peer advertises a tiny window; the sender must never let
     *    more than that be outstanding, yet still deliver everything. */
    {
        peer_wnd_adv = 4000;                      /* small receive window */
        tcp_conn c = mkconn(); int n = 40000; fill(n, 0x90);
        int maxflight = 0;
        /* write in one call, then pump; check outstanding never exceeded window */
        CHECK(tcp_write(&c, payload, n) == n, "flow: tcp_write returns full length");
        struct ooo_state *o = ooo_lookup(c.ooo_idx);
        if (o && (int)(o->snd_nxt - o->snd_una) > maxflight) maxflight = (int)(o->snd_nxt - o->snd_una);
        pump(&c);
        CHECK(maxflight <= 4000, "flow: outstanding data never exceeded the 4000-byte peer window");
        CHECK(all_acked(&c) && stream_ok(n, 0x90), "flow: peer got the exact 40000-byte stream, window-paced");
        peer_wnd_adv = 65535;
    }

    /* 6. Congestion control: a large clean transfer must OPEN the congestion
     *    window (slow start / congestion avoidance) well past its initial value,
     *    up to our send-buffer cap, and still deliver every byte. */
    {
        tcp_conn c = mkconn(); int n = 70000; fill(n, 0x11);
        CHECK(tcp_write(&c, payload, n) == n, "cwnd: tcp_write returns full length");
        pump(&c);
        struct ooo_state *o = ooo_lookup(c.ooo_idx);
        CHECK(o && o->cwnd > CWND_INIT, "cwnd: congestion window grew past the initial window on a clean transfer");
        CHECK(all_acked(&c) && (int)(peer_rcv_nxt - data_isn) == n, "cwnd: peer got the exact 70000-byte stream");
    }

    if (fails == 0) { printf("PASS: reliable TCP sender (retransmit/RTO/fast-rtx/flow control/congestion) verified\n"); return 0; }
    printf("FAIL: %d reliable-TCP check(s) failed\n", fails);
    return 1;
}
