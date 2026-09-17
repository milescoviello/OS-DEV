/* net.h — minimal network stack demo (ARP + ICMP). */
#pragma once

/* Bring up the NIC, ARP-resolve the gateway, and ping it. Prints results.
 * No-op message if there's no NIC. */
void net_demo(void);
void net_rx_service(void);   /* kernel thread: answers ARP for this host whether or not anything is polling, and files what arrives (M2127) */
unsigned long long net_arp_answered(void);  /* ARP requests for us answered since boot (M2127) */

#include <stdint.h>
/* Ping the gateway 3 times; returns the number of echo replies (-1 = no ARP). */
int net_ping_gateway(void);
/* DNS-resolve a host and ICMP-echo it 3 times via the gateway; reply count or -1. */
int net_ping_host(const char *host);
/* Resolve a hostname to an IPv4 address via DNS. 0 on success, -1 otherwise. */
int dns_resolve(const char *host, uint8_t out_ip[4]);
int parse_ipv4(const char *s, uint8_t out[4]);   /* dotted-quad literal -> 4 bytes; 0/-1 (exposed M1847) */
/* HTTP/1.0 GET http://host/path -> raw response into out (max bytes).
 * Returns bytes received, or -1 on error. */
int http_get(const char *host, const char *path, char *out, int max);
/* HTTP/1.0 GET that stops + closes after the first Server-Sent-Events event (so a
 * long-lived stream doesn't block). Raw response (headers + first event) into out. (M-eventsource) */
int http_get_sse(const char *host, const char *path, char *out, int max);

/* WebSocket client transport (M1846): the browser-JS WebSocket object's two
 * backings. ws_open connects + does the RFC 6455 Upgrade handshake (returns a
 * conn id / -1, *status = HTTP code); ws_exchange sends the NUL-separated queue
 * then reads the reply frames NUL-separated into `out` (*nrecv = count). */
int ws_open(const char *url, int *status);
int ws_exchange(int id, const char *sendbuf, int sendtot, char *out, int outmax, int *nrecv);
/* WebSocket SERVER (M1849): accept one client on `port`, handshake, echo its
 * frames back until it closes; *nframes = frames echoed, lastmsg = last payload.
 * Returns frames echoed / -1. Blocking. */
int ws_serve(uint16_t port, char *lastmsg, int lastmax, int *nframes);
/* HTTP/1.0 POST: sends `body` (bodylen) with Content-Type `ctype`; raw response into out. -1 on error. (M702) */
int http_post(const char *host, const char *path, const char *ctype, const char *body, int bodylen, char *out, int max);

/* A minimal TCP stream connection. Multiple may be genuinely concurrent (two
 * sockets, /net/tcp's own slots, HTTP/TLS's own locals) since M1268 -- despite
 * this struct's own name suggesting otherwise, nothing here assumes "one at a
 * time" itself; that assumption lived in net.c's reassembly state until M1606
 * gave each connection its own slot (see ooo_idx below). */
typedef struct {
    uint8_t  ip[4], gw[6];
    uint16_t sport, dport;
    uint32_t myseq, theirseq;
    int      up;                 /* 1 while the connection is open */
    int      errno_hint;         /* SO_ERROR (M1564): 0, or WHY tcp_connect failed
                                   * (ECONNREFUSED/ETIMEDOUT/ENETUNREACH) -- tcp_connect
                                   * itself still just returns 0/-1, unchanged for every
                                   * existing caller; this is purely additive detail. */
    int      ooo_idx;            /* this connection's slot in net.c's private out-of-order
                                   * reassembly + peer-FIN table; assigned by tcp_connect,
                                   * released by tcp_close, -1 if none assigned (M1606) */
} tcp_conn;

int  tcp_connect(tcp_conn *c, const uint8_t ip[4], uint16_t port);  /* 0 / -1 */
int  tcp_write(tcp_conn *c, const uint8_t *data, int len);          /* len / -1 */
int  tcp_read(tcp_conn *c, uint8_t *out, int max, uint64_t ticks);  /* bytes, 0=timeout, -1=closed */
void tcp_close(tcp_conn *c);
/* Passive open: LISTEN on `port`, accept one connection, read the request into
 * reqbuf, send `resp`, close. Request bytes read (>=0), or -1. In-guest httpd. M1133. */
int  net_tcp_serve(uint16_t port, const uint8_t *resp, int resp_len,
                   uint8_t *reqbuf, int reqmax, uint64_t timeout_ticks);
int  net_tcp_accept(uint16_t port, uint8_t *reqbuf, int reqmax, uint64_t timeout_ticks);  /* M1327: passive-open + read one request, hold the conn */
int  net_tcp_respond(const uint8_t *resp, int resp_len);                                  /* M1327: reply on the accepted conn + close */
/* M1870: persistent full-duplex session on the accepted conn (for netcon.c).
 * accept_open: SYN-ACK only, no request read (interactive); 0/-1.
 * recv: bytes/0-timeout/-1-closed (delivers FIN-carried data); send: no close. */
int  net_tcp_accept_open(uint16_t port, uint64_t timeout_ticks);
long net_tcp_accept_recv(uint8_t *out, int max, uint64_t timeout_ticks);
int  net_tcp_accept_send(const uint8_t *data, int len);
void net_tcp_accept_close(void);
int  net_tcp_accept_ready(uint16_t port);   /* would accept() succeed? completes the handshake if so (M2020) */
int  net_tcp_accept_readable(void);         /* has the accepted connection data (or EOF)? (M2020) */

const uint8_t *net_ip(void);
int net_have_lease(void);
const uint8_t *net_gw(void);
const uint8_t *net_mask(void);   /* 1 only if a DHCP server actually answered: a leased address and a compiled-in default are otherwise indistinguishable (M2120) */        /* our IPv4 address (4 bytes) */
const uint8_t *net_gateway(void);   /* the gateway IPv4 address (4 bytes) */
const uint8_t *net_mac(void);       /* our 6-byte hardware (MAC) address */
const uint8_t *net_dns(void);       /* the DNS resolver IPv4 address (4 bytes) */
int net_proc(char *buf, int max);   /* /proc/net: interface + ARP/DNS caches as text; bytes written */
int net_dhcp(void);                 /* DHCP DORA handshake: lease IP/gateway/DNS from the server; 0/-1 */
long net_tftp_get(const char *server, const char *filename, void *out, uint32_t max);  /* TFTP read; bytes/-1 */
int  net_sntp(void);                /* SNTP: set the RTC from pool.ntp.org; 0/-1 */
/* Userspace UDP sockets (M1258): connectionless datagram send/recv for ring 3. */
int  net_udp_send(const uint8_t dstip[4], uint16_t dport, uint16_t sport, const void *payload, int plen);   /* 0/-1 */
int  net_udp_recv(uint16_t sport, void *buf, int max, uint8_t srcip[4], uint16_t *srcport, int timeout_ms);  /* bytes/-1 */
long net_udp_nread(uint16_t sport);                         /* FIONREAD: length of the next datagram, 0 if none (M2086) */
/* Raw packet sockets (M1259): whole-Ethernet-frame send/recv for ring 3. */
int  net_raw_send(const void *frame, int len);              /* send a complete L2 frame; 0/-1 */
int  net_raw_recv(void *buf, int max, int timeout_ms);      /* next L2 frame; length/-1 */
/* TCP client sockets (M1268): persistent TCBs behind AF_INET SOCK_STREAM fds. */
/* A non-blocking recv with nothing buffered. Distinct from 0 (EOF) and from -1
 * (the socket is broken) -- an event loop reads until it sees exactly this and
 * treats either of the others as "this connection is finished". (M1967) */
#define NET_SOCK_EAGAIN (-11)
int  net_tcp_sock_open(void);                               /* alloc a TCB slot; idx/-1 */
int  net_tcp_sock_readable(int idx);                        /* poll: would recv return now? (M1967) */
long net_tcp_sock_nread(int idx);                           /* FIONREAD: bytes in the receive ring; -1 bad idx (M2086) */
int  net_tcp_sock_bufbytes(void);                           /* SO_RCVBUF/SO_SNDBUF: the real ring size (M2088) */
int  net_tcp_sock_writable(int idx);                        /* poll: is it connected? (M1967) */
int  net_tcp_sock_set_nonblock(int idx, int on);            /* O_NONBLOCK -> EAGAIN instead of waiting (M1967) */
int  net_udp_readable(uint16_t sport);                      /* poll: is a datagram queued for this port? (M1967) */
int  net_tcp_sock_connect(int idx, const uint8_t ip[4], uint16_t port);  /* 0/-1 */
long net_tcp_sock_send(int idx, const void *buf, int len);  /* bytes/-1 */
long net_tcp_sock_recv(int idx, void *buf, int max);        /* bytes / NET_SOCK_EAGAIN not-yet / 0 EOF / -1 bad fd (M2026) */
void net_tcp_sock_ref(int idx);                             /* a dup()/fork() alias of an existing fd (M1603) */
void net_tcp_sock_close(int idx);                           /* drop a reference; closes the TCB at 0 (M1603) */
int  net_tcp_sock_setopt(int idx, int level, int optname, int val);   /* 0/-1 (M1554) */
int  net_tcp_sock_getopt(int idx, int level, int optname, int *val);  /* 0/-1 (M1554) */
int  net_tcp_sock_getname(int idx, uint8_t out[6]);   /* our {ip[4],port} for this socket; 0/-1 (M1560) */
int  net_tcp_sock_getpeer(int idx, uint8_t out[6]);   /* the connected peer's {ip[4],port}; 0/-1, ENOTCONN-equivalent if not connected (M1560) */
/* /net/tcp sockets-as-files (M1110): `sub` is the path after "/net/tcp/" —
 * "clone", "<n>/ctl", or "<n>/data". Routed from vfs.c. */
long netfs_read(const char *sub, void *buf, unsigned long max);
long netfs_write(const char *sub, const void *buf, unsigned long len);

/* HTTP cookies (M2029) -- one jar, shared by the plaintext and TLS paths. */
int  cookie_header_for(const char *host, const char *path, int secure, char *out, int max);
int  cookie_script_view(const char *host, const char *path, int secure, char *out, int max);
int  cookie_harvest_from(const char *host, const char *path, const char *resp, int len);
int  cookie_set_one(const char *host, const char *path, const char *hdr);
void cookie_reset(void);
