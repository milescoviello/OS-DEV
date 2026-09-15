/* tls.h — minimal TLS 1.3 HTTPS client (see tls.c). */
#pragma once
#include <stdint.h>

/* HTTPS GET https://host/path over TLS 1.3 -> raw HTTP response into `out`
 * (up to `max` bytes). `seed` seeds the ephemeral-key RNG. Returns bytes
 * received, or -1 on error. */
int tls_get(const char *host, const char *path, uint8_t *out, int max, uint32_t seed);
/* HTTPS GET that stops + closes after the first Server-Sent-Events event (so a long-
 * lived stream doesn't block). Raw response (headers + first event) into out. (M-eventsource) */
int tls_get_sse(const char *host, const char *path, uint8_t *out, int max, uint32_t seed);
/* HTTPS POST: sends `body` (bodylen) with Content-Type `ctype`; raw response into out. -1 on error. (M702) */
int tls_post(const char *host, const char *path, const char *ctype, const char *body, int bodylen, uint8_t *out, int max, uint32_t seed);

/* wss:// persistent TLS session for the WebSocket transport (M1847): open does the
 * full handshake + leaves the connection live; write/read carry frame bytes as TLS
 * application data; close sends close_notify + tears down. One session at a time. */
int  tls_ws_open(const char *host, uint32_t seed);   /* 0 = session open, -1 = fail */
int  tls_ws_write(const uint8_t *data, int len);     /* len / -1 */
int  tls_ws_read(uint8_t *out, int max);             /* app-data bytes / -1 (idle-timeout, close, or alert) */
void tls_ws_close(void);

/* CertificateVerify result of the most recent tls_get: -2 = none/absent,
 * 0 = signature verified (server proved leaf-key possession), -1 = failed.
 * (Chain-to-root path validation is done separately -- see tls_chain_anchored.) */
const char *tls_fail_reason(void);   /* which stage the last failed fetch reached (M2026) */
int tls_cert_status(void);

/* 1 if the most recent tls_get's certificate chain anchored to a trusted root CA
 * (full path validated); 0 otherwise. */
int tls_chain_anchored(void);

/* leaf-certificate hostname match of the most recent tls_get: -2 = n/a, 1 = the cert's
 * SAN/CN matches the requested host, 0 = mismatch (the connection was rejected). */
int tls_host_match(void);

/* leaf-certificate identity of the most recent tls_get (for a cert-info display):
 * the subject commonName and the notAfter (expiry) string; "" if none. */
const char *tls_leaf_cn(void);
const char *tls_leaf_expiry(void);
