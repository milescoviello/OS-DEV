/*
 * tls.c — a minimal TLS 1.3 client (RFC 8446), enough to fetch HTTPS. Runs over
 * the reusable tcp_conn stream and the from-scratch crypto toolkit (X25519,
 * AES-128-GCM, ChaCha20-Poly1305, SHA-256, HKDF). One cipher suite negotiated
 * from {TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256}, X25519 key
 * exchange. The handshake transcript is buffered and re-hashed on demand (the
 * transcript is small), so no streaming SHA is needed.
 *
 * Server authentication: the server Finished is verified (proving it holds the
 * handshake secret derived from the ECDH). The certificate chain is also
 * validated with the from-scratch X.509 + RSA/ECDSA verifiers — CertificateVerify
 * (the leaf key signs the transcript), each issuer link, and anchoring to a
 * baked-in trusted root. This is currently INFORMATIONAL, not ENFORCING: the
 * result is logged and surfaced to the UI (TLS* anchored / TLS+ leaf-key-only /
 * TLS? failed), but a failure is non-fatal — enforcing would need a full (~150)
 * trusted-root set baked in, not a handful (see docs/438). So the hooks are all
 * present; flipping to enforce is a root-set + fatal-gate change.
 *
 * Host-tested against `openssl s_server -tls1_3`.
 */
#include "tls.h"
#include "net.h"
#include "url.h"      /* url_host_port() — honor an explicit :port on an https authority (M1773) */
#include "x25519.h"
#include "sha256.h"
#include "hkdf.h"
#include "aesgcm.h"
#include "chachapoly.h"
#include "x509.h"
#include "ecdsa.h"
#include "rsa.h"
#include "rtc.h"
#include "sha512.h"
#include "rootca.h"
#include "string.h"
#include "console.h"
#include "smp.h"      /* smp_parallel_for — verify independent chain links across cores (M1528, kernel build only) */

#define REC_HS   22
#define REC_APP  23
#define REC_CCS  20
#define REC_ALERT 21

#define HS_CLIENT_HELLO 1
#define HS_SERVER_HELLO 2
#define HS_ENC_EXT      8
#define HS_CERT         11
#define HS_CERT_VERIFY  15
#define HS_FINISHED     20

#define SUITE_AES_GCM   0x1301
#define SUITE_CHACHA    0x1303

typedef struct {
    tcp_conn *tcp;
    int       suite;                 /* negotiated cipher suite */
    uint8_t   trans[40000]; int tlen;/* handshake transcript (for re-hashing; sized for real cert chains) */
    /* traffic keys + per-direction record sequence numbers */
    uint8_t   ckey[32], civ[12]; uint64_t cseq;
    uint8_t   skey[32], siv[12]; uint64_t sseq;
    int       keylen;                /* 16 (AES) or 32 (ChaCha) */
    /* receive buffering for the record layer */
    uint8_t   rbuf[20000]; int rhead, rtail;
    /* leaf certificate public key (copied out of the flight buffer, which moves) */
    uint8_t   leaf_key[1100]; int leaf_key_len, leaf_key_alg;
    int       chain_anchored;        /* chain top verified against a trusted root CA */
    int       host_ok;               /* leaf-cert hostname match: 1 match, 0 definitive mismatch, -1 unknown */
    int       cert_time_ok;          /* leaf-cert validity period: 1 valid, 0 expired/not-yet-valid, -1 unknown */
} tls;

/* CertificateVerify result of the most recent handshake, for the browser UI:
 * -2 = no HTTPS / absent, 0 = signature OK (leaf key proven), -1 = failed. */
static int g_cert_status = -2;
int tls_cert_status(void) { return g_cert_status; }
/* 1 if the most recent chain anchored to a trusted root CA (full path validated). */
static int g_chain_anchored = 0;
int tls_chain_anchored(void) { return g_chain_anchored; }

/* leaf-cert hostname match of the most recent tls_get: -2 none, 1 match, 0 mismatch. */
static int g_host_match = -2;
int tls_host_match(void) { return g_host_match; }

/* leaf-cert identity of the most recent tls_get (for the browser's cert-info display). */
static char g_leaf_cn[64], g_leaf_expiry[24];
const char *tls_leaf_cn(void)     { return g_leaf_cn; }
const char *tls_leaf_expiry(void) { return g_leaf_expiry; }

/* tiny RNG for ephemeral key + randoms (seeded by the caller). */
static uint32_t g_rng = 0x1234abcd;
static void rng_seed(uint32_t s) { g_rng = s ? s : 1; }
static void rng_fill(uint8_t *p, int n) {
    for (int i = 0; i < n; i++) { g_rng ^= g_rng<<13; g_rng ^= g_rng>>17; g_rng ^= g_rng<<5; p[i] = (uint8_t)g_rng; }
}

/* ---- helpers ---- */
static void trans_add(tls *t, const uint8_t *p, int n) {
    if (t->tlen + n <= (int)sizeof(t->trans)) { memcpy(t->trans + t->tlen, p, n); t->tlen += n; }
}
static void trans_hash(tls *t, uint8_t out[32]) { sha256(t->trans, t->tlen, out); }

/* ---- raw record layer over tcp ---- */

/* ensure at least n bytes are buffered from the socket; returns 0/-1 */
static int fill(tls *t, int n) {
    while (t->rtail - t->rhead < n) {
        if (t->rhead > 0) { memmove(t->rbuf, t->rbuf + t->rhead, t->rtail - t->rhead); t->rtail -= t->rhead; t->rhead = 0; }
        if (t->rtail >= (int)sizeof(t->rbuf)) return -1;
        int r = tcp_read(t->tcp, t->rbuf + t->rtail, sizeof(t->rbuf) - t->rtail, 300);
        if (r <= 0) return -1;
        t->rtail += r;
    }
    return 0;
}

/* read one TLS record: type + payload (payload copied to `out`). 0/-1. */
static int read_record(tls *t, int *type, uint8_t *out, int maxn, int *outlen) {
    if (fill(t, 5) != 0) return -1;
    const uint8_t *h = t->rbuf + t->rhead;
    *type = h[0];
    int len = (h[3] << 8) | h[4];
    if (len < 0 || len > maxn || len > 18432) return -1;
    if (fill(t, 5 + len) != 0) return -1;
    memcpy(out, t->rbuf + t->rhead + 5, len);
    t->rhead += 5 + len;
    *outlen = len;
    return 0;
}

static int write_record(tls *t, int type, const uint8_t *data, int len) {
    uint8_t hdr[5] = { (uint8_t)type, 0x03, 0x03, (uint8_t)(len >> 8), (uint8_t)len };
    if (tcp_write(t->tcp, hdr, 5) < 0) return -1;
    if (len && tcp_write(t->tcp, data, len) < 0) return -1;
    return 0;
}

/* AEAD seal/open for an encrypted record. nonce = iv XOR seq (right-aligned). */
static void rec_nonce(uint8_t nonce[12], const uint8_t iv[12], uint64_t seq) {
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (uint8_t)(seq >> (8 * i));
}

/* Send an encrypted handshake/app record carrying inner content `data` of inner
 * type `inner` (TLS 1.3 wraps it as a type-23 record). */
static int write_enc(tls *t, int inner, const uint8_t *data, int len) {
    /* we only ever send small client records (Finished 36 B, the HTTP request
     * <=512 B, close_notify 2 B), so these stay small on the 16 KB task stack */
    uint8_t pt[2048];
    if (len + 1 > (int)sizeof(pt)) return -1;
    memcpy(pt, data, len); pt[len] = (uint8_t)inner;       /* inner plaintext: content ‖ type */
    int ptlen = len + 1;
    int ctlen = ptlen + 16;                                /* + AEAD tag */
    uint8_t hdr[5] = { REC_APP, 0x03, 0x03, (uint8_t)(ctlen >> 8), (uint8_t)ctlen };
    uint8_t nonce[12]; rec_nonce(nonce, t->civ, t->cseq);
    uint8_t out[2048 + 16], tag[16];
    if (t->suite == SUITE_AES_GCM)
        aes128_gcm_encrypt(out, tag, pt, ptlen, hdr, 5, t->ckey, nonce);
    else
        chacha20poly1305_encrypt(out, tag, pt, ptlen, hdr, 5, t->ckey, nonce);
    memcpy(out + ptlen, tag, 16);
    t->cseq++;
    if (tcp_write(t->tcp, hdr, 5) < 0) return -1;
    return tcp_write(t->tcp, out, ctlen) < 0 ? -1 : 0;
}

/* Read+decrypt the next encrypted record's inner plaintext. Sets *inner to the
 * inner content type. Skips ChangeCipherSpec. Returns inner length or -1. */
static int read_enc(tls *t, int *inner, uint8_t *out, int maxn) {
    /* a full TLS record payload can be ~18 KB — too big for the 16 KB task stack.
     * The fetch worker is single-threaded and rec is consumed before return, so
     * BSS is safe here (same reasoning as the buffers in tls_get). */
    static uint8_t rec[20000];
    for (;;) {
        int type, len;
        if (read_record(t, &type, rec, sizeof(rec), &len) != 0) return -1;
        if (type == REC_CCS) continue;                     /* middlebox-compat dummy: ignore */
        if (type == REC_ALERT) return -1;
        if (type != REC_APP) return -1;
        if (len < 17) return -1;
        uint8_t nonce[12]; rec_nonce(nonce, t->siv, t->sseq);
        uint8_t hdr[5] = { (uint8_t)type, 0x03, 0x03, (uint8_t)(len >> 8), (uint8_t)len };
        int ptlen = len - 16;
        if (ptlen > maxn) return -1;                       /* never write past the caller's buffer */
        const uint8_t *tag = rec + ptlen;
        int rc = (t->suite == SUITE_AES_GCM)
               ? aes128_gcm_decrypt(out, rec, ptlen, hdr, 5, tag, t->skey, nonce)
               : chacha20poly1305_decrypt(out, rec, ptlen, hdr, 5, tag, t->skey, nonce);
        if (rc != 0) return -1;
        t->sseq++;
        /* strip trailing zero padding, then the 1-byte inner content type */
        int n = ptlen;
        while (n > 0 && out[n - 1] == 0) n--;
        if (n < 1) continue;
        *inner = out[n - 1];
        return n - 1;
    }
}

/* ---- key schedule (TLS_*_SHA256) ---- */

static void derive_traffic(tls *t, const uint8_t secret[32], uint8_t *key, uint8_t *iv) {
    hkdf_expand_label(secret, "key", 0, 0, key, t->keylen);
    hkdf_expand_label(secret, "iv", 0, 0, iv, 12);
}

/* ECDSA verify with an EC issuer key, picking the curve by point length (P-256 =
 * 65 bytes, P-384 = 97) and deriving z = the leftmost (order-bits) of the digest:
 * P-256 uses the leftmost 32 bytes; P-384 uses the full 48 (or a left-padded
 * shorter digest). `sig` is the DER ECDSA-Sig-Value. Returns 0 if valid. */
static int ecdsa_cert_verify(const uint8_t *ikey, size_t iklen, const uint8_t *hash,
                             int hashlen, const uint8_t *sig, size_t siglen) {
    if (iklen == 65)                       /* P-256 issuer: verify reads the leftmost 32 */
        return ecdsa_p256_verify_der(ikey, iklen, hash, sig, siglen);
    if (iklen == 97) {                     /* P-384 issuer: z is 48 bytes, left-padded */
        if (hashlen <= 0 || hashlen > 48) return -1;   /* callers pass 32/48; guard regardless */
        uint8_t z[48];
        if (hashlen >= 48) memcpy(z, hash, 48);
        else { memset(z, 0, 48 - hashlen); memcpy(z + 48 - hashlen, hash, (size_t)hashlen); }
        return ecdsa_p384_verify_der(ikey, iklen, z, sig, siglen);
    }
    return -1;                             /* unknown EC curve */
}

/* Verify cert `c`'s signature using an issuer public key (`ikey`/`iklen` in
 * x509_cert.key form, alg `ikalg`). Returns 0 if valid. Supports RSA + ECDSA
 * (P-256/P-384) with SHA-256/SHA-384. */
static int cert_sig_ok(const x509_cert *c, const uint8_t *ikey, size_t iklen, int ikalg) {
    if (!c->sig || !c->tbs) return -1;
    const uint8_t *n, *e; size_t nl, el;
    switch (c->sig_alg) {
    case X509_SIG_ECDSA_SHA256:
        if (ikalg != X509_KEY_EC) return -1;
        { uint8_t h[32]; sha256(c->tbs, c->tbs_len, h);
          return ecdsa_cert_verify(ikey, iklen, h, 32, c->sig, c->sig_len); }
    case X509_SIG_ECDSA_SHA384:
        if (ikalg != X509_KEY_EC) return -1;
        { uint8_t h[48]; sha384(c->tbs, c->tbs_len, h);
          return ecdsa_cert_verify(ikey, iklen, h, 48, c->sig, c->sig_len); }
    case X509_SIG_RSA_SHA256:
        if (ikalg != X509_KEY_RSA || rsa_pubkey_parse(ikey, iklen, &n, &nl, &e, &el) != 0) return -1;
        { uint8_t h[32]; sha256(c->tbs, c->tbs_len, h);
          return rsa_pkcs1_sha256_verify(n, nl, e, el, c->sig, c->sig_len, h); }
    case X509_SIG_RSA_SHA384:
        if (ikalg != X509_KEY_RSA || rsa_pubkey_parse(ikey, iklen, &n, &nl, &e, &el) != 0) return -1;
        { uint8_t h[48]; sha384(c->tbs, c->tbs_len, h);
          return rsa_pkcs1_sha384_verify(n, nl, e, el, c->sig, c->sig_len, h); }
    }
    return -1;   /* unsupported signature algorithm */
}

#ifndef TLS_RING3
/* Verify chain links [lo,hi) of an smp_parallel_for split (M1528, kernel build
 * only — see the call site). Each link ("is certs[i] signed by certs[i+1]'s
 * key") is fully independent of every other, so this is safe to run
 * concurrently with the other chunks: cert_sig_ok's whole call chain
 * (ecdsa_cert_verify/rsa_pkcs1_sha*_verify -> bignum.c) is reentrant, and
 * ecdsa.c's only historical exception (the P/N field-prime/order globals)
 * now keeps one slot per core specifically so this is safe. */
struct chain_link_ctx { const x509_cert *certs; int *link_ok; };
static void verify_link_chunk(int lo, int hi, void *ctxp) {
    struct chain_link_ctx *cx = ctxp;
    for (int i = lo; i < hi; i++)
        cx->link_ok[i] = (cert_sig_ok(&cx->certs[i], cx->certs[i + 1].key,
                                       cx->certs[i + 1].key_len, cx->certs[i + 1].key_alg) == 0);
}
#endif

/* ---- server-certificate authentication (TLS 1.3, RFC 8446 4.4.2-4.4.3) ----
 * Parse the Certificate message, extract the LEAF cert's public key, and copy it
 * into t->leaf_key (the flight buffer moves between records, so we can't alias it).
 * `m`/`mlen` are the handshake-message body (after the 4-byte header). Every length
 * read from the wire is bounded against mlen. Returns 0 if a leaf key was captured.
 *
 * Layout: ctx_len(1) ctx[ctx_len] cert_list_len(3) [ cert_len(3) cert[..] ext_len(2) ext[..] ]... */
static int tls_capture_leaf_key(tls *t, const uint8_t *m, int mlen, const char *host) {
    t->leaf_key_len = 0;
    int o = 0;
    if (o + 1 > mlen) return -1;
    int ctxlen = m[o]; o += 1 + ctxlen;                 /* skip certificate_request_context */
    if (o + 3 > mlen) return -1;
    int listlen = (m[o]<<16)|(m[o+1]<<8)|m[o+2]; o += 3;
    if (listlen < 0 || o + listlen > mlen) return -1;
    /* Parse the whole chain (all cert pointers alias m[], valid for this call since
     * the Certificate message is processed in one piece). Each entry:
     * cert_len(3) cert[cert_len] ext_len(2) ext[ext_len]. */
    x509_cert certs[8]; int n = 0;
    while (n < 8 && o + 3 <= mlen) {
        int clen = (m[o]<<16)|(m[o+1]<<8)|m[o+2]; o += 3;
        if (clen <= 0 || o + clen > mlen) break;
        if (x509_parse(m + o, (size_t)clen, &certs[n]) == 0) {
            kprintf("[tls] cert[%d]: CN=%s  expires %s  (%s)\n", n,
                    certs[n].subject_cn[0] ? certs[n].subject_cn : "?", certs[n].not_after,
                    certs[n].key_alg == X509_KEY_EC ? "EC" : certs[n].key_alg == X509_KEY_RSA ? "RSA" : "?");
            n++;
        }
        o += clen;
        if (o + 2 > mlen) break;                         /* per-cert extensions */
        int extlen = (m[o]<<8)|m[o+1]; o += 2;
        if (extlen < 0 || o + extlen > mlen) break;
        o += extlen;
    }
    if (n == 0) return -1;

    /* capture the LEAF (certs[0]) public key (copied — m[] moves between records) */
    if (certs[0].key_alg != X509_KEY_OTHER &&
        certs[0].key_len > 0 && certs[0].key_len <= sizeof(t->leaf_key)) {
        memcpy(t->leaf_key, certs[0].key, certs[0].key_len);
        t->leaf_key_len = (int)certs[0].key_len;
        t->leaf_key_alg = certs[0].key_alg;
    }

    /* snapshot the leaf identity for the browser's cert-info display ('i' key) */
    { int k = 0; while (certs[0].subject_cn[k] && k < (int)sizeof(g_leaf_cn)-1) { g_leaf_cn[k] = certs[0].subject_cn[k]; k++; } g_leaf_cn[k] = 0;
      k = 0; while (certs[0].not_after[k] && k < (int)sizeof(g_leaf_expiry)-1) { g_leaf_expiry[k] = certs[0].not_after[k]; k++; } g_leaf_expiry[k] = 0; }

    /* HOSTNAME VERIFICATION: does the leaf cert's SAN/CN actually name this host?
     * 1 = match, 0 = DEFINITIVE mismatch (we saw the cert's whole name set), -1 =
     * uncertain (no host, or the SAN list was larger than we store — fail open so a
     * legitimate mega-SAN cert is never wrongly rejected). The enforcing gate in
     * tls_get_inner rejects only on a definitive (0) mismatch. */
    if (host && host[0]) {
        if (host_matches_cert(host, &certs[0]))      t->host_ok = 1;
        else if (certs[0].san_capped)                t->host_ok = -1;   /* couldn't see all SANs */
        else                                          t->host_ok = 0;
        kprintf("[tls] hostname %s vs leaf cert (CN=%s, %d SAN): %s\n", host,
                certs[0].subject_cn[0] ? certs[0].subject_cn : "?", certs[0].n_san,
                t->host_ok == 1 ? "MATCH" : t->host_ok == 0 ? "MISMATCH" : "uncertain");
    }

    /* VALIDITY PERIOD: reject an expired / not-yet-valid leaf cert. Only enforced when
     * the wall clock is plausibly set (RTC year >= 2020) — an unset clock fails open
     * (cert_time_ok stays -1) so a missing/garbage RTC can't break all of HTTPS. An
     * unparseable date also fails open (x509_time_cmp returns 0 -> treated as in-range). */
    {
        struct rtc_time now; rtc_now(&now);
        if (now.year >= 2020) {
            int aft = x509_time_cmp(certs[0].not_after,  now.year, now.month, now.day, now.hour, now.min, now.sec);
            int bef = x509_time_cmp(certs[0].not_before, now.year, now.month, now.day, now.hour, now.min, now.sec);
            t->cert_time_ok = (aft >= 0 && bef <= 0) ? 1 : 0;   /* now within [notBefore, notAfter] */
            if (t->cert_time_ok == 0)
                kprintf("[tls] cert validity: %s (notBefore %s notAfter %s, now %d-%02d-%02d)\n",
                        bef > 0 ? "NOT YET VALID" : "EXPIRED",
                        certs[0].not_before, certs[0].not_after, now.year, now.month, now.day);
        }
    }

    /* chain-internal verification (NON-FATAL, logged): each cert is signed by the
     * next one up. This proves the presented chain is self-consistent; it does NOT
     * yet check the top against a trusted root CA (that's the remaining step before
     * this can be enforced for MITM protection). Each link is independent
     * (M1528): the kernel build verifies them all in parallel across cores
     * instead of one at a time (a real chain is short — a couple links — but
     * each is a full public-key signature check, ~tens of ms of bignum work,
     * so this is a genuine wall-clock win, not a micro-optimisation). The
     * ring-3 build (httpget.elf) has no other cores to hand work to, so it
     * keeps the original plain loop. */
    int links = n > 0 ? n - 1 : 0, ok = 0;
#ifdef TLS_RING3
    for (int i = 0; i < links; i++)
        if (cert_sig_ok(&certs[i], certs[i+1].key, certs[i+1].key_len, certs[i+1].key_alg) == 0) ok++;
#else
    int link_ok[8] = {0};
    if (links > 0) {
        struct chain_link_ctx cctx = { certs, link_ok };
        smp_parallel_for(links, verify_link_chunk, &cctx);
        for (int i = 0; i < links; i++) if (link_ok[i]) ok++;
    }
#endif
    if (links) kprintf("[tls] chain: %d/%d issuer link(s) verified%s\n", ok, links,
                       ok == links ? "" : " (rest: unsupported sig alg)");

    /* anchor: is the TOP presented cert signed by a trusted root in our store?
     * (For Let's Encrypt the top is an intermediate signed by ISRG Root X1; for a
     * chain that includes a self-signed/cross-signed root, the top cert's KEY
     * matches a baked-in root key.) Logged, not enforced yet. */
    const x509_cert *top = &certs[n-1];
    for (int r = 0; r < N_ROOT_CAS; r++) {
        int key_match = (top->key_alg == ROOT_CAS[r].key_alg &&
                         top->key_len == ROOT_CAS[r].key_len &&
                         memcmp(top->key, ROOT_CAS[r].key, ROOT_CAS[r].key_len) == 0);
        if (key_match ||
            cert_sig_ok(top, ROOT_CAS[r].key, ROOT_CAS[r].key_len, ROOT_CAS[r].key_alg) == 0) {
            /* "anchored" requires the WHOLE chain to have verified (ok==links), not
             * just that the top is a trusted root — otherwise a broken middle link
             * would still report a full path. This is the gate enforcement will use. */
            kprintf("[tls] chain ANCHORED to trusted root: %s%s\n", ROOT_CAS[r].name,
                    ok == links ? "" : " (but a chain link failed!)");
            if (ok == links) { t->chain_anchored = 1; g_chain_anchored = 1; }
            break;
        }
    }
    return t->leaf_key_len ? 0 : -1;
}

/* Verify the CertificateVerify signature against the captured leaf key.
 * `m`/`mlen` = the CertificateVerify body; `th` = transcript hash through the
 * Certificate message. Returns 0 if the signature is valid, -1 otherwise.
 * Layout: scheme(2) siglen(2) sig[siglen]. */
static int tls_verify_certverify(tls *t, const uint8_t *m, int mlen, const uint8_t th[32]) {
    if (t->leaf_key_len == 0) return -1;
    if (mlen < 4) return -1;
    int scheme = (m[0]<<8)|m[1];
    int siglen = (m[2]<<8)|m[3];
    if (siglen <= 0 || 4 + siglen > mlen) return -1;
    const uint8_t *sig = m + 4;

    /* the signed content: 64 spaces ‖ context ‖ 0x00 ‖ transcript-hash */
    static uint8_t signed_content[64 + 34 + 1 + 32];
    int p = 0;
    for (int i = 0; i < 64; i++) signed_content[p++] = 0x20;
    const char *ctx = "TLS 1.3, server CertificateVerify";
    for (int i = 0; ctx[i]; i++) signed_content[p++] = (uint8_t)ctx[i];
    signed_content[p++] = 0x00;
    memcpy(signed_content + p, th, 32); p += 32;
    uint8_t h[32]; sha256(signed_content, p, h);

    if (scheme == 0x0403 && t->leaf_key_alg == X509_KEY_EC)       /* ecdsa_secp256r1_sha256 */
        return ecdsa_p256_verify_der(t->leaf_key, (size_t)t->leaf_key_len, h, sig, (size_t)siglen);
    if (t->leaf_key_alg == X509_KEY_RSA) {                        /* rsa_pss / rsa_pkcs1, SHA-256 */
        const uint8_t *n, *e; size_t nl, el;
        if (rsa_pubkey_parse(t->leaf_key, (size_t)t->leaf_key_len, &n, &nl, &e, &el) != 0) return -1;
        if (scheme == 0x0804 || scheme == 0x0805 || scheme == 0x0806)   /* rsa_pss_rsae_* */
            return rsa_pss_sha256_verify(n, nl, e, el, sig, (size_t)siglen, h);
        if (scheme == 0x0401)                                            /* rsa_pkcs1_sha256 */
            return rsa_pkcs1_sha256_verify(n, nl, e, el, sig, (size_t)siglen, h);
    }
    return -1;   /* unsupported scheme/key combination */
}

/* full client. Returns response length into `out`, or -1. */
/* Does the HTTP response in buf[0..n) contain a complete first SSE event — i.e. the
 * header terminator (\r\n\r\n or \n\n) followed by a blank-line-terminated body block?
 * Used by the SSE early-stop: a server-sent-events stream stays open, so we must stop
 * reading after the first event rather than block until the (never-coming) close. */
static int tls_sse_first_event(const uint8_t *buf, int n) {
    int bodyoff = -1;
    for (int i = 0; i + 1 < n; i++) {
        if (i + 3 < n && buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n') { bodyoff = i + 4; break; }
        if (buf[i]=='\n' && buf[i+1]=='\n') { bodyoff = i + 2; break; }
    }
    if (bodyoff < 0) return 0;                         /* headers not complete yet */
    for (int i = bodyoff; i + 1 < n; i++) {            /* a blank line ends the first event */
        if (buf[i]=='\n' && buf[i+1]=='\n') return 1;
        if (i + 2 < n && buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r') return 1;
    }
    return 0;
}
/* WebSocket-over-TLS (wss://, M1847): a persistent session left open after the
 * handshake so the net.c WebSocket transport can send/read frames as TLS app
 * data. Copied out of tls_get_inner's function-static `T` + stack `tcp` so a
 * later HTTPS fetch (which reuses those) doesn't clobber the live WS session. */
static tls       g_wss_T;
static tcp_conn  g_wss_tcp;
static int       g_wss_open;

/* WHICH STAGE FAILED (M2026).
 *
 * tls_get answers every failure with -1, and the browser turned that into one
 * sentence naming four different causes at once: "the host may not exist, the
 * connection or TLS handshake failed, or the site refused our request." That
 * is not a diagnosis, it is a list of everything it could have been -- and the
 * one thing the code DOES know, which stage it got to, was the thing it threw
 * away. Same shape as the socket errors in M1965: the error named the wrong
 * thing, so every failure looked alike.
 *
 * One string, set at the point of failure, read by whoever reports it. */
static const char *g_tls_fail = "";
const char *tls_fail_reason(void) { return (g_tls_fail && g_tls_fail[0]) ? g_tls_fail : "unknown"; }

static int tls_get_inner(const char *host, const char *path, uint8_t *out, int max, uint32_t seed,
                         const char *method, const char *ctype, const char *body, int bodylen, int sse, int ws_mode) {   /* method NULL/"GET" => GET (byte-identical to before); "POST" => send body (M702); sse=1 => stop after the first SSE event (M-eventsource); ws_mode=1 => stop after the handshake, leave the session open for tls_ws_* (M1847) */
    rng_seed(seed);
    g_cert_status = -2; g_chain_anchored = 0; g_host_match = -2;   /* clear stale results */
    g_tls_fail = "";                                               /* ...including the last failure stage (M2026) */
    g_leaf_cn[0] = 0; g_leaf_expiry[0] = 0;
    char bare[256]; uint16_t cport = (uint16_t)url_host_port(host, bare, sizeof(bare), 443);   /* honor host:port (M1773); DNS/SNI/cert-match use the bare host, Host: keeps the :port */
    uint8_t ip[4];
    if (parse_ipv4(bare, ip) != 0 && dns_resolve(bare, ip) != 0) { g_tls_fail = "DNS lookup failed"; return -1; }   /* IP literal (M1847), else DNS */
    tcp_conn tcp;
    if (tcp_connect(&tcp, ip, cport) != 0) { g_tls_fail = "TCP connect refused or timed out"; return -1; }

    /* These large buffers live in BSS, not on the small (16 KB) task stack. They're
     * shared, so tls_get() serializes all callers (the browser worker AND the shell's
     * sys_https) — never two tls_get_inner() at once. */
    static tls T; memset(&T, 0, sizeof(T)); T.tcp = &tcp;
    T.host_ok = -1;                 /* unknown until the leaf cert is parsed (0 = mismatch is meaningful) */
    T.cert_time_ok = -1;            /* unknown until validity is checked against a sane clock */

    /* --- ephemeral X25519 key --- */
    uint8_t priv[32], cpub[32];
    rng_fill(priv, 32);
    x25519_base(cpub, priv);

    /* --- build ClientHello --- */
    uint8_t crand[32]; rng_fill(crand, 32);
    uint8_t sid[32];   rng_fill(sid, 32);     /* legacy session id (compat) */
    uint8_t ch[1024]; int p = 0;
    ch[p++] = 0x03; ch[p++] = 0x03;            /* legacy_version TLS 1.2 */
    memcpy(ch + p, crand, 32); p += 32;        /* random */
    ch[p++] = 32; memcpy(ch + p, sid, 32); p += 32;   /* legacy_session_id */
    ch[p++] = 0x00; ch[p++] = 0x04;            /* cipher_suites length */
    ch[p++] = 0x13; ch[p++] = 0x01;            /* TLS_AES_128_GCM_SHA256 */
    ch[p++] = 0x13; ch[p++] = 0x03;            /* TLS_CHACHA20_POLY1305_SHA256 */
    ch[p++] = 0x01; ch[p++] = 0x00;            /* legacy_compression: null */
    int extlen_pos = p; p += 2;                /* extensions length (fill later) */
    /* supported_versions */
    ch[p++]=0x00; ch[p++]=0x2b; ch[p++]=0x00; ch[p++]=0x03; ch[p++]=0x02; ch[p++]=0x03; ch[p++]=0x04;
    /* supported_groups: x25519 */
    ch[p++]=0x00; ch[p++]=0x0a; ch[p++]=0x00; ch[p++]=0x04; ch[p++]=0x00; ch[p++]=0x02; ch[p++]=0x00; ch[p++]=0x1d;
    /* signature_algorithms */
    ch[p++]=0x00; ch[p++]=0x0d; ch[p++]=0x00; ch[p++]=0x08; ch[p++]=0x00; ch[p++]=0x06;
    ch[p++]=0x04;ch[p++]=0x03; ch[p++]=0x08;ch[p++]=0x04; ch[p++]=0x04;ch[p++]=0x01;   /* ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256 */
    /* key_share: x25519 */
    ch[p++]=0x00; ch[p++]=0x33; ch[p++]=0x00; ch[p++]=0x26; ch[p++]=0x00; ch[p++]=0x24;
    ch[p++]=0x00; ch[p++]=0x1d; ch[p++]=0x00; ch[p++]=0x20; memcpy(ch+p, cpub, 32); p += 32;
    /* server_name (SNI) — the bare hostname only (a ":port" is not part of the name) */
    int hl = (int)strlen(bare);
    ch[p++]=0x00; ch[p++]=0x00;
    ch[p++]=(uint8_t)((hl+5)>>8); ch[p++]=(uint8_t)(hl+5);
    ch[p++]=(uint8_t)((hl+3)>>8); ch[p++]=(uint8_t)(hl+3);
    ch[p++]=0x00;
    ch[p++]=(uint8_t)(hl>>8); ch[p++]=(uint8_t)hl;
    for (int i = 0; i < hl; i++) ch[p++] = (uint8_t)bare[i];
    int extlen = p - extlen_pos - 2;
    ch[extlen_pos] = (uint8_t)(extlen >> 8); ch[extlen_pos+1] = (uint8_t)extlen;

    /* wrap as a handshake message and a plaintext record */
    uint8_t hs[1100]; int hp = 0;
    hs[hp++] = HS_CLIENT_HELLO; hs[hp++]=(uint8_t)(p>>16); hs[hp++]=(uint8_t)(p>>8); hs[hp++]=(uint8_t)p;
    memcpy(hs + hp, ch, p); hp += p;
    trans_add(&T, hs, hp);
    if (write_record(&T, REC_HS, hs, hp) != 0) { g_tls_fail = "could not send the TLS ClientHello"; tcp_close(&tcp); return -1; }

    /* --- read ServerHello (plaintext handshake record) --- */
    static uint8_t sh[4096]; int shlen, stype;
    if (read_record(&T, &stype, sh, sizeof(sh), &shlen) != 0 || stype != REC_HS) { g_tls_fail = "no TLS ServerHello (server rejected our handshake)"; tcp_close(&tcp); return -1; }
    if (shlen < 4 || sh[0] != HS_SERVER_HELLO) { g_tls_fail = "malformed TLS ServerHello"; tcp_close(&tcp); return -1; }
    trans_add(&T, sh, shlen);
    /* parse ServerHello: skip version(2)+random(32), session_id, cipher_suite, comp, exts.
     * Every field length is attacker-controlled, so bound each step against shlen
     * (the actual record payload) before indexing — never trust the wire. */
    int q = 4 + 2 + 32;
    if (q + 1 > shlen) { tcp_close(&tcp); return -1; }
    int sidl = sh[q++]; q += sidl;               /* legacy_session_id */
    if (q + 3 > shlen) { tcp_close(&tcp); return -1; }   /* suite(2) + comp(1) */
    T.suite = (sh[q] << 8) | sh[q+1]; q += 2;
    q += 1;                                      /* legacy_compression */
    if (q + 2 > shlen) { tcp_close(&tcp); return -1; }
    int ehl = (sh[q] << 8) | sh[q+1]; q += 2;
    int eend = q + ehl;
    if (eend > shlen) { tcp_close(&tcp); return -1; }    /* extensions must fit */
    uint8_t spub[32]; int have_spub = 0;
    while (q + 4 <= eend) {
        int et = (sh[q]<<8)|sh[q+1], el = (sh[q+2]<<8)|sh[q+3]; q += 4;
        if (el < 0 || q + el > eend) { tcp_close(&tcp); return -1; }
        if (et == 0x0033 && el >= 36) {          /* key_share: group(2) len(2) key */
            if ((sh[q]<<8|sh[q+1]) == 0x001d) { memcpy(spub, sh + q + 4, 32); have_spub = 1; }
        }
        q += el;
    }
    if (!have_spub) { tcp_close(&tcp); return -1; }
    T.keylen = (T.suite == SUITE_CHACHA) ? 32 : 16;

    /* --- key schedule: derive handshake traffic keys --- */
    uint8_t shared[32]; x25519(shared, priv, spub);
    int allzero = 1; for (int i=0;i<32;i++) if (shared[i]) allzero=0;
    if (allzero) { tcp_close(&tcp); return -1; }      /* reject low-order point */

    uint8_t early[32], empty_hash[32], derived[32], hs_secret[32];
    uint8_t zero[32]; memset(zero, 0, 32);
    hkdf_extract(zero, 32, zero, 32, early);
    sha256((const uint8_t *)"", 0, empty_hash);
    tls13_derive_secret(early, "derived", empty_hash, derived);
    hkdf_extract(derived, 32, shared, 32, hs_secret);

    uint8_t th[32]; trans_hash(&T, th);               /* hash(ClientHello||ServerHello) */
    uint8_t c_hs[32], s_hs[32];
    tls13_derive_secret(hs_secret, "c hs traffic", th, c_hs);
    tls13_derive_secret(hs_secret, "s hs traffic", th, s_hs);
    derive_traffic(&T, c_hs, T.ckey, T.civ);
    derive_traffic(&T, s_hs, T.skey, T.siv);
    T.cseq = T.sseq = 0;

    /* master secret (needed after the server Finished) */
    uint8_t derived2[32], master[32];
    tls13_derive_secret(hs_secret, "derived", empty_hash, derived2);
    hkdf_extract(derived2, 32, zero, 32, master);

    /* --- read the server's encrypted handshake flight ---
     * A single handshake message (notably the Certificate, which carries the whole
     * cert chain) can be FRAGMENTED across several TLS records, and one record can
     * also pack several messages back-to-back. So decrypt each record and append
     * its bytes to a reassembly buffer, then consume only the complete messages
     * from the front, carrying the remainder forward to the next record. */
    static uint8_t inner[20000], hsbuf[40000]; int got, itype, hslen = 0;
    int saw_finished = 0;
    uint8_t s_fin_hash[32]; int have_finhash = 0;
    int cv_ok = -2;                       /* CertificateVerify result: -2=absent, 0=ok, -1=bad */
    while (!saw_finished) {
        got = read_enc(&T, &itype, inner, sizeof(inner));
        if (got < 0) { tcp_close(&tcp); return -1; }
        if (itype != REC_HS) continue;
        if (hslen + got > (int)sizeof(hsbuf)) { tcp_close(&tcp); return -1; }
        memcpy(hsbuf + hslen, inner, got); hslen += got;
        int o = 0;
        while (o + 4 <= hslen) {
            int mt = hsbuf[o];
            int ml = (hsbuf[o+1]<<16)|(hsbuf[o+2]<<8)|hsbuf[o+3];
            if (o + 4 + ml > hslen) break;          /* incomplete: wait for more records */
            uint8_t cv_th[32];                       /* transcript hash through Certificate */
            if (mt == HS_FINISHED) {
                trans_hash(&T, s_fin_hash); have_finhash = 1;   /* transcript up to (not incl) server Finished */
            }
            if (mt == HS_CERT)             tls_capture_leaf_key(&T, hsbuf + o + 4, ml, bare);   /* match the cert against the bare host, not host:port (M1773) */
            else if (mt == HS_CERT_VERIFY) trans_hash(&T, cv_th);  /* snapshot BEFORE adding CertVerify */
            trans_add(&T, hsbuf + o, 4 + ml);
            if (mt == HS_CERT_VERIFY)                /* server proves it holds the leaf key (non-fatal) */
                cv_ok = tls_verify_certverify(&T, hsbuf + o + 4, ml, cv_th);
            if (mt == HS_FINISHED) {
                /* verify server Finished = HMAC(s_finished_key, transcript-thru-CertVerify) */
                uint8_t s_fin_key[32], expect[32];
                if (ml != 32) { tcp_close(&tcp); return -1; }   /* SHA-256 verify_data is 32 B */
                hkdf_expand_label(s_hs, "finished", 0, 0, s_fin_key, 32);
                hmac_sha256(s_fin_key, 32, s_fin_hash, 32, expect);
                if (!have_finhash || memcmp(expect, hsbuf + o + 4, 32) != 0) { tcp_close(&tcp); return -1; }
                saw_finished = 1;
            }
            o += 4 + ml;
        }
        memmove(hsbuf, hsbuf + o, hslen - o); hslen -= o;       /* keep the remainder */
    }
    /* The CertificateVerify signature proves the server holds the private key for
     * the leaf cert it presented; we verify it here. The cert CHAIN (issuer links
     * + anchoring to a baked-in trusted root) is validated separately above. The
     * combined result is logged + surfaced to the UI, but is INFORMATIONAL not
     * ENFORCING — a failure is non-fatal (enforcing needs a full root set + a
     * fatal gate; see docs/438). */
    kprintf("[tls] CertificateVerify: %s\n",
            cv_ok == 0 ? "signature OK (leaf key proven)"
                       : cv_ok == -2 ? "absent" : "FAILED/unsupported");
    g_cert_status = cv_ok;          /* expose to the browser UI (see tls_cert_status) */
    g_host_match = T.host_ok;       /* expose the hostname-match result too */

    /* --- application traffic keys (transcript now includes server Finished) --- */
    uint8_t fhash[32]; trans_hash(&T, fhash);
    uint8_t c_ap[32], s_ap[32];
    tls13_derive_secret(master, "c ap traffic", fhash, c_ap);
    tls13_derive_secret(master, "s ap traffic", fhash, s_ap);

    /* --- send client Finished (still under handshake keys) --- */
    uint8_t c_fin_key[32], cfin[36];
    hkdf_expand_label(c_hs, "finished", 0, 0, c_fin_key, 32);
    hmac_sha256(c_fin_key, 32, fhash, 32, cfin + 4);
    cfin[0] = HS_FINISHED; cfin[1]=0; cfin[2]=0; cfin[3]=32;
    /* (optional) send a ChangeCipherSpec for middlebox compatibility */
    { uint8_t ccs = 1; write_record(&T, REC_CCS, &ccs, 1); }
    if (write_enc(&T, REC_HS, cfin, 36) != 0) { tcp_close(&tcp); return -1; }

    /* --- switch to application keys --- */
    derive_traffic(&T, c_ap, T.ckey, T.civ); T.cseq = 0;
    derive_traffic(&T, s_ap, T.skey, T.siv); T.sseq = 0;

    /* ENFORCING (hostname): if the leaf cert's SAN/CN does not name the host we asked
     * for, this is not the site's certificate (a MITM or misissued cert) — abort the
     * connection BEFORE sending the request. Only a DEFINITIVE mismatch (host_ok==0,
     * i.e. we saw the cert's whole name set) rejects; host_ok==-1 (no cert, or a SAN
     * list larger than we store) fails open as informational, so a legitimate site is
     * never wrongly rejected. Chain-to-root anchoring stays informational (the baked
     * root set is incomplete) — see docs/438. */
    if (T.host_ok == 0 || T.cert_time_ok == 0) {
        kprintf("[tls] ABORT: leaf certificate %s for host %s — refusing\n",
                T.host_ok == 0 ? "does not match" : "is expired/not-yet-valid", host);
        tcp_close(&tcp);
        return -1;
    }

    /* wss:// (M1847): the handshake is done and app keys are live — hand the open
     * session to tls_ws_* rather than sending an HTTP request. Copy T (function-
     * static) + tcp (a stack local) into the WS-dedicated statics and return; the
     * caller (net.c ws_open) now owns the connection until tls_ws_close(). */
    if (ws_mode) {
        g_wss_T = T; g_wss_tcp = tcp; g_wss_T.tcp = &g_wss_tcp; g_wss_open = 1;
        return 0;
    }

    /* --- send the HTTP request, read the response --- */
    char req[640]; int rl = 0;
    char rpath[1024]; url_request_path(path, rpath, sizeof(rpath));   /* drop any #fragment from the wire request-target (M1774) */
    int is_post = method && (method[0]=='P' || method[0]=='p');
    if (is_post) {
        if (bodylen < 0) bodylen = 0;
        char clen[12]; { unsigned b=(unsigned)bodylen; int t=0; char tmp[12]; do{ tmp[t++]=(char)('0'+b%10); b/=10; }while(b && t<11); int ci=0; while(t) clen[ci++]=tmp[--t]; clen[ci]=0; }
        const char *parts[] = { "POST ", rpath, " HTTP/1.0\r\nHost: ", host,
                                "\r\nContent-Type: ", ctype ? ctype : "text/plain",
                                "\r\nContent-Length: ", clen,
                                "\r\nConnection: close\r\nUser-Agent: OS-DEV/0.1\r\n\r\n" };
        for (unsigned k = 0; k < sizeof(parts)/sizeof(parts[0]); k++)
            for (const char *s = parts[k]; *s && rl < (int)sizeof(req); s++) req[rl++] = (char)*s;
    } else {                       /* GET: byte-identical to the original request (no regression) */
        const char *parts[] = { "GET ", rpath, " HTTP/1.0\r\nHost: ", host,
                                "\r\nConnection: close\r\nUser-Agent: OS-DEV/0.1\r\n\r\n" };
        for (unsigned k = 0; k < sizeof(parts)/sizeof(parts[0]); k++)
            for (const char *s = parts[k]; *s && rl < (int)sizeof(req); s++) req[rl++] = (char)*s;
    }
    if (write_enc(&T, REC_APP, (uint8_t *)req, rl) != 0) { tcp_close(&tcp); return -1; }
    if (is_post && bodylen > 0 && write_enc(&T, REC_APP, (uint8_t *)body, bodylen) != 0) { tcp_close(&tcp); return -1; }

    int total = 0;
    for (;;) {
        got = read_enc(&T, &itype, inner, sizeof(inner));
        if (got < 0) break;
        if (itype == REC_HS) continue;             /* session tickets etc: ignore */
        if (itype == REC_ALERT) break;             /* close_notify */
        if (itype == REC_APP) {
            int n = got; if (total + n > max) n = max - total;
            if (n > 0) { memcpy(out + total, inner, n); total += n; }
            if (total >= max) break;
            if (sse && tls_sse_first_event(out, total)) break;   /* SSE: stop after the first event, then close */
        }
    }
    /* polite close: send an encrypted close_notify alert before tearing down TCP
     * (level=warning(1), description=close_notify(0)) so the peer sees a clean EOF */
    if (tcp.up) { uint8_t cn[2] = { 1, 0 }; write_enc(&T, REC_ALERT, cn, 2); }
    tcp_close(&tcp);
    return total;
}

/* tls_get_inner() uses big shared static buffers, so only one may run at a time.
 * Originally that was guaranteed by the single fetch worker; now sys_https exposes
 * it to the shell too, so serialize here (a second concurrent caller gets -1). */
#ifdef TLS_RING3
/* RING-3 build (user/httpget.c): no privileged cli/sti (ring 3 can't execute them);
 * a single-threaded fetch program needs no serialization anyway. */
static inline uint64_t tls_irq_save(void) { return 0; }
static inline void tls_irq_restore(uint64_t f) { (void)f; }
#else
/* M1604: cli alone only ever stopped a LOCAL interrupt from reentering --
 * since M1531 every core can run a task that calls sys_https, so two cores
 * could both see g_tls_busy==0 before either sets it to 1 and both enter
 * tls_get_inner() at once, tearing each other's static scratch buffers.
 * Same cross-core spinlock-nested-in-cli treatment as pmm.c/vmm.c/kheap.c. */
static volatile int tls_lock;
static inline uint64_t tls_irq_save(void) {
    uint64_t f;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory");
    while (__atomic_exchange_n(&tls_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return f;
}
static inline void tls_irq_restore(uint64_t f) {
    __atomic_store_n(&tls_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(f) : "memory", "cc");
}
#endif

static volatile int g_tls_busy = 0;   /* one TLS op (get OR post) at a time — they share the big static buffers */
int tls_get(const char *host, const char *path, uint8_t *out, int max, uint32_t seed) {
    uint64_t f = tls_irq_save();
    if (g_tls_busy) { tls_irq_restore(f); return -1; }   /* another TLS op in flight */
    g_tls_busy = 1; tls_irq_restore(f);
    int r = tls_get_inner(host, path, out, max, seed, "GET", 0, 0, 0, 0, 0);
    g_tls_busy = 0;
    return r;
}
/* HTTPS SSE first-event GET (M-eventsource): same path as tls_get, but stops reading
 * (and closes) after the first complete server-sent event, so a long-lived stream
 * doesn't block. Returns the raw HTTP response (headers + first event) length, <0 on error. */
int tls_get_sse(const char *host, const char *path, uint8_t *out, int max, uint32_t seed) {
    uint64_t f = tls_irq_save();
    if (g_tls_busy) { tls_irq_restore(f); return -1; }
    g_tls_busy = 1; tls_irq_restore(f);
    int r = tls_get_inner(host, path, out, max, seed, "GET", 0, 0, 0, 1, 0);
    g_tls_busy = 0;
    return r;
}
/* HTTPS POST (M702): same handshake/record path as tls_get; only the plaintext request
 * (POST + Content-Type/Length + body) differs. -1 on failure or if a TLS op is in flight. */
int tls_post(const char *host, const char *path, const char *ctype,
             const char *body, int bodylen, uint8_t *out, int max, uint32_t seed) {
    uint64_t f = tls_irq_save();
    if (g_tls_busy) { tls_irq_restore(f); return -1; }
    g_tls_busy = 1; tls_irq_restore(f);
    int r = tls_get_inner(host, path, out, max, seed, "POST", ctype, body, bodylen, 0, 0);
    g_tls_busy = 0;
    return r;
}

/* ---- wss:// persistent session (M1847) ----
 * Drives WebSocket-over-TLS for net.c's transport. tls_ws_open does the full
 * handshake (via tls_get_inner ws_mode) and leaves the session open in g_wss_T;
 * write/read carry the WebSocket frame bytes as TLS application data; close
 * sends close_notify + tears down TCP. Each op serializes with the shared record
 * scratch (read_enc's static buffer) via g_tls_busy so a concurrent HTTPS fetch
 * on another core can't reenter it. One session at a time (the JS pump is
 * single-threaded); a caller MUST pair a successful open with a close. */
int tls_ws_open(const char *host, uint32_t seed) {
    uint64_t f = tls_irq_save();
    if (g_tls_busy) { tls_irq_restore(f); return -1; }
    g_tls_busy = 1; tls_irq_restore(f);
    if (g_wss_open) { tcp_close(&g_wss_tcp); g_wss_open = 0; }   /* drop any stale session */
    int r = tls_get_inner(host, "/", 0, 0, seed, "GET", 0, 0, 0, 0, 1 /*ws_mode*/);
    g_tls_busy = 0;
    return r;                                    /* 0 => session live in g_wss_T */
}
int tls_ws_write(const uint8_t *data, int len) {
    if (!g_wss_open) return -1;
    uint64_t f = tls_irq_save();
    if (g_tls_busy) { tls_irq_restore(f); return -1; }
    g_tls_busy = 1; tls_irq_restore(f);
    int off = 0, rc = 0;
    while (off < len) {                          /* chunk into <=2000-B records (write_enc's pt[2048]) */
        int c = len - off; if (c > 2000) c = 2000;
        if (write_enc(&g_wss_T, REC_APP, data + off, c) != 0) { rc = -1; break; }
        off += c;
    }
    g_tls_busy = 0;
    return rc < 0 ? -1 : len;
}
int tls_ws_read(uint8_t *out, int max) {
    if (!g_wss_open) return -1;
    uint64_t f = tls_irq_save();
    if (g_tls_busy) { tls_irq_restore(f); return -1; }
    g_tls_busy = 1; tls_irq_restore(f);
    int n;
    for (;;) {                                   /* skip post-handshake NewSessionTicket (REC_HS) records */
        int inner;
        n = read_enc(&g_wss_T, &inner, out, max); /* one record's inner content, or -1 */
        if (n < 0) { n = -1; break; }            /* closed / alert / idle-timeout */
        if (inner == REC_HS) continue;           /* session tickets etc: not app data, keep reading */
        if (inner != REC_APP) { n = -1; break; }
        break;                                   /* got a WebSocket-carrying application-data record */
    }
    g_tls_busy = 0;
    return n;
}
void tls_ws_close(void) {
    if (!g_wss_open) return;
    uint64_t f = tls_irq_save();
    if (!g_tls_busy) {                           /* best-effort close_notify (skip if a TLS op is mid-flight) */
        g_tls_busy = 1; tls_irq_restore(f);
        if (g_wss_tcp.up) { uint8_t cn[2] = { 1, 0 }; write_enc(&g_wss_T, REC_ALERT, cn, 2); }
        g_tls_busy = 0;
    } else { tls_irq_restore(f); }
    tcp_close(&g_wss_tcp);
    g_wss_open = 0;
}
