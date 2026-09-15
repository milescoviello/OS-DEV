/* cookiejar.h -- HTTP cookies (M2029).
 *
 * The browser had NO cookie support of any kind: nothing parsed Set-Cookie,
 * nothing ever sent a Cookie header. That is not a missing convenience, it is
 * the reason a whole class of page could never work. A session is a cookie; a
 * login is a cookie; a bot-check hands you a clearance cookie and redirects you
 * back, and without one you are handed the challenge again forever. Every such
 * page looked like it "loaded" and then refused to go anywhere.
 *
 * Pure logic, no kernel dependencies -- the current time arrives as an
 * argument -- so the host suite can drive it directly (`make cookietest`).
 * Same shape as layout.h and shexpand.h.
 *
 * Deliberately NOT implemented: the public-suffix list. Without it, a domain
 * attribute of ".co.uk" would be accepted as a match for every site under it.
 * Instead a Domain attribute must be a suffix of the request host AND contain
 * at least one interior dot, which blocks the single-label case ("Domain=com")
 * without pretending to a table we do not ship.
 */
#ifndef COOKIEJAR_H
#define COOKIEJAR_H

#define CJ_N        64      /* cookies retained across all hosts */
#define CJ_NAME     64
#define CJ_VAL     512      /* challenge/session tokens are long */
#define CJ_DOM      96
#define CJ_PATH     96

typedef struct {
    int      used;
    char     dom[CJ_DOM];     /* stored WITHOUT a leading dot */
    char     path[CJ_PATH];
    char     name[CJ_NAME];
    char     val[CJ_VAL];
    int      secure;          /* only send over https */
    int      hostonly;        /* no Domain attribute -> exact host match only */
    int      httponly;        /* hidden from document.cookie */
    unsigned long long expires_ms;   /* 0 = session cookie (never expires in-run) */
} cj_cookie;

typedef struct { cj_cookie c[CJ_N]; } cj_jar;

static inline int cj_lower(int ch) { return (ch >= 'A' && ch <= 'Z') ? ch + 32 : ch; }
static inline int cj_ieq(const char *a, const char *b) {
    while (*a && *b) { if (cj_lower(*a) != cj_lower(*b)) return 0; a++; b++; }
    return *a == 0 && *b == 0;
}
static inline int cj_len(const char *s) { int n = 0; while (s[n]) n++; return n; }
static inline void cj_cpy(char *d, const char *s, int max) {
    int i = 0; while (s[i] && i < max - 1) { d[i] = s[i]; i++; } d[i] = 0;
}
/* case-insensitive "does `host` end with `dom`, on a label boundary?" */
static inline int cj_domain_match(const char *host, const char *dom) {
    int hn = cj_len(host), dn = cj_len(dom);
    if (dn == 0 || dn > hn) return 0;
    for (int i = 0; i < dn; i++)
        if (cj_lower(host[hn - dn + i]) != cj_lower(dom[i])) return 0;
    if (hn == dn) return 1;
    return host[hn - dn - 1] == '.';          /* a boundary, not "evilexample.com" */
}
/* RFC 6265 path match: equal, or a prefix ending at a '/' boundary. */
static inline int cj_path_match(const char *path, const char *cpath) {
    int pn = cj_len(path), cn = cj_len(cpath);
    if (cn == 0) return 1;
    if (cn > pn) return 0;
    for (int i = 0; i < cn; i++) if (path[i] != cpath[i]) return 0;
    if (pn == cn) return 1;
    return cpath[cn - 1] == '/' || path[cn] == '/';
}
static inline int cj_interior_dot(const char *d) {      /* "example.com" yes, "com" no */
    int seen = 0;
    for (int i = 0; d[i]; i++) if (d[i] == '.' && i > 0 && d[i+1]) seen = 1;
    return seen;
}

static inline void cj_clear(cj_jar *j) { for (int i = 0; i < CJ_N; i++) j->c[i].used = 0; }

/* Store one Set-Cookie header VALUE (everything after "Set-Cookie:").
 * `host` and `path` are the request's, used for the defaults. Returns 1 if a
 * cookie was stored (or replaced), 0 if the header was unusable. */
static inline int cj_set(cj_jar *j, const char *host, const char *reqpath,
                         const char *hdr, unsigned long long now_ms) {
    while (*hdr == ' ' || *hdr == '\t') hdr++;
    char name[CJ_NAME], val[CJ_VAL];
    int n = 0;
    while (*hdr && *hdr != '=' && *hdr != ';' && n < CJ_NAME - 1) name[n++] = *hdr++;
    while (n > 0 && (name[n-1] == ' ' || name[n-1] == '\t')) n--;
    name[n] = 0;
    if (*hdr != '=' || !name[0]) return 0;                   /* no name=value -> ignore */
    hdr++;
    int v = 0;
    while (*hdr && *hdr != ';' && *hdr != '\r' && *hdr != '\n' && v < CJ_VAL - 1) val[v++] = *hdr++;
    while (v > 0 && (val[v-1] == ' ' || val[v-1] == '\t')) v--;
    val[v] = 0;

    char dom[CJ_DOM]; dom[0] = 0;
    char path[CJ_PATH]; path[0] = 0;
    int secure = 0, httponly = 0, hostonly = 1;
    unsigned long long expires = 0;
    int have_maxage = 0; long maxage = 0;

    while (*hdr == ';') {
        hdr++;
        while (*hdr == ' ' || *hdr == '\t') hdr++;
        char key[24]; int k = 0;
        while (*hdr && *hdr != '=' && *hdr != ';' && *hdr != '\r' && *hdr != '\n' && k < 23) key[k++] = *hdr++;
        while (k > 0 && (key[k-1] == ' ' || key[k-1] == '\t')) k--;
        key[k] = 0;
        char av[CJ_VAL]; int a = 0; av[0] = 0;
        if (*hdr == '=') {
            hdr++;
            while (*hdr == ' ' || *hdr == '\t') hdr++;
            while (*hdr && *hdr != ';' && *hdr != '\r' && *hdr != '\n' && a < CJ_VAL - 1) av[a++] = *hdr++;
            while (a > 0 && (av[a-1] == ' ' || av[a-1] == '\t')) a--;
            av[a] = 0;
        }
        if      (cj_ieq(key, "Secure"))   secure = 1;
        else if (cj_ieq(key, "HttpOnly")) httponly = 1;
        else if (cj_ieq(key, "Path"))     cj_cpy(path, av, CJ_PATH);
        else if (cj_ieq(key, "Domain")) {
            const char *d = av; if (*d == '.') d++;          /* a leading dot is legacy; strip it */
            if (d[0]) { cj_cpy(dom, d, CJ_DOM); hostonly = 0; }
        } else if (cj_ieq(key, "Max-Age")) {
            long m = 0; int i = 0, neg = 0;
            if (av[0] == '-') { neg = 1; i = 1; }
            for (; av[i] >= '0' && av[i] <= '9'; i++) m = m * 10 + (av[i] - '0');
            maxage = neg ? -m : m; have_maxage = 1;
        } else if (cj_ieq(key, "Expires")) {
            /* Not parsed as a date: treated as "persistent for this run", which
             * is the useful half. A DELETION uses Max-Age=0 or a past date; the
             * Max-Age form is handled exactly, and the date form is the reason
             * this is not claimed to be complete. */
            if (!have_maxage) expires = 0;
        }
        while (*hdr == ' ' || *hdr == '\t') hdr++;
    }
    if (have_maxage) {
        if (maxage <= 0) {                                   /* an explicit delete */
            for (int i = 0; i < CJ_N; i++)
                if (j->c[i].used && cj_ieq(j->c[i].name, name) &&
                    cj_ieq(j->c[i].dom, dom[0] ? dom : host)) j->c[i].used = 0;
            return 1;
        }
        expires = now_ms + (unsigned long long)maxage * 1000ull;
    }
    if (dom[0]) {
        /* Refuse a Domain the request host is not under, and refuse a
         * single-label one ("Domain=com") -- see the header comment. */
        if (!cj_domain_match(host, dom) || !cj_interior_dot(dom)) return 0;
    } else {
        cj_cpy(dom, host, CJ_DOM);
    }
    if (!path[0]) {                                          /* default: the request's directory */
        int last = 0;
        for (int i = 0; reqpath[i]; i++) if (reqpath[i] == '/') last = i;
        int i = 0; for (; i <= last && i < CJ_PATH - 1; i++) path[i] = reqpath[i];
        path[i] = 0;
        if (!path[0]) cj_cpy(path, "/", CJ_PATH);
    }
    int slot = -1;
    for (int i = 0; i < CJ_N; i++)                           /* replace same (name,dom,path) */
        if (j->c[i].used && cj_ieq(j->c[i].name, name) &&
            cj_ieq(j->c[i].dom, dom) && cj_ieq(j->c[i].path, path)) { slot = i; break; }
    if (slot < 0) for (int i = 0; i < CJ_N; i++) if (!j->c[i].used) { slot = i; break; }
    if (slot < 0) {                                          /* full: drop the soonest to expire */
        slot = 0;
        for (int i = 1; i < CJ_N; i++)
            if (j->c[i].expires_ms && (!j->c[slot].expires_ms || j->c[i].expires_ms < j->c[slot].expires_ms)) slot = i;
    }
    cj_cookie *c = &j->c[slot];
    c->used = 1; c->secure = secure; c->httponly = httponly; c->hostonly = hostonly;
    c->expires_ms = expires;
    cj_cpy(c->dom, dom, CJ_DOM); cj_cpy(c->path, path, CJ_PATH);
    cj_cpy(c->name, name, CJ_NAME); cj_cpy(c->val, val, CJ_VAL);
    return 1;
}

/* Build the "a=1; b=2" value for a request. Returns the length written (0 if
 * nothing matches, in which case NO Cookie header should be sent).
 * `want_httponly` = 0 builds the document.cookie view instead. */
static inline int cj_header(cj_jar *j, const char *host, const char *path, int secure,
                            int want_httponly, unsigned long long now_ms, char *out, int max) {
    int p = 0;
    for (int i = 0; i < CJ_N; i++) {
        cj_cookie *c = &j->c[i];
        if (!c->used) continue;
        if (c->expires_ms && c->expires_ms <= now_ms) { c->used = 0; continue; }
        if (c->secure && !secure) continue;
        if (c->httponly && !want_httponly) continue;
        if (c->hostonly ? !cj_ieq(host, c->dom) : !cj_domain_match(host, c->dom)) continue;
        if (!cj_path_match(path, c->path)) continue;
        int need = cj_len(c->name) + 1 + cj_len(c->val) + (p ? 2 : 0);
        if (p + need >= max) break;
        if (p) { out[p++] = ';'; out[p++] = ' '; }
        for (int k = 0; c->name[k]; k++) out[p++] = c->name[k];
        out[p++] = '=';
        for (int k = 0; c->val[k]; k++) out[p++] = c->val[k];
    }
    out[p] = 0;
    return p;
}

/* Harvest every Set-Cookie from a raw HTTP response (headers + body). */
static inline int cj_harvest(cj_jar *j, const char *host, const char *reqpath,
                             const char *resp, int len, unsigned long long now_ms) {
    int got = 0;
    for (int i = 0; i + 11 < len; i++) {
        if (i && resp[i-1] != '\n') continue;                /* only at a header line start */
        const char *k = "set-cookie:";
        int m = 1;
        for (int q = 0; q < 11; q++) if (cj_lower(resp[i+q]) != k[q]) { m = 0; break; }
        if (!m) continue;
        char line[CJ_VAL + 256]; int p = 0;
        int q = i + 11;
        while (q < len && resp[q] != '\r' && resp[q] != '\n' && p < (int)sizeof(line) - 1) line[p++] = resp[q++];
        line[p] = 0;
        if (cj_set(j, host, reqpath, line, now_ms)) got++;
        /* stop at the end of the header block */
        if (q + 3 < len && resp[q] == '\r' && resp[q+1] == '\n' && resp[q+2] == '\r') break;
    }
    return got;
}
#endif
