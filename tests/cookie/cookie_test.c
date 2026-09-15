/* Cookie jar (M2029) -- host-side, ASan/UBSan.
 *
 * The browser had NO cookie support at all, so a session, a login, or a
 * bot-check clearance could never be carried. These assertions pin the rules
 * that make a cookie safe as well as useful: a site must not be able to set
 * one for a site it does not own, Secure must not leak over http, HttpOnly
 * must stay out of document.cookie, and a path must match on a boundary.
 */
#include <stdio.h>
#include "../../kernel/include/cookiejar.h"

static int fails;
static void ck(int cond, const char *what) {
    if (cond) printf("  ok: %s\n", what);
    else { printf("  FAIL: %s\n", what); fails++; }
}

int main(void) {
    cj_jar J; cj_clear(&J);
    char buf[2048];
    const unsigned long long T0 = 1000000ull;

    /* --- the basic round trip --- */
    cj_set(&J, "example.com", "/", "sid=abc123; Path=/", T0);
    ck(cj_header(&J, "example.com", "/", 0, 1, T0, buf, sizeof buf) > 0 &&
       buf[0] == 's' && buf[4] == 'a', "a cookie set on a response comes back on the next request");

    /* --- a site must not set a cookie for somebody else --- */
    ck(cj_set(&J, "evil.test", "/", "x=1; Domain=example.com", T0) == 0,
       "a host cannot set a cookie for a domain it is not under");
    ck(cj_set(&J, "example.com", "/", "y=1; Domain=com", T0) == 0,
       "a single-label Domain is refused (no public-suffix table needed to say no)");
    ck(cj_set(&J, "a.example.com", "/", "z=9; Domain=example.com", T0) == 1,
       "...but a subdomain CAN set one for its parent domain");

    /* --- and must not be handed to a look-alike --- */
    ck(cj_domain_match("notexample.com", "example.com") == 0,
       "domain matching is on a label boundary, not a substring");
    ck(cj_domain_match("a.example.com", "example.com") == 1, "a real subdomain does match");

    /* --- Secure must not leak over plain http --- */
    cj_clear(&J);
    cj_set(&J, "example.com", "/", "tok=s3cret; Secure", T0);
    ck(cj_header(&J, "example.com", "/", 0, 1, T0, buf, sizeof buf) == 0,
       "a Secure cookie is NOT sent over http");
    ck(cj_header(&J, "example.com", "/", 1, 1, T0, buf, sizeof buf) > 0,
       "...and IS sent over https");

    /* --- HttpOnly is hidden from scripts --- */
    cj_clear(&J);
    cj_set(&J, "example.com", "/", "sess=1; HttpOnly", T0);
    ck(cj_header(&J, "example.com", "/", 1, 1, T0, buf, sizeof buf) > 0,
       "an HttpOnly cookie is sent on requests");
    ck(cj_header(&J, "example.com", "/", 1, 0, T0, buf, sizeof buf) == 0,
       "...but is invisible to document.cookie");

    /* --- path scoping --- */
    cj_clear(&J);
    cj_set(&J, "example.com", "/", "p=1; Path=/admin", T0);
    ck(cj_header(&J, "example.com", "/admin/x", 1, 1, T0, buf, sizeof buf) > 0, "path prefix matches");
    ck(cj_header(&J, "example.com", "/other", 1, 1, T0, buf, sizeof buf) == 0, "a different path does not");
    ck(cj_path_match("/administrator", "/admin") == 0,
       "a path matches on a / boundary, not a raw prefix");

    /* --- expiry, and deletion by Max-Age=0 --- */
    cj_clear(&J);
    cj_set(&J, "example.com", "/", "e=1; Max-Age=10", T0);
    ck(cj_header(&J, "example.com", "/", 1, 1, T0 + 5000, buf, sizeof buf) > 0, "a live cookie is sent");
    ck(cj_header(&J, "example.com", "/", 1, 1, T0 + 20000, buf, sizeof buf) == 0,
       "...and an expired one is dropped, not sent");
    cj_set(&J, "example.com", "/", "d=1", T0);
    cj_set(&J, "example.com", "/", "d=1; Max-Age=0", T0);
    ck(cj_header(&J, "example.com", "/", 1, 1, T0, buf, sizeof buf) == 0,
       "Max-Age=0 deletes the cookie");

    /* --- replacement, not duplication --- */
    cj_clear(&J);
    cj_set(&J, "example.com", "/", "k=old", T0);
    cj_set(&J, "example.com", "/", "k=new", T0);
    int n = cj_header(&J, "example.com", "/", 1, 1, T0, buf, sizeof buf);
    ck(n == 5 && buf[2] == 'n', "setting the same name replaces it rather than sending both");

    /* --- harvesting a real response, several headers at once --- */
    cj_clear(&J);
    const char *resp =
        "HTTP/1.1 302 Found\r\n"
        "Set-Cookie: clearance=xyz; Path=/; Secure\r\n"
        "Set-Cookie: other=2; Path=/\r\n"
        "Location: /\r\n\r\n<html>";
    int h = cj_harvest(&J, "example.com", "/", resp, (int)sizeof("HTTP/1.1 302 Found\r\nSet-Cookie: clearance=xyz; Path=/; Secure\r\nSet-Cookie: other=2; Path=/\r\nLocation: /\r\n\r\n<html>") - 1, T0);
    ck(h == 2, "both Set-Cookie headers of one response are harvested");
    n = cj_header(&J, "example.com", "/", 1, 1, T0, buf, sizeof buf);
    ck(n > 0, "and the harvested pair is sent back -- the redirect-with-clearance flow");

    /* --- a malformed header must not be stored, and must not crash --- */
    ck(cj_set(&J, "example.com", "/", "novalue", T0) == 0, "a header with no '=' is ignored");
    ck(cj_set(&J, "example.com", "/", "", T0) == 0, "an empty header is ignored");

    if (fails) { printf("cookietest: %d FAILED\n", fails); return 1; }
    printf("cookietest: all assertions passed\n");
    return 0;
}
