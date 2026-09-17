/* lxgai — does GLIBC's getaddrinfo() work inside OS-DEV?
 *
 * lxinet already proves DNS over UDP works, but it builds the query itself and
 * is linked -static-pie, so its getaddrinfo cannot dlopen an NSS module and
 * would answer a question nobody asked. Node and Claude Code use the DYNAMIC
 * glibc path: nsswitch.conf -> dlopen libnss_dns.so.2 -> read resolv.conf ->
 * send the query. Both report failure as "check your internet or DNS
 * (EAI_AGAIN)", which names neither the step that failed nor the reason.
 *
 * So this is deliberately dynamically linked, and it reports each step
 * separately, because the whole point is to find out WHICH one stops. (M2128)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <resolv.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

static void show_file(const char *p) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) { printf("LXGAI: %s -> CANNOT OPEN (errno %d)\n", p, errno); return; }
    char b[256]; ssize_t n = read(fd, b, sizeof b - 1);
    close(fd);
    if (n <= 0) { printf("LXGAI: %s -> opens but reads %zd\n", p, n); return; }
    b[n] = 0;
    for (char *q = b; *q; q++) if (*q == '\n') *q = '|';
    printf("LXGAI: %s -> %s\n", p, b);
}

int main(void) {
    int fails = 0;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("LXGAI: start (dynamically linked, so this is the path Node uses)\n");

    show_file("/etc/resolv.conf");
    show_file("/etc/nsswitch.conf");

    /* Is a netlink socket available? glibc's __check_pf() wants one to decide
     * which address families this host has. It is documented to fall back when
     * it cannot get one -- this prints whether the fallback is even reached. */
    int nl = socket(16 /*AF_NETLINK*/, SOCK_RAW, 0 /*NETLINK_ROUTE*/);
    printf("LXGAI: AF_NETLINK socket -> %d%s\n", nl, nl < 0 ? " (glibc must fall back)" : "");
    if (nl >= 0) close(nl);

    /* A plain UDP socket, for contrast: if this fails too, it is not netlink. */
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    printf("LXGAI: AF_INET SOCK_DGRAM socket -> %d\n", u);
    if (u >= 0) close(u);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;         /* exactly what Node asks for */
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo("example.com", "80", &hints, &res);
    if (rc != 0) {
        printf("LXGAI-FAIL: getaddrinfo(AF_UNSPEC) -> %d (%s)\n", rc, gai_strerror(rc));
        fails++;
    } else {
        for (struct addrinfo *p = res; p; p = p->ai_next) {
            char t[64] = "?";
            if (p->ai_family == AF_INET)
                inet_ntop(AF_INET, &((struct sockaddr_in *)p->ai_addr)->sin_addr, t, sizeof t);
            else if (p->ai_family == AF_INET6)
                inet_ntop(AF_INET6, &((struct sockaddr_in6 *)p->ai_addr)->sin6_addr, t, sizeof t);
            printf("LXGAI-OK: getaddrinfo(AF_UNSPEC) -> %s\n", t);
        }
        freeaddrinfo(res);
    }

    /* AF_INET only: this skips glibc's "which families does this host have"
     * question entirely, so it separates __check_pf from the resolver. */
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    res = NULL;
    rc = getaddrinfo("example.com", "80", &hints, &res);
    if (rc != 0) {
        printf("LXGAI-FAIL: getaddrinfo(AF_INET) -> %d (%s)\n", rc, gai_strerror(rc));
        fails++;
    } else {
        char t[64] = "?";
        inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, t, sizeof t);
        printf("LXGAI-OK: getaddrinfo(AF_INET) -> %s\n", t);
        freeaddrinfo(res);
    }

    /* AND THE RESOLVER ON ITS OWN, BELOW NSS ENTIRELY (M2128). getaddrinfo
     * failing tells you the lookup failed; it cannot tell you whether the NSS
     * layer never reached the `dns` source or the resolver reached it and could
     * not send. res_init + res_query answer exactly that: nscount is what glibc
     * parsed out of our /etc/resolv.conf, and res_query goes straight to the
     * wire with no nsswitch.conf in the path. */
    if (res_init() != 0) printf("LXGAI-FAIL: res_init() failed\n"), fails++;
    printf("LXGAI: res_init -> %d nameserver(s)\n", _res.nscount);
    for (int i = 0; i < _res.nscount && i < 3; i++)
        printf("LXGAI:   nameserver[%d] = %s:%u\n", i,
               inet_ntoa(_res.nsaddr_list[i].sin_addr),
               (unsigned)ntohs(_res.nsaddr_list[i].sin_port));
    {
        unsigned char ans[1024];
        int n = res_query("example.com", 1 /*C_IN*/, 1 /*T_A*/, ans, sizeof ans);
        if (n < 0) { printf("LXGAI-FAIL: res_query -> %d, h_errno %d\n", n, h_errno); fails++; }
        else       { printf("LXGAI-OK: res_query -> %d bytes of DNS answer\n", n); }
    }

    /* And gethostbyname, the older path, in case they diverge. */
    struct hostent *he = gethostbyname("example.com");
    if (!he) { printf("LXGAI-FAIL: gethostbyname -> h_errno %d\n", h_errno); fails++; }
    else {
        char t[64] = "?";
        inet_ntop(AF_INET, he->h_addr_list[0], t, sizeof t);
        printf("LXGAI-OK: gethostbyname -> %s\n", t);
    }

    printf("LXGAI: %d failure(s)\n", fails);
    return fails ? 3 : 0;
}
