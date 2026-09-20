/* lxdns — the SAME getaddrinfo() call Claude Code makes, several hundred times
 * in ten seconds, so the intermittent EAI_AGAIN can actually be sampled.
 *
 * Every DNS failure hunted since M2294 has been sampled through a `claude -p`
 * boot: twelve minutes of wall clock, an account's usage quota, and roughly
 * TEN lookups at the end of it. Eight boots of that is eighty samples and an
 * afternoon, which is why the failure rate is still only known to within a
 * factor of two -- and why one batch of four was once read as a verdict.
 *
 * The failure does not need Claude to reproduce it. It needs getaddrinfo, the
 * dynamic glibc path, and repetition. This does two hundred lookups per run at
 * a deliberately slow 50 ms cadence, and it is a strictly better instrument for
 * exactly one reason: when it fires, the packet capture is already running and
 * the failing lookup's index and wall time are printed next to it.
 *
 * THE CADENCE IS PART OF THE MEASUREMENT, not a politeness. A resolver that
 * rate-limits us drops replies, which is INDISTINGUISHABLE from the bug being
 * hunted -- so the request rate has to stay somewhere no public resolver could
 * plausibly object to. 20/s is that. Turning LXDNS_GAP down to chase more
 * samples per boot would manufacture the very failure it claims to count.
 *
 * Deliberately DYNAMIC (see the Makefile rule): a -static-pie binary cannot
 * dlopen libnss_dns.so.2 and would answer a question nobody asked. (M2320)
 *
 * ARGV: lxdns [threads] [lookups-per-thread] [gap-ms]. The thread count is the
 * whole point of the second arm (M2321). Two hundred lookups ONE AT A TIME came
 * back 200/200 clean, which rules out "the resolver path is a bit lossy" and
 * leaves the conditions of a Claude boot -- and the first of those to test is
 * that Claude resolves from a dozen threads at once while this probe resolved
 * from one. Running both arms in the SAME boot is the point: same kernel, same
 * network, same minute, one variable.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <resolv.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static int envint_(const char *k, int dflt);

static int argint(int argc, char **argv, int i, const char *k, int dflt) {
    if (argc > i && argv[i] && *argv[i]) { int n = atoi(argv[i]); if (n > 0) return n; }
    return envint_(k, dflt);
}

static int envint_(const char *k, int dflt) {
    const char *v = getenv(k);
    if (!v || !*v) return dflt;
    int n = atoi(v);
    return n > 0 ? n : dflt;
}

/* Several names, not one. If a single authoritative server is having a bad
 * minute, one name would report it as our bug -- and these five have no
 * infrastructure in common. api.anthropic.com is first because it is the name
 * that actually fails in the demo. */
static const char *NAMES[] = {
    "api.anthropic.com", "example.com", "cloudflare.com",
    "github.com", "wikipedia.org",
};
#define NNAMES ((int)(sizeof NAMES / sizeof NAMES[0]))

static int g_n, g_gap, g_threads;
static long g_t0;
static int  g_fails, g_oks;
static long g_worst, g_total;
static pthread_mutex_t g_lk = PTHREAD_MUTEX_INITIALIZER;

static void *sweep(void *arg) {
    long id = (long)arg;
    int n = g_n, gap = g_gap;
    long t0 = g_t0;
    int fails = 0, oks = 0;
    long worst = 0, total = 0;

    for (int i = 0; i < n; i++) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof hints);
        hints.ai_family   = AF_UNSPEC;       /* exactly what Node asks for */
        hints.ai_socktype = SOCK_STREAM;

        /* Offset by thread so the threads are not all asking the same
         * question at the same instant -- which would test one authoritative
         * server's tolerance for a thundering herd, not our stack. */
        const char *host = NAMES[(i + (int)id) % NNAMES];
        long a = now_ms();
        int rc = getaddrinfo(host, "443", &hints, &res);
        long ms = now_ms() - a;

        if (ms > worst) worst = ms;
        total += ms;

        if (rc != 0) {
            fails++;
            /* LOUD, and with everything needed to find it in a pcap: which
             * lookup, which name, how long it burned, and the wall time since
             * this probe started -- the capture is timestamped too. */
            printf("LXDNS-FAIL: t%ld #%d %s -> %d (%s) after %ld ms, t=%ld ms\n",
                   id, i, host, rc, gai_strerror(rc), ms, a - t0);
        } else {
            oks++;
            freeaddrinfo(res);
            if ((i % 25) == 0)
                printf("LXDNS: t%ld #%d %s ok in %ld ms\n", id, i, host, ms);
        }

        if (gap) {
            struct timespec s = { gap / 1000, (long)(gap % 1000) * 1000000L };
            nanosleep(&s, NULL);
        }
    }

    pthread_mutex_lock(&g_lk);
    g_fails += fails; g_oks += oks; g_total += total;
    if (worst > g_worst) g_worst = worst;
    pthread_mutex_unlock(&g_lk);
    return NULL;
}

int main(int argc, char **argv) {
    g_threads = argint(argc, argv, 1, "LXDNS_THREADS", 1);
    g_n       = argint(argc, argv, 2, "LXDNS_N", 200);
    g_gap     = argint(argc, argv, 3, "LXDNS_GAP", 50);
    g_t0      = now_ms();

    setvbuf(stdout, NULL, _IOLBF, 0);

    res_init();
    printf("LXDNS: %d thread(s) x %d lookups, %d ms apart, %d nameserver(s) from resolv.conf\n",
           g_threads, g_n, g_gap, _res.nscount);
    for (int i = 0; i < _res.nscount && i < 3; i++)
        printf("LXDNS:   nameserver[%d] = %s\n", i,
               inet_ntoa(_res.nsaddr_list[i].sin_addr));

    if (g_threads <= 1) {
        sweep((void *)0);
    } else {
        pthread_t th[64];
        int nt = g_threads > 64 ? 64 : g_threads;
        for (long i = 0; i < nt; i++)
            if (pthread_create(&th[i], NULL, sweep, (void *)i) != 0) {
                printf("LXDNS: pthread_create failed at %ld\n", i);
                nt = (int)i; break;
            }
        for (int i = 0; i < nt; i++) pthread_join(th[i], NULL);
    }

    {
        int tot = g_oks + g_fails;
        printf("LXDNS: %dx%d: %d ok, %d FAILED of %d (%d.%d%%), mean %ld ms, worst %ld ms, %ld ms total\n",
               g_threads, g_n, g_oks, g_fails, tot,
               tot ? (g_fails * 100) / tot : 0,
               tot ? ((g_fails * 1000) / tot) % 10 : 0,
               tot ? g_total / tot : 0, g_worst, now_ms() - g_t0);
    }
    /* A failure count is the POINT of this probe, so a non-zero exit would make
     * every harness treat a successful measurement as a broken run. Exit 0 on
     * any completed sweep; the count is in the line above. */
    return 0;
}
