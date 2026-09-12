/*
 * shell.c — a tiny interactive shell, running entirely in ring 3.
 *
 * It loops: print a prompt, read a line via SYS_read, and match it against a
 * few built-in commands. Everything it does — printing, reading input, exiting
 * — is a system call into the kernel. This is a real (if minimal) userspace
 * program talking to our OS exactly the way `sh` talks to Linux.
 */
#include "ulib.h"
#include "bpf.h"      /* struct bpf_insn + opcodes, for the seccomptest filter program (M1190) */
#include "shgrep.h"   /* gr_match(): the grep regex matcher (^ $ . * [..] \), host-tested by tests/shgrep */
#include "shsed.h"    /* sed_sub(): the `sed s/RE/REPL/` substitution engine, host-tested by tests/shsed */
#include "shmath.h"   /* sh_eval(): the $((expr)) integer evaluator, host-tested by tests/shmath */
#include "shsplit.h"  /* sh_next_sep(): the ';' statement splitter (construct-aware), host-tested by tests/shsplit */
#include "shbrace.h"  /* expand_braces(): {a,b}/{1..N} brace expansion, host-tested by tests/shbrace */
#include "shquote.h"  /* sh_quote_pass()/sh_unprot_buf(): "..." '...' quoting, host-tested by tests/shquote */
#include "shtest.h"   /* sh_test_eval(): the test / [ ] conditional evaluator, host-tested by tests/shtest */
#include "lsfmt.h"    /* ls_mode_str()/ls_fmt_time(): `ls -l` formatting, host-tested by tests/lsfmt */
#include "shsort.h"   /* sort_numval()/sort_field()/sort_foldeq(): `sort` key helpers, host-tested by tests/shsort */
#include "shtxt.h"    /* tr_expand()/cut_sel(): `tr`/`cut` text helpers, host-tested by tests/shtxt */
#include "patchcore.h" /* patch_apply(): apply a unified-diff patch (the `patch` builtin), host-tested by tests/diff */

static void perr(const char *s);   /* print an error label in red (defined below); forward-declared for early use (M1379) */

static void jobtest_sigint(int s) { (void)s; sys_exit(42); }   /* job-control demo: a group SIGINT exits the child 42 (M1176) */
static volatile int g_jctid;                                   /* set_tid_address join target (M1226) */
static void join_thread_fn(void *arg) {                        /* registers clear_child_tid, lives a moment, exits */
    (void)arg;
    sys_set_tid_address((void *)&g_jctid);
    for (volatile long i = 0; i < 30000000; i++) {}            /* stay alive so the joiner blocks first */
    sys_thread_exit();
}
static volatile int g_ftx_word;                                /* futextimeouttest's wake-before-deadline case (M1578) */
static void ftx_wake_thread_fn(void *arg) {                     /* sleeps briefly, then FUTEX_WAKEs g_ftx_word */
    (void)arg;
    sys_sleep(150);
    sys_futex((void *)&g_ftx_word, FUTEX_WAKE, 1, -1);
    sys_thread_exit();
}
static volatile int g_evfd_shared;                              /* eventfdblocktest's fd, shared with its clone thread (M1579) */
static void evfd_wake_thread_fn(void *arg) {                     /* sleeps briefly, then posts 7 to g_evfd_shared */
    (void)arg;
    sys_sleep(150);
    unsigned char w[8]; for (int i = 0; i < 8; i++) w[i] = (i == 0) ? 7 : 0;
    sys_fdwrite(g_evfd_shared, w, 8);
    sys_thread_exit();
}
static volatile int g_mq_shared;                                /* mqtest's mq_unlink wake case, shared with its clone thread (M1593) */
static volatile long g_mq_recv_result;
static void mq_unlink_wait_thread_fn(void *arg) {                 /* blocks in mq_receive on an empty queue */
    (void)arg;
    char b[8];
    g_mq_recv_result = sys_mq_receive(g_mq_shared, b, sizeof b, 0);
    sys_thread_exit();
}

static void itoa_simple(int v, char *out) {
    char tmp[12];
    int i = 0, neg = (v < 0);
    unsigned uv = neg ? (unsigned)(-(long)v) : (unsigned)v;   /* via long so INT_MIN is safe */
    if (uv == 0) tmp[i++] = '0';
    while (uv) { tmp[i++] = (char)('0' + uv % 10); uv /= 10; }
    int j = 0;
    if (neg) out[j++] = '-';
    while (i > 0) out[j++] = tmp[--i];
    out[j] = '\0';
}

/* long-width sibling of itoa_simple: sh_eval returns a long, and (( )) results
 * commonly exceed 2^31 (a byte count, a timestamp, an accumulated loop total) --
 * callers that formatted via itoa_simple((int)v, ...) silently wrapped those.
 * Same via-unsigned-long idiom expand_vars' $((...)) formatting already uses. */
static void ltoa_simple(long v, char *out) {
    char tmp[24];
    int i = 0, neg = (v < 0);
    unsigned long uv = neg ? (unsigned long)(-v) : (unsigned long)v;
    if (uv == 0) tmp[i++] = '0';
    while (uv) { tmp[i++] = (char)('0' + uv % 10); uv /= 10; }
    int j = 0;
    if (neg) out[j++] = '-';
    while (i > 0) out[j++] = tmp[--i];
    out[j] = '\0';
}

/* Unsigned -> base-2..16 string (for printf %x/%X/%o/%u). */
static void utoa_base(unsigned long v, int base, int upper, char *out) {
    const char *digs = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char tmp[24]; int i = 0;
    if (v == 0) tmp[i++] = '0';
    while (v) { tmp[i++] = digs[v % (unsigned)base]; v /= (unsigned)base; }
    int j = 0;
    while (i > 0) out[j++] = tmp[--i];
    out[j] = '\0';
}

/* Exit status of the last command (0 = success), exposed as $? and consumed by
 * the && / || operators. run_command resets it to 0 on entry; failure paths
 * (command-not-found, a missing file via slurp(), cd/mkdir failure, `false`)
 * set it to 1. */
static int g_status;
static int g_returning;     /* set by `return` (in a function/sourced script); honored by the body executors, cleared at the boundary */
static int g_loopbrk;       /* 0=none, 1=break, 2=continue: set by break/continue, consumed by the innermost for/while */
static int g_loopdepth;     /* for/while loops currently running; break/continue only fire when >0 (else they're no-ops) */
static int g_xtrace;        /* `set -x`: print each command as `+ cmd` before running it (M1808) */
static int g_errexit;       /* `set -e`: abort the running script when a command fails (M1809) */
static int g_errexit_tripped; /* latch: a command failed under -e; unwinds the script like g_returning, cleared at the source/prompt boundary */
static int g_cond_depth;    /* >0 while evaluating an if/while/until condition or a &&/|| left side, where -e must NOT fire */
/* `while read LINE; do …; done < FILE` (M1811): the loop slurps FILE into this
 * source and the `read` builtin drains it a line at a time, returning EOF ($?=1)
 * so the loop terminates. g_reading nests (a loop inside a loop restores it). */
static char *g_read_src; static long g_read_pos, g_read_len; static int g_reading;
/* Copy the next line (without its '\n') from the read source into out[0..cap);
 * returns 1 if a line was available, 0 at EOF. */
static int sh_read_next(char *out, int cap) {
    if (!g_reading || g_read_pos >= g_read_len) return 0;
    int o = 0;
    while (g_read_pos < g_read_len && g_read_src[g_read_pos] != '\n') {
        if (o < cap - 1) out[o++] = g_read_src[g_read_pos];
        g_read_pos++;
    }
    if (g_read_pos < g_read_len && g_read_src[g_read_pos] == '\n') g_read_pos++;   /* consume the newline */
    out[o] = 0;
    return 1;
}
static int source_depth;   /* recursion guard for `source` (scripts sourcing scripts) */
static char prevcwd[128];  /* the directory before the last cd, for `cd -` */
static void scpy(char *d, const char *s) { int i = 0; while (s[i] && i < 127) { d[i] = s[i]; i++; } d[i] = 0; }

#include "normpath.h"   /* normpath(): cd's . / .. / // path resolver, host-tested by tests/normpath */
static int nargs(const char *s) { int n = 0; while (*s) { while (*s == ' ') s++; if (!*s) break; n++; while (*s && *s != ' ') s++; } return n; }

/* Find a line "key <num>" in buf (key at offset 0 or right after a '\n') and
 * return the decimal num, or -1 if the key isn't present. Used by statcputest
 * to parse /proc/stat's keyed lines (M1253). */
static long sh_kvnum(const char *buf, const char *key) {
    for (int i = 0; buf[i]; i++) {
        if (i != 0 && buf[i - 1] != '\n') continue;
        int k = 0; while (key[k] && buf[i + k] == key[k]) k++;
        if (key[k] != 0 || buf[i + k] != ' ') continue;       /* full key match + a space */
        int j = i + k; while (buf[j] == ' ') j++;
        long v = 0; int any = 0;
        while (buf[j] >= '0' && buf[j] <= '9') { v = v * 10 + (buf[j] - '0'); j++; any = 1; }
        return any ? v : -1;
    }
    return -1;
}

/* SA_SIGINFO demo handler (M1270): a 3-arg handler that inspects the siginfo
 * and the interrupted register file (ucontext) — the form JIT/GC code uses to
 * read a fault's si_addr + the saved PC. */
static volatile int g_si_caught, g_si_signo;
static volatile unsigned long g_si_rip;
static void si_handler(int signo, struct ksiginfo *si, struct kmcontext *uc) {
    (void)signo;
    g_si_caught = 1;
    g_si_signo = si ? si->si_signo : -1;
    g_si_rip = uc ? uc->rip : 0;     /* observe the interrupted PC from the ucontext */
}

/* RT signals / sigqueue (M1271): record each delivered si_value + si_code in
 * arrival order, so the test can prove queued payloads arrive FIFO and that
 * multiple instances of one signal do NOT coalesce (unlike standard signals). */
static volatile int g_rt_n, g_rt_code;
static volatile unsigned long g_rt_vals[8];
static void rt_handler(int signo, struct ksiginfo *si, struct kmcontext *uc) {
    (void)signo; (void)uc;
    if (si && g_rt_n < 8) { g_rt_vals[g_rt_n] = si->si_value; g_rt_code = si->si_code; g_rt_n++; }
}

/* POSIX timer_create (M1272): count fires + capture the delivered payload + si_code. */
static volatile int g_tmr_n, g_tmr_code;
static volatile unsigned long g_tmr_val;
static void tmr_handler(int signo, struct ksiginfo *si, struct kmcontext *uc) {
    (void)signo; (void)uc;
    g_tmr_n++;
    if (si) { g_tmr_val = si->si_value; g_tmr_code = si->si_code; }
}

/* sigaltstack (M1276): the handler checks whether its OWN stack pointer (the
 * address of a local) lies inside the registered alternate-stack region. */
static volatile unsigned long g_alt_lo, g_alt_hi;
static volatile int g_alt_on;
static void alt_handler(int signo, struct ksiginfo *si, struct kmcontext *uc) {
    (void)signo; (void)si; (void)uc;
    char probe;                                  /* a local -> its address is on the handler's current stack */
    unsigned long sp = (unsigned long)&probe;
    g_alt_on = (sp >= g_alt_lo && sp < g_alt_hi) ? 1 : 0;
}

/* SIGWINCH on terminal resize (M1279). */
static volatile int g_winch;
static void winch_handler(int s) { (void)s; g_winch = 1; }

/* Forward decls: `source` and `for` run lines/bodies back through the executor.
 * Defined far below, after run_line. run_input_line handles one logical line
 * (a `for ...; do ...; done` loop, else a ';'-split list of && / || commands). */
static int run_andor(char *seg, char *cwd);
static int run_input_line(char *line, char *cwd);
static int run_for(char *line, char *cwd);
static int run_case(char *line, char *cwd);
static long sh_do_assign(const char *e);   /* (( expr )) / C-style-for assignment; defined below */
static int run_while(char *line, char *cwd);
static int run_until(char *line, char *cwd);
static void source_file(const char *fn, char *cwd, int silent);   /* run shell commands from a file */

/* Read an entire file into a malloc'd, NUL-terminated buffer (caller free()s).
 * The read API has no size query, so grow the buffer until the read no longer
 * fills it — commands then see the whole file, not a fixed 2KB prefix. *len gets
 * the length; returns 0 on missing file / >=32MB / OOM. */
static int hexval(char c) {     /* a hex digit's value, or -1 */
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* SIGALRM demo (M1102): the handler just counts fires (touches only this global,
 * so running it on the shell's stack mid-loop is harmless). */
static volatile int g_alarm_fires;
static void sh_alarm_handler(int sig) { (void)sig; g_alarm_fires++; }
/* SIGXCPU demo (M1548): RLIMIT_CPU fires this once the process's own CPU time
 * crosses the limit; like every signal here, delivery is opt-in (see
 * app_cpulimit_tick) so a test process must install a handler to observe it. */
static volatile int g_xcpu_fired;
static void sh_xcpu_handler(int sig) { (void)sig; g_xcpu_fired = 1; }
/* SIGXFSZ demo (M1549): RLIMIT_FSIZE fires this when a write would grow a
 * file past the limit; same opt-in delivery model as every signal here. */
static volatile int g_xfsz_fired;
static void sh_xfsz_handler(int sig) { (void)sig; g_xfsz_fired = 1; }
/* sigsuspend demo (M1561): confirms the handler actually ran DURING the
 * suspend (not merely that pending_sigs got set) -- this flag only flips
 * from inside the SIGUSR1 handler itself. */
static volatile int g_sigsuspend_fired;
static void sh_sigsuspend_handler(int sig) { (void)sig; g_sigsuspend_fired = 1; }
static volatile int g_sigpipe_fired;                                          /* (M1581) */
static void sh_sigpipe_handler(int sig) { (void)sig; g_sigpipe_fired = 1; }
/* SIGCHLD (M1562): fires on a live parent when a child exits, now that
 * app_reap actually requests it (previously just a waitid siginfo label). */
static volatile int g_sigchld_fired;
static void sh_sigchld_handler(int sig) { (void)sig; g_sigchld_fired = 1; }
/* PR_SET_PDEATHSIG (M1562): fires on a live child when ITS parent dies. */
static volatile int g_pdeathsig_fired;
static void sh_pdeathsig_handler(int sig) { (void)sig; g_pdeathsig_fired = 1; }
static char *slurp(const char *name, long *len) {
    sh_unprot_buf((char *)name);          /* a quoted filename ("my file") arrives with bit-7 sentinels — reveal them
                                           * here, the one chokepoint every file-reading builtin funnels through.
                                           * The guard in sh_unprot_buf never writes a sentinel-free byte, so this is
                                           * safe even on the lone string-literal caller (scores' "SNAKE.HI"). */
    unsigned long cap = 65536;
    char *b = malloc(cap);
    long n = b ? sys_readfile(name, b, cap - 1) : -1;
    while (b && n == (long)(cap - 1) && cap < (32UL << 20)) {   /* read filled the buffer: file may be larger */
        cap <<= 1; free(b); b = malloc(cap);
        if (b) n = sys_readfile(name, b, cap - 1);
    }
    if (!b || n < 0 || n == (long)(cap - 1)) { free(b); *len = -1; g_status = 1; return 0; }
    b[n] = 0; *len = n; return b;
}

/* Run inline JS for `js -e <code>`. Intercepted early (in run_input_line) so the
 * code reaches the engine VERBATIM — JS's >, <, |, &, ; are operators here, not
 * shell metacharacters, and must not be redirected/piped/split/globbed away
 * (e.g. an arrow `x => x*2` contains a `>`). Output is still capturable with
 * $(...). */
static void run_js_inline(const char *code) {
    char *out = malloc(1u << 20);                /* 1MB output buffer */
    if (!out) { perr("js: out of memory\n"); return; }
    sys_js(code, out, (1u << 20) - 1);
    out[(1u << 20) - 1] = 0;
    print(out);
    free(out);
}
/* sort key helpers (sort_numval / sort_foldeq / sort_field) live in shsort.h,
 * host-tested by tests/shsort. */
/* tr_expand() (tr SET expansion) and cut_sel() (cut range membership) live in
 * shtxt.h, host-tested by tests/shtxt. */
/* Print one grep result line with its prefix. `sep` is ':' for a match, '-' for
 * a context line (grep -A/-B/-C). Mirrors the inline prefix logic exactly. */
static void grep_emit(const char *name, int fcount, int nn, int lno, const char *linetext, char sep) {
    char s2[3] = { sep, ' ', 0 };
    if (fcount > 1) print(name);
    if (fcount > 1 && nn) { char s1[2] = { sep, 0 }; print(s1); }
    if (nn) { char ln_[12]; itoa_simple(lno, ln_); print(ln_); }
    if (fcount > 1 || nn) print(s2); else print("  ");
    print(linetext); print("\n");
}

/* (the grep regex matcher gr_match() now lives in shgrep.h, #included above) */
static int b64v(char c) {                 /* base64 digit -> value, or -1 */
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
static void printl(long v) {              /* print a (possibly large) integer */
    char t[24]; int i = 0;
    unsigned long u = v < 0 ? -(unsigned long)v : (unsigned long)v;
    if (v < 0) print("-");
    if (!u) t[i++] = '0';
    while (u) { t[i++] = (char)('0' + u % 10); u /= 10; }
    char o[24]; int j = 0;
    while (i) o[j++] = t[--i];
    o[j] = '\0'; print(o);
}

/* A demo signal handler for `sigtest` — runs in ring 3 when a signal is raised. */
static void sig_demo_handler(int s) {
    print("  [handler] caught signal "); printl(s); print(" in userspace, returning\n");
}
static volatile int g_sigmask_got;                       /* set by the sigprocmask-test handler (M1208) */
static void sigmask_handler(int s) { (void)s; g_sigmask_got = 1; }
static void print_base(unsigned long n, int base) {   /* print n in base 2-16 */
    const char *dgt = "0123456789abcdef";
    char t[72]; int i = 0;
    if (!n) t[i++] = '0';
    while (n) { t[i++] = dgt[n % (unsigned)base]; n /= (unsigned)base; }
    char o[72]; int j = 0;
    while (i) o[j++] = t[--i];
    o[j] = '\0'; print(o);
}
static unsigned shell_rng = 0;            /* xorshift fallback, lazily clock-seeded */
static unsigned char rng_cache[256];      /* batched CSPRNG bytes from sys_getrandom */
static int rng_pos = (int)sizeof(rng_cache);
static int rng_hw  = 1;                   /* 1 = kernel CSPRNG available, 0 = fell back */
static unsigned shroll(void) {
    if (rng_hw) {                         /* prefer the hardware-seeded kernel CSPRNG (M1072) */
        if (rng_pos > (int)sizeof(rng_cache) - 4) {
            if (sys_getrandom(rng_cache, sizeof rng_cache) == (long)sizeof rng_cache) rng_pos = 0;
            else rng_hw = 0;              /* syscall unavailable: stop trying, use the fallback */
        }
        if (rng_hw) {
            unsigned v = (unsigned)rng_cache[rng_pos] | ((unsigned)rng_cache[rng_pos+1] << 8) |
                         ((unsigned)rng_cache[rng_pos+2] << 16) | ((unsigned)rng_cache[rng_pos+3] << 24);
            rng_pos += 4;
            return v;
        }
    }
    if (!shell_rng) {
        char tb[40]; long tn = sys_time(tb, sizeof(tb));
        shell_rng = 0x2545F491u;
        for (long i = 0; i < tn; i++) shell_rng = shell_rng * 31u + (unsigned char)tb[i];
        if (!shell_rng) shell_rng = 12345u;
    }
    shell_rng ^= shell_rng << 13; shell_rng ^= shell_rng >> 17; shell_rng ^= shell_rng << 5;
    return shell_rng;
}

/* Print a month calendar for the current date (from the RTC). */
/* Print one calendar week-line, colouring today's cell (marked '>') cyan (M1319). */
static void print_cal_week(const char *line) {
    for (int i = 0; line[i]; ) {
        if (line[i] == '>') {                              /* today's cell ">dd" -> " dd" in cyan */
            sys_setcolor(4);
            char cell[4] = { ' ', line[i+1], line[i+2], 0 };
            print(cell); sys_setcolor(0); i += 3;
        } else { char c[2] = { line[i], 0 }; print(c); i++; }
    }
    print("\n");
}
static void cmd_cal_ym(int y, int m, int today) {   /* render month m (1-12) of year y; today=0 -> no highlight */
    if (m < 1 || m > 12) { perr("cal: bad date\n"); return; }

    static const int mdays[] = { 31,28,31,30,31,30,31,31,30,31,30,31 };
    int dim = mdays[m-1];
    if (m == 2 && ((y%4==0 && y%100!=0) || y%400==0)) dim = 29;

    /* Sakamoto's day-of-week for the 1st (0=Sun) */
    static const int tt[] = { 0,3,2,5,0,3,5,1,4,6,2,4 };
    int yy = y - (m < 3);
    int dow = (yy + yy/4 - yy/100 + yy/400 + tt[m-1] + 1) % 7;

    static const char *mn[] = { "January","February","March","April","May","June",
        "July","August","September","October","November","December" };
    char yb[8]; itoa_simple(y, yb);
    print("    "); print(mn[m-1]); print(" "); print(yb); print("\n");
    print(" Su Mo Tu We Th Fr Sa\n");
    char line[32]; int p = 0;
    for (int i = 0; i < dow; i++) { line[p++]=' '; line[p++]=' '; line[p++]=' '; }
    for (int d = 1; d <= dim; d++) {                 /* 3-char cells: "> " marks today */
        line[p++] = (d == today) ? '>' : ' ';
        line[p++] = (d < 10) ? ' ' : (char)('0' + d/10);
        line[p++] = (char)('0' + d%10);
        if ((dow + d) % 7 == 0) { line[p] = 0; print_cal_week(line); p = 0; }
    }
    if (p) { line[p] = 0; print_cal_week(line); }
}
static void cmd_cal(void) {                          /* current month, today highlighted */
    char t[24];
    sys_time(t, sizeof(t));                          /* "YYYY-MM-DD HH:MM:SS" */
    int y = (t[0]-'0')*1000 + (t[1]-'0')*100 + (t[2]-'0')*10 + (t[3]-'0');
    int m = (t[5]-'0')*10 + (t[6]-'0');
    int today = (t[8]-'0')*10 + (t[9]-'0');
    cmd_cal_ym(y, m, today);
}

/*
 * Dispatch one command line. Returns 1 if the shell should exit (the "exit"
 * command), else 0. `cwd` is the display path (an array in main); cd/pwd mutate
 * it in place and the changes persist via the pointer.
 *
 * The whole if/else-if chain is wrapped in `do { ... } while (0);` so that the
 * original dispatch-level `continue;` (used to skip to the next command) still
 * does exactly that — it jumps to the `while (0)` and falls out of the block —
 * without disturbing any `continue` inside a command's own for/while loop.
 */
/* ---- shell variables: `set NAME=value` (or `export`), use as $NAME / ${NAME},
 * `unset NAME`, `set`/`env` list them. Persist for the shell process's lifetime. ---- */
static struct { char name[24], val[160]; } g_vars[24];
static int g_nvars;
static const char *vget(const char *n, int nl){
    for (int i=0;i<g_nvars;i++){ int j=0; while(j<nl && g_vars[i].name[j] && g_vars[i].name[j]==n[j]) j++;
        if (j==nl && g_vars[i].name[j]==0) return g_vars[i].val; }
    return 0;
}
/* shmath.h's variable hook: a name's integer value (0 if unset / non-numeric). */
static long sh_var(const char *name, int len){ const char *v = vget(name, len); return v ? sh_str2long(v) : 0; }
static void vset(const char *n, int nl, const char *v){
    if (nl<1) return; if (nl>23) nl=23;
    int slot=-1;
    for (int i=0;i<g_nvars && slot<0;i++){ int j=0; while(j<nl && g_vars[i].name[j]==n[j]) j++; if (j==nl && g_vars[i].name[j]==0) slot=i; }
    if (slot<0){ if (g_nvars>=24) return; slot=g_nvars++; int k=0; for(;k<nl;k++) g_vars[slot].name[k]=n[k]; g_vars[slot].name[k]=0; }
    int k=0; for(;v[k] && k<159;k++) g_vars[slot].val[k]=v[k]; g_vars[slot].val[k]=0;
}
static void vunset(const char *n){
    int nl=0; while(n[nl] && n[nl]!=' ') nl++;
    for (int i=0;i<g_nvars;i++){ int j=0; while(j<nl && g_vars[i].name[j]==n[j]) j++;
        if (j==nl && g_vars[i].name[j]==0){ g_vars[i]=g_vars[--g_nvars]; return; } }
}

/* ---- command aliases: `alias name=value`, expanded on the first word ------ */
static struct { char name[16], val[160]; } g_alias[16];
static int g_nalias;
static const char *alias_get(const char *n, int nl){
    for (int i=0;i<g_nalias;i++){ int j=0; while(j<nl && g_alias[i].name[j] && g_alias[i].name[j]==n[j]) j++;
        if (j==nl && g_alias[i].name[j]==0) return g_alias[i].val; }
    return 0;
}
static void alias_set(const char *n, int nl, const char *v){
    if (nl<1) return; if (nl>15) nl=15;
    int slot=-1;
    for (int i=0;i<g_nalias && slot<0;i++){ int j=0; while(j<nl && g_alias[i].name[j]==n[j]) j++; if (j==nl && g_alias[i].name[j]==0) slot=i; }
    if (slot<0){ if (g_nalias>=16) return; slot=g_nalias++; int k=0; for(;k<nl;k++) g_alias[slot].name[k]=n[k]; g_alias[slot].name[k]=0; }
    int k=0; for(;v[k] && k<159;k++) g_alias[slot].val[k]=v[k]; g_alias[slot].val[k]=0;
}
static void alias_del(const char *n){
    int nl=0; while(n[nl] && n[nl]!=' ') nl++;
    for (int i=0;i<g_nalias;i++){ int j=0; while(j<nl && g_alias[i].name[j]==n[j]) j++;
        if (j==nl && g_alias[i].name[j]==0){ g_alias[i]=g_alias[--g_nalias]; return; } }
}
/* user-defined functions: `NAME() { body }` — body is a ;-list run with $1..$9 bound to the call args. */
static struct { char name[24], body[256]; } g_func[16];
static int g_nfunc, g_func_depth;   /* g_func_depth caps recursion */
/* `local NAME[=val]` in a function: save the caller's value here; the function
 * dispatch restores everything pushed during its body when the call returns, so a
 * function's locals don't leak to (or clobber) the caller. A per-frame mark on the
 * stack makes this nest correctly. */
static struct { char name[24], val[160]; char had; } g_localsave[64];
static int g_nlocalsave;
static const char *func_get(const char *n, int nl){
    for (int i=0;i<g_nfunc;i++){ int j=0; while(j<nl && g_func[i].name[j] && g_func[i].name[j]==n[j]) j++;
        if (j==nl && g_func[i].name[j]==0) return g_func[i].body; }
    return 0;
}
static void func_set(const char *n, int nl, const char *body){
    if (nl<1) return;
    if (nl>23) nl=23;
    int slot=-1;
    for (int i=0;i<g_nfunc && slot<0;i++){ int j=0; while(j<nl && g_func[i].name[j]==n[j]) j++; if (j==nl && g_func[i].name[j]==0) slot=i; }
    if (slot<0){ if (g_nfunc>=16) return; slot=g_nfunc++; int k=0; for(;k<nl;k++) g_func[slot].name[k]=n[k]; g_func[slot].name[k]=0; }
    int k=0; for(;body[k] && k<255;k++) g_func[slot].body[k]=body[k]; g_func[slot].body[k]=0;
}
/* The $((expr)) evaluator (sh_eval, sh_vchar, sh_askip, …) now lives in
 * shmath.h, host-tested by tests/shmath; the sh_var hook above resolves names.
 * The $NAME/${…} parameter expander (expand_vars) now lives in shexpand.h,
 * host-tested by tests/shexpand; it uses vget + sh_laststatus (below). */
static int sh_laststatus(void){ return g_status < 0 ? 0 : g_status; }   /* $? value, clamped >= 0 */
#include "shexpand.h"

/* Expand a word-initial ~ to HOME (which is "/" on this OS): ~ -> /, ~/x -> /x,
 * and ~ before a space/tab/':'/end -> /. A '~' mid-word (foo~bar) is left literal,
 * as is a quoted "~" (sh_quote_pass protected it as a high-bit byte, M1806). Run
 * after variable/alias expansion; returns 1 if a '~' was present (dst holds the
 * result). Word boundary = start of line or just after a space/tab. */
static int expand_tilde(const char *src, char *dst, int cap){
    int has=0; for (int i=0;src[i];i++) if (src[i]=='~'){ has=1; break; }
    if (!has) return 0;
    int o=0, atword=1;
    for (int i=0; src[i] && o<cap-1; ){
        char c=src[i];
        if (c=='~' && atword){
            char n=src[i+1];
            if (n=='/' || n==0 || n==' ' || n=='\t' || n==':'){
                dst[o++]='/';                 /* HOME */
                i++;                          /* consume '~' */
                if (n=='/') i++;              /* fold "~/" -> "/" (HOME is root, avoid "//") */
                atword=0;
                continue;
            }
        }
        atword = (c==' '||c=='\t');            /* next char starts a word iff we just copied a separator */
        dst[o++]=c; i++;
    }
    dst[o]=0; return 1;
}

/* --- `ls` colourisation by file type (M1313), like `ls --color`. FAT32 names
 * are uppercase; ext_eq uppercases for the compare. The colour is a terminal
 * attribute (sys_setcolor), not bytes in the stream, so piping `ls` stays clean. */
static int ext_eq(const char *e, int el, const char *s) {
    int sl = 0; while (s[sl]) sl++;
    if (el != sl) return 0;
    for (int k = 0; k < el; k++) { char c = e[k]; if (c >= 'a' && c <= 'z') c -= 32; if (c != s[k]) return 0; }
    return 1;
}
static int ls_color(const char *name, int len) {
    if (len > 0 && name[len-1] == '/') return 6;                 /* directory: light-blue */
    int dot = -1; for (int k = 0; k < len; k++) if (name[k] == '.') dot = k;
    if (dot < 0) return 0;                                       /* no extension: default green */
    const char *e = name + dot + 1; int el = len - dot - 1;
    if (ext_eq(e,el,"ELF")||ext_eq(e,el,"SH")) return 9;                                                                    /* executable/script: lime */
    if (ext_eq(e,el,"PNG")||ext_eq(e,el,"JPG")||ext_eq(e,el,"GIF")||ext_eq(e,el,"BMP")||ext_eq(e,el,"SVG")) return 5;       /* image: magenta */
    if (ext_eq(e,el,"ZIP")||ext_eq(e,el,"GZ")||ext_eq(e,el,"TGZ")||ext_eq(e,el,"TAR")||ext_eq(e,el,"PAK")||ext_eq(e,el,"WAD")) return 2; /* archive: red */
    if (ext_eq(e,el,"WAV")) return 4;                                                                                       /* audio: cyan */
    if (ext_eq(e,el,"C")||ext_eq(e,el,"H")||ext_eq(e,el,"JS")) return 3;                                                    /* code: yellow */
    if (ext_eq(e,el,"NES")||ext_eq(e,el,"GB")) return 7;                                                                    /* ROM: orange */
    return 0;                                                    /* docs / text / default: green */
}
/* Print an `ls` listing with each name coloured by type + the size/date in grey. */
static void print_ls_colored(const char *buf) {
    char seg[128];
    int i = 0;
    while (buf[i]) {
        int ne = i; while (buf[ne] && buf[ne] != ' ' && buf[ne] != '\n') ne++;   /* name [i,ne) */
        sys_setcolor(ls_color(buf + i, ne - i));
        { int n = 0; for (int k = i; k < ne && n < 127; k++) seg[n++] = buf[k]; seg[n] = 0; print(seg); }
        int k = ne; while (buf[k] && buf[k] != '\n') k++;                          /* metadata [ne,k) */
        sys_setcolor(8);
        { int n = 0; for (int j = ne; j < k && n < 127; j++) seg[n++] = buf[j]; seg[n] = 0; print(seg); }
        sys_setcolor(0);
        if (buf[k] == '\n') { print("\n"); k++; }
        i = k;
    }
}
/* Colour a `tree` listing: the branch/indent prefix in grey, each name by type. */
static void print_tree_colored(const char *buf) {
    char seg[160];
    int i = 0;
    while (buf[i]) {
        int eol = i; while (buf[eol] && buf[eol] != '\n') eol++;          /* line [i,eol) */
        int ns = i;                                                       /* skip the leading branch/indent prefix to the name */
        while (ns < eol) { char c = buf[ns]; if ((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='.'||c=='/') break; ns++; }
        if (ns > i) { sys_setcolor(8); int n=0; for (int k=i;k<ns&&n<159;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); }
        sys_setcolor(ls_color(buf + ns, eol - ns));
        { int n=0; for (int k=ns;k<eol&&n<159;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); }
        sys_setcolor(0);
        if (buf[eol] == '\n') { print("\n"); eol++; }
        i = eol;
    }
}
/* Colour `ps` rows by process STATE (M1317): run lime, ready cyan, blocked
 * yellow, stopped/zombie red; PID + NAME stay default. */
static int pfx(const char *s, int sl, const char *m) {
    int ml = 0; while (m[ml]) ml++; if (ml > sl) return 0;
    for (int k = 0; k < ml; k++) if (s[k] != m[k]) return 0;
    return 1;
}
static void print_ps_colored(const char *buf) {
    char seg[160]; int i = 0;
    while (buf[i]) {
        int eol = i; while (buf[eol] && buf[eol] != '\n') eol++;
        int p = i; while (p < eol && buf[p] == ' ') p++;             /* leading ws */
        while (p < eol && buf[p] != ' ') p++;                        /* the [PID] token */
        while (p < eol && buf[p] == ' ') p++;                        /* ws before STATE */
        int ss = p; while (p < eol && buf[p] != ' ') p++;            /* STATE word [ss,p) */
        { int n=0; for (int k=i;k<ss&&n<159;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); }   /* PID + ws: default */
        int sl = p - ss;
        int col = pfx(buf+ss,sl,"run") ? 9 : pfx(buf+ss,sl,"rea") ? 4
                : (pfx(buf+ss,sl,"blo")||pfx(buf+ss,sl,"sle")||pfx(buf+ss,sl,"wai")) ? 3
                : (pfx(buf+ss,sl,"sto")||pfx(buf+ss,sl,"zom")||pfx(buf+ss,sl,"dea")) ? 2 : 0;
        sys_setcolor(col);
        { int n=0; for (int k=ss;k<p&&n<159;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); }   /* STATE: coloured */
        sys_setcolor(0);
        { int n=0; for (int k=p;k<eol&&n<159;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); }  /* NAME: default */
        if (buf[eol] == '\n') { print("\n"); eol++; }
        i = eol;
    }
}
/* Colour `lspci`: bus address cyan + vendor:device id yellow, rest default (M1321). */
static void print_lspci_colored(const char *buf) {
    char seg[200]; int i = 0;
    while (buf[i]) {
        int eol = i; while (buf[eol] && buf[eol] != '\n') eol++;
        int p = i; while (p < eol && buf[p] == ' ') p++;        /* lead ws */
        int b1 = p; while (p < eol && buf[p] != ' ') p++;       /* token0 = bus [b1,p) */
        { int n=0; for (int k=i;k<b1&&n<199;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); }
        sys_setcolor(4); { int n=0; for (int k=b1;k<p&&n<199;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); } sys_setcolor(0);
        int w2 = p; while (p < eol && buf[p] == ' ') p++;       /* ws */
        int b2 = p; while (p < eol && buf[p] != ' ') p++;       /* token1 = vendor:device [b2,p) */
        { int n=0; for (int k=w2;k<b2&&n<199;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); }
        sys_setcolor(3); { int n=0; for (int k=b2;k<p&&n<199;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); } sys_setcolor(0);
        { int n=0; for (int k=p;k<eol&&n<199;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); }
        if (buf[eol] == '\n') { print("\n"); eol++; }
        i = eol;
    }
}
/* Print a help line; if it starts with a "label:" section header, colour the
 * label cyan (M1322). Continuation lines (leading space) print unchanged. */
static void perr(const char *s) { sys_setcolor(2); print(s); sys_setcolor(0); }   /* print an error label in red (M1379) */
static void helpline(const char *s) {
    int c = 0; while (s[c] && s[c] != ':' && s[c] != ' ') c++;
    if (s[0] != ' ' && s[c] == ':') {
        sys_setcolor(4);
        char lab[16]; int n = 0; for (int k = 0; k <= c && n < 15; k++) lab[n++] = s[k]; lab[n] = 0;
        print(lab); sys_setcolor(0); print(s + c + 1);
    } else print(s);
}
/* Print a listing colouring the first token of each line cyan (M1323, for mount). */
static void print_firsttok_cyan(const char *buf) {
    char seg[200]; int i = 0;
    while (buf[i]) {
        int eol = i; while (buf[eol] && buf[eol] != '\n') eol++;
        int p = i; while (p < eol && buf[p] == ' ') p++;
        int t = p; while (p < eol && buf[p] != ' ') p++;
        { int n=0; for (int k=i;k<t&&n<199;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); }
        sys_setcolor(4); { int n=0; for (int k=t;k<p&&n<199;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); } sys_setcolor(0);
        { int n=0; for (int k=p;k<eol&&n<199;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); }
        if (buf[eol]=='\n') { print("\n"); eol++; }
        i = eol;
    }
}

/* Colour an indented "NAME  metadata" listing (lsblk's file entries): the name
 * token by file type, the rest (size/etc.) grey (M1326). */
static void print_indented_ls(const char *buf) {
    char seg[200]; int i = 0;
    while (buf[i]) {
        int eol = i; while (buf[eol] && buf[eol] != '\n') eol++;
        int ns = i; while (ns < eol && buf[ns] == ' ') ns++;     /* name start (after indent) */
        int ne = ns; while (ne < eol && buf[ne] != ' ') ne++;    /* name end */
        sys_setcolor(ls_color(buf + ns, ne - ns));               /* name token by file type */
        { int n=0; for (int k=i;k<ne&&n<199;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); }   /* indent + name */
        sys_setcolor(8);
        { int n=0; for (int k=ne;k<eol&&n<199;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); } /* metadata grey */
        sys_setcolor(0);
        if (buf[eol] == '\n') { print("\n"); eol++; }
        i = eol;
    }
}

/* Draw a colour-coded 20-cell usage bar + "N% used": lime <70%, amber 70-90%,
 * red >=90%; empty cells grey. Shared by df (disk) and free (memory) (M1331). */
static void print_usage_bar(long used, long total) {
    if (total <= 0) return;
    if (used < 0) used = 0; if (used > total) used = total;
    int pct  = (int)((used * 100) / total);
    int fill = (int)((used * 20 + total / 2) / total);
    int bc   = pct >= 90 ? 2 : (pct >= 70 ? 3 : 9);
    print("      [");
    sys_setcolor(bc); for (int c = 0; c < fill; c++) print("#");
    sys_setcolor(8);  for (int c = fill; c < 20; c++) print("-");
    sys_setcolor(0);  print("] ");
    sys_setcolor(bc); printl(pct); print("%"); sys_setcolor(0); print(" used\n");
}

/* Colour the kernel log's level tags: "[ ok ]" lime, "[warn..]" amber,
 * "[err..]"/"[fail..]" red, any other "[...]" light-blue; message text default (M1355). */
static void print_dmesg_colored(const char *buf) {
    char seg[256]; int i = 0;
    while (buf[i]) {
        int eol = i; while (buf[eol] && buf[eol] != '\n') eol++;
        int lb = -1, rb = -1;
        for (int k = i; k < eol && k < i + 10; k++) if (buf[k] == '[') { lb = k; break; }
        if (lb >= 0) for (int k = lb + 1; k < eol; k++) if (buf[k] == ']') { rb = k; break; }
        if (lb >= 0 && rb > lb + 1) {
            int t = lb + 1; while (t < rb && buf[t] == ' ') t++;          /* trim, then match level WORDS (not 1st char -- "[ehci]" is a subsystem, not an error) */
            const char *p = buf + t; int rem = rb - t; int col = 6;       /* subsystem tag -> light-blue */
            if      (rem >= 2 && p[0]=='o' && p[1]=='k')                     col = 9;   /* [ ok ] -> lime */
            else if (rem >= 4 && p[0]=='w'&&p[1]=='a'&&p[2]=='r'&&p[3]=='n') col = 3;   /* warn  -> amber */
            else if (rem >= 3 && p[0]=='e'&&p[1]=='r'&&p[2]=='r')            col = 2;   /* err   -> red */
            else if (rem >= 4 && p[0]=='f'&&p[1]=='a'&&p[2]=='i'&&p[3]=='l') col = 2;   /* fail  -> red */
            int n=0; for (int k=i;k<lb&&n<255;k++) seg[n++]=buf[k]; seg[n]=0; print(seg);                                  /* before tag */
            sys_setcolor(col); n=0; for (int k=lb;k<=rb&&n<255;k++) seg[n++]=buf[k]; seg[n]=0; print(seg); sys_setcolor(0); /* the [tag] */
            n=0; for (int k=rb+1;k<eol&&n<255;k++) seg[n++]=buf[k]; seg[n]=0; print(seg);                                  /* after tag */
        } else {
            int n=0; for (int k=i;k<eol&&n<255;k++) seg[n++]=buf[k]; seg[n]=0; print(seg);
        }
        if (buf[eol] == '\n') { print("\n"); eol++; }
        i = eol;
    }
}

/* The sh_test_file hook from shtest.h: file-existence/type probe for `test`/`[ ]`.
 * -e/-f/-d/-s reuse the read-one-byte + chdir probe the builtin has always used;
 * this OS has a minimal single-user permission model, so -r/-w/-x are approximated
 * as "exists". (M1816) */
static int sh_test_file(char op, const char *path, const char *cwd) {
    char b; long rf = sys_readfile(path, &b, 1);
    int isdir = 0; if (sys_chdir(path) >= 0) { isdir = 1; sys_chdir((char *)cwd); }
    switch (op) {
        case 'd': return isdir;
        case 'e': return (rf >= 0) || isdir;
        case 'f': return (rf >= 0) && !isdir;
        case 's': return (rf >= 1) && !isdir;
        case 'r': case 'w': case 'x': return (rf >= 0) || isdir;   /* minimal perms: r/w/x ~ exists */
    }
    return 0;
}

/* One `ls -l` line for `name` (statx'd relative to the cwd): mode string, link
 * count, right-aligned size, "YYYY-MM-DD HH:MM" mtime, then the type-coloured
 * name. On a stat failure just prints the bare name. (M1817) */
static void ls_long_entry(const char *name, int human) {
    int nl = 0; while (name[nl]) nl++;
    struct statx st;
    if (sys_statx(name, &st) != 0) { print(name); print("\n"); return; }
    char modes[12], tbuf[20]; ls_mode_str(st.stx_mode, modes); ls_fmt_time(st.stx_mtime, tbuf);
    char sizb[24]; int sl = 0;                             /* size -> string (for right-alignment) */
    if (human) { ls_human_size(st.stx_size, sizb); while (sizb[sl]) sl++; }   /* -h: 1.5K / 27M */
    else { unsigned long v = st.stx_size; char tmp[24]; int ti = 0; if (!v) tmp[ti++] = '0'; while (v) { tmp[ti++] = '0' + (int)(v % 10); v /= 10; } while (ti) sizb[sl++] = tmp[--ti]; sizb[sl] = 0; }
    print(modes); print(" "); printl((long)st.stx_nlink); print(" ");
    for (int s = sl; s < 8; s++) print(" ");               /* right-align size to width 8 */
    sys_setcolor(8); print(sizb); print(" "); print(tbuf); print("  ");
    sys_setcolor(ls_color(name, nl)); print(name); sys_setcolor(0); print("\n");
}

/* List directory `dir` (relative to cwd; NULL/"" = the cwd itself). longfmt ->
 * one `ls -l` line per entry; else the existing coloured name grid. (M1817) */
/* sortkey: 0 none (sys_list order), 1 by size, 2 by mtime (both descending, like
 * GNU ls -S/-t); reverse flips the final order (-r). Plain `ls` (no -l/-S/-t/-r)
 * keeps the fast streaming coloured grid untouched; anything else collects the
 * entries (cap 256) so they can be sorted/reversed. (M1817/M1822/M1824) */
static void ls_print_dir(const char *dir, int longfmt, int human, int sortkey, int reverse, char *cwd) {
    if (dir && dir[0] && sys_chdir(dir) < 0) { perr("ls: no such directory: "); print(dir); print("\n"); g_status = 1; return; }
    char buf[8192]; sys_list(buf, sizeof buf);
    if (!longfmt && !sortkey && !reverse) { print_ls_colored(buf); if (dir && dir[0]) sys_chdir(cwd); return; }
    static char sn[256][64]; static unsigned long sk[256]; int cnt = 0;
    int i = 0;
    while (buf[i] && cnt < 256) {
        int ne = i; while (buf[ne] && buf[ne] != ' ' && buf[ne] != '\n') ne++;         /* name [i,ne) */
        if (ne > i) {
            int n = 0; for (int k = i; k < ne && n < 63; k++) sn[cnt][n++] = buf[k]; sn[cnt][n] = 0;
            sk[cnt] = 0;
            if (sortkey) { struct statx st; if (sys_statx(sn[cnt], &st) == 0) sk[cnt] = (sortkey == 1) ? st.stx_size : st.stx_mtime; }
            cnt++;
        }
        int k = ne; while (buf[k] && buf[k] != '\n') k++;                              /* skip sys_list's own trailing metadata */
        i = (buf[k] == '\n') ? k + 1 : k;
    }
    if (sortkey) {                                                                     /* insertion sort, descending by key */
        for (int a = 1; a < cnt; a++) {
            unsigned long kk = sk[a]; char nm[64]; int z = 0; while (sn[a][z]) { nm[z] = sn[a][z]; z++; } nm[z] = 0;
            int b = a - 1;
            while (b >= 0 && sk[b] < kk) { sk[b+1] = sk[b]; int y = 0; while (sn[b][y]) { sn[b+1][y] = sn[b][y]; y++; } sn[b+1][y] = 0; b--; }
            sk[b+1] = kk; int y = 0; while (nm[y]) { sn[b+1][y] = nm[y]; y++; } sn[b+1][y] = 0;
        }
    }
    for (int idx = 0; idx < cnt; idx++) {
        int e = reverse ? (cnt - 1 - idx) : idx;
        if (longfmt) ls_long_entry(sn[e], human);
        else { int nl = 0; while (sn[e][nl]) nl++; sys_setcolor(ls_color(sn[e], nl)); print(sn[e]); sys_setcolor(0); print("\n"); }
    }
    if (dir && dir[0]) sys_chdir(cwd);
}

static int run_command(char *line, char *cwd) {
    g_status = 0;                          /* assume success; failure paths set $? = 1 */
    do {
        { int wl = 0; while (line[wl] && line[wl] != ' ') wl++;   /* a user-defined function shadows builtins (bash behaviour) */
          const char *fb = wl ? func_get(line, wl) : 0;
          if (fb && g_func_depth < 8) {
              char bc[256]; int bi = 0; while (fb[bi] && bi < 255) { bc[bi] = fb[bi]; bi++; } bc[bi] = 0;   /* snapshot the body */
              static const char pn1[11] = {'1','2','3','4','5','6','7','8','9','@','#'};   /* save caller's params so a nested call gets local scope */
              char saved[11][160]; char had[11];
              for (int s = 0; s < 11; s++) {
                  char nm[2] = { pn1[s], 0 }; const char *ov = vget(nm, 1); had[s] = ov ? 1 : 0;
                  if (ov) { int k = 0; while (ov[k] && k < 159) { saved[s][k] = ov[k]; k++; } saved[s][k] = 0; }
              }
              const char *a = line + wl; while (*a == ' ') a++;   /* bind $1..$9 to the call args */
              vset("@", 1, a);                                    /* $@ = all args; $# = count (set below) */
              int pn = 0;
              while (*a && pn < 9) {
                  char pname[2] = { (char)('1' + pn), 0 };
                  char pv[64]; int pi = 0; while (*a && *a != ' ' && pi < 63) pv[pi++] = *a++;
                  pv[pi] = 0; vset(pname, 1, pv);
                  while (*a == ' ') a++;
                  pn++;
              }
              for (int z = pn; z < 9; z++) { char pname[2] = { (char)('1' + z), 0 }; vset(pname, 1, ""); }   /* clear unused params */
              { char cb[12]; itoa_simple(pn, cb); vset("#", 1, cb); }   /* $# = arg count */
              int localmark = g_nlocalsave;    /* `local` decls in the body restore down to here on return */
              g_func_depth++; run_input_line(bc, cwd); g_func_depth--;
              g_returning = 0;                 /* `return` unwinds only to here (the function boundary) */
              while (g_nlocalsave > localmark) {   /* restore vars this call declared `local` (newest first) */
                  g_nlocalsave--;
                  if (g_localsave[g_nlocalsave].had) vset(g_localsave[g_nlocalsave].name, (int)ustrlen(g_localsave[g_nlocalsave].name), g_localsave[g_nlocalsave].val);
                  else vunset(g_localsave[g_nlocalsave].name);
              }
              for (int s = 0; s < 11; s++) {   /* restore caller's params (revert this call's scope) */
                  char nm[2] = { pn1[s], 0 };
                  if (had[s]) vset(nm, 1, saved[s]); else vunset(nm);
              }
              continue;
          } }
        /* bare NAME=value assignment (sh-style; no `set` prefix). NAME is a valid
         * identifier and '=' follows it directly — no builtin's first word has '='. */
        if (line[0] == '_' || (line[0] >= 'a' && line[0] <= 'z') || (line[0] >= 'A' && line[0] <= 'Z')) {
            int k = 1;
            while (line[k] == '_' || (line[k] >= 'a' && line[k] <= 'z') || (line[k] >= 'A' && line[k] <= 'Z') || (line[k] >= '0' && line[k] <= '9')) k++;
            if (line[k] == '=') { sh_unprot_buf(line + k + 1); vset(line, k, line + k + 1); continue; }   /* value = rest of line (already expanded) */
        }
        if (line[0] == '\0') {
            continue;
        } else if (streq(line, "help")) {
            helpline("files:  ls cat head tail sort[-nrufkt] nl tac uniq[-cdu] cut[-c/-f] cmp<f1 f2> paste[-d]<f1 f2> comm<f1 f2> diff<f1 f2> edit write rm cp mv mkdir[-p] touch ln<-s tgt link> cd pwd basename<p [suf]> dirname<p> tree find grep[-incvelo,-A/B/C,regex] sed<'s/RE/REPL/gi'> file<n> hexdump hexedit<file> strings<file> unhex<hex> gzip<f> gunzip<f.gz> unzip<f.zip> tar<f.tgz> wc[-lwcL] tr fold seq[a b c] printf<fmt args> sleep<n> tee<f> xargs<cmd>\n");
            helpline("net:    get<url> headers<url> wget<url file> browse<url> wsget<ws://url [msg]> wsserve[ port] (WebSocket client/server)\n");
            print("        ping[<host>] resolve<host> ifconfig dhcp (lease IP via DHCP) tftp get<remote [local]> httpd (serve HTTP on :80, then curl a host-forwarded port)\n");
            print("        fw (packet filter: 'fw drop in icmp', 'fw allow out tcp 80', 'fw flush'; bare 'fw' lists rules+hits)\n");
            print("        sntp / ntpdate (set the wall clock from pool.ntp.org over UDP)\n");
            helpline("crypto: sha1<file> sha256<file> sha512<file> crc32<file> genpass[ N] uuidgen crypt base64 unbase64<b64>\n");
            print("        cas store<file> (content-addressed store, SHA-256 key)  cas fetch<key>  cas (stats)\n");
            print("        run: apps run<prog> js<file>  jail<prog promise..> (sandbox a spawned app)\n");
            helpline("math:   factor<n> roll<NdM> seq<n> base<N> dec<0x..> roman<N> gcd<a b> primes<N> fib<N> fizzbuzz<N> stats<n..> size<bytes>\n");
            helpline("misc:   echo cal[ M Y] weekday<YYYYMMDD> dur<sec> date beep tone[ hz ms] play<f.wav> stop morse<text> unmorse<code> rev<text> rot13<text> ascii cowsay<text> fortune\n");
            print("        todo[ add T|done N|clear] clip[ file] wallpaper<file> mem ps top df uptime uname whoami hostname[ NAME] free id neofetch stat<path> fiemap<path> fallocate punch<path off len> dmesg measure lspci lsblk mount losetup<img> scores history clear reboot poweroff kill<pid> exit\n");
            helpline("vm:     mmaptest ringtest jittest madvisetest pageouttest(MADV_PAGEOUT) mincoretest mlocktest swaptest shmtest hugetest(2MiB) thptest(MADV_COLLAPSE) (mmap/ring/W^X/reclaim/residency/pin/swap/shm/hugepage/THP)  usagetest(getrusage)  smaps  mqtest(prio msgq)  semtest(SysV sem)  semopentest(POSIX named sem)  msgtest(SysV msgq)  shmsysvtest(SysV shm)  sysvctltest(msgctl/shmctl)  unixtest(AF_UNIX sockets)  unixpolltest(wait_any poll)  nicetest(CFS fair sched)  schedtest(SCHED_FIFO RT)  affinitytest(sched_setaffinity)  rawkey(TTY raw mode)  jobtest(killpg process group + tcgetpgrp + getsid)  sigsuspendtest(sigsuspend)  pdeathsigtest(SIGCHLD + PR_SET_PDEATHSIG)  pausetest(pause)  flocktest(advisory file locks)  stoptest(SIGTSTP/SIGCONT)  mremaptest(mmap resize/move)  cfrtest(copy_file_range)  pvmtest(process_vm_read)  pvwtest(process_vm_write)  wchantest(/proc/sched WCHAN)  pagemaptest(/proc/pagemap PFNs)  rlimittest(rlimits)  alarmtest  setitimertest(setitimer/getitimer)  fsynctest(fsync/fdatasync/sync_file_range)  fxattrtest(f*xattr)  epollpwaittest(epoll_pwait)  tcflushtest(tcflush/tcdrain)  preadwritetest(pread/pwrite)  ppolltest(ppoll)  iovtest(readv/writev)  piovtest(preadv/pwritev)  futextimeouttest(FUTEX_WAIT timeout)  eventfdblocktest(blocking eventfd read)  sigpipetest(SIGPIPE)  selecttest(select fd_set)  linkattest(linkat)  mmapmunmaptest(munmap flushes dirty MAP_SHARED)  fdleaktest(fd table survives exit-without-close)  dupaliastest(dup'd inotify/TCP-socket fd survives original close)  clockgt  wss[ pid]\n");
            helpline("syntax: cmd1 | cmd2 (pipe)   cmd > file (write)   cmd >> file (append)   cmd < file (read)   $(cmd) (substitute)\n");
            print("        a && b (b if a ok)   a || b (b if a fails)   $? (last status)  true false\n");
            print("        source file (or '. file'): run shell commands from a file (# = comment)\n");
            print("        .SHRC in / is auto-run at shell start (put aliases/set/etc. there)\n");
            print("        read VAR: read a line of input into VAR (for interactive scripts)\n");
            print("        for V in WORDS; do CMDS; done   (loop: WORDS get glob/$var expansion)\n");
            print("        while COND; do CMDS; done   (loops while COND succeeds; Ctrl-C to stop)\n");
            print("        break / continue   (exit / skip to next iteration of the innermost loop)\n");
            print("        for ((i=0;i<N;i++)); do CMDS; done   (C-style loop)   (( expr ))  (arithmetic: i++, x=a*b; sets $?)\n");
            print("        if COND; then CMDS; [elif COND; then CMDS;]... [else CMDS;] fi   (status picks the branch)\n");
            print("        case WORD in PAT) CMDS;; PAT2|PAT3) CMDS;; *) CMDS;; esac   (glob-match dispatch)\n");
            print("        test/[ ]: A -eq/-ne/-lt/-gt/-le/-ge B, A =/!= B, -z/-n S, -e/-f F, ! EXPR\n");
            print("        alias name=value   unalias name   (shortcuts, expanded on the first word)\n");
            print("        name() { cmds; }   (define a function; call `name args` with $1..$9 $# $@ bound)\n");
            print("        return [N]         (from a function: stop it now, set $? to N)\n");
            print("        local NAME[=val]   (function-scoped variable; restored when the function returns)\n");
            print("        *.txt ? (glob)   cmd1 ; cmd2 (run both)   !! (repeat last command)\n");
            print("        NAME=val (or set NAME=val)  $NAME ${NAME} ${N:-def} ${N:+alt} ${#N} ${N#pfx} ${N%sfx}  $((expr))  unset NAME  env\n");
            helpline("edit:   arrows move  Home/End  Del  up/down=history  ^W/^U/^K=kill  ^C=cancel\n");
            print("        Tab completes a filename (longest common prefix); a 2nd Tab lists the matches\n");
        } else if (startswith(line, "set ") || startswith(line, "export ")) {
            const char *p = line + (line[1]=='x' ? 7 : 4); while (*p == ' ') p++;   /* skip "set "/"export " */
            if (line[0]=='s' && (p[0]=='-' || p[0]=='+')) {   /* `set -e`/`-x` (and +) shell options (M1808/M1809); `set -o` unsupported */
                int on = (p[0]=='-'); int ok = 1;
                for (const char *f = p + 1; *f && *f != ' '; f++) {
                    if (*f == 'x') g_xtrace = on;
                    else if (*f == 'e') g_errexit = on;
                    else { ok = 0; }
                }
                if (!ok) print("set: only -e/-x (and +e/+x) supported\n");
            } else {
                int nl = 0; while (p[nl] && p[nl] != '=' && p[nl] != ' ') nl++;
                if (p[nl] == '=' && nl > 0) { sh_unprot_buf((char *)p + nl + 1); vset(p, nl, p + nl + 1); }   /* value = rest of line (may contain spaces) */
                else print("usage: set NAME=value  (or set -x/+x)\n");
            }
        } else if (startswith(line, "local ")) {       /* local NAME[=val] ... : function-scoped vars (restored on return) */
            const char *p = line + 6;
            while (*p) {
                while (*p == ' ') p++;
                if (!*p) break;
                int nl = 0; while (p[nl] && p[nl] != '=' && p[nl] != ' ') nl++;
                if (nl == 0) { p++; continue; }
                char vbuf[160]; const char *val = ""; const char *vp = p + nl;
                if (*vp == '=') { int vi = 0; const char *q = vp + 1; while (*q && *q != ' ' && vi < 159) vbuf[vi++] = *q++; vbuf[vi] = 0; sh_unprot_buf(vbuf); val = vbuf; vp = q; }
                if (g_func_depth > 0 && g_nlocalsave < 64) {   /* remember the caller's value so the function boundary can restore it */
                    const char *ov = vget(p, nl); int s = g_nlocalsave++;
                    int k = 0; for (; k < nl && k < 23; k++) g_localsave[s].name[k] = p[k];
                    g_localsave[s].name[k] = 0; g_localsave[s].had = ov ? 1 : 0;
                    if (ov) { int j = 0; while (ov[j] && j < 159) { g_localsave[s].val[j] = ov[j]; j++; } g_localsave[s].val[j] = 0; }
                }
                vset(p, nl, val);
                p = vp;
            }
        } else if (streq(line, "set") || streq(line, "env")) {                       /* list all variables */
            for (int i = 0; i < g_nvars; i++) { sys_setcolor(4); print(g_vars[i].name); sys_setcolor(8); print("="); sys_setcolor(0); print(g_vars[i].val); print("\n"); }   /* NAME cyan, = grey, value default (M1324) */
            if (g_nvars == 0) print("(no variables set)\n");
        } else if (startswith(line, "read ")) {                                       /* read a line of input into variable(s) */
            char *p = line + 5; while (*p == ' ') p++; sh_unprot_buf(p);
            char rb[256]; int got;
            if (g_reading) got = sh_read_next(rb, sizeof rb);   /* `while read; done < FILE`: next line, or EOF */
            else { readline(rb, sizeof rb); got = 1; }          /* interactive: a keyed line always "succeeds" */
            if (!got) g_status = 1;                             /* EOF -> $?=1 so `while read` stops */
            else {
                g_status = 0;
                /* split rb across the named vars: each earlier var gets one whitespace word,
                 * the LAST var gets the whole remainder (bash `read a b c`). One var = whole line. */
                const char *r = rb;
                while (*p) {
                    while (*p == ' ') p++;
                    if (!*p) break;
                    int nl = 0; while (p[nl] && p[nl] != ' ') nl++;   /* this target var name */
                    const char *next = p + nl; while (*next == ' ') next++;
                    while (*r == ' ' || *r == '\t') r++;              /* skip leading blanks of this field */
                    char val[256]; int vi = 0;
                    if (*next) {                                     /* more vars follow: take ONE word */
                        while (*r && *r != ' ' && *r != '\t' && vi < 255) val[vi++] = *r++;
                    } else {                                         /* last var: take the remainder, trim trailing blanks */
                        while (*r && vi < 255) val[vi++] = *r++;
                        while (vi > 0 && (val[vi-1] == ' ' || val[vi-1] == '\t')) vi--;
                    }
                    val[vi] = 0; vset(p, nl, val);
                    p += nl;
                }
            }
        } else if (startswith(line, "unset ")) {
            char *p = line + 6; while (*p == ' ') p++; sh_unprot_buf(p); vunset(p);
        } else if (streq(line, "ls")) {
            ls_print_dir(0, 0, 0, 0, 0, cwd);          /* the cwd, coloured name grid (M1313) */
        } else if (startswith(line, "ls ")) {     /* ls [-l][-a][-h][-S|-t][-r] <name>...: -l long, -h human, -S size sort, -t time sort, -r reverse */
            const char *p = line + 3;
            int longfmt = 0, human = 0, sortkey = 0, reverse = 0;   /* -a accepted but a no-op here (no dotfiles); -S=size -t=mtime sort (desc); -r reverse */
            char paths[16][64]; int npath = 0;
            while (*p) {
                while (*p == ' ') p++;
                if (!*p) break;
                char tok[64]; int j = 0; while (*p && *p != ' ' && j < 63) tok[j++] = *p++; tok[j] = 0;
                if (tok[0] == '-' && tok[1]) { for (int k = 1; tok[k]; k++) { if (tok[k] == 'l') longfmt = 1; else if (tok[k] == 'h') human = 1; else if (tok[k] == 'S') sortkey = 1; else if (tok[k] == 't') sortkey = 2; else if (tok[k] == 'r') reverse = 1; } }
                else { sh_unprot_buf(tok); if (npath < 16) { int m = 0; while (tok[m] && m < 63) { paths[npath][m] = tok[m]; m++; } paths[npath][m] = 0; npath++; } }
            }
            if (npath == 0) ls_print_dir(0, longfmt, human, sortkey, reverse, cwd);
            else for (int i = 0; i < npath; i++) {
                if (sys_chdir(paths[i]) >= 0) {                    /* a directory: list its contents */
                    sys_chdir(cwd);
                    if (npath > 1) { print(paths[i]); print(":\n"); }
                    ls_print_dir(paths[i], longfmt, human, sortkey, reverse, cwd);
                } else {                                           /* a file (or a glob expansion): name it, long if -l */
                    char b;
                    if (sys_readfile(paths[i], &b, 1) >= 0) { if (longfmt) ls_long_entry(paths[i], human); else { print(paths[i]); print("\n"); } }
                    else { perr("ls: no such file: "); print(paths[i]); print("\n"); g_status = 1; }
                }
            }
        } else if (startswith(line, "cat ")) {
            const char *p = line + 4; int any = 0;
            while (*p) {                                  /* concatenate each space-separated file */
                while (*p == ' ') p++;
                if (!*p) break;
                char name[64]; int i = 0;
                while (*p && *p != ' ' && i < 63) name[i++] = *p++;
                name[i] = '\0'; sh_unprot_buf(name); any = 1;
                long n; char *buf = slurp(name, &n);
                if (!buf) { perr("cat: no such file: "); print(name); print("\n"); }
                else { print(buf); free(buf); }
            }
            if (!any) print("usage: cat <file>...\n");
        } else if (startswith(line, "head ")) {
            const char *p = line + 5;
            while (*p == ' ') p++;
            int cnt = 20, bytes = 0;                       /* -N lines (default 20); -c N = first N bytes */
            if (*p == '-' && p[1] == 'c') { bytes = 1; p += 2; while (*p == ' ') p++; cnt = 0; while (*p >= '0' && *p <= '9' && cnt < 100000000) cnt = cnt * 10 + (*p++ - '0'); if (cnt < 1) cnt = 20; while (*p == ' ') p++; }
            else if (*p == '-' && p[1] >= '0' && p[1] <= '9') { p++; cnt = 0; while (*p >= '0' && *p <= '9' && cnt < 100000000) cnt = cnt * 10 + (*p++ - '0'); if (cnt < 1) cnt = 20; while (*p == ' ') p++; }
            const char *cq = p; int fc = 0;                /* count files -> name headers only if >1 */
            while (*cq) { while (*cq == ' ') cq++; if (!*cq) break; fc++; while (*cq && *cq != ' ') cq++; }
            int any = 0;
            while (*p) {                                   /* first 20 lines of each space-separated file */
                while (*p == ' ') p++;
                if (!*p) break;
                char name[64]; int j = 0;
                while (*p && *p != ' ' && j < 63) name[j++] = *p++;
                name[j] = '\0'; sh_unprot_buf(name); any = 1;
                long n; char *buf = slurp(name, &n);
                if (!buf) { perr("head: no such file: "); print(name); print("\n"); continue; }
                if (fc > 1) { print("==> "); print(name); print(" <==\n"); }
                int i;
                if (bytes) i = (int)(n < cnt ? n : cnt);       /* -c: first cnt bytes */
                else { i = 0; int lines = 0; for (; i < n && lines < cnt; i++) if (buf[i] == '\n') lines++; }
                buf[i] = '\0'; print(buf);
                if (i < n && !cap_active()) print("...\n");   /* "more" hint for the screen; never into a pipe/$() data stream */
                free(buf);
            }
            if (!any) print("usage: head <file>...\n");
        } else if (startswith(line, "patch ")) {          /* patch TARGET PATCHFILE: apply a unified diff in place */
            const char *a = line + 6; while (*a == ' ') a++;
            char tgt[64]; int tl = 0; while (*a && *a != ' ' && tl < 63) tgt[tl++] = *a++; tgt[tl] = 0;
            while (*a == ' ') a++;
            char pf[64]; int pl = 0; while (*a && *a != ' ' && pl < 63) pf[pl++] = *a++; pf[pl] = 0;
            sh_unprot_buf(tgt); sh_unprot_buf(pf);
            if (!tgt[0] || !pf[0]) { print("usage: patch TARGET PATCHFILE  (apply a unified diff in place)\n"); g_status = 2; }
            else {
                long tn, pn; char *tb = slurp(tgt, &tn);
                if (!tb) { perr("patch: no such file: "); print(tgt); print("\n"); g_status = 1; }
                else {
                    char *pb = slurp(pf, &pn);
                    if (!pb) { perr("patch: no such file: "); print(pf); print("\n"); free(tb); g_status = 1; }
                    else {
                        tb[tn] = 0; pb[pn] = 0;
                        char *outp = (char *)malloc((unsigned long)(tn + pn + 16));
                        if (!outp) { print("patch: out of memory\n"); g_status = 1; }
                        else {
                            int r = patch_apply(tb, pb, outp, (int)(tn + pn + 16));
                            if (r < 0) { print("patch: a hunk does not match "); print(tgt); print(" -- not applied\n"); g_status = 1; }
                            else if (sys_writefile(tgt, outp, r) < 0) { perr("patch: write failed: "); print(tgt); print("\n"); g_status = 1; }
                            else { print("patched "); print(tgt); print("\n"); }
                            free(outp);
                        }
                        free(pb);
                    }
                    free(tb);
                }
            }
        } else if (startswith(line, "nl ")) {
            long n; char *buf = slurp(line + 3, &n);
            if (!buf) { perr("nl: no such file: "); print(line + 3); print("\n"); }
            else {
                int ln = 1, start = 0; char num[12];
                for (int i = 0; i < (int)n; i++) {
                    if (buf[i] == '\n') {
                        buf[i] = '\0';
                        itoa_simple(ln++, num);
                        print("  "); print(num); print("  "); print(buf + start); print("\n");
                        start = i + 1;
                    }
                }
                if (start < (int)n) {                       /* final line with no trailing newline */
                    buf[n] = '\0';
                    itoa_simple(ln, num);
                    print("  "); print(num); print("  "); print(buf + start); print("\n");
                }
                free(buf);
            }
        } else if (startswith(line, "tail ")) {
            const char *p = line + 5;
            while (*p == ' ') p++;
            int cnt = 20, bytes = 0;                       /* -N lines (default 20); -c N = last N bytes */
            if (*p == '-' && p[1] == 'c') { bytes = 1; p += 2; while (*p == ' ') p++; cnt = 0; while (*p >= '0' && *p <= '9' && cnt < 100000000) cnt = cnt * 10 + (*p++ - '0'); if (cnt < 1) cnt = 20; while (*p == ' ') p++; }
            else if (*p == '-' && p[1] >= '0' && p[1] <= '9') { p++; cnt = 0; while (*p >= '0' && *p <= '9' && cnt < 100000000) cnt = cnt * 10 + (*p++ - '0'); if (cnt < 1) cnt = 20; while (*p == ' ') p++; }
            const char *cq = p; int fc = 0;
            while (*cq) { while (*cq == ' ') cq++; if (!*cq) break; fc++; while (*cq && *cq != ' ') cq++; }
            int any = 0;
            while (*p) {                                   /* last 20 lines of each space-separated file */
                while (*p == ' ') p++;
                if (!*p) break;
                char name[64]; int j = 0;
                while (*p && *p != ' ' && j < 63) name[j++] = *p++;
                name[j] = '\0'; sh_unprot_buf(name); any = 1;
                long n; char *buf = slurp(name, &n);
                if (!buf) { perr("tail: no such file: "); print(name); print("\n"); continue; }
                if (fc > 1) { print("==> "); print(name); print(" <==\n"); }
                buf[n] = '\0';
                if (bytes) {                                  /* -c: last cnt bytes */
                    int start = (int)(n > cnt ? n - cnt : 0);
                    print(buf + start);
                } else {
                    int total = 0;
                    for (int i = 0; i < n; i++) if (buf[i] == '\n') total++;
                    if (n > 0 && buf[n - 1] != '\n') total++;
                    int skip = total > cnt ? total - cnt : 0;     /* keep the last cnt lines */
                    int i = 0, sk = 0;
                    while (i < n && sk < skip) { if (buf[i++] == '\n') sk++; }
                    print(buf + i);
                }
                free(buf);
            }
            if (!any) print("usage: tail <file>...\n");
        } else if (startswith(line, "tac ")) {           /* print a file's lines in reverse order */
            long n; char *buf = slurp(line + 4, &n);
            if (!buf) { perr("tac: no such file: "); print(line + 4); print("\n"); }
            else {
                buf[n] = 0;
                int cap = 1; for (long i = 0; i < n; i++) if (buf[i] == '\n') cap++;   /* one slot per line (was fixed 1024) */
                int *starts = malloc((unsigned long)cap * sizeof(int));
                if (!starts) perr("tac: out of memory\n");
                else {
                    int ns = 0; starts[ns++] = 0;
                    for (long i = 0; i < n; i++) if (buf[i] == '\n' && ns < cap) starts[ns++] = (int)(i + 1);
                    for (int k = ns - 1; k >= 0; k--) {
                        int s = starts[k]; if (s >= (int)n) continue;     /* skip empty trailing line */
                        int e = s; while (e < (int)n && buf[e] != '\n') e++;
                        char save = buf[e]; buf[e] = 0;
                        print(buf + s); print("\n");
                        buf[e] = save;
                    }
                    free(starts);
                }
                free(buf);
            }
        } else if (startswith(line, "uniq ")) {           /* drop adjacent duplicate lines; -c prefixes a run count */
            const char *fp = line + 5; int countf = 0, dflag = 0, uflag = 0;   /* -c count, -d only duplicated runs, -u only non-repeated runs */
            while (*fp == ' ') fp++;
            while (fp[0] == '-' && fp[1] && fp[1] != ' ') {
                int t, valid = 1;
                for (t = 1; fp[t] && fp[t] != ' '; t++) if (fp[t] != 'c' && fp[t] != 'd' && fp[t] != 'u') valid = 0;
                if (!valid) break;                          /* not a flag token (e.g. a filename) */
                for (t = 1; fp[t] && fp[t] != ' '; t++) { if (fp[t] == 'c') countf = 1; else if (fp[t] == 'd') dflag = 1; else uflag = 1; }
                fp += t; while (*fp == ' ') fp++;
            }
            long n; char *buf = slurp(fp, &n);
            if (!buf) { perr("uniq: no such file: "); print(fp); print("\n"); }
            else {
                buf[n] = 0;
                int rs = -1, rl = 0, ls = 0, count = 0;    /* current run's first line [rs,rs+rl); occurrence count */
                for (long k = 0; k <= n; k++) {
                    if (k == n || buf[k] == '\n') {
                        int len = (int)(k - ls);
                        if (k == n && len == 0) break;      /* no trailing empty line */
                        int same = (rs >= 0 && rl == len);
                        if (same) for (int j = 0; j < len; j++) if (buf[ls + j] != buf[rs + j]) { same = 0; break; }
                        if (same) count++;
                        else {
                            if (rs >= 0 && (dflag ? count > 1 : uflag ? count == 1 : 1)) {  /* emit the ended run (-d: dups only, -u: non-repeated only) */
                                char save = buf[rs + rl]; buf[rs + rl] = 0;
                                if (countf) { char cb[12]; itoa_simple(count, cb); print("  "); print(cb); print(" "); }
                                print(buf + rs); print("\n");
                                buf[rs + rl] = save;
                            }
                            rs = ls; rl = len; count = 1;
                        }
                        ls = (int)k + 1;
                    }
                }
                if (rs >= 0 && (dflag ? count > 1 : uflag ? count == 1 : 1)) {   /* emit the final run (-d/-u filter) */
                    char save = buf[rs + rl]; buf[rs + rl] = 0;
                    if (countf) { char cb[12]; itoa_simple(count, cb); print("  "); print(cb); print(" "); }
                    print(buf + rs); print("\n");
                    buf[rs + rl] = save;
                }
                free(buf);
            }
        } else if (startswith(line, "seq ")) {             /* seq [first [incr]] last -> one number per line */
            const char *p = line + 4; while (*p == ' ') p++;
            long arg[3]; int na = 0;
            while (*p && na < 3) {
                int neg = 0; if (*p == '-') { neg = 1; p++; }
                if (*p < '0' || *p > '9') break;
                long v = 0; while (*p >= '0' && *p <= '9') v = v * 10 + (*p++ - '0');
                arg[na++] = neg ? -v : v;
                while (*p == ' ') p++;
            }
            long first = 1, incr = 1, last = 0;
            if (na == 1) last = arg[0];
            else if (na == 2) { first = arg[0]; last = arg[1]; }
            else if (na == 3) { first = arg[0]; incr = arg[1]; last = arg[2]; }
            if (na < 1 || na > 3 || incr == 0) { print("usage: seq [first [incr]] last\n"); }
            else {
                char num[16]; long cnt = 0;
                for (long v = first; (incr > 0) ? (v <= last) : (v >= last); v += incr) {
                    if (++cnt > 1000000) break;             /* safety cap on output */
                    itoa_simple((int)v, num); print(num); print("\n");
                }
            }
        } else if (startswith(line, "sort ")) {
            const char *fp = line + 5; int rev = 0, nsort = 0, uniq_f = 0, fold = 0, kf = 0; char sdelim = 0;  /* -r rev, -n num, -u uniq, -f fold, -kN field N, -tX delim */
            while (*fp == ' ') fp++;
            while (fp[0] == '-' && fp[1] && fp[1] != ' ') {
                if (fp[1] == 'k') {                         /* -kN / -k N : sort by field N (compared to end of line) */
                    fp += 2; while (*fp == ' ') fp++;
                    kf = 0; while (*fp >= '0' && *fp <= '9') kf = kf * 10 + (*fp++ - '0');
                    if (kf < 1) kf = 1;
                    while (*fp == ' ') fp++;
                    continue;
                }
                if (fp[1] == 't') {                         /* -tX / -t X : field delimiter for -k (default: whitespace) */
                    fp += 2; while (*fp == ' ') fp++;
                    if (*fp) sdelim = *fp++;
                    while (*fp == ' ') fp++;
                    continue;
                }
                int t, valid = 1;
                for (t = 1; fp[t] && fp[t] != ' '; t++) if (fp[t] != 'r' && fp[t] != 'n' && fp[t] != 'u' && fp[t] != 'f') valid = 0;
                if (!valid) break;                          /* not a flag token (e.g. a filename) */
                for (t = 1; fp[t] && fp[t] != ' '; t++) { if (fp[t] == 'r') rev = 1; else if (fp[t] == 'n') nsort = 1; else if (fp[t] == 'u') uniq_f = 1; else fold = 1; }
                fp += t; while (*fp == ' ') fp++;
            }
            long n; char *buf = slurp(fp, &n);
            if (!buf) { perr("sort: no such file: "); print(fp); print("\n"); }
            else {
                buf[n] = '\0';
                int cap = 1; for (long i = 0; i < n; i++) if (buf[i] == '\n') cap++;   /* one slot per line (was fixed at 128) */
                char **lns = malloc((unsigned long)cap * sizeof(char *));
                if (!lns) perr("sort: out of memory\n");
                else {
                    int nl = 0; char *p = buf;
                    while (*p && nl < cap) {                       /* split into lines */
                        lns[nl++] = p;
                        while (*p && *p != '\n') p++;
                        if (*p == '\n') *p++ = '\0';
                    }
                    for (int i = 1; i < nl; i++) {                 /* insertion sort (byte order) */
                        char *key = lns[i]; int j = i - 1;
                        while (j >= 0) {
                            int cmp;
                            const char *ka = kf ? sort_field(lns[j], kf, sdelim) : lns[j];   /* -kN: compare starting at field N */
                            const char *kb = kf ? sort_field(key, kf, sdelim) : key;
                            if (nsort) {                       /* -n: compare by leading integer value */
                                long va = sort_numval(ka), vb = sort_numval(kb);
                                cmp = (va < vb) ? -1 : (va > vb) ? 1 : 0;
                            } else if (fold) {                 /* -f: case-insensitive byte order */
                                const char *a = ka, *b = kb;
                                while (*a && gr_lc(*a) == gr_lc(*b)) { a++; b++; }
                                cmp = (int)(unsigned char)gr_lc(*a) - (int)(unsigned char)gr_lc(*b);
                            } else {                           /* byte order */
                                const char *a = ka, *b = kb;
                                while (*a && *a == *b) { a++; b++; }
                                cmp = (int)(unsigned char)*a - (int)(unsigned char)*b;
                            }
                            if (rev) cmp = -cmp;
                            if (cmp <= 0) break;                   /* lns[j] already in order vs key */
                            lns[j+1] = lns[j]; j--;
                        }
                        lns[j+1] = key;
                    }
                    const char *prevl = 0;
                    for (int i = 0; i < nl; i++) {
                        if (uniq_f && prevl && (fold ? sort_foldeq(prevl, lns[i]) : streq(prevl, lns[i]))) continue;   /* -u: drop adjacent duplicates (-f: case-insensitively) */
                        print(lns[i]); print("\n");
                        prevl = lns[i];
                    }
                    free(lns);
                }
                free(buf);
            }
        } else if (startswith(line, "tr ")) {              /* tr -d SET FILE (delete) | tr -s SET FILE (squeeze) | tr SET1 SET2 FILE (translate); SETs take a-z ranges */
            const char *p = line + 3; while (*p == ' ') p++;
            if (p[0] == '-' && p[1] == 'd' && p[2] == ' ') {
                p += 3; while (*p == ' ') p++;
                char del[128]; int dn = tr_expand(&p, del, 128);   /* SET to delete (chars + ranges) */
                for (int z = 0; z < dn; z++) del[z] = SH_UNPROT(del[z]);   /* a quoted SET char (tr -d ' ') is protected */
                while (*p == ' ') p++;
                long n; char *buf = slurp(p, &n);
                if (!buf) { perr("tr: no such file: "); print(p); print("\n"); }
                else {
                    long oi = 0;
                    for (long i = 0; i < n; i++) {
                        int drop = 0;
                        for (int j = 0; j < dn; j++) if (buf[i] == del[j]) { drop = 1; break; }
                        if (!drop) buf[oi++] = buf[i];          /* compact in place (oi <= i) */
                    }
                    buf[oi] = 0; print(buf); free(buf);
                }
            } else if (p[0] == '-' && p[1] == 's' && p[2] == ' ') {   /* tr -s SET FILE: squeeze runs of a repeated SET char to one (M1825) */
                p += 3; while (*p == ' ') p++;
                char sq[128]; int sn = tr_expand(&p, sq, 128);
                for (int z = 0; z < sn; z++) sq[z] = SH_UNPROT(sq[z]);
                while (*p == ' ') p++;
                long n; char *buf = slurp(p, &n);
                if (!buf) { perr("tr: no such file: "); print(p); print("\n"); }
                else {
                    long oi = 0; int prev_in = 0; char prev = 0;
                    for (long i = 0; i < n; i++) {
                        int in_set = 0;
                        for (int j = 0; j < sn; j++) if (buf[i] == sq[j]) { in_set = 1; break; }
                        if (in_set && prev_in && buf[i] == prev) continue;   /* collapse a repeat of the same SET char */
                        buf[oi++] = buf[i]; prev_in = in_set; prev = buf[i];
                    }
                    buf[oi] = 0; print(buf); free(buf);
                }
            } else {
                char s1[128], s2[128];
                int n1 = tr_expand(&p, s1, 128); while (*p == ' ') p++;   /* SET1 */
                int n2 = tr_expand(&p, s2, 128); while (*p == ' ') p++;   /* SET2 (shorter set: last char repeats) */
                for (int z = 0; z < n1; z++) s1[z] = SH_UNPROT(s1[z]);    /* reveal quoted SET chars (tr ' ' _) */
                for (int z = 0; z < n2; z++) s2[z] = SH_UNPROT(s2[z]);
                long n; char *buf = slurp(p, &n);
                if (!buf || n1 == 0 || n2 == 0) { print("usage: tr SET1 SET2 FILE  |  tr -d SET FILE  |  tr -s SET FILE   (SETs: chars or a-z ranges)\n"); if (buf) free(buf); }
                else {
                    buf[n] = 0;
                    for (long i = 0; i < n; i++)
                        for (int j = 0; j < n1; j++) if (buf[i] == s1[j]) { buf[i] = s2[j < n2 ? j : n2 - 1]; break; }
                    print(buf); free(buf);
                }
            }
        } else if (startswith(line, "sed ")) {            /* sed [-i] 's/RE/REPL/[gi]' [file] : regex stream substitution (RE like grep: ^ $ . * [..] \) */
            const char *p = line + 4; while (*p == ' ') p++;
            int inplace = 0;                              /* sed -i FILE : rewrite the file in place instead of printing (M1810) */
            if (p[0] == '-' && p[1] == 'i' && (p[2] == ' ' || p[2] == 0)) { inplace = 1; p += 2; while (*p == ' ') p++; }
            char scr[256]; int sn = 0;                    /* the script (first arg; a quoted script's spaces arrive sentinel-protected) */
            while (*p && *p != ' ' && sn < (int)sizeof(scr) - 1) scr[sn++] = SH_UNPROT(*p++);
            scr[sn] = 0;
            while (*p == ' ') p++;                         /* the rest is the file (a pipe appends PIPE.TMP) */
            char fname[160]; int fni = 0; { const char *fp = p; while (*fp && fni < 159) fname[fni++] = SH_UNPROT(*fp++); } fname[fni] = 0;   /* unprotected file path for -i write-back */
            while (fni > 0 && fname[fni-1] == ' ') fname[--fni] = 0;
            if (scr[0] != 's' || sn < 4) { print("usage: sed [-i] 's/RE/REPL/[gi]' [file]   (-i edits in place; RE: ^ $ . * [..] \\)\n"); g_status = 2; }
            else if (inplace && !fname[0]) { print("sed: -i needs a file\n"); g_status = 2; }
            else {
                char delim = scr[1];
                char re[160], repl[160]; int rn = 0, pn = 0;
                const char *q = scr + 2;
                while (*q && *q != delim && rn < (int)sizeof(re) - 2) {             /* RE up to the delimiter */
                    if (*q == '\\' && q[1] == delim) { re[rn++] = delim; q += 2; }       /* \<delim> -> literal delim */
                    else if (*q == '\\' && q[1]) { re[rn++] = '\\'; re[rn++] = q[1]; q += 2; }  /* keep \. \* \[ for the regex */
                    else re[rn++] = *q++;
                }
                re[rn] = 0; if (*q == delim) q++;
                while (*q && *q != delim && pn < (int)sizeof(repl) - 2) {           /* REPL up to the delimiter (escapes kept; sed_sub expands them) */
                    if (*q == '\\' && q[1]) { repl[pn++] = '\\'; repl[pn++] = q[1]; q += 2; }
                    else repl[pn++] = *q++;
                }
                repl[pn] = 0; if (*q == delim) q++;
                int g = 0, ci = 0;
                for (; *q; q++) { if (*q == 'g') g = 1; else if (*q == 'i' || *q == 'I') ci = 1; }
                if (re[0] == '^') g = 0;                   /* ^ anchors to line start, so substitute once per line */
                long n; char *buf = slurp(p, &n);
                if (!buf) { perr("sed: no such file: "); print(p); print("\n"); g_status = 2; }
                else {
                    char *out = 0; long outlen = 0, outcap = 0;   /* -i: accumulate the whole result, then write it back */
                    long i = 0;
                    while (i < n) {                        /* one line at a time, flushed (no whole-output cap) */
                        long ls = i; while (i < n && buf[i] != '\n') i++;
                        int had_nl = (i < n);
                        char saved = buf[i]; buf[i] = 0;
                        long osz = (i - ls + 1) * (pn + 2) + 64;   /* generous; sed_sub is bounds-safe regardless */
                        if (osz > (1L << 20)) osz = 1L << 20;
                        char *ob = malloc(osz);
                        if (ob) {
                            sed_sub(buf + ls, re, repl, g, ci, ob, osz);
                            if (inplace) {                 /* grow `out` and append this line + its newline */
                                long oblen = (long)ustrlen(ob), need = outlen + oblen + 2;
                                if (need > outcap) { outcap = need + (need >> 1) + 256; char *no = realloc(out, (unsigned long)outcap); if (no) out = no; }
                                if (out && outcap >= need) { for (long k = 0; k < oblen; k++) out[outlen++] = ob[k]; if (had_nl) out[outlen++] = '\n'; }
                            } else { print(ob); if (had_nl) print("\n"); }
                            free(ob);
                        } else if (!inplace && had_nl) print("\n");   /* OOM: preserve the blank line for the stream form */
                        buf[i] = saved;
                        if (!had_nl) break;
                        i++;
                    }
                    if (inplace) {                         /* write the transformed file back over itself */
                        if (sys_writefile(fname, out ? out : "", (unsigned long)outlen) < 0) { perr("sed: cannot write: "); print(fname); print("\n"); g_status = 2; }
                        free(out);
                    }
                    free(buf);
                }
            }
        } else if (startswith(line, "fold ")) {           /* fold [-w]N FILE : wrap each line at N columns (default 60) */
            const char *p = line + 5; while (*p == ' ') p++;
            int w = 0;
            if (p[0] == '-' && p[1] == 'w') p += 2;
            while (*p >= '0' && *p <= '9') w = w * 10 + (*p++ - '0');
            while (*p == ' ') p++;
            if (w < 1) w = 60;
            if (w > 200) w = 200;
            long n; char *buf = slurp(p, &n);
            if (!buf) { perr("fold: no such file: "); print(p); print("\n"); }
            else {
                buf[n] = 0;
                char lbuf[202]; int li = 0, col = 0;       /* one physical line at a time (w <= 200) — flushed as we go, so no whole-output cap */
                for (long i = 0; i < n; i++) {
                    char c = buf[i];
                    if (c == '\n') { lbuf[li] = 0; print(lbuf); print("\n"); li = 0; col = 0; continue; }
                    lbuf[li++] = c; col++;
                    if (col >= w) { lbuf[li] = 0; print(lbuf); print("\n"); li = 0; col = 0; }
                }
                if (li > 0) { lbuf[li] = 0; print(lbuf); print("\n"); }   /* trailing partial line */
                free(buf);
            }
        } else if (startswith(line, "cut ")) {            /* cut -cN[-M] FILE (char range) | cut -fN[-M] [-dX] FILE (delimited fields, default tab) */
            const char *p = line + 4;
            int mode = 0, nr = 0; int rfrom[8], rto[8], roe[8]; char delim = '\t';
            while (1) {                                    /* parse leading -c/-f/-d flags, any order */
                while (*p == ' ') p++;
                if (*p != '-') break;
                char fl = p[1]; p += 2;
                if (fl == 'c' || fl == 'f') {              /* -cLIST / -fLIST : comma list of N or N-M ranges (e.g. 1,3-5) */
                    mode = fl; nr = 0;
                    for (;;) {
                        int rf = 0, rt = 0, oe = 0;
                        while (*p >= '0' && *p <= '9') { if (rf < 100000000) rf = rf * 10 + (*p - '0'); p++; }   /* cap: no int overflow on absurd N */
                        if (*p == '-') { p++; if (*p >= '0' && *p <= '9') { while (*p >= '0' && *p <= '9') { if (rt < 100000000) rt = rt * 10 + (*p - '0'); p++; } } else oe = 1; }
                        else rt = rf;                      /* N alone = just that column/field */
                        if (rf < 1) rf = 1;
                        if (nr < 8) { rfrom[nr] = rf; rto[nr] = rt; roe[nr] = oe; nr++; }
                        if (*p == ',') p++; else break;    /* another range in the list? */
                    }
                } else if (fl == 'd') { if (*p) delim = SH_UNPROT(*p++); }   /* single-char field delimiter (may be a quoted space: cut -d' ') */
                else break;                                /* unknown flag */
            }
            while (*p == ' ') p++;
            if ((mode != 'c' && mode != 'f') || nr == 0) { print("usage: cut -cLIST <file>  |  cut -fLIST [-dX] <file>   (LIST: N, N-M, or 1,3-5; fields default to tab)\n"); }
            else {
                long n; char *buf = slurp(p, &n);
                if (!buf) { perr("cut: no such file: "); print(p); print("\n"); }
                else {
                    buf[n] = 0;
                    char out[256]; int oi = 0, col = 0, field = 1, dirty = 0, out_any = 0;
                    for (long k = 0; k < n; k++) {
                        char c = buf[k];
                        if (c == '\n') { out[oi] = 0; print(out); print("\n"); oi = 0; col = 0; field = 1; dirty = 0; out_any = 0; continue; }
                        dirty = 1;
                        if (mode == 'c') {                            /* char list */
                            col++;
                            if (cut_sel(col, rfrom, rto, roe, nr) && oi < 255) out[oi++] = c;
                        } else if (c == delim) {                      /* field sep: emit the output delim before the NEXT selected field — joins non-adjacent fields and keeps empty ones */
                            field++;
                            if (cut_sel(field, rfrom, rto, roe, nr) && out_any && oi < 255) out[oi++] = delim;
                        } else if (cut_sel(field, rfrom, rto, roe, nr) && oi < 255) {
                            out[oi++] = c; out_any = 1;               /* field content */
                        }
                    }
                    if (dirty) { out[oi] = 0; print(out); print("\n"); }   /* trailing line w/o newline */
                }
                free(buf);
            }
        } else if (streq(line, "js") || startswith(line, "js ")) {
            static char src[8192];                   /* demo / inline code (the shell line is <=128 bytes) */
            char *jsrc = src, *filesrc = 0;
            int have = 0;
            if (streq(line, "js")) {                 /* no file: run a built-in demo */
                const char *demo =
                    "print(\"Hello from from-scratch JavaScript!\");\n"
                    "function fib(n){ return n<2 ? n : fib(n-1)+fib(n-2); }\n"
                    "var s=\"fib: \"; for (var i=0;i<12;i++) s+=fib(i)+\" \"; print(s);\n"
                    "var a=[3,1,2]; a.push(4); print(\"array: len \"+a.length+\" = [\"+a.join(\",\")+\"]\");\n"
                    "print(\"arrows: \"+[1,2,3,4,5].map(x=>x*x).filter(x=>x>4).join(\",\"));\n"
                    "var o={name:\"OS-DEV\", year:2026}; print(o.name+\" \"+o.year);\n"
                    "function fact(n){ return n<=1?1:n*fact(n-1); } print(\"6! = \"+fact(6));\n"
                    "print(\"2^10 = \"+(1<<10)+\", 17%5 = \"+(17%5));\n"
                    "class Money{ constructor(c){ this.c=c; } toString(){ return \"$\"+this.c; } }\n"
                    "print(\"toString: \"+new Money(42));\n"
                    "var temp={valueOf:function(){return 20;}}; print(\"valueOf: \"+(temp*2+5));\n"
                    "var dm=\"2026-06-18\".match(/(?<y>\\d+)-(?<mo>\\d+)/); print(\"regex groups: \"+dm.groups.y+\"/\"+dm.groups.mo);\n"
                    "print(\"json reviver: \"+JSON.parse('{\"n\":21}',function(k,v){return typeof v==\"number\"?v*2:v;}).n);\n";
                int i = 0; while (demo[i] && i < (int)sizeof(src) - 1) { src[i] = demo[i]; i++; } src[i] = 0;
                have = 1;
            } else if (startswith(line, "js -e ")) {     /* inline: js -e <code> */
                const char *code = line + 6;
                int i = 0; while (code[i] && i < (int)sizeof(src) - 1) { src[i] = code[i]; i++; } src[i] = 0;
                have = 1;
            } else {
                sh_unprot_buf(line + 3);                 /* quoted JS filename (e.g. js "my prog.js") */
                long n; filesrc = slurp(line + 3, &n);   /* whole JS file (was capped at 8KB) */
                if (!filesrc) { perr("js: no such file: "); print(line + 3); print("\n"); }
                else { jsrc = filesrc; have = 1; }
            }
            if (have) {
                char *out = malloc(1u << 20);            /* 1MB JS output buffer (was 8KB) */
                if (out) {
                    /* Run JS in RING 3 via the jsrun program (the JS engine is no longer
                     * executed in the kernel for the shell path): hand it the source via
                     * JSIN.JS, wait for it, read back its JSOUT.TXT. Fall back to the
                     * in-kernel SYS_js only if the spawn fails. */
                    long jl = 0; while (jsrc[jl]) jl++;
                    long pid = -1;
                    if (sys_writefile("JSIN.JS", jsrc, (unsigned long)jl) >= 0) {
                        pid = sys_fork();                     /* fork sets us as parent so waitpid blocks */
                        if (pid == 0) { sys_exec("jsrun", 0); sys_exit(1); }   /* child becomes jsrun (ring 3) */
                    }
                    if (pid > 0) {
                        int st = 0; sys_waitpid((int)pid, &st);               /* block until jsrun exits */
                        long n = sys_readfile("JSOUT.TXT", out, (1u << 20) - 1);
                        if (n < 0) n = 0;
                        out[n] = 0; print(out);
                    } else {                                  /* fork/write failed: in-kernel fallback */
                        sys_js(jsrc, out, (1u << 20) - 1); out[(1u << 20) - 1] = 0; print(out);
                    }
                    free(out);
                }
                else perr("js: out of memory\n");
            }
            free(filesrc);                               /* free(NULL) safe */
        } else if (streq(line, "beep")) {
            sys_beep(880, 150);
            print("beep!\n");
        } else if (startswith(line, "morse ")) {
            /* print AND beep the Morse code for the text (a-z, 0-9, space) */
            static const char *M[36] = {
                ".-","-...","-.-.","-..",".","..-.","--.","....","..",".---","-.-",".-..","--",
                "-.","---",".--.","--.-",".-.","...","-","..-","...-",".--","-..-","-.--","--..",
                "-----",".----","..---","...--","....-",".....","-....","--...","---..","----."
            };
            sh_unprot_buf(line + 6);
            for (const char *p = line + 6; *p; p++) {
                char c = *p;
                if (c >= 'A' && c <= 'Z') c += 32;
                const char *code = 0;
                if (c >= 'a' && c <= 'z') code = M[c - 'a'];
                else if (c >= '0' && c <= '9') code = M[26 + c - '0'];
                else if (c == ' ') { print("  "); sys_sleep(400); continue; }
                if (!code) continue;
                print(code); print(" ");
                for (const char *s = code; *s; s++) {
                    sys_beep(700, *s == '-' ? 240 : 80);   /* dash long, dot short */
                    sys_sleep(80);                          /* intra-character gap */
                }
                sys_sleep(150);                             /* inter-character gap */
            }
            print("\n");
        } else if (startswith(line, "factor ")) {
            const char *q = line + 7; while (*q == ' ') q++;
            long n = 0; int any = 0;
            while (*q >= '0' && *q <= '9' && n < 900000000000000000L) { n = n * 10 + (*q - '0'); q++; any = 1; }   /* bound so n*10+digit can't overflow long */
            if (!any || n < 2) { print("usage: factor <n>  (n >= 2)\n"); }
            else {
                printl(n); print(":");
                long m = n;
                while (m % 2 == 0) { print(" 2"); m /= 2; }
                for (long d = 3; d <= 3000000L && d <= m / d; d += 2)   /* trial division to ~sqrt, capped */
                    while (m % d == 0) { print(" "); printl(d); m /= d; }
                if (m > 1) { print(" "); printl(m); }                  /* remaining prime (or a large factor) */
                print("\n");
            }
        } else if (startswith(line, "roll ")) {
            const char *q = line + 5; while (*q == ' ') q++;
            int a = 0; while (*q >= '0' && *q <= '9' && a < 100000000) { a = a * 10 + (*q - '0'); q++; }
            int n, sides;
            if (*q == 'd' || *q == 'D') { q++; sides = 0; while (*q >= '0' && *q <= '9' && sides < 100000000) { sides = sides * 10 + (*q - '0'); q++; } n = a ? a : 1; }
            else { n = 1; sides = a; }                         /* "roll 6" = 1d6 */
            if (n < 1) n = 1; if (n > 40) n = 40;
            if (sides < 2 || sides > 1000) { print("usage: roll NdM  (e.g. roll 2d6)\n"); }
            else {
                int total = 0; char nb[12]; print(" ");
                for (int i = 0; i < n; i++) { int r = (int)(shroll() % (unsigned)sides) + 1; total += r; itoa_simple(r, nb); print(nb); print(" "); }
                if (n > 1) { print(" total "); itoa_simple(total, nb); print(nb); }
                print("\n");
            }
        } else if (startswith(line, "rev ")) {
            char *t = line + 4; sh_unprot_buf(t);
            char r[128]; int len = 0; while (t[len] && len < 127) len++;
            for (int i = 0; i < len; i++) r[i] = t[len - 1 - i];
            r[len] = 0;
            print(r); print("\n");
        } else if (startswith(line, "seq ")) {
            const char *q = line + 4; while (*q == ' ') q++;
            int m = 0; while (*q >= '0' && *q <= '9' && m < 100000) { m = m * 10 + (*q - '0'); q++; }
            if (m < 1) print("usage: seq <n>  (prints 1..n)\n");
            else {
                if (m > 1000) m = 1000;                /* cap the output */
                char nb[12]; print(" ");
                for (int i = 1; i <= m; i++) { itoa_simple(i, nb); print(nb); print(" "); }
                print("\n");
            }
        } else if (streq(line, "todo") || startswith(line, "todo ")) {
            static char buf[16384];   /* read-modify-write list: generous so edits don't truncate it (~400 items) */
            long n = sys_readfile("TODO.TXT", buf, sizeof(buf) - 1);
            if (n < 0) n = 0;
            buf[n] = 0;
            if (startswith(line, "todo add ")) {                  /* append a new item */
                const char *t = line + 9; while (*t == ' ') t++;
                if (!*t) print("usage: todo add <text>\n");
                else {
                    int p = (int)n;
                    const char *pre = "[ ] ";
                    for (int i = 0; pre[i] && p < (int)sizeof(buf) - 2; i++) buf[p++] = pre[i];
                    for (; *t && p < (int)sizeof(buf) - 2; t++) buf[p++] = *t;
                    buf[p++] = '\n'; buf[p] = 0;
                    sys_writefile("TODO.TXT", buf, (unsigned long)p);
                    print("added.\n");
                }
            } else if (startswith(line, "todo done ")) {          /* toggle item N's checkbox */
                int target = 0; const char *d = line + 10; while (*d == ' ') d++;
                while (*d >= '0' && *d <= '9') target = target * 10 + (*d++ - '0');
                int item = 0, found = 0;
                for (int i = 0; i < (int)n; ) {
                    int ls = i; while (i < (int)n && buf[i] != '\n') i++;
                    if (++item == target && i - ls >= 3 && buf[ls] == '[' && buf[ls + 2] == ']') {
                        buf[ls + 1] = (buf[ls + 1] == 'x') ? ' ' : 'x';
                        found = 1;
                    }
                    if (i < (int)n) i++;
                }
                if (found) { sys_writefile("TODO.TXT", buf, (unsigned long)n); print("toggled.\n"); }
                else print("todo: no such item\n");
            } else if (streq(line, "todo clear")) {               /* drop completed ([x]) items */
                int w = 0;
                for (int i = 0; i < (int)n; ) {
                    int ls = i; while (i < (int)n && buf[i] != '\n') i++;
                    int le = i; if (i < (int)n) i++;
                    if (!(le - ls >= 3 && buf[ls] == '[' && buf[ls + 1] == 'x' && buf[ls + 2] == ']')) {
                        for (int j = ls; j < le; j++) buf[w++] = buf[j];   /* compact in place (w <= ls) */
                        buf[w++] = '\n';
                    }
                }
                buf[w] = 0;
                sys_writefile("TODO.TXT", buf, (unsigned long)w);
                print("cleared completed items.\n");
            } else {                                              /* list */
                if (n == 0) print("  (empty; add with: todo add <text>)\n");
                else {
                    int item = 0;
                    for (int i = 0; i < (int)n; ) {
                        int ls = i; while (i < (int)n && buf[i] != '\n') i++;
                        char save = buf[i]; buf[i] = 0;
                        char num[8]; itoa_simple(++item, num);
                        print("  "); print(num); print(". "); print(buf + ls); print("\n");
                        buf[i] = save;
                        if (i < (int)n) i++;
                    }
                }
            }
        } else if (streq(line, "ifconfig") || streq(line, "netinfo")) {
            char info[128];
            if (sys_netinfo(info, sizeof(info)) > 0) print(info);
            else print("ifconfig: unavailable\n");
        } else if (streq(line, "dhcp")) {            /* lease IP/gateway/DNS from the DHCP server (DORA) */
            print("dhcp: requesting a lease (DISCOVER -> OFFER -> REQUEST -> ACK)...\n");
            if (sys_dhcp() < 0) { print("dhcp: no response from a DHCP server\n"); g_status = 1; }
            else {
                print("dhcp: lease acquired. new configuration:\n");
                char info[128];
                if (sys_netinfo(info, sizeof(info)) > 0) print(info);
            }
        } else if (startswith(line, "tftp get ")) {   /* tftp get REMOTE [LOCAL] -- fetch a file over TFTP from the gateway */
            const char *a = line + 9; while (*a == ' ') a++;
            char remote[96]; int j = 0; while (*a && *a != ' ' && j < 95) remote[j++] = *a++; remote[j] = 0; sh_unprot_buf(remote);
            while (*a == ' ') a++;
            char local[96]; int k = 0; while (*a && *a != ' ' && k < 95) local[k++] = *a++; local[k] = 0; sh_unprot_buf(local);
            unsigned long cap = 1u << 20; char *buf = malloc(cap);   /* up to 1 MiB */
            long n = buf ? sys_tftp(remote, buf, cap - 1) : -1;
            if (n < 0) { print("tftp: transfer failed (no server / not found / too big)\n"); g_status = 1; }
            else if (local[0]) {
                if (sys_writefile(local, buf, (unsigned long)n) < 0) { print("tftp: cannot write "); print(local); print("\n"); g_status = 1; }
                else { print("tftp: saved "); printl(n); print(" bytes to "); print(local); print("\n"); }
            } else { buf[n] = 0; print(buf); }
            free(buf);
        } else if (streq(line, "fw") || startswith(line, "fw ")) {   /* packet filter: `fw` lists, `fw <verb>` adds/flushes a rule */
            if (streq(line, "fw")) {
                long n; char *b = slurp("/proc/fw", &n);
                if (b) { print(b); free(b); } else print("fw: unavailable\n");
            } else {
                const char *v = line + 3; while (*v == ' ') v++;
                if (sys_writefile("/proc/fw", v, ustrlen(v)) < 0) print("fw: bad rule (try: fw drop in icmp | fw allow out tcp 80 | fw flush)\n");
                else { long n; char *b = slurp("/proc/fw", &n); if (b) { print(b); free(b); } }
            }
        } else if (streq(line, "ping")) {
            long n = sys_ping();
            if (n < 0) print("ping: no network\n");
            else {
                char c[2] = { (char)('0' + (int)n), 0 };
                print("gateway 10.0.2.2: "); print(c); print("/3 replies\n");
            }
        } else if (startswith(line, "ping ")) {
            /* ping a host by name: resolve (also shows the IP), then ICMP-echo */
            char host[64]; char *p = line + 5; while (*p == ' ') p++;
            int i = 0; while (*p && *p != ' ' && i < 63) host[i++] = *p++; host[i] = 0; sh_unprot_buf(host);
            if (host[0] == 0) { print("usage: ping <host>\n"); }
            else {
                char ip[40];
                if (sys_resolve(host, ip, sizeof(ip)) < 0) { perr("ping: cannot resolve "); print(host); print("\n"); }
                else {
                    for (int k = 0; ip[k]; k++) if (ip[k] == '\n') ip[k] = 0;   /* inline the IP */
                    print("PING "); print(host); print(" ("); print(ip); print(") ...\n");
                    long n = sys_ping_host(host);
                    if (n < 0) print("ping: no route to host\n");
                    else { char c[2] = { (char)('0' + (int)n), 0 }; print(c); print("/3 echo replies\n"); }
                }
            }
        } else if (startswith(line, "resolve ")) {
            char ip[40]; sh_unprot_buf(line + 8);
            if (sys_resolve(line + 8, ip, sizeof(ip)) < 0) perr("resolve: failed\n");
            else { print(line + 8); print(" -> "); print(ip); }
        } else if (streq(line, "pwd")) {
            print(cwd); print("\n");
        } else if (streq(line, "true")) {
            /* exit status 0 (already set) — useful with && / || */
        } else if (streq(line, "false")) {
            g_status = 1;                          /* exit status 1 — useful with && / || */
        } else if (startswith(line, "test ") || (line[0] == '[' && line[1] == ' ')) {
            /* test EXPR / [ EXPR ] -> set $? (0 = true). Args are already
             * variable-expanded by run_line. The evaluator (sh_test_eval in
             * shtest.h, host-tested by tests/shtest) handles STR (non-empty),
             * -z/-n STR, -e/-f/-d/-s/-r/-w/-x FILE, A OP B (= == != -eq..-ge),
             * a leading ! (negate), and -a (AND) / -o (OR) combiners. */
            const char *p = line + (line[0] == '[' ? 1 : 4);
            char *av[16]; static char tok[256]; int ac = 0, ti = 0;
            while (*p && ac < 16) {
                while (*p == ' ') p++;
                if (!*p) break;
                if (ti >= 255) break;        /* no room for another token + its NUL: stop (else tok[ti++]=0 writes past tok[256] + stores a dangling av[]) */
                av[ac++] = tok + ti;
                while (*p && *p != ' ' && ti < 255) tok[ti++] = *p++;
                tok[ti++] = 0;
            }
            for (int i = 0; i < ac; i++) sh_unprot_buf(av[i]);            /* restore quoted bytes in each arg */
            if (line[0] == '[' && ac > 0 && streq(av[ac-1], "]")) ac--;   /* drop closing ] */
            g_status = sh_test_eval(av, ac, cwd) ? 0 : 1;
        } else if (streq(line, "alias")) {         /* list aliases */
            for (int i = 0; i < g_nalias; i++) { print(g_alias[i].name); print("='"); print(g_alias[i].val); print("'\n"); }
            if (!g_nalias) print("(no aliases)\n");
        } else if (startswith(line, "alias ")) {   /* alias name=value  (or `alias name` to show one) */
            const char *p = line + 6; while (*p == ' ') p++;
            int nl = 0; while (p[nl] && p[nl] != '=' && p[nl] != ' ') nl++;
            if (p[nl] == '=' && nl > 0) { sh_unprot_buf((char *)p + nl + 1); alias_set(p, nl, p + nl + 1); }
            else { const char *v = alias_get(p, nl); if (v) { print(p); print("='"); print(v); print("'\n"); } else { print("alias: not set\n"); g_status = 1; } }
        } else if (startswith(line, "unalias ")) {
            char *p = line + 8; while (*p == ' ') p++; sh_unprot_buf(p); alias_del(p);
        } else if (streq(line, "clip")) {          /* print the system clipboard (GUI selection -> shell) */
            char cb[2048]; int n = sys_clip_get(cb, sizeof cb);
            if (n <= 0) print("(clipboard empty)\n");
            else { cb[n] = 0; print(cb); if (cb[n-1] != '\n') print("\n"); }
        } else if (startswith(line, "clip ")) {    /* clip <file>: set the clipboard from a file (or a pipe) */
            char *fn = line + 5; while (*fn == ' ') fn++; sh_unprot_buf(fn);
            long n; char *buf = slurp(fn, &n);
            if (!buf) { perr("clip: no such file: "); print(fn); print("\n"); }
            else {
                int len = (int)n; if (len > 2047) len = 2047;
                sys_clip_set(buf, len); free(buf);
                char nb[12]; itoa_simple(len, nb);
                print("copied "); print(nb); print(" bytes to clipboard\n");
            }
        } else if (startswith(line, "source ") || startswith(line, ". ")) {
            /* Run shell commands from a file: each line goes through the same
             * ';' split + &&/|| layer as interactive input. '#' lines and blank
             * lines are skipped. The filename is copied out first because the
             * nested run_line() reuses run_line's static expand/glob buffers. */
            char fn[128]; const char *p = line + (line[0] == '.' ? 2 : 7);
            while (*p == ' ') p++;
            int fi = 0; while (*p && *p != ' ' && fi < 127) fn[fi++] = *p++; fn[fi] = 0; sh_unprot_buf(fn);
            source_file(fn, cwd, 0);
        } else if (startswith(line, "crypt ")) {
            char *p = line + 6, fn[32]; int i = 0;
            while (*p == ' ') p++;
            while (*p && *p != ' ' && i < 31) fn[i++] = *p++;
            fn[i] = 0; sh_unprot_buf(fn);
            while (*p == ' ') p++;
            sh_unprot_buf(p);                                 /* the password may be quoted */
            if (fn[0] == 0 || *p == 0) print("usage: crypt <file> <pass>\n");
            else if (sys_crypt(fn, p) < 0) perr("crypt: failed\n");
            else { print("crypt: "); print(fn); print(" (run again to reverse)\n"); }
        } else if (startswith(line, "base64 -d ")) {       /* decode base64 -> bytes, written to a file */
            char *q = line + 10; while (*q == ' ') q++;
            char src[64]; int si = 0; while (*q && *q != ' ' && si < 63) src[si++] = *q++; src[si] = 0; sh_unprot_buf(src);
            while (*q == ' ') q++;
            char dst[64]; int di = 0;
            if (*q) { while (*q && *q != ' ' && di < 63) dst[di++] = *q++; dst[di] = 0; sh_unprot_buf(dst); }
            else { dst[0]='O'; dst[1]='U'; dst[2]='T'; dst[3]=0; }
            long n = -1; char *inb = src[0] ? slurp(src, &n) : 0;
            char *outb = inb ? malloc((unsigned long)n + 1) : 0;   /* decoded output is <= 3/4 of the base64 input */
            if (!inb || !outb) print("base64: no such file (usage: base64 -d <file> [out])\n");
            else {
                unsigned acc = 0; int nbits = 0, op = 0;
                for (long i = 0; i < n; i++) {
                    char c = inb[i];
                    if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
                    if (c == '=') break;
                    int v = b64v(c); if (v < 0) break;
                    acc = (acc << 6) | (unsigned)v; nbits += 6;
                    if (nbits >= 8) { nbits -= 8; outb[op++] = (char)((acc >> nbits) & 0xff); }
                }
                if (sys_writefile(dst, outb, (unsigned long)op) < 0) perr("base64: write failed\n");
                else { char nb[12]; itoa_simple(op, nb); print("base64: wrote "); print(dst); print(" ("); print(nb); print(" bytes)\n"); }
            }
            free(inb); free(outb);
        } else if (startswith(line, "base64 ")) {
            char *a = line + 7; while (*a == ' ') a++;     /* trim spaces so `base64 F > OUT` works */
            char fn[64]; int fi = 0; while (*a && *a != ' ' && fi < 63) fn[fi++] = *a++; fn[fi] = 0; sh_unprot_buf(fn);
            long n = -1; char *buf = fn[0] ? slurp(fn, &n) : 0;
            if (!buf) { print("base64: no such file\n"); }
            else {
                static const char *B =
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                char ln[48]; int col = 0;
                for (long i = 0; i < n; i += 3) {
                    unsigned b0 = (unsigned char)buf[i];
                    unsigned b1 = (i+1 < n) ? (unsigned char)buf[i+1] : 0;
                    unsigned b2 = (i+2 < n) ? (unsigned char)buf[i+2] : 0;
                    ln[col++] = B[b0 >> 2];
                    ln[col++] = B[((b0 & 3) << 4) | (b1 >> 4)];
                    ln[col++] = (i+1 < n) ? B[((b1 & 15) << 2) | (b2 >> 6)] : '=';
                    ln[col++] = (i+2 < n) ? B[b2 & 63] : '=';
                    if (col >= 40) { ln[col] = '\n'; ln[col+1] = 0; print(ln); col = 0; }
                }
                if (col) { ln[col] = '\n'; ln[col+1] = 0; print(ln); }
                free(buf);
            }
        } else if (startswith(line, "sha1 ")) {
            const char *p = line + 5; int any = 0;       /* hash each space-separated file (M1848) */
            while (*p) {
                while (*p == ' ') p++;
                if (!*p) break;
                char fn[64]; int j = 0; while (*p && *p != ' ' && j < 63) fn[j++] = *p++; fn[j] = 0; sh_unprot_buf(fn);
                any = 1; char hex[44];
                if (sys_sha1(fn, hex, sizeof hex) < 0) { print("sha1: no such file: "); print(fn); print("\n"); g_status = 1; }
                else { print("  "); print(hex); print("  "); print(fn); print("\n"); }
            }
            if (!any) print("usage: sha1 <file>...\n");
        } else if (startswith(line, "sha256 ")) {
            const char *p = line + 7; int any = 0;       /* hash each space-separated file */
            while (*p) {
                while (*p == ' ') p++;
                if (!*p) break;
                char fn[64]; int j = 0; while (*p && *p != ' ' && j < 63) fn[j++] = *p++; fn[j] = 0; sh_unprot_buf(fn);
                any = 1; char hex[72];
                if (sys_sha256(fn, hex, sizeof hex) < 0) { print("sha256: no such file: "); print(fn); print("\n"); g_status = 1; }
                else { print("  "); print(hex); print("  "); print(fn); print("\n"); }
            }
            if (!any) print("usage: sha256 <file>...\n");
        } else if (startswith(line, "sha512 ")) {
            const char *p = line + 7; int any = 0;
            while (*p) {
                while (*p == ' ') p++;
                if (!*p) break;
                char fn[64]; int j = 0; while (*p && *p != ' ' && j < 63) fn[j++] = *p++; fn[j] = 0; sh_unprot_buf(fn);
                any = 1; char hex[136];
                if (sys_sha512(fn, hex, sizeof hex) < 0) { print("sha512: no such file: "); print(fn); print("\n"); g_status = 1; }
                else { print("  "); print(hex); print("  "); print(fn); print("\n"); }
            }
            if (!any) print("usage: sha512 <file>...\n");
        } else if (streq(line, "cas") || startswith(line, "cas ")) {   /* content-addressed store: blobs keyed by SHA-256 */
            const char *p = streq(line, "cas") ? "" : line + 4;
            while (*p == ' ') p++;
            if (startswith(p, "store ")) {                /* cas store FILE -> stores it, prints its SHA-256 key */
                const char *f = p + 6; while (*f == ' ') f++;
                char fn[64]; int j = 0; while (f[j] && f[j] != ' ' && j < 63) { fn[j] = f[j]; j++; } fn[j] = 0;
                long n; char *buf = slurp(fn, &n);
                if (!buf) { perr("cas: no such file: "); print(fn); print("\n"); g_status = 1; }
                else {
                    unsigned char h[32];
                    if (sys_cas_store(buf, (unsigned long)n, h) < 0) { print("cas: store full\n"); g_status = 1; }
                    else {
                        static const char *HX = "0123456789abcdef";
                        char hex[66]; for (int i = 0; i < 32; i++) { hex[i*2] = HX[h[i] >> 4]; hex[i*2+1] = HX[h[i] & 15]; } hex[64] = '\n'; hex[65] = 0;
                        print(hex);   /* bare key (== `sha256 FILE`), so `cas fetch $(cas store FILE)` round-trips */
                    }
                    free(buf);
                }
            } else if (startswith(p, "fetch ")) {         /* cas fetch <64-hex-key> -> prints the blob */
                const char *hx = p + 6; while (*hx == ' ') hx++;
                unsigned char h[32]; int ok = 1;
                for (int i = 0; i < 32 && ok; i++) {
                    int hi = hexval(hx[i*2]), lo = (hx[i*2] ? hexval(hx[i*2+1]) : -1);
                    if (hi < 0 || lo < 0) ok = 0; else h[i] = (unsigned char)((hi << 4) | lo);
                }
                if (!ok) { print("cas: fetch needs a 64-hex-char key\n"); g_status = 1; }
                else {
                    unsigned long cap = 256 * 1024; char *out = malloc(cap);
                    long n = out ? sys_cas_fetch(h, out, cap - 1) : -1;
                    if (n < 0) { print("cas: not found / integrity check failed / too big\n"); g_status = 1; }
                    else { out[n] = 0; print(out); }
                    free(out);
                }
            } else {                                      /* cas -> store stats */
                long n; char *b = slurp("/proc/cas", &n);
                if (b) { print(b); free(b); } else print("cas: store unavailable\n");
            }
        } else if (startswith(line, "crc32 ")) {       /* CRC-32 (IEEE 802.3, as in zip/gzip/png) over each file */
            const char *fp = line + 6; int any = 0;
            while (*fp) {
                while (*fp == ' ') fp++;
                if (!*fp) break;
                char fn[64]; int j = 0; while (*fp && *fp != ' ' && j < 63) fn[j++] = *fp++; fn[j] = 0; sh_unprot_buf(fn);
                any = 1;
                long cn; char *cbuf = slurp(fn, &cn);   /* slurp grows the buffer + sets $? on a missing file */
                if (!cbuf) { print("crc32: no such file: "); print(fn); print("\n"); continue; }
                unsigned c = 0xFFFFFFFFu;
                for (long i = 0; i < cn; i++) {
                    c ^= (unsigned char)cbuf[i];
                    for (int k = 0; k < 8; k++) c = (c >> 1) ^ ((c & 1) ? 0xEDB88320u : 0u);
                }
                c ^= 0xFFFFFFFFu; free(cbuf);
                char hex[9]; const char *hd = "0123456789abcdef";
                for (int i = 0; i < 8; i++) hex[i] = hd[(c >> ((7 - i) * 4)) & 0xF];
                hex[8] = 0;
                print("  "); print(hex); print("  "); print(fn); print("\n");
            }
            if (!any) print("usage: crc32 <file>...\n");
        } else if (startswith(line, "grep ")) {
            char *p = line + 5; char pats[8][40]; int npat = 0, ci = 0, nn = 0, cc = 0, vv = 0, ll = 0, actx = 0, bctx = 0, oo = 0, wm = 0, qq = 0, xm = 0;  /* -A/-B/-C N context; -o matched part; -w word; -q quiet; -x whole-line match */
            while (*p == ' ') p++;
            while (p[0] == '-' && p[1] && p[1] != ' ') {   /* flags -i (case-insens), -n (line#s), -c (count), -v (invert); combinable as -in. -e <pat> adds a pattern: a line matches ANY (the alternation the tiny regex lacks, and avoids the shell `|` = pipe clash) */
                if (p[1] == '-' && (p[2] == ' ' || p[2] == 0)) { p += 2; while (*p == ' ') p++; break; }  /* "--": end of flags (pattern may then start with '-') */
                if (p[1] == 'e' && (p[2] == ' ' || p[2] == 0)) {   /* -e <pattern> (repeatable) */
                    p += 2; while (*p == ' ') p++;
                    int q = 0; while (*p && *p != ' ') { if (npat < 8 && q < 39) pats[npat][q++] = *p; p++; }
                    if (npat < 8) { pats[npat][q] = 0; sh_unprot_buf(pats[npat]); npat++; }
                    while (*p == ' ') p++;
                    continue;
                }
                if ((p[1] == 'A' || p[1] == 'B' || p[1] == 'C') && (p[2] == ' ' || (p[2] >= '0' && p[2] <= '9'))) {   /* -A/-B/-C N: after/before/both context lines */
                    char which = p[1]; p += 2; while (*p == ' ') p++;
                    int v = 0; while (*p >= '0' && *p <= '9') v = v * 10 + (*p++ - '0');
                    if (v > 16) v = 16;                          /* before-context ring cap */
                    if (which == 'A' || which == 'C') actx = v;
                    if (which == 'B' || which == 'C') bctx = v;
                    while (*p == ' ') p++;
                    continue;
                }
                int t, valid = 1;
                for (t = 1; p[t] && p[t] != ' '; t++) if (p[t] != 'i' && p[t] != 'n' && p[t] != 'c' && p[t] != 'v' && p[t] != 'l' && p[t] != 'o' && p[t] != 'w' && p[t] != 'q' && p[t] != 'x') valid = 0;
                if (!valid) break;                          /* not a flag token (e.g. a pattern starting with '-') */
                for (t = 1; p[t] && p[t] != ' '; t++) { if (p[t] == 'i') ci = 1; else if (p[t] == 'n') nn = 1; else if (p[t] == 'c') cc = 1; else if (p[t] == 'v') vv = 1; else if (p[t] == 'l') ll = 1; else if (p[t] == 'w') wm = 1; else if (p[t] == 'q') qq = 1; else if (p[t] == 'x') xm = 1; else oo = 1; }   /* -l filenames; -w word; -q quiet; -x whole-line; -o matched part */
                p += t; while (*p == ' ') p++;
            }
            if (npat == 0) {                                /* no -e given: the first non-flag word is the pattern */
                int i = 0; while (*p && *p != ' ' && i < 39) pats[0][i++] = *p++;
                pats[0][i] = 0; sh_unprot_buf(pats[0]); if (i) npat = 1;
                while (*p == ' ') p++;
            }
            if (npat == 0 || *p == 0) { print("usage: grep [-incvlo] [-e pat] [-A/B/C N]... <pattern> <file>...  (regex: ^ $ . * [..] \\)\n"); g_status = 1; }
            else {
                const char *cq = p; int fcount = 0;               /* count files: prefix names only if >1 */
                while (*cq) { while (*cq == ' ') cq++; if (!*cq) break; fcount++; while (*cq && *cq != ' ') cq++; }
                int hits = 0;
                while (*p) {                                       /* grep each space-separated file */
                    while (*p == ' ') p++;
                    if (!*p) break;
                    char name[64]; int j = 0;
                    while (*p && *p != ' ' && j < 63) name[j++] = *p++;
                    name[j] = 0; sh_unprot_buf(name);
                    long n; char *buf = slurp(name, &n);
                    if (!buf) { perr("grep: no such file: "); print(name); print("\n"); continue; }
                    buf[n] = 0;
                    int ls = 0, lno = 0;
                    int after = 0, last_printed = 0;            /* -A/-C after-context counter; lno dedup */
                    int bls[16], bend[16], blno[16], bn = 0;    /* -B/-C before-context ring of recent lines */
                    for (long k = 0; k <= n; k++) {
                        if (k == n || buf[k] == '\n') {
                            lno++;
                            char save = buf[k]; buf[k] = 0;   /* NUL-terminate this line for matching + printing */
                            int found = 0;                 /* ^ $ . * + literal/escape (tiny regex); match ANY -e pattern */
                            for (int pi = 0; pi < npat; pi++) if ((xm ? gr_match_line : wm ? gr_match_word : gr_match)(pats[pi], buf + ls, ci)) { found = 1; break; }   /* -x whole-line, -w whole-word, else substring */
                            int hit = vv ? !found : found;   /* -v inverts: act on non-matching lines */
                            if (qq) { buf[k] = save; if (hit) { hits = 1; break; } ls = (int)k + 1; continue; }   /* -q: no output, stop at the first match */
                            if (oo) {                       /* -o: print just the matched part(s), each on its own line */
                                if (found) {
                                    hits++;
                                    if (!cc && !ll) {
                                        const char *lp = buf + ls;
                                        for (;;) {
                                            const char *bms = 0, *bme = 0; int got = 0;
                                            for (int pi = 0; pi < npat; pi++) {   /* leftmost (then longest) match across patterns */
                                                const char *ms, *me;
                                                if (gr_match_span(pats[pi], lp, ci, &ms, &me))
                                                    if (!got || ms < bms || (ms == bms && me > bme)) { got = 1; bms = ms; bme = me; }
                                            }
                                            if (!got) break;
                                            if (bme > bms) { char es = *bme; *(char *)bme = 0; grep_emit(name, fcount, nn, lno, bms, ':'); *(char *)bme = es; lp = bme; }
                                            else { if (!*lp) break; lp++; }   /* empty match: step past one char */
                                        }
                                    }
                                }
                            } else if (hit) {
                                hits++;
                                if (ll) { print(streq(name, "PIPE.TMP") ? "(standard input)" : name); print("\n"); buf[k] = save; break; }   /* -l: this file matches; name once (piped input has no real name), next file */
                                if (!cc) {                  /* -c: count only, don't print the line */
                                    for (int z = 0; z < bn; z++) if (blno[z] > last_printed) {   /* -B/-C: print buffered before-context */
                                        char bs = buf[bend[z]]; buf[bend[z]] = 0;
                                        grep_emit(name, fcount, nn, blno[z], buf + bls[z], '-');
                                        buf[bend[z]] = bs; last_printed = blno[z];
                                    }
                                    grep_emit(name, fcount, nn, lno, buf + ls, ':');   /* the matching line */
                                    last_printed = lno; after = actx;
                                }
                            } else if (after > 0 && !cc) {  /* -A/-C: print an after-context line */
                                grep_emit(name, fcount, nn, lno, buf + ls, '-');
                                last_printed = lno; after--;
                            }
                            if (bctx > 0) {                 /* remember this line for any later match's before-context */
                                if (bn < bctx) { bls[bn] = ls; bend[bn] = (int)k; blno[bn] = lno; bn++; }
                                else { for (int z = 1; z < bctx; z++) { bls[z-1] = bls[z]; bend[z-1] = bend[z]; blno[z-1] = blno[z]; } bls[bctx-1] = ls; bend[bctx-1] = (int)k; blno[bctx-1] = lno; }
                            }
                            buf[k] = save;
                            ls = (int)k + 1;
                        }
                    }
                    free(buf);
                    if (qq && hits) break;            /* -q: first match anywhere is enough */
                }
                if (qq) { /* -q: no output at all, just the exit status below */ }
                else if (ll) { /* -l already printed the matching filenames; no summary line */ }
                else if (cc) { char cb[12]; itoa_simple(hits, cb); print("  "); print(cb); print("\n"); }
                else if (!hits && !cap_active()) print("  (no matches)\n");   /* screen-only note; would otherwise pollute a pipe/$() */
                g_status = hits ? 0 : 1;          /* exit status like real grep: 0 if any line matched, else 1 */
            }
        } else if (startswith(line, "wc ")) {
            const char *p = line + 3; char num[12];
            int tl = 0, tw = 0, nfiles = 0, tL = 0; long tb = 0;
            int wl = 0, ww = 0, wcb = 0, wL = 0;           /* -l/-w/-c counts (none = all three); -L = longest line length */
            while (*p == ' ') p++;
            while (p[0] == '-' && p[1] && p[1] != ' ') {
                int t, valid = 1;
                for (t = 1; p[t] && p[t] != ' '; t++) if (p[t] != 'l' && p[t] != 'w' && p[t] != 'c' && p[t] != 'L') valid = 0;
                if (!valid) break;                          /* not a flag token (e.g. a filename) */
                for (t = 1; p[t] && p[t] != ' '; t++) { if (p[t] == 'l') wl = 1; else if (p[t] == 'w') ww = 1; else if (p[t] == 'c') wcb = 1; else wL = 1; }
                p += t; while (*p == ' ') p++;
            }
            if (!wl && !ww && !wcb && !wL) { wl = ww = wcb = 1; }   /* no flag at all = lines+words+bytes (not -L) */
            while (*p) {                                   /* count each space-separated file */
                while (*p == ' ') p++;
                if (!*p) break;
                char name[64]; int j = 0;
                while (*p && *p != ' ' && j < 63) name[j++] = *p++;
                name[j] = 0; sh_unprot_buf(name);
                long n; char *buf = slurp(name, &n);
                if (!buf) { perr("wc: no such file: "); print(name); print("\n"); continue; }
                int lines = 0, words = 0, inword = 0, longest = 0, cur = 0;
                for (long i = 0; i < n; i++) {
                    char c = buf[i];
                    if (c == '\n') { lines++; if (cur > longest) longest = cur; cur = 0; }
                    else cur++;
                    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') inword = 0;
                    else if (!inword) { inword = 1; words++; }
                }
                if (cur > longest) longest = cur;             /* last line without a trailing newline */
                if (wl) { print("  lines "); itoa_simple(lines, num); print(num); }
                if (ww) { print("  words "); itoa_simple(words, num); print(num); }
                if (wcb) { print("  bytes "); itoa_simple((int)n, num); print(num); }
                if (wL) { print("  longest "); itoa_simple(longest, num); print(num); }
                if (!streq(name, "PIPE.TMP")) { print("  "); print(name); }   /* don't echo the internal pipe scratch file's name (`cmd | wc`) */
                print("\n");
                tl += lines; tw += words; tb += n; nfiles++; if (longest > tL) tL = longest;
                free(buf);
            }
            if (nfiles > 1) {
                if (wl) { print("  lines "); itoa_simple(tl, num); print(num); }
                if (ww) { print("  words "); itoa_simple(tw, num); print(num); }
                if (wcb) { print("  bytes "); itoa_simple((int)tb, num); print(num); }
                if (wL) { print("  longest "); itoa_simple(tL, num); print(num); }
                print("  total\n");
            }
            if (nfiles == 0) print("usage: wc [-lwc] <file>...\n");
        } else if (startswith(line, "hexdump ")) {
            const char *fp = line + 8; int any = 0, fc = 0;
            { const char *cq = fp; while (*cq) { while (*cq==' ') cq++; if (!*cq) break; fc++; while (*cq && *cq!=' ') cq++; } }
            while (*fp) {
                while (*fp == ' ') fp++;
                if (!*fp) break;
                char name[64]; int j = 0; while (*fp && *fp != ' ' && j < 63) name[j++] = *fp++; name[j] = 0; sh_unprot_buf(name);
                any = 1;
                long n; char *buf = slurp(name, &n);
                if (!buf) { perr("hexdump: no such file: "); print(name); print("\n"); continue; }
                if (fc > 1) { print("==> "); print(name); print(" <==\n"); }
                const char *H = "0123456789abcdef";
                for (long off = 0; off < n; off += 8) {
                    char h[56]; int p = 0;
                    for (int s = 28; s >= 0; s -= 4) h[p++] = H[(off >> s) & 0xF];   /* 8-hex-digit offset (files can exceed 64KB now) */
                    h[p++] = ' '; h[p++] = ' ';
                    for (int i = 0; i < 8; i++) {
                        if (off + i < n) { unsigned char c = (unsigned char)buf[off+i];
                            h[p++] = H[c >> 4]; h[p++] = H[c & 0xF]; }
                        else { h[p++] = ' '; h[p++] = ' '; }
                        h[p++] = ' ';
                    }
                    h[p++] = ' ';
                    for (int i = 0; i < 8 && off + i < n; i++) {
                        unsigned char c = (unsigned char)buf[off+i];
                        h[p++] = (c >= 32 && c < 127) ? (char)c : '.';
                    }
                    h[p++] = '\n'; h[p] = 0;
                    { char sv = h[8];  h[8]  = 0; sys_setcolor(8); print(h);      h[8]  = sv; }   /* offset grey (M1325) */
                    { char sv = h[35]; h[35] = 0; sys_setcolor(0); print(h + 8);  h[35] = sv; }   /* hex bytes default */
                    sys_setcolor(4); print(h + 35); sys_setcolor(0);                              /* ASCII pane cyan */
                }
                free(buf);
            }
            if (!any) print("usage: hexdump <file>...\n");
        } else if (startswith(line, "find ")) {
            static char fb[2048];
            sh_unprot_buf(line + 5);                      /* quoted multi-word substring (e.g. find "my doc") */
            long n = sys_find(line + 5, fb, sizeof(fb));
            if (n > 0) { fb[n] = 0; print_tree_colored(fb); } else if (!cap_active()) print("(no matches)\n");   /* colourised by type (M1315); colour is a terminal attr, so $(find) stays clean */
        } else if (streq(line, "tree")) {
            static char tb[2048];
            long n = sys_tree(tb, sizeof(tb));
            if (n <= 0) print("(empty)\n"); else { tb[n] = 0; print_tree_colored(tb); }
        } else if (startswith(line, "mkdir ")) {
            const char *p = line + 6; int any = 0, parents = 0;   /* -p: make parents as needed, no error if any exist */
            while (*p == ' ') p++;
            if (p[0] == '-' && p[1] == 'p' && (p[2] == ' ' || p[2] == 0)) { parents = 1; p += 2; while (*p == ' ') p++; }
            while (*p) {
                while (*p == ' ') p++;
                if (!*p) break;
                char name[128]; int j = 0;
                while (*p && *p != ' ' && j < 127) name[j++] = *p++;
                name[j] = 0; sh_unprot_buf(name); any = 1;
                if (parents) {                            /* create each path prefix in turn, ignoring "already exists" */
                    char partial[128]; int pi = 0;
                    for (int k = 0; k <= j; k++) {
                        if (name[k] == '/' || name[k] == 0) {
                            if (pi > 0) { partial[pi] = 0; sys_mkdir(partial); }   /* best-effort; a pre-existing dir is fine */
                            if (name[k] == '/' && pi < 127) partial[pi++] = '/';   /* keep the slash for the next prefix */
                        } else if (pi < 127) partial[pi++] = name[k];
                    }
                } else if (sys_mkdir(name) < 0) { perr("mkdir: failed (exists?): "); print(name); print("\n"); g_status = 1; }
                else { print("created "); print(name); print("/\n"); }
            }
            if (!any) print("usage: mkdir [-p] <dir>...\n");
        } else if (startswith(line, "ln -s ") || startswith(line, "ln ")) {  /* ln -s TARGET LINK (symlink: /tmp or an ext2 /diskN mount) */
            const char *p = line + 3;
            while (*p == ' ') p++;
            int is_sym = 0;
            if (p[0] == '-' && p[1] == 's') { is_sym = 1; p += 2; while (*p == ' ') p++; }   /* -s => symlink */
            char target[96]; int j = 0;
            while (*p && *p != ' ' && j < 95) target[j++] = *p++;
            target[j] = 0; sh_unprot_buf(target);
            while (*p == ' ') p++;
            char link[96]; j = 0;
            while (*p && *p != ' ' && j < 95) link[j++] = *p++;
            link[j] = 0; sh_unprot_buf(link);
            if (!target[0] || !link[0]) print("usage: ln [-s] <a> <b>   (-s: symlink b->a under /tmp or ext2; else a hard link, same ext2 /diskN mount)\n");
            else if (is_sym) { if (sys_symlink(link, target) < 0) { perr("ln: symlink failed (linkpath under /tmp or an ext2 /diskN mount)\n"); g_status = 1; } }
            else if (sys_link(target, link) < 0) { perr("ln: hard link failed (both paths must be on the same ext2 /diskN mount)\n"); g_status = 1; }
            else { print(link); print(" -> "); print(target); print("\n"); }
        } else if (startswith(line, "stat ")) {   /* stat <path>: file metadata via statx (M1173) */
            const char *p = line + 5; while (*p == ' ') p++;
            char fn[96]; int j = 0; while (*p && *p != ' ' && j < 95) fn[j++] = *p++; fn[j] = 0; sh_unprot_buf(fn);
            struct statx st;
            if (!fn[0] || sys_statx(fn, &st) != 0) { perr("stat: no such file: "); print(fn); print("\n"); g_status = 1; }
            else {
                unsigned t = st.stx_mode & S_IFMT;
                sys_setcolor(4); print("  File: "); sys_setcolor(0); print(fn); print("\n");
                sys_setcolor(4); print("  Type: "); sys_setcolor(0); print(t == S_IFDIR ? "directory" : (t == S_IFLNK ? "symlink" : "regular file")); print("\n");
                sys_setcolor(4); print("  Size: "); sys_setcolor(0); printl((long)st.stx_size); sys_setcolor(4); print("   Blocks: "); sys_setcolor(0); printl((long)st.stx_blocks);
                sys_setcolor(4); print("   Links: "); sys_setcolor(0); printl((long)st.stx_nlink); print("\n");
                unsigned m = st.stx_mode & 0777;     /* print real octal digits (printl is decimal) */
                sys_setcolor(4); print("  Mode: 0"); sys_setcolor(0); printl((m >> 6) & 7); printl((m >> 3) & 7); printl(m & 7);
                sys_setcolor(4); print("   Mtime(epoch): "); sys_setcolor(0); printl((long)st.stx_mtime); print("\n");
            }
        } else if (startswith(line, "fiemap ")) {   /* fiemap <path>: a file's physical on-disk extent map (ext2 mounts) (M1152) */
            const char *p = line + 7; while (*p == ' ') p++;
            char fn[96]; int j = 0; while (*p && *p != ' ' && j < 95) fn[j++] = *p++; fn[j] = 0; sh_unprot_buf(fn);
            struct fiemap_extent ext[16];
            int n = fn[0] ? (int)sys_fiemap(fn, ext, 16) : -1;
            if (n < 0) { print("fiemap: not an ext2-mount file (try /disk2/FILE), or absent\n"); g_status = 1; }
            else {
                print(fn); print(": "); printl(n); print(n == 1 ? " extent\n" : " extents\n");
                for (int i = 0; i < n; i++) {
                    print("  logical "); printl((long)ext[i].fe_logical);
                    print("  physical "); printl((long)ext[i].fe_physical);
                    print("  length "); printl((long)ext[i].fe_length);
                    if (ext[i].fe_flags & FIEMAP_EXTENT_LAST) print("  [last]");
                    print("\n");
                }
            }
        } else if (startswith(line, "fallocate ")) {   /* fallocate punch <path> <off> <len>: punch a sparse hole (ext2) (M1153) */
            const char *p = line + 10; while (*p == ' ') p++;
            if (startswith(p, "punch ")) {
                p += 6; while (*p == ' ') p++;
                char fn[96]; int j = 0; while (*p && *p != ' ' && j < 95) fn[j++] = *p++; fn[j] = 0; sh_unprot_buf(fn);
                while (*p == ' ') p++;
                unsigned long off = 0; while (*p >= '0' && *p <= '9') off = off * 10 + (unsigned long)(*p++ - '0');
                while (*p == ' ') p++;
                unsigned long len = 0; while (*p >= '0' && *p <= '9') len = len * 10 + (unsigned long)(*p++ - '0');
                if (!fn[0] || len == 0) print("usage: fallocate punch <path> <offset> <len>\n");
                else {
                    long r = sys_fallocate(fn, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, off, len);
                    if (r < 0) { perr("fallocate: failed (ext2 /diskN file only)\n"); g_status = 1; }
                    else { print("punched "); printl(r); print(r == 1 ? " block (hole)\n" : " blocks (hole)\n"); }
                }
            } else print("usage: fallocate punch <path> <offset> <len>\n");
        } else if (startswith(line, "jail ")) {   /* jail <prog> <promise>... : spawn prog pre-confined (pledge) */
            const char *p = line + 5; while (*p == ' ') p++;
            char prog[32]; int j = 0;
            while (*p && *p != ' ' && j < 31) prog[j++] = *p++;
            prog[j] = 0; sh_unprot_buf(prog);
            while (*p == ' ') p++;
            char proms[64]; int k = 0;
            while (*p && k < 63) proms[k++] = *p++;
            proms[k] = 0; sh_unprot_buf(proms);
            if (!prog[0] || !proms[0]) print("usage: jail <prog> <promise>...   (e.g. jail clock stdio rpath)\n");
            else if (sys_jail(prog, proms, "") < 0) { print("jail: failed (bad promise or no such prog)\n"); g_status = 1; }
            else { print("jailed "); print(prog); print(" -> pledge("); print(proms); print(")\n"); }
        } else if (startswith(line, "bind ")) {   /* bind <from> <to>: graft FROM's subtree onto path TO (Plan 9) */
            const char *p = line + 5; while (*p == ' ') p++;
            char from[64]; int j = 0; while (*p && *p != ' ' && j < 63) from[j++] = *p++;
            from[j] = 0; sh_unprot_buf(from);
            while (*p == ' ') p++;
            char to[64]; j = 0; while (*p && *p != ' ' && j < 63) to[j++] = *p++;
            to[j] = 0; sh_unprot_buf(to);
            if (!from[0] || !to[0]) print("usage: bind <from> <to>   (both absolute; e.g. bind /tmp /scratch)\n");
            else if (sys_bind(from, to) < 0) { print("bind: failed (absolute paths only, table full?)\n"); g_status = 1; }
            else { print("bound "); print(to); print(" -> "); print(from); print("\n"); }
        } else if (streq(line, "cd -")) {                        /* swap to the previous directory */
            if (!prevcwd[0]) { print("cd: no previous directory\n"); g_status = 1; }
            else {
                char tmp[128]; scpy(tmp, cwd);
                if (sys_chdir(prevcwd) < 0) { print("cd: previous directory gone\n"); g_status = 1; }
                else { scpy(cwd, prevcwd); scpy(prevcwd, tmp); print(cwd); print("\n"); }
            }
        } else if (streq(line, "cd") || streq(line, "cd ~")) {   /* cd with no arg -> home (root) */
            scpy(prevcwd, cwd);
            sys_chdir("/"); cwd[0] = '/'; cwd[1] = 0;
        } else if (startswith(line, "cd ")) {
            char *path = line + 3; while (*path == ' ') path++;            /* skip extra spaces after `cd` */
            { int pl = (int)ustrlen(path); while (pl > 0 && path[pl-1] == ' ') path[--pl] = 0; }   /* trim trailing spaces */
            sh_unprot_buf(path);                                           /* reveal a quoted dir name (cd "my dir") — chdir, not slurp */
            if (sys_chdir(path) < 0) { print("cd: no such directory\n"); g_status = 1; }
            else {
                scpy(prevcwd, cwd);                              /* remember where we came from */
                char np[128]; normpath(cwd, path, np); scpy(cwd, np);   /* normalize . / .. / // (display path matches the kernel cwd) */
            }
        } else if (streq(line, "ps")) {
            char buf[512];
            long n = sys_ps(buf, sizeof(buf));
            if (n > 0) { buf[n] = 0; print("  PID STATE  NAME\n"); print_ps_colored(buf); }   /* STATE coloured by state (M1317) */
            else print("ps: none\n");
        } else if (streq(line, "history")) {
            char buf[640];
            long n = sys_history(buf, sizeof(buf));
            if (n > 0) {
                buf[n] = 0;
                for (int i = 0; buf[i]; ) {                              /* colour each line's index grey (M1356) */
                    int eol = i; while (buf[eol] && buf[eol] != '\n') eol++;
                    int ns = i; while (ns < eol && buf[ns] == ' ') ns++;
                    while (ns < eol && buf[ns] >= '0' && buf[ns] <= '9') ns++;     /* the index digits */
                    while (ns < eol && buf[ns] == ' ') ns++;                       /* spaces after the index */
                    char seg[200]; int s = 0;
                    for (int k = i; k < ns && s < 199; k++) seg[s++] = buf[k]; seg[s] = 0; sys_setcolor(8); print(seg); sys_setcolor(0);
                    s = 0; for (int k = ns; k < eol && s < 199; k++) seg[s++] = buf[k]; seg[s] = 0; print(seg);
                    if (buf[eol] == '\n') { print("\n"); eol++; }
                    i = eol;
                }
            } else print("  (no history yet)\n");
        } else if (streq(line, "df")) {
            char b[96]; long n = sys_df(b, sizeof(b));
            if (n > 0) {
                b[n] = 0;                                                    /* colour the "free" amount green (M1318) */
                int i = 0; while (b[i] && !(b[i] >= '0' && b[i] <= '9')) i++; /* "disk: " */
                char hd[24]; int s = 0; for (int k = 0; k < i && s < 23; k++) hd[s++] = b[k]; hd[s] = 0; print(hd);
                int j = i; while (b[j] >= '0' && b[j] <= '9') j++;            /* the free number */
                char fr[16]; s = 0; for (int k = i; k < j && s < 15; k++) fr[s++] = b[k]; fr[s] = 0;
                sys_setcolor(9); print(fr); sys_setcolor(0);
                print(b + j);                                                /* " KiB free / N KiB total" */
                /* a colour-coded disk-usage bar (M1330; shared helper M1331) */
                long freev = 0; for (int k = i; k < j; k++) freev = freev * 10 + (b[k] - '0');
                long totv = 0; { int k = j; while (b[k] && !(b[k] >= '0' && b[k] <= '9')) k++;
                                 while (b[k] >= '0' && b[k] <= '9') totv = totv * 10 + (b[k++] - '0'); }
                print_usage_bar(totv > freev ? totv - freev : 0, totv);
            } else print("df: no disk\n");
        } else if (streq(line, "lspci")) {
            char buf[4096];                 /* every PCI device as one text line (kernel caps at 64) */
            long n = sys_lspci(buf, sizeof(buf));
            if (n > 0) { buf[n] = 0; print_lspci_colored(buf); } else print("lspci: no devices\n");
        } else if (streq(line, "lsblk")) {
            char buf[8192];                 /* block devices + each FAT32 volume's root files */
            long n = sys_lsblk(buf, sizeof(buf));
            if (n > 0) { buf[n] = 0; print_indented_ls(buf); } else print("lsblk: no block devices\n");
        } else if (streq(line, "mount")) {  /* list the read-only secondary-disk mounts (cd /diskN to browse) */
            char buf[2048];
            long n = sys_mounts(buf, sizeof(buf));
            if (n > 0) { buf[n] = 0; print_firsttok_cyan(buf); print("  (cd into one to browse, e.g. cd /disk2)\n"); }
            else print("mount: no disk volumes\n");
        } else if (startswith(line, "losetup ")) {  /* mount a FAT/ext2 image FILE as a loop block device */
            const char *f = line + 8; while (*f == ' ') f++;
            char fn[96]; int j = 0; while (*f && *f != ' ' && j < 95) fn[j++] = *f++; fn[j] = 0; sh_unprot_buf(fn);
            long idx = sys_losetup(fn);
            if (idx < 0) { print("losetup: not a FAT/ext2 image (or unreadable / too big)\n"); g_status = 1; }
            else { print("losetup: mounted "); print(fn); print(" as /disk"); printl(idx + 1); print("  (cd /disk"); printl(idx + 1); print(" to browse)\n"); }
        } else if (streq(line, "dmesg")) {  /* the kernel log ring buffer, read back from /proc/kmsg */
            long n; char *b = slurp("/proc/kmsg", &n);
            if (b) { print_dmesg_colored(b); if (n > 0 && b[n - 1] != '\n') print("\n"); free(b); }
            else print("dmesg: kernel log unavailable\n");
        } else if (streq(line, "measure")) {  /* measured-boot PCRs + attestation event log (/proc/measure) */
            long n; char *b = slurp("/proc/measure", &n);
            if (b) { print(b); free(b); }
            else print("measure: unavailable\n");
        } else if (streq(line, "top")) {    /* live per-task CPU view (/proc/sched) until a key is pressed */
            int quit = 0;
            while (!quit) {
                sys_clear();
                long n; char *b = slurp("/proc/sched", &n);
                if (b) { print(b); free(b); } else { print("top: /proc/sched unavailable\n"); break; }
                print("\n(press any key to exit)\n");
                for (int t = 0; t < 10; t++) {           /* refresh ~once a second */
                    if (sys_pollkey() != -1) { quit = 1; break; }
                    sys_sleep(100);
                }
            }
        } else if (streq(line, "mmaptest")) {  /* demonstrate demand-paged mmap (kernel maps pages lazily on fault) */
            unsigned long len = 64 * 1024;     /* 16 pages, none mapped up front */
            unsigned char *m = (unsigned char *)sys_mmap(len);
            if (!m) { perr("mmaptest: mmap failed\n"); g_status = 1; }
            else {
                for (unsigned long i = 0; i < len; i++) m[i] = (unsigned char)(i * 7 + 1);  /* first touch of each page demand-faults */
                int ok = 1;
                for (unsigned long i = 0; i < len; i++) if (m[i] != (unsigned char)(i * 7 + 1)) { ok = 0; break; }
                print("mmap "); printl((long)(len / 4096)); print(" pages: ");
                print(ok ? "demand-paged + verified OK\n" : "VERIFY FAILED\n");
                sys_munmap(m, len); print("munmap: freed\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "madvisetest")) {  /* demonstrate madvise(MADV_DONTNEED): reclaim resident pages now */
            unsigned long len = 256 * 1024;       /* 64 pages */
            unsigned char *m = (unsigned char *)sys_mmap(len);
            if (!m) { perr("madvisetest: mmap failed\n"); g_status = 1; }
            else {
                for (unsigned long i = 0; i < len; i++) m[i] = 0xAB;   /* fault in + dirty every page */
                print("touched "); printl((long)(len / 4096)); print(" pages (each byte = 0xAB)\n");
                long dropped = sys_madvise(m, len, 4 /* MADV_DONTNEED */);
                print("madvise(DONTNEED): reclaimed "); printl(dropped); print(" resident pages\n");
                int zeroed = 1;                    /* re-touch: must re-fault as fresh ZERO pages */
                for (unsigned long i = 0; i < len; i += 4096) if (m[i] != 0) { zeroed = 0; break; }
                print(zeroed ? "  re-read after DONTNEED is ZERO -> pages reclaimed + re-faulted fresh\n"
                             : "  VERIFY FAILED: stale data survived DONTNEED\n");
                if (!zeroed || dropped <= 0) g_status = 1;
                sys_munmap(m, len);
            }
        } else if (streq(line, "pageouttest")) {  /* madvise(MADV_PAGEOUT): proactively swap a range out to zram (M1158) */
            unsigned long np = 32, len = np * 4096;
            unsigned char *m = (unsigned char *)sys_mmap(len);
            unsigned char vec[32];
            if (!m) { perr("pageouttest: mmap failed\n"); g_status = 1; }
            else {
                for (unsigned long i = 0; i < len; i++) m[i] = (unsigned char)(i * 29 + 3);  /* fault in + fill */
                sys_mincore(m, len, vec);
                long r0 = 0; for (unsigned long i = 0; i < np; i++) r0 += vec[i];
                long paged = sys_madvise(m, len, MADV_PAGEOUT);                 /* page the range out NOW */
                sys_mincore(m, len, vec);
                long r1 = 0; for (unsigned long i = 0; i < np; i++) r1 += vec[i];
                int intact = 1;                                                /* re-touch -> faults back in from zram */
                for (unsigned long i = 0; i < len; i++) if (m[i] != (unsigned char)(i * 29 + 3)) { intact = 0; break; }
                print("resident before: "); printl(r0); print("/"); printl((long)np);
                print("   madvise(PAGEOUT) swapped: "); printl(paged);
                print("   resident after: "); printl(r1); print("/"); printl((long)np); print("\n");
                int ok = (r0 == (long)np && paged == (long)np && r1 == 0 && intact);
                print(ok ? "MADV_PAGEOUT: range paged out to zram, faulted back in intact OK\n"
                         : "MADV_PAGEOUT: VERIFY FAILED\n");
                if (!ok) g_status = 1;
                sys_munmap(m, len);
            }
        } else if (streq(line, "mincoretest")) {  /* mincore: observe which mmap pages RAM actually backs (M1147) */
            unsigned long np = 16, len = np * 4096;
            unsigned char *m = (unsigned char *)sys_mmap(len);
            unsigned char vec[16];
            if (!m) { perr("mincoretest: mmap failed\n"); g_status = 1; }
            else if (sys_mincore(m, len, vec) < 0) { perr("mincoretest: mincore failed\n"); g_status = 1; sys_munmap(m, len); }
            else {
                long r0 = 0; for (unsigned long i = 0; i < np; i++) r0 += vec[i];   /* fresh mmap: nothing faulted yet */
                print("fresh mmap of "); printl((long)np); print(" pages, resident now: "); printl(r0); print(" (lazy => 0)\n");
                for (unsigned long i = 0; i < np; i += 2) m[i * 4096] = 1;          /* fault in only the EVEN pages */
                sys_mincore(m, len, vec);
                print("after touching evens:   ");
                for (unsigned long i = 0; i < np; i++) print(vec[i] ? "R" : ".");
                print("\n");
                long re = 0; int patt = 1;
                for (unsigned long i = 0; i < np; i++) { re += vec[i]; if (vec[i] != (unsigned char)((i % 2) ? 0 : 1)) patt = 0; }
                sys_madvise(m, len, 4 /* MADV_DONTNEED */);                          /* reclaim them all */
                sys_mincore(m, len, vec);
                long after = 0; for (unsigned long i = 0; i < np; i++) after += vec[i];
                print("after madvise(DONTNEED): resident "); printl(after); print(" (=> 0)\n");
                int ok = (r0 == 0 && re == 8 && patt && after == 0);
                print(ok ? "mincore: residency exactly tracks the demand pager OK\n" : "mincore: VERIFY FAILED\n");
                if (!ok) g_status = 1;
                sys_munmap(m, len);
            }
        } else if (streq(line, "mlocktest")) {  /* mlock pins pages against reclaim; verify via mincore (M1149) */
            unsigned long np = 8, len = np * 4096;
            unsigned char *lk = (unsigned char *)sys_mmap(len);   /* this region gets mlock'd */
            unsigned char *un = (unsigned char *)sys_mmap(len);   /* this one stays unlocked */
            unsigned char v1[8], v2[8];
            if (!lk || !un) { perr("mlocktest: mmap failed\n"); g_status = 1; }
            else {
                sys_mlock(lk, len);                                          /* pin the first region */
                for (unsigned long i = 0; i < len; i++) { lk[i] = 1; un[i] = 1; }  /* fault both fully in */
                sys_madvise(lk, len, 4 /* MADV_DONTNEED */);                 /* try to reclaim both... */
                sys_madvise(un, len, 4);
                sys_mincore(lk, len, v1); sys_mincore(un, len, v2);          /* ...and see what survived */
                long rl = 0, ru = 0;
                for (unsigned long i = 0; i < np; i++) { rl += v1[i]; ru += v2[i]; }
                print("locked region resident after reclaim:   "); printl(rl); print("/"); printl((long)np); print("\n");
                print("unlocked region resident after reclaim: "); printl(ru); print("/"); printl((long)np); print("\n");
                int ok = (rl == (long)np && ru == 0);   /* locked: all pinned; unlocked: all dropped */
                print(ok ? "mlock: locked pages pinned through reclaim OK\n" : "mlock: VERIFY FAILED\n");
                if (!ok) g_status = 1;
                sys_munlock(lk, len); sys_munmap(lk, len); sys_munmap(un, len);
            }
            /* RLIMIT_MEMLOCK (M1550): cap mlock()'d bytes -- a CHILD again, so
             * the shell's own (just-verified-unlocked) mlock ability is
             * untouched. A 1-page cap: locking exactly one page must succeed,
             * a second page must be denied (would exceed it). */
            long ml = sys_fork();
            if (ml == 0) {
                struct rlimit mll; mll.rlim_cur = 4096; mll.rlim_max = 4096; sys_setrlimit(RLIMIT_MEMLOCK, &mll);
                unsigned char *m1 = (unsigned char *)sys_mmap(4096);
                unsigned char *m2 = (unsigned char *)sys_mmap(4096);
                long r1 = (m1 && m2) ? sys_mlock(m1, 4096) : -1;
                long r2 = (m1 && m2) ? sys_mlock(m2, 4096) : -1;
                sys_exit((r1 == 0 && r2 < 0) ? 0 : 1);
            } else if (ml > 0) {
                int mlst = -1; sys_waitpid((int)ml, &mlst);
                print(mlst == 0 ? "RLIMIT_MEMLOCK: 2nd mlock denied past the 1-page cap OK\n" : "RLIMIT_MEMLOCK: VERIFY FAILED\n");
                if (mlst != 0) g_status = 1;
            }
        } else if (streq(line, "usagetest")) {  /* getrusage: per-process resource accounting (M1150) */
            struct rusage a, b;
            sys_getrusage(RUSAGE_SELF, &a);
            unsigned long len = 100 * 4096;              /* fault in 100 fresh pages => ~100 minor faults */
            unsigned char *m = (unsigned char *)sys_mmap(len);
            if (m) for (unsigned long i = 0; i < len; i += 4096) m[i] = 1;
            volatile unsigned long sink = 0;             /* burn some user-mode CPU so utime is visibly nonzero */
            for (unsigned long i = 0; i < 80000000UL; i++) sink += i;
            sys_getrusage(RUSAGE_SELF, &b);
            print("getrusage(self):\n");
            print("  utime "); printl(b.ru_utime.tv_sec); print("s "); printl(b.ru_utime.tv_usec / 1000);
            print("ms   stime "); printl(b.ru_stime.tv_sec); print("s "); printl(b.ru_stime.tv_usec / 1000); print("ms\n");
            print("  maxrss "); printl(b.ru_maxrss); print(" KiB   ctxsw vol "); printl(b.ru_nvcsw);
            print(" invol "); printl(b.ru_nivcsw); print("\n");
            print("  minflt "); printl(a.ru_minflt); print(" -> "); printl(b.ru_minflt);
            print("  majflt "); printl(b.ru_majflt);
            print("   (touched 100 pages, minflt delta "); printl(b.ru_minflt - a.ru_minflt); print(")\n");
            int ok = (b.ru_minflt - a.ru_minflt >= 100);
            print(ok ? "getrusage: the minor-fault counter tracks demand paging OK\n" : "getrusage: VERIFY FAILED\n");
            if (!ok) g_status = 1;
            if (m) sys_munmap(m, len);
        } else if (streq(line, "smaps")) {   /* /proc/self/smaps: per-region Rss/Pss/Dirty/Swap (M1151) */
            unsigned long len = 64 * 4096;               /* mmap + touch 64 pages so a region shows real Rss */
            unsigned char *m = (unsigned char *)sys_mmap(len);
            if (m) for (unsigned long i = 0; i < len; i += 4096) m[i] = 1;
            long n; char *bb = slurp("/proc/self/smaps", &n);
            if (bb && n > 0) { bb[n] = 0; print(bb); free(bb); } else { print("smaps: read failed\n"); g_status = 1; }
            if (m) sys_munmap(m, len);
        } else if (streq(line, "mqtest")) {   /* POSIX priority message queue: highest-priority-first delivery (M1154) */
            int q = (int)sys_mq_open("/demo", 8, 64);
            if (q < 0) { perr("mqtest: mq_open failed\n"); g_status = 1; }
            else {
                sys_mq_send(q, "low", 3, 1);            /* enqueue out of priority order... */
                sys_mq_send(q, "high", 4, 9);
                sys_mq_send(q, "mid", 3, 5);
                print("sent 3 msgs (priorities 1, 9, 5); receiving:\n");
                const char *expect[3] = { "high", "mid", "low" };
                unsigned int eprio[3] = { 9, 5, 1 };
                int ok = 1;
                for (int i = 0; i < 3; i++) {
                    char buf[64]; unsigned int prio = 0;
                    long n = sys_mq_receive(q, buf, sizeof buf - 1, &prio);
                    if (n < 0) { print("  mq_receive failed\n"); ok = 0; break; }
                    buf[n] = 0;
                    print("  prio "); printl(prio); print(" -> "); print(buf); print("\n");
                    if (prio != eprio[i] || !streq(buf, expect[i])) ok = 0;
                }
                print(ok ? "mqueue: highest-priority-first delivery OK\n" : "mqueue: VERIFY FAILED\n");
                if (!ok) g_status = 1;
                /* priority > 255 (M1623): mqmsg used to store prio in a uint8_t while
                 * mq_send's own param is a full unsigned int, so 300 and 200 wrapped to
                 * 44 and 200 -- the WRONG one (200) would have come out first. */
                int pok = 1;
                sys_mq_send(q, "lo300", 5, 300);
                sys_mq_send(q, "hi200", 5, 200);
                { char b2[64]; unsigned int p2 = 0;
                  long n2 = sys_mq_receive(q, b2, sizeof b2 - 1, &p2);
                  if (n2 < 0) pok = 0; else { b2[n2] = 0; if (p2 != 300 || !streq(b2, "lo300")) pok = 0; } }
                { char b2[64]; unsigned int p2 = 0;
                  long n2 = sys_mq_receive(q, b2, sizeof b2 - 1, &p2);
                  if (n2 < 0) pok = 0; else { b2[n2] = 0; if (p2 != 200 || !streq(b2, "hi200")) pok = 0; } }
                print(pok ? "mqueue: priority 300 (>255) still beats 200 -- OK\n" : "mqueue: priority>255 VERIFY FAILED\n");
                if (!pok) g_status = 1;
                /* mq_getattr/mq_setattr (M1571): maxmsg/msgsize are static from
                 * mq_open, curmsgs tracks real occupancy, and O_NONBLOCK (set via
                 * mq_setattr) makes a full/empty queue fail send/receive
                 * immediately instead of blocking -- the real risk here is a bug
                 * that HANGS the whole test forever rather than just failing it. */
                struct mq_attr attr, oldattr, newattr;
                int aok = 1;
                if (sys_mq_getattr(q, &attr) != 0) aok = 0;
                if (attr.mq_maxmsg != 8 || attr.mq_msgsize != 64 || attr.mq_curmsgs != 0 || attr.mq_flags != 0) aok = 0;
                newattr.mq_flags = 1;   /* O_NONBLOCK */
                if (sys_mq_setattr(q, &newattr, &oldattr) != 0 || oldattr.mq_flags != 0) aok = 0;
                for (int i = 0; i < 8; i++) sys_mq_send(q, "x", 1, 0);   /* fill to maxmsg */
                if (sys_mq_getattr(q, &attr) != 0 || attr.mq_curmsgs != 8) aok = 0;
                if (sys_mq_send(q, "y", 1, 0) != -1) aok = 0;            /* full + O_NONBLOCK -> fail now, not hang */
                for (int i = 0; i < 8; i++) { char b[8]; sys_mq_receive(q, b, sizeof b, 0); }   /* drain everything */
                char eb[8];
                if (sys_mq_receive(q, eb, sizeof eb, 0) != -1) aok = 0;  /* empty + O_NONBLOCK -> fail now, not hang */
                newattr.mq_flags = 0; sys_mq_setattr(q, &newattr, 0);   /* restore blocking -- /demo is find-or-create by name */
                print(aok ? "mq_getattr/mq_setattr: maxmsg/msgsize/curmsgs correct, O_NONBLOCK fails a full/empty queue immediately -- OK\n"
                          : "mqtest: mq_getattr/mq_setattr VERIFY FAILED\n");
                if (!aok) g_status = 1;
                /* mq_unlink (M1593): mqueue_open's create path had no removal path
                 * anywhere before now -- exhaust+unlink+reopen all MQ_N=16 slots is
                 * the real regression proof, plus confirming it wakes a receiver
                 * already blocked on the exact queue being removed */
                int uok = (sys_mq_unlink("/demo") == 0);
                if (sys_mq_unlink("/no-such-mq") != -1) uok = 0;   /* unlinking an absent name -> -1 */
                int eok = 1;
                for (int i = 0; i < 16; i++) {
                    char qn[3] = { 'M', (char)(i < 10 ? ('0' + i) : ('A' + i - 10)), 0 };
                    if (sys_mq_open(qn, 4, 16) < 0) { eok = 0; break; }
                }
                if (sys_mq_open("MX", 4, 16) >= 0) eok = 0;         /* table genuinely full -> a 17th distinct name fails */
                for (int i = 0; i < 16; i++) {
                    char qn[3] = { 'M', (char)(i < 10 ? ('0' + i) : ('A' + i - 10)), 0 };
                    if (sys_mq_unlink(qn) != 0) eok = 0;
                }
                int reopen = (int)sys_mq_open("MX", 4, 16);         /* slots freed -> a distinct name succeeds now */
                if (reopen < 0) eok = 0;
                if (reopen >= 0) sys_mq_unlink("MX");
                int wake_ok = 1;
                int wq = (int)sys_mq_open("/mqwake", 4, 16);
                if (wq < 0) wake_ok = 0;
                else {
                    g_mq_shared = wq; g_mq_recv_result = -999;
                    char *stk = malloc(64 * 1024);
                    if (!stk) wake_ok = 0;
                    else {
                        long tid = sys_clone((void *)mq_unlink_wait_thread_fn, stk + 64 * 1024, 0);
                        sys_sleep(150);                              /* let the thread reach mq_receive and block */
                        if (sys_mq_unlink("/mqwake") != 0) wake_ok = 0;
                        sys_sleep(150);                              /* let the woken thread run + record its result */
                        if (tid <= 0 || g_mq_recv_result != -1) wake_ok = 0;   /* woken, reports gone (not a message) */
                        free(stk);
                    }
                }
                uok = uok && eok && wake_ok;
                print(uok ? "mq_unlink: frees the name; exhaust+unlink+reopen all 16 slots; wakes a blocked receiver -- OK\n"
                          : "mqtest: mq_unlink VERIFY FAILED\n");
                if (!uok) g_status = 1;
            }
        } else if (streq(line, "semtest")) {   /* SysV semaphores: count + IPC_NOWAIT + atomic all-or-nothing (M1159) */
            int id = (int)sys_semget(IPC_PRIVATE, 2, IPC_CREAT);
            if (id < 0) { perr("semtest: semget failed\n"); g_status = 1; }
            else {
                sys_semctl(id, 0, SETVAL, 3);                  /* sem0 = 3 */
                sys_semctl(id, 1, SETVAL, 0);                  /* sem1 = 0 */
                struct sembuf op; op.sem_num = 0; op.sem_op = -2; op.sem_flg = 0;
                sys_semop(id, &op, 1);                         /* sem0: 3 -> 1 */
                int v0 = (int)sys_semctl(id, 0, GETVAL, 0);
                op.sem_op = -2; op.sem_flg = IPC_NOWAIT;       /* take 2 from sem0(=1): would block -> EAGAIN, no change */
                long nw = sys_semop(id, &op, 1);
                int v0b = (int)sys_semctl(id, 0, GETVAL, 0);
                struct sembuf two[2];                          /* {sem0 -1 ok, sem1 -1 would block}: all-or-nothing -> refuse, sem0 untouched */
                two[0].sem_num = 0; two[0].sem_op = -1; two[0].sem_flg = IPC_NOWAIT;
                two[1].sem_num = 1; two[1].sem_op = -1; two[1].sem_flg = IPC_NOWAIT;
                long an = sys_semop(id, two, 2);
                int v0c = (int)sys_semctl(id, 0, GETVAL, 0);
                print("sem0 after op -2: "); printl(v0); print(" (expect 1)\n");
                print("NOWAIT over-take -> "); print(nw < 0 ? "EAGAIN" : "WRONG"); print(", sem0 still "); printl(v0b); print("\n");
                print("all-or-nothing 2-op -> "); print(an < 0 ? "refused" : "WRONG"); print(", sem0 still "); printl(v0c); print(" (not partially applied)\n");
                int ok = (v0 == 1 && nw < 0 && v0b == 1 && an < 0 && v0c == 1);
                print(ok ? "SysV semaphores: count + NOWAIT + atomic all-or-nothing OK\n" : "semtest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
                sys_semctl(id, 0, IPC_RMID, 0);
            }
        } else if (streq(line, "semopentest")) {   /* POSIX named semaphores: sem_open/wait/trywait/post/close/unlink/getvalue (M1575) */
            int ok = 1;
            int s = sys_sem_open("/demo2", O_CREAT, 0);   /* starts at 0 -- a real rendezvous, not pre-signalled */
            if (s < 0) ok = 0;
            else {
                if (sys_sem_trywait(s) != -1) ok = 0;         /* value=0 -> must fail immediately (EAGAIN), not block */
                int val = -1;
                if (sys_sem_getvalue(s, &val) != 0 || val != 0) ok = 0;

                long shmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT);
                volatile unsigned long *sh = (shmid >= 0) ? (volatile unsigned long *)sys_shmat((int)shmid) : 0;
                if (!sh) ok = 0;
                else {
                    sh[0] = 0; sh[1] = 0;
                    long c = sys_fork();
                    if (c == 0) {                              /* child: blocks in sem_wait until the parent posts */
                        int cs = sys_sem_open("/demo2", 0, 0);   /* the SAME named semaphore (already exists, no O_CREAT needed) */
                        volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)shmid);
                        unsigned long t0 = sys_uptime_ms();
                        int r = sys_sem_wait(cs);
                        unsigned long elapsed = sys_uptime_ms() - t0;
                        if (m) { m[0] = elapsed; m[1] = (unsigned long)(r == 0 ? 1 : 0); }
                        sys_sem_close(cs);
                        sys_exit(0);
                    }
                    sys_sleep(200);                             /* let the child reach sem_wait first */
                    if (sys_sem_post(s) != 0) ok = 0;
                    int st; if (c > 0) sys_waitpid((int)c, &st);
                    unsigned long elapsed = sh[0]; int waited_ok = (int)sh[1];
                    if (!(elapsed >= 150 && waited_ok)) ok = 0;   /* really blocked ~the parent's sleep, then succeeded */
                    sys_shmdt((void *)sh);
                }
                sys_sem_close(s);
                sys_sem_unlink("/demo2");
                if (sys_sem_open("/demo2", 0, 0) != -1) ok = 0;   /* unlinked -- a fresh open with no O_CREAT must fail now */
            }
            print(ok ? "POSIX named semaphores: sem_open/trywait(EAGAIN)/wait(blocks+wakes via post)/getvalue/unlink all correct -- OK\n"
                     : "semopentest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "msgtest")) {   /* SysV message queue: mtype-selective receive (M1160) */
            int id = (int)sys_msgget(42, IPC_CREAT);       /* fixed key -> reusable across runs (empty after) */
            if (id < 0) { perr("msgtest: msgget failed\n"); g_status = 1; }
            else {
                struct { long mtype; char data[8]; } m;
                m.mtype = 3; m.data[0] = '3'; sys_msgsnd(id, &m, 1, 0);   /* send in order: type 3, 1, 2 */
                m.mtype = 1; m.data[0] = '1'; sys_msgsnd(id, &m, 1, 0);
                m.mtype = 2; m.data[0] = '2'; sys_msgsnd(id, &m, 1, 0);
                long sel[3] = { 0, 2, -2 };                /* selectors: oldest, exact-2, lowest<=2 */
                long et[3] = { 3, 2, 1 }; char ed[3] = { '3', '2', '1' };
                int ok = 1;
                for (int i = 0; i < 3; i++) {
                    m.mtype = 0; m.data[0] = '?';
                    long n = sys_msgrcv(id, &m, 8, sel[i]);
                    char dd[2]; dd[0] = (n >= 1) ? m.data[0] : '?'; dd[1] = 0;
                    print("  recv #"); printl(i + 1); print(": type "); printl(m.mtype); print(" data "); print(dd); print("\n");
                    if (n < 1 || m.mtype != et[i] || m.data[0] != ed[i]) ok = 0;
                }
                print(ok ? "SysV msgq: selection (oldest / exact-type / lowest-type) OK\n" : "msgtest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "shmsysvtest")) {   /* SysV shared memory: two attaches share one backing (M1161) */
            int id = (int)sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT);
            if (id < 0) { perr("shmsysvtest: shmget failed\n"); g_status = 1; }
            else {
                char *a = (char *)sys_shmat(id);
                char *b = (char *)sys_shmat(id);           /* second attach of the SAME segment */
                if (!a || !b) { perr("shmsysvtest: shmat failed\n"); g_status = 1; }
                else {
                    for (int i = 0; i < 64; i++) a[i] = (char)(i + 1);   /* write through attach A */
                    int shared = 1;
                    for (int i = 0; i < 64; i++) if (b[i] != (char)(i + 1)) { shared = 0; break; }   /* read through attach B */
                    print("shmget + shmat x2 -> VAs "); print(a != b ? "distinct" : "SAME");
                    print(", A's writes "); print(shared ? "visible via B" : "NOT visible"); print("\n");
                    int ok = (a != b && shared);
                    print(ok ? "SysV shm: one keyed segment shared across attaches OK\n" : "shmsysvtest: VERIFY FAILED\n");
                    if (!ok) g_status = 1;
                    sys_shmdt(a); sys_shmdt(b);
                }
            }
            sys_shmctl(id, IPC_RMID);   /* free the id (M1576) -- this test's IPC_PRIVATE would otherwise leak one slot every run */
        } else if (streq(line, "sysvctltest")) {   /* msgctl/shmctl(IPC_RMID): frees an id table that could previously never shrink (M1576) */
            int ok = 1;
            /* Don't assume the tables start empty (an earlier command in the same
             * boot may have its own leaked ids) -- create IPC_PRIVATE ones until
             * creation genuinely fails, proving a real, reachable cap exists,
             * then free ONE and confirm a fresh create succeeds again. Cleans up
             * everything it creates either way, so later SysV tests in the same
             * session aren't left with a permanently-shrunk table. */
            int sids[40]; int nshm = 0;
            while (nshm < 40) { int id2 = (int)sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT); if (id2 < 0) break; sids[nshm++] = id2; }
            if (nshm == 0 || nshm == 40) ok = 0;                          /* never hit a real cap -- wrong assumption or a real regression */
            if (sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT) != -1) ok = 0;   /* table is full -- one more must fail cleanly */
            if (nshm > 0 && sys_shmctl(sids[0], IPC_RMID) != 0) ok = 0;
            int reshm = (nshm > 0) ? (int)sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT) : -1;
            if (reshm < 0) ok = 0;                                        /* the freed id is reusable, not lost forever */
            if (reshm >= 0) sys_shmctl(reshm, IPC_RMID);
            for (int i = 1; i < nshm; i++) sys_shmctl(sids[i], IPC_RMID); /* full cleanup */

            int mids[40]; int nmsg = 0;
            while (nmsg < 40) { int id2 = (int)sys_msgget(IPC_PRIVATE, IPC_CREAT); if (id2 < 0) break; mids[nmsg++] = id2; }
            if (nmsg == 0 || nmsg == 40) ok = 0;
            if (sys_msgget(IPC_PRIVATE, IPC_CREAT) != -1) ok = 0;
            if (nmsg > 0 && sys_msgctl(mids[0], IPC_RMID) != 0) ok = 0;
            int remsg = (nmsg > 0) ? (int)sys_msgget(IPC_PRIVATE, IPC_CREAT) : -1;
            if (remsg < 0) ok = 0;
            if (remsg >= 0) sys_msgctl(remsg, IPC_RMID);
            for (int i = 1; i < nmsg; i++) sys_msgctl(mids[i], IPC_RMID);

            print(ok ? "msgctl/shmctl(IPC_RMID): both tables genuinely cap out, a freed id is reusable, cleaned up after -- OK\n"
                     : "sysvctltest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
            /* shmctl(IPC_RMID) actually freeing shm.c's own (smaller, separate)
             * object table too (M1592) -- the id-table loop above never calls
             * shmat, so it can't exercise this at all; far more than shm.c's own
             * SHM_N=8 only passes if each iteration truly frees its slot there */
            int leak_ok = 1;
            for (int i = 0; i < 20; i++) {
                int id2 = (int)sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT);
                if (id2 < 0) { leak_ok = 0; break; }
                void *va = (void *)sys_shmat(id2);
                if (!va) { leak_ok = 0; break; }
                sys_shmdt(va);
                if (sys_shmctl(id2, IPC_RMID) != 0) { leak_ok = 0; break; }
            }
            if (sys_shmget(IPC_PRIVATE, 512 * 1024, IPC_CREAT) != -1) leak_ok = 0;   /* between shmget's old
                                    * 4 MiB cap and shm.c's real 256 KiB one -- must now be refused at shmget
                                    * itself, not silently accepted and left to fail later at shmat */
            print(leak_ok ? "shmctl(IPC_RMID): 20 create+attach+detach+remove cycles all succeed; "
                             "an over-cap size is refused at shmget -- OK\n"
                           : "sysvctltest: shm.c leak/size-cap VERIFY FAILED\n");
            if (!leak_ok) g_status = 1;
        } else if (streq(line, "pvmtest")) {   /* process_vm_read: read another process's memory cross-AS (M1162) */
            static char sentinel[64];
            for (int i = 0; i < 64; i++) sentinel[i] = (char)(i ^ 0x5A);   /* parent fills it before forking */
            int ppid = sys_getpid();
            long pid = sys_fork();
            if (pid == 0) {                    /* child: read the PARENT's sentinel via its address space */
                char buf[64];
                long n = sys_process_vm_read(ppid, (unsigned long)sentinel, buf, 64);
                int ok = (n == 64);
                for (int i = 0; ok && i < 64; i++) if (buf[i] != (char)(i ^ 0x5A)) ok = 0;
                sys_exit(ok ? 0 : 1);          /* report the cross-read verdict via exit status */
            } else if (pid > 0) {              /* parent: collect the child's verdict */
                int st = -1; sys_waitpid((int)pid, &st);
                print(st == 0 ? "process_vm_read: child read the parent's memory cross-AS OK\n"
                              : "process_vm_read: VERIFY FAILED\n");
                if (st != 0) g_status = 1;
            } else { perr("pvmtest: fork failed\n"); g_status = 1; }
        } else if (streq(line, "pvwtest")) {   /* process_vm_write: poke another process's memory cross-AS (M1165) */
            static char wbuf[64];
            for (int i = 0; i < 64; i++) wbuf[i] = (char)(i + 1);    /* pattern1 (parent fills before forking) */
            int sid = (int)sys_semget(IPC_PRIVATE, 1, IPC_CREAT);
            struct sembuf op;
            long pid = sys_fork();
            if (pid == 0) {                     /* child: block until poked, then verify wbuf changed */
                op.sem_num = 0; op.sem_op = -1; op.sem_flg = 0; sys_semop(sid, &op, 1);
                int ok = 1;
                for (int i = 0; i < 64; i++) if (wbuf[i] != (char)(0xC0 + i)) ok = 0;   /* expect pattern2 */
                sys_exit(ok ? 0 : 1);
            } else if (pid > 0) {               /* parent: write pattern2 into the child's wbuf, then wake it */
                char nd[64]; for (int i = 0; i < 64; i++) nd[i] = (char)(0xC0 + i);
                long n = sys_process_vm_write((int)pid, (unsigned long)wbuf, nd, 64);
                op.sem_num = 0; op.sem_op = 1; op.sem_flg = 0; sys_semop(sid, &op, 1);
                int st = -1; sys_waitpid((int)pid, &st);
                int ok = (n == 64 && st == 0);
                print(ok ? "process_vm_write: parent poked the child's memory cross-AS OK\n" : "process_vm_write: VERIFY FAILED\n");
                int iso = 1; for (int i = 0; i < 64; i++) if (wbuf[i] != (char)(i + 1)) iso = 0;   /* parent's copy intact */
                print(iso ? "  parent's own copy untouched -> COW isolation correct\n" : "  BROKEN: parent's copy was clobbered!\n");
                if (!ok || !iso) g_status = 1;
                sys_semctl(sid, 0, IPC_RMID, 0);
            } else { perr("pvwtest: fork failed\n"); g_status = 1; }
        } else if (streq(line, "pmadvtest")) {   /* process_madvise: MADV_COLD on ANOTHER process via a pidfd (M1555) */
            unsigned long len = 8 * 4096;
            unsigned char *mm = (unsigned char *)sys_mmap(len);
            int ppid = sys_getpid();
            int ok = (mm != 0);
            if (mm) for (unsigned long i = 0; i < len; i += 4096) mm[i] = 1;   /* touch all 8 pages -> Accessed set */
            long pid = ok ? sys_fork() : -1;
            if (pid == 0) {                       /* child: cold-advise the PARENT's range via a pidfd */
                int pfd = sys_pidfd_open(ppid, 0);
                long n = pfd >= 0 ? sys_process_madvise(pfd, mm, len, MADV_COLD) : -1;
                int bad = (int)sys_process_madvise(2 /* stdout fd, not a pidfd */, mm, len, MADV_COLD);   /* must be denied */
                sys_exit((n == 8 && bad == -1) ? 0 : 1);
            } else if (pid > 0) {
                int st = -1; sys_waitpid((int)pid, &st);
                print(st == 0 ? "process_madvise: child cleared the PARENT's Accessed bits cross-process (8 pages) via a pidfd, bad pidfd denied -- OK\n"
                              : "pmadvtest: VERIFY FAILED\n");
                if (st != 0) g_status = 1;
                sys_munmap(mm, len);
            } else { perr("pmadvtest: fork/mmap failed\n"); g_status = 1; }
        } else if (streq(line, "wchantest")) {   /* /proc/sched WCHAN: name the kernel routine a blocked task sleeps in (M1166) */
            int sid = (int)sys_semget(IPC_PRIVATE, 1, IPC_CREAT);
            struct sembuf op;
            long pid = sys_fork();
            if (pid == 0) {                       /* child: P a zero-valued sem -> parks inside sysv_semop */
                op.sem_num = 0; op.sem_op = -1; op.sem_flg = 0; sys_semop(sid, &op, 1);
                sys_exit(0);                      /* released by the parent's V below */
            } else if (pid > 0) {                 /* parent: let the child block, then read its WCHAN from /proc/sched */
                sys_sleep(200);                   /* give the child time to reach task_block() */
                long n; char *buf = slurp("/proc/sched", &n);
                int found = 0;
                if (buf) {
                    for (char *q = buf; *q; q++) {     /* inline substring scan (sh_substr is defined later) */
                        const char *w = "sysv_semop"; int i = 0;
                        while (w[i] && q[i] == w[i]) i++;
                        if (!w[i]) { found = 1; break; }
                    }
                    print(buf); free(buf);            /* dump the table so the WCHAN column is visible */
                }
                op.sem_num = 0; op.sem_op = 1; op.sem_flg = 0; sys_semop(sid, &op, 1);   /* V: wake the child */
                int st = -1; sys_waitpid((int)pid, &st);
                print(found ? "WCHAN: blocked child shown parked in sysv_semop OK\n" : "wchantest: VERIFY FAILED\n");
                if (!found) g_status = 1;
                sys_semctl(sid, 0, IPC_RMID, 0);
            } else { perr("wchantest: fork failed\n"); g_status = 1; }
        } else if (streq(line, "pagemaptest")) {   /* /proc/<pid>/pagemap: per-page residency + PFN, proves demand paging (M1167) */
            const int K = 8;
            void *region = sys_mmap((unsigned long)K * 4096);
            if (!region) { perr("pagemaptest: mmap failed\n"); g_status = 1; }
            else {
                long n1; char *b1 = slurp("/proc/self/pagemap", &n1);   /* fresh region: its pages are all absent */
                int c1 = 0;
                if (b1) { for (char *q = b1; q[0] && q[1] && q[2] && q[3]; q++)
                              if (q[0]=='p' && q[1]=='f' && q[2]=='n' && q[3]=='=') c1++;
                          free(b1); }
                volatile char *vp = (volatile char *)region;
                for (int i = 0; i < K; i++) vp[i * 4096] = (char)(i + 1);   /* fault each of the 8 pages in */
                long n2; char *b2 = slurp("/proc/self/pagemap", &n2);
                int c2 = 0;
                if (b2) { for (char *q = b2; q[0] && q[1] && q[2] && q[3]; q++)
                              if (q[0]=='p' && q[1]=='f' && q[2]=='n' && q[3]=='=') c2++;
                          free(b2); }
                char nb[12];
                print("pagemap resident pages: before="); itoa_simple(c1, nb); print(nb);
                print(", after touching 8="); itoa_simple(c2, nb); print(nb); print("\n");
                int ok = (c2 - c1 >= K);   /* heap pages never drop, mmap gains exactly K -> delta >= K */
                print(ok ? "pagemap: 8 demand-paged pages now resident with PFNs OK\n" : "pagemaptest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
                sys_munmap(region, (unsigned long)K * 4096);
            }
        } else if (streq(line, "thptest")) {   /* MADV_COLLAPSE: fold 512 4KiB pages into one 2MiB hugepage (M1168) */
            unsigned long SZ = 2UL * 1024 * 1024;          /* 2 MiB = 512 x 4 KiB */
            void *region = sys_mmap(SZ);                    /* 2 MiB-aligned (M1168), demand-paged 4 KiB pages */
            if (!region) { perr("thptest: mmap failed\n"); g_status = 1; }
            else {
                volatile unsigned char *vp = (volatile unsigned char *)region;
                for (int pg = 0; pg < 512; pg++) vp[pg * 4096] = (unsigned char)(pg * 7 + 1);   /* fault in + tag each page */
                long n = sys_madvise(region, SZ, MADV_COLLAPSE);                                 /* collapse to a hugepage */
                int intact = 1;
                for (int pg = 0; pg < 512; pg++) if (vp[pg * 4096] != (unsigned char)(pg * 7 + 1)) intact = 0;
                int huge = 0; long mn; char *mb = slurp("/proc/self/maps", &mn);   /* positive proof: now [mmap-huge] */
                if (mb) { const char *needle = "mmap-huge";
                          for (char *q = mb; *q; q++) { int j = 0; while (needle[j] && q[j] == needle[j]) j++;
                                                        if (!needle[j]) { huge = 1; break; } }
                          free(mb); }
                char nb[12];
                print("MADV_COLLAPSE folded "); itoa_simple((int)n, nb); print(nb); print(" pages; data ");
                print(intact ? "intact" : "CORRUPT"); print(", region "); print(huge ? "now [mmap-huge]\n" : "NOT huge\n");
                int ok = (n == 512 && intact && huge);
                print(ok ? "THP: 512 4KiB pages folded into one 2MiB hugepage (contents preserved) OK\n" : "thptest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
                sys_munmap(region, SZ);
            }
        } else if (streq(line, "sockabitest")) {
            /* The socket behaviours the Linux ABI layer depends on (M1965).
             *
             * Every one of these was found by running real Node.js, and every
             * one of them presented as something other than what it was: a
             * half-close that did nothing became "the program hangs at exit",
             * a listener name that outlived its socket became "the table is
             * full", and an epoll_ctl that answered EINVAL instead of EEXIST
             * became an abort() inside libuv. They are asserted here against
             * the NATIVE syscalls so a regression is caught by `make check`
             * rather than by a 20-minute Node run. */
            int ok = 1;
            { /* (A) HALF-CLOSE. After a's shutdown(SHUT_WR): b reads EOF, a can
               *     still RECEIVE, and a's own sends now fail. */
                int sv[2];
                if (sys_socketpair(sv) != 0) { ok = 0; }
                else {
                    if (sys_unix_send(sv[0], "hi", 2) != 2) ok = 0;
                    if (sys_unix_shutdown(sv[0], 1 /*SHUT_WR*/) != 0) ok = 0;
                    char b[8];
                    if (sys_unix_recv(sv[1], b, sizeof b) != 2) ok = 0;   /* buffered bytes survive the shutdown */
                    if (sys_unix_recv(sv[1], b, sizeof b) != 0) ok = 0;   /* THEN EOF -- the whole point */
                    if (sys_unix_send(sv[0], "x", 1) != -1) ok = 0;       /* our write side is closed */
                    if (sys_unix_send(sv[1], "yo", 2) != 2) ok = 0;       /* the peer may still write to us */
                    if (sys_unix_recv(sv[0], b, sizeof b) != 2) ok = 0;   /* and we may still read: HALF, not full */
                    sys_unix_close(sv[0]); sys_unix_close(sv[1]);
                }
            }
            { /* (B) A LISTENER'S NAME IS RELEASED on unlisten, and re-bindable. */
                int lid = sys_unix_listen("/run/sabi");
                if (lid < 0) ok = 0;
                else {
                    if (sys_unix_unlisten(lid) != 0) ok = 0;
                    if (sys_unix_connect("/run/sabi") != -1) ok = 0;   /* nobody is listening any more */
                    int l2 = sys_unix_listen("/run/sabi");             /* the name is free for reuse */
                    if (l2 < 0) ok = 0; else sys_unix_unlisten(l2);
                }
            }
            { /* (C) AN OVER-LONG NAME IS REFUSED, not silently truncated -- a
               *     truncated bind succeeds and then no connect ever matches. */
                char big[200]; int i = 0;
                big[i++] = '/'; while (i < 199) big[i++] = 'n'; big[i] = 0;
                if (sys_unix_listen(big) != -1) ok = 0;
            }
            { /* (D) epoll_ctl reports WHICH error. libuv treats EEXIST as
               *     "already watching, MOD it" and aborts on anything else. */
                int fds[2]; int ep = sys_epoll_create1(0);
                if (ep < 3 || sys_pipe(fds) != 0) ok = 0;
                else {
                    struct epoll_event ev = { POLLIN, 1 };
                    if (sys_epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], &ev) != 0) ok = 0;
                    if (sys_epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], &ev) != -17) ok = 0;  /* -EEXIST */
                    if (sys_epoll_ctl(ep, EPOLL_CTL_MOD, fds[1], &ev) != -2)  ok = 0;  /* -ENOENT */
                    if (sys_epoll_ctl(ep, EPOLL_CTL_DEL, fds[1], 0)   != -2)  ok = 0;  /* -ENOENT */
                    sys_fdclose(ep); sys_fdclose(fds[0]); sys_fdclose(fds[1]);
                }
            }
            { /* (E) /dev and /proc FILES can be opened and read. The
               *     directories always stat'd; their contents never did, so
               *     open() refused every synthetic file in the tree. */
                char b[64];
                int dn = sys_open("/dev/null");
                if (dn < 0) ok = 0;
                else { if (sys_fdread(dn, b, sizeof b) != 0) ok = 0; sys_fdclose(dn); }   /* /dev/null: immediate EOF */
                int mi = sys_open("/proc/meminfo");
                if (mi < 0) ok = 0;
                else { if (sys_fdread(mi, b, sizeof b) <= 0) ok = 0; sys_fdclose(mi); }   /* generated content */
                int ur = sys_open("/dev/urandom");
                if (ur < 0) ok = 0;
                else {
                    /* A char device is a STREAM: a second read must produce
                     * more bytes, not the EOF a file's offset logic would give. */
                    if (sys_fdread(ur, b, 16) != 16) ok = 0;
                    if (sys_fdread(ur, b, 16) != 16) ok = 0;
                    sys_fdclose(ur);
                }
            }
            print(ok ? "sockabi: half-close(peer EOF, reverse still open) + listener name released/rebindable + long name refused + epoll_ctl EEXIST/ENOENT + /dev,/proc files open (urandom streams) -- OK\n"
                     : "sockabitest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "unixtest")) {   /* AF_UNIX path-keyed stream sockets: cross-fork byte round-trip (M1169) */
            int lid = sys_unix_listen("/run/ut");           /* bind BEFORE forking so the child can connect */
            if (lid < 0) { perr("unixtest: listen failed\n"); g_status = 1; }
            else {
                long pid = sys_fork();
                if (pid == 0) {                              /* child = client */
                    int ep = sys_unix_connect("/run/ut");
                    int ok = 0;
                    if (ep >= 0) {
                        sys_unix_send(ep, "ping", 4);
                        char b[8]; long n = sys_unix_recv(ep, b, sizeof(b));   /* expect "pong" back */
                        ok = (n == 4 && b[0]=='p' && b[1]=='o' && b[2]=='n' && b[3]=='g');
                        sys_unix_close(ep);
                    }
                    sys_exit(ok ? 0 : 1);
                } else if (pid > 0) {                        /* parent = server */
                    int ep = sys_unix_accept(lid);           /* blocks until the child connects */
                    char b[8]; long n = sys_unix_recv(ep, b, sizeof(b));       /* expect "ping" */
                    int got = (n == 4 && b[0]=='p' && b[1]=='i' && b[2]=='n' && b[3]=='g');
                    if (got) sys_unix_send(ep, "pong", 4);
                    int st = -1; sys_waitpid((int)pid, &st);
                    sys_unix_close(ep);
                    int ok = (got && st == 0);
                    print(ok ? "AF_UNIX: client<->server round-trip over /run/ut OK (ping->pong cross-fork)\n" : "unixtest: VERIFY FAILED\n");
                    if (!ok) g_status = 1;
                } else { perr("unixtest: fork failed\n"); g_status = 1; }
            }
        } else if (streq(line, "unixpolltest")) {   /* unix_wait_any: poll/epoll-style readiness over 2 sockets (M1170) */
            int lid = sys_unix_listen("/run/up");
            if (lid < 0) { perr("unixpolltest: listen failed\n"); g_status = 1; }
            else {
                long pid = sys_fork();
                if (pid == 0) {                          /* child: two connections, traffic on the 2nd only */
                    int c0 = sys_unix_connect("/run/up");
                    int c1 = sys_unix_connect("/run/up");
                    int ok = 0;
                    if (c0 >= 0 && c1 >= 0) {
                        sys_unix_send(c1, "x", 1);
                        char a = 0; long n = sys_unix_recv(c1, &a, 1);   /* await the parent's ack (keeps c0 open) */
                        ok = (n == 1 && a == 'y');
                    }
                    sys_exit(ok ? 0 : 1);
                } else if (pid > 0) {                    /* parent: accept both, poll — expect only the 2nd ready */
                    int s0 = sys_unix_accept(lid);
                    int s1 = sys_unix_accept(lid);
                    int eps[2]; eps[0] = s0; eps[1] = s1;
                    int idx = sys_unix_wait_any(eps, 2);                 /* only s1 has data -> index 1 */
                    char b = 0; long n = (idx >= 0) ? sys_unix_recv(eps[idx], &b, 1) : -1;
                    sys_unix_send(s1, "y", 1);                           /* always ack so the child's recv unblocks */
                    int st = -1; sys_waitpid((int)pid, &st);
                    sys_unix_close(s0); sys_unix_close(s1);
                    char nb[12]; print("unix_wait_any -> readable index "); itoa_simple(idx, nb); print(nb); print("\n");
                    int ok = (idx == 1 && n == 1 && b == 'x' && st == 0);
                    print(ok ? "AF_UNIX poll: wait_any selected the one ready socket of 2 (cross-fork) OK\n" : "unixpolltest: VERIFY FAILED\n");
                    if (!ok) g_status = 1;
                } else { perr("unixpolltest: fork failed\n"); g_status = 1; }
            }
        } else if (streq(line, "nicetest")) {   /* CFS weighted fair scheduling: nice 0 vs nice 10 CPU share (M1171) */
            long shmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT);   /* shared counters, read by the parent after the run */
            if (shmid < 0) { perr("nicetest: shmget failed\n"); g_status = 1; }
            else {
                long a = sys_fork();
                if (a == 0) {                            /* child A: nice 0 (high weight -> more CPU) */
                    volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)shmid);
                    if (m) { sys_nice(0); unsigned long dl = sys_uptime_ms() + 2000;
                             while (sys_uptime_ms() < dl) for (int k = 0; k < 50000; k++) m[0]++; }
                    sys_exit(0);
                }
                long b = sys_fork();
                if (b == 0) {                            /* child B: nice 10 (low weight -> less CPU) */
                    volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)shmid);
                    if (m) { sys_nice(10); unsigned long dl = sys_uptime_ms() + 2000;
                             while (sys_uptime_ms() < dl) for (int k = 0; k < 50000; k++) m[1]++; }
                    sys_exit(0);
                }
                int st;                                  /* parent: off-CPU in waitpid so the two spinners share it */
                if (a > 0) sys_waitpid((int)a, &st);
                if (b > 0) sys_waitpid((int)b, &st);
                volatile unsigned long *sh = (volatile unsigned long *)sys_shmat((int)shmid);   /* attach AFTER fork -> clean read */
                unsigned long ca = sh ? sh[0] : 0, cb = sh ? sh[1] : 0;
                unsigned long ratio = cb ? ca / cb : 0;
                char nb[24];
                print("CFS nice0 vs nice10 work (Mops): "); itoa_simple((int)(ca / 1000000UL), nb); print(nb);
                print(" vs "); itoa_simple((int)(cb / 1000000UL), nb); print(nb);
                print(", ratio "); itoa_simple((int)ratio, nb); print(nb); print("x\n");
                int ok = (ca > cb * 2);                  /* nice0 clearly out-ran nice10 (expect ~9x by weight) */
                print(ok ? "CFS: lower nice got proportionally more CPU (weighted fair scheduling) OK\n" : "nicetest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
                if (sh) sys_shmdt((void *)sh);
            }
        } else if (streq(line, "schedtest")) {   /* SCHED_FIFO real-time priority ordering (M1172) */
            /* sched_get_priority_max/min (M1589): the range task_set_sched itself clamps to */
            int rng_ok = (sys_sched_get_priority_max(SCHED_FIFO) == 99 && sys_sched_get_priority_min(SCHED_FIFO) == 1 &&
                          sys_sched_get_priority_max(SCHED_RR) == 99 && sys_sched_get_priority_min(SCHED_RR) == 1 &&
                          sys_sched_get_priority_max(SCHED_OTHER) == 0 && sys_sched_get_priority_min(SCHED_OTHER) == 0 &&
                          sys_sched_get_priority_max(999) == -1 && sys_sched_get_priority_min(999) == -1);
            print(rng_ok ? "sched_get_priority_max/min: FIFO/RR 1..99, OTHER 0..0, bad policy -1 -- OK\n"
                         : "schedtest: sched_get_priority_max/min VERIFY FAILED\n");
            if (!rng_ok) g_status = 1;
            /* sched_getscheduler/sched_getparam/sched_rr_get_interval (M1591) */
            int getset_ok = (sys_sched_getscheduler() == SCHED_OTHER && sys_sched_getparam() == 0);  /* this
                                                    * shell never called sched_setscheduler -> still its default */
            if (sys_sched_setscheduler(SCHED_FIFO, 42) == 0) {
                if (sys_sched_getscheduler() != SCHED_FIFO || sys_sched_getparam() != 42) getset_ok = 0;
                sys_sched_setscheduler(SCHED_OTHER, 0);       /* restore -- don't leave this interactive shell RT */
            } else getset_ok = 0;
            long rrsec = -1, rrnsec = -1;
            if (sys_sched_rr_get_interval(&rrsec, &rrnsec) != 0 || rrsec != 0 || rrnsec <= 0) getset_ok = 0;
            print(getset_ok ? "sched_getscheduler/getparam: reads back what setscheduler set; "
                               "sched_rr_get_interval: a real sub-second duration -- OK\n"
                             : "schedtest: sched_getscheduler/getparam/rr_get_interval VERIFY FAILED\n");
            if (!getset_ok) g_status = 1;
            int sid = (int)sys_semget(IPC_PRIVATE, 1, IPC_CREAT);
            long shmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT);
            volatile unsigned long *sh = (shmid >= 0) ? (volatile unsigned long *)sys_shmat((int)shmid) : 0;
            if (sid < 0 || !sh) { print("schedtest: ipc setup failed\n"); g_status = 1; }
            else {
                sh[0] = 0; sh[1] = 0; sh[2] = 0;             /* [0]=order counter, [1]=Lo finish slot, [2]=Hi finish slot */
                struct sembuf op; op.sem_num = 0; op.sem_flg = 0;
                long lo = sys_fork();
                if (lo == 0) {                               /* child Lo: real-time FIFO priority 10 */
                    volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)shmid);
                    sys_sched_setscheduler(SCHED_FIFO, 10);
                    op.sem_op = -1; sys_semop(sid, &op, 1);  /* block on the barrier until released */
                    if (m) m[1] = ++m[0];                     /* record my finish order */
                    sys_exit(0);
                }
                long hi = sys_fork();
                if (hi == 0) {                               /* child Hi: real-time FIFO priority 50 */
                    volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)shmid);
                    sys_sched_setscheduler(SCHED_FIFO, 50);
                    op.sem_op = -1; sys_semop(sid, &op, 1);
                    if (m) m[2] = ++m[0];
                    sys_exit(0);
                }
                if (lo > 0 && hi > 0) {
                    sys_sleep(150);                          /* let both children reach + block on the barrier */
                    op.sem_op = 2; sys_semop(sid, &op, 1);   /* release both at once -> scheduler picks by RT priority */
                    int st; sys_waitpid((int)lo, &st); sys_waitpid((int)hi, &st);
                    unsigned long ordLo = sh[1], ordHi = sh[2];
                    char nb[12];
                    print("SCHED_FIFO finish order: prio50="); itoa_simple((int)ordHi, nb); print(nb);
                    print(", prio10="); itoa_simple((int)ordLo, nb); print(nb); print("\n");
                    int ok = (ordHi == 1 && ordLo == 2);     /* the higher-priority RT task ran to completion first */
                    print(ok ? "RT sched: higher-priority FIFO ran before lower (real-time priority) OK\n" : "schedtest: VERIFY FAILED\n");
                    if (!ok) g_status = 1;
                } else { perr("schedtest: fork failed\n"); g_status = 1; }
                sys_shmdt((void *)sh);
                sys_semctl(sid, 0, IPC_RMID, 0);
            }
        } else if (streq(line, "affinitytest")) {   /* sched_setaffinity/getaffinity: real per-core enforcement (M1557) */
            long shmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT);
            volatile unsigned long *sh0 = (shmid >= 0) ? (volatile unsigned long *)sys_shmat((int)shmid) : 0;
            if (!sh0) { perr("affinitytest: shmget failed\n"); g_status = 1; }
            else {
                sh0[0] = sh0[1] = sh0[2] = 0;
                unsigned defmask = sys_sched_getaffinity();   /* whatever cores are online, before any restriction */

                long a = sys_fork();
                if (a == 0) {                          /* child A: pin to core 0, prove every sample stays there */
                    volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)shmid);
                    int ok = (sys_sched_setaffinity(1) == 0) && (sys_sched_getaffinity() == 1);
                    for (int i = 0; i < 200 && ok; i++) {
                        if (sys_sched_getcpu() != 0) { ok = 0; break; }
                        sys_sched_yield();
                    }
                    if (m) m[0] = (unsigned long)ok;
                    sys_exit(0);
                }
                long b = sys_fork();
                if (b == 0) {                          /* child B: exclude the core it's CURRENTLY on -- must move
                                                          * off it right away, not just "eventually" (M1557's forced
                                                          * task_yield when self-excluding, the trickiest part of the fix) */
                    volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)shmid);
                    int before = sys_sched_getcpu();
                    int ok;
                    if (before < 0 || before >= 32) ok = 1;         /* not a small bit-index -- nothing to safely check */
                    else {
                        unsigned want = defmask & ~(1u << before);
                        if (!want) ok = 1;                          /* only one core online -- nowhere to evict to */
                        else {
                            ok = (sys_sched_setaffinity(want) == 0);
                            int after = sys_sched_getcpu();
                            ok = ok && after != before && ((want >> after) & 1u);
                        }
                    }
                    if (m) m[1] = (unsigned long)ok;
                    sys_exit(0);
                }
                long c = sys_fork();
                if (c == 0) {                          /* child C: a mask naming no real core is rejected, no side effect */
                    volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)shmid);
                    unsigned orig = sys_sched_getaffinity();
                    int ok = (sys_sched_setaffinity(0) == -1) && (sys_sched_setaffinity(1u << 30) == -1);
                    ok = ok && sys_sched_getaffinity() == orig;
                    if (m) m[2] = (unsigned long)ok;
                    sys_exit(0);
                }
                int st;
                if (a > 0) sys_waitpid((int)a, &st);
                if (b > 0) sys_waitpid((int)b, &st);
                if (c > 0) sys_waitpid((int)c, &st);
                int ok = sh0[0] && sh0[1] && sh0[2];
                print(ok ? "sched_setaffinity: pin+enforce, self-evict-now, bad-mask-rejected -- OK\n" : "affinitytest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
                sys_shmdt((void *)sh0);
            }
        } else if (streq(line, "rawkey")) {   /* TTY raw mode: read ONE keystroke unbuffered, no Enter (M1174) */
            struct termios old, raw;
            if (sys_tcgetattr(&old) != 0) { print("rawkey: tcgetattr failed\n"); g_status = 1; }
            else {
                raw = old; raw.c_lflag &= ~(unsigned)ICANON;   /* raw: per-keystroke delivery (ECHO kept) */
                sys_tcsetattr(&raw);
                print("raw mode on: press one key (NO Enter)... ");
                char ch = 0; long r = sys_read(0, &ch, 1);
                sys_tcsetattr(&old);                            /* restore cooked line editing */
                print("\n");
                if (r == 1) {
                    const char *H = "0123456789abcdef"; char hx[3] = { H[(ch >> 4) & 15], H[ch & 15], 0 };
                    char pr[2] = { (ch >= 32 && ch < 127) ? ch : '?', 0 };
                    print("read 1 byte unbuffered: '"); print(pr); print("' (0x"); print(hx); print(")\n");
                    print("TTY raw line discipline OK (cooked mode restored)\n");
                } else { print("rawkey: read returned "); printl(r); print("\n"); g_status = 1; }
            }
        } else if (streq(line, "jobtest")) {   /* job control: kill(-pgid) signals a whole process group (M1176) */
            long a = sys_fork();
            if (a == 0) {                            /* child A */
                sys_signal(2, jobtest_sigint);       /* SIGINT(2) -> exit(42) */
                for (int i = 0; i < 200; i++) sys_sleep(20);   /* bounded: self-exit 0 if no signal (no hang) */
                sys_exit(0);
            }
            long b = sys_fork();
            if (b == 0) {                            /* child B */
                sys_signal(2, jobtest_sigint);
                for (int i = 0; i < 200; i++) sys_sleep(20);
                sys_exit(0);
            }
            if (a > 0 && b > 0) {
                sys_setpgid((int)a, (int)a);         /* A leads a NEW group (isolated from the shell) */
                sys_setpgid((int)b, (int)a);         /* B joins A's group */
                sys_sleep(300);                      /* let both install their SIGINT handler */
                int n = sys_killpg((int)a, 2);       /* kill(-pgid, SIGINT): the whole group */
                int sa = -1, sb = -1; sys_waitpid((int)a, &sa); sys_waitpid((int)b, &sb);
                char nb[12];
                print("killpg signalled "); itoa_simple(n, nb); print(nb); print(" procs; child statuses ");
                itoa_simple(sa, nb); print(nb); print("/"); itoa_simple(sb, nb); print(nb); print("\n");
                int ok = (n == 2 && sa == 42 && sb == 42);
                print(ok ? "job control: kill(-pgid) delivered SIGINT to the whole group OK\n" : "jobtest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            } else { perr("jobtest: fork failed\n"); g_status = 1; }
            int saved_fg = sys_tcgetpgrp();          /* tcgetpgrp (M1558): round-trip against tcsetpgrp, then
                                                       * restore -- this is real console state (fg_pgid), shared
                                                       * by the whole system, not per-process like the rest of
                                                       * this test, so leaving it mutated would misroute this
                                                       * interactive shell's own future ^C after the test returns */
            int pg_ok = (sys_tcsetpgrp(1234) == 0) && (sys_tcgetpgrp() == 1234);
            sys_tcsetpgrp(saved_fg);
            print(pg_ok ? "tcgetpgrp: reads back exactly what tcsetpgrp set OK\n" : "jobtest: tcgetpgrp VERIFY FAILED\n");
            if (!pg_ok) g_status = 1;
            long sidshmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT);            /* getsid (M1580) */
            volatile long *sidsh = (sidshmid >= 0) ? (volatile long *)sys_shmat((int)sidshmid) : 0;
            int sid_ok = (sidsh != 0);
            if (sid_ok) {
                sidsh[0] = -1; sidsh[1] = -1;
                long gc = sys_fork();
                if (gc == 0) {
                    volatile long *m = (volatile long *)sys_shmat((int)sidshmid);
                    int mysid = sys_setsid();                      /* becomes session+group leader; sid = own pid */
                    if (m) { m[0] = mysid; m[1] = sys_getsid(0); }  /* pid==0 -> the caller's own */
                    sys_sleep(300);                                /* stay alive long enough for the parent to query us */
                    sys_exit(0);
                }
                sys_sleep(100);                                    /* let the child setsid before we query it */
                long remote_sid = (gc > 0) ? sys_getsid((int)gc) : -1;
                int st = -1; if (gc > 0) sys_waitpid((int)gc, &st);
                sid_ok = (gc > 0 && sidsh[0] > 0 && sidsh[0] == sidsh[1] && sidsh[0] == gc && remote_sid == gc);
                sys_shmdt((void *)sidsh);
            }
            print(sid_ok ? "getsid: a setsid()'d child's own sid==its pid; the parent's getsid(child_pid) reads the same value -- OK\n"
                         : "jobtest: getsid VERIFY FAILED\n");
            if (!sid_ok) g_status = 1;
        } else if (streq(line, "sigsuspendtest")) {   /* sigsuspend: atomically unblock + wait + re-block (M1561) */
            long c = sys_fork();
            if (c == 0) {
                sys_signal(10 /*SIGUSR1*/, sh_sigsuspend_handler);
                sys_sigprocmask(0 /*SIG_BLOCK*/, 1u << 10);   /* baseline: blocked before the wait, like real usage */
                long rc = sys_sigsuspend(0);                   /* unblock everything for the wait, re-block on return */
                unsigned mask_after = sys_sigprocmask(0 /*SIG_BLOCK*/, 0);   /* empty set -> pure peek at the current mask */
                sys_exit((rc == -1 && g_sigsuspend_fired && (mask_after & (1u << 10))) ? 42 : 10);
            }
            sys_sleep(150);                          /* let the child install the handler + reach sigsuspend first */
            int st = -1;
            if (c > 0) { sys_sigqueue((int)c, 10, 0); sys_waitpid((int)c, &st); }   /* sys_kill() has no signal-number arg -- it's a WM close request, not POSIX kill(2) */
            int ok = (c > 0 && st == 42);
            print(ok ? "sigsuspend: blocked SIGUSR1, sigsuspend(0) unblocked+waited+delivered it, mask restored after -- OK\n"
                     : "sigsuspendtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "pdeathsigtest")) {   /* SIGCHLD-on-exit + prctl(PR_SET_PDEATHSIG) (M1562) */
            long shmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT);
            volatile unsigned long *sh = (shmid >= 0) ? (volatile unsigned long *)sys_shmat((int)shmid) : 0;
            if (!sh) { perr("pdeathsigtest: shmget failed\n"); g_status = 1; }
            else {
                sh[0] = 0;                                       /* grandchild G's own pdeathsig result */
                g_sigchld_fired = 0;                              /* explicit reset -- a rerun in the same session must not inherit a stale 1 */
                sys_signal(17 /*SIGCHLD*/, sh_sigchld_handler);
                long p = sys_fork();
                if (p == 0) {                                     /* P: forks G, then dies immediately, abandoning it */
                    long g = sys_fork();
                    if (g == 0) {                                  /* G: asks to be signalled when P (its parent) dies */
                        volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)shmid);
                        g_pdeathsig_fired = 0;                      /* same reset concern -- G is a fresh COW copy of a long-lived shell */
                        sys_signal(10 /*SIGUSR1*/, sh_pdeathsig_handler);
                        sys_prctl(PR_SET_PDEATHSIG, 10);
                        int ok = 0;
                        for (int i = 0; i < 100 && !ok; i++) { sys_sleep(20); if (g_pdeathsig_fired) ok = 1; }
                        if (m) m[0] = (unsigned long)ok;
                        sys_exit(0);
                    }
                    sys_exit(0);                                    /* P dies now -- G is still alive and waiting */
                }
                int st = -1; if (p > 0) sys_waitpid((int)p, &st);   /* reaps P -> app_reap's pdeathsig-notify path runs for G */
                int sigchld_ok = g_sigchld_fired;
                sys_signal(17, 0);                                  /* disable again -- don't leak a handler into later commands */
                int pd_ok = 0;
                for (int i = 0; i < 100 && !pd_ok; i++) { if (sh[0]) { pd_ok = 1; break; } sys_sleep(20); }
                int ok = sigchld_ok && pd_ok;
                print(ok ? "SIGCHLD delivered on a child's exit, PR_SET_PDEATHSIG delivered when ITS parent died -- OK\n"
                         : "pdeathsigtest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
                sys_shmdt((void *)sh);
            }
        } else if (streq(line, "pausetest")) {   /* pause(): block until a signal, current mask unchanged (M1563) */
            long shmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT);
            volatile unsigned long *sh = (shmid >= 0) ? (volatile unsigned long *)sys_shmat((int)shmid) : 0;
            if (!sh) { perr("pausetest: shmget failed\n"); g_status = 1; }
            else {
                sh[0] = 0;                                    /* elapsed ms the child measured around pause() */
                long c = sys_fork();
                if (c == 0) {
                    volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)shmid);
                    sys_signal(10 /*SIGUSR1*/, sh_sigsuspend_handler);   /* a handler must exist or app_request_signal
                                                                          * drops it and pause() blocks forever; its
                                                                          * flag isn't read here -- elapsed time is
                                                                          * the actual proof pause() really blocked */
                    unsigned long t0 = sys_uptime_ms();
                    sys_pause();
                    unsigned long t1 = sys_uptime_ms();
                    if (m) m[0] = t1 - t0;
                    sys_exit(0);
                }
                sys_sleep(200);                                /* let the child install the handler + reach pause() */
                if (c > 0) { sys_sigqueue((int)c, 10, 0); int st; sys_waitpid((int)c, &st); }
                unsigned long elapsed = sh[0];
                int ok = (c > 0 && elapsed >= 150);             /* blocked for roughly the parent's sleep, not an instant return */
                print("pause: blocked "); printl((int)elapsed); print("ms until signalled (parent slept ~200ms) -- ");
                sys_setcolor(ok ? 10 : 4); print(ok ? "OK\n" : "VERIFY FAILED\n"); sys_setcolor(0);
                if (!ok) g_status = 1;
                sys_shmdt((void *)sh);
            }
        } else if (streq(line, "flocktest")) {   /* advisory whole-file locks: conflict then free on unlock (M1177) */
            const char *path = "/tmp/lck";
            int r1 = sys_flock(path, LOCK_EX);                  /* parent takes an exclusive lock */
            long c1 = sys_fork();
            if (c1 == 0) { int r = sys_flock(path, LOCK_EX | LOCK_NB); sys_exit(r < 0 ? 10 : 11); }   /* held -> conflict -> -1 */
            int s1 = -1; if (c1 > 0) sys_waitpid((int)c1, &s1);
            sys_flock(path, LOCK_UN);                            /* release it */
            long c2 = sys_fork();
            if (c2 == 0) { int r = sys_flock(path, LOCK_EX | LOCK_NB); sys_exit(r == 0 ? 20 : 21); }   /* now free -> 0 */
            int s2 = -1; if (c2 > 0) sys_waitpid((int)c2, &s2);  /* c2 exits holding it -> app_reap releases it */
            char nb[12];
            print("flock: acquire="); itoa_simple(r1, nb); print(nb);
            print(", child-while-held="); itoa_simple(s1, nb); print(nb);
            print(", child-after-unlock="); itoa_simple(s2, nb); print(nb); print("\n");
            int ok = (r1 == 0 && s1 == 10 && s2 == 20);
            print(ok ? "flock: exclusive lock conflicts while held, frees on unlock OK\n" : "flocktest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "stoptest")) {   /* SIGTSTP/SIGCONT job suspend/resume (M1178) */
            long shmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT);
            volatile unsigned long *sh = shmid >= 0 ? (volatile unsigned long *)sys_shmat((int)shmid) : 0;
            if (!sh) { perr("stoptest: shm failed\n"); g_status = 1; }
            else {
                sh[0] = 0; sh[1] = 0;                /* [0]=counter, [1]=exit-flag (init before fork) */
                long c = sys_fork();
                if (c == 0) {                        /* child: spin incrementing the shared counter */
                    volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)shmid);
                    if (m) while (!m[1]) { for (int k = 0; k < 30000; k++) m[0]++; }
                    sys_exit(0);
                }
                if (c > 0) {
                    volatile unsigned long *ps = (volatile unsigned long *)sys_shmat((int)shmid);   /* post-fork attach (COW-safe writes) */
                    sys_setpgid((int)c, (int)c);     /* child leads its own group, so killpg targets only it */
                    sys_sleep(150);                  /* let it run */
                    sys_killpg((int)c, SIGTSTP);     /* suspend the group */
                    sys_sleep(60);
                    unsigned long c1 = ps[0]; sys_sleep(150); unsigned long c2 = ps[0];   /* frozen while stopped */
                    sys_killpg((int)c, SIGCONT);     /* resume */
                    sys_sleep(150); unsigned long c3 = ps[0];                              /* advances after cont */
                    ps[1] = 1;                       /* tell the now-running child to exit */
                    int st = -1; sys_waitpid((int)c, &st);
                    char nb[20];
                    print("counter ran to "); itoa_simple((int)(c1 / 1000), nb); print(nb);
                    print("k; while-stopped delta="); itoa_simple((int)(c2 - c1), nb); print(nb);
                    print("; after-cont delta="); itoa_simple((int)((c3 - c2) / 1000), nb); print(nb); print("k\n");
                    int ok = (c1 > 0 && c2 == c1 && c3 > c2);
                    print(ok ? "job control: SIGTSTP froze the process, SIGCONT resumed it OK\n" : "stoptest: VERIFY FAILED\n");
                    if (!ok) g_status = 1;
                    if (ps) sys_shmdt((void *)ps);
                } else { perr("stoptest: fork failed\n"); g_status = 1; }
                sys_shmdt((void *)sh);
            }
        } else if (streq(line, "mremaptest")) {   /* mremap: grow-in-place + MREMAP_MAYMOVE relocation (M1179) */
            unsigned long P = 4096;
            int moved_ok = 0, grew_ok = 0;
            volatile unsigned char *A = (volatile unsigned char *)sys_mmap(P);
            volatile unsigned char *B = (volatile unsigned char *)sys_mmap(P);   /* blocks the space just above A */
            if (A && B) {
                A[0] = 0x11; A[100] = 0x22;
                volatile unsigned char *A2 = (volatile unsigned char *)sys_mremap((void *)A, P, 4 * P, MREMAP_MAYMOVE);
                if (A2) {
                    A2[3 * P] = 0x33;   /* a freshly-grown (demand-paged) page */
                    moved_ok = (A2 != A && A2[0] == 0x11 && A2[100] == 0x22 && A2[3 * P] == 0x33);
                    sys_munmap((void *)A2, 4 * P);
                }
                sys_munmap((void *)B, P);
            }
            volatile unsigned char *C = (volatile unsigned char *)sys_mmap(P);
            if (C) {
                C[0] = 0x44; C[50] = 0x55;
                volatile unsigned char *C2 = (volatile unsigned char *)sys_mremap((void *)C, P, 2 * P, 0);   /* no MAYMOVE */
                if (C2) {
                    C2[P] = 0x66;       /* the grown page */
                    grew_ok = (C2 == C && C2[0] == 0x44 && C2[50] == 0x55 && C2[P] == 0x66);
                    sys_munmap((void *)C2, 2 * P);
                }
            }
            print("mremap: MAYMOVE relocate "); print(moved_ok ? "OK" : "FAIL");
            print(", grow-in-place "); print(grew_ok ? "OK" : "FAIL"); print("\n");
            int ok = moved_ok && grew_ok;
            print(ok ? "mremap: grow-in-place + MAYMOVE move (data preserved) OK\n" : "mremaptest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "cfrtest")) {   /* copy_file_range: in-kernel file copy, byte-identical (M1181) */
            long n = sys_copy_file_range("MOTD.TXT", "/tmp/cfr_out", 0);   /* FAT root -> RAM /tmp, in-kernel */
            long sa = -1, sb = -1; char *a = slurp("MOTD.TXT", &sa); char *b = slurp("/tmp/cfr_out", &sb);
            int ok = (n > 0 && a && b && sa == sb && sa == n);
            if (ok) for (long i = 0; i < sa; i++) if (a[i] != b[i]) { ok = 0; break; }
            char nb[12];
            print("copy_file_range copied "); itoa_simple((int)n, nb); print(nb);
            print(" bytes; dst "); print(ok ? "byte-identical to src" : "MISMATCH"); print("\n");
            print(ok ? "copy_file_range: in-kernel file copy OK\n" : "cfrtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
            if (a) free(a); if (b) free(b);
        } else if (startswith(line, "xattr ")) {   /* user.* extended attributes on ext2 /diskN files (M1182) */
            char *p = line + 6; while (*p == ' ') p++;
            char sub[8]; int si = 0; while (*p && *p != ' ' && si < 7) sub[si++] = *p++; sub[si] = 0;
            while (*p == ' ') p++;
            char path[128]; int pi = 0; while (*p && *p != ' ' && pi < 127) path[pi++] = *p++; path[pi] = 0;
            while (*p == ' ') p++;
            if (streq(sub, "list") && path[0]) {
                char names[512]; long n = sys_listxattr(path, names, sizeof names);
                if (n < 0) { print("xattr: not an ext2 file (or no EA region)\n"); g_status = 1; }
                else if (n == 0) print("(no attributes)\n");
                else { if (n > (long)sizeof names) n = sizeof names; names[sizeof names - 1] = 0;
                       long i = 0; while (i < n && names[i]) { print(names + i); print("\n");
                                                               while (i < n && names[i]) i++; i++; } }
            } else if (streq(sub, "get") && path[0]) {
                char name[80]; int ni = 0; while (*p && *p != ' ' && ni < 79) name[ni++] = *p++; name[ni] = 0;
                char val[256]; long n = sys_getxattr(path, name, val, sizeof val - 1);
                if (n < 0) { print("xattr: not found\n"); g_status = 1; }
                else { if (n > (long)sizeof val - 1) n = sizeof val - 1; val[n] = 0; print(val); print("\n"); }
            } else if (streq(sub, "set") && path[0]) {
                char name[80]; int ni = 0; while (*p && *p != ' ' && ni < 79) name[ni++] = *p++; name[ni] = 0;
                while (*p == ' ') p++;
                unsigned long vl = 0; while (p[vl]) vl++;                  /* value = rest of line (may have spaces) */
                long n = sys_setxattr(path, name, p, vl);
                if (n < 0) { print("xattr: set failed (needs an ext2 256-byte-inode file; name=user.* ; small value)\n"); g_status = 1; }
                else print("xattr set\n");
            } else if ((streq(sub, "rm") || streq(sub, "remove")) && path[0]) {
                char name[80]; int ni = 0; while (*p && *p != ' ' && ni < 79) name[ni++] = *p++; name[ni] = 0;
                if (sys_removexattr(path, name) < 0) { print("xattr: remove failed (not found?)\n"); g_status = 1; }
                else print("xattr removed\n");
            } else print("usage: xattr get|set|rm|list PATH [user.NAME [VALUE]]\n");
        } else if (streq(line, "ptytest")) {   /* pseudoterminal line discipline (M1185) */
            int m = sys_pty_open();
            if (m < 0) { perr("ptytest: pty_open failed\n"); g_status = 1; }
            else {
                int s = m | 1; char b[80]; long n; int ok = 1;
                sys_pty_ctl(m, PTY_SETFG, 99999);   /* INTR -> a bogus pgid: exercise the path, signal nobody */
                /* 1) cooked: a line written to the master is readable by the slave */
                sys_pty_write(m, "hi\n", 3);
                n = sys_pty_read(s, b, sizeof b);
                if (!(n == 3 && b[0]=='h' && b[1]=='i' && b[2]=='\n')) ok = 0;
                /* 2) ECHO returned the typed line to the master */
                n = sys_pty_read(m, b, sizeof b);
                if (!(n >= 3 && b[0]=='h' && b[1]=='i')) ok = 0;
                /* 3) ERASE (backspace): "ab\bc\n" -> slave sees "ac\n" */
                sys_pty_write(m, "ab\bc\n", 5);
                n = sys_pty_read(s, b, sizeof b);
                if (!(n == 3 && b[0]=='a' && b[1]=='c' && b[2]=='\n')) ok = 0;
                sys_pty_read(m, b, sizeof b);        /* drain the editing echo (one read grabs it all) */
                /* 4) INTR (^C) flushes the pending line and echoes ^C */
                sys_pty_write(m, "xy\x03", 3);
                n = sys_pty_read(m, b, sizeof b);
                int sawC = 0; for (long i = 0; i + 1 < n; i++) if (b[i]=='^' && b[i+1]=='C') sawC = 1;
                if (!sawC) ok = 0;
                sys_pty_write(m, "z\n", 2);          /* a fresh line: "xy" must have been discarded */
                n = sys_pty_read(s, b, sizeof b);
                if (!(n == 2 && b[0]=='z' && b[1]=='\n')) ok = 0;
                sys_pty_read(m, b, sizeof b);        /* drain the "z\n" echo */
                /* 5) raw mode (no ICANON/ECHO): bytes pass through immediately */
                sys_pty_ctl(m, PTY_SETMODE, 0);
                sys_pty_write(m, "R", 1);
                n = sys_pty_read(s, b, sizeof b);
                if (!(n == 1 && b[0]=='R')) ok = 0;
                /* 6) slave output is readable by the master */
                sys_pty_write(s, "OUT", 3);
                n = sys_pty_read(m, b, sizeof b);
                if (!(n == 3 && b[0]=='O' && b[1]=='U' && b[2]=='T')) ok = 0;
                /* 7) VEOF (^D) on an empty line: back to cooked mode, ^D -> slave read sees
                 * EOF (n==0), and the pty is still usable afterward once the master writes a
                 * real line (basic EOF-signaling coverage; ptytest had none before this).
                 * NOTE: this does NOT specifically prove EOF is a one-shot flag (M1663's real
                 * fix) -- pr_cnt(r)>0 short-circuits pty_read's eof check the moment new data
                 * lands in the ring either way, so a stuck/uncleared eof flag from the OLD bug
                 * would still pass this exact sequence. Isolating that needs a genuinely
                 * blocking second read with nothing new written, which risks hanging this
                 * single-threaded test if the fix regresses -- not attempted here. */
                sys_pty_ctl(m, PTY_SETMODE, 0x00B);   /* ICANON|ECHO|ISIG */
                sys_pty_write(m, "\x04", 1);
                n = sys_pty_read(s, b, sizeof b);
                if (n != 0) ok = 0;
                sys_pty_write(m, "ok\n", 3);
                n = sys_pty_read(s, b, sizeof b);
                if (!(n == 3 && b[0]=='o' && b[1]=='k' && b[2]=='\n')) ok = 0;
                sys_pty_read(m, b, sizeof b);        /* drain the "ok\n" echo */
                sys_pty_close(m); sys_pty_close(s);
                print(ok ? "pty: cooked + echo + erase + INTR-flush + raw + slave-output + EOF all OK\n"
                         : "ptytest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "pipetest")) {   /* anonymous pipe + per-process fd table across fork (M1187) */
            int fds[2];
            if (sys_pipe(fds) != 0) { print("pipetest: pipe() failed\n"); g_status = 1; }
            else {
                long pid = sys_fork();
                if (pid == 0) {                          /* child: the writer */
                    sys_fdclose(fds[0]);                 /* close the read end it inherited */
                    sys_fdwrite(fds[1], "hello pipe", 10);
                    sys_fdclose(fds[1]);                 /* drop the write end -> EOF for the parent */
                    sys_exit(0);
                }
                int ok = 1;
                sys_fdclose(fds[1]);                     /* parent drops its write end so EOF can fire */
                char b[32];
                long n = sys_fdread(fds[0], b, sizeof b);    /* blocks until the child writes */
                if (!(n == 10 && b[0] == 'h' && b[6] == 'p')) ok = 0;
                long e = sys_fdread(fds[0], b, sizeof b);     /* child closed + exited -> EOF */
                if (e != 0) ok = 0;
                sys_fdclose(fds[0]);
                int st = 0; sys_waitpid((int)pid, &st);
                /* dup2: a 2nd pipe, write via a dup'd write fd, read the original */
                int ok2 = 0, f2[2];
                if (sys_pipe(f2) == 0) {
                    if (sys_dup2(f2[1], 9) == 9) {
                        sys_fdwrite(9, "dup", 3);
                        char c[8]; long dn = sys_fdread(f2[0], c, sizeof c);
                        ok2 = (dn == 3 && c[0] == 'd' && c[2] == 'p');
                    }
                    sys_fdclose(9); sys_fdclose(f2[0]); sys_fdclose(f2[1]);
                }
                /* dup (M1587): onto the LOWEST free fd, unlike dup2's explicit target */
                int ok3 = 0, f3[2];
                if (sys_pipe(f3) == 0) {
                    int d = sys_dup(f3[1]);
                    if (d > f3[1]) {                              /* the lowest free fd is always above both pipe ends */
                        sys_fdwrite(d, "dp2", 3);
                        char c2[8]; long dn2 = sys_fdread(f3[0], c2, sizeof c2);
                        ok3 = (dn2 == 3 && c2[0] == 'd' && c2[2] == '2');
                        sys_fdclose(d);
                    }
                    sys_fdclose(f3[0]); sys_fdclose(f3[1]);
                }
                print((ok && ok2 && ok3) ? "pipe: fork round-trip + EOF + dup2 + dup all OK\n" : "pipetest: VERIFY FAILED\n");
                if (!(ok && ok2 && ok3)) g_status = 1;
            }
        } else if (streq(line, "sigpipetest")) {   /* write() with no readers left -> -1 (EPIPE) AND SIGPIPE (M1581) */
            int ok = 1;
            int fds[2];
            if (sys_pipe(fds) != 0) { print("sigpipetest: pipe() failed\n"); g_status = 1; }
            else {
                g_sigpipe_fired = 0;
                sys_signal(13 /*SIGPIPE*/, sh_sigpipe_handler);
                sys_fdclose(fds[0]);                          /* drop the read end -> no readers left */
                char c = 'x';
                long w = sys_fdwrite(fds[1], &c, 1);
                ok = (w == -1 && g_sigpipe_fired);
                sys_fdclose(fds[1]);
                sys_signal(13, 0);                             /* disable again -- don't leak a handler into later commands */
            }
            print(ok ? "write() to a pipe with no readers left: -1 (EPIPE) AND SIGPIPE delivered -- OK\n"
                     : "sigpipetest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "polltest")) {   /* poll(2) readiness multiplex over the fd table (M1210) */
            int ok = 1, fds[2];
            if (sys_pipe(fds) != 0) { print("polltest: pipe() failed\n"); g_status = 1; }
            else {
                long pid = sys_fork();
                if (pid == 0) {                      /* child: make the read end readable */
                    sys_fdclose(fds[0]);
                    sys_fdwrite(fds[1], "P", 1);
                    sys_fdclose(fds[1]);
                    sys_exit(0);
                }
                sys_fdclose(fds[1]);                 /* parent drops its write end */
                /* (A) block in poll until the child writes -> 1, POLLIN set */
                struct pollfd p = { fds[0], POLLIN, 0 };
                long r = sys_poll(&p, 1, 1000);
                if (!(r == 1 && (p.revents & POLLIN))) ok = 0;
                char b[8]; long n = sys_fdread(fds[0], b, sizeof b);
                if (!(n == 1 && b[0] == 'P')) ok = 0;
                sys_fdclose(fds[0]);
                int st = 0; sys_waitpid((int)pid, &st);
                /* (B) idle read end (writer still open) + short timeout -> 0, no revents */
                int f2[2];
                if (sys_pipe(f2) == 0) {
                    struct pollfd q = { f2[0], POLLIN, (short)0xFF };
                    if (!(sys_poll(&q, 1, 30) == 0 && q.revents == 0)) ok = 0;
                    /* (C) the empty write end is immediately POLLOUT-ready (timeout 0) */
                    struct pollfd w = { f2[1], POLLOUT, 0 };
                    if (!(sys_poll(&w, 1, 0) == 1 && (w.revents & POLLOUT))) ok = 0;
                    sys_fdclose(f2[0]); sys_fdclose(f2[1]);
                } else ok = 0;
                /* (D) a never-opened fd -> POLLNVAL (counts toward the ready total) */
                struct pollfd bad = { 999, POLLIN, 0 };
                if (!(sys_poll(&bad, 1, 0) == 1 && (bad.revents & POLLNVAL))) ok = 0;
                print(ok ? "poll: blocking POLLIN + timeout=0 + POLLOUT + POLLNVAL all OK\n"
                         : "polltest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "selecttest")) {   /* select(2): fd_set-shaped readiness multiplex (M1584) */
            int ok = 1, fds[2];
            if (sys_pipe(fds) != 0) { print("selecttest: pipe() failed\n"); g_status = 1; }
            else {
                long pid = sys_fork();
                if (pid == 0) {                      /* child: make the read end readable */
                    sys_fdclose(fds[0]);
                    sys_fdwrite(fds[1], "S", 1);
                    sys_fdclose(fds[1]);
                    sys_exit(0);
                }
                sys_fdclose(fds[1]);                 /* parent drops its write end */
                /* (A) block in select until the child writes -> 1, the bit set */
                fd_set rset; FD_ZERO(&rset); FD_SET(fds[0], &rset);
                struct timeval tv1 = { 1, 0 };
                long r = sys_select(fds[0] + 1, &rset, 0, 0, &tv1);
                if (!(r == 1 && FD_ISSET(fds[0], &rset))) ok = 0;
                char b[8]; long n = sys_fdread(fds[0], b, sizeof b);
                if (!(n == 1 && b[0] == 'S')) ok = 0;
                sys_fdclose(fds[0]);
                int st = 0; sys_waitpid((int)pid, &st);
                /* (B) idle read end (writer still open) + short timeout -> 0, bit cleared */
                int f2[2];
                if (sys_pipe(f2) == 0) {
                    fd_set rset2; FD_ZERO(&rset2); FD_SET(f2[0], &rset2);
                    struct timeval tv2 = { 0, 30000 };
                    if (!(sys_select(f2[0] + 1, &rset2, 0, 0, &tv2) == 0 && !FD_ISSET(f2[0], &rset2))) ok = 0;
                    /* (C) the empty write end is immediately writable (timeout 0) */
                    fd_set wset; FD_ZERO(&wset); FD_SET(f2[1], &wset);
                    struct timeval tv3 = { 0, 0 };
                    if (!(sys_select(f2[1] + 1, 0, &wset, 0, &tv3) == 1 && FD_ISSET(f2[1], &wset))) ok = 0;
                    sys_fdclose(f2[0]); sys_fdclose(f2[1]);
                } else ok = 0;
                /* (D) an fd beyond the fd table's own range -> -1 (EBADF-equivalent), matching
                 * real select; unlike polltest's arbitrary 999, must stay < FD_SETSIZE (32) */
                fd_set badset; FD_ZERO(&badset); FD_SET(30, &badset);
                struct timeval tv4 = { 0, 0 };
                if (sys_select(31, &badset, 0, 0, &tv4) != -1) ok = 0;
                print(ok ? "select: blocking read-ready + timeout=0 not-ready + write-ready + bad-fd -1 all OK\n"
                         : "selecttest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "ppolltest")) {   /* ppoll: like poll, but signal-interruptible (M1573) */
            int ok = 1, fds[2];
            if (sys_pipe(fds) != 0) { print("ppolltest: pipe() failed\n"); g_status = 1; }
            else {
                long shmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT);
                volatile unsigned long *sh = (shmid >= 0) ? (volatile unsigned long *)sys_shmat((int)shmid) : 0;
                if (!sh) ok = 0;
                else {
                    sh[0] = 0; sh[1] = 0;
                    long c = sys_fork();     /* fork inherits fds[0] -- nobody ever writes to it, so it never becomes ready on its own */
                    if (c == 0) {
                        sys_signal(10 /*SIGUSR1*/, sh_sigsuspend_handler);   /* required, or the signal is dropped */
                        volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)shmid);
                        struct pollfd p = { fds[0], POLLIN, 0 };
                        unsigned long t0 = sys_uptime_ms();
                        long r = sys_ppoll(&p, 1, 10000, 0);   /* 10s timeout, unblock everything for the wait */
                        unsigned long elapsed = sys_uptime_ms() - t0;
                        if (m) { m[0] = elapsed; m[1] = (unsigned long)(r == -1 ? 1 : 0); }
                        sys_exit(0);
                    }
                    sys_sleep(200);
                    if (c > 0) { sys_sigqueue((int)c, 10, 0); int st; sys_waitpid((int)c, &st); }
                    unsigned long elapsed = sh[0]; int interrupted = (int)sh[1];
                    ok = (elapsed < 2000 && interrupted);   /* returned in well under the 10s timeout, reporting -1 */
                    print("ppoll: a 10s-timeout wait interrupted by a signal after "); printl((int)elapsed); print("ms -- ");
                    sys_setcolor(ok ? 10 : 4); print(ok ? "OK\n" : "VERIFY FAILED\n"); sys_setcolor(0);
                    if (!ok) g_status = 1;
                    sys_shmdt((void *)sh);
                }
                sys_fdclose(fds[0]); sys_fdclose(fds[1]);
            }
        } else if (streq(line, "iovtest")) {   /* readv/writev: scatter-gather over an fd (M1574) */
            int ok = 1, fds[2];
            if (sys_pipe(fds) != 0) { perr("iovtest: pipe failed\n"); g_status = 1; }
            else {
                char a[7] = "Hello, ", b[6] = "world!";       /* 7 + 6 = 13 bytes: "Hello, world!" */
                struct iovec wiov[2] = { { a, 7 }, { b, 6 } };
                long wn = sys_writev(fds[1], wiov, 2);
                if (wn != 13) ok = 0;
                char r1[5] = {0}, r2[8] = {0};                 /* differently-sized read segments: 5 + 8 = 13 */
                struct iovec riov[2] = { { r1, 5 }, { r2, 8 } };
                long rn = sys_readv(fds[0], riov, 2);
                if (rn != 13) ok = 0;
                /* "Hello, world!" split across the two DIFFERENTLY-sized buffers: "Hello" + ", world!" */
                if (!(r1[0] == 'H' && r1[4] == 'o')) ok = 0;
                if (!(r2[0] == ',' && r2[7] == '!')) ok = 0;
                sys_fdclose(fds[0]); sys_fdclose(fds[1]);
            }
            print(ok ? "readv/writev: two-segment scatter-gather over a pipe, byte-exact join/split -- OK\n"
                     : "iovtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "splicetest")) {  /* splice/tee: zero-copy pipe->pipe movement (M1211) */
            int ok = 1, a[2], b[2];
            if (sys_pipe(a) != 0 || sys_pipe(b) != 0) { print("splicetest: pipe() failed\n"); g_status = 1; }
            else {
                /* splice: move "hello world" from a -> b, CONSUMING a */
                sys_fdwrite(a[1], "hello world", 11);
                if (sys_splice(a[0], b[1], 100) != 11) ok = 0;
                char buf[32]; long n = sys_fdread(b[0], buf, sizeof buf);
                if (!(n == 11 && buf[0] == 'h' && buf[10] == 'd')) ok = 0;
                /* the source is now drained (splice consumed it): poll says not readable */
                struct pollfd pf = { a[0], POLLIN, 0 };
                if (sys_poll(&pf, 1, 0) != 0) ok = 0;
                sys_fdclose(a[0]); sys_fdclose(a[1]); sys_fdclose(b[0]); sys_fdclose(b[1]);
                /* tee: copy "abc" from c -> d WITHOUT consuming c */
                int c[2], d[2];
                if (sys_pipe(c) == 0 && sys_pipe(d) == 0) {
                    sys_fdwrite(c[1], "abc", 3);
                    if (sys_tee(c[0], d[1], 100) != 3) ok = 0;
                    char e[8]; long dn = sys_fdread(d[0], e, sizeof e);   /* dest got the copy */
                    if (!(dn == 3 && e[0] == 'a' && e[2] == 'c')) ok = 0;
                    char f[8]; long cn = sys_fdread(c[0], f, sizeof f);   /* source STILL readable */
                    if (!(cn == 3 && f[0] == 'a' && f[2] == 'c')) ok = 0;
                    sys_fdclose(c[0]); sys_fdclose(c[1]); sys_fdclose(d[0]); sys_fdclose(d[1]);
                } else ok = 0;
                print(ok ? "splice/tee: 11B spliced (src drained) + 3B teed (src preserved) -- OK\n"
                         : "splicetest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "memfdtest")) {  /* memfd_create + F_SEAL file seals (M1212) */
            int ok = 1;
            int fd = sys_memfd_create("scratch", MFD_ALLOW_SEALING);
            if (fd < 3) { perr("memfdtest: memfd_create failed\n"); g_status = 1; }
            else {
                /* write, rewind, read back */
                if (sys_fdwrite(fd, "hello world", 11) != 11) ok = 0;
                sys_lseek(fd, 0, SEEK_SET);
                char b[32]; long n = sys_fdread(fd, b, sizeof b);
                if (!(n == 11 && b[0] == 'h' && b[10] == 'd')) ok = 0;
                /* SEAL_GROW: can't grow, but a shrink is still allowed */
                if (sys_memfd_seal(fd, F_SEAL_GROW) < 0) ok = 0;
                if (sys_ftruncate(fd, 100) != -1) ok = 0;        /* grow rejected */
                if (sys_ftruncate(fd, 5) != 0) ok = 0;           /* shrink ok -> "hello" */
                /* SEAL_SHRINK: now a shrink is rejected too */
                if (sys_memfd_seal(fd, F_SEAL_SHRINK) < 0) ok = 0;
                if (sys_ftruncate(fd, 2) != -1) ok = 0;          /* shrink rejected */
                /* SEAL_WRITE: writes rejected, contents intact */
                if (sys_memfd_seal(fd, F_SEAL_WRITE) < 0) ok = 0;
                sys_lseek(fd, 0, SEEK_SET);
                if (sys_fdwrite(fd, "X", 1) != -1) ok = 0;       /* write rejected */
                sys_lseek(fd, 0, SEEK_SET);
                char c[16]; long cn = sys_fdread(fd, c, sizeof c);
                if (!(cn == 5 && c[0] == 'h' && c[4] == 'o')) ok = 0;   /* unchanged "hello" */
                /* SEAL_SEAL: no further seals can be added */
                if (sys_memfd_seal(fd, F_SEAL_SEAL) < 0) ok = 0;
                if (sys_memfd_seal(fd, F_SEAL_WRITE) != -1) ok = 0;     /* sealing is sealed */
                sys_fdclose(fd);
                print(ok ? "memfd: rw + ftruncate + SEAL_GROW/SHRINK/WRITE/SEAL all enforced -- OK\n"
                         : "memfdtest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "fsynctest")) {   /* fsync/fdatasync/sync_file_range: real for a file fd, denied otherwise (M1566) */
            int ok = 1;
            sys_writefile("/tmp/FS.TXT", "durable", 7);
            int fd = sys_open("/tmp/FS.TXT");
            if (fd < 0) ok = 0;
            else {
                if (sys_fsync(fd) != 0) ok = 0;
                if (sys_fdatasync(fd) != 0) ok = 0;
                if (sys_sync_file_range(fd, 0, 7, 0) != 0) ok = 0;
                sys_fdclose(fd);
            }
            sys_delete("/tmp/FS.TXT");
            int mfd = sys_memfd_create("m", 0);            /* no notion of "reached stable storage" for a memfd here -- must be denied */
            if (mfd < 0 || sys_fsync(mfd) != -1) ok = 0;
            if (mfd >= 0) sys_fdclose(mfd);
            sys_sync();                                    /* sync (M1588): no fd, no return value to check -- real
                                                              * POSIX sync() has no failure mode either; the only
                                                              * thing to prove is that it returns at all rather than
                                                              * hanging, which this command finishing and printing
                                                              * its own result right below already demonstrates */
            print(ok ? "fsync/fdatasync/sync_file_range: 0 on a real file fd (write-through already durable), -1 on a memfd; sync() returns -- OK\n"
                     : "fsynctest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "lxabitest")) {
            /* M1938: execute the `syscall` INSTRUCTION from ring 3 and prove it
             * lands in the Linux ABI dispatcher, not the native int 0x80 one.
             *
             * Before this the instruction was unarmed (EFER.SCE clear), so it
             * raised #UD and killed the task -- which is also the failure mode
             * if any part of the entry path is wrong, since a bad stack switch
             * cannot return. Reaching the next line at all is most of the test.
             *
             * The write() output goes through the kernel console, so unlike
             * ring-3 print() it reaches COM1 and a headless run can grep it. */
            long pid = -1, nosys = 0, wrote = -1;
            static const char msg[] = "[lxabi] hello from a LINUX syscall in ring 3\n";

            __asm__ volatile("syscall" : "=a"(pid)   : "a"(39L)   : "rcx", "r11", "memory");   /* Linux getpid */
            __asm__ volatile("syscall" : "=a"(nosys) : "a"(9999L) : "rcx", "r11", "memory");   /* unimplemented */
            __asm__ volatile("syscall"
                             : "=a"(wrote)
                             : "a"(1L), "D"(1L), "S"(msg), "d"((long)sizeof msg - 1)
                             : "rcx", "r11", "memory");                                        /* Linux write */

            int ok = 1;
            if (pid <= 0)                       { print("lxabitest: getpid via syscall returned nothing sane\n"); ok = 0; }
            if (nosys != -38)                   { print("lxabitest: an unimplemented call did not return -ENOSYS\n"); ok = 0; }
            if (wrote != (long)sizeof msg - 1)  { print("lxabitest: write returned the wrong byte count\n"); ok = 0; }
            if (ok) {
                char pb[24]; ltoa_simple(pid, pb);
                print("lxabitest: `syscall` reached the Linux dispatcher -- getpid="); print(pb);
                print(", unknown call -> -ENOSYS, write echoed to the kernel console -- OK\n");
            } else print("lxabitest: VERIFY FAILED\n");
        } else if (startswith(line, "ext2caps")) {
            /* M1937: the Phase-1 completion bar for the self-hosting campaign --
             * everything a borrowed userland needs from a filesystem and the
             * boot FAT32 volume cannot provide at all: long mixed-case names,
             * deep paths, symlinks, hard links, case SENSITIVITY, a directory
             * with far more entries than one block, and a file far larger than
             * any buffer. Runs on the ext2 volume; pass a different mount as an
             * argument if it is not /disk2. */
            const char *M = "/disk2";
            { const char *q = line + 8; while (*q == ' ') q++; if (*q) M = q; }
            int ok = 1;
            char p[192], p2[192];
            int ml = 0; while (M[ml] && ml < 64) ml++;

            /* (1) case SENSITIVITY: FAT32 folds case, so Foo/foo are one file
             *     there. On ext2 they must be two, with distinct contents. */
            { int n = 0; for (int i = 0; i < ml; i++) p[n++] = M[i];
              for (const char *t = "/Case.txt"; *t; t++) p[n++] = *t; p[n] = 0; }
            { int n = 0; for (int i = 0; i < ml; i++) p2[n++] = M[i];
              for (const char *t = "/case.txt"; *t; t++) p2[n++] = *t; p2[n] = 0; }
            sys_delete(p); sys_delete(p2);
            if (sys_writefile(p, "UPPER", 5) < 0 || sys_writefile(p2, "lower", 5) < 0) {
                print("ext2caps: case-pair create failed\n"); ok = 0;
            } else {
                char a[8], b[8];
                long ra = sys_readfile(p, a, sizeof a), rb2 = sys_readfile(p2, b, sizeof b);
                if (ra != 5 || rb2 != 5 || a[0] != 'U' || b[0] != 'l') {
                    print("ext2caps: Foo.txt and foo.txt are NOT distinct files (case folded)\n"); ok = 0;
                }
            }

            /* (2) a DEEP path: 7 nested 20-char directories, ~160 chars total.
             *     The boot volume's 8.3 names cannot express this at all. */
            if (ok) {
                int n = 0; for (int i = 0; i < ml; i++) p[n++] = M[i];
                for (int d = 0; d < 7 && ok; d++) {
                    p[n++] = '/';
                    for (int k = 0; k < 19; k++) p[n++] = (char)('a' + ((d * 7 + k) % 26));
                    p[n] = 0;
                    if (sys_mkdir(p) < 0) {
                        char db[24]; itoa_simple(d, db);
                        print("ext2caps: mkdir failed at depth "); print(db); print("\n"); ok = 0;
                    }
                }
                if (ok) {
                    for (const char *t = "/leaf.txt"; *t; t++) p[n++] = *t; p[n] = 0;
                    if (sys_writefile(p, "deep", 4) < 0) { print("ext2caps: deep-path write failed\n"); ok = 0; }
                    else { char g[8]; if (sys_readfile(p, g, sizeof g) != 4 || g[0] != 'd') {
                             print("ext2caps: deep-path read-back wrong\n"); ok = 0; } }
                }
            }

            /* (3) symlink: created, read back UNFOLLOWED, and followed on read */
            if (ok) {
                int n = 0; for (int i = 0; i < ml; i++) p2[n++] = M[i];
                for (const char *t = "/link-to-case"; *t; t++) p2[n++] = *t; p2[n] = 0;
                { int m = 0; for (int i = 0; i < ml; i++) p[m++] = M[i];
                  for (const char *t = "/Case.txt"; *t; t++) p[m++] = *t; p[m] = 0; }
                sys_delete(p2);
                if (sys_symlink(p2, p) < 0) { print("ext2caps: symlink create failed\n"); ok = 0; }
                else {
                    char tgt[192]; long tn = sys_readlink(p2, tgt, sizeof tgt - 1);
                    if (tn <= 0) { print("ext2caps: readlink failed\n"); ok = 0; }
                    else { tgt[tn] = 0; if (!streq(tgt, p)) { print("ext2caps: symlink target wrong: "); print(tgt); print("\n"); ok = 0; } }
                }
            }

            /* (4) hard link: a second name for the SAME inode -- the contents
             *     must survive unlinking the original name */
            if (ok) {
                int n = 0; for (int i = 0; i < ml; i++) p[n++] = M[i];
                for (const char *t = "/hl-a.txt"; *t; t++) p[n++] = *t; p[n] = 0;
                int m = 0; for (int i = 0; i < ml; i++) p2[m++] = M[i];
                for (const char *t = "/hl-b.txt"; *t; t++) p2[m++] = *t; p2[m] = 0;
                sys_delete(p); sys_delete(p2);
                if (sys_writefile(p, "shared-inode", 12) < 0) { print("ext2caps: hardlink setup failed\n"); ok = 0; }
                else if (sys_link(p, p2) < 0) { print("ext2caps: hard link failed\n"); ok = 0; }
                else {
                    sys_delete(p);                       /* drop the ORIGINAL name */
                    char g[16]; long r = sys_readfile(p2, g, sizeof g);
                    if (r != 12 || g[0] != 's') { print("ext2caps: hard link did not survive unlinking the original\n"); ok = 0; }
                }
            }

            /* (5) 400 files in ONE directory: ~170 entries fit a 4 KiB block,
             *     so this needs the directory to GROW (M1933) */
            int made = 0;
            if (ok) {
                int base = 0; for (int i = 0; i < ml; i++) p[base++] = M[i];
                for (const char *t = "/many"; *t; t++) p[base++] = *t; p[base] = 0;
                sys_mkdir(p);
                for (int i = 0; i < 400; i++) {
                    int n = base; p[n++] = '/';
                    char nb[12]; itoa_simple(i, nb);
                    for (const char *t = "entry-"; *t; t++) p[n++] = *t;
                    for (const char *t = nb; *t; t++) p[n++] = *t;
                    for (const char *t = ".txt"; *t; t++) p[n++] = *t;
                    p[n] = 0;
                    if (sys_writefile(p, "e", 1) < 0) break;
                    made++;
                }
                if (made < 400) { char mb[16]; itoa_simple(made, mb);
                    print("ext2caps: only "); print(mb); print(" of 400 files in one directory\n"); ok = 0; }
            }

            if (ok) { char mb[16]; itoa_simple(made, mb);
                print("ext2caps: case-sensitive pair, 7-deep ~160-char path, symlink, hard link surviving unlink, ");
                print(mb); print(" files in one directory -- OK\n"); }
            else print("ext2caps: VERIFY FAILED\n");
        } else if (startswith(line, "fdcaptest")) {
            /* M1936: the raised process/fd/path caps. 24 fds (21 usable after
             * stdio) is below what ordinary tools open at startup, and the
             * per-fd path was 64 bytes with SILENT truncation -- which would
             * mangle any moderately nested source path. */
            int ok = 1, opened = 0;
            static int fds[120];
            sys_writefile("/tmp/CAP.TXT", "x", 1);
            for (int i = 0; i < 120; i++) {
                fds[i] = sys_open("/tmp/CAP.TXT");
                if (fds[i] < 0) break;
                opened++;
            }
            for (int i = 0; i < opened; i++) sys_fdclose(fds[i]);
            sys_delete("/tmp/CAP.TXT");
            if (opened < 100) {
                char ob[24]; itoa_simple(opened, ob);
                print("fdcaptest: only "); print(ob); print(" concurrent fds (want >=100)\n"); ok = 0;
            }

            /* A path longer than the old 64-byte buffer must survive a
             * round-trip -- truncation would either fail or, far worse,
             * silently read and write a DIFFERENT file. */
            if (ok) {
                /* On the EXT2 volume, not /tmp: tmpfs caps names at 64 chars,
                 * so a 100-char basename cannot round-trip there at all (the
                 * first version of this test used /tmp and failed for that
                 * reason, not because of the fd path). ext2 allows 255. */
                const char *D = "/disk2";
                { const char *q = line + 9; while (*q == ' ') q++; if (*q) D = q; }
                char lp[160]; int n2 = 0;
                for (const char *t = D; *t; t++) lp[n2++] = *t;
                lp[n2++] = '/';
                for (int k = 0; k < 100; k++) lp[n2++] = (char)('a' + (k % 26));   /* 100-char basename */
                lp[n2] = 0;
                if (sys_writefile(lp, "deep-path-payload", 17) < 0) { print("fdcaptest: long-path write failed\n"); ok = 0; }
                else {
                    char back[32]; long r2 = sys_readfile(lp, back, sizeof back);
                    if (r2 != 17) { print("fdcaptest: long-path read-back wrong length\n"); ok = 0; }
                    else {
                        int fd2 = sys_openat(AT_FDCWD, lp, O_RDONLY);
                        if (fd2 < 0) { print("fdcaptest: long path not openable as an fd\n"); ok = 0; }
                        else {
                            char g[32]; long rn = sys_fdread(fd2, g, sizeof g);
                            /* the fd remembers its OWN copy of the path -- this is
                             * what the 64-byte buffer used to truncate */
                            if (rn != 17 || g[0] != 'd') { print("fdcaptest: fd on a long path read wrong data\n"); ok = 0; }
                            sys_fdclose(fd2);
                        }
                    }
                    sys_delete(lp);
                }
            }
            /* M1937: a path too long to REPRESENT must be refused, not
             * truncated. Truncation is the dangerous outcome -- a shortened
             * path names a DIFFERENT file, so the call "succeeds" against the
             * wrong target. Before the guard this created a file at the
             * truncated name and returned success. */
            if (ok) {
                char xl[400]; int n3 = 0;
                for (const char *t = "/disk2/"; *t; t++) xl[n3++] = *t;
                for (int k = 0; k < 300; k++) xl[n3++] = 'z';     /* ~307 chars > VFS_PATH_MAX */
                xl[n3] = 0;
                if (sys_writefile(xl, "nope", 4) >= 0) {
                    print("fdcaptest: a 307-char path was ACCEPTED (silently truncated to another name)\n");
                    ok = 0;
                }
            }
            if (ok) {
                char ob[24]; itoa_simple(opened, ob);
                print("fdcaptest: "); print(ob);
                print(" concurrent fds, 105-char path round-trips, 307-char path refused not truncated -- OK\n");
            } else print("fdcaptest: VERIFY FAILED\n");
        } else if (startswith(line, "streamtest")) {
            /* M1935: build a file FAR larger than any buffer we hold, through
             * the ordinary fd path, on the ext2 volume. Before this, every
             * write through a file fd read-modify-wrote the WHOLE file and was
             * hard-capped at 1 MiB (FILEFD_CAP), so a 4 MiB file was simply
             * not expressible -- which is also why no toolchain could ever run
             * here. 4 MiB in 64 KiB chunks is 64 writes; the whole point is
             * that peak memory stays at one chunk. */
            /* Optional path argument; defaults to the ext2 volume. Which /diskN
             * that is depends on how many drives precede it in the scan (the
             * FAT32 boot disk takes /disk1, so ext2 lands on /disk2) -- so the
             * path is an argument rather than a hardcoded guess. */
            const char *P = "/disk2/stream.bin";
            { const char *q = line + 10; while (*q == ' ') q++; if (*q) P = q; }
            const unsigned long CH = 64ul * 1024, TOTAL = 4ul * 1024 * 1024;
            char *bufp = malloc(CH);
            int ok = 1;
            if (!bufp) { print("streamtest: out of memory\n"); ok = 0; }
            if (ok) {
                sys_delete(P);                              /* start clean if a previous run left it */
                int fd = sys_openat(AT_FDCWD, P, O_WRONLY | O_CREAT);
                if (fd < 0) {
                    print("streamtest: cannot create "); print(P);
                    print(" -- is an ext2 volume mounted there? (try lsblk / df)\n");
                    ok = 0;
                } else {
                    for (unsigned long o = 0; ok && o < TOTAL; o += CH) {
                        for (unsigned long k = 0; k < CH; k++) bufp[k] = (char)((o + k) * 31 + 7);
                        if (sys_pwrite(fd, bufp, CH, (long)o) != (long)CH) {
                            char ob[24]; ltoa_simple((long)o, ob);
                            print("streamtest: pwrite failed at offset "); print(ob); print("\n");
                            ok = 0;
                        }
                    }
                    sys_fdclose(fd);
                }
            }
            if (ok) {   /* verify by POSITION, including well past the old 1 MiB cap */
                int rfd = sys_open(P);
                if (rfd < 0) { print("streamtest: reopen failed\n"); ok = 0; }
                else {
                    unsigned long probes[4] = { 0, 1024ul * 1024 + 5, 3ul * 1024 * 1024, TOTAL - 8 };
                    for (int t = 0; ok && t < 4; t++) {
                        char g[8];
                        if (sys_pread(rfd, g, 8, (long)probes[t]) != 8) {
                            char ob[24]; ltoa_simple((long)probes[t], ob);
                            print("streamtest: pread short at "); print(ob); print("\n"); ok = 0; break;
                        }
                        for (int k = 0; k < 8; k++)
                            if (g[k] != (char)((probes[t] + (unsigned long)k) * 31 + 7)) {
                                char ob[24]; ltoa_simple((long)probes[t] + k, ob);
                                print("streamtest: wrong byte at "); print(ob); print("\n"); ok = 0; break;
                            }
                    }
                    /* and the file must END exactly at TOTAL, not run on */
                    char g2[8];
                    if (ok && sys_pread(rfd, g2, 8, (long)TOTAL) != 0) { print("streamtest: file longer than written\n"); ok = 0; }
                    sys_fdclose(rfd);
                }
            }
            if (bufp) free(bufp);
            if (ok) { print("streamtest: wrote 4 MiB to "); print(P);
                      print(" in 64 KiB chunks (4x the old 1 MiB fd cap), 4 offsets byte-exact -- OK\n"); }
            else    print("streamtest: VERIFY FAILED\n");
        } else if (streq(line, "preadwritetest")) {   /* pread/pwrite: explicit offset, cursor never moves (M1572) */
            int ok = 1;
            sys_writefile("/tmp/PW.TXT", "0123456789", 10);
            int fd = sys_openat(AT_FDCWD, "/tmp/PW.TXT", O_WRONLY);
            if (fd < 0) ok = 0;
            else {
                if (sys_pwrite(fd, "BBBB", 4, 4096) != 4) ok = 0;   /* out of order: high offset first... */
                if (sys_pwrite(fd, "AAAA", 4, 0) != 4) ok = 0;      /* ...then low offset */
                if (sys_lseek(fd, 0, SEEK_CUR) != 0) ok = 0;        /* neither pwrite moved the cursor (started at 0) */
                sys_fdclose(fd);
                int rfd = sys_open("/tmp/PW.TXT");
                char buf[10]; long n = (rfd >= 0) ? sys_fdread(rfd, buf, sizeof buf) : -1;   /* a REGULAR read -- advances the cursor to 10 */
                /* "AAAA456789": the first 4 bytes overwritten, "456789" left untouched */
                if (n != 10 || buf[0] != 'A' || buf[3] != 'A' || buf[4] != '4' || buf[9] != '9') ok = 0;
                long cur_before = (rfd >= 0) ? sys_lseek(rfd, 0, SEEK_CUR) : -1;   /* whatever the regular read left it at (10) */
                char big[8]; long n2 = (rfd >= 0) ? sys_pread(rfd, big, sizeof big, 4096) : -1;
                if (n2 != 4 || big[0] != 'B' || big[3] != 'B') ok = 0;   /* the high-offset write landed too */
                if (rfd >= 0 && sys_lseek(rfd, 0, SEEK_CUR) != cur_before) ok = 0;   /* pread left the cursor EXACTLY where it already was */
                if (rfd >= 0) sys_fdclose(rfd);
            }
            sys_delete("/tmp/PW.TXT");
            print(ok ? "pread/pwrite: out-of-order offsets land correctly, neither moves the fd cursor -- OK\n"
                     : "preadwritetest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "piovtest")) {   /* preadv/pwritev: scatter-gather at an explicit offset, cursor untouched (M1577) */
            int ok = 1;
            sys_writefile("/tmp/PIOV.TXT", "0123456789ABCDEF", 16);
            int fd = sys_openat(AT_FDCWD, "/tmp/PIOV.TXT", O_WRONLY);
            if (fd < 0) ok = 0;
            else {
                char w1[4] = "WXYZ", w2[3] = "!@#";
                struct iovec wiov[2] = { { w1, 4 }, { w2, 3 } };   /* 7 bytes total, at offset 5 */
                if (sys_pwritev(fd, wiov, 2, 5) != 7) ok = 0;
                if (sys_lseek(fd, 0, SEEK_CUR) != 0) ok = 0;        /* pwritev never moved the cursor */
                sys_fdclose(fd);

                int rfd = sys_open("/tmp/PIOV.TXT");
                char buf[16] = {0}; long n = sys_fdread(rfd, buf, sizeof buf);   /* a regular read -- advances rfd's cursor to 16 */
                /* "0123456789ABCDEF" with [5,12) overwritten by "WXYZ!@#" -> "01234WXYZ!@#CDEF" */
                if (n != 16 || buf[0]!='0' || buf[4]!='4' || buf[5]!='W' || buf[8]!='Z' || buf[9]!='!' || buf[11]!='#' || buf[12]!='C' || buf[15]!='F') ok = 0;

                long cur_before = sys_lseek(rfd, 0, SEEK_CUR);      /* whatever the regular read left it at (16) */
                char r1[3] = {0}, r2[4] = {0};
                struct iovec riov[2] = { { r1, 3 }, { r2, 4 } };     /* differently-sized read segments, at offset 5 again */
                long rn = sys_preadv(rfd, riov, 2, 5);
                if (rn != 7) ok = 0;
                if (!(r1[0]=='W' && r1[2]=='Y')) ok = 0;              /* r1 = "WXY" */
                if (!(r2[0]=='Z' && r2[3]=='#')) ok = 0;              /* r2 = "Z!@#" */
                if (sys_lseek(rfd, 0, SEEK_CUR) != cur_before) ok = 0;   /* preadv left the cursor exactly where it already was */
                sys_fdclose(rfd);
            }
            sys_delete("/tmp/PIOV.TXT");
            print(ok ? "preadv/pwritev: scatter-gather at an explicit offset lands correctly, cursor never moves -- OK\n"
                     : "piovtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "fxattrtest")) {   /* f{set,get,list,remove}xattr: fd-based siblings of *xattr (M1569) */
            int ok = 1;
            sys_writefile("/tmp/FX.TXT", "hi", 2);
            int fd = sys_open("/tmp/FX.TXT");
            if (fd < 0) ok = 0;
            else {
                /* FAT32-only boot disk (no ext2 volume) -- same honest limitation as
                 * M1553's fchmodat/fchownat: what's verifiable here is that the fd->path
                 * resolution reaches vfs_*xattr and denies cleanly, the SAME way the
                 * path-based call on the SAME file already does -- not the success path. */
                char buf[32];
                if (sys_fsetxattr(fd, "user.x", "v", 1) != -1) ok = 0;
                if (sys_fgetxattr(fd, "user.x", buf, sizeof buf) != -1) ok = 0;
                if (sys_flistxattr(fd, buf, sizeof buf) != -1) ok = 0;
                if (sys_fremovexattr(fd, "user.x") != -1) ok = 0;
                if (sys_setxattr("/tmp/FX.TXT", "user.x", "v", 1) != -1) ok = 0;   /* path-based: same denial */
                sys_fdclose(fd);
            }
            sys_delete("/tmp/FX.TXT");
            int mfd = sys_memfd_create("mx", 0);          /* a non-FILE fd: app_fd_path returns 0, must deny too */
            if (mfd < 0 || sys_fsetxattr(mfd, "user.x", "v", 1) != -1) ok = 0;
            if (mfd >= 0) sys_fdclose(mfd);
            print(ok ? "f{set,get,list,remove}xattr: fd->path resolution reaches vfs_*xattr (denies cleanly on FAT32, same as path-based; denies a non-file fd too) -- OK\n"
                     : "fxattrtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "tcflushtest")) {   /* tcflush/tcdrain (M1570) */
            int ok = 1;
            /* The actual input-discard behavior needs a pending keystroke already
             * sitting in iq[] to discard -- but nothing ring-3-reachable can inject
             * one there (app_paste is desktop.c-only, triggered by a real middle-
             * click; the raw hardware handler is the ONLY other writer). What's
             * honestly, deterministically testable from a scripted shell command:
             * the three real queue selectors are accepted, a bogus one is denied,
             * and tcdrain (a no-op here -- console output is synchronous, same
             * reasoning as M1566's fsync) always succeeds. */
            if (sys_tcflush(TCIFLUSH) != 0) ok = 0;
            if (sys_tcflush(TCOFLUSH) != 0) ok = 0;
            if (sys_tcflush(TCIOFLUSH) != 0) ok = 0;
            if (sys_tcflush(99 /* bogus selector */) != -1) ok = 0;
            if (sys_tcdrain() != 0) ok = 0;
            print(ok ? "tcflush/tcdrain: TCIFLUSH/TCOFLUSH/TCIOFLUSH accepted, a bad selector denied, tcdrain OK -- OK\n"
                     : "tcflushtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "prlimittest")) {  /* prlimit(2) get/set + /proc/<pid>/limits (M1214) */
            sys_prlimit(0, RLIMIT_NPROC, 7, 1);              /* set self's NPROC limit = 7 */
            long got = sys_prlimit(0, RLIMIT_NPROC, 0, 0);   /* query it back */
            char lb[512]; long n = sys_readfile("/proc/self/limits", lb, sizeof lb - 1);
            int has7 = 0; for (long i = 0; i < n; i++) if (lb[i] == '7') { has7 = 1; break; }
            int ok = (got == 7) && (n > 0) && has7;          /* round-trip + the file rendered it */
            print(ok ? "prlimit: set self NPROC=7, query returns 7, /proc/self/limits shows it -- OK\n"
                     : "prlimittest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "auxvtest")) {   /* synthetic ELF auxv via /proc/self/auxv (M1215) */
            unsigned char ab[256]; long n = sys_readfile("/proc/self/auxv", ab, sizeof ab);
            int pagesz_ok = 0, entry_ok = 0, sawnull = 0;
            for (long i = 0; i + 16 <= n; i += 16) {
                unsigned long t = 0, v = 0;
                for (int k = 0; k < 8; k++) t |= (unsigned long)ab[i + k]     << (8 * k);
                for (int k = 0; k < 8; k++) v |= (unsigned long)ab[i + 8 + k] << (8 * k);
                if (t == AT_PAGESZ && v == 4096) pagesz_ok = 1;
                if (t == AT_ENTRY  && v != 0)    entry_ok = 1;
                if (t == AT_NULL) { sawnull = 1; break; }
            }
            int ok = (n > 0) && pagesz_ok && entry_ok && sawnull;
            print(ok ? "auxv: /proc/self/auxv has AT_PAGESZ=4096 + AT_ENTRY!=0, AT_NULL-terminated -- OK\n"
                     : "auxvtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "kmsgtest")) {   /* /dev/kmsg writer -> kernel log ring (M1216) */
            const char *marker = "M1216-kmsg-userspace-probe";
            int ml = 0; while (marker[ml]) ml++;
            long w = sys_writefile("/dev/kmsg", marker, ml);
            char kb[4096]; long n = sys_readfile("/proc/kmsg", kb, sizeof kb - 1);
            int found = 0;
            for (long i = 0; i + ml <= n && !found; i++) {
                int m = 1; for (int j = 0; j < ml; j++) if (kb[i + j] != marker[j]) { m = 0; break; }
                if (m) found = 1;
            }
            int ok = (w == ml) && found;
            print(ok ? "kmsg: wrote a line to /dev/kmsg, read it back from /proc/kmsg (dmesg) -- OK\n"
                     : "kmsgtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "timerfdtest")) {  /* timerfd: a pollable one-shot timer fd, composed with poll (M1217) */
            int ok = 1;
            int tfd = sys_timerfd_create();
            if (tfd < 3) { perr("timerfdtest: create failed\n"); g_status = 1; }
            else {
                sys_timerfd_settime(tfd, 80, 0);             /* one-shot: fire in 80 ms */
                /* (A) immediately, before expiry: poll timeout 0 -> not ready */
                struct pollfd p = { tfd, POLLIN, 0 };
                if (sys_poll(&p, 1, 0) != 0) ok = 0;
                /* (B) poll with a 1s timeout -> becomes POLLIN-ready after ~80 ms */
                struct pollfd q = { tfd, POLLIN, 0 };
                if (!(sys_poll(&q, 1, 1000) == 1 && (q.revents & POLLIN))) ok = 0;
                /* (C) read the 8-byte expiration count (== 1) */
                unsigned char eb[8]; long nrd = sys_fdread(tfd, eb, sizeof eb);
                if (!(nrd == 8 && eb[0] == 1)) ok = 0;
                /* (D) one-shot: after the read it disarms -> poll timeout 0 -> not ready */
                struct pollfd w = { tfd, POLLIN, 0 };
                if (sys_poll(&w, 1, 0) != 0) ok = 0;
                sys_fdclose(tfd);
                /* (E) periodic (M1302): re-arms itself; reading after several intervals
                 * returns the missed-firing count (>1), and it stays armed afterward. */
                int pfd = sys_timerfd_create();
                if (pfd < 3) ok = 0;
                else {
                    sys_timerfd_settime(pfd, 40, 40);        /* first fire 40ms, then every 40ms */
                    sys_sleep(170);                          /* ~4 firings elapse before we read */
                    unsigned char pb[8]; long pn = sys_fdread(pfd, pb, sizeof pb);
                    unsigned long pc = 0; for (int i = 0; i < 8; i++) pc |= (unsigned long)pb[i] << (i * 8);
                    if (!(pn == 8 && pc >= 2)) ok = 0;       /* accumulated multiple missed firings */
                    sys_sleep(60);                           /* still armed: next interval makes it ready again */
                    struct pollfd pp = { pfd, POLLIN, 0 };
                    if (!(sys_poll(&pp, 1, 1000) == 1 && (pp.revents & POLLIN))) ok = 0;
                    sys_fdclose(pfd);
                }
                print(ok ? "timerfd: one-shot 80ms (count=1, disarmed) + periodic 40ms (re-armed, count>1) -- OK\n"
                         : "timerfdtest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "fcntltest")) {  /* fd hygiene: FD_CLOEXEC + dup3 + close_range + fcntl (M1218) */
            int ok = 1, fds[2];
            if (sys_pipe(fds) != 0) { print("fcntltest: pipe() failed\n"); g_status = 1; }
            else {
                if (sys_fcntl(fds[0], F_GETFD, 0) != 0) ok = 0;             /* not cloexec initially */
                if (sys_fcntl(fds[0], F_SETFD, FD_CLOEXEC) != 0) ok = 0;
                if (sys_fcntl(fds[0], F_GETFD, 0) != FD_CLOEXEC) ok = 0;    /* round-trips */
                if (sys_dup3(fds[0], fds[0], 0) != -1) ok = 0;             /* dup3 EINVAL on old==new */
                if (sys_dup3(fds[1], 9, O_CLOEXEC) != 9) ok = 0;
                if (sys_fcntl(9, F_GETFD, 0) != FD_CLOEXEC) ok = 0;        /* dup3 O_CLOEXEC set it */
                int d = sys_fcntl(fds[1], F_DUPFD, 5);                      /* lowest free fd >= 5 */
                if (d < 5) ok = 0;
                if (sys_close_range(5, 20, 0) != 0) ok = 0;                /* close 5..20 (incl. d and 9) */
                if (sys_fcntl(d, F_GETFD, 0) != -1) ok = 0;                /* d is now closed */
                sys_fdclose(fds[0]); sys_fdclose(fds[1]);
                print(ok ? "fd-hygiene: FD_CLOEXEC get/set + dup3(O_CLOEXEC; EINVAL old==new) + F_DUPFD + close_range -- OK\n"
                         : "fcntltest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "sendfiletest")) {  /* sendfile(2): zero-copy fd->fd (M1219) */
            int ok = 1;
            sys_writefile("/tmp/SF.TXT", "hello sendfile world", 20);
            int in = sys_open("/tmp/SF.TXT"); int fds[2];
            if (in < 3 || sys_pipe(fds) != 0) { perr("sendfiletest: setup failed\n"); g_status = 1; }
            else {
                /* sequential (cursor) sendfile: whole file -> pipe */
                if (sys_sendfile(fds[1], in, 0, 100) != 20) ok = 0;     /* NULL off -> cursor; 20 bytes then EOF */
                char b[32]; long r = sys_fdread(fds[0], b, sizeof b);
                if (!(r == 20 && b[0] == 'h' && b[6] == 's' && b[19] == 'd')) ok = 0;
                /* positioned sendfile: offset 6, 8 bytes ("sendfile") -> a 2nd pipe; cursor untouched */
                int f2[2]; long off = 6;
                if (sys_pipe(f2) == 0) {
                    long n2 = sys_sendfile(f2[1], in, &off, 8);
                    if (!(n2 == 8 && off == 14)) ok = 0;
                    char c[16]; long r2 = sys_fdread(f2[0], c, sizeof c);
                    if (!(r2 == 8 && c[0] == 's' && c[7] == 'e')) ok = 0;   /* "sendfile" */
                    sys_fdclose(f2[0]); sys_fdclose(f2[1]);
                } else ok = 0;
                sys_fdclose(in); sys_fdclose(fds[0]); sys_fdclose(fds[1]);
                sys_delete("/tmp/SF.TXT");
                print(ok ? "sendfile: file->pipe whole (cursor) + positioned slice (off advances, cursor intact) -- OK\n"
                         : "sendfiletest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "epolltest")) {  /* epoll: scalable readiness multiplexing (M1220) */
            int ok = 1, fds[2];
            int ep = sys_epoll_create1(0);
            if (ep < 3 || sys_pipe(fds) != 0) { perr("epolltest: setup failed\n"); g_status = 1; }
            else {
                struct epoll_event ev = { POLLIN, 0xABCD };
                if (sys_epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], &ev) != 0) ok = 0;
                struct epoll_event got[4];
                /* (A) nothing written -> epoll_wait timeout 0 returns 0 */
                if (sys_epoll_wait(ep, got, 4, 0) != 0) ok = 0;
                /* (B) write -> epoll_wait returns 1 with POLLIN + the userdata echoed back */
                sys_fdwrite(fds[1], "x", 1);
                int n = sys_epoll_wait(ep, got, 4, 1000);
                if (!(n == 1 && (got[0].events & POLLIN) && got[0].data == 0xABCD)) ok = 0;
                /* (C) DEL -> the fd is no longer watched -> timeout 0 returns 0 (despite pending data) */
                if (sys_epoll_ctl(ep, EPOLL_CTL_DEL, fds[0], 0) != 0) ok = 0;
                if (sys_epoll_wait(ep, got, 4, 0) != 0) ok = 0;
                /* (D) EPOLLET (M1545): re-add edge-triggered, write once (on top of the
                 * still-undrained byte from B -- harmless, this only checks readiness,
                 * not byte count), then call epoll_wait TWICE without draining. Level-
                 * triggered would fire both times; edge must fire only the first. */
                struct epoll_event evet = { POLLIN | EPOLLET, 0xDCBA };
                if (sys_epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], &evet) != 0) ok = 0;
                sys_fdwrite(fds[1], "y", 1);
                int n1 = sys_epoll_wait(ep, got, 4, 1000);
                int n2 = sys_epoll_wait(ep, got, 4, 0);
                if (!(n1 == 1 && (got[0].events & POLLIN) && got[0].data == 0xDCBA)) ok = 0;
                if (n2 != 0) ok = 0;                        /* the edge already fired -- must stay silent */
                sys_fdclose(ep); sys_fdclose(fds[0]); sys_fdclose(fds[1]);
                print(ok ? "epoll: create + ctl(ADD) + wait(timeout 0=none, then POLLIN+data) + ctl(DEL) + EPOLLET(fires once, not again until re-armed) -- OK\n"
                         : "epolltest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "epollpwaittest")) {   /* epoll_pwait: like epoll_wait, but signal-interruptible (M1567) */
            int ok = 1, fds[2];
            int ep = sys_epoll_create1(0);
            if (ep < 3 || sys_pipe(fds) != 0) { perr("epollpwaittest: setup failed\n"); g_status = 1; }
            else {
                struct epoll_event ev = { POLLIN, 0 };
                sys_epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], &ev);   /* never written to -- never becomes ready on its own */
                long shmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT);
                volatile unsigned long *sh = (shmid >= 0) ? (volatile unsigned long *)sys_shmat((int)shmid) : 0;
                if (!sh) ok = 0;
                else {
                    sh[0] = 0; sh[1] = 0;
                    long c = sys_fork();     /* fork inherits ep/fds[0]/fds[1] -- same underlying kernel objects */
                    if (c == 0) {
                        sys_signal(10 /*SIGUSR1*/, sh_sigsuspend_handler);   /* required, or the signal is dropped */
                        volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)shmid);
                        struct epoll_event got[4];
                        unsigned long t0 = sys_uptime_ms();
                        int n = sys_epoll_pwait(ep, got, 4, 10000, 0);   /* 10s timeout, unblock everything for the wait */
                        unsigned long elapsed = sys_uptime_ms() - t0;
                        if (m) { m[0] = elapsed; m[1] = (unsigned long)(n == -1 ? 1 : 0); }
                        sys_exit(0);
                    }
                    sys_sleep(200);
                    if (c > 0) { sys_sigqueue((int)c, 10, 0); int st; sys_waitpid((int)c, &st); }
                    unsigned long elapsed = sh[0]; int interrupted = (int)sh[1];
                    ok = (elapsed < 2000 && interrupted);   /* returned in well under the 10s timeout, reporting -1 */
                    print("epoll_pwait: a 10s-timeout wait interrupted by a signal after "); printl((int)elapsed); print("ms -- ");
                    sys_setcolor(ok ? 10 : 4); print(ok ? "OK\n" : "VERIFY FAILED\n"); sys_setcolor(0);
                    if (!ok) g_status = 1;
                    sys_shmdt((void *)sh);
                }
                sys_fdclose(ep); sys_fdclose(fds[0]); sys_fdclose(fds[1]);
            }
        } else if (streq(line, "locktest")) {   /* POSIX fcntl byte-range record locks (M1221) */
            int ok = 1, rp[2];
            sys_writefile("/tmp/LK.TXT", "0123456789abcdefghij", 20);
            int fd = sys_open("/tmp/LK.TXT");
            if (fd < 3 || sys_pipe(rp) != 0) { perr("locktest: setup failed\n"); g_status = 1; }
            else {
                struct flock l = { F_WRLCK, 0, 0, 10, 0 };           /* parent write-locks [0,10) */
                if (sys_fcntl(fd, F_SETLK, (long)&l) != 0) ok = 0;
                long pid = sys_fork();
                if (pid == 0) {                                      /* child = a different owner, contends */
                    sys_fdclose(rp[0]);
                    int cok = 1;
                    struct flock c1 = { F_WRLCK, 0, 5, 10, 0 };      /* [5,15) overlaps [0,10) -> conflict */
                    if (sys_fcntl(fd, F_SETLK, (long)&c1) != -1) cok = 0;
                    struct flock c2 = { F_WRLCK, 0, 10, 10, 0 };     /* [10,20) disjoint -> ok */
                    if (sys_fcntl(fd, F_SETLK, (long)&c2) != 0) cok = 0;
                    struct flock g = { F_WRLCK, 0, 0, 5, 0 };        /* F_GETLK [0,5) -> reports the parent */
                    if (sys_fcntl(fd, F_GETLK, (long)&g) != 0) cok = 0;
                    if (!(g.l_type == F_WRLCK && g.l_pid > 0)) cok = 0;
                    sys_fdwrite(rp[1], cok ? "P" : "F", 1);
                    sys_exit(0);
                }
                sys_fdclose(rp[1]);
                char res = 0; sys_fdread(rp[0], &res, 1);
                if (res != 'P') ok = 0;
                int st = 0; sys_waitpid((int)pid, &st);
                struct flock u = { F_UNLCK, 0, 0, 10, 0 };           /* parent releases [0,10) */
                sys_fcntl(fd, F_SETLK, (long)&u);
                sys_fdclose(rp[0]); sys_fdclose(fd); sys_delete("/tmp/LK.TXT");
                print(ok ? "record-locks: WRLCK[0,10); child overlap[5,15)=conflict, disjoint[10,20)=ok, F_GETLK reports holder -- OK\n"
                         : "locktest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
                /* F_SETLKW (M1597): genuinely blocks on a conflicting range instead
                 * of failing immediately like F_SETLK -- measure elapsed time (not
                 * just the return value) to prove it really parked, matching this
                 * session's own established discipline for every timed-block test. */
                int wok = 1;
                sys_writefile("/tmp/LKW.TXT", "0123456789abcdefghij", 20);
                int wfd = sys_open("/tmp/LKW.TXT");
                long wshmid = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT);
                volatile unsigned long *wsh = (wshmid >= 0) ? (volatile unsigned long *)sys_shmat((int)wshmid) : 0;
                if (wfd < 3 || !wsh) wok = 0;
                else {
                    wsh[0] = 0; wsh[1] = 0;         /* [0]=child's measured elapsed, [1]=child's F_SETLKW success */
                    struct flock wl = { F_WRLCK, 0, 0, 10, 0 };
                    if (sys_fcntl(wfd, F_SETLK, (long)&wl) != 0) wok = 0;   /* parent holds [0,10) */
                    long wpid = sys_fork();
                    if (wpid == 0) {
                        volatile unsigned long *m = (volatile unsigned long *)sys_shmat((int)wshmid);
                        int cfd = sys_open("/tmp/LKW.TXT");
                        struct flock cl = { F_WRLCK, 0, 5, 10, 0 };   /* [5,15) overlaps the parent's [0,10) */
                        unsigned long t0 = sys_uptime_ms();
                        long r = sys_fcntl(cfd, F_SETLKW, (long)&cl);
                        unsigned long elapsed = sys_uptime_ms() - t0;
                        if (m) { m[0] = elapsed; m[1] = (unsigned long)(r == 0 ? 1 : 0); }
                        sys_exit(0);
                    }
                    sys_sleep(200);                  /* let the child reach F_SETLKW and block */
                    struct flock wu = { F_UNLCK, 0, 0, 10, 0 };
                    sys_fcntl(wfd, F_SETLK, (long)&wu);   /* release -> the child's F_SETLKW should now succeed */
                    int st2 = 0; if (wpid > 0) sys_waitpid((int)wpid, &st2);
                    unsigned long celapsed = wsh[0]; int cok = (int)wsh[1];
                    if (!(wpid > 0 && cok && celapsed >= 150)) wok = 0;   /* really blocked ~the parent's sleep */
                }
                if (wfd >= 3) sys_fdclose(wfd);
                sys_delete("/tmp/LKW.TXT");
                print(wok ? "F_SETLKW: blocks on a conflicting range (measured ~200ms), succeeds once the holder unlocks -- OK\n"
                          : "locktest: F_SETLKW VERIFY FAILED\n");
                if (!wok) g_status = 1;
            }
        } else if (streq(line, "pidfdtest")) {  /* pidfd: a pollable process-exit handle (M1222) */
            int ok = 1;
            long pid = sys_fork();
            if (pid == 0) {                          /* child: stay alive a moment, then exit */
                for (volatile long i = 0; i < 30000000; i++) {}
                sys_exit(0);
            }
            int pf = sys_pidfd_open((int)pid, 0);
            if (pf < 3) ok = 0;
            /* (A) child still running -> poll(timeout 0) returns 0 (not exited) */
            struct pollfd a0 = { pf, POLLIN, 0 };
            if (sys_poll(&a0, 1, 0) != 0) ok = 0;
            /* (B) block until the child exits -> POLLIN */
            struct pollfd b0 = { pf, POLLIN, 0 };
            if (!(sys_poll(&b0, 1, 2000) == 1 && (b0.revents & POLLIN))) ok = 0;
            int st = 0; sys_waitpid((int)pid, &st);
            sys_fdclose(pf);
            print(ok ? "pidfd: open a child handle -> poll blocks while alive, POLLIN on exit -- OK\n"
                     : "pidfdtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "getdentstest")) {  /* getdents64 + d_type (M1223) */
            int ok = 1;
            sys_mkdir("/GDT");                                /* a fresh, small test dir */
            sys_mkdir("/GDT/SUB");                            /* -> DT_DIR */
            sys_writefile("/GDT/F.TXT", "x", 1);             /* -> DT_REG */
            if (sys_chdir("/GDT") < 0) { perr("getdentstest: chdir failed\n"); g_status = 1; }
            else {
                char buf[2048];
                long n = sys_getdents64(buf, sizeof buf, 0);   /* lists the cwd (/GDT) */
                int saw_dir = 0, saw_file = 0;
                for (long off = 0; off + 19 <= n; ) {
                    struct dirent64 *de = (struct dirent64 *)(buf + off);
                    if (de->d_reclen == 0) break;
                    if (de->d_type == DT_DIR && streq(de->d_name, "SUB")) saw_dir = 1;
                    if (de->d_type == DT_REG && streq(de->d_name, "F.TXT")) saw_file = 1;
                    off += de->d_reclen;
                }
                ok = (n > 0) && saw_dir && saw_file;
                sys_chdir("/");
                sys_delete("/GDT/SUB"); sys_delete("/GDT/F.TXT"); sys_delete("/GDT");
                print(ok ? "getdents64: cwd records w/ d_type -- SUB=DT_DIR + F.TXT=DT_REG -- OK\n"
                         : "getdentstest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "accesstest")) {  /* access(2) (M1224) */
            int ok = 1;
            if (sys_access("/MOTD.TXT", F_OK) != 0) ok = 0;     /* an existing file */
            if (sys_access("/MOTD.TXT", R_OK) != 0) ok = 0;     /* readable */
            if (sys_access("/NOPE.XYZ", F_OK) != -1) ok = 0;    /* absent -> -1 */
            if (sys_access("/", X_OK) != 0) ok = 0;             /* the root dir is searchable */
            print(ok ? "access: F_OK/R_OK on /MOTD.TXT, /NOPE.XYZ absent=-1, / is X_OK -- OK\n"
                     : "accesstest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
            /* faccessat2 (M1556): the *at family's last remaining hole. */
            int ok2 = 1;
            if (sys_faccessat2(AT_FDCWD, "/MOTD.TXT", F_OK, 0) != 0) ok2 = 0;
            if (sys_faccessat2(AT_FDCWD, "/NOPE.XYZ", F_OK, 0) != -1) ok2 = 0;
            int dfd = sys_open("/");
            if (dfd < 0) ok2 = 0;
            else {
                if (sys_faccessat2(dfd, "MOTD.TXT", R_OK, 0) != 0) ok2 = 0;   /* dirfd-relative, not AT_FDCWD */
                if (sys_faccessat2(dfd, "NOPE.XYZ", F_OK, 0) != -1) ok2 = 0;
                sys_fdclose(dfd);
            }
            print(ok2 ? "faccessat2: AT_FDCWD + a real dirfd, both present/absent cases -- OK\n"
                      : "accesstest: faccessat2 VERIFY FAILED\n");
            if (!ok2) g_status = 1;
        } else if (streq(line, "prctltest")) {  /* prctl(PR_SET_NAME) + /proc/self/comm (M1225) */
            int ok = 1;
            sys_prctl(PR_SET_NAME, (unsigned long)"vacuum");
            char nm[20]; sys_prctl(PR_GET_NAME, (unsigned long)nm);
            if (!streq(nm, "vacuum")) ok = 0;                       /* PR_GET_NAME round-trips */
            char cb[64]; long n = sys_readfile("/proc/self/comm", cb, sizeof cb - 1);
            if (n > 0) { cb[n] = 0; if (n > 0 && cb[n-1] == '\n') cb[n-1] = 0; } else ok = 0;
            if (!streq(cb, "vacuum")) ok = 0;                       /* /proc/self/comm shows it */
            sys_prctl(PR_SET_NAME, (unsigned long)"Shell");        /* restore the window name */
            print(ok ? "prctl: PR_SET_NAME=vacuum, PR_GET_NAME reads it, /proc/self/comm shows it -- OK\n"
                     : "prctltest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "jointest")) {   /* set_tid_address futex-on-exit = a real blocking pthread_join (M1226) */
            int ok = 1;
            char *stk = malloc(64 * 1024);
            if (!stk) { print("jointest: oom\n"); g_status = 1; }
            else {
                g_jctid = 0;
                long tid = sys_clone((void *)join_thread_fn, stk + 64 * 1024, 0);
                if (tid <= 0) ok = 0;
                else {
                    g_jctid = (int)tid;                              /* the value the joiner blocks on */
                    sys_futex((void *)&g_jctid, FUTEX_WAIT, (int)tid, -1);  /* block until the thread exits + clears it */
                    if (g_jctid != 0) ok = 0;                        /* the kernel zeroed it on the thread's exit */
                }
                free(stk);
                print(ok ? "set_tid_address: thread registered ctid + exited -> futex woke the joiner, ctid=0 -- OK\n"
                         : "jointest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "futextimeouttest")) {   /* FUTEX_WAIT bounded wait (M1578) */
            unsigned long t0 = sys_uptime_ms();
            long r1 = sys_futex((void *)&g_ftx_word, FUTEX_WAIT, 0, 200);  /* nobody ever wakes/changes it -> must time out */
            unsigned long e1 = sys_uptime_ms() - t0;
            int timeout_ok = (r1 == -1 && e1 >= 150 && e1 < 2000);   /* really blocked ~200ms, didn't hang forever */

            char *stk = malloc(64 * 1024);
            int wake_ok = 0;
            if (stk) {
                long tid = sys_clone((void *)ftx_wake_thread_fn, stk + 64 * 1024, 0);
                unsigned long t1 = sys_uptime_ms();
                long r2 = sys_futex((void *)&g_ftx_word, FUTEX_WAIT, 0, 5000);  /* generous bound; the thread wakes us ~150ms in */
                unsigned long e2 = sys_uptime_ms() - t1;
                wake_ok = (tid > 0 && r2 == 0 && e2 < 2000);         /* woken early by FUTEX_WAKE, not by hitting the 5s bound */
                free(stk);
            }
            int ok = timeout_ok && wake_ok;
            print(ok ? "futex(WAIT, timeout_ms): times out (~200ms) when nobody wakes it, resolves early via FUTEX_WAKE when one arrives -- OK\n"
                     : "futextimeouttest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "waitidtest")) {  /* waitid(2) + WNOHANG (M1227) */
            int ok = 1;
            long pid = sys_fork();
            if (pid == 0) { for (volatile long i = 0; i < 30000000; i++) {} sys_exit(42); }   /* child: spin then exit 42 */
            struct siginfo si;
            si.si_pid = -1;
            long r1 = sys_waitid(P_PID, (int)pid, &si, WNOHANG | WEXITED);   /* (A) child still running */
            if (!(r1 == 0 && si.si_pid == 0)) ok = 0;                        /* WNOHANG: nothing reapable yet */
            long r2 = sys_waitid(P_PID, (int)pid, &si, WEXITED);             /* (B) block until it exits */
            if (!(r2 == 0 && si.si_pid == (int)pid && si.si_status == 42 && si.si_code == CLD_EXITED)) ok = 0;
            print(ok ? "waitid: WNOHANG=nothing-yet (si_pid=0), then blocking reap si_status=42 CLD_EXITED -- OK\n"
                     : "waitidtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "truncatetest")) {  /* truncate/ftruncate on real files (M1228) */
            int ok = 1;
            sys_writefile("/tmp/T.TXT", "hello world", 11);
            if (sys_truncate("/tmp/T.TXT", 5) != 0) ok = 0;              /* shrink */
            char b[32]; long n = sys_readfile("/tmp/T.TXT", b, sizeof b);
            if (!(n == 5 && b[0] == 'h' && b[4] == 'o')) ok = 0;        /* "hello" */
            if (sys_truncate("/tmp/T.TXT", 8) != 0) ok = 0;             /* grow (sparse) */
            long n2 = sys_readfile("/tmp/T.TXT", b, sizeof b);
            if (!(n2 == 8 && b[4] == 'o' && b[5] == 0 && b[7] == 0)) ok = 0;   /* "hello\0\0\0" */
            int fd = sys_open("/tmp/T.TXT");                             /* ftruncate(fd) path */
            if (sys_ftruncate(fd, 3) != 0) ok = 0;
            sys_fdclose(fd);
            long n3 = sys_readfile("/tmp/T.TXT", b, sizeof b);
            if (!(n3 == 3 && b[0] == 'h' && b[2] == 'l')) ok = 0;       /* "hel" */
            sys_delete("/tmp/T.TXT");
            print(ok ? "truncate: shrink 11->5 + grow 5->8 (zero-fill) + ftruncate(fd) 8->3 -- OK\n"
                     : "truncatetest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "seektest")) {   /* lseek SEEK_DATA / SEEK_HOLE (M1229) */
            int ok = 1;
            sys_writefile("/tmp/SK.TXT", "0123456789", 10);
            if (sys_truncate("/tmp/SK.TXT", 200) != 0) ok = 0;          /* grow (tmpfs zero-fills, no holes) */
            int fd = sys_open("/tmp/SK.TXT");
            if (fd < 0) ok = 0;
            else {
                if (sys_lseek(fd, 0,   SEEK_DATA) != 0)   ok = 0;       /* data starts at 0 */
                if (sys_lseek(fd, 0,   SEEK_HOLE) != 200) ok = 0;       /* only hole is the implicit one at EOF */
                if (sys_lseek(fd, 150, SEEK_DATA) != 150) ok = 0;       /* mid-file is data (filled) */
                if (sys_lseek(fd, 200, SEEK_DATA) != -1)  ok = 0;       /* at EOF -> ENXIO */
                if (sys_lseek(fd, 200, SEEK_HOLE) != -1)  ok = 0;       /* at EOF -> ENXIO */
                sys_fdclose(fd);
            }
            sys_delete("/tmp/SK.TXT");
            print(ok ? "seek: SEEK_DATA(0)=0, SEEK_HOLE(0)=EOF, SEEK_DATA(mid)=mid, ENXIO past EOF -- OK\n"
                     : "seektest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "utimestest")) {   /* utimensat / futimens (M1230) */
            int ok = 1;
            struct statx st;
            sys_writefile("/tmp/UT.TXT", "hi", 2);
            if (sys_utimens("/tmp/UT.TXT", UTIME_OMIT, 0x40000000) != 0) ok = 0;   /* set mtime, leave atime */
            if (sys_statx("/tmp/UT.TXT", &st) != 0 || (long)st.stx_mtime != 0x40000000) ok = 0;
            if (sys_utimens("/tmp/UT.TXT", UTIME_OMIT, UTIME_NOW) != 0) ok = 0;     /* mtime -> now */
            if (sys_statx("/tmp/UT.TXT", &st) != 0 || (long)st.stx_mtime <= 0x40000000) ok = 0;  /* advanced */
            int fd = sys_open("/tmp/UT.TXT");                                       /* futimens(fd) path */
            if (fd < 0) ok = 0;
            else { if (sys_futimens(fd, UTIME_OMIT, 0x50000000) != 0) ok = 0; sys_fdclose(fd); }
            if (sys_statx("/tmp/UT.TXT", &st) != 0 || (long)st.stx_mtime != 0x50000000) ok = 0;
            sys_delete("/tmp/UT.TXT");
            print(ok ? "utimes: set mtime to a fixed epoch (statx reads it), UTIME_NOW advances it, futimens(fd) sets it -- OK\n"
                     : "utimestest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
            /* utimensat (M1559): the one *at family member still missing once
             * fchmodat/fchownat/faccessat2 shipped. Same shape as fchownat --
             * atime/mtime are the actual UTIME_NOW/OMIT values directly (M1230's
             * own simplification), not a timespec[2]+flags pair -- so both an
             * AT_FDCWD absolute path and a real dirfd are checked, same as attest. */
            int ok2 = 1;
            sys_writefile("/tmp/UT2.TXT", "z", 1);
            if (sys_utimensat(AT_FDCWD, "/tmp/UT2.TXT", UTIME_OMIT, 0x60000000) != 0) ok2 = 0;
            if (sys_statx("/tmp/UT2.TXT", &st) != 0 || (long)st.stx_mtime != 0x60000000) ok2 = 0;
            int dfd3 = sys_open("/tmp");
            if (dfd3 < 0) ok2 = 0;
            else {
                if (sys_utimensat(dfd3, "UT2.TXT", UTIME_OMIT, 0x70000000) != 0) ok2 = 0;   /* dirfd-relative */
                sys_fdclose(dfd3);
            }
            if (sys_statx("/tmp/UT2.TXT", &st) != 0 || (long)st.stx_mtime != 0x70000000) ok2 = 0;   /* landed on the same file */
            sys_delete("/tmp/UT2.TXT");
            print(ok2 ? "utimensat: sets mtime via AT_FDCWD + a real dirfd, same file both ways -- OK\n"
                      : "utimestest: utimensat VERIFY FAILED\n");
            if (!ok2) g_status = 1;
        } else if (streq(line, "pidstattest")) {   /* /proc/<pid>/stat — the ps/top line (M1231) */
            int ok = 1;
            char sb[256];
            long n = sys_readfile("/proc/self/stat", sb, sizeof sb - 1);
            if (n <= 0) ok = 0;
            else {
                sb[n] = 0;
                int i = 0, v = 0; while (sb[i] >= '0' && sb[i] <= '9') { v = v * 10 + (sb[i] - '0'); i++; }
                if (v != sys_gettid()) ok = 0;                  /* field 1 == /proc/self's id (the task id) */
                int op = -1, cp = -1;
                for (int k = 0; k < (int)n; k++) { if (sb[k] == '(') op = k; else if (sb[k] == ')') cp = k; }
                if (op < 0 || cp < op) ok = 0;                  /* field 2: (comm) */
                char stch = (cp >= 0 && cp + 2 < (int)n) ? sb[cp + 2] : 0;
                if (!(stch == 'R' || stch == 'S' || stch == 'Z' || stch == 'T')) ok = 0;  /* field 3 */
                int sp = 0; for (int k = 0; k < (int)n; k++) if (sb[k] == ' ') sp++;
                if (sp < 23) ok = 0;                            /* >= 24 fields */
            }
            print(ok ? "pidstat: /proc/self/stat -- field1==pid, (comm), state R/S/Z/T, >=24 fields -- OK\n"
                     : "pidstattest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "readlinktest")) {   /* readlink(2) -- read a symlink's target, not followed (M1233) */
            int ok = 1;
            const char *tgt = "/tmp/RL_TARGET.TXT";
            sys_delete("/tmp/RL.LNK");
            if (sys_symlink("/tmp/RL.LNK", tgt) != 0) ok = 0;       /* create RL.LNK -> tgt */
            char b[64];
            long n = sys_readlink("/tmp/RL.LNK", b, sizeof b);
            int tl = 0; while (tgt[tl]) tl++;
            if (n != tl) ok = 0;                                    /* readlink is NOT NUL-terminated -> exact byte count */
            else for (int k = 0; k < tl; k++) if (b[k] != tgt[k]) { ok = 0; break; }
            char rb2[16];
            if (sys_readlink("/tmp", rb2, sizeof rb2) != -1) ok = 0;   /* a non-symlink -> -1 */
            sys_delete("/tmp/RL.LNK");
            /* symlinkat/readlinkat (M1582): same round-trip via AT_FDCWD, then again via a REAL dirfd */
            sys_delete("/tmp/RL2.LNK"); sys_delete("/tmp/RL3.LNK");
            int atok = (sys_symlinkat(tgt, AT_FDCWD, "/tmp/RL2.LNK") == 0);
            char b2[64];
            long n2 = atok ? sys_readlinkat(AT_FDCWD, "/tmp/RL2.LNK", b2, sizeof b2) : -1;
            if (n2 != tl) atok = 0; else for (int k = 0; k < tl; k++) if (b2[k] != tgt[k]) { atok = 0; break; }
            int dfd = sys_open("/tmp");
            if (dfd >= 0) {
                if (sys_symlinkat(tgt, dfd, "RL3.LNK") != 0) atok = 0;      /* dirfd-relative create */
                char b3[64];
                long n3 = sys_readlinkat(dfd, "RL3.LNK", b3, sizeof b3);    /* dirfd-relative read */
                if (n3 != tl) atok = 0; else for (int k = 0; k < tl; k++) if (b3[k] != tgt[k]) { atok = 0; break; }
                sys_fdclose(dfd);
            } else atok = 0;
            sys_delete("/tmp/RL2.LNK"); sys_delete("/tmp/RL3.LNK");
            ok = ok && atok;
            print(ok ? "readlink: RL.LNK -> target read back exact (un-terminated), non-symlink -> -1; "
                       "symlinkat/readlinkat round-trip via AT_FDCWD + a real dirfd both OK -- OK\n"
                     : "readlinktest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "linkattest")) {   /* linkat: hard link relative to dir fds (M1585); ext2-only
                                                    * (like fchmodat/fchownat) and this interactive boot's only
                                                    * disk is FAT32 -- proves the *at wiring reaches vfs_link via
                                                    * BOTH AT_FDCWD and a real dirfd, denying cleanly rather than
                                                    * crashing or silently succeeding on the wrong filesystem */
            int ok = 1;
            if (sys_linkat(AT_FDCWD, "/tmp/LA_OLD.TXT", AT_FDCWD, "/tmp/LA1.TXT") != -1) ok = 0;
            int dfd = sys_open("/tmp");
            if (dfd >= 0) {
                if (sys_linkat(dfd, "LA_OLD.TXT", dfd, "LA2.TXT") != -1) ok = 0;   /* dirfd-relative, same denial */
                sys_fdclose(dfd);
            } else ok = 0;
            print(ok ? "linkat: AT_FDCWD + dirfd-relative both reach vfs_link, FAT32 (non-ext2) denies cleanly -- OK\n"
                     : "linkattest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "nanosleeptest")) {   /* sched_yield + nanosleep (M1234) */
            int ok = 1;
            if (sys_sched_yield() != 0) ok = 0;                 /* yields, returns 0 */
            unsigned long t0 = sys_uptime_ms();
            sys_nanosleep(0, 200000000);                        /* 200 ms */
            unsigned long dt = sys_uptime_ms() - t0;
            if (dt < 180) ok = 0;                               /* actually slept ~200ms (allow scheduler slack) */
            if (ok) { sys_setcolor(9); print("nanosleep: sched_yield()=0 + nanosleep(200ms) elapsed ~"); printl((long)dt); print("ms -- OK\n"); sys_setcolor(0); }
            else { sys_setcolor(2); print("nanosleeptest: VERIFY FAILED\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "timestest")) {   /* times(2) -- per-process CPU accounting (M1235) */
            int ok = 1;
            struct tms a, b;
            long r1 = sys_times(&a);
            volatile unsigned long acc = 0;                      /* burn ring-3 CPU so utime accrues ticks */
            for (unsigned long i = 0; i < 120000000UL; i++) acc += i;
            long r2 = sys_times(&b);
            (void)acc;
            if (r2 < r1) ok = 0;                                 /* the returned real-time ticks are monotonic */
            if (b.tms_utime < a.tms_utime) ok = 0;               /* user CPU time never decreases */
            if (b.tms_utime <= a.tms_utime) ok = 0;              /* the busy loop charged measurable user ticks */
            if (ok) { sys_setcolor(9); print("times: busy loop charged user CPU -- utime "); printl(a.tms_utime); print(" -> "); printl(b.tms_utime); print(" ticks, real-time monotonic -- OK\n"); sys_setcolor(0); }
            else { sys_setcolor(2); print("timestest: VERIFY FAILED\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "idtest")) {   /* uname + getppid/getuid/getgid (M1236) */
            int ok = 1;
            struct utsname u;
            if (sys_uname(&u) != 0) ok = 0;
            else if (!streq(u.sysname, "OS-DEV") || !streq(u.machine, "x86_64") || u.release[0] == 0) ok = 0;
            if (sys_getuid() != 0 || sys_geteuid() != 0 || sys_getgid() != 0 || sys_getegid() != 0) ok = 0;
            int mypid = sys_getpid();
            long kid = sys_fork();
            if (kid == 0) sys_exit(sys_getppid() == mypid ? 55 : 7);   /* child: getppid() == parent's pid? */
            int st = -1; sys_waitpid((int)kid, &st);
            if (st != 55) ok = 0;
            if (ok) { sys_setcolor(9); print("id: uname='"); print(u.sysname); print(" "); print(u.machine); print(" "); print(u.release); print("', uid/gid=0, child getppid()==parent -- OK\n"); sys_setcolor(0); }
            else { sys_setcolor(2); print("idtest: VERIFY FAILED\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "hostnametest")) {   /* gethostname/sethostname + uname.nodename (M1237) */
            int ok = 1;
            char h[64];
            if (sys_gethostname(h, sizeof h) != 0) ok = 0;              /* initial read works */
            if (sys_sethostname("os-dev-box", 10) != 0) ok = 0;        /* set a new name */
            if (sys_gethostname(h, sizeof h) != 0 || !streq(h, "os-dev-box")) ok = 0;   /* read it back */
            struct utsname u;
            if (sys_uname(&u) != 0 || !streq(u.nodename, "os-dev-box")) ok = 0;   /* uname.nodename reflects it */
            sys_sethostname("osdev", 5);                               /* restore the default */
            print(ok ? "hostname: sethostname('os-dev-box') -> gethostname + uname.nodename both reflect it -- OK\n"
                     : "hostnametest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "priotest")) {   /* getentropy + getpriority/setpriority (M1238) */
            int ok = 1;
            unsigned char eb[32]; for (int i = 0; i < 32; i++) eb[i] = 0;
            if (sys_getentropy(eb, 32) != 0) ok = 0;                   /* fill 32 random bytes */
            int nz = 0; for (int i = 0; i < 32; i++) if (eb[i]) nz++;
            if (nz < 4) ok = 0;                                        /* not all-zero -> real entropy */
            unsigned char big[8];
            if (sys_getentropy(big, 300) != -1) ok = 0;               /* >256 rejected */
            int old = sys_getpriority(PRIO_PROCESS, 0);
            if (sys_setpriority(PRIO_PROCESS, 0, 7) != 0) ok = 0;      /* set nice 7 (self) */
            if (sys_getpriority(PRIO_PROCESS, 0) != 7) ok = 0;         /* read it back */
            sys_setpriority(PRIO_PROCESS, 0, (old < -20 || old > 19) ? 0 : old);   /* restore */
            print(ok ? "prio: getentropy(32)=random (>256 rejected) + setpriority(7)/getpriority round-trip -- OK\n"
                     : "priotest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "pipe2test")) {   /* pipe2 with atomic O_CLOEXEC (M1239) */
            int ok = 1;
            int fds[2];
            if (sys_pipe2(fds, O_CLOEXEC) != 0) ok = 0;
            else {
                if (sys_fcntl(fds[0], F_GETFD, 0) != FD_CLOEXEC) ok = 0;   /* both ends cloexec at creation */
                if (sys_fcntl(fds[1], F_GETFD, 0) != FD_CLOEXEC) ok = 0;
                sys_fdwrite(fds[1], "p2", 2);                             /* and data still flows */
                char b[4]; long n = sys_fdread(fds[0], b, 2);
                if (!(n == 2 && b[0] == 'p' && b[1] == '2')) ok = 0;
                sys_fdclose(fds[0]); sys_fdclose(fds[1]);
            }
            int g[2];
            if (sys_pipe2(g, 0) != 0) ok = 0;                            /* flags=0 -> NOT cloexec */
            else { if (sys_fcntl(g[0], F_GETFD, 0) != 0) ok = 0; sys_fdclose(g[0]); sys_fdclose(g[1]); }
            print(ok ? "pipe2: O_CLOEXEC sets FD_CLOEXEC on both ends + data flows; flags=0 -> not cloexec -- OK\n"
                     : "pipe2test: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "statfstest")) {   /* statfs(2) -- filesystem free/total (M1240) */
            int ok = 1;
            struct statvfs sv;
            if (sys_statfs("/", &sv) != 0) ok = 0;
            else {
                if (sv.f_bsize == 0 || sv.f_blocks == 0) ok = 0;          /* real geometry */
                if (sv.f_bavail > sv.f_blocks) ok = 0;                    /* free <= total */
                if (sv.f_namemax == 0) ok = 0;
            }
            if (sys_statfs("/NOPE.XYZ", &sv) != -1) ok = 0;               /* absent path -> -1 */
            if (ok) { print("statfs: / -> "); printl((long)(sv.f_bavail * sv.f_bsize / 1024)); print(" KiB free / ");
                      printl((long)(sv.f_blocks * sv.f_bsize / 1024)); print(" KiB total, namemax="); printl((long)sv.f_namemax);
                      print(" (absent path -> -1) -- OK\n"); }
            else { sys_setcolor(2); print("statfstest: VERIFY FAILED\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "eventfdtest")) {   /* eventfd counter fd (M1242); both fds below are EFD_NONBLOCK
                                                     * so every "empty -> -1" assertion stays a synchronous check
                                                     * even now that a plain (blocking) eventfd really blocks (M1579) */
            int ok = 1;
            unsigned char b[8]; unsigned long long v;
            int efd = sys_eventfd(5, EFD_NONBLOCK);
            if (efd < 0) ok = 0;
            else {
                struct pollfd pf = { efd, POLLIN, 0 };
                if (!(sys_poll(&pf, 1, 0) == 1 && (pf.revents & POLLIN))) ok = 0;   /* count 5 -> POLLIN */
                long n = sys_fdread(efd, b, 8);
                v = 0; for (int i = 0; i < 8; i++) v |= (unsigned long long)b[i] << (i * 8);
                if (!(n == 8 && v == 5)) ok = 0;                                    /* read drains, returns 5 */
                pf.revents = 0;
                if (sys_poll(&pf, 1, 0) != 0) ok = 0;                              /* counter 0 -> not ready */
                unsigned char w[8]; for (int i = 0; i < 8; i++) w[i] = (i == 0) ? 3 : 0;
                if (sys_fdwrite(efd, w, 8) != 8) ok = 0;                            /* add 3 */
                long n2 = sys_fdread(efd, b, 8);
                v = 0; for (int i = 0; i < 8; i++) v |= (unsigned long long)b[i] << (i * 8);
                if (!(n2 == 8 && v == 3)) ok = 0;
                sys_fdclose(efd);
            }
            int sfd = sys_eventfd(2, EFD_SEMAPHORE | EFD_NONBLOCK);                 /* semaphore mode */
            if (sfd < 0) ok = 0;
            else {
                long a1 = sys_fdread(sfd, b, 8); v = 0; for (int i = 0; i < 8; i++) v |= (unsigned long long)b[i] << (i * 8);
                if (!(a1 == 8 && v == 1)) ok = 0;                                   /* returns 1, count 2->1 */
                long a2 = sys_fdread(sfd, b, 8); v = 0; for (int i = 0; i < 8; i++) v |= (unsigned long long)b[i] << (i * 8);
                if (!(a2 == 8 && v == 1)) ok = 0;                                   /* returns 1, count 1->0 */
                if (sys_fdread(sfd, b, 8) != -1) ok = 0;                            /* drained -> -1 */
                sys_fdclose(sfd);
            }
            print(ok ? "eventfd: count(5)->POLLIN->read 5->drained; +3->read 3; EFD_SEMAPHORE read 1,1 then empty -- OK\n"
                     : "eventfdtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "eventfdblocktest")) {   /* a plain (non-EFD_NONBLOCK) eventfd read really blocks (M1579) */
            int ok = 1;
            int bfd = sys_eventfd(0, 0);                          /* no EFD_NONBLOCK -> read() blocks on an empty counter */
            if (bfd < 0) ok = 0;
            else {
                g_evfd_shared = bfd;
                char *stk = malloc(64 * 1024);
                if (!stk) ok = 0;
                else {
                    long tid = sys_clone((void *)evfd_wake_thread_fn, stk + 64 * 1024, 0);
                    unsigned char b[8]; unsigned long long v = 0;
                    unsigned long t0 = sys_uptime_ms();
                    long n = sys_fdread(bfd, b, 8);                /* counter starts at 0 -> really blocks */
                    unsigned long elapsed = sys_uptime_ms() - t0;
                    for (int i = 0; i < 8; i++) v |= (unsigned long long)b[i] << (i * 8);
                    ok = (tid > 0 && n == 8 && v == 7 && elapsed >= 100);   /* really parked ~150ms, not an instant return */
                    free(stk);
                }
                sys_fdclose(bfd);
            }
            print(ok ? "eventfd (no EFD_NONBLOCK): read() blocks on an empty counter, wakes + returns 7 once another thread writes it -- OK\n"
                     : "eventfdblocktest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "iotest")) {   /* /proc/<pid>/io byte accounting (M1244) */
            int ok = 1;
            char sb[256]; long w1 = -1, w2 = -1, n;
            n = sys_readfile("/proc/self/io", sb, sizeof sb - 1);                  /* snapshot wchar */
            if (n > 0) { sb[n] = 0; for (int k = 0; k + 6 < (int)n; k++)
                if (sb[k]=='w'&&sb[k+1]=='c'&&sb[k+2]=='h'&&sb[k+3]=='a'&&sb[k+4]=='r'&&sb[k+5]==':') {
                    int j = k+6; while (sb[j]==' ') j++; long v=0; while (sb[j]>='0'&&sb[j]<='9'){v=v*10+(sb[j]-'0');j++;} w1=v; break; } }
            int pf[2];
            if (sys_pipe(pf) != 0) ok = 0;
            else {
                char blob[64]; for (int i = 0; i < 64; i++) blob[i] = 'x';
                if (sys_fdwrite(pf[1], blob, 64) != 64) ok = 0;                    /* a known 64-byte fd write */
                n = sys_readfile("/proc/self/io", sb, sizeof sb - 1);             /* snapshot again */
                if (n > 0) { sb[n] = 0; for (int k = 0; k + 6 < (int)n; k++)
                    if (sb[k]=='w'&&sb[k+1]=='c'&&sb[k+2]=='h'&&sb[k+3]=='a'&&sb[k+4]=='r'&&sb[k+5]==':') {
                        int j = k+6; while (sb[j]==' ') j++; long v=0; while (sb[j]>='0'&&sb[j]<='9'){v=v*10+(sb[j]-'0');j++;} w2=v; break; } }
                char rb[64]; sys_fdread(pf[0], rb, 64); sys_fdclose(pf[0]); sys_fdclose(pf[1]);
            }
            if (!(w1 >= 0 && w2 >= w1 + 64)) ok = 0;                               /* wchar grew by the write */
            if (ok) { print("io: /proc/self/io wchar "); printl(w1); print(" -> "); printl(w2); print(" (grew >=64 after a 64-byte fd write) -- OK\n"); }
            else { sys_setcolor(2); print("iotest: VERIFY FAILED\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "statmtest")) {   /* /proc/<pid>/statm short memory line (M1245) */
            int ok = 1;
            char sb[128];
            long n = sys_readfile("/proc/self/statm", sb, sizeof sb - 1);
            if (n <= 0) ok = 0;
            else {
                sb[n] = 0;
                long f[7]; int nf = 0, i = 0;
                while (nf < 7 && i < (int)n) {
                    while (sb[i] == ' ' || sb[i] == '\n') i++;
                    if (sb[i] < '0' || sb[i] > '9') break;
                    long v = 0; while (sb[i] >= '0' && sb[i] <= '9') { v = v * 10 + (sb[i] - '0'); i++; }
                    f[nf++] = v;
                }
                if (nf < 7) ok = 0;                                          /* seven fields */
                else if (f[0] == 0 || f[1] == 0 || f[1] > f[0]) ok = 0;      /* size>0, resident>0, resident<=size */
            }
            print(ok ? "statm: /proc/self/statm -- 7 fields, size>0, resident>0, resident<=size -- OK\n"
                     : "statmtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "getcputest")) {   /* sched_getcpu (M1246) */
            int ok = 1;
            int c = sys_sched_getcpu();
            if (c < 0 || c >= 256) ok = 0;          /* a valid APIC id (ring-3 runs on the BSP) */
            if (ok) { print("sched_getcpu: ring-3 runs on CPU "); printl(c); print(" (the BSP) -- OK\n"); }
            else { sys_setcolor(2); print("getcputest: VERIFY FAILED\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "pidwchantest")) {   /* /proc/<pid>/wchan per-pid file (M1247) */
            int ok = 1; char wb[64]; long n;
            /* /proc keys on the TASK id (gettid), not the app pid (fork's return) -- M1231 --
             * so the child hands us its tid before blocking, and we read /proc/<tid>/wchan. */
            int p1[2], p2[2];
            if (sys_pipe(p1) != 0 || sys_pipe(p2) != 0) ok = 0;
            else {
                long kid = sys_fork();
                if (kid == 0) {                                          /* child: announce tid, then block */
                    int tid = sys_gettid(); sys_fdwrite(p1[1], &tid, sizeof tid);
                    char c; sys_fdread(p2[0], &c, 1); sys_exit(0);
                }
                int ctid = 0; sys_fdread(p1[0], &ctid, sizeof ctid);     /* the child's task id */
                sys_sleep(250);                                          /* let it reach the p2 blocking read */
                char path[40]; int pp = 0; const char *pre = "/proc/", *suf = "/wchan"; char nb[12];
                for (int i = 0; pre[i]; i++) path[pp++] = pre[i];
                itoa_simple(ctid, nb); for (int i = 0; nb[i]; i++) path[pp++] = nb[i];
                for (int i = 0; suf[i]; i++) path[pp++] = suf[i]; path[pp] = 0;
                n = sys_readfile(path, wb, sizeof wb - 1);
                if (n <= 0) ok = 0; else { wb[n] = 0; if (wb[0] == '0' && (wb[1] == '\n' || wb[1] == 0)) ok = 0; }  /* blocked -> a real symbol */
                sys_fdwrite(p2[1], "x", 1);                              /* unblock the child */
                int st; sys_waitpid((int)kid, &st);
                sys_fdclose(p1[0]); sys_fdclose(p1[1]); sys_fdclose(p2[0]); sys_fdclose(p2[1]);
                if (ok) { int k = 0; while (wb[k] && wb[k] != '\n') k++; wb[k] = 0;
                          print("wchan: a pipe-blocked child (/proc/"); printl(ctid); print("/wchan) is parked in '"); print(wb); print("' -- OK\n"); }
            }
            if (!ok) { sys_setcolor(2); print("pidwchantest: VERIFY FAILED\n"); sys_setcolor(0); g_status = 1; }
        } else if (streq(line, "getcwdtest")) {   /* getcwd(2) (M1248) */
            int ok = 1; char cb[160];
            sys_chdir("/tmp");
            if (sys_getcwd(cb, sizeof cb) <= 0 || !streq(cb, "/tmp")) ok = 0;
            sys_chdir("/proc");
            if (sys_getcwd(cb, sizeof cb) <= 0 || !streq(cb, "/proc")) ok = 0;
            sys_chdir("/");
            if (sys_getcwd(cb, sizeof cb) <= 0 || !streq(cb, "/")) ok = 0;
            if (sys_getcwd(cb, 1) != -1) ok = 0;   /* "/" + NUL needs 2 bytes -> size 1 is ERANGE */
            /* fchdir (M1586): chdir via an already-open directory fd, instead of a path string */
            int fcok = 1;
            int dfd = sys_open("/tmp");
            if (dfd < 0 || sys_fchdir(dfd) != 0) fcok = 0;
            else if (sys_getcwd(cb, sizeof cb) <= 0 || !streq(cb, "/tmp")) fcok = 0;
            if (dfd >= 0) sys_fdclose(dfd);
            int ffd = sys_open_mode("/tmp/FCD_FILE.TXT", O_WRONLY | O_CREAT | O_TRUNC);   /* a REGULAR
                                                                * file -> vfs_chdir rejects it, not a dir */
            if (ffd >= 0) { if (sys_fchdir(ffd) != -1) fcok = 0; sys_fdclose(ffd); sys_delete("/tmp/FCD_FILE.TXT"); } else fcok = 0;
            sys_chdir("/");
            /* absolute-path stat/open from a non-root cwd (M1622): vfs_stat's boot-
             * FAT32 fallback used to strip the path to a bare basename and match it
             * against vfs_list()'s listing of the CURRENT cwd, so an absolute
             * root-level path silently reported not-found once cwd moved anywhere
             * else -- open() calls vfs_stat first, so this broke plain open(), not
             * just an explicit stat call. */
            int stok = 1;
            sys_chdir("/tmp");
            int sfd = sys_open("/README.TXT");
            if (sfd < 0) stok = 0; else sys_fdclose(sfd);
            sys_chdir("/");
            ok = ok && fcok && stok;
            print(ok ? "getcwd: cd /tmp->'/tmp', /proc->'/proc', /->'/'; tiny buf -> -1; "
                       "fchdir(dir fd)->'/tmp', fchdir(file fd)->-1; "
                       "open(\"/README.TXT\") from cwd=/tmp -- OK\n"
                     : "getcwdtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "procwdtest")) {   /* /proc/<pid>/cwd + /root (M1249) */
            int ok = 1; char b[64]; long n;
            sys_chdir("/tmp");
            n = sys_readfile("/proc/self/cwd", b, sizeof b - 1);
            if (n <= 0) ok = 0; else { b[n] = 0; if (!(b[0]=='/'&&b[1]=='t'&&b[2]=='m'&&b[3]=='p'&&(b[4]=='\n'||b[4]==0))) ok = 0; }  /* "/tmp" */
            sys_chdir("/");
            n = sys_readfile("/proc/self/cwd", b, sizeof b - 1);
            if (n <= 0) ok = 0; else { b[n] = 0; if (!(b[0]=='/'&&(b[1]=='\n'||b[1]==0))) ok = 0; }                                    /* "/" */
            n = sys_readfile("/proc/self/root", b, sizeof b - 1);
            if (n <= 0) ok = 0; else { b[n] = 0; if (!(b[0]=='/'&&(b[1]=='\n'||b[1]==0))) ok = 0; }                                    /* "/" (no chroot) */
            print(ok ? "procwd: /proc/self/cwd tracks cd (/tmp then /); /proc/self/root == / -- OK\n"
                     : "procwdtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "exetest")) {   /* /proc/<pid>/exe (M1250) */
            int ok = 1; char b[80];
            long n = sys_readfile("/proc/self/exe", b, sizeof b - 1);
            if (n <= 0) ok = 0;
            else { b[n] = 0; int k = 0; while (b[k] && b[k] != '\n') k++; b[k] = 0;   /* strip newline */
                   if (k == 0 || (k == 1 && b[0] == '?')) ok = 0; }                   /* a real image path, not the "?" placeholder */
            if (ok) { print("exe: /proc/self/exe = '"); print(b); print("' (the shell's image path) -- OK\n"); }
            else { sys_setcolor(2); print("exetest: VERIFY FAILED\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "attest")) {   /* openat/unlinkat/mkdirat/fstatat (M1251) */
            int ok = 1; struct statx st;
            /* AT_FDCWD with an absolute path: create, stat, unlink, confirm gone */
            int fd = sys_openat(AT_FDCWD, "/tmp/AT.TXT", O_CREAT | O_WRONLY);
            if (fd < 0) ok = 0; else { sys_fdwrite(fd, "at", 2); sys_fdclose(fd); }
            if (sys_fstatat(AT_FDCWD, "/tmp/AT.TXT", &st, 0) != 0) ok = 0;
            if (sys_unlinkat(AT_FDCWD, "/tmp/AT.TXT", 0) != 0) ok = 0;
            if (sys_fstatat(AT_FDCWD, "/tmp/AT.TXT", &st, 0) == 0) ok = 0;          /* removed */
            /* a REAL dir fd: open /tmp, create a file relative to it via openat */
            int dfd = sys_open("/tmp");
            if (dfd < 0) ok = 0;
            else {
                int f = sys_openat(dfd, "AT2.TXT", O_CREAT | O_WRONLY);            /* -> /tmp/AT2.TXT */
                if (f < 0) ok = 0; else { sys_fdwrite(f, "x", 1); sys_fdclose(f); }
                sys_fdclose(dfd);
                if (sys_fstatat(AT_FDCWD, "/tmp/AT2.TXT", &st, 0) != 0) ok = 0;     /* the dirfd-relative create landed in /tmp */
                sys_unlinkat(AT_FDCWD, "/tmp/AT2.TXT", 0);
            }
            print(ok ? "*at: AT_FDCWD openat/fstatat/unlinkat + dirfd-relative openat (open /tmp -> create AT2.TXT in it) -- OK\n"
                     : "attest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
            /* fchmodat/fchownat (M1553): the two *at family members M1251 didn't
             * add. chmod/chown are ext2-only (blockdev_mount_chown denies any
             * non-ext2 mount outright) and this interactive boot's only disk is
             * FAT32 -- and, notably, chmod/chown THEMSELVES have no success-path
             * test anywhere in this codebase either, on ANY path, at_ or not.
             * What's honestly verifiable here: the *at dirfd-resolution wiring
             * reaches vfs_chmod/vfs_chown correctly (both via AT_FDCWD and a
             * real dirfd) and the ext2-only guard denies cleanly rather than
             * crashing or silently succeeding on the wrong filesystem. */
            int ok2 = 1;
            int f2 = sys_openat(AT_FDCWD, "/tmp/AT3.TXT", O_CREAT | O_WRONLY);
            if (f2 < 0) ok2 = 0; else sys_fdclose(f2);
            if (sys_fchmodat(AT_FDCWD, "/tmp/AT3.TXT", 0600) != -1) ok2 = 0;   /* tmpfs -> ext2-only guard denies */
            if (sys_fchownat(AT_FDCWD, "/tmp/AT3.TXT", 7, 8) != -1) ok2 = 0;
            int dfd2 = sys_open("/tmp");                                       /* same denial via a REAL dirfd */
            if (dfd2 < 0) ok2 = 0;
            else {
                if (sys_fchmodat(dfd2, "AT3.TXT", 0600) != -1) ok2 = 0;
                if (sys_fchownat(dfd2, "AT3.TXT", 7, 8) != -1) ok2 = 0;
                sys_fdclose(dfd2);
            }
            sys_unlinkat(AT_FDCWD, "/tmp/AT3.TXT", 0);
            print(ok2 ? "*at: fchmodat/fchownat reach vfs_chmod/vfs_chown via AT_FDCWD + a real dirfd (ext2-only guard denies cleanly on tmpfs) -- OK\n"
                      : "attest: fchmodat/fchownat VERIFY FAILED\n");
            if (!ok2) g_status = 1;
        } else if (streq(line, "faulttest")) {   /* /proc/<pid>/stat minflt field is real now (M1252) */
            int ok = 1; char sb[256]; long m1 = -1, m2 = -1;
            unsigned long len = 100 * 4096;
            unsigned char *mm = (unsigned char *)sys_mmap(len);        /* a fresh demand-paged anon region (like usagetest) */
            for (int pass = 0; pass < 2; pass++) {
                long n = sys_readfile("/proc/self/stat", sb, sizeof sb - 1); long mf = -1;
                if (n > 0) { sb[n] = 0; int fld = 0, i = 0;            /* field 10 = minflt */
                    while (sb[i]) { while (sb[i] == ' ') i++; if (!sb[i]) break;
                        fld++; int s = i; while (sb[i] && sb[i] != ' ') i++;
                        if (fld == 10) { long v = 0; for (int k = s; k < i; k++) if (sb[k] >= '0' && sb[k] <= '9') v = v * 10 + (sb[k] - '0'); mf = v; break; } } }
                if (pass == 0) { m1 = mf; if (mm) for (unsigned long i = 0; i < len; i += 4096) mm[i] = 1; }  /* fault 100 pages */
                else m2 = mf;
            }
            if (!(mm && m1 >= 0 && m2 - m1 >= 100)) ok = 0;            /* /proc/self/stat's minflt tracked the demand paging */
            if (ok) { print("faults: /proc/self/stat minflt "); printl(m1); print(" -> "); printl(m2); print(" after mmap+touch 100 pages (field 10 is the real counter, was hardcoded 0) -- OK\n"); }
            else { sys_setcolor(2); print("faulttest: VERIFY FAILED\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "statcputest")) {   /* /proc/stat is the real Linux cpu/ctxt/btime layout now (M1253) */
            char sb[512]; int ok = 1; long cpufields = 0;
            long n = sys_readfile("/proc/stat", sb, sizeof sb - 1);
            long ctxt1 = -1, btime = -1, prun = -1;
            if (n > 0) { sb[n] = 0;
                if (sb[0] == 'c' && sb[1] == 'p' && sb[2] == 'u') {   /* first line: cpu <u> <n> <s> <i> ... -- count numeric fields */
                    int i = 3;
                    while (sb[i] && sb[i] != '\n') {
                        while (sb[i] == ' ') i++;
                        if (sb[i] >= '0' && sb[i] <= '9') { cpufields++; while (sb[i] >= '0' && sb[i] <= '9') i++; }
                        else if (sb[i] && sb[i] != '\n') i++;
                    }
                }
                ctxt1 = sh_kvnum(sb, "ctxt");
                btime = sh_kvnum(sb, "btime");
                prun  = sh_kvnum(sb, "procs_running");
            }
            sys_sleep(60); sys_sched_yield();                  /* force scheduling so ctxt advances (monotonic counter) */
            long n2 = sys_readfile("/proc/stat", sb, sizeof sb - 1); long ctxt2 = -1;
            if (n2 > 0) { sb[n2] = 0; ctxt2 = sh_kvnum(sb, "ctxt"); }
            if (!(cpufields >= 10 && ctxt1 > 0 && ctxt2 > ctxt1 && btime > 1500000000L && prun >= 1)) ok = 0;
            if (ok) { print("/proc/stat: cpu line has "); printl(cpufields); print(" fields, ctxt "); printl(ctxt1);
                      print(" -> "); printl(ctxt2); print(", btime "); printl(btime); print(", procs_running "); printl(prun);
                      print(" (real Linux layout w/ live ctxt+btime, was a 3-line blob) -- OK\n"); }
            else { sys_setcolor(2); print("statcputest: VERIFY FAILED\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "socketpairtest")) {   /* socketpair(2): a pre-connected AF_UNIX pair, no path/listen/accept (M1254) */
            int sv[2] = { -1, -1 }; int ok = 1; char rb[16];
            if (sys_socketpair(sv) != 0 || sv[0] < 0 || sv[1] < 0 || sv[0] == sv[1]) ok = 0;
            else {
                long w1 = sys_unix_send(sv[0], "ping", 4);          /* A -> B */
                long r1 = sys_unix_recv(sv[1], rb, sizeof rb);
                int ab = (w1 == 4 && r1 == 4 && rb[0]=='p' && rb[1]=='i' && rb[2]=='n' && rb[3]=='g');
                long w2 = sys_unix_send(sv[1], "pong", 4);          /* B -> A (same pair, other direction) */
                long r2 = sys_unix_recv(sv[0], rb, sizeof rb);
                int ba = (w2 == 4 && r2 == 4 && rb[0]=='p' && rb[1]=='o' && rb[2]=='n' && rb[3]=='g');
                if (!(ab && ba)) ok = 0;
                sys_unix_close(sv[0]); sys_unix_close(sv[1]);
            }
            if (ok) { print("socketpair: sv[0]="); printl(sv[0]); print(" sv[1]="); printl(sv[1]);
                      print(" -- A->B 'ping' + B->A 'pong' both delivered (pre-connected, bidirectional, no path/listen/accept) -- OK\n"); }
            else { sys_setcolor(2); print("socketpairtest: VERIFY FAILED\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "scmtest")) {   /* SCM_RIGHTS: pass an open fd over an AF_UNIX socketpair (M1265) */
            int ok = 1; int fds[2] = {-1,-1}, sv[2] = {-1,-1};
            if (sys_pipe(fds) != 0) ok = 0;                       /* fds[0] read end, fds[1] write end */
            else {
                sys_fdwrite(fds[1], "SCM!", 4);                   /* park data in the pipe */
                if (sys_socketpair(sv) != 0) ok = 0;
                else {
                    int snt = sys_sendfd(sv[0], fds[0]);          /* pass the pipe READ end across the socket */
                    int nfd = sys_recvfd(sv[1]);                  /* peer receives it as a fresh fd */
                    char rb[8] = {0};
                    long n = (nfd >= 0) ? sys_fdread(nfd, rb, sizeof rb) : -1;
                    int match = (snt == 0 && nfd >= 0 && nfd != fds[0] && n == 4 &&
                                 rb[0]=='S' && rb[1]=='C' && rb[2]=='M' && rb[3]=='!');
                    if (!match) ok = 0;
                    if (ok) { print("scm: sendfd(pipe-rd "); printl(fds[0]); print(") over socketpair -> recvfd got NEW fd ");
                              printl(nfd); print("; reading it returned 'SCM!' from the SAME pipe -- SCM_RIGHTS OK\n"); }
                    if (nfd >= 0) sys_fdclose(nfd);
                    sys_unix_close(sv[0]); sys_unix_close(sv[1]);
                }
                sys_fdclose(fds[0]); sys_fdclose(fds[1]);
            }
            if (!ok) { sys_setcolor(2); print("scmtest: VERIFY FAILED\n"); sys_setcolor(0); g_status = 1; }
        } else if (streq(line, "inotifytest")) {   /* real pollable inotify fd (M1266) */
            int ok = 1;
            int fd = sys_inotify_init();
            if (fd < 0) ok = 0;
            int wd = (fd >= 0) ? sys_inotify_add_watch(fd, "INOTI", 2 /*IN_MODIFY*/) : -1;
            if (wd < 0) ok = 0;
            sys_writefile("/tmp/INOTI.TXT", "hi", 2);             /* a VFS write -> fsevents -> inotify event */
            unsigned char eb[64]; long n = (fd >= 0) ? sys_fdread(fd, eb, sizeof eb) : -1;
            long emask = (n >= 48) ? (eb[4] | (eb[5]<<8) | (eb[6]<<16) | ((long)eb[7]<<24)) : -1;
            int  ewd  = (n >= 48) ? (eb[0] | (eb[1]<<8) | (eb[2]<<16) | (eb[3]<<24)) : -1;
            int  nameok = (n >= 48 && eb[16]=='I' && eb[17]=='N' && eb[18]=='O');   /* basename "INOTI.TXT" */
            if (!(ok && n >= 48 && emask == 2 && ewd == wd && nameok)) ok = 0;
            if (ok) { print("inotify: watch \"INOTI\" -> writing /tmp/INOTI.TXT delivered an event on a pollable fd (wd ");
                      printl(ewd); print(", mask IN_MODIFY, name '");
                      for (int i = 16; i < 48 && eb[i]; i++) { char c[2] = {(char)eb[i], 0}; print(c); }
                      print("') -- inotify OK\n"); }
            else { sys_setcolor(2); print("inotifytest: VERIFY FAILED (n="); sys_setcolor(0); printl(n); print(" mask="); printl(emask); print(" wd="); printl(ewd); print(")\n"); g_status = 1; }
            /* inotify_rm_watch (M1568): add a second watch, remove the FIRST, write to
             * both paths, confirm only the still-registered watch's event arrives (and
             * that it's the ONLY event -- proving the removed watch stayed silent). */
            int wd2 = (fd >= 0) ? sys_inotify_add_watch(fd, "INOTI2", 2 /*IN_MODIFY*/) : -1;
            int rmok = (fd >= 0) ? (sys_inotify_rm_watch(fd, wd) == 0) : 0;
            sys_writefile("/tmp/INOTI.TXT", "again", 5);    /* watch removed -- must NOT produce an event */
            sys_writefile("/tmp/INOTI2.TXT", "hi2", 3);     /* still watched -- must produce an event */
            unsigned char eb2[64]; long n2 = (fd >= 0) ? sys_fdread(fd, eb2, sizeof eb2) : -1;
            int ewd2 = (n2 >= 48) ? (int)(eb2[0] | (eb2[1]<<8) | (eb2[2]<<16) | (eb2[3]<<24)) : -1;
            long n3 = (fd >= 0) ? sys_fdread(fd, eb2, sizeof eb2) : -1;   /* must be empty -- only one event ever queued */
            int rmtest_ok = wd2 >= 0 && rmok && n2 >= 48 && ewd2 == wd2 && n3 == 0;
            print("inotify_rm_watch: removed watch stays silent, the other watch still fires -- ");
            sys_setcolor(rmtest_ok ? 10 : 4); print(rmtest_ok ? "OK\n" : "VERIFY FAILED\n"); sys_setcolor(0);
            if (!rmtest_ok) g_status = 1;
            if (fd >= 0) sys_fdclose(fd);
        } else if (streq(line, "diskstatstest")) {   /* /proc/diskstats: per-block-device I/O counters (M1256) */
            char sb[1024]; int ok = 1;
            long n = sys_readfile("/proc/diskstats", sb, sizeof sb - 1);
            long ndev = 0, tot_rd_ios = 0, tot_rd_sec = 0;
            if (n > 0) { sb[n] = 0; int i = 0;
                while (sb[i]) {                       /* one device per line: maj min name rd_ios 0 rd_sectors ... */
                    int tok = 0, ls = i; long rdios = 0, rdsec = 0;
                    while (sb[i] && sb[i] != '\n') {
                        while (sb[i] == ' ') i++;
                        if (!sb[i] || sb[i] == '\n') break;
                        tok++; int s = i; while (sb[i] && sb[i] != ' ' && sb[i] != '\n') i++;
                        if (tok == 4 || tok == 6) { long v = 0; for (int k = s; k < i; k++) if (sb[k] >= '0' && sb[k] <= '9') v = v * 10 + (sb[k] - '0');
                                                    if (tok == 4) rdios = v; else rdsec = v; }
                    }
                    if (i > ls && tok >= 6) { ndev++; tot_rd_ios += rdios; tot_rd_sec += rdsec; }
                    if (sb[i] == '\n') i++;
                }
            }
            if (!(ndev >= 1 && tot_rd_ios > 0)) ok = 0;   /* boot enumeration read LBA0 of each device -> rd_ios>0 */
            if (ok) { print("diskstats: "); printl(ndev); print(" block device(s), total rd_ios="); printl(tot_rd_ios);
                      print(" rd_sectors="); printl(tot_rd_sec); print(" (real per-device I/O counters tallied in blockdev_read/write) -- OK\n"); }
            else { sys_setcolor(2); print("diskstatstest: VERIFY FAILED\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "clocknstest")) {   /* clock_nanosleep(TIMER_ABSTIME) + clock_getres (M1257) */
            int ok = 1;                            /* clockid 1 = CLOCK_MONOTONIC, flag 1 = TIMER_ABSTIME */
            long res = sys_clock_getres(1);
            if (res != 10000000) ok = 0;                            /* 10ms tick resolution */
            unsigned long t0 = sys_uptime_ms();
            unsigned long target = t0 + 150;                        /* absolute monotonic deadline 150 ms out */
            sys_clock_nanosleep(1, 1, (long)(target / 1000), (long)((target % 1000) * 1000000));
            unsigned long dt = sys_uptime_ms() - t0;
            if (dt < 130) ok = 0;                                   /* slept until the deadline (~150ms, allow slack) */
            unsigned long t1 = sys_uptime_ms();                     /* a deadline already in the past returns immediately */
            unsigned long past = t1 > 1000 ? t1 - 1000 : 0;
            sys_clock_nanosleep(1, 1, (long)(past / 1000), (long)((past % 1000) * 1000000));
            unsigned long dt2 = sys_uptime_ms() - t1;
            if (dt2 > 50) ok = 0;                                   /* past deadline -> immediate, no sleep */
            if (ok) { print("clock_nanosleep: getres="); printl(res); print("ns; ABSTIME +150ms slept ~"); printl((long)dt);
                      print("ms; past deadline returned ~"); printl((long)dt2); print("ms (immediate) -- OK\n"); }
            else { sys_setcolor(2); print("clocknstest: VERIFY FAILED\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "udptest")) {   /* userspace UDP sockets: a real DNS round-trip via sendto/recvfrom (M1258) */
            unsigned char dns[4] = {10, 0, 2, 3};               /* QEMU slirp built-in DNS resolver */
            unsigned char q[256]; int dl = 0;
            q[dl++]=0x12; q[dl++]=0x34;                         /* id */
            q[dl++]=0x01; q[dl++]=0x00;                         /* flags: recursion desired */
            q[dl++]=0; q[dl++]=1;                               /* qdcount = 1 */
            q[dl++]=0;q[dl++]=0; q[dl++]=0;q[dl++]=0; q[dl++]=0;q[dl++]=0;  /* an/ns/ar = 0 */
            const char *host = "example.com"; const char *p = host;
            while (*p) { int l=0; while (p[l] && p[l]!='.') l++; q[dl++]=(unsigned char)l;
                         for (int i=0;i<l;i++) q[dl++]=(unsigned char)p[i]; p+=l; if(*p=='.')p++; }
            q[dl++]=0; q[dl++]=0;q[dl++]=1; q[dl++]=0;q[dl++]=1; /* root label + QTYPE A + QCLASS IN */
            int ok = 1; unsigned short sport = 0xB0B0;
            if (sys_udp_send(dns, 53, sport, q, dl) != 0) ok = 0;
            unsigned char resp[512]; unsigned char from[6] = {0};
            long n = sys_udp_recv(sport, resp, sizeof resp, from);
            int idok = (n >= 12 && resp[0]==0x12 && resp[1]==0x34);   /* our query's reply came back */
            int an = (n >= 8) ? ((resp[6]<<8)|resp[7]) : 0;           /* answer count */
            long a0=-1,a1=-1,a2=-1,a3=-1;                             /* best-effort: pull the first A record */
            if (idok && an >= 1) {
                int o = 12;
                while (o < n && resp[o]) { if ((resp[o]&0xC0)==0xC0){o++;break;} o += resp[o]+1; }
                o++; o += 4;                                          /* end-of-name + QTYPE/QCLASS */
                for (int a=0; a<an && o+10<=n; a++) {
                    if ((resp[o]&0xC0)==0xC0) o+=2; else { while(o<n && resp[o]) o+=resp[o]+1; o++; }
                    if (o+10 > n) break;
                    int type=(resp[o]<<8)|resp[o+1]; o+=2; o+=2; o+=4;   /* type, class, ttl */
                    int rdlen=(resp[o]<<8)|resp[o+1]; o+=2;
                    if (type==1 && rdlen==4 && o+4<=n) { a0=resp[o];a1=resp[o+1];a2=resp[o+2];a3=resp[o+3]; break; }
                    o+=rdlen;
                }
            }
            if (!(ok && idok && an >= 1)) ok = 0;                     /* PASS = matching reply with >=1 answer */
            if (ok) { print("udp: sendto 10.0.2.3:53 DNS query, recvfrom got "); printl(n);
                      print("B reply (id matches, "); printl(an); print(" answer");
                      if (a0>=0){ print(", A="); printl(a0);print(".");printl(a1);print(".");printl(a2);print(".");printl(a3); }
                      print(") -- userspace UDP round-trip OK\n"); }
            else { sys_setcolor(2); print("udptest: VERIFY FAILED (no DNS reply -- needs slirp + host DNS)\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "insmodtest")) {   /* loadable kernel module lifecycle: insmod + /proc/modules + rmmod (M1261/M1262) */
            int ok = 1; char mb[256];
            long rv = sys_insmod();                 /* loads testmod.ko, returns mod_init()'s value */
            if (rv != 42) ok = 0;                   /* 42 iff its imported timer_ms() resolved + ran */
            long n1 = sys_readfile("/proc/modules", mb, sizeof mb - 1);   /* lsmod: must now list testmod */
            int listed = 0; if (n1 > 0) { mb[n1]=0; for (int i=0;i+7<=n1;i++) if (mb[i]=='t'&&mb[i+1]=='e'&&mb[i+2]=='s'&&mb[i+3]=='t'&&mb[i+4]=='m'&&mb[i+5]=='o'&&mb[i+6]=='d'){listed=1;break;} }
            if (!listed) ok = 0;
            int un = sys_rmmod("testmod");           /* rmmod: runs mod_exit + frees the slot */
            if (un != 0) ok = 0;
            long n2 = sys_readfile("/proc/modules", mb, sizeof mb - 1);   /* must now be gone */
            int gone = 1; if (n2 > 0) { mb[n2]=0; for (int i=0;i+7<=n2;i++) if (mb[i]=='t'&&mb[i+1]=='e'&&mb[i+2]=='s'&&mb[i+3]=='t'&&mb[i+4]=='m'&&mb[i+5]=='o'&&mb[i+6]=='d'){gone=0;break;} }
            if (!gone) ok = 0;
            if (ok) print("insmod: testmod.ko loaded (ELF reloc + ksym resolution, mod_init=42), shown in /proc/modules, then rmmod ran mod_exit + removed it -- module lifecycle OK\n");
            else { sys_setcolor(2); print("insmodtest: VERIFY FAILED (rv="); sys_setcolor(0); printl(rv); print(" listed="); printl(listed); print(" gone="); printl(gone); print(")\n"); g_status = 1; }
            /* insmod_path (M1595): the SAME testmod.ko content, loaded from a real
             * file instead of the incbin'd blob -- mkfatfs copies build/testmod.ko
             * onto the disk image as /TESTMOD.KO specifically so this can be
             * proven in-guest, not just via a host-side module_load() unit test.
             * The module name is derived from the path's own basename -> "TESTMOD". */
            int ok2 = 1;
            long rv2 = sys_insmod_path("/TESTMOD.KO");
            if (rv2 != 42) ok2 = 0;
            long n3 = sys_readfile("/proc/modules", mb, sizeof mb - 1);
            int listed2 = 0; if (n3 > 0) { mb[n3]=0; for (int i=0;i+7<=n3;i++) if (mb[i]=='T'&&mb[i+1]=='E'&&mb[i+2]=='S'&&mb[i+3]=='T'&&mb[i+4]=='M'&&mb[i+5]=='O'&&mb[i+6]=='D'){listed2=1;break;} }
            if (!listed2) ok2 = 0;
            int un2 = sys_rmmod("TESTMOD");
            if (un2 != 0) ok2 = 0;
            long n4 = sys_readfile("/proc/modules", mb, sizeof mb - 1);
            int gone2 = 1; if (n4 > 0) { mb[n4]=0; for (int i=0;i+7<=n4;i++) if (mb[i]=='T'&&mb[i+1]=='E'&&mb[i+2]=='S'&&mb[i+3]=='T'&&mb[i+4]=='M'&&mb[i+5]=='O'&&mb[i+6]=='D'){gone2=0;break;} }
            if (!gone2) ok2 = 0;
            if (ok2) print("insmod_path: /TESTMOD.KO loaded from a real file (name from its basename -> 'TESTMOD'), shown in /proc/modules, rmmod removed it -- OK\n");
            else { sys_setcolor(2); print("insmodtest: insmod_path VERIFY FAILED (rv2="); sys_setcolor(0); printl(rv2); print(" listed2="); printl(listed2); print(" gone2="); printl(gone2); print(")\n"); g_status = 1; }
        } else if (streq(line, "dltest")) {   /* userspace dynamic linker: dlopen a .so from disk, dlsym + call (M1263) */
            int ok = 1;
            void *h = dlopen("DLTEST.SO");          /* read + map + relocate DLTEST.SO off the FAT disk */
            if (!h) ok = 0;
            long ga = -1, an = -1;
            if (h) {
                int (*greet)(int) = (int (*)(int))dlsym(h, "greet");
                long (*answer)(void) = (long (*)(void))dlsym(h, "answer");
                if (greet) ga = greet(40);          /* RIP-relative + global read -> 42 */
                if (answer) an = answer();          /* indirect call through the RELOCATED GOT slot -> 42 */
                if (!greet || !answer) ok = 0;
            }
            if (!(ok && ga == 42 && an == 42)) ok = 0;
            if (ok) print("dl: dlopen(DLTEST.SO) mapped+relocated the shared object, dlsym(greet)(40)=42, dlsym(answer)()=42 (incl. a JUMP_SLOT reloc) -- userspace dynamic linker OK\n");
            else { sys_setcolor(2); print("dltest: VERIFY FAILED (h="); sys_setcolor(0); printl((long)(h!=0)); print(" greet="); printl(ga); print(" answer="); printl(an); print(")\n"); g_status = 1; }
        } else if (streq(line, "dlxtest")) {   /* cross-object dynamic linking: an import resolved against an EARLIER dlopen()'d .so (M1539) */
            int ok = 1;
            void *hb = dlopen("DLBASE.SO");            /* the dependency: must load first, same as classic Unix load-order rules */
            void *he = hb ? dlopen("DLEXT.SO") : 0;     /* imports base_mul as an undefined symbol -- resolved against DLBASE.SO's export */
            if (!hb || !he) ok = 0;
            long mac = -1;
            if (he) {
                int (*ext_mac)(int, int, int) = (int (*)(int, int, int))dlsym(he, "ext_mac");
                if (ext_mac) mac = ext_mac(6, 7, 3);   /* base_mul(6,7)+3 = 45 -- a wrong pre-M1539 resolve (silently base+0) would crash or return garbage, not 45 */
                else ok = 0;
            }
            if (!(ok && mac == 45)) ok = 0;
            if (ok) print("dl: dlopen(DLBASE.SO) then dlopen(DLEXT.SO), dlsym(ext_mac)(6,7,3)=45 -- import resolved against an earlier-loaded object, not misresolved to its own base -- cross-object dynamic linking OK\n");
            else { sys_setcolor(2); print("dlxtest: VERIFY FAILED (hb="); sys_setcolor(0); printl((long)(hb!=0)); print(" he="); printl((long)(he!=0)); print(" mac="); printl(mac); print(")\n"); g_status = 1; }
        } else if (streq(line, "mmapsharedtest")) {   /* MAP_SHARED file-backed mmap: a write through the mapping reaches the file via msync (M1544) */
            int ok = 1;
            const char *path = "MOTD.TXT";              /* an existing, small boot-disk file */
            char before[64];
            long n0 = sys_readfile(path, before, sizeof before - 1);
            if (n0 <= 0) ok = 0;
            char *m = ok ? (char *)sys_mmap_file(path, 4096, 1) : 0;   /* shared=1: MAP_SHARED */
            if (!m) ok = 0;
            char orig = ok ? m[0] : 0;                  /* first touch faults the page in from the file */
            char written = (char)(orig == 'X' ? 'Y' : 'X');   /* a byte distinct from whatever was already there */
            if (ok) m[0] = written;
            char after[64];
            long n1 = -1;
            if (ok) { sys_msync(m, 4096); n1 = sys_readfile(path, after, sizeof after - 1); }
            if (!(ok && n1 == n0 && after[0] == written && written != orig)) ok = 0;
            if (m) { m[0] = orig; sys_msync(m, 4096); }  /* restore the original byte so re-runs (and other tests) see an unchanged file */
            if (ok) print("mmap: mmap_file(MOTD.TXT, MAP_SHARED) + write + msync -- a SEPARATE sys_readfile of the same path sees the write on disk -- shared page cache OK\n");
            else { sys_setcolor(2); print("mmapsharedtest: VERIFY FAILED (m="); sys_setcolor(0); printl((long)(m!=0)); print(" n0="); printl(n0); print(" n1="); printl(n1); print(")\n"); g_status = 1; }
        } else if (streq(line, "mmapmunmaptest")) {   /* munmap (or exit) a dirty MAP_SHARED page with NO explicit msync() first -- must still flush (M1602) */
            int ok = 1;
            const char *path = "MOTD.TXT";
            char before[64];
            long n0 = sys_readfile(path, before, sizeof before - 1);
            if (n0 <= 0) ok = 0;
            char *m = ok ? (char *)sys_mmap_file(path, 4096, 1) : 0;   /* shared=1: MAP_SHARED */
            if (!m) ok = 0;
            char orig = ok ? m[0] : 0;
            char written = (char)(orig == 'X' ? 'Y' : 'X');
            if (ok) m[0] = written;
            if (ok && sys_munmap(m, 4096) != 0) ok = 0;    /* NO sys_msync call before this -- the fix under test */
            char after[64];
            long n1 = -1;
            if (ok) n1 = sys_readfile(path, after, sizeof after - 1);
            if (!(ok && n1 == n0 && after[0] == written && written != orig)) ok = 0;
            if (ok) {   /* restore the original byte via a fresh mapping so re-runs see an unchanged file */
                char *m2 = (char *)sys_mmap_file(path, 4096, 1);
                if (m2) { m2[0] = orig; sys_msync(m2, 4096); sys_munmap(m2, 4096); }
            }
            if (ok) print("mmap: mmap_file(MOTD.TXT, MAP_SHARED) + write + munmap with NO msync -- the dirty page still flushed to disk on unmap -- OK\n");
            else { sys_setcolor(2); print("mmapmunmaptest: VERIFY FAILED (m="); sys_setcolor(0); printl((long)(m!=0)); print(" n0="); printl(n0); print(" n1="); printl(n1); print(")\n"); g_status = 1; }
        } else if (streq(line, "fdleaktest")) {   /* a child that exits WITHOUT closing an owned fd must not leak its global table slot (M1602) */
            int ok = 1;
            int s = -1;
            for (int i = 0; i < 3; i++) {           /* > TCPSOCK_N (2): would exhaust the global table if app_fd_release leaked */
                long pid = sys_fork();
                if (pid == 0) { sys_socket(2, 1); sys_exit(0); }   /* child: alloc a TCP socket fd, exit WITHOUT closing it */
                if (pid < 0) { ok = 0; break; }
                int status = 0;
                sys_waitpid((int)pid, &status);     /* blocks until app_reap has already freed the child's fds */
            }
            if (ok) { s = sys_socket(2, 1); if (s < 0) ok = 0; }   /* table must NOT be exhausted by the 3 leaked-then-reaped children */
            if (s >= 0) sys_fdclose(s);
            if (ok) print("fdleak: 3x fork+socket()+exit-without-close, reaped each time -- TCP socket table NOT exhausted (leaked pre-M1602) -- OK\n");
            else { sys_setcolor(2); print("fdleaktest: VERIFY FAILED (s="); sys_setcolor(0); printl(s); print(")\n"); g_status = 1; }
        } else if (streq(line, "dupaliastest")) {   /* a dup()'d inotify or TCP-socket fd must survive the ORIGINAL fd closing (M1603) */
            int ok = 1;
            int iw = sys_inotify_init();                              /* inotify half */
            int wd = (iw >= 0) ? sys_inotify_add_watch(iw, "DUPAL", 2 /*IN_MODIFY*/) : -1;
            int iw2 = (iw >= 0) ? sys_dup(iw) : -1;
            if (iw < 0 || wd < 0 || iw2 < 0) ok = 0;
            if (ok) sys_fdclose(iw);                                  /* close the ORIGINAL -- iw2 must still work */
            if (ok) sys_writefile("/tmp/DUPAL.TXT", "hi", 2);
            unsigned char eb[64]; long n = ok ? sys_fdread(iw2, eb, sizeof eb) : -1;
            int inot_ok = (n >= 48);
            if (!inot_ok) ok = 0;
            if (iw2 >= 0) sys_fdclose(iw2);
            int s = sys_socket(2, 1);                                 /* TCP-socket half */
            int one = 1;
            if (s >= 0) sys_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            int s2 = (s >= 0) ? sys_dup(s) : -1;
            if (s < 0 || s2 < 0) ok = 0;
            if (ok) sys_fdclose(s);            /* close the ORIGINAL -- s2 must still reference the SAME TCB */
            int rb = 0; unsigned len = 0;
            int tcp_ok = ok && sys_getsockopt(s2, SOL_SOCKET, SO_REUSEADDR, &rb, &len) == 0 && rb == 1;
            if (!tcp_ok) ok = 0;
            if (s2 >= 0) sys_fdclose(s2);
            if (ok) print("dupalias: dup()'d inotify + TCP-socket fds both survive the ORIGINAL fd closing -- no dangling alias (M1603) -- OK\n");
            else { sys_setcolor(2); print("dupaliastest: VERIFY FAILED (inot_ok="); sys_setcolor(0); printl(inot_ok); print(" tcp_ok="); printl(tcp_ok); print(")\n"); g_status = 1; }
        } else if (streq(line, "lotest")) {   /* loopback (lo, 127.0.0.0/8): a UDP round-trip with NO NIC (M1264) */
            unsigned char lo[4] = {127,0,0,1};
            int ok = 1;
            if (sys_udp_send(lo, 7777, 8888, "loop!", 5) != 0) ok = 0;   /* -> 127.0.0.1:7777 from :8888 */
            unsigned char rb[32]; unsigned char from[6] = {0};
            long n = sys_udp_recv(7777, rb, sizeof rb, from);            /* recv on the destination port */
            int match = (n == 5 && rb[0]=='l' && rb[1]=='o' && rb[2]=='o' && rb[3]=='p' && rb[4]=='!');
            int fromlo = (from[0]==127 && from[3]==1);                   /* the datagram came from 127.0.0.1 */
            if (!(match && fromlo)) ok = 0;
            if (ok) { print("lo: UDP to 127.0.0.1:7777 round-tripped through the loopback iface ("); printl(n);
                      print(" B, src 127.0.0.1) with NO NIC -- loopback OK\n"); }
            else { sys_setcolor(2); print("lotest: VERIFY FAILED (n="); sys_setcolor(0); printl(n); print(" from="); printl(from[0]); print(")\n"); g_status = 1; }
        } else if (streq(line, "inettest")) {   /* AF_INET datagram sockets over loopback (M1267) */
            int ok = 1;
            int sa = sys_socket(2, 2);                       /* AF_INET, SOCK_DGRAM */
            int sb = sys_socket(2, 2);
            if (sa < 0 || sb < 0) ok = 0;
            if (ok && sys_sock_bind(sa, 9999) != 0) ok = 0;  /* receiver bound to :9999 */
            unsigned char lo[4] = {127,0,0,1};
            long snt = (ok) ? sys_sendto(sb, lo, 9999, "INET", 4) : -1;   /* sb -> 127.0.0.1:9999 over lo */
            unsigned char rb[16] = {0}, from[6] = {0};
            long n = (ok) ? sys_recvfrom(sa, rb, sizeof rb, from) : -1;
            int match = (snt == 4 && n == 4 && rb[0]=='I'&&rb[1]=='N'&&rb[2]=='E'&&rb[3]=='T');
            int fromlo = (from[0]==127 && from[3]==1);
            int fromport = from[4] | (from[5] << 8);
            if (!(ok && match && fromlo && fromport > 0)) ok = 0;
            if (ok) { print("inet: socket(AF_INET,SOCK_DGRAM) + bind(:9999); sendto 127.0.0.1:9999 over lo; recvfrom got '");
                      for (int i=0;i<n;i++){char c[2]={(char)rb[i],0};print(c);} print("' from 127.0.0.1:"); printl(fromport);
                      print(" -- BSD UDP sockets OK\n"); }
            else { sys_setcolor(2); print("inettest: VERIFY FAILED (snt="); sys_setcolor(0); printl(snt); print(" n="); printl(n); print(")\n"); g_status = 1; }
            if (sa >= 0) sys_fdclose(sa); if (sb >= 0) sys_fdclose(sb);
        } else if (streq(line, "tcptest")) {   /* AF_INET TCP client socket: a real HTTP fetch (M1268) */
            int ok = 1;
            char ips[32]; long rr = sys_resolve("example.com", ips, sizeof ips);
            unsigned char ip[4] = {0,0,0,0};
            if (rr == 0) { int oct=0,v=0,any=0;                  /* parse the dotted-quad */
                for (int i=0;;i++){ char ch=ips[i];
                    if (ch>='0'&&ch<='9'){v=v*10+(ch-'0');any=1;}
                    else { if(any&&oct<4) ip[oct++]=(unsigned char)v; v=0;any=0; if(ch==0||oct>=4)break; } }
            } else ok = 0;
            int s = ok ? sys_socket(2, 1) : -1;                  /* AF_INET, SOCK_STREAM */
            if (s < 0) ok = 0;
            /* setsockopt/getsockopt (M1554): needs no internet, checked before
             * connect so it's exercised even when the fetch below can't be. */
            int sockopt_ok = 1;
            if (s >= 0) {
                int one = 1, rb1 = 0, rb2 = 0; unsigned len = 0;
                if (sys_setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) sockopt_ok = 0;
                if (sys_getsockopt(s, IPPROTO_TCP, TCP_NODELAY, &rb1, &len) != 0 || rb1 != 1) sockopt_ok = 0;
                if (sys_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) sockopt_ok = 0;
                if (sys_getsockopt(s, SOL_SOCKET, SO_REUSEADDR, &rb2, &len) != 0 || rb2 != 1) sockopt_ok = 0;
                if (sys_setsockopt(s, 999 /* bogus level */, TCP_NODELAY, &one, sizeof(one)) != -1) sockopt_ok = 0;
                unsigned char pip0[4]; int pport0 = 0;                          /* getpeername (M1560): not connected yet -- must fail */
                if (sys_getpeername(s, pip0, &pport0) != -1) sockopt_ok = 0;
            } else sockopt_ok = 0;
            print("setsockopt/getsockopt: TCP_NODELAY+SO_REUSEADDR set+readback, bad (level,optname) denied -- ");
            sys_setcolor(sockopt_ok ? 10 : 4); print(sockopt_ok ? "OK\n" : "VERIFY FAILED\n"); sys_setcolor(0);
            if (!sockopt_ok) g_status = 1;
            if (ok && sys_connect(s, ip, 80) != 0) ok = 0;
            /* getsockname/getpeername (M1560): checked right after connect, independent
             * of whether the HTTP fetch below succeeds -- only needs the TCP handshake. */
            int getname_ok = 1;
            if (ok) {
                unsigned char lip[4] = {0,0,0,0}; int lport = 0;
                if (sys_getsockname(s, lip, &lport) != 0 || lport == 0) getname_ok = 0;   /* connect() assigned a real ephemeral port */
                unsigned char pip[4] = {0,0,0,0}; int pport = 0;
                if (sys_getpeername(s, pip, &pport) != 0 || pport != 80) getname_ok = 0;
                if (pip[0]!=ip[0] || pip[1]!=ip[1] || pip[2]!=ip[2] || pip[3]!=ip[3]) getname_ok = 0;   /* matches the resolved peer */
            } else getname_ok = 0;
            print("getsockname/getpeername: local port assigned post-connect, peer matches example.com:80 -- ");
            sys_setcolor(getname_ok ? 10 : 4); print(getname_ok ? "OK\n" : "VERIFY FAILED\n"); sys_setcolor(0);
            if (!getname_ok) g_status = 1;
            /* SO_ERROR (M1564): 0 after a successful connect (checked on `s`, already
             * connected above), and a real, specific error after a FAILED connect on a
             * fresh socket -- port 1 (TCPMUX) is essentially never listening on a real
             * host. Accepts either RST (ECONNREFUSED) or a firewall silently dropping it
             * (ETIMEDOUT) since that's the remote's behavior, not this OS's; either way
             * proves a real, distinguishable code came back, and it must clear to 0 on a
             * second read (read-once, matching real SO_ERROR semantics). */
            int soerr_ok = 1;
            if (ok) { int err = -999; if (sys_getsockopt(s, SOL_SOCKET, SO_ERROR, &err, 0) != 0 || err != 0) soerr_ok = 0; }
            else soerr_ok = 0;
            int s2 = sys_socket(2, 1);
            if (s2 >= 0) {
                sys_connect(s2, ip, 1);
                int err1 = 0, err2 = -999;
                sys_getsockopt(s2, SOL_SOCKET, SO_ERROR, &err1, 0);
                sys_getsockopt(s2, SOL_SOCKET, SO_ERROR, &err2, 0);
                if (!(err1 == ECONNREFUSED || err1 == ETIMEDOUT) || err2 != 0) soerr_ok = 0;
                sys_fdclose(s2);
            } else soerr_ok = 0;
            print("SO_ERROR: 0 after a good connect, a real error after a bad one, clears on read (read-once) -- ");
            sys_setcolor(soerr_ok ? 10 : 4); print(soerr_ok ? "OK\n" : "VERIFY FAILED\n"); sys_setcolor(0);
            if (!soerr_ok) g_status = 1;
            /* SO_RCVTIMEO (M1583): set a short bound, then read a connected-but-idle
             * socket (no request ever sent -> nothing will ever arrive) and confirm
             * the read returns near that bound, not the old hardcoded ~3s default. */
            int rcvto_ok = 1;
            int s3 = ok ? sys_socket(2, 1) : -1;
            if (s3 >= 0 && sys_connect(s3, ip, 80) == 0) {
                int rb = 0; unsigned len = 0; int want = 400;
                if (sys_setsockopt(s3, SOL_SOCKET, SO_RCVTIMEO, &want, sizeof(want)) != 0) rcvto_ok = 0;
                if (sys_getsockopt(s3, SOL_SOCKET, SO_RCVTIMEO, &rb, &len) != 0 || rb != want) rcvto_ok = 0;
                unsigned long t0 = sys_uptime_ms();
                char scratch[16];
                long rn = sys_fdread(s3, scratch, sizeof scratch);
                unsigned long elapsed = sys_uptime_ms() - t0;
                if (!(rn <= 0 && elapsed >= 300 && elapsed < 2500)) rcvto_ok = 0;   /* near 400ms, nowhere near the old ~3s */
                sys_fdclose(s3);
            } else rcvto_ok = 0;
            print("SO_RCVTIMEO: set+readback, idle-socket read returns near the new bound, not the old ~3s default -- ");
            sys_setcolor(rcvto_ok ? 10 : 4); print(rcvto_ok ? "OK\n" : "VERIFY FAILED\n"); sys_setcolor(0);
            if (!rcvto_ok) g_status = 1;
            const char *req = "GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";
            int rl = 0; while (req[rl]) rl++;
            if (ok) sys_fdwrite(s, req, rl);                     /* send via the connected socket fd */
            char resp[512]; long n = ok ? sys_fdread(s, resp, sizeof resp - 1) : -1;
            int http = (n > 12 && resp[0]=='H'&&resp[1]=='T'&&resp[2]=='T'&&resp[3]=='P'&&resp[4]=='/');
            if (!(ok && http)) ok = 0;
            if (ok) { print("tcp: socket(SOCK_STREAM)+connect(");
                      printl(ip[0]);print(".");printl(ip[1]);print(".");printl(ip[2]);print(".");printl(ip[3]);
                      print(":80)+send+recv "); printl(n); print("B, status: ");
                      for (int i=0;i<n && resp[i] && resp[i]!='\r' && resp[i]!='\n';i++){char c[2]={resp[i],0};print(c);}
                      print(" -- BSD TCP client OK\n"); }
            else { sys_setcolor(2); print("tcptest: VERIFY FAILED (rr="); sys_setcolor(0); printl(rr); print(" n="); printl(n); print(") -- needs internet\n"); g_status = 1; }
            if (s >= 0) sys_fdclose(s);
            /* two concurrent sockets must not share reassembly/FIN state (M1606):
             * interleave connect+send on BOTH before reading either, so if they
             * still aliased one global instance under the hood, one's traffic
             * would have a real chance to corrupt the other's in-flight state.
             * Runs only now that `s` above is closed -- TCPSOCK_N is 2, and this
             * needs both slots free for itself. */
            int twook = 1;
            int ta = ok ? sys_socket(2, 1) : -1, tb = ok ? sys_socket(2, 1) : -1;
            if (ta < 0 || tb < 0) twook = 0;
            if (twook && sys_connect(ta, ip, 80) != 0) twook = 0;
            if (twook && sys_connect(tb, ip, 80) != 0) twook = 0;
            if (twook) sys_fdwrite(ta, req, rl);
            if (twook) sys_fdwrite(tb, req, rl);
            char rA[512], rB[512];
            long nTA = twook ? sys_fdread(ta, rA, sizeof rA - 1) : -1;
            long nTB = twook ? sys_fdread(tb, rB, sizeof rB - 1) : -1;
            int httpA = (nTA > 12 && rA[0]=='H'&&rA[1]=='T'&&rA[2]=='T'&&rA[3]=='P'&&rA[4]=='/');
            int httpB = (nTB > 12 && rB[0]=='H'&&rB[1]=='T'&&rB[2]=='T'&&rB[3]=='P'&&rB[4]=='/');
            if (!(twook && httpA && httpB)) twook = 0;
            if (ta >= 0) sys_fdclose(ta);
            if (tb >= 0) sys_fdclose(tb);
            print("tcp: 2 concurrent sockets, interleaved connect+send before either recv, both got clean independent HTTP responses -- ");
            sys_setcolor(twook ? 10 : 4); print(twook ? "OK\n" : "VERIFY FAILED\n"); sys_setcolor(0);
            if (!twook) g_status = 1;
        } else if (streq(line, "hardentest")) {   /* CPU hardening: UMIP makes a ring-3 SGDT fault (M1269) */
            long pid = sys_fork();
            if (pid == 0) {
                unsigned char gdtr[10];
                __asm__ volatile("sgdt %0" : "=m"(gdtr));   /* privileged under UMIP -> #GP in ring 3 */
                sys_exit(42);                                /* only reached if SGDT did NOT fault */
            }
            int st = -1; sys_waitpid((int)pid, &st);
            int ok = (st != 42);   /* child #GP'd at sgdt before exit(42) -> UMIP blocked it */
            if (ok) print("harden: a ring-3 SGDT faulted (child terminated before exit42) -- UMIP active; SMEP also on (OS boots + make check 58-green under both) -- OK\n");
            else { sys_setcolor(2); print("hardentest: VERIFY FAILED (child ran SGDT + exited 42 -> UMIP not blocking ring-3)\n"); sys_setcolor(0); g_status = 1; }
        } else if (streq(line, "siginfotest")) {   /* SA_SIGINFO: 3-arg handler inspects siginfo + ucontext (M1270) */
            g_si_caught = 0; g_si_signo = 0; g_si_rip = 0;
            sys_sigaction(10 /*SIGUSR1*/, si_handler, 4 /*SA_SIGINFO*/);
            sys_raise(10);             /* deliver SIGUSR1 -> 3-arg handler runs, reads siginfo + ucontext */
            int ok = (g_si_caught == 1 && g_si_signo == 10 && g_si_rip != 0);   /* saw the signal + a sane interrupted PC */
            if (ok) { print("siginfo: SA_SIGINFO 3-arg handler caught SIGUSR1, si_signo=10, read interrupted rip=0x");
                      /* print g_si_rip in hex */
                      { unsigned long v=g_si_rip; char h[17]; int n=0; if(!v)h[n++]='0'; while(v){int d=v&0xf; h[n++]=d<10?('0'+d):('a'+d-10); v>>=4;} while(n){char c[2]={h[--n],0}; print(c);} }
                      print(" from the ucontext -- SA_SIGINFO + siginfo/ucontext OK\n"); }
            else { sys_setcolor(2); print("siginfotest: VERIFY FAILED (caught="); sys_setcolor(0); printl(g_si_caught); print(" signo="); printl(g_si_signo); print(" rip="); printl((long)g_si_rip); print(")\n"); g_status = 1; }
        } else if (streq(line, "rtsigtest")) {   /* RT signals: sigqueue queues 3 payloads, delivered FIFO, not coalesced (M1271) */
            g_rt_n = 0; g_rt_code = 0;
            sys_sigaction(SIGRTMIN, rt_handler, SA_SIGINFO);   /* 3-arg handler so si_value is delivered */
            sys_sigqueue(0, SIGRTMIN, 0xAA11);                 /* pid 0 = self; queue 3 distinct payloads */
            sys_sigqueue(0, SIGRTMIN, 0xBB22);
            sys_sigqueue(0, SIGRTMIN, 0xCC33);
            for (int i = 0; i < 200 && g_rt_n < 3; i++) sys_sched_yield();   /* let all 3 drain (one per return to ring 3) */
            int ok = (g_rt_n == 3 && g_rt_code == SI_QUEUE &&
                      g_rt_vals[0] == 0xAA11 && g_rt_vals[1] == 0xBB22 && g_rt_vals[2] == 0xCC33);
            if (ok) print("rtsig: sigqueue queued 3 SIGRTMIN payloads -> handler got all 3 FIFO (si_value 0xAA11,0xBB22,0xCC33, si_code SI_QUEUE), NOT coalesced -- RT signals + sigqueue OK\n");
            else { sys_setcolor(2); print("rtsigtest: VERIFY FAILED (n="); sys_setcolor(0); printl(g_rt_n); print(" code="); printl(g_rt_code);
                   print(" vals="); for (int i=0;i<g_rt_n && i<3;i++){ printl((long)g_rt_vals[i]); print(" "); } print(")\n"); g_status = 1; }
        } else if (streq(line, "timertest")) {   /* POSIX timer_create + SIGEV_SIGNAL fires through the sigqueue FIFO (M1272) */
            g_tmr_n = 0; g_tmr_code = 0; g_tmr_val = 0;
            sys_sigaction(SIGRTMIN, tmr_handler, SA_SIGINFO);          /* 3-arg handler so si_value arrives */
            long id = sys_timer_create(CLOCK_MONOTONIC, SIGRTMIN, 0x7E57);   /* payload 0x7E57 */
            int armed = (id >= 0) && (sys_timer_settime((int)id, 0, 40, 40) == 0);   /* fire at 40ms, then every 40ms */
            unsigned long t0 = sys_uptime_ms();                        /* bound the wait by WALL time (yields alone don't advance it) */
            while (sys_uptime_ms() - t0 < 250 && g_tmr_n < 5) sys_sched_yield();
            long remaining = sys_timer_gettime((int)id);               /* sane: within one interval */
            sys_timer_delete((int)id);
            for (int i = 0; i < 60; i++) sys_sched_yield();            /* drain any already-queued fires */
            int n1 = g_tmr_n;
            for (int i = 0; i < 120 && (sys_uptime_ms() - t0) < 500; i++) sys_sched_yield();   /* confirm NO new fires post-delete */
            int ok = (armed && n1 >= 3 && g_tmr_n == n1 && g_tmr_code == SI_TIMER &&
                      g_tmr_val == 0x7E57 && remaining >= 0 && remaining <= 60);
            if (ok) { print("timer: timer_create+settime(40ms periodic) fired "); printl(n1);
                      print("x via the sigqueue FIFO (si_value=0x7E57, si_code SI_TIMER), gettime remaining="); printl(remaining);
                      print("ms, stopped after timer_delete -- POSIX timer_create + SIGEV_SIGNAL OK\n"); }
            else { sys_setcolor(2); print("timertest: VERIFY FAILED (armed="); sys_setcolor(0); printl(armed); print(" n="); printl(n1); print(" after="); printl(g_tmr_n);
                   print(" code="); printl(g_tmr_code); print(" val="); printl((long)g_tmr_val); print(" rem="); printl(remaining); print(")\n"); g_status = 1; }
        } else if (streq(line, "hpettest")) {   /* HPET high-resolution clocksource (M1273) */
            unsigned long hz = sys_hpet(1);
            int present = (int)sys_hpet(3);
            unsigned long a = sys_hpet(0);          /* nanoseconds */
            sys_sleep(50);                          /* sleep 50 ms (PIT tick) — HPET measures the real elapsed time */
            unsigned long b = sys_hpet(0);
            unsigned long c = sys_hpet(0), d = sys_hpet(0);   /* back-to-back pair: fine-grained monotonic */
            long dms = (long)((b - a) / 1000000ul);
            int ok = present && hz >= 1000000ul && hz <= 1000000000ul && d > c && dms >= 40 && dms <= 90;
            if (ok) { print("hpet: ACPI-discovered HPET @ "); printl((long)hz); print(" Hz; ns counter advanced ");
                      printl(dms); print("ms across a 50ms sleep, monotonic (back-to-back delta="); printl((long)(d - c));
                      print("ns) -- HPET high-res clocksource OK\n"); }
            else { sys_setcolor(2); print("hpettest: VERIFY FAILED (present="); sys_setcolor(0); printl(present); print(" hz="); printl((long)hz);
                   print(" dms="); printl(dms); print(" mono="); printl(d > c); print(")\n"); g_status = 1; }
        } else if (streq(line, "ptmxtest")) {   /* Unix98 /dev/ptmx + /dev/pts/N over the M1185 pty engine (M1274) */
            int mfd = sys_open("/dev/ptmx");               /* master end (intercept makes it read/write) */
            long n = (mfd >= 0) ? sys_ptsname(mfd) : -1;   /* the slave's pts index */
            char sp[24]; int L = 0; const char *pre = "/dev/pts/";
            while (pre[L]) { sp[L] = pre[L]; L++; }
            if (n < 0) sp[L++] = '?';
            else if (n == 0) sp[L++] = '0';
            else { char t[12]; int k = 0; long v = n; while (v) { t[k++] = (char)('0' + v % 10); v /= 10; } while (k) sp[L++] = t[--k]; }
            sp[L] = 0;
            int sfd = (n >= 0) ? sys_open(sp) : -1;
            if (mfd >= 0 && sfd >= 0) {
                char rb[64];
                sys_fdwrite(mfd, "hi\n", 3);               /* master write -> line discipline commits the line */
                long sr = sys_fdread(sfd, rb, sizeof rb);  /* slave reads the cooked line */
                int slave_ok = (sr == 3 && rb[0] == 'h' && rb[1] == 'i' && rb[2] == '\n');
                sys_fdwrite(sfd, "OK\n", 3);               /* slave output -> master-readable */
                long mr = sys_fdread(mfd, rb, sizeof rb);  /* master reads (line echo + slave output) */
                int got_ok = 0; for (long i = 0; i + 1 < mr; i++) if (rb[i] == 'O' && rb[i + 1] == 'K') got_ok = 1;
                if (slave_ok && got_ok) { print("ptmx: open(/dev/ptmx)=master fd, ptsname -> "); print(sp);
                    print("; master->slave line 'hi' read by slave, slave->master 'OK' read by master via the fd table -- Unix98 PTY (/dev/ptmx + /dev/pts/N) OK\n"); }
                else { sys_setcolor(2); print("ptmxtest: VERIFY FAILED (sr="); sys_setcolor(0); printl(sr); print(" slave_ok="); printl(slave_ok); print(" mr="); printl(mr); print(" got_ok="); printl(got_ok); print(")\n"); g_status = 1; }
            } else { perr("ptmxtest: open failed (mfd="); printl(mfd); print(" pts='"); print(sp); print("' sfd="); printl(sfd); print(")\n"); g_status = 1; }
            if (sfd >= 0) sys_fdclose(sfd);
            if (mfd >= 0) sys_fdclose(mfd);
        } else if (streq(line, "oomtest")) {   /* OOM killer: scoring + cooperative victim kill (M1275) */
            long pid = sys_fork();
            if (pid == 0) {                              /* child: become the fattest, OOM-killable, then loop */
                sys_oom(0, 1000);                        /* boost own oom_adj -> the preferred victim */
                char *p = (char *)sys_mmap(1024 * 1024); /* 1 MB anon region */
                if (p) for (int i = 0; i < 1024 * 1024; i += 4096) p[i] = (char)1;   /* touch -> real RSS */
                for (;;) { sys_pollkey(); sys_sleep(10); }   /* stay alive; pollkey honors the kill flag */
                sys_exit(0);                             /* unreachable */
            }
            sys_sleep(250);                              /* let the child boost adj + balloon + enter its loop */
            long score  = sys_oom(2, (int)pid);          /* the child's oom_score */
            long victim = sys_oom(1, 0);                 /* invoke the OOM killer (sysrq-f style) */
            int st = -1; long w = sys_waitpid((int)pid, &st);   /* the looping child returns here ONLY if it was killed */
            int ok = (pid > 0 && score > 0 && victim == pid && w == pid);
            if (ok) { print("oom: forked a 1MB-RSS child (oom_adj=1000), oom_score="); printl(score);
                      print(" pages; OOM killer selected + cooperatively killed pid "); printl(victim);
                      print(", looping child reaped (system survived) -- OOM killer OK\n"); }
            else { sys_setcolor(2); print("oomtest: VERIFY FAILED (pid="); sys_setcolor(0); printl(pid); print(" score="); printl(score);
                   print(" victim="); printl(victim); print(" w="); printl(w); print(")\n"); g_status = 1; }
        } else if (streq(line, "altstacktest")) {   /* sigaltstack + SA_ONSTACK: handler runs on the alt stack (M1276) */
            static char altstk[8192];                    /* the alternate signal stack */
            for (unsigned i = 0; i < sizeof altstk; i += 512) altstk[i] = 0;   /* fault it in so it's mapped/present */
            g_alt_lo = (unsigned long)altstk;
            g_alt_hi = (unsigned long)altstk + sizeof altstk;
            g_alt_on = -1;
            int sset = (int)sys_sigaltstack(altstk, sizeof altstk);
            sys_sigaction(SIGRTMIN, alt_handler, SA_SIGINFO | SA_ONSTACK);
            sys_raise(SIGRTMIN);                         /* deliver -> handler should run ON the alt stack */
            int ok = (sset == 0 && g_alt_on == 1);
            if (ok) print("altstack: SA_ONSTACK handler for SIGRTMIN ran with its stack pointer inside the sigaltstack() region (8KB) -- sigaltstack OK\n");
            else { sys_setcolor(2); print("altstacktest: VERIFY FAILED (sset="); sys_setcolor(0); printl(sset); print(" on_alt="); printl(g_alt_on); print(")\n"); g_status = 1; }
        } else if (streq(line, "oomscoretest")) {   /* /proc/<pid>/oom_score reflects RSS + oom_adj (M1277) */
            char sb[64];
            long n = sys_readfile("/proc/self/oom_score", sb, sizeof sb - 1);
            long base = -1;
            if (n > 0) { sb[n] = 0; base = 0; for (int i = 0; sb[i] >= '0' && sb[i] <= '9'; i++) base = base * 10 + (sb[i] - '0'); }
            sys_oom(0, 100);                              /* bump our oom_adj -> score should rise by 100*256 = 25600 */
            long n2 = sys_readfile("/proc/self/oom_score", sb, sizeof sb - 1);
            long after = -1;
            if (n2 > 0) { sb[n2] = 0; after = 0; for (int i = 0; sb[i] >= '0' && sb[i] <= '9'; i++) after = after * 10 + (sb[i] - '0'); }
            sys_oom(0, 0);                               /* restore default oom_adj */
            int ok = (base > 0 && after - base >= 25000);   /* RSS-based + the +25600 adj bias landed */
            if (ok) { print("oom_score: /proc/self/oom_score="); printl(base); print(" pages (RSS-based); after oom_adj+=100 -> "); printl(after); print(" (+25600 bias) -- /proc/<pid>/oom_score OK\n"); }
            else { sys_setcolor(2); print("oomscoretest: VERIFY FAILED (base="); sys_setcolor(0); printl(base); print(" after="); printl(after); print(")\n"); g_status = 1; }
        } else if (streq(line, "sysrqtest")) {   /* magic SysRq over /proc/sysrq-trigger (M1278) */
            long wm = sys_writefile("/proc/sysrq-trigger", "m", 1);   /* 'm' -> dump meminfo to the kernel log */
            char kb[8192]; long kn = sys_readfile("/proc/kmsg", kb, sizeof kb - 1);
            int mem_ok = 0;
            if (kn > 0) { kb[kn] = 0; for (long i = 0; i + 5 < kn; i++)
                if (kb[i] == 's' && kb[i+1] == 'y' && kb[i+2] == 's' && kb[i+3] == 'r' && kb[i+4] == 'q') { mem_ok = 1; break; } }
            long pid = sys_fork();                                    /* 'f' -> OOM-kill the fattest process */
            if (pid == 0) { sys_oom(0, 1000); for (;;) { sys_pollkey(); sys_sleep(10); } sys_exit(0); }
            sys_sleep(150);                                           /* let the child boost adj + enter its loop */
            long wf = sys_writefile("/proc/sysrq-trigger", "f", 1);   /* invoke the OOM killer via SysRq */
            int st = -1; long w = sys_waitpid((int)pid, &st);         /* looping child returns here only if killed */
            int ok = (wm == 1 && wf == 1 && mem_ok && pid > 0 && w == pid);
            if (ok) print("sysrq: echo m > /proc/sysrq-trigger -> meminfo in the kernel log; echo f -> OOM killer reaped the fattest child (pid match) -- magic SysRq OK\n");
            else { sys_setcolor(2); print("sysrqtest: VERIFY FAILED (wm="); sys_setcolor(0); printl(wm); print(" wf="); printl(wf); print(" mem="); printl(mem_ok); print(" w="); printl(w); print(")\n"); g_status = 1; }
        } else if (streq(line, "winsztest")) {   /* pty TIOCSWINSZ/TIOCGWINSZ + SIGWINCH on resize (M1279) */
            g_winch = 0;
            sys_signal(SIGWINCH, winch_handler);
            int m = sys_pty_open();
            if (m >= 0) sys_pty_ctl(m, 1, sys_getpid());                /* fg pgid = us, so the resize SIGWINCH targets us */
            int set = (m >= 0) ? sys_pty_ctl(m, 2, (40 << 16) | 120) : -1;   /* TIOCSWINSZ: 40 rows x 120 cols */
            int got = (m >= 0) ? sys_pty_ctl(m, 3, 0) : -1;                  /* TIOCGWINSZ: read it back */
            int rows = (got >> 16) & 0xFFFF, cols = got & 0xFFFF;
            if (m >= 0) sys_pty_close(m);
            int ok = (m >= 0 && set == 0 && rows == 40 && cols == 120 && g_winch == 1);
            if (ok) print("winsz: pty TIOCSWINSZ 40x120 -> TIOCGWINSZ read back 40x120; SIGWINCH delivered to the foreground group on resize -- pty window size OK\n");
            else { sys_setcolor(2); print("winsztest: VERIFY FAILED (m="); sys_setcolor(0); printl(m); print(" set="); printl(set); print(" rows="); printl(rows); print(" cols="); printl(cols); print(" winch="); printl(g_winch); print(")\n"); g_status = 1; }
        } else if (streq(line, "settimetest")) {   /* clock_settime(CLOCK_REALTIME) sets the wall clock (M1280) */
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts); long orig = ts.tv_sec;
            long target = 1700000000;                                /* a known epoch (2023-11-14 UTC) */
            long r = sys_clock_settime(CLOCK_REALTIME, target, 0);
            clock_gettime(CLOCK_REALTIME, &ts); long after = ts.tv_sec;
            long mono = sys_clock_settime(CLOCK_MONOTONIC, 0, 0);     /* must be refused */
            sys_clock_settime(CLOCK_REALTIME, orig, 0);              /* restore the real wall clock */
            int ok = (r == 0 && after >= target && after <= target + 2 && mono != 0);
            if (ok) { print("settime: clock_settime(CLOCK_REALTIME, 1700000000) -> clock_gettime read back "); printl(after);
                      print("; setting CLOCK_MONOTONIC refused; original time restored -- clock_settime OK\n"); }
            else { sys_setcolor(2); print("settimetest: VERIFY FAILED (r="); sys_setcolor(0); printl(r); print(" after="); printl(after); print(" mono="); printl(mono); print(")\n"); g_status = 1; }
        } else if (streq(line, "pidfdgetfdtest")) {   /* pidfd_getfd: grab an fd from another process (M1281) */
            sys_writefile("/tmp/PG.TXT", "0123456789ABCDEFGHIJ", 20);
            int f = sys_open("/tmp/PG.TXT");             /* parent opens the file */
            char t[16]; sys_fdread(f, t, 10);            /* parent's fd offset -> 10 */
            long pid = sys_fork();
            if (pid == 0) { sys_sleep(400); sys_exit(0); }   /* child inherits f frozen at offset 10, holds it, self-exits */
            sys_fdread(f, t, 5);                          /* DIVERGE: advance the PARENT's own copy of f -> offset 15 */
            sys_sleep(150);                              /* let the child settle */
            int pfd = sys_pidfd_open((int)pid, 0);
            int newfd = (pfd >= 0) ? sys_pidfd_getfd(pfd, f, 0) : -1;   /* grab the CHILD's copy of f (still at offset 10) */
            char buf[8]; long n = (newfd >= 0) ? sys_fdread(newfd, buf, 5) : -1;
            int match = (n == 5 && buf[0] == 'A' && buf[4] == 'E');     /* child's offset 10 -> "ABCDE" (NOT parent's offset 15 -> "FGHIJ") */
            if (newfd >= 0) sys_fdclose(newfd);
            if (pfd >= 0) sys_fdclose(pfd);
            sys_fdclose(f);
            int st = -1; sys_waitpid((int)pid, &st);     /* child self-exits at ~400ms; reap it */
            int ok = (f >= 0 && pid > 0 && pfd >= 0 && newfd >= 0 && match);
            if (ok) print("pidfd_getfd: parent advanced its own fd to offset 15; pidfd_getfd(pidfd,fd) grabbed the CHILD's copy (offset 10) and read 'ABCDE' (not the parent's 'FGHIJ') -- cross-process fd duplication OK\n");
            else { sys_setcolor(2); print("pidfdgetfdtest: VERIFY FAILED (f="); sys_setcolor(0); printl(f); print(" pid="); printl(pid); print(" pfd="); printl(pfd); print(" newfd="); printl(newfd); print(" n="); printl(n); print(")\n"); g_status = 1; }
        } else if (streq(line, "oomadjtest")) {   /* /proc/<pid>/oom_score_adj read+write (M1282) */
            char b[40]; long n;
            n = sys_readfile("/proc/self/oom_score_adj", b, sizeof b - 1);
            long adj0 = -999; if (n > 0) { b[n] = 0; adj0 = 0; int i = 0, neg = 0; if (b[0] == '-') { neg = 1; i = 1; }
                for (; b[i] >= '0' && b[i] <= '9'; i++) adj0 = adj0 * 10 + (b[i] - '0'); if (neg) adj0 = -adj0; }
            long w = sys_writefile("/proc/self/oom_score_adj", "500", 3);   /* set the bias via the canonical /proc path */
            n = sys_readfile("/proc/self/oom_score_adj", b, sizeof b - 1);
            long adj1 = -999; if (n > 0) { b[n] = 0; adj1 = 0; for (int i = 0; b[i] >= '0' && b[i] <= '9'; i++) adj1 = adj1 * 10 + (b[i] - '0'); }
            n = sys_readfile("/proc/self/oom_score", b, sizeof b - 1);       /* oom_score should reflect +500*256 = 128000 */
            long score = -1; if (n > 0) { b[n] = 0; score = 0; for (int i = 0; b[i] >= '0' && b[i] <= '9'; i++) score = score * 10 + (b[i] - '0'); }
            sys_writefile("/proc/self/oom_score_adj", "0", 1);              /* restore default */
            int ok = (adj0 == 0 && w == 3 && adj1 == 500 && score >= 128000);
            if (ok) { print("oom_score_adj: /proc/self/oom_score_adj 0 -> wrote 500 via /proc -> read back 500; oom_score rose to "); printl(score);
                      print(" (+128000 bias); restored -- /proc/<pid>/oom_score_adj rw OK\n"); }
            else { sys_setcolor(2); print("oomadjtest: VERIFY FAILED (adj0="); sys_setcolor(0); printl(adj0); print(" w="); printl(w); print(" adj1="); printl(adj1); print(" score="); printl(score); print(")\n"); g_status = 1; }
        } else if (streq(line, "mlockalltest")) {   /* mlockall(MCL_CURRENT|MCL_FUTURE) + munlockall (M1283) */
            unsigned long np = 8, len = np * 4096;
            unsigned char *A = (unsigned char *)sys_mmap(len);             /* a CURRENT region */
            unsigned char va[8], vb[8];
            if (!A) { print("mlockalltest: mmap A failed\n"); g_status = 1; }
            else {
                for (unsigned long i = 0; i < len; i++) A[i] = 1;          /* fault A fully in */
                sys_mlockall(MCL_CURRENT | MCL_FUTURE);                    /* pin A (current) + arm future */
                unsigned char *B = (unsigned char *)sys_mmap(len);         /* a FUTURE region -> born locked */
                if (!B) { print("mlockalltest: mmap B failed\n"); g_status = 1; }
                else {
                    for (unsigned long i = 0; i < len; i++) B[i] = 1;      /* fault B in */
                    sys_madvise(A, len, 4 /*MADV_DONTNEED*/); sys_madvise(B, len, 4);   /* try to reclaim; locked VMAs are skipped */
                    sys_mincore(A, len, va); sys_mincore(B, len, vb);
                    long ra = 0, rb = 0; for (unsigned long i = 0; i < np; i++) { ra += va[i]; rb += vb[i]; }
                    sys_munlockall();                                      /* release both + clear future */
                    sys_madvise(A, len, 4); sys_madvise(B, len, 4);        /* now reclaimable */
                    sys_mincore(A, len, va); sys_mincore(B, len, vb);
                    long ra2 = 0, rb2 = 0; for (unsigned long i = 0; i < np; i++) { ra2 += va[i]; rb2 += vb[i]; }
                    int ok = (ra == (long)np && rb == (long)np && ra2 == 0 && rb2 == 0);
                    if (ok) print("mlockall: MCL_CURRENT pinned A + MCL_FUTURE pinned the later B (both survived reclaim); munlockall released both (both dropped) -- mlockall/munlockall OK\n");
                    else { sys_setcolor(2); print("mlockalltest: VERIFY FAILED (lockedA="); sys_setcolor(0); printl(ra); print("/"); printl((long)np); print(" lockedB="); printl(rb); print(" unlockA="); printl(ra2); print(" unlockB="); printl(rb2); print(")\n"); g_status = 1; }
                    sys_munmap(B, len);
                }
                sys_munmap(A, len);
            }
        } else if (streq(line, "amltest")) {   /* ACPI AML DSDT namespace parser (M1284) */
            long total = sys_acpi(0), dev = sys_acpi(1), mth = sys_acpi(2), pci0 = sys_acpi(3), sb = sys_acpi(4);
            int ok = (total > 0 && dev >= 1 && (pci0 == 1 || sb == 1));
            if (ok) { print("aml: parsed QEMU's DSDT AML namespace -> "); printl(total); print(" objects, "); printl(dev);
                      print(" devices, "); printl(mth); print(" methods; found well-known "); print(pci0 ? "PCI0" : "_SB_");
                      print(" -- ACPI AML namespace parser OK\n"); }
            else { sys_setcolor(2); print("amltest: VERIFY FAILED (total="); sys_setcolor(0); printl(total); print(" dev="); printl(dev); print(" mth="); printl(mth); print(" pci0="); printl(pci0); print(" sb="); printl(sb); print(")\n"); g_status = 1; }
        } else if (streq(line, "acpifstest")) {   /* /proc/acpi: browsable AML namespace (M1285) */
            static char b[4096];
            long n = sys_readfile("/proc/acpi", b, sizeof b - 1);
            int has_pci0 = 0, has_dev = 0, has_hdr = 0;
            if (n > 0) { b[n] = 0;
                for (long i = 0; i + 4 <= n; i++) {
                    if (b[i] == 'P' && b[i+1] == 'C' && b[i+2] == 'I' && b[i+3] == '0') has_pci0 = 1;
                    if (b[i] == 'D' && b[i+1] == 'e' && b[i+2] == 'v' && b[i+3] == 'i') has_dev = 1;
                    if (b[i] == 'D' && b[i+1] == 'S' && b[i+2] == 'D' && b[i+3] == 'T') has_hdr = 1;
                }
            }
            int ok = (n > 0 && has_hdr && has_dev && has_pci0);
            if (ok) { print("acpifs: cat /proc/acpi -> "); printl(n); print(" bytes listing the DSDT namespace incl. a Device named PCI0 -- /proc/acpi OK\n"); }
            else { sys_setcolor(2); print("acpifstest: VERIFY FAILED (n="); sys_setcolor(0); printl(n); print(" hdr="); printl(has_hdr); print(" dev="); printl(has_dev); print(" pci0="); printl(has_pci0); print(")\n"); g_status = 1; }
        } else if (streq(line, "amlevaltest")) {   /* AML EVALUATION: eval \\_S5_ + cross-check vs acpi.c's byte-scan (M1286) */
            long ev = sys_acpi(5), scan = sys_acpi(6);   /* ev = AML-evaluated _S5 package; scan = independent table byte-scan */
            int ok = (ev >= 0 && scan >= 0 && ev == scan);
            if (ok) { print("amleval: AML-evaluated the \\_S5_ package through the namespace -> SLP_TYP 0x");
                      { unsigned long v = (unsigned long)ev; char h[9]; int k = 0; if (!v) h[k++] = '0'; while (v) { int d = v & 0xf; h[k++] = d < 10 ? ('0' + d) : ('a' + d - 10); v >>= 4; } while (k) { char c[2] = { h[--k], 0 }; print(c); } }
                      print("; matches acpi.c's independent table byte-scan -- AML evaluation OK\n"); }
            else { sys_setcolor(2); print("amlevaltest: VERIFY FAILED (eval="); sys_setcolor(0); printl(ev); print(" scan="); printl(scan); print(")\n"); g_status = 1; }
        } else if (streq(line, "aslrtest")) {   /* ASLR: independently-exec'd processes get different mmap bases (M1287) */
            unsigned long self = sys_aslr(0);             /* the shell's randomized mmap base */
            long pid2 = sys_spawn("shell");               /* a 2nd, independently app_spawn'd process -> a fresh CSPRNG base */
            unsigned long base2 = (pid2 > 0) ? sys_aslr((int)pid2) : 0;
            if (pid2 > 0) sys_kill((int)pid2);            /* tear down the helper window */
            int in_range = (self >= 0x60000000ul && self < 0x64000000ul) &&
                           (base2 >= 0x60000000ul && base2 < 0x64000000ul);   /* both inside the randomized window */
            int ok = (self != 0 && base2 != 0 && base2 != self && in_range);
            if (ok) {
                print("aslr: two app_spawns landed mmap at 0x");
                { unsigned long v=self; char h[17]; int k=0; if(!v)h[k++]='0'; while(v){int d=v&0xf; h[k++]=d<10?('0'+d):('a'+d-10); v>>=4;} while(k){char c[2]={h[--k],0}; print(c);} }
                print(" and 0x");
                { unsigned long v=base2; char h[17]; int k=0; if(!v)h[k++]='0'; while(v){int d=v&0xf; h[k++]=d<10?('0'+d):('a'+d-10); v>>=4;} while(k){char c[2]={h[--k],0}; print(c);} }
                print(" -- different per exec, both CSPRNG-randomized in the window -- ASLR OK\n");
            } else { sys_setcolor(2); print("aslrtest: VERIFY FAILED (self=0x"); sys_setcolor(0); printl((long)self); print(" base2=0x"); printl((long)base2); print(" inrange="); printl(in_range); print(" pid2="); printl(pid2); print(")\n"); g_status = 1; }
        } else if (streq(line, "rawtest")) {   /* raw packet sockets: send a raw L2 frame + sniff inbound (M1259) */
            int ok = 1;
            /* (1) raw TX: a broadcast ARP-request-shaped frame (proves ring 3 can ship a whole L2 frame). */
            unsigned char frame[42];
            for (int i=0;i<6;i++) frame[i]=0xFF;            /* dst = broadcast */
            for (int i=6;i<42;i++) frame[i]=0;
            frame[12]=0x08; frame[13]=0x06;                 /* ethertype = ARP */
            frame[14]=0x00; frame[15]=0x01; frame[16]=0x08; frame[17]=0x00;  /* HTYPE eth / PTYPE IPv4 */
            frame[18]=6; frame[19]=4; frame[20]=0x00; frame[21]=0x01;         /* HLEN PLEN OP=request */
            if (sys_raw_send(frame, 42) != 0) ok = 0;
            /* (2) raw RX: generate guaranteed inbound traffic (a DNS query -> a reply frame), then sniff it. */
            unsigned char dns[4] = {10,0,2,3};
            unsigned char q[32]; int dl=0;
            q[dl++]=0x33;q[dl++]=0x44; q[dl++]=0x01;q[dl++]=0x00; q[dl++]=0;q[dl++]=1;
            q[dl++]=0;q[dl++]=0; q[dl++]=0;q[dl++]=0; q[dl++]=0;q[dl++]=0;     /* an/ns/ar=0 */
            q[dl++]=1; q[dl++]='a'; q[dl++]=3; q[dl++]='c';q[dl++]='o';q[dl++]='m'; q[dl++]=0;
            q[dl++]=0;q[dl++]=1; q[dl++]=0;q[dl++]=1;        /* QTYPE A / QCLASS IN */
            sys_udp_send(dns, 53, 0xC0C0, q, dl);
            unsigned char fr[1600]; long flen=-1; int et=-1, got=0;
            for (int tries=0; tries<4 && !got; tries++) {
                long n = sys_raw_recv(fr, sizeof fr);
                if (n >= 14) { et = (fr[12]<<8)|fr[13]; flen=n;
                               if (et==0x0800 || et==0x0806) got=1; }   /* captured a real IPv4/ARP frame */
            }
            if (!got) ok = 0;
            if (ok) { print("raw: TX 42B ARP frame ok; sniffed "); printl(flen);
                      print("B frame, ethertype "); printl(et);
                      print(et==0x0800?" (IPv4)":" (ARP)"); print(" -- raw packet socket OK\n"); }
            else { sys_setcolor(2); print("rawtest: VERIFY FAILED\n"); sys_setcolor(0); }
            if (!ok) g_status = 1;
        } else if (streq(line, "fifotest")) {   /* named pipe (mkfifo) rendezvous by pathname (M1188) */
            if (sys_mkfifo("fifotest.pipe") != 0) { perr("fifotest: mkfifo failed\n"); g_status = 1; }
            else {
                long pid = sys_fork();
                if (pid == 0) {                          /* child: open the FIFO BY NAME for writing */
                    int w = sys_fifo_open("fifotest.pipe", 1);
                    if (w >= 0) { sys_fdwrite(w, "fifo!", 5); sys_fdclose(w); }
                    sys_exit(0);
                }
                int ok = 1;
                int rfd = sys_fifo_open("fifotest.pipe", 0);   /* parent opens the SAME name for reading */
                if (rfd < 0) ok = 0;
                else {
                    char b[32];
                    long n = sys_fdread(rfd, b, sizeof b);      /* blocks until the child connects + writes */
                    if (!(n == 5 && b[0] == 'f' && b[4] == '!')) ok = 0;
                    long e = sys_fdread(rfd, b, sizeof b);      /* child closed write end + exited -> EOF */
                    if (e != 0) ok = 0;
                    sys_fdclose(rfd);
                }
                int st = 0; sys_waitpid((int)pid, &st);
                print(ok ? "fifo: mkfifo + open-by-name rendezvous + EOF OK\n" : "fifotest: VERIFY FAILED\n");
                if (!ok) g_status = 1;
            }
        } else if (streq(line, "syscount") || streq(line, "syscount on")) {   /* syscall profiler: load a count-by-number eBPF probe (M1203) */
            struct bpf_insn prog[] = {
                { BPF_LDCTX,  0, 0, 0, 0 },     /* r0 = syscall nr */
                { BPF_MAPINC, 0, 0, 0, 0 },     /* map[nr]++ */
                { BPF_LDI,    1, 0, 0, 1 },     /* r1 = 1 */
                { BPF_RET,    1, 0, 0, 0 },     /* pass */
            };
            if (sys_bpf_trace(prog, sizeof prog) == 0)
                print("syscount: counting syscalls system-wide -- `cat /proc/syscalls` for the histogram, `syscount off` to stop\n");
            else { print("syscount: failed to load the probe\n"); g_status = 1; }
        } else if (streq(line, "syscount off")) {
            sys_bpf_trace(0, 0);
            print("syscount: stopped (histogram cleared)\n");
        } else if (streq(line, "bpftracetest")) {   /* eBPF syscall tracepoint: count syscalls by number into a BPF map (M1202) */
            /* program: r0 = ctx field 0 (the syscall number); bpf_map[r0]++; return 1 (pass) */
            struct bpf_insn prog[] = {
                { BPF_LDCTX,  0, 0, 0, 0 },     /* r0 = syscall nr */
                { BPF_MAPINC, 0, 0, 0, 0 },     /* map[nr]++ */
                { BPF_LDI,    1, 0, 0, 1 },     /* r1 = 1 */
                { BPF_RET,    1, 0, 0, 0 },     /* pass */
            };
            if (sys_bpf_trace(prog, sizeof prog) != 0) { print("bpf-trace: load failed\n"); g_status = 1; }
            else {
                unsigned long before = sys_bpf_map_get(SYS_getpid);
                for (int i = 0; i < 5; i++) (void)sys_getpid();      /* 5 known syscalls -> map[getpid] += 5 */
                unsigned long after = sys_bpf_map_get(SYS_getpid);
                sys_bpf_trace(0, 0);                                 /* stop tracing + clear the histogram */
                if (after >= before + 5)
                    print("bpf-trace: histogram probe on every syscall; 5x getpid -> map[getpid] counted -- OK\n");
                else { print("bpf-trace: FAILED (the histogram did not count the calls)\n"); g_status = 1; }
            }
        } else if (streq(line, "ptracetest")) {   /* ptrace: trace a child — stop, peek/poke mem, snapshot regs, continue (M1199) */
            volatile long x = 111;
            long pid = sys_fork();
            if (pid == 0) {                         /* child = tracee */
                sys_ptrace(PT_TRACEME, 0, 0, 0);
                sys_raise(SIGSTOP);                 /* stop here; the tracer pokes x while we're stopped */
                sys_exit(x == 222 ? 7 : 8);         /* the tracer should have changed x: 111 -> 222 */
            }
            long sig    = sys_ptrace(PT_WAIT, (int)pid, 0, 0);                      /* block until the child stops */
            long before = sys_ptrace(PT_PEEKDATA, (int)pid, (unsigned long)&x, 0);  /* read the child's x (=111) */
            sys_ptrace(PT_POKEDATA, (int)pid, (unsigned long)&x, 222);              /* overwrite it in the child */
            long after  = sys_ptrace(PT_PEEKDATA, (int)pid, (unsigned long)&x, 0);  /* read it back (=222) */
            unsigned long regs[40];
            long gr     = sys_ptrace(PT_GETREGS, (int)pid, (unsigned long)regs, 0); /* snapshot the child's registers */
            long sr     = sys_ptrace(PT_SETREGS, (int)pid, (unsigned long)regs, 0); /* write them back: a non-destructive round-trip */
            sys_ptrace(PT_SINGLESTEP, (int)pid, 0, 0);                              /* run one instruction, then re-stop */
            long sig2   = sys_ptrace(PT_WAIT, (int)pid, 0, 0);                      /* the single-step trap (SIGTRAP) */
            sys_ptrace(PT_CONT, (int)pid, 0, 0);                                    /* resume the child to completion */
            int st = -1; sys_waitpid((int)pid, &st);
            if (sig == SIGSTOP && before == 111 && after == 222 && gr == 0 && sr == 0 && sig2 == SIGTRAP && st == 7)
                print("ptrace: stop + PEEK(111)/POKE(222) + GET/SETREGS + SINGLESTEP(SIGTRAP) + CONT -> child exit 7 -- OK\n");
            else { print("ptrace: FAILED\n"); g_status = 1; }
        } else if (streq(line, "seccomptest")) {   /* self-imposed BPF syscall filter: DENY + KILL (M1190/M1192) */
            int ok = 1;
            /* part 1 (M1190): a DENY filter -> the blocked syscall returns -1, the process continues */
            long pid = sys_fork();
            if (pid == 0) {
                struct bpf_insn prog[] = {           /* deny SYS_writefile, allow the rest */
                    { BPF_LDI,   1, 0, 0, SECCOMP_RET_ALLOW },
                    { BPF_LDCTX, 0, 0, 0, 0 },                       /* r0 = syscall nr */
                    { BPF_JEQ,   0, 1, 0, (int32_t)SYS_writefile },  /* nr==writefile? -> skip to the deny RET */
                    { BPF_RET,   1, 0, 0, 0 },                       /* allow */
                    { BPF_LDI,   1, 0, 0, SECCOMP_RET_DENY },
                    { BPF_RET,   1, 0, 0, 0 },                       /* deny (-1) */
                };
                if (sys_seccomp_filter(prog, sizeof prog) != 0) sys_exit(2);
                long denied = sys_writefile("/tmp/sec_probe", "x", 1);   /* blocked -> -1 */
                long allowed = sys_getpid();                             /* still works */
                sys_exit((denied < 0 && allowed > 0) ? 42 : 1);
            }
            int st = -1; sys_waitpid((int)pid, &st);
            if (st != 42) ok = 0;
            /* part 2 (M1192): a KILL filter -> the process is TERMINATED on the forbidden syscall */
            long kpid = sys_fork();
            if (kpid == 0) {
                struct bpf_insn prog[] = {           /* kill on SYS_writefile, allow the rest */
                    { BPF_LDI,   1, 0, 0, SECCOMP_RET_ALLOW },
                    { BPF_LDCTX, 0, 0, 0, 0 },
                    { BPF_JEQ,   0, 1, 0, (int32_t)SYS_writefile },  /* nr==writefile? -> skip to the kill RET */
                    { BPF_RET,   1, 0, 0, 0 },                       /* allow */
                    { BPF_LDI,   1, 0, 0, SECCOMP_RET_KILL },
                    { BPF_RET,   1, 0, 0, 0 },                       /* kill */
                };
                if (sys_seccomp_filter(prog, sizeof prog) != 0) sys_exit(2);
                sys_writefile("/tmp/sec_probe2", "x", 1);   /* -> KILLED here (never returns) */
                sys_exit(7);                                 /* unreachable if the kill worked */
            }
            int kst = -99; sys_waitpid((int)kpid, &kst);
            if (kst == 7) ok = 0;                            /* reached exit 7 => NOT killed => fail */
            print(ok ? "seccomp: DENY blocks (-1) + allowed runs; KILL terminates the violator -- OK\n"
                     : "seccomptest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "stdiotest")) {   /* stdio over the fd table: print()->fd1->pipe->fd0->readline() (M1191) */
            long h = sys_fork();                  /* a harness child runs the whole producer|consumer pipeline */
            if (h == 0) {                         /* (so the shell's own fd 0/1 are never redirected) */
                int p[2];
                if (sys_pipe(p) != 0) sys_exit(2);
                long pr = sys_fork();
                if (pr == 0) {                    /* producer: redirect stdout to the pipe, then print() */
                    sys_dup2(p[1], 1);
                    sys_fdclose(p[0]); sys_fdclose(p[1]);
                    print("piped-via-stdout\n");  /* -> sys_write(1) -> the pipe */
                    sys_exit(0);
                }
                sys_dup2(p[0], 0);                /* consumer: redirect stdin from the pipe, then readline() */
                sys_fdclose(p[0]); sys_fdclose(p[1]);
                char buf[64]; int n = readline(buf, sizeof buf);   /* -> sys_read(0) -> the pipe */
                int ok = (n == 16 && streq(buf, "piped-via-stdout"));
                int cst = 0; sys_waitpid((int)pr, &cst);
                sys_exit(ok ? 42 : 1);
            }
            int st = -1; sys_waitpid((int)h, &st);
            print(st == 42 ? "stdio-fd: print() -> redirected fd1 -> pipe -> fd0 -> readline() round-trip OK\n"
                           : "stdiotest: VERIFY FAILED\n");
            if (st != 42) g_status = 1;
        } else if (streq(line, "filefdtest")) {   /* read-only file descriptors: open/read/lseek (M1193) */
            const char *content = "0123456789ABCDEFGHIJ";          /* 20 known bytes */
            sys_writefile("/tmp/ffd.txt", content, 20);
            int fd = sys_open("/tmp/ffd.txt");
            int ok = (fd >= 3);
            if (ok) {
                char b[8];
                long n1 = sys_read(fd, b, 5);                      /* [0,5) = "01234" */
                if (!(n1 == 5 && b[0] == '0' && b[4] == '4')) ok = 0;
                long n2 = sys_read(fd, b, 5);                      /* [5,10) = "56789" (offset advanced) */
                if (!(n2 == 5 && b[0] == '5' && b[4] == '9')) ok = 0;
                if (sys_lseek(fd, 16, SEEK_SET) != 16) ok = 0;     /* seek to 16 */
                long n3 = sys_read(fd, b, 8);                      /* [16,20) = "GHIJ" (4, then EOF) */
                if (!(n3 == 4 && b[0] == 'G' && b[3] == 'J')) ok = 0;
                if (sys_read(fd, b, 8) != 0) ok = 0;               /* at end -> EOF (0) */
                if (sys_lseek(fd, -2, SEEK_END) != 18) ok = 0;     /* size-2 = 18 */
                long n5 = sys_read(fd, b, 8);                      /* [18,20) = "IJ" */
                if (!(n5 == 2 && b[0] == 'I' && b[1] == 'J')) ok = 0;
                sys_fdclose(fd);
            }
            print(ok ? "file-fd: open + chunked read (offset advances) + lseek SET/END + EOF all OK\n"
                     : "filefdtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "procfdtest")) {   /* /proc/self/fd lists the fd table (M1194) */
            sys_writefile("/tmp/pf.txt", "x", 1);
            int p[2]; int havp = (sys_pipe(p) == 0);          /* 2 pipe fds */
            int ff = sys_open("/tmp/pf.txt");                  /* a file fd */
            char buf[512]; long n = sys_readfile("/proc/self/fd", buf, sizeof buf - 1);
            if (n < 0) n = 0; buf[n] = 0;
            int sawpipe = 0, sawfile = 0;                      /* the listing must mention both */
            for (long i = 0; i + 4 <= n; i++) {
                if (buf[i]=='p'&&buf[i+1]=='i'&&buf[i+2]=='p'&&buf[i+3]=='e') sawpipe = 1;
                if (buf[i]=='f'&&buf[i+1]=='i'&&buf[i+2]=='l'&&buf[i+3]=='e') sawfile = 1;
            }
            if (havp) { sys_fdclose(p[0]); sys_fdclose(p[1]); }
            if (ff >= 3) sys_fdclose(ff);
            int ok = (havp && ff >= 3 && sawpipe && sawfile);
            print(ok ? "/proc/self/fd: lists open pipe + file fds OK\n" : "procfdtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "filewrtest")) {   /* write/append file fds (M1195) */
            int ok = 1;
            int fd = sys_open_mode("/tmp/fw.txt", O_WRONLY | O_CREAT | O_TRUNC);
            if (fd < 3) ok = 0;
            else {
                sys_fdwrite(fd, "Hello World", 11);            /* "Hello World" */
                sys_lseek(fd, 6, SEEK_SET);                    /* seek into the middle */
                sys_fdwrite(fd, "There", 5);                   /* positioned overwrite -> "Hello There" */
                sys_fdclose(fd);
                int af = sys_open_mode("/tmp/fw.txt", O_WRONLY | O_APPEND);   /* reopen for append */
                if (af < 3) ok = 0;
                else { sys_fdwrite(af, "!", 1); sys_fdclose(af); }            /* -> "Hello There!" */
                char b[32]; long n = sys_readfile("/tmp/fw.txt", b, sizeof b - 1);
                if (n < 0) n = 0; b[n] = 0;
                if (!(n == 12 && streq(b, "Hello There!"))) ok = 0;
            }
            print(ok ? "file-wr: open(WR|CREAT|TRUNC) + positioned overwrite + O_APPEND all OK\n"
                     : "filewrtest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
        } else if (streq(line, "rlimittest")) {   /* RLIMIT_NPROC: cap forks — fork-bomb protection (M1163) */
            struct rlimit rl; sys_getrlimit(RLIMIT_NPROC, &rl);
            print("RLIMIT_NPROC default: "); print(rl.rlim_cur == RLIM_INFINITY ? "infinity\n" : "(limited)\n");
            rl.rlim_cur = 1; rl.rlim_max = 1; sys_setrlimit(RLIMIT_NPROC, &rl);   /* allow 1 live child */
            long c1 = sys_fork();
            if (c1 == 0) { sys_sleep(700); sys_exit(0); }   /* child #1: stay alive while the parent forks again */
            long c2 = sys_fork();                            /* 1 live child >= limit 1 -> must be denied */
            if (c2 == 0) { sys_exit(0); }
            int st = 0;
            if (c1 > 0) sys_waitpid((int)c1, &st);
            if (c2 > 0) sys_waitpid((int)c2, &st);           /* clean up if it was wrongly allowed */
            print("set NPROC=1: fork #1 "); print(c1 > 0 ? "ok" : "FAILED"); print(", fork #2 ");
            print(c2 < 0 ? "DENIED" : "WRONGLY ALLOWED"); print("\n");
            int ok = (c1 > 0 && c2 < 0);
            print(ok ? "RLIMIT_NPROC: 2nd fork capped (fork-bomb protection) OK\n" : "rlimittest: VERIFY FAILED\n");
            if (!ok) g_status = 1;
            rl.rlim_cur = RLIM_INFINITY; rl.rlim_max = RLIM_INFINITY; sys_setrlimit(RLIMIT_NPROC, &rl);   /* restore */
            /* RLIMIT_AS: cap mmap address space (in-process toggle — mmap can't break the shell's heap) */
            rl.rlim_cur = 4096; rl.rlim_max = 4096; sys_setrlimit(RLIMIT_AS, &rl);
            void *as1 = sys_mmap(64 * 1024);                 /* 64 KiB > 4 KiB limit -> denied */
            rl.rlim_cur = RLIM_INFINITY; rl.rlim_max = RLIM_INFINITY; sys_setrlimit(RLIMIT_AS, &rl);
            void *as2 = sys_mmap(64 * 1024);                 /* unlimited -> allowed */
            int as_ok = (as1 == 0 && as2 != 0);
            if (as2) sys_munmap(as2, 64 * 1024);
            print(as_ok ? "RLIMIT_AS: mmap denied over limit, allowed unlimited OK\n" : "RLIMIT_AS: VERIFY FAILED\n");
            if (!as_ok) g_status = 1;
            /* RLIMIT_DATA: cap the heap — done in a CHILD so the shell's own heap is untouched */
            long dc = sys_fork();
            if (dc == 0) {
                struct rlimit dl; dl.rlim_cur = 4096; dl.rlim_max = 4096; sys_setrlimit(RLIMIT_DATA, &dl);
                void *big = malloc(1 << 20);                 /* 1 MiB needs sbrk past 4 KiB -> capped -> NULL */
                sys_exit(big == 0 ? 0 : 1);                  /* 0 = correctly denied */
            } else if (dc > 0) {
                int dst = -1; sys_waitpid((int)dc, &dst);
                print(dst == 0 ? "RLIMIT_DATA: heap growth capped (malloc failed in child) OK\n" : "RLIMIT_DATA: VERIFY FAILED\n");
                if (dst != 0) g_status = 1;
            }
            /* RLIMIT_NOFILE (M1547): cap open fds — a CHILD again, so the shell's
             * own fd table is untouched. limit=4 (beyond stdio) fits exactly 2
             * pipes (each needs 2 slots); a 3rd pipe must be denied. */
            long fc = sys_fork();
            if (fc == 0) {
                struct rlimit fl; fl.rlim_cur = 4; fl.rlim_max = 4; sys_setrlimit(RLIMIT_NOFILE, &fl);
                int pfds[8][2]; int opened = 0;
                for (int i = 0; i < 8; i++) { if (sys_pipe(pfds[i]) != 0) break; opened++; }
                sys_exit(opened == 2 ? 0 : 1);           /* 0 = correctly capped at exactly 2 pipes (4 fds) */
            } else if (fc > 0) {
                int fst = -1; sys_waitpid((int)fc, &fst);
                print(fst == 0 ? "RLIMIT_NOFILE: fd allocation capped (3rd pipe denied past the limit) OK\n" : "RLIMIT_NOFILE: VERIFY FAILED\n");
                if (fst != 0) g_status = 1;
            }
            /* RLIMIT_CPU (M1548): cap CPU time -- a CHILD again. Its own
             * utime_ms/stime_ms is BSP-tick-sampled (the same basis getrusage
             * already uses), so a generous wall-clock safety cap (not a tight
             * one) absorbs however long it takes to actually land enough
             * ticks on the BSP core across a real multi-core scheduler. */
            long xc = sys_fork();
            if (xc == 0) {
                sys_signal(25 /* SIGXCPU */, sh_xcpu_handler);
                struct rlimit xl; xl.rlim_cur = 1; xl.rlim_max = 1; sys_setrlimit(RLIMIT_CPU, &xl);   /* 1 CPU-second */
                long start = sys_uptime_ms();
                while (!g_xcpu_fired && sys_uptime_ms() - start < 8000) { }   /* burn CPU; generous wall-clock cap */
                sys_exit(g_xcpu_fired ? 0 : 1);
            } else if (xc > 0) {
                int xst = -1; sys_waitpid((int)xc, &xst);
                print(xst == 0 ? "RLIMIT_CPU: SIGXCPU delivered once CPU time exceeded the limit OK\n" : "RLIMIT_CPU: VERIFY FAILED\n");
                if (xst != 0) g_status = 1;
            }
            /* RLIMIT_FSIZE (M1549): cap max file size -- a CHILD again, so no
             * shared fd/file state with the shell. A 4-byte limit: writing
             * exactly up to it must succeed, one more byte must be denied
             * AND raise SIGXFSZ (opt-in, like every signal here). */
            long fz = sys_fork();
            if (fz == 0) {
                sys_signal(26 /* SIGXFSZ */, sh_xfsz_handler);
                int wf = sys_open_mode("/tmp/fsizetest.txt", O_WRONLY | O_CREAT | O_TRUNC);
                if (wf < 3) sys_exit(1);
                struct rlimit fzl; fzl.rlim_cur = 4; fzl.rlim_max = 4; sys_setrlimit(RLIMIT_FSIZE, &fzl);
                long w1 = sys_fdwrite(wf, "abcd", 4);   /* exactly at the limit -> allowed */
                long w2 = sys_fdwrite(wf, "e", 1);      /* one more byte -> denied + SIGXFSZ */
                sys_fdclose(wf);
                sys_exit((w1 == 4 && w2 < 0 && g_xfsz_fired) ? 0 : 1);
            } else if (fz > 0) {
                int fzst = -1; sys_waitpid((int)fz, &fzst);
                print(fzst == 0 ? "RLIMIT_FSIZE: write denied + SIGXFSZ delivered past the limit OK\n" : "RLIMIT_FSIZE: VERIFY FAILED\n");
                if (fzst != 0) g_status = 1;
            }
            /* RLIMIT_CORE (M1551): cap core-dump size. Baseline first (no
             * rlim_core set -> just the existing CORE_MAX ceiling), then a
             * capped run at half that size -- proving the cap actually
             * shrinks the written dump, without hardcoding a specific byte
             * count that would drift if app_core_dump's fixed overhead
             * (ELF header + PT_NOTE) ever changes. Each child deliberately
             * NULL-derefs (same technique as user/crash.c) to trigger the
             * kernel's fault handler, which writes /tmp/core. */
            long crf1 = sys_fork();
            if (crf1 == 0) { volatile int *p = (volatile int *)0; *p = 0x1234; sys_exit(1); }
            if (crf1 > 0) { int crst1 = -1; sys_waitpid((int)crf1, &crst1); }
            struct statx crst_a; long sz_full = (sys_statx("/tmp/core", &crst_a) == 0) ? (long)crst_a.stx_size : -1;
            long crf2 = sys_fork();
            if (crf2 == 0) {
                struct rlimit crl; crl.rlim_cur = (uint64_t)(sz_full / 2); crl.rlim_max = crl.rlim_cur;
                sys_setrlimit(RLIMIT_CORE, &crl);
                volatile int *p = (volatile int *)0; *p = 0x1234;
                sys_exit(1);
            }
            if (crf2 > 0) { int crst2 = -1; sys_waitpid((int)crf2, &crst2); }
            struct statx crst_b; long sz_capped = (sys_statx("/tmp/core", &crst_b) == 0) ? (long)crst_b.stx_size : -1;
            print("RLIMIT_CORE: uncapped core="); printl(sz_full); print(" bytes, capped (limit=");
            printl(sz_full / 2); print(") core="); printl(sz_capped); print(" bytes\n");
            int cr_ok = (sz_full > 0 && sz_capped > 0 && sz_capped <= sz_full / 2);
            print(cr_ok ? "RLIMIT_CORE: core dump shrunk to fit the cap OK\n" : "RLIMIT_CORE: VERIFY FAILED\n");
            if (!cr_ok) g_status = 1;
        } else if (streq(line, "hugetest")) {   /* 2 MiB hugepage: ONE fault maps all 512 pages (M1155) */
            unsigned long len = 2 * 1024 * 1024;            /* one 2 MiB huge page */
            unsigned char *m = (unsigned char *)sys_mmap_huge(len);
            if (!m) { perr("hugetest: mmap_huge failed (need 2 MiB contiguous RAM)\n"); g_status = 1; }
            else {
                struct rusage ra, rb;
                sys_getrusage(RUSAGE_SELF, &ra);
                for (unsigned long i = 0; i < len; i += 4096) m[i] = (unsigned char)((i >> 12) & 0xFF);  /* touch all 512 pages */
                sys_getrusage(RUSAGE_SELF, &rb);
                int ok = 1;
                for (unsigned long i = 0; i < len; i += 4096) if (m[i] != (unsigned char)((i >> 12) & 0xFF)) { ok = 0; break; }
                long faults = rb.ru_minflt - ra.ru_minflt;
                int aligned = (((unsigned long)m & (len - 1)) == 0);   /* a hugepage base must be 2 MiB-aligned */
                print("touched 512 pages of a 2 MiB hugepage; minor faults: "); printl(faults); print(" (expect ~1, not 512)\n");
                print(aligned ? "  base is 2 MiB-aligned: yes\n" : "  base is 2 MiB-aligned: NO\n");
                int good = (ok && aligned && faults <= 2);
                print(good ? "hugepage: a single fault mapped all 512 pages (one PD entry) OK\n" : "hugepage: VERIFY FAILED\n");
                if (!good) g_status = 1;
                sys_munmap(m, len);
            }
        } else if (streq(line, "swaptest")) {  /* zram: compress pages into RAM, fault back in intact (M1156) */
            unsigned long len = 256 * 1024;       /* 64 pages */
            unsigned char *m = (unsigned char *)sys_mmap(len);
            if (!m) { perr("swaptest: mmap failed\n"); g_status = 1; }
            else {
                for (unsigned long i = 0; i < len; i++) m[i] = (unsigned char)((i / 64) & 0x0F);   /* compressible: long byte-runs */
                long out = sys_swapout(m, len);
                if (out < 0) { perr("swaptest: swapout failed\n"); g_status = 1; }
                else {
                    print("paged out "); printl(out); print(" pages to zram (compressed RAM)\n");
                    long n; char *b = slurp("/proc/swaps", &n);   /* read stats AT PEAK (before fault-in releases slots) */
                    if (b && n > 0) { b[n] = 0; print(b); free(b); }
                    int ok = 1;                    /* re-touch each page -> faults back in (decompressed) */
                    for (unsigned long i = 0; i < len; i++) if (m[i] != (unsigned char)((i / 64) & 0x0F)) { ok = 0; break; }
                    print(ok ? "every page survived the zram round-trip OK\n"
                             : "VERIFY FAILED: data corrupted across swap\n");
                    if (!ok) g_status = 1;
                }
                sys_munmap(m, len);
            }
        } else if (streq(line, "shmtest")) {  /* demonstrate named shared memory: two mappings, one backing */
            char *a = (char *)sys_shm_open("demo", 4096);
            char *b = (char *)sys_shm_open("demo", 4096);   /* second mapping of the same named object */
            if (!a || !b) { perr("shmtest: shm_open failed\n"); g_status = 1; }
            else if (a == b) { print("shmtest: expected two distinct mappings\n"); g_status = 1; }
            else {
                a[0] = 'S'; a[1] = 'H'; a[2] = 'M'; a[3] = '!'; a[4] = 0;   /* write through mapping A */
                int shared = (b[0] == 'S' && b[1] == 'H' && b[2] == 'M' && b[3] == '!');   /* read through mapping B */
                print("shm_open(\"demo\") twice -> two VAs ("); printl((long)(a != b)); print(" distinct); ");
                print(shared ? "wrote 'SHM!' via A, read it via B -> they share one backing\n"
                             : "VERIFY FAILED: mappings are not shared\n");
                if (!shared) g_status = 1;
                /* shm_unlink (M1590): frees the name without disturbing a's/b's
                 * already-open mapping; a fresh open of the SAME name afterward is a
                 * genuinely new, zeroed object, not the stale 'SHM!' data */
                int ok2 = (sys_shm_unlink("demo") == 0);
                if (a[0] != 'S') ok2 = 0;                        /* the already-open mapping is unaffected */
                char *fresh = (char *)sys_shm_open("demo", 4096);
                if (!fresh || fresh[0] != 0) ok2 = 0;             /* new object -> zeroed, not 'SHM!' */
                if (sys_shm_unlink("demo") != 0) ok2 = 0;
                if (sys_shm_unlink("no-such-shm-object") != -1) ok2 = 0;   /* unlinking an absent name -> -1 */
                /* the real bug this closes (M1576's own documented gap): exhaust all 8
                 * named-shm slots with distinct names, confirm a 9th genuinely fails,
                 * unlink all 8, then confirm the table is NOT permanently exhausted */
                char nm[4] = { 'X', '0', 0, 0 };
                int exok = 1;
                for (int i = 0; i < 8; i++) { nm[1] = (char)('0' + i); if (!sys_shm_open(nm, 4096)) { exok = 0; break; } }
                if (sys_shm_open("X9", 4096) != 0) exok = 0;      /* table genuinely full -> the 9th distinct name fails */
                for (int i = 0; i < 8; i++) { nm[1] = (char)('0' + i); if (sys_shm_unlink(nm) != 0) exok = 0; }
                void *reopen9 = sys_shm_open("X9", 4096);         /* slots freed -> a 9th distinct name succeeds now */
                if (!reopen9) exok = 0;
                if (reopen9) sys_shm_unlink("X9");
                ok2 = ok2 && exok;
                print(ok2 ? "shm_unlink: frees the name (live mapping unaffected, reopen is a fresh zeroed object); "
                            "exhaust+unlink+reopen all 8 slots -- OK\n"
                          : "shmtest: shm_unlink VERIFY FAILED\n");
                if (!ok2) g_status = 1;
            }
        } else if (streq(line, "alarmtest")) {  /* demonstrate SIGALRM: a periodic timer signal to a ring-3 handler */
            g_alarm_fires = 0;
            sys_signal(14 /* SIGALRM */, sh_alarm_handler);
            sys_alarm(20);                       /* fire every 20 ticks = 200ms at 100Hz */
            print("armed SIGALRM every 200ms; spinning ~1s...\n");
            long start = sys_uptime_ms();
            while (sys_uptime_ms() - start < 1000) { }   /* busy ~1s; the alarm fires via the async-signal path */
            sys_alarm(0);                        /* disarm */
            print("SIGALRM fired "); printl(g_alarm_fires); print(" times in ~1s (expected ~5)\n");
            if (g_alarm_fires < 3 || g_alarm_fires > 7) g_status = 1;
        } else if (streq(line, "setitimertest")) {   /* setitimer/getitimer(ITIMER_REAL): delay independent of interval, one-shot (M1565) */
            int ok = 1;
            sys_signal(14 /* SIGALRM */, sh_alarm_handler);

            /* one-shot (interval=0): fires exactly once, never refires -- the real risk
             * this milestone fixed in app_alarm_tick (a naive alarm_next+=0 would have
             * kept re-firing on every subsequent tick forever). */
            g_alarm_fires = 0;
            sys_setitimer(15, 0);                        /* delay 150ms, one-shot */
            long start = sys_uptime_ms();
            while (sys_uptime_ms() - start < 500) { }    /* spin well past the delay */
            sys_setitimer(0, 0);
            int oneshot_ok = (g_alarm_fires == 1);

            /* independent delay+interval: alarm()'s own always-equal shape could never
             * produce this -- first fire ~100ms, second ~400ms (100+300), not ~200ms. */
            g_alarm_fires = 0;
            sys_setitimer(10, 30);                       /* delay 100ms, then every 300ms */
            unsigned long remain0 = 0, interval0 = 0;
            sys_getitimer(&remain0, &interval0);
            long t0 = sys_uptime_ms();
            long fire1_ms = -1, fire2_ms = -1;
            while (sys_uptime_ms() - t0 < 500) {
                if (g_alarm_fires >= 1 && fire1_ms < 0) fire1_ms = sys_uptime_ms() - t0;
                if (g_alarm_fires >= 2 && fire2_ms < 0) fire2_ms = sys_uptime_ms() - t0;
            }
            sys_setitimer(0, 0);
            int getitimer_ok = (interval0 == 30 && remain0 > 0 && remain0 <= 10);
            int timing_ok = (fire1_ms >= 50 && fire1_ms <= 200) && (fire2_ms >= 300 && fire2_ms <= 500);
            ok = oneshot_ok && getitimer_ok && timing_ok;

            print("setitimer: one-shot fires exactly once, delay+interval independent (fire1~");
            printl((int)fire1_ms); print("ms fire2~"); printl((int)fire2_ms); print("ms, not ~200ms) -- ");
            sys_setcolor(ok ? 10 : 4); print(ok ? "OK\n" : "VERIFY FAILED\n"); sys_setcolor(0);
            if (!ok) g_status = 1;
        } else if (streq(line, "clockgt")) {  /* read the clock via the vDSO time page — NO syscall (M1111) */
            struct timespec a, b, r;
            clock_gettime(CLOCK_MONOTONIC, &a);
            clock_gettime(CLOCK_REALTIME,  &r);
            print("clock_gettime via the vDSO page @ 0x80000000 (read straight from RAM, no syscall):\n");
            long ms = a.tv_nsec / 1000000;
            print("  MONOTONIC: "); printl(a.tv_sec); print(".");
            if (ms < 100) print("0"); if (ms < 10) print("0"); printl(ms);
            print(" s since boot\n");
            print("  REALTIME : "); printl(r.tv_sec); print(" Unix s (UTC) -- compare 'date'\n");
            long start = sys_uptime_ms();
            while (sys_uptime_ms() - start < 300) { }     /* let ~300ms pass (delay only; the clock reads below are syscall-free) */
            clock_gettime(CLOCK_MONOTONIC, &b);
            long dms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
            print("  re-read MONOTONIC after ~300ms: advanced "); printl(dms); print(" ms\n");
            if (dms < 150 || dms > 600 || r.tv_sec < 1700000000L) g_status = 1;
        } else if (streq(line, "wss") || startswith(line, "wss ")) {  /* working-set size from the CPU's Accessed/Dirty PTE bits (/proc/<pid>/wss) */
            const char *who = "self"; int self = 1;
            if (startswith(line, "wss ")) { const char *a = line + 4; while (*a == ' ') a++; if (*a) { who = a; self = 0; } }
            char path[48]; int p = 0;
            const char *pre = "/proc/"; for (int i = 0; pre[i]; i++) path[p++] = pre[i];
            for (int i = 0; who[i] && who[i] != ' ' && p < 42; i++) path[p++] = who[i];
            const char *suf = "/wss"; for (int i = 0; suf[i]; i++) path[p++] = suf[i];
            path[p] = 0;
            long n; char *buf = slurp(path, &n);
            if (!buf) { print("wss: no such pid (try 'ps')\n"); g_status = 1; }
            else {
                print(buf); free(buf);
                if (self) {   /* prove the window reset: clear the Accessed bits, then re-read — Referenced collapses to the few pages touched since */
                    sys_writefile("/proc/self/ctl", "clearref", 8);
                    print("-- clearref: cleared Accessed bits; re-reading after minimal activity --\n");
                    long n2; char *b2 = slurp(path, &n2);
                    if (b2) { print(b2); free(b2); }
                }
            }
        } else if (streq(line, "ringtest")) {  /* demonstrate a magic mirrored ring buffer (one frame, two VAs) */
            unsigned long n = 4096;
            char *r = (char *)sys_ringbuf(n);
            if (!r) { perr("ringtest: ringbuf failed\n"); g_status = 1; }
            else {
                /* write "MAGIC" straddling the end: 'MAG' at [n-3,n), 'IC' lands at [n,n+2) -> the mirror of [0,2) */
                r[n-3]='M'; r[n-2]='A'; r[n-1]='G'; r[n]='I'; r[n+1]='C';
                char cont[6]; for (int i = 0; i < 5; i++) cont[i] = r[n-3+i]; cont[5] = 0;   /* contiguous read across the wrap */
                char wrap[3]; wrap[0] = r[0]; wrap[1] = r[1]; wrap[2] = 0;                   /* offset 0 = the mirrored tail */
                print("ring buffer "); printl((long)n); print(" bytes, frame mapped at TWO VAs:\n");
                print("  wrote 'MAGIC' across the end; contiguous read at the wrap = '"); print(cont); print("'\n");
                print("  reading offset 0 = '"); print(wrap); print("' (the wrapped tail, via the mirror)\n");
                print(streq(cont, "MAGIC") && streq(wrap, "IC") ? "  OK: no split, the mirror aliases the same frame\n" : "  VERIFY FAILED\n");
                if (!(streq(cont, "MAGIC") && streq(wrap, "IC"))) g_status = 1;
                sys_munmap(r, n);
            }
        } else if (streq(line, "jittest")) {   /* W^X/JIT: write machine code into a page, mprotect r-x, run it */
            unsigned char *code = (unsigned char *)sys_mmap(4096);
            if (!code) { perr("jittest: mmap failed\n"); g_status = 1; }
            else {
                static const unsigned char prog[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };  /* mov eax,42 ; ret */
                for (int i = 0; i < (int)sizeof prog; i++) code[i] = prog[i];
                int pr = sys_mprotect(code, 4096, 1 | 4);     /* PROT_READ|PROT_EXEC: drop write, allow execute */
                union { unsigned char *p; int (*fn)(void); } u; u.p = code;   /* call the freshly-written code */
                int r = u.fn();
                print("JIT: wrote 'mov eax,42; ret' to an mmap page, mprotect r-x (rc "); printl(pr);
                print("), called it -> "); printl(r); print("\n");
                if (r == 42) { sys_setcolor(9); print("  OK: executed JIT-compiled code from a W^X page\n"); }
                else { sys_setcolor(2); print("  VERIFY FAILED\n"); }
                sys_setcolor(0);
                if (r != 42) g_status = 1;
                sys_munmap(code, 4096);
            }
        } else if (streq(line, "sigtest")) {   /* demonstrate real signals: install a handler, raise it, resume */
            sys_signal(10, sig_demo_handler);
            print("sigtest: raising signal 10 to self...\n");
            sys_raise(10);
            print("sigtest: main resumed after the handler returned (sigreturn OK)\n");
        } else if (streq(line, "sigmasktest")) {   /* sigprocmask: a blocked signal stays pending, then delivers on unblock (M1208) */
            g_sigmask_got = 0;
            sys_signal(10, sigmask_handler);
            sys_sigprocmask(SIG_BLOCK, 1u << 10);       /* block signal 10 */
            sys_raise(10);                              /* raise it -> pending, but blocked (handler must NOT run) */
            sys_sleep(60);                              /* timer ticks fire app_deliver_pending; blocked -> skipped */
            int blocked_ok = (g_sigmask_got == 0);
            int pending_ok = (sys_sigpending() & (1u << 10)) != 0;   /* sigpending sees it queued (M1209) */
            sys_sigprocmask(SIG_UNBLOCK, 1u << 10);     /* unblock -> the pending signal now delivers */
            for (int i = 0; i < 20 && !g_sigmask_got; i++) sys_sleep(20);   /* let a tick deliver it */
            int delivered_ok = (g_sigmask_got == 1);
            if (blocked_ok && pending_ok && delivered_ok)
                print("sigprocmask: blocked signal stays pending (sigpending sees it, handler NOT run), then delivered on unblock -- OK\n");
            else { print("sigprocmask: FAILED\n"); g_status = 1; }
        } else if (streq(line, "scores")) {
            /* a personal leaderboard: the best each game saved to its *.HI file */
            static const struct { const char *name, *file; } hs[] = {
                {"Snake","SNAKE.HI"},{"Tetris","TETRIS.HI"},{"Breakout","BREAKOUT.HI"},
                {"2048","2048.HI"},{"Minesweeper","MINES.HI"},{"Flappy","FLAPPY.HI"},
                {"Space Invaders","SPACEINV.HI"},{"Frogger","FROGGER.HI"},{"15-Puzzle","FIFTEEN.HI"},
                {"Maze","MAZE.HI"},{"Simon","SIMON.HI"},{"Blackjack","BJ.HI"},
                {"Typing","TYPING.HI"},{"Yahtzee","YAHTZEE.HI"},{"Video Poker","VPOKER.HI"},
                {"Pac-Man","PACMAN.HI"},
            };
            print("High scores (your bests):\n");
            int any = 0;
            for (int i = 0; i < (int)(sizeof(hs)/sizeof(hs[0])); i++) {
                long n; char *b = slurp(hs[i].file, &n);
                if (b && n > 0) {
                    int j = 0; while (j < n && b[j] >= '0' && b[j] <= '9') j++; b[j] = 0;
                    if (j > 0) { print("  "); print(hs[i].name); print(": "); print(b); print("\n"); any = 1; }
                }
                if (b) free(b);
            }
            if (!any) print("  (none yet - go set some!)\n");
        } else if (streq(line, "screenshot") || startswith(line, "screenshot ")) {
            char *fn = line + 10; while (*fn == ' ') fn++;   /* optional filename arg */
            sh_unprot_buf(fn);                                /* quoted filename (e.g. screenshot "my shot.bmp") */
            if (!*fn) fn = "SHOT.BMP";
            if (sys_screenshot(fn) < 0) print("screenshot: failed\n");
            else { print("saved screen to "); print(fn); print("\n"); }
        } else if (streq(line, "wallpaper") || startswith(line, "wallpaper ")) {
            char *fn = line + 9; while (*fn == ' ') fn++;     /* image file to set as the desktop background */
            sh_unprot_buf(fn);                                /* quoted filename (e.g. wallpaper "my pic.png") */
            if (!*fn) print("usage: wallpaper <file>\n");
            else if (sys_setwall(fn) < 0) { print("wallpaper: cannot load "); print(fn); print("\n"); }
            else { print("wallpaper set to "); print(fn); print("\n"); }
        } else if (streq(line, "mem")) {
            char buf[128];
            sys_sysinfo(buf, sizeof(buf));
            print(buf);
        } else if (streq(line, "uptime")) {     /* up Dd Hh Mm Ss + the 1/5/15-min load average */
            long n; char *u = slurp("/proc/uptime", &n);
            long secs = 0;
            if (u) { for (int i = 0; u[i] && u[i] != '.' && u[i] != ' '; i++) if (u[i] >= '0' && u[i] <= '9') secs = secs * 10 + (u[i] - '0'); free(u); }
            long d = secs / 86400, h = (secs % 86400) / 3600, m = (secs % 3600) / 60, s = secs % 60;
            print("up "); sys_setcolor(4);                       /* duration in cyan (M1316) */
            if (d) { printl(d); print("d "); }
            printl(h); print("h "); printl(m); print("m "); printl(s); print("s");
            sys_setcolor(0);
            char *la = slurp("/proc/loadavg", &n);
            if (la) {
                print(",  load average: "); sys_setcolor(3);     /* load values in yellow */
                int fld = 0;
                for (int i = 0; la[i] && fld < 3; i++) {
                    if (la[i] == ' ') { fld++; if (fld < 3) print(", "); }
                    else { char c[2] = { la[i], 0 }; print(c); }
                }
                sys_setcolor(0);
                free(la);
            }
            print("\n");
        } else if (streq(line, "uname") || startswith(line, "uname ")) {   /* system identity (uname(2)) */
            struct utsname u;
            if (sys_uname(&u) == 0) {
                if (streq(line, "uname")) { print(u.sysname); print("\n"); }   /* bare: kernel name */
                else { print(u.sysname); print(" "); print(u.nodename); print(" "); print(u.release);
                       print(" "); print(u.version); print(" "); print(u.machine); print("\n"); }   /* -a: all fields */
            } else { print("uname: failed\n"); g_status = 1; }
        } else if (streq(line, "whoami")) {
            print("root\n");                                  /* single-user: uid 0 */
        } else if (streq(line, "hostname")) {
            char h[64]; if (sys_gethostname(h, sizeof h) == 0) { print(h); print("\n"); }
        } else if (startswith(line, "hostname ")) {
            const char *p = line + 9; while (*p == ' ') p++;
            char nm[64]; int i = 0; while (*p && *p != ' ' && i < 63) nm[i++] = *p++; nm[i] = 0; sh_unprot_buf(nm);
            if (i > 0 && sys_sethostname(nm, (unsigned long)i) == 0) { print("hostname set to "); print(nm); print("\n"); }
            else { print("usage: hostname [NAME]\n"); g_status = 1; }
        } else if (streq(line, "free")) {       /* memory summary (kB), parsed from /proc/meminfo */
            long n; char *m = slurp("/proc/meminfo", &n);
            long v[3] = { 0, 0, 0 }; int vi = 0;            /* MemTotal, MemFree, MemUsed (gen_meminfo order) */
            if (m) {
                for (int i = 0; m[i] && vi < 3; ) {
                    if (m[i] == ':') { i++; while (m[i] == ' ') i++; long x = 0; while (m[i] >= '0' && m[i] <= '9') x = x * 10 + (m[i++] - '0'); v[vi++] = x; }
                    else i++;
                }
                free(m);
            }
            print("Mem:  total "); printl(v[0]); print(" kB,  used "); sys_setcolor(7); printl(v[2]); sys_setcolor(0); print(" kB,  free "); sys_setcolor(9); printl(v[1]); sys_setcolor(0); print(" kB\n");   /* used amber, free lime (M1316) */
            print_usage_bar(v[2], v[0]);                    /* matching memory-usage bar (M1331) */
        } else if (streq(line, "neofetch") || streq(line, "screenfetch")) {
            /* a colourful system summary: ASCII monitor logo + live stats +
             * palette swatches -- reuses uname / /proc / hostname (M1329) */
            struct utsname u; int have_u = (sys_uname(&u) == 0);
            char hn[64]; if (sys_gethostname(hn, sizeof hn) != 0 || !hn[0]) scpy(hn, "osdev");
            long n, secs = 0;
            { char *up = slurp("/proc/uptime", &n);
              if (up) { for (int i = 0; up[i] && up[i] != '.' && up[i] != ' '; i++)
                            if (up[i] >= '0' && up[i] <= '9') secs = secs * 10 + (up[i] - '0');
                        free(up); } }
            long ud = secs / 86400, uh = (secs % 86400) / 3600, um = (secs % 3600) / 60;
            long mt = 0, mu = 0;
            { char *m = slurp("/proc/meminfo", &n); long v[3] = { 0, 0, 0 }; int vi = 0;
              if (m) { for (int i = 0; m[i] && vi < 3; ) {
                           if (m[i] == ':') { i++; while (m[i] == ' ') i++; long x = 0;
                               while (m[i] >= '0' && m[i] <= '9') x = x * 10 + (m[i++] - '0'); v[vi++] = x; }
                           else i++; }
                       free(m); }
              mt = v[0] / 1024; mu = v[2] / 1024; }
            int cores = 0;                                   /* core count from /proc/cpuinfo "processors:" (M1340) */
            { char *ci = slurp("/proc/cpuinfo", &n);
              if (ci) { for (int i = 0; ci[i]; i++) if (ci[i] == ':') { int j = i + 1; while (ci[j] == ' ' || ci[j] == '\t') j++;
                            while (ci[j] >= '0' && ci[j] <= '9') cores = cores * 10 + (ci[j++] - '0'); break; }
                        free(ci); } }
            long dfree = 0, dtot = 0;                         /* disk free/total (KiB) from sys_df */
            { char db[96]; long dn = sys_df(db, sizeof db);
              if (dn > 0) { db[dn] = 0; int i = 0;
                  while (db[i] && !(db[i] >= '0' && db[i] <= '9')) i++;
                  while (db[i] >= '0' && db[i] <= '9') dfree = dfree * 10 + (db[i++] - '0');
                  while (db[i] && !(db[i] >= '0' && db[i] <= '9')) i++;
                  while (db[i] >= '0' && db[i] <= '9') dtot = dtot * 10 + (db[i++] - '0'); } }
            long dused = dtot > dfree ? dtot - dfree : 0;
            /* monitor logo: blue frame (6), cyan label (4) */
            sys_setcolor(6); print("    .--------------.\n");
            print("    |   "); sys_setcolor(4); print("OS-DEV"); sys_setcolor(6); print("     |\n");
            print("    |   "); sys_setcolor(4); print("x86_64"); sys_setcolor(6); print("     |\n");
            print("    '--------------'\n");
            print("       |______|\n"); sys_setcolor(0); print("\n");
            /* stats: cyan labels, amber memory, host highlighted */
            print("  "); sys_setcolor(3); print("root"); sys_setcolor(8); print("@");
            sys_setcolor(4); print(hn); sys_setcolor(0); print("\n");
            print("  "); sys_setcolor(4); print("OS:      "); sys_setcolor(0); print("OS-DEV x86_64\n");
            print("  "); sys_setcolor(4); print("Kernel:  "); sys_setcolor(0);
            if (have_u) { print(u.release); print(" "); print(u.version); } else print("1.0");
            print("\n");
            print("  "); sys_setcolor(4); print("CPU:     "); sys_setcolor(0); print("x86_64");
            if (cores > 0) { print(" ("); printl(cores); print(cores == 1 ? " core)" : " cores)"); } print("\n");
            print("  "); sys_setcolor(4); print("Uptime:  "); sys_setcolor(0);
            if (ud) { printl(ud); print("d "); } printl(uh); print("h "); printl(um); print("m\n");
            print("  "); sys_setcolor(4); print("Shell:   "); sys_setcolor(0); print("osdev-sh\n");
            print("  "); sys_setcolor(4); print("Memory:  "); sys_setcolor(0);
            sys_setcolor(7); printl(mu); sys_setcolor(0); print(" / "); printl(mt); print(" MB\n");
            print("  "); sys_setcolor(4); print("Disk:    "); sys_setcolor(0);
            sys_setcolor(7); printl(dused / 1024); sys_setcolor(0); print(" / "); printl(dtot / 1024); print(" MB\n");
            print("  "); sys_setcolor(4); print("Term:    "); sys_setcolor(0); print("44x17\n  ");
            /* palette swatches (white/red/yellow/cyan/magenta/blue/orange/grey/lime);
             * the console font is ASCII-only, so use '#' blocks rather than U+2588 */
            for (int c = 1; c <= 9; c++) { sys_setcolor(c); print("###"); }
            sys_setcolor(0); print("\n");
        } else if (streq(line, "id")) {
            print("uid=0(root) gid=0(root)\n");             /* single-user */
        } else if (streq(line, "clear")) {
            sys_clear();
        } else if (streq(line, "reboot")) {
            print("rebooting...\n");
            sys_reboot();
        } else if (streq(line, "poweroff") || streq(line, "shutdown") || streq(line, "halt")) {
            print("powering off...\n");
            sys_poweroff();
        } else if (startswith(line, "kill ")) {            /* kill <pid> : ask that app to close (see ps for pids) */
            const char *p = line + 5; while (*p == ' ') p++;
            int pid = 0; while (*p >= '0' && *p <= '9') pid = pid * 10 + (*p++ - '0');
            if (pid <= 0) { print("usage: kill <pid>   (run 'ps' for pids)\n"); g_status = 2; }
            else if (sys_kill(pid) == 0) { print("asked pid "); printl(pid); print(" to close\n"); }
            else { print("kill: no such process: "); printl(pid); print("\n"); g_status = 1; }
        } else if (streq(line, "cal")) {
            cmd_cal();
        } else if (startswith(line, "cal ")) {         /* cal <month> <year>, or cal -y <year> for the whole year */
            const char *p = line + 4; while (*p == ' ') p++;
            if (p[0] == '-' && p[1] == 'y') {
                p += 2; while (*p == ' ') p++;
                int y = 0; while (*p >= '0' && *p <= '9') { if (y < 1000000) y = y*10 + (*p - '0'); p++; }
                if (y < 1 || y > 9999) print("usage: cal -y <year>\n");
                else for (int mm = 1; mm <= 12; mm++) cmd_cal_ym(y, mm, 0);    /* the full year, month by month */
            } else if (p[0] == '-' && p[1] == '3') {      /* cal -3 : previous, current, next month */
                char t[24]; sys_time(t, sizeof(t));
                int y = (t[0]-'0')*1000 + (t[1]-'0')*100 + (t[2]-'0')*10 + (t[3]-'0');
                int m = (t[5]-'0')*10 + (t[6]-'0'), today = (t[8]-'0')*10 + (t[9]-'0');
                int pm = m-1, py = y; if (pm < 1) { pm = 12; py--; }
                int nm = m+1, ny = y; if (nm > 12) { nm = 1; ny++; }
                cmd_cal_ym(py, pm, 0); cmd_cal_ym(y, m, today); cmd_cal_ym(ny, nm, 0);
            } else {
                int m = 0, y = 0;
                while (*p >= '0' && *p <= '9') { if (m < 1000000) m = m*10 + (*p - '0'); p++; }
                while (*p == ' ') p++;
                while (*p >= '0' && *p <= '9') { if (y < 1000000) y = y*10 + (*p - '0'); p++; }
                if (m < 1 || m > 12 || y < 1 || y > 9999) print("usage: cal <month 1-12> <year>  |  cal -y <year>  |  cal -3\n");
                else cmd_cal_ym(y, m, 0);
            }
        } else if (startswith(line, "weekday ")) {        /* weekday YYYYMMDD -> the day name (Sakamoto) */
            const char *p = line + 8; while (*p == ' ') p++;
            int dig[8], k = 0;
            while (*p >= '0' && *p <= '9' && k < 8) dig[k++] = *p++ - '0';
            if (k != 8) print("usage: weekday YYYYMMDD   (e.g. weekday 20000101)\n");
            else {
                int y = dig[0]*1000 + dig[1]*100 + dig[2]*10 + dig[3];
                int m = dig[4]*10 + dig[5], d = dig[6]*10 + dig[7];
                if (m < 1 || m > 12 || d < 1 || d > 31) print("weekday: bad date\n");
                else {
                    static const int tt[] = { 0,3,2,5,0,3,5,1,4,6,2,4 };
                    int yy = y - (m < 3);
                    int w = (yy + yy/4 - yy/100 + yy/400 + tt[m-1] + d) % 7;
                    static const char *names[] = { "Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday" };
                    print("  "); print(names[w]); print("\n");
                }
            }
        } else if (startswith(line, "dur ")) {            /* dur SECONDS -> Dd Hh Mm Ss */
            const char *p = line + 4; while (*p == ' ') p++;
            long s = 0; int any = 0;
            while (*p >= '0' && *p <= '9') { if (s < 100000000000L) s = s * 10 + (*p - '0'); p++; any = 1; }
            if (!any) print("usage: dur <seconds>   (e.g. dur 90061)\n");
            else {
                long d = s/86400, h = (s%86400)/3600, m = (s%3600)/60, sec = s%60;
                print("  ");
                if (d) { printl(d); print("d "); }
                if (d || h) { printl(h); print("h "); }
                if (d || h || m) { printl(m); print("m "); }
                printl(sec); print("s\n");
            }
        } else if (streq(line, "date")) {
            char buf[24];
            sys_time(buf, sizeof(buf));                          /* "YYYY-MM-DD HH:MM:SS" */
            int dl = 0; while (buf[dl] && buf[dl] != ' ') dl++;  /* date cyan, time yellow (M1320) */
            char dpart[16]; int i = 0; for (; i < dl && i < 15; i++) dpart[i] = buf[i]; dpart[i] = 0;
            sys_setcolor(4); print(dpart); sys_setcolor(3); print(buf + dl); sys_setcolor(0);
        } else if (startswith(line, "date +")) {            /* date +FORMAT: strftime-style output (M1832) */
            const char *fmt = line + 6;
            char buf[24]; sys_time(buf, sizeof buf);         /* "YYYY-MM-DD HH:MM:SS" at fixed offsets */
            char out[128]; int o = 0;
            for (const char *f = fmt; *f && o < 110; f++) {
                if (*f == '%' && f[1]) {
                    f++;
                    switch (*f) {
                        case 'Y': out[o++]=buf[0]; out[o++]=buf[1]; out[o++]=buf[2]; out[o++]=buf[3]; break;
                        case 'y': out[o++]=buf[2]; out[o++]=buf[3]; break;
                        case 'm': out[o++]=buf[5]; out[o++]=buf[6]; break;
                        case 'd': out[o++]=buf[8]; out[o++]=buf[9]; break;
                        case 'H': out[o++]=buf[11]; out[o++]=buf[12]; break;
                        case 'M': out[o++]=buf[14]; out[o++]=buf[15]; break;
                        case 'S': out[o++]=buf[17]; out[o++]=buf[18]; break;
                        case 'F': for (int k = 0; k < 10; k++) out[o++]=buf[k]; break;   /* %F = %Y-%m-%d */
                        case 'T': for (int k = 11; k < 19; k++) out[o++]=buf[k]; break;  /* %T = %H:%M:%S */
                        case '%': out[o++]='%'; break;
                        default: out[o++]='%'; out[o++]=*f; break;                       /* unknown -> literal */
                    }
                } else out[o++]=*f;
            }
            out[o]=0; print(out); print("\n");
        } else if (streq(line, "sntp") || streq(line, "ntpdate")) {   /* set the wall clock from a network time server */
            char before[24]; sys_time(before, sizeof before);
            print("sntp: querying pool.ntp.org (UDP 123)...\n");
            if (sys_sntp() < 0) { print("sntp: no reply (UDP 123 may be blocked)\n"); g_status = 1; }
            else {
                char after[24]; sys_time(after, sizeof after);
                print("  before: "); print(before);
                print("  after:  "); print(after);
                print("  clock synced (UTC) from pool.ntp.org\n");
            }
        } else if (streq(line, "ver")) {
            print("OS-DEV 0.1 (x86_64, built from scratch)\n");
        } else if (streq(line, "pid")) {
            char num[12];
            itoa_simple(sys_getpid(), num);
            print("pid = ");
            print(num);
            print("\n");
        } else if (streq(line, "echo")) {
            print("\n");                                  /* bare echo: a blank line */
        } else if (startswith(line, "echo ")) {
            char *a = line + 5;
            sh_unprot_buf(a);                             /* reveal quoted spaces/metachars for output */
            if (streq(a, "-n")) { }                       /* echo -n: print nothing, no newline */
            else if (startswith(a, "-n ")) print(a + 3);  /* echo -n TEXT: no trailing newline (good for prompts before `read`) */
            else { print(a); print("\n"); }
        } else if (startswith(line, "printf ")) {         /* printf FMT [args]: \n \t \r \\ escapes + %s %d/%i %x/%X %o %u %c %% (FMT cycles over the args) */
            const char *p = line + 7; while (*p == ' ') p++;
            char fmt[256]; int fi = 0; while (*p && *p != ' ' && fi < 255) fmt[fi++] = *p++; fmt[fi] = 0; sh_unprot_buf(fmt);
            while (*p == ' ') p++;
            static char abuf[512]; char *av[32]; int ac = 0, bi = 0;   /* split the trailing words into args */
            while (*p && ac < 32) {
                if (bi >= 511) break;        /* no room for another arg + its NUL: stop (else av[] gets a dangling abuf+512 fed to sh_unprot_buf) */
                av[ac++] = abuf + bi;
                while (*p && *p != ' ' && bi < 511) abuf[bi++] = *p++;
                if (bi < 512) abuf[bi++] = 0;
                while (*p == ' ') p++;
            }
            for (int i = 0; i < ac; i++) sh_unprot_buf(av[i]);   /* restore quoted bytes in each arg */
            int has_spec = 0;
            for (const char *f = fmt; *f; f++) if (*f == '%' && f[1] && f[1] != '%') has_spec = 1;
            int ai = 0;
            for (;;) {
                int start_ai = ai;
                for (const char *f = fmt; *f; f++) {
                    if (*f == '\\' && f[1]) {
                        f++;
                        char c;
                        if (*f == 'x' && f[1]) {                       /* \xHH : hex byte */
                            int v = 0, k = 0; f++;
                            while (k < 2 && ((*f>='0'&&*f<='9')||((*f|32)>='a'&&(*f|32)<='f'))) {
                                v = v*16 + ((*f<='9') ? *f-'0' : (*f|32)-'a'+10); f++; k++;
                            }
                            f--; c = (char)v;
                        } else if (*f >= '0' && *f <= '7') {           /* \NNN : octal byte (so \033 = ESC) */
                            int v = 0, k = 0;
                            while (k < 3 && *f >= '0' && *f <= '7') { v = v*8 + (*f-'0'); f++; k++; }
                            f--; c = (char)v;
                        } else {                                       /* named escapes; \e/\E = ESC; others -> the char */
                            c = (*f=='n')?'\n':(*f=='t')?'\t':(*f=='r')?'\r':(*f=='e'||*f=='E')?27:
                                (*f=='a')?7:(*f=='b')?8:(*f=='f')?12:(*f=='v')?11:*f;
                        }
                        char s[2] = { c, 0 }; print(s);
                    } else if (*f == '%' && f[1]) {
                        f++;
                        if (*f == '%') { print("%"); }
                        else {                                       /* %[-][0][width](s|d|i|c|x|X|o|u) */
                            int left = 0, zero = 0, width = 0;
                            while (*f == '-' || *f == '0') { if (*f == '-') left = 1; else zero = 1; f++; }
                            while (*f >= '0' && *f <= '9' && width < 256) { width = width*10 + (*f - '0'); f++; }
                            char vs[80]; int vl = 0, consumed = 0, numeric = 0;
                            if (*f == 's') { const char *a = ai < ac ? av[ai] : ""; while (a[vl] && vl < 79) { vs[vl] = a[vl]; vl++; } vs[vl] = 0; consumed = 1; }
                            else if (*f == 'c') { vs[0] = (char)(ai < ac ? av[ai][0] : 0); vs[1] = 0; vl = (vs[0] != 0); consumed = 1; }
                            else if (*f == 'd' || *f == 'i') { itoa_simple(ai < ac ? (int)sh_str2long(av[ai]) : 0, vs); while (vs[vl]) vl++; consumed = 1; numeric = 1; }
                            else if (*f == 'x' || *f == 'X' || *f == 'o' || *f == 'u') {   /* hex / octal / unsigned (32-bit, like %d) */
                                unsigned long uv = ai < ac ? (unsigned long)(unsigned)(int)sh_str2long(av[ai]) : 0;
                                int base = (*f == 'o') ? 8 : (*f == 'u') ? 10 : 16;
                                utoa_base(uv, base, *f == 'X', vs); while (vs[vl]) vl++; consumed = 1; numeric = 1;
                            }
                            else { vs[0] = '%'; vs[1] = *f; vs[2] = 0; vl = 2; }   /* unknown spec: literal */
                            int pad = width > vl ? width - vl : 0;
                            if (left) { print(vs); for (int k = 0; k < pad; k++) print(" "); }
                            else if (zero && numeric) {              /* keep the sign ahead of the zero padding */
                                if (vs[0] == '-') { print("-"); for (int k = 0; k < pad; k++) print("0"); print(vs + 1); }
                                else { for (int k = 0; k < pad; k++) print("0"); print(vs); }
                            } else { for (int k = 0; k < pad; k++) print(" "); print(vs); }
                            if (consumed && ai < ac) ai++;
                        }
                    } else { char s[2] = { *f, 0 }; print(s); }
                }
                if (!(has_spec && ai < ac && ai > start_ai)) break;   /* cycle the format while args remain and a pass consumed one */
            }
        } else if (startswith(line, "sleep ")) {          /* sleep N[.M] : pause N seconds (capped at 300s so a typo can't hang forever) */
            const char *p = line + 6; while (*p == ' ') p++;
            long ms = 0; while (*p >= '0' && *p <= '9') { ms = ms * 10 + (*p++ - '0'); if (ms > 300) ms = 300; }
            ms *= 1000;
            if (*p == '.' && p[1] >= '0' && p[1] <= '9') ms += (p[1] - '0') * 100;   /* .N tenths of a second */
            for (long slept = 0; slept < ms; ) {        /* chunked so Ctrl-C / Esc can interrupt, like the for/while loops */
                int chunk = (ms - slept) > 50 ? 50 : (int)(ms - slept);
                sys_sleep(chunk); slept += chunk;
                int k = sys_pollkey();
                if (k == 0x83 || k == 27) { print("^C\n"); g_status = 130; break; }
            }
        } else if (startswith(line, "tee ")) {            /* cmd | tee FILE... : write the piped input to each FILE and pass it through */
            const char *p = line + 4; while (*p == ' ') p++;
            char tav[8][64]; int tac = 0;                 /* targets + (last, appended by the pipe) the input file */
            while (*p && tac < 8) {
                int q = 0; while (*p && *p != ' ' && q < 63) tav[tac][q++] = *p++;
                tav[tac][q] = 0; sh_unprot_buf(tav[tac]); tac++;
                while (*p == ' ') p++;
            }
            if (tac < 2) print("usage: cmd | tee <file>...\n");   /* the piped input is the appended last arg */
            else {
                long n; char *buf = slurp(tav[tac - 1], &n);      /* last arg = the piped input */
                if (buf) {
                    for (int i = 0; i < tac - 1; i++) sys_writefile(tav[i], buf, (unsigned long)n);   /* fan out to each file */
                    buf[n] = 0; print(buf);                       /* and pass it on down the pipe */
                    free(buf);
                }
            }
        } else if (startswith(line, "xargs ")) {          /* cmd | xargs CMD : append the piped tokens to CMD and run it (e.g. find pat | xargs rm) */
            const char *p = line + 6; while (*p == ' ') p++;
            const char *lastw = 0, *scan = p;             /* the last word is the piped input file (appended by the pipe) */
            while (*scan) { while (*scan == ' ') scan++; if (!*scan) break; lastw = scan; while (*scan && *scan != ' ') scan++; }
            if (!lastw || lastw == p) { print("usage: cmd | xargs <command>...\n"); }   /* need a command before the appended input */
            else {
                char infile[64]; int q = 0; while (lastw[q] && lastw[q] != ' ' && q < 63) { infile[q] = lastw[q]; q++; } infile[q] = 0; sh_unprot_buf(infile);
                long n; char *buf = slurp(infile, &n);
                if (buf) {
                    buf[n] = 0;
                    char built[1024]; int bo = 0;
                    for (const char *c = p; c < lastw && bo < 1000; c++) built[bo++] = *c;   /* the command (everything before the input) */
                    while (bo > 0 && built[bo-1] == ' ') bo--;
                    const char *w = buf;                  /* append each whitespace-separated input token */
                    while (*w && bo < 1000) {
                        while (*w == ' ' || *w == '\n' || *w == '\t' || *w == '\r') w++;
                        if (!*w) break;
                        built[bo++] = ' ';
                        while (*w && *w != ' ' && *w != '\n' && *w != '\t' && *w != '\r' && bo < 1000) built[bo++] = *w++;
                    }
                    built[bo] = 0; free(buf);
                    run_input_line(built, cwd);           /* run the assembled command line */
                }
            }
        } else if (startswith(line, "cowsay ")) {         /* the classic: a cow speaks your message */
            char *msg = line + 7; sh_unprot_buf(msg); int len = 0; while (msg[len]) len++;
            print(" "); for (int i = 0; i < len + 2; i++) print("_"); print("\n");
            print("< "); print(msg); print(" >\n");
            print(" "); for (int i = 0; i < len + 2; i++) print("-"); print("\n");
            print("        \\   ^__^\n");
            print("         \\  (oo)\\_______\n");
            print("            (__)\\       )\\/\\\n");
            print("                ||----w |\n");
            print("                ||     ||\n");
        } else if (streq(line, "fortune")) {              /* a random programming aphorism (pairs with cowsay) */
            static const char *fortunes[] = {
                "The best way to predict the future is to invent it.  -Alan Kay",
                "Premature optimization is the root of all evil.  -Knuth",
                "There are 2 hard problems in CS: cache invalidation, naming things, and off-by-one errors.",
                "Talk is cheap. Show me the code.  -Linus Torvalds",
                "Simplicity is the ultimate sophistication.  -da Vinci",
                "Weeks of coding can save hours of planning.",
                "It works on my machine.",
                "First, solve the problem. Then, write the code.  -John Johnson",
                "Any sufficiently advanced technology is indistinguishable from magic.  -Clarke",
                "A user interface is like a joke: if you have to explain it, it is not that good.",
            };
            int fn = (int)(sizeof(fortunes) / sizeof(fortunes[0]));
            print(fortunes[shroll() % (unsigned)fn]); print("\n");
        } else if (streq(line, "genpass") || startswith(line, "genpass ")) {   /* random password (CLI companion to passgen.htm) */
            int n = 16;
            if (line[7] == ' ') { const char *p = line + 8; while (*p == ' ') p++; if (*p >= '0' && *p <= '9') { n = 0; while (*p >= '0' && *p <= '9' && n < 1000) n = n * 10 + (*p++ - '0'); } }
            if (n < 1) n = 16;
            if (n > 64) n = 64;
            static const char gcs[] = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*";   /* no ambiguous l/I/O/0/1 */
            int gl = (int)sizeof(gcs) - 1;
            char gp[66]; for (int i = 0; i < n; i++) gp[i] = gcs[shroll() % (unsigned)gl]; gp[n] = 0;
            print("  "); print(gp); print("\n");
        } else if (streq(line, "uuidgen")) {              /* random RFC-4122 v4 UUID (CLI companion to uuid.htm) */
            static const char uhx[] = "0123456789abcdef";
            char u[37]; int j = 0;
            for (int i = 0; i < 36; i++) {
                if (i==8 || i==13 || i==18 || i==23) u[j++] = '-';
                else if (i==14) u[j++] = '4';                       /* version 4 */
                else if (i==19) u[j++] = uhx[8 + (shroll() % 4)];   /* variant 8/9/a/b */
                else u[j++] = uhx[shroll() % 16];
            }
            u[j] = 0;
            print("  "); print(u); print("\n");
        } else if (streq(line, "ascii")) {                /* the printable ASCII table (CLI companion to ascii.htm) */
            for (int c = 32; c <= 126; c++) {
                char nb[8]; itoa_simple(c, nb);
                if (c < 100) print(" ");
                print(nb); print(" ");
                char cb[2] = { (char)c, 0 }; print(cb);
                print("  ");
                if ((c - 31) % 6 == 0) print("\n");      /* 6/row fits the 44-col shell grid */
            }
            print("\n");
        } else if (startswith(line, "roman ")) {          /* roman N -> Roman numerals (1-3999) */
            const char *p = line + 6; while (*p == ' ') p++;
            int n = 0; while (*p >= '0' && *p <= '9' && n < 100000) n = n * 10 + (*p++ - '0');
            if (n < 1 || n > 3999) print("usage: roman <1-3999>\n");
            else {
                static const int vals[] = { 1000,900,500,400,100,90,50,40,10,9,5,4,1 };
                static const char *syms[] = { "M","CM","D","CD","C","XC","L","XL","X","IX","V","IV","I" };
                print("  ");
                for (int i = 0; i < 13; i++) while (n >= vals[i]) { print(syms[i]); n -= vals[i]; }
                print("\n");
            }
        } else if (startswith(line, "base ")) {           /* base N -> binary / octal / hex (CLI companion to base.htm) */
            const char *p = line + 5; while (*p == ' ') p++;
            unsigned long n = 0; int any = 0;
            while (*p >= '0' && *p <= '9') { if (n < 100000000000000000UL) n = n * 10 + (unsigned)(*p - '0'); p++; any = 1; }
            if (!any) print("usage: base <decimal>   (e.g. base 255)\n");
            else {
                print("  bin "); print_base(n, 2);
                print("  oct "); print_base(n, 8);
                print("  hex "); print_base(n, 16);
                print("\n");
            }
        } else if (startswith(line, "gcd ")) {            /* gcd A B -> gcd + lcm (Euclid) */
            const char *p = line + 4; while (*p == ' ') p++;
            long a = 0; while (*p >= '0' && *p <= '9' && a < 100000000L) a = a * 10 + (*p++ - '0');   /* cap ~1e9 so a*b can't overflow long */
            while (*p == ' ') p++;
            long b = 0; while (*p >= '0' && *p <= '9' && b < 100000000L) b = b * 10 + (*p++ - '0');
            if (a < 1 || b < 1) print("usage: gcd <a> <b>   (e.g. gcd 12 18)\n");
            else {
                long x = a, y = b; while (y) { long t = x % y; x = y; y = t; }   /* Euclid's algorithm */
                print("  gcd="); printl(x);
                print("  lcm="); printl(a / x * b);                              /* a/g*b avoids a*b overflow */
                print("\n");
            }
        } else if (startswith(line, "primes ")) {         /* primes N -> all primes up to N */
            const char *p = line + 7; while (*p == ' ') p++;
            int n = 0; while (*p >= '0' && *p <= '9' && n < 100000) n = n * 10 + (*p++ - '0');
            if (n < 2 || n > 10000) print("usage: primes <2-10000>\n");
            else {
                char nb[12]; print("  ");
                for (int k = 2; k <= n; k++) {
                    int prime = 1;
                    for (int d = 2; d * d <= k; d++) if (k % d == 0) { prime = 0; break; }
                    if (prime) { itoa_simple(k, nb); print(nb); print(" "); }
                }
                print("\n");
            }
        } else if (startswith(line, "rot13 ")) {          /* rot13 TEXT -> ROT13 (CLI companion to rot13.htm) */
            char *p = line + 6; sh_unprot_buf(p);
            char out[256]; int i = 0;
            while (*p && i < 255) {
                char c = *p++;
                if (c >= 'A' && c <= 'Z') out[i++] = (char)((c - 'A' + 13) % 26 + 'A');
                else if (c >= 'a' && c <= 'z') out[i++] = (char)((c - 'a' + 13) % 26 + 'a');
                else out[i++] = c;
            }
            out[i] = 0;
            print("  "); print(out); print("\n");
        } else if (startswith(line, "fizzbuzz ")) {       /* the classic FizzBuzz up to N */
            const char *p = line + 9; while (*p == ' ') p++;
            int n = 0; while (*p >= '0' && *p <= '9' && n < 10000) n = n * 10 + (*p++ - '0');
            if (n < 1 || n > 1000) print("usage: fizzbuzz <1-1000>\n");
            else {
                char nb[12]; print("  ");
                for (int k = 1; k <= n; k++) {
                    if (k % 15 == 0) print("FizzBuzz");
                    else if (k % 3 == 0) print("Fizz");
                    else if (k % 5 == 0) print("Buzz");
                    else { itoa_simple(k, nb); print(nb); }
                    print(" ");
                }
                print("\n");
            }
        } else if (startswith(line, "dec ")) {            /* dec 0x.. / 0b.. / 0o.. / decimal -> decimal value */
            const char *p = line + 4; while (*p == ' ') p++;
            int base = 10;
            if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { base = 16; p += 2; }
            else if (p[0] == '0' && (p[1] == 'b' || p[1] == 'B')) { base = 2; p += 2; }
            else if (p[0] == '0' && (p[1] == 'o' || p[1] == 'O')) { base = 8; p += 2; }
            unsigned long v = 0; int any = 0;
            while (*p) {
                char c = *p; int d;
                if (c >= '0' && c <= '9') d = c - '0';
                else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
                else break;
                if (d >= base) break;
                if (v > 1000000000000000000UL) break;
                v = v * (unsigned)base + (unsigned)d; any = 1; p++;
            }
            if (!any) print("usage: dec <0x.. | 0b.. | 0o.. | decimal>\n");
            else { print("  "); print_base(v, 10); print("\n"); }   /* unsigned: correct even when v > LONG_MAX */
        } else if (startswith(line, "fib ")) {            /* fib N -> the Nth Fibonacci number */
            const char *p = line + 4; while (*p == ' ') p++;
            int n = 0; while (*p >= '0' && *p <= '9' && n < 1000) n = n * 10 + (*p++ - '0');
            if (n > 90) print("fib: max 90 (fib(91)+ overflows 64-bit)\n");
            else {
                long a = 0, b = 1;
                for (int i = 0; i < n; i++) { long t = a + b; a = b; b = t; }
                print("  "); printl(a); print("\n");
            }
        } else if (startswith(line, "stats ")) {          /* stats N1 N2 ... -> count/min/max/sum */
            const char *p = line + 6;
            long mn = 0, mx = 0, sum = 0; int cnt = 0;
            while (*p) {
                while (*p == ' ') p++;
                if (*p < '0' || *p > '9') break;
                long v = 0; while (*p >= '0' && *p <= '9') { if (v < 1000000000000L) v = v * 10 + (*p - '0'); p++; }
                if (cnt == 0) { mn = mx = v; } else { if (v < mn) mn = v; if (v > mx) mx = v; }
                sum += v; cnt++;
            }
            if (cnt == 0) print("usage: stats <n1> <n2> ...\n");
            else {
                print("  count="); printl(cnt);
                print("  min="); printl(mn);
                print("  max="); printl(mx);
                print("  sum="); printl(sum);
                print("\n");
            }
        } else if (startswith(line, "size ")) {           /* size BYTES -> GB/MB/KB/B (1024-based) */
            const char *p = line + 5; while (*p == ' ') p++;
            long b = 0; int any = 0;
            while (*p >= '0' && *p <= '9') { if (b < 100000000000000L) b = b * 10 + (*p - '0'); p++; any = 1; }
            if (!any) print("usage: size <bytes>   (e.g. size 1536000)\n");
            else {
                long gb = b/1073741824, mb = (b%1073741824)/1048576, kb = (b%1048576)/1024, by = b%1024;
                print("  ");
                if (gb) { printl(gb); print(" GB "); }
                if (gb || mb) { printl(mb); print(" MB "); }
                if (gb || mb || kb) { printl(kb); print(" KB "); }
                printl(by); print(" B\n");
            }
        } else if (startswith(line, "unmorse ")) {        /* unmorse CODE -> text (reverse of morse; / = word space) */
            char *p = line + 8; sh_unprot_buf(p);
            static const char *codes[] = { ".-","-...","-.-.","-..",".","..-.","--.","....","..",".---","-.-",".-..","--","-.","---",".--.","--.-",".-.","...","-","..-","...-",".--","-..-","-.--","--..","-----",".----","..---","...--","....-",".....","-....","--...","---..","----." };
            static const char *letters = "abcdefghijklmnopqrstuvwxyz0123456789";
            char out[256]; int oi = 0;
            while (*p && oi < 255) {
                if (*p == '/') { out[oi++] = ' '; p++; continue; }
                if (*p == ' ') { p++; continue; }
                char tok[12]; int ti = 0;
                while ((*p == '.' || *p == '-') && ti < 11) tok[ti++] = *p++;
                tok[ti] = 0;
                if (ti == 0) { p++; continue; }                       /* skip any other char */
                for (int i = 0; i < 36; i++) {
                    const char *c = codes[i], *t = tok;
                    while (*c && *t && *c == *t) { c++; t++; }
                    if (!*c && !*t) { out[oi++] = letters[i]; break; }
                }
            }
            out[oi] = 0;
            print("  "); print(out); print("\n");
        } else if (startswith(line, "unhex ")) {          /* unhex HEXSTRING -> ASCII text */
            const char *p = line + 6; while (*p == ' ') p++;
            char out[256]; int oi = 0;
            while (*p && oi < 255) {
                int hi = (*p>='0'&&*p<='9') ? *p-'0' : (*p>='a'&&*p<='f') ? *p-'a'+10 : (*p>='A'&&*p<='F') ? *p-'A'+10 : -1;
                if (hi < 0) { p++; continue; }                /* skip spaces / non-hex */
                p++;
                int lo = (*p>='0'&&*p<='9') ? *p-'0' : (*p>='a'&&*p<='f') ? *p-'a'+10 : (*p>='A'&&*p<='F') ? *p-'A'+10 : -1;
                if (lo < 0) break;                            /* odd trailing nibble: stop */
                p++;
                out[oi++] = (char)(hi * 16 + lo);
            }
            out[oi] = 0;
            print("  "); print(out); print("\n");
        } else if (startswith(line, "unbase64 ")) {       /* unbase64 B64 -> decoded text */
            const char *p = line + 9; while (*p == ' ') p++;
            char out[256]; int oi = 0, acc = 0, bits = 0;
            while (*p && oi < 255) {
                char c = *p++; int v;
                if (c >= 'A' && c <= 'Z') v = c - 'A';
                else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
                else if (c >= '0' && c <= '9') v = c - '0' + 52;
                else if (c == '+') v = 62;
                else if (c == '/') v = 63;
                else if (c == '=') break;                 /* padding: done */
                else continue;                            /* skip whitespace/other */
                acc = (acc << 6) | v; bits += 6;
                if (bits >= 8) { bits -= 8; out[oi++] = (char)((acc >> bits) & 0xFF); }
            }
            out[oi] = 0;
            print("  "); print(out); print("\n");
        } else if (startswith(line, "cmp ")) {            /* cmp F1 F2 -> identical, or the first differing line */
            const char *p = line + 4; while (*p == ' ') p++;
            char f1[64]; int j = 0; while (*p && *p != ' ' && j < 63) f1[j++] = *p++; f1[j] = 0; sh_unprot_buf(f1);
            while (*p == ' ') p++;
            char f2[64]; j = 0; while (*p && *p != ' ' && j < 63) f2[j++] = *p++; f2[j] = 0; sh_unprot_buf(f2);
            if (!f1[0] || !f2[0]) { print("usage: cmp <file1> <file2>\n"); g_status = 2; }
            else {
                long n1; char *b1 = slurp(f1, &n1);
                long n2; char *b2 = slurp(f2, &n2);
                if (!b1)      { perr("cmp: no such file: "); print(f1); print("\n"); g_status = 2; }
                else if (!b2) { perr("cmp: no such file: "); print(f2); print("\n"); g_status = 2; }
                else {
                    long i1 = 0, i2 = 0; int lineno = 1, differ = 0;
                    while (i1 < n1 || i2 < n2) {
                        long s1 = i1; while (i1 < n1 && b1[i1] != '\n') i1++; long e1 = i1; if (i1 < n1) i1++;
                        long s2 = i2; while (i2 < n2 && b2[i2] != '\n') i2++; long e2 = i2; if (i2 < n2) i2++;
                        long l1 = e1 - s1, l2 = e2 - s2; int same = (l1 == l2);
                        for (long k = 0; same && k < l1; k++) if (b1[s1 + k] != b2[s2 + k]) same = 0;
                        if (!same) {
                            char t[256]; long k;
                            print("  line "); printl(lineno); print(" differs:\n");
                            print("  < "); for (k = 0; k < l1 && k < 255; k++) t[k] = b1[s1 + k]; t[k] = 0; print(t); print("\n");
                            print("  > "); for (k = 0; k < l2 && k < 255; k++) t[k] = b2[s2 + k]; t[k] = 0; print(t); print("\n");
                            differ = 1; break;
                        }
                        lineno++;
                    }
                    if (!differ) print("  files are identical\n");
                    g_status = differ ? 1 : 0;          /* exit status like real cmp: 0 same, 1 differ */
                }
                free(b1); free(b2);
            }
        } else if (startswith(line, "strings ")) {        /* strings FILE... -> runs of >=4 printable chars */
            const char *p = line + 8; int any = 0, fc = 0;
            { const char *cq = p; while (*cq) { while (*cq==' ') cq++; if (!*cq) break; fc++; while (*cq && *cq!=' ') cq++; } }
            while (*p) {
                while (*p == ' ') p++;
                if (!*p) break;
                char name[64]; int j = 0; while (*p && *p != ' ' && j < 63) name[j++] = *p++; name[j] = 0; sh_unprot_buf(name);
                any = 1;
                long n; char *buf = slurp(name, &n);
                if (!buf) { perr("strings: no such file: "); print(name); print("\n"); continue; }
                if (fc > 1) { print("==> "); print(name); print(" <==\n"); }   /* header when listing several */
                char run[80]; int rl = 0;
                for (long i = 0; i < n; i++) {
                    char c = buf[i];
                    if (c >= 32 && c < 127) { if (rl < 79) run[rl++] = c; }   /* printable ASCII */
                    else { if (rl >= 4) { run[rl] = 0; print("  "); print(run); print("\n"); } rl = 0; }
                }
                if (rl >= 4) { run[rl] = 0; print("  "); print(run); print("\n"); }   /* trailing run */
                free(buf);
            }
            if (!any) print("usage: strings <file>...\n");
        } else if (startswith(line, "basename ")) {       /* basename PATH [SUFFIX] -> last component, minus a trailing SUFFIX */
            const char *p = line + 9; while (*p == ' ') p++;
            char path[160]; int pl = 0; while (p[pl] && p[pl] != ' ' && pl < 159) { path[pl] = p[pl]; pl++; } path[pl] = 0; sh_unprot_buf(path);
            const char *sp = p + pl; while (*sp == ' ') sp++;         /* optional SUFFIX to strip (basename foo.txt .txt -> foo) */
            char suf[64]; int sl = 0; while (*sp && *sp != ' ' && sl < 63) suf[sl++] = *sp++; suf[sl] = 0; sh_unprot_buf(suf);
            while (pl > 1 && path[pl-1] == '/') path[--pl] = 0;        /* strip trailing slashes (keep a lone "/") */
            int last = -1; for (int i = 0; i < pl; i++) if (path[i] == '/') last = i;
            char *base = last >= 0 ? path + last + 1 : path;
            if (sl > 0) { int bl = 0; while (base[bl]) bl++; if (bl > sl && streq(base + bl - sl, suf)) base[bl - sl] = 0; }   /* trim SUFFIX, but never the whole name (POSIX) */
            print("  "); print(base); print("\n");
        } else if (startswith(line, "dirname ")) {        /* dirname PATH -> the directory part */
            const char *p = line + 8; while (*p == ' ') p++;
            char path[160]; int pl = 0; while (p[pl] && p[pl] != ' ' && pl < 159) { path[pl] = p[pl]; pl++; } path[pl] = 0; sh_unprot_buf(path);
            int last = -1; for (int i = 0; i < pl; i++) if (path[i] == '/') last = i;
            if (last < 0) print("  .\n");                              /* no slash -> current dir */
            else if (last == 0) print("  /\n");                        /* "/file" -> "/" */
            else { path[last] = 0; print("  "); print(path); print("\n"); }
        } else if (startswith(line, "paste ")) {          /* paste F1 F2 -> each file's line i, side by side (default tab; -dX picks the joiner) */
            const char *p = line + 6; while (*p == ' ') p++;
            char delim = '\t';
            if (p[0] == '-' && p[1] == 'd') { p += 2; while (*p == ' ') p++; if (*p) delim = *p++; while (*p == ' ') p++; }
            char f1[64]; int j = 0; while (*p && *p != ' ' && j < 63) f1[j++] = *p++; f1[j] = 0; sh_unprot_buf(f1);
            while (*p == ' ') p++;
            char f2[64]; j = 0; while (*p && *p != ' ' && j < 63) f2[j++] = *p++; f2[j] = 0; sh_unprot_buf(f2);
            if (!f1[0] || !f2[0]) { print("usage: paste [-dX] <file1> <file2>\n"); }
            else {
                long n1, n2; char *c1 = slurp(f1, &n1); char *c2 = slurp(f2, &n2);
                if (!c1)      { perr("paste: no such file: "); print(f1); print("\n"); }
                else if (!c2) { perr("paste: no such file: "); print(f2); print("\n"); }
                else {
                    long i1 = 0, i2 = 0;
                    while (i1 < n1 || i2 < n2) {
                        long s1 = i1; while (i1 < n1 && c1[i1] != '\n') i1++; long e1 = i1; if (i1 < n1) i1++;
                        long s2 = i2; while (i2 < n2 && c2[i2] != '\n') i2++; long e2 = i2; if (i2 < n2) i2++;
                        char t[160]; long k, q = 0;
                        for (k = s1; k < e1 && q < 78; k++) t[q++] = c1[k];   /* file1's line */
                        t[q++] = delim;
                        for (k = s2; k < e2 && q < 158; k++) t[q++] = c2[k];  /* file2's line */
                        t[q] = 0; print("  "); print(t); print("\n");
                    }
                }
                free(c1); free(c2);
            }
        } else if (startswith(line, "comm ")) {           /* comm F1 F2 (sorted) -> < only-in-1, > only-in-2, = in-both */
            const char *p = line + 5; while (*p == ' ') p++;
            char f1[64]; int j = 0; while (*p && *p != ' ' && j < 63) f1[j++] = *p++; f1[j] = 0; sh_unprot_buf(f1);
            while (*p == ' ') p++;
            char f2[64]; j = 0; while (*p && *p != ' ' && j < 63) f2[j++] = *p++; f2[j] = 0; sh_unprot_buf(f2);
            if (!f1[0] || !f2[0]) { print("usage: comm <file1> <file2>  (sorted; < only-1, > only-2, = both)\n"); }
            else {
                long n1, n2; char *c1 = slurp(f1, &n1); char *c2 = slurp(f2, &n2);
                if (!c1)      { perr("comm: no such file: "); print(f1); print("\n"); }
                else if (!c2) { perr("comm: no such file: "); print(f2); print("\n"); }
                else {
                    long i1 = 0, i2 = 0;
                    while (i1 < n1 || i2 < n2) {
                        int haveA = i1 < n1, haveB = i2 < n2;     /* peek each line WITHOUT advancing the cursor */
                        long a_s = i1, a_e = i1; if (haveA) { while (a_e < n1 && c1[a_e] != '\n') a_e++; }
                        long b_s = i2, b_e = i2; if (haveB) { while (b_e < n2 && c2[b_e] != '\n') b_e++; }
                        long a_next = a_e < n1 ? a_e + 1 : a_e, b_next = b_e < n2 ? b_e + 1 : b_e;
                        int rel;                                  /* <0: only-A, >0: only-B, 0: both */
                        if (haveA && !haveB) rel = -1;
                        else if (!haveA && haveB) rel = 1;
                        else { long la = a_e - a_s, lb = b_e - b_s, m = la < lb ? la : lb; rel = 0;
                            for (long k = 0; k < m; k++) if (c1[a_s+k] != c2[b_s+k]) { rel = c1[a_s+k] < c2[b_s+k] ? -1 : 1; break; }
                            if (rel == 0 && la != lb) rel = la < lb ? -1 : 1; }
                        char t[160]; long k, q = 0; long s = rel > 0 ? b_s : a_s, e = rel > 0 ? b_e : a_e; char *src = rel > 0 ? c2 : c1;
                        for (k = s; k < e && q < 157; k++) t[q++] = src[k]; t[q] = 0;
                        print(rel < 0 ? "  < " : rel > 0 ? "  > " : "  = "); print(t); print("\n");
                        if (rel <= 0) i1 = a_next;                /* advance the file(s) whose line was emitted */
                        if (rel >= 0) i2 = b_next;
                    }
                }
                free(c1); free(c2);
            }
        } else if (startswith(line, "diff ")) {           /* diff F1 F2 -> LCS line edit script: '- ' removed from F1, '+ ' added in F2, '  ' unchanged */
            const char *p = line + 5; while (*p == ' ') p++;
            char f1[64]; int j = 0; while (*p && *p != ' ' && j < 63) f1[j++] = *p++; f1[j] = 0; sh_unprot_buf(f1);
            while (*p == ' ') p++;
            char f2[64]; j = 0; while (*p && *p != ' ' && j < 63) f2[j++] = *p++; f2[j] = 0; sh_unprot_buf(f2);
            if (!f1[0] || !f2[0]) { print("usage: diff <file1> <file2>  (line edit: - removed, + added)\n"); g_status = 2; }
            else {
                long n1, n2; char *d1 = slurp(f1, &n1); char *d2 = slurp(f2, &n2);   /* whole files; the LCS still caps lines (warned below) */
                if (!d1) { print("diff: "); print(f1); print(": no such file\n"); g_status = 2; }
                else if (!d2) { print("diff: "); print(f2); print(": no such file\n"); g_status = 2; }
                else {
                    static int as[129], ae[129], bs[129], be[129];
                    static short L[129][129];                       /* LCS lengths; capped at 128 lines/file */
                    int na = 0, nb = 0, i;
                    for (i = 0; i < n1 && na < 128; na++) { as[na] = i; while (i < n1 && d1[i] != '\n') i++; ae[na] = i; if (i < n1) i++; }
                    for (i = 0; i < n2 && nb < 128; nb++) { bs[nb] = i; while (i < n2 && d2[i] != '\n') i++; be[nb] = i; if (i < n2) i++; }
                    for (int a = na; a >= 0; a--) for (int b = nb; b >= 0; b--) {
                        if (a == na || b == nb) { L[a][b] = 0; continue; }
                        int la = ae[a]-as[a], lb = be[b]-bs[b], eq = (la == lb), k;
                        for (k = 0; eq && k < la; k++) if (d1[as[a]+k] != d2[bs[b]+k]) eq = 0;
                        if (eq) L[a][b] = (short)(L[a+1][b+1] + 1);
                        else    L[a][b] = L[a+1][b] >= L[a][b+1] ? L[a+1][b] : L[a][b+1];
                    }
                    int a = 0, b = 0, diffs = 0;
                    while (a < na || b < nb) {
                        char t[160]; int k, q = 0; int eq = 0;
                        if (a < na && b < nb) {
                            int la = ae[a]-as[a], lb = be[b]-bs[b]; eq = (la == lb);
                            for (k = 0; eq && k < la; k++) if (d1[as[a]+k] != d2[bs[b]+k]) eq = 0;
                        }
                        if (a < na && b < nb && eq) {                              /* unchanged: context */
                            for (k = as[a]; k < ae[a] && q < 157; k++) t[q++] = d1[k]; t[q] = 0;
                            sys_setcolor(8); print("  "); print(t); sys_setcolor(0); print("\n"); a++; b++;   /* context: grey (M1335) */
                        } else if (b >= nb || (a < na && L[a+1][b] >= L[a][b+1])) { /* removed from F1 */
                            for (k = as[a]; k < ae[a] && q < 157; k++) t[q++] = d1[k]; t[q] = 0;
                            sys_setcolor(2); print("- "); print(t); sys_setcolor(0); print("\n"); a++; diffs++;   /* removed: red */
                        } else {                                                   /* added in F2 */
                            for (k = bs[b]; k < be[b] && q < 157; k++) t[q++] = d2[k]; t[q] = 0;
                            sys_setcolor(9); print("+ "); print(t); sys_setcolor(0); print("\n"); b++; diffs++;   /* added: lime */
                        }
                    }
                    if (!diffs) print("(files are identical)\n");
                    if (na >= 128 || nb >= 128) print("(diff truncated at 128 lines/file)\n");
                    g_status = diffs ? 1 : 0;           /* exit status like real diff: 0 same, 1 differ */
                }
                free(d1); free(d2);
            }
        } else if (startswith(line, "get ")) {
            char host[64], path[160]; int i = 0; char *p = line + 4;
            while (*p == ' ') p++;
            int secure = 0;                            /* https:// -> fetch over TLS */
            if (startswith(p, "https://")) { secure = 1; p += 8; }
            else if (startswith(p, "http://")) { p += 7; }
            while (*p && *p != ' ' && *p != '/' && i < 63) host[i++] = *p++;
            host[i] = 0; sh_unprot_buf(host);
            if (*p == '/' || *p == ' ') {              /* optional path */
                if (*p == ' ') p++;
                int j = 0; while (*p && j < 159) path[j++] = *p++; path[j] = 0;
            } else { path[0] = '/'; path[1] = 0; }
            sh_unprot_buf(path);
            if (host[0] == 0) { print("usage: get [http(s)://]<host>[/path]\n"); }
            else {
                static char resp[8192];
                print(secure ? "fetching https://" : "fetching http://"); print(host); print(path); print(" ...\n");
                long n = secure ? sys_https(host, path, resp, sizeof(resp) - 1)
                                : sys_http(host, path, resp, sizeof(resp) - 1);
                if (n < 0) print("get: failed (no net/DNS/connect)\n");
                else {
                    resp[n] = 0;
                    char num[12]; itoa_simple((int)n, num);
                    print("--- "); print(num); print(" bytes ---\n");
                    print(resp); print("\n");
                }
            }
        } else if (startswith(line, "wsget ")) {
            /* wsget ws://host[:port][/path] [message] — open a WebSocket, send
             * `message` (default "hi"), print each reply frame. A diagnostic for
             * the from-scratch WebSocket client (M1846), like `get` is for HTTP.
             * A `0x`-prefixed message is sent as a BINARY frame of those hex bytes
             * (e.g. `0x01ff80`); binary replies are hex-dumped (M1859). */
            char url[256]; int i = 0; char *p = line + 6;
            while (*p == ' ') p++;
            while (*p && *p != ' ' && i < 255) url[i++] = *p++;
            url[i] = 0; sh_unprot_buf(url);
            while (*p == ' ') p++;
            char msg[256]; int j = 0; while (*p && j < 255) msg[j++] = *p++; msg[j] = 0; sh_unprot_buf(msg);
            if (msg[0] == 0) { msg[0] = 'h'; msg[1] = 'i'; msg[2] = 0; }
            if (url[0] == 0) { print("usage: wsget ws://<host>[:port][/path] [message]\n"); }
            else {
                int status = 0; char num[12];
                long id = sys_ws_open(url, &status);
                if (id < 0) {
                    print("wsget: connect/handshake failed (status "); itoa_simple(status, num); print(num); print(")\n");
                } else {
                    char sbuf[300]; int sl = 0;                 /* one record: [op:1][len:4 LE][payload] */
                    unsigned char pay[256]; int pl2 = 0, op = 1;   /* op 1=WSREC_TEXT, 2=WSREC_BIN */
                    if ((msg[0]=='0') && (msg[1]=='x' || msg[1]=='X')) {
                        op = 2;                                 /* 0x-prefixed -> BINARY frame of hex bytes */
                        for (const char *h = msg + 2; h[0] && h[1] && pl2 < 256; h += 2) {
                            int hi = (h[0]<='9')?h[0]-'0':(h[0]|32)-'a'+10, lo = (h[1]<='9')?h[1]-'0':(h[1]|32)-'a'+10;
                            pay[pl2++] = (unsigned char)((hi << 4) | lo);
                        }
                    } else {
                        while (msg[pl2] && pl2 < 256) { pay[pl2] = (unsigned char)msg[pl2]; pl2++; }
                    }
                    sbuf[sl++] = (char)op;
                    sbuf[sl++] = (char)(pl2 & 0xff);        sbuf[sl++] = (char)((pl2 >> 8) & 0xff);
                    sbuf[sl++] = (char)((pl2 >> 16) & 0xff); sbuf[sl++] = (char)((pl2 >> 24) & 0xff);
                    for (int m2 = 0; m2 < pl2 && sl < 299; m2++) sbuf[sl++] = (char)pay[m2];
                    static char out[8192]; int nrecv = 0;
                    long rb = sys_ws_exchange((int)id, sbuf, sl, out, sizeof out, &nrecv);
                    if (rb < 0) { print("wsget: exchange failed\n"); }
                    else {
                        print("wsget: connected (status "); itoa_simple(status, num); print(num);
                        print("), replies="); itoa_simple(nrecv, num); print(num); print(":\n");
                        const unsigned char *q = (const unsigned char *)out; int off = 0;
                        for (int k = 0; k < nrecv && off + 5 <= rb; k++) {   /* parse reply records */
                            int op = q[off];
                            int L = (int)((unsigned)q[off+1] | ((unsigned)q[off+2] << 8) |
                                          ((unsigned)q[off+3] << 16) | ((unsigned)q[off+4] << 24));
                            off += 5; if (L < 0 || off + L > rb) break;
                            if (op == 2) {                      /* WSREC_BIN: hex-dump the payload */
                                print("  <- (binary "); itoa_simple(L, num); print(num); print(" bytes) ");
                                for (int b = 0; b < L; b++) {
                                    const char *H = "0123456789abcdef"; char hx[3];
                                    hx[0] = H[(q[off+b] >> 4) & 0xf]; hx[1] = H[q[off+b] & 0xf]; hx[2] = 0; print(hx);
                                }
                                print("\n");
                            } else {                            /* WSREC_TEXT */
                                char t[512]; int tl = L < 511 ? L : 511;
                                for (int b = 0; b < tl; b++) t[b] = (char)q[off+b]; t[tl] = 0;
                                print("  <- "); print(t); print("\n");
                            }
                            off += L;
                        }
                    }
                }
            }
        } else if (streq(line, "wsserve") || startswith(line, "wsserve ")) {
            /* wsserve [port] — accept ONE WebSocket client on `port` (default 8080)
             * and echo its frames back, then report. The server side of the M1849
             * from-scratch WebSocket (RFC 6455 handshake w/ SHA-1 accept key). */
            const char *p = streq(line, "wsserve") ? "" : line + 7;
            while (*p == ' ') p++;
            int port = 0; while (*p >= '0' && *p <= '9') port = port * 10 + (*p++ - '0');
            if (port <= 0) port = 8080;
            char num[12]; itoa_simple(port, num);
            print("wsserve: listening for one WebSocket client on port "); print(num); print(" (~60s)...\n");
            char last[256]; int nf = 0;
            long r = sys_ws_serve(port, last, sizeof last, &nf);
            if (r < 0) { print("wsserve: no client connected / not a WebSocket handshake\n"); g_status = 1; }
            else {
                itoa_simple(nf, num);
                print("wsserve: served 1 client, echoed "); print(num); print(" frame(s)");
                if (nf > 0) { print("; last message: \""); print(last); print("\""); }
                print("\n");
            }
        } else if (startswith(line, "headers ")) {
            /* curl -I style: show just the HTTP response headers — status line,
             * Content-Type, redirects (Location:) — that 'browse' hides. Reuses
             * the same fetch; a 2 KB buffer suffices since headers lead the body. */
            char host[64], path[160]; int i = 0; char *p = line + 8;
            while (*p == ' ') p++;
            int secure = 0;
            if (startswith(p, "https://")) { secure = 1; p += 8; }
            else if (startswith(p, "http://")) { p += 7; }
            while (*p && *p != ' ' && *p != '/' && i < 63) host[i++] = *p++; host[i] = 0; sh_unprot_buf(host);
            if (*p == '/') { int j = 0; while (*p && *p != ' ' && j < 159) path[j++] = *p++; path[j] = 0; }
            else { path[0] = '/'; path[1] = 0; }
            sh_unprot_buf(path);
            if (host[0] == 0) { print("usage: headers [http(s)://]<host>[/path]\n"); }
            else {
                static char resp[2048];
                print(secure ? "headers https://" : "headers http://"); print(host); print(path); print(" ...\n");
                long n = secure ? sys_https(host, path, resp, sizeof(resp) - 1)
                                : sys_http(host, path, resp, sizeof(resp) - 1);
                if (n < 0) print("headers: failed (no net/DNS/connect)\n");
                else {
                    int end = (int)n;                        /* print up to the blank line */
                    for (int t = 0; t + 3 < (int)n; t++)
                        if (resp[t]=='\r'&&resp[t+1]=='\n'&&resp[t+2]=='\r'&&resp[t+3]=='\n') { end = t + 2; break; }
                    resp[end] = 0;
                    print(resp); print("\n");
                }
            }
        } else if (startswith(line, "wget ")) {
            /* download a URL's body to a file: wget <host>[/path] <outfile> */
            char host[64], path[160], out[32];
            char *p = line + 5; while (*p == ' ') p++;
            int secure = 0;                            /* https:// -> download over TLS */
            if (startswith(p, "https://")) { secure = 1; p += 8; }
            else if (startswith(p, "http://")) { p += 7; }
            int i = 0; while (*p && *p != ' ' && *p != '/' && i < 63) host[i++] = *p++; host[i] = 0; sh_unprot_buf(host);
            if (*p == '/') { int j = 0; while (*p && *p != ' ' && j < 159) path[j++] = *p++; path[j] = 0; }
            else { path[0] = '/'; path[1] = 0; }
            sh_unprot_buf(path);
            while (*p == ' ') p++;
            int k = 0; while (*p && *p != ' ' && k < 31) out[k++] = *p++; out[k] = 0; sh_unprot_buf(out);
            if (host[0] == 0 || out[0] == 0) { print("usage: wget [http(s)://]<host>[/path] <outfile>\n"); }
            else {
                char *wbuf = malloc(1u << 20);           /* 1MB download buffer (was a fixed 16KB) */
                print(secure ? "downloading https://" : "downloading http://"); print(host); print(path); print(" ...\n");
                long n = !wbuf ? -1 : (secure ? sys_https(host, path, wbuf, (1u << 20) - 1)
                                              : sys_http(host, path, wbuf, (1u << 20) - 1));
                if (n < 0) { print("wget: failed (no net/DNS/connect, or out of memory)\n"); }
                else {
                    int bo = 0;                              /* skip HTTP headers -> body */
                    for (int t = 0; t + 3 < (int)n; t++)
                        if (wbuf[t]=='\r'&&wbuf[t+1]=='\n'&&wbuf[t+2]=='\r'&&wbuf[t+3]=='\n') { bo = t + 4; break; }
                    long bl = n - bo;
                    if (sys_writefile(out, wbuf + bo, (unsigned long)bl) < 0) print("wget: write failed\n");
                    else {
                        char num[12]; itoa_simple((int)bl, num);
                        print("saved "); print(num); print(" bytes to "); print(out); print("\n");
                    }
                }
                free(wbuf);
            }
        } else if (startswith(line, "browse ")) {
            sh_unprot_buf(line + 7);
            sys_browse(line + 7);
            print("opening browser: "); print(line + 7); print("\n");
        } else if (streq(line, "apps")) {
            char b[256];
            if (sys_apps(b, sizeof(b)) > 0) {
                print("apps: "); print(b); print("\n");
                print("(launch: run <name>, or the F9 Apps menu)\n");
            } else print("apps: (none)\n");
        } else if (startswith(line, "play ")) {            /* play a .wav in the background (non-blocking) */
            char *f = line + 5; while (*f == ' ') f++;
            char fn[64]; int fi = 0; while (*f && *f != ' ' && fi < 63) fn[fi++] = *f++; fn[fi] = 0; sh_unprot_buf(fn);
            if (!fn[0]) print("usage: play <file.wav>\n");
            else print(sys_playbg(fn) == 0 ? "play: started in the background ('stop' to halt)\n"
                                           : "play: not a 16-bit PCM WAV (or no file)\n");
        } else if (streq(line, "stop")) {                  /* stop background audio */
            sys_audiostop();
            print("stopped\n");
        } else if (startswith(line, "tone")) {             /* play a tone via AC'97: tone [hz] [ms] */
            const char *p = line + 4; while (*p == ' ') p++;
            int hz = 0; while (*p >= '0' && *p <= '9') hz = hz * 10 + (*p++ - '0');
            while (*p == ' ') p++;
            int ms = 0; while (*p >= '0' && *p <= '9') ms = ms * 10 + (*p++ - '0');
            if (hz <= 0) hz = 440;
            if (ms <= 0) ms = 400;
            if (ms > 5000) ms = 5000;
            int nframes = 48 * ms;                          /* 48000 Hz */
            short *buf = malloc((unsigned long)nframes * 4);
            if (!buf) print("tone: out of memory\n");
            else {
                int period = 48000 / hz; if (period < 2) period = 2;
                for (int i = 0; i < nframes; i++) {         /* a square wave (fundamental = hz) */
                    short s = ((i % period) < period / 2) ? 8000 : -8000;
                    buf[i * 2] = s; buf[i * 2 + 1] = s;
                }
                sys_pcm(buf, nframes);
                free(buf);
                print("tone: played\n");
            }
        } else if (startswith(line, "run ")) {           /* run <prog> [arg] — e.g. `run editor README.TXT` */
            const char *p = line + 4; while (*p == ' ') p++;
            char prog[64]; int pi = 0; while (*p && *p != ' ' && pi < 63) prog[pi++] = *p++; prog[pi] = 0; sh_unprot_buf(prog);
            while (*p == ' ') p++;
            char arg[64]; int ai = 0; while (*p && *p != ' ' && ai < 63) arg[ai++] = *p++; arg[ai] = 0; sh_unprot_buf(arg);
            long rc = arg[0] ? sys_spawn_arg(prog, arg) : sys_spawn(prog);
            if (rc < 0) print("run: no such program. type 'apps' for the list (or run a disk .elf)\n");
            else { print("launched "); print(prog); print("\n"); }
        } else if (startswith(line, "file ")) {            /* identify a file's type by its magic bytes */
            char *f = line + 5; int any = 0;
            while (*f) {                                 /* identify each space-separated file */
                while (*f == ' ') f++;
                if (!*f) break;
                char fn[64]; int fi = 0; while (*f && *f != ' ' && fi < 63) fn[fi++] = *f++; fn[fi] = 0; sh_unprot_buf(fn);
                any = 1;
                static unsigned char b[512];
                long n = sys_readfile(fn, b, sizeof(b));
                if (n < 0) { print(fn); print(": no such file\n"); g_status = 1; }
                else {
                    const char *t;
                    if (n>=8 && b[0]==0x89&&b[1]=='P'&&b[2]=='N'&&b[3]=='G') t = "PNG image";
                    else if (n>=4 && b[0]=='G'&&b[1]=='I'&&b[2]=='F'&&b[3]=='8') t = "GIF image";
                    else if (n>=3 && b[0]==0xFF&&b[1]==0xD8&&b[2]==0xFF) t = "JPEG image";
                    else if (n>=2 && b[0]=='B'&&b[1]=='M') t = "BMP image";
                    else if (n>=4 && b[0]=='<'&&(b[1]|32)=='s'&&(b[2]|32)=='v'&&(b[3]|32)=='g') t = "SVG image";
                    else if (n>=2 && b[0]==0x1F&&b[1]==0x8B) t = "gzip compressed data";
                    else if (n>=4 && b[0]=='P'&&b[1]=='K'&&b[2]==3&&b[3]==4) t = "Zip archive";
                    else if (n>262 && b[257]=='u'&&b[258]=='s'&&b[259]=='t'&&b[260]=='a'&&b[261]=='r') t = "tar archive";
                    else if (n>=18 && b[0]==0x7F&&b[1]=='E'&&b[2]=='L'&&b[3]=='F') t = (b[16]==4) ? "ELF core dump" : "ELF executable";  /* e_type at off 16: 4=ET_CORE */
                    else {
                        int txt = 1;             /* printable -> text, else binary data */
                        for (long i = 0; i < n; i++) { unsigned char c = b[i];
                            if (!(c=='\n'||c=='\r'||c=='\t'||(c>=32&&c<127))) { txt = 0; break; } }
                        t = txt ? "ASCII text" : "data";
                    }
                    print(fn); print(": "); print(t); print("\n");
                }
            }
            if (!any) print("usage: file <name>...\n");
        } else if (startswith(line, "tar ")) {             /* extract a .tar / .tar.gz archive */
            char *t = line + 4; while (*t == ' ') t++;
            char tn[64]; int ti = 0; while (*t && *t != ' ' && ti < 63) tn[ti++] = *t++; tn[ti] = 0; sh_unprot_buf(tn);
            if (tn[0] == 0) print("usage: tar <file.tar|file.tgz>\n");
            else {
                long n = sys_untar(tn);
                if (n < 0) print("tar: failed (not a tar, too big, or missing)\n");
                else { char nb[12]; itoa_simple((int)n, nb); print("tar: extracted "); print(nb); print(" file(s)\n"); }
            }
        } else if (startswith(line, "unzip ")) {           /* extract a .zip archive (reuses the DEFLATE decoder) */
            char *z = line + 6; while (*z == ' ') z++;
            char zn[64]; int zi = 0; while (*z && *z != ' ' && zi < 63) zn[zi++] = *z++; zn[zi] = 0; sh_unprot_buf(zn);
            if (zn[0] == 0) print("usage: unzip <file.zip>\n");
            else {
                long n = sys_unzip(zn);
                if (n < 0) print("unzip: failed (not a .zip, too big, or missing)\n");
                else { char nb[12]; itoa_simple((int)n, nb); print("unzip: extracted "); print(nb); print(" file(s)\n"); }
            }
        } else if (startswith(line, "gzip ")) {            /* compress a file with the from-scratch DEFLATE encoder */
            char src[64]; int i = 0; char *p = line + 5;
            while (*p == ' ') p++;
            while (*p && *p != ' ' && i < 63) src[i++] = *p++;
            src[i] = 0; sh_unprot_buf(src);
            while (*p == ' ') p++;
            char dst[64]; int j = 0;
            if (*p) { while (*p && *p != ' ' && j < 63) dst[j++] = *p++; dst[j] = 0; sh_unprot_buf(dst); }
            else {                                          /* no DST: basename (drop ext) + ".GZ" */
                int L = 0; while (src[L]) L++;
                int dot = -1; for (int k = 0; k < L; k++) if (src[k] == '.') dot = k;
                int b = dot >= 0 ? dot : L;
                for (int k = 0; k < b && j < 60; k++) dst[j++] = src[k];
                dst[j++] = '.'; dst[j++] = 'G'; dst[j++] = 'Z'; dst[j] = 0;
            }
            if (src[0] == 0) print("usage: gzip <file> [out.gz]\n");
            else {
                long n = sys_gzip(src, dst);
                if (n < 0) print("gzip: failed (missing or too big)\n");
                else { char nb[12]; itoa_simple((int)n, nb); print("gzip: wrote "); print(dst); print(" ("); print(nb); print(" bytes)\n"); }
            }
        } else if (startswith(line, "gunzip ")) {          /* decompress a .gz file (reuses the DEFLATE decoder) */
            char src[64]; int i = 0; char *p = line + 7;
            while (*p == ' ') p++;
            while (*p && *p != ' ' && i < 63) src[i++] = *p++;
            src[i] = 0; sh_unprot_buf(src);
            while (*p == ' ') p++;
            char dst[64]; int j = 0;
            if (*p) { while (*p && *p != ' ' && j < 63) dst[j++] = *p++; dst[j] = 0; sh_unprot_buf(dst); }
            else {                                          /* no DST given: strip a trailing .gz, else "OUT" */
                int L = 0; while (src[L]) L++;
                if (L > 3 && src[L-3]=='.' && (src[L-2]=='g'||src[L-2]=='G') && (src[L-1]=='z'||src[L-1]=='Z')) {
                    for (int k = 0; k < L-3; k++) dst[k] = src[k]; dst[L-3] = 0;
                } else { dst[0]='O'; dst[1]='U'; dst[2]='T'; dst[3]=0; }
            }
            if (src[0] == 0) print("usage: gunzip <file.gz> [out]\n");
            else {
                long n = sys_gunzip(src, dst);
                if (n < 0) print("gunzip: failed (not a .gz, too big, or missing)\n");
                else { char nb[12]; itoa_simple((int)n, nb); print("gunzip: wrote "); print(dst); print(" ("); print(nb); print(" bytes)\n"); }
            }
        } else if ((startswith(line, "cp ") || startswith(line, "mv ")) && nargs(line + 3) > 2) {
            /* multi-file: cp/mv SRC... DESTDIR  (e.g. `cp *.txt backup`). The 2-arg
             * form is handled by the next branch, untouched. The last token is the
             * destination, which must be an existing directory; mv deletes each
             * source only after its copy succeeds. */
            int move = (line[0] == 'm');
            char tbuf[256]; int tn = 0; char *av[16]; int ac = 0;
            const char *q = line + 3;
            while (*q && ac < 16) {
                while (*q == ' ') q++;
                if (!*q) break;
                if (tn >= 255) break;        /* no room for another token + its NUL: stop (else tbuf[tn++]=0 writes past tbuf[256] + stores a dangling av[]) */
                av[ac++] = tbuf + tn;
                while (*q && *q != ' ' && tn < 255) tbuf[tn++] = *q++;
                tbuf[tn++] = 0;
            }
            for (int i = 0; i < ac; i++) sh_unprot_buf(av[i]);   /* restore quoted bytes in each path */
            const char *dest = av[ac - 1];
            int destdir = 0;
            if (sys_chdir(dest) >= 0) { destdir = 1; sys_chdir(cwd); }
            if (!destdir) { print(move?"mv":"cp"); print(": target is not a directory: "); print(dest); print("\n"); g_status = 1; }
            else for (int s = 0; s < ac - 1; s++) {
                const char *srcf = av[s];
                long n; char *buf = slurp(srcf, &n);
                if (!buf) { print(move?"mv":"cp"); print(": no such file: "); print(srcf); print("\n"); continue; }
                const char *base = srcf; for (const char *t = srcf; *t; t++) if (*t == '/') base = t + 1;
                char dpath[160]; int d = 0; for (const char *t = dest; *t && d < 158; t++) dpath[d++] = *t;
                if (d > 0 && dpath[d-1] != '/' && d < 158) dpath[d++] = '/';
                for (const char *t = base; *t && d < 159; t++) dpath[d++] = *t;
                dpath[d] = 0;
                if (sys_writefile(dpath, buf, (unsigned long)n) < 0) { print(move?"mv":"cp"); print(": write failed: "); print(dpath); print("\n"); g_status = 1; }
                else { if (move) sys_delete(srcf); print(move?"moved ":"copied "); print(srcf); print(" -> "); print(dpath); print("\n"); }
                free(buf);
            }
        } else if (startswith(line, "cp ") || startswith(line, "mv ")) {
            int move = (line[0] == 'm');
            char src[64]; int i = 0; char *p = line + 3;
            while (*p == ' ') p++;
            while (*p && *p != ' ' && i < 63) src[i++] = *p++;
            src[i] = 0; sh_unprot_buf(src);
            while (*p == ' ') p++;
            sh_unprot_buf(p);                         /* destination may be quoted */
            if (src[0] == 0 || *p == 0) { print("usage: "); print(move?"mv":"cp"); print(" <src> <dst>\n"); }
            else if (sys_chdir(src) >= 0) {        /* src is a directory */
                sys_chdir(cwd);
                char dst[128]; { int d = 0; for (const char *s = p; *s && d < 127; s++) dst[d++] = *s; dst[d] = 0; }
                if (move && !streq(src, dst) && sys_rename(src, dst) >= 0)   /* a real rename can move a directory (ext2; M1213) */
                    { print("moved "); print(src); print(" -> "); print(dst); print("\n"); }
                else { print(move ? "mv" : "cp"); print(": "); print(src); print(" is a directory (cp/mv -r unsupported; rename only within an ext2 mount)\n"); g_status = 1; }
            }
            else {
                /* file size is unknown (no stat syscall): read into a heap buffer,
                 * doubling it until the read no longer fills it. Fixes the old
                 * fixed 4KB buffer that silently truncated files >4KB (and, for
                 * mv, deleted the source after a short copy — data loss). */
                unsigned long cap = 65536;
                char *buf = malloc(cap);
                long n = buf ? sys_readfile(src, buf, cap) : -1;
                while (buf && n == (long)cap && cap < (32UL << 20)) {  /* read filled the buffer: file may be larger */
                    cap <<= 1; free(buf); buf = malloc(cap);
                    if (buf) n = sys_readfile(src, buf, cap);
                }
                if (!buf)                print("cp/mv: file too large (out of memory)\n");
                else if (n < 0)          print("no such file\n");
                else if (n == (long)cap) print("cp/mv: file too large to copy\n");
                else {
                    /* If the destination is a directory, copy into it as dir/basename(src). */
                    char dst[128]; int isdir = 0;
                    if (sys_chdir(p) >= 0) { isdir = 1; sys_chdir(cwd); }
                    if (isdir) {
                        const char *base = src; for (const char *s = src; *s; s++) if (*s == '/') base = s + 1;
                        int d = 0; for (const char *s = p; *s && d < 126; s++) dst[d++] = *s;
                        if (d > 0 && dst[d-1] != '/' && d < 126) dst[d++] = '/';
                        for (const char *s = base; *s && d < 127; s++) dst[d++] = *s;
                        dst[d] = 0;
                    } else { int d = 0; for (const char *s = p; *s && d < 127; s++) dst[d++] = *s; dst[d] = 0; }
                    if (move && !streq(src, dst) && sys_rename(src, dst) >= 0) {   /* atomic rename fast path (M1213; ext2 same-mount, else falls through to copy+delete) */
                        print("moved "); print(src); print(" -> "); print(dst); print("\n");
                    } else if (sys_writefile(dst, buf, (unsigned long)n) < 0) print("write failed\n");
                    else {
                        if (move && !streq(src, dst)) sys_delete(src);   /* never delete when src==dst */
                        print(move ? "moved " : "copied "); print(src);
                        print(" -> "); print(dst); print("\n");
                    }
                }
                free(buf);
            }
        } else if (startswith(line, "rm ")) {
            const char *p = line + 3; int any = 0, force = 0;   /* remove each space-separated file (so `rm *.tmp` / `rm a b` work); -f ignores missing */
            while (*p) {
                while (*p == ' ') p++;
                if (!*p) break;
                char name[64]; int j = 0;
                while (*p && *p != ' ' && j < 63) name[j++] = *p++;
                name[j] = 0; sh_unprot_buf(name);
                if (streq(name, "-f")) { force = 1; continue; }   /* -f: force (no error / no $?=1 when a file is missing) */
                any = 1;
                if (sys_delete(name) < 0) { if (!force) { perr("rm: no such file, or dir not empty: "); print(name); print("\n"); g_status = 1; } }
                else { print("removed "); print(name); print("\n"); }
            }
            if (!any && !force) print("usage: rm <file>...\n");
        } else if (startswith(line, "touch ")) {
            const char *p = line + 6; int any = 0;       /* touch each space-separated file */
            while (*p) {
                while (*p == ' ') p++;
                if (!*p) break;
                char name[64]; int j = 0;
                while (*p && *p != ' ' && j < 63) name[j++] = *p++;
                name[j] = 0; sh_unprot_buf(name); any = 1;
                char probe[1];
                if (sys_readfile(name, probe, 1) >= 0) { }      /* exists: leave content (no mtime API) */
                else if (sys_writefile(name, "", 0) < 0) { print("touch: failed: "); print(name); print("\n"); g_status = 1; }
                else { print("created "); print(name); print("\n"); }
            }
            if (!any) print("usage: touch <file>...\n");
        } else if (startswith(line, "edit ")) {
            char fname[32]; int i = 0;
            for (char *q = line + 5; *q && i < 31; q++) fname[i++] = *q;
            fname[i] = 0; sh_unprot_buf(fname);               /* quoted filename (e.g. edit "my file") */
            sys_setcolor(8); print("-- editor: type lines, '.' on its own line to save --\n"); sys_setcolor(0);   /* hint grey (M1341) */
            char doc[1024], l[128]; int dl = 0;
            for (;;) {
                sys_setcolor(4); print("> "); sys_setcolor(0);
                int n = readline(l, sizeof(l));
                if (n == 1 && l[0] == '.') break;
                for (int k = 0; l[k] && dl < 1023; k++) doc[dl++] = l[k];
                if (dl < 1023) doc[dl++] = '\n';
            }
            if (sys_writefile(fname, doc, dl) < 0) { sys_setcolor(2); print("edit: write failed\n"); sys_setcolor(0); }
            else { sys_setcolor(9); print("saved "); print(fname); sys_setcolor(0); print("\n"); }
        } else if (startswith(line, "hexedit ")) {   /* launch the GUI hex editor on a file (M1344) */
            const char *p = line + 8; while (*p == ' ') p++;
            char fn[64]; int i = 0; while (*p && *p != ' ' && i < 63) fn[i++] = *p++; fn[i] = 0; sh_unprot_buf(fn);
            if (!fn[0]) { print("usage: hexedit <file>\n"); g_status = 2; }
            else if (sys_spawn_arg("hexedit", fn) < 0) { print("hexedit: launch failed\n"); g_status = 1; }
            else { print("launched hexedit on "); print(fn); print("\n"); }
        } else if (startswith(line, "write ")) {
            char *p = line + 6, fname[32]; int i = 0;
            while (*p && *p != ' ' && i < 31) fname[i++] = *p++;
            fname[i] = 0; sh_unprot_buf(fname);
            if (*p == ' ') p++;
            sh_unprot_buf(p);                            /* reveal quoted spaces/metachars in the content */
            long n = sys_writefile(fname, p, ustrlen(p));
            if (n < 0) print("write: failed\n");
            else { print("wrote "); print(fname); print("\n"); }
        } else if (streq(line, "return") || startswith(line, "return ")) {
            const char *a = line + 6; while (*a == ' ') a++;   /* `return [N]`: set $? to N (bare return keeps the last status) */
            if (*a) g_status = (int)sh_str2long(a);
            g_returning = 1;           /* stop the enclosing function body / sourced script */
        } else if (streq(line, "break") || streq(line, "continue")) {
            if (g_loopdepth > 0) g_loopbrk = (line[0] == 'b') ? 1 : 2;   /* consumed by the innermost loop; no-op outside one */
            g_status = 0;
        } else if (line[0] == '(' && line[1] == '(') {     /* (( expr )) arithmetic command: do assignment / eval; $? = (value != 0) ? 0 : 1 */
            char ex[256]; int el = 0; const char *q = line + 2;
            while (*q && el < 255) ex[el++] = *q++;
            while (el > 0 && ex[el-1] == ' ') el--;
            if (el >= 2 && ex[el-1] == ')' && ex[el-2] == ')') el -= 2;   /* drop the closing )) */
            ex[el] = 0;
            long v = sh_do_assign(ex);
            g_status = v ? 0 : 1;
        } else if (streq(line, "exit")) {
            print("bye!\n");
            return 1;                  /* signal main()'s loop to stop */
        } else {
            /* Not a builtin: fall back to launching a program of that name (so
             * `cc DEMO.C`, `editor X.TXT`, `forth` etc. work without `run `).
             * First token = program; optional second token = its launch arg. */
            const char *p = line;
            char prog[64]; int pi = 0; while (*p && *p != ' ' && pi < 63) prog[pi++] = *p++; prog[pi] = 0; sh_unprot_buf(prog);
            while (*p == ' ') p++;
            char arg[64]; int ai = 0; while (*p && *p != ' ' && ai < 63) arg[ai++] = *p++; arg[ai] = 0; sh_unprot_buf(arg);
            long rc = arg[0] ? sys_spawn_arg(prog, arg) : sys_spawn(prog);
            if (rc < 0) {
                sys_setcolor(2); print("unknown command: ");      /* errors in red so they stand out (M1378) */
                print(line);
                print("  (try 'help')\n"); sys_setcolor(0);
                g_status = 1;
            } else g_status = 0;
        }
    } while (0);
    return 0;
}

/*
 * Run a pipeline: split `line` on the first '|' into two commands and feed the
 * first command's captured output to the second as a trailing file argument.
 *
 * Model: capture cmd1's output into a buffer (cap_begin/cap_end), write it to
 * a temp file, then run `cmd2 PIPE.TMP`. This needs no per-command stdin
 * support — the file-reading commands (grep/wc/sort/head/tail/cat/nl/...) read
 * their last argument via sys_readfile, which now reads the piped data.
 *
 * Supports N stages by looping: each stage after the first reads PIPE.TMP and
 * its output replaces it for the next '|'. The capture buffer grows on demand
 * (cap_begin/cap_end over a heap buffer, up to 32MB), so a stage's output is no
 * longer truncated at a fixed size.
 */
/* Write a command's captured output to a file: overwrite for ">", append for
 * ">>" (append reads the existing contents first, capped to the buffer). */
static void write_redirect(const char *file, const char *buf, unsigned long len, int append) {
    if (append) {
        long oldlen; char *old = slurp(file, &oldlen);     /* read the WHOLE existing file (was capped at 8KB) */
        unsigned long ol = (old && oldlen > 0) ? (unsigned long)oldlen : 0;
        char *combined = malloc(ol + len + 1);
        if (combined) {
            for (unsigned long i = 0; i < ol;  i++) combined[i]      = old[i];
            for (unsigned long i = 0; i < len; i++) combined[ol + i] = buf[i];
            sys_writefile(file, combined, ol + len);       /* existing + appended */
            free(combined);
        }
        free(old);                                         /* free(NULL) is safe */
    } else {
        sys_writefile(file, buf, len);
    }
}

static void run_pipe(char *line, char *cwd, const char *rfile, int append) {
    char cmd[160];                     /* the current stage's command line (cmd2 + " PIPE.TMP") */
    const char *seg = line;            /* start of the current segment */
    int first = 1;

    for (;;) {
        /* find the end of this segment: next unescaped '|' or end of string */
        const char *bar = seg;
        while (*bar && *bar != '|') bar++;

        /* copy the segment into cmd[], trimming leading/trailing spaces */
        const char *s = seg;
        while (*s == ' ') s++;                 /* skip leading spaces */
        const char *e = bar;
        while (e > s && (e[-1] == ' ')) e--;    /* trim trailing spaces */
        int ci = 0;
        while (s < e && ci < 158) cmd[ci++] = *s++;
        cmd[ci] = 0;

        if (!first && ci > 0) {                /* append the piped-in temp file as the last argument */
            const char *suf = " PIPE.TMP";
            for (int i = 0; suf[i] && ci < 159; i++) cmd[ci++] = suf[i];
            cmd[ci] = 0;
        }

        int last = (*bar != '|');              /* this is the final stage */

        if (ci == 0) {
            /* empty stage (e.g. "ls |" or "| grep"): nothing to run.
             * For the last stage, fall through so PIPE.TMP gets cleaned up. */
        } else if (last) {
            if (rfile) {                       /* final stage redirected to a file */
                cap_begin();
                run_command(cmd, cwd);
                unsigned long rlen; char *cb = cap_end(&rlen);
                if (cb) { write_redirect(rfile, cb, rlen, append); free(cb); }
            } else {
                run_command(cmd, cwd);         /* final stage: print to the screen */
            }
        } else {
            cap_begin();                       /* intermediate stage: capture its output */
            run_command(cmd, cwd);
            unsigned long len; char *cb = cap_end(&len);
            if (cb) { sys_writefile("PIPE.TMP", cb, len); free(cb); }
        }

        if (last) break;
        seg = bar + 1;
        first = 0;
    }

    sys_delete("PIPE.TMP");                     /* best-effort cleanup of the scratch file */
}

/* glob_match() (filename '*'/'?' globbing, iterative star/backtrack — no
 * catastrophic recursion) now lives in shgrep.h alongside gr_match, host-tested
 * by tests/shgrep.
 * Expand any '*'/'?' token in `src` against the current directory into `dst`
 * (other tokens pass through verbatim); a pattern with no match is left literal,
 * as a shell does. Output is length-bounded by dstsz (a huge match set truncates
 * rather than overflowing). Reuses sys_list — the same listing `ls` prints, one
 * "NAME size" per line — so the first whitespace-delimited field is the name. */
static void glob_expand(const char *src, char *dst, int dstsz){
    static char listing[8192];   /* hold a full directory so globs match every file */
    long ln = sys_list(listing, sizeof listing - 1); if (ln < 0) ln = 0; listing[ln] = 0;
    int dp = 0;
    const char *p = src;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *ts = p; while (*p && *p != ' ') p++; int tl = (int)(p - ts);
        int isglob = 0; for (int i = 0; i < tl; i++) if (ts[i] == '*' || ts[i] == '?') { isglob = 1; break; }
        int appended = 0;
        if (isglob) {
            char pat[64]; int pl = tl < 63 ? tl : 63; for (int i = 0; i < pl; i++) pat[i] = ts[i]; pat[pl] = 0;
            const char *q = listing;
            while (*q) {
                char name[64]; int ni = 0;
                while (*q && *q != ' ' && *q != '\n' && *q != '\r' && ni < 63) name[ni++] = *q++;
                name[ni] = 0;
                while (*q && *q != '\n') q++; if (*q) q++;          /* advance to the next line */
                if (ni && name[ni-1] != '/' && glob_match(pat, name)) {   /* skip dir entries (shown as NAME/) */
                    for (int i = 0; i < ni && dp < dstsz - 1; i++) dst[dp++] = name[i];
                    if (dp < dstsz - 1) dst[dp++] = ' ';
                    appended = 1;
                }
            }
        }
        if (!appended) {                                   /* non-glob token, or a glob with no match: keep literal */
            for (int i = 0; i < tl && dp < dstsz - 1; i++) dst[dp++] = ts[i];
            if (dp < dstsz - 1) dst[dp++] = ' ';
        }
    }
    if (dp > 0 && dst[dp-1] == ' ') dp--;                  /* trim the trailing separator */
    dst[dp] = 0;
}

/* Command substitution: replace each $(cmd) in `src` with the command's output
 * (trailing newlines stripped, internal newlines -> spaces for word splitting),
 * writing to `dst`. $((..)) arithmetic is left alone. Substitutions nest — e.g.
 * `$(echo $(echo x))` — up to a recursion cap; cap_begin/cap_end stack the output
 * buffers. Returns 1 if any substitution happened.
 * Shared by run_line (whole command) and run_for (the word list). */
static int in_cmdsub;
static int cmdsub_expand(const char *src, char *dst, int dstsz, char *cwd) {
    if (in_cmdsub >= 8) return 0;          /* runaway-recursion guard (CAP_STACK has the headroom) */
    int has = 0;
    for (int i = 0; src[i]; i++) if (src[i]=='$' && src[i+1]=='(' && src[i+2]!='(') { has = 1; break; }
    if (!has) return 0;
    int o = 0;
    for (int i = 0; src[i] && o < dstsz-1; ) {
        if (src[i]=='$' && src[i+1]=='(' && src[i+2]!='(') {
            int depth = 1, j = i + 2, s = j;
            while (src[j] && depth) { if (src[j]=='(') depth++; else if (src[j]==')') { depth--; if (!depth) break; } j++; }
            char inner[1024]; int ii = 0; for (int k = s; k < j && ii < 1023; k++) inner[ii++] = src[k]; inner[ii] = 0;
            in_cmdsub++; cap_begin(); run_input_line(inner, cwd);   /* run_input_line (not run_andor) so a `;` list and for/while/if work inside $() */
            unsigned long clen; char *cb = cap_end(&clen); in_cmdsub--;
            if (cb) {
                while (clen > 0 && cb[clen-1] == '\n') clen--;
                for (unsigned long k = 0; k < clen && o < dstsz-1; k++) dst[o++] = cb[k]=='\n' ? ' ' : cb[k];
                free(cb);
            }
            i = (src[j]==')') ? j + 1 : j;
        } else dst[o++] = src[i++];
    }
    dst[o] = 0;
    return 1;
}

/* Run one command line (a single ';'-separated segment): expand filename globs,
 * then peel off output redirection and pipelines, then dispatch. Returns 1 only
 * when the shell should exit (the "exit" command). */
static int run_line(char *line, char *cwd) {
    static char gline[1024], vline[1024], aline[1024], bline[1024], tline[1024];
    /* cmdsub_expand recurses back through run_line (a nested $(...)), so its dst
     * can't be one shared static buffer — the inner call would clobber the outer
     * one mid-build. Index by the cmdsub depth (in_cmdsub) instead. gline/vline/
     * aline stay shared: run_line touches them only after cmdsub_expand returns. */
    static char subline[9][1024];
    int sbi = in_cmdsub < 9 ? in_cmdsub : 8;
    sh_quote_pass(line);                          /* strip "..."/'...' + protect their specials, before any expansion/splitting */
    char *cmd = line;
    if (cmdsub_expand(cmd, subline[sbi], sizeof subline[0], cwd)) cmd = subline[sbi];   /* $(...) command substitution */
    if (expand_vars(cmd, vline, sizeof vline)) cmd = vline;   /* $NAME / ${NAME} variable expansion (before glob/pipe/redirect) */
    /* alias expansion: if the first word is an alias, substitute its value
     * (one level only, so a -> b -> a can't loop). */
    { int wl = 0; while (cmd[wl] && cmd[wl] != ' ') wl++;
      const char *av = wl ? alias_get(cmd, wl) : 0;
      if (av) { int o = 0;
          for (int i = 0; av[i] && o < 1023; i++) aline[o++] = av[i];
          for (int i = wl; cmd[i] && o < 1023; i++) aline[o++] = cmd[i];
          aline[o] = 0; cmd = aline; } }
    if (expand_tilde(cmd, tline, sizeof tline)) cmd = tline;    /* ~ / ~/x -> HOME (after vars/alias, before glob) */
    if (expand_braces(cmd, bline, sizeof bline)) cmd = bline;   /* {a,b} / {1..N} brace expansion (after vars, before glob) */
    if (cmd[0] == '(' && cmd[1] == '(')        /* (( expr )) arithmetic command: bypass glob/redirect/pipe — its */
        return run_command(cmd, cwd);          /* < > | * << >> are operators, not shell metacharacters */
    for (int i = 0; cmd[i]; i++) if (cmd[i] == '*' || cmd[i] == '?') {
        glob_expand(cmd, gline, sizeof gline); cmd = gline; break;
    }

    const char *rfile = 0; int append = 0;
    for (int i = 0; cmd[i]; i++) if (cmd[i] == '>') {
        if (cmd[i+1] == '>') { append = 1; rfile = &cmd[i+2]; } else { rfile = &cmd[i+1]; }
        cmd[i] = 0;
        while (i > 0 && cmd[i-1] == ' ') cmd[--i] = 0;   /* trim spaces before '>' so "cmd arg > f" doesn't pass "arg " (trailing space) on */
        while (*rfile == ' ') rfile++;
        char *fe = (char *)rfile; while (*fe) fe++; while (fe > rfile && fe[-1] == ' ') *--fe = 0;
        sh_unprot_buf((char *)rfile);                    /* quoted redirect target: cmd > "my file" */
        if (!*rfile) rfile = 0;
        break;
    }

    /* Here-string `cmd <<< STRING` (M1820): write STRING (+ a trailing newline) to
     * a temp file and rewrite to `cmd /tmp/HERESTR`, i.e. append it as the input
     * arg — the same file-arg convention the `<` redirect below uses. $VARs in
     * STRING are already expanded (expand_vars ran above). Handled before the
     * single-`<` scan so the `<<<` isn't mis-read as a plain input redirect. */
    for (int i = 0; cmd[i]; i++) if (cmd[i] == '<' && cmd[i+1] == '<' && cmd[i+2] == '<') {
        char *str = &cmd[i+3]; while (*str == ' ') str++;
        char sb[1024]; int sl = 0; while (str[sl] && sl < 1022) { sb[sl] = str[sl]; sl++; } sb[sl] = 0;
        sh_unprot_buf(sb);                                                   /* reveal quoted "..."/'...' bytes */
        int e2 = 0; while (sb[e2]) e2++; while (e2 > 0 && sb[e2-1] == ' ') sb[--e2] = 0;   /* trim trailing spaces */
        sb[e2++] = '\n';                                                     /* here-strings add one trailing newline */
        sys_writefile("/tmp/HERESTR", sb, (unsigned long)e2);
        cmd[i] = 0;
        while (i > 0 && cmd[i-1] == ' ') cmd[--i] = 0;                       /* trim spaces before <<< */
        int e = i; if (e < 1008) cmd[e++] = ' ';
        const char *tf = "/tmp/HERESTR"; for (int k = 0; tf[k] && e < 1022; k++) cmd[e++] = tf[k]; cmd[e] = 0;
        break;
    }

    /* Input redirect `cmd < file`: our commands read a file argument, so rewrite
     * it to `cmd file` (append the input file as a trailing arg). The result is
     * never longer than the original, so it rewrites cmd[] in place safely. */
    for (int i = 0; cmd[i]; i++) if (cmd[i] == '<') {
        char *infile = &cmd[i+1]; while (*infile == ' ') infile++;
        char fcopy[160]; int fc = 0; while (infile[fc] && infile[fc] != ' ' && fc < 159) { fcopy[fc] = infile[fc]; fc++; } fcopy[fc] = 0;
        cmd[i] = 0;
        while (i > 0 && cmd[i-1] == ' ') cmd[--i] = 0;   /* trim spaces before '<' */
        if (fcopy[0]) { int e = i; if (e < 1022) cmd[e++] = ' '; for (int k = 0; fcopy[k] && e < 1022; k++) cmd[e++] = fcopy[k]; cmd[e] = 0; }
        break;
    }

    if (g_xtrace && *cmd) {                          /* `set -x` trace: show the fully-expanded command */
        char tr[256]; int ti = 0; for (int k = 0; cmd[k] && ti < 255; k++) tr[ti++] = cmd[k]; tr[ti] = 0;
        sh_unprot_buf(tr);                           /* reveal any quoted (high-bit) bytes so the trace is readable */
        print("+ "); print(tr); print("\n");
    }
    int piped = 0;
    for (int i = 0; cmd[i]; i++) if (cmd[i] == '|') { piped = 1; break; }

    if (piped) { run_pipe(cmd, cwd, rfile, append); return 0; }
    if (rfile) {
        cap_begin();
        run_command(cmd, cwd);
        unsigned long rlen; char *cb = cap_end(&rlen);
        if (cb) { write_redirect(rfile, cb, rlen, append); free(cb); }
        return 0;
    }
    return run_command(cmd, cwd);                /* 1 only for "exit" */
}

/* Run a ';'-separated segment that may contain && / || operators, left to
 * right, honouring each command's exit status ($?: 0 = success). A single |
 * (pipe) or & is left intact for run_line — only the doubled forms are operators
 * here, and they're matched on the raw text so arithmetic like $((a & b)) is
 * untouched. Returns 1 if a command was the "exit" builtin. */
static int run_andor(char *seg, char *cwd) {
    char *p = seg;
    int run_this = 1, exitflag = 0, skipped = 0;   /* skipped: a segment was short-circuited past (its failure was "used" by &&/||) */
    while (p) {
        char *op = p; int oplen = 0, pd = 0, q = 0;
        while (*op) {
            if (q) { if (*op == q) q = 0; op++; continue; }                   /* inside "..."/'...': &&/|| are literal */
            if (*op == '"' || *op == '\'') { q = *op; op++; continue; }
            if (op[0] == '$' && op[1] == '(') { pd++; op += 2; continue; }   /* enter $( or $(( : its &&/|| are arithmetic/command-sub, not ours */
            if (pd > 0) { if (*op == '(') pd++; else if (*op == ')') pd--; op++; continue; }
            if ((op[0] == '&' && op[1] == '&') || (op[0] == '|' && op[1] == '|')) { oplen = 2; break; }
            op++;
        }
        char opc = oplen ? op[0] : 0;
        if (oplen) *op = 0;                            /* terminate this command */
        while (*p == ' ') p++;                         /* trim leading spaces */
        char *e = p; while (*e) e++;                   /* ...and trailing ones, so */
        while (e > p && e[-1] == ' ') *--e = 0;        /* "true && .." matches streq("true") */
        if (run_this && *p) { if (run_line(p, cwd)) exitflag = 1; }
        else if (*p) skipped = 1;                          /* short-circuited: this segment didn't run */
        if      (opc == '&') run_this = (g_status == 0);   /* &&: next runs only on success */
        else if (opc == '|') run_this = (g_status != 0);   /* ||: next runs only on failure */
        p = oplen ? op + oplen : 0;
    }
    /* `set -e`: abort the script if this complete list failed AND its failure was
     * not "used" by a &&/|| short-circuit (`false && x` doesn't fire; `x; false`
     * and `true && false` do) and we're not inside an if/while/until condition. */
    if (g_errexit && !g_cond_depth && !in_cmdsub && !skipped && g_status != 0) g_errexit_tripped = 1;
    return exitflag;
}

/* for VAR in WORDS; do BODY; done  (one line). WORDS get $var + glob expansion,
 * then BODY runs once per word with VAR bound to it. Buffers are on the stack so
 * nested loops don't clobber each other. */
/* Evaluate one C-style-for assignment piece: VAR=expr / VAR++ / VAR-- / VAR+=expr (and -=,*=,/=,%=).
 * Read parts use sh_eval (which resolves bare names); the assignment itself goes through vset. */
static long sh_do_assign(const char *e) {
    while (*e == ' ') e++;
    const char *vs = e; int vl = 0; while (sh_vchar(e[vl])) vl++;
    if (vl == 0) { const char *q = e; return *q ? sh_eval(&q) : 0; }   /* no lvalue -> just evaluate */
    const char *op = e + vl; while (*op == ' ') op++;
    char num[24];
    if (op[0]=='+' && op[1]=='+') { long o=sh_var(vs,vl); ltoa_simple(o+1, num); vset(vs,vl,num); return o; }   /* i++ (post: old value) */
    if (op[0]=='-' && op[1]=='-') { long o=sh_var(vs,vl); ltoa_simple(o-1, num); vset(vs,vl,num); return o; }   /* i-- */
    if (op[0]=='=' && op[1]!='=') { const char *q=op+1; long r=sh_eval(&q); ltoa_simple(r,num); vset(vs,vl,num); return r; }   /* i=expr */
    if (op[1]=='=' && (op[0]=='+'||op[0]=='-'||op[0]=='*'||op[0]=='/'||op[0]=='%')) {                       /* i+=expr etc. */
        const char *q=op+2; long r=sh_eval(&q), cur=sh_var(vs,vl), nv;
        switch(op[0]){ case '+':nv=cur+r;break; case '-':nv=cur-r;break; case '*':nv=cur*r;break; case '/':nv=r?cur/r:0;break; default:nv=r?cur%r:0; }
        ltoa_simple(nv,num); vset(vs,vl,num); return nv;
    }
    { const char *q=e; return sh_eval(&q); }                           /* bare expression (e.g. a comparison i<5) */
}
/* C-style loop: for ((init; cond; incr)); do CMDS; done. `p` points at the "((".
 * cond is a read-only sh_eval (empty == true); init/incr are assignments. */
static int run_for_carith(char *p, char *cwd) {
    /* Depth-tracked, like cmdsub_expand's $(...) scan: the first "))" at depth 0
     * (i.e. not the close of some inner nested "(...)" in cond/incr, e.g.
     * i<((n))) is the one that ends this construct. */
    char *close = 0; int depth = 0;
    for (char *q = p + 2; *q; q++) {
        if (*q == '(') depth++;
        else if (*q == ')') { if (depth > 0) depth--; else if (q[1] == ')') { close = q; break; } }
    }
    if (!close) { print("for: missing '))'\n"); g_status=1; return 0; }
    *close = 0;
    char *init = p + 2, *cond, *incr, *s1 = init, *s2;
    while (*s1 && *s1 != ';') s1++;
    if (*s1 != ';') { print("for: ((init; cond; incr))\n"); g_status=1; return 0; }
    *s1 = 0; cond = s1 + 1; s2 = cond;
    while (*s2 && *s2 != ';') s2++;
    if (*s2 != ';') { print("for: ((init; cond; incr))\n"); g_status=1; return 0; }
    *s2 = 0; incr = s2 + 1;
    char *a = close + 2; while (*a == ' ') a++; if (*a == ';') a++; while (*a == ' ') a++;
    if (!(a[0]=='d' && a[1]=='o' && (a[2]==' '||a[2]==0))) { print("for: missing 'do'\n"); g_status=1; return 0; }
    char *body = a + 2; while (*body == ' ') body++;
    int blen = (int)ustrlen(body); while (blen>0 && body[blen-1]==' ') body[--blen]=0;
    if (!(blen >= 4 && streq(body+blen-4, "done"))) { print("for: missing 'done'\n"); g_status=1; return 0; }
    blen -= 4; while (blen>0 && body[blen-1]==' ') blen--; if (blen>0 && body[blen-1]==';') blen--; while (blen>0 && body[blen-1]==' ') blen--;
    body[blen] = 0;
    sh_do_assign(init);                                                /* run init once */
    int doexit = 0, iters = 0; char bodybuf[1024];
    g_loopdepth++;
    while (!doexit) {
        if (iters++ >= 100000) { print("\nfor: stopped at 100000 iterations\n"); break; }
        int k = sys_pollkey(); if (k == 0x83 || k == 27) { print("\n^C\n"); break; }   /* Ctrl-C / Esc */
        { const char *q = cond; while (*q == ' ') q++; long cv = *q ? sh_eval(&q) : 1; if (!cv) break; }   /* empty cond = forever */
        int bi = 0; for (const char *c = body; *c && bi < 1023; c++) bodybuf[bi++] = *c; bodybuf[bi] = 0;
        if (run_input_line(bodybuf, cwd)) doexit = 1;
        if (g_returning || g_errexit_tripped) break;
        if (g_loopbrk) { int brk = (g_loopbrk == 1); g_loopbrk = 0; if (brk) break; }
        sh_do_assign(incr);
    }
    g_loopdepth--;
    return doexit;
}
static int run_for(char *line, char *cwd) {
    char *p = line + 3; while (*p == ' ') p++;             /* skip "for" */
    if (p[0] == '(' && p[1] == '(') return run_for_carith(p, cwd);   /* C-style for ((init; cond; incr)) */
    char var[32]; int vi = 0;
    while (*p && *p != ' ' && vi < 31) var[vi++] = *p++;
    var[vi] = 0;
    while (*p == ' ') p++;
    if (!(p[0]=='i' && p[1]=='n' && (p[2]==' '||p[2]==0))) { print("for: syntax: for V in WORDS; do CMDS; done\n"); g_status=1; return 0; }
    p += 2; while (*p == ' ') p++;
    char *list = p, *semi = p; while (*semi && *semi != ';') semi++;
    if (*semi != ';') { print("for: missing ';' before do\n"); g_status=1; return 0; }
    *semi = 0;
    char *q = semi + 1; while (*q == ' ') q++;
    if (!(q[0]=='d' && q[1]=='o' && (q[2]==' '||q[2]==0))) { print("for: missing 'do'\n"); g_status=1; return 0; }
    q += 2; while (*q == ' ') q++;
    char *body = q;
    int blen = (int)ustrlen(body);
    while (blen > 0 && body[blen-1]==' ') body[--blen]=0;
    if (!(blen >= 4 && streq(body+blen-4, "done"))) { print("for: missing 'done'\n"); g_status=1; return 0; }
    blen -= 4; while (blen>0 && body[blen-1]==' ') blen--;   /* drop "done" + a trailing "; " */
    if (blen>0 && body[blen-1]==';') blen--;
    while (blen>0 && body[blen-1]==' ') blen--;
    body[blen] = 0;
    char elist[1024], glist[1024], bodybuf[1024], sublist[1024], blist[1024];
    char *lst = list;
    if (cmdsub_expand(lst, sublist, sizeof sublist, cwd)) lst = sublist;   /* for f in $(cmd) */
    if (expand_vars(lst, elist, sizeof elist)) lst = elist;
    if (expand_braces(lst, blist, sizeof blist)) lst = blist;   /* {a,b} / {1..N}: run_for is dispatched from run_input_line, bypassing run_line's brace pass (M1748) */
    for (int i=0; lst[i]; i++) if (lst[i]=='*' || lst[i]=='?') { glob_expand(lst, glist, sizeof glist); lst = glist; break; }
    int doexit = 0;
    char *w = lst;
    g_loopdepth++;
    while (*w && !doexit) {
        while (*w == ' ') w++;
        if (!*w) break;
        char *we = w; while (*we && *we != ' ') we++;
        char wsave = *we; *we = 0;
        sh_unprot_buf(w);                                   /* a quoted word: restore its protected bytes before binding */
        vset(var, vi, w);                                   /* bind the loop variable */
        *we = wsave;
        int bi = 0; for (const char *b = body; *b && bi < 1023; b++) bodybuf[bi++] = *b; bodybuf[bi] = 0;
        if (run_input_line(bodybuf, cwd)) doexit = 1;       /* fresh copy: run_input_line edits it in place */
        if (g_returning || g_errexit_tripped) break;        /* `return`, or a `set -e` trip, inside the loop body */
        if (g_loopbrk) { int brk = (g_loopbrk == 1); g_loopbrk = 0; if (brk) break; }   /* break stops; continue advances */
        w = we;
    }
    g_loopdepth--;
    return doexit;
}

/* First occurrence of needle in haystack (for the if/then/else markers). */
static char *sh_substr(char *h, const char *n) {
    for (; *h; h++) { int i = 0; while (n[i] && h[i] == n[i]) i++; if (!n[i]) return h; }
    return 0;
}

/* if COND; then THEN; [else ELSE;] fi  (one line). COND's exit status ($?)
 * picks the branch. THEN/ELSE may be ';'-separated lists (and nest), but a
 * nested if/else *inside* THEN on the same line can mis-bind its else — keep
 * deep nesting on separate lines (via source) or use && / ||. */
static int run_if(char *line, char *cwd) {
    char *p = line + 2; while (*p == ' ') p++;             /* skip "if" */
    char *thn = sh_substr(p, "; then");
    if (!thn) { print("if: missing '; then'\n"); g_status = 1; return 0; }
    *thn = 0;                                              /* COND = p */
    char *body = thn + 6; while (*body == ' ') body++;
    int blen = (int)ustrlen(body);
    while (blen > 0 && body[blen-1] == ' ') body[--blen] = 0;
    if (!(blen >= 2 && streq(body+blen-2, "fi"))) { print("if: missing 'fi'\n"); g_status = 1; return 0; }
    blen -= 2; while (blen>0 && body[blen-1]==' ') blen--;   /* drop "fi" + a trailing "; " */
    if (blen>0 && body[blen-1]==';') blen--;
    while (blen>0 && body[blen-1]==' ') blen--;
    body[blen] = 0;
    char *thenb = body, *elseb = 0;
    char elsebuf[1024];
    char *eif = sh_substr(body, "; elif ");                /* elif: the else-branch becomes a nested `if`, recursed via run_input_line */
    if (eif) {
        *eif = 0;                                          /* thenb = body up to "; elif" */
        const char *rest = eif + 7;                        /* "COND2; then BODY2 [; elif …] [; else …]" */
        int bi = 0; const char *pre = "if ";
        while (*pre) elsebuf[bi++] = *pre++;
        while (*rest && bi < 1019) elsebuf[bi++] = *rest++;
        const char *suf = "; fi"; while (*suf && bi < 1023) elsebuf[bi++] = *suf++;
        elsebuf[bi] = 0; elseb = elsebuf;
    } else {
        char *els = sh_substr(body, "; else");
        if (els) { *els = 0; elseb = els + 6; while (*elseb == ' ') elseb++; }
    }
    g_cond_depth++; run_input_line(p, cwd); g_cond_depth--; /* run COND -> sets g_status (COND is exempt from set -e) */
    if (g_status == 0) return run_input_line(thenb, cwd);
    if (elseb)         return run_input_line(elseb, cwd);
    return 0;
}

/* case WORD in PAT) CMDS;; PAT2|PAT3) CMDS;; *) CMDS;; esac
 * Expands $vars in WORD, then runs the FIRST arm whose '|'-separated glob pattern
 * (* ? literals, via glob_match) matches WORD. No fall-through; no match -> $? = 0. */
static int run_case(char *line, char *cwd) {
    char *p = line + 4; while (*p == ' ') p++;             /* skip "case" */
    char *inkw = sh_substr(p, " in ");
    if (!inkw) { print("case: missing 'in'\n"); g_status = 1; return 0; }
    *inkw = 0;                                             /* WORD = p */
    char wordbuf[256]; char *word = p;
    if (expand_vars(p, wordbuf, sizeof wordbuf)) word = wordbuf;   /* $x -> its value */
    while (*word == ' ') word++;
    { int wl = (int)ustrlen(word); while (wl > 0 && word[wl-1] == ' ') word[--wl] = 0; }
    char *body = inkw + 4; while (*body == ' ') body++;    /* arms, up to a trailing "esac" */
    int blen = (int)ustrlen(body);
    while (blen > 0 && body[blen-1] == ' ') body[--blen] = 0;
    if (!(blen >= 4 && streq(body + blen - 4, "esac"))) { print("case: missing 'esac'\n"); g_status = 1; return 0; }
    blen -= 4; while (blen > 0 && body[blen-1] == ' ') blen--;
    body[blen] = 0;
    g_status = 0;                                          /* no match -> success, like sh */
    char *arm = body;
    while (arm && *arm) {
        char *sep = sh_substr(arm, ";;"); char *next = 0;  /* this arm ends at the next ";;" */
        if (sep) { *sep = 0; next = sep + 2; }
        while (*arm == ' ' || *arm == ';') arm++;          /* trim leading sep/space */
        char *rp = arm; while (*rp && *rp != ')') rp++;    /* ')' splits patterns from commands */
        if (*rp == ')') {
            *rp = 0; char *cmds = rp + 1;
            int hit = 0; char *pat = arm;                  /* patterns are '|'-separated globs */
            while (pat && !hit) {
                char *bar = pat; while (*bar && *bar != '|') bar++;
                char psave = *bar; if (*bar) *bar = 0;
                char *pp = pat; while (*pp == ' ') pp++;
                { int pl = (int)ustrlen(pp); while (pl > 0 && pp[pl-1] == ' ') pp[--pl] = 0; }
                if (glob_match(pp, word)) hit = 1;
                if (psave) *bar = psave;
                pat = psave ? bar + 1 : 0;
            }
            if (hit) { run_input_line(cmds, cwd); return 0; }   /* first match wins; stop */
        }
        arm = next;
    }
    return 0;
}

/* while/until COND; do BODY; done  (one line). Re-runs COND each pass; `while`
 * loops while it succeeds ($? == 0), `until` loops while it fails (invert=1, M1807).
 * Bounded at 100000 iterations and interruptible with Ctrl-C / Esc so a runaway
 * loop can't hang the shell. "while" and "until" are both 5 chars. */
static int run_while_until(char *line, char *cwd, int invert) {
    const char *kw = invert ? "until" : "while";
    char *p = line + 5; while (*p == ' ') p++;             /* skip "while"/"until" */
    char *cond = p, *semi = p; while (*semi && *semi != ';') semi++;
    if (*semi != ';') { print(kw); print(": missing ';' before do\n"); g_status = 1; return 0; }
    *semi = 0;
    char *q = semi + 1; while (*q == ' ') q++;
    if (!(q[0]=='d' && q[1]=='o' && (q[2]==' '||q[2]==0))) { print(kw); print(": missing 'do'\n"); g_status = 1; return 0; }
    q += 2; while (*q == ' ') q++;
    char *body = q;
    int blen = (int)ustrlen(body);
    while (blen > 0 && body[blen-1]==' ') body[--blen]=0;
    /* M1811: optional `done < FILE` — feeds the `read` builtin inside the loop (while read line; do …; done < f).
     * Only probed when the body doesn't already end in "done", so an inner `cmd < f` in the body is untouched. */
    char readfile[160]; int has_readfile = 0; readfile[0] = 0;
    if (!(blen >= 4 && streq(body+blen-4, "done"))) {
        char *lt = 0; for (int k = 0; k < blen; k++) if (body[k] == '<') lt = body + k;   /* the last '<' */
        if (lt) {
            const char *fp = lt + 1; while (*fp == ' ') fp++;
            int fi = 0; while (*fp && fi < 159) readfile[fi++] = SH_UNPROT(*fp++);
            while (fi > 0 && readfile[fi-1] == ' ') fi--; readfile[fi] = 0;
            char *be = lt; while (be > body && be[-1] == ' ') be--; *be = 0; blen = (int)(be - body);   /* body := up to '<' */
            if (blen >= 4 && streq(body+blen-4, "done") && readfile[0]) has_readfile = 1;
        }
    }
    if (!(blen >= 4 && streq(body+blen-4, "done"))) { print(kw); print(": missing 'done'\n"); g_status = 1; return 0; }
    blen -= 4; while (blen>0 && body[blen-1]==' ') blen--;
    if (blen>0 && body[blen-1]==';') blen--;
    while (blen>0 && body[blen-1]==' ') blen--;
    body[blen] = 0;
    int doexit = 0, iters = 0;
    char condbuf[1024], bodybuf[1024];
    /* M1811: install the `read` source from `done < FILE`, saving any enclosing loop's source (nesting-safe) */
    char *rd_save_src = g_read_src; long rd_save_pos = g_read_pos, rd_save_len = g_read_len; int rd_save_reading = g_reading;
    char *rdbuf = 0;
    if (has_readfile) {
        long rn; rdbuf = slurp(readfile, &rn);
        if (rdbuf) { g_read_src = rdbuf; g_read_pos = 0; g_read_len = rn; g_reading = 1; }
        else { print(kw); print(": no such file: "); print(readfile); print("\n"); g_read_src = 0; g_read_pos = 0; g_read_len = 0; g_reading = 1; }  /* empty -> 0 iterations */
    }
    g_loopdepth++;
    while (!doexit) {
        if (iters >= 100000) { print("\n"); print(kw); print(": stopped at 100000 iterations\n"); break; }
        int k = sys_pollkey(); if (k == 0x83 || k == 27) { print("\n^C\n"); break; }   /* Ctrl-C / Esc */
        int ci = 0; for (const char *c = cond; *c && ci < 1023; c++) condbuf[ci++] = *c; condbuf[ci] = 0;
        g_cond_depth++; run_input_line(condbuf, cwd); g_cond_depth--;   /* COND is exempt from set -e */
        if (invert ? (g_status == 0) : (g_status != 0)) break;   /* while: stop when COND false; until: stop when COND true */
        int bi = 0; for (const char *c = body; *c && bi < 1023; c++) bodybuf[bi++] = *c; bodybuf[bi] = 0;
        if (run_input_line(bodybuf, cwd)) doexit = 1;
        if (g_returning || g_errexit_tripped) break;       /* `return`, or a `set -e` trip, inside the loop body */
        if (g_loopbrk) { int brk = (g_loopbrk == 1); g_loopbrk = 0; if (brk) break; }   /* break stops; continue re-tests COND */
        iters++;
    }
    g_loopdepth--;
    if (has_readfile) { free(rdbuf); g_read_src = rd_save_src; g_read_pos = rd_save_pos; g_read_len = rd_save_len; g_reading = rd_save_reading; }
    return doexit;
}
static int run_while(char *line, char *cwd) { return run_while_until(line, cwd, 0); }
static int run_until(char *line, char *cwd) { return run_while_until(line, cwd, 1); }

/* Run one logical input line: a ';'-separated list, where each item may be a
 * `for`/`while`/`if` construct or a && / || pipeline. The splitter tracks
 * control-construct nesting so a construct's internal ';'s aren't break points.
 * Returns 1 if it ran the `exit` builtin. */
static int run_input_line(char *line, char *cwd) {
    char *t = line; while (*t == ' ') t++;
    if (startswith(t, "js -e ")) { run_js_inline(t + 6); g_status = 0; return 0; }   /* literal code (its >|&; are JS, not shell) */
    { const char *q = t; while (*q && *q != ' ' && *q != '(') q++;   /* function definition: NAME() { body } */
      if (q > t && *q == '(' && q[1] == ')') {
          const char *b = q + 2; while (*b == ' ') b++;
          if (*b == '{') {
              const char *body = b + 1; while (*body == ' ') body++;
              /* Find the '}' that MATCHES this '{' by brace depth -- NOT the last
               * '}' in the line. The old last-'}' scan mis-captured a second def
               * ("a(){..}; b(){..}" swallowed b into a's body) and dropped any
               * command after a def ("greet(){..}; greet" never ran greet). M1749. */
              int depth = 1; const char *close = 0;
              for (const char *e = body; *e; e++) {
                  if (*e == '{') depth++;
                  else if (*e == '}' && --depth == 0) { close = e; break; }
              }
              if (close) {
                  char bb[256]; int bi = 0; for (const char *c = body; c < close && bi < 255; c++) bb[bi++] = *c;
                  while (bi > 0 && (bb[bi-1] == ' ' || bb[bi-1] == ';')) bi--;   /* trim trailing ; / space */
                  bb[bi] = 0;
                  func_set(t, (int)(q - t), bb); g_status = 0;
                  const char *rest = close + 1;                  /* run whatever follows the '}' (another def, or a call) */
                  while (*rest == ' ' || *rest == ';') rest++;
                  if (*rest) return run_input_line((char *)rest, cwd);
                  return 0;
              }
          }
      } }
    sh_quote_pass(line);                       /* strip "..."/'...' + protect their specials BEFORE the ;-split and
                                                * for/while/if/case dispatch, so quoting works in their word lists too
                                                * (func defs above stored their body raw -> processed at call time;
                                                * $(...) content is copied verbatim and quote-processed by its run_line) */
    char *seg = line; int doexit = 0;
    while (seg && !doexit) {
        char *semi = seg + sh_next_sep(seg);   /* next top-level ';' (skips $() and stays inside if…fi/while…done/for…done) */
        int more = (*semi == ';'); if (more) *semi = 0;
        while (*seg == ' ') seg++;
        if (*seg) {
            int rc;
            if (startswith(seg, "for "))        rc = run_for(seg, cwd);
            else if (startswith(seg, "while ")) rc = run_while(seg, cwd);
            else if (startswith(seg, "until ")) rc = run_until(seg, cwd);
            else if (startswith(seg, "if "))    rc = run_if(seg, cwd);
            else if (startswith(seg, "case "))  rc = run_case(seg, cwd);
            else                                rc = run_andor(seg, cwd);
            if (rc) doexit = 1;
        }
        if (g_returning || g_loopbrk || g_errexit_tripped) break;   /* `return`, `break`/`continue`, or a `set -e` trip stops the rest of this line */
        seg = more ? semi + 1 : 0;
    }
    return doexit;
}

/* Run shell commands from a file: each non-blank, non-'#' line goes through the
 * same executor as interactive input. `silent` suppresses the not-found message
 * (used for the optional startup .shrc). */
/* Index of a here-doc `<<` operator in a script line, or -1. Skips a `<<` that is
 * quoted, inside `((`/`$((` arithmetic, or actually `<<<` (a here-string, which
 * run_line handles on its own). (M1820) */
static int sh_heredoc_op(const char *s) {
    char q = 0; int paren = 0;
    for (int i = 0; s[i]; i++) {
        char c = s[i];
        if (q) { if (c == q) q = 0; continue; }
        if (c == '"' || c == '\'') { q = c; continue; }
        if (c == '(') { paren++; continue; }
        if (c == ')') { if (paren > 0) paren--; continue; }
        if (paren > 0) continue;                       /* inside (...) / $((...)): << is arithmetic */
        if (c == '<' && s[i+1] == '<') {
            if (s[i+2] == '<') { i += 2; continue; }    /* <<< here-string (handled in run_line) */
            return i;
        }
    }
    return -1;
}
/* Run a here-doc `cmd << [-]DELIM` whose `<<` is at t[hd]. Collects body lines from
 * `body` (the buffer just after this command line) up to a line == DELIM, writes them
 * to /tmp/HEREDOC, rewrites the command to read that file (reusing the file-arg
 * convention), runs it, and returns the buffer position just past the DELIM line (0 at
 * EOF). $VARs in the body expand unless DELIM was quoted; `<<-` strips leading tabs. */
static char *sh_run_heredoc(char *t, int hd, char *body, char *cwd) {
    int dash = (t[hd + 2] == '-');
    const char *d = t + hd + 2 + dash; while (*d == ' ' || *d == '\t') d++;
    int expand = 1; char q = 0;
    if (*d == '"' || *d == '\'') { q = *d; expand = 0; d++; }        /* quoted delimiter -> literal body */
    char delim[64]; int dl = 0;
    while (*d && dl < 63 && (q ? *d != q : (*d != ' ' && *d != '\t'))) delim[dl++] = *d++;
    delim[dl] = 0;
    if (q && *d == q) d++;
    while (*d == ' ' || *d == '\t') d++;
    const char *suffix = d;                                         /* e.g. "> out" after the delimiter */
    unsigned long cap = 1024, blen = 0; char *bbuf = malloc(cap);
    if (!bbuf) return body;
    char *ln = body;
    while (ln && *ln) {
        char *nl = ln; while (*nl && *nl != '\n') nl++;
        int more = (*nl == '\n'); if (more) *nl = 0;
        char *cmp = ln; if (dash) while (*cmp == '\t') cmp++;       /* <<- : the terminator may be tab-indented */
        if (streq(cmp, delim)) { ln = more ? nl + 1 : 0; break; }   /* delimiter line ends the body */
        char *bl = ln; if (dash) while (*bl == '\t') bl++;          /* <<- : strip leading tabs from body too */
        char exp[1024]; const char *out = bl;
        if (expand && expand_vars(bl, exp, sizeof exp)) out = exp;
        unsigned long olen = 0; while (out[olen]) olen++;
        if (blen + olen + 2 >= cap) { cap = (blen + olen + 2) * 2; char *nb = realloc(bbuf, cap); if (!nb) break; bbuf = nb; }
        for (unsigned long k = 0; k < olen; k++) bbuf[blen++] = out[k];
        bbuf[blen++] = '\n';
        ln = more ? nl + 1 : 0;
    }
    bbuf[blen] = 0;
    sys_writefile("/tmp/HEREDOC", bbuf, blen);
    free(bbuf);
    char rw[1024]; int p = 0;
    for (int k = 0; k < hd && p < 1000; k++) rw[p++] = t[k];
    while (p > 0 && rw[p - 1] == ' ') p--;                          /* trim spaces before << */
    const char *ins = " /tmp/HEREDOC "; for (int k = 0; ins[k] && p < 1010; k++) rw[p++] = ins[k];
    for (int k = 0; suffix[k] && p < 1022; k++) rw[p++] = suffix[k];
    rw[p] = 0;
    run_input_line(rw, cwd);
    return ln;
}
static void source_file(const char *fn, char *cwd, int silent) {
    if (source_depth >= 8) { if (!silent) print("source: nested too deep\n"); g_status = 1; return; }
    long n; char *txt = slurp(fn, &n);
    if (!txt) { if (!silent) { perr("source: no such file: "); print(fn); print("\n"); g_status = 1; } return; }
    source_depth++;
    char *ln = txt;
    while (ln && *ln) {
        char *nl = ln; while (*nl && *nl != '\n') nl++;
        int more = (*nl == '\n'); if (more) *nl = 0;
        char *t = ln; while (*t == ' ' || *t == '\t') t++;
        int hd = (*t && *t != '#') ? sh_heredoc_op(t) : -1;   /* `cmd << DELIM` here-doc? (M1820) */
        if (hd >= 0) {
            ln = sh_run_heredoc(t, hd, more ? nl + 1 : 0, cwd);   /* collects the body, runs, jumps past the delimiter */
        } else {
            if (*t && *t != '#') run_input_line(t, cwd);   /* skip blanks + # comments */
            ln = more ? nl + 1 : 0;
        }
        if (g_returning || g_errexit_tripped) break;   /* `return`, or a `set -e` failure, ends the sourced script */
    }
    g_returning = 0; g_loopbrk = 0; g_errexit_tripped = 0;   /* consume: return/break/errexit unwind only to the end of this source */
    source_depth--;
    free(txt);
}

int main(void) {
    print("\n");
    sys_setcolor(4); print("  OS-DEV shell v0.1"); sys_setcolor(8); print(" - running in userspace (ring 3)\n");   /* coloured banner (M1339) */
    sys_setcolor(8); print("  type "); sys_setcolor(3); print("'help'"); sys_setcolor(8); print(" for commands\n\n"); sys_setcolor(0);

    char line[1024];                               /* command line: roomy enough for long URLs + pastes */
    char cwd[128]; cwd[0] = '/'; cwd[1] = 0;       /* display path (kernel tracks the real cwd) */
    char lastcmd[1024]; lastcmd[0] = 0;            /* previous command, for `!!` */
    source_file(".SHRC", cwd, 1); g_status = 0;    /* run the startup rc file if it exists (aliases, set, banner) */
    for (;;) {
        char hn[64]; if (sys_gethostname(hn, sizeof hn) != 0 || !hn[0]) scpy(hn, "osdev");   /* prompt reflects the real hostname (M1311) */
        sys_setcolor(4); print(hn); sys_setcolor(8); print(":");                             /* coloured prompt (M1312): */
        sys_setcolor(6); print(cwd); sys_setcolor(0); print("$ ");                           /* cyan host, grey :, blue cwd, green $ */
        readline(line, sizeof(line));

        /* `!!` (optionally followed by more, e.g. `!! | grep x`) re-runs the
         * previous command with the trailing text appended; echo the expansion. */
        if (line[0] == '!' && line[1] == '!') {
            if (!lastcmd[0]) { print("!!: no previous command\n"); continue; }
            char exp[1024]; int p = 0;
            for (int i = 0; lastcmd[i] && p < 1023; i++) exp[p++] = lastcmd[i];
            for (int i = 2; line[i] && p < 1023; i++) exp[p++] = line[i];
            exp[p] = 0;
            int i = 0; for (; exp[i] && i < 1023; i++) line[i] = exp[i]; line[i] = 0;
            print(line); print("\n");
        }
        /* remember this command (non-blank) so the next `!!` can repeat it */
        { int ne = 0; for (int i = 0; line[i]; i++) if (line[i] != ' ') { ne = 1; break; }
          if (ne) { int i = 0; for (; line[i] && i < 1023; i++) lastcmd[i] = line[i]; lastcmd[i] = 0; } }

        /* run the line: a `for` loop, or a ';'-separated list of && / || pipelines */
        if (run_input_line(line, cwd)) break;
        g_returning = 0; g_loopbrk = 0; g_errexit_tripped = 0;   /* a stray `return`/`break`, or a `set -e` trip, must not wedge the next prompt line (the interactive shell survives) */
    }
    return 0;
}
