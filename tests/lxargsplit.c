/* Host test for kernel/include/lxargsplit.h (M2071).
 *
 * The bug it exists for: OS-DEV's shell implements quoting by setting bit 7 on
 * every character a quote protects, and SYS_linux_run copied those bytes into
 * a Linux program's argv verbatim. Claude Code printed its own argv in a crash
 * report and showed three U+FFFD where the spaces of a quoted argument should
 * have been. The split and the unprotect are the same operation -- a protected
 * space must not end an argument, and must arrive as a space. */
#include <stdio.h>
#include <string.h>
#include "../kernel/include/lxargsplit.h"

#define P(c) ((char)((unsigned char)(c) | 0x80u))

static int fails;
static void ck(const char *what, int cond) {
    if (cond) printf("  ok: %s\n", what);
    else { printf("  FAIL: %s\n", what); fails++; }
}

int main(void) {
    char buf[512]; char *av[16]; int n;

    /* 1. plain words */
    n = lx_split_args("-p hello world", buf, sizeof buf, av, 16);
    ck("three plain words split into three arguments", n == 3);
    ck("...and read back verbatim",
       n == 3 && !strcmp(av[0], "-p") && !strcmp(av[1], "hello") && !strcmp(av[2], "world"));

    /* 2. THE BUG. A quoted argument arrives with its spaces protected: it must
     *    stay ONE argument, and the spaces must come back as spaces. */
    char q[64]; int i = 0;
    const char *lit = "-p Reply with exactly: OS-DEV";
    for (const char *s = lit; *s; s++) q[i++] = (*s == ' ' && s > lit + 2) ? P(' ') : *s;
    q[i] = 0;
    n = lx_split_args(q, buf, sizeof buf, av, 16);
    ck("a quoted argument stays ONE argument", n == 2);
    ck("...and its protected spaces are restored",
       n == 2 && !strcmp(av[1], "Reply with exactly: OS-DEV"));
    ck("...with no byte left above 0x7F",
       n == 2 && !strchr(av[1], (char)0xA0) && (unsigned char)av[1][5] == ' ');

    /* 3. every protected character comes back, not just space */
    char r[32]; i = 0;
    r[i++] = 'a'; r[i++] = P('|'); r[i++] = P('*'); r[i++] = P('$'); r[i++] = 'z'; r[i] = 0;
    n = lx_split_args(r, buf, sizeof buf, av, 16);
    ck("any protected byte is restored, not only space", n == 1 && !strcmp(av[0], "a|*$z"));

    /* 4. leading/trailing/multiple real spaces produce no empty arguments */
    n = lx_split_args("   a    b   ", buf, sizeof buf, av, 16);
    ck("runs of real spaces make no empty arguments", n == 2 && !strcmp(av[0], "a") && !strcmp(av[1], "b"));

    /* 5. degenerate inputs do not write anywhere */
    ck("an empty string yields no arguments", lx_split_args("", buf, sizeof buf, av, 16) == 0);
    ck("a NULL string yields no arguments", lx_split_args(NULL, buf, sizeof buf, av, 16) == 0);
    ck("only spaces yields no arguments", lx_split_args("     ", buf, sizeof buf, av, 16) == 0);

    /* 6. BOUNDS. More arguments than slots, and a string longer than the
     *    buffer, must both truncate rather than overrun. */
    n = lx_split_args("a b c d e f g h i j k l m n o p q r s t", buf, sizeof buf, av, 4);
    ck("more arguments than slots truncates to the slot count", n == 4);
    char small[8]; char *sv[4];
    n = lx_split_args("aaaa bbbb cccc", small, (int)sizeof small, sv, 4);
    ck("a buffer smaller than the input does not overrun",
       n >= 1 && strlen(sv[0]) < sizeof small);

    if (fails) { printf("lxargsplit: %d FAILED\n", fails); return 1; }
    printf("PASS: shell quoting survives into a Linux program's argv (10 checks)\n");
    return 0;
}
