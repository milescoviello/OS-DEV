/* Compiled by REAL GCC running inside OS-DEV (M1957).
 *
 * Freestanding on purpose: no #include, no libc, no headers to find. The only
 * thing between this source and a running program is cc1, as and ld -- all of
 * them unmodified host binaries executing under the Linux ABI shim. Exit
 * status 29 is this file's own, so it cannot be faked by a stale artifact.
 */
static long wr(long fd, const char *b, long n) {
    long r;
    __asm__ volatile ("syscall" : "=a"(r) : "a"(1L), "D"(fd), "S"(b), "d"(n)
                      : "rcx", "r11", "memory");
    return r;
}

void _start(void) {
    const char *m = "CCSELF: compiled by real GCC running inside OS-DEV\n";
    long n = 0;
    while (m[n]) n++;
    wr(1, m, n);
    __asm__ volatile ("syscall" :: "a"(231L), "D"(29L) : "rcx", "r11");   /* exit_group(29) */
    __builtin_unreachable();
}
