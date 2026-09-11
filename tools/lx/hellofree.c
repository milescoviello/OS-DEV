/* A freestanding static-PIE Linux binary: no libc, no startup files. It exists
 * to test the ABI and the loader in isolation -- if this runs, the syscall
 * entry path, the ELF load and the relocations are all correct, with none of
 * libc's auxv/TLS expectations in the way yet. */
static long sys3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c)
                               : "rcx", "r11", "memory");
    return r;
}
void _start(void) {
    static const char m[] = "hello from a freestanding static-PIE Linux binary\n";
    sys3(1, 1, (long)m, sizeof m - 1);     /* write(1, m, len) */
    sys3(231, 42, 0, 0);                   /* exit_group(42) */
    for (;;) { }
}
