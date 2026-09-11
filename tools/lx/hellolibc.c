/* A real LIBC static-PIE Linux binary. Unlike hellofree.c this goes through the
 * host libc's full startup: it reads argc/argv/envp and the auxiliary vector off
 * the initial stack before main runs, sets up TLS, and initialises stdio. It is
 * the first thing here that actually depends on the kernel building a correct
 * System V process stack -- AT_RANDOM in particular, which is where the stack
 * canary and malloc's pointer-mangling secret come from. */
#include <stdio.h>
int main(int argc, char **argv) {
    printf("hello from a static-PIE LIBC binary: argc=%d argv0=%s\n",
           argc, argc > 0 ? argv[0] : "(none)");
    fflush(stdout);
    return 7;
}
