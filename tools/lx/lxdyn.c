/* A DYNAMICALLY-LINKED binary (no -static-pie). It cannot start on its own:
 * the kernel must honour PT_INTERP, map ld-linux-x86-64.so.2, and enter the
 * INTERPRETER -- which then maps libc.so.6, relocates, and only then calls
 * main. Every host toolchain binary has exactly this shape, so this is the
 * gate on Phase 4. */
#include <stdio.h>
int main(int argc, char **argv) {
    printf("LXDYN: a dynamically-linked binary ran, argc=%d argv0=%s\n",
           argc, argc > 0 ? argv[0] : "(none)");
    fflush(stdout);
    return 11;
}
