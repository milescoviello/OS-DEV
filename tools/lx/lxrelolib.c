/* lxrelolib.c -- a shared object whose whole content is RELOCATIONS (M2187).
 *
 * See lxrelo.c for why. Every entry of `g_ptr` is initialised to the address of
 * a function in this same object, which the compiler emits as an
 * R_X86_64_RELATIVE: the addend is a link-time offset and ld.so must add the
 * load bias at load time. There are 4096 of them, because the failure being
 * hunted is ONE wrong pointer among many -- a single garbage GOT slot -- and a
 * probe with one relocation would have to be unlucky in exactly that slot.
 *
 * `const` puts the table in `.data.rel.ro`: relocated, then mprotected
 * read-only by ld.so, which is the exact segment the remaining Firefox fault
 * writes into.
 *
 * EVERY SLOT POINTS AT THE SAME FUNCTION, deliberately. The first version used
 * four targets and a clever index formula, and the formula in the checker did
 * not match the one in the table -- so the probe reported 3072 of 4096
 * "WRONG" on a HOST where ld.so is beyond suspicion. A probe whose expectation
 * is computed by different arithmetic than the thing it checks is measuring its
 * own arithmetic. One target, and the expectation taken at runtime by a
 * DIFFERENT mechanism (taking the address, which is PC-relative, not a
 * RELATIVE relocation in .data.rel.ro), so a uniform bias error cancels and
 * only a genuinely wrong slot shows.
 */
#include <stddef.h>

#define NPTR 4096

int lxrelo_hits;
void lxrelo_target(void);
void lxrelo_target(void) { lxrelo_hits++; }

void (*const g_ptr[NPTR])(void) = {
#define P1   lxrelo_target
#define P4   P1, P1, P1, P1
#define P16  P4, P4, P4, P4
#define P64  P16, P16, P16, P16
#define P256 P64, P64, P64, P64
#define P1024 P256, P256, P256, P256
    P1024, P1024, P1024, P1024
};

/* The table's own address and extent, so the probe can mprotect the very pages
 * ld.so relocated and then made read-only. (M2187) */
void *lxrelo_table(void)             { return (void *)g_ptr; }
unsigned long lxrelo_table_bytes(void) { return sizeof g_ptr; }

int  lxrelo_n(void)                  { return NPTR; }
void (*lxrelo_slot(int i))(void)     { return (i >= 0 && i < NPTR) ? g_ptr[i] : NULL; }
/* The expectation, taken at runtime and NOT out of the table under test. */
void (*lxrelo_expect(void))(void)    { return lxrelo_target; }
int  lxrelo_calls(void)              { return lxrelo_hits; }
