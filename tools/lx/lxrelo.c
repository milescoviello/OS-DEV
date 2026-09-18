/* lxrelo.c -- DID ld.so COMPUTE THE RELOCATIONS CORRECTLY? (M2187)
 *
 * WHY THIS EXISTS, and it is the last standing hypothesis rather than a guess.
 * Firefox's remaining fault is an indirect call through a GOT slot holding a
 * non-canonical pointer, plus a write into libxul's RELRO segment. Four things
 * have now been ruled out by measurement rather than argument:
 *
 *   - the library's bytes are the FILE's bytes (lxmapcmp against a host-
 *     computed hash, so the oracle is outside the guest) -- M2173
 *   - a MAP_PRIVATE file mapping is private ACROSS PROCESSES, so one process
 *     is not seeing another's relocations -- M2167
 *   - the RELRO page is UNCHANGED since ld.so made it read-only, so the kernel
 *     did not lose or replace it -- the concurrent session's M2177
 *   - the protections are right: GNU_RELRO covers exactly that LOAD, so
 *     read-only is correct and the WRITE is the anomaly
 *
 * What is left is the relocation ITSELF: ld.so reads correct `.rela.dyn` and
 * either computes a wrong value or never writes one. That is testable without
 * Firefox, with a probe several orders of magnitude smaller.
 *
 * THE METHOD. lxrelolib.so contains 4096 `const` function pointers, each
 * initialised to a function in the same object -- which the compiler emits as
 * R_X86_64_RELATIVE, the commonest relocation in any PIE and the one whose
 * addend is a link-time offset the loader must bias. `const` puts them in
 * `.data.rel.ro`: relocated, then mprotected read-only, the exact shape of the
 * segment Firefox faults writing into.
 *
 * Thousands, not one, because the symptom is ONE wrong pointer among many.
 * A probe with a single relocation would have to be unlucky in precisely the
 * right slot to see it.
 *
 * The assertion is not "the pointers are non-null" -- a wrong bias gives a
 * plausible non-null address, which is exactly how this failure presents. Each
 * slot must equal the address the library itself computes for its own target
 * AT RUNTIME, by taking the address (PC-relative) rather than by reading the
 * table under test -- so a uniform bias error cancels, only a genuinely wrong
 * slot shows, and the expectation is not computed by the same arithmetic as the
 * thing being checked. The first version got that wrong and reported 3072 of
 * 4096 pointers "WRONG" on a host where ld.so is beyond suspicion.
 *
 * And every pointer is CALLED, with the target counting its own invocations,
 * because a canonical-looking address that compares equal but does not reach
 * the function is the one case a comparison alone still misses.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

extern int lxrelo_n(void);
extern void (*lxrelo_slot(int i))(void);
extern void (*lxrelo_expect(void))(void);
extern int lxrelo_calls(void);
extern void *lxrelo_table(void);
extern unsigned long lxrelo_table_bytes(void);

int main(void) {
    int n = lxrelo_n();
    if (n <= 0) { printf("LXRELO: SKIP (the library reported %d slots)\n", n); return 0; }

    void (*want)(void) = lxrelo_expect();
    int wrong = 0, noncanon = 0, first = -1;
    for (int i = 0; i < n; i++) {
        void (*got)(void) = lxrelo_slot(i);
        unsigned long g = (unsigned long)got;
        /* A user pointer must be canonical and in the low half. A non-canonical
         * value is the shape the Firefox crash showed (garbage in the top
         * sixteen bits, hence a GPF rather than a page fault). */
        if ((g >> 47) != 0) { noncanon++; if (first < 0) first = i; continue; }
        if (got != want) { wrong++; if (first < 0) first = i; }
    }
    if (wrong || noncanon) {
        printf("LXRELO: *** %d of %d relocated pointers are WRONG and %d are NON-CANONICAL; "
               "first bad slot %d holds %p, the library computes %p ***\n",
               wrong, n, noncanon, first, (void *)lxrelo_slot(first), (void *)want);
        printf("LXRELO: %d CHECK(S) FAILED\n", wrong + noncanon);
        return 1;
    }
    printf("LXRELO: all %d R_X86_64_RELATIVE pointers in .data.rel.ro are exactly right\n", n);

    /* CALL every one. A canonical address that is not the function is the case
     * a comparison alone can still miss -- and calling is what Firefox does
     * through the slot that kills it. */
    for (int i = 0; i < n; i++) lxrelo_slot(i)();
    if (lxrelo_calls() != n) {
        printf("LXRELO: *** called %d slots but the target ran %d time(s) -- a pointer that "
               "compares equal but does not reach the function ***\n", n, lxrelo_calls());
        return 1;
    }
    printf("LXRELO: and all %d are callable, and the target ran exactly %d time(s)\n",
           n, lxrelo_calls());
    /* PART 2: A WRITE INTO A RELOCATED, THEN READ-ONLY, PAGE (M2187).
     *
     * This is the state RELRO leaves and the state the Firefox fault occurs
     * in: ld.so relocated `.data.rel.ro`, then mprotected it read-only, and
     * something then writes to it. Whether that write is legitimate or not,
     * what the KERNEL must do is unambiguous -- grant write, keep the page's
     * existing contents, and not substitute a fresh or a shared one.
     *
     * The dangerous failure is not the write failing. It is the write
     * SUCCEEDING while the page is quietly replaced: a copy-on-write break
     * that copies the wrong source, or a fresh zeroed frame, loses every
     * relocation in the page and leaves exactly one wrong pointer among
     * thousands -- which is the reported symptom. So the assertion is that the
     * OTHER 4095 pointers survive a write to one page. */
    {
        unsigned long pagesz = 4096;
        char *tbl = (char *)lxrelo_table();
        unsigned long bytes = lxrelo_table_bytes();
        char *page = (char *)((unsigned long)tbl & ~(pagesz - 1));

        if (mprotect(page, pagesz, PROT_READ) != 0)
            printf("LXRELO: SKIP part 2 (cannot make the table read-only: errno %d)\n", errno);
        else if (mprotect(page, pagesz, PROT_READ | PROT_WRITE) != 0)
            printf("LXRELO: *** granting WRITE back to a read-only relocated page FAILED: "
                   "errno %d -- an mprotect that cannot re-grant access is the M2186 shape ***\n",
                   errno), wrong++;
        else {
            /* Write a sentinel into the first slot, then require every OTHER
             * slot in the table to be untouched. */
            void (**slot0)(void) = (void (**)(void))page;
            void (*saved)(void) = *slot0;
            *slot0 = (void (*)(void))0x1234;
            int lost = 0;
            for (int i = 1; i < n; i++) if (lxrelo_slot(i) != want) lost++;
            *slot0 = saved;
            if (mprotect(page, pagesz, PROT_READ) != 0)
                printf("LXRELO: (note: could not restore read-only, errno %d)\n", errno);
            if (lost) {
                printf("LXRELO: *** writing one slot of a relocated read-only page LOST %d of "
                       "%d other pointers -- the page was replaced, not made writable ***\n",
                       lost, n - 1);
                wrong += lost;
            } else {
                printf("LXRELO: a write into a relocated read-only page kept the other %d "
                       "pointers (%lu-byte table)\n", n - 1, bytes);
            }
        }
    }

    if (wrong) { printf("LXRELO: %d CHECK(S) FAILED\n", wrong); return 1; }
    printf("LXRELO: ALL PASSED\n");
    return 0;
}
