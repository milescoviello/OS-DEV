/*
 * shm.c — named shared memory. See shm.h. The frames are allocated once (held
 * by the object at refcount 0); each app_shm_open mapping pmm_addref's them, and
 * teardown (vmm_destroy_address_space's pmm_free_frame) decrements — so the
 * frames outlive any single mapper and are genuinely shared. Built on the
 * M1089 per-frame refcount.
 */
#include "string.h"   /* memset: a page is zeroed word-at-a-time, not byte-at-a-time (M2094) */
#include "shm.h"
#include "pmm.h"
#include "vmm.h"   /* hhdm() */
#include <stdint.h>

/* M1618: shm_get's own scan-then-create was the worst case this whole pass
 * found -- two cores racing to create the SAME brand-new name could both
 * find the same free slot and each write HALF of tab[i] (name/npages/used
 * interleaved with the other's, or one's frame-allocation loop stomping the
 * other's), corrupting the shared struct or handing out two different frame
 * sets under one name. shm_unlink's scan-then-free races the same slot from
 * the other direction. One lock for the whole file, same idiom as the other
 * three files this pass. */
static volatile int shm_lock;
static inline uint64_t sh_irq_save(void) {
    uint64_t f;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(f) :: "memory");
    while (__atomic_exchange_n(&shm_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return f;
}
static inline void sh_irq_restore(uint64_t f) {
    __atomic_store_n(&shm_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(f) : "memory", "cc");
}

#define SHM_N        8        /* up to 8 named objects */
#define SHM_MAXPAGES 64       /* up to 256 KiB per object */

struct shm { char name[32]; int used, npages; uint64_t frames[SHM_MAXPAGES]; };
static struct shm tab[SHM_N];

static int sh_eq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }

uint64_t shm_max_bytes(void) { return (uint64_t)SHM_MAXPAGES * PAGE_SIZE; }  /* the real cap shm_get enforces below (M1592) */

int shm_get(const char *name, uint64_t size, uint64_t **frames, int *npages) {
    if (!name || !name[0]) return -1;
    int pages = (int)((size + PAGE_SIZE - 1) / PAGE_SIZE);
    if (pages <= 0) pages = 1;
    if (pages > SHM_MAXPAGES) return -1;

    uint64_t f0 = sh_irq_save();
    for (int i = 0; i < SHM_N; i++)                       /* existing object */
        if (tab[i].used && sh_eq(tab[i].name, name)) { *frames = tab[i].frames; *npages = tab[i].npages; sh_irq_restore(f0); return 0; }

    for (int i = 0; i < SHM_N; i++) if (!tab[i].used) {   /* create */
        for (int p = 0; p < pages; p++) {
            uint64_t f = pmm_alloc_frame();
            if (!f) { for (int u = 0; u < p; u++) pmm_free_frame(tab[i].frames[u]); sh_irq_restore(f0); return -1; }  /* OOM: unwind */
            uint8_t *z = (uint8_t *)hhdm(f);
            memset(z, 0, PAGE_SIZE);   /* word-at-a-time (M2094) */
            tab[i].frames[p] = f;
        }
        int j = 0; while (name[j] && j < 31) { tab[i].name[j] = name[j]; j++; } tab[i].name[j] = 0;
        tab[i].npages = pages; tab[i].used = 1;
        *frames = tab[i].frames; *npages = pages;
        sh_irq_restore(f0);
        return 0;
    }
    sh_irq_restore(f0);
    return -1;                                            /* table full */
}

/* shm_unlink (M1590): drop the table SLOT's own implicit hold on each frame
 * (the "refcount 0" baseline pmm_alloc_frame left it at, per this file's own
 * header comment) and free the name for reuse. Any process that already
 * app_shm_open'd this object keeps working -- its own earlier pmm_addref
 * call is a SEPARATE reference pmm_free_frame here doesn't touch; the frame
 * only actually returns to the pool once every one of those drops too (each
 * mapper's own vmm_destroy_address_space teardown, same as any other shared
 * frame). A later shm_open of the SAME name after this creates a genuinely
 * NEW, distinct, freshly-zeroed object, matching real POSIX shm_unlink --
 * unlink only removes the name -> object association, not live mappings. */
int shm_unlink(const char *name) {
    if (!name || !name[0]) return -1;
    uint64_t f = sh_irq_save();
    for (int i = 0; i < SHM_N; i++) if (tab[i].used && sh_eq(tab[i].name, name)) {
        for (int p = 0; p < tab[i].npages; p++) pmm_free_frame(tab[i].frames[p]);
        tab[i].used = 0;
        sh_irq_restore(f);
        return 0;
    }
    sh_irq_restore(f);
    return -1;
}

static int s_put(char *b, int p, int max, const char *s) { while (*s && p + 1 < max) b[p++] = *s++; return p; }
static int s_num(char *b, int p, int max, uint64_t v) {
    char t[16]; int n = 0; if (!v) t[n++] = '0';
    while (v) { t[n++] = (char)('0' + v % 10); v /= 10; }
    while (n && p + 1 < max) b[p++] = t[--n];
    return p;
}

int shm_format(char *out, int max) {
    int p = s_put(out, 0, max, "  NAME                  KiB\n");
    int any = 0;
    for (int i = 0; i < SHM_N; i++) if (tab[i].used) {
        p = s_put(out, p, max, "  "); p = s_put(out, p, max, tab[i].name);
        int nl = 0; while (tab[i].name[nl]) nl++;
        for (int k = nl; k < 20 && p + 1 < max; k++) out[p++] = ' ';
        p = s_num(out, p, max, (uint64_t)tab[i].npages * PAGE_SIZE / 1024);
        p = s_put(out, p, max, "\n"); any = 1;
    }
    if (!any) p = s_put(out, p, max, "  (none -- shm_open a name to create one)\n");
    if (p < max) out[p] = 0;
    return p;
}
