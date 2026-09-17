/*
 * flock.c — advisory whole-file locks, keyed by path (M1177). See flock.h.
 *
 * A fixed table of held locks {path, owner pid, type}. LOCK_EX conflicts with
 * any other holder; LOCK_SH only with an exclusive holder. A conflicting
 * request without LOCK_NB blocks (task_block) and retries when any unlock
 * wakes it. Re-locking a path you already hold upgrades/downgrades it. Locks
 * are advisory: they coordinate cooperating processes, they don't police
 * read/write.
 *
 * M1611: this used to rely on the mbox.c discipline (IF=0 alone makes
 * "conflict? then block" atomic against an unlock) -- the same single-CPU
 * assumption M1531 invalidated in mbox.c itself (fixed this same session).
 * Also affects rlock_set/F_SETLKW (M1597), which explicitly reuses this
 * file's own waiter array + wake function. One lock now covers every
 * check-then-block, unlock-then-wake, and table scan-and-claim in this file
 * (conflicts()/rl_conflict() are only ever called from within it, so they
 * need no locking of their own). Same idiom as the other five files this
 * session already fixed the same way. */
#include "flock.h"
#include "console.h"   /* kprintf: a full lock table must announce itself (M2149) */
#include "syscall.h"   /* LOCK_SH/EX/NB/UN */
#include "task.h"

static volatile int flk_lock;
static inline uint64_t flk_irq_save(void) {
    uint64_t irqf;
    __asm__ volatile("pushfq; pop %0; cli" : "=r"(irqf) :: "memory");
    while (__atomic_exchange_n(&flk_lock, 1, __ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    return irqf;
}
static inline void flk_irq_restore(uint64_t irqf) {
    __atomic_store_n(&flk_lock, 0, __ATOMIC_RELEASE);
    __asm__ volatile("push %0; popfq" : : "r"(irqf) : "memory", "cc");
}

#define FLK_N 32                 /* max concurrent held locks */
/* A LOCK KEY THAT IS TRUNCATED LOCKS THE WRONG FILE (M2149).
 *
 * This was 64 bytes, and the path is the ONLY thing identifying what a lock
 * covers -- so two files whose names agree for 63 characters became one lock.
 * Firefox's profile makes that the normal case, not a corner:
 *
 *   /disk2/root/.mozilla/firefox/xx586yef.default-release/   = 54 chars
 *
 * leaving nine characters to distinguish places.sqlite from places.sqlite-wal
 * from places.sqlite-journal from permissions.sqlite. sqlite locks the
 * database and its write-ahead log separately and expects them to be
 * independent; here a lock on one conflicted with a lock on the other, held by
 * a different process, and sqlite reported exactly what it saw:
 *
 *   console.error: "Error opening database: Error executing SQL: database is
 *                   locked"
 *
 * That is the fixed-buffer truncation class this project has paid for before
 * (M604-M610), in the one structure where a collision is not a truncated
 * string but a false mutual exclusion. VFS_PATH_MAX is what every other path
 * in the kernel is sized to, so this is sized to it too. */
#define FLK_PATH 256

struct flk { char path[FLK_PATH]; int owner; int type; int used; };  /* type: LOCK_SH / LOCK_EX */
static struct flk fl[FLK_N];
static task_t *fl_waiters[FLK_N];
static int fl_nwait;

static int peq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }

/* Would acquiring `want` (LOCK_SH/EX) on `path` for `pid` conflict with a lock
 * held by someone else? EX conflicts with any other holder; SH only with EX. */
static int conflicts(const char *path, int pid, int want) {
    for (int i = 0; i < FLK_N; i++)
        if (fl[i].used && fl[i].owner != pid && peq(fl[i].path, path))
            if (want == LOCK_EX || fl[i].type == LOCK_EX) return 1;
    return 0;
}

static void flk_wake_all(void) {                  /* a lock changed: let every blocked acquirer recheck */
    int n = fl_nwait; fl_nwait = 0;
    for (int i = 0; i < n; i++) if (fl_waiters[i]) task_wake(fl_waiters[i]);
}

int flock_op(const char *path, int pid, int op) {
    if (!path || !path[0]) return -1;
    int nb = op & LOCK_NB, base = op & ~LOCK_NB;

    if (base == LOCK_UN) {                          /* release this pid's lock on the path */
        uint64_t irqf = flk_irq_save();
        for (int i = 0; i < FLK_N; i++)
            if (fl[i].used && fl[i].owner == pid && peq(fl[i].path, path)) fl[i].used = 0;
        flk_wake_all();
        flk_irq_restore(irqf);
        return 0;
    }
    if (base != LOCK_SH && base != LOCK_EX) return -1;

    for (;;) {
        uint64_t irqf = flk_irq_save();
        if (!conflicts(path, pid, base)) {
            for (int i = 0; i < FLK_N; i++)         /* already hold it -> upgrade/downgrade in place */
                if (fl[i].used && fl[i].owner == pid && peq(fl[i].path, path)) { fl[i].type = base; flk_irq_restore(irqf); return 0; }
            for (int i = 0; i < FLK_N; i++) if (!fl[i].used) {   /* take a free slot */
                int j = 0; while (path[j] && j < FLK_PATH - 1) { fl[i].path[j] = path[j]; j++; } fl[i].path[j] = 0;
                fl[i].owner = pid; fl[i].type = base; fl[i].used = 1;
                flk_irq_restore(irqf);
                return 0;
            }
            flk_irq_restore(irqf);
            return -1;                              /* lock table full */
        }
        if (nb) { flk_irq_restore(irqf); return -1; }   /* EWOULDBLOCK */
        if (fl_nwait < FLK_N) fl_waiters[fl_nwait++] = task_self();
        flk_irq_restore(irqf);
        task_block();                               /* woken by an unlock (or a kill) */
    }
}

/* ---- POSIX fcntl byte-range record locks (M1221) -----------------------------
 * A SEPARATE lock space from flock() above (POSIX keeps the two independent),
 * keyed by {path, [start,len)} + owner pid. type F_RDLCK (shared) / F_WRLCK
 * (exclusive); len <= 0 means "to EOF". Released on F_UNLCK or process exit. */
/* AND ENOUGH OF THEM (M2149). 64 record locks for the whole machine, and a
 * full table returned a silent -1 that the Linux layer turns into EAGAIN --
 * which sqlite also reports as "database is locked", so the two failures were
 * indistinguishable from outside. One browser profile holds locks on places,
 * cookies, favicons, permissions, content-prefs, storage and their WAL and
 * journal siblings, from more than one process. */
#define RLK_N 256
struct rlk { char path[FLK_PATH]; int owner, type, used; long start, len; };
static struct rlk rl[RLK_N];

static long rl_end(long start, long len) { return len <= 0 ? 0x7fffffffffffffffL : start + len; }
static int rl_overlap(const struct rlk *a, long start, long len) {
    return a->start < rl_end(start, len) && start < rl_end(a->start, a->len);
}
/* A conflicting holder of [start,len) on `path` vs a `type` request by `pid`:
 * a different owner whose range overlaps and where at least one side is F_WRLCK. */
static struct rlk *rl_conflict(const char *path, int pid, int type, long start, long len) {
    for (int i = 0; i < RLK_N; i++)
        if (rl[i].used && rl[i].owner != pid && peq(rl[i].path, path) && rl_overlap(&rl[i], start, len))
            if (type == F_WRLCK || rl[i].type == F_WRLCK) return &rl[i];
    return 0;
}
/* F_SETLK/F_SETLKW: F_UNLCK drops this pid's overlapping locks on `path`;
 * F_RD/WRLCK acquires after clearing this pid's overlaps. can_block (M1597):
 * F_SETLKW blocks on a conflict instead of failing immediately, reusing
 * flock_op's own waiter array + flk_wake_all() -- already called from this
 * function's own F_UNLCK branch below, so a parked waiter here is woken by
 * every relevant unlock without any change to the wake side. 0, or -1 on
 * conflict (F_SETLK only) / table full. */
int rlock_set(const char *path, int pid, int type, long start, long len, int can_block) {
    if (!path || !path[0]) return -1;
    uint64_t irqf = flk_irq_save();
    if (type != F_UNLCK) {
        while (rl_conflict(path, pid, type, start, len)) {
            if (!can_block) { flk_irq_restore(irqf); return -1; }
            if (fl_nwait < FLK_N) fl_waiters[fl_nwait++] = task_self();
            flk_irq_restore(irqf);
            task_block();                             /* woken by an unlock (or a kill) */
            irqf = flk_irq_save();
        }
    }
    for (int i = 0; i < RLK_N; i++)                  /* clear this pid's overlapping locks first */
        if (rl[i].used && rl[i].owner == pid && peq(rl[i].path, path) && rl_overlap(&rl[i], start, len)) rl[i].used = 0;
    if (type == F_UNLCK) { flk_wake_all(); flk_irq_restore(irqf); return 0; }
    for (int i = 0; i < RLK_N; i++) if (!rl[i].used) {   /* record the new lock */
        int j = 0; while (path[j] && j < FLK_PATH - 1) { rl[i].path[j] = path[j]; j++; } rl[i].path[j] = 0;
        rl[i].owner = pid; rl[i].type = type; rl[i].start = start; rl[i].len = len; rl[i].used = 1;
        flk_irq_restore(irqf);
        return 0;
    }
    flk_irq_restore(irqf);
    /* SAY IT, rather than looking like a lock conflict (M2149). A caller told
     * EAGAIN retries for ever; a caller told the truth can at least be
     * debugged. */
    {   static int told;
        if (!told) { told = 1;
            kprintf("[flock] the record-lock table is FULL (%d entries) -- refusing a lock on "
                    "\"%s\"; this is NOT a conflict with another holder\n", RLK_N, path); } }
    return -1;                                        /* table full */
}
/* F_GETLK: if a conflicting lock exists, report it in *out_* and return 1; else 0. */
int rlock_get(const char *path, int pid, int type, long start, long len,
              int *out_pid, int *out_type, long *out_start, long *out_len) {
    struct rlk *c = rl_conflict(path, pid, type, start, len);
    if (!c) return 0;
    *out_pid = c->owner; *out_type = c->type; *out_start = c->start; *out_len = c->len;
    return 1;
}

void flock_release_pid(int pid) {                   /* process exit: drop everything it held */
    uint64_t irqf = flk_irq_save();
    int any = 0;
    for (int i = 0; i < FLK_N; i++) if (fl[i].used && fl[i].owner == pid) { fl[i].used = 0; any = 1; }
    for (int i = 0; i < RLK_N; i++) if (rl[i].used && rl[i].owner == pid) { rl[i].used = 0; any = 1; }   /* record locks too (M1221) */
    if (any) flk_wake_all();
    flk_irq_restore(irqf);
}

static int sapp(char *b, int p, int max, const char *s) { while (*s && p < max - 1) b[p++] = *s++; return p; }
static int sdec(char *b, int p, int max, int v) {
    char t[12]; int n = 0; if (!v) t[n++] = '0';
    while (v > 0) { t[n++] = (char)('0' + v % 10); v /= 10; }
    while (n && p < max - 1) b[p++] = t[--n];
    return p;
}
int flock_format(char *b, int max) {
    int p = sapp(b, 0, max, "  OWNER  TYPE  PATH\n"), any = 0;
    for (int i = 0; i < FLK_N; i++) if (fl[i].used) {
        p = sapp(b, p, max, "  ");  p = sdec(b, p, max, fl[i].owner);
        p = sapp(b, p, max, fl[i].type == LOCK_EX ? "   EX   " : "   SH   ");
        p = sapp(b, p, max, fl[i].path); p = sapp(b, p, max, "\n"); any = 1;
    }
    if (!any) p = sapp(b, p, max, "  (no locks held)\n");
    if (p < max) b[p] = 0;
    return p;
}
