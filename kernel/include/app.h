/*
 * app.h — userspace applications running as windowed processes.
 *
 * An "app" is a real ring-3 program (the embedded shell ELF) running in its own
 * address space as a preemptive task. Its stdout goes to a text grid the window
 * manager draws; its stdin comes from the keyboard when its window is focused.
 */
#pragma once
#include <stdint.h>

typedef struct app app_t;

app_t      *app_spawn(const void *elf, const char *title, uint64_t elfsz);  /* run an ELF as a process */
int         app_spawn_named(const char *name);   /* launch a registered program; 0/-1 */
int         app_spawn_named_arg(const char *name, const char *arg);  /* launch with a one-shot arg */
int         app_getarg(char *out, int max);      /* read the calling app's launch arg; returns length */
int         app_list_names(char *buf, int max);  /* space-separated prog names; bytes written */
int         app_spawn_from_file(const char *path);/* load + run an ELF from a FAT32 file */
int         app_spawn_linux_from_file(const char *path);
void        app_write_to(app_t *dest, const char *buf, unsigned len);  /* write into a specific app's window grid (M1988) */
void        app_set_out_to(int pid, app_t *dest);                      /* route a Linux child's stdout to dest's window (M1988) */
void        app_futex_forget(void *t);                                 /* drop any futex waiter slot owned by task t (M1990) */
int         app_last_spawn_pid(void);
int         app_state_of(int pid);
void        app_dump_threads(int pid);                                /* where every thread of a pid is parked (M1996) */                                     /* task state of a live pid, -1 if gone (M1996) */                                  /* pid of the last successful spawn (M1988) */
void        app_count_lx_syscall(unsigned long nr);                    /* one more Linux syscall by the caller, counted BY NUMBER (M2004/M2066) */
int         app_reap_selftest(void);
int         app_pendq_selftest(void);                                  /* -append selftest: a live app must not lose its window to a dead one (M2076) */                                   /* -append selftest: only ONE reaper may tear a process down (M2072) */
#define LX_ENV_CMDLINE 4
extern const char *g_lx_env_cmdline[LX_ENV_CMDLINE];   /* extra environment for every Linux program, from -append (M2073) */
void        app_set_fault_siginfo(uint64_t addr, int code);       /* si_addr/si_code for the NEXT fault signal delivered (M2073) */
void        app_lx_syshist_dump(app_t *a, int want);                   /* the top `want` syscall numbers since the last sample -- what a stuck program is actually doing (M2066) */
void        app_stall_watchdog(void);                                  /* WM: report any Linux process that has stopped making syscalls (M2004) */
int         app_open_console_alias(void);                              /* a new fd for the controlling terminal: open("/dev/tty") (M2004) */
app_t      *app_out_to_of(app_t *a);                                   /* the window this app's output goes to, or NULL (M2004) */
int         app_pid_of(app_t *a);                                      /* an app handle's pid (M2004) */
void        app_arm_next_spawn(app_t *dest, int ppid);                 /* the next Linux spawn: output -> dest's window, parent = ppid (M2004) */
int         app_console_size(int *cols, int *rows);                    /* the grid this process's output lands on; 0 = no terminal (M2004) */
app_t      *app_out_to(void);                                          /* the current app's stdout target, or NULL (M1988) */
int         app_spawn_linux_from_file_arg(const char *path, const char *arg);  /* + a one-shot arg that becomes argv[1] (M1948) */
int         app_spawn_linux_from_file_argv(const char *path, const char *const *args, int n);  /* + a FULL argv: args[] become argv[1..n] (M1955) */
int         app_run_linux_sync(const char *path, const char *const *args, int n, int timeout_ms);  /* spawn + BLOCK in kernel context until it exits; exit status, -1 no-start, -2 timeout (M1955) */
/* Forward-declared HERE, not just at line ~107: a struct first mentioned inside
 * a prototype gets PROTOTYPE scope, which makes it a different type from the
 * file-scope one declared later -- "conflicting types" at the definition. */
struct registers;
long        app_execve_linux(struct registers *r, const char *path, const char *const *argv, const char *const *envp);  /* Linux execve(2): replace this image, enter with a SysV stack; returns only on failure (M1948) */
app_t      *app_take_pending(void);              /* next app awaiting a window (WM)    */
void        app_browse(const char *url);         /* queue a URL for a browser window   */
int         app_take_browse(char *out, int max); /* WM claims a queued browse URL; 0/1 */
const char *app_title(app_t *a);
long app_prctl(int option, uint64_t arg2);   /* PR_SET_NAME / PR_GET_NAME (M1225) */
long app_set_tid_address(uint64_t tidptr);    /* register clear_child_tid; returns the tid (M1226) */
struct siginfo;
long app_waitid(int idtype, int id, struct siginfo *si, int options);   /* waitid + WNOHANG; 0/-1 (M1227) */
const char *app_arg(app_t *a);          /* the app's launch argument (/proc/<pid>/cmdline) */
void       *app_task(app_t *a);         /* the app's task_t* (cast in procfs for stop/cont) */
uint64_t    app_cr3(app_t *a);          /* the app's CR3 (address space), for /proc/<pid>/wss */
void        app_self_faults(uint64_t *minflt, uint64_t *majflt);   /* current app's minor/major fault counts (M1150) */
void        app_faults(app_t *a, uint64_t *minflt, uint64_t *majflt);  /* any app's fault counts, for /proc/<pid>/stat (M1252) */
int         app_format_smaps(app_t *a, char *b, int max);          /* /proc/<pid>/smaps: per-region Rss/Pss/Dirty/Swap (M1151) */
int         app_format_pagemap(app_t *a, char *b, int max);        /* /proc/<pid>/pagemap: per-page residency + PFN (M1167) */
uint64_t    app_heap_bytes(app_t *a);   /* heap size in bytes */
int         app_nfd_max(void);          /* per-process descriptor ceiling, for RLIMIT_NOFILE (M1972) */
uint64_t    app_stack_bytes(void);      /* usable user-stack bytes, for RLIMIT_STACK (M1975) */
int         app_proc_max(void);         /* process ceiling, for RLIMIT_NPROC (M1972) */
int         app_vma_count(app_t *a);    /* number of mmap regions */
int         app_vma_info(app_t *a, int i, uint64_t *start, uint64_t *len, int *prot);  /* one VMA's extent+prot; 0/-1 (M1970) */
int         app_ppid(app_t *a);         /* parent pid, for /proc/<pid>/stat (M1231) */
void        app_io_account(int is_write, long n);            /* tally fd read/write bytes for /proc/<pid>/io (M1244) */
void        app_io_counts(app_t *a, uint64_t *rc, uint64_t *wc);  /* read the rchar/wchar tallies (M1244) */
int         app_pgid_of(app_t *a);      /* process-group id (M1231) */
int         app_sid_of(app_t *a);       /* session id (M1231) */
int         app_format_maps(app_t *a, char *buf, int max);   /* /proc/<pid>/maps: memory regions as text */
int         app_format_fds(app_t *a, char *buf, int max);    /* /proc/<pid>/fd: open descriptors (pipe/file) (M1194) */
int    app_alive(app_t *a);
int    app_shows_caret(app_t *a);                /* does this app's window blink a text caret right now? (M1527) */
int    app_reap(app_t *a);                       /* free a self-exited app's task+stack+slot (WM) */
int    app_slot_max(void);                       /* process-slot count, for the WM's reap sweep (M2025) */
app_t *app_exited_slot(int i);                   /* slot i if it holds an exited, un-reaped process (M2025) */
void   app_request_kill(app_t *a);               /* ask a running app to close (it self-exits) */
void   app_kill_check(void);                     /* honor a pending kill from a polling/gfx/sleep syscall (exits) */
int    app_dirty_clear(app_t *a);                /* 1 if the grid changed (WM poll) */
int    app_sys_pollkey(void);                    /* non-blocking key for the caller */
void   app_render(app_t *a, int px, int py, int focused); /* draw text grid (+caret if focused) */
void   grid_write(struct app *a, const char *buf, unsigned len);   /* terminal-interpreting write into an app grid (M2004) */
void   app_key(app_t *a, char c);              /* deliver one keystroke        */

/* Mouse-driven text selection + clipboard (WM calls these; row/col are visible cells). */
void   app_sel_begin(app_t *a, int row, int col);   /* start a selection at the anchor cell */
void   app_sel_extend(app_t *a, int row, int col);  /* drag the selection end */
void   app_sel_commit(app_t *a);                    /* release: copy the selection to the clipboard */
void   app_sel_clear(app_t *a);                     /* drop the highlight */
void   app_sel_word(app_t *a, int row, int col);    /* double-click: select+copy the word at a cell */
void   app_scroll_frac(app_t *a, int num, int den);  /* scrollbar click/drag: thumb at num/den of track */
void   app_paste(app_t *a);                         /* inject the clipboard into the input queue */
void   clip_set(const char *s, int n);              /* set the system clipboard */
int    clip_get(char *out, int max);                /* read it (NUL-terminated); returns length */
int    app_cols(void);                              /* default terminal open size (cols) */
int    app_rows(void);                              /* ... rows */
int    app_grid_cols(app_t *a);                     /* a terminal's CURRENT visible grid size (M1473) */
int    app_grid_rows(app_t *a);
void   app_set_grid(app_t *a, int cols, int rows);  /* WM: resize the live grid to fit the window */
int    app_is_gfx(app_t *a);                        /* 1 = gfx-canvas app, 0 = text terminal */

/* Called from the syscall dispatcher, acting on the currently-running app. */
void   app_sys_write(const char *buf, unsigned len);
int    app_sys_read(char *buf, unsigned max);
struct termios;
int    app_tcgetattr(struct termios *t);          /* read the TTY discipline mode (M1174) */
int    app_tcsetattr(const struct termios *t);    /* set the TTY discipline mode cooked/raw (M1174) */
int    app_tcflush(int queue_selector);           /* discard unread input (TCIFLUSH/TCIOFLUSH); TCOFLUSH is a no-op; 0/-1 (M1570) */
int    app_tcdrain(void);                          /* wait for pending output; a no-op here (synchronous output); 0/-1 (M1570) */
int    app_sys_getpid(void);
int    app_sys_getppid(void);          /* parent pid, for getppid(2) (M1236) */
void   app_chdir_track(const char *rel);   /* update cwd_path after a successful chdir, for getcwd (M1248) */
long   app_getcwd(char *buf, unsigned long max);  /* copy the cwd string out; length/-1 (M1248) */
const char *app_cwd_str(app_t *a);     /* the cwd path string of any app, for /proc/<pid>/cwd (M1249) */
const char *app_exe_str(app_t *a);     /* the spawn/exec path of any app, for /proc/<pid>/exe (M1250) */
int    app_pipe2(int *out, int flags); /* pipe() + atomic O_CLOEXEC (M1239) */
int    app_unix_send_fd(int sockfd, int fd);  /* SCM_RIGHTS keyed on the SOCKET fd (M1977) */
int    app_unix_recv_fd(int sockfd);          /* SCM_RIGHTS receive keyed on the socket fd; new fd/-1 (M1977) */
int    app_scm_send(int ep, int fd);   /* SCM_RIGHTS: queue fd to pass over an AF_UNIX endpoint; 0/-1 (M1265) */
int    app_scm_recv(int ep);           /* SCM_RIGHTS: install a passed fd from the peer; new fd/-1 (M1265) */
int    app_scm_take_memfd(int ep, void **base, unsigned long *size);  /* take a passed memfd as an object, for the in-kernel compositor (M1979) */
/* Same, but also reports WHICH memfd object it was, so a caller that keeps the
 * pool alive past the request can re-query it later -- wl_shm_pool.resize has
 * to ask the object how big it actually is rather than believe the client.
 * `*idx` is an opaque handle for app_memfd_obj_info, not an fd. (M2058) */
int    app_scm_take_memfd_idx(int ep, void **base, unsigned long *size, int *idx);
/* The live base/size/capacity of a memfd OBJECT taken with the call above.
 * CAPACITY is what the object can be resized to without reallocating, which is
 * the only bound a compositor may safely hand a client. 0/-1. (M2058) */
int    app_memfd_obj_info(int idx, void **base, unsigned long *size, unsigned long *cap);
int    app_scm_give_kernel_memfd(int ep, const char *name, const void *data, unsigned long len);  /* the kernel hands a client a readable memfd: wl_keyboard.keymap (M1984) */
int    app_eventfd_create(unsigned int initval, int flags);  /* pollable u64-counter fd (M1242) */
int    app_inotify_init(void);                       /* a pollable filesystem-watch fd (M1266) */
int    app_inotify_add(int fd, const char *path, unsigned int mask);  /* register a watch; wd/-1 (M1266) */
int    app_inotify_rm(int fd, int wd);                /* unregister a watch by wd; 0/-1 (M1568) */
int    app_socket(int domain, int type);
int    app_unix_bind(int fd, const char *path);   /* AF_UNIX: record the name (M1965) */
int    app_unix_listen(int fd);                   /* AF_UNIX: claim the name, fd becomes a listener */
int    app_unix_accept(int fd);                   /* AF_UNIX: non-blocking accept -> new fd; -1 if none */
int    app_unix_connect(int fd, const char *path);/* AF_UNIX: connect to a listener */
int    app_unix_shutdown(int fd, int how); /* AF_UNIX: half-close (SHUT_WR -> peer EOF) (M1965) */
int    app_unix_socketpair(int *out);             /* AF_UNIX: two connected fds; 0/-1 */             /* AF_INET SOCK_DGRAM socket fd; fd/-1 (M1267) */
int    app_sock_bind(int fd, int port);              /* bind a datagram socket to a local port; 0/-1 (M1267) */
int    app_sock_localaddr(int fd, unsigned char ip[4], unsigned short *port);  /* getsockname for an AF_INET fd (M1967) */
int    app_sock_peeraddr(int fd, unsigned char ip[4], unsigned short *port);   /* getpeername for an AF_INET fd (M1986) */
long   app_sendto(int fd, const unsigned char ip[4], int port, const void *buf, int len);  /* bytes/-1 (M1267) */
long   app_recvfrom(int fd, void *buf, int max, unsigned char srcip[4], unsigned short *srcport);  /* bytes/-1 (M1267) */
int    app_connect(int fd, const unsigned char ip[4], int port);  /* connect a TCP socket fd; 0/-1 (M1268) */
int    app_setsockopt(int fd, int level, int optname, int val);    /* set a TCP-socket option; 0/-1 (M1554) */
int    app_getsockopt(int fd, int level, int optname, int *val);   /* read a TCP-socket option; 0/-1 (M1554) */
int    app_getsockname(int fd, unsigned char out[6]);   /* this socket's own {ip[4],port}; 0/-1 (M1560) */
int    app_getpeername(int fd, unsigned char out[6]);   /* the connected peer's {ip[4],port}; 0/-1 (M1560) */
uint64_t app_sbrk(long inc);
uint64_t app_heap_base(void);                    /* the heap base (M2049) */
void     app_set_break(uint64_t addr);           /* lower the recorded break; brk must honour a shrink (M2049) */            /* grow the calling app's heap; old break or -1 */
uint64_t app_mmap(uint64_t len);
uint64_t app_mmap_fixed(uint64_t addr, uint64_t len);   /* MAP_FIXED anon: reserve at the CALLER's address; 0 if unaligned/out of range/overlapping (M1952) */        /* reserve a demand-paged anonymous region; base VA or 0 */
uint64_t app_mmap_huge(uint64_t len);   /* reserve a 2 MiB-backed demand-paged region (MAP_HUGETLB); base VA or 0 (M1155) */
uint64_t app_mmap_file(const char *path, uint64_t len, int shared);
uint64_t app_mmap_file_at(const char *path, uint64_t addr, uint64_t len, uint64_t off, int shared);  /* file-backed at a chosen addr + file OFFSET -- what ld.so needs (M1953) */   /* demand-paged file-backed region; shared=0 MAP_PRIVATE (M1136), shared=1 MAP_SHARED (M1544); base VA or 0 */
int      app_msync(uint64_t addr, uint64_t len);   /* flush a MAP_SHARED file-backed mmap's dirty pages to disk; 0/-1 (M1544) */
struct registers;
long     app_clone(struct registers *r, uint64_t fn, uint64_t stack, uint64_t arg);  /* spawn a thread sharing this address space; tid/-1 (M1138) */
void     app_thread_exit(void);    /* end just the calling thread's task (M1138) */
int      app_gettid(void);         /* the calling thread's id (its task id) (M1138) */
long     app_join(int tid);        /* block until thread `tid` exits, then reap it; 0/-1 (M1139) */
uint64_t app_ringbuf(uint64_t len);     /* a magic mirrored ring buffer: len frames mapped twice back-to-back */
int      app_mprotect(uint64_t addr, uint64_t len, int prot);   /* change R/W/X of a mapped range (W^X/JIT); 0/-1 */
int      app_munmap(uint64_t addr, uint64_t len);   /* free an mmap region; 0/-1 */
uint64_t app_mremap(uint64_t old_addr, uint64_t old_len, uint64_t new_len, int flags);  /* resize/move an mmap region; base or -1 (M1179) */
int      app_mseal(uint64_t addr, uint64_t len);    /* irreversibly seal mmap regions in range against munmap/mprotect; count/-1 (M1130) */
int      app_uffd_register(uint64_t addr, uint64_t len);   /* userfaultfd: route this region's faults to a monitor; 0/-1 (M1134) */
long     app_uffd_read(void);                              /* monitor: block until a fault; returns the faulting page addr, or -1 */
int      app_uffd_copy(uint64_t addr, const void *data, uint64_t len);  /* monitor: fill the faulting page + wake the owner; 0/-1 */
int      app_madvise(uint64_t addr, uint64_t len, int advice);  /* MADV_DONTNEED(4): drop resident anon frames; pages dropped/-1 */
int      app_process_madvise(int pidfd, uint64_t addr, uint64_t len, int advice);  /* MADV_COLD only, on another process; pages touched/-1 (M1555) */
int      app_mincore(uint64_t addr, uint64_t len, uint8_t *vec); /* per-page residency of an mmap range; vec[i]=1 resident; 0/-1 (M1147) */
int      app_mlock(uint64_t addr, uint64_t len);                /* pin mmap pages against reclaim (swap/madvise skip them); 0/-1 (M1149) */
int      app_munlock(uint64_t addr, uint64_t len);              /* unpin mmap pages locked by app_mlock; 0/-1 (M1149) */
int      app_mlockall(int flags);                               /* MCL_CURRENT pins all VMAs, MCL_FUTURE auto-pins new mmaps; 0/-1 (M1283) */
int      app_munlockall(void);                                  /* unpin all VMAs + clear MCL_FUTURE; 0/-1 (M1283) */
int      app_swap_out(uint64_t addr, uint64_t len);             /* page out anon pages in range to swap; pages/-1 (M1105) */
uint64_t app_shm_open(const char *name, uint64_t size);
int      app_shm_fd(const char *name, int o_creat, int o_excl);  /* open /dev/shm/NAME as a shareable memfd; fd or -errno (M2008) */
int      app_shm_unlink(const char *name);                       /* shm_unlink: drop the NAME, keep the object (M2008) */         /* map a named shared-memory object; base VA or 0 (M1108) */
long     app_futex(uint64_t uaddr, int op, int val, long timeout_ms);  /* FUTEX_WAIT/WAKE on a (possibly shared) user word; timeout_ms<0 = wait forever (M1109, timeout M1578) */
int      app_fault_handle(uint64_t cr2, uint64_t err); /* #PF hook: COW copy / swap-in / lazily map an mmap page; 1 if handled */
struct registers;                                   /* (interrupts.h) */
long     app_fork(struct registers *r);             /* COW fork: child returns 0, parent returns child pid; -1 fail (M1116) */
long     app_clone_linux(struct registers *r, unsigned long flags, uint64_t stack,
                         uint64_t ptid, uint64_t ctid, uint64_t tls);   /* a REAL thread, Linux entry convention: returns in the child (M1959) */
void     app_futex_dump(void);                   /* who is parked on a futex; printed on a sync-run timeout (M1959) */
int      app_is_main_thread(void);               /* exit(2) ends a thread, but the MAIN thread's exit(2) ends the process (M1959) */
long     app_fork_at(struct registers *r, uint64_t child_rsp);  /* ... and with the CHILD's rsp overridden: clone(CLONE_VM|CLONE_VFORK, stack), what posix_spawn uses (M1958) */
long     app_vfork_at(struct registers *r, uint64_t child_rsp);  /* REAL vfork: shared address space + suspended parent (M2006) */
void     app_vfork_release(app_t *a);                            /* child exec'd or exited: release its vfork parent (M2006) */
long     app_process_vm_read(int pid, uint64_t raddr, void *local, uint64_t len);  /* read another (same-tree) process's memory; bytes/-1 (M1162) */
long     app_process_vm_write(int pid, uint64_t raddr, const void *local, uint64_t len);  /* write another (same-tree) process's memory (COW-safe); bytes/-1 (M1165) */
int      app_setrlimit(int resource, uint64_t val);   /* set a resource limit (RLIMIT_NPROC); 0/-1 (M1163) */
uint64_t app_getrlimit(int resource);                 /* read a resource limit (RLIM_INFINITY if unset) (M1163) */
long     app_prlimit(int pid, int resource, uint64_t newval, int do_set);  /* get/set another process's rlimit; old value (M1214) */
int      app_format_limits(app_t *a, char *b, int max);   /* render /proc/<pid>/limits (M1214) */
int      app_format_auxv(app_t *a, char *b, int max);     /* synthetic ELF auxv for /proc/<pid>/auxv (M1215) */
long     app_exec(struct registers *r, const char *name, const char *arg);  /* replace this process's image in place; -1 fail (M1121) */
long     app_singlestep(struct registers *r, int n);  /* hardware single-step the next n user instructions (M1123) */
void     app_singlestep_trap(struct registers *r);    /* #DB handler: record the RIP, keep/stop stepping */
int      app_sstep_get(app_t *a, uint64_t *out, int max);  /* copy the recorded single-step RIPs; returns count */
/* seccomp-notify: userspace syscall supervision (M1124) */
long     app_seccomp_arm(int nr);                          /* child: trap syscall `nr` to the supervisor */
int      app_seccomp_traps(app_t *a, uint64_t nr);         /* does `a` trap syscall `nr`? */
long     app_seccomp_notify(app_t *a, uint64_t nr, uint64_t a1, uint64_t a2, uint64_t a3, int *run_real);  /* park the child */
long     app_seccomp_wait(int childpid, uint64_t *ev4);    /* supervisor: block until the child parks; ev[4]={nr,a,b,c} */
long     app_seccomp_reply(int childpid, int run_real, long retval);  /* supervisor: deliver the verdict */
long     app_ptrace(long req, int pid, uint64_t addr, uint64_t data); /* ptrace: stop/inspect/continue a traced child (M1199) */
int      app_trace_on_signal(app_t *a, int signo);  /* SYS_raise hook: traced proc -> trace-stop; 1 if handled */
/* signalfd: signals routed to /proc/self/sigfd instead of a handler (M1126) */
long     app_signalfd(uint32_t mask);                      /* arm: route the masked signos to signalfd */
long     app_sigfd_read(app_t *a, char *buf, int max);     /* read the next sigfd signo (blocks); text + '\n' */
int      app_sigfd_ready(app_t *a);                        /* fswait peek: a sigfd signal pending? */
void app_signal_set(int signo, uint64_t handler, uint64_t restorer);  /* SYS_signal */
void app_sigaction(int signo, uint64_t handler, uint64_t restorer, uint32_t flags);  /* SYS_sigaction: SA_SIGINFO etc. (M1270) */
void app_sigaction_full(int signo, uint64_t handler, uint64_t restorer, uint32_t flags, uint64_t samask);  /* + sa_mask, for rt_sigaction (M2063) */
uint64_t app_sig_handler_of(int signo);   /* what rt_sigaction's oldact must report (M2063) */
uint32_t app_sig_flags_of(int signo);
uint64_t app_sig_restorer_of(void);
uint64_t app_sig_mask_of(int signo);
int  app_signal_deliver(struct registers *r, int signo);  /* redirect r to the handler; 1 if delivered */
void app_sigreturn(struct registers *r);            /* restore the pre-signal context */
void app_request_signal(app_t *a, int signo);      /* async-raise a signal (Ctrl-C->SIGINT); opt-in (needs a handler) */
/* kill/tkill/tgkill for the Linux ABI: raise `signo` at `pid` (<=0 or our own
 * pid = self), honouring SIG_IGN and the default action. 0 = raised/discarded,
 * 1 = the CALLER must exit 128+signo, 2 = the target was killed, -1 = ESRCH.
 * The decision needs struct app, so it lives in app.c. (M2063) */
int  app_raise_signal_to(int pid, int signo);
int  app_raise_signal_to_thread(int pid, int tid, int signo);   /* tkill/tgkill/pthread_kill: the named THREAD, not just its process (M2075) */
uint64_t app_sigprocmask(int how, uint64_t set);   /* block/unblock signals; returns the old mask (M1208; 64-bit since M2063) */
uint64_t app_sigpending(void);                      /* the raised-but-blocked (pending) signal set (M1209) */
int      app_signal_deliverable(void);              /* 1 if the current task has a real (handled, unblocked) signal pending (M1567) */
long     app_sigsuspend(struct registers *r, uint64_t mask);  /* swap the blocked mask, block for a signal, deliver it, restore + always -1 (M1561) */
long     app_pause(struct registers *r);                     /* block for a signal using the CURRENT mask, unchanged; always -1 (M1563) */
int  app_sigqueue(int pid, int signo, uint64_t value);  /* SYS_sigqueue: RT signal carrying a queued sigval payload (M1271) */
/* POSIX per-process interval timers: timer_create(2) firing a signal via the sigqueue FIFO (M1272) */
long app_timer_create(int signo, uint64_t value);                                   /* -> timer id, or -1 */
long app_timer_settime(int id, int abs, uint64_t value_ms, uint64_t interval_ms);   /* arm/disarm; 0/-1 */
long app_timer_gettime(int id);                                                     /* ms until next fire, or -1 */
long app_timer_delete(int id);                                                      /* 0/-1 */
void app_timer_tick(void);                                                          /* timer-IRQ hook: fire due timers on every app */
/* Job control (M1176): process groups + sessions + foreground TTY group. */
int  app_setpgid(int pid, int pgid);   /* set a process's group (pid 0 = self, pgid 0 = own pid); 0/-1 */
int  app_getpgid(int pid);             /* a process's group id (pid 0 = self); -1 if absent */
int  app_getsid(int pid);              /* a process's session id (pid 0 = self); -1 if absent (M1580) */
int  app_setsid(void);                 /* become session+group leader; returns sid */
int  app_tcsetpgrp(int pgid);          /* set the console's foreground process group; 0 */
int  app_tcgetpgrp(void);              /* the console's foreground process group (0 = none) */
int  app_killpg(int pgid, int signo);  /* deliver signo to every app in pgid (killpg); count/-1 */
int  app_pipe(int *out);               /* pipe(): out[0]=read fd, out[1]=write fd; 0/-1 (M1187) */
/* Negative returns from app_fd_read/app_fd_write. Historically every failure
 * was a bare -1, which the Linux ABI layer had no choice but to report as
 * EBADF -- and "EBADF" on a healthy socket sends the caller looking for a
 * descriptor bug that isn't there. A socket needs two failures told apart from
 * a bad fd: "nothing right now" and "the peer is gone". (M1965) */
#define APP_FD_EAGAIN (-11)   /* would block; the value is Linux's EAGAIN */
#define APP_FD_EPIPE  (-32)   /* peer closed;  the value is Linux's EPIPE  */
/* READ ON A DIRECTORY IS EISDIR, NOT EBADF (M2071). The value is Linux's
 * EISDIR, so the ABI layer needs no translation table -- and the distinction
 * is load-bearing: opening `.git` and reading it is how every git client asks
 * "is this a normal repository or a worktree pointer file?". EISDIR means
 * directory, success means it is a file holding `gitdir: ...`. Answered EBADF,
 * the caller learns neither, and cannot tell a directory from a broken
 * descriptor. */
#define APP_FD_EISDIR (-21)   /* the fd names a directory; the value is Linux's EISDIR */
long app_fd_read(int fd, void *buf, unsigned long max);        /* read a pipe fd; bytes/0 EOF/-1 (M1187) */
long app_fd_write(int fd, const void *buf, unsigned long len); /* write a pipe fd; bytes/-1 EPIPE (M1187) */
int  app_termios_get(uint32_t *ifl, uint32_t *ofl, uint32_t *cfl, uint32_t *lfl, uint8_t *cc);  /* the terminal settings this app asked for (M2014) */
int  app_termios_set(uint32_t ifl, uint32_t ofl, uint32_t cfl, uint32_t lfl, const uint8_t *cc); /* ...and TCSETS, stored for real */
long app_fd_port(int fd);                     /* the local port bind() recorded (M2020) */
int  app_inet_bind(int fd, uint16_t port);    /* AF_INET bind; returns the port actually bound (M2020) */
int  app_inet_listen(int fd, int backlog);    /* ...and turn it into a listener */
int  app_inet_accept(int fd);                 /* one non-blocking passive open; new fd or -EAGAIN */
int  app_tio_echo(void);                                      /* is ECHO on? (M2014) */
void app_epoll_dump_of(app_t *a, int epfd);   /* ...for a process that is not the caller (M2016) */
void app_net_stall_watch(void);   /* report a socket that has gone quiet (M2016) */
extern int g_net_trace;   /* -append lxnettrace: trace socket byte counts (M2016) */
int  app_fd_nonblock(int fd);                                  /* is O_NONBLOCK set on this fd? (M1965) */
int  app_fd_set_nonblock(int fd, int on);                      /* fcntl(F_SETFL, O_NONBLOCK); 0/-1 (M1965) */
int  app_fd_obj(int fd);                                       /* the object index behind an fd (pipe no., memfd idx), or -1 (M2004) */
int  app_fd_type(int fd);
long app_memfd_size(int fd);                                   /* a memfd's size, or -1 if fd is not one (M2000) */
void app_memfd_selftest(void);                                 /* boot-time: a MAPPED memfd can grow, and its old buffer is retired (M2082) */
uint64_t app_mmap_hint(uint64_t addr, uint64_t len);           /* mmap's addr WITHOUT MAP_FIXED: place there only if free, else 0 (M2000) */
void app_set_next_env(const char *e);                          /* one extra env var for the NEXT Linux spawn only (M1999) */
void app_set_next_cwd(const char *p);                          /* working directory for the NEXT Linux spawn only (M2056) */
void app_term_selftest(void);                                  /* -append termtest: assert on the terminal's CELLS, not a screenshot (M2057) */
int  app_current_pid(void);                                    /* the calling process's pid, or -1 (M1998) */
void app_describe_fault_addr(void);                             /* describe the page CR2 points at: VMA, prot, PTE bits (M2005) */
void app_describe_addr(uint64_t addr);                          /* print the file+offset an address maps to, for a fault report (M2003) */
void app_epoll_dump(int epfd);                                 /* print an epoll instance's registered fds + readiness (M1998) */                                      /* fd-table type, or -1 if not open (M1965) */
int  app_fd_set_cloexec(int fd, int on);                       /* FD_CLOEXEC, for MFD_CLOEXEC/SOCK_CLOEXEC (M1977) */
#define APP_NREAD_ENOTTY (-1)   /* this kind of descriptor keeps no byte count at all (M2086) */
#define APP_NREAD_EINVAL (-2)   /* a socket with no byte stream to count -- a listener (M2086) */
int  app_fd_nread(int fd, long *out);                          /* FIONREAD: bytes readable without blocking; 0/APP_NREAD_* (M2086) */
long app_console_nread(void);                                  /* FIONREAD on fd 0/1/2 with no table entry: queued keys (M2086) */
long app_pread(int fd, void *buf, unsigned long max, long off);        /* read a FILE fd without moving its cursor; bytes/0 EOF/-1 (M1572) */
long app_pwrite(int fd, const void *buf, unsigned long len, long off); /* write a FILE fd without moving its cursor; bytes/-1 (M1572) */
int  app_fd_close(int fd);             /* close an fd; 0/-1 (M1187) */
int  app_dup2(int oldfd, int newfd);   /* redirect newfd onto oldfd's object; newfd/-1 (M1187) */
int  app_fd_is_redirected(app_t *a, int fd);  /* is fd a redirected pipe/file? (stdio + file-fd routing, M1191/M1193) */
int  app_fd_ready(app_t *a, int fd, int events); /* poll(2): revents subset of events that won't block now (M1210) */
long app_splice(int in_fd, int out_fd, unsigned long len); /* move bytes pipe->pipe in-kernel (consumes src); bytes/0/-1 (M1211) */
long app_tee(int in_fd, int out_fd, unsigned long len);    /* copy bytes pipe->pipe (src preserved); bytes/0/-1 (M1211) */
int  app_memfd_create(const char *name, int flags);        /* anonymous sealable in-RAM file fd (>=3); -1 (M1212) */
long app_memfd_seal(int fd, unsigned add);                 /* add F_SEAL_* (one-way); new seal set/-1 (M1212) */
long app_ftruncate(int fd, long len);                      /* resize a memfd (seal-checked); 0/-1 (M1212) */
uint64_t app_mmap_memfd(int fd, uint64_t len, uint64_t off);  /* MAP_SHARED a memfd: the wl_shm primitive; VA/0 (M1977) */
long app_fsync(int fd);                                     /* fsync/fdatasync: 0 for a real file fd (write-through already durable), -1 otherwise (M1566) */
long app_sync_file_range(int fd, uint64_t offset, uint64_t nbytes, unsigned flags);  /* same as app_fsync; range/flags unused (M1566) */
void app_sync(void);                                        /* whole-system flush, no fd, never fails (M1588) */
int  app_timerfd_create(void);                             /* a pollable one-shot timer fd (>=3); -1 (M1217) */
long app_timerfd_settime(int fd, long delay_ms, long interval_ms);
long app_timerfd_remaining_ms(int fd);                     /* ms until it fires, 0 = disarmed/expired, -1 = not a timerfd (M2073) */
long app_timerfd_interval_ms(int fd);                      /* its periodic interval in ms, 0 = one-shot (M2073) */  /* arm a timerfd: initial delay + periodic interval (ms; interval 0 = one-shot, delay <=0 disarms); 0/-1 (M1217, periodic M1302) */
long app_fcntl(int fd, int cmd, long arg);                 /* F_GETFD/SETFD/DUPFD/DUPFD_CLOEXEC (M1218) */
int  app_dup3(int oldfd, int newfd, int flags);            /* dup w/ O_CLOEXEC; -1 if old==new (M1218) */
long app_close_range(unsigned lo, unsigned hi, int flags); /* close fds in [lo,hi]; 0/-1 (M1218) */
long app_sendfile(int out_fd, int in_fd, long *off, unsigned long count); /* zero-copy fd->fd; bytes/-1 (M1219) */
int  app_fd_is_open(int fd);        /* is fd a live fd-table entry? distinguishes a dup2'd stdio fd from an untouched one (M1949) */
const char *app_fd_path(int fd);                           /* path behind a FILE fd (type 2), or 0 (M1221) */
const char *app_fd_path_of(int fd);                        /* path behind ANY fd that has one, incl. a directory (M2032) */
int  app_pidfd_open(int pid);                              /* a pollable process-exit handle (>=3); -1 (M1222) */
int  app_pidfd_send_signal(int pidfd, int sig);            /* signal the pidfd's process; 0/-1 (M1222) */
int  app_pidfd_getfd(int pidfd, int targetfd);             /* duplicate the pidfd-process's fd into ours; new fd/-1 (M1281) */
uint64_t app_aslr_base(int pid);                           /* the ASLR-randomized mmap base of pid (0=self), for verification (M1287) */
long app_getdents64(void *buf, unsigned long max, int start); /* packed dirent64 of the cwd; bytes/0/-1 (M1223) */
struct epoll_event;                                        /* full definition in syscall.h (M1220) */
int  app_epoll_create(void);                               /* an epoll fd (>=3); -1 (M1220) */
int  app_epoll_ctl(int epfd, int op, int fd, unsigned events, unsigned long data); /* ADD/MOD/DEL; 0 or a NEGATIVE LINUX ERRNO (M1220/M1965) */
int  app_epoll_check(int epfd, struct epoll_event *out, int maxevents);  /* one non-blocking readiness pass; count/-1 (M1220) */
int  app_open(const char *path, int flags);   /* open a FILE fd (O_RDONLY default; O_WRONLY/APPEND/TRUNC/CREAT); fd(>=3)/-1 (M1193/M1195) */
long app_pts_number(int fd);                   /* ptsname: the /dev/pts/<n> index for a /dev/ptmx master fd, or -1 (M1274) */
int  app_oom_kill(void);                       /* OOM killer: cooperatively terminate the highest-scoring process; victim pid/-1 (M1275) */
long app_oom(int cmd, int arg);                /* SYS_oom: 0=set self oom_adj 1=trigger kill 2=score of pid (M1275) */
long app_sigaltstack(uint64_t ss_sp, uint64_t ss_size);  /* register an alternate signal stack for SA_ONSTACK handlers; 0/-1 (M1276) */
long app_oom_score_of(app_t *a);               /* OOM score (RSS pages + oom_adj bias) of any app, for /proc/<pid>/oom_score (M1277) */
int  app_oom_adj_get(app_t *a);                /* the oom_score_adj tuning bias of any app (M1282) */
void app_oom_adj_set(app_t *a, int v);         /* set oom_score_adj (clamped to [-1000,1000]) (M1282) */
long app_lseek(int fd, long off, int whence); /* reposition a FILE fd (0=SET,1=CUR,2=END); new offset/-1 (M1193) */
long app_utimens(const char *path, long atime, long mtime);  /* set a path's atime/mtime (UTIME_NOW/OMIT); 0/-1 (M1230) */
long app_futimens(int fd, long atime, long mtime);           /* set an open fd's atime/mtime; 0/-1 (M1230) */
int  app_mkfifo(const char *path);     /* create a named pipe (FIFO); 0/-1 (M1188) */
int  app_fifo_open(const char *path, int write);  /* open a FIFO end -> fd; -1 (M1188) */
int  app_seccomp_filter_install(const void *prog, int n);   /* install a self-imposed BPF syscall filter; 0/-1 (M1190) */
int  app_seccomp_filter_active(app_t *a);                   /* does this app have a seccomp-BPF filter? (M1190) */
long app_seccomp_filter_check(app_t *a, uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2);  /* raw verdict: 0 deny / 2 kill / else allow (M1190, M1192) */
int  app_deliver_pending(struct registers *r);     /* deliver a pending async signal on return to ring 3; 1 if delivered */
void app_set_alarm(uint64_t ticks);                /* SYS_alarm: arm a periodic SIGALRM every `ticks` ticks (0=disarm) */
void app_alarm_tick(void);                         /* timer IRQ hook: raise SIGALRM if the current app's alarm is due */
void app_setitimer(uint64_t delay_ticks, uint64_t interval_ticks);  /* SYS_setitimer(ITIMER_REAL): delay to first fire, independent repeat interval; 0 delay = disarm (M1565) */
void app_getitimer(uint64_t *remain_ticks, uint64_t *interval_ticks);  /* SYS_getitimer: time left + configured interval (M1565) */
void app_cpulimit_tick(void);                      /* timer IRQ hook: raise SIGXCPU if the current task exceeds RLIMIT_CPU (M1548) */
void app_set_traced(app_t *a, int on);             /* strace: log this app's syscalls to dmesg */
int  app_is_traced(app_t *a);
void app_jail_next(uint32_t promises, const char *path);   /* confine the NEXT spawned app (pledge + unveil) */
int    app_gfx_init(int w, int h);     /* put the caller in graphics mode (w*h pixel canvas) */
int    app_gfx_blit(const uint32_t *pixels);  /* copy the caller's pixels to the canvas */
int    app_gfx_get(app_t *a, uint32_t **buf, int *w, int *h);  /* WM: canvas + dims; 1/0 */
void   app_set_rawkb(int on);          /* caller opts into raw make/break key events */
void   app_set_caret(int on);          /* 1 = show system caret (default), 0 = app draws its own */
int    app_caret_hidden(app_t *a);     /* WM: 1 if this app draws its own view (full-screen) */
int    app_get_rawkb(app_t *a);        /* WM: is this app in raw keyboard mode? */
void   app_key_raw(app_t *a, unsigned short ev);  /* WM: deliver a raw key event */
int    app_sys_getkbevent(void);       /* next raw key event for the caller, or -1 */
void   app_set_mouse(app_t *a, int x, int y, int btn);  /* WM: canvas-relative cursor + buttons */
long   app_get_mouse(void);            /* SYS_mouse: packed x|y|buttons for the caller */
void   app_add_mouse_rel(app_t *a, int dx, int dy);  /* WM: accumulate relative motion */
long   app_get_mouse_rel(void);        /* SYS_mouse_rel: packed dx|dy, read+cleared */
void   app_sys_clear(void);             /* clear the calling app's screen */
void   app_setcolor(int idx);           /* set the calling app's text colour (palette 0-15) */
void   app_sys_exit(int code);          /* records the exit status; does not return */
long   app_waitpid(int pid, int *status);   /* block until a child (pid, or -1=any) exits; returns its pid + *status (M1117) */
long   app_wait4(int pid, int *status, int nohang);   /* wait4, honouring WNOHANG (M2025) */
void   app_fault_current(struct registers *r);  /* a ring-3 task faulted: dump a core, kill it, keep the kernel alive; no return */
void   app_core_dump(struct registers *r);      /* write an ET_CORE ELF of the faulting app to /tmp/core (M1104) */

/* pledge() sandbox (M1074): a process voluntarily drops the right to make whole
 * classes of syscalls; the dispatcher kills it if it then tries one. The class
 * bits are the user ABI (named in the string passed to pledge()). */
#define PL_STDIO (1u<<0)   /* basic I/O: read/write/time/sleep/poll/signal/sbrk/rng */
#define PL_RPATH (1u<<1)   /* read the filesystem */
#define PL_WPATH (1u<<2)   /* create / write / delete files */
#define PL_INET  (1u<<3)   /* network */
#define PL_GFX   (1u<<4)   /* graphics + audio + clipboard */
#define PL_PROC  (1u<<5)   /* spawn / kill / process listing */
#define PL_VM    (1u<<6)   /* mmap / munmap */
#define PL_POWER (1u<<7)   /* power off / reboot */
#define PL_THREAD (1u<<8)  /* clone/join: threads sharing THIS address space (M1533) —
                             * deliberately separate from PL_PROC: a sandboxed decoder
                             * can be allowed to parallelize itself across cores without
                             * gaining the ability to spawn/exec/kill other processes. */

app_t   *app_current(void);             /* the app owning the running task, or NULL */
void     app_cwd_save(app_t *a, int synth, const char *sub, uint32_t fat);   /* stash an app's cwd (M1144) */
void     app_cwd_load(app_t *a, int *synth, char *sub, int submax, uint32_t *fat);  /* load an app's cwd (M1144) */
int      app_ns_id(app_t *a);           /* the app's mount-namespace id (0 = shared) (M1122) */
void     app_set_ns_id(app_t *a, int id);
int      app_pledge(app_t *a, uint32_t mask);   /* restrict promises (monotonic); 0/-1 */
int      app_is_pledged(app_t *a);      /* 1 once pledge() has been called */
uint32_t app_promises(app_t *a);        /* current promise bitmask */
int      app_pledge_parse(const char *s, uint32_t *out);  /* names -> mask; 0 ok, -1 unknown name */
int      app_pledge_format(uint32_t mask, char *buf, int max);  /* mask -> "stdio rpath ..."; bytes */

/* unveil() — restrict which filesystem paths the process can reach (default:
 * all, until the first unveil). A denied access fails (-1), it does not kill. */
#define UV_R (1u<<0)   /* read permission for an unveiled prefix */
#define UV_W (1u<<1)   /* write/create permission */
int      app_unveil(app_t *a, const char *path, uint32_t perms);  /* add a prefix (path NULL = lock); 0/-1 */
uint32_t app_unveil_parse(const char *perms);   /* "rwc" -> UV_* bits */
int      app_unveil_ok(app_t *a, const char *path, int need_write);  /* 1 if the path is reachable */
int    app_sys_history(char *buf, int max);  /* the caller's command history */
