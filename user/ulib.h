/* ulib.h — tiny userspace C library (the start of a libc). */
#pragma once
#include "robust.h"   /* robust_t + FUTEX_OWNER_DIED, for robust mutexes (M1141) */
#include "syscall.h"  /* SYS_* numbers + shared ABI structs (e.g. struct rusage, M1150) */

/* raw syscalls */
long sys_write(int fd, const void *buf, unsigned long len);
long sys_read(int fd, void *buf, unsigned long len);
void sys_exit(int code);
int  sys_getpid(void);
long sys_fork(void);                 /* COW fork: child returns 0, parent returns child pid, -1 on failure (M1116) */
long sys_waitpid(int pid, int *status);  /* block until child (pid, or -1=any) exits; returns its pid, *status=code (M1117) */
long sys_exec(const char *name, const char *arg);  /* replace this process's image with registered program `name`; -1 fail (M1121) */
long sys_unshare(void);              /* detach into a private mount namespace (later binds are private); 0/-1 (M1122) */
long sys_singlestep(int n);          /* hardware single-step the next n user instructions; read /proc/self/sstrace (M1123) */
/* seccomp-notify: userspace syscall supervision (M1124) */
long sys_seccomp(int nr);            /* child: trap syscall `nr` to a supervisor */
long sys_seccomp_wait(int childpid, unsigned long *ev4);  /* supervisor: block until child parks; ev={nr,a,b,c}; 1/0/-1 */
long sys_seccomp_reply(int childpid, int run_real, long retval);  /* supervisor: allow(run_real=1)/deny/emulate */
long sys_fswait(const char *const *paths, int n, long timeout_ms);  /* block until one of n paths is readable; index/-1 (M1125) */
long sys_poll(struct pollfd *fds, int nfds, long timeout_ms);       /* fd-table readiness multiplex; #ready/0 timeout/-1 (M1210) */
long sys_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);  /* fd_set-shaped readiness multiplex; #ready/0 timeout/-1 (M1584) */
long sys_ppoll(struct pollfd *fds, int nfds, long timeout_ms, unsigned sigmask);  /* like poll, signal-interruptible; #ready/-1 on signal/-1 (M1573) */
long sys_splice(int in_fd, int out_fd, unsigned long len);         /* move bytes pipe->pipe in-kernel (consumes src); bytes/0/-1 (M1211) */
long sys_tee(int in_fd, int out_fd, unsigned long len);            /* copy bytes pipe->pipe (src preserved); bytes/0/-1 (M1211) */
int  sys_memfd_create(const char *name, int flags);                /* anonymous sealable in-RAM file fd (>=3); -1 (M1212) */
long sys_memfd_seal(int fd, unsigned seals);                       /* add F_SEAL_*; new seal set/-1 (M1212) */
long sys_ftruncate(int fd, long len);                              /* resize a memfd (seal-checked); 0/-1 (M1212) */
long sys_fsync(int fd);                                            /* 0 for a real file fd, -1 otherwise (M1566) */
long sys_fdatasync(int fd);                                        /* identical to fsync here; 0/-1 (M1566) */
void sys_sync(void);                                               /* whole-system flush, no fd, never fails (M1588) */
long sys_sync_file_range(int fd, unsigned long offset, unsigned long nbytes, unsigned flags);  /* same as fsync; 0/-1 (M1566) */
long sys_signalfd(unsigned mask);    /* route the masked signos to /proc/self/sigfd instead of a handler (M1126) */
/* fanotify-style userspace file materialization (M1128) */
long sys_fanotify_serve(void);                       /* become the /fan daemon */
long sys_fanotify_wait(char *namebuf, int max);      /* block until a /fan read; fills the name; len/-1 */
long sys_fanotify_provide(const void *content, unsigned long len);  /* hand bytes back to the reader */
long sys_io_uring_enter(void *ring);                 /* drain a struct io_ring of batched ops; # completed/-1 (M1129) */
long sys_mseal(void *addr, unsigned long len);       /* irreversibly seal mmap regions in range vs munmap/mprotect; count/-1 (M1130) */
long sys_tcp_serve(int port, const void *resp, unsigned long resp_len, void *reqbuf, unsigned long reqmax);  /* serve one TCP conn; request bytes/-1 (M1133) */
long sys_tcp_accept(int port, void *reqbuf, unsigned long reqmax);  /* passive-open + read one request, hold the conn; request bytes/-1 (M1327) */
long sys_tcp_respond(const void *resp, unsigned long resp_len);     /* reply on the accepted conn + close; 0/-1 (M1327) */
/* userfaultfd (M1134): register a region, then a monitor process services its faults */
long sys_uffd_register(void *addr, unsigned long len);              /* route this region's faults to a monitor; 0/-1 */
long sys_uffd_read(void);                                           /* monitor: block until a fault; faulting page addr/-1 */
long sys_uffd_copy(void *addr, const void *data, unsigned long len);/* monitor: fill the faulting page + wake the owner; 0/-1 */
long sys_list(void *buf, unsigned long len);
long sys_readfile(const char *name, void *buf, unsigned long len);
long sys_writefile(const char *name, const void *buf, unsigned long len);
long sys_delete(const char *name);
long sys_time(void *buf, unsigned long len);
void sys_beep(int hz, int ms);
long sys_sysinfo(void *buf, unsigned long len);
void sys_clear(void);
void sys_reboot(void);
void sys_poweroff(void);   /* enter ACPI S5: power the machine off; never returns */
long sys_kill(int pid);    /* ask the app with this pid to close; 0 ok / -1 not found */
long sys_ping(void);
long sys_ping_host(const char *host);
long sys_netinfo(void *buf, unsigned long len);
long sys_dhcp(void);
long sys_cas_store(const void *buf, unsigned long len, void *hash32);
long sys_cas_fetch(const void *hash32, void *buf, unsigned long max);
long sys_tftp(const char *filename, void *buf, unsigned long max);
#define MADV_DONTNEED 4    /* drop resident pages now (re-fault zero) */
#define MADV_COLD     20   /* deactivate: clear accessed bits (M1158) */
#define MADV_PAGEOUT  21   /* page the range out to swap/zram now (M1158) */
#define MADV_COLLAPSE 25   /* synchronously fold the range into 2 MiB hugepage(s) (M1168) */
long sys_madvise(void *addr, unsigned long len, int advice);
long sys_process_madvise(int pidfd, void *addr, unsigned long len, int advice);  /* MADV_COLD only, on another process; pages/-1 (M1555) */
long sys_mincore(void *addr, unsigned long len, unsigned char *vec);   /* per-page residency; vec[i]=1 if resident; 0/-1 (M1147) */
long sys_mlock(void *addr, unsigned long len);     /* pin mmap pages against reclaim; 0/-1 (M1149) */
long sys_munlock(void *addr, unsigned long len);   /* unpin mlock'd mmap pages; 0/-1 (M1149) */
long sys_mlockall(int flags);                      /* MCL_CURRENT=1 pins all VMAs, MCL_FUTURE=2 auto-pins new anon mmaps; 0/-1 (M1283) */
long sys_munlockall(void);                         /* unpin all pages + clear MCL_FUTURE; 0/-1 (M1283) */
long sys_acpi(int what);                           /* ACPI AML namespace: 0=total 1=devices 2=methods 3=PCI0? 4=_SB_? (M1284) */
unsigned long sys_aslr(int pid);                   /* the ASLR-randomized mmap base of pid (0=self) (M1287) */
long sys_getrusage(int who, struct rusage *ru);    /* fill resource usage (RUSAGE_SELF=0); 0/-1 (M1150) */
long sys_fiemap(const char *path, struct fiemap_extent *out, int max);  /* file physical extent map; count/-1 (M1152) */
long sys_fallocate(const char *path, int mode, unsigned long offset, unsigned long len);  /* punch hole (FALLOC_FL_PUNCH_HOLE); blocks/-1 (M1153) */
long sys_mq_open(const char *name, int maxmsg, int msgsize);   /* open/create priority msg queue; index/-1 (M1154) */
long sys_mq_unlink(const char *name);                           /* remove a named message queue; 0/-1 (M1593) */
long sys_mq_send(int idx, const void *buf, unsigned long len, unsigned int prio);    /* enqueue; bytes/-1 (M1154) */
long sys_mq_receive(int idx, void *buf, unsigned long max, unsigned int *prio);      /* dequeue highest prio; bytes/-1 (M1154) */
long sys_mq_getattr(int idx, struct mq_attr *out);                                    /* flags/maxmsg/msgsize/curmsgs; 0/-1 (M1571) */
long sys_mq_setattr(int idx, const struct mq_attr *newattr, struct mq_attr *oldattr); /* set O_NONBLOCK only; 0/-1 (M1571) */
long sys_semget(int key, int nsems, int flags);                    /* SysV semaphore set; id/-1 (M1159) */
int  sys_sem_open(const char *name, int oflag, unsigned int value);  /* POSIX named semaphore; index/-1 (M1575) */
int  sys_sem_close(int idx);                                          /* drop this handle; 0/-1 (M1575) */
int  sys_sem_unlink(const char *name);                                /* remove the name; 0/-1 (M1575) */
int  sys_sem_wait(int idx);                                            /* block until value>0, then decrement; 0/-1 (M1575) */
int  sys_sem_trywait(int idx);                                        /* non-blocking sem_wait; 0/-1 (M1575) */
int  sys_sem_post(int idx);                                            /* increment + wake waiters; 0/-1 (M1575) */
int  sys_sem_getvalue(int idx, int *out);                             /* the current value; 0/-1 (M1575) */
long sys_semop(int semid, struct sembuf *sops, unsigned nsops);    /* atomic all-or-nothing semop; 0/-1 (M1159) */
long sys_semctl(int semid, int semnum, int cmd, int arg);          /* SETVAL/GETVAL/IPC_RMID (M1159) */
long sys_msgget(int key, int flags);                               /* SysV message queue; id/-1 (M1160) */
long sys_msgsnd(int id, const void *msgp, unsigned long sz, int flags);   /* enqueue {long mtype; data} (M1160) */
long sys_msgrcv(int id, void *msgp, unsigned long sz, long mtyp);  /* receive by type; bytes/-1 (M1160) */
int  sys_msgctl(int id, int cmd);                                  /* IPC_RMID only; 0/-1 (M1576) */
long sys_shmget(int key, unsigned long size, int flags);          /* SysV shm segment; id/-1 (M1161) */
void *sys_shmat(int shmid);                                       /* attach: base VA or 0 (M1161) */
long sys_shmdt(void *addr);                                       /* detach a shm mapping (M1161) */
int  sys_shmctl(int id, int cmd);                                  /* IPC_RMID only; 0/-1 (M1576) */
long sys_process_vm_read(int pid, unsigned long raddr, void *buf, unsigned long len);  /* read another process's mem; bytes/-1 (M1162) */
long sys_ptrace(long req, int pid, unsigned long addr, unsigned long data);  /* trace a child process (M1199) */
long sys_bpf_trace(const void *prog, unsigned long bytes);  /* load a global syscall-tracepoint BPF program (M1202) */
unsigned long sys_bpf_map_get(unsigned idx);                /* read a BPF histogram cell (M1202) */
long sys_process_vm_write(int pid, unsigned long raddr, const void *buf, unsigned long len);  /* write another process's mem (COW-safe); bytes/-1 (M1165) */
/* AF_UNIX path-keyed stream sockets (M1169): listen/connect/accept by path, send/recv over an endpoint id (survives fork) */
int  sys_unix_listen(const char *path);                /* -> listener id; -1 */
int  sys_unix_connect(const char *path);               /* -> client endpoint id; -1 */
int  sys_unix_accept(int lid);                         /* -> server endpoint id (blocks); -1 */
long sys_unix_send(int ep, const void *buf, unsigned long len);   /* bytes written; -1 closed */
long sys_unix_recv(int ep, void *buf, unsigned long max);         /* bytes read; 0 EOF; -1 bad ep */
int  sys_unix_close(int ep);                           /* 0/-1 */
int  sys_unix_wait_any(const int *eps, int n);         /* poll: index of first readable ep (blocks once); -1 (M1170) */
int  sys_unix_shutdown(int ep, int how);              /* half-close: SHUT_WR(1) gives the peer EOF; 0/-1 (M1965) */
int  sys_unix_unlisten(int lid);                      /* release a listener's bound name; 0/-1 (M1965) */
int  sys_socketpair(int *sv);                          /* socketpair(2): sv[0]/sv[1] = pre-connected AF_UNIX pair; 0/-1 (M1254) */
int  sys_nice(int nice);                               /* set current task's CFS nice (-20..19); returns clamped (M1171) */
int  sys_sched_setscheduler(int policy, int rt_priority);  /* SCHED_OTHER/FIFO/RR; rt_priority 1..99 for RT; 0/-1 (M1172) */
int  sys_sched_get_priority_max(int policy);               /* the valid rt_priority ceiling for a policy; -1 on a bad policy (M1589) */
int  sys_sched_get_priority_min(int policy);               /* the valid rt_priority floor for a policy; -1 on a bad policy (M1589) */
int  sys_sched_getscheduler(void);                          /* the caller's own scheduling policy; -1 if unset (M1591) */
int  sys_sched_getparam(void);                              /* the caller's own rt_priority (0 for SCHED_OTHER); -1 if unset (M1591) */
long sys_sched_rr_get_interval(long *sec, long *nsec);      /* the SCHED_RR timeslice as a real duration; 0/-1 (M1591) */
long sys_statx(const char *path, struct statx *st);        /* file metadata: mode/size/mtime/nlink (M1173) */
int  sys_tcgetattr(struct termios *t);                     /* read the TTY discipline mode (M1174) */
int  sys_tcsetattr(const struct termios *t);               /* set cooked/raw TTY mode (M1174) */
int  sys_tcflush(int queue_selector);                       /* discard unread input (TCIFLUSH/TCIOFLUSH); 0/-1 (M1570) */
int  sys_tcdrain(void);                                     /* wait for pending output; a no-op here; 0/-1 (M1570) */
int  sys_setpgid(int pid, int pgid);                       /* job control: set a process group (M1176) */
int  sys_getpgid(int pid);                                 /* process group id (M1176) */
int  sys_getsid(int pid);                                  /* session id; pid==0 = caller's own (M1580) */
int  sys_setsid(void);                                     /* become session+group leader (M1176) */
int  sys_tcsetpgrp(int pgid);                              /* set the console foreground group (M1176) */
int  sys_tcgetpgrp(void);                                  /* the console's foreground process group; 0 = none (M1558) */
int  sys_killpg(int pgid, int signo);                      /* signal every process in a group (M1176) */
int  sys_flock(const char *path, int op);                  /* advisory whole-file lock LOCK_SH/EX/UN|NB (M1177) */
long sys_getrlimit(int resource, struct rlimit *rl);   /* read a resource limit (M1163) */
long sys_setrlimit(int resource, struct rlimit *rl);   /* set a resource limit (M1163) */
long sys_alarm(unsigned long ticks);
long sys_setitimer(unsigned long delay_ticks, unsigned long interval_ticks);   /* ITIMER_REAL; 0 (M1565) */
long sys_getitimer(unsigned long *remain_ticks, unsigned long *interval_ticks);  /* 0/-1 (M1565) */
long sys_sntp(void);
long sys_swapout(void *addr, unsigned long len);
long sys_losetup(const char *path);
void *sys_shm_open(const char *name, unsigned long size);
long  sys_shm_unlink(const char *name);                     /* remove a named shared-memory object's name; 0/-1 (M1590) */
long sys_futex(void *uaddr, int op, int val, long timeout_ms);   /* timeout_ms<0 = wait forever (M1578) */
long sys_apps(void *buf, unsigned long len);
long sys_resolve(const char *host, void *buf, unsigned long len);
long sys_http(const char *host, const char *path, void *buf, unsigned long max);
long sys_https(const char *host, const char *path, void *buf, unsigned long max);
long sys_ws_open(const char *url, int *status);   /* WebSocket connect + handshake; conn id / -1 (M1846) */
long sys_ws_exchange(int id, const char *sendbuf, int sendtot, char *out, int outmax, int *nrecv);  /* send + recv frames (M1846) */
long sys_ws_serve(int port, char *lastmsg, int lastmax, int *nframes);   /* accept 1 WS client + echo; frames/-1 (M1849) */
long sys_spawn(const char *name);
long sys_spawn_arg(const char *name, const char *arg);   /* launch with an arg (e.g. `run editor FILE`) */
long sys_browse(const char *url);
long sys_mkdir(const char *path);
long sys_chdir(const char *path);
long sys_fchdir(int fd);                                    /* chdir via an already-open directory fd; 0/-1 (M1586) */
long sys_tree(void *buf, unsigned long len);
long sys_ps(void *buf, unsigned long len);
long sys_font(void *buf, unsigned long len);            /* copy the 8x16 console font (128*16 bytes) for gfx text (M1362) */
long sys_loadimg(const char *name, void *buf, int cw, int ch, int *outwh);  /* decode+fit-scale an image file into a cw*ch XRGB buf; native size -> outwh[2]; 0/-1 (M1392) */
long sys_history(void *buf, unsigned long len);
int  sys_pollkey(void);
long sys_df(void *buf, unsigned long len);
long sys_lspci(void *buf, unsigned long len);
long sys_lsblk(void *buf, unsigned long len);
long sys_mounts(void *buf, unsigned long len);
long sys_getrandom(void *buf, unsigned long len);   /* fill buf with hardware-seeded CSPRNG bytes */
int  sys_pledge(const char *promises);   /* restrict this process to the named syscall classes; 0/-1 */
int  sys_unveil(const char *path, const char *perms);   /* limit filesystem visibility to path (perms "rwc"); 0/-1 */
int  sys_symlink(const char *linkpath, const char *target);   /* create a symlink under /tmp; 0/-1 */
int  sys_link(const char *oldpath, const char *newpath);       /* hard link (same ext2 mount); 0/-1 (M1207) */
int  sys_rename(const char *oldpath, const char *newpath);     /* rename/move within one ext2 mount; 0/-1 (M1213) */
int  sys_renameat2(const char *oldpath, const char *newpath, int flags); /* renameat2 NOREPLACE/EXCHANGE; 0/-1 (M1232) */
long sys_readlink(const char *path, void *buf, unsigned long size);      /* read a symlink's target (not followed); bytes/-1 (M1233) */
int  sys_sched_yield(void);                                     /* voluntarily yield the CPU; 0 (M1234) */
int  sys_nanosleep(long sec, long nsec);                        /* sleep sec+nsec (100Hz-rounded); 0 (M1234) */
int  sys_clock_nanosleep(int clockid, int flags, long sec, long nsec);  /* TIMER_ABSTIME=absolute deadline; 0 (M1257) */
long sys_clock_settime(int clockid, long sec, long nsec);  /* set the wall clock (CLOCK_REALTIME only); 0/-1 (M1280) */
long sys_clock_getres(int clockid);                             /* clock resolution in nanoseconds (M1257) */
int  sys_udp_send(const unsigned char *ip4, unsigned short dport, unsigned short sport, const void *buf, unsigned len);  /* UDP datagram; 0/-1 (M1258) */
long sys_udp_recv(unsigned short sport, void *buf, unsigned max, void *from);  /* recv to local port; bytes/-1, 2s timeout; from={u8 ip[4];u16 port} (M1258) */
int  sys_raw_send(const void *frame, unsigned len);            /* send a complete Ethernet frame; 0/-1 (M1259) */
long sys_raw_recv(void *buf, unsigned max);                    /* next Ethernet frame (2s timeout); length/-1 (M1259) */
long sys_insmod(void);                                         /* load+relocate+run the built-in .ko; mod_init retval/-err (M1261) */
long sys_insmod_path(const char *path);                         /* load+relocate+run a .ko from a real file; mod_init retval/-err (M1595) */
int  sys_rmmod(const char *name);                              /* unload a module: run mod_exit + free its slot; 0/-1 (M1262) */
int  sys_sendfd(int ep, int fd);                               /* SCM_RIGHTS: pass an fd over an AF_UNIX endpoint; 0/-1 (M1265) */
int  sys_recvfd(int ep);                                       /* SCM_RIGHTS: receive a passed fd; new fd/-1 (M1265) */
int  sys_inotify_init(void);                                   /* a pollable filesystem-watch fd; fd/-1 (M1266) */
int  sys_inotify_add_watch(int fd, const char *path, unsigned int mask);  /* register a watch; wd/-1 (M1266) */
int  sys_inotify_rm_watch(int fd, int wd);                          /* unregister a watch; 0/-1 (M1568) */
int  sys_socket(int domain, int type);                         /* AF_INET(2) SOCK_DGRAM(2) socket fd; fd/-1 (M1267) */
int  sys_sock_bind(int fd, int port);                          /* bind a datagram socket to a local port; 0/-1 (M1267) */
long sys_sendto(int fd, const unsigned char *ip4, int port, const void *buf, unsigned len);  /* bytes/-1 (M1267) */
long sys_recvfrom(int fd, void *buf, unsigned max, void *from); /* bytes/-1, 2s timeout; from={u8 ip[4];u16 port} (M1267) */
int  sys_connect(int fd, const unsigned char *ip4, int port);  /* active-open a TCP socket fd; 0/-1 (M1268) */
int  sys_setsockopt(int fd, int level, int optname, const void *optval, unsigned optlen);  /* 0/-1 (M1554) */
int  sys_getsockopt(int fd, int level, int optname, void *optval, unsigned *optlen);       /* 0/-1 (M1554) */
int  sys_getsockname(int fd, unsigned char ip4_out[4], int *port_out);   /* this socket's own address; 0/-1 (M1560) */
int  sys_getpeername(int fd, unsigned char ip4_out[4], int *port_out);   /* the connected peer's address; 0/-1 (M1560) */
void *dlopen(const char *path);                                /* userspace dynamic linker: map+relocate a .so; handle/0 (M1263) */
void *dlsym(void *handle, const char *name);                   /* resolve an exported symbol to its runtime address; 0 if absent (M1263) */
long sys_times(struct tms *t);                                  /* fill CPU times (ticks); returns boot ticks (M1235) */
int  sys_uname(struct utsname *u);                              /* system identity strings; 0/-1 (M1236) */
int  sys_getppid(void);                                         /* parent pid (M1236) */
int  sys_getuid(void);                                          /* real uid (0) (M1236) */
int  sys_getgid(void);                                          /* real gid (0) (M1236) */
int  sys_geteuid(void);                                         /* effective uid (0) (M1236) */
int  sys_getegid(void);                                         /* effective gid (0) (M1236) */
int  sys_sethostname(const char *buf, unsigned long len);       /* set the system hostname; 0/-1 (M1237) */
int  sys_gethostname(char *buf, unsigned long len);             /* copy the system hostname; 0/-1 (M1237) */
int  sys_getentropy(void *buf, unsigned long len);              /* fill <=256 bytes with CSPRNG; 0/-1 (M1238) */
int  sys_getpriority(int which, int who);                       /* caller's nice (self); -1 (M1238) */
int  sys_setpriority(int which, int who, int prio);             /* set caller's nice (self); 0/-1 (M1238) */
int  sys_pipe2(int *fds, int flags);                            /* pipe with atomic O_CLOEXEC; 0/-1 (M1239) */
int  sys_statfs(const char *path, struct statvfs *sv);          /* filesystem free/total; 0/-1 (M1240) */
int  sys_chmod(const char *path, unsigned mode);                /* set permission bits (ext2); 0/-1 (M1241) */
int  sys_fchmod(int fd, unsigned mode);                         /* set permission bits on an open fd; 0/-1 (M1241) */
int  sys_eventfd(unsigned initval, int flags);                  /* pollable u64-counter fd; fd/-1 (M1242) */
int  sys_chown(const char *path, int uid, int gid);            /* set owner/group (ext2; -1 = leave); 0/-1 (M1243) */
int  sys_fchown(int fd, int uid, int gid);                     /* set owner/group on an open fd; 0/-1 (M1243) */
int  sys_sched_getcpu(void);                                   /* APIC id of the CPU the caller runs on (M1246) */
int  sys_sched_setaffinity(unsigned int mask);                 /* restrict the caller to a CPU subset (bit i = core i); 0/-1 (M1557) */
unsigned int sys_sched_getaffinity(void);                      /* the caller's current CPU-affinity mask (M1557) */
long sys_getcwd(char *buf, unsigned long size);                /* the absolute current directory; length/-1 (M1248) */
int  sys_openat(int dirfd, const char *path, int flags);       /* open relative to a dir fd (or AT_FDCWD); fd/-1 (M1251) */
int  sys_unlinkat(int dirfd, const char *path, int flags);     /* remove relative to a dir fd; 0/-1 (M1251) */
int  sys_mkdirat(int dirfd, const char *path, int mode);       /* mkdir relative to a dir fd; 0/-1 (M1251) */
int  sys_fstatat(int dirfd, const char *path, struct statx *st, int flags); /* stat relative to a dir fd; 0/-1 (M1251) */
int  sys_fchmodat(int dirfd, const char *path, unsigned mode);    /* chmod relative to a dir fd (or AT_FDCWD); 0/-1 (M1553) */
int  sys_fchownat(int dirfd, const char *path, int uid, int gid); /* chown relative to a dir fd (or AT_FDCWD); 0/-1 (M1553) */
int  sys_symlinkat(const char *target, int newdirfd, const char *linkpath);  /* symlink relative to a dir fd (or AT_FDCWD); 0/-1 (M1582) */
int  sys_linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);  /* hard link relative to dir fds (or AT_FDCWD); 0/-1 (M1585) */
long sys_readlinkat(int dirfd, const char *path, void *buf, unsigned long size);  /* a symlink's target relative to a dir fd (or AT_FDCWD), not followed; bytes/-1 (M1582) */
int  sys_utimensat(int dirfd, const char *path, long atime, long mtime);  /* set timestamps relative to a dir fd (or AT_FDCWD); 0/-1 (M1559) */
long sys_prlimit(int pid, int resource, unsigned long newval, int do_set);  /* get/set a process's rlimit; old value (M1214) */
int  sys_timerfd_create(void);                                 /* a pollable one-shot timer fd (>=3); -1 (M1217) */
long sys_timerfd_settime(int fd, long delay_ms, long interval_ms);  /* arm a timerfd: delay + periodic interval (ms; interval 0 = one-shot); 0/-1 (M1217, periodic M1302) */
long sys_fcntl(int fd, int cmd, long arg);                     /* F_GETFD/SETFD/DUPFD/DUPFD_CLOEXEC (M1218) */
int  sys_dup3(int oldfd, int newfd, int flags);                /* dup w/ O_CLOEXEC; -1 if old==new (M1218) */
long sys_close_range(unsigned lo, unsigned hi, int flags);     /* close fds in [lo,hi]; 0/-1 (M1218) */
long sys_sendfile(int out_fd, int in_fd, long *off, unsigned long count);  /* zero-copy fd->fd; bytes/-1 (M1219) */
int  sys_epoll_create1(int flags);                             /* an epoll fd (>=3); -1 (M1220) */
int  sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev);      /* ADD/MOD/DEL; 0/-1 (M1220) */
int  sys_epoll_wait(int epfd, struct epoll_event *evs, int maxevents, long timeout);  /* # ready/0/-1 (M1220) */
int  sys_epoll_pwait(int epfd, struct epoll_event *evs, int maxevents, long timeout, unsigned sigmask);  /* like epoll_wait, signal-interruptible; #ready/-1 on signal/-1 (M1567) */
int  sys_pidfd_open(int pid, int flags);                       /* a pollable process-exit handle (>=3); -1 (M1222) */
int  sys_pidfd_send_signal(int pidfd, int sig);                /* signal the pidfd's process; 0/-1 (M1222) */
int  sys_pidfd_getfd(int pidfd, int targetfd, int flags);      /* duplicate the pidfd-process's fd into ours; new fd/-1 (M1281) */
long sys_getdents64(void *buf, unsigned long max, int start);  /* packed dirent64 of the cwd; bytes/0/-1 (M1223) */
int  sys_access(const char *path, int amode);                  /* 0 if accessible, -1 (M1224) */
int  sys_faccessat2(int dirfd, const char *path, int amode, int flags);  /* access() relative to a dir fd (or AT_FDCWD); 0/-1 (M1556) */
long sys_prctl(int option, unsigned long arg2);                /* PR_SET_NAME/PR_GET_NAME; 0/-1 (M1225) */
long sys_set_tid_address(void *tidptr);                        /* register clear_child_tid (futex-on-exit); tid (M1226) */
int  sys_waitid(int idtype, int id, struct siginfo *si, int options);  /* waitid + WNOHANG; 0/-1 (M1227) */
int  sys_truncate(const char *path, long len);                 /* resize a real file (tmpfs/ext2); 0/-1 (M1228) */
int  sys_utimens(const char *path, long atime, long mtime);     /* set atime/mtime (UTIME_NOW/OMIT); 0/-1 (M1230) */
int  sys_futimens(int fd, long atime, long mtime);              /* set atime/mtime on an open fd; 0/-1 (M1230) */
int  sys_jail(const char *prog, const char *promises, const char *path);   /* spawn prog pre-confined (pledge + optional unveil) */
long sys_find(const char *want, void *buf, unsigned long len);
long sys_sha1(const char *name, void *hexbuf, unsigned long max);
long sys_sha256(const char *name, void *hexbuf, unsigned long max);
long sys_sha512(const char *name, void *hexbuf, unsigned long max);
long sys_crypt(const char *name, const char *pass);
long sys_js(const char *src, void *out, unsigned long max);
long sys_screenshot(const char *name);
long sys_savebmp(const char *name, const void *pixels, int w, int h);   /* save a w*h 0x00RRGGBB canvas as a 24-bit BMP; 0/-1 */
long sys_setwall(const char *name);   /* load an image file as the desktop wallpaper; 0/-1 */
long sys_gunzip(const char *insrc, const char *outname);
long sys_gzip(const char *insrc, const char *outname);
long sys_unzip(const char *zipname);
long sys_untar(const char *tarname);
void sys_sleep(int ms);
void sys_setcolor(int color);   /* text colour for subsequent output: palette index 0-15 (0 = default) */
void *sbrk(long inc);           /* grow the heap by inc bytes; previous break, or (void*)-1 */
void *sys_mmap(unsigned long len);              /* reserve a demand-paged anon region; base or 0 */
void *sys_mmap_huge(unsigned long len);         /* reserve a 2 MiB-backed (hugepage) region; base or 0 (M1155) */
void *sys_mmap_file(const char *path, unsigned long len, int shared);  /* demand-paged file-backed mmap; shared=0 MAP_PRIVATE (M1136), shared=1 MAP_SHARED (M1544); base or 0 */
int   sys_msync(void *addr, unsigned long len);         /* flush a MAP_SHARED file-backed mmap's dirty pages to disk; 0/-1 (M1544) */
/* threads (M1138): shared-address-space concurrency (unlike fork's separate space) */
long sys_clone(void *fn, void *stack, void *arg);  /* low-level: start fn(arg) on `stack` in a new thread; tid/-1 */
int  sys_gettid(void);                             /* the calling thread's id */
void sys_thread_exit(void);                        /* end the calling thread (not the process) */
int  thread_spawn(void (*fn)(void *), void *arg);  /* convenience: alloc a stack + clone; tid/-1 */
int  sys_join(int tid);                            /* block until thread tid exits + reap it; 0/-1 (M1139) */
void mutex_lock(volatile int *m);                  /* futex-backed mutex (M1139); lock word: 0=free 1=held */
void mutex_unlock(volatile int *m);
void sys_set_tls(void *base);                      /* set this thread's %fs base for TLS (M1140) */
/* robust mutexes (M1141): survive a thread dying while holding the lock */
long sys_set_robust_list(void *r);                 /* register this thread's robust_t */
int  rmutex_lock(volatile int *m, robust_t *r);    /* 0, or 1 (EOWNERDEAD) if the prior owner died holding it */
void rmutex_unlock(volatile int *m, robust_t *r);
void *sys_ringbuf(unsigned long len);           /* a magic mirrored ring buffer (mapped twice back-to-back); base or 0 */
int   sys_mprotect(void *addr, unsigned long len, int prot);  /* change R/W/X (prot: 1=R 2=W 4=X); 0/-1 */
int   sys_bind(const char *from, const char *to);  /* bind mount: graft FROM's subtree onto path TO; 0/-1 */
long  sys_overlay(const char *lower, const char *upper);  /* mount a union overlay at /over (copy-up to upper); 0/-1 (M1142) */
long  sys_munmap(void *addr, unsigned long len);/* free an mmap region; 0/-1 */
void *sys_mremap(void *old_addr, unsigned long old_len, unsigned long new_len, int flags);  /* resize/move; new base or NULL (M1179) */
long  sys_copy_file_range(const char *src, const char *dst, unsigned long len);  /* in-kernel file copy (dst /net/tcp = sendfile); bytes/-1 (M1181) */
long  sys_setxattr(const char *path, const char *name, const void *val, unsigned long vlen);  /* set a user.* xattr (ext2); vlen/-1 (M1182) */
long  sys_getxattr(const char *path, const char *name, void *out, unsigned long max);  /* read a user.* xattr; full size/-1 (M1182) */
long  sys_listxattr(const char *path, char *out, unsigned long max);  /* NUL-sep user.* xattr names; total/-1 (M1182) */
long  sys_removexattr(const char *path, const char *name);  /* remove a user.* xattr; 0/-1 (M1182) */
long  sys_fsetxattr(int fd, const char *name, const void *val, unsigned long vlen);  /* set a user.* xattr on an open fd; vlen/-1 (M1569) */
long  sys_fgetxattr(int fd, const char *name, void *out, unsigned long max);  /* read a user.* xattr on an open fd; size/-1 (M1569) */
long  sys_flistxattr(int fd, char *out, unsigned long max);  /* NUL-sep user.* xattr names on an open fd; total/-1 (M1569) */
long  sys_fremovexattr(int fd, const char *name);  /* remove a user.* xattr on an open fd; 0/-1 (M1569) */
int   sys_pty_open(void);                                    /* -> pty master id (slave = master|1); -1 (M1185) */
long  sys_pty_read(int id, void *buf, unsigned long max);    /* bytes; 0 EOF; -1 (M1185) */
long  sys_pty_write(int id, const void *buf, unsigned long len);  /* bytes; -1 (master write feeds the ldisc) (M1185) */
int   sys_pty_close(int id);                                 /* close one end; 0/-1 (M1185) */
int   sys_pty_ctl(int id, int cmd, int arg);                 /* cmd 0=lflag, 1=fg pgid; 0/-1 (M1185) */
int   sys_pipe(int fds[2]);                                  /* anonymous pipe; fds[0]=read, fds[1]=write; 0/-1 (M1187) */
long  sys_fdread(int fd, void *buf, unsigned long max);      /* read a pipe fd; bytes/0 EOF/-1 (M1187) */
long  sys_fdwrite(int fd, const void *buf, unsigned long len);  /* write a pipe fd; bytes/-1 EPIPE (M1187) */
int   sys_fdclose(int fd);                                   /* close an fd; 0/-1 (M1187) */
int   sys_dup2(int oldfd, int newfd);                        /* redirect newfd onto oldfd; newfd/-1 (M1187) */
int   sys_dup(int fd);                                       /* duplicate onto the lowest free fd; fd/-1 (M1587) */
int   sys_mkfifo(const char *path);                          /* create a named pipe (FIFO); 0/-1 (M1188) */
int   sys_fifo_open(const char *path, int write);            /* open a FIFO end -> fd; -1 (M1188) */
int   sys_open(const char *path);                            /* open a read-only file fd (>=3); -1 (M1193) */
int   sys_open_mode(const char *path, int flags);            /* open a file fd with O_* flags (M1195) */
long  sys_lseek(int fd, long off, int whence);               /* reposition a file fd (SEEK_SET/CUR/END); offset/-1 (M1193) */
long  sys_pread(int fd, void *buf, unsigned long max, long off);        /* read without moving the cursor; bytes/0 EOF/-1 (M1572) */
long  sys_pwrite(int fd, const void *buf, unsigned long len, long off); /* write without moving the cursor; bytes/-1 (M1572) */
long  sys_readv(int fd, struct iovec *iov, int iovcnt);       /* read into each segment in turn; total bytes/-1 (M1574) */
long  sys_writev(int fd, const struct iovec *iov, int iovcnt); /* write each segment in turn; total bytes/-1 (M1574) */
long  sys_preadv(int fd, struct iovec *iov, int iovcnt, long off);        /* like readv, at an explicit offset, cursor untouched; total bytes/-1 (M1577) */
long  sys_pwritev(int fd, const struct iovec *iov, int iovcnt, long off); /* like writev, at an explicit offset, cursor untouched; total bytes/-1 (M1577) */
long  sys_seccomp_filter(const void *prog, unsigned long bytes);  /* install a self-imposed BPF syscall filter; 0/-1 (M1190) */
#define PTY_SETMODE 0
#define PTY_SETFG   1
long  sys_signal(int signo, void (*handler)(int));  /* install a ring-3 signal handler */
/* SA_SIGINFO (M1270): a 3-arg handler h(signo, ksiginfo*, kmcontext*). kmcontext
 * mirrors the kernel's saved register file; editing its rip/GP regs/rsp and
 * returning makes sigreturn resume at the edited state (JIT-trap / GC-barrier
 * mechanism). cs/ss/rflags are forced safe by the kernel. */
struct ksiginfo { int si_signo; int si_code; unsigned long si_addr; unsigned long si_value; };  /* si_value: the sigqueue payload (M1271) */
struct kmcontext {
    unsigned long r15,r14,r13,r12,r11,r10,r9,r8;
    unsigned long rbp,rdi,rsi,rdx,rcx,rbx,rax;
    unsigned long int_no,err_code;
    unsigned long rip,cs,rflags,rsp,ss;
};
long  sys_sigaction(int signo, void (*h)(int, struct ksiginfo *, struct kmcontext *), int flags);  /* M1270 */
void  sys_raise(int signo);                     /* deliver a signal to self (runs the handler) */
long  sys_sigqueue(int pid, int signo, unsigned long value);  /* queue an RT signal carrying a sigval payload; pid 0 = self (M1271) */
long  sys_timer_create(int clockid, int signo, unsigned long value);  /* POSIX timer firing signo w/ payload via sigqueue; -> id/-1 (M1272) */
long  sys_timer_settime(int id, int flags, unsigned long value_ms, unsigned long interval_ms);  /* arm (TIMER_ABSTIME=abs); value_ms 0=disarm; 0/-1 (M1272) */
long  sys_timer_gettime(int id);          /* ms until timer id next fires (0 disarmed), or -1 (M1272) */
long  sys_timer_delete(int id);           /* destroy timer id; 0/-1 (M1272) */
unsigned long sys_hpet(int what);         /* HPET high-res clock: 0=ns, 1=hz, 2=counter, 3=present (M1273) */
long  sys_ptsname(int fd);                /* /dev/pts/<n> index for a /dev/ptmx master fd, or -1 (M1274) */
long  sys_oom(int cmd, int arg);          /* OOM killer: 0=set self oom_adj, 1=trigger kill (->victim pid), 2=oom_score of pid (M1275) */
long  sys_sigaltstack(void *ss_sp, unsigned long ss_size);  /* register an alternate signal stack for SA_ONSTACK handlers; 0/-1 (M1276) */
unsigned sys_sigprocmask(int how, unsigned set);  /* block/unblock signals; returns the old mask (M1208) */
unsigned sys_sigpending(void);                    /* the pending (raised-but-blocked) signal set (M1209) */
int      sys_sigsuspend(unsigned mask);           /* swap blocked mask, block for a signal, restore; always -1 (M1561) */
int      sys_pause(void);                         /* block until a signal is delivered, current mask unchanged; always -1 (M1563) */
unsigned long sys_uptime_ms(void);   /* monotonic milliseconds since boot */
int  sys_gfx_init(int w, int h);     /* enter graphics mode: a w*h XRGB pixel canvas; 0/-1 */
int  sys_gfx_blit(const void *pixels); /* copy w*h pixels (0x00RRGGBB) to the window; 0/-1 */
void sys_setkbmode(int raw);         /* 1 = raw make/break key events, 0 = cooked ASCII */
void sys_caret(int on);              /* 1 = show system caret (default), 0 = this app draws its own */
int  sys_clip_get(char *buf, int max);     /* copy the system clipboard into buf; returns length */
void sys_clip_set(const char *buf, int len); /* set the system clipboard (shared with middle-click paste) */
int  sys_getarg(char *buf, int max);       /* copy this app's launch argument into buf; returns length */
int  sys_getkbevent(void);           /* next raw key event (scancode|0x100 released|0x200 ext), or -1 */
void sys_pcm(const void *frames, int nframes);   /* play 16-bit stereo PCM @ 48 kHz (blocks) */
long sys_playwav(const char *name);              /* play a .wav file (16-bit PCM); 0/-1 */
int  sys_pcm_stream(const void *frames, int nframes);  /* queue stereo PCM (non-blocking); accepted */
int  sys_pcm_avail(void);                        /* free frames in the streaming ring */
int  sys_mouse(int *x, int *y);   /* cursor relative to the gfx canvas (-1 outside); returns button bits */
void sys_mouse_rel(int *dx, int *dy);   /* accumulated relative motion since last call (mouselook) */
long sys_playbg(const char *name);   /* play a .wav in the background (non-blocking); 0/-1 */
void sys_audiostop(void);            /* stop background audio */

/* dynamic memory (a first-fit free list over sbrk) */
void *malloc(unsigned long n);
void  free(void *p);
void *calloc(unsigned long nmemb, unsigned long size);
void *realloc(void *p, unsigned long n);

/* freestanding mem primitives (GCC may also emit calls to these) */
void *memset(void *dst, int c, unsigned long n);
void *memcpy(void *dst, const void *src, unsigned long n);
void *memmove(void *dst, const void *src, unsigned long n);

/* convenience */
void          print(const char *s);
void          cap_begin(void);                          /* redirect print() into a growable heap buffer */
char         *cap_end(unsigned long *outlen);           /* stop capturing; returns the malloc'd buffer (caller frees) + byte count */
int           cap_active(void);                         /* nonzero if print() is being captured (pipe stage / $()) — suppress decorative output */
int           readline(char *buf, int max);   /* reads a line, strips '\n', NUL-terminates */
unsigned long ustrlen(const char *s);
int           streq(const char *a, const char *b);
int           startswith(const char *s, const char *prefix);

/* clock_gettime — reads the kernel's vDSO time page directly, with NO syscall
 * (the page is mapped read-only into every process; the timer IRQ refreshes it
 * under a seqlock). M1111. Returns 0. */
#define CLOCK_REALTIME  0   /* wall clock: seconds since the Unix epoch (UTC) */
#define CLOCK_MONOTONIC 1   /* steady time since boot (never jumps) */
struct timespec { long tv_sec; long tv_nsec; };
int clock_gettime(int clk, struct timespec *ts);
