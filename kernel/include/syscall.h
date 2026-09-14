/*
 * syscall.h — the system-call ABI, shared by kernel and userspace.
 *
 * A user program puts the call number in rax and arguments in rdi/rsi/rdx,
 * then executes `int 0x80`. The kernel handler reads those, does the work, and
 * returns a result in rax. (We use the int-0x80 trap, the simplest mechanism;
 * the faster `syscall`/`sysret` instructions are a later optimization.)
 */
#pragma once

#define SYS_write  1   /* (fd, buf, len)  -> bytes written          */
#define SYS_exit   2   /* (code)          -> does not return        */
#define SYS_getpid 3   /* ()              -> process id             */
#define SYS_read   4   /* (fd, buf, len)  -> bytes read (line)      */
#define SYS_list   5   /* (buf, len)      -> formatted dir listing  */
#define SYS_readfile 6 /* (name, buf, len)-> file bytes, or -1      */
#define SYS_time   7   /* (buf, len)      -> "YYYY-MM-DD HH:MM:SS"  */
#define SYS_beep   8   /* (hz, ms)        -> beep the PC speaker     */
#define SYS_sysinfo 9  /* (buf, len)      -> RAM/uptime/task summary */
#define SYS_clear  10  /* ()              -> clear the terminal      */
#define SYS_reboot 11  /* ()              -> reboot the machine      */
#define SYS_writefile 12 /* (name, buf, len) -> bytes written, or -1 */
#define SYS_ping   13  /* ()              -> echo replies from gateway */
#define SYS_resolve 14 /* (host, buf, len)-> 0 + IP string, or -1     */
#define SYS_delete 15  /* (name)          -> 0, or -1                 */
#define SYS_spawn  16  /* (name)          -> launch a program; 0/-1   */
#define SYS_sleep  17  /* (ms)            -> sleep for ms              */
#define SYS_http   18  /* (host,path,buf,max) -> HTTP GET bytes, or -1 */
#define SYS_browse 19  /* (url)           -> open a browser window; 0    */
#define SYS_mkdir  20  /* (path)          -> make a directory; 0/-1      */
#define SYS_chdir  21  /* (path)          -> change current dir; 0/-1    */
#define SYS_tree   22  /* (buf, len)      -> recursive dir listing       */
#define SYS_ps     23  /* (buf, len)      -> running task/process list   */
#define SYS_pollkey 24 /* ()              -> next key, or -1 (non-blocking) */
#define SYS_df     25  /* (buf, len)      -> disk free/total summary       */
#define SYS_find   26  /* (want,buf,len)  -> recursive name search         */
#define SYS_sha256 27  /* (name, hexbuf)  -> SHA-256 of a file as hex; 0/-1 */
#define SYS_crypt  28  /* (name, pass)    -> AES-CTR (de/en)crypt file; 0/-1 */
#define SYS_history 29 /* (buf, len)      -> recent command history; bytes      */
#define SYS_https  30  /* (host,path,buf,max) -> HTTPS GET bytes via TLS 1.3, or -1 */
#define SYS_js     31  /* (src, out, outmax)  -> run JavaScript; output bytes, or -1 */
#define SYS_setcolor 32 /* (idx)            -> set the app text colour (palette 0-15)  */
#define SYS_pinghost 33 /* (host)           -> DNS-resolve + ICMP-echo a host; replies/-1 */
#define SYS_netinfo 34  /* (buf, len)       -> our IP/MAC/gateway/DNS as text; bytes/-1 */
#define SYS_apps   35   /* (buf, len)       -> registered app names, space-separated; bytes */
#define SYS_sha512 36   /* (name, hexbuf)   -> SHA-512 of a file as 128 hex chars; 0/-1 */
#define SYS_screenshot 37 /* (name)         -> save the screen to a BMP file; 0/-1 */
#define SYS_gunzip 38   /* (insrc, outname) -> decompress a .gz file; output bytes, or -1 */
#define SYS_gzip   39   /* (insrc, outname) -> gzip-compress a file; output bytes, or -1 */
#define SYS_unzip  40   /* (zipname)        -> extract a .zip to 8.3 files; files written, or -1 */
#define SYS_untar  41   /* (tarname)        -> extract a .tar/.tar.gz to 8.3 files; files written, or -1 */
#define SYS_sbrk   42   /* (inc)            -> grow the heap by inc bytes; old break, or (void*)-1 */
#define SYS_uptime_ms 43 /* ()              -> milliseconds since boot (monotonic) */
#define SYS_gfx_init 44 /* (w, h)           -> enter graphics mode with a w*h canvas; 0/-1 */
#define SYS_gfx_blit 45 /* (pixels)         -> copy w*h XRGB pixels to the window; 0/-1 */
#define SYS_setkbmode 46 /* (raw)           -> 1 = raw make/break key events, 0 = cooked */
#define SYS_getkbevent 47 /* ()             -> next raw key event, or -1 (non-blocking) */
#define SYS_pcm    48   /* (frames, nframes) -> play 16-bit stereo PCM at 48 kHz (blocks) */
#define SYS_playwav 49  /* (name)          -> play a .wav file (16-bit PCM); 0/-1 */
#define SYS_pcm_stream 50 /* (frames,nframes)-> queue stereo PCM (non-blocking); frames accepted */
#define SYS_pcm_avail 51 /* ()              -> free frames in the streaming ring */
#define SYS_mouse  52   /* ()              -> packed cursor: x|0-15 y|16-31 buttons|32-34 */
#define SYS_playbg 53   /* (name)          -> play a .wav in the background (non-blocking); 0/-1 */
#define SYS_audiostop 54 /* ()             -> stop background audio */
#define SYS_mouse_rel 55 /* ()             -> packed relative motion dx|0-31 dy|32-63 (mouselook) */
#define SYS_caret  56   /* (on)            -> 1 = show system caret (default), 0 = app draws its own */
#define SYS_clip_get 57 /* (buf, max)      -> copy the system clipboard into buf; returns length */
#define SYS_clip_set 58 /* (buf, len)      -> set the system clipboard from buf; 0 */
#define SYS_getarg  59  /* (buf, max)      -> copy this app's launch argument into buf; returns length */
#define SYS_savebmp 60  /* (name, pixels, w, h) -> save a w*h 0x00RRGGBB canvas as a 24-bit BMP; 0/-1 */
#define SYS_setwall 61  /* (name)          -> load image as the desktop wallpaper; 0/-1 */
#define SYS_lspci  62   /* (buf, len)      -> PCI device list as text lines; bytes      */
#define SYS_lsblk  63   /* (buf, len)      -> block devices + FAT32 volumes as text; bytes */
#define SYS_poweroff 64 /* ()              -> enter ACPI S5 (power the machine off); never returns */
#define SYS_kill   65   /* (pid)           -> ask the app with this pid to close; 0 ok / -1 not found */
#define SYS_mounts 66   /* (buf, max)      -> list the read-only disk mounts (/disk1..) as text; bytes */
#define SYS_mmap   67   /* (len)           -> reserve a demand-paged anon region; base VA, or 0 */
#define SYS_munmap 68   /* (addr, len)     -> free an mmap region; 0/-1 */
#define SYS_signal 69   /* (signo, handler, restorer) -> install a ring-3 signal handler; 0 */
#define SYS_raise  70   /* (signo)         -> deliver a signal to self (runs the handler, returns after) */
#define SYS_sigreturn 71/* ()              -> return from a signal handler (restore the saved context) */
#define SYS_getrandom 72/* (buf, len)      -> fill buf with CSPRNG bytes (hardware-seeded); bytes written */
#define SYS_pledge 73   /* (promises)      -> restrict this process to the named syscall classes; 0/-1 */
#define SYS_unveil 74   /* (path, perms)   -> limit filesystem visibility to path (perms "rwc"); 0/-1 */
#define SYS_symlink 75  /* (linkpath, target) -> create a symlink under /tmp; 0/-1 */
#define SYS_jail   76   /* (prog, promises, path) -> spawn prog pre-confined (pledge + optional unveil); 0/-1 */
#define SYS_ringbuf 77  /* (len)           -> a magic mirrored ring buffer (len frames mapped twice); base VA or 0 */
#define SYS_mprotect 78 /* (addr, len, prot) -> change R/W/X of a mapped range (prot: 1=R 2=W 4=X); 0/-1 */
#define SYS_bind   79   /* (from, to)      -> graft path FROM's subtree onto path TO (bind mount); 0/-1 */
#define SYS_dhcp   80   /* ()              -> DHCP DORA: lease IP/gateway/DNS from the server; 0/-1 */
#define SYS_cas_store 81 /* (buf,len,hash32) -> store a blob in the content-addressed store; writes its SHA-256 key; 0/-1 */
#define SYS_cas_fetch 82 /* (hash32,buf,max) -> fetch a blob by its SHA-256 key; bytes/-1 */
#define SYS_tftp   83   /* (server,file,buf,max) -> fetch a file over TFTP into buf; bytes/-1 */
#define SYS_madvise 84  /* (addr,len,advice) -> MADV_DONTNEED(4): reclaim resident anon pages now; pages/-1 */
#define SYS_alarm  85   /* (ticks) -> arm a periodic SIGALRM every `ticks` timer ticks (0 = disarm); 0 */
#define SYS_sntp   86   /* ()      -> SNTP: set the wall clock from pool.ntp.org; 0/-1 */
#define SYS_swapout 87  /* (addr,len) -> page out anon pages in range to swap (MADV_PAGEOUT); pages/-1 */
#define SYS_losetup 88  /* (path) -> mount a FAT/ext2 image file as a loop block device; mount index (/disk<n+1>) or -1 */
#define SYS_shm_open 89  /* (name, size) -> map a named shared-memory object into this app; base VA or 0 */
#define SYS_futex  90   /* (uaddr, op, val) -> FUTEX_WAIT(0): block if *uaddr==val; FUTEX_WAKE(1): wake up to val waiters */
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define SYS_fork   91   /* () -> copy-on-write fork: child returns 0, parent returns the child's pid; -1 on failure */
#define SYS_waitpid 92  /* (pid, int *status) -> block until child (pid, or -1=any) exits; returns its pid + *status; -1 if none */
#define SYS_exec   93   /* (name, arg) -> replace this process's program image with the registered program `name`; -1 on failure (no return on success) */
#define SYS_unshare 94  /* () -> detach into a private mount namespace (later binds become private); 0/-1 */
#define SYS_singlestep 95 /* (n) -> hardware single-step the next n user instructions; read the trace via /proc/<pid>/sstrace */
#define SYS_seccomp       96 /* (nr) -> child: trap syscall `nr` to a supervisor (seccomp-notify) */
#define SYS_seccomp_wait  97 /* (childpid, ev[4]) -> supervisor: block until the child parks; ev={nr,a,b,c}; 1/0/-1 */
#define SYS_seccomp_reply 98 /* (childpid, run_real, retval) -> supervisor: allow(run_real=1)/deny/emulate; 0/-1 */
#define SYS_fswait        99 /* (names, n, timeout_ms) -> block until one of n NUL-separated paths is readable; index/-1 timeout */
#define SYS_signalfd     100  /* (mask) -> route the masked signos to /proc/self/sigfd (read returns the signo) instead of a handler */
#define SYS_fanotify_serve  101 /* () -> become the /fan userspace-materialization daemon; 0/-1 */
#define SYS_fanotify_wait   102 /* (namebuf, max) -> block until a /fan read request; fills the name; len/-1 */
#define SYS_fanotify_provide 103 /* (content, len) -> hand bytes to the blocked /fan reader; len/-1 */
#define SYS_io_uring_enter  104 /* (ring) -> drain a userspace submission ring; ops completed, or -1 (M1129) */
#define SYS_mseal           105 /* (addr, len) -> irreversibly seal mmap regions in range (no later munmap/mprotect); count/-1 (M1130) */
#define SYS_tcp_serve       106 /* (port, resp, resp_len, reqbuf, reqmax) -> serve one TCP connection; request bytes/-1 (M1133) */
#define SYS_uffd_register   107 /* (addr, len) -> route this region's page faults to a monitor (userfaultfd); 0/-1 (M1134) */
#define SYS_uffd_read       108 /* () -> monitor: block until the owner faults; the faulting page addr, or -1 */
#define SYS_uffd_copy       109 /* (addr, data, len) -> monitor: fill the faulting page + wake the owner; 0/-1 */
#define SYS_mmap_file       110 /* (path, len, shared) -> demand-paged file-backed mmap; shared=0 MAP_PRIVATE (M1136), shared=1 MAP_SHARED (M1544, writes flow back via msync/munmap/exit); base VA, or 0 */
#define SYS_clone           111 /* (fn, stack, arg) -> spawn a thread sharing this address space; tid, or -1 (M1138) */
#define SYS_gettid          112 /* () -> the calling thread's id (its task id) (M1138) */
#define SYS_thread_exit     113 /* () -> end just the calling thread (not the process) (M1138) */
#define SYS_join            114 /* (tid) -> block until thread tid exits, then reap it; 0/-1 (M1139) */
#define SYS_set_tls         115 /* (base) -> set this thread's %fs (TLS) base; 0 (M1140) */
#define SYS_set_robust_list 116 /* (robust_t*) -> register this thread's robust-futex list; 0 (M1141) */
#define SYS_overlay         117 /* (lower, upper) -> mount a union overlay at /over (copy-up to upper); 0/-1 (M1142) */
#define SYS_mincore         118 /* (addr, len, vec) -> per-page residency of an mmap range; 0/-1 (M1147) */
#define SYS_mlock           119 /* (addr, len) -> pin mmap pages against reclaim; 0/-1 (M1149) */
#define SYS_munlock         120 /* (addr, len) -> unpin mlock'd mmap pages; 0/-1 (M1149) */
#define SYS_getrusage       121 /* (who, struct rusage*) -> fill resource usage; 0/-1 (M1150) */
#define SYS_fiemap          122 /* (path, struct fiemap_extent*, max) -> file physical extent map; count/-1 (M1152) */
#define SYS_fallocate       123 /* (path, mode, offset, len) -> punch a hole / preallocate; blocks-affected/-1 (M1153) */
#define SYS_mq_open         124 /* (name, maxmsg, msgsize) -> open/create a priority msg queue; index/-1 (M1154) */
#define SYS_mq_send         125 /* (idx, buf, len, prio) -> enqueue (blocks if full); bytes/-1 (M1154) */
#define SYS_mq_receive      126 /* (idx, buf, max, uint*prio) -> dequeue highest prio (blocks if empty); bytes/-1 (M1154) */
#define SYS_mmap_huge       127 /* (len) -> reserve a 2 MiB-backed demand-paged region (MAP_HUGETLB); base VA or 0 (M1155) */
#define SYS_semget          128 /* (key, nsems, flags) -> SysV semaphore-set id; -1 (M1159) */
#define SYS_semop           129 /* (semid, struct sembuf*, nsops) -> atomic all-or-nothing semop; 0/-1 (M1159) */
#define SYS_semctl          130 /* (semid, semnum, cmd, arg) -> SETVAL/GETVAL/IPC_RMID; value/0/-1 (M1159) */
#define SYS_msgget          131 /* (key, flags) -> SysV message-queue id; -1 (M1160) */
#define SYS_msgsnd          132 /* (msqid, msgbuf*, msgsz, flags) -> enqueue a typed message; 0/-1 (M1160) */
#define SYS_msgrcv          133 /* (msqid, msgbuf*, msgsz, mtyp) -> receive by type; bytes/-1 (M1160) */
#define SYS_shmget          134 /* (key, size, flags) -> SysV shared-memory segment id; -1 (M1161) */
#define SYS_shmat           135 /* (shmid) -> attach: base VA, or 0 (M1161) */
#define SYS_shmdt           136 /* (addr) -> detach a SysV shm mapping; 0/-1 (M1161) */
#define SYS_process_vm_read 137 /* (pid, raddr, local, len) -> read another process's memory; bytes/-1 (M1162) */
#define SYS_getrlimit       138 /* (resource, struct rlimit*) -> read a resource limit; 0/-1 (M1163) */
#define SYS_setrlimit       139 /* (resource, struct rlimit*) -> set a resource limit; 0/-1 (M1163) */
#define SYS_process_vm_write 140 /* (pid, raddr, local, len) -> write another process's memory (COW-safe); bytes/-1 (M1165) */
#define SYS_unix_listen  141   /* (path) -> AF_UNIX listener id; -1 (M1169) */
#define SYS_unix_connect 142   /* (path) -> client endpoint id; -1 (M1169) */
#define SYS_unix_accept  143   /* (lid) -> server endpoint id (blocks); -1 (M1169) */
#define SYS_unix_send    144   /* (ep, buf, len) -> bytes written; -1 closed (M1169) */
#define SYS_unix_recv    145   /* (ep, buf, max) -> bytes read; 0 EOF; -1 bad ep (M1169) */
#define SYS_unix_close   146   /* (ep) -> 0/-1 (M1169) */
#define SYS_unix_wait_any 147  /* (int*eps, n) -> index of first readable ep (blocks once); -1 (M1170) */
#define SYS_nice         148   /* (nice) -> set current task's CFS nice (-20..19); returns the clamped nice (M1171) */
#define SYS_sched_setscheduler 149 /* (policy, rt_priority) -> set current task's scheduling class; 0/-1 (M1172) */
#define SYS_statx        150   /* (path, struct statx*) -> file metadata (mode/size/times/nlink); 0/-1 (M1173) */
#define SYS_tcgetattr    151   /* (struct termios*) -> read the TTY discipline mode; 0/-1 (M1174) */
#define SYS_tcsetattr    152   /* (struct termios*) -> set the TTY discipline mode (cooked/raw); 0/-1 (M1174) */
#define SYS_setpgid      153   /* (pid, pgid) -> set a process group (job control); 0/-1 (M1176) */
#define SYS_getpgid      154   /* (pid) -> process group id; -1 (M1176) */
#define SYS_setsid       155   /* () -> become session+group leader; sid (M1176) */
#define SYS_tcsetpgrp    156   /* (pgid) -> set the console foreground group; 0/-1 (M1176) */
#define SYS_killpg       157   /* (pgid, signo) -> signal every process in the group; count/-1 (M1176) */
#define SYS_flock        158   /* (path, op) -> advisory whole-file lock (LOCK_SH/EX/UN|NB); 0/-1 (M1177) */
#define SYS_mremap       159   /* (old_addr, old_len, new_len, flags) -> resize/move an mmap region; base/-1 (M1179) */
#define MREMAP_MAYMOVE   1
#define SYS_copy_file_range 160 /* (src_path, dst_path, len) -> in-kernel copy (also file->/net/tcp = sendfile); bytes/-1 (M1181) */
#define SYS_setxattr     161   /* (path, name, value, vlen) -> set a user.* xattr (ext2 in-inode); vlen/-1 (M1182) */
#define SYS_getxattr     162   /* (path, name, out, max) -> read a user.* xattr; full size/-1 (M1182) */
#define SYS_listxattr    163   /* (path, out, max) -> NUL-separated user.* xattr names; total/-1 (M1182) */
#define SYS_removexattr  164   /* (path, name) -> remove a user.* xattr; 0/-1 (M1182) */
#define SYS_pty_open     165   /* () -> pseudoterminal master id (slave = master|1); -1 (M1185) */
#define SYS_pty_read     166   /* (id, buf, max) -> bytes; 0 EOF; -1 (blocks if empty) (M1185) */
#define SYS_pty_write    167   /* (id, buf, len) -> bytes; -1 (master write feeds the line discipline) (M1185) */
#define SYS_pty_close    168   /* (id) -> close one end; 0/-1 (M1185) */
#define SYS_pty_ctl      169   /* (id, cmd, arg) -> cmd 0=set lflag, 1=set fg pgid; 0/-1 (M1185) */
#define SYS_pipe         170   /* (int fds[2]) -> anonymous pipe; fds[0]=read, fds[1]=write; 0/-1 (M1187) */
#define SYS_fdread       171   /* (fd, buf, max) -> read a pipe fd; bytes/0 EOF/-1 (M1187) */
#define SYS_fdwrite      172   /* (fd, buf, len) -> write a pipe fd; bytes/-1 EPIPE (M1187) */
#define SYS_fdclose      173   /* (fd) -> close an fd; 0/-1 (M1187) */
#define SYS_dup2         174   /* (oldfd, newfd) -> redirect newfd onto oldfd; newfd/-1 (M1187) */
#define SYS_mkfifo       175   /* (path) -> create a named pipe (FIFO); 0/-1 (M1188) */
#define SYS_fifo_open    176   /* (path, write) -> open a FIFO end -> fd; -1 (M1188) */
#define SYS_seccomp_filter 177 /* (prog, bytes) -> install a self-imposed BPF syscall filter (one-way); 0/-1 (M1190) */
/* seccomp-BPF filter verdicts — the value a filter program RETs (M1190/M1192). */
#define SECCOMP_RET_DENY  0    /* the syscall returns -1 */
#define SECCOMP_RET_ALLOW 1    /* run the syscall (any non-0/2 value allows) */
#define SECCOMP_RET_KILL  2    /* terminate the process (hard sandbox) */
#define SYS_open         178   /* (path) -> a read-only file fd (>=3); -1 (M1193) */
#define SYS_lseek        179   /* (fd, off, whence) -> reposition a file fd (0=SET,1=CUR,2=END); offset/-1 (M1193) */
#define SYS_ptrace       180   /* (request, pid, addr, data) -> trace a child process; per-request (M1199) */
#define SYS_bpf_trace    181   /* (prog, bytes) -> load a global syscall-tracepoint BPF program (0 bytes = clear); 0/-1 (M1202) */
#define SYS_bpf_map_get  182   /* (idx) -> read BPF histogram cell idx (M1202) */
#define SYS_link         183   /* (oldpath, newpath) -> hard link (same ext2 mount); 0/-1 (M1207) */
#define SYS_sigprocmask  184   /* (how, set) -> block/unblock signals; returns the old mask (M1208) */
#define SYS_sigpending   185   /* () -> the pending (raised-but-blocked) signal set (M1209) */
#define SYS_poll         186   /* (struct pollfd*, nfds, timeout_ms) -> # ready, 0 on timeout, -1 (M1210) */
#define SYS_splice       187   /* (in_fd, out_fd, len) -> move bytes pipe->pipe in-kernel; bytes/0/-1 (M1211) */
#define SYS_tee          188   /* (in_fd, out_fd, len) -> copy bytes pipe->pipe w/o consuming src; bytes/0/-1 (M1211) */
#define SYS_memfd_create 189   /* (name, flags) -> a sealable in-RAM file fd; fd(>=3)/-1 (M1212) */
#define SYS_memfd_seal   190   /* (fd, add_seals) -> add F_SEAL_*; new seal set/-1 (M1212) */
#define SYS_ftruncate    191   /* (fd, len) -> resize a memfd (seal-checked); 0/-1 (M1212) */
#define SYS_rename       192   /* (oldpath, newpath) -> rename/move within one ext2 mount; 0/-1 (M1213) */
#define SYS_prlimit      193   /* (pid, resource, newval, do_set) -> get/set a process's rlimit; old value (M1214) */
#define SYS_timerfd_create  194  /* () -> a pollable one-shot timer fd (>=3); -1 (M1217) */
#define SYS_timerfd_settime 195  /* (fd, delay_ms, interval_ms) -> arm/disarm a timerfd (interval>0 = periodic); 0/-1 (M1217, periodic M1302) */
#define SYS_fcntl        196   /* (fd, cmd, arg) -> F_GETFD/SETFD/DUPFD/DUPFD_CLOEXEC (M1218) */
#define SYS_dup3         197   /* (oldfd, newfd, flags) -> dup w/ O_CLOEXEC; -1 if old==new (M1218) */
#define SYS_close_range  198   /* (lo, hi, flags) -> close fds in [lo,hi]; 0/-1 (M1218) */
#define SYS_sendfile     199   /* (out_fd, in_fd, off_ptr, count) -> zero-copy fd->fd; bytes/-1 (M1219) */
#define SYS_epoll_create1 200  /* (flags) -> an epoll fd (>=3); -1 (M1220) */
#define SYS_epoll_ctl    201   /* (epfd, op, fd, struct epoll_event*) -> register interest; 0/-1 (M1220) */
#define SYS_epoll_wait   202   /* (epfd, struct epoll_event*, maxevents, timeout_ms) -> # ready/0/-1 (M1220) */
#define SYS_pidfd_open   203   /* (pid, flags) -> a pollable process-exit handle (>=3); -1 (M1222) */
#define SYS_pidfd_send_signal 204  /* (pidfd, sig) -> signal the process; 0/-1 (M1222) */
#define SYS_getdents64   205   /* (buf, max, start_idx) -> packed dirent64 records of the cwd; bytes/0/-1 (M1223) */
#define SYS_access       206   /* (path, amode) -> 0 if accessible, -1 (M1224) */
#define SYS_prctl        207   /* (option, arg2) -> PR_SET_NAME/PR_GET_NAME/PR_SET_PDEATHSIG/PR_GET_PDEATHSIG; 0/-1 (M1225, M1562) */
#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define PR_SET_PDEATHSIG 1   /* real Linux's own value (M1562) */
#define PR_GET_PDEATHSIG 2
#define SYS_set_tid_address 208  /* (tidptr) -> register clear_child_tid (futex-on-exit); returns the tid (M1226) */
#define SYS_waitid       209   /* (idtype, id, siginfo*, options) -> 0/-1; WNOHANG = non-blocking reap (M1227) */
#define SYS_truncate     210   /* (path, len) -> resize a real file (tmpfs / ext2 mount); 0/-1 (M1228) */
#define SYS_utimens      211   /* (path, atime, mtime) -> set timestamps; UTIME_NOW/OMIT sentinels; 0/-1 (M1230) */
#define SYS_futimens     212   /* (fd, atime, mtime) -> set timestamps on an open file fd; 0/-1 (M1230) */
#define SYS_renameat2    213   /* (oldpath, newpath, flags) -> rename with RENAME_* flags; 0/-1 (M1232) */
#define SYS_readlink     214   /* (path, buf, size) -> read a symlink's target (not followed); bytes/-1 (M1233) */
#define SYS_sched_yield  215   /* () -> voluntarily yield the CPU; 0 (M1234) */
#define SYS_nanosleep    216   /* (sec, nsec) -> sleep sec+nsec (rounded to the 100Hz tick); 0 (M1234) */
#define SYS_times        217   /* (struct tms*) -> fill CPU times (ticks); returns elapsed ticks since boot (M1235) */
#define SYS_uname        218   /* (struct utsname*) -> system identity strings; 0/-1 (M1236) */
#define SYS_getppid      219   /* () -> parent pid (M1236) */
#define SYS_getuid       220   /* () -> real uid (single-user: 0) (M1236) */
#define SYS_getgid       221   /* () -> real gid (0) (M1236) */
#define SYS_geteuid      222   /* () -> effective uid (0) (M1236) */
#define SYS_getegid      223   /* () -> effective gid (0) (M1236) */
#define SYS_sethostname  224   /* (buf, len) -> set the system hostname; 0/-1 (M1237) */
#define SYS_gethostname  225   /* (buf, len) -> copy the system hostname; 0/-1 (M1237) */
#define SYS_getentropy   226   /* (buf, len<=256) -> fill with CSPRNG bytes; 0/-1 (M1238) */
#define SYS_getpriority  227   /* (which, who) -> nice value of the caller (who==0/self); -1 (M1238) */
#define SYS_setpriority  228   /* (which, who, prio) -> set the caller's nice (who==0/self); 0/-1 (M1238) */
#define SYS_pipe2        229   /* (int fds[2], flags) -> pipe with atomic O_CLOEXEC; 0/-1 (M1239) */
#define SYS_statfs       230   /* (path, struct statvfs*) -> filesystem free/total; 0/-1 (M1240) */
#define SYS_chmod        231   /* (path, mode) -> set permission bits (ext2); 0/-1 (M1241) */
#define SYS_fchmod       232   /* (fd, mode) -> set permission bits on an open fd; 0/-1 (M1241) */
#define SYS_eventfd      233   /* (initval, flags) -> a pollable u64-counter fd; fd/-1 (M1242) */
#define EFD_SEMAPHORE 1        /* eventfd: read decrements by 1 (returns 1) instead of draining (M1242) */
#define EFD_CLOEXEC   2        /* eventfd: set FD_CLOEXEC (M1242) */
#define EFD_NONBLOCK  4        /* eventfd: read returns -1 on an empty counter instead of blocking (M1242; real blocking-if-unset M1579) */
#define SYS_chown        234   /* (path, uid, gid) -> set owner/group (ext2; -1 = leave); 0/-1 (M1243) */
#define SYS_fchown       235   /* (fd, uid, gid) -> set owner/group on an open fd; 0/-1 (M1243) */
#define SYS_sched_getcpu 236   /* () -> APIC id of the CPU the caller runs on (M1246) */
#define SYS_getcwd       237   /* (buf, size) -> the absolute current directory; length/-1 (M1248) */
#define SYS_openat       238   /* (dirfd, path, flags) -> open relative to a dir fd (or AT_FDCWD); fd/-1 (M1251) */
#define SYS_unlinkat     239   /* (dirfd, path, flags) -> remove relative to a dir fd; 0/-1 (M1251) */
#define SYS_mkdirat      240   /* (dirfd, path, mode) -> mkdir relative to a dir fd; 0/-1 (M1251) */
#define SYS_fstatat      241   /* (dirfd, path, statx*, flags) -> stat relative to a dir fd; 0/-1 (M1251) */
#define SYS_socketpair   242   /* (int sv[2]) -> a pre-connected AF_UNIX endpoint pair; 0/-1 (M1254) */
#define SYS_clock_nanosleep 243 /* (clockid, flags, sec, nsec) -> sleep; TIMER_ABSTIME = absolute deadline; 0 (M1257) */
#define SYS_clock_getres 244   /* (clockid) -> clock resolution in nanoseconds (M1257) */
#define SYS_udp_send     245   /* (dstip[4], (dport<<16)|sport, payload, plen) -> 0/-1 (M1258) */
#define SYS_udp_recv     246   /* (sport, buf, max, from{u8 ip[4];u16 port}|0) -> bytes/-1, 2s timeout (M1258) */
#define SYS_raw_send     247   /* (frame, len) -> send a complete Ethernet frame; 0/-1 (M1259) */
#define SYS_raw_recv     248   /* (buf, max) -> next Ethernet frame (2s timeout); length/-1 (M1259) */
#define SYS_insmod       249   /* () -> load the built-in .ko: relocate+resolve+run mod_init; its retval/-err (M1261) */
#define SYS_rmmod        250   /* (name) -> unload a module: run mod_exit + free its slot; 0/-1 (M1262) */
#define SYS_sendfd       251   /* (ep, fd) -> SCM_RIGHTS: pass fd over an AF_UNIX endpoint; 0/-1 (M1265) */
#define SYS_recvfd       252   /* (ep) -> SCM_RIGHTS: receive a passed fd; new fd/-1 (M1265) */
#define SYS_inotify_init 253   /* () -> a pollable filesystem-watch fd; fd/-1 (M1266) */
#define SYS_inotify_add_watch 254 /* (fd, path, mask) -> register a watch; wd/-1 (M1266) */
#define SYS_socket       255   /* (domain, type) -> AF_INET SOCK_DGRAM socket fd; fd/-1 (M1267) */
#define SYS_sock_bind    256   /* (fd, port) -> bind a datagram socket to a local port; 0/-1 (M1267) */
#define SYS_sendto       257   /* (fd, addr{u8 ip[4];u16 port}, buf, len) -> bytes/-1 (M1267) */
#define SYS_recvfrom     258   /* (fd, buf, max, from{u8 ip[4];u16 port}|0) -> bytes/-1, 2s timeout (M1267) */
#define SYS_connect      259   /* (fd, addr{u8 ip[4];u16 port}) -> active-open a TCP socket; 0/-1 (M1268) */
#define SYS_sigaction    260   /* (signo, handler, restorer, flags) -> install a handler w/ sa_flags (M1270) */
#define SYS_sigqueue     261   /* (pid, signo, value) -> queue an RT signal carrying a sigval payload; 0/-1 (M1271) */
#define SYS_timer_create 262   /* (clockid, signo, value) -> create a POSIX timer firing signo w/ payload; id/-1 (M1272) */
#define SYS_timer_settime 263  /* (id, flags, value_ms, interval_ms) -> arm/disarm; 0/-1 (M1272) */
#define SYS_timer_gettime 264  /* (id) -> ms until next fire (0 disarmed), or -1 (M1272) */
#define SYS_timer_delete 265   /* (id) -> destroy the timer; 0/-1 (M1272) */
#define SYS_hpet         266   /* (what) -> HPET high-res clock: 0=ns 1=hz 2=counter 3=present (M1273) */
#define SYS_ptsname      267   /* (fd) -> the /dev/pts/<n> index for a /dev/ptmx master fd, or -1 (M1274) */
#define SYS_oom          268   /* (cmd,arg) -> OOM killer: 0=set self oom_adj 1=trigger kill(->pid) 2=score of pid (M1275) */
#define SYS_sigaltstack  269   /* (ss_sp, ss_size) -> set the alternate signal stack (size 0 disables); 0/-1 (M1276) */
#define SYS_clock_settime 270  /* (clockid, sec, nsec) -> set the wall clock (CLOCK_REALTIME only); 0/-1 (M1280) */
#define SYS_pidfd_getfd  271   /* (pidfd, targetfd, flags) -> duplicate another process's fd into ours; new fd/-1 (M1281) */
#define SYS_mlockall     272   /* (flags) -> pin all current (MCL_CURRENT=1) + future (MCL_FUTURE=2) pages; 0/-1 (M1283) */
#define SYS_munlockall   273   /* () -> unpin all pages + clear MCL_FUTURE; 0/-1 (M1283) */
#define MCL_CURRENT 1
#define MCL_FUTURE  2
#define SYS_acpi         274   /* (what) -> ACPI AML namespace query: 0=total 1=devices 2=methods 3=PCI0? 4=_SB_? (M1284) */
#define SYS_aslr         275   /* (pid) -> the ASLR-randomized mmap base of pid (0=self); for verification (M1287) */
#define SYS_tcp_accept   276   /* (port, reqbuf, reqmax) -> passive-open + read one request, hold the conn; request bytes/-1 (M1327) */
#define SYS_tcp_respond  277   /* (resp, resp_len) -> reply on the accepted conn + close; 0/-1 (M1327) */
#define SYS_font         278   /* (buf,len) -> copy the 8x16 console font (128*16 bytes) for gfx text; bytes/-1 (M1362) */
#define SYS_loadimg      279   /* (name, buf, cw<<16|ch, outwh[2]) -> decode+fit-scale an image file into the cw*ch XRGB buf; native size in outwh; 0/-1 (M1392) */
#define SYS_msync        280   /* (addr, len) -> write back dirty pages of a MAP_SHARED file-backed mmap to disk; 0/-1 (M1544) */
#define SYS_fchmodat     281   /* (dirfd, path, mode) -> chmod relative to a dir fd (or AT_FDCWD); 0/-1 (M1553) */
#define SYS_fchownat     282   /* (dirfd, path, uid, gid) -> chown relative to a dir fd (or AT_FDCWD); 0/-1 (M1553) */
#define SYS_setsockopt   283   /* (fd, level, optname, optval*, optlen) -> set a TCP-socket option; 0/-1 (M1554) */
#define SYS_getsockopt   284   /* (fd, level, optname, optval*, optlen*) -> read a TCP-socket option; 0/-1 (M1554) */
#define SYS_process_madvise 285  /* (pidfd, addr, len, advice) -> MADV_COLD on another process's memory; pages/-1 (M1555) */
#define SYS_faccessat2   286   /* (dirfd, path, amode, flags) -> access() relative to a dir fd (or AT_FDCWD); 0/-1 (M1556) */
#define SYS_sched_setaffinity 287  /* (mask) -> restrict the calling task to a subset of online cores; 0/-1 (M1557) */
#define SYS_sched_getaffinity 288  /* () -> the calling task's current CPU-affinity mask (M1557) */
#define SYS_tcgetpgrp    289   /* () -> the console's foreground process group (0 = none); mirrors tcsetpgrp (M1558) */
#define SYS_utimensat    290   /* (dirfd, path, atime, mtime) -> set timestamps relative to a dir fd (or AT_FDCWD); 0/-1 (M1559) */
#define SYS_getsockname  291   /* (fd, addr{u8 ip[4];u16 port}[6]) -> this socket's own address; 0/-1 (M1560) */
#define SYS_getpeername  292   /* (fd, addr{u8 ip[4];u16 port}[6]) -> the connected peer's address; 0/-1 (M1560) */
#define SYS_sigsuspend   293   /* (mask) -> swap the blocked-signal mask, block for a signal, restore; always -1 (M1561) */
#define SYS_pause        294   /* () -> block until a signal is delivered, using the current mask; always -1 (M1563) */
#define SYS_setitimer    295   /* (delay_ticks, interval_ticks) -> ITIMER_REAL, delay independent of repeat; 0 (M1565) */
#define SYS_getitimer    296   /* (remain_ticks*, interval_ticks*) -> time left + configured interval; 0/-1 (M1565) */
#define SYS_fsync        297   /* (fd) -> 0 for a real file fd (write-through already durable), -1 otherwise (M1566) */
#define SYS_fdatasync    298   /* (fd) -> identical to fsync here; 0/-1 (M1566) */
#define SYS_sync_file_range 299  /* (fd, offset, nbytes, flags) -> same as fsync; range/flags unused; 0/-1 (M1566) */
#define SYS_epoll_pwait  300   /* (epfd, events*, maxevents, timeout_ms, sigmask) -> like epoll_wait, signal-interruptible; #ready/-1 on signal/-1 (M1567) */
#define SYS_inotify_rm_watch 301  /* (fd, wd) -> unregister a watch; 0/-1 (M1568) */
#define SYS_fsetxattr    302   /* (fd, name, value, vlen) -> set a user.* xattr on an open FILE fd; vlen/-1 (M1569) */
#define SYS_fgetxattr    303   /* (fd, name, out, max) -> read a user.* xattr on an open FILE fd; size/-1 (M1569) */
#define SYS_flistxattr   304   /* (fd, out, max) -> NUL-separated user.* names on an open FILE fd; total/-1 (M1569) */
#define SYS_fremovexattr 305   /* (fd, name) -> remove a user.* xattr on an open FILE fd; 0/-1 (M1569) */
#define SYS_tcflush      306   /* (queue_selector) -> discard unread input (TCIFLUSH/TCIOFLUSH); TCOFLUSH is a no-op (synchronous output); 0/-1 (M1570) */
#define SYS_tcdrain      307   /* () -> wait for pending output to transmit; a no-op here (synchronous console output); 0/-1 (M1570) */
#define TCIFLUSH  0
#define TCOFLUSH  1
#define TCIOFLUSH 2
#define SYS_mq_getattr   308   /* (idx, struct mq_attr*) -> read flags/maxmsg/msgsize/curmsgs; 0/-1 (M1571) */
#define SYS_mq_setattr   309   /* (idx, struct mq_attr *newattr, struct mq_attr *oldattr) -> set O_NONBLOCK only; 0/-1 (M1571) */
#define SYS_pread        310   /* (fd, buf, max, off) -> read a FILE fd without moving its cursor; bytes/0 EOF/-1 (M1572) */
#define SYS_pwrite       311   /* (fd, buf, len, off) -> write a FILE fd without moving its cursor; bytes/-1 (M1572) */
#define SYS_ppoll        312   /* (fds, nfds, timeout_ms, sigmask) -> like poll, signal-interruptible; #ready/-1 on signal/-1 (M1573) */
#define SYS_readv        313   /* (fd, iov, iovcnt) -> read into each segment in turn; total bytes/-1 (M1574) */
#define SYS_writev       314   /* (fd, iov, iovcnt) -> write each segment in turn; total bytes/-1 (M1574) */
struct iovec { void *iov_base; unsigned long iov_len; };
struct mq_attr { long mq_flags, mq_maxmsg, mq_msgsize, mq_curmsgs; };
/* POSIX named semaphores (M1575): distinct from the keyed SysV sets
 * (semget/semop/semctl) already in this file -- a single named counting
 * semaphore, opened/closed by any number of independent handles. */
#define SYS_sem_open     315   /* (name, oflag, value) -> find-or-create; index/-1 */
#define SYS_sem_close    316   /* (idx) -> drop this handle; 0/-1 */
#define SYS_sem_unlink   317   /* (name) -> remove the name; 0/-1 */
#define SYS_sem_wait     318   /* (idx) -> block until value>0, then decrement; 0/-1 */
#define SYS_sem_trywait  319   /* (idx) -> non-blocking sem_wait; 0/-1 (EAGAIN) */
#define SYS_sem_post     320   /* (idx) -> increment + wake waiters; 0/-1 */
#define SYS_sem_getvalue 321   /* (idx, int*) -> the current value; 0/-1 */
#define SYS_msgctl       322   /* (id, cmd) -> IPC_RMID only, frees a leaked-forever id slot; 0/-1 (M1576) */
#define SYS_shmctl       323   /* (id, cmd) -> IPC_RMID only; 0/-1 (M1576) */
#define SYS_preadv       324   /* (fd, iov, iovcnt, offset) -> like readv, at an explicit offset, cursor untouched; total bytes/-1 (M1577) */
#define SYS_pwritev      325   /* (fd, iov, iovcnt, offset) -> like writev, at an explicit offset, cursor untouched; total bytes/-1 (M1577) */
#define SYS_getsid       326   /* (pid) -> session id; pid==0 = the caller's own; -1 on a bad pid (M1580) */
#define SYS_symlinkat    327   /* (target, newdirfd, linkpath) -> symlink relative to a dir fd (or AT_FDCWD); 0/-1 (M1582) */
#define SYS_readlinkat   328   /* (dirfd, path, buf, size) -> a symlink's target relative to a dir fd (or AT_FDCWD), not followed; bytes/-1 (M1582) */
#define SYS_select       329   /* (nfds, readfds*, writefds*, exceptfds*, timeout*) -> like poll, fd_set-shaped; #ready/0 timeout/-1 (M1584) */
#define SYS_linkat       330   /* (olddirfd, oldpath, newdirfd, newpath) -> hard link relative to dir fds (or AT_FDCWD); 0/-1 (M1585) */
#define SYS_fchdir       331   /* (fd) -> chdir via an already-open directory fd; 0/-1 (M1586) */
#define SYS_dup          332   /* (fd) -> duplicate onto the lowest free fd (fcntl F_DUPFD with arg=0); fd/-1 (M1587) */
#define SYS_sync         333   /* () -> flush all filesystem buffers; always 0 here (write-through, nothing deferred) (M1588) */
#define SYS_sched_get_priority_max  334   /* (policy) -> the valid rt_priority ceiling for SCHED_*; -1 on a bad policy (M1589) */
#define SYS_sched_get_priority_min  335   /* (policy) -> the valid rt_priority floor for SCHED_*; -1 on a bad policy (M1589) */
#define SYS_shm_unlink   336   /* (name) -> remove a named shared-memory object's name -> object association; 0/-1 (M1590) */
#define SYS_sched_getscheduler  337   /* () -> the caller's own scheduling policy (SCHED_OTHER/FIFO/RR); -1 if unset (M1591) */
#define SYS_sched_getparam      338   /* () -> the caller's own rt_priority (0 for SCHED_OTHER); -1 if unset (M1591) */
#define SYS_sched_rr_get_interval  339   /* (sec*, nsec*) -> the SCHED_RR timeslice as a real duration; 0/-1 (M1591) */
#define SYS_mq_unlink    340   /* (name) -> remove a named message queue, waking any blocked sender/receiver; 0/-1 (M1593) */
#define SYS_insmod_path  341   /* (path) -> load a .ko module from a real file (relocate+resolve+run); retval/-err (M1595) */
#define SYS_ws_open      342   /* (url, status*) -> WebSocket connect + RFC 6455 handshake; conn id / -1 (M1846) */
#define SYS_ws_exchange  343   /* (id, sendbuf, sendtot, out, outmax, nrecv*) -> send queue + read reply frames; bytes / -1 (M1846) */
#define SYS_sha1         344   /* (name, hexbuf) -> SHA-1 of a file as 40 hex chars; 0/-1 (M1848) */
#define SYS_ws_serve     345   /* (port, lastmsg, lastmax, nframes*) -> accept 1 WS client + echo its frames; frames/-1 (M1849) */
#define SYS_unix_shutdown 346  /* (ep, how) -> half-close: SHUT_WR gives the peer EOF; 0/-1 (M1965) */
#define SYS_unix_unlisten 347  /* (lid) -> release a listener's bound name; 0/-1 (M1965) */
#define SYS_linux_run    348   /* (path, argstr) -> spawn a LINUX binary from the guest's own shell; pid/-1 (M1988) */

/* select(2) (M1584): a from-scratch fd_set, now a BIT ARRAY rather than a
 * single word (M1936). It was one `unsigned long` with FD_SETSIZE 32, which was
 * fine while APP_NFD was 24 -- but raising the fd table past 64 would have made
 * FD_SET(fd) shift by >= the word width, which is undefined behaviour and
 * silently corrupts a neighbouring bit or does nothing at all. An array of
 * longs is also glibc's own shape, so ported code that pokes fds_bits[] rather
 * than using the macros now works too. exceptfds is still always reported
 * empty -- this stack has no OOB/urgent-data concept for select to observe. */
#define FD_SETSIZE 256
typedef struct { unsigned long fds_bits[FD_SETSIZE / 64]; } fd_set;
#define FD_ZERO(s)      do { for (int _fdi = 0; _fdi < FD_SETSIZE / 64; _fdi++) (s)->fds_bits[_fdi] = 0; } while (0)
#define FD_SET(fd, s)   ((s)->fds_bits[(unsigned)(fd) >> 6] |=  (1UL << ((unsigned)(fd) & 63)))
#define FD_CLR(fd, s)   ((s)->fds_bits[(unsigned)(fd) >> 6] &= ~(1UL << ((unsigned)(fd) & 63)))
#define FD_ISSET(fd, s) (int)(((s)->fds_bits[(unsigned)(fd) >> 6] >> ((unsigned)(fd) & 63)) & 1UL)
struct timeval { long tv_sec; long tv_usec; };

/* setsockopt/getsockopt (M1554): real Linux's own numbering (not a free-slot
 * pick like the signals above -- these live in a separate namespace, no
 * collision risk with anything already in this file). */
#define SOL_SOCKET    1
#define SO_REUSEADDR  2
#define SO_KEEPALIVE  9
#define SO_ERROR      4      /* the pending per-socket error, read-once (M1564) */
#define SO_RCVTIMEO   20     /* recv()/read() timeout in ms (a plain int here, not a real timeval); 0 = block indefinitely, matching real SO_RCVTIMEO (M1583) */
#define IPPROTO_TCP   6
#define TCP_NODELAY   1
/* Real Linux's own errno values (M1564) -- this codebase otherwise never
 * distinguishes WHY a call failed (just -1), but SO_ERROR's entire point is
 * reporting a specific reason, so using the real numbers means ported code
 * checking `errno == ECONNREFUSED` after a getsockopt(SO_ERROR) just works. */
#define ENETUNREACH   101
#define ETIMEDOUT     110
#define ECONNREFUSED  111
#define SA_ONSTACK 0x08000000  /* sigaction flag: run this handler on the sigaltstack() stack (M1276) */
#define SIGUSR1  10            /* user signal 1 */
#define SIGRTMIN 28            /* first real-time signal; signos >= here are intended for queued sigqueue use (M1271) */
#define SA_SIGINFO 4           /* sigaction flag: 3-arg handler h(signo, siginfo*, ucontext*) (M1270) */
#define SI_QUEUE  (-1)         /* siginfo.si_code: signal sent by sigqueue (carries si_value) (M1271) */
#define SI_USER   0            /* siginfo.si_code: signal sent by kill/raise (no payload) (M1271) */
#define SI_TIMER  (-2)         /* siginfo.si_code: signal sent by a POSIX timer_create() timer (M1272) */

/* clock ids + clock_nanosleep flags (M1257). */
#define CLOCK_REALTIME   0     /* wall-clock (rtc); absolute deadlines are epoch seconds */
#define CLOCK_MONOTONIC  1     /* uptime since boot; absolute deadlines are uptime ms */
#define TIMER_ABSTIME    1     /* clock_nanosleep flag: the time is an ABSOLUTE deadline */
#define AT_FDCWD (-100)        /* *at dirfd sentinel: resolve relative to the cwd (M1251) */
#define PRIO_PROCESS 0         /* getpriority/setpriority `which`: by process (M1238) */
#define RENAME_NOREPLACE 1     /* renameat2: fail if newpath exists (M1232) */
#define RENAME_EXCHANGE  2     /* renameat2: atomically swap oldpath and newpath (M1232) */
#define UTIME_NOW  (-1L)       /* set the timestamp to the current time (M1230) */
#define UTIME_OMIT (-2L)       /* leave the timestamp unchanged (M1230) */
#define SIGCHLD 17
#define SIGWINCH 24            /* terminal window-size change (M1279); standard (coalescing), < SIGRTMIN */
/* waitid (M1227): minimal siginfo + idtype/options/si_code constants. */
struct siginfo { int si_signo, si_errno, si_code, si_pid, si_uid, si_status; };
#define P_ALL   0
#define P_PID   1
#define P_PGID  2
#define P_PIDFD 3
#define WNOHANG     1
#define WSTOPPED    2
#define WEXITED     4
#define WCONTINUED  8
#define CLD_EXITED  1
#define CLD_KILLED  2
/* access(2) mode bits (M1224). */
#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4

/* getdents64 (M1223): Linux-layout directory entries. d_name offset is 19
 * (d_ino@0 + d_off@8 + d_reclen@16 + d_type@18); records are 8-byte aligned. */
struct dirent64 { unsigned long d_ino; long d_off; unsigned short d_reclen; unsigned char d_type; char d_name[]; };
#define DT_UNKNOWN 0
#define DT_DIR     4
#define DT_REG     8
#define DT_LNK     10

/* epoll (M1220): scalable readiness multiplexing as an fd object. `events` uses
 * the POLLIN/POLLOUT bits; `data` is opaque userdata echoed back on a ready
 * event. EPOLLIN/EPOLLOUT/EPOLLET are defined further down, right after
 * POLLIN/POLLOUT themselves (EPOLLIN/EPOLLOUT alias them — real Linux's
 * epoll.h defines them to the same values as poll.h's too). */
struct epoll_event { unsigned events; unsigned long data; };
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

/* fd-flag ops (M1218). O_CLOEXEC (0x10) doesn't collide with O_RDONLY..O_CREAT. */
#define O_CLOEXEC        0x10
#define FD_CLOEXEC       1
#define F_DUPFD          0
#define F_GETFD          1
#define F_SETFD          2
#define F_DUPFD_CLOEXEC  1030

/* POSIX fcntl byte-range record locks (M1221). l_len <= 0 means "to EOF". */
struct flock { short l_type; short l_whence; long l_start; long l_len; int l_pid; };
#define F_RDLCK  0
#define F_WRLCK  1
#define F_UNLCK  2
#define F_GETLK  5
#define F_SETLK  6
#define F_SETLKW 7

/* ELF auxiliary-vector entry types, for /proc/<pid>/auxv (M1215). Standard a_type
 * values; the vector is (a_type, a_val) u64 pairs terminated by AT_NULL. */
#define AT_NULL    0
#define AT_PAGESZ  6
#define AT_ENTRY   9
#define AT_UID     11
#define AT_EUID    12
#define AT_GID     13
#define AT_EGID    14
#define AT_CLKTCK  17
#define AT_SECURE  23

/* poll(2) readiness multiplexing over the fd table (M1210). `events`/`revents`
 * are bitmasks; the kernel sets revents to the subset that won't block now.
 * int+short (no stdint here) — matches the Linux struct layout (8 bytes). */
struct pollfd { int fd; short events; short revents; };
#define POLLIN   0x0001   /* a read won't block (data, or EOF) */
#define POLLOUT  0x0004   /* a write won't block (space, and a reader exists) */
#define POLLERR  0x0008   /* (kernel-only revents) error condition */
#define POLLHUP  0x0010   /* (kernel-only revents) hang-up */
#define POLLNVAL 0x0020   /* (kernel-only revents) fd not open */

/* epoll's own names for the same two bits (M1545) + EPOLLET: opts a
 * registered fd into edge-triggered reporting (bit 31, matching real
 * epoll's own value) -- see struct epoll_event's comment above. */
#define EPOLLIN  POLLIN
#define EPOLLOUT POLLOUT
#define EPOLLET  (1u << 31)
/* EPOLLONESHOT (M2016): report this fd ONCE and then stop, until the caller
 * re-arms it with EPOLL_CTL_MOD. Ignoring it is not a missing optimisation --
 * it is an infinite loop. Claude Code registers its console descriptors with
 * EPOLLONESHOT|EPOLLOUT, which is always ready, so an epoll that keeps saying
 * yes spins the event loop at full speed and the socket it was actually
 * waiting on is never serviced. */
#define EPOLLONESHOT (1u << 30)

/* memfd_create flags + F_SEAL_* file seals (M1212). Seals are one-way (add-only);
 * F_SEAL_SEAL forbids adding any further seal. */
#define MFD_CLOEXEC       0x0001
#define MFD_ALLOW_SEALING 0x0002
#define F_SEAL_SEAL    0x0001   /* no more seals may be added */
#define F_SEAL_SHRINK  0x0002   /* the file may not be shrunk */
#define F_SEAL_GROW    0x0004   /* the file may not be grown */
#define F_SEAL_WRITE   0x0008   /* the file's contents may not be modified */

/* sigprocmask `how` values (M1208) */
#define SIG_BLOCK   0   /* add `set` to the blocked mask */
#define SIG_UNBLOCK 1   /* remove `set` from the blocked mask */
#define SIG_SETMASK 2   /* replace the blocked mask with `set` */

/* ptrace request codes (M1199) — the tracee self-marks with TRACEME; the tracer
 * (its parent) drives the rest while the tracee is stopped. */
#define PT_TRACEME   0   /* tracee: "trace me" (called by the child) */
#define PT_PEEKDATA  1   /* tracer: read one word from the tracee at addr -> word */
#define PT_POKEDATA  2   /* tracer: write `data` word into the tracee at addr */
#define PT_GETREGS   3   /* tracer: copy the tracee's registers into *(addr) */
#define PT_SETREGS   4   /* (reserved — follow-on) */
#define PT_CONT      5   /* tracer: resume the stopped tracee */
#define PT_WAIT      6   /* tracer: block until the tracee stops -> stop signal */
#define PT_SINGLESTEP 7  /* tracer: resume for ONE instruction, then re-stop (SIGTRAP) (M1200) */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#define SEEK_DATA 3   /* next data byte at/after off (M1229) */
#define SEEK_HOLE 4   /* next hole at/after off (M1229) */
/* open() flags (M1195): O_RDONLY is the default (0); the rest are bit flags. */
#define O_RDONLY 0
#define O_WRONLY 1
#define O_APPEND 2
#define O_TRUNC  4
#define O_CREAT  8
#define O_EXCL   0x80  /* real Linux's own value; first used by sem_open (M1575) */

/* Job-control signal numbers (M1178), shared by the kernel + ulib. SIGSTOP/TSTP
 * default-action stop a process; SIGCONT resumes it (no handler required). */
#define SIGTRAP  5    /* a ptrace single-step / breakpoint trap (M1200) */
#define SIGCONT  18
#define SIGSTOP  19
#define SIGTSTP  20

/* flock advisory whole-file locks (M1177), shared by the kernel + ulib. */
#define LOCK_SH  1
#define LOCK_EX  2
#define LOCK_NB  4
#define LOCK_UN  8

/* TTY line discipline (M1174), shared by the kernel + ulib. c_lflag selects
 * cooked (ICANON) vs raw input; raw delivers each keystroke immediately. Default
 * is ICANON|ECHO|ISIG (the existing line-editing behaviour). unsigned/unsigned
 * char (no stdint in userspace syscall.h). */
struct termios {
    unsigned       c_lflag;      /* ICANON | ECHO | ISIG */
    unsigned char  c_cc[8];      /* control chars: c_cc[VINTR]=ETX, c_cc[VEOF]=EOT, ... */
};
#define ISIG    0x001
#define ICANON  0x002
#define ECHO    0x008
#define VINTR   0
#define VEOF    1
#define VERASE  2
#define VKILL   3

/* statx (M1173) — unified file metadata, shared by the kernel + ulib. stx_mode's
 * top nibble is the type (S_IFMT); times are Unix epoch seconds. */
struct statx {                /* unsigned/unsigned long to match the other shared structs (no stdint here) */
    unsigned       stx_mode;     /* type (S_IF*) | permission bits */
    unsigned       stx_nlink;    /* hard-link count */
    unsigned long  stx_size;     /* bytes */
    unsigned long  stx_blocks;   /* 512-byte blocks allocated */
    unsigned long  stx_mtime;    /* last modification (epoch s) */
    unsigned long  stx_ctime;    /* last status change (epoch s) */
    unsigned long  stx_atime;    /* last access (epoch s) */
    unsigned       stx_ino;      /* inode number (0 if n/a) */
    unsigned       stx_blksize;  /* preferred I/O block size */
};
#define S_IFMT   0xF000
#define S_IFREG  0x8000
#define S_IFDIR  0x4000
#define S_IFLNK  0xA000
#define S_IFCHR  0x2000    /* character device: /dev/null and friends report this (M1965) */

/* sched_setscheduler policies (M1172), shared by the kernel + ulib. SCHED_OTHER
 * is the M1171 CFS/nice class; FIFO/RR are real-time classes that preempt it. */
#define SCHED_OTHER    0
#define SCHED_FIFO     1
#define SCHED_RR       2

/* getrlimit/setrlimit (M1163), shared by the kernel + ulib. */
#define RLIMIT_CPU     0    /* max CPU seconds (this thread's own; M1548) -> SIGXCPU */
#define RLIMIT_FSIZE   1    /* max file size in bytes (M1549) -> SIGXFSZ */
#define RLIMIT_DATA    2
#define RLIMIT_CORE    4    /* max core-dump bytes (M1551) */
#define RLIMIT_NOFILE  7    /* max open fds (M1547) */
#define RLIMIT_MEMLOCK 8    /* max mlock()'d bytes (M1550) */
#define RLIMIT_NPROC   6
#define RLIMIT_AS      9
#define RLIM_INFINITY  (~0UL)
struct rlimit { unsigned long rlim_cur, rlim_max; };

/* System V semaphore ABI (M1159), shared by the kernel + ulib. */
#define IPC_PRIVATE 0
#define IPC_CREAT   0x200
#define IPC_NOWAIT  0x800
#define IPC_RMID    0
#define GETVAL      12
#define SETVAL      16
struct sembuf { short sem_num; short sem_op; short sem_flg; };

/* fallocate(2) modes (M1153). PUNCH_HOLE deallocates whole blocks in the range,
 * leaving a sparse hole that reads as zeros; it must be OR'd with KEEP_SIZE. */
#define FALLOC_FL_KEEP_SIZE  0x01
#define FALLOC_FL_PUNCH_HOLE 0x02

#define SYSCALL_VECTOR 0x80

/* FIEMAP (M1152): a file's physical on-disk extent list (ext2 mounts). Each
 * extent is a maximal run of contiguous physical blocks. Shared kernel/user. */
#define FIEMAP_EXTENT_LAST 0x1            /* this is the file's last extent */
struct fiemap_extent {
    unsigned long fe_logical;            /* byte offset within the file   */
    unsigned long fe_physical;           /* byte offset on the device     */
    unsigned long fe_length;             /* length of the extent in bytes */
    unsigned int  fe_flags;              /* FIEMAP_EXTENT_* */
    unsigned int  _pad;
};

/* getrusage(2) (M1150). RUSAGE_SELF reports the calling process; RUSAGE_CHILDREN
 * is accepted but reports zeros (no child-time accumulation). Shared by the
 * kernel filler and the ulib wrapper, so the layout cannot drift. */
#define RUSAGE_SELF      0
#define RUSAGE_CHILDREN (-1)
struct ru_timeval { long tv_sec; long tv_usec; };
struct rusage {
    struct ru_timeval ru_utime;   /* user-mode CPU time   */
    struct ru_timeval ru_stime;   /* kernel-mode CPU time */
    long ru_maxrss;               /* resident set size, KiB */
    long ru_minflt;               /* minor page faults (no I/O: demand-zero + COW) */
    long ru_majflt;               /* major page faults (disk I/O: swap-in + file-backed) */
    long ru_nvcsw;                /* voluntary context switches (blocked/yielded)   */
    long ru_nivcsw;               /* involuntary context switches (preempted)       */
};

struct tms {                      /* times(2): CPU time in clock ticks @ 100 Hz (M1235) */
    long tms_utime;               /* user CPU time of the caller          */
    long tms_stime;               /* system CPU time of the caller        */
    long tms_cutime;              /* user CPU time of reaped children     */
    long tms_cstime;              /* system CPU time of reaped children   */
};

struct statvfs {                  /* statfs(2): filesystem stats (M1240) */
    unsigned long f_bsize;        /* block size                      */
    unsigned long f_frsize;       /* fragment size (== f_bsize here) */
    unsigned long f_blocks;       /* total data blocks               */
    unsigned long f_bfree;        /* free blocks                     */
    unsigned long f_bavail;       /* free blocks for unprivileged    */
    unsigned long f_files;        /* total inodes (0 = not tracked)  */
    unsigned long f_ffree;        /* free inodes                     */
    unsigned long f_namemax;      /* max filename length             */
};

struct utsname {                  /* uname(2): system identity (M1236) */
    char sysname[65];             /* "OS-DEV"        */
    char nodename[65];            /* host name       */
    char release[65];             /* kernel release  */
    char version[65];             /* build version   */
    char machine[65];             /* "x86_64"        */
};

#ifdef __KERNEL__
struct registers;
void syscall_dispatch(struct registers *regs);
#endif
