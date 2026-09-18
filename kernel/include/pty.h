/*
 * pty.h — pseudoterminal master/slave pairs with a kernel line discipline (M1185).
 *
 * Endpoint-id based (no fd table), mirroring unixsock.c's design. pty_open()
 * returns a MASTER id; the SLAVE id is master|1 (master ids are even). The master
 * is the "terminal emulator" side; the slave is what a program reads/writes as
 * its controlling tty. Bytes written to the master pass through a line discipline
 * (canonical: line-buffering + echo + ERASE/KILL editing + INTR->signal; raw:
 * byte passthrough) and become slave-readable input; bytes written by the slave
 * become master-readable output. fswait-composable via pty_ready().
 */
#pragma once

int  pty_open(void);                                       /* -> master id (slave id = master|1), or -1 */
long pty_read(int id, void *buf, unsigned long max);       /* bytes; 0 at EOF; -1 bad id (blocks if empty) */
long pty_write(int id, const void *buf, unsigned long len);/* bytes; -1 bad id */
int  pty_close(int id);                                    /* close one end (wakes the peer); 0/-1 */
int  pty_ctl(int id, int cmd, int arg);                    /* 0=set lflag (ICANON|ECHO|ISIG); 1=set fg pgid; 2=set winsize (rows<<16|cols); 3=get winsize; 4=get lflag (M2211) */
int  pty_ready(int id);                                    /* fswait peek: would pty_read NOT block? */
int  pty_writable(int id);                                 /* would a WRITE come up short? for poll POLLOUT (M2206) */
unsigned long pty_lost_bytes(void);                        /* bytes a full input ring dropped (M2206) */
long pty_nread(int id);                                    /* FIONREAD: bytes queued on this side; -1 bad id (M2086) */
int  pty_pts_valid(int n);                                 /* is pair n a live pty whose slave /dev/pts/n is openable? (M1274) */
void pty_release_pid(int pid);                             /* close every pty owned by a dead pid (app_reap) */
