/*
 * pipe.h — anonymous pipe objects for the per-process fd table (M1187).
 *
 * A kernel-side table of unidirectional byte pipes, each a ring buffer with a
 * reader-end and writer-end open-count. The per-process fd table (struct app.fd)
 * holds {pipe index, which end}; these calls are the object layer beneath it.
 * Blocking is the mbox.c/unixsock.c discipline (block-once-when-empty/full, woken
 * by the peer; lost-wakeup-free on this single CPU via the IF=0 int-0x80 gate).
 */
#pragma once

int  pipe_new(void);                                          /* -> pipe index (r_open=w_open=1), or -1 */
int  pipe_new_fifo(void);                                     /* -> a pinned, unopened (0/0) pipe for a FIFO, or -1 (M1188) */
long pipe_read(int idx, void *buf, unsigned long max);        /* bytes; 0 at EOF (no writers, drained); -1 bad idx */
long pipe_write(int idx, const void *buf, unsigned long len); /* bytes; -1 if no readers (EPIPE) or bad idx */
int  pipe_readable(int idx);                                  /* poll: 1 if a read won't block (data or EOF) (M1210) */
void pipe_state(int idx, int *r_open, int *w_open, int *queued, int *had_writer);  /* reference counts + queued bytes, for a stalled poll (M2004) */
#define PIPE_EAGAIN (-11)                                        /* pipe_write_ex(nb): the ring is full and nothing moved (M2009) */
long pipe_write_ex(int idx, const void *buf, unsigned long len, int nb);   /* O_NONBLOCK-aware write; partial counts are real (M2009) */
int  pipe_writable(int idx);                                  /* poll: 1 if a write won't block (space or no reader) (M1210) */
long pipe_splice(int in, int out, unsigned long max);         /* move bytes in->out (consumes in); bytes/-1 (M1211) */
long pipe_tee(int in, int out, unsigned long max);            /* copy bytes in->out (in preserved); bytes/-1 (M1211) */
void pipe_open_end(int idx, int write_end);                   /* fork/dup2: add a reference to one end */
void pipe_close_end(int idx, int write_end);                  /* drop a reference; wake the peer; free at 0/0 */
