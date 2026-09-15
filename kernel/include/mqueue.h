/*
 * mqueue.h — POSIX-style priority message queues (M1154). Named, bounded,
 * priority-ordered queues with blocking send/receive; shared by name (no fd
 * table needed). See mqueue.c.
 */
#pragma once

int  mqueue_open(const char *name, int maxmsg, int msgsize);  /* find-or-create; index, or -1 */
long mqueue_send(int idx, const void *buf, unsigned long len, unsigned int prio);   /* enqueue (blocks if full); bytes/-1 */
long mqueue_receive(int idx, void *buf, unsigned long max, unsigned int *prio_out); /* dequeue highest prio (blocks if empty); bytes/-1 */
int  mqueue_format(char *out, int max);                       /* /proc/mqueue text */
int  mqueue_getattr(int idx, long *flags, long *maxmsg, long *msgsize, long *curmsgs);  /* 0/-1 (M1571) */
int  mqueue_setattr(int idx, long new_flags, long *old_flags_out);  /* set O_NONBLOCK; 0/-1 (M1571) */
int  mqueue_unlink(const char *name);                         /* remove a named queue, waking any blocked sender/receiver; 0/-1 (M1593) */
void mqueue_forget_task(void *t);    /* a freed task must not stay a stored waiter (M2053) */
