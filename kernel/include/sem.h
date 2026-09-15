/*
 * sem.h — POSIX named semaphores (M1575). See sem.c.
 */
#pragma once
#include "syscall.h"   /* O_CREAT/O_EXCL */

int sem_named_open(const char *name, int oflag, unsigned int value);  /* find-or-create; index, or -1 */
int sem_named_close(int idx);                                          /* drop this handle; 0/-1 */
int sem_named_unlink(const char *name);                                /* remove the name; 0/-1 */
int sem_named_wait(int idx);                                            /* block until value>0, then decrement; 0/-1 */
int sem_named_trywait(int idx);                                        /* non-blocking sem_wait; 0/-1 (EAGAIN) */
int sem_named_post(int idx);                                            /* increment + wake waiters; 0/-1 */
int sem_named_getvalue(int idx, int *out);                             /* read the current value; 0/-1 */
void psem_forget_task(void *t);      /* a freed task must not stay a stored waiter (M2053) */
