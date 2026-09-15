/*
 * mbox.h — named message-queue IPC (M1087).
 *
 * The OS had no general process-to-process data channel (only signals for
 * notification and a single global clipboard). This adds named mailboxes,
 * addressed by name through the VFS as /ipc/<name>: a write ENQUEUES one
 * discrete message, a read DEQUEUES one (FIFO) and BLOCKS if the queue is empty
 * until a writer arrives — a real producer/consumer primitive built on the
 * round-robin block/wake ring (M1079), with no fd table required.
 */
#pragma once

long mbox_write(const char *name, const void *data, unsigned long len);  /* enqueue one message; bytes, or -1 if full/bad */
long mbox_read(const char *name, void *buf, unsigned long max);          /* dequeue one (blocks if empty); bytes, or 0 if woken empty */
int  mbox_format(char *buf, int max);                                    /* list queues + pending depth (backs /proc/ipc) */
int  mbox_ready(const char *name);                                       /* fswait peek: a message queued? (M1125) */
void mbox_forget_task(void *t);      /* a freed task must not stay a stored waiter (M2053) */
