/*
 * inotify.h — real, pollable filesystem-watch fds (M1266).
 *
 * Distinct from /proc/fsevents (M1085, a single global read-only ring): an
 * inotify instance is a per-process FD on which you register path watches and
 * then read() typed events — and it's epoll-able (app_fd_ready reports POLLIN
 * when events are queued). Events are fed from the one VFS mutation chokepoint
 * (fsevents_record), so every create/write/delete/rename the VFS sees is
 * matched against the registered watches.
 *
 * MVP scope: a watch matches when its path is a substring of the event path
 * (so watching "X.TXT" or a dir prefix catches writes under it); events are
 * fixed 48-byte records { wd(4), mask(4), cookie(4), len(4)=32, name[32] }.
 */
#pragma once
#include <stdint.h>

/* event mask bits (Linux values) */
#define IN_MODIFY    0x00000002u
#define IN_MOVED_TO  0x00000080u
#define IN_CREATE    0x00000100u
#define IN_DELETE    0x00000200u

int  inotify_new(void);                                  /* alloc an instance; index or -1 */
int  inotify_add(int idx, const char *path, uint32_t mask);  /* register a watch; wd or -1 */
int  inotify_rm(int idx, int wd);                        /* unregister a watch by wd; 0/-1 (M1568) */
void inotify_ref(int idx);                               /* a dup()/fork() alias of an existing fd (M1603) */
void inotify_free(int idx);                              /* drop a reference; frees the instance at 0 (M1603) */
int  inotify_ready(int idx);                             /* are events queued? (epoll/poll) */
long inotify_nread(int idx);                             /* FIONREAD: queued bytes (48 per event); -1 bad idx (M2086) */
long inotify_read(int idx, void *buf, unsigned long max);/* drain queued events; bytes written (0 = none) */
void inotify_feed(char op, const char *path);            /* called from fsevents_record on every VFS mutation */
