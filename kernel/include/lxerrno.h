/*
 * lxerrno.h — Linux errno values and the return convention (M1938).
 *
 * THE SINGLE MOST IMPORTANT PIECE OF THE ABI, and the one that is invisible
 * until it has poisoned everything.
 *
 * Our native syscalls return a bare -1 on failure. Linux returns the NEGATED
 * errno in rax: -2 for ENOENT, -22 for EINVAL, and so on. musl's wrapper is
 *
 *     if (r < 0 && r > -4096) { errno = -r; return -1; }
 *
 * so a bare -1 is read as errno 1 = EPERM. Every single failure — a missing
 * file, a bad fd, a short read — would report "Operation not permitted". A
 * shell would print nonsense, and worse, code that branches on ENOENT (which
 * is most `stat`-then-create logic, and all of a compiler's include-path
 * search) takes the wrong branch and fails in ways that look like anything but
 * an errno bug. So every handler here returns -LX_Exxx, never -1.
 */
#pragma once

#define LX_EPERM     1
#define LX_ENOENT    2
#define LX_ESRCH     3
#define LX_EINTR     4
#define LX_EIO       5
#define LX_ENXIO     6
#define LX_E2BIG     7
#define LX_ENOEXEC   8
#define LX_EBADF     9
#define LX_ECHILD   10
#define LX_EAGAIN   11
#define LX_ENOMEM   12
#define LX_EACCES   13
#define LX_EFAULT   14
#define LX_EBUSY    16
#define LX_EEXIST   17
#define LX_EXDEV    18
#define LX_ENODEV   19
#define LX_ENOTDIR  20
#define LX_EISDIR   21
#define LX_EINVAL   22
#define LX_ENFILE   23
#define LX_EMFILE   24
#define LX_ENOTTY   25
#define LX_EFBIG    27
#define LX_ENOSPC   28
#define LX_ESPIPE   29
#define LX_EROFS    30
#define LX_EMLINK   31
#define LX_EPIPE    32
#define LX_ERANGE   34
#define LX_ENAMETOOLONG 36
#define LX_ENOSYS   38
#define LX_ENOTEMPTY 39
#define LX_ELOOP    40
#define LX_EOVERFLOW 75

/* Map a native "-1 means it failed" result onto a Linux return. `fallback` is
 * the errno to report, chosen per call site because our layer genuinely does
 * not know why the native call failed -- the native ABI threw that information
 * away. Guessing badly is still far better than reporting EPERM for
 * everything, and the honest ones are noted at each use. */
static inline long lx_ret(long native, int fallback) {
    return native < 0 ? -(long)fallback : native;
}
#define LX_ETIMEDOUT 110  /* futex wait hit its deadline (M1959) */
#define LX_EAFNOSUPPORT 97
#define LX_ENOTCONN    107
#define LX_ENETUNREACH 101
#define LX_EADDRINUSE 98
#define LX_ECONNREFUSED 111
#define LX_ENOTSOCK    88   /* getpeername on something that is not a socket (M1986) */
#define LX_EOPNOTSUPP  95   /* a filesystem may legitimately refuse fallocate (M1986) */
