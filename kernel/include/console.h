/*
 * console.h — the kernel's unified text output.
 *
 * console_putc writes one character to *both* the VGA screen and the serial
 * port, so everything the kernel prints is visible in a QEMU window and
 * capturable headlessly. kprintf is our freestanding printf built on top.
 */
#pragma once
#include <stdarg.h>

void console_init(void);
void console_putc(char c);
void console_write(const char *s);
void console_write_n(const char *s, unsigned long n);   /* n bytes, console lock held ONCE -- no mid-string splicing (M1952) */
void console_enable_gfx(void);   /* route output to the framebuffer console */
void console_gfx_release(void);  /* the window manager owns the framebuffer: stop DRAWING the log (serial + /proc/kmsg unaffected) (M2011) */
void console_gfx_reclaim(void);  /* take the screen back -- a panic has to be visible (M2011) */

void kprintf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void kvprintf(const char *fmt, va_list ap);

/* Copy the most recent kernel-log bytes (oldest-first, NUL-terminated) into
 * out[max]; returns the byte count written. Backs /proc/kmsg (a `dmesg`). */
int klog_copy(char *out, int max);
void klog_write(const char *buf, int n);   /* append userspace bytes to the log ring (/dev/kmsg, M1216) */
/* Console capture (M1870): redirect a kprintf-based dumper's output into buf[max]
 * (for the network debug console). Single-consumer, best-effort; returns bytes. */
void console_capture_begin(char *buf, int max);
int  console_capture_end(void);
void console_selftest(void);
/* PANIC MODE (M2080): while set, nothing takes the console lock and fbcon stops
 * scrolling, so the panic path can never be silenced by a lock it cannot win or
 * slowed by a 4.9 MB framebuffer memmove per line. */
void     console_panic_mode(void);
int      console_in_panic(void);
unsigned console_panic_lock_attempts(void);   /* violations of the above, for the panic path to report */
void     console_panic_selftest(void);        /* -append selftest: a panic-mode print must refuse the lock, not spin (M2080) */
