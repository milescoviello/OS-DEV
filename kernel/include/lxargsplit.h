/*
 * lxargsplit.h — split a shell-supplied argument string into argv for a Linux
 * program, and UNDO THE SHELL'S QUOTING SENTINEL while doing it.
 *
 * WHY THIS EXISTS (M2071). SYS_linux_run used to split on spaces and copy the
 * bytes verbatim, under a comment saying "quoting belongs to the shell and is
 * not reinvented here". Quoting does belong to the shell — but OS-DEV's shell
 * implements it by setting BIT 7 on any character a quote is protecting
 * (user/shquote.h: SH_PROT/SH_UNPROT), and only the shell's own
 * sh_unprot_buf() ever puts those bytes back. The shell hands this syscall the
 * raw, still-protected string.
 *
 * So a quoted argument arrived at the program with its spaces replaced by
 * 0xA0. Claude Code printed its own argv in a crash report and showed it:
 *
 *     Args: "/usr/bin/claude" "-p" "Reply?with?exactly:?OS-DEV"
 *
 * — three U+FFFD, because 0xA0 is not valid UTF-8. Every quoted argument to
 * every Linux program was corrupted, silently, and the program could not tell:
 * it is a well-formed string, just not the one that was typed.
 *
 * The sentinel is what makes the split correct in the first place — a
 * protected space must NOT end an argument — so the two operations belong
 * together: split on REAL spaces, strip the high bit from what you copy.
 *
 * Pure (no syscalls, no allocation) so it is host-tested by tests/lxargsplit.c,
 * the same treatment shquote/shsplit/shbrace get.
 */
#ifndef LXARGSPLIT_H
#define LXARGSPLIT_H

/* Split `src` into up to `maxav` arguments, copying into `buf` (capacity
 * `bufsz`, NUL-separated). Returns the argument count. `av[i]` points into
 * `buf`. A NULL/empty `src` yields 0. Truncation is silent but bounded: it can
 * only drop trailing arguments or tail bytes, never run off either buffer. */
static int lx_split_args(const char *src, char *buf, int bufsz, char **av, int maxav) {
    int nav = 0, k = 0;
    if (!src || !buf || !av || bufsz <= 0 || maxav <= 0) return 0;
    while (*src && k < bufsz - 1) {
        while (*src == ' ') src++;          /* a REAL space separates; a protected one does not */
        if (!*src) break;
        if (nav >= maxav) break;
        av[nav++] = &buf[k];
        while (*src && *src != ' ' && k < bufsz - 1) {
            unsigned char c = (unsigned char)*src++;
            /* THE SENTINEL COMES OFF HERE. Shell input is 7-bit, so a high bit
             * is always the shell's quoting marker and never data. */
            buf[k++] = (char)(c & 0x7Fu);
        }
        if (k < bufsz) buf[k++] = 0;
    }
    return nav;
}

#endif
