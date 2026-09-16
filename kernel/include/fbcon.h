/* fbcon.h — a text console rendered on the framebuffer. */
#pragma once
#include <stdint.h>

int  fbcon_init(void);          /* set graphics mode + clear; 0 on success */
void fbcon_putc(char c);        /* draw a character, handling \n \r \b \t + scroll */
void fbcon_set_colors(unsigned fg, unsigned bg);
/* WHAT THE BOOT LOG COST TO DRAW (M2091): characters, lines, full-screen
 * scrolls, and the cycles spent in each. Measured before optimising, so the
 * fix can be predicted and then checked rather than hoped for. */
void fbcon_stats(uint64_t *chars, uint64_t *lines,
                 uint64_t *scrolls, uint64_t *cyc_glyph,
                 uint64_t *cyc_scroll);
