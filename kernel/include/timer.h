/* timer.h — the 8253/8254 Programmable Interval Timer (PIT) on IRQ0. */
#pragma once
#include <stdint.h>

void     timer_init(uint32_t hz);   /* program the PIT and install IRQ0 handler */
uint64_t timer_ticks(void);         /* ticks since boot */
uint64_t timer_ms(void);            /* milliseconds since boot (monotonic) */
/* NANOSECONDS since boot: whole PIT ticks plus a TSC-derived fraction, so the
 * monotonic clock stops advancing in 10 ms jumps. A 60 Hz frame interval is
 * 16.7 ms, so a 10 ms clock cannot express one. (M2114) */
uint32_t timer_hz(void);            /* the tick rate: never assume 100 (M2117) */
uint64_t timer_cycles_per_ms(void);   /* TSC cycles per ms, 0 if uncalibrated (M2139) */
uint64_t timer_ns(void);
uint64_t timer_res_ns(void);        /* what that clock's resolution ACTUALLY is */
void     timer_calibrate_tsc(void); /* once, after the PIT is running */
void     timer_wait(uint64_t ticks);/* busy-sleep this many ticks (hlt-based) */
uint32_t timer_tick_ms(void);       /* ms per tick (1000/hz); APs use this to charge CPU time at the same rate (M1548) */
