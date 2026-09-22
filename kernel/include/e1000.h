/* e1000.h — Intel 82540EM (e1000) gigabit NIC driver. */
#pragma once
#include <stdint.h>

/* Initialize the card: map its registers, read the MAC, set up the RX/TX
 * descriptor rings. Returns 0 on success, -1 if no e1000 is present. */
int  e1000_init(void);
uint64_t e1000_irq_count(void);   /* RX interrupts taken (0 before M1858); storm sanity-check */

const uint8_t *e1000_mac(void);              /* our 6-byte hardware address */

int  e1000_send(const void *frame, uint16_t len);          /* 0 on success   */
int  e1000_receive(void *out, uint16_t max);               /* len, or 0 none */
void e1000_report(void);   /* RX ring / irq / drop summary (M2365) */
