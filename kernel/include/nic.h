/*
 * nic.h — the NIC-agnostic seam between the network stack (net.c) and a concrete
 * card driver (e1000.c or rtl8139.c).
 *
 * net.c builds raw Ethernet frames and polls for replies; it doesn't care which
 * card moves the bytes. It calls nic_send / nic_receive / nic_mac, and nic_init
 * picks whichever supported card is on the PCI bus and wires these calls to that
 * driver. Adding a third card means writing its driver + one probe line in
 * nic_init — net.c never changes.
 */
#pragma once
#include <stdint.h>

/* Probe the PCI bus for a supported NIC and bring it up. If both an e1000 and an
 * RTL8139 are present, the e1000 is preferred (it's the richer gigabit part and
 * the default the test suite boots with). Returns 0 on success (a card is up),
 * -1 if no supported NIC was found. */
int  nic_init(void);

const uint8_t *nic_mac(void);                  /* our 6-byte hardware address */
int  nic_send(const void *frame, uint16_t len);            /* 0 on success   */
int  nic_receive(void *out, uint16_t max);                 /* len, or 0 none */
uint64_t nic_rx_total(void);   /* frames handed out by nic_receive, ever: the only way to see a second consumer (M2125) */

/* Human-readable name of the active card ("e1000", "rtl8139", or "none") — for
 * the boot banner so it's clear which driver carried the traffic. */
const char *nic_name(void);
