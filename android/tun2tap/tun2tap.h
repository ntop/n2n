//
// Created by switchwang(https://github.com/switch-st) on 2018-04-14.
//

#ifndef _TUN2TAP_H_
#define _TUN2TAP_H_

#ifdef HTONS
#undef HTONS
#endif

#include "uip-conf.h"
#include <uip/uip.h>
#include <uip/uip_arp.h>

#define UIP_ARP_LEN 28

struct arp_hdr {
    struct uip_eth_hdr ethhdr;
    u16_t hwtype;
    u16_t protocol;
    u8_t hwlen;
    u8_t protolen;
    u16_t opcode;
    struct uip_eth_addr shwaddr;
    u16_t sipaddr[2];
    struct uip_eth_addr dhwaddr;
    u16_t dipaddr[2];
};

struct ethip_hdr {
    struct uip_eth_hdr ethhdr;
    /* IP header. */
    u8_t vhl,
            tos,
            len[2],
            ipid[2],
            ipoffset[2],
            ttl,
            proto;
    u16_t ipchksum;
    u16_t srcipaddr[2],
            destipaddr[2];
};

#define BUF   ((struct arp_hdr *)&uip_buf[0])
#define IPBUF ((struct ethip_hdr *)&uip_buf[0])

extern u8_t* uip_buf;
extern u8_t uip_arp_buf[UIP_LLH_LEN + UIP_ARP_LEN];
extern u16_t uip_arp_len;

#endif //_TUN2TAP_H_
