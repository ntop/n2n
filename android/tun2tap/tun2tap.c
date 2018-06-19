//
// Created by switchwang(https://github.com/switch-st) on 2018-04-20.
//

#include "tun2tap.h"

u8_t* uip_buf = NULL;
u8_t uip_arp_buf[UIP_LLH_LEN + UIP_ARP_LEN];
u16_t uip_arp_len = 0;
