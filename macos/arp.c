/**
 * (C) 2007-21 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#ifdef __APPLE__

#include "n2n.h"
#include "arp.h"

#include <string.h>
#include <arpa/inet.h>


void edge_send_packet2net(n2n_edge_t *eee, uint8_t *tap_pkt, size_t len);


typedef struct arp_entry {
    uint32_t       ip_addr;
    n2n_mac_t      mac_addr;
    time_t         last_seen;
    UT_hash_handle hh;
} arp_entry_t;


static arp_entry_t *arp_cache = NULL;
static int arp_cache_count = 0;


void arp_cache_init (void) {

    arp_cache = NULL;
    arp_cache_count = 0;
}


void arp_cache_update (uint32_t ip_addr, const uint8_t *mac_addr) {

    arp_entry_t *entry = NULL;
    static const uint8_t zero_mac[6] = {0};
    static const uint8_t bcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    if(ip_addr == 0)
        return;
    if(memcmp(mac_addr, zero_mac, 6) == 0)
        return;
    if(memcmp(mac_addr, bcast_mac, 6) == 0)
        return;

    HASH_FIND_INT(arp_cache, &ip_addr, entry);

    if(entry) {
        memcpy(entry->mac_addr, mac_addr, 6);
        entry->last_seen = time(NULL);
        return;
    }

    /* evict oldest if at capacity */
    if(arp_cache_count >= ARP_CACHE_MAX_ENTRIES) {
        arp_entry_t *oldest = NULL, *cur, *tmp;
        HASH_ITER(hh, arp_cache, cur, tmp) {
            if(!oldest || cur->last_seen < oldest->last_seen)
                oldest = cur;
        }
        if(oldest) {
            HASH_DEL(arp_cache, oldest);
            free(oldest);
            arp_cache_count--;
        }
    }

    entry = (arp_entry_t *)calloc(1, sizeof(arp_entry_t));
    if(!entry)
        return;

    entry->ip_addr = ip_addr;
    memcpy(entry->mac_addr, mac_addr, 6);
    entry->last_seen = time(NULL);

    HASH_ADD_INT(arp_cache, ip_addr, entry);
    arp_cache_count++;
}


void arp_cache_lookup (uint32_t ip_addr, uint8_t *mac_out) {

    arp_entry_t *entry = NULL;

    HASH_FIND_INT(arp_cache, &ip_addr, entry);

    if(entry) {
        time_t now = time(NULL);
        if((now - entry->last_seen) < ARP_CACHE_EXPIRY_SEC) {
            memcpy(mac_out, entry->mac_addr, 6);
            return;
        }
    }

    memset(mac_out, 0xFF, 6);
}


void arp_cache_destroy (void) {

    arp_entry_t *cur, *tmp;

    HASH_ITER(hh, arp_cache, cur, tmp) {
        HASH_DEL(arp_cache, cur);
        free(cur);
    }
    arp_cache = NULL;
    arp_cache_count = 0;
}


void ip_to_dest_mac (uint32_t dst_ip, uint32_t netmask, uint8_t *mac_out) {

    uint32_t ip_host = ntohl(dst_ip);

    /* broadcast: 255.255.255.255 */
    if(dst_ip == 0xFFFFFFFF) {
        memset(mac_out, 0xFF, 6);
        return;
    }

    /* subnet broadcast: host bits all 1 */
    if(netmask != 0) {
        uint32_t mask_host = ntohl(netmask);
        if((ip_host | mask_host) == 0xFFFFFFFF) {
            memset(mac_out, 0xFF, 6);
            return;
        }
    }

    /* IPv4 multicast: 224.0.0.0/4 -> 01:00:5E:xx:xx:xx per RFC 1112 */
    if((ip_host & 0xF0000000) == 0xE0000000) {
        mac_out[0] = 0x01;
        mac_out[1] = 0x00;
        mac_out[2] = 0x5E;
        mac_out[3] = (ip_host >> 16) & 0x7F;
        mac_out[4] = (ip_host >> 8) & 0xFF;
        mac_out[5] = ip_host & 0xFF;
        return;
    }

    arp_cache_lookup(dst_ip, mac_out);
}


void ipv6_to_dest_mac (const uint8_t *ipv6_pkt, uint8_t *mac_out) {

    /* IPv6 header: dst address at offset 24, 16 bytes */
    const uint8_t *dst_addr = ipv6_pkt + 24;

    /* IPv6 multicast (ff00::/8) -> 33:33:xx:xx:xx:xx per RFC 2464 */
    if(dst_addr[0] == 0xFF) {
        mac_out[0] = 0x33;
        mac_out[1] = 0x33;
        mac_out[2] = dst_addr[12];
        mac_out[3] = dst_addr[13];
        mac_out[4] = dst_addr[14];
        mac_out[5] = dst_addr[15];
        return;
    }

    memset(mac_out, 0xFF, 6);
}


int arp_handle_packet (struct tuntap_dev *tuntap, unsigned char *buf, int len) {

    uint16_t hw_type, proto_type, arp_op;
    uint8_t *arp_data;
    uint8_t sender_mac[6];
    uint32_t sender_ip, target_ip;

    if(len < ARP_PACKET_MIN_LEN)
        return len;

    arp_data = buf + ARP_ETH_HEADER_OFFSET;

    hw_type = (arp_data[0] << 8) | arp_data[1];
    proto_type = (arp_data[2] << 8) | arp_data[3];

    if(hw_type != 0x0001 || proto_type != 0x0800)
        return len;

    if(arp_data[4] != 6 || arp_data[5] != 4)
        return len;

    arp_op = (arp_data[6] << 8) | arp_data[7];
    memcpy(sender_mac, &arp_data[8], 6);
    memcpy(&sender_ip, &arp_data[14], 4);
    memcpy(&target_ip, &arp_data[24], 4);

    arp_cache_update(sender_ip, sender_mac);

    if(arp_op == ARP_OP_REQUEST && target_ip == tuntap->ip_addr && tuntap->edge_context) {
        /* build ARP reply as full Ethernet frame */
        uint8_t reply[42];
        n2n_edge_t *eee = (n2n_edge_t *)tuntap->edge_context;

        /* Ethernet header */
        memcpy(&reply[0], sender_mac, 6);           /* dst = original sender */
        memcpy(&reply[6], tuntap->mac_addr, 6);     /* src = our MAC */
        reply[12] = 0x08; reply[13] = 0x06;         /* EtherType = ARP */

        /* ARP payload */
        reply[14] = 0x00; reply[15] = 0x01;         /* hardware type = Ethernet */
        reply[16] = 0x08; reply[17] = 0x00;         /* protocol type = IPv4 */
        reply[18] = 6;                               /* hardware size */
        reply[19] = 4;                               /* protocol size */
        reply[20] = 0x00; reply[21] = 0x02;          /* operation = reply */
        memcpy(&reply[22], tuntap->mac_addr, 6);    /* sender MAC = ours */
        memcpy(&reply[28], &tuntap->ip_addr, 4);    /* sender IP = ours */
        memcpy(&reply[32], sender_mac, 6);           /* target MAC = requester */
        memcpy(&reply[38], &sender_ip, 4);           /* target IP = requester */

        edge_send_packet2net(eee, reply, sizeof(reply));

        traceEvent(TRACE_DEBUG, "sent internal ARP reply for our IP");
    }

    return len;
}

#endif /* __APPLE__ */
