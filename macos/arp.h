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

#ifndef _MACOS_ARP_H_
#define _MACOS_ARP_H_

#ifdef __APPLE__

#include <stdint.h>
#include <time.h>

#define ARP_CACHE_MAX_ENTRIES   1024
#define ARP_CACHE_EXPIRY_SEC    300

#define ARP_OP_REQUEST  0x0001
#define ARP_OP_REPLY    0x0002

#define ARP_ETH_HEADER_OFFSET   14
#define ARP_PACKET_MIN_LEN      (ARP_ETH_HEADER_OFFSET + 28)

struct tuntap_dev; /* forward declaration */

/**
 * Initialize the ARP cache. Must be called before any other arp_ function.
 */
void arp_cache_init(void);

/**
 * Add or update an entry in the ARP cache.
 *
 * @param ip_addr   IP address in network byte order
 * @param mac_addr  6-byte MAC address
 */
void arp_cache_update(uint32_t ip_addr, const uint8_t *mac_addr);

/**
 * Look up a MAC address for the given IP.
 * If not found or expired, writes broadcast MAC (FF:FF:FF:FF:FF:FF).
 *
 * @param ip_addr   IP address in network byte order
 * @param mac_out   6-byte buffer to receive the MAC address
 */
void arp_cache_lookup(uint32_t ip_addr, uint8_t *mac_out);

/**
 * Destroy the ARP cache and free all entries.
 */
void arp_cache_destroy(void);

/**
 * Handle an incoming ARP packet from the n2n network.
 * - Always learns sender MAC/IP
 * - If ARP request for our IP, generates a reply and sends via edge_send_packet2net
 *
 * @param tuntap  pointer to the tuntap device (contains ip_addr, mac_addr, edge_context)
 * @param buf     full Ethernet frame containing ARP
 * @param len     length of the frame
 * @return len on success (pretend we consumed it), -1 on error
 */
int arp_handle_packet(struct tuntap_dev *tuntap, unsigned char *buf, int len);

/**
 * Map an IPv4 destination address to a destination MAC for synthetic Ethernet headers.
 * Handles multicast (RFC 1112), broadcast, and ARP cache lookup.
 *
 * @param dst_ip    destination IP in network byte order
 * @param netmask   network mask in network byte order (for subnet broadcast detection)
 * @param mac_out   6-byte buffer to receive the destination MAC
 */
void ip_to_dest_mac(uint32_t dst_ip, uint32_t netmask, uint8_t *mac_out);

/**
 * Map an IPv6 destination address to a destination MAC for synthetic Ethernet headers.
 * Handles multicast per RFC 2464.
 *
 * @param ipv6_pkt  pointer to raw IPv6 packet (at least 40 bytes)
 * @param mac_out   6-byte buffer to receive the destination MAC
 */
void ipv6_to_dest_mac(const uint8_t *ipv6_pkt, uint8_t *mac_out);

#endif /* __APPLE__ */
#endif /* _MACOS_ARP_H_ */
