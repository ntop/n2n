/**
 * (C) 2007-20 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#include "network_traffic_filter.h"
#include "uthash.h"

typedef struct network_traffic_filter_rule
{
    n2n_sock_t source;
    n2n_sock_t destination;
    uint16_t protocol;
    uint8_t actionOnMatch;
    uint8_t actionOnNoMatch;
} network_traffic_filter_rule_t;

typedef struct network_traffic_filter_impl
{
    n2n_verdict (*filter_packet_from_peer)(struct network_traffic_filter* filter, n2n_edge_t *eee, const n2n_sock_t *peer, uint8_t *payload, uint16_t *payload_size);

    n2n_verdict (*filter_packet_from_tap)(struct network_traffic_filter* filter, n2n_edge_t *eee, uint8_t *payload, uint16_t *payload_size);



}network_traffic_filter_impl_t;

n2n_verdict filter_packet_from_peer(network_traffic_filter_t *filter, n2n_edge_t *eee, const n2n_sock_t *peer, uint8_t *payload, uint16_t *payload_size)
{
    printf("do filter_packet_from_peer");
    return N2N_ACCEPT;
}


n2n_verdict filter_packet_from_tap(network_traffic_filter_t *filter, n2n_edge_t *eee, uint8_t *payload, uint16_t *payload_size)
{
    printf("do filter_packet_from_tap");
    return N2N_ACCEPT;
}

network_traffic_filter_t *create_network_traffic_filter() {
    return NULL;
}

void destroy_network_traffic_filter(network_traffic_filter_t *filter) {

}
