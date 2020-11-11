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

//
// Zhou Bin <joshuafc@foxmail.com>
//

#ifndef N2N_NETWORK_TRAFFIC_FILTER_H
#define N2N_NETWORK_TRAFFIC_FILTER_H

#include "n2n.h"

/*
 * add feature to drop or accept specific packet transmit over edge network interface by rules.
 *
 * below structs and function used 'n2n_verdict' and other structs, so defined in 'n2n.h', to avoid header files circular dependency.
 * port_range_t, filter_rule_key_t, filter_rule_t, network_traffic_filter_t
 * uint8_t process_traffic_filter_rule_str(const char* rule_str, filter_rule_t* rule_struct);
 */



network_traffic_filter_t* create_network_traffic_filter();

void destroy_network_traffic_filter(network_traffic_filter_t* filter);

void network_traffic_filter_add_rule(network_traffic_filter_t* filter, filter_rule_t* rules);

#endif //N2N_NETWORK_TRAFFIC_FILTER_H
