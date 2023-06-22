/**
 * (C) 2007-22 - ntop.org and contributors
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

#ifndef _EDGE_UTILS_WIN32_H_
#define _EDGE_UTILS_WIN32_H_

#include <n2n.h>


/* Multicast peers discovery disabled due to https://github.com/ntop/n2n/issues/65 */

/* Currently, multicast is performed by specifying the default routing network adapter.
 * If the solution is determined to be stable and effective,
 * all macro definitions "SKIP_MULTICAST_PEERS_DISCOVERY" will be completely deleted in the future.
 */
//#define SKIP_MULTICAST_PEERS_DISCOVERY

// TODO: this struct is pretty empty now, collapse it to just n2n_edge_t ?
struct tunread_arg {
    n2n_edge_t *eee;
};

extern HANDLE startTunReadThread (struct tunread_arg *arg);
int get_best_interface_ip (n2n_edge_t * eee, dec_ip_str_t *ip_addr);


#endif /* _EDGE_UTILS_WIN32_H_ */

