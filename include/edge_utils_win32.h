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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#ifndef _EDGE_UTILS_WIN32_H_
#define _EDGE_UTILS_WIN32_H_

#ifdef WIN32

#define WIN32_LEAN_AND_MEAN

#include <process.h>
#include <n2n.h>


/* Multicast peers discovery disabled due to https://github.com/ntop/n2n/issues/65 */
#define SKIP_MULTICAST_PEERS_DISCOVERY

struct tunread_arg {
    n2n_edge_t *eee;
    int *keep_running;
};

extern HANDLE startTunReadThread (struct tunread_arg *arg);


#endif /* WIN32 */

#endif /* _EDGE_UTILS_WIN32_H_ */

