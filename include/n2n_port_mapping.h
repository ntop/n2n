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


#ifndef _N2N_PORT_MAPPING_H_
#define _N2N_PORT_MAPPING_H_


#include <stdint.h>

#ifdef HAVE_MINIUPNP
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif // HAVE_MINIUPNP


#ifdef HAVE_NATPMP
#include "natpmp.h"
#endif // HAVE_NATPMP


void n2n_set_port_mapping (const uint16_t port);
void n2n_del_port_mapping (const uint16_t port);


#endif // _N2N_PORT_MAPPING_H_
