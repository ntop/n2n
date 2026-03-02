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

#ifndef _MACOS_ROUTE_H_
#define _MACOS_ROUTE_H_

#ifdef __APPLE__

#include "n2n_typedefs.h"

/**
 * Initialize routes on macOS using the route command.
 * Routes are bound to the utun interface and are automatically cleaned up
 * when the interface is destroyed (fd closed).
 *
 * @param eee        edge context
 * @param routes     array of routes to add
 * @param num_routes number of routes
 * @return 0 on success, -1 on failure
 */
int edge_init_routes_darwin(n2n_edge_t *eee, n2n_route_t *routes, uint16_t num_routes);

#endif /* __APPLE__ */
#endif /* _MACOS_ROUTE_H_ */
