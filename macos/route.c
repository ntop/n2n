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
#include "route.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>


static int run_route_cmd (const char *cmd) {

    int rc;

    traceEvent(TRACE_DEBUG, "route cmd: %s", cmd);
    rc = system(cmd);
    if(rc != 0) {
        traceEvent(TRACE_WARNING, "route command failed (rc=%d): %s", rc, cmd);
    }
    return rc;
}


static int add_supernode_host_route (n2n_edge_t *eee) {

    /*
     * Before overriding the default route, add a host route to each supernode
     * via the current default gateway so supernode traffic doesn't go through
     * the tunnel.
     */
    struct peer_info *scan, *tmp;
    char cmd[256];
    char gw_buf[64];
    FILE *fp;
    char line[256];
    char gw[64] = {0};

    /* find current default gateway */
    fp = popen("route -n get default 2>/dev/null | grep gateway | awk '{print $2}'", "r");
    if(!fp)
        return -1;

    if(fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';
        strlcpy(gw, line, sizeof(gw));
    }
    pclose(fp);

    if(gw[0] == '\0') {
        traceEvent(TRACE_WARNING, "could not determine current default gateway");
        return -1;
    }

    traceEvent(TRACE_NORMAL, "current default gateway: %s", gw);

    /* save gateway for potential cleanup */
    strlcpy(gw_buf, gw, sizeof(gw_buf));

    HASH_ITER(hh, eee->conf.supernodes, scan, tmp) {
        if(scan->ip_addr && scan->ip_addr[0]) {
            /* extract IP part (before the colon/port) */
            char sn_ip[64];
            const char *colon;

            strlcpy(sn_ip, scan->ip_addr, sizeof(sn_ip));
            colon = strchr(sn_ip, ':');
            if(colon)
                sn_ip[colon - sn_ip] = '\0';

            snprintf(cmd, sizeof(cmd), "route add -host %s %s", sn_ip, gw_buf);
            run_route_cmd(cmd);
        }
    }

    return 0;
}


int edge_init_routes_darwin (n2n_edge_t *eee, n2n_route_t *routes, uint16_t num_routes) {

    int i;
    char cmd[256];
    struct in_addr net;
    int has_default = 0;

    if(!routes || num_routes == 0)
        return 0;

    /* check if any route is a default route */
    for(i = 0; i < num_routes; i++) {
        if(routes[i].net_addr == 0 && routes[i].net_bitlen == 0) {
            has_default = 1;
            break;
        }
    }

    /* add supernode host routes before overriding default */
    if(has_default) {
        add_supernode_host_route(eee);
    }

    for(i = 0; i < num_routes; i++) {
        n2n_route_t *route = &routes[i];

        if(route->net_addr == 0 && route->net_bitlen == 0) {
            /*
             * Default route override using the 0/1 + 128/1 split trick.
             * This takes priority over the existing 0/0 default route
             * without deleting it, so it can be restored on exit.
             */
            snprintf(cmd, sizeof(cmd), "route add -net 0.0.0.0/1 -interface %s",
                     eee->device.dev_name);
            run_route_cmd(cmd);

            snprintf(cmd, sizeof(cmd), "route add -net 128.0.0.0/1 -interface %s",
                     eee->device.dev_name);
            run_route_cmd(cmd);
        } else {
            net.s_addr = route->net_addr;
            snprintf(cmd, sizeof(cmd), "route add -net %s/%d -interface %s",
                     inet_ntoa(net), route->net_bitlen, eee->device.dev_name);
            run_route_cmd(cmd);
        }
    }

    return 0;
}

#endif /* __APPLE__ */
