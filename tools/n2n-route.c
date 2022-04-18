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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include "n2n.h"


#define WITH_ADDRESS            1
#define CORRECT_TAG             2

#define INFO_TIMEOUT            2
#define REFRESH_INTERVAL       10
#define PURGE_ROUTE_INTERVAL   30
#define REMOVE_ROUTE_AGE       75


typedef struct n2n_route {
    in_addr_t    net_addr;
    uint8_t      net_bitlen;
    in_addr_t    gateway;

    uint8_t      purgeable;            /* unpurgeable user-supplied route */
    time_t       last_seen;            /* last seen at management port output */
    UT_hash_handle hh;                 /* makes this structure hashable */
} n2n_route_t;


SOCKET connect_to_management_port (void) {

    SOCKET ret;
    struct sockaddr_in sock_addr;

    ret = socket (PF_INET, SOCK_DGRAM, 0);
    if((int)ret < 0)
        return -1;

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sock_addr.sin_port = htons(N2N_EDGE_MGMT_PORT);
    if(0 != connect(ret, (struct sockaddr *)&sock_addr, sizeof(sock_addr)))
        return -1;

    return ret;
}


int get_addr_from_json (struct in_addr *addr, json_object_t *json, char *key, int tag, int flags) {

    int i;
    char *colon = NULL;

    if(NULL == json)
        return 0;

    for(i = 0; i < json->count; i++) {
        if(json->pairs[i].type == JSON_STRING) {
            if(!strcmp(json->pairs[i].key, key)) {
                // cut off port from IP address
                if((colon = strchr(json->pairs[i].value->string_value, ':'))) {
                    *colon = '\0';
                }
                if(inet_pton(AF_INET, json->pairs[i].value->string_value, addr)) {
                    flags |= WITH_ADDRESS;
                }
            }
            if(!strcmp(json->pairs[i].key, "_tag" )) {
                if(atoi(json->pairs[i].value->string_value) == tag) {
                    flags |= CORRECT_TAG;
                }
            }
        } else if(json->pairs[i].type == JSON_OBJECT) {
            flags |= get_addr_from_json(addr, json, key, tag, flags);
        }
    }

    return flags;
}


int main (int argc, char* argv[]) {

    SOCKET sock;
    size_t msg_len;
    char udp_buf[N2N_PKT_BUF_SIZE];
    fd_set socket_mask;
    struct timeval wait_time;
    time_t now = 0;
    time_t last_purge = 0;
    json_object_t *json;
    int ret;
    int tag_info, tag_route_ip;
    struct in_addr addr, edge;
    n2n_route_t *routes = NULL;
    n2n_route_t *route, *tmp_route;


    n2n_srand(n2n_seed());

// !!! SIGINT to properly end the tool

// !!! evaluate some cli parameters, e.g. for port, password, additional manual routes for dns or so, gateway to use

// !!! determine the original default gateway

    sock = connect_to_management_port();
    if(sock == -1)
        goto end_route_tool;

reset_main_loop:
    wait_time.tv_sec = 0;
    wait_time.tv_usec = 0;
    edge.s_addr = 1; // !!! INADDR_NONE; // set to 1 for testing without info request
    tag_info = 0;
    tag_route_ip = 0;

    // main loop
    // read answer packet by packet which are only accepted if a corresponding request was sent before
    // of which we know about by having set the related tag, tag_info or tag_route_ip resp.
    // a valid edge ip address indicates that we have seen a valid answer to the info request
    while(1) {
        FD_ZERO(&socket_mask);
        FD_SET(sock, &socket_mask);
        ret = select(sock + 1, &socket_mask, NULL, NULL, &wait_time);
        now = time(NULL);
        if(ret > 0) {
            if(FD_ISSET(sock, &socket_mask)) {
                msg_len = recv(sock, udp_buf, sizeof(udp_buf), 0);
                if((msg_len > 0) && (msg_len < sizeof(udp_buf))) {
                    // make sure it is a string
                    udp_buf[msg_len] = 0;
                    // handle the answer
                    json = json_parse(udp_buf);

                    // look for edge/supernode ip addresses
                    if(tag_route_ip) {
                        ret = get_addr_from_json(&addr, json, "sockaddr", tag_route_ip, 0);
                        if(ret == (WITH_ADDRESS | CORRECT_TAG)) {
                            // add to hash list if required
                            printf("IP: %s\n", inet_ntoa(addr)); // !!!
                            HASH_FIND(hh, routes, &addr, sizeof(struct in_addr), route);
                            if(!route)
                                route = calloc(1, sizeof(n2n_route_t));
                            else
                               HASH_DEL(routes, route);
                            if(route) {
                                // !!! if we want to exec route command only for new routes, we need to do it here
                                // !!! if(!(route->last_seen)) ...
                                // !!! also make sure edge ip address is valid
                                route->net_addr = addr.s_addr;
                                route->net_bitlen = 32;
                                route->purgeable = PURGEABLE;
                                route->last_seen = now;
                                HASH_ADD(hh, routes, net_addr, sizeof(struct in_addr), route);
                                // !!! if we always want to exec route command (and leave doublet handling to OS),
                                // !!! we need to do it here
                            }
                        }
                    }

                    // look for local edge information, especially edge's local
                    // ip address for the new 'default' route
                    if(tag_info) {
                        ret = get_addr_from_json(&addr, json, "ip4addr", tag_info, 0);
                        if(ret == (WITH_ADDRESS | CORRECT_TAG)) {
                            edge = addr;
                        }
                    }

                    // no need for current json object anymore
                    json_free(json);
                }
            } else {
                // can this happen? reset the loop
                goto reset_main_loop;
            }
        } else {
            // select(): error or time out -- including the initial timeout

            // send info read request
            while(!(tag_info = ((uint32_t)n2n_rand()) >> 23));
            msg_len = 0;
            msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                "r %u info\n", tag_info);
            ret = send(sock, udp_buf, msg_len, 0);
            wait_time.tv_sec = INFO_TIMEOUT;

            // the following requests shall only be sent if we have a valid local edge ip address,
            // i.e. a valid answer to the info request
            if(edge.s_addr != INADDR_NONE) {
                // !!! send unsubscribe request to management port if required to re-subscribe
                while(!(tag_route_ip = ((uint32_t)n2n_rand()) >> 23));
                // send subscribe request to management port
                msg_len = 0;
                msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "s %u:1:%s peer\n", tag_route_ip, N2N_MGMT_PASSWORD);
                // !!! something smashes the edge when sending subscritpion request or when edge sends event
                // !!! ret = send(sock, udp_buf, msg_len, 0);

                // send read requests to management port
                msg_len = 0;
                msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "r %u edges\n", tag_route_ip);
                ret = send(sock, udp_buf, msg_len, 0);
                msg_len = 0;
                msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "r %u supernodes\n", tag_route_ip);
                ret = send(sock, udp_buf, msg_len, 0);
                wait_time.tv_sec = REFRESH_INTERVAL;
            }
        }

        // purge the routes from time to time
        if(now > last_purge + PURGE_ROUTE_INTERVAL) {
            last_purge = now;
            HASH_ITER(hh, routes, route, tmp_route) {
                if((route->purgeable == PURGEABLE) && (now > route->last_seen + REMOVE_ROUTE_AGE)) {
                    // !!! delete route command
                    HASH_DEL(routes, route);
                    free(route);
                }
            }
        }
    }

    // !!! send unsubscribe request to management port

end_route_tool:

    // delete all routes
    HASH_ITER(hh, routes, route, tmp_route) {
        // !!! delete route command
        HASH_DEL(routes, route);
        free(route);
    }
    // close connection
    closesocket(sock);

    return 0;
}
