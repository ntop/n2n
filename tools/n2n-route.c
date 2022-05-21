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

#ifdef __linux__  /* currently, Linux only !!! */


#include <net/route.h>


#define WITH_ADDRESS            1
#define CORRECT_TAG             2

#define SOCKET_TIMEOUT          2
#define GATEWAY_INTERVAL        5
#define INFO_INTERVAL           5
#define REFRESH_INTERVAL       10
#define PURGE_INTERVAL         30
#define REMOVE_ROUTE_AGE       75

#define HOST_MASK              "255.255.255.255" /* <ip address>/32 */
#define ROUTE_ADD              0
#define ROUTE_DEL              1


#define NEW_GATEWAY "10.1.1.1"            /* !!! Logan's test enviornment */

typedef struct n2n_route {
    struct in_addr    net_addr;           /* network address to be routed, also key for hash table*/
    struct in_addr    net_mask;           /* network address mask */
    struct in_addr    gateway;            /* gateway address */

    uint8_t           purgeable;          /* unpurgeable user-supplied or new default route */
    time_t            last_seen;          /* last seen at management port output */

    UT_hash_handle    hh;                 /* makes this structure hashable */
} n2n_route_t;


static int keep_running = 1;              /* for main loop, handled by signals */



// -------------------------------------------------------------------------------------------------------


// taken from https://gist.github.com/javiermon/6272065
// with modifications, originally licensed under GPLV2, Apache, and MIT

#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>

#define BUFFER_SIZE 4096


int get_gateway_and_iface (struct in_addr *gateway_addr) {

    int     received_bytes = 0, msg_len = 0, route_attribute_len = 0;
    SOCKET  sock = -1;
    int     msgseq = 0;
    struct  nlmsghdr *nlh, *nlmsg;
    struct  rtmsg *route_entry;
    struct  rtattr *route_attribute; /* this contains route attributes (route type) */
    ipstr_t gateway_address;
    devstr_t interface;
    char    msgbuf[BUFFER_SIZE], buffer[BUFFER_SIZE];
    char    *ptr = buffer;
    struct timeval tv;

    if((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
        traceEvent(TRACE_WARNING, "error from socket() while determining gateway");
        return EXIT_FAILURE;
    }

    memset(msgbuf, 0, sizeof(msgbuf));
    memset(gateway_address, 0, sizeof(gateway_address));
    memset(interface, 0, sizeof(interface));
    memset(buffer, 0, sizeof(buffer));

    // point the header and the msg structure pointers into the buffer
    nlmsg = (struct nlmsghdr*)msgbuf;

    // fill in the nlmsg header
    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlmsg->nlmsg_type = RTM_GETROUTE; /* get the routes from kernel routing table */
    nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; /* the message is a request for dump */
    nlmsg->nlmsg_seq = msgseq++; /* sequence of the message packet */
    nlmsg->nlmsg_pid = getpid(); /* PID of process sending the request */

    // 1 sec timeout to avoid stall
    tv.tv_sec = 1;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));

    // send msg
    if (send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
        traceEvent(TRACE_WARNING, "error from send() while determining gateway");
        return EXIT_FAILURE;
    }

    // receive response
    do {
        received_bytes = recv(sock, ptr, sizeof(buffer) - msg_len, 0);
        if(received_bytes < 0) {
            traceEvent(TRACE_WARNING, "error from recv() while determining gateway");
            return EXIT_FAILURE;
        }

        nlh = (struct nlmsghdr *) ptr;

        // check if the header is valid
        if((NLMSG_OK(nlmsg, received_bytes) == 0) ||
           (nlmsg->nlmsg_type == NLMSG_ERROR)) {
            traceEvent(TRACE_WARNING, "error in received paket while determining gateway");
            return EXIT_FAILURE;
        }

        // if we received all data break
        if(nlh->nlmsg_type == NLMSG_DONE) {
            break;
        } else {
            ptr += received_bytes;
            msg_len += received_bytes;
        }

        // break if its not a multi part message
        if((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
            break;
    } while((nlmsg->nlmsg_seq != msgseq) || (nlmsg->nlmsg_pid != getpid()));

    // parse response
    for ( ; NLMSG_OK(nlh, received_bytes); nlh = NLMSG_NEXT(nlh, received_bytes)) {
        // get the route data
        route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

        // we are just interested in main routing table
        if (route_entry->rtm_table != RT_TABLE_MAIN)
            continue;

        route_attribute = (struct rtattr*)RTM_RTA(route_entry);
        route_attribute_len = RTM_PAYLOAD(nlh);

        // loop through all attributes
        for( ; RTA_OK(route_attribute, route_attribute_len);
               route_attribute = RTA_NEXT(route_attribute, route_attribute_len)) {
            switch(route_attribute->rta_type) {
                case RTA_OIF:
                    if_indextoname(*(int*)RTA_DATA(route_attribute), interface);
                    break;
                case RTA_GATEWAY:
                    inet_ntop(AF_INET, RTA_DATA(route_attribute),
                              gateway_address, sizeof(gateway_address));
                    break;
                default:
                    break;
            }
        }

        if((*gateway_address) && (*interface)) {
            // REVISIT: inet_ntop followed by inet_pton... maybe not too elegant
            if(inet_pton(AF_INET, gateway_address, gateway_addr)) {
                traceEvent(TRACE_DEBUG, "found default gateway %s on interface %s\n", gateway_address, interface);
               break;
            }
        }
    }
    closesocket(sock);

    return 0;
}


// -------------------------------------------------------------------------------------------------------


// applies inet_pton on input string and returns address struct-in_addr-typed address
struct in_addr inet_address (char* in) {

    struct in_addr out;

    if(inet_pton(AF_INET, in, &out) <= 0) {
        out.s_addr = INADDR_NONE;
    }

    return out;
}


// -------------------------------------------------------------------------------------------------------


void fill_route (n2n_route_t* route, struct in_addr net_addr, struct in_addr net_mask, struct in_addr gateway) {

    route->net_addr = net_addr;
    route->net_mask = net_mask;
    route->gateway = gateway;
}


/* adds (verb == ROUTE_ADD) or deletes (verb == ROUTE_DEL) a route */
void handle_route (n2n_route_t* in_route, int verb) {

    struct sockaddr_in *addr_tmp;
    struct rtentry route;
    SOCKET sock;
    struct sockaddr_in *dst, *mask, *gateway;
    ipstr_t dst_ip_str, gateway_ip_str;
    in_addr_t mask_addr;
    int bitlen = 0;

    // prepare rtentry-typed route entry
    memset(&route, 0, sizeof(route));
    addr_tmp = (struct sockaddr_in*)&route.rt_dst;
    addr_tmp->sin_family = AF_INET;
    addr_tmp->sin_addr.s_addr = in_route->net_addr.s_addr;
    addr_tmp = (struct sockaddr_in*)&route.rt_genmask;
    addr_tmp->sin_family = AF_INET;
    addr_tmp->sin_addr.s_addr = in_route->net_mask.s_addr;
    addr_tmp = (struct sockaddr_in*)&route.rt_gateway;
    addr_tmp->sin_family = AF_INET;
    addr_tmp->sin_addr.s_addr = in_route->gateway.s_addr;
    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_metric = 0;

    // open a socket
    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    // prepare route data for eventual text output
    dst = (struct sockaddr_in*)&route.rt_dst;
    mask = (struct sockaddr_in*)&route.rt_genmask;
    mask_addr = ntohl(mask->sin_addr.s_addr);
    for(bitlen = 0; (int)mask_addr < 0; mask_addr <<= 1)
        bitlen++;
    gateway = (struct sockaddr_in*)&route.rt_gateway;

    // try to set route through ioctl
    if(ioctl(sock, verb == ROUTE_ADD ? SIOCADDRT : SIOCDELRT, &route) < 0) {
        traceEvent(TRACE_WARNING, "error '%s' while %s route for %s/%u via %s",
                                  strerror(errno),
                                  !verb ? "adding" : "deleting",
                                  inaddrtoa(dst_ip_str, dst->sin_addr),
                                  bitlen,
                                  inaddrtoa(gateway_ip_str, gateway->sin_addr));
    } else {
        traceEvent(TRACE_NORMAL, "%s route for %s/%u via %s",
                                 !verb ? "added" : "deleted",
                                 inaddrtoa(dst_ip_str, dst->sin_addr),
                                 bitlen,
                                 inaddrtoa(gateway_ip_str, gateway->sin_addr));
    }

    closesocket(sock);
}


// -------------------------------------------------------------------------------------------------------


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


// -------------------------------------------------------------------------------------------------------


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
                *addr = inet_address(json->pairs[i].value->string_value);
                flags |= WITH_ADDRESS;
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


// -------------------------------------------------------------------------------------------------------


#if defined(__linux__) || defined(WIN32)
#ifdef WIN32
BOOL WINAPI term_handler(DWORD sig)
#else
    static void term_handler(int sig)
#endif
{
    static int called = 0;

    if(called) {
        traceEvent(TRACE_NORMAL, "ok, I am leaving now");
        _exit(0);
    } else {
        traceEvent(TRACE_NORMAL, "shutting down...");
        called = 1;
    }

    keep_running = 0;
#ifdef WIN32
    return(TRUE);
#endif
}
#endif /* defined(__linux__) || defined(WIN32) */


// -------------------------------------------------------------------------------------------------------


// taken from https://web.archive.org/web/20170407122137/http://cc.byexamples.com/2007/04/08/non-blocking-user-input-in-loop-without-ncurses/
int kbhit () {

    struct timeval tv;
    fd_set fds;

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds); //STDIN_FILENO is 0
    select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);

    return FD_ISSET(STDIN_FILENO, &fds);
}


// -------------------------------------------------------------------------------------------------------


int main (int argc, char* argv[]) {

    SOCKET sock;
    size_t msg_len;
    char udp_buf[N2N_PKT_BUF_SIZE];
    fd_set socket_mask;
    struct timeval wait_time;
    time_t now = 0;
    time_t last_gateway_check = 0;
    time_t last_info_req = 0;
    time_t last_read_req = 0;
    time_t last_purge = 0;
    json_object_t *json;
    int ret;
    int tag_info, tag_route_ip;
    struct in_addr addr, edge, gateway_org, gateway_vpn, addr_tmp;
    ipstr_t ip_str;

    n2n_route_t *routes = NULL;
    n2n_route_t *route, *tmp_route;


    n2n_srand(n2n_seed());

    // !!! can we check if forwarding is enabled and, if not so,  warn the user?

    // handle signals to properly end the tool
#ifdef __linux__
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, term_handler);
    signal(SIGINT, term_handler);
#endif
#ifdef WIN32
    SetConsoleCtrlHandler(term_handler, TRUE);
#endif

// !!! evaluate some cli parameters, e.g. for port, password, additional manual routes for dns or so, gateway to use
// -t management port
// -p port
// -r route
// -g regular gateway
//    new gateway (some n2n node)

    // set new default route
    route = calloc(1, sizeof(n2n_route_t));
    gateway_vpn = inet_address(NEW_GATEWAY);
    if(route) {
        fill_route(route, inet_address("0.0.0.0"), inet_address("128.0.0.0"), gateway_vpn);
        route->purgeable = UNPURGEABLE;
        HASH_ADD(hh, routes, net_addr, sizeof(struct in_addr), route);
        handle_route(route, ROUTE_ADD);
    }
    route = calloc(1, sizeof(n2n_route_t));
    if(route) {
        fill_route(route, inet_address("128.0.0.0"), inet_address("128.0.0.0"), gateway_vpn);
        route->purgeable = UNPURGEABLE;
        HASH_ADD(hh, routes, net_addr, sizeof(route->net_addr), route);
        handle_route(route, ROUTE_ADD);
    }

    sock = connect_to_management_port();
    if(sock == -1)
        goto end_route_tool;

reset_main_loop:
    wait_time.tv_sec = SOCKET_TIMEOUT;
    wait_time.tv_usec = 0;
    edge.s_addr = INADDR_NONE;
    addr_tmp.s_addr = INADDR_NONE;
    gateway_org.s_addr = INADDR_NONE;
    tag_info = 0;
    tag_route_ip = 0;


    // main loop
    // read answer packet by packet which are only accepted if a corresponding request was sent before
    // of which we know about by having set the related tag, tag_info or tag_route_ip resp.
    // a valid edge ip address indicates that we have seen a valid answer to the info request
    while(keep_running && !kbhit()) {
        // current time
        now = time(NULL);

        // check for (changed) default gateway from time to time (and initially)
        if(now > last_gateway_check + GATEWAY_INTERVAL) {
            // determine the original default gateway
            get_gateway_and_iface(&addr_tmp);
            if(memcmp(&addr_tmp, &gateway_org, sizeof(gateway_org))) {
                // store the detected change
                gateway_org = addr_tmp;
                // delete all purgeable routes as they are still relying on old original default gateway
                HASH_ITER(hh, routes, route, tmp_route) {
                    if((route->purgeable == PURGEABLE)) {
                        handle_route(route, ROUTE_DEL);
                        HASH_DEL(routes, route);
                        free(route);
                    }
                }
                // give way for new info and read requests
                last_info_req = 0;
                last_read_req = 0;

                traceEvent(TRACE_NORMAL, "using default gateway %s\n",  inaddrtoa(ip_str, gateway_org));
            }
            last_gateway_check = now;
        }

        // check if we need to send info request again
        if(now > last_info_req + INFO_INTERVAL) {
            // send info read request
            while(!(tag_info = ((uint32_t)n2n_rand()) >> 23));
            msg_len = 0;
            msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                 "r %u info\n", tag_info);
            ret = send(sock, udp_buf, msg_len, 0);
            last_info_req = now;
        }

        // check if we need to send read request again
        if(now > last_read_req + REFRESH_INTERVAL) {
            // the following requests shall only be sent if we have a valid local edge ip address,
            // i.e. a valid answer to the info request
            if(edge.s_addr != INADDR_NONE) {

                // !!! send unsubscribe request to management port if required to re-subscribe

                // send subscribe request to management port, generate fresh tag
                while(!(tag_route_ip = ((uint32_t)n2n_rand()) >> 23)); /* >> 23: tags too long can crash the mgmt */
                msg_len = 0;
                msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "s %u:1:%s peer\n", tag_route_ip, N2N_MGMT_PASSWORD);
                // !!! something smashes the edge when sending subscritpion request or when edge sends event
                // !!! ret = send(sock, udp_buf, msg_len, 0);

                // send read requests to management port with same tag
                msg_len = 0;
                msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "r %u edges\n", tag_route_ip);
                ret = send(sock, udp_buf, msg_len, 0);
                msg_len = 0;
                msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "r %u supernodes\n", tag_route_ip);
                ret = send(sock, udp_buf, msg_len, 0);

                last_read_req = now;
            }
        }

        // purge the routes from time to time
        if(now > last_purge + PURGE_INTERVAL) {
            last_purge = now;
            HASH_ITER(hh, routes, route, tmp_route) {
                if((route->purgeable == PURGEABLE) && (now > route->last_seen + REMOVE_ROUTE_AGE)) {
                    handle_route(route, ROUTE_DEL);
                    HASH_DEL(routes, route);
                    free(route);
                }
            }
        }

        // wait for any answer to info or read request
        FD_ZERO(&socket_mask);
        FD_SET(sock, &socket_mask);
        ret = select(sock + 1, &socket_mask, NULL, NULL, &wait_time);

        // refresh current time after having waited
        now = time(NULL);

        if(ret > 0) {
            if(FD_ISSET(sock, &socket_mask)) {
                msg_len = recv(sock, udp_buf, sizeof(udp_buf), 0);
                if((msg_len > 0) && (msg_len < sizeof(udp_buf))) {
                    // make sure it is a string
                    udp_buf[msg_len] = 0;
                    // handle the answer
                    json = json_parse(udp_buf);

                    // look for local edge information, especially edge's local ip address
                    if(tag_info) {
                        ret = get_addr_from_json(&addr, json, "ip4addr", tag_info, 0);
                        if(ret == (WITH_ADDRESS | CORRECT_TAG)) {
                            traceEvent(TRACE_DEBUG, "received information about %s being edge's IP address", inaddrtoa(ip_str, addr));
                            if(memcmp(&edge, &addr, sizeof(edge))) {
                                edge = addr;
                                // do we need it beyond output?
                                traceEvent(TRACE_NORMAL, "found %s being edge's IP address", inaddrtoa(ip_str, addr));
                            }
                        }
                    }

                    // look for edge/supernode ip addresses
                    if(tag_route_ip) {
                        ret = get_addr_from_json(&addr, json, "sockaddr", tag_route_ip, 0);
                        if(ret == (WITH_ADDRESS | CORRECT_TAG)) {
                            // add to hash list if required
                            traceEvent(TRACE_DEBUG, "received information about %s to be routed via default gateway", inaddrtoa(ip_str, addr));
                            HASH_FIND(hh, routes, &addr, sizeof(route->net_addr), route);
                            if(!route)
                                route = calloc(1, sizeof(n2n_route_t));
                            else
                               HASH_DEL(routes, route);
                            if(route) {
                                fill_route(route, addr, inet_address(HOST_MASK), gateway_org);
                                route->purgeable = PURGEABLE;
                                if(!(route->last_seen)) {
                                    handle_route(route, ROUTE_ADD);
                                }
                                route->last_seen = now;
                                HASH_ADD(hh, routes, net_addr, sizeof(route->net_addr), route);
                            }
                        }
                    }

                    // no need for current json object anymore
                    json_free(json);
                }
            } else {
                // can this happen? reset the loop
                goto reset_main_loop;
            }
        } else if(ret == 0) {
            // select() timeout
            // action required?
        } else {
            // select() error
            // action required?
        }

    }

    // !!! send unsubscribe request to management port if required

end_route_tool:

    // delete all routes
    HASH_ITER(hh, routes, route, tmp_route) {
        handle_route(route, ROUTE_DEL);
        HASH_DEL(routes, route);
        free(route);
    }
    // close connection
    closesocket(sock);

    return 0;
}



#else  /* ifdef __linux__  --  currently, Linux only !!! */


int main (int argc, char* argv[]) {

    traceEvent(TRACE_WARNING, "Currently, only Linux supported");

    return 0;
}


#endif /* ifdef __linux__  --  currently, Linux only !!! */
