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


#ifdef __linux__  /* currently, Linux only */


#include <net/route.h>


#define WITH_ADDRESS            1
#define CORRECT_TAG             2

#define SOCKET_TIMEOUT          2
#define GATEWAY_INTERVAL        5
#define INFO_INTERVAL           5
#define REFRESH_INTERVAL       10
#define PURGE_INTERVAL         30
#define REMOVE_ROUTE_AGE       75

#define LOWER_HALF             "0.0.0.0"
#define UPPER_HALF             "128.0.0.0"
#define MASK_HALF              "128.0.0.0"       /* <ip address>/1  */
#define HOST_MASK              "255.255.255.255" /* <ip address>/32 */
#define ROUTE_ADD              0
#define ROUTE_DEL              1
#define NO_DETECT              0
#define AUTO_DETECT            1


typedef struct n2n_route {
    struct in_addr    net_addr;           /* network address to be routed, also key for hash table*/
    struct in_addr    net_mask;           /* network address mask */
    struct in_addr    gateway;            /* gateway address */

    uint8_t           purgeable;          /* unpurgeable user-supplied or new default route */
    time_t            last_seen;          /* last seen at management port output */

    UT_hash_handle    hh;                 /* makes this structure hashable */
} n2n_route_t;

typedef struct n2n_route_conf {
    struct in_addr    gateway_vpn;        /* vpn gateway address */
    struct in_addr    gateway_org;        /* original default gateway used for peer/supernode traffic */
    uint8_t           gateway_detect;     /* have the gateway automatically detected */
    char*             password;           /* pointer to management port password */
    uint16_t          port;               /* management port */
    n2n_route_t       *routes;            /* list of routes */
} n2n_route_conf_t;


static int keep_running = 1;              /* for main loop, handled by signals */


// -------------------------------------------------------------------------------------------------------
// PLATFORM-DEPENDANT CODE


// taken from https://stackoverflow.com/questions/4159910/check-if-user-is-root-in-c
int is_privileged (void) {

    uid_t euid = geteuid();

    return euid == 0;
}


// -------------------------------------------------------------------------------------------------------
// PLATFORM-DEPENDANT CODE


void set_term_handler(const void *handler) {

#ifdef __linux__
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, handler);
    signal(SIGINT, handler);
#endif
#ifdef WIN32 /* the beginning of Windows support ...? */
    SetConsoleCtrlHandler(handler, TRUE);
#endif
}


#ifdef WIN32 /* the beginning of Windows support ...? */
BOOL WINAPI term_handler (DWORD sig) {
#else
static void term_handler (int sig) {
#endif

    static int called = 0;

    if(called) {
        traceEvent(TRACE_NORMAL, "ok, leaving now");
        _exit(0);
    } else {
        traceEvent(TRACE_NORMAL, "shutting down...");
        called = 1;
    }

    keep_running = 0;
#ifdef WIN32 /* the beginning of Windows support ...? */
    return TRUE;
#endif
}


// -------------------------------------------------------------------------------------------------------
// PLATFORM-DEPENDANT CODE


// taken from https://gist.github.com/javiermon/6272065
// with modifications
// originally licensed under GPLV2, Apache, and/or MIT

#define RTLINK_BUFFER_SIZE 8192

int find_default_gateway (struct in_addr *gateway_addr, struct in_addr *exclude) {

    int     ret = 0;
    int     received_bytes = 0, msg_len = 0, route_attribute_len = 0;
    SOCKET  sock = -1;
    int     msgseq = 0;
    struct  nlmsghdr *nlh, *nlmsg;
    struct  rtmsg *route_entry;
    struct  rtattr *route_attribute; /* this contains route attributes (route type) */
    ipstr_t gateway_address;
    devstr_t interface;
    char    msgbuf[RTLINK_BUFFER_SIZE], buffer[RTLINK_BUFFER_SIZE];
    char    *ptr = buffer;
    struct timeval tv;

    if((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
        traceEvent(TRACE_WARNING, "error from socket() while determining gateway");
        // return immediately
        return EXIT_FAILURE;
    }

    memset(msgbuf, 0, sizeof(msgbuf));
    memset(buffer, 0, sizeof(buffer));
    memset(gateway_address, 0, sizeof(gateway_address));
    memset(interface, 0, sizeof(interface));

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
        ret = EXIT_FAILURE;
        goto find_default_gateway_end;
    }

    // receive response
    do {
        received_bytes = recv(sock, ptr, sizeof(buffer) - msg_len, 0);
        if(received_bytes < 0) {
            traceEvent(TRACE_WARNING, "error from recv() while determining gateway");
            ret = EXIT_FAILURE;
            goto find_default_gateway_end;
        }

        nlh = (struct nlmsghdr *) ptr;

        // check if the header is valid
        if((NLMSG_OK(nlmsg, received_bytes) == 0) ||
           (nlmsg->nlmsg_type == NLMSG_ERROR)) {
            traceEvent(TRACE_WARNING, "error in received packet while determining gateway");
            ret = EXIT_FAILURE;
            goto find_default_gateway_end;
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

        gateway_address[0] = '\0';
        interface[0] = '\0';
        // loop through all attributes
        for( ; RTA_OK(route_attribute, route_attribute_len);
               route_attribute = RTA_NEXT(route_attribute, route_attribute_len)) {
            switch(route_attribute->rta_type) {
                case RTA_OIF:
                    // for informational purposes only
                    if_indextoname(*(int*)RTA_DATA(route_attribute), interface);
                    break;
                case RTA_GATEWAY:
                    inaddrtoa(gateway_address, *(struct in_addr*)RTA_DATA(route_attribute));
                    break;
                default:
                    break;
            }
        }

        if((*gateway_address) && (*interface)) {
            // REVISIT: inet_ntop followed by inet_pton... maybe not too elegant
            if(inet_pton(AF_INET, gateway_address, gateway_addr)) {
                // do not use the one to be excluded
                if(!memcmp(gateway_addr, exclude, sizeof(*gateway_addr)))
                    continue;
                traceEvent(TRACE_DEBUG, "assuming default gateway %s on interface %s",
                                        gateway_address, interface);
                break;
            }
        }

    }

find_default_gateway_end:

    closesocket(sock);
    return ret;
}


// -------------------------------------------------------------------------------------------------------
// PLATFORM-DEPENDANT CODE


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
        traceEvent(TRACE_WARNING, "error '%s' while %s route to %s/%u via %s",
                                  strerror(errno),
                                  !verb ? "adding" : "deleting",
                                  inaddrtoa(dst_ip_str, dst->sin_addr),
                                  bitlen,
                                  inaddrtoa(gateway_ip_str, gateway->sin_addr));
    } else {
        traceEvent(TRACE_INFO, "%s route to %s/%u via %s",
                               !verb ? "added" : "deleted",
                               inaddrtoa(dst_ip_str, dst->sin_addr),
                               bitlen,
                               inaddrtoa(gateway_ip_str, gateway->sin_addr));
    }

    closesocket(sock);
}


// -------------------------------------------------------------------------------------------------------


void fill_route (n2n_route_t* route, struct in_addr net_addr, struct in_addr net_mask, struct in_addr gateway) {

    route->net_addr = net_addr;
    route->net_mask = net_mask;
    route->gateway = gateway;
}


// applies inet_pton on input string and returns address struct-in_addr-typed address
struct in_addr inet_address (char* in) {

    struct in_addr out;

    if(inet_pton(AF_INET, in, &out) <= 0) {
        out.s_addr = INADDR_NONE;
    }

    return out;
}


int inet_address_valid (struct in_addr in) {

    if(in.s_addr == INADDR_NONE)
        return 0;
    else
        return 1;
}


int same_subnet (struct in_addr addr0, struct in_addr addr1, struct in_addr subnet) {

    return (addr0.s_addr & subnet.s_addr) == (addr1.s_addr & subnet.s_addr);
}


// -------------------------------------------------------------------------------------------------------


SOCKET connect_to_management_port (n2n_route_conf_t *rrr) {

    SOCKET ret;
    struct sockaddr_in sock_addr;

    ret = socket (PF_INET, SOCK_DGRAM, 0);
    if((int)ret < 0)
        return -1;

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sock_addr.sin_port = htons(rrr->port);
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


static void help (int level) {

    if(level == 0) return; /* no help required */

    printf("  n2n-route [-t <manangement_port>] [-p <management_port_password>] [-v] [-V]"
         "\n            [-g <default gateway>] [-n <network address>/bitlen] <vpn gateway>"
        "\n"
        "\n           This tool sets new routes for all the traffic to be routed via the"
        "\n           <vpn gateway> and polls the management port of a local n2n edge for"
        "\n           it can add routes to supernodes and peers via the original default"
        "\n           gateway. Adapt port (default: %d) and password (default: '%s')"
        "\n           to match your edge's configuration."
      "\n\n           If no <default gateway> provided, the tool will try to auto-detect."
      "\n\n           To not route all traffic through vpn, inidicate the networks to be"
        "\n           routed with '-n' option and use as many as required."
      "\n\n           Verbosity can be increased or decreased with -v or -V , repeat as"
        "\n           as needed."
      "\n\n           Run with sufficient rights to let the tool add and delete routes."
      "\n\n",
           N2N_EDGE_MGMT_PORT, N2N_MGMT_PASSWORD);

    exit(0);
}


static int set_option (n2n_route_conf_t *rrr, int optkey, char *optargument) {

    switch(optkey) {
        case 't': /* management port */ {
            uint16_t port = atoi(optargument);
            if(port) {
                rrr->port = port;
            } else {
                traceEvent(TRACE_WARNING, "invalid management port provided with '-t'");
            }
            break;
        }

        case 'p': /* management port password string */ {
            rrr->password = optargument;
            break;
        }

        case 'g': /* user-provided original default route */ {
            rrr->gateway_org = inet_address(optargument);
            if(inet_address_valid(rrr->gateway_org)) {
                rrr->gateway_detect = NO_DETECT;
            } else {
                traceEvent(TRACE_WARNING, "invalid original default gateway provided with '-g'");
            }
            break;
        }

        case 'n': /* user-provided network to be routed */ {
            char cidr_net[64], bitlen;
            n2n_route_t *route;
            struct in_addr mask;

            if(sscanf(optargument, "%63[^/]/%hhd", cidr_net, &bitlen) != 2) {
                traceEvent(TRACE_WARNING, "bad cidr network format '%d'", optargument);
                return 1;
            }
            if((bitlen < 0) || (bitlen > 32)) {
                traceEvent(TRACE_WARNING, "bad prefix '%d' in '%s'", bitlen, optargument);
                return 1;
            }
            if(!inet_address_valid(inet_address(cidr_net))) {
                traceEvent(TRACE_WARNING, "bad network '%s' in '%s'", cidr_net, optargument);
                return 1;
            }

            traceEvent(TRACE_NORMAL, "routing %s/%d", cidr_net, bitlen);

            route = calloc(1, sizeof(*route));
            if(route) {
                mask.s_addr = htonl(bitlen2mask(bitlen));
                // gateway is unknown at this point, will be rectified later
                fill_route(route, inet_address(cidr_net), mask, inet_address(""));
                HASH_ADD(hh, rrr->routes, net_addr, sizeof(route->net_addr), route);
                // will be added to system table later
            }
            break;
        }

        case 'v': /* more verbose */ {
            setTraceLevel(getTraceLevel() + 1);
            break;
        }

        case 'V': /* less verbose */ {
            setTraceLevel(getTraceLevel() - 1);
            break;
        }

        default: /* unknown option */ {
            return 1; /* for help */
        }
    }

   return 0;
}


// -------------------------------------------------------------------------------------------------------


int main (int argc, char* argv[]) {

    n2n_route_conf_t rrr;
    uint8_t c;
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
    struct in_addr addr, edge, edge_netmask, addr_tmp;
    ipstr_t ip_str;
    n2n_route_t *route, *tmp_route;

    // version
    print_n2n_version();

    // handle signals to properly end the tool
    set_term_handler(term_handler);

    // init data structure
    rrr.gateway_vpn = inet_address("");
    rrr.gateway_org = inet_address("");
    rrr.gateway_detect = AUTO_DETECT;
    rrr.password = N2N_MGMT_PASSWORD;
    rrr.port = N2N_EDGE_MGMT_PORT;
    rrr.routes = NULL;
    setTraceLevel(2); /* NORMAL, should already be default */
    n2n_srand(n2n_seed());

    // get command line options and eventually overwrite initialized conf
    while((c = getopt_long(argc, argv, "t:p:g:n:vV", NULL, NULL)) != '?') {
        if(c == 255) break;
        help(set_option(&rrr, c, optarg));
    }

    // get mandatory vpn gateway from command line and ...
    if(argv[optind]) {
        rrr.gateway_vpn = inet_address(argv[optind]);
    }
    // ... output help if invalid
    help(!inet_address_valid(rrr.gateway_vpn));
    traceEvent(TRACE_NORMAL, "using vpn gateway %s", inaddrtoa(ip_str, rrr.gateway_vpn));

    // verify conf and react with output to conf-related changes
    if(rrr.gateway_detect == NO_DETECT) {
        traceEvent(TRACE_NORMAL, "using default gateway %s", inaddrtoa(ip_str, rrr.gateway_org));
    }
    // if nothing else set, set new default route
    if(!rrr.routes) {
        route = calloc(1, sizeof(n2n_route_t));
        if(route) {
            traceEvent(TRACE_NORMAL, "routing 0.0.0.1/1");
            fill_route(route, inet_address(LOWER_HALF), inet_address(MASK_HALF), rrr.gateway_vpn);
            HASH_ADD(hh, rrr.routes, net_addr, sizeof(route->net_addr), route);
        }
        route = calloc(1, sizeof(n2n_route_t));
        if(route) {
            traceEvent(TRACE_NORMAL, "routing 128.0.0.1/1");
            fill_route(route, inet_address(UPPER_HALF), inet_address(MASK_HALF), rrr.gateway_vpn);
            HASH_ADD(hh, rrr.routes, net_addr, sizeof(route->net_addr), route);
        }
    }
    // set gateway for all so far present routes as '-n'-provided do not have it yet,
    // make them UNPURGEABLE and add them to system table
    HASH_ITER(hh, rrr.routes, route, tmp_route) {
        route->gateway = rrr.gateway_vpn;
        route->purgeable = UNPURGEABLE;
        handle_route(route, ROUTE_ADD);
    }

    // additional checks
    // check for sufficient rights for adding/deleting routes
    if(!is_privileged()) {
        traceEvent(TRACE_WARNING, "did not detect sufficient privileges to exercise route control");
    }
    // REVISIT: can we check if forwarding is enabled and, if not so,  warn the user?

    // connect to mamagement port
    traceEvent(TRACE_NORMAL, "connecting to edge management port %d", rrr.port);
    sock = connect_to_management_port(&rrr);
    if(sock == -1) {
        traceEvent(TRACE_ERROR, "unable to open socket for management port connection");
        goto end_route_tool;
    }

    // output status
    traceEvent(TRACE_NORMAL, "press ENTER to end the program");

reset_main_loop:

    wait_time.tv_sec = SOCKET_TIMEOUT;
    wait_time.tv_usec = 0;
    edge = inet_address("");
    edge_netmask = inet_address("");
    addr_tmp = inet_address("");
    tag_info = 0;
    tag_route_ip = 0;

    // main loop
    // read answer packet by packet which are only accepted if a corresponding request was sent before
    // of which we know about by having set the related tag, tag_info or tag_route_ip resp.
    // a valid edge ip address indicates that we have seen a valid answer to the info request
    while(keep_running && !kbhit()) {
        // current time
        now = time(NULL);

        // in case of AUTO_DETECT, check for (changed) default gateway from time to time (and initially)
        if((rrr.gateway_detect == AUTO_DETECT) && (now > last_gateway_check + GATEWAY_INTERVAL)) {
            // determine the original default gateway excluding the VPN gateway from search
            find_default_gateway(&addr_tmp, &rrr.gateway_vpn);
            if(memcmp(&addr_tmp, &rrr.gateway_org, sizeof(rrr.gateway_org))) {
                // store the detected change
                rrr.gateway_org = addr_tmp;
                // delete all purgeable routes as they are still relying on old original default gateway
                HASH_ITER(hh, rrr.routes, route, tmp_route) {
                    if((route->purgeable == PURGEABLE)) {
                        handle_route(route, ROUTE_DEL);
                        HASH_DEL(rrr.routes, route);
                        free(route);
                    }
                }
                // give way for new info and read requests
                last_info_req = 0;
                last_read_req = 0;

                traceEvent(TRACE_NORMAL, "using default gateway %s", inaddrtoa(ip_str, rrr.gateway_org));
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
            if(inet_address_valid(edge)) {

                // REVISIT: send unsubscribe request to management port if required to re-subscribe

                // send subscribe request to management port, generate fresh tag
                while(!(tag_route_ip = ((uint32_t)n2n_rand()) >> 23)); /* >> 23: tags too long can crash the mgmt */
                msg_len = 0;
                msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "s %u:1:%s peer\n", tag_route_ip, rrr.password);
                // REVISIT:  something smashes the edge when sending subscritpion request or when edge sends event
                //           so, the subscription request is not sent yet
                // ret = send(sock, udp_buf, msg_len, 0);

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
            HASH_ITER(hh, rrr.routes, route, tmp_route) {
                if((route->purgeable == PURGEABLE) && (now > route->last_seen + REMOVE_ROUTE_AGE)) {
                    handle_route(route, ROUTE_DEL);
                    HASH_DEL(rrr.routes, route);
                    free(route);
                }
            }
        }

        // REVISIT: check all routes from rrr.routes for still being in system table from time to time?
        //          or even apply some rtlink magic to get notified on route changes?

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
                    // make sure it is a string and replace all newlines with spaces
                    udp_buf[msg_len] = '\0';
                    for (char *p = udp_buf; (p = strchr(p, '\n')) != NULL; p++) *p = ' ';
                    traceEvent(TRACE_DEBUG, "received '%s' from management port", udp_buf);

                    // handle the answer, json needs to be freed later
                    json = json_parse(udp_buf);

                    // look for local edge information
                    if(tag_info) {
                        // local IP address (for information)
                        ret = get_addr_from_json(&addr, json, "ip4addr", tag_info, 0);
                        if(ret == (WITH_ADDRESS | CORRECT_TAG)) {
                            traceEvent(TRACE_DEBUG, "received information about %s being edge's IP address", inaddrtoa(ip_str, addr));
                            if(memcmp(&edge, &addr, sizeof(edge))) {
                                edge = addr;
                                traceEvent(TRACE_NORMAL, "found %s being edge's IP address", inaddrtoa(ip_str, addr));
                            }
                        }
                        // local netmask
                        ret = get_addr_from_json(&addr, json, "ip4netmask", tag_info, 0);
                        if(ret == (WITH_ADDRESS | CORRECT_TAG)) {
                            traceEvent(TRACE_DEBUG, "received information about %s being edge's IP netmask", inaddrtoa(ip_str, addr));
                            if(memcmp(&edge_netmask, &addr, sizeof(edge_netmask))) {
                                edge_netmask = addr;
                                traceEvent(TRACE_NORMAL, "found %s being edge's IP netmask", inaddrtoa(ip_str, addr));
                                // check if vpn gateway matches edge information and warn user if not so
                                if(!same_subnet(edge, rrr.gateway_vpn, edge_netmask)) {
                                    traceEvent(TRACE_WARNING, "vpn gateway and edge do not share the same subnet");
                                }
                            }
                        }
                    }

                    // look for edge/supernode ip addresses
                    if(tag_route_ip) {
                        ret = get_addr_from_json(&addr, json, "sockaddr", tag_route_ip, 0);
                        if(ret == (WITH_ADDRESS | CORRECT_TAG)) {
                            // add to hash list if required
                            traceEvent(TRACE_DEBUG, "received information about %s to be routed via default gateway", inaddrtoa(ip_str, addr));
                            HASH_FIND(hh, rrr.routes, &addr, sizeof(route->net_addr), route);
                            if(!route)
                                route = calloc(1, sizeof(n2n_route_t));
                            else
                               HASH_DEL(rrr.routes, route);
                            if(route) {
                                fill_route(route, addr, inet_address(HOST_MASK), rrr.gateway_org);
                                route->purgeable = PURGEABLE;
                                if(!(route->last_seen)) {
                                    handle_route(route, ROUTE_ADD);
                                }
                                route->last_seen = now;
                                HASH_ADD(hh, rrr.routes, net_addr, sizeof(route->net_addr), route);
                            }
                        }
                    }

                    // no need for current json object anymore
                    json_free(json);
                }
            } else {
                // can this happen? reset the loop
                traceEvent(TRACE_ERROR, "loop reset");
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

    // REVISIT: send unsubscribe request to management port if required

end_route_tool:

    // delete all routes
    HASH_ITER(hh, rrr.routes, route, tmp_route) {
        handle_route(route, ROUTE_DEL);
        HASH_DEL(rrr.routes, route);
        free(route);
    }
    // close connection
    closesocket(sock);

    return 0;
}


#else  /* ifdef __linux__  --  currently, Linux only */


int main (int argc, char* argv[]) {

    traceEvent(TRACE_WARNING, "currently, only Linux is supported");
    traceEvent(TRACE_WARNING, "if you want to port to other OS, please find the source code having clearly marked the platform-dependant portions");

    return 0;
}


#endif /* ifdef __linux__  --  currently, Linux only */
