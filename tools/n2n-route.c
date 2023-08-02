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


#include <errno.h>             // for errno
#include <getopt.h>            // for getopt_long, optind, optarg
#include <signal.h>            // for signal, SIGINT, SIGPIPE, SIGTERM, SIG_IGN
#include <stdbool.h>
#include <stdint.h>            // for uint8_t, uint16_t, uint32_t
#include <stdio.h>             // for snprintf, printf, sscanf
#include <stdlib.h>            // for calloc, free, atoi, EXIT_FAILURE, exit
#include <string.h>            // for memset, NULL, memcmp, strchr, strcmp
#include <sys/time.h>          // for timeval
#include <time.h>              // for time, time_t
#include <unistd.h>            // for getpid, STDIN_FILENO, _exit, geteuid
#include "json.h"              // for _jsonpair, json_object_t, _jsonvalue
#include "n2n.h"               // for inaddrtoa, traceEvent, TRACE_WARNING
#include "random_numbers.h"    // for n2n_rand, n2n_seed, n2n_srand
#include "uthash.h"            // for UT_hash_handle, HASH_ADD, HASH_DEL

#ifdef __linux__
#include <linux/netlink.h>     // for nlmsghdr, NLMSG_OK, NETLINK_ROUTE, NLM...
#include <linux/rtnetlink.h>   // for RTA_DATA, rtmsg, RTA_GATEWAY, RTA_NEXT
#endif

#ifdef _WIN32
#include <winsock.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>         // for inet_pton
#include <net/if.h>            // for if_indextoname
#include <net/route.h>         // for rtentry, RTF_GATEWAY, RTF_UP
#include <netinet/in.h>        // for in_addr, sockaddr_in, htonl, htons, ntohl
#include <sys/ioctl.h>         // for ioctl, SIOCADDRT, SIOCDELRT
#include <sys/select.h>        // for select, FD_ISSET, FD_SET, FD_ZERO, fd_set
#include <sys/socket.h>        // for send, socket, AF_INET, recv, connect
#endif

#if defined (__linux__) || defined(_WIN64)  /*  currently, Linux and Windows only */
/* Technically, this could be supported on some 32-bit windows.
 * The assumption here is that a version of Windows new enough to
 * support the features needed is probably running with 64-bit.
 *
 * The alternative is that people trying to run old games are probably on
 * Windows XP and are probably 32-bit.
 */


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

// REVISIT: may become obsolete
#ifdef _WIN32
#ifndef STDIN_FILENO
#define STDIN_FILENO            _fileno(stdin)
#endif
#endif


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


static bool keep_running = true;              /* for main loop, handled by signals */


// -------------------------------------------------------------------------------------------------------
// PLATFORM-DEPENDANT CODE


int is_privileged (void) {

#if defined(__linux__)
// taken from https://stackoverflow.com/questions/4159910/check-if-user-is-root-in-c
    uid_t euid = geteuid();

    return euid == 0;

#elif defined(_WIN32)
// taken from https://stackoverflow.com/a/10553065
        int result;
        DWORD rc;
        wchar_t user_name[256];
        USER_INFO_1 *info;
        DWORD size = sizeof(user_name);

        GetUserNameW(user_name, &size);
        rc = NetUserGetInfo(NULL, user_name, 1, (unsigned char**)&info);
        if (rc) {
                return 0;
        }
        result = (info->usri1_priv == USER_PRIV_ADMIN);
        NetApiBufferFree(info);

        return result;
#endif
}


// -------------------------------------------------------------------------------------------------------
// PLATFORM-DEPENDANT CODE


void set_term_handler(const void *handler) {

#if defined(__linux__)
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, handler);
    signal(SIGINT, handler);
#elif defined(_WIN32)
    SetConsoleCtrlHandler(handler, TRUE);
#endif
}


#ifndef _WIN32
static void term_handler (int sig) {
#else
BOOL WINAPI term_handler (DWORD sig) {
#endif

    static int called = 0;

    if(called) {
        traceEvent(TRACE_NORMAL, "ok, leaving now");
        _exit(0);
    } else {
        traceEvent(TRACE_NORMAL, "shutting down...");
        called = 1;
    }

    keep_running = false;
#ifdef _WIN32
    return TRUE;
#endif
}


// -------------------------------------------------------------------------------------------------------
// PLATFORM-DEPENDANT CODE



#define RTLINK_BUFFER_SIZE 8192

int find_default_gateway (struct in_addr *gateway_addr, struct in_addr *exclude) {

#if defined(__linux__)
    // taken from https://gist.github.com/javiermon/6272065
    // with modifications
    // originally licensed under GPLV2, Apache, and/or MIT

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

#elif defined(_WIN32)
    // taken from (and modified)
    // https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-createipforwardentry

    PMIB_IPFORWARDTABLE pIpForwardTable = NULL;
    DWORD dwSize = 0;
    BOOL bOrder = FALSE;
    DWORD dwStatus = 0;
    unsigned int i;
    ipstr_t gateway_address;

    // find out how big our buffer needs to be
    dwStatus = GetIpForwardTable(pIpForwardTable, &dwSize, bOrder);
    if(dwStatus == ERROR_INSUFFICIENT_BUFFER) {
        // allocate the memory for the table
        if(!(pIpForwardTable = (PMIB_IPFORWARDTABLE)malloc(dwSize))) {
            traceEvent(TRACE_DEBUG, "malloc failed, out of memory\n");
            return EXIT_FAILURE;
        }
        // now get the table
        dwStatus = GetIpForwardTable(pIpForwardTable, &dwSize, bOrder);
    }

    if (dwStatus != ERROR_SUCCESS) {
        traceEvent(TRACE_DEBUG, "getIpForwardTable failed\n");
        if(pIpForwardTable)
            free(pIpForwardTable);
        return EXIT_FAILURE;
    }

    dwStatus = EXIT_FAILURE;
    // search for the row in the table we want. The default gateway has a destination of 0.0.0.0
    for(i = 0; i < pIpForwardTable->dwNumEntries; i++) {
        if(pIpForwardTable->table[i].dwForwardDest == 0) {
            // we have found a default route
            // do not use if the gateway is the one to be excluded
            if(pIpForwardTable->table[i].dwForwardNextHop == exclude->S_un.S_addr)
                continue;
            dwStatus = 0;
            gateway_addr->S_un.S_addr = pIpForwardTable->table[i].dwForwardNextHop;
            traceEvent(TRACE_DEBUG, "assuming default gateway %s",
                                    inaddrtoa(gateway_address, *gateway_addr));
            break;
        }
    }

    if(pIpForwardTable) {
        free(pIpForwardTable);
    }

    return dwStatus;
#endif
}


// -------------------------------------------------------------------------------------------------------
// PLATFORM-DEPENDANT CODE


#ifdef _WIN32
DWORD get_interface_index (struct in_addr addr) {
    // taken from (and modified)
    // https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-createipforwardentry

    PMIB_IPFORWARDTABLE pIpForwardTable = NULL;
    DWORD dwSize = 0;
    BOOL bOrder = FALSE;
    DWORD dwStatus = 0;
    DWORD mask_addr = 0;
    DWORD max_idx = 0;
    uint8_t bitlen, max_bitlen = 0;
    unsigned int i;
    ipstr_t gateway_address;

    // find out how big our buffer needs to be
    dwStatus = GetIpForwardTable(pIpForwardTable, &dwSize, bOrder);
    if(dwStatus == ERROR_INSUFFICIENT_BUFFER) {
        // allocate the memory for the table
        if(!(pIpForwardTable = (PMIB_IPFORWARDTABLE)malloc(dwSize))) {
            traceEvent(TRACE_DEBUG, "malloc failed, out of memory\n");
            return EXIT_FAILURE;
        }
        // now get the table
        dwStatus = GetIpForwardTable(pIpForwardTable, &dwSize, bOrder);
    }

    if (dwStatus != ERROR_SUCCESS) {
        traceEvent(TRACE_DEBUG, "getIpForwardTable failed\n");
        if(pIpForwardTable)
            free(pIpForwardTable);
        return 0;
    }

    // search for the row in the table we want. The default gateway has a destination of 0.0.0.0
    for(i = 0; i < pIpForwardTable->dwNumEntries; i++) {
        mask_addr = pIpForwardTable->table[i].dwForwardMask;
        // if same subnet ...
        if((mask_addr & addr.S_un.S_addr) == (mask_addr & pIpForwardTable->table[i].dwForwardDest)) {
            mask_addr = ntohl(mask_addr);
            for(bitlen = 0; (int)mask_addr < 0; mask_addr <<= 1)
                bitlen++;
            if(bitlen > max_bitlen) {
                max_bitlen = bitlen;
                max_idx = pIpForwardTable->table[i].dwForwardIfIndex;
            }
        }
    }

    traceEvent(TRACE_DEBUG, "found interface index %u for gateway %s",
                           max_idx, inaddrtoa(gateway_address, addr));

    if(pIpForwardTable) {
        free(pIpForwardTable);
    }

    return max_idx;
}
#endif


// -------------------------------------------------------------------------------------------------------
// PLATFORM-DEPENDANT CODE


/* adds (verb == ROUTE_ADD) or deletes (verb == ROUTE_DEL) a route */
void handle_route (n2n_route_t* in_route, int verb) {

#if defined(__linux__)
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

#elif defined(_WIN32)
    // REVISIT: use 'CreateIpForwardEntry()' and 'DeleteIpForwardEntry()' [iphlpapi.h]
    char c_net_addr[32];
    char c_gateway[32];
    char c_interface[32];
    char c_verb[32];
    uint32_t mask;
    uint8_t bitlen;
    DWORD if_idx;
    char cmd[256];

    // assemble route command components
    _snprintf(c_net_addr, sizeof(c_net_addr), inet_ntoa(in_route->net_addr));
    _snprintf(c_gateway, sizeof(c_gateway), inet_ntoa(in_route->gateway));
    mask = ntohl(in_route->net_mask.S_un.S_addr);
    for(bitlen = 0; (int)mask < 0; mask <<= 1)
        bitlen++;
    if_idx = get_interface_index(in_route->gateway);
    _snprintf(c_interface, sizeof(c_interface), "if %u", if_idx);
    _snprintf(c_verb, sizeof(c_verb), (verb == ROUTE_ADD) ? "add" : "delete");
    _snprintf(cmd, sizeof(cmd), "route %s %s/%d %s %s > nul", c_verb, c_net_addr, bitlen, c_gateway, c_interface);
    traceEvent(TRACE_INFO, "ROUTE CMD = '%s'\n", cmd);

    // issue the route command
    system(cmd);
#endif
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
// PLATFORM-DEPENDANT CODE


SOCKET connect_to_management_port (n2n_route_conf_t *rrr) {

    SOCKET ret;
    struct sockaddr_in sock_addr;

#ifdef _WIN32
    // Windows requires a call to WSAStartup() before it can work with sockets
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    // Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h
    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        // tell the user that we could not find a usable Winsock DLL
        traceEvent(TRACE_ERROR, "WSAStartup failed with error: %d\n", err);
        return -1;
    }
#endif

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
// PLATFORM-DEPENDANT CODE


#ifndef _WIN32
// taken from https://web.archive.org/web/20170407122137/http://cc.byexamples.com/2007/04/08/non-blocking-user-input-in-loop-without-ncurses/
int _kbhit () {

    struct timeval tv;
    fd_set fds;

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds); //STDIN_FILENO is 0
    select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);

    return FD_ISSET(STDIN_FILENO, &fds);
}
#else
// A dummy definition to avoid compile errors on windows
int _kbhit () {
    return 0;
}
#endif


// -------------------------------------------------------------------------------------------------------


static void help (int level) {

    if(level == 0) return; /* no help required */

    printf("  n2n-route [-t <manangement_port>] [-p <management_port_password>] [-v] [-V]"
         "\n            [-g <default gateway>] [-n <network address>/bitlen[:gateway]]"
         "\n            <vpn gateway>"
        "\n"
        "\n           This tool sets new routes for all the traffic to be routed via the"
        "\n           <vpn gateway> and polls the management port of a local n2n edge for"
        "\n           it can add routes to supernodes and peers via the original default"
        "\n           gateway. Adapt port (default: %d) and password (default: '%s')"
        "\n           to match your edge's configuration."
      "\n\n           If no <default gateway> provided, the tool will try to auto-detect."
      "\n\n           To only route some traffic through vpn, inidicate the networks to be"
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
            char cidr_net[64], bitlen, gateway[64];
            n2n_route_t *route;
            struct in_addr mask;
            int ret;

            gateway[0] = '\0'; // optional parameter
            ret = sscanf(optargument, "%63[^/]/%hhd:%63s", cidr_net, &bitlen, gateway);
            if((ret < 2) || (ret > 3)) {
                traceEvent(TRACE_WARNING, "bad cidr network format '%s'", optargument);
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
            if(gateway[0]) {
                if(!inet_address_valid(inet_address(gateway))) {
                    traceEvent(TRACE_WARNING, "bad gateway '%s' in '%s'", gateway, optargument);
                    return 1;
                 }
            }
            traceEvent(TRACE_NORMAL, "routing %s/%d via %s", cidr_net, bitlen, gateway[0] ? gateway : "vpn gateway");

            route = calloc(1, sizeof(*route));
            if(route) {
                mask.s_addr = htonl(bitlen2mask(bitlen));
                // gateway might be unknown at this point, will be rectified later
                fill_route(route, inet_address(cidr_net), mask, inet_address(gateway));
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
    char *p;
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
    } else {
        traceEvent(TRACE_WARNING, "only user-supplied networks will be routed, not the complete traffic");
    }
    // set gateway for all so far present routes if '-n'-provided do not have it yet,
    // make them UNPURGEABLE and add them to system table
    HASH_ITER(hh, rrr.routes, route, tmp_route) {
        if(!inet_address_valid(route->gateway)) {
            route->gateway = rrr.gateway_vpn;
        }
        route->purgeable = false;
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
    while(keep_running && !_kbhit()) {
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
                    if((route->purgeable == true)) {
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
                if((route->purgeable == true) && (now > route->last_seen + REMOVE_ROUTE_AGE)) {
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
                    for (p = udp_buf; (p = strchr(p, '\n')) != NULL; p++) *p = ' ';
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
                                route->purgeable = true;
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


#else  /* if defined(__linux__) || defined(_WIN64) --  currently, Linux and Windows only */


int main (int argc, char* argv[]) {

    traceEvent(TRACE_WARNING, "currently, only Linux and 64-bit Windows are supported");
    traceEvent(TRACE_WARNING, "if you want to port to other OS, please find the source code having clearly marked the platform-dependant portions");

    return 0;
}


#endif /* if defined (__linux__) || defined(_WIN64)  --  currently, Linux and Windows only */
