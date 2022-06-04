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


#define WITH_PORT               1
#define CORRECT_TAG             2

#define SOCKET_TIMEOUT          2
#define INFO_INTERVAL           5


typedef struct n2n_portfwd_conf {
    uint16_t          port;               /* management port */
} n2n_portfwd_conf_t;


static int keep_running = 1;              /* for main loop, handled by signals */


// -------------------------------------------------------------------------------------------------------
// PLATFORM-DEPENDANT CODE (FOR NON-MANDATORY FEATURE)


void set_term_handler(const void *handler) {

#ifdef __linux__
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, handler);
    signal(SIGINT, handler);
#endif
#ifdef WIN32
    SetConsoleCtrlHandler(handler, TRUE);
#endif
}


#ifdef WIN32
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
#ifdef WIN32
    return TRUE;
#endif
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


SOCKET connect_to_management_port (n2n_portfwd_conf_t *ppp) {

    SOCKET ret;
    struct sockaddr_in sock_addr;

    ret = socket (PF_INET, SOCK_DGRAM, 0);
    if((int)ret < 0)
        return -1;

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sock_addr.sin_port = htons(ppp->port);
    if(0 != connect(ret, (struct sockaddr *)&sock_addr, sizeof(sock_addr)))
        return -1;

    return ret;
}


// -------------------------------------------------------------------------------------------------------


int get_port_from_json (uint16_t *port, json_object_t *json, char *key, int tag, int flags) {

    int i;
    char *colon = NULL;

    if(NULL == json)
        return 0;

    for(i = 0; i < json->count; i++) {
        if(json->pairs[i].type == JSON_STRING) {
            if(!strcmp(json->pairs[i].key, key)) {
                // cut off port from IP address
                if((colon = strchr(json->pairs[i].value->string_value, ':'))) {
                    if(*colon != '\0') {
                        *port = atoi(colon + 1);
                        flags |= WITH_PORT;
                    }
                }
            }
            if(!strcmp(json->pairs[i].key, "_tag" )) {
                if(atoi(json->pairs[i].value->string_value) == tag) {
                    flags |= CORRECT_TAG;
                }
            }
        } else if(json->pairs[i].type == JSON_OBJECT) {
            flags |= get_port_from_json(port, json, key, tag, flags);
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

    printf("  n2n-portfwd [-t <manangement_port>] [-V] [-v]"
        "\n"
        "\n           This tool tries to find a router in local network and asks it to"
        "\n           forward the edge's port(UDP and TCP) by sending corresponding"
        "\n           UPnP and PMP requests."
      "\n\n           Adapt port (default: %d) to match your edge's management port"
        "\n           configuration."
      "\n\n           Verbosity can be increased or decreased with -V or -v , repeat as"
        "\n           as needed."
      "\n\n",
           N2N_EDGE_MGMT_PORT);

    exit(0);
}


static int set_option (n2n_portfwd_conf_t *ppp, int optkey, char *optargument) {

    switch(optkey) {
        case 't': /* management port */ {
            uint16_t port = atoi(optargument);
            if(port) {
                ppp->port = port;
            } else {
                traceEvent(TRACE_WARNING, "invalid management port provided with '-t'");
            }
            break;
        }

        case 'V': /* more verbose */ {
            setTraceLevel(getTraceLevel() + 1);
            break;
        }

        case 'v': /* less verbose */ {
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

    n2n_portfwd_conf_t ppp;
    uint8_t c;
    SOCKET sock;
    size_t msg_len;
    char udp_buf[N2N_PKT_BUF_SIZE];
    fd_set socket_mask;
    struct timeval wait_time;
    time_t now = 0;
    time_t last_info_req = 0;
    json_object_t *json;
    int ret;
    int tag_info;
    uint16_t port, current_port;

    // version
    print_n2n_version();

    // handle signals to properly end the tool
    set_term_handler(term_handler);

    // init data structure
    ppp.port = N2N_EDGE_MGMT_PORT;
    setTraceLevel(2); /* NORMAL, should already be default */
    n2n_srand(n2n_seed());

    // get command line options and eventually overwrite initialized conf
    while((c = getopt_long(argc, argv, "t:vV", NULL, NULL)) != '?') {
        if(c == 255) break;
        help(set_option(&ppp, c, optarg));
    }

    // verify conf and react with output to conf-related changes
    // (nothing to do)

    // additional checks
    // (nothing to do)

    // connect to mamagement port
    traceEvent(TRACE_NORMAL, "connecting to edge management port %d", ppp.port);
    sock = connect_to_management_port(&ppp);
    if(sock == -1) {
        traceEvent(TRACE_ERROR, "unable to open socket for management port connection");
        goto end_route_tool;
    }

    // output status
    traceEvent(TRACE_NORMAL, "press ENTER to end the program");

reset_main_loop:

    wait_time.tv_sec = SOCKET_TIMEOUT;
    wait_time.tv_usec = 0;
    port = 0;
    current_port = 0;
    tag_info = 0;

    // main loop
    // read answer packet by packet which are only accepted if a corresponding request was sent before
    // of which we know about by having set the related tag, tag_info
    // a valid sock address indicates that we have seen a valid answer to the info request
    while(keep_running && !kbhit()) {
        // current time
        now = time(NULL);

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
                        // local IP address port
                        port = 0;
                        ret = get_port_from_json(&port, json, "sockaddr", tag_info, 0);
                        if(ret == (WITH_PORT | CORRECT_TAG)) {
                            traceEvent(TRACE_DEBUG, "received information about %d being edge's port", port);
                            // evaluate current situation and take appropriate action
                            if(port != current_port) {
                                if(current_port)
                                    n2n_del_port_mapping(current_port);
                                if(port)
                                    n2n_set_port_mapping(port);
                                current_port = port;
                                traceEvent(TRACE_NORMAL, "found %d being edge's port", current_port);
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

end_route_tool:

    // close connection
    closesocket(sock);

    return 0;
}
