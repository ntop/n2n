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

#include "n2n.h"
#include "edge_utils_win32.h"

enum n2n_mgmt_type {
    N2N_MGMT_UNKNOWN = 0,
    N2N_MGMT_READ = 1,
    N2N_MGMT_WRITE = 2,
    N2N_MGMT_SUB = 3,
};

/*
 * Everything needed to reply to a request
 */
typedef struct mgmt_req {
    n2n_edge_t *eee;
    enum n2n_mgmt_type type;
    char tag[10];
    struct sockaddr_in sender_sock;
} mgmt_req_t;

/*
 * Read/Write handlers are defined in this structure
 */
#define FLAG_WROK 1
typedef struct mgmt_handler {
    int flags;
    char  *cmd;
    char  *help;
    void (*func)(mgmt_req_t *req, char *udp_buf, char *argv0, char *argv);
} mgmt_handler_t;

/*
 * Event topic names are defined in this structure
 */
typedef struct mgmt_events {
    int topic; // topic number define
    char  *cmd;
    char  *help;
} mgmt_events_t;

// Lookup the index of matching argv0 in a cmd list
// store index in "Result", or -1 for not found
#define lookup_handler(Result, list, argv0) do { \
        int nr_max = sizeof(list) / sizeof(list[0]); \
        for( Result=0; Result < nr_max; Result++ ) { \
            if(0 == strcmp(list[Result].cmd, argv0)) { \
                break; \
            } \
        } \
        if( Result >= nr_max ) { \
            Result = -1; \
        } \
} while(0)

static void send_reply (mgmt_req_t *req, char *udp_buf, size_t msg_len) {
    // TODO: error handling
    sendto(req->eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &req->sender_sock, sizeof(struct sockaddr_in));
}

static void send_json_1str (mgmt_req_t *req, char *udp_buf, char *_type, char *key, char *val) {
    size_t msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                              "{"
                              "\"_tag\":\"%s\","
                              "\"_type\":\"%s\","
                              "\"%s\":\"%s\"}\n",
                              req->tag,
                              _type,
                              key,
                              val);
    send_reply(req, udp_buf, msg_len);
}

static void send_json_1uint (mgmt_req_t *req, char *udp_buf, char *_type, char *key, unsigned int val) {
    size_t msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                              "{"
                              "\"_tag\":\"%s\","
                              "\"_type\":\"%s\","
                              "\"%s\":%u}\n",
                              req->tag,
                              _type,
                              key,
                              val);
    send_reply(req, udp_buf, msg_len);
}

static void event_debug (mgmt_req_t *req, char *udp_buf) {
    send_reply(req, "test", 4);
}

static void mgmt_error (mgmt_req_t *req, char *udp_buf, char *msg) {
    send_json_1str(req, udp_buf, "error", "error", msg);
}

static void mgmt_stop (mgmt_req_t *req, char *udp_buf, char *argv0, char *argv) {

    if(req->type==N2N_MGMT_WRITE) {
        *req->eee->keep_running = 0;
    }

    send_json_1uint(req, udp_buf, "row", "keep_running", *req->eee->keep_running);
}

static void mgmt_verbose (mgmt_req_t *req, char *udp_buf, char *argv0, char *argv) {

    if(req->type==N2N_MGMT_WRITE) {
        if(argv) {
            setTraceLevel(strtoul(argv, NULL, 0));
        }
    }

    send_json_1uint(req, udp_buf, "row", "traceLevel", getTraceLevel());
}

static void mgmt_communities (mgmt_req_t *req, char *udp_buf, char *argv0, char *argv) {

    if(req->eee->conf.header_encryption != HEADER_ENCRYPTION_NONE) {
        mgmt_error(req, udp_buf, "noaccess");
        return;
    }

    send_json_1str(req, udp_buf, "row", "community", (char *)req->eee->conf.community_name);
}

static void mgmt_supernodes (mgmt_req_t *req, char *udp_buf, char *argv0, char *argv) {
    size_t msg_len;
    struct peer_info *peer, *tmpPeer;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    selection_criterion_str_t sel_buf;

    HASH_ITER(hh, req->eee->conf.supernodes, peer, tmpPeer) {

        /*
         * TODO:
         * The version string provided by the remote supernode could contain
         * chars that make our JSON invalid.
         * - do we care?
         */

        msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                           "{"
                           "\"_tag\":\"%s\","
                           "\"_type\":\"row\","
                           "\"version\":\"%s\","
                           "\"purgeable\":%i,"
                           "\"current\":%i,"
                           "\"macaddr\":\"%s\","
                           "\"sockaddr\":\"%s\","
                           "\"selection\":\"%s\","
                           "\"last_seen\":%li,"
                           "\"uptime\":%li}\n",
                           req->tag,
                           peer->version,
                           peer->purgeable,
                           (peer == req->eee->curr_sn) ? (req->eee->sn_wait ? 2 : 1 ) : 0,
                           is_null_mac(peer->mac_addr) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                           sock_to_cstr(sockbuf, &(peer->sock)),
                           sn_selection_criterion_str(req->eee, sel_buf, peer),
                           peer->last_seen,
                           peer->uptime);

        send_reply(req, udp_buf, msg_len);
    }
}

static void mgmt_edges_row (mgmt_req_t *req, char *udp_buf, struct peer_info *peer, char *mode) {
    size_t msg_len;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"mode\":\"%s\","
                       "\"ip4addr\":\"%s\","
                       "\"purgeable\":%i,"
                       "\"local\":%i,"
                       "\"macaddr\":\"%s\","
                       "\"sockaddr\":\"%s\","
                       "\"desc\":\"%s\","
                       "\"last_p2p\":%li,\n"
                       "\"last_sent_query\":%li,\n"
                       "\"last_seen\":%li}\n",
                       req->tag,
                       mode,
                       (peer->dev_addr.net_addr == 0) ? "" : ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
                       peer->purgeable,
                       peer->local,
                       (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                       sock_to_cstr(sockbuf, &(peer->sock)),
                       peer->dev_desc,
                       peer->last_p2p,
                       peer->last_sent_query,
                       peer->last_seen);

    send_reply(req, udp_buf, msg_len);
}

static void mgmt_edges (mgmt_req_t *req, char *udp_buf, char *argv0, char *argv) {
    struct peer_info *peer, *tmpPeer;

    // dump nodes with forwarding through supernodes
    HASH_ITER(hh, req->eee->pending_peers, peer, tmpPeer) {
        mgmt_edges_row(req, udp_buf, peer, "pSp");
    }

    // dump peer-to-peer nodes
    HASH_ITER(hh, req->eee->known_peers, peer, tmpPeer) {
        mgmt_edges_row(req, udp_buf, peer, "p2p");
    }
}

static void mgmt_timestamps (mgmt_req_t *req, char *udp_buf, char *argv0, char *argv) {
    size_t msg_len;

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"start_time\":%lu,"
                       "\"last_super\":%ld,"
                       "\"last_p2p\":%ld}\n",
                       req->tag,
                       req->eee->start_time,
                       req->eee->last_sup,
                       req->eee->last_p2p);

    send_reply(req, udp_buf, msg_len);
}

static void mgmt_packetstats (mgmt_req_t *req, char *udp_buf, char *argv0, char *argv) {
    size_t msg_len;

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"transop\","
                       "\"tx_pkt\":%lu,"
                       "\"rx_pkt\":%lu}\n",
                       req->tag,
                       req->eee->transop.tx_cnt,
                       req->eee->transop.rx_cnt);

    send_reply(req, udp_buf, msg_len);

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"p2p\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_p2p,
                       req->eee->stats.rx_p2p);

    send_reply(req, udp_buf, msg_len);

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"super\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_sup,
                       req->eee->stats.rx_sup);

    send_reply(req, udp_buf, msg_len);

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"super_broadcast\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_sup_broadcast,
                       req->eee->stats.rx_sup_broadcast);

    send_reply(req, udp_buf, msg_len);
}

static void mgmt_unimplemented (mgmt_req_t *req, char *udp_buf, char *argv0, char *argv) {

    mgmt_error(req, udp_buf, "unimplemented");
}

// Forward define so we can include this in the mgmt_handlers[] table
static void mgmt_help (mgmt_req_t *req, char *udp_buf, char *argv0, char *argv);
static void mgmt_help_events (mgmt_req_t *req, char *udp_buf, char *argv0, char *argv);

static const mgmt_handler_t mgmt_handlers[] = {
    { .cmd = "reload_communities", .flags = FLAG_WROK, .help = "Reserved for supernode", .func = mgmt_unimplemented},

    { .cmd = "stop", .flags = FLAG_WROK, .help = "Gracefully exit edge", .func = mgmt_stop},
    { .cmd = "verbose", .flags = FLAG_WROK, .help = "Manage verbosity level", .func = mgmt_verbose},
    { .cmd = "communities", .help = "Show current community", .func = mgmt_communities},
    { .cmd = "edges", .help = "List current edges/peers", .func = mgmt_edges},
    { .cmd = "supernodes", .help = "List current supernodes", .func = mgmt_supernodes},
    { .cmd = "timestamps", .help = "Event timestamps", .func = mgmt_timestamps},
    { .cmd = "packetstats", .help = "traffic counters", .func = mgmt_packetstats},
    { .cmd = "help", .flags = FLAG_WROK, .help = "Show JSON commands", .func = mgmt_help},
    { .cmd = "help.events", .help = "Show available Subscribe topics", .func = mgmt_help_events},
};

/* Current subscriber for each event topic */
static mgmt_req_t mgmt_event_subscribers[] = {
    [0] = { .eee = NULL, .type = N2N_MGMT_UNKNOWN, .tag = "\0" },
};

/* Map topic number to function */
static const void (*mgmt_events[])(mgmt_req_t *req, char *udp_buf) = {
    [0] = event_debug,
};

/* Allow help and subscriptions to use topic name */
static const mgmt_events_t mgmt_event_names[] = {
    { .cmd = "debug", .topic = 0, .help = "All events - for event debugging"},
};

static void mgmt_help_events (mgmt_req_t *req, char *udp_buf, char *argv0, char *argv) {
    size_t msg_len;

    int i;
    int nr_handlers = sizeof(mgmt_event_names) / sizeof(mgmt_events_t);
    for( i=0; i < nr_handlers; i++ ) {
        int topic = mgmt_event_names[i].topic;
        mgmt_req_t *sub = &mgmt_event_subscribers[topic];

        msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                           "{"
                           "\"_tag\":\"%s\","
                           "\"_type\":\"row\","
                           "\"topic\":\"%s\","
                           "\"tag\":\"%s\","
                           // "\"sockaddr\":\"%s\","
                           "\"help\":\"%s\"}\n",
                           req->tag,
                           mgmt_event_names[i].cmd,
                           sub->tag,
                           // "FIXME",
                           mgmt_event_names[i].help);

        send_reply(req, udp_buf, msg_len);
    }
}

static void mgmt_help (mgmt_req_t *req, char *udp_buf, char *argv0, char *argv) {
    size_t msg_len;

    /*
     * Even though this command is readonly, we deliberately do not check
     * the type - allowing help replies to both read and write requests
     */

    int i;
    int nr_handlers = sizeof(mgmt_handlers) / sizeof(mgmt_handler_t);
    for( i=0; i < nr_handlers; i++ ) {
        msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                           "{"
                           "\"_tag\":\"%s\","
                           "\"_type\":\"row\","
                           "\"cmd\":\"%s\","
                           "\"help\":\"%s\"}\n",
                           req->tag,
                           mgmt_handlers[i].cmd,
                           mgmt_handlers[i].help);

        send_reply(req, udp_buf, msg_len);
    }
}

/*
 * Check if the user is authorised for this command.
 * - this should be more configurable!
 * - for the moment we use some simple heuristics:
 *   Reads are not dangerous, so they are simply allowed
 *   Writes are possibly dangerous, so they need a fake password
 */
static int mgmt_auth (mgmt_req_t *req, char *auth, char *argv0, char *argv) {

    if(auth) {
        /* If we have an auth key, it must match */
        if(req->eee->conf.mgmt_password_hash == pearson_hash_64((uint8_t*)auth, strlen(auth))) {
            return 1;
        }
        return 0;
    }
    /* if we dont have an auth key, we can still read */
    if(req->type == N2N_MGMT_READ) {
        return 1;
    }

    return 0;
}

static void handleMgmtJson (mgmt_req_t *req, char *udp_buf, const int recvlen) {

    char cmdlinebuf[80];
    char *typechar;
    char *options;
    char *argv0;
    char *argv;
    char *flagstr;
    int flags;
    char *auth;

    /* Initialise the tag field until we extract it from the cmdline */
    req->tag[0] = '-';
    req->tag[1] = '1';
    req->tag[2] = '\0';

    /* save a copy of the commandline before we reuse the udp_buf */
    strncpy(cmdlinebuf, udp_buf, sizeof(cmdlinebuf)-1);
    cmdlinebuf[sizeof(cmdlinebuf)-1] = 0;

    traceEvent(TRACE_DEBUG, "mgmt json %s", cmdlinebuf);

    typechar = strtok(cmdlinebuf, " \r\n");
    if(!typechar) {
        /* should not happen */
        mgmt_error(req, udp_buf, "notype");
        return;
    }
    if(*typechar == 'r') {
        req->type=N2N_MGMT_READ;
    } else if(*typechar == 'w') {
        req->type=N2N_MGMT_WRITE;
    } else if(*typechar == 's') {
        req->type=N2N_MGMT_SUB;
    } else {
        mgmt_error(req, udp_buf, "badtype");
        return;
    }

    /* Extract the tag to use in all reply packets */
    options = strtok(NULL, " \r\n");
    if(!options) {
        mgmt_error(req, udp_buf, "nooptions");
        return;
    }

    argv0 = strtok(NULL, " \r\n");
    if(!argv0) {
        mgmt_error(req, udp_buf, "nocmd");
        return;
    }

    /*
     * The entire rest of the line is the argv. We apply no processing
     * or arg separation so that the cmd can use it however it needs.
     */
    argv = strtok(NULL, "\r\n");

    /*
     * There might be an auth token mixed in with the tag
     */
    char *tagp = strtok(options, ":");
    strncpy(req->tag, tagp, sizeof(req->tag)-1);
    req->tag[sizeof(req->tag)-1] = '\0';

    flagstr = strtok(NULL, ":");
    if(flagstr) {
        flags = strtoul(flagstr, NULL, 16);
    } else {
        flags = 0;
    }

    /* Only 1 flag bit defined at the moment - "auth option present" */
    if(flags & 1) {
        auth = strtok(NULL, ":");
    } else {
        auth = NULL;
    }

    if(!mgmt_auth(req, auth, argv0, argv)) {
        mgmt_error(req, udp_buf, "badauth");
        return;
    }

    if(req->type == N2N_MGMT_SUB) {
        mgmt_error(req, udp_buf, "unimplemented");
        return;
    }

    int handler;
    lookup_handler(handler, mgmt_handlers, argv0);
    if(handler == -1) {
        mgmt_error(req, udp_buf, "unknowncmd");
        return;
    }

    if((req->type==N2N_MGMT_WRITE) && !(mgmt_handlers[handler].flags & FLAG_WROK)) {
        mgmt_error(req, udp_buf, "readonly");
        return;
    }

    /*
     * TODO:
     * The tag provided by the requester could contain chars
     * that make our JSON invalid.
     * - do we care?
     */
    send_json_1str(req, udp_buf, "begin", "cmd", argv0);

    mgmt_handlers[handler].func(req, udp_buf, argv0, argv);

    send_json_1str(req, udp_buf, "end", "cmd", argv0);
    return;
}

/** Read a datagram from the management UDP socket and take appropriate
 *    action. */
void readFromMgmtSocket (n2n_edge_t *eee) {

    char udp_buf[N2N_PKT_BUF_SIZE]; /* Compete UDP packet */
    ssize_t recvlen;
    /* ssize_t sendlen; */
    mgmt_req_t req;
    socklen_t i;
    size_t msg_len;
    time_t now;
    struct peer_info *peer, *tmpPeer;
    macstr_t mac_buf;
    char time_buf[10]; /* 9 digits + 1 terminating zero */
    char uptime_buf[11]; /* 10 digits + 1 terminating zero */
    /* dec_ip_bit_str_t ip_bit_str = {'\0'}; */
    /* dec_ip_str_t ip_str = {'\0'}; */
    in_addr_t net;
    n2n_sock_str_t sockbuf;
    uint32_t num_pending_peers = 0;
    uint32_t num_known_peers = 0;
    uint32_t num = 0;
    selection_criterion_str_t sel_buf;

    req.eee = eee;

    now = time(NULL);
    i = sizeof(req.sender_sock);
    recvlen = recvfrom(eee->udp_mgmt_sock, udp_buf, N2N_PKT_BUF_SIZE, 0 /*flags*/,
                       (struct sockaddr *) &req.sender_sock, (socklen_t *) &i);

    if(recvlen < 0) {
        traceEvent(TRACE_WARNING, "mgmt recvfrom failed: %d - %s", errno, strerror(errno));
        return; /* failed to receive data from UDP */
    }

    /* avoid parsing any uninitialized junk from the stack */
    udp_buf[recvlen] = 0;

    if((0 == memcmp(udp_buf, "help", 4)) || (0 == memcmp(udp_buf, "?", 1))) {
        msg_len = 0;

        msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                            "Help for edge management console:\n"
                            "\tstop    | Gracefully exit edge\n"
                            "\thelp    | This help message\n"
                            "\t+verb   | Increase verbosity of logging\n"
                            "\t-verb   | Decrease verbosity of logging\n"
                            "\tr ...   | start query with JSON reply\n"
                            "\tw ...   | start update with JSON reply\n"
                            "\ts ...   | subscribe to event channel JSON reply\n"
                            "\t<enter> | Display statistics\n\n");

        send_reply(&req, udp_buf, msg_len);

        return;
    }

    if(0 == memcmp(udp_buf, "stop", 4)) {
        traceEvent(TRACE_NORMAL, "stop command received");
        *eee->keep_running = 0;
        return;
    }

    if(0 == memcmp(udp_buf, "+verb", 5)) {
        msg_len = 0;
        setTraceLevel(getTraceLevel() + 1);

        traceEvent(TRACE_NORMAL, "+verb traceLevel=%u", (unsigned int) getTraceLevel());
        msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                            "> +OK traceLevel=%u\n", (unsigned int) getTraceLevel());

        send_reply(&req, udp_buf, msg_len);

        return;
    }

    if(0 == memcmp(udp_buf, "-verb", 5)) {
        msg_len = 0;

        if(getTraceLevel() > 0) {
            setTraceLevel(getTraceLevel() - 1);
            msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                "> -OK traceLevel=%u\n", getTraceLevel());
        } else {
            msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                "> -NOK traceLevel=%u\n", getTraceLevel());
        }

        traceEvent(TRACE_NORMAL, "-verb traceLevel=%u", (unsigned int) getTraceLevel());

        send_reply(&req, udp_buf, msg_len);
        return;
    }

    if((udp_buf[0] >= 'a' && udp_buf[0] <= 'z') && (udp_buf[1] == ' ')) {
        /* this is a JSON request */
        handleMgmtJson(&req, udp_buf, recvlen);
        return;
    }

    traceEvent(TRACE_DEBUG, "mgmt status requested");

    msg_len = 0;
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "COMMUNITY '%s'\n\n",
                        (eee->conf.header_encryption == HEADER_ENCRYPTION_NONE) ? (char*)eee->conf.community_name : "-- header encrypted --");
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        " ### | TAP             | MAC               | EDGE                  | HINT            | LAST SEEN |     UPTIME\n");
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "=============================================================================================================\n");

    // dump nodes with forwarding through supernodes
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "SUPERNODE FORWARD\n");
    num = 0;
    HASH_ITER(hh, eee->pending_peers, peer, tmpPeer) {
        ++num_pending_peers;
        net = htonl(peer->dev_addr.net_addr);
        snprintf(time_buf, sizeof(time_buf), "%9u", (unsigned int)(now - peer->last_seen));
        msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                            "%4u | %-15s | %-17s | %-21s | %-15s | %9s |\n",
                            ++num,
                            (peer->dev_addr.net_addr == 0) ? "" : inet_ntoa(*(struct in_addr *) &net),
                            (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                            sock_to_cstr(sockbuf, &(peer->sock)),
                            peer->dev_desc,
                            (peer->last_seen) ? time_buf : "");

        send_reply(&req, udp_buf, msg_len);
        msg_len = 0;
    }

    // dump peer-to-peer nodes
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "-------------------------------------------------------------------------------------------------------------\n");
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "PEER TO PEER\n");
    num = 0;
    HASH_ITER(hh, eee->known_peers, peer, tmpPeer) {
        ++num_known_peers;
        net = htonl(peer->dev_addr.net_addr);
        snprintf(time_buf, sizeof(time_buf), "%9u", (unsigned int)(now - peer->last_seen));
        msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                            "%4u | %-15s | %-17s | %-21s | %-15s | %9s |\n",
                            ++num,
                            (peer->dev_addr.net_addr == 0) ? "" : inet_ntoa(*(struct in_addr *) &net),
                            (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                            sock_to_cstr(sockbuf, &(peer->sock)),
                            peer->dev_desc,
                            (peer->last_seen) ? time_buf : "");

        send_reply(&req, udp_buf, msg_len);
        msg_len = 0;
    }

    // dump supernodes
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "-------------------------------------------------------------------------------------------------------------\n");

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "SUPERNODES\n");
    HASH_ITER(hh, eee->conf.supernodes, peer, tmpPeer) {
        net = htonl(peer->dev_addr.net_addr);
        snprintf(time_buf, sizeof(time_buf), "%9u", (unsigned int)(now - peer->last_seen));
        snprintf(uptime_buf, sizeof(uptime_buf), "%10u", (unsigned int)(peer->uptime));
        msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                            "%-19s %1s%1s | %-17s | %-21s | %-15s | %9s | %10s\n",
                            peer->version,
                            (peer->purgeable == SN_UNPURGEABLE) ? "l" : "",
                            (peer == eee->curr_sn) ? (eee->sn_wait ? "." : "*" ) : "",
                            is_null_mac(peer->mac_addr) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                            sock_to_cstr(sockbuf, &(peer->sock)),
                            sn_selection_criterion_str(eee, sel_buf, peer),
                            (peer->last_seen) ? time_buf : "",
                            (peer->uptime) ? uptime_buf : "");

        send_reply(&req, udp_buf, msg_len);
        msg_len = 0;
    }

    // further stats
    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "=============================================================================================================\n");

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "uptime %lu | ",
                        time(NULL) - eee->start_time);

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "pend_peers %u | ",
                        num_pending_peers);

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "known_peers %u | ",
                        num_known_peers);

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "transop %u,%u\n",
                        (unsigned int) eee->transop.tx_cnt,
                        (unsigned int) eee->transop.rx_cnt);

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "super %u,%u | ",
                        (unsigned int) eee->stats.tx_sup,
                        (unsigned int) eee->stats.rx_sup);

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "p2p %u,%u\n",
                        (unsigned int) eee->stats.tx_p2p,
                        (unsigned int) eee->stats.rx_p2p);

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "last_super %ld sec ago | ",
                        (now - eee->last_sup));

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "last_p2p %ld sec ago\n",
                        (now - eee->last_p2p));

    msg_len += snprintf((char *) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "\nType \"help\" to see more commands.\n\n");

    send_reply(&req, udp_buf, msg_len);
}
