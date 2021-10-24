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

#define FLAG_WROK 1
typedef struct n2n_mgmt_handler {
    int flags;
    char  *cmd;
    char  *help;
    void (*func)(n2n_edge_t *eee, char *udp_buf, struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv);
} n2n_mgmt_handler_t;

static void mgmt_error (n2n_edge_t *eee, char *udp_buf, const struct sockaddr_in sender_sock, char *tag, char *msg) {
    size_t msg_len;
    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"error\","
                       "\"error\":\"%s\"}\n",
                       tag,
                       msg);
    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
}

static void mgmt_stop (n2n_edge_t *eee, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;

    if(type==N2N_MGMT_WRITE) {
        *eee->keep_running = 0;
    }

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"keep_running\":%u}\n",
                       tag,
                       *eee->keep_running);

    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
}

static void mgmt_verbose (n2n_edge_t *eee, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;

    if(type==N2N_MGMT_WRITE) {
        if(argv) {
            setTraceLevel(strtoul(argv, NULL, 0));
        }
    }

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"traceLevel\":%u}\n",
                       tag,
                       getTraceLevel());

    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
}

static void mgmt_communities (n2n_edge_t *eee, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;

    if(eee->conf.header_encryption != HEADER_ENCRYPTION_NONE) {
        mgmt_error(eee, udp_buf, sender_sock, tag, "noaccess");
        return;
    }

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"community\":\"%s\"}",
                       tag,
                       eee->conf.community_name);

    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
}

static void mgmt_supernodes (n2n_edge_t *eee, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;
    struct peer_info *peer, *tmpPeer;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    selection_criterion_str_t sel_buf;

    HASH_ITER(hh, eee->conf.supernodes, peer, tmpPeer) {

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
                           tag,
                           peer->version,
                           peer->purgeable,
                           (peer == eee->curr_sn) ? (eee->sn_wait ? 2 : 1 ) : 0,
                           is_null_mac(peer->mac_addr) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                           sock_to_cstr(sockbuf, &(peer->sock)),
                           sn_selection_criterion_str(eee, sel_buf, peer),
                           peer->last_seen,
                           peer->uptime);

        sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
               (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
    }
}

static void mgmt_edges_row (n2n_edge_t *eee, char *udp_buf, const struct sockaddr_in sender_sock, char *tag, struct peer_info *peer, char *mode) {
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
                       tag,
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

    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0 /*flags*/,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
}

static void mgmt_edges (n2n_edge_t *eee, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    struct peer_info *peer, *tmpPeer;

    // dump nodes with forwarding through supernodes
    HASH_ITER(hh, eee->pending_peers, peer, tmpPeer) {
        mgmt_edges_row(eee, udp_buf, sender_sock, tag, peer, "pSp");
    }

    // dump peer-to-peer nodes
    HASH_ITER(hh, eee->known_peers, peer, tmpPeer) {
        mgmt_edges_row(eee, udp_buf, sender_sock, tag, peer, "p2p");
    }
}

static void mgmt_timestamps (n2n_edge_t *eee, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"start_time\":%lu,"
                       "\"last_super\":%ld,"
                       "\"last_p2p\":%ld}\n",
                       tag,
                       eee->start_time,
                       eee->last_sup,
                       eee->last_p2p);

    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
}

static void mgmt_packetstats (n2n_edge_t *eee, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"transop\","
                       "\"tx_pkt\":%lu,"
                       "\"rx_pkt\":%lu}\n",
                       tag,
                       eee->transop.tx_cnt,
                       eee->transop.rx_cnt);

    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"p2p\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       tag,
                       eee->stats.tx_p2p,
                       eee->stats.rx_p2p);

    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"super\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       tag,
                       eee->stats.tx_sup,
                       eee->stats.rx_sup);

    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"super_broadcast\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       tag,
                       eee->stats.tx_sup_broadcast,
                       eee->stats.rx_sup_broadcast);

    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
}

static void mgmt_unimplemented (n2n_edge_t *eee, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {

    mgmt_error(eee, udp_buf, sender_sock, tag, "unimplemented");
}

static void mgmt_help (n2n_edge_t *eee, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv);

n2n_mgmt_handler_t mgmt_handlers[] = {
    { .cmd = "reload_communities", .flags = FLAG_WROK, .help = "Reserved for supernode", .func = mgmt_unimplemented},

    { .cmd = "stop", .flags = FLAG_WROK, .help = "Gracefully exit edge", .func = mgmt_stop},
    { .cmd = "verbose", .flags = FLAG_WROK, .help = "Manage verbosity level", .func = mgmt_verbose},
    { .cmd = "communities", .help = "Show current community", .func = mgmt_communities},
    { .cmd = "edges", .help = "List current edges/peers", .func = mgmt_edges},
    { .cmd = "supernodes", .help = "List current supernodes", .func = mgmt_supernodes},
    { .cmd = "timestamps", .help = "Event timestamps", .func = mgmt_timestamps},
    { .cmd = "packetstats", .help = "traffic counters", .func = mgmt_packetstats},
    { .cmd = "help", .flags = FLAG_WROK, .help = "Show JSON commands", .func = mgmt_help},
    { .cmd = NULL },
};

static void mgmt_help (n2n_edge_t *eee, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;
    n2n_mgmt_handler_t *handler;

    /*
     * Even though this command is readonly, we deliberately do not check
     * the type - allowing help replies to both read and write requests
     */

    for( handler=mgmt_handlers; handler->cmd; handler++ ) {
        msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                           "{"
                           "\"_tag\":\"%s\","
                           "\"_type\":\"row\","
                           "\"cmd\":\"%s\","
                           "\"help\":\"%s\"}\n",
                           tag,
                           handler->cmd,
                           handler->help);

        sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
               (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
    }
}

/*
 * Check if the user is authorised for this command.
 * - this should be more configurable!
 * - for the moment we use some simple heuristics:
 *   Reads are not dangerous, so they are simply allowed
 *   Writes are possibly dangerous, so they need a fake password
 */
static int mgmt_auth (n2n_edge_t *eee, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *auth, char *argv0, char *argv) {

    if(auth) {
        /* If we have an auth key, it must match */
        if(eee->conf.mgmt_password_hash == pearson_hash_64((uint8_t*)auth, strlen(auth))) {
            return 1;
        }
        return 0;
    }
    /* if we dont have an auth key, we can still read */
    if(type == N2N_MGMT_READ) {
        return 1;
    }

    return 0;
}

void handleMgmtJson (n2n_edge_t *eee, char *udp_buf, const struct sockaddr_in sender_sock) {

    char cmdlinebuf[80];
    enum n2n_mgmt_type type;
    char *typechar;
    char *options;
    char *argv0;
    char *argv;
    char *tag;
    char *flagstr;
    int flags;
    char *auth;
    n2n_mgmt_handler_t *handler;
    size_t msg_len;

    /* save a copy of the commandline before we reuse the udp_buf */
    strncpy(cmdlinebuf, udp_buf, sizeof(cmdlinebuf)-1);
    cmdlinebuf[sizeof(cmdlinebuf)-1] = 0;

    traceEvent(TRACE_DEBUG, "mgmt json %s", cmdlinebuf);

    typechar = strtok(cmdlinebuf, " \r\n");
    if(!typechar) {
        /* should not happen */
        mgmt_error(eee, udp_buf, sender_sock, "-1", "notype");
        return;
    }
    if(*typechar == 'r') {
        type=N2N_MGMT_READ;
    } else if(*typechar == 'w') {
        type=N2N_MGMT_WRITE;
    } else {
        /* dunno how we got here */
        mgmt_error(eee, udp_buf, sender_sock, "-1", "badtype");
        return;
    }

    /* Extract the tag to use in all reply packets */
    options = strtok(NULL, " \r\n");
    if(!options) {
        mgmt_error(eee, udp_buf, sender_sock, "-1", "nooptions");
        return;
    }

    argv0 = strtok(NULL, " \r\n");
    if(!argv0) {
        mgmt_error(eee, udp_buf, sender_sock, "-1", "nocmd");
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
    tag = strtok(options, ":");
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

    if(!mgmt_auth(eee, sender_sock, type, auth, argv0, argv)) {
        mgmt_error(eee, udp_buf, sender_sock, tag, "badauth");
        return;
    }

    for( handler=mgmt_handlers; handler->cmd; handler++ ) {
        if(0 == strcmp(handler->cmd, argv0)) {
            break;
        }
    }
    if(!handler->cmd) {
        mgmt_error(eee, udp_buf, sender_sock, tag, "unknowncmd");
        return;
    }

    if((type==N2N_MGMT_WRITE) && !(handler->flags & FLAG_WROK)) {
        mgmt_error(eee, udp_buf, sender_sock, tag, "readonly");
        return;
    }

    /*
     * TODO:
     * The tag provided by the requester could contain chars
     * that make our JSON invalid.
     * - do we care?
     */
    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{\"_tag\":\"%s\",\"_type\":\"begin\",\"cmd\":\"%s\"}\n", tag, argv0);
    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));

    handler->func(eee, udp_buf, sender_sock, type, tag, argv0, argv);

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{\"_tag\":\"%s\",\"_type\":\"end\"}\n", tag);
    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
    return;
}
