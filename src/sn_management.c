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

/*
 * This file has a large amount of duplication with the edge_management.c
 * code.  In the fullness of time, they should both be merged
 */

#include "n2n.h"
#include "edge_utils_win32.h"

int load_allowed_sn_community (n2n_sn_t *sss); /* defined in sn_utils.c */

#define FLAG_WROK 1
typedef struct mgmt_handler {
    int flags;
    char  *cmd;
    char  *help;
    void (*func)(n2n_sn_t *sss, char *udp_buf, struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv);
} mgmt_handler_t;

static void mgmt_error (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, char *tag, char *msg) {
    size_t msg_len;
    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"error\","
                       "\"error\":\"%s\"}\n",
                       tag,
                       msg);
    sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
}

static void mgmt_stop (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;

    if(type==N2N_MGMT_WRITE) {
        *sss->keep_running = 0;
    }

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"keep_running\":%u}\n",
                       tag,
                       *sss->keep_running);

    sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
}

static void mgmt_verbose (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
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

    sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
}

static void mgmt_reload_communities (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;

    if(type!=N2N_MGMT_WRITE) {
        mgmt_error(sss, udp_buf, sender_sock, tag, "writeonly");
        return;
    }

    if(!sss->community_file) {
        mgmt_error(sss, udp_buf, sender_sock, tag, "nofile");
        return;
    }

    int ok = load_allowed_sn_community(sss);

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"ok\":%i}\n",
                       tag,
                       ok);

    sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
}

static void mgmt_timestamps (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"start_time\":%lu,"
                       "\"last_fwd\":%ld,"
                       "\"last_reg_super\":%ld}\n",
                       tag,
                       sss->start_time,
                       sss->stats.last_fwd,
                       sss->stats.last_reg_super);

    sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
}

static void mgmt_packetstats (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"forward\","
                       "\"tx_pkt\":%lu}\n",
                       tag,
                       sss->stats.fwd);

    sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"broadcast\","
                       "\"tx_pkt\":%lu}\n",
                       tag,
                       sss->stats.broadcast);

    sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"reg_super\","
                       "\"rx_pkt\":%lu,"
                       "\"nak\":%lu}\n",
                       tag,
                       sss->stats.reg_super,
                       sss->stats.reg_super_nak);

    /* Note: reg_super_nak is not currently incremented anywhere */

    sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));

    /* Generic errors when trying to sendto() */
    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"errors\","
                       "\"tx_pkt\":%lu}\n",
                       tag,
                       sss->stats.errors);

    sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));

}

static void mgmt_communities (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;
    struct sn_community *community, *tmp;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    HASH_ITER(hh, sss->communities, community, tmp) {

        msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                           "{"
                           "\"_tag\":\"%s\","
                           "\"_type\":\"row\","
                           "\"community\":\"%s\","
                           "\"purgeable\":%i,"
                           "\"is_federation\":%i,"
                           "\"ip4addr\":\"%s\"}\n",
                           tag,
                           (community->is_federation) ? "-/-" : community->community,
                           community->purgeable,
                           community->is_federation,
                           (community->auto_ip_net.net_addr == 0) ? "" : ip_subnet_to_str(ip_bit_str, &community->auto_ip_net));


        sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
               (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
    }
}

static void mgmt_edges (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;
    struct sn_community *community, *tmp;
    struct peer_info *peer, *tmpPeer;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    HASH_ITER(hh, sss->communities, community, tmp) {
        HASH_ITER(hh, community->edges, peer, tmpPeer) {

            msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                               "{"
                               "\"_tag\":\"%s\","
                               "\"_type\":\"row\","
                               "\"community\":\"%s\","
                               "\"ip4addr\":\"%s\","
                               "\"purgeable\":%i,"
                               "\"macaddr\":\"%s\","
                               "\"sockaddr\":\"%s\","
                               "\"proto\":\"%s\","
                               "\"desc\":\"%s\","
                               "\"last_seen\":%li}\n",
                               tag,
                               (community->is_federation) ? "-/-" : community->community,
                               (peer->dev_addr.net_addr == 0) ? "" : ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
                               peer->purgeable,
                               (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                               sock_to_cstr(sockbuf, &(peer->sock)),
                               ((peer->socket_fd >= 0) && (peer->socket_fd != sss->sock)) ? "TCP" : "UDP",
                               peer->dev_desc,
                               peer->last_seen);

            sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
                   (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
        }
    }
}

static void mgmt_unimplemented (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    mgmt_error(sss, udp_buf, sender_sock, tag, "unimplemented");
}

static void mgmt_help (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv);

mgmt_handler_t mgmt_handlers[] = {
    { .cmd = "supernodes", .help = "Reserved for edge", .func = mgmt_unimplemented},

    { .cmd = "stop", .flags = FLAG_WROK, .help = "Gracefully exit edge", .func = mgmt_stop},
    { .cmd = "verbose", .flags = FLAG_WROK, .help = "Manage verbosity level", .func = mgmt_verbose},
    { .cmd = "reload_communities", .flags = FLAG_WROK, .help = "Reloads communities and user's public keys", .func = mgmt_reload_communities},
    { .cmd = "communities", .help = "List current communities", .func = mgmt_communities},
    { .cmd = "edges", .help = "List current edges/peers", .func = mgmt_edges},
    { .cmd = "timestamps", .help = "Event timestamps", .func = mgmt_timestamps},
    { .cmd = "packetstats", .help = "Traffic statistics", .func = mgmt_packetstats},
    { .cmd = "help", .flags = FLAG_WROK, .help = "Show JSON commands", .func = mgmt_help},
    { .cmd = NULL },
};

static void mgmt_help (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;
    mgmt_handler_t *handler;

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

        sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
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
static int mgmt_auth (n2n_sn_t *sss, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *auth, char *argv0, char *argv) {

    if(auth) {
        /* If we have an auth key, it must match */
        if(sss->mgmt_password_hash == pearson_hash_64((uint8_t*)auth, strlen(auth))) {
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

static void handleMgmtJson (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock) {

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
    mgmt_handler_t *handler;
    size_t msg_len;

    /* save a copy of the commandline before we reuse the udp_buf */
    strncpy(cmdlinebuf, udp_buf, sizeof(cmdlinebuf)-1);
    cmdlinebuf[sizeof(cmdlinebuf)-1] = 0;

    traceEvent(TRACE_DEBUG, "mgmt json %s", cmdlinebuf);

    typechar = strtok(cmdlinebuf, " \r\n");
    if(!typechar) {
        /* should not happen */
        mgmt_error(sss, udp_buf, sender_sock, "-1", "notype");
        return;
    }
    if(*typechar == 'r') {
        type=N2N_MGMT_READ;
    } else if(*typechar == 'w') {
        type=N2N_MGMT_WRITE;
    } else {
        /* dunno how we got here */
        mgmt_error(sss, udp_buf, sender_sock, "-1", "badtype");
        return;
    }

    /* Extract the tag to use in all reply packets */
    options = strtok(NULL, " \r\n");
    if(!options) {
        mgmt_error(sss, udp_buf, sender_sock, "-1", "nooptions");
        return;
    }

    argv0 = strtok(NULL, " \r\n");
    if(!argv0) {
        mgmt_error(sss, udp_buf, sender_sock, "-1", "nocmd");
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

    if(!mgmt_auth(sss, sender_sock, type, auth, argv0, argv)) {
        mgmt_error(sss, udp_buf, sender_sock, tag, "badauth");
        return;
    }

    for( handler=mgmt_handlers; handler->cmd; handler++ ) {
        if(0 == strcmp(handler->cmd, argv0)) {
            break;
        }
    }
    if(!handler->cmd) {
        mgmt_error(sss, udp_buf, sender_sock, tag, "unknowncmd");
        return;
    }

    if((type==N2N_MGMT_WRITE) && !(handler->flags & FLAG_WROK)) {
        mgmt_error(sss, udp_buf, sender_sock, tag, "readonly");
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
    sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));

    handler->func(sss, udp_buf, sender_sock, type, tag, argv0, argv);

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{\"_tag\":\"%s\",\"_type\":\"end\"}\n", tag);
    sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
    return;
}

static int sendto_mgmt (n2n_sn_t *sss,
                        const struct sockaddr_in *sender_sock,
                        const uint8_t *mgmt_buf,
                        size_t mgmt_size) {

    ssize_t r = sendto(sss->mgmt_sock, (void *)mgmt_buf, mgmt_size, 0 /*flags*/,
                       (struct sockaddr *)sender_sock, sizeof (struct sockaddr_in));

    if(r <= 0) {
        ++(sss->stats.errors);
        traceEvent(TRACE_ERROR, "sendto_mgmt : sendto failed. %s", strerror(errno));
        return -1;
    }

    return 0;
}

int process_mgmt (n2n_sn_t *sss,
                  const struct sockaddr_in *sender_sock,
                  char *mgmt_buf,
                  size_t mgmt_size,
                  time_t now) {

    char resbuf[N2N_SN_PKTBUF_SIZE];
    size_t ressize = 0;
    uint32_t num_edges = 0;
    uint32_t num_comm = 0;
    uint32_t num = 0;
    struct sn_community *community, *tmp;
    struct peer_info *peer, *tmpPeer;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    char time_buf[10]; /* 9 digits + 1 terminating zero */
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    traceEvent(TRACE_DEBUG, "process_mgmt");

    /* avoid parsing any uninitialized junk from the stack */
    mgmt_buf[mgmt_size] = 0;

    // process input, if any
    if((0 == memcmp(mgmt_buf, "help", 4)) || (0 == memcmp(mgmt_buf, "?", 1))) {
        ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                            "Help for supernode management console:\n"
                            "\thelp                 | This help message\n"
                            "\treload_communities   | Reloads communities and user's public keys\n"
                            "\t<enter>              | Display status and statistics\n");
        sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);
        return 0; /* no status output afterwards */
    }

    if(0 == memcmp(mgmt_buf, "reload_communities", 18)) {
        if(!sss->community_file) {
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "No community file provided (-c command line option)\n");
            sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);
            return 0; /* no status output afterwards */
        }
        traceEvent(TRACE_NORMAL, "'reload_communities' command");

        if(load_allowed_sn_community(sss)) {
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "Error while re-loading community file (not found or no valid content)\n");
            sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);
            return 0; /* no status output afterwards */
        }
        ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                            "OK.\n");
        sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);
        return 0; /* no status output afterwards */
    }

    if((mgmt_buf[0] == 'r' || mgmt_buf[0] == 'w') && (mgmt_buf[1] == ' ')) {
        /* this is a JSON request */
        handleMgmtJson(sss, mgmt_buf, *sender_sock);
        return 0;
    }

    // output current status

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        " ### | TAP                 | MAC               | EDGE                      | HINT            | LAST SEEN\n");
    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "========================================================================================================\n");
    HASH_ITER(hh, sss->communities, community, tmp) {
        if(num_comm)
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "--------------------------------------------------------------------------------------------------------\n");
        num_comm++;
        num_edges += HASH_COUNT(community->edges);

        ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                            "%s '%s'\n",
                            (community->is_federation) ? "FEDERATION" : ((community->purgeable == COMMUNITY_UNPURGEABLE) ? "FIXED NAME COMMUNITY" : "COMMUNITY"),
                            (community->is_federation) ? "-/-" : community->community);
        sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);
        ressize = 0;

        num = 0;
        HASH_ITER(hh, community->edges, peer, tmpPeer) {
            sprintf(time_buf, "%9u", (unsigned int)(now - peer->last_seen));
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "%4u | %-19s | %-17s | %-21s %-3s | %-15s | %9s\n",
                                ++num,
                                (peer->dev_addr.net_addr == 0) ? ((peer->purgeable == SN_UNPURGEABLE) ? "-l" : "") : ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
                                (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                                sock_to_cstr(sockbuf, &(peer->sock)),
                                ((peer->socket_fd >= 0) && (peer->socket_fd != sss->sock)) ? "TCP" : "",
                                peer->dev_desc,
                                (peer->last_seen) ? time_buf : "");

            sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);
            ressize = 0;
        }
    }
    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "========================================================================================================\n");

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "uptime %lu | ", (now - sss->start_time));

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "edges %u | ",
                        num_edges);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "reg_sup %u | ",
                        (unsigned int) sss->stats.reg_super);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "reg_nak %u | ",
                        (unsigned int) sss->stats.reg_super_nak);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "errors %u \n",
                        (unsigned int) sss->stats.errors);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "fwd %u | ",
                        (unsigned int) sss->stats.fwd);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "broadcast %u | ",
                        (unsigned int) sss->stats.broadcast);

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "cur_cmnts %u\n", HASH_COUNT(sss->communities));

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "last_fwd  %lu sec ago | ",
                        (long unsigned int) (now - sss->stats.last_fwd));

    ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                        "last reg  %lu sec ago\n\n",
                        (long unsigned int) (now - sss->stats.last_reg_super));

    sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);

    return 0;
}
