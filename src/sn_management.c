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

typedef struct n2n_mgmt_handler {
    char  *cmd;
    char  *help;
    void (*func)(n2n_sn_t *sss, char *udp_buf, struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv);
} n2n_mgmt_handler_t;

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

static void mgmt_verbose (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;

    if(type==N2N_MGMT_WRITE) {
        setTraceLevel(strtoul(argv, NULL, 0));
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

    if(type==N2N_MGMT_WRITE) {
        mgmt_error(sss, udp_buf, sender_sock, tag, "readonly");
        return;
    }

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"start_time\":%lu,"
                       "\"last_fwd\":%ld,"
                       "\"last_reg\":%ld}\n",
                       tag,
                       sss->start_time,
                       sss->stats.last_fwd,
                       sss->stats.last_reg_super);

    sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));
}

static void mgmt_stats (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;

    if(type==N2N_MGMT_WRITE) {
        mgmt_error(sss, udp_buf, sender_sock, tag, "readonly");
        return;
    }

    msg_len = snprintf(udp_buf, N2N_PKT_BUF_SIZE,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"reg_sup\":%lu,"
                       "\"reg_nak\":%lu,"
                       "\"errors\":%lu,"
                       "\"fwd\":%lu,"
                       "\"broadcast\":%lu,"
                       "\"cur_cmnts\":%u}\n",
                       tag,
                       sss->stats.reg_super,
                       sss->stats.reg_super_nak,
                       sss->stats.errors,
                       sss->stats.fwd,
                       sss->stats.broadcast,
                       HASH_COUNT(sss->communities));

    sendto(sss->mgmt_sock, udp_buf, msg_len, 0,
           (struct sockaddr *) &sender_sock, sizeof(struct sockaddr_in));

}

static void mgmt_communities (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;
    struct sn_community *community, *tmp;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    if(type!=N2N_MGMT_READ) {
        mgmt_error(sss, udp_buf, sender_sock, tag, "readonly");
        return;
    }

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


    if(type!=N2N_MGMT_READ) {
        mgmt_error(sss, udp_buf, sender_sock, tag, "readonly");
        return;
    }

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

n2n_mgmt_handler_t mgmt_handlers[] = {
    { .cmd = "stop", .help = "Reserved", .func = mgmt_unimplemented},
    { .cmd = "community", .help = "Reserved for edge", .func = mgmt_unimplemented},
    { .cmd = "super", .help = "Reserved for edge", .func = mgmt_unimplemented},

    { .cmd = "verbose", .help = "Manage verbosity level", .func = mgmt_verbose},
    { .cmd = "reload_communities", .help = "Reloads communities and user's public keys", .func = mgmt_reload_communities},
    { .cmd = "communities", .help = "List current communities", .func = mgmt_communities},
    { .cmd = "edges", .help = "List current edges/peers", .func = mgmt_edges},
    { .cmd = "timestamps", .help = "Event timestamps", .func = mgmt_timestamps},
    { .cmd = "stats", .help = "Usage statistics", .func = mgmt_stats},
    { .cmd = "help", .help = "Show JSON commands", .func = mgmt_help},
    { .cmd = NULL },
};

static void mgmt_help (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *tag, char *argv0, char *argv) {
    size_t msg_len;
    n2n_mgmt_handler_t *handler;

    /*
     * Even though this command is readonly, we deliberately do not check
     * the type - allowing help replys to both read and write requests
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
static int mgmt_auth (const struct sockaddr_in sender_sock, enum n2n_mgmt_type type, char *auth, char *argv0, char *argv) {
    if(auth) {
        /* If we have an auth key, it must match */
        if(0 == strcmp(auth,"CHANGEME")) {
            return 1;
        }
        return 0;
    }
    /* if we dont have an auth key, we can still read */
    if(type==N2N_MGMT_READ) {
        return 1;
    }
    return 0;
}

void handleMgmtJson_sn (n2n_sn_t *sss, char *udp_buf, const struct sockaddr_in sender_sock) {

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

    if(!mgmt_auth(sender_sock, type, auth, argv0, argv)) {
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
