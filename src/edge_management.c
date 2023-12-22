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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#include "n2n.h"           // for n2n_edge_t, peer_info, getTraceLevel, N2N_...
// FIXME: if this headers is sorted alphabetically, the test_integration_edge
// fails with what looks like a struct rearrangement involving eee->stats

#include <errno.h>         // for errno
#include <stdbool.h>
#include <stdint.h>        // for uint32_t
#include <stdio.h>         // for snprintf, size_t, NULL
#include <string.h>        // for memcmp, memcpy, strerror, strncpy
#include <sys/types.h>     // for ssize_t
#include <time.h>          // for time, time_t
#include "config.h"        // for PACKAGE_VERSION
#include "management.h"    // for mgmt_req_t, send_reply, send_json_1str
#include "n2n_define.h"    // for N2N_PKT_BUF_SIZE, N2N_EVENT_DEBUG, N2N_EVE...
#include "n2n_typedefs.h"  // for n2n_edge_t, peer_info, n2n_edge_conf_t
#include "sn_selection.h"  // for sn_selection_criterion_str, selection_crit...
#include "strbuf.h"        // for strbuf_t, STRBUF_INIT
#include "uthash.h"        // for UT_hash_handle, HASH_ITER

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>     // for inet_ntoa
#include <netinet/in.h>    // for in_addr, htonl, in_addr_t
#include <sys/socket.h>    // for sendto, recvfrom, sockaddr_storage
#endif

size_t event_debug (strbuf_t *buf, char *tag, int data0, void *data1) {
    traceEvent(TRACE_DEBUG, "Unexpected call to event_debug");
    return 0;
}

size_t event_test (strbuf_t *buf, char *tag, int data0, void *data1) {
    size_t msg_len = gen_json_1str(buf, tag, "event", "test", (char *)data1);
    return msg_len;
}

size_t event_peer (strbuf_t *buf, char *tag, int data0, void *data1) {
    int action = data0;
    struct peer_info *peer = (struct peer_info *)data1;

    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    /*
     * Just the peer_info bits that are needed for lookup (maccaddr) or
     * firewall and routing (sockaddr)
     * If needed, other details can be fetched via the edges method call.
     */
    return snprintf(buf->str, buf->size,
                    "{"
                    "\"_tag\":\"%s\","
                    "\"_type\":\"event\","
                    "\"action\":%i,"
                    "\"macaddr\":\"%s\","
                    "\"sockaddr\":\"%s\"}\n",
                    tag,
                    action,
                    (is_null_mac(peer->mac_addr)) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                    sock_to_cstr(sockbuf, &(peer->sock)));
}



static void mgmt_communities (mgmt_req_t *req, strbuf_t *buf) {

    if(req->eee->conf.header_encryption != HEADER_ENCRYPTION_NONE) {
        mgmt_error(req, buf, "noaccess");
        return;
    }

    send_json_1str(req, buf, "row", "community", (char *)req->eee->conf.community_name);
}

static void mgmt_supernodes (mgmt_req_t *req, strbuf_t *buf) {
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

        msg_len = snprintf(buf->str, buf->size,
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

        send_reply(req, buf, msg_len);
    }
}

static void mgmt_edges_row (mgmt_req_t *req, strbuf_t *buf, struct peer_info *peer, char *mode) {
    size_t msg_len;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    msg_len = snprintf(buf->str, buf->size,
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

    send_reply(req, buf, msg_len);
}

static void mgmt_edges (mgmt_req_t *req, strbuf_t *buf) {
    struct peer_info *peer, *tmpPeer;

    // dump nodes with forwarding through supernodes
    HASH_ITER(hh, req->eee->pending_peers, peer, tmpPeer) {
        mgmt_edges_row(req, buf, peer, "pSp");
    }

    // dump peer-to-peer nodes
    HASH_ITER(hh, req->eee->known_peers, peer, tmpPeer) {
        mgmt_edges_row(req, buf, peer, "p2p");
    }
}

static void mgmt_edge_info (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;
    macstr_t mac_buf;
    struct in_addr ip_addr, ip_addr_mask;
    ipstr_t ip_address, ip_address_mask;
    n2n_sock_str_t sockbuf;

    ip_addr.s_addr = req->eee->device.ip_addr;
    inaddrtoa(ip_address, ip_addr);
    ip_addr_mask.s_addr = req->eee->device.device_mask;
    inaddrtoa(ip_address_mask, ip_addr_mask);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"version\":\"%s\","
                       "\"macaddr\":\"%s\","
                       "\"ip4addr\":\"%s\","
                       "\"ip4netmask\":\"%s\","
                       "\"sockaddr\":\"%s\"}\n",
                       req->tag,
                       PACKAGE_VERSION,
                       is_null_mac(req->eee->device.mac_addr) ? "" : macaddr_str(mac_buf, req->eee->device.mac_addr),
                       ip_address, ip_address_mask,
                       sock_to_cstr(sockbuf, &req->eee->conf.preferred_sock));

    send_reply(req, buf, msg_len);
}

static void mgmt_timestamps (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;

    msg_len = snprintf(buf->str, buf->size,
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

    send_reply(req, buf, msg_len);
}

static void mgmt_packetstats (mgmt_req_t *req, strbuf_t *buf) {
    size_t msg_len;

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"transop\","
                       "\"tx_pkt\":%lu,"
                       "\"rx_pkt\":%lu}\n",
                       req->tag,
                       req->eee->transop.tx_cnt,
                       req->eee->transop.rx_cnt);

    send_reply(req, buf, msg_len);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"p2p\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_p2p,
                       req->eee->stats.rx_p2p);

    send_reply(req, buf, msg_len);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"super\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_sup,
                       req->eee->stats.rx_sup);

    send_reply(req, buf, msg_len);

    msg_len = snprintf(buf->str, buf->size,
                       "{"
                       "\"_tag\":\"%s\","
                       "\"_type\":\"row\","
                       "\"type\":\"super_broadcast\","
                       "\"tx_pkt\":%u,"
                       "\"rx_pkt\":%u}\n",
                       req->tag,
                       req->eee->stats.tx_sup_broadcast,
                       req->eee->stats.rx_sup_broadcast);

    send_reply(req, buf, msg_len);
}

static void mgmt_post_test (mgmt_req_t *req, strbuf_t *buf) {

    send_json_1str(req, buf, "row", "sending", "test");
    mgmt_event_post(N2N_EVENT_TEST, -1, req->argv);
}

// Forward define so we can include this in the mgmt_handlers[] table
static void mgmt_help (mgmt_req_t *req, strbuf_t *buf);
static void mgmt_help_events (mgmt_req_t *req, strbuf_t *buf);

static const mgmt_handler_t mgmt_handlers[] = {
    { .cmd = "reload_communities", .flags = FLAG_WROK, .help = "Reserved for supernode", .func = mgmt_unimplemented},

    { .cmd = "stop", .flags = FLAG_WROK, .help = "Gracefully exit edge", .func = mgmt_stop},
    { .cmd = "verbose", .flags = FLAG_WROK, .help = "Manage verbosity level", .func = mgmt_verbose},
    { .cmd = "communities", .help = "Show current community", .func = mgmt_communities},
    { .cmd = "edges", .help = "List current edges/peers", .func = mgmt_edges},
    { .cmd = "supernodes", .help = "List current supernodes", .func = mgmt_supernodes},
    { .cmd = "info", .help = "Provide basic edge information", .func = mgmt_edge_info},
    { .cmd = "timestamps", .help = "Event timestamps", .func = mgmt_timestamps},
    { .cmd = "packetstats", .help = "traffic counters", .func = mgmt_packetstats},
    { .cmd = "post.test", .help = "send a test event", .func = mgmt_post_test},
    { .cmd = "help", .flags = FLAG_WROK, .help = "Show JSON commands", .func = mgmt_help},
    { .cmd = "help.events", .help = "Show available Subscribe topics", .func = mgmt_help_events},
};

/* Current subscriber for each event topic */
static mgmt_req_t mgmt_event_subscribers[] = {
    [N2N_EVENT_DEBUG] = { .eee = NULL, .type = N2N_MGMT_UNKNOWN, .tag = "\0" },
    [N2N_EVENT_TEST] = { .eee = NULL, .type = N2N_MGMT_UNKNOWN, .tag = "\0" },
    [N2N_EVENT_PEER] = { .eee = NULL, .type = N2N_MGMT_UNKNOWN, .tag = "\0" },
};

/* Map topic number to function */
// TODO: want this to be const
static mgmt_event_handler_t *mgmt_events[] = {
    [N2N_EVENT_DEBUG] = event_debug,
    [N2N_EVENT_TEST] = event_test,
    [N2N_EVENT_PEER] = event_peer,
};

/* Allow help and subscriptions to use topic name */
static const mgmt_events_t mgmt_event_names[] = {
    { .cmd = "debug", .topic = N2N_EVENT_DEBUG, .help = "All events - for event debugging"},
    { .cmd = "test", .topic = N2N_EVENT_TEST, .help = "Used only by post.test"},
    { .cmd = "peer", .topic = N2N_EVENT_PEER, .help = "Changes to peer list"},
};

void mgmt_event_post (enum n2n_event_topic topic, int data0, void *data1) {
    mgmt_req_t *debug = &mgmt_event_subscribers[N2N_EVENT_DEBUG];
    mgmt_req_t *sub = &mgmt_event_subscribers[topic];
    mgmt_event_handler_t *fn =  mgmt_events[topic];

    mgmt_event_post2(topic, data0, data1, debug, sub, fn);
}

static void mgmt_help_events (mgmt_req_t *req, strbuf_t *buf) {
    int i;
    int nr_handlers = sizeof(mgmt_event_names) / sizeof(mgmt_events_t);
    for( i=0; i < nr_handlers; i++ ) {
        int topic = mgmt_event_names[i].topic;
        mgmt_req_t *sub = &mgmt_event_subscribers[topic];

        mgmt_help_events_row(req, buf, sub, mgmt_event_names[i].cmd, mgmt_event_names[i].help);
    }
}

// TODO: want to keep the mgmt_handlers defintion const static, otherwise
// this whole function could be shared
static void mgmt_help (mgmt_req_t *req, strbuf_t *buf) {
    /*
     * Even though this command is readonly, we deliberately do not check
     * the type - allowing help replies to both read and write requests
     */

    int i;
    int nr_handlers = sizeof(mgmt_handlers) / sizeof(mgmt_handler_t);
    for( i=0; i < nr_handlers; i++ ) {
        mgmt_help_row(req, buf, mgmt_handlers[i].cmd, mgmt_handlers[i].help);
    }
}

static void handleMgmtJson (mgmt_req_t *req, char *udp_buf, const int recvlen) {

    strbuf_t *buf;
    char cmdlinebuf[80];

    /* save a copy of the commandline before we reuse the udp_buf */
    strncpy(cmdlinebuf, udp_buf, sizeof(cmdlinebuf)-1);
    cmdlinebuf[sizeof(cmdlinebuf)-1] = 0;

    traceEvent(TRACE_DEBUG, "mgmt json %s", cmdlinebuf);

    /* we reuse the buffer already on the stack for all our strings */
    STRBUF_INIT(buf, udp_buf, N2N_SN_PKTBUF_SIZE);

    if(!mgmt_req_init2(req, buf, (char *)&cmdlinebuf)) {
        // if anything failed during init
        return;
    }

    if(req->type == N2N_MGMT_SUB) {
        int handler;
        lookup_handler(handler, mgmt_event_names, req->argv0);
        if(handler == -1) {
            mgmt_error(req, buf, "unknowntopic");
            return;
        }

        int topic = mgmt_event_names[handler].topic;
        if(mgmt_event_subscribers[topic].type == N2N_MGMT_SUB) {
            send_json_1str(&mgmt_event_subscribers[topic], buf,
                           "unsubscribed", "topic", req->argv0);
            send_json_1str(req, buf, "replacing", "topic", req->argv0);
        }

        memcpy(&mgmt_event_subscribers[topic], req, sizeof(*req));

        send_json_1str(req, buf, "subscribe", "topic", req->argv0);
        return;
    }

    int handler;
    lookup_handler(handler, mgmt_handlers, req->argv0);
    if(handler == -1) {
        mgmt_error(req, buf, "unknowncmd");
        return;
    }

    if((req->type==N2N_MGMT_WRITE) && !(mgmt_handlers[handler].flags & FLAG_WROK)) {
        mgmt_error(req, buf, "readonly");
        return;
    }

    /*
     * TODO:
     * The tag provided by the requester could contain chars
     * that make our JSON invalid.
     * - do we care?
     */
    send_json_1str(req, buf, "begin", "cmd", req->argv0);

    mgmt_handlers[handler].func(req, buf);

    send_json_1str(req, buf, "end", "cmd", req->argv0);
    return;
}

/** Read a datagram from the management UDP socket and take appropriate
 *    action. */
void readFromMgmtSocket (n2n_edge_t *eee) {

    char udp_buf[N2N_PKT_BUF_SIZE]; /* Compete UDP packet */
    ssize_t recvlen;
    /* ssize_t sendlen; */
    mgmt_req_t req;
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

    req.sss = NULL;
    req.eee = eee;
    req.mgmt_sock = eee->udp_mgmt_sock;
    req.keep_running = eee->keep_running;
    req.mgmt_password_hash = eee->conf.mgmt_password_hash;
    req.sock_len = sizeof(req.sas);

    now = time(NULL);
    recvlen = recvfrom(eee->udp_mgmt_sock, udp_buf, N2N_PKT_BUF_SIZE, 0 /*flags*/,
                       &req.sender_sock, &req.sock_len);

    if(recvlen < 0) {
        traceEvent(TRACE_WARNING, "mgmt recvfrom failed: %d - %s", errno, strerror(errno));
        return; /* failed to receive data from UDP */
    }

    /* avoid parsing any uninitialized junk from the stack */
    udp_buf[recvlen] = 0;

    if((0 == memcmp(udp_buf, "help", 4)) || (0 == memcmp(udp_buf, "?", 1))) {
        strbuf_t *buf;
        STRBUF_INIT(buf, &udp_buf, sizeof(udp_buf));
        msg_len = snprintf(buf->str, buf->size,
                           "Help for edge management console:\n"
                           "\tstop    | Gracefully exit edge\n"
                           "\thelp    | This help message\n"
                           "\t+verb   | Increase verbosity of logging\n"
                           "\t-verb   | Decrease verbosity of logging\n"
                           "\tr ...   | start query with JSON reply\n"
                           "\tw ...   | start update with JSON reply\n"
                           "\ts ...   | subscribe to event channel JSON reply\n"
                           "\t<enter> | Display statistics\n\n");

        send_reply(&req, buf, msg_len);

        return;
    }

    if(0 == memcmp(udp_buf, "stop", 4)) {
        traceEvent(TRACE_NORMAL, "stop command received");
        *eee->keep_running = false;
        return;
    }

    if(0 == memcmp(udp_buf, "+verb", 5)) {
        setTraceLevel(getTraceLevel() + 1);

        traceEvent(TRACE_NORMAL, "+verb traceLevel=%u", (unsigned int) getTraceLevel());

        strbuf_t *buf;
        STRBUF_INIT(buf, &udp_buf, sizeof(udp_buf));
        msg_len = snprintf(buf->str, buf->size,
                           "> +OK traceLevel=%u\n", (unsigned int) getTraceLevel());

        send_reply(&req, buf, msg_len);

        return;
    }

    if(0 == memcmp(udp_buf, "-verb", 5)) {
        strbuf_t *buf;
        STRBUF_INIT(buf, &udp_buf, sizeof(udp_buf));

        if(getTraceLevel() > 0) {
            setTraceLevel(getTraceLevel() - 1);
            msg_len = snprintf(buf->str, buf->size,
                               "> -OK traceLevel=%u\n", getTraceLevel());
        } else {
            msg_len = snprintf(buf->str, buf->size,
                               "> -NOK traceLevel=%u\n", getTraceLevel());
        }

        traceEvent(TRACE_NORMAL, "-verb traceLevel=%u", (unsigned int) getTraceLevel());

        send_reply(&req, buf, msg_len);
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

        sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
               &req.sender_sock, req.sock_len);
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

        sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
               &req.sender_sock, req.sock_len);
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
                            (peer->purgeable) ? "" : "l",
                            (peer == eee->curr_sn) ? (eee->sn_wait ? "." : "*" ) : "",
                            is_null_mac(peer->mac_addr) ? "" : macaddr_str(mac_buf, peer->mac_addr),
                            sock_to_cstr(sockbuf, &(peer->sock)),
                            sn_selection_criterion_str(eee, sel_buf, peer),
                            (peer->last_seen) ? time_buf : "",
                            (peer->uptime) ? uptime_buf : "");

        sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
               &req.sender_sock, req.sock_len);
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

    sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0,
           &req.sender_sock, req.sock_len);
}
