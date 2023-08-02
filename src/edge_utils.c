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


#include <errno.h>                   // for errno, EAFNOSUPPORT, EINPROGRESS
#include <fcntl.h>                   // for fcntl, F_SETFL, O_NONBLOCK
#include <stdbool.h>
#include <stdint.h>                  // for uint8_t, uint16_t, uint32_t, uin...
#include <stdio.h>                   // for snprintf, sprintf
#include <stdlib.h>                  // for free, calloc, getenv
#include <string.h>                  // for memcpy, memset, NULL, memcmp
#include <sys/time.h>                // for timeval
#include <sys/types.h>               // for time_t, ssize_t, u_int
#include <time.h>                    // for time
#include <unistd.h>                  // for gethostname, sleep
#include "auth.h"                    // for generate_private_key
#include "portable_endian.h"         // for be16toh, htobe16
#include "header_encryption.h"       // for packet_header_encrypt, packet_he...
#include "n2n.h"                     // for n2n_edge_t, peer_info, n2n_edge_...
#include "n2n_wire.h"                // for encode_mac, fill_sockaddr, decod...
#include "network_traffic_filter.h"  // for create_network_traffic_filter
#include "pearson.h"                 // for pearson_hash_128, pearson_hash_64
#include "random_numbers.h"          // for n2n_rand, n2n_rand_sqr
#include "sn_selection.h"            // for sn_selection_criterion_common_da...
#include "speck.h"                   // for speck_128_decrypt, speck_128_enc...
#include "uthash.h"                  // for UT_hash_handle, HASH_COUNT, HASH...

#ifdef _WIN32
#include "win32/defs.h"
#include "win32/edge_utils_win32.h"
#else
#include <arpa/inet.h>               // for inet_ntoa, inet_addr, inet_ntop
#include <netinet/in.h>              // for sockaddr_in, ntohl, IPPROTO_IP
#include <netinet/tcp.h>             // for TCP_NODELAY
#include <sys/select.h>              // for select, FD_SET, FD_ISSET, FD_ZERO
#include <sys/socket.h>              // for setsockopt, AF_INET, connect
#endif


/* ************************************** */

int resolve_create_thread (n2n_resolve_parameter_t **param, struct peer_info *sn_list);
int resolve_check (n2n_resolve_parameter_t *param, uint8_t resolution_request, time_t now);
int resolve_cancel_thread (n2n_resolve_parameter_t *param);

static const char * supernode_ip (const n2n_edge_t * eee);
static void send_register (n2n_edge_t *eee, const n2n_sock_t *remote_peer, const n2n_mac_t peer_mac, n2n_cookie_t cookie);

static void check_peer_registration_needed (n2n_edge_t *eee,
                                            uint8_t from_supernode,
                                            uint8_t via_multicast,
                                            const n2n_mac_t mac,
                                            const n2n_cookie_t cookie,
                                            const n2n_ip_subnet_t *dev_addr,
                                            const n2n_desc_t *dev_desc,
                                            const n2n_sock_t *peer);

static int edge_init_sockets (n2n_edge_t *eee);

static void check_known_peer_sock_change (n2n_edge_t *eee,
                                          uint8_t from_supernode,
                                          uint8_t via_multicast,
                                          const n2n_mac_t mac,
                                          const n2n_ip_subnet_t *dev_addr,
                                          const n2n_desc_t *dev_desc,
                                          const n2n_sock_t *peer,
                                          time_t when);

/* ************************************** */

int edge_verify_conf (const n2n_edge_conf_t *conf) {

    if(conf->community_name[0] == 0)
        return -1;

    // REVISIT: are the following two conditions equal? if so, remove one. but note that sn_num is used elsewhere
    if(conf->sn_num == 0)
        return -2;

    if(HASH_COUNT(conf->supernodes) == 0)
        return -5;

    if(conf->register_interval < 1)
        return -3;

    if(((conf->encrypt_key == NULL) && (conf->transop_id != N2N_TRANSFORM_ID_NULL)) ||
       ((conf->encrypt_key != NULL) && (conf->transop_id == N2N_TRANSFORM_ID_NULL)))
        return -4;

    return 0;
}


/* ************************************** */

void edge_set_callbacks (n2n_edge_t *eee, const n2n_edge_callbacks_t *callbacks) {

    memcpy(&eee->cb, callbacks, sizeof(n2n_edge_callbacks_t));
}

/* ************************************** */

void edge_set_userdata (n2n_edge_t *eee, void *user_data) {

    eee->user_data = user_data;
}

/* ************************************** */

void* edge_get_userdata (n2n_edge_t *eee) {

    return(eee->user_data);
}

/* ************************************** */

int edge_get_n2n_socket (n2n_edge_t *eee) {

    return(eee->sock);
}

/* ************************************** */

int edge_get_management_socket (n2n_edge_t *eee) {

    return(eee->udp_mgmt_sock);
}

/* ************************************** */

const char* transop_str (enum n2n_transform tr) {

    switch(tr) {
        case N2N_TRANSFORM_ID_NULL:    return("null");
        case N2N_TRANSFORM_ID_TWOFISH: return("Twofish");
        case N2N_TRANSFORM_ID_AES:     return("AES");
        case N2N_TRANSFORM_ID_CHACHA20:return("ChaCha20");
        case N2N_TRANSFORM_ID_SPECK:   return("Speck");
        default:                       return("invalid");
    };
}

/* ************************************** */

const char* compression_str (uint8_t cmpr) {

    switch(cmpr) {
        case N2N_COMPRESSION_ID_NONE:    return("none");
        case N2N_COMPRESSION_ID_LZO:     return("lzo1x");
        case N2N_COMPRESSION_ID_ZSTD:    return("zstd");
        default:                         return("invalid");
    };
}

/* ************************************** */

/** Destination 01:00:5E:00:00:00 - 01:00:5E:7F:FF:FF is multicast ethernet.
 */
static int is_ethMulticast (const void * buf, size_t bufsize) {

    int retval = 0;

    /* Match 01:00:5E:00:00:00 - 01:00:5E:7F:FF:FF */
    if(bufsize >= sizeof(ether_hdr_t)) {
        /* copy to aligned memory */
        ether_hdr_t eh;
        memcpy(&eh, buf, sizeof(ether_hdr_t));

        if((0x01 == eh.dhost[0]) &&
           (0x00 == eh.dhost[1]) &&
           (0x5E == eh.dhost[2]) &&
           (0 == (0x80 & eh.dhost[3])))
            retval = 1; /* This is an ethernet multicast packet [RFC1112]. */
    }

    return retval;
}

/* ************************************** */

/** Destination MAC 33:33:0:00:00:00 - 33:33:FF:FF:FF:FF is reserved for IPv6
 *    neighbour discovery.
 */
static int is_ip6_discovery (const void * buf, size_t bufsize) {

    int retval = 0;

    if(bufsize >= sizeof(ether_hdr_t)) {
        /* copy to aligned memory */
        ether_hdr_t eh;

        memcpy(&eh, buf, sizeof(ether_hdr_t));

        if((0x33 == eh.dhost[0]) && (0x33 == eh.dhost[1]))
            retval = 1; /* This is an IPv6 multicast packet [RFC2464]. */
    }

    return retval;
}


/* ************************************** */


// reset number of supernode connection attempts: try only once for already more realiable tcp connections
void reset_sup_attempts (n2n_edge_t *eee) {

    eee->sup_attempts = (eee->conf.connect_tcp) ? 1 : N2N_EDGE_SUP_ATTEMPTS;
}


// detect local IP address by probing a connection to the supernode
static int detect_local_ip_address (n2n_sock_t* out_sock, const n2n_edge_t* eee) {

    struct sockaddr_in local_sock;
    struct sockaddr_in sn_sock;
    socklen_t sock_len = sizeof(local_sock);
    SOCKET probe_sock;
    int ret = 0;

    out_sock->family = AF_INVALID;

    // always detetct local port even/especially if chosen by OS...
    if((getsockname(eee->sock, (struct sockaddr *)&local_sock, &sock_len) == 0)
    && (local_sock.sin_family == AF_INET)
    && (sock_len == sizeof(local_sock)))
        // remember the port number
        out_sock->port = ntohs(local_sock.sin_port);
    else
        ret = -1;

    // probe for local IP address
    probe_sock = socket(PF_INET, SOCK_DGRAM, 0);
    // connecting the UDP socket makes getsockname read the local address it uses to connect (to the sn in this case);
    // we cannot do it with the real (eee->sock) socket because socket does not accept any conenction from elsewhere then,
    // e.g. from another edge instead of the supernode; as re-connecting to AF_UNSPEC might not work to release the socket
    // on non-UNIXoids, we use a temporary socket
    if((int)probe_sock >= 0) {
        fill_sockaddr((struct sockaddr*)&sn_sock, sizeof(sn_sock), &eee->curr_sn->sock);
        if(connect(probe_sock, (struct sockaddr *)&sn_sock, sizeof(sn_sock)) == 0) {
            if((getsockname(probe_sock, (struct sockaddr *)&local_sock, &sock_len) == 0)
            && (local_sock.sin_family == AF_INET)
            && (sock_len == sizeof(local_sock))) {
                memcpy(&(out_sock->addr.v4), &(local_sock.sin_addr.s_addr), IPV4_SIZE);
            } else
                ret = -4;
        } else
            ret = -3;
        closesocket(probe_sock);
    } else
        ret = -2;

    out_sock->family = AF_INET;

    return ret;
}


// open socket, close it before if TCP
// in case of TCP, 'connect()' is required
int supernode_connect (n2n_edge_t *eee) {

    int sockopt;
    struct sockaddr_in sn_sock;
    n2n_sock_t local_sock;
    n2n_sock_str_t sockbuf;

    if((eee->conf.connect_tcp) && (eee->sock >= 0)) {
        closesocket(eee->sock);
        eee->sock = -1;
    }

    if(eee->sock < 0) {

        if(eee->conf.local_port > 0)
            traceEvent(TRACE_NORMAL, "binding to local port %d",
                                     (eee->conf.connect_tcp) ? 0 : eee->conf.local_port);

        eee->sock = open_socket((eee->conf.connect_tcp) ?  0 : eee->conf.local_port,
                                 eee->conf.bind_address,
                                 eee->conf.connect_tcp);

        if(eee->sock < 0) {
            traceEvent(TRACE_ERROR, "failed to bind main UDP port %u",
                                     (eee->conf.connect_tcp) ? 0 : eee->conf.local_port);
            return -1;
        }

        fill_sockaddr((struct sockaddr*)&sn_sock, sizeof(sn_sock), &eee->curr_sn->sock);

        // set tcp socket to O_NONBLOCK so connect does not hang
        // requires checking the socket for readiness before sending and receving
        if(eee->conf.connect_tcp) {
#ifdef _WIN32
            u_long value = 1;
            ioctlsocket(eee->sock, FIONBIO, &value);
#else
            fcntl(eee->sock, F_SETFL, O_NONBLOCK);
#endif
            if((connect(eee->sock, (struct sockaddr*)&(sn_sock), sizeof(struct sockaddr)) < 0)
               && (errno != EINPROGRESS)) {
                eee->sock = -1;
                return -1;
            }
        }

        if(eee->conf.tos) {
            /* https://www.tucny.com/Home/dscp-tos */
            sockopt = eee->conf.tos;

            if(setsockopt(eee->sock, IPPROTO_IP, IP_TOS, (char *)&sockopt, sizeof(sockopt)) == 0)
                traceEvent(TRACE_INFO, "TOS set to 0x%x", eee->conf.tos);
            else
                traceEvent(TRACE_WARNING, "could not set TOS 0x%x[%d]: %s", eee->conf.tos, errno, strerror(errno));
        }
#ifdef IP_PMTUDISC_DO
        sockopt = (eee->conf.disable_pmtu_discovery) ? IP_PMTUDISC_DONT : IP_PMTUDISC_DO;

        if(setsockopt(eee->sock, IPPROTO_IP, IP_MTU_DISCOVER, &sockopt, sizeof(sockopt)) < 0)
            traceEvent(TRACE_WARNING, "could not %s PMTU discovery[%d]: %s",
                       (eee->conf.disable_pmtu_discovery) ? "disable" : "enable", errno, strerror(errno));
        else
            traceEvent(TRACE_INFO, "PMTU discovery %s", (eee->conf.disable_pmtu_discovery) ? "disabled" : "enabled");
#endif

        memset(&local_sock, 0, sizeof(n2n_sock_t));
        if(detect_local_ip_address(&local_sock, eee) == 0) {
            // always overwrite local port even/especially if chosen by OS...
            eee->conf.preferred_sock.port = local_sock.port;
            // only if auto-detection mode, ...
            if(eee->conf.preferred_sock_auto) {
                // ... overwrite IP address, too (whole socket struct here)
                memcpy(&eee->conf.preferred_sock, &local_sock, sizeof(n2n_sock_t));
                traceEvent(TRACE_INFO, "determined local socket [%s]",
                                       sock_to_cstr(sockbuf, &local_sock));
            }
        }

        if(eee->cb.sock_opened)
            eee->cb.sock_opened(eee);
    }

    // REVISIT: add mgmt port notification to listener for better mgmt port
    //          subscription support

    return 0;
}


// always closes the socket
void supernode_disconnect (n2n_edge_t *eee) {
    if(!eee) {
        return;
    }
    if(eee->sock >= 0) {
        closesocket(eee->sock);
        eee->sock = -1;
        traceEvent(TRACE_DEBUG, "closed");
    }
}


/* ************************************** */

/** Initialise an edge to defaults.
 *
 *    This also initialises the NULL transform operation opstruct.
 */
n2n_edge_t* edge_init (const n2n_edge_conf_t *conf, int *rv) {

    n2n_transform_t transop_id = conf->transop_id;
    n2n_edge_t *eee = calloc(1, sizeof(n2n_edge_t));
    int rc = -1, i = 0;
    struct peer_info *scan, *tmp;
    uint8_t tmp_key[N2N_AUTH_CHALLENGE_SIZE];

    if((rc = edge_verify_conf(conf)) != 0) {
        traceEvent(TRACE_ERROR, "invalid configuration");
        goto edge_init_error;
    }

    if(!eee) {
        traceEvent(TRACE_ERROR, "cannot allocate memory");
        goto edge_init_error;
    }


    memcpy(&eee->conf, conf, sizeof(*conf));
    eee->curr_sn = eee->conf.supernodes;
    eee->start_time = time(NULL);

    eee->known_peers        = NULL;
    eee->pending_peers    = NULL;
    reset_sup_attempts(eee);

    sn_selection_criterion_common_data_default(eee);

    pearson_hash_init();

    // always initialize compression transforms so we can at least decompress
    rc = n2n_transop_lzo_init(&eee->conf, &eee->transop_lzo);
    if(rc) goto edge_init_error; /* error message is printed in lzo_init */
#ifdef HAVE_ZSTD
    rc = n2n_transop_zstd_init(&eee->conf, &eee->transop_zstd);
    if(rc) goto edge_init_error; /* error message is printed in zstd_init */
#endif

    traceEvent(TRACE_NORMAL, "number of supernodes in the list: %d\n", HASH_COUNT(eee->conf.supernodes));
    HASH_ITER(hh, eee->conf.supernodes, scan, tmp) {
        traceEvent(TRACE_NORMAL, "supernode %u => %s\n", i, (scan->ip_addr));
        i++;
    }

    /* Set active transop */
    switch(transop_id) {
        case N2N_TRANSFORM_ID_TWOFISH:
            rc = n2n_transop_tf_init(&eee->conf, &eee->transop);
            break;

        case N2N_TRANSFORM_ID_AES:
            rc = n2n_transop_aes_init(&eee->conf, &eee->transop);
            break;

        case N2N_TRANSFORM_ID_CHACHA20:
            rc = n2n_transop_cc20_init(&eee->conf, &eee->transop);
            break;

        case N2N_TRANSFORM_ID_SPECK:
            rc = n2n_transop_speck_init(&eee->conf, &eee->transop);
            break;

        default:
            rc = n2n_transop_null_init(&eee->conf, &eee->transop);
    }

    if((rc < 0) || (eee->transop.fwd == NULL) || (eee->transop.transform_id != transop_id)) {
        traceEvent(TRACE_ERROR, "transop init failed");
        goto edge_init_error;
    }

    // set the key schedule (context) for header encryption if enabled
    if(conf->header_encryption == HEADER_ENCRYPTION_ENABLED) {
        traceEvent(TRACE_NORMAL, "Header encryption is enabled.");
        packet_header_setup_key((char *)(eee->conf.community_name),
                                &(eee->conf.header_encryption_ctx_static),
                                &(eee->conf.header_encryption_ctx_dynamic),
                                &(eee->conf.header_iv_ctx_static),
                                &(eee->conf.header_iv_ctx_dynamic));
        // in case of user/password auth, initialize a random dynamic key to prevent
        // unintentional communication with only-header-encrypted community; will be
        // overwritten by legit key later
        if(conf->shared_secret) {
            memrnd(tmp_key, N2N_AUTH_CHALLENGE_SIZE);
            packet_header_change_dynamic_key(tmp_key,
                                             &(eee->conf.header_encryption_ctx_dynamic),
                                             &(eee->conf.header_iv_ctx_dynamic));
        }
    }

    // setup authentication scheme
    if(!conf->shared_secret) {
        // id-based scheme
        eee->conf.auth.scheme = n2n_auth_simple_id;
        // random authentication token
        memrnd(eee->conf.auth.token, N2N_AUTH_ID_TOKEN_SIZE);
        eee->conf.auth.token_size = N2N_AUTH_ID_TOKEN_SIZE;
    } else {
        // user-password scheme
        eee->conf.auth.scheme = n2n_auth_user_password;
        // 'token' stores public key and the last random challenge being set upon sending REGISTER_SUPER
        memcpy(eee->conf.auth.token, eee->conf.public_key, N2N_PRIVATE_PUBLIC_KEY_SIZE);
        // random part of token (challenge) will be generated and filled in at each REGISTER_SUPER
        eee->conf.auth.token_size = N2N_AUTH_PW_TOKEN_SIZE;
        // make sure that only stream ciphers are being used
        if((transop_id != N2N_TRANSFORM_ID_CHACHA20)
        && (transop_id != N2N_TRANSFORM_ID_SPECK)) {
            traceEvent(TRACE_ERROR, "user-password authentication requires ChaCha20 (-A4) or SPECK (-A5) to be used.");
            goto edge_init_error;
        }
    }

    if(eee->transop.no_encryption)
        traceEvent(TRACE_WARNING, "encryption is disabled in edge");

    // first time calling edge_init_sockets needs -1 in the sockets for it does throw an error
    // on trying to close them (open_sockets does so for also being able to RE-open the sockets
    // if called in-between, see "Supernode not responding" in update_supernode_reg(...)
    eee->sock = -1;
    eee->udp_mgmt_sock = -1;
#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    eee->udp_multicast_sock = -1;
#endif
    if(edge_init_sockets(eee) < 0) {
        traceEvent(TRACE_ERROR, "socket setup failed");
        goto edge_init_error;
    }

    if(resolve_create_thread(&(eee->resolve_parameter), eee->conf.supernodes) == 0) {
        traceEvent(TRACE_NORMAL, "successfully created resolver thread");
    }

    eee->network_traffic_filter = create_network_traffic_filter();
    network_traffic_filter_add_rule(eee->network_traffic_filter, eee->conf.network_traffic_filter_rules);

    //edge_init_success:
    *rv = 0;
    return(eee);

edge_init_error:
    if(eee)
        free(eee);
    *rv = rc;
    return(NULL);
}

/* ************************************** */

static int find_and_remove_peer (struct peer_info **head, const n2n_mac_t mac) {

    struct peer_info *peer;

    HASH_FIND_PEER(*head, mac, peer);
    if(peer) {
        HASH_DEL(*head, peer);
        free(peer);
        return(1);
    }

    return(0);
}

/* ************************************** */

static uint32_t localhost_v4 = 0x7f000001;
static uint8_t localhost_v6[IPV6_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};

/* Exclude localhost as it may be received when an edge node runs
 * in the same supernode host.
 */
static int is_valid_peer_sock (const n2n_sock_t *sock) {

    switch(sock->family) {
        case AF_INET: {
            uint32_t *a = (uint32_t*)sock->addr.v4;

            if(*a != htonl(localhost_v4))
                return(1);
        }
        break;

        case AF_INET6:
            if(memcmp(sock->addr.v6, localhost_v6, IPV6_SIZE))
                return(1);
            break;
    }

    return(0);
}

/* ***************************************************** */


/***
 *
 * For a given packet, find the apporopriate internal last valid time stamp for lookup
 * and verify it (and also update, if applicable).
 */
static int find_peer_time_stamp_and_verify (n2n_edge_t * eee,
                                            peer_info_t *sn, const n2n_mac_t mac,
                                            uint64_t stamp, int allow_jitter) {

    uint64_t *previous_stamp = NULL;

    if(sn) {
        // from supernode
        previous_stamp = &(sn->last_valid_time_stamp);
    } else {
        // from (peer) edge
        struct peer_info *peer;
        HASH_FIND_PEER(eee->pending_peers, mac, peer);
        if(!peer) {
            HASH_FIND_PEER(eee->known_peers, mac, peer);
        }

        if(peer) {
            // time_stamp_verify_and_update allows the pointer a previous stamp to be NULL
            // if it is a (so far) unknown peer
            previous_stamp = &(peer->last_valid_time_stamp);
        }
    }

    // failure --> 0;    success --> 1
    return time_stamp_verify_and_update(stamp, previous_stamp, allow_jitter);
}


/* ************************************** */

/***
 *
 * Register over multicast in case there is a peer on the same network listening
 */
static void register_with_local_peers (n2n_edge_t * eee) {
#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    if((eee->multicast_joined && eee->conf.allow_p2p)
    && (eee->conf.preferred_sock.family == (uint8_t)AF_INVALID)) {
        /* send registration to the local multicast group */
        traceEvent(TRACE_DEBUG, "registering with multicast group %s:%u",
                   N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT);
        send_register(eee, &(eee->multicast_peer), NULL, N2N_MCAST_REG_COOKIE);
    }
#else
    traceEvent(TRACE_DEBUG, "multicast peers discovery is disabled, skipping");
#endif
}

/* ************************************** */

static struct peer_info* find_peer_by_sock (const n2n_sock_t *sock, struct peer_info *peer_list) {

    struct peer_info *scan, *tmp, *ret = NULL;

    HASH_ITER(hh, peer_list, scan, tmp) {
        if(memcmp(&(scan->sock), sock, sizeof(n2n_sock_t)) == 0) {
            ret = scan;
            break;
        }
    }

    return ret;
}

/* ************************************** */

/** Start the registration process.
 *
 *    If the peer is already in pending_peers, ignore the request.
 *    If not in pending_peers, add it and send a REGISTER.
 *
 *    If hdr is for a direct peer-to-peer packet, try to register back to sender
 *    even if the MAC is in pending_peers. This is because an incident direct
 *    packet indicates that peer-to-peer exchange should work so more aggressive
 *    registration can be permitted (once per incoming packet) as this should only
 *    last for a small number of packets..
 *
 *    Called from the main loop when Rx a packet for our device mac.
 */
static void register_with_new_peer (n2n_edge_t *eee,
                                    uint8_t from_supernode,
                                    uint8_t via_multicast,
                                    const n2n_mac_t mac,
                                    const n2n_ip_subnet_t *dev_addr,
                                    const n2n_desc_t *dev_desc,
                                    const n2n_sock_t *peer) {

    /* REVISIT: purge of pending_peers not yet done. */
    struct peer_info *scan;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    HASH_FIND_PEER(eee->pending_peers, mac, scan);

    /* NOTE: pending_peers are purged periodically with purge_expired_nodes */
    if(scan == NULL) {
        scan = calloc(1, sizeof(struct peer_info));

        memcpy(scan->mac_addr, mac, N2N_MAC_SIZE);
        scan->sock = *peer;
        scan->timeout = eee->conf.register_interval; /* TODO: should correspond to the peer supernode registration timeout */
        scan->last_valid_time_stamp = initial_time_stamp();
        if(via_multicast)
            scan->local = 1;

        HASH_ADD_PEER(eee->pending_peers, scan);

        traceEvent(TRACE_DEBUG, "new pending peer %s [%s]",
                   macaddr_str(mac_buf, scan->mac_addr),
                   sock_to_cstr(sockbuf, &(scan->sock)));

        traceEvent(TRACE_DEBUG, "pending peers list size=%u",
                   HASH_COUNT(eee->pending_peers));
        /* trace Sending REGISTER */
        if(from_supernode) {
            /* UDP NAT hole punching through supernode. Send to peer first(punch local UDP hole)
             * and then ask supernode to forward. Supernode then ask peer to ack. Some nat device
             * drop and block ports with incoming UDP packet if out-come traffic does not exist.
             * So we can alternatively set TTL so that the packet sent to peer never really reaches
             * The register_ttl is basically nat level + 1. Set it to 1 means host like DMZ.
             */
            if(eee->conf.register_ttl == 1) {
                /* We are DMZ host or port is directly accessible. Just let peer to send back the ack */
#ifndef _WIN32
            } else if(eee->conf.register_ttl > 1) {
                /* Setting register_ttl usually implies that the edge knows the internal net topology
                 * clearly, we can apply aggressive port prediction to support incoming Symmetric NAT
                 */
                int curTTL = 0;
                socklen_t lenTTL = sizeof(int);
                n2n_sock_t sock = scan->sock;
                int alter = 16; /* TODO: set by command line or more reliable prediction method */

                getsockopt(eee->sock, IPPROTO_IP, IP_TTL, (void *) (char *) &curTTL, &lenTTL);
                setsockopt(eee->sock, IPPROTO_IP, IP_TTL,
                           (void *) (char *) &eee->conf.register_ttl,
                           sizeof(eee->conf.register_ttl));
                for(; alter > 0; alter--, sock.port++) {
                    send_register(eee, &sock, mac, N2N_PORT_REG_COOKIE);
                }
                setsockopt(eee->sock, IPPROTO_IP, IP_TTL, (void *) (char *) &curTTL, sizeof(curTTL));
#endif
            } else { /* eee->conf.register_ttl <= 0 */
                /* Normal STUN */
                send_register(eee, &(scan->sock), mac, N2N_REGULAR_REG_COOKIE);
            }
            send_register(eee, &(eee->curr_sn->sock), mac, N2N_FORWARDED_REG_COOKIE);
        } else {
            /* P2P register, send directly */
            send_register(eee, &(scan->sock), mac, N2N_REGULAR_REG_COOKIE);
        }
        register_with_local_peers(eee);
    } else{
        scan->sock = *peer;
    }
    scan->last_seen = time(NULL);
    if(dev_addr != NULL) {
        memcpy(&(scan->dev_addr), dev_addr, sizeof(n2n_ip_subnet_t));
    }
    if(dev_desc) memcpy(scan->dev_desc, dev_desc, N2N_DESC_SIZE);
}


/* ************************************** */

/** Update the last_seen time for this peer, or get registered. */
static void check_peer_registration_needed (n2n_edge_t *eee,
                                            uint8_t from_supernode,
                                            uint8_t via_multicast,
                                            const n2n_mac_t mac,
                                            const n2n_cookie_t cookie,
                                            const n2n_ip_subnet_t *dev_addr,
                                            const n2n_desc_t *dev_desc,
                                            const n2n_sock_t *peer) {

    struct peer_info *scan;

    HASH_FIND_PEER(eee->known_peers, mac, scan);

    /* If we were not able to find it by MAC, we try to find it by socket. */
    if(scan == NULL ) {
        scan = find_peer_by_sock(peer, eee->known_peers);

        // MAC change
        if(scan) {
            HASH_DEL(eee->known_peers, scan);
            memcpy(scan->mac_addr, mac, sizeof(n2n_mac_t));
            HASH_ADD_PEER(eee->known_peers, scan);
            // reset last_local_reg to allow re-registration
            scan->last_cookie = N2N_NO_REG_COOKIE;
        }
    }

    if(scan == NULL) {
        /* Not in known_peers - start the REGISTER process. */
        register_with_new_peer(eee, from_supernode, via_multicast, mac, dev_addr, dev_desc, peer);
    } else {
        /* Already in known_peers. */
        time_t now = time(NULL);

        if(!from_supernode)
            scan->last_p2p = now;

        if(via_multicast)
            scan->local = 1;

        if(((now - scan->last_seen) > 0 /* >= 1 sec */)
          ||(cookie > scan->last_cookie)) {
            /* Don't register too often */
            check_known_peer_sock_change(eee, from_supernode, via_multicast, mac, dev_addr, dev_desc, peer, now);
        }
    }
}

/* ************************************** */


/* Confirm that a pending peer is reachable directly via P2P.
 *
 * peer must be a pointer to an element of the pending_peers list.
 */
static void peer_set_p2p_confirmed (n2n_edge_t * eee,
                                    const n2n_mac_t mac,
                                    const n2n_cookie_t cookie,
                                    const n2n_sock_t * peer,
                                    time_t now) {

    struct peer_info *scan, *scan_tmp;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    HASH_FIND_PEER(eee->pending_peers, mac, scan);
    if(scan == NULL) {
        scan = find_peer_by_sock(peer, eee->pending_peers);
        // in case of MAC change, reset last_local_reg to allow re-registration
        if(scan)
            scan->last_cookie = N2N_NO_REG_COOKIE;
    }

    if(scan) {
        HASH_DEL(eee->pending_peers, scan);

        scan_tmp = find_peer_by_sock(peer, eee->known_peers);
        if(scan_tmp != NULL) {
            HASH_DEL(eee->known_peers, scan_tmp);
            mgmt_event_post(N2N_EVENT_PEER,N2N_EVENT_PEER_DEL_P2P,scan);
            free(scan);
            scan = scan_tmp;
            memcpy(scan->mac_addr, mac, sizeof(n2n_mac_t));
            // in case of MAC change, reset cookie to allow immediate re-registration
            scan->last_cookie = N2N_NO_REG_COOKIE;
        } else {
            // update sock but ...
            // ... ignore ACKs's (and their socks) from lower ranked inbound ways for a while
            if(((now - scan->last_seen) > REGISTRATION_TIMEOUT / 4)
             ||(cookie > scan->last_cookie)) {
                scan->sock = *peer;
                scan->last_cookie = cookie;
            }
        }

        HASH_ADD_PEER(eee->known_peers, scan);
        scan->last_p2p = now;
        mgmt_event_post(N2N_EVENT_PEER,N2N_EVENT_PEER_ADD_P2P,scan);

        traceEvent(TRACE_DEBUG, "p2p connection established: %s [%s]",
                   macaddr_str(mac_buf, mac),
                   sock_to_cstr(sockbuf, peer));

        traceEvent(TRACE_DEBUG, "new peer %s [%s]",
                   macaddr_str(mac_buf, scan->mac_addr),
                   sock_to_cstr(sockbuf, &(scan->sock)));

        traceEvent(TRACE_DEBUG, "pending peers list size=%u",
                   HASH_COUNT(eee->pending_peers));

        traceEvent(TRACE_DEBUG, "known peers list size=%u",
                   HASH_COUNT(eee->known_peers));

        scan->last_seen = now;
    } else
        traceEvent(TRACE_DEBUG, "failed to find sender in pending_peers");
}


/* ************************************** */


// provides the current / a new local auth token
static int get_local_auth (n2n_edge_t *eee, n2n_auth_t *auth) {

    switch(eee->conf.auth.scheme) {
        case n2n_auth_simple_id:
            memcpy(auth, &(eee->conf.auth), sizeof(n2n_auth_t));
            break;
        case n2n_auth_user_password:
            // start from the locally stored complete auth token (including type and size fields)
            memcpy(auth, &(eee->conf.auth), sizeof(n2n_auth_t));

            // the token data consists of
            //    32 bytes public key
            //    16 bytes random challenge

            // generate a new random auth challenge every time
            memrnd(auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
            // store it in local auth token (for comparison later)
            memcpy(eee->conf.auth.token + N2N_PRIVATE_PUBLIC_KEY_SIZE, auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
            // encrypt the challenge for transmission
            speck_128_encrypt(auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)eee->conf.shared_secret_ctx);
            break;
        default:
            break;
    }

    return 0;
}


// handles a returning (remote) auth token, takes action as required by auth scheme
static int handle_remote_auth (n2n_edge_t *eee, struct peer_info *peer, const n2n_auth_t *remote_auth) {

    uint8_t tmp_token[N2N_AUTH_MAX_TOKEN_SIZE];

    switch(eee->conf.auth.scheme) {
        case n2n_auth_simple_id:
            // no action required
            break;
        case n2n_auth_user_password:
            memcpy(tmp_token, remote_auth->token, N2N_AUTH_PW_TOKEN_SIZE);

            // the returning token data consists of
            //    16 bytes double-encrypted challenge
            //    16 bytes public key (second half)
            //    16 bytes encrypted (original random challenge XOR shared secret XOR dynamic key)

            // decrypt double-encrypted received challenge (first half of public key field)
            speck_128_decrypt(tmp_token, (speck_context_t*)eee->conf.shared_secret_ctx);
            speck_128_decrypt(tmp_token, (speck_context_t*)eee->conf.shared_secret_ctx);

            // compare to original challenge
            if(0 != memcmp(tmp_token, eee->conf.auth.token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE))
                return -1;

            // decrypt the received challenge in which the dynamic key is wrapped
            speck_128_decrypt(tmp_token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)eee->conf.shared_secret_ctx);
            // un-XOR the original challenge
            memxor(tmp_token + N2N_PRIVATE_PUBLIC_KEY_SIZE, eee->conf.auth.token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
            // un-XOR the shared secret
            memxor(tmp_token + N2N_PRIVATE_PUBLIC_KEY_SIZE, *(eee->conf.shared_secret), N2N_AUTH_CHALLENGE_SIZE);
            // setup for use as dynamic key
            packet_header_change_dynamic_key(tmp_token + N2N_PRIVATE_PUBLIC_KEY_SIZE,
                                             &(eee->conf.header_encryption_ctx_dynamic),
                                             &(eee->conf.header_iv_ctx_dynamic));
            break;
        default:
            break;
    }

    return 0;
}


/* ************************************** */


int is_empty_ip_address (const n2n_sock_t * sock) {

    const uint8_t * ptr = NULL;
    size_t len = 0;
    size_t i;

    if(AF_INET6 == sock->family) {
        ptr = sock->addr.v6;
        len = 16;
    } else {
        ptr = sock->addr.v4;
        len = 4;
    }

    for(i = 0; i < len; ++i) {
        if(0 != ptr[i]) {
            /* found a non-zero byte in address */
            return 0;
        }
    }

    return 1;
}

/* ************************************** */


/** Check if a known peer socket has changed and possibly register again.
 */
static void check_known_peer_sock_change (n2n_edge_t *eee,
                                          uint8_t from_supernode,
                                          uint8_t via_multicast,
                                          const n2n_mac_t mac,
                                          const n2n_ip_subnet_t *dev_addr,
                                          const n2n_desc_t *dev_desc,
                                          const n2n_sock_t *peer,
                                          time_t when) {

    struct peer_info *scan;
    n2n_sock_str_t sockbuf1;
    n2n_sock_str_t sockbuf2; /* don't clobber sockbuf1 if writing two addresses to trace */
    macstr_t mac_buf;

    if(is_empty_ip_address(peer))
        return;

    if(is_multi_broadcast(mac))
        return;

    /* Search the peer in known_peers */
    HASH_FIND_PEER(eee->known_peers, mac, scan);

    if(!scan)
        /* Not in known_peers */
        return;

    if(!sock_equal(&(scan->sock), peer)) {
        if(!from_supernode) {
            /* This is a P2P packet */
            traceEvent(TRACE_NORMAL, "peer %s changed [%s] -> [%s]",
                       macaddr_str(mac_buf, scan->mac_addr),
                       sock_to_cstr(sockbuf1, &(scan->sock)),
                       sock_to_cstr(sockbuf2, peer));
            /* The peer has changed public socket. It can no longer be assumed to be reachable. */
            HASH_DEL(eee->known_peers, scan);
            mgmt_event_post(N2N_EVENT_PEER,N2N_EVENT_PEER_DEL_P2P,scan);
            free(scan);

            register_with_new_peer(eee, from_supernode, via_multicast, mac, dev_addr, dev_desc, peer);
        } else {
            /* Don't worry about what the supernode reports, it could be seeing a different socket. */
        }
    } else
        scan->last_seen = when;
}

/* ************************************** */

/*
 * Confirm that we can send to this edge.
 * TODO: for the TCP case, this could cause a stall in the packet
 * send path, so this probably should be reworked to use a queue
 */
static int check_sock_ready (n2n_edge_t *eee) {
    // if required (tcp), wait until writeable as soket is set to
    // O_NONBLOCK, could require some wait time directly after re-opening
    if(eee->conf.connect_tcp) {
        fd_set socket_mask;
        struct timeval wait_time;

        FD_ZERO(&socket_mask);
        FD_SET(eee->sock, &socket_mask);
        wait_time.tv_sec = 0;
        wait_time.tv_usec = 500000;
        return select(eee->sock + 1, NULL, &socket_mask, NULL, &wait_time);
    }

    return 1;
}

/** Send a datagram to a socket file descriptor */
static ssize_t sendto_fd (n2n_edge_t *eee, const void *buf,
                          size_t len, struct sockaddr_in *dest,
                          const n2n_sock_t * n2ndest) {

    ssize_t sent = 0;

    if(check_sock_ready(eee) < 1) {
        goto err_out;
    }

    sent = sendto(eee->sock, buf, len, 0 /*flags*/,
                  (struct sockaddr *)dest, sizeof(struct sockaddr_in));

    if(sent != -1) {
        // sendto success
        traceEvent(TRACE_DEBUG, "sent=%d", (signed int)sent);
        return sent;
    }

    // We only get here if sendto failed, so errno must be valid

    char * errstr = strerror(errno);
    n2n_sock_str_t sockbuf;

    if(!errstr) {
        traceEvent(TRACE_WARNING, "bad strerror");
    }

    int level = TRACE_WARNING;
    // downgrade to TRACE_DEBUG in case of custom AF_INVALID,
    // i.e. supernode not resolved yet
    if(errno == EAFNOSUPPORT /* 93 */) {
        level = TRACE_DEBUG;
    }

    traceEvent(level, "sendto(%s) failed (%d) %s",
            sock_to_cstr(sockbuf, n2ndest),
            errno, errstr);
#ifdef _WIN32
    traceEvent(level, "WSAGetLastError(): %u", WSAGetLastError());
#endif

    /*
     * we get here if the sock is not ready or
     * if the sendto had an error
     */
err_out:
    if(eee->conf.connect_tcp) {
        supernode_disconnect(eee);
        eee->sn_wait = 1;
        traceEvent(TRACE_DEBUG, "error in sendto_fd");
    }

    /*
     * If we got an error and are using UDP, this is still an error
     * case.  The only caller of sendto_fd() checks the return only
     * in the TCP case.
     *
     * Thus, we can safely return an error code for any error.
     */
    return -1;
}


/** Send a datagram to a socket defined by a n2n_sock_t */
static void sendto_sock (n2n_edge_t *eee, const void * buf,
                            size_t len, const n2n_sock_t * dest) {

    struct sockaddr_in peer_addr;
    ssize_t sent;
    int value = 0;

    // TODO: audit callers and confirm if this can ever happen
    if(!eee) {
        traceEvent(TRACE_WARNING, "bad eee");
        return;
    }

    if(!dest->family)
        // invalid socket
        return;

    if(eee->sock < 0)
        // invalid socket file descriptor, e.g. TCP unconnected has fd of '-1'
        return;

    // network order socket
    fill_sockaddr((struct sockaddr *) &peer_addr, sizeof(peer_addr), dest);

    // if the connection is tcp, i.e. not the regular sock...
    if(eee->conf.connect_tcp) {

        setsockopt(eee->sock, IPPROTO_TCP, TCP_NODELAY, (void *)&value, sizeof(value));
        value = 1;
#ifdef LINUX
        setsockopt(eee->sock, IPPROTO_TCP, TCP_CORK, &value, sizeof(value));
#endif

        // prepend packet length...
        uint16_t pktsize16 = htobe16(len);
        sent = sendto_fd(eee, (uint8_t*)&pktsize16, sizeof(pktsize16), &peer_addr, dest);

        if(sent <= 0)
            return;
        // ...before sending the actual data
    }
    sent = sendto_fd(eee, buf, len, &peer_addr, dest);

    // if the connection is tcp, i.e. not the regular sock...
    if(eee->conf.connect_tcp) {
        value = 1; /* value should still be set to 1 */
        setsockopt(eee->sock, IPPROTO_TCP, TCP_NODELAY, (void *)&value, sizeof(value));
#ifdef LINUX
        value = 0;
        setsockopt(eee->sock, IPPROTO_TCP, TCP_CORK, &value, sizeof(value));
#endif
    }

    return;
}


/* ************************************** */


/* Bind eee->udp_multicast_sock to multicast group */
static void check_join_multicast_group (n2n_edge_t *eee) {

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    if((eee->conf.allow_p2p)
    && (eee->conf.preferred_sock.family == (uint8_t)AF_INVALID)) {
        if(!eee->multicast_joined) {
            struct ip_mreq mreq;
            mreq.imr_multiaddr.s_addr = inet_addr(N2N_MULTICAST_GROUP);
#ifdef _WIN32
            dec_ip_str_t ip_addr;
            get_best_interface_ip(eee, &ip_addr);
            mreq.imr_interface.s_addr = inet_addr(ip_addr);
#else
            mreq.imr_interface.s_addr = htonl(INADDR_ANY);
#endif

            if(setsockopt(eee->udp_multicast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
                traceEvent(TRACE_WARNING, "failed to bind to local multicast group %s:%u [errno %u]",
                           N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT, errno);

#ifdef _WIN32
                traceEvent(TRACE_WARNING, "WSAGetLastError(): %u", WSAGetLastError());
#endif
            } else {
                traceEvent(TRACE_NORMAL, "successfully joined multicast group %s:%u",
                           N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT);
                eee->multicast_joined = 1;
            }
        }
    }
#endif
}

/* ************************************** */

/** Send a QUERY_PEER packet to the current supernode. */
void send_query_peer (n2n_edge_t * eee,
                      const n2n_mac_t dst_mac) {

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n2n_common_t cmn = {0};
    n2n_QUERY_PEER_t query = {0};
    struct peer_info *peer, *tmp;
    int n_o_pings = 0;
    int n_o_top_sn = 0;
    int n_o_rest_sn = 0;
    int n_o_skip_sn = 0;

    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_query_peer;
    cmn.flags = 0;
    memcpy(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

    idx = 0;
    encode_mac(query.srcMac, &idx, eee->device.mac_addr);

    idx = 0;
    encode_mac(query.targetMac, &idx, dst_mac);

    idx = 0;
    encode_QUERY_PEER(pktbuf, &idx, &cmn, &query);

    if(!is_null_mac(dst_mac)) {

        traceEvent(TRACE_DEBUG, "send QUERY_PEER to supernode");

        if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
            packet_header_encrypt(pktbuf, idx, idx,
                                  eee->conf.header_encryption_ctx_dynamic, eee->conf.header_iv_ctx_dynamic,
                                  time_stamp());
        }

        sendto_sock(eee, pktbuf, idx, &(eee->curr_sn->sock));

    } else {
        traceEvent(TRACE_DEBUG, "send PING to supernodes");

        if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
            packet_header_encrypt(pktbuf, idx, idx,
                                  eee->conf.header_encryption_ctx_dynamic, eee->conf.header_iv_ctx_dynamic,
                                  time_stamp());
        }

        n_o_pings = eee->conf.number_max_sn_pings;
        eee->conf.number_max_sn_pings = NUMBER_SN_PINGS_REGULAR;

        // ping the 'floor(n/2)' top supernodes and 'ceiling(n/2)' of the remaining
        n_o_top_sn  = n_o_pings >> 1;
        n_o_rest_sn = (n_o_pings + 1) >> 1;

        // skip a random number of supernodes between top and remaining
        n_o_skip_sn = HASH_COUNT(eee->conf.supernodes) - n_o_pings;
        n_o_skip_sn = (n_o_skip_sn < 0) ? 0 : n2n_rand_sqr(n_o_skip_sn);
        HASH_ITER(hh, eee->conf.supernodes, peer, tmp) {
            if(n_o_top_sn) {
                n_o_top_sn--;
                // fall through (send to top supernode)
            } else if(n_o_skip_sn) {
                n_o_skip_sn--;
                // skip (do not send)
                continue;
            } else if(n_o_rest_sn) {
                n_o_rest_sn--;
                // fall through (send to remaining supernode)
            } else {
                // done with the remaining (do not send anymore)
                break;
            }
            sendto_sock(eee, pktbuf, idx, &(peer->sock));
        }
    }
}

/* ******************************************************** */

/** Send a REGISTER_SUPER packet to the current supernode. */
void send_register_super (n2n_edge_t *eee) {

    uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};
    uint8_t hash_buf[16] = {0};
    size_t idx;
    /* ssize_t sent; */
    n2n_common_t cmn;
    n2n_REGISTER_SUPER_t reg;
    n2n_sock_str_t sockbuf;

    memset(&cmn, 0, sizeof(cmn));
    memset(&reg, 0, sizeof(reg));

    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_register_super;
    if(eee->conf.preferred_sock.family == (uint8_t)AF_INVALID) {
        cmn.flags = 0;
    } else {
        cmn.flags = N2N_FLAGS_SOCKET;
        memcpy(&(reg.sock), &(eee->conf.preferred_sock), sizeof(n2n_sock_t));
    }
    memcpy(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

    eee->curr_sn->last_cookie = n2n_rand();

    reg.cookie = eee->curr_sn->last_cookie;
    reg.dev_addr.net_addr = ntohl(eee->device.ip_addr);
    reg.dev_addr.net_bitlen = mask2bitlen(ntohl(eee->device.device_mask));
    memcpy(reg.dev_desc, eee->conf.dev_desc, N2N_DESC_SIZE);
    get_local_auth(eee, &(reg.auth));

    idx = 0;
    encode_mac(reg.edgeMac, &idx, eee->device.mac_addr);

    idx = 0;
    encode_REGISTER_SUPER(pktbuf, &idx, &cmn, &reg);

    traceEvent(TRACE_DEBUG, "send REGISTER_SUPER to [%s]",
               sock_to_cstr(sockbuf, &(eee->curr_sn->sock)));

    if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
        packet_header_encrypt(pktbuf, idx, idx,
                              eee->conf.header_encryption_ctx_static, eee->conf.header_iv_ctx_static,
                              time_stamp());

        if(eee->conf.shared_secret) {
            pearson_hash_128(hash_buf, pktbuf, idx);
            speck_128_encrypt(hash_buf, (speck_context_t*)eee->conf.shared_secret_ctx);
            encode_buf(pktbuf, &idx, hash_buf, N2N_REG_SUP_HASH_CHECK_LEN);
        }
    }

    sendto_sock(eee, pktbuf, idx, &(eee->curr_sn->sock));
}


static void send_unregister_super (n2n_edge_t *eee) {

    uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};
    size_t idx;
    /* ssize_t sent; */
    n2n_common_t cmn;
    n2n_UNREGISTER_SUPER_t unreg;
    n2n_sock_str_t sockbuf;

    memset(&cmn, 0, sizeof(cmn));
    memset(&unreg, 0, sizeof(unreg));

    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_unregister_super;
    cmn.flags = 0;
    memcpy(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);
    get_local_auth(eee, &(unreg.auth));

    idx = 0;
    encode_mac(unreg.srcMac, &idx, eee->device.mac_addr);

    idx = 0;
    encode_UNREGISTER_SUPER(pktbuf, &idx, &cmn, &unreg);

    traceEvent(TRACE_DEBUG, "send UNREGISTER_SUPER to [%s]",
               sock_to_cstr(sockbuf, &(eee->curr_sn->sock)));

    if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED)
        packet_header_encrypt(pktbuf, idx, idx,
                              eee->conf.header_encryption_ctx_dynamic, eee->conf.header_iv_ctx_dynamic,
                              time_stamp());

    sendto_sock(eee, pktbuf, idx, &(eee->curr_sn->sock));

}


static int sort_supernodes (n2n_edge_t *eee, time_t now) {

    struct peer_info *scan, *tmp;

    if(now - eee->last_sweep > SWEEP_TIME) {
        // this routine gets periodically called

        if(!eee->sn_wait) {
            // sort supernodes in ascending order of their selection_criterion fields
            sn_selection_sort(&(eee->conf.supernodes));
        }

        if(eee->curr_sn != eee->conf.supernodes) {
            // we have not been connected to the best/top one
            send_unregister_super(eee);
            eee->curr_sn = eee->conf.supernodes;
            reset_sup_attempts(eee);
            supernode_connect(eee);

            traceEvent(TRACE_INFO, "registering with supernode [%s][number of supernodes %d][attempts left %u]",
                       supernode_ip(eee), HASH_COUNT(eee->conf.supernodes), (unsigned int)eee->sup_attempts);

            send_register_super(eee);
            eee->last_register_req = now;
            eee->sn_wait = 1;
        }

        HASH_ITER(hh, eee->conf.supernodes, scan, tmp) {
            if(scan == eee->curr_sn)
                sn_selection_criterion_good(&(scan->selection_criterion));
            else
                sn_selection_criterion_default(&(scan->selection_criterion));
        }
        sn_selection_criterion_common_data_default(eee);

        // send PING to all the supernodes
        if(!eee->conf.connect_tcp)
            send_query_peer(eee, null_mac);
        eee->last_sweep = now;

        // no answer yet (so far, unused in regular edge code; mainly used during bootstrap loading)
        eee->sn_pong = 0;
    }

    return 0; /* OK */
}

/** Send a REGISTER packet to another edge. */
static void send_register (n2n_edge_t * eee,
                           const n2n_sock_t * remote_peer,
                           const n2n_mac_t peer_mac,
                           const n2n_cookie_t cookie) {

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    /* ssize_t sent; */
    n2n_common_t cmn;
    n2n_REGISTER_t reg;
    n2n_sock_str_t sockbuf;

    if(!eee->conf.allow_p2p) {
        traceEvent(TRACE_DEBUG, "skipping register as P2P is disabled");
        return;
    }

    memset(&cmn, 0, sizeof(cmn));
    memset(&reg, 0, sizeof(reg));
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_register;
    cmn.flags = 0;
    memcpy(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

    reg.cookie = cookie;
    idx = 0;
    encode_mac(reg.srcMac, &idx, eee->device.mac_addr);

    if(peer_mac) {
        // can be NULL for multicast registrations
        idx = 0;
        encode_mac(reg.dstMac, &idx, peer_mac);
    }
    reg.dev_addr.net_addr = ntohl(eee->device.ip_addr);
    reg.dev_addr.net_bitlen = mask2bitlen(ntohl(eee->device.device_mask));
    memcpy(reg.dev_desc, eee->conf.dev_desc, N2N_DESC_SIZE);

    idx = 0;
    encode_REGISTER(pktbuf, &idx, &cmn, &reg);

    traceEvent(TRACE_INFO, "send REGISTER to [%s]",
               sock_to_cstr(sockbuf, remote_peer));

    if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED)
        packet_header_encrypt(pktbuf, idx, idx,
                              eee->conf.header_encryption_ctx_dynamic, eee->conf.header_iv_ctx_dynamic,
                              time_stamp());

    sendto_sock(eee, pktbuf, idx, remote_peer);
}

/* ************************************** */

/** Send a REGISTER_ACK packet to a peer edge. */
static void send_register_ack (n2n_edge_t * eee,
                               const n2n_sock_t * remote_peer,
                               const n2n_REGISTER_t * reg) {

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    /* ssize_t sent; */
    n2n_common_t cmn;
    n2n_REGISTER_ACK_t ack;
    n2n_sock_str_t sockbuf;

    if(!eee->conf.allow_p2p) {
        traceEvent(TRACE_DEBUG, "skipping register ACK as P2P is disabled");
        return;
    }

    memset(&cmn, 0, sizeof(cmn));
    memset(&ack, 0, sizeof(reg));
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_register_ack;
    cmn.flags = 0;
    memcpy(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

    memset(&ack, 0, sizeof(ack));
    ack.cookie = reg->cookie;
    memcpy(ack.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
    memcpy(ack.dstMac, reg->srcMac, N2N_MAC_SIZE);

    idx = 0;
    encode_REGISTER_ACK(pktbuf, &idx, &cmn, &ack);

    traceEvent(TRACE_INFO, "send REGISTER_ACK to [%s]",
               sock_to_cstr(sockbuf, remote_peer));

    if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED)
        packet_header_encrypt(pktbuf, idx, idx,
                              eee->conf.header_encryption_ctx_dynamic, eee->conf.header_iv_ctx_dynamic,
                              time_stamp());

    sendto_sock(eee, pktbuf, idx, remote_peer);
}

/* ************************************** */

static char gratuitous_arp[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* dest MAC */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* src MAC */
    0x08, 0x06, /* ARP */
    0x00, 0x01, /* ethernet */
    0x08, 0x00, /* IP */
    0x06, /* hw Size */
    0x04, /* protocol Size */
    0x00, 0x02, /* ARP reply */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* src MAC */
    0x00, 0x00, 0x00, 0x00, /* src IP */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* target MAC */
    0x00, 0x00, 0x00, 0x00 /* target IP */
};

// build a gratuitous ARP packet */
static int build_gratuitous_arp (n2n_edge_t * eee, char *buffer, uint16_t buffer_len) {

    if(buffer_len < sizeof(gratuitous_arp)) return(-1);

    memcpy(buffer, gratuitous_arp, sizeof(gratuitous_arp));
    memcpy(&buffer[6], eee->device.mac_addr, 6);
    memcpy(&buffer[22], eee->device.mac_addr, 6);
    memcpy(&buffer[28], &(eee->device.ip_addr), 4);
    memcpy(&buffer[38], &(eee->device.ip_addr), 4);

    return(sizeof(gratuitous_arp));
}

/** Called from update_supernode_reg to periodically send gratuitous ARP
 *    broadcasts. */
static void send_grat_arps (n2n_edge_t * eee) {

    uint8_t buffer[48];
    size_t len;

    traceEvent(TRACE_DEBUG, "sending gratuitous ARP...");
    len = build_gratuitous_arp(eee, (char*)buffer, sizeof(buffer));

    edge_send_packet2net(eee, buffer, len);
    edge_send_packet2net(eee, buffer, len); /* Two is better than one :-) */
}

/* ************************************** */

/** @brief Check to see if we should re-register with the supernode.
 *
 *    This is frequently called by the main loop.
 */
void update_supernode_reg (n2n_edge_t * eee, time_t now) {

    struct peer_info *peer, *tmp_peer;
    int cnt = 0;
    int off = 0;

    if((eee->sn_wait && (now > (eee->last_register_req + (eee->conf.register_interval / 10))))
     ||(eee->sn_wait == 2)) /* immediately re-register in case of RE_REGISTER_SUPER */ {
        /* fall through */
        traceEvent(TRACE_DEBUG, "update_supernode_reg: doing fast retry.");
    } else if(now < (eee->last_register_req + eee->conf.register_interval))
        return; /* Too early */

    // determine time offset to apply on last_register_req for
    // all edges's next re-registration does not happen all at once
    if(eee->sn_wait == 2) {
        // remaining 1/4 is greater than 1/10 fast retry allowance;
        // '%' might be expensive but does not happen all too often
        off = n2n_rand() % ((eee->conf.register_interval * 3) / 4);
    }

    check_join_multicast_group(eee);

    if(0 == eee->sup_attempts) {
        /* Give up on that supernode and try the next one. */
        sn_selection_criterion_bad(&(eee->curr_sn->selection_criterion));
        sn_selection_sort(&(eee->conf.supernodes));
        eee->curr_sn = eee->conf.supernodes;
        traceEvent(TRACE_WARNING, "supernode not responding, now trying [%s]", supernode_ip(eee));
        reset_sup_attempts(eee);
        // trigger out-of-schedule DNS resolution
        eee->resolution_request = 1;

        // in some multi-NATed scenarios communication gets stuck on losing connection to supernode
        // closing and re-opening the socket allows for re-establishing communication
        // this can only be done, if working on some unprivileged port and/or having sufficent
        // privileges. as we are not able to check for sufficent privileges here, we only do it
        // if port is sufficently high or unset. uncovered: privileged port and sufficent privileges
        if((eee->conf.local_port == 0) || (eee->conf.local_port > 1024)) {
            // do not explicitly disconnect every time as the condition described is rare, so ...
            // ... check that there are no external peers (indicating a working socket) ...
            HASH_ITER(hh, eee->known_peers, peer, tmp_peer)
                if(!peer->local) {
                   cnt++;
                   break;
                }
            if(!cnt) {
                // ... and then count the connection retries
                (eee->close_socket_counter)++;
                if(eee->close_socket_counter >= N2N_CLOSE_SOCKET_COUNTER_MAX) {
                    eee->close_socket_counter = 0;
                    supernode_disconnect(eee);
                }
            }

            traceEvent(TRACE_DEBUG, "reconnected to supernode");
        }
        supernode_connect(eee);

    } else {
        --(eee->sup_attempts);
    }

#ifndef HAVE_LIBPTHREAD
    if(supernode2sock(&(eee->curr_sn->sock), eee->curr_sn->ip_addr) == 0) {
#endif
        traceEvent(TRACE_INFO, "registering with supernode [%s][number of supernodes %d][attempts left %u]",
                   supernode_ip(eee), HASH_COUNT(eee->conf.supernodes), (unsigned int)eee->sup_attempts);

        send_register_super(eee);
#ifndef HAVE_LIBPTHREAD
    }
#endif

    register_with_local_peers(eee);

    // if supernode repeatedly not responding (already waiting), safeguard the
    // current known connections to peers by re-registering
    if(eee->sn_wait == 1)
        HASH_ITER(hh, eee->known_peers, peer, tmp_peer)
            if((now - peer->last_seen) > REGISTER_SUPER_INTERVAL_DFL)
                send_register(eee, &(peer->sock), peer->mac_addr, peer->last_cookie);

    eee->sn_wait = 1;

    eee->last_register_req = now - off;
}

/* ************************************** */

/** Return the IP address of the current supernode in the ring. */
static const char * supernode_ip (const n2n_edge_t * eee) {

    return (eee->curr_sn->ip_addr);
}

/* ************************************** */

/** A PACKET has arrived containing an encapsulated ethernet datagram - usually
 *    encrypted. */
static int handle_PACKET (n2n_edge_t * eee,
                          const uint8_t from_supernode,
                          const n2n_PACKET_t * pkt,
                          const n2n_sock_t * orig_sender,
                          uint8_t * payload,
                          size_t psize) {

    ssize_t                   data_sent_len;
    uint8_t *                 eth_payload = NULL;
    int                       retval = -1;
    time_t                    now;
    ether_hdr_t *             eh;
    ipstr_t                   ip_buf;
    macstr_t                  mac_buf;
    n2n_sock_str_t            sockbuf;

    now = time(NULL);

    traceEvent(TRACE_DEBUG, "handle_PACKET size %u transform %u",
               (unsigned int)psize, (unsigned int)pkt->transform);
    /* hexdump(payload, psize); */

    if(from_supernode) {
        if(is_multi_broadcast(pkt->dstMac))
            ++(eee->stats.rx_sup_broadcast);

        ++(eee->stats.rx_sup);
        eee->last_sup = now;
    } else {
        ++(eee->stats.rx_p2p);
        eee->last_p2p=now;
    }

    /* Handle transform. */
    {
        uint8_t decode_buf[N2N_PKT_BUF_SIZE];
        uint8_t deflate_buf[N2N_PKT_BUF_SIZE];
        size_t eth_size;
        n2n_transform_t rx_transop_id;
        uint8_t rx_compression_id;

        rx_transop_id = (n2n_transform_t)pkt->transform;
        rx_compression_id = pkt->compression;

        if(rx_transop_id == eee->conf.transop_id) {
            uint8_t is_multicast;
            // decrypt
            eth_payload = decode_buf;
            eth_size = eee->transop.rev(&eee->transop,
                                        eth_payload, N2N_PKT_BUF_SIZE,
                                        payload, psize, pkt->srcMac);
            ++(eee->transop.rx_cnt); /* stats */

            /* decompress if necessary */
            size_t deflate_len;

            switch(rx_compression_id) {
                case N2N_COMPRESSION_ID_NONE:
                    break; // continue afterwards

                case N2N_COMPRESSION_ID_LZO:
                    deflate_len = eee->transop_lzo.rev(&eee->transop_lzo,
                                                       deflate_buf, N2N_PKT_BUF_SIZE,
                                                       decode_buf, eth_size, pkt->srcMac);
                    break;

#ifdef HAVE_ZSTD
                case N2N_COMPRESSION_ID_ZSTD:
                    deflate_len = eee->transop_zstd.rev(&eee->transop_zstd,
                                                        deflate_buf, N2N_PKT_BUF_SIZE,
                                                        decode_buf, eth_size, pkt->srcMac);
                    break;
#endif
                default:
                    traceEvent(TRACE_WARNING, "payload decompression failed: received packet indicating unsupported %s compression.",
                               compression_str(rx_compression_id));
                    return(-1); // cannot handle it
            }

            if(rx_compression_id != N2N_COMPRESSION_ID_NONE) {
                traceEvent(TRACE_DEBUG, "payload decompression %s: deflated %u bytes to %u bytes",
                                        compression_str(rx_compression_id), eth_size, (int)deflate_len);
                eth_payload = deflate_buf;
                eth_size = deflate_len;
            }
            eh = (ether_hdr_t*)eth_payload;

            is_multicast = (is_ip6_discovery(eth_payload, eth_size) || is_ethMulticast(eth_payload, eth_size));

            if(eee->conf.drop_multicast && is_multicast) {
                traceEvent(TRACE_INFO, "dropping RX multicast");
                return(-1);
            } else if((!eee->conf.allow_routing) && (!is_multicast)) {
                /* Check if it is a routed packet */

                if((ntohs(eh->type) == 0x0800) && (eth_size >= ETH_FRAMESIZE + IP4_MIN_SIZE)) {

                    uint32_t *dst = (uint32_t*)&eth_payload[ETH_FRAMESIZE + IP4_DSTOFFSET];
                    uint8_t *dst_mac = (uint8_t*)eth_payload;

                    /* Note: all elements of the_ip are in network order */
                    if(!memcmp(dst_mac, broadcast_mac, N2N_MAC_SIZE))
                        traceEvent(TRACE_DEBUG, "RX broadcast packet destined to [%s]",
                                   intoa(ntohl(*dst), ip_buf, sizeof(ip_buf)));
                    else if((*dst != eee->device.ip_addr)) {
                        /* This is a packet that needs to be routed */
                        traceEvent(TRACE_INFO, "discarding routed packet destined to [%s]",
                                   intoa(ntohl(*dst), ip_buf, sizeof(ip_buf)));
                        return(-1);
                    } else {
                        /* This packet is directed to us */
                        /* traceEvent(TRACE_INFO, "Sending non-routed packet"); */
                    }
                }
            }

#ifdef HAVE_BRIDGING_SUPPORT
            if((eee->conf.allow_routing) && (!is_multi_broadcast(eh->shost))) {
                struct host_info *host = NULL;

                HASH_FIND(hh, eee->known_hosts, eh->shost, sizeof(n2n_mac_t), host);
                if(host == NULL) {
                    struct host_info *host = calloc(1, sizeof(struct host_info));
                    memcpy(host->mac_addr, eh->shost, sizeof(n2n_mac_t));
                    memcpy(host->edge_addr, pkt->srcMac, sizeof(n2n_mac_t));
                    host->last_seen = now;
                    HASH_ADD(hh, eee->known_hosts, mac_addr, sizeof(n2n_mac_t), host);
                } else {
                    memcpy(host->edge_addr, pkt->srcMac, sizeof(n2n_mac_t));
                    host->last_seen = now;
                }
            }
#endif

            if(eee->network_traffic_filter->filter_packet_from_peer(eee->network_traffic_filter, eee, orig_sender,
                                                                    eth_payload, eth_size) == N2N_DROP) {
                traceEvent(TRACE_DEBUG, "filtered packet of size %u", (unsigned int)eth_size);
                return(0);
            }

            if(eee->cb.packet_from_peer) {
                uint16_t tmp_eth_size = eth_size;
                if(eee->cb.packet_from_peer(eee, orig_sender, eth_payload, &tmp_eth_size) == N2N_DROP) {
                    traceEvent(TRACE_DEBUG, "DROP packet of size %u", (unsigned int)eth_size);
                    return(0);
                }
                eth_size = tmp_eth_size;
            }

            /* Write ethernet packet to tap device. */
            traceEvent(TRACE_DEBUG, "sending data of size %u to TAP", (unsigned int)eth_size);
            data_sent_len = tuntap_write(&(eee->device), eth_payload, eth_size);

            if(data_sent_len == eth_size) {
                retval = 0;
            }
        } else {
                traceEvent(TRACE_WARNING, "invalid transop ID: expected %s (%u), got %s (%u) from %s [%s]",
                           transop_str(eee->conf.transop_id), eee->conf.transop_id,
                           transop_str(rx_transop_id), rx_transop_id,
                           macaddr_str(mac_buf, pkt->srcMac),
                           sock_to_cstr(sockbuf, orig_sender));
        }
    }

    return retval;
}

/* ************************************** */


#if 0
#ifndef _WIN32

static char *get_ip_from_arp (dec_ip_str_t buf, const n2n_mac_t req_mac) {

    FILE *fd;
    dec_ip_str_t ip_str = {'\0'};
    devstr_t dev_str = {'\0'};
    macstr_t mac_str = {'\0'};
    n2n_mac_t mac = {'\0'};

    strncpy(buf, "0.0.0.0", N2N_NETMASK_STR_SIZE - 1);

    if(is_null_mac(req_mac)) {
        traceEvent(TRACE_DEBUG, "MAC address is null.");
        return buf;
    }

    if(!(fd = fopen("/proc/net/arp", "r"))) {
        traceEvent(TRACE_WARNING, "could not open arp table: %d - %s", errno, strerror(errno));
        return buf;
    }

    while(!feof(fd) && fgetc(fd) != '\n');
    while(!feof(fd) && (fscanf(fd, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %15s", ip_str, mac_str, dev_str) == 3)) {
        str2mac(mac, mac_str);
        if(0 == memcmp(mac, req_mac, sizeof(n2n_mac_t))) {
            strncpy(buf, ip_str, N2N_NETMASK_STR_SIZE - 1);
            break;
        }
    }
    fclose(fd);

    return buf;
}

#endif
#endif

/* ************************************** */

static int check_query_peer_info (n2n_edge_t *eee, time_t now, n2n_mac_t mac) {

    struct peer_info *scan;

    HASH_FIND_PEER(eee->pending_peers, mac, scan);

    if(!scan) {
        scan = calloc(1, sizeof(struct peer_info));

        memcpy(scan->mac_addr, mac, N2N_MAC_SIZE);
        scan->timeout = eee->conf.register_interval; /* TODO: should correspond to the peer supernode registration timeout */
        scan->last_seen = now; /* Don't change this it marks the pending peer for removal. */
        scan->last_valid_time_stamp = initial_time_stamp();

        HASH_ADD_PEER(eee->pending_peers, scan);
    }

    if(now - scan->last_sent_query > eee->conf.register_interval) {
        send_register(eee, &(eee->curr_sn->sock), mac, N2N_FORWARDED_REG_COOKIE);
        send_query_peer(eee, scan->mac_addr);
        scan->last_sent_query = now;
        return(0);
    }

    return(1);
}

/* ************************************** */

/* @return 1 if destination is a peer, 0 if destination is supernode */
static int find_peer_destination (n2n_edge_t * eee,
                                  n2n_mac_t mac_address,
                                  n2n_sock_t * destination) {

    struct peer_info *scan;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    int retval = 0;
    time_t now = time(NULL);

    if(is_multi_broadcast(mac_address)) {
        traceEvent(TRACE_DEBUG, "multicast or broadcast destination peer, using supernode");
        memcpy(destination, &(eee->curr_sn->sock), sizeof(struct sockaddr_in));
        return(0);
    }

    traceEvent(TRACE_DEBUG, "searching destination socket for %s",
                            macaddr_str(mac_buf, mac_address));

    HASH_FIND_PEER(eee->known_peers, mac_address, scan);

    if(scan && (scan->last_seen > 0)) {
        if((now - scan->last_p2p) >= (scan->timeout / 2)) {
            /* Too much time passed since we saw the peer, need to register again
             * since the peer address may have changed. */
            traceEvent(TRACE_DEBUG, "refreshing idle known peer");
            HASH_DEL(eee->known_peers, scan);
            mgmt_event_post(N2N_EVENT_PEER,N2N_EVENT_PEER_DEL_P2P,scan);
            free(scan);
            /* NOTE: registration will be performed upon the receival of the next response packet */
        } else {
            /* Valid known peer found */
            memcpy(destination, &scan->sock, sizeof(n2n_sock_t));
            retval = 1;
        }
    }

    if(retval == 0) {
        memcpy(destination, &(eee->curr_sn->sock), sizeof(struct sockaddr_in));
        traceEvent(TRACE_DEBUG, "p2p peer %s not found, using supernode",
                                macaddr_str(mac_buf, mac_address));

        check_query_peer_info(eee, now, mac_address);
    }

    traceEvent(TRACE_DEBUG, "found peer's socket %s [%s]",
               macaddr_str(mac_buf, mac_address),
               sock_to_cstr(sockbuf, destination));

    return retval;
}

/* ***************************************************** */

/** Send an ecapsulated ethernet PACKET to a destination edge or broadcast MAC
 *    address. */
static int send_packet (n2n_edge_t * eee,
                        n2n_mac_t dstMac,
                        const uint8_t * pktbuf,
                        size_t pktlen) {

    int is_p2p;
    /*ssize_t s; */
    n2n_sock_str_t sockbuf;
    n2n_sock_t destination;
    macstr_t mac_buf;
    struct peer_info *peer, *tmp_peer;

    /* hexdump(pktbuf, pktlen); */

    is_p2p = find_peer_destination(eee, dstMac, &destination);

    traceEvent(TRACE_INFO, "Tx PACKET of %u bytes to %s [%s]",
               pktlen, macaddr_str(mac_buf, dstMac),
               sock_to_cstr(sockbuf, &destination));

    if(is_p2p)
        ++(eee->stats.tx_p2p);
    else
        ++(eee->stats.tx_sup);

    if(is_multi_broadcast(dstMac)) {
        ++(eee->stats.tx_sup_broadcast);

        // if no supernode around, foward the broadcast to all known peers
        if(eee->sn_wait) {
            HASH_ITER(hh, eee->known_peers, peer, tmp_peer)
                sendto_sock(eee, pktbuf, pktlen, &peer->sock);
            return 0;
        }
        // fall through otherwise
    }

    sendto_sock(eee, pktbuf, pktlen, &destination);

    return 0;
}

/* ************************************** */

/** A layer-2 packet was received at the tunnel and needs to be sent via UDP. */
void edge_send_packet2net (n2n_edge_t * eee,
                           uint8_t *tap_pkt, size_t len) {

    ipstr_t ip_buf;
    n2n_mac_t destMac;
    n2n_common_t cmn;
    n2n_PACKET_t pkt;
    uint8_t *enc_src = tap_pkt;
    size_t enc_len = len;
    uint8_t compression_buf[N2N_PKT_BUF_SIZE];
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    n2n_transform_t tx_transop_idx = eee->transop.transform_id;
    ether_hdr_t eh;

    /* tap_pkt is not aligned so we have to copy to aligned memory */
    memcpy(&eh, tap_pkt, sizeof(ether_hdr_t));

    /* Discard IP packets that are not originated by this hosts */
    if(!(eee->conf.allow_routing)) {
        if(ntohs(eh.type) == 0x0800) {
            /* This is an IP packet from the local source address - not forwarded. */
            uint32_t *src = (uint32_t*)&tap_pkt[ETH_FRAMESIZE + IP4_SRCOFFSET];

            /* Note: all elements of the_ip are in network order */
            if(*src != eee->device.ip_addr) {
                /* This is a packet that needs to be routed */
                traceEvent(TRACE_INFO, "discarding routed packet destined to [%s]",
                           intoa(ntohl(*src), ip_buf, sizeof(ip_buf)));
                return;
            } else {
                /* This packet is originated by us */
                /* traceEvent(TRACE_INFO, "Sending non-routed packet"); */
            }
        }
    }

    /* Optionally compress then apply transforms, eg encryption. */

    /* Once processed, send to destination in PACKET */

    memcpy(destMac, tap_pkt, N2N_MAC_SIZE); /* dest MAC is first in ethernet header */
#ifdef HAVE_BRIDGING_SUPPORT
    /* find the destMac behind which edge, and change dest to this edge */
    if((eee->conf.allow_routing) && (!is_multi_broadcast(destMac))) {
        struct host_info *host = NULL;
        HASH_FIND(hh, eee->known_hosts, destMac, sizeof(n2n_mac_t), host);
        if(host) {
            memcpy(destMac, host->edge_addr, N2N_MAC_SIZE);
        }
    }
#endif

    memset(&cmn, 0, sizeof(cmn));
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_packet;
    cmn.flags = 0; /* no options, not from supernode, no socket */
    memcpy(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

    memset(&pkt, 0, sizeof(pkt));
    memcpy(pkt.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
    memcpy(pkt.dstMac, destMac, N2N_MAC_SIZE);

    pkt.transform = tx_transop_idx;

    // compression needs to be tried before encode_PACKET is called for compression indication gets encoded there
    pkt.compression = N2N_COMPRESSION_ID_NONE;

    if(eee->conf.compression) {
        int32_t   compression_len;

        switch(eee->conf.compression) {
            case N2N_COMPRESSION_ID_LZO:
                compression_len = eee->transop_lzo.fwd(&eee->transop_lzo,
                                                       compression_buf, sizeof(compression_buf),
                                                       tap_pkt, len,
                                                       pkt.dstMac);

                if((compression_len > 0) && (compression_len < len)) {
                    pkt.compression = N2N_COMPRESSION_ID_LZO;
                }
                break;

#ifdef HAVE_ZSTD
            case N2N_COMPRESSION_ID_ZSTD:
                compression_len = eee->transop_zstd.fwd(&eee->transop_zstd,
                                                        compression_buf, sizeof(compression_buf),
                                                        tap_pkt, len,
                                                        pkt.dstMac);

                if((compression_len > 0) && (compression_len < len)) {
                    pkt.compression = N2N_COMPRESSION_ID_ZSTD;
                }
                break;
#endif

            default:
                break;
        }

        if(pkt.compression != N2N_COMPRESSION_ID_NONE) {
            traceEvent(TRACE_DEBUG, "payload compression [%s]: compressed %u bytes to %u bytes\n",
                       compression_str(pkt.compression), len, compression_len);
            enc_src = compression_buf;
            enc_len = compression_len;
        }
    }

    idx = 0;
    encode_PACKET(pktbuf, &idx, &cmn, &pkt);

    uint16_t headerIdx = idx;

    idx += eee->transop.fwd(&eee->transop,
                            pktbuf + idx, N2N_PKT_BUF_SIZE - idx,
                            enc_src, enc_len, pkt.dstMac);

    traceEvent(TRACE_DEBUG, "encode PACKET of %u bytes, %u bytes data, %u bytes overhead, transform %u",
               (u_int)idx, (u_int)len, (u_int)(idx - len), tx_transop_idx);

    if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED)
        // in case of user-password auth, also encrypt the iv of payload assuming ChaCha20 and SPECK having the same iv size
        packet_header_encrypt(pktbuf, headerIdx + (NULL != eee->conf.shared_secret) * min(idx - headerIdx, N2N_SPECK_IVEC_SIZE), idx,
                              eee->conf.header_encryption_ctx_dynamic, eee->conf.header_iv_ctx_dynamic,
                              time_stamp());

#ifdef MTU_ASSERT_VALUE
    {
        const u_int eth_udp_overhead = ETH_FRAMESIZE + IP4_MIN_SIZE + UDP_SIZE;

        // MTU assertion which avoids fragmentation by N2N
        assert(idx + eth_udp_overhead <= MTU_ASSERT_VALUE);
    }
#endif

    eee->transop.tx_cnt++; /* stats */

    send_packet(eee, destMac, pktbuf, idx); /* to peer or supernode */
}

/* ************************************** */

/** Read a single packet from the TAP interface, process it and write out the
 *    corresponding packet to the cooked socket.
 */
void edge_read_from_tap (n2n_edge_t * eee) {

    /* tun -> remote */
    uint8_t                         eth_pkt[N2N_PKT_BUF_SIZE];
    macstr_t                        mac_buf;
    ssize_t                         len;

    len = tuntap_read( &(eee->device), eth_pkt, N2N_PKT_BUF_SIZE );
    if((len <= 0) || (len > N2N_PKT_BUF_SIZE)) {
        traceEvent(TRACE_WARNING, "read()=%d [%d/%s]",
                   (signed int)len, errno, strerror(errno));
        traceEvent(TRACE_WARNING, "TAP I/O operation aborted, restart later.");
        sleep(3);
        tuntap_close(&(eee->device));
        tuntap_open(&(eee->device), eee->tuntap_priv_conf.tuntap_dev_name, eee->tuntap_priv_conf.ip_mode, eee->tuntap_priv_conf.ip_addr,
                    eee->tuntap_priv_conf.netmask, eee->tuntap_priv_conf.device_mac, eee->tuntap_priv_conf.mtu,
                    eee->tuntap_priv_conf.metric
                    );
    } else {
        const uint8_t * mac = eth_pkt;
        traceEvent(TRACE_DEBUG, "Rx TAP packet (%4d) for %s",
                   (signed int)len, macaddr_str(mac_buf, mac));

        if(eee->conf.drop_multicast &&
           (is_ip6_discovery(eth_pkt, len) ||
            is_ethMulticast(eth_pkt, len))) {
                traceEvent(TRACE_INFO, "dropping Tx multicast");
        } else {
            if(!eee->last_sup) {
                // drop packets before first registration with supernode
                traceEvent(TRACE_DEBUG, "DROP packet before first registration with supernode");
                return;
            }

            if(eee->network_traffic_filter) {
                if(eee->network_traffic_filter->filter_packet_from_tap(eee->network_traffic_filter, eee, eth_pkt,
                                                                           len) == N2N_DROP) {
                    traceEvent(TRACE_DEBUG, "filtered packet of size %u", (unsigned int)len);
                    return;
                }
            }

            if(eee->cb.packet_from_tap) {
                uint16_t tmp_len = len;
                if(eee->cb.packet_from_tap(eee, eth_pkt, &tmp_len) == N2N_DROP) {
                    traceEvent(TRACE_DEBUG, "DROP packet of size %u", (unsigned int)len);
                    return;
                }
                len = tmp_len;
            }

            edge_send_packet2net(eee, eth_pkt, len);
        }
    }
}


/* ************************************** */


/** handle a datagram from the main UDP socket to the internet. */
void process_udp (n2n_edge_t *eee, const struct sockaddr *sender_sock, const SOCKET in_sock,
                 uint8_t *udp_buf, size_t udp_size, time_t now) {

    n2n_common_t          cmn; /* common fields in the packet header */
    n2n_sock_str_t        sockbuf1;
    n2n_sock_str_t        sockbuf2; /* don't clobber sockbuf1 if writing two addresses to trace */
    macstr_t              mac_buf1;
    macstr_t              mac_buf2;
    uint8_t               hash_buf[16];
    size_t                rem;
    size_t                idx;
    size_t                msg_type;
    uint8_t               from_supernode;
    uint8_t               via_multicast;
    peer_info_t           *sn = NULL;
    n2n_sock_t            sender;
    n2n_sock_t *          orig_sender = NULL;
    uint32_t              header_enc = 0;
    uint64_t              stamp = 0;
    int                   skip_add = 0;

    /* REVISIT: when UDP/IPv6 is supported we will need a flag to indicate which
     * IP transport version the packet arrived on. May need to UDP sockets. */

    memset(&sender, 0, sizeof(n2n_sock_t));

    if(eee->conf.connect_tcp)
        // TCP expects that we know our comm partner and does not deliver the sender
        memcpy(&sender, &(eee->curr_sn->sock), sizeof(struct sockaddr_in));
    else {
        // REVISIT: type conversion back and forth, choose a consistent approach throughout whole code,
        //          i.e. stick with more general sockaddr as long as possible and narrow only if required
        fill_n2nsock(&sender, sender_sock);
    }
    /* The packet may not have an orig_sender socket spec. So default to last
     * hop as sender. */
    orig_sender = &sender;

#ifdef SKIP_MULTICAST_PEERS_DISCOVERY
    via_multicast = 0;
#else
    via_multicast = (in_sock == eee->udp_multicast_sock);
#endif

    traceEvent(TRACE_DEBUG, "Rx N2N_UDP of size %d from [%s]",
               (signed int)udp_size, sock_to_cstr(sockbuf1, &sender));

    if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
        // match with static (1) or dynamic (2) ctx?
        // check dynamic first as it is identical to static in normal header encryption mode
        if(packet_header_decrypt(udp_buf, udp_size,
                                     (char *)eee->conf.community_name,
                                     eee->conf.header_encryption_ctx_dynamic, eee->conf.header_iv_ctx_dynamic,
                                     &stamp)) {
                header_enc = 2; /* not accurate with normal header encryption but does not matter */
        }
        if(!header_enc) {
            // check static now (very likely to be REGISTER_SUPER_ACK, REGISTER_SUPER_NAK or invalid)
            if(eee->conf.shared_secret) {
                // hash the still encrypted packet to eventually be able to check it later (required for REGISTER_SUPER_ACK with user/pw auth)
                pearson_hash_128(hash_buf, udp_buf, max(0, (int)udp_size - (int)N2N_REG_SUP_HASH_CHECK_LEN));
            }
            header_enc = packet_header_decrypt(udp_buf, max(0, (int)udp_size - (int)N2N_REG_SUP_HASH_CHECK_LEN),
                                           (char *)eee->conf.community_name,
                                           eee->conf.header_encryption_ctx_static, eee->conf.header_iv_ctx_static,
                                           &stamp);
        }
        if(!header_enc) {
            traceEvent(TRACE_DEBUG, "failed to decrypt header");
            return;
        }
        // time stamp verification follows in the packet specific section as it requires to determine the
        // sender from the hash list by its MAC, or the packet might be from the supernode, this all depends
        // on packet type, path taken (via supernode) and packet structure (MAC is not always in the same place)
    }

    rem = udp_size; /* Counts down bytes of packet to protect against buffer overruns. */
    idx = 0; /* marches through packet header as parts are decoded. */
    if(decode_common(&cmn, udp_buf, &rem, &idx) < 0) {
        if(via_multicast) {
            // from some other edge on local network, possibly header encrypted
            traceEvent(TRACE_DEBUG, "dropped packet arriving via multicast due to error while decoding N2N_UDP");
        } else {
            traceEvent(TRACE_INFO, "failed to decode common section in N2N_UDP");
        }
        return; /* failed to decode packet */
    }

    msg_type = cmn.pc; /* packet code */

    // special case for user/pw auth
    // community's auth scheme and message type need to match the used key (dynamic)
    if((eee->conf.shared_secret)
    && (msg_type != MSG_TYPE_REGISTER_SUPER_ACK)
    && (msg_type != MSG_TYPE_REGISTER_SUPER_NAK)) {
        if(header_enc != 2) {
            traceEvent(TRACE_INFO, "dropped packet encrypted with static key where dynamic key expected");
            return;
        }
    }

    // check if packet is from supernode and find the corresponding supernode in list
    from_supernode = cmn.flags & N2N_FLAGS_FROM_SUPERNODE;
    if(from_supernode) {
        skip_add = SN_ADD_SKIP;
        sn = add_sn_to_list_by_mac_or_sock(&(eee->conf.supernodes), &sender, null_mac, &skip_add);
        if(!sn) {
            traceEvent(TRACE_DEBUG, "dropped incoming data from unknown supernode");
            return;
        }
    }

    if(0 == memcmp(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE)) {
        switch(msg_type) {
            case MSG_TYPE_PACKET: {
                /* process PACKET - most frequent so first in list. */
                n2n_PACKET_t pkt;

                decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx);

                if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_peer_time_stamp_and_verify(eee, sn, pkt.srcMac, stamp, TIME_STAMP_ALLOW_JITTER)) {
                        traceEvent(TRACE_DEBUG, "dropped PACKET due to time stamp error");
                        return;
                    }
                }

                if(!eee->last_sup) {
                    // drop packets received before first registration with supernode
                    traceEvent(TRACE_DEBUG, "dropped PACKET recevied before first registration with supernode");
                    return;
                }

                if(!from_supernode) {
                    /* This is a P2P packet from the peer. We purge a pending
                     * registration towards the possibly nat-ted peer address as we now have
                     * a valid channel. We still use check_peer_registration_needed in
                     * handle_PACKET to double check this.
                     */
                    traceEvent(TRACE_DEBUG, "[p2p] from %s",
                               macaddr_str(mac_buf1, pkt.srcMac));
                    find_and_remove_peer(&eee->pending_peers, pkt.srcMac);
                } else {
                    /* [PsP] : edge Peer->Supernode->edge Peer */

                    if(is_valid_peer_sock(&pkt.sock))
                        orig_sender = &(pkt.sock);

                    traceEvent(TRACE_DEBUG, "[pSp] from %s via [%s]",
                               macaddr_str(mac_buf1, pkt.srcMac),
                               sock_to_cstr(sockbuf1, &sender));
                }

                /* Update the sender in peer table entry */
                check_peer_registration_needed(eee, from_supernode, via_multicast,
                                               pkt.srcMac,
                                               // REVISIT: also consider PORT_REG_COOKIEs when implemented
                                               from_supernode ? N2N_FORWARDED_REG_COOKIE : N2N_REGULAR_REG_COOKIE,
                                               NULL, NULL, orig_sender);

                handle_PACKET(eee, from_supernode, &pkt, orig_sender, udp_buf + idx, udp_size - idx);
                break;
            }

            case MSG_TYPE_REGISTER: {
                /* Another edge is registering with us */
                n2n_REGISTER_t reg;

                decode_REGISTER(&reg, &cmn, udp_buf, &rem, &idx);

                via_multicast &= is_null_mac(reg.dstMac);

                if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_peer_time_stamp_and_verify(eee, sn, reg.srcMac, stamp,
                                                        via_multicast ? TIME_STAMP_ALLOW_JITTER : TIME_STAMP_NO_JITTER)) {
                        traceEvent(TRACE_DEBUG, "dropped REGISTER due to time stamp error");
                        return;
                    }
                }

                if(is_valid_peer_sock(&reg.sock))
                    orig_sender = &(reg.sock);

                if(via_multicast && !memcmp(reg.srcMac, eee->device.mac_addr, N2N_MAC_SIZE)) {
                    traceEvent(TRACE_DEBUG, "skipping REGISTER from self");
                    break;
                }

                if(!via_multicast && memcmp(reg.dstMac, eee->device.mac_addr, N2N_MAC_SIZE)) {
                    traceEvent(TRACE_DEBUG, "skipping REGISTER for other peer");
                    break;
                }

                if(!from_supernode) {
                    /* This is a P2P registration from the peer. We purge a pending
                     * registration towards the possibly nat-ted peer address as we now have
                     * a valid channel. We still use check_peer_registration_needed below
                     * to double check this.
                     */
                    traceEvent(TRACE_INFO, "[p2p] Rx REGISTER from %s [%s]%s",
                                           macaddr_str(mac_buf1, reg.srcMac),
                                           sock_to_cstr(sockbuf1, &sender),
                                           (reg.cookie & N2N_LOCAL_REG_COOKIE) ? " (local)" : "");
                    find_and_remove_peer(&eee->pending_peers, reg.srcMac);

                    /* NOTE: only ACK to peers */
                    send_register_ack(eee, orig_sender, &reg);
                } else {
                    traceEvent(TRACE_INFO, "[pSp] Rx REGISTER from %s [%s] to %s via [%s]",
                               macaddr_str(mac_buf1, reg.srcMac), sock_to_cstr(sockbuf2, orig_sender),
                               macaddr_str(mac_buf2, reg.dstMac), sock_to_cstr(sockbuf1, &sender));
                }

                check_peer_registration_needed(eee, from_supernode, via_multicast,
                                               reg.srcMac, reg.cookie, &reg.dev_addr, (const n2n_desc_t*)&reg.dev_desc, orig_sender);
                break;
            }

            case MSG_TYPE_REGISTER_ACK: {
                /* Peer edge is acknowledging our register request */
                n2n_REGISTER_ACK_t ra;

                decode_REGISTER_ACK(&ra, &cmn, udp_buf, &rem, &idx);

                if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_peer_time_stamp_and_verify(eee, sn, ra.srcMac, stamp, TIME_STAMP_NO_JITTER)) {
                        traceEvent(TRACE_DEBUG, "dropped REGISTER_ACK due to time stamp error");
                        return;
                    }
                }

                if(is_valid_peer_sock(&ra.sock))
                    orig_sender = &(ra.sock);

                traceEvent(TRACE_INFO, "Rx REGISTER_ACK from %s [%s] to %s via [%s]%s",
                           macaddr_str(mac_buf1, ra.srcMac),
                           sock_to_cstr(sockbuf2, orig_sender),
                           macaddr_str(mac_buf2, ra.dstMac),
                           sock_to_cstr(sockbuf1, &sender),
                          (ra.cookie & N2N_LOCAL_REG_COOKIE) ? " (local)" : "");

                peer_set_p2p_confirmed(eee, ra.srcMac,
                                      ra.cookie,
                                      &sender, now);
                break;
            }

            case MSG_TYPE_REGISTER_SUPER_ACK: {
                in_addr_t net;
                char * ip_str = NULL;
                n2n_REGISTER_SUPER_ACK_t ra;
                uint8_t tmpbuf[REG_SUPER_ACK_PAYLOAD_SPACE];
                char ip_tmp[N2N_EDGE_SN_HOST_SIZE];
                n2n_REGISTER_SUPER_ACK_payload_t *payload;
                n2n_sock_t payload_sock;
                int i;
                int skip_add;

                if(!(eee->sn_wait)) {
                    traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER_ACK with no outstanding REGISTER_SUPER");
                    return;
                }

                memset(&ra, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));
                decode_REGISTER_SUPER_ACK(&ra, &cmn, udp_buf, &rem, &idx, tmpbuf);

                if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_peer_time_stamp_and_verify(eee, sn, ra.srcMac, stamp, TIME_STAMP_NO_JITTER)) {
                        traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER_ACK due to time stamp error");
                        return;
                    }
                }

                // hash check (user/pw auth only)
                if(eee->conf.shared_secret) {
                    speck_128_encrypt(hash_buf, (speck_context_t*)eee->conf.shared_secret_ctx);
                    if(memcmp(hash_buf, udp_buf + udp_size - N2N_REG_SUP_HASH_CHECK_LEN /* length is has already been checked */, N2N_REG_SUP_HASH_CHECK_LEN)) {
                        traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK with wrong hash");
                        return;
                    }
                }

                if(ra.cookie != eee->curr_sn->last_cookie) {
                    traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK with wrong or old cookie");
                    return;
                }

                if(handle_remote_auth(eee, sn, &(ra.auth))) {
                    traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK with wrong or old response to challenge");
                    if(eee->conf.shared_secret) {
                        traceEvent(TRACE_NORMAL, "Rx REGISTER_SUPER_ACK with wrong or old response to challenge, maybe indicating wrong federation public key (-P)");
                    }
                    return;
                }

                if(is_valid_peer_sock(&ra.sock))
                    orig_sender = &(ra.sock);

                traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK from %s [%s] (external %s) with %u attempts left",
                           macaddr_str(mac_buf1, ra.srcMac),
                           sock_to_cstr(sockbuf1, &sender),
                           sock_to_cstr(sockbuf2, orig_sender),
                           (unsigned int)eee->sup_attempts);

                if(is_null_mac(eee->curr_sn->mac_addr)) {
                    HASH_DEL(eee->conf.supernodes, eee->curr_sn);
                    memcpy(&eee->curr_sn->mac_addr, ra.srcMac, N2N_MAC_SIZE);
                    HASH_ADD_PEER(eee->conf.supernodes, eee->curr_sn);
                }

                payload = (n2n_REGISTER_SUPER_ACK_payload_t*)tmpbuf;

                // from here on, 'sn' gets used differently
                for(i = 0; i < ra.num_sn; i++) {
                    skip_add = SN_ADD;

                    // bugfix for https://github.com/ntop/n2n/issues/1029
                    // REVISIT: best to be removed with 4.0
                    idx = 0;
                    rem = sizeof(payload->sock);
                    decode_sock_payload(&payload_sock, payload->sock, &rem, &idx);

                    sn = add_sn_to_list_by_mac_or_sock(&(eee->conf.supernodes), &payload_sock, payload->mac, &skip_add);

                    if(skip_add == SN_ADD_ADDED) {
                        sn->ip_addr = calloc(1, N2N_EDGE_SN_HOST_SIZE);
                        if(sn->ip_addr != NULL) {
                            inet_ntop(payload_sock.family,
                                      (payload_sock.family == AF_INET) ? (void*)&(payload_sock.addr.v4) : (void*)&(payload_sock.addr.v6),
                                      sn->ip_addr, N2N_EDGE_SN_HOST_SIZE - 1);
                            sprintf(ip_tmp, "%s:%u", (char*)sn->ip_addr, (uint16_t)(payload_sock.port));
                            memcpy(sn->ip_addr, ip_tmp, sizeof(ip_tmp));
                        }
                        sn_selection_criterion_default(&(sn->selection_criterion));
                        sn->last_seen = 0; /* as opposed to payload handling in supernode */
                        traceEvent(TRACE_NORMAL, "supernode '%s' added to the list of supernodes.", sn->ip_addr);
                    }
                    // shift to next payload entry
                    payload++;
                }

                if(eee->conf.tuntap_ip_mode == TUNTAP_IP_MODE_SN_ASSIGN) {
                    if((ra.dev_addr.net_addr != 0) && (ra.dev_addr.net_bitlen != 0)) {
                        net = htonl(ra.dev_addr.net_addr);
                        if((ip_str = inet_ntoa(*(struct in_addr *) &net)) != NULL) {
                            strncpy(eee->tuntap_priv_conf.ip_addr, ip_str, N2N_NETMASK_STR_SIZE);
                            eee->tuntap_priv_conf.ip_addr[N2N_NETMASK_STR_SIZE - 1] = '\0';
                        }
                        net = htonl(bitlen2mask(ra.dev_addr.net_bitlen));
                        if((ip_str = inet_ntoa(*(struct in_addr *) &net)) != NULL) {
                            strncpy(eee->tuntap_priv_conf.netmask, ip_str, N2N_NETMASK_STR_SIZE);
                            eee->tuntap_priv_conf.netmask[N2N_NETMASK_STR_SIZE - 1] = '\0';
                        }
                    }
                }

                eee->sn_wait = 0;
                reset_sup_attempts(eee); /* refresh because we got a response */

                // update last_sup only on 'real' REGISTER_SUPER_ACKs, not on bootstrap ones (own MAC address
                // still null_mac) this allows reliable in/out PACKET drop if not really registered with a supernode yet
                if(!is_null_mac(eee->device.mac_addr)) {
                    if(!eee->last_sup) {
                        // indicates first successful connection between the edge and a supernode
                        traceEvent(TRACE_NORMAL, "[OK] edge <<< ================ >>> supernode");
                        // send gratuitous ARP only upon first registration with supernode
                        send_grat_arps(eee);
                    }
                    eee->last_sup = now;
                }

                // NOTE: the register_interval should be chosen by the edge node based on its NAT configuration.
                // eee->conf.register_interval = ra.lifetime;

                if(eee->cb.sn_registration_updated && !is_null_mac(eee->device.mac_addr))
                    eee->cb.sn_registration_updated(eee, now, &sender);

                break;
            }

            case MSG_TYPE_REGISTER_SUPER_NAK: {

                n2n_REGISTER_SUPER_NAK_t nak;

                if(!(eee->sn_wait)) {
                    traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER_NAK with no outstanding REGISTER_SUPER");
                    return;
                }

                memset(&nak, 0, sizeof(n2n_REGISTER_SUPER_NAK_t));
                decode_REGISTER_SUPER_NAK(&nak, &cmn, udp_buf, &rem, &idx);

                if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_peer_time_stamp_and_verify(eee, sn, nak.srcMac, stamp, TIME_STAMP_NO_JITTER)) {
                        traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER_NAK due to time stamp error");
                        return;
                    }
                }

                if(nak.cookie != eee->curr_sn->last_cookie) {
                    traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER_NAK with wrong or old cookie");
                    return;
                }

                // REVISIT: authenticate the NAK packet really originating from the supernode along the auth token.
                //          this must follow a different scheme because it needs to prove authenticity although the
                //          edge-provided credentials are wrong

                traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_NAK");

                if((memcmp(nak.srcMac, eee->device.mac_addr, sizeof(n2n_mac_t))) == 0) {
                    if(eee->conf.shared_secret) {
                        traceEvent(TRACE_ERROR, "authentication error, username or password not recognized by supernode");
                    } else {
                        traceEvent(TRACE_ERROR, "authentication error, MAC or IP address already in use or not released yet by supernode");
                    }
                    // REVISIT: the following portion is too harsh, repeated error warning should be sufficient until it eventually is resolved,
                    //           preventing de-auth attacks
                    /* exit(1); this is too harsh, repeated error warning should be sufficient until it eventually is resolved, preventing de-auth attacks
                } else {
                    HASH_FIND_PEER(eee->known_peers, nak.srcMac, peer);
                    if(peer != NULL) {
                        HASH_DEL(eee->known_peers, peer);
                    }
                    HASH_FIND_PEER(eee->pending_peers, nak.srcMac, scan);
                    if(scan != NULL) {
                        HASH_DEL(eee->pending_peers, scan);
                    } */
                }
                break;
            }

            case MSG_TYPE_PEER_INFO: {

                n2n_PEER_INFO_t pi;
                struct peer_info * scan;
                int skip_add;

                decode_PEER_INFO(&pi, &cmn, udp_buf, &rem, &idx);

                if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_peer_time_stamp_and_verify(eee, sn, null_mac, stamp, TIME_STAMP_ALLOW_JITTER)) {
                        traceEvent(TRACE_DEBUG, "dropped PEER_INFO due to time stamp error");
                        return;
                    }
                }

                if((cmn.flags & N2N_FLAGS_SOCKET) && !is_valid_peer_sock(&pi.sock)) {
                    traceEvent(TRACE_DEBUG, "skip invalid PEER_INFO from %s [%s]",
                              macaddr_str(mac_buf1, pi.mac),
                              sock_to_cstr(sockbuf1, &pi.sock));
                    break;
                }

                if(is_null_mac(pi.mac)) {
                    // PONG - answer to PING (QUERY_PEER_INFO with null mac)
                    skip_add = SN_ADD_SKIP;
                    scan = add_sn_to_list_by_mac_or_sock(&(eee->conf.supernodes), &sender, pi.srcMac, &skip_add);
                    if(scan != NULL) {
                        eee->sn_pong = 1;
                        scan->last_seen = now;
                        scan->uptime = pi.uptime;
                        memcpy(scan->version, pi.version, sizeof(n2n_version_t));
                        /* The data type depends on the actual selection strategy that has been chosen. */
                        SN_SELECTION_CRITERION_DATA_TYPE sn_sel_tmp = pi.load;
                        sn_selection_criterion_calculate(eee, scan, &sn_sel_tmp);

                        traceEvent(TRACE_INFO, "Rx PONG from supernode %s version '%s'",
                                   macaddr_str(mac_buf1, pi.srcMac),
                                   pi.version);

                        break;
                    }
                } else {
                    // regular PEER_INFO
                    HASH_FIND_PEER(eee->pending_peers, pi.mac, scan);
                    if(!scan)
                        // just in case the remote edge has been upgraded by the REG/ACK mechanism in the meantime
                        HASH_FIND_PEER(eee->known_peers, pi.mac, scan);

                    if(scan) {
                        scan->sock = pi.sock;

                        traceEvent(TRACE_INFO, "Rx PEER_INFO %s can be found at [%s]",
                                   macaddr_str(mac_buf1, pi.mac),
                                   sock_to_cstr(sockbuf1, &pi.sock));

                        if(cmn.flags & N2N_FLAGS_SOCKET) {
                            scan->preferred_sock = pi.preferred_sock;
                            send_register(eee, &scan->preferred_sock, scan->mac_addr, N2N_LOCAL_REG_COOKIE);

                            traceEvent(TRACE_INFO, "%s has preferred local socket at [%s]",
                                       macaddr_str(mac_buf1, pi.mac),
                                       sock_to_cstr(sockbuf1, &pi.preferred_sock));
                        }

                        send_register(eee, &scan->sock, scan->mac_addr, N2N_REGULAR_REG_COOKIE);

                    } else {
                        traceEvent(TRACE_INFO, "Rx PEER_INFO unknown peer %s",
                                   macaddr_str(mac_buf1, pi.mac));
                    }
                }
                break;
            }

            case MSG_TYPE_RE_REGISTER_SUPER: {

                if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_peer_time_stamp_and_verify(eee, sn, null_mac, stamp, TIME_STAMP_NO_JITTER)) {
                        traceEvent(TRACE_DEBUG, "dropped RE_REGISTER due to time stamp error");
                        return;
                    }
                }

                // only accept in user/pw mode for immediate re-registration because the new
                // key is required for continous traffic flow, in other modes edge will realize
                // changes with regular recurring REGISTER_SUPER
                if(!eee->conf.shared_secret) {
                    traceEvent(TRACE_DEBUG, "dropped RE_REGISTER_SUPER as not in user/pw auth mode");
                    return;
                }

                traceEvent(TRACE_INFO, "Rx RE_REGISTER_SUPER");

                eee->sn_wait = 2; /* immediately */

                break;
            }

            default:
                /* Not a known message type */
                traceEvent(TRACE_INFO, "unable to handle packet type %d: ignored", (signed int)msg_type);
                return;
        } /* switch(msg_type) */
    } else if(from_supernode) /* if(community match) */
        traceEvent(TRACE_INFO, "received packet with unknown community");
    else
        traceEvent(TRACE_INFO, "ignoring packet with unknown community");
}


/* ************************************** */


int fetch_and_eventually_process_data (n2n_edge_t *eee, SOCKET sock,
                                       uint8_t *pktbuf, uint16_t *expected, uint16_t *position,
                                       time_t now) {

    ssize_t bread = 0;

    struct sockaddr_storage sas;
    struct sockaddr *sender_sock = (struct sockaddr*)&sas;
    socklen_t ss_size = sizeof(sas);

    if((!eee->conf.connect_tcp)
#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    || (sock == eee->udp_multicast_sock)
#endif
      ) {
        // udp
        bread = recvfrom(sock, (void *)pktbuf, N2N_PKT_BUF_SIZE, 0 /*flags*/,
                         sender_sock, &ss_size);

        if((bread < 0)
#ifdef _WIN32
           && (WSAGetLastError() != WSAECONNRESET)
#endif
          ) {
            /* For UDP bread of zero just means no data (unlike TCP). */
            /* The fd is no good now. Maybe we lost our interface. */
            traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
#ifdef _WIN32
            traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
            return -1;
        }

        // we have a datagram to process...
        if(bread > 0) {
            // ...and the datagram has data (not just a header)
            process_udp(eee, sender_sock, sock, pktbuf, bread, now);
        }

    } else {
        // tcp
        bread = recvfrom(sock,
                         (void *)(pktbuf + *position), *expected - *position, 0 /*flags*/,
                        sender_sock, &ss_size);
        if((bread <= 0) && (errno)) {
            traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
#ifdef _WIN32
            traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
            supernode_disconnect(eee);
            eee->sn_wait = 1;
            goto tcp_done;
        }
        *position = *position + bread;

        if(*position == *expected) {
            if(*position == sizeof(uint16_t)) {
                // the prepended length has been read, preparing for the packet
                *expected = *expected + be16toh(*(uint16_t*)(pktbuf));
                if(*expected > N2N_PKT_BUF_SIZE) {
                    supernode_disconnect(eee);
                    eee->sn_wait = 1;
                    traceEvent(TRACE_DEBUG, "too many bytes expected");
                    goto tcp_done;
                }
            } else {
                // full packet read, handle it
                process_udp(eee, sender_sock, sock,
                                 pktbuf + sizeof(uint16_t), *position - sizeof(uint16_t), now);
                // reset, await new prepended length
                *expected = sizeof(uint16_t);
                *position = 0;
            }
        }
    }
 tcp_done:
         ;

    return 0;
}


void print_edge_stats (const n2n_edge_t *eee) {

    const struct n2n_edge_stats *s = &eee->stats;

    traceEvent(TRACE_NORMAL, "**********************************");
    traceEvent(TRACE_NORMAL, "Packet stats:");
    traceEvent(TRACE_NORMAL, "      TX P2P: %u pkts", s->tx_p2p);
    traceEvent(TRACE_NORMAL, "      RX P2P: %u pkts", s->rx_p2p);
    traceEvent(TRACE_NORMAL, "      TX Supernode: %u pkts (%u broadcast)", s->tx_sup, s->tx_sup_broadcast);
    traceEvent(TRACE_NORMAL, "      RX Supernode: %u pkts (%u broadcast)", s->rx_sup, s->rx_sup_broadcast);
    traceEvent(TRACE_NORMAL, "**********************************");
}


/* ************************************** */


int run_edge_loop (n2n_edge_t *eee) {

    size_t numPurged;
    time_t lastIfaceCheck = 0;
    time_t lastTransop = 0;
    time_t last_purge_known = 0;
    time_t last_purge_pending = 0;
#ifdef HAVE_BRIDGING_SUPPORT
    time_t last_purge_host = 0;
#endif

    uint16_t expected = sizeof(uint16_t);
    uint16_t position = 0;
    uint8_t  pktbuf[N2N_PKT_BUF_SIZE + sizeof(uint16_t)]; /* buffer + prepended buffer length in case of tcp */

#ifdef _WIN32
    struct tunread_arg arg;
    arg.eee = eee;
    HANDLE tun_read_thread = startTunReadThread(&arg);
#endif

    *eee->keep_running = true;
    update_supernode_reg(eee, time(NULL));

    /* Main loop
     *
     * select() is used to wait for input on either the TAP fd or the UDP/TCP
     * socket. When input is present the data is read and processed by either
     * readFromIPSocket() or edge_read_from_tap()
     */

    while(*eee->keep_running) {

        int rc, max_sock = 0;
        fd_set socket_mask;
        struct timeval wait_time;
        time_t now;

        FD_ZERO(&socket_mask);

        FD_SET(eee->udp_mgmt_sock, &socket_mask);
        max_sock = eee->udp_mgmt_sock;

        if(eee->sock >= 0) {
            FD_SET(eee->sock, &socket_mask);
            max_sock = max(eee->sock, eee->udp_mgmt_sock);
        }
#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
        if((eee->conf.allow_p2p)
        && (eee->conf.preferred_sock.family == (uint8_t)AF_INVALID)) {
            FD_SET(eee->udp_multicast_sock, &socket_mask);
            max_sock = max(eee->sock, eee->udp_multicast_sock);
        }
#endif

#ifndef _WIN32
        FD_SET(eee->device.fd, &socket_mask);
        max_sock = max(max_sock, eee->device.fd);
#endif

        wait_time.tv_sec = (eee->sn_wait) ? (SOCKET_TIMEOUT_INTERVAL_SECS / 10 + 1) : (SOCKET_TIMEOUT_INTERVAL_SECS);
        wait_time.tv_usec = 0;
        rc = select(max_sock + 1, &socket_mask, NULL, NULL, &wait_time);
        now = time(NULL);

        // make sure ciphers are updated before the packet is treated
        if((now - lastTransop) > TRANSOP_TICK_INTERVAL) {
            lastTransop = now;

            eee->transop.tick(&eee->transop, now);
        }

        if(rc > 0) {
            // any or all of the FDs could have input; check them all

            // external
            if((eee->sock >= 0) && FD_ISSET(eee->sock, &socket_mask)) {
                if(0 != fetch_and_eventually_process_data(eee, eee->sock,
                                                          pktbuf, &expected, &position,
                                                          now)) {
                    *eee->keep_running = false;
                    break;
                }
                if(eee->conf.connect_tcp) {
                    if((expected >= N2N_PKT_BUF_SIZE) || (position >= N2N_PKT_BUF_SIZE)) {
                        // something went wrong, possibly even before
                        // e.g. connection failure/closure in the middle of transmission (between len & data)
                        supernode_disconnect(eee);
                        eee->sn_wait = 1;

                        expected = sizeof(uint16_t);
                        position = 0;
                    }
                }
            }

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
            if(FD_ISSET(eee->udp_multicast_sock, &socket_mask)) {
                if(0 != fetch_and_eventually_process_data(eee, eee->udp_multicast_sock,
                                                          pktbuf, &expected, &position,
                                                          now)) {
                    *eee->keep_running = false;
                    break;
                }
            }
#endif

            if(FD_ISSET(eee->udp_mgmt_sock, &socket_mask)) {
                // read from the management port socket
                readFromMgmtSocket(eee);

                if(!(*eee->keep_running))
                    break;
            }

#ifndef _WIN32
            if(FD_ISSET(eee->device.fd, &socket_mask)) {
                // read an ethernet frame from the TAP socket; write on the IP socket
                edge_read_from_tap(eee);
            }
#endif
        }

        // finished processing select data
        update_supernode_reg(eee, now);

        numPurged = 0;
        // keep, i.e. do not purge, the known peers while no supernode supernode connection
        if(!eee->sn_wait)
            numPurged = purge_expired_nodes(&eee->known_peers,
                                            eee->sock, NULL,
                                            &last_purge_known,
                                            PURGE_REGISTRATION_FREQUENCY, REGISTRATION_TIMEOUT);
        numPurged += purge_expired_nodes(&eee->pending_peers,
                                         eee->sock, NULL,
                                         &last_purge_pending,
                                         PURGE_REGISTRATION_FREQUENCY, REGISTRATION_TIMEOUT);

        if(numPurged > 0) {
            traceEvent(TRACE_INFO, "%u peers removed. now: pending=%u, operational=%u",
                       numPurged,
                       HASH_COUNT(eee->pending_peers),
                       HASH_COUNT(eee->known_peers));
        }

#ifdef HAVE_BRIDGING_SUPPORT
        if((eee->conf.allow_routing) && (now > last_purge_host + SWEEP_TIME)) {
            struct host_info *host, *host_tmp;
            HASH_ITER(hh, eee->known_hosts, host, host_tmp) {
                if(now > host->last_seen + HOSTINFO_TIMEOUT) {
                    HASH_DEL(eee->known_hosts, host);
                    free(host);
                }
            }
            last_purge_host = now;
        }
#endif

        if((eee->conf.tuntap_ip_mode == TUNTAP_IP_MODE_DHCP) &&
           ((now - lastIfaceCheck) > IFACE_UPDATE_INTERVAL)) {
            uint32_t old_ip = eee->device.ip_addr;

            traceEvent(TRACE_NORMAL, "re-checking dynamic IP address");
            tuntap_get_address(&(eee->device));
            lastIfaceCheck = now;

            if((old_ip != eee->device.ip_addr) && eee->cb.ip_address_changed)
                eee->cb.ip_address_changed(eee, old_ip, eee->device.ip_addr);
        }

        sort_supernodes(eee, now);

        eee->resolution_request = resolve_check(eee->resolve_parameter, eee->resolution_request, now);

        if(eee->cb.main_loop_period)
            eee->cb.main_loop_period(eee, now);

    } /* while */

    send_unregister_super(eee);

#ifdef _WIN32
    WaitForSingleObject(tun_read_thread, INFINITE);
#endif

    supernode_disconnect(eee);

    return 0;
}

/* ************************************** */

/** Deinitialise the edge and deallocate any owned memory. */
void edge_term (n2n_edge_t * eee) {

    resolve_cancel_thread(eee->resolve_parameter);

    if(eee->sock >= 0)
        closesocket(eee->sock);

    if(eee->udp_mgmt_sock >= 0)
        closesocket(eee->udp_mgmt_sock);

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    if(eee->udp_multicast_sock >= 0)
        closesocket(eee->udp_multicast_sock);
#endif

    clear_peer_list(&eee->pending_peers);
    clear_peer_list(&eee->known_peers);
    clear_peer_list(&eee->conf.supernodes);

#ifdef HAVE_BRIDGING_SUPPORT
    if(eee->conf.allow_routing) {
        struct host_info *host, *host_tmp;
        HASH_ITER(hh, eee->known_hosts, host, host_tmp) {
            HASH_DEL(eee->known_hosts, host);
            free(host);
        }
    }
#endif

    eee->transop.deinit(&eee->transop);
    eee->transop_lzo.deinit(&eee->transop_lzo);
#ifdef HAVE_ZSTD
    eee->transop_zstd.deinit(&eee->transop_zstd);
#endif

    destroy_network_traffic_filter(eee->network_traffic_filter);

    closeTraceFile();

    free(eee);
}


/* ************************************** */


static int edge_init_sockets (n2n_edge_t *eee) {

    if(eee->udp_mgmt_sock >= 0)
        closesocket(eee->udp_mgmt_sock);

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    if(eee->udp_multicast_sock >= 0)
        closesocket(eee->udp_multicast_sock);
#endif

    eee->udp_mgmt_sock = open_socket(eee->conf.mgmt_port, INADDR_LOOPBACK, 0 /* UDP */);
    if(eee->udp_mgmt_sock < 0) {
        traceEvent(TRACE_ERROR, "failed to bind management UDP port %u", eee->conf.mgmt_port);
        return(-2);
    }

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    /* Populate the multicast group for local edge */
    eee->multicast_peer.family     = AF_INET;
    eee->multicast_peer.port       = N2N_MULTICAST_PORT;
    eee->multicast_peer.addr.v4[0] = 224; /* N2N_MULTICAST_GROUP */
    eee->multicast_peer.addr.v4[1] = 0;
    eee->multicast_peer.addr.v4[2] = 0;
    eee->multicast_peer.addr.v4[3] = 68;

    eee->udp_multicast_sock = open_socket(N2N_MULTICAST_PORT, INADDR_ANY, 0 /* UDP */);
    if(eee->udp_multicast_sock < 0)
        return(-3);
    else {
        u_int enable_reuse = 1;

        /* allow multiple sockets to use the same PORT number */
        setsockopt(eee->udp_multicast_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&enable_reuse, sizeof(enable_reuse));
#ifdef SO_REUSEPORT /* no SO_REUSEPORT in Windows / old linux versions */
        setsockopt(eee->udp_multicast_sock, SOL_SOCKET, SO_REUSEPORT, &enable_reuse, sizeof(enable_reuse));
#endif
    }
#endif

    return(0);
}


/* ************************************** */


void edge_init_conf_defaults (n2n_edge_conf_t *conf) {

    char *tmp_string;

    memset(conf, 0, sizeof(*conf));

    conf->bind_address = INADDR_ANY; /* any address */
    conf->local_port = 0 /* any port */;
    conf->preferred_sock.family = AF_INVALID;
    conf->mgmt_port = N2N_EDGE_MGMT_PORT; /* 5644 by default */
    conf->transop_id = N2N_TRANSFORM_ID_NULL;
    conf->header_encryption = HEADER_ENCRYPTION_NONE;
    conf->compression = N2N_COMPRESSION_ID_NONE;
    conf->drop_multicast = 1;
    conf->allow_p2p = 1;
    conf->disable_pmtu_discovery = 1;
    conf->register_interval = REGISTER_SUPER_INTERVAL_DFL;
    conf->tuntap_ip_mode = TUNTAP_IP_MODE_SN_ASSIGN;
    /* reserve possible last char as null terminator. */
    gethostname((char*)conf->dev_desc, N2N_DESC_SIZE-1);

    if(getenv("N2N_KEY")) {
        conf->encrypt_key = strdup(getenv("N2N_KEY"));
        conf->transop_id = N2N_TRANSFORM_ID_AES;
    }
    if(getenv("N2N_COMMUNITY")) {
        strncpy((char*)conf->community_name, getenv("N2N_COMMUNITY"), N2N_COMMUNITY_SIZE);
        conf->community_name[N2N_COMMUNITY_SIZE - 1] = '\0';
    }
    if(getenv("N2N_PASSWORD")) {
        conf->shared_secret = calloc(1, sizeof(n2n_private_public_key_t));
        if(conf->shared_secret)
            generate_private_key(*(conf->shared_secret), getenv("N2N_PASSWORD"));
    }

    tmp_string = calloc(1, strlen(N2N_MGMT_PASSWORD) + 1);
    if(tmp_string) {
        strncpy((char*)tmp_string, N2N_MGMT_PASSWORD, strlen(N2N_MGMT_PASSWORD) + 1);
        conf->mgmt_password_hash = pearson_hash_64((uint8_t*)tmp_string, strlen(N2N_MGMT_PASSWORD));
        free(tmp_string);
    }

    conf->sn_selection_strategy = SN_SELECTION_STRATEGY_LOAD;
    conf->metric = 0;
}

/* ************************************** */

void edge_term_conf (n2n_edge_conf_t *conf) {

    if(conf->encrypt_key) free(conf->encrypt_key);

    if(conf->network_traffic_filter_rules) {
        filter_rule_t *el = 0, *tmp = 0;
        HASH_ITER(hh, conf->network_traffic_filter_rules, el, tmp) {
            HASH_DEL(conf->network_traffic_filter_rules, el);
            free(el);
        }
    }
}

/* ************************************** */

const n2n_edge_conf_t* edge_get_conf (const n2n_edge_t *eee) {

    return(&eee->conf);
}

/* ************************************** */

int edge_conf_add_supernode (n2n_edge_conf_t *conf, const char *ip_and_port) {

    struct peer_info *sn;
    n2n_sock_t *sock;
    int skip_add;
    int rv = -1;

    sock = (n2n_sock_t*)calloc(1,sizeof(n2n_sock_t));
    rv = supernode2sock(sock, ip_and_port);

    if(rv < -2) { /* we accept resolver failure as it might resolve later */
        traceEvent(TRACE_WARNING, "invalid supernode parameter.");
        free(sock);
        return 1;
    }

    skip_add = SN_ADD;
    sn = add_sn_to_list_by_mac_or_sock(&(conf->supernodes), sock, null_mac, &skip_add);

    if(sn != NULL) {
        sn->ip_addr = calloc(1, N2N_EDGE_SN_HOST_SIZE);

        if(sn->ip_addr != NULL) {
            strncpy(sn->ip_addr, ip_and_port, N2N_EDGE_SN_HOST_SIZE - 1);
            memcpy(&(sn->sock), sock, sizeof(n2n_sock_t));
            memcpy(sn->mac_addr, null_mac, sizeof(n2n_mac_t));
            sn->purgeable = false;
        }
    }

    free(sock);

    traceEvent(TRACE_NORMAL, "adding supernode = %s", sn->ip_addr);
    conf->sn_num++;

    return 0;
}

/* ************************************** */

int quick_edge_init (char *device_name, char *community_name,
                     char *encrypt_key, char *device_mac,
                     char *local_ip_address,
                     char *supernode_ip_address_port,
                     bool *keep_on_running) {

    tuntap_dev tuntap;
    n2n_edge_t *eee;
    n2n_edge_conf_t conf;
    int rv;

    /* Setup the configuration */
    edge_init_conf_defaults(&conf);
    conf.encrypt_key = encrypt_key;
    conf.transop_id = N2N_TRANSFORM_ID_AES;
    conf.compression = N2N_COMPRESSION_ID_NONE;
    snprintf((char*)conf.community_name, sizeof(conf.community_name), "%s", community_name);
    edge_conf_add_supernode(&conf, supernode_ip_address_port);

    /* Validate configuration */
    if(edge_verify_conf(&conf) != 0)
        return(-1);

    /* Open the tuntap device */
    if(tuntap_open(&tuntap, device_name, "static",
                   local_ip_address, "255.255.255.0",
                   device_mac, DEFAULT_MTU,
                   0) < 0)
        return(-2);

    /* Init edge */
    if((eee = edge_init(&conf, &rv)) == NULL)
        goto quick_edge_init_end;

    eee->keep_running = keep_on_running;
    rv = run_edge_loop(eee);
    edge_term(eee);
    edge_term_conf(&conf);

quick_edge_init_end:
    tuntap_close(&tuntap);
    return(rv);
}

/* ************************************** */
