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


#include <errno.h>              // for errno, EAFNOSUPPORT
#include <stdbool.h>
#include <stdint.h>             // for uint8_t, uint32_t, uint16_t, uint64_t
#include <stdio.h>              // for sscanf, snprintf, fclose, fgets, fopen
#include <stdlib.h>             // for free, calloc, getenv
#include <string.h>             // for memcpy, NULL, memset, size_t, strerror
#include <sys/param.h>          // for MAX
#include <sys/time.h>           // for timeval
#include <sys/types.h>          // for ssize_t
#include <time.h>               // for time_t, time
#include "auth.h"               // for ascii_to_bin, calculate_dynamic_key
#include "config.h"             // for PACKAGE_VERSION
#include "header_encryption.h"  // for packet_header_encrypt, packet_header_...
#include "n2n.h"                // for sn_community, n2n_sn_t, peer_info
#include "n2n_regex.h"          // for re_matchp, re_compile
#include "n2n_wire.h"           // for encode_buf, encode_PEER_INFO, encode_...
#include "pearson.h"            // for pearson_hash_128, pearson_hash_32
#include "portable_endian.h"    // for be16toh, htobe16
#include "random_numbers.h"     // for n2n_rand, n2n_rand_sqr, n2n_seed, n2n...
#include "sn_selection.h"       // for sn_selection_criterion_gather_data
#include "speck.h"              // for speck_128_encrypt, speck_context_t
#include "uthash.h"             // for UT_hash_handle, HASH_ITER, HASH_DEL

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>          // for inet_addr, inet_ntoa
#include <netinet/in.h>         // for ntohl, in_addr_t, sockaddr_in, INADDR...
#include <netinet/tcp.h>        // for TCP_NODELAY
#include <sys/select.h>         // for FD_ISSET, FD_SET, select, FD_SETSIZE
#include <sys/socket.h>         // for recvfrom, shutdown, sockaddr_storage
#endif


#define HASH_FIND_COMMUNITY(head, name, out) HASH_FIND_STR(head, name, out)

int resolve_create_thread (n2n_resolve_parameter_t **param, struct peer_info *sn_list);
int resolve_check (n2n_resolve_parameter_t *param, uint8_t resolution_request, time_t now);
int resolve_cancel_thread (n2n_resolve_parameter_t *param);


static ssize_t sendto_peer (n2n_sn_t *sss,
                            const struct peer_info *peer,
                            const uint8_t *pktbuf,
                            size_t pktsize);

static uint16_t reg_lifetime (n2n_sn_t *sss);

static int update_edge (n2n_sn_t *sss,
                        const n2n_common_t* cmn,
                        const n2n_REGISTER_SUPER_t* reg,
                        struct sn_community *comm,
                        const n2n_sock_t *sender_sock,
                        const SOCKET socket_fd,
                        n2n_auth_t *answer_auth,
                        int skip_add,
                        time_t now);

static int re_register_and_purge_supernodes (n2n_sn_t *sss,
                                             struct sn_community *comm,
                                             time_t *p_last_re_reg_and_purge,
                                             time_t now,
                                             uint8_t forced);

static int purge_expired_communities (n2n_sn_t *sss,
                                      time_t* p_last_purge,
                                      time_t now);

static int sort_communities (n2n_sn_t *sss,
                             time_t* p_last_sort,
                             time_t now);

int process_mgmt (n2n_sn_t *sss,
                  const struct sockaddr *sender_sock, socklen_t sock_size,
                  char *mgmt_buf,
                  size_t mgmt_size,
                  time_t now);

static int process_udp (n2n_sn_t *sss,
                        const struct sockaddr *sender_sock, socklen_t sock_size,
                        const SOCKET socket_fd,
                        uint8_t *udp_buf,
                        size_t udp_size,
                        time_t now);


/* ************************************** */


void close_tcp_connection (n2n_sn_t *sss, n2n_tcp_connection_t *conn) {

    struct sn_community *comm, *tmp_comm;
    struct peer_info *edge, *tmp_edge;

    if(!conn)
        return;

    // find peer by file descriptor
    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        HASH_ITER(hh, comm->edges, edge, tmp_edge) {
            if(edge->socket_fd == conn->socket_fd) {
                // remove peer
                HASH_DEL(comm->edges, edge);
                free(edge);
                goto close_conn; /* break - level 2 */
            }
        }
    }

 close_conn:
    // close the connection
    shutdown(conn->socket_fd, SHUT_RDWR);
    closesocket(conn->socket_fd);
    // forget about the connection, will be deleted later
    conn->inactive = 1;
}


/* *************************************************** */


// generate shared secrets for user authentication; can be done only after
// federation name is known (-F) and community list completely read (-c)
void calculate_shared_secrets (n2n_sn_t *sss) {

    struct sn_community *comm, *tmp_comm;
    sn_user_t *user, *tmp_user;

    traceEvent(TRACE_INFO, "started shared secrets calculation for edge authentication");

    generate_private_key(sss->private_key, sss->federation->community + 1); /* skip '*' federation leading character */
    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        if(comm->is_federation) {
            continue;
        }
        HASH_ITER(hh, comm->allowed_users, user, tmp_user) {
            // calculate common shared secret (ECDH)
            generate_shared_secret(user->shared_secret, sss->private_key, user->public_key);
            // prepare for use as key
            user->shared_secret_ctx = (he_context_t*)calloc(1, sizeof(speck_context_t));
            speck_init((speck_context_t**)&user->shared_secret_ctx, user->shared_secret, 128);
        }
    }

    traceEvent(TRACE_NORMAL, "calculated shared secrets for edge authentication");
}


// calculate dynamic keys
void calculate_dynamic_keys (n2n_sn_t *sss) {

    struct sn_community *comm, *tmp_comm = NULL;

    traceEvent(TRACE_INFO, "calculating dynamic keys");
    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        // skip federation
        if(comm->is_federation) {
            continue;
        }

        // calculate dynamic keys if this is a user/pw auth'ed community
        if(comm->allowed_users) {
            calculate_dynamic_key(comm->dynamic_key,           /* destination */
                                  sss->dynamic_key_time,       /* time - same for all */
                                  (uint8_t *)comm->community,  /* community name */
                                  (uint8_t *)sss->federation->community); /* federation name */
            packet_header_change_dynamic_key(comm->dynamic_key,
                                             &(comm->header_encryption_ctx_dynamic),
                                             &(comm->header_iv_ctx_dynamic));
            traceEvent(TRACE_DEBUG, "calculated dynamic key for community '%s'", comm->community);
        }
    }
}


// send RE_REGISTER_SUPER to all edges from user/pw auth'ed communites
void send_re_register_super (n2n_sn_t *sss) {

    struct sn_community *comm, *tmp_comm = NULL;
    struct peer_info *edge, *tmp_edge = NULL;
    n2n_common_t   cmn;
    uint8_t        rereg_buf[N2N_SN_PKTBUF_SIZE];
    size_t         encx = 0;
    n2n_sock_str_t sockbuf;

    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        if(comm->is_federation) {
            continue;
        }

        // send RE_REGISTER_SUPER to edges if this is a user/pw auth community
        if(comm->allowed_users) {
            // prepare
            cmn.ttl = N2N_DEFAULT_TTL;
            cmn.pc = n2n_re_register_super;
            cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
            memcpy(cmn.community, comm->community, N2N_COMMUNITY_SIZE);

            HASH_ITER(hh, comm->edges, edge, tmp_edge) {
                // encode
                encx = 0;
                encode_common(rereg_buf, &encx, &cmn);

                // send
                traceEvent(TRACE_DEBUG, "send RE_REGISTER_SUPER to %s",
                                         sock_to_cstr(sockbuf, &(edge->sock)));

                packet_header_encrypt(rereg_buf, encx, encx,
                                      comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                      time_stamp());

                /* sent = */ sendto_peer(sss, edge, rereg_buf, encx);
             }
        }
    }
}


/** Load the list of allowed communities. Existing/previous ones will be removed,
 *  return 0 on success, -1 if file not found, -2 if no valid entries found
 */
int load_allowed_sn_community (n2n_sn_t *sss) {

    char buffer[4096], *line, *cmn_str, net_str[20], format[20];

    sn_user_t *user, *tmp_user;
    n2n_desc_t username;
    n2n_private_public_key_t public_key;
    char ascii_public_key[(N2N_PRIVATE_PUBLIC_KEY_SIZE * 8 + 5) / 6 + 1];

    dec_ip_str_t ip_str = {'\0'};
    uint8_t bitlen;
    in_addr_t net;
    uint32_t mask;
    FILE *fd = fopen(sss->community_file, "r");

    struct sn_community *comm, *tmp_comm, *last_added_comm = NULL;
    struct peer_info *edge, *tmp_edge;
    node_supernode_association_t *assoc, *tmp_assoc;
    n2n_tcp_connection_t *conn;
    time_t any_time = 0;

    uint32_t num_communities = 0;

    struct sn_community_regular_expression *re, *tmp_re;
    uint32_t num_regex = 0;
    int has_net;

    if(fd == NULL) {
        traceEvent(TRACE_WARNING, "File %s not found", sss->community_file);
        return -1;
    }

    // reset data structures ------------------------------

    // send RE_REGISTER_SUPER to all edges from user/pw auth communites, this is safe because
    // follow-up REGISTER_SUPER cannot be handled before this function ends
    send_re_register_super(sss);

    // remove communities (not: federation)
    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        if(comm->is_federation) {
            continue;
        }

        // remove all edges from community
        HASH_ITER(hh, comm->edges, edge, tmp_edge) {
            // remove all edge associations (with other supernodes)
            HASH_ITER(hh, comm->assoc, assoc, tmp_assoc) {
                HASH_DEL(comm->assoc, assoc);
                free(assoc);
            }

            // close TCP connections, if any (also causes reconnect)
            // and delete edge from list
            if((edge->socket_fd != sss->sock) && (edge->socket_fd >= 0)) {
                HASH_FIND_INT(sss->tcp_connections, &(edge->socket_fd), conn);
                close_tcp_connection(sss, conn); /* also deletes the edge */
            } else {
                HASH_DEL(comm->edges, edge);
                free(edge);
            }
        }

        // remove allowed users from community
        HASH_ITER(hh, comm->allowed_users, user, tmp_user) {
            free(user->shared_secret_ctx);
            HASH_DEL(comm->allowed_users, user);
            free(user);
        }

        // remove community
        HASH_DEL(sss->communities, comm);
        if(NULL != comm->header_encryption_ctx_static) {
            // remove header encryption keys
            free(comm->header_encryption_ctx_static);
            free(comm->header_iv_ctx_static);
            free(comm->header_encryption_ctx_dynamic);
            free(comm->header_iv_ctx_dynamic);
        }
        free(comm);
    }

    // remove all regular expressions for allowed communities
    HASH_ITER(hh, sss->rules, re, tmp_re) {
        HASH_DEL(sss->rules, re);
        free(re);
    }

    // prepare reading data -------------------------------

    // new key_time for all communities, requires dynamic keys to be recalculated (see further below),
    // and  edges to re-register (see above) and ...
    sss->dynamic_key_time = time(NULL);
    // ... federated supernodes to re-register
    re_register_and_purge_supernodes(sss, sss->federation, &any_time, any_time, 1 /* forced */);

    // format definition for possible user-key entries
    sprintf(format, "%c %%%ds %%%lds", N2N_USER_KEY_LINE_STARTER, N2N_DESC_SIZE - 1, sizeof(ascii_public_key)-1);

    while((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {
        int len = strlen(line);

        if((len < 2) || line[0] == '#') {
            continue;
        }

        len--;
        while(len > 0) {
            if((line[len] == '\n') || (line[len] == '\r')) {
                line[len] = '\0';
                len--;
            } else {
                break;
            }
        }
        // the loop above does not always determine correct 'len'
        len = strlen(line);

        // user-key line for edge authentication?
        if(line[0] == N2N_USER_KEY_LINE_STARTER) { /* special first character */
            if(sscanf(line, format, username, ascii_public_key) == 2) { /* correct format */
                if(last_added_comm) { /* is there a valid community to add users to */
                    user = (sn_user_t*)calloc(1, sizeof(sn_user_t));
                    if(user) {
                        // username
                        memcpy(user->name, username, sizeof(username));
                        // public key
                        ascii_to_bin(public_key, ascii_public_key);
                        memcpy(user->public_key, public_key, sizeof(public_key));
                        // common shared secret will be calculated later
                        // add to list
                        HASH_ADD(hh, last_added_comm->allowed_users, public_key, sizeof(n2n_private_public_key_t), user);
                        traceEvent(TRACE_INFO, "added user '%s' with public key '%s' to community '%s'",
                                               user->name, ascii_public_key, last_added_comm->community);
                        // enable header encryption
                        last_added_comm->header_encryption = HEADER_ENCRYPTION_ENABLED;
                        packet_header_setup_key(last_added_comm->community,
                                                &(last_added_comm->header_encryption_ctx_static),
                                                &(last_added_comm->header_encryption_ctx_dynamic),
                                                &(last_added_comm->header_iv_ctx_static),
                                                &(last_added_comm->header_iv_ctx_dynamic));
                        // dynamic key setup follows at a later point in code
                    }
                    continue;
                }
            }
        }

        // --- community name or regular expression

        // cut off any IP sub-network upfront
        cmn_str = (char*)calloc(len + 1, sizeof(char));
        has_net = (sscanf(line, "%s %s", cmn_str, net_str) == 2);

        // if it contains typical characters...
        if(NULL != strpbrk(cmn_str, ".*+?[]\\")) {
            // ...it is treated as regular expression
            re = (struct sn_community_regular_expression*)calloc(1, sizeof(struct sn_community_regular_expression));
            if(re) {
                re->rule = re_compile(cmn_str);
                HASH_ADD_PTR(sss->rules, rule, re);
                num_regex++;
                traceEvent(TRACE_INFO, "added regular expression for allowed communities '%s'", cmn_str);
                free(cmn_str);
                last_added_comm = NULL;
                continue;
            }
        }

        comm = (struct sn_community*)calloc(1,sizeof(struct sn_community));

        if(comm != NULL) {
            comm_init(comm, cmn_str);
            /* loaded from file, this community is unpurgeable */
            comm->purgeable = false;
            /* we do not know if header encryption is used in this community,
             * first packet will show. just in case, setup the key. */
            comm->header_encryption = HEADER_ENCRYPTION_UNKNOWN;
            packet_header_setup_key(comm->community,
                                    &(comm->header_encryption_ctx_static),
                                    &(comm->header_encryption_ctx_dynamic),
                                    &(comm->header_iv_ctx_static),
                                    &(comm->header_iv_ctx_dynamic));
            HASH_ADD_STR(sss->communities, community, comm);
            last_added_comm = comm;

            num_communities++;
            traceEvent(TRACE_INFO, "added allowed community '%s' [total: %u]",
                       (char*)comm->community, num_communities);

            // check for sub-network address
            if(has_net) {
                if(sscanf(net_str, "%15[^/]/%hhu", ip_str, &bitlen) != 2) {
                    traceEvent(TRACE_WARNING, "bad net/bit format '%s' for community '%c', ignoring; see comments inside community.list file",
                                           net_str, cmn_str);
                    has_net = 0;
                }
                net = inet_addr(ip_str);
                mask = bitlen2mask(bitlen);
                if((net == (in_addr_t)(-1)) || (net == INADDR_NONE) || (net == INADDR_ANY)
                         || ((ntohl(net) & ~mask) != 0)) {
                    traceEvent(TRACE_WARNING, "bad network '%s/%u' in '%s' for community '%s', ignoring",
                                           ip_str, bitlen, net_str, cmn_str);
                    has_net = 0;
                }
                if((bitlen > 30) || (bitlen == 0)) {
                    traceEvent(TRACE_WARNING, "bad prefix '%hhu' in '%s' for community '%s', ignoring",
                                           bitlen, net_str, cmn_str);
                    has_net = 0;
                }
            }
            if(has_net) {
                comm->auto_ip_net.net_addr = ntohl(net);
                comm->auto_ip_net.net_bitlen = bitlen;
                traceEvent(TRACE_INFO, "assigned sub-network %s/%u to community '%s'",
                                       inet_ntoa(*(struct in_addr *) &net),
                           comm->auto_ip_net.net_bitlen,
                           comm->community);
            } else {
                assign_one_ip_subnet(sss, comm);
            }
        }
        free(cmn_str);
    }

    fclose(fd);

    if((num_regex + num_communities) == 0) {
        traceEvent(TRACE_WARNING, "file %s does not contain any valid community names or regular expressions", sss->community_file);
        return -2;
    }

    traceEvent(TRACE_NORMAL, "loaded %u fixed-name communities from %s",
                     num_communities, sss->community_file);

    traceEvent(TRACE_NORMAL, "loaded %u regular expressions for community name matching from %s",
                     num_regex, sss->community_file);

    // calculate allowed user's shared secrets (shared with federation)
    calculate_shared_secrets(sss);

    // calculcate communties' dynamic keys
    calculate_dynamic_keys(sss);

    // no new communities will be allowed
    sss->lock_communities = 1;

    return 0;
}


/* *************************************************** */


/** Send a datagram to a file descriptor socket.
 *
 *    @return -1 on error otherwise number of bytes sent
 */
static ssize_t sendto_fd (n2n_sn_t *sss,
                          SOCKET socket_fd,
                          const struct sockaddr *socket,
                          const uint8_t *pktbuf,
                          size_t pktsize) {

    ssize_t sent = 0;
    n2n_tcp_connection_t *conn;

    sent = sendto(socket_fd, (void *)pktbuf, pktsize, 0 /* flags */,
                  socket, sizeof(struct sockaddr_in));

    if((sent <= 0) && (errno)) {
        char * c = strerror(errno);
        traceEvent(TRACE_ERROR, "sendto failed (%d) %s", errno, c);
#ifdef _WIN32
        traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
        // if the erroneous connection is tcp, i.e. not the regular sock...
        if((socket_fd >= 0) && (socket_fd != sss->sock)) {
            // ...forget about the corresponding peer and the connection
            HASH_FIND_INT(sss->tcp_connections, &socket_fd, conn);
            close_tcp_connection(sss, conn);
            return -1;
        }
    } else {
            traceEvent(TRACE_DEBUG, "sendto sent=%d to ", (signed int)sent);
    }

    return sent;
}


/** Send a datagram to a network order socket of type struct sockaddr.
 *
 *    @return -1 on error otherwise number of bytes sent
 */
static ssize_t sendto_sock(n2n_sn_t *sss,
                           SOCKET socket_fd,
                           const struct sockaddr *socket,
                           const uint8_t *pktbuf,
                           size_t pktsize) {

    ssize_t sent = 0;
    int value = 0;

    // if the connection is tcp, i.e. not the regular sock...
    if((socket_fd >= 0) && (socket_fd != sss->sock)) {

        setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
        value = 1;
#ifdef LINUX
        setsockopt(socket_fd, IPPROTO_TCP, TCP_CORK, &value, sizeof(value));
#endif

        // prepend packet length...
        uint16_t pktsize16 = htobe16(pktsize);
        sent = sendto_fd(sss, socket_fd, socket, (uint8_t*)&pktsize16, sizeof(pktsize16));

        if(sent <= 0)
            return -1;
        // ...before sending the actual data
    }

    sent = sendto_fd(sss, socket_fd, socket, pktbuf, pktsize);

    // if the connection is tcp, i.e. not the regular sock...
    if((socket_fd >= 0) && (socket_fd != sss->sock)) {
        value = 1; /* value should still be set to 1 */
        setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&value, sizeof(value));
#ifdef LINUX
        value = 0;
        setsockopt(socket_fd, IPPROTO_TCP, TCP_CORK, &value, sizeof(value));
#endif
    }

    return sent;
}


/** Send a datagram to a peer whose destination socket is embodied in its sock field of type n2n_sock_t.
 *  It calls sendto_sock to do the final send.
 *
 *    @return -1 on error otherwise number of bytes sent
 */
static ssize_t sendto_peer (n2n_sn_t *sss,
                            const struct peer_info *peer,
                            const uint8_t *pktbuf,
                            size_t pktsize) {

    n2n_sock_str_t sockbuf;

    if(AF_INET == peer->sock.family) {

        // network order socket
        struct sockaddr_in socket;
        fill_sockaddr((struct sockaddr *)&socket, sizeof(socket), &(peer->sock));

        traceEvent(TRACE_DEBUG, "sent %lu bytes to [%s]",
                   pktsize,
                   sock_to_cstr(sockbuf, &(peer->sock)));

        return sendto_sock(sss,
                           (peer->socket_fd >= 0) ? peer->socket_fd : sss->sock,
                           (const struct sockaddr*)&socket, pktbuf, pktsize);
    } else {
        /* AF_INET6 not implemented */
        errno = EAFNOSUPPORT;
        return -1;
    }
}


/** Try and broadcast a message to all edges in the community.
 *
 *    This will send the exact same datagram to zero or more edges registered to
 *    the supernode.
 */
static int try_broadcast (n2n_sn_t * sss,
                          const struct sn_community *comm,
                          const n2n_common_t * cmn,
                          const n2n_mac_t srcMac,
                          uint8_t from_supernode,
                          const uint8_t * pktbuf,
                          size_t pktsize,
                          time_t now) {

    struct peer_info        *scan, *tmp;
    macstr_t                mac_buf;
    n2n_sock_str_t          sockbuf;

    traceEvent(TRACE_DEBUG, "try_broadcast");

    /* We have to make sure that a broadcast reaches the other supernodes and edges
     * connected to them. try_broadcast needs a from_supernode parameter: if set,
     * do forward to edges of community only. If unset, forward to all locally known
     * nodes of community AND all supernodes associated with the community */

    if (!from_supernode) {
        HASH_ITER(hh, sss->federation->edges, scan, tmp) {
            int data_sent_len;

            // only forward to active supernodes
            if(scan->last_seen + LAST_SEEN_SN_INACTIVE > now) {

                data_sent_len = sendto_peer(sss, scan, pktbuf, pktsize);

                if(data_sent_len != pktsize) {
                    ++(sss->stats.errors);
                    traceEvent(TRACE_WARNING, "multicast %lu to supernode [%s] %s failed %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr),
                               strerror(errno));
                 } else {
                     ++(sss->stats.broadcast);
                     traceEvent(TRACE_DEBUG, "multicast %lu to supernode [%s] %s",
                                pktsize,
                                sock_to_cstr(sockbuf, &(scan->sock)),
                                macaddr_str(mac_buf, scan->mac_addr));
                 }
            }
        }
    }

    if(comm) {
        HASH_ITER(hh, comm->edges, scan, tmp) {
            if(memcmp(srcMac, scan->mac_addr, sizeof(n2n_mac_t)) != 0) {
                /* REVISIT: exclude if the destination socket is where the packet came from. */
                int data_sent_len;

                data_sent_len = sendto_peer(sss, scan, pktbuf, pktsize);

                if(data_sent_len != pktsize) {
                    ++(sss->stats.errors);
                    traceEvent(TRACE_WARNING, "multicast %lu to [%s] %s failed %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr),
                               strerror(errno));
                } else {
                    ++(sss->stats.broadcast);
                    traceEvent(TRACE_DEBUG, "multicast %lu to [%s] %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr));
                }
            }
        }
    }

    return 0;
}


static int try_forward (n2n_sn_t * sss,
                        const struct sn_community *comm,
                        const n2n_common_t * cmn,
                        const n2n_mac_t dstMac,
                        uint8_t from_supernode,
                        const uint8_t * pktbuf,
                        size_t pktsize,
                        time_t now) {

    struct peer_info *             scan;
    node_supernode_association_t   *assoc;
    macstr_t                       mac_buf;
    n2n_sock_str_t                 sockbuf;

    HASH_FIND_PEER(comm->edges, dstMac, scan);

    if(NULL != scan) {
        int data_sent_len;
        data_sent_len = sendto_peer(sss, scan, pktbuf, pktsize);

        if(data_sent_len == pktsize) {
            ++(sss->stats.fwd);
            traceEvent(TRACE_DEBUG, "unicast %lu to [%s] %s",
                       pktsize,
                       sock_to_cstr(sockbuf, &(scan->sock)),
                       macaddr_str(mac_buf, scan->mac_addr));
        } else {
            ++(sss->stats.errors);
            traceEvent(TRACE_ERROR, "unicast %lu to [%s] %s FAILED (%d: %s)",
                       pktsize,
                       sock_to_cstr(sockbuf, &(scan->sock)),
                       macaddr_str(mac_buf, scan->mac_addr),
                       errno, strerror(errno));
            return -1;
        }
    } else {
        if(!from_supernode) {
            // check if target edge is associated with a certain supernode
            HASH_FIND(hh, comm->assoc, dstMac, sizeof(n2n_mac_t), assoc);
            if(assoc) {
                traceEvent(TRACE_DEBUG, "found mac address associated with a known supernode, forwarding packet to that supernode");
                sendto_sock(sss, sss->sock,
                            &(assoc->sock),
                            pktbuf, pktsize);
            } else {
                // forwarding packet to all federated supernodes
                traceEvent(TRACE_DEBUG, "unknown mac address, broadcasting packet to all federated supernodes");
                try_broadcast(sss, NULL, cmn, sss->mac_addr, from_supernode, pktbuf, pktsize, now);
            }
        } else {
            traceEvent(TRACE_DEBUG, "unknown mac address in packet from a supernode, dropping the packet");
            /* Not a known MAC so drop. */
            return -2;
        }
    }

    return 0;
}


/** Initialise some fields of the community structure **/
int comm_init (struct sn_community *comm, char *cmn) {

    strncpy((char*)comm->community, cmn, N2N_COMMUNITY_SIZE);
    comm->community[N2N_COMMUNITY_SIZE - 1] = '\0';
    comm->is_federation = IS_NO_FEDERATION;

    return 0; /* OK */
}


/** Initialise the supernode structure */
int sn_init_defaults (n2n_sn_t *sss) {

    char *tmp_string;

#ifdef _WIN32
    initWin32();
#endif

    pearson_hash_init();

    memset(sss, 0, sizeof(n2n_sn_t));

    strncpy(sss->version, PACKAGE_VERSION, sizeof(n2n_version_t));
    sss->version[sizeof(n2n_version_t) - 1] = '\0';
    sss->daemon = 1; /* By defult run as a daemon. */
    sss->bind_address = INADDR_ANY; /* any address */
    sss->lport = N2N_SN_LPORT_DEFAULT;
    sss->mport = N2N_SN_MGMT_PORT;
    sss->sock = -1;
    sss->mgmt_sock = -1;
    sss->min_auto_ip_net.net_addr = inet_addr(N2N_SN_MIN_AUTO_IP_NET_DEFAULT);
    sss->min_auto_ip_net.net_addr = ntohl(sss->min_auto_ip_net.net_addr);
    sss->min_auto_ip_net.net_bitlen = N2N_SN_AUTO_IP_NET_BIT_DEFAULT;
    sss->max_auto_ip_net.net_addr = inet_addr(N2N_SN_MAX_AUTO_IP_NET_DEFAULT);
    sss->max_auto_ip_net.net_addr = ntohl(sss->max_auto_ip_net.net_addr);
    sss->max_auto_ip_net.net_bitlen = N2N_SN_AUTO_IP_NET_BIT_DEFAULT;

    sss->federation = (struct sn_community *)calloc(1, sizeof(struct sn_community));
    /* Initialize the federation */
    if(sss->federation) {
        if(getenv("N2N_FEDERATION"))
            snprintf(sss->federation->community, N2N_COMMUNITY_SIZE - 1 ,"*%s", getenv("N2N_FEDERATION"));
        else
            strncpy(sss->federation->community, (char*)FEDERATION_NAME, N2N_COMMUNITY_SIZE);
        sss->federation->community[N2N_COMMUNITY_SIZE - 1] = '\0';
        /* enable the flag for federation */
        sss->federation->is_federation = IS_FEDERATION;
        sss->federation->purgeable = false;
        /* header encryption enabled by default */
        sss->federation->header_encryption = HEADER_ENCRYPTION_ENABLED;
        /*setup the encryption key */
        packet_header_setup_key(sss->federation->community,
                                &(sss->federation->header_encryption_ctx_static),
                                &(sss->federation->header_encryption_ctx_dynamic),
                                &(sss->federation->header_iv_ctx_static),
                                &(sss->federation->header_iv_ctx_dynamic));
        sss->federation->edges = NULL;
    }

    n2n_srand(n2n_seed());

    /* Random auth token */
    sss->auth.scheme = n2n_auth_simple_id;
    memrnd(sss->auth.token, N2N_AUTH_ID_TOKEN_SIZE);
    sss->auth.token_size = N2N_AUTH_ID_TOKEN_SIZE;

    /* Random MAC address */
    memrnd(sss->mac_addr, N2N_MAC_SIZE);
    sss->mac_addr[0] &= ~0x01; /* Clear multicast bit */
    sss->mac_addr[0] |= 0x02;    /* Set locally-assigned bit */

    tmp_string = calloc(1, strlen(N2N_MGMT_PASSWORD) + 1);
    if(tmp_string) {
        strncpy((char*)tmp_string, N2N_MGMT_PASSWORD, strlen(N2N_MGMT_PASSWORD) + 1);
        sss->mgmt_password_hash = pearson_hash_64((uint8_t*)tmp_string, strlen(N2N_MGMT_PASSWORD));
        free(tmp_string);
    }

    return 0; /* OK */
}


/** Initialise the supernode */
void sn_init (n2n_sn_t *sss) {

    if(resolve_create_thread(&(sss->resolve_parameter), sss->federation->edges) == 0) {
         traceEvent(TRACE_NORMAL, "successfully created resolver thread");
    }
}


/** Deinitialise the supernode structure and deallocate any memory owned by
 *    it. */
void sn_term (n2n_sn_t *sss) {

    struct sn_community *community, *tmp;
    struct sn_community_regular_expression *re, *tmp_re;
    n2n_tcp_connection_t *conn, *tmp_conn;
    node_supernode_association_t *assoc, *tmp_assoc;

    resolve_cancel_thread(sss->resolve_parameter);

    if(sss->sock >= 0) {
        closesocket(sss->sock);
    }
    sss->sock = -1;

    HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
        shutdown(conn->socket_fd, SHUT_RDWR);
        closesocket(conn->socket_fd);
        HASH_DEL(sss->tcp_connections, conn);
        free(conn);
    }

    if(sss->tcp_sock >= 0) {
        shutdown(sss->tcp_sock, SHUT_RDWR);
        closesocket(sss->tcp_sock);
    }
    sss->tcp_sock = -1;

    if(sss->mgmt_sock >= 0) {
        closesocket(sss->mgmt_sock);
    }
    sss->mgmt_sock = -1;

    HASH_ITER(hh, sss->communities, community, tmp) {
        clear_peer_list(&community->edges);
        if(NULL != community->header_encryption_ctx_static) {
            free(community->header_encryption_ctx_static);
            free(community->header_encryption_ctx_dynamic);
        }
        // remove all associations
        HASH_ITER(hh, community->assoc, assoc, tmp_assoc) {
            HASH_DEL(community->assoc, assoc);
            free(assoc);
        }
        HASH_DEL(sss->communities, community);
        free(community);
    }

    HASH_ITER(hh, sss->rules, re, tmp_re) {
        HASH_DEL(sss->rules, re);
        if (NULL != re->rule) {
            free(re->rule);
        }
        free(re);
    }

    if(sss->community_file)
        free(sss->community_file);
#ifdef _WIN32
    destroyWin32();
#endif
}

void update_node_supernode_association (struct sn_community *comm,
                                        n2n_mac_t *edgeMac, const struct sockaddr *sender_sock, socklen_t sock_size,
                                        time_t now) {

    node_supernode_association_t *assoc;

    HASH_FIND(hh, comm->assoc, edgeMac, sizeof(n2n_mac_t), assoc);
    if(!assoc) {
        // create a new association
        assoc = (node_supernode_association_t*)calloc(1, sizeof(node_supernode_association_t));
        if(assoc) {
            memcpy(&(assoc->mac), edgeMac, sizeof(n2n_mac_t));
            memcpy(&(assoc->sock), sender_sock, sock_size);
            assoc->sock_len = sock_size;
            assoc->last_seen = now;
            HASH_ADD(hh, comm->assoc, mac, sizeof(n2n_mac_t), assoc);
        } else {
            // already there, update socket and time only
            memcpy(&(assoc->sock), sender_sock, sock_size);
            assoc->sock_len = sock_size;
            assoc->last_seen = now;
        }
    }
}


/** Determine the appropriate lifetime for new registrations.
 *
 *    If the supernode has been put into a pre-shutdown phase then this lifetime
 *    should not allow registrations to continue beyond the shutdown point.
 */
static uint16_t reg_lifetime (n2n_sn_t *sss) {

    /* NOTE: UDP firewalls usually have a 30 seconds timeout */
    return 15;
}


/** Verifies authentication tokens from known edges.
 *
 *  It is called by update_edge and during UNREGISTER_SUPER handling
 *  to verify the stored auth token.
 */
static int auth_edge (const n2n_auth_t *present, const n2n_auth_t *presented, n2n_auth_t *answer, struct sn_community *community) {

    sn_user_t *user = NULL;

    if(present->scheme == n2n_auth_none) {
        // n2n_auth_none scheme (set at supernode if cli option '-M')
        // if required, zero_token answer (not for NAK)
        if(answer)
            memset(answer, 0, sizeof(n2n_auth_t));
        // 0 == (always) successful
        return 0;
    }

    if((present->scheme == n2n_auth_simple_id) && (presented->scheme == n2n_auth_simple_id)) {
        // n2n_auth_simple_id scheme: if required, zero_token answer (not for NAK)
        if(answer)
            memset(answer, 0, sizeof(n2n_auth_t));

        // 0 = success (tokens are equal)
        return (memcmp(present, presented, sizeof(n2n_auth_t)));
    }

    if((present->scheme == n2n_auth_user_password) && (presented->scheme == n2n_auth_user_password)) {
        // check if submitted public key is in list of allowed users
        HASH_FIND(hh, community->allowed_users, &presented->token, sizeof(n2n_private_public_key_t), user);
        if(user) {
            if(answer) {
                memcpy(answer, presented, sizeof(n2n_auth_t));

                // return a double-encrypted challenge (just encrypt again) in the (first half of) public key field so edge can verify
                memcpy(answer->token, answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
                speck_128_encrypt(answer->token, (speck_context_t*)user->shared_secret_ctx);

                // decrypt the challenge using user's shared secret
                speck_128_decrypt(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)user->shared_secret_ctx);
                // xor-in the community dynamic key
                memxor(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, community->dynamic_key, N2N_AUTH_CHALLENGE_SIZE);
                // xor-in the user's shared secret
                memxor(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, user->shared_secret, N2N_AUTH_CHALLENGE_SIZE);
                // encrypt it using user's shared secret
                speck_128_encrypt(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)user->shared_secret_ctx);
                // user in list? success! (we will see if edge can handle the key for further com)
            }
            return 0;
        }
    }

    // if not successful earlier: failure
    return -1;
}


// provides the current / a new local auth token
// REVISIT: behavior should depend on some local auth scheme setting (to be implemented)
static int get_local_auth (n2n_sn_t *sss, n2n_auth_t *auth) {

    // n2n_auth_simple_id scheme
    memcpy(auth, &(sss->auth), sizeof(n2n_auth_t));

    return 0;
}


// handles an incoming (remote) auth token from a so far unknown edge,
// takes action as required by auth scheme, and
// could provide an answer auth token for use in REGISTER_SUPER_ACK
static int handle_remote_auth (n2n_sn_t *sss, const n2n_auth_t *remote_auth,
                                              n2n_auth_t *answer_auth,
                                              struct sn_community *community) {

    sn_user_t *user = NULL;

    if((NULL == community->allowed_users) != (remote_auth->scheme != n2n_auth_user_password)) {
        // received token's scheme does not match expected scheme
        return -1;
    }

    switch(remote_auth->scheme) {
        // we do not handle n2n_auth_none because the edge always edge always uses either id or user/password
        // auth_none is sn-internal only (skipping MAC/IP address spoofing protection)
        case n2n_auth_none:
        case n2n_auth_simple_id:
            // zero_token answer
            memset(answer_auth, 0, sizeof(n2n_auth_t));
            return 0;
        case n2n_auth_user_password:
            // check if submitted public key is in list of allowed users
            HASH_FIND(hh, community->allowed_users, &remote_auth->token, sizeof(n2n_private_public_key_t), user);
            if(user) {
                memcpy(answer_auth, remote_auth, sizeof(n2n_auth_t));

                // return a double-encrypted challenge (just encrypt again) in the (first half of) public key field so edge can verify
                memcpy(answer_auth->token, answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
                speck_128_encrypt(answer_auth->token, (speck_context_t*)user->shared_secret_ctx);

                // wrap dynamic key for transmission
                // decrypt the challenge using user's shared secret
                speck_128_decrypt(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)user->shared_secret_ctx);
                // xor-in the community dynamic key
                memxor(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, community->dynamic_key, N2N_AUTH_CHALLENGE_SIZE);
                // xor-in the user's shared secret
                memxor(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, user->shared_secret, N2N_AUTH_CHALLENGE_SIZE);
                // encrypt it using user's shared secret
                speck_128_encrypt(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)user->shared_secret_ctx);
                return 0;
            }
            break;
        default:
            break;
    }

    // if not successful earlier: failure
    return -1;
}


/** Update the edge table with the details of the edge which contacted the
 *    supernode. */
static int update_edge (n2n_sn_t *sss,
                        const n2n_common_t* cmn,
                        const n2n_REGISTER_SUPER_t* reg,
                        struct sn_community *comm,
                        const n2n_sock_t *sender_sock,
                        const SOCKET socket_fd,
                        n2n_auth_t *answer_auth,
                        int skip_add,
                        time_t now) {

    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    struct peer_info *scan, *iter, *tmp;
    int ret;

    traceEvent(TRACE_DEBUG, "update_edge for %s [%s]",
               macaddr_str(mac_buf, reg->edgeMac),
               sock_to_cstr(sockbuf, sender_sock));

    HASH_FIND_PEER(comm->edges, reg->edgeMac, scan);

    // if unknown, make sure it is also not known by IP address
    if(NULL == scan) {
        HASH_ITER(hh,comm->edges,iter,tmp) {
            if(iter->dev_addr.net_addr == reg->dev_addr.net_addr) {
                scan = iter;
                HASH_DEL(comm->edges, scan);
                memcpy(scan->mac_addr, reg->edgeMac, sizeof(n2n_mac_t));
                HASH_ADD_PEER(comm->edges, scan);
                break;
            }
        }
    }

    if(NULL == scan) {
    /* Not known */
        if(handle_remote_auth(sss, &(reg->auth), answer_auth, comm) == 0) {
            if(skip_add == SN_ADD) {
                scan = (struct peer_info *) calloc(1, sizeof(struct peer_info)); /* deallocated in purge_expired_nodes */
                scan->purgeable = true;
                memcpy(&(scan->mac_addr), reg->edgeMac, sizeof(n2n_mac_t));
                scan->dev_addr.net_addr = reg->dev_addr.net_addr;
                scan->dev_addr.net_bitlen = reg->dev_addr.net_bitlen;
                memcpy((char*)scan->dev_desc, reg->dev_desc, N2N_DESC_SIZE);
                memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
                scan->socket_fd = socket_fd;
                scan->last_cookie = reg->cookie;
                scan->last_valid_time_stamp = initial_time_stamp();
                // eventually, store edge's preferred local socket from REGISTER_SUPER
                if(cmn->flags & N2N_FLAGS_SOCKET)
                    memcpy(&scan->preferred_sock, &reg->sock, sizeof(n2n_sock_t));
                else
                    scan->preferred_sock.family = AF_INVALID;

                // store the submitted auth token
                memcpy(&(scan->auth), &(reg->auth), sizeof(n2n_auth_t));
                // manually set to type 'auth_none' if cli option disables MAC/IP address spoofing protection
                // for id based auth communities. This will be obsolete when handling public keys only (v4.0?)
                if((reg->auth.scheme == n2n_auth_simple_id) && (sss->override_spoofing_protection))
                    scan->auth.scheme = n2n_auth_none;

                HASH_ADD_PEER(comm->edges, scan);

                traceEvent(TRACE_INFO, "created edge  %s ==> %s",
                           macaddr_str(mac_buf, reg->edgeMac),
                           sock_to_cstr(sockbuf, sender_sock));
            }
            ret = update_edge_new_sn;
        } else {
            traceEvent(TRACE_INFO, "authentication failed");
            ret = update_edge_auth_fail;
        }
    } else {
        /* Known */
        if(auth_edge(&(scan->auth), &(reg->auth), answer_auth, comm) == 0) {
            if(!sock_equal(sender_sock, &(scan->sock))) {
                memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
                scan->socket_fd = socket_fd;
                scan->last_cookie = reg->cookie;
                // eventually, update edge's preferred local socket from REGISTER_SUPER
                if(cmn->flags & N2N_FLAGS_SOCKET)
                    memcpy(&scan->preferred_sock, &reg->sock, sizeof(n2n_sock_t));
                else
                    scan->preferred_sock.family = AF_INVALID;

                traceEvent(TRACE_INFO, "updated edge  %s ==> %s",
                           macaddr_str(mac_buf, reg->edgeMac),
                           sock_to_cstr(sockbuf, sender_sock));
                ret = update_edge_sock_change;
            } else {
                scan->last_cookie = reg->cookie;

                traceEvent(TRACE_DEBUG, "edge unchanged %s ==> %s",
                           macaddr_str(mac_buf, reg->edgeMac),
                           sock_to_cstr(sockbuf, sender_sock));

                ret = update_edge_no_change;
            }
        } else {
            traceEvent(TRACE_INFO, "authentication failed");
            ret = update_edge_auth_fail;
        }
    }

    if((scan != NULL) && (ret != update_edge_auth_fail)) {
        scan->last_seen = now;
    }

    return ret;
}


/** checks if a certain ip address is still available, i.e. not used by any other edge of a given community */
static int ip_addr_available (struct sn_community *comm, n2n_ip_subnet_t *ip_addr) {

    int success = 1;
    struct peer_info *peer, *tmp_peer;

    // prerequisite: list of peers is sorted according to peer's tap ip address
    HASH_ITER(hh, comm->edges, peer, tmp_peer) {
        if(peer->dev_addr.net_addr  > ip_addr->net_addr) {
            break;
        }
        if(peer->dev_addr.net_addr == ip_addr->net_addr) {
            success = 0;
            break;
        }
    }

    return success;
}


static signed int peer_tap_ip_sort (struct peer_info *a, struct peer_info *b) {

    uint32_t a_host_id = a->dev_addr.net_addr & (~bitlen2mask(a->dev_addr.net_bitlen));
    uint32_t b_host_id = b->dev_addr.net_addr & (~bitlen2mask(b->dev_addr.net_bitlen));

    return ((signed int)a_host_id - (signed int)b_host_id);
}


/** The IP address assigned to the edge by the auto ip address function of sn. */
static int assign_one_ip_addr (struct sn_community *comm, n2n_desc_t dev_desc, n2n_ip_subnet_t *ip_addr) {

    uint32_t tmp, success, net_id, mask, max_host, host_id = 1;
    dec_ip_bit_str_t ip_bit_str = {'\0'};

    mask = bitlen2mask(comm->auto_ip_net.net_bitlen);
    net_id = comm->auto_ip_net.net_addr & mask;
    max_host = ~mask;

    // sorting is a prerequisite for more efficient availabilitiy check
    HASH_SORT(comm->edges, peer_tap_ip_sort);

    // first proposal derived from hash of mac address
    tmp = pearson_hash_32(dev_desc, sizeof(n2n_desc_t)) & max_host;
    if(tmp == 0)        tmp++; /* avoid 0 host */
    if(tmp == max_host) tmp--; /* avoid broadcast address */
    tmp |= net_id;

    // candidate
    ip_addr->net_bitlen = comm->auto_ip_net.net_bitlen;

    // check for availability starting from proposal, then downwards, ...
    for(host_id = tmp; host_id > net_id; host_id--) {
        ip_addr->net_addr = host_id;
        success = ip_addr_available(comm, ip_addr);
        if(success) {
            break;
        }
    }
    // ... then upwards
    if(!success) {
        for(host_id = tmp + 1; host_id < (net_id + max_host); host_id++) {
            ip_addr->net_addr = host_id;
            success = ip_addr_available(comm, ip_addr);
            if(success) {
                break;
            }
        }
    }

    if(success) {
        traceEvent(TRACE_INFO, "assign IP %s to tap adapter of edge", ip_subnet_to_str(ip_bit_str, ip_addr));
        return 0;
    } else {
        traceEvent(TRACE_WARNING, "no assignable IP to edge tap adapter");
        return -1;
    }
}


/** checks if a certain sub-network is still available, i.e. does not cut any other community's sub-network */
int subnet_available (n2n_sn_t *sss,
                      struct sn_community *comm,
                      uint32_t net_id,
                      uint32_t mask) {

    struct sn_community *cmn, *tmpCmn;
    int success = 1;

    HASH_ITER(hh, sss->communities, cmn, tmpCmn) {
        if(cmn == comm) {
            continue;
        }
        if(cmn->is_federation == IS_FEDERATION) {
            continue;
        }
        if((net_id <= (cmn->auto_ip_net.net_addr + ~bitlen2mask(cmn->auto_ip_net.net_bitlen)))
           &&(net_id + ~mask >= cmn->auto_ip_net.net_addr)) {
            success = 0;
            break;
        }
    }

    return success;
}


/** The IP address range (subnet) assigned to the community by the auto ip address function of sn. */
int assign_one_ip_subnet (n2n_sn_t *sss,
                          struct sn_community *comm) {

    uint32_t net_id, net_id_i, mask, net_increment;
    uint32_t no_subnets;
    uint8_t success;
    in_addr_t net;

    mask = bitlen2mask(sss->min_auto_ip_net.net_bitlen);
    // number of possible sub-networks
    no_subnets   = (sss->max_auto_ip_net.net_addr - sss->min_auto_ip_net.net_addr);
    no_subnets >>= (32 - sss->min_auto_ip_net.net_bitlen);
    no_subnets  += 1;

    // proposal for sub-network to choose
    net_id    = pearson_hash_32((const uint8_t *)comm->community, N2N_COMMUNITY_SIZE) % no_subnets;
    net_id    = sss->min_auto_ip_net.net_addr + (net_id << (32 - sss->min_auto_ip_net.net_bitlen));

    // check for availability starting from net_id, then downwards, ...
    net_increment = (~mask+1);
    for(net_id_i = net_id; net_id_i >= sss->min_auto_ip_net.net_addr; net_id_i -= net_increment) {
        success = subnet_available(sss, comm, net_id_i, mask);
        if(success) {
            break;
        }
    }
    // ... then upwards
    if(!success) {
        for(net_id_i = net_id + net_increment; net_id_i <= sss->max_auto_ip_net.net_addr; net_id_i += net_increment) {
            success = subnet_available(sss, comm, net_id_i, mask);
            if(success) {
                break;
            }
        }
    }

    if(success) {
        comm->auto_ip_net.net_addr = net_id_i;
        comm->auto_ip_net.net_bitlen = sss->min_auto_ip_net.net_bitlen;
        net = htonl(comm->auto_ip_net.net_addr);
        traceEvent(TRACE_INFO, "assigned sub-network %s/%u to community '%s'",
                   inet_ntoa(*(struct in_addr *) &net),
                   comm->auto_ip_net.net_bitlen,
                   comm->community);
        return 0;
    } else {
        comm->auto_ip_net.net_addr = 0;
        comm->auto_ip_net.net_bitlen = 0;
        traceEvent(TRACE_WARNING, "no assignable sub-network left for community '%s'",
                   comm->community);
        return -1;
    }
}


/***
 *
 * For a given packet, find the apporopriate internal last valid time stamp for lookup
 * and verify it (and also update, if applicable).
 */
static int find_edge_time_stamp_and_verify (struct peer_info * edges,
                                            peer_info_t *sn, n2n_mac_t mac,
                                            uint64_t stamp, int allow_jitter) {

    uint64_t *previous_stamp = NULL;

    if(sn) {
        previous_stamp = &(sn->last_valid_time_stamp);
    } else {
        struct peer_info *edge;
        HASH_FIND_PEER(edges, mac, edge);

        if(edge) {
            // time_stamp_verify_and_update allows the pointer a previous stamp to be NULL
            // if it is a (so far) unknown edge
            previous_stamp = &(edge->last_valid_time_stamp);
        }
    }

    // failure --> 0;    success --> 1
    return time_stamp_verify_and_update(stamp, previous_stamp, allow_jitter);
}


static int re_register_and_purge_supernodes (n2n_sn_t *sss, struct sn_community *comm, time_t *p_last_re_reg_and_purge, time_t now, uint8_t forced) {

    time_t time;
    struct peer_info *peer, *tmp;

    if(!forced) {
        if((now - (*p_last_re_reg_and_purge)) < RE_REG_AND_PURGE_FREQUENCY) {
            return 0;
        }

        // purge long-time-not-seen supernodes
        if (comm) {
            purge_expired_nodes(&(comm->edges), sss->sock, &sss->tcp_connections, p_last_re_reg_and_purge,
                                RE_REG_AND_PURGE_FREQUENCY, LAST_SEEN_SN_INACTIVE);
        }
    }

    if(comm != NULL) {
        HASH_ITER(hh,comm->edges,peer,tmp) {

            time = now - peer->last_seen;

            if(!forced) {
                if(time <= LAST_SEEN_SN_ACTIVE) {
                    continue;
                }
            }

            /* re-register (send REGISTER_SUPER) */
            uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};
            size_t idx;
            /* ssize_t sent; */
            n2n_common_t cmn;
            n2n_REGISTER_SUPER_t reg;
            n2n_sock_str_t sockbuf;

            memset(&cmn, 0, sizeof(cmn));
            memset(&reg, 0, sizeof(reg));

            cmn.ttl = N2N_DEFAULT_TTL;
            cmn.pc = n2n_register_super;
            cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
            memcpy(cmn.community, comm->community, N2N_COMMUNITY_SIZE);

            reg.cookie = n2n_rand();
            peer->last_cookie = reg.cookie;

            reg.dev_addr.net_addr = ntohl(peer->dev_addr.net_addr);
            reg.dev_addr.net_bitlen = mask2bitlen(ntohl(peer->dev_addr.net_bitlen));
            get_local_auth(sss, &(reg.auth));

            reg.key_time = sss->dynamic_key_time;

            idx = 0;
            encode_mac(reg.edgeMac, &idx, sss->mac_addr);

            idx = 0;
            encode_REGISTER_SUPER(pktbuf, &idx, &cmn, &reg);

            traceEvent(TRACE_DEBUG, "send REGISTER_SUPER to %s",
                                     sock_to_cstr(sockbuf, &(peer->sock)));

            packet_header_encrypt(pktbuf, idx, idx,
                                  comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                  time_stamp());

            /* sent = */ sendto_peer(sss, peer, pktbuf, idx);
        }
    }

    return 0; /* OK */
}


static int purge_expired_communities (n2n_sn_t *sss,
                                      time_t* p_last_purge,
                                      time_t now) {

    struct sn_community *comm, *tmp_comm;
    node_supernode_association_t *assoc, *tmp_assoc;
    size_t num_reg = 0;
    size_t num_assoc = 0;

    if((now - (*p_last_purge)) < PURGE_REGISTRATION_FREQUENCY) {
        return 0;
    }

    traceEvent(TRACE_DEBUG, "purging old communities and edges");

    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        // federation is taken care of in re_register_and_purge_supernodes()
        if(comm->is_federation == IS_FEDERATION)
            continue;

        // purge the community's local peers
        num_reg += purge_peer_list(&comm->edges, sss->sock, &sss->tcp_connections, now - REGISTRATION_TIMEOUT);

        // purge the community's associated peers (connected to other supernodes)
        HASH_ITER(hh, comm->assoc, assoc, tmp_assoc) {
            if(comm->assoc->last_seen < (now - 3 * REGISTRATION_TIMEOUT)) {
                HASH_DEL(comm->assoc, assoc);
                free(assoc);
                num_assoc++;
            }
        }

        if((comm->edges == NULL) && (comm->purgeable == true)) {
            traceEvent(TRACE_INFO, "purging idle community %s", comm->community);
            if(NULL != comm->header_encryption_ctx_static) {
                /* this should not happen as 'purgeable' and thus only communities w/o encrypted header here */
                free(comm->header_encryption_ctx_static);
                free(comm->header_iv_ctx_static);
                free(comm->header_encryption_ctx_dynamic);
                free(comm->header_iv_ctx_dynamic);
            }
            // remove all associations
            HASH_ITER(hh, comm->assoc, assoc, tmp_assoc) {
                HASH_DEL(comm->assoc, assoc);
                free(assoc);
            }
            HASH_DEL(sss->communities, comm);
            free(comm);
        }
    }
    (*p_last_purge) = now;

    traceEvent(TRACE_DEBUG, "purge_expired_communities removed %ld locally registered edges and %ld remotely associated edges",
                            num_reg, num_assoc);

    return 0;
}


static int number_enc_packets_sort (struct sn_community *a, struct sn_community *b) {

    // comparison function for sorting communities in descending order of their
    // number_enc_packets-fields
    return (b->number_enc_packets - a->number_enc_packets);
}


static int sort_communities (n2n_sn_t *sss,
                             time_t* p_last_sort,
                             time_t now) {

    struct sn_community *comm, *tmp;

    if((now - (*p_last_sort)) < SORT_COMMUNITIES_INTERVAL) {
        return 0;
    }

    // this routine gets periodically called as defined in SORT_COMMUNITIES_INTERVAL
    // it sorts the communities in descending order of their number_enc_packets-fields...
    HASH_SORT(sss->communities, number_enc_packets_sort);

    // ... and afterward resets the number_enc__packets-fields to zero
    // (other models could reset it to half of their value to respect history)
    HASH_ITER(hh, sss->communities, comm, tmp) {
        comm->number_enc_packets = 0;
    }

    (*p_last_sort) = now;

    return 0;
}


/** Examine a datagram and determine what to do with it.
 *
 */
static int process_udp (n2n_sn_t * sss,
                        const struct sockaddr *sender_sock, socklen_t sock_size,
                        const SOCKET socket_fd,
                        uint8_t * udp_buf,
                        size_t udp_size,
                        time_t now) {

    n2n_common_t        cmn; /* common fields in the packet header */
    size_t              rem;
    size_t              idx;
    size_t              msg_type;
    uint8_t             from_supernode;
    peer_info_t         *sn = NULL;
    n2n_sock_t          sender;
    n2n_sock_t          *orig_sender;
    macstr_t            mac_buf;
    macstr_t            mac_buf2;
    n2n_sock_str_t      sockbuf;
    uint8_t             hash_buf[16] = {0}; /* always size of 16 (max) despite the actual value of N2N_REG_SUP_HASH_CHECK_LEN (<= 16) */

    struct sn_community *comm, *tmp;
    uint32_t            header_enc = 0; /* 1 == encrypted by static key, 2 == encrypted by dynamic key */
    uint64_t            stamp;
    int                 skip_add;
    time_t              any_time = 0;

    memset(&sender, 0, sizeof(n2n_sock_t));
    fill_n2nsock(&sender, sender_sock);
    orig_sender = &sender;

    traceEvent(TRACE_DEBUG, "processing incoming UDP packet [len: %lu][sender: %s]",
               udp_size, sock_to_cstr(sockbuf, &sender));

    /* check if header is unencrypted. the following check is around 99.99962 percent reliable.
     * it heavily relies on the structure of packet's common part
     * changes to wire.c:encode/decode_common need to go together with this code */
    if(udp_size < 24) {
        traceEvent(TRACE_DEBUG, "dropped a packet too short to be valid");
        return -1;
    }
    if((udp_buf[23] == (uint8_t)0x00) // null terminated community name
       && (udp_buf[00] == N2N_PKT_VERSION) // correct packet version
       && ((be16toh(*(uint16_t*)&(udp_buf[02])) & N2N_FLAGS_TYPE_MASK) <= MSG_TYPE_MAX_TYPE) // message type
       && ( be16toh(*(uint16_t*)&(udp_buf[02])) < N2N_FLAGS_OPTIONS) // flags
       ) {
        /* most probably unencrypted */
        /* make sure, no downgrading happens here and no unencrypted packets can be
         * injected in a community which definitely deals with encrypted headers */
        HASH_FIND_COMMUNITY(sss->communities, (char *)&udp_buf[04], comm);
        if(comm) {
            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                traceEvent(TRACE_DEBUG, "dropped a packet with unencrypted header "
                           "addressed to community '%s' which uses encrypted headers",
                           comm->community);
                return -1;
            }
            if(comm->header_encryption == HEADER_ENCRYPTION_UNKNOWN) {
                traceEvent(TRACE_INFO, "locked community '%s' to "
                           "unencrypted headers", comm->community);
                /* set 'no encryption' in case it is not set yet */
                comm->header_encryption = HEADER_ENCRYPTION_NONE;
                comm->header_encryption_ctx_static = NULL;
                comm->header_encryption_ctx_dynamic = NULL;
            }
        }
    } else {
        /* most probably encrypted */
        /* cycle through the known communities (as keys) to eventually decrypt */
        HASH_ITER(hh, sss->communities, comm, tmp) {
            /* skip the definitely unencrypted communities */
            if(comm->header_encryption == HEADER_ENCRYPTION_NONE) {
                continue;
            }

            // match with static (1) or dynamic (2) ctx?
            // check dynamic first as it is identical to static in normal header encryption mode
            if(packet_header_decrypt(udp_buf, udp_size,
                                     comm->community,
                                     comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                     &stamp)) {
                    header_enc = 2;
            }
            if(!header_enc) {
                pearson_hash_128(hash_buf, udp_buf, max(0, (int)udp_size - (int)N2N_REG_SUP_HASH_CHECK_LEN));
                header_enc = packet_header_decrypt(udp_buf, max(0, (int)udp_size - (int)N2N_REG_SUP_HASH_CHECK_LEN), comm->community,
                                                   comm->header_encryption_ctx_static, comm->header_iv_ctx_static, &stamp);
            }

            if(header_enc) {
                // time stamp verification follows in the packet specific section as it requires to determine the
                // sender from the hash list by its MAC, this all depends on packet type and packet structure
                // (MAC is not always in the same place)

                if(comm->header_encryption == HEADER_ENCRYPTION_UNKNOWN) {
                    traceEvent(TRACE_INFO, "locked community '%s' to "
                               "encrypted headers", comm->community);
                    /* set 'encrypted' in case it is not set yet */
                    comm->header_encryption = HEADER_ENCRYPTION_ENABLED;
                }
                // count the number of encrypted packets for sorting the communities from time to time
                // for the HASH_ITER a few lines above gets faster for the more busy communities
                (comm->number_enc_packets)++;
                // no need to test further communities
                break;
            }
        }
        if(!header_enc) {
            // no matching key/community
            traceEvent(TRACE_DEBUG, "dropped a packet with seemingly encrypted header "
                       "for which no matching community which uses encrypted headers was found");
            return -1;
        }
    }

    /* Use decode_common() to determine the kind of packet then process it:
     *
     * REGISTER_SUPER adds an edge and generate a return REGISTER_SUPER_ACK
     *
     * REGISTER, REGISTER_ACK and PACKET messages are forwarded to their
     * destination edge. If the destination is not known then PACKETs are
     * broadcast.
     */

    rem = udp_size; /* Counts down bytes of packet to protect against buffer overruns. */
    idx = 0; /* marches through packet header as parts are decoded. */

    if(decode_common(&cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_ERROR, "failed to decode common section");
        return -1; /* failed to decode packet */
    }

    msg_type = cmn.pc; /* packet code */

    // special case for user/pw auth
    // community's auth scheme and message type need to match the used key (dynamic)
    if(comm) {
        if((comm->allowed_users)
        && (msg_type != MSG_TYPE_REGISTER_SUPER)
        && (msg_type != MSG_TYPE_REGISTER_SUPER_ACK)
        && (msg_type != MSG_TYPE_REGISTER_SUPER_NAK)) {
            if(header_enc != 2) {
                traceEvent(TRACE_WARNING, "dropped packet encrypted with static key where expecting dynamic key");
                return -1;
            }
        }
    }

    from_supernode = cmn.flags & N2N_FLAGS_FROM_SUPERNODE;
    if(from_supernode) {
        skip_add = SN_ADD_SKIP;
        sn = add_sn_to_list_by_mac_or_sock (&(sss->federation->edges), &sender, null_mac, &skip_add);
        // only REGISTER_SUPER allowed from unknown supernodes
        if((!sn) && (msg_type != MSG_TYPE_REGISTER_SUPER)) {
            traceEvent(TRACE_DEBUG, "dropped incoming data from unknown supernode");
            return -1;
        }
    }

    if(cmn.ttl < 1) {
        traceEvent(TRACE_WARNING, "expired TTL");
        return 0; /* Don't process further */
    }

    --(cmn.ttl); /* The value copied into all forwarded packets. */

    switch(msg_type) {
        case MSG_TYPE_PACKET: {
            /* PACKET from one edge to another edge via supernode. */

            /* pkt will be modified in place and recoded to an output of potentially
             * different size due to addition of the socket.*/
            n2n_PACKET_t  pkt;
            n2n_common_t  cmn2;
            uint8_t       encbuf[N2N_SN_PKTBUF_SIZE];
            size_t        encx = 0;
            int           unicast; /* non-zero if unicast */
            uint8_t *     rec_buf; /* either udp_buf or encbuf */

            if(!comm) {
                traceEvent(TRACE_DEBUG, "PACKET with unknown community %s", cmn.community);
                return -1;
            }

            sss->stats.last_fwd = now;
            decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx);

            // already checked for valid comm
            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_edge_time_stamp_and_verify(comm->edges, sn, pkt.srcMac, stamp, TIME_STAMP_ALLOW_JITTER)) {
                    traceEvent(TRACE_DEBUG, "dropped PACKET due to time stamp error");
                    return -1;
                }
            }

            unicast = (0 == is_multi_broadcast(pkt.dstMac));

            traceEvent(TRACE_DEBUG, "RX PACKET (%s) %s -> %s %s",
                       (unicast ? "unicast" : "multicast"),
                       macaddr_str(mac_buf, pkt.srcMac),
                       macaddr_str(mac_buf2, pkt.dstMac),
                       (from_supernode ? "from sn" : "local"));

            if(!from_supernode) {
                memcpy(&cmn2, &cmn, sizeof(n2n_common_t));

                /* We are going to add socket even if it was not there before */
                cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

                memcpy(&pkt.sock, &sender, sizeof(sender));

                rec_buf = encbuf;
                /* Re-encode the header. */
                encode_PACKET(encbuf, &encx, &cmn2, &pkt);

                uint16_t oldEncx = encx;

                /* Copy the original payload unchanged */
                encode_buf(encbuf, &encx, (udp_buf + idx), (udp_size - idx));

                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    // in case of user-password auth, also encrypt the iv of payload assuming ChaCha20 and SPECK having the same iv size
                    packet_header_encrypt(rec_buf, oldEncx + (NULL != comm->allowed_users) * min(encx - oldEncx, N2N_SPECK_IVEC_SIZE), encx,
                                          comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                          time_stamp());
                }
            } else {
                /* Already from a supernode. Nothing to modify, just pass to
                 * destination. */

                traceEvent(TRACE_DEBUG, "Rx PACKET fwd unmodified");

                rec_buf = udp_buf;
                encx = udp_size;

                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    // in case of user-password auth, also encrypt the iv of payload assuming ChaCha20 and SPECK having the same iv size
                    packet_header_encrypt(rec_buf, idx + (NULL != comm->allowed_users) * min(encx - idx, N2N_SPECK_IVEC_SIZE), encx,
                                          comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                          time_stamp());
                }
            }

            /* Common section to forward the final product. */
            if(unicast) {
                try_forward(sss, comm, &cmn, pkt.dstMac, from_supernode, rec_buf, encx, now);
            } else {
                try_broadcast(sss, comm, &cmn, pkt.srcMac, from_supernode, rec_buf, encx, now);
            }
            break;
        }

        case MSG_TYPE_REGISTER: {
            /* Forwarding a REGISTER from one edge to the next */

            n2n_REGISTER_t  reg;
            n2n_common_t    cmn2;
            uint8_t         encbuf[N2N_SN_PKTBUF_SIZE];
            size_t          encx = 0;
            int             unicast; /* non-zero if unicast */
            uint8_t *       rec_buf; /* either udp_buf or encbuf */

            if(!comm) {
                traceEvent(TRACE_DEBUG, "REGISTER from unknown community %s", cmn.community);
                return -1;
            }

            sss->stats.last_fwd = now;
            decode_REGISTER(&reg, &cmn, udp_buf, &rem, &idx);

            // already checked for valid comm
            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_edge_time_stamp_and_verify(comm->edges, sn, reg.srcMac, stamp, TIME_STAMP_NO_JITTER)) {
                    traceEvent(TRACE_DEBUG, "dropped REGISTER due to time stamp error");
                    return -1;
                }
            }

            unicast = (0 == is_multi_broadcast(reg.dstMac));

            if(unicast) {
                traceEvent(TRACE_DEBUG, "Rx REGISTER %s -> %s %s",
                           macaddr_str(mac_buf, reg.srcMac),
                           macaddr_str(mac_buf2, reg.dstMac),
                           ((cmn.flags & N2N_FLAGS_FROM_SUPERNODE) ? "from sn" : "local"));

                if(0 == (cmn.flags & N2N_FLAGS_FROM_SUPERNODE)) {
                    memcpy(&cmn2, &cmn, sizeof(n2n_common_t));

                    /* We are going to add socket even if it was not there before */
                    cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

                    memcpy(&reg.sock, &sender, sizeof(sender));

                    /* Re-encode the header. */
                    encode_REGISTER(encbuf, &encx, &cmn2, &reg);

                    rec_buf = encbuf;
                } else {
                    /* Already from a supernode. Nothing to modify, just pass to
                     * destination. */

                    rec_buf = udp_buf;
                    encx = udp_size;
                }

                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    packet_header_encrypt(rec_buf, encx, encx,
                                          comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                          time_stamp());
                }
                try_forward(sss, comm, &cmn, reg.dstMac, from_supernode, rec_buf, encx, now); /* unicast only */
            } else {
                traceEvent(TRACE_ERROR, "Rx REGISTER with multicast destination");
            }
            break;
        }

        case MSG_TYPE_REGISTER_ACK: {
            traceEvent(TRACE_DEBUG, "Rx REGISTER_ACK (not implemented) should not be via supernode");
            break;
        }

        case MSG_TYPE_REGISTER_SUPER: {
            n2n_REGISTER_SUPER_t                   reg;
            n2n_REGISTER_SUPER_ACK_t               ack;
            n2n_REGISTER_SUPER_NAK_t               nak;
            n2n_common_t                           cmn2;
            uint8_t                                ackbuf[N2N_SN_PKTBUF_SIZE];
            uint8_t                                payload_buf[REG_SUPER_ACK_PAYLOAD_SPACE];
            n2n_REGISTER_SUPER_ACK_payload_t       *payload;
            size_t                                 encx = 0;
            struct sn_community_regular_expression *re, *tmp_re;
            struct peer_info                       *peer, *tmp_peer, *p;
            int8_t                                 allowed_match = -1;
            uint8_t                                match = 0;
            int                                    match_length = 0;
            n2n_ip_subnet_t                        ipaddr;
            int                                    num = 0;
            int                                    skip;
            int                                    ret_value;
            sn_user_t                              *user = NULL;

            memset(&ack, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));
            memset(&nak, 0, sizeof(n2n_REGISTER_SUPER_NAK_t));

            /* Edge/supernode requesting registration with us.    */
            sss->stats.last_reg_super=now;
            ++(sss->stats.reg_super);
            decode_REGISTER_SUPER(&reg, &cmn, udp_buf, &rem, &idx);

            if(comm) {
                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_edge_time_stamp_and_verify(comm->edges, sn, reg.edgeMac, stamp, TIME_STAMP_NO_JITTER)) {
                        traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER due to time stamp error");
                        return -1;
                    }
                }
            }

            /*
                Before we move any further, we need to check if the requested
                community is allowed by the supernode. In case it is not we do
                not report any message back to the edge to hide the supernode
                existance (better from the security standpoint)
            */

            if(!comm && sss->lock_communities) {
                HASH_ITER(hh, sss->rules, re, tmp_re) {
                    allowed_match = re_matchp(re->rule, (const char *)cmn.community, &match_length);

                    if((allowed_match != -1)
                       && (match_length == strlen((const char *)cmn.community)) // --- only full matches allowed (remove, if also partial matches wanted)
                       && (allowed_match == 0)) { // --- only full matches allowed (remove, if also partial matches wanted)
                        match = 1;
                        break;
                    }
                }
                if(match != 1) {
                    traceEvent(TRACE_INFO, "discarded registration with unallowed community '%s'",
                               (char*)cmn.community);
                    return -1;
                }
            }

            if(!comm && (!sss->lock_communities || (match == 1))) {
                comm = (struct sn_community*)calloc(1, sizeof(struct sn_community));

                if(comm) {
                    comm_init(comm, (char *)cmn.community);
                    /* new communities introduced by REGISTERs could not have had encrypted header... */
                    comm->header_encryption = HEADER_ENCRYPTION_NONE;
                    comm->header_encryption_ctx_static = NULL;
                    comm->header_encryption_ctx_dynamic = NULL;
                    /* ... and also are purgeable during periodic purge */
                    comm->purgeable = true;
                    comm->number_enc_packets = 0;
                    HASH_ADD_STR(sss->communities, community, comm);

                    traceEvent(TRACE_INFO, "new community: %s", comm->community);
                    assign_one_ip_subnet(sss, comm);
                }
            }

            if(!comm) {
                traceEvent(TRACE_INFO, "discarded registration with unallowed community '%s'",
                                       (char*)cmn.community);
                return -1;
            }

            // hash check (user/pw auth only)
            if(comm->allowed_users) {
                // check if submitted public key is in list of allowed users
                HASH_FIND(hh, comm->allowed_users, &reg.auth.token, sizeof(n2n_private_public_key_t), user);
                if(user) {
                    speck_128_encrypt(hash_buf, (speck_context_t*)user->shared_secret_ctx);
                    if(memcmp(hash_buf, udp_buf + udp_size - N2N_REG_SUP_HASH_CHECK_LEN /* length has already been checked */, N2N_REG_SUP_HASH_CHECK_LEN)) {
                        traceEvent(TRACE_INFO, "Rx REGISTER_SUPER with wrong hash");
                        return -1;
                    }
                } else {
                    traceEvent(TRACE_INFO, "Rx REGISTER_SUPER from unknown user");
                    // continue and let auth check do the rest (otherwise, no NAK is sent)
               }
            }

            if(!memcmp(reg.edgeMac, sss->mac_addr, sizeof(n2n_mac_t))) {
                traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER from self, ignoring");
                return -1;
            }

            cmn2.ttl = N2N_DEFAULT_TTL;
            cmn2.pc = n2n_register_super_ack;
            cmn2.flags = N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;
            memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));

            ack.cookie = reg.cookie;
            memcpy(ack.srcMac, sss->mac_addr, sizeof(n2n_mac_t));

            if(comm->is_federation != IS_FEDERATION) { /* alternatively, do not send zero tap ip address in federation REGISTER_SUPER */
                if((reg.dev_addr.net_addr == 0) || (reg.dev_addr.net_addr == 0xFFFFFFFF) || (reg.dev_addr.net_bitlen == 0) ||
                   ((reg.dev_addr.net_addr & 0xFFFF0000) == 0xA9FE0000 /* 169.254.0.0 */)) {
                    memset(&ipaddr, 0, sizeof(n2n_ip_subnet_t));
                    assign_one_ip_addr(comm, reg.dev_desc, &ipaddr);
                    ack.dev_addr.net_addr = ipaddr.net_addr;
                    ack.dev_addr.net_bitlen = ipaddr.net_bitlen;
                }
            }

            ack.lifetime = reg_lifetime(sss);

            memcpy(&ack.sock, &sender, sizeof(sender));

            /* Add sender's data to federation (or update it) */
            if(comm->is_federation == IS_FEDERATION) {
                skip_add = SN_ADD;
                p = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), &(ack.sock), reg.edgeMac, &skip_add);
                p->last_seen = now;
                // communication with other supernodes happens via standard udp port
                p->socket_fd = sss->sock;
            }

            /* Skip random numbers of supernodes before payload assembling, calculating an appropriate random_number.
             * That way, all supernodes have a chance to be propagated with REGISTER_SUPER_ACK. */
            skip = HASH_COUNT(sss->federation->edges) - (int)(REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE / REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE);
            skip = (skip < 0) ? 0 : n2n_rand_sqr(skip);

            /* Assembling supernode list for REGISTER_SUPER_ACK payload */
            payload = (n2n_REGISTER_SUPER_ACK_payload_t*)payload_buf;
            HASH_ITER(hh, sss->federation->edges, peer, tmp_peer) {
                if(skip) {
                    skip--;
                    continue;
                }
                if(peer->sock.family == (uint8_t)AF_INVALID)
                    continue; /* do not add unresolved supernodes to payload */
                if(memcmp(&(peer->sock), &(ack.sock), sizeof(n2n_sock_t)) == 0) continue; /* a supernode doesn't add itself to the payload */
                if((now - peer->last_seen) >= LAST_SEEN_SN_NEW) continue;  /* skip long-time-not-seen supernodes.
                                                                            * We need to allow for a little extra time because supernodes sometimes exceed
                                                                            * their SN_ACTIVE time before they get re-registred to. */
                if(((++num)*REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE) > REG_SUPER_ACK_PAYLOAD_SPACE) break; /* no more space available in REGISTER_SUPER_ACK payload */

                // bugfix for https://github.com/ntop/n2n/issues/1029
                // REVISIT: best to be removed with 4.0 (replace with encode_sock)
                idx = 0;
                encode_sock_payload(payload->sock, &idx, &(peer->sock));

                memcpy(payload->mac, peer->mac_addr, sizeof(n2n_mac_t));
                // shift to next payload entry
                payload++;
            }
            ack.num_sn = num;

            traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER for %s [%s]",
                       macaddr_str(mac_buf, reg.edgeMac),
                       sock_to_cstr(sockbuf, &(ack.sock)));

            // check authentication
            ret_value = update_edge_no_change;
            if(comm->is_federation != IS_FEDERATION) { /* REVISIT: auth among supernodes is not implemented yet */
                if(cmn.flags & N2N_FLAGS_FROM_SUPERNODE) {
                    ret_value = update_edge(sss, &cmn, &reg, comm, &(ack.sock), socket_fd, &(ack.auth), SN_ADD_SKIP, now);
                } else {
                    // do not add in case of null mac (edge asking for ip address)
                    ret_value = update_edge(sss, &cmn, &reg, comm, &(ack.sock), socket_fd, &(ack.auth), is_null_mac(reg.edgeMac) ? SN_ADD_SKIP : SN_ADD, now);
                }
            }

            if(ret_value == update_edge_auth_fail) {
                // send REGISTER_SUPER_NAK
                cmn2.pc = n2n_register_super_nak;
                nak.cookie = reg.cookie;
                memcpy(nak.srcMac, reg.edgeMac, sizeof(n2n_mac_t));

                encode_REGISTER_SUPER_NAK(ackbuf, &encx, &cmn2, &nak);

                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    packet_header_encrypt(ackbuf, encx, encx,
                                          comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                          time_stamp());
                    // if user-password-auth
                    if(comm->allowed_users) {
                        encode_buf(ackbuf, &encx, hash_buf /* no matter what content */, N2N_REG_SUP_HASH_CHECK_LEN);
                    }
                }
                sendto_sock(sss, socket_fd, sender_sock, ackbuf, encx);

                traceEvent(TRACE_DEBUG, "Tx REGISTER_SUPER_NAK for %s",
                           macaddr_str(mac_buf, reg.edgeMac));
            } else {
                // if this is not already from a supernode ...
                // and not from federation, ...
                if((!(cmn.flags & N2N_FLAGS_FROM_SUPERNODE)) || (!(cmn.flags & N2N_FLAGS_SOCKET))) {
                    // ... forward to all other supernodes (note try_broadcast()'s behavior with
                    //     NULL comm and from_supernode parameter)
                    // exception: do not forward auto ip draw
                    if(!is_null_mac(reg.edgeMac)) {
                        memcpy(&reg.sock, &sender, sizeof(sender));

                        cmn2.pc = n2n_register_super;
                        encode_REGISTER_SUPER(ackbuf, &encx, &cmn2, &reg);

                        if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                            packet_header_encrypt(ackbuf, encx, encx,
                                                  comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                                  time_stamp());
                           // if user-password-auth
                           if(comm->allowed_users) {
                               // append an encrypted packet hash
                               pearson_hash_128(hash_buf, ackbuf, encx);
                               // same 'user' as above
                               speck_128_encrypt(hash_buf, (speck_context_t*)user->shared_secret_ctx);
                               encode_buf(ackbuf, &encx, hash_buf, N2N_REG_SUP_HASH_CHECK_LEN);
                            }
                        }

                        try_broadcast(sss, NULL, &cmn, reg.edgeMac, from_supernode, ackbuf, encx, now);
                    }

                    // dynamic key time handling if appropriate
                    ack.key_time = 0;
                    if(comm->is_federation == IS_FEDERATION) {
                        if(reg.key_time > sss->dynamic_key_time) {
                            traceEvent(TRACE_DEBUG, "setting new key time");
                            // have all edges re_register (using old dynamic key)
                            send_re_register_super(sss);
                            // set new key time
                            sss->dynamic_key_time = reg.key_time;
                            // calculate new dynamic keys for all communities
                            calculate_dynamic_keys(sss);
                            // force re-register with all supernodes
                            re_register_and_purge_supernodes(sss, sss->federation, &any_time, now, 1 /* forced */);
                        }
                        ack.key_time = sss->dynamic_key_time;
                    }

                    // send REGISTER_SUPER_ACK
                    encx = 0;
                    cmn2.pc = n2n_register_super_ack;

                    encode_REGISTER_SUPER_ACK(ackbuf, &encx, &cmn2, &ack, payload_buf);

                    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                        packet_header_encrypt(ackbuf, encx, encx,
                                              comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                              time_stamp());
                       // if user-password-auth
                       if(comm->allowed_users) {
                           // append an encrypted packet hash
                           pearson_hash_128(hash_buf, ackbuf, encx);
                           // same 'user' as above
                           speck_128_encrypt(hash_buf, (speck_context_t*)user->shared_secret_ctx);
                           encode_buf(ackbuf, &encx, hash_buf, N2N_REG_SUP_HASH_CHECK_LEN);
                        }
                    }

                    sendto_sock(sss, socket_fd, sender_sock, ackbuf, encx);

                    traceEvent(TRACE_DEBUG, "Tx REGISTER_SUPER_ACK for %s [%s]",
                               macaddr_str(mac_buf, reg.edgeMac),
                               sock_to_cstr(sockbuf, &(ack.sock)));
                } else {
                    // this is an edge with valid authentication registering with another supernode, so ...
                    // 1- ... associate it with that other supernode
                    update_node_supernode_association(comm, &(reg.edgeMac), sender_sock, sock_size, now);
                    // 2- ... we can delete it from regular list if present (can happen)
                    HASH_FIND_PEER(comm->edges, reg.edgeMac, peer);
                    if(peer != NULL) {
                        if((peer->socket_fd != sss->sock) && (peer->socket_fd >= 0)) {
                            n2n_tcp_connection_t *conn;
                            HASH_FIND_INT(sss->tcp_connections, &(peer->socket_fd), conn);
                            close_tcp_connection(sss, conn); /* also deletes the peer */
                        } else {
                            HASH_DEL(comm->edges, peer);
                            free(peer);
                        }
                    }
                }
            }

            break;
        }

        case MSG_TYPE_UNREGISTER_SUPER: {
            n2n_UNREGISTER_SUPER_t unreg;
            struct peer_info       *peer;
            int                    auth;


            memset(&unreg, 0, sizeof(n2n_UNREGISTER_SUPER_t));

            if(!comm) {
                traceEvent(TRACE_DEBUG, "dropped UNREGISTER_SUPER with unknown community %s", cmn.community);
                return -1;
            }

            if((from_supernode == 1) || (comm->is_federation == IS_FEDERATION)) {
                traceEvent(TRACE_DEBUG, "dropped UNREGISTER_SUPER: should not come from a supernode or federation.");
                return -1;
            }

            decode_UNREGISTER_SUPER(&unreg, &cmn, udp_buf, &rem, &idx);

            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_edge_time_stamp_and_verify(comm->edges, sn, unreg.srcMac, stamp, TIME_STAMP_NO_JITTER)) {
                    traceEvent(TRACE_DEBUG, "dropped UNREGISTER_SUPER due to time stamp error");
                    return -1;
                }
            }

            traceEvent(TRACE_DEBUG, "Rx UNREGISTER_SUPER from %s",
                       macaddr_str(mac_buf, unreg.srcMac));

            HASH_FIND_PEER(comm->edges, unreg.srcMac, peer);
            if(peer != NULL) {
                if((auth = auth_edge(&(peer->auth), &unreg.auth, NULL, comm)) == 0) {
                    if((peer->socket_fd != sss->sock) && (peer->socket_fd >= 0)) {
                        n2n_tcp_connection_t *conn;
                        HASH_FIND_INT(sss->tcp_connections, &(peer->socket_fd), conn);
                        close_tcp_connection(sss, conn); /* also deletes the peer */
                    } else {
                        HASH_DEL(comm->edges, peer);
                        free(peer);
                    }
                }
            }
            break;
        }

        case MSG_TYPE_REGISTER_SUPER_ACK: {
            n2n_REGISTER_SUPER_ACK_t         ack;
            struct peer_info                 *scan, *tmp;
            n2n_sock_str_t                   sockbuf1;
            n2n_sock_str_t                   sockbuf2;
            macstr_t                         mac_buf1;
            int                              i;
            uint8_t                          dec_tmpbuf[REG_SUPER_ACK_PAYLOAD_SPACE];
            n2n_REGISTER_SUPER_ACK_payload_t *payload;
            n2n_sock_t                       payload_sock;

            memset(&ack, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));

            if(!comm) {
                traceEvent(TRACE_DEBUG, "REGISTER_SUPER_ACK with unknown community %s", cmn.community);
                return -1;
            }

            if((from_supernode == 0) || (comm->is_federation == IS_NO_FEDERATION)) {
                traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER_ACK, should not come from an edge or regular community");
                return -1;
            }

            decode_REGISTER_SUPER_ACK(&ack, &cmn, udp_buf, &rem, &idx, dec_tmpbuf);
            orig_sender = &(ack.sock);

            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_edge_time_stamp_and_verify(comm->edges, sn, ack.srcMac, stamp, TIME_STAMP_NO_JITTER)) {
                    traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER_ACK due to time stamp error");
                    return -1;
                }
            }

            traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK from MAC %s [%s] (external %s)",
                       macaddr_str(mac_buf1, ack.srcMac),
                       sock_to_cstr(sockbuf1, &sender),
                       sock_to_cstr(sockbuf2, orig_sender));

            skip_add = SN_ADD_SKIP;
            scan = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), &sender, ack.srcMac, &skip_add);
            if(scan != NULL) {
                scan->last_seen = now;
            } else {
                traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER_ACK due to an unknown supernode");
                break;
            }

            if(ack.cookie == scan->last_cookie) {

                payload = (n2n_REGISTER_SUPER_ACK_payload_t *)dec_tmpbuf;
                for(i = 0; i < ack.num_sn; i++) {
                    skip_add = SN_ADD;

                    // bugfix for https://github.com/ntop/n2n/issues/1029
                    // REVISIT: best to be removed with 4.0
                    idx = 0;
                    rem = sizeof(payload->sock);
                    decode_sock_payload(&payload_sock, payload->sock, &rem, &idx);

                    tmp = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), &(payload_sock), payload->mac, &skip_add);
                    // other supernodes communicate via standard udp socket
                    tmp->socket_fd = sss->sock;

                    if(skip_add == SN_ADD_ADDED) {
                        tmp->last_seen = now - LAST_SEEN_SN_NEW;
                    }

                    // shift to next payload entry
                    payload++;
                }

                if(ack.key_time > sss->dynamic_key_time) {
                    traceEvent(TRACE_DEBUG, "setting new key time");
                    // have all edges re_register (using old dynamic key)
                    send_re_register_super(sss);
                    // set new key time
                    sss->dynamic_key_time = ack.key_time;
                    // calculate new dynamic keys for all communities
                    calculate_dynamic_keys(sss);
                    // force re-register with all supernodes
                    re_register_and_purge_supernodes(sss, sss->federation, &any_time, now, 1 /* forced */);
               }

            } else {
                traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK with wrong or old cookie");
            }
            break;
        }

        case MSG_TYPE_REGISTER_SUPER_NAK: {
            n2n_REGISTER_SUPER_NAK_t  nak;
            uint8_t                   nakbuf[N2N_SN_PKTBUF_SIZE];
            size_t                    encx = 0;
            struct peer_info          *peer;
            n2n_sock_str_t            sockbuf;
            macstr_t                  mac_buf;

            memset(&nak, 0, sizeof(n2n_REGISTER_SUPER_NAK_t));

            if(!comm) {
                traceEvent(TRACE_DEBUG, "REGISTER_SUPER_NAK with unknown community %s", cmn.community);
                return -1;
            }

            decode_REGISTER_SUPER_NAK(&nak, &cmn, udp_buf, &rem, &idx);

            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_edge_time_stamp_and_verify(comm->edges, sn, nak.srcMac, stamp, TIME_STAMP_NO_JITTER)) {
                    traceEvent(TRACE_DEBUG, "process_udp dropped REGISTER_SUPER_NAK due to time stamp error");
                    return -1;
                }
            }

            traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_NAK from %s [%s]",
                       macaddr_str(mac_buf, nak.srcMac),
                       sock_to_cstr(sockbuf, &sender));

            HASH_FIND_PEER(comm->edges, nak.srcMac, peer);
            if(comm->is_federation == IS_NO_FEDERATION) {
                if(peer != NULL) {
                    // this is a NAK for one of the edges conencted to this supernode, forward,
                    // i.e. re-assemble (memcpy from udpbuf to nakbuf could be sufficient as well)

                    // use incoming cmn (with already decreased TTL)
                    // NAK (cookie, srcMac, auth) remains unchanged

                    encode_REGISTER_SUPER_NAK(nakbuf, &encx, &cmn, &nak);

                    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                        packet_header_encrypt(nakbuf, encx, encx,
                                              comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                              time_stamp());
                        // if user-password-auth
                        if(comm->allowed_users) {
                            encode_buf(nakbuf, &encx, hash_buf /* no matter what content */, N2N_REG_SUP_HASH_CHECK_LEN);
                        }
                    }

                    sendto_peer(sss, peer, nakbuf, encx);

                    if((peer->socket_fd != sss->sock) && (peer->socket_fd >= 0)) {
                        n2n_tcp_connection_t *conn;
                        HASH_FIND_INT(sss->tcp_connections, &(peer->socket_fd), conn);
                        close_tcp_connection(sss, conn); /* also deletes the peer */
                    } else {
                        HASH_DEL(comm->edges, peer);
                        free(peer);
                    }
                }
            }
            break;
        }

        case MSG_TYPE_QUERY_PEER: {
            n2n_QUERY_PEER_t                       query;
            uint8_t                                encbuf[N2N_SN_PKTBUF_SIZE];
            size_t                                 encx = 0;
            n2n_common_t                           cmn2;
            n2n_PEER_INFO_t                        pi;
            struct sn_community_regular_expression *re, *tmp_re;
            int8_t                                 allowed_match = -1;
            uint8_t                                match = 0;
            int                                    match_length = 0;

            if(!comm && sss->lock_communities) {
                HASH_ITER(hh, sss->rules, re, tmp_re) {
                    allowed_match = re_matchp(re->rule, (const char *)cmn.community, &match_length);

                    if((allowed_match != -1)
                       && (match_length == strlen((const char *)cmn.community)) // --- only full matches allowed (remove, if also partial matches wanted)
                       && (allowed_match == 0)) {                               // --- only full matches allowed (remove, if also partial matches wanted)
                        match = 1;
                        break;
                    }
                }
                if(match != 1) {
                    traceEvent(TRACE_DEBUG, "QUERY_PEER from unknown community %s", cmn.community);
                    return -1;
                }
            }

            if(!comm && sss->lock_communities && (match == 0)) {
                traceEvent(TRACE_DEBUG, "QUERY_PEER from not allowed community %s", cmn.community);
                return -1;
            }

            decode_QUERY_PEER( &query, &cmn, udp_buf, &rem, &idx );

            // to answer a PING, it is sufficient if the provided communtiy would be a valid one, there does not
            // neccessarily need to be a comm entry present, e.g. because there locally are no edges of the
            // community connected (several supernodes in a federation setup)
            if(comm) {
                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_edge_time_stamp_and_verify(comm->edges, sn, query.srcMac, stamp, TIME_STAMP_ALLOW_JITTER)) {
                        traceEvent(TRACE_DEBUG, "dropped QUERY_PEER due to time stamp error");
                        return -1;
                    }
                }
            }

            if(is_null_mac(query.targetMac)) {
                traceEvent(TRACE_DEBUG, "Rx PING from %s",
                           macaddr_str(mac_buf, query.srcMac));

                cmn2.ttl = N2N_DEFAULT_TTL;
                cmn2.pc = n2n_peer_info;
                cmn2.flags = N2N_FLAGS_FROM_SUPERNODE;
                memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));

                pi.aflags = 0;
                memcpy(pi.mac, query.targetMac, sizeof(n2n_mac_t));
                memcpy(pi.srcMac, sss->mac_addr, sizeof(n2n_mac_t));

                memcpy(&pi.sock, &sender, sizeof(sender));

                pi.load = sn_selection_criterion_gather_data(sss);

                snprintf(pi.version, sizeof(pi.version), "%s", sss->version);
                pi.uptime = now - sss->start_time;

                encode_PEER_INFO(encbuf, &encx, &cmn2, &pi);

                if(comm) {
                    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                        packet_header_encrypt(encbuf, encx, encx, comm->header_encryption_ctx_dynamic,
                                              comm->header_iv_ctx_dynamic,
                                              time_stamp());
                    }
                }

                sendto_sock(sss, socket_fd, sender_sock, encbuf, encx);

                traceEvent(TRACE_DEBUG, "Tx PONG to %s",
                           macaddr_str(mac_buf, query.srcMac));

            } else {
                traceEvent(TRACE_DEBUG, "Rx QUERY_PEER from %s for %s",
                           macaddr_str(mac_buf, query.srcMac),
                           macaddr_str(mac_buf2, query.targetMac));

                struct peer_info *scan;

                // as opposed to the special case 'PING', proper QUERY_PEER processing requires a locally actually present community entry
                if(!comm) {
                    traceEvent(TRACE_DEBUG, "QUERY_PEER with unknown community %s", cmn.community);
                    return -1;
                }

                HASH_FIND_PEER(comm->edges, query.targetMac, scan);
                if(scan) {
                    cmn2.ttl = N2N_DEFAULT_TTL;
                    cmn2.pc = n2n_peer_info;
                    cmn2.flags = N2N_FLAGS_FROM_SUPERNODE;
                    memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));

                    pi.aflags = 0;
                    memcpy(pi.srcMac, query.srcMac, sizeof(n2n_mac_t));
                    memcpy(pi.mac, query.targetMac, sizeof(n2n_mac_t));
                    pi.sock = scan->sock;
                    if(scan->preferred_sock.family != (uint8_t)AF_INVALID) {
                        cmn2.flags |= N2N_FLAGS_SOCKET;
                        pi.preferred_sock = scan->preferred_sock;
                    }

                    encode_PEER_INFO(encbuf, &encx, &cmn2, &pi);

                    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                        packet_header_encrypt(encbuf, encx, encx, comm->header_encryption_ctx_dynamic,
                                              comm->header_iv_ctx_dynamic,
                                              time_stamp());
                    }
                    // back to sender, be it edge or supernode (which will forward to edge)
                    sendto_sock(sss, socket_fd, sender_sock, encbuf, encx);

                    traceEvent(TRACE_DEBUG, "Tx PEER_INFO to %s",
                               macaddr_str(mac_buf, query.srcMac));

                } else {

                    if(from_supernode) {
                        traceEvent(TRACE_DEBUG, "QUERY_PEER on unknown edge from supernode %s, dropping the packet",
                                   macaddr_str(mac_buf, query.srcMac));
                    } else {
                        traceEvent(TRACE_DEBUG, "QUERY_PEER from unknown edge %s, forwarding to all other supernodes",
                                   macaddr_str(mac_buf, query.srcMac));

                        memcpy(&cmn2, &cmn, sizeof(n2n_common_t));
                        cmn2.flags |= N2N_FLAGS_FROM_SUPERNODE;

                        encode_QUERY_PEER(encbuf, &encx, &cmn2, &query);

                        if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                            packet_header_encrypt(encbuf, encx, encx, comm->header_encryption_ctx_dynamic,
                                                  comm->header_iv_ctx_dynamic,
                                                  time_stamp());
                        }

                        try_broadcast(sss, NULL, &cmn, query.srcMac, from_supernode, encbuf, encx, now);
                    }
                }
            }
            break;
        }

        case MSG_TYPE_PEER_INFO: {
            n2n_PEER_INFO_t                        pi;
            uint8_t                                encbuf[N2N_SN_PKTBUF_SIZE];
            size_t                                 encx = 0;
            struct peer_info                       *peer;

            if(!comm) {
                traceEvent(TRACE_DEBUG, "PEER_INFO with unknown community %s", cmn.community);
                return -1;
            }

            decode_PEER_INFO(&pi, &cmn, udp_buf, &rem, &idx);

            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_edge_time_stamp_and_verify(comm->edges, sn, pi.srcMac, stamp, TIME_STAMP_NO_JITTER)) {
                    traceEvent(TRACE_DEBUG, "dropped PEER_INFO due to time stamp error");
                    return -1;
                }
            }

            traceEvent(TRACE_INFO, "Rx PEER_INFO from %s [%s]",
                       macaddr_str(mac_buf, pi.srcMac),
                       sock_to_cstr(sockbuf, &sender));

            HASH_FIND_PEER(comm->edges, pi.srcMac, peer);
            if(peer != NULL) {
                if((comm->is_federation == IS_NO_FEDERATION) && (!is_null_mac(pi.srcMac))) {
                    // snoop on the information to use for supernode forwarding (do not wait until first remote REGISTER_SUPER)
                    update_node_supernode_association(comm, &(pi.mac), sender_sock, sock_size, now);

                    // this is a PEER_INFO for one of the edges conencted to this supernode, forward,
                    // i.e. re-assemble (memcpy of udpbuf to encbuf could be sufficient as well)

                    // use incoming cmn (with already decreased TTL)
                    // PEER_INFO remains unchanged

                    encode_PEER_INFO(encbuf, &encx, &cmn, &pi);

                    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                        packet_header_encrypt(encbuf, encx, encx,
                                              comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                              time_stamp());
                    }

                    sendto_peer(sss, peer, encbuf, encx);
                }
            }
            break;
        }

        default:
            /* Not a known message type */
            traceEvent(TRACE_WARNING, "unable to handle packet type %d: ignored", (signed int)msg_type);
    } /* switch(msg_type) */

    return 0;
}


/** Long lived processing entry point. Split out from main to simply
 *  daemonisation on some platforms. */
int run_sn_loop (n2n_sn_t *sss) {

    uint8_t pktbuf[N2N_SN_PKTBUF_SIZE];
    time_t last_purge_edges = 0;
    time_t last_sort_communities = 0;
    time_t last_re_reg_and_purge = 0;

    sss->start_time = time(NULL);

    while(*sss->keep_running) {
        int rc;
        ssize_t bread;
        int max_sock;
        fd_set socket_mask;
        n2n_tcp_connection_t *conn, *tmp_conn;

#ifdef N2N_HAVE_TCP
        SOCKET tmp_sock;
        n2n_sock_str_t sockbuf;
#endif
        struct timeval wait_time;
        time_t before, now = 0;

        FD_ZERO(&socket_mask);

        FD_SET(sss->sock, &socket_mask);
#ifdef N2N_HAVE_TCP
        FD_SET(sss->tcp_sock, &socket_mask);
#endif
        FD_SET(sss->mgmt_sock, &socket_mask);

        max_sock = MAX(MAX(sss->sock, sss->mgmt_sock), sss->tcp_sock);

#ifdef N2N_HAVE_TCP
        // add the tcp connections' sockets
        HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
            //socket descriptor
            FD_SET(conn->socket_fd, &socket_mask);
            if(conn->socket_fd > max_sock)
                max_sock = conn->socket_fd;
        }
#endif

        wait_time.tv_sec = 10;
        wait_time.tv_usec = 0;

        before = time(NULL);

        rc = select(max_sock + 1, &socket_mask, NULL, NULL, &wait_time);

        now = time(NULL);

        if(rc > 0) {

            // external udp
            if(FD_ISSET(sss->sock, &socket_mask)) {
                struct sockaddr_storage sas;
                struct sockaddr *sender_sock = (struct sockaddr*)&sas;
                socklen_t ss_size = sizeof(sas);

                bread = recvfrom(sss->sock, (void *)pktbuf, N2N_SN_PKTBUF_SIZE, 0 /*flags*/,
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
                    *sss->keep_running = false;
                    break;
                }

                // we have a datagram to process...
                if(bread > 0) {
                    // ...and the datagram has data (not just a header)
                    process_udp(sss, sender_sock, ss_size, sss->sock, pktbuf, bread, now);
                }
            }

#ifdef N2N_HAVE_TCP
            // the so far known tcp connections

            // beware: current conn and other items of the connection list may be found
            // due for deletion while processing packets. Even OTHER connections, e.g. if
            // forwarding to another edge node fails. connections due for deletion will
            // not immediately be deleted but marked 'inactive' for later deletion
            HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
                // do not process entries that have been marked inactive, those will be deleted
                // immediately after this loop
                if(conn->inactive)
                    continue;

                if(FD_ISSET(conn->socket_fd, &socket_mask)) {
                    struct sockaddr_storage sas;
                    struct sockaddr *sender_sock = (struct sockaddr*)&sas;
                    socklen_t ss_size = sizeof(sas);

                    bread = recvfrom(conn->socket_fd,
                                     conn->buffer + conn->position, conn->expected - conn->position, 0 /*flags*/,
                                     sender_sock, &ss_size);

                    if(bread <= 0) {
                        traceEvent(TRACE_INFO, "closing tcp connection to [%s]", sock_to_cstr(sockbuf, (n2n_sock_t*)sender_sock));
                        traceEvent(TRACE_DEBUG, "recvfrom() returns %d and sees errno %d (%s)", bread, errno, strerror(errno));
#ifdef _WIN32
                        traceEvent(TRACE_DEBUG, "WSAGetLastError(): %u", WSAGetLastError());
#endif
                        close_tcp_connection(sss, conn);
                        continue;
                    }
                    conn->position += bread;

                    if(conn->position == conn->expected) {
                        if(conn->position == sizeof(uint16_t)) {
                            // the prepended length has been read, preparing for the packet
                            conn->expected += be16toh(*(uint16_t*)(conn->buffer));
                            if(conn->expected > N2N_SN_PKTBUF_SIZE) {
                                traceEvent(TRACE_INFO, "closing tcp connection to [%s]", sock_to_cstr(sockbuf, (n2n_sock_t*)sender_sock));
                                traceEvent(TRACE_DEBUG, "too many bytes in tcp packet expected");
                                close_tcp_connection(sss, conn);
                                continue;
                            }
                        } else {
                            // full packet read, handle it
                            process_udp(sss, &(conn->sock), conn->sock_len, conn->socket_fd,
                                             conn->buffer + sizeof(uint16_t), conn->position - sizeof(uint16_t), now);

                            // reset, await new prepended length
                            conn->expected = sizeof(uint16_t);
                            conn->position = 0;
                        }
                    }
                }
            }

            // remove inactive / already closed tcp connections from list
            HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
                if(conn->inactive) {
                    HASH_DEL(sss->tcp_connections, conn);
                    free(conn);
                }
            }

            // accept new incoming tcp connection
            if(FD_ISSET(sss->tcp_sock, &socket_mask)) {
                struct sockaddr_storage sas;
                struct sockaddr *sender_sock = (struct sockaddr*)&sas;
                socklen_t ss_size = sizeof(sas);

                if((HASH_COUNT(sss->tcp_connections) + 4) < FD_SETSIZE) {
                    tmp_sock = accept(sss->tcp_sock, sender_sock, &ss_size);
                    // REVISIT: should we error out if ss_size returns bigger than before? can this ever happen?
                    if(tmp_sock >= 0) {
                        conn = (n2n_tcp_connection_t*)calloc(1, sizeof(n2n_tcp_connection_t));
                        if(conn) {
                            conn->socket_fd = tmp_sock;
                            memcpy(&(conn->sock), sender_sock, ss_size);
                            conn->sock_len = ss_size;
                            conn->inactive = 0;
                            conn->expected = sizeof(uint16_t);
                            conn->position = 0;
                            HASH_ADD_INT(sss->tcp_connections, socket_fd, conn);
                            traceEvent(TRACE_INFO, "accepted incoming TCP connection from [%s]",
                                                   sock_to_cstr(sockbuf, (n2n_sock_t*)sender_sock));
                        }
                    }
                } else {
                        // no space to store the socket for a new connection, close immediately
                        traceEvent(TRACE_DEBUG, "denied incoming TCP connection from [%s] due to max connections limit hit",
                                                sock_to_cstr(sockbuf, (n2n_sock_t*)sender_sock));
                }
            }
#endif /* N2N_HAVE_TCP */

            // handle management port input
            if(FD_ISSET(sss->mgmt_sock, &socket_mask)) {
                struct sockaddr_storage sas;
                struct sockaddr *sender_sock = (struct sockaddr*)&sas;
                socklen_t ss_size = sizeof(sas);

                bread = recvfrom(sss->mgmt_sock, (void *)pktbuf, N2N_SN_PKTBUF_SIZE, 0 /*flags*/,
                                 sender_sock, &ss_size);

                // REVISIT: should we error out if ss_size returns bigger than before? can this ever happen?
                if(bread <= 0) {
                    traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
                    *sss->keep_running = false;
                    break;
                }

                // we have a datagram to process
                process_mgmt(sss, sender_sock, ss_size, (char *)pktbuf, bread, now);
            }

        } else {
            if(((now - before) < wait_time.tv_sec) && (*sss->keep_running)){
                // this is no real timeout, something went wrong with one of the tcp connections (probably)
                // close them all, edges will re-open if they detect closure
                traceEvent(TRACE_DEBUG, "falsly claimed timeout, assuming issue with tcp connection, closing them all");
                HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn)
                    close_tcp_connection(sss, conn);
            } else
                traceEvent(TRACE_DEBUG, "timeout");
        }

        re_register_and_purge_supernodes(sss, sss->federation, &last_re_reg_and_purge, now, 0 /* not forced */);
        purge_expired_communities(sss, &last_purge_edges, now);
        sort_communities(sss, &last_sort_communities, now);
        resolve_check(sss->resolve_parameter, 0 /* presumably, no special resolution requirement */, now);
    } /* while */

    sn_term(sss);

    return 0;
}
