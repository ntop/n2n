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

#define HASH_FIND_COMMUNITY(head, name, out) HASH_FIND_STR(head, name, out)

static int try_forward (n2n_sn_t * sss,
                        const struct sn_community *comm,
                        const n2n_common_t * cmn,
                        const n2n_mac_t dstMac,
                        uint8_t from_supernode,
                        const uint8_t * pktbuf,
                        size_t pktsize);

static ssize_t sendto_peer (n2n_sn_t *sss,
                            const struct peer_info *peer,
                            const uint8_t *pktbuf,
                            size_t pktsize);

static int sendto_mgmt (n2n_sn_t *sss,
                        const struct sockaddr_in *sender_sock,
                        const uint8_t *mgmt_buf,
                        size_t mgmt_size);

static int try_broadcast (n2n_sn_t * sss,
                          const struct sn_community *comm,
                          const n2n_common_t * cmn,
                          const n2n_mac_t srcMac,
                          uint8_t from_supernode,
                          const uint8_t * pktbuf,
                          size_t pktsize);

static uint16_t reg_lifetime (n2n_sn_t *sss);

static int update_edge (n2n_sn_t *sss,
                        const n2n_REGISTER_SUPER_t* reg,
                        struct sn_community *comm,
                        const n2n_sock_t *sender_sock,
                        const SOCKET socket_fd,
                        n2n_auth_t *answer_auth,
                        int skip_add,
                        time_t now);

static int purge_expired_communities (n2n_sn_t *sss,
                                      time_t* p_last_purge,
                                      time_t now);

static int sort_communities (n2n_sn_t *sss,
                             time_t* p_last_sort,
                             time_t now);

static int process_mgmt (n2n_sn_t *sss,
                         const struct sockaddr_in *sender_sock,
                         const uint8_t *mgmt_buf,
                         size_t mgmt_size,
                         time_t now);

static int process_udp (n2n_sn_t *sss,
                        const struct sockaddr_in *sender_sock,
                        const SOCKET socket_fd,
                        uint8_t *udp_buf,
                        size_t udp_size,
                        time_t now);


/* ************************************** */

static int try_forward (n2n_sn_t * sss,
                        const struct sn_community *comm,
                        const n2n_common_t * cmn,
                        const n2n_mac_t dstMac,
                        uint8_t from_supernode,
                        const uint8_t * pktbuf,
                        size_t pktsize) {

    struct peer_info *    scan;
    macstr_t              mac_buf;
    n2n_sock_str_t        sockbuf;

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
        }
    } else {
        if(!from_supernode) {
            /* Forwarding packet to all federated supernodes. */
            traceEvent(TRACE_DEBUG, "Unknown MAC. Broadcasting packet to all federated supernodes.");
            try_broadcast(sss, NULL, cmn, sss->mac_addr, from_supernode, pktbuf, pktsize);
        } else {
            traceEvent(TRACE_DEBUG, "try_forward unknown MAC. Dropping the packet.");
            /* Not a known MAC so drop. */
            return(-2);
        }
    }

    return(0);
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

    size_t sent;

    struct sn_community *comm, *tmp_comm;
    struct peer_info *edge, *tmp_edge;
    n2n_tcp_connection_t *conn;

    sent = sendto(socket_fd, pktbuf, pktsize, 0,
                  socket, sizeof(struct sockaddr_in));

        if(sent < 0) {
            char * c = strerror(errno);
            traceEvent(TRACE_ERROR, "sendto_sock failed (%d) %s", errno, c);
#ifdef WIN32
            traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
            // if the erroneous connection is tcp, i.e. not the regular sock...
            if((socket_fd >= 0) && (socket_fd != sss->sock)) {
                // ...forget about the corresponding peer...
                HASH_ITER(hh, sss->communities, comm, tmp_comm)
                    HASH_ITER(hh, comm->edges, edge, tmp_edge) {
                        if(edge->socket_fd == socket_fd) {
                            HASH_DEL(comm->edges, edge);
                            free(edge);
                        }
                }
                // ...and the connection
                shutdown(socket_fd, SHUT_RDWR);
                closesocket(socket_fd);
                HASH_FIND_INT(sss->tcp_connections, &socket_fd, conn);
                if(conn) {
                    HASH_DEL(sss->tcp_connections, conn);
                    free(conn);
                }
            }
        } else {
            traceEvent(TRACE_DEBUG, "sendto_sock sent=%d to ", (signed int)sent);
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
        struct sockaddr_in socket;

        // network order socket
        socket.sin_family = AF_INET;
        socket.sin_port = htons(peer->sock.port);
        memcpy(&(socket.sin_addr.s_addr), &(peer->sock.addr.v4), IPV4_SIZE);

        traceEvent(TRACE_DEBUG, "sendto_peer %lu to [%s]",
                   pktsize,
                   sock_to_cstr(sockbuf, &(peer->sock)));

        return sendto_sock(sss,
                           (peer->socket_fd >= 0) ? peer->socket_fd : sss->sock,
                           (const struct sockaddr *)&socket, pktbuf, pktsize);
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
                          size_t pktsize) {

    struct peer_info        *scan, *tmp;
    macstr_t                mac_buf;
    n2n_sock_str_t          sockbuf;

    traceEvent(TRACE_DEBUG, "try_broadcast");

    /* We have to make sure that a broadcast reaches the other supernodes and edges
     * connected to them. try_broadcast needs a from_supernode parameter: if set
     * do forward to edges of community only. If unset. forward to all locally known
     * nodes and all supernodes */

    if (!from_supernode) {
        HASH_ITER(hh, sss->federation->edges, scan, tmp) {
            int data_sent_len;

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

/** Initialise some fields of the community structure **/
int comm_init (struct sn_community *comm, char *cmn) {

    strncpy((char*)comm->community, cmn, N2N_COMMUNITY_SIZE - 1);
    comm->community[N2N_COMMUNITY_SIZE - 1] = '\0';
    comm->is_federation = IS_NO_FEDERATION;

    return 0; /* OK */
}


/** Initialise the supernode structure */
int sn_init(n2n_sn_t *sss) {

    int i;
    size_t idx;

#ifdef WIN32
    initWin32();
#endif

    pearson_hash_init();

    memset(sss, 0, sizeof(n2n_sn_t));

    sss->daemon = 1; /* By defult run as a daemon. */
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
        strncpy(sss->federation->community, (char*)FEDERATION_NAME, N2N_COMMUNITY_SIZE - 1);
        sss->federation->community[N2N_COMMUNITY_SIZE - 1] = '\0';
        /* enable the flag for federation */
        sss->federation->is_federation = IS_FEDERATION;
        sss->federation->purgeable = COMMUNITY_UNPURGEABLE;
        /* header encryption enabled by default */
        sss->federation->header_encryption = HEADER_ENCRYPTION_ENABLED;
        /*setup the encryption key */
        packet_header_setup_key(sss->federation->community, &(sss->federation->header_encryption_ctx), &(sss->federation->header_iv_ctx));
        sss->federation->edges = NULL;
    }

    n2n_srand(n2n_seed());

    /* Random auth token */
    sss->auth.scheme = n2n_auth_simple_id;
    for(idx = 0; idx < N2N_AUTH_TOKEN_SIZE; ++idx) {
        sss->auth.token[idx] = n2n_rand() % 0xff;
    }
    sss->auth.toksize = sizeof(sss->auth.token);

    /* Random MAC address */
    for(i = 0; i < 6; i++) {
        sss->mac_addr[i] = n2n_rand();
    }
    sss->mac_addr[0] &= ~0x01; /* Clear multicast bit */
    sss->mac_addr[0] |= 0x02;    /* Set locally-assigned bit */

    return 0; /* OK */
}

/** Deinitialise the supernode structure and deallocate any memory owned by
 *    it. */
void sn_term (n2n_sn_t *sss) {

    struct sn_community *community, *tmp;
    struct sn_community_regular_expression *re, *tmp_re;
    n2n_tcp_connection_t *conn, *tmp_conn;

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
        if(NULL != community->header_encryption_ctx) {
            free(community->header_encryption_ctx);
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
#ifdef WIN32
    destroyWin32();
#endif
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


/** Compare two authentication tokens. It is called by update_edge
    * and in UNREGISTER_SUPER handling to compare the stored auth token
    * with the one received from the packet.
    */
static int auth_edge (const n2n_auth_t *auth1, const n2n_auth_t *auth2, n2n_auth_t *answer_auth) {

    if((auth1->scheme == n2n_auth_simple_id) && (auth2->scheme == n2n_auth_simple_id)) {
        // n2n_auth_simple_id scheme: if required, zero_token answer (not for NAK)
        if(answer_auth)
            memset(answer_auth, 0, sizeof(n2n_auth_t));

        // 0 = success (tokens are equal)
        return (memcmp(auth1, auth2, sizeof(n2n_auth_t)));
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


// handles an incoming (remote) auth token, takes action as required by auth scheme, and
// could provide an answer auth token for use in REGISTER_SUPER_ACK
// REVISIT: behavior should depend on some local auth scheme setting (to be implemented)
static int handle_remote_auth (n2n_sn_t *sss, struct peer_info *peer, const n2n_auth_t *remote_auth,
                                                                            n2n_auth_t *answer_auth) {

    // n2n_auth_simple_id scheme: store the arrived token
    memcpy(&(peer->auth), remote_auth, sizeof(n2n_auth_t));
    // n2n_auth_simple_id scheme: zero_token answer
    memset(answer_auth, 0, sizeof(n2n_auth_t));

    return 0;
}


/** Update the edge table with the details of the edge which contacted the
 *    supernode. */
static int update_edge (n2n_sn_t *sss,
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
    int auth;
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
        if(skip_add == SN_ADD) {
            scan = (struct peer_info *) calloc(1, sizeof(struct peer_info)); /* deallocated in purge_expired_nodes */
            memcpy(&(scan->mac_addr), reg->edgeMac, sizeof(n2n_mac_t));
            scan->dev_addr.net_addr = reg->dev_addr.net_addr;
            scan->dev_addr.net_bitlen = reg->dev_addr.net_bitlen;
            memcpy((char*)scan->dev_desc, reg->dev_desc, N2N_DESC_SIZE);
            memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
            scan->socket_fd = socket_fd;
            memcpy(&(scan->last_cookie), reg->cookie, sizeof(N2N_COOKIE_SIZE));
            handle_remote_auth(sss, scan, &(reg->auth), answer_auth);
            scan->last_valid_time_stamp = initial_time_stamp();

            HASH_ADD_PEER(comm->edges, scan);

            traceEvent(TRACE_INFO, "update_edge created  %s ==> %s",
                       macaddr_str(mac_buf, reg->edgeMac),
                       sock_to_cstr(sockbuf, sender_sock));
        }
        ret = update_edge_new_sn;
    } else {
        /* Known */
        if(!sock_equal(sender_sock, &(scan->sock))) {
            if((auth = auth_edge(&(scan->auth), &(reg->auth), answer_auth)) == 0) {
                memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));
                scan->socket_fd = socket_fd;
                memcpy(&(scan->last_cookie), reg->cookie, sizeof(N2N_COOKIE_SIZE));

                traceEvent(TRACE_INFO, "update_edge updated  %s ==> %s",
                           macaddr_str(mac_buf, reg->edgeMac),
                           sock_to_cstr(sockbuf, sender_sock));
                ret = update_edge_sock_change;
            } else {
                traceEvent(TRACE_INFO, "authentication failed");

                ret = update_edge_auth_fail;
            }
        } else {
            memcpy(&(scan->last_cookie), reg->cookie, sizeof(N2N_COOKIE_SIZE));

            traceEvent(TRACE_DEBUG, "update_edge unchanged %s ==> %s",
                       macaddr_str(mac_buf, reg->edgeMac),
                       sock_to_cstr(sockbuf, sender_sock));

            ret = update_edge_no_change;
        }
    }

    if(scan != NULL) {
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

    struct peer_info *peer, *tmp_peer;
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
        traceEvent(TRACE_INFO, "Assign IP %s to tap adapter of edge.", ip_subnet_to_str(ip_bit_str, ip_addr));
        return 0;
    } else {
        traceEvent(TRACE_WARNING, "No assignable IP to edge tap adapter.");
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
        traceEvent(TRACE_INFO, "Assigned sub-network %s/%u to community '%s'.",
                   inet_ntoa(*(struct in_addr *) &net),
                   comm->auto_ip_net.net_bitlen,
                   comm->community);
        return 0;
    } else {
        comm->auto_ip_net.net_addr = 0;
        comm->auto_ip_net.net_bitlen = 0;
        traceEvent(TRACE_WARNING, "No assignable sub-network left for community '%s'.",
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


static int re_register_and_purge_supernodes (n2n_sn_t *sss, struct sn_community *comm, time_t *p_last_re_reg_and_purge, time_t now) {

    time_t time;
    struct peer_info *peer, *tmp;

    if((now - (*p_last_re_reg_and_purge)) < RE_REG_AND_PURGE_FREQUENCY) {
        return 0;
    }

    // purge long-time-not-seen supernodes
    purge_expired_nodes(&(comm->edges), sss->sock, p_last_re_reg_and_purge,
                        RE_REG_AND_PURGE_FREQUENCY, LAST_SEEN_SN_INACTIVE);

    if(comm != NULL) {
        HASH_ITER(hh,comm->edges,peer,tmp) {

            time = now - peer->last_seen;

            if(time <= LAST_SEEN_SN_ACTIVE) {
                continue;
            }

            /* re-register (send REGISTER_SUPER) */
            uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};
            size_t idx;
            /* ssize_t sent; */
            n2n_common_t cmn;
            n2n_cookie_t cookie;
            n2n_REGISTER_SUPER_t reg;
            n2n_sock_str_t sockbuf;

            memset(&cmn, 0, sizeof(cmn));
            memset(&reg, 0, sizeof(reg));

            cmn.ttl = N2N_DEFAULT_TTL;
            cmn.pc = n2n_register_super;
            cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
            memcpy(cmn.community, comm->community, N2N_COMMUNITY_SIZE);

            for(idx = 0; idx < N2N_COOKIE_SIZE; ++idx) {
                cookie[idx] = n2n_rand() % 0xff;
            }

            memcpy(reg.cookie, cookie, N2N_COOKIE_SIZE);
            reg.dev_addr.net_addr = ntohl(peer->dev_addr.net_addr);
            reg.dev_addr.net_bitlen = mask2bitlen(ntohl(peer->dev_addr.net_bitlen));
            get_local_auth(sss, &(reg.auth));

            idx = 0;
            encode_mac(reg.edgeMac, &idx, sss->mac_addr);

            idx = 0;
            encode_REGISTER_SUPER(pktbuf, &idx, &cmn, &reg);

            traceEvent(TRACE_DEBUG, "send REGISTER_SUPER to %s",
                                     sock_to_cstr(sockbuf, &(peer->sock)));

            packet_header_encrypt(pktbuf, idx, idx,
                                  comm->header_encryption_ctx, comm->header_iv_ctx,
                                  time_stamp());

            /* sent = */ sendto_peer(sss, peer, pktbuf, idx);
        }
    }

    return 0; /* OK */
}


static int purge_expired_communities (n2n_sn_t *sss,
                                      time_t* p_last_purge,
                                      time_t now) {

    struct sn_community *comm, *tmp;
    size_t num_reg = 0;

    if((now - (*p_last_purge)) < PURGE_REGISTRATION_FREQUENCY) {
        return 0;
    }

    traceEvent(TRACE_DEBUG, "Purging old communities and edges");

    HASH_ITER(hh, sss->communities, comm, tmp) {
        // federation is taken care of in re_register_and_purge_supernodes()
        if(comm->is_federation == IS_FEDERATION)
            continue;

        num_reg += purge_peer_list(&comm->edges, sss->sock, now - REGISTRATION_TIMEOUT);
        if((comm->edges == NULL) && (comm->purgeable == COMMUNITY_PURGEABLE)) {
            traceEvent(TRACE_INFO, "Purging idle community %s", comm->community);
            if(NULL != comm->header_encryption_ctx) {
                /* this should not happen as 'purgeable' and thus only communities w/o encrypted header here */
                free(comm->header_encryption_ctx);
            }
            HASH_DEL(sss->communities, comm);
            free(comm);
        }
    }
    (*p_last_purge) = now;

    traceEvent(TRACE_DEBUG, "Remove %ld edges", num_reg);

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


static int process_mgmt (n2n_sn_t *sss,
                         const struct sockaddr_in *sender_sock,
                         const uint8_t *mgmt_buf,
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
                            (community->is_federation) ? "FEDERATION" :
                                                                      ((community->purgeable == COMMUNITY_UNPURGEABLE) ? "FIXED NAME COMMUNITY" : "COMMUNITY"),
                            community->community);
        sendto_mgmt(sss, sender_sock, (const uint8_t *) resbuf, ressize);
        ressize = 0;

        num = 0;
        HASH_ITER(hh, community->edges, peer, tmpPeer) {
            sprintf (time_buf, "%9u", now - peer->last_seen);
            ressize += snprintf(resbuf + ressize, N2N_SN_PKTBUF_SIZE - ressize,
                                "%4u | %-19s | %-17s | %-21s %-3s | %-15s | %9s\n",
                                ++num,
                                (peer->dev_addr.net_addr == 0) ? ((peer->purgeable == SN_UNPURGEABLE) ? "-l" : "") :
                                                                   ip_subnet_to_str(ip_bit_str, &peer->dev_addr),
                                macaddr_str(mac_buf, peer->mac_addr),
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


static int sendto_mgmt (n2n_sn_t *sss,
                        const struct sockaddr_in *sender_sock,
                        const uint8_t *mgmt_buf,
                        size_t mgmt_size) {

    ssize_t r = sendto(sss->mgmt_sock, mgmt_buf, mgmt_size, 0 /*flags*/,
                       (struct sockaddr *)sender_sock, sizeof (struct sockaddr_in));

    if(r <= 0) {
        ++(sss->stats.errors);
        traceEvent (TRACE_ERROR, "sendto_mgmt : sendto failed. %s", strerror (errno));
        return -1;
    }

    return 0;
}

/** Examine a datagram and determine what to do with it.
 *
 */
static int process_udp (n2n_sn_t * sss,
                        const struct sockaddr_in * sender_sock,
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
    macstr_t            mac_buf;
    macstr_t            mac_buf2;
    n2n_sock_str_t      sockbuf;
    char                buf[32];
    struct sn_community *comm, *tmp;
    uint64_t            stamp;
    int                 skip_add;

    traceEvent(TRACE_DEBUG, "Processing incoming UDP packet [len: %lu][sender: %s:%u]",
               udp_size, intoa(ntohl(sender_sock->sin_addr.s_addr), buf, sizeof(buf)),
               ntohs(sender_sock->sin_port));

    /* check if header is unencrypted. the following check is around 99.99962 percent reliable.
     * it heavily relies on the structure of packet's common part
     * changes to wire.c:encode/decode_common need to go together with this code */
    if(udp_size < 24) {
        traceEvent(TRACE_DEBUG, "process_udp dropped a packet too short to be valid.");
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
                traceEvent(TRACE_DEBUG, "process_udp dropped a packet with unencrypted header "
                           "addressed to community '%s' which uses encrypted headers.",
                           comm->community);
                return -1;
            }
            if(comm->header_encryption == HEADER_ENCRYPTION_UNKNOWN) {
                traceEvent(TRACE_INFO, "process_udp locked community '%s' to using "
                           "unencrypted headers.", comm->community);
                /* set 'no encryption' in case it is not set yet */
                comm->header_encryption = HEADER_ENCRYPTION_NONE;
                comm->header_encryption_ctx = NULL;
            }
        }
    } else {
        /* most probably encrypted */
        /* cycle through the known communities (as keys) to eventually decrypt */
        uint32_t ret = 0;
        HASH_ITER(hh, sss->communities, comm, tmp) {
            /* skip the definitely unencrypted communities */
            if(comm->header_encryption == HEADER_ENCRYPTION_NONE) {
                continue;
            }
            if((ret = packet_header_decrypt(udp_buf, udp_size,
                                            comm->community,
                                            comm->header_encryption_ctx, comm->header_iv_ctx,
                                            &stamp))) {
                // time stamp verification follows in the packet specific section as it requires to determine the
                // sender from the hash list by its MAC, this all depends on packet type and packet structure
                // (MAC is not always in the same place)

                if(comm->header_encryption == HEADER_ENCRYPTION_UNKNOWN) {
                    traceEvent(TRACE_INFO, "process_udp locked community '%s' to using "
                               "encrypted headers.", comm->community);
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
        if(!ret) {
            // no matching key/community
            traceEvent(TRACE_DEBUG, "process_udp dropped a packet with seemingly encrypted header "
                       "for which no matching community which uses encrypted headers was found.");
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
        traceEvent(TRACE_ERROR, "Failed to decode common section");
        return -1; /* failed to decode packet */
    }

    msg_type = cmn.pc; /* packet code */

    /* REVISIT: when UDP/IPv6 is supported we will need a flag to indicate which
     * IP transport version the packet arrived on. May need to UDP sockets. */

    memset(&sender, 0, sizeof(n2n_sock_t));

    sender.family = AF_INET; /* UDP socket was opened PF_INET v4 */
    sender.port = ntohs(sender_sock->sin_port);
    memcpy(&(sender.addr.v4), &(sender_sock->sin_addr.s_addr), IPV4_SIZE);

    from_supernode = cmn.flags & N2N_FLAGS_FROM_SUPERNODE;
    if(from_supernode) {
        skip_add = SN_ADD_SKIP;
        sn = add_sn_to_list_by_mac_or_sock (&(sss->federation->edges), &sender, null_mac, &skip_add);
        // only REGISTER_SUPER allowed from unknown supernodes
        if((!sn) && (msg_type != MSG_TYPE_REGISTER_SUPER)) {
            traceEvent(TRACE_DEBUG, "process_udp dropped incoming data from unknown supernode.");
            return -1;
        }
    }

    if(cmn.ttl < 1) {
        traceEvent(TRACE_WARNING, "Expired TTL");
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
                traceEvent(TRACE_DEBUG, "process_udp PACKET with unknown community %s", cmn.community);
                return -1;
            }

            sss->stats.last_fwd = now;
            decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx);

            // already checked for valid comm
            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_edge_time_stamp_and_verify(comm->edges, sn, pkt.srcMac, stamp, TIME_STAMP_ALLOW_JITTER)) {
                    traceEvent(TRACE_DEBUG, "process_udp dropped PACKET due to time stamp error.");
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

                pkt.sock.family = AF_INET;
                pkt.sock.port = ntohs(sender_sock->sin_port);
                memcpy(pkt.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE);

                rec_buf = encbuf;
                /* Re-encode the header. */
                encode_PACKET(encbuf, &encx, &cmn2, &pkt);
                uint16_t oldEncx = encx;

                /* Copy the original payload unchanged */
                encode_buf(encbuf, &encx, (udp_buf + idx), (udp_size - idx));

                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    packet_header_encrypt(rec_buf, oldEncx, encx,
                                          comm->header_encryption_ctx, comm->header_iv_ctx,
                                          time_stamp());
                }
            } else {
                /* Already from a supernode. Nothing to modify, just pass to
                 * destination. */

                traceEvent(TRACE_DEBUG, "Rx PACKET fwd unmodified");

                rec_buf = udp_buf;
                encx = udp_size;

                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    packet_header_encrypt(rec_buf, idx, encx,
                                          comm->header_encryption_ctx, comm->header_iv_ctx,
                                          time_stamp());
                }
            }

            /* Common section to forward the final product. */
            if(unicast) {
                try_forward(sss, comm, &cmn, pkt.dstMac, from_supernode, rec_buf, encx);
            } else {
                try_broadcast(sss, comm, &cmn, pkt.srcMac, from_supernode, rec_buf, encx);
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
                traceEvent(TRACE_DEBUG, "process_udp REGISTER from unknown community %s", cmn.community);
                return -1;
            }

            sss->stats.last_fwd = now;
            decode_REGISTER(&reg, &cmn, udp_buf, &rem, &idx);

            // already checked for valid comm
            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_edge_time_stamp_and_verify(comm->edges, sn, reg.srcMac, stamp, TIME_STAMP_NO_JITTER)) {
                    traceEvent(TRACE_DEBUG, "process_udp dropped REGISTER due to time stamp error.");
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

                    reg.sock.family = AF_INET;
                    reg.sock.port = ntohs(sender_sock->sin_port);
                    memcpy(reg.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE);

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
                                          comm->header_encryption_ctx, comm->header_iv_ctx,
                                          time_stamp());
                }
                try_forward(sss, comm, &cmn, reg.dstMac, from_supernode, rec_buf, encx); /* unicast only */
            } else {
                traceEvent(TRACE_ERROR, "Rx REGISTER with multicast destination");
            }
            break;
        }

        case MSG_TYPE_REGISTER_ACK: {
            traceEvent(TRACE_DEBUG, "Rx REGISTER_ACK (NOT IMPLEMENTED) Should not be via supernode");
            break;
        }

        case MSG_TYPE_REGISTER_SUPER: {
            n2n_REGISTER_SUPER_t                   reg;
            n2n_REGISTER_SUPER_ACK_t               ack;
            n2n_REGISTER_SUPER_NAK_t               nak;
            n2n_common_t                           cmn2;
            uint8_t                                ackbuf[N2N_SN_PKTBUF_SIZE];
            uint8_t                                *tmp_dst;
            uint8_t                                payload_buf[REG_SUPER_ACK_PAYLOAD_SPACE];
            n2n_REGISTER_SUPER_ACK_payload_t       *payload;
            size_t                                 encx = 0;
            struct sn_community                    *fed;
            struct sn_community_regular_expression *re, *tmp_re;
            struct peer_info                       *peer, *tmp_peer, *p;
            int8_t                                 allowed_match = -1;
            uint8_t                                match = 0;
            int                                    match_length = 0;
            n2n_ip_subnet_t                        ipaddr;
            int                                    num = 0;
            int                                    skip;
            int                                    ret_value;

            memset(&ack, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));
            memset(&nak, 0, sizeof(n2n_REGISTER_SUPER_NAK_t));

            /* Edge/supernode requesting registration with us.    */
            sss->stats.last_reg_super=now;
            ++(sss->stats.reg_super);
            decode_REGISTER_SUPER(&reg, &cmn, udp_buf, &rem, &idx);

            if(comm) {
                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_edge_time_stamp_and_verify(comm->edges, sn, reg.edgeMac, stamp, TIME_STAMP_NO_JITTER)) {
                        traceEvent(TRACE_DEBUG, "process_udp dropped REGISTER_SUPER due to time stamp error.");
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
                    traceEvent(TRACE_INFO, "Discarded registration: unallowed community '%s'",
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
                    comm->header_encryption_ctx = NULL;
                    /* ... and also are purgeable during periodic purge */
                    comm->purgeable = COMMUNITY_PURGEABLE;
                    comm->number_enc_packets = 0;
                    HASH_ADD_STR(sss->communities, community, comm);

                    traceEvent(TRACE_INFO, "New community: %s", comm->community);
                    assign_one_ip_subnet(sss, comm);
                }
            }

            if(comm) {
                cmn2.ttl = N2N_DEFAULT_TTL;
                cmn2.pc = n2n_register_super_ack;
                cmn2.flags = N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;
                memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));

                memcpy(&(ack.cookie), &(reg.cookie), sizeof(n2n_cookie_t));

                if(comm->is_federation == IS_FEDERATION) {
                    memcpy(ack.edgeMac, sss->mac_addr, sizeof(n2n_mac_t));
                } else {
                    memcpy(ack.edgeMac, reg.edgeMac, sizeof(n2n_mac_t));
                }

                if((reg.dev_addr.net_addr == 0) || (reg.dev_addr.net_addr == 0xFFFFFFFF) || (reg.dev_addr.net_bitlen == 0) ||
                   ((reg.dev_addr.net_addr & 0xFFFF0000) == 0xA9FE0000 /* 169.254.0.0 */)) {
                    memset(&ipaddr, 0, sizeof(n2n_ip_subnet_t));
                    assign_one_ip_addr(comm, reg.dev_desc, &ipaddr);
                    ack.dev_addr.net_addr = ipaddr.net_addr;
                    ack.dev_addr.net_bitlen = ipaddr.net_bitlen;
                }
                ack.lifetime = reg_lifetime(sss);

                ack.sock.family = AF_INET;
                ack.sock.port = ntohs(sender_sock->sin_port);
                memcpy(ack.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE);

                /* Add sender's data to federation (or update it) */
                if(comm->is_federation == IS_FEDERATION) {
                    skip_add = SN_ADD;
                    p = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), &(ack.sock), reg.edgeMac, &skip_add);
// !!! OTHER SUPERNODES COMMUNICATE VIA STANDARD UDP SOCKET
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
                    if(memcmp(&(peer->sock), &(ack.sock), sizeof(n2n_sock_t)) == 0) continue; /* a supernode doesn't add itself to the payload */
                    if((now - peer->last_seen) >= LAST_SEEN_SN_NEW) continue; /* skip long-time-not-seen supernodes.
                                                                                * We need to allow for a little extra time because supernodes sometimes exceed
                                                                                * their SN_ACTIVE time before they get re-registred to. */
                    if(((++num)*REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE) > REG_SUPER_ACK_PAYLOAD_SPACE) break; /* no more space available in REGISTER_SUPER_ACK payload */
                    memcpy(&(payload->sock), &(peer->sock), sizeof(n2n_sock_t));
                    memcpy(payload->mac, peer->mac_addr, sizeof(n2n_mac_t));
                    // shift to next payload entry
                    payload++;
                }
                ack.num_sn = num;

                traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER for %s [%s]",
                           macaddr_str(mac_buf, reg.edgeMac),
                           sock_to_cstr(sockbuf, &(ack.sock)));

                if(!is_null_mac(reg.edgeMac)) {
                    if(cmn.flags & N2N_FLAGS_SOCKET) {
                        ret_value = update_edge(sss, &reg, comm, &(ack.sock), socket_fd, &(ack.auth), SN_ADD_SKIP, now);
                    } else {
                        ret_value = update_edge(sss, &reg, comm, &(ack.sock), socket_fd, &(ack.auth), SN_ADD, now);
                    }
                }

                if(ret_value == update_edge_auth_fail) {
                    cmn2.pc = n2n_register_super_nak;
                    memcpy(&(nak.cookie), &(reg.cookie), sizeof(n2n_cookie_t));
                    memcpy(nak.srcMac, reg.edgeMac, sizeof(n2n_mac_t));

                    encode_REGISTER_SUPER_NAK(ackbuf, &encx, &cmn2, &nak);

                    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                        packet_header_encrypt(ackbuf, encx, encx,
                                              comm->header_encryption_ctx, comm->header_iv_ctx,
                                              time_stamp());
                    }
                    sendto_sock(sss, socket_fd, (struct sockaddr *)sender_sock, ackbuf, encx);

// !!! THIS NEEDS TO BE REWRITTEN TO FORWARD THROUGH ORIGINATING SUPERNODE AS
// !!! FINAL RECIPIENT MIGHT ONLY ACCEPT PACKETS FROM THERE
// !!!
// !!!                    if(cmn.flags & N2N_FLAGS_SOCKET) {
// !!!                        sendto_peer(sss, &reg.sock, ackbuf, encx);
// !!!                    }

                    traceEvent(TRACE_DEBUG, "Tx REGISTER_SUPER_NAK for %s",
                               macaddr_str(mac_buf, reg.edgeMac));
                } else {
                    // if this is not already forwarded from a supernode, ...
                    if(!(cmn.flags & N2N_FLAGS_SOCKET)) {
                        // ... forward to all other supernodes (note try_broadcast()'s behavior with
                        //     NULL comm and from_supernode parameter)

                        // exception: do not forward auto ip draw
                        if(!is_null_mac(reg.edgeMac)) {
                            reg.sock.family = AF_INET;
                            reg.sock.port = ntohs(sender_sock->sin_port);
                            memcpy(reg.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE);

                            cmn2.pc = n2n_register_super;
                            encode_REGISTER_SUPER(ackbuf, &encx, &cmn2, &reg);

                            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                                packet_header_encrypt(ackbuf, encx, encx,
                                                      comm->header_encryption_ctx, comm->header_iv_ctx,
                                                      time_stamp());
                            }

                            try_broadcast(sss, NULL, &cmn, reg.edgeMac, from_supernode, ackbuf, encx);
                        }

                        // send REGISTER_SUPER_ACK
                        encx = 0;
                        cmn2.pc = n2n_register_super_ack;

                        encode_REGISTER_SUPER_ACK(ackbuf, &encx, &cmn2, &ack, payload_buf);

                        if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                            packet_header_encrypt(ackbuf, encx, encx,
                                                  comm->header_encryption_ctx, comm->header_iv_ctx,
                                                  time_stamp());
                        }

                        sendto_sock(sss, socket_fd, (struct sockaddr *)sender_sock, ackbuf, encx);

                        traceEvent(TRACE_DEBUG, "Tx REGISTER_SUPER_ACK for %s [%s]",
                                   macaddr_str(mac_buf, reg.edgeMac),
                                   sock_to_cstr(sockbuf, &(ack.sock)));
                    }
                }
            } else {
                traceEvent(TRACE_INFO, "Discarded registration: unallowed community '%s'",
                           (char*)cmn.community);
                return -1;
            }
            break;
        }

        case MSG_TYPE_UNREGISTER_SUPER: {
            n2n_UNREGISTER_SUPER_t unreg;
            struct peer_info       *peer;
            int                    auth;


            memset(&unreg, 0, sizeof(n2n_UNREGISTER_SUPER_t));

            if(!comm) {
                traceEvent(TRACE_DEBUG, "process_udp UNREGISTER_SUPER with unknown community %s", cmn.community);
                return -1;
            }

            if((from_supernode == 1) || (comm->is_federation == IS_FEDERATION)) {
                traceEvent(TRACE_DEBUG, "process_udp dropped UNREGISTER_SUPER: should not come from a supernode or federation.");
                return -1;
            }

            decode_UNREGISTER_SUPER(&unreg, &cmn, udp_buf, &rem, &idx);

            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_edge_time_stamp_and_verify (comm->edges, sn, unreg.srcMac, stamp, TIME_STAMP_NO_JITTER)) {
                    traceEvent(TRACE_DEBUG, "process_udp dropped UNREGISTER_SUPER due to time stamp error.");
                    return -1;
                }
            }

            traceEvent(TRACE_DEBUG, "Rx UNREGISTER_SUPER from %s",
                       macaddr_str(mac_buf, unreg.srcMac));

// !!! IS THIS ALL IT NEEDS TO FORGET ABOUT A PEER AND ITS TCP CONNECTION?
            n2n_tcp_connection_t *conn;
            HASH_FIND_PEER(comm->edges, unreg.srcMac, peer);
            if(peer != NULL) {
                if((auth = auth_edge(&(peer->auth), &unreg.auth, NULL)) == 0) {
                    if((peer->socket_fd != sss->sock) && (peer->socket_fd >= 0)) {
                        shutdown(peer->socket_fd, SHUT_RDWR);
                        closesocket(peer->socket_fd);
                        HASH_FIND_INT(sss->tcp_connections, &(peer->socket_fd), conn);
                        if(conn) {
                            HASH_DEL(sss->tcp_connections, conn);
                            free(conn);
                        }
                    }
                    HASH_DEL(comm->edges, peer);
                    free(peer);
                }
            }

            break;
        }

        case MSG_TYPE_REGISTER_SUPER_ACK: {
            n2n_REGISTER_SUPER_ACK_t         ack;
            size_t                           encx = 0;
            struct sn_community              *fed;
            struct peer_info                 *scan, *tmp;
            n2n_sock_str_t                   sockbuf1;
            n2n_sock_str_t                   sockbuf2;
            macstr_t                         mac_buf1;
            n2n_sock_t                       sender;
            n2n_sock_t                       *orig_sender;
            n2n_sock_t                       *tmp_sock;
            n2n_mac_t                        *tmp_mac;
            int                              i;
            uint8_t                          dec_tmpbuf[REG_SUPER_ACK_PAYLOAD_SPACE];
            n2n_REGISTER_SUPER_ACK_payload_t *payload;

            memset(&sender, 0, sizeof(n2n_sock_t));
            sender.family = AF_INET;
            sender.port = ntohs(sender_sock->sin_port);
            memcpy(&(sender.addr.v4), &(sender_sock->sin_addr.s_addr), IPV4_SIZE);
            orig_sender = &sender;

            memset(&ack, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));

            if(!comm) {
                traceEvent(TRACE_DEBUG, "process_udp REGISTER_SUPER_ACK with unknown community %s", cmn.community);
                return -1;
            }

            if((from_supernode == 0) || (comm->is_federation == IS_NO_FEDERATION)) {
                traceEvent(TRACE_DEBUG, "process_udp dropped REGISTER_SUPER_ACK: should not come from an edge or regular community.");
                return -1;
            }

            decode_REGISTER_SUPER_ACK(&ack, &cmn, udp_buf, &rem, &idx, dec_tmpbuf);
            orig_sender = &(ack.sock);

            if(comm) {
                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_edge_time_stamp_and_verify (comm->edges, sn, ack.edgeMac, stamp, TIME_STAMP_NO_JITTER)) {
                        traceEvent(TRACE_DEBUG, "process_udp dropped REGISTER_SUPER_ACK due to time stamp error.");
                        return -1;
                    }
                }
            }

            traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK myMAC=%s [%s] (external %s)",
                       macaddr_str(mac_buf1, ack.edgeMac),
                       sock_to_cstr(sockbuf1, &sender),
                       sock_to_cstr(sockbuf2, orig_sender));

            if(comm->is_federation == IS_FEDERATION) {
                skip_add = SN_ADD_SKIP;
                scan = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), &sender, ack.edgeMac, &skip_add);
                if(scan != NULL) {
                    scan->last_seen = now;
                } else {
                    traceEvent(TRACE_DEBUG, "process_udp dropped REGISTER_SUPER_ACK due to an unknown supernode.");
                    break;
                }
            }

            payload = (n2n_REGISTER_SUPER_ACK_payload_t *)dec_tmpbuf;

            for(i = 0; i < ack.num_sn; i++) {
                skip_add = SN_ADD;
                tmp = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), &(payload->sock), payload->mac, &skip_add);
// !!! OTHER SUPERNODES COMMUNICATE VIA STANDARD UDP SOCKET
                tmp->socket_fd = sss->sock;

                if(skip_add == SN_ADD_ADDED) {
                    tmp->last_seen = now - LAST_SEEN_SN_NEW;
                }

                // shift to next payload entry
                payload++;
            }

            break;
        }

        case MSG_TYPE_REGISTER_SUPER_NAK: {
            n2n_REGISTER_SUPER_NAK_t  nak;
            size_t                    encx = 0;
            struct peer_info          *peer;
            n2n_sock_str_t            sockbuf;
            macstr_t                  mac_buf;
            n2n_sock_t                sender;

            memset(&sender, 0, sizeof(n2n_sock_t));
            sender.family = AF_INET;
            sender.port = ntohs(sender_sock->sin_port);
            memcpy(&(sender.addr.v4), &(sender_sock->sin_addr.s_addr), IPV4_SIZE);

            memset(&nak, 0, sizeof(n2n_REGISTER_SUPER_NAK_t));

            if(!comm) {
                traceEvent(TRACE_DEBUG, "process_udp REGISTER_SUPER_NAK with unknown community %s", cmn.community);
                return -1;
            }

            decode_REGISTER_SUPER_NAK(&nak, &cmn, udp_buf, &rem, &idx);

            if(comm) {
                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_edge_time_stamp_and_verify (comm->edges, sn, nak.srcMac, stamp, TIME_STAMP_NO_JITTER)) {
                        traceEvent(TRACE_DEBUG, "process_udp dropped REGISTER_SUPER_NAK due to time stamp error.");
                        return -1;
                    }
                }
            }

            traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_NAK from %s [%s]",
                       macaddr_str(mac_buf, nak.srcMac),
                       sock_to_cstr(sockbuf, &sender));

            HASH_FIND_PEER(comm->edges, nak.srcMac, peer);
            if(comm->is_federation == IS_NO_FEDERATION) {
                if(peer != NULL) {
// !!! IS THIS ALL IT NEEDS TO FORGET ABOUT A PEER AND ITS TCP CONNECTION?
// !!! GIVE IT ITS OWN FUNCTION?
                    n2n_tcp_connection_t *conn;
                    if((peer->socket_fd != sss->sock) && (peer->socket_fd >= 0)) {
                        shutdown(peer->socket_fd, SHUT_RDWR);
                        closesocket(peer->socket_fd);
                        HASH_FIND_INT(sss->tcp_connections, &(peer->socket_fd), conn);
                        if(conn) {
                            HASH_DEL(sss->tcp_connections, conn);
                            free(conn);
                        }
                    }
// !!! THIS IS WHERE THE NAK MUST BE FORWARDED TO ORIGINATING SUPERNODE
                    HASH_DEL(comm->edges, peer);
                    free(peer);
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
            struct peer_info                       *peer, *tmp_peer, *p;
            int8_t                                 allowed_match = -1;
            uint8_t                                match = 0;
            int                                    match_length = 0;
            uint8_t                                *rec_buf; /* either udp_buf or encbuf */

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
                    traceEvent(TRACE_DEBUG, "process_udp QUERY_PEER from unknown community %s", cmn.community);
                    return -1;
                }
            }

            if(!comm && sss->lock_communities && (match == 0)) {
                traceEvent(TRACE_DEBUG, "process_udp QUERY_PEER from not allowed community %s", cmn.community);
                return -1;
            }

            decode_QUERY_PEER( &query, &cmn, udp_buf, &rem, &idx );

            // already checked for valid comm
            if(comm) {
                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    if(!find_edge_time_stamp_and_verify (comm->edges, sn, query.srcMac, stamp, TIME_STAMP_ALLOW_JITTER)) {
                        traceEvent(TRACE_DEBUG, "process_udp dropped QUERY_PEER due to time stamp error.");
                        return -1;
                    }
                }
            }

            if(is_null_mac(query.targetMac)) {
                traceEvent(TRACE_DEBUG, "Rx PING from %s.",
                           macaddr_str(mac_buf, query.srcMac));

                cmn2.ttl = N2N_DEFAULT_TTL;
                cmn2.pc = n2n_peer_info;
                cmn2.flags = N2N_FLAGS_FROM_SUPERNODE;
                memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));

                pi.aflags = 0;
                memcpy(pi.mac, query.targetMac, sizeof(n2n_mac_t));
                memcpy(pi.srcMac, sss->mac_addr, sizeof(n2n_mac_t));
                pi.sock.family = AF_INET;
                pi.sock.port = ntohs(sender_sock->sin_port);
                memcpy(pi.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE);
                pi.data = sn_selection_criterion_gather_data(sss);

                encode_PEER_INFO(encbuf, &encx, &cmn2, &pi);

                if(comm) {
                    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                        packet_header_encrypt(encbuf, encx, encx, comm->header_encryption_ctx,
                                              comm->header_iv_ctx,
                                              time_stamp());
                    }
                }

                sendto_sock(sss, socket_fd, (struct sockaddr *)sender_sock, encbuf, encx);

                traceEvent(TRACE_DEBUG, "Tx PONG to %s",
                           macaddr_str(mac_buf, query.srcMac));

            } else {
                traceEvent(TRACE_DEBUG, "Rx QUERY_PEER from %s for %s",
                           macaddr_str(mac_buf, query.srcMac),
                           macaddr_str(mac_buf2, query.targetMac));

                struct peer_info *scan;
                HASH_FIND_PEER(comm->edges, query.targetMac, scan);
                if(scan) {
                    cmn2.ttl = N2N_DEFAULT_TTL;
                    cmn2.pc = n2n_peer_info;
                    cmn2.flags = N2N_FLAGS_FROM_SUPERNODE;
                    memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));

                    pi.aflags = 0;
                    memcpy(pi.mac, query.targetMac, sizeof(n2n_mac_t));
                    pi.sock = scan->sock;

                    encode_PEER_INFO(encbuf, &encx, &cmn2, &pi);

                    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                        packet_header_encrypt(encbuf, encx, encx, comm->header_encryption_ctx,
                                              comm->header_iv_ctx,
                                              time_stamp());
                    }

                    if(cmn.flags & N2N_FLAGS_SOCKET) {
// !!! THIS NEEDS TO BE REWRITTEN TO FORWARD THROUGH ORIGINATING SUPERNODE AS
// !!! FINAL RECIPIENT MIGHT ONLY ACCEPT PACKETS FROM THERE, INCLUDES PEER_INFO
// !!! FORWARDING CODE IN SN_UTILS.C (NO HANDLING OF INCOMING PEER_INFO YET
// !!!
// !!!                        sendto_peer(sss, &query.sock, encbuf, encx);
                    } else {
                        sendto_sock(sss, socket_fd, (struct sockaddr *)sender_sock, encbuf, encx);
                    }
                    traceEvent(TRACE_DEBUG, "Tx PEER_INFO to %s",
                               macaddr_str(mac_buf, query.srcMac));

                } else {

                    if(from_supernode) {
                        traceEvent(TRACE_DEBUG, "QUERY_PEER on unknown edge from supernode %s. Dropping the packet.",
                                   macaddr_str(mac_buf, query.srcMac));
                    } else {
                        traceEvent(TRACE_DEBUG, "QUERY_PEER from unknown edge %s. Forwarding to all other supernodes.",
                                   macaddr_str(mac_buf, query.srcMac));

                        memcpy(&cmn2, &cmn, sizeof(n2n_common_t));

                        /* We are going to add socket even if it was not there before */
                        cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;
                        query.sock.family = AF_INET;
                        query.sock.port = ntohs(sender_sock->sin_port);
                        memcpy(query.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE);

                        encode_QUERY_PEER(encbuf, &encx, &cmn2, &query);

                        if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                            packet_header_encrypt(encbuf, encx, encx, comm->header_encryption_ctx,
                                                  comm->header_iv_ctx,
                                                  time_stamp());
                        }

                        try_broadcast(sss, NULL, &cmn, query.srcMac, from_supernode, encbuf, encx);
                    }
                }
            }

            break;
        }

        default:
            /* Not a known message type */
            traceEvent(TRACE_WARNING, "Unable to handle packet type %d: ignored", (signed int)msg_type);
    } /* switch(msg_type) */

    return 0;
}

/** Long lived processing entry point. Split out from main to simply
 *  daemonisation on some platforms. */
int run_sn_loop (n2n_sn_t *sss, int *keep_running) {

    uint8_t pktbuf[N2N_SN_PKTBUF_SIZE];
    time_t last_purge_edges = 0;
    time_t last_sort_communities = 0;
    time_t last_re_reg_and_purge = 0;

    sss->start_time = time(NULL);

    while(*keep_running) {
        int rc;
        ssize_t bread;
        int max_sock;
        fd_set socket_mask;
        n2n_tcp_connection_t *conn, *tmp_conn;
        struct sn_community *comm, *tmp_comm;
        struct peer_info *edge, *tmp_edge;

        SOCKET tmp_sock;
        n2n_sock_str_t sockbuf;
        struct timeval wait_time;
        time_t now = 0;

        FD_ZERO(&socket_mask);

        FD_SET(sss->sock, &socket_mask);
        FD_SET(sss->tcp_sock, &socket_mask);
        FD_SET(sss->mgmt_sock, &socket_mask);

        max_sock = MAX(MAX(sss->sock, sss->mgmt_sock), sss->tcp_sock);

        // add the tcp connections' sockets
        HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
            //socket descriptor
            FD_SET(conn->socket_fd, &socket_mask);
            if(conn->socket_fd > max_sock)
                max_sock = conn->socket_fd;
        }

        wait_time.tv_sec = 10;
        wait_time.tv_usec = 0;

        rc = select(max_sock + 1, &socket_mask, NULL, NULL, &wait_time);

        now = time(NULL);

        if(rc > 0) {

            // external udp
            if(FD_ISSET(sss->sock, &socket_mask)) {
                struct sockaddr_in sender_sock;
                socklen_t i;

                i = sizeof(sender_sock);
                bread = recvfrom(sss->sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0 /*flags*/,
                                 (struct sockaddr *)&sender_sock, (socklen_t *)&i);

                if((bread < 0)
#ifdef WIN32
                   && (WSAGetLastError() != WSAECONNRESET)
#endif
                  ) {
                    /* For UDP bread of zero just means no data (unlike TCP). */
                    /* The fd is no good now. Maybe we lost our interface. */
                    traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
#ifdef WIN32
                    traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
                    *keep_running = 0;
                    break;
                }

                // we have a datagram to process...
                if(bread > 0) {
                    // ...and the datagram has data (not just a header)
                    process_udp(sss, &sender_sock, sss->sock, pktbuf, bread, now);
                }
            }

            // the so far known tcp connections
            HASH_ITER(hh, sss->tcp_connections, conn, tmp_conn) {
                if(FD_ISSET(conn->socket_fd, &socket_mask)) {
                    struct sockaddr_in sender_sock;
                    socklen_t i;

                    i = sizeof(sender_sock);
                    bread = recvfrom(conn->socket_fd, pktbuf, N2N_SN_PKTBUF_SIZE, 0 /*flags*/,
                                     (struct sockaddr *)&sender_sock, (socklen_t *)&i);

                    // error and
                    // for TCP bread of zero just means connection terminated
                    if((bread <= 0)
#ifdef WIN32
// !!! CONNECTION RESET SHALL NOT BE IGNORED
// !!!                    && (WSAGetLastError() != WSAECONNRESET)
#endif
                      ) {
                        traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
#ifdef WIN32
                        traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif

                        // forget about this peer...
                        HASH_ITER(hh, sss->communities, comm, tmp_comm)
                            HASH_ITER(hh, comm->edges, edge, tmp_edge) {
                                if(edge->socket_fd == conn->socket_fd) {
                                    HASH_DEL(comm->edges, edge);
                                    free(edge);
                                }
                            }
                        // ...and the connection
                        shutdown(conn->socket_fd, SHUT_RDWR);
                        closesocket(conn->socket_fd);
                        HASH_DEL(sss->tcp_connections, conn);
                        free(conn);

                    // bread > 0: we have a datagram to process...
                    } else {
                        // ...and the datagram has data (not just a header)
                        process_udp(sss, (struct sockaddr_in*)&(conn->sock), conn->socket_fd, pktbuf, bread, now);

                    }
                }
            }

           // accept new incoming tcp connection
            if(FD_ISSET(sss->tcp_sock, &socket_mask)) {
                struct sockaddr_in sender_sock;
                socklen_t i;

                i = sizeof(sender_sock);
                tmp_sock = accept(sss->tcp_sock, (struct sockaddr *)&sender_sock, (socklen_t *)&i);
                if(tmp_sock >= 0) {
                    if((HASH_COUNT(sss->tcp_connections) + 4) < FD_SETSIZE) {
                        conn = (n2n_tcp_connection_t*)malloc(sizeof(n2n_tcp_connection_t));
                        if(conn) {
                            conn->socket_fd = tmp_sock;
                            memcpy(&(conn->sock), &sender_sock, sizeof(struct sockaddr));
                            HASH_ADD_INT(sss->tcp_connections, socket_fd, conn);
                            traceEvent(TRACE_DEBUG, "run_sn_loop accepted incoming TCP connection from %s",
                                                    sock_to_cstr(sockbuf, (n2n_sock_t*)&sender_sock));
                        }
                    } else {
                        // no space to store the socket for a new connection, close immediately
                        closesocket(tmp_sock);
                    }
                }
            }

            // handle management port input
            if(FD_ISSET(sss->mgmt_sock, &socket_mask)) {
                struct sockaddr_in sender_sock;
                size_t i;

                i = sizeof(sender_sock);
                bread = recvfrom(sss->mgmt_sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0 /*flags*/,
                                 (struct sockaddr *)&sender_sock, (socklen_t *)&i);

                if(bread <= 0) {
                    traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
                    *keep_running = 0;
                    break;
                }

                // we have a datagram to process
                process_mgmt(sss, &sender_sock, pktbuf, bread, now);
            }

        } else {
            traceEvent(TRACE_DEBUG, "timeout");
        }

        re_register_and_purge_supernodes(sss, sss->federation, &last_re_reg_and_purge, now);
        purge_expired_communities(sss, &last_purge_edges, now);
        sort_communities(sss, &last_sort_communities, now);
    } /* while */

    sn_term(sss);

    return 0;
}
