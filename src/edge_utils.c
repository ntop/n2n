/**
 * (C) 2007-20 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#include "n2n.h"
#include "edge_utils_win32.h"

/* heap allocation for compression as per lzo example doc */
#define HEAP_ALLOC(var,size) lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]
static HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);

/* ************************************** */

static const char * supernode_ip(const n2n_edge_t * eee);
static void send_register(n2n_edge_t *eee, const n2n_sock_t *remote_peer, const n2n_mac_t peer_mac);
static void check_peer_registration_needed(n2n_edge_t * eee,
					   uint8_t from_supernode,
					   const n2n_mac_t mac,
					   const n2n_sock_t * peer);
static int edge_init_sockets(n2n_edge_t *eee, int udp_local_port, int mgmt_port, uint8_t tos);
static int edge_init_routes(n2n_edge_t *eee, n2n_route_t *routes, uint16_t num_routes);
static void edge_cleanup_routes(n2n_edge_t *eee);
static int supernode2addr(n2n_sock_t * sn, const n2n_sn_name_t addrIn);
static void check_known_peer_sock_change(n2n_edge_t * eee,
					 uint8_t from_supernode,
					 const n2n_mac_t mac,
					 const n2n_sock_t * peer,
					 time_t when);

/* ************************************** */

int edge_verify_conf(const n2n_edge_conf_t *conf) {
  if(conf->community_name[0] == 0)
    return(-1);

  if(conf->sn_num == 0)
    return(-2);

  if(conf->register_interval < 1)
    return(-3);

  if(((conf->encrypt_key == NULL) && (conf->transop_id != N2N_TRANSFORM_ID_NULL)) ||
     ((conf->encrypt_key != NULL) && (conf->transop_id == N2N_TRANSFORM_ID_NULL)))
    return(-4);

  return(0);
}


/* ************************************** */

void edge_set_callbacks(n2n_edge_t *eee, const n2n_edge_callbacks_t *callbacks) {
  memcpy(&eee->cb, callbacks, sizeof(n2n_edge_callbacks_t));
}

/* ************************************** */

void edge_set_userdata(n2n_edge_t *eee, void *user_data) {
  eee->user_data = user_data;
}

/* ************************************** */

void* edge_get_userdata(n2n_edge_t *eee) {
  return(eee->user_data);
}

/* ************************************** */

int edge_get_n2n_socket(n2n_edge_t *eee) {
  return(eee->udp_sock);
}

/* ************************************** */

int edge_get_management_socket(n2n_edge_t *eee) {
  return(eee->udp_mgmt_sock);
}

/* ************************************** */

const char* transop_str(enum n2n_transform tr) {
  switch(tr) {
  case N2N_TRANSFORM_ID_NULL:    return("null");
  case N2N_TRANSFORM_ID_TWOFISH: return("twofish");
  case N2N_TRANSFORM_ID_AESCBC:  return("AES-CBC");
  case N2N_TRANSFORM_ID_CHACHA20:return("ChaCha20");
  case N2N_TRANSFORM_ID_SPECK   :return("Speck");
  default:                       return("invalid");
  };
}

/* ************************************** */

const char* compression_str(uint8_t cmpr) {
  switch(cmpr) {
  case N2N_COMPRESSION_ID_NONE:  return("none");
  case N2N_COMPRESSION_ID_LZO:   return("lzo1x");

#ifdef HAVE_LIBZSTD
  case N2N_COMPRESSION_ID_ZSTD:  return("zstd");
#endif
  default:                       return("invalid");
  };
}

/* ************************************** */

/** Destination 01:00:5E:00:00:00 - 01:00:5E:7F:FF:FF is multicast ethernet.
 */
static int is_ethMulticast(const void * buf, size_t bufsize) {
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
 *  neighbour discovery.
 */
static int is_ip6_discovery(const void * buf, size_t bufsize) {
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

/** Initialise an edge to defaults.
 *
 *  This also initialises the NULL transform operation opstruct.
 */
n2n_edge_t* edge_init(const n2n_edge_conf_t *conf, int *rv) {
  n2n_transform_t transop_id = conf->transop_id;
  n2n_edge_t *eee = calloc(1, sizeof(n2n_edge_t));
  int rc = -1, i;

  if((rc = edge_verify_conf(conf)) != 0) {
    traceEvent(TRACE_ERROR, "Invalid configuration");
    goto edge_init_error;
  }

  if(!eee) {
    traceEvent(TRACE_ERROR, "Cannot allocate memory");
    goto edge_init_error;
  }

#ifdef WIN32
  initWin32();
#endif

  memcpy(&eee->conf, conf, sizeof(*conf));
  eee->start_time = time(NULL);

  eee->known_peers    = NULL;
  eee->pending_peers  = NULL;
  eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;
  eee->sn_last_valid_time_stamp = initial_time_stamp ();

  pearson_hash_init();

  if(eee->conf.compression == N2N_COMPRESSION_ID_LZO)
    if(lzo_init() != LZO_E_OK) {
      traceEvent(TRACE_ERROR, "LZO compression error");
      goto edge_init_error;
    }

#ifdef N2N_HAVE_ZSTD
  // zstd does not require initialization. if it were required, this would be a good place
#endif

  for(i=0; i<eee->conf.sn_num; ++i)
    traceEvent(TRACE_NORMAL, "supernode %u => %s\n", i, (eee->conf.sn_ip_array[i]));

  /* Set the active supernode */
  supernode2addr(&(eee->supernode), eee->conf.sn_ip_array[eee->sn_idx]);

  /* Set active transop */
  switch(transop_id) {
  case N2N_TRANSFORM_ID_TWOFISH:
    rc = n2n_transop_twofish_init(&eee->conf, &eee->transop);
    break;
#ifdef N2N_HAVE_AES
  case N2N_TRANSFORM_ID_AESCBC:
    rc = n2n_transop_aes_cbc_init(&eee->conf, &eee->transop);
    break;
#endif
#ifdef HAVE_OPENSSL_1_1
  case N2N_TRANSFORM_ID_CHACHA20:
    rc = n2n_transop_cc20_init(&eee->conf, &eee->transop);
    break;
#endif
  case N2N_TRANSFORM_ID_SPECK:
    rc = n2n_transop_speck_init(&eee->conf, &eee->transop);
    break;
  default:
    rc = n2n_transop_null_init(&eee->conf, &eee->transop);
  }

  if((rc < 0) || (eee->transop.fwd == NULL) || (eee->transop.transform_id != transop_id)) {
    traceEvent(TRACE_ERROR, "Transop init failed");
    goto edge_init_error;
  }

  /* Set the key schedule (context) for header encryption if enabled */
  if(conf->header_encryption == HEADER_ENCRYPTION_ENABLED) {
    traceEvent(TRACE_NORMAL, "Header encryption is enabled.");
    packet_header_setup_key ((char *)(eee->conf.community_name), &(eee->conf.header_encryption_ctx),&(eee->conf.header_iv_ctx));
  }

  if(eee->transop.no_encryption)
    traceEvent(TRACE_WARNING, "Encryption is disabled in edge");

  if(edge_init_sockets(eee, eee->conf.local_port, eee->conf.mgmt_port, eee->conf.tos) < 0) {
    traceEvent(TRACE_ERROR, "socket setup failed");
    goto edge_init_error;
  }

  if(edge_init_routes(eee, eee->conf.routes, eee->conf.num_routes) < 0) {
    traceEvent(TRACE_ERROR, "routes setup failed");
    goto edge_init_error;
  }

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

static int find_and_remove_peer(struct peer_info **head, const n2n_mac_t mac) {
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
static int is_valid_peer_sock(const n2n_sock_t *sock) {
  switch(sock->family) {
  case AF_INET:
    {
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

/** Resolve the supernode IP address.
 *
 *  REVISIT: This is a really bad idea. The edge will block completely while the
 *           hostname resolution is performed. This could take 15 seconds.
 */
static int supernode2addr(n2n_sock_t * sn, const n2n_sn_name_t addrIn) {
  n2n_sn_name_t addr;
  const char *supernode_host;
  int rv = 0;

  memcpy(addr, addrIn, N2N_EDGE_SN_HOST_SIZE);

  supernode_host = strtok(addr, ":");

  if(supernode_host) {
    in_addr_t sn_addr;
    char *supernode_port = strtok(NULL, ":");
    const struct addrinfo aihints = {0, PF_INET, 0, 0, 0, NULL, NULL, NULL};
    struct addrinfo * ainfo = NULL;
    int nameerr;

    if(supernode_port)
      sn->port = atoi(supernode_port);
    else
      traceEvent(TRACE_WARNING, "Bad supernode parameter (-l <host:port>) %s %s:%s",
		 addr, supernode_host, supernode_port);

    nameerr = getaddrinfo(supernode_host, NULL, &aihints, &ainfo);

    if(0 == nameerr)
      {
	struct sockaddr_in * saddr;

	/* ainfo s the head of a linked list if non-NULL. */
	if(ainfo && (PF_INET == ainfo->ai_family))
	  {
	    /* It is definitely and IPv4 address -> sockaddr_in */
	    saddr = (struct sockaddr_in *)ainfo->ai_addr;

	    memcpy(sn->addr.v4, &(saddr->sin_addr.s_addr), IPV4_SIZE);
	    sn->family=AF_INET;
	  }
	else
	  {
	    /* Should only return IPv4 addresses due to aihints. */
	    traceEvent(TRACE_WARNING, "Failed to resolve supernode IPv4 address for %s", supernode_host);
	    rv = -1;
	  }

	freeaddrinfo(ainfo); /* free everything allocated by getaddrinfo(). */
	ainfo = NULL;
      } else {
      traceEvent(TRACE_WARNING, "Failed to resolve supernode host %s", supernode_host);
      rv = -2;
    }

  } else {
    traceEvent(TRACE_WARNING, "Wrong supernode parameter (-l <host:port>)");
    rv = -3;
  }

  return(rv);
}

/* ************************************** */

static const int definitely_from_supernode = 1;

/***
 *
 * For a given packet, find the apporopriate internal last valid time stamp for lookup
 * and verify it (and also update, if applicable).
 */
static int find_peer_time_stamp_and_verify (n2n_edge_t * eee,
                                           int from_supernode, const n2n_mac_t mac,
                                           uint64_t stamp) {

  uint64_t * previous_stamp = NULL;

  if(from_supernode) {
    // from supernode
    previous_stamp = &(eee->sn_last_valid_time_stamp);
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

  // failure --> 0;  success --> 1
  return ( time_stamp_verify_and_update (stamp, previous_stamp) );
}

/* ************************************** */

/***
 *
 * Register over multicast in case there is a peer on the same network listening
 */
static void register_with_local_peers(n2n_edge_t * eee) {
#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
  if(eee->multicast_joined && eee->conf.allow_p2p) {
    /* send registration to the local multicast group */
    traceEvent(TRACE_DEBUG, "Registering with multicast group %s:%u",
	       N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT);
    send_register(eee, &(eee->multicast_peer), NULL);
  }
#else
  traceEvent(TRACE_DEBUG, "Multicast peers discovery is disabled, skipping");
#endif
}

/* ************************************** */

/** Start the registration process.
 *
 *  If the peer is already in pending_peers, ignore the request.
 *  If not in pending_peers, add it and send a REGISTER.
 *
 *  If hdr is for a direct peer-to-peer packet, try to register back to sender
 *  even if the MAC is in pending_peers. This is because an incident direct
 *  packet indicates that peer-to-peer exchange should work so more aggressive
 *  registration can be permitted (once per incoming packet) as this should only
 *  last for a small number of packets..
 *
 *  Called from the main loop when Rx a packet for our device mac.
 */
static void register_with_new_peer(n2n_edge_t * eee,
				   uint8_t from_supernode,
				   const n2n_mac_t mac,
				   const n2n_sock_t * peer) {
  /* REVISIT: purge of pending_peers not yet done. */
  struct peer_info * scan;
  macstr_t mac_buf;
  n2n_sock_str_t sockbuf;

  HASH_FIND_PEER(eee->pending_peers, mac, scan);

  /* NOTE: pending_peers are purged periodically with purge_expired_registrations */
  if(scan == NULL) {
    scan = calloc(1, sizeof(struct peer_info));

    memcpy(scan->mac_addr, mac, N2N_MAC_SIZE);
    scan->sock = *peer;
    scan->timeout = REGISTER_SUPER_INTERVAL_DFL; /* TODO: should correspond to the peer supernode registration timeout */
    scan->last_seen = time(NULL); /* Don't change this it marks the pending peer for removal. */
    scan->last_valid_time_stamp = initial_time_stamp ();

    HASH_ADD_PEER(eee->pending_peers, scan);

    traceEvent(TRACE_DEBUG, "=== new pending %s -> %s",
	       macaddr_str(mac_buf, scan->mac_addr),
	       sock_to_cstr(sockbuf, &(scan->sock)));

    traceEvent(TRACE_DEBUG, "Pending peers list size=%u",
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
#ifndef WIN32
      } else if(eee->conf.register_ttl > 1) {
        /* Setting register_ttl usually implies that the edge knows the internal net topology
         * clearly, we can apply aggressive port prediction to support incoming Symmetric NAT
         */
        int curTTL = 0;
        socklen_t lenTTL = sizeof(int);
        n2n_sock_t sock = scan->sock;
        int alter = 16; /* TODO: set by command line or more reliable prediction method */

        getsockopt(eee->udp_sock, IPPROTO_IP, IP_TTL, (void *)(char *)&curTTL, &lenTTL);
        setsockopt(eee->udp_sock, IPPROTO_IP, IP_TTL,
		   (void *)(char *)&eee->conf.register_ttl,
		   sizeof(eee->conf.register_ttl));
        for (; alter > 0; alter--, sock.port++)
	  {
	    send_register(eee, &sock, mac);
	  }
        setsockopt(eee->udp_sock, IPPROTO_IP, IP_TTL, (void *)(char *)&curTTL, sizeof(curTTL));
#endif
      } else { /* eee->conf.register_ttl <= 0 */
        /* Normal STUN */
        send_register(eee, &(scan->sock), mac);
      }
      send_register(eee, &(eee->supernode), mac);
    } else {
      /* P2P register, send directly */
      send_register(eee, &(scan->sock), mac);
    }

    register_with_local_peers(eee);
  } else
    scan->sock = *peer;
}

/* ************************************** */

/** Update the last_seen time for this peer, or get registered. */
static void check_peer_registration_needed(n2n_edge_t * eee,
					   uint8_t from_supernode,
					   const n2n_mac_t mac,
					   const n2n_sock_t * peer) {
  struct peer_info *scan;

  HASH_FIND_PEER(eee->known_peers, mac, scan);

  if(scan == NULL) {
    /* Not in known_peers - start the REGISTER process. */
    register_with_new_peer(eee, from_supernode, mac, peer);
  } else {
    /* Already in known_peers. */
    time_t now = time(NULL);

    if(!from_supernode)
      scan->last_p2p = now;

    if((now - scan->last_seen) > 0 /* >= 1 sec */) {
      /* Don't register too often */
      check_known_peer_sock_change(eee, from_supernode, mac, peer, now);
    }
  }
}
/* ************************************** */


/* Confirm that a pending peer is reachable directly via P2P.
 *
 * peer must be a pointer to an element of the pending_peers list.
 */
static void peer_set_p2p_confirmed(n2n_edge_t * eee,
				   const n2n_mac_t mac,
				   const n2n_sock_t * peer,
				   time_t now) {
  struct peer_info *scan;
  macstr_t mac_buf;
  n2n_sock_str_t sockbuf;

  HASH_FIND_PEER(eee->pending_peers, mac, scan);

  if(scan) {
    HASH_DEL(eee->pending_peers, scan);

    /* Add scan to known_peers. */
    HASH_ADD_PEER(eee->known_peers, scan);

    scan->sock = *peer;
    scan->last_p2p = now;

    traceEvent(TRACE_DEBUG, "P2P connection established: %s [%s]",
	       macaddr_str(mac_buf, mac),
	       sock_to_cstr(sockbuf, peer));

    traceEvent(TRACE_DEBUG, "=== new peer %s -> %s",
	       macaddr_str(mac_buf, scan->mac_addr),
	       sock_to_cstr(sockbuf, &(scan->sock)));

    traceEvent(TRACE_DEBUG, "Pending peers list size=%u",
	       HASH_COUNT(eee->pending_peers));

    traceEvent(TRACE_DEBUG, "Known peers list size=%u",
	       HASH_COUNT(eee->known_peers));

    scan->last_seen = now;
  } else
    traceEvent(TRACE_DEBUG, "Failed to find sender in pending_peers.");
}

/* ************************************** */

int is_empty_ip_address(const n2n_sock_t * sock) {
  const uint8_t * ptr=NULL;
  size_t len=0;
  size_t i;

  if(AF_INET6 == sock->family)
    {
      ptr = sock->addr.v6;
      len = 16;
    }
  else
    {
      ptr = sock->addr.v4;
      len = 4;
    }

  for (i=0; i<len; ++i)
    {
      if(0 != ptr[i])
        {
	  /* found a non-zero byte in address */
	  return 0;
        }
    }

  return 1;
}

/* ************************************** */

static const n2n_mac_t broadcast_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const n2n_mac_t null_mac = {0, 0, 0, 0, 0, 0};

/** Check if a known peer socket has changed and possibly register again.
 */
static void check_known_peer_sock_change(n2n_edge_t * eee,
					 uint8_t from_supernode,
					 const n2n_mac_t mac,
					 const n2n_sock_t * peer,
					 time_t when) {
  struct peer_info *scan;
  n2n_sock_str_t sockbuf1;
  n2n_sock_str_t sockbuf2; /* don't clobber sockbuf1 if writing two addresses to trace */
  macstr_t mac_buf;

  if(is_empty_ip_address(peer))
    return;

  if(!memcmp(mac, broadcast_mac, N2N_MAC_SIZE))
    return;

  /* Search the peer in known_peers */
  HASH_FIND_PEER(eee->known_peers, mac, scan);

  if(!scan)
    /* Not in known_peers */
    return;

  if(!sock_equal(&(scan->sock), peer)) {
    if(!from_supernode) {
      /* This is a P2P packet */
      traceEvent(TRACE_NORMAL, "Peer changed %s: %s -> %s",
		 macaddr_str(mac_buf, scan->mac_addr),
		 sock_to_cstr(sockbuf1, &(scan->sock)),
		 sock_to_cstr(sockbuf2, peer));
      /* The peer has changed public socket. It can no longer be assumed to be reachable. */
      HASH_DEL(eee->known_peers, scan);
      free(scan);

      register_with_new_peer(eee, from_supernode, mac, peer);
    } else {
      /* Don't worry about what the supernode reports, it could be seeing a different socket. */
    }
  } else
    scan->last_seen = when;
}

/* ************************************** */

/** Send a datagram to a socket defined by a n2n_sock_t */
static ssize_t sendto_sock(int fd, const void * buf,
			   size_t len, const n2n_sock_t * dest) {
  struct sockaddr_in peer_addr;
  ssize_t sent;

  if(!dest->family)
    // Invalid socket
    return 0;

  fill_sockaddr((struct sockaddr *) &peer_addr,
		sizeof(peer_addr),
		dest);

  sent = sendto(fd, buf, len, 0/*flags*/,
		(struct sockaddr *)&peer_addr, sizeof(struct sockaddr_in));
  if(sent < 0)
    {
      char * c = strerror(errno);
      traceEvent(TRACE_ERROR, "sendto failed (%d) %s", errno, c);
    }
  else
    {
      traceEvent(TRACE_DEBUG, "sendto sent=%d to ", (signed int)sent);
    }

  return sent;
}

/* ************************************** */

/* Bind eee->udp_multicast_sock to multicast group */
static void check_join_multicast_group(n2n_edge_t *eee) {
#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
  if(!eee->multicast_joined) {
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(N2N_MULTICAST_GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if(setsockopt(eee->udp_multicast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
      traceEvent(TRACE_WARNING, "Failed to bind to local multicast group %s:%u [errno %u]",
		 N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT, errno);

#ifdef WIN32
      traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
    } else {
      traceEvent(TRACE_NORMAL, "Successfully joined multicast group %s:%u",
		 N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT);
      eee->multicast_joined = 1;
    }
  }
#endif
}

/* ************************************** */

/** Send a REGISTER_SUPER packet to the current supernode. */
static void send_register_super(n2n_edge_t *eee, const n2n_sock_t *supernode, int sn_idx) {
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
	cmn.flags = 0;
	memcpy(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

	for (idx = 0; (sn_idx==0) && (idx < N2N_COOKIE_SIZE); ++idx)
		eee->last_cookie[idx] = n2n_rand() % 0xff;

	memcpy(reg.cookie, eee->last_cookie, N2N_COOKIE_SIZE);
	reg.dev_addr.net_addr = ntohl(eee->device.ip_addr);
	reg.dev_addr.net_bitlen = mask2bitlen(ntohl(eee->device.device_mask));
	reg.auth.scheme = 0; /* No auth yet */

	idx = 0;
	encode_mac(reg.edgeMac, &idx, eee->device.mac_addr);

	idx = 0;
	encode_REGISTER_SUPER(pktbuf, &idx, &cmn, &reg);

	traceEvent(TRACE_DEBUG, "send REGISTER_SUPER to %s",
	           sock_to_cstr(sockbuf, supernode));

	if (eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED)
		packet_header_encrypt(pktbuf, idx, eee->conf.header_encryption_ctx,
		                      eee->conf.header_iv_ctx,
		                      time_stamp(), pearson_hash_16(pktbuf, idx));

	/* sent = */ sendto_sock(eee->udp_sock, pktbuf, idx, supernode);
}

/* ************************************** */

/** Send a QUERY_PEER packet to the current supernode. */
static void send_query_peer( n2n_edge_t * eee,
                             const n2n_mac_t dstMac) {
  uint8_t pktbuf[N2N_PKT_BUF_SIZE];
  size_t idx;
  n2n_common_t cmn = {0};
  n2n_QUERY_PEER_t query = {{0}};

  cmn.ttl=N2N_DEFAULT_TTL;
  cmn.pc = n2n_query_peer;
  cmn.flags = 0;
  memcpy( cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE );

  idx=0;
  encode_mac( query.srcMac, &idx, eee->device.mac_addr );
  idx=0;
  encode_mac( query.targetMac, &idx, dstMac );

  idx=0;
  encode_QUERY_PEER( pktbuf, &idx, &cmn, &query );

  traceEvent( TRACE_DEBUG, "send QUERY_PEER to supernode" );

  if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED){
    packet_header_encrypt (pktbuf, idx, eee->conf.header_encryption_ctx,
                                        eee->conf.header_iv_ctx,
                                        time_stamp (), pearson_hash_16 (pktbuf, idx));
	}
    sendto_sock( eee->udp_sock, pktbuf, idx, &(eee->supernode) );
}

/** Send a REGISTER packet to another edge. */
static void send_register(n2n_edge_t * eee,
			  const n2n_sock_t * remote_peer,
			  const n2n_mac_t peer_mac) {
  uint8_t pktbuf[N2N_PKT_BUF_SIZE];
  size_t idx;
  /* ssize_t sent; */
  n2n_common_t cmn;
  n2n_REGISTER_t reg;
  n2n_sock_str_t sockbuf;

  if(!eee->conf.allow_p2p) {
    traceEvent(TRACE_DEBUG, "Skipping register as P2P is disabled");
    return;
  }

  memset(&cmn, 0, sizeof(cmn));
  memset(&reg, 0, sizeof(reg));
  cmn.ttl=N2N_DEFAULT_TTL;
  cmn.pc = n2n_register;
  cmn.flags = 0;
  memcpy(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

  idx=0;
  encode_uint32(reg.cookie, &idx, 123456789);
  idx=0;
  encode_mac(reg.srcMac, &idx, eee->device.mac_addr);

  if(peer_mac) {
    /* Can be NULL for multicast registrations */
    idx=0;
    encode_mac(reg.dstMac, &idx, peer_mac);
  }

  idx=0;
  encode_REGISTER(pktbuf, &idx, &cmn, &reg);

  traceEvent(TRACE_INFO, "Send REGISTER to %s",
	     sock_to_cstr(sockbuf, remote_peer));

  if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED)
    packet_header_encrypt (pktbuf, idx, eee->conf.header_encryption_ctx,
                                        eee->conf.header_iv_ctx,
                                        time_stamp (), pearson_hash_16 (pktbuf, idx));

  /* sent = */ sendto_sock(eee->udp_sock, pktbuf, idx, remote_peer);
}

/* ************************************** */

/** Send a REGISTER_ACK packet to a peer edge. */
static void send_register_ack(n2n_edge_t * eee,
			      const n2n_sock_t * remote_peer,
			      const n2n_REGISTER_t * reg) {
  uint8_t pktbuf[N2N_PKT_BUF_SIZE];
  size_t idx;
  /* ssize_t sent; */
  n2n_common_t cmn;
  n2n_REGISTER_ACK_t ack;
  n2n_sock_str_t sockbuf;

  if(!eee->conf.allow_p2p) {
    traceEvent(TRACE_DEBUG, "Skipping register ACK as P2P is disabled");
    return;
  }

  memset(&cmn, 0, sizeof(cmn));
  memset(&ack, 0, sizeof(reg));
  cmn.ttl=N2N_DEFAULT_TTL;
  cmn.pc = n2n_register_ack;
  cmn.flags = 0;
  memcpy(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

  memset(&ack, 0, sizeof(ack));
  memcpy(ack.cookie, reg->cookie, N2N_COOKIE_SIZE);
  memcpy(ack.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
  memcpy(ack.dstMac, reg->srcMac, N2N_MAC_SIZE);

  idx=0;
  encode_REGISTER_ACK(pktbuf, &idx, &cmn, &ack);

  traceEvent(TRACE_INFO, "send REGISTER_ACK %s",
	     sock_to_cstr(sockbuf, remote_peer));

  if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED)
    packet_header_encrypt (pktbuf, idx, eee->conf.header_encryption_ctx,
                                        eee->conf.header_iv_ctx,
                                        time_stamp (), pearson_hash_16 (pktbuf, idx));

  /* sent = */ sendto_sock(eee->udp_sock, pktbuf, idx, remote_peer);
}

/* ************************************** */

/** @brief Check to see if we should re-register with the supernode.
 *
 *  This is frequently called by the main loop.
 */
void update_supernode_reg(n2n_edge_t * eee, time_t nowTime) {
  u_int sn_idx;

  if(eee->sn_wait && (nowTime > (eee->last_register_req + (eee->conf.register_interval/10)))) {
    /* fall through */
    traceEvent(TRACE_DEBUG, "update_supernode_reg: doing fast retry.");
  } else if(nowTime < (eee->last_register_req + eee->conf.register_interval))
    return; /* Too early */

  check_join_multicast_group(eee);

  if(0 == eee->sup_attempts) {
    /* Give up on that supernode and try the next one. */
    ++(eee->sn_idx);

    if(eee->sn_idx >= eee->conf.sn_num) {
      /* Got to end of list, go back to the start. Also works for list of one entry. */
      eee->sn_idx=0;
    }

    traceEvent(TRACE_WARNING, "Supernode not responding, now trying %s", supernode_ip(eee));

    eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;
  }
  else
    --(eee->sup_attempts);

  for(sn_idx=0; sn_idx<eee->conf.sn_num; sn_idx++) {
    if(supernode2addr(&(eee->supernode), eee->conf.sn_ip_array[sn_idx]) == 0) {
      traceEvent(TRACE_INFO, "Registering with supernode [id: %u/%u][%s][attempts left %u]",
		 sn_idx+1, eee->conf.sn_num,
		 supernode_ip(eee), (unsigned int)eee->sup_attempts);

      send_register_super(eee, &(eee->supernode), sn_idx);
    }
  }

  register_with_local_peers(eee);

  eee->sn_wait=1;

  /* REVISIT: turn-on gratuitous ARP with config option. */
  /* send_grat_arps(sock_fd, is_udp_sock); */

  eee->last_register_req = nowTime;
}

/* ************************************** */

/** NOT IMPLEMENTED
 *
 *  This would send a DEREGISTER packet to a peer edge or supernode to indicate
 *  the edge is going away.
 */
static void send_deregister(n2n_edge_t * eee,
                            n2n_sock_t * remote_peer) {
  /* Marshall and send message */
}

/* ************************************** */

/** Return the IP address of the current supernode in the ring. */
static const char * supernode_ip(const n2n_edge_t * eee) {
  return (eee->conf.sn_ip_array)[eee->sn_idx];
}

/* ************************************** */

/** A PACKET has arrived containing an encapsulated ethernet datagram - usually
 *  encrypted. */
static int handle_PACKET(n2n_edge_t * eee,
			 const n2n_common_t * cmn,
			 const n2n_PACKET_t * pkt,
			 const n2n_sock_t * orig_sender,
			 uint8_t * payload,
			 size_t psize) {
  ssize_t             data_sent_len;
  uint8_t             from_supernode;
  uint8_t *           eth_payload=NULL;
  int                 retval = -1;
  time_t              now;
  ether_hdr_t *       eh;
  ipstr_t             ip_buf;

  now = time(NULL);

  traceEvent(TRACE_DEBUG, "handle_PACKET size %u transform %u",
	     (unsigned int)psize, (unsigned int)pkt->transform);
  /* hexdump(payload, psize); */

  from_supernode= cmn->flags & N2N_FLAGS_FROM_SUPERNODE;

  if(from_supernode)
    {
      if(!memcmp(pkt->dstMac, broadcast_mac, N2N_MAC_SIZE))
        ++(eee->stats.rx_sup_broadcast);

      ++(eee->stats.rx_sup);
      eee->last_sup=now;
    }
  else
    {
      ++(eee->stats.rx_p2p);
      eee->last_p2p=now;
    }

  /* Update the sender in peer table entry */
  check_peer_registration_needed(eee, from_supernode, pkt->srcMac, orig_sender);

  /* Handle transform. */
  {
    uint8_t decodebuf[N2N_PKT_BUF_SIZE];
    size_t eth_size;
    n2n_transform_t rx_transop_id;

    rx_transop_id = (n2n_transform_t)pkt->transform;
    /* optional compression is encoded in uppermost bit of transform field.
     * this is an intermediate solution to maintain compatibility until some
     * upcoming major release (3.0?) brings up changes in packet structure anyway
     * in the course of which a dedicated compression field could be spent.
     * REVISIT then. */
    uint16_t rx_compression_id;

    rx_compression_id = (uint16_t)rx_transop_id >> (8*sizeof((uint16_t)rx_transop_id)-N2N_COMPRESSION_ID_BITLEN);
    rx_transop_id &= (1 << (8*sizeof((uint16_t)rx_transop_id)-N2N_COMPRESSION_ID_BITLEN)) -1;

    if(rx_transop_id == eee->conf.transop_id) {
      uint8_t is_multicast;
      eth_payload = decodebuf;
      eh = (ether_hdr_t*)eth_payload;
      eth_size = eee->transop.rev(&eee->transop,
				  eth_payload, N2N_PKT_BUF_SIZE,
				  payload, psize, pkt->srcMac);
      ++(eee->transop.rx_cnt); /* stats */

      /* decompress if necessary */
      uint8_t * deflation_buffer = 0;
      int32_t deflated_len;
      switch (rx_compression_id) {
      case N2N_COMPRESSION_ID_NONE:
	break; // continue afterwards

      case N2N_COMPRESSION_ID_LZO:
	deflation_buffer = malloc (N2N_PKT_BUF_SIZE);
	lzo1x_decompress (eth_payload, eth_size, deflation_buffer, (lzo_uint*)&deflated_len, NULL);
	break;
#ifdef N2N_HAVE_ZSTD
      case N2N_COMPRESSION_ID_ZSTD:
	deflated_len = N2N_PKT_BUF_SIZE;
	deflation_buffer = malloc (deflated_len);
	deflated_len = (int32_t)ZSTD_decompress (deflation_buffer, deflated_len, eth_payload, eth_size);
	if(ZSTD_isError(deflated_len)) {
	  traceEvent (TRACE_ERROR, "payload decompression failed with zstd error '%s'.",
		      ZSTD_getErrorName(deflated_len));
	  free (deflation_buffer);
	  return (-1); // cannot help it
	}
	break;
#endif
      default:
	traceEvent (TRACE_ERROR, "payload decompression failed: received packet indicating unsupported %s compression.",
		    compression_str(rx_compression_id));
	return (-1); // cannot handle it
      }

      if(rx_compression_id) {
	traceEvent (TRACE_DEBUG, "payload decompression [%s]: deflated %u bytes to %u bytes",
		    compression_str(rx_compression_id), eth_size, (int)deflated_len);
	memcpy(eth_payload ,deflation_buffer, deflated_len );
	eth_size = deflated_len;
	free (deflation_buffer);
      }

      is_multicast = (is_ip6_discovery(eth_payload, eth_size) || is_ethMulticast(eth_payload, eth_size));

      if(eee->conf.drop_multicast && is_multicast) {
	traceEvent(TRACE_INFO, "Dropping RX multicast");
	return(-1);
      } else if((!eee->conf.allow_routing) && (!is_multicast)) {
	/* Check if it is a routed packet */
	if((ntohs(eh->type) == 0x0800) && (eth_size >= ETH_FRAMESIZE + IP4_MIN_SIZE)) {
	  uint32_t *dst = (uint32_t*)&eth_payload[ETH_FRAMESIZE + IP4_DSTOFFSET];
	  uint8_t *dst_mac = (uint8_t*)eth_payload;

	  /* Note: all elements of the_ip are in network order */
	  if(!memcmp(dst_mac, broadcast_mac, N2N_MAC_SIZE))
	    traceEvent(TRACE_DEBUG, "Broadcast packet [%s]",
		       intoa(ntohl(*dst), ip_buf, sizeof(ip_buf)));
	  else if((*dst != eee->device.ip_addr)) {
	    /* This is a packet that needs to be routed */
	    traceEvent(TRACE_INFO, "Discarding routed packet [%s]",
		       intoa(ntohl(*dst), ip_buf, sizeof(ip_buf)));
	    return(-1);
	  } else {
	    /* This packet is directed to us */
	    /* traceEvent(TRACE_INFO, "Sending non-routed packet"); */
	  }
	}
      }

      if(eee->cb.packet_from_peer) {
	uint16_t tmp_eth_size = eth_size;
	if(eee->cb.packet_from_peer(eee, orig_sender, eth_payload, &tmp_eth_size) == N2N_DROP) {
	  traceEvent(TRACE_DEBUG, "DROP packet %u", (unsigned int)eth_size);

	  return(0);
	}
	eth_size = tmp_eth_size;
      }

      /* Write ethernet packet to tap device. */
      traceEvent(TRACE_DEBUG, "sending to TAP %u", (unsigned int)eth_size);
      data_sent_len = tuntap_write(&(eee->device), eth_payload, eth_size);

      if(data_sent_len == eth_size)
	{
	  retval = 0;
	}
    }
    else
      {
	traceEvent(TRACE_ERROR, "invalid transop ID: expected %s(%u), got %s(%u)",
		   transop_str(eee->conf.transop_id), eee->conf.transop_id,
		   transop_str(rx_transop_id), rx_transop_id);
      }
  }

  return retval;
}

/* ************************************** */

/** Read a datagram from the management UDP socket and take appropriate
 *  action. */
static void readFromMgmtSocket(n2n_edge_t * eee, int * keep_running) {
  uint8_t             udp_buf[N2N_PKT_BUF_SIZE];      /* Compete UDP packet */
  ssize_t             recvlen;
  /* ssize_t             sendlen; */
  struct sockaddr_in  sender_sock;
  socklen_t           i;
  size_t              msg_len;
  time_t              now;

  now = time(NULL);
  i = sizeof(sender_sock);
  recvlen = recvfrom(eee->udp_mgmt_sock, udp_buf, N2N_PKT_BUF_SIZE, 0/*flags*/,
		     (struct sockaddr *)&sender_sock, (socklen_t*)&i);

  if(recvlen < 0)
    {
      traceEvent(TRACE_ERROR, "mgmt recvfrom failed with %s", strerror(errno));

      return; /* failed to receive data from UDP */
    }

  if(recvlen >= 4)
    {
      if(0 == memcmp(udp_buf, "stop", 4))
        {
	  traceEvent(TRACE_ERROR, "stop command received.");
	  *keep_running = 0;
	  return;
        }

      if(0 == memcmp(udp_buf, "help", 4))
        {
	  msg_len=0;
	  setTraceLevel(getTraceLevel()+1);

	  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
			      "Help for edge management console:\n"
			      "  stop    Gracefully exit edge\n"
			      "  help    This help message\n"
			      "  +verb   Increase verbosity of logging\n"
			      "  -verb   Decrease verbosity of logging\n"
			      "  <enter> Display statistics\n\n");

	  sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0/*flags*/,
		 (struct sockaddr *)&sender_sock, sizeof(struct sockaddr_in));

	  return;
        }

    }

  if(recvlen >= 5)
    {
      if(0 == memcmp(udp_buf, "+verb", 5))
        {
	  msg_len=0;
	  setTraceLevel(getTraceLevel()+1);

	  traceEvent(TRACE_ERROR, "+verb traceLevel=%u", (unsigned int)getTraceLevel());
	  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
			      "> +OK traceLevel=%u\n", (unsigned int)getTraceLevel());

	  sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0/*flags*/,
		 (struct sockaddr *)&sender_sock, sizeof(struct sockaddr_in));

	  return;
        }

      if(0 == memcmp(udp_buf, "-verb", 5))
        {
	  msg_len=0;

	  if(getTraceLevel() > 0)
            {
	      setTraceLevel(getTraceLevel()-1);
	      msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
				  "> -OK traceLevel=%u\n", getTraceLevel());
            }
	  else
            {
	      msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
				  "> -NOK traceLevel=%u\n", getTraceLevel());
            }

	  traceEvent(TRACE_ERROR, "-verb traceLevel=%u", (unsigned int)getTraceLevel());

	  sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0/*flags*/,
		 (struct sockaddr *)&sender_sock, sizeof(struct sockaddr_in));
	  return;
        }
    }

  traceEvent(TRACE_DEBUG, "mgmt status rq");

  msg_len=0;
  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
		      "Statistics for edge\n");

  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
		      "uptime %lu\n",
		      time(NULL) - eee->start_time);

  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
		      "paths  super:%u,%u p2p:%u,%u\n",
		      (unsigned int)eee->stats.tx_sup,
		      (unsigned int)eee->stats.rx_sup,
		      (unsigned int)eee->stats.tx_p2p,
		      (unsigned int)eee->stats.rx_p2p);

  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
		      "transop |%6u|%6u|\n",
		      (unsigned int)eee->transop.tx_cnt,
		      (unsigned int)eee->transop.rx_cnt);

  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
		      "peers  pend:%u full:%u\n",
		      HASH_COUNT(eee->pending_peers),
		      HASH_COUNT(eee->known_peers));

  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
		      "last super:%lu(%ld sec ago) p2p:%lu(%ld sec ago)\n",
		      eee->last_sup, (now-eee->last_sup), eee->last_p2p,
		      (now-eee->last_p2p));

  traceEvent(TRACE_DEBUG, "mgmt status sending: %s", udp_buf);


  /* sendlen = */ sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0/*flags*/,
			 (struct sockaddr *)&sender_sock, sizeof(struct sockaddr_in));
}

/* ************************************** */

static int check_query_peer_info(n2n_edge_t *eee, time_t now, n2n_mac_t mac) {
  struct peer_info *scan;

  HASH_FIND_PEER(eee->pending_peers, mac, scan);

  if(!scan) {
    scan = calloc(1, sizeof(struct peer_info));

    memcpy(scan->mac_addr, mac, N2N_MAC_SIZE);
    scan->timeout = REGISTER_SUPER_INTERVAL_DFL; /* TODO: should correspond to the peer supernode registration timeout */
    scan->last_seen = now; /* Don't change this it marks the pending peer for removal. */
    scan->last_valid_time_stamp = initial_time_stamp ();

    HASH_ADD_PEER(eee->pending_peers, scan);
  }

  if(now - scan->last_sent_query > REGISTER_SUPER_INTERVAL_DFL) {
    send_query_peer(eee, scan->mac_addr);
    scan->last_sent_query = now;
    return(0);
  }

  return(1);
}

/* ************************************** */

/* @return 1 if destination is a peer, 0 if destination is supernode */
static int find_peer_destination(n2n_edge_t * eee,
                                 n2n_mac_t mac_address,
                                 n2n_sock_t * destination) {
  struct peer_info *scan;
  macstr_t mac_buf;
  n2n_sock_str_t sockbuf;
  int retval=0;
  time_t now = time(NULL);

  if(!memcmp(mac_address, broadcast_mac, N2N_MAC_SIZE)) {
    traceEvent(TRACE_DEBUG, "Broadcast destination peer, using supernode");
    memcpy(destination, &(eee->supernode), sizeof(struct sockaddr_in));
    return(0);
  }

  traceEvent(TRACE_DEBUG, "Searching destination peer for MAC %02X:%02X:%02X:%02X:%02X:%02X",
	     mac_address[0] & 0xFF, mac_address[1] & 0xFF, mac_address[2] & 0xFF,
	     mac_address[3] & 0xFF, mac_address[4] & 0xFF, mac_address[5] & 0xFF);

  HASH_FIND_PEER(eee->known_peers, mac_address, scan);

  if(scan && (scan->last_seen > 0)) {
    if((now - scan->last_p2p) >= (scan->timeout / 2)) {
      /* Too much time passed since we saw the peer, need to register again
       * since the peer address may have changed. */
      traceEvent(TRACE_DEBUG, "Refreshing idle known peer");
      HASH_DEL(eee->known_peers, scan);
      free(scan);
      /* NOTE: registration will be performed upon the receival of the next response packet */
    } else {
      /* Valid known peer found */
      memcpy(destination, &scan->sock, sizeof(n2n_sock_t));
      retval=1;
    }
  }

  if(retval == 0) {
    memcpy(destination, &(eee->supernode), sizeof(struct sockaddr_in));
    traceEvent(TRACE_DEBUG, "P2P Peer [MAC=%02X:%02X:%02X:%02X:%02X:%02X] not found, using supernode",
	       mac_address[0] & 0xFF, mac_address[1] & 0xFF, mac_address[2] & 0xFF,
	       mac_address[3] & 0xFF, mac_address[4] & 0xFF, mac_address[5] & 0xFF);

    check_query_peer_info(eee, now, mac_address);
  }

  traceEvent(TRACE_DEBUG, "find_peer_address (%s) -> [%s]",
	     macaddr_str(mac_buf, mac_address),
	     sock_to_cstr(sockbuf, destination));

  return retval;
}

/* ***************************************************** */

/** Send an ecapsulated ethernet PACKET to a destination edge or broadcast MAC
 *  address. */
static int send_packet(n2n_edge_t * eee,
		       n2n_mac_t dstMac,
		       const uint8_t * pktbuf,
		       size_t pktlen) {
  int is_p2p;
  /*ssize_t s; */
  n2n_sock_str_t sockbuf;
  n2n_sock_t destination;
  macstr_t mac_buf;

  /* hexdump(pktbuf, pktlen); */

  is_p2p = find_peer_destination(eee, dstMac, &destination);

  if(is_p2p)
    ++(eee->stats.tx_p2p);
  else {
    ++(eee->stats.tx_sup);

    if(!memcmp(dstMac, broadcast_mac, N2N_MAC_SIZE))
      ++(eee->stats.tx_sup_broadcast);
  }

  traceEvent(TRACE_INFO, "Tx PACKET to %s (dest=%s) [%u B]",
	     sock_to_cstr(sockbuf, &destination),
	     macaddr_str(mac_buf, dstMac), pktlen);

  /* s = */ sendto_sock(eee->udp_sock, pktbuf, pktlen, &destination);

  return 0;
}

/* ************************************** */

/** A layer-2 packet was received at the tunnel and needs to be sent via UDP. */
void edge_send_packet2net(n2n_edge_t * eee,
			  uint8_t *tap_pkt, size_t len) {
  ipstr_t ip_buf;
  n2n_mac_t destMac;

  n2n_common_t cmn;
  n2n_PACKET_t pkt;

  uint8_t pktbuf[N2N_PKT_BUF_SIZE];
  size_t idx=0;
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
	traceEvent(TRACE_INFO, "Discarding routed packet [%s]",
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

  memset(&cmn, 0, sizeof(cmn));
  cmn.ttl = N2N_DEFAULT_TTL;
  cmn.pc = n2n_packet;
  cmn.flags=0; /* no options, not from supernode, no socket */
  memcpy(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

  memset(&pkt, 0, sizeof(pkt));
  memcpy(pkt.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
  memcpy(pkt.dstMac, destMac, N2N_MAC_SIZE);

  pkt.sock.family=0; /* do not encode sock */
  pkt.transform = tx_transop_idx;

  // compression needs to be tried before encode_PACKET is called for compression indication gets encoded there
  pkt.compression = N2N_COMPRESSION_ID_NONE;

  if(eee->conf.compression) {
    uint8_t * compression_buffer = NULL;
    int32_t  compression_len;

    switch (eee->conf.compression) {
    case N2N_COMPRESSION_ID_LZO:
      compression_buffer = malloc (len + len / 16 + 64 + 3);
      if(lzo1x_1_compress(tap_pkt, len, compression_buffer, (lzo_uint*)&compression_len, wrkmem) == LZO_E_OK) {
	if(compression_len < len) {
	  pkt.compression = N2N_COMPRESSION_ID_LZO;
	}
      }
      break;
#ifdef N2N_HAVE_ZSTD
    case N2N_COMPRESSION_ID_ZSTD:
      compression_len = N2N_PKT_BUF_SIZE + 128;
      compression_buffer = malloc (compression_len); // leaves enough room, for exact size call compression_len = ZSTD_compressBound (len); (slower)
      compression_len = (int32_t)ZSTD_compress(compression_buffer, compression_len, tap_pkt, len, ZSTD_COMPRESSION_LEVEL) ;
      if(!ZSTD_isError(compression_len)) {
	if(compression_len < len) {
	  pkt.compression = N2N_COMPRESSION_ID_ZSTD;
	}
      } else {
	traceEvent (TRACE_ERROR, "payload compression failed with zstd error '%s'.",
		    ZSTD_getErrorName(compression_len));
	free (compression_buffer);
	// continue with unset without pkt.compression --> will send uncompressed
      }
      break;
#endif
    default:
      break;
    }

    if(pkt.compression) {
      traceEvent (TRACE_DEBUG, "payload compression [%s]: compressed %u bytes to %u bytes\n",
		  compression_str(pkt.compression), len, compression_len);

      memcpy (tap_pkt, compression_buffer, compression_len);
      len = compression_len;
      free (compression_buffer);
    }
  }
  /* optional compression is encoded in uppermost bits of transform field.
   * this is an intermediate solution to maintain compatibility until some
   * upcoming major release (3.0?) brings up changes in packet structure anyway
   * in the course of which a dedicated compression field could be spent.
   * REVISIT then. */
  pkt.transform = pkt.transform | (pkt.compression << (8*sizeof(pkt.transform)-N2N_COMPRESSION_ID_BITLEN));

  idx=0;
  encode_PACKET(pktbuf, &idx, &cmn, &pkt);

  uint16_t headerIdx = idx;

  idx += eee->transop.fwd(&eee->transop,
			  pktbuf+idx, N2N_PKT_BUF_SIZE-idx,
			  tap_pkt, len, pkt.dstMac);

  traceEvent(TRACE_DEBUG, "Encode %u B PACKET [%u B data, %u B overhead] transform %u",
	     (u_int)idx, (u_int)len, (u_int)(idx-len), tx_transop_idx);

  if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED)
    packet_header_encrypt (pktbuf, headerIdx, eee->conf.header_encryption_ctx,
                                              eee->conf.header_iv_ctx,
                                              time_stamp (), pearson_hash_16 (pktbuf, idx));

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
 *  corresponding packet to the cooked socket.
 */
void edge_read_from_tap(n2n_edge_t * eee) {
  /* tun -> remote */
  uint8_t             eth_pkt[N2N_PKT_BUF_SIZE];
  macstr_t            mac_buf;
  ssize_t             len;

  len = tuntap_read( &(eee->device), eth_pkt, N2N_PKT_BUF_SIZE );
  if((len <= 0) || (len > N2N_PKT_BUF_SIZE))
    {
      traceEvent(TRACE_WARNING, "read()=%d [%d/%s]",
		 (signed int)len, errno, strerror(errno));
      traceEvent(TRACE_WARNING, "TAP I/O operation aborted, restart later.");
      sleep(3);
      tuntap_close(&(eee->device));
      tuntap_open(&(eee->device), eee->tuntap_priv_conf.tuntap_dev_name, eee->tuntap_priv_conf.ip_mode, eee->tuntap_priv_conf.ip_addr,
		  eee->tuntap_priv_conf.netmask, eee->tuntap_priv_conf.device_mac, eee->tuntap_priv_conf.mtu);
    }
  else
    {
      const uint8_t * mac = eth_pkt;
      traceEvent(TRACE_DEBUG, "### Rx TAP packet (%4d) for %s",
		 (signed int)len, macaddr_str(mac_buf, mac));

      if(eee->conf.drop_multicast &&
	 (is_ip6_discovery(eth_pkt, len) ||
	  is_ethMulticast(eth_pkt, len)
	  )
	 )
        {
	  traceEvent(TRACE_INFO, "Dropping TX multicast");
        }
      else
        {
	  if(eee->cb.packet_from_tap) {
	    uint16_t tmp_len = len;
	    if(eee->cb.packet_from_tap(eee, eth_pkt, &tmp_len) == N2N_DROP) {
	      traceEvent(TRACE_DEBUG, "DROP packet %u", (unsigned int)len);

	      return;
	    }
	    len = tmp_len;
	  }

	  edge_send_packet2net(eee, eth_pkt, len);
        }
    }
}

/* ************************************** */


/* ************************************** */

/** Read a datagram from the main UDP socket to the internet. */
void readFromIPSocket(n2n_edge_t * eee, int in_sock) {
  n2n_common_t        cmn; /* common fields in the packet header */

  n2n_sock_str_t      sockbuf1;
  n2n_sock_str_t      sockbuf2; /* don't clobber sockbuf1 if writing two addresses to trace */
  macstr_t            mac_buf1;
  macstr_t            mac_buf2;

  uint8_t             udp_buf[N2N_PKT_BUF_SIZE];      /* Compete UDP packet */
  ssize_t             recvlen;
  size_t              rem;
  size_t              idx;
  size_t              msg_type;
  uint8_t             from_supernode;
  struct sockaddr_in  sender_sock;
  n2n_sock_t          sender;
  n2n_sock_t *        orig_sender=NULL;
  time_t              now=0;
  uint64_t 	      stamp = 0;

  size_t              i;

  i = sizeof(sender_sock);
  recvlen = recvfrom(in_sock, udp_buf, N2N_PKT_BUF_SIZE, 0/*flags*/,
		     (struct sockaddr *)&sender_sock, (socklen_t*)&i);

  if(recvlen < 0) {
#ifdef WIN32
    if(WSAGetLastError() != WSAECONNRESET)
#endif
      {
	traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", recvlen, errno, strerror(errno));
#ifdef WIN32
	traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
      }

    return; /* failed to receive data from UDP */
  }

  /* REVISIT: when UDP/IPv6 is supported we will need a flag to indicate which
   * IP transport version the packet arrived on. May need to UDP sockets. */
  sender.family = AF_INET; /* UDP socket was opened PF_INET v4 */
  sender.port = ntohs(sender_sock.sin_port);
  memcpy(&(sender.addr.v4), &(sender_sock.sin_addr.s_addr), IPV4_SIZE);

  /* The packet may not have an orig_sender socket spec. So default to last
   * hop as sender. */
  orig_sender=&sender;

  traceEvent(TRACE_DEBUG, "### Rx N2N UDP (%d) from %s",
	     (signed int)recvlen, sock_to_cstr(sockbuf1, &sender));

  if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
    uint16_t checksum = 0;
    if( packet_header_decrypt (udp_buf, recvlen, (char *)eee->conf.community_name, eee->conf.header_encryption_ctx,
                               eee->conf.header_iv_ctx,
                               &stamp, &checksum) == 0) {
      traceEvent(TRACE_DEBUG, "readFromIPSocket failed to decrypt header.");
      return;
    }

    // time stamp verification follows in the packet specific section as it requires to determine the
    // sender from the hash list by its MAC, or the packet might be from the supernode, this all depends
    // on packet type, path taken (via supernode) and packet structure (MAC is not always in the same place)

    if (checksum != pearson_hash_16 (udp_buf, recvlen)) {
      traceEvent(TRACE_DEBUG, "readFromIPSocket dropped packet due to checksum error.");
      return;
    }
  }

  /* hexdump(udp_buf, recvlen); */

  rem = recvlen; /* Counts down bytes of packet to protect against buffer overruns. */
  idx = 0; /* marches through packet header as parts are decoded. */
  if(decode_common(&cmn, udp_buf, &rem, &idx) < 0)
    {
      traceEvent(TRACE_ERROR, "Failed to decode common section in N2N_UDP");
      return; /* failed to decode packet */
    }

  now = time(NULL);

  msg_type = cmn.pc; /* packet code */
  from_supernode= cmn.flags & N2N_FLAGS_FROM_SUPERNODE;

  if(0 == memcmp(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE)) {
    switch(msg_type) {
    case MSG_TYPE_PACKET:
      {
	  /* process PACKET - most frequent so first in list. */
	  n2n_PACKET_t pkt;

	  decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx);

          if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
            if(!find_peer_time_stamp_and_verify (eee, from_supernode, pkt.srcMac, stamp)) {
              traceEvent(TRACE_DEBUG, "readFromIPSocket dropped PACKET due to time stamp error.");
              return;
            }
          }

	  if(is_valid_peer_sock(&pkt.sock))
	    orig_sender = &(pkt.sock);

	  if(!from_supernode) {
	    /* This is a P2P packet from the peer. We purge a pending
	     * registration towards the possibly nat-ted peer address as we now have
	     * a valid channel. We still use check_peer_registration_needed in
	     * handle_PACKET to double check this.
	     */
	    traceEvent(TRACE_DEBUG, "Got P2P packet");
      traceEvent(TRACE_DEBUG, "[P2P] Rx data from %s [%u B]", sock_to_cstr(sockbuf1, &sender), recvlen);
      find_and_remove_peer(&eee->pending_peers, pkt.srcMac);
	  }
    else {
      /* [PsP] : edge Peer->Supernode->edge Peer */
      traceEvent(TRACE_DEBUG, "[PsP] Rx data from %s (Via=%s) [%u B]",
                 sock_to_cstr(sockbuf2, orig_sender), sock_to_cstr(sockbuf1, &sender), recvlen);
    }

	handle_PACKET(eee, &cmn, &pkt, orig_sender, udp_buf+idx, recvlen-idx);
	break;
      }
    case MSG_TYPE_REGISTER:
      {
	/* Another edge is registering with us */
	n2n_REGISTER_t reg;
	int via_multicast;

	decode_REGISTER(&reg, &cmn, udp_buf, &rem, &idx);

          if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
            if(!find_peer_time_stamp_and_verify (eee, from_supernode, reg.srcMac, stamp)) {
              traceEvent(TRACE_DEBUG, "readFromIPSocket dropped REGISTER due to time stamp error.");
              return;
            }
          }

	  if(is_valid_peer_sock(&reg.sock))
	    orig_sender = &(reg.sock);

	via_multicast = !memcmp(reg.dstMac, null_mac, N2N_MAC_SIZE);

	if(via_multicast && !memcmp(reg.srcMac, eee->device.mac_addr, N2N_MAC_SIZE)) {
	  traceEvent(TRACE_DEBUG, "Skipping REGISTER from self");
	  break;
	}

	if(!via_multicast && memcmp(reg.dstMac, eee->device.mac_addr, N2N_MAC_SIZE)) {
	  traceEvent(TRACE_DEBUG, "Skipping REGISTER for other peer");
	  break;
	}

	if(!from_supernode) {
	  /* This is a P2P registration from the peer. We purge a pending
	   * registration towards the possibly nat-ted peer address as we now have
	   * a valid channel. We still use check_peer_registration_needed below
	   * to double check this.
	   */
	  traceEvent(TRACE_DEBUG, "Got P2P register");
    traceEvent(TRACE_INFO, "[P2P] Rx REGISTER from %s", sock_to_cstr(sockbuf1, &sender));
    find_and_remove_peer(&eee->pending_peers, reg.srcMac);

	  /* NOTE: only ACK to peers */
	  send_register_ack(eee, orig_sender, &reg);
	}
  else {
    traceEvent(TRACE_INFO, "[PsP] Rx REGISTER src=%s dst=%s from sn=%s (edge:%s)",
               macaddr_str(mac_buf1, reg.srcMac), macaddr_str(mac_buf2, reg.dstMac),
               sock_to_cstr(sockbuf1, &sender), sock_to_cstr(sockbuf2, orig_sender));
  }

	check_peer_registration_needed(eee, from_supernode, reg.srcMac, orig_sender);
	break;
      }
    case MSG_TYPE_REGISTER_ACK:
      {
	/* Peer edge is acknowledging our register request */
	n2n_REGISTER_ACK_t ra;

	decode_REGISTER_ACK(&ra, &cmn, udp_buf, &rem, &idx);

          if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
            if(!find_peer_time_stamp_and_verify (eee, !definitely_from_supernode, ra.srcMac, stamp)) {
              traceEvent(TRACE_DEBUG, "readFromIPSocket dropped REGISTER_ACK due to time stamp error.");
              return;
            }
          }

	  if(is_valid_peer_sock(&ra.sock))
	    orig_sender = &(ra.sock);

	traceEvent(TRACE_INFO, "Rx REGISTER_ACK src=%s dst=%s from peer %s (%s)",
		   macaddr_str(mac_buf1, ra.srcMac),
		   macaddr_str(mac_buf2, ra.dstMac),
		   sock_to_cstr(sockbuf1, &sender),
		   sock_to_cstr(sockbuf2, orig_sender));

	peer_set_p2p_confirmed(eee, ra.srcMac, &sender, now);
	break;
      }
    case MSG_TYPE_REGISTER_SUPER_ACK:
      {
	      in_addr_t net;
	      char * ip_str = NULL;
	      n2n_REGISTER_SUPER_ACK_t ra;

	      memset(&ra, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));

	      // Indicates successful connection between the edge and SN nodes
        static int bTrace = 1;
        if (bTrace)
        {
          traceEvent(TRACE_NORMAL, "[OK] Edge Peer <<< ================ >>> Super Node");
          bTrace = 0;
        }


	  if(eee->sn_wait)
            {
	      decode_REGISTER_SUPER_ACK(&ra, &cmn, udp_buf, &rem, &idx);

              if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
                if(!find_peer_time_stamp_and_verify (eee, definitely_from_supernode, null_mac, stamp)) {
                  traceEvent(TRACE_DEBUG, "readFromIPSocket dropped REGISTER_SUPER_ACK due to time stamp error.");
                  return;
                }
              }

	      if(is_valid_peer_sock(&ra.sock))
		  orig_sender = &(ra.sock);

	      traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK myMAC=%s [%s] (external %s). Attempts %u",
			 macaddr_str(mac_buf1, ra.edgeMac),
			 sock_to_cstr(sockbuf1, &sender),
			 sock_to_cstr(sockbuf2, orig_sender),
			 (unsigned int)eee->sup_attempts);

             if(memcmp(ra.edgeMac, eee->device.mac_addr, N2N_MAC_SIZE)) {
               traceEvent(TRACE_INFO, "readFromIPSocket dropped REGISTER_SUPER_ACK due to wrong addressing.");
	       return;
             }

	      if(0 == memcmp(ra.cookie, eee->last_cookie, N2N_COOKIE_SIZE))
                {
		  if(ra.num_sn > 0)
                    {
		      traceEvent(TRACE_NORMAL, "Rx REGISTER_SUPER_ACK backup supernode at %s",
				 sock_to_cstr(sockbuf1, &(ra.sn_bak)));
                    }

		  eee->last_sup = now;
		  eee->sn_wait=0;
		  eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS; /* refresh because we got a response */
            if (eee->conf.tuntap_ip_mode == TUNTAP_IP_MODE_SN_ASSIGN) {
                if ((ra.dev_addr.net_addr != 0) && (ra.dev_addr.net_bitlen != 0)) {
	                net = htonl(ra.dev_addr.net_addr);
	                if ((ip_str = inet_ntoa(*(struct in_addr *) &net)) != NULL) {
		                strncpy(eee->tuntap_priv_conf.ip_addr, ip_str,
		                        N2N_NETMASK_STR_SIZE);
	                }
	                net = htonl(bitlen2mask(ra.dev_addr.net_bitlen));
	                if ((ip_str = inet_ntoa(*(struct in_addr *) &net)) != NULL) {
		                strncpy(eee->tuntap_priv_conf.netmask, ip_str,
		                        N2N_NETMASK_STR_SIZE);
	                }
                }
            }

		  if(eee->cb.sn_registration_updated)
		    eee->cb.sn_registration_updated(eee, now, &sender);

		  /* NOTE: the register_interval should be chosen by the edge node
		   * based on its NAT configuration. */
		  //eee->conf.register_interval = ra.lifetime;
                }
	      else
                {
		  traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK with wrong or old cookie.");
                }
            }
	  else
            {
	      traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK with no outstanding REGISTER_SUPER.");
            }
	  break;
      }
      case MSG_TYPE_PEER_INFO: {
        n2n_PEER_INFO_t pi;
        struct peer_info *  scan;
        decode_PEER_INFO( &pi, &cmn, udp_buf, &rem, &idx );

        if(eee->conf.header_encryption == HEADER_ENCRYPTION_ENABLED) {
          if(!find_peer_time_stamp_and_verify (eee, definitely_from_supernode, null_mac, stamp)) {
            traceEvent(TRACE_DEBUG, "readFromIPSocket dropped PEER_INFO due to time stamp error.");
            return;
          }
        }

        if(!is_valid_peer_sock(&pi.sock)) {
          traceEvent(TRACE_DEBUG, "Skip invalid PEER_INFO %s [%s]",
                     sock_to_cstr(sockbuf1, &pi.sock),
                     macaddr_str(mac_buf1, pi.mac) );
          break;
        }

	  HASH_FIND_PEER(eee->pending_peers, pi.mac, scan);
	  if(scan) {
            scan->sock = pi.sock;
            traceEvent(TRACE_INFO, "Rx PEER_INFO for %s: is at %s",
                       macaddr_str(mac_buf1, pi.mac),
                       sock_to_cstr(sockbuf1, &pi.sock));
            send_register(eee, &scan->sock, scan->mac_addr);
	  } else {
            traceEvent(TRACE_INFO, "Rx PEER_INFO unknown peer %s",
                       macaddr_str(mac_buf1, pi.mac) );
	  }

	  break;
	}
    default:
      /* Not a known message type */
      traceEvent(TRACE_WARNING, "Unable to handle packet type %d: ignored", (signed int)msg_type);
      return;
    } /* switch(msg_type) */
  } else if(from_supernode) /* if(community match) */
    traceEvent(TRACE_WARNING, "Received packet with unknown community");
  else
    traceEvent(TRACE_INFO, "Ignoring packet with unknown community");
}

/* ************************************** */

void print_edge_stats(const n2n_edge_t *eee) {
  const struct n2n_edge_stats *s = &eee->stats;

  traceEvent(TRACE_NORMAL, "**********************************");
  traceEvent(TRACE_NORMAL, "Packet stats:");
  traceEvent(TRACE_NORMAL, "    TX P2P: %u pkts", s->tx_p2p);
  traceEvent(TRACE_NORMAL, "    RX P2P: %u pkts", s->rx_p2p);
  traceEvent(TRACE_NORMAL, "    TX Supernode: %u pkts (%u broadcast)", s->tx_sup, s->tx_sup_broadcast);
  traceEvent(TRACE_NORMAL, "    RX Supernode: %u pkts (%u broadcast)", s->rx_sup, s->rx_sup_broadcast);
  traceEvent(TRACE_NORMAL, "**********************************");
}

/* ************************************** */

int run_edge_loop(n2n_edge_t * eee, int *keep_running) {
  size_t numPurged;
  time_t lastIfaceCheck=0;
  time_t lastTransop=0;
  time_t last_purge_known = 0;
  time_t last_purge_pending = 0;

#ifdef WIN32
  struct tunread_arg arg;
  arg.eee = eee;
  arg.keep_running = keep_running;
  HANDLE tun_read_thread = startTunReadThread(&arg);
#endif

  *keep_running = 1;
  update_supernode_reg(eee, time(NULL));

  /* Main loop
   *
   * select() is used to wait for input on either the TAP fd or the UDP/TCP
   * socket. When input is present the data is read and processed by either
   * readFromIPSocket() or edge_read_from_tap()
   */

  while(*keep_running) {
    int rc, max_sock = 0;
    fd_set socket_mask;
    struct timeval wait_time;
    time_t nowTime;

    FD_ZERO(&socket_mask);
    FD_SET(eee->udp_sock, &socket_mask);
    FD_SET(eee->udp_mgmt_sock, &socket_mask);
    max_sock = max(eee->udp_sock, eee->udp_mgmt_sock);

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    FD_SET(eee->udp_multicast_sock, &socket_mask);
    max_sock = max(eee->udp_sock, eee->udp_multicast_sock);
#endif

#ifndef WIN32
    FD_SET(eee->device.fd, &socket_mask);
    max_sock = max(max_sock, eee->device.fd);
#endif

    wait_time.tv_sec = SOCKET_TIMEOUT_INTERVAL_SECS; wait_time.tv_usec = 0;

    rc = select(max_sock+1, &socket_mask, NULL, NULL, &wait_time);
    nowTime=time(NULL);

    /* Make sure ciphers are updated before the packet is treated. */
    if((nowTime - lastTransop) > TRANSOP_TICK_INTERVAL) {
      lastTransop = nowTime;

      eee->transop.tick(&eee->transop, nowTime);
    }

    if(rc > 0) {
      /* Any or all of the FDs could have input; check them all. */

      if(FD_ISSET(eee->udp_sock, &socket_mask)) {
	/* Read a cooked socket from the internet socket (unicast). Writes on the TAP
	 * socket. */
	readFromIPSocket(eee, eee->udp_sock);
      }


#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
      if(FD_ISSET(eee->udp_multicast_sock, &socket_mask)) {
	/* Read a cooked socket from the internet socket (multicast). Writes on the TAP
	 * socket. */
	traceEvent(TRACE_DEBUG, "Received packet from multicast socket");
	readFromIPSocket(eee, eee->udp_multicast_sock);
      }
#endif

      if(FD_ISSET(eee->udp_mgmt_sock, &socket_mask)) {
	/* Read a cooked socket from the internet socket. Writes on the TAP
	 * socket. */
	readFromMgmtSocket(eee, keep_running);

	if(!(*keep_running))
	  break;
      }

#ifndef WIN32
      if(FD_ISSET(eee->device.fd, &socket_mask)) {
	/* Read an ethernet frame from the TAP socket. Write on the IP
	 * socket. */
	edge_read_from_tap(eee);
      }
#endif
    }

    /* Finished processing select data. */
    update_supernode_reg(eee, nowTime);

    numPurged =  purge_expired_registrations(&eee->known_peers, &last_purge_known);
    numPurged += purge_expired_registrations(&eee->pending_peers, &last_purge_pending);

    if(numPurged > 0) {
      traceEvent(TRACE_INFO, "%u peers removed. now: pending=%u, operational=%u",
		 numPurged,
		 HASH_COUNT(eee->pending_peers),
		 HASH_COUNT(eee->known_peers));
    }

    if((eee->conf.tuntap_ip_mode == TUNTAP_IP_MODE_DHCP) &&
       ((nowTime - lastIfaceCheck) > IFACE_UPDATE_INTERVAL)) {
      uint32_t old_ip = eee->device.ip_addr;

      traceEvent(TRACE_NORMAL, "Re-checking dynamic IP address.");
      tuntap_get_address(&(eee->device));
      lastIfaceCheck = nowTime;

      if((old_ip != eee->device.ip_addr) && eee->cb.ip_address_changed)
	eee->cb.ip_address_changed(eee, old_ip, eee->device.ip_addr);
    }

    if (eee->cb.main_loop_period)
      eee->cb.main_loop_period(eee, nowTime);

  } /* while */

#ifdef WIN32
  WaitForSingleObject(tun_read_thread, INFINITE);
#endif

  send_deregister(eee, &(eee->supernode));

  closesocket(eee->udp_sock);

  return(0);
}

/* ************************************** */

/** Deinitialise the edge and deallocate any owned memory. */
void edge_term(n2n_edge_t * eee) {
  if(eee->udp_sock >= 0)
    closesocket(eee->udp_sock);

  if(eee->udp_mgmt_sock >= 0)
    closesocket(eee->udp_mgmt_sock);

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
  if(eee->udp_multicast_sock >= 0)
    closesocket(eee->udp_multicast_sock);
#endif

  clear_peer_list(&eee->pending_peers);
  clear_peer_list(&eee->known_peers);

  eee->transop.deinit(&eee->transop);

  edge_cleanup_routes(eee);

  closeTraceFile();

  free(eee);
}

/* ************************************** */

static int edge_init_sockets(n2n_edge_t *eee, int udp_local_port, int mgmt_port, uint8_t tos) {
  int sockopt;

  if(udp_local_port > 0)
    traceEvent(TRACE_NORMAL, "Binding to local port %d", udp_local_port);

  eee->udp_sock = open_socket(udp_local_port, 1 /* bind ANY */);
  if(eee->udp_sock < 0) {
    traceEvent(TRACE_ERROR, "Failed to bind main UDP port %u", udp_local_port);
    return(-1);
  }

  if(tos) {
    /* https://www.tucny.com/Home/dscp-tos */
    sockopt = tos;

    if(setsockopt(eee->udp_sock, IPPROTO_IP, IP_TOS, (char *)&sockopt, sizeof(sockopt)) == 0)
      traceEvent(TRACE_NORMAL, "TOS set to 0x%x", tos);
    else
      traceEvent(TRACE_ERROR, "Could not set TOS 0x%x[%d]: %s", tos, errno, strerror(errno));
  }

#ifdef IP_PMTUDISC_DO
  sockopt = (eee->conf.disable_pmtu_discovery) ? IP_PMTUDISC_DONT : IP_PMTUDISC_DO;

  if(setsockopt(eee->udp_sock, IPPROTO_IP, IP_MTU_DISCOVER, &sockopt, sizeof(sockopt)) < 0)
    traceEvent(TRACE_WARNING, "Could not %s PMTU discovery[%d]: %s",
	       (eee->conf.disable_pmtu_discovery) ? "disable" : "enable", errno, strerror(errno));
  else
    traceEvent(TRACE_DEBUG, "PMTU discovery %s", (eee->conf.disable_pmtu_discovery) ? "disabled" : "enabled");
#endif

  eee->udp_mgmt_sock = open_socket(mgmt_port, 0 /* bind LOOPBACK */);
  if(eee->udp_mgmt_sock < 0) {
    traceEvent(TRACE_ERROR, "Failed to bind management UDP port %u", mgmt_port);
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

  eee->udp_multicast_sock = open_socket(N2N_MULTICAST_PORT, 1 /* bind ANY */);
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

#ifdef __linux__

static uint32_t get_gateway_ip() {
  FILE *fd;
  char *token = NULL;
  char *gateway_ip_str = NULL;
  char buf[256];
  uint32_t gateway = 0;

  if(!(fd = fopen("/proc/net/route", "r")))
    return(0);

  while(fgets(buf, sizeof(buf), fd)) {
    if(strtok(buf, "\t") && (token = strtok(NULL, "\t")) && (!strcmp(token, "00000000"))) {
      token = strtok(NULL, "\t");

      if(token) {
        struct in_addr addr;

        addr.s_addr = strtoul(token, NULL, 16);
        gateway_ip_str = inet_ntoa(addr);

        if(gateway_ip_str) {
          gateway = addr.s_addr;
          break;
        }
      }
    }
  }

  fclose(fd);

  return(gateway);
}

static char* route_cmd_to_str(int cmd, const n2n_route_t *route, char *buf, size_t bufsize) {
  const char *cmd_str;
  struct in_addr addr;
  char netbuf[64], gwbuf[64];

  switch(cmd) {
  case RTM_NEWROUTE:
    cmd_str = "Add";
    break;
  case RTM_DELROUTE:
    cmd_str = "Delete";
    break;
  default:
    cmd_str = "?";
  }

  addr.s_addr = route->net_addr;
  inet_ntop(AF_INET, &addr, netbuf, sizeof(netbuf));
  addr.s_addr = route->gateway;
  inet_ntop(AF_INET, &addr, gwbuf, sizeof(gwbuf));

  snprintf(buf, bufsize, "%s %s/%d via %s", cmd_str, netbuf, route->net_bitlen, gwbuf);

  return(buf);
}

/* Adapted from https://olegkutkov.me/2019/08/29/modifying-linux-network-routes-using-netlink/ */
#define NLMSG_TAIL(nmsg)						\
  ((struct rtattr *) (((char *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/* Add new data to rtattr */
static int rtattr_add(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen)
{
  int len = RTA_LENGTH(alen);
  struct rtattr *rta;

  if(NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
    traceEvent(TRACE_ERROR, "rtattr_add error: message exceeded bound of %d\n", maxlen);
    return -1;
  }

  rta = NLMSG_TAIL(n);
  rta->rta_type = type;
  rta->rta_len = len;

  if(alen)
    memcpy(RTA_DATA(rta), data, alen);

  n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

  return 0;
}

static int routectl(int cmd, int flags, n2n_route_t *route, int if_idx) {
  int rv = -1;
  int rv2;
  char nl_buf[8192]; /* >= 8192 to avoid truncation, see "man 7 netlink" */
  char route_buf[256];
  struct iovec iov;
  struct msghdr msg;
  struct sockaddr_nl sa;
  uint8_t read_reply = 1;
  int nl_sock;

  struct {
    struct nlmsghdr n;
    struct rtmsg r;
    char buf[4096];
  } nl_request;

  if((nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1) {
    traceEvent(TRACE_ERROR, "netlink socket creation failed [%d]: %s", errno, strerror(errno));
    return(-1);
  }

  /* Subscribe to route change events */
  iov.iov_base = nl_buf;
  iov.iov_len = sizeof(nl_buf);

  memset(&sa, 0, sizeof(sa));
  sa.nl_family = PF_NETLINK;
  sa.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_NOTIFY;
  sa.nl_pid = getpid();

  memset(&msg, 0, sizeof(msg));
  msg.msg_name = &sa;
  msg.msg_namelen = sizeof(sa);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  /* Subscribe to route events */
  if(bind(nl_sock, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
    traceEvent(TRACE_ERROR, "netlink socket bind failed [%d]: %s", errno, strerror(errno));
    goto out;
  }

  /* Initialize request structure */
  memset(&nl_request, 0, sizeof(nl_request));
  nl_request.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  nl_request.n.nlmsg_flags = NLM_F_REQUEST | flags;
  nl_request.n.nlmsg_type = cmd;
  nl_request.r.rtm_family = AF_INET;
  nl_request.r.rtm_table = RT_TABLE_MAIN;
  nl_request.r.rtm_scope = RT_SCOPE_NOWHERE;

  /* Set additional flags if NOT deleting route */
  if(cmd != RTM_DELROUTE) {
    nl_request.r.rtm_protocol = RTPROT_BOOT;
    nl_request.r.rtm_type = RTN_UNICAST;
  }

  nl_request.r.rtm_family = AF_INET;
  nl_request.r.rtm_dst_len = route->net_bitlen;

  /* Select scope, for simplicity we supports here only IPv6 and IPv4 */
  if(nl_request.r.rtm_family == AF_INET6)
    nl_request.r.rtm_scope = RT_SCOPE_UNIVERSE;
  else
    nl_request.r.rtm_scope = RT_SCOPE_LINK;

  /* Set gateway */
  if(route->net_bitlen) {
    if(rtattr_add(&nl_request.n, sizeof(nl_request), RTA_GATEWAY, &route->gateway, 4) < 0)
      goto out;

    nl_request.r.rtm_scope = 0;
    nl_request.r.rtm_family = AF_INET;
  }

  /* Don't set destination and interface in case of default gateways */
  if(route->net_bitlen) {
    /* Set destination network */
    if(rtattr_add(&nl_request.n, sizeof(nl_request), /*RTA_NEWDST*/ RTA_DST, &route->net_addr, 4) < 0)
      goto out;

    /* Set interface */
    if(if_idx > 0) {
      if(rtattr_add(&nl_request.n, sizeof(nl_request), RTA_OIF, &if_idx, sizeof(int)) < 0)
	goto out;
    }
  }

  /* Send message to the netlink */
  if((rv2 = send(nl_sock, &nl_request, sizeof(nl_request), 0)) != sizeof(nl_request)) {
    traceEvent(TRACE_ERROR, "netlink send failed [%d]: %s", errno, strerror(errno));
    goto out;
  }

  /* Wait for the route notification. Assume that the first reply we get is the correct one. */
  traceEvent(TRACE_DEBUG, "waiting for netlink response...");

  while(read_reply) {
    ssize_t len = recvmsg(nl_sock, &msg, 0);
    struct nlmsghdr *nh;

    for(nh = (struct nlmsghdr *)nl_buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
      /* Stop after the first reply */
      read_reply = 0;

      if(nh->nlmsg_type == NLMSG_ERROR) {
	struct nlmsgerr *err = NLMSG_DATA(nh);
	int errcode = err->error;

	if(errcode < 0)
	  errcode = -errcode;

	/* Ignore EEXIST as existing rules are ok */
	if(errcode != EEXIST) {
	  traceEvent(TRACE_ERROR, "[err=%d] route: %s", errcode, route_cmd_to_str(cmd, route, route_buf, sizeof(route_buf)));
	  goto out;
	}
      }

      if(nh->nlmsg_type == NLMSG_DONE)
        break;

      if(nh->nlmsg_type == cmd) {
	traceEvent(TRACE_DEBUG, "Found netlink reply");
	break;
      }
    }
  }

  traceEvent(TRACE_DEBUG, route_cmd_to_str(cmd, route, route_buf, sizeof(route_buf)));
  rv = 0;

 out:
  close(nl_sock);

  return(rv);
}
#endif

/* ************************************** */

static int edge_init_routes_linux(n2n_edge_t *eee, n2n_route_t *routes, uint16_t num_routes) {
#ifdef __linux__
  int i;
  for (i = 0; i<num_routes; i++) {
    n2n_route_t *route = &routes[i];

    if ((route->net_addr == 0) && (route->net_bitlen == 0)) {
      /* This is a default gateway rule. We need to:
       *
       *  1. Add a route to the supernode via the host internet gateway
       *  2. Add the new default gateway route
       *
       * Instead of modifying the system default gateway, we use the trick
       * of adding a route to the networks 0.0.0.0/1 and 128.0.0.0/1, thus
       * covering the whole IPv4 range. Such routes in linux take precedence
       * over the default gateway (0.0.0.0/0) since are more specific.
       * This leaves the default gateway unchanged so that after n2n is
       * stopped the cleanup is easier.
       * See https://github.com/zerotier/ZeroTierOne/issues/178#issuecomment-204599227
       */
      n2n_sock_t sn;
      n2n_route_t custom_route;
      uint32_t *a;

      if (eee->sn_route_to_clean) {
	traceEvent(TRACE_ERROR, "Only one default gateway route allowed");
	return(-1);
      }

      if (eee->conf.sn_num != 1) {
	traceEvent(TRACE_ERROR, "Only one supernode supported with routes");
	return(-1);
      }

      if (supernode2addr(&sn, eee->conf.sn_ip_array[0]) < 0)
	return(-1);

      if (sn.family != AF_INET) {
	traceEvent(TRACE_ERROR, "Only IPv4 routes supported");
	return(-1);
      }

      a = (u_int32_t*)sn.addr.v4;
      custom_route.net_addr = *a;
      custom_route.net_bitlen = 32;
      custom_route.gateway = get_gateway_ip();

      if (!custom_route.gateway) {
	traceEvent(TRACE_ERROR, "could not determine the gateway IP address");
	return(-1);
      }

      /* ip route add supernode via internet_gateway */
      if (routectl(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &custom_route, -1) < 0)
	return(-1);

      /* Save the route to delete it when n2n is stopped */
      eee->sn_route_to_clean = calloc(1, sizeof(n2n_route_t));

      /* Store a copy of the rules into the runtime to delete it during shutdown */
      if (eee->sn_route_to_clean)
	*eee->sn_route_to_clean = custom_route;

      /* ip route add 0.0.0.0/1 via n2n_gateway */
      custom_route.net_addr = 0;
      custom_route.net_bitlen = 1;
      custom_route.gateway = route->gateway;

      if (routectl(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &custom_route, eee->device.if_idx) < 0)
	return(-1);

      /* ip route add 128.0.0.0/1 via n2n_gateway */
      custom_route.net_addr = 128;
      custom_route.net_bitlen = 1;
      custom_route.gateway = route->gateway;

      if (routectl(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &custom_route, eee->device.if_idx) < 0)
	return(-1);
    }
    else {
      /* ip route add net via n2n_gateway */
      if (routectl(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, route, eee->device.if_idx) < 0)
	return(-1);
    }
  }
#endif

  return(0);
}

/* ************************************** */

static int edge_init_routes_win(n2n_edge_t *eee, n2n_route_t *routes, uint16_t num_routes)
{
#ifdef WIN32
  int i;
  struct in_addr net_addr, gateway;
  char c_net_addr[32];
  char c_gateway[32];
  char cmd[256];

  for (i = 0; i < num_routes; i++)
    {
      n2n_route_t *route = &routes[i];
      if ((route->net_addr == 0) && (route->net_bitlen == 0))
        {
	  traceEvent(TRACE_NORMAL, "Warning: The 0.0.0.0/0 route settings are not supported on Windows");
	  return (-1);
        }
      else
        {
	  /* ip route add net via n2n_gateway */
	  memcpy(&net_addr, &(route->net_addr), sizeof(net_addr));
	  memcpy(&gateway, &(route->gateway), sizeof(gateway));
	  _snprintf(c_net_addr, sizeof(c_net_addr), inet_ntoa(net_addr));
	  _snprintf(c_gateway, sizeof(c_gateway), inet_ntoa(gateway));
	  _snprintf(cmd, sizeof(cmd), "route add %s/%d %s > nul", c_net_addr, route->net_bitlen, c_gateway);
	  traceEvent(TRACE_NORMAL, "ROUTE CMD = '%s'\n", cmd);
	  system(cmd);
        }
    }

#endif // WIN32

  return (0);
}

/* ************************************** */

/* Add the user-provided routes to the linux routing table. Network routes
 * are bound to the n2n TAP device, so they are automatically removed when
 * the TAP device is destroyed. */
static int edge_init_routes(n2n_edge_t *eee, n2n_route_t *routes, uint16_t num_routes) {
#ifdef __linux__
  return  edge_init_routes_linux(eee, routes, num_routes);
#endif

#ifdef WIN32
  return  edge_init_routes_win(eee, routes, num_routes);
#endif
  return 0;
}

/* ************************************** */

static void edge_cleanup_routes(n2n_edge_t *eee) {
#ifdef __linux__
  if(eee->sn_route_to_clean) {
    /* ip route del supernode via internet_gateway */
    routectl(RTM_DELROUTE, 0, eee->sn_route_to_clean, -1);
    free(eee->sn_route_to_clean);
  }
#endif
}

/* ************************************** */

void edge_init_conf_defaults(n2n_edge_conf_t *conf) {
	memset(conf, 0, sizeof(*conf));

	conf->local_port = 0 /* any port */;
	conf->mgmt_port = N2N_EDGE_MGMT_PORT; /* 5644 by default */
	conf->transop_id = N2N_TRANSFORM_ID_NULL;
	conf->header_encryption = HEADER_ENCRYPTION_NONE;
	conf->compression = N2N_COMPRESSION_ID_NONE;
	conf->drop_multicast = 1;
	conf->allow_p2p = 1;
	conf->disable_pmtu_discovery = 1;
	conf->register_interval = REGISTER_SUPER_INTERVAL_DFL;
	conf->tuntap_ip_mode = TUNTAP_IP_MODE_SN_ASSIGN;

	if (getenv("N2N_KEY")) {
		conf->encrypt_key = strdup(getenv("N2N_KEY"));
		conf->transop_id = N2N_TRANSFORM_ID_TWOFISH;
	}
}

/* ************************************** */

void edge_term_conf(n2n_edge_conf_t *conf) {
	if (conf->routes) free(conf->routes);
	if (conf->encrypt_key) free(conf->encrypt_key);
}

/* ************************************** */

const n2n_edge_conf_t* edge_get_conf(const n2n_edge_t *eee) {
  return(&eee->conf);
}

/* ************************************** */

int edge_conf_add_supernode(n2n_edge_conf_t *conf, const char *ip_and_port) {
  if(conf->sn_num >= N2N_EDGE_NUM_SUPERNODES)
    return(-1);

  strncpy((conf->sn_ip_array[conf->sn_num]), ip_and_port, N2N_EDGE_SN_HOST_SIZE);
  traceEvent(TRACE_NORMAL, "Adding supernode[%u] = %s", (unsigned int)conf->sn_num, (conf->sn_ip_array[conf->sn_num]));
  conf->sn_num++;

  return(0);
}

/* ************************************** */

int quick_edge_init(char *device_name, char *community_name,
		    char *encrypt_key, char *device_mac,
		    char *local_ip_address,
		    char *supernode_ip_address_port,
		    int *keep_on_running) {
  tuntap_dev tuntap;
  n2n_edge_t *eee;
  n2n_edge_conf_t conf;
  int rv;

  /* Setup the configuration */
  edge_init_conf_defaults(&conf);
  conf.encrypt_key = encrypt_key;
  conf.transop_id = N2N_TRANSFORM_ID_TWOFISH;
  snprintf((char*)conf.community_name, sizeof(conf.community_name), "%s", community_name);
  edge_conf_add_supernode(&conf, supernode_ip_address_port);

  /* Validate configuration */
  if(edge_verify_conf(&conf) != 0)
    return(-1);

  /* Open the tuntap device */
  if(tuntap_open(&tuntap, device_name, "static",
		 local_ip_address, "255.255.255.0",
		 device_mac, DEFAULT_MTU) < 0)
    return(-2);

  /* Init edge */
  if((eee = edge_init(&conf, &rv)) == NULL)
    goto quick_edge_init_end;

  rv = run_edge_loop(eee, keep_on_running);
  edge_term(eee);
  edge_term_conf(&conf);

 quick_edge_init_end:
  tuntap_close(&tuntap);
  return(rv);
}

/* ************************************** */
