/**
 * (C) 2007-18 - ntop.org and contributors
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
#include "lzoconf.h"

#ifdef WIN32
#include <process.h>
#endif

#ifdef __ANDROID_NDK__
#include "android/edge_android.h"
#include <tun2tap/tun2tap.h>
#endif /* __ANDROID_NDK__ */


#define SOCKET_TIMEOUT_INTERVAL_SECS    10
#define REGISTER_SUPER_INTERVAL_DFL     20 /* sec, usually UDP NAT entries in a firewall expire after 30 seconds */

#define IFACE_UPDATE_INTERVAL           (30) /* sec. How long it usually takes to get an IP lease. */
#define TRANSOP_TICK_INTERVAL           (10) /* sec */

#ifdef __ANDROID_NDK__
#define ARP_PERIOD_INTERVAL             (10) /* sec */
#endif

#define ETH_FRAMESIZE 14
#define IP4_SRCOFFSET 12
#define IP4_DSTOFFSET 16

/* ************************************** */

static const char * supernode_ip(const n2n_edge_t * eee);
static void send_register(n2n_edge_t *eee, const n2n_sock_t *remote_peer, const n2n_mac_t peer_mac);
static void check_peer_registration_needed(n2n_edge_t * eee,
		uint8_t from_supernode,
		const n2n_mac_t mac,
		const n2n_sock_t * peer);
static int edge_init_sockets(n2n_edge_t *eee, int udp_local_port, int mgmt_port);
static void supernode2addr(n2n_sock_t * sn, const n2n_sn_name_t addrIn);
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

struct n2n_edge_stats {
  uint32_t tx_p2p;
  uint32_t rx_p2p;
  uint32_t tx_sup;
  uint32_t rx_sup;
};

/* ************************************** */

struct n2n_edge {
  n2n_edge_conf_t     conf;

  /* Status */
  uint8_t             sn_idx;                 /**< Currently active supernode. */
  uint8_t             sn_wait;                /**< Whether we are waiting for a supernode response. */
  size_t              sup_attempts;           /**< Number of remaining attempts to this supernode. */
  tuntap_dev          device;                 /**< All about the TUNTAP device */
  n2n_trans_op_t      transop;                /**< The transop to use when encoding */
  n2n_cookie_t        last_cookie;            /**< Cookie sent in last REGISTER_SUPER. */

  /* Sockets */
  n2n_sock_t          supernode;
  n2n_sock_t          multicast_peer;         /**< Multicast peer group (for local edges) */
  int                 udp_sock;
  int                 udp_mgmt_sock;          /**< socket for status info. */
  int                 udp_multicast_sock;     /**< socket for local multicast registrations. */

  /* Peers */
  struct peer_info *  known_peers;            /**< Edges we are connected to. */
  struct peer_info *  pending_peers;          /**< Edges we have tried to register with. */

  /* Timers */
  time_t              last_register_req;      /**< Check if time to re-register with super*/
  time_t              last_p2p;               /**< Last time p2p traffic was received. */
  time_t              last_sup;               /**< Last time a packet arrived from supernode. */
  time_t              start_time;             /**< For calculating uptime */

  /* Statistics */
  struct n2n_edge_stats stats;
};

/* ************************************** */

static const char* transop_str(enum n2n_transform tr) {
  switch(tr) {
  case N2N_TRANSFORM_ID_NULL:    return("null");
  case N2N_TRANSFORM_ID_TWOFISH: return("twofish");
  case N2N_TRANSFORM_ID_AESCBC:  return("AES-CBC");
  default:                       return("invalid");
  };
}

/* ************************************** */

/** Initialise an edge to defaults.
 *
 *  This also initialises the NULL transform operation opstruct.
 */
n2n_edge_t* edge_init(const tuntap_dev *dev, const n2n_edge_conf_t *conf, int *rv) {
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
  memcpy(&eee->device, dev, sizeof(*dev));
  eee->start_time = time(NULL);

  /* REVISIT: BbMaj7 : Should choose something with less predictability
           * particularly for embedded targets with no real-time clock. */
  srand(eee->start_time);

  eee->known_peers    = NULL;
  eee->pending_peers  = NULL;
  eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;

#ifdef NOT_USED
  if(lzo_init() != LZO_E_OK) {
    traceEvent(TRACE_ERROR, "LZO compression error");
    goto edge_init_error;
  }
#endif

  for(i=0; i<conf->sn_num; ++i)
    traceEvent(TRACE_NORMAL, "supernode %u => %s\n", i, (conf->sn_ip_array[i]));

  /* Set the active supernode */
  supernode2addr(&(eee->supernode), conf->sn_ip_array[eee->sn_idx]);

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
  default:
    rc = n2n_transop_null_init(&eee->conf, &eee->transop);
  }

  if((rc < 0) || (eee->transop.fwd == NULL) || (eee->transop.transform_id != transop_id)) {
    traceEvent(TRACE_ERROR, "Transop init failed");
    goto edge_init_error;
  }

  if(eee->transop.no_encryption)
    traceEvent(TRACE_WARNING, "Encryption is disabled in edge");

  if(edge_init_sockets(eee, conf->local_port, conf->mgmt_port) < 0) {
    traceEvent(TRACE_ERROR, "Error: socket setup failed");
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

/* ***************************************************** */

static inline void update_peer_seen(struct peer_info *peer, time_t t) {
  peer->last_seen = t;
}

/* ***************************************************** */

static void remove_peer_from_list(struct peer_info **head, struct peer_info *prev,
			 struct peer_info *scan) {
  /* Remove the peer. */
  if(prev == NULL)
    /* scan was head of list */
    *head = scan->next;
  else
    prev->next = scan->next;

  free(scan);
}

/* ************************************** */

static uint32_t localhost_v4 = 0x7f000001;
static uint8_t localhost_v6[IPV6_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};

/* Exclude localhost as it may be received when an edge node runs
 * in the same supernode host.
 */
static int is_valid_peer_sock(const n2n_sock_t *sock) {
  if(((sock->family == AF_INET) && (*((uint32_t*)sock->addr.v4) != htonl(localhost_v4)))
     || ((sock->family == AF_INET6) && memcmp(sock->addr.v6, localhost_v6, IPV6_SIZE)))
    return(1);

  return(0);
}

/* ***************************************************** */

/** Resolve the supernode IP address.
 *
 *  REVISIT: This is a really bad idea. The edge will block completely while the
 *           hostname resolution is performed. This could take 15 seconds.
 */
static void supernode2addr(n2n_sock_t * sn, const n2n_sn_name_t addrIn) {
  n2n_sn_name_t addr;
  const char *supernode_host;

  memcpy(addr, addrIn, N2N_EDGE_SN_HOST_SIZE);

  supernode_host = strtok(addr, ":");

  if(supernode_host)
    {
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
            }

	  freeaddrinfo(ainfo); /* free everything allocated by getaddrinfo(). */
	  ainfo = NULL;
        } else {
	traceEvent(TRACE_WARNING, "Failed to resolve supernode host %s, assuming numeric", supernode_host);
	sn_addr = inet_addr(supernode_host); /* uint32_t */
	memcpy(sn->addr.v4, &(sn_addr), IPV4_SIZE);
	sn->family=AF_INET;
      }

    } else
    traceEvent(TRACE_WARNING, "Wrong supernode parameter (-l <host:port>)");
}

/* ************************************** */

/***
 *
 * Register over multicast in case there is a peer on the same network listening
 */
static void register_with_local_peers(n2n_edge_t * eee) {
  /* no send registration to the local multicast group */
  traceEvent(TRACE_INFO, "Registering with multicast group %s:%u",
	     N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT);    
  send_register(eee, &(eee->multicast_peer), NULL);
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
			      const n2n_mac_t mac,
			      const n2n_sock_t * peer) {
  /* REVISIT: purge of pending_peers not yet done. */
  struct peer_info * scan = find_peer_by_mac(eee->pending_peers, mac);
  macstr_t mac_buf;
  n2n_sock_str_t sockbuf;

  /* NOTE: pending_peers are purged periodically with purge_expired_registrations */
  if(scan == NULL) {
    scan = calloc(1, sizeof(struct peer_info));

    memcpy(scan->mac_addr, mac, N2N_MAC_SIZE);
    scan->sock = *peer;
    scan->timeout = REGISTER_SUPER_INTERVAL_DFL; /* TODO: should correspond to the peer supernode registration timeout */
    update_peer_seen(scan, time(NULL)); /* Don't change this it marks the pending peer for removal. */

    peer_list_add(&(eee->pending_peers), scan);

    traceEvent(TRACE_DEBUG, "=== new pending %s -> %s",
	       macaddr_str(mac_buf, scan->mac_addr),
	       sock_to_cstr(sockbuf, &(scan->sock)));

    traceEvent(TRACE_INFO, "Pending peers list size=%u",
	       (unsigned int)peer_list_size(eee->pending_peers));

    /* trace Sending REGISTER */
    send_register(eee, &(scan->sock), mac);

    register_with_local_peers(eee);
  }
}

/* ************************************** */

/** Update the last_seen time for this peer, or get registered. */
static void check_peer_registration_needed(n2n_edge_t * eee,
		uint8_t from_supernode,
		const n2n_mac_t mac,
		const n2n_sock_t * peer) {
  struct peer_info * scan = find_peer_by_mac(eee->known_peers, mac);
  
  if(scan == NULL) {
    /* Not in known_peers - start the REGISTER process. */
    register_with_new_peer(eee, mac, peer);
  } else {
    /* Already in known_peers. */
    time_t now = time(NULL);

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
			  const n2n_sock_t * peer) {
  struct peer_info * prev = NULL;
  struct peer_info * scan;
  macstr_t mac_buf;
  n2n_sock_str_t sockbuf;

  traceEvent(TRACE_INFO, "peer_set_p2p_confirmed: %s -> %s",
	     macaddr_str(mac_buf, mac),
	     sock_to_cstr(sockbuf, peer));

  scan=eee->pending_peers;

  while (NULL != scan)
    {
      if(0 == memcmp(scan->mac_addr, mac, N2N_MAC_SIZE))
        {
	  break; /* found. */
        }

      prev = scan;
      scan = scan->next;
    }

  if(scan)
    {


      /* Remove scan from pending_peers. */
      if(prev)
        {
	  prev->next = scan->next;
        }
      else
        {
	  eee->pending_peers = scan->next;
        }

      /* Add scan to known_peers. */
      scan->next = eee->known_peers;
      eee->known_peers = scan;

      scan->sock = *peer;

      traceEvent(TRACE_DEBUG, "=== new peer %s -> %s",
		 macaddr_str(mac_buf, scan->mac_addr),
		 sock_to_cstr(sockbuf, &(scan->sock)));

      traceEvent(TRACE_INFO, "Pending peers list size=%u",
		 (unsigned int)peer_list_size(eee->pending_peers));

      traceEvent(TRACE_INFO, "Known peers list size=%u",
		 (unsigned int)peer_list_size(eee->known_peers));


      update_peer_seen(scan, time(NULL));
    }
  else
    {
      traceEvent(TRACE_DEBUG, "Failed to find sender in pending_peers.");
    }
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

static n2n_mac_t broadcast_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/** Check if a known peer socket has changed and possibly register again.
 */
static void check_known_peer_sock_change(n2n_edge_t * eee,
			 uint8_t from_supernode,
			 const n2n_mac_t mac,
			 const n2n_sock_t * peer,
			 time_t when) {
  struct peer_info *scan = eee->known_peers;
  struct peer_info *prev = NULL; /* use to remove bad registrations. */
  n2n_sock_str_t sockbuf1;
  n2n_sock_str_t sockbuf2; /* don't clobber sockbuf1 if writing two addresses to trace */
  macstr_t mac_buf;

  if(is_empty_ip_address(peer))
    return;

  if(!memcmp(mac, broadcast_mac, N2N_MAC_SIZE))
    return;

  /* Search the peer in known_peers */
  while(scan != NULL) {
      if(memcmp(mac, scan->mac_addr, N2N_MAC_SIZE) == 0)
	  break;

      prev = scan;
      scan = scan->next;
  }

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
	  remove_peer_from_list(&eee->known_peers, prev, scan);

	  register_with_new_peer(eee, mac, peer);
      } else {
	  /* Don't worry about what the supernode reports, it could be seeing a different socket. */
      }
  } else
    update_peer_seen(scan, when);
}

/* ************************************** */

/** Send a datagram to a socket defined by a n2n_sock_t */
static ssize_t sendto_sock(int fd, const void * buf,
			   size_t len, const n2n_sock_t * dest) {
  struct sockaddr_in peer_addr;
  ssize_t sent;

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

/** Send a REGISTER_SUPER packet to the current supernode. */
static void send_register_super(n2n_edge_t * eee,
				const n2n_sock_t * supernode) {
  uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};
  size_t idx;
  /* ssize_t sent; */
  n2n_common_t cmn;
  n2n_REGISTER_SUPER_t reg;
  n2n_sock_str_t sockbuf;

  memset(&cmn, 0, sizeof(cmn));
  memset(&reg, 0, sizeof(reg));
  cmn.ttl=N2N_DEFAULT_TTL;
  cmn.pc = n2n_register_super;
  cmn.flags = 0;
  memcpy(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

  for(idx=0; idx < N2N_COOKIE_SIZE; ++idx)
    eee->last_cookie[idx] = rand() % 0xff;

  memcpy(reg.cookie, eee->last_cookie, N2N_COOKIE_SIZE);
  reg.auth.scheme=0; /* No auth yet */

  idx=0;
  encode_mac(reg.edgeMac, &idx, eee->device.mac_addr);

  idx=0;
  encode_REGISTER_SUPER(pktbuf, &idx, &cmn, &reg);

  traceEvent(TRACE_INFO, "send REGISTER_SUPER to %s",
	     sock_to_cstr(sockbuf, supernode));

  /* sent = */ sendto_sock(eee->udp_sock, pktbuf, idx, supernode);
}

/* ************************************** */

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

  traceEvent(TRACE_INFO, "send REGISTER %s",
	     sock_to_cstr(sockbuf, remote_peer));

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


  /* sent = */ sendto_sock(eee->udp_sock, pktbuf, idx, remote_peer);
}

/* ************************************** */

/** @brief Check to see if we should re-register with the supernode.
 *
 *  This is frequently called by the main loop.
 */
static void update_supernode_reg(n2n_edge_t * eee, time_t nowTime) {
  u_int sn_idx;
  
  if(eee->sn_wait && (nowTime > (eee->last_register_req + (eee->conf.register_interval/10)))) {
    /* fall through */
    traceEvent(TRACE_DEBUG, "update_supernode_reg: doing fast retry.");
  } else if(nowTime < (eee->last_register_req + eee->conf.register_interval))
    return; /* Too early */

  if(0 == eee->sup_attempts) {
    /* Give up on that supernode and try the next one. */
    ++(eee->sn_idx);

    if (eee->sn_idx >= eee->conf.sn_num) {
      /* Got to end of list, go back to the start. Also works for list of one entry. */
      eee->sn_idx=0;
    }

    traceEvent(TRACE_WARNING, "Supernode not responding - moving to %u of %u",
	       (unsigned int)eee->sn_idx, (unsigned int)eee->conf.sn_num);

    eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;
  }
  else
    --(eee->sup_attempts);

  for(sn_idx=0; sn_idx<eee->conf.sn_num; sn_idx++) {
    supernode2addr(&(eee->supernode), eee->conf.sn_ip_array[sn_idx]);
    
    traceEvent(TRACE_INFO, "Registering with supernode [id: %u/%u][%s][attempts left %u]",
	       sn_idx+1, eee->conf.sn_num,
	       supernode_ip(eee), (unsigned int)eee->sup_attempts);
    
    send_register_super(eee, &(eee->supernode));
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

    if(rx_transop_id == eee->conf.transop_id) {
	eth_payload = decodebuf;
	eh = (ether_hdr_t*)eth_payload;
	eth_size = eee->transop.rev(&eee->transop,
						    eth_payload, N2N_PKT_BUF_SIZE,
						    payload, psize, pkt->srcMac);
	++(eee->transop.rx_cnt); /* stats */

	if(!(eee->conf.allow_routing)) {
	  if(ntohs(eh->type) == 0x0800) {
	    uint32_t *dst = (uint32_t*)&eth_payload[ETH_FRAMESIZE + IP4_DSTOFFSET];

	    /* Note: all elements of the_ip are in network order */
	    if(*dst != eee->device.ip_addr) {
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

	/* Write ethernet packet to tap device. */
	traceEvent(TRACE_INFO, "sending to TAP %u", (unsigned int)eth_size);
	data_sent_len = tuntap_write(&(eee->device), eth_payload, eth_size);

	if (data_sent_len == eth_size)
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
		      (unsigned int)peer_list_size(eee->pending_peers),
		      (unsigned int)peer_list_size(eee->known_peers));

  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
		      "last super:%lu(%ld sec ago) p2p:%lu(%ld sec ago)\n",
		      eee->last_sup, (now-eee->last_sup), eee->last_p2p,
		      (now-eee->last_p2p));

  traceEvent(TRACE_DEBUG, "mgmt status sending: %s", udp_buf);


  /* sendlen = */ sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0/*flags*/,
			 (struct sockaddr *)&sender_sock, sizeof(struct sockaddr_in));
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

/* @return 1 if destination is a peer, 0 if destination is supernode */
static int find_peer_destination(n2n_edge_t * eee,
                                 n2n_mac_t mac_address,
                                 n2n_sock_t * destination) {
  struct peer_info *scan = eee->known_peers;
  struct peer_info *prev = NULL;
  macstr_t mac_buf;
  n2n_sock_str_t sockbuf;
  int retval=0;
  time_t now = time(NULL);

  traceEvent(TRACE_DEBUG, "Searching destination peer for MAC %02X:%02X:%02X:%02X:%02X:%02X",
	     mac_address[0] & 0xFF, mac_address[1] & 0xFF, mac_address[2] & 0xFF,
	     mac_address[3] & 0xFF, mac_address[4] & 0xFF, mac_address[5] & 0xFF);

  while(scan != NULL) {
    traceEvent(TRACE_DEBUG, "Evaluating peer [MAC=%02X:%02X:%02X:%02X:%02X:%02X]",
	       scan->mac_addr[0] & 0xFF, scan->mac_addr[1] & 0xFF, scan->mac_addr[2] & 0xFF,
	       scan->mac_addr[3] & 0xFF, scan->mac_addr[4] & 0xFF, scan->mac_addr[5] & 0xFF
	       );

    if((scan->last_seen > 0) &&
       (memcmp(mac_address, scan->mac_addr, N2N_MAC_SIZE) == 0)) {
	if((now - scan->last_seen) >= (scan->timeout / 2)) {
	  /* Too much time passed since we saw the peer, need to register again
	   * since the peer address may have changed. */
	  traceEvent(TRACE_DEBUG, "Refreshing idle known peer");
	  remove_peer_from_list(&eee->known_peers, prev, scan);
	  /* NOTE: registration will be performed upon the receival of the next response packet */
	} else {
	  /* Valid known peer found */
	  memcpy(destination, &scan->sock, sizeof(n2n_sock_t));
	  retval=1;
	}

	break;
    }

    prev = scan;
    scan = scan->next;
  }

  if(retval == 0)
    memcpy(destination, &(eee->supernode), sizeof(struct sockaddr_in));

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

  /* hexdump(pktbuf, pktlen); */

  is_p2p = find_peer_destination(eee, dstMac, &destination);

  if(is_p2p)
    ++(eee->stats.tx_p2p);
  else
    ++(eee->stats.tx_sup);

  traceEvent(TRACE_INFO, "send_packet to %s", sock_to_cstr(sockbuf, &destination));

  /* s = */ sendto_sock(eee->udp_sock, pktbuf, pktlen, &destination);

  return 0;
}

/* ************************************** */

/** A layer-2 packet was received at the tunnel and needs to be sent via UDP. */
void send_packet2net(n2n_edge_t * eee,
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

  idx=0;
  encode_PACKET(pktbuf, &idx, &cmn, &pkt);
  traceEvent(TRACE_DEBUG, "encoded PACKET header of size=%u transform %u",
	     (unsigned int)idx, tx_transop_idx);

  idx += eee->transop.fwd(&eee->transop,
					  pktbuf+idx, N2N_PKT_BUF_SIZE-idx,
					  tap_pkt, len, pkt.dstMac);
  eee->transop.tx_cnt++; /* stats */

  send_packet(eee, destMac, pktbuf, idx); /* to peer or supernode */
}

/* ************************************** */

/** Read a single packet from the TAP interface, process it and write out the
 *  corresponding packet to the cooked socket.
 */
static void readFromTAPSocket(n2n_edge_t * eee) {
  /* tun -> remote */
  uint8_t             eth_pkt[N2N_PKT_BUF_SIZE];
  macstr_t            mac_buf;
  ssize_t             len;

#ifdef __ANDROID_NDK__
  if (uip_arp_len != 0) {
    len = uip_arp_len;
    memcpy(eth_pkt, uip_arp_buf, MIN(uip_arp_len, N2N_PKT_BUF_SIZE));
    traceEvent(TRACE_DEBUG, "ARP reply packet to send");
  }
  else
    {
#endif /* #ifdef __ANDROID_NDK__ */
      len = tuntap_read( &(eee->device), eth_pkt, N2N_PKT_BUF_SIZE );
#ifdef __ANDROID_NDK__
    }
#endif /* #ifdef __ANDROID_NDK__ */

  if((len <= 0) || (len > N2N_PKT_BUF_SIZE))
    {
      traceEvent(TRACE_WARNING, "read()=%d [%d/%s]",
		 (signed int)len, errno, strerror(errno));
    }
  else
    {
      const uint8_t * mac = eth_pkt;
      traceEvent(TRACE_INFO, "### Rx TAP packet (%4d) for %s",
		 (signed int)len, macaddr_str(mac_buf, mac));

      if(eee->conf.drop_multicast &&
	 (is_ip6_discovery(eth_pkt, len) ||
	  is_ethMulticast(eth_pkt, len)
	  )
	 )
        {
	  traceEvent(TRACE_DEBUG, "Dropping multicast");
        }
      else
        {
	  send_packet2net(eee, eth_pkt, len);
        }
    }
}

/* ************************************** */

#ifdef WIN32
static DWORD tunReadThread(LPVOID lpArg) {
  n2n_edge_t *eee = (n2n_edge_t*)lpArg;

  while(1)
    readFromTAPSocket(eee);

  return((DWORD)NULL);
}

/* ************************************** */

/** Start a second thread in Windows because TUNTAP interfaces do not expose
 *  file descriptors. */
static void startTunReadThread(n2n_edge_t *eee) {
  HANDLE hThread;
  DWORD dwThreadId;

  hThread = CreateThread(NULL,         /* security attributes */
			 0,            /* use default stack size */
			 (LPTHREAD_START_ROUTINE)tunReadThread, /* thread function */
			 (void*)eee,   /* argument to thread function */
			 0,            /* thread creation flags */
			 &dwThreadId); /* thread id out */
}
#endif

/* ************************************** */

/** Read a datagram from the main UDP socket to the internet. */
static void readFromIPSocket(n2n_edge_t * eee, int in_sock) {
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

  traceEvent(TRACE_INFO, "### Rx N2N UDP (%d) from %s",
	     (signed int)recvlen, sock_to_cstr(sockbuf1, &sender));

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

	  if(is_valid_peer_sock(&pkt.sock))
	    orig_sender = &(pkt.sock);

	  traceEvent(TRACE_INFO, "Rx PACKET from %s (%s)",
		     sock_to_cstr(sockbuf1, &sender),
		     sock_to_cstr(sockbuf2, orig_sender));

	  handle_PACKET(eee, &cmn, &pkt, orig_sender, udp_buf+idx, recvlen-idx);
	  break;
      }
      case MSG_TYPE_REGISTER:
      {
	  /* Another edge is registering with us */
	  n2n_REGISTER_t reg;
	  n2n_mac_t null_mac = { '\0' };
	  int skip_register = 0;
	  
	  decode_REGISTER(&reg, &cmn, udp_buf, &rem, &idx);

	  if(is_valid_peer_sock(&reg.sock))
	    orig_sender = &(reg.sock);

	  traceEvent(TRACE_INFO, "Rx REGISTER src=%s dst=%s from peer %s (%s)",
		     macaddr_str(mac_buf1, reg.srcMac),
		     macaddr_str(mac_buf2, reg.dstMac),
		     sock_to_cstr(sockbuf1, &sender),
		     sock_to_cstr(sockbuf2, orig_sender));

	  if(!memcmp(reg.dstMac, eee->device.mac_addr, 6))
	    check_peer_registration_needed(eee, from_supernode, reg.srcMac, orig_sender);
	  else if(// (sender.port == N2N_MULTICAST_PORT) &&
		  (!memcmp(reg.dstMac, null_mac, 6))) { /* Announce via a multicast socket */
	    if(memcmp(reg.srcMac, eee->device.mac_addr, 6)) /* It's not our self-announce */
	      check_peer_registration_needed(eee, from_supernode, reg.srcMac, orig_sender);
	    else {
	      traceEvent(TRACE_INFO, "Skipping REGISTER from self");
	      skip_register = 1; /* do not register with ourselves */
	    }
	  }

	  if(!skip_register)
	    send_register_ack(eee, orig_sender, &reg);
	  break;
      }
      case MSG_TYPE_REGISTER_ACK:
      {
	  /* Peer edge is acknowledging our register request */
	  n2n_REGISTER_ACK_t ra;

	  decode_REGISTER_ACK(&ra, &cmn, udp_buf, &rem, &idx);

	  if(is_valid_peer_sock(&ra.sock))
	    orig_sender = &(ra.sock);

	  traceEvent(TRACE_INFO, "Rx REGISTER_ACK src=%s dst=%s from peer %s (%s)",
		     macaddr_str(mac_buf1, ra.srcMac),
		     macaddr_str(mac_buf2, ra.dstMac),
		     sock_to_cstr(sockbuf1, &sender),
		     sock_to_cstr(sockbuf2, orig_sender));

	  peer_set_p2p_confirmed(eee, ra.srcMac, &sender);
	  break;
      }
      case MSG_TYPE_REGISTER_SUPER_ACK:
      {
	  n2n_REGISTER_SUPER_ACK_t ra;

	  if(eee->sn_wait)
            {
	      decode_REGISTER_SUPER_ACK(&ra, &cmn, udp_buf, &rem, &idx);

	      if(is_valid_peer_sock(&ra.sock))
		  orig_sender = &(ra.sock);

	      traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK myMAC=%s [%s] (external %s). Attempts %u",
			 macaddr_str(mac_buf1, ra.edgeMac),
			 sock_to_cstr(sockbuf1, &sender),
			 sock_to_cstr(sockbuf2, orig_sender),
			 (unsigned int)eee->sup_attempts);

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

		  /* NOTE: the register_interval should be chosen by the edge node
		   * based on its NAT configuration. */
		  //eee->conf.register_interval = ra.lifetime;
                }
	      else
                {
		  traceEvent(TRACE_WARNING, "Rx REGISTER_SUPER_ACK with wrong or old cookie.");
                }
            }
	  else
            {
	      traceEvent(TRACE_WARNING, "Rx REGISTER_SUPER_ACK with no outstanding REGISTER_SUPER.");
            }
	  break;
      }
      default:
        /* Not a known message type */
        traceEvent(TRACE_WARNING, "Unable to handle packet type %d: ignored", (signed int)msg_type);
        return;
      } /* switch(msg_type) */
  } else if(from_supernode) /* if (community match) */
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
  traceEvent(TRACE_NORMAL, "    TX Supernode: %u pkts", s->tx_sup);
  traceEvent(TRACE_NORMAL, "    RX Supernode: %u pkts", s->rx_sup);
  traceEvent(TRACE_NORMAL, "**********************************");
}

/* ************************************** */

int run_edge_loop(n2n_edge_t * eee, int *keep_running) {
  size_t numPurged;
  time_t lastIfaceCheck=0;
  time_t lastTransop=0;
  time_t last_purge_known = 0;
  time_t last_purge_pending = 0;
#ifdef __ANDROID_NDK__
  time_t lastArpPeriod=0;
#endif

#ifdef WIN32
  startTunReadThread(eee);
#endif

  *keep_running = 1;
  update_supernode_reg(eee, time(NULL));
      
  /* Main loop
   *
   * select() is used to wait for input on either the TAP fd or the UDP/TCP
   * socket. When input is present the data is read and processed by either
   * readFromIPSocket() or readFromTAPSocket()
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
    FD_SET(eee->udp_multicast_sock, &socket_mask);
    max_sock = max(eee->udp_sock, eee->udp_multicast_sock);
    
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

      if(FD_ISSET(eee->udp_multicast_sock, &socket_mask)) {
	/* Read a cooked socket from the internet socket (multicast). Writes on the TAP
	 * socket. */
	traceEvent(TRACE_INFO, "Received packet from multicast socket");
	readFromIPSocket(eee, eee->udp_multicast_sock);
      }

#ifdef __ANDROID_NDK__
      if (uip_arp_len != 0) {
	readFromTAPSocket(eee);
	uip_arp_len = 0;
      }
#endif /* #ifdef __ANDROID_NDK__ */

      if(FD_ISSET(eee->udp_mgmt_sock, &socket_mask)) {
	/* Read a cooked socket from the internet socket. Writes on the TAP
	 * socket. */
	readFromMgmtSocket(eee, keep_running);
      }

#ifndef WIN32
      if(FD_ISSET(eee->device.fd, &socket_mask)) {
	/* Read an ethernet frame from the TAP socket. Write on the IP
	 * socket. */
	readFromTAPSocket(eee);
      }
#endif
    }

    /* Finished processing select data. */
    update_supernode_reg(eee, nowTime);

    numPurged =  purge_expired_registrations(&(eee->known_peers), &last_purge_known);
    numPurged += purge_expired_registrations(&(eee->pending_peers), &last_purge_pending);

    if(numPurged > 0) {
      traceEvent(TRACE_NORMAL, "Peer removed: pending=%u, operational=%u",
		 (unsigned int)peer_list_size(eee->pending_peers),
		 (unsigned int)peer_list_size(eee->known_peers));
    }

    if(eee->conf.dyn_ip_mode &&
       ((nowTime - lastIfaceCheck) > IFACE_UPDATE_INTERVAL)) {
      traceEvent(TRACE_NORMAL, "Re-checking dynamic IP address.");
      tuntap_get_address(&(eee->device));
      lastIfaceCheck = nowTime;
    }

#ifdef __ANDROID_NDK__
    if ((nowTime - lastArpPeriod) > ARP_PERIOD_INTERVAL) {
      uip_arp_timer();
      lastArpPeriod = nowTime;
    }
#endif /* #ifdef __ANDROID_NDK__ */
  } /* while */

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

  if(eee->udp_multicast_sock >= 0)
    closesocket(eee->udp_multicast_sock);    

  clear_peer_list(&(eee->pending_peers));
  clear_peer_list(&(eee->known_peers));

  eee->transop.deinit(&eee->transop);
  free(eee);
}

/* ************************************** */

static int edge_init_sockets(n2n_edge_t *eee, int udp_local_port, int mgmt_port) {
  /* Populate the multicast group for local edge */
  eee->multicast_peer.family     = AF_INET;
  eee->multicast_peer.port       = N2N_MULTICAST_PORT;
  eee->multicast_peer.addr.v4[0] = 224; /* N2N_MULTICAST_GROUP */
  eee->multicast_peer.addr.v4[1] = 0;
  eee->multicast_peer.addr.v4[2] = 0;
  eee->multicast_peer.addr.v4[3] = 68;

  if(udp_local_port > 0)
    traceEvent(TRACE_NORMAL, "Binding to local port %d", udp_local_port);

  eee->udp_sock = open_socket(udp_local_port, 1 /* bind ANY */);
  if(eee->udp_sock < 0) {
    traceEvent(TRACE_ERROR, "Failed to bind main UDP port %u", udp_local_port);
    return(-1);
  }

  eee->udp_mgmt_sock = open_socket(mgmt_port, 0 /* bind LOOPBACK */);
  if(eee->udp_mgmt_sock < 0) {
    traceEvent(TRACE_ERROR, "Failed to bind management UDP port %u", mgmt_port);
    return(-2);
  }

  eee->udp_multicast_sock = open_socket(N2N_MULTICAST_PORT, 1 /* bind ANY */);
  if(eee->udp_multicast_sock < 0)
    return(-3);
  else {
    /* Bind eee->udp_multicast_sock to multicast group */
    struct ip_mreq mreq;
    u_int enable_reuse = 1;
    
    /* allow multiple sockets to use the same PORT number */
    setsockopt(eee->udp_multicast_sock, SOL_SOCKET, SO_REUSEADDR, &enable_reuse, sizeof(enable_reuse));
#ifdef SO_REUSEPORT /* no SO_REUSEPORT in Windows / old linux versions */
    setsockopt(eee->udp_multicast_sock, SOL_SOCKET, SO_REUSEPORT, &enable_reuse, sizeof(enable_reuse));
#endif

    mreq.imr_multiaddr.s_addr = inet_addr(N2N_MULTICAST_GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(eee->udp_multicast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
      traceEvent(TRACE_ERROR, "Failed to bind to local multicast group %s:%u [errno %u]",
		 N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT, errno);

#ifdef WIN32
      traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", WSAGetLastError());
#endif
      return(-4);
    }    
  }

  return(0);
}

/* ************************************** */

void edge_init_conf_defaults(n2n_edge_conf_t *conf) {
  memset(conf, 0, sizeof(*conf));

  conf->local_port = 0 /* any port */;
  conf->mgmt_port = N2N_EDGE_MGMT_PORT; /* 5644 by default */
  conf->transop_id = N2N_TRANSFORM_ID_NULL;
  conf->drop_multicast = 1;
  conf->register_interval = REGISTER_SUPER_INTERVAL_DFL;

  if(getenv("N2N_KEY")) {
    conf->encrypt_key = strdup(getenv("N2N_KEY"));
    conf->transop_id = N2N_TRANSFORM_ID_TWOFISH;
  }
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
  if((eee = edge_init(&tuntap, &conf, &rv)) == NULL)
    goto quick_edge_init_end;

  rv = run_edge_loop(eee, keep_on_running);
  edge_term(eee);

quick_edge_init_end:
  tuntap_close(&tuntap);
  return(rv);
}
