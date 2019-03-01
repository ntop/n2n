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

#if defined(DEBUG)
#define SOCKET_TIMEOUT_INTERVAL_SECS    5
#define REGISTER_SUPER_INTERVAL_DFL     20 /* sec */
#else  /* #if defined(DEBUG) */
#define SOCKET_TIMEOUT_INTERVAL_SECS    10
#define REGISTER_SUPER_INTERVAL_DFL     60 /* sec */
#endif /* #if defined(DEBUG) */

#define REGISTER_SUPER_INTERVAL_MIN     5    /* sec */
#define REGISTER_SUPER_INTERVAL_MAX     3600 /* sec */

#define IFACE_UPDATE_INTERVAL           (30) /* sec. How long it usually takes to get an IP lease. */
#define TRANSOP_TICK_INTERVAL           (10) /* sec */

#ifdef __ANDROID_NDK__
#define ARP_PERIOD_INTERVAL             (10) /* sec */
#endif

/** Positions in the transop array where various transforms are stored.
 *
 *  Used by transop_enum_to_index(). See also the transform enumerations in
 *  n2n_transforms.h */
#define N2N_TRANSOP_NULL_IDX    0
#define N2N_TRANSOP_TF_IDX      1
#define N2N_TRANSOP_AESCBC_IDX  2
/* etc. */

#define ETH_FRAMESIZE 14
#define IP4_SRCOFFSET 12
#define IP4_DSTOFFSET 16

/* ************************************** */

/** Initialise an edge to defaults.
 *
 *  This also initialises the NULL transform operation opstruct.
 */
int edge_init(n2n_edge_t * eee) {
#ifdef WIN32
  initWin32();
#endif
  memset(eee, 0, sizeof(n2n_edge_t));
  eee->start_time = time(NULL);

  transop_null_init(   &(eee->transop[N2N_TRANSOP_NULL_IDX]));
  transop_twofish_init(&(eee->transop[N2N_TRANSOP_TF_IDX] ));
  transop_aes_init(&(eee->transop[N2N_TRANSOP_AESCBC_IDX] ));

  eee->tx_transop_idx = N2N_TRANSOP_NULL_IDX; /* No guarantee the others have been setup */

  eee->daemon = 1;    /* By default run in daemon mode. */
  eee->preferred_aes = 0; /* Disable AES by default (for compatibility) */
  eee->re_resolve_supernode_ip = 0;
  /* keyschedule set to NULLs by memset */
  /* community_name set to NULLs by memset */
  eee->null_transop   = 0;
  eee->udp_sock       = -1;
  eee->udp_mgmt_sock  = -1;
  eee->udp_multicast_sock = -1;
  eee->dyn_ip_mode    = 0;
  eee->allow_routing  = 0;
  eee->drop_multicast = 1;
  eee->known_peers    = NULL;
  eee->pending_peers  = NULL;
  eee->last_register_req = 0;
  eee->register_lifetime = REGISTER_SUPER_INTERVAL_DFL;
  eee->last_p2p = 0;
  eee->last_sup = 0;
  eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;

  if(lzo_init() != LZO_E_OK) {
    traceEvent(TRACE_ERROR, "LZO compression error");
    return(-1);
  }

  return(0);
}

/* ***************************************************** */

/** Resolve the supernode IP address.
 *
 *  REVISIT: This is a really bad idea. The edge will block completely while the
 *           hostname resolution is performed. This could take 15 seconds.
 */
void supernode2addr(n2n_sock_t * sn, const n2n_sn_name_t addrIn) {
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
  send_register(eee, &(eee->multicast_peer));   
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
static void try_send_register(n2n_edge_t * eee,
			      uint8_t from_supernode,
			      const n2n_mac_t mac,
			      const n2n_sock_t * peer) {
  /* REVISIT: purge of pending_peers not yet done. */
  struct peer_info * scan = find_peer_by_mac(eee->pending_peers, mac);
  macstr_t mac_buf;
  n2n_sock_str_t sockbuf;

  if(scan == NULL) {
    scan = calloc(1, sizeof(struct peer_info));

    memcpy(scan->mac_addr, mac, N2N_MAC_SIZE);
    scan->sock = *peer;
    scan->last_seen = time(NULL); /* Don't change this it marks the pending peer for removal. */

    peer_list_add(&(eee->pending_peers), scan);

    traceEvent(TRACE_DEBUG, "=== new pending %s -> %s",
	       macaddr_str(mac_buf, scan->mac_addr),
	       sock_to_cstr(sockbuf, &(scan->sock)));

    traceEvent(TRACE_INFO, "Pending peers list size=%u",
	       (unsigned int)peer_list_size(eee->pending_peers));

    /* trace Sending REGISTER */
    send_register(eee, &(scan->sock));

    register_with_local_peers(eee);
  }
}

/* ************************************** */

/** Update the last_seen time for this peer, or get registered. */
void check_peer(n2n_edge_t * eee,
		uint8_t from_supernode,
		const n2n_mac_t mac,
		const n2n_sock_t * peer) {
  struct peer_info * scan = find_peer_by_mac(eee->known_peers, mac);
  
  if(scan == NULL) {
    /* Not in known_peers - start the REGISTER process. */
    try_send_register(eee, from_supernode, mac, peer);
  } else {
    /* Already in known_peers. */
    time_t now = time(NULL);

    if((now - scan->last_seen) > 0 /* >= 1 sec */) {
      /* Don't register too often */
      update_peer_address(eee, from_supernode, mac, peer, now);
    }
  }
}
/* ************************************** */


/* Move the peer from the pending_peers list to the known_peers lists.
 *
 * peer must be a pointer to an element of the pending_peers list.
 *
 * Called by main loop when Rx a REGISTER_ACK.
 */
void set_peer_operational(n2n_edge_t * eee,
			  const n2n_mac_t mac,
			  const n2n_sock_t * peer) {
  struct peer_info * prev = NULL;
  struct peer_info * scan;
  macstr_t mac_buf;
  n2n_sock_str_t sockbuf;

  traceEvent(TRACE_INFO, "set_peer_operational: %s -> %s",
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

      traceEvent(TRACE_INFO, "Operational peers list size=%u",
		 (unsigned int)peer_list_size(eee->known_peers));


      scan->last_seen = time(NULL);
    }
  else
    {
      traceEvent(TRACE_DEBUG, "Failed to find sender in pending_peers.");
    }
}

/* ************************************** */

n2n_mac_t broadcast_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

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

/** Keep the known_peers list straight.
 *
 *  Ignore broadcast L2 packets, and packets with invalid public_ip.
 *  If the dst_mac is in known_peers make sure the entry is correct:
 *  - if the public_ip socket has changed, erase the entry
 *  - if the same, update its last_seen = when
 */
void update_peer_address(n2n_edge_t * eee,
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
    {
      /* Not to be registered. */
      return;
    }

  if(0 == memcmp(mac, broadcast_mac, N2N_MAC_SIZE))
    {
      /* Not to be registered. */
      return;
    }


  while(scan != NULL)
    {
      if(memcmp(mac, scan->mac_addr, N2N_MAC_SIZE) == 0)
        {
	  break;
        }

      prev = scan;
      scan = scan->next;
    }

  if(NULL == scan)
    {
      /* Not in known_peers. */
      return;
    }

  if(0 != sock_equal(&(scan->sock), peer))
    {
      if(0 == from_supernode)
        {
	  traceEvent(TRACE_NORMAL, "Peer changed %s: %s -> %s",
		     macaddr_str(mac_buf, scan->mac_addr),
		     sock_to_cstr(sockbuf1, &(scan->sock)),
		     sock_to_cstr(sockbuf2, peer));

	  /* The peer has changed public socket. It can no longer be assumed to be reachable. */
	  /* Remove the peer. */
	  if(NULL == prev)
            {
	      /* scan was head of list */
	      eee->known_peers = scan->next;
            }
	  else
            {
	      prev->next = scan->next;
            }
	  free(scan);

	  try_send_register(eee, from_supernode, mac, peer);
        }
      else
        {
	  /* Don't worry about what the supernode reports, it could be seeing a different socket. */
        }
    }
  else
    {
      /* Found and unchanged. */
      scan->last_seen = when;
    }
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
  uint8_t pktbuf[N2N_PKT_BUF_SIZE];
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
  memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);

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
void send_register(n2n_edge_t * eee,
		   const n2n_sock_t * remote_peer) {
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
  memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);

  idx=0;
  encode_uint32(reg.cookie, &idx, 123456789);
  idx=0;
  encode_mac(reg.srcMac, &idx, eee->device.mac_addr);

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
  memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);

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
void update_supernode_reg(n2n_edge_t * eee, time_t nowTime) {
  u_int sn_idx;
  
  if(eee->sn_wait && (nowTime > (eee->last_register_req + (eee->register_lifetime/10)))) {
    /* fall through */
    traceEvent(TRACE_DEBUG, "update_supernode_reg: doing fast retry.");
  } else if(nowTime < (eee->last_register_req + eee->register_lifetime))
    return; /* Too early */

  if(0 == eee->sup_attempts) {
    /* Give up on that supernode and try the next one. */
    ++(eee->sn_idx);

    if (eee->sn_idx >= eee->sn_num) {
      /* Got to end of list, go back to the start. Also works for list of one entry. */
      eee->sn_idx=0;
    }

    traceEvent(TRACE_WARNING, "Supernode not responding - moving to %u of %u",
	       (unsigned int)eee->sn_idx, (unsigned int)eee->sn_num);

    eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;
  }
  else
    --(eee->sup_attempts);

  for(sn_idx=0; sn_idx<eee->sn_num; sn_idx++) {
    supernode2addr(&(eee->supernode), eee->sn_ip_array[sn_idx]);
    
    traceEvent(TRACE_NORMAL, "Registering with supernode [id: %u/%u][%s][attempts left %u]",
	       sn_idx+1, eee->sn_num,
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
const char * supernode_ip(const n2n_edge_t * eee) {
  return (eee->sn_ip_array)[eee->sn_idx];
}

/* ************************************** */

int edge_init_twofish_psk(n2n_edge_t * eee, uint8_t *encrypt_pwd,
		      uint32_t encrypt_pwd_len) {
  return transop_twofish_setup_psk(&(eee->transop[N2N_TRANSOP_TF_IDX]),
			       0, encrypt_pwd, encrypt_pwd_len);
}

/* ************************************** */

int edge_init_aes_psk(n2n_edge_t * eee, uint8_t *encrypt_pwd,
		      uint32_t encrypt_pwd_len) {
  return transop_aes_setup_psk(&(eee->transop[N2N_TRANSOP_AESCBC_IDX]),
			       0, encrypt_pwd, encrypt_pwd_len);
}

/* ************************************** */

static n2n_tostat_t n2n_tick_aes(n2n_edge_t * eee, time_t now, size_t *trop) {
  n2n_tostat_t tst = (eee->transop[N2N_TRANSOP_AESCBC_IDX].tick)(&(eee->transop[N2N_TRANSOP_AESCBC_IDX]), now);

  if(tst.can_tx)
    {
      traceEvent(TRACE_DEBUG, "can_tx AESCBC (idx=%u)", (unsigned int)N2N_TRANSOP_AESCBC_IDX);
      *trop = N2N_TRANSOP_AESCBC_IDX;
    }

  return tst;
}

/* ************************************** */
static n2n_tostat_t n2n_tick_twofish(n2n_edge_t * eee, time_t now, size_t *trop) {
  n2n_tostat_t tst = (eee->transop[N2N_TRANSOP_TF_IDX].tick)(&(eee->transop[N2N_TRANSOP_TF_IDX]), now);
  if(tst.can_tx)
    {
      traceEvent(TRACE_DEBUG, "can_tx TF (idx=%u)", (unsigned int)N2N_TRANSOP_TF_IDX);
      *trop = N2N_TRANSOP_TF_IDX;
    }

  return tst;
}

/* ************************************** */

/** Called periodically to roll keys and do any periodic maintenance in the
 *  tranform operations state machines. */
static int n2n_tick_transop(n2n_edge_t * eee, time_t now)
{
  size_t trop = eee->tx_transop_idx;

  /* Tests are done in order that most preferred transform is last and causes
   * tx_transop_idx to be left at most preferred valid transform. */
  (eee->transop[N2N_TRANSOP_NULL_IDX].tick)(&(eee->transop[N2N_TRANSOP_NULL_IDX]), now);

  if(eee->preferred_aes) {
    n2n_tick_twofish(eee, now, &trop);
    n2n_tick_aes(eee, now, &trop);
  } else {
    n2n_tick_aes(eee, now, &trop);
    n2n_tick_twofish(eee, now, &trop);
  }

  if(trop != eee->tx_transop_idx)
    {
      eee->tx_transop_idx = trop;
      traceEvent(TRACE_NORMAL, "Chose new tx_transop_idx=%u", (unsigned int)(eee->tx_transop_idx));
    }

  return 0;
}

/* ************************************** */

/** Find the transop op-struct for the transform enumeration required.
 *
 * @return - index into the transop array, or -1 on failure.
 */
int transop_enum_to_index(n2n_transform_t id) {
  switch (id)
    {
    case N2N_TRANSFORM_ID_TWOFISH:
      return N2N_TRANSOP_TF_IDX;
      break;
    case N2N_TRANSFORM_ID_NULL:
      return N2N_TRANSOP_NULL_IDX;
      break;
    case N2N_TRANSFORM_ID_AESCBC:
      return N2N_TRANSOP_AESCBC_IDX;
      break;
    default:
      return -1;
    }
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
      ++(eee->rx_sup);
      eee->last_sup=now;
    }
  else
    {
      ++(eee->rx_p2p);
      eee->last_p2p=now;
    }

  /* Update the sender in peer table entry */
  check_peer(eee, from_supernode, pkt->srcMac, orig_sender);

  /* Handle transform. */
  {
    uint8_t decodebuf[N2N_PKT_BUF_SIZE];
    size_t eth_size;
    int rx_transop_idx;

    rx_transop_idx = transop_enum_to_index(pkt->transform);

    if(rx_transop_idx >=0)
      {
	eth_payload = decodebuf;
	eh = (ether_hdr_t*)eth_payload;
	eth_size = eee->transop[rx_transop_idx].rev(&(eee->transop[rx_transop_idx]),
						    eth_payload, N2N_PKT_BUF_SIZE,
						    payload, psize, pkt->srcMac);
	++(eee->transop[rx_transop_idx].rx_cnt); /* stats */

	if(!(eee->allow_routing)) {
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
	traceEvent(TRACE_ERROR, "handle_PACKET dropped unknown transform enum %u",
		   (unsigned int)pkt->transform);
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
	  ++traceLevel;

	  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
			      "Help for edge management console:\n"
			      "  stop    Gracefully exit edge\n"
			      "  help    This help message\n"
			      "  +verb   Increase verbosity of logging\n"
			      "  -verb   Decrease verbosity of logging\n"
			      "  reload  Re-read the keyschedule\n"
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
	  ++traceLevel;

	  traceEvent(TRACE_ERROR, "+verb traceLevel=%u", (unsigned int)traceLevel);
	  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
			      "> +OK traceLevel=%u\n", (unsigned int)traceLevel);

	  sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0/*flags*/,
		 (struct sockaddr *)&sender_sock, sizeof(struct sockaddr_in));

	  return;
        }

      if(0 == memcmp(udp_buf, "-verb", 5))
        {
	  msg_len=0;

	  if(traceLevel > 0)
            {
	      --traceLevel;
	      msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
				  "> -OK traceLevel=%u\n", traceLevel);
            }
	  else
            {
	      msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
				  "> -NOK traceLevel=%u\n", traceLevel);
            }

	  traceEvent(TRACE_ERROR, "-verb traceLevel=%u", (unsigned int)traceLevel);

	  sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0/*flags*/,
		 (struct sockaddr *)&sender_sock, sizeof(struct sockaddr_in));
	  return;
        }
    }

  if(recvlen >= 6)
    {
      if(0 == memcmp(udp_buf, "reload", 6))
        {
	  if(strlen(eee->keyschedule) > 0)
            {
	      if(edge_init_keyschedule(eee) == 0)
                {
		  msg_len=0;
		  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
				      "> OK\n");
		  sendto(eee->udp_mgmt_sock, udp_buf, msg_len, 0/*flags*/,
			 (struct sockaddr *)&sender_sock, sizeof(struct sockaddr_in));
                }
	      return;
            }
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
		      (unsigned int)eee->tx_sup,
		      (unsigned int)eee->rx_sup,
		      (unsigned int)eee->tx_p2p,
		      (unsigned int)eee->rx_p2p);

  msg_len += snprintf((char *)(udp_buf+msg_len), (N2N_PKT_BUF_SIZE-msg_len),
		      "trans:null |%6u|%6u|\n"
		      "trans:tf   |%6u|%6u|\n"
		      "trans:aes  |%6u|%6u|\n",
		      (unsigned int)eee->transop[N2N_TRANSOP_NULL_IDX].tx_cnt,
		      (unsigned int)eee->transop[N2N_TRANSOP_NULL_IDX].rx_cnt,
		      (unsigned int)eee->transop[N2N_TRANSOP_TF_IDX].tx_cnt,
		      (unsigned int)eee->transop[N2N_TRANSOP_TF_IDX].rx_cnt,
		      (unsigned int)eee->transop[N2N_TRANSOP_AESCBC_IDX].tx_cnt,
		      (unsigned int)eee->transop[N2N_TRANSOP_AESCBC_IDX].rx_cnt);

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

/* Choose the transop for Tx. This should be based on the newest valid
 * cipherspec in the key schedule.
 *
 * Never fall back to NULL tranform unless no key sources were specified. It is
 * better to render edge inoperative than to expose user data in the clear. In
 * the case where all SAs are expired an arbitrary transform will be chosen for
 * Tx. It will fail having no valid SAs but one must be selected.
 */
static size_t edge_choose_tx_transop(const n2n_edge_t * eee) {
  if(eee->null_transop)
    {
      return N2N_TRANSOP_NULL_IDX;
    }

  return eee->tx_transop_idx;
}

/* ************************************** */

/* @return 1 if destination is a peer, 0 if destination is supernode */
static int find_peer_destination(n2n_edge_t * eee,
                                 n2n_mac_t mac_address,
                                 n2n_sock_t * destination) {
  const struct peer_info *scan = eee->known_peers;
  macstr_t mac_buf;
  n2n_sock_str_t sockbuf;
  int retval=0;

  traceEvent(TRACE_DEBUG, "Searching destination peer for MAC %02X:%02X:%02X:%02X:%02X:%02X",
	     mac_address[0] & 0xFF, mac_address[1] & 0xFF, mac_address[2] & 0xFF,
	     mac_address[3] & 0xFF, mac_address[4] & 0xFF, mac_address[5] & 0xFF);

  while(scan != NULL) {
    traceEvent(TRACE_DEBUG, "Evaluating peer [MAC=%02X:%02X:%02X:%02X:%02X:%02X]",
	       scan->mac_addr[0] & 0xFF, scan->mac_addr[1] & 0xFF, scan->mac_addr[2] & 0xFF,
	       scan->mac_addr[3] & 0xFF, scan->mac_addr[4] & 0xFF, scan->mac_addr[5] & 0xFF
	       );

    if((scan->last_seen > 0) &&
       (memcmp(mac_address, scan->mac_addr, N2N_MAC_SIZE) == 0))
      {
	memcpy(destination, &scan->sock, sizeof(n2n_sock_t));
	retval=1;
	break;
      }
    scan = scan->next;
  }

  if(0 == retval)
    {
      memcpy(destination, &(eee->supernode), sizeof(struct sockaddr_in));
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
  int dest;
  /*ssize_t s; */
  n2n_sock_str_t sockbuf;
  n2n_sock_t destination;

  /* hexdump(pktbuf, pktlen); */

  dest = find_peer_destination(eee, dstMac, &destination);

  if(dest)
    ++(eee->tx_p2p);
  else
    ++(eee->tx_sup);

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
  size_t tx_transop_idx=0;

  ether_hdr_t eh;

  /* tap_pkt is not aligned so we have to copy to aligned memory */
  memcpy(&eh, tap_pkt, sizeof(ether_hdr_t));

  /* Discard IP packets that are not originated by this hosts */
  if(!(eee->allow_routing)) {
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
  memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);

  memset(&pkt, 0, sizeof(pkt));
  memcpy(pkt.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
  memcpy(pkt.dstMac, destMac, N2N_MAC_SIZE);

  tx_transop_idx = edge_choose_tx_transop(eee);

  pkt.sock.family=0; /* do not encode sock */
  pkt.transform = eee->transop[tx_transop_idx].transform_id;

  idx=0;
  encode_PACKET(pktbuf, &idx, &cmn, &pkt);
  traceEvent(TRACE_DEBUG, "encoded PACKET header of size=%u transform %u (idx=%u)",
	     (unsigned int)idx, (unsigned int)pkt.transform, (unsigned int)tx_transop_idx);

  idx += eee->transop[tx_transop_idx].fwd(&(eee->transop[tx_transop_idx]),
					  pktbuf+idx, N2N_PKT_BUF_SIZE-idx,
					  tap_pkt, len, pkt.dstMac);
  ++(eee->transop[tx_transop_idx].tx_cnt); /* stats */

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

      if(eee->drop_multicast &&
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
    traceEvent(TRACE_ERROR, "recvfrom failed with %s", strerror(errno));
    
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

  if(0 == memcmp(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE)) {
      if(msg_type == MSG_TYPE_PACKET) {
	  /* process PACKET - most frequent so first in list. */
	  n2n_PACKET_t pkt;

	  decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx);

	  if(pkt.sock.family)
            {
	      orig_sender = &(pkt.sock);
            }

	  traceEvent(TRACE_INFO, "Rx PACKET from %s (%s)",
		     sock_to_cstr(sockbuf1, &sender),
		     sock_to_cstr(sockbuf2, orig_sender));

	  handle_PACKET(eee, &cmn, &pkt, orig_sender, udp_buf+idx, recvlen-idx);
        } else if(msg_type == MSG_TYPE_REGISTER) {
	  /* Another edge is registering with us */
	  n2n_REGISTER_t reg;
	  n2n_mac_t null_mac = { '\0' };
	  int skip_register = 0;
	  
	  decode_REGISTER(&reg, &cmn, udp_buf, &rem, &idx);

	  if(reg.sock.family)
	    orig_sender = &(reg.sock);

	  traceEvent(TRACE_INFO, "Rx REGISTER src=%s dst=%s from peer %s (%s)",
		     macaddr_str(mac_buf1, reg.srcMac),
		     macaddr_str(mac_buf2, reg.dstMac),
		     sock_to_cstr(sockbuf1, &sender),
		     sock_to_cstr(sockbuf2, orig_sender));

	  if(!memcmp(reg.dstMac, eee->device.mac_addr, 6))
	    check_peer(eee, from_supernode, reg.srcMac, orig_sender);
	  else if(// (sender.port == N2N_MULTICAST_PORT) &&
		  (!memcmp(reg.dstMac, null_mac, 6))) { /* Announce via a multicast socket */
	    if(memcmp(reg.srcMac, eee->device.mac_addr, 6)) /* It's not our self-announce */
	      check_peer(eee, from_supernode, reg.srcMac, orig_sender);
	    else {
	      traceEvent(TRACE_INFO, "Skipping REGISTER from self");
	      skip_register = 1; /* do not register with ourselves */
	    }
	  }

	  if(!skip_register)
	    send_register_ack(eee, orig_sender, &reg);
        }
      else if(msg_type == MSG_TYPE_REGISTER_ACK)
        {
	  /* Peer edge is acknowledging our register request */
	  n2n_REGISTER_ACK_t ra;

	  decode_REGISTER_ACK(&ra, &cmn, udp_buf, &rem, &idx);

	  if(ra.sock.family)
	    orig_sender = &(ra.sock);

	  traceEvent(TRACE_INFO, "Rx REGISTER_ACK src=%s dst=%s from peer %s (%s)",
		     macaddr_str(mac_buf1, ra.srcMac),
		     macaddr_str(mac_buf2, ra.dstMac),
		     sock_to_cstr(sockbuf1, &sender),
		     sock_to_cstr(sockbuf2, orig_sender));

	  /* Move from pending_peers to known_peers; ignore if not in pending. */
	  set_peer_operational(eee, ra.srcMac, &sender);
        }
      else if(msg_type == MSG_TYPE_REGISTER_SUPER_ACK)
        {
	  n2n_REGISTER_SUPER_ACK_t ra;

	  if(eee->sn_wait)
            {
	      decode_REGISTER_SUPER_ACK(&ra, &cmn, udp_buf, &rem, &idx);

	      if(ra.sock.family)
                {
		  orig_sender = &(ra.sock);
                }

	      traceEvent(TRACE_NORMAL, "Rx REGISTER_SUPER_ACK myMAC=%s [%s] (external %s). Attempts %u",
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

		  /* REVISIT: store sn_back */
		  eee->register_lifetime = ra.lifetime;
		  eee->register_lifetime = MAX(eee->register_lifetime, REGISTER_SUPER_INTERVAL_MIN);
		  eee->register_lifetime = MIN(eee->register_lifetime, REGISTER_SUPER_INTERVAL_MAX);
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
        }
      else
        {
	  /* Not a known message type */
	  traceEvent(TRACE_WARNING, "Unable to handle packet type %d: ignored", (signed int)msg_type);
	  return;
        }
    } /* if (community match) */
  else
    {
      traceEvent(TRACE_WARNING, "Received packet with invalid community");
    }
}

/* ************************************** */

int run_edge_loop(n2n_edge_t * eee, int *keep_running) {
  size_t numPurged;
  time_t lastIfaceCheck=0;
  time_t lastTransop=0;
#ifdef __ANDROID_NDK__
  time_t lastArpPeriod=0;
#endif

#ifdef WIN32
  startTunReadThread(eee);
#endif

  *keep_running = 1;
      
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
      
      n2n_tick_transop(eee, nowTime);
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

    numPurged =  purge_expired_registrations(&(eee->known_peers));
    numPurged += purge_expired_registrations(&(eee->pending_peers));

    if(numPurged > 0) {
      traceEvent(TRACE_NORMAL, "Peer removed: pending=%u, operational=%u",
		 (unsigned int)peer_list_size(eee->pending_peers),
		 (unsigned int)peer_list_size(eee->known_peers));
    }

    if(eee->dyn_ip_mode &&
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
  tuntap_close(&(eee->device));

  edge_term(eee);

  return(0);
}

/* ************************************** */

/** Read in a key-schedule file, parse the lines and pass each line to the
 *  appropriate trans_op for parsing of key-data and adding key-schedule
 *  entries. The lookup table of time->trans_op is constructed such that
 *  encoding can be passed to the correct trans_op. The trans_op internal table
 *  will then determine the best SA for that trans_op from the key schedule to
 *  use for encoding. */

int edge_init_keyschedule(n2n_edge_t * eee) {
#define N2N_NUM_CIPHERSPECS 32

  int retval = -1;
  ssize_t numSpecs=0;
  n2n_cipherspec_t specs[N2N_NUM_CIPHERSPECS];
  size_t i;
  time_t now = time(NULL);

  numSpecs = n2n_read_keyfile(specs, N2N_NUM_CIPHERSPECS, eee->keyschedule);

  if(numSpecs > 0)
    {
      traceEvent(TRACE_NORMAL, "keyfile = %s read -> %d specs.\n", optarg, (signed int)numSpecs);

      for (i=0; i < (size_t)numSpecs; ++i)
        {
	  int idx;

	  idx = transop_enum_to_index(specs[i].t);

	  switch (idx)
            {
            case N2N_TRANSOP_TF_IDX:
            case N2N_TRANSOP_AESCBC_IDX:
	      {
                retval = (eee->transop[idx].addspec)(&(eee->transop[idx]),
						     &(specs[i]));
                break;
	      }
            default:
	      retval = -1;
            }

	  if (0 != retval)
            {
	      traceEvent(TRACE_ERROR, "keyschedule failed to add spec[%u] to transop[%d].\n",
			 (unsigned int)i, idx);

	      return retval;
            }
        }

      n2n_tick_transop(eee, now);
    }
  else    
    traceEvent(TRACE_ERROR, "Failed to process '%s'", eee->keyschedule);
    
  return retval;
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

  (eee->transop[N2N_TRANSOP_TF_IDX].deinit)(&eee->transop[N2N_TRANSOP_TF_IDX]);
  (eee->transop[N2N_TRANSOP_NULL_IDX].deinit)(&eee->transop[N2N_TRANSOP_NULL_IDX]);
}

/* ************************************** */

const char *random_device_mac(void)
{
  const char key[] = "0123456789abcdef";
  static char mac[18];
  int i;

  srand(getpid());
  for (i = 0; i < sizeof(mac) - 1; ++i) {
    if ((i + 1) % 3 == 0) {
      mac[i] = ':';
      continue;
    }
#ifdef WIN32
#define random rand
#endif
    mac[i] = key[random() % sizeof(key)];
#ifdef WIN32
#undef random
#endif
  }
  mac[sizeof(mac) - 1] = '\0';
  return mac;
}

/* ************************************** */

int quick_edge_init(char *device_name, char *community_name,
		    char *encrypt_key, char *device_mac,
		    char *local_ip_address,
		    char *supernode_ip_address_port,
		    int *keep_on_running) {
  n2n_edge_t eee;

  edge_init(&eee);
  
  if(tuntap_open(&(eee.device), device_name, "static",
		 local_ip_address, "255.255.255.0",
		 device_mac, DEFAULT_MTU) < 0)
    return(-1);

  if(edge_init_aes_psk(&eee, (uint8_t *)encrypt_key, strlen(encrypt_key)) < 0)
    return(-2);
  if(edge_init_twofish_psk(&eee, (uint8_t *)encrypt_key, strlen(encrypt_key)) < 0)
    return(-2);

  snprintf((char*)eee.community_name, sizeof(eee.community_name), "%s", community_name);
  supernode2addr(&(eee.supernode), supernode_ip_address_port);
  
  eee.udp_sock = open_socket(0 /* any port */, 1 /* bind ANY */);
  if(eee.udp_sock < 0)
    return(-3);  
  
  eee.udp_mgmt_sock = open_socket(0 /* any port */, 0 /* bind LOOPBACK */);
  if(eee.udp_mgmt_sock < 0)
    return(-4);

  eee.udp_multicast_sock = open_socket(N2N_MULTICAST_PORT, 1 /* bind ANY */);
  if(eee.udp_multicast_sock < 0)
    return(-5);
  else {
    /* Bind eee.udp_multicast_sock to multicast group */
    struct ip_mreq mreq;
    u_int enable_reuse = 1;
    
    /* allow multiple sockets to use the same PORT number */
    setsockopt(eee.udp_multicast_sock, SOL_SOCKET, SO_REUSEADDR, &enable_reuse, sizeof(enable_reuse));
#ifndef WIN32 /* no SO_REUSEPORT in Windows */
	  setsockopt(eee.udp_multicast_sock, SOL_SOCKET, SO_REUSEPORT, &enable_reuse, sizeof(enable_reuse));
#endif

    mreq.imr_multiaddr.s_addr = inet_addr(N2N_MULTICAST_GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(eee.udp_multicast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
      traceEvent(TRACE_ERROR, "Failed to bind to local multicast group %s:%u",
		 N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT);
      return(-6);
    }    
  }
  
  update_supernode_reg(&eee, time(NULL));
  
  return(run_edge_loop(&eee, keep_on_running));
}
