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

/* N2N packet header indicators. */
#define MSG_TYPE_REGISTER               1
#define MSG_TYPE_DEREGISTER             2
#define MSG_TYPE_PACKET                 3
#define MSG_TYPE_REGISTER_ACK           4
#define MSG_TYPE_REGISTER_SUPER         5
#define MSG_TYPE_REGISTER_SUPER_ACK     6
#define MSG_TYPE_REGISTER_SUPER_NAK     7
#define MSG_TYPE_FEDERATION             8
#define MSG_TYPE_PEER_INFO              9
#define MSG_TYPE_QUERY_PEER            10
#define MSG_TYPE_MAX_TYPE	       10

#define SOCKET_TIMEOUT_INTERVAL_SECS    10
#define REGISTER_SUPER_INTERVAL_DFL     20 /* sec, usually UDP NAT entries in a firewall expire after 30 seconds */

#define IFACE_UPDATE_INTERVAL           (30) /* sec. How long it usually takes to get an IP lease. */
#define TRANSOP_TICK_INTERVAL           (10) /* sec */

#define ETH_FRAMESIZE 14
#define IP4_SRCOFFSET 12
#define IP4_DSTOFFSET 16
#define IP4_MIN_SIZE  20
#define UDP_SIZE      8

/* N2N compression indicators. */
/* Compression is disabled by default for outgoing packets if no cli
 * option is given. All edges are built with decompression support so
 * they are able to understand each other (this applies to lzo only). */
#define N2N_COMPRESSION_ID_NONE		0	/* default, see edge_init_conf_defaults(...) in edge_utils.c */
#define N2N_COMPRESSION_ID_LZO		1	/* set if '-z1' or '-z' cli option is present, see setOption(...) in edge.c */
#ifdef N2N_HAVE_ZSTD
#define N2N_COMPRESSION_ID_ZSTD		2	/* set if '-z2' cli option is present, available only if compiled with zstd lib */
#define ZSTD_COMPRESSION_LEVEL		7	/* 1 (faster) ... 22 (more compression) */
#endif
// with the next major packet structure update, make '0' = invalid, and '1' = no compression
// '2' = LZO, '3' = ZSTD, ... REVISIT then (also: change all occurences in source).

#define N2N_COMPRESSION_ID_BITLEN	3	/* number of bits used for encoding compression id in the uppermost
				 	           bits of transform_id; will be obsolete as soon as compression gets
						   its own field in the packet. REVISIT then. */

/* Header encryption indicators */
#define HEADER_ENCRYPTION_UNKNOWN       0
#define HEADER_ENCRYPTION_NONE          1
#define HEADER_ENCRYPTION_ENABLED       2

#define DEFAULT_MTU   1290

#define HASH_ADD_PEER(head,add)				\
  HASH_ADD(hh,head,mac_addr,sizeof(n2n_mac_t),add)
#define HASH_FIND_PEER(head,mac,out)		\
  HASH_FIND(hh,head,mac,sizeof(n2n_mac_t),out)
#define N2N_EDGE_SN_HOST_SIZE   48
#define N2N_EDGE_NUM_SUPERNODES 2
#define N2N_EDGE_SUP_ATTEMPTS   3       /* Number of failed attmpts before moving on to next supernode. */
#define N2N_PATHNAME_MAXLEN     256
#define N2N_EDGE_MGMT_PORT      5644

/* ************************************** */

#define SUPERNODE_IP    "127.0.0.1"
#define SUPERNODE_PORT  1234

/* ************************************** */

#ifndef max
#define max(a, b) ((a < b) ? b : a)
#endif

#ifndef min
#define min(a, b) ((a > b) ? b : a)
#endif

