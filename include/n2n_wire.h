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

#if !defined( N2N_WIRE_H_ )
#define N2N_WIRE_H_

#include <stdlib.h>
#ifndef _MSC_VER
/* Not included in Visual Studio 2008 */
#include <stdint.h>
#endif

#define N2N_PKT_VERSION                 2
#define N2N_DEFAULT_TTL                 2       /* can be forwarded twice at most */
#define N2N_COMMUNITY_SIZE              16
#define N2N_MAC_SIZE                    6
#define N2N_COOKIE_SIZE                 4
#define N2N_PKT_BUF_SIZE                2048
#define N2N_SOCKBUF_SIZE                64      /* string representation of INET or INET6 sockets */

#define N2N_MULTICAST_PORT              1968
#define N2N_MULTICAST_GROUP             "224.0.0.68"

typedef uint8_t n2n_community_t[N2N_COMMUNITY_SIZE];
typedef uint8_t n2n_mac_t[N2N_MAC_SIZE];
typedef uint8_t n2n_cookie_t[N2N_COOKIE_SIZE];

typedef char    n2n_sock_str_t[N2N_SOCKBUF_SIZE];       /* tracing string buffer */

#if defined(WIN32)
#include "win32/n2n_win32.h"
#else /* #if defined(WIN32) */
#include <netinet/in.h>
#include <sys/socket.h> /* AF_INET and AF_INET6 */
#endif /* #if defined(WIN32) */

typedef enum n2n_pc
{
    n2n_ping=0,                 /* Not used */
    n2n_register=1,             /* Register edge to edge */
    n2n_deregister=2,           /* Deregister this edge */
    n2n_packet=3,               /* PACKET data content */
    n2n_register_ack=4,         /* ACK of a registration from edge to edge */
    n2n_register_super=5,       /* Register edge to supernode */
    n2n_register_super_ack=6,   /* ACK from supernode to edge */
    n2n_register_super_nak=7,   /* NAK from supernode to edge - registration refused */
    n2n_federation=8,           /* Not used by edge */
    n2n_peer_info=9,            /* Send info on a peer from sn to edge */
    n2n_query_peer=10           /* ask supernode for info on a peer */
} n2n_pc_t;

#define N2N_FLAGS_OPTIONS               0x0080
#define N2N_FLAGS_SOCKET                0x0040
#define N2N_FLAGS_FROM_SUPERNODE        0x0020

/* The bits in flag that are the packet type */
#define N2N_FLAGS_TYPE_MASK             0x001f  /* 0 - 31 */
#define N2N_FLAGS_BITS_MASK             0xffe0

#define IPV4_SIZE                       4
#define IPV6_SIZE                       16


#define N2N_AUTH_TOKEN_SIZE             32      /* bytes */


#define N2N_EUNKNOWN                    -1
#define N2N_ENOTIMPL                    -2
#define N2N_EINVAL                      -3
#define N2N_ENOSPACE                    -4

typedef struct n2n_ip_subnet {
	uint32_t            net_addr;       /* Host order IP address. */
	uint8_t             net_bitlen;     /* Subnet prefix. */
} n2n_ip_subnet_t;


typedef struct n2n_sock
{
    uint8_t     family;         /* AF_INET or AF_INET6; or 0 if invalid */
    uint16_t    port;           /* host order */
    union
    {
    uint8_t     v6[IPV6_SIZE];  /* byte sequence */
    uint8_t     v4[IPV4_SIZE];  /* byte sequence */
    } addr;
} n2n_sock_t;

typedef struct n2n_auth
{
    uint16_t    scheme;                         /* What kind of auth */
    uint16_t    toksize;                        /* Size of auth token */
    uint8_t     token[N2N_AUTH_TOKEN_SIZE];     /* Auth data interpreted based on scheme */
} n2n_auth_t;

typedef struct n2n_common
{
    /* NOTE: wire representation is different! */
    /* int                 version; */

    uint8_t             ttl;
    uint8_t             pc;
    uint16_t            flags;
    n2n_community_t     community;
} n2n_common_t;

typedef struct n2n_REGISTER
{
	n2n_cookie_t         cookie;         /**< Link REGISTER and REGISTER_ACK */
	n2n_mac_t            srcMac;         /**< MAC of registering party */
	n2n_mac_t            dstMac;         /**< MAC of target edge */
	n2n_sock_t           sock;           /**< REVISIT: unused? */
} n2n_REGISTER_t;

typedef struct n2n_REGISTER_ACK
{
	n2n_cookie_t         cookie;         /**< Return cookie from REGISTER */
	n2n_mac_t            srcMac;         /**< MAC of acknowledging party (supernode or edge) */
	n2n_mac_t            dstMac;         /**< Reflected MAC of registering edge from REGISTER */
	n2n_sock_t           sock;           /**< Supernode's view of edge socket (IP Addr, port) */
} n2n_REGISTER_ACK_t;

typedef struct n2n_PACKET
{
    n2n_mac_t           srcMac;
    n2n_mac_t           dstMac;
    n2n_sock_t          sock;
    uint16_t            transform;
    uint16_t		compression;
} n2n_PACKET_t;

/* Linked with n2n_register_super in n2n_pc_t. Only from edge to supernode. */
typedef struct n2n_REGISTER_SUPER {
	n2n_cookie_t        cookie;         /**< Link REGISTER_SUPER and REGISTER_SUPER_ACK */
	n2n_mac_t           edgeMac;        /**< MAC to register with edge sending socket */
	n2n_ip_subnet_t     dev_addr;       /**< IP address of the tuntap adapter. */
	n2n_auth_t          auth;           /**< Authentication scheme and tokens */
} n2n_REGISTER_SUPER_t;


/* Linked with n2n_register_super_ack in n2n_pc_t. Only from supernode to edge. */
typedef struct n2n_REGISTER_SUPER_ACK {
	n2n_cookie_t         cookie;        /**< Return cookie from REGISTER_SUPER */
	n2n_mac_t            edgeMac;       /**< MAC registered to edge sending socket */
	n2n_ip_subnet_t      dev_addr;      /**< Assign an IP address to the tuntap adapter of edge. */
	uint16_t             lifetime;      /**< How long the registration will live */
	n2n_sock_t           sock;          /**< Sending sockets associated with edgeMac */

	/** The packet format provides additional supernode definitions here.
	 * uint8_t count, then for each count there is one
	 * n2n_sock_t.
	 */
	uint8_t              num_sn;         /**< Number of supernodes that were send
                                         * even if we cannot store them all. If
                                         * non-zero then sn_bak is valid. */
	n2n_sock_t           sn_bak;         /**< Socket of the first backup supernode */
} n2n_REGISTER_SUPER_ACK_t;


/* Linked with n2n_register_super_ack in n2n_pc_t. Only from supernode to edge. */
typedef struct n2n_REGISTER_SUPER_NAK
{
    n2n_cookie_t        cookie;         /* Return cookie from REGISTER_SUPER */
} n2n_REGISTER_SUPER_NAK_t;


typedef struct n2n_PEER_INFO {
	uint16_t             aflags;
	n2n_mac_t            mac;
	n2n_sock_t           sock;
} n2n_PEER_INFO_t;


typedef struct n2n_QUERY_PEER
{
  n2n_mac_t           srcMac;
  n2n_mac_t           targetMac;
} n2n_QUERY_PEER_t;

typedef struct n2n_buf n2n_buf_t;

int encode_uint8( uint8_t * base,
                  size_t * idx,
                  const uint8_t v );

int decode_uint8( uint8_t * out,
                  const uint8_t * base,
                  size_t * rem,
                  size_t * idx );

int encode_uint16( uint8_t * base,
                   size_t * idx,
                   const uint16_t v );

int decode_uint16( uint16_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );

int encode_uint32( uint8_t * base,
                   size_t * idx,
                   const uint32_t v );

int decode_uint32( uint32_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );

int encode_buf( uint8_t * base,
                size_t * idx,
                const void * p,
                size_t s);

int decode_buf( uint8_t * out,
                size_t bufsize,
                const uint8_t * base,
                size_t * rem,
                size_t * idx );

int encode_mac( uint8_t * base,
                size_t * idx,
                const n2n_mac_t m );

int decode_mac( uint8_t * out, /* of size N2N_MAC_SIZE. This clearer than passing a n2n_mac_t */
                const uint8_t * base,
                size_t * rem,
                size_t * idx );

int encode_common( uint8_t * base,
                   size_t * idx,
                   const n2n_common_t * common );

int decode_common( n2n_common_t * out,
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );

int encode_sock( uint8_t * base,
                 size_t * idx,
                 const n2n_sock_t * sock );

int decode_sock( n2n_sock_t * sock,
                 const uint8_t * base,
                 size_t * rem,
                 size_t * idx );

int encode_REGISTER( uint8_t * base,
                     size_t * idx,
                     const n2n_common_t * common,
                     const n2n_REGISTER_t * reg );

int decode_REGISTER( n2n_REGISTER_t * pkt,
                     const n2n_common_t * cmn, /* info on how to interpret it */
                     const uint8_t * base,
                     size_t * rem,
                     size_t * idx );

int encode_REGISTER_SUPER( uint8_t * base,
                           size_t * idx,
                           const n2n_common_t * common,
                           const n2n_REGISTER_SUPER_t * reg );

int decode_REGISTER_SUPER( n2n_REGISTER_SUPER_t * pkt,
                           const n2n_common_t * cmn, /* info on how to interpret it */
                           const uint8_t * base,
                           size_t * rem,
                           size_t * idx );

int encode_REGISTER_ACK( uint8_t * base,
                         size_t * idx,
                         const n2n_common_t * common,
                         const n2n_REGISTER_ACK_t * reg );

int decode_REGISTER_ACK( n2n_REGISTER_ACK_t * pkt,
                         const n2n_common_t * cmn, /* info on how to interpret it */
                         const uint8_t * base,
                         size_t * rem,
                         size_t * idx );

int encode_REGISTER_SUPER_ACK( uint8_t * base,
                               size_t * idx,
                               const n2n_common_t * cmn,
                               const n2n_REGISTER_SUPER_ACK_t * reg );

int decode_REGISTER_SUPER_ACK( n2n_REGISTER_SUPER_ACK_t * reg,
                               const n2n_common_t * cmn, /* info on how to interpret it */
                               const uint8_t * base,
                               size_t * rem,
                               size_t * idx );

int fill_sockaddr( struct sockaddr * addr,
                   size_t addrlen,
                   const n2n_sock_t * sock );

int encode_PACKET( uint8_t * base,
                   size_t * idx,
                   const n2n_common_t * common,
                   const n2n_PACKET_t * pkt );

int decode_PACKET( n2n_PACKET_t * pkt,
                   const n2n_common_t * cmn, /* info on how to interpret it */
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );

int encode_PEER_INFO( uint8_t * base,
                   size_t * idx,
                   const n2n_common_t * common,
                   const n2n_PEER_INFO_t * pkt );

int decode_PEER_INFO( n2n_PEER_INFO_t * pkt,
                   const n2n_common_t * cmn, /* info on how to interpret it */
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );

int encode_QUERY_PEER( uint8_t * base,
                   size_t * idx,
                   const n2n_common_t * common,
                   const n2n_QUERY_PEER_t * pkt );

int decode_QUERY_PEER( n2n_QUERY_PEER_t * pkt,
                   const n2n_common_t * cmn, /* info on how to interpret it */
                   const uint8_t * base,
                   size_t * rem,
                   size_t * idx );

#endif /* #if !defined( N2N_WIRE_H_ ) */
