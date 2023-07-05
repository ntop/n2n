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

#ifndef _N2N_TYPEDEFS_H_
#define _N2N_TYPEDEFS_H_

#include <stdbool.h>
#include <stdint.h>     // for uint8_t and friends
#ifndef _WIN32
#include <arpa/inet.h>  // for in_addr_t
#include <sys/socket.h> // for sockaddr
#endif
#include <uthash.h>
#include <n2n_define.h>

typedef uint8_t  n2n_community_t[N2N_COMMUNITY_SIZE];
typedef uint8_t  n2n_private_public_key_t[N2N_PRIVATE_PUBLIC_KEY_SIZE];
typedef uint8_t  n2n_mac_t[N2N_MAC_SIZE];
typedef uint32_t n2n_cookie_t;
typedef uint8_t  n2n_desc_t[N2N_DESC_SIZE];
typedef char     n2n_sock_str_t[N2N_SOCKBUF_SIZE]; /* tracing string buffer */


#if defined(_MSC_VER) || defined(__MINGW32__)
#include "getopt.h"

/* Other Win environments are expected to support stdint.h */

/* stdint.h typedefs (C99) (not present in Visual Studio) */
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

#ifndef __MINGW32__
typedef int ssize_t;
#endif

typedef unsigned long in_addr_t;

#include "../src/win32/n2n_win32.h"
// FIXME - continue untangling the build and includes - dont have a ".." here

#endif /* #if defined(_MSC_VER) || defined(__MINGW32__) */

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <machine/endian.h>
#endif

#ifdef __OpenBSD__
#include <endian.h>
#define __BYTE_ORDER BYTE_ORDER
#if BYTE_ORDER == LITTLE_ENDIAN
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#endif /* __LITTLE_ENDIAN__ */
#else
#define __BIG_ENDIAN__
#endif/* BYTE_ORDER */
#endif/* __OPENBSD__ */


#if __BYTE_ORDER == __LITTLE_ENDIAN
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#endif
#else
#ifndef __BIG_ENDIAN__
#define __BIG_ENDIAN__
#endif
#endif

#ifdef _WIN32
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__ 1
#endif
#endif

#if !(defined(__LITTLE_ENDIAN__) || defined(__BIG_ENDIAN__))
#if defined(__mips__)
#undef __LITTLE_ENDIAN__
#undef __LITTLE_ENDIAN
#define __BIG_ENDIAN__
#endif

/* Everything else */
#if (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#else
#define __BIG_ENDIAN__
#endif
#endif

#endif

/* *************************************** */

#ifdef __GNUC__
#define PACK_STRUCT __attribute__((__packed__))
#else
#define PACK_STRUCT
#endif

#if defined(_MSC_VER) || defined(__MINGW32__)
#pragma pack(push,1)
#endif

#include <time.h>

// those are definitely not typedefs (with a view to the filename) but neither are they defines
static const n2n_mac_t broadcast_mac      = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static const n2n_mac_t multicast_mac      = { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x00 }; /* First 3 bytes are meaningful */
static const n2n_mac_t ipv6_multicast_mac = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x00 }; /* First 2 bytes are meaningful */
static const n2n_mac_t null_mac           = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


#define ETH_ADDR_LEN 6

struct ether_hdr {
    uint8_t    dhost[ETH_ADDR_LEN];
    uint8_t    shost[ETH_ADDR_LEN];
    uint16_t   type;                /* higher layer protocol encapsulated */
} PACK_STRUCT;

typedef struct ether_hdr ether_hdr_t;


struct n2n_iphdr {
#if defined(__LITTLE_ENDIAN__)
        uint8_t ihl:4, version:4;
#elif defined(__BIG_ENDIAN__)
        uint8_t version:4, ihl:4;
#else
# error "Byte order must be defined"
#endif
        uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
} PACK_STRUCT;

struct n2n_tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#if defined(__LITTLE_ENDIAN__)
    uint16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif defined(__BIG_ENDIAN__)
    uint16_t doff:4, res1:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#else
# error "Byte order must be defined"
#endif
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} PACK_STRUCT;

struct n2n_udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} PACK_STRUCT;

#if defined(_MSC_VER) || defined(__MINGW32__)
#pragma pack(pop)
#endif


typedef struct port_range {
    uint16_t start_port; // range contain 'start_port' self
    uint16_t end_port;   // range contain 'end_port' self
} port_range_t;

typedef struct filter_rule_key {
    in_addr_t            src_net_cidr;
    uint8_t              src_net_bit_len;
    port_range_t         src_port_range;
    in_addr_t            dst_net_cidr;
    uint8_t              dst_net_bit_len;
    port_range_t         dst_port_range;
    uint8_t              bool_tcp_configured;
    uint8_t              bool_udp_configured;
    uint8_t              bool_icmp_configured;
} filter_rule_key_t;

typedef struct filter_rule {
    filter_rule_key_t key;

    uint8_t              bool_accept_icmp;
    uint8_t              bool_accept_udp;
    uint8_t              bool_accept_tcp;

    UT_hash_handle hh;   /* makes this structure hashable */
} filter_rule_t;


/** Uncomment this to enable the MTU check, then try to ssh to generate a fragmented packet. */
/** NOTE: see doc/MTU.md for an explanation on the 1400 value */
//#define MTU_ASSERT_VALUE 1400

/** Common type used to hold stringified IP addresses. */
typedef char ipstr_t[INET_ADDRSTRLEN];

/** Common type used to hold stringified MAC addresses. */
#define N2N_MACSTR_SIZE 32
typedef char macstr_t[N2N_MACSTR_SIZE];
typedef char dec_ip_str_t[N2N_NETMASK_STR_SIZE];
typedef char dec_ip_bit_str_t[N2N_NETMASK_STR_SIZE + 4];
typedef char devstr_t[N2N_IFNAMSIZ];


#ifndef _WIN32
typedef struct tuntap_dev {
    int                  fd;
    int                  if_idx;
    n2n_mac_t            mac_addr;
    uint32_t             ip_addr;
    uint32_t             device_mask;
    uint16_t             mtu;
    devstr_t             dev_name;
} tuntap_dev;

#define SOCKET int
#else /* #ifndef _WIN32 */
typedef u_short sa_family_t;
#endif /* #ifndef _WIN32 */


typedef struct speck_context_t he_context_t;
typedef char n2n_sn_name_t[N2N_EDGE_SN_HOST_SIZE];

typedef enum n2n_pc {
    n2n_ping =               0,     /* Not used */
    n2n_register =           1,     /* Register edge to edge */
    n2n_deregister =         2,     /* Deregister this edge */
    n2n_packet =             3,     /* PACKET data content */
    n2n_register_ack =       4,     /* ACK of a registration from edge to edge */
    n2n_register_super =     5,     /* Register edge to supernode */
    n2n_unregister_super =   6,     /* Deregister edge from supernode */
    n2n_register_super_ack = 7,     /* ACK from supernode to edge */
    n2n_register_super_nak = 8,     /* NAK from supernode to edge - registration refused */
    n2n_federation =         9,     /* Not used by edge */
    n2n_peer_info =          10,    /* Send info on a peer from sn to edge */
    n2n_query_peer =         11,    /* ask supernode for info on a peer */
    n2n_re_register_super =  12     /* ask edge to re-register with supernode */
} n2n_pc_t;

#define N2N_FLAGS_OPTIONS                0x0080
#define N2N_FLAGS_SOCKET                 0x0040
#define N2N_FLAGS_FROM_SUPERNODE         0x0020

/* The bits in flag that are the packet type */
#define N2N_FLAGS_TYPE_MASK              0x001f  /* 0 - 31 */
#define N2N_FLAGS_BITS_MASK              0xffe0

#define IPV4_SIZE                        4
#define IPV6_SIZE                        16


#define N2N_AUTH_MAX_TOKEN_SIZE          48  /* max token size in bytes */
#define N2N_AUTH_CHALLENGE_SIZE          16  /* challenge always is of same size as dynamic key */
#define N2N_AUTH_ID_TOKEN_SIZE           16
#define N2N_AUTH_PW_TOKEN_SIZE           (N2N_PRIVATE_PUBLIC_KEY_SIZE + N2N_AUTH_CHALLENGE_SIZE)

#define N2N_EUNKNOWN                     -1
#define N2N_ENOTIMPL                     -2
#define N2N_EINVAL                       -3
#define N2N_ENOSPACE                     -4


#define N2N_VERSION_STRING_SIZE           20
typedef char n2n_version_t[N2N_VERSION_STRING_SIZE];


#define SN_SELECTION_STRATEGY_LOAD       1
#define SN_SELECTION_STRATEGY_RTT        2
#define SN_SELECTION_STRATEGY_MAC        3


typedef struct n2n_ip_subnet {
    uint32_t	    net_addr;       /* Host order IP address. */
    uint8_t         net_bitlen;     /* Subnet prefix. */
} n2n_ip_subnet_t;

typedef struct n2n_sock {
    uint8_t         family;           /* AF_INET, AF_INET6 or AF_INVALID (-1, a custom #define);
                                         mind that AF_UNSPEC (0) means auto IPv4 or IPv6 */
    uint8_t         type;             /* for later use, usually SOCK_STREAM (1) or SOCK_DGRAM (2) */
    uint16_t        port;             /* host order */
    union {
        uint8_t     v6[IPV6_SIZE];    /* byte sequence */
        uint8_t     v4[IPV4_SIZE];    /* byte sequence */
    } addr;
} n2n_sock_t;

typedef enum {
    n2n_auth_none =          0,
    n2n_auth_simple_id =     1,
    n2n_auth_user_password = 2
} n2n_auth_scheme_t;

typedef enum {
    update_edge_no_change =   0,
    update_edge_sock_change = 1,
    update_edge_new_sn =      2,
    update_edge_auth_fail =  -1
} update_edge_ret_value_t;

typedef struct n2n_auth {
    uint16_t        scheme;                         /* What kind of auth */
    uint16_t        token_size;                     /* Size of auth token */
    uint8_t         token[N2N_AUTH_MAX_TOKEN_SIZE]; /* Auth data interpreted based on scheme */
} n2n_auth_t;

typedef struct n2n_common {
    /* NOTE: wire representation is different! */
    /* int             version; */

    uint8_t            ttl;
    uint8_t            pc;
    uint16_t           flags;
    n2n_community_t    community;
} n2n_common_t;

typedef struct n2n_REGISTER {
    n2n_cookie_t       cookie;      /**< Link REGISTER and REGISTER_ACK */
    n2n_mac_t          srcMac;      /**< MAC of registering party */
    n2n_mac_t          dstMac;      /**< MAC of target edge */
    n2n_sock_t         sock;        /**< Supernode's view of edge socket OR edge's preferred local socket */
    n2n_ip_subnet_t    dev_addr;    /**< IP address of the tuntap adapter. */
    n2n_desc_t         dev_desc;    /**< Hint description correlated with the edge */
} n2n_REGISTER_t;

typedef struct n2n_REGISTER_ACK {
    n2n_cookie_t    cookie;    /**< Return cookie from REGISTER */
    n2n_mac_t       srcMac;    /**< MAC of acknowledging party (supernode or edge) */
    n2n_mac_t       dstMac;    /**< Reflected MAC of registering edge from REGISTER */
    n2n_sock_t      sock;      /**< Supernode's view of edge socket (IP Addr, port) */
} n2n_REGISTER_ACK_t;

typedef struct n2n_PACKET {
    n2n_mac_t     srcMac;
    n2n_mac_t     dstMac;
    n2n_sock_t    sock;
    uint8_t       transform;
    uint8_t       compression;
} n2n_PACKET_t;

/* Linked with n2n_register_super in n2n_pc_t. Only from edge to supernode. */
typedef struct n2n_REGISTER_SUPER {
    n2n_cookie_t       cookie;      /**< Link REGISTER_SUPER and REGISTER_SUPER_ACK */
    n2n_mac_t          edgeMac;     /**< MAC to register with edge sending socket */
    n2n_sock_t         sock;        /**< Sending socket associated with edgeMac */
    n2n_ip_subnet_t    dev_addr;    /**< IP address of the tuntap adapter. */
    n2n_desc_t         dev_desc;    /**< Hint description correlated with the edge */
    n2n_auth_t         auth;        /**< Authentication scheme and tokens */
    uint32_t           key_time;    /**< key time for dynamic key, used between federatred supernodes only */
} n2n_REGISTER_SUPER_t;


/* Linked with n2n_register_super_ack in n2n_pc_t. Only from supernode to edge. */
typedef struct n2n_REGISTER_SUPER_ACK {
    n2n_cookie_t       cookie;      /**< Return cookie from REGISTER_SUPER */
    n2n_mac_t          srcMac;      /**< MAC of answering supernode */
    n2n_ip_subnet_t    dev_addr;    /**< Assign an IP address to the tuntap adapter of edge. */
    uint16_t           lifetime;    /**< How long the registration will live */
    n2n_sock_t         sock;        /**< Sending sockets associated with edge */
    n2n_auth_t         auth;        /**< Authentication scheme and tokens */

    /** The packet format provides additional supernode definitions here.
     * uint8_t count, then for each count there is one
     * n2n_sock_t.
     */
    uint8_t            num_sn;      /**< Number of supernodes that were send
                                       * even if we cannot store them all. */

    uint32_t           key_time;    /**< key time for dynamic key, used between federatred supernodes only */
} n2n_REGISTER_SUPER_ACK_t;


/* Linked with n2n_register_super_ack in n2n_pc_t. Only from supernode to edge. */
typedef struct n2n_REGISTER_SUPER_NAK {
    n2n_cookie_t    cookie;    /* Return cookie from REGISTER_SUPER */
    n2n_mac_t       srcMac;
    n2n_auth_t      auth;      /* Authentication scheme and tokens */
} n2n_REGISTER_SUPER_NAK_t;


/* REGISTER_SUPER_ACK may contain extra payload (their number given by num_sn)
 * of following type describing a(nother) supernode */
typedef struct n2n_REGISTER_SUPER_ACK_payload {
    // REVISIT: interim for bugfix (https://github.com/ntop/n2n/issues/1029)
    //          remove with 4.0
    uint8_t       sock[sizeof(uint16_t) + sizeof(uint16_t) + IPV6_SIZE]; /**< socket of supernode */
    n2n_mac_t     mac;                                                   /**< MAC of supernode */
} n2n_REGISTER_SUPER_ACK_payload_t;


/* Linked with n2n_unregister_super in n2n_pc_t. */
typedef struct n2n_UNREGISTER_SUPER {
    n2n_auth_t     auth;
    n2n_mac_t      srcMac;
} n2n_UNREGISTER_SUPER_t;


typedef struct n2n_PEER_INFO {
    uint16_t                         aflags;
    n2n_mac_t                        srcMac;
    n2n_mac_t                        mac;
    n2n_sock_t                       sock;
    n2n_sock_t                       preferred_sock;
    uint32_t                         load;
    n2n_version_t                    version;
    time_t                           uptime;
} n2n_PEER_INFO_t;


typedef struct n2n_QUERY_PEER {
    uint16_t                      aflags;
    n2n_mac_t                     srcMac;
    n2n_sock_t                    sock;
    n2n_mac_t                     targetMac;

} n2n_QUERY_PEER_t;

typedef struct n2n_buf n2n_buf_t;

struct peer_info {
    n2n_mac_t                        mac_addr;
    n2n_ip_subnet_t                  dev_addr;
    n2n_desc_t                       dev_desc;
    n2n_sock_t                       sock;
    SOCKET                           socket_fd;
    n2n_sock_t                       preferred_sock;
    n2n_cookie_t                     last_cookie;
    n2n_auth_t                       auth;
    int                              timeout;
    bool                             purgeable;
    time_t                           last_seen;
    time_t                           last_p2p;
    time_t                           last_sent_query;
    SN_SELECTION_CRITERION_DATA_TYPE selection_criterion;
    uint64_t                         last_valid_time_stamp;
    char                             *ip_addr;
    uint8_t                          local;
    time_t                           uptime;
    n2n_version_t                    version;

    UT_hash_handle     hh; /* makes this structure hashable */
};

typedef struct peer_info peer_info_t;

#ifdef HAVE_BRIDGING_SUPPORT
struct host_info {
    n2n_mac_t                        mac_addr;
    n2n_mac_t                        edge_addr;
    time_t                           last_seen;
    UT_hash_handle     hh; /* makes this structure hashable */
};
#endif

typedef struct n2n_edge n2n_edge_t;

/* *************************************************** */

typedef enum {
    N2N_ACCEPT = 0,
    N2N_DROP =   1
} n2n_verdict;

/* *************************************************** */

typedef enum {
    FPP_UNKNOWN = 0,
    FPP_ARP =     1,
    FPP_TCP =     2,
    FPP_UDP =     3,
    FPP_ICMP =    4,
    FPP_IGMP =    5
} filter_packet_proto;


typedef struct packet_address_proto_info {
    in_addr_t           src_ip;
    uint16_t            src_port;
    in_addr_t           dst_ip;
    uint16_t            dst_port;
    filter_packet_proto proto;
}packet_address_proto_info_t;

typedef struct filter_rule_pair_cache {
    packet_address_proto_info_t key;

    uint8_t                     bool_allow_traffic;
    uint32_t                    active_count;

    UT_hash_handle hh;                 /* makes this structure hashable */
} filter_rule_pair_cache_t;

struct network_traffic_filter;
typedef struct network_traffic_filter network_traffic_filter_t;

struct network_traffic_filter {
    n2n_verdict (*filter_packet_from_peer)(network_traffic_filter_t* filter, n2n_edge_t *eee,
                                           const n2n_sock_t *peer, uint8_t *payload, uint16_t payload_size);

    n2n_verdict (*filter_packet_from_tap)(network_traffic_filter_t* filter, n2n_edge_t *eee, uint8_t *payload, uint16_t payload_size);

    filter_rule_t *rules;

    filter_rule_pair_cache_t *connections_rule_cache;

    uint32_t work_count_scene_last_clear;

};

/* *************************************************** */

/* Callbacks allow external programs to attach functions in response to
 * N2N events. */
typedef struct n2n_edge_callbacks {
    /* The supernode registration has been updated */
    void (*sn_registration_updated)(n2n_edge_t *eee, time_t now, const n2n_sock_t *sn);

    /* A packet has been received from a peer. N2N_DROP can be returned to
     * drop the packet. The packet payload can be modified. This only allows
     * the packet size to be reduced */
    n2n_verdict (*packet_from_peer)(n2n_edge_t *eee, const n2n_sock_t *peer, uint8_t *payload, uint16_t *payload_size);

    /* A packet has been received from the TAP interface. N2N_DROP can be
     * returned to drop the packet. The packet payload can be modified.
     * This only allows the packet size to be reduced */
    n2n_verdict (*packet_from_tap)(n2n_edge_t *eee, uint8_t *payload, uint16_t *payload_size);

    /* Called whenever the IP address of the TAP interface changes. */
    void (*ip_address_changed)(n2n_edge_t *eee, uint32_t old_ip, uint32_t new_ip);

    /* Called periodically in the main loop. */
    void (*main_loop_period)(n2n_edge_t *eee, time_t now);

    /* Called when a new socket to supernode is created. */
    void (*sock_opened)(n2n_edge_t *eee);
} n2n_edge_callbacks_t;

typedef struct n2n_tuntap_priv_config {
    devstr_t        tuntap_dev_name;
    char            ip_mode[N2N_IF_MODE_SIZE];
    dec_ip_str_t    ip_addr;
    dec_ip_str_t    netmask;
    char            device_mac[N2N_MACNAMSIZ];
    int             mtu;
    int             metric;
    uint8_t         daemon;
#ifndef _WIN32
    uid_t           userid;
    gid_t           groupid;
#endif
} n2n_tuntap_priv_config_t;

/* *************************************************** */

typedef enum n2n_transform {
    N2N_TRANSFORM_ID_INVAL =    0,
    N2N_TRANSFORM_ID_NULL =     1,
    N2N_TRANSFORM_ID_TWOFISH =  2,
    N2N_TRANSFORM_ID_AES =      3,
    N2N_TRANSFORM_ID_CHACHA20 = 4,
    N2N_TRANSFORM_ID_SPECK =    5,
} n2n_transform_t;

struct n2n_trans_op; /* Circular definition */

typedef int  (*n2n_transdeinit_f)(struct n2n_trans_op * arg);
typedef void (*n2n_transtick_f)(struct n2n_trans_op * arg, time_t now);
typedef int  (*n2n_transform_f)(struct n2n_trans_op * arg,
                                uint8_t * outbuf,
                                size_t out_len,
                                const uint8_t * inbuf,
                                size_t in_len,
                                const n2n_mac_t peer_mac);
/** Holds the info associated with a data transform plugin.
 *
 *  When a packet arrives the transform ID is extracted. This defines the code
 *  to use to decode the packet content. The transform code then decodes the
 *  packet and consults its internal key lookup.
 */
typedef struct n2n_trans_op {
    void *             priv;          /* opaque data. Key schedule goes here. */
    uint8_t            no_encryption; /* 1 if this transop does not perform encryption */
    n2n_transform_t    transform_id;
    size_t             tx_cnt;
    size_t             rx_cnt;

    n2n_transdeinit_f  deinit;        /* destructor function */
    n2n_transtick_f    tick;          /* periodic maintenance */
    n2n_transform_f    fwd;           /* encode a payload */
    n2n_transform_f    rev;           /* decode a payload */
} n2n_trans_op_t;


/* *************************************************** */


typedef struct n2n_resolve_ip_sock {
    char          *org_ip;            /* pointer to original ip/named address string (used read only) */
    n2n_sock_t    sock;               /* resolved socket */
    n2n_sock_t    *org_sock;          /* pointer to original socket where 'sock' gets copied to from time to time */
    int           error_code;         /* result of last resolution attempt */

    UT_hash_handle hh;                /* makes this structure hashable */
} n2n_resolve_ip_sock_t;


// structure to hold resolver thread's parameters
typedef struct n2n_resolve_parameter {
    n2n_resolve_ip_sock_t   *list;         /* pointer to list of to be resolved nodes */
    uint8_t                 changed;       /* indicates a change */
#ifdef HAVE_LIBPTHREAD
    pthread_t               id;            /* thread id */
    pthread_mutex_t         access;        /* mutex for shared access */
#endif
    uint8_t                 request;       /* flags main thread's need for intermediate resolution */
    time_t                  check_interval;/* interval to checik resolover results */
    time_t                  last_checked;  /* last time the resolver results were cheked */
    time_t                  last_resolved; /* last time the resolver completed */
} n2n_resolve_parameter_t;


/* *************************************************** */


typedef struct n2n_edge_conf {
    struct peer_info         *supernodes;            /**< List of supernodes */
    n2n_community_t          community_name;         /**< The community. 16 full octets. */
    n2n_desc_t               dev_desc;               /**< The device description (hint) */
    n2n_private_public_key_t *public_key;            /**< edge's public key (for user/password based authentication) */
    n2n_private_public_key_t *shared_secret;         /**< shared secret derived from federation public key, username and password */
    he_context_t             *shared_secret_ctx;     /**< context holding the roundkeys derived from shared secret */
    n2n_private_public_key_t *federation_public_key; /**< federation public key provided by command line */
    uint8_t                  header_encryption;      /**< Header encryption indicator. */
    he_context_t     *header_encryption_ctx_static;  /**< Header encryption cipher context. */
    he_context_t     *header_encryption_ctx_dynamic; /**< Header encryption cipher context. */
    he_context_t             *header_iv_ctx_static;  /**< Header IV ecnryption cipher context, REMOVE as soon as separate fileds for checksum and replay protection available */
    he_context_t             *header_iv_ctx_dynamic; /**< Header IV ecnryption cipher context, REMOVE as soon as separate fileds for checksum and replay protection available */
    n2n_transform_t          transop_id;             /**< The transop to use. */
    uint8_t                  compression;            /**< Compress outgoing data packets before encryption */
    uint8_t                  tuntap_ip_mode;         /**< Interface IP address allocated mode, eg. DHCP. */
    uint8_t                  allow_routing;          /**< Accept packet no to interface address. */
    uint8_t                  drop_multicast;         /**< Multicast ethernet addresses. */
    uint8_t                  disable_pmtu_discovery; /**< Disable the Path MTU discovery. */
    uint8_t                  allow_p2p;              /**< Allow P2P connection */
    uint8_t                  sn_num;                 /**< Number of supernode addresses defined. */
    uint8_t                  tos;                    /** TOS for sent packets */
    char                     *encrypt_key;
    int                      register_interval;      /**< Interval for supernode registration, also used for UDP NAT hole punching. */
    int                      register_ttl;           /**< TTL for registration packet when UDP NAT hole punching through supernode. */
    in_addr_t                bind_address;           /**< The address to bind to if provided */
    n2n_sock_t               preferred_sock;         /**< propagated local sock for better p2p in LAN (-e) */
    uint8_t                  preferred_sock_auto;    /**< indicates desired auto detect for preferred sock */
    int                      local_port;
    int                      mgmt_port;
    uint8_t                  connect_tcp;            /** connection to supernode 0 = UDP; 1 = TCP */
    n2n_auth_t               auth;
    filter_rule_t            *network_traffic_filter_rules;
    int                      metric;                /**< Network interface metric (Windows only). */
    uint8_t                  sn_selection_strategy; /**< encodes currently chosen supernode selection strategy. */
    uint8_t                  number_max_sn_pings;   /**< Number of maximum concurrently allowed supernode pings. */
    uint64_t                 mgmt_password_hash;    /**< contains hash of managament port password. */
} n2n_edge_conf_t;


struct n2n_edge_stats {
    uint32_t tx_p2p;
    uint32_t rx_p2p;
    uint32_t tx_sup;
    uint32_t rx_sup;
    uint32_t tx_sup_broadcast;
    uint32_t rx_sup_broadcast;
};

struct n2n_edge {
    n2n_edge_conf_t         conf;

    /* Status */
    bool                             *keep_running;                      /**< Pointer to edge loop stop/go flag */
    struct peer_info                 *curr_sn;                           /**< Currently active supernode. */
    uint8_t                          sn_wait;                            /**< Whether we are waiting for a supernode response. */
    uint8_t                          sn_pong;                            /**< Whether we have seen a PONG since last time reset. */
    size_t                           sup_attempts;                       /**< Number of remaining attempts to this supernode. */
    tuntap_dev                       device;                             /**< All about the TUNTAP device */
    n2n_trans_op_t                   transop;                            /**< The transop to use when encoding */
    n2n_trans_op_t                   transop_lzo;                        /**< The transop for LZO  compression */
#ifdef HAVE_ZSTD
    n2n_trans_op_t                   transop_zstd;                       /**< The transop for ZSTD compression */
#endif
    n2n_edge_callbacks_t cb;                                             /**< API callbacks */
    void                             *user_data;                         /**< Can hold user data */
    SN_SELECTION_CRITERION_DATA_TYPE sn_selection_criterion_common_data;

    /* Sockets */
    /* supernode socket is in        eee->curr_sn->sock (of type n2n_sock_t) */
    int                              sock;
    int                              close_socket_counter;               /**< counter for close-event before re-opening */
    int                              udp_mgmt_sock;                      /**< socket for status info. */

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    n2n_sock_t                       multicast_peer;                     /**< Multicast peer group (for local edges) */
    int                              udp_multicast_sock;                 /**< socket for local multicast registrations. */
    int                              multicast_joined;                   /**< 1 if the group has been joined.*/
#endif

    /* Peers */
    struct peer_info *               known_peers;                        /**< Edges we are connected to. */
    struct peer_info *               pending_peers;                      /**< Edges we have tried to register with. */
#ifdef HAVE_BRIDGING_SUPPORT
    struct host_info *               known_hosts;                        /**< hosts we know. */
#endif
/* Timers */
    time_t                           last_register_req;                  /**< Check if time to re-register with super*/
    time_t                           last_p2p;                           /**< Last time p2p traffic was received. */
    time_t                           last_sup;                           /**< Last time a packet arrived from supernode. */
    time_t                           last_sweep;                         /**< Last time a sweep was performed. */
    time_t                           start_time;                         /**< For calculating uptime */


    struct n2n_edge_stats            stats;                              /**< Statistics */

    n2n_resolve_parameter_t          *resolve_parameter;                 /**< Pointer to name resolver's parameter block */
    uint8_t                          resolution_request;                 /**< Flag an immediate DNS resolution request */

    n2n_tuntap_priv_config_t         tuntap_priv_conf;                   /**< Tuntap config */

    network_traffic_filter_t         *network_traffic_filter;
};

typedef struct sn_stats {
    size_t errors;         /* Number of errors encountered. */
    size_t reg_super;      /* Number of REGISTER_SUPER requests received. */
    size_t reg_super_nak;  /* Number of REGISTER_SUPER requests declined. */
    size_t fwd;            /* Number of messages forwarded. */
    size_t broadcast;      /* Number of messages broadcast to a community. */
    time_t last_fwd;       /* Time when last message was forwarded. */
    time_t last_reg_super; /* Time when last REGISTER_SUPER was received. */
} sn_stats_t;

typedef struct node_supernode_association {

    n2n_mac_t                   mac;        /* mac address of an edge                          */
    socklen_t                   sock_len;   /* amount of actually used space (of the following)    */
    union {
        struct sockaddr         sock;       /* network order socket of that edge's supernode       */
        struct sockaddr_storage sas;        /* the actual memory for it, sockaddr can be too small */
    };
    time_t                      last_seen;  /* time mark to keep track of purging requirements */

    UT_hash_handle hh;                      /* makes this structure hashable */
} node_supernode_association_t;

typedef struct sn_user {
    n2n_private_public_key_t   public_key;
    n2n_private_public_key_t   shared_secret;
    he_context_t               *shared_secret_ctx;
    n2n_desc_t                 name;

   UT_hash_handle hh;
} sn_user_t;

struct sn_community {
    char                          community[N2N_COMMUNITY_SIZE];
    uint8_t                       is_federation;          /* if not-zero, then the current community is the federation of supernodes */
    bool                          purgeable;              /* indicates purgeable community (fixed-name, predetermined (-c parameter) communties usually are unpurgeable) */
    uint8_t                       header_encryption;      /* Header encryption indicator. */
    he_context_t          *header_encryption_ctx_static;  /* Header encryption cipher context. */
    he_context_t          *header_encryption_ctx_dynamic; /* Header encryption cipher context. */
    he_context_t                  *header_iv_ctx_static;  /* Header IV encryption cipher context, REMOVE as soon as separate fields for checksum and replay protection available */
    he_context_t                  *header_iv_ctx_dynamic; /* Header IV encryption cipher context, REMOVE as soon as separate fields for checksum and replay protection available */
    uint8_t                       dynamic_key[N2N_AUTH_CHALLENGE_SIZE]; /* dynamic key */
    struct                        peer_info *edges;       /* Link list of registered edges. */
    node_supernode_association_t  *assoc;                 /* list of other edges from this community and their supernodes */
    sn_user_t                     *allowed_users;         /* list of allowed users */
    int64_t                       number_enc_packets;     /* Number of encrypted packets handled so far, required for sorting from time to time */
    n2n_ip_subnet_t               auto_ip_net;            /* Address range of auto ip address service. */

    UT_hash_handle hh;                                    /* makes this structure hashable */
};

/* Typedef'd pointer to get abstract datatype. */
typedef struct regex_t* re_t;

struct sn_community_regular_expression {
    re_t rule;         /* compiles regular expression */

    UT_hash_handle hh; /* makes this structure hashable */
};


typedef struct n2n_tcp_connection {
    int    socket_fd;                                     /* file descriptor for tcp socket */
    socklen_t                   sock_len;                 /* amount of actually used space (of the following) */
    union {
        struct sockaddr         sock;                     /* network order socket */
        struct sockaddr_storage sas;                      /* memory for it, can be longer than sockaddr */
    };
    uint16_t expected;                                    /* number of bytes expected to be read */
    uint16_t position;                                    /* current position in the buffer */
    uint8_t  buffer[N2N_PKT_BUF_SIZE + sizeof(uint16_t)]; /* buffer for data collected from tcp socket incl. prepended length */
    uint8_t  inactive;                                    /* connection not be handled if set, already closed and to be deleted soon */

    UT_hash_handle hh; /* makes this structure hashable */
} n2n_tcp_connection_t;


typedef struct n2n_sn {
    bool                                   *keep_running;   /* Pointer to sn loop stop/go flag */
    time_t                                 start_time;      /* Used to measure uptime. */
    n2n_version_t                          version;         /* version string sent to edges along with PEER_INFO a.k.a. PONG */
    sn_stats_t                             stats;
    int                                    daemon;          /* If non-zero then daemonise. */
    n2n_mac_t                              mac_addr;
    in_addr_t                              bind_address;    /* The address to bind to if provided */
    uint16_t                               lport;           /* Local UDP port to bind to. */
    uint16_t                               mport;           /* Management UDP port to bind to. */
    int                                    sock;            /* Main socket for UDP traffic with edges. */
    int                                    tcp_sock;        /* auxiliary socket for optional TCP connections */
    n2n_tcp_connection_t                   *tcp_connections;/* list of established TCP connections */
    int                                    mgmt_sock;       /* management socket. */
    n2n_ip_subnet_t                        min_auto_ip_net; /* Address range of auto_ip service. */
    n2n_ip_subnet_t                        max_auto_ip_net; /* Address range of auto_ip service. */
#ifndef _WIN32
    uid_t                                  userid;
    gid_t                                  groupid;
#endif
    int                                    lock_communities; /* If true, only loaded and matching communities can be used. */
    char                                   *community_file;
    struct sn_community                    *communities;
    struct sn_community_regular_expression *rules;
    struct sn_community                    *federation;
    n2n_private_public_key_t               private_key;       /* private federation key derived from federation name */
    n2n_auth_t                             auth;
    uint32_t                               dynamic_key_time;  /* UTC time of last dynamic key generation (second accuracy) */
    uint8_t                                override_spoofing_protection; /* set if overriding MAC/IP spoofing protection (cli option '-M') */
    n2n_resolve_parameter_t                *resolve_parameter;/*Pointer to name resolver's parameter block */
    uint64_t                               mgmt_password_hash;/* contains hash of managament port password */
} n2n_sn_t;


/* *************************************************** */

#endif /* _N2N_TYPEDEFS_H_ */
