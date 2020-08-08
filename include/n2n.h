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

#ifndef _N2N_H_
#define _N2N_H_

/*
  tunctl -t tun0
  tunctl -t tun1
  ifconfig tun0 1.2.3.4 up
  ifconfig tun1 1.2.3.5 up
  ./edge -d tun0 -l 2000 -r 127.0.0.1:3000 -c hello
  ./edge -d tun1 -l 3000 -r 127.0.0.1:2000 -c hello


  tunctl -u UID -t tunX
*/


/* #define N2N_CAN_NAME_IFACE */

/* Moved here to define _CRT_SECURE_NO_WARNINGS before all the including takes place */
#ifdef WIN32
#ifdef _MSC_VER
#include "config.h" /* Visual C++ */
#else
#include "win32/winconfig.h"
#endif
#define N2N_CAN_NAME_IFACE 1
#undef N2N_HAVE_DAEMON
#undef N2N_HAVE_SETUID
#else
#ifndef CMAKE_BUILD
#include "config.h"
#endif
#endif



#define PACKAGE_BUILDDATE (__DATE__ " " __TIME__)

#include <time.h>
#include <ctype.h>
#include <stdlib.h>

#ifndef WIN32
#include <netdb.h>
#endif

#ifndef _MSC_VER
#include <getopt.h>
#endif /* #ifndef _MSC_VER */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <pthread.h>

#ifdef __linux__
#define N2N_CAN_NAME_IFACE 1
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#define GRND_NONBLOCK       1
#endif /* #ifdef __linux__ */

#ifdef __FreeBSD__
#include <netinet/in_systm.h>
#endif /* #ifdef __FreeBSD__ */

#include <syslog.h>
#include <sys/wait.h>

#if defined (__RDRND__) || defined (__RDSEED__)
#include <immintrin.h>
#endif

#define ETH_ADDR_LEN 6

struct ether_hdr
{
  uint8_t  dhost[ETH_ADDR_LEN];
  uint8_t  shost[ETH_ADDR_LEN];
  uint16_t type;                /* higher layer protocol encapsulated */
} __attribute__ ((__packed__));

typedef struct ether_hdr ether_hdr_t;

#ifdef HAVE_LIBZSTD
#include <zstd.h>
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <stdint.h>
#ifdef N2N_HAVE_AES
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#endif


#define closesocket(a) close(a)
#endif /* #ifndef WIN32 */

#include "minilzo.h"
#include "n2n_define.h"
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include "uthash.h"
#include "lzoconf.h"

#ifdef WIN32
#include "win32/wintap.h"
#include <sys/stat.h>
#else
#include <pwd.h>
#endif /* #ifdef WIN32 */

#include "n2n_wire.h"
#include "n2n_transforms.h"
#include "random_numbers.h"
#include "pearson.h"
#include "portable_endian.h"
#include "speck.h"

#ifdef WIN32
#define N2N_IFNAMSIZ            64
#else
#define N2N_IFNAMSIZ            16 /* 15 chars * NULL */
#endif

#ifndef WIN32
typedef struct tuntap_dev {
	int             fd;
	int             if_idx;
	n2n_mac_t       mac_addr;
	uint32_t        ip_addr;
	uint32_t        device_mask;
	uint16_t        mtu;
	char            dev_name[N2N_IFNAMSIZ];
} tuntap_dev;

#define SOCKET int
#endif /* #ifndef WIN32 */

/** Uncomment this to enable the MTU check, then try to ssh to generate a fragmented packet. */
/** NOTE: see doc/MTU.md for an explanation on the 1400 value */
//#define MTU_ASSERT_VALUE 1400

/** Common type used to hold stringified IP addresses. */
typedef char ipstr_t[32];

/** Common type used to hold stringified MAC addresses. */
#define N2N_MACSTR_SIZE 32
typedef char macstr_t[N2N_MACSTR_SIZE];
typedef char dec_ip_str_t[N2N_NETMASK_STR_SIZE];
typedef char dec_ip_bit_str_t[N2N_NETMASK_STR_SIZE + 4];


struct peer_info {
	n2n_mac_t        mac_addr;
	n2n_ip_subnet_t  dev_addr;
	n2n_sock_t       sock;
	int              timeout;
	time_t           last_seen;
	time_t           last_p2p;
	time_t           last_sent_query;
	uint64_t         last_valid_time_stamp;

	UT_hash_handle   hh; /* makes this structure hashable */
};


typedef struct speck_context_t he_context_t;
typedef char n2n_sn_name_t[N2N_EDGE_SN_HOST_SIZE];

typedef struct n2n_route {
	in_addr_t        net_addr;
	uint8_t          net_bitlen;
	in_addr_t        gateway;
} n2n_route_t;

typedef struct n2n_edge n2n_edge_t;

/* *************************************************** */

typedef enum {
  N2N_ACCEPT = 0,
  N2N_DROP = 1
} n2n_verdict;

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
} n2n_edge_callbacks_t;

/* ***************************************************** */

typedef struct n2n_tuntap_priv_config {
	char                tuntap_dev_name[N2N_IFNAMSIZ];
	char                ip_mode[N2N_IF_MODE_SIZE];
	dec_ip_str_t        ip_addr;
	dec_ip_str_t        netmask;
	char                device_mac[N2N_MACNAMSIZ];
	int                 mtu;
	uint8_t             got_s;
	uint8_t             daemon;
#ifndef WIN32
	uid_t               userid;
	gid_t               groupid;
#endif
} n2n_tuntap_priv_config_t;

/* *************************************************** */


typedef struct n2n_edge_conf {
	n2n_sn_name_t       sn_ip_array[N2N_EDGE_NUM_SUPERNODES];
	n2n_route_t         *routes;                /**< Networks to route through n2n */
	n2n_community_t     community_name;         /**< The community. 16 full octets. */
	uint8_t	            header_encryption;      /**< Header encryption indicator. */
	he_context_t        *header_encryption_ctx; /**< Header encryption cipher context. */
	he_context_t        *header_iv_ctx;         /**< Header IV ecnryption cipher context, REMOVE as soon as seperte fileds for checksum and replay protection available */
	n2n_transform_t     transop_id;             /**< The transop to use. */
	uint16_t            compression;            /**< Compress outgoing data packets before encryption */
	uint16_t            num_routes;	            /**< Number of routes in routes */
	uint8_t             tuntap_ip_mode;         /**< Interface IP address allocated mode, eg. DHCP. */
	uint8_t             allow_routing;          /**< Accept packet no to interface address. */
	uint8_t             drop_multicast;         /**< Multicast ethernet addresses. */
	uint8_t             disable_pmtu_discovery; /**< Disable the Path MTU discovery. */
	uint8_t             allow_p2p;              /**< Allow P2P connection */
	uint8_t             sn_num;                 /**< Number of supernode addresses defined. */
	uint8_t             tos;                    /** TOS for sent packets */
	char                *encrypt_key;
	int                 register_interval;      /**< Interval for supernode registration, also used for UDP NAT hole punching. */
	int                 register_ttl;           /**< TTL for registration packet when UDP NAT hole punching through supernode. */
	int                 local_port;
	int                 mgmt_port;
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
	n2n_edge_conf_t     conf;

	/* Status */
	uint8_t             sn_idx;                  /**< Currently active supernode. */
	uint8_t             sn_wait;                 /**< Whether we are waiting for a supernode response. */
	size_t              sup_attempts;            /**< Number of remaining attempts to this supernode. */
	tuntap_dev          device;                  /**< All about the TUNTAP device */
	n2n_trans_op_t      transop;                 /**< The transop to use when encoding */
	n2n_cookie_t        last_cookie;             /**< Cookie sent in last REGISTER_SUPER. */
	n2n_route_t         *sn_route_to_clean;      /**< Supernode route to clean */
	n2n_edge_callbacks_t cb;                     /**< API callbacks */
	void 	            *user_data;              /**< Can hold user data */
	uint64_t            sn_last_valid_time_stamp;/**< last valid time stamp from supernode */

	/* Sockets */
	n2n_sock_t          supernode;
	int                 udp_sock;
	int                 udp_mgmt_sock;           /**< socket for status info. */

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
	n2n_sock_t          multicast_peer;          /**< Multicast peer group (for local edges) */
	int                 udp_multicast_sock;      /**< socket for local multicast registrations. */
	int                 multicast_joined;        /**< 1 if the group has been joined.*/
#endif

	/* Peers */
	struct peer_info *  known_peers;             /**< Edges we are connected to. */
	struct peer_info *  pending_peers;           /**< Edges we have tried to register with. */

	/* Timers */
	time_t              last_register_req;       /**< Check if time to re-register with super*/
	time_t              last_p2p;                /**< Last time p2p traffic was received. */
	time_t              last_sup;                /**< Last time a packet arrived from supernode. */
	time_t              start_time;              /**< For calculating uptime */


	struct n2n_edge_stats stats;                 /**< Statistics */

	n2n_tuntap_priv_config_t tuntap_priv_conf;   /**< Tuntap config */
};


typedef struct sn_stats
{
    size_t errors;         /* Number of errors encountered. */
    size_t reg_super;      /* Number of REGISTER_SUPER requests received. */
    size_t reg_super_nak;  /* Number of REGISTER_SUPER requests declined. */
    size_t fwd;            /* Number of messages forwarded. */
    size_t broadcast;      /* Number of messages broadcast to a community. */
    time_t last_fwd;       /* Time when last message was forwarded. */
    time_t last_reg_super; /* Time when last REGISTER_SUPER was received. */
} sn_stats_t;

struct sn_community
{
  char community[N2N_COMMUNITY_SIZE];
  uint8_t	      header_encryption;      /* Header encryption indicator. */
  he_context_t        *header_encryption_ctx; /* Header encryption cipher context. */
  he_context_t        *header_iv_ctx;	      /* Header IV ecnryption cipher context, REMOVE as soon as seperate fields for checksum and replay protection available */
  struct peer_info *edges; 		      /* Link list of registered edges. */
  int64_t	      number_enc_packets;     /* Number of encrypted packets handled so far, required for sorting from time to time */

  UT_hash_handle hh; /* makes this structure hashable */
};

typedef struct n2n_sn {
	time_t start_time;         /* Used to measure uptime. */
	sn_stats_t stats;
	int daemon;                /* If non-zero then daemonise. */
	uint16_t lport;            /* Local UDP port to bind to. */
	uint16_t mport;            /* Management UDP port to bind to. */
	int sock;                  /* Main socket for UDP traffic with edges. */
	int mgmt_sock;             /* management socket. */
	n2n_ip_subnet_t dhcp_addr; /* Address range of dhcp service. */
#ifndef WIN32
	uid_t userid;
	gid_t groupid;
#endif
	int lock_communities;      /* If true, only loaded communities can be used. */
	struct sn_community *communities;
} n2n_sn_t;

/* ************************************** */

#include "header_encryption.h"
#include "twofish.h"

#ifndef TRACE_ERROR
#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__
#define TRACE_DEBUG     4, __FILE__, __LINE__
#endif

/* ************************************** */

/* Transop Init Functions */
int n2n_transop_null_init(const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
int n2n_transop_twofish_init(const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
#ifdef N2N_HAVE_AES
int n2n_transop_aes_cbc_init(const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
#endif
#ifdef HAVE_OPENSSL_1_1
int n2n_transop_cc20_init(const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
#endif
int n2n_transop_speck_init(const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);

/* Log */
void setTraceLevel(int level);
void setUseSyslog(int use_syslog);
void setTraceFile(FILE *f);
int getTraceLevel();
void closeTraceFile();
void traceEvent(int eventTraceLevel, char* file, int line, char * format, ...);

/* Tuntap API */
int tuntap_open(tuntap_dev *device, char *dev, const char *address_mode, char *device_ip,
			char *device_mask, const char * device_mac, int mtu);
int tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, int len);
int tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, int len);
void tuntap_close(struct tuntap_dev *tuntap);
void tuntap_get_address(struct tuntap_dev *tuntap);

/* Utils */
char* intoa(uint32_t addr, char* buf, uint16_t buf_len);
uint32_t bitlen2mask(uint8_t bitlen);
uint8_t mask2bitlen(uint32_t mask);
char* macaddr_str(macstr_t buf, const n2n_mac_t mac);
int str2mac( uint8_t * outmac /* 6 bytes */, const char * s );
uint8_t is_multi_broadcast(const uint8_t * dest_mac);
char* msg_type2str(uint16_t msg_type);
void hexdump(const uint8_t * buf, size_t len);
void print_n2n_version();
int is_empty_ip_address(const n2n_sock_t * sock);
void print_edge_stats(const n2n_edge_t *eee);

/* Sockets */
char* sock_to_cstr( n2n_sock_str_t out,
                            const n2n_sock_t * sock );
char * ip_subnet_to_str(dec_ip_bit_str_t buf, const n2n_ip_subnet_t *ipaddr);
SOCKET open_socket(int local_port, int bind_any);
int sock_equal( const n2n_sock_t * a,
                       const n2n_sock_t * b );

/* Header encryption */
uint64_t time_stamp(void);
uint64_t initial_time_stamp (void);
int time_stamp_verify_and_update (uint64_t stamp, uint64_t * previous_stamp);

/* Operations on peer_info lists. */
size_t purge_peer_list( struct peer_info ** peer_list,
                        time_t purge_before );
size_t clear_peer_list( struct peer_info ** peer_list );
size_t purge_expired_registrations( struct peer_info ** peer_list, time_t* p_last_purge );

/* Edge conf */
void edge_init_conf_defaults(n2n_edge_conf_t *conf);
int edge_verify_conf(const n2n_edge_conf_t *conf);
int edge_conf_add_supernode(n2n_edge_conf_t *conf, const char *ip_and_port);
const n2n_edge_conf_t* edge_get_conf(const n2n_edge_t *eee);
void edge_term_conf(n2n_edge_conf_t *conf);

/* Public functions */
n2n_edge_t* edge_init(const n2n_edge_conf_t *conf, int *rv);
void update_supernode_reg(n2n_edge_t * eee, time_t nowTime);
void readFromIPSocket(n2n_edge_t * eee, int in_sock);
void edge_term(n2n_edge_t *eee);
void edge_set_callbacks(n2n_edge_t *eee, const n2n_edge_callbacks_t *callbacks);
void edge_set_userdata(n2n_edge_t *eee, void *user_data);
void* edge_get_userdata(n2n_edge_t *eee);
void edge_send_packet2net(n2n_edge_t *eee, uint8_t *tap_pkt, size_t len);
void edge_read_from_tap(n2n_edge_t *eee);
int edge_get_n2n_socket(n2n_edge_t *eee);
int edge_get_management_socket(n2n_edge_t *eee);
int run_edge_loop(n2n_edge_t *eee, int *keep_running);
int quick_edge_init(char *device_name, char *community_name,
		    char *encrypt_key, char *device_mac,
		    char *local_ip_address,
		    char *supernode_ip_address_port,
		    int *keep_on_running);
int sn_init(n2n_sn_t *sss);
void sn_term(n2n_sn_t *sss);
int run_sn_loop(n2n_sn_t *sss, int *keep_running);
const char* compression_str(uint8_t cmpr);
const char* transop_str(enum n2n_transform tr);

#endif /* _N2N_H_ */
