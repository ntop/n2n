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
#include "win32/n2n_win32.h"
#include "win32/winconfig.h"
#define N2N_CAN_NAME_IFACE 1
#undef N2N_HAVE_DAEMON
#undef N2N_HAVE_SETUID
#else
#include "config.h"
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

#ifndef WIN32
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <pthread.h>

#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#define N2N_CAN_NAME_IFACE 1
#endif /* #ifdef __linux__ */

#ifdef __FreeBSD__
#include <netinet/in_systm.h>
#endif /* #ifdef __FreeBSD__ */

#include <syslog.h>
#include <sys/wait.h>

#define ETH_ADDR_LEN 6
struct ether_hdr
{
  uint8_t  dhost[ETH_ADDR_LEN];
  uint8_t  shost[ETH_ADDR_LEN];
  uint16_t type;                /* higher layer protocol encapsulated */
} __attribute__ ((__packed__));

typedef struct ether_hdr ether_hdr_t;

#ifdef __ANDROID_NDK__
#undef N2N_HAVE_DAEMON
#undef N2N_HAVE_SETUID
#undef N2N_CAN_NAME_IFACE
#endif /* #ifdef __ANDROID_NDK__ */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>

/* Define N2N_COMPRESSION_ENABLED to enable lzo1x compression of ethernet
 * frames. Doing this will break compatibility with the standard n2n packet
 * format so do it only for experimentation. All edges must be built with the
 * same value if they are to understand each other. Comment out to disable. 
 * Changing this setting requires a clean rebuild. */
#define N2N_COMPRESSION_ENABLED

#ifdef N2N_COMPRESSION_ENABLED
#include "minilzo.h"
#endif

#define closesocket(a) close(a)
#endif /* #ifndef WIN32 */

#include <string.h>

#include <stdarg.h>

#include "uthash.h"

#ifdef WIN32
#include "win32/wintap.h"
#endif /* #ifdef WIN32 */

#include "n2n_wire.h"
#include "n2n_transforms.h"

#ifdef WIN32
#define N2N_IFNAMSIZ            64
#else
#define N2N_IFNAMSIZ            16 /* 15 chars * NULL */
#endif

#ifndef WIN32
typedef struct tuntap_dev {
  int           fd;
  uint8_t       mac_addr[6];
  uint32_t      ip_addr, device_mask;
  uint16_t      mtu;
  char          dev_name[N2N_IFNAMSIZ];
} tuntap_dev;

#define SOCKET int
#endif /* #ifndef WIN32 */

#define QUICKLZ               1

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

#define DEFAULT_MTU   1390

/** Uncomment this to enable the MTU check */
//#define MTU_ASSERT_VALUE 1500

/** Common type used to hold stringified IP addresses. */
typedef char ipstr_t[32];

/** Common type used to hold stringified MAC addresses. */
#define N2N_MACSTR_SIZE 32
typedef char macstr_t[N2N_MACSTR_SIZE];

struct peer_info {
  n2n_mac_t           mac_addr;
  n2n_sock_t          sock;
  int                 timeout;
  time_t              last_seen;
  time_t              last_p2p;
  time_t              last_sent_query;

  UT_hash_handle hh; /* makes this structure hashable */
};

#define HASH_ADD_PEER(head,add)                                                \
    HASH_ADD(hh,head,mac_addr,sizeof(n2n_mac_t),add)
#define HASH_FIND_PEER(head,mac,out)                                           \
    HASH_FIND(hh,head,mac,sizeof(n2n_mac_t),out)

#define N2N_EDGE_SN_HOST_SIZE   48
#define N2N_EDGE_NUM_SUPERNODES 2
#define N2N_EDGE_SUP_ATTEMPTS   3       /* Number of failed attmpts before moving on to next supernode. */
#define N2N_PATHNAME_MAXLEN     256
#define N2N_EDGE_MGMT_PORT      5644


typedef char n2n_sn_name_t[N2N_EDGE_SN_HOST_SIZE];

typedef struct n2n_edge_conf {
  n2n_sn_name_t       sn_ip_array[N2N_EDGE_NUM_SUPERNODES];
  n2n_community_t     community_name;         /**< The community. 16 full octets. */
  n2n_transform_t     transop_id;             /**< The transop to use. */
  uint8_t             re_resolve_supernode_ip;
  uint8_t             dyn_ip_mode;            /**< Interface IP address is dynamically allocated, eg. DHCP. */
  uint8_t             allow_routing;          /**< Accept packet no to interface address. */
  uint8_t             drop_multicast;         /**< Multicast ethernet addresses. */
  uint8_t             allow_p2p;              /**< Allow P2P connection */
  uint8_t             sn_num;                 /**< Number of supernode addresses defined. */
  uint8_t             tos;                    /** TOS for sent packets */
  char                *encrypt_key;
  int                 register_interval;      /**< Interval for supernode registration, also used for UDP NAT hole punching. */
  int                 local_port;
  int                 mgmt_port;
} n2n_edge_conf_t;

typedef struct n2n_edge n2n_edge_t; /* Opaque, see edge_utils.c */

/* ************************************** */

#ifdef __ANDROID_NDK__
#include <android/log.h>
#endif /* #ifdef __ANDROID_NDK__ */
#ifndef TRACE_ERROR
#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__
#define TRACE_DEBUG     4, __FILE__, __LINE__
#endif

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

/* ************************************** */

/* Transop Init Functions */
int n2n_transop_null_init(const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
int n2n_transop_twofish_init(const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
#ifdef N2N_HAVE_AES
int n2n_transop_aes_cbc_init(const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt);
#endif

/* Log */
void setTraceLevel(int level);
void setUseSyslog(int use_syslog);
int getTraceLevel();
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
SOCKET open_socket(int local_port, int bind_any);
int sock_equal( const n2n_sock_t * a,
                       const n2n_sock_t * b );

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

/* Public functions */
n2n_edge_t* edge_init(const tuntap_dev *dev, const n2n_edge_conf_t *conf, int *rv);
void edge_term(n2n_edge_t *eee);
int run_edge_loop(n2n_edge_t *eee, int *keep_running);
int quick_edge_init(char *device_name, char *community_name,
		    char *encrypt_key, char *device_mac,
		    char *local_ip_address,
		    char *supernode_ip_address_port,
		    int *keep_on_running);

#endif /* _N2N_H_ */
