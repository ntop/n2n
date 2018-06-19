//
// Created by switchwang(https://github.com/switch-st) on 2018-04-13.
//

#ifndef _EDGE_ANDROID_H_
#define _EDGE_ANDROID_H_

#ifdef __ANDROID_NDK__

#include "../n2n.h"
#include <pthread.h>

#define EDGE_CMD_IPSTR_SIZE 16
#define EDGE_CMD_SUPERNODES_NUM 2
#define EDGE_CMD_SN_HOST_SIZE 48
#define EDGE_CMD_MACNAMSIZ 18


typedef struct n2n_edge_cmd_st
{
    char ip_addr[EDGE_CMD_IPSTR_SIZE];
    char ip_netmask[EDGE_CMD_IPSTR_SIZE];
    char supernodes[EDGE_CMD_SUPERNODES_NUM][EDGE_CMD_SN_HOST_SIZE];
    char community[N2N_COMMUNITY_SIZE];
    char* enc_key;
    char* enc_key_file;
    char mac_addr[EDGE_CMD_MACNAMSIZ];
    unsigned int mtu;
    int re_resolve_supernode_ip;
    unsigned int local_port;
    int allow_routing;
    int drop_multicast;
    int trace_vlevel;
    int vpn_fd;
} n2n_edge_cmd_t;

typedef struct n2n_edge_status_st
{
    pthread_mutex_t mutex;
    uint8_t is_running;
} n2n_edge_status;

#define INIT_EDGE_CMD(cmd)      do {\
    memset(&(cmd), 0, sizeof((cmd))); \
    (cmd).enc_key = NULL;             \
    (cmd).enc_key_file = NULL;        \
    (cmd).mtu = 1400;                 \
    (cmd).re_resolve_supernode_ip = 0;\
    (cmd).local_port = 0;             \
    (cmd).allow_routing = 0;          \
    (cmd).drop_multicast = 1;         \
    (cmd).trace_vlevel = 2;           \
    (cmd).vpn_fd = -1;                \
} while (0);

n2n_edge_status status;

int start_edge(const n2n_edge_cmd_t* cmd);
int stop_edge(void);
void report_edge_status(void);

#endif /* __ANDROID_NDK__ */

#endif //_EDGE_ANDROID_H_
