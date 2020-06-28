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

#ifdef __ANDROID_NDK__
#include <edge_jni/edge_jni.h>
#include <tun2tap/tun2tap.h>

#define N2N_NETMASK_STR_SIZE    16 /* dotted decimal 12 numbers + 3 dots */
#define N2N_MACNAMSIZ           18 /* AA:BB:CC:DD:EE:FF + NULL*/
#define N2N_IF_MODE_SIZE        16 /* static | dhcp */

n2n_edge_status_t* g_status;

/* ***************************************************** */

/** Find the address and IP mode for the tuntap device.
 *
 *  s is one of these forms:
 *
 *  <host> := <hostname> | A.B.C.D
 *
 *  <host> | static:<host> | dhcp:<host>
 *
 *  If the mode is present (colon required) then fill ip_mode with that value
 *  otherwise do not change ip_mode. Fill ip_mode with everything after the
 *  colon if it is present; or s if colon is not present.
 *
 *  ip_add and ip_mode are NULL terminated if modified.
 *
 *  return 0 on success and -1 on error
 */
static int scan_address(char * ip_addr, size_t addr_size,
                        char * ip_mode, size_t mode_size,
                        const char * s) {
  int retval = -1;
  char * p;

  if((NULL == s) || (NULL == ip_addr))
    {
      return -1;
    }

  memset(ip_addr, 0, addr_size);

  p = strpbrk(s, ":");

  if(p)
    {
      /* colon is present */
      if(ip_mode)
        {
	  size_t end=0;

	  memset(ip_mode, 0, mode_size);
	  end = MIN(p-s, (ssize_t)(mode_size-1)); /* ensure NULL term */
	  strncpy(ip_mode, s, end);
	  strncpy(ip_addr, p+1, addr_size-1); /* ensure NULL term */
	  retval = 0;
        }
    }
  else
    {
      /* colon is not present */
      strncpy(ip_addr, s, addr_size);
    }

  return retval;
}

/* *************************************************** */

static const char *random_device_mac(void)
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
    mac[i] = key[random() % sizeof(key)];
  }
  mac[sizeof(mac) - 1] = '\0';
  return mac;
}

/* *************************************************** */

int start_edge_v2(n2n_edge_status_t* status)
{
  int     keep_on_running = 0;
  char    tuntap_dev_name[N2N_IFNAMSIZ] = "tun0";
  char    ip_mode[N2N_IF_MODE_SIZE]="static";
  char    ip_addr[N2N_NETMASK_STR_SIZE] = "";
  char    netmask[N2N_NETMASK_STR_SIZE]="255.255.255.0";
  char    device_mac[N2N_MACNAMSIZ]="";
  char *  encrypt_key=NULL;
  struct in_addr gateway_ip = {0};
  n2n_edge_conf_t conf;
  n2n_edge_t *eee = NULL;
  int i;
  tuntap_dev dev;

  if (!status) {
    traceEvent( TRACE_ERROR, "Empty cmd struct" );
    return 1;
  }
  g_status = status;
  n2n_edge_cmd_t* cmd = &status->cmd;

  if (cmd->vpn_fd < 0) {
    traceEvent(TRACE_ERROR, "VPN socket is invalid.");
    return 1;
  }

  pthread_mutex_lock(&g_status->mutex);
  g_status->running_status = EDGE_STAT_CONNECTING;
  pthread_mutex_unlock(&g_status->mutex);
  g_status->report_edge_status();

  edge_init_conf_defaults(&conf);

  /* Load the configuration */
  strncpy((char *)conf.community_name, cmd->community, N2N_COMMUNITY_SIZE-1);

  if(cmd->enc_key && cmd->enc_key[0]) {
    conf.transop_id = N2N_TRANSFORM_ID_TWOFISH;
    conf.encrypt_key = strdup(cmd->enc_key);
    traceEvent(TRACE_DEBUG, "encrypt_key = '%s'\n", encrypt_key);
  }

  scan_address(ip_addr, N2N_NETMASK_STR_SIZE,
	       ip_mode, N2N_IF_MODE_SIZE,
	       cmd->ip_addr);

  dev.fd = cmd->vpn_fd;

  conf.drop_multicast = cmd->drop_multicast == 0 ? 0 : 1;
  conf.allow_routing = cmd->allow_routing == 0 ? 0 : 1;
  conf.dyn_ip_mode = (strcmp("dhcp", ip_mode) == 0) ? 1 : 0;

  for (i = 0; i < N2N_EDGE_NUM_SUPERNODES && i < EDGE_CMD_SUPERNODES_NUM; ++i)
    {
      if (cmd->supernodes[i][0] != '\0')
        {
	  strncpy(conf.sn_ip_array[conf.sn_num], cmd->supernodes[i], N2N_EDGE_SN_HOST_SIZE);
	  traceEvent(TRACE_DEBUG, "Adding supernode[%u] = %s\n", (unsigned int)conf.sn_num, (conf.sn_ip_array[conf.sn_num]));
	  ++conf.sn_num;
        }
    }

  if (cmd->ip_netmask[0] != '\0')
    strncpy(netmask, cmd->ip_netmask, N2N_NETMASK_STR_SIZE);

  if (cmd->gateway_ip[0] != '\0')
    inet_aton(cmd->gateway_ip, &gateway_ip);

  if (cmd->mac_addr[0] != '\0')
    strncpy(device_mac, cmd->mac_addr, N2N_MACNAMSIZ);
  else {
    strncpy(device_mac, random_device_mac(), N2N_MACNAMSIZ);
    traceEvent(TRACE_DEBUG, "random device mac: %s\n", device_mac);
  }

  if(edge_verify_conf(&conf) != 0) {
    if(conf.encrypt_key) free(conf.encrypt_key);
    traceEvent(TRACE_ERROR, "Bad configuration");
    return 1;
  }

  /* Open the TAP device */
  if(tuntap_open(&dev, tuntap_dev_name, ip_mode, ip_addr, netmask, device_mac, cmd->mtu) < 0) {
    traceEvent(TRACE_ERROR, "Failed in tuntap_open");
    free(encrypt_key);
    return 1;
  }

  /* Start n2n */
  eee = edge_init(&dev, &conf, &i);

  if(eee == NULL) {
    traceEvent( TRACE_ERROR, "Failed in edge_init" );
    return 1;
  }

  /* Set runtime information */
  eee->gateway_ip = gateway_ip.s_addr;

  /* set host addr, netmask, mac addr for UIP and init arp*/
  {
    int match, i;
    int ip[4];
    uip_ipaddr_t ipaddr;
    struct uip_eth_addr eaddr;

    match = sscanf(ip_addr, "%d.%d.%d.%d", ip, ip + 1, ip + 2, ip + 3);
    if (match != 4) {
      traceEvent(TRACE_ERROR, "scan ip failed, ip: %s", ip_addr);
      return 1;
    }
    uip_ipaddr(ipaddr, ip[0], ip[1], ip[2], ip[3]);
    uip_sethostaddr(ipaddr);
    match = sscanf(netmask, "%d.%d.%d.%d", ip, ip + 1, ip + 2, ip + 3);
    if (match != 4) {
      traceEvent(TRACE_ERROR, "scan netmask error, ip: %s", netmask);
      return 1;
    }
    uip_ipaddr(ipaddr, ip[0], ip[1], ip[2], ip[3]);
    uip_setnetmask(ipaddr);
    for (i = 0; i < 6; ++i) {
      eaddr.addr[i] = eee->device.mac_addr[i];
    }
    uip_setethaddr(eaddr);

    uip_arp_init();
  }

  keep_on_running = 1;
  pthread_mutex_lock(&g_status->mutex);
  g_status->running_status = EDGE_STAT_CONNECTED;
  pthread_mutex_unlock(&g_status->mutex);
  g_status->report_edge_status();
  traceEvent(TRACE_NORMAL, "edge started");

  update_supernode_reg(eee, time(NULL));

  run_edge_loop(eee, &keep_on_running);

  /* Cleanup */
  edge_term(eee);
  tuntap_close(&dev);
  edge_term_conf(&conf);

  traceEvent(TRACE_NORMAL, "Edge stopped");

  return 0;
}

int stop_edge_v2(void)
{
  // quick stop
  int fd = open_socket(0, 0 /* bind LOOPBACK*/ );
  if (fd < 0) {
    return 1;
  }

  struct sockaddr_in peer_addr;
  peer_addr.sin_family = PF_INET;
  peer_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  peer_addr.sin_port = htons(N2N_EDGE_MGMT_PORT);
  sendto(fd, "stop", 4, 0, (struct sockaddr *)&peer_addr, sizeof(struct sockaddr_in));
  close(fd);

  pthread_mutex_lock(&g_status->mutex);
  g_status->running_status = EDGE_STAT_DISCONNECT;
  pthread_mutex_unlock(&g_status->mutex);
  g_status->report_edge_status();

  return 0;
}

/* ************************************** */

static char arp_packet[] = {
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Dest mac */
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Src mac */
			    0x08, 0x06, /* ARP */
			    0x00, 0x01, /* Ethernet */
			    0x08, 0x00, /* IP */
			    0x06, /* Hw Size */
			    0x04, /* Protocol Size */
			    0x00, 0x01, /* ARP Request */
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Src mac */
			    0x00, 0x00, 0x00, 0x00, /* Src IP */
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Target mac */
			    0x00, 0x00, 0x00, 0x00 /* Target IP */
};

/* ************************************** */

static int build_unicast_arp(char *buffer, size_t buffer_len, uint32_t target, tuntap_dev *device) {
  if(buffer_len < sizeof(arp_packet)) return(-1);

  memcpy(buffer, arp_packet, sizeof(arp_packet));
  memcpy(&buffer[6], device->mac_addr, 6);
  memcpy(&buffer[22], device->mac_addr, 6);
  memcpy(&buffer[28], &device->ip_addr, 4);
  memcpy(&buffer[32], broadcast_mac, 6);
  memcpy(&buffer[38], &target, 4);
  return(sizeof(arp_packet));
}

/* ************************************** */

/** Called periodically to update the gateway MAC address. The ARP reply packet
    is handled in handle_PACKET . */

static void update_gateway_mac(n2n_edge_t *eee) {
  if(eee->gateway_ip != 0) {
    size_t len;
    char buffer[48];

    len = build_unicast_arp(buffer, sizeof(buffer), eee->gateway_ip, &eee->device);
    traceEvent(TRACE_DEBUG, "Updating gateway mac");
    send_packet2net(eee, (uint8_t*)buffer, len);
  }
}

#endif /* #ifdef __ANDROID_NDK__ */

/* ************************************** */
