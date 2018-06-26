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

#include "../n2n.h"

#ifdef __ANDROID_NDK__
#include "edge_android.h"
#include <tun2tap/tun2tap.h>

#define N2N_NETMASK_STR_SIZE    16 /* dotted decimal 12 numbers + 3 dots */
#define N2N_MACNAMSIZ           18 /* AA:BB:CC:DD:EE:FF + NULL*/
#define N2N_IF_MODE_SIZE        16 /* static | dhcp */

/* *************************************************** */

#if defined(DUMMY_ID_00001) /* Disabled waiting for config option to enable it */

static char gratuitous_arp[] = {
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

/** Build a gratuitous ARP packet for a /24 layer 3 (IP) network. */
static int build_gratuitous_arp(char *buffer, uint16_t buffer_len) {
  if(buffer_len < sizeof(gratuitous_arp)) return(-1);

  memcpy(buffer, gratuitous_arp, sizeof(gratuitous_arp));
  memcpy(&buffer[6], device.mac_addr, 6);
  memcpy(&buffer[22], device.mac_addr, 6);
  memcpy(&buffer[28], &device.ip_addr, 4);

  /* REVISIT: BbMaj7 - use a real netmask here. This is valid only by accident
   * for /24 IPv4 networks. */
  buffer[31] = 0xFF; /* Use a faked broadcast address */
  memcpy(&buffer[38], &device.ip_addr, 4);
  return(sizeof(gratuitous_arp));
}

/* ************************************** */

/** Called from update_supernode_reg to periodically send gratuitous ARP
 *  broadcasts. */
static void send_grat_arps(n2n_edge_t * eee,) {
  char buffer[48];
  size_t len;

  traceEvent(TRACE_NORMAL, "Sending gratuitous ARP...");
  len = build_gratuitous_arp(buffer, sizeof(buffer));
  send_packet2net(eee, buffer, len);
  send_packet2net(eee, buffer, len); /* Two is better than one :-) */
}

#endif /* #if defined(DUMMY_ID_00001) */

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

int start_edge(const n2n_edge_cmd_t* cmd)
{
    int     keep_on_running = 0;
    int     local_port = 0 /* any port */;
    char    tuntap_dev_name[N2N_IFNAMSIZ] = "tun0";
    char    ip_mode[N2N_IF_MODE_SIZE]="static";
    char    ip_addr[N2N_NETMASK_STR_SIZE] = "";
    char    netmask[N2N_NETMASK_STR_SIZE]="255.255.255.0";
    char    device_mac[N2N_MACNAMSIZ]="";
    char *  encrypt_key=NULL;
    n2n_edge_t eee;
    int i;

    keep_on_running = 0;
    pthread_mutex_lock(&status.mutex);
    status.is_running = keep_on_running;
    pthread_mutex_unlock(&status.mutex);
    report_edge_status();
    if (!cmd) {
        traceEvent( TRACE_ERROR, "Empty cmd struct" );
        return 1;
    }

    traceLevel = cmd->trace_vlevel;
    traceLevel = traceLevel < 0 ? 0 : traceLevel;   /* TRACE_ERROR */
    traceLevel = traceLevel > 4 ? 4 : traceLevel;   /* TRACE_DEBUG */

    if (-1 == edge_init(&eee) )
    {
        traceEvent( TRACE_ERROR, "Failed in edge_init" );
        return 1;
    }
    memset(&(eee.supernode), 0, sizeof(eee.supernode));
    eee.supernode.family = AF_INET;

    if (cmd->vpn_fd < 0) {
        traceEvent(TRACE_ERROR, "VPN socket is invalid.");
        return 1;
    }
    eee.device.fd = cmd->vpn_fd;
    if (cmd->enc_key_file)
    {
        strncpy(eee.keyschedule, cmd->enc_key_file, N2N_PATHNAME_MAXLEN-1);
        eee.keyschedule[N2N_PATHNAME_MAXLEN-1]=0; /* strncpy does not add NULL if the source has no NULL. */
        traceEvent(TRACE_DEBUG, "keyfile = '%s'\n", eee.keyschedule);
    }
    else if (cmd->enc_key)
    {
        encrypt_key = strdup(cmd->enc_key);
        traceEvent(TRACE_DEBUG, "encrypt_key = '%s'\n", encrypt_key);
    }

    if (cmd->ip_addr[0] != '\0')
    {
        scan_address(ip_addr, N2N_NETMASK_STR_SIZE,
                     ip_mode, N2N_IF_MODE_SIZE,
                     cmd->ip_addr);
    }
    else
    {
        traceEvent(TRACE_ERROR, "Ip address is not set.");
        free(encrypt_key);
        return 1;
    }
    if (cmd->community[0] != '\0')
    {
        strncpy((char *)eee.community_name, cmd->community, N2N_COMMUNITY_SIZE);
    }
    else
    {
        traceEvent(TRACE_ERROR, "Community is not set.");
        free(encrypt_key);
        return 1;
    }
    eee.drop_multicast = cmd->drop_multicast == 0 ? 0 : 1;
    if (cmd->mac_addr[0] != '\0')
    {
        strncpy(device_mac, cmd->mac_addr, N2N_MACNAMSIZ);
    }
    else
    {
        strncpy(device_mac, random_device_mac(), N2N_MACNAMSIZ);
        traceEvent(TRACE_DEBUG, "random device mac: %s\n", device_mac);
    }
    eee.allow_routing = cmd->allow_routing == 0 ? 0 : 1;
    for (i = 0; i < N2N_EDGE_NUM_SUPERNODES && i < EDGE_CMD_SUPERNODES_NUM; ++i)
    {
        if (cmd->supernodes[i][0] != '\0')
        {
            strncpy(eee.sn_ip_array[eee.sn_num], cmd->supernodes[i], N2N_EDGE_SN_HOST_SIZE);
            traceEvent(TRACE_DEBUG, "Adding supernode[%u] = %s\n", (unsigned int)eee.sn_num, (eee.sn_ip_array[eee.sn_num]));
            ++eee.sn_num;
        }
    }
    eee.re_resolve_supernode_ip = cmd->re_resolve_supernode_ip == 0 ? 0 : 1;
    if (cmd->ip_netmask[0] != '\0')
    {
        strncpy(netmask, cmd->ip_netmask, N2N_NETMASK_STR_SIZE);
    }

    for (i=0; i< N2N_EDGE_NUM_SUPERNODES; ++i )
    {
        traceEvent(TRACE_NORMAL, "supernode %u => %s\n", i, (eee.sn_ip_array[i]));
    }
    supernode2addr(&(eee.supernode), eee.sn_ip_array[eee.sn_idx]);
    if (encrypt_key == NULL && strlen(eee.keyschedule) == 0)
    {
        traceEvent(TRACE_WARNING, "Encryption is disabled in edge.");
        eee.null_transop = 1;
    }
    if (0 == strcmp("dhcp", ip_mode))
    {
        traceEvent(TRACE_NORMAL, "Dynamic IP address assignment enabled.");
        eee.dyn_ip_mode = 1;
    }
    else
    {
        traceEvent(TRACE_NORMAL, "ip_mode='%s'", ip_mode);
    }
    if(tuntap_open(&(eee.device), tuntap_dev_name, ip_mode, ip_addr, netmask, device_mac, cmd->mtu) < 0)
    {
        traceEvent(TRACE_ERROR, "Failed in tuntap_open");
        free(encrypt_key);
        return 1;
    }
    if(local_port > 0)
    {
        traceEvent(TRACE_NORMAL, "Binding to local port %d", (signed int)local_port);
    }
    if (encrypt_key)
    {
        if(edge_init_twofish(&eee, (uint8_t *)(encrypt_key), strlen(encrypt_key)) < 0)
        {
            traceEvent(TRACE_ERROR, "twofish setup failed.\n");
            free(encrypt_key);
            return 1;
        }
        free(encrypt_key);
        encrypt_key = NULL;
    }
    else if (strlen(eee.keyschedule) > 0)
    {
        if (edge_init_keyschedule(&eee) != 0)
        {
            traceEvent(TRACE_ERROR, "keyschedule setup failed.\n");
            free(encrypt_key);
            return 1;
        }
    }
    /* else run in NULL mode */
    eee.udp_sock = open_socket(local_port, 1 /*bind ANY*/ );
    if(eee.udp_sock < 0)
    {
        traceEvent(TRACE_ERROR, "Failed to bind main UDP port %u", (signed int)local_port);
        return 1;
    }
    eee.udp_mgmt_sock = open_socket(N2N_EDGE_MGMT_PORT, 0 /* bind LOOPBACK*/ );
    if(eee.udp_mgmt_sock < 0)
    {
        traceEvent( TRACE_ERROR, "Failed to bind management UDP port %u", (unsigned int)N2N_EDGE_MGMT_PORT );
        return 1;
    }

    /* set host addr, netmask, mac addr for UIP and init arp*/
    {
        int match, i;
        u8_t ip[4];
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
            eaddr.addr[i] = eee.device.mac_addr[i];
        }
        uip_setethaddr(eaddr);

        uip_arp_init();
    }

    keep_on_running = 1;
    pthread_mutex_lock(&status.mutex);
    status.is_running = keep_on_running;
    pthread_mutex_unlock(&status.mutex);
    report_edge_status();
    traceEvent(TRACE_NORMAL, "edge started");

    update_supernode_reg(&eee, time(NULL));

    return run_edge_loop(&eee, &keep_on_running);
}

int stop_edge(void)
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

    pthread_mutex_lock(&status.mutex);
    status.is_running = 0;
    pthread_mutex_unlock(&status.mutex);
    report_edge_status();

    return 0;
}
#endif /* #ifdef __ANDROID_NDK__ */

/* ************************************** */
