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
#ifdef WIN32
#include <sys/stat.h>
#endif

#define N2N_NETMASK_STR_SIZE    16 /* dotted decimal 12 numbers + 3 dots */
#define N2N_MACNAMSIZ           18 /* AA:BB:CC:DD:EE:FF + NULL*/
#define N2N_IF_MODE_SIZE        16 /* static | dhcp */

/* *************************************************** */

/** maximum length of command line arguments */
#define MAX_CMDLINE_BUFFER_LENGTH    4096

/** maximum length of a line in the configuration file */
#define MAX_CONFFILE_LINE_LENGTH     1024

/* ***************************************************** */

typedef struct {
  int     local_port;
  int     mgmt_port;
  char    tuntap_dev_name[N2N_IFNAMSIZ];
  char    ip_mode[N2N_IF_MODE_SIZE];
  char    ip_addr[N2N_NETMASK_STR_SIZE];
  char    netmask[N2N_NETMASK_STR_SIZE];
  int     mtu;
  int     got_s;
  char    device_mac[N2N_MACNAMSIZ];
  char *  encrypt_key;
#ifndef WIN32
  uid_t   userid;
  gid_t   groupid;
#endif
} edge_conf_t;

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

static void help() {
  print_n2n_version();

  printf("edge <config file> (see edge.conf)\n"
	 "or\n"
	 );
  printf("edge "
#if defined(N2N_CAN_NAME_IFACE)
	 "-d <tun device> "
#endif /* #if defined(N2N_CAN_NAME_IFACE) */
	 "-a [static:|dhcp:]<tun IP address> "
	 "-c <community> "
	 "[-k <encrypt key> | -K <key file>]\n"
	 "    "
	 "[-s <netmask>] "
#ifndef WIN32
	 "[-u <uid> -g <gid>]"
#endif /* #ifndef WIN32 */

#ifndef WIN32
	 "[-f]"
#endif /* #ifndef WIN32 */
	 "[-m <MAC address>] "
	 "-l <supernode host:port>\n"
	 "    "
	 "[-p <local port>] [-M <mtu>] "
	 "[-r] [-E] [-v] [-t <mgmt port>] [-b] [-h]\n\n");

#ifdef __linux__
  printf("-d <tun device>          | tun device name\n");
#endif

  printf("-a <mode:address>        | Set interface address. For DHCP use '-r -a dhcp:0.0.0.0'\n");
  printf("-c <community>           | n2n community name the edge belongs to.\n");
  printf("-k <encrypt key>         | Encryption key (ASCII) - also N2N_KEY=<encrypt key>. Not with -K.\n");
  printf("-K <key file>            | Specify a key schedule file to load. Not with -k.\n");
  printf("-s <netmask>             | Edge interface netmask in dotted decimal notation (255.255.255.0).\n");
  printf("-l <supernode host:port> | Supernode IP:port\n");
  printf("-b                       | Periodically resolve supernode IP\n");
  printf("                         | (when supernodes are running on dynamic IPs)\n");
  printf("-p <local port>          | Fixed local UDP port.\n");
#ifndef WIN32
  printf("-u <UID>                 | User ID (numeric) to use when privileges are dropped.\n");
  printf("-g <GID>                 | Group ID (numeric) to use when privileges are dropped.\n");
#endif /* ifndef WIN32 */
#ifndef WIN32
  printf("-f                       | Do not fork and run as a daemon; rather run in foreground.\n");
#endif /* #ifndef WIN32 */
  printf("-m <MAC address>         | Fix MAC address for the TAP interface (otherwise it may be random)\n"
         "                         | eg. -m 01:02:03:04:05:06\n");
  printf("-M <mtu>                 | Specify n2n MTU of edge interface (default %d).\n", DEFAULT_MTU);
  printf("-r                       | Enable packet forwarding through n2n community.\n");
  printf("-E                       | Accept multicast MAC addresses (default=drop).\n");
  printf("-v                       | Make more verbose. Repeat as required.\n");
  printf("-t <port>                | Management UDP Port (for multiple edges on a machine).\n");

  printf("\nEnvironment variables:\n");
  printf("  N2N_KEY                | Encryption key (ASCII). Not with -K or -k.\n");

  exit(0);
}

/* *************************************************** */

static int setOption(int optkey, char *optargument, edge_conf_t *ec, n2n_edge_t *eee) {
  /* traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, optargument ? optargument : ""); */

  switch(optkey) {
  case'K':
    {
      if(ec->encrypt_key) {
        fprintf(stderr, "Error: -K and -k options are mutually exclusive.\n");
        exit(1);
      } else {
        strncpy(eee->keyschedule, optargument, N2N_PATHNAME_MAXLEN-1);
        /* strncpy does not add NULL if the source has no NULL. */
        eee->keyschedule[N2N_PATHNAME_MAXLEN-1] = 0;
	      
        traceEvent(TRACE_DEBUG, "keyfile = '%s'\n", eee->keyschedule);
        fprintf(stderr, "keyfile = '%s'\n", eee->keyschedule);
      }
      break;
    }

  case 'a': /* IP address and mode of TUNTAP interface */
    {
      scan_address(ec->ip_addr, N2N_NETMASK_STR_SIZE,
		   ec->ip_mode, N2N_IF_MODE_SIZE,
		   optargument);
      break;
    }

  case 'c': /* community as a string */
    {
      memset(eee->community_name, 0, N2N_COMMUNITY_SIZE);
      strncpy((char *)eee->community_name, optargument, N2N_COMMUNITY_SIZE);
      break;
    }

  case 'E': /* multicast ethernet addresses accepted. */
    {
      eee->drop_multicast=0;
      traceEvent(TRACE_DEBUG, "Enabling ethernet multicast traffic\n");
      break;
    }

#ifndef WIN32
  case 'u': /* unprivileged uid */
    {
      ec->userid = atoi(optargument);
      break;
    }

  case 'g': /* unprivileged uid */
    {
      ec->groupid = atoi(optargument);
      break;
    }
#endif

#ifndef WIN32
  case 'f' : /* do not fork as daemon */
    {
      eee->daemon=0;
      break;
    }
#endif /* #ifndef WIN32 */

  case 'm' : /* TUNTAP MAC address */
    {
      strncpy(ec->device_mac,optargument,N2N_MACNAMSIZ);
      break;
    }

  case 'M' : /* TUNTAP MTU */
    {
      ec->mtu = atoi(optargument);
      break;
    }

  case 'k': /* encrypt key */
    {
      if(strlen(eee->keyschedule) > 0) {
        fprintf(stderr, "Error: -K and -k options are mutually exclusive.\n");
        exit(1);
      } else {
        traceEvent(TRACE_DEBUG, "encrypt_key = '%s'\n", ec->encrypt_key);
        ec->encrypt_key = strdup(optargument);
      }
      break;
    }

  case 'r': /* enable packet routing across n2n endpoints */
    {
      eee->allow_routing = 1;
      break;
    }

  case 'l': /* supernode-list */
    {
      if(eee->sn_num < N2N_EDGE_NUM_SUPERNODES) {
        strncpy((eee->sn_ip_array[eee->sn_num]), optargument, N2N_EDGE_SN_HOST_SIZE);
        traceEvent(TRACE_NORMAL, "Adding supernode[%u] = %s\n", (unsigned int)eee->sn_num, (eee->sn_ip_array[eee->sn_num]));
        ++eee->sn_num;
      } else {
        traceEvent(TRACE_WARNING, "Too many supernodes!\n");
        exit(1);
      }
      break;
    }

#if defined(N2N_CAN_NAME_IFACE)
  case 'd': /* TUNTAP name */
    {
      strncpy(ec->tuntap_dev_name, optargument, N2N_IFNAMSIZ);
      break;
    }
#endif

  case 'b':
    {
      eee->re_resolve_supernode_ip = 1;
      break;
    }

  case 'p':
    {
      ec->local_port = atoi(optargument);
      break;
    }

  case 't':
    {
      ec->mgmt_port = atoi(optargument);
      break;
    }

  case 's': /* Subnet Mask */
    {
      if(0 != ec->got_s) {
        traceEvent(TRACE_WARNING, "Multiple subnet masks supplied.");
      }
      strncpy(ec->netmask, optargument, N2N_NETMASK_STR_SIZE);
      ec->got_s = 1;
      break;
    }

  case 'h': /* help */
    {
      help();
      break;
    }

  case 'v': /* verbose */
    traceLevel = 4; /* DEBUG */
    break;
    
  default:
    {
      traceEvent(TRACE_WARNING, "Unknown option -%c: Ignored.", (char)optkey);
      return(-1);
    }
  }

  return(0);
}

/* *********************************************** */

static const struct option long_options[] = {
  { "community",       required_argument, NULL, 'c' },
  { "supernode-list",  required_argument, NULL, 'l' },
  { "tun-device",      required_argument, NULL, 'd' },
  { "euid",            required_argument, NULL, 'u' },
  { "egid",            required_argument, NULL, 'g' },
  { "help"   ,         no_argument,       NULL, 'h' },
  { "verbose",         no_argument,       NULL, 'v' },
  { NULL,              0,                 NULL,  0  }
};

/* *************************************************** */

/* read command line options */
static int loadFromCLI(int argc, char *argv[], edge_conf_t *ec, n2n_edge_t *eee) {
  u_char c;

  while((c = getopt_long(argc, argv,
			 "K:k:a:bc:Eu:g:m:M:s:d:l:p:fvhrt:",
			 long_options, NULL)) != '?') {
    if(c == 255) break;
    setOption(c, optarg, ec, eee);
  }

  return 0;
}

/* *************************************************** */

static char *trim(char *s) {
  char *end;

  while(isspace(s[0]) || (s[0] == '"') || (s[0] == '\'')) s++;
  if(s[0] == 0) return s;

  end = &s[strlen(s) - 1];
  while(end > s
	&& (isspace(end[0])|| (end[0] == '"') || (end[0] == '\'')))
    end--;
  end[1] = 0;

  return s;
}

/* *************************************************** */

/* parse the configuration file */
static int loadFromFile(const char *path, edge_conf_t *ec, n2n_edge_t *eee) {
  char buffer[4096], *line, *key, *value;
  u_int line_len, opt_name_len;
  FILE *fd;
  const struct option *opt;

  fd = fopen(path, "r");

  if(fd == NULL) {
    traceEvent(TRACE_WARNING, "Config file %s not found", path);
    return -1;
  }

  while((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {

    line = trim(line);
    value = NULL;

    if((line_len = strlen(line)) < 2 || line[0] == '#')
      continue;

    if(!strncmp(line, "--", 2)) { /* long opt */
      key = &line[2], line_len -= 2;

      opt = long_options;
      while(opt->name != NULL) {
	opt_name_len = strlen(opt->name);

	if(!strncmp(key, opt->name, opt_name_len)
	   && (line_len <= opt_name_len
	       || key[opt_name_len] == '\0'
	       || key[opt_name_len] == ' '
	       || key[opt_name_len] == '=')) {
	  if(line_len > opt_name_len)	  key[opt_name_len] = '\0';
	  if(line_len > opt_name_len + 1) value = trim(&key[opt_name_len + 1]);

	  // traceEvent(TRACE_NORMAL, "long key: %s value: %s", key, value);
	  setOption(opt->val, value, ec, eee);
	  break;
	}

	opt++;
      }
    } else if(line[0] == '-') { /* short opt */
      key = &line[1], line_len--;
      if(line_len > 1) key[1] = '\0';
      if(line_len > 2) value = trim(&key[2]);

      // traceEvent(TRACE_NORMAL, "key: %c value: %s", key[0], value);
      setOption(key[0], value, ec, eee);
    } else {
      traceEvent(TRACE_WARNING, "Skipping unrecognized line: %s", line);
      continue;
    }
  }

  fclose(fd);

  return 0;
}

/* ************************************** */

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

/* ************************************** */

static void daemonize() {
#ifndef WIN32
  int childpid;

  traceEvent(TRACE_NORMAL, "Parent process is exiting (this is normal)");

  signal(SIGPIPE, SIG_IGN);
  signal(SIGHUP,  SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);

  if((childpid = fork()) < 0)
    traceEvent(TRACE_ERROR, "Occurred while daemonizing (errno=%d)",
	       errno);
  else {
    if(!childpid) { /* child */
      int rc;

      //traceEvent(TRACE_NORMAL, "Bye bye: I'm becoming a daemon...");
      rc = chdir("/");
      if(rc != 0)
	traceEvent(TRACE_ERROR, "Error while moving to / directory");

      setsid();  /* detach from the terminal */

      fclose(stdin);
      fclose(stdout);
      /* fclose(stderr); */

      /*
       * clear any inherited file mode creation mask
       */
      //umask(0);

      /*
       * Use line buffered stdout
       */
      /* setlinebuf (stdout); */
      setvbuf(stdout, (char *)NULL, _IOLBF, 0);
    } else /* father */
      exit(0);
  }
#endif
}

/* *************************************************** */

/** Entry point to program from kernel. */
int main(int argc, char* argv[]) {
  int     keep_on_running = 1;
  int     rc;
  int     i;
  n2n_edge_t eee; /* single instance for this program */
  edge_conf_t ec;

  if(argc == 1)
    help();
  
  ec.local_port = 0 /* any port */;
  ec.mgmt_port = N2N_EDGE_MGMT_PORT; /* 5644 by default */
  snprintf(ec.tuntap_dev_name, sizeof(ec.tuntap_dev_name), "edge0");
  snprintf(ec.ip_mode, sizeof(ec.ip_mode), "static");
  snprintf(ec.netmask, sizeof(ec.netmask), "255.255.255.0");
  ec.ip_addr[0] = '\0';
  ec.device_mac[0] = '\0';
  ec.mtu = DEFAULT_MTU;
  ec.got_s = 0;
  ec.encrypt_key = NULL;
#ifndef WIN32
  ec.userid = 0; /* root is the only guaranteed ID */
  ec.groupid = 0; /* root is the only guaranteed ID */
#endif

  if(-1 == edge_init(&eee)) {
    traceEvent(TRACE_ERROR, "Failed in edge_init");
    exit(1);
  }
  
  if(getenv("N2N_KEY")) {
    ec.encrypt_key = strdup(getenv("N2N_KEY"));
  }
  
#ifdef WIN32
  ec.tuntap_dev_name[0] = '\0';
#endif
  memset(&(eee.supernode), 0, sizeof(eee.supernode));
  eee.supernode.family = AF_INET;

#ifndef WIN32
  if((argc >= 2) && (argv[1][0] != '-')) {
    rc = loadFromFile(argv[1], &ec, &eee);
    if(argc > 2)
      rc = loadFromCLI(argc, argv, &ec, &eee);
  } else
#endif
    rc = loadFromCLI(argc, argv, &ec, &eee);

  if((rc < 0) || (eee.sn_num == 0))
    help();
  
  traceEvent(TRACE_NORMAL, "Starting n2n edge %s %s", n2n_sw_version, n2n_sw_buildDate);

  for (i=0; i<eee.sn_num; ++i)
    traceEvent(TRACE_NORMAL, "supernode %u => %s\n", i, (eee.sn_ip_array[i]));

  supernode2addr(&(eee.supernode), eee.sn_ip_array[eee.sn_idx]);

  if(!(
#ifdef __linux__
       (ec.tuntap_dev_name[0] != 0) &&
#endif
       (eee.community_name[0] != 0) &&
       (ec.ip_addr[0] != 0)
       ))
    {
      help();
    }

#ifndef WIN32
  if(eee.daemon) {
    useSyslog = 1; /* traceEvent output now goes to syslog. */
    daemonize();
  }
#endif /* #ifndef WIN32 */
  
  if((NULL == ec.encrypt_key) && (0 == strlen(eee.keyschedule)))
    {
      traceEvent(TRACE_WARNING, "Encryption is disabled in edge.");
      
      eee.null_transop = 1;
    }
  
#ifndef WIN32
  /* If running suid root then we need to setuid before using the force. */
  setuid(0);
  /* setgid(0); */
#endif

  if(0 == strcmp("dhcp", ec.ip_mode)) {
    traceEvent(TRACE_NORMAL, "Dynamic IP address assignment enabled.");
    
    eee.dyn_ip_mode = 1;
  } else
    traceEvent(TRACE_NORMAL, "ip_mode='%s'", ec.ip_mode);    

  if(tuntap_open(&(eee.device), ec.tuntap_dev_name, ec.ip_mode, ec.ip_addr, ec.netmask, ec.device_mac, ec.mtu) < 0)
    return(-1);

#ifndef WIN32
  if((ec.userid != 0) || (ec.groupid != 0)) {
    traceEvent(TRACE_NORMAL, "Interface up. Dropping privileges to uid=%d, gid=%d",
	       (signed int)ec.userid, (signed int)ec.groupid);

    /* Finished with the need for root privileges. Drop to unprivileged user. */
    setreuid(ec.userid, ec.userid);
    setregid(ec.groupid, ec.groupid);
  }
#endif

  if(ec.local_port > 0)
    traceEvent(TRACE_NORMAL, "Binding to local port %d", (signed int)ec.local_port);

  if(ec.encrypt_key) {
    if(edge_init_twofish(&eee, (uint8_t *)(ec.encrypt_key), strlen(ec.encrypt_key)) < 0) {
      fprintf(stderr, "Error: twofish setup failed.\n");
      return(-1);
    }
  } else if(strlen(eee.keyschedule) > 0) {
    if(edge_init_keyschedule(&eee) != 0) {
      fprintf(stderr, "Error: keyschedule setup failed.\n");
      return(-1);
    }
  }  
  /* else run in NULL mode */

  /* Populate the multicast group for local edge */
  eee.multicast_peer.family     = AF_INET;
  eee.multicast_peer.port       = N2N_MULTICAST_PORT;
  eee.multicast_peer.addr.v4[0] = 224; /* N2N_MULTICAST_GROUP */
  eee.multicast_peer.addr.v4[1] = 0;
  eee.multicast_peer.addr.v4[2] = 0;
  eee.multicast_peer.addr.v4[3] = 68;
      
  eee.udp_sock = open_socket(ec.local_port, 1 /* bind ANY */);
  if(eee.udp_sock < 0) {
    traceEvent(TRACE_ERROR, "Failed to bind main UDP port %u", (signed int)ec.local_port);
    return(-1);
  }
  
  eee.udp_mgmt_sock = open_socket(ec.mgmt_port, 0 /* bind LOOPBACK */);  
  if(eee.udp_mgmt_sock < 0) {
    traceEvent(TRACE_ERROR, "Failed to bind management UDP port %u", ec.mgmt_port);
    return(-1);
  }

  eee.udp_multicast_sock = open_socket(N2N_MULTICAST_PORT, 1 /* bind ANY */);
  if(eee.udp_multicast_sock < 0)
    return(-5);
  else {
    /* Bind eee.udp_multicast_sock to multicast group */
    struct ip_mreq mreq;
    u_int enable_reuse = 1;
    
    /* allow multiple sockets to use the same PORT number */
    setsockopt(eee.udp_multicast_sock, SOL_SOCKET, SO_REUSEADDR, &enable_reuse, sizeof(enable_reuse));
    setsockopt(eee.udp_multicast_sock, SOL_SOCKET, SO_REUSEPORT, &enable_reuse, sizeof(enable_reuse));
    
    mreq.imr_multiaddr.s_addr = inet_addr(N2N_MULTICAST_GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(eee.udp_multicast_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
      traceEvent(TRACE_ERROR, "Failed to bind to local multicast group %s:%u",
		 N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT);
      return(-6);
    }    
  }

  traceEvent(TRACE_NORMAL, "edge started");

  update_supernode_reg(&eee, time(NULL));

  return run_edge_loop(&eee, &keep_on_running);
}

/* ************************************** */
