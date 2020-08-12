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

#include "n2n.h"

/* *************************************************** */

/** maximum length of command line arguments */
#define MAX_CMDLINE_BUFFER_LENGTH    4096

/** maximum length of a line in the configuration file */
#define MAX_CONFFILE_LINE_LENGTH     1024

/* ***************************************************** */

#ifdef HAVE_LIBCAP

#include <sys/capability.h>
#include <sys/prctl.h>

static cap_value_t cap_values[] = {
				   //CAP_NET_RAW,      /* Use RAW and PACKET sockets */
				   CAP_NET_ADMIN     /* Needed to performs routes cleanup at exit */
};

int num_cap = sizeof(cap_values)/sizeof(cap_value_t);
#endif

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
      strncpy(ip_addr, s, addr_size-1);
      ip_addr[addr_size-1] = '\0';
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
	 "[-k <encrypt key>]\n"
	 "    "
	 "[-s <netmask>] "
#ifndef WIN32
	 "[-u <uid> -g <gid>]"
#endif /* #ifndef WIN32 */

#ifndef WIN32
	 "[-f]"
#endif /* #ifndef WIN32 */
#ifdef __linux__
	 "[-T <tos>]"
#endif
	 "[-n cidr:gateway] "
	 "[-m <MAC address>] "
	 "-l <supernode host:port>\n"
	 "    "
	 "[-p <local port>] [-M <mtu>] "
#ifndef __APPLE__
	 "[-D] "
#endif
	 "[-r] [-E] [-v] [-i <reg_interval>] [-L <reg_ttl>] [-t <mgmt port>] [-A[<cipher>]] [-H] [-z[<compression algo>]] [-h]\n\n");

#if defined(N2N_CAN_NAME_IFACE)
  printf("-d <tun device>          | tun device name\n");
#endif

  printf("-a <mode:address>        | Set interface address. For DHCP use '-r -a dhcp:0.0.0.0'\n");
  printf("-c <community>           | n2n community name the edge belongs to.\n");
  printf("-k <encrypt key>         | Encryption key (ASCII) - also N2N_KEY=<encrypt key>.\n");
  printf("-s <netmask>             | Edge interface netmask in dotted decimal notation (255.255.255.0).\n");
  printf("-l <supernode host:port> | Supernode IP:port\n");
  printf("-i <reg_interval>        | Registration interval, for NAT hole punching (default 20 seconds)\n");
  printf("-L <reg_ttl>             | TTL for registration packet when UDP NAT hole punching through supernode (default 0 for not set )\n");
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
#ifndef __APPLE__
  printf("-D                       | Enable PMTU discovery. PMTU discovery can reduce fragmentation but\n"
         "                         | causes connections stall when not properly supported.\n");
#endif
  printf("-r                       | Enable packet forwarding through n2n community.\n");
  printf("-A1                      | Disable payload encryption. Do not use with key (defaulting to Twofish then).\n");
  printf("-A2 ... -A5 or -A        | Choose a cipher for payload encryption, requires a key: -A2 = Twofish (default),\n");
  printf("                         | "
#ifdef N2N_HAVE_AES
  "-A3 or -A (deprecated) = AES-CBC, "
#endif
#ifdef HAVE_OPENSSL_1_1
  "-A4 = ChaCha20, "
#endif
  "-A5 = Speck-CTR.\n");
  printf("-H                       | Enable full header encryption. Requires supernode with fixed community.\n");
  printf("-z1 ... -z2 or -z        | Enable compression for outgoing data packets: -z1 or -z = lzo1x"
#ifdef N2N_HAVE_ZSTD
  ", -z2 = zstd"
#endif
  " (default=disabled).\n");
  printf("-E                       | Accept multicast MAC addresses (default=drop).\n");
  printf("-S                       | Do not connect P2P. Always use the supernode.\n");
#ifdef __linux__
  printf("-T <tos>                 | TOS for packets (e.g. 0x48 for SSH like priority)\n");
#endif
  printf("-n <cidr:gateway>        | Route an IPv4 network via the gw. Use 0.0.0.0/0 for the default gw. Can be set multiple times.\n");
  printf("-v                       | Make more verbose. Repeat as required.\n");
  printf("-t <port>                | Management UDP Port (for multiple edges on a machine).\n");

  printf("\nEnvironment variables:\n");
  printf("  N2N_KEY                | Encryption key (ASCII). Not with -k.\n");

#ifdef WIN32
  printf("\nAvailable TAP adapters:\n");
  win_print_available_adapters();
#endif

  exit(0);
}

/* *************************************************** */

static void setPayloadCompression(n2n_edge_conf_t *conf, int compression) {
  /* even though 'compression' and 'conf->compression' share the same encoding scheme,
   * a switch-statement under conditional compilation is used to sort out the
   * unsupported optarguments */
  switch (compression) {
  case 1:
    {
      conf->compression = N2N_COMPRESSION_ID_LZO;
      break;
    }
#ifdef N2N_HAVE_ZSTD
  case 2:
    {
      conf->compression = N2N_COMPRESSION_ID_ZSTD;
      break;
    }
#endif
  default:
    {
      conf->compression = N2N_COMPRESSION_ID_NONE;
      traceEvent(TRACE_NORMAL, "the %s compression given by -z_ option is not supported in this version.", compression_str(compression));
      exit(1); // to make the user aware
    }
  }
}

/* *************************************************** */

static void setPayloadEncryption( n2n_edge_conf_t *conf, int cipher) {
  /* even though 'cipher' and 'conf->transop_id' share the same encoding scheme,
   * a switch-statement under conditional compilation is used to sort out the
   * unsupported ciphers */
  switch (cipher) {
  case 1:
    {
      conf->transop_id = N2N_TRANSFORM_ID_NULL;
      break;
    }
  case 2:
    {
      conf->transop_id = N2N_TRANSFORM_ID_TWOFISH;
      break;
    }
#ifdef N2N_HAVE_AES
  case 3:
    {
      conf->transop_id = N2N_TRANSFORM_ID_AESCBC;
      break;
    }
#endif
#ifdef HAVE_OPENSSL_1_1
  case 4:
    {
      conf->transop_id = N2N_TRANSFORM_ID_CHACHA20;
      break;
    }
#endif
  case 5:
    {
      conf->transop_id = N2N_TRANSFORM_ID_SPECK;
      break;
    }
  default:
    {
      conf->transop_id = N2N_TRANSFORM_ID_INVAL;
      traceEvent(TRACE_NORMAL, "the %s cipher given by -A_ option is not supported in this version.", transop_str(cipher));
      exit(1);
    }
  }
}

/* *************************************************** */

static int setOption(int optkey, char *optargument, n2n_tuntap_priv_config_t *ec, n2n_edge_conf_t *conf) {
  /* traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, optargument ? optargument : ""); */

  switch(optkey) {
  case 'a': /* IP address and mode of TUNTAP interface */
    {
      scan_address(ec->ip_addr, N2N_NETMASK_STR_SIZE,
		   ec->ip_mode, N2N_IF_MODE_SIZE,
		   optargument);
      break;
    }

  case 'c': /* community as a string */
    {
      memset(conf->community_name, 0, N2N_COMMUNITY_SIZE);
      strncpy((char *)conf->community_name, optargument, N2N_COMMUNITY_SIZE);
      conf->community_name[N2N_COMMUNITY_SIZE-1] = '\0';
      break;
    }

  case 'E': /* multicast ethernet addresses accepted. */
    {
      conf->drop_multicast=0;
      traceEvent(TRACE_DEBUG, "Enabling ethernet multicast traffic");
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
      ec->daemon=0;
      break;
    }
#endif /* #ifndef WIN32 */

  case 'm' : /* TUNTAP MAC address */
    {
      strncpy(ec->device_mac,optargument,N2N_MACNAMSIZ);
      ec->device_mac[N2N_MACNAMSIZ-1] = '\0';
      break;
    }

  case 'M' : /* TUNTAP MTU */
    {
      ec->mtu = atoi(optargument);
      break;
    }

#ifndef __APPLE__
  case 'D' : /* enable PMTU discovery */
    {
      conf->disable_pmtu_discovery = 0;
      break;
    }
#endif

  case 'k': /* encrypt key */
    {
      if(conf->encrypt_key) free(conf->encrypt_key);
      conf->encrypt_key = strdup(optargument);
      traceEvent(TRACE_DEBUG, "encrypt_key = '%s'\n", conf->encrypt_key);
      break;
    }

  case 'r': /* enable packet routing across n2n endpoints */
    {
      conf->allow_routing = 1;
      break;
    }

  case 'A':
    {
      int cipher;

      if (optargument) {
        cipher = atoi(optargument);
      } else {
        traceEvent(TRACE_NORMAL, "the use of the solitary -A switch is deprecated and might not be supported in future versions. "
		   "please use -A3 instead to choose a the AES-CBC cipher for payload encryption.");

      	cipher = N2N_TRANSFORM_ID_AESCBC; // default, if '-A' only   
      }

      setPayloadEncryption(conf, cipher);
      break;
    }

  case 'H': /* indicate header encryption */
    {
	/* we cannot be sure if this gets parsed before the community name is set.
	 * so, only an indicator is set, action is taken later*/
	conf->header_encryption = HEADER_ENCRYPTION_ENABLED;
	break;
    }

  case 'z':
    {
      int compression;
      
      if (optargument) {
        compression = atoi(optargument);
      } else
	compression = N2N_COMPRESSION_ID_LZO; // default, if '-z' only

      setPayloadCompression(conf, compression);
      break;
    }

  case 'l': /* supernode-list */
    if(optargument) {
      if(edge_conf_add_supernode(conf, optargument) != 0) {
        traceEvent(TRACE_WARNING, "Too many supernodes!");
        exit(1);
      }
      break;
    }

  case 'i': /* supernode registration interval */
    conf->register_interval = atoi(optargument);
    break;

  case 'L': /* supernode registration interval */
    conf->register_ttl = atoi(optarg);
    break;

#if defined(N2N_CAN_NAME_IFACE)
  case 'd': /* TUNTAP name */
    {
      strncpy(ec->tuntap_dev_name, optargument, N2N_IFNAMSIZ);
      ec->tuntap_dev_name[N2N_IFNAMSIZ-1] = '\0';
      break;
    }
#endif

  case 'p':
    {
      conf->local_port = atoi(optargument);
      break;
    }

  case 't':
    {
      conf->mgmt_port = atoi(optargument);
      break;
    }

#ifdef __linux__
  case 'T':
    {
      if((optargument[0] == '0') && (optargument[1] == 'x'))
        conf->tos = strtol(&optargument[2], NULL, 16);
      else
        conf->tos = atoi(optargument);

      break;
    }
#endif

  case 'n':
    {
      char cidr_net[64], gateway[64];
      n2n_route_t route;

      if(sscanf(optargument, "%63[^/]/%hhd:%63s", cidr_net, &route.net_bitlen, gateway) != 3) {
        traceEvent(TRACE_WARNING, "Bad cidr/gateway format '%d'. See -h.", optargument);
        break;
      }

      route.net_addr = inet_addr(cidr_net);
      route.gateway = inet_addr(gateway);

      if((route.net_bitlen < 0) || (route.net_bitlen > 32)) {
        traceEvent(TRACE_WARNING, "Bad prefix '%d' in '%s'", route.net_bitlen, optargument);
        break;
      }

      if(route.net_addr == INADDR_NONE) {
        traceEvent(TRACE_WARNING, "Bad network '%s' in '%s'", cidr_net, optargument);
        break;
      }

      if(route.gateway == INADDR_NONE) {
        traceEvent(TRACE_WARNING, "Bad gateway '%s' in '%s'", gateway, optargument);
        break;
      }

      traceEvent(TRACE_DEBUG, "Adding %s/%d via %s", cidr_net, route.net_bitlen, gateway);

      conf->routes = realloc(conf->routes, sizeof(struct n2n_route) * (conf->num_routes + 1));
      conf->routes[conf->num_routes] = route;
      conf->num_routes++;

      break;
    }

  case 's': /* Subnet Mask */
    {
      if(0 != ec->got_s) {
        traceEvent(TRACE_WARNING, "Multiple subnet masks supplied");
      }
      strncpy(ec->netmask, optargument, N2N_NETMASK_STR_SIZE);
      ec->netmask[N2N_NETMASK_STR_SIZE - 1] = '\0';
      ec->got_s = 1;
      break;
    }

  case 'S':
    {
      conf->allow_p2p = 0;
      break;
    }

  case 'h': /* help */
    {
      help();
      break;
    }

  case 'v': /* verbose */
    setTraceLevel(getTraceLevel() + 1);
    break;

  default:
    {
      traceEvent(TRACE_WARNING, "Unknown option -%c: Ignored", (char)optkey);
      return(-1);
    }
  }

  return(0);
}

/* *********************************************** */

static const struct option long_options[] =
  {
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
static int loadFromCLI(int argc, char *argv[], n2n_edge_conf_t *conf, n2n_tuntap_priv_config_t *ec) {
  u_char c;

  while ((c = getopt_long(argc, argv,
                          "k:a:bc:Eu:g:m:M:s:d:l:p:fvhrt:i:SDL:z::A::Hn:"
#ifdef __linux__
                          "T:"
#endif
                          ,
                          long_options, NULL)) != '?') {
    if(c == 255) break;
    setOption(c, optarg, ec, conf);
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
static int loadFromFile(const char *path, n2n_edge_conf_t *conf, n2n_tuntap_priv_config_t *ec) {
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
	  setOption(opt->val, value, ec, conf);
	  break;
	}

	opt++;
      }
    } else if(line[0] == '-') { /* short opt */
      char *equal;
      
      key = &line[1], line_len--;

      equal = strchr(line, '=');

      if(equal) {
	equal[0] = '\0';

	value = &equal[1];

      } else {

	value = NULL;

	/* Adding an exception for -A_ -z_ which can come
           without '=' and even without any further data */

	if (key[0] == 'z') {
	  if (key[1]) value = &key[1];
	  key = "z";
	} else if (key[0] == 'A') {
	  if (key[1]) value = &key[1];
	  key = "A";
        }
      }
      // traceEvent(TRACE_NORMAL, "key: %c value: %s", key[0], value);
      setOption(key[0], value, ec, conf);
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

static int keep_on_running;

#if defined(__linux__) || defined(WIN32)
#ifdef WIN32
BOOL WINAPI term_handler(DWORD sig)
#else
  static void term_handler(int sig)
#endif
{
  static int called = 0;

  if(called) {
    traceEvent(TRACE_NORMAL, "Ok I am leaving now");
    _exit(0);
  } else {
    traceEvent(TRACE_NORMAL, "Shutting down...");
    called = 1;
  }

  keep_on_running = 0;
#ifdef WIN32
  return(TRUE);
#endif
}
#endif /* defined(__linux__) || defined(WIN32) */

/* *************************************************** */

/** Entry point to program from kernel. */
int main(int argc, char* argv[]) {
  int rc;
  tuntap_dev tuntap;    /* a tuntap device */
  n2n_edge_t *eee;      /* single instance for this program */
  n2n_edge_conf_t conf; /* generic N2N edge config */
  n2n_tuntap_priv_config_t ec; /* config used for standalone program execution */
#ifndef WIN32
  struct passwd *pw = NULL;
#endif
#ifdef HAVE_LIBCAP
  cap_t caps;
#endif

  /* Defaults */
  edge_init_conf_defaults(&conf);
  memset(&ec, 0, sizeof(ec));
  ec.mtu = DEFAULT_MTU;
  ec.daemon = 1;    /* By default run in daemon mode. */

#ifndef WIN32
  if(((pw = getpwnam("n2n")) != NULL) ||
     ((pw = getpwnam("nobody")) != NULL)) {
    ec.userid = pw->pw_uid;
    ec.groupid = pw->pw_gid;
  }
#endif

#ifdef WIN32
  ec.tuntap_dev_name[0] = '\0';
#else
  snprintf(ec.tuntap_dev_name, sizeof(ec.tuntap_dev_name), "edge0");
#endif
  snprintf(ec.netmask, sizeof(ec.netmask), "255.255.255.0");

  if((argc >= 2) && (argv[1][0] != '-')) {
    rc = loadFromFile(argv[1], &conf, &ec);
    if(argc > 2)
      rc = loadFromCLI(argc, argv, &conf, &ec);
  } else if(argc > 1)
    rc = loadFromCLI(argc, argv, &conf, &ec);
  else
#ifdef WIN32
    /* Load from current directory */
    rc = loadFromFile("edge.conf", &conf, &ec);
#else
  rc = -1;
#endif

  if(conf.transop_id == N2N_TRANSFORM_ID_NULL) {
    if(conf.encrypt_key) {
      /* make sure that Twofish is default cipher if key only (and no cipher) is specified */
      traceEvent(TRACE_WARNING, "Switching to Twofish as key was provided.");
      conf.transop_id = N2N_TRANSFORM_ID_TWOFISH;
    }
  }

  if(rc < 0)
    help();

  if(edge_verify_conf(&conf) != 0)
    help();

  traceEvent(TRACE_NORMAL, "Starting n2n edge %s %s", PACKAGE_VERSION, PACKAGE_BUILDDATE);

#if defined(HAVE_OPENSSL_1_1)
  traceEvent(TRACE_NORMAL, "Using %s", OpenSSL_version(0));
#endif
  
  traceEvent(TRACE_NORMAL, "Using compression: %s.", compression_str(conf.compression));
  traceEvent(TRACE_NORMAL, "Using %s cipher.", transop_str(conf.transop_id));

  /* Random seed */
  n2n_srand (n2n_seed());

#ifndef WIN32
  /* If running suid root then we need to setuid before using the force. */
  if(setuid(0) != 0)
    traceEvent(TRACE_ERROR, "Unable to become root [%u/%s]", errno, strerror(errno)); 
  /* setgid(0); */
#endif

  if(conf.encrypt_key && !strcmp((char*)conf.community_name, conf.encrypt_key))
    traceEvent(TRACE_WARNING, "Community and encryption key must differ, otherwise security will be compromised");

	if((eee = edge_init(&conf, &rc)) == NULL) {
		traceEvent(TRACE_ERROR, "Failed in edge_init");
		exit(1);
	}
	memcpy(&(eee->tuntap_priv_conf), &ec, sizeof(ec));

	if ((0 == strcmp("static", eee->tuntap_priv_conf.ip_mode)) ||
	    ((eee->tuntap_priv_conf.ip_mode[0] == '\0') && (eee->tuntap_priv_conf.ip_addr[0] != '\0'))) {
		traceEvent(TRACE_NORMAL, "Use manually set IP address.");
		eee->conf.tuntap_ip_mode = TUNTAP_IP_MODE_STATIC;
	} else if (0 == strcmp("dhcp", eee->tuntap_priv_conf.ip_mode)) {
		traceEvent(TRACE_NORMAL, "Obtain IP from other edge DHCP services.");
		eee->conf.tuntap_ip_mode = TUNTAP_IP_MODE_DHCP;
	} else {
		traceEvent(TRACE_NORMAL, "Automatically assign IP address by supernode.");
		eee->conf.tuntap_ip_mode = TUNTAP_IP_MODE_SN_ASSIGN;
		do {
			fd_set socket_mask;
			struct timeval wait_time;

			update_supernode_reg(eee, time(NULL));
			FD_ZERO(&socket_mask);
			FD_SET(eee->udp_sock, &socket_mask);
			wait_time.tv_sec = SOCKET_TIMEOUT_INTERVAL_SECS;
			wait_time.tv_usec = 0;

			if (select(eee->udp_sock + 1, &socket_mask, NULL, NULL, &wait_time) > 0) {
				if (FD_ISSET(eee->udp_sock, &socket_mask)) {
					readFromIPSocket(eee, eee->udp_sock);
				}
			}
		} while (eee->sn_wait);
		eee->last_register_req = 0;
	}

	if (tuntap_open(&tuntap, eee->tuntap_priv_conf.tuntap_dev_name, eee->tuntap_priv_conf.ip_mode,
	                eee->tuntap_priv_conf.ip_addr, eee->tuntap_priv_conf.netmask,
	                eee->tuntap_priv_conf.device_mac, eee->tuntap_priv_conf.mtu) < 0) exit(1);
	traceEvent(TRACE_NORMAL, "Local tuntap IP: %s, Mask: %s",
	           eee->tuntap_priv_conf.ip_addr, eee->tuntap_priv_conf.netmask);
	memcpy(&eee->device, &tuntap, sizeof(tuntap));
//	hexdump((unsigned char*)&tuntap,sizeof(tuntap_dev));

#ifndef WIN32
  if(eee->tuntap_priv_conf.daemon) {
    setUseSyslog(1); /* traceEvent output now goes to syslog. */
    daemonize();
  }
#endif /* #ifndef WIN32 */

#ifndef WIN32

#ifdef HAVE_LIBCAP
  /* Before dropping the privileges, retain capabilities to regain them in future. */
  caps = cap_get_proc();

  cap_set_flag(caps, CAP_PERMITTED, num_cap, cap_values, CAP_SET);
  cap_set_flag(caps, CAP_EFFECTIVE, num_cap, cap_values, CAP_SET);

  if((cap_set_proc(caps) != 0) || (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0))
    traceEvent(TRACE_WARNING, "Unable to retain permitted capabilities [%s]\n", strerror(errno));
#else
#ifndef __APPLE__
  traceEvent(TRACE_WARNING, "n2n has not been compiled with libcap-dev. Some commands may fail.");
#endif
#endif /* HAVE_LIBCAP */

  if((eee->tuntap_priv_conf.userid != 0) || (eee->tuntap_priv_conf.groupid != 0)) {
    traceEvent(TRACE_NORMAL, "Dropping privileges to uid=%d, gid=%d",
	       (signed int)eee->tuntap_priv_conf.userid, (signed int)eee->tuntap_priv_conf.groupid);

    /* Finished with the need for root privileges. Drop to unprivileged user. */
    if((setgid(eee->tuntap_priv_conf.groupid) != 0)
       || (setuid(eee->tuntap_priv_conf.userid) != 0)) {
      traceEvent(TRACE_ERROR, "Unable to drop privileges [%u/%s]", errno, strerror(errno));
      exit(1);
    }
  }

  if((getuid() == 0) || (getgid() == 0))
    traceEvent(TRACE_WARNING, "Running as root is discouraged, check out the -u/-g options");
#endif

#ifdef __linux__
  signal(SIGTERM, term_handler);
  signal(SIGINT,  term_handler);
#endif
#ifdef WIN32
  SetConsoleCtrlHandler(term_handler, TRUE);
#endif

  keep_on_running = 1;
  traceEvent(TRACE_NORMAL, "edge started");
  rc = run_edge_loop(eee, &keep_on_running);
  print_edge_stats(eee);

#ifdef HAVE_LIBCAP
  /* Before completing the cleanup, regain the capabilities as some
   * cleanup tasks require them (e.g. routes cleanup). */
  cap_set_flag(caps, CAP_EFFECTIVE, num_cap, cap_values, CAP_SET);

  if(cap_set_proc(caps) != 0)
    traceEvent(TRACE_WARNING, "Could not regain the capabilities [%s]\n", strerror(errno));

  cap_free(caps);
#endif

  /* Cleanup */
  edge_term(eee);
  edge_term_conf(&eee->conf);
  tuntap_close(&eee->device);

  return(rc);
}

/* ************************************** */
