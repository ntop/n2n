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

#define N2N_NETMASK_STR_SIZE    16 /* dotted decimal 12 numbers + 3 dots */
#define N2N_MACNAMSIZ           18 /* AA:BB:CC:DD:EE:FF + NULL*/
#define N2N_IF_MODE_SIZE        16 /* static | dhcp */

/* *************************************************** */

/** maximum length of command line arguments */
#define MAX_CMDLINE_BUFFER_LENGTH    4096

/** maximum length of a line in the configuration file */
#define MAX_CONFFILE_LINE_LENGTH     1024

/* ******************************************************* */

/** Main structure type for edge. */

/* ************************************** */

/* parse the configuration file */
static int readConfFile(const char * filename, char * const linebuffer) {
  struct stat stats;
  FILE    *   fd;
  char    *   buffer = NULL;

  buffer = (char *)malloc(MAX_CONFFILE_LINE_LENGTH);
  if(!buffer) {
    traceEvent(TRACE_ERROR, "Unable to allocate memory");
    return -1;
  }

  if(stat(filename, &stats)) {
    if(errno == ENOENT)
      traceEvent(TRACE_ERROR, "parameter file %s not found/unable to access\n", filename);
    else
      traceEvent(TRACE_ERROR, "cannot stat file %s, errno=%d\n",filename, errno);
    free(buffer);
    return -1;
  }

  fd = fopen(filename, "rb");
  if(!fd) {
    traceEvent(TRACE_ERROR, "Unable to open parameter file '%s' (%d)...\n",filename,errno);
    free(buffer);
    return -1;
  }
  while(fgets(buffer, MAX_CONFFILE_LINE_LENGTH,fd)) {
    char    *   p = NULL;

    /* strip out comments */
    p = strchr(buffer, '#');
    if(p) *p ='\0';

    /* remove \n */
    p = strchr(buffer, '\n');
    if(p) *p ='\0';

    /* strip out heading spaces */
    p = buffer;
    while(*p == ' ' && *p != '\0') ++p;
    if(p != buffer) strncpy(buffer,p,strlen(p)+1);

    /* strip out trailing spaces */
    while(strlen(buffer) && buffer[strlen(buffer)-1]==' ')
      buffer[strlen(buffer)-1]= '\0';

    /* check for nested @file option */
    if(strchr(buffer, '@')) {
      traceEvent(TRACE_ERROR, "@file in file nesting is not supported\n");
      free(buffer);
      return -1;
    }
    if((strlen(linebuffer)+strlen(buffer)+2)< MAX_CMDLINE_BUFFER_LENGTH) {
      strncat(linebuffer, " ", 1);
      strncat(linebuffer, buffer, strlen(buffer));
    } else {
      traceEvent(TRACE_ERROR, "too many argument");
      free(buffer);
      return -1;
    }
  }

  free(buffer);
  fclose(fd);

  return 0;
}

/* ************************************** */

/* Create the argv vector */
static char ** buildargv(int * effectiveargc, char * const linebuffer) {
  const int  INITIAL_MAXARGC = 16;	/* Number of args + NULL in initial argv */
  int     maxargc;
  int     argc=0;
  char ** argv;
  char *  buffer, * buff;

  *effectiveargc = 0;
  buffer = (char *)calloc(1, strlen(linebuffer)+2);
  if(!buffer) {
    traceEvent(TRACE_ERROR, "Unable to allocate memory");
    return NULL;
  }
  strncpy(buffer, linebuffer,strlen(linebuffer));

  maxargc = INITIAL_MAXARGC;
  argv = (char **)malloc(maxargc * sizeof(char*));
  if(argv == NULL) {
    traceEvent(TRACE_ERROR, "Unable to allocate memory");
    return NULL;
  }

  buff = buffer;

  while(buff) {
    char * p = strchr(buff,' ');
    if(p) {
      *p='\0';
      argv[argc++] = strdup(buff);
      while(*++p == ' ' && *p != '\0');
      buff=p;
      if(argc >= maxargc) {
	maxargc *= 2;
	argv = (char **)realloc(argv, maxargc * sizeof(char*));
	if(argv == NULL) {
	  traceEvent(TRACE_ERROR, "Unable to re-allocate memory");
	  free(buffer);
	  return NULL;
	}
      }
    } else {
      argv[argc++] = strdup(buff);
      break;
    }
  }
  free(buffer);
  *effectiveargc = argc;

  return argv;
}

/* ************************************** */

static void help() {
  print_n2n_version();

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
  int     opt;
  int     keep_on_running = 1;
  int     local_port = 0 /* any port */;
  int     mgmt_port = N2N_EDGE_MGMT_PORT; /* 5644 by default */
  char    tuntap_dev_name[N2N_IFNAMSIZ] = "edge0";
  char    ip_mode[N2N_IF_MODE_SIZE] = "static";
  char    ip_addr[N2N_NETMASK_STR_SIZE] = "";
  char    netmask[N2N_NETMASK_STR_SIZE] = "255.255.255.0";
  int     mtu = DEFAULT_MTU;
  int     got_s = 0;

#ifndef WIN32
  uid_t   userid = 0; /* root is the only guaranteed ID */
  gid_t   groupid = 0; /* root is the only guaranteed ID */
#endif

  char    device_mac[N2N_MACNAMSIZ] = "";
  char *  encrypt_key = NULL;

  int     i, effectiveargc = 0;
  char ** effectiveargv = NULL;
  char  * linebuffer = NULL;

  n2n_edge_t eee; /* single instance for this program */

  if(-1 == edge_init(&eee))
    {
      traceEvent(TRACE_ERROR, "Failed in edge_init");
      exit(1);
    }

  if(getenv("N2N_KEY"))
    {
      encrypt_key = strdup(getenv("N2N_KEY"));
    }

#ifdef WIN32
  tuntap_dev_name[0] = '\0';
#endif
  memset(&(eee.supernode), 0, sizeof(eee.supernode));
  eee.supernode.family = AF_INET;

  linebuffer = (char *)malloc(MAX_CMDLINE_BUFFER_LENGTH);
  if(!linebuffer)
    {
      traceEvent(TRACE_ERROR, "Unable to allocate memory");
      exit(1);
    }
  snprintf(linebuffer, MAX_CMDLINE_BUFFER_LENGTH, "%s",argv[0]);

#ifdef WIN32
  for(i=0; i < (int)strlen(linebuffer); i++)
    if(linebuffer[i] == '\\') linebuffer[i] = '/';
#endif

  for(i=1;i<argc;++i)
    {
      if(argv[i][0] == '@')
        {
	  if(readConfFile(&argv[i][1], linebuffer)<0) exit(1); /* <<<<----- check */
        }
      else if((strlen(linebuffer)+strlen(argv[i])+2) < MAX_CMDLINE_BUFFER_LENGTH)
        {
	  strncat(linebuffer, " ", 1);
	  strncat(linebuffer, argv[i], strlen(argv[i]));
        }
      else
        {
	  traceEvent(TRACE_ERROR, "too many argument");
	  exit(1);
        }
    }
  /*  strip trailing spaces */
  while(strlen(linebuffer) && linebuffer[strlen(linebuffer)-1]==' ')
    linebuffer[strlen(linebuffer)-1]= '\0';

  /* build the new argv from the linebuffer */
  effectiveargv = buildargv(&effectiveargc, linebuffer);

  if(linebuffer)
    {
      free(linebuffer);
      linebuffer = NULL;
    }

  /* {int k;for(k=0;k<effectiveargc;++k)  printf("%s\n",effectiveargv[k]);} */

  if(effectiveargc < 2)
    help();

  optarg = NULL;
  while((opt = getopt_long(effectiveargc,
			   effectiveargv,
			   "K:k:a:bc:Eu:g:m:M:s:d:l:p:fvhrt:", long_options, NULL)) != EOF) {
    switch (opt)
      {
      case'K':
	{
	  if(encrypt_key)
	    {
	      fprintf(stderr, "Error: -K and -k options are mutually exclusive.\n");
	      exit(1);
	    }
	  else
	    {
	      strncpy(eee.keyschedule, optarg, N2N_PATHNAME_MAXLEN-1);
	      /* strncpy does not add NULL if the source has no NULL. */
	      eee.keyschedule[N2N_PATHNAME_MAXLEN-1] = 0;
	      
	      traceEvent(TRACE_DEBUG, "keyfile = '%s'\n", eee.keyschedule);
	      fprintf(stderr, "keyfile = '%s'\n", eee.keyschedule);
	    }
	  break;
	}
      case 'a': /* IP address and mode of TUNTAP interface */
	{
	  scan_address(ip_addr, N2N_NETMASK_STR_SIZE,
		       ip_mode, N2N_IF_MODE_SIZE,
		       optarg);
	  break;
	}
      case 'c': /* community as a string */
	{
	  memset(eee.community_name, 0, N2N_COMMUNITY_SIZE);
	  strncpy((char *)eee.community_name, optarg, N2N_COMMUNITY_SIZE);
	  break;
	}
      case 'E': /* multicast ethernet addresses accepted. */
	{
	  eee.drop_multicast=0;
	  traceEvent(TRACE_DEBUG, "Enabling ethernet multicast traffic\n");
	  break;
	}

#ifndef WIN32
      case 'u': /* unprivileged uid */
	{
	  userid = atoi(optarg);
	  break;
	}
      case 'g': /* unprivileged uid */
	{
	  groupid = atoi(optarg);
	  break;
	}
#endif
#ifndef WIN32
      case 'f' : /* do not fork as daemon */
	{
	  eee.daemon=0;
	  break;
	}
#endif /* #ifndef WIN32 */

      case 'm' : /* TUNTAP MAC address */
	{
	  strncpy(device_mac,optarg,N2N_MACNAMSIZ);
	  break;
	}

      case 'M' : /* TUNTAP MTU */
	{
	  mtu = atoi(optarg);
	  break;
	}

      case 'k': /* encrypt key */
	{
	  if(strlen(eee.keyschedule) > 0)
	    {
	      fprintf(stderr, "Error: -K and -k options are mutually exclusive.\n");
	      exit(1);
	    } else {
	    traceEvent(TRACE_DEBUG, "encrypt_key = '%s'\n", encrypt_key);
	    encrypt_key = strdup(optarg);
	  }
	  break;
	}
      case 'r': /* enable packet routing across n2n endpoints */
	{
	  eee.allow_routing = 1;
	  break;
	}

      case 'l': /* supernode-list */
	{
	  if(eee.sn_num < N2N_EDGE_NUM_SUPERNODES)
	    {
	      strncpy((eee.sn_ip_array[eee.sn_num]), optarg, N2N_EDGE_SN_HOST_SIZE);
	      traceEvent(TRACE_DEBUG, "Adding supernode[%u] = %s\n", (unsigned int)eee.sn_num, (eee.sn_ip_array[eee.sn_num]));
	      ++eee.sn_num;
	    }
	  else
	    {
	      fprintf(stderr, "Too many supernodes!\n");
	      exit(1);
	    }
	  break;
	}

#if defined(N2N_CAN_NAME_IFACE)
      case 'd': /* TUNTAP name */
	{
	  strncpy(tuntap_dev_name, optarg, N2N_IFNAMSIZ);
	  break;
	}
#endif

      case 'b':
	{
	  eee.re_resolve_supernode_ip = 1;
	  break;
	}

      case 'p':
	{
	  local_port = atoi(optarg);
	  break;
	}

      case 't':
	{
	  mgmt_port = atoi(optarg);
	  break;
	}

      case 's': /* Subnet Mask */
	{
	  if(0 != got_s)
	    {
	      traceEvent(TRACE_WARNING, "Multiple subnet masks supplied.");
	    }
	  strncpy(netmask, optarg, N2N_NETMASK_STR_SIZE);
	  got_s = 1;
	  break;
	}

      case 'h': /* help */
	{
	  help();
	  break;
	}

      case 'v': /* verbose */
	{
	  ++traceLevel; /* do 2 -v flags to increase verbosity to DEBUG level*/
	  break;
	}

      } /* end switch */
  }


#ifndef WIN32
  if(eee.daemon) {
    useSyslog = 1; /* traceEvent output now goes to syslog. */
    daemonize();
  }
#endif /* #ifndef WIN32 */

  traceEvent(TRACE_NORMAL, "Starting n2n edge %s %s", n2n_sw_version, n2n_sw_buildDate);

  for (i=0; i< N2N_EDGE_NUM_SUPERNODES; ++i)
    traceEvent(TRACE_NORMAL, "supernode %u => %s\n", i, (eee.sn_ip_array[i]));

  supernode2addr(&(eee.supernode), eee.sn_ip_array[eee.sn_idx]);

  for (i=0; i<effectiveargc; ++i)
    free(effectiveargv[i]);

  free(effectiveargv);
  effectiveargv = NULL, effectiveargc = 0;

  if(!(
#ifdef __linux__
       (tuntap_dev_name[0] != 0) &&
#endif
       (eee.community_name[0] != 0) &&
       (ip_addr[0] != 0)
       ))
    {
      help();
    }

  if((NULL == encrypt_key) && (0 == strlen(eee.keyschedule)))
    {
      traceEvent(TRACE_WARNING, "Encryption is disabled in edge.");

      eee.null_transop = 1;
    }

#ifndef WIN32
  /* If running suid root then we need to setuid before using the force. */
  setuid(0);
  /* setgid(0); */
#endif

  if(0 == strcmp("dhcp", ip_mode)) {
    traceEvent(TRACE_NORMAL, "Dynamic IP address assignment enabled.");
    
    eee.dyn_ip_mode = 1;
  } else
    traceEvent(TRACE_NORMAL, "ip_mode='%s'", ip_mode);    

  if(tuntap_open(&(eee.device), tuntap_dev_name, ip_mode, ip_addr, netmask, device_mac, mtu) < 0)
    return(-1);

#ifndef WIN32
  if((userid != 0) || (groupid != 0)) {
    traceEvent(TRACE_NORMAL, "Interface up. Dropping privileges to uid=%d, gid=%d",
	       (signed int)userid, (signed int)groupid);

    /* Finished with the need for root privileges. Drop to unprivileged user. */
    setreuid(userid, userid);
    setregid(groupid, groupid);
  }
#endif

  if(local_port > 0)
    traceEvent(TRACE_NORMAL, "Binding to local port %d", (signed int)local_port);

  if(encrypt_key) {
    if(edge_init_twofish(&eee, (uint8_t *)(encrypt_key), strlen(encrypt_key)) < 0) {
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

  eee.udp_sock = open_socket(local_port, 1 /* bind ANY */);
  if(eee.udp_sock < 0) {
    traceEvent(TRACE_ERROR, "Failed to bind main UDP port %u", (signed int)local_port);
    return(-1);
  }
  
  eee.udp_mgmt_sock = open_socket(mgmt_port, 0 /* bind LOOPBACK */);
  
  if(eee.udp_mgmt_sock < 0) {
    traceEvent(TRACE_ERROR, "Failed to bind management UDP port %u", mgmt_port);
    return(-1);
  }
  
  traceEvent(TRACE_NORMAL, "edge started");

  update_supernode_reg(&eee, time(NULL));

  return run_edge_loop(&eee, &keep_on_running);
}

/* ************************************** */
