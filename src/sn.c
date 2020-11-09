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

/* Supernode for n2n-2.x */

#include "n2n.h"
#include "header_encryption.h"

#define HASH_FIND_COMMUNITY(head, name, out) HASH_FIND_STR(head, name, out)

static n2n_sn_t sss_node;
static const n2n_mac_t null_mac = {0, 0, 0, 0, 0, 0};

/** Load the list of allowed communities. Existing/previous ones will be removed
 *
 */
static int load_allowed_sn_community(n2n_sn_t *sss, char *path) {
  char buffer[4096], *line, *cmn_str, net_str[20];
  dec_ip_str_t ip_str = {'\0'};
  uint8_t bitlen;
  in_addr_t net;
  uint32_t mask;
  FILE *fd = fopen(path, "r");
  struct sn_community *s, *tmp;
  uint32_t num_communities = 0;
  struct sn_community_regular_expression *re, *tmp_re;
  uint32_t num_regex = 0;
  int has_net;

  if(fd == NULL) {
    traceEvent(TRACE_WARNING, "File %s not found", path);
    return -1;
  }

  HASH_ITER(hh, sss->communities, s, tmp) {
    if(s->is_federation) continue;
    HASH_DEL(sss->communities, s);
    if (NULL != s->header_encryption_ctx)
      free (s->header_encryption_ctx);
    free(s);
  }

  HASH_ITER(hh, sss->rules, re, tmp_re) {
    HASH_DEL(sss->rules, re);
    free(re);
  }

  while((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {
    int len = strlen(line);

    if((len < 2) || line[0] == '#')
      continue;

    len--;
    while(len > 0) {
      if((line[len] == '\n') || (line[len] == '\r')) {
	line[len] = '\0';
	len--;
      } else
	break;
    }

    // cut off any IP sub-network upfront
    cmn_str = (char*)calloc(len+1, sizeof(char));
    has_net = ( sscanf (line, "%s %s", cmn_str, net_str) == 2 );

    // if it contains typical characters...
    if(NULL != strpbrk(cmn_str, ".*+?[]\\")) {
      // ...it is treated as regular expression
      re = (struct sn_community_regular_expression*)calloc(1,sizeof(struct sn_community_regular_expression));
      if (re) {
        re->rule = re_compile(cmn_str);
        HASH_ADD_PTR(sss->rules, rule, re);
	num_regex++;
        traceEvent(TRACE_INFO, "Added regular expression for allowed communities '%s'", cmn_str);
        free(cmn_str);
        continue;
      }
    }

    s = (struct sn_community*)calloc(1,sizeof(struct sn_community));

    if(s != NULL) {
      comm_init(s,cmn_str);
      /* loaded from file, this community is unpurgeable */
      s->purgeable = COMMUNITY_UNPURGEABLE;
      /* we do not know if header encryption is used in this community,
       * first packet will show. just in case, setup the key.           */
      s->header_encryption = HEADER_ENCRYPTION_UNKNOWN;
      packet_header_setup_key (s->community, &(s->header_encryption_ctx), &(s->header_iv_ctx));
      HASH_ADD_STR(sss->communities, community, s);

      num_communities++;
      traceEvent(TRACE_INFO, "Added allowed community '%s' [total: %u]",
		 (char*)s->community, num_communities);

      // check for sub-network address
      if(has_net) {
        if(sscanf(net_str, "%15[^/]/%hhu", ip_str, &bitlen) != 2) {
          traceEvent(TRACE_WARNING, "Bad net/bit format '%s' for community '%c', ignoring. See comments inside community.list file.",
		     net_str, cmn_str);
          has_net = 0;
        }
        net = inet_addr(ip_str);
        mask = bitlen2mask(bitlen);
        if((net == (in_addr_t)(-1)) || (net == INADDR_NONE) || (net == INADDR_ANY)
	   || ((ntohl(net) & ~mask) != 0) ) {
          traceEvent(TRACE_WARNING, "Bad network '%s/%u' in '%s' for community '%s', ignoring.",
		     ip_str, bitlen, net_str, cmn_str);
          has_net = 0;
        }
        if ((bitlen > 30) || (bitlen == 0)) {
          traceEvent(TRACE_WARNING, "Bad prefix '%hhu' in '%s' for community '%s', ignoring.",
		     bitlen, net_str, cmn_str);
          has_net = 0;
        }
      }
      if(has_net) {
        s->auto_ip_net.net_addr = ntohl(net);
        s->auto_ip_net.net_bitlen = bitlen;
        traceEvent(TRACE_INFO, "Assigned sub-network %s/%u to community '%s'.",
		   inet_ntoa(*(struct in_addr *) &net),
		   s->auto_ip_net.net_bitlen,
		   s->community);
      } else {
        assign_one_ip_subnet(sss, s);
      }
    }

    free(cmn_str);

  }

  fclose(fd);

  if ((num_regex + num_communities) == 0)
    {
      traceEvent(TRACE_WARNING, "File %s does not contain any valid community names or regular expressions", path);
      return -1;
    }

  traceEvent(TRACE_NORMAL, "Loaded %u fixed-name communities from %s",
	     num_communities, path);

  traceEvent(TRACE_NORMAL, "Loaded %u regular expressions for community name matching from %s",
	     num_regex, path);

  /* No new communities will be allowed */
  sss->lock_communities = 1;

  return(0);
}


/* *************************************************** */

/** Help message to print if the command line arguments are not valid. */
static void help() {
  print_n2n_version();

  printf("supernode <config file> (see supernode.conf)\n"
	 "or\n"
	 );
  printf("supernode ");
  printf("-p <local port> ");
  printf("-c <path> ");
  printf("-l <supernode:port> ");
#if defined(N2N_HAVE_DAEMON)
  printf("[-f] ");
#endif
  printf("[-F <federation_name>] ");
#if 0
  printf("[-m <mac_address>] ");
#endif /* #if 0 */
#ifndef WIN32
  printf("[-u <uid> -g <gid>] ");
#endif /* ifndef WIN32 */
  printf("[-t <mgmt port>] ");
  printf("[-a <net-net/bit>] ");
  printf("[-v] ");
  printf("\n\n");

  printf("-p <port>         | Set UDP main listen port to <port>\n");
  printf("-c <path>         | File containing the allowed communities.\n");
  printf("-l <sn host:port> | Name/IP of a known supernode:port.\n");
#if defined(N2N_HAVE_DAEMON)
  printf("-f                | Run in foreground.\n");
#endif /* #if defined(N2N_HAVE_DAEMON) */
  printf("-F <fed_name>     | Name of the supernodes federation (otherwise use '%s' by default)\n",(char *)FEDERATION_NAME);
#if 0
  printf("-m <mac_addr>     | Fix MAC address for the supernode (otherwise it may be random)\n"
         "                  | eg. -m 01:02:03:04:05:06\n");
#endif /* #if 0 */
#ifndef WIN32
  printf("-u <UID>          | User ID (numeric) to use when privileges are dropped.\n");
  printf("-g <GID>          | Group ID (numeric) to use when privileges are dropped.\n");
#endif /* ifndef WIN32 */
  printf("-t <port>         | Management UDP Port (for multiple supernodes on a machine).\n");
  printf("-a <net-net/bit>  | Subnet range for auto ip address service, e.g.\n");
  printf("                  | -a 192.168.0.0-192.168.255.0/24, defaults to 10.128.255.0-10.255.255.0/24\n");
  printf("-v                | Increase verbosity. Can be used multiple times.\n");
  printf("-h                | This help message.\n");
  printf("\n");

  exit(1);
}

/* *************************************************** */

static int setOption(int optkey, char *_optarg, n2n_sn_t *sss) {
  //traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, _optarg ? _optarg : "");

  switch (optkey) {
  case 'p': /* local-port */
    sss->lport = atoi(_optarg);

    if(sss->lport == 0){
      traceEvent(TRACE_WARNING, "Bad local port format");
      break;
    }

    break;

  case 't': /* mgmt-port */
    sss->mport = atoi(_optarg);

    if(sss->mport == 0){
      traceEvent(TRACE_WARNING, "Bad management port format");
      break;
    }

    break;

  case 'l': { /* supernode:port */
    n2n_sock_t *socket;
    struct peer_info *anchor_sn;
    size_t length;
    int rv = -1;
    int skip_add;
    char *double_column = strchr(_optarg, ':');

    length = strlen(_optarg);
    if(length >= N2N_EDGE_SN_HOST_SIZE) {
      traceEvent(TRACE_WARNING, "Size of -l argument too long: %zu. Maximum size is %d", length, N2N_EDGE_SN_HOST_SIZE);
      break;
    }

    if(!double_column){
      traceEvent(TRACE_WARNING, "Invalid -l format: ignored");
      return (-1);
    }

    socket = (n2n_sock_t *)calloc(1,sizeof(n2n_sock_t));
    rv = supernode2sock(socket, _optarg);

    if(rv != 0){
      traceEvent(TRACE_WARNING, "Invalid socket");
      free(socket);
      break;
    }

    if(sss->federation != NULL) {

      skip_add = NO_SKIP;
      anchor_sn = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), socket, (n2n_mac_t*) null_mac, &skip_add);

      if(anchor_sn != NULL){
        anchor_sn->ip_addr = calloc(1,N2N_EDGE_SN_HOST_SIZE);
        if(anchor_sn->ip_addr){
          strncpy(anchor_sn->ip_addr,_optarg,N2N_EDGE_SN_HOST_SIZE-1);
	  memcpy(&(anchor_sn->sock), socket, sizeof(n2n_sock_t));
          memcpy(&(anchor_sn->mac_addr),null_mac,sizeof(n2n_mac_t));
          anchor_sn->purgeable = SN_UNPURGEABLE;
          anchor_sn->last_valid_time_stamp = initial_time_stamp();

        }
      }
    }

    free(socket);
    break;
  }

  case 'a': {
    dec_ip_str_t ip_min_str = {'\0'};
    dec_ip_str_t ip_max_str = {'\0'};
    in_addr_t net_min, net_max;
    uint8_t bitlen;
    uint32_t mask;

    if (sscanf(_optarg, "%15[^\\-]-%15[^/]/%hhu", ip_min_str, ip_max_str, &bitlen) != 3) {
      traceEvent(TRACE_WARNING, "Bad net-net/bit format '%s'. See -h.", _optarg);
      break;
    }

    net_min = inet_addr(ip_min_str);
    net_max = inet_addr(ip_max_str);
    mask = bitlen2mask(bitlen);
    if ((net_min == (in_addr_t)(-1)) || (net_min == INADDR_NONE) || (net_min == INADDR_ANY)
	|| (net_max == (in_addr_t)(-1)) || (net_max == INADDR_NONE) || (net_max == INADDR_ANY)
	|| (ntohl(net_min) >  ntohl(net_max))
	|| ((ntohl(net_min) & ~mask) != 0) || ((ntohl(net_max) & ~mask) != 0) ) {
      traceEvent(TRACE_WARNING, "Bad network range '%s...%s/%u' in '%s', defaulting to '%s...%s/%d'",
		 ip_min_str, ip_max_str, bitlen, _optarg,
		 N2N_SN_MIN_AUTO_IP_NET_DEFAULT, N2N_SN_MAX_AUTO_IP_NET_DEFAULT, N2N_SN_AUTO_IP_NET_BIT_DEFAULT);
      break;
    }

    if ((bitlen > 30) || (bitlen == 0)) {
      traceEvent(TRACE_WARNING, "Bad prefix '%hhu' in '%s', defaulting to '%s...%s/%d'",
		 bitlen, _optarg,
		 N2N_SN_MIN_AUTO_IP_NET_DEFAULT, N2N_SN_MAX_AUTO_IP_NET_DEFAULT, N2N_SN_AUTO_IP_NET_BIT_DEFAULT);
      break;
    }

    traceEvent(TRACE_NORMAL, "The network range for community ip address service is '%s...%s/%hhu'.", ip_min_str, ip_max_str, bitlen);

    sss->min_auto_ip_net.net_addr = ntohl(net_min);
    sss->min_auto_ip_net.net_bitlen = bitlen;
    sss->max_auto_ip_net.net_addr = ntohl(net_max);
    sss->max_auto_ip_net.net_bitlen = bitlen;

    break;
  }

#ifndef WIN32
  case 'u': /* unprivileged uid */
    sss->userid = atoi(_optarg);
    break;

  case 'g': /* unprivileged uid */
    sss->groupid = atoi(_optarg);
    break;
#endif

  case 'F': { /* federation name */

      snprintf(sss->federation->community,N2N_COMMUNITY_SIZE-1,"*%s",_optarg);
      sss->federation->community[N2N_COMMUNITY_SIZE-1] = '\0';

    break;
  }

#if 0
  case 'm': {/* MAC address */
    str2mac(sss->mac_addr,_optarg);
    break;
  }
#endif /* #if 0 */

  case 'c': /* community file */
    load_allowed_sn_community(sss, _optarg);
    break;

  case 'f': /* foreground */
    sss->daemon = 0;
    break;

  case 'h': /* help */
    help();
    break;

  case 'v': /* verbose */
    setTraceLevel(getTraceLevel() + 1);
    break;

  default:
    traceEvent(TRACE_WARNING, "Unknown option -%c: Ignored.", (char) optkey);
    return (-1);
  }

  return (0);
}


/* *********************************************** */

static const struct option long_options[] = {
  {"communities", required_argument, NULL, 'c'},
  {"foreground",  no_argument,       NULL, 'f'},
  {"local-port",  required_argument, NULL, 'p'},
  {"mgmt-port",   required_argument, NULL, 't'},
  {"autoip",      required_argument, NULL, 'a'},
  {"help",        no_argument,       NULL, 'h'},
  {"verbose",     no_argument,       NULL, 'v'},
  {NULL, 0,                          NULL, 0}
};

/* *************************************************** */

/* read command line options */
static int loadFromCLI(int argc, char * const argv[], n2n_sn_t *sss) {
  u_char c;

  while((c = getopt_long(argc, argv, "fp:l:u:g:t:a:c:F:m:vh",
			 long_options, NULL)) != '?') {
    if(c == 255) break;
    setOption(c, optarg, sss);
  }

  return 0;
}

/* *************************************************** */

static char *trim(char *s) {
  char *end;

  while(isspace(s[0]) || (s[0] == '"') || (s[0] == '\''))
    s++;

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
static int loadFromFile(const char *path, n2n_sn_t *sss) {
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
	  setOption(opt->val, value, sss);
	  break;
	}

	opt++;
      }
    } else if(line[0] == '-') { /* short opt */
      key = &line[1], line_len--;
      if(line_len > 1) key[1] = '\0';
      if(line_len > 2) value = trim(&key[2]);

      // traceEvent(TRACE_NORMAL, "key: %c value: %s", key[0], value);
      setOption(key[0], value, sss);
    } else {
      traceEvent(TRACE_WARNING, "Skipping unrecognized line: %s", line);
      continue;
    }
  }

  fclose(fd);

  return 0;
}

/* *************************************************** */

/* Add the federation to the communities list of a supernode */
static int add_federation_to_communities(n2n_sn_t *sss){
  uint32_t  num_communities = 0;

  if(sss->federation != NULL) {
    HASH_ADD_STR(sss->communities, community, sss->federation);

    num_communities = HASH_COUNT(sss->communities);

    traceEvent(TRACE_INFO, "Added federation '%s' to the list of communities [total: %u]",
	       (char*)sss->federation->community, num_communities);
  }

  return 0;
}

/* *************************************************** */

#ifdef __linux__
static void dump_registrations(int signo) {
  struct sn_community *comm, *ctmp;
  struct peer_info *list, *tmp;
  char buf[32];
  time_t now = time(NULL);
  u_int num = 0;

  traceEvent(TRACE_NORMAL, "====================================");

  HASH_ITER(hh, sss_node.communities, comm, ctmp) {
    traceEvent(TRACE_NORMAL, "Dumping community: %s", comm->community);

    HASH_ITER(hh, comm->edges, list, tmp) {
      if(list->sock.family == AF_INET)
	traceEvent(TRACE_NORMAL, "[id: %u][MAC: %s][edge: %u.%u.%u.%u:%u][last seen: %u sec ago]",
		   ++num, macaddr_str(buf, list->mac_addr),
		   list->sock.addr.v4[0], list->sock.addr.v4[1], list->sock.addr.v4[2], list->sock.addr.v4[3],
		   list->sock.port,
		   now-list->last_seen);
      else
	traceEvent(TRACE_NORMAL, "[id: %u][MAC: %s][edge: IPv6:%u][last seen: %u sec ago]",
		   ++num, macaddr_str(buf, list->mac_addr), list->sock.port,
		   now-list->last_seen);
    }
  }

  traceEvent(TRACE_NORMAL, "====================================");
}
#endif

/* *************************************************** */

static int keep_running;

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

  keep_running = 0;
#ifdef WIN32
  return(TRUE);
#endif
}
#endif /* defined(__linux__) || defined(WIN32) */

/* *************************************************** */

/** Main program entry point from kernel. */
int main(int argc, char * const argv[]) {
  int rc;
#ifndef WIN32
  struct passwd *pw = NULL;
#endif

  sn_init(&sss_node);
  add_federation_to_communities(&sss_node);

  if((argc >= 2) && (argv[1][0] != '-')) {
    rc = loadFromFile(argv[1], &sss_node);
    if(argc > 2)
      rc = loadFromCLI(argc, argv, &sss_node);
  } else if(argc > 1)
    rc = loadFromCLI(argc, argv, &sss_node);
  else
#ifdef WIN32
    /* Load from current directory */
    rc = loadFromFile("supernode.conf", &sss_node);
#else
  rc = -1;
#endif

  if(rc < 0)
    help();

#if defined(N2N_HAVE_DAEMON)
  if(sss_node.daemon) {
    setUseSyslog(1); /* traceEvent output now goes to syslog. */

    if(-1 == daemon(0, 0)) {
      traceEvent(TRACE_ERROR, "Failed to become daemon.");
      exit(-5);
    }
  }
#endif /* #if defined(N2N_HAVE_DAEMON) */

  traceEvent(TRACE_DEBUG, "traceLevel is %d", getTraceLevel());

  sss_node.sock = open_socket(sss_node.lport, 1 /*bind ANY*/);
  if(-1 == sss_node.sock) {
    traceEvent(TRACE_ERROR, "Failed to open main socket. %s", strerror(errno));
    exit(-2);
  } else {
    traceEvent(TRACE_NORMAL, "supernode is listening on UDP %u (main)", sss_node.lport);
  }

  sss_node.mgmt_sock = open_socket(sss_node.mport, 0 /* bind LOOPBACK */);
  if(-1 == sss_node.mgmt_sock) {
    traceEvent(TRACE_ERROR, "Failed to open management socket. %s", strerror(errno));
    exit(-2);
  } else
    traceEvent(TRACE_NORMAL, "supernode is listening on UDP %u (management)", sss_node.mport);

#ifndef WIN32
  if (((pw = getpwnam ("n2n")) != NULL) || ((pw = getpwnam ("nobody")) != NULL)) {
    sss_node.userid = sss_node.userid == 0 ? pw->pw_uid : 0;
    sss_node.groupid = sss_node.groupid == 0 ? pw->pw_gid : 0;
  }
  if((sss_node.userid != 0) || (sss_node.groupid != 0)) {
    traceEvent(TRACE_NORMAL, "Dropping privileges to uid=%d, gid=%d",
	       (signed int)sss_node.userid, (signed int)sss_node.groupid);

    /* Finished with the need for root privileges. Drop to unprivileged user. */
    if((setgid(sss_node.groupid) != 0)
       || (setuid(sss_node.userid) != 0)) {
      traceEvent(TRACE_ERROR, "Unable to drop privileges [%u/%s]", errno, strerror(errno));
      exit(1);
    }
  }

  if((getuid() == 0) || (getgid() == 0))
    traceEvent(TRACE_WARNING, "Running as root is discouraged, check out the -u/-g options");
#endif

  traceEvent(TRACE_NORMAL, "supernode started");

#ifdef __linux__
  signal(SIGTERM, term_handler);
  signal(SIGINT, term_handler);
  signal(SIGHUP, dump_registrations);
#endif
#ifdef WIN32
  SetConsoleCtrlHandler(term_handler, TRUE);
#endif

  keep_running = 1;
  return run_sn_loop(&sss_node, &keep_running);
}
