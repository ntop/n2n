/**
 * (C) 2007-21 - ntop.org and contributors
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

/* Supernode for n2n-2.x */

#include "n2n.h"
#include "header_encryption.h"

#define HASH_FIND_COMMUNITY(head, name, out) HASH_FIND_STR(head, name, out)

static n2n_sn_t sss_node;

/** Load the list of allowed communities. Existing/previous ones will be removed
 *
 */
static int load_allowed_sn_community (n2n_sn_t *sss) {

    char buffer[4096], *line, *cmn_str, net_str[20], format[20];

    sn_user_t *user, *tmp_user;
    n2n_desc_t username;
    n2n_private_public_key_t public_key;
    uint8_t ascii_public_key[(N2N_PRIVATE_PUBLIC_KEY_SIZE * 8 + 5) / 6 + 1];

    dec_ip_str_t ip_str = {'\0'};
    uint8_t bitlen;
    in_addr_t net;
    uint32_t mask;
    FILE *fd = fopen(sss->community_file, "r");
    struct sn_community *comm, *tmp_comm, *last_added_comm = NULL;
    uint32_t num_communities = 0;
    struct sn_community_regular_expression *re, *tmp_re;
    uint32_t num_regex = 0;
    int has_net;

    if(fd == NULL) {
        traceEvent(TRACE_WARNING, "File %s not found", sss->community_file);
        return -1;
    }

    // remove communities (not: federation)
    HASH_ITER(hh, sss->communities, comm, tmp_comm) {
        if(comm->is_federation) {
            continue;
        }

        // remove allowed users from community
        HASH_ITER(hh, comm->allowed_users, user, tmp_user) {
            free(user->shared_secret_ctx);
            HASH_DEL(comm->allowed_users, user);
            free(user);
        }

        // remove community
        HASH_DEL(sss->communities, comm);
        if(NULL != comm->header_encryption_ctx_static) {
            // remove header encryption keys
            free(comm->header_encryption_ctx_static);
            free(comm->header_encryption_ctx_dynamic);
        }
        free(comm);
    }

    // remove all regular expressions for allowed communities
    HASH_ITER(hh, sss->rules, re, tmp_re) {
        HASH_DEL(sss->rules, re);
        free(re);
    }

    // format definition for possible user-key entries
    sprintf(format, "%c %%%ds %%%ds", N2N_USER_KEY_LINE_STARTER, N2N_DESC_SIZE - 1, sizeof(ascii_public_key)-1);

    while((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {
        int len = strlen(line);

        if((len < 2) || line[0] == '#') {
            continue;
        }

        len--;
        while(len > 0) {
            if((line[len] == '\n') || (line[len] == '\r')) {
	        line[len] = '\0';
	        len--;
            } else {
	        break;
            }
        }
        // the loop above does not always determine correct 'len'
        len = strlen(line);

        // user-key line for edge authentication?
        if(line[0] == N2N_USER_KEY_LINE_STARTER) { /* special first character */
            if(sscanf(line, format, username, ascii_public_key) == 2) { /* correct format */
                if(last_added_comm) { /* is there a valid community to add users to */
                    user = (sn_user_t*)calloc(1, sizeof(sn_user_t));
                    if(user) {
                        // username
                        memcpy(user->name, username, sizeof(username));
                        // public key
                        ascii_to_bin(public_key, ascii_public_key);
                        memcpy(user->public_key, public_key, sizeof(public_key));
                        // common shared secret will be calculated later
                        // add to list
                        HASH_ADD_PTR(last_added_comm->allowed_users, public_key, user);
                        traceEvent(TRACE_INFO, "Added user '%s' with public key '%s' to community '%s'",
                                               user->name, ascii_public_key, last_added_comm->community);
// !!! set this community to 'encrypted community'
// !!! trigger dynamic key setup
                    }
                    continue;
                }
            }
        }

        // --- community name or regular expression

        // cut off any IP sub-network upfront
        cmn_str = (char*)calloc(len + 1, sizeof(char));
        has_net = (sscanf(line, "%s %s", cmn_str, net_str) == 2);

        // if it contains typical characters...
        if(NULL != strpbrk(cmn_str, ".*+?[]\\")) {
            // ...it is treated as regular expression
            re = (struct sn_community_regular_expression*)calloc(1, sizeof(struct sn_community_regular_expression));
            if(re) {
                re->rule = re_compile(cmn_str);
                HASH_ADD_PTR(sss->rules, rule, re);
	        num_regex++;
                traceEvent(TRACE_INFO, "Added regular expression for allowed communities '%s'", cmn_str);
                free(cmn_str);
                last_added_comm = NULL;
                continue;
            }
        }

        comm = (struct sn_community*)calloc(1,sizeof(struct sn_community));

        if(comm != NULL) {
            comm_init(comm, cmn_str);
            /* loaded from file, this community is unpurgeable */
            comm->purgeable = COMMUNITY_UNPURGEABLE;
            /* we do not know if header encryption is used in this community,
             * first packet will show. just in case, setup the key. */
            comm->header_encryption = HEADER_ENCRYPTION_UNKNOWN;
            packet_header_setup_key(comm->community,
                                    comm->community,
                                    &(comm->header_encryption_ctx_static),
                                    &(comm->header_encryption_ctx_dynamic),
                                    &(comm->header_iv_ctx_static),
                                    &(comm->header_iv_ctx_dynamic));
            HASH_ADD_STR(sss->communities, community, comm);
            last_added_comm = comm;

            num_communities++;
            traceEvent(TRACE_INFO, "Added allowed community '%s' [total: %u]",
		       (char*)comm->community, num_communities);

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
	                 || ((ntohl(net) & ~mask) != 0)) {
                    traceEvent(TRACE_WARNING, "Bad network '%s/%u' in '%s' for community '%s', ignoring.",
		                           ip_str, bitlen, net_str, cmn_str);
                    has_net = 0;
                }
                if((bitlen > 30) || (bitlen == 0)) {
                    traceEvent(TRACE_WARNING, "Bad prefix '%hhu' in '%s' for community '%s', ignoring.",
		                           bitlen, net_str, cmn_str);
                    has_net = 0;
                }
            }
            if(has_net) {
                comm->auto_ip_net.net_addr = ntohl(net);
                comm->auto_ip_net.net_bitlen = bitlen;
                traceEvent(TRACE_INFO, "Assigned sub-network %s/%u to community '%s'.",
		                       inet_ntoa(*(struct in_addr *) &net),
		           comm->auto_ip_net.net_bitlen,
		           comm->community);
            } else {
                assign_one_ip_subnet(sss, comm);
            }
        }

        free(cmn_str);

    }

    fclose(fd);

    if((num_regex + num_communities) == 0) {
        traceEvent(TRACE_WARNING, "File %s does not contain any valid community names or regular expressions", sss->community_file);
        return -1;
    }

    traceEvent(TRACE_NORMAL, "Loaded %u fixed-name communities from %s",
	             num_communities, sss->community_file);

    traceEvent(TRACE_NORMAL, "Loaded %u regular expressions for community name matching from %s",
	             num_regex, sss->community_file);

    /* No new communities will be allowed */
    sss->lock_communities = 1;

    return(0);
}


/* *************************************************** */

/** Help message to print if the command line arguments are not valid. */
static void help (int level) {

    printf("\n");
    print_n2n_version();

    if(level == 0) /* short help */ {

        printf("   basic usage:  supernode <config file> (see supernode.conf)\n"
               "\n"
               "            or   supernode "
               "[optional parameters, at least one] "
               "\n                      "
               "\n technically, all parameters are optional, but the supernode executable"
               "\n requires at least one parameter to run, .e.g. -v or -f, as otherwise this"
               "\n short help text is displayed"
             "\n\n  -h    shows a quick reference including all available options"
               "\n --help gives a detailed parameter description"
               "\n   man  files for n2n, edge, and superndode contain in-depth information"
               "\n\n");

    } else if(level == 1) /* quick reference */ {

        printf(" general usage:  supernode <config file> (see supernode.conf)\n"
           "\n"
               "            or   supernode "
               "[-p <local port>] "
            "\n                           "
               "[-F <federation name>] "
            "\n options for under-        "
               "[-l <supernode host:port>] "
            "\n lying connection          "
#ifdef SN_MANUAL_MAC
               "[-m <mac address>] "
#endif
          "\n\n overlay network           "
               "[-c <community list file>] "
            "\n configuration             "
               "[-a <net ip>-<net ip>/<cidr suffix>] "
          "\n\n local options             "
#if defined(N2N_HAVE_DAEMON)
               "[-f] "
#endif
               "[-t <management port>] "
               "[-v] "
#ifndef WIN32
            "\n                           "
               "[-u <numerical user id>]"
               "[-g <numerical group id>]"
#endif
          "\n\n meaning of the            "
#if defined(N2N_HAVE_DAEMON)
                "[-f]  do not fork but run in foreground"
#endif
            "\n flag options              "
                "[-v]  make more verbose, repeat as required"
            "\n                           "
          "\n technically, all parameters are optional, but the supernode executable"
          "\n requires at least one parameter to run, .e.g. -v or -f, as otherwise a"
          "\n short help text is displayed"
        "\n\n  -h    shows this quick reference including all available options"
          "\n --help gives a detailed parameter description"
          "\n   man  files for n2n, edge, and superndode contain in-depth information"
          "\n\n");

    } else /* long help */ {

        printf(" general usage:  supernode <config file> (see supernode.conf)\n"
               "\n"
               "            or   supernode [optional parameters, at least one]\n\n"
        );
        printf (" OPTIONS FOR THE UNDERLYING NETWORK CONNECTION\n");
        printf (" ---------------------------------------------\n\n");
        printf(" -p <local port>   | fixed local UDP port, defaults to 7654\n");
        printf(" -F <fed name>     | name of the supernode's federation, defaults to\n"
               "                   | '%s'\n", (char *)FEDERATION_NAME);
        printf(" -l <host:port>    | ip address or name, and port of known supernode\n");
#ifdef SN_MANUAL_MAC
        printf(" -m <mac>          | fixed MAC address for the supernode, e.g.\n"
               "                   | '-m 10:20:30:40:50:60', random otherwise\n");
#endif
        printf ("\n");
        printf (" TAP DEVICE AND OVERLAY NETWORK CONFIGURATION\n");
        printf (" --------------------------------------------\n\n");
        printf(" -c <path>         | file containing the allowed communities\n");
        printf(" -a <net-net/n>    | subnet range for auto ip address service, e.g.\n"
               "                   | '-a 192.168.0.0-192.168.255.0/24', defaults\n"
               "                   | to '10.128.255.0-10.255.255.0/24'\n");
        printf ("\n");
        printf (" LOCAL OPTIONS\n");
        printf (" -------------\n\n");
#if defined(N2N_HAVE_DAEMON)
        printf(" -f                | do not fork and run as a daemon, rather run in foreground\n");
#endif
        printf(" -t <port>         | management UDP port, for multiple supernodes on a machine,\n"
               "                   | defaults to 5645\n");
        printf(" -v                | make more verbose, repeat as required\n");
#ifndef WIN32
        printf(" -u <UID>          | numeric user ID to use when privileges are dropped\n");
        printf(" -g <GID>          | numeric group ID to use when privileges are dropped\n");
#endif
        printf("\n technically, all parameters are optional, but the supernode executable"
               "\n requires at least one parameter to run, .e.g. -v or -f, as otherwise a"
               "\n short help text is displayed"
             "\n\n  -h    shows a quick reference including all available options"
               "\n --help gives this detailed parameter description"
               "\n   man  files for n2n, edge, and superndode contain in-depth information"
               "\n\n");
    }

    exit(0);
}


/* *************************************************** */

static int setOption (int optkey, char *_optarg, n2n_sn_t *sss) {

    //traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, _optarg ? _optarg : "");

    switch(optkey) {
        case 'p': /* local-port */
            sss->lport = atoi(_optarg);

            if(sss->lport == 0) {
                traceEvent(TRACE_WARNING, "Bad local port format");
                break;
            }

            break;

        case 't': /* mgmt-port */
            sss->mport = atoi(_optarg);

            if(sss->mport == 0) {
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

            if(!double_column) {
                traceEvent(TRACE_WARNING, "Invalid -l format: ignored");
                return (-1);
            }

            socket = (n2n_sock_t *)calloc(1, sizeof(n2n_sock_t));
            rv = supernode2sock(socket, _optarg);

            if(rv != 0) {
                traceEvent(TRACE_WARNING, "Invalid socket");
                free(socket);
                break;
            }

            if(sss->federation != NULL) {

                skip_add = SN_ADD;
                anchor_sn = add_sn_to_list_by_mac_or_sock(&(sss->federation->edges), socket, null_mac, &skip_add);

                if(anchor_sn != NULL) {
                    anchor_sn->ip_addr = calloc(1, N2N_EDGE_SN_HOST_SIZE);
                    if(anchor_sn->ip_addr) {
                        strncpy(anchor_sn->ip_addr, _optarg, N2N_EDGE_SN_HOST_SIZE - 1);
	                      memcpy(&(anchor_sn->sock), socket, sizeof(n2n_sock_t));
                        memcpy(anchor_sn->mac_addr, null_mac, sizeof(n2n_mac_t));
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

            if(sscanf(_optarg, "%15[^\\-]-%15[^/]/%hhu", ip_min_str, ip_max_str, &bitlen) != 3) {
                traceEvent(TRACE_WARNING, "Bad net-net/bit format '%s'. See -h.", _optarg);
                break;
            }

            net_min = inet_addr(ip_min_str);
            net_max = inet_addr(ip_max_str);
            mask = bitlen2mask(bitlen);
            if((net_min == (in_addr_t)(-1)) || (net_min == INADDR_NONE) || (net_min == INADDR_ANY)
	             || (net_max == (in_addr_t)(-1)) || (net_max == INADDR_NONE) || (net_max == INADDR_ANY)
	             || (ntohl(net_min) >  ntohl(net_max))
	             || ((ntohl(net_min) & ~mask) != 0) || ((ntohl(net_max) & ~mask) != 0)) {
                traceEvent(TRACE_WARNING, "Bad network range '%s...%s/%u' in '%s', defaulting to '%s...%s/%d'",
		                       ip_min_str, ip_max_str, bitlen, _optarg,
		                       N2N_SN_MIN_AUTO_IP_NET_DEFAULT, N2N_SN_MAX_AUTO_IP_NET_DEFAULT, N2N_SN_AUTO_IP_NET_BIT_DEFAULT);
                break;
            }

            if((bitlen > 30) || (bitlen == 0)) {
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

            snprintf(sss->federation->community, N2N_COMMUNITY_SIZE - 1 ,"*%s", _optarg);
            sss->federation->community[N2N_COMMUNITY_SIZE - 1] = '\0';
            break;
        }
#ifdef SN_MANUAL_MAC
        case 'm': {/* MAC address */
            str2mac(sss->mac_addr,_optarg);
            break;
        }
#endif
        case 'c': /* community file */
            sss->community_file = calloc(1, strlen(_optarg) + 1);
            if(sss->community_file)
                strcpy(sss->community_file, _optarg);
            break;
#if defined(N2N_HAVE_DAEMON)
        case 'f': /* foreground */
            sss->daemon = 0;
            break;
#endif
        case 'h': /* quick reference */
            help(1);
            break;

        case '@': /* long help */
            help(2);
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
#if defined(N2N_HAVE_DAEMON)
    {"foreground",  no_argument,       NULL, 'f'},
#endif
    {"local-port",  required_argument, NULL, 'p'},
    {"mgmt-port",   required_argument, NULL, 't'},
    {"autoip",      required_argument, NULL, 'a'},
    {"help",        no_argument,       NULL, '@'}, /* special character '@' to identify long help case */
    {"verbose",     no_argument,       NULL, 'v'},
    {NULL,          0,                 NULL, 0}
};

/* *************************************************** */

/* read command line options */
static int loadFromCLI (int argc, char * const argv[], n2n_sn_t *sss) {

    u_char c;

    while((c = getopt_long(argc, argv,
                           "p:l:t:a:c:F:vh"
#ifdef SN_MANUAL_MAC
                           "m:"
#endif
#if defined(N2N_HAVE_DAEMON)
                           "f"
#endif
#ifndef WIN32
                           "u:g:"
#endif
                            ,
			    long_options, NULL)) != '?') {
        if(c == 255) {
            break;
        }
        setOption(c, optarg, sss);
    }

    return 0;
}

/* *************************************************** */

static char *trim (char *s) {

    char *end;

    while(isspace(s[0]) || (s[0] == '"') || (s[0] == '\'')) {
        s++;
    }

    if(s[0] == 0) {
        return s;
    }

    end = &s[strlen(s) - 1];
    while(end > s && (isspace(end[0])|| (end[0] == '"') || (end[0] == '\''))) {
        end--;
    }
    end[1] = 0;

    return s;
}

/* *************************************************** */

/* parse the configuration file */
static int loadFromFile (const char *path, n2n_sn_t *sss) {

    char buffer[4096], *line;
    char *line_vec[3];
    int tmp;

    FILE *fd;

    fd = fopen(path, "r");

    if(fd == NULL) {
        traceEvent(TRACE_WARNING, "Config file %s not found", path);
        return -1;
    }

    // we mess around with optind, better save it
    tmp = optind;

    while((line = fgets(buffer, sizeof(buffer), fd)) != NULL) {
        line = trim(line);

        if(strlen(line) < 2 || line[0] == '#') {
            continue;
        }

        // executable, cannot be omitted, content can be anything
        line_vec[0] = line;
        // first token, e.g. `-p`, eventually followed by a whitespace or '=' delimiter
        line_vec[1] = strtok(line, "\t =");
        // separate parameter option, if present
        line_vec[2] = strtok(NULL, "\t ");

        // not to duplicate the option parser code, call loadFromCLI and pretend we have no option read yet
        optind = 0;
        // if separate second token present (optional argument, not part of first), then announce 3 vector members
        loadFromCLI(line_vec[2] ? 3 : 2, line_vec, sss);
    }

    fclose(fd);
    optind = tmp;

    return 0;
}

/* *************************************************** */

/* Add the federation to the communities list of a supernode */
static int add_federation_to_communities (n2n_sn_t *sss) {

    uint32_t    num_communities = 0;

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
static void dump_registrations (int signo) {

    struct sn_community *comm, *ctmp;
    struct peer_info *list, *tmp;
    char buf[32];
    time_t now = time(NULL);
    u_int num = 0;

    traceEvent(TRACE_NORMAL, "====================================");

    HASH_ITER(hh, sss_node.communities, comm, ctmp) {
        traceEvent(TRACE_NORMAL, "Dumping community: %s", comm->community);

        HASH_ITER(hh, comm->edges, list, tmp) {
            if(list->sock.family == AF_INET) {
	              traceEvent(TRACE_NORMAL, "[id: %u][MAC: %s][edge: %u.%u.%u.%u:%u][last seen: %u sec ago]",
		                       ++num, macaddr_str(buf, list->mac_addr),
		                       list->sock.addr.v4[0], list->sock.addr.v4[1], list->sock.addr.v4[2], list->sock.addr.v4[3],
		                       list->sock.port,
		                       now - list->last_seen);
            } else {
	              traceEvent(TRACE_NORMAL, "[id: %u][MAC: %s][edge: IPv6:%u][last seen: %u sec ago]",
		                       ++num, macaddr_str(buf, list->mac_addr), list->sock.port,
		                       now - list->last_seen);
            }
        }
    }

    traceEvent(TRACE_NORMAL, "====================================");
}
#endif

/* *************************************************** */

static int keep_running;

#if defined(__linux__) || defined(WIN32)
#ifdef WIN32
BOOL WINAPI term_handler (DWORD sig)
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
int main (int argc, char * const argv[]) {

    int rc;
#ifndef WIN32
    struct passwd *pw = NULL;
#endif
    struct peer_info *scan, *tmp;
    struct sn_community *comm, *tmp_comm;
    sn_user_t *user, *tmp_user;


    sn_init(&sss_node);
    add_federation_to_communities(&sss_node);

    if((argc >= 2) && (argv[1][0] != '-')) {
        rc = loadFromFile(argv[1], &sss_node);
        if(argc > 2) {
            rc = loadFromCLI(argc, argv, &sss_node);
        }
    } else if(argc > 1) {
        rc = loadFromCLI(argc, argv, &sss_node);
    } else

#ifdef WIN32
        // load from current directory
        rc = loadFromFile("supernode.conf", &sss_node);
#else
        rc = -1;
#endif

    if(rc < 0) {
        help(0); /* short help */
    }

    if(sss_node.community_file)
        load_allowed_sn_community(&sss_node);

#if defined(N2N_HAVE_DAEMON)
    if(sss_node.daemon) {
        setUseSyslog(1); /* traceEvent output now goes to syslog. */

        if(-1 == daemon(0, 0)) {
            traceEvent(TRACE_ERROR, "Failed to become daemon.");
            exit(-5);
        }
    }
#endif /* #if defined(N2N_HAVE_DAEMON) */

    // generate shared secrets for user authentication; can be done only after
    // federation name is known (-F) and community list completely read (-c)
    traceEvent(TRACE_INFO, "started shared secrets calculation for edge authentication");
    generate_private_key(sss_node.private_key, sss_node.federation->community + 1); /* skip '*' federation leading character */
    HASH_ITER(hh, sss_node.communities, comm, tmp_comm) {
        if(comm->is_federation) {
            continue;
        }
        HASH_ITER(hh, comm->allowed_users, user, tmp_user) {
            // calculate common shared secret (ECDH)
            generate_shared_secret(user->shared_secret, sss_node.private_key, user->public_key);
            // prepare for use as key
            user->shared_secret_ctx = (he_context_t*)calloc(1, sizeof(speck_context_t));
            speck_init((speck_context_t**)&user->shared_secret_ctx, user->shared_secret, 128);
        }
    }
    traceEvent(TRACE_NORMAL, "calculated shared secrets for edge authentication");


    traceEvent(TRACE_DEBUG, "traceLevel is %d", getTraceLevel());

    sss_node.sock = open_socket(sss_node.lport, 1 /*bind ANY*/, 0 /* UDP */);
    if(-1 == sss_node.sock) {
        traceEvent(TRACE_ERROR, "Failed to open main socket. %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode is listening on UDP %u (main)", sss_node.lport);
    }

#ifdef N2N_HAVE_TCP
    sss_node.tcp_sock = open_socket(sss_node.lport, 1 /*bind ANY*/, 1 /* TCP */);
    if(-1 == sss_node.tcp_sock) {
        traceEvent(TRACE_ERROR, "Failed to open auxiliary TCP socket. %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode opened TCP %u (aux)", sss_node.lport);
    }

    if(-1 == listen(sss_node.tcp_sock, N2N_TCP_BACKLOG_QUEUE_SIZE)) {
        traceEvent(TRACE_ERROR, "Failed to listen on auxiliary TCP socket. %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode is listening on TCP %u (aux)", sss_node.lport);
    }
#endif

    sss_node.mgmt_sock = open_socket(sss_node.mport, 0 /* bind LOOPBACK */, 0 /* UDP */);
    if(-1 == sss_node.mgmt_sock) {
        traceEvent(TRACE_ERROR, "Failed to open management socket. %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode is listening on UDP %u (management)", sss_node.mport);
    }

    HASH_ITER(hh, sss_node.federation->edges, scan, tmp)
        scan->socket_fd = sss_node.sock;

#ifndef WIN32
    if(((pw = getpwnam ("n2n")) != NULL) || ((pw = getpwnam ("nobody")) != NULL)) {
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

    if((getuid() == 0) || (getgid() == 0)) {
        traceEvent(TRACE_WARNING, "Running as root is discouraged, check out the -u/-g options");
    }
#endif

    traceEvent(TRACE_NORMAL, "supernode started");

#ifdef __linux__
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, term_handler);
    signal(SIGINT,  term_handler);
    signal(SIGHUP,  dump_registrations);
#endif
#ifdef WIN32
    SetConsoleCtrlHandler(term_handler, TRUE);
#endif

    keep_running = 1;
    return run_sn_loop(&sss_node, &keep_running);
}
