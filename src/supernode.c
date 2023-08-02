/**
 * (C) 2007-22 - ntop.org and contributors
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


#include <ctype.h>             // for isspace
#include <errno.h>             // for errno
#include <getopt.h>            // for required_argument, getopt_long, no_arg...
#include <signal.h>            // for signal, SIGHUP, SIGINT, SIGPIPE, SIGTERM
#include <stdbool.h>
#include <stdint.h>            // for uint8_t, uint32_t
#include <stdio.h>             // for printf, NULL, fclose, fgets, fopen
#include <stdlib.h>            // for exit, atoi, calloc, free
#include <string.h>            // for strerror, strlen, memcpy, strncpy, str...
#include <sys/types.h>         // for time_t, u_char, u_int
#include <time.h>              // for time
#include <unistd.h>            // for _exit, daemon, getgid, getuid, setgid
#include "n2n.h"               // for n2n_sn_t, sn_community, traceEvent
#include "pearson.h"           // for pearson_hash_64
#include "uthash.h"            // for UT_hash_handle, HASH_ITER, HASH_ADD_STR

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>         // for inet_addr
#include <netinet/in.h>        // for ntohl, INADDR_ANY, INADDR_NONE, in_addr_t
#include <pwd.h>               // for getpwnam, passwd
#include <sys/socket.h>        // for listen, AF_INET
#endif

#define HASH_FIND_COMMUNITY(head, name, out) HASH_FIND_STR(head, name, out)

static n2n_sn_t sss_node;

void close_tcp_connection (n2n_sn_t *sss, n2n_tcp_connection_t *conn);
void calculate_shared_secrets (n2n_sn_t *sss);
int load_allowed_sn_community (n2n_sn_t *sss);
int resolve_create_thread (n2n_resolve_parameter_t **param, struct peer_info *sn_list);


/** Help message to print if the command line arguments are not valid. */
static void help (int level) {

    if(level == 0) /* no help required */
        return;

    printf("\n");
    print_n2n_version();

    if(level == 1) /* short help */ {

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
               "\n   man  files for n2n, edge, and supernode contain in-depth information"
               "\n\n");

    } else if(level == 2) /* quick reference */ {

        printf(" general usage:  supernode <config file> (see supernode.conf)\n"
           "\n"
               "            or   supernode "
               "[-p [<local bind ip address>:]<local port>] "
            "\n                           "
               "[-F <federation name>] "
            "\n options for under-        "
               "[-l <supernode host:port>] "
            "\n lying connection          "
#ifdef SN_MANUAL_MAC
               "[-m <mac address>] "
#endif
               "[-M] "
               "[-V <version text>] "
          "\n\n overlay network           "
               "[-c <community list file>] "
            "\n configuration             "
               "[-a <net ip>-<net ip>/<cidr suffix>] "
          "\n\n local options             "
#if defined(N2N_HAVE_DAEMON)
               "[-f] "
#endif
               "[-t <management port>] "
            "\n                           "
               "[--management-password <pw>] "
               "[-v] "
#ifndef _WIN32
            "\n                           "
               "[-u <numerical user id>]"
               "[-g <numerical group id>]"
#endif
          "\n\n meaning of the            "
                "[-M]  disable MAC and IP address spoofing protection"
            "\n flag options              "
#if defined(N2N_HAVE_DAEMON)
                "[-f]  do not fork but run in foreground"
            "\n                           "
#endif
                "[-v]  make more verbose, repeat as required"
            "\n                           "
          "\n technically, all parameters are optional, but the supernode executable"
          "\n requires at least one parameter to run, .e.g. -v or -f, as otherwise a"
          "\n short help text is displayed"
        "\n\n  -h    shows this quick reference including all available options"
          "\n --help gives a detailed parameter description"
          "\n   man  files for n2n, edge, and supernode contain in-depth information"
          "\n\n");

    } else /* long help */ {

        printf(" general usage:  supernode <config file> (see supernode.conf)\n"
               "\n"
               "            or   supernode [optional parameters, at least one]\n\n"
        );
        printf (" OPTIONS FOR THE UNDERLYING NETWORK CONNECTION\n");
        printf (" ---------------------------------------------\n\n");
        printf(" -p [<ip>:]<port>  | fixed local UDP port (defaults to %u) and optionally\n"
               "                   | bind to specified local IP address only ('any' by default)\n", N2N_SN_LPORT_DEFAULT);
        printf(" -F <fed name>     | name of the supernode's federation, defaults to\n"
               "                   | '%s'\n", (char *)FEDERATION_NAME);
        printf(" -l <host:port>    | ip address or name, and port of known supernode\n");
#ifdef SN_MANUAL_MAC
        printf(" -m <mac>          | fixed MAC address for the supernode, e.g.\n"
               "                   | '-m 10:20:30:40:50:60', random otherwise\n");
#endif
        printf(" -M                | disable MAC and IP address spoofing protection for all\n"
               "                   | non-username-password-authenticating communities\n");
        printf(" -V <version text> | sends a custom supernode version string of max 19 letters \n"
               "                   | length to edges, visible in their management port output\n");
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
               "                   | defaults to %u\n", N2N_SN_MGMT_PORT);
        printf(" --management_...  | management port password, defaults to '%s'\n"
               " ...password <pw>  | \n", N2N_MGMT_PASSWORD);
        printf(" -v                | make more verbose, repeat as required\n");
#ifndef _WIN32
        printf(" -u <UID>          | numeric user ID to use when privileges are dropped\n");
        printf(" -g <GID>          | numeric group ID to use when privileges are dropped\n");
#endif
        printf("\n technically, all parameters are optional, but the supernode executable"
               "\n requires at least one parameter to run, .e.g. -v or -f, as otherwise a"
               "\n short help text is displayed"
             "\n\n  -h    shows a quick reference including all available options"
               "\n --help gives this detailed parameter description"
               "\n   man  files for n2n, edge, and supernode contain in-depth information"
               "\n\n");
    }

    exit(0);
}


/* *************************************************** */

static int setOption (int optkey, char *_optarg, n2n_sn_t *sss) {

    //traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, _optarg ? _optarg : "");

    switch(optkey) {
        case 'p': { /* local-port */
            char* colon = strpbrk(_optarg, ":");
            if(colon) { /*ip address:port */
                *colon = 0;
                sss->bind_address = ntohl(inet_addr(_optarg));
                sss->lport = atoi(++colon);

                if(sss->bind_address == INADDR_NONE) {
                    traceEvent(TRACE_WARNING, "bad address to bind to, binding to any IP address");
                    sss->bind_address = INADDR_ANY;
                }
                if(sss->lport == 0) {
                    traceEvent(TRACE_WARNING, "bad local port format, defaulting to %u", N2N_SN_LPORT_DEFAULT);
                    sss->lport = N2N_SN_LPORT_DEFAULT;
                }
            } else { /* ip address or port only */
                char* dot = strpbrk(_optarg, ".");
                if(dot) { /* ip address only */
                    sss->bind_address = ntohl(inet_addr(_optarg));
                    if(sss->bind_address == INADDR_NONE) {
                        traceEvent(TRACE_WARNING, "bad address to bind to, binding to any IP address");
                        sss->bind_address = INADDR_ANY;
                    }
                } else { /* port only */
                    sss->lport = atoi(_optarg);
                    if(sss->lport == 0) {
                        traceEvent(TRACE_WARNING, "bad local port format, defaulting to %u", N2N_SN_LPORT_DEFAULT);
                        sss->lport = N2N_SN_LPORT_DEFAULT;
                    }
                }
            }
            break;
        }

        case 't': /* mgmt-port */
            sss->mport = atoi(_optarg);

            if(sss->mport == 0)
                traceEvent(TRACE_WARNING, "bad management port format, defaulting to %u", N2N_SN_MGMT_PORT);
                // default is made sure in sn_init()

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
                traceEvent(TRACE_WARNING, "size of -l argument too long: %zu; maximum size is %d", length, N2N_EDGE_SN_HOST_SIZE);
                return 1;
            }

            if(!double_column) {
                traceEvent(TRACE_WARNING, "invalid -l format, missing port");
                return 1;
            }

            socket = (n2n_sock_t *)calloc(1, sizeof(n2n_sock_t));
            rv = supernode2sock(socket, _optarg);

            if(rv < -2) { /* we accept resolver failure as it might resolve later */
                traceEvent(TRACE_WARNING, "invalid supernode parameter");
                free(socket);
                return 1;
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
                        anchor_sn->purgeable = false;
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
                traceEvent(TRACE_WARNING, "bad net-net/bit format '%s'.", _optarg);
                return 2;
            }

            net_min = inet_addr(ip_min_str);
            net_max = inet_addr(ip_max_str);
            mask = bitlen2mask(bitlen);
            if((net_min == (in_addr_t)(-1)) || (net_min == INADDR_NONE) || (net_min == INADDR_ANY)
	             || (net_max == (in_addr_t)(-1)) || (net_max == INADDR_NONE) || (net_max == INADDR_ANY)
	             || (ntohl(net_min) >  ntohl(net_max))
	             || ((ntohl(net_min) & ~mask) != 0) || ((ntohl(net_max) & ~mask) != 0)) {
                traceEvent(TRACE_WARNING, "bad network range '%s...%s/%u' in '%s', defaulting to '%s...%s/%d'",
		                       ip_min_str, ip_max_str, bitlen, _optarg,
		                       N2N_SN_MIN_AUTO_IP_NET_DEFAULT, N2N_SN_MAX_AUTO_IP_NET_DEFAULT, N2N_SN_AUTO_IP_NET_BIT_DEFAULT);
                return 2;
            }

            if((bitlen > 30) || (bitlen == 0)) {
                traceEvent(TRACE_WARNING, "bad prefix '%hhu' in '%s', defaulting to '%s...%s/%d'",
		                       bitlen, _optarg,
		                       N2N_SN_MIN_AUTO_IP_NET_DEFAULT, N2N_SN_MAX_AUTO_IP_NET_DEFAULT, N2N_SN_AUTO_IP_NET_BIT_DEFAULT);
                return 2;
            }

            traceEvent(TRACE_NORMAL, "the network range for community ip address service is '%s...%s/%hhu'", ip_min_str, ip_max_str, bitlen);

            sss->min_auto_ip_net.net_addr = ntohl(net_min);
            sss->min_auto_ip_net.net_bitlen = bitlen;
            sss->max_auto_ip_net.net_addr = ntohl(net_max);
            sss->max_auto_ip_net.net_bitlen = bitlen;

            break;
        }
#ifndef _WIN32
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
            sss->federation->purgeable = false;
            break;
        }
#ifdef SN_MANUAL_MAC
        case 'm': {/* MAC address */
            str2mac(sss->mac_addr, _optarg);

            // clear multicast bit
            sss->mac_addr[0] &= ~0x01;
            // set locally-assigned bit
            sss->mac_addr[0] |= 0x02;

            break;
        }
#endif
        case 'M': /* override spoofing protection */
            sss->override_spoofing_protection = 1;
            break;

        case 'V': /* version text */
            strncpy(sss->version, _optarg, sizeof(n2n_version_t));
            sss->version[sizeof(n2n_version_t) - 1] = '\0';
            break;
        case 'c': /* community file */
            sss->community_file = calloc(1, strlen(_optarg) + 1);
            if(sss->community_file)
                strcpy(sss->community_file, _optarg);
            break;

        case ']': /* password for management port */ {
            sss->mgmt_password_hash = pearson_hash_64((uint8_t*)_optarg, strlen(_optarg));

            break;
        }
#if defined(N2N_HAVE_DAEMON)
        case 'f': /* foreground */
            sss->daemon = 0;
            break;
#endif
        case 'h': /* quick reference */
            return 2;

        case '@': /* long help */
            return 3;

        case 'v': /* verbose */
            setTraceLevel(getTraceLevel() + 1);
            break;

        default:
            traceEvent(TRACE_WARNING, "unknown option -%c:", (char) optkey);
            return 2;
    }

    return 0;
}


/* *********************************************** */

static const struct option long_options[] = {
    {"communities",         required_argument, NULL, 'c'},
#if defined(N2N_HAVE_DAEMON)
    {"foreground",          no_argument,       NULL, 'f'},
#endif
    {"local-port",          required_argument, NULL, 'p'},
    {"mgmt-port",           required_argument, NULL, 't'},
    {"autoip",              required_argument, NULL, 'a'},
    {"verbose",             no_argument,       NULL, 'v'},
    {"help",                no_argument,       NULL, '@'}, /* special character '@' to identify long help case */
    {"management-password", required_argument, NULL, ']' }, /*                  ']'             management port password */
    {NULL,                  0,                 NULL, 0}
};

/* *************************************************** */

/* read command line options */
static int loadFromCLI (int argc, char * const argv[], n2n_sn_t *sss) {

    u_char c;

    while((c = getopt_long(argc, argv,
                           "p:l:t:a:c:F:vhMV:"
#ifdef SN_MANUAL_MAC
                           "m:"
#endif
#if defined(N2N_HAVE_DAEMON)
                           "f"
#endif
#ifndef _WIN32
                           "u:g:"
#endif
                            ,
			    long_options, NULL)) != '?') {
        if(c == 255) {
            break;
        }
        help(setOption(c, optarg, sss));
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
        traceEvent(TRACE_WARNING, "config file %s not found", path);
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

        traceEvent(TRACE_INFO, "added federation '%s' to the list of communities [total: %u]",
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
        traceEvent(TRACE_NORMAL, "dumping community: %s", comm->community);

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

static bool keep_running = true;

#if defined(__linux__) || defined(_WIN32)
#ifdef _WIN32
BOOL WINAPI term_handler (DWORD sig)
#else
    static void term_handler(int sig)
#endif
{
    static int called = 0;

    if(called) {
        traceEvent(TRACE_NORMAL, "ok, I am leaving now");
        _exit(0);
    } else {
        traceEvent(TRACE_NORMAL, "shutting down...");
        called = 1;
    }

    keep_running = false;
#ifdef _WIN32
    return(TRUE);
#endif
}
#endif /* defined(__linux__) || defined(_WIN32) */

/* *************************************************** */

/** Main program entry point from kernel. */
int main (int argc, char * const argv[]) {

    int rc;
#ifndef _WIN32
    struct passwd *pw = NULL;
#endif
    struct peer_info *scan, *tmp;


    sn_init_defaults(&sss_node);
    add_federation_to_communities(&sss_node);

    if((argc >= 2) && (argv[1][0] != '-')) {
        rc = loadFromFile(argv[1], &sss_node);
        if(argc > 2) {
            rc = loadFromCLI(argc, argv, &sss_node);
        }
    } else if(argc > 1) {
        rc = loadFromCLI(argc, argv, &sss_node);
    } else

#ifdef _WIN32
        // load from current directory
        rc = loadFromFile("supernode.conf", &sss_node);
#else
        rc = -1;
#endif

    if(rc < 0) {
        help(1); /* short help */
    }

    if(sss_node.community_file)
        load_allowed_sn_community(&sss_node);

#if defined(N2N_HAVE_DAEMON)
    if(sss_node.daemon) {
        setUseSyslog(1); /* traceEvent output now goes to syslog. */

        if(-1 == daemon(0, 0)) {
            traceEvent(TRACE_ERROR, "failed to become daemon");
            exit(-5);
        }
    }
#endif /* #if defined(N2N_HAVE_DAEMON) */

    // warn on default federation name
    if(!strcmp(sss_node.federation->community, FEDERATION_NAME)) {
        traceEvent(TRACE_WARNING, "using default federation name; FOR TESTING ONLY, usage of a custom federation name (-F) is highly recommended!");
    }

    if(sss_node.override_spoofing_protection) {
        traceEvent(TRACE_WARNING, "disabled MAC and IP address spoofing protection; FOR TESTING ONLY, usage of user-password authentication (-I, -J, -P) recommended instead!");
    }

    calculate_shared_secrets(&sss_node);

    traceEvent(TRACE_DEBUG, "traceLevel is %d", getTraceLevel());

    sss_node.sock = open_socket(sss_node.lport, sss_node.bind_address, 0 /* UDP */);
    if(-1 == sss_node.sock) {
        traceEvent(TRACE_ERROR, "failed to open main socket. %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode is listening on UDP %u (main)", sss_node.lport);
    }

#ifdef N2N_HAVE_TCP
    sss_node.tcp_sock = open_socket(sss_node.lport, sss_node.bind_address, 1 /* TCP */);
    if(-1 == sss_node.tcp_sock) {
        traceEvent(TRACE_ERROR, "failed to open auxiliary TCP socket, %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode opened TCP %u (aux)", sss_node.lport);
    }

    if(-1 == listen(sss_node.tcp_sock, N2N_TCP_BACKLOG_QUEUE_SIZE)) {
        traceEvent(TRACE_ERROR, "failed to listen on auxiliary TCP socket, %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode is listening on TCP %u (aux)", sss_node.lport);
    }
#endif

    sss_node.mgmt_sock = open_socket(sss_node.mport, INADDR_LOOPBACK, 0 /* UDP */);
    if(-1 == sss_node.mgmt_sock) {
        traceEvent(TRACE_ERROR, "failed to open management socket, %s", strerror(errno));
        exit(-2);
    } else {
        traceEvent(TRACE_NORMAL, "supernode is listening on UDP %u (management)", sss_node.mport);
    }

    HASH_ITER(hh, sss_node.federation->edges, scan, tmp)
        scan->socket_fd = sss_node.sock;

#ifndef _WIN32
    /*
     * If no uid/gid is specified on the commandline, use the uid/gid of the
     * first found out of user "n2n" or "nobody"
     */
    if(((pw = getpwnam ("n2n")) != NULL) || ((pw = getpwnam ("nobody")) != NULL)) {
        /*
         * If the uid/gid is not set from the CLI, set it from getpwnam
         * otherwise reset it to zero
         * (TODO: this looks wrong)
         */
        sss_node.userid = sss_node.userid == 0 ? pw->pw_uid : 0;
        sss_node.groupid = sss_node.groupid == 0 ? pw->pw_gid : 0;
    }

    /*
     * If we have a non-zero requested uid/gid, attempt to switch to use
     * those
     */
    if((sss_node.userid != 0) || (sss_node.groupid != 0)) {
        traceEvent(TRACE_NORMAL, "dropping privileges to uid=%d, gid=%d",
	                 (signed int)sss_node.userid, (signed int)sss_node.groupid);

        /* Finished with the need for root privileges. Drop to unprivileged user. */
        if((setgid(sss_node.groupid) != 0)
           || (setuid(sss_node.userid) != 0)) {
            traceEvent(TRACE_ERROR, "unable to drop privileges [%u/%s]", errno, strerror(errno));
        }
    }

    if((getuid() == 0) || (getgid() == 0)) {
        traceEvent(TRACE_WARNING, "running as root is discouraged, check out the -u/-g options");
    }
#endif

    sn_init(&sss_node);

    traceEvent(TRACE_NORMAL, "supernode started");

#ifdef __linux__
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, term_handler);
    signal(SIGINT,  term_handler);
    signal(SIGHUP,  dump_registrations);
#endif
#ifdef _WIN32
    SetConsoleCtrlHandler(term_handler, TRUE);
#endif

    sss_node.keep_running = &keep_running;
    return run_sn_loop(&sss_node);
}
