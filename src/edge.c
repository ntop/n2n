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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include <ctype.h>                   // for isspace
#include <errno.h>                   // for errno
#include <getopt.h>                  // for required_argument, no_argument
#include <signal.h>                  // for signal, SIG_IGN, SIGPIPE, SIGCHLD
#include <stdbool.h>
#include <stdint.h>                  // for uint8_t, uint16_t
#include <stdio.h>                   // for printf, NULL, fclose, snprintf
#include <stdlib.h>                  // for atoi, exit, calloc, free, malloc
#include <string.h>                  // for strncpy, memset, strlen, strcmp
#include <sys/param.h>               // for MIN
#include <sys/time.h>                // for timeval
#include <sys/types.h>               // for u_char
#include <time.h>                    // for time
#include <unistd.h>                  // for setuid, _exit, chdir, fork, getgid
#include "auth.h"                    // for generate_private_key, generate_p...
#include "config.h"                  // for PACKAGE_BUILDDATE, PACKAGE_VERSION
#include "n2n.h"                     // for n2n_edge_conf_t, n2n_edge_t, fil...
#include "network_traffic_filter.h"  // for process_traffic_filter_rule_str
#include "pearson.h"                 // for pearson_hash_64
#include "portable_endian.h"         // for htobe32
#include "random_numbers.h"          // for n2n_seed, n2n_srand
#include "sn_selection.h"            // for sn_selection_sort, sn_selection_...
#include "speck.h"                   // for speck_init, speck_context_t
#include "uthash.h"                  // for UT_hash_handle, HASH_ADD, HASH_C...

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>               // for inet_addr, inet_ntop
#include <netinet/in.h>              // for INADDR_ANY, INADDR_NONE, ntohl
#include <pwd.h>                     // for getpwnam, passwd
#include <sys/select.h>              // for select, FD_ISSET, FD_SET, FD_ZERO
#include <sys/socket.h>              // for AF_INET
#endif

/* *************************************************** */

/** maximum length of command line arguments */
#define MAX_CMDLINE_BUFFER_LENGTH        4096

/** maximum length of a line in the configuration file */
#define MAX_CONFFILE_LINE_LENGTH         1024

/* ***************************************************** */

#ifdef HAVE_LIBCAP

#include <sys/capability.h>
#include <sys/prctl.h>

static cap_value_t cap_values[] = {
    //CAP_NET_RAW,            /* Use RAW and PACKET sockets */
    CAP_NET_ADMIN         /* Needed to performs routes cleanup at exit */
};

int num_cap = sizeof(cap_values)/sizeof(cap_value_t);
#endif

// forward declaration for use in main()
void send_register_super (n2n_edge_t *eee);
void send_query_peer (n2n_edge_t *eee, const n2n_mac_t dst_mac);
int supernode_connect (n2n_edge_t *eee);
int supernode_disconnect (n2n_edge_t *eee);
int fetch_and_eventually_process_data (n2n_edge_t *eee, SOCKET sock,
                                       uint8_t *pktbuf, uint16_t *expected, uint16_t *position,
                                       time_t now);
int resolve_check (n2n_resolve_parameter_t *param, uint8_t resolution_request, time_t now);

/* ***************************************************** */

/** Find the address and IP mode for the tuntap device.
 *
 *    s is of the form:
 *
 * ["static"|"dhcp",":"] (<host>|<ip>) [/<cidr subnet mask>]
 *
 * for example        static:192.168.8.5/24
 *
 * Fill the parts of the string into the fileds, ip_mode only if
 * present. All strings are NULL terminated.
 *
 *    return 0 on success and -1 on error
 */
static int scan_address (char * ip_addr, size_t addr_size,
                         char * netmask, size_t netmask_size,
                         char * ip_mode, size_t mode_size,
                         char * s) {

    int retval = -1;
    char * start;
    char * end;
    int bitlen = N2N_EDGE_DEFAULT_CIDR_NM;

    if((NULL == s) || (NULL == ip_addr) || (NULL == netmask)) {
        return -1;
    }

    memset(ip_addr, 0, addr_size);
    memset(netmask, 0, netmask_size);

    start = s;
    end = strpbrk(s, ":");

    if(end) {
        // colon is present
        if(ip_mode) {
            memset(ip_mode, 0, mode_size);
            strncpy(ip_mode, start, (size_t)MIN(end - start, mode_size - 1));
        }
        start = end + 1;
    } else {
        // colon is not present
    }
    // start now points to first address character
    retval = 0; // we have got an address

    end = strpbrk(start, "/");

    if(!end)
        // no slash present -- default end
        end = s + strlen(s);
    else
	// slash is present. now, handle the sub-network address
	sscanf(end + 1, "%u", &bitlen);

    strncpy(ip_addr, start, (size_t)MIN(end - start, addr_size - 1)); // ensure NULL term

    bitlen = htobe32(bitlen2mask(bitlen));
    inet_ntop(AF_INET, &bitlen, netmask, netmask_size);

    return retval;
}

/* *************************************************** */

static void help (int level) {

    if(level == 0) return; /* no help required */

    printf("\n");
    print_n2n_version();

    if(level == 1) /* short help */ {

        printf("   basic usage:  edge <config file> (see edge.conf)\n"
               "\n"
               "            or   edge "
               " -c <community name> "
               "\n                      "
               " -l <supernode host>:<port> "
               "\n                      "
               "[-a <tap IP address>] "
               "\n                      "
#if defined(N2N_CAN_NAME_IFACE)
               "[-d <tap device name>] "
               "\n                      "
#endif
               "[-k <encryption key>] "
               "\n"
               "\n  -h    shows a quick reference including all available options"
               "\n --help gives a detailed parameter description"
               "\n   man  files for n2n, edge, and supernode contain in-depth information"
               "\n\n");

    } else if(level == 2) /* quick reference */ {

        printf(" general usage:  edge <config file> (see edge.conf)\n"
           "\n"
               "            or   edge "
               " -c <community name>"
               " -l <supernode host:port>"
            "\n                      "
               "[-p [<local bind ip address>:]<local port>] "
            "\n                      "

#ifdef __linux__
               "[-T <type of service>] "
#endif
#ifndef __APPLE__
               "[-D] "
#endif
            "\n options for under-   "
               "[-i <registration interval>] "
               "[-L <registration ttl>] "
            "\n lying connection     "
               "[-k <key>] "
               "[-A<cipher>] "
               "[-H] "
               "[-z<compression>] "
            "\n                      "
               "[-e <preferred local IP address>] [-S<level of solitude>]"
            "\n                      "
               "[--select-rtt] "
#if defined(HAVE_MINIUPNP) || defined(HAVE_NATPMP)
               "[--no-port-forwarding] "
#endif // HAVE_MINIUPNP || HAVE_NATPMP
          "\n\n tap device and       "
               "[-a [static:|dhcp:]<tap IP address>[/<cidr suffix>]] "
            "\n overlay network      "
               "[-m <tap MAC address>] "
#if defined(N2N_CAN_NAME_IFACE)
               "[-d <tap device name>] "
#endif
            "\n configuration        "
               "[-M <tap MTU>] "
               "[-r] "
               "[-E] "
               "[-I <edge description>] "
            "\n                      "
               "[-J <password>] "
               "[-P <public key>] "
               "[-R <rule string>] "
#ifdef _WIN32
            "\n                      "
               "[-x <metric>] "
#endif
          "\n\n local options        "
#ifndef _WIN32
               "[-f] "
#endif
               "[-t <management port>] "
               "[--management-password <pw>] "
            "\n                      "
               "[-v] "
               "[-V] "
#ifndef _WIN32
            "\n                      "
               "[-u <numerical user id>] "
               "[-g <numerical group id>] "
#endif
          "\n\n environment          "
               "N2N_KEY         instead of [-k <key>]"
          "\n variables            "
               "N2N_COMMUNITY   instead of -c <community>"
          "\n                      "
               "N2N_PASSWORD    instead of [-J <password>]"

          "\n                      "

          "\n meaning of the       "
#ifndef __APPLE__
                                  "[-D]  enable PMTU discovery"
#endif
          "\n flag options         [-H]  enable header encryption"
          "\n                      [-r]  enable packet forwarding through n2n community"
          "\n                      [-E]  accept multicast MAC addresses"
          "\n            [--select-rtt]  select supernode by round trip time"
          "\n            [--select-mac]  select supernode by MAC address"
#ifndef _WIN32
          "\n                      [-f]  do not fork but run in foreground"
#endif
          "\n                      [-v]  make more verbose, repeat as required"
          "\n                      [-V]  make less verbose, repeat as required"
          "\n                      "

          "\n  -h    shows this quick reference including all available options"
          "\n --help gives a detailed parameter description"
          "\n   man  files for n2n, edge, and supernode contain in-depth information"
          "\n\n");

    } else /* long help */ {

        printf(" general usage:  edge <config file> (see edge.conf)\n"
               "\n"
               "            or   edge  -c <community name> -l <supernode host:port>\n"
               "                      [further optional command line parameters]\n\n"
        );
        printf (" OPTIONS FOR THE UNDERLYING NETWORK CONNECTION\n");
        printf (" ---------------------------------------------\n\n");
        printf(" -c <community>    | n2n community name the edge belongs to\n");
        printf(" -l <host:port>    | supernode ip address or name, and port\n");
        printf(" -p [<ip>:]<port>  | fixed local UDP port and optionally bind to the\n"
               "                   | sepcified local IP address only (any by default)\n");
#ifdef __linux__
        printf(" -T <tos>          | TOS for packets, e.g. 0x48 for SSH like priority\n");
#endif
#ifndef __APPLE__
        printf(" -D                | enable PMTU discovery, it can reduce fragmentation but\n"
               "                   | causes connections to stall if not properly supported\n");
#endif
        printf(" -e <local ip>     | advertises the provided local IP address as preferred,\n"
               "                   | useful if multicast peer detection is not available,\n"
               "                   | '-e auto' tries IP address auto-detection\n");
        printf(" -S1 ... -S2       | do not connect p2p, always use the supernode,\n"
               "                   | -S1 = via UDP"

#ifdef N2N_HAVE_TCP
                                  ", -S2 = via TCP"
#endif
"\n");
        printf(" -i <reg_interval> | registration interval, for NAT hole punching (default\n"
               "                   | %u seconds)\n", REGISTER_SUPER_INTERVAL_DFL);
        printf(" -L <reg_ttl>      | TTL for registration packet for NAT hole punching through\n"
               "                   | supernode (default 0 for not set)\n");
        printf(" -k <key>          | encryption key (ASCII) - also N2N_KEY=<key>\n");
        printf(" -A1               | disable payload encryption, do not use with key, defaults\n"
               "                   | to AES then\n");
        printf(" -A2 ... -A5       | choose a cipher for payload encryption, requires a key,\n"
               "                   | -A2 = Twofish, -A3 = AES (default if key provided),\n"
               "                   | -A4 = ChaCha20, -A5 = Speck-CTR\n");
        printf(" -H                | use header encryption, supernode needs fixed community\n");
        printf(" -z1 ... -z2       | compress outgoing data packets, -z1 = lzo1x,\n"
               "                   | "
#ifdef HAVE_ZSTD
                                     "-z2 = zstd, "
#endif
                                     "disabled by default\n");
        printf("--select-rtt       | supernode selection based on round trip time\n"
               "--select-mac       | supernode selection based on MAC address (default:\n"
               "                   | by load)\n");
        printf ("\n");
        printf (" TAP DEVICE AND OVERLAY NETWORK CONFIGURATION\n");
        printf (" --------------------------------------------\n\n");
        printf(" -a [mode]<ip>[/n] | interface address and optional CIDR subnet, default '/24',\n"
               "                   | mode = [static|dhcp]:, for DHCP use '-r -a dhcp:0.0.0.0',\n"
               "                   | edge draws IP address from supernode if no '-a ...' given\n");
        printf(" -m <mac>          | fixed MAC address for the TAP interface, e.g.\n"
               "                   | '-m 10:20:30:40:50:60', random otherwise\n");
#if defined(N2N_CAN_NAME_IFACE)
        printf(" -d <device>       | TAP device name\n");
#endif
        printf(" -M <mtu>          | specify n2n MTU of TAP interface, default %d\n", DEFAULT_MTU);
        printf(" -r                | enable packet forwarding through n2n community,\n"
               "                   | also required for bridging\n");
        printf(" -E                | accept multicast MAC addresses, drop by default\n");
        printf(" -I <description>  | annotate the edge's description used for easier\n"
               "                   | identification in management port output or username\n");
        printf(" -J <password>     | password for user-password edge authentication\n");
        printf(" -P <public key>   | federation public key for user-password authentication\n");
        printf(" -R <rule>         | drop or accept packets by rules, can be set multiple times\n");
        printf("                   | rule format:    'src_ip/n:[s_port,e_port],...\n"
               "                   |    |on same|  ...dst_ip/n:[s_port,e_port],...\n"
               "                   |    | line  |  ...TCP+/-,UDP+/-,ICMP+/-'\n");
#ifdef _WIN32
        printf(" -x <metric>       | set TAP interface metric, defaults to 0 (auto),\n"
               "                   | e.g. set to 1 for better multiplayer game detection\n");
#endif
        printf ("\n");
        printf (" LOCAL OPTIONS\n");
        printf (" -------------\n\n");
#ifndef _WIN32
        printf(" -f                | do not fork and run as a daemon, rather run in foreground\n");
#endif
        printf(" -t <port>         | management UDP port, for multiple edges on a machine,\n"
               "                   | defaults to %u\n", N2N_EDGE_MGMT_PORT);
        printf(" --management_...  | management port password, defaults to '%s'\n"
               " ...password <pw>  | \n", N2N_MGMT_PASSWORD);
        printf(" -v                | make more verbose, repeat as required\n");
        printf(" -V                | make less verbose, repeat as required\n");
#ifndef _WIN32
        printf(" -u <UID>          | numeric user ID to use when privileges are dropped\n");
        printf(" -g <GID>          | numeric group ID to use when privileges are dropped\n");
#endif
        printf ("\n");
        printf (" ENVIRONMENT VARIABLES\n");
        printf (" ---------------------\n\n");
        printf(" N2N_KEY           | encryption key (ASCII), not with '-k ...'\n");
        printf(" N2N_COMMUNITY     | community name (ASCII), overwritten by '-c ...'\n");
        printf(" N2N_PASSWORD      | password (ASCII) for user-password authentication,\n"
               "                   | overwritten by '-J ...'\n");
#ifdef _WIN32
        printf ("\n");
        printf (" AVAILABLE TAP ADAPTERS\n");
        printf (" ----------------------\n\n");
        win_print_available_adapters();
#endif
        printf ("\n"
                "\n  -h    shows a quick reference including all available options"
                "\n --help gives this detailed parameter description"
                "\n   man  files for n2n, edge, and supernode contain in-depth information"
                "\n\n");
    }

    exit(0);
}

/* *************************************************** */

static void setPayloadCompression (n2n_edge_conf_t *conf, int compression) {

    /* even though 'compression' and 'conf->compression' share the same encoding scheme,
     * a switch-statement under conditional compilation is used to sort out the
     * unsupported optarguments */
    switch (compression) {
        case 1: {
            conf->compression = N2N_COMPRESSION_ID_LZO;
            break;
        }
#ifdef HAVE_ZSTD
        case 2: {
            conf->compression = N2N_COMPRESSION_ID_ZSTD;
            break;
        }
#endif
        default: {
            conf->compression = N2N_COMPRESSION_ID_NONE;
            // internal comrpession scheme numbering differs from cli counting by one, hence plus one
            // (internal: 0 == invalid, 1 == none, 2 == lzo, 3 == zstd)
            traceEvent(TRACE_NORMAL, "the %s compression given by -z_ option is not supported in this version", compression_str(compression + 1));
            exit(1); // to make the user aware
        }
    }
}

/* *************************************************** */

static void setPayloadEncryption (n2n_edge_conf_t *conf, int cipher) {

    /* even though 'cipher' and 'conf->transop_id' share the same encoding scheme,
     * a switch-statement under conditional compilation is used to sort out the
     * unsupported ciphers */
    switch (cipher) {
        case 1: {
            conf->transop_id = N2N_TRANSFORM_ID_NULL;
            break;
        }

        case 2: {
            conf->transop_id = N2N_TRANSFORM_ID_TWOFISH;
            break;
        }

        case 3: {
            conf->transop_id = N2N_TRANSFORM_ID_AES;
            break;
        }

        case 4: {
            conf->transop_id = N2N_TRANSFORM_ID_CHACHA20;
            break;
        }

        case 5: {
            conf->transop_id = N2N_TRANSFORM_ID_SPECK;
            break;
        }

        default: {
            conf->transop_id = N2N_TRANSFORM_ID_INVAL;
            traceEvent(TRACE_NORMAL, "the %s cipher given by -A_ option is not supported in this version", transop_str(cipher));
            exit(1);
        }
    }
}

/* *************************************************** */

static int setOption (int optkey, char *optargument, n2n_tuntap_priv_config_t *ec, n2n_edge_conf_t *conf) {

    /* traceEvent(TRACE_NORMAL, "Option %c = %s", optkey, optargument ? optargument : ""); */

    switch(optkey) {
        case 'a': /* IP address and mode of TUNTAP interface */ {
            scan_address(ec->ip_addr, N2N_NETMASK_STR_SIZE,
                                     ec->netmask, N2N_NETMASK_STR_SIZE,
                                     ec->ip_mode, N2N_IF_MODE_SIZE,
                                     optargument);
            break;
        }

        case 'c': /* community as a string */ {
            strncpy((char *)conf->community_name, optargument, N2N_COMMUNITY_SIZE);
            conf->community_name[N2N_COMMUNITY_SIZE - 1] = '\0';
            break;
        }

        case 'E': /* multicast ethernet addresses accepted. */ {
            conf->drop_multicast = 0;
            traceEvent(TRACE_INFO, "enabling ethernet multicast traffic");
            break;
        }

#ifndef _WIN32
        case 'u': /* unprivileged uid */ {
            ec->userid = atoi(optargument);
            break;
        }

        case 'g': /* unprivileged uid */ {
            ec->groupid = atoi(optargument);
            break;
        }
#endif

#ifndef _WIN32
        case 'f' : /* do not fork as daemon */ {
            ec->daemon = 0;
            break;
        }
#endif /* #ifndef _WIN32 */

        case 'm' : /* TUNTAP MAC address */ {
            strncpy(ec->device_mac, optargument, N2N_MACNAMSIZ);
            ec->device_mac[N2N_MACNAMSIZ - 1] = '\0';
            break;
        }

        case 'M' : /* TUNTAP MTU */ {
            ec->mtu = atoi(optargument);
            break;
        }

#ifndef __APPLE__
        case 'D' : /* enable PMTU discovery */ {
            conf->disable_pmtu_discovery = 0;
            break;
        }
#endif

        case 'k': /* encrypt key */ {
            if(conf->encrypt_key) free(conf->encrypt_key);
            conf->encrypt_key = strdup(optargument);
            traceEvent(TRACE_DEBUG, "encrypt_key = '%s'\n", conf->encrypt_key);
            break;
        }

        case 'r': /* enable packet routing across n2n endpoints */ {
            conf->allow_routing = 1;
            break;
        }

        case 'A': {
            int cipher;

            if(optargument) {
                cipher = atoi(optargument);
            } else {
                traceEvent(TRACE_WARNING, "the use of the solitary -A switch is deprecated and will not be supported in future versions, "
                           "please use -A3 instead to choose AES cipher for payload encryption");

                cipher = N2N_TRANSFORM_ID_AES; // default, if '-A' only
            }

            setPayloadEncryption(conf, cipher);
            break;
        }

        case 'H': /* indicate header encryption */ {
            /* we cannot be sure if this gets parsed before the community name is set.
             * so, only an indicator is set, action is taken later*/
            conf->header_encryption = HEADER_ENCRYPTION_ENABLED;
            break;
        }

        case 'z': {
            int compression;

            if(optargument) {
                compression = atoi(optargument);
            } else {
                traceEvent(TRACE_WARNING, "the use of the solitary -z switch is deprecated and will not be supported in future versions, "
                           "please use -z1 instead to choose LZO1X algorithm for payload compression");

                compression = 1; // default, if '-z' only, equals -z1
            }

            setPayloadCompression(conf, compression);
            break;
        }

        case 'l': /* supernode-list */ {
            if(optargument) {
                if(edge_conf_add_supernode(conf, optargument) != 0) {
                    traceEvent(TRACE_WARNING, "failed to add supernode '%s'", optargument);
                }
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
        case 'd': /* TUNTAP name */ {
            strncpy(ec->tuntap_dev_name, optargument, sizeof(devstr_t));
            ec->tuntap_dev_name[sizeof(devstr_t) - 1] = '\0';
            break;
        }
#endif
        case 'I': /* Device Description (hint) or username */ {
            strncpy((char *)conf->dev_desc, optargument, N2N_DESC_SIZE);
            conf->dev_desc[N2N_DESC_SIZE - 1] = '\0';
            break;
        }

        case 'J': /* password for user-password authentication */ {
            if(!conf->shared_secret) /* we could already have it from environment variable, see edge_init_conf_defaults() */
                conf->shared_secret = calloc(1, sizeof(n2n_private_public_key_t));
            if(conf->shared_secret)
                generate_private_key(*(conf->shared_secret), optargument);

            // the hash of the username (-I) gets xored into this key later,
            // we can't be sure to already have it at this point
            // also, the complete shared secret will be calculated then as we
            // might still be missing the federation public key as well
            break;
        }

        case 'P': /* federation public key for user-password authentication */ {
            if(strlen(optargument) < ((N2N_PRIVATE_PUBLIC_KEY_SIZE * 8 + 5)/ 6 + 1)) {
                conf->federation_public_key = calloc(1, sizeof(n2n_private_public_key_t));
                if(conf->federation_public_key) {
                    ascii_to_bin(*(conf->federation_public_key), optargument);
                }
            } else {
                traceEvent(TRACE_WARNING, "public key too long");
                return 2;
            }
            break;
        }

        case 'p': {
            char* colon = strpbrk(optargument, ":");
            if(colon) { /*ip address:port */
                *colon = 0;
                conf->bind_address = ntohl(inet_addr(optargument));
                conf->local_port = atoi(++colon);

                if(conf->bind_address == INADDR_NONE) {
                    traceEvent(TRACE_WARNING, "bad address to bind to, binding to any IP address");
                    conf->bind_address = INADDR_ANY;
                }
                if(conf->local_port == 0) {
                    traceEvent(TRACE_WARNING, "bad local port format, using OS assigned port");
                }
            } else { /* ip address or port only */
                char* dot = strpbrk(optargument, ".");
                if(dot) { /* ip address only */
                    conf->bind_address = ntohl(inet_addr(optargument));
                    if(conf->bind_address == INADDR_NONE) {
                        traceEvent(TRACE_WARNING, "bad address to bind to, binding to any IP address");
                        conf->bind_address = INADDR_ANY;
                    }
                } else { /* port only */
                    conf->local_port = atoi(optargument);
                     if(conf->local_port == 0) {
                        traceEvent(TRACE_WARNING, "bad local port format, using OS assigned port");
                    }
                }
            }
            break;
        }

        case 'e': {
            in_addr_t address_tmp;

            if(optargument) {

                if(!strcmp(optargument, "auto")) {
                    address_tmp = INADDR_ANY;
                    conf->preferred_sock_auto = 1;
                } else {
                    address_tmp = inet_addr(optargument);
                }

                memcpy(&(conf->preferred_sock.addr.v4), &(address_tmp), IPV4_SIZE);

                if(address_tmp == INADDR_NONE) {
                    traceEvent(TRACE_WARNING, "bad address for preferred local socket, skipping");
                    conf->preferred_sock.family = AF_INVALID;
                    break;
                } else {
                    conf->preferred_sock.family = AF_INET;
                    // port is set after parsing all cli parameters during supernode_connect()
                }

            }

            break;
        }

        case 't': {
            conf->mgmt_port = atoi(optargument);
            break;
        }
#ifdef __linux__
        case 'T': {
            if((optargument[0] == '0') && (optargument[1] == 'x'))
                conf->tos = strtol(&optargument[2], NULL, 16);
            else
                conf->tos = atoi(optargument);

            break;
        }
#endif
        case 'n': {
            traceEvent(TRACE_WARNING, "route support (-n) has been removed from n2n's core since version 3.1, "
                                      "please try tools/n2n-route instead");
            return 2;
        }

        case 'S': {
            int solitude;
            if(optargument) {
                solitude = atoi(optargument);
            } else {
                traceEvent(TRACE_WARNING, "the use of the solitary -S switch is deprecated and will not be supported in future versions, "
                           "please use -S1 instead to choose supernode-only connection via UDP");

                solitude = 1;
            }

            // set the level
            if(solitude >= 1)
                conf->allow_p2p = 0;
#ifdef N2N_HAVE_TCP
            if(solitude == 2)
                conf->connect_tcp = 1;
#endif
            break;
        }

        case '[': /* round-trip-time-based supernode selection strategy */ {
            // overwrites the default load-based strategy
            conf->sn_selection_strategy = SN_SELECTION_STRATEGY_RTT;

            break;
        }

        case ']': /* mac-address-based supernode selection strategy */ {
            // overwrites the default load-based strategy
            conf->sn_selection_strategy = SN_SELECTION_STRATEGY_MAC;

            break;
        }

        case '{': /* password for management port */ {
            conf->mgmt_password_hash = pearson_hash_64((uint8_t*)optargument, strlen(optargument));

            break;
        }

        case 'h': /* quick reference */ {
            return 2;
        }

        case '@': /* long help */ {
            return 3;
        }

        case 'v': /* verbose */
            setTraceLevel(getTraceLevel() + 1);
            break;

        case 'V': /* less verbose */ {
            setTraceLevel(getTraceLevel() - 1);
            break;
        }

        case 'R': /* network traffic filter */ {
            filter_rule_t *new_rule = malloc(sizeof(filter_rule_t));
            memset(new_rule, 0, sizeof(filter_rule_t));

            if(process_traffic_filter_rule_str(optargument, new_rule)) {
                HASH_ADD(hh, conf->network_traffic_filter_rules, key, sizeof(filter_rule_key_t), new_rule);
            } else {
                free(new_rule);
                traceEvent(TRACE_WARNING, "invalid filter rule: %s", optargument);
                return 2;
            }
            break;
        }
#ifdef _WIN32
        case 'x': {
            conf->metric = atoi(optargument);
            ec->metric = atoi(optargument);
            break;
        }
#endif
        default: {
            traceEvent(TRACE_WARNING, "unknown option -%c", (char)optkey);
            return 2;
        }
    }

    return 0;
}

/* *********************************************** */


static const struct option long_options[] =
    {
        { "community",           required_argument, NULL, 'c' },
        { "supernode-list",      required_argument, NULL, 'l' },
        { "tap-device",          required_argument, NULL, 'd' },
        { "euid",                required_argument, NULL, 'u' },
        { "egid",                required_argument, NULL, 'g' },
        { "verbose",             no_argument,       NULL, 'v' },
        { "help",                no_argument,       NULL, '@' }, /* internal special character '@' to identify long help case */
        { "select-rtt",          no_argument,       NULL, '[' }, /*                            '['             rtt selection strategy */
        { "select-mac",          no_argument,       NULL, ']' }, /*                            ']'             mac selection strategy */
        { "management-password", required_argument, NULL, '{' }, /*                            '{'             management port password */
        { NULL,                  0,                 NULL,  0  }
    };

/* *************************************************** */

/* read command line options */
static int loadFromCLI (int argc, char *argv[], n2n_edge_conf_t *conf, n2n_tuntap_priv_config_t *ec) {

    u_char c;

    while ((c = getopt_long(argc, argv,
                            "k:a:c:Eu:g:m:M:s:d:l:p:fvVhrt:i:I:J:P:S::DL:z::A::Hn:R:e:"
#ifdef __linux__
                            "T:"
#endif
#ifdef _WIN32
                            "x:"
#endif
                            ,
                            long_options, NULL)) != '?') {

        if(c == 255) break;
        help(setOption(c, optarg, ec, conf));

    }

    return 0;
}

/* *************************************************** */

static char *trim (char *s) {

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
static int loadFromFile (const char *path, n2n_edge_conf_t *conf, n2n_tuntap_priv_config_t *ec) {

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

        if(strlen(line) < 2 || line[0] == '#')
            continue;

        // executable, cannot be omitted, content can be anything
        line_vec[0] = line;
        // first token, e.g. `-p` or `-A3', eventually followed by a whitespace or '=' delimiter
        line_vec[1] = strtok(line, "\t =");
        // separate parameter option, if present
        line_vec[2] = strtok(NULL, "");
        if(line_vec[2])
            line_vec[2] = trim(line_vec[2]);
        // not to duplicate the option parser code, call loadFromCLI and pretend we have no option read yet at all
        optind = 0;
        // if second token present (optional argument, not part of first), then announce 3 vector members
        loadFromCLI(line_vec[2] ? 3 : 2, line_vec, conf, ec);
    }

    fclose(fd);
    optind = tmp;

    return 0;
}

/* ************************************** */

#ifndef _WIN32
static void daemonize () {
    int childpid;

    traceEvent(TRACE_NORMAL, "parent process is exiting (this is normal)");

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP,  SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);

    if((childpid = fork()) < 0)
        traceEvent(TRACE_ERROR, "occurred while daemonizing (errno=%d)",
                   errno);
    else {
        if(!childpid) { /* child */
            int rc;

            //traceEvent(TRACE_NORMAL, "Bye bye: I'm becoming a daemon...");
            rc = chdir("/");
            if(rc != 0)
                traceEvent(TRACE_ERROR, "error while moving to / directory");

            setsid();    /* detach from the terminal */

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
}
#endif

/* *************************************************** */

static bool keep_on_running = true;

#if defined(__linux__) || defined(_WIN32)
#ifdef _WIN32
BOOL WINAPI term_handler(DWORD sig)
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

    keep_on_running = false;
#ifdef _WIN32
    switch (sig) {
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            // Will terminate us after we return, blocking it to cleanup
            Sleep(INFINITE);
    }
    return(TRUE);
#endif
}
#endif /* defined(__linux__) || defined(_WIN32) */

/* *************************************************** */

/** Entry point to program from kernel. */
int main (int argc, char* argv[]) {

    int rc;
    tuntap_dev tuntap;            /* a tuntap device */
    n2n_edge_t *eee;              /* single instance for this program */
    n2n_edge_conf_t conf;         /* generic N2N edge config */
    n2n_tuntap_priv_config_t ec;  /* config used for standalone program execution */
    uint8_t runlevel = 0;         /* bootstrap: runlevel */
    uint8_t seek_answer = 1;      /*            expecting answer from supernode */
    time_t now, last_action = 0;  /*            timeout */
    macstr_t mac_buf;             /*            output mac address */
    fd_set socket_mask;           /*            for supernode answer */
    struct timeval wait_time;     /*            timeout for sn answer */
    peer_info_t *scan, *scan_tmp; /*            supernode iteration */

    uint16_t expected = sizeof(uint16_t);
    uint16_t position = 0;
    uint8_t  pktbuf[N2N_SN_PKTBUF_SIZE + sizeof(uint16_t)]; /* buffer + prepended buffer length in case of tcp */


#ifndef _WIN32
    struct passwd *pw = NULL;
#endif
#ifdef HAVE_LIBCAP
    cap_t caps;
#endif
#ifdef _WIN32
    initWin32();
#endif

    /* Defaults */
    edge_init_conf_defaults(&conf);
    memset(&ec, 0, sizeof(ec));
    ec.mtu = DEFAULT_MTU;
    ec.daemon = 1;        /* By default run in daemon mode. */

#ifndef _WIN32
    if(((pw = getpwnam("n2n")) != NULL) ||
       ((pw = getpwnam("nobody")) != NULL)) {
        ec.userid = pw->pw_uid;
        ec.groupid = pw->pw_gid;
    }
#endif

#ifdef _WIN32
    ec.tuntap_dev_name[0] = '\0';
    ec.metric = 0;
#else
    snprintf(ec.tuntap_dev_name, sizeof(ec.tuntap_dev_name), N2N_EDGE_DEFAULT_DEV_NAME);
#endif
    snprintf(ec.netmask, sizeof(ec.netmask), N2N_EDGE_DEFAULT_NETMASK);

    if((argc >= 2) && (argv[1][0] != '-')) {
        rc = loadFromFile(argv[1], &conf, &ec);
        if(argc > 2)
            rc = loadFromCLI(argc, argv, &conf, &ec);
    } else if(argc > 1)
        rc = loadFromCLI(argc, argv, &conf, &ec);
    else

#ifdef _WIN32
        // load from current directory
        rc = loadFromFile("edge.conf", &conf, &ec);
#else
        rc = -1;
#endif

    // --- additional crypto setup; REVISIT: move to edge_init()?
    // payload
    if(conf.transop_id == N2N_TRANSFORM_ID_NULL) {
        if(conf.encrypt_key) {
            // make sure that AES is default cipher if key only (and no cipher) is specified
            traceEvent(TRACE_WARNING, "switching to AES as key was provided");
            conf.transop_id = N2N_TRANSFORM_ID_AES;
        }
    }
    // user auth
    if(conf.shared_secret /* containing private key only so far*/) {
        // if user-password auth and no federation public key provided, use default
        if(!conf.federation_public_key) {
            conf.federation_public_key = calloc(1, sizeof(n2n_private_public_key_t));
            if(conf.federation_public_key) {
                traceEvent(TRACE_WARNING, "using default federation public key; FOR TESTING ONLY, usage of a custom federation name and key (-P) is highly recommended!");
                generate_private_key(*(conf.federation_public_key), &FEDERATION_NAME[1]);
                generate_public_key(*(conf.federation_public_key), *(conf.federation_public_key));
            }
        }
        // calculate public key and shared secret
        if(conf.federation_public_key) {
            traceEvent(TRACE_NORMAL, "using username and password for edge authentication");
            bind_private_key_to_username(*(conf.shared_secret), (char *)conf.dev_desc);
            conf.public_key = calloc(1, sizeof(n2n_private_public_key_t));
            if(conf.public_key)
                generate_public_key(*conf.public_key, *(conf.shared_secret));
            generate_shared_secret(*(conf.shared_secret), *(conf.shared_secret), *(conf.federation_public_key));
            // prepare (first 128 bit) for use as key
            conf.shared_secret_ctx = (he_context_t*)calloc(1, sizeof(speck_context_t));
            speck_init((speck_context_t**)&(conf.shared_secret_ctx), *(conf.shared_secret), 128);
        }
        // force header encryption
        if(conf.header_encryption != HEADER_ENCRYPTION_ENABLED) {
            traceEvent(TRACE_NORMAL, "enabling header encryption for edge authentication");
            conf.header_encryption = HEADER_ENCRYPTION_ENABLED;
        }
    }

    if(rc < 0)
        help(1); /* short help */

    if(edge_verify_conf(&conf) != 0)
        help(1); /* short help */

    traceEvent(TRACE_NORMAL, "starting n2n edge %s %s", PACKAGE_VERSION, PACKAGE_BUILDDATE);

#ifdef HAVE_LIBCRYPTO
    traceEvent(TRACE_NORMAL, "using %s", OpenSSL_version(0));
#endif

    traceEvent(TRACE_NORMAL, "using compression: %s.", compression_str(conf.compression));
    traceEvent(TRACE_NORMAL, "using %s cipher.", transop_str(conf.transop_id));

    /* Random seed */
    n2n_srand (n2n_seed());

#ifndef _WIN32
    /* If running suid root then we need to setuid before using the force. */
    if(setuid(0) != 0)
        traceEvent(TRACE_ERROR, "unable to become root [%u/%s]", errno, strerror(errno));
    /* setgid(0); */
#endif

    if(conf.encrypt_key && !strcmp((char*)conf.community_name, conf.encrypt_key))
        traceEvent(TRACE_WARNING, "community and encryption key must differ, otherwise security will be compromised");

    if((eee = edge_init(&conf, &rc)) == NULL) {
        traceEvent(TRACE_ERROR, "failed in edge_init");
        exit(1);
    }

    memcpy(&(eee->tuntap_priv_conf), &ec, sizeof(ec));

    if((0 == strcmp("static", eee->tuntap_priv_conf.ip_mode)) ||
         ((eee->tuntap_priv_conf.ip_mode[0] == '\0') && (eee->tuntap_priv_conf.ip_addr[0] != '\0'))) {
        traceEvent(TRACE_NORMAL, "use manually set IP address");
        eee->conf.tuntap_ip_mode = TUNTAP_IP_MODE_STATIC;
    } else if(0 == strcmp("dhcp", eee->tuntap_priv_conf.ip_mode)) {
        traceEvent(TRACE_NORMAL, "obtain IP from other edge DHCP services");
        eee->conf.tuntap_ip_mode = TUNTAP_IP_MODE_DHCP;
    } else {
        traceEvent(TRACE_NORMAL, "automatically assign IP address by supernode");
        eee->conf.tuntap_ip_mode = TUNTAP_IP_MODE_SN_ASSIGN;
    }

    // mini main loop for bootstrap, not using main loop code because some of its mechanisms do not fit in here
    // for the sake of quickly establishing connection. REVISIT when a more elegant way to re-use main loop code
    // is found

    // find at least one supernode alive to faster establish connection
    // exceptions:
    if((HASH_COUNT(eee->conf.supernodes) <= 1) || (eee->conf.connect_tcp) || (eee->conf.shared_secret)) {
        // skip the initial supernode ping
        traceEvent(TRACE_DEBUG, "skip PING to supernode");
        runlevel = 2;
    }

    eee->last_sup = 0; /* if it wasn't zero yet */
    eee->curr_sn = eee->conf.supernodes;
    supernode_connect(eee);
    while(runlevel < 5) {

        now = time(NULL);

        // we do not use switch-case because we also check for 'greater than'

        if(runlevel == 0) { /* PING to all known supernodes */
            last_action = now;
            eee->sn_pong = 0;
            // (re-)initialize the number of max concurrent pings (decreases by calling send_query_peer)
            eee->conf.number_max_sn_pings = NUMBER_SN_PINGS_INITIAL;
            send_query_peer(eee, null_mac);
            traceEvent(TRACE_NORMAL, "send PING to supernodes");
            runlevel++;
        }

        if(runlevel == 1) { /* PING has been sent to all known supernodes */
            if(eee->sn_pong) {
                // first answer
                eee->sn_pong = 0;
                sn_selection_sort(&(eee->conf.supernodes));
                eee->curr_sn = eee->conf.supernodes;
                supernode_connect(eee);
                traceEvent(TRACE_NORMAL, "received first PONG from supernode [%s]", eee->curr_sn->ip_addr);
                runlevel++;
            } else if(last_action <= (now - BOOTSTRAP_TIMEOUT)) {
                // timeout
                runlevel--;
                // skip waiting for answer to direcly go to send PING again
                seek_answer = 0;
                traceEvent(TRACE_DEBUG, "PONG timeout");
            }
        }

        // by the way, have every later PONG cause the remaining (!) list to be sorted because the entries
        // before have already been tried; as opposed to initial PONG, do not change curr_sn
        if(runlevel > 1) {
            if(eee->sn_pong) {
                eee->sn_pong = 0;
                if(eee->curr_sn->hh.next) {
                    sn_selection_sort((peer_info_t**)&(eee->curr_sn->hh.next));
                    traceEvent(TRACE_DEBUG, "received additional PONG from supernode");
                    // here, it is hard to detemine from which one, so no details to output
                }
            }
        }

        if(runlevel == 2) { /* send REGISTER_SUPER to get auto ip address from a supernode */
            if(eee->conf.tuntap_ip_mode == TUNTAP_IP_MODE_SN_ASSIGN) {
                last_action = now;
                eee->sn_wait = 1;
                send_register_super(eee);
                runlevel++;
                traceEvent(TRACE_NORMAL, "send REGISTER_SUPER to supernode [%s] asking for IP address",
                                         eee->curr_sn->ip_addr);
            } else {
                runlevel += 2; /* skip waiting for TUNTAP IP address */
                traceEvent(TRACE_DEBUG, "skip auto IP address asignment");
            }
        }

        if(runlevel == 3) { /* REGISTER_SUPER to get auto ip address from a sn has been sent */
            if(!eee->sn_wait) { /* TUNTAP IP address received */
                runlevel++;
                traceEvent(TRACE_NORMAL, "received REGISTER_SUPER_ACK from supernode for IP address asignment");
                // it should be from curr_sn, but we can't determine definitely here, so no details to output
            } else if(last_action <= (now - BOOTSTRAP_TIMEOUT)) {
                // timeout, so try next supernode
                if(eee->curr_sn->hh.next)
                    eee->curr_sn = eee->curr_sn->hh.next;
                else
                    eee->curr_sn = eee->conf.supernodes;
                supernode_connect(eee);
                runlevel--;
                // skip waiting for answer to direcly go to send REGISTER_SUPER again
                seek_answer = 0;
                traceEvent(TRACE_DEBUG, "REGISTER_SUPER_ACK timeout");
            }
        }

        if(runlevel == 4) { /* configure the TUNTAP device, including routes */
            if(tuntap_open(&tuntap, eee->tuntap_priv_conf.tuntap_dev_name, eee->tuntap_priv_conf.ip_mode,
                           eee->tuntap_priv_conf.ip_addr, eee->tuntap_priv_conf.netmask,
                           eee->tuntap_priv_conf.device_mac, eee->tuntap_priv_conf.mtu
#ifdef _WIN32
                           , eee->tuntap_priv_conf.metric
#endif
                                                           ) < 0)
                exit(1);
            memcpy(&eee->device, &tuntap, sizeof(tuntap));
            traceEvent(TRACE_NORMAL, "created local tap device IP: %s, Mask: %s, MAC: %s",
                                     eee->tuntap_priv_conf.ip_addr,
                                     eee->tuntap_priv_conf.netmask,
                                     macaddr_str(mac_buf, eee->device.mac_addr));
            runlevel = 5;
            // no more answers required
            seek_answer = 0;
        }

        // we usually wait for some answer, there however are exceptions when going back to a previous runlevel
        if(seek_answer) {
            FD_ZERO(&socket_mask);
            FD_SET(eee->sock, &socket_mask);
            wait_time.tv_sec = BOOTSTRAP_TIMEOUT;
            wait_time.tv_usec = 0;

            if(select(eee->sock + 1, &socket_mask, NULL, NULL, &wait_time) > 0) {
                if(FD_ISSET(eee->sock, &socket_mask)) {

                    fetch_and_eventually_process_data (eee, eee->sock,
                                                       pktbuf, &expected, &position,
                                                       now);
                }
            }
        }
        seek_answer = 1;

        resolve_check(eee->resolve_parameter, 0 /* no intermediate resolution requirement at this point */, now);
    }
    // allow a higher number of pings for first regular round of ping
    // to quicker get an inital 'supernode selection criterion overview'
    eee->conf.number_max_sn_pings = NUMBER_SN_PINGS_INITIAL;
    // shape supernode list; make current one the first on the list
    HASH_ITER(hh, eee->conf.supernodes, scan, scan_tmp) {
        if(scan == eee->curr_sn)
            sn_selection_criterion_good(&(scan->selection_criterion));
        else
            sn_selection_criterion_default(&(scan->selection_criterion));
    }
    sn_selection_sort(&(eee->conf.supernodes));
    // do not immediately ping again, allow some time
    eee->last_sweep = now - SWEEP_TIME + 2 * BOOTSTRAP_TIMEOUT;
    eee->sn_wait = 1;
    eee->last_register_req = 0;

#ifndef _WIN32
    if(eee->tuntap_priv_conf.daemon) {
        setUseSyslog(1); /* traceEvent output now goes to syslog. */
        daemonize();
    }

#ifdef HAVE_LIBCAP
    /* Before dropping the privileges, retain capabilities to regain them in future. */
    caps = cap_get_proc();

    cap_set_flag(caps, CAP_PERMITTED, num_cap, cap_values, CAP_SET);
    cap_set_flag(caps, CAP_EFFECTIVE, num_cap, cap_values, CAP_SET);

    if((cap_set_proc(caps) != 0) || (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0))
        traceEvent(TRACE_WARNING, "unable to retain permitted capabilities [%s]\n", strerror(errno));
#else
#ifndef __APPLE__
    traceEvent(TRACE_WARNING, "n2n has not been compiled with libcap-dev; some commands may fail");
#endif
#endif /* HAVE_LIBCAP */

    if((eee->tuntap_priv_conf.userid != 0) || (eee->tuntap_priv_conf.groupid != 0)) {
        traceEvent(TRACE_NORMAL, "dropping privileges to uid=%d, gid=%d",
                   (signed int)eee->tuntap_priv_conf.userid, (signed int)eee->tuntap_priv_conf.groupid);

        /* Finished with the need for root privileges. Drop to unprivileged user. */
        if((setgid(eee->tuntap_priv_conf.groupid) != 0)
           || (setuid(eee->tuntap_priv_conf.userid) != 0)) {
            traceEvent(TRACE_ERROR, "unable to drop privileges [%u/%s]", errno, strerror(errno));
            exit(1);
        }
    }

    if((getuid() == 0) || (getgid() == 0))
        traceEvent(TRACE_WARNING, "running as root is discouraged, check out the -u/-g options");
#endif

#ifdef __linux__
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, term_handler);
    signal(SIGINT,  term_handler);
#endif
#ifdef _WIN32
    SetConsoleCtrlHandler(term_handler, TRUE);
#endif

    eee->keep_running = &keep_on_running;
    traceEvent(TRACE_NORMAL, "edge started");
    rc = run_edge_loop(eee);
    print_edge_stats(eee);

#ifdef HAVE_LIBCAP
    /* Before completing the cleanup, regain the capabilities as some
     * cleanup tasks require them (e.g. routes cleanup). */
    cap_set_flag(caps, CAP_EFFECTIVE, num_cap, cap_values, CAP_SET);

    if(cap_set_proc(caps) != 0)
        traceEvent(TRACE_WARNING, "could not regain the capabilities [%s]\n", strerror(errno));

    cap_free(caps);
#endif

    /* Cleanup */
    edge_term_conf(&eee->conf);
    tuntap_close(&eee->device);
    edge_term(eee);

#ifdef _WIN32
    destroyWin32();
#endif

    return(rc);
}

/* ************************************** */
