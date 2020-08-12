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

static int keep_running;

int main()
{
    n2n_edge_conf_t conf;
    tuntap_dev tuntap;
    n2n_edge_t *eee;
    int rc;

    edge_init_conf_defaults(&conf);
    conf.allow_p2p = 1;                                                                      // Whether to allow peer-to-peer communication
    conf.allow_routing = 1;                                                                  // Whether to allow the edge to route packets to other edges
    snprintf((char *)conf.community_name, sizeof(conf.community_name), "%s", "mycommunity"); // Community to connect to
    conf.disable_pmtu_discovery = 1;                                                         // Whether to disable the path MTU discovery
    conf.drop_multicast = 0;                                                                 // Whether to disable multicast
    conf.tuntap_ip_mode = TUNTAP_IP_MODE_SN_ASSIGN;                                          // How to set the IP address
    conf.encrypt_key = "mysecret";                                                           // Secret to decrypt & encrypt with
    conf.local_port = 0;                                                                     // What port to use (0 = any port)
    conf.mgmt_port = N2N_EDGE_MGMT_PORT;                                                     // Edge management port (5644 by default)
    conf.register_interval = 1;                                                              // Interval for both UDP NAT hole punching and supernode registration
    conf.register_ttl = 1;                                                                   // Interval for UDP NAT hole punching through supernode
    edge_conf_add_supernode(&conf, "localhost:1234");                                        // Supernode to connect to
    conf.tos = 16;                                                                           // Type of service for sent packets
    conf.transop_id = N2N_TRANSFORM_ID_TWOFISH;                                              // Use the twofish encryption

    if (edge_verify_conf(&conf) != 0)
    {
        return -1;
    }

    if (tuntap_open(&tuntap,
                    "edge0",             // Name of the device to create
                    "static",            // IP mode; static|dhcp
                    "10.0.0.1",          // Set ip address
                    "255.255.255.0",     // Netmask to use
                    "DE:AD:BE:EF:01:10", // Set mac address
                    DEFAULT_MTU) < 0)    // MTU to use
    {
        return -1;
    }

    eee = edge_init(&conf, &rc);
    if (eee == NULL)
    {
        exit(1);
    }

    keep_running = 1;
    rc = run_edge_loop(eee, &keep_running);

    edge_term(eee);
    tuntap_close(&tuntap);

    return rc;
}
