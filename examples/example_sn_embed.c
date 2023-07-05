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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include <stdbool.h>
#include <stdlib.h>      // for exit
#include "n2n.h"         // for n2n_sn_t, open_socket, run_sn_loop, sn_init

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>  // for INADDR_ANY, INADDR_LOOPBACK
#endif


static bool keep_running = true;

int main () {

        n2n_sn_t sss_node;
        int rc;

        sn_init_defaults(&sss_node);
        sss_node.daemon = 0;   // Whether to daemonize
        sss_node.lport = 1234; // Main UDP listen port

        sss_node.sock = open_socket(sss_node.lport, INADDR_ANY, 0 /* UDP */);
        if(-1 == sss_node.sock) {
            exit(-2);
        }

        sss_node.mgmt_sock = open_socket(5645, INADDR_LOOPBACK, 0 /* UDP */); // Main UDP management port
        if(-1 == sss_node.mgmt_sock) {
            exit(-2);
        }

        sn_init(&sss_node);

        sss_node.keep_running = &keep_running;
        rc = run_sn_loop(&sss_node);

        sn_term(&sss_node);

        return rc;
}
