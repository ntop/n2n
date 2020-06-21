#include "n2n.h"

static int keep_running;

int main()
{
    n2n_sn_t sss_node;
    int rc;

    sn_init(&sss_node);
    sss_node.daemon = 0;   // Whether to daemonize
    sss_node.lport = 1234; // Main UDP listen port

    sss_node.sock = open_socket(sss_node.lport, 1);
    if (-1 == sss_node.sock)
    {
        exit(-2);
    }

    sss_node.mgmt_sock = open_socket(5645, 0); // Main UDP management port
    if (-1 == sss_node.mgmt_sock)
    {
        exit(-2);
    }

    keep_running = 1;
    rc = run_sn_loop(&sss_node, &keep_running);

    sn_term(&sss_node);

    return rc;
}