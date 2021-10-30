#ifndef _N2N_PORT_MAPPING_H_
#define _N2N_PORT_MAPPING_H_

#include <stdint.h>

#ifdef HAVE_MINIUPNP
// #include <miniupnpc/miniwget.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
// #include <miniupnpc/portlistingparse.h>
#include <miniupnpc/upnperrors.h>

// !!!
// #include "miniupnpcstrings.h"
// is said to equal
//     #define OS_STRING "Windows"
//     #define MINIUPNPC_VERSION_STRING "2.0"
//     #define UPNP_VERSION_STRING "UPnP/1.1"
// but does not seem to be required at all
#endif // HAVE_MINIUPNP


#ifdef HAVE_NATPMP
#include "natpmp.h"
#endif // HAVE_NATPMP


void n2n_set_port_mapping (const uint16_t port);

void n2n_del_port_mapping (const uint16_t port);


#endif // _N2N_PORT_MAPPING_H_
