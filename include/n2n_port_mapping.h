#ifndef _N2N_PORT_MAPPING_H_
#define _N2N_PORT_MAPPING_H_

#include <stdint.h>

#ifdef HAVE_MINIUPNP
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif // HAVE_MINIUPNP


#ifdef HAVE_NATPMP
#include "natpmp.h"
#endif // HAVE_NATPMP


void n2n_chg_port_mapping (struct n2n_edge *eee, const uint16_t port);


#endif // _N2N_PORT_MAPPING_H_
