#ifndef _N2N_PORT_MAPPING_H_
#define _N2N_PORT_MAPPING_H_

#ifdef HAVE_PORT_FORWARDING

#include <stdint.h>

#ifdef HAVE_MINIUPNP
#ifdef CMAKE_BUILD
// CMAKE uses static linked lib as submodule which requires different includes than
//       the dynamically linked, intalled library in case of plain make
#include <miniupnpc.h>
#include <upnpcommands.h>
#include <upnperrors.h>
#else
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif // CMAKE_BUILD
#endif // HAVE_MINIUPNP


#ifdef HAVE_NATPMP
#include "natpmp.h"
#endif // HAVE_NATPMP


void n2n_chg_port_mapping (struct n2n_edge *eee, const uint16_t port);


#endif // HAVE_PORT_FORWARDING
#endif // _N2N_PORT_MAPPING_H_
