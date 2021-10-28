#ifndef _N2N_UPNPC_H_
#define _N2N_UPNPC_H_


#include <stdint.h>


#ifdef N2N_HAVE_MINIUPNP
// include only if actually wanted (and present)
#include "miniwget.h"
#include "miniupnpc.h"
#include "upnpcommands.h"
#include "portlistingparse.h"
#include "upnperrors.h"
#include "miniupnpcstrings.h"

#endif // N2N_HAVE_MINIUPNP


typedef struct IGDdatas IGdatas;
typedef struct UPNPUrls UPNPUrls;


int n2n_upnp_set_port_mapping (const uint16_t port);

void n2n_upnp_del_port_mapping (const uint16_t port);


#endif // _N2N_UPNPC_H_
