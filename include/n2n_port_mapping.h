#ifndef _N2N_PORT_MAPPING_H_
#define _N2N_PORT_MAPPING_H_

#include <stdint.h>

#include "miniwget.h"
#include "miniupnpc.h"
#include "upnpcommands.h"
#include "portlistingparse.h"
#include "upnperrors.h"
#include "miniupnpcstrings.h"

#include "natpmp.h"




void n2n_set_port_mapping (const uint16_t port);

void n2n_del_port_mapping (const uint16_t port);


#endif // _N2N_PORT_MAPPING_H_
