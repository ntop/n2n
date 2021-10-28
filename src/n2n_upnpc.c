

#include "n2n.h"


#ifdef N2N_HAVE_MINIUPNP

/* protofix() checks if protocol is "UDP" or "TCP"
 * returns NULL if not */
static const char *protofix (const char *proto) {

    int i, b;
    const char proto_tcp[4] = {'T', 'C', 'P', 0};
    const char proto_udp[4] = {'U', 'D', 'P', 0};

    for(i = 0, b = 1; i < 4; i++)
        b = b && ((proto[i] == proto_tcp[i]) || (proto[i] == (proto_tcp[i] | 32)));
    if(b)
        return proto;
    for(i = 0, b = 1; i < 4; i++)
        b = b && ((proto[i] == proto_udp[i]) || (proto[i] == (proto_udp[i] | 32)));
    if(b)
        return proto;

    return NULL;
}



static int n2n_UPNP_GetValidIGD (struct UPNPUrls *urls, struct IGDdatas *data, char *lanaddr, char *externaladdr) {

    struct UPNPDev *devlist = NULL;
    struct UPNPDev *device = NULL;
    int delay = 2000;
    const char *multicastif = NULL;
    const char *minissdpdpath = NULL;
    int localport = UPNP_LOCAL_PORT_ANY;
    int ipv6 = 0;
    unsigned char ttl = 2; /* defaulting to 2 */
    int error = 0;
    int ret = 0;

    devlist = upnpDiscover(delay, multicastif, minissdpdpath, localport, ipv6, ttl, &error);
    if(error != UPNPDISCOVER_SUCCESS) {
        traceEvent(TRACE_WARNING, "no IGD UPnP device found on the network");
        return -1;
    }

    traceEvent(TRACE_INFO, "list of UPNP devices found on the network:");
    for(device = devlist; device; device = device->pNext) {
        traceEvent(TRACE_INFO, "  desc: %s", device->descURL);
        traceEvent(TRACE_INFO, "    st: %s", device->st);
        traceEvent(TRACE_INFO, "    usn: %s", device->usn);
    }

    ret = UPNP_GetValidIGD(devlist, urls, data, lanaddr, N2N_NETMASK_STR_SIZE);
    if(ret == 0) {
        traceEvent(TRACE_WARNING, "UPNP get valid IGD failed, code %d (%s)", ret, strupnperror(ret));
        freeUPNPDevlist(devlist);
        devlist = NULL;
        return -1;
    }
    freeUPNPDevlist(devlist);
    devlist = NULL;
    traceEvent(TRACE_INFO, "found valid IGD: %s", urls->controlURL);

    ret = UPNP_GetExternalIPAddress(urls->controlURL,
                                    data->first.servicetype,
                                    externaladdr);
    if(ret != UPNPCOMMAND_SUCCESS) {
        traceEvent(TRACE_WARNING, "get external ip address failed, code %d (%s)", ret, strupnperror(ret));
    }

    return 0;
}


static int n2n_upnp_get_port_mapping (const struct UPNPUrls *urls, const struct IGDdatas *data, const uint16_t port, const char *proto,
                                      char *lanaddr, char *lanport, char *description, char *enabled, char *duration) {
    // struct UPNPUrls urls;
    // struct IGDdatas data;
    // char lanaddr[N2N_NETMASK_STR_SIZE] = {'\0'};
    // char lanport[6] = {'\0'};
    char externaladdr[N2N_NETMASK_STR_SIZE] = {'\0'};
    char externalport[6] = {'\0'};
    // char description[64] = {'\0'};
    // char enabled[16] = {'\0'};
    // char duration[16] = {'\0'};
    int ret = 0;

    proto = protofix(proto);
    if(!proto) {
        traceEvent(TRACE_ERROR, "invalid protocol");
        return -1;
    }

    snprintf(externalport, sizeof(externalport), "%d", port);

    ret = UPNP_GetSpecificPortMappingEntry(urls->controlURL,
                                           data->first.servicetype,
                                           externalport, proto, NULL,
                                           lanaddr, lanport, description,
                                           enabled, duration);
    if(ret != UPNPCOMMAND_SUCCESS) {
        traceEvent(TRACE_WARNING, "UPNP_GetSpecificPortMappingEntry() failed, code %d (%s)", ret, strupnperror(ret));
        return -1;
    }

    return 0;
}

#endif // N2N_HAVE_MINIUPNP


// static
// ----------------------------------------------------------------------------------------------------
// public


int n2n_upnp_set_port_mapping (const uint16_t port) {

    int errorcode = 0;
#ifdef N2N_HAVE_MINIUPNP
    struct UPNPUrls urls;
    struct IGDdatas data;
    char lanaddr[N2N_NETMASK_STR_SIZE] = {'\0'};
    char lanport[6] = {'\0'};
    char externaladdr[N2N_NETMASK_STR_SIZE] = {'\0'};
    char externalport[6] = {'\0'};
    int ret = 0;

    if(port == 0) {
        traceEvent(TRACE_ERROR, "invalid port");
        errorcode = -1;
        return errorcode;
    }
    snprintf(lanport, sizeof(lanport), "%d", port);
    memcpy(externalport, lanport, sizeof(externalport));

    ret = n2n_UPNP_GetValidIGD(&urls, &data, lanaddr, externaladdr);
    if(ret != 0) {
        errorcode = -1;
        return errorcode;
    }

    // TCP port
    ret = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                              externalport, lanport, lanaddr, "n2n-vpn",
                              "TCP", NULL, "0");
    if(ret != UPNPCOMMAND_SUCCESS) {
        traceEvent(TRACE_ERROR, "local TCP port %s mapping failed, code %d (%s)", lanport, ret, strupnperror(ret));
        errorcode = -1;
    } else
        traceEvent(TRACE_NORMAL, "added TCP port mapping: %s:%s -> %s:%s", externaladdr, externalport, lanaddr, lanport);

    // UDP port
    ret = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                              externalport, lanport, lanaddr, "n2n-vpn",
                              "UDP", NULL, "0");
    if(ret != UPNPCOMMAND_SUCCESS) {
        traceEvent(TRACE_ERROR, "local UDP port %s mapping failed, code %d (%s)", lanport, ret, strupnperror(ret));
        errorcode = -1;
    } else
        traceEvent(TRACE_NORMAL, "added UDP port mapping: %s:%s -> %s:%s", externaladdr, externalport, lanaddr, lanport);

    FreeUPNPUrls(&urls);
#endif // N2N_HAVE_MINIUPNP

    return errorcode;
}


void n2n_upnp_del_port_mapping (const uint16_t port) {

#ifdef N2N_HAVE_MINIUPNP
    struct UPNPUrls urls;
    struct IGDdatas data;
    char lanaddr[N2N_NETMASK_STR_SIZE] = {'\0'};
    char lanport[6] = {'\0'};
    char externaladdr[N2N_NETMASK_STR_SIZE] = {'\0'};
    char externalport[6] = {'\0'};
    int ret = 0;

    if(port == 0) {
        traceEvent(TRACE_ERROR, "invalid port");
        return;
    }
    snprintf(externalport, sizeof(externalport), "%d", port);

    ret = n2n_UPNP_GetValidIGD(&urls, &data, lanaddr, externaladdr);
    if(ret != 0)
        return;


    // TCP port
    ret = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, externalport, "TCP", NULL);
    if(ret != UPNPCOMMAND_SUCCESS)
        traceEvent(TRACE_ERROR, "failed to delete TCP port mapping for %s:%s, code %d (%s)", externaladdr, externalport, ret, strupnperror(ret));
    else
        traceEvent(TRACE_NORMAL, "deleted TCP port mapping for %s:%s", externaladdr, externalport);

    // UDP port
    ret = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, externalport, "UDP", NULL);
    if(ret != UPNPCOMMAND_SUCCESS)
        traceEvent(TRACE_ERROR, "failed to delete UDP port mapping for %s:%s, code %d (%s)", externaladdr, externalport, ret, strupnperror(ret));
    else
        traceEvent(TRACE_NORMAL, "deleted UDP port mapping for %s:%s", externaladdr, externalport);

    FreeUPNPUrls(&urls);
#endif // N2N_HAVE_MINIUPNP

    return;
}



