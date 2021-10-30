#ifdef N2N_HAVE_MINIUPNP

#include "n2n.h"



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

    traceEvent(TRACE_INFO, "list of UPnP devices found on the network:");
    for(device = devlist; device; device = device->pNext) {
        traceEvent(TRACE_INFO, "  desc: %s", device->descURL);
        traceEvent(TRACE_INFO, "    st: %s", device->st);
        traceEvent(TRACE_INFO, "    usn: %s", device->usn);
    }

    ret = UPNP_GetValidIGD(devlist, urls, data, lanaddr, N2N_NETMASK_STR_SIZE);
    if(ret == 0) {
        traceEvent(TRACE_WARNING, "UPnP get valid IGD failed, code %d (%s)", ret, strupnperror(ret));
        freeUPNPDevlist(devlist);
        devlist = NULL;
        return -1;
    }
    freeUPNPDevlist(devlist);
    devlist = NULL;
    traceEvent(TRACE_INFO, "UPnP found valid IGD: %s", urls->controlURL);

    ret = UPNP_GetExternalIPAddress(urls->controlURL,
                                    data->first.servicetype,
                                    externaladdr);
    if(ret != UPNPCOMMAND_SUCCESS) {
        traceEvent(TRACE_WARNING, "UPnP get external ip address failed, code %d (%s)", ret, strupnperror(ret));
    }

    return 0;
}


static int n2n_upnp_get_port_mapping (const struct UPNPUrls *urls, const struct IGDdatas *data, const uint16_t port, const char *proto,
                                      char *lanaddr, char *lanport, char *description, char *enabled, char *duration) {
    int errorcode = 0;
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
        errorcode = -1;
        goto end;
    }

    snprintf(externalport, sizeof(externalport), "%d", port);

    ret = UPNP_GetSpecificPortMappingEntry(urls->controlURL,
                                           data->first.servicetype,
                                           externalport, proto, NULL,
                                           lanaddr, lanport, description,
                                           enabled, duration);
    if(ret != UPNPCOMMAND_SUCCESS) {
        traceEvent(TRACE_WARNING, "UPNP_GetSpecificPortMappingEntry() failed, code %d (%s)", ret, strupnperror(ret));
        errorcode = -1;
        goto end;
    }

    end:
    FreeUPNPUrls(&urls);

    return errorcode;
}


static int n2n_upnp_set_port_mapping(const uint16_t port) {

    int errorcode = 0;
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
        goto end;
    }
    snprintf(lanport, sizeof(lanport), "%d", port);
    memcpy(externalport, lanport, sizeof(externalport));

    ret = n2n_UPNP_GetValidIGD(&urls, &data, lanaddr, externaladdr);
    if(ret != 0) {
        errorcode = -1;
        goto end;
    }

    // TCP port
    ret = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                              externalport, lanport, lanaddr, "n2n-vpn",
                              "TCP", NULL, "0");
    if(ret != UPNPCOMMAND_SUCCESS) {
        traceEvent(TRACE_ERROR, "UPnP local TCP port %s mapping failed, code %d (%s)", lanport, ret, strupnperror(ret));
        errorcode = -1;
    } else
        traceEvent(TRACE_NORMAL, "UPnP added TCP port mapping: %s:%s -> %s:%s", externaladdr, externalport, lanaddr, lanport);

    // UDP port
    ret = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                              externalport, lanport, lanaddr, "n2n-vpn",
                              "UDP", NULL, "0");
    if(ret != UPNPCOMMAND_SUCCESS) {
        traceEvent(TRACE_ERROR, "UPnP local UDP port %s mapping failed, code %d (%s)", lanport, ret, strupnperror(ret));
        errorcode = -1;
    } else
        traceEvent(TRACE_NORMAL, "UPnP added UDP port mapping: %s:%s -> %s:%s", externaladdr, externalport, lanaddr, lanport);

    end:
    FreeUPNPUrls(&urls);

    return errorcode;
}


static int n2n_upnp_del_port_mapping(const uint16_t port) {
    int errorcode = 0;
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
        goto end;
    }
    snprintf(externalport, sizeof(externalport), "%d", port);

    ret = n2n_UPNP_GetValidIGD(&urls, &data, lanaddr, externaladdr);
    if (ret != 0) {
        errorcode = -1;
        goto end;
    }

    // TCP port
    ret = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, externalport, "TCP", NULL);
    if(ret != UPNPCOMMAND_SUCCESS){
        traceEvent(TRACE_ERROR, "UPnP failed to delete TCP port mapping for %s:%s, code %d (%s)", externaladdr, externalport, ret, strupnperror(ret));
        errorcode = -1;
    }
    else
        traceEvent(TRACE_NORMAL, "UPnP deleted TCP port mapping for %s:%s", externaladdr, externalport);

    // UDP port
    ret = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, externalport, "UDP", NULL);
    if(ret != UPNPCOMMAND_SUCCESS){
        traceEvent(TRACE_ERROR, "UPnP failed to delete UDP port mapping for %s:%s, code %d (%s)", externaladdr, externalport, ret, strupnperror(ret));
        errorcode = -1;
    }
    else
        traceEvent(TRACE_NORMAL, "UPnP deleted UDP port mapping for %s:%s", externaladdr, externalport);

    end:
    FreeUPNPUrls(&urls);

    return errorcode;
}


static int n2n_natpmp_initialization(natpmp_t *natpmp, char *lanaddr, char *externaladdr) {
    int errorcode = 0;
    natpmpresp_t response;
    int ret = 0;
    int forcegw = 0;
    in_addr_t gateway = 0;
    struct in_addr gateway_in_use;

    ret = initnatpmp(natpmp, forcegw, gateway);
    if (ret != 0) {
        traceEvent(TRACE_WARNING, "NAT-PMP failed to initialize, code %d", ret);
        errorcode = -1;
        return errorcode;
    }
    gateway_in_use.s_addr = natpmp->gateway;
    traceEvent(TRACE_INFO, "NAT-PMP using gateway: %s", inet_ntoa(gateway_in_use));

    ret = sendpublicaddressrequest(natpmp);
    if (ret != 2) {
        traceEvent(TRACE_WARNING, "NAT-PMP get external ip address failed, code %d", ret);
        errorcode = -1;
        return errorcode;
    }

    ret = readnatpmpresponseorretry(natpmp, &response);
    if (ret != 0) {
        traceEvent(TRACE_WARNING, "NAT-PMP read response failed, code %d", ret);
        errorcode = -1;
        return errorcode;
    }
    if (response.type != NATPMP_RESPTYPE_PUBLICADDRESS) {
        traceEvent(TRACE_WARNING, "NAT-PMP invalid response type %u", response.type);
        errorcode = -1;
        return errorcode;
    }
    snprintf(externaladdr, N2N_NETMASK_STR_SIZE, "%s", inet_ntoa(response.pnu.publicaddress.addr));
    snprintf(lanaddr, N2N_NETMASK_STR_SIZE, "localhost");

    return errorcode;
}


static int n2n_natpmp_port_mapping_request(natpmp_t *natpmp,
                                           const uint16_t port,
                                           const int protocol /* NATPMP_PROTOCOL_TCP or NATPMP_PROTOCOL_UDP */,
                                           const int method /* set:1  del:0 */)
{
    int errorcode = 0;
    natpmpresp_t response;
    int ret = 0;
    uint16_t lanport = 0;
    uint16_t externalport = 0;

    if (port == 0) {
        traceEvent(TRACE_ERROR, "invalid port");
        errorcode = -1;
        return errorcode;
    }
    lanport = port;
    externalport = port;

    ret = sendnewportmappingrequest(natpmp, protocol, lanport, externalport, (method ? -1 : 0));
    if (ret != 12) {
        traceEvent(TRACE_WARNING, "NAT-PMP new port mapping request failed, code %d", ret);
        errorcode = -1;
        return errorcode;
    }

    ret = readnatpmpresponseorretry(natpmp, &response);
    if (ret != 0)
    {
        traceEvent(TRACE_WARNING, "NAT-PMP read response failed, code %d", ret);
        errorcode = -1;
        return errorcode;
    }
    if ((response.type != NATPMP_RESPTYPE_TCPPORTMAPPING) || (response.type != NATPMP_RESPTYPE_UDPPORTMAPPING))
    {
        traceEvent(TRACE_WARNING, "NAT-PMP invalid response type %u", response.type);
        errorcode = -1;
        return errorcode;
    }

    return errorcode;
}


static int n2n_natpmp_set_port_mapping(const uint16_t port) {
    int errorcode = 0;
    natpmp_t natpmp;
    int ret = 0;
    char lanaddr[N2N_NETMASK_STR_SIZE] = {'\0'};
    uint16_t lanport = 0;
    char externaladdr[N2N_NETMASK_STR_SIZE] = {'\0'};
    uint16_t externalport = 0;

    lanport = port;
    externalport = port;

    ret = n2n_natpmp_initialization(&natpmp, lanaddr, externaladdr);
    if (ret != 0) {
        errorcode = -1;
        goto end;
    }

    // TCP port
    ret = n2n_natpmp_port_mapping_request(&natpmp, port, NATPMP_PROTOCOL_TCP, 1);
    if (ret != 0) {
        traceEvent(TRACE_ERROR, "NAT-PMP local TCP port %hu mapping failed", lanport);
        errorcode = -1;
    }
    else
        traceEvent(TRACE_NORMAL, "NAT-PMP added TCP port mapping: %s:%hu -> %s:%hu", externaladdr, externalport, lanaddr, lanport);

    // UDP port
    ret = n2n_natpmp_port_mapping_request(&natpmp, port, NATPMP_PROTOCOL_UDP, 1);
    if (ret != 0) {
        traceEvent(TRACE_ERROR, "NAT-PMP local UDP port %hu mapping failed", lanport);
        errorcode = -1;
    }
    else
        traceEvent(TRACE_NORMAL, "NAT-PMP added UDP port mapping: %s:%hu -> %s:%hu", externaladdr, externalport, lanaddr, lanport);

    end:
    closenatpmp(&natpmp);

    return errorcode;
}


static int n2n_natpmp_del_port_mapping(const uint16_t port) {
    int errorcode = 0;
    natpmp_t natpmp;
    int ret = 0;
    char lanaddr[N2N_NETMASK_STR_SIZE] = {'\0'};
    uint16_t lanport = 0;
    char externaladdr[N2N_NETMASK_STR_SIZE] = {'\0'};
    uint16_t externalport = 0;

    lanport = port;
    externalport = port;

    ret = n2n_natpmp_initialization(&natpmp, lanaddr, externaladdr);
    if (ret != 0) {
        errorcode = -1;
        goto end;
    }

    // TCP port
    ret = n2n_natpmp_port_mapping_request(&natpmp, port, NATPMP_PROTOCOL_TCP, 0);
    if (ret != 0) {
        traceEvent(TRACE_ERROR, "NAT-PMP failed to delete TCP port mapping for %s:%hu", externaladdr, externalport);
        errorcode = -1;
    }
    else
        traceEvent(TRACE_NORMAL, "NAT-PMP deleted TCP port mapping for %s:%hu", externaladdr, externalport);

    // UDP port
    ret = n2n_natpmp_port_mapping_request(&natpmp, port, NATPMP_PROTOCOL_UDP, 0);
    if (ret != 0)  {
        traceEvent(TRACE_ERROR, "NAT-PMP failed to delete UDP port mapping for %s:%hu", externaladdr, externalport);
        errorcode = -1;
    }
    else
        traceEvent(TRACE_NORMAL, "NAT-PMP deleted UDP port mapping for %s:%hu", externaladdr, externalport);

    end:
    closenatpmp(&natpmp);

    return errorcode;
}

// static
// ----------------------------------------------------------------------------------------------------
// public


void n2n_set_port_mapping(const uint16_t port)
{
    int errorcode = 0;
    // since the NAT-PMP protocol is more concise than UPnP, NAT-PMP is preferred.
    errorcode = n2n_natpmp_set_port_mapping(port);
    if (errorcode != 0)
        n2n_upnp_set_port_mapping(port);
}


void n2n_del_port_mapping(const uint16_t port)
{
    int errorcode = 0;
    errorcode = n2n_natpmp_del_port_mapping(port);
    if (errorcode != 0)
        n2n_upnp_del_port_mapping(port);
}






// ----------------------------------------------------------------------------------------------------


N2N_THREAD_RETURN_DATATYPE upnp_thread(N2N_THREAD_PARAMETER_DATATYPE p) {

#ifdef HAVE_PTHREAD
    n2n_upnp_parameter_t *param = (n2n_upnp_parameter_t*)p;

    // !!!
    // - open a new socket and connect to local mgmt port
    // - subscribe to mgmt port for port change events
    // - initialize upnp
    // - loop select/waiting for events
    // - handle events accordingly (delete old port if applicable, set new port)
    return 0; // !!! dummy
#endif
}


int upnp_create_thread (n2n_upnp_parameter_t **param, uint16_t mgmt_port) {

#ifdef HAVE_PTHREAD
    int ret;

    // create parameter structure
    *param = (n2n_upnp_parameter_t*)calloc(1, sizeof(n2n_upnp_parameter_t));
    if(*param) {
        // !!!
        // - initialize values
        (*param)->mgmt_port = mgmt_port;
    } else {
        traceEvent(TRACE_WARNING, "upnp_create_thread was unable to create parameter structure");
        return -1;
    }

    // create thread
    ret = pthread_create(&((*param)->id), NULL, upnp_thread, (void *)*param);
    if(ret) {
        traceEvent(TRACE_WARNING, "upnp_create_thread failed to create upnp thread with error number %d", ret);
        return -1;
    }

    return 0;
#endif
}


void upnp_cancel_thread (n2n_upnp_parameter_t *param) {

#ifdef HAVE_PTHREAD
    pthread_cancel(param->id);
    // !!!
    // - delete old port if applicable
    free(param);
#endif
}











#endif // N2N_HAVE_MINIUPNP
