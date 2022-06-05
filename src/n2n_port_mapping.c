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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


// This file contains code taken from MiniUPnPc and natpmp found at
// https://github.com/miniupnp/miniupnp/  or
// https://github.com/miniupnp/natpmp/    respectively
// both as of October 2021


/**
 * MiniUPnPc
 * Copyright (c) 2005-2021, Thomas BERNARD
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 *     * The name of the author may not be used to endorse or promote products
 * 	  derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "n2n.h"


#ifdef HAVE_MINIUPNP


#if 0 /* unused code */
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
#endif // unused code


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
    if((error != UPNPDISCOVER_SUCCESS) || (devlist == NULL) ) {
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


#if 0 /* unused code */
static int n2n_upnp_get_port_mapping (struct UPNPUrls *urls, const struct IGDdatas *data, const uint16_t port, const char *proto,
                                      char *lanaddr, char *lanport, char *description, char *enabled, char *duration) {

    int errorcode = 0;
    // struct UPNPUrls urls;
    // struct IGDdatas data;
    // char lanaddr[N2N_NETMASK_STR_SIZE] = {'\0'};
    // char lanport[6] = {'\0'};
    // char externaladdr[N2N_NETMASK_STR_SIZE] = {'\0'};
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
    FreeUPNPUrls(urls);

    return errorcode;
}
#endif // unused code


static int n2n_upnp_set_port_mapping (const uint16_t port) {

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
        traceEvent(TRACE_WARNING, "UPnP local TCP port %s mapping failed, code %d (%s)", lanport, ret, strupnperror(ret));
        errorcode = -1;
    } else
        traceEvent(TRACE_NORMAL, "UPnP added TCP port mapping: %s:%s -> %s:%s", externaladdr, externalport, lanaddr, lanport);

    // UDP port
    ret = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                              externalport, lanport, lanaddr, "n2n-vpn",
                              "UDP", NULL, "0");
    if(ret != UPNPCOMMAND_SUCCESS) {
        traceEvent(TRACE_WARNING, "UPnP local UDP port %s mapping failed, code %d (%s)", lanport, ret, strupnperror(ret));
        errorcode = -1;
    } else
        traceEvent(TRACE_NORMAL, "UPnP added UDP port mapping: %s:%s -> %s:%s", externaladdr, externalport, lanaddr, lanport);

    FreeUPNPUrls(&urls);

    return errorcode;
}


static int n2n_upnp_del_port_mapping (const uint16_t port) {

    int errorcode = 0;
    struct UPNPUrls urls;
    struct IGDdatas data;
    char lanaddr[N2N_NETMASK_STR_SIZE] = {'\0'};
    // char lanport[6] = {'\0'};
    char externaladdr[N2N_NETMASK_STR_SIZE] = {'\0'};
    char externalport[6] = {'\0'};
    int ret = 0;

    if(port == 0) {
        traceEvent(TRACE_ERROR, "invalid port");
        errorcode = -1;
        return errorcode;
    }
    snprintf(externalport, sizeof(externalport), "%d", port);

    ret = n2n_UPNP_GetValidIGD(&urls, &data, lanaddr, externaladdr);
    if(ret != 0) {
        errorcode = -1;
        return errorcode;
    }

    // TCP port
    ret = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, externalport, "TCP", NULL);
    if(ret != UPNPCOMMAND_SUCCESS) {
        traceEvent(TRACE_WARNING, "UPnP failed to delete TCP port mapping for %s:%s, code %d (%s)", externaladdr, externalport, ret, strupnperror(ret));
        errorcode = -1;
    } else
        traceEvent(TRACE_NORMAL, "UPnP deleted TCP port mapping for %s:%s", externaladdr, externalport);

    // UDP port
    ret = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, externalport, "UDP", NULL);
    if(ret != UPNPCOMMAND_SUCCESS) {
        traceEvent(TRACE_WARNING, "UPnP failed to delete UDP port mapping for %s:%s, code %d (%s)", externaladdr, externalport, ret, strupnperror(ret));
        errorcode = -1;
    } else
        traceEvent(TRACE_NORMAL, "UPnP deleted UDP port mapping for %s:%s", externaladdr, externalport);

    FreeUPNPUrls(&urls);

    return errorcode;
}

#endif // HAVE_MINIUPNP


// ----------------------------------------------------------------------------------------------------


#ifdef HAVE_NATPMP

static int n2n_natpmp_initialization (natpmp_t *natpmp, char *lanaddr, char *externaladdr) {

    int errorcode = 0;
    natpmpresp_t response;
    int ret = 0;
    int forcegw = 0;
    in_addr_t gateway = 0;
    struct in_addr gateway_in_use;
    struct timeval timeout;
    fd_set fds;

    ret = initnatpmp(natpmp, forcegw, gateway);
    if(ret != 0) {
        traceEvent(TRACE_WARNING, "NAT-PMP failed to initialize, code %d", ret);
        errorcode = -1;
        return errorcode;
    }
    gateway_in_use.s_addr = natpmp->gateway;
    traceEvent(TRACE_INFO, "NAT-PMP using gateway: %s", inet_ntoa(gateway_in_use));

    ret = sendpublicaddressrequest(natpmp);
    if(ret != 2) {
        traceEvent(TRACE_WARNING, "NAT-PMP get external ip address failed, code %d", ret);
        closenatpmp(natpmp);
        errorcode = -1;
        return errorcode;
    }

    do
    {
        FD_ZERO(&fds);
        FD_SET(natpmp->s, &fds);
        getnatpmprequesttimeout(natpmp, &timeout);
        select(FD_SETSIZE, &fds, NULL, NULL, &timeout);
        ret = readnatpmpresponseorretry(natpmp, &response);
        traceEvent(TRACE_INFO, "NAT-PMP read response returned %d (%s)", ret, ret == 0 ? "OK" : (ret == NATPMP_TRYAGAIN ? "TRY AGAIN" : "FAILED"));
    } while (ret == NATPMP_TRYAGAIN);

    if(response.type != NATPMP_RESPTYPE_PUBLICADDRESS) {
        traceEvent(TRACE_WARNING, "NAT-PMP invalid response type %u", response.type);
        closenatpmp(natpmp);
        errorcode = -1;
        return errorcode;
    }
    snprintf(externaladdr, N2N_NETMASK_STR_SIZE, "%s", inet_ntoa(response.pnu.publicaddress.addr));
    snprintf(lanaddr, N2N_NETMASK_STR_SIZE, "localhost");

    return errorcode;
}


static int n2n_natpmp_port_mapping_request (natpmp_t *natpmp,
                                            const uint16_t port,
                                            const int protocol /* NATPMP_PROTOCOL_TCP or NATPMP_PROTOCOL_UDP */,
                                            const int method /* set:1  del:0 */) {

    int errorcode = 0;
    natpmpresp_t response;
    int ret = 0;
    uint16_t lanport = 0;
    uint16_t externalport = 0;
    struct timeval timeout;
    fd_set fds;

    if(port == 0) {
        traceEvent(TRACE_ERROR, "invalid port");
        errorcode = -1;
        return errorcode;
    }
    lanport = port;
    externalport = port;

    ret = sendnewportmappingrequest(natpmp, protocol, lanport, externalport, (method ? 31104000 /* lifetime 360 days*/ : 0));
    if(ret != 12) {
        traceEvent(TRACE_WARNING, "NAT-PMP new port mapping request failed, code %d", ret);
        errorcode = -1;
        return errorcode;
    }

    do
    {
        FD_ZERO(&fds);
        FD_SET(natpmp->s, &fds);
        getnatpmprequesttimeout(natpmp, &timeout);
        select(FD_SETSIZE, &fds, NULL, NULL, &timeout);
        ret = readnatpmpresponseorretry(natpmp, &response);
        traceEvent(TRACE_INFO, "NAT-PMP read response returned %d (%s)", ret, ret == 0 ? "OK" : (ret == NATPMP_TRYAGAIN ? "TRY AGAIN" : "FAILED"));
    } while (ret == NATPMP_TRYAGAIN);

    if(!((response.type == NATPMP_RESPTYPE_TCPPORTMAPPING) || (response.type == NATPMP_RESPTYPE_UDPPORTMAPPING))) {
        traceEvent(TRACE_WARNING, "NAT-PMP invalid response type %u", response.type);
        errorcode = -1;
        return errorcode;
    }

    return errorcode;
}


static int n2n_natpmp_set_port_mapping (const uint16_t port) {

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
    if(ret != 0) {
        errorcode = -1;
        return errorcode;
    }

    // TCP port
    ret = n2n_natpmp_port_mapping_request(&natpmp, port, NATPMP_PROTOCOL_TCP, 1);
    if(ret != 0) {
        traceEvent(TRACE_WARNING, "NAT-PMP local TCP port %hu mapping failed", lanport);
        errorcode = -1;
    } else
        traceEvent(TRACE_NORMAL, "NAT-PMP added TCP port mapping: %s:%hu -> %s:%hu", externaladdr, externalport, lanaddr, lanport);

    // UDP port
    ret = n2n_natpmp_port_mapping_request(&natpmp, port, NATPMP_PROTOCOL_UDP, 1);
    if(ret != 0) {
        traceEvent(TRACE_WARNING, "NAT-PMP local UDP port %hu mapping failed", lanport);
        errorcode = -1;
    } else
        traceEvent(TRACE_NORMAL, "NAT-PMP added UDP port mapping: %s:%hu -> %s:%hu", externaladdr, externalport, lanaddr, lanport);

    closenatpmp(&natpmp);

    return errorcode;
}


static int n2n_natpmp_del_port_mapping (const uint16_t port) {

    int errorcode = 0;
    natpmp_t natpmp;
    int ret = 0;
    char lanaddr[N2N_NETMASK_STR_SIZE] = {'\0'};
    // uint16_t lanport = 0;
    char externaladdr[N2N_NETMASK_STR_SIZE] = {'\0'};
    uint16_t externalport = 0;

    // lanport = port;
    externalport = port;

    ret = n2n_natpmp_initialization(&natpmp, lanaddr, externaladdr);
    if(ret != 0) {
        errorcode = -1;
        return errorcode;
    }

    // TCP port
    ret = n2n_natpmp_port_mapping_request(&natpmp, port, NATPMP_PROTOCOL_TCP, 0);
    if(ret != 0) {
        traceEvent(TRACE_WARNING, "NAT-PMP failed to delete TCP port mapping for %s:%hu", externaladdr, externalport);
        errorcode = -1;
    } else
        traceEvent(TRACE_NORMAL, "NAT-PMP deleted TCP port mapping for %s:%hu", externaladdr, externalport);

    // UDP port
    ret = n2n_natpmp_port_mapping_request(&natpmp, port, NATPMP_PROTOCOL_UDP, 0);
    if(ret != 0)  {
        traceEvent(TRACE_WARNING, "NAT-PMP failed to delete UDP port mapping for %s:%hu", externaladdr, externalport);
        errorcode = -1;
    } else
        traceEvent(TRACE_NORMAL, "NAT-PMP deleted UDP port mapping for %s:%hu", externaladdr, externalport);

    closenatpmp(&natpmp);

    return errorcode;
}

#endif // HAVE_NATPMP


// static
// ----------------------------------------------------------------------------------------------------
// public


void n2n_set_port_mapping (const uint16_t port) {

#ifdef HAVE_NATPMP
    // since the NAT-PMP protocol is more concise than UPnP, NAT-PMP is preferred.
    if(n2n_natpmp_set_port_mapping(port))
#endif // HAVE_NATPMP
    {
#ifdef HAVE_MINIUPNP
        n2n_upnp_set_port_mapping(port);
#endif // HAVE_MINIUPNP
    }
}


void n2n_del_port_mapping (const uint16_t port) {

#ifdef HAVE_NATPMP
    if(n2n_natpmp_del_port_mapping(port))
#endif // HAVE_NATPMP
    {
#ifdef HAVE_MINIUPNP
        n2n_upnp_del_port_mapping(port);
#endif // HAVE_MINIUPNP
    }
}
