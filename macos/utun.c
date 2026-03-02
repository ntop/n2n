/**
 * (C) 2007-21 - ntop.org and contributors
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

#ifdef __APPLE__

#include "n2n.h"
#include "utun.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>


static int parse_utun_unit (const char *name) {

    int unit;

    if(!name || name[0] == '\0')
        return 0;

    if(strncmp(name, "utun", 4) != 0)
        return 0;

    if(name[4] == '\0')
        return 0;

    unit = atoi(&name[4]);
    /* sc_unit is 1-indexed: utun0 = unit 1, utun5 = unit 6 */
    return unit + 1;
}


int utun_open (char *dev_name, size_t dev_name_size, const char *requested_name) {

    int fd;
    struct ctl_info ctlInfo;
    struct sockaddr_ctl sc;
    socklen_t ifname_len;

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if(fd < 0) {
        traceEvent(TRACE_ERROR, "socket(PF_SYSTEM) failed [%d]: %s", errno, strerror(errno));
        return -1;
    }

    memset(&ctlInfo, 0, sizeof(ctlInfo));
    strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name));

    if(ioctl(fd, CTLIOCGINFO, &ctlInfo) < 0) {
        traceEvent(TRACE_ERROR, "ioctl(CTLIOCGINFO) for %s failed [%d]: %s",
                   UTUN_CONTROL_NAME, errno, strerror(errno));
        close(fd);
        return -1;
    }

    memset(&sc, 0, sizeof(sc));
    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;

    /* try requested unit first, fall back to auto-assign */
    sc.sc_unit = parse_utun_unit(requested_name);

    if(sc.sc_unit > 0) {
        if(connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
            traceEvent(TRACE_WARNING, "requested interface %s is busy, auto-assigning",
                       requested_name);
            sc.sc_unit = 0;
        }
    }

    if(sc.sc_unit == 0) {
        if(connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
            traceEvent(TRACE_ERROR, "connect(utun) failed [%d]: %s", errno, strerror(errno));
            close(fd);
            return -1;
        }
    }

    ifname_len = (socklen_t)dev_name_size;
    if(getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, dev_name, &ifname_len) < 0) {
        traceEvent(TRACE_ERROR, "getsockopt(UTUN_OPT_IFNAME) failed [%d]: %s",
                   errno, strerror(errno));
        close(fd);
        return -1;
    }

    traceEvent(TRACE_NORMAL, "opened utun device %s (fd=%d)", dev_name, fd);
    return fd;
}


int utun_configure (const char *dev_name, const char *ip, const char *netmask, int mtu) {

    char cmd[256];
    int rc;
    struct in_addr addr, mask, net;

    if(!dev_name || !ip || !netmask)
        return -1;

    /*
     * utun is POINTOPOINT and requires a destination address. If we set
     * dest == local, macOS routes our own IP through the utun fd instead
     * of delivering via loopback. Use a different address as the P2P
     * "gateway" so local traffic stays local.
     */
    {
        struct in_addr gw_addr;
        uint32_t net_h, mask_h, ip_h, last_host, first_host, gw_h;
        char gw_str[INET_ADDRSTRLEN];

        inet_pton(AF_INET, ip, &addr);
        inet_pton(AF_INET, netmask, &mask);

        ip_h = ntohl(addr.s_addr);
        mask_h = ntohl(mask.s_addr);
        net_h = ip_h & mask_h;
        last_host = (net_h | ~mask_h) - 1;   /* e.g. 10.88.0.254 for /24 */
        first_host = net_h + 1;               /* e.g. 10.88.0.1 for /24 */

        gw_h = (last_host != ip_h) ? last_host : first_host;
        gw_addr.s_addr = htonl(gw_h);
        inet_ntop(AF_INET, &gw_addr, gw_str, sizeof(gw_str));

        snprintf(cmd, sizeof(cmd), "ifconfig %s inet %s %s netmask %s mtu %d up",
                 dev_name, ip, gw_str, netmask, mtu);
    }

    traceEvent(TRACE_NORMAL, "configuring interface: %s", cmd);
    rc = system(cmd);

    if(rc != 0) {
        traceEvent(TRACE_ERROR, "interface configuration failed (rc=%d): %s", rc, cmd);
        return -1;
    }

    /*
     * Add an explicit subnet route through the utun interface.
     * Point-to-point interfaces may not auto-create subnet routes.
     */
    if(inet_pton(AF_INET, ip, &addr) == 1 && inet_pton(AF_INET, netmask, &mask) == 1) {
        int cidr = 0;
        uint32_t m = ntohl(mask.s_addr);
        while(m & 0x80000000) { cidr++; m <<= 1; }

        net.s_addr = addr.s_addr & mask.s_addr;
        snprintf(cmd, sizeof(cmd), "route -n add -net %s/%d -interface %s",
                 inet_ntoa(net), cidr, dev_name);

        traceEvent(TRACE_NORMAL, "adding subnet route: %s", cmd);
        rc = system(cmd);
        if(rc != 0) {
            traceEvent(TRACE_WARNING, "subnet route add failed (rc=%d), may already exist", rc);
        }
    }

    traceEvent(TRACE_NORMAL, "configured %s: %s netmask %s mtu %d", dev_name, ip, netmask, mtu);
    return 0;
}


void utun_close (int fd) {

    if(fd >= 0)
        close(fd);
}

#endif /* __APPLE__ */
