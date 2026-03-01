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


#include "n2n.h"


#ifdef __APPLE__

#include "utun.h"
#include "arp.h"

#include <sys/uio.h>
#include <ifaddrs.h>


int tuntap_open (tuntap_dev *device,
                 char *dev,
                 const char *address_mode,
                 char *device_ip,
                 char *device_mask,
                 const char *device_mac,
                 int mtu) {

    device->fd = utun_open(device->dev_name, sizeof(device->dev_name), dev);
    if(device->fd < 0) {
        traceEvent(TRACE_ERROR, "failed to open utun device");
        return -1;
    }

    /* virtual MAC for the n2n wire protocol (utun has no real MAC) */
    if(device_mac && device_mac[0] != '\0') {
        int a, b, c, d, e, f;
        if(sscanf(device_mac, "%02x:%02x:%02x:%02x:%02x:%02x", &a, &b, &c, &d, &e, &f) == 6) {
            device->mac_addr[0] = a;
            device->mac_addr[1] = b;
            device->mac_addr[2] = c;
            device->mac_addr[3] = d;
            device->mac_addr[4] = e;
            device->mac_addr[5] = f;
        } else {
            traceEvent(TRACE_WARNING, "invalid MAC address format, generating random MAC");
            memrnd(device->mac_addr, 6);
            device->mac_addr[0] = 0xFE;
            device->mac_addr[0] &= ~0x01; /* unicast */
            device->mac_addr[0] |= 0x02;  /* locally administered */
        }
    } else {
        memrnd(device->mac_addr, 6);
        device->mac_addr[0] = 0xFE;
        device->mac_addr[0] &= ~0x01;
        device->mac_addr[0] |= 0x02;
    }

    device->ip_addr = inet_addr(device_ip);
    device->device_mask = inet_addr(device_mask);
    device->mtu = mtu;

#ifdef __APPLE__
    device->edge_context = NULL;
#endif

    if(utun_configure(device->dev_name, device_ip, device_mask, mtu) < 0) {
        traceEvent(TRACE_ERROR, "failed to configure utun device %s", device->dev_name);
        close(device->fd);
        return -1;
    }

    arp_cache_init();

    traceEvent(TRACE_NORMAL, "utun device %s opened successfully (fd=%d)", device->dev_name, device->fd);
    traceEvent(TRACE_NORMAL, "virtual MAC: %02x:%02x:%02x:%02x:%02x:%02x",
               device->mac_addr[0], device->mac_addr[1], device->mac_addr[2],
               device->mac_addr[3], device->mac_addr[4], device->mac_addr[5]);

    return device->fd;
}


int tuntap_read (struct tuntap_dev *tuntap, unsigned char *buf, int len) {

    unsigned char readbuf[N2N_PKT_BUF_SIZE + 4];
    ssize_t nread;
    uint32_t af_family;
    uint16_t ether_type;
    ether_hdr_t eh;
    int total;

    do {
        nread = read(tuntap->fd, readbuf, sizeof(readbuf));
    } while(nread < 0 && errno == EINTR);

    if(nread <= 4)
        return -1;

    memcpy(&af_family, readbuf, 4);
    af_family = ntohl(af_family);

    if(af_family == AF_INET)
        ether_type = htons(0x0800);
    else if(af_family == AF_INET6)
        ether_type = htons(0x86DD);
    else
        return -1;

    memset(&eh, 0, sizeof(eh));
    memcpy(eh.shost, tuntap->mac_addr, ETH_ADDR_LEN);
    eh.type = ether_type;

    if(af_family == AF_INET && nread >= (4 + IP4_MIN_SIZE)) {
        uint32_t dst_ip;
        memcpy(&dst_ip, readbuf + 4 + IP4_DSTOFFSET, 4);
        ip_to_dest_mac(dst_ip, tuntap->device_mask, eh.dhost);
    } else if(af_family == AF_INET6 && nread >= (4 + 40)) {
        ipv6_to_dest_mac(readbuf + 4, eh.dhost);
    } else {
        memset(eh.dhost, 0xFF, ETH_ADDR_LEN);
    }

    total = (int)(sizeof(ether_hdr_t) + (nread - 4));
    if(total > len)
        return -1;

    memcpy(buf, &eh, sizeof(ether_hdr_t));
    memcpy(buf + sizeof(ether_hdr_t), readbuf + 4, nread - 4);

    return total;
}


int tuntap_write (struct tuntap_dev *tuntap, unsigned char *buf, int len) {

    ether_hdr_t eh;
    uint16_t ether_type;
    uint32_t af_family;
    ssize_t nwritten;
    struct iovec iov[2];

    if(len < (int)sizeof(ether_hdr_t))
        return -1;

    memcpy(&eh, buf, sizeof(ether_hdr_t));
    ether_type = ntohs(eh.type);

    /* learn source MAC <-> source IP from incoming IPv4 packets */
    if(ether_type == 0x0800 && len >= (int)(sizeof(ether_hdr_t) + IP4_MIN_SIZE)) {
        uint32_t src_ip;
        memcpy(&src_ip, buf + sizeof(ether_hdr_t) + IP4_SRCOFFSET, 4);
        arp_cache_update(src_ip, eh.shost);
    }

    /* ARP packets are handled internally, never written to utun */
    if(ether_type == 0x0806)
        return arp_handle_packet(tuntap, buf, len);

    /* silently consume non-IP protocols */
    if(ether_type != 0x0800 && ether_type != 0x86DD)
        return len;

    if(ether_type == 0x0800)
        af_family = htonl(AF_INET);
    else
        af_family = htonl(AF_INET6);

    iov[0].iov_base = &af_family;
    iov[0].iov_len = 4;
    iov[1].iov_base = buf + sizeof(ether_hdr_t);
    iov[1].iov_len = len - sizeof(ether_hdr_t);

    do {
        nwritten = writev(tuntap->fd, iov, 2);
    } while(nwritten < 0 && errno == EINTR);

    if(nwritten < 0)
        return -1;

    /* return original frame size so caller's size check passes */
    return len;
}


void tuntap_close (struct tuntap_dev *tuntap) {

    arp_cache_destroy();
    utun_close(tuntap->fd);
}


void tuntap_get_address (struct tuntap_dev *tuntap) {

    struct ifaddrs *ifap, *ifa;

    if(getifaddrs(&ifap) != 0)
        return;

    for(ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if(ifa->ifa_addr &&
           ifa->ifa_addr->sa_family == AF_INET &&
           strcmp(ifa->ifa_name, tuntap->dev_name) == 0) {
            tuntap->ip_addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
            break;
        }
    }

    freeifaddrs(ifap);
}


#endif /* __APPLE__ */
