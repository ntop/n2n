/**
 * (C) 2007-18 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#include "n2n.h"

#ifdef __linux__

#include <net/if_arp.h>

/* *************************************************** */

static void read_mac(char *ifname, n2n_mac_t mac_addr) {
  int _sock, res;
  struct ifreq ifr;
  macstr_t mac_addr_buf;

  memset (&ifr,0,sizeof(struct ifreq));

  /* Dummy socket, just to make ioctls with */
  _sock=socket(PF_INET, SOCK_DGRAM, 0);
  strcpy(ifr.ifr_name, ifname);
  res = ioctl(_sock,SIOCGIFHWADDR,&ifr);
  
  if(res < 0) {
    perror ("Get hw addr");
    traceEvent(TRACE_ERROR, "Unable to read interfce %s MAC", ifname);
  } else
    memcpy(mac_addr, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);

  traceEvent(TRACE_NORMAL, "Interface %s has MAC %s",
	     ifname,
	     macaddr_str(mac_addr_buf, mac_addr ));
  close(_sock);
}

/* ********************************** */

static int setup_ifname(int fd, const char *ifname, const char *ipaddr,
          const char *netmask, const char *mac, int mtu) {
  struct ifreq ifr;

  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  ifr.ifr_name[IFNAMSIZ-1] = '\0';

  if(mac && mac[0]) {
    str2mac((uint8_t *)ifr.ifr_hwaddr.sa_data, mac);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

    if(ioctl(fd, SIOCSIFHWADDR, &ifr) == -1) {
      traceEvent(TRACE_ERROR, "ioctl(SIOCSIFHWADDR) failed [%d]: %s", errno, strerror(errno));
      return(-1);
    }
  }

  ifr.ifr_addr.sa_family = AF_INET;

  /* Interface Address */
  inet_pton(AF_INET, ipaddr, &((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
  if(ioctl(fd, SIOCSIFADDR, &ifr) == -1) {
    traceEvent(TRACE_ERROR, "ioctl(SIOCSIFADDR) failed [%d]: %s", errno, strerror(errno));
    return(-2);
  }

  /* Netmask */
  if(netmask && (((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr != 0)) {
    inet_pton(AF_INET, netmask, &((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
    if(ioctl(fd, SIOCSIFNETMASK, &ifr) == -1) {
      traceEvent(TRACE_ERROR, "ioctl(SIOCSIFNETMASK, %s) failed [%d]: %s", netmask, errno, strerror(errno));
      return(-3);
    }
  }

  /* MTU */
  ifr.ifr_mtu = mtu;
  if(ioctl(fd, SIOCSIFMTU, &ifr) == -1) {
    traceEvent(TRACE_ERROR, "ioctl(SIOCSIFMTU) failed [%d]: %s", errno, strerror(errno));
    return(-4);
  }

  /* Set up and running */
  if(ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
    traceEvent(TRACE_ERROR, "ioctl(SIOCGIFFLAGS) failed [%d]: %s", errno, strerror(errno));
    return(-5);
  }

  ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

  if(ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
    traceEvent(TRACE_ERROR, "ioctl(SIOCSIFFLAGS) failed [%d]: %s", errno, strerror(errno));
    return(-6);
  }

  return(0);
}

/* ********************************** */

/** @brief  Open and configure the TAP device for packet read/write.
 *
 *  This routine creates the interface via the tuntap driver and then
 *  configures it.
 *
 *  @param device      - [inout] a device info holder object
 *  @param dev         - user-defined name for the new iface, 
 *                       if NULL system will assign a name
 *  @param device_ip   - address of iface
 *  @param device_mask - netmask for device_ip
 *  @param mtu         - MTU for device_ip
 *
 *  @return - negative value on error
 *          - non-negative file-descriptor on success
 */
int tuntap_open(tuntap_dev *device, 
                char *dev, /* user-definable interface name, eg. edge0 */
                const char *address_mode, /* static or dhcp */
                char *device_ip, 
                char *device_mask,
                const char * device_mac,
		int mtu) {
  char *tuntap_device = "/dev/net/tun";
  int ioctl_fd;
  struct ifreq ifr;
  int rc;

  device->fd = open(tuntap_device, O_RDWR);
  if(device->fd < 0) {
    traceEvent(TRACE_ERROR, "tuntap open() error: %s[%d]. Is the tun kernel module loaded?\n", strerror(errno), errno);
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP|IFF_NO_PI; /* Want a TAP device for layer 2 frames. */
  strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
  ifr.ifr_name[IFNAMSIZ-1] = '\0';
  rc = ioctl(device->fd, TUNSETIFF, (void *)&ifr);

  if(rc < 0) {
    traceEvent(TRACE_ERROR, "tuntap ioctl(TUNSETIFF, IFF_TAP) error: %s[%d]\n", strerror(errno), rc);
    close(device->fd);
    return -1;
  }

  /* Store the device name for later reuse */
  strncpy(device->dev_name, ifr.ifr_name, MIN(IFNAMSIZ, N2N_IFNAMSIZ) );

  if((ioctl_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
    traceEvent(TRACE_ERROR, "socket creation failed [%d]: %s", errno, strerror(errno));
    return -1;
  }

  if(setup_ifname(ioctl_fd, device->dev_name, device_ip, device_mask, device_mac, mtu) < 0) {
    close(ioctl_fd);
    close(device->fd);
    return -1;
  }

  close(ioctl_fd);

  device->ip_addr = inet_addr(device_ip);
  device->device_mask = inet_addr(device_mask);
  read_mac(dev, device->mac_addr);
  return(device->fd);
}

/* *************************************************** */

int tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, int len) {
  return(read(tuntap->fd, buf, len));
}

/* *************************************************** */

int tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, int len) {
  return(write(tuntap->fd, buf, len));
}

/* *************************************************** */

void tuntap_close(struct tuntap_dev *tuntap) {
  close(tuntap->fd);
}

/* *************************************************** */

/* Fill out the ip_addr value from the interface. Called to pick up dynamic
 * address changes. */
void tuntap_get_address(struct tuntap_dev *tuntap) {
  struct ifreq ifr;
  int fd;

  if((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
    traceEvent(TRACE_ERROR, "socket creation failed [%d]: %s", errno, strerror(errno));
    return;
  }

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, tuntap->dev_name, IFNAMSIZ);
  ifr.ifr_name[IFNAMSIZ-1] = '\0';

  if(ioctl(fd, SIOCGIFADDR, &ifr) != -1)
    tuntap->ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

  close(fd);
}

#endif /* #ifdef __linux__ */
