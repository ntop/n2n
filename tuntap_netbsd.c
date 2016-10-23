/*
 * (C) 2007-09 - Luca Deri <deri@ntop.org>
 * (C) 2009 - Alaric Snell-Pym <alaric@kitten-technologies.co.uk>
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
 */

#include "n2n.h"

#ifdef __NetBSD__

#include <errno.h>
#include <string.h>
#include <net/if_tap.h>

void tun_close(tuntap_dev *device);

/* ********************************** */

#define N2N_NETBSD_TAPDEVICE_SIZE 32
int tuntap_open(tuntap_dev *device /* ignored */,
                char *dev,
                const char *address_mode, /* static or dhcp */
                char *device_ip,
                char *device_mask,
                const char * device_mac,
		int mtu) {
  char tap_device[N2N_NETBSD_TAPDEVICE_SIZE];
  struct ifreq req;

  if (dev) {
     snprintf(tap_device, sizeof(tap_device), "/dev/%s", dev);
     device->fd = open(tap_device, O_RDWR);
     snprintf(tap_device, sizeof(tap_device), "%s", dev);
  }
  else {
     device->fd = open("/dev/tap", O_RDWR);
     if(device->fd >= 0) {
        if (ioctl(device->fd, TAPGIFNAME, &req) == -1) {
           traceEvent(TRACE_ERROR, "Unable to obtain name of tap device (%s)", strerror(errno));
           close(device->fd);
           return(-1);
        }
        else {
           snprintf(tap_device, sizeof(tap_device), req.ifr_name);
        }
     }
  }

  if(device->fd < 0) {
    traceEvent(TRACE_ERROR, "Unable to open tap device (%s)", strerror(errno));
    return(-1);
  } else {
    char buf[256];
    FILE *fd;

    traceEvent(TRACE_NORMAL, "Succesfully open %s", tap_device);

    device->ip_addr = inet_addr(device_ip);

    if ( device_mac && device_mac[0] != '\0' )
    {
        /* Set the hw address before bringing the if up. */
        snprintf(buf, sizeof(buf), "ifconfig %s link %s active",
                 tap_device, device_mac);
        system(buf);
    }

    snprintf(buf, sizeof(buf), "ifconfig %s %s netmask %s mtu %d up",
             tap_device, device_ip, device_mask, mtu);
    system(buf);

    traceEvent(TRACE_NORMAL, "Interface %s up and running (%s/%s)",
               tap_device, device_ip, device_mask);

  /* Read MAC address */

    snprintf(buf, sizeof(buf), "ifconfig %s |grep address|cut -c 11-28", tap_device);
    /* traceEvent(TRACE_INFO, "%s", buf); */

    fd = popen(buf, "r");
    if(fd < 0) {
      tun_close(device);
      return(-1);
    } else {
      int a, b, c, d, e, f;

      buf[0] = 0;
      fgets(buf, sizeof(buf), fd);
      pclose(fd);

      if(buf[0] == '\0') {
	traceEvent(TRACE_ERROR, "Unable to read %s interface MAC address", tap_device);
	exit(0);
      }

      traceEvent(TRACE_NORMAL, "Interface %s mac %s", tap_device, buf);
      if(sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", &a, &b, &c, &d, &e, &f) == 6) {
	device->mac_addr[0] = a, device->mac_addr[1] = b;
	device->mac_addr[2] = c, device->mac_addr[3] = d;
	device->mac_addr[4] = e, device->mac_addr[5] = f;
      }
    }
  }


  /* read_mac(dev, device->mac_addr); */
  return(device->fd);
}

/* ********************************** */

int tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, int len) {
  return(read(tuntap->fd, buf, len));
}

/* ********************************** */

int tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, int len) {
  return(write(tuntap->fd, buf, len));
}

/* ********************************** */

void tuntap_close(struct tuntap_dev *tuntap) {
  close(tuntap->fd);
}

/* Fill out the ip_addr value from the interface. Called to pick up dynamic
 * address changes. */
void tuntap_get_address(struct tuntap_dev *tuntap)
{
}

#endif /* #ifdef __NetBSD__ */
