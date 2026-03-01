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

#ifndef _MACOS_UTUN_H_
#define _MACOS_UTUN_H_

#ifdef __APPLE__

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <net/if.h>

/**
 * Open a macOS utun device.
 *
 * @param dev_name      buffer to receive the assigned interface name (e.g. "utun7")
 * @param dev_name_size size of dev_name buffer
 * @param requested_name if non-empty and starts with "utun", try to open that specific unit
 * @return file descriptor on success, -1 on failure
 */
int utun_open(char *dev_name, size_t dev_name_size, const char *requested_name);

/**
 * Configure IP address, netmask, and MTU on a utun interface.
 *
 * @param dev_name  interface name (e.g. "utun7")
 * @param ip        IP address string (e.g. "10.0.0.1")
 * @param netmask   netmask string (e.g. "255.255.255.0")
 * @param mtu       MTU value
 * @return 0 on success, -1 on failure
 */
int utun_configure(const char *dev_name, const char *ip, const char *netmask, int mtu);

/**
 * Close a utun device. The kernel automatically destroys the interface.
 *
 * @param fd file descriptor from utun_open
 */
void utun_close(int fd);

#endif /* __APPLE__ */
#endif /* _MACOS_UTUN_H_ */
