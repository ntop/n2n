#!/bin/bash
#
# This is a sample script to route all the host traffic towards a remote
# gateway, which is reacheable via the n2n virtual interface.
#
# This assumes the n2n connection is already been established and the
# VPN gateway can be pinged by this host.
#

#######################################################
# CONFIG
#######################################################

# The IP address of the gateway through the n2n interface
N2N_GATEWAY="192.168.100.1"

# The IP address of the supernode as configured in n2n
N2N_SUPERNODE="1.2.3.4"

# The n2n interface name
N2N_INTERFACE="n2n0"

# The DNS server to use. Must be a public DNS or a DNS located on the
# N2N virtual network, otherwise DNS query information will be leaked
# outside the VPN.
DNS_SERVER="8.8.8.8"

#######################################################
# END CONFIG
#######################################################

if [[ $UID -ne 0 ]]; then
  echo "This script must be run as root"
  exit 1
fi

if ! ip route get $N2N_GATEWAY | grep -q $N2N_INTERFACE ; then
  echo "Cannot reach the gateway ($N2N_GATEWAY) via $N2N_INTERFACE. Is edge running?"
  exit 1
fi

# Determine the current internet gateway
internet_gateway=$(ip route get 8.8.8.8 | head -n1 | awk '{ print $3 }')

# Backup the DNS resolver configuration and use the specified server
cp /etc/resolv.conf /etc/resolv.conf.my_bak
echo "Using DNS server $DNS_SERVER"
echo "nameserver $DNS_SERVER" > /etc/resolv.conf

# The public IP of the supernode must be reachable via the internet gateway
# Whereas all the other traffic will go through the new VPN gateway.
ip route add $N2N_SUPERNODE via "$internet_gateway"
ip route del default
echo "Forwarding traffic via $N2N_GATEWAY"
ip route add default via $N2N_GATEWAY

function stopService {
  echo "Deleting custom routes"
  ip route del default
  ip route del $N2N_SUPERNODE via "$internet_gateway"

  echo "Restoring original gateway $internet_gateway"
  ip route add default via "$internet_gateway"

  echo "Restoring original DNS"
  mv /etc/resolv.conf.my_bak /etc/resolv.conf

  exit 0
}

# setup signal handlers
trap "stopService" SIGHUP SIGINT SIGTERM

# enter wait loop
echo "VPN is now up"
while :; do sleep 300; done
