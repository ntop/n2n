# TAP Device Configuration

n2n provides its service through a TAP device which is the virtual ethernet device seen by the computer and user. As a prerequisite, it requires the appropriate TAP driver to be installed. Most Linux systems come with it. If not loaded, `sudo modprobe tap` will do.

For MacOS and Windows there are specific instructions; please see the [Building](./Building.md) document.

## Device Name

If the OS specific driver allows **naming** the virtual Ethernet device created by n2n, the `-d <device>` command-line option can be used to give a name, e.g. `-d n2n0`. This device name makes the virtual ethernet device easily accessible to all `ip` command activity, `iptables`, `tcpdump` and any other of your preferred network tools. It defaults to `edge0` if not provided through `-d`.

One exception applies to Windows: As the installed TAP driver(s) come with fixed names, `-d <device>` **selects** the appropriate device by name out of the present ones. This is only required if more than one TAP devices are present. To help with it, `edge --help` lists the available TAP adapters at the bottom of its output (Windows only).

## MAC

Even virtual ethernet devices have a MAC address. As in real networks, it should be unique as it is used to identify the different participants and transport packets accordingly. The MAC address can optionally be specified by using the `-m <MAC address>` command line parameter, e.g. `-m 01:02:03:04:05:06`. If omitted, n2n tries to assign a random MAC address.

## IP Address

n2n supports several ways to assign an IPv4 address to the virtual ethernet device. Support for IPv6 addresses relies on OS support.

### Manually Assigned IP Address

The command line parameter `-a <static:IP address>` assigns a static IP address, e.g. `-a static:192.168.8.5` to the device. The optional `static` keyword (and the delimiting colon) can be omitted, so `-a 192.168.8.5` works as well.

The netmask in CIDR notation can optionally be appended to the address, e.g. `-a 192.168.8.5/24` for netmask `255.255.255.0` which also is the default should the netmask not be provided.

### Auto IP Address

If `-a` is omitted, the supernode assigns an IP address to the node. This feature uses different IP address pools on a per-community basis. So, all edges of the same community will find themselves in the same sub-network.

By default, `/24`-sized IP address sub-network pools from the upper half of the `10.0.0.0` class A network will be used, that is from `10.128.0.0/24` … `10.255.255.0/24`. The supernode can be configured to assign addresses from a different network range: `-a 10.0.0.0-10.255.0.0/16` would the supernode make use of the complete `10.0.0.0` class A range but handle `/16`-sized sub-networks. Also, named communities could be pre-assigned certain sub-networks, please see the explanatory comments in the `community.list` file.

### DHCP

If an edge of the community runs a DHCP server, the others could draw their IP addresses from there. It requires the new edges to start-up with the `-r -a dhcp:0.0.0.0` parameters (literally).

### IPv6

n2n supports the carriage of IPv6 packets within the n2n tunnel. n2n does not
yet use IPv6 for transport between edges and supernodes.

To make IPv6 carriage work you need to manually add IPv6 addresses to the TAP
interfaces at each end. There is currently no way to specify an IPv6 address on
the edge command line.

For example, under Linux

on hostA:
`[hostA] $ /sbin/ip -6 addr add fc00:abcd:1234::7/48 dev n2n0`

on hostB:
`[hostB] $ /sbin/ip -6 addr add fc00:abcd:1234::6/48 dev n2n0`

You may find it useful to make use of `tunctl` from the uml-utilities
package. `tunctl` allows you to bring up a TAP interface and configure addressing
prior to starting the edge. It also allows the edge to be restarted without the
interface closing (which would normally affect routing tables).

Once the IPv6 addresses are configured and edge is started, IPv6 neighbor discovery
packets flow (get broadcast) and IPv6 entities self-arrange. Test your IPv6
setup with `ping6` - the IPv6 ping command.

## MTU

The MTU of the VPN interface is set to a lower value (rather than the standard
value of 1500 bytes) to avoid excessive fragmentation of the datagram sent over the internet.
This is required because n2n adds additional headers to the packets received from
the VPN interface. The size of the final frame sent through the internet interface
must have a size lower or equal to the internet interface MTU (usually 1500 bytes).

As a fragmentation example, suppose that a 3000 byte TCP segment should be sent through
the VPN. If the VPN interface MTU is set to 1500, the packet will be split into two
fragments of 1500 bytes each. However, n2n will add its headers to each fragment, so
each fragment becomes a 1540 byte packet. The internet interface MTU of 1500 bytes
will fragment each packet again in two further fragments, e.g. 1500 + 50 bytes, so a
total of 4 fragments will be sent over the internet. On the other hand, if the VPN interface
MTU was set to 1460 bytes, it would result in only 3 fragments sent as the initial segment of
3000 bytes would be split in 1460 + 1460 + 80 bytes without further fragmentation.

IP packet fragmentation in general is something to avoid, as described in
http://www.hpl.hp.com/techreports/Compaq-DEC/WRL-87-3.pdf. If possible,
the fragmentation should be moved to the TCP layer by a proper MSS value.
This can be forced by mangling the packet MSS, which is called "MSS clamping" (currently not
implemented in n2n). See https://github.com/gsliepen/tinc/blob/228a03aaa707a5fcced9dd5148a4bdb7e5ef025b/src/route.c#L386.

The exact value to use as a clamp value, however, depends on the PMTU, which is the minimum
MTU of the path between two hosts. Knowing the PMTU is also useful for a sender in order to
avoid fragmentation at IP level. Trying to find the highest non-fragmenting MTU possible is useful since it allows to
maximize bandwidth.

### PMTU Discovery Failures

Most operating systems try to periodically discover the PMTU by using a PMTU discovery algorithm.
This involves setting the DF (don't fragment) flag on the IP packets. When a large IP packet exceeds
the MTU of a router in the path, an "ICMP Fragmentation Needed" message should be received, which will
help the OS along to tune the size of the next IP packets. However, some routers do not report such ICMP message,
which results in packets being silently dropped. The `tracepath` tool can be used to detect the PMTU.

The main problem with this situation is that the actual PMTU is unknown, so an automatic
solution is not applicable. The user must manually specify a lower MTU for the VPN interface
in order to solve the issue.

### n2n and MTU

n2n shall work by default in different environments. For this reason, the following solution
has been provided:

- PMTU discovery is disabled if possible (via the IP_MTU_DISCOVER socket option). This avoids
  silently dropping an oversized packet due to the DF flag; however, it possibly increments fragmentation on the path.
- As examplained above, a lower MTU is set on the VPN interface, thus removing excessive fragmentation on
  the sender.
- A value of 1290 bytes is used instead of 1500 bytes as reference value for the internet interface MTU.
  This essentially avoids fragmentation if the PMTU is greater or equal than 1400 bytes.

This is a conservative solution which should make n2n work by default. The user can manually
specify the MTU (`-M <mtu>`) and re-enable PMTU discovery (`-D`) via the command-line interface options.

## Interface Metric and Broadcasts

On Windows, broadcasts are sent out to the network interface with the lowest metric only. This usually is the
WAN interface with its default metric of `25`. The `-x <metric>` option could be used to configure the TAP with a
lower interface metric and hence facilitate service and online game server detection over n2n.

Linux and others do not require this feature as broadcasts are sent to all network interfaces by default, also to the
virtual ones.

## Multicast

n2n does not transmit multicast packets by default. It can be enabled by edge's `-E` command-line parameter.

## Egde Description

To keep edge's and supernode's management port output well arranged and understandable, each edge can have a plain text description
fed to the edge by the optional `-I <edge description>` command-line parameter. If not provided, n2n uses the
hostname by default.

A description field's hash value is used to choose an auto IP address. So, just be aware that changing the hostname
can lead to assigning a different auto IP address on next edge start-up – if auto IP address is used.

## Routing

n2n supports routing the traffic through its network. `-r` enables an edge to accept packets at its TAP interface not originating from the local IP address or not destined to the local IP address. As there is more to routing than just this one command-line option, please refer to the dedicated [Routing](Routing.md) document
explaining it all in detail.

## Traffic Filter

Setting up the integrated traffic filter permits to define exactly the kind of allowed traffic or deny 
other on edge's TAP interface. It helps to keep unwanted traffic out of the n2n network for
bandwitdth and security reasons. The traffic filter is disabled by default and gets activated by providing
as many `-R <rule>`-rules as required through edge's command-line. Specifics are written down in the
[Traffic Restrictions](TrafficRestricitons.md) documentation.
