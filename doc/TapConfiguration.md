# TAP Device Configuration

n2n provides its service through a TAP device which is the virtual ethernet device seen by the computer and user. As a prerequisite, it requires the appropriate TAP driver to be installed. Most Linux systems come with it. If not loaded, `sudo modprobe tap` will do.

For MacOS and Windows specific instructions, please see the [Building](./Building.md) document.

## Device Name

If the OS specific driver allows for naming the virtual Ethernet device, n2n's `-d <device>` command line options can be used to give a name, e.g. `-d n2n0`. This device name makes the virtual ethernet device easily accessible to all `ip` command activity, `iptables`, `tcpdump` and any other of your preferred network tools. It defaults to `edge0` if not provided through `-d`.

## MAC

Even virtual ethernet devices have a MAC address. As in real networks, it should be unique as it is used to identify the different participants and transport packets accordingly. The MAC address can optionally be specified by using the `-m <MAC address>` command line parameter, e.g. `-m 01:02:03:04:05:06`. If omitted, n2n assigns a random MAC address.

## IP Address

n2n supports several ways to assign an IPv4 address to the virtual ethernet device. Support for IPv6 addresses relies on OS support.

### Manually Assigned IP Address

The command line parameter `-a <static:IP address>` assigns a static IP address, e.g. `-a static:192.168.8.5` to the device. The optional `static` keyword (and the delimiting colon) can be omitted, so `-a 192.168.8.5` works as well.

The netmask in CIDR notation can optionally be appended to the address, e.g. `-a 192.168.8.5/24` for netmask `255.255.255.0` which also is the default should the netmask not be provided.

### Auto-IP Address

If `-a` is omitted, the supernode assigns an IP address to the node. This feature uses different IP address pools on a per-community basis. So, all edges in the same community will find themselves in the same sub-network.

By default, `/24`-sized IP address sub-network pools from the upper half of the `10.0.0.0` class A network will be used, that is from `10.128.0.0/24` … `10.255.255.0/24`. The supernode can be configured to assign addresses from a different network range: `-d 10.0.0.0-10.255.0.0/16` would the supernode make use of the complete `10.0.0.0` class A range but handle `/16`-sized sub-networks. Also, named communities could be pre-assigned certain sub-networks, please see the explanatory comments in the `community.list` file.

### DHCP

If an edge of the community runs a DHCP server, the others could draw their IP addresses from there. It requires the new edges to start-up with the `-r -a dhcp:0.0.0.0` parameters (literally).

### IPv6

n2n supports the carriage of IPv6 packets within the n2n tunnel. N2n does not
yet use IPv6 for transport between edges and supernodes.

To make IPv6 carriage work you need to manually add IPv6 addresses to the TAP
interfaces at each end. There is currently no way to specify an IPv6 address on
the edge command line.

Eg. under linux:

on hostA:
`[hostA] $ /sbin/ip -6 addr add fc00:abcd:1234::7/48 dev n2n0`

on hostB:
`[hostB] $ /sbin/ip -6 addr add fc00​:abcd:​1234::6/48 dev n2n0`

You may find it useful to make use of tunctl from the uml-utilities
package. Tunctl allow you to bring up a TAP interface and configure addressing
prior to starting edge. It also allows edge to be restarted without the
interface closing (which would normally affect routing tables).

Once the IPv6 addresses are configured and edge started, IPv6 neighbor discovery
packets flow (get broadcast) and IPv6 entities self arrange. Test your IPv6
setup with ping6 - the IPv6 ping command.

## MTU

The MTU of the VPN interface is set to a lower value (rather than the standard
1500 B value) to avoid excessive fragmentation on the datagram sent on internet.
This is required because n2n adds additional headers to the packets received from
the VPN interface. The size of the final frame sent through the internet interface
must have a size <= the internet interface MTU (usually 1500 B).

As a fragmentation example, suppose that a 3000 B TCP segment should be sent through
the VPN. If the VPN interface MTU is set to 1500, the packet will be split into two
fragments of 1500 B each. However, n2n will add its headers to each fragment, so
each fragment becomes a 1540 B packet. The internet interface mtu, which is 1500 B,
will fragment each packet again in two further fragments (e.g. 1500 + 50 B), so a
total of 4 fragments will be sent over internet. On the other hand, if the VPN interface
MTU was set to 1460 that would result in only 3 fragments sent as the initial segment of
3000 would be split in 1460 + 1460 + 80 B and that would not be further fragmented.

IP packet fragmentation in general is something to avoid, as described in
http://www.hpl.hp.com/techreports/Compaq-DEC/WRL-87-3.pdf . When possible,
the fragmentation should be moved to the TCP layer by a proper MSS value.
This can be forced by mangling the packet MSS, which is called "MSS clamping" (currently not
implemented in n2n). See https://github.com/gsliepen/tinc/blob/228a03aaa707a5fcced9dd5148a4bdb7e5ef025b/src/route.c#L386 .

The exact value to use as a clamp value, however, depends on the PMTU, which is the minimum
MTU of the path between two hosts. Knowing the PMTU is also useful for a sender in order to
avoid fragmentation at the IP level. Trying to find the biggest MTU is useful since it allows to
maximize bandwidth.

### PMTU Discovery Failures

Most operating systems try to periodically discover the PMTU by using a PMTU discovery algorithm.
This involves setting the DF (don't fragment) flag on the IP packets. When a large IP packet exceeds
the MTU of a router in the path, an "ICMP Fragmentation Needed" message should be received, which will
help the OS tune the size of the next IP packets. However, some routers do not report such ICMP message,
which results in packets being silently dropped. The `tracepath` tool can be used to detect the PMTU.

The main problem when this situation occurs is that the actual PMTU is unknown, so an automatic
solution is not applicable. The user must manually specify a lower MTU for the VPN interface
in order to solve the issue.

### n2n and MTU

n2n should work by default in different environments. For this reason, the following solution
has been provided:

- PMTU discovery is disabled when possible (via the IP_MTU_DISCOVER socket option). This avoid
  silently dropping a oversize packet due to the DF flag, however it possibly increments fragmentation on the path.
- As examplained above, a lower MTU is set on the VPN interface, thus removing excessive fragmentation on
  the sender.
- 1290 B is used instead of 1500 B as the reference value for the internet interface MTU.
  This essentially avoids fragmentation when the PMTU is >= 1400 B.

This is a conservative solution which should make n2n work by default. The user can manually
specify the MTU (`-M <mtu>`) and re-enable PMTU discovery (`-D`) via the CLI options.
