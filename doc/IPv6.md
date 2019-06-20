n2n supports the carriage of IPv6 packets within the n2n tunnel. N2n does not
yet use IPv6 for transport between edges and supernodes.

To make IPv6 carriage work you need to manually add IPv6 addresses to the TAP
interfaces at each end. There is currently no way to specify an IPv6 address on
the edge command line.

eg. under linux:

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
