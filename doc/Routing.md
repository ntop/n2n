# IPv4 Routing (Linux)

## General Remarks

Reaching a remote network or tunneling all the internet traffic via n2n are two common tasks which require a proper routing setup. n2n supports routing needs providing options for packet forwarding including broadcasts as well as modifying the routing table. 

In this context, the `server` is the edge node which provides access to the remote network/internet, whereas the `client` is the connecting edge node.

In order to enable routing, the `server` must be configured as follows:

1. Add the `-r` option to the edge options to enable routing
2. Enable packet forwarding with `sudo sysctl -w net.ipv4.ip_forward=1`
3. Enable IP masquerading: `sudo iptables -t nat -A POSTROUTING -j MASQUERADE`

On the client side, the easiest way to configure routing is via the `tools/n2n-route` utility. For example:

- In order to tunnel all the internet traffic, use `tools/n2n-route 10.0.0.1`
- In order to connect to the remote network `192.168.100.0/24`, use `tools/n2n-route -n 192.168.100.0/24 10.0.0.1`

10.0.0.1 is the IP address of the gateway to use to route the specified network. It should correspond to the IP address of the `server` within n2n. Multiple `-n` options can be specified.

The utility connects to the local edge's management port to receive information about peers and supernodes. It currently works on Linux only but certainly can be ported to other OS (the route handling code is quite OS dependant).

As an alternative to the `tools/n2n-route` utility, the `ip route` linux command can be manually used. See the [n2n-gateway.sh](scripts/n2n-gateway.sh) script for an example. See also the following description of other use cases and in depth explanation.

## Special Scenarios

### Assumptions

- There are two Local Area Networks, namely 10.11.12.0/24 (maybe at
  **h**ome) and 192.168.1.0/24 (maybe in **o**ffice).
- These networks are connected to the internet via routers 10.11.12.1
  and 192.168.1.1, respectively.
- In each network, there is a computer running a successfully setup n2n
  node: 10.11.12.5 (**h**ickory) and 192.168.1.6 (**o**scar). They are
  connected to their networks through a device called _eth0_. Their n2n
  devices shall be called _n2n0_, and their n2n IP addresses are
  10.99.99.50 (**h**ickory) and 10.99.99.60 (**o**scar) in the
  10.99.99.0/24 network.
- The _iptables_ are flushed.

### Prerequisites

- Both, **h**ickory and **o**scar have ip forwarding enabled: `echo 1 > /proc/sys/net/ipv4/ip_forward` or `sysctl -w net.ipv4.ip_forward=1`. To
  make this setting persistent over reboot, a file containing the line
  `net.ipv4.ip_forward=1` could be added in /etc/sysctl.d/ – your distro
  may vary.
- To allow n2n to forward packets, both edge nodes need to be started
  with `-r` option on their command line. All other regular network
  interfaces usually already allow packet forwarding and thus do not need
  any further configuration.

### Reach Complete Office Network from n2n Node at Home

- To make **h**ickory send all packets with office destination via
  **o**scar, **h**ickory needs to be made aware of where to route this
  packets to. On **h**ickory: `ip route add 192.168.1.0/24 via 10.99.99.60 dev n2n0 src 10.11.12.5`.
- **o**scar needs to know where to send packets to, too. So, on
  **o**scar: `ip route add 10.11.12.5 via 10.99.99.50 dev n2n0 src 192.168.1.6`.

**o**scar and **h**ickory should now be able to exchange packets by
using just their regular (non-n2n) IP addresses 10.11.12.5 and 192.168.1.6.
To make the complete office network aware of how packets or answers are
sent to **h**ickory, one more step is required:

- Packets from any office computer to **h**ickory need to be directed to
  **o**scar that – thanks to enabled IP forwarding and the routing rule –
  already knows how to handle this kind of packets.
  - To handle it in a one-stop-shop, the office router 192.168.1.1 can
    be configured to direct those packets to **o**scar. Luckily, even most
    modern small-office-and-home routers allow to add static routing rules
    via a web interface. A rule like "All packets for host 10.11.12.5 (or
    network 10.11.12.0/24) need to be sent to another router, namely
    192.168.1.5" will do. This is the **recommended** solution.
  - However, a **less recommended** but working option would be to add
    static routes to each single of those computers in the office network
    that shall be able to connect to or be accessed by **h**ickory. On
    those, e.g. **o**livia with IP address 192.168.1.123: `ip route add 10.11.12.5 via 192.168.1.5 dev eth0 src 192.168.1.123`.
  - Alternatively, in case the office router does not allow to have
    added own static routing rules, **o**scar needs to perform NAT for all
    connections initiated from **h**ickory:
    `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE`
    `iptables -A FORWARD -i eth0 -o n2n0 -m state --state RELATED,ESTABLISHED -j ACCEPT`
    `iptables -A FORWARD -i n2n0 -o eth0 -j ACCEPT`
    There is a major drawback with this solution which thus is the **least
    recommended**: Connections between **h**ickory and the office network
    will only work if initiated by **h**ickory – not the other way 'round.
    By the way, in case _iptables_ are messed up, they can be flushed by:
    `iptables -F`
    `iptables -X`
    `iptables -t nat -F`
    `iptables -t nat -X`
    `iptables -t mangle -F`
    `iptables -t mangle -X`
    `iptables -t raw -F`
    `iptables -t raw -X`
    `iptables -t security -F`
    `iptables -t security -X`
    `iptables -P INPUT ACCEPT`
    `iptables -P FORWARD ACCEPT`
    `iptables -P OUTPUT ACCEPT`

### Reach n2n Node in Office from Whole Home Network

This is easy:

- Just exchange home and office IP addresses and the computer names in
  the instructions given above.

### Reach Whole Home Network from Whole Office Network

This is not too complicated either. Basically, follow the given example
above and apply the following changes:

- The instructions used above need to be expanded from **h**ickory's IP
  10.11.12.5 to its full network 10.11.12.0/24 in the route commands on
  **o**scar:, especially: `ip route add 10.11.12.0/24 via 10.99.99.50 dev n2n0 src 192.168.1.6`.
- In case of adding a static route to the office network router
  192.168.1.1, the home network 10.11.12.0/24 must be specified instead of
  **h**ickory's more specific IP address 11.11.12.5. Same for the less
  recommended static routes on other office computers.
- Packets from home network's computers to the office network need to be
  sent through the n2n tunnel. The three alternatives given above can be
  used just with exchanged office and home IP addresses. One needs to be
  aware that NAT only (third alternative) on both sides will not allow any
  connection, i.e. at least on one side static routes need to be added
  either to the router (best option) or all those computers that shall be
  able to connect to the other network.

### Route All Internet Traffic from n2n Node at Home through Office Network

This scenario could be considered a n2n-tunneled VPN connection which
also would work for travelling users on their laptop. All external
internet traffic will appear to originate from **o**scar and the office
network.

- First, one of the setups described above needs to be in place, with
  the following change:
- NAT on **o**scar (see the three _iptables_ commands above) must be
  enabled. It will not work without because the office router 192.168.1.1
  usually denies forwarding to packets not originating from its own
  network. It could be in addition to the eventually installed static
  routes for 10.11.12.0/24 in the router 192.168.1.1 or on other office
  computers – it will not interfere. However, **o**scar definitely needs
  the route given above: `ip route add 10.11.12.5 via 10.99.99.50 dev n2n0 src 192.168.1.6`.
- To have **h**ickory's complete internet traffic going through the n2n
  tunnel, its default route needs to be changed:
  `ip route del default`
  `ip route add default via 10.99.99.60 dev n2n0 src 10.11.12.5`

- **h**ickory's home network should still be reachable as usually,
  _eth0_ and the associated network 10.11.12.0/24 get their very own
  route. If not, i.e. it was only covered by default route before, it
  needs to be added: `ip route add 10.11.12.0/24 dev eth0 src 10.11.12.5`.
- Unfortunately (unless the supernode is on **h**ickory's local
  network), n2n supernode becomes unreachable for **h**ickory. To fix it:
  `ip route add <supernode IP address> via 10.11.12.1 dev eth0 src 10.11.12.5`

The supernode's IP address needs to be known to have this work. However,
if the supernode's IP needs to be resolved from some domain name (FQDN),
e.g. in case of using dynamic domain name services, a DNS server needs
to remain reachable, too. Either the reachable home network router
10.11.12.1 is good enough for that (if it offers DNS) or another route
could to be added and **h**ickory's DNS settings might be set
accordingly, maybe to Google's 8.8.8.8.

If [DNS leaks](https://en.wikipedia.org/wiki/DNS_leak) do not matter,
this setup is complete.

### Preventing DNS Leaks

Otherwise, there is more to it: Without changes, all future DNS queries
go through the home router 10.11.12.1 to the ISP's servers or directly
to Google (via the home router 10.11.12.1 along the configured route for
8.8.8.8 and not through the n2n tunnel) while the remaining traffic
ships through the n2n tunnel.

To prevent such a DNS leak, the supernode's IP address must be
determined independently from **h**ickory's DNS configuration, e.g. by
digesting `dig +short mysupernode.myfavoritednsservice.com @8.8.8.8`'s
output in the n2n-edge's setup script for both, the edge node command
line as well as the static route mentioned above. Without further
additional work, dynamic address changes remain undetected. A static
route to 8.8.8.8 is still required. **h**ickory's regular DNS
configuration should query a different DNS server for its regular DNS
needs, e.g. 9.9.9.9 or 1.1.1.1 or maybe the office DNS server, maybe
192.168.1.1. This guarantees the regular DNS queries also to get sent
through the n2n tunnel.

A test for DNS leaks can be found [here](https://www.dnsleaktest.com/).
