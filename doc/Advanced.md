# Advanced Configuration


## Running edge as a Service

edge can also be run as a service instead of cli:

1. Edit `/etc/n2n/edge.conf` with your custom options. See `/etc/n2n/edge.conf.sample`.
2. Start the service: `sudo systemctl start edge`
3. Optionally enable edge start on boot: `sudo systemctl enable edge`

You can run multiple edge service instances by creating `/etc/n2n/edge-instance1.conf` and
starting it with `sudo systemctl start edge@instance1`.


## Communities

You might be interested to learn some [details about Communities](doc/Communities.md) and understand how to limit supernodes' services to only a specified set of communities.


## Virtual Network Device Configuration

The [TAP Configuration Guide](https://github.com/ntop/n2n/blob/dev/doc/TapConfiguration.md) contains hints on various settings that can be applied to the virtual network device, including IPv6 addresses as well as notes on MTU and on how to draw IP addresses from DHCP servers.


## Routing the Traffic

Reaching a remote network or tunneling all the internet traffic via n2n are two common tasks which require a proper routing setup. n2n supports routing needs providing options for packet forwarding (`-r`) including broadcasts (`-E`) as well as temporarily modifying the routing table (`-n`). Details can be found in the [Routing document](doc/Routing.md).


## Traffic Restrictions

It is possible to drop or accept specific packet transmit over edge network interface by rules. Rules can be specify by (`-R rule_str`) multiple times. Details can be found in the [Traffic Restrictions](doc/TrafficRestrictions.md).
