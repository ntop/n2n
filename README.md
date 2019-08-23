# N2N

N2n is a light VPN software which make it easy to create virtual networks bypassing intermediate firewalls.

In order to start using N2N, two elements are required:

- A *supernode*: it allows edge nodes to announce and discover other nodes. It must have a port publicly accessible on internet.

- *Edge* nodes: the nodes which will be part of the virtual networks

A virtual network shared between multiple edge nodes in n2n is called a *community*. A single supernode can relay multiple communities and a single PC can be part of multiple communities at the same time. An encryption key can be used by the edge nodes to encrypt the packets within their community.

N2n tries to enstablish a direct P2P connection between the edge nodes when possible. When this is not possible (usually due to special NAT devices), the supernode is also used to relay the packets.

Quick Setup
-----------

Some linux distributions already provide n2n as a package so a simple `sudo apt-get install n2n` will do the work. Alternatively, up to date packages for most distributions are available on [ntop repositories](http://packages.ntop.org/).

On host1 run:

```sh
$ sudo edge -c mynetwork -k mysecretpass -a 192.168.100.1 -f -l supernode.ntop.org:7777
```

On host2 run:

```sh
$ sudo edge -c mynetwork -k mysecretpass -a 192.168.100.2 -f -l supernode.ntop.org:7777
```

Now the two hosts can ping each other.

**IMPORTANT** It is strongly adviced to choose a custom community name (-c) and a secret encryption key (-k) in order to prevent other users to connect to your PC. For privacy and to reduce the above server load, it is also suggested to set up a custom supernode as exmplained below.

Setting up a custom Supernode
-----------------------------

You can create your own infrastructure by setting up a supernode on a public server (e.g. a VPS). You just need to open a single port (1234 in the example below) on your firewall (usually iptables).

1. Install the n2n package
2. Edit `/etc/n2n/supernode.conf` and add the following:
```
-l=1234
```
3. Start the supernode service with `sudo systemctl start supernode`
4. Optionally enable supernode start on boot: `sudo systemctl enable supernode`

Now the supernode service should be up and running on port 1234. On your edge nodes you can now specify `-l your_supernode_ip:1234` to use it. All the edge nodes must use the same supernode.

Routing the traffic
-------------------

On linux, n2n provides a standard TAP interface, so routing works gracefully via the standard system utilities as follows.

In this example host1 is the edge router (with n2n IP 192.168.100.1), whereas host2 is the client.

Here is how to configure host1:

1. Add the `-r` option to the edge options to enable routing
2. Enable packet forwarding with `sudo sysctl -w net.ipv4.ip_forward=1`
3. Possibly configure iptables to `ACCEPT` the packets on the `FORWARD` chain.

On host2, run the `edge` program as normal to join the host1 community.

In order to forward all the internet traffic via host2:

```sh
# Determine the current gateway (e.g. 192.168.1.1)
$ ip route show default

# Add a route to reach the supernode via such gateway
$ sudo ip route add supernode.ntop.org via 192.168.1.1

# Forward all the internet traffic via host1
$ sudo ip route del default
$ sudo ip route add default via 192.168.100.1
```

This process can be greatly simplified by using the [n2n_gateway.sh](https://github.com/ntop/n2n/blob/dev/doc/n2n_gateway.sh) script.

See [Routing.md](https://github.com/ntop/n2n/blob/dev/doc/Routing.md) for other use cases and in depth explanation.

Manual Compilation
------------------

On linux, compilation from source is straight forward:

```sh
./autogen.sh
./configure
make

# optionally install
make install
```

For Windows, check out [Windows.md](doc/Windows.md) for compilation and run instuctions.

For MacOS, check out [n2n_on_MacOS.txt](https://github.com/ntop/n2n/blob/dev/doc/n2n_on_MacOS.txt).

Running edge as a service
-------------------------

edge can also be run as a service instead of cli:

1. Edit `/etc/n2n/edge.conf` with your custom options. See `/etc/n2n/edge.conf.sample`.
2. Start the service: `sudo systemctl start edge`
3. Optionally enable edge start on boot: `sudo systemctl enable edge`

You can run multiple edge service instances by creating `/etc/n2n/edge-instance1.conf` and
starting it with `sudo systemctl start edge@instance1`.

IPv6 Support
------------

N2n can tunnel IPv6 traffic into the virtual network but does not support
IPv6 for edge-to-supernode communication yet.

Check out [IPv6.md](https://github.com/ntop/n2n/blob/dev/doc/IPv6.md) for more information.

Security considerations
-----------------------

n2n edge nodes use twofish encryption by default for compatibility reasons with existing versions.

**IMPORTANT** Encryption is only applied to the packet payload. Some metadata like the virtual MAC address
of the edge nodes, their IP address and the community are sent in cleartext.

When encryption is enabled, the supernode will not be able to decrypt the traffic exchanged between
two edge nodes, but it will now that edge A is talking with edge B.

Recently AES encryption support has been implemented, which increases both security and performance,
so it is recommended to enable it on all the edge nodes by specifying the `-A` option.

A benchmark of the encryption methods is available when compiled from source with `./benchmark`.

Contribution
------------

You can contribute to n2n in variuos ways:

- Update an [open issue](https://github.com/ntop/n2n/issues) or create a new one with detailed information
- Propose new features
- Improve the documentation
- Provide pull requests with enhancenents

For details about the internals of n2n check out [Hacking guide](https://github.com/ntop/n2n/blob/dev/doc/HACKING).

Related Projects
----------------

Here is a list of third-party projects connected to this repository.

- N2n for android: [hin2n](https://github.com/switch-iot/hin2n)
- N2n v1 and v2 version from meyerd: [meyerd n2n](https://github.com/meyerd/n2n)
- Docker images: [DockerHub](https://hub.docker.com/r/supermock/supernode/) - [DockerStore](https://store.docker.com/community/images/supermock/supernode/)

-----------------
(C) 2007-2019 - ntop.org and contributors
