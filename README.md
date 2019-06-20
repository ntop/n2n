# N2N

N2n is a light VPN software which make it easy to create virtual networks bypassing intermediate firewalls. In order to start using N2N, two elements are required:

- A *supernode*: it allows edge nodes to announce and discover other nodes. It must have a port publicly accessible on internet.

- *Edge* nodes: the nodes which will be part of the virtual networks

A virtual network shared between multiple edge nodes in n2n is called a *community*. A single supernode can relay multiple communities and a single PC can be part of multiple communities at the same time. An encryption key can be used by the edge nodes to encrypt the packets within their community.

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

Setting up a custom Supernode
-----------------------------

You can create your own infrastructure by setting up a supernode on a public server (e.g. a VPS). You just need to open a single port (1234 in the example below) on your firewall (usually iptables).

1. Install the n2n package
2. Edit `/etc/n2n/supernode.conf` and add the following:
```
-l=1234
```
3. Start the supernode service with `sudo systemctl start supernode`

Now the supernode service should be up and running on port 1234. On your edge nodes you can now specify `-l your_supernode_ip:1234` to use it. All the edge nodes must use the same supernode.

IPv6 Support
------------

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

## Docker registry

*NOTE*: docker packages may be outdated.

- [DockerHub](https://hub.docker.com/r/supermock/supernode/)
- [DockerStore](https://store.docker.com/community/images/supermock/supernode/)

Run with:

```sh
$ docker run --rm -d -p 5645:5645/udp -p 7654:7654/udp supermock/supernode:[TAGNAME]
```

-----------------
(C) 2007-2019 - ntop.org and contributors
