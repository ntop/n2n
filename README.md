# n2n

n2n is a light VPN software which makes it easy to create virtual networks bypassing intermediate firewalls.

In order to start using n2n, two elements are required:

- A _supernode_: it allows edge nodes to announce and discover other nodes. It must have a port publicly accessible on internet.
- _edge_ nodes: the nodes which will be a part of the virtual networks

A virtual network shared between multiple edge nodes in n2n is called a _community_. A single supernode can relay multiple communities and a single computer can be part of multiple communities at the same time. An encryption key can be used by the edge nodes to encrypt the packets within their community.

n2n tries to establish a direct peer-to-peer connection via udp between the edge nodes when possible. When this is not possible (usually due to special NAT devices), the supernode is also used to relay the packets.

## Quick Setup

Some Linux distributions already provide n2n as a package so a simple `sudo apt install n2n` will do the work. Alternatively, up-to-date packages for most distributions are available on [ntop repositories](http://packages.ntop.org/).

On host1 run:

```sh
$ sudo edge -c mynetwork -k mysecretpass -a 192.168.100.1 -f -l supernode.ntop.org:7777
```

On host2 run:

```sh
$ sudo edge -c mynetwork -k mysecretpass -a 192.168.100.2 -f -l supernode.ntop.org:7777
```

Now the two hosts can ping each other.

**IMPORTANT** It is strongly advised to choose a custom community name (`-c`) and a secret encryption key (`-k`) in order to prevent other users from connecting to your computer. For the privacy of your data sent and to reduce the server load of `supernode.ntop.org`, it is also suggested to set up a custom supernode as explained below.

## Setting up a Custom Supernode

You can create your own infrastructure by setting up a supernode on a public server (e.g. a VPS). You just need to open a single port (1234 in the example below) on your firewall (usually `iptables`).

1. Install the n2n package
2. Edit `/etc/n2n/supernode.conf` and add the following:
   ```
   -l=1234
   ```
3. Start the supernode service with `sudo systemctl start supernode`
4. Optionally enable supernode start on boot: `sudo systemctl enable supernode`

Now the supernode service should be up and running on port 1234. On your edge nodes you can now specify `-l your_supernode_ip:1234` to use it. All the edge nodes must use the same supernode.

## Manual Compilation

On linux, compilation from source is straight forward:

```sh
./autogen.sh
./configure
make

# optionally install
make install
```

Some parts of the code significantly benefit from compiler optimizations and platform features such as NEON, SSE and AVX. To enable, use `./configure CFLAGS="-O3 -march=native"` for configuration instead of `./configure`.

For Windows, MacOS and general building options, please check out [Building.md](doc/Building.md) for compilation and running.

**IMPORTANT** It is generally recommended to use the [latest stable release](https://github.com/ntop/n2n/releases). Please note that the current _dev_ branch usually is not guaranteed to be backward compatible neither with the latest stable release nor with previous _dev_ states. On the other hand, if you dare to try the bleeding edge features, you are encouraged to compile from _dev_ – just keep track of sometimes rapidly occuring changes. Feedback in the _Issues_ section is appreciated.

## Running edge as a Service

edge can also be run as a service instead of cli:

1. Edit `/etc/n2n/edge.conf` with your custom options. See `/etc/n2n/edge.conf.sample`.
2. Start the service: `sudo systemctl start edge`
3. Optionally enable edge start on boot: `sudo systemctl enable edge`

You can run multiple edge service instances by creating `/etc/n2n/edge-instance1.conf` and
starting it with `sudo systemctl start edge@instance1`.

## Security Considerations

When payload encryption is enabled (provide a key using `-k`), the supernode will not be able to decrypt
the traffic exchanged between two edge nodes but it will know that edge A is talking with edge B.

The choice of encryption schemes that can be applied to payload has recently been enhanced. Please have
a look at [Crypto.md](doc/Crypto.md) for a quick comparison chart to help make a choice. n2n edge nodes use 
Twofish encryption by default for compatibility reasons with existing versions. Other ciphers can be chosen
using the `-A_` option.

A benchmark of the encryption methods is available when compiled from source with `tools/n2n-benchmark`.

The header which contains some metadata like the virtual MAC address of the edge nodes, their IP address
and the community name optionally can be encrypted applying `-H` on the edges.

## Routing the Traffic

Reaching a remote network or tunneling all the internet traffic via n2n are two common tasks which require a proper routing setup. n2n supports routing needs providing options for packet forwarding (`-r`) including broadcasts (`-E`) as well as temporarily modifying the routing table (`-n`). Details can be found in the [Routing.md](doc/Routing.md) document.

## IPv6 Support

n2n can tunnel IPv6 traffic into the virtual network but does not support
IPv6 for edge-to-supernode communication yet.

Have a look at [IPv6.md](https://github.com/ntop/n2n/blob/dev/doc/IPv6.md) for more information.

## Contribution

You can contribute to n2n in various ways:

- Update an [open issue](https://github.com/ntop/n2n/issues) or create a new one with detailed information
- Propose new features
- Improve the documentation
- Provide pull requests with enhancements

For details about the internals of n2n check out [Hacking guide](https://github.com/ntop/n2n/blob/dev/doc/Hacking.md).

## Further Readings and Related Projects

Answers to frequently asked questions can be found in our [FAQ document](https://github.com/ntop/n2n/blob/dev/doc/Faq.md).

Here is a list of third-party projects connected to this repository:

- Collection of pre-built binaries for Windows: [lucktu](https://github.com/lucktu/n2n)
- n2n for Android: [hin2n](https://github.com/switch-iot/hin2n)
- Docker images: [Docker Hub](https://hub.docker.com/r/supermock/supernode/)
- Go bindings, management daemons and CLIs for n2n edges and supernodes, Docker, Kubernetes & Helm Charts: [pojntfx/gon2n](https://pojntfx.github.io/gon2n/)

---

(C) 2007-2020 - ntop.org and contributors
