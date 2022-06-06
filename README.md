[![Build Status](https://travis-ci.org/ntop/n2n.png?branch=dev)](https://travis-ci.org/ntop/n2n)


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
   -p=1234
   ```
3. Start the supernode service with `sudo systemctl start supernode`
4. Optionally enable supernode start on boot: `sudo systemctl enable supernode`

Now the supernode service should be up and running on port 1234. On your edge nodes you can now specify `-l your_supernode_ip:1234` to use it. All the edge nodes must use the same supernode.


## Manual Compilation

On Linux, compilation from source is straight forward:

```sh
./autogen.sh
./configure
make

# optionally install
make install
```

For Windows, MacOS, CMake, optimizations and general building options, please check out [Building documentation](doc/Building.md) for compilation and running.

**IMPORTANT** It is generally recommended to use the [latest stable release](https://github.com/ntop/n2n/releases). Please note that the current _dev_ branch usually is not guaranteed to be backward compatible neither with the latest stable release nor with previous _dev_ states. On the other hand, if you dare to try bleeding edge features, you are encouraged to compile from _dev_ – just keep track of sometimes rapidly occuring changes. Feedback in the _Issues_ section is appreciated.


## Security Considerations

When payload encryption is enabled (provide a key using `-k`), the supernode will not be able to decrypt
the traffic exchanged between two edge nodes but it will know that edge A is talking with edge B.

The choice of encryption schemes that can be applied to payload has recently been enhanced. Please have
a look at [Crypto description](doc/Crypto.md) for a quick comparison chart to help make a choice. n2n edge nodes use 
AES encryption by default. Other ciphers can be chosen using the `-A_` option.

A benchmark of the encryption methods is available when compiled from source with `tools/n2n-benchmark`.

The header which contains some metadata like the virtual MAC address of the edge nodes, their IP address, their real 
hostname and the community name optionally can be encrypted applying `-H` on the edges.


## Advanced Configuration

More information about communities, support for multiple supernodes, routing, traffic restrictions and on how to run an edge as 
a service is available in the [more detailed documentation](doc/Advanced.md).


## Contribution

You can contribute to n2n in various ways:

- Update an [open issue](https://github.com/ntop/n2n/issues) or create a new one with detailed information
- Propose new features
- Improve the documentation
- Provide pull requests with enhancements

For details about the internals of n2n check out the [Hacking guide](https://github.com/ntop/n2n/blob/dev/doc/Hacking.md).


## Further Readings and Related Projects

Answers to frequently asked questions can be found in our [FAQ document](https://github.com/ntop/n2n/blob/dev/doc/Faq.md).

Here is a list of third-party projects connected to this repository:

- Collection of pre-built binaries for Windows: [lucktu](https://github.com/lucktu/n2n)
- n2n for Android: [hin2n](https://github.com/switch-iot/hin2n)
- Docker images: [Docker Hub](https://hub.docker.com/r/supermock/supernode/)
- Go bindings, management daemons and CLIs for n2n edges and supernodes, Docker, Kubernetes & Helm Charts: [pojntfx/gon2n](https://pojntfx.github.io/gon2n/)
- Windows GUI (along with a custom version of n2n) but also working with regular n2n: [HappyNet](https://github.com/happynclient/happynwindows)

---

(C) 2007-22 - ntop.org and contributors
