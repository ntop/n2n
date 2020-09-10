## Prerequisites

This instructions explain how to build an OpenWRT .ipk package for n2n.

Before going on, it is required to have a working cross-compiling build
environment for the OpenWRT version installed into your device. This usually
comes down to the following steps:

1. Download and extract the SDK toolchain for your device. The toolchain
   must match the *exact* OpenWRT version installed in your device. Toolchain
   for official OpenWRT images can be downloaded from https://downloads.openwrt.org

2. Build the toolchain: run `make menuconfig`, save the configuration, then
   run `make` to build the cross compiling tools

3. Download the feeds with `./scripts/feeds update -a`

## Compilation

From the OpenWRT build directory:

```
git clone https://github.com/ntop/n2n n2n
cp -r n2n/packages/openwrt package/n2n
make menuconfig # select Network -> VPN -> n2n-edge and n2n-supernode
make package/n2n/compile V=s
```

If everything went fine, two ipk will be generated, one for the n2n-edge
and the other for n2n-supernode. They can be found with `find . -name "n2n*.ipk"`,
copied to the target device, and installed with `opkg install`.

## Configuration

The edge node can be started with `/etc/init.d/edge start`.
Its configuration file is `/etc/n2n/edge.conf`.

The supernode can be started with `/etc/init.d/supernode start`.
Its configuration file is `/etc/n2n/supernode.conf`.
