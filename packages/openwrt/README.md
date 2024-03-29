## Prerequisites

This instructions explain how to build an OpenWRT .ipk package for n2n.

You will either need to build a full OpenWRT buildchain (See the github
action for building openwrt.yml for some example steps) or have a working
cross-compiling build environment for the OpenWRT version installed into
your device.

### Downloading a cross-compiling build environment

This usually comes down to the following steps:

1. Download and extract the SDK toolchain for your device. The toolchain
   must match the *exact* OpenWRT version installed in your device. Toolchain
   for official OpenWRT images can be downloaded from https://downloads.openwrt.org

2. Build the toolchain: run `make menuconfig`, save the configuration, then
   run `make` to build the cross compiling tools

3. Download the feeds with `./scripts/feeds update -a`

## Compilation

These instructions are for building the current checked out version of the
n2n source  (The generally used OpenWRT alternative is to download a tar.gz
file of a specific n2n version, but that is not as suitable for development
or local builds)

You need both the openwrt repository and the n2n repository checked out
for this.  In these instructions, we assume that `openwrt` is the directory
where your openwrt checkout is located and `n2n` is the directory for
the n2n repository.

```
git clone https://github.com/ntop/n2n n2n
N2N_PKG_VERSION=$(n2n/scripts/version.sh)
export N2N_PKG_VERSION
echo $N2N_PKG_VERSION

cp -r n2n/packages/openwrt openwrt/package/n2n

cd openwrt
make oldconfig
# In the VPN section, select "m" for n2n-edge and n2n-supernode

make package/n2n/clean V=s
make package/n2n/prepare USE_SOURCE_DIR=$(realpath ../n2n) V=s
make package/n2n/compile V=s
```

If everything went fine, two ipk will be generated, one for the n2n-edge
and the other for n2n-supernode. They can be found with `find . -name "n2n*.ipk"`,
copied to the target device, and installed with `opkg install`.

The github action described in `.github/workflows/openwrt.yml` implements
an automated version of the above steps.

## Configuration

The edge node can be started with `/etc/init.d/edge start`.
Its configuration file is `/etc/n2n/edge.conf`.

The supernode can be started with `/etc/init.d/supernode start`.
Its configuration file is `/etc/n2n/supernode.conf`.
