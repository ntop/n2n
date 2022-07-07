This instructions explain how to build an OpenWrt .ipk package for n2n.

1. Install build dependencies

   See [\[OpenWrt Wiki\] Build system setup](https://openwrt.org/docs/guide-developer/toolchain/install-buildsystem).

2. Download and extract the SDK

   Go to [downloads.openwrt.org](https://downloads.openwrt.org/) and download the correspond SDK for your device.

   Note: The SDK must match the **exact OpenWrt version and architecture** installed in your device.

   For details, see [\[OpenWrt Wiki\] Using the SDK](https://openwrt.org/docs/guide-developer/toolchain/using_the_sdk).

3. Update feeds

   ```bash
   ./scripts/feeds update -a && ./scripts/feeds install -a
   ```

4. Clone the n2n source code

   ```bash
   git clone https://github.com/ntop/n2n packages/n2n
   ```

5. Build n2n

   ```bash
   make defconfig
   make package/n2n/packages/openwrt/compile -j$(nproc) V=s
   ```

6. Install

   If everything went fine, four ipk will be generated.

   Generally speaking, you just need the n2n-edge and n2n-supernode.

   They can be found with `find bin/packages -name "n2n*.ipk"`.

   Copy them to the target device, and install with `opkg install`.

7. Configure

   The edge node can be started with `/etc/init.d/edge start`. Its configuration file is `/etc/n2n/edge.conf`.

   The supernode can be started with `/etc/init.d/supernode start`. Its configuration file is `/etc/n2n/supernode.conf`.
