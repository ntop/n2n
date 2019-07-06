## Compilation

From the OpenWRT build directory:

```
git clone https://github.com/ntop/n2n n2n
cp -r n2n/packages/openwrt package/n2n
make menuconfig # select Network -> VPN -> n2n-edge and n2n-supernode
make package/n2n/compile V=s
```

## Configuration

The edge node can be started with `/etc/init.d/edge start`.
Its configuration file is `/etc/config/n2n-edge.conf`.

The supernode can be started with `/etc/init.d/supernode start`.
Its configuration file is `/etc/config/n2n-supernode.conf`.
