## Instructions

From the OpenWRT build directory:

```
git clone https://github.com/ntop/n2n n2n
ln -s n2n/packages/n2n package/n2n
make menuconfig # select Network -> VPN -> n2n-edge and n2n-supernode
make package/n2n/compile V=s
```
