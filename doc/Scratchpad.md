# n2n's Scratchpad

## RPM Packaging

```
bash
./autogen.sh
./configure
make

cd packages/rpm
./configure
rpmbuild -bb ./n2n.spec
```

## New Features between 2.0.x and 2.1.x

- Better ming Windows build support.
- Added `-E` flag to allow multicast ethernet traffic.

