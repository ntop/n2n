# Packaging

```
./autogen.sh
./configure
make

cd packages/rpm
./configure
rpmbuild -bb ./n2n.spec
```
