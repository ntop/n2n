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


## Version Update

- change `VERSION` file to new version, e.g. `4.0.1`
- `git add VERSION`
- `git commit -m "moved to version 4.0.1"`
- `git tag -a 4.0.1 -m "moved to version 4.0.1"`
- `git push --tags`


## Draft changelog between 3.0 and 3.2 (as of 2022)

### New Features

- Enhanced management port JSON interface to let n2n interact with external tools
- Added `n2n-route` tool (Linux only so far)
- Introduced `n2n-portfwd` tool to support UPnP and PMP port forwarding
- Furthered the build system

### Improvements

- Fixed a federation related bug
- Code clean-up




