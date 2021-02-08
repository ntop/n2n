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

## Draft changelog between 2.8.x and 2.9.x (as of February 8, 2021)

### New Features

- Federated supernodes to allow multiple supernodes for load balancing and fail-over (`doc/Federation.md`)
- Automatic IP address assignment allows edges to draw IP addresses from the supernode (just skip `-a`)
- Allowed community names can be restricted by regular expressions (`community.list` file)
- Network filter for rules (`-R`) allowing and denying specific traffic to tunnel
- Experimental TCP support (`-S2`) lets edges connect to the supernodes via TCP in case firewalls block UDP
- All four supported ciphers offer integrated versions rendering OpenSSL dependency non-mandatory (optionally still available)
- MAC and IP address spoofing prevention
- Network interface metric can be set by command-line option `-x` (Windows only)
- Re-enabled local peer detection by multicast on Windows
- Edge identifier (`-I`) helps to identify edges more easily in management port output

### Improvements

- Fixed a compression-related memeory leak
- Ciphers partly come with platform-specific hardware acceleration (check `tools/n2n-benchmark`)
- Clean-up management port output
- Polished benchmark tool output
- Reactivated send out of gratuitous ARP packet on establishing connection
- Enhanced documentation (`doc/` folder) including the man pages and command-line help text
- Self-monitoring time stamp accuracy for use on systems with less accurate clocks
- Fixed man pages' and config files' paths
- Code clean-up




