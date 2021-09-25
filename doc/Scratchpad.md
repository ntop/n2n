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

## Draft changelog between 2.8.x and 2.9.x (as of August 29, 2021)

### New Features

- Federated supernodes to allow multiple supernodes for load balancing and fail-over (`doc/Federation.md`)
- Automatic IP address assignment allows edges to draw IP addresses from the supernode (just skip `-a`)
- Allowed community names can be restricted by regular expressions (`community.list` file)
- Network filter for rules (`-R`) allowing and denying specific traffic to tunnel
- Experimental TCP support (`-S2`) lets edges connect to the supernodes via TCP in case firewalls block UDP (not available on Windows yet)
- All four supported ciphers offer integrated versions rendering OpenSSL dependency non-mandatory (optionally still available)
- MAC and IP address spoofing prevention
- Network interface metric can be set by command-line option `-x` (Windows only)
- Re-enabled local peer detection by multicast on Windows
- Edge identifier (`-I`) helps to identify edges more easily in management port output
- Optionally bind edge to one local IP address only (extension to `-p`)
- A preferred local socket can be advertised to other edges for better local peer-to-peer connections (`-e`)
- Optional edge user and password authentication (`-J`, `-P`, `doc/Authentication.md`)


### Improvements

- Increased edges' resilience to temporary supernode failure
- Fixed a compression-related memory leak
- Ciphers partly come with platform-specific hardware acceleration
- Clean-up management port output
- Polished benchmark tool output
- Spun-off the name resolution into a separate thread avoiding lags
- Added support for additional environment variables (`N2N_COMMUNITY` and `N2N_PASSWORD`)
- Implemented new `reload_communities` command to make supernode hot-reload the `-c` provided `community.list` file, issued through management port
- Reactivated send out of gratuitous ARP packet on establishing connection
- Enhanced documentation (`doc/` folder) including the man pages and command-line help text (`-h` and more detailed `--help`)
- Self-monitoring time stamp accuracy for use on systems with less accurate clocks
- Fixed man pages' and config files' paths
- Code clean-up




