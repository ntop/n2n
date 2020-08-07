# Changelog

## n2n 2.8 (August 2020)

This release brings significant new features to n2n's crypto world and offers
some compression opportunities. The added support for routing table manipulation
might increase comfort. Besides further honing existing features, this release
addresses some bugs.

### New Features

* Two lightweight stream ciphers: ChaCha20 (optional, through OpenSSL) & SPECK (integrated)
* Full Header Encryption (including packet checksumming as well as replay protection)
* A callback interface to better integrate n2n in third party software (you can still use it stand-alone)
* Enable the integrated LZO1x compression
* Add optional ZSTD compression (through zstdlib)
* Support for changing system routes at program start and end
* User and group id parameter for supernode
* Application of cryptography in n2n is seperately documented
* Add a new pseudo random number generator with higher periodicity seeded with more entropy if available

### Improvements

* Have AES and ChaCha20 use OpenSSL's `evp_*` interface to make better use of available hardware acceleration
* Fix invalid sendto when supernode name resolution fails* Update to supernode's purge logic
* Extended management supernode's port output
* Fix read tap device failed when OS wakes up from sleep
* Free choice of supernode's management UDP port (for multiple supernodes on one machine).
* Additional trace messages to better indicate established connections and connection type
* Fix edge's register-to-supernode loop
* Remove redundant code
* Restructure the code in directories
* Clean-up platform-dependant code
* Compile fixes for Windows
* Fix build warnings
* …and many more under-the-hood fixes and tunings

## n2n 2.6 (March 2020)

The 2.6 release is mostly a maintenance release to address the issues 
of 2.4 that has been the first release since a long time of silence.

### New Features

* AES encryption that features an overall speed bump (12x speed) and security with respect to Twofish used in the previous n2n version
* Add ability to specify a whitelist of allowed communities on the supernode
* Implement local peers discovery via multicast
* Full peer-to-peer topology support.
* Add support for multiple edge systemd services
* Add benchmark tool for the encryption throughput
* Implement packet stats for P2P vs supernode communication
* Automatically drop privileges to user n2n
* Add support for ARM64 build
* More options to control MTU, P2P connections, TOS and log verbosity
* Implement a wireshark dissector for the n2n protocol
* Implement n2n-decode utility to decode and dump traffic to PCAP


### Improvements
* Extensive Windows and OpenWRT support.
* Windows compilation fixes and instructions
* Instructions and makefile file to build n2n on OpenWRT
* MacOS compilation fixes and instructions
* Improve the connection stability and the chances to establish a P2P connection
* Stable and more resilient connection.
* Remove keyschedule support to simplify the encryption code
* Replace peers linked list with hash table for faster lookup in big networks
* Integrate the changes made in the meyerd fork of n2n
* Remove calls to system() in tuntap_linux and use netlink instead
* n2n version improvements

## n2n 2.4 (August 2018)

This is the first release after 2012 and thus it is focusing mainly
on making it work on current operating system versions, so that the
next release will be based on modern code.

### New Features
* Added deb/rpm packages
* Added systemd configuration files
* Added ability to read configuration files instead of using only the CLI (needed for packaging)
* Added n2n Android app
* Implemented simple API to embed n2n in applications (in addition to use it stand-alone)

### Improvements
* Major code cleanup
* Fixed compilation issues on MacOS
* Fixed Linux segmentation fault
