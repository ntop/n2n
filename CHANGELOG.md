# Changelog

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

## n2n 2.8 (August 2020)

This release brings significant new features to n2n's crypto world. Besides honing existing features, bugs get fixed.

### New Features

### Improvements
