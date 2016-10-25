


Edge node
---------

You need to start an edge node on each host you want to connect with the *same*
community.

0. become root

1. create tun device: `$ tunctl -t tun0`

2. enable the edge process
```
$ ./edge -d n2n0 -c mynetwork -k encryptme -u 99 -g 99 -m 3C:A0:12:34:56:78 -a 1.2.3.4 -l a.b.c.d:xyw
```
or
```
$ N2N_KEY=encryptme ./edge -d n2n0 -c mynetwork -u 99 -g 99 -m 3C:A0:12:34:56:78 -a 1.2.3.4 -l a.b.c.d:xyw
```

Once you have this worked out, you can add the `-f` option to make edge detach
and run as a daemon.

Note that `-u`, `-g` and `-f` options are not available for Windows.


Supernode
--------

You need to start the supernode once

1. `./supernode -l 1234 -v`



Dropping Root Privileges and SUID-Root Executables (UNIX)
--------------------------------------------------

The edge node uses superuser privileges to create a TAP network interface
device. Once this is created root privileges are not required and can constitute
a security hazard if there is some way for an attacker to take control of an
edge process while it is running. Edge will drop to a non-privileged user if you
specify the `-u <uid>` and `-g <gid>` options. These are numeric IDs. Consult
`/etc/passwd`.

You may choose to install edge SUID-root to do this:

1. Become root
2. `chown root:root edge`
3. `chmod +s edge`
4. done

Any user can now run edge. You may not want this, but it may be convenient and
safe if your host has only one login user.


Running As a Daemon (UNIX)
-------------------

Unless given `-f` as a command line option, edge will call daemon(3) after
successful setup. This causes the process to fork a child which closes stdin,
stdout and stderr then sets itself as process group leader. When this is done,
the edge command returns immediately and you will only see the edge process in
the process listings, eg. from ps or top.

If the edge command returns 0 then the daemon started successfully. If it
returns non-zero then edge failed to start up for some reason. When edge starts
running as a daemon, all logging goes to syslog daemon.info facility.


IPv6 Support
------------

n2n supports the carriage of IPv6 packets within the n2n tunnel. N2n does not
yet use IPv6 for transport between edges and supernodes.

To make IPv6 carriage work you need to manually add IPv6 addresses to the TAP
interfaces at each end. There is currently no way to specify an IPv6 address on
the edge command line.

eg. under linux:

on hostA:
`[hostA] $ /sbin/ip -6 addr add fc00:abcd:1234::7/48 dev n2n0`

on hostB:
`[hostB] $ /sbin/ip -6 addr add fc00​:abcd:​1234::6/48 dev n2n0`

You may find it useful to make use of tunctl from the uml-utilities
package. Tunctl allow you to bring up a TAP interface and configure addressing
prior to starting edge. It also allows edge to be restarted without the
interface closing (which would normally affect routing tables).

Once the IPv6 addresses are configured and edge started, IPv6 neighbor discovery
packets flow (get broadcast) and IPv6 entities self arrange. Test your IPv6
setup with ping6 - the IPv6 ping command.


Performance Notes
-----------------

The time taken to perform a ping test for various ciphers is given below:

Test: `ping -f -l 8 -s 800 -c 10000 <far_edge>`

AES  (-O0) 11820
TF   (-O0) 25761

TF   (-O2) 20554

AES  (-O3) 12532
TF   (-O3) 14046
NULL (-O3) 10659

(C) 2007-2010 - Luca Deri <deri@ntop.org> and Richard Andrews <andrews@ntop.org>

(C) 2016 - ntop