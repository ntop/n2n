MTU
---

The MTU of the VPN interface is set to a lower value (rather than the standard
1500 B value) to avoid excessive fragmentation on the datagram sent on internet.
This is required because n2n adds additional headers to the packets received from
the VPN interface. The size of the final frame sent through the internet interface
must have a size <= the internet interface MTU (usually 1500 B).

As a fragmentation example, suppose that a 3000 B TCP segment should be sent through
the VPN. If the VPN interface MTU is set to 1500, the packet will be split into two
fragments of 1500 B each. However, n2n will add its headers to each fragment, so
each fragment becomes a 1540 B packet. The internet interface mtu, which is 1500 B,
will fragment each packet again in two further fragments (e.g. 1500 + 50 B), so a
total of 4 fragments will be sent over internet. On the other hand, if the VPN interface
MTU was set to 1460 that would result in only 3 fragments sent as the initial segment of
3000 would be split in 1460 + 1460 + 80 B and that would not be further fragmented.

IP packet fragmentation in general is something to avoid, as described in
http://www.hpl.hp.com/techreports/Compaq-DEC/WRL-87-3.pdf . When possible,
the fragmentation should be moved to the TCP layer by a proper MSS value.
This can be forced by mangling the packet MSS, which is called "MSS clamping" (currently not
implemented in n2n). See https://github.com/gsliepen/tinc/blob/228a03aaa707a5fcced9dd5148a4bdb7e5ef025b/src/route.c#L386 .

The exact value to use as a clamp value, however, depends on the PMTU, which is the minimum
MTU of the path between two hosts. Knowing the PMTU is also useful for a sender in order to
avoid fragmentation at the IP level. Trying to find the biggest MTU is useful since it allows to
maximize bandwidth.

PMTU Discovery Failures
-----------------------

Most operating systems try to periodically discover the PMTU by using a PMTU discovery algorithm.
This involves setting the DF (don't fragment) flag on the IP packets. When a large IP packet exceeds
the MTU of a router in the path, an "ICMP Fragmentation Needed" message should be received, which will
help the OS tune the size of the next IP packets. However, some routers do not report such ICMP message,
which results in packets being silently dropped. The `tracepath` tool can be used to detect the PMTU.

The main problem when this situation occurs is that the actual PMTU is unknown, so an automatic
solution is not applicable. The user must manually specify a lower MTU for the VPN interface
in order to solve the issue.

n2n and MTU
-----------

n2n should work by default in different environments. For this reason, the following solution
has been provided:

- PMTU discovery is disabled when possible (via the IP_MTU_DISCOVER socket option). This avoid
  silently dropping a oversize packet due to the DF flag, however it possibly increments fragmentation on the path.

- As examplained above, a lower MTU is set on the VPN interface, thus removing excessive fragmentation on
  the sender.

- 1400 B is used instead of 1500 B as the reference value for the internet interface MTU.
  This essentially avoids fragmentation when the PMTU is >= 1400 B.

This is a conservative solution which should make n2n work by default. The user can manually
specify the MTU and re-enable PMTU discovery via the CLI options.
