# Edge Authentication

From a discussion on how to prevent MAC address spoofing, the need of edge authentication became evident. In fact, the REGISTER_SUPER type messages already have shown a so far unused `auth` field which gets used for the first time starting in the course of n2n version 2.9 development.

## Implementation

A very basic authentication scheme based on a uniqe identification number is put in place. This ID is randomly generated during edge start-up and remains unchanged until the edge terminates. With every REGISTER_SUPER, it is tranmitted to the supernode which remembers it from the first REGISTER_SUPER and can compare it to all the following ones. It is a verfication based on "showing the ID". The supernode accepts REGISTER_SUPER (and thus changed MAC address or internet socket) and UNREGISTER type messages only if verification passes.

This does not only prevent UNREGISTER attacks but also MAC spoofing even in case of several federated supernodes because each REGISTER_SUPER message is forwarded to all other supernodes. If a new edge (un)intentionally tries to claim a MAC address which already has been in use by another edge, this would be detected as unauthorized MAC change because the new edge presents a different authentication ID. The supernode which rejects it (based on a failed comparison) sends a REGISTER_SUPER_**NAK** type message to the new edge as well as the supernode through which the new edge tried to register. The REGISTER_SUPER_NAK will cause deletion of associated entries at the supernode and make a complying edge stop.

As opposed to the MAC address which is sent out with each packet also between edges, the ID remains between the edge and the supernode. Other edges do not become aware of it and thus are not able to spoof.

A somewhat hurdling network sniffing attack aimed at observing the authentication ID could break this scheme. Thus, further development towards a more sophisticated crypto-based authentication scheme is intended.