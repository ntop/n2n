# Supernode Federation

## Idea
To enhance resilience in terms of backup and fail-over, also for load-balancing, multiple supernodes can easily interconnect and form a special community, called **federation**.


## Using Multiple Supernodes

### Form a Federation

To form a federation, multiple supernodes need to be aware of each other. To get them connected, additional `-l` option from CLI is required at the supernode.

This option takes the IP address (or name) and the UDP port of a known supernode, e.g. `-l 192.168.1.1:1234`.

### Use a Federation

Federated supernodes take care of propagating their knowledge about other supernodes to all other supernodes and the edges. 

So, edges only need to connect to one supernode (called anchor supernode), using `-l` option. That supernode needs to be present at start-up. 

Optionally, more anchor supernodes of the same federation can be provided to an edge using several `-l` options. This will counter scenarios with less assured initial supernode availability. 

## How It Works

Supernodes should be able to communicate among each other as regular edges already do. For this purpose, a special community called federation was introduced. Federation provides mechanisms to connect the supernodes of the network, and enhance backup, fail-over and load-sharing, without any visible behavioral change. 

The default name for the federation is `*Federation`. Internally, a madnatory special character is prepended to the name: that way, an edge won't be able to provide a regular community with the same name of the federation. Optionally, a user can choose a federation name (same on all supernodes) and provide it via `-F mySecretFed` option to the supernode.

Federated supernodes register to each other using REGISTER_SUPER message type. The answer, REGISTER_SUPER_ACK, contains a payload with informations about other supernodes in the network.

This specific mechanism is used also during the registration process happening between edges and supernodes, so edges are able to learn about other supernodes.

Once edges have saved this information, it is up to them choosing the supernode they want to connect. Each edge pings supernodes from time to time and receives information about them inside the answer. We decided to implement a work-load based selection strategy because it is more in line with the idea of keeping the workload low on supernodes. Moreover, that way the entire load of the network is distributed evenly among all available supernodes.

An edge connects to the supernode with the lowest work-load and it is re-considered from time to time, with each re-registration. We used a stickyness factor to avoid too much jumping between supernodes.

Thanks to this feature, n2n is now able to handle security attacks such as DoS against supernodes and it can redistribute the entire load of the network in a fair manner between all the supernodes.

To serve scenarios in which an edge is supposed to select the supernode by round trip time, i.e. choosing the "closest" one, a [compile-time option](https://github.com/ntop/n2n/blob/dev/doc/Building.md#federation--supernode-selection-by-round-trip-time) is available. Note, that workload distribution among supernodes is not so fair then.
