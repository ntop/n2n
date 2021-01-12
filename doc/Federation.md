# Supernode Federation

## Idea
To enhance resilience in terms of backup and fail-over, also for load-balancing, multiple supernodes can easily interconnect and form a special community, called **federation**.


## Using Multiple Supernodes

### Form a Federation
To form a federation, multiple supernodes need to be aware of each other. To get them connected, additional `-l` option from CLI is required at the supernode.

This option takes the IP address (or name) and the UDP port of a known supernode (e.g., `-l <192.168.1.1:1234>`) and connect to it.

### Use a Federation
Supernodes that are part of the federation take care of the knowledge about other supernodes get propagated to the edges. 
So, edges only need to connect to one supernode (called anchor supernode), using `-l` option, although that supernode needs to be present at start-up. 

Optionally, more anchor supernodes from the same federation using several `-l` options can be provided an edge to counter a scenario in which initial supernode availability is less assured. 

## How It Works
Supernodes should be able to communicate each other as regular edges already do. For this purpose it has been created a special community, called federation. Supernodes inside the federation then are able to do any action an edge inside a regular community can perform. 

Federation provides mechanisms to connect the supernodes of the network, and enhance backup, fail-over and load-sharing, without any visible behavioral change. 

The default name for the federation is `*Federation`. There is a special character at the beginning of the name: that way, an edge won't be able to provide a regular community with the same name of the federation. Optionally, a user can choose a federation name (same on all supernodes) and provide it via `-F` option at the supernode. 

Federated supernodes register to each other using REGISTER_SUPER message type. The answer, REGISTER_SUPER_ACK, contains a payload with informations about other supernodes in the network.

This specific mechanism is used also during the registration between edges and supernodes, so that way edges are able to learn about other supernodes.

Once edges have saved those informations, it is up to them choosing the supernode they want to connect. Each edge pings supernodes from time to time and receives information about them inside the answer. We decided to implement a work-load based selection strategy because it is more in line with the idea of keeping the workload low on supernodes. Moreover, that way the entire load of the network is distributed evenly on all available supernodes.

An edge connects to the supernode with the lowest work-load and it is re-considered from time to time, with each re-registration. We used a stickyness factor to avoid too much jumping between supernodes.

Thanks to this last feature, n2n is now able to handle security attacks (e.g., DoS against supernodes) and it can redistribute the entire load of the network in a fair manner between all the supernodes.

To serve scenarios in which an edge is supposed to select the supernode by round trip time, i.e. choosing the "closest" one, a [compile-time option](Building.md) is offered. Note, that workload distribution among supernodes is not so fair then.