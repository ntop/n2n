# Supernode Federation

## Idea
Supernodes should be able to communicate each other as regular edges already do. For this purpose it has been created a special community, called **federation**. Supernodes inside the federation then are able to do any action an edge inside a regular community can perform. 

Federation provides mechanisms to connect the supernodes of the network, as backup, fail-over and for load-sharing, without any visible behavioral change. 


## Using Multiple Supernodes

### Form a Federation
To form a federation, multiple supernodes need to be aware of each other. To get them connected, additional `-l` option from CLI is required at the supernode.

This option takes the IP address (or name) and the UDP port of a known supernode (e.g., `-l <192.168.1.1:1234>`) and connect to it.

The default name for the federation is `*Federation`. There is a special character at the beginning of the name: that way, an edge won't be able to provide a regular community with the same name of the federation. Optionally, a user can choose a federation name (same on all supernodes) and provide it via `-F` option at the supernode. 

### Use a Federation
Supernodes that are part of the federation take care of the knowledge about other supernodes get propagated to the edges. 
So, edges only need to connect to one supernode (called anchor supernode), using `-l` option, although that supernode needs to be present at start-up. 

Optionally, more anchor supernodes from the same federation using several `-l` options can be provided an edge to counter a scenario in which initial supernode availability is less assured. 

## How It Works
Federated supernodes register to each other using REGISTER_SUPER message type. The answer, REGISTER_SUPER_ACK, contains a payload with informations about other supernodes in the network.

This specific mechanism is used also during the registration between edges and supernodes, so that way edges are able to learn about other supernodes. 

Edges save the informations in a specific list and ping the supernodes time to time. Then, they gather information about supernodes' workload and, on that basis, they decide to which one to connect. 

Thanks to this last feature, n2n is now able to handle security attacks (e.g., DoS against supernodes) and it can redistribute the entire load of the network in a fair manner between all the supernodes.
