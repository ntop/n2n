# Supernode Federation

## Idea
To enhance resilience in terms of backup and fail-over, also for load-balancing, multiple supernodes can easily interconnect and form a special community, called **federation**.


## Using Multiple Supernodes

### Form a Federation

To form a federation, multiple supernodes need to be aware of each other. To get them connected, an additional `-l` option from command line is required at the supernode.

This option takes the IP address (or name) and the UDP port of another known supernode, e.g. `-l 192.168.1.1:1234`.

### Use a Federation

Federated supernodes take care of propagating their knowledge about other supernodes to all other supernodes and the edges. 

So, in the first place, edges only need to connect to one supernode (called anchor supernode) using `-l` option. This supernode needs to be present at start-up. 

Optionally, more anchor supernodes of the same federation can be provided to an edge using several `-l` options. This will counter scenarios with reduced assured initial supernode availability. 

## How It Works

Supernodes should be able to communicate among each other as regular edges already do. For this purpose, a special community called federation was introduced. The federation feature provides some mechanisms to inter-connect the supernodes of the network enhancing backup, fail-over and load-sharing, without any visible behavioral change. 

The default name for the federation is `*Federation`. Internally, a mandatory special character is prepended to the name: that way, an edge won't be able to provide a regular community with the same name of the federation. Optionally, a user can choose a federation name (same on all supernodes) and provide it via `-F mySecretFed` option to the supernode. Alternatively, the federation name can be passed through the environment variable `N2N_FEDERATION`.

Federated supernodes register to each other using REGISTER_SUPER message type. The answer, REGISTER_SUPER_ACK, contains a payload with information about other supernodes in the network.

This specific mechanism is also used during the registration process taking place between edges and supernodes, so edges are able to learn about other supernodes.

Once edges have received this information, it is up to them choosing the supernode they want to connect to. Each edge pings supernodes from time to time and receives information about them inside the answer. We decided to implement a work-load based selection strategy because it is more in line with the idea of keeping the workload low on supernodes. Moreover, this way, the entire network load is evenly distributed among all available supernodes.

An edge connects to the supernode with the lowest work-load and it is re-considered from time to time, with each re-registration. We use a stickyness factor to avoid too much jumping between supernodes.

Thanks to this feature, n2n is now able to handle security attacks such as DoS against supernodes and it can redistribute the entire load of the network in a fair manner between all the supernodes.

To serve scenarios in which an edge is supposed to select the supernode by round trip time, i.e. choosing the "closest" one, the `--select-rtt` command line option is available at the edge. Note, that workload distribution among supernodes might not be so fair then.

Furthermore, `--select-mac` would switch to a MAC address based selection strategy choosing the supernode active with the lowest MAC address. 
