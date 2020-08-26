# n2n Frequently Asked Questions

## Supernode

### I want to setup a supernode that only I can use. Perhaps even password protected?

Please think of the community-name as password and start the supernode with the `-c <community file>` parameter where the `<community file>` is the path to a simple text file containing a single line with the name of your secret community. It will be the only community allowed. Only edge nodes from that community can join (`-c <community name>` at the edge).

If you additionally want to prevent open transmission of your secret community name via the network, **all** edge nodes should use `-H` command line option for header encryption.

Also, please see the community.list file for advanced use of that file.

Beyond this access barrier you may want to use payload encryption `-A_` at the edges. Only the edges – not the supernode – are able to decipher the payload data. So, even if anyone would be able to break the access barrier to the supernode, the payload remains protected by the payload crypto, see [this document](https://github.com/ntop/n2n/blob/dev/doc/Crypto.md) for details.

### Can I get a list of connected edge node and their community and source IP from the supernode?

The supernode provides basic information via its localhost udp management port. It defaults to 5645.

You can request that information by just sending a new line, i.e. pressing [ENTER] key, running the following command (localhost only):

`netcat -u localhost 5645`


## Edge

### How can I know if p2p is successfully established?

The edge also offer a management port at which it provides some information about connected _peers_, i.e. allowing a peer-to-peer connection, and _pending peers_ whose connections are forwarded through the supernode.

The edge's management port defaults 5644. Connecting using the following command

`netcat -u localhost 5644`

answers every new line, i.e. press [ENTER] key, with the current information. The edge even understands some simple commands, try `help`.
