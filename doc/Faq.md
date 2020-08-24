# n2n Frequently Asked Questions

## Supernode

### I want to setup a supernode that only I can use. Perhaps even password protected?

Please think of the community-name as password and start the supernode with the `-c <community file>` parameter where the `<community file>` is the path to a simple text file containing a single line with the name of your secret community. It will be the only community allowed. Only edge nodes from that community can join (`-c <community name>` at the edge).

If you additionally want to prevent open transmission of your secret community name via the network, **all** edge nodes should use `-H` command line option for header encryption.

Also, please see the community.list file for advanced use of that file.

Beyond this access barrier you may want to use payload encryption `-A_` at the edges. Only the edges – not the supernode – are able to decipher the payload data. So, even if anyone would be able to break the access barrier to the supernode, the payload remains protected by the payload crypto, see [this document](https://github.com/ntop/n2n/blob/dev/doc/Crypto.md) for details.


## Edge
