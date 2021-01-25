# n2n Frequently Asked Questions


## Supernode


### I want to setup a supernode that only I can use. Perhaps even password protected?

Please think of the community-name as password and start the supernode with the `-c <community file>` parameter where the `<community file>` is the path to a simple text file containing a single line with the name of your secret community. It will be the only community allowed. Only edge nodes from that community can join (`-c <community name>` at the edge).

If you additionally want to prevent open transmission of your secret community name via the network, **all** edge nodes should use `-H` command line option for header encryption.

Also, please see the community.list file for advanced use of that file.

Beyond this access barrier you may want to use payload encryption `-A_` at the edges. Only the edges – not the supernode – are able to decipher the payload data. So, even if anyone would be able to break the access barrier to the supernode, the payload remains protected by the payload crypto, see [this document](https://github.com/ntop/n2n/blob/dev/doc/Crypto.md) for details.


### Can I get a list of connected edge node and their community and source IP from the supernode?

The supernode provides basic information via its localhost udp management port. It defaults to 5645 and can be changed using supernode's `-t` command line option.

You can request the current status by just sending a new line, i.e. pressing [ENTER] key, running the following command (localhost only)

`netcat -u localhost 5645`


### Is there support for multiple supernodes?

As of now, one additional supernode is supported. The additional supernode is handled in a backup-fashion: A reserve-supernode can be started if one fails. The reserve-supernode just has to be known to the edges beforehand (simply by an additional `-l <ip:port>` at the edge).

Actively using several supernodes in parallel will have the network fall apart (partitioned – some edges connected to one supernode, some to another).

Considering these known limitations, current discussions however seem to include thoughts on increasing supernode reliability as well as fall-back mechanisms and might even shift more towards a full p2p-approach which then would not require a supernode at all, every node could be equal highly increasing network resilience.


### Can a supernode listen on multiple ports?

The supernode itself can only listen on one port. However, your firewall might be able to map additional UDP ports to the supernode's regular port:

`sudo iptables -t nat -A PREROUTING -i <network interface name> -d <supernode's ip address> -p udp --dport <additional port number> -j REDIRECT --to-ports <regular supernode port number>`

This command line can be put down as additional `ExecStartPost=` line (without `sudo`) in the supernode's `.service` file which can hold several such lines if required.


### How to handle the error message "process_udp dropped a packet with seemingly encrypted header for which no matching community which uses encrypted headers was found"?

This error message means that the supernode is not able to identify a packet as unencrypted. It does check for a sane packet format. If it fails the header is assuemd encrypted (thus, "_seemingly_ encrypted header") and the supernode tries all communties that would make a key (some have already been ruled out as they definetly are unenecrypted). If no matching community is found, the error occurs.

If all edges use the same `-H` setting (all edges either with it or without it) and restarting the supernode does not help, most probably one of the components (an edge or the supernode) is outdated, i.e. uses a different packet format – from time to time, a lot of changes happen to the packet format in a very short period of time, especially in _dev_ branch.

So, please make sure that all edges **and** the supernode have the exact same built version, e.g. all from current _dev_.


## Edge


### How can I know if peer-to-peer connection has successfully been established?

The edge also offers a local udp management port at which it provides some information about connected _peers_ allowing a peer-to-peer connection, and _pending peers_ whose connections are forwarded through the supernode.

The edge's management port defaults to 5644 and can be changed using edge's `-t` command line option. Connecting using the following command (localhost only)

`netcat -u localhost 5644`

answers every new line, i.e. pressing [ENTER] key, with current information. The edge even understands some simple commands, try `help`.


### The edge surprisingly stops – throwing an "Authentication error. MAC or IP address already in use or not released yet by supernode" message. What is wrong?

The edge encountered n2n's protection against spoofing. It prevents that one edge's identity, MAC and IP address, can be impersonated by some other while the original one is still online, see some [details](Authentication.md). Mostly, there are two situations which can trigger this:

If you use a MAC or IP address that already is in use, just change those parameters.

If the edge prematurely has ended in a non-regular way, i.e. by killing it using `kill -9 ...` or `kill -SIGKILL ...`, it did not have a chance to un-register with the supernode which still counts the edge for online. A re-registration with the same MAC or IP address will be unsuccessful then. After two minutes or so the supernode will have forgotten. A new registration with the same parameters will be possible then. So, either wait two minutes or chose different parameters to restart with.

And, as a matter of principal, always end an edge by either pressing `CTRL` + `C` or by sending SIGTERM or SIGINT by using `kill -SIGTERM ...` or `kill -SIGINT ...`! A plain `kill ...` without `-9` will do, too. And finally, a `stop` command to the management port peacefully ends the edge as well.