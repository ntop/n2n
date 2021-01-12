# Configuration Files

To help deployment and better handle locally different configurations, n2n supports the optional use of configuration files for `edge` and `supernode`.

They are plain text files and contain the desired command line options, **one per line**.

The exemplary command line

```bash
sudo edge -c mynetwork -k mysecretpass -a 192.168.100.1 -f -l supernode.ntop.org:7777
```

translates into the following `edge.conf` file:

```
-c mynetwork
-k mysecretpass
-a 192.168.100.1
-f
-l supernode.ntop.org:7777
-A5
```

which can be loaded by

```
sudo ./edge edge.conf
```

Comment lines starting with a hash '#' are ignored.

```
# automated edge configuration
# created by bot7
# on April 31, 2038 – 1800Z
-c    mynetwork
-k    mysecretpass
-a    192.168.100.1
-f
-A5
# --- supernode section ---
-l    supernode.ntop.org:7777
```

Long options can be used as well. Please note the double minus/dash-character `--`, just like you would use them on the command line with long options:

```
--community    mynetwork
-k             mysecretpass
-a             192.168.100.1
-f
-A5
-l             supernode.ntop.org:7777
```

If using a configuration file, its filename needs to be supplied as first parameter to `edge` or `supernode`. If required, additional command line parameters can be supplied afterwards:

```
sudo edge edge.conf -z1 -I myComputer
```

Finally, the `.conf` file syntax also allows `=` between parameter and its option:

```
-c=mynetwork
-k=mysecretpass
-a=192.168.100.1
-f
-A5
-l=supernode.ntop.org:7777
```

When used with `=`, there is no whitespace allowed between parameter, delimter (`=`), and option. So, do **not** put `-c = mynetwork` – it is required to be `-c=mynetwork`.
