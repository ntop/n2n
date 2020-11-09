# Traffic Restrictions

It is possible to drop or accept specific packet transmit over edge network interface by rules. Rules can be specify by (`-F rule_str`) multiple times.

## Rule String Format

rule_str format: src_ip/len:[b_port,e_port],dst_ip/len:[s_port,e_port],TCP+/-,UDP+/-,ICMP+/-

ip/len indicate a cidr block, len can be ignore, means single ip (not cidr block) will be use in filter rule.

'+','-' after `TCP`,`UDP`,`ICMP` proto type indicate allow or drop packet of that proto. if any of above three proto missed, the rule will not take effect for that proto.

[s_port,e_port] can be instead by single port number, if not specify, 0-65535 ports will be used. ports range include start_port and end_port.

examples:
192.168.1.5/32:[0,65535],192.168.0.0/24:[8081,65535],TCP-,UDP-,ICMP+
192.168.1.5:[0,65535],192.168.0.0/24:8000,ICMP+
192.168.1.5,192.168.0.7,TCP-,UDP-,ICMP- // packets by all proto of all ports from 192.158.1.5 to any ports of 192.168.0.7 will be dropped.

## Multiple Rules

-F rule_str flag can use multiple times to add multiple rules. Each -F rule_str flags add one rule. for example:

`edge -c xxxx -k xxxx -a 192.168.100.5 -l xxx.xxx.xxx.xxx:1234 -r -F 192.168.1.5/32:[0,65535],192.168.0.0/24:[8081,65535],TCP-,UDP-,ICMP+ -F 192.168.1.5:[0,65535],192.168.0.0/24:8000,ICMP+ -F 192.168.1.5,192.168.0.7,TCP-`

## Matching Rules Priority

If multiple rules matching packet's ips and ports, the rule with smaller cidr block(smaller address space) will be selected. That means rules with larger `len` value has higher priority.

Actually, current implementation will add the `len` of src cidr and dst cidr of each matched rules as priority value, the rule with largest priority value will indicate which proto is allowed for current packet.

## Blocklist/Allowlist mode

Packets that cannot match any rule will be accepted by default. Users can add rules to block traffics.

This behavior can be change by add a rule : `0.0.0.0/0:[0,65535],0.0.0.0/0:[0,65535],TCP-,UDP-,ICMP-`. Then all traffic will be dropped, users need add rules to allow traffics. for example : `-F 0.0.0.0/0,0.0.0.0/0,TCP-,UDP-,ICMP- -F 192.168.100.0/24,192.168.100.0/24,ICMP+`

More complex behavior can be set with the feature of `Matching Rules Priority`.

