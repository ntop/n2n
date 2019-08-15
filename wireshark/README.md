Wireshark Lua plugin to dissect n2n traffic.

Quick load:

```
  wireshark -X lua_script:n2n.lua
```

NOTE: the dissector only decodes traffic on UDP port 50001. In order to decode n2n traffic on another UDP port you can use the "Decode As..." function of wireshark.
