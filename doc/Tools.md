# Tools

There are a number of handy tools coming with n2n extending fumction and
user experience or just prove helpful during build and development.

All tools can be found in the `tools` directory.

## End User Tools

### `n2n-benchmark`

This C tool has n2n's basic transforms (the ciphers, compression, hash)
crunch a test packet and outputs the measured throughput. You might observe
differences depending on compiler optimizations or enabled hardware support,
see [build configuration](BuildConfig.md).

Example:
- `tools/n2n-benchmark`

### `n2n-route`

This C tool sets new routes for all the traffic to be routed via a VPN gateway
(another edge) and polls the management port of a local n2n edge for adding
appropriate routes to supernodes and peers via the original default gateway.

The tool can auto-detect the default gateway and also has options to only route
traffic to specified networks through the VPN gateway.

Make sure to run with sufficient rights to let the tool add and delete routes.

More general information can be found in the [routing document](Routing.md)
including hints how to setup the remote edge (IP routing, masquerading).

Example:
- `tools/n2n-route <remote edge address>`
- `tools/n2n-route -n 10.10.10.0/24 <remote edge address>`
- `tools/n2n-route -n 8.8.8.8/32 <remote edge address>`

### `n2n-portfwd`

This C tool uses UPnP and/or PMP to have a local router forward the edge port.
The program polls a local edge's management port and takes apporpriate action.

Note that n2n needs to be compiled with the corresponding options enabled, e.g.

```
./configure --enable-miniupnp --enable-natpmp
```

or

```
`cmake -DN2N_OPTION_USE_PORTMAPPING=ON`

```

Also see [build configuration](BuildConfig.md).

Example:
- `tools/n2n-portfwd`


## Build and Development Tools

### `tests-*`

These C programs run certain parts of n2n with pre-defined data and output
the results. The expected results can be found in the `tests/` directory
following the `tests-*.expected` naming scheme.

The `test_*` [scripts](Scripts.md) residing inside the `scripts/` directory
compare test output and expected results to quickly show deviations, helpful
when on bug hunt.

Example:
- `tools/tests-transforms`

### `n2n-decode`

This C tool intends to decrypt captured n2n traffic when all keys are provided.
Its development unfortunately did not follow main n2n's pace after version 2.8 
and thus is not up to date.

Contributions to help lifting it to match version 3.x traffic are very welcome.
