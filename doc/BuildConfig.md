# Configuration at Build time

There are a number of configuration options that are made only at build time.

In order to assist with cross compilation, minimising test cases, repeatable
builds and minimising externalities, the build options are generally defaulted
to off.

As part of simplifying cross compilation, the use of auto-detected
configuration settings are being removed.

## Options

After changing any configuration, please do no forget to `make clean` after
the (re-)configuration and before building (again) using `make`.  (Or the
equivalent with `cmake`)

### `--with-zstd`

ZSTD Compression Support

In addition to the built-in LZO1x for payload compression (`-z1` at the edge's
commandline), n2n optionally supports [ZSTD](https://github.com/facebook/zstd).
As of 2020, it is considered cutting edge and [praised](https://en.wikipedia.org/wiki/Zstandard)
for reaching the currently technologically possible Pareto frontier in terms
of CPU power versus compression ratio.

#### Makefile

ZSTD support can be configured using

`./configure --with-zstd`

which then will include ZSTD. It will be available via `-z2` at the edges. Of course, it can be combined with the other optimisation features:

`./configure --with-zstd --with-openssl CFLAGS="-O3 -march=native"`

Again, and this needs to be reiterated sufficiently often, please do no forget to `make clean` after (re-)configuration and before building (again) using `make`.

### `--with-openssl`

Use openssl instead of the built-in AES code

The speed of some ciphers' can take advantage of OpenSSL support This is
disabled by default as the built-in ciphers already prove reasonably fast
in most cases.

When enabled, this will include OpenSSL 1.1. This can also be combined with
the hardware support and compiler optimizations such as.

`./configure --with-openssl CFLAGS="-O3 -march=native"`

#### Makefile

Add `--with-openssl` to the `configure` command

#### Cmake

Add `-DN2N_OPTION_USE_OPENSSL=ON` to the cmake configure step.

Additionally, it is possible to statically link the OpenSSL library.
Add `-DOPENSSL_USE_STATIC_LIBS=true` to the cmake configure step.

Building statically with openssl in this way has been known to have
issues recently on Windows (See #944)

### `--with-edgex`

A legacy option intended to help cross compilation - if you use this option
please let us know as there are probably more modern options for
cross-compiling

### `--enable-pthread`

Enable threading using the pthread library

### `--enable-cap`

Use the libcap to provide reduction of the security privileges needed in the
running daemon

### `--enable-pcap`

If the pcap library is available then the `n2n-decode` tool can be compiled.

### `--enable-natpmp`

One of the two UPnP libraries, this one supports the NATPMP protocol.
See also the next option.

This option depends on the library being installed - on Debian and Ubuntu,
this is `apt-get install libnatpmp-dev`

### `--enable-miniupnp`

Enables the other kind of UPnP port mapping protocol.

Turning on either of these two UPnP libraries will enable UPnP support within
the n2n-portfwd tool.

This option depends on the library being installed - on Debian and Ubuntu,
this is `apt-get install libminiupnpc-dev`

### Disable Multicast Local Peer Detection

For better local peer detection, the edges try to detect local peers by sending REGISTER
packets to a certain multicast address. Also, edges listen to this address to eventually
fetch such packets.

If these packets disturb network's peace or even get forwarded by (other) edges through the
n2n network, this behavior can be disabled

#### Makefile

Add
`-DSKIP_MULTICAST_PEERS_DISCOVERY`

to your `CFLAGS` when configuring, e.g.

`./configure --with-zstd CFLAGS="-O3 -march=native -DSKIP_MULTICAST_PEERS_DISCOVERY"`

### Deprecation of --with options

Due to historical reasons, the autoconf system does not validate the syntax
of any `--with-X` style options, thus to provide the highest confidence in
the correctness of configuration and compilation, `--enable-X` style options
are preferred.  As part of this, the older `--with-X` options will eventually
be migrated to use `--enable-X`

## CMake configuration

There are a number of OPTION statements in the CMakeLists.txt file that can
have their settings changed.  This is done by adding a commandline option
to the cmake configure stage.

e.g:
`cmake -DN2N_OPTION_USE_ZSTD=ON ..`

Note that the names of the configure option variables used in the cmake
process will probably change to make the source code consistent.

# Optimisation options

## Compiler Optimizations

The easiest way to boosting speed is by allowing the compiler to apply optimization to the code. To let the compiler know, the configuration process can take in the optionally specified compiler flag `-O3`:

`./configure CFLAGS="-O3"`

The `tools/n2n-benchmark` tool reports speed-ups of 200% or more! There is no known risk in terms of instable code or so.

## Hardware Features

Some parts of the code significantly benefit from compiler optimizations (`-O3`) and platform features
such as NEON, SSE and AVX. It needs to be decided at compile-time. Hence if compiling for a specific
platform with known features (maybe the local one), it should be specified to the compiler – for
example through the `-march=sandybridge` (you name it) or just `-march=native` for local use.

So far, the following portions of n2n's code benefit from hardware features:

```
AES:               AES-NI
ChaCha20:          SSE2, SSSE3
SPECK:             SSE2, SSSE3, AVX2, AVX512, (NEON)
Random Numbers:    RDSEED, RDRND (not faster but more random seed)
```

The compilations flags could easily be combined:

`./configure CFLAGS="-O3 -march=native"`.

There are reports of compile errors showing `n2n_seed': random_numbers.c:(.text+0x214): undefined reference to _rdseed64_step'` even though the CPU should support it, see #696. In this case, best solution found so far is to disable `RDSEED` support by adding `-U__RDSEED__` to the `CFLAGS`.

## SPECK – ARM NEON Hardware Acceleration

By default, SPECK does not take advantage of ARM NEON hardware acceleration even if compiled with `-march=native`. The reason is that the NEON implementation proved to be slower than the 64-bit scalar code on Raspberry Pi 3B+, see [here](https://github.com/ntop/n2n/issues/563).

Your specific ARM mileage may vary, so it can be enabled by configuring the definition of the `SPECK_ARM_NEON` macro:

`./configure CFLAGS="-DSPECK_ARM_NEON"`

Just make sure that the correct architecture is set, too. `-march=native` usually works quite well.

