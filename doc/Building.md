# n2n on macOS

In order to use n2n on macOS, you first need to install support for TUN/TAP interfaces:

```bash
brew tap homebrew/cask
brew cask install tuntap
```

If you are on a modern version of macOS (i.e. Catalina), the commands above will ask you to enable the TUN/TAP kernel extension in System Preferences → Security & Privacy → General.

For more information refer to vendor documentation or the [Apple Technical Note](https://developer.apple.com/library/content/technotes/tn2459/_index.html).


# Build on Windows

## Requirements

In order to build on Windows the following tools should be installed:

- Visual Studio. For a minimal install, the command line only build tools can be
  downloaded and installed from https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2017
- Cmake
- (optional) The OpenSSL library. Prebuild binaries can be downloaded from https://slproweb.com/products/Win32OpenSSL.html .
  The full version is required (not the "Light" version). The Win32 version of it is usually required for a standard build.

  NOTE: in order to skip OpenSSL compilation, edit CMakeLists.txt and replace

  ```plaintext
  OPTION(N2N_OPTION_AES "USE AES" ON)
  with
  OPTION(N2N_OPTION_AES "USE AES" OFF)
  ```

  NOTE: to static link OpenSSL, add the `-DOPENSSL_USE_STATIC_LIBS=true` option to the cmake command

In order to run n2n:

- The TAP drivers should be installed into the system. They can be installed from
  http://build.openvpn.net/downloads/releases (search for "tap-windows")
- If OpenSSL has been linked dynamically, the corresponding .dll file should be available
  into the target computer

## Build (CLI)

In order to build from the command line, open a terminal window and run the following commands:

```batch
md build
cd build
cmake ..

MSBuild edge.vcxproj /t:Build /p:Configuration=Release
MSBuild supernode.vcxproj /t:Build /p:Configuration=Release
```

NOTE: if cmake has problems finding the installed OpenSSL library, try to download the official cmake and invoke it with:
`C:\Program Files\CMake\bin\cmake`

The compiled exe files should now be available under the Release directory.

## Run

The `edge.exe` program reads the `edge.conf` file located into the current directory if no option is provided.

Here is an example `edge.conf` file:

```plaintext
-c=mycommunity
-k=mysecretkey

# supernode IP address
-l=1.2.3.4:5678

# edge IP address
-a=192.168.100.1
```

The `supernode.exe` program reads the `supernode.conf` file located into the current directory if no option is provided.

Here is an example `supernode.conf` file:

```plaintext
-l=5678
```

See `edge.exe --help` and `supernode.exe --help` for a list of supported options.

# General Building Options

## Compiler Optimizations

The easiest way to boosting speed is by allowing the compiler to apply optimization to the code. To let the compiler know, the configuration process can take in the optionally specified compiler flag `-O3`:

`./configure CFLAGS="-O3"`

The `tools/n2n-benchmark` tool reports speed-ups of 200% or more! There is no known risk in terms of instable code or so.

## Hardware Features

Some parts of the code can be compiled to benefit from available hardware acceleration. It needs to be decided at compile-time. So, if compiling for a specific platform with known features (maybe the local one), it should be specified to the compiler, for example through the `-march=sandybridge` (you name it) or just `-march=native` for local use.

So far, the following portions of n2n's code benefit from hardware features:

```
AES:               AES-NI
ChaCha20:          SSE2, SSSE3
SPECK:             SSE2, SSSE3, AVX2, NEON
Pearson Hashing:   AES-NI
Random Numbers:    RDSEED, RDRND (not faster but more random seed)
```

The compilations flags could easily be combined:

`./configure CFLAGS="-O3 -march=native"`.

## OpenSSL Support

Some ciphers' speed can take advantage of OpenSSL support which is disabled by default as the built-in ciphers already prove reasonably fast in most cases. OpenSSL support can be configured using

`./configure --with-openssl`

which then will include OpenSSL 1.1 if found on the system. This can be combined with the hardware support and compiler optimizations such as

`./configure --with-openssl CFLAGS="-O3 -march=native"`

Please do no forget to `make clean` after (re-)configuration and before building (again) using `make`.

## ZSTD Compression Support

In addition to the built-in LZO1x for payload compression (`-z1` at the edge's commandline), n2n optionally supports [ZSTD](https://github.com/facebook/zstd). As of 2020, it is considered cutting edge and [praised](https://en.wikipedia.org/wiki/Zstandard) for reaching the currently technologically possible Pareto frontier in terms of CPU power versus compression ratio. ZSTD support can be configured using

`./configure --with-zstd`

which then will include ZSTD if found on the system. It will be available via `-z2` at the edges. Of course, it can be combined with the other features mentioned above:

`./configure --with-zstd --with-openssl CFLAGS="-O3 -march=native"`

Again, and this needs to be reiterated sufficiently often, please do no forget to `make clean` after (re-)configuration and before building (again) using `make`.
